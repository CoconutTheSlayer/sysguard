#include "janitor.hpp"

#include "metrics.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <dirent.h>
#include <filesystem>
#include <fstream>
#include <fts.h>
#include <libproc.h>
#include <sstream>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <thread>
#include <unistd.h>
#include <unordered_set>

namespace fs = std::filesystem;

namespace sysguard {

namespace {

constexpr uint64_t kGB = 1024ULL * 1024ULL * 1024ULL;

uint64_t disk_avail_now() {
  struct statvfs sv{};
  if (statvfs("/System/Volumes/Data", &sv) == 0 || statvfs("/", &sv) == 0) {
    return static_cast<uint64_t>(sv.f_bavail) * sv.f_frsize;
  }
  return 0;
}

struct DevIno {
  dev_t dev;
  ino_t ino;
  bool operator==(const DevIno& o) const noexcept {
    return dev == o.dev && ino == o.ino;
  }
};

struct DevInoHash {
  size_t operator()(const DevIno& k) const noexcept {
    uint64_t h1 = static_cast<uint64_t>(k.dev);
    uint64_t h2 = static_cast<uint64_t>(k.ino);
    return static_cast<size_t>(h1 * 11400714819323198485ULL ^ h2);
  }
};

std::string trim_copy(std::string s) {
  while (!s.empty() &&
         (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' ||
          s.back() == '\t')) {
    s.pop_back();
  }
  size_t i = 0;
  while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
  return s.substr(i);
}

bool read_first_line(const std::string& file_path, std::string& out_line) {
  std::ifstream ifs(file_path, std::ios::in);
  if (!ifs) return false;
  if (!std::getline(ifs, out_line)) return false;
  out_line = trim_copy(std::move(out_line));
  return true;
}

bool parse_worktree_git_metadata(const std::string& wt,
                                 std::string& out_gitdir) {
  std::string line;
  if (!read_first_line(wt + "/.git", line)) return false;
  if (line.rfind("gitdir:", 0) != 0) return false;
  std::string gd = trim_copy(line.substr(7));
  if (gd.empty()) return false;
  fs::path p(gd);
  if (p.is_relative()) {
    p = fs::path(wt) / p;
  }
  p = p.lexically_normal();
  if (p.filename().empty() || p.filename() == ".") {
    p = p.parent_path();
  }
  out_gitdir = p.string();
  while (out_gitdir.size() > 1 && out_gitdir.back() == '/') {
    out_gitdir.pop_back();
  }
  return !out_gitdir.empty();
}

bool dir_has_recent_mtime(const std::string& root, time_t cutoff) {
  struct stat st{};
  if (lstat(root.c_str(), &st) != 0) return true;
  if (st.st_mtime > cutoff) return true;

  char* paths[] = {const_cast<char*>(root.c_str()), nullptr};
  FTS* tree = fts_open(paths, FTS_PHYSICAL | FTS_XDEV | FTS_NOCHDIR, nullptr);
  if (!tree) return true;
  bool recent = false;
  FTSENT* node = nullptr;
  while ((node = fts_read(tree)) != nullptr) {
    if (node->fts_statp && node->fts_statp->st_mtime > cutoff) {
      recent = true;
      break;
    }
  }
  fts_close(tree);
  return recent;
}

std::string build_active_process_blob() {
  std::string blob;
  blob.reserve(64 * 1024);

  const uid_t my_uid = getuid();
  int byte_sz = proc_listpids(PROC_UID_ONLY, static_cast<uint32_t>(my_uid),
                              nullptr, 0);
  size_t est = (byte_sz > 0)
                   ? (static_cast<size_t>(byte_sz) / sizeof(pid_t))
                   : 256;
  std::vector<pid_t> pids(est + 128);
  int ret_bytes = proc_listpids(
      PROC_UID_ONLY, static_cast<uint32_t>(my_uid), pids.data(),
      static_cast<int>(pids.size() * sizeof(pid_t)));
  if (ret_bytes > 0) {
    const size_t n = std::min<size_t>(
        static_cast<size_t>(ret_bytes) / sizeof(pid_t), pids.size());
    for (size_t i = 0; i < n; ++i) {
      pid_t pid = pids[i];
      if (pid <= 0) continue;

      std::string cwd = read_proc_cwd(pid);
      if (!cwd.empty()) {
        blob.append(cwd);
        blob.push_back('\n');
      }
      std::string args = read_proc_args(pid);
      if (!args.empty()) {
        blob.append(args);
        blob.push_back('\n');
      }
    }
  }

  char cwd_buf[PATH_MAX];
  if (getcwd(cwd_buf, sizeof(cwd_buf))) {
    blob.append(cwd_buf);
    blob.push_back('\n');
  }
  return blob;
}

std::string resolve_pnpm() {
  const char* home = std::getenv("HOME");
  std::vector<std::string> candidates;
  if (home) {
    candidates.push_back(std::string(home) + "/Library/pnpm/pnpm");
    candidates.push_back(std::string(home) + "/.local/share/pnpm/pnpm");
  }
  candidates.push_back("/opt/homebrew/bin/pnpm");
  candidates.push_back("/usr/local/bin/pnpm");
  for (const auto& p : candidates) {
    if (access(p.c_str(), X_OK) == 0) return p;
  }
  return {};
}

std::string resolve_brew() {
  for (const char* p : {"/opt/homebrew/bin/brew", "/usr/local/bin/brew"}) {
    if (access(p, X_OK) == 0) return p;
  }
  return {};
}

WorktreeInfo inspect_one_worktree(const std::string& wt,
                                  const std::string& active_blob,
                                  time_t now_wall,
                                  uint64_t min_age_hours,
                                  WorktreeSizeMode size_mode) {
  WorktreeInfo info;
  info.path = wt;

  struct stat st_dir{};
  if (lstat(wt.c_str(), &st_dir) != 0 || !S_ISDIR(st_dir.st_mode) ||
      S_ISLNK(st_dir.st_mode)) {
    info.status = WorktreeStatus::NotWorktree;
    info.reason = "not directory";
    return info;
  }

  std::string git_file = wt + "/.git";
  struct stat st_git{};
  if (lstat(git_file.c_str(), &st_git) != 0 || !S_ISREG(st_git.st_mode)) {
    info.status = WorktreeStatus::NotWorktree;
    info.reason = "not git worktree";
    return info;
  }

  time_t latest = std::max(st_dir.st_mtime, st_git.st_mtime);

  // Fast path: parse <wt>/.git + <gitdir>/{index,HEAD,commondir} with zero git forks
  std::string gitdir;
  bool got_index = false;
  bool got_branch = false;
  bool got_parent = false;
  if (parse_worktree_git_metadata(wt, gitdir)) {
    struct stat st_idx{};
    std::string idx_path = gitdir + "/index";
    if (lstat(idx_path.c_str(), &st_idx) == 0) {
      latest = std::max(latest, st_idx.st_mtime);
      got_index = true;
    } else if (fs::is_directory(gitdir)) {
      // Worktree gitdir exists even if index was not materialized
      got_index = true;
    }

    std::string head_line;
    if (read_first_line(gitdir + "/HEAD", head_line) && !head_line.empty()) {
      constexpr const char* kRefPrefix = "ref: refs/heads/";
      constexpr size_t kRefLen = 16;
      if (head_line.rfind(kRefPrefix, 0) == 0) {
        info.branch = head_line.substr(kRefLen);
        got_branch = !info.branch.empty();
      } else if (head_line.rfind("ref:", 0) != 0) {
        info.branch = "HEAD";
        got_branch = true;
      }
    }

    std::string common_line;
    if (read_first_line(gitdir + "/commondir", common_line) &&
        !common_line.empty()) {
      fs::path cp(common_line);
      if (cp.is_relative()) {
        cp = fs::path(gitdir) / cp;
      }
      cp = cp.lexically_normal();
      if (cp.filename().empty() || cp.filename() == ".") {
        cp = cp.parent_path();
      }
      info.parent_repo =
          (cp.filename() == ".git") ? cp.parent_path().string() : cp.string();
      got_parent = !info.parent_repo.empty();
    }
  }

  // Fallback to git rev-parse only if direct metadata parsing missed anything
  int rc = -1;
  if (!got_index) {
    std::string idx_out;
    if (run_command_capture(
            {"/usr/bin/git", "--no-optional-locks", "-C", wt, "rev-parse",
             "--git-path", "index"},
            idx_out, rc, 10000) &&
        rc == 0) {
      std::string idx_path = trim_copy(idx_out);
      if (!idx_path.empty()) {
        if (idx_path[0] != '/') idx_path = wt + "/" + idx_path;
        struct stat st_idx{};
        if (lstat(idx_path.c_str(), &st_idx) == 0) {
          latest = std::max(latest, st_idx.st_mtime);
        }
      }
    }
  }
  if (now_wall > latest) {
    info.age_hours = static_cast<uint64_t>(now_wall - latest) / 3600ULL;
  }

  if (!got_branch) {
    std::string br_name;
    if (run_command_capture(
            {"/usr/bin/git", "--no-optional-locks", "-C", wt, "rev-parse",
             "--abbrev-ref", "HEAD"},
            br_name, rc, 10000) &&
        rc == 0) {
      info.branch = trim_copy(br_name);
    }
  }

  if (!got_parent) {
    std::string cdir;
    if (run_command_capture(
            {"/usr/bin/git", "--no-optional-locks", "-C", wt, "rev-parse",
             "--path-format=absolute", "--git-common-dir"},
            cdir, rc, 10000) &&
        rc == 0) {
      cdir = trim_copy(cdir);
      fs::path cp(cdir);
      info.parent_repo =
          (cp.filename() == ".git") ? cp.parent_path().string() : cdir;
    }
  }

  auto finish_with_size = [&]() -> WorktreeInfo {
    if (size_mode == WorktreeSizeMode::All ||
        (size_mode == WorktreeSizeMode::SafeOnly &&
         info.status == WorktreeStatus::SafeToPrune)) {
      info.size_bytes = dir_size_bytes(wt);
    }
    return info;
  };

  if (path_mentioned_in_blob(active_blob, wt)) {
    info.status = WorktreeStatus::Active;
    info.reason = "in use by running process";
    return finish_with_size();
  }

  if (info.age_hours < min_age_hours) {
    info.status = WorktreeStatus::Recent;
    info.reason = "modified < " + std::to_string(min_age_hours) + "h ago";
    return finish_with_size();
  }

  std::string status_out;
  if (!run_command_capture(
          {"/usr/bin/git", "--no-optional-locks", "-C", wt, "status",
           "--porcelain"},
          status_out, rc, 10000) ||
      rc != 0) {
    info.status = WorktreeStatus::Error;
    info.reason = "git status failed";
    return finish_with_size();
  }
  if (!trim_copy(status_out).empty()) {
    info.status = WorktreeStatus::Dirty;
    info.reason = "uncommitted changes";
    return finish_with_size();
  }

  std::string remote_out;
  if (!run_command_capture(
          {"/usr/bin/git", "--no-optional-locks", "-C", wt, "branch", "-r",
           "--contains", "HEAD"},
          remote_out, rc, 10000) ||
      rc != 0) {
    info.status = WorktreeStatus::Error;
    info.reason = "git branch check failed";
    return finish_with_size();
  }
  if (trim_copy(remote_out).empty()) {
    info.status = WorktreeStatus::Unpushed;
    info.reason = "unpushed HEAD commit";
    return finish_with_size();
  }

  info.status = WorktreeStatus::SafeToPrune;
  info.reason = "clean & pushed";
  return finish_with_size();
}

}  // namespace

uint64_t dir_size_bytes(const std::string& root) {
  char* paths[] = {const_cast<char*>(root.c_str()), nullptr};
  FTS* tree = fts_open(paths, FTS_PHYSICAL | FTS_XDEV | FTS_NOCHDIR, nullptr);
  if (!tree) return 0;

  std::unordered_set<DevIno, DevInoHash> seen_hardlinks;
  uint64_t total = 0;
  FTSENT* node = nullptr;
  while ((node = fts_read(tree)) != nullptr) {
    if (node->fts_info == FTS_F || node->fts_info == FTS_SL ||
        node->fts_info == FTS_SLNONE || node->fts_info == FTS_DEFAULT) {
      if (node->fts_statp) {
        if (node->fts_statp->st_nlink > 1) {
          if (!seen_hardlinks
                   .emplace(DevIno{node->fts_statp->st_dev,
                                   node->fts_statp->st_ino})
                   .second) {
            continue;
          }
        }
        total += static_cast<uint64_t>(node->fts_statp->st_blocks) * 512ULL;
      }
    }
  }
  fts_close(tree);
  return total;
}

bool path_mentioned_in_blob(const std::string& blob, const std::string& path) {
  if (blob.empty() || path.empty()) return false;
  std::string needle = path;
  while (needle.size() > 1 && needle.back() == '/') {
    needle.pop_back();
  }
  if (needle.empty()) return false;

  auto is_before_delim = [](char c) -> bool {
    return c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '\'' ||
           c == '"' || c == '=' || c == ':' || c == '(';
  };
  auto is_after_delim = [](char c) -> bool {
    return c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '/' ||
           c == '\'' || c == '"' || c == ':' || c == ')' || c == ',' ||
           c == ';';
  };

  size_t from = 0;
  while (from < blob.size()) {
    size_t pos = blob.find(needle, from);
    if (pos == std::string::npos) return false;
    bool before_ok = (pos == 0) || is_before_delim(blob[pos - 1]);
    size_t end = pos + needle.size();
    bool after_ok = (end == blob.size()) || is_after_delim(blob[end]);
    if (before_ok && after_ok) {
      return true;
    }
    from = pos + 1;
  }
  return false;
}

WorktreeAuditSummary audit_worktrees_in_candidates(
    const std::vector<std::string>& candidates,
    uint64_t min_age_hours,
    WorktreeSizeMode size_mode,
    const std::string* active_blob_override) {
  WorktreeAuditSummary summary;
  if (candidates.empty()) return summary;

  std::string active_blob =
      active_blob_override ? *active_blob_override : build_active_process_blob();
  time_t now_wall = std::time(nullptr);

  std::vector<WorktreeInfo> results(candidates.size());
  std::atomic<size_t> next_idx{0};

  unsigned hw = std::thread::hardware_concurrency();
  size_t num_threads = std::min<size_t>(candidates.size(), hw ? std::min<size_t>(8, hw) : 4);
  if (num_threads == 0) num_threads = 1;

  std::vector<std::thread> workers;
  workers.reserve(num_threads);
  for (size_t t = 0; t < num_threads; ++t) {
    workers.emplace_back([&]() {
      while (true) {
        size_t i = next_idx.fetch_add(1, std::memory_order_relaxed);
        if (i >= candidates.size()) break;
        results[i] = inspect_one_worktree(candidates[i], active_blob, now_wall,
                                          min_age_hours, size_mode);
      }
    });
  }
  for (auto& w : workers) w.join();

  for (auto& item : results) {
    if (item.status == WorktreeStatus::NotWorktree) {
      summary.non_worktree_count += 1;
      continue;
    }
    summary.total_bytes += item.size_bytes;
    switch (item.status) {
      case WorktreeStatus::SafeToPrune:
        summary.safe_count += 1;
        summary.safe_bytes += item.size_bytes;
        break;
      case WorktreeStatus::Active:
        summary.active_count += 1;
        break;
      case WorktreeStatus::Recent:
        summary.recent_count += 1;
        break;
      case WorktreeStatus::Dirty:
        summary.dirty_count += 1;
        break;
      case WorktreeStatus::Unpushed:
        summary.unpushed_count += 1;
        break;
      case WorktreeStatus::Error:
        summary.error_count += 1;
        break;
      case WorktreeStatus::NotWorktree:
        break;
    }
    summary.items.push_back(std::move(item));
  }

  std::sort(summary.items.begin(), summary.items.end(),
            [size_mode](const WorktreeInfo& a, const WorktreeInfo& b) {
              if (size_mode != WorktreeSizeMode::None &&
                  a.size_bytes != b.size_bytes) {
                return a.size_bytes > b.size_bytes;
              }
              return a.age_hours > b.age_hours;
            });
  return summary;
}

WorktreeAuditSummary audit_worktrees(uint64_t min_age_hours,
                                     WorktreeSizeMode size_mode,
                                     const std::vector<std::string>& extra_roots) {
  return audit_worktrees_in_candidates(
      discover_worktree_candidates(extra_roots), min_age_hours, size_mode,
      nullptr);
}

WorktreeAuditSummary audit_worktrees(uint64_t min_age_hours,
                                     bool compute_sizes) {
  return audit_worktrees(
      min_age_hours,
      compute_sizes ? WorktreeSizeMode::All : WorktreeSizeMode::None);
}

std::vector<std::string> discover_worktree_candidates(
    const std::vector<std::string>& extra_roots) {
  std::vector<std::string> out;
  std::unordered_set<std::string> seen;
  std::error_code ec;

  auto add_children_of = [&](const std::string& parent) {
    if (!fs::is_directory(parent, ec)) return;
    for (const auto& ent : fs::directory_iterator(parent, ec)) {
      if (ec) break;
      std::string p = ent.path().lexically_normal().string();
      if (seen.insert(p).second) {
        out.push_back(std::move(p));
      }
    }
  };

  const char* home_c = std::getenv("HOME");
  if (home_c) {
    std::string home = home_c;

    // 1. ~/.t3/worktrees/*/*
    std::string t3_wt = home + "/.t3/worktrees";
    if (fs::is_directory(t3_wt, ec)) {
      for (const auto& proj : fs::directory_iterator(t3_wt, ec)) {
        if (ec) break;
        if (proj.is_directory(ec)) {
          add_children_of(proj.path().string());
        }
      }
    }

    // 2. ~/Projects/*-worktrees/*, ~/Projects/*/.claude/worktrees/*, ~/Projects/*/worktrees/*
    std::string projects = home + "/Projects";
    if (fs::is_directory(projects, ec)) {
      for (const auto& entry : fs::directory_iterator(projects, ec)) {
        if (ec) break;
        if (!entry.is_directory(ec)) continue;
        std::string name = entry.path().filename().string();
        std::string full = entry.path().string();
        if (name.size() > 10 &&
            name.compare(name.size() - 10, 10, "-worktrees") == 0) {
          add_children_of(full);
        } else {
          add_children_of(full + "/.claude/worktrees");
          add_children_of(full + "/worktrees");
        }
      }
    }
  }

  for (const auto& raw : extra_roots) {
    if (raw.empty()) continue;
    fs::path ep = fs::path(raw).lexically_normal();
    std::string ep_str = ep.string();
    if (fs::is_regular_file(ep / ".git", ec)) {
      if (seen.insert(ep_str).second) out.push_back(std::move(ep_str));
    } else {
      add_children_of(ep_str);
    }
  }

  return out;
}

WorktreePruneResult prune_worktrees(const WorktreeAuditSummary& audit,
                                    bool run_pnpm_prune) {
  WorktreePruneResult res;
  uint64_t avail_before = disk_avail_now();
  std::string active_blob = build_active_process_blob();
  std::unordered_set<std::string> parent_repos;

  for (const auto& item : audit.items) {
    if (item.status != WorktreeStatus::SafeToPrune) continue;
    if (path_mentioned_in_blob(active_blob, item.path)) continue;

    std::error_code ec;
    if (!fs::is_directory(item.path, ec) || fs::is_symlink(item.path, ec)) {
      continue;
    }

    // Re-verify cleanliness and pushed status right before deletion (TOCTOU guard)
    std::string status_out;
    int st_rc = -1;
    if (!run_command_capture(
            {"/usr/bin/git", "--no-optional-locks", "-C", item.path,
             "status", "--porcelain"},
            status_out, st_rc, 10000) ||
        st_rc != 0 || !trim_copy(status_out).empty()) {
      continue;
    }

    std::string remote_out;
    int br_rc = -1;
    if (!run_command_capture(
            {"/usr/bin/git", "--no-optional-locks", "-C", item.path,
             "branch", "-r", "--contains", "HEAD"},
            remote_out, br_rc, 10000) ||
        br_rc != 0 || trim_copy(remote_out).empty()) {
      continue;
    }

    bool done = false;
    if (!item.parent_repo.empty() && fs::is_directory(item.parent_repo, ec)) {
      parent_repos.insert(item.parent_repo);
      std::string out;
      int rc = -1;
      if (run_command_capture(
              {"/usr/bin/git", "--no-optional-locks", "-C", item.parent_repo,
               "worktree", "remove", item.path},
              out, rc, 30000) &&
          rc == 0 && !fs::exists(item.path, ec)) {
        done = true;
      }
    }
    if (!done) {
      fs::remove_all(item.path, ec);
      if (!ec && !fs::exists(item.path, ec)) {
        done = true;
      }
    }
    if (done) {
      res.removed_count += 1;
    } else {
      res.failed_count += 1;
    }
  }

  for (const auto& repo : parent_repos) {
    std::string out;
    int rc = 0;
    run_command_capture({"/usr/bin/git", "--no-optional-locks", "-C", repo,
                         "worktree", "prune"},
                        out, rc, 30000);
  }

  if (run_pnpm_prune) {
    std::string pnpm = resolve_pnpm();
    if (!pnpm.empty()) {
      std::string out;
      int rc = -1;
      if (run_command_capture({pnpm, "store", "prune"}, out, rc, 120000) &&
          rc == 0) {
        res.ran_pnpm_prune = true;
      }
    }
  }

  usleep(500000);
  uint64_t avail_after = disk_avail_now();
  if (avail_after > avail_before) {
    res.freed_bytes = avail_after - avail_before;
  }

  std::ostringstream os;
  os << "Removed " << res.removed_count << " worktree(s)";
  if (res.failed_count > 0) os << " (" << res.failed_count << " failed)";
  if (res.freed_bytes > 0) os << ", freed " << format_bytes(res.freed_bytes);
  res.detail = os.str();
  return res;
}

JanitorReport run_dev_janitor(const JanitorOptions& opts) {
  JanitorReport report;
  uint64_t avail_before = disk_avail_now();
  std::string active_blob = build_active_process_blob();
  const bool chrome_running =
      (active_blob.find("Google Chrome.app") != std::string::npos);
  int rc = 0;

  time_t now_wall = std::time(nullptr);
  time_t tmp_cutoff =
      now_wall - static_cast<time_t>(opts.tmp_min_age_hours * 3600ULL);
  std::error_code ec;

  // 1. Safe /private/tmp cleanup (rev-*-tests & claude-<uid>/*/* only)
  std::vector<std::string> tmp_candidates;
  if (fs::is_directory("/private/tmp", ec)) {
    for (const auto& ent : fs::directory_iterator("/private/tmp", ec)) {
      if (ec || ent.is_symlink(ec)) continue;
      std::string fn = ent.path().filename().string();
      if (fn.rfind("rev-", 0) == 0 && fn.size() > 6 &&
          fn.compare(fn.size() - 6, 6, "-tests") == 0) {
        tmp_candidates.push_back(ent.path().string());
      }
    }
  }
  const std::string claude_tmp =
      "/private/tmp/claude-" + std::to_string(getuid());
  if (fs::is_directory(claude_tmp, ec) && !fs::is_symlink(claude_tmp, ec)) {
    for (const auto& proj : fs::directory_iterator(claude_tmp, ec)) {
      if (ec || proj.is_symlink(ec) || !proj.is_directory(ec)) continue;
      for (const auto& sub : fs::directory_iterator(proj.path(), ec)) {
        if (ec || sub.is_symlink(ec)) continue;
        tmp_candidates.push_back(sub.path().string());
      }
    }
  }

  for (const auto& p : tmp_candidates) {
    if (fs::is_symlink(p, ec)) continue;
    if (path_mentioned_in_blob(active_blob, p)) continue;
    if (dir_has_recent_mtime(p, tmp_cutoff)) continue;
    if (opts.dry_run) {
      report.tmp_removed += 1;
      report.estimated_bytes += dir_size_bytes(p);
    } else {
      fs::remove_all(p, ec);
      if (!ec) report.tmp_removed += 1;
    }
  }

  // 2. Stale Chrome code_sign_clone entries when Chrome isn't running
  if (!chrome_running && fs::is_directory("/private/var/folders", ec) &&
      !fs::is_symlink("/private/var/folders", ec)) {
    for (const auto& l1 :
         fs::directory_iterator("/private/var/folders", ec)) {
      if (ec || l1.is_symlink(ec) || !l1.is_directory(ec)) continue;
      for (const auto& l2 : fs::directory_iterator(l1.path(), ec)) {
        if (ec || l2.is_symlink(ec) || !l2.is_directory(ec)) continue;
        fs::path clone_dir =
            l2.path() / "X" / "com.google.Chrome.code_sign_clone";
        if (fs::is_symlink(clone_dir, ec) || !fs::is_directory(clone_dir, ec)) {
          continue;
        }
        for (const auto& ent : fs::directory_iterator(clone_dir, ec)) {
          if (ec || ent.is_symlink(ec)) continue;
          if (opts.dry_run) {
            report.chrome_clones_removed += 1;
          } else {
            fs::remove_all(ent.path(), ec);
            if (!ec) report.chrome_clones_removed += 1;
          }
        }
      }
    }
  }

  // 3. Clean, pushed, idle git worktrees
  if (opts.include_worktrees) {
    WorktreeSizeMode mode =
        opts.dry_run ? WorktreeSizeMode::SafeOnly : WorktreeSizeMode::None;
    WorktreeAuditSummary audit = audit_worktrees(
        opts.worktree_min_age_hours, mode, opts.extra_worktree_roots);
    if (opts.dry_run) {
      report.worktrees_removed = audit.safe_count;
      report.estimated_bytes += audit.safe_bytes;
    } else if (audit.safe_count > 0) {
      WorktreePruneResult pr = prune_worktrees(audit, false);
      report.worktrees_removed = pr.removed_count;
    }
  }

  // 4. Rebuildable caches (trigger automatically if include_caches or disk < 150 GB)
  const char* home_c = std::getenv("HOME");
  if (home_c && (opts.include_caches || avail_before < 150ULL * kGB)) {
    std::string home = home_c;
    std::vector<std::string> cache_targets = {
        home + "/Library/Caches/ms-playwright-mcp",
        home + "/Library/Caches/ms-playwright",
        home + "/Library/Caches/pnpm",
        home + "/Library/Caches/Homebrew",
        home + "/Library/Caches/Codex",
        home + "/Library/Caches/bun",
        home + "/Library/Caches/Cypress",
        home + "/Library/Caches/kimi-desktop-updater",
        home + "/Library/Caches/t3code-updater",
        home + "/.npm/_cacache",
        home + "/.npm/_logs",
        home + "/.bun/install/cache",
        home + "/.cache/uv",
        home + "/.cache/puppeteer",
        home + "/.cache/chrome-devtools-mcp",
    };
    if (!chrome_running) {
      cache_targets.push_back(home + "/Library/Caches/Google");
    }

    std::vector<std::string> existing_caches;
    existing_caches.reserve(cache_targets.size());
    for (const auto& cp : cache_targets) {
      auto st = fs::symlink_status(cp, ec);
      if (!ec && st.type() != fs::file_type::symlink &&
          st.type() != fs::file_type::not_found) {
        existing_caches.push_back(cp);
      }
    }

    if (opts.dry_run) {
      report.cache_dirs_removed += static_cast<int>(existing_caches.size());
      if (!existing_caches.empty()) {
        std::atomic<size_t> next_c{0};
        std::atomic<uint64_t> cache_bytes{0};
        size_t n_threads = std::min<size_t>(4, existing_caches.size());
        std::vector<std::thread> cworkers;
        cworkers.reserve(n_threads);
        for (size_t t = 0; t < n_threads; ++t) {
          cworkers.emplace_back([&]() {
            while (true) {
              size_t i = next_c.fetch_add(1, std::memory_order_relaxed);
              if (i >= existing_caches.size()) break;
              cache_bytes.fetch_add(dir_size_bytes(existing_caches[i]),
                                    std::memory_order_relaxed);
            }
          });
        }
        for (auto& w : cworkers) w.join();
        report.estimated_bytes += cache_bytes.load();
      }
    } else {
      for (const auto& cp : existing_caches) {
        fs::remove_all(cp, ec);
        if (!ec) report.cache_dirs_removed += 1;
      }
    }
  }

  // 5. simctl unavailable + pnpm store prune + brew cleanup
  if (!opts.dry_run && opts.include_pnpm_brew) {
    std::string out;
    if (run_command_capture({"/usr/bin/xcrun", "simctl", "delete", "unavailable"},
                            out, rc, 30000) &&
        rc == 0) {
      report.ran_simctl_unavailable = true;
    }
    std::string pnpm = resolve_pnpm();
    if (!pnpm.empty() &&
        run_command_capture({pnpm, "store", "prune"}, out, rc, 120000) &&
        rc == 0) {
      report.ran_pnpm_prune = true;
    }
    std::string brew = resolve_brew();
    if (!brew.empty() &&
        run_command_capture({brew, "cleanup", "-s"}, out, rc, 120000) &&
        rc == 0) {
      report.ran_brew_cleanup = true;
    }
  }

  if (!opts.dry_run) {
    usleep(500000);
    uint64_t avail_after = disk_avail_now();
    if (avail_after > avail_before) {
      report.freed_bytes = avail_after - avail_before;
    }
  }

  std::ostringstream os;
  if (opts.dry_run) {
    os << "[Dry Run] Would clean " << report.tmp_removed << " tmp dirs, "
       << report.chrome_clones_removed << " Chrome clones, "
       << report.worktrees_removed << " worktrees, "
       << report.cache_dirs_removed << " cache dirs (~"
       << format_bytes(report.estimated_bytes) << ")";
  } else {
    os << "Freed " << format_bytes(report.freed_bytes) << " ("
       << report.tmp_removed << " tmp, " << report.chrome_clones_removed
       << " clones, " << report.worktrees_removed << " worktrees, "
       << report.cache_dirs_removed << " caches)";
  }
  report.summary = os.str();

  if (!opts.dry_run && home_c) {
    std::string log_dir = std::string(home_c) + "/Library/Logs";
    fs::create_directories(log_dir, ec);
    std::ofstream logf(log_dir + "/SysGuard-janitor.log", std::ios::app);
    if (logf) {
      std::time_t t = std::time(nullptr);
      char tbuf[32];
      struct tm lt{};
      localtime_r(&t, &lt);
      std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &lt);
      logf << "[" << tbuf << "] " << report.summary << "\n";
    }
  }

  return report;
}

const char* worktree_status_label(WorktreeStatus s) {
  switch (s) {
    case WorktreeStatus::SafeToPrune:
      return "SAFE";
    case WorktreeStatus::Active:
      return "ACTIVE";
    case WorktreeStatus::Recent:
      return "RECENT";
    case WorktreeStatus::Dirty:
      return "DIRTY";
    case WorktreeStatus::Unpushed:
      return "UNPUSHED";
    case WorktreeStatus::NotWorktree:
      return "OTHER";
    case WorktreeStatus::Error:
      return "ERROR";
  }
  return "UNKNOWN";
}

}  // namespace sysguard
