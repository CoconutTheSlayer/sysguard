#include "janitor.hpp"
#include "metrics.hpp"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using namespace sysguard;

namespace {

constexpr uint64_t kMB = 1024ULL * 1024ULL;
constexpr uint64_t kGB = 1024ULL * 1024ULL * 1024ULL;

void test_group_classification() {
  assert(classify_group_name(
             "/Applications/Opera.app/Contents/Frameworks/Opera Helper.app/Contents/MacOS/Opera Helper",
             "Opera Helper --type=renderer") == "Opera");

  assert(classify_group_name(
             "/Applications/T3 Code (Beta).app/Contents/Frameworks/T3 Code (Beta) Helper.app/Contents/MacOS/T3 Code (Beta) Helper",
             "T3 Code") == "T3 Code (Beta)");

  assert(classify_group_name(
             "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
             "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/Users/dev/.cache/dev-browser --remote-debugging-port=9223") ==
         "Chrome (dev-browser)");

  assert(classify_group_name(
             "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
             "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome") ==
         "Google Chrome");

  assert(classify_group_name(
             "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/FSEvents.framework/Versions/A/Support/fseventsd",
             "fseventsd") == "fseventsd");
}

void test_evaluate_alerts() {
  FastMetrics fast;
  fast.ram_total_bytes = 64ULL * kGB;
  fast.ram_used_bytes = 20ULL * kGB;
  fast.swap_used_bytes = 5ULL * kGB;
  fast.memory_free_pct = 70;
  fast.disk_total_bytes = 2000ULL * kGB;
  fast.disk_avail_bytes = 70ULL * kGB;
  fast.disk_used_pct = 96.5;

  DeepMetrics deep;
  deep.fseventsd_rss_bytes = 600ULL * kMB;
  deep.fseventsd_cpu_pct = 15.0;

  std::vector<ProcEntry> procs;
  auto alerts = evaluate_alerts(fast, deep, procs);

  auto find_alert = [&](AlertKind k) -> const Alert* {
    for (const auto& a : alerts) {
      if (a.kind == k) return &a;
    }
    return nullptr;
  };

  assert(find_alert(AlertKind::FseventsdLeak) != nullptr);
  assert(find_alert(AlertKind::FseventsdLeak)->severity == AlertSeverity::Warn);
  assert(find_alert(AlertKind::HighSwap) != nullptr);
  assert(find_alert(AlertKind::HighSwap)->severity == AlertSeverity::Warn);
  assert(find_alert(AlertKind::LowDisk) != nullptr);
  assert(find_alert(AlertKind::LowDisk)->severity == AlertSeverity::Crit);

  deep.fseventsd_rss_bytes = 2ULL * kGB;
  fast.swap_used_bytes = 10ULL * kGB;
  fast.disk_avail_bytes = 70ULL * kGB;
  fast.disk_used_pct = 93.0;
  alerts = evaluate_alerts(fast, deep, procs);
  assert(find_alert(AlertKind::FseventsdLeak)->severity == AlertSeverity::Crit);
  assert(find_alert(AlertKind::HighSwap)->severity == AlertSeverity::Crit);
  assert(find_alert(AlertKind::LowDisk)->severity == AlertSeverity::Warn);
}

void test_orphan_candidate_rules() {
  std::unordered_map<pid_t, ProcEntry> by_pid;

  ProcEntry vite;
  vite.pid = 1001;
  vite.ppid = 1;
  vite.uid = 501;
  vite.uptime_sec = 3 * 3600;
  vite.comm = "/usr/local/bin/node";
  vite.args = "node ./node_modules/.bin/../vite/bin/vite.js dev --port 5391 --strictPort";
  by_pid[vite.pid] = vite;

  OrphanKind kind{};
  std::string label;
  bool auto_reap = false;
  bool sigkill = false;
  assert(is_orphan_candidate(vite, by_pid, 7200, kind, label, auto_reap, sigkill));
  assert(kind == OrphanKind::DevServer);
  assert(auto_reap == true);
  assert(sigkill == false);

  ProcEntry young_vite = vite;
  young_vite.uptime_sec = 600;
  assert(!is_orphan_candidate(young_vite, by_pid, 7200, kind, label, auto_reap, sigkill));

  ProcEntry py;
  py.pid = 1002;
  py.ppid = 1;
  py.uid = 501;
  py.uptime_sec = 4 * 3600;
  py.comm = "/Applications/Xcode.app/.../Python";
  py.args = "Python -I -c import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); while True: time.sleep(1)";
  assert(is_orphan_candidate(py, by_pid, 7200, kind, label, auto_reap, sigkill));
  assert(kind == OrphanKind::StuckLoop);
  assert(sigkill == true);

  ProcEntry tmp_pg;
  tmp_pg.pid = 1003;
  tmp_pg.ppid = 1;
  tmp_pg.uid = 501;
  tmp_pg.uptime_sec = 5 * 3600;
  tmp_pg.comm = "/opt/homebrew/Cellar/postgresql@17/17.12/bin/postgres";
  tmp_pg.args = "/opt/homebrew/Cellar/postgresql@17/17.12/bin/postgres -D /private/tmp/claude-501/work/pg -p 55480";
  assert(is_orphan_candidate(tmp_pg, by_pid, 7200, kind, label, auto_reap, sigkill));
  assert(kind == OrphanKind::TempPostgres);

  ProcEntry active_pg = tmp_pg;
  active_pg.args = "/opt/homebrew/Cellar/postgresql@16/16.16/bin/postgres -D /Users/dev/Projects/my-worktrees/.db-instance/pg/data -p 55451";
  assert(!is_orphan_candidate(active_pg, by_pid, 7200, kind, label, auto_reap, sigkill));

  ProcEntry chrome;
  chrome.pid = 1004;
  chrome.ppid = 1;
  chrome.uid = 501;
  chrome.uptime_sec = 10 * 3600;
  chrome.comm = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  chrome.args = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/Users/dev/.cache/dev-browser --remote-debugging-port=9223";
  assert(is_orphan_candidate(chrome, by_pid, 7200, kind, label, auto_reap, sigkill));
  assert(kind == OrphanKind::IdleDebugChrome);
  assert(auto_reap == false);
}

void test_formatters() {
  assert(format_bytes(512) == "512 B");
  assert(format_bytes(2048) == "2 KB");
  assert(format_bytes(1536ULL * 1024ULL) == "1.5 MB");
  assert(format_bytes(3ULL * kGB) == "3.00 GB");

  assert(format_bytes_compact(512ULL * 1024ULL) == "512K");
  assert(format_bytes_compact(100ULL * kMB) == "100M");
  assert(format_bytes_compact(1536ULL * kMB) == "1.5G");
  assert(format_bytes_compact(12ULL * kGB) == "12G");

  assert(format_uptime(45) == "45s");
  assert(format_uptime(180) == "3m");
  assert(format_uptime(3665) == "1h 1m");
  assert(format_uptime(90000) == "1d 1h");
}

void test_extract_flag_value() {
  assert(extract_flag_value("/my-Dev/postgres -D /real/data -p 5432", "-D") ==
         "/real/data");
  assert(extract_flag_value("app -Debug -D /real/data", "-D") == "/real/data");
  assert(extract_flag_value("app -Debug", "-D").empty());
  assert(extract_flag_value("app -D", "-D").empty());
  assert(extract_flag_value(
             "chrome --user-data-dir=/tmp/prof --remote-debugging-port=9223",
             "--user-data-dir=") == "/tmp/prof");
  assert(extract_flag_value("cloudflared tunnel --hostname dev.example.com",
                            "--hostname") == "dev.example.com");
}

void test_run_command_capture_and_timeout() {
  std::string out;
  int rc = -1;
  bool ok_echo = run_command_capture({"/bin/echo", "sysguard-ok"}, out, rc, 5000);
  assert(ok_echo);
  assert(rc == 0);
  assert(out == "sysguard-ok\n");

  bool ok_false = run_command_capture({"/usr/bin/false"}, out, rc, 5000);
  assert(ok_false);
  assert(rc != 0);

  bool ok_missing =
      run_command_capture({"/nonexistent/sysguard_missing_bin"}, out, rc, 5000);
  assert(!ok_missing);

  auto t0 = std::chrono::steady_clock::now();
  bool ok_sleep = run_command_capture({"/bin/sleep", "5"}, out, rc, 150);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0)
                .count();
  assert(!ok_sleep);
  assert(ms < 1000);

  // Process-group timeout test: backgrounded descendant holding stdout must be killed
  auto tg0 = std::chrono::steady_clock::now();
  bool ok_pg = run_command_capture({"/bin/sh", "-c", "sleep 5 & wait"}, out, rc, 150);
  auto pg_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - tg0)
                   .count();
  assert(!ok_pg);
  assert(pg_ms < 1000);

  // Concurrent spawn stress test: verifies FD_CLOEXEC + POSIX_SPAWN_CLOEXEC_DEFAULT
  std::vector<std::thread> threads;
  for (int t = 0; t < 8; ++t) {
    threads.emplace_back([t]() {
      for (int i = 0; i < 10; ++i) {
        std::string msg = "t" + std::to_string(t) + "-" + std::to_string(i);
        std::string tout;
        int trc = -1;
        bool ok_t = run_command_capture({"/bin/echo", msg}, tout, trc, 5000);
        assert(ok_t);
        assert(trc == 0);
        assert(tout == msg + "\n");
      }
    });
  }
  for (auto& th : threads) th.join();
}

void test_path_boundary_matching() {
  assert(!path_mentioned_in_blob("/tmp/wt/foo-2\n", "/tmp/wt/foo"));
  assert(!path_mentioned_in_blob("/tmp/wt/foobar\n", "/tmp/wt/foo"));
  assert(path_mentioned_in_blob("/tmp/wt/foo\n", "/tmp/wt/foo"));
  assert(path_mentioned_in_blob("/tmp/wt/foo/src\n", "/tmp/wt/foo"));
  assert(path_mentioned_in_blob("node /tmp/wt/foo/index.js", "/tmp/wt/foo"));
  assert(path_mentioned_in_blob("--cwd=/tmp/wt/foo/", "/tmp/wt/foo"));
}

struct TempDirGuard {
  std::string path;
  ~TempDirGuard() {
    if (!path.empty()) {
      std::error_code ec;
      fs::remove_all(path, ec);
    }
  }
};

void backdate_path_hours(const std::string& p, long hours) {
  struct timeval tvs[2];
  time_t ts = std::time(nullptr) - hours * 3600L;
  tvs[0].tv_sec = ts;
  tvs[0].tv_usec = 0;
  tvs[1].tv_sec = ts;
  tvs[1].tv_usec = 0;
  utimes(p.c_str(), tvs);
}

void backdate_worktree(const std::string& wt, const std::string& gitdir,
                       long hours) {
  backdate_path_hours(wt, hours);
  backdate_path_hours(wt + "/.git", hours);
  if (!gitdir.empty()) {
    backdate_path_hours(gitdir + "/index", hours);
  }
}

void write_file_bytes(const std::string& p, size_t count, char fill) {
  std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
  assert(static_cast<bool>(ofs));
  std::string data(count, fill);
  ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
  ofs.close();
}

void run_git_ok(const std::vector<std::string>& args) {
  std::string out;
  int rc = -1;
  bool ok = run_command_capture(args, out, rc, 15000);
  if (!ok || rc != 0) {
    std::cerr << "git failed (" << rc << "): " << out << "\n";
    assert(false);
  }
}

void test_worktree_audit_and_prune_isolated() {
  char tmpl[] = "/tmp/sysguard-test-XXXXXX";
  char* dir = mkdtemp(tmpl);
  assert(dir != nullptr);
  TempDirGuard guard{std::string(dir)};

  const std::string root = guard.path;
  const std::string origin = root + "/origin.git";
  const std::string repo = root + "/repo";
  const std::string wt_safe = root + "/wt-safe";
  const std::string wt_toctou = root + "/wt-toctou";
  const std::string wt_toctou_commit = root + "/wt-toctou-commit";
  const std::string wt_dirty = root + "/wt-dirty";
  const std::string wt_unpushed = root + "/wt-unpushed";
  const std::string wt_recent = root + "/wt-recent";

  run_git_ok({"/usr/bin/git", "init", "--bare", "-b", "main", origin});
  run_git_ok({"/usr/bin/git", "init", "-b", "main", repo});
  run_git_ok({"/usr/bin/git", "-C", repo, "config", "user.name", "SysGuard Test"});
  run_git_ok({"/usr/bin/git", "-C", repo, "config", "user.email", "test@local"});
  run_git_ok({"/usr/bin/git", "-C", repo, "config", "commit.gpgsign", "false"});
  run_git_ok({"/usr/bin/git", "-C", repo, "remote", "add", "origin", origin});

  write_file_bytes(repo + "/README.md", 64, 'x');
  run_git_ok({"/usr/bin/git", "-C", repo, "add", "README.md"});
  run_git_ok({"/usr/bin/git", "-C", repo, "commit", "-m", "init"});
  run_git_ok({"/usr/bin/git", "-C", repo, "push", "-u", "origin", "main"});

  // 1. Safe worktree with two hardlinked 64 KB files
  run_git_ok({"/usr/bin/git", "-C", repo, "worktree", "add", "-b", "br-safe",
              wt_safe, "main"});
  write_file_bytes(wt_safe + "/h1.bin", 65536, 'A');
  write_file_bytes(wt_safe + "/h2.bin", 65536, 'A');
  run_git_ok({"/usr/bin/git", "-C", wt_safe, "add", "h1.bin", "h2.bin"});
  run_git_ok({"/usr/bin/git", "-C", wt_safe, "commit", "-m", "add payload"});
  run_git_ok({"/usr/bin/git", "-C", wt_safe, "push", "-u", "origin", "br-safe"});
  int urc = unlink((wt_safe + "/h2.bin").c_str());
  assert(urc == 0);
  int lrc =
      link((wt_safe + "/h1.bin").c_str(), (wt_safe + "/h2.bin").c_str());
  assert(lrc == 0);
  // Confirm hardlink dedup directly on wt_safe
  uint64_t wt_safe_sz = dir_size_bytes(wt_safe);
  assert(wt_safe_sz >= 65536 && wt_safe_sz < 100000);
  backdate_worktree(wt_safe, repo + "/.git/worktrees/wt-safe", 48);

  // 2. Dirty worktree
  run_git_ok({"/usr/bin/git", "-C", repo, "worktree", "add", "-b", "br-dirty",
              wt_dirty, "main"});
  run_git_ok({"/usr/bin/git", "-C", wt_dirty, "push", "-u", "origin", "br-dirty"});
  write_file_bytes(wt_dirty + "/dirty.txt", 32, 'D');
  backdate_worktree(wt_dirty, repo + "/.git/worktrees/wt-dirty", 48);

  // 3. Unpushed worktree
  run_git_ok({"/usr/bin/git", "-C", repo, "worktree", "add", "-b",
              "br-unpushed", wt_unpushed, "main"});
  write_file_bytes(wt_unpushed + "/local.txt", 32, 'U');
  run_git_ok({"/usr/bin/git", "-C", wt_unpushed, "add", "local.txt"});
  run_git_ok({"/usr/bin/git", "-C", wt_unpushed, "commit", "-m", "unpushed"});
  backdate_worktree(wt_unpushed, repo + "/.git/worktrees/wt-unpushed", 48);

  // 4. Recent worktree
  run_git_ok({"/usr/bin/git", "-C", repo, "worktree", "add", "-b", "br-recent",
              wt_recent, "main"});
  run_git_ok({"/usr/bin/git", "-C", wt_recent, "push", "-u", "origin", "br-recent"});

  // 5. Worktree initially safe at audit time, dirtied before prune (TOCTOU test)
  run_git_ok({"/usr/bin/git", "-C", repo, "worktree", "add", "-b", "br-toctou",
              wt_toctou, "main"});
  run_git_ok({"/usr/bin/git", "-C", wt_toctou, "push", "-u", "origin", "br-toctou"});
  backdate_worktree(wt_toctou, repo + "/.git/worktrees/wt-toctou", 48);

  // 6. Worktree initially safe at audit time, receives unpushed commit before prune
  run_git_ok({"/usr/bin/git", "-C", repo, "worktree", "add", "-b",
              "br-toctou-commit", wt_toctou_commit, "main"});
  run_git_ok({"/usr/bin/git", "-C", wt_toctou_commit, "push", "-u", "origin",
              "br-toctou-commit"});
  backdate_worktree(wt_toctou_commit,
                    repo + "/.git/worktrees/wt-toctou-commit", 48);

  const std::vector<std::string> cands = {
      wt_safe, wt_toctou, wt_toctou_commit, wt_dirty, wt_unpushed, wt_recent};

  // SafeOnly sizing + classification accuracy
  const std::string prefix_false_blob = wt_safe + "-other\n";
  WorktreeAuditSummary audit = audit_worktrees_in_candidates(
      cands, 24, WorktreeSizeMode::SafeOnly, &prefix_false_blob);
  assert(audit.safe_count == 3);
  assert(audit.dirty_count == 1);
  assert(audit.unpushed_count == 1);
  assert(audit.recent_count == 1);
  assert(audit.error_count == 0);
  for (const auto& item : audit.items) {
    if (item.path == wt_safe) {
      assert(item.status == WorktreeStatus::SafeToPrune);
      assert(item.branch == "br-safe");
      assert(item.size_bytes >= 65536 && item.size_bytes < 100000);
    } else if (item.path == wt_toctou) {
      assert(item.status == WorktreeStatus::SafeToPrune);
      assert(item.branch == "br-toctou");
    } else if (item.path == wt_toctou_commit) {
      assert(item.status == WorktreeStatus::SafeToPrune);
      assert(item.branch == "br-toctou-commit");
    } else {
      assert(item.status != WorktreeStatus::SafeToPrune);
      assert(item.size_bytes == 0);
    }
  }

  // Active process override detection
  const std::string active_blob = "node " + wt_safe + "/index.js\n";
  WorktreeAuditSummary active_audit = audit_worktrees_in_candidates(
      cands, 24, WorktreeSizeMode::None, &active_blob);
  assert(active_audit.safe_count == 2);
  assert(active_audit.active_count == 1);

  // Dirty wt_toctou and add an unpushed commit to wt_toctou_commit after audit
  write_file_bytes(wt_toctou + "/just-edited.txt", 32, 'T');
  write_file_bytes(wt_toctou_commit + "/new-commit.txt", 32, 'C');
  run_git_ok({"/usr/bin/git", "-C", wt_toctou_commit, "add", "new-commit.txt"});
  run_git_ok({"/usr/bin/git", "-C", wt_toctou_commit, "commit", "-m",
              "post-audit local commit"});

  // Selective pruning removes only wt_safe (preserves both TOCTOU worktrees)
  WorktreePruneResult pr = prune_worktrees(audit, false);
  assert(pr.removed_count == 1);
  assert(pr.failed_count == 0);
  assert(!fs::exists(wt_safe));
  assert(fs::exists(wt_toctou));
  assert(fs::exists(wt_toctou_commit));
  assert(fs::exists(wt_dirty));
  assert(fs::exists(wt_unpushed));
  assert(fs::exists(wt_recent));
}

void test_config_and_daily_state() {
  char tmpl[] = "/tmp/sysguard-cfg-XXXXXX";
  char* dir = mkdtemp(tmpl);
  assert(dir != nullptr);
  TempDirGuard guard{std::string(dir)};

  const std::string cfg_path = guard.path + "/config.ini";
  {
    std::ofstream ofs(cfg_path, std::ios::trunc);
    assert(static_cast<bool>(ofs));
    ofs << "# SysGuard custom config\n"
        << "fseventsd_warn_mb = 768\n"
        << "swap_crit_gb = 12\n"
        << "mem_free_crit_pct = 15\n"
        << "hw_disk_write_warn_mb_s = 250.5\n"
        << "podman_default_machine = customvm\n"
        << "extra_worktree_root = /tmp/custom-wt\n"
        << "fseventsd_warn_cpu_pct = invalid_number\n"
        << "unknown_key = ignored\n";
  }

  SysGuardConfig cfg = load_config(cfg_path);
  assert(cfg.fseventsd_warn_bytes == 768ULL * kMB);
  assert(cfg.swap_crit_bytes == 12ULL * kGB);
  assert(cfg.mem_free_crit_pct == 15);
  assert(cfg.hw_disk_write_warn_mb_s == 250.5);
  assert(cfg.podman_default_machine == "customvm");
  assert(cfg.extra_worktree_roots.size() == 1);
  assert(cfg.extra_worktree_roots[0] == "/tmp/custom-wt");
  assert(cfg.fseventsd_warn_cpu_pct == thresholds::kFseventsdWarnCpuPct);

  // ensure_default_config_file creates a default template without overwriting existing files
  const std::string created_cfg = guard.path + "/new/config.ini";
  assert(ensure_default_config_file(created_cfg));
  assert(fs::exists(created_cfg));
  SysGuardConfig def_cfg = load_config(created_cfg);
  assert(def_cfg.podman_default_machine == "podman-machine-default");
  assert(def_cfg.fseventsd_warn_bytes == thresholds::kFseventsdWarnBytes);

  assert(ensure_default_config_file(cfg_path));
  assert(load_config(cfg_path).fseventsd_warn_bytes == 768ULL * kMB);

  const std::string state_path = guard.path + "/nested/daily_io.state";
  assert(save_daily_write_state(state_path, 20261125, 123456789ULL));
  DailyWriteState st = load_daily_write_state(state_path);
  assert(st.valid);
  assert(st.yyyymmdd == 20261125);
  assert(st.start_written_bytes == 123456789ULL);

  // MonitorState restores saved daily baseline if today's date matches & <= hw_now
  std::time_t now = std::time(nullptr);
  struct tm lt{};
  localtime_r(&now, &lt);
  int today =
      (lt.tm_year + 1900) * 10000 + (lt.tm_mon + 1) * 100 + lt.tm_mday;
  uint64_t hw_now = read_hw_disk_write_bytes();
  if (hw_now >= 4096ULL) {
    const std::string mon_state = guard.path + "/mon_daily.state";
    assert(save_daily_write_state(mon_state, today, hw_now - 4096ULL));
    MonitorState m_restored(cfg, mon_state);
    FastMetrics fr = m_restored.sample_fast_metrics();
    assert(fr.hw_disk_written_today_bytes >= 4096ULL);
    m_restored.set_config(def_cfg);
    assert(m_restored.config().podman_default_machine ==
           "podman-machine-default");
    assert(m_restored.config().fseventsd_warn_bytes ==
           thresholds::kFseventsdWarnBytes);
  } else {
    MonitorState m_cfg(cfg, "");
    m_cfg.set_config(def_cfg);
    assert(m_cfg.config().podman_default_machine == "podman-machine-default");
  }
}

void test_history_ring_and_reset_deltas() {
  MonitorState mon({}, "");
  for (int i = 0; i < 5; ++i) {
    FastMetrics f = mon.sample_fast_metrics();
    assert(f.ram_total_bytes > 0);
  }
  auto hist = mon.copy_history();
  assert(hist.size() == 5);
  assert(hist.back().ram_ratio > 0.0f && hist.back().ram_ratio <= 1.0f);

  mon.reset_deltas();
  FastMetrics after_reset = mon.sample_fast_metrics();
  assert(after_reset.hw_disk_write_mb_s == 0.0);
  assert(after_reset.self_cpu_pct == 0.0);
  assert(mon.copy_history().size() == 6);
}

void test_live_sampling_and_v2() {
  const bool in_ci = (std::getenv("CI") != nullptr);
  uint64_t hw_bytes = read_hw_disk_write_bytes();
  if (!in_ci) {
    assert(hw_bytes > 0);
  }

  MonitorState mon({}, "");
  auto t0 = std::chrono::steady_clock::now();
  FastMetrics f = mon.sample_fast_metrics();
  auto t1 = std::chrono::steady_clock::now();
  assert(f.ram_total_bytes >= 2ULL * kGB);
  assert(f.ram_used_bytes > 0 && f.ram_used_bytes <= f.ram_total_bytes);
  assert(f.memory_free_pct >= 0 && f.memory_free_pct <= 100);
  assert(f.disk_total_bytes > 0);
  assert(f.self_footprint_bytes > 0);
  if (!in_ci) {
    assert(f.hw_disk_written_total_bytes > 0);
  }

  DeepMetrics d = mon.sample_deep_metrics(f, 7200, true);
  auto t2 = std::chrono::steady_clock::now();
  assert(d.fseventsd_pid > 0);
  assert(d.fseventsd_rss_bytes > 0);
  assert(d.total_procs > 20);
  assert(!d.top_mem_groups.empty());

  // Warm steady-state sampling (with ps scan & adaptive skipped ps scan)
  auto t3 = std::chrono::steady_clock::now();
  FastMetrics f2 = mon.sample_fast_metrics();
  auto t4 = std::chrono::steady_clock::now();
  DeepMetrics d2 = mon.sample_deep_metrics(f2, 7200, true);
  auto t5 = std::chrono::steady_clock::now();
  DeepMetrics d3 = mon.sample_deep_metrics(f2, 7200, false);
  auto t6 = std::chrono::steady_clock::now();
  assert(d2.total_procs > 20);
  assert(d3.fseventsd_pid == d2.fseventsd_pid);
  assert(!d2.top_mem_groups.empty() && d2.top_mem_groups[0].mem_bytes > 0);

  bool saw_ws = false;
  for (const auto& g : d2.top_mem_groups) {
    if (g.name == "WindowServer" && g.mem_bytes > 0) saw_ws = true;
  }
  for (const auto& g : d2.top_cpu_groups) {
    if (g.name == "WindowServer" && g.mem_bytes > 0) saw_ws = true;
  }
  if (!in_ci) {
    assert(saw_ws);
  }

  const pid_t self_pid = getpid();
  for (const auto& o : d2.orphans) {
    assert(o.pid != self_pid);
  }

  for (const auto& s : d2.listening_services) {
    assert(s.port > 0);
    if (s.name == "cli-proxy-api") assert(s.is_protected);
  }

  auto fast_cold_us =
      std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
  auto deep_cold_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
  auto fast_warm_us =
      std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
  auto deep_warm_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count();
  auto deep_nops_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(t6 - t5).count();

  std::cout << "Live sample OK (fastCold=" << fast_cold_us << "us fastWarm="
            << fast_warm_us << "us deepCold=" << deep_cold_ms
            << "ms deepWarm=" << deep_warm_ms
            << "ms deepWarmNoPs=" << deep_nops_ms
            << "ms): RAM=" << format_bytes(f2.ram_used_bytes) << "/"
            << format_bytes(f2.ram_total_bytes)
            << " Swap=" << format_bytes(f2.swap_used_bytes)
            << " DiskAvail=" << format_bytes(f2.disk_avail_bytes)
            << " HwWriteTotal=" << format_bytes(f2.hw_disk_written_total_bytes)
            << " fseventsd=" << format_bytes(d2.fseventsd_rss_bytes)
            << " ports=" << d2.listening_services.size()
            << " orbRunning=" << d2.vm_status.orbstack_running
            << " podRunning=" << d2.vm_status.podman_running << "\n";
}

void test_worktree_audit_and_janitor_dry_run() {
  auto t0 = std::chrono::steady_clock::now();
  WorktreeAuditSummary audit = audit_worktrees(24, WorktreeSizeMode::None);
  auto t1 = std::chrono::steady_clock::now();
  for (const auto& w : audit.items) {
    if (w.status == WorktreeStatus::SafeToPrune) {
      assert(w.age_hours >= 24);
    }
  }

  JanitorOptions opts;
  opts.dry_run = true;
  opts.worktree_min_age_hours = 72;
  JanitorReport rep = run_dev_janitor(opts);
  auto t2 = std::chrono::steady_clock::now();
  assert(rep.freed_bytes == 0);
  assert(!rep.summary.empty());

  auto audit_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
  auto janitor_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

  std::cout << "Audit OK (" << audit_ms << "ms): worktrees=" << audit.items.size()
            << " safe=" << audit.safe_count
            << " dirty=" << audit.dirty_count
            << " unpushed=" << audit.unpushed_count
            << " | Janitor dry-run (" << janitor_ms << "ms): " << rep.summary
            << "\n";
}

}  // namespace

int main() {
  test_group_classification();
  test_evaluate_alerts();
  test_orphan_candidate_rules();
  test_formatters();
  test_extract_flag_value();
  test_run_command_capture_and_timeout();
  test_path_boundary_matching();
  test_worktree_audit_and_prune_isolated();
  test_config_and_daily_state();
  test_history_ring_and_reset_deltas();
  test_live_sampling_and_v2();
  test_worktree_audit_and_janitor_dry_run();
  std::cout << "All SysGuard v2 tests passed.\n";
  return 0;
}
