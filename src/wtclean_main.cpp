#include "config.hpp"
#include "janitor.hpp"
#include "metrics.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace {

void print_help() {
  std::cout
      << "wtclean — Fast parallel Git worktree auditor & safe pruner\n\n"
      << "Usage:\n"
      << "  wtclean [options]\n\n"
      << "Options:\n"
      << "  --prune        Remove SAFE worktrees (clean, pushed, idle > hours)\n"
      << "  --dry-run      Audit only; do not delete anything\n"
      << "  --hours <N>    Minimum idle age in hours (default: 24)\n"
      << "  --path <dir>   Scan only specific worktree or parent dir (repeatable)\n"
      << "  --safe-size    Only measure disk size for SAFE worktrees (fast)\n"
      << "  --no-size      Skip disk size scan for instant status listing\n"
      << "  --pnpm         Also run `pnpm store prune` after pruning\n"
      << "  --json         Emit structured JSON output\n"
      << "  --help         Show this help\n";
}

std::string shorten_path(const std::string& p) {
  const char* home = std::getenv("HOME");
  if (home) {
    std::string h(home);
    if (p.rfind(h, 0) == 0) {
      return "~" + p.substr(h.size());
    }
  }
  return p;
}

std::string json_escape(const std::string& s) {
  std::ostringstream out;
  out << '"';
  for (char raw_c : s) {
    unsigned char c = static_cast<unsigned char>(raw_c);
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
          out << buf;
        } else {
          out << static_cast<char>(c);
        }
        break;
    }
  }
  out << '"';
  return out.str();
}

const char* size_mode_label(sysguard::WorktreeSizeMode m) {
  switch (m) {
    case sysguard::WorktreeSizeMode::All:
      return "all";
    case sysguard::WorktreeSizeMode::SafeOnly:
      return "safe-only";
    case sysguard::WorktreeSizeMode::None:
      return "none";
  }
  return "all";
}

const char* status_color(sysguard::WorktreeStatus s) {
  switch (s) {
    case sysguard::WorktreeStatus::SafeToPrune:
      return "\033[32m";  // green
    case sysguard::WorktreeStatus::Active:
      return "\033[36m";  // cyan
    case sysguard::WorktreeStatus::Recent:
      return "\033[34m";  // blue
    case sysguard::WorktreeStatus::Dirty:
    case sysguard::WorktreeStatus::Unpushed:
      return "\033[33m";  // yellow
    case sysguard::WorktreeStatus::Error:
      return "\033[31m";  // red
    case sysguard::WorktreeStatus::NotWorktree:
      return "\033[90m";
  }
  return "";
}

std::vector<std::string> expand_override_paths(
    const std::vector<std::string>& paths) {
  std::vector<std::string> out;
  std::unordered_set<std::string> seen;
  std::error_code ec;
  for (const auto& raw : paths) {
    fs::path p = fs::path(raw).lexically_normal();
    if (fs::is_regular_file(p / ".git", ec)) {
      std::string s = p.string();
      if (seen.insert(s).second) out.push_back(std::move(s));
    } else if (fs::is_directory(p, ec)) {
      for (const auto& ent : fs::directory_iterator(p, ec)) {
        if (ec) break;
        std::string s = ent.path().lexically_normal().string();
        if (seen.insert(s).second) out.push_back(std::move(s));
      }
    }
  }
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  bool do_prune = false;
  bool dry_run = false;
  auto size_mode = sysguard::WorktreeSizeMode::All;
  bool run_pnpm = false;
  bool json_out = false;
  uint64_t hours = 24;
  std::vector<std::string> override_paths;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      print_help();
      return 0;
    } else if (arg == "--prune") {
      do_prune = true;
    } else if (arg == "--dry-run") {
      dry_run = true;
    } else if (arg == "--safe-size") {
      size_mode = sysguard::WorktreeSizeMode::SafeOnly;
    } else if (arg == "--no-size") {
      size_mode = sysguard::WorktreeSizeMode::None;
    } else if (arg == "--pnpm") {
      run_pnpm = true;
    } else if (arg == "--json") {
      json_out = true;
    } else if (arg == "--hours" && i + 1 < argc) {
      hours = static_cast<uint64_t>(std::strtoull(argv[++i], nullptr, 10));
    } else if (arg == "--path" && i + 1 < argc) {
      override_paths.emplace_back(argv[++i]);
    } else {
      std::cerr << "Unknown option: " << arg << "\n";
      print_help();
      return 1;
    }
  }

  sysguard::WorktreeAuditSummary audit;
  if (!override_paths.empty()) {
    audit = sysguard::audit_worktrees_in_candidates(
        expand_override_paths(override_paths), hours, size_mode, nullptr);
  } else {
    sysguard::SysGuardConfig cfg = sysguard::load_config();
    audit = sysguard::audit_worktrees(hours, size_mode, cfg.extra_worktree_roots);
  }

  bool ran_prune = false;
  sysguard::WorktreePruneResult prune_res;
  if (do_prune && !dry_run && audit.safe_count > 0) {
    prune_res = sysguard::prune_worktrees(audit, run_pnpm);
    ran_prune = true;
  }

  if (json_out) {
    std::cout << "{\n"
              << "  \"summary\": {\n"
              << "    \"total\": " << audit.items.size() << ",\n"
              << "    \"safe\": " << audit.safe_count << ",\n"
              << "    \"active\": " << audit.active_count << ",\n"
              << "    \"recent\": " << audit.recent_count << ",\n"
              << "    \"dirty\": " << audit.dirty_count << ",\n"
              << "    \"unpushed\": " << audit.unpushed_count << ",\n"
              << "    \"error\": " << audit.error_count << ",\n"
              << "    \"total_bytes\": " << audit.total_bytes << ",\n"
              << "    \"safe_bytes\": " << audit.safe_bytes << ",\n"
              << "    \"size_mode\": " << json_escape(size_mode_label(size_mode)) << "\n"
              << "  },\n"
              << "  \"worktrees\": [\n";
    for (size_t i = 0; i < audit.items.size(); ++i) {
      const auto& w = audit.items[i];
      std::cout << "    {\"path\": " << json_escape(w.path)
                << ", \"parent_repo\": " << json_escape(w.parent_repo)
                << ", \"branch\": " << json_escape(w.branch.empty() ? "HEAD" : w.branch)
                << ", \"status\": " << json_escape(sysguard::worktree_status_label(w.status))
                << ", \"reason\": " << json_escape(w.reason)
                << ", \"age_hours\": " << w.age_hours
                << ", \"size_bytes\": " << w.size_bytes << "}"
                << (i + 1 < audit.items.size() ? "," : "") << "\n";
    }
    std::cout << "  ]";
    if (ran_prune) {
      std::cout << ",\n  \"prune\": {\"removed\": " << prune_res.removed_count
                << ", \"failed\": " << prune_res.failed_count
                << ", \"freed_bytes\": " << prune_res.freed_bytes
                << ", \"ran_pnpm_prune\": "
                << (prune_res.ran_pnpm_prune ? "true" : "false")
                << ", \"detail\": " << json_escape(prune_res.detail) << "}";
    }
    std::cout << "\n}\n";
    return 0;
  }

  const bool tty = isatty(STDOUT_FILENO) != 0;
  const bool show_header_size = (size_mode != sysguard::WorktreeSizeMode::None);

  std::cout << std::left << std::setw(10) << "STATUS"
            << std::right << std::setw(10) << (show_header_size ? "SIZE" : "-")
            << std::setw(7) << "AGE" << "  "
            << std::left << std::setw(30) << "REPO / BRANCH"
            << "PATH\n";
  std::cout << std::string(86, '-') << "\n";

  for (const auto& item : audit.items) {
    std::string repo = item.parent_repo.empty()
                           ? "?"
                           : fs::path(item.parent_repo).filename().string();
    std::string br = item.branch.empty() ? "HEAD" : item.branch;
    std::string rb = repo + ":" + br;
    if (rb.size() > 28) rb = rb.substr(0, 27) + "~";

    const bool show_row_size =
        (size_mode == sysguard::WorktreeSizeMode::All) ||
        (size_mode == sysguard::WorktreeSizeMode::SafeOnly &&
         item.status == sysguard::WorktreeStatus::SafeToPrune);
    std::string sz = show_row_size
                         ? sysguard::format_bytes_compact(item.size_bytes)
                         : "-";
    std::string age = std::to_string(item.age_hours) + "h";

    if (tty) std::cout << status_color(item.status);
    std::cout << std::left << std::setw(10)
              << sysguard::worktree_status_label(item.status);
    if (tty) std::cout << "\033[0m";

    std::cout << std::right << std::setw(10) << sz << std::setw(7) << age
              << "  " << std::left << std::setw(30) << rb
              << shorten_path(item.path) << "\n";
  }

  std::string size_summary = "size skipped";
  if (size_mode == sysguard::WorktreeSizeMode::All) {
    size_summary = sysguard::format_bytes(audit.total_bytes);
  } else if (size_mode == sysguard::WorktreeSizeMode::SafeOnly) {
    size_summary = "safe-only size";
  }

  std::cout << "\nSummary: total=" << audit.items.size()
            << " (" << size_summary << ")"
            << " | SAFE=" << audit.safe_count
            << (show_header_size ? (" (" + sysguard::format_bytes(audit.safe_bytes) + ")") : "")
            << " | ACTIVE=" << audit.active_count
            << " | RECENT=" << audit.recent_count
            << " | DIRTY=" << audit.dirty_count
            << " | UNPUSHED=" << audit.unpushed_count << "\n";

  if (do_prune && !dry_run) {
    if (!ran_prune) {
      std::cout << "Nothing safe to prune.\n";
      return 0;
    }
    std::cout << prune_res.detail;
    if (prune_res.ran_pnpm_prune) std::cout << " + pnpm store pruned";
    std::cout << "\n";
  } else if (do_prune && dry_run) {
    std::cout << "[Dry Run] Would prune " << audit.safe_count
              << " SAFE worktree(s).\n";
  }

  return 0;
}
