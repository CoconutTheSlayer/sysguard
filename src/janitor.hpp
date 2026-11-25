#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sysguard {

enum class WorktreeStatus {
  SafeToPrune,
  Active,
  Recent,
  Dirty,
  Unpushed,
  NotWorktree,
  Error,
};

enum class WorktreeSizeMode {
  None,
  SafeOnly,
  All,
};

struct WorktreeInfo {
  std::string path;
  std::string parent_repo;
  std::string branch;
  WorktreeStatus status = WorktreeStatus::Error;
  uint64_t size_bytes = 0;
  uint64_t age_hours = 0;
  std::string reason;
};

struct WorktreeAuditSummary {
  std::vector<WorktreeInfo> items;
  int safe_count = 0;
  uint64_t safe_bytes = 0;
  int dirty_count = 0;
  int unpushed_count = 0;
  int active_count = 0;
  int recent_count = 0;
  int non_worktree_count = 0;
  int error_count = 0;
  uint64_t total_bytes = 0;
};

struct WorktreePruneResult {
  int removed_count = 0;
  int failed_count = 0;
  uint64_t freed_bytes = 0;
  bool ran_pnpm_prune = false;
  std::string detail;
};

struct JanitorOptions {
  bool dry_run = false;
  uint64_t tmp_min_age_hours = 48;
  uint64_t worktree_min_age_hours = 72;
  bool include_caches = true;
  bool include_worktrees = true;
  bool include_pnpm_brew = true;
  std::vector<std::string> extra_worktree_roots;
};

struct JanitorReport {
  uint64_t freed_bytes = 0;
  uint64_t estimated_bytes = 0;
  int tmp_removed = 0;
  int chrome_clones_removed = 0;
  int worktrees_removed = 0;
  int cache_dirs_removed = 0;
  bool ran_pnpm_prune = false;
  bool ran_brew_cleanup = false;
  bool ran_simctl_unavailable = false;
  std::string summary;
};

[[nodiscard]] std::vector<std::string> discover_worktree_candidates(
    const std::vector<std::string>& extra_roots = {});

[[nodiscard]] WorktreeAuditSummary audit_worktrees(
    uint64_t min_age_hours = 24,
    WorktreeSizeMode size_mode = WorktreeSizeMode::All,
    const std::vector<std::string>& extra_roots = {});

[[nodiscard]] WorktreeAuditSummary audit_worktrees(uint64_t min_age_hours,
                                                   bool compute_sizes);

[[nodiscard]] WorktreeAuditSummary audit_worktrees_in_candidates(
    const std::vector<std::string>& candidates,
    uint64_t min_age_hours,
    WorktreeSizeMode size_mode,
    const std::string* active_blob_override = nullptr);

WorktreePruneResult prune_worktrees(const WorktreeAuditSummary& audit,
                                    bool run_pnpm_prune = false);

JanitorReport run_dev_janitor(const JanitorOptions& opts);

[[nodiscard]] const char* worktree_status_label(WorktreeStatus s);
[[nodiscard]] uint64_t dir_size_bytes(const std::string& root);
[[nodiscard]] bool path_mentioned_in_blob(const std::string& blob,
                                          const std::string& path);

}  // namespace sysguard
