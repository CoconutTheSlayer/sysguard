#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sysguard {

namespace thresholds {

inline constexpr uint64_t kFseventsdWarnBytes = 512ULL * 1024ULL * 1024ULL;
inline constexpr uint64_t kFseventsdCritBytes = 1536ULL * 1024ULL * 1024ULL;
inline constexpr uint64_t kFseventsdAutoHealBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr double kFseventsdWarnCpuPct = 60.0;
inline constexpr double kFseventsdCritCpuPct = 90.0;

inline constexpr uint64_t kSwapWarnBytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr uint64_t kSwapCritBytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;

inline constexpr int kMemFreeWarnPct = 35;
inline constexpr int kMemFreeCritPct = 20;

inline constexpr uint64_t kDiskWarnAvailBytes = 100ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr uint64_t kDiskCritAvailBytes = 50ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr double kDiskWarnUsedPct = 92.0;
inline constexpr double kDiskCritUsedPct = 96.0;

inline constexpr double kProcDiskWriteWarnMbS = 50.0;
inline constexpr double kHwDiskWriteWarnMbS = 150.0;
inline constexpr double kHwDiskWriteBadgeMbS = 30.0;

}  // namespace thresholds

struct SysGuardConfig {
  uint64_t fseventsd_warn_bytes = thresholds::kFseventsdWarnBytes;
  uint64_t fseventsd_crit_bytes = thresholds::kFseventsdCritBytes;
  uint64_t fseventsd_auto_heal_bytes = thresholds::kFseventsdAutoHealBytes;
  double fseventsd_warn_cpu_pct = thresholds::kFseventsdWarnCpuPct;
  double fseventsd_crit_cpu_pct = thresholds::kFseventsdCritCpuPct;

  uint64_t swap_warn_bytes = thresholds::kSwapWarnBytes;
  uint64_t swap_crit_bytes = thresholds::kSwapCritBytes;

  int mem_free_warn_pct = thresholds::kMemFreeWarnPct;
  int mem_free_crit_pct = thresholds::kMemFreeCritPct;

  uint64_t disk_warn_avail_bytes = thresholds::kDiskWarnAvailBytes;
  uint64_t disk_crit_avail_bytes = thresholds::kDiskCritAvailBytes;
  double disk_warn_used_pct = thresholds::kDiskWarnUsedPct;
  double disk_crit_used_pct = thresholds::kDiskCritUsedPct;

  double proc_disk_write_warn_mb_s = thresholds::kProcDiskWriteWarnMbS;
  double hw_disk_write_warn_mb_s = thresholds::kHwDiskWriteWarnMbS;
  double hw_disk_write_badge_mb_s = thresholds::kHwDiskWriteBadgeMbS;

  std::string podman_default_machine = "podman-machine-default";
  std::vector<std::string> extra_worktree_roots;
};

struct DailyWriteState {
  int yyyymmdd = 0;
  uint64_t start_written_bytes = 0;
  bool valid = false;
};

[[nodiscard]] std::string default_config_path();
[[nodiscard]] SysGuardConfig load_config(
    const std::string& path = default_config_path());
bool ensure_default_config_file(
    const std::string& path = default_config_path());

[[nodiscard]] std::string default_daily_state_path();
[[nodiscard]] DailyWriteState load_daily_write_state(const std::string& path);
bool save_daily_write_state(const std::string& path,
                            int yyyymmdd,
                            uint64_t start_written_bytes);

}  // namespace sysguard
