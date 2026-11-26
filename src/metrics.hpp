#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <sys/proc_info.h>
#include <sys/types.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "config.hpp"
#include "subprocess.hpp"

namespace sysguard {

struct FastMetrics {
  uint64_t ram_total_bytes = 0;
  uint64_t ram_used_bytes = 0;
  uint64_t ram_compressed_bytes = 0;
  uint64_t ram_wired_bytes = 0;
  uint64_t ram_free_bytes = 0;

  uint64_t swap_used_bytes = 0;
  uint64_t swap_total_bytes = 0;
  int memory_free_pct = 100;

  double cpu_used_pct = 0.0;

  uint64_t disk_total_bytes = 0;
  uint64_t disk_avail_bytes = 0;
  double disk_used_pct = 0.0;

  uint64_t hw_disk_written_total_bytes = 0;
  uint64_t hw_disk_written_today_bytes = 0;
  double hw_disk_write_mb_s = 0.0;

  uint64_t self_footprint_bytes = 0;
  double self_cpu_pct = 0.0;
  double sample_timestamp_sec = 0.0;
};

struct MetricPoint {
  float ram_ratio = 0.0f;
  float swap_gb = 0.0f;
  float write_mb_s = 0.0f;
};

struct ProcEntry {
  pid_t pid = 0;
  pid_t ppid = 0;
  uid_t uid = 0;
  uint64_t start_sec = 0;
  uint64_t mem_bytes = 0;
  double cpu_pct = 0.0;
  double disk_write_mb_s = 0.0;
  uint64_t session_written_bytes = 0;
  uint64_t uptime_sec = 0;
  std::string comm;
  std::string args;
  std::string cached_group_name;
  bool is_system = false;
};

struct AppGroup {
  std::string name;
  int proc_count = 0;
  uint64_t mem_bytes = 0;
  double cpu_pct = 0.0;
  uint64_t max_uptime_sec = 0;
  std::vector<std::pair<pid_t, uint64_t>> leader_pids;
  std::vector<std::pair<pid_t, uint64_t>> all_pids;
  bool is_system = false;
};

struct DiskWriter {
  pid_t pid = 0;
  uint64_t start_sec = 0;
  std::string name;
  double write_mb_s = 0.0;
  uint64_t session_written_bytes = 0;
  uint64_t mem_bytes = 0;
  bool is_system = false;
};

struct ListeningService {
  pid_t pid = 0;
  uint64_t start_sec = 0;
  uint16_t port = 0;
  std::string name;
  std::string project_hint;
  int established_conns = 0;
  bool is_http_like = false;
  bool is_protected = false;
};

struct VmStatus {
  bool orbstack_installed = false;
  bool orbstack_running = false;
  uint64_t orbstack_mem_bytes = 0;

  bool podman_installed = false;
  std::string podman_machine_name = "podman-machine-default";
  bool podman_running = false;
  uint64_t podman_mem_bytes = 0;
};

enum class OrphanKind {
  DevServer,
  TempPostgres,
  StuckLoop,
  IdleDebugChrome,
};

struct OrphanProc {
  pid_t pid = 0;
  uint64_t start_sec = 0;
  OrphanKind kind = OrphanKind::DevServer;
  std::string label;
  std::string detail;
  uint64_t mem_bytes = 0;
  uint64_t uptime_sec = 0;
  std::vector<uint16_t> listening_ports;
  int established_conns = 0;
  bool auto_reap_safe = false;
  bool needs_sigkill = false;
  std::vector<std::pair<pid_t, uint64_t>> related_pids;
};

enum class AlertSeverity {
  None = 0,
  Warn = 1,
  Crit = 2,
};

enum class AlertKind {
  FseventsdLeak,
  HighSwap,
  MemoryPressure,
  LowDisk,
  OrphansFound,
  HeavyDiskWrite,
  SsdWear,
};

struct SsdSmartHealth {
  bool available = false;
  uint8_t critical_warning = 0;
  uint8_t percentage_used = 0;
  uint8_t available_spare = 100;
  uint8_t available_spare_threshold = 0;
  int temperature_c = 0;
  uint64_t data_units_written = 0;
  uint64_t data_units_read = 0;
  double total_written_tb = 0.0;
  double total_read_tb = 0.0;
  uint64_t power_on_hours = 0;
  uint64_t power_cycles = 0;
  uint64_t unsafe_shutdowns = 0;
  uint64_t media_errors = 0;
};

struct Alert {
  AlertKind kind = AlertKind::FseventsdLeak;
  AlertSeverity severity = AlertSeverity::None;
  std::string title;
  std::string detail;
};

struct DeepMetrics {
  pid_t fseventsd_pid = 0;
  uint64_t fseventsd_rss_bytes = 0;
  double fseventsd_cpu_pct = 0.0;
  int fseventsd_high_strikes = 0;
  SsdSmartHealth ssd_smart;

  std::vector<AppGroup> top_mem_groups;
  std::vector<AppGroup> top_cpu_groups;
  std::vector<DiskWriter> top_disk_writers;
  std::vector<ListeningService> listening_services;
  VmStatus vm_status;
  std::vector<OrphanProc> orphans;
  std::vector<Alert> alerts;
  AlertSeverity max_severity = AlertSeverity::None;

  int total_procs = 0;
  double deep_scan_timestamp_sec = 0.0;
};

class MonitorState {
public:
  static constexpr size_t kHistoryCapacity = 180;

  explicit MonitorState(
      SysGuardConfig cfg = {},
      std::string daily_state_path = default_daily_state_path());

  FastMetrics sample_fast_metrics();
  DeepMetrics sample_deep_metrics(const FastMetrics& fast,
                                  uint64_t orphan_min_age_sec = 7200,
                                  bool force_sys_scan = true);
  void reset_deltas();
  void set_config(SysGuardConfig cfg);

  [[nodiscard]] std::vector<MetricPoint> copy_history() const;
  [[nodiscard]] const SysGuardConfig& config() const noexcept { return config_; }

private:
  struct PrevProcCounters {
    uint64_t cpu_ns = 0;
    uint64_t write_bytes = 0;
    uint64_t first_write_bytes = 0;
    double timestamp_sec = 0.0;
  };

  struct CachedCmd {
    std::string comm;
    std::string args;
    std::string comm_base;
    std::string group_name;
    bool is_dev_candidate = false;
    bool is_orbstack = false;
    bool is_orbstack_vmgr = false;
  };

  SysGuardConfig config_;
  std::string daily_state_path_;

  bool has_prev_cpu_ = false;
  uint64_t prev_cpu_user_ = 0;
  uint64_t prev_cpu_sys_ = 0;
  uint64_t prev_cpu_idle_ = 0;
  uint64_t prev_cpu_nice_ = 0;

  bool has_prev_self_ = false;
  uint64_t prev_self_cpu_ns_ = 0;
  double prev_self_ts_ = 0.0;

  bool has_prev_hw_write_ = false;
  uint64_t prev_hw_written_bytes_ = 0;
  double prev_hw_write_ts_ = 0.0;
  int today_yyyymmdd_ = 0;
  uint64_t today_start_written_bytes_ = 0;

  uint32_t tb_numer_ = 1;
  uint32_t tb_denom_ = 1;
  uint64_t page_size_ = 16384;
  uint64_t hw_memsize_ = 0;

  int fseventsd_high_strikes_ = 0;

  std::vector<pid_t> pids_buf_;
  double vm_env_checked_ts_ = -1.0;
  bool cached_orbstack_installed_ = false;
  bool cached_podman_installed_ = false;
  std::string cached_podman_machine_name_ = "podman-machine-default";

  double smart_checked_ts_ = -1.0;
  SsdSmartHealth cached_ssd_smart_;

  double last_sys_ps_ts_ = -1.0;
  std::vector<ProcEntry> cached_sys_procs_;
  pid_t cached_fseventsd_pid_ = 0;
  uint64_t cached_fseventsd_rss_ = 0;
  double cached_fseventsd_cpu_ = 0.0;

  std::unordered_map<uint64_t, PrevProcCounters> prev_proc_;
  std::unordered_map<uint64_t, PrevProcCounters> next_prev_buf_;
  std::vector<struct proc_fdinfo> fds_buf_;
  std::unordered_map<uint64_t, CachedCmd> cmd_cache_;

  std::array<MetricPoint, kHistoryCapacity> history_{};
  size_t history_head_ = 0;
  size_t history_count_ = 0;
};

// Hardware & process helpers
[[nodiscard]] uint64_t read_hw_disk_write_bytes();
[[nodiscard]] SsdSmartHealth read_ssd_smart_health();
[[nodiscard]] std::string read_proc_cwd(pid_t pid);
[[nodiscard]] std::string read_proc_args(pid_t pid);
[[nodiscard]] std::string extract_flag_value(const std::string& args,
                                             const std::string& prefix);

// Pure helpers (also unit tested directly).
[[nodiscard]] std::string classify_group_name(const std::string& comm,
                                              const std::string& args);

[[nodiscard]] std::vector<AppGroup> group_processes(
    const std::vector<ProcEntry>& procs, pid_t self_pid);

[[nodiscard]] bool is_orphan_candidate(
    const ProcEntry& proc,
    const std::unordered_map<pid_t, const ProcEntry*>& by_pid,
    uint64_t min_age_sec,
    OrphanKind& out_kind,
    std::string& out_label,
    bool& out_auto_reap_safe,
    bool& out_needs_sigkill);

[[nodiscard]] bool is_orphan_candidate(
    const ProcEntry& proc,
    const std::unordered_map<pid_t, ProcEntry>& by_pid,
    uint64_t min_age_sec,
    OrphanKind& out_kind,
    std::string& out_label,
    bool& out_auto_reap_safe,
    bool& out_needs_sigkill);

[[nodiscard]] std::vector<Alert> evaluate_alerts(
    const FastMetrics& fast,
    const DeepMetrics& deep,
    const std::vector<ProcEntry>& user_procs,
    const SysGuardConfig& cfg = {});

bool inspect_tcp_sockets(pid_t pid,
                         std::vector<uint16_t>& listening_ports,
                         int& established_count,
                         std::vector<uint16_t>* established_local_ports = nullptr);

[[nodiscard]] std::string format_bytes(uint64_t bytes);
[[nodiscard]] std::string format_bytes_compact(uint64_t bytes);
[[nodiscard]] std::string format_uptime(uint64_t seconds);

}  // namespace sysguard

#include "system_actions.hpp"
