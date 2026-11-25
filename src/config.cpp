#include "config.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <unistd.h>

namespace fs = std::filesystem;

namespace sysguard {

namespace {

constexpr uint64_t kMB = 1024ULL * 1024ULL;
constexpr uint64_t kGB = 1024ULL * 1024ULL * 1024ULL;

std::string trim_ws(std::string s) {
  while (!s.empty() &&
         (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' ||
          s.back() == '\n')) {
    s.pop_back();
  }
  size_t i = 0;
  while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
  return s.substr(i);
}

std::string expand_tilde(const std::string& p) {
  if (p.empty() || p[0] != '~') return p;
  if (p.size() > 1 && p[1] != '/') return p;
  const char* home = std::getenv("HOME");
  if (!home) return p;
  return std::string(home) + p.substr(1);
}

bool parse_positive_u64(const std::string& val, uint64_t& out) {
  if (val.empty() || val[0] == '-') return false;
  errno = 0;
  char* endp = nullptr;
  unsigned long long v = std::strtoull(val.c_str(), &endp, 10);
  if (errno == ERANGE || endp == val.c_str() || *endp != '\0' || v == 0ULL) {
    return false;
  }
  out = static_cast<uint64_t>(v);
  return true;
}

bool parse_positive_u64_scaled(const std::string& val,
                               uint64_t scale,
                               uint64_t& out) {
  uint64_t raw = 0;
  if (!parse_positive_u64(val, raw)) return false;
  if (scale > 0 && raw > std::numeric_limits<uint64_t>::max() / scale) {
    return false;
  }
  out = raw * scale;
  return true;
}

bool parse_positive_double(const std::string& val, double max_val, double& out) {
  if (val.empty()) return false;
  errno = 0;
  char* endp = nullptr;
  double v = std::strtod(val.c_str(), &endp);
  if (errno == ERANGE || endp == val.c_str() || *endp != '\0' || v <= 0.0 ||
      v > max_val) {
    return false;
  }
  out = v;
  return true;
}

bool parse_pct_int(const std::string& val, int& out) {
  if (val.empty()) return false;
  errno = 0;
  char* endp = nullptr;
  long v = std::strtol(val.c_str(), &endp, 10);
  if (errno == ERANGE || endp == val.c_str() || *endp != '\0' || v < 1 ||
      v > 99) {
    return false;
  }
  out = static_cast<int>(v);
  return true;
}

std::string app_support_dir() {
  const char* home = std::getenv("HOME");
  if (!home) return {};
  return std::string(home) + "/Library/Application Support/SysGuard";
}

bool write_file_atomic(const std::string& path, const std::string& content) {
  if (path.empty()) return false;

  std::error_code ec;
  fs::path p(path);
  if (p.has_parent_path()) {
    fs::create_directories(p.parent_path(), ec);
    if (ec) return false;
  }

  std::string tmp_path = path + ".tmp." + std::to_string(getpid());
  {
    std::ofstream ofs(tmp_path, std::ios::out | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    ofs.flush();
    if (!ofs.good()) {
      ofs.close();
      std::error_code rm_ec;
      fs::remove(tmp_path, rm_ec);
      return false;
    }
  }

  if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
    std::error_code rm_ec;
    fs::remove(tmp_path, rm_ec);
    return false;
  }
  return true;
}

}  // namespace

std::string default_config_path() {
  std::string dir = app_support_dir();
  if (dir.empty()) return {};
  return dir + "/config.ini";
}

SysGuardConfig load_config(const std::string& path) {
  SysGuardConfig cfg;
  if (path.empty()) return cfg;

  std::ifstream ifs(path, std::ios::in);
  if (!ifs) return cfg;

  std::string line;
  while (std::getline(ifs, line)) {
    std::string trimmed = trim_ws(std::move(line));
    if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') continue;

    size_t eq = trimmed.find('=');
    if (eq == std::string::npos) continue;

    std::string key = trim_ws(trimmed.substr(0, eq));
    std::string val = trim_ws(trimmed.substr(eq + 1));
    if (key.empty() || val.empty()) continue;

    if (key == "fseventsd_warn_mb") {
      parse_positive_u64_scaled(val, kMB, cfg.fseventsd_warn_bytes);
    } else if (key == "fseventsd_warn_bytes") {
      parse_positive_u64(val, cfg.fseventsd_warn_bytes);
    } else if (key == "fseventsd_crit_mb") {
      parse_positive_u64_scaled(val, kMB, cfg.fseventsd_crit_bytes);
    } else if (key == "fseventsd_crit_bytes") {
      parse_positive_u64(val, cfg.fseventsd_crit_bytes);
    } else if (key == "fseventsd_auto_heal_mb") {
      parse_positive_u64_scaled(val, kMB, cfg.fseventsd_auto_heal_bytes);
    } else if (key == "fseventsd_auto_heal_bytes") {
      parse_positive_u64(val, cfg.fseventsd_auto_heal_bytes);
    } else if (key == "fseventsd_warn_cpu_pct") {
      parse_positive_double(val, 2000.0, cfg.fseventsd_warn_cpu_pct);
    } else if (key == "fseventsd_crit_cpu_pct") {
      parse_positive_double(val, 2000.0, cfg.fseventsd_crit_cpu_pct);
    } else if (key == "swap_warn_gb") {
      parse_positive_u64_scaled(val, kGB, cfg.swap_warn_bytes);
    } else if (key == "swap_warn_bytes") {
      parse_positive_u64(val, cfg.swap_warn_bytes);
    } else if (key == "swap_crit_gb") {
      parse_positive_u64_scaled(val, kGB, cfg.swap_crit_bytes);
    } else if (key == "swap_crit_bytes") {
      parse_positive_u64(val, cfg.swap_crit_bytes);
    } else if (key == "mem_free_warn_pct") {
      parse_pct_int(val, cfg.mem_free_warn_pct);
    } else if (key == "mem_free_crit_pct") {
      parse_pct_int(val, cfg.mem_free_crit_pct);
    } else if (key == "disk_warn_avail_gb") {
      parse_positive_u64_scaled(val, kGB, cfg.disk_warn_avail_bytes);
    } else if (key == "disk_warn_avail_bytes") {
      parse_positive_u64(val, cfg.disk_warn_avail_bytes);
    } else if (key == "disk_crit_avail_gb") {
      parse_positive_u64_scaled(val, kGB, cfg.disk_crit_avail_bytes);
    } else if (key == "disk_crit_avail_bytes") {
      parse_positive_u64(val, cfg.disk_crit_avail_bytes);
    } else if (key == "disk_warn_used_pct") {
      parse_positive_double(val, 99.9, cfg.disk_warn_used_pct);
    } else if (key == "disk_crit_used_pct") {
      parse_positive_double(val, 99.9, cfg.disk_crit_used_pct);
    } else if (key == "proc_disk_write_warn_mb_s") {
      parse_positive_double(val, 100000.0, cfg.proc_disk_write_warn_mb_s);
    } else if (key == "hw_disk_write_warn_mb_s") {
      parse_positive_double(val, 100000.0, cfg.hw_disk_write_warn_mb_s);
    } else if (key == "hw_disk_write_badge_mb_s") {
      parse_positive_double(val, 100000.0, cfg.hw_disk_write_badge_mb_s);
    } else if (key == "podman_default_machine") {
      cfg.podman_default_machine = val;
    } else if (key == "extra_worktree_root") {
      std::string expanded = expand_tilde(val);
      if (!expanded.empty()) {
        cfg.extra_worktree_roots.push_back(std::move(expanded));
      }
    }
  }
  return cfg;
}

bool ensure_default_config_file(const std::string& path) {
  if (path.empty()) return false;
  std::error_code ec;
  auto st = fs::symlink_status(path, ec);
  if (!ec && st.type() != fs::file_type::not_found) {
    return true;
  }

  static constexpr const char* kDefaultTemplate =
      "# SysGuard configuration (key=value)\n"
      "# Uncomment any setting to override its built-in default.\n"
      "# In SysGuard.app, click Prevention & Settings -> Reload Config after saving.\n"
      "\n"
      "# fseventsd leak & CPU thresholds\n"
      "# fseventsd_warn_mb=512\n"
      "# fseventsd_crit_mb=1536\n"
      "# fseventsd_auto_heal_mb=2048\n"
      "# fseventsd_warn_cpu_pct=60.0\n"
      "# fseventsd_crit_cpu_pct=90.0\n"
      "\n"
      "# Swap & memory thresholds\n"
      "# swap_warn_gb=4\n"
      "# swap_crit_gb=8\n"
      "# mem_free_warn_pct=35\n"
      "# mem_free_crit_pct=20\n"
      "\n"
      "# SSD capacity & write throughput thresholds\n"
      "# disk_warn_avail_gb=100\n"
      "# disk_crit_avail_gb=50\n"
      "# disk_warn_used_pct=92.0\n"
      "# disk_crit_used_pct=96.0\n"
      "# proc_disk_write_warn_mb_s=50.0\n"
      "# hw_disk_write_warn_mb_s=150.0\n"
      "# hw_disk_write_badge_mb_s=30.0\n"
      "\n"
      "# Fallback Podman machine name (used only when auto-detection finds none)\n"
      "# podman_default_machine=podman-machine-default\n"
      "\n"
      "# Extra worktree roots to scan (repeatable, supports ~/)\n"
      "# extra_worktree_root=~/work/my-worktrees\n";

  return write_file_atomic(path, kDefaultTemplate);
}

std::string default_daily_state_path() {
  std::string dir = app_support_dir();
  if (dir.empty()) return {};
  return dir + "/daily_io.state";
}

DailyWriteState load_daily_write_state(const std::string& path) {
  DailyWriteState st;
  if (path.empty()) return st;

  std::ifstream ifs(path, std::ios::in);
  if (!ifs) return st;

  std::string line;
  if (!std::getline(ifs, line)) return st;
  line = trim_ws(std::move(line));
  if (line.empty()) return st;

  errno = 0;
  char* end1 = nullptr;
  long day_val = std::strtol(line.c_str(), &end1, 10);
  if (errno == ERANGE || end1 == line.c_str() ||
      day_val < 20000101L || day_val > 21001231L) {
    return st;
  }

  while (*end1 == ' ' || *end1 == '\t') ++end1;
  if (*end1 == '\0' || *end1 == '-') return st;

  errno = 0;
  char* end2 = nullptr;
  unsigned long long bytes_val = std::strtoull(end1, &end2, 10);
  if (errno == ERANGE || end2 == end1 || *end2 != '\0') return st;

  st.yyyymmdd = static_cast<int>(day_val);
  st.start_written_bytes = static_cast<uint64_t>(bytes_val);
  st.valid = true;
  return st;
}

bool save_daily_write_state(const std::string& path,
                            int yyyymmdd,
                            uint64_t start_written_bytes) {
  std::string payload =
      std::to_string(yyyymmdd) + " " + std::to_string(start_written_bytes) + "\n";
  return write_file_atomic(path, payload);
}

}  // namespace sysguard
