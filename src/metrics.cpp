#include "metrics.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <IOKit/storage/nvme/NVMeSMARTLibExternal.h>
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <libproc.h>
#include <limits>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sstream>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <unordered_set>

namespace sysguard {

namespace {

constexpr uint64_t kKB = 1024ULL;
constexpr uint64_t kMB = 1024ULL * 1024ULL;
constexpr uint64_t kGB = 1024ULL * 1024ULL * 1024ULL;

double monotonic_now_sec() {
  using clock = std::chrono::steady_clock;
  return std::chrono::duration<double>(clock::now().time_since_epoch()).count();
}

uint64_t wall_now_sec() {
  using clock = std::chrono::system_clock;
  auto s = std::chrono::duration_cast<std::chrono::seconds>(
               clock::now().time_since_epoch())
               .count();
  return s > 0 ? static_cast<uint64_t>(s) : 0ULL;
}

int local_yyyymmdd() {
  std::time_t now = std::time(nullptr);
  struct tm lt{};
  localtime_r(&now, &lt);
  return (lt.tm_year + 1900) * 10000 + (lt.tm_mon + 1) * 100 + lt.tm_mday;
}

uint64_t proc_key(pid_t pid, uint64_t start_sec) {
  return (static_cast<uint64_t>(static_cast<uint32_t>(pid)) << 32) |
         static_cast<uint32_t>(start_sec);
}

uint64_t ticks_to_ns(uint64_t ticks, uint32_t numer, uint32_t denom) {
  if (denom == 0) return ticks;
  __uint128_t prod = static_cast<__uint128_t>(ticks) * numer;
  return static_cast<uint64_t>(prod / denom);
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
  if (needle.empty()) return true;
  auto it = std::search(
      haystack.begin(), haystack.end(), needle.begin(), needle.end(),
      [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
      });
  return it != haystack.end();
}

std::string basename_of(const std::string& path) {
  if (path.empty()) return {};
  size_t end = path.size();
  while (end > 1 && path[end - 1] == '/') --end;
  auto pos = path.find_last_of('/', end - 1);
  if (pos == std::string::npos) return path.substr(0, end);
  return path.substr(pos + 1, end - pos - 1);
}

std::string tail_components(const std::string& path, int max_parts) {
  if (path.empty()) return {};
  size_t end = path.size();
  while (end > 1 && path[end - 1] == '/') --end;
  int found = 0;
  size_t pos = end;
  while (pos > 0) {
    --pos;
    if (path[pos] == '/') {
      ++found;
      if (found == max_parts) {
        return path.substr(pos + 1, end - pos - 1);
      }
    }
  }
  return path.substr(0, end);
}

std::string first_token(const std::string& s) {
  size_t i = 0;
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  size_t j = i;
  while (j < s.size() && !std::isspace(static_cast<unsigned char>(s[j]))) ++j;
  return s.substr(i, j - i);
}

std::string extract_app_bundle(const std::string& s) {
  size_t pos = 0;
  while (pos < s.size()) {
    size_t found = s.find(".app/", pos);
    if (found == std::string::npos) break;
    size_t start = found;
    while (start > 0 && s[start - 1] != '/') {
      --start;
    }
    if (found > start) {
      return s.substr(start, found - start);
    }
    pos = found + 5;
  }
  return {};
}

uint16_t parse_u16_flag(const std::string& args, const std::string& prefix) {
  std::string val = extract_flag_value(args, prefix);
  if (val.empty()) return 0;
  char* endp = nullptr;
  unsigned long v = std::strtoul(val.c_str(), &endp, 10);
  if (endp == val.c_str() || v == 0 || v > 65535) return 0;
  return static_cast<uint16_t>(v);
}

bool read_procargs2(pid_t pid, std::string& out_exec, std::string& out_args) {
  int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
  size_t size = 0;
  if (sysctl(mib, 3, nullptr, &size, nullptr, 0) != 0 || size < sizeof(int32_t)) {
    return false;
  }
  if (size > 256 * 1024) size = 256 * 1024;

  std::string buf(size, '\0');
  if (sysctl(mib, 3, buf.data(), &size, nullptr, 0) != 0 ||
      size < sizeof(int32_t)) {
    return false;
  }
  buf.resize(size);

  int32_t argc = 0;
  std::memcpy(&argc, buf.data(), sizeof(int32_t));
  if (argc <= 0 || argc > 4096) {
    return false;
  }

  size_t off = sizeof(int32_t);
  size_t exec_end = buf.find('\0', off);
  if (exec_end == std::string::npos) {
    out_exec = buf.substr(off);
    out_args = out_exec;
    return true;
  }
  out_exec = buf.substr(off, exec_end - off);
  off = exec_end + 1;

  while (off < size && buf[off] == '\0') {
    ++off;
  }

  std::string joined;
  joined.reserve(256);
  for (int32_t i = 0; i < argc && off < size; ++i) {
    size_t nul = buf.find('\0', off);
    size_t len = (nul == std::string::npos) ? (size - off) : (nul - off);
    if (!joined.empty()) joined.push_back(' ');
    if (joined.size() + len > 2048) {
      size_t take = 2048 > joined.size() ? 2048 - joined.size() : 0;
      joined.append(buf, off, take);
      break;
    }
    joined.append(buf, off, len);
    if (nul == std::string::npos) break;
    off = nul + 1;
  }

  if (joined.empty()) joined = out_exec;
  out_args = std::move(joined);
  return true;
}

std::vector<ProcEntry> sample_system_daemons_ps() {
  std::vector<ProcEntry> out;

  std::string data;
  int exit_code = 0;
  if (!run_command_capture(
          {"/bin/ps", "-U", "root,_windowserver", "-o",
           "pid=,uid=,%cpu=,rss=,comm="},
          data, exit_code, 5000) ||
      exit_code != 0) {
    return out;
  }

  out.reserve(128);
  const char* cur = data.data();
  const char* const end = cur + data.size();
  while (cur < end) {
    const char* nl = static_cast<const char*>(
        std::memchr(cur, '\n', static_cast<size_t>(end - cur)));
    const char* line_end = nl ? nl : end;

    char* next1 = nullptr;
    long pid_val = std::strtol(cur, &next1, 10);
    if (next1 == cur || next1 > line_end) {
      cur = nl ? (nl + 1) : end;
      continue;
    }

    char* next2 = nullptr;
    long uid_val = std::strtol(next1, &next2, 10);
    if (next2 == next1 || next2 > line_end) {
      cur = nl ? (nl + 1) : end;
      continue;
    }

    char* next3 = nullptr;
    double cpu_val = std::strtod(next2, &next3);
    if (next3 == next2 || next3 > line_end) {
      cur = nl ? (nl + 1) : end;
      continue;
    }

    char* next4 = nullptr;
    unsigned long long rss_kb = std::strtoull(next3, &next4, 10);
    if (next4 == next3 || next4 > line_end) {
      cur = nl ? (nl + 1) : end;
      continue;
    }

    const char* comm_start = next4;
    while (comm_start < line_end &&
           (*comm_start == ' ' || *comm_start == '\t')) {
      ++comm_start;
    }
    const char* comm_end = line_end;
    while (comm_end > comm_start &&
           (*(comm_end - 1) == '\r' || *(comm_end - 1) == ' ' ||
            *(comm_end - 1) == '\t')) {
      --comm_end;
    }

    if (pid_val > 0 && pid_val <= std::numeric_limits<pid_t>::max() &&
        comm_end > comm_start) {
      ProcEntry p;
      p.pid = static_cast<pid_t>(pid_val);
      p.ppid = 1;
      p.uid = static_cast<uid_t>(uid_val);
      p.mem_bytes = static_cast<uint64_t>(rss_kb) * kKB;
      p.cpu_pct = cpu_val;
      p.comm.assign(comm_start, static_cast<size_t>(comm_end - comm_start));
      p.args = p.comm;
      p.is_system = true;
      out.push_back(std::move(p));
    }

    cur = nl ? (nl + 1) : end;
  }

  return out;
}

std::string build_orphan_detail(uint64_t mem_bytes,
                                uint64_t uptime_sec,
                                const std::vector<uint16_t>& ports,
                                int established_conns) {
  std::ostringstream os;
  os << format_bytes_compact(mem_bytes) << " · up " << format_uptime(uptime_sec);
  if (!ports.empty()) {
    os << " · :";
    for (size_t i = 0; i < ports.size() && i < 2; ++i) {
      if (i > 0) os << ",";
      os << ports[i];
    }
  }
  os << " (" << established_conns << " conns)";
  return os.str();
}

bool is_dev_server_candidate(const std::string& comm,
                             const std::string& base,
                             const std::string& args) {
  if (contains_ci(args, "T3 Code.app") || contains_ci(args, "T3 Code (Beta)") ||
      contains_ci(args, "antigravity") || contains_ci(args, "Opera.app") ||
      contains_ci(args, "Discord.app") || contains_ci(args, "Steam.AppBundle") ||
      contains_ci(args, "Raycast.app") || contains_ci(args, "SysGuard.app") ||
      contains_ci(args, "Claude.app") || contains_ci(args, "ChatGPT.app")) {
    return false;
  }

  if (base == "postgres" || base == "cli-proxy-api" || base == "cloudflared" ||
      base == "nginx" || base == "caddy" || base == "redis-server" ||
      base == "mongod" || base == "node" || base == "bun" || base == "deno" ||
      base == "ruby" || base == "java" || base == "dotnet" ||
      base == "vite" || base == "next-server") {
    return true;
  }
  if (base.rfind("python", 0) == 0 || base.rfind("Python", 0) == 0) {
    return true;
  }
  if ((base == "Google Chrome" ||
       contains_ci(comm, "Google Chrome.app/Contents/MacOS/Google Chrome")) &&
      args.find("--type=") == std::string::npos &&
      args.find("--remote-debugging-port=") != std::string::npos) {
    return true;
  }
  return false;
}

bool is_http_dev_port(const std::string& base,
                      const std::string& args,
                      uint16_t port) {
  if (base == "postgres" || base == "redis-server" || base == "mongod" ||
      base == "cli-proxy-api" || base == "cloudflared") {
    return false;
  }
  if (port == 5432 || port == 5433 || port == 5434 || port == 6379 ||
      port == 27017 || port == 15433 || port == 8317 || port == 7265 ||
      port == 9223 || port == 9333 || (port >= 55430 && port <= 55500)) {
    return false;
  }
  if (contains_ci(args, "vite") || contains_ci(args, "next") ||
      contains_ci(args, "astro") || contains_ci(args, "nuxt") ||
      contains_ci(args, "webpack") || contains_ci(args, "svelte") ||
      base == "nginx" || base == "caddy") {
    return true;
  }
  return (port >= 3000 && port <= 4999) || (port >= 5100 && port <= 5399) ||
         (port >= 8000 && port <= 8999);
}

std::string service_display_name(const std::string& base,
                                 const std::string& args) {
  if (base == "postgres") return "PostgreSQL";
  if (base == "cli-proxy-api") return "cli-proxy-api";
  if (base == "cloudflared") return "cloudflared";
  if (contains_ci(args, "vite")) return "Vite";
  if (contains_ci(args, "next-server") || contains_ci(args, "next dev")) {
    return "Next.js";
  }
  if (contains_ci(args, "svelte")) return "SvelteKit";
  if (contains_ci(args, "Google Chrome")) return "Chrome Debug";
  if (contains_ci(args, "codegraph")) return "codegraph";
  return base.empty() ? "server" : base;
}

std::string service_project_hint(pid_t pid,
                                 const std::string& base,
                                 const std::string& args) {
  if (base == "postgres") {
    std::string ddir = extract_flag_value(args, "-D");
    if (!ddir.empty()) {
      return tail_components(ddir, 3);
    }
  }
  if (base == "cloudflared") {
    std::string host = extract_flag_value(args, "--hostname");
    if (!host.empty()) return host;
  }
  if (contains_ci(args, "Google Chrome")) {
    std::string udd = extract_flag_value(args, "--user-data-dir=");
    if (!udd.empty()) return basename_of(udd);
  }
  std::string cwd = read_proc_cwd(pid);
  if (!cwd.empty() && cwd != "/") {
    return tail_components(cwd, 2);
  }
  return {};
}

struct GroupInput {
  pid_t pid = 0;
  pid_t ppid = 0;
  uint64_t start_sec = 0;
  uint64_t mem_bytes = 0;
  double cpu_pct = 0.0;
  uint64_t uptime_sec = 0;
  bool is_system = false;
  const std::string* comm = nullptr;
  const std::string* args = nullptr;
  const std::string* cached_group = nullptr;
};

std::vector<AppGroup> group_inputs(const std::vector<GroupInput>& inputs,
                                   pid_t self_pid) {
  struct Accum {
    AppGroup group;
    std::unordered_set<pid_t> member_pids;
    std::vector<const GroupInput*> members;
  };

  std::unordered_map<std::string, Accum> buckets;
  buckets.reserve(64);
  for (const auto& p : inputs) {
    std::string gname;
    if (p.pid == self_pid) {
      gname = "SysGuard (Self)";
    } else if (p.cached_group && !p.cached_group->empty()) {
      gname = *p.cached_group;
    } else {
      gname = classify_group_name(p.comm ? *p.comm : std::string{},
                                  p.args ? *p.args : std::string{});
    }

    auto& acc = buckets[gname];
    acc.group.name = gname;
    acc.group.proc_count += 1;
    acc.group.mem_bytes += p.mem_bytes;
    acc.group.cpu_pct += p.cpu_pct;
    if (p.uptime_sec > acc.group.max_uptime_sec) {
      acc.group.max_uptime_sec = p.uptime_sec;
    }
    if (p.is_system || p.pid == self_pid || gname == "fseventsd" ||
        gname == "WindowServer" || gname == "kernel_task" ||
        gname == "SysGuard (Self)") {
      acc.group.is_system = true;
    }
    acc.group.all_pids.emplace_back(p.pid, p.start_sec);
    acc.member_pids.insert(p.pid);
    acc.members.push_back(&p);
  }

  std::vector<AppGroup> result;
  result.reserve(buckets.size());
  for (auto& [name, acc] : buckets) {
    for (const GroupInput* m : acc.members) {
      if (m->ppid <= 1 || !acc.member_pids.count(m->ppid)) {
        acc.group.leader_pids.emplace_back(m->pid, m->start_sec);
      }
    }
    if (acc.group.leader_pids.empty() && !acc.group.all_pids.empty()) {
      acc.group.leader_pids.push_back(acc.group.all_pids.front());
    }
    result.push_back(std::move(acc.group));
  }

  std::sort(result.begin(), result.end(),
            [](const AppGroup& a, const AppGroup& b) {
              return a.mem_bytes > b.mem_bytes;
            });
  return result;
}

template <typename ParentLookupFn>
bool is_orphan_candidate_impl(pid_t pid,
                              pid_t ppid,
                              uint64_t uptime_sec,
                              bool is_system,
                              const std::string& comm,
                              const std::string& base,
                              const std::string& args,
                              ParentLookupFn&& lookup_parent,
                              uint64_t min_age_sec,
                              OrphanKind& out_kind,
                              std::string& out_label,
                              bool& out_auto_reap_safe,
                              bool& out_needs_sigkill) {
  if (is_system || pid <= 1) return false;
  if (uptime_sec < min_age_sec) return false;

  if (contains_ci(args, "T3 Code") || contains_ci(args, "antigravity") ||
      contains_ci(args, "SysGuard") || base == "claude" ||
      args.rfind("claude ", 0) == 0 || contains_ci(args, "Opera.app") ||
      contains_ci(args, "OrbStack.app")) {
    return false;
  }

  auto is_orphaned_root_or_wrapper = [&]() -> bool {
    if (ppid == 1) return true;
    pid_t grand_ppid = 0;
    std::string pbase;
    if (!lookup_parent(ppid, grand_ppid, pbase)) return false;
    if (grand_ppid != 1) return false;
    return pbase == "pnpm" || pbase == "bun" || pbase == "npm" ||
           pbase == "node";
  };

  if ((base == "postgres" || contains_ci(comm, "/postgres")) && ppid == 1) {
    if (args.find(" -D /private/tmp/") != std::string::npos ||
        args.find(" -D /tmp/") != std::string::npos ||
        args.find("-D /private/tmp/") != std::string::npos ||
        args.find("-D /tmp/") != std::string::npos) {
      out_kind = OrphanKind::TempPostgres;
      uint16_t port = parse_u16_flag(args, "-p ");
      out_label = port ? ("Temp Postgres :" + std::to_string(port))
                       : "Temp Postgres";
      out_auto_reap_safe = true;
      out_needs_sigkill = false;
      return true;
    }
    return false;
  }

  if ((base == "node" || base == "bun") &&
      !contains_ci(args, "vitest") &&
      !contains_ci(args, "mcp") &&
      !contains_ci(args, "codegraph") &&
      is_orphaned_root_or_wrapper()) {
    bool is_dev =
        (args.find("vite.js") != std::string::npos ||
         args.find("/vite ") != std::string::npos ||
         args.find("vite dev") != std::string::npos ||
         args.find("vite preview") != std::string::npos ||
         args.find("next dev") != std::string::npos ||
         args.find("next-server") != std::string::npos ||
         args.find("astro dev") != std::string::npos ||
         args.find("nuxt dev") != std::string::npos ||
         args.find("webpack serve") != std::string::npos);
    if (is_dev) {
      out_kind = OrphanKind::DevServer;
      uint16_t port = parse_u16_flag(args, "--port ");
      if (port == 0) port = parse_u16_flag(args, "-p ");
      out_label = port ? ("Orphan Vite/Dev :" + std::to_string(port))
                       : "Orphan Vite/Dev Server";
      out_auto_reap_safe = true;
      out_needs_sigkill = false;
      return true;
    }
  }

  if (ppid == 1 &&
      (base == "Python" || base == "python3" || base == "python" ||
       base == "node")) {
    bool is_inline = (args.find(" -c ") != std::string::npos ||
                      args.find(" -e ") != std::string::npos);
    bool is_loop = (args.find("while True:") != std::string::npos ||
                    args.find("while (true)") != std::string::npos ||
                    args.find("pathlib.Path(gate)") != std::string::npos ||
                    args.find("time.sleep(") != std::string::npos);
    if (is_inline && is_loop) {
      out_kind = OrphanKind::StuckLoop;
      out_label = "Stuck " + base + " test loop";
      out_auto_reap_safe = true;
      out_needs_sigkill = (args.find("SIG_IGN") != std::string::npos);
      return true;
    }
  }

  if (ppid == 1 &&
      (contains_ci(comm, "Google Chrome.app/Contents/MacOS/Google Chrome") ||
       base == "Google Chrome") &&
      args.find("--type=") == std::string::npos &&
      args.find("--remote-debugging-port=") != std::string::npos) {
    std::string udd = extract_flag_value(args, "--user-data-dir=");
    if (!udd.empty() &&
        (udd.find("/.cache/") != std::string::npos ||
         udd.find("/tmp/") != std::string::npos ||
         udd.find("/private/tmp/") != std::string::npos)) {
      out_kind = OrphanKind::IdleDebugChrome;
      std::string prof = basename_of(udd);
      out_label = prof.empty() ? "Idle Debug Chrome" : ("Chrome (" + prof + ")");
      out_auto_reap_safe = false;
      out_needs_sigkill = false;
      return true;
    }
  }

  return false;
}

std::vector<Alert> evaluate_alerts_impl(const FastMetrics& fast,
                                        const DeepMetrics& deep,
                                        bool saw_proc_writer,
                                        const std::string& writer_base,
                                        double writer_mb_s,
                                        const SysGuardConfig& cfg) {
  std::vector<Alert> alerts;

  if (deep.fseventsd_rss_bytes >= cfg.fseventsd_crit_bytes ||
      (deep.fseventsd_cpu_pct >= cfg.fseventsd_crit_cpu_pct &&
       deep.fseventsd_high_strikes >= 2)) {
    std::ostringstream os;
    os << format_bytes_compact(deep.fseventsd_rss_bytes) << " RSS · "
       << static_cast<int>(deep.fseventsd_cpu_pct + 0.5) << "% CPU";
    alerts.push_back({AlertKind::FseventsdLeak, AlertSeverity::Crit,
                      "fseventsd runaway leak", os.str()});
  } else if (deep.fseventsd_rss_bytes >= cfg.fseventsd_warn_bytes ||
             (deep.fseventsd_cpu_pct >= cfg.fseventsd_warn_cpu_pct &&
              deep.fseventsd_high_strikes >= 2)) {
    std::ostringstream os;
    os << format_bytes_compact(deep.fseventsd_rss_bytes) << " RSS · "
       << static_cast<int>(deep.fseventsd_cpu_pct + 0.5) << "% CPU";
    alerts.push_back({AlertKind::FseventsdLeak, AlertSeverity::Warn,
                      "fseventsd elevated", os.str()});
  }

  if (fast.swap_used_bytes >= cfg.swap_crit_bytes) {
    alerts.push_back({AlertKind::HighSwap, AlertSeverity::Crit,
                      "High swap usage",
                      format_bytes_compact(fast.swap_used_bytes) + " used"});
  } else if (fast.swap_used_bytes >= cfg.swap_warn_bytes) {
    alerts.push_back({AlertKind::HighSwap, AlertSeverity::Warn,
                      "Elevated swap usage",
                      format_bytes_compact(fast.swap_used_bytes) + " used"});
  }

  if (fast.memory_free_pct <= cfg.mem_free_crit_pct) {
    alerts.push_back({AlertKind::MemoryPressure, AlertSeverity::Crit,
                      "Critical memory pressure",
                      std::to_string(fast.memory_free_pct) + "% free"});
  } else if (fast.memory_free_pct <= cfg.mem_free_warn_pct) {
    alerts.push_back({AlertKind::MemoryPressure, AlertSeverity::Warn,
                      "Memory pressure rising",
                      std::to_string(fast.memory_free_pct) + "% free"});
  }

  if (fast.disk_total_bytes > 0) {
    if (fast.disk_avail_bytes < cfg.disk_crit_avail_bytes ||
        fast.disk_used_pct >= cfg.disk_crit_used_pct) {
      std::ostringstream os;
      os << format_bytes_compact(fast.disk_avail_bytes) << " free ("
         << static_cast<int>(fast.disk_used_pct * 10.0 + 0.5) / 10.0 << "% used)";
      alerts.push_back({AlertKind::LowDisk, AlertSeverity::Crit,
                        "Low SSD space", os.str()});
    } else if (fast.disk_avail_bytes < cfg.disk_warn_avail_bytes ||
               fast.disk_used_pct >= cfg.disk_warn_used_pct) {
      std::ostringstream os;
      os << format_bytes_compact(fast.disk_avail_bytes) << " free ("
         << static_cast<int>(fast.disk_used_pct * 10.0 + 0.5) / 10.0 << "% used)";
      alerts.push_back({AlertKind::LowDisk, AlertSeverity::Warn,
                        "SSD filling up", os.str()});
    }
  }

  if (!deep.orphans.empty()) {
    uint64_t orphan_mem = 0;
    for (const auto& o : deep.orphans) orphan_mem += o.mem_bytes;
    if (orphan_mem >= cfg.fseventsd_warn_bytes || deep.orphans.size() >= 2) {
      std::ostringstream os;
      os << deep.orphans.size() << " idle (" << format_bytes_compact(orphan_mem)
         << ")";
      alerts.push_back({AlertKind::OrphansFound, AlertSeverity::Warn,
                        "Orphaned/idle processes", os.str()});
    }
  }

  if (saw_proc_writer) {
    std::ostringstream os;
    os << writer_base << " (" << static_cast<int>(writer_mb_s) << " MB/s)";
    alerts.push_back({AlertKind::HeavyDiskWrite, AlertSeverity::Warn,
                      "Heavy disk write", os.str()});
  } else if (fast.hw_disk_write_mb_s >= cfg.hw_disk_write_warn_mb_s) {
    std::ostringstream os;
    os << static_cast<int>(fast.hw_disk_write_mb_s) << " MB/s hardware write";
    alerts.push_back({AlertKind::HeavyDiskWrite, AlertSeverity::Warn,
                      "Heavy SSD write", os.str()});
  }

  if (deep.ssd_smart.available) {
    const auto& s = deep.ssd_smart;
    const bool crit_flag = (s.critical_warning != 0);
    const bool media_err = (s.media_errors > 0);
    const bool low_spare = (s.available_spare_threshold > 0 &&
                            s.available_spare <= s.available_spare_threshold);
    const int pct_used = static_cast<int>(s.percentage_used);
    if (crit_flag || media_err || low_spare ||
        pct_used >= cfg.ssd_wear_crit_pct) {
      std::ostringstream os;
      os << pct_used << "% wear · " << static_cast<unsigned>(s.available_spare)
         << "% spare · " << std::fixed;
      os.precision(1);
      os << s.total_written_tb << " TBW";
      if (media_err) os << " · " << s.media_errors << " media err";
      if (crit_flag) os << " · critical flag";
      alerts.push_back(
          {AlertKind::SsdWear, AlertSeverity::Crit, "SSD health warning",
           os.str()});
    } else if (pct_used >= cfg.ssd_wear_warn_pct) {
      std::ostringstream os;
      os << pct_used << "% wear · ";
      os.precision(1);
      os << std::fixed << s.total_written_tb << " TBW · "
         << static_cast<unsigned>(s.available_spare) << "% spare";
      alerts.push_back(
          {AlertKind::SsdWear, AlertSeverity::Warn, "SSD wear elevated",
           os.str()});
    }
  }

  return alerts;
}

bool inspect_tcp_sockets_with_buf(
    pid_t pid,
    std::vector<uint16_t>& listening_ports,
    int& established_count,
    std::vector<uint16_t>* established_local_ports,
    std::vector<struct proc_fdinfo>& fds_buf) {
  listening_ports.clear();
  established_count = 0;
  if (established_local_ports) established_local_ports->clear();

  int buf_sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
  if (buf_sz <= 0) return false;

  size_t needed =
      static_cast<size_t>(buf_sz) / sizeof(struct proc_fdinfo) + 16;
  if (fds_buf.size() < needed) fds_buf.resize(needed);
  int actual = proc_pidinfo(
      pid, PROC_PIDLISTFDS, 0, fds_buf.data(),
      static_cast<int>(fds_buf.size() * sizeof(struct proc_fdinfo)));
  if (actual <= 0) return false;

  size_t nfds = std::min<size_t>(
      static_cast<size_t>(actual) / sizeof(struct proc_fdinfo), fds_buf.size());
  for (size_t i = 0; i < nfds; ++i) {
    if (fds_buf[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
    struct socket_fdinfo si{};
    int sr = proc_pidfdinfo(pid, fds_buf[i].proc_fd, PROC_PIDFDSOCKETINFO, &si,
                            PROC_PIDFDSOCKETINFO_SIZE);
    if (sr != static_cast<int>(PROC_PIDFDSOCKETINFO_SIZE)) continue;

    if (si.psi.soi_kind != SOCKINFO_TCP) continue;
    if (si.psi.soi_family != AF_INET && si.psi.soi_family != AF_INET6) continue;

    const auto& tcp = si.psi.soi_proto.pri_tcp;
    uint16_t lport = ntohs(static_cast<uint16_t>(tcp.tcpsi_ini.insi_lport));
    if (tcp.tcpsi_state == TSI_S_LISTEN) {
      if (lport != 0 &&
          std::find(listening_ports.begin(), listening_ports.end(), lport) ==
              listening_ports.end()) {
        listening_ports.push_back(lport);
      }
    } else if (tcp.tcpsi_state == TSI_S_ESTABLISHED) {
      ++established_count;
      if (established_local_ports && lport != 0) {
        established_local_ports->push_back(lport);
      }
    }
  }
  return true;
}

}  // namespace

std::string extract_flag_value(const std::string& args,
                               const std::string& prefix) {
  if (prefix.empty()) return {};
  const bool ends_delim =
      (prefix.back() == '=' ||
       std::isspace(static_cast<unsigned char>(prefix.back())));
  size_t search_from = 0;
  while (search_from < args.size()) {
    size_t pos = args.find(prefix, search_from);
    if (pos == std::string::npos) return {};
    bool start_ok =
        (pos == 0 || std::isspace(static_cast<unsigned char>(args[pos - 1])));
    size_t after = pos + prefix.size();
    bool end_ok = true;
    if (!ends_delim && after < args.size()) {
      unsigned char ch = static_cast<unsigned char>(args[after]);
      end_ok = (std::isspace(ch) != 0 || ch == '=');
    }
    if (start_ok && end_ok) {
      if (!ends_delim && after < args.size() && args[after] == '=') {
        ++after;
      }
      while (after < args.size() &&
             std::isspace(static_cast<unsigned char>(args[after]))) {
        ++after;
      }
      size_t end = after;
      while (end < args.size() &&
             !std::isspace(static_cast<unsigned char>(args[end]))) {
        ++end;
      }
      return args.substr(after, end - after);
    }
    search_from = pos + 1;
  }
  return {};
}

uint64_t read_hw_disk_write_bytes() {
  uint64_t total = 0;
  CFMutableDictionaryRef matching = IOServiceMatching("IOBlockStorageDriver");
  if (!matching) return 0;

  io_iterator_t iter = IO_OBJECT_NULL;
  if (IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter) !=
      KERN_SUCCESS) {
    return 0;
  }

  io_object_t entry = IO_OBJECT_NULL;
  while ((entry = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
    CFTypeRef props = IORegistryEntryCreateCFProperty(
        entry, CFSTR(kIOBlockStorageDriverStatisticsKey), kCFAllocatorDefault, 0);
    if (props != nullptr) {
      if (CFGetTypeID(props) == CFDictionaryGetTypeID()) {
        CFDictionaryRef dict = static_cast<CFDictionaryRef>(props);
        const void* val = CFDictionaryGetValue(
            dict, CFSTR(kIOBlockStorageDriverStatisticsBytesWrittenKey));
        if (val != nullptr &&
            CFGetTypeID(static_cast<CFTypeRef>(val)) == CFNumberGetTypeID()) {
          int64_t bytes = 0;
          if (CFNumberGetValue(static_cast<CFNumberRef>(val),
                               kCFNumberSInt64Type, &bytes) &&
              bytes > 0) {
            total += static_cast<uint64_t>(bytes);
          }
        }
      }
      CFRelease(props);
    }
    IOObjectRelease(entry);
  }
  IOObjectRelease(iter);
  return total;
}

namespace {

bool is_internal_block_device(io_service_t svc) {
  CFTypeRef proto = IORegistryEntryCreateCFProperty(
      svc, CFSTR("Protocol Characteristics"), kCFAllocatorDefault, 0);
  if (!proto) return false;
  bool is_internal = false;
  if (CFGetTypeID(proto) == CFDictionaryGetTypeID()) {
    CFDictionaryRef dict = static_cast<CFDictionaryRef>(proto);
    const void* loc =
        CFDictionaryGetValue(dict, CFSTR("Physical Interconnect Location"));
    if (loc != nullptr &&
        CFGetTypeID(static_cast<CFTypeRef>(loc)) == CFStringGetTypeID() &&
        CFStringCompare(static_cast<CFStringRef>(loc), CFSTR("Internal"), 0) ==
            kCFCompareEqualTo) {
      is_internal = true;
    }
  }
  CFRelease(proto);
  return is_internal;
}

bool read_nvme_smart_for_service(io_service_t svc, SsdSmartHealth& out) {
  IOCFPlugInInterface** plug = nullptr;
  SInt32 score = 0;
  kern_return_t kr = IOCreatePlugInInterfaceForService(
      svc, kIONVMeSMARTUserClientTypeID, kIOCFPlugInInterfaceID, &plug, &score);
  if (kr != KERN_SUCCESS || !plug) return false;

  bool ok = false;
  LPVOID raw_iface = nullptr;
  HRESULT hr = (*plug)->QueryInterface(
      plug, CFUUIDGetUUIDBytes(kIONVMeSMARTInterfaceID), &raw_iface);
  if (hr == S_OK && raw_iface != nullptr) {
    IONVMeSMARTInterface** smart =
        static_cast<IONVMeSMARTInterface**>(raw_iface);
    NVMeSMARTData d{};
    if ((*smart)->SMARTReadData(smart, &d) == kIOReturnSuccess) {
      out.available = true;
      out.critical_warning = d.CRITICAL_WARNING;
      out.percentage_used = d.PERCENTAGE_USED;
      out.available_spare = d.AVAILABLE_SPARE;
      out.available_spare_threshold = d.AVAILABLE_SPARE_THRESHOLD;
      out.temperature_c =
          (d.TEMPERATURE >= 273) ? (static_cast<int>(d.TEMPERATURE) - 273) : 0;
      const uint64_t duw = d.DATA_UNITS_WRITTEN[0];
      const uint64_t dur = d.DATA_UNITS_READ[0];
      out.data_units_written = duw;
      out.data_units_read = dur;
      out.total_written_tb = static_cast<double>(duw) * 512000.0 / 1e12;
      out.total_read_tb = static_cast<double>(dur) * 512000.0 / 1e12;
      out.power_on_hours = d.POWER_ON_HOURS[0];
      out.power_cycles = d.POWER_CYCLES[0];
      out.unsafe_shutdowns = d.UNSAFE_SHUTDOWNS[0];
      out.media_errors = d.MEDIA_ERRORS[0];
      ok = true;
    }
    (*smart)->Release(smart);
  }
  IODestroyPlugInInterface(plug);
  return ok;
}

}  // namespace

SsdSmartHealth read_ssd_smart_health() {
  SsdSmartHealth fallback_health;
  CFMutableDictionaryRef matching = IOServiceMatching("IOBlockStorageDevice");
  if (!matching) return fallback_health;

  io_iterator_t iter = IO_OBJECT_NULL;
  if (IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter) !=
      KERN_SUCCESS) {
    return fallback_health;
  }

  io_service_t entry = IO_OBJECT_NULL;
  while ((entry = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
    CFTypeRef cap = IORegistryEntryCreateCFProperty(
        entry, CFSTR(kIOPropertyNVMeSMARTCapableKey), kCFAllocatorDefault, 0);
    bool smart_capable =
        (cap != nullptr &&
         CFGetTypeID(cap) == CFBooleanGetTypeID() &&
         CFBooleanGetValue(static_cast<CFBooleanRef>(cap)));
    if (cap != nullptr) CFRelease(cap);

    if (smart_capable) {
      SsdSmartHealth candidate;
      if (read_nvme_smart_for_service(entry, candidate)) {
        if (is_internal_block_device(entry)) {
          IOObjectRelease(entry);
          IOObjectRelease(iter);
          return candidate;
        }
        if (!fallback_health.available) {
          fallback_health = candidate;
        }
      }
    }
    IOObjectRelease(entry);
  }
  IOObjectRelease(iter);
  return fallback_health;
}

std::string read_proc_cwd(pid_t pid) {
  if (pid <= 0) return {};
  struct proc_vnodepathinfo vpi{};
  int r = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi,
                       PROC_PIDVNODEPATHINFO_SIZE);
  if (r != static_cast<int>(PROC_PIDVNODEPATHINFO_SIZE)) return {};
  vpi.pvi_cdir.vip_path[sizeof(vpi.pvi_cdir.vip_path) - 1] = '\0';
  return std::string(vpi.pvi_cdir.vip_path);
}

std::string read_proc_args(pid_t pid) {
  if (pid <= 0) return {};
  std::string exec_path;
  std::string args;
  if (read_procargs2(pid, exec_path, args)) {
    return args;
  }
  return {};
}

MonitorState::MonitorState(SysGuardConfig cfg, std::string daily_state_path)
    : config_(std::move(cfg)), daily_state_path_(std::move(daily_state_path)) {
  mach_timebase_info_data_t tb{};
  mach_timebase_info(&tb);
  tb_numer_ = tb.numer ? tb.numer : 1;
  tb_denom_ = tb.denom ? tb.denom : 1;

  vm_size_t ps = 16384;
  if (host_page_size(mach_host_self(), &ps) == KERN_SUCCESS && ps > 0) {
    page_size_ = static_cast<uint64_t>(ps);
  }

  uint64_t memsz = 0;
  size_t len = sizeof(memsz);
  if (sysctlbyname("hw.memsize", &memsz, &len, nullptr, 0) == 0 && memsz > 0) {
    hw_memsize_ = memsz;
  }

  cached_podman_machine_name_ = config_.podman_default_machine;

  today_yyyymmdd_ = local_yyyymmdd();
  uint64_t hw_now = read_hw_disk_write_bytes();
  DailyWriteState saved = load_daily_write_state(daily_state_path_);
  if (saved.valid && saved.yyyymmdd == today_yyyymmdd_ &&
      saved.start_written_bytes <= hw_now) {
    today_start_written_bytes_ = saved.start_written_bytes;
  } else {
    today_start_written_bytes_ = hw_now;
    if (!daily_state_path_.empty()) {
      save_daily_write_state(daily_state_path_, today_yyyymmdd_,
                             today_start_written_bytes_);
    }
  }
}

void MonitorState::reset_deltas() {
  has_prev_cpu_ = false;
  has_prev_self_ = false;
  has_prev_hw_write_ = false;
  prev_proc_.clear();
  last_sys_ps_ts_ = -1.0;
}

void MonitorState::set_config(SysGuardConfig cfg) {
  config_ = std::move(cfg);
  cached_podman_machine_name_ = config_.podman_default_machine;
  vm_env_checked_ts_ = -1.0;
}

std::vector<MetricPoint> MonitorState::copy_history() const {
  std::vector<MetricPoint> out;
  out.reserve(history_count_);
  size_t start = (history_count_ < kHistoryCapacity) ? 0 : history_head_;
  for (size_t i = 0; i < history_count_; ++i) {
    out.push_back(history_[(start + i) % kHistoryCapacity]);
  }
  return out;
}

FastMetrics MonitorState::sample_fast_metrics() {
  FastMetrics m;
  const double now = monotonic_now_sec();
  m.sample_timestamp_sec = now;
  m.ram_total_bytes = hw_memsize_;

  // 1. RAM via host_statistics64
  vm_statistics64_data_t vm{};
  mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
  if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                        reinterpret_cast<host_info64_t>(&vm),
                        &count) == KERN_SUCCESS) {
    uint64_t app_pages =
        vm.internal_page_count > vm.purgeable_count
            ? (vm.internal_page_count - vm.purgeable_count)
            : 0;
    uint64_t used_pages =
        app_pages + vm.wire_count + vm.compressor_page_count;
    m.ram_used_bytes = used_pages * page_size_;
    if (m.ram_total_bytes > 0 && m.ram_used_bytes > m.ram_total_bytes) {
      m.ram_used_bytes = m.ram_total_bytes;
    }
    m.ram_compressed_bytes =
        static_cast<uint64_t>(vm.compressor_page_count) * page_size_;
    m.ram_wired_bytes = static_cast<uint64_t>(vm.wire_count) * page_size_;
    if (m.ram_total_bytes > m.ram_used_bytes) {
      m.ram_free_bytes = m.ram_total_bytes - m.ram_used_bytes;
    }
  }

  // 2. Swap via vm.swapusage
  struct xsw_usage xsw{};
  size_t xsw_len = sizeof(xsw);
  if (sysctlbyname("vm.swapusage", &xsw, &xsw_len, nullptr, 0) == 0) {
    m.swap_used_bytes = xsw.xsu_used;
    m.swap_total_bytes = xsw.xsu_total;
  }

  // 3. Memory pressure via kern.memorystatus_level
  int level = 100;
  size_t level_len = sizeof(level);
  if (sysctlbyname("kern.memorystatus_level", &level, &level_len, nullptr, 0) == 0) {
    m.memory_free_pct = std::clamp(level, 0, 100);
  }

  // 4. Host CPU % delta
  host_cpu_load_info_data_t cpu{};
  mach_msg_type_number_t cpu_count = HOST_CPU_LOAD_INFO_COUNT;
  if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                      reinterpret_cast<host_info_t>(&cpu),
                      &cpu_count) == KERN_SUCCESS) {
    uint64_t user = cpu.cpu_ticks[CPU_STATE_USER];
    uint64_t sys = cpu.cpu_ticks[CPU_STATE_SYSTEM];
    uint64_t idle = cpu.cpu_ticks[CPU_STATE_IDLE];
    uint64_t nice = cpu.cpu_ticks[CPU_STATE_NICE];

    if (has_prev_cpu_) {
      uint64_t d_user = user >= prev_cpu_user_ ? user - prev_cpu_user_ : 0;
      uint64_t d_sys = sys >= prev_cpu_sys_ ? sys - prev_cpu_sys_ : 0;
      uint64_t d_idle = idle >= prev_cpu_idle_ ? idle - prev_cpu_idle_ : 0;
      uint64_t d_nice = nice >= prev_cpu_nice_ ? nice - prev_cpu_nice_ : 0;
      uint64_t d_total = d_user + d_sys + d_idle + d_nice;
      if (d_total > 0) {
        m.cpu_used_pct =
            100.0 * static_cast<double>(d_user + d_sys + d_nice) /
            static_cast<double>(d_total);
      }
    }
    prev_cpu_user_ = user;
    prev_cpu_sys_ = sys;
    prev_cpu_idle_ = idle;
    prev_cpu_nice_ = nice;
    has_prev_cpu_ = true;
  }

  // 5. Disk space via statvfs
  struct statvfs sv{};
  if (statvfs("/System/Volumes/Data", &sv) == 0 || statvfs("/", &sv) == 0) {
    uint64_t total = static_cast<uint64_t>(sv.f_blocks) * sv.f_frsize;
    uint64_t avail = static_cast<uint64_t>(sv.f_bavail) * sv.f_frsize;
    m.disk_total_bytes = total;
    m.disk_avail_bytes = avail;
    if (total > 0) {
      double used = total > avail ? static_cast<double>(total - avail) : 0.0;
      m.disk_used_pct = 100.0 * used / static_cast<double>(total);
    }
  }

  // 6. Hardware SSD bytes written & rate via IOKit
  uint64_t hw_written = read_hw_disk_write_bytes();
  m.hw_disk_written_total_bytes = hw_written;
  int today = local_yyyymmdd();
  if (today != today_yyyymmdd_ || hw_written < today_start_written_bytes_) {
    today_yyyymmdd_ = today;
    today_start_written_bytes_ = hw_written;
    if (!daily_state_path_.empty()) {
      save_daily_write_state(daily_state_path_, today_yyyymmdd_,
                             today_start_written_bytes_);
    }
  }
  m.hw_disk_written_today_bytes =
      hw_written >= today_start_written_bytes_
          ? (hw_written - today_start_written_bytes_)
          : 0;
  if (has_prev_hw_write_ && now > prev_hw_write_ts_ &&
      hw_written >= prev_hw_written_bytes_) {
    double dt = now - prev_hw_write_ts_;
    if (dt > 0.05) {
      m.hw_disk_write_mb_s =
          static_cast<double>(hw_written - prev_hw_written_bytes_) /
          (static_cast<double>(kMB) * dt);
    }
  }
  prev_hw_written_bytes_ = hw_written;
  prev_hw_write_ts_ = now;
  has_prev_hw_write_ = true;

  // 7. Self footprint & CPU
  rusage_info_v4 ri{};
  if (proc_pid_rusage(getpid(), RUSAGE_INFO_V4,
                      reinterpret_cast<rusage_info_t*>(&ri)) == 0) {
    m.self_footprint_bytes = ri.ri_phys_footprint;
    uint64_t cpu_ns = ticks_to_ns(ri.ri_user_time + ri.ri_system_time,
                                  tb_numer_, tb_denom_);
    if (has_prev_self_ && now > prev_self_ts_ && cpu_ns >= prev_self_cpu_ns_) {
      double dt_ns = (now - prev_self_ts_) * 1e9;
      m.self_cpu_pct =
          100.0 * static_cast<double>(cpu_ns - prev_self_cpu_ns_) / dt_ns;
    }
    prev_self_cpu_ns_ = cpu_ns;
    prev_self_ts_ = now;
    has_prev_self_ = true;
  }

  // 8. Push into 15-minute trend ring buffer
  float ram_r = (m.ram_total_bytes > 0)
                    ? static_cast<float>(static_cast<double>(m.ram_used_bytes) /
                                         static_cast<double>(m.ram_total_bytes))
                    : 0.0f;
  float swap_g = static_cast<float>(static_cast<double>(m.swap_used_bytes) /
                                    static_cast<double>(kGB));
  float write_ms = static_cast<float>(m.hw_disk_write_mb_s);
  history_[history_head_] = MetricPoint{ram_r, swap_g, write_ms};
  history_head_ = (history_head_ + 1) % kHistoryCapacity;
  if (history_count_ < kHistoryCapacity) {
    history_count_ += 1;
  }

  return m;
}

DeepMetrics MonitorState::sample_deep_metrics(const FastMetrics& fast,
                                            uint64_t orphan_min_age_sec,
                                            bool force_sys_scan) {
  DeepMetrics deep;
  const double now_mono = monotonic_now_sec();
  const uint64_t now_wall = wall_now_sec();
  const uid_t my_uid = getuid();
  const pid_t self_pid = getpid();
  deep.deep_scan_timestamp_sec = now_mono;

  struct LiveProc {
    pid_t pid = 0;
    pid_t ppid = 0;
    uid_t uid = 0;
    uint64_t start_sec = 0;
    uint64_t mem_bytes = 0;
    double cpu_pct = 0.0;
    double disk_write_mb_s = 0.0;
    uint64_t session_written_bytes = 0;
    uint64_t uptime_sec = 0;
    const CachedCmd* cmd = nullptr;
  };

  // 1. Enumerate total PID count + current user PIDs directly in kernel
  int all_bytes = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
  int total_proc_count =
      (all_bytes > 0)
          ? static_cast<int>(static_cast<size_t>(all_bytes) / sizeof(pid_t))
          : 0;

  int uid_bytes =
      proc_listpids(PROC_UID_ONLY, static_cast<uint32_t>(my_uid), nullptr, 0);
  size_t cap =
      ((uid_bytes > 0) ? (static_cast<size_t>(uid_bytes) / sizeof(pid_t)) : 256) +
      128;
  pids_buf_.resize(cap);
  int ret_bytes = proc_listpids(
      PROC_UID_ONLY, static_cast<uint32_t>(my_uid), pids_buf_.data(),
      static_cast<int>(pids_buf_.size() * sizeof(pid_t)));
  const size_t num_uid_pids =
      (ret_bytes > 0)
          ? std::min<size_t>(static_cast<size_t>(ret_bytes) / sizeof(pid_t),
                             pids_buf_.size())
          : 0;
  pids_buf_.resize(num_uid_pids);

  std::vector<LiveProc> live_procs;
  live_procs.reserve(num_uid_pids + 16);

  next_prev_buf_.clear();
  next_prev_buf_.reserve(num_uid_pids + 16);

  for (pid_t pid : pids_buf_) {
    if (pid <= 0) continue;

    struct proc_bsdinfo bsd{};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, PROC_PIDTBSDINFO_SIZE) !=
        static_cast<int>(PROC_PIDTBSDINFO_SIZE)) {
      continue;
    }
    if (bsd.pbi_uid != my_uid) continue;

    rusage_info_v4 ri{};
    if (proc_pid_rusage(pid, RUSAGE_INFO_V4,
                        reinterpret_cast<rusage_info_t*>(&ri)) != 0) {
      continue;
    }

    const uint64_t key = proc_key(pid, bsd.pbi_start_tvsec);

    LiveProc lp;
    lp.pid = pid;
    lp.ppid = static_cast<pid_t>(bsd.pbi_ppid);
    lp.uid = bsd.pbi_uid;
    lp.start_sec = bsd.pbi_start_tvsec;
    lp.mem_bytes = ri.ri_phys_footprint;
    if (now_wall > lp.start_sec && lp.start_sec > 0) {
      lp.uptime_sec = now_wall - lp.start_sec;
    }

    uint64_t cpu_ns = ticks_to_ns(ri.ri_user_time + ri.ri_system_time,
                                  tb_numer_, tb_denom_);
    uint64_t wr_bytes = ri.ri_diskio_byteswritten;
    uint64_t first_wr = wr_bytes;

    auto prev_it = prev_proc_.find(key);
    if (prev_it != prev_proc_.end()) {
      first_wr = prev_it->second.first_write_bytes;
      if (wr_bytes >= first_wr) {
        lp.session_written_bytes = wr_bytes - first_wr;
      } else {
        first_wr = wr_bytes;
      }
      if (now_mono > prev_it->second.timestamp_sec) {
        double dt = now_mono - prev_it->second.timestamp_sec;
        if (dt > 0.05) {
          if (cpu_ns >= prev_it->second.cpu_ns) {
            lp.cpu_pct =
                100.0 * static_cast<double>(cpu_ns - prev_it->second.cpu_ns) /
                (dt * 1e9);
          }
          if (wr_bytes >= prev_it->second.write_bytes) {
            lp.disk_write_mb_s =
                static_cast<double>(wr_bytes - prev_it->second.write_bytes) /
                (static_cast<double>(kMB) * dt);
          }
        }
      }
    }
    next_prev_buf_[key] = PrevProcCounters{cpu_ns, wr_bytes, first_wr, now_mono};

    auto cmd_it = cmd_cache_.find(key);
    if (cmd_it == cmd_cache_.end()) {
      CachedCmd cached;
      std::string exec_path;
      std::string args;
      if (read_procargs2(pid, exec_path, args)) {
        cached.comm =
            exec_path.empty() ? std::string(bsd.pbi_comm) : std::move(exec_path);
        cached.args = std::move(args);
      } else {
        cached.comm = bsd.pbi_name[0] ? std::string(bsd.pbi_name)
                                      : std::string(bsd.pbi_comm);
        cached.args = cached.comm;
      }
      cached.comm_base = basename_of(cached.comm);
      cached.group_name = classify_group_name(cached.comm, cached.args);
      cached.is_dev_candidate =
          is_dev_server_candidate(cached.comm, cached.comm_base, cached.args);
      cached.is_orbstack =
          contains_ci(cached.comm, "OrbStack.app/Contents/MacOS/OrbStack");
      cached.is_orbstack_vmgr =
          contains_ci(cached.args, "OrbStack Helper vmgr");
      cmd_it = cmd_cache_.emplace(key, std::move(cached)).first;
    }

    lp.cmd = &cmd_it->second;
    live_procs.push_back(lp);
  }

  prev_proc_.swap(next_prev_buf_);
  for (auto it = cmd_cache_.begin(); it != cmd_cache_.end();) {
    if (prev_proc_.find(it->first) == prev_proc_.end()) {
      it = cmd_cache_.erase(it);
    } else {
      ++it;
    }
  }

  // 2. Adaptive root / _windowserver daemon sampling via /bin/ps
  const bool need_sys_refresh =
      force_sys_scan || (last_sys_ps_ts_ < 0.0) ||
      (cached_fseventsd_rss_ >= config_.fseventsd_warn_bytes / 2) ||
      (cached_fseventsd_cpu_ >= 25.0) ||
      ((now_mono - last_sys_ps_ts_) >= 45.0);

  if (need_sys_refresh) {
    cached_sys_procs_ = sample_system_daemons_ps();
    last_sys_ps_ts_ = now_mono;
    cached_fseventsd_pid_ = 0;
    cached_fseventsd_rss_ = 0;
    cached_fseventsd_cpu_ = 0.0;
    for (const auto& sp : cached_sys_procs_) {
      if (basename_of(sp.comm) == "fseventsd") {
        cached_fseventsd_pid_ = sp.pid;
        cached_fseventsd_rss_ = sp.mem_bytes;
        cached_fseventsd_cpu_ = sp.cpu_pct;
        break;
      }
    }
  }

  deep.fseventsd_pid = cached_fseventsd_pid_;
  deep.fseventsd_rss_bytes = cached_fseventsd_rss_;
  deep.fseventsd_cpu_pct = cached_fseventsd_cpu_;

  std::vector<GroupInput> group_in;
  group_in.reserve(live_procs.size() + 16);
  for (const auto& lp : live_procs) {
    group_in.push_back(GroupInput{lp.pid, lp.ppid, lp.start_sec, lp.mem_bytes,
                                  lp.cpu_pct, lp.uptime_sec, false,
                                  &lp.cmd->comm, &lp.cmd->args,
                                  &lp.cmd->group_name});
  }
  for (const auto& sp : cached_sys_procs_) {
    std::string base = basename_of(sp.comm);
    if (base == "fseventsd" || base == "WindowServer" ||
        sp.mem_bytes >= 300 * kMB || sp.cpu_pct >= 40.0) {
      group_in.push_back(GroupInput{sp.pid, sp.ppid, sp.start_sec, sp.mem_bytes,
                                    sp.cpu_pct, sp.uptime_sec, true, &sp.comm,
                                    &sp.args, nullptr});
    }
  }

  if (deep.fseventsd_cpu_pct >= config_.fseventsd_warn_cpu_pct ||
      deep.fseventsd_rss_bytes >= config_.fseventsd_warn_bytes) {
    fseventsd_high_strikes_ += 1;
  } else {
    fseventsd_high_strikes_ = 0;
  }
  deep.fseventsd_high_strikes = fseventsd_high_strikes_;
  deep.total_procs = std::max(total_proc_count, static_cast<int>(num_uid_pids));

  // 3. Group processes (zero ProcEntry string copies; partial-sort top CPU by index)
  std::vector<AppGroup> groups = group_inputs(group_in, self_pid);

  if (!groups.empty()) {
    std::vector<size_t> cpu_idx(groups.size());
    for (size_t i = 0; i < groups.size(); ++i) cpu_idx[i] = i;
    size_t top_cpu_n = std::min<size_t>(6, groups.size());
    std::partial_sort(cpu_idx.begin(),
                      cpu_idx.begin() + static_cast<std::ptrdiff_t>(top_cpu_n),
                      cpu_idx.end(), [&groups](size_t a, size_t b) {
                        return groups[a].cpu_pct > groups[b].cpu_pct;
                      });
    deep.top_cpu_groups.reserve(top_cpu_n);
    for (size_t i = 0; i < top_cpu_n; ++i) {
      deep.top_cpu_groups.push_back(groups[cpu_idx[i]]);
    }

    size_t top_mem_n = std::min<size_t>(12, groups.size());
    deep.top_mem_groups.reserve(top_mem_n);
    for (size_t i = 0; i < top_mem_n; ++i) {
      deep.top_mem_groups.push_back(std::move(groups[i]));
    }
  }

  // 3b. Top Disk Writers + heavy-writer alert check (zero-copy)
  bool saw_proc_writer = false;
  std::string heavy_writer_base;
  double heavy_writer_mb_s = 0.0;

  for (const auto& lp : live_procs) {
    if (lp.pid == self_pid) continue;
    if (!saw_proc_writer &&
        lp.disk_write_mb_s >= config_.proc_disk_write_warn_mb_s) {
      saw_proc_writer = true;
      heavy_writer_base = lp.cmd->comm_base;
      heavy_writer_mb_s = lp.disk_write_mb_s;
    }
    if (lp.disk_write_mb_s >= 0.05 || lp.session_written_bytes >= 10 * kMB) {
      DiskWriter dw;
      dw.pid = lp.pid;
      dw.start_sec = lp.start_sec;
      dw.name = lp.cmd->group_name;
      dw.write_mb_s = lp.disk_write_mb_s;
      dw.session_written_bytes = lp.session_written_bytes;
      dw.mem_bytes = lp.mem_bytes;
      dw.is_system = (dw.name == "SysGuard (Self)");
      deep.top_disk_writers.push_back(std::move(dw));
    }
  }
  std::sort(deep.top_disk_writers.begin(), deep.top_disk_writers.end(),
            [](const DiskWriter& a, const DiskWriter& b) {
              if (std::abs(a.write_mb_s - b.write_mb_s) > 0.1) {
                return a.write_mb_s > b.write_mb_s;
              }
              return a.session_written_bytes > b.session_written_bytes;
            });
  if (deep.top_disk_writers.size() > 5) deep.top_disk_writers.resize(5);

  // 4. Build lookup maps for socket/orphan/VM inspection
  std::unordered_map<pid_t, const LiveProc*> by_pid;
  std::unordered_map<pid_t, std::vector<pid_t>> children_by_ppid;
  by_pid.reserve(live_procs.size());
  for (const auto& lp : live_procs) {
    by_pid.emplace(lp.pid, &lp);
    children_by_ppid[lp.ppid].push_back(lp.pid);
  }

  // 4a. VM status (OrbStack & Podman) with 300s cached environment probe
  if (vm_env_checked_ts_ < 0.0 || (now_mono - vm_env_checked_ts_) >= 300.0) {
    cached_orbstack_installed_ =
        !find_executable({"/usr/local/bin/orbctl", "/opt/homebrew/bin/orbctl"})
             .empty();
    cached_podman_installed_ =
        !find_executable({"/opt/homebrew/bin/podman", "/usr/local/bin/podman"})
             .empty();
    cached_podman_machine_name_ =
        detect_podman_machine_name(config_.podman_default_machine);
    vm_env_checked_ts_ = now_mono;
  }
  if (smart_checked_ts_ < 0.0 || (now_mono - smart_checked_ts_) >= 300.0) {
    cached_ssd_smart_ = read_ssd_smart_health();
    smart_checked_ts_ = now_mono;
  }
  deep.ssd_smart = cached_ssd_smart_;
  deep.vm_status.orbstack_installed = cached_orbstack_installed_;
  deep.vm_status.podman_installed = cached_podman_installed_;
  deep.vm_status.podman_machine_name = cached_podman_machine_name_;

  for (const auto& lp : live_procs) {
    if (lp.cmd->is_orbstack || lp.cmd->is_orbstack_vmgr) {
      if (lp.cmd->is_orbstack_vmgr) {
        deep.vm_status.orbstack_running = true;
      }
      deep.vm_status.orbstack_mem_bytes += lp.mem_bytes;
    }
    const std::string& base = lp.cmd->comm_base;
    if ((base == "vfkit" || base == "gvproxy" || base == "krunkit" ||
         base.rfind("qemu-system", 0) == 0) &&
        (contains_ci(lp.cmd->args, "podman") ||
         contains_ci(lp.cmd->args, deep.vm_status.podman_machine_name))) {
      deep.vm_status.podman_running = true;
      deep.vm_status.podman_mem_bytes += lp.mem_bytes;
    }
  }

  // Per-scan TCP socket cache shared across Step 4b (ports) and Step 4c (orphans)
  struct CachedSockets {
    std::vector<uint16_t> listening;
    int established = 0;
    std::vector<uint16_t> est_local_ports;
  };
  std::unordered_map<pid_t, CachedSockets> sock_cache;
  auto get_sockets = [&](pid_t target_pid) -> const CachedSockets& {
    auto it = sock_cache.find(target_pid);
    if (it != sock_cache.end()) return it->second;
    CachedSockets cs;
    inspect_tcp_sockets_with_buf(target_pid, cs.listening, cs.established,
                                 &cs.est_local_ports, fds_buf_);
    return sock_cache.emplace(target_pid, std::move(cs)).first->second;
  };

  auto has_t3_anc = [&](pid_t start_pid) -> bool {
    pid_t cur = start_pid;
    for (int hop = 0; hop < 5; ++hop) {
      auto it = by_pid.find(cur);
      if (it == by_pid.end() || !it->second) break;
      const LiveProc* entry = it->second;
      if (contains_ci(entry->cmd->args, "T3 Code") ||
          contains_ci(entry->cmd->comm, "T3 Code")) {
        return true;
      }
      if (entry->ppid <= 1 || entry->ppid == cur) break;
      cur = entry->ppid;
    }
    return false;
  };

  // 4b. Listening local dev ports (targeted syscalls only on dev server processes)
  std::unordered_set<uint64_t> seen_pid_port;
  for (const auto& lp : live_procs) {
    if (lp.pid == self_pid) continue;
    if (!lp.cmd->is_dev_candidate) continue;

    const CachedSockets& cs = get_sockets(lp.pid);
    if (cs.listening.empty()) continue;

    int est = cs.established;
    const std::string& base = lp.cmd->comm_base;
    if (base == "postgres") {
      auto ch_it = children_by_ppid.find(lp.pid);
      if (ch_it != children_by_ppid.end()) {
        for (pid_t cpid : ch_it->second) {
          est += get_sockets(cpid).established;
        }
      }
    }

    bool protected_svc =
        (base == "cli-proxy-api") ||
        (base == "cloudflared" &&
         (has_t3_anc(lp.pid) ||
          contains_ci(lp.cmd->args, "tunnel --no-autoupdate")));

    std::string sname = service_display_name(base, lp.cmd->args);
    std::string hint = service_project_hint(lp.pid, base, lp.cmd->args);

    for (uint16_t port : cs.listening) {
      uint64_t pair_key =
          (static_cast<uint64_t>(static_cast<uint32_t>(lp.pid)) << 16) |
          static_cast<uint64_t>(port);
      if (!seen_pid_port.insert(pair_key).second) continue;

      ListeningService svc;
      svc.pid = lp.pid;
      svc.start_sec = lp.start_sec;
      svc.port = port;
      svc.name = sname;
      svc.project_hint = hint;
      svc.established_conns = est;
      svc.is_http_like = is_http_dev_port(base, lp.cmd->args, port);
      svc.is_protected = protected_svc;
      deep.listening_services.push_back(std::move(svc));
    }
  }
  std::sort(deep.listening_services.begin(), deep.listening_services.end(),
            [](const ListeningService& a, const ListeningService& b) {
              if (a.port != b.port) return a.port < b.port;
              return a.pid < b.pid;
            });

  // 4c. Orphan detection (with socket inspection ONLY on candidates)
  auto lookup_live_parent = [&](pid_t ppid_arg, pid_t& out_grand_ppid,
                                std::string& out_pbase) -> bool {
    auto it = by_pid.find(ppid_arg);
    if (it == by_pid.end() || !it->second) return false;
    out_grand_ppid = it->second->ppid;
    out_pbase = it->second->cmd->comm_base;
    return true;
  };

  std::unordered_set<pid_t> covered_pids;
  for (const auto& lp : live_procs) {
    if (lp.pid == self_pid) continue;
    if (covered_pids.count(lp.pid)) continue;

    OrphanKind kind{};
    std::string label;
    bool auto_reap = false;
    bool needs_kill = false;
    if (!is_orphan_candidate_impl(lp.pid, lp.ppid, lp.uptime_sec, false,
                                  lp.cmd->comm, lp.cmd->comm_base, lp.cmd->args,
                                  lookup_live_parent, orphan_min_age_sec, kind,
                                  label, auto_reap, needs_kill)) {
      continue;
    }

    pid_t root_pid = lp.pid;
    if (kind == OrphanKind::DevServer && lp.ppid > 1) {
      auto parent_it = by_pid.find(lp.ppid);
      if (parent_it != by_pid.end() && parent_it->second->ppid == 1) {
        root_pid = parent_it->first;
      }
    }
    if (covered_pids.count(root_pid)) continue;

    std::vector<pid_t> tree_pids = {root_pid};
    for (size_t idx = 0; idx < tree_pids.size() && tree_pids.size() < 64; ++idx) {
      auto ch_it = children_by_ppid.find(tree_pids[idx]);
      if (ch_it == children_by_ppid.end()) continue;
      for (pid_t cpid : ch_it->second) {
        if (std::find(tree_pids.begin(), tree_pids.end(), cpid) == tree_pids.end()) {
          tree_pids.push_back(cpid);
        }
      }
    }

    std::vector<uint16_t> listening_ports;
    int total_established = 0;
    std::vector<uint16_t> est_local_ports;
    uint64_t total_mem = 0;
    std::vector<std::pair<pid_t, uint64_t>> related;

    for (pid_t tpid : tree_pids) {
      covered_pids.insert(tpid);
      auto pit = by_pid.find(tpid);
      if (pit != by_pid.end()) {
        total_mem += pit->second->mem_bytes;
        related.emplace_back(tpid, pit->second->start_sec);
      }
      if (kind != OrphanKind::StuckLoop) {
        const CachedSockets& cs = get_sockets(tpid);
        for (uint16_t port : cs.listening) {
          if (std::find(listening_ports.begin(), listening_ports.end(), port) ==
              listening_ports.end()) {
            listening_ports.push_back(port);
          }
        }
        total_established += cs.established;
        est_local_ports.insert(est_local_ports.end(), cs.est_local_ports.begin(),
                               cs.est_local_ports.end());
      }
    }

    bool active = false;
    int reported_conns = total_established;
    if (kind == OrphanKind::IdleDebugChrome) {
      uint16_t dbg_port =
          parse_u16_flag(lp.cmd->args, "--remote-debugging-port=");
      if (dbg_port == 0) continue;
      int dbg_conns = 0;
      for (uint16_t eport : est_local_ports) {
        if (eport == dbg_port) ++dbg_conns;
      }
      reported_conns = dbg_conns;
      active = (dbg_conns > 0);
      if (listening_ports.empty()) listening_ports.push_back(dbg_port);
    } else if (kind != OrphanKind::StuckLoop) {
      active = (total_established > 0);
    }

    if (active) continue;

    OrphanProc orph;
    orph.pid = lp.pid;
    orph.start_sec = lp.start_sec;
    orph.kind = kind;
    orph.label = label;
    orph.mem_bytes = total_mem;
    orph.uptime_sec = lp.uptime_sec;
    orph.listening_ports = listening_ports;
    orph.established_conns = reported_conns;
    orph.auto_reap_safe = auto_reap;
    orph.needs_sigkill = needs_kill;
    orph.related_pids = std::move(related);
    orph.detail =
        build_orphan_detail(total_mem, lp.uptime_sec, listening_ports, reported_conns);

    deep.orphans.push_back(std::move(orph));
  }

  std::sort(deep.orphans.begin(), deep.orphans.end(),
            [](const OrphanProc& a, const OrphanProc& b) {
              return a.mem_bytes > b.mem_bytes;
            });

  // 5. Evaluate alerts
  deep.alerts = evaluate_alerts_impl(fast, deep, saw_proc_writer,
                                     heavy_writer_base, heavy_writer_mb_s,
                                     config_);
  for (const auto& a : deep.alerts) {
    if (static_cast<int>(a.severity) > static_cast<int>(deep.max_severity)) {
      deep.max_severity = a.severity;
    }
  }

  return deep;
}

std::string classify_group_name(const std::string& comm, const std::string& args) {
  std::string base = basename_of(comm);
  if (base.empty()) base = basename_of(first_token(args));

  if (base == "fseventsd") return "fseventsd";
  if (base == "WindowServer") return "WindowServer";
  if (base == "kernel_task") return "kernel_task";
  if (base == "SysGuard") return "SysGuard (Self)";

  if (contains_ci(args, "Google Chrome.app") || base == "Google Chrome") {
    std::string udd = extract_flag_value(args, "--user-data-dir=");
    if (!udd.empty() && udd.find("/.cache/") != std::string::npos) {
      std::string prof = basename_of(udd);
      if (!prof.empty()) return "Chrome (" + prof + ")";
    }
    return "Google Chrome";
  }

  if (contains_ci(args, "Steam.AppBundle") || base == "steam_osx" ||
      base == "Steam Helper" || base == "ipcserver") {
    return "Steam";
  }

  if (base == "postgres" || contains_ci(comm, "/postgres")) {
    return "PostgreSQL";
  }

  if (contains_ci(args, "antigravity")) return "Antigravity";
  if (contains_ci(args, "codegraph")) return "codegraph (MCP)";
  if (contains_ci(args, "vitest") || contains_ci(args, "svelte-kit")) {
    return "Vitest / SvelteKit";
  }

  if (base == "claude" || contains_ci(comm, "/.local/share/claude/") ||
      args.rfind("claude ", 0) == 0) {
    return "Claude Code";
  }

  if (contains_ci(args, "mcp") &&
      (base == "node" || base == "npm" || base == "npx" ||
       contains_ci(args, "playwright-mcp") ||
       contains_ci(args, "chrome-devtools-mcp") ||
       contains_ci(args, "convex mcp"))) {
    return "MCP Servers";
  }

  if ((base == "node" || base == "bun" || base == "pnpm") &&
      (contains_ci(args, "vite") || contains_ci(args, "next dev") ||
       contains_ci(args, "webpack") || contains_ci(args, "astro dev") ||
       contains_ci(args, "nuxt dev"))) {
    return "Vite / Dev Servers";
  }

  std::string app = extract_app_bundle(comm);
  if (app.empty()) app = extract_app_bundle(args);
  if (!app.empty()) {
    if (app == "ChatGPT" && contains_ci(args, "codex")) return "ChatGPT / Codex";
    if (app == "Claude") return "Claude Desktop";
    return app;
  }

  if (base.empty()) return "unknown";
  return base;
}

std::vector<AppGroup> group_processes(const std::vector<ProcEntry>& procs,
                                      pid_t self_pid) {
  std::vector<GroupInput> inputs;
  inputs.reserve(procs.size());
  for (const auto& p : procs) {
    inputs.push_back(GroupInput{p.pid, p.ppid, p.start_sec, p.mem_bytes,
                                p.cpu_pct, p.uptime_sec, p.is_system, &p.comm,
                                &p.args, &p.cached_group_name});
  }
  return group_inputs(inputs, self_pid);
}

bool is_orphan_candidate(
    const ProcEntry& proc,
    const std::unordered_map<pid_t, const ProcEntry*>& by_pid,
    uint64_t min_age_sec,
    OrphanKind& out_kind,
    std::string& out_label,
    bool& out_auto_reap_safe,
    bool& out_needs_sigkill) {
  auto lookup = [&](pid_t ppid_arg, pid_t& out_grand_ppid,
                    std::string& out_pbase) -> bool {
    auto it = by_pid.find(ppid_arg);
    if (it == by_pid.end() || !it->second) return false;
    out_grand_ppid = it->second->ppid;
    out_pbase = basename_of(it->second->comm);
    return true;
  };
  return is_orphan_candidate_impl(
      proc.pid, proc.ppid, proc.uptime_sec, proc.is_system, proc.comm,
      basename_of(proc.comm), proc.args, lookup, min_age_sec, out_kind,
      out_label, out_auto_reap_safe, out_needs_sigkill);
}

bool is_orphan_candidate(const ProcEntry& proc,
                         const std::unordered_map<pid_t, ProcEntry>& by_pid,
                         uint64_t min_age_sec,
                         OrphanKind& out_kind,
                         std::string& out_label,
                         bool& out_auto_reap_safe,
                         bool& out_needs_sigkill) {
  auto lookup = [&](pid_t ppid_arg, pid_t& out_grand_ppid,
                    std::string& out_pbase) -> bool {
    auto it = by_pid.find(ppid_arg);
    if (it == by_pid.end()) return false;
    out_grand_ppid = it->second.ppid;
    out_pbase = basename_of(it->second.comm);
    return true;
  };
  return is_orphan_candidate_impl(
      proc.pid, proc.ppid, proc.uptime_sec, proc.is_system, proc.comm,
      basename_of(proc.comm), proc.args, lookup, min_age_sec, out_kind,
      out_label, out_auto_reap_safe, out_needs_sigkill);
}

std::vector<Alert> evaluate_alerts(const FastMetrics& fast,
                                   const DeepMetrics& deep,
                                   const std::vector<ProcEntry>& user_procs,
                                   const SysGuardConfig& cfg) {
  bool saw_proc_writer = false;
  std::string writer_base;
  double writer_mb_s = 0.0;
  for (const auto& p : user_procs) {
    if (p.disk_write_mb_s >= cfg.proc_disk_write_warn_mb_s) {
      saw_proc_writer = true;
      writer_base = basename_of(p.comm);
      writer_mb_s = p.disk_write_mb_s;
      break;
    }
  }
  return evaluate_alerts_impl(fast, deep, saw_proc_writer, writer_base,
                              writer_mb_s, cfg);
}

bool inspect_tcp_sockets(pid_t pid,
                         std::vector<uint16_t>& listening_ports,
                         int& established_count,
                         std::vector<uint16_t>* established_local_ports) {
  std::vector<struct proc_fdinfo> local_buf;
  return inspect_tcp_sockets_with_buf(pid, listening_ports, established_count,
                                      established_local_ports, local_buf);
}

std::string format_bytes(uint64_t bytes) {
  char buf[32];
  double d = static_cast<double>(bytes);
  if (bytes >= kGB) {
    std::snprintf(buf, sizeof(buf), "%.2f GB", d / static_cast<double>(kGB));
  } else if (bytes >= kMB) {
    std::snprintf(buf, sizeof(buf), "%.1f MB", d / static_cast<double>(kMB));
  } else if (bytes >= kKB) {
    std::snprintf(buf, sizeof(buf), "%.0f KB", d / static_cast<double>(kKB));
  } else {
    std::snprintf(buf, sizeof(buf), "%llu B",
                  static_cast<unsigned long long>(bytes));
  }
  return std::string(buf);
}

std::string format_bytes_compact(uint64_t bytes) {
  char buf[24];
  double d = static_cast<double>(bytes);
  if (bytes >= 10ULL * kGB) {
    std::snprintf(buf, sizeof(buf), "%.0fG", d / static_cast<double>(kGB));
  } else if (bytes >= kGB) {
    std::snprintf(buf, sizeof(buf), "%.1fG", d / static_cast<double>(kGB));
  } else if (bytes >= kMB) {
    std::snprintf(buf, sizeof(buf), "%.0fM", d / static_cast<double>(kMB));
  } else {
    std::snprintf(buf, sizeof(buf), "%.0fK", d / static_cast<double>(kKB));
  }
  return std::string(buf);
}

std::string format_uptime(uint64_t seconds) {
  char buf[32];
  if (seconds >= 86400) {
    uint64_t d = seconds / 86400;
    uint64_t h = (seconds % 86400) / 3600;
    std::snprintf(buf, sizeof(buf), "%llud %lluh",
                  static_cast<unsigned long long>(d),
                  static_cast<unsigned long long>(h));
  } else if (seconds >= 3600) {
    uint64_t h = seconds / 3600;
    uint64_t m = (seconds % 3600) / 60;
    std::snprintf(buf, sizeof(buf), "%lluh %llum",
                  static_cast<unsigned long long>(h),
                  static_cast<unsigned long long>(m));
  } else if (seconds >= 60) {
    std::snprintf(buf, sizeof(buf), "%llum",
                  static_cast<unsigned long long>(seconds / 60));
  } else {
    std::snprintf(buf, sizeof(buf), "%llus",
                  static_cast<unsigned long long>(seconds));
  }
  return std::string(buf);
}

}  // namespace sysguard
