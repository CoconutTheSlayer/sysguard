#include "system_actions.hpp"

#include "metrics.hpp"
#include "subprocess.hpp"

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <libproc.h>
#include <pwd.h>
#include <signal.h>
#include <sys/proc_info.h>
#include <unistd.h>

namespace sysguard {

namespace {

constexpr const char* kSudoersRulePath = "/etc/sudoers.d/sysguard-fseventsd";

bool verify_pid_alive(pid_t pid,
                      uint64_t expected_start_sec,
                      bool require_same_uid) {
  if (pid <= 1 || pid == getpid()) return false;
  struct proc_bsdinfo bsd{};
  int r = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, PROC_PIDTBSDINFO_SIZE);
  if (r != static_cast<int>(PROC_PIDTBSDINFO_SIZE)) return false;
  if (require_same_uid && bsd.pbi_uid != getuid()) return false;
  if (expected_start_sec != 0 && bsd.pbi_start_tvsec != expected_start_sec) {
    return false;
  }
  return true;
}

}  // namespace

std::string detect_podman_machine_name(const std::string& fallback) {
  std::string def = fallback.empty() ? "podman-machine-default" : fallback;
  const char* home = std::getenv("HOME");
  if (!home) return def;
  std::string dir =
      std::string(home) + "/.local/share/containers/podman/machine/applehv";
  DIR* d = opendir(dir.c_str());
  if (!d) return def;
  std::string found;
  struct dirent* ent = nullptr;
  while ((ent = readdir(d)) != nullptr) {
    std::string name = ent->d_name;
    if (name.size() > 4 && name.compare(name.size() - 4, 4, ".raw") == 0) {
      std::string base = name.substr(0, name.size() - 4);
      for (const char* suf : {"-arm64", "-x86_64"}) {
        size_t slen = std::strlen(suf);
        if (base.size() > slen &&
            base.compare(base.size() - slen, slen, suf) == 0) {
          base.resize(base.size() - slen);
          break;
        }
      }
      if (!base.empty()) {
        found = base;
        break;
      }
    }
  }
  closedir(d);
  return found.empty() ? def : found;
}

bool terminate_orphan(const OrphanProc& orphan, std::string& err_msg) {
  int sig = SIGTERM;
  if (orphan.needs_sigkill) {
    sig = SIGKILL;
  } else if (orphan.kind == OrphanKind::TempPostgres) {
    sig = SIGINT;
  }

  std::vector<std::pair<pid_t, uint64_t>> targets = orphan.related_pids;
  if (targets.empty()) {
    targets.emplace_back(orphan.pid, orphan.start_sec);
  }

  int sent = 0;
  for (const auto& [pid, start_sec] : targets) {
    if (!verify_pid_alive(pid, start_sec, true)) continue;
    if (kill(pid, sig) == 0) {
      ++sent;
    } else if (errno != ESRCH) {
      err_msg = std::strerror(errno);
    }
  }

  if (sent == 0) return true;

  if (sig != SIGKILL) {
    for (int attempt = 0; attempt < 20; ++attempt) {
      bool any_alive = false;
      for (const auto& [pid, start_sec] : targets) {
        if (verify_pid_alive(pid, start_sec, true)) {
          any_alive = true;
          break;
        }
      }
      if (!any_alive) return true;
      usleep(100000);
    }
    if (orphan.kind != OrphanKind::IdleDebugChrome) {
      for (const auto& [pid, start_sec] : targets) {
        if (verify_pid_alive(pid, start_sec, true)) {
          kill(pid, SIGKILL);
        }
      }
    }
  }

  return true;
}

bool terminate_group(const AppGroup& group, bool force, std::string& err_msg) {
  if (group.is_system) {
    err_msg = "Refusing to terminate system group";
    return false;
  }
  const int sig = force ? SIGKILL : SIGTERM;
  const auto& targets = force ? group.all_pids : group.leader_pids;
  bool ok = true;
  for (const auto& [pid, start_sec] : targets) {
    if (!verify_pid_alive(pid, start_sec, true)) continue;
    if (kill(pid, sig) != 0 && errno != ESRCH) {
      err_msg = std::strerror(errno);
      ok = false;
    }
  }
  return ok;
}

bool terminate_service(const ListeningService& svc, std::string& err_msg) {
  if (svc.is_protected) {
    err_msg = "Refusing to stop protected service";
    return false;
  }
  if (!verify_pid_alive(svc.pid, svc.start_sec, true)) {
    return true;
  }
  int sig = (svc.name == "PostgreSQL") ? SIGINT : SIGTERM;
  if (kill(svc.pid, sig) != 0 && errno != ESRCH) {
    err_msg = std::strerror(errno);
    return false;
  }
  return true;
}

bool terminate_pid_verified(pid_t pid,
                            uint64_t expected_start_sec,
                            bool force,
                            std::string& err_msg) {
  if (!verify_pid_alive(pid, expected_start_sec, true)) return true;
  if (kill(pid, force ? SIGKILL : SIGTERM) != 0 && errno != ESRCH) {
    err_msg = std::strerror(errno);
    return false;
  }
  return true;
}

bool control_orbstack(bool start, std::string& err_msg) {
  std::string orb =
      find_executable({"/usr/local/bin/orbctl", "/opt/homebrew/bin/orbctl"});
  if (orb.empty()) {
    err_msg = "orbctl not found";
    return false;
  }
  std::string out;
  int rc = -1;
  if (!run_command_capture({orb, start ? "start" : "stop"}, out, rc, 60000) ||
      rc != 0) {
    err_msg = out.empty() ? "orbctl failed" : out;
    return false;
  }
  if (!start) {
    // Also quit OrbStack GUI if still open
    std::string dummy;
    int dummy_rc = 0;
    run_command_capture({"/usr/bin/pkill", "-x", "OrbStack"}, dummy, dummy_rc,
                        5000);
  }
  return true;
}

bool control_podman_machine(const std::string& name,
                            bool start,
                            std::string& err_msg) {
  std::string podman =
      find_executable({"/opt/homebrew/bin/podman", "/usr/local/bin/podman"});
  if (podman.empty()) {
    err_msg = "podman not found";
    return false;
  }
  std::string target = name.empty() ? detect_podman_machine_name() : name;
  std::string out;
  int rc = -1;
  if (!run_command_capture({podman, "machine", start ? "start" : "stop", target},
                           out, rc, 60000) ||
      rc != 0) {
    err_msg = out.empty() ? "podman command failed" : out;
    return false;
  }
  return true;
}

bool restart_fseventsd_admin(std::string& err_msg) {
  const char* script =
      "do shell script \"/usr/bin/killall fseventsd\" with administrator privileges";
  std::string out;
  int rc = -1;
  if (!run_command_capture({"/usr/bin/osascript", "-e", script}, out, rc,
                           120000) ||
      rc != 0) {
    err_msg = "Administrator authentication cancelled or failed";
    return false;
  }
  return true;
}

bool is_passwordless_fseventsd_configured() {
  if (access(kSudoersRulePath, F_OK) != 0) return false;
  std::string out;
  int rc = -1;
  return run_command_capture(
             {"/usr/bin/sudo", "-n", "-l", "/usr/bin/killall", "fseventsd"},
             out, rc, 5000) &&
         rc == 0;
}

bool install_passwordless_fseventsd_rule(std::string& err_msg) {
  struct passwd* pw = getpwuid(getuid());
  if (!pw || !pw->pw_name) {
    err_msg = "Could not resolve current username";
    return false;
  }
  std::string user = pw->pw_name;
  for (char c : user) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-' &&
        c != '.') {
      err_msg = "Unexpected username characters";
      return false;
    }
  }

  char tmpl[] = "/tmp/sysguard-sudoers-XXXXXX";
  int fd = mkstemp(tmpl);
  if (fd < 0) {
    err_msg = std::strerror(errno);
    return false;
  }
  std::string rule =
      user + " ALL=(root) NOPASSWD: /usr/bin/killall fseventsd\n";
  ssize_t written = write(fd, rule.data(), rule.size());
  close(fd);
  if (written != static_cast<ssize_t>(rule.size())) {
    unlink(tmpl);
    err_msg = "Failed to write temporary sudoers rule";
    return false;
  }

  std::string cmd = std::string("/usr/sbin/visudo -cf ") + tmpl +
                    " && /usr/bin/install -o root -g wheel -m 440 " + tmpl +
                    " " + kSudoersRulePath;
  std::string script =
      "do shell script \"" + cmd + "\" with administrator privileges";

  std::string out;
  int rc = -1;
  bool ok = run_command_capture({"/usr/bin/osascript", "-e", script}, out, rc,
                                120000) &&
            rc == 0;
  unlink(tmpl);
  if (!ok) {
    err_msg =
        out.empty() ? "Administrator authentication cancelled or failed" : out;
    return false;
  }
  return is_passwordless_fseventsd_configured();
}

bool remove_passwordless_fseventsd_rule(std::string& err_msg) {
  if (access(kSudoersRulePath, F_OK) != 0) return true;
  std::string script = std::string("do shell script \"/bin/rm -f ") +
                       kSudoersRulePath + "\" with administrator privileges";
  std::string out;
  int rc = -1;
  if (!run_command_capture({"/usr/bin/osascript", "-e", script}, out, rc,
                           120000) ||
      rc != 0) {
    err_msg = "Administrator authentication cancelled or failed";
    return false;
  }
  return true;
}

bool restart_fseventsd_smart(bool allow_interactive_prompt,
                             std::string& err_msg) {
  if (is_passwordless_fseventsd_configured()) {
    std::string out;
    int rc = -1;
    if (run_command_capture(
            {"/usr/bin/sudo", "-n", "/usr/bin/killall", "fseventsd"}, out, rc,
            5000) &&
        rc == 0) {
      return true;
    }
  }
  if (!allow_interactive_prompt) {
    err_msg = "Passwordless sudoers rule not configured";
    return false;
  }
  return restart_fseventsd_admin(err_msg);
}

}  // namespace sysguard
