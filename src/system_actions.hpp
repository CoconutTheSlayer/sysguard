#pragma once

#include <cstdint>
#include <string>
#include <sys/types.h>

namespace sysguard {

struct OrphanProc;
struct AppGroup;
struct ListeningService;

bool terminate_orphan(const OrphanProc& orphan, std::string& err_msg);
bool terminate_group(const AppGroup& group, bool force, std::string& err_msg);
bool terminate_service(const ListeningService& svc, std::string& err_msg);
bool terminate_pid_verified(pid_t pid,
                            uint64_t expected_start_sec,
                            bool force,
                            std::string& err_msg);

[[nodiscard]] std::string detect_podman_machine_name(
    const std::string& fallback = "podman-machine-default");

bool control_orbstack(bool start, std::string& err_msg);
bool control_podman_machine(const std::string& name,
                            bool start,
                            std::string& err_msg);

bool restart_fseventsd_admin(std::string& err_msg);
[[nodiscard]] bool is_passwordless_fseventsd_configured();
bool install_passwordless_fseventsd_rule(std::string& err_msg);
bool remove_passwordless_fseventsd_rule(std::string& err_msg);
bool restart_fseventsd_smart(bool allow_interactive_prompt,
                             std::string& err_msg);

}  // namespace sysguard
