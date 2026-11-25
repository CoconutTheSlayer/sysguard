#pragma once

#include <string>
#include <vector>

namespace sysguard {

bool run_command_capture(const std::vector<std::string>& argv,
                         std::string& output,
                         int& exit_code,
                         int timeout_ms = 30000);

[[nodiscard]] std::string find_executable(
    const std::vector<std::string>& candidates);

}  // namespace sysguard
