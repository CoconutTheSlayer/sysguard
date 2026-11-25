#include "subprocess.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace sysguard {

bool run_command_capture(const std::vector<std::string>& argv,
                         std::string& output,
                         int& exit_code,
                         int timeout_ms) {
  output.clear();
  exit_code = -1;
  if (argv.empty()) return false;

  int pipefd[2];
  if (pipe(pipefd) != 0) return false;
  for (int i = 0; i < 2; ++i) {
    int flags = fcntl(pipefd[i], F_GETFD, 0);
    if (flags >= 0) fcntl(pipefd[i], F_SETFD, flags | FD_CLOEXEC);
  }

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
  posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDERR_FILENO);
  posix_spawn_file_actions_addclose(&actions, pipefd[0]);
  posix_spawn_file_actions_addclose(&actions, pipefd[1]);

  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  posix_spawnattr_setflags(
      &attr, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP);
  posix_spawnattr_setpgroup(&attr, 0);

  std::vector<char*> c_argv;
  c_argv.reserve(argv.size() + 1);
  for (const auto& s : argv) c_argv.push_back(const_cast<char*>(s.c_str()));
  c_argv.push_back(nullptr);

  pid_t child = 0;
  int spawn_rc = posix_spawnp(&child, argv[0].c_str(), &actions, &attr,
                              c_argv.data(), environ);
  posix_spawnattr_destroy(&attr);
  posix_spawn_file_actions_destroy(&actions);
  close(pipefd[1]);

  if (spawn_rc != 0) {
    close(pipefd[0]);
    output = std::strerror(spawn_rc);
    return false;
  }

  int fl = fcntl(pipefd[0], F_GETFL, 0);
  if (fl >= 0) fcntl(pipefd[0], F_SETFL, fl | O_NONBLOCK);

  using clock = std::chrono::steady_clock;
  const auto deadline =
      (timeout_ms > 0) ? (clock::now() + std::chrono::milliseconds(timeout_ms))
                       : clock::time_point::max();

  constexpr size_t kMaxOutputBytes = 2 * 1024 * 1024;
  char buf[4096];
  bool timed_out = false;
  bool eof = false;

  while (!eof) {
    int wait_ms = -1;
    if (timeout_ms > 0) {
      auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                     deadline - clock::now())
                     .count();
      if (rem <= 0) {
        timed_out = true;
        break;
      }
      wait_ms = static_cast<int>(std::min<long long>(rem, 60000LL));
    }

    struct pollfd pfd{};
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;
    int pr = poll(&pfd, 1, wait_ms);
    if (pr < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (pr == 0) {
      timed_out = true;
      break;
    }

    if (pfd.revents & POLLNVAL) {
      break;
    }
    if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) {
      while (true) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n > 0) {
          if (output.size() < kMaxOutputBytes) {
            size_t avail = kMaxOutputBytes - output.size();
            output.append(buf, std::min(static_cast<size_t>(n), avail));
          }
          continue;
        }
        if (n == 0) {
          eof = true;
          break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        eof = true;
        break;
      }
    }
  }
  close(pipefd[0]);

  int status = 0;
  bool reaped = false;
  if (!timed_out) {
    if (timeout_ms <= 0) {
      while (true) {
        pid_t w = waitpid(child, &status, 0);
        if (w == child) {
          reaped = true;
          break;
        }
        if (w < 0 && errno != EINTR) break;
      }
    } else {
      while (true) {
        pid_t w = waitpid(child, &status, WNOHANG);
        if (w == child) {
          reaped = true;
          break;
        }
        if (w < 0) {
          if (errno == EINTR) continue;
          break;
        }
        if (clock::now() >= deadline) {
          timed_out = true;
          break;
        }
        usleep(1000);
      }
    }
  }

  if (timed_out) {
    if (kill(-child, SIGTERM) != 0 && errno == ESRCH) {
      kill(child, SIGTERM);
    }
    for (int i = 0; i < 15; ++i) {
      pid_t w = waitpid(child, &status, WNOHANG);
      if (w == child || (w < 0 && errno != EINTR)) {
        reaped = true;
        break;
      }
      usleep(10000);
    }
    if (!reaped) {
      if (kill(-child, SIGKILL) != 0 && errno == ESRCH) {
        kill(child, SIGKILL);
      }
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    exit_code = -1;
    return false;
  }

  if (reaped && WIFEXITED(status)) {
    exit_code = WEXITSTATUS(status);
    return true;
  }
  exit_code = -1;
  return false;
}

std::string find_executable(const std::vector<std::string>& candidates) {
  for (const auto& c : candidates) {
    if (access(c.c_str(), X_OK) == 0) return c;
  }
  return {};
}

}  // namespace sysguard
