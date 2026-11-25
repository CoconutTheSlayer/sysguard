# SysGuard v2.0

Ultra-lightweight native macOS menu bar monitor + companion `wtclean` CLI written in **C++20 / Objective-C++ (AppKit)** with direct Darwin Mach / `libproc` / `IOKit` syscalls and zero external dependencies.

## Features
- **Menu Bar Live Readout & Single-Instance Lock:** `● <RAM>  S:<Swap>  D:<SSD free>` with green / orange / red health status (switches to `MB/s` write rate during heavy disk bursts, or `fseventsd!` if `fseventsd` starts leaking), plus `flock`-guarded single GUI instance.
- **Header Gauge Card & 15-Min Sparklines:** Live bars for **RAM** (`App + Wired + Compressed`), **Swap**, **SSD**, **SSD I/O** (`MB/s` + persistent daily hardware bytes written via `IOBlockStorageDriver`), and **CPU / `fseventsd`**, paired with compact **RAM / Swap / Write** 15-minute trend sparklines.
- **Sleep & Display-Sleep Aware:** Automatically suspends timers during system sleep, resets delta baselines on wake, and backs off to a 60s cadence when displays sleep.
- **Dev Services & VMs Switchboard:**
  - Start / Stop **OrbStack** and **Podman** straight from the menu bar.
  - Lists local listening dev ports (`:5173`, `:55451`, `:15433`, `:8317`, etc.) with project folder hints and active TCP connection counts, plus 1-click **Open in Browser** or **Stop** (protects live T3 Code tunnels and `cli-proxy-api`).
- **Top Memory, CPU & Disk Writers:** Grouped memory totals with **Quit / Force Kill** submenus plus live Top CPU and Top Disk Writers (`MB/s` + session bytes written).
- **Orphan Detector & `fseventsd` Auto-Heal:**
  - Flags idle `vite`/`next`/`webpack` servers, temp `/private/tmp` Postgres instances, stuck inline test loops, and idle debug Chrome profiles (after verifying `0` TCP connections).
  - Optional scoped `/etc/sudoers.d/sysguard-fseventsd` rule allows 1-click or hands-free `Auto-Heal fseventsd (> 2 GB / 90% CPU)`.
- **Worktrees & Dev Janitor + `wtclean` CLI:**
  - 1-click **Clean Dev Junk Now (Safe)** or **Weekly Auto-Clean (Sun 04:00)** `LaunchAgent` (`SysGuard --janitor`, synced live via `launchctl`).
  - Parallel worktree audit & TOCTOU-guarded safe pruner in the menu or via `~/.local/bin/wtclean` (`wtclean`, `wtclean --prune`, `wtclean --safe-size`, `wtclean --no-size`, `wtclean --path <dir>`, `wtclean --json`).
- **Optional Configuration:** Create `~/Library/Application Support/SysGuard/config.ini` (`key=value`) to override thresholds (`fseventsd_warn_mb`, `swap_warn_gb`, `disk_warn_avail_gb`, etc.), `podman_default_machine`, or add repeatable `extra_worktree_root=~/...` directories.

## Architecture

- `src/config.{hpp,cpp}` — INI config loader & atomic daily SSD write baseline persistence
- `src/subprocess.{hpp,cpp}` — timeout-enforced, PGID-isolated `posix_spawn` command runner
- `src/system_actions.{hpp,cpp}` — verified PID termination, VM toggles, sudoers helpers
- `src/metrics.{hpp,cpp}` — zero-copy Mach/`libproc`/`IOKit` sampler, adaptive daemon cadence, 15m ring buffer, alert evaluation
- `src/janitor.{hpp,cpp}` — parallel worktree auditor, TOCTOU-safe pruner, and cache/tmp janitor
- `src/header_view.{hpp,mm}` — AppKit gauge bars & 15m trend sparklines
- `src/app.mm` — menu bar delegate, sleep/wake lifecycle, LaunchAgents
- `src/wtclean_main.cpp` — standalone CLI

## Build, Check & Install

```sh
make check    # unit + isolated tests, ASan/UBSan, TSan, and Clang Static Analyzer
make install
open -a /Applications/SysGuard.app
```
