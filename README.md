# SysGuard v2.0

Ultra-lightweight native macOS menu bar system monitor and Git worktree / dev-cache janitor written in **C++20 / Objective-C++ (AppKit)**.

Uses direct Darwin Mach, `libproc`, and `IOKit` syscalls with **zero third-party dependencies** to monitor memory, swap, SSD health/writes, `fseventsd` leaks, listening dev ports, orphaned dev processes, and stale Git worktrees.

Status bar readout:

```text
● 42G  S:2.1G  D:431G           # Normal / active state
● 42G  S:2.1G  D:431G  120MB/s  # Heavy SSD write burst badge
● 42G  S:2.1G  D:431G  ⚠2       # Active warning/critical alerts
● 42G  S:2.1G  D:431G  fseventsd!  # fseventsd leak critical alert
```

---

## Requirements

- **macOS 14.0+** (`Sonoma` or later; `LSMinimumSystemVersion = 14.0`)
- **Xcode Command Line Tools** (`clang++` with C++20 support and system SDKs):
  ```sh
  xcode-select --install
  ```
- **Architecture:** `Makefile` defaults to Apple Silicon (`-arch arm64`). On Intel Macs, change `-arch arm64` to `-arch x86_64` in [Makefile](Makefile).
- **Optional CLI integrations** (detected automatically when present): `git`, `orbctl` (OrbStack), `podman`, `pnpm`, `brew`, and `xcrun simctl`.

---

## Quick Start (Install & Launch)

```sh
git clone https://github.com/CoconutTheSlayer/sysguard.git
cd sysguard
make install
```

What `make install` does:
1. Builds and ad-hoc codesigns `SysGuard.app` and installs it to `/Applications/SysGuard.app` (falls back to `~/Applications/SysGuard.app` if `/Applications` is not writable).
2. Builds and installs the standalone `wtclean` CLI to `~/.local/bin/wtclean`.

Make sure `~/.local/bin` is on your `PATH` (for `zsh`):

```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Launch the menu bar app:

```sh
open -a SysGuard
# or:
open /Applications/SysGuard.app
```

> **Single-instance lock:** Launching `SysGuard.app` a second time prints `SysGuard is already running.` and exits cleanly (`flock` on `~/Library/Caches/com.local.sysguard.lock`).

---

## Menu Bar App Guide

Click the status bar indicator to open the live dashboard:

- **Header Gauge Card & 15-Minute Trend Sparklines**
  - Live progress bars for **RAM** (used / total + compressed), **Swap** (used / total + % free), **SSD** (free space & % used), **SSD I/O** (real-time write `MB/s` + persistent daily hardware bytes written via `IOBlockStorageDriver`), and **CPU / `fseventsd`**.
  - Compact 15-minute trend sparklines for **RAM 15m**, **Swap 15m**, and **Write 15m**.
  - Sleep & display-sleep aware: suspends sampling timers on system sleep, resets delta baselines on wake, and backs off to a 60s cadence while displays sleep.
- **Alerts & Notifications**
  - Evaluates `fseventsd` RSS/CPU leaks, high swap usage, low free memory %, low SSD free space / high disk usage, and sustained heavy disk write rates.
  - Sends native macOS notifications (toggleable under **Prevention & Settings → Notifications on Alerts**).
- **Orphaned / Idle Dev Processes**
  - Flags idle `vite`/`next`/`webpack` dev servers, orphaned `/private/tmp` Postgres instances, stuck inline test loops, and idle debug Chrome instances (verified `0` active connections).
  - Supports 1-click **Kill** / **Kill All Orphans**, or automatic background cleanup via **Prevention & Settings → Auto-Kill Idle Orphans (> 4h, 0 conns)**.
- **Dev Services & VMs**
  - Start / Stop **OrbStack** and **Podman** VMs directly from the menu.
  - Lists local listening dev ports (`:5173`, `:55451`, `:15433`, etc.) with project folder hints and active connection counts, with 1-click **Open `http://localhost:<port>`** or **Stop `<service>`** (protects live T3 Code tunnels and `cli-proxy-api`).
- **Top Memory, CPU & Disk Writers**
  - Top 8 grouped applications/services by memory footprint with **Quit** / **Force Kill** submenus.
  - **Top CPU & Disk Writers** submenu showing top CPU groups and active disk writers (`MB/s` + session bytes written) with PID-verified **Terminate**.
- **`fseventsd` Restart & Auto-Heal**
  - One-click **Restart fseventsd** (prompts for macOS administrator credentials, or runs silently if you enable the optional scoped sudoers rule).
  - **Prevention & Settings → Install Passwordless fseventsd Rule (Admin)…** writes `/etc/sudoers.d/sysguard-fseventsd` (`<user> ALL=(root) NOPASSWD: /usr/bin/killall fseventsd`), validated with `visudo -cf` before installation, and removable from the same menu item.
  - Once installed, **Auto-Heal fseventsd (> 2 GB / 90% CPU)** can restart runaway `fseventsd` automatically.
- **Worktrees & Disk Janitor + Launch at Login**
  - **Clean Dev Junk Now (Safe)**, **Audit Worktrees Now**, **Prune Safe Worktrees**, and **Weekly Auto-Clean (Sun 04:00)** (`com.local.sysguard.janitor` `LaunchAgent` managed live via `launchctl`).
  - **Prevention & Settings → Launch at Login** installs/removes `~/Library/LaunchAgents/com.local.sysguard.plist`.

---

## CLI Reference

### `wtclean` — Git Worktree Auditor & Safe Pruner

```sh
wtclean [options]
```

| Option | Description |
| --- | --- |
| `--prune` | Remove `SAFE` worktrees (clean, pushed, idle past `--hours`) |
| `--dry-run` | Audit and report without deleting anything |
| `--hours <N>` | Minimum idle age in hours before a clean/pushed worktree is `SAFE` (default: `24`) |
| `--path <dir>` | Scan only a specific worktree or parent directory containing worktrees (repeatable) |
| `--safe-size` | Compute disk usage only for `SAFE` worktrees (faster than full scan) |
| `--no-size` | Skip disk usage measurement for near-instant status listing |
| `--pnpm` | Run `pnpm store prune` after pruning worktrees |
| `--json` | Output structured JSON (summary, per-worktree records, and `prune` results if run) |
| `--help`, `-h` | Print CLI help |

**Common examples:**

```sh
# Audit all discovered worktrees and show disk sizes
wtclean

# Fast listing without calculating directory sizes
wtclean --no-size

# Preview what would be pruned after 72h idle
wtclean --prune --dry-run --hours 72

# Prune SAFE worktrees (idle >= 24h) and prune pnpm store
wtclean --prune --safe-size --pnpm

# Scan a custom directory and output JSON
wtclean --path ~/Projects/my-app-worktrees --no-size --json
```

**Default discovery locations** (when `--path` is not passed):
- `~/.t3/worktrees/*/*`
- `~/Projects/*-worktrees/*`
- `~/Projects/*/.claude/worktrees/*`
- `~/Projects/*/worktrees/*`
- Any `extra_worktree_root` entries in `~/Library/Application Support/SysGuard/config.ini`

**Safety classification:**
- `ACTIVE` — Worktree path appears in an active user process command line
- `DIRTY` — Uncommitted or untracked changes (`git status --porcelain`)
- `UNPUSHED` — `HEAD` is not reachable from any remote tracking branch (`git branch -r --contains HEAD`)
- `RECENT` — Latest commit/mtime is newer than `--hours`
- `ERROR` / `OTHER` — Unreadable repo or non-worktree directory
- `SAFE` — Clean, pushed to remote, idle past `--hours`, and unused by active processes. Before deletion, `prune_worktrees()` re-verifies process activity, `git status --porcelain`, and `git branch -r --contains HEAD` (TOCTOU guard) and cleans up parent Git worktree metadata (`git worktree prune`).

### Headless Janitor (`SysGuard --janitor`)

The app binary also acts as the scheduled headless janitor (invoked automatically every Sunday at 04:00 when **Weekly Auto-Clean** is enabled):

```sh
# Dry run: show what would be reclaimed without deleting anything
/Applications/SysGuard.app/Contents/MacOS/SysGuard --janitor --dry-run

# Run safe cleanup now
/Applications/SysGuard.app/Contents/MacOS/SysGuard --janitor
```

What `--janitor` safely targets:
1. Aged test/temp directories in `/private/tmp/rev-*-tests` and `/private/tmp/claude-501/*/*` older than 48h and unused by running processes.
2. Stale `com.google.Chrome.code_sign_clone` directories in `/private/var/folders` (only when Google Chrome is not running).
3. `SAFE` Git worktrees idle >= 72h (including `extra_worktree_root` paths from `config.ini`).
4. Rebuildable dev/package-manager caches (`ms-playwright`, `Homebrew`, `pnpm`, `npm`, `bun`, `uv`, `puppeteer`, `Cypress`, `chrome-devtools-mcp`, `Codex`, updater caches, plus `~/Library/Caches/Google` when Chrome is stopped).
5. `xcrun simctl delete unavailable`, `pnpm store prune`, and `brew cleanup -s`.

Runs append a timestamped summary to `~/Library/Logs/SysGuard-janitor.log`.

---

## Configuration (`config.ini`)

Create `~/Library/Application Support/SysGuard/config.ini` (`key=value`, `#` or `;` comments) to customize thresholds, your fallback Podman machine name, or additional worktree scan roots.

- **SysGuard.app** reads `config.ini` at launch (quit and reopen SysGuard after editing).
- **`wtclean`** and **`SysGuard --janitor`** read `config.ini` on every invocation.

Example `~/Library/Application Support/SysGuard/config.ini`:

```ini
# fseventsd leak thresholds
fseventsd_warn_mb=512
fseventsd_crit_mb=1536
fseventsd_auto_heal_mb=2048
fseventsd_warn_cpu_pct=60.0
fseventsd_crit_cpu_pct=90.0

# Swap & memory thresholds
swap_warn_gb=4
swap_crit_gb=8
mem_free_warn_pct=35
mem_free_crit_pct=20

# SSD capacity & write throughput thresholds
disk_warn_avail_gb=100
disk_crit_avail_gb=50
disk_warn_used_pct=92.0
disk_crit_used_pct=96.0
proc_disk_write_warn_mb_s=50.0
hw_disk_write_warn_mb_s=150.0
hw_disk_write_badge_mb_s=30.0

# Fallback Podman machine name (used only if auto-detection finds no .raw VM disk)
podman_default_machine=podman-machine-default

# Extra worktree directories or parent folders to audit (repeatable, supports ~/)
extra_worktree_root=~/work/my-worktrees
extra_worktree_root=~/src/feature-branch-wt
```

<details>
<summary>All supported configuration keys and defaults</summary>

| Key | Default | Notes |
| --- | --- | --- |
| `fseventsd_warn_mb` / `fseventsd_warn_bytes` | `512` MB | Orange `fseventsd` leak alert |
| `fseventsd_crit_mb` / `fseventsd_crit_bytes` | `1536` MB | Red `fseventsd!` alert |
| `fseventsd_auto_heal_mb` / `fseventsd_auto_heal_bytes` | `2048` MB | RSS threshold for auto-heal restart |
| `fseventsd_warn_cpu_pct` | `60.0` | Sustained CPU % warn threshold (`0`–`2000`) |
| `fseventsd_crit_cpu_pct` | `90.0` | Sustained CPU % critical / auto-heal threshold (`0`–`2000`) |
| `swap_warn_gb` / `swap_warn_bytes` | `4` GB | Orange Swap alert |
| `swap_crit_gb` / `swap_crit_bytes` | `8` GB | Red Swap alert |
| `mem_free_warn_pct` | `35` | Orange alert when macOS free memory % drops below (`1`–`99`) |
| `mem_free_crit_pct` | `20` | Red alert when macOS free memory % drops below (`1`–`99`) |
| `disk_warn_avail_gb` / `disk_warn_avail_bytes` | `100` GB | Orange Low Disk alert |
| `disk_crit_avail_gb` / `disk_crit_avail_bytes` | `50` GB | Red Low Disk alert |
| `disk_warn_used_pct` | `92.0` | Orange Low Disk alert by % used (`< 100`) |
| `disk_crit_used_pct` | `96.0` | Red Low Disk alert by % used (`< 100`) |
| `proc_disk_write_warn_mb_s` | `50.0` | Per-process heavy writer threshold & I/O bar warn |
| `hw_disk_write_warn_mb_s` | `150.0` | Hardware SSD write burst alert threshold |
| `hw_disk_write_badge_mb_s` | `30.0` | Minimum `MB/s` before menu bar shows live write rate |
| `podman_default_machine` | auto-detected | Fallback if `~/.local/share/containers/podman/machine/applehv/*.raw` has no match |
| `extra_worktree_root` | *(none)* | Repeatable path (accepts worktree root or parent folder of worktrees) |

</details>

---

## Files & Local State

| Path | Purpose |
| --- | --- |
| `/Applications/SysGuard.app` | Installed menu bar application bundle (or `~/Applications/SysGuard.app`) |
| `~/.local/bin/wtclean` | Installed worktree auditor & pruner CLI |
| `~/Library/Application Support/SysGuard/config.ini` | Optional user configuration file |
| `~/Library/Application Support/SysGuard/daily_io.state` | Atomic daily SSD hardware write baseline (`YYYYMMDD <bytes>`) |
| `~/Library/Caches/com.local.sysguard.lock` | `flock` single-instance lock file for GUI launches |
| `~/Library/Logs/SysGuard-janitor.log` | Timestamped log of headless `--janitor` cleanup runs |
| `~/Library/LaunchAgents/com.local.sysguard.plist` | Launch-at-Login agent (if enabled in menu) |
| `~/Library/LaunchAgents/com.local.sysguard.janitor.plist` | Weekly Sunday 04:00 `--janitor` agent (if enabled in menu) |
| `/etc/sudoers.d/sysguard-fseventsd` | Optional passwordless `/usr/bin/killall fseventsd` rule (if installed via menu) |

---

## Build, Test & Architecture

```sh
make          # Build build/SysGuard.app and build/wtclean
make test     # Run unit and isolated worktree tests
make sanitize # Run tests with ASan + UBSan
make tsan     # Run tests with ThreadSanitizer
make analyze  # Run Clang Static Analyzer across all C++ and ObjC++ units
make check    # Run test + sanitize + tsan + analyze
make install  # Install SysGuard.app and wtclean
make clean    # Remove build/
```

### Architecture

- [src/config.hpp](src/config.hpp), [src/config.cpp](src/config.cpp) — INI config loader & atomic daily SSD write baseline persistence
- [src/subprocess.hpp](src/subprocess.hpp), [src/subprocess.cpp](src/subprocess.cpp) — timeout-enforced, PGID-isolated `posix_spawn` command runner
- [src/system_actions.hpp](src/system_actions.hpp), [src/system_actions.cpp](src/system_actions.cpp) — PID-verified termination, VM controls, sudoers helpers
- [src/metrics.hpp](src/metrics.hpp), [src/metrics.cpp](src/metrics.cpp) — zero-copy Mach / `libproc` / `IOKit` sampler, adaptive daemon cadence, 15m ring buffer, alert evaluation
- [src/janitor.hpp](src/janitor.hpp), [src/janitor.cpp](src/janitor.cpp) — parallel worktree auditor, TOCTOU-safe pruner, cache/tmp janitor
- [src/header_view.hpp](src/header_view.hpp), [src/header_view.mm](src/header_view.mm) — AppKit gauge bars & 15m trend sparklines
- [src/app.mm](src/app.mm) — menu bar delegate, `flock` single-instance lock, sleep/wake lifecycle, `LaunchAgent` management, `--janitor` entrypoint
- [src/wtclean_main.cpp](src/wtclean_main.cpp) — standalone `wtclean` CLI
- [tests/test_metrics.cpp](tests/test_metrics.cpp) — unit, alert, orphan, config/state, history, and isolated TOCTOU worktree tests

---

## Uninstall

```sh
pkill -x SysGuard || true
launchctl bootout "gui/$(id -u)/com.local.sysguard.janitor" 2>/dev/null || true
launchctl bootout "gui/$(id -u)/com.local.sysguard" 2>/dev/null || true
rm -rf /Applications/SysGuard.app ~/Applications/SysGuard.app
rm -f ~/.local/bin/wtclean
rm -f ~/Library/LaunchAgents/com.local.sysguard.plist \
      ~/Library/LaunchAgents/com.local.sysguard.janitor.plist \
      ~/Library/Caches/com.local.sysguard.lock \
      ~/Library/Logs/SysGuard-janitor.log
rm -rf ~/Library/Application\ Support/SysGuard
# Optional: remove the passwordless fseventsd sudoers rule if you installed it
# sudo rm -f /etc/sudoers.d/sysguard-fseventsd
```
