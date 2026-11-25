#import <Cocoa/Cocoa.h>
#import <UserNotifications/UserNotifications.h>
#include <dispatch/dispatch.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "config.hpp"
#include "header_view.hpp"
#include "janitor.hpp"
#include "metrics.hpp"

namespace {

NSString* const kPrefNotifications = @"NotificationsEnabled";
NSString* const kPrefAutoKillOrphans = @"AutoKillOrphansEnabled";
NSString* const kPrefAutoHealFseventsd = @"AutoHealFseventsdEnabled";
NSString* const kLaunchAgentLabel = @"com.local.sysguard";
NSString* const kJanitorAgentLabel = @"com.local.sysguard.janitor";

NSString* LaunchAgentPath() {
  return [NSHomeDirectory()
      stringByAppendingPathComponent:
          @"Library/LaunchAgents/com.local.sysguard.plist"];
}

NSString* JanitorAgentPath() {
  return [NSHomeDirectory()
      stringByAppendingPathComponent:
          @"Library/LaunchAgents/com.local.sysguard.janitor.plist"];
}

NSString* CurrentExecutablePath() {
  NSString* execPath = NSBundle.mainBundle.executablePath;
  if (!execPath || execPath.length == 0) {
    execPath = @"/Applications/SysGuard.app/Contents/MacOS/SysGuard";
  }
  return execPath;
}

bool IsLaunchAtLoginEnabled() {
  return [[NSFileManager defaultManager] fileExistsAtPath:LaunchAgentPath()];
}

void SetLaunchAtLoginEnabled(bool enabled) {
  NSString* plistPath = LaunchAgentPath();
  NSFileManager* fm = [NSFileManager defaultManager];
  if (!enabled) {
    [fm removeItemAtPath:plistPath error:nil];
    return;
  }

  NSString* dir = [plistPath stringByDeletingLastPathComponent];
  [fm createDirectoryAtPath:dir
      withIntermediateDirectories:YES
                       attributes:nil
                            error:nil];

  NSDictionary* plist = @{
    @"Label" : kLaunchAgentLabel,
    @"ProgramArguments" : @[ CurrentExecutablePath() ],
    @"RunAtLoad" : @YES,
    @"KeepAlive" : @NO,
  };
  [plist writeToFile:plistPath atomically:YES];
}

bool IsWeeklyJanitorEnabled() {
  return [[NSFileManager defaultManager] fileExistsAtPath:JanitorAgentPath()];
}

void SetWeeklyJanitorEnabled(bool enabled) {
  NSString* plistPath = JanitorAgentPath();
  NSFileManager* fm = [NSFileManager defaultManager];
  if (!enabled) {
    [fm removeItemAtPath:plistPath error:nil];
    return;
  }

  NSString* dir = [plistPath stringByDeletingLastPathComponent];
  [fm createDirectoryAtPath:dir
      withIntermediateDirectories:YES
                       attributes:nil
                            error:nil];

  NSDictionary* plist = @{
    @"Label" : kJanitorAgentLabel,
    @"ProgramArguments" : @[ CurrentExecutablePath(), @"--janitor" ],
    @"RunAtLoad" : @NO,
    @"KeepAlive" : @NO,
    @"StartCalendarInterval" : @{
      @"Weekday" : @0,
      @"Hour" : @4,
      @"Minute" : @0,
    },
  };
  [plist writeToFile:plistPath atomically:YES];
}

NSString* FindProtonDriveFolder() {
  NSString* cloudDir = [NSHomeDirectory()
      stringByAppendingPathComponent:@"Library/CloudStorage"];
  NSArray<NSString*>* items =
      [[NSFileManager defaultManager] contentsOfDirectoryAtPath:cloudDir
                                                          error:nil];
  for (NSString* item in items) {
    if ([item hasPrefix:@"ProtonDrive"]) {
      return [cloudDir stringByAppendingPathComponent:item];
    }
  }
  return nil;
}

NSString* SafeNSString(const std::string& s) {
  if (s.empty()) return @"";
  NSString* str = [NSString stringWithUTF8String:s.c_str()];
  if (str) return str;
  str = [[NSString alloc] initWithBytes:s.data()
                                 length:static_cast<NSUInteger>(s.size())
                               encoding:NSISOLatin1StringEncoding];
  return str ? str : @"";
}

int AcquireGuiSingleInstanceLock() {
  const char* home = std::getenv("HOME");
  if (!home) return -1;
  std::filesystem::path lockDir =
      std::filesystem::path(home) / "Library" / "Caches";
  std::error_code ec;
  std::filesystem::create_directories(lockDir, ec);
  std::string lockPath = (lockDir / "com.local.sysguard.lock").string();
  int fd = open(lockPath.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0) return -1;
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    close(fd);
    return -2;
  }
  return fd;
}

}  // namespace

@interface SysGuardDelegate : NSObject <NSApplicationDelegate, NSMenuDelegate>
@end

@implementation SysGuardDelegate {
  NSStatusItem* _statusItem;
  NSMenu* _menu;
  dispatch_source_t _timer;
  dispatch_queue_t _workQueue;
  dispatch_queue_t _actionQueue;

  sysguard::SysGuardConfig _config;
  std::unique_ptr<sysguard::MonitorState> _monitor;
  sysguard::FastMetrics _fast;
  sysguard::DeepMetrics _deep;
  std::vector<sysguard::MetricPoint> _history;
  std::vector<sysguard::AppGroup> _menuGroups;
  std::vector<sysguard::OrphanProc> _menuOrphans;
  std::vector<sysguard::ListeningService> _menuServices;
  std::vector<sysguard::DiskWriter> _menuWriters;
  sysguard::WorktreeAuditSummary _lastAudit;
  __weak SysGuardHeaderView* _headerView;
  NSFont* _statusFont;

  uint64_t _tickCount;
  std::atomic<bool> _deepScanInFlight;
  std::atomic<bool> _menuOpenAtomic;
  bool _menuOpen;
  bool _timerSuspended;
  bool _displayAsleep;
  std::atomic<bool> _notifAvailable;
  std::atomic<bool> _passwordlessFsReady;
  bool _hasAudit;
  bool _auditingWorktrees;
  bool _janitorRunning;
  bool _vmActionInFlight;
  std::string _lastActionStatus;
  std::string _lastStatusBarKey;
  std::string _lastTooltipStr;
  double _lastAutoHealAt;
  std::unordered_map<int, double> _lastNotifAt;
}

- (void)applicationWillTerminate:(NSNotification*)notification {
  (void)notification;
  [[[NSWorkspace sharedWorkspace] notificationCenter] removeObserver:self];
  if (_timer) {
    if (_timerSuspended) {
      dispatch_resume(_timer);
      _timerSuspended = false;
    }
    dispatch_source_cancel(_timer);
    _timer = nil;
  }
}

- (void)applicationDidFinishLaunching:(NSNotification*)notification {
  (void)notification;
  [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
  _statusFont = [NSFont monospacedDigitSystemFontOfSize:12.0
                                                 weight:NSFontWeightMedium];
  _config = sysguard::load_config();
  _monitor = std::make_unique<sysguard::MonitorState>(
      _config, sysguard::default_daily_state_path());

  NSUserDefaults* defs = [NSUserDefaults standardUserDefaults];
  if ([defs objectForKey:kPrefNotifications] == nil) {
    [defs setBool:YES forKey:kPrefNotifications];
  }
  if ([defs objectForKey:kPrefAutoKillOrphans] == nil) {
    [defs setBool:NO forKey:kPrefAutoKillOrphans];
  }
  if ([defs objectForKey:kPrefAutoHealFseventsd] == nil) {
    [defs setBool:NO forKey:kPrefAutoHealFseventsd];
  }

  _workQueue = dispatch_queue_create(
      "com.local.sysguard.monitor",
      dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,
                                              QOS_CLASS_UTILITY, 0));
  _actionQueue = dispatch_queue_create(
      "com.local.sysguard.actions",
      dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,
                                              QOS_CLASS_UTILITY, 0));

  _statusItem = [[NSStatusBar systemStatusBar]
      statusItemWithLength:NSVariableStatusItemLength];
  _menu = [[NSMenu alloc] initWithTitle:@"SysGuard"];
  _menu.delegate = self;
  _statusItem.menu = _menu;

  [self setupNotifications];
  [self registerWorkspaceSleepNotifications];

  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      bool ready = sysguard::is_passwordless_fseventsd_configured();
      self->_passwordlessFsReady.store(ready, std::memory_order_relaxed);
    }
  });

  _fast = _monitor->sample_fast_metrics();
  _history = _monitor->copy_history();
  [self updateStatusBarButton];
  [self triggerDeepScanWithAutoReap:NO];

  _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _workQueue);
  dispatch_source_set_timer(
      _timer, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
      5 * NSEC_PER_SEC, 1500 * NSEC_PER_MSEC);
  __weak SysGuardDelegate* weakSelf = self;
  dispatch_source_set_event_handler(_timer, ^{
    @autoreleasepool {
      __strong SysGuardDelegate* strongSelf = weakSelf;
      if (!strongSelf) return;
      [strongSelf onTimerTick];
    }
  });
  dispatch_resume(_timer);
}

- (void)registerWorkspaceSleepNotifications {
  NSNotificationCenter* ws =
      [[NSWorkspace sharedWorkspace] notificationCenter];
  [ws addObserver:self
         selector:@selector(onSystemWillSleep:)
             name:NSWorkspaceWillSleepNotification
           object:nil];
  [ws addObserver:self
         selector:@selector(onSystemDidWake:)
             name:NSWorkspaceDidWakeNotification
           object:nil];
  [ws addObserver:self
         selector:@selector(onScreensDidSleep:)
             name:NSWorkspaceScreensDidSleepNotification
           object:nil];
  [ws addObserver:self
         selector:@selector(onScreensDidWake:)
             name:NSWorkspaceScreensDidWakeNotification
           object:nil];
}

- (void)onSystemWillSleep:(NSNotification*)notification {
  (void)notification;
  if (_timer && !_timerSuspended) {
    dispatch_suspend(_timer);
    _timerSuspended = true;
  }
}

- (void)onSystemDidWake:(NSNotification*)notification {
  (void)notification;
  _displayAsleep = false;
  if (_workQueue) {
    dispatch_async(_workQueue, ^{
      self->_monitor->reset_deltas();
    });
  }
  if (_timer) {
    dispatch_source_set_timer(
        _timer, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
        5 * NSEC_PER_SEC, 1500 * NSEC_PER_MSEC);
    if (_timerSuspended) {
      dispatch_resume(_timer);
      _timerSuspended = false;
    }
  }
  [self triggerDeepScanWithAutoReap:NO];
}

- (void)onScreensDidSleep:(NSNotification*)notification {
  (void)notification;
  _displayAsleep = true;
  if (_timer) {
    dispatch_source_set_timer(
        _timer, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC),
        60 * NSEC_PER_SEC, 5 * NSEC_PER_SEC);
  }
}

- (void)onScreensDidWake:(NSNotification*)notification {
  (void)notification;
  _displayAsleep = false;
  if (_workQueue) {
    dispatch_async(_workQueue, ^{
      self->_monitor->reset_deltas();
    });
  }
  if (_timer) {
    dispatch_source_set_timer(
        _timer, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
        5 * NSEC_PER_SEC, 1500 * NSEC_PER_MSEC);
  }
  [self triggerDeepScanWithAutoReap:NO];
}

- (void)setupNotifications {
  @try {
    UNUserNotificationCenter* center =
        [UNUserNotificationCenter currentNotificationCenter];
    if (!center) return;
    _notifAvailable.store(true, std::memory_order_relaxed);
    [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert |
                                             UNAuthorizationOptionSound)
                          completionHandler:^(BOOL granted, NSError* error) {
                            (void)granted;
                            (void)error;
                          }];
  } @catch (NSException* ex) {
    (void)ex;
    _notifAvailable.store(false, std::memory_order_relaxed);
  }
}

- (void)postNotificationTitle:(NSString*)title
                         body:(NSString*)body
                        sound:(bool)withSound
                        reqId:(NSString*)reqId {
  if (!_notifAvailable.load(std::memory_order_relaxed)) return;
  if (![[NSUserDefaults standardUserDefaults] boolForKey:kPrefNotifications]) {
    return;
  }
  @try {
    UNMutableNotificationContent* content =
        [[UNMutableNotificationContent alloc] init];
    content.title = title;
    content.body = body;
    if (withSound) {
      content.sound = [UNNotificationSound defaultSound];
    }
    UNNotificationRequest* req =
        [UNNotificationRequest requestWithIdentifier:reqId
                                             content:content
                                             trigger:nil];
    [[UNUserNotificationCenter currentNotificationCenter]
        addNotificationRequest:req
         withCompletionHandler:nil];
  } @catch (NSException* ex) {
    (void)ex;
  }
}

- (bool)autoReapOrphansIfEnabled:(sysguard::DeepMetrics&)deep
                            fast:(sysguard::FastMetrics&)fast {
  if (![[NSUserDefaults standardUserDefaults]
          boolForKey:kPrefAutoKillOrphans]) {
    return false;
  }
  bool reapedAny = false;
  for (const auto& orph : deep.orphans) {
    if (orph.auto_reap_safe && orph.uptime_sec >= 4 * 3600) {
      std::string err;
      if (sysguard::terminate_orphan(orph, err)) {
        reapedAny = true;
      }
    }
  }
  if (reapedAny) {
    fast = _monitor->sample_fast_metrics();
    deep = _monitor->sample_deep_metrics(fast, 7200, true);
  }
  return reapedAny;
}

- (void)updateHeaderInPlaceIfVisible {
  [self updateStatusBarButton];
  SysGuardHeaderView* header = _headerView;
  if (_menuOpen && header != nil) {
    header.fast = _fast;
    header.deep = _deep;
    header.config = _config;
    header.history = _history;
    [header setNeedsDisplay:YES];
  }
}

- (void)onTimerTick {
  _tickCount += 1;
  sysguard::FastMetrics nextFast = _monitor->sample_fast_metrics();
  std::vector<sysguard::MetricPoint> nextHistory = _monitor->copy_history();
  bool runDeep = (_tickCount % 3 == 0);

  if (!runDeep) {
    dispatch_async(dispatch_get_main_queue(), ^{
      self->_fast = nextFast;
      self->_history = std::move(nextHistory);
      [self updateHeaderInPlaceIfVisible];
    });
    return;
  }

  bool autoHealFs = [[NSUserDefaults standardUserDefaults]
      boolForKey:kPrefAutoHealFseventsd];
  const auto& cfg = _monitor->config();
  bool forcePs = _menuOpenAtomic.load(std::memory_order_relaxed);
  sysguard::DeepMetrics nextDeep =
      _monitor->sample_deep_metrics(nextFast, 7200, forcePs);
  if ([self autoReapOrphansIfEnabled:nextDeep fast:nextFast]) {
    nextHistory = _monitor->copy_history();
  }

  // Optional hands-free fseventsd auto-heal when passwordless rule is active
  if (autoHealFs && _passwordlessFsReady.load(std::memory_order_relaxed) &&
      (nextDeep.fseventsd_rss_bytes >= cfg.fseventsd_auto_heal_bytes ||
       (nextDeep.fseventsd_cpu_pct >= cfg.fseventsd_crit_cpu_pct &&
        nextDeep.fseventsd_high_strikes >= 4))) {
    double now = std::chrono::duration<double>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
    if (now - _lastAutoHealAt >= 1800.0) {
      _lastAutoHealAt = now;
      uint64_t rss = nextDeep.fseventsd_rss_bytes;
      double cpu = nextDeep.fseventsd_cpu_pct;
      dispatch_async(_actionQueue, ^{
        @autoreleasepool {
          std::string err;
          if (sysguard::restart_fseventsd_smart(false, err)) {
            [self
                postNotificationTitle:@"SysGuard: Auto-restarted fseventsd"
                                 body:[NSString
                                          stringWithFormat:
                                              @"Was using %s RSS (%.0f%% CPU)",
                                              sysguard::format_bytes(rss).c_str(),
                                              cpu]
                                sound:false
                                reqId:[NSString
                                          stringWithFormat:
                                              @"sysguard-autoheal-%.0f", now]];
            usleep(500000);
            [self triggerDeepScanWithAutoReap:NO];
          }
        }
      });
    }
  }

  [self maybePostAlertNotifications:nextDeep];

  dispatch_async(dispatch_get_main_queue(), ^{
    self->_fast = nextFast;
    self->_deep = nextDeep;
    self->_history = std::move(nextHistory);
    [self updateHeaderInPlaceIfVisible];
  });
}

- (void)triggerDeepScanWithAutoReap:(bool)allowReap {
  if (_deepScanInFlight.exchange(true, std::memory_order_acq_rel)) return;
  dispatch_async(_workQueue, ^{
    @autoreleasepool {
      sysguard::FastMetrics nextFast = self->_monitor->sample_fast_metrics();
      sysguard::DeepMetrics nextDeep =
          self->_monitor->sample_deep_metrics(nextFast, 7200, true);
      if (allowReap) {
        [self autoReapOrphansIfEnabled:nextDeep fast:nextFast];
      }
      std::vector<sysguard::MetricPoint> nextHistory =
          self->_monitor->copy_history();
      [self maybePostAlertNotifications:nextDeep];
      self->_deepScanInFlight.store(false, std::memory_order_release);
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_fast = nextFast;
        self->_deep = nextDeep;
        self->_history = std::move(nextHistory);
        [self updateHeaderInPlaceIfVisible];
      });
    }
  });
}

- (void)maybePostAlertNotifications:(const sysguard::DeepMetrics&)deep {
  if (!_notifAvailable.load(std::memory_order_relaxed)) return;
  if (![[NSUserDefaults standardUserDefaults] boolForKey:kPrefNotifications]) {
    return;
  }

  double now = std::chrono::duration<double>(
                   std::chrono::steady_clock::now().time_since_epoch())
                   .count();

  for (const auto& alert : deep.alerts) {
    if (alert.severity == sysguard::AlertSeverity::None) continue;
    if (alert.severity == sysguard::AlertSeverity::Warn &&
        alert.kind == sysguard::AlertKind::LowDisk) {
      continue;
    }
    int key = static_cast<int>(alert.kind);
    auto it = _lastNotifAt.find(key);
    if (it != _lastNotifAt.end() && (now - it->second) < 1800.0) {
      continue;
    }
    _lastNotifAt[key] = now;

    [self
        postNotificationTitle:[NSString stringWithFormat:@"SysGuard: %@",
                                                         SafeNSString(
                                                             alert.title)]
                         body:SafeNSString(alert.detail)
                        sound:(alert.severity == sysguard::AlertSeverity::Crit)
                        reqId:[NSString stringWithFormat:@"sysguard-alert-%d-%.0f",
                                                         key, now]];
  }
}

- (void)updateStatusBarButton {
  NSStatusBarButton* btn = _statusItem.button;
  if (!btn) return;

  NSFont* font =
      _statusFont
          ? _statusFont
          : [NSFont monospacedDigitSystemFontOfSize:12.0
                                             weight:NSFontWeightMedium];
  NSColor* dotColor = SysGuardColorForSeverity(_deep.max_severity);

  bool fsCrit = false;
  for (const auto& a : _deep.alerts) {
    if (a.kind == sysguard::AlertKind::FseventsdLeak &&
        a.severity == sysguard::AlertSeverity::Crit) {
      fsCrit = true;
      break;
    }
  }

  std::string ramS = sysguard::format_bytes_compact(_fast.ram_used_bytes);
  std::string swapS = sysguard::format_bytes_compact(_fast.swap_used_bytes);
  std::string diskS = sysguard::format_bytes_compact(_fast.disk_avail_bytes);

  std::string badgeKey;
  long roundedIo = 0;
  if (fsCrit) {
    badgeKey = "fs";
  } else if (_fast.hw_disk_write_mb_s >= _config.hw_disk_write_badge_mb_s) {
    roundedIo = std::llround(_fast.hw_disk_write_mb_s);
    char ioColorBucket =
        (_fast.hw_disk_write_mb_s >= _config.hw_disk_write_warn_mb_s) ? 'R'
                                                                      : 'O';
    badgeKey = ioColorBucket + std::to_string(roundedIo);
  } else if (!_deep.alerts.empty()) {
    badgeKey = "W" + std::to_string(_deep.alerts.size());
  }

  std::string statusKey = std::to_string(static_cast<int>(_deep.max_severity)) +
                          "|" + ramS + "|" + swapS + "|" + diskS + "|" +
                          badgeKey;

  if (statusKey != _lastStatusBarKey) {
    _lastStatusBarKey = statusKey;
    NSMutableAttributedString* title = [[NSMutableAttributedString alloc] init];
    [title appendAttributedString:[[NSAttributedString alloc]
                                      initWithString:@"● "
                                          attributes:@{
                                            NSFontAttributeName : font,
                                            NSForegroundColorAttributeName :
                                                dotColor,
                                          }]];

    NSString* statsStr = [NSString
        stringWithFormat:@"%s  S:%s  D:%s", ramS.c_str(), swapS.c_str(),
                         diskS.c_str()];
    [title appendAttributedString:[[NSAttributedString alloc]
                                      initWithString:statsStr
                                          attributes:@{
                                            NSFontAttributeName : font,
                                            NSForegroundColorAttributeName :
                                                [NSColor labelColor],
                                          }]];

    if (fsCrit) {
      [title appendAttributedString:
                 [[NSAttributedString alloc]
                     initWithString:@"  fseventsd!"
                         attributes:@{
                           NSFontAttributeName : font,
                           NSForegroundColorAttributeName :
                               [NSColor systemRedColor],
                         }]];
    } else if (_fast.hw_disk_write_mb_s >= _config.hw_disk_write_badge_mb_s) {
      NSString* ioStr = [NSString stringWithFormat:@"  %ldMB/s", roundedIo];
      NSColor* ioCol =
          (_fast.hw_disk_write_mb_s >= _config.hw_disk_write_warn_mb_s)
              ? [NSColor systemRedColor]
              : [NSColor systemOrangeColor];
      [title appendAttributedString:[[NSAttributedString alloc]
                                        initWithString:ioStr
                                            attributes:@{
                                              NSFontAttributeName : font,
                                              NSForegroundColorAttributeName :
                                                  ioCol,
                                            }]];
    } else if (!_deep.alerts.empty()) {
      NSString* warnStr =
          [NSString stringWithFormat:@"  ⚠%zu", _deep.alerts.size()];
      [title appendAttributedString:
                 [[NSAttributedString alloc]
                     initWithString:warnStr
                         attributes:@{
                           NSFontAttributeName : font,
                           NSForegroundColorAttributeName : dotColor,
                         }]];
    }

    btn.attributedTitle = title;
  }

  char tipBuf[512];
  std::snprintf(
      tipBuf, sizeof(tipBuf),
      "RAM: %s / %s (%s compressed, %d%% free)\nSwap: %s / %s\nSSD: %s free · Write: %.1f MB/s (%s today)\nfseventsd: %s (%.1f%% CPU)\nListening ports: %zu · Orphans: %zu · SysGuard: %s",
      sysguard::format_bytes(_fast.ram_used_bytes).c_str(),
      sysguard::format_bytes(_fast.ram_total_bytes).c_str(),
      sysguard::format_bytes(_fast.ram_compressed_bytes).c_str(),
      _fast.memory_free_pct,
      sysguard::format_bytes(_fast.swap_used_bytes).c_str(),
      sysguard::format_bytes(_fast.swap_total_bytes).c_str(),
      sysguard::format_bytes(_fast.disk_avail_bytes).c_str(),
      _fast.hw_disk_write_mb_s,
      sysguard::format_bytes_compact(_fast.hw_disk_written_today_bytes).c_str(),
      sysguard::format_bytes(_deep.fseventsd_rss_bytes).c_str(),
      _deep.fseventsd_cpu_pct, _deep.listening_services.size(),
      _deep.orphans.size(),
      sysguard::format_bytes(_fast.self_footprint_bytes).c_str());

  if (_lastTooltipStr != tipBuf) {
    _lastTooltipStr = tipBuf;
    btn.toolTip = SafeNSString(_lastTooltipStr);
  }
}

- (void)menuWillOpen:(NSMenu*)menu {
  (void)menu;
  _menuOpen = true;
  _menuOpenAtomic.store(true, std::memory_order_relaxed);
  [self rebuildMenu];

  double now = std::chrono::duration<double>(
                   std::chrono::steady_clock::now().time_since_epoch())
                   .count();
  if ((now - _deep.deep_scan_timestamp_sec) > 3.0) {
    [self triggerDeepScanWithAutoReap:NO];
  }
}

- (void)menuDidClose:(NSMenu*)menu {
  (void)menu;
  _menuOpen = false;
  _menuOpenAtomic.store(false, std::memory_order_relaxed);
  _headerView = nil;
  [_menu removeAllItems];
}

- (NSMenuItem*)sectionHeader:(NSString*)title {
  NSMenuItem* item = [[NSMenuItem alloc] initWithTitle:title
                                                action:nil
                                         keyEquivalent:@""];
  item.enabled = NO;
  item.attributedTitle = [[NSAttributedString alloc]
      initWithString:title
          attributes:@{
            NSFontAttributeName :
                [NSFont systemFontOfSize:11.0 weight:NSFontWeightSemibold],
            NSForegroundColorAttributeName : [NSColor secondaryLabelColor],
          }];
  return item;
}

- (void)rebuildMenu {
  [_menu removeAllItems];

  // 1. Header gauges (5 bars + 3 sparklines)
  SysGuardHeaderView* header =
      [[SysGuardHeaderView alloc] initWithFrame:NSMakeRect(0, 0, 352, 196)];
  header.fast = _fast;
  header.deep = _deep;
  header.config = _config;
  header.history = _history;
  _headerView = header;
  NSMenuItem* headerItem = [[NSMenuItem alloc] init];
  headerItem.view = header;
  [_menu addItem:headerItem];
  [_menu addItem:[NSMenuItem separatorItem]];

  // 2. Alerts
  if (!_deep.alerts.empty()) {
    [_menu addItem:[self sectionHeader:@"Alerts"]];
    for (const auto& a : _deep.alerts) {
      NSString* icon =
          (a.severity == sysguard::AlertSeverity::Crit) ? @"🔴" : @"🟠";
      NSString* line = [NSString
          stringWithFormat:@"%@ %@ — %@", icon, SafeNSString(a.title),
                           SafeNSString(a.detail)];
      NSMenuItem* item = [[NSMenuItem alloc] initWithTitle:line
                                                    action:nil
                                             keyEquivalent:@""];
      item.enabled = NO;
      [_menu addItem:item];

      if (a.kind == sysguard::AlertKind::FseventsdLeak) {
        NSString* fixTitle =
            _passwordlessFsReady.load(std::memory_order_relaxed)
                ? @"   ↳ Restart fseventsd Now"
                : @"   ↳ Restart fseventsd (Admin)…";
        NSMenuItem* fix =
            [[NSMenuItem alloc] initWithTitle:fixTitle
                                       action:@selector(onRestartFseventsd:)
                                keyEquivalent:@""];
        fix.target = self;
        [_menu addItem:fix];
      }
    }
    [_menu addItem:[NSMenuItem separatorItem]];
  }

  // 3. Orphaned / Idle processes
  _menuOrphans = _deep.orphans;
  if (!_menuOrphans.empty()) {
    [_menu addItem:[self sectionHeader:@"Orphaned / Idle Dev Processes"]];
    uint64_t totalOrphMem = 0;
    for (size_t i = 0; i < _menuOrphans.size(); ++i) {
      const auto& o = _menuOrphans[i];
      totalOrphMem += o.mem_bytes;
      NSString* title = [NSString
          stringWithFormat:@"Kill %@ — %@", SafeNSString(o.label),
                           SafeNSString(o.detail)];
      NSMenuItem* item = [[NSMenuItem alloc] initWithTitle:title
                                                    action:@selector(onKillOrphan:)
                                             keyEquivalent:@""];
      item.target = self;
      item.tag = static_cast<NSInteger>(i);
      [_menu addItem:item];
    }
    if (_menuOrphans.size() > 1) {
      NSString* allTitle = [NSString
          stringWithFormat:@"Kill All Orphans (%s)",
                           sysguard::format_bytes_compact(totalOrphMem).c_str()];
      NSMenuItem* allItem = [[NSMenuItem alloc]
          initWithTitle:allTitle
                 action:@selector(onKillAllOrphans:)
          keyEquivalent:@""];
      allItem.target = self;
      [_menu addItem:allItem];
    }
    [_menu addItem:[NSMenuItem separatorItem]];
  }

  // 4. Dev Services & VMs submenu
  _menuServices = _deep.listening_services;
  const auto& vm = _deep.vm_status;
  NSString* vmTag = @"Idle";
  if (vm.orbstack_running && vm.podman_running) {
    vmTag = @"OrbStack + Podman On";
  } else if (vm.orbstack_running) {
    vmTag = [NSString
        stringWithFormat:@"OrbStack %s",
                         sysguard::format_bytes_compact(vm.orbstack_mem_bytes)
                             .c_str()];
  } else if (vm.podman_running) {
    vmTag = [NSString
        stringWithFormat:@"Podman %s",
                         sysguard::format_bytes_compact(vm.podman_mem_bytes)
                             .c_str()];
  }
  NSString* devSummary = [NSString
      stringWithFormat:@"Dev Services & VMs (%zu ports · %@)",
                       _menuServices.size(), vmTag];
  NSMenuItem* devItem = [[NSMenuItem alloc] initWithTitle:devSummary
                                                   action:nil
                                            keyEquivalent:@""];
  NSMenu* devMenu = [[NSMenu alloc] init];

  [devMenu addItem:[self sectionHeader:@"Virtual Machines"]];
  if (vm.orbstack_installed) {
    NSString* orbTitle =
        vm.orbstack_running
            ? [NSString
                  stringWithFormat:@"Stop OrbStack (Running · %s)",
                                   sysguard::format_bytes_compact(
                                       vm.orbstack_mem_bytes)
                                       .c_str()]
            : @"Start OrbStack (Stopped)";
    NSMenuItem* orbItem = [[NSMenuItem alloc]
        initWithTitle:orbTitle
               action:_vmActionInFlight ? nil : @selector(onToggleOrbStack:)
        keyEquivalent:@""];
    orbItem.target = self;
    orbItem.enabled = !_vmActionInFlight;
    [devMenu addItem:orbItem];
  }
  if (vm.podman_installed) {
    NSString* podName = SafeNSString(vm.podman_machine_name);
    NSString* podTitle =
        vm.podman_running
            ? [NSString
                  stringWithFormat:@"Stop Podman (%@ · %s)", podName,
                                   sysguard::format_bytes_compact(
                                       vm.podman_mem_bytes)
                                       .c_str()]
            : [NSString stringWithFormat:@"Start Podman (%@ · Stopped)", podName];
    NSMenuItem* podItem = [[NSMenuItem alloc]
        initWithTitle:podTitle
               action:_vmActionInFlight ? nil : @selector(onTogglePodman:)
        keyEquivalent:@""];
    podItem.target = self;
    podItem.enabled = !_vmActionInFlight;
    [devMenu addItem:podItem];
  }
  if (!vm.orbstack_installed && !vm.podman_installed) {
    NSMenuItem* noneVm = [[NSMenuItem alloc] initWithTitle:@"No VMs installed"
                                                    action:nil
                                             keyEquivalent:@""];
    noneVm.enabled = NO;
    [devMenu addItem:noneVm];
  }

  [devMenu addItem:[NSMenuItem separatorItem]];
  [devMenu addItem:[self sectionHeader:@"Listening Local Dev Ports"]];
  if (_menuServices.empty()) {
    NSMenuItem* noPorts =
        [[NSMenuItem alloc] initWithTitle:@"No local dev ports listening"
                                   action:nil
                            keyEquivalent:@""];
    noPorts.enabled = NO;
    [devMenu addItem:noPorts];
  } else {
    NSFont* svcFont =
        [NSFont monospacedDigitSystemFontOfSize:12.0
                                         weight:NSFontWeightRegular];
    for (size_t i = 0; i < _menuServices.size() && i < 20; ++i) {
      const auto& s = _menuServices[i];
      NSString* hint =
          s.project_hint.empty()
              ? @""
              : [NSString stringWithFormat:@"  %@", SafeNSString(s.project_hint)];
      NSString* prot = s.is_protected ? @" [T3]" : @"";
      NSString* svcName = SafeNSString(s.name);
      NSString* label = [NSString
          stringWithFormat:@":%-5u %@%@  (%d conns)%@", s.port, svcName, hint,
                           s.established_conns, prot];
      NSMenuItem* sItem = [[NSMenuItem alloc] initWithTitle:label
                                                     action:nil
                                              keyEquivalent:@""];
      sItem.attributedTitle = [[NSAttributedString alloc]
          initWithString:label
              attributes:@{NSFontAttributeName : svcFont}];

      if (s.is_http_like || !s.is_protected) {
        NSMenu* sub = [[NSMenu alloc] init];
        if (s.is_http_like) {
          NSMenuItem* openUrl = [[NSMenuItem alloc]
              initWithTitle:[NSString stringWithFormat:@"Open http://localhost:%u",
                                                       s.port]
                     action:@selector(onOpenServiceUrl:)
              keyEquivalent:@""];
          openUrl.target = self;
          openUrl.tag = static_cast<NSInteger>(i);
          [sub addItem:openUrl];
        }
        if (!s.is_protected) {
          NSMenuItem* stopSvc = [[NSMenuItem alloc]
              initWithTitle:[NSString stringWithFormat:@"Stop %@ (PID %d)",
                                                       svcName, s.pid]
                     action:@selector(onStopService:)
              keyEquivalent:@""];
          stopSvc.target = self;
          stopSvc.tag = static_cast<NSInteger>(i);
          [sub addItem:stopSvc];
        }
        sItem.submenu = sub;
      } else {
        sItem.enabled = NO;
      }
      [devMenu addItem:sItem];
    }
  }
  devItem.submenu = devMenu;
  [_menu addItem:devItem];

  // 5. Top Memory (Grouped) — top 8 compact
  [_menu addItem:[NSMenuItem separatorItem]];
  _menuGroups = _deep.top_mem_groups;
  [_menu addItem:[self sectionHeader:@"Top Memory (Grouped)"]];
  NSFont* rowFont =
      [NSFont monospacedDigitSystemFontOfSize:12.5
                                       weight:NSFontWeightRegular];
  size_t showMemCount = _menuGroups.size() < 8 ? _menuGroups.size() : 8;
  for (size_t i = 0; i < showMemCount; ++i) {
    const auto& g = _menuGroups[i];
    NSString* gName = SafeNSString(g.name);
    NSString* label = [NSString
        stringWithFormat:@"%@ (%d)  —  %s  ·  %.0f%% CPU", gName,
                         g.proc_count, sysguard::format_bytes(g.mem_bytes).c_str(),
                         g.cpu_pct];
    NSMenuItem* item = [[NSMenuItem alloc] initWithTitle:label
                                                  action:nil
                                           keyEquivalent:@""];
    item.attributedTitle = [[NSAttributedString alloc]
        initWithString:label
            attributes:@{NSFontAttributeName : rowFont}];

    if (!g.is_system) {
      NSMenu* sub = [[NSMenu alloc] init];
      NSMenuItem* quitItem = [[NSMenuItem alloc]
          initWithTitle:[NSString stringWithFormat:@"Quit %@", gName]
                 action:@selector(onQuitGroup:)
          keyEquivalent:@""];
      quitItem.target = self;
      quitItem.tag = static_cast<NSInteger>(i);
      [sub addItem:quitItem];

      NSMenuItem* killItem = [[NSMenuItem alloc]
          initWithTitle:[NSString stringWithFormat:@"Force Kill %@", gName]
                 action:@selector(onForceKillGroup:)
          keyEquivalent:@""];
      killItem.target = self;
      killItem.tag = static_cast<NSInteger>(i);
      [sub addItem:killItem];

      item.submenu = sub;
    }
    [_menu addItem:item];
  }

  // 6. Top CPU & Disk Writers submenu
  _menuWriters = _deep.top_disk_writers;
  NSMenuItem* perfItem =
      [[NSMenuItem alloc] initWithTitle:@"Top CPU & Disk Writers"
                                 action:nil
                          keyEquivalent:@""];
  NSMenu* perfMenu = [[NSMenu alloc] init];

  [perfMenu addItem:[self sectionHeader:@"Top CPU"]];
  if (_deep.top_cpu_groups.empty()) {
    NSMenuItem* noneCpu = [[NSMenuItem alloc] initWithTitle:@"Idle"
                                                     action:nil
                                              keyEquivalent:@""];
    noneCpu.enabled = NO;
    [perfMenu addItem:noneCpu];
  } else {
    size_t showCpu =
        _deep.top_cpu_groups.size() < 5 ? _deep.top_cpu_groups.size() : 5;
    for (size_t i = 0; i < showCpu; ++i) {
      const auto& g = _deep.top_cpu_groups[i];
      NSString* label = [NSString
          stringWithFormat:@"%@  —  %.1f%% CPU  (%s)", SafeNSString(g.name),
                           g.cpu_pct,
                           sysguard::format_bytes_compact(g.mem_bytes).c_str()];
      NSMenuItem* cItem = [[NSMenuItem alloc] initWithTitle:label
                                                     action:nil
                                              keyEquivalent:@""];
      cItem.enabled = NO;
      [perfMenu addItem:cItem];
    }
  }

  [perfMenu addItem:[NSMenuItem separatorItem]];
  [perfMenu addItem:[self sectionHeader:@"Top Disk Writers"]];
  if (_menuWriters.empty()) {
    NSMenuItem* noneWr =
        [[NSMenuItem alloc] initWithTitle:@"No heavy user disk writers"
                                   action:nil
                            keyEquivalent:@""];
    noneWr.enabled = NO;
    [perfMenu addItem:noneWr];
  } else {
    for (size_t i = 0; i < _menuWriters.size(); ++i) {
      const auto& w = _menuWriters[i];
      NSString* label = [NSString
          stringWithFormat:@"%@ (PID %d)  —  %.1f MB/s  ·  %s written",
                           SafeNSString(w.name), w.pid, w.write_mb_s,
                           sysguard::format_bytes_compact(
                               w.session_written_bytes)
                               .c_str()];
      NSMenuItem* wItem = [[NSMenuItem alloc] initWithTitle:label
                                                     action:nil
                                              keyEquivalent:@""];
      if (!w.is_system) {
        NSMenu* sub = [[NSMenu alloc] init];
        NSMenuItem* kItem = [[NSMenuItem alloc]
            initWithTitle:[NSString
                              stringWithFormat:@"Terminate PID %d", w.pid]
                   action:@selector(onKillWriter:)
            keyEquivalent:@""];
        kItem.target = self;
        kItem.tag = static_cast<NSInteger>(i);
        [sub addItem:kItem];
        wItem.submenu = sub;
      } else {
        wItem.enabled = NO;
      }
      [perfMenu addItem:wItem];
    }
  }
  perfItem.submenu = perfMenu;
  [_menu addItem:perfItem];

  // 7. Worktrees & Disk Janitor submenu
  NSMenuItem* janItem =
      [[NSMenuItem alloc] initWithTitle:@"Worktrees & Disk Janitor"
                                 action:nil
                          keyEquivalent:@""];
  NSMenu* janMenu = [[NSMenu alloc] init];

  NSString* cleanTitle =
      _janitorRunning ? @"Cleaning Dev Junk…" : @"Clean Dev Junk Now (Safe)";
  NSMenuItem* cleanBtn = [[NSMenuItem alloc]
      initWithTitle:cleanTitle
             action:_janitorRunning ? nil : @selector(onRunJanitor:)
      keyEquivalent:@""];
  cleanBtn.target = self;
  cleanBtn.enabled = !_janitorRunning;
  [janMenu addItem:cleanBtn];

  NSString* auditTitle =
      _auditingWorktrees ? @"Auditing Worktrees…" : @"Audit Worktrees Now";
  NSMenuItem* auditBtn = [[NSMenuItem alloc]
      initWithTitle:auditTitle
             action:_auditingWorktrees ? nil : @selector(onAuditWorktrees:)
      keyEquivalent:@""];
  auditBtn.target = self;
  auditBtn.enabled = !_auditingWorktrees;
  [janMenu addItem:auditBtn];

  if (_hasAudit) {
    NSString* sumLine = [NSString
        stringWithFormat:@"   Safe: %d (%s) · Dirty: %d · Unpushed: %d · Active: %d",
                         _lastAudit.safe_count,
                         sysguard::format_bytes_compact(_lastAudit.safe_bytes)
                             .c_str(),
                         _lastAudit.dirty_count, _lastAudit.unpushed_count,
                         _lastAudit.active_count];
    NSMenuItem* sumItem = [[NSMenuItem alloc] initWithTitle:sumLine
                                                     action:nil
                                              keyEquivalent:@""];
    sumItem.enabled = NO;
    [janMenu addItem:sumItem];

    if (_lastAudit.safe_count > 0) {
      NSString* pruneTitle = [NSString
          stringWithFormat:@"Prune %d Safe Worktrees (%s)",
                           _lastAudit.safe_count,
                           sysguard::format_bytes_compact(_lastAudit.safe_bytes)
                               .c_str()];
      NSMenuItem* pruneBtn = [[NSMenuItem alloc]
          initWithTitle:pruneTitle
                 action:_auditingWorktrees ? nil : @selector(onPruneWorktrees:)
          keyEquivalent:@""];
      pruneBtn.target = self;
      pruneBtn.enabled = !_auditingWorktrees;
      [janMenu addItem:pruneBtn];
    }
  }

  [janMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* weeklyItem = [[NSMenuItem alloc]
      initWithTitle:@"Weekly Auto-Clean (Sun 04:00)"
             action:@selector(onToggleWeeklyJanitor:)
      keyEquivalent:@""];
  weeklyItem.target = self;
  weeklyItem.state = IsWeeklyJanitorEnabled() ? NSControlStateValueOn
                                              : NSControlStateValueOff;
  [janMenu addItem:weeklyItem];

  NSString* protonPath = FindProtonDriveFolder();
  if (protonPath != nil) {
    NSMenuItem* protonItem =
        [[NSMenuItem alloc] initWithTitle:@"Open Proton Drive in Finder…"
                                   action:@selector(onOpenProtonDrive:)
                            keyEquivalent:@""];
    protonItem.target = self;
    [janMenu addItem:protonItem];
  }

  if (!_lastActionStatus.empty()) {
    [janMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem* stItem = [[NSMenuItem alloc]
        initWithTitle:[NSString stringWithFormat:@"Last: %@",
                                                 SafeNSString(_lastActionStatus)]
               action:nil
        keyEquivalent:@""];
    stItem.enabled = NO;
    [janMenu addItem:stItem];
  }

  janItem.submenu = janMenu;
  [_menu addItem:janItem];

  // 8. Prevention & Settings submenu
  NSMenuItem* prefsItem =
      [[NSMenuItem alloc] initWithTitle:@"Prevention & Settings"
                                 action:nil
                          keyEquivalent:@""];
  NSMenu* prefsMenu = [[NSMenu alloc] init];

  NSMenuItem* notifItem =
      [[NSMenuItem alloc] initWithTitle:@"Notifications on Alerts"
                                 action:@selector(onToggleNotifications:)
                          keyEquivalent:@""];
  notifItem.target = self;
  notifItem.state =
      [[NSUserDefaults standardUserDefaults] boolForKey:kPrefNotifications]
          ? NSControlStateValueOn
          : NSControlStateValueOff;
  [prefsMenu addItem:notifItem];

  NSMenuItem* autoReapItem = [[NSMenuItem alloc]
      initWithTitle:@"Auto-Kill Idle Orphans (> 4h, 0 conns)"
             action:@selector(onToggleAutoReap:)
      keyEquivalent:@""];
  autoReapItem.target = self;
  autoReapItem.state =
      [[NSUserDefaults standardUserDefaults] boolForKey:kPrefAutoKillOrphans]
          ? NSControlStateValueOn
          : NSControlStateValueOff;
  [prefsMenu addItem:autoReapItem];

  NSMenuItem* autoHealItem = [[NSMenuItem alloc]
      initWithTitle:@"Auto-Heal fseventsd (> 2 GB / 90% CPU)"
             action:@selector(onToggleAutoHealFseventsd:)
      keyEquivalent:@""];
  autoHealItem.target = self;
  autoHealItem.state =
      [[NSUserDefaults standardUserDefaults] boolForKey:kPrefAutoHealFseventsd]
          ? NSControlStateValueOn
          : NSControlStateValueOff;
  [prefsMenu addItem:autoHealItem];

  NSString* ruleTitle =
      _passwordlessFsReady.load(std::memory_order_relaxed)
          ? @"Remove Passwordless fseventsd Rule…"
          : @"Install Passwordless fseventsd Rule (Admin)…";
  NSMenuItem* ruleItem = [[NSMenuItem alloc]
      initWithTitle:ruleTitle
             action:@selector(onTogglePasswordlessRule:)
      keyEquivalent:@""];
  ruleItem.target = self;
  [prefsMenu addItem:ruleItem];

  [prefsMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* openCfgItem =
      [[NSMenuItem alloc] initWithTitle:@"Open config.ini…"
                                 action:@selector(onOpenConfig:)
                          keyEquivalent:@""];
  openCfgItem.target = self;
  [prefsMenu addItem:openCfgItem];

  NSMenuItem* reloadCfgItem =
      [[NSMenuItem alloc] initWithTitle:@"Reload Config"
                                 action:@selector(onReloadConfig:)
                          keyEquivalent:@""];
  reloadCfgItem.target = self;
  [prefsMenu addItem:reloadCfgItem];

  [prefsMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* loginItem =
      [[NSMenuItem alloc] initWithTitle:@"Launch at Login"
                                 action:@selector(onToggleLaunchAtLogin:)
                          keyEquivalent:@""];
  loginItem.target = self;
  loginItem.state = IsLaunchAtLoginEnabled() ? NSControlStateValueOn
                                             : NSControlStateValueOff;
  [prefsMenu addItem:loginItem];

  prefsItem.submenu = prefsMenu;
  [_menu addItem:prefsItem];

  [_menu addItem:[NSMenuItem separatorItem]];

  NSString* restartTitle =
      _passwordlessFsReady.load(std::memory_order_relaxed)
          ? @"Restart fseventsd"
          : @"Restart fseventsd (Admin)…";
  NSMenuItem* restartFs =
      [[NSMenuItem alloc] initWithTitle:restartTitle
                                 action:@selector(onRestartFseventsd:)
                          keyEquivalent:@""];
  restartFs.target = self;
  [_menu addItem:restartFs];

  NSMenuItem* refresh = [[NSMenuItem alloc] initWithTitle:@"Refresh Now"
                                                   action:@selector(onRefreshNow:)
                                            keyEquivalent:@"r"];
  refresh.target = self;
  [_menu addItem:refresh];

  NSString* selfStr = [NSString
      stringWithFormat:@"SysGuard v2.0 · Self: %s · %.1f%% CPU · %d procs",
                       sysguard::format_bytes(_fast.self_footprint_bytes).c_str(),
                       _fast.self_cpu_pct, _deep.total_procs];
  NSMenuItem* selfItem = [[NSMenuItem alloc] initWithTitle:selfStr
                                                    action:nil
                                             keyEquivalent:@""];
  selfItem.enabled = NO;
  [_menu addItem:selfItem];

  NSMenuItem* quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit SysGuard"
                                                    action:@selector(terminate:)
                                             keyEquivalent:@"q"];
  quitItem.target = NSApp;
  [_menu addItem:quitItem];
}

// --- Actions ---

- (void)onKillOrphan:(NSMenuItem*)sender {
  NSInteger idx = sender.tag;
  if (idx < 0 || static_cast<size_t>(idx) >= _menuOrphans.size()) return;
  sysguard::OrphanProc orph = _menuOrphans[static_cast<size_t>(idx)];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      sysguard::terminate_orphan(orph, err);
      [self triggerDeepScanWithAutoReap:NO];
    }
  });
}

- (void)onKillAllOrphans:(id)sender {
  (void)sender;
  std::vector<sysguard::OrphanProc> list = _menuOrphans;
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      for (const auto& o : list) {
        std::string err;
        sysguard::terminate_orphan(o, err);
      }
      [self triggerDeepScanWithAutoReap:NO];
    }
  });
}

- (void)onQuitGroup:(NSMenuItem*)sender {
  NSInteger idx = sender.tag;
  if (idx < 0 || static_cast<size_t>(idx) >= _menuGroups.size()) return;
  sysguard::AppGroup g = _menuGroups[static_cast<size_t>(idx)];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      sysguard::terminate_group(g, false, err);
      usleep(300000);
      [self triggerDeepScanWithAutoReap:NO];
    }
  });
}

- (void)onForceKillGroup:(NSMenuItem*)sender {
  NSInteger idx = sender.tag;
  if (idx < 0 || static_cast<size_t>(idx) >= _menuGroups.size()) return;
  sysguard::AppGroup g = _menuGroups[static_cast<size_t>(idx)];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      sysguard::terminate_group(g, true, err);
      usleep(200000);
      [self triggerDeepScanWithAutoReap:NO];
    }
  });
}

- (void)onOpenServiceUrl:(NSMenuItem*)sender {
  NSInteger idx = sender.tag;
  if (idx < 0 || static_cast<size_t>(idx) >= _menuServices.size()) return;
  uint16_t port = _menuServices[static_cast<size_t>(idx)].port;
  NSURL* url = [NSURL
      URLWithString:[NSString stringWithFormat:@"http://localhost:%u", port]];
  if (url) {
    [[NSWorkspace sharedWorkspace] openURL:url];
  }
}

- (void)onStopService:(NSMenuItem*)sender {
  NSInteger idx = sender.tag;
  if (idx < 0 || static_cast<size_t>(idx) >= _menuServices.size()) return;
  sysguard::ListeningService svc = _menuServices[static_cast<size_t>(idx)];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      sysguard::terminate_service(svc, err);
      usleep(300000);
      [self triggerDeepScanWithAutoReap:NO];
    }
  });
}

- (void)onKillWriter:(NSMenuItem*)sender {
  NSInteger idx = sender.tag;
  if (idx < 0 || static_cast<size_t>(idx) >= _menuWriters.size()) return;
  sysguard::DiskWriter w = _menuWriters[static_cast<size_t>(idx)];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      sysguard::terminate_pid_verified(w.pid, w.start_sec, false, err);
      usleep(300000);
      [self triggerDeepScanWithAutoReap:NO];
    }
  });
}

- (void)onToggleOrbStack:(id)sender {
  (void)sender;
  if (_vmActionInFlight) return;
  bool shouldStart = !_deep.vm_status.orbstack_running;
  _vmActionInFlight = true;
  if (_menuOpen) [self rebuildMenu];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      bool ok = sysguard::control_orbstack(shouldStart, err);
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_vmActionInFlight = false;
        self->_lastActionStatus =
            ok ? (shouldStart ? "OrbStack started" : "OrbStack stopped")
               : ("OrbStack error: " + err);
        if (self->_menuOpen) [self rebuildMenu];
        [self triggerDeepScanWithAutoReap:NO];
      });
    }
  });
}

- (void)onTogglePodman:(id)sender {
  (void)sender;
  if (_vmActionInFlight) return;
  bool shouldStart = !_deep.vm_status.podman_running;
  std::string mname = _deep.vm_status.podman_machine_name;
  _vmActionInFlight = true;
  if (_menuOpen) [self rebuildMenu];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      bool ok = sysguard::control_podman_machine(mname, shouldStart, err);
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_vmActionInFlight = false;
        self->_lastActionStatus =
            ok ? (shouldStart ? "Podman started" : "Podman stopped")
               : ("Podman error: " + err);
        if (self->_menuOpen) [self rebuildMenu];
        [self triggerDeepScanWithAutoReap:NO];
      });
    }
  });
}

- (void)onRunJanitor:(id)sender {
  (void)sender;
  if (_janitorRunning) return;
  _janitorRunning = true;
  std::vector<std::string> extraRoots = _config.extra_worktree_roots;
  if (_menuOpen) [self rebuildMenu];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      sysguard::JanitorOptions opts;
      opts.dry_run = false;
      opts.tmp_min_age_hours = 48;
      opts.worktree_min_age_hours = 72;
      opts.include_caches = true;
      opts.include_worktrees = true;
      opts.include_pnpm_brew = true;
      opts.extra_worktree_roots = std::move(extraRoots);
      sysguard::JanitorReport rep = sysguard::run_dev_janitor(opts);
      [self postNotificationTitle:@"SysGuard: Dev Janitor Finished"
                             body:SafeNSString(rep.summary)
                            sound:false
                            reqId:@"sysguard-janitor-done"];
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_janitorRunning = false;
        self->_hasAudit = false;
        self->_lastActionStatus = rep.summary;
        if (self->_menuOpen) [self rebuildMenu];
        [self triggerDeepScanWithAutoReap:NO];
      });
    }
  });
}

- (void)onAuditWorktrees:(id)sender {
  (void)sender;
  if (_auditingWorktrees) return;
  _auditingWorktrees = true;
  std::vector<std::string> extraRoots = _config.extra_worktree_roots;
  if (_menuOpen) [self rebuildMenu];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      sysguard::WorktreeAuditSummary summary = sysguard::audit_worktrees(
          24, sysguard::WorktreeSizeMode::SafeOnly, extraRoots);
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_lastAudit = std::move(summary);
        self->_hasAudit = true;
        self->_auditingWorktrees = false;
        self->_lastActionStatus =
            "Worktrees: " + std::to_string(self->_lastAudit.safe_count) +
            " safe (" +
            sysguard::format_bytes_compact(self->_lastAudit.safe_bytes) + ")";
        if (self->_menuOpen) [self rebuildMenu];
      });
    }
  });
}

- (void)onPruneWorktrees:(id)sender {
  (void)sender;
  if (_auditingWorktrees || !_hasAudit || _lastAudit.safe_count == 0) return;
  _auditingWorktrees = true;
  sysguard::WorktreeAuditSummary auditCopy = _lastAudit;
  std::vector<std::string> extraRoots = _config.extra_worktree_roots;
  if (_menuOpen) [self rebuildMenu];
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      sysguard::WorktreePruneResult res =
          sysguard::prune_worktrees(auditCopy, true);
      sysguard::WorktreeAuditSummary fresh = sysguard::audit_worktrees(
          24, sysguard::WorktreeSizeMode::SafeOnly, extraRoots);
      [self postNotificationTitle:@"SysGuard: Worktrees Pruned"
                             body:SafeNSString(res.detail)
                            sound:false
                            reqId:@"sysguard-wtprune-done"];
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_lastAudit = std::move(fresh);
        self->_hasAudit = true;
        self->_auditingWorktrees = false;
        self->_lastActionStatus = res.detail;
        if (self->_menuOpen) [self rebuildMenu];
        [self triggerDeepScanWithAutoReap:NO];
      });
    }
  });
}

- (void)onToggleWeeklyJanitor:(id)sender {
  (void)sender;
  bool enable = !IsWeeklyJanitorEnabled();
  SetWeeklyJanitorEnabled(enable);
  NSString* plistPathNS = JanitorAgentPath();
  std::string plistPath = plistPathNS ? [plistPathNS UTF8String] : "";
  std::string domain = "gui/" + std::to_string(getuid());
  std::string serviceTarget = domain + "/com.local.sysguard.janitor";
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string out;
      int rc = 0;
      if (enable && !plistPath.empty()) {
        sysguard::run_command_capture(
            {"/bin/launchctl", "bootout", serviceTarget}, out, rc, 5000);
        sysguard::run_command_capture(
            {"/bin/launchctl", "bootstrap", domain, plistPath}, out, rc, 5000);
      } else {
        sysguard::run_command_capture(
            {"/bin/launchctl", "bootout", serviceTarget}, out, rc, 5000);
      }
    }
  });
}

- (void)onOpenProtonDrive:(id)sender {
  (void)sender;
  NSString* p = FindProtonDriveFolder();
  if (p) {
    [[NSWorkspace sharedWorkspace]
        activateFileViewerSelectingURLs:@[ [NSURL fileURLWithPath:p] ]];
  }
}

- (void)onRestartFseventsd:(id)sender {
  (void)sender;
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      bool ok = sysguard::restart_fseventsd_smart(true, err);
      usleep(500000);
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_lastActionStatus =
            ok ? "fseventsd restarted" : ("fseventsd restart failed: " + err);
        if (self->_menuOpen) [self rebuildMenu];
        [self triggerDeepScanWithAutoReap:NO];
      });
    }
  });
}

- (void)onToggleAutoHealFseventsd:(id)sender {
  (void)sender;
  NSUserDefaults* defs = [NSUserDefaults standardUserDefaults];
  bool current = [defs boolForKey:kPrefAutoHealFseventsd];
  if (current) {
    [defs setBool:NO forKey:kPrefAutoHealFseventsd];
    return;
  }
  if (_passwordlessFsReady.load(std::memory_order_relaxed)) {
    [defs setBool:YES forKey:kPrefAutoHealFseventsd];
    return;
  }
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      bool ok = sysguard::install_passwordless_fseventsd_rule(err);
      self->_passwordlessFsReady.store(ok, std::memory_order_relaxed);
      dispatch_async(dispatch_get_main_queue(), ^{
        if (ok) {
          [[NSUserDefaults standardUserDefaults] setBool:YES
                                                  forKey:kPrefAutoHealFseventsd];
          self->_lastActionStatus = "Auto-heal fseventsd enabled";
        } else {
          self->_lastActionStatus = "Sudoers rule install failed: " + err;
        }
        if (self->_menuOpen) [self rebuildMenu];
      });
    }
  });
}

- (void)onTogglePasswordlessRule:(id)sender {
  (void)sender;
  bool currentlyReady = _passwordlessFsReady.load(std::memory_order_relaxed);
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string err;
      bool ok = currentlyReady
                    ? sysguard::remove_passwordless_fseventsd_rule(err)
                    : sysguard::install_passwordless_fseventsd_rule(err);
      bool nowReady = sysguard::is_passwordless_fseventsd_configured();
      self->_passwordlessFsReady.store(nowReady, std::memory_order_relaxed);
      dispatch_async(dispatch_get_main_queue(), ^{
        if (!nowReady) {
          [[NSUserDefaults standardUserDefaults] setBool:NO
                                                  forKey:kPrefAutoHealFseventsd];
        }
        self->_lastActionStatus =
            ok ? (nowReady ? "Passwordless fseventsd rule installed"
                           : "Passwordless fseventsd rule removed")
               : ("Rule update failed: " + err);
        if (self->_menuOpen) [self rebuildMenu];
      });
    }
  });
}

- (void)onRefreshNow:(id)sender {
  (void)sender;
  [self triggerDeepScanWithAutoReap:NO];
}

- (void)onToggleNotifications:(id)sender {
  (void)sender;
  NSUserDefaults* defs = [NSUserDefaults standardUserDefaults];
  [defs setBool:![defs boolForKey:kPrefNotifications] forKey:kPrefNotifications];
}

- (void)onToggleAutoReap:(id)sender {
  (void)sender;
  NSUserDefaults* defs = [NSUserDefaults standardUserDefaults];
  [defs setBool:![defs boolForKey:kPrefAutoKillOrphans]
         forKey:kPrefAutoKillOrphans];
}

- (void)onToggleLaunchAtLogin:(id)sender {
  (void)sender;
  SetLaunchAtLoginEnabled(!IsLaunchAtLoginEnabled());
}

- (void)onOpenConfig:(id)sender {
  (void)sender;
  dispatch_async(_actionQueue, ^{
    @autoreleasepool {
      std::string cfgPath = sysguard::default_config_path();
      bool okCfg = sysguard::ensure_default_config_file(cfgPath);
      std::string out;
      int rc = -1;
      bool opened =
          okCfg &&
          sysguard::run_command_capture({"/usr/bin/open", "-t", cfgPath}, out,
                                        rc, 5000) &&
          rc == 0;
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_lastActionStatus =
            opened ? "Opened config.ini"
                   : (okCfg ? "Failed to open config.ini"
                            : "Failed to create config.ini");
        if (self->_menuOpen) [self rebuildMenu];
      });
    }
  });
}

- (void)onReloadConfig:(id)sender {
  (void)sender;
  dispatch_async(_workQueue, ^{
    @autoreleasepool {
      sysguard::SysGuardConfig newCfg = sysguard::load_config();
      self->_monitor->set_config(newCfg);
      dispatch_async(dispatch_get_main_queue(), ^{
        self->_config = std::move(newCfg);
        self->_lastStatusBarKey.clear();
        self->_lastActionStatus = "Config reloaded";
        [self updateStatusBarButton];
        if (self->_menuOpen) [self rebuildMenu];
        [self triggerDeepScanWithAutoReap:NO];
      });
    }
  });
}

@end

int main(int argc, const char* argv[]) {
  bool runJanitor = false;
  bool dryRun = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--janitor") == 0) {
      runJanitor = true;
    } else if (std::strcmp(argv[i], "--dry-run") == 0) {
      dryRun = true;
    }
  }

  if (runJanitor) {
    sysguard::SysGuardConfig cfg = sysguard::load_config();
    sysguard::JanitorOptions opts;
    opts.dry_run = dryRun;
    opts.tmp_min_age_hours = 48;
    opts.worktree_min_age_hours = 72;
    opts.include_caches = true;
    opts.include_worktrees = true;
    opts.include_pnpm_brew = true;
    opts.extra_worktree_roots = std::move(cfg.extra_worktree_roots);
    sysguard::JanitorReport rep = sysguard::run_dev_janitor(opts);
    std::cout << rep.summary << "\n";
    return 0;
  }

  int lockFd = AcquireGuiSingleInstanceLock();
  if (lockFd == -2) {
    std::cerr << "SysGuard is already running.\n";
    return 0;
  }

  std::signal(SIGPIPE, SIG_IGN);

  @autoreleasepool {
    NSApplication* app = [NSApplication sharedApplication];
    SysGuardDelegate* delegate = [[SysGuardDelegate alloc] init];
    app.delegate = delegate;
    [app run];
  }

  if (lockFd >= 0) {
    close(lockFd);
  }
  return 0;
}
