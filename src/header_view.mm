#import "header_view.hpp"

#include <algorithm>

NSColor* SysGuardColorForRatio(double ratio, double warnAt, double critAt) {
  if (ratio >= critAt) return [NSColor systemRedColor];
  if (ratio >= warnAt) return [NSColor systemOrangeColor];
  return [NSColor systemGreenColor];
}

NSColor* SysGuardColorForSeverity(sysguard::AlertSeverity sev) {
  switch (sev) {
    case sysguard::AlertSeverity::Crit:
      return [NSColor systemRedColor];
    case sysguard::AlertSeverity::Warn:
      return [NSColor systemOrangeColor];
    case sysguard::AlertSeverity::None:
      return [NSColor systemGreenColor];
  }
}

@implementation SysGuardHeaderView

- (instancetype)initWithFrame:(NSRect)frameRect {
  self = [super initWithFrame:frameRect];
  if (self) {
    self.autoresizingMask = NSViewWidthSizable;
  }
  return self;
}

- (BOOL)isFlipped {
  return YES;
}

- (void)drawBarAtY:(CGFloat)y
             label:(NSString*)label
             value:(NSString*)value
             ratio:(double)ratio
             color:(NSColor*)color {
  const CGFloat padX = 14.0;
  const CGFloat width = NSWidth(self.bounds) - padX * 2.0;

  static NSDictionary* labelAttrs = nil;
  static NSDictionary* valAttrs = nil;
  static NSColor* trackColor = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    labelAttrs = @{
      NSFontAttributeName :
          [NSFont systemFontOfSize:11.5 weight:NSFontWeightSemibold],
      NSForegroundColorAttributeName : [NSColor labelColor],
    };
    valAttrs = @{
      NSFontAttributeName :
          [NSFont monospacedDigitSystemFontOfSize:11.0
                                           weight:NSFontWeightRegular],
      NSForegroundColorAttributeName : [NSColor secondaryLabelColor],
    };
    trackColor = [[NSColor labelColor] colorWithAlphaComponent:0.12];
  });

  [label drawAtPoint:NSMakePoint(padX, y) withAttributes:labelAttrs];
  NSSize valSize = [value sizeWithAttributes:valAttrs];
  [value drawAtPoint:NSMakePoint(padX + width - valSize.width, y + 0.5)
      withAttributes:valAttrs];

  const CGFloat barY = y + 16.0;
  const CGFloat barH = 5.0;
  NSRect trackRect = NSMakeRect(padX, barY, width, barH);
  [trackColor setFill];
  [[NSBezierPath bezierPathWithRoundedRect:trackRect xRadius:2.5 yRadius:2.5]
      fill];

  double clamped = ratio < 0.0 ? 0.0 : (ratio > 1.0 ? 1.0 : ratio);
  if (clamped > 0.0) {
    NSRect fillRect = NSMakeRect(padX, barY, width * clamped, barH);
    [color setFill];
    [[NSBezierPath bezierPathWithRoundedRect:fillRect xRadius:2.5 yRadius:2.5]
        fill];
  }
}

- (void)drawSparklineInRect:(NSRect)rect
                      title:(NSString*)title
                     values:(const std::vector<double>&)values
                     minVal:(double)minVal
                     maxVal:(double)maxVal
                      color:(NSColor*)color {
  static NSDictionary* titleAttrs = nil;
  static NSColor* bgCol = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    titleAttrs = @{
      NSFontAttributeName :
          [NSFont monospacedDigitSystemFontOfSize:9.5
                                           weight:NSFontWeightMedium],
      NSForegroundColorAttributeName : [NSColor secondaryLabelColor],
    };
    bgCol = [[NSColor labelColor] colorWithAlphaComponent:0.05];
  });

  [title drawAtPoint:NSMakePoint(rect.origin.x, rect.origin.y)
      withAttributes:titleAttrs];

  NSRect plotRect = NSMakeRect(rect.origin.x, rect.origin.y + 13.0,
                               NSWidth(rect), NSHeight(rect) - 13.0);
  [bgCol setFill];
  [[NSBezierPath bezierPathWithRoundedRect:plotRect xRadius:2.5 yRadius:2.5]
      fill];

  const CGFloat pad = 2.0;
  const CGFloat innerW = NSWidth(plotRect) - pad * 2.0;
  const CGFloat innerH = NSHeight(plotRect) - pad * 2.0;
  const CGFloat x0 = plotRect.origin.x + pad;
  const CGFloat yBottom = plotRect.origin.y + NSHeight(plotRect) - pad;
  const double span = (maxVal > minVal) ? (maxVal - minVal) : 1.0;

  if (values.empty()) {
    NSBezierPath* base = [NSBezierPath bezierPath];
    [base moveToPoint:NSMakePoint(x0, yBottom - innerH * 0.15)];
    [base lineToPoint:NSMakePoint(x0 + innerW, yBottom - innerH * 0.15)];
    base.lineWidth = 1.0;
    [[[NSColor labelColor] colorWithAlphaComponent:0.20] setStroke];
    [base stroke];
    return;
  }

  auto normY = [&](double v) -> CGFloat {
    double r = (v - minVal) / span;
    if (r < 0.0) r = 0.0;
    if (r > 1.0) r = 1.0;
    return yBottom - static_cast<CGFloat>(r) * innerH;
  };

  NSBezierPath* linePath = [NSBezierPath bezierPath];
  NSBezierPath* fillPath = [NSBezierPath bezierPath];
  linePath.lineJoinStyle = NSLineJoinStyleRound;
  linePath.lineCapStyle = NSLineCapStyleRound;
  linePath.lineWidth = 1.3;

  if (values.size() == 1) {
    CGFloat py = normY(values[0]);
    [linePath moveToPoint:NSMakePoint(x0, py)];
    [linePath lineToPoint:NSMakePoint(x0 + innerW, py)];
    [fillPath moveToPoint:NSMakePoint(x0, yBottom)];
    [fillPath lineToPoint:NSMakePoint(x0, py)];
    [fillPath lineToPoint:NSMakePoint(x0 + innerW, py)];
    [fillPath lineToPoint:NSMakePoint(x0 + innerW, yBottom)];
    [fillPath closePath];
  } else {
    const size_t n = values.size();
    for (size_t i = 0; i < n; ++i) {
      CGFloat px =
          x0 + innerW * static_cast<CGFloat>(static_cast<double>(i) /
                                             static_cast<double>(n - 1));
      CGFloat py = normY(values[i]);
      if (i == 0) {
        [linePath moveToPoint:NSMakePoint(px, py)];
        [fillPath moveToPoint:NSMakePoint(px, yBottom)];
        [fillPath lineToPoint:NSMakePoint(px, py)];
      } else {
        [linePath lineToPoint:NSMakePoint(px, py)];
        [fillPath lineToPoint:NSMakePoint(px, py)];
      }
    }
    [fillPath lineToPoint:NSMakePoint(x0 + innerW, yBottom)];
    [fillPath closePath];
  }

  [[color colorWithAlphaComponent:0.16] setFill];
  [fillPath fill];
  [color setStroke];
  [linePath stroke];
}

- (void)drawRect:(NSRect)dirtyRect {
  [super drawRect:dirtyRect];

  const auto& f = self.fast;
  const auto& d = self.deep;
  const auto& cfg = self.config;
  const auto& hist = self.history;

  double ramRatio =
      f.ram_total_bytes > 0
          ? static_cast<double>(f.ram_used_bytes) /
                static_cast<double>(f.ram_total_bytes)
          : 0.0;
  NSColor* ramColor = SysGuardColorForRatio(ramRatio, 0.78, 0.90);
  NSString* ramVal = [NSString
      stringWithFormat:@"%s / %s · %s cmprs",
                       sysguard::format_bytes_compact(f.ram_used_bytes).c_str(),
                       sysguard::format_bytes_compact(f.ram_total_bytes).c_str(),
                       sysguard::format_bytes_compact(f.ram_compressed_bytes)
                           .c_str()];
  [self drawBarAtY:8.0
             label:@"RAM"
             value:ramVal
             ratio:ramRatio
             color:ramColor];

  double swapRatio =
      f.swap_total_bytes > 0
          ? static_cast<double>(f.swap_used_bytes) /
                static_cast<double>(f.swap_total_bytes)
          : (f.swap_used_bytes > 0 ? 0.5 : 0.0);
  NSColor* swapColor =
      (f.swap_used_bytes >= cfg.swap_crit_bytes)
          ? [NSColor systemRedColor]
          : ((f.swap_used_bytes >= cfg.swap_warn_bytes)
                 ? [NSColor systemOrangeColor]
                 : [NSColor systemGreenColor]);
  NSString* swapVal = [NSString
      stringWithFormat:@"%s / %s · %d%% free",
                       sysguard::format_bytes_compact(f.swap_used_bytes).c_str(),
                       sysguard::format_bytes_compact(f.swap_total_bytes)
                           .c_str(),
                       f.memory_free_pct];
  [self drawBarAtY:36.0
             label:@"Swap"
             value:swapVal
             ratio:swapRatio
             color:swapColor];

  double diskRatio = f.disk_used_pct / 100.0;
  NSColor* diskColor =
      (f.disk_avail_bytes < cfg.disk_crit_avail_bytes ||
       f.disk_used_pct >= cfg.disk_crit_used_pct)
          ? [NSColor systemRedColor]
          : ((f.disk_avail_bytes < cfg.disk_warn_avail_bytes ||
              f.disk_used_pct >= cfg.disk_warn_used_pct)
                 ? [NSColor systemOrangeColor]
                 : [NSColor systemGreenColor]);
  NSString* diskVal = [NSString
      stringWithFormat:@"%s free · %.1f%% used",
                       sysguard::format_bytes_compact(f.disk_avail_bytes)
                           .c_str(),
                       f.disk_used_pct];
  [self drawBarAtY:64.0
             label:@"SSD"
             value:diskVal
             ratio:diskRatio
             color:diskColor];

  double ioRatio = f.hw_disk_write_mb_s / 200.0;
  NSColor* ioColor = SysGuardColorForRatio(f.hw_disk_write_mb_s,
                                           cfg.proc_disk_write_warn_mb_s,
                                           cfg.hw_disk_write_warn_mb_s);
  NSString* ioVal = [NSString
      stringWithFormat:@"Write: %.1f MB/s · Today: %s", f.hw_disk_write_mb_s,
                       sysguard::format_bytes_compact(
                           f.hw_disk_written_today_bytes)
                           .c_str()];
  [self drawBarAtY:92.0
             label:@"SSD I/O"
             value:ioVal
             ratio:ioRatio
             color:ioColor];

  double fsRatio = static_cast<double>(d.fseventsd_rss_bytes) /
                   static_cast<double>(cfg.fseventsd_crit_bytes);
  double cpuRatio = f.cpu_used_pct / 100.0;
  double barRatio = fsRatio > cpuRatio ? fsRatio : cpuRatio;
  NSColor* fsColor = [NSColor systemGreenColor];
  if (d.fseventsd_rss_bytes >= cfg.fseventsd_crit_bytes ||
      (d.fseventsd_cpu_pct >= cfg.fseventsd_crit_cpu_pct &&
       d.fseventsd_high_strikes >= 2)) {
    fsColor = [NSColor systemRedColor];
  } else if (d.fseventsd_rss_bytes >= cfg.fseventsd_warn_bytes ||
             (d.fseventsd_cpu_pct >= cfg.fseventsd_warn_cpu_pct &&
              d.fseventsd_high_strikes >= 2)) {
    fsColor = [NSColor systemOrangeColor];
  }
  NSString* fsVal = [NSString
      stringWithFormat:@"CPU %.0f%% · fseventsd %s (%.1f%%)",
                       f.cpu_used_pct,
                       sysguard::format_bytes_compact(d.fseventsd_rss_bytes)
                           .c_str(),
                       d.fseventsd_cpu_pct];
  [self drawBarAtY:120.0
             label:@"CPU / fs"
             value:fsVal
             ratio:barRatio
             color:fsColor];

  // Subtle divider
  [[[NSColor labelColor] colorWithAlphaComponent:0.10] setFill];
  NSRectFill(NSMakeRect(14.0, 148.0, NSWidth(self.bounds) - 28.0, 1.0));

  // 15-minute trend sparklines
  std::vector<double> ramSeries;
  std::vector<double> swapSeries;
  std::vector<double> writeSeries;
  ramSeries.reserve(hist.size());
  swapSeries.reserve(hist.size());
  writeSeries.reserve(hist.size());
  double maxSwapGb = 4.0;
  double maxWriteMbS = 50.0;
  for (const auto& pt : hist) {
    ramSeries.push_back(static_cast<double>(pt.ram_ratio));
    double sg = static_cast<double>(pt.swap_gb);
    double wm = static_cast<double>(pt.write_mb_s);
    swapSeries.push_back(sg);
    writeSeries.push_back(wm);
    maxSwapGb = std::max(maxSwapGb, sg * 1.15);
    maxWriteMbS = std::max(maxWriteMbS, wm * 1.15);
  }

  const CGFloat sparkY = 154.0;
  const CGFloat sparkH = 34.0;
  const CGFloat sparkW = 101.0;
  [self drawSparklineInRect:NSMakeRect(14.0, sparkY, sparkW, sparkH)
                      title:@"RAM 15m"
                     values:ramSeries
                     minVal:0.0
                     maxVal:1.0
                      color:ramColor];
  [self drawSparklineInRect:NSMakeRect(125.5, sparkY, sparkW, sparkH)
                      title:@"Swap 15m"
                     values:swapSeries
                     minVal:0.0
                     maxVal:maxSwapGb
                      color:swapColor];
  [self drawSparklineInRect:NSMakeRect(237.0, sparkY, sparkW, sparkH)
                      title:@"Write 15m"
                     values:writeSeries
                     minVal:0.0
                     maxVal:maxWriteMbS
                      color:ioColor];
}

@end
