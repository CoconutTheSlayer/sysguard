#pragma once

#import <Cocoa/Cocoa.h>
#include <vector>

#include "config.hpp"
#include "metrics.hpp"

NSColor* SysGuardColorForRatio(double ratio, double warnAt, double critAt);
NSColor* SysGuardColorForSeverity(sysguard::AlertSeverity sev);

@interface SysGuardHeaderView : NSView
@property(nonatomic) sysguard::FastMetrics fast;
@property(nonatomic) sysguard::DeepMetrics deep;
@property(nonatomic) sysguard::SysGuardConfig config;
@property(nonatomic) std::vector<sysguard::MetricPoint> history;
@end
