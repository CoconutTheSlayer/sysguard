CXX       := clang++
O_LEVEL   := -O3
ARCH      ?= $(shell uname -m)
ARCH_FLAGS := $(addprefix -arch ,$(ARCH))
ANALYZE_ARCH := $(firstword $(ARCH))
WARN_COMMON := -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wimplicit-fallthrough -Wextra-semi -Wunreachable-code -Wformat=2 -Wnull-dereference -Werror=return-type
WARN_CXX  := -Wpedantic -Wnon-virtual-dtor -Woverloaded-virtual -Wcast-qual
WARN_OBJCXX := -Warc-repeated-use-of-weak
CXXFLAGS  := $(O_LEVEL) -std=c++20 $(WARN_COMMON) $(WARN_CXX) $(ARCH_FLAGS)
OBJCXXFLAGS := $(O_LEVEL) -std=c++20 $(WARN_COMMON) $(WARN_OBJCXX) $(ARCH_FLAGS) -fobjc-arc
SANFLAGS  := -O1 -g -std=c++20 $(WARN_COMMON) $(WARN_CXX) $(ARCH_FLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer
TSANFLAGS := -O1 -g -std=c++20 $(WARN_COMMON) $(WARN_CXX) $(ARCH_FLAGS) -fsanitize=thread
FRAMEWORKS := -framework Cocoa -framework UserNotifications -framework IOKit -framework CoreFoundation
CLI_FRAMEWORKS := -framework IOKit -framework CoreFoundation

BUILD_DIR := build
APP_BUNDLE := $(BUILD_DIR)/SysGuard.app
APP_CONTENTS := $(APP_BUNDLE)/Contents
APP_MACOS := $(APP_CONTENTS)/MacOS
APP_EXEC := $(APP_MACOS)/SysGuard
WTCLEAN_BIN := $(BUILD_DIR)/wtclean
TEST_BIN := $(BUILD_DIR)/test_metrics
TEST_SAN_BIN := $(BUILD_DIR)/test_metrics_san
TEST_TSAN_BIN := $(BUILD_DIR)/test_metrics_tsan

CORE_SRCS := src/config.cpp src/subprocess.cpp src/system_actions.cpp src/metrics.cpp src/janitor.cpp
CORE_OBJS := $(BUILD_DIR)/config.o $(BUILD_DIR)/subprocess.o $(BUILD_DIR)/system_actions.o $(BUILD_DIR)/metrics.o $(BUILD_DIR)/janitor.o
APP_OBJS  := $(CORE_OBJS) $(BUILD_DIR)/header_view.o $(BUILD_DIR)/app.o

.PHONY: all test sanitize tsan analyze check install uninstall clean

all: $(APP_EXEC) $(WTCLEAN_BIN)

$(BUILD_DIR)/config.o: src/config.cpp src/config.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c src/config.cpp -o $@

$(BUILD_DIR)/subprocess.o: src/subprocess.cpp src/subprocess.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c src/subprocess.cpp -o $@

$(BUILD_DIR)/system_actions.o: src/system_actions.cpp src/system_actions.hpp src/metrics.hpp src/subprocess.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c src/system_actions.cpp -o $@

$(BUILD_DIR)/metrics.o: src/metrics.cpp src/metrics.hpp src/config.hpp src/subprocess.hpp src/system_actions.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c src/metrics.cpp -o $@

$(BUILD_DIR)/janitor.o: src/janitor.cpp src/janitor.hpp src/metrics.hpp src/config.hpp src/subprocess.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c src/janitor.cpp -o $@

$(BUILD_DIR)/header_view.o: src/header_view.mm src/header_view.hpp src/metrics.hpp src/config.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(OBJCXXFLAGS) -c src/header_view.mm -o $@

$(BUILD_DIR)/app.o: src/app.mm src/header_view.hpp src/metrics.hpp src/janitor.hpp src/config.hpp src/subprocess.hpp src/system_actions.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(OBJCXXFLAGS) -c src/app.mm -o $@

$(BUILD_DIR)/wtclean_main.o: src/wtclean_main.cpp src/janitor.hpp src/metrics.hpp src/config.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c src/wtclean_main.cpp -o $@

$(APP_EXEC): $(APP_OBJS) Info.plist
	@mkdir -p $(APP_MACOS)
	$(CXX) $(OBJCXXFLAGS) $(APP_OBJS) $(FRAMEWORKS) -o $(APP_EXEC)
	@cp Info.plist $(APP_CONTENTS)/Info.plist
	@codesign --force --deep --sign - $(APP_BUNDLE)

$(WTCLEAN_BIN): $(CORE_OBJS) $(BUILD_DIR)/wtclean_main.o
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(CORE_OBJS) $(BUILD_DIR)/wtclean_main.o $(CLI_FRAMEWORKS) -o $(WTCLEAN_BIN)

$(TEST_BIN): $(CORE_OBJS) tests/test_metrics.cpp src/metrics.hpp src/janitor.hpp src/config.hpp src/subprocess.hpp src/system_actions.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -Isrc $(CORE_OBJS) tests/test_metrics.cpp $(CLI_FRAMEWORKS) -o $(TEST_BIN)

test: $(TEST_BIN)
	./$(TEST_BIN)

sanitize: $(CORE_SRCS) tests/test_metrics.cpp src/metrics.hpp src/janitor.hpp src/config.hpp src/subprocess.hpp src/system_actions.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(SANFLAGS) -Isrc $(CORE_SRCS) tests/test_metrics.cpp $(CLI_FRAMEWORKS) -o $(TEST_SAN_BIN)
	ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(TEST_SAN_BIN)

tsan: $(CORE_SRCS) tests/test_metrics.cpp src/metrics.hpp src/janitor.hpp src/config.hpp src/subprocess.hpp src/system_actions.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(TSANFLAGS) -Isrc $(CORE_SRCS) tests/test_metrics.cpp $(CLI_FRAMEWORKS) -o $(TEST_TSAN_BIN)
	TSAN_OPTIONS=halt_on_error=1 ./$(TEST_TSAN_BIN)

analyze: $(CORE_SRCS) src/wtclean_main.cpp src/header_view.mm src/app.mm
	@OUT=$$( \
		for f in $(CORE_SRCS) src/wtclean_main.cpp; do \
			$(CXX) --analyze -Xanalyzer -analyzer-output=text -std=c++20 $(WARN_COMMON) $(WARN_CXX) -arch $(ANALYZE_ARCH) -Isrc -o /dev/null "$$f" 2>&1; \
		done; \
		for f in src/header_view.mm src/app.mm; do \
			$(CXX) --analyze -Xanalyzer -analyzer-output=text -std=c++20 $(WARN_COMMON) $(WARN_OBJCXX) -arch $(ANALYZE_ARCH) -fobjc-arc -Isrc -o /dev/null "$$f" 2>&1; \
		done \
	); \
	rm -f config.plist subprocess.plist system_actions.plist metrics.plist janitor.plist wtclean_main.plist header_view.plist app.plist; \
	if [ -n "$$OUT" ]; then echo "$$OUT"; exit 1; fi; \
	echo "Clang Static Analyzer passed cleanly."

check: test sanitize tsan analyze

install: all
	@DEST="/Applications/SysGuard.app"; \
	if [ ! -w /Applications ]; then DEST="$(HOME)/Applications/SysGuard.app"; mkdir -p "$(HOME)/Applications"; fi; \
	rm -rf "$$DEST" && cp -R "$(APP_BUNDLE)" "$$DEST"; \
	mkdir -p "$(HOME)/.local/bin"; \
	cp "$(WTCLEAN_BIN)" "$(HOME)/.local/bin/wtclean"; \
	chmod 755 "$(HOME)/.local/bin/wtclean"; \
	echo "Installed to $$DEST and $(HOME)/.local/bin/wtclean"

uninstall:
	@pkill -x SysGuard || true
	@launchctl bootout "gui/$$(id -u)/com.local.sysguard.janitor" 2>/dev/null || true
	@launchctl bootout "gui/$$(id -u)/com.local.sysguard" 2>/dev/null || true
	@rm -rf /Applications/SysGuard.app "$(HOME)/Applications/SysGuard.app"
	@rm -f "$(HOME)/.local/bin/wtclean" \
	       "$(HOME)/Library/LaunchAgents/com.local.sysguard.plist" \
	       "$(HOME)/Library/LaunchAgents/com.local.sysguard.janitor.plist" \
	       "$(HOME)/Library/Caches/com.local.sysguard.lock" \
	       "$(HOME)/Library/Logs/SysGuard-janitor.log"
	@echo "Uninstalled SysGuard.app, wtclean, LaunchAgents, lock, and janitor log."
	@echo "Preserved $(HOME)/Library/Application Support/SysGuard (config/state) and /etc/sudoers.d/sysguard-fseventsd (if installed)."
	@echo "To purge those too, run:"
	@echo "  rm -rf \"$(HOME)/Library/Application Support/SysGuard\""
	@echo "  sudo rm -f /etc/sudoers.d/sysguard-fseventsd"

clean:
	rm -rf $(BUILD_DIR)
