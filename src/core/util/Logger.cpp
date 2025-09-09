#include "observathor/core/util/Logger.h"
#include <fmt/format.h>
#include <iostream>

namespace observathor::core::util {
Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::set_level(Level new_level) { current_level = new_level; }

const char* Logger::label(Level level) const {
    switch (level) {
        case Level::trace: return "TRACE";
        case Level::debug: return "DEBUG";
        case Level::info: return "INFO";
        case Level::warn: return "WARN";
        case Level::error: return "ERROR";
        case Level::critical: return "CRIT";
    }
    return "?";
}

void Logger::log(Level level, std::string_view message) {
    if (static_cast<int>(level) < static_cast<int>(current_level)) return;
    auto now = std::chrono::system_clock::now();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::lock_guard lock(guard);
    fmt::print("[{0}] {1} {2}\n", label(level), millis, message);
}

void log_info(std::string_view message) { Logger::instance().log(Logger::Level::info, message); }
}
