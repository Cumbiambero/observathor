#pragma once
#include <string>
#include <mutex>
#include <chrono>
#include <string_view>
#include <cstdio>

namespace observathor::core::util {
class Logger {
public:
    enum class Level { trace, debug, info, warn, error, critical };
    static Logger& instance();
    void set_level(Level new_level);
    void log(Level level, std::string_view message);
private:
    Logger() = default;
    std::mutex guard;
    Level current_level { Level::info };
    const char* label(Level level) const;
};
void log_info(std::string_view message);
}
