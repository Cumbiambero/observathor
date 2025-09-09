#include "observathor/core/proxy/ProxyServer.h"
#include "observathor/core/proxy/TransactionLogObserver.h"
#include "observathor/core/proxy/TransactionFileStore.h"
#include "observathor/core/util/Logger.h"
#include <string>
#include <iostream>
#include <vector>

using namespace observathor::core::proxy;
using namespace observathor::core::util;

namespace {
Logger::Level parse_level(const std::string& v) {
    if (v == "trace") return Logger::Level::trace;
    if (v == "debug") return Logger::Level::debug;
    if (v == "info") return Logger::Level::info;
    if (v == "warn") return Logger::Level::warn;
    if (v == "error") return Logger::Level::error;
    if (v == "critical") return Logger::Level::critical;
    return Logger::Level::info;
}
void print_help() {
    std::cout << "Usage: observathor_cli [--port N|-p N] [--log-level L] [--capture-bytes N] [--capture-file path]" << std::endl;
}
}

int main(int argc, char** argv) {
    uint16_t port = 8080;
    Logger::Level level = Logger::Level::info;
    std::vector<std::string> args(argv + 1, argv + argc);
    std::size_t capture_bytes = 0;
    std::string capture_file;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--help" || a == "-h") { print_help(); return 0; }
        if ((a == "--port" || a == "-p") && i + 1 < args.size()) { port = static_cast<uint16_t>(std::stoi(args[++i])); continue; }
    if (a == "--log-level" && i + 1 < args.size()) { level = parse_level(args[++i]); continue; }
    if (a == "--capture-bytes" && i + 1 < args.size()) { capture_bytes = static_cast<std::size_t>(std::stoull(args[++i])); continue; }
    if (a == "--capture-file" && i + 1 < args.size()) { capture_file = args[++i]; continue; }
    }
    Logger::instance().set_level(level);
    Logger::instance().log(Logger::Level::info, "starting");
    observathor::core::proxy::Config cfg; cfg.capture_bytes_limit = capture_bytes; if(!capture_file.empty()) cfg.capture_file_path = capture_file.c_str();
    ProxyServer server(port, cfg);
    auto obs = make_transaction_log_observer(server.dispatcher());
    if (cfg.capture_file_path) { make_file_store(server.dispatcher(), cfg.capture_file_path); }
    server.start();
    std::string line;
    std::getline(std::cin, line);
    server.stop();
    Logger::instance().log(Logger::Level::info, "stopped");
    return 0;
}
