#ifdef _WIN32
#define NOMINMAX
#endif
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
    std::cout << "                     [--enable-mitm] [--ca-cert path] [--ca-key path] [--export-ca file] [--export-ca-der file]" << std::endl;
    std::cout << "  Use --enable-mitm to enable TLS interception (tunneling by default)." << std::endl;
}
}

int main(int argc, char** argv) {
    uint16_t port = 8080;
    Logger::Level level = Logger::Level::info;
    std::vector<std::string> args(argv + 1, argv + argc);
    std::size_t capture_bytes = 0;
    std::string capture_file;
    std::string caCertPath; std::string caKeyPath; bool enableMitm=false; bool regenerateCa=false; std::string exportCaFile; std::string exportCaDerFile;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--help" || a == "-h") { print_help(); return 0; }
        if ((a == "--port" || a == "-p") && i + 1 < args.size()) { port = static_cast<uint16_t>(std::stoi(args[++i])); continue; }
    if (a == "--log-level" && i + 1 < args.size()) { level = parse_level(args[++i]); continue; }
    if (a == "--capture-bytes" && i + 1 < args.size()) { capture_bytes = static_cast<std::size_t>(std::stoull(args[++i])); continue; }
    if (a == "--capture-file" && i + 1 < args.size()) { capture_file = args[++i]; continue; }
    if (a == "--enable-mitm") { enableMitm = true; continue; }
    if (a == "--disable-mitm") { /* deprecated, MITM disabled by default */ continue; }
    if (a == "--regenerate-ca") { regenerateCa = true; continue; }
    if (a == "--ca-cert" && i + 1 < args.size()) { caCertPath = args[++i]; continue; }
    if (a == "--ca-key" && i + 1 < args.size()) { caKeyPath = args[++i]; continue; }
    if (a == "--export-ca" && i + 1 < args.size()) { exportCaFile = args[++i]; continue; }
    if (a == "--export-ca-der" && i + 1 < args.size()) { exportCaDerFile = args[++i]; continue; }
    }
    Logger::instance().set_level(level);
    Logger::instance().log(Logger::Level::info, "starting");
    observathor::core::proxy::Config cfg; cfg.capture_bytes_limit = capture_bytes; if(!capture_file.empty()) cfg.capture_file_path = capture_file.c_str();
    if (enableMitm) { cfg.enableTlsMitm = true; if(!caCertPath.empty()) cfg.caCertPath = caCertPath.c_str(); if(!caKeyPath.empty()) cfg.caKeyPath = caKeyPath.c_str(); }
    if (regenerateCa) {
        // Delete existing CA files before server creates context.
        if(!caCertPath.empty()) { std::remove(caCertPath.c_str()); }
        if(!caKeyPath.empty())  { std::remove(caKeyPath.c_str()); }
    }
    ProxyServer server(port, cfg);
    auto obs = make_transaction_log_observer(server.dispatcher());
    if (cfg.capture_file_path) { make_file_store(server.dispatcher(), cfg.capture_file_path); }
    server.start();
    if (!exportCaFile.empty() || !exportCaDerFile.empty()) {
#ifdef OBSERVATHOR_HAVE_OPENSSL
        if (cfg.enableTlsMitm) {
            // Hack: create a temporary TlsContext again to extract CA if server's context not exposed; revisit design.
            observathor::core::tls::CertConfig cc{}; if(cfg.caCertPath) cc.caCertPath = cfg.caCertPath; if(cfg.caKeyPath) cc.caKeyPath = cfg.caKeyPath; cc.generateIfMissing = true;
            auto temp = observathor::core::tls::TlsContext::create(cc);
            if (!exportCaFile.empty()) {
                auto pem = temp->export_ca_pem();
                if (!pem.empty()) { FILE* f = fopen(exportCaFile.c_str(), "wb"); if(f){ fwrite(pem.data(),1,pem.size(),f); fclose(f); std::cout << "Exported CA PEM to " << exportCaFile << std::endl; } }
            }
            if (!exportCaDerFile.empty()) {
                auto der = temp->export_ca_der();
                if (!der.empty()) { FILE* f = fopen(exportCaDerFile.c_str(), "wb"); if(f){ fwrite(der.data(),1,der.size(),f); fclose(f); std::cout << "Exported CA DER to " << exportCaDerFile << std::endl; } }
            }
        } else {
            std::cout << "--export-ca ignored: MITM not enabled" << std::endl;
        }
#else
        std::cout << "TLS not compiled in; cannot export CA" << std::endl;
#endif
    }
    std::string line;
    std::getline(std::cin, line);
    server.stop();
    Logger::instance().log(Logger::Level::info, "stopped");
    return 0;
}
