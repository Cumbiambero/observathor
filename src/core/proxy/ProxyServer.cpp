#include "observathor/core/proxy/ProxyServer.h"
#include "observathor/core/util/Logger.h"
#include "observathor/core/net/Socket.h"
#include "observathor/core/proxy/Transaction.h"
#include "observathor/core/proxy/ClientSession.h"
#include <vector>
#include <memory>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#endif

namespace observathor::core::proxy {
using observathor::core::util::log_info;
using observathor::core::net::Listener;
using observathor::core::net::Socket;

namespace {
struct PlatformInit {
    PlatformInit() {
#ifdef _WIN32
        WSADATA d; WSAStartup(MAKEWORD(2,2), &d);
#endif
    }
    ~PlatformInit() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};
}

TransactionDispatcher& ProxyServer::dispatcher() { return tx_dispatcher; }

ProxyServer::ProxyServer(uint16_t listen_port, Config cfg) : port(listen_port), config(cfg) {
    // Derive default CA file locations if none provided.
    std::string autoCert, autoKey;
    if (!config.caCertPath || !config.caKeyPath) {
#ifdef _WIN32
        const char* appdata = std::getenv("APPDATA");
        std::string base = appdata? std::string(appdata) : std::string(".");
#else
        const char* home = std::getenv("HOME");
        std::string base = home? std::string(home) : std::string(".");
#endif
        base += "/Observathor";
        std::error_code ec; std::filesystem::create_directories(base, ec);
        autoCert = base + "/root_ca.pem";
        autoKey  = base + "/root_ca_key.pem";
    }
    tls::CertConfig cc{};
    cc.caCertPath = config.caCertPath? config.caCertPath : autoCert.c_str();
    cc.caKeyPath  = config.caKeyPath? config.caKeyPath : autoKey.c_str();
    cc.generateIfMissing = config.generateCaIfMissing;
    tls_ctx = tls::TlsContext::create(cc);
#ifdef OBSERVATHOR_HAVE_OPENSSL
    if (tls_ctx) {
        std::string fp = tls_ctx->ca_fingerprint_sha256();
        if (!fp.empty()) {
            log_info(std::string("CA fingerprint SHA256 ")+fp);
        }
    }
#endif
    // Initialize MITM policy runtime state from config
    mitmPolicy.set_enabled(config.enableTlsMitm);
}
ProxyServer::~ProxyServer() { stop(); }

void ProxyServer::start() {
    if (active.load()) return;
    active.store(true);
    io_thread = std::thread(&ProxyServer::run_loop, this);
}

void ProxyServer::stop() {
    if (!active.load()) return;
    active.store(false);
    io.stop();
    if (io_thread.joinable()) io_thread.join();
}

void ProxyServer::run_loop() {
    PlatformInit platform;
    Listener listener;
    if (!listener.open(port)) return;
    log_info("proxy listening");

    while (active.load()) {
        io.poll();
        auto client = listener.accept();
        if (!client.valid()) { std::this_thread::sleep_for(std::chrono::milliseconds(4)); continue; }
        auto socket_ptr = std::make_shared<Socket>(std::move(client));
    auto session = std::make_shared<ClientSession>(socket_ptr, tx_dispatcher, config, tls_ctx);
        session->set_mitm_policy(&mitmPolicy);
        io.post([session]{ session->start(); });
    }
}
}
