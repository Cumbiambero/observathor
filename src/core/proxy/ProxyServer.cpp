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

ProxyServer::ProxyServer(uint16_t listen_port, Config cfg) : port(listen_port), config(cfg) {}
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
    auto session = std::make_shared<ClientSession>(socket_ptr, tx_dispatcher, config.capture_bytes_limit);
        io.post([session]{ session->start(); });
    }
}
}
