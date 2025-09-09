#pragma once
#include <cstdint>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>
#include "observathor/core/net/IoContext.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include "observathor/core/proxy/Config.h"

namespace observathor::core::proxy {
class ProxyServer {
public:
    explicit ProxyServer(uint16_t listen_port, Config cfg = {});
    ~ProxyServer();
    void start();
    void stop();
    TransactionDispatcher& dispatcher();
private:
    uint16_t port;
    Config config;
    std::thread io_thread;
    std::atomic<bool> active { false };
    net::IoContext io;
    TransactionDispatcher tx_dispatcher;
    void run_loop();
};
}
