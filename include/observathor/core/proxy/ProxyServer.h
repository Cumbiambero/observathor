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
#include "observathor/core/tls/TlsContext.h"
#include "observathor/core/proxy/MitmPolicy.h"

namespace observathor::core::proxy {
class ProxyServer {
public:
    explicit ProxyServer(uint16_t listen_port, Config cfg = {});
    ~ProxyServer();
    void start();
    void stop();
    TransactionDispatcher& dispatcher();
    std::shared_ptr<tls::TlsContext> tls_context() const { return tls_ctx; }
    MitmPolicy& mitm_policy() { return mitmPolicy; }
private:
    uint16_t port;
    Config config;
    std::thread io_thread;
    std::atomic<bool> active { false };
    net::IoContext io;
    TransactionDispatcher tx_dispatcher;
    std::shared_ptr<tls::TlsContext> tls_ctx; // created if TLS MITM enabled
    MitmPolicy mitmPolicy; // runtime toggle & filters
    void run_loop();
};
}
