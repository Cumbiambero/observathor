#pragma once
#include <memory>
#include <vector>
#include <string>
#include <chrono>
#include "observathor/core/net/Socket.h"
#include "observathor/core/http/HttpParser.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include "observathor/core/proxy/Config.h"
#include "observathor/core/tls/TlsContext.h"

namespace observathor::core::proxy {
class ClientSession : public std::enable_shared_from_this<ClientSession> {
public:
    ClientSession(std::shared_ptr<net::Socket> socket, TransactionDispatcher& dispatcher, const Config& cfg, std::shared_ptr<tls::TlsContext> tlsCtx = {});
    void set_mitm_policy(class MitmPolicy* p){ policy = p; }
    void start();
private:
    std::shared_ptr<net::Socket> sock;
    TransactionDispatcher& dispatcher_ref;
    http::HttpParser parser;
    std::vector<char> buffer;
    std::chrono::steady_clock::time_point start_time;
    Config config; // copy of config at session start
    std::shared_ptr<tls::TlsContext> tls_ctx; // may be null
    class MitmPolicy* policy { nullptr }; // non-owning
    void process();
#ifdef OBSERVATHOR_HAVE_OPENSSL
    bool can_attempt_mitm(const std::string& host);
    void handle_ssl_mitm(const std::string& host, int port);
#endif
};
}
