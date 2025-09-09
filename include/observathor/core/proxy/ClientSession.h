#pragma once
#include <memory>
#include <vector>
#include <string>
#include <chrono>
#include "observathor/core/net/Socket.h"
#include "observathor/core/http/HttpParser.h"
#include "observathor/core/proxy/TransactionDispatcher.h"

namespace observathor::core::proxy {
class ClientSession : public std::enable_shared_from_this<ClientSession> {
public:
    ClientSession(std::shared_ptr<net::Socket> socket, TransactionDispatcher& dispatcher, std::size_t capture_limit);
    void start();
private:
    std::shared_ptr<net::Socket> sock;
    TransactionDispatcher& dispatcher_ref;
    http::HttpParser parser;
    std::vector<char> buffer;
    std::chrono::steady_clock::time_point start_time;
    std::size_t capture_bytes_limit{0};
    void process();
};
}
