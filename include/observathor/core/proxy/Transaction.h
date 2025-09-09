#pragma once
#include <string>
#include <chrono>
#include <cstdint>

namespace observathor::core::proxy {
struct Transaction {
    uint64_t id{0};
    std::chrono::steady_clock::time_point start_time;
    std::string request_line;
    uint64_t bytes_in{0};
    uint64_t bytes_out{0};
    // captured data (may be truncated according to config)
    std::string request_headers;
    std::string request_body;
    std::string response_status_line;
    std::string response_headers;
    std::string response_body;
};
class TransactionObserver {
public:
    virtual ~TransactionObserver() = default;
    virtual void on_transaction(const Transaction& t) = 0;
};
}
