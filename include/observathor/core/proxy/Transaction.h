#pragma once
#include <string>
#include <chrono>
#include <cstdint>

namespace observathor::core::proxy {
struct Transaction {
    uint64_t id{0};
    std::chrono::steady_clock::time_point startTime;
    std::chrono::system_clock::time_point wallTime; // wall clock for UI/local time display
    std::string requestLine;
    uint64_t bytesIn{0};
    uint64_t bytesOut{0};
    std::string requestHeaders;
    std::string requestBody; // may be empty if spilled to file
    std::string responseStatusLine;
    std::string responseHeaders;
    std::string responseBody; // may be empty if spilled
    std::string requestBodyPath;
    std::string responseBodyPath;
    bool requestBodyInFile{false};
    bool responseBodyInFile{false};
    bool requestWasChunked{false};
    bool responseWasChunked{false};
    bool tlsMitmIntercepted{false}; // true if HTTPS was MITM-decrypted (not just tunneled)
    std::string mitmOutcome; // "intercepted", "tunneled", or reason like "filtered" / "handshake-fail"
};
extern std::size_t g_captureMemoryInUse; // global tracker
class TransactionObserver {
public:
    virtual ~TransactionObserver() = default;
    virtual void on_transaction(const Transaction& t) = 0;
};
}
