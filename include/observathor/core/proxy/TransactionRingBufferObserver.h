#pragma once
#include "observathor/core/proxy/Transaction.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include <deque>
#include <mutex>
#include <memory>

namespace observathor::core::proxy {
class TransactionRingBufferObserver : public TransactionObserver {
public:
    explicit TransactionRingBufferObserver(size_t capacity = 1000) : cap(capacity), recording(true) {}
    void on_transaction(const Transaction& t) override {
        std::lock_guard<std::mutex> lk(mu);
        if (recording) {
            q.push_back(t);
            if(q.size() > cap) q.pop_front();
        }
    }
    std::vector<Transaction> snapshot() {
        std::lock_guard<std::mutex> lk(mu);
        return {q.begin(), q.end()};
    }
    void clear() {
        std::lock_guard<std::mutex> lk(mu);
        q.clear();
    }
    void set_recording(bool enabled) {
        std::lock_guard<std::mutex> lk(mu);
        recording = enabled;
    }
    bool is_recording() const {
        std::lock_guard<std::mutex> lk(mu);
        return recording;
    }
private:
    size_t cap;
    std::deque<Transaction> q;
    mutable std::mutex mu;
    bool recording;
};
inline std::shared_ptr<TransactionRingBufferObserver> make_ring_buffer(TransactionDispatcher& d, size_t cap = 1000){
    auto ptr = std::make_shared<TransactionRingBufferObserver>(cap);
    d.add(ptr);
    return ptr;
}
}
