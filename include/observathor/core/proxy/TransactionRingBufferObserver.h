#pragma once
#include "observathor/core/proxy/Transaction.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include <deque>
#include <mutex>
#include <memory>

namespace observathor::core::proxy {
class TransactionRingBufferObserver : public TransactionObserver {
public:
    explicit TransactionRingBufferObserver(size_t capacity = 1000) : cap(capacity) {}
    void on_transaction(const Transaction& t) override {
        std::lock_guard<std::mutex> lk(mu);
        q.push_back(t);
        if(q.size() > cap) q.pop_front();
    }
    std::vector<Transaction> snapshot() {
        std::lock_guard<std::mutex> lk(mu);
        return {q.begin(), q.end()};
    }
private:
    size_t cap;
    std::deque<Transaction> q;
    std::mutex mu;
};
inline std::shared_ptr<TransactionRingBufferObserver> make_ring_buffer(TransactionDispatcher& d, size_t cap = 1000){
    auto ptr = std::make_shared<TransactionRingBufferObserver>(cap);
    d.add(ptr);
    return ptr;
}
}
