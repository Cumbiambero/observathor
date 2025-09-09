#pragma once
#include "observathor/core/proxy/Transaction.h"
#include <vector>
#include <mutex>
// forward declare dispatcher to avoid circular include
namespace observathor::core::proxy { class TransactionDispatcher; }
namespace observathor::core::proxy {
class TransactionMemoryStore : public TransactionObserver, public std::enable_shared_from_this<TransactionMemoryStore> {
public:
    void on_transaction(const Transaction& t) override {
        std::lock_guard lock(mu);
        store.push_back(t);
    }
    std::vector<Transaction> snapshot() const {
        std::lock_guard lock(mu);
        return store;
    }
private:
    mutable std::mutex mu;
    std::vector<Transaction> store;
};
std::shared_ptr<TransactionMemoryStore> make_memory_store(TransactionDispatcher& d);
}
