#include "observathor/core/proxy/TransactionDispatcher.h"

namespace observathor::core::proxy {
void TransactionDispatcher::add(std::shared_ptr<TransactionObserver> obs) {
    std::lock_guard lock(guard);
    observers.push_back(obs);
}
void TransactionDispatcher::publish(const Transaction& t) {
    std::vector<std::shared_ptr<TransactionObserver>> alive;
    {
        std::lock_guard lock(guard);
        for (auto& w : observers) {
            if (auto s = w.lock()) alive.push_back(std::move(s));
        }
    }
    for (auto& o : alive) o->on_transaction(t);
}
}
