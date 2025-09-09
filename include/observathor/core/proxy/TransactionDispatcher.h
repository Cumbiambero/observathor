#pragma once
#include <vector>
#include <memory>
#include <mutex>
#include "observathor/core/proxy/Transaction.h"

namespace observathor::core::proxy {
class TransactionDispatcher {
public:
    void add(std::shared_ptr<TransactionObserver> obs);
    void publish(const Transaction& t);
private:
    std::mutex guard;
    std::vector<std::weak_ptr<TransactionObserver>> observers;
};
}
