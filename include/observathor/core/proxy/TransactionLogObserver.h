#pragma once
#include "observathor/core/proxy/Transaction.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include "observathor/core/util/Logger.h"
#include <memory>

namespace observathor::core::proxy {
class TransactionLogObserver : public TransactionObserver, public std::enable_shared_from_this<TransactionLogObserver> {
public:
    void on_transaction(const Transaction& t) override;
};
std::shared_ptr<TransactionLogObserver> make_transaction_log_observer(TransactionDispatcher& d);
}
