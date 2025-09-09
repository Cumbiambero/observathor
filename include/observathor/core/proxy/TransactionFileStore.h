#pragma once
#include "observathor/core/proxy/Transaction.h"
#include <string>
#include <mutex>
#include <fstream>
namespace observathor::core::proxy {
class TransactionDispatcher;
class TransactionFileStore : public TransactionObserver, public std::enable_shared_from_this<TransactionFileStore> {
public:
    explicit TransactionFileStore(std::string path);
    void on_transaction(const Transaction& t) override;
private:
    std::mutex mu;
    std::ofstream ofs;
    static std::string escape_json(const std::string& in);
    static std::string b64(const std::string& in);
};
std::shared_ptr<TransactionFileStore> make_file_store(TransactionDispatcher& d, const std::string& path);
}
