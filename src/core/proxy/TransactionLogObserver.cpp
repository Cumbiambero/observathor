#include "observathor/core/proxy/TransactionLogObserver.h"
#include <fmt/format.h>

namespace observathor::core::proxy {
using observathor::core::util::Logger;

void TransactionLogObserver::on_transaction(const Transaction& t) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.start_time.time_since_epoch()).count();
    std::string extra;
    if (!t.request_headers.empty() || !t.response_status_line.empty()) {
        extra = fmt::format(" req_cap {}/{} resp_cap {}/{}", t.request_headers.size(), t.request_body.size(), t.response_headers.size(), t.response_body.size());
    }
    Logger::instance().log(Logger::Level::info, fmt::format("tx {} {} bytes_in {} bytes_out{}", ms, t.request_line, t.bytes_in, t.bytes_out, extra));
}
std::shared_ptr<TransactionLogObserver> make_transaction_log_observer(TransactionDispatcher& d) {
    auto o = std::make_shared<TransactionLogObserver>();
    d.add(o);
    return o;
}
}
