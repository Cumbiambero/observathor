#include "observathor/core/proxy/TransactionLogObserver.h"
#include <fmt/format.h>

namespace observathor::core::proxy {
using observathor::core::util::Logger;

void TransactionLogObserver::on_transaction(const Transaction& t) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.startTime.time_since_epoch()).count();
    std::string extra;
    if (!t.requestHeaders.empty() || !t.responseStatusLine.empty()) {
        extra = fmt::format(" req_cap {}/{} resp_cap {}/{}", t.requestHeaders.size(), t.requestBody.size(), t.responseHeaders.size(), t.responseBody.size());
    }
    Logger::instance().log(Logger::Level::info, fmt::format("tx {} {} bytes_in {} bytes_out{}", ms, t.requestLine, t.bytesIn, t.bytesOut, extra));
}
std::shared_ptr<TransactionLogObserver> make_transaction_log_observer(TransactionDispatcher& d) {
    auto o = std::make_shared<TransactionLogObserver>();
    d.add(o);
    return o;
}
}
