#pragma once
#include "observathor/core/proxy/Transaction.h"
#include <vector>
#include <string>
#include <optional>

namespace observathor::core::proxy {
struct SessionExportOptions { bool includeBodiesBase64{true}; };

std::string export_transactions_json(const std::vector<Transaction>& txs, const SessionExportOptions& opt = {});
std::optional<std::vector<Transaction>> import_transactions_json(const std::string& json);
}
