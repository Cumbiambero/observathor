#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include "observathor/core/http/HttpParser.h"

namespace observathor::core::http {
struct HostTarget {
    std::string host;
    uint16_t port{80};
    std::string path;
};
std::optional<HostTarget> extract_host_target(const HttpRequest& req);
}
