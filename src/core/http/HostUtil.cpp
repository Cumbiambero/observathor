#include "observathor/core/http/HostUtil.h"
#include <algorithm>

namespace observathor::core::http {
static std::string to_lower(std::string v) { std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c){ return char(std::tolower(c)); }); return v; }

std::optional<HostTarget> extract_host_target(const HttpRequest& req) {
    std::string host_header;
    for (auto& h : req.headers) {
        if (to_lower(h.name) == "host") { host_header = h.value; break; }
    }
    if (host_header.empty()) return std::nullopt;
    std::string host = host_header;
    uint16_t port = 80;
    auto colon = host.find(':');
    if (colon != std::string::npos) {
        auto port_str = host.substr(colon + 1);
        host.erase(colon);
        try { int p = std::stoi(port_str); if (p > 0 && p < 65536) port = static_cast<uint16_t>(p); } catch(...) {}
    }
    std::string path = req.request_line.target;
    if (path.rfind("http://", 0) == 0 || path.rfind("https://", 0) == 0) {
        auto scheme_end = path.find("//");
        if (scheme_end != std::string::npos) {
            auto after = scheme_end + 2;
            auto slash = path.find('/', after);
            if (slash != std::string::npos) {
                path = path.substr(slash);
            } else {
                path = "/";
            }
        }
    }
    return HostTarget{ host, port, path };
}
}
