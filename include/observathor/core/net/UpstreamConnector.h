#pragma once
#include <string>
#include <optional>
#include "observathor/core/net/Socket.h"

namespace observathor::core::net {
class UpstreamConnector {
public:
    static std::optional<Socket> connect(const std::string& host, uint16_t port, int timeout_ms = 3000);
};
}
