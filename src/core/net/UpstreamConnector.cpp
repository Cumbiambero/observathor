#include "observathor/core/net/UpstreamConnector.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#endif
#include <cstring>
#include <chrono>

namespace observathor::core::net {
std::optional<Socket> UpstreamConnector::connect(const std::string& host, uint16_t port, int timeout_ms) {
    auto port_str = std::to_string(port);
#ifdef _WIN32
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) return std::nullopt;
    for (auto p = res; p; p = p->ai_next) {
        int s = (int)::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        u_long mode = 1; ioctlsocket(s, FIONBIO, &mode);
        int r = ::connect(s, p->ai_addr, (int)p->ai_addrlen);
        if (r == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) { closesocket(s); continue; }
            fd_set wfds; FD_ZERO(&wfds); FD_SET(s, &wfds);
            timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            if (select(0, nullptr, &wfds, nullptr, &tv) <= 0) { closesocket(s); continue; }
        }
        u_long mode0 = 0; ioctlsocket(s, FIONBIO, &mode0);
        freeaddrinfo(res);
        return Socket(s);
    }
    if (res) freeaddrinfo(res);
    return std::nullopt;
#else
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) return std::nullopt;
    for (auto p = res; p; p = p->ai_next) {
        int s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        int flags = fcntl(s, F_GETFL, 0); fcntl(s, F_SETFL, flags | O_NONBLOCK);
        int r = ::connect(s, p->ai_addr, p->ai_addrlen);
        if (r < 0) {
            if (errno != EINPROGRESS) { ::close(s); continue; }
            fd_set wfds; FD_ZERO(&wfds); FD_SET(s, &wfds);
            timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            if (select(s + 1, nullptr, &wfds, nullptr, &tv) <= 0) { ::close(s); continue; }
        }
        fcntl(s, F_SETFL, flags);
        ::freeaddrinfo(res);
        return Socket(s);
    }
    if (res) ::freeaddrinfo(res);
    return std::nullopt;
#endif
}
}
