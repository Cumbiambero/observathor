#include "observathor/core/net/Socket.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif
#include <cstring>

namespace observathor::core::net {
namespace {
inline int close_native(int fd) {
#ifdef _WIN32
    return closesocket(fd);
#else
    return ::close(fd);
#endif
}
inline bool set_nb(int fd) {
#ifdef _WIN32
    u_long mode = 1; return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0); if (flags < 0) return false; return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}
}

Socket::Socket() = default;
Socket::Socket(int fd) : handle(fd) {}
Socket::Socket(Socket&& other) noexcept : handle(other.handle) { other.handle = -1; }
Socket& Socket::operator=(Socket&& other) noexcept { if (this != &other) { close(); handle = other.handle; other.handle = -1; } return *this; }
Socket::~Socket() { close(); }
bool Socket::valid() const { return handle >= 0; }
int Socket::native() const { return handle; }
void Socket::close() { if (handle >= 0) { close_native(handle); handle = -1; } }
bool Socket::set_non_blocking() { if (!valid()) return false; return set_nb(handle); }
std::optional<int> Socket::recv_some(std::vector<char>& buffer) {
    if (!valid()) return std::nullopt;
#ifdef _WIN32
    int r = ::recv(handle, buffer.data(), static_cast<int>(buffer.size()), 0);
#else
    int r = static_cast<int>(::recv(handle, buffer.data(), buffer.size(), 0));
#endif
    if (r <= 0) return std::nullopt; return r;
}
bool Socket::send_all(std::string_view data) {
    if (!valid()) return false;
    const char* p = data.data(); size_t remaining = data.size();
    while (remaining > 0) {
#ifdef _WIN32
        int sent = ::send(handle, p, static_cast<int>(remaining), 0);
#else
        int sent = static_cast<int>(::send(handle, p, remaining, 0));
#endif
        if (sent <= 0) return false; p += sent; remaining -= sent;
    }
    return true;
}

Listener::Listener() = default;
Listener::~Listener() { close(); }
bool Listener::valid() const { return handle >= 0; }
int Listener::native() const { return handle; }
void Listener::close() { if (handle >= 0) { close_native(handle); handle = -1; } }
bool Listener::open(uint16_t port) {
    handle = ::socket(AF_INET, SOCK_STREAM, 0);
    if (handle < 0) return false;
    int yes = 1;
#ifdef _WIN32
    setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
#else
    setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(port);
    if (bind(handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { close(); return false; }
    if (listen(handle, 128) < 0) { close(); return false; }
    set_nb(handle);
    return true;
}
Socket Listener::accept() {
    if (!valid()) return Socket();
    sockaddr_in addr{}; socklen_t len = sizeof(addr);
    int c = ::accept(handle, reinterpret_cast<sockaddr*>(&addr), &len);
    if (c < 0) return Socket();
    Socket s(c); s.set_non_blocking(); return s;
}
}
