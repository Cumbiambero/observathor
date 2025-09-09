#pragma once
#include <cstdint>
#include <string>
#include <optional>
#include <vector>

namespace observathor::core::net {
class Socket {
public:
    Socket();
    explicit Socket(int fd);
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    ~Socket();
    bool valid() const;
    int native() const;
    void close();
    bool set_non_blocking();
    std::optional<int> recv_some(std::vector<char>& buffer);
    bool send_all(std::string_view data);
private:
    int handle{-1};
};

class Listener {
public:
    Listener();
    ~Listener();
    bool open(uint16_t port);
    Socket accept();
    void close();
    bool valid() const;
    int native() const;
private:
    int handle{-1};
};
}
