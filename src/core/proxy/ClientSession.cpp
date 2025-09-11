#include "observathor/core/proxy/ClientSession.h"
#include "observathor/core/proxy/Transaction.h"
#include "observathor/core/proxy/BodyCapture.h"
#include "observathor/core/http/HostUtil.h"
#include "observathor/core/net/UpstreamConnector.h"
#include <string>
#include <atomic>
#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <algorithm>
#include <string_view>
#include "observathor/core/proxy/MitmPolicy.h"

namespace observathor::core::proxy {

static std::atomic<uint64_t> nextId{1};

ClientSession::ClientSession(std::shared_ptr<net::Socket> socket, TransactionDispatcher& dispatcher, const Config& cfg, std::shared_ptr<tls::TlsContext> tlsCtx)
    : sock(socket), dispatcher_ref(dispatcher), config(cfg), tls_ctx(tlsCtx), start_time(std::chrono::steady_clock::now()) {
    buffer.resize(8192);
}

void ClientSession::start() {
    process();
}

void ClientSession::process() {
    uint64_t bytesIn = 0;
    uint64_t bytesOut = 0;

    std::string accumulated;
    bool headersComplete = false;
    std::string requestLineStr;
    std::string reqHeadersBlock;
    std::optional<http::HttpRequest> reqOpt;

    // Read request until we have headers
    while (!headersComplete) {
        auto r = sock->recv_some(buffer);
        if (!r || *r <= 0) {
            sock->close();
            return;
        }

        accumulated.append(buffer.data(), (size_t)*r);
        bytesIn += (uint64_t)*r;

        auto headerEnd = accumulated.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            std::string fullRequest = accumulated.substr(0, headerEnd + 4);
            reqOpt = parser.parse_request(fullRequest);
            if (reqOpt) {
                auto firstEol = fullRequest.find("\r\n");
                if (firstEol != std::string::npos) {
                    requestLineStr = fullRequest.substr(0, firstEol);
                    reqHeadersBlock = fullRequest.substr(firstEol + 2, headerEnd - (firstEol + 2));
                }
            }
            headersComplete = true;
        }
    }

    if (!reqOpt) {
        sock->close();
        return;
    }

    // Check if this is a CONNECT request for potential MITM
    if (reqOpt->request_line.method == "CONNECT") {
        // Parse host:port from CONNECT target
        std::string host;
        uint16_t port = 443;
        std::string target = reqOpt->request_line.target;
        size_t colonPos = target.find_last_of(':');
        if (colonPos != std::string::npos) {
            host = target.substr(0, colonPos);
            try {
                port = (uint16_t)std::stoul(target.substr(colonPos + 1));
            } catch (...) {
                port = 443;
            }
        } else {
            host = target;
        }

        if (host.empty()) {
            const char* fail = "HTTP/1.1 400 Bad Request\r\n\r\n";
            sock->send_all(fail);
            sock->close();
            return;
        }

        // Check if we should MITM this connection
        bool shouldIntercept = false;
        if (policy) {
            shouldIntercept = policy->should_intercept(host);
        }
        
        if (shouldIntercept) {
            // For now, just establish the tunnel (MITM implementation can be added later)
            const char* msg = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: Observathor-MITM\r\n\r\n";
            sock->send_all(msg);
            bytesOut += std::strlen(msg);
            
            // TODO: Implement SSL MITM here
            // For now, just close to avoid infinite waiting
            sock->close();
            
            Transaction t{};
            t.id = nextId.fetch_add(1, std::memory_order_relaxed);
            t.startTime = start_time;
            t.wallTime = std::chrono::system_clock::now();
            t.requestLine = std::move(requestLineStr);
            t.bytesIn = bytesIn;
            t.bytesOut = bytesOut;
            t.requestHeaders = std::move(reqHeadersBlock);
            t.tlsMitmIntercepted = true;
            t.mitmOutcome = "attempted";
            dispatcher_ref.publish(t);
            return;
        }
        
        // Plain tunnel
        auto upstream = net::UpstreamConnector::connect(host, port, 3000);
        if (upstream) {
            const char* established = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: Observathor\r\n\r\n";
            sock->send_all(established);
            bytesOut += std::strlen(established);

            // Simple TCP forwarding
            std::vector<char> clientBuf(16384), upstreamBuf(16384);
            bool done = false;
            auto lastActivity = std::chrono::steady_clock::now();
            
            while (!done) {
                fd_set readfds;
                FD_ZERO(&readfds);
                
#ifdef _WIN32
                SOCKET cfd = (SOCKET)sock->native();
                SOCKET ufd = (SOCKET)upstream->native();
                FD_SET(cfd, &readfds);
                FD_SET(ufd, &readfds);
                
                timeval tv;
                tv.tv_sec = 30;
                tv.tv_usec = 0;
                int ret = select(0, &readfds, nullptr, nullptr, &tv);
#else
                int cfd = sock->native();
                int ufd = upstream->native();
                FD_SET(cfd, &readfds);
                FD_SET(ufd, &readfds);
                
                struct timeval tv;
                tv.tv_sec = 30;
                tv.tv_usec = 0;
                int nfds = (cfd > ufd ? cfd : ufd) + 1;
                int ret = select(nfds, &readfds, nullptr, nullptr, &tv);
#endif
                
                if (ret <= 0) {
                    auto now = std::chrono::steady_clock::now();
                    if (ret < 0 || (now - lastActivity) > std::chrono::seconds(30)) {
                        break;
                    }
                    continue;
                }

                bool clientReadable = FD_ISSET(cfd, &readfds);
                bool upstreamReadable = FD_ISSET(ufd, &readfds);

                if (clientReadable) {
#ifdef _WIN32
                    int r = ::recv(cfd, clientBuf.data(), (int)clientBuf.size(), 0);
#else
                    int r = (int)::recv(cfd, clientBuf.data(), clientBuf.size(), 0);
#endif
                    if (r <= 0) {
                        done = true;
                    } else {
                        upstream->send_all(std::string_view(clientBuf.data(), (size_t)r));
                        bytesIn += (uint64_t)r;
                        lastActivity = std::chrono::steady_clock::now();
                    }
                }

                if (upstreamReadable) {
#ifdef _WIN32
                    int r = ::recv(ufd, upstreamBuf.data(), (int)upstreamBuf.size(), 0);
#else
                    int r = (int)::recv(ufd, upstreamBuf.data(), upstreamBuf.size(), 0);
#endif
                    if (r <= 0) {
                        done = true;
                    } else {
                        sock->send_all(std::string_view(upstreamBuf.data(), (size_t)r));
                        bytesOut += (uint64_t)r;
                        lastActivity = std::chrono::steady_clock::now();
                    }
                }
            }
        } else {
            const char* fail = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\nConnection: close\r\n\r\nBad";
            sock->send_all(fail);
            bytesOut += std::strlen(fail);
        }
        
        sock->close();
        Transaction t{};
        t.id = nextId.fetch_add(1, std::memory_order_relaxed);
        t.startTime = start_time;
        t.wallTime = std::chrono::system_clock::now();
        t.requestLine = std::move(requestLineStr);
        t.bytesIn = bytesIn;
        t.bytesOut = bytesOut;
        t.requestHeaders = std::move(reqHeadersBlock);
        dispatcher_ref.publish(t);
        return;
    }

    // Handle regular HTTP requests
    auto hostTarget = http::extract_host_target(*reqOpt);
    if (hostTarget) {
        auto upstream = net::UpstreamConnector::connect(hostTarget->host, hostTarget->port, 3000);
        if (upstream) {
            std::string firstLine = reqOpt->request_line.method + " " + hostTarget->path + " " + reqOpt->request_line.version + "\r\n";
            std::string headersBlock;
            
            for (auto& h : reqOpt->headers) {
                headersBlock += h.name;
                headersBlock += ": ";
                headersBlock += h.value;
                headersBlock += "\r\n";
            }
            headersBlock += "\r\n";

            upstream->send_all(firstLine);
            upstream->send_all(headersBlock);
            bytesOut += firstLine.size() + headersBlock.size();

            // Forward any remaining body data
            size_t headerEnd = accumulated.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                size_t bodyStart = headerEnd + 4;
                if (bodyStart < accumulated.size()) {
                    std::string_view bodyData(accumulated.data() + bodyStart, accumulated.size() - bodyStart);
                    upstream->send_all(bodyData);
                    bytesOut += bodyData.size();
                }
            }

            // Simple response forwarding
            std::vector<char> responseBuffer(16384);
            while (true) {
                auto r = upstream->recv_some(responseBuffer);
                if (!r || *r <= 0) break;
                
                sock->send_all(std::string_view(responseBuffer.data(), (size_t)*r));
                bytesIn += (uint64_t)*r;
            }
        } else {
            const char* fail = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\nConnection: close\r\n\r\nBad";
            sock->send_all(fail);
            bytesOut += std::strlen(fail);
        }
    }

    sock->close();
    Transaction t{};
    t.id = nextId.fetch_add(1, std::memory_order_relaxed);
    t.startTime = start_time;
    t.wallTime = std::chrono::system_clock::now();
    t.requestLine = std::move(requestLineStr);
    t.bytesIn = bytesIn;
    t.bytesOut = bytesOut;
    t.requestHeaders = std::move(reqHeadersBlock);
    dispatcher_ref.publish(t);
}

} // namespace observathor::core::proxy
