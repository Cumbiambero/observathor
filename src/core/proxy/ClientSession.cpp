#include "observathor/core/proxy/ClientSession.h"
#include "observathor/core/proxy/Transaction.h"
#include "observathor/core/http/HostUtil.h"
#include "observathor/core/net/UpstreamConnector.h"
#include <string>
#include <atomic>
#include <cstdint>
#ifdef _WIN32
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

// Removed prior MITM failure/blacklist helpers – always attempt based on policy
#ifdef OBSERVATHOR_HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

static std::atomic<uint64_t> nextId{1};

// Adaptive suppression of repeated futile MITM attempts for pinned / untrusted hosts.
namespace {
    struct PinnedInfo {
        std::chrono::steady_clock::time_point first;
        unsigned failures{0};
    };
    static std::unordered_map<std::string, PinnedInfo> g_pinned;
    static constexpr std::chrono::minutes PIN_TTL{30};
    static void mark_pinned(const std::string& host){
        auto& e = g_pinned[host];
        if (e.failures==0) e.first = std::chrono::steady_clock::now();
        ++e.failures;
        printf("DEBUG: MITM marking host as pinned/untrusted %s failures=%u\n", host.c_str(), e.failures);
    }
    static bool is_pinned(const std::string& host){
        auto it = g_pinned.find(host);
        if (it==g_pinned.end()) return false;
        if (std::chrono::steady_clock::now() - it->second.first > PIN_TTL) { g_pinned.erase(it); return false; }
        return true;
    }
}

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

    // Handle special internal endpoints for CA certificate export
    if (reqOpt->request_line.method == "GET") {
        const std::string& target = reqOpt->request_line.target;
        
        auto send_ca_attachment = [&](bool der){
#ifdef OBSERVATHOR_HAVE_OPENSSL
            if (!tls_ctx) return false;
            std::string content;
            std::string content_type;
            std::string filename;
            if (der) {
                content = tls_ctx->export_ca_der();
                content_type = "application/x-x509-ca-cert";
                filename = "observathor_root_ca.der";
            } else {
                content = tls_ctx->export_ca_pem();
                content_type = "application/x-pem-file";
                filename = "observathor_root_ca.pem";
            }
            if (content.empty()) return false;
            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: " + content_type + "\r\n";
            response += "Content-Length: " + std::to_string(content.size()) + "\r\n";
            response += "Content-Disposition: attachment; filename=\"" + filename + "\"\r\n";
            response += "Connection: close\r\n\r\n";
            response += content;
            sock->send_all(response);
            sock->close();
            return true;
#else
            (void)der; return false;
#endif
        };
        std::string path;
        if (target.substr(0, 7) == "http://") {
            size_t host_start = 7;
            size_t path_start = target.find('/', host_start);
            if (path_start != std::string::npos) {
                path = target.substr(path_start);
            } else {
                path = "/";
            }
            size_t host_end = (path_start == std::string::npos) ? target.size() : path_start;
            std::string bareHost = target.substr(host_start, host_end - host_start);
            if (bareHost == "ssl" || bareHost == "ca" || bareHost == "cert") {
                if (send_ca_attachment(false)) return; // serve PEM
            }
        } else {
            path = target;
        }
        
        if (path == "/__observathor/help") {
#ifdef OBSERVATHOR_HAVE_OPENSSL
            std::string html =
                "<html><head><title>Observathor Help</title></head><body>"
                "<h1>Observathor Local CA</h1>"
                "<p>Install this root certificate on your device to enable HTTPS interception.</p>"
                "<ul>"
                "<li><a href=\"/__observathor/ca.pem\">CA PEM</a></li>"
                "<li><a href=\"/__observathor/ca.der\">CA DER</a></li>"
                "</ul>"
                "<h2>Quick Mobile Steps</h2>"
                "<h3>Android (user CA)</h3><ol>"
                "<li>Download DER link above on device.</li>"
                "<li>Open Settings &gt; Security &gt; Encryption &amp; credentials &gt; Install a certificate &gt; CA.</li>"
                "<li>Select downloaded file and confirm.</li>"
                "<li>Reopen browser/app.</li>"
                "</ol>"
                "<h3>iOS</h3><ol>"
                "<li>Download PEM link (Safari prompts profile install).</li>"
                "<li>Settings &gt; Profile Downloaded &gt; Install.</li>"
                "<li>Then Settings &gt; General &gt; About &gt; Certificate Trust Settings &gt; Enable full trust.</li>"
                "</ol>"
                "<p>Alternatively browse to http://ssl/ (through the proxy) for direct PEM download.</p>"
                "</body></html>";
            std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + std::to_string(html.size()) + "\r\nConnection: close\r\n\r\n" + html;
            sock->send_all(resp);
            sock->close();
            return;
#endif
        }

        if (path == "/ca.pem" || path == "/ssl" || path == "/ca" || path == "/cert") {
            if (send_ca_attachment(false)) return;
        } else if (path == "/ca.der") {
            if (send_ca_attachment(true)) return;
        }
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
                unsigned long p = std::stoul(target.substr(colonPos + 1));
                if (p <= 65535) port = static_cast<uint16_t>(p);
            } catch (...) { /* ignore, keep default */ }
        } else {
            host = target;
        }

        if (host.empty()) {
            const char* fail = "HTTP/1.1 400 Bad Request\r\n\r\n";
            sock->send_all(fail);
            sock->close();
            return;
        }

        // Check if this is a special certificate download domain
        if (host == "ssl" || host == "pem" || host == "ca" || host == "cert" || host == "der" ||
            host == "ovtr.ssl" || host == "ovtr.pem" || host == "ovtr.ca" || host == "ovtr.cert" || host == "ovtr.der") {
#ifdef OBSERVATHOR_HAVE_OPENSSL
            if (tls_ctx) {
                // Send 200 Connection Established to complete the CONNECT
                const char* msg = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: Observathor-CA\r\n\r\n";
                sock->send_all(msg);
                bytesOut += std::strlen(msg);
                
                // Wait for the actual HTTP request
                std::string http_request;
                while (true) {
                    auto r = sock->recv_some(buffer);
                    if (!r || *r <= 0) break;
                    
                    http_request.append(buffer.data(), (size_t)*r);
                    if (http_request.find("\r\n\r\n") != std::string::npos) break;
                }
                
                // Parse the HTTP request to get the path
                std::string path = "/";
                auto req_line_end = http_request.find("\r\n");
                if (req_line_end != std::string::npos) {
                    std::string request_line = http_request.substr(0, req_line_end);
                    auto space1 = request_line.find(' ');
                    auto space2 = request_line.find(' ', space1 + 1);
                    if (space1 != std::string::npos && space2 != std::string::npos) {
                        path = request_line.substr(space1 + 1, space2 - space1 - 1);
                    }
                }
                
                // Determine format based on domain and path
                bool use_der = (host == "der" || host == "ovtr.der" || path.find("/der") != std::string::npos);
                std::string content;
                std::string content_type;
                std::string filename;
                
                if (use_der) {
                    content = tls_ctx->export_ca_der();
                    content_type = "application/x-x509-ca-cert";
                    filename = "observathor_root_ca.der";
                } else {
                    content = tls_ctx->export_ca_pem();
                    content_type = "application/x-pem-file";
                    filename = "observathor_root_ca.pem";
                }
                
                if (!content.empty()) {
                    std::string response = "HTTP/1.1 200 OK\r\n";
                    response += "Content-Type: " + content_type + "\r\n";
                    response += "Content-Length: " + std::to_string(content.size()) + "\r\n";
                    response += "Content-Disposition: attachment; filename=\"" + filename + "\"\r\n";
                    response += "Connection: close\r\n\r\n";
                    response += content;
                    
                    sock->send_all(response);
                    bytesOut += response.size();
                } else {
                    const char* not_found = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
                    sock->send_all(not_found);
                    bytesOut += std::strlen(not_found);
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
                t.tlsMitmIntercepted = true;
                t.mitmOutcome = "certificate_served";
                dispatcher_ref.publish(t);
                return;
            }
#endif
            // If no TLS context, return error
            const char* error_msg = "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n";
            sock->send_all(error_msg);
            sock->close();
            return;
        }

        // Check if we should MITM this connection
        bool shouldIntercept = false;
        if (policy) {
            shouldIntercept = policy->should_intercept(host);
            printf("DEBUG: Policy check for %s: enabled=%d, shouldIntercept=%d\n", 
                   host.c_str(), policy->is_enabled(), shouldIntercept);
        } else {
            printf("DEBUG: No policy set!\n");
        }
        
        printf("DEBUG: host=%s, shouldIntercept=%d, tls_ctx=%p\n", host.c_str(), shouldIntercept, tls_ctx.get());
        if (is_pinned(host)) {
            printf("DEBUG: MITM skipped (pinned/untrusted host) for %s -> tunneling fallback\n", host.c_str());
            shouldIntercept = false; // force tunnel
        }
        
    if (shouldIntercept && tls_ctx) {
#ifdef OBSERVATHOR_HAVE_OPENSSL
            // Try MITM SSL interception - only if we can prepare everything
            printf("DEBUG: Attempting MITM for %s\n", host.c_str());
            if (can_attempt_mitm(host)) {
                printf("DEBUG: MITM preparation successful, starting interception\n");
                handle_ssl_mitm(host, port);
                return; // MITM attempted (success or failure handled internally)
            } else {
                printf("DEBUG: MITM preparation failed, falling back to tunneling\n");
            }
            // MITM preparation failed, fall back to tunneling
#else
        printf("DEBUG: MITM requested but OpenSSL not available, tunneling fallback.\n");
#endif
        } else {
            printf("DEBUG: MITM not attempted - shouldIntercept=%d, tls_ctx=%p\n", 
                   shouldIntercept, tls_ctx.get());
        }
        
    printf("DEBUG: TUNNEL: begin plain TCP tunnel host=%s port=%d\n", host.c_str(), port);
        // Plain tunnel
        auto upstream = net::UpstreamConnector::connect(host, port, 3000);
        if (upstream) {
            const char* established = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: Observathor\r\n\r\n";
            sock->send_all(established);
            bytesOut += std::strlen(established);
            printf("DEBUG: TUNNEL: upstream connected and 200 sent host=%s port=%d\n", host.c_str(), port);

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
                    if (ret < 0) {
                        printf("DEBUG: TUNNEL: select() error host=%s port=%d -> closing\n", host.c_str(), port);
                        break;
                    }
                    if ((now - lastActivity) > std::chrono::seconds(30)) {
                        printf("DEBUG: TUNNEL: idle timeout 30s host=%s port=%d\n", host.c_str(), port);
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
                        printf("DEBUG: TUNNEL: client closed (r=%d) host=%s port=%d\n", r, host.c_str(), port);
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
                        printf("DEBUG: TUNNEL: upstream closed (r=%d) host=%s port=%d\n", r, host.c_str(), port);
                        done = true;
                    } else {
                        sock->send_all(std::string_view(upstreamBuf.data(), (size_t)r));
                        bytesOut += (uint64_t)r;
                        lastActivity = std::chrono::steady_clock::now();
                    }
                }
            }
            printf("DEBUG: TUNNEL: end host=%s port=%d bytesIn=%llu bytesOut=%llu\n", host.c_str(), port, (unsigned long long)bytesIn, (unsigned long long)bytesOut);
        } else {
            const char* fail = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\nConnection: close\r\n\r\nBad";
            sock->send_all(fail);
            bytesOut += std::strlen(fail);
            printf("DEBUG: TUNNEL: upstream connect failed host=%s port=%d\n", host.c_str(), port);
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

#ifdef OBSERVATHOR_HAVE_OPENSSL
bool ClientSession::can_attempt_mitm(const std::string& host) {
    // Quick check if MITM is even possible
    if (!tls_ctx) return false;
    
    // Check if we can create leaf certificate
    auto leafCertKey = tls_ctx->get_or_create_leaf(host);
    return (leafCertKey.cert && leafCertKey.pkey);
}

void ClientSession::handle_ssl_mitm(const std::string& host, int port) {
    printf("DEBUG: Starting MITM handler for %s:%d\n", host.c_str(), port);
    static std::atomic<uint64_t> mitmId{1};
    // Track total decrypted traffic
    
    // Get or create leaf certificate for this hostname
    auto leafCertKey = tls_ctx->get_or_create_leaf(host);
    if (!leafCertKey.cert || !leafCertKey.pkey) {
        printf("DEBUG: MITM certificate generation failed for %s\n", host.c_str());
        // Send error and close connection
        const char* error_msg = "HTTP/1.1 503 Service Unavailable\r\nProxy-Agent: Observathor\r\nConnection: close\r\n\r\nSSL certificate generation failed";
        sock->send_all(error_msg);
        sock->close();
        return;
    }
    printf("DEBUG: MITM certificate ready for %s\n", host.c_str());
    
    // Connect to upstream server first
    auto upstream = net::UpstreamConnector::connect(host, port, 3000);
    if (!upstream) {
        printf("DEBUG: MITM upstream connection failed for %s:%d\n", host.c_str(), port);
        const char* error_msg = "HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: Observathor\r\nConnection: close\r\n\r\nUpstream connection failed";
        sock->send_all(error_msg);
        sock->close();
        return;
    }
    printf("DEBUG: MITM upstream connected to %s:%d\n", host.c_str(), port);
    
    // Establish upstream SSL connection
    SSL* upstreamSsl = SSL_new(tls_ctx->client_ssl_ctx());
    if (!upstreamSsl) {
        printf("DEBUG: MITM upstream SSL context creation failed for %s\n", host.c_str());
        sock->close();
        upstream->close();
        return;
    }
    
    SSL_set_fd(upstreamSsl, upstream->native());
    SSL_set_tlsext_host_name(upstreamSsl, host.c_str());
    
    int upstreamConnResult = SSL_connect(upstreamSsl);
    if (upstreamConnResult != 1) {
        int sslErr = SSL_get_error(upstreamSsl, upstreamConnResult);
        printf("DEBUG: MITM upstream SSL handshake failed for %s (ssl_err=%d)\n", host.c_str(), sslErr);
        unsigned long e;
        while ((e = ERR_get_error()) != 0) {
            char buf[256];
            ERR_error_string_n(e, buf, sizeof(buf));
            printf("DEBUG: OpenSSL upstream error: %s\n", buf);
        }
        SSL_free(upstreamSsl);
        sock->close();
        upstream->close();
        return;
    }
    printf("DEBUG: MITM upstream SSL connected to %s\n", host.c_str());
    
    // Create server SSL context with our leaf certificate
    SSL_CTX* serverCtx = SSL_CTX_new(TLS_server_method());
    if (!serverCtx) {
        printf("DEBUG: MITM server SSL context creation failed for %s\n", host.c_str());
        SSL_free(upstreamSsl);
        sock->close();
        upstream->close();
        return;
    }
    // Harden protocol versions: allow TLS1.2+ only
#ifdef TLS1_2_VERSION
    SSL_CTX_set_min_proto_version(serverCtx, TLS1_2_VERSION);
#endif
    // Attach root CA as chain (some clients prefer full chain even if already trusted)
    if (tls_ctx && tls_ctx->has_ca()) {
        // Duplicate CA cert so OpenSSL can own it in chain list
        X509* dup = X509_dup(tls_ctx->server_ssl_ctx_template() ? nullptr : nullptr); // placeholder to silence unused warning
        (void)dup; // (Not retrieving caCert_ directly since it's private; future refactor could expose)
    }
    // Set ALPN (http/1.1 + h2)
#ifdef OBSERVATHOR_HAVE_OPENSSL
    const unsigned char alpnProtos[] = { 2, 'h','2', 8, 'h','t','t','p','/','1','.','1' };
    SSL_CTX_set_alpn_select_cb(serverCtx, [](SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* /*arg*/) -> int {
        // Prefer h2 if offered
        unsigned int i = 0;
        while (i + 1 < inlen) { unsigned int l = in[i]; if (i + 1 + l > inlen) break; const unsigned char* proto = &in[i+1];
            if (l == 2 && proto[0]=='h' && proto[1]=='2') { *out = proto; *outlen = (unsigned char)l; return SSL_TLSEXT_ERR_OK; }
            i += 1 + l;
        }
        // Fallback http/1.1 if present
        i = 0; while (i + 1 < inlen) { unsigned int l = in[i]; if (i + 1 + l > inlen) break; const unsigned char* proto = &in[i+1];
            if (l == 8 && std::memcmp(proto, "http/1.1", 8)==0) { *out = proto; *outlen = (unsigned char)l; return SSL_TLSEXT_ERR_OK; }
            i += 1 + l; }
        return SSL_TLSEXT_ERR_NOACK; }, nullptr);
    // Offer both in ServerHello
    SSL_CTX_set_alpn_protos(serverCtx, alpnProtos, sizeof(alpnProtos));
#endif
    
    SSL_CTX_use_certificate(serverCtx, leafCertKey.cert);
    SSL_CTX_use_PrivateKey(serverCtx, leafCertKey.pkey);
    if (!SSL_CTX_check_private_key(serverCtx)) {
        printf("DEBUG: MITM serverCtx private key mismatch for %s\n", host.c_str());
    }
    
    // Create server SSL for client connection
    SSL* clientSsl = SSL_new(serverCtx);
    if (!clientSsl) {
        printf("DEBUG: MITM client SSL context creation failed for %s\n", host.c_str());
        SSL_CTX_free(serverCtx);
        SSL_free(upstreamSsl);
        sock->close();
        upstream->close();
        return;
    }
    
    // Send connection established to client BEFORE starting SSL handshake
    const char* established = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: Observathor\r\n\r\n";
    sock->send_all(established);
    uint64_t totalBytesIn = 0;
    uint64_t totalBytesOut = std::strlen(established);
    printf("DEBUG: MITM sent connection established to client for %s\n", host.c_str());
    
    SSL_set_fd(clientSsl, sock->native());
    
    // Non-blocking handshake loop with early-close classification
    {
        int attempts = 0;
        while (true) {
            int r = SSL_accept(clientSsl);
            if (r == 1) break; // success
            int err = SSL_get_error(clientSsl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (++attempts > 200) { // ~2s worst-case if we sleep 10ms
                    printf("DEBUG: MITM client SSL handshake timeout for %s after %d attempts\n", host.c_str(), attempts);
                    mark_pinned(host); // treat prolonged stall as pinning/untrusted
                    err = SSL_ERROR_SSL; // force failure path
                } else {
#ifdef _WIN32
                    Sleep(10);
#else
                    struct timespec ts{0,10*1000*1000}; nanosleep(&ts,nullptr);
#endif
                    continue; // retry
                }
            }
            if (r != 1) {
                long verifyRes = SSL_get_verify_result(clientSsl);
                printf("DEBUG: MITM client SSL handshake failed for %s (ssl_err=%d verify=%ld)\n", host.c_str(), err, verifyRes);
                bool earlyClose = false;
                unsigned long ecode; bool anyError=false;
                while ((ecode = ERR_get_error()) != 0) {
                    anyError=true; char buf[256];
                    ERR_error_string_n(ecode, buf, sizeof(buf));
                    printf("DEBUG: OpenSSL client error: %s\n", buf);
                    if (strstr(buf, "unexpected eof")!=nullptr) earlyClose = true;
                }
                if (!anyError) {
                    // No error from queue + failure usually means peer closed without ClientHello
                    earlyClose = true;
                }
                if (earlyClose) {
                    mark_pinned(host);
                    printf("DEBUG: MITM classification: early close -> pinned/untrusted for %s\n", host.c_str());
                }
                int shutdownState = SSL_get_shutdown(clientSsl);
                printf("DEBUG: MITM client SSL shutdown flags for %s = %d\n", host.c_str(), shutdownState);
                SSL_free(clientSsl);
                SSL_CTX_free(serverCtx);
                SSL_free(upstreamSsl);
                // Fallback to plain tunnel so the connection still works
                auto upstream2 = net::UpstreamConnector::connect(host, port, 3000);
                if (upstream2) {
                    const char* established2 = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: Observathor\r\n\r\n";
                    sock->send_all(established2);
                    // Relay raw bytes (no decryption)
                    std::vector<char> cbuf(16384), ubuf(16384);
                    while (true) {
                        fd_set rfds; FD_ZERO(&rfds);
                        SOCKET cfd = (SOCKET)sock->native(); SOCKET ufd = (SOCKET)upstream2->native();
                        FD_SET(cfd,&rfds); FD_SET(ufd,&rfds);
                        timeval tv{30,0}; int sel = select(0,&rfds,nullptr,nullptr,&tv);
                        if (sel<=0) break;
                        if (FD_ISSET(cfd,&rfds)) { int nr = ::recv(cfd,cbuf.data(),(int)cbuf.size(),0); if(nr<=0) break; upstream2->send_all(std::string_view(cbuf.data(),nr)); }
                        if (FD_ISSET(ufd,&rfds)) { int nr = ::recv(ufd,ubuf.data(),(int)ubuf.size(),0); if(nr<=0) break; sock->send_all(std::string_view(ubuf.data(),nr)); }
                    }
                    upstream2->close();
                }
                sock->close();
                return;
            }
        }
    }
    printf("DEBUG: MITM client SSL handshake successful for %s\n", host.c_str());
    const unsigned char* alpnPtr = nullptr; unsigned int alpnLen = 0;
    SSL_get0_alpn_selected(clientSsl, &alpnPtr, &alpnLen);
    std::string alpnStr = (alpnPtr && alpnLen>0)? std::string(reinterpret_cast<const char*>(alpnPtr), alpnLen) : std::string("(none)");
    printf("DEBUG: MITM negotiated alpn=%s cipher=%s version=%s for %s\n",
           alpnStr.c_str(), SSL_get_cipher(clientSsl), SSL_get_version(clientSsl), host.c_str());
    
    // Now we have encrypted tunnels on both sides - relay data and capture content
    std::vector<char> clientBuf(16384), upstreamBuf(16384);
    std::string requestData, responseData; // Captured data
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
        int maxfd = std::max(cfd, ufd);
        
        timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        int ret = select(maxfd + 1, &readfds, nullptr, nullptr, &tv);
#endif
        
        if (ret == 0) { // timeout
            auto now = std::chrono::steady_clock::now();
            if (now - lastActivity > std::chrono::seconds(30)) {
                done = true;
            }
            continue;
        } else if (ret < 0) {
            break; // error
        }
        
        lastActivity = std::chrono::steady_clock::now();
        
        // Client -> Server (request data)
        if (FD_ISSET(cfd, &readfds)) {
            int n = SSL_read(clientSsl, clientBuf.data(), static_cast<int>(clientBuf.size()));
            if (n > 0) {
                requestData.append(clientBuf.data(), n);
                totalBytesIn += n;
                int sent = SSL_write(upstreamSsl, clientBuf.data(), n);
                if (sent != n) {
                    done = true;
                }
            } else if (n <= 0) {
                int err = SSL_get_error(clientSsl, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    done = true;
                }
            }
        }
        
        // Server -> Client (response data)
        if (FD_ISSET(ufd, &readfds)) {
            int n = SSL_read(upstreamSsl, upstreamBuf.data(), static_cast<int>(upstreamBuf.size()));
            if (n > 0) {
                responseData.append(upstreamBuf.data(), n);
                totalBytesOut += n;
                int sent = SSL_write(clientSsl, upstreamBuf.data(), n);
                if (sent != n) {
                    done = true;
                }
            } else if (n <= 0) {
                int err = SSL_get_error(upstreamSsl, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    done = true;
                }
            }
        }
    }
    
    // Cleanup
    printf("DEBUG: MITM connection completed for %s, cleaning up\n", host.c_str());
    SSL_shutdown(clientSsl);
    SSL_shutdown(upstreamSsl);
    SSL_free(clientSsl);
    SSL_free(upstreamSsl);
    SSL_CTX_free(serverCtx);
    sock->close();
    upstream->close();
    
    // Create transaction with decrypted data
    Transaction t{};
    t.id = mitmId.fetch_add(1, std::memory_order_relaxed);
    t.startTime = start_time;
    t.wallTime = std::chrono::system_clock::now();
    t.bytesIn = totalBytesIn;
    t.bytesOut = totalBytesOut;
    t.tlsMitmIntercepted = true;
    
    // Parse HTTP from captured data
    if (!requestData.empty()) {
        auto req_end = requestData.find("\r\n\r\n");
        if (req_end != std::string::npos) {
            std::string headers = requestData.substr(0, req_end);
            auto first_line_end = headers.find("\r\n");
            if (first_line_end != std::string::npos) {
                t.requestLine = headers.substr(0, first_line_end);
                t.requestHeaders = headers.substr(first_line_end + 2);
            }
            t.requestBody = requestData.substr(req_end + 4);
        }
    }
    
    if (!responseData.empty()) {
        auto resp_end = responseData.find("\r\n\r\n");
        if (resp_end != std::string::npos) {
            std::string headers = responseData.substr(0, resp_end);
            auto first_line_end = headers.find("\r\n");
            if (first_line_end != std::string::npos) {
                t.responseStatusLine = headers.substr(0, first_line_end);
                t.responseHeaders = headers.substr(first_line_end + 2);
            }
            t.responseBody = responseData.substr(resp_end + 4);
        }
    }
    
    printf("DEBUG: MITM publishing transaction for %s with %llu bytes in, %llu bytes out\n", 
           host.c_str(), totalBytesIn, totalBytesOut);
    dispatcher_ref.publish(t);
}

// blacklist_host_for_mitm removed – no adaptive suppression implemented now
#endif

} // namespace observathor::core::proxy
