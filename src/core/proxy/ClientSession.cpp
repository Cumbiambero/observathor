#include "observathor/core/proxy/ClientSession.h"
#include "observathor/core/proxy/Transaction.h"
#include "observathor/core/http/HostUtil.h"
#include "observathor/core/net/UpstreamConnector.h"
#include <string>
#include <atomic>

namespace observathor::core::proxy {
ClientSession::ClientSession(std::shared_ptr<net::Socket> socket, TransactionDispatcher& dispatcher, std::size_t capture_limit)
    : sock(std::move(socket)), dispatcher_ref(dispatcher), buffer(4096), start_time(std::chrono::steady_clock::now()), capture_bytes_limit(capture_limit) {}

void ClientSession::start() { process(); }

void ClientSession::process() {
    static std::atomic<uint64_t> next_id{1};
    auto got = sock->recv_some(buffer);
    if (!got || *got <= 0) { sock->close(); return; }
    std::string_view data(buffer.data(), static_cast<size_t>(*got));
    auto req_opt = parser.parse_request(data);
    std::string req_line;
    std::string captured_req_headers;
    std::string captured_req_body; // bodies currently not parsed beyond headers (future extension)
    if (req_opt) {
        const auto& rl = req_opt->request_line;
        req_line = rl.method + " " + rl.target + " " + rl.version;
    } else {
        auto eol = data.find('\n');
        if (eol != std::string_view::npos) req_line.assign(data.substr(0, eol)); else req_line.assign(data);
    }
    uint64_t in_bytes = static_cast<uint64_t>(*got);

    std::string response;
    std::string response_status_line;
    std::string response_headers;
    std::string response_body;
    uint64_t out_bytes = 0;

    if (req_opt) {
        auto host_target = http::extract_host_target(*req_opt);
        if (host_target) {
            auto upstream = net::UpstreamConnector::connect(host_target->host, host_target->port, 2000);
            if (upstream) {
                std::string first_line = req_opt->request_line.method + " " + host_target->path + " " + req_opt->request_line.version + "\r\n";
                std::string headers_block;
                for (auto& h : req_opt->headers) {
                    headers_block += h.name;
                    headers_block += ": ";
                    headers_block += h.value;
                    headers_block += "\r\n";
                }
                headers_block += "\r\n";
                upstream->send_all(first_line + headers_block);
                std::vector<char> upstream_buf(8192);
                auto r = upstream->recv_some(upstream_buf);
                if (r && *r > 0) {
                    response.assign(upstream_buf.data(), static_cast<size_t>(*r));
                    if (capture_bytes_limit) {
                        // very naive split status line + headers + body
                        auto hdr_end = response.find("\r\n\r\n");
                        if (hdr_end != std::string::npos) {
                            auto first_eol = response.find("\r\n");
                            if (first_eol != std::string::npos) {
                                response_status_line = response.substr(0, first_eol);
                                response_headers = response.substr(first_eol + 2, hdr_end - (first_eol + 2));
                                response_body = response.substr(hdr_end + 4);
                            }
                        }
                        if (response_body.size() > capture_bytes_limit) response_body.resize(capture_bytes_limit);
                    }
                } else {
                    response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
                }
            } else {
                response = "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 7\r\nConnection: close\r\n\r\nTimeout";
            }
        } else {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\nConnection: close\r\n\r\nBad";
        }
    } else {
        response = "HTTP/1.1 200 Observathor\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
    }

    sock->send_all(response);
    out_bytes = static_cast<uint64_t>(response.size());
    sock->close();
    if (capture_bytes_limit && req_opt) {
        // reconstruct request headers block for capture
        std::string headers_block;
        for (auto& h : req_opt->headers) {
            headers_block += h.name;
            headers_block += ": ";
            headers_block += h.value;
            headers_block += "\r\n";
        }
        captured_req_headers = std::move(headers_block);
        if (captured_req_headers.size() > capture_bytes_limit) captured_req_headers.resize(capture_bytes_limit);
    }

    Transaction t{ };
    t.id = next_id.fetch_add(1, std::memory_order_relaxed);
    t.start_time = start_time;
    t.request_line = std::move(req_line);
    t.bytes_in = in_bytes;
    t.bytes_out = out_bytes;
    t.request_headers = std::move(captured_req_headers);
    t.request_body = std::move(captured_req_body);
    t.response_status_line = std::move(response_status_line);
    t.response_headers = std::move(response_headers);
    t.response_body = std::move(response_body);
    dispatcher_ref.publish(t);
}
}
