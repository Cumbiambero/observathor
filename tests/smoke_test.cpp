#include "observathor/core/http/HttpParser.h"
#include "observathor/core/http/HostUtil.h"
#include <cassert>
#include <string>

using namespace observathor::core::http;

int main() {
    HttpParser p;
    auto rl = p.parse_request_line("GET /index.html HTTP/1.1");
    assert(rl.has_value());
    assert(rl->method == "GET");
    assert(rl->target == "/index.html");
    assert(rl->version == "HTTP/1.1");

    std::string full = "GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: X\r\n\r\n";
    auto req = p.parse_request(full);
    assert(req.has_value());
    auto host_target = extract_host_target(*req);
    assert(host_target.has_value());
    assert(host_target->host == "example.com");
    assert(host_target->port == 80);
    assert(host_target->path == "/path");

    std::string abs_req = "GET http://example.net/abc?q=1 HTTP/1.1\r\nHost: example.net\r\n\r\n";
    auto req2 = p.parse_request(abs_req);
    assert(req2.has_value());
    auto host_target2 = extract_host_target(*req2);
    assert(host_target2.has_value());
    assert(host_target2->host == "example.net");
    assert(host_target2->path == "/abc?q=1");

    std::string host_port_req = "GET /x HTTP/1.1\r\nHost: example.org:8080\r\n\r\n";
    auto req3 = p.parse_request(host_port_req);
    assert(req3.has_value());
    auto host_target3 = extract_host_target(*req3);
    assert(host_target3.has_value());
    assert(host_target3->host == "example.org");
    assert(host_target3->port == 8080);
    assert(host_target3->path == "/x");

    return 0;
}
