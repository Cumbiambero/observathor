#include "observathor/core/http/HttpParser.h"
#include <string_view>

namespace observathor::core::http {
std::optional<HttpRequestLine> HttpParser::parse_request_line(std::string_view line) {
    auto first_space = line.find(' ');
    if (first_space == std::string_view::npos) return std::nullopt;
    auto second_space = line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) return std::nullopt;
    HttpRequestLine rl;
    rl.method = std::string(line.substr(0, first_space));
    rl.target = std::string(line.substr(first_space + 1, second_space - first_space - 1));
    rl.version = std::string(line.substr(second_space + 1));
    return rl;
}
std::optional<HttpRequest> HttpParser::parse_request(std::string_view data) {
    auto end_headers = data.find("\r\n\r\n");
    if (end_headers == std::string_view::npos) return std::nullopt;
    std::string_view head = data.substr(0, end_headers);
    auto first_eol = head.find("\r\n");
    if (first_eol == std::string_view::npos) return std::nullopt;
    auto rl_opt = parse_request_line(head.substr(0, first_eol));
    if (!rl_opt) return std::nullopt;
    HttpRequest req; req.request_line = *rl_opt;
    size_t pos = first_eol + 2;
    while (pos < head.size()) {
        auto next = head.find("\r\n", pos);
        if (next == std::string_view::npos) break;
        auto line = head.substr(pos, next - pos);
        if (line.empty()) break;
        auto colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string name(line.substr(0, colon));
            size_t value_start = colon + 1;
            while (value_start < line.size() && (line[value_start] == ' ' || line[value_start] == '\t')) value_start++;
            std::string value(line.substr(value_start));
            req.headers.push_back(HttpHeader{ std::move(name), std::move(value) });
        }
        pos = next + 2;
    }
    // capture final header line if not terminated by CRLF inside head
    if (pos < head.size()) {
        auto line = head.substr(pos);
        if (!line.empty()) {
            auto colon = line.find(':');
            if (colon != std::string_view::npos) {
                std::string name(line.substr(0, colon));
                size_t value_start = colon + 1;
                while (value_start < line.size() && (line[value_start] == ' ' || line[value_start] == '\t')) value_start++;
                std::string value(line.substr(value_start));
                req.headers.push_back(HttpHeader{ std::move(name), std::move(value) });
            }
        }
    }
    return req;
}
}
