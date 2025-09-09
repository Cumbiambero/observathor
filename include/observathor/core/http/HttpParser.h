#pragma once
#include <string>
#include <string_view>
#include <optional>
#include <vector>
#include <utility>

namespace observathor::core::http {
struct HttpHeader { std::string name; std::string value; };
struct HttpRequestLine { std::string method; std::string target; std::string version; };
struct HttpRequest { HttpRequestLine request_line; std::vector<HttpHeader> headers; };
class HttpParser {
public:
    std::optional<HttpRequestLine> parse_request_line(std::string_view line);
    std::optional<HttpRequest> parse_request(std::string_view data);
};
}
