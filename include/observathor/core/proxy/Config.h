#pragma once
#include <cstddef>
namespace observathor::core::proxy {
struct Config {
    std::size_t capture_bytes_limit { 0 }; // 0 means disabled
    const char* capture_file_path { nullptr }; // if set, write NDJSON lines
};
}
