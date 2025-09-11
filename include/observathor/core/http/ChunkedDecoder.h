#pragma once
#include <string>
#include <string_view>
#include <cstddef>
#include <optional>

namespace observathor::core::http {

// Incremental HTTP/1.1 chunked transfer decoder.
// Feed raw bytes via feed(); collect decoded body via take_decoded().
// When finished() becomes true, all chunks (including terminating 0) processed.
class ChunkedDecoder {
public:
    enum class State { SizeLine, Data, CRLF, Done, Error };

    // Feed data; returns number of bytes consumed from input.
    size_t feed(const char* data, size_t len);

    bool finished() const { return state_ == State::Done; }
    bool error() const { return state_ == State::Error; }

    // Extract decoded bytes accumulated so far (clears internal buffer returned).
    std::string take_decoded();

    // Internal state (for tests/inspection)
    State state() const { return state_; }
    size_t remaining_in_chunk() const { return remaining_; }

private:
    State state_ = State::SizeLine;
    std::string sizeLine_;
    size_t remaining_ = 0;
    std::string decoded_;
};

}
