#include "observathor/core/http/ChunkedDecoder.h"
#include <cassert>
#include <string>
using namespace observathor::core::http;

int main(){
    // Happy path single feed
    {
        ChunkedDecoder dec;
        std::string in = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        size_t used = dec.feed(in.data(), in.size());
        assert(dec.finished());
        auto body = dec.take_decoded();
        assert(body == "Wikipedia");
        // Used should be at least up to the end of chunks
        assert(used >= 22);
    }
    
    // Split boundaries  
    {
        ChunkedDecoder dec;
        std::string in1 = "4\r\nWi";
        std::string in2 = "ki\r\n";
        std::string in3 = "5\r\nped";
        std::string in4 = "ia\r\n0\r\n\r\n";
        dec.feed(in1.data(), in1.size());
        dec.feed(in2.data(), in2.size());
        dec.feed(in3.data(), in3.size());
        dec.feed(in4.data(), in4.size());
        assert(dec.finished());
        auto body = dec.take_decoded();
        assert(body == "Wikipedia");
    }
    
    // With extension
    {
        ChunkedDecoder dec;
        std::string in = "A;foo=bar\r\nHelloWorld\r\n0\r\n\r\n";
        dec.feed(in.data(), in.size());
        assert(dec.finished());
        auto body = dec.take_decoded();
        assert(body == "HelloWorld");
    }
    
    // Invalid hex -> error
    {
        ChunkedDecoder dec;
        std::string in = "Q\r\n";
        dec.feed(in.data(), in.size());
        assert(dec.error());
    }
    
    // Zero chunk immediate termination
    {
        ChunkedDecoder dec;
        std::string in = "0\r\n\r\n";
        dec.feed(in.data(), in.size());
        assert(dec.finished());
        auto body = dec.take_decoded();
        assert(body.empty());
    }
    
    return 0;
}
