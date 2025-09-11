#include "observathor/core/http/ChunkedDecoder.h"
#include <algorithm>

using namespace observathor::core::http;

static bool hex_to_size(const std::string& line, size_t& out){
    size_t v = 0; bool any=false; for(char c: line){ if(c==';') break; if(c=='\r'||c=='\n') break; int d=-1; if(c>='0'&&c<='9') d=c-'0'; else if(c>='a'&&c<='f') d=10+(c-'a'); else if(c>='A'&&c<='F') d=10+(c-'A'); else return false; v=(v<<4)|(unsigned)d; any=true; }
    if(!any) return false; out=v; return true;
}

size_t ChunkedDecoder::feed(const char* data, size_t len){
    size_t off=0; while(off < len && state_ != State::Done && state_ != State::Error){
        switch(state_){
            case State::SizeLine:{
                char c = data[off++]; sizeLine_.push_back(c);
                if(sizeLine_.size()>=2 && sizeLine_[sizeLine_.size()-2]=='\r' && sizeLine_.back()=='\n'){
                    std::string core = sizeLine_.substr(0,sizeLine_.size()-2); sizeLine_.clear(); size_t sz=0; if(!hex_to_size(core, sz)){ state_=State::Error; break; }
                    if(sz==0){ state_=State::Done; break; }
                    remaining_=sz; state_=State::Data;
                }
                break; }
            case State::Data:{
                size_t avail = len - off; size_t take = std::min(avail, remaining_);
                decoded_.append(data+off, take); off += take; remaining_ -= take; if(remaining_==0) state_=State::CRLF; break; }
            case State::CRLF:{
                if(len-off < 2) { off=len; break; } // need more data next call
                if(data[off]=='\r' && data[off+1]=='\n'){ off+=2; state_=State::SizeLine; }
                else { state_=State::Error; }
                break; }
            case State::Done: case State::Error: break;
        }
    }
    return off;
}

std::string ChunkedDecoder::take_decoded(){
    std::string out; out.swap(decoded_); return out;
}
