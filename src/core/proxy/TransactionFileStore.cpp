#include "observathor/core/proxy/TransactionFileStore.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include <chrono>
#include <vector>

namespace observathor::core::proxy {
static const char* B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string TransactionFileStore::b64(const std::string& in) {
    std::string out; out.reserve((in.size()*4)/3+4);
    size_t i=0; unsigned val=0; int valb=-6; for(unsigned char c: in){ val=(val<<8)+c; valb+=8; while(valb>=0){ out.push_back(B64[(val>>valb)&0x3F]); valb-=6; }} while(valb>-6){ out.push_back(B64[((val<<8)>>(valb+8))&0x3F]); valb-=6;} while(out.size()%4) out.push_back('='); return out; }
std::string TransactionFileStore::escape_json(const std::string& in){ std::string o; o.reserve(in.size()+8); for(char c: in){ switch(c){ case '"': o+="\\\""; break; case '\\': o+="\\\\"; break; case '\n': o+="\\n"; break; case '\r': o+="\\r"; break; case '\t': o+="\\t"; break; default: if((unsigned char)c<0x20){ char buf[7]; std::snprintf(buf,sizeof(buf),"\\u%04x", (unsigned char)c); o+=buf; } else o+=c; }} return o; }

TransactionFileStore::TransactionFileStore(std::string path) : ofs(path, std::ios::app | std::ios::out) {}
void TransactionFileStore::on_transaction(const Transaction& t) {
    if(!ofs.is_open()) return;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.start_time.time_since_epoch()).count();
    std::lock_guard lock(mu);
    ofs << "{\"ts\":" << ms
        << ",\"request_line\":\"" << escape_json(t.request_line) << "\""
        << ",\"bytes_in\":" << t.bytes_in
        << ",\"bytes_out\":" << t.bytes_out;
    if(!t.request_headers.empty()) ofs << ",\"req_headers\":\"" << escape_json(t.request_headers) << "\"";
    if(!t.request_body.empty()) ofs << ",\"req_body_b64\":\"" << b64(t.request_body) << "\"";
    if(!t.response_status_line.empty()) ofs << ",\"resp_status\":\"" << escape_json(t.response_status_line) << "\"";
    if(!t.response_headers.empty()) ofs << ",\"resp_headers\":\"" << escape_json(t.response_headers) << "\"";
    if(!t.response_body.empty()) ofs << ",\"resp_body_b64\":\"" << b64(t.response_body) << "\"";
    ofs << "}" << '\n';
    ofs.flush();
}
std::shared_ptr<TransactionFileStore> make_file_store(TransactionDispatcher& d, const std::string& path) {
    auto ptr = std::make_shared<TransactionFileStore>(path);
    d.add(ptr);
    return ptr;
}
}
