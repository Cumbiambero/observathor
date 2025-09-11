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
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.startTime.time_since_epoch()).count();
    std::lock_guard lock(mu);
    auto wall = std::chrono::system_clock::to_time_t(t.wallTime);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &wall);
#else
    localtime_r(&wall, &tm);
#endif
    char iso[64]; std::snprintf(iso, sizeof(iso), "%04d-%02d-%02dT%02d:%02d:%02d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    ofs << "{\"ts\":" << ms
        << ",\"request_line\":\"" << escape_json(t.requestLine) << "\""
        << ",\"wall_time_iso\":\"" << iso << "\""
        << ",\"bytes_in\":" << t.bytesIn
        << ",\"bytes_out\":" << t.bytesOut;
    if(!t.requestHeaders.empty()) ofs << ",\"req_headers\":\"" << escape_json(t.requestHeaders) << "\"";
    if(!t.requestBody.empty()) ofs << ",\"req_body_b64\":\"" << b64(t.requestBody) << "\"";
    if(t.requestBodyInFile) ofs << ",\"req_body_path\":\"" << escape_json(t.requestBodyPath) << "\"";
    if(t.requestWasChunked) ofs << ",\"req_chunked\":true";
    if(!t.responseStatusLine.empty()) ofs << ",\"resp_status\":\"" << escape_json(t.responseStatusLine) << "\"";
    if(!t.responseHeaders.empty()) ofs << ",\"resp_headers\":\"" << escape_json(t.responseHeaders) << "\"";
    if(!t.responseBody.empty()) ofs << ",\"resp_body_b64\":\"" << b64(t.responseBody) << "\"";
    if(t.responseBodyInFile) ofs << ",\"resp_body_path\":\"" << escape_json(t.responseBodyPath) << "\"";
    if(t.responseWasChunked) ofs << ",\"resp_chunked\":true";
    if(t.tlsMitmIntercepted) ofs << ",\"tls_mitm\":true";
    ofs << "}" << '\n';
    ofs.flush();
}
std::shared_ptr<TransactionFileStore> make_file_store(TransactionDispatcher& d, const std::string& path) {
    auto ptr = std::make_shared<TransactionFileStore>(path);
    d.add(ptr);
    return ptr;
}
}
