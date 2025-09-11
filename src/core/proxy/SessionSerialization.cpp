#include "observathor/core/proxy/SessionSerialization.h"
#include <sstream>
#include <cctype>

namespace observathor::core::proxy {
static const char* B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string b64enc(const std::string& in){ std::string out; out.reserve((in.size()*4)/3+4); size_t i=0; unsigned val=0; int valb=-6; for(unsigned char c: in){ val=(val<<8)+c; valb+=8; while(valb>=0){ out.push_back(B64[(val>>valb)&0x3F]); valb-=6; }} while(valb>-6){ out.push_back(B64[((val<<8)>>(valb+8))&0x3F]); valb-=6;} while(out.size()%4) out.push_back('='); return out; }
static std::string esc(const std::string& s){ std::string o; o.reserve(s.size()+8); for(char c: s){ switch(c){ case '"': o+="\\\""; break; case '\\': o+="\\\\"; break; case '\n': o+="\\n"; break; case '\r': o+="\\r"; break; case '\t': o+="\\t"; break; default: if((unsigned char)c<0x20){ char buf[7]; std::snprintf(buf,sizeof(buf),"\\u%04x", (unsigned char)c); o+=buf; } else o+=c; }} return o; }

std::string export_transactions_json(const std::vector<Transaction>& txs, const SessionExportOptions& opt){
    std::ostringstream oss; oss << "["; bool first=true; for(const auto& t: txs){ if(!first) oss << ","; first=false; oss << "{\"id\":" << t.id; oss << ",\"request_line\":\"" << esc(t.requestLine) << "\""; if(!t.requestHeaders.empty()) oss<<",\"req_headers\":\""<<esc(t.requestHeaders)<<"\""; if(!t.responseStatusLine.empty()) oss<<",\"resp_status\":\""<<esc(t.responseStatusLine)<<"\""; if(!t.responseHeaders.empty()) oss<<",\"resp_headers\":\""<<esc(t.responseHeaders)<<"\""; if(opt.includeBodiesBase64 && !t.requestBody.empty()) oss<<",\"req_body_b64\":\""<<b64enc(t.requestBody)<<"\""; if(opt.includeBodiesBase64 && !t.responseBody.empty()) oss<<",\"resp_body_b64\":\""<<b64enc(t.responseBody)<<"\""; oss << "}"; } oss << "]"; return oss.str(); }

// Minimal, lenient JSON array parser for our constrained format.
std::optional<std::vector<Transaction>> import_transactions_json(const std::string& json){
    std::vector<Transaction> out; size_t i=0; auto skip_ws=[&]{ while(i<json.size() && std::isspace((unsigned char)json[i])) ++i; };
    skip_ws(); if(i>=json.size() || json[i] != '[') return std::nullopt; ++i; skip_ws(); if(i<json.size() && json[i]==']'){ return out; }
    while(i<json.size()){
        skip_ws(); if(i>=json.size()||json[i]!='{') return std::nullopt; ++i; Transaction t{}; bool done=false; while(!done){ skip_ws(); if(i>=json.size()) return std::nullopt; if(json[i]=='}'){ ++i; done=true; break; } if(json[i] != '"') return std::nullopt; size_t kstart=++i; while(i<json.size() && json[i] != '"') ++i; if(i>=json.size()) return std::nullopt; std::string key = json.substr(kstart, i-kstart); ++i; skip_ws(); if(i>=json.size()||json[i] != ':') return std::nullopt; ++i; skip_ws(); if(i>=json.size()) return std::nullopt; if(json[i]=='"'){ size_t vstart=++i; while(i<json.size() && json[i] != '"') ++i; if(i>=json.size()) return std::nullopt; std::string val = json.substr(vstart, i-vstart); ++i; if(key=="request_line") t.requestLine=val; else if(key=="req_headers") t.requestHeaders=val; else if(key=="resp_status") t.responseStatusLine=val; else if(key=="resp_headers") t.responseHeaders=val; /* bodies omitted decode for brevity */ }
            else { size_t vstart=i; while(i<json.size() && (std::isdigit((unsigned char)json[i])||json[i]=='+'||json[i]=='-')) ++i; std::string num=json.substr(vstart,i-vstart); if(key=="id") t.id=std::strtoull(num.c_str(),nullptr,10); }
            skip_ws(); if(i<json.size() && json[i]==','){ ++i; continue; }
        }
        out.push_back(std::move(t)); skip_ws(); if(i<json.size() && json[i]==','){ ++i; continue; } else break; }
    skip_ws(); if(i>=json.size() || json[i] != ']') return std::nullopt; return out; }
}
