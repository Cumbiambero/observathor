#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <mutex>

namespace observathor::core::proxy {
// Simple runtime policy container for MITM enable toggle and host allow/deny lists.
class MitmPolicy {
public:
    void set_enabled(bool v){ enabled.store(v, std::memory_order_relaxed); }
    bool is_enabled() const { return enabled.load(std::memory_order_relaxed); }
    void set_lists(std::vector<std::string> allow, std::vector<std::string> deny){ std::lock_guard<std::mutex> lk(mu); allow_list = std::move(allow); deny_list = std::move(deny); }
    bool should_intercept(const std::string& host) const {
        if(!is_enabled()) return false;
        std::lock_guard<std::mutex> lk(mu);
        // if deny matches -> false
        for(auto &p: deny_list){ if(glob_match(p, host)) return false; }
        // if allow list empty -> allowed
        if(allow_list.empty()) return true;
        for(auto &p: allow_list){ if(glob_match(p, host)) return true; }
        return false;
    }
    static bool glob_match(const std::string& pat, const std::string& text){
        // Very small glob: '*' matches any sequence, '?' matches single char, case-insensitive
        return glob_match_ci(pat.c_str(), 0, pat.size(), text.c_str(), 0, text.size());
    }
private:
    static char lower(char c){ return (c>='A'&&c<='Z')? char(c-'A'+'a'):c; }
    static bool glob_match_ci(const char* p, size_t pi, size_t pn, const char* t, size_t ti, size_t tn){
        while(true){
            if(pi==pn) return ti==tn;
            char pc = p[pi];
            if(pc=='*'){
                // collapse consecutive '*'
                while(pi<pn && p[pi]=='*') ++pi;
                if(pi==pn) return true; // trailing * matches rest
                for(size_t skip=0; ti+skip<=tn; ++skip){ if(glob_match_ci(p, pi, pn, t, ti+skip, tn)) return true; }
                return false;
            } else if(pc=='?') {
                if(ti==tn) return false; ++pi; ++ti; continue;
            } else {
                if(ti==tn) return false; if(lower(pc)!=lower(t[ti])) return false; ++pi; ++ti; continue;
            }
        }
    }
    std::atomic<bool> enabled { true };
    mutable std::mutex mu;
    std::vector<std::string> allow_list;
    std::vector<std::string> deny_list;
};
}
