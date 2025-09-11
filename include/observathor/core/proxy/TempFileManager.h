#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <cstdio>
#include <filesystem>

namespace observathor::core::proxy {
class TempFileManager {
public:
    static TempFileManager& instance(){ static TempFileManager i; return i; }
    std::string createFile(const char* prefix){
        std::lock_guard<std::mutex> lk(mu);
        auto dir = std::filesystem::temp_directory_path();
        std::string name;
        for(int tries=0; tries<5; ++tries){
            name = dir.string() + "/" + prefix + std::to_string(counter++) + ".tmp";
            FILE* f = std::fopen(name.c_str(), "wb");
            if(f){ std::fclose(f); files.push_back(name); return name; }
        }
        return {};
    }
    void removeFile(const std::string& path){
        std::lock_guard<std::mutex> lk(mu);
        std::filesystem::remove(path);
    }
    void purgeAll(){
        std::lock_guard<std::mutex> lk(mu);
        for(auto & p: files) std::filesystem::remove(p);
        files.clear();
    }
private:
    TempFileManager() = default;
    ~TempFileManager(){ purgeAll(); }
    std::mutex mu;
    std::vector<std::string> files;
    unsigned long long counter{0};
};
}
