#pragma once
#include <string>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include "TempFileManager.h"

namespace observathor::core::proxy {
class BodyCapture {
public:
    BodyCapture(std::size_t spillThreshold, std::size_t hardLimit, std::size_t& globalMem, std::size_t globalBudget)
        : spillThreshold(spillThreshold), hardLimit(hardLimit), globalMemRef(globalMem), globalBudget(globalBudget) {}
    void append(const char* data, std::size_t n){
        if(n==0) return;
        if(fileMode){ writeFile(data,n); return; }
        if(buffer.size() + n > hardLimit){ ensureFile(); writeFile(data,n); return; }
        if(buffer.size() + n > spillThreshold || globalMemRef + n > globalBudget){ ensureFile(); writeFile(data,n); return; }
        buffer.append(data,n); globalMemRef += n; }
    const std::string& inMemory() const { return buffer; }
    bool isFile() const { return fileMode; }
    const std::string& path() const { return filePath; }
    std::size_t size() const { return fileMode ? fileSize : buffer.size(); }
private:
    void ensureFile(){ if(fileMode) return; filePath = TempFileManager::instance().createFile("obst"); FILE* f = std::fopen(filePath.c_str(), "ab"); if(!f) { fileMode=true; return; } if(!buffer.empty()) { std::fwrite(buffer.data(),1,buffer.size(),f); buffer.clear(); } std::fclose(f); fileMode=true; }
    void writeFile(const char* data, std::size_t n){ FILE* f = std::fopen(filePath.c_str(), "ab"); if(!f) return; std::fwrite(data,1,n,f); std::fclose(f); fileSize += n; }
    std::string buffer; bool fileMode=false; std::string filePath; std::size_t fileSize{0};
    std::size_t spillThreshold; std::size_t hardLimit; std::size_t& globalMemRef; std::size_t globalBudget; };
}
