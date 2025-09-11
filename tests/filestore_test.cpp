#include "observathor/core/proxy/TransactionFileStore.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include <cassert>
#include <fstream>
#include <string>

using namespace observathor::core::proxy;
int main(){
    TransactionDispatcher d;
    auto store = make_file_store(d, "filestore_test_output.ndjson");
    Transaction t{}; t.requestLine="GET /abc HTTP/1.1"; t.bytesIn=1; t.bytesOut=2; t.responseStatusLine="HTTP/1.1 200 OK"; t.responseBody="Hi";
    d.publish(t);
    store.reset();
    std::ifstream ifs("filestore_test_output.ndjson");
    std::string line; std::getline(ifs,line);
    assert(line.find("GET /abc HTTP/1.1")!=std::string::npos);
    return 0;
}
