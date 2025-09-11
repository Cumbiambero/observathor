#include "observathor/core/proxy/TransactionMemoryStore.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include <cassert>
using namespace observathor::core::proxy;
int main(){
    TransactionDispatcher d;
    auto store = make_memory_store(d);
    Transaction t{}; t.requestLine = "GET / HTTP/1.1"; t.bytesIn=10; t.bytesOut=20; t.requestHeaders="Host: x\r\n"; t.responseStatusLine="HTTP/1.1 200 OK"; t.responseBody="Hello";
    d.publish(t);
    auto snap = store->snapshot();
    assert(snap.size()==1);
    assert(snap[0].responseBody=="Hello");
    return 0;
}
