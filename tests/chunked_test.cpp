#include "observathor/core/proxy/TransactionDispatcher.h"
#include "observathor/core/proxy/TransactionMemoryStore.h"
#include <cassert>
using namespace observathor::core::proxy;
int main(){
    TransactionDispatcher d; auto mem = make_memory_store(d);
    Transaction t{}; t.requestLine="GET /c HTTP/1.1"; t.bytesIn=10; t.bytesOut=20; t.requestWasChunked=true; t.responseWasChunked=true; t.responseBody="decoded";
    d.publish(t);
    auto snap = mem->snapshot();
    assert(snap.size()==1); assert(snap[0].responseWasChunked); assert(snap[0].requestWasChunked); assert(snap[0].responseBody=="decoded");
    return 0;
}