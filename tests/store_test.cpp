#include "observathor/core/proxy/TransactionMemoryStore.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
#include <cassert>
using namespace observathor::core::proxy;
int main(){
    TransactionDispatcher d;
    auto store = make_memory_store(d);
    Transaction t{}; t.request_line = "GET / HTTP/1.1"; t.bytes_in=10; t.bytes_out=20; t.request_headers="Host: x\r\n"; t.response_status_line="HTTP/1.1 200 OK"; t.response_body="Hello";
    d.publish(t);
    auto snap = store->snapshot();
    assert(snap.size()==1);
    assert(snap[0].response_body=="Hello");
    return 0;
}
