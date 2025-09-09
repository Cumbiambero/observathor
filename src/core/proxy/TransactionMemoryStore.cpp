#include "observathor/core/proxy/TransactionMemoryStore.h"
#include "observathor/core/proxy/TransactionDispatcher.h"
namespace observathor::core::proxy {
std::shared_ptr<TransactionMemoryStore> make_memory_store(TransactionDispatcher& d) {
    auto ptr = std::make_shared<TransactionMemoryStore>();
    d.add(ptr);
    return ptr;
}
}
