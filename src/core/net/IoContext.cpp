#include "observathor/core/net/IoContext.h"

namespace observathor::core::net {
IoContext::IoContext() = default;
IoContext::~IoContext() { stop(); }

void IoContext::post(Task task) {
    {
        std::lock_guard lock(guard);
        tasks.push(std::move(task));
    }
    cv.notify_one();
}

void IoContext::run() {
    while (running.load()) {
        Task task;
        {
            std::unique_lock lock(guard);
            cv.wait(lock, [&]{ return !running.load() || !tasks.empty(); });
            if (!running.load() && tasks.empty()) return;
            task = std::move(tasks.front());
            tasks.pop();
        }
        if (task) task();
    }
}

void IoContext::poll() {
    for(;;) {
        Task task;
        {
            std::lock_guard lock(guard);
            if (tasks.empty()) break;
            task = std::move(tasks.front());
            tasks.pop();
        }
        if (task) task();
    }
}

void IoContext::stop() {
    running.store(false);
    cv.notify_all();
}
}
