#pragma once
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace observathor::core::net {
class IoContext {
public:
    using Task = std::function<void()>;

    IoContext();
    ~IoContext();

    void post(Task task);
    void run();
    void stop();
    void poll();

private:
    std::atomic<bool> running{true};
    std::mutex guard;
    std::condition_variable cv;
    std::queue<Task> tasks;
};
}
