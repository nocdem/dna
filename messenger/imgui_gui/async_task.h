#ifndef ASYNC_TASK_H
#define ASYNC_TASK_H

#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include <string>
#include <mutex>

// Reusable async task runner for background operations
class AsyncTask {
public:
    AsyncTask() : running(false), completed(false) {}
    
    ~AsyncTask() {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    // Start async task with callback
    void start(std::function<void(AsyncTask*)> task_func) {
        if (running) return;
        
        // Join previous thread if it exists
        if (worker.joinable()) {
            worker.join();
        }
        
        running = true;
        completed = false;
        status_messages.clear();
        
        worker = std::thread([this, task_func]() {
            task_func(this);
            completed = true;
            running = false;
        });
    }
    
    // Add status message (thread-safe)
    void addMessage(const std::string& msg) {
        std::lock_guard<std::mutex> lock(msg_mutex);
        status_messages.push_back(msg);
    }
    
    // Get status messages (thread-safe)
    std::vector<std::string> getMessages() {
        std::lock_guard<std::mutex> lock(msg_mutex);
        return status_messages;
    }
    
    // Check if task is running
    bool isRunning() const { return running; }
    
    // Check if task is completed
    bool isCompleted() const { return completed; }
    
    // Wait for task to complete
    void wait() {
        if (worker.joinable()) {
            worker.join();
        }
    }

private:
    std::thread worker;
    std::atomic<bool> running;
    std::atomic<bool> completed;
    std::vector<std::string> status_messages;
    std::mutex msg_mutex;
};

#endif // ASYNC_TASK_H
