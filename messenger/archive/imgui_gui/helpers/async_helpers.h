/**
 * Async Helpers
 * 
 * Unified async task helpers for DNA Messenger GUI.
 * Provides both single-task (AsyncTask) and queue-based (AsyncTaskQueue) processing.
 */

#ifndef ASYNC_HELPERS_H
#define ASYNC_HELPERS_H

#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include <string>
#include <mutex>
#include <queue>
#include <condition_variable>

// ============================================================================
// AsyncTask - Single reusable async task runner for background operations
// ============================================================================
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
/**
 * Async Task Queue
 *
 * Queue-based asynchronous task processor for DNA Messenger.
 * Allows multiple tasks to be enqueued and processed sequentially
 * by a single worker thread.
 *
 * Thread-safe with mutex protection for queue operations.
 */

#ifndef ASYNC_TASK_QUEUE_H
#define ASYNC_TASK_QUEUE_H

#include <functional>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

class AsyncTaskQueue {
private:
    struct TaskData {
        std::function<void()> func;
        int message_index;

        TaskData(std::function<void()> f, int idx) : func(f), message_index(idx) {}
    };

    std::thread worker;
    std::queue<TaskData> queue;
    mutable std::mutex queue_mutex;  // mutable allows locking in const methods
    std::condition_variable cv;
    std::atomic<bool> shutdown{false};
    std::atomic<bool> worker_running{false};

    /**
     * Worker thread loop - processes tasks from queue one-by-one
     */
    void processorLoop() {
        while (!shutdown) {
            std::function<void()> task;

            // Wait for task or shutdown signal
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                cv.wait(lock, [this] { return !queue.empty() || shutdown.load(); });

                if (shutdown && queue.empty()) {
                    break;
                }

                if (!queue.empty()) {
                    task = queue.front().func;
                    queue.pop();
                }
            }

            // Execute task outside of lock
            if (task) {
                try {
                    task();
                } catch (const std::exception& e) {
                    // Catch exceptions to prevent worker thread crash
                    fprintf(stderr, "[AsyncTaskQueue] Task exception: %s\n", e.what());
                } catch (...) {
                    fprintf(stderr, "[AsyncTaskQueue] Unknown task exception\n");
                }
            }
        }
    }

public:
    /**
     * Constructor - starts worker thread
     */
    AsyncTaskQueue() {
        worker_running = true;
        worker = std::thread(&AsyncTaskQueue::processorLoop, this);
    }

    /**
     * Destructor - signals shutdown and joins worker thread
     */
    ~AsyncTaskQueue() {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            shutdown = true;
        }
        cv.notify_all();

        if (worker.joinable()) {
            worker.join();
        }

        worker_running = false;
    }

    // Prevent copying
    AsyncTaskQueue(const AsyncTaskQueue&) = delete;
    AsyncTaskQueue& operator=(const AsyncTaskQueue&) = delete;

    /**
     * Enqueue a task for asynchronous execution
     *
     * @param func Task function to execute
     * @param msg_idx Message index for tracking
     */
    void enqueue(std::function<void()> func, int msg_idx) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            queue.emplace(func, msg_idx);
        }
        cv.notify_one();
    }

    /**
     * Get current queue size
     *
     * @return Number of tasks waiting in queue
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return queue.size();
    }

    /**
     * Check if queue is empty
     *
     * @return true if no tasks waiting
     */
    bool isEmpty() const {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return queue.empty();
    }

    /**
     * Check if worker thread is running
     *
     * @return true if worker active
     */
    bool isRunning() const {
        return worker_running.load();
    }
};

#endif // ASYNC_HELPERS_H
