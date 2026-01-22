/**
 * @file threadpool.h
 * @brief Simple thread pool for parallel I/O-bound operations
 *
 * Provides a centralized thread pool for parallel DHT operations, message
 * fetching, watermark publishing, and other I/O-bound tasks.
 *
 * Usage:
 *   threadpool_t *pool = threadpool_create(0);  // 0 = auto (CPU cores)
 *   for (int i = 0; i < n; i++) {
 *       threadpool_submit(pool, my_worker, &tasks[i]);
 *   }
 *   threadpool_wait(pool);  // Wait for all to complete
 *   threadpool_destroy(pool);
 *
 * Part of DNA Messenger
 */

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque thread pool handle */
typedef struct threadpool threadpool_t;

/* Task function signature */
typedef void (*threadpool_task_fn)(void *arg);

/**
 * Create a new thread pool
 *
 * @param num_threads Number of worker threads (0 = auto based on CPU cores)
 * @return Thread pool handle, or NULL on error
 */
threadpool_t *threadpool_create(int num_threads);

/**
 * Submit a task to the pool
 *
 * Task will be executed by one of the worker threads. Tasks are executed
 * in approximately FIFO order but no strict ordering is guaranteed.
 *
 * @param pool Thread pool
 * @param task Task function to execute
 * @param arg Argument passed to task function
 * @return 0 on success, -1 on error (pool full or shutting down)
 */
int threadpool_submit(threadpool_t *pool, threadpool_task_fn task, void *arg);

/**
 * Wait for all submitted tasks to complete
 *
 * Blocks until the task queue is empty and all workers are idle.
 * New tasks can still be submitted after wait returns.
 *
 * @param pool Thread pool
 */
void threadpool_wait(threadpool_t *pool);

/**
 * Destroy the thread pool
 *
 * Waits for all pending tasks to complete, then shuts down worker threads.
 * The pool handle is invalid after this call.
 *
 * @param pool Thread pool
 */
void threadpool_destroy(threadpool_t *pool);

/**
 * Get optimal thread count for I/O-bound operations
 *
 * Returns CPU cores + 2, clamped to [2, 16].
 * Use this for DHT operations, network I/O, etc.
 *
 * @return Recommended thread count
 */
int threadpool_optimal_size(void);

/**
 * Execute tasks in parallel and wait for completion (convenience function)
 *
 * Creates a temporary thread pool, submits all tasks, waits, and destroys.
 * Use for one-shot parallel operations.
 *
 * @param tasks Array of task functions
 * @param args Array of arguments (one per task)
 * @param count Number of tasks
 * @param num_threads Number of threads (0 = auto)
 * @return 0 on success, -1 on error
 */
int threadpool_parallel_exec(
    threadpool_task_fn *tasks,
    void **args,
    size_t count,
    int num_threads
);

/**
 * Execute same function on multiple arguments in parallel (convenience)
 *
 * Simpler version when all tasks use the same function.
 *
 * @param task Task function to execute for each arg
 * @param args Array of arguments
 * @param count Number of arguments
 * @param num_threads Number of threads (0 = auto)
 * @return 0 on success, -1 on error
 */
int threadpool_map(
    threadpool_task_fn task,
    void **args,
    size_t count,
    int num_threads
);

#ifdef __cplusplus
}
#endif

#endif /* THREADPOOL_H */
