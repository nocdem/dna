/**
 * @file threadpool.c
 * @brief Simple thread pool implementation
 *
 * Part of DNA Messenger
 */

#include "threadpool.h"
#include "qgp_platform.h"
#include "qgp_log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define LOG_TAG "THREADPOOL"

/* Task queue node */
typedef struct task_node {
    threadpool_task_fn task;
    void *arg;
    struct task_node *next;
} task_node_t;

/* Thread pool structure */
struct threadpool {
    pthread_t *threads;
    int num_threads;

    /* Task queue */
    task_node_t *queue_head;
    task_node_t *queue_tail;
    size_t queue_size;

    /* Synchronization */
    pthread_mutex_t mutex;
    pthread_cond_t task_available;
    pthread_cond_t tasks_done;

    /* State */
    int active_tasks;
    bool shutdown;
};

/* Limits */
#define THREADPOOL_MIN 2
#define THREADPOOL_MAX 16
#define THREADPOOL_QUEUE_MAX 4096

/* Worker thread function */
static void *worker_thread(void *arg) {
    threadpool_t *pool = (threadpool_t *)arg;

    while (1) {
        pthread_mutex_lock(&pool->mutex);

        /* Wait for task or shutdown */
        while (pool->queue_size == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->task_available, &pool->mutex);
        }

        /* Check for shutdown */
        if (pool->shutdown && pool->queue_size == 0) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }

        /* Dequeue task */
        task_node_t *node = pool->queue_head;
        if (node) {
            pool->queue_head = node->next;
            if (pool->queue_head == NULL) {
                pool->queue_tail = NULL;
            }
            pool->queue_size--;
            pool->active_tasks++;
        }

        pthread_mutex_unlock(&pool->mutex);

        /* Execute task outside lock */
        if (node) {
            node->task(node->arg);
            free(node);

            /* Signal task completion */
            pthread_mutex_lock(&pool->mutex);
            pool->active_tasks--;
            if (pool->queue_size == 0 && pool->active_tasks == 0) {
                pthread_cond_broadcast(&pool->tasks_done);
            }
            pthread_mutex_unlock(&pool->mutex);
        }
    }

    return NULL;
}

int threadpool_optimal_size(void) {
    int cores = qgp_platform_cpu_count();
    int size = cores + 2;  /* Extra threads for I/O wait */

    if (size < THREADPOOL_MIN) size = THREADPOOL_MIN;
    if (size > THREADPOOL_MAX) size = THREADPOOL_MAX;

    return size;
}

threadpool_t *threadpool_create(int num_threads) {
    if (num_threads <= 0) {
        num_threads = threadpool_optimal_size();
    }
    if (num_threads < THREADPOOL_MIN) num_threads = THREADPOOL_MIN;
    if (num_threads > THREADPOOL_MAX) num_threads = THREADPOOL_MAX;

    threadpool_t *pool = calloc(1, sizeof(threadpool_t));
    if (!pool) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate thread pool");
        return NULL;
    }

    pool->num_threads = num_threads;
    pool->threads = calloc(num_threads, sizeof(pthread_t));
    if (!pool->threads) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate thread array");
        free(pool);
        return NULL;
    }

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->task_available, NULL);
    pthread_cond_init(&pool->tasks_done, NULL);

    /* Start worker threads */
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create worker thread %d", i);
            /* Continue with fewer threads */
            pool->num_threads = i;
            break;
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "Created thread pool with %d workers", pool->num_threads);
    return pool;
}

int threadpool_submit(threadpool_t *pool, threadpool_task_fn task, void *arg) {
    if (!pool || !task) {
        return -1;
    }

    task_node_t *node = malloc(sizeof(task_node_t));
    if (!node) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate task node");
        return -1;
    }

    node->task = task;
    node->arg = arg;
    node->next = NULL;

    pthread_mutex_lock(&pool->mutex);

    if (pool->shutdown || pool->queue_size >= THREADPOOL_QUEUE_MAX) {
        pthread_mutex_unlock(&pool->mutex);
        free(node);
        return -1;
    }

    /* Enqueue */
    if (pool->queue_tail) {
        pool->queue_tail->next = node;
    } else {
        pool->queue_head = node;
    }
    pool->queue_tail = node;
    pool->queue_size++;

    pthread_cond_signal(&pool->task_available);
    pthread_mutex_unlock(&pool->mutex);

    return 0;
}

void threadpool_wait(threadpool_t *pool) {
    if (!pool) return;

    pthread_mutex_lock(&pool->mutex);
    while (pool->queue_size > 0 || pool->active_tasks > 0) {
        pthread_cond_wait(&pool->tasks_done, &pool->mutex);
    }
    pthread_mutex_unlock(&pool->mutex);
}

void threadpool_destroy(threadpool_t *pool) {
    if (!pool) return;

    /* Signal shutdown */
    pthread_mutex_lock(&pool->mutex);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->task_available);
    pthread_mutex_unlock(&pool->mutex);

    /* Wait for all workers to exit */
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    /* Free remaining tasks (shouldn't be any) */
    task_node_t *node = pool->queue_head;
    while (node) {
        task_node_t *next = node->next;
        free(node);
        node = next;
    }

    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->task_available);
    pthread_cond_destroy(&pool->tasks_done);

    free(pool->threads);
    free(pool);

    QGP_LOG_DEBUG(LOG_TAG, "Thread pool destroyed");
}

int threadpool_parallel_exec(
    threadpool_task_fn *tasks,
    void **args,
    size_t count,
    int num_threads
) {
    if (!tasks || !args || count == 0) {
        return -1;
    }

    threadpool_t *pool = threadpool_create(num_threads);
    if (!pool) {
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        if (threadpool_submit(pool, tasks[i], args[i]) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to submit task %zu", i);
        }
    }

    threadpool_wait(pool);
    threadpool_destroy(pool);

    return 0;
}

int threadpool_map(
    threadpool_task_fn task,
    void **args,
    size_t count,
    int num_threads
) {
    if (!task || !args || count == 0) {
        return -1;
    }

    threadpool_t *pool = threadpool_create(num_threads);
    if (!pool) {
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        if (threadpool_submit(pool, task, args[i]) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to submit task %zu", i);
        }
    }

    threadpool_wait(pool);
    threadpool_destroy(pool);

    return 0;
}
