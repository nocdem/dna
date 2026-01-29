/*
 * DNA Engine - Workers Module
 *
 * Worker thread pool for async task execution.
 *
 * Functions:
 *   - dna_worker_thread()         // Main worker loop
 *   - dna_start_workers()         // Start worker thread pool
 *   - dna_stop_workers()          // Stop all workers gracefully
 */

#define DNA_ENGINE_WORKERS_IMPL
#include "engine_includes.h"

#include <pthread.h>
#include <stdatomic.h>

/* Worker thread bounds defined in dna_engine_internal.h:
 * DNA_WORKER_THREAD_MIN, DNA_WORKER_THREAD_MAX */

/* ============================================================================
 * WORKER THREAD
 * ============================================================================ */

void* dna_worker_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t*)arg;

    while (!atomic_load(&engine->shutdown_requested)) {
        dna_task_t task;
        bool has_task = false;

        pthread_mutex_lock(&engine->task_mutex);
        while (dna_task_queue_empty(&engine->task_queue) &&
               !atomic_load(&engine->shutdown_requested)) {
            pthread_cond_wait(&engine->task_cond, &engine->task_mutex);
        }

        if (!atomic_load(&engine->shutdown_requested)) {
            has_task = dna_task_queue_pop(&engine->task_queue, &task);
        }
        pthread_mutex_unlock(&engine->task_mutex);

        if (has_task && !task.cancelled) {
            dna_execute_task(engine, &task);
            dna_free_task_params(&task);
        }
    }

    return NULL;
}

/**
 * Get optimal worker thread count based on CPU cores.
 * Returns: cores + 4 (for I/O bound work), clamped to min/max bounds.
 */
static int dna_get_optimal_worker_count(void) {
    int cores = qgp_platform_cpu_count();

    /* For I/O bound work (network, disk), more threads than cores is beneficial */
    int workers = cores + 4;

    /* Clamp to bounds */
    if (workers < DNA_WORKER_THREAD_MIN) workers = DNA_WORKER_THREAD_MIN;
    if (workers > DNA_WORKER_THREAD_MAX) workers = DNA_WORKER_THREAD_MAX;

    return workers;
}

/* NOTE: dna_get_parallel_limit() removed in v0.6.15
 * Parallel operations now use centralized threadpool (crypto/utils/threadpool.c)
 * which handles optimal sizing via threadpool_optimal_size(). */

int dna_start_workers(dna_engine_t *engine) {
    if (!engine) return -1;
    atomic_store(&engine->shutdown_requested, false);

    /* Calculate optimal thread count based on CPU cores */
    engine->worker_count = dna_get_optimal_worker_count();
    engine->worker_threads = calloc(engine->worker_count, sizeof(pthread_t));
    if (!engine->worker_threads) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate worker threads array");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Starting %d worker threads (based on CPU cores)", engine->worker_count);

    for (int i = 0; i < engine->worker_count; i++) {
        int rc = pthread_create(&engine->worker_threads[i], NULL, dna_worker_thread, engine);
        if (rc != 0) {
            /* Stop already-started threads */
            atomic_store(&engine->shutdown_requested, true);
            pthread_cond_broadcast(&engine->task_cond);
            for (int j = 0; j < i; j++) {
                pthread_join(engine->worker_threads[j], NULL);
            }
            free(engine->worker_threads);
            engine->worker_threads = NULL;
            engine->worker_count = 0;
            return -1;
        }
    }
    return 0;
}

void dna_stop_workers(dna_engine_t *engine) {
    if (!engine || !engine->worker_threads) return;
    atomic_store(&engine->shutdown_requested, true);

    pthread_mutex_lock(&engine->task_mutex);
    pthread_cond_broadcast(&engine->task_cond);
    pthread_mutex_unlock(&engine->task_mutex);

    for (int i = 0; i < engine->worker_count; i++) {
        pthread_join(engine->worker_threads[i], NULL);
    }

    free(engine->worker_threads);
    engine->worker_threads = NULL;
    engine->worker_count = 0;
}
