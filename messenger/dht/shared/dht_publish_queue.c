/**
 * @file dht_publish_queue.c
 * @brief Non-blocking DHT Publish Queue Implementation
 *
 * Single worker thread processes FIFO queue of publish requests.
 * Uses existing dht_chunked_publish() which has per-key mutex for
 * preventing chunk interleaving.
 *
 * Part of DNA Messenger
 *
 * @date 2026-01-30
 * @version 0.6.80
 */

#include "dht_publish_queue.h"
#include "dht_chunked.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#define LOG_TAG "DHT_PUB_Q"

/*============================================================================
 * Internal Structures
 *============================================================================*/

/**
 * Single publish request in queue
 */
typedef struct publish_queue_item {
    dht_publish_request_id_t id;        // Unique request ID
    dht_context_t *ctx;                 // DHT context (borrowed, not owned)
    char *base_key;                     // Key to publish to (owned, heap allocated)
    uint8_t *data;                      // Data to publish (owned, heap allocated)
    size_t data_len;                    // Data length
    uint32_t ttl_seconds;               // TTL for DHT storage
    dht_publish_callback_t callback;    // Completion callback (may be NULL)
    void *user_data;                    // User data for callback
    int retry_count;                    // Current retry attempt (0 = first try)
    struct publish_queue_item *next;    // Next item in linked list
} publish_queue_item_t;

/**
 * Publish queue structure
 */
struct dht_publish_queue {
    // Queue storage (linked list)
    publish_queue_item_t *head;         // First item (oldest)
    publish_queue_item_t *tail;         // Last item (newest)
    size_t count;                       // Current queue size

    // Thread synchronization
    pthread_mutex_t mutex;              // Protects queue access
    pthread_cond_t cond;                // Signals worker when items added
    pthread_t worker_thread;            // Worker thread handle

    // State flags
    atomic_bool running;                // True while worker should run
    atomic_bool worker_started;         // True after worker thread launched

    // Request ID generator
    atomic_uint_fast64_t next_id;       // Monotonic ID counter

    // Currently processing item (for cancel detection)
    dht_publish_request_id_t processing_id;
};

/*============================================================================
 * Internal Helper Functions
 *============================================================================*/

/**
 * Free a queue item and all its owned memory
 */
static void free_queue_item(publish_queue_item_t *item) {
    if (!item) return;
    free(item->base_key);
    free(item->data);
    free(item);
}

/**
 * Dequeue the next item (caller must hold mutex)
 * Returns NULL if queue is empty
 */
static publish_queue_item_t* dequeue_item_locked(dht_publish_queue_t *queue) {
    if (!queue->head) {
        return NULL;
    }

    publish_queue_item_t *item = queue->head;
    queue->head = item->next;
    if (!queue->head) {
        queue->tail = NULL;
    }
    queue->count--;
    item->next = NULL;
    return item;
}

/**
 * Enqueue an item at the tail (caller must hold mutex)
 * Returns 0 on success, -1 if queue is full
 */
static int enqueue_item_locked(dht_publish_queue_t *queue, publish_queue_item_t *item) {
    if (queue->count >= DHT_PUBLISH_QUEUE_MAX_ITEMS) {
        return -1;
    }

    item->next = NULL;
    if (queue->tail) {
        queue->tail->next = item;
    } else {
        queue->head = item;
    }
    queue->tail = item;
    queue->count++;
    return 0;
}

/**
 * Process a single publish request with retry logic
 *
 * @param item  Item to process (owned by caller, will be freed)
 * @return Final status code (DHT_PUBLISH_STATUS_*)
 */
static int process_publish_item(publish_queue_item_t *item) {
    int last_error = 0;
    int retry_delay_ms = DHT_PUBLISH_QUEUE_RETRY_DELAY_MS;

    for (int attempt = 0; attempt <= DHT_PUBLISH_QUEUE_MAX_RETRIES; attempt++) {
        if (attempt > 0) {
            QGP_LOG_INFO(LOG_TAG, "Retry %d/%d for key=%s (delay=%dms)",
                         attempt, DHT_PUBLISH_QUEUE_MAX_RETRIES, item->base_key, retry_delay_ms);
            qgp_platform_sleep_ms(retry_delay_ms);
            retry_delay_ms *= DHT_PUBLISH_QUEUE_RETRY_BACKOFF;
        }

        // Call existing sync publish (has per-key mutex internally)
        int result = dht_chunked_publish(item->ctx, item->base_key,
                                          item->data, item->data_len,
                                          item->ttl_seconds);

        if (result == DHT_CHUNK_OK) {
            QGP_LOG_INFO(LOG_TAG, "Publish OK: key=%s (attempt %d)", item->base_key, attempt + 1);
            return DHT_PUBLISH_STATUS_OK;
        }

        last_error = result;

        // DHT_CHUNK_ERR_HASH_MISMATCH is retryable (DHT version inconsistency)
        // DHT_CHUNK_ERR_DHT_PUT is retryable (network issues)
        // Other errors may not benefit from retry
        if (result != DHT_CHUNK_ERR_DHT_PUT &&
            result != DHT_CHUNK_ERR_HASH_MISMATCH &&
            result != DHT_CHUNK_ERR_TIMEOUT) {
            QGP_LOG_WARN(LOG_TAG, "Non-retryable error %d (%s) for key=%s",
                         result, dht_chunked_strerror(result), item->base_key);
            break;
        }

        QGP_LOG_WARN(LOG_TAG, "Publish failed (attempt %d): key=%s, error=%d (%s)",
                     attempt + 1, item->base_key, result, dht_chunked_strerror(result));
    }

    QGP_LOG_ERROR(LOG_TAG, "Publish FAILED after %d retries: key=%s, last_error=%d",
                  DHT_PUBLISH_QUEUE_MAX_RETRIES + 1, item->base_key, last_error);

    return DHT_PUBLISH_STATUS_FAILED;
}

/**
 * Worker thread main function
 */
static void* worker_thread_func(void *arg) {
    dht_publish_queue_t *queue = (dht_publish_queue_t *)arg;

    QGP_LOG_INFO(LOG_TAG, "Worker thread started");

    while (atomic_load(&queue->running)) {
        publish_queue_item_t *item = NULL;

        // Wait for work
        pthread_mutex_lock(&queue->mutex);
        while (atomic_load(&queue->running) && !queue->head) {
            pthread_cond_wait(&queue->cond, &queue->mutex);
        }

        if (!atomic_load(&queue->running)) {
            pthread_mutex_unlock(&queue->mutex);
            break;
        }

        // Dequeue next item
        item = dequeue_item_locked(queue);
        if (item) {
            queue->processing_id = item->id;
        }
        pthread_mutex_unlock(&queue->mutex);

        if (!item) {
            continue;
        }

        QGP_LOG_DEBUG(LOG_TAG, "Processing item id=%llu key=%s (%zu bytes)",
                      (unsigned long long)item->id, item->base_key, item->data_len);

        // Process the item (may take 30-60s)
        int status = process_publish_item(item);
        int error_code = (status == DHT_PUBLISH_STATUS_OK) ? 0 : status;

        // Clear processing ID
        pthread_mutex_lock(&queue->mutex);
        queue->processing_id = 0;
        pthread_mutex_unlock(&queue->mutex);

        // Invoke callback if provided
        if (item->callback) {
            item->callback(item->id, item->base_key, status, error_code, item->user_data);
        }

        // Free item
        free_queue_item(item);
    }

    QGP_LOG_INFO(LOG_TAG, "Worker thread exiting");
    return NULL;
}

/*============================================================================
 * Public API Implementation
 *============================================================================*/

dht_publish_queue_t* dht_publish_queue_create(void) {
    dht_publish_queue_t *queue = calloc(1, sizeof(dht_publish_queue_t));
    if (!queue) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate queue");
        return NULL;
    }

    // Initialize mutex and condition variable
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to init mutex");
        free(queue);
        return NULL;
    }

    if (pthread_cond_init(&queue->cond, NULL) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to init cond var");
        pthread_mutex_destroy(&queue->mutex);
        free(queue);
        return NULL;
    }

    // Initialize state
    atomic_store(&queue->running, true);
    atomic_store(&queue->worker_started, false);
    atomic_store(&queue->next_id, 1);
    queue->processing_id = 0;

    // Start worker thread
    if (pthread_create(&queue->worker_thread, NULL, worker_thread_func, queue) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create worker thread");
        pthread_cond_destroy(&queue->cond);
        pthread_mutex_destroy(&queue->mutex);
        free(queue);
        return NULL;
    }

    atomic_store(&queue->worker_started, true);
    QGP_LOG_INFO(LOG_TAG, "Publish queue created");
    return queue;
}

void dht_publish_queue_destroy(dht_publish_queue_t *queue) {
    if (!queue) return;

    QGP_LOG_INFO(LOG_TAG, "Destroying publish queue");

    // Signal worker to stop
    atomic_store(&queue->running, false);

    // Wake up worker if waiting
    pthread_mutex_lock(&queue->mutex);
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);

    // Wait for worker to finish (if it was started)
    if (atomic_load(&queue->worker_started)) {
        pthread_join(queue->worker_thread, NULL);
    }

    // Cancel all remaining items
    pthread_mutex_lock(&queue->mutex);
    while (queue->head) {
        publish_queue_item_t *item = dequeue_item_locked(queue);
        if (item) {
            // Invoke callback with cancelled status
            if (item->callback) {
                item->callback(item->id, item->base_key,
                              DHT_PUBLISH_STATUS_CANCELLED, 0, item->user_data);
            }
            free_queue_item(item);
        }
    }
    pthread_mutex_unlock(&queue->mutex);

    // Cleanup sync primitives
    pthread_cond_destroy(&queue->cond);
    pthread_mutex_destroy(&queue->mutex);

    free(queue);
    QGP_LOG_INFO(LOG_TAG, "Publish queue destroyed");
}

dht_publish_request_id_t dht_chunked_publish_async(
    dht_publish_queue_t *queue,
    dht_context_t *ctx,
    const char *base_key,
    const uint8_t *data,
    size_t data_len,
    uint32_t ttl_seconds,
    dht_publish_callback_t callback,
    void *user_data
) {
    if (!queue || !ctx || !base_key || !data || data_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for async publish");
        return 0;
    }

    if (!atomic_load(&queue->running)) {
        QGP_LOG_ERROR(LOG_TAG, "Queue is not running");
        return 0;
    }

    // Allocate and populate item
    publish_queue_item_t *item = calloc(1, sizeof(publish_queue_item_t));
    if (!item) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate queue item");
        return 0;
    }

    // Copy base_key
    item->base_key = strdup(base_key);
    if (!item->base_key) {
        free(item);
        return 0;
    }

    // Copy data
    item->data = malloc(data_len);
    if (!item->data) {
        free(item->base_key);
        free(item);
        return 0;
    }
    memcpy(item->data, data, data_len);

    // Fill in other fields
    item->ctx = ctx;
    item->data_len = data_len;
    item->ttl_seconds = ttl_seconds;
    item->callback = callback;
    item->user_data = user_data;
    item->retry_count = 0;
    item->next = NULL;

    // Generate unique ID
    item->id = atomic_fetch_add(&queue->next_id, 1);

    // Enqueue
    pthread_mutex_lock(&queue->mutex);
    int result = enqueue_item_locked(queue, item);
    if (result != 0) {
        pthread_mutex_unlock(&queue->mutex);
        QGP_LOG_WARN(LOG_TAG, "Queue full (%zu items), rejecting request", queue->count);
        free_queue_item(item);
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Enqueued publish: id=%llu key=%s (%zu bytes) queue_size=%zu",
                 (unsigned long long)item->id, base_key, data_len, queue->count);

    // Signal worker thread
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);

    return item->id;
}

int dht_publish_queue_cancel(
    dht_publish_queue_t *queue,
    dht_publish_request_id_t request_id
) {
    if (!queue || request_id == 0) {
        return -1;
    }

    pthread_mutex_lock(&queue->mutex);

    // Check if currently being processed
    if (queue->processing_id == request_id) {
        pthread_mutex_unlock(&queue->mutex);
        QGP_LOG_DEBUG(LOG_TAG, "Cannot cancel id=%llu - already processing",
                      (unsigned long long)request_id);
        return -1;
    }

    // Search queue for item
    publish_queue_item_t *prev = NULL;
    publish_queue_item_t *curr = queue->head;

    while (curr) {
        if (curr->id == request_id) {
            // Found it - remove from queue
            if (prev) {
                prev->next = curr->next;
            } else {
                queue->head = curr->next;
            }
            if (curr == queue->tail) {
                queue->tail = prev;
            }
            queue->count--;

            pthread_mutex_unlock(&queue->mutex);

            // Invoke callback with cancelled status
            if (curr->callback) {
                curr->callback(curr->id, curr->base_key,
                              DHT_PUBLISH_STATUS_CANCELLED, 0, curr->user_data);
            }

            QGP_LOG_INFO(LOG_TAG, "Cancelled publish: id=%llu key=%s",
                         (unsigned long long)request_id, curr->base_key);

            free_queue_item(curr);
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }

    pthread_mutex_unlock(&queue->mutex);
    QGP_LOG_DEBUG(LOG_TAG, "Cancel failed: id=%llu not found in queue",
                  (unsigned long long)request_id);
    return -1;
}

size_t dht_publish_queue_pending_count(dht_publish_queue_t *queue) {
    if (!queue) return 0;

    pthread_mutex_lock(&queue->mutex);
    size_t count = queue->count;
    pthread_mutex_unlock(&queue->mutex);

    return count;
}

bool dht_publish_queue_is_running(dht_publish_queue_t *queue) {
    if (!queue) return false;
    return atomic_load(&queue->running) && atomic_load(&queue->worker_started);
}
