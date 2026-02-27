/**
 * @file dht_publish_queue.h
 * @brief Non-blocking DHT Publish Queue with Per-Key Serialization
 *
 * Provides asynchronous publishing to DHT without blocking callers.
 * Features:
 * - Non-blocking submit: callers return immediately
 * - Single worker thread processes FIFO queue
 * - Automatic retry with exponential backoff (1s, 2s, 4s)
 * - Per-key serialization via existing dht_chunked_publish() mutex
 * - Optional callback notification on completion
 * - Post-publish verification (content hash check)
 *
 * Usage:
 *   // Create queue (typically in engine init)
 *   dht_publish_queue_t *queue = dht_publish_queue_create();
 *
 *   // Submit publish request (non-blocking)
 *   dht_publish_request_id_t id = dht_chunked_publish_async(
 *       queue, ctx, "fingerprint:profile", data, len, ttl, callback, user_data);
 *
 *   // Callback fires when complete (success or failure)
 *   void callback(dht_publish_request_id_t id, const char *key, int status, int error, void *ud) {
 *       if (status == DHT_PUBLISH_STATUS_OK) { ... }
 *   }
 *
 *   // Destroy queue (waits for pending items)
 *   dht_publish_queue_destroy(queue);
 *
 * Part of DNA Messenger
 *
 * @date 2026-01-30
 * @version 0.6.80
 */

#ifndef DHT_PUBLISH_QUEUE_H
#define DHT_PUBLISH_QUEUE_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

/** Maximum items in queue (prevents unbounded memory growth) */
#define DHT_PUBLISH_QUEUE_MAX_ITEMS     256

/** Maximum retry attempts per item */
#define DHT_PUBLISH_QUEUE_MAX_RETRIES   3

/** Initial retry delay in milliseconds */
#define DHT_PUBLISH_QUEUE_RETRY_DELAY_MS    1000

/** Retry delay multiplier (exponential backoff) */
#define DHT_PUBLISH_QUEUE_RETRY_BACKOFF     2

/*============================================================================
 * Status Codes
 *============================================================================*/

/** Publish completed successfully */
#define DHT_PUBLISH_STATUS_OK           0

/** Publish failed after all retries */
#define DHT_PUBLISH_STATUS_FAILED       (-1)

/** Publish was cancelled before completion */
#define DHT_PUBLISH_STATUS_CANCELLED    (-2)

/** Queue is full, request rejected */
#define DHT_PUBLISH_STATUS_QUEUE_FULL   (-3)

/** Invalid parameters */
#define DHT_PUBLISH_STATUS_INVALID      (-4)

/*============================================================================
 * Types
 *============================================================================*/

/** Opaque queue handle */
typedef struct dht_publish_queue dht_publish_queue_t;

/** Request ID for tracking submitted publishes */
typedef uint64_t dht_publish_request_id_t;

/**
 * Callback invoked when publish completes (success or failure)
 *
 * @param request_id  ID returned from dht_chunked_publish_async()
 * @param base_key    The key that was published to
 * @param status      DHT_PUBLISH_STATUS_OK, _FAILED, or _CANCELLED
 * @param error_code  DHT_CHUNK_* error code (only meaningful if status != OK)
 * @param user_data   User data passed to dht_chunked_publish_async()
 *
 * Note: Callback is invoked from worker thread. Keep it fast and non-blocking.
 * For UI updates, post to main thread via event system.
 */
typedef void (*dht_publish_callback_t)(
    dht_publish_request_id_t request_id,
    const char *base_key,
    int status,
    int error_code,
    void *user_data
);

/*============================================================================
 * Lifecycle Functions
 *============================================================================*/

/**
 * Create publish queue and start worker thread
 *
 * @return Queue handle on success, NULL on failure
 */
dht_publish_queue_t* dht_publish_queue_create(void);

/**
 * Destroy publish queue
 *
 * Signals worker thread to stop, waits for it to finish current item,
 * then frees all pending items (invoking callbacks with CANCELLED status).
 *
 * @param queue  Queue to destroy (may be NULL)
 */
void dht_publish_queue_destroy(dht_publish_queue_t *queue);

/*============================================================================
 * Submit Functions
 *============================================================================*/

/**
 * Submit data for asynchronous DHT publishing (non-blocking)
 *
 * Data is copied internally - caller can free original after return.
 * Returns immediately; actual publish happens in worker thread.
 *
 * @param queue        Publish queue
 * @param ctx          DHT context (must remain valid until callback)
 * @param base_key     Base key for chunked storage (copied internally)
 * @param data         Data to publish (copied internally)
 * @param data_len     Data length
 * @param ttl_seconds  TTL for DHT storage (use DHT_CHUNK_TTL_* constants)
 * @param callback     Callback when complete (may be NULL for fire-and-forget)
 * @param user_data    User data passed to callback
 *
 * @return Request ID (>0) on success, 0 on failure (queue full or invalid params)
 */
dht_publish_request_id_t dht_chunked_publish_async(
    dht_publish_queue_t *queue,
    dht_context_t *ctx,
    const char *base_key,
    const uint8_t *data,
    size_t data_len,
    uint32_t ttl_seconds,
    dht_publish_callback_t callback,
    void *user_data
);

/*============================================================================
 * Control Functions
 *============================================================================*/

/**
 * Cancel a pending publish request
 *
 * If the request is still queued (not yet being processed), it will be
 * removed and callback invoked with CANCELLED status. If already being
 * processed, it will complete normally.
 *
 * @param queue       Publish queue
 * @param request_id  Request ID to cancel
 *
 * @return 0 if found and cancelled, -1 if not found or already processing
 */
int dht_publish_queue_cancel(
    dht_publish_queue_t *queue,
    dht_publish_request_id_t request_id
);

/**
 * Get number of pending items in queue
 *
 * @param queue  Publish queue
 * @return Number of items waiting to be processed
 */
size_t dht_publish_queue_pending_count(dht_publish_queue_t *queue);

/**
 * Check if queue worker is running
 *
 * @param queue  Publish queue
 * @return true if worker thread is active
 */
bool dht_publish_queue_is_running(dht_publish_queue_t *queue);

#ifdef __cplusplus
}
#endif

#endif // DHT_PUBLISH_QUEUE_H
