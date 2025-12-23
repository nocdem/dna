/**
 * DHT Listen API - C wrapper for OpenDHT listen() functionality
 *
 * Provides real-time notifications when DHT values are published or expired.
 * Used for push notifications in offline message delivery system.
 *
 * Phase 14: Added extended API with cleanup callbacks, auto-reconnection,
 * and listener limits for reliable Android background operation.
 */

#ifndef DHT_LISTEN_H
#define DHT_LISTEN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct dht_context dht_context_t;

// Maximum number of simultaneous listeners (Phase 14)
#define DHT_MAX_LISTENERS 256

/**
 * Callback invoked when DHT values are received or expired
 *
 * @param value Serialized DHT value data (NULL if expired)
 * @param value_len Length of value data (0 if expired)
 * @param expired True if this is an expiration notification, false for new values
 * @param user_data User-provided context pointer
 *
 * @return true to continue listening, false to stop
 *
 * Note: The callback may be invoked multiple times for the same key as values
 * are added, updated, or removed from the DHT. The callback is always invoked
 * from a DHT worker thread, so implementations must be thread-safe.
 */
typedef bool (*dht_listen_callback_t)(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data
);

/**
 * Cleanup callback - invoked when a listener is cancelled (Phase 14)
 *
 * Use this to free any resources associated with user_data when the
 * listener is cancelled or the DHT context is destroyed.
 *
 * @param user_data The user_data pointer passed to dht_listen_ex()
 *
 * Note: This callback is invoked synchronously from dht_cancel_listen() or
 * dht_cancel_all_listeners(). Do not call dht_listen functions from within.
 */
typedef void (*dht_listen_cleanup_t)(void *user_data);

/**
 * Start listening for DHT values at the specified key
 *
 * Subscribes to real-time notifications when values are published or expire
 * at the given DHT key. This is the foundation for push notifications in the
 * offline message delivery system.
 *
 * Workflow:
 * 1. Converts C key to OpenDHT InfoHash
 * 2. Registers C++ lambda that wraps the C callback
 * 3. Calls dht::DhtRunner::listen() to start subscription
 * 4. Returns a token that can be used to cancel the subscription
 *
 * The subscription remains active until:
 * - dht_cancel_listen() is called with the returned token
 * - The DHT context is destroyed
 * - The callback returns false
 * - Network connectivity is lost (will auto-resubscribe when restored)
 *
 * @param ctx DHT context
 * @param key DHT key to listen on (typically 64 bytes for SHA3-512 hash)
 * @param key_len Length of key in bytes
 * @param callback Function to invoke when values arrive or expire
 * @param user_data Context pointer passed to callback
 *
 * @return Listen token (> 0 on success, 0 on failure)
 *
 * Example usage:
 * ```c
 * // Listen for offline messages from a contact
 * uint8_t outbox_key[64];
 * dht_generate_outbox_key(contact_fp, my_fp, outbox_key);
 *
 * size_t token = dht_listen(ctx, outbox_key, 64,
 *                          my_callback, my_context);
 * if (token == 0) {
 *     fprintf(stderr, "Failed to start listening\n");
 * }
 *
 * // Later, stop listening:
 * dht_cancel_listen(ctx, token);
 * ```
 */
size_t dht_listen(
    dht_context_t *ctx,
    const uint8_t *key,
    size_t key_len,
    dht_listen_callback_t callback,
    void *user_data
);

/**
 * Cancel an active DHT listen subscription
 *
 * Stops receiving notifications for the subscription associated with the
 * given token. After this call, the callback will no longer be invoked.
 *
 * This is a non-blocking operation. If callbacks are currently in progress,
 * they will complete normally but no new callbacks will be triggered.
 *
 * @param ctx DHT context
 * @param token Listen token returned by dht_listen()
 *
 * Note: It is safe to call this multiple times with the same token, or with
 * an invalid token (no-op). Tokens are not reused.
 */
void dht_cancel_listen(
    dht_context_t *ctx,
    size_t token
);

/**
 * Get the number of active listen subscriptions
 *
 * Returns the count of currently active dht_listen() subscriptions for this
 * DHT context. Useful for monitoring and debugging.
 *
 * @param ctx DHT context
 * @return Number of active subscriptions
 */
size_t dht_get_active_listen_count(
    dht_context_t *ctx
);

// ============================================================================
// Extended API (Phase 14)
// ============================================================================

/**
 * Start listening with cleanup callback support (Phase 14)
 *
 * Extended version of dht_listen() that accepts a cleanup callback. The cleanup
 * callback is invoked when the listener is cancelled (via dht_cancel_listen() or
 * dht_cancel_all_listeners()), allowing automatic resource management.
 *
 * This version also stores the key data for potential auto-resubscription when
 * DHT connection is restored after network loss.
 *
 * @param ctx DHT context
 * @param key DHT key to listen on (typically 64 bytes for SHA3-512 hash)
 * @param key_len Length of key in bytes
 * @param callback Function to invoke when values arrive or expire
 * @param user_data Context pointer passed to callback
 * @param cleanup Cleanup function called when listener is cancelled (may be NULL)
 *
 * @return Listen token (> 0 on success, 0 on failure)
 *
 * Note: Will fail if DHT_MAX_LISTENERS limit is reached.
 */
size_t dht_listen_ex(
    dht_context_t *ctx,
    const uint8_t *key,
    size_t key_len,
    dht_listen_callback_t callback,
    void *user_data,
    dht_listen_cleanup_t cleanup
);

/**
 * Cancel all active listen subscriptions (Phase 14)
 *
 * Cancels all active listeners and invokes their cleanup callbacks.
 * Useful for cleanup during shutdown or DHT reconnection.
 *
 * @param ctx DHT context
 */
void dht_cancel_all_listeners(
    dht_context_t *ctx
);

/**
 * Resubscribe all active listeners (Phase 14)
 *
 * Re-registers all active listeners with OpenDHT. This should be called
 * when DHT connection is restored after network loss.
 *
 * The listeners must have been created with dht_listen_ex() which stores
 * the key data for resubscription.
 *
 * @param ctx DHT context
 * @return Number of listeners successfully resubscribed
 */
size_t dht_resubscribe_all_listeners(
    dht_context_t *ctx
);

#ifdef __cplusplus
}
#endif

#endif // DHT_LISTEN_H
