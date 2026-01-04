/**
 * DHT Context - C API for OpenDHT
 *
 * This is a thin C wrapper around the C++ OpenDHT library.
 * Provides simple put/get/delete operations for distributed storage.
 *
 * @file dht_context.h
 * @author DNA Messenger Team
 * @date 2025-11-01
 */

#ifndef DHT_CONTEXT_H
#define DHT_CONTEXT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Phase 3: Include extracted modules
#include "dht_stats.h"
#include "../client/dht_identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DHT Configuration
 */
typedef struct {
    uint16_t port;                    // DHT port (default: 4000)
    bool is_bootstrap;                // Is this a bootstrap node?
    char identity[256];               // Node identity (username or "bootstrap1")
    char bootstrap_nodes[5][256];     // Up to 5 bootstrap nodes (IP:port)
    size_t bootstrap_count;           // Number of bootstrap nodes
    char persistence_path[512];       // Disk persistence path (empty = memory-only)
} dht_config_t;

/**
 * DHT Context (Opaque pointer - hides C++ implementation)
 */
typedef struct dht_context dht_context_t;

/**
 * DHT Identity (Opaque pointer - for encrypted backup system)
 * Forward declaration for use in dht_context_start_with_identity()
 */
typedef struct dht_identity dht_identity_t;

/**
 * Initialize DHT context
 *
 * @param config DHT configuration
 * @return DHT context or NULL on error
 */
dht_context_t* dht_context_new(const dht_config_t *config);

/**
 * Start DHT node (begins listening and bootstrapping)
 *
 * @param ctx DHT context
 * @return 0 on success, -1 on error
 */
int dht_context_start(dht_context_t *ctx);

/**
 * Start DHT node with user-provided identity
 *
 * Uses the provided DHT identity instead of generating/loading one.
 * This is used for encrypted backup system where identity is managed externally.
 *
 * @param ctx DHT context
 * @param identity User-provided DHT identity (for signing DHT operations)
 * @return 0 on success, -1 on error
 */
int dht_context_start_with_identity(dht_context_t *ctx, dht_identity_t *identity);

/**
 * Stop DHT node
 *
 * @param ctx DHT context
 */
void dht_context_stop(dht_context_t *ctx);

/**
 * Free DHT context
 *
 * @param ctx DHT context
 */
void dht_context_free(dht_context_t *ctx);

/**
 * Check if DHT is ready (connected to network)
 *
 * @param ctx DHT context
 * @return true if ready (has at least 1 peer), false otherwise
 */
bool dht_context_is_ready(dht_context_t *ctx);

/**
 * Check if DHT context is running (not stopped/cleaned up)
 *
 * This is a simpler check than dht_context_is_ready() - it only checks
 * if the context is running, not if it's connected to peers.
 * Use this to detect if DHT is being cleaned up during reinit.
 *
 * @param ctx DHT context
 * @return true if running, false if stopped/NULL
 */
bool dht_context_is_running(dht_context_t *ctx);

/**
 * Status change callback type
 *
 * @param is_connected true if DHT is now connected, false if disconnected
 * @param user_data User-provided context pointer
 */
typedef void (*dht_status_callback_t)(bool is_connected, void *user_data);

/**
 * Set callback for DHT connection status changes
 *
 * The callback will be invoked from OpenDHT's internal thread when the
 * connection status changes between connected and disconnected states.
 *
 * @param ctx DHT context
 * @param callback Function to call on status change (NULL to clear)
 * @param user_data User context passed to callback
 */
void dht_context_set_status_callback(dht_context_t *ctx, dht_status_callback_t callback, void *user_data);

/**
 * Put value in DHT with custom TTL
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param value Value to store
 * @param value_len Value length
 * @param ttl_seconds Time-to-live in seconds (0 = default 7 days, UINT_MAX = permanent)
 * @return 0 on success, -1 on error
 */
int dht_put_ttl(dht_context_t *ctx,
                const uint8_t *key, size_t key_len,
                const uint8_t *value, size_t value_len,
                unsigned int ttl_seconds);

/**
 * Put value in DHT permanently (never expires)
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param value Value to store
 * @param value_len Value length
 * @return 0 on success, -1 on error
 */
int dht_put_permanent(dht_context_t *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *value, size_t value_len);

/**
 * Put value in DHT (default 7-day TTL)
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param value Value to store
 * @param value_len Value length
 * @return 0 on success, -1 on error
 */
int dht_put(dht_context_t *ctx,
            const uint8_t *key, size_t key_len,
            const uint8_t *value, size_t value_len);

/**
 * Put SIGNED value in DHT with fixed value ID (enables editing/replacement)
 *
 * This function uses OpenDHT's putSigned() with a fixed value ID, which
 * allows subsequent PUTs with the same ID to REPLACE the old value instead
 * of accumulating. This solves the value accumulation problem where multiple
 * unsigned values with different IDs would pile up at the same key.
 *
 * Key differences from dht_put():
 * - Uses putSigned() instead of put()
 * - Sets fixed value ID (not auto-generated)
 * - Old values with same ID are replaced (not accumulated)
 * - Sequence numbers auto-increment for versioning
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param value Value to store
 * @param value_len Value length
 * @param value_id Fixed value ID (e.g., 1 for offline queue slot)
 * @param ttl_seconds Time-to-live in seconds (0 = default 7 days)
 * @return 0 on success, -1 on error
 */
int dht_put_signed(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *value, size_t value_len,
                   uint64_t value_id,
                   unsigned int ttl_seconds);

/**
 * Put SIGNED value in DHT permanently with fixed value ID
 *
 * This is a convenience wrapper around dht_put_signed() that sets TTL to
 * permanent (never expires). Use this for data that should persist indefinitely
 * but still needs the replacement behavior (e.g., contact lists, profiles).
 *
 * Combines benefits of:
 * - dht_put_signed(): Replacement via fixed value_id (no accumulation)
 * - dht_put_permanent(): Never expires (TTL = UINT_MAX)
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param value Value to store
 * @param value_len Value length
 * @param value_id Fixed value ID (e.g., 1 for contact list)
 * @return 0 on success, -1 on error
 */
int dht_put_signed_permanent(dht_context_t *ctx,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *value, size_t value_len,
                              uint64_t value_id);

/**
 * Republish a serialized (packed) Value to DHT exactly as-is
 *
 * This function deserializes a msgpack-encoded dht::Value and publishes it
 * back to the DHT network. Unlike dht_put_ttl(), this preserves the original
 * signature and all other Value fields (owner, seq, id, etc.).
 *
 * Used by republish_worker() to restore signed values after bootstrap restart.
 * The value_data must be from Value::getPacked() serialization.
 *
 * @param ctx DHT context
 * @param key_hex InfoHash as hex string (40 chars, from key.toString())
 * @param packed_data Serialized Value from Value::getPacked()
 * @param packed_len Length of packed data
 * @return 0 on success, -1 on error
 */
int dht_republish_packed(dht_context_t *ctx,
                         const char *key_hex,
                         const uint8_t *packed_data,
                         size_t packed_len);

/**
 * Get value from DHT (returns first value only)
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param value_out Buffer to store value (caller must free)
 * @param value_len_out Value length (output)
 * @return 0 on success, -1 on error (not found or error)
 */
int dht_get(dht_context_t *ctx,
            const uint8_t *key, size_t key_len,
            uint8_t **value_out, size_t *value_len_out);

/**
 * Get value from DHT asynchronously (non-blocking)
 * Callback is invoked when value is retrieved (or on error)
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param callback Function called with (value, value_len, userdata). Value is NULL on error. Caller must free value.
 * @param userdata User data passed to callback
 */
void dht_get_async(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   void (*callback)(uint8_t *value, size_t value_len, void *userdata),
                   void *userdata);

/**
 * Get all values from DHT for a given key
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param values_out Array of value buffers (caller must free each + array)
 * @param values_len_out Array of value lengths
 * @param count_out Number of values returned
 * @return 0 on success, -1 on error (not found or error)
 */
int dht_get_all(dht_context_t *ctx,
                const uint8_t *key, size_t key_len,
                uint8_t ***values_out, size_t **values_len_out,
                size_t *count_out);

/**
 * Batch result structure for dht_get_batch()
 */
typedef struct {
    const uint8_t *key;     // Original key (pointer to caller's data, not freed)
    size_t key_len;         // Key length
    uint8_t *value;         // First value data (caller must free), NULL if not found
    size_t value_len;       // Value length (0 if not found)
    int found;              // 1 if found, 0 if not found
} dht_batch_result_t;

/**
 * Batch GET callback type
 *
 * Called once when ALL batch GET operations complete.
 *
 * @param results Array of results (one per key)
 * @param count Number of results (same as input key count)
 * @param userdata User-provided context pointer
 */
typedef void (*dht_batch_callback_t)(
    dht_batch_result_t *results,
    size_t count,
    void *userdata
);

/**
 * Get multiple values from DHT in parallel (batch operation)
 *
 * Fires all GET operations simultaneously and calls callback once
 * when ALL operations complete. Much faster than sequential GETs
 * for retrieving data from multiple keys (e.g., offline message check).
 *
 * Performance: 50 keys sequential = ~12.5s, batch = ~0.3s (40x speedup)
 *
 * @param ctx DHT context
 * @param keys Array of key pointers
 * @param key_lens Array of key lengths
 * @param count Number of keys
 * @param callback Called once when all GETs complete (results array valid only during callback)
 * @param userdata User data passed to callback
 */
void dht_get_batch(
    dht_context_t *ctx,
    const uint8_t **keys,
    const size_t *key_lens,
    size_t count,
    dht_batch_callback_t callback,
    void *userdata
);

/**
 * Synchronous batch GET (blocking)
 *
 * Blocks until all keys are retrieved. Results array is allocated
 * and must be freed by caller using dht_batch_results_free().
 *
 * @param ctx DHT context
 * @param keys Array of key pointers
 * @param key_lens Array of key lengths
 * @param count Number of keys
 * @param results_out Output array (caller must free with dht_batch_results_free)
 * @return 0 on success, -1 on error
 */
int dht_get_batch_sync(
    dht_context_t *ctx,
    const uint8_t **keys,
    const size_t *key_lens,
    size_t count,
    dht_batch_result_t **results_out
);

/**
 * Free batch results array
 *
 * Frees all value buffers and the results array itself.
 *
 * @param results Results array from dht_get_batch_sync()
 * @param count Number of results
 */
void dht_batch_results_free(dht_batch_result_t *results, size_t count);

/**
 * Get DHT statistics
 *
 * @param ctx DHT context
 * @param node_count Number of nodes in routing table (output)
 * @param stored_values Number of values stored locally (output)
 * @return 0 on success, -1 on error
 */
// NOTE: dht_get_stats() and dht_get_storage() moved to dht/core/dht_stats.h (Phase 3)
// NOTE: dht_identity_* functions moved to dht/client/dht_identity.h (Phase 3)

/**
 * Get this DHT node's ID (SHA3-512 hash of public key)
 * Used for bootstrap node registry
 *
 * @param ctx DHT context
 * @param node_id_out Output buffer (must be at least 129 bytes for hex string + null)
 * @return 0 on success, -1 on error
 */
int dht_get_node_id(dht_context_t *ctx, char *node_id_out);

/**
 * Get unique value_id for this DHT node's identity
 *
 * Returns a 64-bit value derived from the node's public key.
 * Used as value_id for putSigned() to ensure each owner has a unique slot.
 *
 * @param ctx DHT context
 * @param value_id_out Output for the 64-bit value_id
 * @return 0 on success, -1 on error
 */
int dht_get_owner_value_id(dht_context_t *ctx, uint64_t *value_id_out);

/**
 * Bootstrap to additional DHT nodes at runtime
 * Used for dynamic bootstrap node discovery
 *
 * @param ctx DHT context
 * @param ip Bootstrap node IP address
 * @param port Bootstrap node port
 * @return 0 on success, -1 on error
 */
int dht_context_bootstrap_runtime(dht_context_t *ctx, const char *ip, uint16_t port);

#ifdef __cplusplus
}
#endif

#endif // DHT_CONTEXT_H
