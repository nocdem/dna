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
 * Get value from DHT
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
 * Delete value from DHT
 *
 * Note: In DHT, deletion is not immediate. This removes the value
 * from this node and asks peers to remove it. Use with caution.
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @return 0 on success, -1 on error
 */
int dht_delete(dht_context_t *ctx,
               const uint8_t *key, size_t key_len);

/**
 * Get DHT statistics
 *
 * @param ctx DHT context
 * @param node_count Number of nodes in routing table (output)
 * @param stored_values Number of values stored locally (output)
 * @return 0 on success, -1 on error
 */
int dht_get_stats(dht_context_t *ctx,
                  size_t *node_count,
                  size_t *stored_values);

#ifdef __cplusplus
}
#endif

#endif // DHT_CONTEXT_H
