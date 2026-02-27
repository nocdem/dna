/**
 * @file dht_value_storage.h
 * @brief SQLite-backed persistent storage for DHT values
 *
 * This module provides persistent storage for critical DHT values on bootstrap nodes.
 * It stores PERMANENT and 365-day values (identity keys, name registrations) to SQLite,
 * allowing them to survive node restarts.
 *
 * Features:
 * - Selective persistence (only critical values)
 * - Background async republishing on startup
 * - Periodic cleanup of expired values
 * - Thread-safe operations
 * - Full monitoring and statistics
 *
 * @author DNA Messenger Team
 * @date 2025-11-08
 */

#ifndef DHT_VALUE_STORAGE_H
#define DHT_VALUE_STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque storage handle
 */
typedef struct dht_value_storage dht_value_storage_t;

/**
 * @brief Forward declaration of dht_context
 */
struct dht_context;

/**
 * @brief Storage statistics for monitoring
 */
typedef struct {
    uint64_t total_values;        /**< Total values currently stored */
    uint64_t storage_size_bytes;  /**< Database file size in bytes */
    uint64_t put_count;           /**< Total PUT operations */
    uint64_t get_count;           /**< Total GET operations */
    uint64_t republish_count;     /**< Total values republished on startup */
    uint64_t error_count;         /**< Total errors encountered */
    uint64_t last_cleanup_time;   /**< Unix timestamp of last cleanup */
    bool republish_in_progress;   /**< Is background republish still running? */
} dht_storage_stats_t;

/**
 * @brief Value metadata for storage filtering
 */
typedef struct {
    const uint8_t *key_hash;     /**< DHT key hash (raw bytes) */
    size_t key_hash_len;         /**< Key hash length */
    const uint8_t *value_data;   /**< Serialized value data */
    size_t value_data_len;       /**< Value data length */
    uint32_t value_type;         /**< ValueType ID (0x1001, 0x1002, etc.) */
    uint64_t value_id;           /**< Unique value ID within the key (for multi-writer support) */
    uint64_t created_at;         /**< Creation timestamp (Unix epoch) */
    uint64_t expires_at;         /**< Expiration timestamp (0 = permanent) */
} dht_value_metadata_t;

/**
 * @brief Create new value storage
 *
 * Initializes SQLite database and creates tables if needed.
 * Thread-safe for concurrent operations.
 *
 * @param db_path Path to SQLite database file
 * @return Storage handle, or NULL on error
 */
dht_value_storage_t* dht_value_storage_new(const char *db_path);

/**
 * @brief Free storage and close database
 *
 * @param storage Storage handle (can be NULL)
 */
void dht_value_storage_free(dht_value_storage_t *storage);

/**
 * @brief Store value to database
 *
 * Filters out non-critical values (7-day ephemeral data).
 * Only stores PERMANENT and 365-day values.
 *
 * Thread-safe. Returns 0 on success, -1 on error.
 *
 * @param storage Storage handle
 * @param metadata Value metadata
 * @return 0 on success, -1 on error
 */
int dht_value_storage_put(dht_value_storage_t *storage,
                           const dht_value_metadata_t *metadata);

/**
 * @brief Retrieve values for a key
 *
 * Returns all non-expired values for the given key hash.
 * Caller must free returned array with dht_value_storage_free_results().
 *
 * Thread-safe.
 *
 * @param storage Storage handle
 * @param key_hash Key hash (raw bytes)
 * @param key_hash_len Key hash length
 * @param results_out Output array of value metadata
 * @param count_out Number of results
 * @return 0 on success, -1 on error
 */
int dht_value_storage_get(dht_value_storage_t *storage,
                           const uint8_t *key_hash,
                           size_t key_hash_len,
                           dht_value_metadata_t **results_out,
                           size_t *count_out);

/**
 * @brief Free results returned by dht_value_storage_get()
 *
 * @param results Results array
 * @param count Number of results
 */
void dht_value_storage_free_results(dht_value_metadata_t *results, size_t count);

/**
 * @brief Restore all values to DHT (async, background thread)
 *
 * Launches background thread to republish all stored values to DHT.
 * Node starts immediately, republishing happens in background.
 *
 * @param storage Storage handle
 * @param ctx DHT context for republishing
 * @return 0 on success, -1 on error
 */
int dht_value_storage_restore_async(dht_value_storage_t *storage,
                                     struct dht_context *ctx);

/**
 * @brief Clean up expired values
 *
 * Removes values with expires_at < current time.
 * Should be called periodically (e.g., daily).
 *
 * Thread-safe. Returns number of values deleted.
 *
 * @param storage Storage handle
 * @return Number of values deleted, or -1 on error
 */
int dht_value_storage_cleanup(dht_value_storage_t *storage);

/**
 * @brief Get storage statistics
 *
 * Returns current storage metrics for monitoring.
 * Thread-safe.
 *
 * @param storage Storage handle
 * @param stats_out Output statistics structure
 * @return 0 on success, -1 on error
 */
int dht_value_storage_get_stats(dht_value_storage_t *storage,
                                 dht_storage_stats_t *stats_out);

/**
 * @brief Check if value should be persisted
 *
 * Returns true for PERMANENT and 365-day values only.
 * False for 7-day ephemeral data.
 *
 * @param value_type ValueType ID
 * @param expires_at Expiration timestamp (0 = permanent)
 * @return true if should persist, false otherwise
 */
bool dht_value_storage_should_persist(uint32_t value_type, uint64_t expires_at);

#ifdef __cplusplus
}
#endif

#endif // DHT_VALUE_STORAGE_H
