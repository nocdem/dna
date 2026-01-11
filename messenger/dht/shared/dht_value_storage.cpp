/**
 * @file dht_value_storage.cpp
 * @brief SQLite-backed persistent storage for DHT values (implementation)
 */

#include "dht_value_storage.h"
#include "dht_context.h"
#include <sqlite3.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <climits>
#include <thread>
#include <chrono>
#include <exception>

// Unified logging (respects config log level)
extern "C" {
#include "crypto/utils/qgp_log.h"
}
#define LOG_TAG "STORAGE"

// Custom ValueType IDs (must match dht_context.cpp)
#define DNA_TYPE_7DAY_ID    0x1001
#define DNA_TYPE_365DAY_ID  0x1002

/**
 * @brief Internal storage structure
 */
struct dht_value_storage {
    sqlite3 *db;                    ///< SQLite database handle
    char *db_path;                  ///< Database file path
    pthread_mutex_t mutex;          ///< Thread safety mutex

    // Statistics
    uint64_t total_values;
    uint64_t put_count;
    uint64_t get_count;
    uint64_t republish_count;
    uint64_t error_count;
    uint64_t last_cleanup_time;
    bool republish_in_progress;

    // Background republish thread
    std::thread *republish_thread;
};

/**
 * @brief SQLite schema
 */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS dht_values ("
    "  key_hash TEXT NOT NULL,"
    "  value_data BLOB NOT NULL,"
    "  value_type INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  expires_at INTEGER,"
    "  original_key TEXT,"
    "  PRIMARY KEY (key_hash, created_at)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_expires ON dht_values(expires_at);"
    "CREATE INDEX IF NOT EXISTS idx_key ON dht_values(key_hash);";

/**
 * @brief Helper: Convert binary hash to hex string
 */
static void hash_to_hex(const uint8_t *hash, size_t len, char *hex_out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_out + (i * 2), "%02x", hash[i]);
    }
    hex_out[len * 2] = '\0';
}


/**
 * @brief Helper: Get file size
 */
static uint64_t get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return st.st_size;
    }
    return 0;
}

/**
 * @brief Initialize database schema
 */
static int init_schema(sqlite3 *db) {
    char *err_msg = NULL;
    int rc = sqlite3_exec(db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Schema creation failed: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}

// ============================================================================
// Public API Implementation
// ============================================================================

dht_value_storage_t* dht_value_storage_new(const char *db_path) {
    if (!db_path) {
        QGP_LOG_ERROR(LOG_TAG, "NULL database path");
        return NULL;
    }

    // Allocate structure
    dht_value_storage_t *storage = (dht_value_storage_t*)calloc(1, sizeof(dht_value_storage_t));
    if (!storage) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        return NULL;
    }

    // Initialize mutex
    pthread_mutex_init(&storage->mutex, NULL);

    // Copy path
    storage->db_path = strdup(db_path);

    // Open database
    int rc = sqlite3_open(db_path, &storage->db);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s", sqlite3_errmsg(storage->db));
        free(storage->db_path);
        pthread_mutex_destroy(&storage->mutex);
        free(storage);
        return NULL;
    }

    // Enable WAL mode for better concurrency
    sqlite3_exec(storage->db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);

    // Initialize schema
    if (init_schema(storage->db) != 0) {
        sqlite3_close(storage->db);
        free(storage->db_path);
        pthread_mutex_destroy(&storage->mutex);
        free(storage);
        return NULL;
    }

    // Count existing values
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(storage->db, "SELECT COUNT(*) FROM dht_values", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            storage->total_values = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    QGP_LOG_INFO(LOG_TAG, "Initialized: %s", db_path);
    QGP_LOG_DEBUG(LOG_TAG, "Existing values: %llu", (unsigned long long)storage->total_values);

    return storage;
}

void dht_value_storage_free(dht_value_storage_t *storage) {
    if (!storage) return;

    // Wait for republish thread
    if (storage->republish_thread) {
        QGP_LOG_DEBUG(LOG_TAG, "Waiting for republish thread to finish...");
        storage->republish_thread->join();
        delete storage->republish_thread;
    }

    // Close database
    if (storage->db) {
        sqlite3_close(storage->db);
    }

    // Free resources
    if (storage->db_path) {
        free(storage->db_path);
    }

    pthread_mutex_destroy(&storage->mutex);
    free(storage);

    QGP_LOG_DEBUG(LOG_TAG, "Freed");
}

bool dht_value_storage_should_persist(uint32_t value_type, uint64_t expires_at) {
    // Persist PERMANENT values (expires_at == 0)
    if (expires_at == 0) {
        return true;
    }

    // Persist 365-day values (profiles, avatars, etc.)
    if (value_type == DNA_TYPE_365DAY_ID) {
        return true;
    }

    // Persist 30-day values (wall posts, name registrations)
    if (value_type == 0x1003) {  // DNA_TYPE_30DAY
        return true;
    }

    // Skip 7-day ephemeral values (messages, etc.)
    if (value_type == DNA_TYPE_7DAY_ID) {
        return false;
    }

    // For unknown types, persist if TTL >= 7 days
    uint64_t now = time(NULL);
    uint64_t ttl_seconds = (expires_at > now) ? (expires_at - now) : 0;
    return (ttl_seconds >= 7 * 24 * 3600);
}

int dht_value_storage_put(dht_value_storage_t *storage,
                           const dht_value_metadata_t *metadata) {
    if (!storage || !metadata) {
        return -1;
    }

    // Filter: only persist critical values
    if (!dht_value_storage_should_persist(metadata->value_type, metadata->expires_at)) {
        return 0;  // Success (but not stored)
    }

    pthread_mutex_lock(&storage->mutex);

    // Convert key hash to hex
    char key_hex[256];
    hash_to_hex(metadata->key_hash, metadata->key_hash_len, key_hex);

    // Prepare INSERT statement
    sqlite3_stmt *stmt;
    const char *sql = "INSERT OR REPLACE INTO dht_values "
                      "(key_hash, value_data, value_type, created_at, expires_at) "
                      "VALUES (?, ?, ?, ?, ?)";

    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "PUT prepare failed: %s", sqlite3_errmsg(storage->db));
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    // Bind parameters
    sqlite3_bind_text(stmt, 1, key_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, metadata->value_data, metadata->value_data_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, metadata->value_type);
    sqlite3_bind_int64(stmt, 4, metadata->created_at);
    if (metadata->expires_at > 0) {
        sqlite3_bind_int64(stmt, 5, metadata->expires_at);
    } else {
        sqlite3_bind_null(stmt, 5);  // Permanent
    }

    // Execute
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "PUT execute failed: %s", sqlite3_errmsg(storage->db));
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    // Update stats
    storage->put_count++;

    // Recount total values (could be optimized with INSERT/UPDATE triggers)
    rc = sqlite3_prepare_v2(storage->db, "SELECT COUNT(*) FROM dht_values", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            storage->total_values = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    pthread_mutex_unlock(&storage->mutex);
    return 0;
}

int dht_value_storage_get(dht_value_storage_t *storage,
                           const uint8_t *key_hash,
                           size_t key_hash_len,
                           dht_value_metadata_t **results_out,
                           size_t *count_out) {
    if (!storage || !key_hash || !results_out || !count_out) {
        return -1;
    }

    *results_out = NULL;
    *count_out = 0;

    pthread_mutex_lock(&storage->mutex);

    // Convert key hash to hex
    char key_hex[256];
    hash_to_hex(key_hash, key_hash_len, key_hex);

    // Query values
    sqlite3_stmt *stmt;
    const char *sql = "SELECT value_data, value_type, created_at, expires_at "
                      "FROM dht_values "
                      "WHERE key_hash = ? AND (expires_at IS NULL OR expires_at > ?)";

    uint64_t now = time(NULL);
    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "GET prepare failed: %s", sqlite3_errmsg(storage->db));
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, now);

    // Count results
    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        storage->get_count++;
        pthread_mutex_unlock(&storage->mutex);
        return 0;  // No results
    }

    // Allocate results
    dht_value_metadata_t *results = (dht_value_metadata_t*)calloc(count, sizeof(dht_value_metadata_t));
    if (!results) {
        sqlite3_finalize(stmt);
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    // Fetch results
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        // Copy value data
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);

        results[i].value_data = (uint8_t*)malloc(blob_len);
        if (results[i].value_data) {
            memcpy((void*)results[i].value_data, blob, blob_len);
            results[i].value_data_len = blob_len;
        }

        results[i].value_type = sqlite3_column_int(stmt, 1);
        results[i].created_at = sqlite3_column_int64(stmt, 2);

        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            results[i].expires_at = sqlite3_column_int64(stmt, 3);
        } else {
            results[i].expires_at = 0;  // Permanent
        }

        // Copy key hash
        results[i].key_hash = (uint8_t*)malloc(key_hash_len);
        if (results[i].key_hash) {
            memcpy((void*)results[i].key_hash, key_hash, key_hash_len);
            results[i].key_hash_len = key_hash_len;
        }

        i++;
    }

    sqlite3_finalize(stmt);
    storage->get_count++;
    pthread_mutex_unlock(&storage->mutex);

    *results_out = results;
    *count_out = i;
    return 0;
}

void dht_value_storage_free_results(dht_value_metadata_t *results, size_t count) {
    if (!results) return;

    for (size_t i = 0; i < count; i++) {
        if (results[i].key_hash) {
            free((void*)results[i].key_hash);
        }
        if (results[i].value_data) {
            free((void*)results[i].value_data);
        }
    }

    free(results);
}

int dht_value_storage_cleanup(dht_value_storage_t *storage) {
    if (!storage) {
        return -1;
    }

    pthread_mutex_lock(&storage->mutex);

    uint64_t now = time(NULL);

    // Delete expired values
    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM dht_values WHERE expires_at IS NOT NULL AND expires_at < ?";

    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Cleanup prepare failed: %s", sqlite3_errmsg(storage->db));
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, now);

    rc = sqlite3_step(stmt);
    int deleted = sqlite3_changes(storage->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Cleanup execute failed: %s", sqlite3_errmsg(storage->db));
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    // Update stats
    storage->last_cleanup_time = now;

    // Recount total values
    rc = sqlite3_prepare_v2(storage->db, "SELECT COUNT(*) FROM dht_values", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            storage->total_values = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    pthread_mutex_unlock(&storage->mutex);

    QGP_LOG_DEBUG(LOG_TAG, "Cleanup: deleted %d expired values", deleted);
    return deleted;
}

/**
 * @brief Background republish worker function
 *
 * CRITICAL FIX (2025-11-25): Now uses dht_republish_packed() to preserve signatures.
 * Previously used dht_put_ttl() which created NEW unsigned values, losing signatures.
 * The stored value_data is now a full serialized dht::Value (from getPacked()).
 *
 * CRITICAL FIX (2026-01-12): Wait for DHT peers before republishing.
 * Previously republished immediately on startup, before connecting to other nodes.
 * If all bootstrap nodes restart simultaneously, values were published to zero peers
 * and lost forever. Now waits up to 60 seconds for at least 1 peer connection.
 */
static void republish_worker(dht_value_storage_t *storage, dht_context_t *ctx) {
    QGP_LOG_INFO(LOG_TAG, "Republish thread started (signature-preserving mode)");

    pthread_mutex_lock(&storage->mutex);
    storage->republish_in_progress = true;
    pthread_mutex_unlock(&storage->mutex);

    // CRITICAL: Wait for DHT to connect to at least 1 peer before republishing
    // This prevents data loss when all bootstrap nodes restart simultaneously
    QGP_LOG_INFO(LOG_TAG, "Waiting for DHT peers before republishing...");
    int wait_seconds = 0;
    const int max_wait_seconds = 60;  // Wait up to 60 seconds for peers

    while (wait_seconds < max_wait_seconds) {
        if (dht_context_is_ready(ctx)) {
            QGP_LOG_INFO(LOG_TAG, "DHT connected to peers after %d seconds, starting republish", wait_seconds);
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        wait_seconds++;

        if (wait_seconds % 10 == 0) {
            QGP_LOG_INFO(LOG_TAG, "Still waiting for DHT peers... (%d/%d seconds)", wait_seconds, max_wait_seconds);
        }
    }

    if (wait_seconds >= max_wait_seconds) {
        QGP_LOG_WARN(LOG_TAG, "Timed out waiting for DHT peers after %d seconds, proceeding anyway", max_wait_seconds);
    }

    // Query only LATEST version per key (not all versions)
    sqlite3_stmt *stmt;
    const char *sql = "SELECT key_hash, value_data, value_type, created_at, expires_at "
                      "FROM dht_values "
                      "WHERE (expires_at IS NULL OR expires_at > ?) "
                      "  AND created_at = ("
                      "    SELECT MAX(created_at) "
                      "    FROM dht_values AS dv2 "
                      "    WHERE dv2.key_hash = dht_values.key_hash"
                      "  )";

    uint64_t now = time(NULL);

    pthread_mutex_lock(&storage->mutex);
    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    pthread_mutex_unlock(&storage->mutex);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Republish query failed");
        pthread_mutex_lock(&storage->mutex);
        storage->republish_in_progress = false;
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return;
    }

    pthread_mutex_lock(&storage->mutex);
    sqlite3_bind_int64(stmt, 1, now);
    pthread_mutex_unlock(&storage->mutex);

    size_t count = 0;
    size_t skipped = 0;
    size_t failed = 0;

    // Republish each value
    while (true) {
        pthread_mutex_lock(&storage->mutex);
        int step_rc = sqlite3_step(stmt);
        pthread_mutex_unlock(&storage->mutex);

        if (step_rc != SQLITE_ROW) {
            break;
        }

        pthread_mutex_lock(&storage->mutex);

        const char *key_hex = (const char*)sqlite3_column_text(stmt, 0);
        const void *packed_blob = sqlite3_column_blob(stmt, 1);
        int packed_len = sqlite3_column_bytes(stmt, 1);
        uint32_t value_type = sqlite3_column_int(stmt, 2);
        uint64_t expires_at = 0;

        if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) {
            expires_at = sqlite3_column_int64(stmt, 4);
        }

        // Copy key and packed data (need to free mutex before DHT operation)
        char key_hex_copy[256] = {0};
        strncpy(key_hex_copy, key_hex, sizeof(key_hex_copy) - 1);

        uint8_t *packed_copy = (uint8_t*)malloc(packed_len);
        if (packed_copy) {
            memcpy(packed_copy, packed_blob, packed_len);
        }

        pthread_mutex_unlock(&storage->mutex);

        if (!packed_copy) {
            QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed during republish");
            continue;
        }

        // Check if value has expired
        if (expires_at > 0) {
            uint64_t current_time = time(NULL);
            if (expires_at <= current_time) {
                // Value expired, skip it
                free(packed_copy);
                skipped++;
                continue;
            }
        }

        // CRITICAL FIX: Use dht_republish_packed() to preserve signatures
        // The packed_copy contains a full serialized dht::Value including signature
        // key_hex is already the InfoHash as hex string (from key.toString() in store callback)
        //
        // CRITICAL FIX (2026-01-12): Retry failed republishes up to 3 times
        // If network is unstable during startup, retrying helps ensure data survives
        int put_result = -1;
        const int max_retries = 3;
        for (int retry = 0; retry < max_retries; retry++) {
            put_result = dht_republish_packed(ctx, key_hex_copy,
                                               packed_copy, packed_len);
            if (put_result == 0) {
                break;  // Success
            }

            // Wait before retry, with exponential backoff
            if (retry < max_retries - 1) {
                int delay_ms = 500 * (1 << retry);  // 500ms, 1000ms, 2000ms
                QGP_LOG_WARN(LOG_TAG, "Republish failed (attempt %d/%d), retrying in %dms...",
                             retry + 1, max_retries, delay_ms);
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));

                // Re-check DHT connectivity before retry
                if (!dht_context_is_ready(ctx)) {
                    QGP_LOG_WARN(LOG_TAG, "DHT disconnected, waiting for reconnect...");
                    int reconnect_wait = 0;
                    while (reconnect_wait < 30 && !dht_context_is_ready(ctx)) {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        reconnect_wait++;
                    }
                }
            }
        }

        free(packed_copy);

        if (put_result == 0) {
            count++;
        } else {
            failed++;
            QGP_LOG_ERROR(LOG_TAG, "Failed to republish value type=0x%x after %d attempts",
                          value_type, max_retries);
            pthread_mutex_lock(&storage->mutex);
            storage->error_count++;
            pthread_mutex_unlock(&storage->mutex);
        }

        // Rate limit: 100ms delay per value
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    pthread_mutex_lock(&storage->mutex);
    sqlite3_finalize(stmt);
    storage->republish_count = count;
    storage->republish_in_progress = false;
    pthread_mutex_unlock(&storage->mutex);

    if (failed > 0) {
        QGP_LOG_WARN(LOG_TAG, "Republish complete: %zu values OK, %zu FAILED (skipped %zu expired)", count, failed, skipped);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Republish complete: %zu values (skipped %zu expired)", count, skipped);
    }
}

int dht_value_storage_restore_async(dht_value_storage_t *storage, dht_context_t *ctx) {
    if (!storage || !ctx) {
        return -1;
    }

    // Launch background thread
    QGP_LOG_DEBUG(LOG_TAG, "Launching async republish...");

    try {
        storage->republish_thread = new std::thread(republish_worker, storage, ctx);
    } catch (const std::exception& e) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to launch republish thread: %s", e.what());
        pthread_mutex_lock(&storage->mutex);
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    return 0;
}

int dht_value_storage_get_stats(dht_value_storage_t *storage,
                                 dht_storage_stats_t *stats_out) {
    if (!storage || !stats_out) {
        return -1;
    }

    pthread_mutex_lock(&storage->mutex);

    stats_out->total_values = storage->total_values;
    stats_out->storage_size_bytes = get_file_size(storage->db_path);
    stats_out->put_count = storage->put_count;
    stats_out->get_count = storage->get_count;
    stats_out->republish_count = storage->republish_count;
    stats_out->error_count = storage->error_count;
    stats_out->last_cleanup_time = storage->last_cleanup_time;
    stats_out->republish_in_progress = storage->republish_in_progress;

    pthread_mutex_unlock(&storage->mutex);
    return 0;
}
