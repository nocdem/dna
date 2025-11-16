/**
 * @file dht_value_storage.cpp
 * @brief SQLite-backed persistent storage for DHT values (implementation)
 */

#include "dht_value_storage.h"
#include "../../../dht/core/dht_context.h"
#include <sqlite3.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <climits>
#include <iostream>
#include <thread>
#include <chrono>

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
 * @brief Helper: Convert hex string to binary bytes
 */
static size_t hex_to_bytes(const char *hex, uint8_t *bytes_out, size_t max_len) {
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;

    if (byte_len > max_len) {
        byte_len = max_len;
    }

    for (size_t i = 0; i < byte_len; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bytes_out[i]);
    }

    return byte_len;
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
        std::cerr << "[Storage] Schema creation failed: " << err_msg << std::endl;
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
        std::cerr << "[Storage] NULL database path" << std::endl;
        return NULL;
    }

    // Allocate structure
    dht_value_storage_t *storage = (dht_value_storage_t*)calloc(1, sizeof(dht_value_storage_t));
    if (!storage) {
        std::cerr << "[Storage] Memory allocation failed" << std::endl;
        return NULL;
    }

    // Initialize mutex
    pthread_mutex_init(&storage->mutex, NULL);

    // Copy path
    storage->db_path = strdup(db_path);

    // Open database
    int rc = sqlite3_open(db_path, &storage->db);
    if (rc != SQLITE_OK) {
        std::cerr << "[Storage] Failed to open database: " << sqlite3_errmsg(storage->db) << std::endl;
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

    std::cout << "[Storage] Initialized: " << db_path << std::endl;
    std::cout << "[Storage] Existing values: " << storage->total_values << std::endl;

    return storage;
}

void dht_value_storage_free(dht_value_storage_t *storage) {
    if (!storage) return;

    // Wait for republish thread
    if (storage->republish_thread) {
        std::cout << "[Storage] Waiting for republish thread to finish..." << std::endl;
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

    std::cout << "[Storage] Freed" << std::endl;
}

bool dht_value_storage_should_persist(uint32_t value_type, uint64_t expires_at) {
    // Persist PERMANENT values (expires_at == 0)
    if (expires_at == 0) {
        return true;
    }

    // Persist 365-day values
    if (value_type == DNA_TYPE_365DAY_ID) {
        return true;
    }

    // Skip 7-day ephemeral values
    if (value_type == DNA_TYPE_7DAY_ID) {
        return false;
    }

    // For unknown types, persist if TTL > 30 days
    uint64_t now = time(NULL);
    uint64_t ttl_seconds = (expires_at > now) ? (expires_at - now) : 0;
    return (ttl_seconds > 30 * 24 * 3600);
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
        std::cerr << "[Storage] PUT prepare failed: " << sqlite3_errmsg(storage->db) << std::endl;
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
        std::cerr << "[Storage] PUT execute failed: " << sqlite3_errmsg(storage->db) << std::endl;
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
        std::cerr << "[Storage] GET prepare failed: " << sqlite3_errmsg(storage->db) << std::endl;
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
        std::cerr << "[Storage] Cleanup prepare failed: " << sqlite3_errmsg(storage->db) << std::endl;
        storage->error_count++;
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, now);

    rc = sqlite3_step(stmt);
    int deleted = sqlite3_changes(storage->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        std::cerr << "[Storage] Cleanup execute failed: " << sqlite3_errmsg(storage->db) << std::endl;
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

    std::cout << "[Storage] Cleanup: deleted " << deleted << " expired values" << std::endl;
    return deleted;
}

/**
 * @brief Background republish worker function
 */
static void republish_worker(dht_value_storage_t *storage, dht_context_t *ctx) {
    std::cout << "[Storage] Republish thread started" << std::endl;

    pthread_mutex_lock(&storage->mutex);
    storage->republish_in_progress = true;
    pthread_mutex_unlock(&storage->mutex);

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
        std::cerr << "[Storage] Republish query failed" << std::endl;
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
        const void *value_blob = sqlite3_column_blob(stmt, 1);
        int value_len = sqlite3_column_bytes(stmt, 1);
        uint32_t value_type = sqlite3_column_int(stmt, 2);
        uint64_t expires_at = 0;

        if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) {
            expires_at = sqlite3_column_int64(stmt, 4);
        }

        // Copy data (need to free mutex before DHT operation)
        uint8_t *value_copy = (uint8_t*)malloc(value_len);
        if (value_copy) {
            memcpy(value_copy, value_blob, value_len);
        }

        pthread_mutex_unlock(&storage->mutex);

        if (!value_copy) {
            std::cerr << "[Storage] Memory allocation failed during republish" << std::endl;
            continue;
        }

        // Convert hex key back to bytes
        uint8_t key_bytes[256];
        size_t key_len = hex_to_bytes(key_hex, key_bytes, sizeof(key_bytes));

        // CRITICAL: Detect old format and skip to prevent double-hashing
        // Old formats: 40-char hex (20-byte) OR 80-char hex (40-byte) - stored before 2025-11-12 fix
        // New format: 128-char hex (64-byte SHA3-512 original key)
        size_t hex_len = strlen(key_hex);
        if (hex_len == 40 || hex_len == 80) {
            // Old format detected - DO NOT republish (would hash again → wrong key)
            std::cout << "[Storage] Skipping old-format entry (" << hex_len << "-char hex) - prevents double-hash bug" << std::endl;
            free(value_copy);
            continue;  // Skip this value
        } else if (hex_len < 128) {
            // Unknown short format - skip for safety
            std::cerr << "[Storage] Skipping unknown format entry (hex_len=" << hex_len << ")" << std::endl;
            free(value_copy);
            continue;
        }

        // Calculate TTL
        unsigned int ttl_seconds = UINT_MAX;  // Default: permanent
        if (expires_at > 0) {
            uint64_t current_time = time(NULL);
            if (expires_at > current_time) {
                ttl_seconds = (unsigned int)(expires_at - current_time);
            } else {
                // Value expired, skip it
                free(value_copy);
                continue;
            }
        }

        // Republish to DHT (only new format 64+ byte keys reach here)
        int put_result = dht_put_ttl(ctx, key_bytes, key_len, value_copy, value_len, ttl_seconds);

        free(value_copy);

        if (put_result == 0) {
            count++;
        } else {
            std::cerr << "[Storage] Failed to republish value (error " << put_result << ")" << std::endl;
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

    std::cout << "[Storage] Republish complete: " << count << " values" << std::endl;
}

int dht_value_storage_restore_async(dht_value_storage_t *storage, dht_context_t *ctx) {
    if (!storage || !ctx) {
        return -1;
    }

    // Launch background thread
    std::cout << "[Storage] Launching async republish..." << std::endl;

    try {
        storage->republish_thread = new std::thread(republish_worker, storage, ctx);
    } catch (const std::exception& e) {
        std::cerr << "[Storage] Failed to launch republish thread: " << e.what() << std::endl;
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
