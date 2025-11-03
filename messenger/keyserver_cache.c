/**
 * Keyserver Cache Implementation
 * Phase 4: SQLite-based local cache for public keys
 */

#include "keyserver_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Default TTL: 7 days = 604800 seconds
#define DEFAULT_TTL_SECONDS 604800

// Global database connection
static sqlite3 *g_cache_db = NULL;

// SQL schema for keyserver cache
static const char *CACHE_SCHEMA =
    "CREATE TABLE IF NOT EXISTS keyserver_cache ("
    "    identity TEXT PRIMARY KEY,"
    "    dilithium_pubkey BLOB NOT NULL,"
    "    kyber_pubkey BLOB NOT NULL,"
    "    cached_at INTEGER NOT NULL,"  // Unix timestamp
    "    ttl_seconds INTEGER NOT NULL DEFAULT 604800"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_cached_at ON keyserver_cache(cached_at);";

// Helper: Get default cache path (~/.dna/keyserver_cache.db)
static void get_default_cache_path(char *path_out, size_t path_size) {
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE");  // Windows fallback
        if (!home) {
            home = "/tmp";  // Last resort fallback
        }
    }

    snprintf(path_out, path_size, "%s/.dna", home);

    // Create ~/.dna directory if it doesn't exist
    struct stat st = {0};
    if (stat(path_out, &st) == -1) {
#ifdef _WIN32
        mkdir(path_out);  // Windows mkdir() takes only 1 argument
#else
        mkdir(path_out, 0700);  // Unix mkdir() takes mode
#endif
    }

    snprintf(path_out, path_size, "%s/.dna/keyserver_cache.db", home);
}

// Initialize keyserver cache
int keyserver_cache_init(const char *db_path) {
    if (g_cache_db) {
        fprintf(stderr, "[CACHE] Already initialized\n");
        return 0;
    }

    char default_path[512];
    if (!db_path) {
        get_default_cache_path(default_path, sizeof(default_path));
        db_path = default_path;
    }

    int rc = sqlite3_open(db_path, &g_cache_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CACHE] Failed to open database: %s\n", sqlite3_errmsg(g_cache_db));
        sqlite3_close(g_cache_db);
        g_cache_db = NULL;
        return -1;
    }

    // Enable WAL mode for better concurrency
    sqlite3_exec(g_cache_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);

    // Create tables
    char *err_msg = NULL;
    rc = sqlite3_exec(g_cache_db, CACHE_SCHEMA, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CACHE] Failed to create tables: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_cache_db);
        g_cache_db = NULL;
        return -1;
    }

    printf("[CACHE] Initialized: %s\n", db_path);
    return 0;
}

// Cleanup keyserver cache
void keyserver_cache_cleanup(void) {
    if (g_cache_db) {
        sqlite3_close(g_cache_db);
        g_cache_db = NULL;
        printf("[CACHE] Cleanup complete\n");
    }
}

// Get cached public key
int keyserver_cache_get(const char *identity, keyserver_cache_entry_t **entry_out) {
    if (!g_cache_db || !identity || !entry_out) {
        fprintf(stderr, "[CACHE] Invalid arguments to get\n");
        return -1;
    }

    *entry_out = NULL;

    const char *sql = "SELECT dilithium_pubkey, kyber_pubkey, cached_at, ttl_seconds "
                     "FROM keyserver_cache WHERE identity = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_cache_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CACHE] Failed to prepare query: %s\n", sqlite3_errmsg(g_cache_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  // Not found
    }

    // Extract data
    const void *dilithium_blob = sqlite3_column_blob(stmt, 0);
    int dilithium_len = sqlite3_column_bytes(stmt, 0);
    const void *kyber_blob = sqlite3_column_blob(stmt, 1);
    int kyber_len = sqlite3_column_bytes(stmt, 1);
    uint64_t cached_at = sqlite3_column_int64(stmt, 2);
    uint64_t ttl_seconds = sqlite3_column_int64(stmt, 3);

    // Check if expired
    uint64_t now = time(NULL);
    if (now > cached_at + ttl_seconds) {
        sqlite3_finalize(stmt);
        printf("[CACHE] Entry expired for '%s'\n", identity);
        return -2;  // Expired
    }

    // Allocate entry
    keyserver_cache_entry_t *entry = malloc(sizeof(keyserver_cache_entry_t));
    if (!entry) {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(entry, 0, sizeof(keyserver_cache_entry_t));
    strncpy(entry->identity, identity, sizeof(entry->identity) - 1);

    // Copy Dilithium key
    entry->dilithium_pubkey = malloc(dilithium_len);
    if (!entry->dilithium_pubkey) {
        free(entry);
        sqlite3_finalize(stmt);
        return -1;
    }
    memcpy(entry->dilithium_pubkey, dilithium_blob, dilithium_len);
    entry->dilithium_pubkey_len = dilithium_len;

    // Copy Kyber key
    entry->kyber_pubkey = malloc(kyber_len);
    if (!entry->kyber_pubkey) {
        free(entry->dilithium_pubkey);
        free(entry);
        sqlite3_finalize(stmt);
        return -1;
    }
    memcpy(entry->kyber_pubkey, kyber_blob, kyber_len);
    entry->kyber_pubkey_len = kyber_len;

    entry->cached_at = cached_at;
    entry->ttl_seconds = ttl_seconds;

    sqlite3_finalize(stmt);

    *entry_out = entry;
    printf("[CACHE] Hit: '%s' (cached %ld seconds ago)\n", identity, (long)(now - cached_at));
    return 0;
}

// Store public key in cache
int keyserver_cache_put(
    const char *identity,
    const uint8_t *dilithium_pubkey,
    size_t dilithium_pubkey_len,
    const uint8_t *kyber_pubkey,
    size_t kyber_pubkey_len,
    uint64_t ttl_seconds
) {
    if (!g_cache_db || !identity || !dilithium_pubkey || !kyber_pubkey) {
        fprintf(stderr, "[CACHE] Invalid arguments to put\n");
        return -1;
    }

    if (ttl_seconds == 0) {
        ttl_seconds = DEFAULT_TTL_SECONDS;
    }

    const char *sql = "INSERT OR REPLACE INTO keyserver_cache "
                     "(identity, dilithium_pubkey, kyber_pubkey, cached_at, ttl_seconds) "
                     "VALUES (?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_cache_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CACHE] Failed to prepare insert: %s\n", sqlite3_errmsg(g_cache_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, dilithium_pubkey, dilithium_pubkey_len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, kyber_pubkey, kyber_pubkey_len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, time(NULL));
    sqlite3_bind_int64(stmt, 5, ttl_seconds);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[CACHE] Failed to insert: %s\n", sqlite3_errmsg(g_cache_db));
        return -1;
    }

    printf("[CACHE] Stored: '%s' (TTL: %ld seconds)\n", identity, (long)ttl_seconds);
    return 0;
}

// Delete cached entry
int keyserver_cache_delete(const char *identity) {
    if (!g_cache_db || !identity) {
        fprintf(stderr, "[CACHE] Invalid arguments to delete\n");
        return -1;
    }

    const char *sql = "DELETE FROM keyserver_cache WHERE identity = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_cache_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CACHE] Failed to prepare delete: %s\n", sqlite3_errmsg(g_cache_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[CACHE] Failed to delete: %s\n", sqlite3_errmsg(g_cache_db));
        return -1;
    }

    printf("[CACHE] Deleted: '%s'\n", identity);
    return 0;
}

// Clear all expired entries
int keyserver_cache_expire_old(void) {
    if (!g_cache_db) {
        fprintf(stderr, "[CACHE] Not initialized\n");
        return -1;
    }

    uint64_t now = time(NULL);

    // Delete entries where cached_at + ttl_seconds < now
    const char *sql = "DELETE FROM keyserver_cache WHERE cached_at + ttl_seconds < ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_cache_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[CACHE] Failed to prepare expire: %s\n", sqlite3_errmsg(g_cache_db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[CACHE] Failed to expire: %s\n", sqlite3_errmsg(g_cache_db));
        return -1;
    }

    int deleted = sqlite3_changes(g_cache_db);
    if (deleted > 0) {
        printf("[CACHE] Expired %d old entries\n", deleted);
    }

    return deleted;
}

// Check if cached entry exists and is valid
bool keyserver_cache_exists(const char *identity) {
    if (!g_cache_db || !identity) {
        return false;
    }

    const char *sql = "SELECT cached_at, ttl_seconds FROM keyserver_cache WHERE identity = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_cache_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    uint64_t cached_at = sqlite3_column_int64(stmt, 0);
    uint64_t ttl_seconds = sqlite3_column_int64(stmt, 1);
    sqlite3_finalize(stmt);

    uint64_t now = time(NULL);
    return (now <= cached_at + ttl_seconds);
}

// Get cache statistics
int keyserver_cache_stats(int *total_entries, int *expired_entries) {
    if (!g_cache_db || !total_entries || !expired_entries) {
        fprintf(stderr, "[CACHE] Invalid arguments to stats\n");
        return -1;
    }

    // Get total
    const char *total_sql = "SELECT COUNT(*) FROM keyserver_cache";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_cache_db, total_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *total_entries = sqlite3_column_int(stmt, 0);
    } else {
        *total_entries = 0;
    }
    sqlite3_finalize(stmt);

    // Get expired
    uint64_t now = time(NULL);
    const char *expired_sql = "SELECT COUNT(*) FROM keyserver_cache WHERE cached_at + ttl_seconds < ?";
    rc = sqlite3_prepare_v2(g_cache_db, expired_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, now);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *expired_entries = sqlite3_column_int(stmt, 0);
    } else {
        *expired_entries = 0;
    }
    sqlite3_finalize(stmt);

    return 0;
}

// Free cache entry
void keyserver_cache_free_entry(keyserver_cache_entry_t *entry) {
    if (!entry) return;

    if (entry->dilithium_pubkey) {
        free(entry->dilithium_pubkey);
    }
    if (entry->kyber_pubkey) {
        free(entry->kyber_pubkey);
    }

    free(entry);
}
