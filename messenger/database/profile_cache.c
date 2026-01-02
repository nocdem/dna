/**
 * Profile Cache Database Implementation
 * GLOBAL SQLite cache for user profiles (not per-identity)
 *
 * Profiles are public DHT data - no reason to cache per-identity.
 * Global cache allows prefetching before identity is loaded.
 *
 * @file profile_cache.c
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#include "profile_cache.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#endif

#define LOG_TAG "DB_PROFILE"

static sqlite3 *g_db = NULL;

// Forward declaration for lazy init
int profile_cache_init(void);

// Get global database path
static int get_db_path(char *path_out, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    // v0.3.0: Flat structure - db/profiles.db
    snprintf(path_out, path_size, "%s/db/profiles.db", data_dir);
    return 0;
}

/**
 * Initialize global profile cache
 */
int profile_cache_init(void) {
    // Already initialized
    if (g_db) {
        return 0;
    }

    // Get global database path
    char db_path[1024];
    if (get_db_path(db_path, sizeof(db_path)) != 0) {
        return -1;
    }

    // v0.3.0: Ensure db/ directory exists
    const char *data_dir = qgp_platform_app_data_dir();
    if (data_dir) {
        char db_dir[1024];
        snprintf(db_dir, sizeof(db_dir), "%s/db", data_dir);
        mkdir(db_dir, 0755);
    }

    QGP_LOG_INFO(LOG_TAG, "Opening database: %s\n", db_path);

    // Open database
    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    // MIGRATION: Check if old schema exists (without fingerprint column)
    // Query to check if fingerprint column exists
    const char *check_sql = "SELECT fingerprint FROM profiles LIMIT 1;";
    sqlite3_stmt *check_stmt = NULL;
    rc = sqlite3_prepare_v2(g_db, check_sql, -1, &check_stmt, NULL);

    if (rc != SQLITE_OK) {
        // Table doesn't exist or has wrong schema - drop and recreate
        QGP_LOG_INFO(LOG_TAG, "Migrating to new schema (fingerprint column)\n");
        char *err_msg = NULL;
        sqlite3_exec(g_db, "DROP TABLE IF EXISTS profiles;", NULL, NULL, &err_msg);
        if (err_msg) {
            QGP_LOG_ERROR(LOG_TAG, "Migration warning: %s\n", err_msg);
            sqlite3_free(err_msg);
        }
    } else {
        sqlite3_finalize(check_stmt);
    }

    // Create table if it doesn't exist (Phase 5: Unified Identity)
    const char *sql =
        "CREATE TABLE IF NOT EXISTS profiles ("
        "    fingerprint TEXT PRIMARY KEY,"
        "    identity_json TEXT NOT NULL,"
        "    cached_at INTEGER NOT NULL"
        ");";

    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    // Create index on cached_at for TTL queries
    const char *index_sql = "CREATE INDEX IF NOT EXISTS idx_cached_at ON profiles(cached_at);";
    rc = sqlite3_exec(g_db, index_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create index: %s\n", err_msg);
        sqlite3_free(err_msg);
        // Non-fatal, continue
    }

    QGP_LOG_INFO(LOG_TAG, "Global profile cache initialized\n");
    return 0;
}

/**
 * Add or update profile in cache (Phase 5: Unified Identity)
 */
int profile_cache_add_or_update(const char *user_fingerprint, const dna_unified_identity_t *identity) {
    if (profile_cache_init() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize database\n");
        return -1;
    }

    if (!user_fingerprint || !identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // Serialize identity to JSON
    char *identity_json = dna_identity_to_json(identity);
    if (!identity_json) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize identity to JSON\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO profiles "
        "(fingerprint, identity_json, cached_at) "
        "VALUES (?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        free(identity_json);
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, identity_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(identity_json);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert/update: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Cached identity for: %s\n", user_fingerprint);
    return 0;
}

/**
 * Get profile from cache (Phase 5: Unified Identity)
 */
int profile_cache_get(const char *user_fingerprint, dna_unified_identity_t **identity_out, uint64_t *cached_at_out) {
    if (profile_cache_init() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize database\n");
        return -1;
    }

    if (!user_fingerprint || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    const char *sql =
        "SELECT identity_json, cached_at "
        "FROM profiles WHERE fingerprint = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  // Not found
    }

    // Read JSON and deserialize
    const char *identity_json = (const char*)sqlite3_column_text(stmt, 0);
    if (!identity_json) {
        QGP_LOG_ERROR(LOG_TAG, "NULL identity_json in database\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    dna_unified_identity_t *identity = NULL;
    int parse_result = dna_identity_from_json(identity_json, &identity);
    if (parse_result != 0 || !identity) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse identity JSON\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (cached_at_out) {
        *cached_at_out = sqlite3_column_int64(stmt, 1);
    }

    sqlite3_finalize(stmt);
    *identity_out = identity;
    return 0;
}

/**
 * Check if profile exists in cache
 */
bool profile_cache_exists(const char *user_fingerprint) {
    if (!user_fingerprint || profile_cache_init() != 0) {
        return false;
    }

    const char *sql = "SELECT COUNT(*) FROM profiles WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = (sqlite3_column_int(stmt, 0) > 0);
    }

    sqlite3_finalize(stmt);
    return exists;
}

/**
 * Check if cached profile is expired (>7 days old)
 */
bool profile_cache_is_expired(const char *user_fingerprint) {
    if (!user_fingerprint || profile_cache_init() != 0) {
        return true;  // Treat as expired if error
    }

    const char *sql = "SELECT cached_at FROM profiles WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return true;
    }

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);

    bool expired = true;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t cached_at = sqlite3_column_int64(stmt, 0);
        uint64_t now = (uint64_t)time(NULL);
        uint64_t age = now - cached_at;

        expired = (age >= PROFILE_CACHE_TTL_SECONDS);
    }

    sqlite3_finalize(stmt);
    return expired;
}

/**
 * Delete profile from cache
 */
int profile_cache_delete(const char *user_fingerprint) {
    if (profile_cache_init() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize database\n");
        return -1;
    }

    if (!user_fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint\n");
        return -1;
    }

    const char *sql = "DELETE FROM profiles WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, user_fingerprint, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

/**
 * Get list of all expired profiles
 */
int profile_cache_list_expired(char ***fingerprints_out, size_t *count_out) {
    if (!fingerprints_out || !count_out || profile_cache_init() != 0) {
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    uint64_t cutoff = now - PROFILE_CACHE_TTL_SECONDS;

    const char *sql = "SELECT fingerprint FROM profiles WHERE cached_at < ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, cutoff);

    // Count results
    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        *fingerprints_out = NULL;
        *count_out = 0;
        sqlite3_finalize(stmt);
        return 0;
    }

    // Allocate array
    char **fingerprints = malloc(count * sizeof(char*));
    if (!fingerprints) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fill array
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        const char *fp = (const char*)sqlite3_column_text(stmt, 0);
        fingerprints[i] = strdup(fp ? fp : "");
        i++;
    }

    sqlite3_finalize(stmt);

    *fingerprints_out = fingerprints;
    *count_out = count;
    return 0;
}

/**
 * Get all cached profiles
 */
int profile_cache_list_all(profile_cache_list_t **list_out) {
    if (!list_out || profile_cache_init() != 0) {
        return -1;
    }

    const char *sql = "SELECT fingerprint, identity_json, cached_at FROM profiles;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    // Count results
    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    // Allocate list
    profile_cache_list_t *list = malloc(sizeof(profile_cache_list_t));
    if (!list) {
        sqlite3_finalize(stmt);
        return -1;
    }

    list->entries = NULL;
    list->count = 0;

    if (count == 0) {
        *list_out = list;
        sqlite3_finalize(stmt);
        return 0;
    }

    list->entries = malloc(count * sizeof(profile_cache_entry_t));
    if (!list->entries) {
        free(list);
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fill entries
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        profile_cache_entry_t *entry = &list->entries[i];
        memset(entry, 0, sizeof(profile_cache_entry_t));

        // Read fingerprint
        const char *fp = (const char*)sqlite3_column_text(stmt, 0);
        if (fp) strncpy(entry->fingerprint, fp, sizeof(entry->fingerprint) - 1);

        // Parse identity JSON
        const char *identity_json = (const char*)sqlite3_column_text(stmt, 1);
        if (identity_json) {
            dna_unified_identity_t *identity = NULL;
            if (dna_identity_from_json(identity_json, &identity) == 0 && identity) {
                entry->identity = identity;
            } else {
                // Skip entries with invalid JSON
                QGP_LOG_ERROR(LOG_TAG, "Skipping entry with invalid JSON: %s\n", fp);
                continue;
            }
        }

        // Read cached_at
        entry->cached_at = sqlite3_column_int64(stmt, 2);

        i++;
    }

    sqlite3_finalize(stmt);

    list->count = i;
    *list_out = list;
    return 0;
}

/**
 * Get profile count
 */
int profile_cache_count(void) {
    if (profile_cache_init() != 0) {
        return -1;
    }

    const char *sql = "SELECT COUNT(*) FROM profiles;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

/**
 * Clear all cached profiles
 */
int profile_cache_clear_all(void) {
    if (profile_cache_init() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize database\n");
        return -1;
    }

    const char *sql = "DELETE FROM profiles;";
    char *err_msg = NULL;

    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to clear profiles: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Cleared all profiles\n");
    return 0;
}

/**
 * Free profile list (Phase 5: Unified Identity)
 */
void profile_cache_free_list(profile_cache_list_t *list) {
    if (list) {
        if (list->entries) {
            // Free each identity
            for (size_t i = 0; i < list->count; i++) {
                if (list->entries[i].identity) {
                    dna_identity_free(list->entries[i].identity);
                }
            }
            free(list->entries);
        }
        free(list);
    }
}

/**
 * Close profile cache database
 */
void profile_cache_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Closed database\n");
    }
}
