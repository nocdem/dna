/**
 * Bootstrap Node Cache Implementation
 * SQLite-based local cache for discovered bootstrap nodes
 */

#include "bootstrap_cache.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <time.h>

#define LOG_TAG "BOOT_CACHE"

// Global database connection
static sqlite3 *g_bootstrap_db = NULL;

// SQL schema for bootstrap cache (v2: added connection_attempts)
static const char *CACHE_SCHEMA =
    "CREATE TABLE IF NOT EXISTS bootstrap_nodes ("
    "    ip TEXT NOT NULL,"
    "    port INTEGER NOT NULL,"
    "    node_id TEXT,"
    "    version TEXT,"
    "    last_seen INTEGER NOT NULL,"
    "    last_connected INTEGER DEFAULT 0,"
    "    connection_attempts INTEGER DEFAULT 0,"
    "    connection_failures INTEGER DEFAULT 0,"
    "    PRIMARY KEY (ip, port)"
    ");";

// Migration: add connection_attempts column if missing
static const char *MIGRATION_V2 =
    "ALTER TABLE bootstrap_nodes ADD COLUMN connection_attempts INTEGER DEFAULT 0;";

// Helper: Get default cache path (<data_dir>/bootstrap_cache.db)
static int get_default_cache_path(char *path_out, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        return -1;
    }

    snprintf(path_out, path_size, "%s/bootstrap_cache.db", data_dir);
    return 0;
}

int bootstrap_cache_init(const char *db_path) {
    if (g_bootstrap_db) {
        QGP_LOG_DEBUG(LOG_TAG, "Already initialized");
        return 0;
    }

    char default_path[512];
    if (!db_path) {
        if (get_default_cache_path(default_path, sizeof(default_path)) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot determine cache path");
            return -1;
        }
        db_path = default_path;
    }

    // Open with FULLMUTEX for thread safety (DHT callbacks + main thread)
    int rc = sqlite3_open_v2(db_path, &g_bootstrap_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s", sqlite3_errmsg(g_bootstrap_db));
        sqlite3_close(g_bootstrap_db);
        g_bootstrap_db = NULL;
        return -1;
    }

    // Android force-close recovery: Set busy timeout and force WAL checkpoint
    sqlite3_busy_timeout(g_bootstrap_db, 5000);
    sqlite3_wal_checkpoint(g_bootstrap_db, NULL);

    // Enable WAL mode for better concurrency
    sqlite3_exec(g_bootstrap_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);

    // Create tables
    char *err_msg = NULL;
    rc = sqlite3_exec(g_bootstrap_db, CACHE_SCHEMA, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create tables: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_bootstrap_db);
        g_bootstrap_db = NULL;
        return -1;
    }

    // Migration v2: add connection_attempts column (ignore error if already exists)
    sqlite3_exec(g_bootstrap_db, MIGRATION_V2, NULL, NULL, NULL);

    QGP_LOG_INFO(LOG_TAG, "Bootstrap cache initialized: %s", db_path);
    return 0;
}

void bootstrap_cache_cleanup(void) {
    if (g_bootstrap_db) {
        sqlite3_close(g_bootstrap_db);
        g_bootstrap_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Bootstrap cache cleanup complete");
    }
}

int bootstrap_cache_put(const char *ip, uint16_t port, const char *node_id,
                        const char *version, uint64_t last_seen) {
    if (!g_bootstrap_db || !ip) {
        return -1;
    }

    const char *sql =
        "INSERT INTO bootstrap_nodes (ip, port, node_id, version, last_seen) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(ip, port) DO UPDATE SET "
        "node_id = COALESCE(excluded.node_id, node_id), "
        "version = COALESCE(excluded.version, version), "
        "last_seen = excluded.last_seen";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_bootstrap_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare put: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, port);
    sqlite3_bind_text(stmt, 3, node_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, version, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)last_seen);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Cached node: %s:%d", ip, port);
    return 0;
}

int bootstrap_cache_get_best(size_t limit, bootstrap_cache_entry_t **nodes_out,
                             size_t *count_out) {
    if (!g_bootstrap_db || !nodes_out || !count_out) {
        return -1;
    }

    *nodes_out = NULL;
    *count_out = 0;

    // Sort by reliability ratio: failures/attempts (lower is better)
    // Nodes with 0 attempts go last, then sort by last_connected
    const char *sql =
        "SELECT ip, port, node_id, version, last_seen, last_connected, "
        "       connection_attempts, connection_failures "
        "FROM bootstrap_nodes "
        "ORDER BY "
        "  CASE WHEN connection_attempts = 0 THEN 1 ELSE 0 END, "
        "  CAST(connection_failures AS REAL) / NULLIF(connection_attempts, 1) ASC, "
        "  last_connected DESC "
        "LIMIT ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_bootstrap_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare get_best: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, (int)limit);

    // Count results first
    size_t capacity = limit;
    bootstrap_cache_entry_t *entries = calloc(capacity, sizeof(bootstrap_cache_entry_t));
    if (!entries) {
        sqlite3_finalize(stmt);
        return -1;
    }

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < capacity) {
        bootstrap_cache_entry_t *e = &entries[count];

        const char *ip = (const char *)sqlite3_column_text(stmt, 0);
        if (ip) {
            strncpy(e->ip, ip, sizeof(e->ip) - 1);
        }

        e->port = (uint16_t)sqlite3_column_int(stmt, 1);

        const char *node_id = (const char *)sqlite3_column_text(stmt, 2);
        if (node_id) {
            strncpy(e->node_id, node_id, sizeof(e->node_id) - 1);
        }

        const char *version = (const char *)sqlite3_column_text(stmt, 3);
        if (version) {
            strncpy(e->version, version, sizeof(e->version) - 1);
        }

        e->last_seen = (uint64_t)sqlite3_column_int64(stmt, 4);
        e->last_connected = (uint64_t)sqlite3_column_int64(stmt, 5);
        e->connection_attempts = sqlite3_column_int(stmt, 6);
        e->connection_failures = sqlite3_column_int(stmt, 7);

        count++;
    }

    sqlite3_finalize(stmt);

    if (count == 0) {
        free(entries);
        return 0;
    }

    *nodes_out = entries;
    *count_out = count;
    return 0;
}

int bootstrap_cache_get_all(bootstrap_cache_entry_t **nodes_out, size_t *count_out) {
    if (!g_bootstrap_db || !nodes_out || !count_out) {
        return -1;
    }

    *nodes_out = NULL;
    *count_out = 0;

    // First count entries
    const char *count_sql = "SELECT COUNT(*) FROM bootstrap_nodes";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_bootstrap_db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    size_t total = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        total = (size_t)sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (total == 0) {
        return 0;
    }

    // Allocate array
    bootstrap_cache_entry_t *entries = calloc(total, sizeof(bootstrap_cache_entry_t));
    if (!entries) {
        return -1;
    }

    // Fetch all
    const char *sql =
        "SELECT ip, port, node_id, version, last_seen, last_connected, "
        "       connection_attempts, connection_failures "
        "FROM bootstrap_nodes";

    rc = sqlite3_prepare_v2(g_bootstrap_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(entries);
        return -1;
    }

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < total) {
        bootstrap_cache_entry_t *e = &entries[count];

        const char *ip = (const char *)sqlite3_column_text(stmt, 0);
        if (ip) {
            strncpy(e->ip, ip, sizeof(e->ip) - 1);
        }

        e->port = (uint16_t)sqlite3_column_int(stmt, 1);

        const char *node_id = (const char *)sqlite3_column_text(stmt, 2);
        if (node_id) {
            strncpy(e->node_id, node_id, sizeof(e->node_id) - 1);
        }

        const char *version = (const char *)sqlite3_column_text(stmt, 3);
        if (version) {
            strncpy(e->version, version, sizeof(e->version) - 1);
        }

        e->last_seen = (uint64_t)sqlite3_column_int64(stmt, 4);
        e->last_connected = (uint64_t)sqlite3_column_int64(stmt, 5);
        e->connection_attempts = sqlite3_column_int(stmt, 6);
        e->connection_failures = sqlite3_column_int(stmt, 7);

        count++;
    }

    sqlite3_finalize(stmt);

    *nodes_out = entries;
    *count_out = count;
    return 0;
}

int bootstrap_cache_mark_connected(const char *ip, uint16_t port) {
    if (!g_bootstrap_db || !ip) {
        return -1;
    }

    // Increment attempts, update last_connected (failures stays as total)
    const char *sql =
        "UPDATE bootstrap_nodes SET "
        "last_connected = ?, connection_attempts = connection_attempts + 1 "
        "WHERE ip = ? AND port = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_bootstrap_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare mark_connected: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, port);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to mark connected: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Marked connected: %s:%d", ip, port);
    return 0;
}

int bootstrap_cache_mark_failed(const char *ip, uint16_t port) {
    if (!g_bootstrap_db || !ip) {
        return -1;
    }

    // Increment both attempts and failures
    const char *sql =
        "UPDATE bootstrap_nodes SET "
        "connection_attempts = connection_attempts + 1, "
        "connection_failures = connection_failures + 1 "
        "WHERE ip = ? AND port = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_bootstrap_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare mark_failed: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, port);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to mark failed: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Marked failed: %s:%d", ip, port);
    return 0;
}

int bootstrap_cache_expire(uint64_t max_age_seconds) {
    if (!g_bootstrap_db) {
        return -1;
    }

    const char *sql = "DELETE FROM bootstrap_nodes WHERE last_seen < ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_bootstrap_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare expire: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    uint64_t cutoff = (uint64_t)time(NULL) - max_age_seconds;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)cutoff);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to expire: %s", sqlite3_errmsg(g_bootstrap_db));
        return -1;
    }

    int deleted = sqlite3_changes(g_bootstrap_db);
    if (deleted > 0) {
        QGP_LOG_INFO(LOG_TAG, "Expired %d stale bootstrap nodes", deleted);
    }
    return deleted;
}

int bootstrap_cache_count(void) {
    if (!g_bootstrap_db) {
        return -1;
    }

    const char *sql = "SELECT COUNT(*) FROM bootstrap_nodes";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_bootstrap_db, sql, -1, &stmt, NULL);
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

bool bootstrap_cache_exists(const char *ip, uint16_t port) {
    if (!g_bootstrap_db || !ip) {
        return false;
    }

    const char *sql = "SELECT 1 FROM bootstrap_nodes WHERE ip = ? AND port = ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_bootstrap_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, port);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return exists;
}

void bootstrap_cache_free_entries(bootstrap_cache_entry_t *entries) {
    free(entries);
}
