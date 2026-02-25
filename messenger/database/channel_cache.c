/**
 * Channel Cache Database Implementation
 * GLOBAL SQLite cache for channel metadata and posts (not per-identity)
 *
 * Channel data is public DHT data - no reason to cache per-identity.
 * Global cache allows fast channel rendering without DHT round-trips.
 *
 * @file channel_cache.c
 * @author DNA Messenger Team
 * @date 2026-02-26
 */

#include "channel_cache.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#ifdef _WIN32
/* No additional includes needed */
#else
#include <unistd.h>
#endif

#define LOG_TAG "CHANNEL_CACHE"

static sqlite3 *g_db = NULL;

/* ---- Internal helpers -------------------------------------------------- */

/**
 * Get database path: <data_dir>/channel_cache.db
 * Stored at root level (same pattern as feed_cache.db)
 */
static int get_db_path(char *path_out, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    snprintf(path_out, path_size, "%s/channel_cache.db", data_dir);
    return 0;
}

/**
 * Create schema (tables + indexes)
 */
static int create_schema(void) {
    const char *schema_sql =
        /* ---- channels -------------------------------------------------- */
        "CREATE TABLE IF NOT EXISTS channels ("
        "    uuid         TEXT PRIMARY KEY,"
        "    channel_json TEXT NOT NULL,"
        "    created_at   INTEGER,"
        "    deleted      INTEGER DEFAULT 0,"
        "    last_cached  INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_channels_cached "
        "    ON channels(last_cached);"

        /* ---- channel_posts --------------------------------------------- */
        "CREATE TABLE IF NOT EXISTS channel_posts ("
        "    channel_uuid TEXT PRIMARY KEY,"
        "    posts_json   TEXT NOT NULL,"
        "    post_count   INTEGER DEFAULT 0,"
        "    last_cached  INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_channel_posts_cached "
        "    ON channel_posts(last_cached);"

        /* ---- cache_meta ------------------------------------------------ */
        "CREATE TABLE IF NOT EXISTS cache_meta ("
        "    cache_key    TEXT PRIMARY KEY,"
        "    last_fetched INTEGER NOT NULL"
        ");";

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create schema: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

/* ---- Lifecycle --------------------------------------------------------- */

int channel_cache_init(void) {
    /* Already initialized */
    if (g_db) {
        return 0;
    }

    /* Database path */
    char db_path[1024];
    if (get_db_path(db_path, sizeof(db_path)) != 0) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Opening database: %s\n", db_path);

    /* Open with FULLMUTEX for thread safety (DHT callbacks + main thread) */
    int rc = sqlite3_open_v2(db_path, &g_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    /* Android force-close recovery: busy timeout + WAL checkpoint */
    sqlite3_busy_timeout(g_db, 5000);
    sqlite3_wal_checkpoint(g_db, NULL);

    /* Enable WAL mode for better concurrency and crash resilience
     * (matches feed_cache pattern - proven to work on Android) */
    sqlite3_exec(g_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);

    /* Create schema */
    if (create_schema() != 0) {
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Channel cache initialized\n");
    return 0;
}

void channel_cache_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Closed database\n");
    }
}

/* ---- Channel metadata operations --------------------------------------- */

int channel_cache_put_channel_json(const char *uuid, const char *channel_json,
                                    uint64_t created_at, int deleted) {
    if (!g_db) {
        if (channel_cache_init() != 0) {
            QGP_LOG_WARN(LOG_TAG, "put_channel_json: cache not available (init failed)\n");
            return -3;
        }
    }

    if (!uuid || !channel_json) {
        QGP_LOG_ERROR(LOG_TAG, "put_channel_json: invalid parameters\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO channels "
        "(uuid, channel_json, created_at, deleted, last_cached) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "put_channel_json prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, channel_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (int64_t)created_at);
    sqlite3_bind_int(stmt, 4, deleted);
    sqlite3_bind_int64(stmt, 5, (int64_t)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "put_channel_json step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int channel_cache_get_channel_json(const char *uuid, char **channel_json_out) {
    if (!g_db) {
        if (channel_cache_init() != 0) return -3;
    }

    if (!uuid || !channel_json_out) {
        QGP_LOG_ERROR(LOG_TAG, "get_channel_json: invalid parameters\n");
        return -1;
    }

    const char *sql =
        "SELECT channel_json FROM channels WHERE uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "get_channel_json prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2; /* Not found */
    }

    const char *json = (const char *)sqlite3_column_text(stmt, 0);
    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "get_channel_json: NULL json in database\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    *channel_json_out = strdup(json);
    sqlite3_finalize(stmt);

    if (!*channel_json_out) {
        QGP_LOG_ERROR(LOG_TAG, "get_channel_json: strdup failed\n");
        return -1;
    }

    return 0;
}

/* ---- Channel posts operations ------------------------------------------ */

int channel_cache_put_posts(const char *channel_uuid, const char *posts_json,
                             int post_count) {
    if (!g_db) {
        if (channel_cache_init() != 0) {
            QGP_LOG_WARN(LOG_TAG, "put_posts: cache not available (init failed)\n");
            return -3;
        }
    }

    if (!channel_uuid || !posts_json) {
        QGP_LOG_ERROR(LOG_TAG, "put_posts: invalid parameters\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO channel_posts "
        "(channel_uuid, posts_json, post_count, last_cached) "
        "VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "put_posts prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, channel_uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, posts_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, post_count);
    sqlite3_bind_int64(stmt, 4, (int64_t)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "put_posts step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int channel_cache_get_posts(const char *channel_uuid, char **posts_json_out,
                             int *post_count_out) {
    if (!g_db) {
        if (channel_cache_init() != 0) return -3;
    }

    if (!channel_uuid || !posts_json_out) {
        QGP_LOG_ERROR(LOG_TAG, "get_posts: invalid parameters\n");
        return -1;
    }

    const char *sql =
        "SELECT posts_json, post_count "
        "FROM channel_posts WHERE channel_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "get_posts prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, channel_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2; /* Not found */
    }

    const char *json = (const char *)sqlite3_column_text(stmt, 0);
    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "get_posts: NULL json in database\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    *posts_json_out = strdup(json);

    if (post_count_out) {
        *post_count_out = sqlite3_column_int(stmt, 1);
    }

    sqlite3_finalize(stmt);

    if (!*posts_json_out) {
        QGP_LOG_ERROR(LOG_TAG, "get_posts: strdup failed\n");
        return -1;
    }

    return 0;
}

/* ---- Staleness tracking ------------------------------------------------ */

bool channel_cache_is_stale(const char *cache_key) {
    if (!cache_key) {
        return true;
    }

    if (!g_db) {
        if (channel_cache_init() != 0) return true;
    }

    const char *sql =
        "SELECT last_fetched FROM cache_meta WHERE cache_key = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return true; /* Treat as stale on error */
    }

    sqlite3_bind_text(stmt, 1, cache_key, -1, SQLITE_STATIC);

    bool stale = true;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t last_fetched = (uint64_t)sqlite3_column_int64(stmt, 0);
        uint64_t now = (uint64_t)time(NULL);
        uint64_t age = now - last_fetched;
        stale = (age >= CHANNEL_CACHE_TTL_SECONDS);
    }

    sqlite3_finalize(stmt);
    return stale;
}

int channel_cache_mark_fresh(const char *cache_key) {
    if (!g_db) {
        if (channel_cache_init() != 0) return -3;
    }

    if (!cache_key) {
        QGP_LOG_ERROR(LOG_TAG, "mark_fresh: NULL cache_key\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO cache_meta "
        "(cache_key, last_fetched) VALUES (?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "mark_fresh prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, cache_key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (int64_t)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "mark_fresh step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

/* ---- Eviction ---------------------------------------------------------- */

int channel_cache_evict_old(void) {
    if (!g_db) {
        if (channel_cache_init() != 0) return -1;
    }

    uint64_t cutoff = (uint64_t)time(NULL) - CHANNEL_CACHE_EVICT_SECONDS;

    const char *sql_channels = "DELETE FROM channels WHERE last_cached < ?;";
    const char *sql_posts    = "DELETE FROM channel_posts WHERE last_cached < ?;";
    const char *sql_meta     = "DELETE FROM cache_meta WHERE last_fetched < ?;";

    int total_deleted = 0;
    const char *queries[] = { sql_channels, sql_posts, sql_meta };

    for (int q = 0; q < 3; q++) {
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(g_db, queries[q], -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Evict prepare failed: %s\n", sqlite3_errmsg(g_db));
            return -1;
        }

        sqlite3_bind_int64(stmt, 1, (int64_t)cutoff);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "Evict step failed: %s\n", sqlite3_errmsg(g_db));
            return -1;
        }

        total_deleted += sqlite3_changes(g_db);
    }

    if (total_deleted > 0) {
        QGP_LOG_INFO(LOG_TAG, "Evicted %d stale rows\n", total_deleted);
    }

    return total_deleted;
}
