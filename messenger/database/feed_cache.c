/**
 * Feed Cache Database Implementation
 * GLOBAL SQLite cache for feed topics and comments (not per-identity)
 *
 * Feed data is public DHT data - no reason to cache per-identity.
 * Global cache allows fast feed rendering without DHT round-trips.
 *
 * @file feed_cache.c
 * @author DNA Messenger Team
 * @date 2026-02-22
 */

#include "feed_cache.h"
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

#define LOG_TAG "FEED_CACHE"

static sqlite3 *g_db = NULL;

/* ── Internal helpers ──────────────────────────────────────────────── */

/**
 * Get database path: <data_dir>/db/feed_cache.db
 */
static int get_db_path(char *path_out, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    snprintf(path_out, path_size, "%s/db/feed_cache.db", data_dir);
    return 0;
}

/**
 * Create schema (tables + indexes)
 */
static int create_schema(void) {
    const char *schema_sql =
        /* ── feed_topics ─────────────────────────────────────────── */
        "CREATE TABLE IF NOT EXISTS feed_topics ("
        "    topic_uuid   TEXT PRIMARY KEY,"
        "    topic_json   TEXT NOT NULL,"
        "    category_id  TEXT NOT NULL,"
        "    created_at   INTEGER NOT NULL,"
        "    deleted      INTEGER DEFAULT 0,"
        "    cached_at    INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_feed_topics_category "
        "    ON feed_topics(category_id, created_at DESC);"
        "CREATE INDEX IF NOT EXISTS idx_feed_topics_created "
        "    ON feed_topics(created_at DESC);"
        "CREATE INDEX IF NOT EXISTS idx_feed_topics_cached "
        "    ON feed_topics(cached_at);"

        /* ── feed_comments ───────────────────────────────────────── */
        "CREATE TABLE IF NOT EXISTS feed_comments ("
        "    topic_uuid    TEXT PRIMARY KEY,"
        "    comments_json TEXT NOT NULL,"
        "    comment_count INTEGER DEFAULT 0,"
        "    cached_at     INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_feed_comments_cached "
        "    ON feed_comments(cached_at);"

        /* ── feed_cache_meta ─────────────────────────────────────── */
        "CREATE TABLE IF NOT EXISTS feed_cache_meta ("
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

/* ── Lifecycle ─────────────────────────────────────────────────────── */

int feed_cache_init(void) {
    /* Already initialized */
    if (g_db) {
        return 0;
    }

    /* Database path */
    char db_path[1024];
    if (get_db_path(db_path, sizeof(db_path)) != 0) {
        return -1;
    }

    /* Ensure db/ directory exists */
    const char *data_dir = qgp_platform_app_data_dir();
    if (data_dir) {
        char db_dir[1024];
        snprintf(db_dir, sizeof(db_dir), "%s/db", data_dir);
        mkdir(db_dir, 0755);
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

    /* Create schema */
    if (create_schema() != 0) {
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Feed cache initialized\n");
    return 0;
}

void feed_cache_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Closed database\n");
    }
}

int feed_cache_evict_expired(void) {
    if (feed_cache_init() != 0) {
        return -1;
    }

    uint64_t cutoff = (uint64_t)time(NULL) - FEED_CACHE_EVICT_SECONDS;

    const char *sql_topics  = "DELETE FROM feed_topics WHERE cached_at < ?;";
    const char *sql_comments = "DELETE FROM feed_comments WHERE cached_at < ?;";
    const char *sql_meta    = "DELETE FROM feed_cache_meta WHERE last_fetched < ?;";

    int total_deleted = 0;
    const char *queries[] = { sql_topics, sql_comments, sql_meta };

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

/* ── Topic operations ──────────────────────────────────────────────── */

int feed_cache_put_topic_json(const char *uuid, const char *topic_json,
                              const char *category_id, uint64_t created_at,
                              int deleted) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    if (!uuid || !topic_json || !category_id) {
        QGP_LOG_ERROR(LOG_TAG, "put_topic_json: invalid parameters\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO feed_topics "
        "(topic_uuid, topic_json, category_id, created_at, deleted, cached_at) "
        "VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "put_topic_json prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, topic_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, category_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (int64_t)created_at);
    sqlite3_bind_int(stmt, 5, deleted);
    sqlite3_bind_int64(stmt, 6, (int64_t)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "put_topic_json step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int feed_cache_get_topic_json(const char *uuid, char **topic_json_out) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    if (!uuid || !topic_json_out) {
        QGP_LOG_ERROR(LOG_TAG, "get_topic_json: invalid parameters\n");
        return -1;
    }

    const char *sql =
        "SELECT topic_json FROM feed_topics WHERE topic_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "get_topic_json prepare: %s\n", sqlite3_errmsg(g_db));
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
        QGP_LOG_ERROR(LOG_TAG, "get_topic_json: NULL json in database\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    *topic_json_out = strdup(json);
    sqlite3_finalize(stmt);

    if (!*topic_json_out) {
        QGP_LOG_ERROR(LOG_TAG, "get_topic_json: strdup failed\n");
        return -1;
    }

    return 0;
}

int feed_cache_delete_topic(const char *uuid) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    if (!uuid) {
        QGP_LOG_ERROR(LOG_TAG, "delete_topic: invalid uuid\n");
        return -1;
    }

    const char *sql = "DELETE FROM feed_topics WHERE topic_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "delete_topic prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "delete_topic step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

/**
 * Internal: query topics with optional category filter and date window.
 * Builds the appropriate SQL and returns an array of strdup'd JSON strings.
 */
static int query_topics(const char *category_id, int days_back,
                        char ***topic_jsons_out, int *count) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    if (!topic_jsons_out || !count) {
        return -1;
    }

    *topic_jsons_out = NULL;
    *count = 0;

    /*
     * Build query.
     * Always filter deleted == 0.
     * Optionally filter by category_id and/or created_at cutoff.
     */
    char sql[512];
    int has_category = (category_id && category_id[0] != '\0');
    int has_date     = (days_back > 0);

    if (has_category && has_date) {
        snprintf(sql, sizeof(sql),
            "SELECT topic_json FROM feed_topics "
            "WHERE deleted = 0 AND category_id = ? AND created_at >= ? "
            "ORDER BY created_at DESC;");
    } else if (has_category) {
        snprintf(sql, sizeof(sql),
            "SELECT topic_json FROM feed_topics "
            "WHERE deleted = 0 AND category_id = ? "
            "ORDER BY created_at DESC;");
    } else if (has_date) {
        snprintf(sql, sizeof(sql),
            "SELECT topic_json FROM feed_topics "
            "WHERE deleted = 0 AND created_at >= ? "
            "ORDER BY created_at DESC;");
    } else {
        snprintf(sql, sizeof(sql),
            "SELECT topic_json FROM feed_topics "
            "WHERE deleted = 0 "
            "ORDER BY created_at DESC;");
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "query_topics prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    /* Bind parameters */
    int bind_idx = 1;
    if (has_category) {
        sqlite3_bind_text(stmt, bind_idx++, category_id, -1, SQLITE_STATIC);
    }
    if (has_date) {
        uint64_t cutoff = (uint64_t)time(NULL) - ((uint64_t)days_back * 86400);
        sqlite3_bind_int64(stmt, bind_idx, (int64_t)cutoff);
    }

    /* First pass: count rows */
    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        n++;
    }
    sqlite3_reset(stmt);

    if (n == 0) {
        sqlite3_finalize(stmt);
        return 0;
    }

    /* Allocate array */
    char **jsons = malloc(n * sizeof(char *));
    if (!jsons) {
        QGP_LOG_ERROR(LOG_TAG, "query_topics: malloc failed\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    /* Second pass: collect strings */
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < n) {
        const char *json = (const char *)sqlite3_column_text(stmt, 0);
        jsons[i] = strdup(json ? json : "");
        if (!jsons[i]) {
            /* Cleanup on strdup failure */
            for (size_t j = 0; j < i; j++) free(jsons[j]);
            free(jsons);
            sqlite3_finalize(stmt);
            return -1;
        }
        i++;
    }

    sqlite3_finalize(stmt);

    *topic_jsons_out = jsons;
    *count = i;
    return 0;
}

int feed_cache_get_topics_all(int days_back, char ***topic_jsons_out,
                              int *count) {
    return query_topics(NULL, days_back, topic_jsons_out, count);
}

int feed_cache_get_topics_by_category(const char *category_id, int days_back,
                                      char ***topic_jsons_out, int *count) {
    if (!category_id) {
        QGP_LOG_ERROR(LOG_TAG, "get_topics_by_category: NULL category_id\n");
        return -1;
    }
    return query_topics(category_id, days_back, topic_jsons_out, count);
}

void feed_cache_free_json_list(char **jsons, int count) {
    if (!jsons) return;
    for (int i = 0; i < count; i++) {
        free(jsons[i]);
    }
    free(jsons);
}

/* ── Comment operations ────────────────────────────────────────────── */

int feed_cache_put_comments(const char *topic_uuid, const char *comments_json,
                            int comment_count) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    if (!topic_uuid || !comments_json) {
        QGP_LOG_ERROR(LOG_TAG, "put_comments: invalid parameters\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO feed_comments "
        "(topic_uuid, comments_json, comment_count, cached_at) "
        "VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "put_comments prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, topic_uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, comments_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, comment_count);
    sqlite3_bind_int64(stmt, 4, (int64_t)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "put_comments step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int feed_cache_get_comments(const char *topic_uuid, char **comments_json_out,
                            int *comment_count_out) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    if (!topic_uuid || !comments_json_out) {
        QGP_LOG_ERROR(LOG_TAG, "get_comments: invalid parameters\n");
        return -1;
    }

    const char *sql =
        "SELECT comments_json, comment_count "
        "FROM feed_comments WHERE topic_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "get_comments prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, topic_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2; /* Not found */
    }

    const char *json = (const char *)sqlite3_column_text(stmt, 0);
    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "get_comments: NULL json in database\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    *comments_json_out = strdup(json);

    if (comment_count_out) {
        *comment_count_out = sqlite3_column_int(stmt, 1);
    }

    sqlite3_finalize(stmt);

    if (!*comments_json_out) {
        QGP_LOG_ERROR(LOG_TAG, "get_comments: strdup failed\n");
        return -1;
    }

    return 0;
}

int feed_cache_invalidate_comments(const char *topic_uuid) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    if (!topic_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "invalidate_comments: NULL topic_uuid\n");
        return -1;
    }

    const char *sql = "DELETE FROM feed_comments WHERE topic_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "invalidate_comments prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, topic_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "invalidate_comments step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

/* ── Meta / staleness ──────────────────────────────────────────────── */

int feed_cache_update_meta(const char *cache_key) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    if (!cache_key) {
        QGP_LOG_ERROR(LOG_TAG, "update_meta: NULL cache_key\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO feed_cache_meta "
        "(cache_key, last_fetched) VALUES (?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "update_meta prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, cache_key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (int64_t)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "update_meta step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

bool feed_cache_is_stale(const char *cache_key) {
    if (!cache_key) {
        return true;
    }

    if (!g_db) {
        if (feed_cache_init() != 0) return true;
    }

    const char *sql =
        "SELECT last_fetched FROM feed_cache_meta WHERE cache_key = ?;";

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
        stale = (age >= FEED_CACHE_TTL_SECONDS);
    }

    sqlite3_finalize(stmt);
    return stale;
}

int feed_cache_stats(int *total_topics, int *total_comments, int *expired) {
    if (!g_db) {
        if (feed_cache_init() != 0) return -3;
    }

    /* Total topics */
    if (total_topics) {
        const char *sql = "SELECT COUNT(*) FROM feed_topics;";
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            return -1;
        }
        *total_topics = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *total_topics = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    /* Total comments */
    if (total_comments) {
        const char *sql = "SELECT COUNT(*) FROM feed_comments;";
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            return -1;
        }
        *total_comments = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *total_comments = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    /* Expired topics (older than eviction threshold) */
    if (expired) {
        uint64_t cutoff = (uint64_t)time(NULL) - FEED_CACHE_EVICT_SECONDS;
        const char *sql = "SELECT COUNT(*) FROM feed_topics WHERE cached_at < ?;";
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_int64(stmt, 1, (int64_t)cutoff);
        *expired = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *expired = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    return 0;
}
