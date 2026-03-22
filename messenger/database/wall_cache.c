/**
 * Wall Cache Database Implementation
 * GLOBAL SQLite cache for wall posts (not per-identity)
 *
 * Wall data is public DHT data - no reason to cache per-identity.
 * Global cache allows fast wall/timeline rendering without DHT round-trips.
 *
 * @file wall_cache.c
 * @author DNA Connect Team
 * @date 2026-02-25
 */

#include "wall_cache.h"
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

#define LOG_TAG "WALL_CACHE"

static sqlite3 *g_db = NULL;

/* ── Internal helpers ──────────────────────────────────────────────── */

/**
 * Get database path: <data_dir>/wall_cache.db
 * Stored at root level (same pattern as feed_cache.db)
 */
static int get_db_path(char *path_out, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    snprintf(path_out, path_size, "%s/wall_cache.db", data_dir);
    return 0;
}

/**
 * Create schema (tables + indexes)
 */
static int create_schema(void) {
    const char *schema_sql =
        /* ── wall_posts ─────────────────────────────────────────── */
        "CREATE TABLE IF NOT EXISTS wall_posts ("
        "    uuid TEXT PRIMARY KEY,"
        "    author_fingerprint TEXT NOT NULL,"
        "    text TEXT NOT NULL,"
        "    image_json TEXT,"
        "    timestamp INTEGER NOT NULL,"
        "    signature BLOB,"
        "    signature_len INTEGER DEFAULT 0,"
        "    verified INTEGER DEFAULT 0,"
        "    cached_at INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_wall_author "
        "    ON wall_posts(author_fingerprint);"
        "CREATE INDEX IF NOT EXISTS idx_wall_timestamp "
        "    ON wall_posts(timestamp DESC);"

        /* ── wall_cache_meta ───────────────────────────────────── */
        "CREATE TABLE IF NOT EXISTS wall_cache_meta ("
        "    cache_key TEXT PRIMARY KEY,"
        "    last_fetched INTEGER NOT NULL"
        ");"

        /* ── wall_comments (v0.7.0+) ─────────────────────────── */
        "CREATE TABLE IF NOT EXISTS wall_comments ("
        "    post_uuid TEXT PRIMARY KEY,"
        "    comments_json TEXT NOT NULL,"
        "    comment_count INTEGER DEFAULT 0,"
        "    cached_at INTEGER NOT NULL"
        ");"

        /* ── wall_likes (v0.9.53+) ───────────────────────────── */
        "CREATE TABLE IF NOT EXISTS wall_likes ("
        "    post_uuid TEXT PRIMARY KEY,"
        "    likes_json TEXT NOT NULL,"
        "    like_count INTEGER DEFAULT 0,"
        "    cached_at INTEGER NOT NULL"
        ");";

    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create schema: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    /* v0.7.0 migration: add image_json column if missing (existing DBs) */
    sqlite3_exec(g_db, "ALTER TABLE wall_posts ADD COLUMN image_json TEXT;",
                 NULL, NULL, NULL);

    return 0;
}

/**
 * Fill a dna_wall_post_t from a SELECT statement row.
 * Expected column order: uuid, author_fingerprint, text, image_json,
 *                        timestamp, signature, signature_len, verified
 */
static void fill_post_from_row(sqlite3_stmt *stmt, dna_wall_post_t *post) {
    memset(post, 0, sizeof(dna_wall_post_t));

    const char *uuid_str = (const char *)sqlite3_column_text(stmt, 0);
    if (uuid_str) {
        strncpy(post->uuid, uuid_str, sizeof(post->uuid) - 1);
    }

    const char *fp_str = (const char *)sqlite3_column_text(stmt, 1);
    if (fp_str) {
        strncpy(post->author_fingerprint, fp_str, sizeof(post->author_fingerprint) - 1);
    }

    const char *text_str = (const char *)sqlite3_column_text(stmt, 2);
    if (text_str) {
        strncpy(post->text, text_str, DNA_WALL_MAX_TEXT_LEN - 1);
    }

    /* image_json: heap-allocated, NULL if no image (v0.7.0+) */
    const char *img_str = (const char *)sqlite3_column_text(stmt, 3);
    post->image_json = img_str ? strdup(img_str) : NULL;

    post->timestamp = (uint64_t)sqlite3_column_int64(stmt, 4);

    const void *sig_blob = sqlite3_column_blob(stmt, 5);
    int sig_len = sqlite3_column_int(stmt, 6);
    if (sig_blob && sig_len > 0 && (size_t)sig_len <= sizeof(post->signature)) {
        memcpy(post->signature, sig_blob, (size_t)sig_len);
        post->signature_len = (size_t)sig_len;
    }

    post->verified = sqlite3_column_int(stmt, 7) ? true : false;
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */

int wall_cache_init(void) {
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

    QGP_LOG_INFO(LOG_TAG, "Wall cache initialized\n");
    return 0;
}

void wall_cache_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        QGP_LOG_INFO(LOG_TAG, "Closed database\n");
    }
}

int wall_cache_evict_expired(void) {
    if (wall_cache_init() != 0) {
        return -1;
    }

    uint64_t cutoff = (uint64_t)time(NULL) - WALL_CACHE_EVICT_SECONDS;

    const char *sql_posts = "DELETE FROM wall_posts WHERE cached_at < ?;";
    const char *sql_meta  = "DELETE FROM wall_cache_meta WHERE last_fetched < ?;";

    int total_deleted = 0;
    const char *queries[] = { sql_posts, sql_meta };

    for (int q = 0; q < 2; q++) {
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

/* ── Post operations ──────────────────────────────────────────────── */

int wall_cache_store(const char *fingerprint,
                     const dna_wall_post_t *posts, size_t count) {
    if (!g_db) {
        if (wall_cache_init() != 0) {
            QGP_LOG_WARN(LOG_TAG, "store: cache not available (init failed)\n");
            return -3;
        }
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "store: NULL fingerprint\n");
        return -1;
    }

    /* Begin transaction */
    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, "BEGIN TRANSACTION;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store: BEGIN failed: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    /* Upsert posts — INSERT OR REPLACE avoids DELETE+INSERT race condition
     * where concurrent reads see 0 rows between DELETE and INSERT.
     * Old posts not in the new set are cleaned up AFTER insert. */
    if (posts && count > 0) {
        const char *sql_insert =
            "INSERT OR REPLACE INTO wall_posts "
            "(uuid, author_fingerprint, text, image_json, timestamp, signature, signature_len, verified, cached_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

        sqlite3_stmt *ins_stmt = NULL;
        rc = sqlite3_prepare_v2(g_db, sql_insert, -1, &ins_stmt, NULL);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "store: insert prepare: %s\n", sqlite3_errmsg(g_db));
            sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
            return -1;
        }

        uint64_t now = (uint64_t)time(NULL);

        for (size_t i = 0; i < count; i++) {
            sqlite3_reset(ins_stmt);
            sqlite3_clear_bindings(ins_stmt);

            sqlite3_bind_text(ins_stmt, 1, posts[i].uuid, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins_stmt, 2, posts[i].author_fingerprint, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins_stmt, 3, posts[i].text, -1, SQLITE_TRANSIENT);
            if (posts[i].image_json) {
                sqlite3_bind_text(ins_stmt, 4, posts[i].image_json, -1, SQLITE_TRANSIENT);
            } else {
                sqlite3_bind_null(ins_stmt, 4);
            }
            sqlite3_bind_int64(ins_stmt, 5, (int64_t)posts[i].timestamp);
            sqlite3_bind_blob(ins_stmt, 6, posts[i].signature, (int)posts[i].signature_len, SQLITE_TRANSIENT);
            sqlite3_bind_int(ins_stmt, 7, (int)posts[i].signature_len);
            sqlite3_bind_int(ins_stmt, 8, posts[i].verified ? 1 : 0);
            sqlite3_bind_int64(ins_stmt, 9, (int64_t)now);

            rc = sqlite3_step(ins_stmt);
            if (rc != SQLITE_DONE) {
                QGP_LOG_ERROR(LOG_TAG, "store: insert step[%zu]: %s\n", i, sqlite3_errmsg(g_db));
                sqlite3_finalize(ins_stmt);
                sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
                return -1;
            }
        }

        sqlite3_finalize(ins_stmt);
    }

    /* Update meta: mark this fingerprint as freshly fetched */
    const char *sql_meta =
        "INSERT OR REPLACE INTO wall_cache_meta "
        "(cache_key, last_fetched) VALUES (?, ?);";

    sqlite3_stmt *meta_stmt = NULL;
    rc = sqlite3_prepare_v2(g_db, sql_meta, -1, &meta_stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store: meta prepare: %s\n", sqlite3_errmsg(g_db));
        sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_text(meta_stmt, 1, fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_int64(meta_stmt, 2, (int64_t)now);

    rc = sqlite3_step(meta_stmt);
    sqlite3_finalize(meta_stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "store: meta step: %s\n", sqlite3_errmsg(g_db));
        sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    /* Clean up stale posts by this author that weren't in the new set */
    {
        const char *sql_cleanup =
            "DELETE FROM wall_posts WHERE author_fingerprint = ? AND cached_at < ?;";
        sqlite3_stmt *cleanup_stmt = NULL;
        if (sqlite3_prepare_v2(g_db, sql_cleanup, -1, &cleanup_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(cleanup_stmt, 1, fingerprint, -1, SQLITE_STATIC);
            sqlite3_bind_int64(cleanup_stmt, 2, (int64_t)time(NULL) - 1);
            sqlite3_step(cleanup_stmt);
            sqlite3_finalize(cleanup_stmt);
        }
    }

    /* Commit transaction */
    rc = sqlite3_exec(g_db, "COMMIT;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store: COMMIT failed: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Stored %zu wall posts for %.16s...\n", count, fingerprint);
    /* DEBUG: Log mismatch between store fingerprint and post author */
    if (posts && count > 0 && strcmp(fingerprint, posts[0].author_fingerprint) != 0) {
        QGP_LOG_WARN(LOG_TAG, "MISMATCH: store fp=%.32s... vs post[0].author=%.32s...\n",
                     fingerprint, posts[0].author_fingerprint);
    }
    return 0;
}

int wall_cache_load(const char *fingerprint,
                    dna_wall_post_t **posts, size_t *count) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }

    if (!fingerprint || !posts || !count) {
        QGP_LOG_ERROR(LOG_TAG, "load: invalid parameters\n");
        return -1;
    }

    *posts = NULL;
    *count = 0;

    const char *sql =
        "SELECT uuid, author_fingerprint, text, image_json, timestamp, "
        "signature, signature_len, verified "
        "FROM wall_posts WHERE author_fingerprint = ? "
        "ORDER BY timestamp DESC;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "load: prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);

    /* First pass: count rows */
    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        n++;
    }
    sqlite3_reset(stmt);

    if (n == 0) {
        sqlite3_finalize(stmt);
        return -2; /* Not found */
    }

    /* Allocate array */
    dna_wall_post_t *result = calloc(n, sizeof(dna_wall_post_t));
    if (!result) {
        QGP_LOG_ERROR(LOG_TAG, "load: calloc failed\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    /* Second pass: collect posts */
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < n) {
        fill_post_from_row(stmt, &result[i]);
        i++;
    }

    sqlite3_finalize(stmt);

    *posts = result;
    *count = i;
    return 0;
}

int wall_cache_load_timeline(const char **fingerprints, size_t fp_count,
                             dna_wall_post_t **posts, size_t *count) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }

    if (!fingerprints || fp_count == 0 || !posts || !count) {
        QGP_LOG_ERROR(LOG_TAG, "load_timeline: invalid parameters\n");
        return -1;
    }

    *posts = NULL;
    *count = 0;

    /* v0.9.80: Per-fingerprint approach replaces unreliable IN clause.
     * The IN (?,?,...) query was returning 0 rows on Android despite
     * matching data existing — likely a SQLite WAL/ARM64 edge case.
     * Individual WHERE = ? queries work reliably. Merge + sort here. */

    /* Phase 1: Collect all posts from individual fingerprint queries */
    size_t capacity = 64;
    size_t total = 0;
    dna_wall_post_t *merged = calloc(capacity, sizeof(dna_wall_post_t));
    if (!merged) {
        QGP_LOG_ERROR(LOG_TAG, "load_timeline: calloc failed\n");
        return -1;
    }

    const char *sql_single =
        "SELECT uuid, author_fingerprint, text, image_json, timestamp, "
        "signature, signature_len, verified "
        "FROM wall_posts WHERE author_fingerprint = ? "
        "ORDER BY timestamp DESC;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql_single, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "load_timeline: prepare: %s\n", sqlite3_errmsg(g_db));
        free(merged);
        return -1;
    }

    for (size_t f = 0; f < fp_count; f++) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_bind_text(stmt, 1, fingerprints[f], -1, SQLITE_STATIC);

        size_t count_before = total;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            /* Grow array if needed */
            if (total >= capacity) {
                size_t new_cap = capacity * 2;
                if (new_cap > 200) new_cap = 200;
                if (total >= new_cap) break;  /* Hit 200 limit */
                dna_wall_post_t *tmp = realloc(merged, new_cap * sizeof(dna_wall_post_t));
                if (!tmp) break;
                memset(tmp + capacity, 0, (new_cap - capacity) * sizeof(dna_wall_post_t));
                merged = tmp;
                capacity = new_cap;
            }
            fill_post_from_row(stmt, &merged[total]);
            total++;
            if (total >= 200) break;
        }
        QGP_LOG_DEBUG(LOG_TAG, "load_timeline: fp[%zu]=%.32s... → %zu rows\n",
                      f, fingerprints[f], total - count_before);
        if (total >= 200) break;
    }

    sqlite3_finalize(stmt);

    if (total == 0) {
        free(merged);
        QGP_LOG_DEBUG(LOG_TAG, "load_timeline: 0 posts from %zu fingerprints\n", fp_count);
        return 0;
    }

    /* Phase 2: Sort by timestamp descending (simple insertion sort, max 200 items) */
    for (size_t i = 1; i < total; i++) {
        dna_wall_post_t tmp = merged[i];
        size_t j = i;
        while (j > 0 && merged[j - 1].timestamp < tmp.timestamp) {
            merged[j] = merged[j - 1];
            j--;
        }
        merged[j] = tmp;
    }

    *posts = merged;
    *count = total;
    QGP_LOG_DEBUG(LOG_TAG, "load_timeline: %zu posts from %zu fingerprints\n", total, fp_count);
    return 0;
}

int wall_cache_delete_by_author(const char *fingerprint) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "delete_by_author: NULL fingerprint\n");
        return -1;
    }

    const char *sql = "DELETE FROM wall_posts WHERE author_fingerprint = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "delete_by_author prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "delete_by_author step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int wall_cache_delete_post(const char *post_uuid) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }

    if (!post_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "delete_post: NULL post_uuid\n");
        return -1;
    }

    const char *sql = "DELETE FROM wall_posts WHERE uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "delete_post prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "delete_post step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int wall_cache_insert_post(const dna_wall_post_t *post) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }

    if (!post) {
        QGP_LOG_ERROR(LOG_TAG, "insert_post: NULL post\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO wall_posts "
        "(uuid, author_fingerprint, text, image_json, timestamp, signature, signature_len, verified, cached_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "insert_post prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, post->uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, post->author_fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, post->text, -1, SQLITE_TRANSIENT);
    if (post->image_json) {
        sqlite3_bind_text(stmt, 4, post->image_json, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 4);
    }
    sqlite3_bind_int64(stmt, 5, (int64_t)post->timestamp);
    sqlite3_bind_blob(stmt, 6, post->signature, (int)post->signature_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, (int)post->signature_len);
    sqlite3_bind_int(stmt, 8, post->verified ? 1 : 0);
    sqlite3_bind_int64(stmt, 9, (int64_t)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "insert_post step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Inserted post %s by %.16s...\n", post->uuid, post->author_fingerprint);
    return 0;
}

int wall_cache_delete_meta(const char *fingerprint) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "delete_meta: NULL fingerprint\n");
        return -1;
    }

    const char *sql = "DELETE FROM wall_cache_meta WHERE cache_key = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "delete_meta prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "delete_meta step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

/* ── Meta / staleness ──────────────────────────────────────────────── */

int wall_cache_update_meta(const char *fingerprint) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "update_meta: NULL fingerprint\n");
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO wall_cache_meta "
        "(cache_key, last_fetched) VALUES (?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "update_meta prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (int64_t)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "update_meta step: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

bool wall_cache_is_stale(const char *fingerprint) {
    if (!fingerprint) {
        return true;
    }

    if (!g_db) {
        if (wall_cache_init() != 0) return true;
    }

    const char *sql =
        "SELECT last_fetched FROM wall_cache_meta WHERE cache_key = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return true; /* Treat as stale on error */
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);

    bool stale = true;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t last_fetched = (uint64_t)sqlite3_column_int64(stmt, 0);
        uint64_t now = (uint64_t)time(NULL);
        uint64_t age = now - last_fetched;
        stale = (age >= WALL_CACHE_TTL_SECONDS);
    }

    sqlite3_finalize(stmt);
    return stale;
}

/* ── Memory management ─────────────────────────────────────────────── */

void wall_cache_free_posts(dna_wall_post_t *posts, size_t count) {
    if (posts) {
        for (size_t i = 0; i < count; i++) {
            free(posts[i].image_json); /* NULL-safe */
        }
        free(posts);
    }
}

/* ── Comment cache (v0.7.0+) ──────────────────────────────────────── */

int wall_cache_store_comments(const char *post_uuid, const char *comments_json, int count) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -1;
    }
    if (!post_uuid || !comments_json) return -1;

    const char *sql =
        "INSERT OR REPLACE INTO wall_comments "
        "(post_uuid, comments_json, comment_count, cached_at) VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store_comments prepare: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, comments_json, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, count);
    sqlite3_bind_int64(stmt, 4, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "store_comments step: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int wall_cache_load_comments(const char *post_uuid, char **json_out, int *count_out) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -1;
    }
    if (!post_uuid || !json_out || !count_out) return -1;

    *json_out = NULL;
    *count_out = 0;

    const char *sql =
        "SELECT comments_json, comment_count FROM wall_comments WHERE post_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "load_comments prepare: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2; /* Not found */
    }

    const char *json = (const char *)sqlite3_column_text(stmt, 0);
    int cnt = sqlite3_column_int(stmt, 1);

    if (json) {
        *json_out = strdup(json);
    }
    *count_out = cnt;

    sqlite3_finalize(stmt);
    return (*json_out) ? 0 : -1;
}

int wall_cache_invalidate_comments(const char *post_uuid) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -1;
    }
    if (!post_uuid) return -1;

    const char *sql = "DELETE FROM wall_comments WHERE post_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "invalidate_comments prepare: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

bool wall_cache_is_stale_comments(const char *post_uuid) {
    if (!post_uuid) return true;
    if (!g_db) {
        if (wall_cache_init() != 0) return true;
    }

    const char *sql = "SELECT cached_at FROM wall_comments WHERE post_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return true;

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);

    bool stale = true;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t cached_at = (uint64_t)sqlite3_column_int64(stmt, 0);
        uint64_t age = (uint64_t)time(NULL) - cached_at;
        stale = (age >= WALL_CACHE_TTL_SECONDS);
    }

    sqlite3_finalize(stmt);
    return stale;
}

/* ── Likes cache (v0.9.53+) ──────────────────────────────────────── */

int wall_cache_store_likes(const char *post_uuid, const char *likes_json, int count) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -1;
    }
    if (!post_uuid || !likes_json) return -1;

    const char *sql =
        "INSERT OR REPLACE INTO wall_likes "
        "(post_uuid, likes_json, like_count, cached_at) VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store_likes prepare: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, likes_json, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, count);
    sqlite3_bind_int64(stmt, 4, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "store_likes step: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int wall_cache_load_likes(const char *post_uuid, char **json_out, int *count_out) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -1;
    }
    if (!post_uuid || !json_out || !count_out) return -1;

    *json_out = NULL;
    *count_out = 0;

    const char *sql =
        "SELECT likes_json, like_count FROM wall_likes WHERE post_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "load_likes prepare: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2; /* Not found */
    }

    const char *json = (const char *)sqlite3_column_text(stmt, 0);
    int cnt = sqlite3_column_int(stmt, 1);

    if (json) {
        *json_out = strdup(json);
    }
    *count_out = cnt;

    sqlite3_finalize(stmt);
    return (*json_out) ? 0 : -1;
}

int wall_cache_invalidate_likes(const char *post_uuid) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -1;
    }
    if (!post_uuid) return -1;

    const char *sql = "DELETE FROM wall_likes WHERE post_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "invalidate_likes prepare: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

bool wall_cache_is_stale_likes(const char *post_uuid) {
    if (!post_uuid) return true;
    if (!g_db) {
        if (wall_cache_init() != 0) return true;
    }

    const char *sql = "SELECT cached_at FROM wall_likes WHERE post_uuid = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return true;

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);

    bool stale = true;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t cached_at = (uint64_t)sqlite3_column_int64(stmt, 0);
        uint64_t age = (uint64_t)time(NULL) - cached_at;
        stale = (age >= WALL_CACHE_TTL_SECONDS);
    }

    sqlite3_finalize(stmt);
    return stale;
}
