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
#include <pthread.h>
#ifdef _WIN32
/* No additional includes needed */
#else
#include <unistd.h>
#endif

#define LOG_TAG "WALL_CACHE"

static sqlite3 *g_db = NULL;
static pthread_mutex_t g_store_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_recovery_attempted = false;

/* Forward declarations for recovery helper */
static int get_db_path(char *path_out, size_t path_size);
static int create_schema(void);

/**
 * Check if SQLite error code is a fatal corruption/IO error
 * that warrants nuking the cache and starting fresh.
 */
static bool is_fatal_sqlite_error(int rc) {
    switch (rc) {
    case SQLITE_IOERR:      /* 10 — disk I/O error */
    case SQLITE_CORRUPT:    /* 11 — database corruption */
    case SQLITE_NOTADB:     /* 26 — not a database file */
    case 266:               /* SQLITE_IOERR_READ — extended I/O read error */
        return true;
    default:
        return false;
    }
}

/**
 * Nuclear recovery: close DB, delete all files, reopen fresh.
 * Only attempted ONCE per session to avoid infinite loops.
 * Returns 0 on success, -1 on failure.
 */
static int wall_cache_nuke_and_reopen(void) {
    if (g_recovery_attempted) {
        QGP_LOG_ERROR(LOG_TAG, "Recovery already attempted this session, giving up\n");
        return -1;
    }
    g_recovery_attempted = true;

    QGP_LOG_WARN(LOG_TAG, "RECOVERY: nuking corrupt wall_cache.db and reopening fresh\n");

    /* Close existing handle */
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }

    /* Build paths and remove all DB files */
    char db_path[1024];
    if (get_db_path(db_path, sizeof(db_path)) != 0) {
        return -1;
    }

    char wal_path[1040];
    char shm_path[1040];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
    snprintf(shm_path, sizeof(shm_path), "%s-shm", db_path);

    remove(db_path);
    remove(wal_path);
    remove(shm_path);

    /* Reopen fresh */
    int rc = sqlite3_open_v2(db_path, &g_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "RECOVERY: reopen failed: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    sqlite3_busy_timeout(g_db, 5000);
    sqlite3_exec(g_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);

    if (create_schema() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "RECOVERY: create_schema failed after nuke\n");
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    /* Set user_version to current so we don't trigger the migration reset */
    sqlite3_exec(g_db, "PRAGMA user_version = 7;", NULL, NULL, NULL);

    /* Ensure temp storage is memory-based after recovery too */
    sqlite3_exec(g_db, "PRAGMA temp_store = 2;", NULL, NULL, NULL);

    QGP_LOG_WARN(LOG_TAG, "RECOVERY: wall_cache.db rebuilt successfully\n");
    return 0;
}

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
        "CREATE INDEX IF NOT EXISTS idx_wall_author_ts "
        "    ON wall_posts(author_fingerprint, timestamp DESC);"

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
        ");"

        /* ── wall_boost_pointers (v0.9.98+) ─────────────────── */
        "CREATE TABLE IF NOT EXISTS wall_boost_pointers ("
        "    uuid TEXT PRIMARY KEY,"
        "    author_fingerprint TEXT NOT NULL,"
        "    timestamp INTEGER NOT NULL,"
        "    cached_at INTEGER NOT NULL"
        ");"

        /* ── wall_day_meta (v0.9.141+ daily buckets) ────── */
        "CREATE TABLE IF NOT EXISTS wall_day_meta ("
        "    fingerprint TEXT PRIMARY KEY,"
        "    meta_json TEXT NOT NULL,"
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s (rc=%d)\n", sqlite3_errmsg(g_db), rc);
        sqlite3_close(g_db);
        g_db = NULL;
        if (is_fatal_sqlite_error(rc)) {
            return wall_cache_nuke_and_reopen();
        }
        return -1;
    }

    /* Android force-close recovery: busy timeout + WAL checkpoint */
    sqlite3_busy_timeout(g_db, 5000);
    sqlite3_wal_checkpoint(g_db, NULL);

    /* Enable WAL mode for better concurrency and crash resilience
     * (matches feed_cache pattern - proven to work on Android) */
    sqlite3_exec(g_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);

    /* Force temp storage to memory — prevents SQLITE_IOERR when ORDER BY
     * needs a temp B-tree for large blob rows (e.g. 500KB image_json × 9).
     * Some Android devices have restricted/broken temp file I/O. */
    sqlite3_exec(g_db, "PRAGMA temp_store = 2;", NULL, NULL, NULL);

    /* Create schema */
    if (create_schema() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Schema creation failed, attempting recovery\n");
        sqlite3_close(g_db);
        g_db = NULL;
        return wall_cache_nuke_and_reopen();
    }

    /* One-time cache reset: clears stale meta + mismatched posts.
     * v4: forced clean build to ensure this code actually runs
     * (previous versions may have used cached .o with old code). */
    {
        int uv = 0;
        sqlite3_stmt *uv_stmt = NULL;
        if (sqlite3_prepare_v2(g_db, "PRAGMA user_version;", -1, &uv_stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(uv_stmt) == SQLITE_ROW)
                uv = sqlite3_column_int(uv_stmt, 0);
            sqlite3_finalize(uv_stmt);
        }
        QGP_LOG_INFO(LOG_TAG, "PRAGMA user_version = %d\n", uv);
        if (uv < 6) {
            sqlite3_exec(g_db, "DELETE FROM wall_posts;", NULL, NULL, NULL);
            sqlite3_exec(g_db, "DELETE FROM wall_cache_meta;", NULL, NULL, NULL);
            sqlite3_exec(g_db, "DELETE FROM wall_boost_pointers;", NULL, NULL, NULL);
            sqlite3_exec(g_db, "DROP INDEX IF EXISTS idx_wall_timestamp;", NULL, NULL, NULL);
            sqlite3_exec(g_db, "REINDEX;", NULL, NULL, NULL);
            sqlite3_wal_checkpoint_v2(g_db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL);
            sqlite3_exec(g_db, "VACUUM;", NULL, NULL, NULL);
            sqlite3_exec(g_db, "PRAGMA user_version = 7;", NULL, NULL, NULL);
            QGP_LOG_INFO(LOG_TAG, "Cache reset (v6→7): nuke all + drop timestamp index + vacuum + composite index\n");
        }
        if (uv == 6) {
            /* v7: Add composite index for ORDER BY without temp sorter.
             * Fixes SQLITE_IOERR on Android when sorting large image_json blobs. */
            sqlite3_exec(g_db, "CREATE INDEX IF NOT EXISTS idx_wall_author_ts "
                                "ON wall_posts(author_fingerprint, timestamp DESC);",
                         NULL, NULL, NULL);
            /* Nuke cache to force rebuild with new index */
            sqlite3_exec(g_db, "DELETE FROM wall_posts;", NULL, NULL, NULL);
            sqlite3_exec(g_db, "DELETE FROM wall_cache_meta;", NULL, NULL, NULL);
            sqlite3_exec(g_db, "PRAGMA user_version = 7;", NULL, NULL, NULL);
            QGP_LOG_INFO(LOG_TAG, "Migration v7: composite index + cache nuke (IOERR fix)\n");
        }
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

void wall_cache_wal_checkpoint(void) {
    if (g_db) {
        /* TRUNCATE mode: blocks until all readers finish, then copies
         * WAL content to main DB and truncates WAL file.  Fixes Android
         * ARM64 visibility issue where PASSIVE checkpoint left frames
         * in WAL that subsequent readers couldn't see. */
        sqlite3_wal_checkpoint_v2(g_db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL);
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
    pthread_mutex_lock(&g_store_mutex);

    if (!g_db) {
        if (wall_cache_init() != 0) {
            QGP_LOG_WARN(LOG_TAG, "store: cache not available (init failed)\n");
            pthread_mutex_unlock(&g_store_mutex);
            return -3;
        }
    }

    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "store: NULL fingerprint\n");
        pthread_mutex_unlock(&g_store_mutex);
        return -1;
    }

    /* Begin transaction */
    char *err_msg = NULL;
    int rc = sqlite3_exec(g_db, "BEGIN TRANSACTION;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store: BEGIN failed: %s\n", err_msg);
        sqlite3_free(err_msg);
        pthread_mutex_unlock(&g_store_mutex);
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
            pthread_mutex_unlock(&g_store_mutex);
            return -1;
        }

        uint64_t now = (uint64_t)time(NULL);

        for (size_t i = 0; i < count; i++) {
            sqlite3_reset(ins_stmt);
            sqlite3_clear_bindings(ins_stmt);

            QGP_LOG_DEBUG(LOG_TAG, "store: INSERT [%zu] fp=%.32s... uuid=%s\n",
                         i, posts[i].author_fingerprint, posts[i].uuid);
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
                pthread_mutex_unlock(&g_store_mutex);
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
        pthread_mutex_unlock(&g_store_mutex);
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
        pthread_mutex_unlock(&g_store_mutex);
        return -1;
    }

    /* Commit transaction */
    rc = sqlite3_exec(g_db, "COMMIT;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store: COMMIT failed: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&g_store_mutex);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Stored %zu wall posts for %.16s...\n", count, fingerprint);
    /* DEBUG: Log mismatch between store fingerprint and post author */
    if (posts && count > 0 && strcmp(fingerprint, posts[0].author_fingerprint) != 0) {
        QGP_LOG_WARN(LOG_TAG, "MISMATCH: store fp=%.32s... vs post[0].author=%.32s...\n",
                     fingerprint, posts[0].author_fingerprint);
    }
    /* DEBUG: Verify rows actually persisted after COMMIT */
    {
        const char *sql_verify = "SELECT COUNT(*) FROM wall_posts WHERE author_fingerprint = ?;";
        sqlite3_stmt *v_stmt = NULL;
        if (sqlite3_prepare_v2(g_db, sql_verify, -1, &v_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(v_stmt, 1, fingerprint, -1, SQLITE_STATIC);
            if (sqlite3_step(v_stmt) == SQLITE_ROW) {
                int db_count = sqlite3_column_int(v_stmt, 0);
                QGP_LOG_INFO(LOG_TAG, "store: verify fp=%.16s... inserted=%zu db_count=%d\n",
                             fingerprint, count, db_count);
            }
            sqlite3_finalize(v_stmt);
        }
    }
    pthread_mutex_unlock(&g_store_mutex);
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

    /* Two-phase query to avoid SQLITE_IOERR from temp sorter on large blobs.
     * Phase 1: index-only scan for UUIDs in sorted order.
     * Phase 2: fetch full rows by UUID (no ORDER BY). */
    const char *sql_uuids =
        "SELECT uuid FROM wall_posts WHERE author_fingerprint = ? "
        "ORDER BY timestamp DESC;";

    sqlite3_stmt *uuid_stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql_uuids, -1, &uuid_stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "load: prepare: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(uuid_stmt, 1, fingerprint, -1, SQLITE_STATIC);

    /* Collect UUIDs */
    char uuids[200][37];
    size_t n = 0;
    while (sqlite3_step(uuid_stmt) == SQLITE_ROW && n < 200) {
        const char *u = (const char *)sqlite3_column_text(uuid_stmt, 0);
        if (u) {
            strncpy(uuids[n], u, 36);
            uuids[n][36] = '\0';
            n++;
        }
    }
    sqlite3_finalize(uuid_stmt);

    if (n == 0) {
        return -2; /* Not found */
    }

    /* Allocate array */
    dna_wall_post_t *result = calloc(n, sizeof(dna_wall_post_t));
    if (!result) {
        QGP_LOG_ERROR(LOG_TAG, "load: calloc failed\n");
        return -1;
    }

    /* Fetch full rows by UUID */
    const char *sql_full =
        "SELECT uuid, author_fingerprint, text, image_json, timestamp, "
        "signature, signature_len, verified "
        "FROM wall_posts WHERE uuid = ?;";

    size_t i = 0;
    for (size_t k = 0; k < n; k++) {
        sqlite3_stmt *full_stmt = NULL;
        rc = sqlite3_prepare_v2(g_db, sql_full, -1, &full_stmt, NULL);
        if (rc != SQLITE_OK) continue;
        sqlite3_bind_text(full_stmt, 1, uuids[k], -1, SQLITE_STATIC);
        if (sqlite3_step(full_stmt) == SQLITE_ROW) {
            fill_post_from_row(full_stmt, &result[i]);
            i++;
        }
        sqlite3_finalize(full_stmt);
    }

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

    /* Two-phase query: Phase 1 collects UUIDs via index-only scan (no blob I/O),
     * Phase 2 fetches full rows by UUID (no ORDER BY, no temp sorter).
     * This avoids SQLITE_IOERR when ORDER BY tries to sort large image_json blobs
     * through temp file storage on some Android devices. */
    const char *sql_uuids =
        "SELECT uuid FROM wall_posts WHERE author_fingerprint = ? "
        "ORDER BY timestamp DESC;";

    const char *sql_full =
        "SELECT uuid, author_fingerprint, text, image_json, timestamp, "
        "signature, signature_len, verified "
        "FROM wall_posts WHERE uuid = ?;";

    for (size_t f = 0; f < fp_count; f++) {
        /* Phase 1: Get sorted UUIDs (index-only scan with composite index) */
        sqlite3_stmt *uuid_stmt = NULL;
        int rc = sqlite3_prepare_v2(g_db, sql_uuids, -1, &uuid_stmt, NULL);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "load_timeline: prepare[%zu]: %s\n", f, sqlite3_errmsg(g_db));
            continue;
        }
        sqlite3_bind_text(uuid_stmt, 1, fingerprints[f], -1, SQLITE_STATIC);

        /* Collect UUIDs into temp array */
        char uuids[200][37];  /* max 200 UUIDs, 36 chars + null */
        size_t uuid_count = 0;
        int step_rc;
        while ((step_rc = sqlite3_step(uuid_stmt)) == SQLITE_ROW && uuid_count < 200) {
            const char *u = (const char *)sqlite3_column_text(uuid_stmt, 0);
            if (u) {
                strncpy(uuids[uuid_count], u, 36);
                uuids[uuid_count][36] = '\0';
                uuid_count++;
            }
            if (total + uuid_count >= 200) break;
        }
        sqlite3_finalize(uuid_stmt);

        /* Phase 2: Fetch full rows by UUID (no ORDER BY needed) */
        size_t count_before = total;
        for (size_t u = 0; u < uuid_count; u++) {
            if (total >= capacity) {
                size_t new_cap = capacity * 2;
                if (new_cap > 200) new_cap = 200;
                if (total >= new_cap) break;
                dna_wall_post_t *tmp = realloc(merged, new_cap * sizeof(dna_wall_post_t));
                if (!tmp) break;
                memset(tmp + capacity, 0, (new_cap - capacity) * sizeof(dna_wall_post_t));
                merged = tmp;
                capacity = new_cap;
            }

            sqlite3_stmt *full_stmt = NULL;
            rc = sqlite3_prepare_v2(g_db, sql_full, -1, &full_stmt, NULL);
            if (rc != SQLITE_OK) continue;
            sqlite3_bind_text(full_stmt, 1, uuids[u], -1, SQLITE_STATIC);
            if (sqlite3_step(full_stmt) == SQLITE_ROW) {
                fill_post_from_row(full_stmt, &merged[total]);
                total++;
            }
            sqlite3_finalize(full_stmt);
            if (total >= 200) break;
        }
        size_t select_rows = total - count_before;
        if (select_rows == 0 && step_rc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "load_timeline: fp[%zu] sqlite3_step returned %d (%s) errmsg=%s",
                          f, step_rc, sqlite3_errstr(step_rc), sqlite3_errmsg(g_db));
            /* Fatal DB error: nuke and return empty timeline (DHT will repopulate) */
            if (is_fatal_sqlite_error(step_rc)) {
                QGP_LOG_WARN(LOG_TAG, "load_timeline: fatal error %d, triggering recovery\n", step_rc);
                /* Free any posts we already collected */
                for (size_t k = 0; k < total; k++) {
                    free(merged[k].image_json);
                }
                free(merged);
                wall_cache_nuke_and_reopen();
                *posts = NULL;
                *count = 0;
                return 0; /* Empty timeline — DHT fetch will repopulate */
            }
        }
        QGP_LOG_INFO(LOG_TAG, "load_timeline: fp[%zu]=%.32s... (len=%zu) → %zu rows (step_rc=%d)",
                     f, fingerprints[f], fingerprints[f] ? strlen(fingerprints[f]) : 0,
                     select_rows, step_rc);
        /* DEBUG: if SELECT returned 0, exhaustive diagnosis */
        if (select_rows == 0 && fingerprints[f]) {
            /* 1. COUNT with same WHERE */
            const char *dbg_sql = "SELECT COUNT(*) FROM wall_posts WHERE author_fingerprint = ?;";
            sqlite3_stmt *dbg = NULL;
            int dbg_count = 0;
            if (sqlite3_prepare_v2(g_db, dbg_sql, -1, &dbg, NULL) == SQLITE_OK) {
                sqlite3_bind_text(dbg, 1, fingerprints[f], -1, SQLITE_STATIC);
                if (sqlite3_step(dbg) == SQLITE_ROW) {
                    dbg_count = sqlite3_column_int(dbg, 0);
                }
                sqlite3_finalize(dbg);
            }

            /* 2. SELECT WITHOUT ORDER BY */
            const char *no_order_sql =
                "SELECT uuid, author_fingerprint FROM wall_posts WHERE author_fingerprint = ?;";
            sqlite3_stmt *no_stmt = NULL;
            int no_order_count = 0;
            if (sqlite3_prepare_v2(g_db, no_order_sql, -1, &no_stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(no_stmt, 1, fingerprints[f], -1, SQLITE_STATIC);
                while (sqlite3_step(no_stmt) == SQLITE_ROW) {
                    no_order_count++;
                    if (no_order_count == 1) {
                        /* Log first matching row's fingerprint for comparison */
                        const char *db_fp = (const char *)sqlite3_column_text(no_stmt, 1);
                        QGP_LOG_WARN(LOG_TAG, "load_timeline: NO-ORDER fp[%zu] row1 db_fp=%s",
                                     f, db_fp ? db_fp : "(null)");
                    }
                }
                sqlite3_finalize(no_stmt);
            }

            /* 3. Total rows in table */
            const char *total_sql = "SELECT COUNT(*) FROM wall_posts;";
            sqlite3_stmt *tot = NULL;
            int total_rows = 0;
            if (sqlite3_prepare_v2(g_db, total_sql, -1, &tot, NULL) == SQLITE_OK) {
                if (sqlite3_step(tot) == SQLITE_ROW) {
                    total_rows = sqlite3_column_int(tot, 0);
                }
                sqlite3_finalize(tot);
            }

            /* 4. FULL table scan — list all distinct author_fingerprints */
            const char *authors_sql = "SELECT DISTINCT author_fingerprint, COUNT(*) FROM wall_posts GROUP BY author_fingerprint;";
            sqlite3_stmt *auth_stmt = NULL;
            if (sqlite3_prepare_v2(g_db, authors_sql, -1, &auth_stmt, NULL) == SQLITE_OK) {
                QGP_LOG_WARN(LOG_TAG, "load_timeline: DB DUMP — %d total rows, queried fp=%.32s...", total_rows, fingerprints[f]);
                while (sqlite3_step(auth_stmt) == SQLITE_ROW) {
                    const char *afp = (const char *)sqlite3_column_text(auth_stmt, 0);
                    int acnt = sqlite3_column_int(auth_stmt, 1);
                    QGP_LOG_WARN(LOG_TAG, "load_timeline:   author=%.32s... count=%d %s",
                                 afp ? afp : "(null)", acnt,
                                 (afp && fingerprints[f] && strcmp(afp, fingerprints[f]) == 0) ? "← MATCH" : "");
                }
                sqlite3_finalize(auth_stmt);
            }

            QGP_LOG_WARN(LOG_TAG, "load_timeline: DIAG fp[%zu] COUNT=%d NO_ORDER_SELECT=%d total=%d",
                         f, dbg_count, no_order_count, total_rows);
        }
        if (total >= 200) break;
    }

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

    /* Phase 3: Content dedup — same author+text within 5 min = duplicate.
     * Array is sorted newest-first. Keep the OLDEST (last seen), drop newer dupes.
     * We walk backwards so the oldest survives. */
    {
        size_t deduped = 0;
        for (size_t i = 0; i < total; i++) {
            bool is_dup = false;
            /* Check against already-kept posts */
            for (size_t k = 0; k < deduped; k++) {
                /* Same author? */
                if (strcmp(merged[i].author_fingerprint,
                           merged[k].author_fingerprint) != 0) continue;
                /* Same text? */
                if (strcmp(merged[i].text, merged[k].text) != 0) continue;
                /* Within 5 minutes of each other? */
                uint64_t t1 = merged[i].timestamp;
                uint64_t t2 = merged[k].timestamp;
                uint64_t diff = (t1 > t2) ? (t1 - t2) : (t2 - t1);
                if (diff > 300) continue;
                /* Same image presence? */
                bool has_img_i = (merged[i].image_json != NULL &&
                                  merged[i].image_json[0] != '\0');
                bool has_img_k = (merged[k].image_json != NULL &&
                                  merged[k].image_json[0] != '\0');
                if (has_img_i != has_img_k) continue;
                /* Duplicate found — drop this one */
                is_dup = true;
                QGP_LOG_DEBUG(LOG_TAG, "load_timeline: dedup dropping %s (dup of %s)",
                              merged[i].uuid, merged[k].uuid);
                free(merged[i].image_json);
                merged[i].image_json = NULL;
                break;
            }
            if (!is_dup) {
                if (deduped != i) {
                    merged[deduped] = merged[i];
                }
                deduped++;
            }
        }
        if (deduped < total) {
            QGP_LOG_INFO(LOG_TAG, "load_timeline: deduped %zu → %zu posts",
                         total, deduped);
            total = deduped;
        }
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
        QGP_LOG_WARN(LOG_TAG, "is_stale: prepare failed for %.16s...: %s",
                     fingerprint, sqlite3_errmsg(g_db));
        return true;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);

    bool stale = true;
    bool has_meta = false;
    uint64_t age = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        has_meta = true;
        uint64_t last_fetched = (uint64_t)sqlite3_column_int64(stmt, 0);
        uint64_t now = (uint64_t)time(NULL);
        age = now - last_fetched;
        stale = (age >= WALL_CACHE_TTL_SECONDS);
    }

    sqlite3_finalize(stmt);

    /* 0-post check: meta fresh but no cached posts → force stale */
    int post_count = -1;
    if (!stale && has_meta) {
        const char *cnt_sql =
            "SELECT COUNT(*) FROM wall_posts WHERE author_fingerprint = ?;";
        sqlite3_stmt *cnt_stmt = NULL;
        if (sqlite3_prepare_v2(g_db, cnt_sql, -1, &cnt_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(cnt_stmt, 1, fingerprint, -1, SQLITE_STATIC);
            if (sqlite3_step(cnt_stmt) == SQLITE_ROW) {
                post_count = sqlite3_column_int(cnt_stmt, 0);
                if (post_count == 0) {
                    stale = true;
                }
            }
            sqlite3_finalize(cnt_stmt);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "is_stale: %.16s... meta=%s age=%llu post_count=%d → %s",
                 fingerprint,
                 has_meta ? "YES" : "NO",
                 (unsigned long long)age,
                 post_count,
                 stale ? "STALE" : "FRESH");

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

/* ── Boost pointer cache (v0.9.98+) ──────────────────────────────── */

int wall_cache_store_boosts(const dna_wall_boost_ptr_t *ptrs, size_t count) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }
    if (!ptrs || count == 0) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO wall_boost_pointers "
        "(uuid, author_fingerprint, timestamp, cached_at) VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store_boosts prepare: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    for (size_t i = 0; i < count; i++) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_bind_text(stmt, 1, ptrs[i].uuid, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, ptrs[i].author_fingerprint, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, (int64_t)ptrs[i].timestamp);
        sqlite3_bind_int64(stmt, 4, (int64_t)now);
        sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);
    QGP_LOG_DEBUG(LOG_TAG, "Stored %zu boost pointers in cache", count);
    return 0;
}

int wall_cache_load_boosts(dna_wall_boost_ptr_t **ptrs_out, size_t *count_out) {
    if (!g_db) {
        if (wall_cache_init() != 0) return -3;
    }
    if (!ptrs_out || !count_out) return -1;

    *ptrs_out = NULL;
    *count_out = 0;

    /* Only load boosts cached in the last 7 days */
    uint64_t cutoff = (uint64_t)time(NULL) - 604800;

    const char *sql =
        "SELECT uuid, author_fingerprint, timestamp FROM wall_boost_pointers "
        "WHERE cached_at > ? ORDER BY timestamp DESC LIMIT 50;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "load_boosts prepare: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (int64_t)cutoff);

    size_t capacity = 16;
    size_t total = 0;
    dna_wall_boost_ptr_t *ptrs = calloc(capacity, sizeof(dna_wall_boost_ptr_t));
    if (!ptrs) {
        sqlite3_finalize(stmt);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (total >= capacity) {
            size_t new_cap = capacity * 2;
            if (new_cap > 50) new_cap = 50;
            if (total >= new_cap) break;
            dna_wall_boost_ptr_t *tmp = realloc(ptrs, new_cap * sizeof(dna_wall_boost_ptr_t));
            if (!tmp) break;
            ptrs = tmp;
            capacity = new_cap;
        }

        const char *uuid_str = (const char *)sqlite3_column_text(stmt, 0);
        const char *fp_str = (const char *)sqlite3_column_text(stmt, 1);
        if (uuid_str) strncpy(ptrs[total].uuid, uuid_str, 36);
        ptrs[total].uuid[36] = '\0';
        if (fp_str) strncpy(ptrs[total].author_fingerprint, fp_str, 128);
        ptrs[total].author_fingerprint[128] = '\0';
        ptrs[total].timestamp = (uint64_t)sqlite3_column_int64(stmt, 2);
        total++;
    }

    sqlite3_finalize(stmt);

    if (total == 0) {
        free(ptrs);
        return -2;
    }

    *ptrs_out = ptrs;
    *count_out = total;
    return 0;
}

/* ============================================================================
 * Daily Bucket Meta (v0.9.141+)
 * ============================================================================ */

bool wall_cache_is_stale_wall_meta(const char *fingerprint) {
    if (!fingerprint) return true;
    char cache_key[256];
    snprintf(cache_key, sizeof(cache_key), "meta:%s", fingerprint);
    return wall_cache_is_stale(cache_key);
}

int wall_cache_update_wall_meta(const char *fingerprint) {
    if (!fingerprint) return -1;
    char cache_key[256];
    snprintf(cache_key, sizeof(cache_key), "meta:%s", fingerprint);
    return wall_cache_update_meta(cache_key);
}

bool wall_cache_is_stale_day(const char *fingerprint, const char *date_str) {
    if (!fingerprint || !date_str) return true;
    char cache_key[256];
    snprintf(cache_key, sizeof(cache_key), "%s:%s", fingerprint, date_str);
    return wall_cache_is_stale(cache_key);
}

int wall_cache_update_meta_day(const char *fingerprint, const char *date_str) {
    if (!fingerprint || !date_str) return -1;
    char cache_key[256];
    snprintf(cache_key, sizeof(cache_key), "%s:%s", fingerprint, date_str);
    return wall_cache_update_meta(cache_key);
}

int wall_cache_store_wall_meta(const char *fingerprint, const char *meta_json) {
    if (!fingerprint || !meta_json) return -1;
    if (!g_db) return -3;

    pthread_mutex_lock(&g_store_mutex);

    const char *sql = "INSERT OR REPLACE INTO wall_day_meta "
                      "(fingerprint, meta_json, cached_at) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "store_wall_meta prepare: %s", sqlite3_errmsg(g_db));
        pthread_mutex_unlock(&g_store_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, meta_json, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_store_mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int wall_cache_load_wall_meta(const char *fingerprint, char **meta_json_out) {
    if (!fingerprint || !meta_json_out) return -1;
    if (!g_db) return -3;
    *meta_json_out = NULL;

    pthread_mutex_lock(&g_store_mutex);

    const char *sql = "SELECT meta_json FROM wall_day_meta WHERE fingerprint = ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_store_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        const char *json = (const char *)sqlite3_column_text(stmt, 0);
        if (json) *meta_json_out = strdup(json);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_store_mutex);

    return *meta_json_out ? 0 : -2;
}

uint64_t wall_cache_get_post_timestamp(const char *post_uuid) {
    if (!post_uuid || !g_db) return 0;

    pthread_mutex_lock(&g_store_mutex);

    const char *sql = "SELECT timestamp FROM wall_posts WHERE uuid = ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g_store_mutex);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, post_uuid, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    uint64_t ts = 0;
    if (rc == SQLITE_ROW) {
        ts = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_store_mutex);
    return ts;
}
