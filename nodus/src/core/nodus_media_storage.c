/**
 * Nodus — Media Storage (SQLite)
 *
 * Chunked media storage for photos/videos/audio up to 64MB.
 * Content-addressed by SHA3-512 hash, stored in 4MB chunks.
 * Shares the existing SQLite database handle with main storage.
 */

#include "core/nodus_media_storage.h"
#include "crypto/utils/qgp_log.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "MEDIA_STORE"

/* ── Schema ──────────────────────────────────────────────────────── */

static const char *MEDIA_SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS media_meta ("
    "  content_hash  BLOB PRIMARY KEY,"
    "  owner_fp      TEXT NOT NULL,"
    "  media_type    INTEGER NOT NULL,"
    "  total_size    INTEGER NOT NULL,"
    "  chunk_count   INTEGER NOT NULL,"
    "  encrypted     INTEGER NOT NULL,"
    "  ttl           INTEGER NOT NULL,"
    "  created_at    INTEGER NOT NULL,"
    "  expires_at    INTEGER NOT NULL,"
    "  complete      INTEGER DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS media_chunks ("
    "  content_hash  BLOB NOT NULL,"
    "  chunk_index   INTEGER NOT NULL,"
    "  data          BLOB NOT NULL,"
    "  PRIMARY KEY (content_hash, chunk_index)"
    ");";

static const char *PUT_META_SQL =
    "INSERT OR IGNORE INTO media_meta "
    "(content_hash, owner_fp, media_type, total_size, chunk_count, "
    " encrypted, ttl, created_at, expires_at, complete) "
    "VALUES (?,?,?,?,?,?,?,?,?,?)";

static const char *PUT_CHUNK_SQL =
    "INSERT OR REPLACE INTO media_chunks "
    "(content_hash, chunk_index, data) VALUES (?,?,?)";

static const char *GET_META_SQL =
    "SELECT content_hash, owner_fp, media_type, total_size, chunk_count, "
    "       encrypted, ttl, created_at, expires_at, complete "
    "FROM media_meta WHERE content_hash = ?";

static const char *GET_CHUNK_SQL =
    "SELECT data FROM media_chunks WHERE content_hash = ? AND chunk_index = ?";

static const char *EXISTS_SQL =
    "SELECT complete FROM media_meta WHERE content_hash = ?";

static const char *MARK_COMPLETE_SQL =
    "UPDATE media_meta SET complete = 1 WHERE content_hash = ?";

static const char *COUNT_CHUNKS_SQL =
    "SELECT COUNT(*) FROM media_chunks WHERE content_hash = ?";

static const char *CLEANUP_EXPIRED_SQL =
    "DELETE FROM media_meta WHERE expires_at > 0 AND expires_at <= ?";

static const char *CLEANUP_EXPIRED_CHUNKS_SQL =
    "DELETE FROM media_chunks WHERE content_hash NOT IN "
    "(SELECT content_hash FROM media_meta)";

static const char *CLEANUP_INCOMPLETE_SQL =
    "DELETE FROM media_meta WHERE complete = 0 AND created_at <= ?";

static const char *COUNT_PER_OWNER_SQL =
    "SELECT COUNT(*) FROM media_meta WHERE owner_fp = ?";

/* ── API ─────────────────────────────────────────────────────────── */

int nodus_media_storage_open(sqlite3 *db, nodus_media_storage_t *ms) {
    if (!db || !ms) return -1;

    memset(ms, 0, sizeof(*ms));
    ms->db = db;

    /* Create schema */
    char *err = NULL;
    int rc = sqlite3_exec(db, MEDIA_SCHEMA_SQL, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "schema creation failed: %s", err ? err : "unknown");
        sqlite3_free(err);
        return -1;
    }

    /* Prepare all statements */
    if (sqlite3_prepare_v2(db, PUT_META_SQL, -1, &ms->stmt_put_meta, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, PUT_CHUNK_SQL, -1, &ms->stmt_put_chunk, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, GET_META_SQL, -1, &ms->stmt_get_meta, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, GET_CHUNK_SQL, -1, &ms->stmt_get_chunk, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, EXISTS_SQL, -1, &ms->stmt_exists, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, MARK_COMPLETE_SQL, -1, &ms->stmt_mark_complete, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, COUNT_CHUNKS_SQL, -1, &ms->stmt_count_chunks, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, CLEANUP_EXPIRED_SQL, -1, &ms->stmt_cleanup_expired, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, CLEANUP_INCOMPLETE_SQL, -1, &ms->stmt_cleanup_incomplete, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, COUNT_PER_OWNER_SQL, -1, &ms->stmt_count_per_owner, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "statement preparation failed: %s", sqlite3_errmsg(db));
        nodus_media_storage_close(ms);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "media storage opened");
    return 0;
}

void nodus_media_storage_close(nodus_media_storage_t *ms) {
    if (!ms) return;
    if (ms->stmt_put_meta)           sqlite3_finalize(ms->stmt_put_meta);
    if (ms->stmt_put_chunk)          sqlite3_finalize(ms->stmt_put_chunk);
    if (ms->stmt_get_meta)           sqlite3_finalize(ms->stmt_get_meta);
    if (ms->stmt_get_chunk)          sqlite3_finalize(ms->stmt_get_chunk);
    if (ms->stmt_exists)             sqlite3_finalize(ms->stmt_exists);
    if (ms->stmt_mark_complete)      sqlite3_finalize(ms->stmt_mark_complete);
    if (ms->stmt_count_chunks)       sqlite3_finalize(ms->stmt_count_chunks);
    if (ms->stmt_cleanup_expired)    sqlite3_finalize(ms->stmt_cleanup_expired);
    if (ms->stmt_cleanup_incomplete) sqlite3_finalize(ms->stmt_cleanup_incomplete);
    if (ms->stmt_count_per_owner)    sqlite3_finalize(ms->stmt_count_per_owner);
    /* NOTE: We do NOT close ms->db — it is owned by the caller (main storage) */
    memset(ms, 0, sizeof(*ms));
}

int nodus_media_put_meta(nodus_media_storage_t *ms, const nodus_media_meta_t *meta) {
    if (!ms || !ms->db || !meta) return -1;

    sqlite3_stmt *s = ms->stmt_put_meta;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, meta->content_hash, 64, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, meta->owner_fp, -1, SQLITE_STATIC);
    sqlite3_bind_int(s, 3, (int)meta->media_type);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)meta->total_size);
    sqlite3_bind_int(s, 5, (int)meta->chunk_count);
    sqlite3_bind_int(s, 6, meta->encrypted ? 1 : 0);
    sqlite3_bind_int(s, 7, (int)meta->ttl);
    sqlite3_bind_int64(s, 8, (sqlite3_int64)meta->created_at);
    sqlite3_bind_int64(s, 9, (sqlite3_int64)meta->expires_at);
    sqlite3_bind_int(s, 10, meta->complete ? 1 : 0);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "put_meta failed: %s", sqlite3_errmsg(ms->db));
        return -1;
    }

    return 0;
}

int nodus_media_put_chunk(nodus_media_storage_t *ms,
                          const uint8_t content_hash[64],
                          uint32_t chunk_index,
                          const uint8_t *data, size_t data_len) {
    if (!ms || !ms->db || !content_hash || !data) return -1;

    sqlite3_stmt *s = ms->stmt_put_chunk;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, content_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, (int)chunk_index);
    sqlite3_bind_blob(s, 3, data, (int)data_len, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "put_chunk failed: %s", sqlite3_errmsg(ms->db));
        return -1;
    }

    return 0;
}

int nodus_media_get_meta(nodus_media_storage_t *ms,
                         const uint8_t content_hash[64],
                         nodus_media_meta_t *meta_out) {
    if (!ms || !ms->db || !content_hash || !meta_out) return -1;

    sqlite3_stmt *s = ms->stmt_get_meta;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, content_hash, 64, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_ROW) return -1;

    memset(meta_out, 0, sizeof(*meta_out));

    /* content_hash */
    const void *blob = sqlite3_column_blob(s, 0);
    int blob_len = sqlite3_column_bytes(s, 0);
    if (blob && blob_len == 64)
        memcpy(meta_out->content_hash, blob, 64);

    /* owner_fp */
    const char *fp = (const char *)sqlite3_column_text(s, 1);
    if (fp) {
        strncpy(meta_out->owner_fp, fp, sizeof(meta_out->owner_fp) - 1);
        meta_out->owner_fp[sizeof(meta_out->owner_fp) - 1] = '\0';
    }

    meta_out->media_type  = (uint8_t)sqlite3_column_int(s, 2);
    meta_out->total_size  = (uint64_t)sqlite3_column_int64(s, 3);
    meta_out->chunk_count = (uint32_t)sqlite3_column_int(s, 4);
    meta_out->encrypted   = sqlite3_column_int(s, 5) != 0;
    meta_out->ttl         = (uint32_t)sqlite3_column_int(s, 6);
    meta_out->created_at  = (uint64_t)sqlite3_column_int64(s, 7);
    meta_out->expires_at  = (uint64_t)sqlite3_column_int64(s, 8);
    meta_out->complete    = sqlite3_column_int(s, 9) != 0;

    return 0;
}

int nodus_media_get_chunk(nodus_media_storage_t *ms,
                          const uint8_t content_hash[64],
                          uint32_t chunk_index,
                          uint8_t **data_out, size_t *data_len_out) {
    if (!ms || !ms->db || !content_hash || !data_out || !data_len_out) return -1;

    sqlite3_stmt *s = ms->stmt_get_chunk;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, content_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, (int)chunk_index);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_ROW) return -1;

    const void *blob = sqlite3_column_blob(s, 0);
    int blob_len = sqlite3_column_bytes(s, 0);
    if (!blob || blob_len <= 0) return -1;

    *data_out = malloc((size_t)blob_len);
    if (!*data_out) return -1;

    memcpy(*data_out, blob, (size_t)blob_len);
    *data_len_out = (size_t)blob_len;

    return 0;
}

int nodus_media_exists(nodus_media_storage_t *ms,
                       const uint8_t content_hash[64],
                       bool *exists_out, bool *complete_out) {
    if (!ms || !ms->db || !content_hash || !exists_out || !complete_out) return -1;

    sqlite3_stmt *s = ms->stmt_exists;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, content_hash, 64, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_ROW) {
        *exists_out = false;
        *complete_out = false;
        return 0;
    }

    *exists_out = true;
    *complete_out = sqlite3_column_int(s, 0) != 0;
    return 0;
}

int nodus_media_mark_complete(nodus_media_storage_t *ms,
                              const uint8_t content_hash[64]) {
    if (!ms || !ms->db || !content_hash) return -1;

    sqlite3_stmt *s = ms->stmt_mark_complete;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, content_hash, 64, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "mark_complete failed: %s", sqlite3_errmsg(ms->db));
        return -1;
    }

    return (sqlite3_changes(ms->db) > 0) ? 0 : -1;
}

int nodus_media_count_chunks(nodus_media_storage_t *ms,
                             const uint8_t content_hash[64]) {
    if (!ms || !ms->db || !content_hash) return -1;

    sqlite3_stmt *s = ms->stmt_count_chunks;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, content_hash, 64, SQLITE_STATIC);

    if (sqlite3_step(s) == SQLITE_ROW)
        return sqlite3_column_int(s, 0);

    return -1;
}

int nodus_media_cleanup(nodus_media_storage_t *ms) {
    if (!ms || !ms->db) return -1;

    uint64_t now = (uint64_t)time(NULL);
    int total_cleaned = 0;

    /* 1. Delete expired media meta */
    sqlite3_stmt *s = ms->stmt_cleanup_expired;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)now);

    int rc = sqlite3_step(s);
    if (rc == SQLITE_DONE)
        total_cleaned += sqlite3_changes(ms->db);

    /* 2. Delete incomplete uploads older than timeout */
    uint64_t cutoff = now - NODUS_MEDIA_INCOMPLETE_TIMEOUT;
    s = ms->stmt_cleanup_incomplete;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)cutoff);

    rc = sqlite3_step(s);
    if (rc == SQLITE_DONE)
        total_cleaned += sqlite3_changes(ms->db);

    /* 3. Delete orphaned chunks (meta was deleted above) */
    if (total_cleaned > 0) {
        char *err = NULL;
        sqlite3_exec(ms->db, CLEANUP_EXPIRED_CHUNKS_SQL, NULL, NULL, &err);
        if (err) {
            QGP_LOG_WARN(LOG_TAG, "orphan chunk cleanup error: %s", err);
            sqlite3_free(err);
        }
    }

    if (total_cleaned > 0)
        QGP_LOG_INFO(LOG_TAG, "cleaned %d expired/incomplete media entries", total_cleaned);

    return total_cleaned;
}

int nodus_media_count_per_owner(nodus_media_storage_t *ms,
                                const char *owner_fp) {
    if (!ms || !ms->db || !owner_fp) return -1;

    sqlite3_stmt *s = ms->stmt_count_per_owner;
    sqlite3_reset(s);

    sqlite3_bind_text(s, 1, owner_fp, -1, SQLITE_STATIC);

    if (sqlite3_step(s) == SQLITE_ROW)
        return sqlite3_column_int(s, 0);

    return -1;
}
