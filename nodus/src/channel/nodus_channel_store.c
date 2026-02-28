/**
 * Nodus v5 — Channel Storage Implementation
 *
 * Per-channel SQLite tables, hinted handoff queue, retention cleanup.
 */

#include "channel/nodus_channel_store.h"
#include "transport/nodus_tcp.h"  /* nodus_time_now() */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── UUID validation + hex conversion ───────────────────────────── */

static void uuid_to_hex(const uint8_t uuid[NODUS_UUID_BYTES], char hex[33]) {
    for (int i = 0; i < NODUS_UUID_BYTES; i++)
        snprintf(hex + i * 2, 3, "%02x", uuid[i]);
    hex[32] = '\0';
}

static bool uuid_hex_valid(const char hex[33]) {
    for (int i = 0; i < 32; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return hex[32] == '\0';
}

/* ── SQL helpers ────────────────────────────────────────────────── */

static int exec_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err ? err : "unknown");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ── Public API ──────────────────────────────────────────────────── */

int nodus_channel_store_open(const char *db_path, nodus_channel_store_t *store) {
    if (!db_path || !store) return -1;
    memset(store, 0, sizeof(*store));

    int rc = sqlite3_open(db_path, &store->db);
    if (rc != SQLITE_OK) return -1;

    /* WAL mode for concurrent reads */
    exec_sql(store->db, "PRAGMA journal_mode=WAL");
    exec_sql(store->db, "PRAGMA synchronous=NORMAL");

    /* Create hinted handoff table */
    rc = exec_sql(store->db,
        "CREATE TABLE IF NOT EXISTS hinted_handoff ("
        "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  target_fp    BLOB NOT NULL,"
        "  channel_uuid BLOB NOT NULL,"
        "  post_data    BLOB NOT NULL,"
        "  created_at   INTEGER NOT NULL,"
        "  retry_count  INTEGER DEFAULT 0,"
        "  expires_at   INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_hinted_target ON hinted_handoff(target_fp);"
        "CREATE INDEX IF NOT EXISTS idx_hinted_expires ON hinted_handoff(expires_at);");
    if (rc != 0) { sqlite3_close(store->db); store->db = NULL; return -1; }

    /* Prepare hinted handoff statements */
    sqlite3_prepare_v2(store->db,
        "INSERT INTO hinted_handoff (target_fp, channel_uuid, post_data, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        -1, &store->stmt_hint_insert, NULL);

    sqlite3_prepare_v2(store->db,
        "SELECT id, target_fp, channel_uuid, post_data, created_at, retry_count, expires_at "
        "FROM hinted_handoff WHERE target_fp = ? ORDER BY id LIMIT ?",
        -1, &store->stmt_hint_get, NULL);

    sqlite3_prepare_v2(store->db,
        "DELETE FROM hinted_handoff WHERE id = ?",
        -1, &store->stmt_hint_delete, NULL);

    sqlite3_prepare_v2(store->db,
        "DELETE FROM hinted_handoff WHERE expires_at < ?",
        -1, &store->stmt_hint_cleanup, NULL);

    sqlite3_prepare_v2(store->db,
        "UPDATE hinted_handoff SET retry_count = retry_count + 1 WHERE id = ?",
        -1, &store->stmt_hint_update_retry, NULL);

    return 0;
}

void nodus_channel_store_close(nodus_channel_store_t *store) {
    if (!store) return;
    if (store->stmt_hint_insert)       sqlite3_finalize(store->stmt_hint_insert);
    if (store->stmt_hint_get)          sqlite3_finalize(store->stmt_hint_get);
    if (store->stmt_hint_delete)       sqlite3_finalize(store->stmt_hint_delete);
    if (store->stmt_hint_cleanup)      sqlite3_finalize(store->stmt_hint_cleanup);
    if (store->stmt_hint_update_retry) sqlite3_finalize(store->stmt_hint_update_retry);
    if (store->db) sqlite3_close(store->db);
    memset(store, 0, sizeof(*store));
}

int nodus_channel_create(nodus_channel_store_t *store,
                          const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!store || !store->db || !uuid) return -1;

    char hex[33];
    uuid_to_hex(uuid, hex);
    if (!uuid_hex_valid(hex)) return -1;

    char sql[384];

    snprintf(sql, sizeof(sql),
        "CREATE TABLE IF NOT EXISTS channel_%s ("
        "seq_id INTEGER NOT NULL,"
        "post_uuid BLOB NOT NULL,"
        "author_fp BLOB NOT NULL,"
        "timestamp INTEGER NOT NULL,"
        "body BLOB NOT NULL,"
        "signature BLOB NOT NULL,"
        "received_at INTEGER NOT NULL,"
        "PRIMARY KEY(seq_id))", hex);
    if (exec_sql(store->db, sql) != 0) return -1;

    snprintf(sql, sizeof(sql),
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_%s_uuid ON channel_%s(post_uuid)",
        hex, hex);
    if (exec_sql(store->db, sql) != 0) return -1;

    snprintf(sql, sizeof(sql),
        "CREATE INDEX IF NOT EXISTS idx_%s_recv ON channel_%s(received_at)",
        hex, hex);
    return exec_sql(store->db, sql);
}

bool nodus_channel_exists(nodus_channel_store_t *store,
                           const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!store || !store->db || !uuid) return false;

    char hex[33];
    uuid_to_hex(uuid, hex);
    if (!uuid_hex_valid(hex)) return false;

    char sql[128];
    snprintf(sql, sizeof(sql),
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='channel_%s'", hex);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return false;

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

int nodus_channel_post(nodus_channel_store_t *store,
                        nodus_channel_post_t *post) {
    if (!store || !store->db || !post) return -1;

    char hex[33];
    uuid_to_hex(post->channel_uuid, hex);
    if (!uuid_hex_valid(hex)) return -1;

    /* Get next seq_id */
    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT COALESCE(MAX(seq_id), 0) FROM channel_%s", hex);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    uint32_t next_seq = 1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        next_seq = (uint32_t)sqlite3_column_int(stmt, 0) + 1;
    sqlite3_finalize(stmt);

    post->seq_id = next_seq;
    post->received_at = nodus_time_now();

    /* Check duplicate post_uuid */
    snprintf(sql, sizeof(sql),
        "SELECT 1 FROM channel_%s WHERE post_uuid = ?", hex);
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(stmt, 1, post->post_uuid, NODUS_UUID_BYTES, SQLITE_STATIC);
    bool duplicate = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    if (duplicate) return 1;  /* Duplicate — not an error */

    /* Insert */
    snprintf(sql, sizeof(sql),
        "INSERT INTO channel_%s (seq_id, post_uuid, author_fp, timestamp, body, signature, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)", hex);

    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_int(stmt, 1, (int)post->seq_id);
    sqlite3_bind_blob(stmt, 2, post->post_uuid, NODUS_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, post->author_fp.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (int64_t)post->timestamp);
    sqlite3_bind_blob(stmt, 5, post->body, (int)post->body_len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, post->signature.bytes, NODUS_SIG_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, (int64_t)post->received_at);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int nodus_channel_get_posts(nodus_channel_store_t *store,
                             const uint8_t uuid[NODUS_UUID_BYTES],
                             uint32_t since_seq, int max_count,
                             nodus_channel_post_t **posts_out,
                             size_t *count_out) {
    if (!store || !store->db || !uuid || !posts_out || !count_out) return -1;
    *posts_out = NULL;
    *count_out = 0;

    char hex[33];
    uuid_to_hex(uuid, hex);
    if (!uuid_hex_valid(hex)) return -1;

    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT seq_id, post_uuid, author_fp, timestamp, body, signature, received_at "
        "FROM channel_%s WHERE seq_id > ? ORDER BY seq_id LIMIT ?", hex);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_int(stmt, 1, (int)since_seq);
    sqlite3_bind_int(stmt, 2, max_count > 0 ? max_count : 1000);

    size_t cap = 64;
    size_t count = 0;
    nodus_channel_post_t *posts = calloc(cap, sizeof(*posts));
    if (!posts) { sqlite3_finalize(stmt); return -1; }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2;
            nodus_channel_post_t *p = realloc(posts, cap * sizeof(*p));
            if (!p) break;
            posts = p;
        }

        nodus_channel_post_t *p = &posts[count];
        memset(p, 0, sizeof(*p));
        memcpy(p->channel_uuid, uuid, NODUS_UUID_BYTES);
        p->seq_id = (uint32_t)sqlite3_column_int(stmt, 0);

        const void *blob = sqlite3_column_blob(stmt, 1);
        if (blob) memcpy(p->post_uuid, blob, NODUS_UUID_BYTES);

        blob = sqlite3_column_blob(stmt, 2);
        if (blob) memcpy(p->author_fp.bytes, blob, NODUS_KEY_BYTES);

        p->timestamp = (uint64_t)sqlite3_column_int64(stmt, 3);

        blob = sqlite3_column_blob(stmt, 4);
        int blen = sqlite3_column_bytes(stmt, 4);
        if (blob && blen > 0) {
            p->body = malloc((size_t)blen + 1);
            if (p->body) {
                memcpy(p->body, blob, (size_t)blen);
                p->body[blen] = '\0';
                p->body_len = (size_t)blen;
            }
        }

        blob = sqlite3_column_blob(stmt, 5);
        if (blob) memcpy(p->signature.bytes, blob, NODUS_SIG_BYTES);

        p->received_at = (uint64_t)sqlite3_column_int64(stmt, 6);
        count++;
    }

    sqlite3_finalize(stmt);

    if (count == 0) {
        free(posts);
        return 0;
    }

    *posts_out = posts;
    *count_out = count;
    return 0;
}

uint32_t nodus_channel_max_seq(nodus_channel_store_t *store,
                                const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!store || !store->db || !uuid) return 0;

    char hex[33];
    uuid_to_hex(uuid, hex);
    if (!uuid_hex_valid(hex)) return 0;

    char sql[128];
    snprintf(sql, sizeof(sql),
        "SELECT COALESCE(MAX(seq_id), 0) FROM channel_%s", hex);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    uint32_t max_seq = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        max_seq = (uint32_t)sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return max_seq;
}

int nodus_channel_cleanup(nodus_channel_store_t *store,
                           const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!store || !store->db || !uuid) return -1;

    char hex[33];
    uuid_to_hex(uuid, hex);
    if (!uuid_hex_valid(hex)) return -1;

    uint64_t cutoff = nodus_time_now() - NODUS_CHANNEL_RETENTION;

    char sql[128];
    snprintf(sql, sizeof(sql),
        "DELETE FROM channel_%s WHERE received_at < %lu",
        hex, (unsigned long)cutoff);

    if (exec_sql(store->db, sql) != 0) return -1;
    return sqlite3_changes(store->db);
}

int nodus_channel_drop(nodus_channel_store_t *store,
                        const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!store || !store->db || !uuid) return -1;

    char hex[33];
    uuid_to_hex(uuid, hex);
    if (!uuid_hex_valid(hex)) return -1;

    char sql[128];
    snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS channel_%s", hex);
    return exec_sql(store->db, sql);
}

/* ── Hinted handoff ─────────────────────────────────────────────── */

int nodus_hinted_insert(nodus_channel_store_t *store,
                         const nodus_key_t *target_fp,
                         const uint8_t uuid[NODUS_UUID_BYTES],
                         const uint8_t *post_data, size_t post_data_len) {
    if (!store || !target_fp || !uuid || !post_data) return -1;

    sqlite3_stmt *s = store->stmt_hint_insert;
    sqlite3_reset(s);

    uint64_t now = nodus_time_now();
    sqlite3_bind_blob(s, 1, target_fp->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, uuid, NODUS_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 3, post_data, (int)post_data_len, SQLITE_STATIC);
    sqlite3_bind_int64(s, 4, (int64_t)now);
    sqlite3_bind_int64(s, 5, (int64_t)(now + NODUS_HINTED_TTL_SEC));

    return (sqlite3_step(s) == SQLITE_DONE) ? 0 : -1;
}

int nodus_hinted_get(nodus_channel_store_t *store,
                      const nodus_key_t *target_fp, int max_count,
                      nodus_hinted_entry_t **entries_out,
                      size_t *count_out) {
    if (!store || !target_fp || !entries_out || !count_out) return -1;
    *entries_out = NULL;
    *count_out = 0;

    sqlite3_stmt *s = store->stmt_hint_get;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, target_fp->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, max_count > 0 ? max_count : NODUS_MAX_HINTED_POSTS);

    size_t cap = 64;
    size_t count = 0;
    nodus_hinted_entry_t *entries = calloc(cap, sizeof(*entries));
    if (!entries) return -1;

    while (sqlite3_step(s) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2;
            nodus_hinted_entry_t *e = realloc(entries, cap * sizeof(*e));
            if (!e) break;
            entries = e;
        }

        nodus_hinted_entry_t *e = &entries[count];
        memset(e, 0, sizeof(*e));
        e->id = sqlite3_column_int64(s, 0);

        const void *blob = sqlite3_column_blob(s, 1);
        if (blob) memcpy(e->target_fp.bytes, blob, NODUS_KEY_BYTES);

        blob = sqlite3_column_blob(s, 2);
        if (blob) memcpy(e->channel_uuid, blob, NODUS_UUID_BYTES);

        blob = sqlite3_column_blob(s, 3);
        int blen = sqlite3_column_bytes(s, 3);
        if (blob && blen > 0) {
            e->post_data = malloc((size_t)blen);
            if (e->post_data) {
                memcpy(e->post_data, blob, (size_t)blen);
                e->post_data_len = (size_t)blen;
            }
        }

        e->created_at = (uint64_t)sqlite3_column_int64(s, 4);
        e->retry_count = sqlite3_column_int(s, 5);
        e->expires_at = (uint64_t)sqlite3_column_int64(s, 6);
        count++;
    }

    if (count == 0) {
        free(entries);
        return 0;
    }

    *entries_out = entries;
    *count_out = count;
    return 0;
}

int nodus_hinted_delete(nodus_channel_store_t *store, int64_t id) {
    if (!store) return -1;
    sqlite3_stmt *s = store->stmt_hint_delete;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, id);
    return (sqlite3_step(s) == SQLITE_DONE) ? 0 : -1;
}

int nodus_hinted_retry(nodus_channel_store_t *store, int64_t id) {
    if (!store) return -1;
    sqlite3_stmt *s = store->stmt_hint_update_retry;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, id);
    return (sqlite3_step(s) == SQLITE_DONE) ? 0 : -1;
}

int nodus_hinted_cleanup(nodus_channel_store_t *store) {
    if (!store) return -1;
    sqlite3_stmt *s = store->stmt_hint_cleanup;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (int64_t)nodus_time_now());
    if (sqlite3_step(s) != SQLITE_DONE) return -1;
    return sqlite3_changes(store->db);
}

/* ── Free helpers ───────────────────────────────────────────────── */

void nodus_channel_post_free(nodus_channel_post_t *post) {
    if (post) { free(post->body); post->body = NULL; }
}

void nodus_channel_posts_free(nodus_channel_post_t *posts, size_t count) {
    if (!posts) return;
    for (size_t i = 0; i < count; i++)
        nodus_channel_post_free(&posts[i]);
    free(posts);
}

void nodus_hinted_entries_free(nodus_hinted_entry_t *entries, size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++)
        free(entries[i].post_data);
    free(entries);
}
