/**
 * Nodus — SQLite DHT Storage
 *
 * Persistent storage for DHT values with TTL cleanup.
 * PRIMARY KEY: (key_hash, owner_fp, value_id)
 * Conflict resolution: INSERT OR REPLACE (seq comparison in application layer)
 */

#include "core/nodus_storage.h"
#include "crypto/hash/qgp_sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "NODUS_STORE"

/* ── Schema ──────────────────────────────────────────────────────── */

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS nodus_values ("
    "  key_hash  BLOB NOT NULL,"
    "  owner_fp  BLOB NOT NULL,"
    "  value_id  INTEGER NOT NULL,"
    "  data      BLOB,"
    "  type      INTEGER NOT NULL,"
    "  ttl       INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  expires_at INTEGER NOT NULL,"
    "  seq       INTEGER NOT NULL,"
    "  owner_pk  BLOB NOT NULL,"
    "  signature BLOB NOT NULL,"
    "  PRIMARY KEY (key_hash, owner_fp, value_id)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_nodus_values_key ON nodus_values(key_hash);"
    "CREATE INDEX IF NOT EXISTS idx_nodus_values_expires ON nodus_values(expires_at) WHERE expires_at > 0;"
    /* Owner quota queries (OWNER_USAGE_SQL, QUOTA_OWNER_COUNT_SQL) search by
     * owner_fp; without it each write cap check scanned the whole table.
     * Built once on the first open of an existing DB. */
    "CREATE INDEX IF NOT EXISTS idx_nodus_values_owner ON nodus_values(owner_fp);";

static const char *PUT_SQL =
    "INSERT OR REPLACE INTO nodus_values "
    "(key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature, data_hash) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";

static const char *GET_SQL =
    "SELECT key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature "
    "FROM nodus_values WHERE key_hash = ? "
    "ORDER BY (CASE WHEN type = 3 THEN 1 ELSE 0 END) DESC, seq DESC LIMIT 1";

static const char *GET_ALL_SQL =
    "SELECT key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature "
    "FROM nodus_values WHERE key_hash = ? "
    "ORDER BY seq DESC, owner_fp ASC "
    "LIMIT 10000";  /* == NODUS_GET_ALL_MAX_ROWS — DoS cap, deterministic order */

static const char *DELETE_SQL =
    "DELETE FROM nodus_values WHERE key_hash = ? AND owner_fp = ? AND value_id = ?";

static const char *CLEANUP_SQL =
    "DELETE FROM nodus_values WHERE expires_at > 0 AND expires_at <= ?";

static const char *COUNT_SQL =
    "SELECT COUNT(*) FROM nodus_values";

/* Ownership lock is scoped to key_hash ALONE (NOT value_id): the first identity
 * to store a type=3 value at a key_hash owns the whole namespace entry. Keying on
 * value_id was a hijack vector — value_id is per-writer (SHA3-512(pk)[0:8]), so a
 * different owner never collided and the cross-owner reject was dead code
 * (docs/plans/2026-07-17-dht-name-ownership-fix-design.md, F1). */
static const char *EXCLUSIVE_OWNER_SQL =
    "SELECT owner_fp FROM nodus_values "
    "WHERE key_hash = ? AND type = 3 LIMIT 1";

static const char *PUT_IF_NEWER_SQL =
    "INSERT OR REPLACE INTO nodus_values "
    "(key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature, data_hash) "
    "SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12 "
    "WHERE NOT EXISTS ("
    "  SELECT 1 FROM nodus_values "
    "  WHERE key_hash = ?1 AND owner_fp = ?2 AND value_id = ?3 "
    "  AND (seq > ?9 OR (seq = ?9 AND data_hash >= ?12))"
    ")";

/* "Would PUT_IF_NEWER_SQL skip this value?" — the NOT EXISTS predicate above,
 * verbatim, so the quota pre-check never disagrees with the atomic put. */
static const char *NEWER_EXISTS_SQL =
    "SELECT 1 FROM nodus_values "
    "WHERE key_hash = ?1 AND owner_fp = ?2 AND value_id = ?3 "
    "AND (seq > ?9 OR (seq = ?9 AND data_hash >= ?12))";

/* The stored row of one (key, owner, value_id): seq (SQLite INTEGER, compared
 * as signed int64 like PUT_IF_NEWER_SQL), data length (quota growth) and
 * expires_at (an expired row is not counted by the caps — replacing it is a
 * new row for them). */
static const char *EXISTING_ROW_SQL =
    "SELECT seq, LENGTH(data), expires_at FROM nodus_values "
    "WHERE key_hash = ? AND owner_fp = ? AND value_id = ?";

/* One owner's newest row at a key — total order: seq, data_hash (NULL legacy
 * hashes sort last under DESC), value_id. */
static const char *GET_OWNER_SQL =
    "SELECT key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature "
    "FROM nodus_values WHERE key_hash = ?1 AND owner_fp = ?2 "
    "ORDER BY seq DESC, data_hash DESC, value_id ASC LIMIT 1";

/* Paged get_all in PRIMARY KEY order (owner_fp, value_id — value_id as signed
 * int64, SQLite INTEGER). ?2 = owner filter or NULL; ?3/?4 = cursor or NULL.
 * The cursor is bound as NULL when absent — an all-zero sentinel would skip
 * a zero owner_fp with value_id <= 0. */
static const char *GET_ALL_PAGE_SQL =
    "SELECT key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature "
    "FROM nodus_values WHERE key_hash = ?1 "
    "AND (?2 IS NULL OR owner_fp = ?2) "
    "AND (?3 IS NULL OR owner_fp > ?3 OR (owner_fp = ?3 AND value_id > ?4)) "
    "ORDER BY owner_fp ASC, value_id ASC";

/* Composite bookmark on (key_hash, owner_fp, value_id) — PRIMARY KEY tuple.
 * Bookmarking on key_hash alone skipped tied rows at batch boundaries
 * (republication bug: ~15% of multi-row keys lost per cycle). */
static const char *FETCH_BATCH_SQL =
    "SELECT key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature "
    "FROM nodus_values "
    "WHERE (key_hash > ?1) "
    "   OR (key_hash = ?1 AND owner_fp > ?2) "
    "   OR (key_hash = ?1 AND owner_fp = ?2 AND value_id > ?3) "
    "ORDER BY key_hash, owner_fp, value_id LIMIT ?4";

/* ── DHT Hinted Handoff SQL ──────────────────────────────────────── */

static const char *QUOTA_TOTAL_BYTES_SQL =
    "SELECT COALESCE(SUM(LENGTH(data)), 0) FROM nodus_values";

static const char *QUOTA_OWNER_COUNT_SQL =
    "SELECT COUNT(*) FROM nodus_values WHERE owner_fp = ?";

/* Write caps (nodus_storage_put / put_if_newer) count LIVE rows only. A row
 * is expired exactly when CLEANUP_SQL would delete it (expires_at > 0 AND
 * expires_at <= now), so a row cleanup never removes — expires_at 0, or a
 * negative stored INTEGER — always counts. existing_row() applies the same
 * predicate in C.
 * Query plan (EXPLAIN QUERY PLAN, sqlite3 3.44 CLI; asserted at run time
 * against the linked library by test_storage_owner_quota): SEARCH
 * nodus_values USING INDEX idx_nodus_values_owner (owner_fp=?). Reading
 * expires_at (stored after data) walks a large row's overflow pages; bounded
 * by the owner's rows (row cap + expired rows awaiting cleanup). */
static const char *OWNER_USAGE_SQL =
    "SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0) FROM nodus_values "
    "WHERE owner_fp = ?1 AND NOT (expires_at > 0 AND expires_at <= ?2)";

/* Whole-table live usage = everything minus the expired rows. The two
 * whole-table terms read no column stored after data (COUNT(*) scans the
 * smallest index; LENGTH(data) comes from the record header, no overflow
 * page), the cost of the QUOTA_TOTAL_BYTES_SQL pre-check; the expired terms
 * SEARCH idx_nodus_values_expires (the literal expires_at > 0 matches its
 * partial-index WHERE). Filtering expires_at row by row instead would walk
 * every large row's overflow chain on each check. Only run for a new row or
 * a growing replace that passed the owner caps. */
static const char *GLOBAL_USAGE_SQL =
    "SELECT (SELECT COUNT(*) FROM nodus_values) - "
    "       (SELECT COUNT(*) FROM nodus_values WHERE expires_at > 0 AND expires_at <= ?1), "
    "       (SELECT COALESCE(SUM(LENGTH(data)), 0) FROM nodus_values) - "
    "       (SELECT COALESCE(SUM(LENGTH(data)), 0) FROM nodus_values "
    "        WHERE expires_at > 0 AND expires_at <= ?1)";

static const char *HINT_SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS dht_hinted_handoff ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  node_id     BLOB NOT NULL,"
    "  peer_ip     TEXT NOT NULL,"
    "  peer_port   INTEGER NOT NULL,"
    "  frame_data  BLOB NOT NULL,"
    "  frame_hash  BLOB NOT NULL,"
    "  created_at  INTEGER NOT NULL,"
    "  expires_at  INTEGER NOT NULL,"
    "  retry_count INTEGER DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_dht_hint_node ON dht_hinted_handoff(node_id);"
    "CREATE INDEX IF NOT EXISTS idx_dht_hint_expires ON dht_hinted_handoff(expires_at);"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_dht_hint_dedup ON dht_hinted_handoff(node_id, frame_hash);"
    /* Whole-table frame byte total for the global hint cap, kept by SQLite
     * itself: every path that inserts or deletes a hint row (insert,
     * delete, cleanup, any future one) moves it, so it cannot drift from
     * SUM(LENGTH(frame_data)). An ignored duplicate inserts nothing and
     * fires nothing. Re-seeded from the table on every open. */
    "CREATE TABLE IF NOT EXISTS dht_hint_totals ("
    "  id          INTEGER PRIMARY KEY CHECK (id = 1),"
    "  total_bytes INTEGER NOT NULL"
    ");"
    "INSERT OR REPLACE INTO dht_hint_totals (id, total_bytes) "
    "  SELECT 1, COALESCE(SUM(LENGTH(frame_data)), 0) FROM dht_hinted_handoff;"
    "CREATE TRIGGER IF NOT EXISTS trg_dht_hint_ins AFTER INSERT ON dht_hinted_handoff BEGIN "
    "  UPDATE dht_hint_totals SET total_bytes = total_bytes + LENGTH(NEW.frame_data) WHERE id = 1; "
    "END;"
    "CREATE TRIGGER IF NOT EXISTS trg_dht_hint_del AFTER DELETE ON dht_hinted_handoff BEGIN "
    "  UPDATE dht_hint_totals SET total_bytes = total_bytes - LENGTH(OLD.frame_data) WHERE id = 1; "
    "END;"
    "CREATE TRIGGER IF NOT EXISTS trg_dht_hint_upd AFTER UPDATE OF frame_data ON dht_hinted_handoff BEGIN "
    "  UPDATE dht_hint_totals SET total_bytes = total_bytes - LENGTH(OLD.frame_data) + LENGTH(NEW.frame_data) WHERE id = 1; "
    "END;";

static const char *HINT_INSERT_SQL =
    "INSERT OR IGNORE INTO dht_hinted_handoff (node_id, peer_ip, peer_port, frame_data, frame_hash, created_at, expires_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)";

static const char *HINT_GET_SQL =
    "SELECT id, peer_ip, peer_port, frame_data, created_at, expires_at, retry_count "
    "FROM dht_hinted_handoff WHERE node_id = ? "
    "ORDER BY created_at ASC LIMIT ?";

static const char *HINT_DELETE_SQL =
    "DELETE FROM dht_hinted_handoff WHERE id = ?";

static const char *HINT_CLEANUP_SQL =
    "DELETE FROM dht_hinted_handoff WHERE expires_at <= ?";

static const char *HINT_COUNT_SQL =
    "SELECT COUNT(*) FROM dht_hinted_handoff";

/* Hint caps: every row counts until hinted_cleanup removes it, the same rows
 * HINT_GET_SQL returns. Per-peer usage is a SEARCH on node_id (the sqlite3
 * 3.44 CLI picks idx_dht_hint_dedup; test_hinted_caps asserts a SEARCH on
 * node_id against the linked library) over at most
 * NODUS_DHT_HINT_PEER_MAX_ROWS rows. */
static const char *HINT_PEER_USAGE_SQL =
    "SELECT COUNT(*), COALESCE(SUM(LENGTH(frame_data)), 0) "
    "FROM dht_hinted_handoff WHERE node_id = ?";

/* O(1): the trigger-maintained total (HINT_SCHEMA_SQL), no table scan. */
static const char *HINT_TOTAL_BYTES_SQL =
    "SELECT total_bytes FROM dht_hint_totals WHERE id = 1";

static const char *HINT_EXISTS_SQL =
    "SELECT 1 FROM dht_hinted_handoff WHERE node_id = ? AND frame_hash = ?";

#define DHT_HINT_TTL_SEC    NODUS_DHT_HINT_TTL_SEC   /* 24 h (was 7 days) */

/* ── Helpers ─────────────────────────────────────────────────────── */

static nodus_value_t *row_to_value(sqlite3_stmt *stmt) {
    nodus_value_t *val = calloc(1, sizeof(nodus_value_t));
    if (!val) return NULL;

    /* key_hash */
    const void *blob = sqlite3_column_blob(stmt, 0);
    int blob_len = sqlite3_column_bytes(stmt, 0);
    if (blob && blob_len == NODUS_KEY_BYTES)
        memcpy(val->key_hash.bytes, blob, NODUS_KEY_BYTES);

    /* owner_fp */
    blob = sqlite3_column_blob(stmt, 1);
    blob_len = sqlite3_column_bytes(stmt, 1);
    if (blob && blob_len == NODUS_KEY_BYTES)
        memcpy(val->owner_fp.bytes, blob, NODUS_KEY_BYTES);

    /* value_id */
    val->value_id = (uint64_t)sqlite3_column_int64(stmt, 2);

    /* data */
    blob = sqlite3_column_blob(stmt, 3);
    blob_len = sqlite3_column_bytes(stmt, 3);
    if (blob && blob_len > 0) {
        val->data = malloc((size_t)blob_len);
        if (val->data) {
            memcpy(val->data, blob, (size_t)blob_len);
            val->data_len = (size_t)blob_len;
        }
    }

    /* type */
    val->type = (nodus_value_type_t)sqlite3_column_int(stmt, 4);

    /* ttl */
    val->ttl = (uint32_t)sqlite3_column_int(stmt, 5);

    /* created_at */
    val->created_at = (uint64_t)sqlite3_column_int64(stmt, 6);

    /* expires_at */
    val->expires_at = (uint64_t)sqlite3_column_int64(stmt, 7);

    /* seq */
    val->seq = (uint64_t)sqlite3_column_int64(stmt, 8);

    /* owner_pk */
    blob = sqlite3_column_blob(stmt, 9);
    blob_len = sqlite3_column_bytes(stmt, 9);
    if (blob && blob_len == NODUS_PK_BYTES)
        memcpy(val->owner_pk.bytes, blob, NODUS_PK_BYTES);

    /* signature */
    blob = sqlite3_column_blob(stmt, 10);
    blob_len = sqlite3_column_bytes(stmt, 10);
    if (blob && blob_len == NODUS_SIG_BYTES)
        memcpy(val->signature.bytes, blob, NODUS_SIG_BYTES);

    return val;
}

/* ── API ─────────────────────────────────────────────────────────── */

int nodus_storage_open(const char *path, nodus_storage_t *store) {
    if (!path || !store) return -1;

    memset(store, 0, sizeof(*store));

    int rc = sqlite3_open(path, &store->db);
    if (rc != SQLITE_OK) return -1;

    /* Create schema */
    char *err = NULL;
    rc = sqlite3_exec(store->db, SCHEMA_SQL, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        sqlite3_free(err);
        sqlite3_close(store->db);
        store->db = NULL;
        return -1;
    }

    /* Hinted handoff schema — drop and recreate (data is transient). The
     * triggers go with their table; the totals row is re-seeded from the
     * table by HINT_SCHEMA_SQL either way. */
    sqlite3_exec(store->db, "DROP TABLE IF EXISTS dht_hinted_handoff", NULL, NULL, NULL);
    sqlite3_exec(store->db, "DROP TABLE IF EXISTS dht_hint_totals", NULL, NULL, NULL);
    rc = sqlite3_exec(store->db, HINT_SCHEMA_SQL, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "nodus_storage: hint schema failed: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(store->db);
        store->db = NULL;
        return -1;
    }

    /* WAL mode for better concurrency */
    sqlite3_exec(store->db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(store->db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);

    /* Enable incremental auto_vacuum. On existing DBs this requires VACUUM
     * to take effect (one-time migration, skipped on subsequent starts). */
    {
        sqlite3_stmt *av = NULL;
        int cur_av = 0;
        if (sqlite3_prepare_v2(store->db, "PRAGMA auto_vacuum", -1, &av, NULL) == SQLITE_OK) {
            if (sqlite3_step(av) == SQLITE_ROW)
                cur_av = sqlite3_column_int(av, 0);
            sqlite3_finalize(av);
        }
        if (cur_av != 2) {  /* 2 = INCREMENTAL */
            fprintf(stderr, "STORAGE: migrating auto_vacuum to INCREMENTAL (one-time VACUUM)...\n");
            sqlite3_exec(store->db, "PRAGMA auto_vacuum=INCREMENTAL", NULL, NULL, NULL);
            sqlite3_exec(store->db, "VACUUM", NULL, NULL, NULL);
            fprintf(stderr, "STORAGE: auto_vacuum migration complete\n");
        }
    }

    /* Schema migration: add data_hash column if missing.
     * Existing rows get NULL — NULL >= X evaluates to NULL (not TRUE),
     * so existing NULL-hash values always lose tiebreaks until re-PUT. */
    sqlite3_exec(store->db,
        "ALTER TABLE nodus_values ADD COLUMN data_hash BLOB",
        NULL, NULL, NULL);  /* Silently fails if column exists */

    /* Prepare statements */
    if (sqlite3_prepare_v2(store->db, PUT_SQL, -1, &store->stmt_put, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, GET_SQL, -1, &store->stmt_get, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, GET_ALL_SQL, -1, &store->stmt_get_all, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, DELETE_SQL, -1, &store->stmt_delete, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, CLEANUP_SQL, -1, &store->stmt_cleanup, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, COUNT_SQL, -1, &store->stmt_count, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, PUT_IF_NEWER_SQL, -1, &store->stmt_put_if_newer, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, FETCH_BATCH_SQL, -1, &store->stmt_fetch_batch, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, QUOTA_TOTAL_BYTES_SQL, -1, &store->stmt_quota_total_bytes, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, QUOTA_OWNER_COUNT_SQL, -1, &store->stmt_quota_owner_count, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, OWNER_USAGE_SQL, -1, &store->stmt_quota_owner_usage, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, GLOBAL_USAGE_SQL, -1, &store->stmt_quota_global_usage, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, EXISTING_ROW_SQL, -1, &store->stmt_existing_row, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, NEWER_EXISTS_SQL, -1, &store->stmt_newer_exists, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, GET_OWNER_SQL, -1, &store->stmt_get_owner, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, GET_ALL_PAGE_SQL, -1, &store->stmt_get_all_page, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, HINT_PEER_USAGE_SQL, -1, &store->stmt_hint_peer_usage, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, HINT_TOTAL_BYTES_SQL, -1, &store->stmt_hint_total_bytes, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, HINT_EXISTS_SQL, -1, &store->stmt_hint_exists, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, HINT_INSERT_SQL, -1, &store->stmt_hint_insert, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, HINT_GET_SQL, -1, &store->stmt_hint_get, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, HINT_DELETE_SQL, -1, &store->stmt_hint_delete, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, HINT_CLEANUP_SQL, -1, &store->stmt_hint_cleanup, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, HINT_COUNT_SQL, -1, &store->stmt_hint_count, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, EXCLUSIVE_OWNER_SQL, -1, &store->stmt_exclusive_owner, NULL) != SQLITE_OK) {
        nodus_storage_close(store);
        return -1;
    }

    return 0;
}

void nodus_storage_close(nodus_storage_t *store) {
    if (!store) return;
    if (store->stmt_put) sqlite3_finalize(store->stmt_put);
    if (store->stmt_get) sqlite3_finalize(store->stmt_get);
    if (store->stmt_get_all) sqlite3_finalize(store->stmt_get_all);
    if (store->stmt_delete) sqlite3_finalize(store->stmt_delete);
    if (store->stmt_cleanup) sqlite3_finalize(store->stmt_cleanup);
    if (store->stmt_count) sqlite3_finalize(store->stmt_count);
    if (store->stmt_put_if_newer) sqlite3_finalize(store->stmt_put_if_newer);
    if (store->stmt_fetch_batch) sqlite3_finalize(store->stmt_fetch_batch);
    if (store->stmt_quota_total_bytes) sqlite3_finalize(store->stmt_quota_total_bytes);
    if (store->stmt_quota_owner_count) sqlite3_finalize(store->stmt_quota_owner_count);
    if (store->stmt_quota_owner_usage) sqlite3_finalize(store->stmt_quota_owner_usage);
    if (store->stmt_quota_global_usage) sqlite3_finalize(store->stmt_quota_global_usage);
    if (store->stmt_existing_row) sqlite3_finalize(store->stmt_existing_row);
    if (store->stmt_newer_exists) sqlite3_finalize(store->stmt_newer_exists);
    if (store->stmt_get_owner) sqlite3_finalize(store->stmt_get_owner);
    if (store->stmt_get_all_page) sqlite3_finalize(store->stmt_get_all_page);
    if (store->stmt_hint_peer_usage) sqlite3_finalize(store->stmt_hint_peer_usage);
    if (store->stmt_hint_total_bytes) sqlite3_finalize(store->stmt_hint_total_bytes);
    if (store->stmt_hint_exists) sqlite3_finalize(store->stmt_hint_exists);
    if (store->stmt_exclusive_owner) sqlite3_finalize(store->stmt_exclusive_owner);
    if (store->stmt_hint_insert) sqlite3_finalize(store->stmt_hint_insert);
    if (store->stmt_hint_get) sqlite3_finalize(store->stmt_hint_get);
    if (store->stmt_hint_delete) sqlite3_finalize(store->stmt_hint_delete);
    if (store->stmt_hint_cleanup) sqlite3_finalize(store->stmt_hint_cleanup);
    if (store->stmt_hint_count) sqlite3_finalize(store->stmt_hint_count);
    if (store->db) sqlite3_close(store->db);
    memset(store, 0, sizeof(*store));
}

/* First 8 bytes of a key as 16 hex chars (log lines only). */
static void key_prefix_hex(const uint8_t *bytes, char out[17]) {
    for (int i = 0; i < 8; i++)
        snprintf(out + i * 2, 17 - (size_t)i * 2, "%02x", bytes[i]);
    out[16] = '\0';
}

/* The stored row of one (key, owner, value_id), as the write paths see it. */
typedef struct {
    int           exists;     /* a row is stored (live or expired) */
    int           live;       /* ... and the caps count it (not expired) */
    sqlite3_int64 seq;
    size_t        data_len;
} stored_row_t;

/* Look up the stored row of (key, owner, value_id). `now` decides liveness
 * with CLEANUP_SQL's predicate: expired = expires_at > 0 AND
 * expires_at <= now (signed int64, as SQLite compares it).
 * Returns 0 and fills *row, -1 on error. */
static int existing_row(nodus_storage_t *store, const nodus_value_t *val,
                        sqlite3_int64 now, stored_row_t *row) {
    memset(row, 0, sizeof(*row));
    sqlite3_stmt *s = store->stmt_existing_row;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, val->key_hash.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, val->owner_fp.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)val->value_id);
    int rc = sqlite3_step(s);
    if (rc == SQLITE_ROW) {
        sqlite3_int64 exp = sqlite3_column_int64(s, 2);
        row->exists = 1;
        row->live = !(exp > 0 && exp <= now);
        row->seq = sqlite3_column_int64(s, 0);
        row->data_len = (size_t)sqlite3_column_int64(s, 1);
    } else if (rc != SQLITE_DONE) {
        sqlite3_reset(s);
        return -1;
    }
    sqlite3_reset(s);
    return 0;
}

/* Live-row usage of one owner (owner_fp != NULL) or of the whole table:
 * row count and data bytes. Returns 0, or -1 on error. */
static int live_usage(nodus_storage_t *store, const nodus_key_t *owner_fp,
                      sqlite3_int64 now, uint64_t *rows, uint64_t *data_bytes) {
    sqlite3_stmt *s = owner_fp ? store->stmt_quota_owner_usage
                               : store->stmt_quota_global_usage;
    sqlite3_reset(s);
    if (owner_fp) {
        sqlite3_bind_blob(s, 1, owner_fp->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
        sqlite3_bind_int64(s, 2, now);
    } else {
        sqlite3_bind_int64(s, 1, now);
    }
    if (sqlite3_step(s) != SQLITE_ROW) {
        sqlite3_reset(s);
        return -1;
    }
    *rows = (uint64_t)sqlite3_column_int64(s, 0);
    *data_bytes = (uint64_t)sqlite3_column_int64(s, 1);
    sqlite3_reset(s);
    return 0;
}

/* "Would `add` more on top of `used` pass `cap`?" — overflow-safe. */
static int over_cap(uint64_t used, uint64_t add, uint64_t cap) {
    return add > cap || used > cap - add;
}

/* Write caps (F5 + rev 2 items 1-3), growth-only:
 *   - a replace of a LIVE stored row that does not grow -> 0, no query;
 *   - a new row (none stored, or the stored one expired) -> owner row cap,
 *     and (with_global) the global row cap;
 *   - new row or growing replace -> owner byte quota over
 *     NODUS_STORAGE_ROW_CHARGE, and (with_global) the global byte cap over
 *     data bytes (the unit nodus_storage_check_quota uses).
 * Owner caps first (indexed); the global SCAN only when they pass.
 * Returns 0 = within caps, NODUS_STORAGE_RC_QUOTA = refused, -1 = error. */
static int write_caps_check(nodus_storage_t *store, const nodus_value_t *val,
                            const stored_row_t *row, sqlite3_int64 now,
                            int with_global) {
    int new_row = !row->live;
    if (!new_row && val->data_len <= row->data_len) return 0;

    /* Owner charge growth equals data growth on a replace (the fixed part
     * of NODUS_STORAGE_ROW_CHARGE is already paid by the stored row). */
    uint64_t data_growth = new_row ? (uint64_t)val->data_len
                                   : (uint64_t)(val->data_len - row->data_len);
    uint64_t charge_growth = new_row ? NODUS_STORAGE_ROW_CHARGE(val->data_len)
                                     : data_growth;

    uint64_t owner_rows = 0, owner_data = 0;
    if (live_usage(store, &val->owner_fp, now, &owner_rows, &owner_data) != 0)
        return -1;
    uint64_t owner_charge = owner_data + owner_rows * NODUS_STORAGE_ROW_CHARGE(0);

    const char *why = NULL;
    if (new_row && owner_rows >= NODUS_STORAGE_MAX_PER_OWNER)
        why = "owner row cap";
    else if (over_cap(owner_charge, charge_growth, NODUS_STORAGE_OWNER_MAX_BYTES))
        why = "owner byte quota";

    uint64_t total_rows = 0, total_data = 0;
    if (!why && with_global) {
        if (live_usage(store, NULL, now, &total_rows, &total_data) != 0)
            return -1;
        if (new_row && total_rows >= NODUS_STORAGE_MAX_VALUES)
            why = "global row cap";
        else if (data_growth > 0 &&
                 over_cap(total_data, data_growth, NODUS_STORAGE_MAX_BYTES))
            why = "global byte cap";
    }

    if (why) {
        char own_hex[17];
        key_prefix_hex(val->owner_fp.bytes, own_hex);
        QGP_LOG_WARN(LOG_TAG, "PUT refused (%s) — owner %s...: %s, +%llu bytes; "
                     "owner %llu rows / %llu charged bytes, table %llu rows / %llu data bytes",
                     why, own_hex, new_row ? "new row" : "growing replace",
                     (unsigned long long)charge_growth,
                     (unsigned long long)owner_rows, (unsigned long long)owner_charge,
                     (unsigned long long)total_rows, (unsigned long long)total_data);
        return NODUS_STORAGE_RC_QUOTA;
    }
    return 0;
}

int nodus_storage_put(nodus_storage_t *store, const nodus_value_t *val) {
    if (!store || !store->db || !val) return -1;

    /* C-04: Verify Dilithium5 signature before storing */
    if (nodus_value_verify(val) != 0) {
        fprintf(stderr, "NODUS_STORE: PUT rejected — value signature verification failed\n");
        return -1;
    }

    /* EXCLUSIVE ownership enforcement:
     * If any existing value at (key_hash, value_id) has type=EXCLUSIVE
     * from a different owner, reject the PUT (any type). */
    {
        sqlite3_stmt *ex = store->stmt_exclusive_owner;
        sqlite3_reset(ex);
        sqlite3_bind_blob(ex, 1, val->key_hash.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
        int ex_rc = sqlite3_step(ex);
        if (ex_rc == SQLITE_ROW) {
            const void *existing_fp = sqlite3_column_blob(ex, 0);
            int fp_len = sqlite3_column_bytes(ex, 0);
            if (existing_fp && fp_len == NODUS_KEY_BYTES &&
                memcmp(existing_fp, val->owner_fp.bytes, NODUS_KEY_BYTES) != 0) {
                char kh[17], own_hex[17], new_hex[17];
                for (int i = 0; i < 8; i++) {
                    snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", val->key_hash.bytes[i]);
                    snprintf(own_hex + i*2, sizeof(own_hex) - i*2, "%02x", ((const uint8_t*)existing_fp)[i]);
                    snprintf(new_hex + i*2, sizeof(new_hex) - i*2, "%02x", val->owner_fp.bytes[i]);
                }
                kh[16] = own_hex[16] = new_hex[16] = '\0';
                fprintf(stderr, "NODUS_STORE: EXCLUSIVE PUT rejected — key=%s... owned by %s..., attempted by %s...\n",
                        kh, own_hex, new_hex);
                return -2;  /* KEY_OWNED */
            }
        }
    }

    /* F7 stale refusal + write caps — both need the stored row of this
     * (key, owner, value_id). Runs after the EXCLUSIVE check: -2 keeps
     * priority over -4 / -3. */
    sqlite3_int64 now = (sqlite3_int64)time(NULL);
    stored_row_t row;
    if (existing_row(store, val, now, &row) != 0)
        return -1;

    /* F7: only a STRICTLY lower seq is refused; equal or higher seq replaces
     * as before (INSERT OR REPLACE below). Compared as signed int64, the
     * SQLite INTEGER order PUT_IF_NEWER_SQL uses. Any stored row counts,
     * live or expired. */
    if (row.exists && row.seq > (sqlite3_int64)val->seq) {
        char kh[17], own_hex[17];
        key_prefix_hex(val->key_hash.bytes, kh);
        key_prefix_hex(val->owner_fp.bytes, own_hex);
        QGP_LOG_WARN(LOG_TAG, "PUT refused — stale seq: key=%s... owner=%s... vid=%llu seq=%lld < stored %lld",
                     kh, own_hex, (unsigned long long)val->value_id,
                     (long long)(sqlite3_int64)val->seq, (long long)row.seq);
        return NODUS_STORAGE_RC_STALE;
    }

    /* Write caps: owner rows / owner bytes / global rows / global bytes,
     * growth only. */
    {
        int q = write_caps_check(store, val, &row, now, 1);
        if (q != 0) return q;
    }

    /* Compute SHA3-256 hash of value data for put_if_newer tiebreaker */
    uint8_t data_hash[32];
    if (!val->data || val->data_len == 0) {
        memset(data_hash, 0, sizeof(data_hash));
    } else {
        if (qgp_sha3_256(val->data, val->data_len, data_hash) != 0) {
            fprintf(stderr, "NODUS_STORE: data_hash computation failed\n");
            return -1;
        }
    }

    sqlite3_stmt *s = store->stmt_put;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, val->key_hash.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, val->owner_fp.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)val->value_id);
    sqlite3_bind_blob(s, 4, val->data, (int)val->data_len, SQLITE_STATIC);
    sqlite3_bind_int(s, 5, (int)val->type);
    sqlite3_bind_int(s, 6, (int)val->ttl);
    sqlite3_bind_int64(s, 7, (sqlite3_int64)val->created_at);
    sqlite3_bind_int64(s, 8, (sqlite3_int64)val->expires_at);
    sqlite3_bind_int64(s, 9, (sqlite3_int64)val->seq);
    sqlite3_bind_blob(s, 10, val->owner_pk.bytes, NODUS_PK_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 11, val->signature.bytes, NODUS_SIG_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 12, data_hash, 32, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int nodus_storage_get(nodus_storage_t *store,
                      const nodus_key_t *key_hash,
                      nodus_value_t **val_out) {
    if (!store || !store->db || !key_hash || !val_out) return -1;

    sqlite3_stmt *s = store->stmt_get;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, key_hash->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc == SQLITE_DONE)
        return -1;                       /* no row */
    if (rc != SQLITE_ROW)
        return NODUS_STORAGE_RC_FAULT;   /* could not look */

    *val_out = row_to_value(s);
    return (*val_out) ? 0 : NODUS_STORAGE_RC_FAULT;
}

int nodus_storage_get_all(nodus_storage_t *store,
                          const nodus_key_t *key_hash,
                          nodus_value_t ***vals_out,
                          size_t *count_out) {
    if (!store || !store->db || !key_hash || !vals_out || !count_out) return -1;

    sqlite3_stmt *s = store->stmt_get_all;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, key_hash->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);

    /* Collect results */
    size_t cap = 16;
    size_t count = 0;
    size_t total_bytes = 0;  /* cumulative response size — cap at NODUS_GET_ALL_MAX_BYTES */
    nodus_value_t **vals = calloc(cap, sizeof(nodus_value_t *));
    if (!vals) return -1;

    while (sqlite3_step(s) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2;
            nodus_value_t **new_vals = realloc(vals, cap * sizeof(nodus_value_t *));
            if (!new_vals) {
                for (size_t i = 0; i < count; i++)
                    nodus_value_free(vals[i]);
                free(vals);
                return -1;
            }
            vals = new_vals;
        }
        vals[count] = row_to_value(s);
        if (!vals[count]) continue;
        /* Enforce byte budget. SQL LIMIT bounds row count; this bounds memory. */
        if (total_bytes + vals[count]->data_len > NODUS_GET_ALL_MAX_BYTES) {
            nodus_value_free(vals[count]);
            vals[count] = NULL;
            break;
        }
        total_bytes += vals[count]->data_len;
        count++;
    }

    if (count == 0) {
        free(vals);
        *vals_out = NULL;
        *count_out = 0;
        return -1;
    }

    *vals_out = vals;
    *count_out = count;
    return 0;
}

int nodus_storage_get_owner(nodus_storage_t *store,
                            const nodus_key_t *key_hash,
                            const nodus_key_t *owner_fp,
                            nodus_value_t **val_out) {
    if (!val_out) return -1;
    *val_out = NULL;
    if (!store || !store->db || !key_hash || !owner_fp) return -1;

    sqlite3_stmt *s = store->stmt_get_owner;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, key_hash->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, owner_fp->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc == SQLITE_ROW)
        *val_out = row_to_value(s);
    sqlite3_reset(s);
    if (rc == SQLITE_DONE) return -1;                 /* no row */
    if (rc != SQLITE_ROW) return NODUS_STORAGE_RC_FAULT;
    return (*val_out) ? 0 : NODUS_STORAGE_RC_FAULT;   /* row, alloc failed */
}

int nodus_storage_get_all_page(nodus_storage_t *store,
                               const nodus_key_t *key_hash,
                               const nodus_key_t *owner_fp,
                               const nodus_key_t *after_owner,
                               uint64_t after_vid,
                               size_t budget_bytes,
                               nodus_value_t ***vals_out,
                               size_t *count_out,
                               int *more_out) {
    if (!vals_out || !count_out || !more_out) return -1;
    *vals_out = NULL;
    *count_out = 0;
    *more_out = 0;
    if (!store || !store->db || !key_hash) return -1;

    sqlite3_stmt *s = store->stmt_get_all_page;
    sqlite3_reset(s);
    sqlite3_clear_bindings(s);   /* absent filter / cursor = NULL */
    sqlite3_bind_blob(s, 1, key_hash->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    if (owner_fp)
        sqlite3_bind_blob(s, 2, owner_fp->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    if (after_owner) {
        sqlite3_bind_blob(s, 3, after_owner->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
        sqlite3_bind_int64(s, 4, (sqlite3_int64)after_vid);
    }

    size_t cap = 16;
    size_t count = 0;
    size_t used = 0;   /* cumulative NODUS_VALUE_SERIALIZED_EST */
    int more = 0;
    nodus_value_t **vals = calloc(cap, sizeof(nodus_value_t *));
    if (!vals) { sqlite3_reset(s); return NODUS_STORAGE_RC_FAULT; }

    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        /* Budget check on the column length before materialising the row. */
        size_t est = NODUS_VALUE_SERIALIZED_EST((size_t)sqlite3_column_bytes(s, 3));
        if (count > 0 && (est > budget_bytes || used > budget_bytes - est)) {
            more = 1;   /* a row remains that did not fit */
            break;
        }
        if (count >= cap) {
            size_t ncap = cap * 2;
            nodus_value_t **nv = realloc(vals, ncap * sizeof(nodus_value_t *));
            if (!nv) goto fail;
            vals = nv;
            cap = ncap;
        }
        nodus_value_t *v = row_to_value(s);
        if (!v) goto fail;
        vals[count++] = v;
        used += est;
    }
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) goto fail;
    sqlite3_reset(s);   /* release the read snapshot */

    if (count == 0) {
        free(vals);
        return 0;   /* empty page — not an error */
    }
    *vals_out = vals;
    *count_out = count;
    *more_out = more;
    return 0;

fail:   /* SQLite step error or allocation failure: could not look */
    sqlite3_reset(s);
    for (size_t i = 0; i < count; i++)
        nodus_value_free(vals[i]);
    free(vals);
    return NODUS_STORAGE_RC_FAULT;
}

int nodus_storage_delete(nodus_storage_t *store,
                         const nodus_key_t *key_hash,
                         const nodus_key_t *owner_fp,
                         uint64_t value_id) {
    if (!store || !store->db || !key_hash || !owner_fp) return -1;

    sqlite3_stmt *s = store->stmt_delete;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, key_hash->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, owner_fp->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)value_id);

    int rc = sqlite3_step(s);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int nodus_storage_cleanup(nodus_storage_t *store) {
    if (!store || !store->db) return -1;

    sqlite3_stmt *s = store->stmt_cleanup;
    sqlite3_reset(s);

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)now);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE)
        return -1;

    return sqlite3_changes(store->db);
}

int nodus_storage_count(nodus_storage_t *store) {
    if (!store || !store->db) return -1;

    sqlite3_stmt *s = store->stmt_count;
    sqlite3_reset(s);

    if (sqlite3_step(s) == SQLITE_ROW)
        return sqlite3_column_int(s, 0);

    return -1;
}

int nodus_storage_count_key(nodus_storage_t *store,
                             const nodus_key_t *key_hash) {
    if (!store || !store->db || !key_hash) return -1;

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(store->db,
        "SELECT COUNT(*) FROM nodus_values WHERE key_hash = ?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(s, 1, key_hash->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    int count = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        count = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return count;
}

int nodus_storage_has_owner(nodus_storage_t *store,
                             const nodus_key_t *key_hash,
                             const nodus_key_t *owner_fp) {
    if (!store || !store->db || !key_hash || !owner_fp) return -1;

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(store->db,
        "SELECT 1 FROM nodus_values WHERE key_hash = ? AND owner_fp = ? LIMIT 1",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(s, 1, key_hash->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, owner_fp->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    int result = (sqlite3_step(s) == SQLITE_ROW) ? 1 : 0;
    sqlite3_finalize(s);
    return result;
}

int nodus_storage_put_if_newer(nodus_storage_t *store, const nodus_value_t *val) {
    if (!store || !store->db || !val) return -1;

    /* EXCLUSIVE ownership enforcement (same check as nodus_storage_put) */
    {
        sqlite3_stmt *ex = store->stmt_exclusive_owner;
        sqlite3_reset(ex);
        sqlite3_bind_blob(ex, 1, val->key_hash.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
        int ex_rc = sqlite3_step(ex);
        if (ex_rc == SQLITE_ROW) {
            const void *existing_fp = sqlite3_column_blob(ex, 0);
            int fp_len = sqlite3_column_bytes(ex, 0);
            if (existing_fp && fp_len == NODUS_KEY_BYTES &&
                memcmp(existing_fp, val->owner_fp.bytes, NODUS_KEY_BYTES) != 0) {
                return -2;  /* KEY_OWNED — block replication of hijacked keys */
            }
        }
    }

    /* Compute SHA3-256 hash of value data for equal-seq tiebreaker */
    uint8_t data_hash[32];
    if (!val->data || val->data_len == 0) {
        memset(data_hash, 0, sizeof(data_hash));
    } else {
        if (qgp_sha3_256(val->data, val->data_len, data_hash) != 0) {
            fprintf(stderr, "STORAGE: data_hash computation failed, rejecting PUT\n");
            return -1;
        }
    }

    /* F5: a value the atomic put below would skip returns 1 (skipped)
     * without a cap check — same predicate, NEWER_EXISTS_SQL. A value it
     * would store is checked against the per-owner caps (row cap for a new
     * row, byte quota for growth) with nodus_storage_put's accounting; the
     * global caps are not applied on the replica path. */
    {
        sqlite3_stmt *ne = store->stmt_newer_exists;
        sqlite3_reset(ne);
        sqlite3_bind_blob(ne, 1, val->key_hash.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
        sqlite3_bind_blob(ne, 2, val->owner_fp.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
        sqlite3_bind_int64(ne, 3, (sqlite3_int64)val->value_id);
        sqlite3_bind_int64(ne, 9, (sqlite3_int64)val->seq);
        sqlite3_bind_blob(ne, 12, data_hash, 32, SQLITE_STATIC);
        int ne_rc = sqlite3_step(ne);
        sqlite3_reset(ne);
        if (ne_rc == SQLITE_ROW) return 1;  /* skipped — existing is newer/equal */
        if (ne_rc != SQLITE_DONE) return -1;

        sqlite3_int64 now = (sqlite3_int64)time(NULL);
        stored_row_t row;
        if (existing_row(store, val, now, &row) != 0)
            return -1;
        int q = write_caps_check(store, val, &row, now, 0);
        if (q != 0) return q;
    }

    sqlite3_stmt *s = store->stmt_put_if_newer;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, val->key_hash.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, val->owner_fp.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)val->value_id);
    sqlite3_bind_blob(s, 4, val->data, (int)val->data_len, SQLITE_STATIC);
    sqlite3_bind_int(s, 5, (int)val->type);
    sqlite3_bind_int(s, 6, (int)val->ttl);
    sqlite3_bind_int64(s, 7, (sqlite3_int64)val->created_at);
    sqlite3_bind_int64(s, 8, (sqlite3_int64)val->expires_at);
    sqlite3_bind_int64(s, 9, (sqlite3_int64)val->seq);
    sqlite3_bind_blob(s, 10, val->owner_pk.bytes, NODUS_PK_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 11, val->signature.bytes, NODUS_SIG_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(s, 12, data_hash, 32, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) return -1;

    return (sqlite3_changes(store->db) > 0) ? 0 : 1;  /* 0=stored, 1=skipped */
}

int nodus_storage_fetch_batch(nodus_storage_t *store,
                               const nodus_key_t *after_key,
                               const nodus_key_t *after_owner,
                               uint64_t after_vid,
                               nodus_value_t **batch_out,
                               int batch_size) {
    if (!store || !store->db || !batch_out || batch_size <= 0) return 0;

    sqlite3_stmt *s = store->stmt_fetch_batch;
    sqlite3_reset(s);

    /* Function-scope buffers: SQLITE_STATIC requires the blob to remain
     * valid until sqlite3_step completes (and subsequent steps). */
    uint8_t zeros_key[NODUS_KEY_BYTES] = {0};
    uint8_t zeros_owner[NODUS_KEY_BYTES] = {0};
    if (after_key) {
        sqlite3_bind_blob(s, 1, after_key->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    } else {
        sqlite3_bind_blob(s, 1, zeros_key, NODUS_KEY_BYTES, SQLITE_STATIC);
    }
    if (after_owner) {
        sqlite3_bind_blob(s, 2, after_owner->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    } else {
        sqlite3_bind_blob(s, 2, zeros_owner, NODUS_KEY_BYTES, SQLITE_STATIC);
    }
    sqlite3_bind_int64(s, 3, (sqlite3_int64)after_vid);
    sqlite3_bind_int(s, 4, batch_size);

    int fetched = 0;
    while (sqlite3_step(s) == SQLITE_ROW && fetched < batch_size) {
        batch_out[fetched] = row_to_value(s);
        if (batch_out[fetched])
            fetched++;
    }

    sqlite3_reset(s);  /* Release read snapshot — allows WAL checkpoint */
    return fetched;
}

/* ── Storage Quotas ──────────────────────────────────────────────── */

int nodus_storage_check_quota(nodus_storage_t *store,
                               const nodus_key_t *owner_fp) {
    if (!store || !store->db || !owner_fp) return -1;

    /* Check 1: global value count */
    int total_count = nodus_storage_count(store);
    if (total_count >= (int)NODUS_STORAGE_MAX_VALUES)
        return -1;

    /* Check 2: global total bytes */
    sqlite3_stmt *s = store->stmt_quota_total_bytes;
    sqlite3_reset(s);
    if (sqlite3_step(s) == SQLITE_ROW) {
        uint64_t total_bytes = (uint64_t)sqlite3_column_int64(s, 0);
        if (total_bytes >= NODUS_STORAGE_MAX_BYTES)
            return -1;
    }

    /* Check 3: per-owner value count */
    s = store->stmt_quota_owner_count;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, owner_fp->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    if (sqlite3_step(s) == SQLITE_ROW) {
        int owner_count = sqlite3_column_int(s, 0);
        if (owner_count >= (int)NODUS_STORAGE_MAX_PER_OWNER)
            return -1;
    }

    return 0;  /* Within quota */
}

/* ── DHT Hinted Handoff ─────────────────────────────────────────── */

int nodus_storage_hinted_insert(nodus_storage_t *store,
                                 const nodus_key_t *node_id,
                                 const char *peer_ip, uint16_t peer_port,
                                 const uint8_t *frame_data, size_t frame_len) {
    if (!store || !store->db || !node_id || !peer_ip || !frame_data) return -1;

    /* Compute SHA3-512 of frame_data, use first 32 bytes as dedup hash */
    uint8_t hash_full[64];
    qgp_sha3_512(frame_data, frame_len, hash_full);

    /* F4 caps: per node_id rows + bytes first (indexed, <= 64 rows), and
     * only when they pass the whole-table byte total (O(1) trigger-kept
     * row). Checked before the insert; over a cap nothing is stored. */
    {
        int64_t peer_rows = 0, peer_bytes = 0, total_bytes = 0;
        sqlite3_stmt *u = store->stmt_hint_peer_usage;
        sqlite3_reset(u);
        sqlite3_bind_blob(u, 1, node_id->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
        int urc = sqlite3_step(u);
        if (urc == SQLITE_ROW) {
            peer_rows = sqlite3_column_int64(u, 0);
            peer_bytes = sqlite3_column_int64(u, 1);
        }
        sqlite3_reset(u);
        if (urc != SQLITE_ROW) return -1;

        uint64_t flen = (uint64_t)frame_len;
        const char *why = NULL;
        if ((uint64_t)peer_rows >= NODUS_DHT_HINT_PEER_MAX_ROWS)
            why = "peer row cap";
        else if (flen > NODUS_DHT_HINT_PEER_MAX_BYTES ||
                 (uint64_t)peer_bytes > NODUS_DHT_HINT_PEER_MAX_BYTES - flen)
            why = "peer byte cap";

        if (!why) {
            sqlite3_stmt *t = store->stmt_hint_total_bytes;
            sqlite3_reset(t);
            int trc = sqlite3_step(t);
            if (trc == SQLITE_ROW)
                total_bytes = sqlite3_column_int64(t, 0);
            sqlite3_reset(t);
            if (trc != SQLITE_ROW) return -1;
            /* flen <= PEER_MAX_BYTES < TOTAL_MAX_BYTES here: no underflow */
            if (total_bytes < 0 ||
                (uint64_t)total_bytes > NODUS_DHT_HINT_TOTAL_MAX_BYTES - flen)
                why = "total byte cap";
        }

        if (why) {
            /* A duplicate (node_id, frame) adds nothing — keep today's
             * "ignored, 0" answer for it even at the cap. */
            sqlite3_stmt *e = store->stmt_hint_exists;
            sqlite3_reset(e);
            sqlite3_bind_blob(e, 1, node_id->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
            sqlite3_bind_blob(e, 2, hash_full, 32, SQLITE_STATIC);
            int erc = sqlite3_step(e);
            sqlite3_reset(e);
            if (erc == SQLITE_ROW) return 0;
            if (erc != SQLITE_DONE) return -1;

            QGP_LOG_WARN(LOG_TAG, "DHT-HINT refused (%s) for %s:%d: %zu bytes; peer %lld rows / %lld bytes, total %lld bytes",
                         why, peer_ip, peer_port, frame_len,
                         (long long)peer_rows, (long long)peer_bytes,
                         (long long)total_bytes);
            return NODUS_STORAGE_RC_QUOTA;
        }
    }

    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires = now + DHT_HINT_TTL_SEC;

    sqlite3_stmt *s = store->stmt_hint_insert;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, node_id->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, peer_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, peer_port);
    sqlite3_bind_blob(s, 4, frame_data, (int)frame_len, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 5, hash_full, 32, SQLITE_STATIC);
    sqlite3_bind_int64(s, 6, (sqlite3_int64)now);
    sqlite3_bind_int64(s, 7, (sqlite3_int64)expires);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        /* SQLITE_CONSTRAINT = duplicate (node_id, frame_hash) → silently ignore */
        if (sqlite3_errcode(store->db) == SQLITE_CONSTRAINT) {
            return 0;
        }
        fprintf(stderr, "DHT-HINT: insert failed: %s\n", sqlite3_errmsg(store->db));
        return -1;
    }

    if (sqlite3_changes(store->db) > 0) {
        fprintf(stderr, "DHT-HINT: queued for %s:%d (%zu bytes)\n",
                peer_ip, peer_port, frame_len);
    }
    return 0;
}

int nodus_storage_hinted_get(nodus_storage_t *store,
                              const nodus_key_t *node_id,
                              int limit,
                              nodus_dht_hint_t **entries_out,
                              size_t *count_out) {
    if (!store || !store->db || !node_id || !entries_out || !count_out) return -1;

    sqlite3_stmt *s = store->stmt_hint_get;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, node_id->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, limit);

    size_t cap = 16;
    size_t count = 0;
    uint64_t frame_bytes = 0;   /* bounded by NODUS_DHT_HINT_PEER_MAX_BYTES */
    nodus_dht_hint_t *entries = calloc(cap, sizeof(nodus_dht_hint_t));
    if (!entries) return -1;

    while (sqlite3_step(s) == SQLITE_ROW) {
        uint64_t row_len = (uint64_t)sqlite3_column_bytes(s, 3);
        if (count > 0 && frame_bytes + row_len > NODUS_DHT_HINT_PEER_MAX_BYTES)
            break;   /* first entry always returned; the rest wait for the next pass */
        frame_bytes += row_len;
        if (count >= cap) {
            cap *= 2;
            nodus_dht_hint_t *new_e = realloc(entries, cap * sizeof(nodus_dht_hint_t));
            if (!new_e) { nodus_storage_hinted_free(entries, count); return -1; }
            entries = new_e;
        }

        nodus_dht_hint_t *e = &entries[count];
        e->id = sqlite3_column_int64(s, 0);
        const char *ip = (const char *)sqlite3_column_text(s, 1);
        if (ip) strncpy(e->peer_ip, ip, sizeof(e->peer_ip) - 1);
        e->peer_port = (uint16_t)sqlite3_column_int(s, 2);

        const void *blob = sqlite3_column_blob(s, 3);
        int blob_len = sqlite3_column_bytes(s, 3);
        if (blob && blob_len > 0) {
            e->frame_data = malloc((size_t)blob_len);
            if (e->frame_data) {
                memcpy(e->frame_data, blob, (size_t)blob_len);
                e->frame_len = (size_t)blob_len;
            }
        }

        e->created_at = (uint64_t)sqlite3_column_int64(s, 4);
        e->expires_at = (uint64_t)sqlite3_column_int64(s, 5);
        e->retry_count = sqlite3_column_int(s, 6);
        count++;
    }
    sqlite3_reset(s);   /* the byte bound may stop mid-result — release it */

    if (count == 0) {
        free(entries);
        *entries_out = NULL;
        *count_out = 0;
        return -1;
    }

    *entries_out = entries;
    *count_out = count;
    return 0;
}

int nodus_storage_hinted_delete(nodus_storage_t *store, int64_t id) {
    if (!store || !store->db) return -1;

    sqlite3_stmt *s = store->stmt_hint_delete;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)id);

    int rc = sqlite3_step(s);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int nodus_storage_hinted_bump_retry(nodus_storage_t *store, int64_t id) {
    if (!store || !store->db) return -1;

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(store->db,
            "UPDATE dht_hinted_handoff SET retry_count = retry_count + 1 WHERE id = ? RETURNING retry_count",
            -1, &s, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_int64(s, 1, (sqlite3_int64)id);
    int result = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        result = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return result;
}

int nodus_storage_hinted_cleanup(nodus_storage_t *store) {
    if (!store || !store->db) return -1;

    sqlite3_stmt *s = store->stmt_hint_cleanup;
    sqlite3_reset(s);

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)now);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) return -1;

    int cleaned = sqlite3_changes(store->db);
    if (cleaned > 0)
        fprintf(stderr, "DHT-HINT: cleaned %d expired entries\n", cleaned);
    return cleaned;
}

int nodus_storage_hinted_count(nodus_storage_t *store) {
    if (!store || !store->db) return -1;

    sqlite3_stmt *s = store->stmt_hint_count;
    sqlite3_reset(s);

    if (sqlite3_step(s) == SQLITE_ROW)
        return sqlite3_column_int(s, 0);

    return -1;
}

void nodus_storage_hinted_free(nodus_dht_hint_t *entries, size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) {
        free(entries[i].frame_data);
    }
    free(entries);
}
