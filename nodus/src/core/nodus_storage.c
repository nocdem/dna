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
    "CREATE INDEX IF NOT EXISTS idx_nodus_values_expires ON nodus_values(expires_at) WHERE expires_at > 0;";

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
    "FROM nodus_values WHERE key_hash = ?";

static const char *DELETE_SQL =
    "DELETE FROM nodus_values WHERE key_hash = ? AND owner_fp = ? AND value_id = ?";

static const char *CLEANUP_SQL =
    "DELETE FROM nodus_values WHERE expires_at > 0 AND expires_at <= ?";

static const char *COUNT_SQL =
    "SELECT COUNT(*) FROM nodus_values";

static const char *EXCLUSIVE_OWNER_SQL =
    "SELECT owner_fp FROM nodus_values "
    "WHERE key_hash = ? AND value_id = ? AND type = 3 LIMIT 1";

static const char *PUT_IF_NEWER_SQL =
    "INSERT OR REPLACE INTO nodus_values "
    "(key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature, data_hash) "
    "SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12 "
    "WHERE NOT EXISTS ("
    "  SELECT 1 FROM nodus_values "
    "  WHERE key_hash = ?1 AND owner_fp = ?2 AND value_id = ?3 "
    "  AND (seq > ?9 OR (seq = ?9 AND data_hash >= ?12))"
    ")";

static const char *FETCH_BATCH_SQL =
    "SELECT key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature "
    "FROM nodus_values WHERE key_hash > ? ORDER BY key_hash LIMIT ?";

/* ── DHT Hinted Handoff SQL ──────────────────────────────────────── */

static const char *QUOTA_TOTAL_BYTES_SQL =
    "SELECT COALESCE(SUM(LENGTH(data)), 0) FROM nodus_values";

static const char *QUOTA_OWNER_COUNT_SQL =
    "SELECT COUNT(*) FROM nodus_values WHERE owner_fp = ?";

static const char *HINT_SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS dht_hinted_handoff ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  node_id     BLOB NOT NULL,"
    "  peer_ip     TEXT NOT NULL,"
    "  peer_port   INTEGER NOT NULL,"
    "  frame_data  BLOB NOT NULL,"
    "  created_at  INTEGER NOT NULL,"
    "  expires_at  INTEGER NOT NULL,"
    "  retry_count INTEGER DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_dht_hint_node ON dht_hinted_handoff(node_id);"
    "CREATE INDEX IF NOT EXISTS idx_dht_hint_expires ON dht_hinted_handoff(expires_at);";

static const char *HINT_INSERT_SQL =
    "INSERT INTO dht_hinted_handoff (node_id, peer_ip, peer_port, frame_data, created_at, expires_at) "
    "VALUES (?, ?, ?, ?, ?, ?)";

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

#define DHT_HINT_TTL_SEC    (7 * 24 * 3600)   /* 7 days */

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

    /* Hinted handoff schema — drop and recreate (data is transient) */
    sqlite3_exec(store->db, "DROP TABLE IF EXISTS dht_hinted_handoff", NULL, NULL, NULL);
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
    sqlite3_exec(store->db, "PRAGMA auto_vacuum=INCREMENTAL", NULL, NULL, NULL);

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
    if (store->stmt_exclusive_owner) sqlite3_finalize(store->stmt_exclusive_owner);
    if (store->stmt_hint_insert) sqlite3_finalize(store->stmt_hint_insert);
    if (store->stmt_hint_get) sqlite3_finalize(store->stmt_hint_get);
    if (store->stmt_hint_delete) sqlite3_finalize(store->stmt_hint_delete);
    if (store->stmt_hint_cleanup) sqlite3_finalize(store->stmt_hint_cleanup);
    if (store->stmt_hint_count) sqlite3_finalize(store->stmt_hint_count);
    if (store->db) sqlite3_close(store->db);
    memset(store, 0, sizeof(*store));
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
        sqlite3_bind_int64(ex, 2, (sqlite3_int64)val->value_id);
        int ex_rc = sqlite3_step(ex);
        if (ex_rc == SQLITE_ROW) {
            const void *existing_fp = sqlite3_column_blob(ex, 0);
            int fp_len = sqlite3_column_bytes(ex, 0);
            if (existing_fp && fp_len == NODUS_KEY_BYTES &&
                memcmp(existing_fp, val->owner_fp.bytes, NODUS_KEY_BYTES) != 0) {
                char kh[17], own_hex[17], new_hex[17];
                for (int i = 0; i < 8; i++) {
                    sprintf(kh + i*2, "%02x", val->key_hash.bytes[i]);
                    sprintf(own_hex + i*2, "%02x", ((const uint8_t*)existing_fp)[i]);
                    sprintf(new_hex + i*2, "%02x", val->owner_fp.bytes[i]);
                }
                kh[16] = own_hex[16] = new_hex[16] = '\0';
                fprintf(stderr, "NODUS_STORE: EXCLUSIVE PUT rejected — key=%s... owned by %s..., attempted by %s...\n",
                        kh, own_hex, new_hex);
                return -2;  /* KEY_OWNED */
            }
        }
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
    if (rc != SQLITE_ROW)
        return -1;

    *val_out = row_to_value(s);
    return (*val_out) ? 0 : -1;
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
        if (vals[count])
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
        sqlite3_bind_int64(ex, 2, (sqlite3_int64)val->value_id);
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
                               nodus_value_t **batch_out,
                               int batch_size) {
    if (!store || !store->db || !batch_out || batch_size <= 0) return 0;

    sqlite3_stmt *s = store->stmt_fetch_batch;
    sqlite3_reset(s);

    /* Function-scope buffer: SQLITE_STATIC requires the blob to remain
     * valid until sqlite3_step completes (and subsequent steps). If we
     * declared `zeros` inside the else block it would go out of scope
     * before sqlite3_step ran — a real stack-use-after-scope bug caught
     * by AddressSanitizer. */
    uint8_t zeros[NODUS_KEY_BYTES] = {0};
    if (after_key) {
        sqlite3_bind_blob(s, 1, after_key->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    } else {
        /* First batch: start from beginning (all zeros) */
        sqlite3_bind_blob(s, 1, zeros, NODUS_KEY_BYTES, SQLITE_STATIC);
    }
    sqlite3_bind_int(s, 2, batch_size);

    int fetched = 0;
    while (sqlite3_step(s) == SQLITE_ROW && fetched < batch_size) {
        batch_out[fetched] = row_to_value(s);
        if (batch_out[fetched])
            fetched++;
    }

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

    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires = now + DHT_HINT_TTL_SEC;

    sqlite3_stmt *s = store->stmt_hint_insert;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, node_id->bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, peer_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, peer_port);
    sqlite3_bind_blob(s, 4, frame_data, (int)frame_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 5, (sqlite3_int64)now);
    sqlite3_bind_int64(s, 6, (sqlite3_int64)expires);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "DHT-HINT: insert failed: %s\n", sqlite3_errmsg(store->db));
        return -1;
    }

    fprintf(stderr, "DHT-HINT: queued for %s:%d (%zu bytes)\n",
            peer_ip, peer_port, frame_len);
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
    nodus_dht_hint_t *entries = calloc(cap, sizeof(nodus_dht_hint_t));
    if (!entries) return -1;

    while (sqlite3_step(s) == SQLITE_ROW) {
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
