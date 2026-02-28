/**
 * Nodus v5 — SQLite DHT Storage
 *
 * Persistent storage for DHT values with TTL cleanup.
 * PRIMARY KEY: (key_hash, owner_fp, value_id)
 * Conflict resolution: INSERT OR REPLACE (seq comparison in application layer)
 */

#include "core/nodus_storage.h"
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
    "(key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?)";

static const char *GET_SQL =
    "SELECT key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature "
    "FROM nodus_values WHERE key_hash = ? ORDER BY seq DESC LIMIT 1";

static const char *GET_ALL_SQL =
    "SELECT key_hash, owner_fp, value_id, data, type, ttl, created_at, expires_at, seq, owner_pk, signature "
    "FROM nodus_values WHERE key_hash = ?";

static const char *DELETE_SQL =
    "DELETE FROM nodus_values WHERE key_hash = ? AND owner_fp = ? AND value_id = ?";

static const char *CLEANUP_SQL =
    "DELETE FROM nodus_values WHERE expires_at > 0 AND expires_at <= ?";

static const char *COUNT_SQL =
    "SELECT COUNT(*) FROM nodus_values";

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

    /* WAL mode for better concurrency */
    sqlite3_exec(store->db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(store->db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);

    /* Prepare statements */
    if (sqlite3_prepare_v2(store->db, PUT_SQL, -1, &store->stmt_put, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, GET_SQL, -1, &store->stmt_get, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, GET_ALL_SQL, -1, &store->stmt_get_all, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, DELETE_SQL, -1, &store->stmt_delete, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, CLEANUP_SQL, -1, &store->stmt_cleanup, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, COUNT_SQL, -1, &store->stmt_count, NULL) != SQLITE_OK) {
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
    if (store->db) sqlite3_close(store->db);
    memset(store, 0, sizeof(*store));
}

int nodus_storage_put(nodus_storage_t *store, const nodus_value_t *val) {
    if (!store || !store->db || !val) return -1;

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
