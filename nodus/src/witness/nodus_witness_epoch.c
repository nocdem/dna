/**
 * Nodus — v0.16 push-settlement epoch-state CRUD.
 *
 * Implements the primitives declared in nodus_witness_epoch.h. The
 * `epoch_state` schema is created inside WITNESS_DB_SCHEMA so fresh
 * DBs pick it up automatically; migrations are handled by Stage B.2's
 * supply_tracking migration (no-op here since the table is new).
 */

#include "witness/nodus_witness_epoch.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS_EPOCH"

/* ── Helpers ─────────────────────────────────────────────────────── */

static void blob_free(nodus_epoch_state_t *e) {
    if (!e) return;
    free(e->snapshot_blob);
    e->snapshot_blob = NULL;
    e->snapshot_blob_len = 0;
}

void nodus_witness_epoch_free(nodus_epoch_state_t *e) {
    blob_free(e);
}

/* ── Insert ──────────────────────────────────────────────────────── */

int nodus_witness_epoch_insert(nodus_witness_t *w,
                                const nodus_epoch_state_t *e) {
    if (!w || !w->db || !e) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO epoch_state "
        "(epoch_start_height, epoch_pool_accum, snapshot_hash, snapshot_blob) "
        "VALUES (?, ?, ?, ?)";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: insert prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)e->epoch_start_height);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)e->epoch_pool_accum);
    sqlite3_bind_blob(stmt, 3, e->snapshot_hash,
                      NODUS_EPOCH_SNAPSHOT_HASH_LEN, SQLITE_STATIC);
    if (e->snapshot_blob && e->snapshot_blob_len > 0) {
        sqlite3_bind_blob(stmt, 4, e->snapshot_blob,
                          (int)e->snapshot_blob_len, SQLITE_STATIC);
    } else {
        sqlite3_bind_zeroblob(stmt, 4, 0);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) return 0;
    if (rc == SQLITE_CONSTRAINT) return -2;

    fprintf(stderr, "%s: insert step failed rc=%d: %s\n",
            LOG_TAG, rc, sqlite3_errmsg(w->db));
    return -1;
}

/* ── Read helper ─────────────────────────────────────────────────── */

static int epoch_row_read(sqlite3_stmt *stmt, nodus_epoch_state_t *out) {
    memset(out, 0, sizeof(*out));
    out->epoch_start_height = (uint64_t)sqlite3_column_int64(stmt, 0);
    out->epoch_pool_accum   = (uint64_t)sqlite3_column_int64(stmt, 1);

    const void *hash = sqlite3_column_blob(stmt, 2);
    int hash_len = sqlite3_column_bytes(stmt, 2);
    if (hash && hash_len == NODUS_EPOCH_SNAPSHOT_HASH_LEN) {
        memcpy(out->snapshot_hash, hash, NODUS_EPOCH_SNAPSHOT_HASH_LEN);
    }

    const void *blob = sqlite3_column_blob(stmt, 3);
    int blob_len = sqlite3_column_bytes(stmt, 3);
    if (blob && blob_len > 0) {
        out->snapshot_blob = malloc((size_t)blob_len);
        if (!out->snapshot_blob) return -1;
        memcpy(out->snapshot_blob, blob, (size_t)blob_len);
        out->snapshot_blob_len = (size_t)blob_len;
    }
    return 0;
}

/* ── Get by epoch_start_height ───────────────────────────────────── */

int nodus_witness_epoch_get(nodus_witness_t *w,
                             uint64_t epoch_start_height,
                             nodus_epoch_state_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT epoch_start_height, epoch_pool_accum, snapshot_hash, "
        "       snapshot_blob "
        "FROM epoch_state WHERE epoch_start_height = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)epoch_start_height);

    rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        ret = (epoch_row_read(stmt, out) == 0) ? 0 : -1;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        fprintf(stderr, "%s: get step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        ret = -1;
    }
    sqlite3_finalize(stmt);
    return ret;
}

/* ── Get current (highest epoch_start_height) ────────────────────── */

int nodus_witness_epoch_get_current(nodus_witness_t *w,
                                     nodus_epoch_state_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT epoch_start_height, epoch_pool_accum, snapshot_hash, "
        "       snapshot_blob "
        "FROM epoch_state ORDER BY epoch_start_height DESC LIMIT 1";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        ret = (epoch_row_read(stmt, out) == 0) ? 0 : -1;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        fprintf(stderr, "%s: get_current step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        ret = -1;
    }
    sqlite3_finalize(stmt);
    return ret;
}

/* ── Set pool_accum ──────────────────────────────────────────────── */

int nodus_witness_epoch_set_pool_accum(nodus_witness_t *w,
                                        uint64_t epoch_start_height,
                                        uint64_t new_pool_accum) {
    if (!w || !w->db) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "UPDATE epoch_state SET epoch_pool_accum = ? "
        "WHERE epoch_start_height = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)new_pool_accum);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)epoch_start_height);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
}

int nodus_witness_epoch_add_pool(nodus_witness_t *w,
                                  uint64_t epoch_start_height,
                                  uint64_t delta) {
    if (!w || !w->db) return -1;
    if (delta == 0) return 0;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "UPDATE epoch_state SET epoch_pool_accum = epoch_pool_accum + ? "
        "WHERE epoch_start_height = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)delta);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)epoch_start_height);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
}

/* ── Delete ──────────────────────────────────────────────────────── */

int nodus_witness_epoch_delete(nodus_witness_t *w,
                                uint64_t epoch_start_height) {
    if (!w || !w->db) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM epoch_state WHERE epoch_start_height = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)epoch_start_height);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
}
