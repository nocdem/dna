/**
 * @file nodus_witness_tm_wal.c
 * @brief Tendermint consensus WAL + validator state row — implementation.
 *        Contract, layouts and the durability argument: the header.
 *        (T2 wire design §4.6/§4.10; Atlas D-13, D-15 rev 4, INACTIVE.)
 *
 * @file nodus_witness_tm_wal.c
 */

#include "witness/nodus_witness_tm_wal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "nodus/nodus_types.h"        /* NODUS_W_DB_BUSY_TIMEOUT_MS       */
#include "crypto/hash/qgp_sha3.h"     /* qgp_sha3_512                     */
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_TMWAL"

/* ── The busy timeout the two connections must SHARE ──────────────────
 *
 * The main connection's live busy timeout is the PER-ATTEMPT share of
 * the tree's one answer to "how long is a lock transient":
 * `NODUS_W_DB_OPEN_ATTEMPT_BUSY_MS = NODUS_W_DB_BUSY_TIMEOUT_MS /
 * NODUS_W_DB_OPEN_ATTEMPTS`, set at `nodus_witness.c:484` and kept for
 * the connection's whole life.
 *
 * BOTH of those macros are file-local to `nodus_witness.c:404-406`, so
 * they cannot be included here. The share is re-derived from the SAME
 * published root constant (`nodus_types.h:269`) and the SAME divisor.
 * That duplicates the divisor, which is why it is written down: the two
 * connections write to ONE file and contend with EACH OTHER, so they
 * must wait the same amount or the pair has two different ideas of when
 * a lock has stopped being transient. Exporting the witness macro is a
 * `nodus_witness.c` edit, outside this wave's whitelist. */
#define NODUS_TM_WAL_DB_OPEN_ATTEMPTS 3
#define NODUS_TM_WAL_BUSY_MS \
    (NODUS_W_DB_BUSY_TIMEOUT_MS / NODUS_TM_WAL_DB_OPEN_ATTEMPTS)

struct nodus_tm_wal {
    sqlite3 *full;        /* OWNED — the second, synchronous=FULL handle  */
    sqlite3 *normal;      /* BORROWED — the caller's main handle          */
    uint32_t protocol_id;
    uint64_t next_seq;
};

/* ── Big-endian scalars (idiom: nodus_witness_chain_config.c:118) ────── */

static void be64_into(uint64_t v, uint8_t out[8]) {
    out[0] = (uint8_t)(v >> 56); out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40); out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24); out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);  out[7] = (uint8_t)v;
}

static void be32_into(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}

static uint64_t be64_from(const uint8_t in[8]) {
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48) |
           ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32) |
           ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16) |
           ((uint64_t)in[6] << 8)  |  (uint64_t)in[7];
}

static uint32_t be32_from(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  |  (uint32_t)in[3];
}

/* Two's-complement round trip for the signed priority. Casting a u64
 * above INT64_MAX straight to int64_t is implementation-defined, so the
 * high half is folded explicitly — the encoding is the same bytes on
 * every platform, which is the point (DG-13). */
static int64_t i64_from_u64(uint64_t u) {
    if (u <= (uint64_t)INT64_MAX) return (int64_t)u;
    return (int64_t)(u - (uint64_t)INT64_MAX - 1u) - INT64_MAX - 1;
}

/* ── SQLite helpers ──────────────────────────────────────────────────── */

/* 0 on success, -2 on any SQLite fault (this process could not decide). */
static int tmw_exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "SQL failed (%s): %s", sql,
                      err ? err : "?");
        sqlite3_free(err);
        return -2;
    }
    return 0;
}

/* `PRAGMA journal_mode` ANSWERS with the resulting mode, and a database
 * that refuses WAL answers "delete" without failing. The answer is read,
 * not discarded: a second connection in rollback-journal mode would lock
 * the writer out for the duration of every read. 0 = wal, -2 = anything
 * else. */
static int tmw_set_wal_mode(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL", -1, &st, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "journal_mode pragma failed: %s",
                      sqlite3_errmsg(db));
        return -2;
    }
    int mode_ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *mode = sqlite3_column_text(st, 0);
        mode_ok = (mode && strcmp((const char *)mode, "wal") == 0);
    }
    sqlite3_finalize(st);
    if (!mode_ok) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "second connection did not enter WAL mode");
        return -2;
    }
    return 0;
}

/* Restore the per-protocol sequence counter: max(seq) + 1, 0 when the
 * log holds no row. Read through the FULL handle like every other read.
 * 0 / -2. */
static int tmw_restore_next_seq(nodus_tm_wal_t *w) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->full,
            "SELECT MAX(seq) FROM tm_wal WHERE protocol_id = ?1",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "seq restore prepare failed: %s",
                      sqlite3_errmsg(w->full));
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w->protocol_id);

    int rc = sqlite3_step(st);
    int ret = -2;
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) == SQLITE_NULL) {
            w->next_seq = 0;                       /* empty log */
        } else {
            uint64_t max_seq = (uint64_t)sqlite3_column_int64(st, 0);
            if (max_seq == UINT64_MAX) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "seq space exhausted");
                sqlite3_finalize(st);
                return -2;
            }
            w->next_seq = max_seq + 1u;
        }
        ret = 0;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "seq restore step failed: %s",
                      sqlite3_errmsg(w->full));
    }
    sqlite3_finalize(st);
    return ret;
}

/* Verify a stored row: `bytes` is SHA3-512(payload) ‖ payload. On
 * success `*payload` / `*plen` point into the caller's buffer.
 * 0 verified; -2 short row, hash fault, or DIGEST MISMATCH — which is a
 * halt, never a skip (D-15 rev 4 (1), DG-15). */
static int tmw_verify_row(const uint8_t *bytes, size_t len,
                          const uint8_t **payload, size_t *plen) {
    if (!bytes || len <= NODUS_TM_WAL_DIGEST_LEN) {
        QGP_LOG_ERROR(LOG_TAG,
                      "row shorter than its digest (%zu bytes)", len);
        return -2;
    }
    const uint8_t *body = bytes + NODUS_TM_WAL_DIGEST_LEN;
    size_t body_len = len - NODUS_TM_WAL_DIGEST_LEN;

    uint8_t want[NODUS_TM_WAL_DIGEST_LEN];
    if (qgp_sha3_512(body, body_len, want) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "SHA3-512 backend failed");
        return -2;
    }
    if (memcmp(want, bytes, NODUS_TM_WAL_DIGEST_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "row digest mismatch — stopping (no skip path)");
        return -2;
    }
    *payload = body;
    *plen = body_len;
    return 0;
}

/* Build `SHA3-512(payload) ‖ payload` into a fresh heap buffer.
 * 0 / -2 (allocation or hash backend). */
static int tmw_frame_row(const uint8_t *payload, size_t len,
                         uint8_t **out, size_t *out_len) {
    size_t total = NODUS_TM_WAL_DIGEST_LEN + len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        QGP_LOG_ERROR(LOG_TAG, "row buffer allocation failed (%zu)", total);
        return -2;
    }
    if (qgp_sha3_512(payload, len, buf) != 0) {
        free(buf);
        QGP_LOG_ERROR(LOG_TAG, "%s", "SHA3-512 backend failed");
        return -2;
    }
    memcpy(buf + NODUS_TM_WAL_DIGEST_LEN, payload, len);
    *out = buf;
    *out_len = total;
    return 0;
}

/* INSERT one framed row on `conn`. The seq is consumed by the caller. */
static int tmw_insert_row(nodus_tm_wal_t *w, sqlite3 *conn, uint64_t height,
                          uint64_t seq, uint8_t kind,
                          const uint8_t *payload, size_t len) {
    /* sqlite3_bind_blob takes an int length; a payload that cannot be
     * bound WITHOUT truncation is refused rather than silently shortened
     * into a row whose digest would then never verify. The message class
     * ceilings are far below this (T2 §4.8), so this is a floor under the
     * type system, not a policy bound. */
    if (len > (size_t)INT_MAX - NODUS_TM_WAL_DIGEST_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "payload too large to store (%zu bytes)", len);
        return -1;
    }

    uint8_t *row = NULL;
    size_t row_len = 0;
    int rc = tmw_frame_row(payload, len, &row, &row_len);
    if (rc != 0) return rc;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(conn,
            "INSERT INTO tm_wal(protocol_id, height, seq, kind, bytes) "
            "VALUES(?1, ?2, ?3, ?4, ?5)", -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "append prepare failed: %s",
                      sqlite3_errmsg(conn));
        free(row);
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)height);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)seq);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)kind);
    /* SQLITE_STATIC: `row` outlives the step below and is freed here. */
    sqlite3_bind_blob(st, 5, row, (int)row_len, SQLITE_STATIC);

    int step = sqlite3_step(st);
    sqlite3_finalize(st);
    free(row);

    if (step != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "append step failed (kind %u, h %llu): %s",
                      (unsigned)kind, (unsigned long long)height,
                      sqlite3_errmsg(conn));
        return -2;
    }
    return 0;
}

/* Append a framed row, allocating the next sequence number.
 *
 * The seq is consumed whether or not the INSERT lands: a failed append
 * must never hand the same number to a later row, because the row it
 * failed on may yet be present (a commit that reported a fault). A gap
 * costs nothing — replay orders by (height, seq) and never counts. */
static int tmw_append(nodus_tm_wal_t *w, sqlite3 *conn, uint64_t height,
                      uint8_t kind, const uint8_t *payload, size_t len,
                      uint64_t *seq_out) {
    if (w->next_seq == UINT64_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "seq space exhausted");
        return -2;
    }
    uint64_t seq = w->next_seq++;
    int rc = tmw_insert_row(w, conn, height, seq, kind, payload, len);
    if (rc != 0) return rc;
    if (seq_out) *seq_out = seq;
    return 0;
}

/* ── Open / close ────────────────────────────────────────────────────── */

int nodus_tm_wal_open(nodus_tm_wal_t **out, sqlite3 *main_db,
                      uint32_t protocol_id) {
    if (!out || !main_db) return -1;
    *out = NULL;

    /* The second connection needs a FILE to attach to. An in-memory or
     * temporary database reports an empty filename and cannot be shared
     * between two connections — refuse BEFORE opening anything, so the
     * caller gets the deterministic -1 and not a fault from a later
     * statement. */
    const char *path = sqlite3_db_filename(main_db, "main");
    if (!path || path[0] == '\0' || strcmp(path, ":memory:") == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "main database is not file-backed — refusing the "
                      "second (synchronous=FULL) connection");
        return -1;
    }

    nodus_tm_wal_t *w = (nodus_tm_wal_t *)calloc(1, sizeof(*w));
    if (!w) return -2;
    w->normal = main_db;
    w->protocol_id = protocol_id;

    /* READWRITE without CREATE: the file is already open on `main_db`,
     * so a missing file here means the path is wrong — creating a second
     * empty database next to the real one would hide that. */
    if (sqlite3_open_v2(path, &w->full, SQLITE_OPEN_READWRITE, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "second connection open failed: %s",
                      w->full ? sqlite3_errmsg(w->full) : "?");
        sqlite3_close(w->full);
        free(w);
        return -2;
    }

    sqlite3_busy_timeout(w->full, NODUS_TM_WAL_BUSY_MS);

    if (tmw_set_wal_mode(w->full) != 0 ||
        /* D-13: this is the whole reason the second connection exists —
         * an fsync of the WAL after every commit, so an own vote that has
         * been broadcast cannot be missing after a power loss. */
        tmw_exec(w->full, "PRAGMA synchronous=FULL") != 0 ||
        tmw_restore_next_seq(w) != 0) {
        sqlite3_close(w->full);
        free(w);
        return -2;
    }

    QGP_LOG_INFO(LOG_TAG,
                 "tm_wal open (protocol %u, next_seq %llu, FULL conn)",
                 protocol_id, (unsigned long long)w->next_seq);
    *out = w;
    return 0;
}

/* Test-visible internal; declared in the header behind
 * NODUS_WITNESS_INTERNAL_API (idiom: nodus_witness_sync_find_peer). */
sqlite3 *nodus_tm_wal_full_conn(const nodus_tm_wal_t *w) {
    return w ? w->full : NULL;
}

void nodus_tm_wal_close(nodus_tm_wal_t **w) {
    if (!w || !*w) return;
    /* Only the handle this module opened. `normal` is the caller's. */
    sqlite3_close((*w)->full);
    (*w)->full = NULL;
    (*w)->normal = NULL;
    free(*w);
    *w = NULL;
}

/* ── Appends ─────────────────────────────────────────────────────────── */

int nodus_tm_wal_append_msg(nodus_tm_wal_t *w, uint64_t height,
                            const uint8_t *body, size_t len, int own,
                            uint64_t *seq_out) {
    if (!w || !body || len == 0) return -1;
    /* own = 1 → FULL: the INSERT has been fsynced when this returns, and
     * only then may the message go on the wire (D-13, G20). */
    sqlite3 *conn = own ? w->full : w->normal;
    return tmw_append(w, conn, height, (uint8_t)NODUS_TM_WAL_KIND_MSG,
                      body, len, seq_out);
}

int nodus_tm_wal_append_timeout(nodus_tm_wal_t *w, uint64_t height,
                                uint32_t round, uint8_t step) {
    if (!w) return -1;
    uint8_t payload[NODUS_TM_WAL_TIMEOUT_PAYLOAD_LEN];
    be64_into(height, payload);
    be32_into(round, payload + 8);
    payload[12] = step;
    return tmw_append(w, w->normal, height,
                      (uint8_t)NODUS_TM_WAL_KIND_TIMEOUT,
                      payload, sizeof(payload), NULL);
}

int nodus_tm_wal_append_end_height(nodus_tm_wal_t *w, uint64_t height) {
    if (!w) return -1;
    uint8_t payload[NODUS_TM_WAL_END_PAYLOAD_LEN];
    be64_into(height, payload);
    return tmw_append(w, w->full, height,
                      (uint8_t)NODUS_TM_WAL_KIND_END_HEIGHT,
                      payload, sizeof(payload), NULL);
}

/* ── Reads (all on the FULL handle: one reader, one answer) ──────────── */

int nodus_tm_wal_last_end_height(nodus_tm_wal_t *w, int *have,
                                 uint64_t *height) {
    if (!w || !have || !height) return -1;
    *have = 0;
    *height = 0;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->full,
            "SELECT MAX(height) FROM tm_wal "
            " WHERE protocol_id = ?1 AND kind = ?2",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "end_height prepare failed: %s",
                      sqlite3_errmsg(w->full));
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)NODUS_TM_WAL_KIND_END_HEIGHT);

    int rc = sqlite3_step(st);
    int ret = -2;
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_NULL) {
            *height = (uint64_t)sqlite3_column_int64(st, 0);
            *have = 1;
        }
        ret = 0;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "end_height step failed: %s",
                      sqlite3_errmsg(w->full));
    }
    sqlite3_finalize(st);
    return ret;
}

int nodus_tm_wal_replay(nodus_tm_wal_t *w, uint64_t from_height_exclusive,
                        nodus_tm_wal_replay_cb cb, void *ctx) {
    if (!w || !cb) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->full,
            "SELECT height, seq, kind, bytes FROM tm_wal "
            " WHERE protocol_id = ?1 AND height > ?2 "
            " ORDER BY height ASC, seq ASC", -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "replay prepare failed: %s",
                      sqlite3_errmsg(w->full));
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)from_height_exclusive);

    int ret = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint64_t height = (uint64_t)sqlite3_column_int64(st, 0);
        uint64_t seq    = (uint64_t)sqlite3_column_int64(st, 1);
        sqlite3_int64 kind_raw = sqlite3_column_int64(st, 2);

        /* The digest covers `bytes` only, so `kind` is checked rather
         * than trusted: an out-of-range integer must not be truncated
         * into a valid kind by the cast to uint8_t. The set is closed
         * (D-15 rev 4) — anything else is a corrupt row, and a corrupt
         * row stops the replay like a bad digest does. */
        if (kind_raw < NODUS_TM_WAL_KIND_MSG ||
            kind_raw > NODUS_TM_WAL_KIND_END_HEIGHT) {
            QGP_LOG_ERROR(LOG_TAG,
                          "unknown WAL kind %lld at height %llu seq %llu "
                          "— stopping", (long long)kind_raw,
                          (unsigned long long)height,
                          (unsigned long long)seq);
            ret = -2;
            break;
        }

        const uint8_t *stored = (const uint8_t *)sqlite3_column_blob(st, 3);
        size_t stored_len = (size_t)sqlite3_column_bytes(st, 3);
        const uint8_t *payload = NULL;
        size_t plen = 0;
        if (tmw_verify_row(stored, stored_len, &payload, &plen) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "integrity fault at height %llu seq %llu — "
                          "replay stopped, later rows NOT delivered",
                          (unsigned long long)height,
                          (unsigned long long)seq);
            ret = -2;
            break;
        }

        if (cb(ctx, (uint8_t)kind_raw, height, seq, payload, plen) != 0) {
            ret = -1;                       /* the caller asked to stop */
            break;
        }
    }
    if (ret == 0 && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "replay step failed: %s",
                      sqlite3_errmsg(w->full));
        ret = -2;
    }
    sqlite3_finalize(st);
    return ret;
}

int nodus_tm_wal_prune_below(nodus_tm_wal_t *w, uint64_t height) {
    if (!w) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->full,
            "DELETE FROM tm_wal WHERE protocol_id = ?1 AND height < ?2",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prune prepare failed: %s",
                      sqlite3_errmsg(w->full));
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)height);

    int step = sqlite3_step(st);
    sqlite3_finalize(st);
    if (step != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "prune step failed: %s",
                      sqlite3_errmsg(w->full));
        return -2;
    }
    return 0;
}

/* ── tm_state codec ──────────────────────────────────────────────────── */

int nodus_tm_state_encode(const nodus_tm_state_row_t *row, uint8_t *dst,
                          size_t cap, size_t *written) {
    if (!row || !dst) return -1;
    if (row->n > DNA_MAX_ACTIVE_VALIDATORS) return -1;

    size_t need = NODUS_TM_STATE_PAYLOAD_LEN(row->n);
    if (cap < need) return -1;

    uint8_t *p = dst;
    be64_into(row->height, p);                       p += 8;
    memcpy(p, row->vset_hash, sizeof(row->vset_hash)); p += sizeof(row->vset_hash);
    be32_into(row->n, p);                            p += 4;
    for (uint32_t i = 0; i < row->n; i++) {
        memcpy(p, row->voter_id[i], 32);             p += 32;
    }
    for (uint32_t i = 0; i < row->n; i++) {
        be64_into((uint64_t)row->priority[i], p);    p += 8;
    }
    be32_into(row->proposer_idx, p);                 p += 4;

    if (written) *written = need;
    return 0;
}

int nodus_tm_state_decode(const uint8_t *src, size_t len,
                          nodus_tm_state_row_t *row) {
    if (!src || !row) return -1;
    /* Everything before the two variable arrays must be present before
     * `n` can even be read. */
    if (len < NODUS_TM_STATE_PAYLOAD_LEN(0)) return -1;

    uint32_t n = be32_from(src + 72);
    if (n > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    /* Exact length: a trailing byte is a REJECT, never ignored (DG-13). */
    if (len != NODUS_TM_STATE_PAYLOAD_LEN(n)) return -1;

    memset(row, 0, sizeof(*row));
    const uint8_t *p = src;
    row->height = be64_from(p);                      p += 8;
    memcpy(row->vset_hash, p, sizeof(row->vset_hash)); p += sizeof(row->vset_hash);
    row->n = n;                                      p += 4;
    for (uint32_t i = 0; i < n; i++) {
        memcpy(row->voter_id[i], p, 32);             p += 32;
    }
    for (uint32_t i = 0; i < n; i++) {
        row->priority[i] = i64_from_u64(be64_from(p)); p += 8;
    }
    row->proposer_idx = be32_from(p);
    return 0;
}

int nodus_tm_state_write(nodus_tm_wal_t *w, const nodus_tm_state_row_t *row) {
    if (!w || !row) return -1;

    uint8_t payload[NODUS_TM_STATE_MAX_PAYLOAD];
    size_t plen = 0;
    if (nodus_tm_state_encode(row, payload, sizeof(payload), &plen) != 0)
        return -1;

    uint8_t *framed = NULL;
    size_t framed_len = 0;
    int rc = tmw_frame_row(payload, plen, &framed, &framed_len);
    if (rc != 0) return rc;

    sqlite3_stmt *st = NULL;
    /* FULL connection: the set a height is being run with must survive
     * the same crash the height's own END_HEIGHT survives (D-15 rev 4,
     * close order step 3). */
    if (sqlite3_prepare_v2(w->full,
            "INSERT OR REPLACE INTO tm_state(protocol_id, bytes) "
            "VALUES(?1, ?2)", -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "state write prepare failed: %s",
                      sqlite3_errmsg(w->full));
        free(framed);
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_blob(st, 2, framed, (int)framed_len, SQLITE_STATIC);

    int step = sqlite3_step(st);
    sqlite3_finalize(st);
    free(framed);

    if (step != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "state write step failed: %s",
                      sqlite3_errmsg(w->full));
        return -2;
    }
    return 0;
}

int nodus_tm_state_read(nodus_tm_wal_t *w, int *have,
                        nodus_tm_state_row_t *row) {
    if (!w || !have || !row) return -1;
    *have = 0;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->full,
            "SELECT bytes FROM tm_state WHERE protocol_id = ?1",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "state read prepare failed: %s",
                      sqlite3_errmsg(w->full));
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w->protocol_id);

    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_DONE) {
        ret = 0;                                   /* no row — have = 0 */
    } else if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "state read step failed: %s",
                      sqlite3_errmsg(w->full));
        ret = -2;
    } else {
        const uint8_t *stored = (const uint8_t *)sqlite3_column_blob(st, 0);
        size_t stored_len = (size_t)sqlite3_column_bytes(st, 0);
        const uint8_t *payload = NULL;
        size_t plen = 0;
        ret = tmw_verify_row(stored, stored_len, &payload, &plen);
        if (ret == 0) {
            /* A payload that carries an intact digest and still does not
             * decode is the SAME bytes on every node — a deterministic
             * reject, not this process's fault. */
            if (nodus_tm_state_decode(payload, plen, row) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "tm_state payload failed to decode");
                ret = -1;
            } else {
                *have = 1;
            }
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* ── Startup classification (PURE — DG-16) ───────────────────────────── */

nodus_tm_startup_t nodus_tm_wal_startup_classify(uint64_t tip_T,
                                                 uint64_t last_end_E,
                                                 uint64_t state_S) {
    /* E + 1 is compared three times below. At UINT64_MAX it would wrap to
     * 0 and make an impossible state look like a defined row, so that
     * input is refused outright — no height reaches it, and a FAULT is
     * the fail-closed answer either way. */
    if (last_end_E == UINT64_MAX) return NODUS_TM_STARTUP_FAULT;
    uint64_t e1 = last_end_E + 1u;

    /* Clean restart: the height named by tm_state has not been closed. */
    if (state_S == e1 && tip_T == last_end_E)
        return NODUS_TM_STARTUP_NORMAL;
    /* Crash between END_HEIGHT(E) and the tm_state(E+1) write. */
    if (state_S == last_end_E && tip_T == last_end_E)
        return NODUS_TM_STARTUP_FAST_FORWARD;
    /* Crash between the block INSERT and END_HEIGHT: the block is on
     * disk, the log does not know the height closed. */
    if (state_S == e1 && tip_T == e1)
        return NODUS_TM_STARTUP_WRITE_END_THEN_FF;

    return NODUS_TM_STARTUP_FAULT;
}
