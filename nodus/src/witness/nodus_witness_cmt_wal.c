/**
 * @file nodus_witness_cmt_wal.c
 * @brief cometbft @709fd12b consensus/wal.go's STORAGE side over the
 *        `cmt_wal` SQLite table. Contract: nodus_witness_cmt_wal.h.
 */

#include "witness/nodus_witness_cmt_wal.h"

#include <stdlib.h>
#include <string.h>

#include "nodus/nodus_types.h"          /* NODUS_W_DB_BUSY_TIMEOUT_MS */
#include "crypto/hash/qgp_sha3.h"       /* qgp_sha3_512               */
#include "crypto/utils/qgp_log.h"
#include "dnac/cmt_msgs.h"

#define LOG_TAG "W_CMTWAL"

/* nodus_witness.c:404-406 re-derived (see the header): the same root
 * constant, the same divisor, so both connections wait the same. */
#define NODUS_CMT_WAL_DB_OPEN_ATTEMPTS 3
#define NODUS_CMT_WAL_BUSY_MS \
    (NODUS_W_DB_BUSY_TIMEOUT_MS / NODUS_CMT_WAL_DB_OPEN_ATTEMPTS)

/* ── SQL ─────────────────────────────────────────────────────────────── */

static const char SQL_INSERT[] =
    "INSERT INTO cmt_wal (protocol_id, height, seq, kind, bytes) "
    "VALUES (?1, ?2, ?3, ?4, ?5)";
static const char SQL_MAX_SEQ[] =
    "SELECT MAX(seq) FROM cmt_wal WHERE protocol_id = ?1";
/* wal.go:231-292 — the LAST EndHeight(h) (header: why that is the
 * reference's first-in-newest-file). */
static const char SQL_SEARCH[] =
    "SELECT height, seq, bytes FROM cmt_wal "
    "WHERE protocol_id = ?1 AND kind = 4 AND height = ?2 "
    "ORDER BY height DESC, seq DESC LIMIT 1";
/* The first row strictly after the cursor in (height, seq) order; ?4 = 0
 * means "no cursor" — the start of the log. */
static const char SQL_NEXT[] =
    "SELECT height, seq, kind, bytes FROM cmt_wal "
    "WHERE protocol_id = ?1 AND "
    "(?4 = 0 OR height > ?2 OR (height = ?2 AND seq > ?3)) "
    "ORDER BY height, seq LIMIT 1";
static const char SQL_PRUNE[] =
    "DELETE FROM cmt_wal WHERE protocol_id = ?1 AND height < ?2";
/* The FlushAndSync barrier: one real write, so the commit at
 * synchronous=FULL is a real fsync of the shared `-wal` file. An empty
 * transaction syncs nothing (measured), which is why this row exists. */
static const char SQL_SYNC_SEED[] =
    "INSERT OR IGNORE INTO cmt_wal_sync (protocol_id, n) VALUES (?1, 0)";
static const char SQL_SYNC_BUMP[] =
    "UPDATE cmt_wal_sync SET n = n + 1 WHERE protocol_id = ?1";

static int wal_exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "SQL failed (%s): %s", sql, err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* `PRAGMA journal_mode=WAL` ANSWERS with the resulting mode and a
 * database that refuses WAL answers "delete" without failing; the answer
 * is read. A second connection in rollback-journal mode would lock the
 * writer out for every read. */
static int wal_set_wal_mode(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL", -1, &st, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "journal_mode pragma failed: %s",
                      sqlite3_errmsg(db));
        return -1;
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
        return -1;
    }
    return 0;
}

/* ── the row's height (header table) ─────────────────────────────────── */

int nodus_cmt_wal_message_height(const cmt_wal_message_t *msg, int64_t *out) {
    if (!msg || !out) return CMT_FAULT;
    switch (msg->kind) {
    case CMT_PB_WAL_EVENT_DATA_ROUND_STATE:
        *out = msg->u.event_data_round_state.height;       /* events.go:94 */
        return CMT_OK;
    case CMT_PB_WAL_MSG_INFO: {
        const cmt_msg_t *m = &msg->u.msg_info.msg;
        switch (m->kind) {
        case CMT_PB_CONS_MSG_NEW_ROUND_STEP:
            *out = m->u.new_round_step.height; return CMT_OK;
        case CMT_PB_CONS_MSG_NEW_VALID_BLOCK:
            *out = m->u.new_valid_block.height; return CMT_OK;
        case CMT_PB_CONS_MSG_PROPOSAL:
            *out = m->u.proposal.proposal.height; return CMT_OK;
        case CMT_PB_CONS_MSG_PROPOSAL_POL:
            *out = m->u.proposal_pol.height; return CMT_OK;
        case CMT_PB_CONS_MSG_BLOCK_PART:
            *out = m->u.block_part.height; return CMT_OK;
        case CMT_PB_CONS_MSG_VOTE:
            *out = m->u.vote.has_vote ? m->u.vote.vote.height : 0;
            return CMT_OK;
        case CMT_PB_CONS_MSG_HAS_VOTE:
            *out = m->u.has_vote.height; return CMT_OK;
        case CMT_PB_CONS_MSG_VOTE_SET_MAJ23:
            *out = m->u.vote_set_maj23.height; return CMT_OK;
        case CMT_PB_CONS_MSG_VOTE_SET_BITS:
            *out = m->u.vote_set_bits.height; return CMT_OK;
        default:
            return CMT_REJECT;
        }
    }
    case CMT_PB_WAL_TIMEOUT_INFO:
        *out = msg->u.timeout_info.height;                 /* state.go:56 */
        return CMT_OK;
    case CMT_PB_WAL_END_HEIGHT:
        *out = msg->u.end_height.height;                   /* wal.go:43   */
        return CMT_OK;
    default:
        return CMT_REJECT;
    }
}

/* ── open / start / close ────────────────────────────────────────────── */

static int wal_restore_next_seq(nodus_cmt_wal_t *w, bool *out_empty) {
    sqlite3_reset(w->st_max_seq);
    sqlite3_bind_int64(w->st_max_seq, 1, (sqlite3_int64)w->protocol_id);
    int rc = sqlite3_step(w->st_max_seq);
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "max(seq) failed: %s",
                      sqlite3_errmsg(w->main_db));
        sqlite3_reset(w->st_max_seq);
        return CMT_FAULT;
    }
    if (sqlite3_column_type(w->st_max_seq, 0) == SQLITE_NULL) {
        w->next_seq = 0;
        *out_empty = true;
    } else {
        sqlite3_int64 m = sqlite3_column_int64(w->st_max_seq, 0);
        if (m < 0) {
            sqlite3_reset(w->st_max_seq);
            QGP_LOG_ERROR(LOG_TAG, "%s", "negative seq in cmt_wal");
            return CMT_FAULT;
        }
        w->next_seq = (uint64_t)m + 1u;
        *out_empty = false;
    }
    sqlite3_reset(w->st_max_seq);
    return CMT_OK;
}

static void wal_release(nodus_cmt_wal_t *w) {
    sqlite3_finalize(w->st_insert);
    sqlite3_finalize(w->st_insert_main);
    sqlite3_finalize(w->st_sync);
    sqlite3_finalize(w->st_max_seq);
    sqlite3_finalize(w->st_search);
    sqlite3_finalize(w->st_next);
    sqlite3_finalize(w->st_prune);
    w->st_insert = w->st_insert_main = w->st_sync = w->st_max_seq =
        w->st_search = w->st_next = w->st_prune = NULL;
    if (w->full) {
        sqlite3_close(w->full);
        w->full = NULL;
    }
    w->main_db = NULL;                 /* BORROWED — never closed here */
    free(w->read_arena.buf);
    w->read_arena.buf = NULL;
    w->read_arena.cap = w->read_arena.used = 0;
    free(w->enc_buf);
    w->enc_buf = NULL;
    w->enc_cap = 0;
}

int nodus_cmt_wal_open(nodus_cmt_wal_t *w, sqlite3 *main_db,
                       cmt_now_fn now, void *now_ctx) {
    if (!w || !main_db || !now) return CMT_FAULT;
    memset(w, 0, sizeof *w);
    w->protocol_id = NODUS_CMT_WAL_PROTOCOL_ID;
    w->main_db = main_db;              /* BORROWED, synchronous=NORMAL */
    w->now = now;
    w->now_ctx = now_ctx;

    /* The second connection needs a FILE. An in-memory or temporary
     * database reports an empty filename and cannot be shared between
     * two connections — refuse before opening anything. */
    const char *path = sqlite3_db_filename(main_db, "main");
    if (!path || path[0] == '\0' || strcmp(path, ":memory:") == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "main database is not file-backed — refusing the "
                      "second (synchronous=FULL) connection");
        return CMT_FAULT;
    }

    /* READWRITE without CREATE: the file is already open on `main_db`,
     * so a missing file here means the path is wrong. */
    if (sqlite3_open_v2(path, &w->full, SQLITE_OPEN_READWRITE, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "second connection open failed: %s",
                      w->full ? sqlite3_errmsg(w->full) : "?");
        sqlite3_close(w->full);
        w->full = NULL;
        return CMT_FAULT;
    }
    sqlite3_busy_timeout(w->full, NODUS_CMT_WAL_BUSY_MS);

    if (wal_set_wal_mode(w->full) != 0 ||
        /* S24: a COMMIT on this connection is an fsync. */
        wal_exec(w->full, "PRAGMA synchronous=FULL") != 0) {
        wal_release(w);
        return CMT_FAULT;
    }

    w->enc_cap = NODUS_CMT_WAL_DIGEST_LEN + (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES;
    w->enc_buf = (uint8_t *)malloc(w->enc_cap);
    w->read_arena.cap = (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES;
    w->read_arena.buf = (uint8_t *)malloc(w->read_arena.cap);
    w->read_arena.used = 0;
    if (!w->enc_buf || !w->read_arena.buf) {
        wal_release(w);
        return CMT_FAULT;
    }

    /* WriteSync, the barrier and prune run on `full`; the Write class and
     * every read run on the main connection (D-13, D-15 rev 5 (4)). */
    if (sqlite3_prepare_v2(w->full, SQL_INSERT, -1, &w->st_insert, NULL)
            != SQLITE_OK ||
        sqlite3_prepare_v2(w->full, SQL_SYNC_BUMP, -1, &w->st_sync, NULL)
            != SQLITE_OK ||
        sqlite3_prepare_v2(w->full, SQL_PRUNE, -1, &w->st_prune, NULL)
            != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare (FULL) failed: %s",
                      sqlite3_errmsg(w->full));
        wal_release(w);
        return CMT_FAULT;
    }
    if (sqlite3_prepare_v2(w->main_db, SQL_INSERT, -1, &w->st_insert_main,
                           NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(w->main_db, SQL_MAX_SEQ, -1, &w->st_max_seq, NULL)
            != SQLITE_OK ||
        sqlite3_prepare_v2(w->main_db, SQL_SEARCH, -1, &w->st_search, NULL)
            != SQLITE_OK ||
        sqlite3_prepare_v2(w->main_db, SQL_NEXT, -1, &w->st_next, NULL)
            != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare (main) failed: %s",
                      sqlite3_errmsg(w->main_db));
        wal_release(w);
        return CMT_FAULT;
    }

    /* The barrier row must exist before the first FlushAndSync; the
     * UPDATE would otherwise change nothing and commit nothing. */
    {
        sqlite3_stmt *seed = NULL;
        int prc = sqlite3_prepare_v2(w->full, SQL_SYNC_SEED, -1, &seed, NULL);
        if (prc == SQLITE_OK) {
            sqlite3_bind_int64(seed, 1, (sqlite3_int64)w->protocol_id);
            prc = (sqlite3_step(seed) == SQLITE_DONE) ? SQLITE_OK : -1;
        }
        sqlite3_finalize(seed);
        if (prc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "cmt_wal_sync seed failed: %s",
                          sqlite3_errmsg(w->full));
            wal_release(w);
            return CMT_FAULT;
        }
    }

    bool empty = false;
    if (wal_restore_next_seq(w, &empty) != CMT_OK) {
        wal_release(w);
        return CMT_FAULT;
    }
    QGP_LOG_INFO(LOG_TAG, "cmt_wal open (protocol %u, next_seq %llu, FULL)",
                 w->protocol_id, (unsigned long long)w->next_seq);
    return CMT_OK;
}

int nodus_cmt_wal_start(nodus_cmt_wal_t *w) {
    if (!w || !w->full) return CMT_FAULT;
    bool empty = false;
    if (wal_restore_next_seq(w, &empty) != CMT_OK) return CMT_FAULT;
    if (!empty) return CMT_OK;                               /* :127 size != 0 */
    cmt_wal_message_t m;
    memset(&m, 0, sizeof m);
    m.kind = CMT_PB_WAL_END_HEIGHT;
    m.u.end_height.height = 0;                               /* :128 */
    return nodus_cmt_wal_write_sync(w, &m);
}

void nodus_cmt_wal_close(nodus_cmt_wal_t *w) {
    if (!w) return;
    if (w->full && w->unsynced) {
        if (nodus_cmt_wal_flush_and_sync(w) != CMT_OK)       /* :168 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "error on flush data to disk");
    }
    wal_release(w);
}

/* ── the write classes ───────────────────────────────────────────────── */

/* wal.go:189 + :302-320: stamp, encode P, size-check, frame as
 * SHA3-512(P) ‖ P into w->enc_buf. */
static int wal_frame(nodus_cmt_wal_t *w, const cmt_wal_message_t *msg,
                     int64_t *out_height, int64_t *out_stamp_ns,
                     size_t *out_row_len) {
    int64_t height = 0;
    if (nodus_cmt_wal_message_height(msg, &height) != CMT_OK) return CMT_REJECT;

    cmt_timed_wal_message_t *tw =
        (cmt_timed_wal_message_t *)malloc(sizeof *tw);
    if (!tw) return CMT_FAULT;
    if (w->now(w->now_ctx, &tw->time) != CMT_OK) {         /* :189 */
        free(tw);
        return CMT_FAULT;
    }
    tw->msg = *msg;

    size_t plen = 0;
    int rc = cmt_timed_wal_message_encode(
        tw, w->enc_buf + NODUS_CMT_WAL_DIGEST_LEN,
        (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES, &plen);          /* :302-311 */
    int64_t stamp_ns = cmt_time_unix_nano(tw->time);
    free(tw);
    if (rc != CMT_OK) return rc;
    if (plen > (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES) {
        QGP_LOG_ERROR(LOG_TAG, "msg is too big: %zu bytes, max: %d bytes",
                      plen, (int)CMT_WAL_MAX_MSG_SIZE_BYTES);  /* :318-320 */
        return CMT_REJECT;
    }
    if (qgp_sha3_512(w->enc_buf + NODUS_CMT_WAL_DIGEST_LEN, plen, w->enc_buf)
        != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "SHA3-512 backend failed");
        return CMT_FAULT;
    }
    *out_height = height;
    *out_stamp_ns = stamp_ns;
    *out_row_len = NODUS_CMT_WAL_DIGEST_LEN + plen;
    return CMT_OK;
}

/* One AUTOCOMMIT row. `sync` picks the connection and therefore the
 * durability class: the FULL one fsyncs on commit, the main one does not
 * (D-13, D-15 rev 5 (4)). Neither opens a transaction. */
static int wal_append(nodus_cmt_wal_t *w, const cmt_wal_message_t *msg,
                      bool sync) {
    if (!w || !w->full || !w->main_db || !msg) return CMT_FAULT;

    int64_t height = 0, stamp_ns = 0;
    size_t row_len = 0;
    int rc = wal_frame(w, msg, &height, &stamp_ns, &row_len);
    if (rc != CMT_OK) return rc;

    sqlite3      *db = sync ? w->full : w->main_db;
    sqlite3_stmt *st = sync ? w->st_insert : w->st_insert_main;

    sqlite3_reset(st);
    sqlite3_bind_int64(st, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)height);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)w->next_seq);
    sqlite3_bind_int(st, 4, (int)msg->kind);
    sqlite3_bind_blob(st, 5, w->enc_buf, (int)row_len, SQLITE_STATIC);
    int src = sqlite3_step(st);
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    if (src != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "cmt_wal insert failed: %s",
                      sqlite3_errmsg(db));
        return CMT_FAULT;                /* autocommit: nothing to undo */
    }
    w->next_seq++;

    if (sync) {
        /* :211's fsync happened with the commit, and it covered the
         * whole `-wal` file, so any earlier Write-class row is durable
         * too and the ticker has nothing left to flush. */
        w->unsynced = false;
        w->flush_armed = false;
    } else if (!w->unsynced) {
        /* wal.go:28/:137-155 — the 2 s ticker, as a deadline from the
         * FIRST unsynced write. */
        w->unsynced = true;
        w->flush_armed = true;
        w->flush_deadline_ns = stamp_ns + NODUS_CMT_WAL_FLUSH_INTERVAL_NS;
    }
    return CMT_OK;
}

int nodus_cmt_wal_write(void *ctx, const cmt_wal_message_t *msg) {
    return wal_append((nodus_cmt_wal_t *)ctx, msg, false);
}

int nodus_cmt_wal_write_sync(void *ctx, const cmt_wal_message_t *msg) {
    int rc = wal_append((nodus_cmt_wal_t *)ctx, msg, true);
    return rc == CMT_OK ? CMT_OK : CMT_FAULT;               /* :206-215 */
}

/* The durability barrier. One real write on the FULL connection, because
 * SQLite has no fsync-on-demand and an empty transaction syncs nothing
 * (measured); the commit fdatasyncs the `-wal` file the main connection
 * appended its rows to, so all of them become durable with it. */
static int wal_sync_barrier(nodus_cmt_wal_t *w) {
    sqlite3_reset(w->st_sync);
    sqlite3_bind_int64(w->st_sync, 1, (sqlite3_int64)w->protocol_id);
    int rc = sqlite3_step(w->st_sync);
    sqlite3_reset(w->st_sync);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "cmt_wal_sync barrier failed: %s",
                      sqlite3_errmsg(w->full));
        return CMT_FAULT;
    }
    if (sqlite3_changes(w->full) != 1) {
        /* The seeded row is gone: the barrier would commit nothing and
         * sync nothing, so the durability claim would be false. */
        QGP_LOG_ERROR(LOG_TAG, "%s", "cmt_wal_sync row is missing");
        return CMT_FAULT;
    }
    w->unsynced = false;
    w->flush_armed = false;
    return CMT_OK;
}

int nodus_cmt_wal_flush_and_sync(void *ctx) {
    nodus_cmt_wal_t *w = (nodus_cmt_wal_t *)ctx;
    if (!w || !w->full) return CMT_FAULT;
    if (!w->unsynced) return CMT_OK;
    return wal_sync_barrier(w);
}

bool nodus_cmt_wal_next_flush_deadline(const nodus_cmt_wal_t *w,
                                       int64_t *out_deadline_ns) {
    if (!w || !w->flush_armed) return false;
    if (out_deadline_ns) *out_deadline_ns = w->flush_deadline_ns;
    return true;
}

int nodus_cmt_wal_flush_if_due(nodus_cmt_wal_t *w, int64_t now_ns) {
    if (!w) return CMT_FAULT;
    if (!w->flush_armed || now_ns < w->flush_deadline_ns) return CMT_OK;
    return nodus_cmt_wal_flush_and_sync(w);                  /* :145 */
}

/* ── the read side ───────────────────────────────────────────────────── */

/* The message half of Decode (wal.go:385-419) after the row digest.
 * Every failure is the reference's DataCorruptionError → CMT_FAULT
 * (D-15 rev 5: stop, never skip). */
static int wal_decode_row(nodus_cmt_wal_t *w, int64_t row_height,
                          int row_kind, const uint8_t *blob, size_t blob_len,
                          cmt_timed_wal_message_t *out) {
    if (blob_len < NODUS_CMT_WAL_DIGEST_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "cmt_wal row shorter than its digest");
        return CMT_FAULT;
    }
    const uint8_t *p = blob + NODUS_CMT_WAL_DIGEST_LEN;
    size_t plen = blob_len - NODUS_CMT_WAL_DIGEST_LEN;
    if (plen > (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES) {         /* :385-390 */
        QGP_LOG_ERROR(LOG_TAG, "length %zu exceeded maximum possible value "
                      "of %d bytes", plen, (int)CMT_WAL_MAX_MSG_SIZE_BYTES);
        return CMT_FAULT;
    }
    uint8_t want[NODUS_CMT_WAL_DIGEST_LEN];
    if (qgp_sha3_512(p, plen, want) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "SHA3-512 backend failed");
        return CMT_FAULT;
    }
    if (memcmp(want, blob, NODUS_CMT_WAL_DIGEST_LEN) != 0) { /* :399-402 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "cmt_wal row digest mismatch");
        return CMT_FAULT;
    }
    if (row_kind < (int)CMT_PB_WAL_EVENT_DATA_ROUND_STATE ||
        row_kind > (int)CMT_PB_WAL_END_HEIGHT) {
        QGP_LOG_ERROR(LOG_TAG, "cmt_wal row kind %d out of range", row_kind);
        return CMT_FAULT;
    }
    w->read_arena.used = 0;
    int rc = cmt_timed_wal_message_decode(p, plen, out, &w->read_arena);
    if (rc != CMT_OK) {                                      /* :404-413 */
        QGP_LOG_ERROR(LOG_TAG, "cmt_wal row does not decode (rc %d)", rc);
        return CMT_FAULT;
    }
    /* The two columns this module derived from P must still agree
     * with P: a disagreement is a torn row, not a message. */
    int64_t h = 0;
    if ((int)out->msg.kind != row_kind ||
        nodus_cmt_wal_message_height(&out->msg, &h) != CMT_OK ||
        h != row_height) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "cmt_wal row columns disagree with its payload");
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_wal_search_end_height(void *ctx, int64_t height,
                                    bool *out_found) {
    nodus_cmt_wal_t *w = (nodus_cmt_wal_t *)ctx;
    if (!w || !w->main_db || !out_found) return CMT_FAULT;
    *out_found = false;

    sqlite3_reset(w->st_search);
    sqlite3_bind_int64(w->st_search, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_int64(w->st_search, 2, (sqlite3_int64)height);
    int rc = sqlite3_step(w->st_search);
    if (rc == SQLITE_DONE) {
        sqlite3_reset(w->st_search);
        return CMT_OK;                                       /* :291 not found */
    }
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "cmt_wal search failed: %s",
                      sqlite3_errmsg(w->main_db));
        sqlite3_reset(w->st_search);
        return CMT_FAULT;
    }
    int64_t row_height = sqlite3_column_int64(w->st_search, 0);
    sqlite3_int64 row_seq = sqlite3_column_int64(w->st_search, 1);
    const void *blob = sqlite3_column_blob(w->st_search, 2);
    size_t blob_len = (size_t)sqlite3_column_bytes(w->st_search, 2);

    cmt_timed_wal_message_t *tw =
        (cmt_timed_wal_message_t *)malloc(sizeof *tw);
    if (!tw) { sqlite3_reset(w->st_search); return CMT_FAULT; }
    int drc = wal_decode_row(w, row_height, (int)CMT_PB_WAL_END_HEIGHT,
                             (const uint8_t *)blob, blob_len, tw);
    bool is_end = (drc == CMT_OK && tw->msg.kind == CMT_PB_WAL_END_HEIGHT &&
                   tw->msg.u.end_height.height == height);   /* :281-284 */
    free(tw);
    sqlite3_reset(w->st_search);
    if (drc != CMT_OK) return CMT_FAULT;
    if (!is_end || row_seq < 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "cmt_wal kind-4 row is not EndHeight");
        return CMT_FAULT;
    }
    w->cursor_valid = true;
    w->cursor_height = row_height;
    w->cursor_seq = (uint64_t)row_seq;
    *out_found = true;
    return CMT_OK;
}

int nodus_cmt_wal_read_next(void *ctx, cmt_timed_wal_message_t *out,
                            bool *out_eof) {
    nodus_cmt_wal_t *w = (nodus_cmt_wal_t *)ctx;
    if (!w || !w->main_db || !out || !out_eof) return CMT_FAULT;
    *out_eof = false;

    sqlite3_reset(w->st_next);
    sqlite3_bind_int64(w->st_next, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_int64(w->st_next, 2, (sqlite3_int64)w->cursor_height);
    sqlite3_bind_int64(w->st_next, 3, (sqlite3_int64)w->cursor_seq);
    sqlite3_bind_int(w->st_next, 4, w->cursor_valid ? 1 : 0);
    int rc = sqlite3_step(w->st_next);
    if (rc == SQLITE_DONE) {
        sqlite3_reset(w->st_next);
        *out_eof = true;                                     /* :370-372 */
        return CMT_OK;
    }
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "cmt_wal read failed: %s",
                      sqlite3_errmsg(w->main_db));
        sqlite3_reset(w->st_next);
        return CMT_FAULT;
    }
    int64_t row_height = sqlite3_column_int64(w->st_next, 0);
    sqlite3_int64 row_seq = sqlite3_column_int64(w->st_next, 1);
    int row_kind = sqlite3_column_int(w->st_next, 2);
    const void *blob = sqlite3_column_blob(w->st_next, 3);
    size_t blob_len = (size_t)sqlite3_column_bytes(w->st_next, 3);

    int drc = wal_decode_row(w, row_height, row_kind, (const uint8_t *)blob,
                             blob_len, out);
    sqlite3_reset(w->st_next);
    if (drc != CMT_OK) return CMT_FAULT;
    if (row_seq < 0) return CMT_FAULT;
    w->cursor_valid = true;
    w->cursor_height = row_height;
    w->cursor_seq = (uint64_t)row_seq;
    return CMT_OK;
}

/* ── prune ───────────────────────────────────────────────────────────── */

int nodus_cmt_wal_prune_below(nodus_cmt_wal_t *w, int64_t height) {
    if (!w || !w->full) return CMT_FAULT;
    sqlite3_reset(w->st_prune);
    sqlite3_bind_int64(w->st_prune, 1, (sqlite3_int64)w->protocol_id);
    sqlite3_bind_int64(w->st_prune, 2, (sqlite3_int64)height);
    int rc = sqlite3_step(w->st_prune);          /* autocommit on FULL */
    sqlite3_reset(w->st_prune);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "cmt_wal prune failed: %s",
                      sqlite3_errmsg(w->full));
        return CMT_FAULT;
    }
    /* A DELETE that removed rows is a real commit on the FULL
     * connection, so it fsynced the shared `-wal`. A DELETE that matched
     * nothing commits nothing, so a pending Write-class row stays
     * pending and the deadline must survive. */
    if (sqlite3_changes(w->full) > 0) {
        w->unsynced = false;
        w->flush_armed = false;
    }
    return CMT_OK;
}
