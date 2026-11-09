/**
 * @file amm_journal.c
 * @brief nodus-amm durable journal (see amm_journal.h).
 *
 * "A DB failure is never a value" (nodus/CLAUDE.md): every bind and every
 * column extraction is checked; a column of the wrong type, a NULL text, a
 * text that does not fit its field or a blob of the wrong length is a
 * FAULT (-1) of the read, never an empty or zero field.
 */
#include "amm_journal.h"

#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "crypto/hash/keccak256.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_JNL"

/* 2: package 2 adds nodus_rows and nodus_attempts (CREATE IF NOT EXISTS, so a
 * version 1 file only gains the two tables). */
/* 3: swaps.approved_tip (the height bound of fix (a)). Nothing has shipped, so
 * a version 1 or 2 file is not migrated: it must be deleted. Package 3 adds
 * the table eth_attempts. */
/* 4: eth_attempts.state gains 'unknown' (a receipt without the USDT Transfer
 * log, plan line 264); the CHECK of an existing table cannot change, so a
 * version 3 file (never shipped) is refused and must be deleted. */
#define SCHEMA_VERSION 4
#define BUSY_MS 5000

struct amm_journal {
    sqlite3        *db;
    pthread_mutex_t mu;        /* recursive                                 */
    int             txd;       /* >0: inside amm_journal_tx_begin           */
    int             poisoned;  /* a database fault inside the outer tx      */
    int             sp;        /* savepoint counter for inner ops           */
};

static int (*t_precommit_hook)(void) = NULL;

void amm_journal_test_precommit_hook(int (*fn)(void)) { t_precommit_hook = fn; }

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS swaps("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
    " id TEXT NOT NULL UNIQUE,"
    " dir INTEGER NOT NULL CHECK(dir IN (0,1)),"
    " state TEXT NOT NULL CHECK(state IN ('approved','paid_waiting_depth',"
    "'counted','payout_pending','paid','refund_pending','refunded','expired',"
    "'held','reversed','unknown')),"
    " sender TEXT NOT NULL,"
    " dest TEXT NOT NULL,"
    " amount INTEGER NOT NULL,"
    " minimum INTEGER NOT NULL,"
    " value_usdt INTEGER NOT NULL,"
    " approved_at INTEGER NOT NULL,"
    " expiry INTEGER NOT NULL,"
    " incoming_id TEXT NOT NULL DEFAULT '',"
    " message TEXT NOT NULL DEFAULT '',"
    " approved_tip INTEGER NOT NULL DEFAULT 0);"
    "CREATE INDEX IF NOT EXISTS swaps_state ON swaps(state);"
    "CREATE INDEX IF NOT EXISTS swaps_sender ON swaps(sender, amount);"
    "CREATE INDEX IF NOT EXISTS swaps_incoming ON swaps(incoming_id);"
    "CREATE TABLE IF NOT EXISTS req_numbers("
    " sender TEXT NOT NULL, req_no BLOB NOT NULL, swap_seq INTEGER NOT NULL,"
    " PRIMARY KEY(sender, req_no));"
    "CREATE TABLE IF NOT EXISTS paid_markers("
    " transfer_id TEXT PRIMARY KEY, swap_seq INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS pool("
    " id INTEGER PRIMARY KEY CHECK(id=1),"
    " depth_n BLOB NOT NULL, depth_u BLOB NOT NULL, units BLOB NOT NULL);"
    "CREATE TABLE IF NOT EXISTS flags("
    " name TEXT PRIMARY KEY, value INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS cursors("
    " name TEXT PRIMARY KEY, value INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS blocks("
    " height INTEGER PRIMARY KEY, hash BLOB NOT NULL, parent BLOB NOT NULL,"
    " ts INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS eth_records("
    " tx BLOB NOT NULL, log_index INTEGER NOT NULL,"
    " block_number INTEGER NOT NULL, block_hash BLOB NOT NULL,"
    " block_ts INTEGER NOT NULL, from_addr BLOB NOT NULL,"
    " to_addr BLOB NOT NULL, value BLOB NOT NULL,"
    " state TEXT NOT NULL CHECK(state IN ('candidate','seen','deep','held',"
    "'dropped','reversed')),"
    " PRIMARY KEY(tx, log_index));"
    "CREATE INDEX IF NOT EXISTS rec_block ON eth_records(block_number);"
    "CREATE TABLE IF NOT EXISTS nodus_rows("
    " height INTEGER NOT NULL, item INTEGER NOT NULL, seq INTEGER NOT NULL,"
    " wire BLOB NOT NULL, peer TEXT NOT NULL, amount INTEGER NOT NULL,"
    " ts INTEGER NOT NULL,"
    " state TEXT NOT NULL CHECK(state IN ('held','counted')),"
    " swap_seq INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '',"
    " PRIMARY KEY(height, item, seq));"
    "CREATE INDEX IF NOT EXISTS nrow_wire ON nodus_rows(wire);"
    "CREATE TABLE IF NOT EXISTS nodus_attempts("
    " swap_seq INTEGER NOT NULL, n INTEGER NOT NULL,"
    " gross INTEGER NOT NULL, net INTEGER NOT NULL, fee INTEGER NOT NULL,"
    " dest TEXT NOT NULL, env BLOB NOT NULL,"
    " wire_id BLOB NOT NULL, intent_id BLOB NOT NULL, inputs BLOB NOT NULL,"
    " n_in INTEGER NOT NULL, build_tip INTEGER NOT NULL,"
    " expiry INTEGER NOT NULL, scan_next INTEGER NOT NULL,"
    " last_submit_tip INTEGER NOT NULL DEFAULT 0,"
    " state TEXT NOT NULL CHECK(state IN ('signed','submitted','expired',"
    "'confirmed')),"
    " PRIMARY KEY(swap_seq, n));"
    /* package 3: the signed USDT payouts, stored before they are broadcast
     * (plan section 10 line 265: "unique on hash and on (chain, nonce)",
     * Boltz PendingEthereumTransaction.ts:51-60). Created with IF NOT EXISTS
     * like the package 2 tables: a version 3 file gains it. */
    "CREATE TABLE IF NOT EXISTS eth_attempts("
    " swap_seq INTEGER NOT NULL, n INTEGER NOT NULL,"
    " chain_id INTEGER NOT NULL, nonce INTEGER NOT NULL,"
    " hash BLOB NOT NULL, raw BLOB NOT NULL, recipient BLOB NOT NULL,"
    " gross INTEGER NOT NULL, net INTEGER NOT NULL, fee INTEGER NOT NULL,"
    " gas_limit INTEGER NOT NULL, max_fee INTEGER NOT NULL,"
    " max_priority INTEGER NOT NULL,"
    " last_submit_tip INTEGER NOT NULL DEFAULT 0,"
    " state TEXT NOT NULL CHECK(state IN ('signed','submitted','confirmed',"
    "'failed','orphaned','unknown')),"
    " PRIMARY KEY(swap_seq, n),"
    " UNIQUE(hash),"
    " UNIQUE(chain_id, nonce));";

/* ── checked column access ──────────────────────────────────────────── */

static int col_text(sqlite3_stmt *st, int i, char *dst, size_t cap) {
    if (sqlite3_column_type(st, i) != SQLITE_TEXT) return -1;
    const unsigned char *s = sqlite3_column_text(st, i);
    int n = sqlite3_column_bytes(st, i);
    if (!s || n < 0 || (size_t)n >= cap) return -1;
    memcpy(dst, s, (size_t)n);
    dst[n] = '\0';
    return 0;
}

static int col_i64(sqlite3_stmt *st, int i, int64_t *out) {
    if (sqlite3_column_type(st, i) != SQLITE_INTEGER) return -1;
    *out = sqlite3_column_int64(st, i);
    return 0;
}

/* A non-negative INTEGER column into a uint64. */
static int col_u64(sqlite3_stmt *st, int i, uint64_t *out) {
    int64_t v;
    if (col_i64(st, i, &v) != 0 || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* A BLOB column of EXACTLY n bytes. */
static int col_blob_n(sqlite3_stmt *st, int i, void *dst, int n) {
    if (sqlite3_column_type(st, i) != SQLITE_BLOB) return -1;
    if (sqlite3_column_bytes(st, i) != n) return -1;
    const void *p = sqlite3_column_blob(st, i);
    if (!p) return -1;
    memcpy(dst, p, (size_t)n);
    return 0;
}

/* ── statement helpers ──────────────────────────────────────────────── */

typedef struct {
    enum { A_INT, A_TXT, A_BLOB } t;
    int64_t     i;
    const char *s;
    const void *p;
    int         n;
} arg_t;

#define AI(v)    ((arg_t){ .t = A_INT,  .i = (int64_t)(v) })
#define AT(v)    ((arg_t){ .t = A_TXT,  .s = (v) })
#define AB(v, l) ((arg_t){ .t = A_BLOB, .p = (v), .n = (l) })

static int prep(amm_journal_t *j, const char *sql, const arg_t *args, int nargs,
                sqlite3_stmt **out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare failed: %s", sqlite3_errmsg(j->db));
        return -1;
    }
    for (int k = 0; k < nargs; k++) {
        int rc;
        switch (args[k].t) {
        case A_INT:  rc = sqlite3_bind_int64(st, k + 1, args[k].i); break;
        case A_TXT:  rc = sqlite3_bind_text(st, k + 1, args[k].s, -1, SQLITE_STATIC); break;
        default:     rc = sqlite3_bind_blob(st, k + 1, args[k].p, args[k].n, SQLITE_STATIC); break;
        }
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "bind failed: %s", sqlite3_errmsg(j->db));
            sqlite3_finalize(st);
            return -1;
        }
    }
    *out = st;
    return 0;
}

/* Run a statement that returns no row. @return 0 / -1; *changes (optional)
 * = rows changed. */
static int run(amm_journal_t *j, const char *sql, const arg_t *args, int nargs,
               int *changes) {
    sqlite3_stmt *st;
    if (prep(j, sql, args, nargs, &st) != 0) return -1;
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "step failed (%d): %s", rc, sqlite3_errmsg(j->db));
        return -1;
    }
    if (changes) *changes = sqlite3_changes(j->db);
    return 0;
}

static int exec_sql(sqlite3 *db, const char *sql) {
    char *em = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &em);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "sql failed (%d): %s", rc, em ? em : "?");
        sqlite3_free(em);
        return -1;
    }
    return 0;
}

/* One integer result. @return 0 / -1. */
static int one_int(amm_journal_t *j, const char *sql, const arg_t *args,
                   int nargs, int64_t *out) {
    sqlite3_stmt *st;
    if (prep(j, sql, args, nargs, &st) != 0) return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW && col_i64(st, 0, out) == 0) ret = 0;
    sqlite3_finalize(st);
    return ret;
}

/* ── locking and transactions ───────────────────────────────────────── */

static void lock(amm_journal_t *j) {
    pthread_mutex_lock(&j->mu);
    sqlite3_busy_timeout(j->db, BUSY_MS);
}

static void unlock(amm_journal_t *j) { pthread_mutex_unlock(&j->mu); }

/* Start a WRITE operation: BEGIN IMMEDIATE on its own, or a savepoint inside
 * an outer transaction. Lock held on success. @return 0 / -1 (unlocked). */
static int op_begin(amm_journal_t *j) {
    lock(j);
    int rc;
    if (j->txd) {
        if (j->poisoned) { unlock(j); return -1; }
        rc = exec_sql(j->db, "SAVEPOINT amm_op");
    } else {
        rc = exec_sql(j->db, "BEGIN IMMEDIATE");
    }
    if (rc != 0) { unlock(j); return -1; }
    return 0;
}

/* Finish a write operation with its result `rc`: AMM_J_OK commits (or
 * releases the savepoint); any other value writes nothing (rolled back); -1
 * inside an outer transaction poisons it. Returns `rc`, or -1 when the
 * commit itself fails. Unlocks. */
static int op_end(amm_journal_t *j, int rc) {
    if (j->txd) {
        if (rc == AMM_J_OK) {
            if (exec_sql(j->db, "RELEASE amm_op") != 0) { j->poisoned = 1; rc = -1; }
        } else {
            exec_sql(j->db, "ROLLBACK TO amm_op");
            exec_sql(j->db, "RELEASE amm_op");
            if (rc == -1) j->poisoned = 1;
        }
    } else {
        if (rc == AMM_J_OK) {
            if (t_precommit_hook && t_precommit_hook() != 0) {
                exec_sql(j->db, "ROLLBACK");
                rc = -1;
            } else if (exec_sql(j->db, "COMMIT") != 0) {
                exec_sql(j->db, "ROLLBACK");
                rc = -1;
            }
        } else {
            exec_sql(j->db, "ROLLBACK");
        }
    }
    unlock(j);
    return rc;
}

int amm_journal_tx_begin(amm_journal_t *j) {
    if (!j) return -1;
    lock(j);
    if (j->txd) { unlock(j); return -1; }            /* no nesting          */
    if (exec_sql(j->db, "BEGIN IMMEDIATE") != 0) { unlock(j); return -1; }
    j->txd = 1;
    j->poisoned = 0;
    return 0;                                         /* lock stays held     */
}

int amm_journal_tx_commit(amm_journal_t *j) {
    int rc = 0;
    if (!j || !j->txd) return -1;
    if (j->poisoned) {
        exec_sql(j->db, "ROLLBACK");
        rc = -1;
    } else if (t_precommit_hook && t_precommit_hook() != 0) {
        exec_sql(j->db, "ROLLBACK");
        rc = -1;
    } else if (exec_sql(j->db, "COMMIT") != 0) {
        exec_sql(j->db, "ROLLBACK");
        rc = -1;
    }
    j->txd = 0;
    j->poisoned = 0;
    unlock(j);
    return rc;
}

void amm_journal_tx_rollback(amm_journal_t *j) {
    if (!j || !j->txd) return;
    exec_sql(j->db, "ROLLBACK");
    j->txd = 0;
    j->poisoned = 0;
    unlock(j);
}

/* ── helpers ────────────────────────────────────────────────────────── */

static void hex_of(const uint8_t *b, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = '\0';
}

void amm_journal_eth_key(const uint8_t tx[32], char *out, size_t cap) {
    char hx[65];
    hex_of(tx, 32, hx);
    snprintf(out, cap, "eth:%s", hx);
}

static int hex_lower_n(const char *s, size_t n) {
    if (!s || strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static int addr_ok(const char *s, amm_dir_t dir, int sender) {
    /* USDT->NODUS: sender is an Ethereum address, destination a Nodus one;
     * NODUS->USDT the other way round. */
    int eth_side = (dir == AMM_USDT_TO_NODUS) ? sender : !sender;
    return hex_lower_n(s, eth_side ? AMM_ADDR_ETH : AMM_ADDR_NODUS);
}

static int tid_ok(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n >= AMM_TID_MAX) return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] <= 0x20 || (unsigned char)s[i] > 0x7e) return 0;
    return 1;
}

static int known_swap_state(const char *s) {
    static const char *all[] = {AMM_S_APPROVED, AMM_S_PAID_WAITING, AMM_S_COUNTED,
        AMM_S_PAYOUT_PENDING, AMM_S_PAID, AMM_S_REFUND_PENDING, AMM_S_REFUNDED,
        AMM_S_EXPIRED, AMM_S_HELD, AMM_S_REVERSED, AMM_S_UNKNOWN};
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (!strcmp(s, all[i])) return 1;
    return 0;
}

/* The legal swap-state graph: see amm_journal.h for every edge's plan line. */
static int legal_swap(const char *from, const char *to) {
    static const struct { const char *f, *t; } ok[] = {
        {AMM_S_APPROVED, AMM_S_PAID_WAITING}, {AMM_S_APPROVED, AMM_S_EXPIRED},
        {AMM_S_PAID_WAITING, AMM_S_COUNTED},  {AMM_S_PAID_WAITING, AMM_S_APPROVED},
        {AMM_S_COUNTED, AMM_S_PAYOUT_PENDING}, {AMM_S_COUNTED, AMM_S_REFUND_PENDING},
        {AMM_S_COUNTED, AMM_S_REVERSED},
        {AMM_S_PAYOUT_PENDING, AMM_S_PAID}, {AMM_S_PAYOUT_PENDING, AMM_S_UNKNOWN},
        {AMM_S_PAYOUT_PENDING, AMM_S_REFUND_PENDING},
        {AMM_S_PAYOUT_PENDING, AMM_S_HELD},      /* USDT delivered != sent (l.264, 277) */
        {AMM_S_PAYOUT_PENDING, AMM_S_REVERSED},
        {AMM_S_PAID, AMM_S_REVERSED},
        {AMM_S_REFUND_PENDING, AMM_S_REFUNDED}, {AMM_S_REFUND_PENDING, AMM_S_HELD},
        {AMM_S_REFUND_PENDING, AMM_S_UNKNOWN}, {AMM_S_REFUND_PENDING, AMM_S_REVERSED},
        {AMM_S_REFUNDED, AMM_S_REVERSED},
        {AMM_S_HELD, AMM_S_REVERSED}, {AMM_S_UNKNOWN, AMM_S_REVERSED},
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        if (!strcmp(from, ok[i].f) && !strcmp(to, ok[i].t)) return 1;
    return 0;
}

/* ── swap rows ──────────────────────────────────────────────────────── */

#define SWAP_COLS "seq, id, dir, state, sender, dest, amount, minimum, " \
                  "value_usdt, approved_at, expiry, incoming_id, message, " \
                  "approved_tip"

static int load_swap_row(sqlite3_stmt *st, amm_swap_t *s) {
    memset(s, 0, sizeof(*s));
    int64_t dir = 0;
    if (col_i64(st, 0, &s->seq) != 0 ||
        col_text(st, 1, s->id, sizeof(s->id)) != 0 ||
        col_i64(st, 2, &dir) != 0 ||
        col_text(st, 3, s->state, sizeof(s->state)) != 0 ||
        col_text(st, 4, s->sender, sizeof(s->sender)) != 0 ||
        col_text(st, 5, s->dest, sizeof(s->dest)) != 0 ||
        col_u64(st, 6, &s->amount) != 0 || col_u64(st, 7, &s->minimum) != 0 ||
        col_u64(st, 8, &s->value_usdt) != 0 ||
        col_u64(st, 9, &s->approved_at) != 0 || col_u64(st, 10, &s->expiry) != 0 ||
        col_text(st, 11, s->incoming_id, sizeof(s->incoming_id)) != 0 ||
        col_text(st, 12, s->message, sizeof(s->message)) != 0 ||
        col_u64(st, 13, &s->approved_tip) != 0 || s->approved_tip == 0 ||
        (dir != 0 && dir != 1) || strlen(s->id) != 32 ||
        !known_swap_state(s->state)) {
        QGP_LOG_ERROR(LOG_TAG, "a swap row does not read back as a valid swap "
                      "(seq %lld)", (long long)s->seq);
        memset(s, 0, sizeof(*s));
        return -1;
    }
    s->dir = (amm_dir_t)dir;
    if (!addr_ok(s->sender, s->dir, 1) || !addr_ok(s->dest, s->dir, 0)) {
        QGP_LOG_ERROR(LOG_TAG, "a swap row holds a malformed address "
                      "(seq %lld)", (long long)s->seq);
        memset(s, 0, sizeof(*s));
        return -1;
    }
    return 0;
}

/* One swap by a WHERE clause. @return 0 found / 1 none / -1. Lock held. */
static int swap_query(amm_journal_t *j, const char *where, const arg_t *args,
                      int nargs, amm_swap_t *out) {
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT " SWAP_COLS " FROM swaps WHERE %s "
             "ORDER BY seq LIMIT 1", where);
    sqlite3_stmt *st;
    if (prep(j, sql, args, nargs, &st) != 0) return -1;
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) {
        amm_swap_t tmp;
        if (load_swap_row(st, &tmp) != 0) ret = -1;
        else { if (out) *out = tmp; ret = 0; }
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "step failed: %s", sqlite3_errmsg(j->db));
        ret = -1;
    }
    sqlite3_finalize(st);
    return ret;
}

int amm_journal_swap_get(amm_journal_t *j, const char *id, amm_swap_t *out) {
    if (!j || !id) return -1;
    lock(j);
    int r = swap_query(j, "id=?1", (arg_t[]){AT(id)}, 1, out);
    unlock(j);
    return r;
}

int amm_journal_swap_by_seq(amm_journal_t *j, int64_t seq, amm_swap_t *out) {
    if (!j) return -1;
    lock(j);
    int r = swap_query(j, "seq=?1", (arg_t[]){AI(seq)}, 1, out);
    unlock(j);
    return r;
}

int amm_journal_swap_by_incoming(amm_journal_t *j, const char *incoming_id,
                                 amm_swap_t *out) {
    if (!j || !incoming_id || !*incoming_id) return -1;
    lock(j);
    int r = swap_query(j, "incoming_id=?1", (arg_t[]){AT(incoming_id)}, 1, out);
    unlock(j);
    return r;
}

int amm_journal_swap_open_nodus(amm_journal_t *j, const char *incoming_id,
                                const char *sender, uint64_t amount,
                                amm_swap_t *out) {
    if (!j || !incoming_id || !*incoming_id || !sender || !out ||
        amount > (uint64_t)INT64_MAX) return -1;
    lock(j);
    int r = swap_query(j, "incoming_id=?1 AND sender=?2 AND amount=?3 AND "
                          "dir=1 AND state='approved'",
                       (arg_t[]){AT(incoming_id), AT(sender), AI(amount)}, 3, out);
    unlock(j);
    return r;
}

/* ── sums, counts, markers ──────────────────────────────────────────── */

#define INFLIGHT_STATES "('approved','paid_waiting_depth','counted'," \
                        "'payout_pending','refund_pending')"

/* `held` holds its room only when `held_keeps_room` is 1 (plan lines 312, 407
 * defer the question; the value is a required setting). */
static int inflight_sum_locked(amm_journal_t *j, int held_keeps_room,
                               uint64_t *out) {
    sqlite3_stmt *st;
    if (prep(j, "SELECT value_usdt FROM swaps WHERE state IN " INFLIGHT_STATES
             " OR (?1=1 AND state='held') ORDER BY seq",
             (arg_t[]){AI(held_keeps_room ? 1 : 0)}, 1, &st) != 0) return -1;
    uint64_t sum = 0;
    int rc, ret = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint64_t v;
        if (col_u64(st, 0, &v) != 0 || sum > UINT64_MAX - v) { ret = -1; break; }
        sum += v;
    }
    if (ret == 0 && rc != SQLITE_DONE) ret = -1;
    sqlite3_finalize(st);
    if (ret == 0) *out = sum;
    return ret;
}

int amm_journal_inflight_sum(amm_journal_t *j, int held_keeps_room,
                             uint64_t *out) {
    if (!j || !out) return -1;
    lock(j);
    int r = inflight_sum_locked(j, held_keeps_room, out);
    unlock(j);
    return r;
}

int amm_journal_state_count(amm_journal_t *j, const char *state, int *out) {
    if (!j || !state || !out) return -1;
    lock(j);
    int64_t n = 0;
    int r = one_int(j, "SELECT COUNT(*) FROM swaps WHERE state=?1",
                    (arg_t[]){AT(state)}, 1, &n);
    unlock(j);
    if (r != 0) return -1;
    *out = (int)n;
    return 0;
}

static int exists_q(amm_journal_t *j, const char *sql, const arg_t *args, int n) {
    sqlite3_stmt *st;
    if (prep(j, sql, args, n, &st) != 0) return -1;
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 0;
    if (rc == SQLITE_DONE) return 1;
    return -1;
}

int amm_journal_marker_exists(amm_journal_t *j, const char *transfer_id) {
    if (!j || !transfer_id) return -1;
    lock(j);
    int r = exists_q(j, "SELECT 1 FROM paid_markers WHERE transfer_id=?1",
                     (arg_t[]){AT(transfer_id)}, 1);
    unlock(j);
    return r;
}

int amm_journal_req_marker_exists(amm_journal_t *j, const char *sender,
                                  const uint8_t req_no[32]) {
    if (!j || !sender || !req_no) return -1;
    lock(j);
    int r = exists_q(j, "SELECT 1 FROM req_numbers WHERE sender=?1 AND req_no=?2",
                     (arg_t[]){AT(sender), AB(req_no, 32)}, 2);
    unlock(j);
    return r;
}

/* ── flags, cursors, pool ───────────────────────────────────────────── */

static int flag_get_locked(amm_journal_t *j, const char *name, int *out) {
    sqlite3_stmt *st;
    if (prep(j, "SELECT value FROM flags WHERE name=?1", (arg_t[]){AT(name)}, 1,
             &st) != 0) return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_DONE) { *out = 0; ret = 0; }
    else if (rc == SQLITE_ROW) {
        int64_t v;
        if (col_i64(st, 0, &v) == 0 && (v == 0 || v == 1)) { *out = (int)v; ret = 0; }
    }
    sqlite3_finalize(st);
    return ret;
}

int amm_journal_reversal_pause_get(amm_journal_t *j, int *out) {
    if (!j || !out) return -1;
    lock(j);
    int r = flag_get_locked(j, "reversal_pause", out);
    unlock(j);
    return r;
}

int amm_journal_cursor_get(amm_journal_t *j, const char *name, uint64_t *out) {
    if (!j || !name || !out) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    if (prep(j, "SELECT value FROM cursors WHERE name=?1", (arg_t[]){AT(name)}, 1,
             &st) == 0) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) ret = (col_u64(st, 0, out) == 0) ? 0 : -1;
        else if (rc == SQLITE_DONE) ret = 1;
        sqlite3_finalize(st);
    }
    unlock(j);
    return ret;
}

int amm_journal_cursor_put(amm_journal_t *j, const char *name, uint64_t v) {
    if (!j || !name || v > (uint64_t)INT64_MAX) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    sqlite3_stmt *st;
    if (prep(j, "SELECT value FROM cursors WHERE name=?1", (arg_t[]){AT(name)}, 1,
             &st) == 0) {
        int s = sqlite3_step(st);
        uint64_t cur = 0;
        if (s == SQLITE_ROW && col_u64(st, 0, &cur) == 0) {
            rc = (v > cur) ? AMM_J_OK : AMM_J_ILLEGAL;
        } else if (s == SQLITE_DONE) {
            rc = AMM_J_OK;
        }
        sqlite3_finalize(st);
    }
    if (rc == AMM_J_OK &&
        run(j, "INSERT INTO cursors(name, value) VALUES(?1, ?2) "
               "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            (arg_t[]){AT(name), AI(v)}, 2, NULL) != 0) rc = -1;
    return op_end(j, rc);
}

int amm_journal_cursor_reset(amm_journal_t *j, const char *name, uint64_t v) {
    if (!j || !name || v > (uint64_t)INT64_MAX) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = run(j, "INSERT INTO cursors(name, value) VALUES(?1, ?2) "
                    "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                 (arg_t[]){AT(name), AI(v)}, 2, NULL) == 0 ? AMM_J_OK : -1;
    return op_end(j, rc);
}

int amm_journal_pool_get(amm_journal_t *j, amm_pool_t *out) {
    if (!j || !out) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    if (prep(j, "SELECT depth_n, depth_u, units FROM pool WHERE id=1", NULL, 0,
             &st) == 0) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            uint8_t a[32], b[32], c[32];
            if (col_blob_n(st, 0, a, 32) == 0 && col_blob_n(st, 1, b, 32) == 0 &&
                col_blob_n(st, 2, c, 32) == 0) {
                evm_u256_from_be(&out->depth_n, a);
                evm_u256_from_be(&out->depth_u, b);
                evm_u256_from_be(&out->units, c);
                ret = 0;
            }
        } else if (rc == SQLITE_DONE) {
            ret = 1;
        }
        sqlite3_finalize(st);
    }
    unlock(j);
    return ret;
}

static int pool_put_locked(amm_journal_t *j, const amm_pool_t *p) {
    uint8_t a[32], b[32], c[32];
    evm_u256_to_be(a, &p->depth_n);
    evm_u256_to_be(b, &p->depth_u);
    evm_u256_to_be(c, &p->units);
    return run(j, "INSERT INTO pool(id, depth_n, depth_u, units) "
                  "VALUES(1, ?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET "
                  "depth_n=excluded.depth_n, depth_u=excluded.depth_u, "
                  "units=excluded.units",
               (arg_t[]){AB(a, 32), AB(b, 32), AB(c, 32)}, 3, NULL);
}

int amm_journal_pool_put(amm_journal_t *j, const amm_pool_t *p) {
    if (!j || !p) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = pool_put_locked(j, p) == 0 ? AMM_J_OK : -1;
    return op_end(j, rc);
}

/* ── approval ───────────────────────────────────────────────────────── */

int amm_journal_approve(amm_journal_t *j, const amm_approve_t *a,
                        amm_swap_t *out) {
    if (!j || !a || !out) return -1;
    const char *incoming = a->incoming_id ? a->incoming_id : "";
    if ((a->dir != AMM_USDT_TO_NODUS && a->dir != AMM_NODUS_TO_USDT) ||
        !addr_ok(a->sender, a->dir, 1) || !addr_ok(a->dest, a->dir, 0) ||
        !tid_ok(incoming) || a->amount > (uint64_t)INT64_MAX ||
        a->minimum > (uint64_t)INT64_MAX || a->value_usdt > (uint64_t)INT64_MAX ||
        a->approved_at > (uint64_t)INT64_MAX || a->expiry > (uint64_t)INT64_MAX ||
        a->approved_tip == 0 || a->approved_tip > (uint64_t)INT64_MAX ||
        a->swap_max > (uint64_t)INT64_MAX || a->inflight_max > (uint64_t)INT64_MAX)
        return AMM_J_RANGE;

    if (op_begin(j) != 0) return -1;
    int rc = -1;
    int flag = 0;
    int64_t n = 0;
    amm_swap_t dup;

    if (flag_get_locked(j, "reversal_pause", &flag) != 0) goto done;
    if (a->swaps_paused_cfg || flag) { rc = AMM_J_PAUSED; goto done; }

    if (one_int(j, "SELECT COUNT(*) FROM swaps WHERE state='unknown'", NULL, 0,
                &n) != 0) goto done;
    if (n > 0) { rc = AMM_J_STOPPED; goto done; }

    int e = exists_q(j, "SELECT 1 FROM req_numbers WHERE sender=?1 AND req_no=?2",
                     (arg_t[]){AT(a->sender), AB(a->req_no, 32)}, 2);
    if (e < 0) goto done;
    if (e == 0) { rc = AMM_J_REQ_REUSED; goto done; }

    int d = swap_query(j, "sender=?1 AND amount=?2 AND state IN "
                          "('approved','paid_waiting_depth')",
                       (arg_t[]){AT(a->sender), AI(a->amount)}, 2, &dup);
    if (d < 0) goto done;
    if (d == 0) { *out = dup; rc = AMM_J_OPEN_DUP; goto done; }

    uint64_t sum = 0;
    if (inflight_sum_locked(j, a->held_keeps_room, &sum) != 0) goto done;
    int ar = amm_inflight_admit(a->value_usdt, sum, a->swap_max, a->inflight_max);
    if (ar == AMM_E_SWAP_LIMIT) { rc = AMM_J_SWAP_LIMIT; goto done; }
    if (ar == AMM_E_INFLIGHT)   { rc = AMM_J_INFLIGHT; goto done; }
    if (ar != AMM_OK) goto done;                    /* sum overflow: fault  */

    char id[33];
    hex_of(a->rand16, 16, id);
    if (run(j, "INSERT INTO swaps(id, dir, state, sender, dest, amount, "
               "minimum, value_usdt, approved_at, expiry, incoming_id, "
               "approved_tip) "
               "VALUES(?1, ?2, 'approved', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            (arg_t[]){AT(id), AI(a->dir), AT(a->sender), AT(a->dest),
                      AI(a->amount), AI(a->minimum), AI(a->value_usdt),
                      AI(a->approved_at), AI(a->expiry), AT(incoming),
                      AI(a->approved_tip)},
            11, NULL) != 0) goto done;
    int64_t seq = sqlite3_last_insert_rowid(j->db);
    if (run(j, "INSERT INTO req_numbers(sender, req_no, swap_seq) "
               "VALUES(?1, ?2, ?3)",
            (arg_t[]){AT(a->sender), AB(a->req_no, 32), AI(seq)}, 3,
            NULL) != 0) goto done;
    if (swap_query(j, "seq=?1", (arg_t[]){AI(seq)}, 1, out) != 0) goto done;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

/* ── transitions ────────────────────────────────────────────────────── */

int amm_journal_swap_transition(amm_journal_t *j, int64_t seq, const char *to,
                                const char *incoming_id,
                                const amm_pool_t *pool, const char *message) {
    if (!j || !to || !known_swap_state(to)) return AMM_J_ILLEGAL;
    if (incoming_id && !tid_ok(incoming_id)) return AMM_J_RANGE;
    if (message && strlen(message) >= AMM_MSG_MAX) return AMM_J_RANGE;
    /* "approved" and "reversed" are reached only through payment_gone */
    if (!strcmp(to, AMM_S_APPROVED) || !strcmp(to, AMM_S_REVERSED))
        return AMM_J_ILLEGAL;

    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_swap_t s;
    int g = swap_query(j, "seq=?1", (arg_t[]){AI(seq)}, 1, &s);
    if (g < 0) goto done;
    if (g == 1 || !legal_swap(s.state, to)) { rc = AMM_J_ILLEGAL; goto done; }

    const int given = incoming_id && *incoming_id;
    const char *inc = given ? incoming_id : s.incoming_id;
    if (!strcmp(to, AMM_S_PAID_WAITING) && !given) {
        rc = AMM_J_ILLEGAL;                 /* seen payment must be named    */
        goto done;
    }
    /* an incoming id, once set, is never changed: a later transition cannot
     * move a swap onto another swap's transfer (the carrier guard below
     * would otherwise be skipped by naming the id after paid_waiting_depth) */
    if (given && *s.incoming_id && strcmp(incoming_id, s.incoming_id) != 0) {
        rc = AMM_J_ILLEGAL;
        goto done;
    }
    /* payout_pending -> refund_pending (plan line 226: zero or below the
     * minimum after the Nodus fee -> refund) only while no attempt of this
     * swap is signed or submitted: an envelope that may still apply would pay
     * AND refund */
    if (!strcmp(s.state, AMM_S_PAYOUT_PENDING) && !strcmp(to, AMM_S_REFUND_PENDING)) {
        int64_t open_att = 0, open_eth = 0;
        if (one_int(j, "SELECT COUNT(*) FROM nodus_attempts WHERE swap_seq=?1 AND "
                       "state IN ('signed','submitted')",
                    (arg_t[]){AI(seq)}, 1, &open_att) != 0) goto done;
        /* the same for the USDT payout of a NODUS -> USDT swap (package 3) */
        if (one_int(j, "SELECT COUNT(*) FROM eth_attempts WHERE swap_seq=?1 AND "
                       "state IN ('signed','submitted')",
                    (arg_t[]){AI(seq)}, 1, &open_eth) != 0) goto done;
        if (open_att > 0 || open_eth > 0) { rc = AMM_J_ILLEGAL; goto done; }
    }
    if (given) {
        /* the carrier check runs on EVERY transition that names an id, not
         * only at paid_waiting_depth */
        int64_t others = 0;
        if (one_int(j, "SELECT COUNT(*) FROM swaps WHERE incoming_id=?1 AND "
                       "seq<>?2 AND state NOT IN ('approved','expired')",
                    (arg_t[]){AT(inc), AI(seq)}, 2, &others) != 0) goto done;
        if (others > 0) { rc = AMM_J_DUP_TRANSFER; goto done; }
    }
    if (!strcmp(to, AMM_S_COUNTED)) {
        if (!*inc) { rc = AMM_J_ILLEGAL; goto done; }
        int ch = 0;
        if (run(j, "INSERT OR IGNORE INTO paid_markers(transfer_id, swap_seq) "
                   "VALUES(?1, ?2)", (arg_t[]){AT(inc), AI(seq)}, 2, &ch) != 0)
            goto done;
        if (ch == 0) { rc = AMM_J_DUP_TRANSFER; goto done; }
    }
    if (pool && pool_put_locked(j, pool) != 0) goto done;
    if (run(j, "UPDATE swaps SET state=?1, incoming_id=?2, message=?3 WHERE seq=?4",
            (arg_t[]){AT(to), AT(inc), AT(message ? message : s.message), AI(seq)},
            4, NULL) != 0) goto done;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

/* ── blocks ─────────────────────────────────────────────────────────── */

int amm_journal_block_put(amm_journal_t *j, const amm_blk_t *b) {
    if (!j || !b || b->height > (uint64_t)INT64_MAX || b->ts > (uint64_t)INT64_MAX)
        return -1;
    if (op_begin(j) != 0) return -1;
    int rc = run(j, "INSERT OR REPLACE INTO blocks(height, hash, parent, ts) "
                    "VALUES(?1, ?2, ?3, ?4)",
                 (arg_t[]){AI(b->height), AB(b->hash, 32), AB(b->parent, 32),
                           AI(b->ts)}, 4, NULL) == 0 ? AMM_J_OK : -1;
    return op_end(j, rc);
}

int amm_journal_block_get(amm_journal_t *j, uint64_t height, amm_blk_t *out) {
    if (!j || !out || height > (uint64_t)INT64_MAX) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    if (prep(j, "SELECT height, hash, parent, ts FROM blocks WHERE height=?1",
             (arg_t[]){AI(height)}, 1, &st) == 0) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            amm_blk_t t;
            if (col_u64(st, 0, &t.height) == 0 && col_blob_n(st, 1, t.hash, 32) == 0 &&
                col_blob_n(st, 2, t.parent, 32) == 0 && col_u64(st, 3, &t.ts) == 0) {
                *out = t;
                ret = 0;
            }
        } else if (rc == SQLITE_DONE) {
            ret = 1;
        }
        sqlite3_finalize(st);
    }
    unlock(j);
    return ret;
}

int amm_journal_blocks_delete_from(amm_journal_t *j, uint64_t height) {
    if (!j || height > (uint64_t)INT64_MAX) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = run(j, "DELETE FROM blocks WHERE height>=?1", (arg_t[]){AI(height)}, 1,
                 NULL) == 0 ? AMM_J_OK : -1;
    return op_end(j, rc);
}

int amm_journal_blocks_prune_below(amm_journal_t *j, uint64_t height) {
    if (!j || height > (uint64_t)INT64_MAX) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = run(j, "DELETE FROM blocks WHERE height<?1", (arg_t[]){AI(height)}, 1,
                 NULL) == 0 ? AMM_J_OK : -1;
    return op_end(j, rc);
}

int amm_journal_block_after_ts(amm_journal_t *j, uint64_t ts,
                               uint64_t max_height, uint64_t *out_height) {
    if (!j || !out_height || ts > (uint64_t)INT64_MAX ||
        max_height > (uint64_t)INT64_MAX) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    if (prep(j, "SELECT height FROM blocks WHERE ts>?1 AND height<=?2 "
                "ORDER BY height LIMIT 1",
             (arg_t[]){AI(ts), AI(max_height)}, 2, &st) == 0) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) ret = (col_u64(st, 0, out_height) == 0) ? 0 : -1;
        else if (rc == SQLITE_DONE) ret = 1;
        sqlite3_finalize(st);
    }
    unlock(j);
    return ret;
}

/* ── records ────────────────────────────────────────────────────────── */

static int known_rec_state(const char *s) {
    static const char *all[] = {AMM_R_CANDIDATE, AMM_R_SEEN, AMM_R_DEEP,
                                AMM_R_HELD, AMM_R_DROPPED, AMM_R_REVERSED};
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (!strcmp(s, all[i])) return 1;
    return 0;
}

static int legal_rec(const char *from, const char *to) {
    if (!strcmp(from, to))      /* a same-state refresh */
        return strcmp(from, AMM_R_DROPPED) && strcmp(from, AMM_R_REVERSED);
    static const struct { const char *f, *t; } ok[] = {
        {AMM_R_CANDIDATE, AMM_R_SEEN}, {AMM_R_CANDIDATE, AMM_R_DROPPED},
        {AMM_R_SEEN, AMM_R_CANDIDATE}, {AMM_R_SEEN, AMM_R_DEEP},
        {AMM_R_SEEN, AMM_R_DROPPED},
        {AMM_R_DEEP, AMM_R_SEEN}, {AMM_R_DEEP, AMM_R_HELD},
        {AMM_R_DEEP, AMM_R_DROPPED},
        {AMM_R_HELD, AMM_R_DEEP}, {AMM_R_HELD, AMM_R_DROPPED},
        {AMM_R_DROPPED, AMM_R_CANDIDATE}, {AMM_R_DROPPED, AMM_R_SEEN},
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        if (!strcmp(from, ok[i].f) && !strcmp(to, ok[i].t)) return 1;
    return 0;
}

#define REC_COLS "tx, log_index, block_number, block_hash, block_ts, " \
                 "from_addr, to_addr, value, state"

static int load_rec_row(sqlite3_stmt *st, amm_rec_t *r) {
    memset(r, 0, sizeof(*r));
    int64_t li = 0;
    if (col_blob_n(st, 0, r->tx, 32) != 0 || col_i64(st, 1, &li) != 0 ||
        li < 0 || li > (int64_t)UINT32_MAX ||
        col_u64(st, 2, &r->block_number) != 0 ||
        col_blob_n(st, 3, r->block_hash, 32) != 0 ||
        col_u64(st, 4, &r->block_ts) != 0 ||
        col_blob_n(st, 5, r->from, 20) != 0 || col_blob_n(st, 6, r->to, 20) != 0 ||
        col_blob_n(st, 7, r->value, 32) != 0 ||
        col_text(st, 8, r->state, sizeof(r->state)) != 0 ||
        !known_rec_state(r->state)) {
        QGP_LOG_ERROR(LOG_TAG, "a record row does not read back as a valid record");
        memset(r, 0, sizeof(*r));
        return -1;
    }
    r->log_index = (uint32_t)li;
    return 0;
}

static int rec_get_locked(amm_journal_t *j, const uint8_t tx[32],
                          uint32_t log_index, amm_rec_t *out) {
    sqlite3_stmt *st;
    if (prep(j, "SELECT " REC_COLS " FROM eth_records WHERE tx=?1 AND log_index=?2",
             (arg_t[]){AB(tx, 32), AI(log_index)}, 2, &st) != 0) return -1;
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) {
        amm_rec_t t;
        if (load_rec_row(st, &t) != 0) ret = -1;
        else { if (out) *out = t; ret = 0; }
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        ret = -1;
    }
    sqlite3_finalize(st);
    return ret;
}

int amm_journal_rec_get(amm_journal_t *j, const uint8_t tx[32],
                        uint32_t log_index, amm_rec_t *out) {
    if (!j || !tx || !out) return -1;
    lock(j);
    int r = rec_get_locked(j, tx, log_index, out);
    unlock(j);
    return r;
}

/* One live record per transaction: a record that becomes live (candidate or
 * seen) while another live record of the same transaction exists is refused,
 * except that a quorum (seen) record displaces candidates of that
 * transaction. Lock and operation held. @return 0 ok / AMM_J_ILLEGAL / -1. */
static int rec_single_live(amm_journal_t *j, const amm_rec_t *r) {
    if (strcmp(r->state, AMM_R_CANDIDATE) != 0 && strcmp(r->state, AMM_R_SEEN) != 0)
        return 0;
    int64_t others = 0, non_cand = 0;
    if (one_int(j, "SELECT COUNT(*) FROM eth_records WHERE tx=?1 AND log_index<>?2 "
                   "AND state IN ('candidate','seen','deep','held')",
                (arg_t[]){AB(r->tx, 32), AI(r->log_index)}, 2, &others) != 0) return -1;
    if (others == 0) return 0;
    if (!strcmp(r->state, AMM_R_CANDIDATE)) return AMM_J_ILLEGAL;
    if (one_int(j, "SELECT COUNT(*) FROM eth_records WHERE tx=?1 AND log_index<>?2 "
                   "AND state IN ('seen','deep','held')",
                (arg_t[]){AB(r->tx, 32), AI(r->log_index)}, 2, &non_cand) != 0) return -1;
    if (non_cand > 0) return AMM_J_ILLEGAL;
    if (run(j, "UPDATE eth_records SET state='dropped' WHERE tx=?1 AND log_index<>?2 "
               "AND state='candidate'",
            (arg_t[]){AB(r->tx, 32), AI(r->log_index)}, 2, NULL) != 0) return -1;
    return 0;
}

int amm_journal_rec_put(amm_journal_t *j, const amm_rec_t *r) {
    if (!j || !r || !known_rec_state(r->state) ||
        r->block_number > (uint64_t)INT64_MAX || r->block_ts > (uint64_t)INT64_MAX)
        return -1;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_rec_t cur;
    int g = rec_get_locked(j, r->tx, r->log_index, &cur);
    if (g < 0) goto done;
    /* becoming live: a new row, or a dropped one revived */
    if (g == 1 || !strcmp(cur.state, AMM_R_DROPPED)) {
        int sl = rec_single_live(j, r);
        /* AMM_J_ILLEGAL is -2, a refusal; only -1 is a database fault (rc
         * stays -1 for it) */
        if (sl == -1) goto done;
        if (sl != 0) { rc = sl; goto done; }
    }
    if (g == 0) {
        if (!legal_rec(cur.state, r->state)) { rc = AMM_J_ILLEGAL; goto done; }
        if (run(j, "UPDATE eth_records SET block_number=?1, block_hash=?2, "
                   "block_ts=?3, from_addr=?4, to_addr=?5, value=?6, state=?7 "
                   "WHERE tx=?8 AND log_index=?9",
                (arg_t[]){AI(r->block_number), AB(r->block_hash, 32),
                          AI(r->block_ts), AB(r->from, 20), AB(r->to, 20),
                          AB(r->value, 32), AT(r->state), AB(r->tx, 32),
                          AI(r->log_index)}, 9, NULL) != 0) goto done;
    } else {
        /* a new record starts as candidate or seen (the watcher's first
         * sight); deep/held/dropped/reversed only by a transition */
        if (strcmp(r->state, AMM_R_CANDIDATE) && strcmp(r->state, AMM_R_SEEN)) {
            rc = AMM_J_ILLEGAL;
            goto done;
        }
        if (run(j, "INSERT INTO eth_records(tx, log_index, block_number, "
                   "block_hash, block_ts, from_addr, to_addr, value, state) "
                   "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                (arg_t[]){AB(r->tx, 32), AI(r->log_index), AI(r->block_number),
                          AB(r->block_hash, 32), AI(r->block_ts), AB(r->from, 20),
                          AB(r->to, 20), AB(r->value, 32), AT(r->state)}, 9,
                NULL) != 0) goto done;
    }
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

int amm_journal_rec_list(amm_journal_t *j, uint64_t min_block,
                         const char *state, amm_rec_t *out, int cap, int *n) {
    if (!j || !out || !n || cap < 0 || min_block > (uint64_t)INT64_MAX ||
        (state && !known_rec_state(state))) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    int pr;
    if (state)
        pr = prep(j, "SELECT " REC_COLS " FROM eth_records WHERE block_number>=?1 "
                     "AND state=?2 ORDER BY block_number, tx, log_index",
                  (arg_t[]){AI(min_block), AT(state)}, 2, &st);
    else
        pr = prep(j, "SELECT " REC_COLS " FROM eth_records WHERE block_number>=?1 "
                     "AND state IN ('candidate','seen','deep','held') "
                     "ORDER BY block_number, tx, log_index",
                  (arg_t[]){AI(min_block)}, 1, &st);
    if (pr == 0) {
        int cnt = 0, rc;
        ret = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (cnt >= cap || load_rec_row(st, &out[cnt]) != 0) { ret = -1; break; }
            cnt++;
        }
        if (ret == 0 && rc != SQLITE_DONE) ret = -1;
        sqlite3_finalize(st);
        if (ret == 0) *n = cnt;
    }
    unlock(j);
    return ret;
}

int amm_journal_rec_other_live(amm_journal_t *j, const uint8_t tx[32],
                               uint32_t log_index) {
    if (!j || !tx) return -1;
    lock(j);
    int r = exists_q(j, "SELECT 1 FROM eth_records WHERE tx=?1 AND log_index<>?2 "
                        "AND state IN ('candidate','seen','deep','held')",
                     (arg_t[]){AB(tx, 32), AI(log_index)}, 2);
    unlock(j);
    return r;
}

int amm_journal_rec_candidate_exists(amm_journal_t *j, const uint8_t from[20],
                                     const uint8_t value[32],
                                     uint64_t approved_tip,
                                     uint64_t max_block_ts) {
    if (!j || !from || !value || approved_tip > (uint64_t)INT64_MAX ||
        max_block_ts > (uint64_t)INT64_MAX) return -1;
    lock(j);
    int r = exists_q(j, "SELECT 1 FROM eth_records WHERE state='candidate' AND "
                        "from_addr=?1 AND value=?2 AND block_number>?3 AND "
                        "(block_ts=0 OR block_ts<=?4)",
                     (arg_t[]){AB(from, 20), AB(value, 32), AI(approved_tip),
                               AI(max_block_ts)}, 4);
    unlock(j);
    return r;
}

int amm_journal_payment_gone(amm_journal_t *j, const uint8_t tx[32],
                             uint32_t log_index, amm_gone_t *outcome) {
    if (!j || !tx || !outcome) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_rec_t r;
    int g = rec_get_locked(j, tx, log_index, &r);
    if (g < 0) goto done;
    if (g == 1 || !strcmp(r.state, AMM_R_DROPPED) || !strcmp(r.state, AMM_R_REVERSED)) {
        rc = AMM_J_ILLEGAL;
        goto done;
    }
    char key[AMM_TID_MAX];
    amm_journal_eth_key(tx, key, sizeof(key));
    /* EVERY swap carrying the key, each by its own state (one statement per
     * outcome, so no swap is skipped and nothing is cut at a bound) */
    int reversed = 0, ch = 0;
    if (run(j, "UPDATE swaps SET state='reversed' WHERE incoming_id=?1 AND "
               "state IN ('counted','payout_pending','paid','refund_pending',"
               "'refunded','held','unknown')",
            (arg_t[]){AT(key)}, 1, &ch) != 0) goto done;
    if (ch > 0) {
        reversed = 1;
        if (run(j, "INSERT INTO flags(name, value) VALUES('reversal_pause', 1) "
                   "ON CONFLICT(name) DO UPDATE SET value=1", NULL, 0,
                NULL) != 0) goto done;
    }
    if (run(j, "UPDATE swaps SET state='approved', incoming_id='' "
               "WHERE incoming_id=?1 AND state='paid_waiting_depth'",
            (arg_t[]){AT(key)}, 1, NULL) != 0) goto done;
    if (run(j, "UPDATE eth_records SET state=?1 WHERE tx=?2 AND log_index=?3",
            (arg_t[]){AT(reversed ? AMM_R_REVERSED : AMM_R_DROPPED), AB(tx, 32),
                      AI(log_index)}, 3, NULL) != 0) goto done;
    *outcome = reversed ? AMM_GONE_REVERSED : AMM_GONE_DROPPED;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

/* ── Nodus incoming rows ────────────────────────────────────────────── */

#define NROW_COLS "height, item, seq, wire, peer, amount, ts, state, swap_seq, reason"

static int load_nrow(sqlite3_stmt *st, amm_nrow_t *r) {
    memset(r, 0, sizeof(*r));
    int64_t item = 0, seq = 0;
    if (col_u64(st, 0, &r->height) != 0 || col_i64(st, 1, &item) != 0 ||
        col_i64(st, 2, &seq) != 0 || item < 0 || item > (int64_t)UINT32_MAX ||
        seq < 0 || seq > (int64_t)UINT32_MAX ||
        col_blob_n(st, 3, r->wire, 64) != 0 ||
        col_text(st, 4, r->peer, sizeof(r->peer)) != 0 ||
        col_u64(st, 5, &r->amount) != 0 || col_u64(st, 6, &r->ts) != 0 ||
        col_text(st, 7, r->state, sizeof(r->state)) != 0 ||
        col_i64(st, 8, &r->swap_seq) != 0 || r->swap_seq < 0 ||
        col_text(st, 9, r->reason, sizeof(r->reason)) != 0 ||
        !hex_lower_n(r->peer, AMM_ADDR_NODUS) ||
        (strcmp(r->state, AMM_NR_HELD) && strcmp(r->state, AMM_NR_COUNTED))) {
        QGP_LOG_ERROR(LOG_TAG, "a Nodus row does not read back as a valid row");
        memset(r, 0, sizeof(*r));
        return -1;
    }
    r->item = (uint32_t)item;
    r->seq = (uint32_t)seq;
    return 0;
}

int amm_journal_nrow_put(amm_journal_t *j, const amm_nrow_t *r) {
    if (!j || !r) return -1;
    if (r->height > (uint64_t)INT64_MAX || r->amount > (uint64_t)INT64_MAX ||
        r->ts > (uint64_t)INT64_MAX || r->swap_seq < 0 ||
        !hex_lower_n(r->peer, AMM_ADDR_NODUS) ||
        (strcmp(r->state, AMM_NR_HELD) && strcmp(r->state, AMM_NR_COUNTED)) ||
        strlen(r->reason) >= AMM_MSG_MAX) return AMM_J_RANGE;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    int e = exists_q(j, "SELECT 1 FROM nodus_rows WHERE height=?1 AND item=?2 "
                        "AND seq=?3",
                     (arg_t[]){AI(r->height), AI(r->item), AI(r->seq)}, 3);
    if (e < 0) goto done;
    if (e == 0) { rc = AMM_J_ILLEGAL; goto done; }
    if (run(j, "INSERT INTO nodus_rows(height, item, seq, wire, peer, amount, "
               "ts, state, swap_seq, reason) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            (arg_t[]){AI(r->height), AI(r->item), AI(r->seq), AB(r->wire, 64),
                      AT(r->peer), AI(r->amount), AI(r->ts), AT(r->state),
                      AI(r->swap_seq), AT(r->reason)}, 10, NULL) != 0) goto done;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

static int nrow_one(amm_journal_t *j, const char *where, const arg_t *args,
                    int nargs, amm_nrow_t *out) {
    char sql[320];
    snprintf(sql, sizeof(sql), "SELECT " NROW_COLS " FROM nodus_rows WHERE %s "
             "ORDER BY height, item, seq LIMIT 1", where);
    sqlite3_stmt *st;
    if (prep(j, sql, args, nargs, &st) != 0) return -1;
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) {
        amm_nrow_t t;
        if (load_nrow(st, &t) != 0) ret = -1;
        else { if (out) *out = t; ret = 0; }
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        ret = -1;
    }
    sqlite3_finalize(st);
    return ret;
}

int amm_journal_nrow_get(amm_journal_t *j, uint64_t height, uint32_t item,
                         uint32_t seq, amm_nrow_t *out) {
    if (!j || !out || height > (uint64_t)INT64_MAX) return -1;
    lock(j);
    int r = nrow_one(j, "height=?1 AND item=?2 AND seq=?3",
                     (arg_t[]){AI(height), AI(item), AI(seq)}, 3, out);
    unlock(j);
    return r;
}

int amm_journal_nrow_by_wire(amm_journal_t *j, const uint8_t wire[64],
                             amm_nrow_t *out) {
    if (!j || !wire || !out) return -1;
    lock(j);
    int r = nrow_one(j, "wire=?1", (arg_t[]){AB(wire, 64)}, 1, out);
    unlock(j);
    return r;
}

int amm_journal_nrow_list(amm_journal_t *j, const char *state, amm_nrow_t *out,
                          int cap, int *n) {
    if (!j || !out || !n || cap < 0) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    int pr;
    if (state)
        pr = prep(j, "SELECT " NROW_COLS " FROM nodus_rows WHERE state=?1 "
                     "ORDER BY height, item, seq", (arg_t[]){AT(state)}, 1, &st);
    else
        pr = prep(j, "SELECT " NROW_COLS " FROM nodus_rows "
                     "ORDER BY height, item, seq", NULL, 0, &st);
    if (pr == 0) {
        int cnt = 0, rc;
        ret = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (cnt >= cap || load_nrow(st, &out[cnt]) != 0) { ret = -1; break; }
            cnt++;
        }
        if (ret == 0 && rc != SQLITE_DONE) ret = -1;
        sqlite3_finalize(st);
        if (ret == 0) *n = cnt;
    }
    unlock(j);
    return ret;
}

/* ── NODUS payout attempts ──────────────────────────────────────────── */

#define ATT_ENV_MAX (256u * 1024u)    /* a built envelope is a few KiB      */

void amm_attempt_free(amm_attempt_t *a) {
    if (!a) return;
    free(a->env);
    a->env = NULL;
    a->env_len = 0;
}

static int known_attempt_state(const char *s) {
    return !strcmp(s, AMM_A_SIGNED) || !strcmp(s, AMM_A_SUBMITTED) ||
           !strcmp(s, AMM_A_EXPIRED) || !strcmp(s, AMM_A_CONFIRMED);
}

#define ATT_COLS "swap_seq, n, gross, net, fee, dest, env, wire_id, intent_id, " \
                 "inputs, n_in, build_tip, expiry, scan_next, last_submit_tip, state"

static int load_attempt(sqlite3_stmt *st, amm_attempt_t *a) {
    memset(a, 0, sizeof(*a));
    int64_t n = 0, n_in = 0;
    uint8_t *env = NULL;
    int ok = 0;
    if (col_i64(st, 0, &a->swap_seq) == 0 && col_i64(st, 1, &n) == 0 && n >= 1 &&
        n <= INT32_MAX && col_u64(st, 2, &a->gross) == 0 &&
        col_u64(st, 3, &a->net) == 0 && col_u64(st, 4, &a->fee) == 0 &&
        col_text(st, 5, a->dest, sizeof(a->dest)) == 0 &&
        sqlite3_column_type(st, 6) == SQLITE_BLOB &&
        col_blob_n(st, 7, a->wire_id, 64) == 0 &&
        col_blob_n(st, 8, a->intent_id, 64) == 0 &&
        col_i64(st, 10, &n_in) == 0 && n_in >= 1 && n_in <= AMM_MAX_INPUTS &&
        sqlite3_column_type(st, 9) == SQLITE_BLOB &&
        sqlite3_column_bytes(st, 9) == (int)(n_in * 64) &&
        col_u64(st, 11, &a->build_tip) == 0 && col_u64(st, 12, &a->expiry) == 0 &&
        col_u64(st, 13, &a->scan_next) == 0 &&
        col_u64(st, 14, &a->last_submit_tip) == 0 &&
        col_text(st, 15, a->state, sizeof(a->state)) == 0 &&
        known_attempt_state(a->state) && hex_lower_n(a->dest, AMM_ADDR_NODUS)) {
        int el = sqlite3_column_bytes(st, 6);
        const void *ep = sqlite3_column_blob(st, 6);
        const void *ip = sqlite3_column_blob(st, 9);
        if (el > 0 && (size_t)el <= ATT_ENV_MAX && ep && ip &&
            (env = malloc((size_t)el)) != NULL) {
            memcpy(env, ep, (size_t)el);
            memcpy(a->inputs, ip, (size_t)n_in * 64);
            a->env = env;
            a->env_len = (size_t)el;
            a->n = (int)n;
            a->n_in = (int)n_in;
            ok = 1;
        }
    }
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "an attempt row does not read back as a valid "
                      "attempt");
        free(env);
        memset(a, 0, sizeof(*a));
        return -1;
    }
    return 0;
}

static int attempt_latest_locked(amm_journal_t *j, int64_t swap_seq,
                                 amm_attempt_t *out) {
    sqlite3_stmt *st;
    if (prep(j, "SELECT " ATT_COLS " FROM nodus_attempts WHERE swap_seq=?1 "
                "ORDER BY n DESC LIMIT 1", (arg_t[]){AI(swap_seq)}, 1, &st) != 0)
        return -1;
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) ret = load_attempt(st, out) == 0 ? 0 : -1;
    else if (rc == SQLITE_DONE) ret = 1;
    else ret = -1;
    sqlite3_finalize(st);
    return ret;
}

int amm_journal_swap_head_payout(amm_journal_t *j, amm_swap_t *out) {
    if (!j || !out) return -1;
    lock(j);
    /* only a swap that owes a NODUS payout: the payout of a USDT -> NODUS swap
     * or the refund of a NODUS -> USDT swap (the other two are USDT payouts) */
    int r = swap_query(j, "(dir=0 AND state='payout_pending') OR "
                          "(dir=1 AND state='refund_pending')", NULL, 0, out);
    unlock(j);
    return r;
}

int amm_journal_attempt_latest(amm_journal_t *j, int64_t swap_seq,
                               amm_attempt_t *out) {
    if (!j || !out) return -1;
    lock(j);
    int r = attempt_latest_locked(j, swap_seq, out);
    unlock(j);
    return r;
}

int amm_journal_attempt_sign(amm_journal_t *j, amm_attempt_t *a) {
    if (!j || !a || !a->env) return -1;
    if (a->env_len == 0 || a->env_len > ATT_ENV_MAX || a->net == 0 ||
        a->fee > UINT64_MAX - a->net || a->net + a->fee != a->gross ||
        a->gross > (uint64_t)INT64_MAX || a->n_in < 1 || a->n_in > AMM_MAX_INPUTS ||
        a->build_tip > (uint64_t)INT64_MAX || a->expiry > (uint64_t)INT64_MAX ||
        a->scan_next > (uint64_t)INT64_MAX ||
        a->last_submit_tip > (uint64_t)INT64_MAX ||
        !hex_lower_n(a->dest, AMM_ADDR_NODUS)) return AMM_J_RANGE;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_swap_t s;
    int g = swap_query(j, "seq=?1", (arg_t[]){AI(a->swap_seq)}, 1, &s);
    if (g < 0) goto done;
    /* the one place a NODUS payout of this swap can be owed: the payout of a
     * USDT -> NODUS swap to its destination, the refund of a NODUS -> USDT
     * swap to its sender (plan section 11, "the user's native address") */
    if (g == 1) { rc = AMM_J_ILLEGAL; goto done; }
    int owed = (s.dir == AMM_USDT_TO_NODUS && !strcmp(s.state, AMM_S_PAYOUT_PENDING)) ||
               (s.dir == AMM_NODUS_TO_USDT && !strcmp(s.state, AMM_S_REFUND_PENDING));
    if (!owed) { rc = AMM_J_ILLEGAL; goto done; }
    if (strcmp(a->dest, s.dir == AMM_USDT_TO_NODUS ? s.dest : s.sender) != 0) {
        rc = AMM_J_ILLEGAL;
        goto done;
    }
    /* ONE PAYOUT IN FLIGHT (the faucet's head claim; there is no coin
     * reservation table): another swap's open attempt would pick the same
     * coins, and the two envelopes could not both apply */
    int64_t others = 0;
    if (one_int(j, "SELECT COUNT(*) FROM nodus_attempts WHERE swap_seq<>?1 AND "
                   "state IN ('signed','submitted')",
                (arg_t[]){AI(a->swap_seq)}, 1, &others) != 0) goto done;
    if (others > 0) { rc = AMM_J_ILLEGAL; goto done; }
    amm_attempt_t prev;
    int p = attempt_latest_locked(j, a->swap_seq, &prev);
    if (p < 0) goto done;
    int next_n = 1;
    if (p == 0) {
        int expired = !strcmp(prev.state, AMM_A_EXPIRED);
        next_n = prev.n + 1;
        amm_attempt_free(&prev);
        if (!expired) { rc = AMM_J_ILLEGAL; goto done; }
    }
    uint8_t inb[AMM_MAX_INPUTS * 64];
    for (int i = 0; i < a->n_in; i++) memcpy(inb + (size_t)i * 64, a->inputs[i], 64);
    if (run(j, "INSERT INTO nodus_attempts(swap_seq, n, gross, net, fee, dest, "
               "env, wire_id, intent_id, inputs, n_in, build_tip, expiry, "
               "scan_next, last_submit_tip, state) "
               "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,'signed')",
            (arg_t[]){AI(a->swap_seq), AI(next_n), AI(a->gross), AI(a->net),
                      AI(a->fee), AT(a->dest), AB(a->env, (int)a->env_len),
                      AB(a->wire_id, 64), AB(a->intent_id, 64),
                      AB(inb, a->n_in * 64), AI(a->n_in), AI(a->build_tip),
                      AI(a->expiry), AI(a->scan_next), AI(a->last_submit_tip)},
            15, NULL) != 0) goto done;
    a->n = next_n;
    snprintf(a->state, sizeof(a->state), "%s", AMM_A_SIGNED);
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

int amm_journal_attempt_submitted(amm_journal_t *j, int64_t swap_seq,
                                  uint64_t tip) {
    if (!j || tip > (uint64_t)INT64_MAX) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_attempt_t a;
    int g = attempt_latest_locked(j, swap_seq, &a);
    if (g < 0) goto done;
    if (g == 1) { rc = AMM_J_ILLEGAL; goto done; }
    int ok = !strcmp(a.state, AMM_A_SIGNED) || !strcmp(a.state, AMM_A_SUBMITTED);
    int n = a.n;
    amm_attempt_free(&a);
    if (!ok) { rc = AMM_J_ILLEGAL; goto done; }
    if (run(j, "UPDATE nodus_attempts SET state='submitted', last_submit_tip=?1 "
               "WHERE swap_seq=?2 AND n=?3",
            (arg_t[]){AI(tip), AI(swap_seq), AI(n)}, 3, NULL) != 0) goto done;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

int amm_journal_attempt_scanned(amm_journal_t *j, int64_t swap_seq,
                                uint64_t scan_next) {
    if (!j || scan_next > (uint64_t)INT64_MAX) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_attempt_t a;
    int g = attempt_latest_locked(j, swap_seq, &a);
    if (g < 0) goto done;
    if (g == 1) { rc = AMM_J_ILLEGAL; goto done; }
    int n = a.n;
    int ok = scan_next > a.scan_next;
    amm_attempt_free(&a);
    if (!ok) { rc = AMM_J_ILLEGAL; goto done; }
    if (run(j, "UPDATE nodus_attempts SET scan_next=?1 WHERE swap_seq=?2 AND n=?3",
            (arg_t[]){AI(scan_next), AI(swap_seq), AI(n)}, 3, NULL) != 0) goto done;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

int amm_journal_attempt_finish(amm_journal_t *j, int64_t swap_seq,
                               const char *state) {
    if (!j || !state) return -1;
    if (strcmp(state, AMM_A_CONFIRMED) && strcmp(state, AMM_A_EXPIRED))
        return AMM_J_ILLEGAL;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_attempt_t a;
    int g = attempt_latest_locked(j, swap_seq, &a);
    if (g < 0) goto done;
    if (g == 1) { rc = AMM_J_ILLEGAL; goto done; }
    int n = a.n;
    int ok = !strcmp(a.state, AMM_A_SIGNED) || !strcmp(a.state, AMM_A_SUBMITTED);
    amm_attempt_free(&a);
    if (!ok) { rc = AMM_J_ILLEGAL; goto done; }
    if (run(j, "UPDATE nodus_attempts SET state=?1 WHERE swap_seq=?2 AND n=?3",
            (arg_t[]){AT(state), AI(swap_seq), AI(n)}, 3, NULL) != 0) goto done;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

/* ── USDT payout attempts (package 3; plan sections 10, 17) ────────────── */

#define EATT_RAW_MAX 4096u            /* a payout is ~200 bytes             */
#define EATT_COLS "swap_seq, n, chain_id, nonce, hash, raw, recipient, gross, " \
                  "net, fee, gas_limit, max_fee, max_priority, " \
                  "last_submit_tip, state"

void amm_eattempt_free(amm_eattempt_t *a) {
    if (!a) return;
    free(a->raw);
    a->raw = NULL;
    a->raw_len = 0;
}

static int known_eattempt_state(const char *s) {
    return !strcmp(s, AMM_EA_SIGNED) || !strcmp(s, AMM_EA_SUBMITTED) ||
           !strcmp(s, AMM_EA_CONFIRMED) || !strcmp(s, AMM_EA_FAILED) ||
           !strcmp(s, AMM_EA_ORPHANED) || !strcmp(s, AMM_EA_UNKNOWN);
}

static int load_eattempt(sqlite3_stmt *st, amm_eattempt_t *a) {
    memset(a, 0, sizeof(*a));
    int64_t n = 0;
    uint8_t *raw = NULL;
    int ok = 0;
    if (col_i64(st, 0, &a->swap_seq) == 0 && col_i64(st, 1, &n) == 0 && n >= 1 &&
        n <= INT32_MAX && col_u64(st, 2, &a->chain_id) == 0 && a->chain_id >= 1 &&
        col_u64(st, 3, &a->nonce) == 0 &&
        col_blob_n(st, 4, a->hash, 32) == 0 &&
        sqlite3_column_type(st, 5) == SQLITE_BLOB &&
        col_blob_n(st, 6, a->recipient, 20) == 0 &&
        col_u64(st, 7, &a->gross) == 0 && col_u64(st, 8, &a->net) == 0 &&
        col_u64(st, 9, &a->fee) == 0 && col_u64(st, 10, &a->gas_limit) == 0 &&
        col_u64(st, 11, &a->max_fee_per_gas) == 0 &&
        col_u64(st, 12, &a->max_priority_fee_per_gas) == 0 &&
        col_u64(st, 13, &a->last_submit_tip) == 0 &&
        col_text(st, 14, a->state, sizeof(a->state)) == 0 &&
        known_eattempt_state(a->state)) {
        int rl = sqlite3_column_bytes(st, 5);
        const void *rp = sqlite3_column_blob(st, 5);
        uint8_t h[32];
        if (rl > 0 && (size_t)rl <= EATT_RAW_MAX && rp &&
            (raw = malloc((size_t)rl)) != NULL) {
            memcpy(raw, rp, (size_t)rl);
            /* what was stored must still be what was signed */
            if (keccak256(raw, (size_t)rl, h) == 0 && !memcmp(h, a->hash, 32)) {
                a->raw = raw;
                a->raw_len = (size_t)rl;
                a->n = (int)n;
                ok = 1;
            }
        }
    }
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "a USDT attempt row does not read back as a "
                      "valid attempt");
        free(raw);
        memset(a, 0, sizeof(*a));
        return -1;
    }
    return 0;
}

static int eattempt_latest_locked(amm_journal_t *j, int64_t swap_seq,
                                  amm_eattempt_t *out) {
    sqlite3_stmt *st;
    if (prep(j, "SELECT " EATT_COLS " FROM eth_attempts WHERE swap_seq=?1 "
                "ORDER BY n DESC LIMIT 1", (arg_t[]){AI(swap_seq)}, 1, &st) != 0)
        return -1;
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) ret = load_eattempt(st, out) == 0 ? 0 : -1;
    else if (rc == SQLITE_DONE) ret = 1;
    else ret = -1;
    sqlite3_finalize(st);
    return ret;
}

/* 40 lowercase hex digits into 20 bytes. */
static int unhex20(const char *s, uint8_t out[20]) {
    if (!hex_lower_n(s, AMM_ADDR_ETH)) return -1;
    for (int i = 0; i < 20; i++) {
        int a = s[2 * i], b = s[2 * i + 1];
        a = a <= '9' ? a - '0' : a - 'a' + 10;
        b = b <= '9' ? b - '0' : b - 'a' + 10;
        out[i] = (uint8_t)(a * 16 + b);
    }
    return 0;
}

int amm_journal_swap_list_usdt_owed(amm_journal_t *j, amm_swap_t *out, int cap,
                                    int *n) {
    if (!j || !out || !n || cap < 1) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1, cnt = 0;
    if (prep(j, "SELECT " SWAP_COLS " FROM swaps WHERE (dir=1 AND "
                "state='payout_pending') OR (dir=0 AND state='refund_pending') "
                "ORDER BY seq", NULL, 0, &st) == 0) {
        int rc;
        ret = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (cnt >= cap || load_swap_row(st, &out[cnt]) != 0) { ret = -1; break; }
            cnt++;
        }
        if (ret == 0 && rc != SQLITE_DONE) ret = -1;
        sqlite3_finalize(st);
    }
    unlock(j);
    if (ret == 0) *n = cnt;
    return ret;
}

int amm_journal_eth_next_nonce(amm_journal_t *j, uint64_t chain_id,
                               uint64_t *next) {
    if (!j || !next || chain_id < 1 || chain_id > (uint64_t)INT64_MAX) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    if (prep(j, "SELECT MAX(nonce) FROM eth_attempts WHERE chain_id=?1",
             (arg_t[]){AI(chain_id)}, 1, &st) == 0) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (sqlite3_column_type(st, 0) == SQLITE_NULL) {
                ret = 1;
            } else {
                uint64_t m;
                if (col_u64(st, 0, &m) == 0 && m < (uint64_t)INT64_MAX) {
                    *next = m + 1;
                    ret = 0;
                }
            }
        }
        sqlite3_finalize(st);
    }
    unlock(j);
    return ret;
}

int amm_journal_eth_attempt_latest(amm_journal_t *j, int64_t swap_seq,
                                   amm_eattempt_t *out) {
    if (!j || !out) return -1;
    lock(j);
    int r = eattempt_latest_locked(j, swap_seq, out);
    unlock(j);
    return r;
}

int amm_journal_eth_attempt_by_hash(amm_journal_t *j, const uint8_t hash[32],
                                    amm_eattempt_t *out) {
    if (!j || !hash || !out) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    if (prep(j, "SELECT " EATT_COLS " FROM eth_attempts WHERE hash=?1",
             (arg_t[]){AB(hash, 32)}, 1, &st) == 0) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) ret = load_eattempt(st, out) == 0 ? 0 : -1;
        else if (rc == SQLITE_DONE) ret = 1;
        sqlite3_finalize(st);
    }
    unlock(j);
    return ret;
}

int amm_journal_eth_attempt_sign(amm_journal_t *j, amm_eattempt_t *a) {
    if (!j || !a || !a->raw) return -1;
    uint8_t h[32];
    if (a->raw_len == 0 || a->raw_len > EATT_RAW_MAX || a->net == 0 ||
        a->fee > UINT64_MAX - a->net || a->net + a->fee != a->gross ||
        a->gross > (uint64_t)INT64_MAX || a->chain_id < 1 ||
        a->chain_id > (uint64_t)INT64_MAX || a->nonce > (uint64_t)INT64_MAX ||
        a->gas_limit == 0 || a->gas_limit > (uint64_t)INT64_MAX ||
        a->max_fee_per_gas > (uint64_t)INT64_MAX ||
        a->max_priority_fee_per_gas > (uint64_t)INT64_MAX ||
        a->last_submit_tip > (uint64_t)INT64_MAX) return AMM_J_RANGE;
    /* the stored hash must be the hash of the stored bytes */
    if (keccak256(a->raw, a->raw_len, h) != 0 || memcmp(h, a->hash, 32) != 0)
        return AMM_J_RANGE;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_swap_t s;
    int g = swap_query(j, "seq=?1", (arg_t[]){AI(a->swap_seq)}, 1, &s);
    if (g < 0) goto done;
    if (g == 1) { rc = AMM_J_ILLEGAL; goto done; }
    /* the one place a USDT payout of this swap can be owed: the payout of a
     * NODUS -> USDT swap to its destination, the refund of a USDT -> NODUS
     * swap to its sender (the Ethereum address of the request) */
    int owed = (s.dir == AMM_NODUS_TO_USDT && !strcmp(s.state, AMM_S_PAYOUT_PENDING)) ||
               (s.dir == AMM_USDT_TO_NODUS && !strcmp(s.state, AMM_S_REFUND_PENDING));
    if (!owed) { rc = AMM_J_ILLEGAL; goto done; }
    uint8_t want[20];
    if (unhex20(s.dir == AMM_NODUS_TO_USDT ? s.dest : s.sender, want) != 0 ||
        memcmp(want, a->recipient, 20) != 0) { rc = AMM_J_ILLEGAL; goto done; }
    amm_eattempt_t prev;
    int p = eattempt_latest_locked(j, a->swap_seq, &prev);
    if (p < 0) goto done;
    if (p == 0) {                 /* one attempt per swap: no automatic retry */
        amm_eattempt_free(&prev);
        rc = AMM_J_ILLEGAL;
        goto done;
    }
    /* UNIQUE(hash) and UNIQUE(chain_id, nonce) are the database's: a
     * violation is a refusal, not a fault */
    sqlite3_stmt *st;
    if (prep(j, "INSERT INTO eth_attempts(swap_seq, n, chain_id, nonce, hash, "
                "raw, recipient, gross, net, fee, gas_limit, max_fee, "
                "max_priority, last_submit_tip, state) "
                "VALUES(?1,1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'signed')",
             (arg_t[]){AI(a->swap_seq), AI(a->chain_id), AI(a->nonce),
                       AB(a->hash, 32), AB(a->raw, (int)a->raw_len),
                       AB(a->recipient, 20), AI(a->gross), AI(a->net),
                       AI(a->fee), AI(a->gas_limit), AI(a->max_fee_per_gas),
                       AI(a->max_priority_fee_per_gas), AI(a->last_submit_tip)},
             13, &st) != 0) goto done;
    int sr = sqlite3_step(st);
    sqlite3_finalize(st);
    if (sr == SQLITE_CONSTRAINT) { rc = AMM_J_ILLEGAL; goto done; }
    if (sr != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "step failed (%d): %s", sr, sqlite3_errmsg(j->db));
        goto done;
    }
    a->n = 1;
    snprintf(a->state, sizeof(a->state), "%s", AMM_EA_SIGNED);
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

int amm_journal_eth_attempt_submitted(amm_journal_t *j, int64_t swap_seq,
                                      uint64_t tip) {
    if (!j || tip > (uint64_t)INT64_MAX) return -1;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_eattempt_t a;
    int g = eattempt_latest_locked(j, swap_seq, &a);
    if (g < 0) goto done;
    if (g == 1) { rc = AMM_J_ILLEGAL; goto done; }
    int ok = !strcmp(a.state, AMM_EA_SIGNED) || !strcmp(a.state, AMM_EA_SUBMITTED);
    int n = a.n;
    amm_eattempt_free(&a);
    if (!ok) { rc = AMM_J_ILLEGAL; goto done; }
    if (run(j, "UPDATE eth_attempts SET state='submitted', last_submit_tip=?1 "
               "WHERE swap_seq=?2 AND n=?3",
            (arg_t[]){AI(tip), AI(swap_seq), AI(n)}, 3, NULL) != 0) goto done;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

int amm_journal_eth_attempt_finish(amm_journal_t *j, int64_t swap_seq,
                                   const char *state) {
    if (!j || !state) return -1;
    if (strcmp(state, AMM_EA_CONFIRMED) && strcmp(state, AMM_EA_FAILED) &&
        strcmp(state, AMM_EA_ORPHANED) && strcmp(state, AMM_EA_UNKNOWN))
        return AMM_J_ILLEGAL;
    if (op_begin(j) != 0) return -1;
    int rc = -1;
    amm_eattempt_t a;
    int g = eattempt_latest_locked(j, swap_seq, &a);
    if (g < 0) goto done;
    if (g == 1) { rc = AMM_J_ILLEGAL; goto done; }
    int n = a.n;
    int ok = !strcmp(a.state, AMM_EA_SIGNED) || !strcmp(a.state, AMM_EA_SUBMITTED);
    amm_eattempt_free(&a);
    if (!ok) { rc = AMM_J_ILLEGAL; goto done; }
    if (run(j, "UPDATE eth_attempts SET state=?1 WHERE swap_seq=?2 AND n=?3",
            (arg_t[]){AT(state), AI(swap_seq), AI(n)}, 3, NULL) != 0) goto done;
    rc = AMM_J_OK;
done:
    return op_end(j, rc);
}

int amm_journal_eth_pending_usdt(amm_journal_t *j, uint64_t *out) {
    if (!j || !out) return -1;
    lock(j);
    sqlite3_stmt *st;
    int ret = -1;
    if (prep(j, "SELECT net FROM eth_attempts WHERE state IN "
                "('signed','submitted') ORDER BY swap_seq, n", NULL, 0, &st) == 0) {
        uint64_t sum = 0;
        int rc;
        ret = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            uint64_t v;
            if (col_u64(st, 0, &v) != 0 || sum > UINT64_MAX - v) { ret = -1; break; }
            sum += v;
        }
        if (ret == 0 && rc != SQLITE_DONE) ret = -1;
        sqlite3_finalize(st);
        if (ret == 0) *out = sum;
    }
    unlock(j);
    return ret;
}

/* ── open / close ───────────────────────────────────────────────────── */

int amm_journal_open(const char *path, amm_journal_t **out) {
    if (!path || !out) return -1;
    *out = NULL;
    amm_journal_t *j = calloc(1, sizeof(*j));
    if (!j) return -1;
    pthread_mutexattr_t at;
    pthread_mutexattr_init(&at);
    pthread_mutexattr_settype(&at, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&j->mu, &at);
    pthread_mutexattr_destroy(&at);
    if (sqlite3_open_v2(path, &j->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                        SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "cannot open journal %s", path);
        goto fail;
    }
    sqlite3_busy_timeout(j->db, BUSY_MS);
    {   /* WAL must really be on: a silent fallback would weaken durability */
        sqlite3_stmt *st = NULL;
        int ok = 0;
        if (sqlite3_prepare_v2(j->db, "PRAGMA journal_mode=WAL", -1, &st,
                               NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW) {
            const char *m = (const char *)sqlite3_column_text(st, 0);
            ok = m && !strcmp(m, "wal");
        }
        sqlite3_finalize(st);
        if (!ok) { QGP_LOG_ERROR(LOG_TAG, "WAL mode not available"); goto fail; }
    }
    if (exec_sql(j->db, "PRAGMA synchronous=FULL") != 0) goto fail;
    {
        int64_t ver = 0;
        if (one_int(j, "PRAGMA user_version", NULL, 0, &ver) != 0) goto fail;
        if (ver != 0 && ver < SCHEMA_VERSION) {
            QGP_LOG_ERROR(LOG_TAG, "journal schema %lld is older than this "
                          "binary (%d) and is not migrated", (long long)ver,
                          SCHEMA_VERSION);
            goto fail;
        }
        if (ver > SCHEMA_VERSION) {
            QGP_LOG_ERROR(LOG_TAG, "journal schema %lld is newer than this "
                          "binary (%d)", (long long)ver, SCHEMA_VERSION);
            goto fail;
        }
    }
    if (exec_sql(j->db, SCHEMA_SQL) != 0) goto fail;
    if (exec_sql(j->db, "PRAGMA user_version=4") != 0) goto fail;   /* = SCHEMA_VERSION */
    chmod(path, 0600);
    *out = j;
    return 0;
fail:
    if (j->db) sqlite3_close(j->db);
    pthread_mutex_destroy(&j->mu);
    free(j);
    return -1;
}

void amm_journal_close(amm_journal_t *j) {
    if (!j) return;
    if (j->txd) exec_sql(j->db, "ROLLBACK");
    if (j->db) sqlite3_close(j->db);
    pthread_mutex_destroy(&j->mu);
    free(j);
}
