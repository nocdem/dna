/**
 * @file nodus_witness_cmt_store.c
 * @brief cometbft @709fd12b store/store.go + state/store.go over SQLite.
 *        Contract and every file:line: nodus_witness_cmt_store.h.
 */

#include "witness/nodus_witness_cmt_store.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_CMTSTORE"

/* ── SQL, both tables ────────────────────────────────────────────────── */

static const char SQL_BS_GET[] = "SELECT value FROM cmt_blockstore WHERE key = ?1";
static const char SQL_BS_SET[] =
    "INSERT OR REPLACE INTO cmt_blockstore (key, value) VALUES (?1, ?2)";
static const char SQL_BS_DEL[] = "DELETE FROM cmt_blockstore WHERE key = ?1";
static const char SQL_SS_GET[] = "SELECT value FROM cmt_state WHERE key = ?1";
static const char SQL_SS_SET[] =
    "INSERT OR REPLACE INTO cmt_state (key, value) VALUES (?1, ?2)";
static const char SQL_SS_DEL[] = "DELETE FROM cmt_state WHERE key = ?1";

static int store_exec(nodus_cmt_store_t *s, const char *sql)
{
    char *err = NULL;

    if (sqlite3_exec(s->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "SQL failed (%s): %s", sql, err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ── the batch: one transaction, joined if one is already open ───────── */

static int batch_begin(nodus_cmt_store_t *s)
{
    if (sqlite3_get_autocommit(s->db)) {
        if (store_exec(s, "BEGIN IMMEDIATE") != 0) {
            return CMT_FAULT;
        }
        s->own_txn = true;
    } else {
        s->own_txn = false;               /* the caller's transaction */
    }
    return CMT_OK;
}

static int batch_write(nodus_cmt_store_t *s)
{
    if (!s->own_txn) {
        return CMT_OK;
    }
    s->own_txn = false;
    if (store_exec(s, "COMMIT") != 0) {
        (void)store_exec(s, "ROLLBACK");
        return CMT_FAULT;
    }
    return CMT_OK;
}

static void batch_abort(nodus_cmt_store_t *s)
{
    if (s->own_txn) {
        (void)store_exec(s, "ROLLBACK");
        s->own_txn = false;
    }
}

/* ── raw table access ────────────────────────────────────────────────── */

int nodus_cmt_store_get(nodus_cmt_store_t *s, bool state_table,
                        const char *key, const uint8_t **out_value,
                        size_t *out_len)
{
    sqlite3_stmt  *st;
    uint8_t      **val_buf;
    size_t        *val_cap;
    int            rc;

    if (!s || !s->db || !key || !out_value || !out_len) {
        return CMT_FAULT;
    }
    st      = state_table ? s->ss_get : s->bs_get;
    val_buf = state_table ? &s->ss_val : &s->bs_val;
    val_cap = state_table ? &s->ss_val_cap : &s->bs_val_cap;
    sqlite3_reset(st);
    sqlite3_bind_blob(st, 1, key, (int)strlen(key), SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        /* R3-W3-C2a-17 (delta 9) — reset HERE too, not only on the next
         * call's top-of-function reset: a statement that reached DONE
         * without ever returning ROW still holds the same deferred
         * read-transaction snapshot open until it is reset, exactly as
         * the ROW case below did before this fix. */
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        *out_value = NULL;
        *out_len = 0;
        return CMT_OK;
    }
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "get %s failed: %s", key, sqlite3_errmsg(s->db));
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        return CMT_FAULT;
    }
    /* R3-W3-C2a-17 (delta 9) — COPY the row into this table's store-owned
     * buffer and reset the statement IMMEDIATELY, rather than leaving it
     * stepped (row materialised) until the NEXT call resets it at the
     * top of this function. Leaving it stepped pins an open READ
     * transaction (a WAL snapshot) on the MAIN connection for the whole
     * span between calls: the moment ANY other connection commits
     * (the WAL module's own separate FULL connection, in production),
     * SQLite's SQLITE_BUSY_SNAPSHOT rule makes every subsequent WRITE on
     * this connection fail "database is locked" — NOT retried by the
     * busy handler, because a read transaction can never be promoted to
     * a write one once another connection has written since the
     * snapshot was taken. Measured on the Genesis Protocol harness
     * (7 nodes, production constants): every node's WAL writes and its
     * own `BEGIN IMMEDIATE` failed this way after height 1, stopping
     * consensus participation on all seven. See this function's own doc
     * comment in nodus_witness_cmt_store.h for the full citation. The
     * OBSERVABLE contract is unchanged: `*out_value` is still valid
     * until the next `get` on the SAME table — it is now a copy, not a
     * row pointer, but nothing outside this file can tell the
     * difference. */
    {
        const uint8_t *col = (const uint8_t *)sqlite3_column_blob(st, 0);
        size_t         n   = (size_t)sqlite3_column_bytes(st, 0);

        if (n == 0) {
            sqlite3_reset(st);
            sqlite3_clear_bindings(st);
            *out_value = NULL;            /* the reference's len(bz) == 0 */
            *out_len = 0;
            return CMT_OK;
        }
        if (n > *val_cap) {
            uint8_t *grown = (uint8_t *)realloc(*val_buf, n);
            if (!grown) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "get: out of memory copying "
                              "the row out of the statement");
                sqlite3_reset(st);
                sqlite3_clear_bindings(st);
                return CMT_FAULT;
            }
            *val_buf = grown;
            *val_cap = n;
        }
        memcpy(*val_buf, col, n);
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        *out_value = *val_buf;
        *out_len = n;
    }
    return CMT_OK;
}

int nodus_cmt_store_set(nodus_cmt_store_t *s, bool state_table,
                        const char *key, const uint8_t *value, size_t len)
{
    sqlite3_stmt *st;
    int           rc;

    if (!s || !s->db || !key || (!value && len)) {
        return CMT_FAULT;
    }
    st = state_table ? s->ss_set : s->bs_set;
    sqlite3_reset(st);
    sqlite3_bind_blob(st, 1, key, (int)strlen(key), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, len ? (const void *)value : (const void *)"",
                      (int)len, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "set %s failed: %s", key, sqlite3_errmsg(s->db));
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_store_delete(nodus_cmt_store_t *s, bool state_table,
                           const char *key)
{
    sqlite3_stmt *st;
    int           rc;

    if (!s || !s->db || !key) {
        return CMT_FAULT;
    }
    st = state_table ? s->ss_del : s->bs_del;
    sqlite3_reset(st);
    sqlite3_bind_blob(st, 1, key, (int)strlen(key), SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "delete %s failed: %s", key,
                      sqlite3_errmsg(s->db));
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* ── the keys (store.go:632-658, state/store.go:30-45, state.go:21) ──── */

static void key_block_meta(int64_t h, char out[NODUS_CMT_STORE_KEY_MAX])
{
    snprintf(out, NODUS_CMT_STORE_KEY_MAX, "H:%" PRId64, h);          /* :632 */
}

static void key_block_part(int64_t h, int i, char out[NODUS_CMT_STORE_KEY_MAX])
{
    snprintf(out, NODUS_CMT_STORE_KEY_MAX, "P:%" PRId64 ":%d", h, i); /* :636 */
}

static void key_block_commit(int64_t h, char out[NODUS_CMT_STORE_KEY_MAX])
{
    snprintf(out, NODUS_CMT_STORE_KEY_MAX, "C:%" PRId64, h);          /* :640 */
}

static void key_seen_commit(int64_t h, char out[NODUS_CMT_STORE_KEY_MAX])
{
    snprintf(out, NODUS_CMT_STORE_KEY_MAX, "SC:%" PRId64, h);         /* :644 */
}

static void key_ext_commit(int64_t h, char out[NODUS_CMT_STORE_KEY_MAX])
{
    snprintf(out, NODUS_CMT_STORE_KEY_MAX, "EC:%" PRId64, h);         /* :648 */
}

/* :652-654 `BH:%x` — lowercase hex of the hash bytes. */
static void key_block_hash(const uint8_t *hash, size_t n,
                           char out[NODUS_CMT_STORE_KEY_MAX])
{
    static const char HX[] = "0123456789abcdef";
    size_t i;

    if (n > CMT_TMHASH_SIZE) {
        n = CMT_TMHASH_SIZE;              /* never: the hash is ≤ 64 */
    }
    out[0] = 'B'; out[1] = 'H'; out[2] = ':';
    for (i = 0; i < n; i++) {
        out[3 + 2 * i]     = HX[hash[i] >> 4];
        out[3 + 2 * i + 1] = HX[hash[i] & 15];
    }
    out[3 + 2 * n] = '\0';
}

#define KEY_BLOCK_STORE  "blockStore"                  /* store.go:658 */
#define KEY_STATE        "stateKey"                    /* state.go:21  */
#define KEY_LAST_ABCI    "lastABCIResponseKey"         /* state/store.go:44 */
#define KEY_OFFLINE_SS   "offlineStateSyncHeightKey"   /* :45 */

static void key_validators(int64_t h, char out[NODUS_CMT_STORE_KEY_MAX])
{
    snprintf(out, NODUS_CMT_STORE_KEY_MAX, "validatorsKey:%" PRId64, h); /* :30 */
}

static void key_consensus_params(int64_t h, char out[NODUS_CMT_STORE_KEY_MAX])
{
    snprintf(out, NODUS_CMT_STORE_KEY_MAX, "consensusParamsKey:%" PRId64, h); /* :34 */
}

static void key_abci_responses(int64_t h, char out[NODUS_CMT_STORE_KEY_MAX])
{
    snprintf(out, NODUS_CMT_STORE_KEY_MAX, "abciResponsesKey:%" PRId64, h); /* :38 */
}

/* ── small ports ─────────────────────────────────────────────────────── */

/* libs/math/safemath.go:36-43 SafeConvertInt32 — the panic is CMT_FAULT. */
static int safe_convert_int32(int64_t a, int32_t *out)
{
    if (a > INT32_MAX || a < INT32_MIN) {
        return CMT_FAULT;
    }
    *out = (int32_t)a;
    return CMT_OK;
}

/* libs/math/math.go:3-8 MaxInt64 */
static int64_t max_int64(int64_t a, int64_t b)
{
    return a > b ? a : b;
}

/* state/store.go:760-765 min */
static int64_t min_int64(int64_t a, int64_t b)
{
    return a < b ? a : b;
}

int64_t nodus_cmt_last_stored_height_for(int64_t height,
                                         int64_t last_height_changed)
{
    int64_t checkpoint = height - height % NODUS_CMT_VALSET_CHECKPOINT_INTERVAL;

    return max_int64(checkpoint, last_height_changed);           /* :589-590 */
}

/* encoding/binary PutVarint: zigzag then uvarint (state/store.go:823-827). */
size_t nodus_cmt_int64_to_bytes(int64_t v, uint8_t out[10])
{
    uint64_t ux = (uint64_t)v << 1;
    size_t   n = 0;

    if (v < 0) {
        ux = ~ux;
    }
    while (ux >= 0x80u) {
        out[n++] = (uint8_t)(ux | 0x80u);
        ux >>= 7;
    }
    out[n++] = (uint8_t)ux;
    return n;
}

/* encoding/binary Varint (:818-821): a malformed buffer yields 0 because
 * the reference discards the count. */
int64_t nodus_cmt_int64_from_bytes(const uint8_t *in, size_t len)
{
    uint64_t ux = 0;
    unsigned shift = 0;
    size_t   i;
    int64_t  x;

    for (i = 0; i < len; i++) {
        uint8_t b = in[i];

        if (i == 9 && b > 1) {
            return 0;                     /* overflow: Uvarint returns n<0 */
        }
        if (b < 0x80u) {
            if (i > 9 || (i == 9 && b > 1)) {
                return 0;
            }
            ux |= (uint64_t)b << shift;
            x = (int64_t)(ux >> 1);
            if (ux & 1u) {
                x = ~x;
            }
            return x;
        }
        ux |= (uint64_t)(b & 0x7fu) << shift;
        shift += 7;
        if (shift >= 64) {
            return 0;
        }
    }
    return 0;                             /* buffer too small: n == 0 */
}

/* Go stdlib `time.Time.Sub` — not pinned, behaviour stated, not verified:
 * for two canonical (monotonic-less) times, the int64-nanosecond
 * difference, saturating at the Duration limits when it does not fit. */
static int64_t time_sub_saturating(cmt_time_t t, cmt_time_t u)
{
    int64_t ds = t.seconds - u.seconds;   /* both within ±10 000 years */
    int64_t dn = (int64_t)t.nanos - (int64_t)u.nanos;
    const int64_t MAX_S = INT64_MAX / 1000000000LL;   /* 9223372036 */
    const int64_t MIN_S = INT64_MIN / 1000000000LL;   /* -9223372036 */
    int64_t d;

    if (ds > MAX_S + 1) {
        return INT64_MAX;
    }
    if (ds < MIN_S - 1) {
        return INT64_MIN;
    }
    if (ds > MAX_S || ds < MIN_S) {
        /* |ds| == MAX_S + 1: the product alone overflows; only a
         * compensating dn could bring it back, which needs 128-bit
         * care. Do it in two halves. */
        int64_t base = (ds > 0 ? MAX_S : MIN_S) * 1000000000LL;
        int64_t rest = (ds > 0 ? 1000000000LL : -1000000000LL) + dn;

        if (rest > 0 && base > INT64_MAX - rest) {
            return INT64_MAX;
        }
        if (rest < 0 && base < INT64_MIN - rest) {
            return INT64_MIN;
        }
        return base + rest;
    }
    d = ds * 1000000000LL;
    if (dn > 0 && d > INT64_MAX - dn) {
        return INT64_MAX;
    }
    if (dn < 0 && d < INT64_MIN - dn) {
        return INT64_MIN;
    }
    return d + dn;
}

/* evidence/verify.go:295-303 */
bool nodus_cmt_is_evidence_expired(int64_t height_now, cmt_time_t time_now,
                                   int64_t height_ev, cmt_time_t time_ev,
                                   const cmt_evidence_params_t *params)
{
    int64_t age_duration = time_sub_saturating(time_now, time_ev);  /* :296 */
    int64_t age_num_blocks = height_now - height_ev;                /* :297 */

    if (age_duration > params->max_age_duration_ns &&
        age_num_blocks > params->max_age_num_blocks) {              /* :299 */
        return true;
    }
    return false;
}

/* ── types/block_meta.go ─────────────────────────────────────────────── */

int nodus_cmt_new_block_meta(cmt_block_t *block, const cmt_part_set_t *parts,
                             uint8_t *scratch, size_t scratch_cap,
                             nodus_cmt_block_meta_t *out)
{
    int rc;

    if (!block || !parts || !out) {
        return CMT_FAULT;
    }
    cmt_pb_store_block_meta_init(out);
    rc = cmt_block_hash(block, out->block_id.hash);                 /* :22 */
    if (rc == CMT_OK) {
        out->block_id.hash_len = CMT_TMHASH_SIZE;
    } else if (rc == CMT_HASH_NIL) {
        out->block_id.hash_len = 0;
    } else {
        return rc;
    }
    rc = cmt_part_set_header(parts, &out->block_id.part_set_header);  /* :22 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->block_size = (int64_t)cmt_block_size(block, scratch, scratch_cap); /* :23 */
    out->header = block->header;                                    /* :24 */
    out->num_txs = (int64_t)block->data.txs_len;                    /* :25 */
    return CMT_OK;
}

int nodus_cmt_block_meta_from_trusted_proto(nodus_cmt_block_meta_t *bm,
                                            uint64_t block_protocol)
{
    cmt_block_id_t bid;
    cmt_header_t   h;
    int            rc;

    if (!bm) {
        return CMT_REJECT;                                          /* :52-54 */
    }
    rc = cmt_block_id_from_proto(&bm->block_id, &bid);              /* :58-61 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_header_from_proto(&bm->header, block_protocol, &h);    /* :63-66 */
    if (rc != CMT_OK) {
        return rc;
    }
    bm->block_id = bid;                                             /* :68 */
    bm->header = h;                                                 /* :70 */
    return CMT_OK;
}

int nodus_cmt_block_meta_validate_basic(const nodus_cmt_block_meta_t *bm)
{
    uint8_t hh[CMT_TMHASH_SIZE];
    int     rc;

    if (!bm) {
        return CMT_FAULT;
    }
    rc = cmt_block_id_validate_basic(&bm->block_id);                /* :78-80 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_header_hash(&bm->header, hh);                          /* :81 */
    if (rc == CMT_HASH_NIL) {
        return bm->block_id.hash_len == 0 ? CMT_OK : CMT_REJECT;
    }
    if (rc != CMT_OK) {
        return rc;
    }
    if (bm->block_id.hash_len != CMT_TMHASH_SIZE ||
        memcmp(bm->block_id.hash, hh, CMT_TMHASH_SIZE) != 0) {
        return CMT_REJECT;                                          /* :82-83 */
    }
    return CMT_OK;
}

int nodus_cmt_block_meta_from_proto(nodus_cmt_block_meta_t *bm,
                                    uint64_t block_protocol)
{
    int rc = nodus_cmt_block_meta_from_trusted_proto(bm, block_protocol); /* :44 */

    if (rc != CMT_OK) {
        return rc;
    }
    return nodus_cmt_block_meta_validate_basic(bm);                 /* :48 */
}

/* ── the block decode step ───────────────────────────────────────────── */

int nodus_cmt_block_decode(const uint8_t *bytes, size_t len,
                           nodus_cmt_block_decode_t *st, cmt_block_t *out)
{
    int rc;

    if (!st || !out || (!bytes && len)) {
        return CMT_FAULT;
    }
    /* Bind the view's storage, then decode into it. */
    memset(&st->pb_block, 0, sizeof(st->pb_block));
    st->pb_block.data.txs = st->txs;
    st->pb_block.data.txs_cap = st->txs_cap;
    st->pb_block.evidence.evidence = st->pb_evidence;
    st->pb_block.evidence.evidence_cap = st->pb_evidence_cap;
    memset(&st->pb_last_commit, 0, sizeof(st->pb_last_commit));
    st->pb_last_commit.signatures = st->pb_sigs;
    st->pb_last_commit.signatures_cap = st->pb_sigs_cap;
    if (st->arena) {
        st->arena->used = 0;
    }
    rc = cmt_pb_block_unmarshal(bytes, len, &st->pb_block, &st->pb_last_commit,
                                st->arena);                          /* :154 */
    if (rc != CMT_OK) {
        return rc;
    }
    memset(&st->last_commit, 0, sizeof(st->last_commit));
    st->last_commit.signatures = st->sigs;
    st->last_commit.signatures_cap = st->sigs_cap;
    return cmt_block_from_proto(&st->pb_block, CMT_BLOCK_PROTOCOL,
                                st->sigs, st->sigs_cap,
                                st->evidence, st->evidence_cap,
                                &st->last_commit, out);              /* :161 */
}

/* ── init / release ──────────────────────────────────────────────────── */

static void store_free_scratch(nodus_cmt_store_t *s)
{
    int k;

    /* R3-W3-C2a-17 (delta 9) — nodus_cmt_store_get's own per-table copy
     * buffers; see nodus_cmt_store_t's own struct comment and
     * nodus_cmt_store_get's doc comment for why they exist. */
    free(s->bs_val);
    s->bs_val = NULL;
    s->bs_val_cap = 0;
    free(s->ss_val);
    s->ss_val = NULL;
    s->ss_val_cap = 0;
    free(s->buf);
    s->buf = NULL;
    s->buf_cap = 0;
    for (k = 0; k < 3; k++) {
        free(s->pb_vals[k]);
        s->pb_vals[k] = NULL;
    }
    free(s->pb_sigs);
    s->pb_sigs = NULL;
    free(s->pb_ext_sigs);
    s->pb_ext_sigs = NULL;
}

void nodus_cmt_store_release(nodus_cmt_store_t *s)
{
    if (!s) {
        return;
    }
    sqlite3_finalize(s->bs_get); sqlite3_finalize(s->bs_set);
    sqlite3_finalize(s->bs_del); sqlite3_finalize(s->ss_get);
    sqlite3_finalize(s->ss_set); sqlite3_finalize(s->ss_del);
    s->bs_get = s->bs_set = s->bs_del = NULL;
    s->ss_get = s->ss_set = s->ss_del = NULL;
    store_free_scratch(s);
    s->db = NULL;
}

int nodus_cmt_bs_load_block_store_state(nodus_cmt_store_t *s,
                                        cmt_pb_block_store_state_t *out)
{
    const uint8_t *v;
    size_t         n;
    int            rc;

    if (!s || !out) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_store_get(s, false, KEY_BLOCK_STORE, &v, &n);     /* :693 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (n == 0) {                                                    /* :698-703 */
        cmt_pb_store_block_store_state_init(out);
        return CMT_OK;
    }
    if (cmt_pb_store_block_store_state_unmarshal(v, n, out) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "Could not unmarshal blockStore bytes");
        return CMT_FAULT;                                            /* :707 */
    }
    if (out->height > 0 && out->base == 0) {                         /* :711-713 */
        out->base = 1;
    }
    return CMT_OK;
}

int nodus_cmt_store_init(nodus_cmt_store_t *s, sqlite3 *db,
                         bool discard_abci_responses)
{
    cmt_pb_block_store_state_t bss;
    int k;

    if (!s || !db) {
        return CMT_FAULT;
    }
    memset(s, 0, sizeof(*s));
    s->db = db;
    s->discard_abci_responses = discard_abci_responses;

    if (sqlite3_prepare_v2(db, SQL_BS_GET, -1, &s->bs_get, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, SQL_BS_SET, -1, &s->bs_set, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, SQL_BS_DEL, -1, &s->bs_del, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, SQL_SS_GET, -1, &s->ss_get, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, SQL_SS_SET, -1, &s->ss_set, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, SQL_SS_DEL, -1, &s->ss_del, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare failed: %s", sqlite3_errmsg(db));
        nodus_cmt_store_release(s);
        return CMT_FAULT;
    }

    s->buf_cap = cmt_pb_store_state_upper_bound(CMT_VALSET_MAX);
    s->buf = (uint8_t *)malloc(s->buf_cap);
    for (k = 0; k < 3; k++) {
        s->pb_vals[k] = (cmt_pb_validator_t *)
            calloc(CMT_VALSET_MAX, sizeof(cmt_pb_validator_t));
    }
    s->pb_sigs = (cmt_commit_sig_t *)
        calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    s->pb_ext_sigs = (cmt_extended_commit_sig_t *)
        calloc(CMT_VALSET_MAX, sizeof(cmt_extended_commit_sig_t));
    if (!s->buf || !s->pb_vals[0] || !s->pb_vals[1] || !s->pb_vals[2] ||
        !s->pb_sigs || !s->pb_ext_sigs) {
        nodus_cmt_store_release(s);
        return CMT_FAULT;
    }

    /* store.go:67-76 NewBlockStore */
    if (nodus_cmt_bs_load_block_store_state(s, &bss) != CMT_OK) {
        nodus_cmt_store_release(s);
        return CMT_FAULT;
    }
    s->base = bss.base;
    s->height = bss.height;
    return CMT_OK;
}

/* ── store.go — reads ────────────────────────────────────────────────── */

bool nodus_cmt_bs_is_empty(const nodus_cmt_store_t *s)
{
    return s && s->base == s->height && s->base == 0;               /* :98 */
}

int64_t nodus_cmt_bs_base(const nodus_cmt_store_t *s)
{
    return s ? s->base : 0;                                         /* :105 */
}

int64_t nodus_cmt_bs_height(const nodus_cmt_store_t *s)
{
    return s ? s->height : 0;                                       /* :112 */
}

int64_t nodus_cmt_bs_size(const nodus_cmt_store_t *s)
{
    if (!s || s->height == 0) {                                     /* :119-121 */
        return 0;
    }
    return s->height - s->base + 1;                                 /* :122 */
}

int nodus_cmt_bs_load_block_meta(nodus_cmt_store_t *s, int64_t height,
                                 nodus_cmt_block_meta_t *out, bool *out_found)
{
    char           key[NODUS_CMT_STORE_KEY_MAX];
    const uint8_t *v;
    size_t         n;

    if (!s || !out || !out_found) {
        return CMT_FAULT;
    }
    *out_found = false;
    key_block_meta(height, key);
    if (nodus_cmt_store_get(s, false, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;                                            /* :221 */
    }
    if (n == 0) {
        return CMT_OK;                                               /* :224-226 */
    }
    if (cmt_pb_store_block_meta_unmarshal(v, n, out) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "unmarshal to cmtproto.BlockMeta failed");
        return CMT_FAULT;                                            /* :230 */
    }
    if (nodus_cmt_block_meta_from_trusted_proto(out, CMT_BLOCK_PROTOCOL)
        != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "error from proto blockMeta");
        return CMT_FAULT;                                            /* :235 */
    }
    *out_found = true;
    return CMT_OK;
}

int nodus_cmt_bs_load_base_meta(nodus_cmt_store_t *s,
                                nodus_cmt_block_meta_t *out, bool *out_found)
{
    if (!s || !out || !out_found) {
        return CMT_FAULT;
    }
    if (s->base == 0) {                                              /* :129-131 */
        *out_found = false;
        return CMT_OK;
    }
    return nodus_cmt_bs_load_block_meta(s, s->base, out, out_found); /* :132 */
}

int nodus_cmt_bs_load_block_part(nodus_cmt_store_t *s, int64_t height,
                                 int index, cmt_pb_arena_t *arena,
                                 cmt_part_t *out, bool *out_found)
{
    char           key[NODUS_CMT_STORE_KEY_MAX];
    const uint8_t *v;
    size_t         n;
    cmt_pb_part_t  pb;

    if (!s || !out || !out_found) {
        return CMT_FAULT;
    }
    *out_found = false;
    key_block_part(height, index, key);
    if (nodus_cmt_store_get(s, false, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;                                            /* :197 */
    }
    if (n == 0) {
        return CMT_OK;                                               /* :199-201 */
    }
    if (cmt_pb_part_unmarshal(v, n, &pb, arena) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "unmarshal to cmtproto.Part failed");
        return CMT_FAULT;                                            /* :205 */
    }
    if (cmt_part_from_proto(&pb, out) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Error reading block part");
        return CMT_FAULT;                                            /* :209 */
    }
    *out_found = true;
    return CMT_OK;
}

int nodus_cmt_bs_load_block(nodus_cmt_store_t *s, int64_t height,
                            uint8_t *buf, size_t buf_cap,
                            nodus_cmt_block_decode_t *st, cmt_block_t *out,
                            bool *out_found)
{
    nodus_cmt_block_meta_t *meta;
    bool     found = false;
    size_t   off = 0;
    uint32_t total, i;
    int      rc;

    if (!s || !buf || !st || !out || !out_found) {
        return CMT_FAULT;
    }
    *out_found = false;
    meta = (nodus_cmt_block_meta_t *)malloc(sizeof(*meta));
    if (!meta) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_bs_load_block_meta(s, height, meta, &found);      /* :138 */
    if (rc != CMT_OK) {
        free(meta);
        return rc;
    }
    if (!found) {
        free(meta);
        return CMT_OK;                                               /* :139-141 */
    }
    total = meta->block_id.part_set_header.total;
    free(meta);

    for (i = 0; i < total; i++) {                                    /* :145 */
        cmt_pb_arena_t arena;
        cmt_part_t     part;

        /* The part's payload is decoded straight into the concatenation
         * buffer: the arena IS the buffer's tail. */
        arena.buf = buf + off;
        arena.cap = buf_cap - off;
        arena.used = 0;
        rc = nodus_cmt_bs_load_block_part(s, height, (int)i, &arena, &part,
                                          &found);                   /* :146 */
        if (rc != CMT_OK) {
            return rc;
        }
        if (!found) {
            return CMT_OK;                                           /* :149-151 */
        }
        if (part.bytes.len != 0 && part.bytes.data != buf + off) {
            memmove(buf + off, part.bytes.data, part.bytes.len);
        }
        off += part.bytes.len;                                       /* :152 */
    }
    rc = nodus_cmt_block_decode(buf, off, st, out);                  /* :154-164 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Error reading block (rc %d)", rc);
        return CMT_FAULT;                                            /* :158, :163 */
    }
    *out_found = true;
    return CMT_OK;
}

/* :172-187 / :243-258 — the `BH:<hex>` → height half. `*out_found`
 * false when the key is absent; a value that is not a decimal int64 is
 * the panic at :184 / :255 → CMT_FAULT. */
static int height_by_hash(nodus_cmt_store_t *s, const uint8_t *hash,
                          size_t hash_len, int64_t *out_height,
                          bool *out_found)
{
    char           key[NODUS_CMT_STORE_KEY_MAX];
    const uint8_t *v;
    size_t         n, i;
    bool           neg = false;
    uint64_t       acc = 0;

    *out_found = false;
    key_block_hash(hash, hash_len, key);
    if (nodus_cmt_store_get(s, false, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;
    }
    if (n == 0) {
        return CMT_OK;
    }
    /* strconv.ParseInt(s, 10, 64) */
    i = 0;
    if (v[0] == '+' || v[0] == '-') {
        neg = (v[0] == '-');
        i = 1;
    }
    if (i >= n) {
        return CMT_FAULT;
    }
    for (; i < n; i++) {
        uint64_t d;

        if (v[i] < '0' || v[i] > '9') {
            return CMT_FAULT;
        }
        d = (uint64_t)(v[i] - '0');
        if (acc > (UINT64_MAX - d) / 10u) {
            return CMT_FAULT;
        }
        acc = acc * 10u + d;
    }
    if (neg) {
        if (acc > (uint64_t)INT64_MAX + 1u) {
            return CMT_FAULT;
        }
        *out_height = (acc == (uint64_t)INT64_MAX + 1u)
                          ? INT64_MIN : -(int64_t)acc;
    } else {
        if (acc > (uint64_t)INT64_MAX) {
            return CMT_FAULT;
        }
        *out_height = (int64_t)acc;
    }
    *out_found = true;
    return CMT_OK;
}

int nodus_cmt_bs_load_block_by_hash(nodus_cmt_store_t *s,
                                    const uint8_t *hash, size_t hash_len,
                                    uint8_t *buf, size_t buf_cap,
                                    nodus_cmt_block_decode_t *st,
                                    cmt_block_t *out, bool *out_found)
{
    int64_t h = 0;
    bool    found = false;
    int     rc;

    if (!s || !out_found || (!hash && hash_len)) {
        return CMT_FAULT;
    }
    rc = height_by_hash(s, hash, hash_len, &h, &found);              /* :173-185 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!found) {
        *out_found = false;
        return CMT_OK;
    }
    return nodus_cmt_bs_load_block(s, h, buf, buf_cap, st, out, out_found); /* :186 */
}

int nodus_cmt_bs_load_block_meta_by_hash(nodus_cmt_store_t *s,
                                         const uint8_t *hash, size_t hash_len,
                                         nodus_cmt_block_meta_t *out,
                                         bool *out_found)
{
    int64_t h = 0;
    bool    found = false;
    int     rc;

    if (!s || !out || !out_found || (!hash && hash_len)) {
        return CMT_FAULT;
    }
    rc = height_by_hash(s, hash, hash_len, &h, &found);              /* :244-256 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!found) {
        *out_found = false;
        return CMT_OK;
    }
    return nodus_cmt_bs_load_block_meta(s, h, out, out_found);      /* :257 */
}

/* The shared body of LoadBlockCommit (:264-287) and LoadSeenCommit
 * (:320-344): unmarshal into the module's proto-side signature storage,
 * CommitFromProto into the caller's. */
static int load_commit_at(nodus_cmt_store_t *s, const char *key,
                          cmt_commit_sig_t *sigs, size_t sigs_cap,
                          cmt_commit_t *out, bool *out_found)
{
    const uint8_t *v;
    size_t         n;
    cmt_pb_commit_t pb;

    *out_found = false;
    if (nodus_cmt_store_get(s, false, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;
    }
    if (n == 0) {
        return CMT_OK;
    }
    memset(&pb, 0, sizeof(pb));
    pb.signatures = s->pb_sigs;
    pb.signatures_cap = CMT_VALSET_MAX;
    if (cmt_pb_commit_unmarshal(v, n, &pb) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "error reading commit %s", key);
        return CMT_FAULT;
    }
    if (cmt_commit_from_proto(&pb, sigs, sigs_cap, out) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "converting commit %s from proto failed", key);
        return CMT_FAULT;
    }
    *out_found = true;
    return CMT_OK;
}

int nodus_cmt_bs_load_block_commit(nodus_cmt_store_t *s, int64_t height,
                                   cmt_commit_sig_t *sigs, size_t sigs_cap,
                                   cmt_commit_t *out, bool *out_found)
{
    char key[NODUS_CMT_STORE_KEY_MAX];

    if (!s || !out || !out_found) {
        return CMT_FAULT;
    }
    key_block_commit(height, key);
    return load_commit_at(s, key, sigs, sigs_cap, out, out_found);
}

int nodus_cmt_bs_load_seen_commit(nodus_cmt_store_t *s, int64_t height,
                                  cmt_commit_sig_t *sigs, size_t sigs_cap,
                                  cmt_commit_t *out, bool *out_found)
{
    char key[NODUS_CMT_STORE_KEY_MAX];

    if (!s || !out || !out_found) {
        return CMT_FAULT;
    }
    key_seen_commit(height, key);
    return load_commit_at(s, key, sigs, sigs_cap, out, out_found);
}

int nodus_cmt_bs_load_block_extended_commit(nodus_cmt_store_t *s,
                                            int64_t height,
                                            cmt_extended_commit_sig_t *sigs,
                                            size_t sigs_cap,
                                            cmt_pb_arena_t *arena,
                                            cmt_extended_commit_t *out,
                                            bool *out_found)
{
    char           key[NODUS_CMT_STORE_KEY_MAX];
    const uint8_t *v;
    size_t         n;
    cmt_pb_extended_commit_t pb;

    if (!s || !out || !out_found) {
        return CMT_FAULT;
    }
    *out_found = false;
    key_ext_commit(height, key);
    if (nodus_cmt_store_get(s, false, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;                                            /* :300 */
    }
    if (n == 0) {
        return CMT_OK;                                               /* :302-304 */
    }
    memset(&pb, 0, sizeof(pb));
    pb.extended_signatures = s->pb_ext_sigs;
    pb.extended_signatures_cap = CMT_VALSET_MAX;
    if (cmt_pb_extended_commit_unmarshal(v, n, &pb, arena) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "decoding extended commit %s failed", key);
        return CMT_FAULT;                                            /* :307 */
    }
    if (cmt_extended_commit_from_proto(&pb, sigs, sigs_cap, out) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "converting extended commit %s failed", key);
        return CMT_FAULT;                                            /* :311 */
    }
    *out_found = true;
    return CMT_OK;
}

/* ── store.go — writes ───────────────────────────────────────────────── */

/* :601-614 saveStateAndWriteDB: the `blockStore` row inside the batch,
 * then WriteSync. */
static int save_state_and_write_db(nodus_cmt_store_t *s, const char *err_msg)
{
    cmt_pb_block_store_state_t bss;
    size_t n = 0;

    bss.base = s->base;
    bss.height = s->height;
    if (cmt_pb_store_block_store_state_marshal(&bss, s->buf, s->buf_cap, &n)
        != CMT_OK) {
        return CMT_FAULT;                                            /* :675 */
    }
    if (nodus_cmt_store_set(s, false, KEY_BLOCK_STORE, s->buf, n) != CMT_OK) {
        return CMT_FAULT;                                            /* :686 */
    }
    if (batch_write(s) != CMT_OK) {                                  /* :608 */
        QGP_LOG_ERROR(LOG_TAG, "error writing batch to DB \"%s\": "
                      "(base %" PRId64 ", height %" PRId64 ")",
                      err_msg, s->base, s->height);
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_bs_save_block_store_state(nodus_cmt_store_t *s,
                                        const cmt_pb_block_store_state_t *bss)
{
    size_t n = 0;

    if (!s || !bss) {
        return CMT_FAULT;
    }
    if (cmt_pb_store_block_store_state_marshal(bss, s->buf, s->buf_cap, &n)
        != CMT_OK) {
        return CMT_FAULT;
    }
    return nodus_cmt_store_set(s, false, KEY_BLOCK_STORE, s->buf, n); /* :683 */
}

/* :584-598 saveBlockPart — inside the one transaction either branch of
 * :590-594 is the same write (header: DEVIATION). */
static int save_block_part(nodus_cmt_store_t *s, int64_t height, int index,
                           const cmt_part_t *part)
{
    char          key[NODUS_CMT_STORE_KEY_MAX];
    cmt_pb_part_t pb;
    size_t        n = 0;

    if (cmt_part_to_proto(part, &pb) != CMT_OK) {                   /* :585 */
        return CMT_FAULT;
    }
    if (cmt_pb_part_marshal(&pb, s->buf, s->buf_cap, &n) != CMT_OK) { /* :589 */
        return CMT_FAULT;
    }
    key_block_part(height, index, key);
    return nodus_cmt_store_set(s, false, key, s->buf, n);           /* :591 */
}

/* :516-582 saveBlockToBatch. CMT_REJECT for the three contract errors
 * (:530, :533, :536); CMT_FAULT for a panic or a SQLite failure. */
static int save_block_to_batch(nodus_cmt_store_t *s, cmt_block_t *block,
                               const cmt_part_set_t *parts,
                               const cmt_commit_t *seen_commit,
                               uint8_t *scratch, size_t scratch_cap)
{
    int64_t  height;
    uint8_t  hash[CMT_TMHASH_SIZE];
    size_t   hash_len = 0;
    char     key[NODUS_CMT_STORE_KEY_MAX];
    char     val[32];
    uint32_t total, i;
    size_t   n = 0;
    int      rc;
    nodus_cmt_block_meta_t *meta;
    cmt_pb_commit_t pbc;

    if (!block || !parts || !seen_commit) {
        return CMT_FAULT;                                            /* :522-524 */
    }
    height = block->header.height;                                   /* :526 */
    rc = cmt_block_hash(block, hash);                                /* :527 */
    if (rc == CMT_OK) {
        hash_len = CMT_TMHASH_SIZE;
    } else if (rc != CMT_HASH_NIL) {
        return CMT_FAULT;
    }
    if (s->base > 0 && height != s->height + 1) {                    /* :529-531 */
        QGP_LOG_ERROR(LOG_TAG, "BlockStore can only save contiguous blocks. "
                      "Wanted %" PRId64 ", got %" PRId64, s->height + 1, height);
        return CMT_REJECT;
    }
    if (!cmt_part_set_is_complete(parts)) {                          /* :532-534 */
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "BlockStore can only save complete block part sets");
        return CMT_REJECT;
    }
    if (height != seen_commit->height) {                             /* :535-537 */
        QGP_LOG_ERROR(LOG_TAG, "BlockStore cannot save seen commit of a "
                      "different height (block: %" PRId64 ", commit: %" PRId64 ")",
                      height, seen_commit->height);
        return CMT_REJECT;
    }

    /* :541 saveBlockPartsToBatch — moot, see the header. */
    total = cmt_part_set_total(parts);
    for (i = 0; i < total; i++) {                                    /* :547-550 */
        const cmt_part_t *part = cmt_part_set_get_part(parts, i);

        if (!part) {
            return CMT_FAULT;
        }
        rc = save_block_part(s, height, (int)i, part);
        if (rc != CMT_OK) {
            return rc;
        }
    }

    /* :553-561 block meta */
    meta = (nodus_cmt_block_meta_t *)malloc(sizeof(*meta));
    if (!meta) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_new_block_meta(block, parts, scratch, scratch_cap, meta);
    if (rc != CMT_OK) {
        free(meta);
        return CMT_FAULT;
    }
    rc = cmt_pb_store_block_meta_marshal(meta, s->buf, s->buf_cap, &n);
    free(meta);
    if (rc != CMT_OK) {
        return CMT_FAULT;                                            /* :558 mustEncode */
    }
    key_block_meta(height, key);
    if (nodus_cmt_store_set(s, false, key, s->buf, n) != CMT_OK) {
        return CMT_FAULT;
    }
    /* :562-564 `BH:%x` → "%d" */
    key_block_hash(hash, hash_len, key);
    snprintf(val, sizeof(val), "%" PRId64, height);
    if (nodus_cmt_store_set(s, false, key, (const uint8_t *)val, strlen(val))
        != CMT_OK) {
        return CMT_FAULT;
    }
    /* :567-571 the block's LastCommit under C:<h-1> */
    if (!block->last_commit) {
        return CMT_FAULT;                 /* mustEncode(nil.ToProto()) */
    }
    if (cmt_commit_to_proto(block->last_commit, &pbc) != CMT_OK ||
        cmt_pb_commit_marshal(&pbc, s->buf, s->buf_cap, &n) != CMT_OK) {
        return CMT_FAULT;
    }
    key_block_commit(height - 1, key);
    if (nodus_cmt_store_set(s, false, key, s->buf, n) != CMT_OK) {
        return CMT_FAULT;
    }
    /* :575-579 the seen commit under SC:<h> */
    if (cmt_commit_to_proto(seen_commit, &pbc) != CMT_OK ||
        cmt_pb_commit_marshal(&pbc, s->buf, s->buf_cap, &n) != CMT_OK) {
        return CMT_FAULT;
    }
    key_seen_commit(height, key);
    if (nodus_cmt_store_set(s, false, key, s->buf, n) != CMT_OK) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_bs_save_block(nodus_cmt_store_t *s, cmt_block_t *block,
                            const cmt_part_set_t *parts,
                            const cmt_commit_t *seen_commit,
                            uint8_t *scratch, size_t scratch_cap)
{
    int rc;

    if (!s || !block) {
        return CMT_FAULT;                                            /* :450-452 */
    }
    if (batch_begin(s) != CMT_OK) {                                  /* :454 */
        return CMT_FAULT;
    }
    rc = save_block_to_batch(s, block, parts, seen_commit, scratch, scratch_cap);
    if (rc != CMT_OK) {                                              /* :457-459 panic */
        batch_abort(s);
        return CMT_FAULT;
    }
    s->height = block->header.height;                                /* :463 */
    if (s->base == 0) {                                              /* :464-466 */
        s->base = block->header.height;
    }
    rc = save_state_and_write_db(s, "failed to save block");         /* :469 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return CMT_FAULT;                                            /* :471 panic */
    }
    return CMT_OK;
}

int nodus_cmt_bs_save_block_with_extended_commit(
        nodus_cmt_store_t *s, cmt_block_t *block, const cmt_part_set_t *parts,
        const cmt_extended_commit_t *seen_ext_commit,
        cmt_commit_sig_t *commit_sigs, size_t commit_sigs_cap,
        uint8_t *scratch, size_t scratch_cap)
{
    cmt_commit_t             commit;
    cmt_pb_extended_commit_t pbec;
    char                     key[NODUS_CMT_STORE_KEY_MAX];
    size_t                   n = 0;
    int64_t                  height;
    int                      rc;

    if (!s || !block || !seen_ext_commit) {
        return CMT_FAULT;                                            /* :481-483 */
    }
    if (cmt_extended_commit_ensure_extensions(seen_ext_commit, true) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "problems saving block with extensions");
        return CMT_FAULT;                                            /* :484-486 panic */
    }
    memset(&commit, 0, sizeof(commit));
    commit.signatures = commit_sigs;
    commit.signatures_cap = commit_sigs_cap;
    if (cmt_extended_commit_to_commit(seen_ext_commit, commit_sigs,
                                      commit_sigs_cap, &commit) != CMT_OK) {
        return CMT_FAULT;                                            /* :491 */
    }
    if (batch_begin(s) != CMT_OK) {                                  /* :488 */
        return CMT_FAULT;
    }
    rc = save_block_to_batch(s, block, parts, &commit, scratch, scratch_cap);
    if (rc != CMT_OK) {                                              /* :491-493 */
        batch_abort(s);
        return CMT_FAULT;
    }
    height = block->header.height;                                   /* :494 */
    /* :496-500 EC:<h> */
    if (cmt_extended_commit_to_proto(seen_ext_commit, &pbec) != CMT_OK ||
        cmt_pb_extended_commit_marshal(&pbec, s->buf, s->buf_cap, &n)
            != CMT_OK) {
        batch_abort(s);
        return CMT_FAULT;
    }
    key_ext_commit(height, key);
    if (nodus_cmt_store_set(s, false, key, s->buf, n) != CMT_OK) {
        batch_abort(s);
        return CMT_FAULT;
    }
    s->height = height;                                              /* :504 */
    if (s->base == 0) {                                              /* :505-507 */
        s->base = height;
    }
    rc = save_state_and_write_db(s, "failed to save block with extended commit");
    if (rc != CMT_OK) {                                              /* :511-513 */
        batch_abort(s);
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_bs_save_seen_commit(nodus_cmt_store_t *s, int64_t height,
                                  const cmt_commit_t *seen_commit,
                                  uint8_t *scratch, size_t scratch_cap)
{
    cmt_pb_commit_t pbc;
    char            key[NODUS_CMT_STORE_KEY_MAX];
    size_t          n = 0;

    if (!s || !seen_commit || !scratch) {
        return CMT_FAULT;
    }
    if (cmt_commit_to_proto(seen_commit, &pbc) != CMT_OK ||
        cmt_pb_commit_marshal(&pbc, scratch, scratch_cap, &n) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "unable to marshal commit");
        return CMT_REJECT;                                           /* :620-622 */
    }
    key_seen_commit(height, key);
    return nodus_cmt_store_set(s, false, key, scratch, n);          /* :623 */
}

int nodus_cmt_bs_prune_blocks(nodus_cmt_store_t *s, int64_t height,
                              const cmt_state_t *state,
                              uint64_t *out_pruned,
                              int64_t *out_evidence_point)
{
    int64_t  base, h, evidence_point;
    uint64_t pruned = 0;
    char     key[NODUS_CMT_STORE_KEY_MAX];
    nodus_cmt_block_meta_t *meta;
    int      rc;

    if (!s || !state || !out_pruned || !out_evidence_point) {
        return CMT_FAULT;
    }
    *out_pruned = 0;
    *out_evidence_point = -1;
    if (height <= 0) {                                               /* :348-350 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "height must be greater than 0");
        return CMT_REJECT;
    }
    if (height > s->height) {                                        /* :352-355 */
        QGP_LOG_ERROR(LOG_TAG, "cannot prune beyond the latest height %" PRId64,
                      s->height);
        return CMT_REJECT;
    }
    base = s->base;                                                  /* :356 */
    if (height < base) {                                             /* :358-361 */
        QGP_LOG_ERROR(LOG_TAG, "cannot prune to height %" PRId64 ", it is "
                      "lower than base height %" PRId64, height, base);
        return CMT_REJECT;
    }

    meta = (nodus_cmt_block_meta_t *)malloc(sizeof(*meta));
    if (!meta) {
        return CMT_FAULT;
    }
    if (batch_begin(s) != CMT_OK) {                                  /* :364 */
        free(meta);
        return CMT_FAULT;
    }
    evidence_point = height;                                         /* :376 */
    for (h = base; h < height; h++) {                                /* :377 */
        bool     found = false;
        uint32_t p, total;

        rc = nodus_cmt_bs_load_block_meta(s, h, meta, &found);       /* :379 */
        if (rc != CMT_OK) {
            batch_abort(s);
            free(meta);
            return rc;
        }
        if (!found) {
            continue;                                                /* :380-382 */
        }
        /* :387-389 */
        if (evidence_point == height &&
            !nodus_cmt_is_evidence_expired(state->last_block_height,
                                           state->last_block_time, h,
                                           meta->header.time,
                                           &state->consensus_params.evidence)) {
            evidence_point = h;
        }
        rc = CMT_OK;
        if (h < evidence_point) {                                    /* :392-396 */
            key_block_meta(h, key);
            rc = nodus_cmt_store_delete(s, false, key);
        }
        if (rc == CMT_OK) {                                          /* :397-399 */
            key_block_hash(meta->block_id.hash, meta->block_id.hash_len, key);
            rc = nodus_cmt_store_delete(s, false, key);
        }
        if (rc == CMT_OK && h < evidence_point) {                    /* :401-405 */
            key_block_commit(h, key);
            rc = nodus_cmt_store_delete(s, false, key);
        }
        if (rc == CMT_OK) {                                          /* :406-408 */
            key_seen_commit(h, key);
            rc = nodus_cmt_store_delete(s, false, key);
        }
        if (rc == CMT_OK && h < evidence_point) {                    /* :410-415 */
            key_ext_commit(h, key);
            rc = nodus_cmt_store_delete(s, false, key);
        }
        total = meta->block_id.part_set_header.total;
        for (p = 0; rc == CMT_OK && p < total; p++) {                /* :417-421 */
            key_block_part(h, (int)p, key);
            rc = nodus_cmt_store_delete(s, false, key);
        }
        if (rc != CMT_OK) {
            batch_abort(s);
            free(meta);
            return CMT_FAULT;
        }
        pruned++;                                                    /* :422 */

        if (pruned % 1000 == 0 && pruned > 0) {                      /* :425-432 */
            /* :366-374 flush: base first, then the batch. */
            s->base = h;
            rc = save_state_and_write_db(s, "failed to prune");
            if (rc != CMT_OK) {
                batch_abort(s);
                free(meta);
                return CMT_FAULT;
            }
            if (batch_begin(s) != CMT_OK) {
                free(meta);
                return CMT_FAULT;
            }
        }
    }
    free(meta);
    s->base = height;                                                /* :435 flush */
    rc = save_state_and_write_db(s, "failed to prune");
    if (rc != CMT_OK) {
        batch_abort(s);
        return CMT_FAULT;
    }
    *out_pruned = pruned;
    *out_evidence_point = evidence_point;                            /* :439 */
    return CMT_OK;
}

int nodus_cmt_bs_delete_latest_block(nodus_cmt_store_t *s)
{
    int64_t target;
    char    key[NODUS_CMT_STORE_KEY_MAX];
    bool    found = false;
    int     rc;
    nodus_cmt_block_meta_t *meta;

    if (!s) {
        return CMT_FAULT;
    }
    target = s->height;                                              /* :732 */
    meta = (nodus_cmt_block_meta_t *)malloc(sizeof(*meta));
    if (!meta) {
        return CMT_FAULT;
    }
    if (batch_begin(s) != CMT_OK) {                                  /* :735 */
        free(meta);
        return CMT_FAULT;
    }
    rc = nodus_cmt_bs_load_block_meta(s, target, meta, &found);      /* :740 */
    if (rc != CMT_OK) {
        batch_abort(s);
        free(meta);
        return rc;
    }
    if (found) {
        uint32_t p, total = meta->block_id.part_set_header.total;

        key_block_hash(meta->block_id.hash, meta->block_id.hash_len, key);
        rc = nodus_cmt_store_delete(s, false, key);                  /* :741 */
        for (p = 0; rc == CMT_OK && p < total; p++) {                /* :744-748 */
            key_block_part(target, (int)p, key);
            rc = nodus_cmt_store_delete(s, false, key);
        }
    }
    free(meta);
    if (rc == CMT_OK) {                                              /* :750 */
        key_block_commit(target, key);
        rc = nodus_cmt_store_delete(s, false, key);
    }
    if (rc == CMT_OK) {                                              /* :753 */
        key_seen_commit(target, key);
        rc = nodus_cmt_store_delete(s, false, key);
    }
    if (rc == CMT_OK) {                                              /* :757 */
        key_block_meta(target, key);
        rc = nodus_cmt_store_delete(s, false, key);
    }
    if (rc != CMT_OK) {
        batch_abort(s);
        return CMT_FAULT;
    }
    s->height = target - 1;                                          /* :763 */
    rc = save_state_and_write_db(s, "failed to delete the latest block"); /* :764 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* ── state/store.go ──────────────────────────────────────────────────── */

/* Bind the module's proto-side validator storage into a cmt_pb_state_t. */
static void pb_state_bind(nodus_cmt_store_t *s, cmt_pb_state_t *pb)
{
    memset(pb, 0, sizeof(*pb));
    pb->next_validators.validators = s->pb_vals[0];
    pb->next_validators.validators_cap = CMT_VALSET_MAX;
    pb->validators.validators = s->pb_vals[1];
    pb->validators.validators_cap = CMT_VALSET_MAX;
    pb->last_validators.validators = s->pb_vals[2];
    pb->last_validators.validators_cap = CMT_VALSET_MAX;
    cmt_pb_store_state_init(pb);
}

/* :158-181 loadState */
static int load_state(nodus_cmt_store_t *s, const char *key, cmt_state_t *out)
{
    const uint8_t *v;
    size_t         n;
    cmt_pb_state_t *pb;
    int            rc;

    if (nodus_cmt_store_get(s, true, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;                                            /* :160-162 */
    }
    if (n == 0) {
        return CMT_OK;                                               /* :163-165 */
    }
    pb = (cmt_pb_state_t *)malloc(sizeof(*pb));
    if (!pb) {
        return CMT_FAULT;
    }
    pb_state_bind(s, pb);
    if (cmt_pb_store_state_unmarshal(v, n, pb) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "LoadState: Data has been corrupted or "
                      "its spec has changed");
        free(pb);
        return CMT_FAULT;                                            /* :172-173 Exit */
    }
    rc = cmt_pb_store_state_to_c(pb, out);                           /* :176 */
    free(pb);
    if (rc != CMT_OK) {
        return CMT_REJECT;                                           /* :177-179 */
    }
    return CMT_OK;
}

int nodus_cmt_ss_load(nodus_cmt_store_t *s, cmt_state_t *out)
{
    if (!s || !out || !out->storage) {
        return CMT_FAULT;
    }
    /* :158 `(state State, err error)` — the zero State, EMPTY. */
    if (cmt_state_init(out, out->storage) != CMT_OK) {
        return CMT_FAULT;
    }
    return load_state(s, KEY_STATE, out);                            /* :155 */
}

int nodus_cmt_ss_load_from_db_or_genesis_doc(nodus_cmt_store_t *s,
                                             cmt_genesis_doc_t *genesis_doc,
                                             cmt_now_fn now, void *now_ctx,
                                             cmt_valset_scratch_t *scratch,
                                             cmt_state_t *out)
{
    int rc;

    if (!s || !genesis_doc || !scratch || !out) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_ss_load(s, out);                                  /* :137 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (cmt_state_is_empty(out)) {                                   /* :142 */
        rc = cmt_state_make_genesis(genesis_doc, now, now_ctx, scratch, out); /* :144 */
        if (rc != CMT_OK) {
            return rc;
        }
    }
    return CMT_OK;
}

/* :621-649 saveValidatorsInfo */
static int save_validators_info(nodus_cmt_store_t *s, int64_t height,
                                int64_t last_height_changed,
                                const cmt_validator_set_t *val_set)
{
    cmt_pb_validators_info_t *vi;
    char   key[NODUS_CMT_STORE_KEY_MAX];
    size_t n = 0;
    int    rc;

    if (last_height_changed > height) {                              /* :622-624 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "lastHeightChanged cannot be greater "
                      "than ValidatorsInfo height");
        return CMT_REJECT;
    }
    vi = (cmt_pb_validators_info_t *)malloc(sizeof(*vi));
    if (!vi) {
        return CMT_FAULT;
    }
    memset(vi, 0, sizeof(*vi));
    vi->validator_set.validators = s->pb_vals[0];
    vi->validator_set.validators_cap = CMT_VALSET_MAX;
    cmt_pb_store_validators_info_init(vi);
    vi->last_height_changed = last_height_changed;                   /* :626 */
    if (height == last_height_changed ||
        height % NODUS_CMT_VALSET_CHECKPOINT_INTERVAL == 0) {        /* :630 */
        rc = cmt_validator_set_to_proto(val_set, &vi->validator_set); /* :631 */
        if (rc != CMT_OK) {
            free(vi);
            return rc;
        }
        vi->has_validator_set = true;                                /* :635 */
    }
    rc = cmt_pb_store_validators_info_marshal(vi, s->buf, s->buf_cap, &n); /* :638 */
    free(vi);
    if (rc != CMT_OK) {
        return rc;
    }
    key_validators(height, key);
    return nodus_cmt_store_set(s, true, key, s->buf, n);            /* :643 */
}

/* :707-726 saveConsensusParamsInfo */
static int save_consensus_params_info(nodus_cmt_store_t *s, int64_t next_height,
                                      int64_t change_height,
                                      const cmt_consensus_params_t *params)
{
    cmt_pb_consensus_params_info_t pi;
    char   key[NODUS_CMT_STORE_KEY_MAX];
    size_t n = 0;
    int    rc;

    cmt_pb_store_consensus_params_info_init(&pi);
    pi.last_height_changed = change_height;                          /* :709 */
    if (change_height == next_height) {                              /* :712-714 */
        rc = cmt_pb_store_consensus_params_from_c(params, &pi.consensus_params);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    rc = cmt_pb_store_consensus_params_info_marshal(&pi, s->buf, s->buf_cap, &n);
    if (rc != CMT_OK) {
        return rc;                                                   /* :716-718 */
    }
    key_consensus_params(next_height, key);
    return nodus_cmt_store_set(s, true, key, s->buf, n);            /* :720 */
}

/* `state.Bytes()` (state.go:116-126) into s->buf. */
static int state_bytes(nodus_cmt_store_t *s, const cmt_state_t *state,
                       size_t *out_len)
{
    cmt_pb_state_t *pb = (cmt_pb_state_t *)malloc(sizeof(*pb));
    int rc;

    if (!pb) {
        return CMT_FAULT;
    }
    pb_state_bind(s, pb);
    rc = cmt_pb_store_state_from_c(state, pb);                       /* :117 */
    if (rc == CMT_OK) {
        rc = cmt_pb_store_state_marshal(pb, s->buf, s->buf_cap, out_len); /* :121 */
    }
    free(pb);
    return rc == CMT_OK ? CMT_OK : CMT_FAULT;                        /* :119, :123 panic */
}

/* :189-223 save */
static int save_state(nodus_cmt_store_t *s, const cmt_state_t *state,
                      const char *key)
{
    int64_t next_height;
    size_t  n = 0;
    int     rc;

    if (batch_begin(s) != CMT_OK) {                                  /* :190 */
        return CMT_FAULT;
    }
    next_height = state->last_block_height + 1;                      /* :197 */
    if (next_height == 1) {                                          /* :199 */
        next_height = state->initial_height;                         /* :200 */
        rc = save_validators_info(s, next_height, next_height,
                                  &state->validators);               /* :203 */
        if (rc != CMT_OK) {
            batch_abort(s);
            return rc;
        }
    }
    rc = save_validators_info(s, next_height + 1,
                              state->last_height_validators_changed,
                              &state->next_validators);              /* :208 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return rc;
    }
    rc = save_consensus_params_info(s, next_height,
                                    state->last_height_consensus_params_changed,
                                    &state->consensus_params);       /* :212 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return rc;
    }
    rc = state_bytes(s, state, &n);                                  /* :216 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return rc;
    }
    if (nodus_cmt_store_set(s, true, key, s->buf, n) != CMT_OK) {
        batch_abort(s);
        return CMT_FAULT;
    }
    if (batch_write(s) != CMT_OK) {                                  /* :219 panic */
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_ss_save(nodus_cmt_store_t *s, const cmt_state_t *state)
{
    if (!s || !state) {
        return CMT_FAULT;
    }
    return save_state(s, state, KEY_STATE);                          /* :186 */
}

int nodus_cmt_ss_bootstrap(nodus_cmt_store_t *s, const cmt_state_t *state)
{
    int64_t height;
    size_t  n = 0;
    int     rc;

    if (!s || !state) {
        return CMT_FAULT;
    }
    if (batch_begin(s) != CMT_OK) {                                  /* :227 */
        return CMT_FAULT;
    }
    height = state->last_block_height + 1;                           /* :234 */
    if (height == 1) {                                               /* :235-237 */
        height = state->initial_height;
    }
    if (height > 1 && !cmt_validator_set_is_nil_or_empty(&state->last_validators)) {
        rc = save_validators_info(s, height - 1, height - 1,
                                  &state->last_validators);          /* :240 */
        if (rc != CMT_OK) {
            batch_abort(s);
            return rc;
        }
    }
    rc = save_validators_info(s, height, height, &state->validators); /* :245 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return rc;
    }
    rc = save_validators_info(s, height + 1, height + 1,
                              &state->next_validators);              /* :249 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return rc;
    }
    rc = save_consensus_params_info(s, height,
                                    state->last_height_consensus_params_changed,
                                    &state->consensus_params);       /* :253 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return rc;
    }
    rc = state_bytes(s, state, &n);                                  /* :258 */
    if (rc != CMT_OK) {
        batch_abort(s);
        return rc;
    }
    if (nodus_cmt_store_set(s, true, KEY_STATE, s->buf, n) != CMT_OK) {
        batch_abort(s);
        return CMT_FAULT;
    }
    if (batch_write(s) != CMT_OK) {                                  /* :262 panic */
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* :594-614 loadValidatorsInfo — CMT_REJECT for "value retrieved from db
 * is empty" (:601), CMT_FAULT for the Exit (:608). */
static int load_validators_info(nodus_cmt_store_t *s, int64_t height,
                                cmt_pb_validator_t *vals_storage,
                                cmt_pb_validators_info_t *out)
{
    const uint8_t *v;
    size_t         n;
    char           key[NODUS_CMT_STORE_KEY_MAX];

    key_validators(height, key);
    if (nodus_cmt_store_get(s, true, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;
    }
    if (n == 0) {
        return CMT_REJECT;
    }
    memset(out, 0, sizeof(*out));
    out->validator_set.validators = vals_storage;
    out->validator_set.validators_cap = CMT_VALSET_MAX;
    if (cmt_pb_store_validators_info_unmarshal(v, n, out) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "LoadValidators: Data has been "
                      "corrupted or its spec has changed");
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_ss_load_validators(nodus_cmt_store_t *s, int64_t height,
                                 cmt_validator_set_t *out)
{
    cmt_pb_validators_info_t *vi;
    int rc;

    if (!s || !out) {
        return CMT_FAULT;
    }
    vi = (cmt_pb_validators_info_t *)malloc(sizeof(*vi));
    if (!vi) {
        return CMT_FAULT;
    }
    rc = load_validators_info(s, height, s->pb_vals[0], vi);         /* :549 */
    if (rc != CMT_OK) {
        free(vi);
        return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;             /* :551 */
    }
    if (!vi->has_validator_set) {                                    /* :553 */
        int64_t last_stored = nodus_cmt_last_stored_height_for(
            height, vi->last_height_changed);                        /* :554 */
        int32_t times = 0;

        rc = load_validators_info(s, last_stored, s->pb_vals[1], vi); /* :555 */
        if (rc == CMT_FAULT) {
            free(vi);
            return CMT_FAULT;
        }
        if (rc != CMT_OK || !vi->has_validator_set) {                /* :556-563 */
            QGP_LOG_ERROR(LOG_TAG, "couldn't find validators at height %" PRId64
                          " (height %" PRId64 " was originally requested)",
                          last_stored, height);
            free(vi);
            return CMT_REJECT;
        }
        rc = cmt_validator_set_from_proto(&vi->validator_set, out);  /* :565 */
        if (rc != CMT_OK) {
            free(vi);
            return CMT_REJECT;
        }
        if (safe_convert_int32(height - last_stored, &times) != CMT_OK) {
            free(vi);
            return CMT_FAULT;                 /* safemath.go:37-40 panic */
        }
        rc = cmt_validator_set_increment_proposer_priority(out, times); /* :570 */
        if (rc != CMT_OK) {
            free(vi);
            return rc;
        }
        /* :571-577 — back through the proto form, exactly as the
         * reference does before the final FromProto. */
        vi->validator_set.validators = s->pb_vals[2];
        vi->validator_set.validators_cap = CMT_VALSET_MAX;
        rc = cmt_validator_set_to_proto(out, &vi->validator_set);
        if (rc != CMT_OK) {
            free(vi);
            return CMT_REJECT;
        }
        vi->has_validator_set = true;
    }
    rc = cmt_validator_set_from_proto(&vi->validator_set, out);      /* :580 */
    free(vi);
    return rc == CMT_OK ? CMT_OK : CMT_REJECT;
}

/* :683-701 loadConsensusParamsInfo — CMT_REJECT for "value retrieved
 * from db is empty" (:689), CMT_FAULT for the Exit (:695). */
static int load_consensus_params_info(nodus_cmt_store_t *s, int64_t height,
                                      cmt_pb_consensus_params_info_t *out)
{
    const uint8_t *v;
    size_t         n;
    char           key[NODUS_CMT_STORE_KEY_MAX];

    key_consensus_params(height, key);
    if (nodus_cmt_store_get(s, true, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;
    }
    if (n == 0) {
        return CMT_REJECT;
    }
    if (cmt_pb_store_consensus_params_info_unmarshal(v, n, out) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "LoadConsensusParams: Data has been "
                      "corrupted or its spec has changed");
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_ss_load_consensus_params(nodus_cmt_store_t *s, int64_t height,
                                       cmt_consensus_params_t *out)
{
    cmt_pb_consensus_params_info_t pi;
    int rc;

    if (!s || !out) {
        return CMT_FAULT;
    }
    rc = load_consensus_params_info(s, height, &pi);                 /* :661 */
    if (rc != CMT_OK) {
        if (rc != CMT_FAULT) {
            QGP_LOG_ERROR(LOG_TAG, "could not find consensus params for "
                          "height #%" PRId64, height);
        }
        return rc;                                                   /* :663 */
    }
    if (cmt_pb_store_consensus_params_is_empty(&pi.consensus_params)) { /* :666 */
        int64_t changed = pi.last_height_changed;

        rc = load_consensus_params_info(s, changed, &pi);            /* :667 */
        if (rc != CMT_OK) {
            if (rc != CMT_FAULT) {
                QGP_LOG_ERROR(LOG_TAG, "couldn't find consensus params at "
                              "height %" PRId64 " as last changed from height %"
                              PRId64, changed, height);
            }
            return rc;                                               /* :668-675 */
        }
    }
    rc = cmt_pb_store_consensus_params_to_c(&pi.consensus_params, out); /* :680 */
    return rc == CMT_OK ? CMT_OK : CMT_REJECT;
}

int nodus_cmt_ss_prune_states(nodus_cmt_store_t *s, int64_t from, int64_t to,
                              int64_t evidence_threshold_height,
                              cmt_validator_t *vals_storage, size_t vals_cap,
                              cmt_valset_scratch_t *scratch)
{
    cmt_pb_validators_info_t       *vi;
    cmt_pb_consensus_params_info_t  pi;
    int64_t  keep_vals_a = -1, keep_vals_b = -1, keep_params = -1;
    int64_t  h;
    uint64_t pruned = 0;
    char     key[NODUS_CMT_STORE_KEY_MAX];
    int      rc;

    (void)scratch;
    if (!s || !vals_storage) {
        return CMT_FAULT;
    }
    if (from <= 0 || to <= 0) {                                      /* :278-280 */
        QGP_LOG_ERROR(LOG_TAG, "from height %" PRId64 " and to height %" PRId64
                      " must be greater than 0", from, to);
        return CMT_REJECT;
    }
    if (from >= to) {                                                /* :281-283 */
        QGP_LOG_ERROR(LOG_TAG, "from height %" PRId64 " must be lower than to "
                      "height %" PRId64, from, to);
        return CMT_REJECT;
    }
    vi = (cmt_pb_validators_info_t *)malloc(sizeof(*vi));
    if (!vi) {
        return CMT_FAULT;
    }
    rc = load_validators_info(s, min_int64(to, evidence_threshold_height),
                              s->pb_vals[0], vi);                    /* :285 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "validators at height %" PRId64 " not found", to);
        free(vi);
        return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
    }
    rc = load_consensus_params_info(s, to, &pi);                     /* :289 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "consensus params at height %" PRId64 " not found",
                      to);
        free(vi);
        return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
    }
    /* :294-298 keepVals — a two-entry set. */
    if (!vi->has_validator_set) {
        keep_vals_a = vi->last_height_changed;
        keep_vals_b = nodus_cmt_last_stored_height_for(to, vi->last_height_changed);
    }
    /* :299-302 keepParams */
    if (cmt_pb_store_consensus_params_is_empty(&pi.consensus_params)) {
        keep_params = pi.last_height_changed;
    }

    if (batch_begin(s) != CMT_OK) {                                  /* :304 */
        free(vi);
        return CMT_FAULT;
    }
    for (h = to - 1; h >= from; h--) {                               /* :310 */
        bool keep_v = (h == keep_vals_a || h == keep_vals_b);
        bool keep_p = (h == keep_params);

        if (keep_v) {                                                /* :314 */
            rc = load_validators_info(s, h, s->pb_vals[1], vi);      /* :315 */
            if (rc == CMT_FAULT) {
                goto fault;
            }
            if (rc != CMT_OK || !vi->has_validator_set) {            /* :316 */
                cmt_validator_set_t vs;
                size_t n = 0;

                if (cmt_validator_set_init(&vs, vals_storage, vals_cap) != CMT_OK) {
                    goto fault;
                }
                rc = nodus_cmt_ss_load_validators(s, h, &vs);        /* :317 */
                if (rc != CMT_OK) {
                    goto out_rc;
                }
                memset(vi, 0, sizeof(*vi));
                vi->validator_set.validators = s->pb_vals[1];
                vi->validator_set.validators_cap = CMT_VALSET_MAX;
                cmt_pb_store_validators_info_init(vi);
                rc = cmt_validator_set_to_proto(&vs, &vi->validator_set); /* :322 */
                if (rc != CMT_OK) {
                    goto out_rc;
                }
                vi->has_validator_set = true;                        /* :327 */
                vi->last_height_changed = h;                         /* :328 */
                rc = cmt_pb_store_validators_info_marshal(vi, s->buf,
                                                          s->buf_cap, &n); /* :330 */
                if (rc != CMT_OK) {
                    goto out_rc;
                }
                key_validators(h, key);
                if (nodus_cmt_store_set(s, true, key, s->buf, n) != CMT_OK) {
                    goto fault;                                      /* :334 */
                }
            }
        } else if (h < evidence_threshold_height) {                  /* :339 */
            key_validators(h, key);
            if (nodus_cmt_store_delete(s, true, key) != CMT_OK) {
                goto fault;                                          /* :340 */
            }
        }
        /* :345-346 else keep for evidence verification */

        if (keep_p) {                                                /* :348 */
            rc = load_consensus_params_info(s, h, &pi);              /* :349 */
            if (rc != CMT_OK) {
                goto out_rc;
            }
            if (cmt_pb_store_consensus_params_is_empty(&pi.consensus_params)) { /* :354 */
                cmt_consensus_params_t params;
                size_t n = 0;

                rc = nodus_cmt_ss_load_consensus_params(s, h, &params); /* :355 */
                if (rc != CMT_OK) {
                    goto out_rc;
                }
                rc = cmt_pb_store_consensus_params_from_c(&params,
                                                          &pi.consensus_params); /* :359 */
                if (rc != CMT_OK) {
                    goto out_rc;
                }
                pi.last_height_changed = h;                          /* :361 */
                rc = cmt_pb_store_consensus_params_info_marshal(&pi, s->buf,
                                                                s->buf_cap, &n); /* :362 */
                if (rc != CMT_OK) {
                    goto out_rc;
                }
                key_consensus_params(h, key);
                if (nodus_cmt_store_set(s, true, key, s->buf, n) != CMT_OK) {
                    goto fault;                                      /* :367 */
                }
            }
        } else {                                                     /* :372 */
            key_consensus_params(h, key);
            if (nodus_cmt_store_delete(s, true, key) != CMT_OK) {
                goto fault;                                          /* :373 */
            }
        }

        key_abci_responses(h, key);
        if (nodus_cmt_store_delete(s, true, key) != CMT_OK) {
            goto fault;                                              /* :379 */
        }
        pruned++;                                                    /* :383 */

        if (pruned % 1000 == 0 && pruned > 0) {                      /* :386-394 */
            if (batch_write(s) != CMT_OK) {
                goto fault_nb;
            }
            if (batch_begin(s) != CMT_OK) {
                goto fault_nb;
            }
        }
    }
    if (batch_write(s) != CMT_OK) {                                  /* :397 */
        goto fault_nb;
    }
    free(vi);
    return CMT_OK;

out_rc:
    batch_abort(s);
    free(vi);
    return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
fault:
    batch_abort(s);
fault_nb:
    free(vi);
    return CMT_FAULT;
}

int nodus_cmt_ss_tx_results_hash(const cmt_pb_exec_tx_result_t *tx_results,
                                 size_t n, cmt_abci_results_t *results,
                                 uint8_t *leaf_scratch, size_t leaf_cap,
                                 cmt_merkle_item_t *items, size_t items_cap,
                                 uint8_t out[CMT_TMHASH_SIZE])
{
    int rc;

    if (!results || !out || (!tx_results && n)) {
        return CMT_FAULT;
    }
    rc = cmt_new_results(tx_results, n, results);                    /* :412 */
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_abci_results_hash(results, leaf_scratch, leaf_cap, items,
                                 items_cap, out);                    /* :412 Hash */
}

int nodus_cmt_ss_load_finalize_block_response(nodus_cmt_store_t *s,
                                              int64_t height,
                                              cmt_pb_rfb_storage_t *storage,
                                              cmt_pb_response_finalize_block_t *out)
{
    const uint8_t *v;
    size_t         n;
    char           key[NODUS_CMT_STORE_KEY_MAX];
    int            rc;

    if (!s || !storage || !out) {
        return CMT_FAULT;
    }
    if (s->discard_abci_responses) {                                 /* :419-421 */
        return CMT_REJECT;
    }
    key_abci_responses(height, key);
    if (nodus_cmt_store_get(s, true, key, &v, &n) != CMT_OK) {
        return CMT_FAULT;                                            /* :423-426 */
    }
    if (n == 0) {
        return CMT_REJECT;                                           /* :427-429 */
    }
    rc = cmt_pb_store_response_finalize_block_unmarshal(v, n, out, storage); /* :432 */
    if (rc != CMT_OK || out->app_hash_len == 0) {                    /* :440 */
        /* The legacy branch (:441-452): this chain has none. */
        QGP_LOG_ERROR(LOG_TAG, "abciResponsesKey:%" PRId64 " is not a "
                      "ResponseFinalizeBlock with an app hash — no legacy "
                      "format in this chain", height);
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_ss_load_last_finalize_block_response(
        nodus_cmt_store_t *s, int64_t height, cmt_pb_rfb_storage_t *storage,
        cmt_pb_response_finalize_block_t *out)
{
    const uint8_t *v;
    size_t         n;
    cmt_pb_abci_responses_info_t *info;
    int            rc;

    if (!s || !storage || !out) {
        return CMT_FAULT;
    }
    if (nodus_cmt_store_get(s, true, KEY_LAST_ABCI, &v, &n) != CMT_OK) {
        return CMT_FAULT;                                            /* :467-470 */
    }
    if (n == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "no last ABCI response has been persisted");
        return CMT_REJECT;                                           /* :472-474 */
    }
    info = (cmt_pb_abci_responses_info_t *)malloc(sizeof(*info));
    if (!info) {
        return CMT_FAULT;
    }
    rc = cmt_pb_store_abci_responses_info_unmarshal(v, n, info, storage); /* :477 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "LoadLastFinalizeBlockResponse: Data has "
                      "been corrupted or its spec has changed");
        free(info);
        return CMT_FAULT;                                            /* :479 Exit */
    }
    if (height != info->height) {                                    /* :484-486 */
        QGP_LOG_ERROR(LOG_TAG, "expected height %" PRId64 " but last stored abci "
                      "responses was at height %" PRId64, height, info->height);
        free(info);
        return CMT_REJECT;
    }
    if (!info->has_response_finalize_block) {                        /* :491-497 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "state store contains last abci response "
                      "but it is empty — no legacy format in this chain");
        free(info);
        return CMT_FAULT;
    }
    *out = info->response_finalize_block;                            /* :499 */
    free(info);
    return CMT_OK;
}

int nodus_cmt_ss_save_finalize_block_response(
        nodus_cmt_store_t *s, int64_t height,
        const cmt_pb_response_finalize_block_t *resp)
{
    cmt_pb_abci_responses_info_t info;
    char   key[NODUS_CMT_STORE_KEY_MAX];
    size_t need, n = 0;
    int    rc;

    if (!s || !resp) {
        return CMT_FAULT;
    }
    /* ABCIResponsesInfo's own two fields (height, a frame) on top of the
     * response's bound. No reference line: Go marshals into a growing
     * slice. `s->buf` is `cmt_pb_store_state_upper_bound(CMT_VALSET_MAX)`
     * bytes (nodus_cmt_store_init) and the response is THIS NODE'S OWN
     * PRODUCT — the engine's ExecTxResults and validator updates out of
     * FinalizeBlock (execution.go:259), never a peer's bytes — so a
     * response wider than the bound is a NODE-LOCAL invariant broken
     * (the bound or the engine), not something a peer sent: CMT_FAULT
     * (umbrella rev 5 panic rule), not REJECT. */
    need = 32u + cmt_pb_store_response_finalize_block_upper_bound(resp);
    if (need > s->buf_cap) {
        QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock response needs %zu bytes, the "
                      "store's bound is %zu — this node's invariant", need,
                      s->buf_cap);
        return CMT_FAULT;                 /* wider than the module's scratch */
    }
    if (!s->discard_abci_responses) {                                /* :520 */
        rc = cmt_pb_store_response_finalize_block_marshal(resp, s->buf,
                                                          s->buf_cap, &n); /* :521 */
        if (rc != CMT_OK) {
            return rc;
        }
        key_abci_responses(height, key);
        if (nodus_cmt_store_set(s, true, key, s->buf, n) != CMT_OK) {
            return CMT_FAULT;                                        /* :525 */
        }
    }
    /* :530-541 the last response, always */
    cmt_pb_store_abci_responses_info_init(&info);
    info.height = height;
    info.has_response_finalize_block = true;
    info.response_finalize_block = *resp;
    rc = cmt_pb_store_abci_responses_info_marshal(&info, s->buf, s->buf_cap, &n);
    if (rc != CMT_OK) {
        return rc;
    }
    return nodus_cmt_store_set(s, true, KEY_LAST_ABCI, s->buf, n);   /* :541 */
}

int nodus_cmt_ss_set_offline_state_sync_height(nodus_cmt_store_t *s,
                                               int64_t height)
{
    uint8_t bz[10];
    size_t  n;

    if (!s) {
        return CMT_FAULT;
    }
    n = nodus_cmt_int64_to_bytes(height, bz);
    return nodus_cmt_store_set(s, true, KEY_OFFLINE_SS, bz, n);     /* :729 */
}

/**
 * FLEET-TM-R3 W3 (item 8, R3-C1c-2, CLOSED — was "REPORTED" as both
 * cases returning CMT_REJECT). state/store.go:397-403 (the caller,
 * ported in nodus_witness_cmt_node.c) treats an EMPTY value as absence
 * and tolerates it SILENTLY (height 0, no log, :400) and PANICS on a
 * NEGATIVE stored height (:750-752). The two cases now have distinct
 * returns so the caller can tell them apart without a second store read:
 *   - absent (`n == 0`, store.go:745-747's "value empty"): CMT_OK,
 *     `*out = 0`, no log — the caller's ordinary "no state-sync height
 *     recorded" path, unchanged in outcome from before this fix.
 *   - a genuinely unreadable store row: CMT_FAULT, as before.
 *   - a NEGATIVE decoded height (store.go:750-752): CMT_FAULT — the
 *     reference's panic, translated as this node's own state
 *     contradicting itself, not a peer's doing.
 */
int nodus_cmt_ss_get_offline_state_sync_height(nodus_cmt_store_t *s,
                                               int64_t *out)
{
    const uint8_t *v;
    size_t         n;
    int64_t        h;

    if (!s || !out) {
        return CMT_FAULT;
    }
    if (nodus_cmt_store_get(s, true, KEY_OFFLINE_SS, &v, &n) != CMT_OK) {
        return CMT_FAULT;                                            /* :740-743 */
    }
    if (n == 0) {
        *out = 0;                                                    /* :745-747, silent */
        return CMT_OK;
    }
    h = nodus_cmt_int64_from_bytes(v, n);                            /* :749 */
    if (h < 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "invalid value for height: height "
                      "cannot be negative");
        return CMT_FAULT;                                            /* :750-752, panic */
    }
    *out = h;
    return CMT_OK;
}
