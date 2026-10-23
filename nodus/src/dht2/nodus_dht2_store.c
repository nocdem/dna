/**
 * Nodus — DHT v2: the holder store and admission (package 5).
 * See nodus_dht2_store.h for the contract and the governing records.
 *
 * @file nodus_dht2_store.c
 */

#include "dht2/nodus_dht2_store.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "dht2/dht2_place.h"
#include "dht2/dht2_record.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "DHT2_STORE"

#define CODE_FAULT DHT2_E_HOLDER_FAULT

/* u64 <-> SQLite's signed int64. Every value that is ORDERED or compared in
 * SQL (insertion index, times) is kept ≤ INT64_MAX and refused beyond it
 * (fail closed). Sequence / HANDLED cutoffs may use the whole u64 range; they
 * are stored as the int64 bit pattern and only ever compared in C. Expiry
 * values come from the 20-byte Validity text (≤ 9999-12-31T23:59:59Z =
 * 253,402,300,799), far below INT64_MAX; the snapshot time is bounded by
 * gate(). */
#define TIME_SLACK_MAX (DHT2_SEC_7D + DHT2_SEC_SLACK_3H)

struct nodus_dht2_store {
    sqlite3 *db;
    uint64_t gen;
    uint8_t  chain[DHT2_CHAIN_LEN];     /* recorded at create (G8) */
};

/* One row per ADDRESS (the primary key). `idx` is the insertion index,
 * unique, re-assigned on every stored change (§4.5 i). `named` is the pool
 * the record is charged to; `noexp` is its own flag (ValidityType 1), never
 * encoded in `expiry`. There is NO holder memory of dropped entries
 * (decision 2026-10-24-dht-v2-handled-client-rule.md). dht2_meta
 * `v` has no declared type: integers (top, gen) and the chain id blob. */
static const char SCHEMA_SQL[] =
    "CREATE TABLE IF NOT EXISTS dht2_meta("
    "  k TEXT PRIMARY KEY, v NOT NULL);"
    "CREATE TABLE IF NOT EXISTS dht2_rec("
    "  address   BLOB PRIMARY KEY,"
    "  placement BLOB NOT NULL,"
    "  owner     BLOB NOT NULL,"
    "  cls       INTEGER NOT NULL,"
    "  seq       INTEGER NOT NULL,"
    "  noexp     INTEGER NOT NULL,"
    "  expiry    INTEGER NOT NULL,"
    "  del       INTEGER NOT NULL,"
    "  named     INTEGER NOT NULL,"
    "  handover  INTEGER NOT NULL DEFAULT 0,"
    "  size      INTEGER NOT NULL,"
    "  hash      BLOB NOT NULL,"
    "  canon     BLOB NOT NULL,"
    "  idx       INTEGER NOT NULL UNIQUE);"
    "CREATE INDEX IF NOT EXISTS dht2_rec_owner ON dht2_rec(owner, size);"
    "CREATE INDEX IF NOT EXISTS dht2_rec_pool  ON dht2_rec(named, size);"
    "CREATE INDEX IF NOT EXISTS dht2_rec_place ON dht2_rec(placement, cls, owner);";

/* ══ small SQLite helpers: every error is a fault (-1) ═════════════════ */

static sqlite3_stmt *prep(nodus_dht2_store_t *s, const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(s->db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare: %s", sqlite3_errmsg(s->db));
        return NULL;
    }
    return st;
}

static int exec_sql(nodus_dht2_store_t *s, const char *sql)
{
    char *err = NULL;

    if (sqlite3_exec(s->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "exec: %s", err != NULL ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* Binders return 0 / -1; a failed bind leaves NULL bound, so the callers
 * OR the results together and pass them to bound(), which finalizes the
 * statement on a failure. */
static int b_blob(sqlite3_stmt *st, int i, const void *p, size_t n)
{
    return sqlite3_bind_blob(st, i, p, (int)n, SQLITE_STATIC) == SQLITE_OK
               ? 0 : -1;
}

static int b_i64(sqlite3_stmt *st, int i, int64_t v)
{
    return sqlite3_bind_int64(st, i, v) == SQLITE_OK ? 0 : -1;
}

static int b_text(sqlite3_stmt *st, int i, const char *t)
{
    return sqlite3_bind_text(st, i, t, -1, SQLITE_STATIC) == SQLITE_OK
               ? 0 : -1;
}

static int b_64(sqlite3_stmt *st, int i, const uint8_t *p)
{
    return b_blob(st, i, p, DHT2_HASH_LEN);
}

/* true when every bind succeeded; otherwise logs, finalizes, false. */
static bool bound(sqlite3_stmt *st, int bad)
{
    if (bad != 0) {
        QGP_LOG_ERROR(LOG_TAG, "bind failed");
        sqlite3_finalize(st);
        return false;
    }
    return true;
}

/* Step a statement that must end in SQLITE_DONE, then finalize it. */
static int step_done(nodus_dht2_store_t *s, sqlite3_stmt *st)
{
    int rc = sqlite3_step(st);

    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "step: %s", sqlite3_errmsg(s->db));
        return -1;
    }
    return 0;
}

/* A single-value u64 query. `blob` (64 B) binds to ?1 when non-NULL, `ival`
 * to ?2 when `use_ival`. SUM / COUNT / MAX always return exactly one row. */
static int query_u64(nodus_dht2_store_t *s, const char *sql,
                     const uint8_t *blob, bool use_ival, int64_t ival,
                     uint64_t *out)
{
    sqlite3_stmt *st = prep(s, sql);
    int           rc;

    if (st == NULL) {
        return -1;
    }
    if (!bound(st, (blob != NULL ? b_64(st, 1, blob) : 0) |
                       (use_ival ? b_i64(st, 2, ival) : 0))) {
        return -1;
    }
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "query: %s", sqlite3_errmsg(s->db));
        sqlite3_finalize(st);
        return -1;
    }
    *out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return 0;
}

/* meta: an integer (blob == NULL) or a 32-byte blob (blob != NULL). */
static int meta_get(nodus_dht2_store_t *s, const char *key, uint64_t *out,
                    uint8_t *blob, bool *found)
{
    sqlite3_stmt *st = prep(s, "SELECT v FROM dht2_meta WHERE k = ?1");
    int           rc;

    if (st == NULL) {
        return -1;
    }
    if (!bound(st, b_text(st, 1, key))) {
        return -1;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (blob != NULL) {
            if (sqlite3_column_type(st, 0) != SQLITE_BLOB ||
                sqlite3_column_bytes(st, 0) != (int)DHT2_CHAIN_LEN) {
                QGP_LOG_ERROR(LOG_TAG, "meta %s malformed", key);
                sqlite3_finalize(st);
                return -1;
            }
            memcpy(blob, sqlite3_column_blob(st, 0), DHT2_CHAIN_LEN);
        } else {
            if (sqlite3_column_type(st, 0) != SQLITE_INTEGER) {
                QGP_LOG_ERROR(LOG_TAG, "meta %s malformed", key);
                sqlite3_finalize(st);
                return -1;
            }
            *out = (uint64_t)sqlite3_column_int64(st, 0);
        }
        *found = true;
    } else if (rc == SQLITE_DONE) {
        *found = false;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "meta read: %s", sqlite3_errmsg(s->db));
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

static int meta_set(nodus_dht2_store_t *s, const char *key, uint64_t v)
{
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO dht2_meta(k, v) "
                               "VALUES(?1, ?2)");

    if (st == NULL) {
        return -1;
    }
    if (!bound(st, b_text(st, 1, key) | b_i64(st, 2, (int64_t)v))) {
        return -1;
    }
    return step_done(s, st);
}

static int meta_set_chain(nodus_dht2_store_t *s, const uint8_t *chain)
{
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO dht2_meta(k, v) "
                               "VALUES('chain', ?1)");

    if (st == NULL) {
        return -1;
    }
    if (!bound(st, b_blob(st, 1, chain, DHT2_CHAIN_LEN))) {
        return -1;
    }
    return step_done(s, st);
}

/* ══ open / close ══════════════════════════════════════════════════════ */

void nodus_dht2_limits_default(nodus_dht2_limits_t *out)
{
    if (out == NULL) {
        return;
    }
    out->ident_unnamed = NODUS_DHT2_QUOTA_UNNAMED;
    out->ident_named   = NODUS_DHT2_QUOTA_NAMED;
    out->pool_unnamed  = NODUS_DHT2_NODE_POOL_DEFAULT;
    out->pool_named    = NODUS_DHT2_NODE_POOL_DEFAULT;
}

nodus_dht2_store_t *nodus_dht2_store_open(const char *path,
                                          const uint8_t chain[DHT2_CHAIN_LEN])
{
    nodus_dht2_store_t *s;
    uint64_t            top = 0, gen = 0, n = 0;
    uint8_t             have_chain[DHT2_CHAIN_LEN];
    bool                ft = false, fg = false, fc = false;
    bool                in_txn = false;

    if (path == NULL || chain == NULL) {
        return NULL;
    }
    s = (nodus_dht2_store_t *)calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    if (sqlite3_open_v2(path, &s->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "open %s: %s", path,
                      s->db != NULL ? sqlite3_errmsg(s->db) : "oom");
        goto fail;
    }
    if (exec_sql(s, SCHEMA_SQL) != 0 ||
        exec_sql(s, "BEGIN IMMEDIATE") != 0) {
        goto fail;
    }
    in_txn = true;
    if (meta_get(s, "top", &top, NULL, &ft) != 0 ||
        meta_get(s, "gen", &gen, NULL, &fg) != 0 ||
        meta_get(s, "chain", &n, have_chain, &fc) != 0) {
        goto fail;
    }
    if (!ft && !fg && !fc) {
        /* The create path — and only when no record exists: a store with
         * rows but no counter is damaged, never silently restarted. */
        if (query_u64(s, "SELECT COUNT(*) FROM dht2_rec", NULL, false, 0,
                      &n) != 0 || n != 0) {
            QGP_LOG_ERROR(LOG_TAG, "records without counter: refusing to open");
            goto fail;
        }
        /* Insertion counter: starts at 0, the first index handed out is 1
         * (row 12: top = 0 <=> empty). */
        if (meta_set(s, "top", 0) != 0 || meta_set_chain(s, chain) != 0) {
            goto fail;
        }
        /* Generation g: drawn when the store is created, persisted with it
         * (row 12). A node-local token compared for equality only — it
         * never enters a consensus path, so the platform CSPRNG is the right
         * source. */
        {
            uint8_t rnd[8];
            size_t  i;

            if (qgp_platform_random(rnd, sizeof(rnd)) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "generation: no randomness");
                goto fail;
            }
            gen = 0;
            for (i = 0; i < sizeof(rnd); i++) {
                gen = (gen << 8) | rnd[i];
            }
        }
        if (meta_set(s, "gen", gen) != 0) {
            goto fail;
        }
        memcpy(s->chain, chain, DHT2_CHAIN_LEN);
    } else {
        if (!ft || !fg || !fc) {
            QGP_LOG_ERROR(LOG_TAG, "store meta incomplete: refusing to open");
            goto fail;
        }
        if (memcmp(have_chain, chain, DHT2_CHAIN_LEN) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "store belongs to another chain");
            goto fail;
        }
        if (top > (uint64_t)INT64_MAX ||
            query_u64(s, "SELECT COALESCE(MAX(idx), 0) FROM dht2_rec", NULL,
                      false, 0, &n) != 0 || n > top) {
            /* A counter behind the highest index would hand out an index
             * that is already used: never reset it, never open. */
            QGP_LOG_ERROR(LOG_TAG, "counter behind the records: refusing");
            goto fail;
        }
        memcpy(s->chain, have_chain, DHT2_CHAIN_LEN);
    }
    s->gen = gen;
    if (exec_sql(s, "COMMIT") != 0) {
        goto fail;
    }
    return s;

fail:
    if (s->db != NULL) {
        if (in_txn) {
            (void)sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
        }
        sqlite3_close(s->db);
    }
    free(s);
    return NULL;
}

void nodus_dht2_store_close(nodus_dht2_store_t *s)
{
    if (s == NULL) {
        return;
    }
    if (s->db != NULL) {
        sqlite3_close(s->db);
    }
    free(s);
}

uint64_t nodus_dht2_store_generation(const nodus_dht2_store_t *s)
{
    return s != NULL ? s->gen : 0;
}

struct sqlite3 *nodus_dht2_store_db(nodus_dht2_store_t *s)
{
    return s != NULL ? s->db : NULL;
}

int nodus_dht2_store_top(nodus_dht2_store_t *s, uint64_t *top)
{
    bool found = false;

    if (s == NULL || top == NULL) {
        return CODE_FAULT;
    }
    if (meta_get(s, "top", top, NULL, &found) != 0 || !found ||
        *top > (uint64_t)INT64_MAX) {
        return CODE_FAULT;
    }
    return 0;
}

/* The call-level gate of put / get / list / sweep / scan (§2, §4.1): no
 * snapshot, or the witness is still in block sync (consensus_up false) ->
 * 15; a snapshot time no bound below INT64_MAX can hold -> 15 (so every time
 * threshold below fits SQLite's int64); a snapshot of another chain than the
 * one this store was created for -> 16 (G8). */
static int gate(const nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx)
{
    if (ctx == NULL || ctx->snap == NULL || !ctx->snap->consensus_up) {
        return DHT2_E_NOT_CAUGHT_UP;
    }
    if (ctx->snap->tip_time > (uint64_t)INT64_MAX - TIME_SLACK_MAX) {
        return DHT2_E_NOT_CAUGHT_UP;
    }
    if (memcmp(ctx->snap->chain_id, s->chain, DHT2_CHAIN_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "snapshot chain differs from the store's");
        return CODE_FAULT;
    }
    return 0;
}

/* ══ held row ══════════════════════════════════════════════════════════ */

typedef struct {
    bool     found;
    uint8_t *canon;                /* malloc'd; freed by held_free */
    size_t   len;
    uint8_t  hash[DHT2_HASH_LEN];
    int      named;
    int      handover;
    bool     noexp;
    uint64_t expiry;
} held_t;

static void held_free(held_t *h)
{
    free(h->canon);
    h->canon = NULL;
}

static int held_load(nodus_dht2_store_t *s, const uint8_t *address, held_t *h)
{
    sqlite3_stmt *st;
    int           rc;

    memset(h, 0, sizeof(*h));
    st = prep(s, "SELECT canon, hash, named, handover, noexp, expiry "
                 "FROM dht2_rec WHERE address = ?1");
    if (st == NULL) {
        return -1;
    }
    if (!bound(st, b_64(st, 1, address))) {
        return -1;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        return 0;
    }
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "held load: %s", sqlite3_errmsg(s->db));
        sqlite3_finalize(st);
        return -1;
    }
    h->len = (size_t)sqlite3_column_bytes(st, 0);
    if (sqlite3_column_bytes(st, 1) != (int)DHT2_HASH_LEN || h->len == 0 ||
        h->len > DHT2_ENVELOPE_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "held row malformed");
        sqlite3_finalize(st);
        return -1;
    }
    h->canon = (uint8_t *)malloc(h->len);
    if (h->canon == NULL) {
        sqlite3_finalize(st);
        return -1;
    }
    memcpy(h->canon, sqlite3_column_blob(st, 0), h->len);
    memcpy(h->hash, sqlite3_column_blob(st, 1), DHT2_HASH_LEN);
    h->named = sqlite3_column_int(st, 2) != 0;
    h->handover = sqlite3_column_int(st, 3) != 0;
    h->noexp = sqlite3_column_int(st, 4) != 0;
    h->expiry = (uint64_t)sqlite3_column_int64(st, 5);
    h->found = true;
    sqlite3_finalize(st);
    return 0;
}

/* ══ the selected inbox control record (§3.3) ══════════════════════════ */

/* The selected control record of `inbox`, when it is LIVE at chain time
 * `t` (held, not a tombstone, not expired). *`canon` malloc'd (or NULL),
 * its hash in `hash`. 0 / -1 (fault). */
static int ctl_load_live(nodus_dht2_store_t *s, const uint8_t *inbox,
                         uint64_t t, uint8_t **canon, size_t *len,
                         uint8_t hash[DHT2_HASH_LEN], bool *present)
{
    sqlite3_stmt *st;
    int           rc;

    *canon = NULL;
    *present = false;
    st = prep(s, "SELECT canon, hash, del, noexp, expiry FROM dht2_rec "
                 "WHERE placement = ?1 AND cls = 5 ORDER BY address LIMIT 1");
    if (st == NULL) {
        return -1;
    }
    if (!bound(st, b_64(st, 1, inbox))) {
        return -1;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        return 0;
    }
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "ctl load: %s", sqlite3_errmsg(s->db));
        sqlite3_finalize(st);
        return -1;
    }
    if (sqlite3_column_int(st, 2) == 0 &&
        (sqlite3_column_int(st, 3) != 0 ||
         (uint64_t)sqlite3_column_int64(st, 4) > t)) {
        size_t n = (size_t)sqlite3_column_bytes(st, 0);

        if (sqlite3_column_bytes(st, 1) != (int)DHT2_HASH_LEN || n == 0 ||
            n > DHT2_ENVELOPE_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "ctl row malformed");
            sqlite3_finalize(st);
            return -1;
        }
        *canon = (uint8_t *)malloc(n);
        if (*canon == NULL) {
            sqlite3_finalize(st);
            return -1;
        }
        memcpy(*canon, sqlite3_column_blob(st, 0), n);
        memcpy(hash, sqlite3_column_blob(st, 1), DHT2_HASH_LEN);
        *len = n;
        *present = true;
    }
    sqlite3_finalize(st);
    return 0;
}

/* ══ put ═══════════════════════════════════════════════════════════════ */

typedef struct {
    dht2_record_t rec;                          /* the incoming record     */
    dht2_record_t held_rec;                     /* the held version        */
    dht2_record_t ctl_rec;                      /* the selected control    */
    uint8_t       canon[DHT2_ENVELOPE_MAX + 64];
    size_t        canon_len;
    uint8_t       hash[DHT2_HASH_LEN];
    uint8_t       placement[DHT2_HASH_LEN];
    bool          named;
} put_work_t;

/* Row 7 code of a codec return: a real code passes through; anything else
 * (an ARG error, an unexpected value) is the holder's own fault. */
static int code_of(int rc)
{
    return (rc >= DHT2_E_TOO_LARGE && rc <= DHT2_E_HANDLED) ? rc : CODE_FAULT;
}

/* §3.3 / row 15: an inbox entry's writer against the SELECTED, LIVE control
 * record only. 0 = no objection; 12 = DENIED (while listed); 18 = Sequence
 * at or below the writer's HANDLED cutoff, which is returned in
 * res->through; 16 = fault. */
static int ctl_check_entry(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                           put_work_t *w, nodus_dht2_put_t *res)
{
    uint8_t         *canon = NULL;
    size_t           len = 0;
    uint8_t          chash[DHT2_HASH_LEN];
    bool             present = false, found = false;
    dht2_ctl_entry_t ent;

    memset(&ent, 0, sizeof(ent));
    if (ctl_load_live(s, w->placement, ctx->snap->tip_time, &canon, &len,
                      chash, &present) != 0) {
        return CODE_FAULT;
    }
    if (present) {
        if (dht2_record_parse(canon, len, ctx->snap->chain_id, NULL,
                              &w->ctl_rec) != DHT2_OK ||
            dht2_ctl_lookup(w->ctl_rec.d.data, w->ctl_rec.d.data_len,
                            w->rec.fp, &found, &ent) != DHT2_OK) {
            QGP_LOG_ERROR(LOG_TAG, "stored control record unreadable");
            free(canon);
            return CODE_FAULT;
        }
        free(canon);
        if (found && ent.mark == DHT2_CTL_DENIED) {
            return DHT2_E_DENIED;
        }
        if (found && w->rec.d.sequence <= ent.through) {
            res->through = ent.through;
            return DHT2_E_HANDLED;
        }
    }
    return 0;
}

/* Apply the entries of an owner-signed control record that carry `mark`
 * to the entries at its inbox (§3.3, row 15). One entry per (inbox, writer)
 * exists (the address binds both), so a second row is corruption. Runs
 * inside the put transaction BEFORE the quota checks, so the bytes it frees
 * are credited (row 16).
 *
 * Called ONLY for a control record that won Select and is going to be
 * stored (a losing record changes nothing, row 16). HANDLED drops the
 * writer's entry with Sequence ≤ through, DENIED drops it whatever its
 * Sequence. Nothing is remembered: keeping a handled request from coming
 * back is a CLIENT rule (decision 2026-10-24-dht-v2-handled-client-rule.md:
 * the owner keeps the writer listed until its entries expired). 0 / -1. */
static int ctl_apply(nodus_dht2_store_t *s, const put_work_t *w)
{
    const dht2_data_t *d = &w->rec.d;
    size_t             count = 0, i;

    if (dht2_ctl_check(d->data, d->data_len, &count) != DHT2_OK) {
        QGP_LOG_ERROR(LOG_TAG, "control list unreadable after admission");
        return -1;
    }
    for (i = 0; i < count; i++) {
        dht2_ctl_entry_t ent;
        sqlite3_stmt    *st;
        uint8_t          addr[DHT2_HASH_LEN];
        bool             drop = false, row = false;
        int              rc;

        if (dht2_ctl_at(d->data, d->data_len, i, &ent) != DHT2_OK) {
            return -1;
        }
        st = prep(s, "SELECT address, seq FROM dht2_rec "
                     "WHERE placement = ?1 AND cls = 4 AND owner = ?2 "
                     "ORDER BY address");
        if (st == NULL) {
            return -1;
        }
        if (!bound(st, b_64(st, 1, w->placement) | b_64(st, 2, ent.fp))) {
            return -1;
        }
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            row = true;
            if (sqlite3_column_bytes(st, 0) != (int)DHT2_HASH_LEN) {
                sqlite3_finalize(st);
                return -1;
            }
            memcpy(addr, sqlite3_column_blob(st, 0), DHT2_HASH_LEN);
            drop = ent.mark == DHT2_CTL_DENIED ||
                   (uint64_t)sqlite3_column_int64(st, 1) <= ent.through;
            rc = sqlite3_step(st);
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "control apply scan");
            return -1;
        }
        if (row && drop) {
            st = prep(s, "DELETE FROM dht2_rec WHERE address = ?1");
            if (st == NULL) {
                return -1;
            }
            if (!bound(st, b_64(st, 1, addr)) || step_done(s, st) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

/* Everything after the signature, inside one write transaction (row 16):
 * control check, Select, the stored-state change (including what a control
 * record drops), quota / pool checks and the writes. Returns the row-7
 * code; *res set. */
static int admit_locked(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                        put_work_t *w, nodus_dht2_put_t *res)
{
    const dht2_data_t *d = &w->rec.d;
    held_t             hd;
    uint64_t           t = ctx->snap->tip_time;
    uint64_t           new_size = (uint64_t)w->canon_len;
    uint64_t           old_size = 0, used = 0, top = 0, limit;
    int                pool = w->named ? 1 : 0;
    int                code, handover = 0;
    sqlite3_stmt      *st;

    /* Inbox entries: DENIED / HANDLED come before Select, so a re-put of
     * an entry the owner has since dropped is refused, not acknowledged. */
    if (d->cls == DHT2_CLASS_INBOX_ENTRY) {
        code = ctl_check_entry(s, ctx, w, res);
        if (code != 0) {
            return code;
        }
    }

    /* Select (§4.2): Validate -> Select -> store, nothing else. A held row
     * whose expiry has passed is an INVALID existing record and counts as
     * absent (kad-dht value_store.go existingForSelect; boxo validation.go:73
     * expired = invalid) — whatever its class — but it is still the row the
     * incoming version replaces, so its bytes are freed by the replace. */
    if (held_load(s, w->rec.address, &hd) != 0) {
        return CODE_FAULT;
    }
    if (hd.found) {
        bool held_expired = !hd.noexp && hd.expiry <= t;

        old_size = (uint64_t)hd.len;
        handover = hd.handover;
        if (!held_expired) {
            int cmp;

            if (dht2_record_parse(hd.canon, hd.len, ctx->snap->chain_id, NULL,
                                  &w->held_rec) != DHT2_OK) {
                QGP_LOG_ERROR(LOG_TAG, "held record unreadable");
                held_free(&hd);
                return CODE_FAULT;
            }
            cmp = dht2_record_compare(&w->rec, &w->held_rec);
            if (cmp <= 0) {
                /* Equal: acknowledged again. Loser: the winner's hash. Both
                 * change nothing and cost 0 (row 16, row 17). */
                res->outcome = cmp == 0 ? NODUS_DHT2_PUT_EQUAL
                                        : NODUS_DHT2_PUT_LOST;
                memcpy(res->hash, hd.hash, DHT2_HASH_LEN);
                held_free(&hd);
                return 0;
            }
        }
        /* A deletion never moves pools: the tombstone is charged where the
         * record it replaces was (row 16 "a tombstone replacing a larger
         * record refunds" must not be refusable by a pool check). */
        if (d->del) {
            pool = hd.named;
        }
    }
    held_free(&hd);

    /* The incoming version wins. A control record first drops the entries
     * it marks (HANDLED, DENIED): the stored-state change it causes counts
     * BEFORE the checks below (row 16); a refusal rolls the whole
     * transaction back, nothing of it stays. */
    if (d->cls == DHT2_CLASS_INBOX_CTL && !d->del && ctl_apply(s, w) != 0) {
        return CODE_FAULT;
    }

    /* Order of the refusals is a reading (the text names no order): inbox
     * pool 11, identity quota 10, node pool 13. */
    if (d->cls == DHT2_CLASS_INBOX_ENTRY && !d->del) {
        uint64_t slots = 0;
        uint64_t cap = w->named ? NODUS_DHT2_POOL_NAMED
                                : NODUS_DHT2_POOL_UNNAMED;

        /* Live entries of this pool at this inbox, not counting this
         * writer's own current row: an update takes no second slot, and a
         * writer that gained a name is counted in its new pool only. */
        st = prep(s, "SELECT COUNT(*) FROM dht2_rec WHERE placement = ?1 "
                     "AND cls = 4 AND del = 0 AND named = ?2 "
                     "AND (noexp = 1 OR expiry > ?3) AND address <> ?4");
        if (st == NULL) {
            return CODE_FAULT;
        }
        if (!bound(st, b_64(st, 1, w->placement) |
                           b_i64(st, 2, pool) | b_i64(st, 3, (int64_t)t) |
                           b_64(st, 4, w->rec.address))) {
            return CODE_FAULT;
        }
        if (sqlite3_step(st) != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "pool count: %s", sqlite3_errmsg(s->db));
            sqlite3_finalize(st);
            return CODE_FAULT;
        }
        slots = (uint64_t)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        if (slots >= cap) {
            return DHT2_E_POOL_FULL;
        }
    }

    /* Per identity (the owner fp = the writer) per holder: whole canonical
     * bytes; a replacement costs new - old, a smaller one refunds. */
    limit = w->named ? ctx->limits.ident_named : ctx->limits.ident_unnamed;
    if (query_u64(s, "SELECT COALESCE(SUM(size), 0) FROM dht2_rec "
                     "WHERE owner = ?1", w->rec.fp, false, 0, &used) != 0 ||
        used < old_size) {
        return CODE_FAULT;
    }
    if (new_size > old_size && used - old_size + new_size > limit) {
        return DHT2_E_QUOTA;
    }

    /* Node pool. A record that stays in its pool costs new - old there; one
     * that moves pools costs new in the new pool (the old pool is refunded
     * by the replace). */
    limit = pool == 1 ? ctx->limits.pool_named : ctx->limits.pool_unnamed;
    if (query_u64(s, "SELECT COALESCE(SUM(size), 0) FROM dht2_rec "
                     "WHERE named = ?2", NULL, true, pool, &used) != 0) {
        return CODE_FAULT;
    }
    {
        /* old_size is in this pool only when the replaced row was charged
         * to it: re-read its pool through the replace target. */
        uint64_t in_pool_old = 0;
        sqlite3_stmt *os = prep(s, "SELECT size FROM dht2_rec "
                                   "WHERE address = ?1 AND named = ?2");
        int           orc;

        if (os == NULL) {
            return CODE_FAULT;
        }
        if (!bound(os, b_64(os, 1, w->rec.address) | b_i64(os, 2, pool))) {
            return CODE_FAULT;
        }
        orc = sqlite3_step(os);
        if (orc == SQLITE_ROW) {
            in_pool_old = (uint64_t)sqlite3_column_int64(os, 0);
        } else if (orc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "pool old: %s", sqlite3_errmsg(s->db));
            sqlite3_finalize(os);
            return CODE_FAULT;
        }
        sqlite3_finalize(os);
        if (used < in_pool_old) {
            return CODE_FAULT;
        }
        if (in_pool_old != 0) {
            if (new_size > in_pool_old &&
                used - in_pool_old + new_size > limit) {
                return DHT2_E_NODE_FULL;
            }
        } else if (used + new_size > limit) {
            return DHT2_E_NODE_FULL;
        }
    }

    /* Store the canonical form, re-indexed at the counter's top; the old
     * row (same address) is deleted EXPLICITLY and the new one inserted
     * plainly, so an index clash is a fault, never a silent delete of
     * another address's row. */
    if (nodus_dht2_store_top(s, &top) != 0 || top >= (uint64_t)INT64_MAX) {
        return CODE_FAULT;
    }
    top++;
    st = prep(s, "DELETE FROM dht2_rec WHERE address = ?1");
    if (st == NULL) {
        return CODE_FAULT;
    }
    if (!bound(st, b_64(st, 1, w->rec.address)) || step_done(s, st) != 0) {
        return CODE_FAULT;
    }
    st = prep(s, "INSERT INTO dht2_rec(address, placement, owner, "
                 "cls, seq, noexp, expiry, del, named, handover, size, hash, "
                 "canon, idx) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, "
                 "?11, ?12, ?13, ?14)");
    if (st == NULL) {
        return CODE_FAULT;
    }
    if (!bound(st, b_64(st, 1, w->rec.address) | b_64(st, 2, w->placement) |
                       b_64(st, 3, w->rec.fp) |
                       b_i64(st, 4, (int64_t)d->cls) |
                       b_i64(st, 5, (int64_t)d->sequence) |
                       b_i64(st, 6, d->validity_type == DHT2_VT_NONE ? 1 : 0) |
                       b_i64(st, 7, d->validity_type == DHT2_VT_NONE
                                        ? 0 : (int64_t)d->expiry) |
                       b_i64(st, 8, d->del ? 1 : 0) |
                       b_i64(st, 9, pool) | b_i64(st, 10, handover) |
                       b_i64(st, 11, (int64_t)new_size) |
                       b_64(st, 12, w->hash) |
                       b_blob(st, 13, w->canon, w->canon_len) |
                       b_i64(st, 14, (int64_t)top))) {
        return CODE_FAULT;
    }
    if (step_done(s, st) != 0 || meta_set(s, "top", top) != 0) {
        return CODE_FAULT;
    }
    res->outcome = NODUS_DHT2_PUT_STORED;
    memcpy(res->hash, w->hash, DHT2_HASH_LEN);
    return 0;
}

int nodus_dht2_store_put(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                         const uint8_t *env, size_t len,
                         const uint8_t *expect_address, nodus_dht2_put_t *res)
{
    put_work_t *w;
    int         rc, code;
    nodus_dht2_name_t nm;

    if (s == NULL || ctx == NULL || res == NULL || ctx->name == NULL ||
        (env == NULL && len != 0)) {
        return DHT2_E_ARG;
    }
    memset(res, 0, sizeof(*res));
    /* No snapshot / block sync / no sets for its `e`: refuse, never guess
     * (§2, §4.1, D2). */
    rc = gate(s, ctx);
    if (rc != 0) {
        return rc;
    }
    if (!ctx->have_sets) {
        return DHT2_E_NOT_CAUGHT_UP;
    }
    w = (put_work_t *)calloc(1, sizeof(*w));
    if (w == NULL) {
        return CODE_FAULT;
    }

    /* size, envelope, strict data, `_chain`, owner fp, address (1-4). */
    rc = dht2_record_parse(env, len, ctx->snap->chain_id, expect_address,
                           &w->rec);
    if (rc != DHT2_OK) {
        code = code_of(rc);
        goto out;
    }
    /* The address is known from here on, whatever check fails next: the
     * serving layer names the result by it (one parse, no second one). */
    memcpy(res->address, w->rec.address, DHT2_HASH_LEN);
    res->has_address = true;
    /* holder check (5): eligible(placement key) over S(H) and S(H − E). */
    if (dht2_record_placement_key(&w->rec, w->placement) != DHT2_OK) {
        code = CODE_FAULT;
        goto out;
    }
    rc = dht2_eligible(w->placement, ctx->s0, ctx->n0, ctx->s1, ctx->n1,
                       ctx->self_fp);
    if (rc < 0) {
        code = CODE_FAULT;
        goto out;
    }
    if (rc == 0) {
        code = DHT2_E_NOT_HOLDER;
        goto out;
    }
    /* class rules (6), incl. ValidityType <=> Validity. */
    rc = dht2_record_check_class(&w->rec);
    if (rc != DHT2_OK) {
        code = code_of(rc);
        goto out;
    }
    /* The writer's name status: needed from here on (class max, pool,
     * quota). A FAULT answer is reported as holder-fault and thereby
     * consumed; it is never read as "no name". */
    nm = ctx->name(ctx->name_user, w->rec.fp);
    if (nm == NODUS_DHT2_NAME_FAULT ||
        (nm != NODUS_DHT2_NAME_NAMED && nm != NODUS_DHT2_NAME_UNNAMED)) {
        code = CODE_FAULT;
        goto out;
    }
    w->named = nm == NODUS_DHT2_NAME_NAMED;
    /* expiry > t and ≤ t + class max + 3 h (7, 8). */
    rc = dht2_record_check_expiry(&w->rec, ctx->snap->tip_time, w->named);
    if (rc != DHT2_OK) {
        code = code_of(rc);
        goto out;
    }
    /* signature (9). */
    rc = dht2_record_verify(&w->rec);
    if (rc != DHT2_OK) {
        code = code_of(rc);
        goto out;
    }
    /* From here the canonical form is what is compared, hashed, charged
     * and stored (§3.1 "Stored form"). */
    if (dht2_record_canonical(&w->rec, w->canon, sizeof(w->canon),
                              &w->canon_len) != DHT2_OK ||
        w->canon_len > DHT2_ENVELOPE_MAX ||
        qgp_sha3_512(w->canon, w->canon_len, w->hash) != 0) {
        code = CODE_FAULT;
        goto out;
    }

    if (exec_sql(s, "BEGIN IMMEDIATE") != 0) {
        code = CODE_FAULT;
        goto out;
    }
    code = admit_locked(s, ctx, w, res);
    /* Only a stored version keeps what the transaction did. An equal or
     * losing write, and every refusal (a quota-refused control record
     * included), changes nothing (row 16): full rollback. */
    if (code == 0 && res->outcome == NODUS_DHT2_PUT_STORED) {
        if (exec_sql(s, "COMMIT") != 0) {
            (void)exec_sql(s, "ROLLBACK");
            code = CODE_FAULT;
        }
    } else if (exec_sql(s, "ROLLBACK") != 0) {
        /* Nothing was to be kept, but an open transaction would poison the
         * next call: report the fault. */
        code = CODE_FAULT;
    }

out:
    if (code != 0) {
        uint64_t through = res->through;

        memset(res, 0, sizeof(*res));
        res->through = code == DHT2_E_HANDLED ? through : 0;
    }
    free(w);
    return code;
}

/* ══ get ═══════════════════════════════════════════════════════════════ */

int nodus_dht2_store_get(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                         const uint8_t address[DHT2_HASH_LEN], uint8_t *out,
                         size_t cap, size_t *out_len,
                         uint8_t hash[DHT2_HASH_LEN])
{
    sqlite3_stmt *st;
    int           rc, code = NODUS_DHT2_GET_NOT_HELD;

    if (s == NULL || ctx == NULL || address == NULL || out == NULL ||
        out_len == NULL || hash == NULL) {
        return DHT2_E_ARG;
    }
    rc = gate(s, ctx);
    if (rc != 0) {
        return rc;
    }
    st = prep(s, "SELECT canon, hash, noexp, expiry FROM dht2_rec "
                 "WHERE address = ?1");
    if (st == NULL) {
        return CODE_FAULT;
    }
    if (!bound(st, b_64(st, 1, address))) {
        return CODE_FAULT;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        size_t n = (size_t)sqlite3_column_bytes(st, 0);

        /* §5: never served past its expiry (the 3 h slack is for deletion
         * only). */
        if (sqlite3_column_int(st, 2) == 0 &&
            (uint64_t)sqlite3_column_int64(st, 3) <= ctx->snap->tip_time) {
            code = NODUS_DHT2_GET_NOT_HELD;
        } else if (n == 0 || n > cap ||
                   sqlite3_column_bytes(st, 1) != (int)DHT2_HASH_LEN) {
            QGP_LOG_ERROR(LOG_TAG, "get: row or buffer size");
            code = CODE_FAULT;
        } else {
            memcpy(out, sqlite3_column_blob(st, 0), n);
            memcpy(hash, sqlite3_column_blob(st, 1), DHT2_HASH_LEN);
            *out_len = n;
            code = NODUS_DHT2_GET_HELD;
        }
    } else if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "get: %s", sqlite3_errmsg(s->db));
        code = CODE_FAULT;
    }
    sqlite3_finalize(st);
    return code;
}

/* ══ list ══════════════════════════════════════════════════════════════ */

int nodus_dht2_store_list(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                          const uint8_t inbox[DHT2_HASH_LEN],
                          const uint8_t *cursor, dht2_list_answer_t *out)
{
    static const uint8_t zero_fp[DHT2_FP_LEN] = { 0 };
    sqlite3_stmt *st;
    uint8_t      *hashes = NULL;
    uint8_t      *ctl_canon = NULL;
    size_t        ctl_len = 0, n = 0, bytes = 0;
    bool          more = false, ctl_present = false;
    int           rc, code = 0;

    if (s == NULL || ctx == NULL || inbox == NULL || out == NULL) {
        return DHT2_E_ARG;
    }
    rc = gate(s, ctx);
    if (rc != 0) {
        return rc;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->n, ctx->self_fp, DHT2_FP_LEN);
    memcpy(out->c, ctx->snap->chain_id, DHT2_CHAIN_LEN);
    out->h = ctx->snap->height;
    out->t = ctx->snap->tip_time;

    /* The selected control record's hash travels beside the entries, and its
     * bytes are part of the page: charge them first, so entries + control
     * stay within the 2 MiB page budget (row 11). */
    if (ctl_load_live(s, inbox, ctx->snap->tip_time, &ctl_canon, &ctl_len,
                      out->ctl, &ctl_present) != 0) {
        memset(out, 0, sizeof(*out));
        return CODE_FAULT;
    }
    free(ctl_canon);
    out->has_ctl = ctl_present;
    if (ctl_present) {
        bytes = ctl_len;
    } else {
        memset(out->ctl, 0, sizeof(out->ctl));
    }

    hashes = (uint8_t *)malloc((size_t)DHT2_LIST_PAGE_MAX * DHT2_HASH_LEN);
    if (hashes == NULL) {
        return CODE_FAULT;
    }
    /* Live entries only: a tombstone is a deleted entry, an expired one is
     * never served. ORDER BY the writer fp, strictly after the cursor
     * (EXCLUSIVE, row 11); one row more than a page tells `complete`. */
    st = prep(s, "SELECT owner, hash, size FROM dht2_rec WHERE placement = ?1 "
                 "AND cls = 4 AND del = 0 AND (noexp = 1 OR expiry > ?2) "
                 "AND owner > ?3 ORDER BY owner ASC LIMIT 17");
    if (st == NULL) {
        free(hashes);
        return CODE_FAULT;
    }
    if (!bound(st, b_64(st, 1, inbox) |
                       b_i64(st, 2, (int64_t)ctx->snap->tip_time) |
                       b_blob(st, 3, cursor != NULL ? cursor : zero_fp,
                              DHT2_FP_LEN))) {
        free(hashes);
        return CODE_FAULT;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint64_t sz = (uint64_t)sqlite3_column_int64(st, 2);

        if (sqlite3_column_bytes(st, 0) != (int)DHT2_FP_LEN ||
            sqlite3_column_bytes(st, 1) != (int)DHT2_HASH_LEN) {
            QGP_LOG_ERROR(LOG_TAG, "list: row malformed");
            code = CODE_FAULT;
            break;
        }
        /* A page holds ≤ 16 entries and ≤ 2 MiB; the first entry always
         * fits (each page must advance). */
        if (n >= DHT2_LIST_PAGE_MAX ||
            (n > 0 && bytes + sz > NODUS_DHT2_LIST_PAGE_BYTES)) {
            more = true;
            break;
        }
        memcpy(out->list[n].w, sqlite3_column_blob(st, 0), DHT2_FP_LEN);
        memcpy(out->list[n].d, sqlite3_column_blob(st, 1), DHT2_HASH_LEN);
        memcpy(hashes + n * DHT2_HASH_LEN, out->list[n].d, DHT2_HASH_LEN);
        bytes += sz;
        n++;
    }
    if (code == 0 && !more && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "list: %s", sqlite3_errmsg(s->db));
        code = CODE_FAULT;
    }
    sqlite3_finalize(st);
    if (code != 0) {
        free(hashes);
        memset(out, 0, sizeof(*out));
        return code;
    }

    out->list_count = n;
    out->complete = !more;
    if (n > 0) {
        out->has_cursor = true;
        memcpy(out->cursor, out->list[n - 1].w, DHT2_FP_LEN);
    }
    if (cursor != NULL) {
        out->has_req_cursor = true;
        memcpy(out->req_cursor, cursor, DHT2_FP_LEN);
    }
    /* Row 18: k = the inbox id, v = SHA3-512 over the concatenation of the
     * listed entry hashes. */
    memcpy(out->r.key, inbox, DHT2_HASH_LEN);
    out->r.kind = DHT2_RV_HASH;
    if (qgp_sha3_512(hashes, n * DHT2_HASH_LEN, out->r.hash) != 0) {
        free(hashes);
        memset(out, 0, sizeof(*out));
        return CODE_FAULT;
    }
    free(hashes);
    return 0;
}

/* ══ sweep ═════════════════════════════════════════════════════════════ */

int nodus_dht2_store_sweep(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                           uint64_t *deleted)
{
    sqlite3_stmt *st;
    uint64_t      t, n;
    int           rc;

    if (s == NULL || ctx == NULL) {
        return DHT2_E_ARG;
    }
    rc = gate(s, ctx);
    if (rc != 0) {
        return rc;
    }
    if (deleted != NULL) {
        *deleted = 0;
    }
    t = ctx->snap->tip_time;
    if (t < DHT2_SEC_SLACK_3H) {
        return 0;                       /* nothing can be 3 h past expiry */
    }
    if (exec_sql(s, "BEGIN IMMEDIATE") != 0) {
        return CODE_FAULT;
    }
    /* expiry + 3 h ≤ t  <=>  expiry ≤ t − 3 h (t ≥ 3 h here). */
    st = prep(s, "DELETE FROM dht2_rec WHERE noexp = 0 AND expiry <= ?1");
    if (st == NULL ||
        !bound(st, b_i64(st, 1, (int64_t)(t - DHT2_SEC_SLACK_3H))) ||
        step_done(s, st) != 0) {
        (void)exec_sql(s, "ROLLBACK");
        return CODE_FAULT;
    }
    n = (uint64_t)sqlite3_changes(s->db);
    if (exec_sql(s, "COMMIT") != 0) {
        (void)exec_sql(s, "ROLLBACK");
        return CODE_FAULT;
    }
    if (deleted != NULL) {
        *deleted = n;
    }
    return 0;
}

/* ══ insertion index scan ══════════════════════════════════════════════ */

int nodus_dht2_store_scan(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                          uint64_t from, nodus_dht2_scan_entry_t *out,
                          size_t max, size_t *count, uint64_t *topmost)
{
    sqlite3_stmt *st;
    size_t        n = 0;
    uint64_t      last = 0;
    int           rc, code = 0;

    if (s == NULL || ctx == NULL || out == NULL || count == NULL ||
        topmost == NULL || max == 0 || max > DHT2_PULL_PAGE_MAX) {
        return DHT2_E_ARG;
    }
    rc = gate(s, ctx);
    if (rc != 0) {
        return rc;
    }
    *count = 0;
    /* An index above INT64_MAX is never handed out: nothing is there. */
    if (from > (uint64_t)INT64_MAX) {
        return nodus_dht2_store_top(s, topmost);
    }
    st = prep(s, "SELECT idx, address, hash, placement FROM dht2_rec "
                 "WHERE idx >= ?1 ORDER BY idx ASC LIMIT ?2");
    if (st == NULL) {
        return CODE_FAULT;
    }
    if (!bound(st, b_i64(st, 1, (int64_t)from) | b_i64(st, 2, (int64_t)max))) {
        return CODE_FAULT;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (sqlite3_column_bytes(st, 1) != (int)DHT2_HASH_LEN ||
            sqlite3_column_bytes(st, 2) != (int)DHT2_HASH_LEN ||
            sqlite3_column_bytes(st, 3) != (int)DHT2_HASH_LEN) {
            QGP_LOG_ERROR(LOG_TAG, "scan: row malformed");
            code = CODE_FAULT;
            break;
        }
        last = (uint64_t)sqlite3_column_int64(st, 0);
        out[n].index = last;
        memcpy(out[n].address, sqlite3_column_blob(st, 1), DHT2_HASH_LEN);
        memcpy(out[n].hash, sqlite3_column_blob(st, 2), DHT2_HASH_LEN);
        memcpy(out[n].placement, sqlite3_column_blob(st, 3), DHT2_HASH_LEN);
        n++;
    }
    if (code == 0 && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "scan: %s", sqlite3_errmsg(s->db));
        code = CODE_FAULT;
    }
    sqlite3_finalize(st);
    if (code != 0) {
        return code;
    }
    if (n == 0) {
        /* Bee pullsync.go:251-254: an empty interval still returns a top. */
        return nodus_dht2_store_top(s, topmost);
    }
    *count = n;
    *topmost = last;
    return 0;
}

/* ══ hand-over flag ════════════════════════════════════════════════════ */

int nodus_dht2_store_handover_set(nodus_dht2_store_t *s,
                                  const uint8_t address[DHT2_HASH_LEN],
                                  bool pending, bool *found)
{
    sqlite3_stmt *st;

    if (s == NULL || address == NULL) {
        return DHT2_E_ARG;
    }
    st = prep(s, "UPDATE dht2_rec SET handover = ?2 WHERE address = ?1");
    if (st == NULL) {
        return CODE_FAULT;
    }
    if (!bound(st, b_64(st, 1, address) | b_i64(st, 2, pending ? 1 : 0))) {
        return CODE_FAULT;
    }
    if (step_done(s, st) != 0) {
        return CODE_FAULT;
    }
    if (found != NULL) {
        *found = sqlite3_changes(s->db) > 0;
    }
    return 0;
}

int nodus_dht2_store_handover_get(nodus_dht2_store_t *s,
                                  const uint8_t address[DHT2_HASH_LEN],
                                  bool *pending, bool *found)
{
    held_t h;

    if (s == NULL || address == NULL || pending == NULL || found == NULL) {
        return DHT2_E_ARG;
    }
    if (held_load(s, address, &h) != 0) {
        return CODE_FAULT;
    }
    *found = h.found;
    *pending = h.found && h.handover != 0;
    held_free(&h);
    return 0;
}
