/**
 * @file nodus_witness_v2_shadow.c
 * @brief HF-9 WP5 - the shadow run. Contract: nodus_witness_v2_shadow.h.
 *        Plan docs/plans/approved/2026-11-04-hf9.md §11.
 *
 * Threading: the hook runs on the witness event loop right after the host's
 * COMMIT and state save (nodus_witness.h:18-19 "single-threaded state
 * transitions in the event loop"), like every handler that reads w->db, so
 * the shadow's transactions never overlap a block transaction.
 * Clock: none (the log row has no timestamp).
 */

#include "witness/nodus_witness_v2_shadow.h"
#include "witness/nodus_witness_v2_trie.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_v2_claims.h"    /* nodus_witness_v2_runtime_for */
#include "witness/nodus_witness_v2_produce.h"   /* nodus_witness_v2_tip_height  */
#include "witness/nodus_witness_v2_schema.h"

#include "evm/trie/evm_trie_full.h"

#include "dnac/ledger_ids.h"                    /* DNA_DOMAIN_SYSTEM            */
#include "crypto/utils/qgp_log.h"

#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2SHADOW"

static uint64_t g_rows_scanned;

uint64_t nodus_witness_v2_shadow_rows_scanned(void) {
    return g_rows_scanned;
}

#ifdef QGP_FAULT_INJECT
static int g_fault_armed;
static int g_fault_hits;

int nodus_witness_v2_shadow_test_fault(int point) {
    if (point < 0 || point > 5) return -1;
    g_fault_armed = point;
    return 0;
}
int nodus_witness_v2_shadow_test_hits(void) { return g_fault_hits; }

static int fault_here(int point) {
    if (g_fault_armed != point) return 0;
    g_fault_armed = 0;
    g_fault_hits++;
    return 1;
}
#define FAULT_AT(p) fault_here(p)
#else
#define FAULT_AT(p) 0
#endif

/* ── the node-local tables ───────────────────────────────────────────── */

static const char *const SHADOW_DDL[] = {
    "CREATE TABLE IF NOT EXISTS v2_trie_shadow_nodes ("
    "  digest BLOB NOT NULL PRIMARY KEY,"
    "  rlp BLOB NOT NULL"
    ") WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS v2_trie_shadow_roots ("
    "  leg INTEGER NOT NULL PRIMARY KEY,"
    "  root BLOB NOT NULL"
    ") WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS v2_trie_shadow_rows ("
    "  leg INTEGER NOT NULL,"
    "  key BLOB NOT NULL,"
    "  value BLOB NOT NULL,"
    "  PRIMARY KEY (leg, key)"
    ") WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS v2_trie_shadow_log ("
    "  height INTEGER NOT NULL PRIMARY KEY,"
    "  leg1 BLOB NOT NULL, leg2 BLOB NOT NULL, leg3 BLOB NOT NULL,"
    "  leg4 BLOB NOT NULL, leg5 BLOB NOT NULL, leg6 BLOB NOT NULL,"
    "  leg7 BLOB NOT NULL, leg8 BLOB NOT NULL,"
    "  core BLOB NOT NULL, stor BLOB NOT NULL, sys BLOB NOT NULL,"
    "  glob BLOB NOT NULL"
    ") WITHOUT ROWID"
};
#define SHADOW_N_TABLES  ((int)(sizeof(SHADOW_DDL) / sizeof(SHADOW_DDL[0])))

static const char *const SHADOW_CLEAR[] = {
    "DELETE FROM v2_trie_shadow_nodes",
    "DELETE FROM v2_trie_shadow_roots",
    "DELETE FROM v2_trie_shadow_rows",
    "DELETE FROM v2_trie_shadow_log"
};

static int exec_sql(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* ── the status ──────────────────────────────────────────────────────── */

int nodus_witness_v2_shadow_status(nodus_witness_t *w, int *status) {
    if (!w || !w->db || !status) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT status, typeof(status) FROM v2_trie_shadow_state "
            "WHERE id = 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_DONE) {
        *status = NODUS_V2_SHADOW_NONE;
        ret = 0;
    } else if (rc == SQLITE_ROW) {
        const char *ty = (const char *)sqlite3_column_text(st, 1);
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (ty && strcmp(ty, "integer") == 0 &&
            (v == NODUS_V2_SHADOW_STOPPED || v == NODUS_V2_SHADOW_RUNNING ||
             v == NODUS_V2_SHADOW_FAULTED)) {
            *status = (int)v;
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static int status_write(nodus_witness_t *w, int status) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO v2_trie_shadow_state (id, status) "
            "VALUES (1, ?1)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_bind_int(st, 1, status) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* A shadow failure (plan §11): roll the shadow's own transaction back (only
 * when it began one), log, set FAULTED in a separate autocommit statement.
 * Writes nothing else - in particular not v2_trie_state - and the host never
 * sees it. */
static int shadow_fail(nodus_witness_t *w, int began, uint64_t height,
                       const char *reason) {
    if (began && !sqlite3_get_autocommit(w->db))
        (void)exec_sql(w->db, "ROLLBACK");
    QGP_LOG_ERROR(LOG_TAG, "HF9-SHADOW FAULT %" PRIu64 " %s", height, reason);
    if (sqlite3_get_autocommit(w->db) &&
        status_write(w, NODUS_V2_SHADOW_FAULTED) != 0)
        QGP_LOG_ERROR(LOG_TAG, "%s", "HF9-SHADOW FAULT the faulted status "
                      "could not be written");
    return -1;
}

/* 0 = the shadow is idle here (not S20, no resolvable SYSTEM runtime, or
 * below the ROOTS generation), 1 = inside the shadow window (>= ROOTS and
 * < TRIE), 2 = the committed generation is >= TRIE, -1 = fault. */
static int generation_window(nodus_witness_t *w) {
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver != NODUS_V2_SCHEMA_VERSION_S20) return 0;
    const nodus_domain_runtime_t *rt = NULL;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 0, &rt) != 0 ||
        !rt)
        return 0;
    if (rt->generation >= NODUS_RT_GEN_TRIE) return 2;
    if (rt->generation >= NODUS_RT_GEN_ROOTS) return 1;
    return 0;
}

/* ── the log row ─────────────────────────────────────────────────────── */

static const char *const LOG_COLS =
    "height, leg1, leg2, leg3, leg4, leg5, leg6, leg7, leg8, core, stor, "
    "sys, glob";

/* The eight shadow leg roots and the four shadow compositions, written as
 * the row of `height`. @return 0 / -1. */
static int log_write(nodus_witness_t *w, uint64_t height) {
    nodus_v2_shadow_log_t r;
    memset(&r, 0, sizeof(r));
    r.height = height;
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        if (nodus_witness_v2_trie_shadow_leg_root(w, leg, r.leg[leg - 1]) != 0)
            return -1;
    if (nodus_witness_core_root_v4_shadow(w, r.core) != 0) return -1;
    if (nodus_witness_storage_root_v3_shadow(w, r.stor) != 0) return -1;
    if (nodus_witness_system_root_v7_shadow(w, r.sys) != 0) return -1;
    if (nodus_witness_global_root_v2_shadow(w, r.glob, NULL, NULL, NULL) != 0)
        return -1;
    if (FAULT_AT(3)) return -1;

    sqlite3_stmt *st = NULL;
    char sql[256];
    snprintf(sql, sizeof(sql), "INSERT INTO v2_trie_shadow_log (%s) VALUES "
             "(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
             LOG_COLS);
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int ok = sqlite3_bind_int64(st, 1, (sqlite3_int64)height) == SQLITE_OK;
    for (int i = 0; ok && i < 8; i++)
        ok = sqlite3_bind_blob(st, 2 + i, r.leg[i], 64, SQLITE_STATIC)
                 == SQLITE_OK;
    ok = ok && sqlite3_bind_blob(st, 10, r.core, 64, SQLITE_STATIC)
                   == SQLITE_OK &&
         sqlite3_bind_blob(st, 11, r.stor, 64, SQLITE_STATIC) == SQLITE_OK &&
         sqlite3_bind_blob(st, 12, r.sys, 64, SQLITE_STATIC) == SQLITE_OK &&
         sqlite3_bind_blob(st, 13, r.glob, 64, SQLITE_STATIC) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR;
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int nodus_witness_v2_shadow_log_read(nodus_witness_t *w, uint64_t height,
                                     nodus_v2_shadow_log_t *out) {
    if (!w || !w->db || !out) return -1;
    char sql[320];
    snprintf(sql, sizeof(sql), "SELECT %s FROM v2_trie_shadow_log %s", LOG_COLS,
             height ? "WHERE height = ?1" : "ORDER BY height DESC LIMIT 1");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) {
        /* the table is created by the seeding: none yet = no such row */
        const char *msg = sqlite3_errmsg(w->db);
        return (msg && strstr(msg, "no such table")) ? 0 : -1;
    }
    if (height && sqlite3_bind_int64(st, 1, (sqlite3_int64)height)
                      != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_DONE) {
        ret = 0;
    } else if (rc == SQLITE_ROW) {
        sqlite3_int64 h = sqlite3_column_int64(st, 0);
        int ok = h >= 0 && sqlite3_column_type(st, 0) == SQLITE_INTEGER;
        for (int c = 1; ok && c <= 12; c++)
            ok = sqlite3_column_type(st, c) == SQLITE_BLOB &&
                 sqlite3_column_bytes(st, c) == 64;
        if (ok) {
            memset(out, 0, sizeof(*out));
            out->height = (uint64_t)h;
            for (int i = 0; i < 8; i++)
                memcpy(out->leg[i], sqlite3_column_blob(st, 1 + i), 64);
            memcpy(out->core, sqlite3_column_blob(st, 9), 64);
            memcpy(out->stor, sqlite3_column_blob(st, 10), 64);
            memcpy(out->sys, sqlite3_column_blob(st, 11), 64);
            memcpy(out->glob, sqlite3_column_blob(st, 12), 64);
            ret = 1;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* the height the last log row names, 0 with none. @return 0 / -1. */
static int log_last_height(nodus_witness_t *w, uint64_t *h) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT MAX(height) FROM v2_trie_shadow_log",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) == SQLITE_NULL) {
            *h = 0;
            ret = 0;
        } else if (sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
                   sqlite3_column_int64(st, 0) >= 0) {
            *h = (uint64_t)sqlite3_column_int64(st, 0);
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* ── the seeding ─────────────────────────────────────────────────────── */

typedef struct {
    sqlite3_stmt *ins;     /* INSERT INTO v2_trie_shadow_rows               */
    int           leg;
} seed_sink_t;

static int seed_sink(void *vctx, const uint8_t *key, size_t key_len,
                     const uint8_t val[64]) {
    seed_sink_t *s = (seed_sink_t *)vctx;
    if (sqlite3_reset(s->ins) != SQLITE_OK ||
        sqlite3_clear_bindings(s->ins) != SQLITE_OK) return -1;
    if (sqlite3_bind_int(s->ins, 1, s->leg) != SQLITE_OK ||
        sqlite3_bind_blob(s->ins, 2, key, (int)key_len, SQLITE_STATIC)
            != SQLITE_OK ||
        sqlite3_bind_blob(s->ins, 3, val, 64, SQLITE_STATIC) != SQLITE_OK)
        return -1;
    return sqlite3_step(s->ins) == SQLITE_DONE ? 0 : -1;
}

static int roots_put(nodus_witness_t *w, int leg, const uint8_t root[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO v2_trie_shadow_roots (leg, root) "
            "VALUES (?1, ?2)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ok = sqlite3_bind_int(st, 1, leg) == SQLITE_OK &&
             sqlite3_bind_blob(st, 2, root, 64, SQLITE_STATIC) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR;
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int nodus_witness_v2_shadow_build(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    if (sqlite3_get_autocommit(w->db)) return -1;      /* inside a txn only */
    for (int i = 0; i < SHADOW_N_TABLES; i++)
        if (exec_sql(w->db, SHADOW_DDL[i]) != 0) return -1;
    for (size_t i = 0; i < sizeof(SHADOW_CLEAR) / sizeof(SHADOW_CLEAR[0]); i++)
        if (exec_sql(w->db, SHADOW_CLEAR[i]) != 0) return -1;
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_trie_shadow_rows (leg, key, value) "
            "VALUES (?1, ?2, ?3)", -1, &ins, NULL) != SQLITE_OK)
        return -1;
    for (int leg = NODUS_V2_TRIE_LEG_UTXO; leg <= NODUS_V2_TRIE_LEG_ATTENDANCE;
         leg++) {
        uint8_t inc[64], full[64];
        seed_sink_t sk = { ins, leg };
        /* the SAME build as the edge's (root_inc == root_full checked) */
        if (nodus_witness_v2_trie_shadow_build_leg(w, leg, seed_sink, &sk,
                                                   inc, full) != 0 ||
            memcmp(inc, full, 64) != 0 || roots_put(w, leg, inc) != 0 ||
            (leg == NODUS_V2_TRIE_LEG_UTXO && FAULT_AT(5))) {
            sqlite3_finalize(ins);
            return -1;
        }
    }
    sqlite3_finalize(ins);
    return 0;
}

int nodus_witness_v2_shadow_seed(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    /* REFUSALS: nothing is written, the status stays */
    if (!sqlite3_get_autocommit(w->db)) {
        QGP_LOG_WARN(LOG_TAG, "%s", "seeding refused: a transaction is open");
        return -1;
    }
    if (generation_window(w) != 1) {
        QGP_LOG_WARN(LOG_TAG, "%s", "seeding refused: the committed "
                     "generation is not in the shadow window (>= 5, < 6)");
        return -1;
    }
    int st = 0;
    if (nodus_witness_v2_shadow_status(w, &st) != 0 ||
        st != NODUS_V2_SHADOW_NONE) {
        QGP_LOG_WARN(LOG_TAG, "%s", "seeding refused: the shadow status "
                     "row is there (or unreadable)");
        return -1;
    }
    uint64_t tip = 0;
    if (nodus_witness_v2_tip_height(w, &tip) != 0) return -1;
    if (exec_sql(w->db, "BEGIN IMMEDIATE") != 0) return -1;

    if (nodus_witness_v2_shadow_build(w) != 0)
        return shadow_fail(w, 1, tip, "seeding: shadow tables and legs");
    if (log_write(w, tip) != 0)
        return shadow_fail(w, 1, tip, "seeding: the first log row");
    if (status_write(w, NODUS_V2_SHADOW_RUNNING) != 0)
        return shadow_fail(w, 1, tip, "seeding: the status");
    if (exec_sql(w->db, "COMMIT") != 0)
        return shadow_fail(w, 1, tip, "seeding: commit");
    QGP_LOG_INFO(LOG_TAG, "shadow run seeded at height %" PRIu64, tip);
    return 0;
}

/* ── the pass ────────────────────────────────────────────────────────── */

typedef struct {
    nodus_v2_trie_key_t k;
    uint8_t             val[64];
    int                 del;
} chg_t;

typedef struct {
    uint8_t key[64];
    size_t  key_len;
    uint8_t val[64];
} row_t;

typedef struct {
    sqlite3_stmt *cur;               /* the copy, ORDER BY key              */
    int           have;
    uint8_t       ck[64];
    size_t        ckl;
    uint8_t       cv[64];
    uint8_t       pk[64];            /* the previous scan key (order check) */
    size_t        pkl;
    int           have_prev;
    chg_t        *chg;
    size_t        nchg, capchg;
    int           want_rows;         /* mode `full`                         */
    row_t        *rows;
    size_t        nrows, caprows;
} cmp_t;

/* BLOB order, as SQLite compares: memcmp over the shorter, then length */
static int keycmp(const uint8_t *a, size_t al, const uint8_t *b, size_t bl) {
    size_t m = al < bl ? al : bl;
    int c = memcmp(a, b, m);
    if (c) return c;
    return al < bl ? -1 : al > bl ? 1 : 0;
}

static int cur_advance(cmp_t *c) {
    int rc = sqlite3_step(c->cur);
    if (rc == SQLITE_DONE) {
        c->have = 0;
        return 0;
    }
    if (rc != SQLITE_ROW) return -1;
    const void *k = sqlite3_column_blob(c->cur, 0);
    int kl = sqlite3_column_bytes(c->cur, 0);
    const void *v = sqlite3_column_blob(c->cur, 1);
    int vl = sqlite3_column_bytes(c->cur, 1);
    if (!k || kl < 1 || kl > 64 || !v || vl != 64 ||
        sqlite3_column_type(c->cur, 0) != SQLITE_BLOB ||
        sqlite3_column_type(c->cur, 1) != SQLITE_BLOB)
        return -1;
    memcpy(c->ck, k, (size_t)kl);
    c->ckl = (size_t)kl;
    memcpy(c->cv, v, 64);
    c->have = 1;
    return 0;
}

static int add_chg(cmp_t *c, const uint8_t *key, size_t kl,
                   const uint8_t *val, int del) {
    if (c->nchg == c->capchg) {
        size_t nc = c->capchg ? c->capchg * 2 : 32;
        chg_t *n = realloc(c->chg, nc * sizeof(*n));
        if (!n) return -1;
        c->chg = n;
        c->capchg = nc;
    }
    chg_t *e = &c->chg[c->nchg++];
    memset(e, 0, sizeof(*e));
    memcpy(e->k.b, key, kl);
    e->k.len = kl;
    e->del = del;
    if (val) memcpy(e->val, val, 64);
    return 0;
}

/* one scanned row against the copy (a merge of two ascending sequences) */
static int cmp_row(void *vctx, const uint8_t *key, size_t key_len,
                   const uint8_t val[64]) {
    cmp_t *c = (cmp_t *)vctx;
    g_rows_scanned++;
    if (c->have_prev && keycmp(c->pk, c->pkl, key, key_len) >= 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the row scan is not in canonical key "
                      "order");
        return -1;
    }
    memcpy(c->pk, key, key_len);
    c->pkl = key_len;
    c->have_prev = 1;

    while (c->have && keycmp(c->ck, c->ckl, key, key_len) < 0) {
        if (add_chg(c, c->ck, c->ckl, NULL, 1) != 0) return -1;
        if (cur_advance(c) != 0) return -1;
    }
    if (c->have && keycmp(c->ck, c->ckl, key, key_len) == 0) {
        if (memcmp(c->cv, val, 64) != 0 &&
            add_chg(c, key, key_len, val, 0) != 0)
            return -1;
        if (cur_advance(c) != 0) return -1;
    } else if (add_chg(c, key, key_len, val, 0) != 0) {
        return -1;
    }
    if (c->want_rows) {
        if (c->nrows == c->caprows) {
            size_t nc = c->caprows ? c->caprows * 2 : 64;
            row_t *n = realloc(c->rows, nc * sizeof(*n));
            if (!n) return -1;
            c->rows = n;
            c->caprows = nc;
        }
        row_t *r = &c->rows[c->nrows++];
        memcpy(r->key, key, key_len);
        r->key_len = key_len;
        memcpy(r->val, val, 64);
    }
    return 0;
}

/* the changes into the copy */
static int rows_apply(nodus_witness_t *w, int leg, const chg_t *chg,
                      size_t n) {
    sqlite3_stmt *up = NULL, *del = NULL;
    int ret = -1;
    do {
        if (sqlite3_prepare_v2(w->db,
                "INSERT OR REPLACE INTO v2_trie_shadow_rows (leg, key, value) "
                "VALUES (?1, ?2, ?3)", -1, &up, NULL) != SQLITE_OK) break;
        if (sqlite3_prepare_v2(w->db,
                "DELETE FROM v2_trie_shadow_rows WHERE leg = ?1 AND key = ?2",
                -1, &del, NULL) != SQLITE_OK) break;
        size_t i;
        for (i = 0; i < n; i++) {
            sqlite3_stmt *s = chg[i].del ? del : up;
            if (sqlite3_reset(s) != SQLITE_OK ||
                sqlite3_clear_bindings(s) != SQLITE_OK) break;
            if (sqlite3_bind_int(s, 1, leg) != SQLITE_OK ||
                sqlite3_bind_blob(s, 2, chg[i].k.b, (int)chg[i].k.len,
                                  SQLITE_STATIC) != SQLITE_OK) break;
            if (!chg[i].del &&
                sqlite3_bind_blob(s, 3, chg[i].val, 64, SQLITE_STATIC)
                    != SQLITE_OK) break;
            if (sqlite3_step(s) != SQLITE_DONE) break;
        }
        if (i != n) break;
        ret = 0;
    } while (0);
    sqlite3_finalize(up);
    sqlite3_finalize(del);
    return ret;
}

/* the full-rebuild check of one leg (mode `full`): the root of all rows
 * must be the shadow incremental root. @return 0 equal, -1 not / fault */
static int full_check(const cmp_t *c, const uint8_t incremental[64]) {
    evm_trie_full_kv *fk = c->nrows ? malloc(c->nrows * sizeof(*fk)) : NULL;
    if (c->nrows && !fk) return -1;
    for (size_t i = 0; i < c->nrows; i++) {
        fk[i].key = c->rows[i].key;
        fk[i].key_len = c->rows[i].key_len;
        fk[i].val = c->rows[i].val;
        fk[i].val_len = 64;
    }
    uint8_t full[64];
    int ok = evm_trie_full_root(fk, c->nrows, 1, EVM_TRIE_FULL_SHA3_512,
                                full) == 0;
    free(fk);
    if (!ok) return -1;
#ifdef QGP_FAULT_INJECT
    if (fault_here(4)) full[0] ^= 0x01;
#endif
    return memcmp(full, incremental, 64) == 0 ? 0 : -1;
}

/* One leg of a pass: compare, update, store, full check. @return 0 / -1. */
static int pass_leg(nodus_witness_t *w, int leg, int full_mode,
                    uint64_t height) {
    cmp_t c;
    memset(&c, 0, sizeof(c));
    c.want_rows = full_mode;
    int ret = -1;
    nodus_v2_trie_key_t *keys = NULL;
    do {
        if (sqlite3_prepare_v2(w->db,
                "SELECT key, value FROM v2_trie_shadow_rows WHERE leg = ?1 "
                "ORDER BY key ASC", -1, &c.cur, NULL) != SQLITE_OK) break;
        if (sqlite3_bind_int(c.cur, 1, leg) != SQLITE_OK) break;
        if (cur_advance(&c) != 0) break;
        if (FAULT_AT(1)) break;
        if (nodus_witness_v2_trie_scan_leg(w, leg, cmp_row, &c) != 0) break;
        int bad = 0;
        while (c.have) {                       /* the copy's tail: deleted */
            if (add_chg(&c, c.ck, c.ckl, NULL, 1) != 0 ||
                cur_advance(&c) != 0) { bad = 1; break; }
        }
        if (bad) break;
        sqlite3_finalize(c.cur);
        c.cur = NULL;

        uint8_t root[64];
        if (nodus_witness_v2_trie_shadow_leg_root(w, leg, root) != 0) break;
        if (c.nchg > 0) {
            keys = malloc(c.nchg * sizeof(*keys));
            if (!keys) break;
            for (size_t i = 0; i < c.nchg; i++) keys[i] = c.chg[i].k;
            uint8_t nroot[64];
            if (FAULT_AT(2) ||
                nodus_witness_v2_trie_shadow_update_leg(w, leg, keys, c.nchg,
                                                        root, nroot) != 0)
                break;
            if (rows_apply(w, leg, c.chg, c.nchg) != 0) break;
            if (roots_put(w, leg, nroot) != 0) break;
            memcpy(root, nroot, 64);
        }
        if (full_mode && full_check(&c, root) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "leg %d: the shadow incremental root is "
                          "not the full rebuild (height %" PRIu64 ")", leg,
                          height);
            break;
        }
        ret = 0;
    } while (0);
    sqlite3_finalize(c.cur);
    free(keys);
    free(c.chg);
    free(c.rows);
    return ret;
}

int nodus_witness_v2_shadow_sync(nodus_witness_t *w, int full) {
    if (!w || !w->db) return -1;
    if (sqlite3_get_autocommit(w->db)) return -1;      /* inside a txn only */
    for (int leg = NODUS_V2_TRIE_LEG_UTXO; leg <= NODUS_V2_TRIE_LEG_ATTENDANCE;
         leg++)
        if (pass_leg(w, leg, full ? 1 : 0, 0) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "leg %d: the shadow row comparison, trie "
                          "update or full check failed", leg);
            return -1;
        }
    return 0;
}

static int run_pass(nodus_witness_t *w) {
    uint64_t tip = 0, last = 0;
    if (nodus_witness_v2_tip_height(w, &tip) != 0) return -1;
    if (exec_sql(w->db, "BEGIN IMMEDIATE") != 0) return -1;
    if (log_last_height(w, &last) != 0)
        return shadow_fail(w, 1, tip, "the last logged height");
    if (tip <= last) {                         /* nothing is due             */
        (void)exec_sql(w->db, "ROLLBACK");
        return 0;
    }
    const int full_mode = w->config.hf9_shadow == NODUS_HF9_SHADOW_FULL;
    if (nodus_witness_v2_shadow_sync(w, full_mode) != 0)
        return shadow_fail(w, 1, tip, "row comparison, trie update or full "
                           "check (see the leg in the log above)");
    if (log_write(w, tip) != 0)
        return shadow_fail(w, 1, tip, "the log row");
    if (exec_sql(w->db, "COMMIT") != 0)
        return shadow_fail(w, 1, tip, "commit");
    return 0;
}

/* The decision of one hook call. `allow_seed` 0 = never seeds. */
static int step(nodus_witness_t *w, int allow_seed) {
    if (!w || !w->db) return -1;
    if (!sqlite3_get_autocommit(w->db)) {
        QGP_LOG_WARN(LOG_TAG, "%s", "shadow skipped: a transaction is open");
        return 0;
    }
    int win = generation_window(w);
    if (win < 0) {
        QGP_LOG_WARN(LOG_TAG, "%s", "shadow skipped: the committed "
                     "generation is unreadable");
        return 0;
    }
    if (win == 0) return 0;                       /* idle                    */
    int st = 0;
    if (nodus_witness_v2_shadow_status(w, &st) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "HF9-SHADOW FAULT the status is "
                      "unreadable");
        return -1;
    }
    if (win == 2) {                      /* generation >= 6: stop for good   */
        if (st == NODUS_V2_SHADOW_RUNNING &&
            status_write(w, NODUS_V2_SHADOW_STOPPED) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "HF9-SHADOW FAULT the stopped "
                          "status could not be written");
            return -1;
        }
        return 0;
    }
    if (st == NODUS_V2_SHADOW_NONE)
        return allow_seed ? nodus_witness_v2_shadow_seed(w) : 0;
    if (st != NODUS_V2_SHADOW_RUNNING) return 0;  /* stopped / faulted       */
    return run_pass(w);
}

int nodus_witness_v2_shadow_pass(nodus_witness_t *w) {
    return step(w, 0);
}

void nodus_witness_v2_shadow_after_commit(void *vw) {
    nodus_witness_t *w = (nodus_witness_t *)vw;
    if (!w || w->config.hf9_shadow == NODUS_HF9_SHADOW_OFF) return;
    (void)step(w, 1);
}
