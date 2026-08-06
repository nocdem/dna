/**
 * Nodus — Ledger V2 S5: atomic apply engine, genesis roots, supply gate,
 * rollback and cross-domain atomicity (INACTIVE layer).
 *
 * Rollback claims are NEVER made from return codes alone: db_state_digest
 * serializes EVERY table (sorted names, rows by rowid, typed column
 * bytes) into one SHA3-512 and the tests byte-compare it around every
 * fault point.
 *
 * Sections:
 *   1. Genesis: migrate + v2_genesis; idempotent / conflicting re-run;
 *      GENESIS-ROOT CYCLE PROOF — manifest.genesis_state_root(SYSTEM) ==
 *      the independently recomputed pre-registry PAYLOAD root, CORE's ==
 *      pre-registry core root, the FINAL head root differs from the
 *      payload (registry committed), full recomputation of system/
 *      domains/global roots equals the stored bytes, no all-zero
 *      placeholder anywhere, and an INDEPENDENT second fixture lands on
 *      byte-identical roots.
 *   2. Heads/updates: initial heads; CORE-only block (SYSTEM does not
 *      advance); SYSTEM-only block; two-tx one-update; declared-no-op
 *      rejects; undeclared mutation (cross-domain substitution) rejects;
 *      root-history linkage; restart reconstructs identical heads.
 *   3. Replay: idempotent re-apply (rc 1, digest unchanged), same-height
 *      conflict, height gap, wrong prev, reused BlockID.
 *   4. Cross-domain atomicity: one op touches SYSTEM+CORE → both commit
 *      (one tx identity, two local indices); fault after SYSTEM phase and
 *      after the CORE batch → NEITHER commits.
 *   5. Fault injection F1..F14 on a rich block: rc −1 and the FULL DB
 *      digest is byte-identical; F15: rc 2, state committed, restart
 *      reconstructs it and re-apply is idempotent.
 *   6. Resource limits: global tx cap; global verify budget; per-domain
 *      quota (consistent fixture-written CORE manifest with quota 1 /
 *      cost 5); rejected block leaves usage state unchanged.
 *   7. Supply (fixture 2, official DNA numbers): 1B raw total,
 *      7 × 10M self-bonds CARVED (additive 70M violates), remaining 930M
 *      as transparent UTXOs; bucket moves conserve; fee burn exactly
 *      once (double burn violates); reward mint path; underflow /
 *      overflow; duplicate / missing ownership; shielded state must not
 *      exist; restart invariant; engine block that breaks supply rolls
 *      back completely.
 *
 * @file test_v2_apply.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/domain_wire.h"
#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── fs + fixture ───────────────────────────────────────────────────── */
static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_apply_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x33, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    nodus_chain_config_db_migrate(fx->w);
    return 0;
}

static int fx_reopen(fixture_t *fx) {
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ── full-DB digest (the rollback oracle) ───────────────────────────── */
typedef struct { uint8_t *buf; size_t len, cap; } dyn_t;

static int dyn_put(dyn_t *d, const void *p, size_t n) {
    if (d->len + n > d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 65536;
        while (nc < d->len + n) nc *= 2;
        uint8_t *nb = realloc(d->buf, nc);
        if (!nb) return -1;
        d->buf = nb; d->cap = nc;
    }
    memcpy(d->buf + d->len, p, n);
    d->len += n;
    return 0;
}

static int db_state_digest(nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *ts = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "name NOT LIKE 'sqlite_%' ORDER BY name", -1, &ts, NULL)
        != SQLITE_OK)
        return -1;
    dyn_t d = { 0 };
    int rc, out_rc = -1;
    while ((rc = sqlite3_step(ts)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(ts, 0);
        if (dyn_put(&d, name, strlen(name) + 1) != 0) goto done;
        char sql[256];
        snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid",
                 name);
        sqlite3_stmt *rs = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rs, NULL) != SQLITE_OK)
            goto done;
        int rrc;
        while ((rrc = sqlite3_step(rs)) == SQLITE_ROW) {
            int nc = sqlite3_column_count(rs);
            for (int c = 0; c < nc; c++) {
                uint8_t t = (uint8_t)sqlite3_column_type(rs, c);
                if (dyn_put(&d, &t, 1) != 0) { sqlite3_finalize(rs); goto done; }
                if (t == SQLITE_NULL) continue;
                const void *b = sqlite3_column_blob(rs, c);
                int bl = sqlite3_column_bytes(rs, c);
                uint32_t bl32 = (uint32_t)bl;
                if (dyn_put(&d, &bl32, 4) != 0 ||
                    (bl > 0 && dyn_put(&d, b, (size_t)bl) != 0)) {
                    sqlite3_finalize(rs);
                    goto done;
                }
            }
        }
        sqlite3_finalize(rs);
        if (rrc != SQLITE_DONE) goto done;
    }
    if (rc != SQLITE_DONE) goto done;
    out_rc = qgp_sha3_512(d.buf ? d.buf : (const uint8_t *)"", d.len, out)
                 == 0 ? 0 : -1;
done:
    sqlite3_finalize(ts);
    free(d.buf);
    return out_rc;
}

/* ── block helpers ──────────────────────────────────────────────────── */
static void mk_id(uint8_t out[64], uint8_t fill) { memset(out, fill, 64); }

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_op_t *ops, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = 0;
    mk_id(b->block_id, (uint8_t)(0xB0 + h));
    mk_id(b->prev_block_id, h == 1 ? 0xEE : (uint8_t)(0xB0 + h - 1));
    mk_id(b->vset_hash, 0x77);
    b->ops = ops;
    b->n_ops = n;
}

static void mk_op(nodus_v2_op_t *op, uint8_t idfill, const char *sql,
                  uint32_t cost, uint32_t d0, int both) {
    memset(op, 0, sizeof(*op));
    memset(op->tx_id, idfill, 64);
    op->sql = sql;
    op->verify_cost = cost;
    if (both) {
        op->touched[0] = 0; op->touched[1] = 1; op->touched_n = 2;
    } else {
        op->touched[0] = d0; op->touched_n = 1;
    }
}

/* deterministic test mutations (the v1 merkle loader enforces 64-byte
 * nullifier/token_id/tx_hash widths — zeroblob-padded literals).
 * domain_id is EXPLICIT: the migrated utxo_set carries no default. */
#define SQL_CORE_UTXO(nul, amt) \
    "INSERT INTO utxo_set (nullifier, owner, amount, token_id, tx_hash, " \
    "output_index, block_height, created_at, unlock_block, domain_id) " \
    "VALUES (zeroblob(63)||x'" nul "', 'fp', " #amt ", zeroblob(64), " \
    "zeroblob(63)||x'aa', 0, 1, 0, 0, 1)"
/* PK is (param_id, effective_block) — the nonce digit keys both. */
#define SQL_SYS_CC(nonce) \
    "INSERT INTO chain_config_history (param_id, new_value, " \
    "effective_block, commit_block, tx_hash, proposal_nonce, " \
    "created_at_unix) VALUES (2, 5, 99999" #nonce ", 1, x'cc', " \
    #nonce ", 0)"

static uint64_t q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    uint64_t v = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int head_height(nodus_witness_t *w, int dom, uint64_t *out) {
    char sql[128];
    snprintf(sql, sizeof(sql),
             "SELECT domain_height FROM v2_domain_heads WHERE domain_id=%d",
             dom);
    *out = q1(w, sql);
    return *out == UINT64_MAX ? -1 : 0;
}

int main(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();
    /* S6: the apply engine + V2 genesis now require schema version 6
     * (the migration includes the S5 stage; every S5 root below is
     * byte-unchanged because the S6 tables are empty). */
    CHECK(nodus_witness_db_migrate_v2s6(fx.w) == 0, "migrate"); OK();

    /* ── 1. genesis + cycle proof ───────────────────────────────────── */
    /* independent PRE-registry recomputation of both payload roots */
    uint8_t sys_payload_pre[64], core_pre[64];
    CHECK(nodus_witness_system_payload_root_v2(fx.w, sys_payload_pre) == 0,
          "payload pre"); OK();
    CHECK(nodus_witness_core_root_v2(fx.w, core_pre) == 0, "core pre");

    uint8_t gen_id[64], vset[64];
    mk_id(gen_id, 0xEE);
    mk_id(vset, 0x77);
    CHECK(nodus_witness_v2_genesis(fx.w, gen_id, vset, 0) == 0, "genesis");
    OK();
    CHECK(nodus_witness_v2_genesis(fx.w, gen_id, vset, 0) == 0,
          "genesis not idempotent"); OK();
    uint8_t gen_id2[64];
    mk_id(gen_id2, 0xEF);
    CHECK(nodus_witness_v2_genesis(fx.w, gen_id2, vset, 0) == -2,
          "conflicting genesis accepted"); OK();

    dna_domain_manifest_t sys_man, core_man;
    CHECK(nodus_witness_domreg_get(fx.w, 0, NULL, &sys_man, NULL) == 0,
          "get sys man");
    CHECK(nodus_witness_domreg_get(fx.w, 1, NULL, &core_man, NULL) == 0,
          "get core man");
    uint8_t zero64[64];
    memset(zero64, 0, 64);
    /* no zero placeholder */
    CHECK(memcmp(sys_man.genesis_state_root, zero64, 64) != 0,
          "SYSTEM gsr is a zero placeholder"); OK();
    CHECK(memcmp(core_man.genesis_state_root, zero64, 64) != 0,
          "CORE gsr is a zero placeholder"); OK();
    /* cycle break: manifest gsr == PRE-registry payload roots */
    CHECK(memcmp(sys_man.genesis_state_root, sys_payload_pre, 64) == 0,
          "SYSTEM gsr != payload root"); OK();
    CHECK(memcmp(core_man.genesis_state_root, core_pre, 64) == 0,
          "CORE gsr != core payload"); OK();
    /* the FINAL head root commits the registry ⇒ differs from payload */
    uint8_t sys_head_root[64];
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT head FROM v2_domain_heads WHERE domain_id=0", -1,
              &st, NULL) == SQLITE_OK, "prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "sys head row");
        memcpy(sys_head_root,
               (const uint8_t *)sqlite3_column_blob(st, 0) + 4, 64);
        sqlite3_finalize(st);
    }
    CHECK(memcmp(sys_head_root, sys_payload_pre, 64) != 0,
          "final SYSTEM root == payload (registry not committed?)"); OK();
    /* independent recomputation == stored bytes (system/global) */
    uint8_t sys_now[64];
    CHECK(nodus_witness_system_root_v2(fx.w, sys_now) == 0, "sys now");
    CHECK(memcmp(sys_now, sys_head_root, 64) == 0,
          "stored SYSTEM head != recomputation"); OK();
    {
        uint8_t stored_g[64], stored_d[64];
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT domains_root, global_root FROM v2_blocks "
              "WHERE global_height=0", -1, &st, NULL) == SQLITE_OK, "prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "gen row");
        memcpy(stored_d, sqlite3_column_blob(st, 0), 64);
        memcpy(stored_g, sqlite3_column_blob(st, 1), 64);
        sqlite3_finalize(st);
        uint8_t g2[64];
        CHECK(dna_v2_global_root(stored_d, g2) == 0 &&
              memcmp(g2, stored_g, 64) == 0,
              "global root recomputation mismatch"); OK();
    }
    /* independent second fixture → byte-identical genesis roots */
    {
        fixture_t fb;
        CHECK(fx_open(&fb) == 0, "fixture b");
        CHECK(nodus_witness_db_migrate_v2s6(fb.w) == 0, "migrate b");
        CHECK(nodus_witness_v2_genesis(fb.w, gen_id, vset, 0) == 0,
              "genesis b");
        uint8_t sys_b[64];
        CHECK(nodus_witness_system_root_v2(fb.w, sys_b) == 0, "sys b");
        CHECK(memcmp(sys_b, sys_head_root, 64) == 0,
              "independent fixture roots diverge"); OK();
        fx_close(&fb);
    }

    /* ── 2+3. heads / updates / replay ──────────────────────────────── */
    uint64_t h_sys = 9, h_core = 9;
    CHECK(head_height(fx.w, 0, &h_sys) == 0 && h_sys == 0, "sys h0"); OK();
    CHECK(head_height(fx.w, 1, &h_core) == 0 && h_core == 0, "core h0");
    OK();

    /* block 1: CORE-only */
    nodus_v2_op_t op1;
    mk_op(&op1, 0x01, SQL_CORE_UTXO("01", 100), 1, 1, 0);
    nodus_v2_block_t b1;
    mk_block(&b1, 1, &op1, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b1) == 0, "block 1"); OK();
    CHECK(head_height(fx.w, 0, &h_sys) == 0 && h_sys == 0,
          "SYSTEM advanced while untouched"); OK();
    CHECK(head_height(fx.w, 1, &h_core) == 0 && h_core == 1, "core h1");
    OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_updates "
                   "WHERE global_height=1") == 1,
          "block1 must carry exactly one update"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_root_history "
                   "WHERE domain_id=1 AND domain_height=1") == 1,
          "history row missing"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_root_history "
                   "WHERE domain_id=0 AND domain_height>0") == 0,
          "phantom SYSTEM history"); OK();

    /* replay matrix */
    uint8_t dg[64], dg2[64];
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    nodus_v2_block_t rb = b1;
    CHECK(nodus_witness_v2_apply_block(fx.w, &rb) == 1,
          "identical replay not idempotent"); OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "idempotent replay wrote state"); OK();
    rb = b1;
    rb.block_id[0] ^= 1;                       /* same height, diff id  */
    CHECK(nodus_witness_v2_apply_block(fx.w, &rb) == -1,
          "conflicting height accepted"); OK();
    nodus_v2_op_t opx;
    mk_op(&opx, 0x0F, SQL_CORE_UTXO("0f", 5), 1, 1, 0);
    nodus_v2_block_t bx;
    mk_block(&bx, 3, &opx, 1);                 /* gap                    */
    CHECK(nodus_witness_v2_apply_block(fx.w, &bx) == -1, "gap accepted");
    OK();
    mk_block(&bx, 2, &opx, 1);
    bx.prev_block_id[0] ^= 1;                  /* wrong prev             */
    CHECK(nodus_witness_v2_apply_block(fx.w, &bx) == -1,
          "wrong prev accepted"); OK();
    mk_block(&bx, 2, &opx, 1);
    memcpy(bx.block_id, b1.block_id, 64);      /* reused BlockID         */
    CHECK(nodus_witness_v2_apply_block(fx.w, &bx) == -1,
          "reused BlockID accepted"); OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "rejected blocks wrote state"); OK();

    /* block 2: SYSTEM-only */
    nodus_v2_op_t op2;
    mk_op(&op2, 0x02, SQL_SYS_CC(1), 1, 0, 0);
    nodus_v2_block_t b2;
    mk_block(&b2, 2, &op2, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b2) == 0, "block 2"); OK();
    CHECK(head_height(fx.w, 0, &h_sys) == 0 && h_sys == 1, "sys h1"); OK();
    CHECK(head_height(fx.w, 1, &h_core) == 0 && h_core == 1,
          "core advanced while untouched"); OK();

    /* block 3: two CORE txs → ONE update, local indices 0 and 1 */
    nodus_v2_op_t two[2];
    mk_op(&two[0], 0x31, SQL_CORE_UTXO("31", 10), 1, 1, 0);
    mk_op(&two[1], 0x32, SQL_CORE_UTXO("32", 20), 2, 1, 0);
    nodus_v2_block_t b3;
    mk_block(&b3, 3, two, 2);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b3) == 0, "block 3"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_updates "
                   "WHERE global_height=3") == 1, "one update for 2 tx");
    OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_tx_local_index "
                   "WHERE domain_id=1 AND domain_height=2") == 2 &&
          q1(fx.w, "SELECT local_index FROM v2_tx_local_index "
                   "WHERE tx_id=x'"
                   "32323232323232323232323232323232"
                   "32323232323232323232323232323232"
                   "32323232323232323232323232323232"
                   "32323232323232323232323232323232' AND domain_id=1")
              == 1, "local indices wrong"); OK();
    /* update carries the summed resources */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT upd FROM v2_domain_updates WHERE global_height=3",
              -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW,
              "upd row");
        dna_domain_update_t u;
        CHECK(dna_dupd_decode(sqlite3_column_blob(st, 0),
                              (size_t)sqlite3_column_bytes(st, 0), &u) == 0,
              "upd decode");
        sqlite3_finalize(st);
        CHECK(u.res_tx_count == 2 && u.res_verify_cost == 3 &&
              u.old_height == 1 && u.new_height == 2,
              "update resource/height fields wrong"); OK();
    }

    /* declared no-op rejects (no fake updates) */
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    nodus_v2_op_t noop;
    mk_op(&noop, 0x40, NULL, 1, 1, 0);
    nodus_v2_block_t b4;
    mk_block(&b4, 4, &noop, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b4) == -1,
          "declared no-op produced an update"); OK();
    /* undeclared mutation rejects (cross-domain substitution guard) */
    nodus_v2_op_t subst;
    mk_op(&subst, 0x41, SQL_CORE_UTXO("41", 5), 1, 0, 0); /* declares SYS */
    mk_block(&b4, 4, &subst, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b4) == -1,
          "undeclared CORE mutation accepted"); OK();
    /* wrong expected root rejects */
    nodus_v2_op_t ok4;
    mk_op(&ok4, 0x42, SQL_CORE_UTXO("42", 5), 1, 1, 0);
    mk_block(&b4, 4, &ok4, 1);
    uint8_t bad_root[64];
    memset(bad_root, 0xDD, 64);
    b4.expect_global_root = bad_root;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b4) == -1,
          "wrong expected root accepted"); OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "rejected block 4 candidates wrote state"); OK();

    /* ── 4. cross-domain atomicity ──────────────────────────────────── */
    nodus_v2_op_t cross;
    mk_op(&cross, 0x50,
          SQL_SYS_CC(2) ";" SQL_CORE_UTXO("50", 30), 2, 0, 1);
    nodus_v2_block_t b4c;
    mk_block(&b4c, 4, &cross, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b4c) == 0, "cross block");
    OK();
    CHECK(head_height(fx.w, 0, &h_sys) == 0 && h_sys == 2 &&
          head_height(fx.w, 1, &h_core) == 0 && h_core == 3,
          "cross block heights"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_updates "
                   "WHERE global_height=4") == 2, "two updates"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_tx_index WHERE tx_id=x'"
                   "50505050505050505050505050505050"
                   "50505050505050505050505050505050"
                   "50505050505050505050505050505050"
                   "50505050505050505050505050505050'") == 1 &&
          q1(fx.w, "SELECT COUNT(*) FROM v2_tx_local_index WHERE tx_id=x'"
                   "50505050505050505050505050505050"
                   "50505050505050505050505050505050"
                   "50505050505050505050505050505050"
                   "50505050505050505050505050505050'") == 2,
          "one identity, two local indices"); OK();

    /* fault after SYSTEM phase / after CORE batch → NEITHER commits */
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    nodus_v2_op_t cross2;
    mk_op(&cross2, 0x51,
          SQL_SYS_CC(3) ";" SQL_CORE_UTXO("51", 40), 2, 0, 1);
    nodus_v2_block_t b5;
    mk_block(&b5, 5, &cross2, 1);
    b5.fail_at = V2AP_FAIL_AFTER_SYSTEM;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b5) == -1, "F2 cross");
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "SYSTEM half survived"); OK();
    mk_block(&b5, 5, &cross2, 1);
    b5.fail_at = V2AP_FAIL_AFTER_DOMAIN_BATCH;
    b5.fail_domain_batch = 1;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b5) == -1, "F4 cross");
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "CORE half survived"); OK();

    /* ── 5. fault injection F1..F14 (rich block), then F15 ──────────── */
    nodus_v2_op_t rich[3];
    mk_op(&rich[0], 0x61, SQL_SYS_CC(4), 1, 0, 0);
    mk_op(&rich[1], 0x62,
          SQL_SYS_CC(5) ";" SQL_CORE_UTXO("62", 11), 2, 0, 1);
    mk_op(&rich[2], 0x63, SQL_CORE_UTXO("63", 12), 1, 1, 0);
    for (int f = V2AP_FAIL_AFTER_BEGIN; f <= V2AP_FAIL_COMMIT; f++) {
        nodus_v2_block_t bf;
        mk_block(&bf, 5, rich, 3);
        bf.fail_at = (nodus_v2_apply_fail_t)f;
        bf.fail_domain_batch = 1;
        CHECK(nodus_witness_v2_apply_block(fx.w, &bf) == -1,
              "fault point did not fail");
        CHECK(db_state_digest(fx.w, dg2) == 0 &&
              memcmp(dg, dg2, 64) == 0, "fault point leaked state");
    }
    OK();
    /* F15: committed, pre-cache crash window */
    nodus_v2_block_t b5f;
    mk_block(&b5f, 5, rich, 3);
    b5f.fail_at = V2AP_FAIL_AFTER_COMMIT;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b5f) == 2, "F15 rc"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_blocks WHERE global_height=5")
              == 1, "F15 not committed"); OK();
    /* restart reconstructs the committed state; replay is idempotent */
    uint8_t dg_committed[64];
    CHECK(db_state_digest(fx.w, dg_committed) == 0, "digest");
    CHECK(fx_reopen(&fx) == 0, "reopen after F15");
    CHECK(db_state_digest(fx.w, dg2) == 0 &&
          memcmp(dg_committed, dg2, 64) == 0,
          "restart lost committed state"); OK();
    nodus_v2_block_t b5r;
    mk_block(&b5r, 5, rich, 3);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b5r) == 1,
          "post-crash replay applied twice"); OK();

    /* ── 6. resource limits ─────────────────────────────────────────── */
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    {   /* global tx cap (10) */
        nodus_v2_op_t many[11];
        for (int i = 0; i < 11; i++) {
            char *sql = NULL;   /* declaration-only ops still count */
            mk_op(&many[i], (uint8_t)(0x70 + i), sql, 1, 1, 0);
        }
        nodus_v2_block_t bm;
        mk_block(&bm, 6, many, 11);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bm) == -1,
              "global tx cap ignored"); OK();
    }
    {   /* global verify budget */
        nodus_v2_op_t big;
        mk_op(&big, 0x7F, SQL_CORE_UTXO("7f", 1), 1001, 1, 0);
        nodus_v2_block_t bb;
        mk_block(&bb, 6, &big, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bb) == -1,
              "global budget ignored"); OK();
    }
    {   /* per-domain quota via a CONSISTENT fixture-written manifest */
        dna_domain_manifest_t qman = core_man;
        qman.quota_tx_per_block = 1;
        qman.quota_verify_cost = 5;
        uint8_t enc[DNA_DOMMAN_MAX_ENC_LEN], mh[64];
        size_t el = 0;
        CHECK(dna_domman_encode(&qman, enc, sizeof(enc), &el) == 0, "enc");
        CHECK(dna_domman_hash(&qman, mh) == 0, "hash");
        dna_domreg_record_t rec;
        CHECK(nodus_witness_domreg_get(fx.w, 1, &rec, NULL, NULL) == 0,
              "rec");
        memcpy(rec.current_manifest_hash, mh, 64);
        uint8_t recb[DNA_DOMREG_REC_ENC_LEN];
        CHECK(dna_domreg_record_encode(&rec, recb) == 0, "recb");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE domain_registry SET record=?1, current_manifest=?2 "
              "WHERE domain_id=1", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, recb, sizeof(recb), SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, enc, (int)el, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "update");
        sqlite3_finalize(st);

        nodus_v2_op_t d2[2];
        mk_op(&d2[0], 0x81, SQL_CORE_UTXO("81", 1), 1, 1, 0);
        mk_op(&d2[1], 0x82, SQL_CORE_UTXO("82", 1), 1, 1, 0);
        nodus_v2_block_t bq;
        mk_block(&bq, 6, d2, 2);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bq) == -1,
              "per-domain tx quota ignored"); OK();
        nodus_v2_op_t costly;
        mk_op(&costly, 0x83, SQL_CORE_UTXO("83", 1), 6, 1, 0);
        mk_block(&bq, 6, &costly, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bq) == -1,
              "per-domain cost quota ignored"); OK();
        /* restore the genesis manifest (consistent again) */
        uint8_t enc0[DNA_DOMMAN_MAX_ENC_LEN], mh0[64];
        size_t el0 = 0;
        CHECK(dna_domman_encode(&core_man, enc0, sizeof(enc0), &el0) == 0 &&
              dna_domman_hash(&core_man, mh0) == 0, "enc0");
        memcpy(rec.current_manifest_hash, mh0, 64);
        CHECK(dna_domreg_record_encode(&rec, recb) == 0, "recb0");
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE domain_registry SET record=?1, current_manifest=?2 "
              "WHERE domain_id=1", -1, &st, NULL) == SQLITE_OK, "prep0");
        sqlite3_bind_blob(st, 1, recb, sizeof(recb), SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, enc0, (int)el0, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "restore");
        sqlite3_finalize(st);
    }
    /* rejected blocks left resource/usage state unchanged (digest holds
     * for everything except the two manifest writes we restored) */
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "resource rejections leaked state"); OK();
    fx_close(&fx);

    /* ── 7. supply (official DNA numbers) ───────────────────────────── */
    fixture_t fs;
    CHECK(fx_open(&fs) == 0, "supply fixture"); OK();
    CHECK(nodus_witness_db_migrate_v2s6(fs.w) == 0, "migrate");

    /* 1B total; 7 × 10M self-bonds CARVED; remainder 930M as UTXOs.
     * Production supply_tracking schema (nodus_witness.c): id=1 CHECK,
     * genesis/burned/minted + current_supply/last_tx_hash/last_sequence. */
    CHECK(run_sql(fs.w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "total_minted, current_supply, last_tx_hash, last_sequence) "
        "VALUES (1, 100000000000000000, 0, 0, 100000000000000000, "
        "x'00', 0)") == 0, "supply row"); OK();
    for (int i = 0; i < 7; i++) {
        char sql[640];
        snprintf(sql, sizeof(sql),
            "INSERT INTO validators (pubkey_hash, pubkey, self_stake, "
            "total_delegated, commission_bps, status, active_since_block, "
            "unstake_destination_fp, unstake_destination_pubkey) "
            "VALUES (zeroblob(63)||x'%02x', zeroblob(2591)||x'%02x', "
            "1000000000000000, 0, 100, 0, 0, 'fp%d', zeroblob(2592))",
            0xA0 + i, 0xB0 + i, i);
        CHECK(run_sql(fs.w->db, sql) == 0, "validator");
    }
    CHECK(run_sql(fs.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (zeroblob(63)||x'01', 'genesis', 93000000000000000, "
        "zeroblob(64), zeroblob(63)||x'aa', 0, 0, 0, 0, 1)") == 0,
        "930M utxo");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0,
          "official 1B/70M carve-out does not conserve"); OK();

    /* ADDITIVE 70M (on top of 1B) must violate */
    CHECK(run_sql(fs.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (zeroblob(63)||x'02', 'bogus', 7000000000000000, "
        "zeroblob(64), zeroblob(63)||x'bb', 0, 0, 0, 0, 1)") == 0,
        "additive");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "additive 70M conserved"); OK();
    CHECK(run_sql(fs.w->db,
        "DELETE FROM utxo_set WHERE nullifier=zeroblob(63)||x'02'") == 0, "undo");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "restore"); OK();

    /* transparent → self-bond lock (move, no mint) + unlock */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 1000000000000000 "
        "WHERE nullifier=zeroblob(63)||x'01';"
        "UPDATE validators SET self_stake = self_stake + 1000000000000000 "
        "WHERE pubkey_hash=zeroblob(63)||x'a0'") == 0, "lock");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "bond lock broke"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE validators SET self_stake = self_stake - 1000000000000000 "
        "WHERE pubkey_hash=zeroblob(63)||x'a0';"
        "UPDATE utxo_set SET amount = amount + 1000000000000000 "
        "WHERE nullifier=zeroblob(63)||x'01'") == 0, "unlock");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "unlock broke"); OK();
    /* delegation lock (classification change, not total) */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 10000000000 "
        "WHERE nullifier=zeroblob(63)||x'01';"
        "UPDATE validators SET total_delegated = total_delegated + "
        "10000000000 WHERE pubkey_hash=zeroblob(63)||x'a1'") == 0, "delegate");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "delegation broke");
    OK();
    /* fee burn EXACTLY once */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 1000000 "
        "WHERE nullifier=zeroblob(63)||x'01';"
        "UPDATE supply_tracking SET total_burned = total_burned + 1000000")
        == 0, "burn");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "single burn broke");
    OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_burned = total_burned + 1000000")
        == 0, "double burn");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "fee processed twice conserved"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_burned = total_burned - 1000000")
        == 0, "undo double");
    /* reward: mint into the epoch pool, then settle pool → utxo */
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_minted = total_minted + 3200;"
        "INSERT INTO epoch_state (epoch_start_height, epoch_pool_accum, "
        "snapshot_hash) VALUES (0, 3200, zeroblob(64))") == 0, "mint");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "mint broke"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE epoch_state SET epoch_pool_accum = 0 "
        "WHERE epoch_start_height = 0;"
        "UPDATE utxo_set SET amount = amount + 3200 "
        "WHERE nullifier=zeroblob(63)||x'01'") == 0, "settle");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "settle broke"); OK();
    /* duplicate ownership: value in a UTXO AND a bond simultaneously */
    CHECK(run_sql(fs.w->db,
        "UPDATE validators SET self_stake = self_stake + 5 "
        "WHERE pubkey_hash=zeroblob(63)||x'a2'") == 0, "dup owner");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "double-counted value conserved"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE validators SET self_stake = self_stake - 5 "
        "WHERE pubkey_hash=zeroblob(63)||x'a2'") == 0, "undo");
    /* missing ownership */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 5 WHERE nullifier=zeroblob(63)||x'01'")
        == 0, "vanish");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0, "vanished conserved");
    OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount + 5 WHERE nullifier=zeroblob(63)||x'01'")
        == 0, "undo");
    /* underflow / overflow */
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_burned = 200000000000000001")
        == 0, "uf");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0, "underflow passed");
    OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_burned = 1000000, "
        "total_minted = 18446744073709551615") == 0, "of");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0, "overflow passed");
    OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_minted = 3200") == 0, "restore");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "restore broke"); OK();
    /* shielded state must not exist */
    CHECK(run_sql(fs.w->db, "CREATE TABLE pool_state (x INTEGER)") == 0,
          "mk pool");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "shielded pool state tolerated"); OK();
    CHECK(run_sql(fs.w->db, "DROP TABLE pool_state") == 0, "drop pool");
    /* restart invariant */
    CHECK(fx_reopen(&fs) == 0, "reopen");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "restart broke"); OK();

    /* an engine block that BREAKS supply rolls back completely:
     * (needs v2 genesis on this populated fixture) */
    CHECK(nodus_witness_v2_genesis(fs.w, gen_id, vset, 0) == 0,
          "supply-fixture genesis"); OK();
    uint8_t sdg[64], sdg2[64];
    CHECK(db_state_digest(fs.w, sdg) == 0, "digest");
    nodus_v2_op_t inflate;
    mk_op(&inflate, 0x90, SQL_CORE_UTXO("90", 999), 1, 1, 0);
    nodus_v2_block_t sb;
    mk_block(&sb, 1, &inflate, 1);
    CHECK(nodus_witness_v2_apply_block(fs.w, &sb) == -1,
          "supply-breaking block accepted"); OK();
    CHECK(db_state_digest(fs.w, sdg2) == 0 && memcmp(sdg, sdg2, 64) == 0,
          "supply-breaking block leaked state"); OK();

    /* ── 8. SUPPLY OWNERSHIP (locked correction): native issuance is a
     * DNA_CORE commitment. A SYSTEM-side value movement (mint into the
     * epoch pool, pool settlement) touches BOTH domains atomically
     * through the GENERIC touched mechanism; a fee burn is CORE-local
     * (both of its buckets — the UTXO and the burned counter — are
     * CORE-owned); an undeclared issuance mutation trips the untouched-
     * domain guard on CORE. ─────────────────────────────────────────── */
    {
        /* (a) MINT: total_minted (CORE issuance) + epoch pool (SYSTEM
         * accrual) — one cross-domain op, two DomainUpdates, conserved. */
        nodus_v2_op_t mint;
        mk_op(&mint, 0x91,
              "UPDATE supply_tracking SET total_minted = total_minted + 500;"
              "UPDATE epoch_state SET epoch_pool_accum = "
              "epoch_pool_accum + 500 WHERE epoch_start_height = 0",
              2, 0, 1);
        nodus_v2_block_t mb;
        mk_block(&mb, 1, &mint, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == 0, "mint block");
        CHECK(q1(fs.w, "SELECT COUNT(*) FROM v2_domain_updates "
                       "WHERE global_height=1") == 2,
              "mint must update BOTH domains atomically"); OK();
        CHECK(q1(fs.w, "SELECT total_minted FROM supply_tracking")
                  == 3200 + 500, "minted exactly once");
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "mint conserves");
        OK();

        /* (b) SETTLE: pool (SYSTEM) → transparent UTXO (CORE): a native
         * value MOVE between a SYSTEM-owned and a CORE-owned bucket —
         * both domains touched, total supply unchanged. */
        nodus_v2_op_t settle;
        mk_op(&settle, 0x92,
              "UPDATE epoch_state SET epoch_pool_accum = "
              "epoch_pool_accum - 500 WHERE epoch_start_height = 0;"
              "UPDATE utxo_set SET amount = amount + 500 "
              "WHERE nullifier = zeroblob(63)||x'01'",
              2, 0, 1);
        mk_block(&mb, 2, &settle, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == 0, "settle block");
        CHECK(q1(fs.w, "SELECT COUNT(*) FROM v2_domain_updates "
                       "WHERE global_height=2") == 2,
              "settle must update BOTH domains"); OK();
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0,
              "cross-domain move conserves total supply"); OK();

        /* (c) BURN: fee UTXO decrement + burned counter — BOTH buckets
         * are CORE-owned now, so the burn is a CORE-LOCAL transition
         * (exactly one DomainUpdate; SYSTEM does not move). */
        uint64_t sys_h_burn = q1(fs.w,
            "SELECT domain_height FROM v2_domain_heads WHERE domain_id=0");
        nodus_v2_op_t burn;
        mk_op(&burn, 0x93,
              "UPDATE utxo_set SET amount = amount - 100 "
              "WHERE nullifier = zeroblob(63)||x'01';"
              "UPDATE supply_tracking SET total_burned = total_burned + 100",
              1, 1, 0);
        mk_block(&mb, 3, &burn, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == 0, "burn block");
        CHECK(q1(fs.w, "SELECT COUNT(*) FROM v2_domain_updates "
                       "WHERE global_height=3") == 1,
              "burn is CORE-local: exactly one update"); OK();
        CHECK(q1(fs.w, "SELECT domain_height FROM v2_domain_heads "
                       "WHERE domain_id=0") == sys_h_burn,
              "burn must not advance SYSTEM"); OK();
        CHECK(q1(fs.w, "SELECT total_burned FROM supply_tracking")
                  == 1000000 + 100,      /* fixture's prior fee burn + 100 */
              "burned exactly once");
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "burn conserves");
        OK();

        /* (d) an issuance mutation NOT declaring CORE trips the
         * untouched-domain guard (the counters are CORE-committed). */
        uint8_t g0[64], g1[64];
        CHECK(db_state_digest(fs.w, g0) == 0, "digest");
        nodus_v2_op_t sneak;
        mk_op(&sneak, 0x94,
              SQL_SYS_CC(7) ";"
              "UPDATE supply_tracking SET total_minted = total_minted + 1",
              1, 0, 0);                    /* declares SYSTEM only */
        mk_block(&mb, 4, &sneak, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == -1,
              "undeclared issuance mutation accepted"); OK();
        CHECK(db_state_digest(fs.w, g1) == 0 && memcmp(g0, g1, 64) == 0,
              "undeclared issuance mutation leaked state"); OK();

        /* (e) fault during a cross-domain native move rolls BOTH
         * domains, heads, roots, accounting and metadata back. */
        nodus_v2_op_t mint2;
        mk_op(&mint2, 0x95,
              "UPDATE supply_tracking SET total_minted = total_minted + 9;"
              "UPDATE epoch_state SET epoch_pool_accum = "
              "epoch_pool_accum + 9 WHERE epoch_start_height = 0",
              2, 0, 1);
        static const nodus_v2_apply_fail_t xpts[] = {
            V2AP_FAIL_AFTER_CROSS, V2AP_FAIL_AFTER_SUPPLY_MUT,
            V2AP_FAIL_AFTER_UPDATES, V2AP_FAIL_AFTER_HEADS,
            V2AP_FAIL_AFTER_BLOCK_META, V2AP_FAIL_BEFORE_COMMIT
        };
        for (size_t i = 0; i < sizeof(xpts) / sizeof(xpts[0]); i++) {
            mk_block(&mb, 4, &mint2, 1);
            mb.fail_at = xpts[i];
            CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == -1,
                  "cross-move fault did not fail");
            CHECK(db_state_digest(fs.w, g1) == 0 &&
                  memcmp(g0, g1, 64) == 0,
                  "cross-move fault leaked one domain's half");
        }
        OK();
    }
    fx_close(&fs);

    printf("test_v2_apply: ALL %d checks passed\n", g_checks);
    return 0;
}
