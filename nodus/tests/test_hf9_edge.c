/**
 * @file nodus/tests/test_hf9_edge.c
 * @brief HF-9 WP3, plan row T-6 — the generation-6 edge at the end of block
 *        A-1 (phase 6b'''''), on a seeded S20 chain through the engine's own
 *        block path (the cometbft lane's apply, as test_hf7_edge.c).
 *
 * Plan docs/plans/approved/2026-11-04-hf9.md §7.2 (steps 1-7), §7.3 (the
 * boundary table), §12 T-6; decisions D12 (one-time build allowed, mismatch
 * stops the node), D17 report 1 finding 1 (capture only from the committed
 * activation), D24 / D25. The pure half (the literal D6, the pins, the
 * param-24 / 25 rules) is test_hf9_activation.c.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. THE EDGE (production runtimes, EVM-enabled build, an S20 database
 *     climbing 1 -> 2 -> 3 -> 4 -> 5 -> 6 by params 9 / 14 / 18 / 22 / 24 at
 *     heights 3 / 5 / 8 / 11 / 14, so the edge block is 13):
 *     before the edge capture = 0, v2_trie_roots has no row and the dirty
 *     table is empty; the A-1 block commits; then
 *      (a) the registry is SYSTEM v12 / CORE v11 with the compiled
 *          generation-6 hashes, both resolve generation 6, the EVM record
 *          is untouched;
 *      (b) SYSTEM and CORE have a DomainUpdate at A-1 naming v12 / v11 and
 *          SYSTEM's root moved;
 *      (c) v2_trie_state.capture = 1, v2_trie_dirty is empty;
 *      (d) v2_trie_roots has one row per leg, each equal to this test's
 *          recomputation of the leg from the rows (nodus_witness_v2_trie_
 *          build_leg: incremental root == full-rebuild root == the stored
 *          root); legs 2 (tokens), 4 (names), 5 (one RELEASED registry
 *          row) and 6 (segments) hold this test's extra rows and are not
 *          the empty root (so the build visited rows); for every leg the
 *          root is the empty root SHA3-512(0x80) exactly when its table has
 *          no row (the genesis fixture writes no UTXO, so leg 1 is empty
 *          here);
 *      (e) the committed SYSTEM root is "NDS.SYS.v7" (== nodus_witness_
 *          system_root_v7 and not v6) and the committed CORE root is
 *          "NDS.CORE.v4" (== nodus_witness_core_root_v4 and not the
 *          generation-3..5 composition), the global root of A-1 equals the
 *          recomputation, and the root fixed at A-1 is the one carried
 *          through block A (an idle block: no root moves);
 *      (f) after the edge the 24 triggers are live: a token row written
 *          between blocks leaves exactly one dirty key; the next idle block
 *          flushes it (phase 8-pre) and the untouched-domain guard of phase
 *          8 refuses it (CORE's root moved, CORE not declared touched: a
 *          VERDICT, the database byte-identical); deleting the row restores
 *          the root, the next idle block commits, the dirty table is empty
 *          and every leg root equals its recomputation again.
 *     The migration snapshot, the trigger-after-edge and the two roots are
 *     the §7.3 table's rows "Tries", "CORE / SYSTEM / storage composition",
 *     "First changed application post-state".
 *  B. A param-24 row whose effective block is the NEXT block but whose
 *     registry is not generation 5 (params 9 / 14 only: the EVM generation)
 *     is a node FAULT at its A-1 ("registry is not generation 5"), the
 *     database byte-identical.
 *  C. A param-24 row holding D6 + 1 is a node FAULT at A-1 ("generation-6
 *     vote D6").
 *  D. TRIGGER SHAPE (§7.2 step 1): absent at h and absent at h+1 (a
 *     param-24 row effective at block 1 000 000, probed through block A+2)
 *     is not the edge: nothing happens, the registry stays generation 5,
 *     capture stays 0, no trie is built. Present at h and at h+1 (blocks A,
 *     A+1) leaves the registry alone too (A); absent at h and present at
 *     h+1 is the edge (A). A READ FAILURE of the param-24 row is NOT
 *     induced: the reader (chain_config_cache / history) answers a corrupt
 *     stored value with the value, not -1, and a dropped table answers
 *     "pre-migration: absent" — the edge's -2 path is read in source only
 *     (nodus_chain_config_get_u64's own fault paths are
 *     test_chain_config_failclose.c).
 *  E. ATOMICITY AND THE MISMATCH FAULT (compiled only with
 *     -DQGP_FAULT_INJECT=ON): an injected incremental-vs-full mismatch on
 *     one leg makes block A-1 a node FAULT ("one-time build of the eight
 *     tries"), the database byte-identical, capture still 0, the registry
 *     still generation 5 and v2_trie_roots empty (a rolled-back A-1 leaves
 *     the capture 0); with the hook disarmed the same block commits and the
 *     edge runs exactly once.
 *  F. A MISSING TRIGGER at the edge (one of the 24 dropped before A-1) is a
 *     node FAULT ("24 dirty-capture triggers"), the database byte-identical,
 *     capture 0.
 *  G. SHADOW STATUS NEVER SELECTS COMMITMENT: four fresh chains, each with
 *     a v2_trie_shadow_state row of another status (0, 1, 2, 3) written
 *     before the edge, produce the same committed roots as the chain with no
 *     such row — SYSTEM / CORE head roots, every v2_trie_roots row and the
 *     global root at A-1 — and capture is 1 in all of them.
 *  H. REPLAY FROM GENESIS: a second chain built from scratch through the
 *     same blocks reaches the same leg roots, the same SYSTEM / CORE roots
 *     and the same global roots at A-1 and A as the first (determinism of
 *     the edge as a pure function of committed rows and the param row).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generations 3-6 and the tries exist
 * only there; the target is registered only in that configuration).
 * Section E is compiled only under -DQGP_FAULT_INJECT=ON (the hook
 * nodus_witness_v2_trie_test_corrupt_full) and is ABSENT otherwise: a build
 * without the flag has missing coverage for E, not a pass. No environment.
 * The heights assume no epoch boundary among 1..16 (DNAC_EPOCH_LENGTH 720);
 * the test CHECKs that, so a short-epoch build (E = 15) fails the guard
 * rather than running the wrong scenario (precedent test_hf7_edge.c).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * /tmp/test_hf9_edge_<tag>_XXXXXX directories, removed at the end of every
 * case (a crash leaves one).
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  - The recomputation in A(d) is nodus_witness_v2_trie_build_leg, which
 *    shares the row readers with the edge's own build: it proves "stored
 *    root == a fresh build of the same rows == the full rebuild", not that
 *    the readers select the right rows (that is test_hf9_trie_legs.c and
 *    the independent KAT test_hf9_kat.c).
 *  - The extra rows this test writes (tokens, names, segments, one
 *    RELEASED registry node) are written between blocks with capture 0 and
 *    are the only rows beyond the genesis fixture's; no UTXO is added (the
 *    conservation invariant would refuse the block), so a UTXO-writer
 *    path through the edge is covered only by the genesis rows.
 *  - The edge's schema check (EXACTLY S20, step 2) sits behind the block-
 *    entry schema gate (S16-S20), which refuses an older or newer schema
 *    first with its own FAULT: the edge's own check is defence in depth and
 *    is NOT induced here (no downgrade path; precedent test_hf7_edge.c).
 *  - Case E depends on the injection hook being reached: the test asserts
 *    the FAULT reason names the build, and that the same block commits
 *    once the hook is disarmed.
 *  - Case G's statuses are arbitrary integers (the shadow package, WP5,
 *    defines the real values); the property is that NO value of the row
 *    changes a committed byte.
 *  - The storage step of the edge (§7.2 step 6, E-s1..E-s3) is a named
 *    inert seam until HF-9 WP4: nothing here covers it.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_trie.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#ifdef QGP_FAULT_INJECT
int nodus_witness_v2_trie_test_corrupt_full(int leg);
#endif

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)

/* the heights of the ladder */
#define H9    3u    /* param 9: generation 2 from block 3                   */
#define HE    5u    /* param 14: the EVM generation from block 5            */
#define HS    8u    /* param 18: generation 4 from block 8                  */
#define H5   11u    /* param 22: generation 5 from block 11                 */
#define HA   14u    /* param 24: generation 6 from block A = 14; edge = 13  */

/* ══ fixture ══════════════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    fx->w->v2_runtime_table = NULL;
    fx->w->v2_runtime_table_n = 0;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n  %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static sqlite3_int64 q1(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_int64 v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* rows written BETWEEN blocks with capture 0 (the triggers are silent):
 * two tokens, two names, two contiguous segments and one RELEASED registry
 * node (status 3: its bond is not in the running bond total, so the
 * conservation invariant is untouched). No UTXO: it would break it. */
static int add_extras(nodus_witness_t *w) {
    sqlite3 *db = w->db;
    if (run_sql(db,
            "INSERT INTO tokens (token_id, name, symbol, decimals, supply, "
            "creator_fp, flags, block_height, timestamp) VALUES "
            "(CAST(zeroblob(63)||x'a1' AS BLOB), 'tokone', 'T1', 8, 1000, "
            "'fp1', 1, 7, 99), "
            "(CAST(zeroblob(63)||x'a2' AS BLOB), 'toktwo', 'T2', 8, 2000, "
            "'fp2', 1, 7, 99)") != 0) return -1;
    if (run_sql(db,
            "INSERT INTO v2_names (name, owner, registered_height) VALUES "
            "(CAST('alice' AS BLOB), CAST(zeroblob(63)||x'b1' AS BLOB), 4), "
            "(CAST('bobby' AS BLOB), CAST(zeroblob(63)||x'b2' AS BLOB), 4)")
        != 0) return -1;
    if (run_sql(db,
            "INSERT INTO v2_storage_segments (k, root, published_height) "
            "VALUES (1, CAST(zeroblob(63)||x'c1' AS BLOB), 101), "
            "(2, CAST(zeroblob(63)||x'c2' AS BLOB), 102)") != 0) return -1;
    uint8_t pk[DNAC_PUBKEY_SIZE], fp[64];
    memset(pk, 0x5E, sizeof(pk));
    if (qgp_sha3_512(pk, sizeof(pk), fp) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, "
            "bond, status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES (?1, ?2, zeroblob(64), 1000, 3, 3, 0, 0, 0)",
            -1, &st, NULL) != SQLITE_OK) return -1;
    int ok = sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC) == SQLITE_OK &&
             sqlite3_bind_blob(st, 2, pk, sizeof(pk), SQLITE_STATIC)
                 == SQLITE_OK &&
             sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/* HF-2 on from 1; the ladder rows (0 = no row); `v24` the param-24 value;
 * `shadow` >= 0 writes a v2_trie_shadow_state row of that status BEFORE the
 * edge (a node-local row: it must change nothing committed); all before the
 * engine genesis, on an S20 database. */
static int fx_open(fixture_t *fx, const char *tag, uint64_t h9, uint64_t he,
                   uint64_t hs, uint64_t h5, uint64_t ha, uint64_t v24,
                   int shadow) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));      /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf9_edge_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x59, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    {
        uint32_t ver = 0;
        if (nodus_witness_db_migrate_v2s20(fx->w) != 0 ||
            nodus_witness_db_schema_version(fx->w, &ver) != 0 ||
            ver != NODUS_V2_SCHEMA_VERSION_S20)
            return -1;
    }
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0)
        return -1;
    if (h9 && cc_row(fx->w, DNAC_CFG_RULESET_GEN2,
                     (uint64_t)DNAC_CFG_RULESET_GEN2_D2, h9, 12) != 0)
        return -1;
    if (he && cc_row(fx->w, DNAC_CFG_EVM_ACTIVE,
                     (uint64_t)DNAC_CFG_EVM_ACTIVE_D, he, 14) != 0)
        return -1;
    if (hs && cc_row(fx->w, DNAC_CFG_RULESET_GEN_ROLES,
                     (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, hs, 13) != 0)
        return -1;
    if (h5 && cc_row(fx->w, DNAC_CFG_RULESET_GEN_ROOTS,
                     (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, h5, 15) != 0)
        return -1;
    if (ha && cc_row(fx->w, DNAC_CFG_RULESET_GEN_TRIE, v24, ha, 16) != 0)
        return -1;
    if (shadow >= 0) {
        char sql[96];
        snprintf(sql, sizeof(sql), "INSERT INTO v2_trie_shadow_state "
                 "(id, status) VALUES (1, %d)", shadow);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
}

static int run_idle(fixture_t *fx, uint64_t first, uint64_t last) {
    nodus_v2_block_t b;
    for (uint64_t h = first; h <= last; h++) {
        mk_block(&b, h);
        if (v2x_cmt_apply_ok(fx->w, &b) != 0) return -1;
    }
    return 0;
}

static int reg_man(nodus_witness_t *w, uint32_t dom,
                   dna_domain_manifest_t *m) {
    return nodus_witness_domreg_get(w, dom, NULL, m, NULL);
}

static int upd_at(nodus_witness_t *w, uint64_t gh, uint32_t dom,
                  dna_domain_update_t *u) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT upd FROM v2_domain_updates WHERE "
                           "global_height = ?1 AND domain_id = ?2", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)gh);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        dna_dupd_decode(sqlite3_column_blob(st, 0),
                        (size_t)sqlite3_column_bytes(st, 0), u) == 0)
        ok = 0;
    sqlite3_finalize(st);
    return ok;
}

/* the COMMITTED domain state root of `dom` (head bytes 4..67) */
static int head_root(nodus_witness_t *w, uint32_t dom, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head FROM v2_domain_heads WHERE "
                           "domain_id = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(out, (const uint8_t *)sqlite3_column_blob(st, 0) + 4, 64);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

static int block_global(nodus_witness_t *w, uint64_t h, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT global_root FROM v2_blocks WHERE "
                           "global_height = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 0) == 64;
    if (ok) memcpy(out, sqlite3_column_blob(st, 0), 64);
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/* every leg's stored v2_trie_roots row, leg 1..8 into roots[leg-1] */
static int stored_roots(nodus_witness_t *w, uint8_t roots[8][64]) {
    for (int leg = 1; leg <= 8; leg++)
        if (nodus_witness_v2_trie_leg_root(w, leg, roots[leg - 1]) != 0)
            return -1;
    return 0;
}

/* each stored leg root == the recomputation from the rows: the
 * incremental build, the full rebuild (both from nodus_witness_v2_trie_
 * build_leg) and the stored row all agree */
static int roots_match_rows(nodus_witness_t *w) {
    for (int leg = 1; leg <= 8; leg++) {
        uint8_t st[64], inc[64], full[64];
        if (nodus_witness_v2_trie_leg_root(w, leg, st) != 0) return -1;
        if (nodus_witness_v2_trie_build_leg(w, leg, inc, full) != 0)
            return -1;
        if (memcmp(st, inc, 64) != 0 || memcmp(st, full, 64) != 0)
            return -1;
    }
    return 0;
}

/* everything the generation-6 edge decided, from chains built the same
 * way, for the cross-chain comparisons of G and H */
typedef struct {
    uint8_t legs[8][64];
    uint8_t sys[64], core[64];
    uint8_t global_a1[64], global_a[64];
    int     capture;
} outcome_t;

static int ladder(fixture_t *fx, const char *tag, int shadow,
                  uint64_t v24, outcome_t *out) {
    if (fx_open(fx, tag, H9, HE, HS, H5, HA, v24, shadow) != 0) return -1;
    if (run_idle(fx, 1, HA - 2u) != 0) return -1;
    if (add_extras(fx->w) != 0) return -1;
    nodus_v2_block_t b;
    mk_block(&b, HA - 1u);
    if (v2x_cmt_apply_ok(fx->w, &b) != 0) return -1;
    if (stored_roots(fx->w, out->legs) != 0) return -1;
    if (head_root(fx->w, DNA_DOMAIN_SYSTEM, out->sys) != 0 ||
        head_root(fx->w, DNA_DOMAIN_CORE, out->core) != 0) return -1;
    if (block_global(fx->w, HA - 1u, out->global_a1) != 0) return -1;
    mk_block(&b, HA);
    if (v2x_cmt_apply_ok(fx->w, &b) != 0) return -1;
    if (block_global(fx->w, HA, out->global_a) != 0) return -1;
    out->capture = (int)q1(fx->w->db, "SELECT capture FROM v2_trie_state");
    return 0;
}

/* ══ A. the generation-6 edge at A-1 ═════════════════════════════════ */

static int t_edge(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    const nodus_domain_runtime_t *s5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *s6 =
        nodus_runtime_for_generation(NODUS_RT_GEN_TRIE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c6 =
        nodus_runtime_for_generation(NODUS_RT_GEN_TRIE, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *ev =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_EVM);
    CHECK(s5 && c5 && s6 && c6 && ev, "compiled generations 3-6");
    CHECK(E_LEN > HA + 2u, "no epoch boundary among heights 1..A+2");

    CHECK(fx_open(&fx, "edge", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded S20 chain (HF-2 on, params 9 / 14 / 18 / 22 / 24 at "
          "3 / 5 / 8 / 11 / 14)");

    /* ── A1. blocks 1..A-2: generation 5 from the end of block H5-1 ── */
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    CHECK(add_extras(fx.w) == 0, "tokens, names, segments, a registry node");
    {
        dna_domain_manifest_t ms, mc;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              reg_man(fx.w, DNA_DOMAIN_CORE, &mc) == 0, "registry");
        CHECK(ms.ruleset_version == 11 && mc.ruleset_version == 10,
              "before the edge: generation 5 (SYSTEM v11 / CORE v10)");
        CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0,
              "before the edge: capture 0");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0,
              "before the edge: no v2_trie_roots row");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
              "before the edge: no dirty key (the extras were written "
              "with capture 0)");
    }
    uint8_t sys_before[64], core_before[64];
    CHECK(head_root(fx.w, DNA_DOMAIN_SYSTEM, sys_before) == 0 &&
          head_root(fx.w, DNA_DOMAIN_CORE, core_before) == 0,
          "SYSTEM / CORE roots at A-2");

    /* ── A2. block A-1: THE GENERATION-6 EDGE ── */
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "the A-1 block commits");
    {
        /* (a) the registry switched 5 -> 6, the EVM record untouched */
        dna_domain_manifest_t ms, mc, me;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              reg_man(fx.w, DNA_DOMAIN_CORE, &mc) == 0 &&
              reg_man(fx.w, DNA_DOMAIN_EVM, &me) == 0, "registry after");
        CHECK(ms.ruleset_version == 12 && mc.ruleset_version == 11,
              "(a) SYSTEM v12 / CORE v11 at the end of A-1");
        CHECK(memcmp(ms.ruleset_hash, s6->ruleset_hash, 64) == 0 &&
              memcmp(mc.ruleset_hash, c6->ruleset_hash, 64) == 0,
              "(a) the compiled generation-6 hashes");
        CHECK(me.ruleset_version == ev->ruleset_version &&
              memcmp(me.ruleset_hash, ev->ruleset_hash, 64) == 0,
              "the EVM record is still the EVM generation's v2");
        const nodus_domain_runtime_t *rs = NULL, *rc = NULL;
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs == s6, "SYSTEM resolves generation 6");
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_CORE, 1, &rc)
                  == 0 && rc == c6, "CORE resolves generation 6");
    }
    {
        /* (b) SYSTEM and CORE touched at A-1 */
        dna_domain_update_t us, uc;
        CHECK(upd_at(fx.w, HA - 1u, DNA_DOMAIN_SYSTEM, &us) == 0 &&
              upd_at(fx.w, HA - 1u, DNA_DOMAIN_CORE, &uc) == 0,
              "(b) a DomainUpdate for SYSTEM and CORE at A-1");
        CHECK(us.ruleset_version == 12 && uc.ruleset_version == 11,
              "(b) the A-1 updates name generation 6");
        CHECK(memcmp(us.pre_root, sys_before, 64) == 0 &&
              memcmp(us.pre_root, us.post_root, 64) != 0,
              "(b) SYSTEM's root moved from the A-2 value");
        CHECK(memcmp(uc.pre_root, core_before, 64) == 0 &&
              memcmp(uc.pre_root, uc.post_root, 64) != 0,
              "(b) CORE's root moved from the A-2 value");
    }
    /* (c) capture on, dirty empty */
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "(c) capture is 1 after the edge");
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "(c) the dirty table is empty after the edge block");
    CHECK(nodus_witness_db_s20_trie_shape_ok(fx.w) == 1,
          "(c) all 24 triggers, the tables and the index are in place");
    /* (d) the eight tries from the rows */
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 8,
          "(d) one v2_trie_roots row per leg");
    CHECK(roots_match_rows(fx.w) == 0,
          "(d) every stored leg root == the build from the rows == the "
          "full rebuild");
    {
        uint8_t legs[8][64], empty[64];
        const uint8_t e80 = 0x80;
        CHECK(stored_roots(fx.w, legs) == 0 &&
              qgp_sha3_512(&e80, 1, empty) == 0, "(d) the leg roots");
        /* a leg root is the empty root SHA3-512(0x80) exactly when its
         * table (the leg's selection) has no row — whatever the genesis
         * fixture wrote (it writes no UTXO) */
        static const char *const counts[8] = {
            "SELECT COUNT(*) FROM utxo_set",
            "SELECT COUNT(*) FROM tokens",
            "SELECT COUNT(*) FROM v2_claims_spent WHERE target_domain_id = 1",
            "SELECT COUNT(*) FROM v2_names",
            "SELECT COUNT(*) FROM v2_storage_nodes",
            "SELECT COUNT(*) FROM v2_storage_segments",
            "SELECT COUNT(*) FROM validator_set_snapshots",
            "SELECT COUNT(*) FROM v2_attendance_epoch" };
        for (int i = 0; i < 8; i++) {
            sqlite3_int64 n = q1(fx.w->db, counts[i]);
            CHECK(n >= 0, "(d) the leg's row count");
            CHECK((n > 0) == (memcmp(legs[i], empty, 64) != 0),
                  "(d) a leg root is the empty root exactly when its "
                  "table has no row (the empty root is SHA3-512(0x80), "
                  "not a tagged DNA_V2_EMPTY_*)");
        }
        CHECK(memcmp(legs[1], empty, 64) != 0 &&
              memcmp(legs[3], empty, 64) != 0 &&
              memcmp(legs[4], empty, 64) != 0 &&
              memcmp(legs[5], empty, 64) != 0,
              "(d) legs 2, 4, 5, 6 hold this test's extra rows: not empty");
        for (int i = 0; i < 8; i++)
            for (int j = i + 1; j < 8; j++)
                if (memcmp(legs[i], empty, 64) != 0 &&
                    memcmp(legs[j], empty, 64) != 0)
                    CHECK(memcmp(legs[i], legs[j], 64) != 0,
                          "(d) distinct non-empty legs, distinct roots");
    }
    {
        /* (e) the compositions */
        uint8_t csys[64], ccore[64], v7[64], v6[64], k4[64], k_evm[64];
        CHECK(head_root(fx.w, DNA_DOMAIN_SYSTEM, csys) == 0 &&
              head_root(fx.w, DNA_DOMAIN_CORE, ccore) == 0, "heads");
        CHECK(nodus_witness_system_root_v7(fx.w, v7) == 0 &&
              nodus_witness_system_root_v6(fx.w, v6) == 0 &&
              nodus_witness_core_root_v4(fx.w, k4) == 0 &&
              nodus_witness_core_root_v2_evm(fx.w, k_evm) == 0,
              "the four compositions");
        CHECK(memcmp(csys, v7, 64) == 0,
              "(e) at A-1 the committed SYSTEM root is NDS.SYS.v7");
        CHECK(memcmp(csys, v6, 64) != 0, "(e) and no longer v6");
        CHECK(memcmp(ccore, k4, 64) == 0,
              "(e) at A-1 the committed CORE root is NDS.CORE.v4");
        CHECK(memcmp(ccore, k_evm, 64) != 0,
              "(e) and no longer the generation-3..5 composition");
        uint8_t g_commit[64], g_fresh[64], doms[64];
        CHECK(block_global(fx.w, HA - 1u, g_commit) == 0,
              "the committed A-1 global root");
        CHECK(nodus_witness_global_root_v2(fx.w, g_fresh, doms, NULL, NULL)
                  == 0, "recomputed global root");
        CHECK(memcmp(g_commit, g_fresh, 64) == 0,
              "(e) the committed A-1 global root == recomputation from the "
              "committed heads");
    }

    /* ── A3. block A: an idle block carries the A-1 roots ── */
    uint8_t sys_a1[64], core_a1[64], legs_a1[8][64];
    CHECK(head_root(fx.w, DNA_DOMAIN_SYSTEM, sys_a1) == 0 &&
          head_root(fx.w, DNA_DOMAIN_CORE, core_a1) == 0 &&
          stored_roots(fx.w, legs_a1) == 0, "roots at A-1");
    mk_block(&b, HA);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "block A commits under gen 6");
    {
        uint8_t sa[64], ca[64], la[8][64];
        CHECK(head_root(fx.w, DNA_DOMAIN_SYSTEM, sa) == 0 &&
              head_root(fx.w, DNA_DOMAIN_CORE, ca) == 0 &&
              stored_roots(fx.w, la) == 0, "roots at A");
        CHECK(memcmp(sa, sys_a1, 64) == 0 && memcmp(ca, core_a1, 64) == 0 &&
              memcmp(la, legs_a1, sizeof(la)) == 0,
              "an idle block at A moves no root and no leg");
        dna_domain_manifest_t ms;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              ms.ruleset_version == 12, "no second switch at A");
        CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
              "capture stays 1");
    }

    /* ── A4. (f) the triggers are live after the edge, the flush is wired,
     *        the untouched-domain guard is unchanged ── */
    {
        uint8_t d0[64], legs_f[8][64];
        CHECK(run_sql(fx.w->db,
                  "INSERT INTO tokens (token_id, name, symbol, decimals, "
                  "supply, creator_fp, flags, block_height, timestamp) "
                  "VALUES (CAST(zeroblob(63)||x'a3' AS BLOB), 'tokthree', "
                  "'T3', 8, 3000, 'fp3', 1, 9, 99)") == 0,
              "(f) a token row written between blocks");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 1 &&
              q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty WHERE "
                           "leg = 2") == 1,
              "(f) exactly one dirty key, of leg 2, was captured");
        mk_block(&b, HA + 1u);
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest before");
        CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_VERDICT,
                                "UNTOUCHED-DOMAIN GUARD") == 0,
              "(f) the flush put the token into the CORE root and CORE was "
              "not declared touched: the phase-8 guard refuses the block "
              "(the flush ran at 8-pre, the guard is unchanged), the "
              "database byte-identical");
        CHECK(run_sql(fx.w->db, "DELETE FROM tokens WHERE token_id = "
                                "CAST(zeroblob(63)||x'a3' AS BLOB)") == 0,
              "(f) the row is deleted again");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 1,
              "(f) the same key, one dirty row (duplicates collapsed)");
        mk_block(&b, HA + 1u);
        CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0,
              "(f) the key was written and restored: the flush deletes it "
              "again, the root is unchanged, the block commits");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
              "(f) the dirty table is empty after the block");
        CHECK(stored_roots(fx.w, legs_f) == 0 &&
              memcmp(legs_f, legs_a1, sizeof(legs_f)) == 0,
              "(f) every leg root is the A-1 value again");
        CHECK(roots_match_rows(fx.w) == 0,
              "(f) and equals the rebuild from the rows");
    }
    fx_close(&fx);
    return 0;
}

/* ══ B. the edge on a registry that is not generation 5 → FAULT ══════ */

static int t_edge_not_gen5_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    /* params 9 at 3, 14 at 5, NO 18, NO 22, param 24 at 7: the registry is
     * at the EVM generation (3) when block 6 is the edge */
    CHECK(fx_open(&fx, "notg5", H9, HE, 0, 0, 7,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded chain (param 24 at 7, registry at the EVM generation)");
    CHECK(run_idle(&fx, 1, 5) == 0, "idle blocks 1..5");
    mk_block(&b, 6);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "registry is not generation 5") == 0,
          "the generation-6 edge on a generation-3 registry is a node "
          "FAULT, DB byte-unchanged");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0,
          "capture stays 0");
    fx_close(&fx);
    return 0;
}

/* ══ C. a param-24 row that is not this build's D6 → FAULT ═══════════ */

static int t_edge_wrong_value_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "wrongd", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D + 1u, -1) == 0,
          "seeded chain (param 24 at 14 with D6 + 1)");
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "generation-6 vote D6") == 0,
          "a param-24 row holding another value is a node FAULT at A-1");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0,
          "capture stays 0");
    fx_close(&fx);
    return 0;
}

/* ══ D. the trigger's shape: absent at both heights is not the edge ═══ */

static int t_edge_not_the_edge(void) {
    fixture_t fx;
    /* a param-24 row whose effective block is far in the future: at every
     * probed block it is absent at h AND at h+1, so there is no edge —
     * the chain keeps applying under generation 5 with capture 0 and no
     * trie is built. (Present at h AND h+1 — blocks A, A+1 — is asserted
     * in A; absent at h and present at h+1 is the edge, A.) */
    CHECK(fx_open(&fx, "future", H9, HE, HS, H5, 1000000u,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded chain (param 24 effective at block 1 000 000)");
    CHECK(run_idle(&fx, 1, HA + 2u) == 0,
          "idle blocks 1..A+2 commit with no edge");
    {
        dna_domain_manifest_t ms, mc;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              reg_man(fx.w, DNA_DOMAIN_CORE, &mc) == 0 &&
              ms.ruleset_version == 11 && mc.ruleset_version == 10,
              "the registry stays generation 5");
        CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0,
              "capture stays 0");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0,
              "no trie was built");
    }
    fx_close(&fx);
    return 0;
}

#ifdef QGP_FAULT_INJECT
/* ══ E. an incremental / full mismatch is a FAULT, atomically ════════ */

static int t_edge_mismatch_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "mismatch", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded chain");
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    CHECK(add_extras(fx.w) == 0, "extras");
    CHECK(nodus_witness_v2_trie_test_corrupt_full(3) == 0,
          "the hook arms a mismatch on leg 3");
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "one-time build of the eight tries") == 0,
          "an incremental root that differs from the full rebuild is a "
          "node FAULT at A-1, the database byte-identical (the node stops "
          "and does not vote, D12)");
    {
        dna_domain_manifest_t ms;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              ms.ruleset_version == 11,
              "a rolled-back A-1 leaves the registry at generation 5");
        CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0,
              "a rolled-back A-1 leaves capture 0");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0,
              "and writes no root row");
    }
    CHECK(nodus_witness_v2_trie_test_corrupt_full(0) == 0, "disarmed");
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0,
          "the same block commits once the hook is disarmed: the edge ran "
          "exactly once");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1 &&
          q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 8,
          "capture 1 and eight leg roots after the edge");
    CHECK(roots_match_rows(fx.w) == 0, "and they equal the rows");
    fx_close(&fx);
    return 0;
}
#endif

/* ══ F. a missing trigger at the edge → FAULT ════════════════════════ */

static int t_edge_missing_trigger_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "notrig", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded chain");
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    CHECK(run_sql(fx.w->db, "DROP TRIGGER v2_trie_l3_ins") == 0,
          "one of the 24 triggers is dropped");
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "24 dirty-capture triggers") == 0,
          "a missing trigger at the edge is a node FAULT, DB byte-"
          "identical");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0,
          "capture stays 0 (the rolled-back edge never switched it on)");
    fx_close(&fx);
    return 0;
}

/* ══ G. the shadow status never selects commitment; H. replay ════════ */

static int t_shadow_and_replay(void) {
    fixture_t fx;
    outcome_t base, o;
    CHECK(ladder(&fx, "base", -1, (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D,
                 &base) == 0, "the control chain (no shadow row)");
    CHECK(base.capture == 1, "control: capture 1");
    fx_close(&fx);
    /* H: a second chain through the same blocks reaches the same roots */
    CHECK(ladder(&fx, "replay", -1, (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D,
                 &o) == 0, "the replay chain");
    CHECK(memcmp(o.legs, base.legs, sizeof(o.legs)) == 0 &&
          memcmp(o.sys, base.sys, 64) == 0 &&
          memcmp(o.core, base.core, 64) == 0 &&
          memcmp(o.global_a1, base.global_a1, 64) == 0 &&
          memcmp(o.global_a, base.global_a, 64) == 0 && o.capture == 1,
          "H: a replay from genesis reaches the same leg roots, SYSTEM / "
          "CORE roots and global roots at A-1 and A");
    fx_close(&fx);
    /* G: whatever the shadow row says, nothing committed moves */
    for (int status = 0; status <= 3; status++) {
        char tag[24];
        snprintf(tag, sizeof(tag), "shadow%d", status);
        CHECK(ladder(&fx, tag, status,
                     (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, &o) == 0,
              "a chain with a shadow row");
        CHECK(memcmp(o.legs, base.legs, sizeof(o.legs)) == 0 &&
              memcmp(o.sys, base.sys, 64) == 0 &&
              memcmp(o.core, base.core, 64) == 0 &&
              memcmp(o.global_a1, base.global_a1, 64) == 0 &&
              memcmp(o.global_a, base.global_a, 64) == 0 &&
              o.capture == 1,
              "G: the edge's result is identical whatever the shadow "
              "status (stopped / running / faulted / other)");
        CHECK(q1(fx.w->db, "SELECT status FROM v2_trie_shadow_state") ==
              status, "the shadow row itself was never written by the edge");
        fx_close(&fx);
    }
    return 0;
}

int main(void) {
    int rc = 0;
    if (!rc) rc = t_edge();
    if (!rc) rc = t_edge_not_gen5_faults();
    if (!rc) rc = t_edge_wrong_value_faults();
    if (!rc) rc = t_edge_not_the_edge();
#ifdef QGP_FAULT_INJECT
    if (!rc) rc = t_edge_mismatch_faults();
#endif
    if (!rc) rc = t_edge_missing_trigger_faults();
    if (!rc) rc = t_shadow_and_replay();
    if (rc) {
        fprintf(stderr, "test_hf9_edge: FAILED\n");
        return 1;
    }
    printf("test_hf9_edge: all cases passed, %d checks%s\n", g_checks,
#ifdef QGP_FAULT_INJECT
           " (incl. the QGP_FAULT_INJECT mismatch case)"
#else
           " (the QGP_FAULT_INJECT mismatch case E not compiled)"
#endif
           );
    return 0;
}
