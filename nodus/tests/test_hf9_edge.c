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
 *     heights 3 / 5 / 8 / 11 / A with A = 14 (edge block 13) at production
 *     constants and A = 13 (edge block 12) at the short-epoch setting, see
 *     HA below):
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
 *          root); legs 2 (tokens) and 4 (names) hold this test's extra
 *          rows and are not the empty root (so the build visited rows),
 *          legs 5 (registry) and 6 (segments) are the empty root (no node
 *          / segment can exist at the edge height, see add_extras); for every leg the
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
 *     h+1 is the edge (A). The READ FAILURE of the param-24 row is case K.
 *  E. ATOMICITY AND THE MISMATCH FAULT (compiled only with
 *     -DQGP_FAULT_INJECT=ON): an injected incremental-vs-full mismatch on
 *     one leg makes block A-1 a node FAULT ("one-time build of the eight
 *     tries"), the database byte-identical, capture still 0, the registry
 *     still generation 5 and v2_trie_roots empty (the mismatch is raised
 *     before the edge sets capture, so this case does NOT exercise the
 *     rollback of capture 1 - that is case I); with the hook disarmed the
 *     same block commits and the edge runs exactly once.
 *  F. A MISSING TRIGGER at the edge (one of the 24 dropped before A-1) is a
 *     node FAULT ("24 dirty-capture triggers"), the database byte-identical,
 *     capture 0.
 *  G. SHADOW STATUS NEVER SELECTS COMMITMENT: one fresh chain per REAL
 *     shadow status (HF-9 WP5, nodus_witness_v2_shadow.h: stopped 0,
 *     running 1, faulted 2), each with a v2_trie_shadow_state row of that
 *     status written before the edge, produce the same committed roots as
 *     the chain with no such row ("off") — SYSTEM / CORE head roots, every
 *     v2_trie_roots row and the global root at A-1 — and capture is 1 in
 *     all of them.
 *  H. REPLAY FROM GENESIS: a second chain built from scratch through the
 *     same blocks reaches the same leg roots, the same SYSTEM / CORE roots
 *     and the same global roots at A-1 and A as the first (determinism of
 *     the edge as a pure function of committed rows and the param row).
 *  I. A FAULT AFTER THE EDGE RAN ROLLS CAPTURE 1 BACK (Sol verifier row 3):
 *     block A-1 carries the engine's own injection point
 *     V2AP_FAIL_AFTER_DOMAIN_ROOTS (a test field of the block, no compile
 *     flag), which fires after the edge, the phase 8-pre flush and phase 8:
 *     the block is a FAULT naming the injection, the whole database is
 *     byte-identical, capture is 0 again, the registry is SYSTEM v11 /
 *     CORE v10, v2_trie_roots has no row, v2_trie_nodes has its previous
 *     row count, v2_trie_dirty is empty, the SYSTEM / CORE heads are the
 *     A-2 ones and there is no block row for A-1; the same block without
 *     the injection then runs the edge (capture 1, eight roots), which is
 *     the control that the injection fired after a real edge.
 *  J. AN ACCEPTED OLDER SCHEMA (Sol verifier rows 1 and 4): the block-entry
 *     gate accepts S16-S20. (J1) Block A-1 on a database reporting S19
 *     (PRAGMA user_version = 19) passes the generation-5 block start and
 *     is refused by the EDGE's own exact-S20 check (a FAULT "needs schema
 *     S20 exactly", database byte-identical, capture 0, no root); at S20
 *     the same block commits. (J2) A block under generation 6 on a
 *     database reporting S19 is a node FAULT at the block start ("generation
 *     6 needs schema 20", before any item, database byte-identical); at S20
 *     the same block commits.
 *  K. A PARAM-24 READ FAILURE AT THE EDGE (Sol verifier row 5): the
 *     chain_config_history table is replaced by a VIEW over its own rows
 *     in which only the param-24 row raises an integer overflow when its
 *     value is read (test_chain_config_failclose.c cc_view's pattern). The
 *     reader answers -1 (control), and block A-1 is the edge's own node
 *     FAULT ("RULESET_GEN_TRIE at heights ... unreadable"), the database
 *     byte-identical, capture 0 - never "not the edge"; with the row
 *     readable again the same block is the edge.
 *  L. THE PARAM-24 VOTE'S SINGLE USE ON THE BLOCK PATH (Sol verifier row 2;
 *     test_hf7_edge.c case D's shape for param 22): params 9 / 14 / 18 /
 *     22 at 3 / 5 / 8 / 11, NO param-24 row; at block 13 (generation 5)
 *     two really signed param-24 (D6) CHAIN_CONFIG envelopes in ONE block
 *     - the first applies, the second is refused NODUS_V2_TX_ERR_EXEC
 *     while the first row is still pending (effective block ~17 000
 *     blocks away), the engine handed the exec ctx.ruleset_gen_trie_voted
 *     0 then 1, exactly one param-24 row; at block 14 a third vote is
 *     refused the same way (fact 1 from the committed row), still one
 *     row, the registry still generation 5. The fact is derived by the
 *     engine (env_ruleset_gen_trie_voted) and transferred by the SYSTEM
 *     exec (nodus_witness_rt_native.c, facts.ruleset_gen_trie_voted), so
 *     removing either makes the second vote apply.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generations 3-6 and the tries exist
 * only there; the target is registered only in that configuration).
 * Section E is compiled only under -DQGP_FAULT_INJECT=ON (the hook
 * nodus_witness_v2_trie_test_corrupt_full) and is ABSENT otherwise: a build
 * without the flag has missing coverage for E, not a pass. No environment.
 * The heights assume no epoch boundary among 1..A+1: A = 14 when
 * DNAC_EPOCH_LENGTH is above 16 (production 720), A = 13 at E = 15 (the first
 * boundary 15 is then A + 2; the one case that applies A + 2 blocks, D, runs
 * them under generation 5 on a chain whose param-24 row is far in the future).
 * The test CHECKs the guard E > A + 1, so a build with a smaller E fails the
 * guard rather than running the wrong scenario (precedent test_hf7_edge.c).
 * Compile flags for the two settings: none besides the build's constants
 * (-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
 * -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
 * -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15 for the short-epoch run).
 * HOW IT CAN FALSELY PASS at E = 15: the ladder is one block tighter (A = 13,
 * gen-5 edge at the end of block 10, gen-6 edge at the end of block 12), so
 * the claim that the tightened ladder behaves like the production one rests
 * on the edges deciding only on their own parameter's rows (above), not on a
 * second spacing run.
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
 *  - The extra rows this test writes (tokens, names) are written between blocks with capture 0 and
 *    are the only rows beyond the genesis fixture's; no UTXO is added (the
 *    conservation invariant would refuse the block), so a UTXO-writer
 *    path through the edge is covered only by the genesis rows.
 *  - J lowers PRAGMA user_version on a database whose tables are the S20
 *    ones: the engine reads only the version number, so the case proves
 *    the version-driven checks (the edge's exact-S20 check and the block
 *    start's generation-6 schema check), not the behaviour on a database
 *    that really lacks the S20 tables. A newer schema than S20 is not
 *    induced (the block-entry gate refuses it first).
 *  - K's poison is an integer overflow raised by SQLite when the param-24
 *    value is read; it proves the edge's handling of the reader's -1, not
 *    every way a read can fail. Its premise (the reader answers -1) is
 *    asserted in the case itself.
 *  - I depends on the injection point being reached after the edge: the
 *    FAULT must name the injection point and the control block must show
 *    the edge ran (capture 1). It does not observe capture inside the
 *    block; it proves the state after the rollback.
 *  - Case E depends on the injection hook being reached: the test asserts
 *    the FAULT reason names the build, and that the same block commits
 *    once the hook is disarmed.
 *  - Case G writes the three status values the shadow package defines
 *    (NODUS_V2_SHADOW_STOPPED / _RUNNING / _FAULTED) as a bare row, with
 *    no shadow table behind it and no shadow job running (the job itself
 *    is test_hf9_shadow.c); the property is that none of the real values
 *    changes a committed byte, so a status outside them is not covered.
 *    "Off" is the control chain with no row at all.
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
#include "witness/nodus_witness_v2_shadow.h"    /* the real shadow statuses */
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

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
/* param 24: generation 6 from block A; the edge is the end of block A - 1.
 * A = 14 (edge 13) at every epoch length above A + 1 (production 720); at the
 * short-epoch setting (E = 15) A is 13 (edge 12): the blocks this file applies
 * go up to A + 1 and an epoch boundary among them would change legs 7 / 8 and
 * the storage relations (a boundary writes the validator snapshot and the
 * attendance epoch), which the "A + 1 is an idle block" claims of case A
 * (f) forbid. A = 13 keeps the first boundary 15 = A + 2. H5 = 11 is
 * unchanged (A - 2 = 11: generation 5 is already in force when the idle
 * prefix ends). The ladder rows are planted directly in chain_config_history
 * (cc_row), so only the order of the edges matters to the engine
 * (phase_6b_gen4_edge / gen5 / gen6 each decide on "present at h + 1, absent
 * at h" of their own parameter - plan :236 "param 24 present at A = h+1 and
 * absent at h"; nodus_witness_v2_apply.c:5557 requires `at_next == 0 &&
 * at_h == 1`, where 0 is present and 1 absent, nodus_witness_chain_config.c
 * :504, :508 - nodus_witness_v2_apply.c:5143-5200, :5340-5400, :5531). */
#define HA   (E_LEN > 16u ? 14u : 13u)

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
 * two tokens and two names. No UTXO: it would break the conservation
 * invariant. NO REGISTRY ROW (HF-9 WP4, Sol round 3 row 7): a RELEASED
 * node exists only after a STORAGE_EXIT and the boundary that releases it,
 * and a registered one needs a funded bond; the fixture has neither, so
 * leg 5 is the empty root here (leg 5's roots: test_hf9_kat and the
 * trie_legs groups A-J). NO SEGMENT (HF-9 WP4): a segment
 * is published only at a storage boundary together with the freeze of that
 * boundary's set, so a chain with segments has a frozen set at the last
 * boundary before the edge (H2 >= E); at this test's edge height (13 <
 * DNAC_EPOCH_LENGTH) H2 is 0, no set and no segment can exist, and the
 * edge's storage transition faults on segments without a set. Leg 6 is
 * therefore the empty root here; its non-empty roots are test_hf9_kat's
 * and test_hf9_trie_legs groups A-J. */
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
    return 0;
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
    CHECK(E_LEN > HA + 1u, "no epoch boundary among heights 1..A+1");

    CHECK(fx_open(&fx, "edge", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded S20 chain (HF-2 on, params 9 / 14 / 18 / 22 / 24 at "
          "3 / 5 / 8 / 11 / A, A = 14 at production, 13 at E = 15)");

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
              memcmp(legs[4], empty, 64) == 0 &&
              memcmp(legs[5], empty, 64) == 0,
              "(d) legs 2, 4 hold this test's extra rows: not empty; "
              "legs 5, 6 have no node / segment: the empty root");
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
          "seeded chain (param 24 at A with D6 + 1)");
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
    static const int shadow_statuses[] = {
        NODUS_V2_SHADOW_STOPPED, NODUS_V2_SHADOW_RUNNING,
        NODUS_V2_SHADOW_FAULTED
    };
    for (size_t si = 0; si < sizeof(shadow_statuses) /
                             sizeof(shadow_statuses[0]); si++) {
        const int status = shadow_statuses[si];
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
              "status (stopped / running / faulted)");
        CHECK(q1(fx.w->db, "SELECT status FROM v2_trie_shadow_state") ==
              status, "the shadow row itself was never written by the edge");
        fx_close(&fx);
    }
    return 0;
}

/* ══ I. a fault AFTER the edge ran rolls capture 1 back (T-6) ═══════ */

static int t_edge_rollback_after_capture(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "rollback", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded chain");
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    CHECK(add_extras(fx.w) == 0, "extras");
    uint8_t sys0[64], core0[64];
    CHECK(head_root(fx.w, DNA_DOMAIN_SYSTEM, sys0) == 0 &&
          head_root(fx.w, DNA_DOMAIN_CORE, core0) == 0, "roots at A-2");
    const sqlite3_int64 nodes0 =
        q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_nodes");
    CHECK(nodes0 >= 0, "the node table is readable");

    /* the engine's own injection point V2AP_FAIL_AFTER_DOMAIN_ROOTS fires
     * after the edge (6b'''''), after the phase 8-pre flush and after
     * phase 8: by then the edge has switched the registry, written the
     * eight roots and the nodes and set capture = 1 inside this block's
     * transaction. The host rolls the whole block back */
    mk_block(&b, HA - 1u);
    b.fail_at = V2AP_FAIL_AFTER_DOMAIN_ROOTS;
    CHECK(v2x_cmt_injected(fx.w, &b) == 0,
          "A-1 failing after the edge is a FAULT naming the injection "
          "point, the whole database byte-identical");
    {
        dna_domain_manifest_t ms, mc;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              reg_man(fx.w, DNA_DOMAIN_CORE, &mc) == 0 &&
              ms.ruleset_version == 11 && mc.ruleset_version == 10,
              "the rollback restored the generation-5 registry");
        CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0,
              "the rollback restored capture 0");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0 &&
              q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_nodes") == nodes0 &&
              q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
              "the previous trie state: no leg root, the node table as it "
              "was, no dirty key");
        uint8_t sys1[64], core1[64];
        CHECK(head_root(fx.w, DNA_DOMAIN_SYSTEM, sys1) == 0 &&
              head_root(fx.w, DNA_DOMAIN_CORE, core1) == 0 &&
              memcmp(sys0, sys1, 64) == 0 && memcmp(core0, core1, 64) == 0,
              "SYSTEM / CORE heads as at A-2");
        {
            char sql[96];
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM v2_blocks WHERE "
                     "global_height = %u", (unsigned)(HA - 1u));
            CHECK(q1(fx.w->db, sql) == 0, "no block row for A-1");
        }
    }
    /* control: the same block without the injection runs the edge and
     * leaves capture 1 - the injection above fired AFTER a real edge */
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "A-1 commits without the fault");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1 &&
          q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 8,
          "control: the edge sets capture 1 and writes eight leg roots");
    fx_close(&fx);
    return 0;
}

/* ══ J. the edge on an accepted OLDER schema, and generation 6 on one ═ */

static int set_user_version(nodus_witness_t *w, unsigned v) {
    char sql[48];
    snprintf(sql, sizeof(sql), "PRAGMA user_version = %u", v);
    return run_sql(w->db, sql);
}

static int t_edge_older_schema_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "oldschema", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded chain");
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    CHECK(add_extras(fx.w) == 0, "extras");
    /* S19 is inside the block-entry gate (S16-S20): the generation-5 block
     * start accepts it, so the refusal below is the EDGE's own exact-S20
     * check (plan §7.2 step 2) */
    CHECK(set_user_version(fx.w, NODUS_V2_SCHEMA_VERSION_S19) == 0,
          "the database reports schema S19");
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "needs schema S20 exactly") == 0,
          "A-1 on schema S19 is the edge's schema FAULT, the database "
          "byte-identical");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0 &&
          q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0,
          "capture 0, no leg root");
    /* control: at S20 the same block commits - only the schema refused it */
    CHECK(set_user_version(fx.w, NODUS_V2_SCHEMA_VERSION_S20) == 0,
          "schema S20 again");
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "A-1 commits at S20");
    fx_close(&fx);
    return 0;
}

static int t_gen6_older_schema_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "gen6old", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded chain");
    CHECK(run_idle(&fx, 1, HA) == 0, "blocks 1..A: the edge ran, A is "
          "judged under generation 6");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "capture 1");
    /* a generation-6 registry on a database reporting an accepted older
     * schema (plan §5.2: generation >= 6 requires the capture flag and
     * the 24 triggers, which exist from S20) */
    CHECK(set_user_version(fx.w, NODUS_V2_SCHEMA_VERSION_S19) == 0,
          "the database reports schema S19");
    mk_block(&b, HA + 1u);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "generation 6 needs schema 20") == 0,
          "a generation-6 block on schema S19 is a node FAULT before any "
          "item, the database byte-identical");
    CHECK(set_user_version(fx.w, NODUS_V2_SCHEMA_VERSION_S20) == 0,
          "schema S20 again");
    mk_block(&b, HA + 1u);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0,
          "control: the same block commits at S20");
    fx_close(&fx);
    return 0;
}

/* ══ K. a param-24 READ FAILURE at the edge is a FAULT (T-6) ═════════ */

/* chain_config_history becomes a VIEW over its own rows (test_chain_config_
 * failclose.c cc_view's pattern): reading the param-24 row's value raises
 * an integer overflow inside SQLite, every other row reads normally. */
static int poison_param24(nodus_witness_t *w) {
    if (run_sql(w->db, "ALTER TABLE chain_config_history RENAME TO "
                       "cch_raw") != 0 ||
        run_sql(w->db, "ALTER TABLE cch_raw ADD COLUMN bad INTEGER NOT "
                       "NULL DEFAULT 0") != 0 ||
        run_sql(w->db, "UPDATE cch_raw SET bad = 1 WHERE param_id = 24")
            != 0 ||
        run_sql(w->db,
                "CREATE VIEW chain_config_history AS SELECT param_id, "
                "CASE WHEN bad = 1 THEN abs(-9223372036854775808) ELSE "
                "new_value END AS new_value, effective_block, commit_block, "
                "tx_hash, proposal_nonce, created_at_unix FROM cch_raw")
            != 0)
        return -1;
    w->chain_config_cache_warm = false;
    for (int i = 0; i <= DNAC_CFG_PARAM_MAX_ID; i++)
        w->chain_config_cache_count[i] = 0;
    return 0;
}

static int unpoison_param24(nodus_witness_t *w) {
    if (run_sql(w->db, "DROP VIEW chain_config_history") != 0 ||
        run_sql(w->db, "ALTER TABLE cch_raw DROP COLUMN bad") != 0 ||
        run_sql(w->db, "ALTER TABLE cch_raw RENAME TO "
                       "chain_config_history") != 0)
        return -1;
    w->chain_config_cache_warm = false;
    for (int i = 0; i <= DNAC_CFG_PARAM_MAX_ID; i++)
        w->chain_config_cache_count[i] = 0;
    return 0;
}

static int t_edge_param24_read_fault(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "readfail", H9, HE, HS, H5, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1) == 0,
          "seeded chain");
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    CHECK(add_extras(fx.w) == 0, "extras");
    CHECK(poison_param24(fx.w) == 0,
          "the param-24 row now raises when its value is read");
    {
        uint64_t v = 0;
        CHECK(nodus_chain_config_get_u64(fx.w, (uint8_t)DNAC_CFG_RULESET_GEN_TRIE,
                                         HA, 0ULL, &v) < 0,
              "control: the reader itself answers a fault (-1) for the "
              "poisoned row");
    }
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "RULESET_GEN_TRIE at heights") == 0,
          "an unreadable param-24 row at the edge is the edge's own node "
          "FAULT (not 'not the edge'), the database byte-identical");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0 &&
          q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0,
          "capture 0, no leg root");
    /* control: with the row readable the same block is the edge */
    CHECK(unpoison_param24(fx.w) == 0, "the row reads normally again");
    mk_block(&b, HA - 1u);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "A-1 commits once readable");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "the edge ran");
    fx_close(&fx);
    return 0;
}

/* ══ L. the param-24 vote's single use on the BLOCK path (T-12) ══════ */

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static void mk_block_envs(nodus_v2_block_t *b, uint64_t h,
                          const nodus_v2_envelope_t *envs, size_t n) {
    mk_block(b, h);
    b->envs = envs;
    b->n_envs = n;
}

/* the param-24 single-use fact the engine handed each probed exec, in call
 * order (test_hf7_edge.c's probe, for ruleset_gen_trie_voted) */
#define PROBE_MAX 8
static uint8_t g_seen[PROBE_MAX];
static int     g_n_seen;

/* The compiled generation-5 SYSTEM exec, wrapped: it records the fact the
 * ENGINE put into the context, lifts the committee quorum (the probe's
 * only change: the vote's rules are the system under test, not the
 * committee) and runs nodus_rt_system_exec itself, which copies the fact
 * into the stateful rules (nodus_witness_rt_native.c, facts.ruleset_gen_
 * trie_voted). */
static int probe_exec(const nodus_domain_runtime_t *rt,
                      const dna_env_view_t *env, uint16_t leg_index,
                      const nodus_rt_exec_ctx_t *ctx,
                      const nodus_rt_read_res_t *reads, uint16_t n_reads,
                      uint8_t *res_out, size_t res_cap, size_t *res_len_out) {
    if (!ctx || !ctx->auth) return -2;
    if (g_n_seen < PROBE_MAX)
        g_seen[g_n_seen++] = ctx->ruleset_gen_trie_voted;
    nodus_rt_auth_verdict_t av = *ctx->auth;
    av.n_approvals = 7;
    av.committee_n = 7;
    av.approved_power = 7;
    av.committee_power = 7;
    nodus_rt_exec_ctx_t c2 = *ctx;
    c2.auth = &av;
    return nodus_rt_system_exec(rt, env, leg_index, &c2, reads, n_reads,
                                res_out, res_cap, res_len_out);
}

static nodus_domain_runtime_t *g_probe = NULL;

/* the compiled table, copied, with ONLY the generation-`gen` SYSTEM exec
 * replaced; every tuple unchanged, so the committed registry resolves
 * onto the same entries */
static int probe_install(nodus_witness_t *w, uint32_t gen) {
    size_t n = 0;
    const nodus_domain_runtime_t *all = nodus_runtime_all_table(&n);
    if (!all || n == 0) return -1;
    free(g_probe);
    g_probe = malloc(n * sizeof(*g_probe));
    if (!g_probe) return -1;
    memcpy(g_probe, all, n * sizeof(*g_probe));
    int hit = 0;
    for (size_t i = 0; i < n; i++)
        if (g_probe[i].generation == gen &&
            g_probe[i].domain_id == DNA_DOMAIN_SYSTEM) {
            g_probe[i].exec = probe_exec;
            hit++;
        }
    if (hit != 1) return -1;
    w->v2_runtime_table = g_probe;
    w->v2_runtime_table_n = n;
    g_n_seen = 0;
    return 0;
}

#define CC_CALL_LEN 41u
#define K1_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)

typedef struct {
    uint8_t  call[CC_CALL_LEN];
    uint8_t  auth[K1_AUTH_LEN];
    uint8_t *bytes;
    size_t   len;
} cc_env_t;

static uint8_t g_pk[QGP_DSA87_PUBLICKEYBYTES], g_sk[QGP_DSA87_SECRETKEYBYTES];

/* One SYSTEM CHAIN_CONFIG envelope (test_hf7_edge.c cc_env_build), REALLY
 * signed by g_sk over the engine-derived leg digest at candidate `height`.
 * @return 0 / -1. */
static int cc_env_build(nodus_witness_t *w, uint64_t height, uint8_t param,
                        uint64_t value, uint64_t effective, uint64_t nonce,
                        cc_env_t *e) {
    dna_domain_manifest_t sys;
    memset(e, 0, sizeof(*e));
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL) != 0)
        return -1;
    e->call[0] = param;
    put64(e->call + 1, value);
    put64(e->call + 9, effective);
    put64(e->call + 17, nonce);
    put64(e->call + 25, height);                /* signed_at              */
    put64(e->call + 33, effective + 1000u);     /* valid_before           */

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
    leg.hdr.ruleset_version      = sys.ruleset_version;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len             = CC_CALL_LEN;
    leg.hdr.auth_len             = K1_AUTH_LEN;
    leg.hdr.res_max_effects      = 4;
    leg.hdr.res_max_effect_bytes = 4096;
    leg.call_data = e->call;
    leg.auth_data = e->auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    /* inside the D2 window [height, height + 720] of the block that
     * carries it (0 is refused, phase 0d); height + 5 as test_hf7_edge.c
     * case A3 sets (:667 "expiry A + 5") */
    in.expiry_height       = height + 5u;
    in.fee_amount          = 0;
    in.res_max_total_units = 200000;
    in.leg_count           = 1;
    in.legs                = &leg;

    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys.ruleset_version;
    memcpy(lctx.ruleset_hash, sys.ruleset_hash, 64);

    if (dna_env_encoded_size(&leg, 1, &e->len) != 0) return -1;
    e->bytes = malloc(e->len);
    if (!e->bytes) return -1;
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    size_t used = 0;
    int ok = -1;
    do {
        if (dna_env_encode(&in, e->bytes, e->len, &used) != 0 ||
            used != e->len) break;
        if (dna_env_preflight(e->bytes, e->len, w->v2_chain32, height,
                              &lctx, 1, pf) != DNA_ENV_PF_OK) break;
        e->auth[0] = 1;
        memcpy(e->auth + 1, g_pk, QGP_DSA87_PUBLICKEYBYTES);
        size_t sl = 0;
        if (qgp_dsa87_sign(e->auth + 1 + QGP_DSA87_PUBLICKEYBYTES, &sl,
                           pf->auth_digest[0], 64, g_sk) != 0) break;
        if (dna_env_encode(&in, e->bytes, e->len, &used) != 0 ||
            used != e->len) break;
        ok = 0;
    } while (0);
    free(pf);
    return ok;
}

/* the smallest effective >= floor_h whose A-1 and A are both off an epoch
 * boundary (the param-24 rules (d) and (e), copied from param 22) */
static uint64_t eff_ok(uint64_t floor_h) {
    uint64_t e = floor_h;
    for (;;) {
        int b1 = ((e - 1u) != 0) && ((e - 1u) % E_LEN) == 0;
        int b0 = (e % E_LEN) == 0;
        if (!b1 && !b0) return e;
        e++;
    }
}

static int t_param24_single_use_block_path(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    cc_env_t e1, e2, e3;
    const uint8_t P = (uint8_t)DNAC_CFG_RULESET_GEN_TRIE;
    const uint64_t D6 = (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D;
    const uint64_t GRACE_S = (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
    const uint64_t h = H5 + 2u;             /* 13: under generation 5       */
    CHECK(E_LEN > h + 1u, "no epoch boundary among heights 1..h+1");

    /* params 9 / 14 / 18 / 22 at 3 / 5 / 8 / 11, NO param-24 row */
    CHECK(fx_open(&fx, "once24", H9, HE, HS, H5, 0, 0, -1) == 0,
          "seeded chain (generation 5 from 11, no param-24 row)");
    CHECK(run_idle(&fx, 1, h - 1u) == 0, "idle blocks 1..h-1");
    {
        dna_domain_manifest_t ms;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              ms.ruleset_version == 11,
              "the registry is generation 5 (SYSTEM v11) - the only one "
              "whose exec accepts a param-24 vote (rule (c))");
    }
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM chain_config_history WHERE "
                       "param_id = 24") == 0,
          "no param-24 row before the votes");
    CHECK(probe_install(fx.w, NODUS_RT_GEN_ROOTS) == 0,
          "probe runtime table (gen-5 SYSTEM)");

    const uint64_t eff1 = eff_ok(h + GRACE_S);
    const uint64_t eff2 = eff_ok(eff1 + 3u);
    const uint64_t eff3 = eff_ok(eff2 + 3u);
    CHECK(cc_env_build(fx.w, h, P, D6, eff1, 41, &e1) == 0,
          "first param-24 envelope");
    CHECK(cc_env_build(fx.w, h, P, D6, eff2, 42, &e2) == 0,
          "second param-24 envelope");

    /* L1. two votes in ONE block: the engine re-reads the fact per item,
     * so the second sees the row the first wrote - which is still pending
     * (its effective block is ~17 000 blocks away) */
    {
        nodus_v2_envelope_t envs[2] = { { e1.bytes, e1.len },
                                        { e2.bytes, e2.len } };
        mk_block_envs(&b, h, envs, 2);
        CHECK(v2x_cmt_apply(fx.w, &b) == 0, "block h commits");
        CHECK(b.cmt.results[0].code == NODUS_V2_TX_OK,
              "the first param-24 vote applies");
        CHECK(b.cmt.results[1].code == NODUS_V2_TX_ERR_EXEC,
              "the second param-24 vote is refused in exec (rule (a))");
        CHECK(g_n_seen == 2 && g_seen[0] == 0 && g_seen[1] == 1,
              "the engine filled ctx.ruleset_gen_trie_voted per item "
              "(0, then 1)");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM chain_config_history "
                           "WHERE param_id = 24") == 1,
              "exactly one param-24 row");
        CHECK(q1(fx.w->db, "SELECT effective_block FROM "
                           "chain_config_history WHERE param_id = 24") ==
                  (sqlite3_int64)eff1 && eff1 > h + 1u,
              "and it is still pending (effective block after h + 1)");
    }

    /* L2. a vote in a LATER block: the committed row refuses it */
    CHECK(cc_env_build(fx.w, h + 1u, P, D6, eff3, 43, &e3) == 0,
          "third param-24 envelope");
    {
        nodus_v2_envelope_t envs[1] = { { e3.bytes, e3.len } };
        g_n_seen = 0;
        mk_block_envs(&b, h + 1u, envs, 1);
        CHECK(v2x_cmt_apply(fx.w, &b) == 0, "block h+1 commits");
        CHECK(b.cmt.results[0].code == NODUS_V2_TX_ERR_EXEC,
              "a param-24 vote after a committed row is refused");
        CHECK(g_n_seen == 1 && g_seen[0] == 1,
              "the engine handed the exec the committed row's fact");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM chain_config_history "
                           "WHERE param_id = 24") == 1,
              "still exactly one param-24 row");
        dna_domain_manifest_t ms;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              ms.ruleset_version == 11, "no switch: still generation 5");
    }
    free(e1.bytes);
    free(e2.bytes);
    free(e3.bytes);
    fx_close(&fx);
    return 0;
}

int main(void) {
    int rc = 0;
    {
        uint8_t seed[32];
        memset(seed, 0x5E, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk, g_sk, seed) != 0) {
            fprintf(stderr, "test_hf9_edge: key generation failed\n");
            return 1;
        }
    }
    if (!rc) rc = t_edge();
    if (!rc) rc = t_edge_not_gen5_faults();
    if (!rc) rc = t_edge_wrong_value_faults();
    if (!rc) rc = t_edge_not_the_edge();
#ifdef QGP_FAULT_INJECT
    if (!rc) rc = t_edge_mismatch_faults();
#endif
    if (!rc) rc = t_edge_missing_trigger_faults();
    if (!rc) rc = t_edge_rollback_after_capture();
    if (!rc) rc = t_edge_older_schema_faults();
    if (!rc) rc = t_gen6_older_schema_faults();
    if (!rc) rc = t_edge_param24_read_fault();
    if (!rc) rc = t_param24_single_use_block_path();
    if (!rc) rc = t_shadow_and_replay();
    free(g_probe);
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
