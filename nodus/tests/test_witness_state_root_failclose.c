/*
 * Nodus — witness fail-close: state-root leg faults + supply-gate
 * ambiguity (D1-D3, 2026-07-31; retargeted by the root-layout round,
 * 2026-09-25).
 *
 * The defect class this pins: a transient DB failure used to be converted
 * into a legitimate "empty" or "zero" value and then fed into a state
 * root.
 *
 *   D1  nodus_witness_supply_get is three-valued — 0 present / 1 absent /
 *       -1 real error. Before, a prepare failure and a missing row both
 *       returned -1, so no caller could tell "pre-genesis" from "broken".
 *   D2  every leg of the chain's state root fails CLOSED — a missing
 *       backing table never becomes a tagged-empty sentinel.
 *
 * ROOT-LAYOUT ROUND (K2/K3, docs/plans/decisions/
 * 2026-09-25-root-layout-round.md): the subject of D2 used to be the
 * legacy five-input nodus_witness_merkle_compute_state_root (utxo ‖
 * validator ‖ delegation ‖ epoch_state ‖ chain_config via combine_v3),
 * and D3 was its epoch_state leaf loader. All three are DELETED — no
 * block header carried that root. D2 is re-pinned here on the roots the
 * chain DOES commit: nodus_witness_system_root_v2 ("DNA.SYS.v3" —
 * validator, delegation, chain_config legs among others) and
 * nodus_witness_core_root_v2 ("DNA.CORE.v2" — the utxo and supply legs
 * among others). D3 has no successor subject: the supply counters now
 * reach the root only through supply_root, whose fail-closed read is
 * the "supply" case below. The healthy-composition pin that stood here
 * (state_root == combine_v3 of five subtrees) is replaced by the
 * composition checks in test_roots_v2.c.
 *
 *   R3 W4-D (Delta B): D4 — the v0.16 hard supply gate,
 *   check_supply_invariant_v016, rejecting on a DB error rather than
 *   silently passing — is DELETED here: the gate's only production
 *   definition was nodus_witness_bft.c, deleted whole with the closed
 *   consensus lane, and it has no version-2 successor. Its version-3
 *   counterpart, nodus_witness_v2_supply_check -> nodus_rt_core_invariant,
 *   is already pinned fail-closed by test_v2_gen.c §3.5 (L2-F1) and by
 *   test_v2_pools.c.
 *
 * DETERMINISM: fault injection here is purely structural — DROP TABLE /
 * DELETE FROM against a temp DB. No sleeps, no timing, no randomness, no
 * dependence on scheduling. Every check produces the same verdict on
 * every run and under any ctest parallelism.
 *
 * FIXTURE: nodus_witness_t is multi-MB — heap-allocated with calloc,
 * never on the stack.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_roots_v2.h"
#include "nodus/nodus_types.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail = 0;
static int g_checks = 0;

#define CHECK(cond) do {                                            \
    g_checks++;                                                     \
    if (!(cond)) {                                                  \
        fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        g_fail++;                                                   \
    }                                                               \
} while (0)

#define CHECK_EQ(a, b) do {                                         \
    long long _a = (long long)(a), _b = (long long)(b);             \
    g_checks++;                                                     \
    if (_a != _b) {                                                 \
        fprintf(stderr, "  FAIL %s:%d: %s == %s (got %lld, want %lld)\n", \
                __FILE__, __LINE__, #a, #b, _a, _b);                \
        g_fail++;                                                   \
    }                                                               \
} while (0)

/* ── Fixture ────────────────────────────────────────────────────────── */

/* A witness on a freshly created chain DB. create_chain_db runs the full
 * WITNESS_DB_SCHEMA (validators / delegations / utxo_set / supply_tracking
 * as an empty table / the attendance, accrual, vset and domain-registry
 * tables — no epoch_state since the root-layout round) plus migrate_v12
 * (chain_config_history, and the v17 supply_tracking.total_minted
 * back-fill) and the utxo_set.unlock_block migration the K1 leaf reads.
 *
 * supply_init is still called explicitly below, because the table being
 * present says nothing about the id = 1 ROW: the schema deliberately
 * seeds no row, and it is that row these tests need. */
static nodus_witness_t *fixture_new(const char *label, uint64_t genesis_supply) {
    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB — never on the stack */
    if (!w) return NULL;

    snprintf(w->data_path, sizeof(w->data_path),
             "/tmp/test_wsrfc_%s_XXXXXX", label);
    if (!mkdtemp(w->data_path)) {
        free(w);
        return NULL;
    }

    uint8_t chain_id[16];
    memset(chain_id, 0xC1, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0 || !w->db) {
        free(w);
        return NULL;
    }

    uint8_t genesis_tx_hash[NODUS_T3_TX_HASH_LEN];
    memset(genesis_tx_hash, 0x77, sizeof(genesis_tx_hash));
    if (nodus_witness_supply_init(w, genesis_supply, 0,
                                  genesis_tx_hash) != 0) {
        sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

static void fixture_free(nodus_witness_t *w) {
    if (!w) return;
    if (w->db) sqlite3_close(w->db);
    free(w);
}

/* Deterministic structural fault: remove a backing table outright. Every
 * subsequent sqlite3_prepare_v2 against it returns SQLITE_ERROR
 * ("no such table"), on every platform, on every run. */
static int drop_table(nodus_witness_t *w, const char *table) {
    char sql[128];
    snprintf(sql, sizeof(sql), "DROP TABLE %s", table);
    return sqlite3_exec(w->db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

typedef int (*root_fn_t)(nodus_witness_t *w, uint8_t out[64]);

/* ── (d) the healthy path computes, stably ──────────────────────────── */

static void test_healthy_roots(void) {
    printf("  (d) healthy DB: SYSTEM and CORE roots compute, stably\n");
    nodus_witness_t *w = fixture_new("healthy", 0);
    CHECK(w != NULL);
    if (!w) return;

    uint8_t sys[64], core[64], again[64], zero[64];
    memset(zero, 0, sizeof(zero));
    CHECK_EQ(nodus_witness_system_root_v2(w, sys), 0);
    CHECK_EQ(nodus_witness_core_root_v2(w, core), 0);
    /* An all-zero root would be tautologically matchable by any peer. */
    CHECK(memcmp(sys, zero, 64) != 0);
    CHECK(memcmp(core, zero, 64) != 0);
    CHECK_EQ(nodus_witness_system_root_v2(w, again), 0);
    CHECK(memcmp(sys, again, 64) == 0);
    CHECK_EQ(nodus_witness_core_root_v2(w, again), 0);
    CHECK(memcmp(core, again, 64) == 0);

    fixture_free(w);
}

/* ── (a) Each leg fault fails closed, with no substituted root ──────── */

/* Drops `table`, then asserts `fn` (1) returns non-zero and (2) leaves
 * its output byte-for-byte untouched. The untouched-buffer check is the
 * "did NOT emit a substituted root" evidence. */
static void assert_leg_fails_closed(const char *label, const char *table,
                                    root_fn_t fn, const char *root_name) {
    printf("  (a) DROP %s -> %s fails closed\n", table, root_name);
    nodus_witness_t *w = fixture_new(label, 0);
    CHECK(w != NULL);
    if (!w) return;

    /* Healthy first, so the fault is the only difference. */
    uint8_t healthy[64];
    CHECK_EQ(fn(w, healthy), 0);

    CHECK_EQ(drop_table(w, table), 0);

    uint8_t root[64];
    memset(root, 0x5A, sizeof(root));          /* sentinel canary */
    CHECK(fn(w, root) != 0);

    uint8_t canary[64];
    memset(canary, 0x5A, sizeof(canary));
    CHECK(memcmp(root, canary, 64) == 0);      /* nothing was written */
    CHECK(memcmp(root, healthy, 64) != 0);     /* and it is not the real root */

    fixture_free(w);
}

/* ── (b) supply_get: absent row vs real error, distinguishable ──────── */

static void test_supply_get_three_valued(void) {
    printf("  (b) supply_get: 0 present / 1 absent / -1 error\n");
    nodus_witness_t *w = fixture_new("supplyget", 4200);
    CHECK(w != NULL);
    if (!w) return;

    /* 0 — row present, fields are the ones supply_init wrote. */
    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    int rc_present = nodus_witness_supply_get(w, &sup);
    CHECK_EQ(rc_present, 0);
    CHECK_EQ(sup.genesis_supply, 4200);
    CHECK_EQ(sup.current_supply, 4200);
    CHECK_EQ(sup.total_minted, 0);
    CHECK_EQ(sup.total_burned, 0);

    /* 1 — table present, id = 1 row genuinely gone (sqlite3_step returns
     * SQLITE_DONE). This is the pre-genesis shape. */
    CHECK_EQ(sqlite3_exec(w->db, "DELETE FROM supply_tracking WHERE id = 1",
                          NULL, NULL, NULL), SQLITE_OK);
    memset(&sup, 0, sizeof(sup));
    int rc_absent = nodus_witness_supply_get(w, &sup);
    CHECK_EQ(rc_absent, 1);

    /* -1 — real error (prepare fails: no such table). */
    CHECK_EQ(drop_table(w, "supply_tracking"), 0);
    memset(&sup, 0, sizeof(sup));
    int rc_error = nodus_witness_supply_get(w, &sup);
    CHECK_EQ(rc_error, -1);

    /* The whole point of D1: these two are not the same answer. A caller
     * written as `if (rc != 0) { treat as pre-genesis; }` — which is what
     * check_supply_invariant_v016 used to be — cannot tell them apart. */
    CHECK(rc_absent != rc_error);

    /* NULL out is still a hard error, not "absent". */
    CHECK_EQ(nodus_witness_supply_get(w, NULL), -1);

    fixture_free(w);
}

/* ── main ───────────────────────────────────────────────────────────── */

int main(void) {
    printf("\nWitness fail-close: state-root legs + supply gate (D1-D2)\n");

    test_healthy_roots();

    /* One per backing table of a committed leg. SYSTEM: validator,
     * delegation, chain_config legs. CORE: utxo and supply legs (a DB
     * error in supply_get is -1, never pre-genesis zeros — D1 feeding
     * D2). */
    assert_leg_fails_closed("validator",  "validators",
                            nodus_witness_system_root_v2, "SYSTEM root");
    assert_leg_fails_closed("delegation", "delegations",
                            nodus_witness_system_root_v2, "SYSTEM root");
    assert_leg_fails_closed("chaincfg",   "chain_config_history",
                            nodus_witness_system_root_v2, "SYSTEM root");
    assert_leg_fails_closed("utxo",       "utxo_set",
                            nodus_witness_core_root_v2, "CORE root");
    assert_leg_fails_closed("supply",     "supply_tracking",
                            nodus_witness_core_root_v2, "CORE root");

    test_supply_get_three_valued();

    if (g_fail == 0) {
        printf("test_witness_state_root_failclose: ALL %d CHECKS PASSED\n",
               g_checks);
        return 0;
    }
    printf("test_witness_state_root_failclose: %d/%d CHECKS FAILED\n",
           g_fail, g_checks);
    return 1;
}
