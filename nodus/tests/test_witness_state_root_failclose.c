/*
 * Nodus — witness fail-close: state_root subtree faults + supply-gate
 * ambiguity (D1-D4, 2026-07-31).
 *
 * The defect class this pins: a transient DB failure used to be converted
 * into a legitimate "empty" or "zero" value and then fed into state_root.
 *
 *   D1  nodus_witness_supply_get is three-valued — 0 present / 1 absent /
 *       -1 real error. Before, a prepare failure and a missing row both
 *       returned -1, so no caller could tell "pre-genesis" from "broken".
 *   D2  nodus_witness_merkle_compute_state_root fails CLOSED on every
 *       subtree, not just utxo. The four nodus_merkle_empty_root(...)
 *       sentinel fallbacks are gone.
 *   D3  load_epoch_state_leaves zeroes the supply counters only when D1
 *       reports 1 (genuinely absent); a -1 propagates out.
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
#include "witness/nodus_witness_merkle.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The v0.16 Stage F.1 hard supply gate. Non-static in the library for the
 * same reason as the other BFT primitives tests reach into (see the header
 * block of nodus_witness_bft_internal.h). Its canonical prototype belongs
 * in that header; it is declared locally here because that file was
 * outside this change's approved file whitelist. */
int check_supply_invariant_v016(nodus_witness_t *w);

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
 * WITNESS_DB_SCHEMA (validators / delegations / epoch_state / utxo_set —
 * and, since the K4 change merged alongside this one, supply_tracking as
 * an empty table) plus migrate_v12 (chain_config_history, and the v17
 * supply_tracking.total_minted back-fill).
 *
 * MERGE NOTE (2026-07-31): this comment used to say supply_tracking "is
 * created lazily by supply_init". That is no longer true — the table is
 * in the open-time schema. supply_init is still called explicitly below,
 * because the table being present says nothing about the id = 1 ROW: the
 * schema deliberately seeds no row, and it is that row these tests need.
 * That is exactly what the genesis commit path does before it reaches
 * finalize_block (nodus_witness_bft.c:5924). */
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
    if (nodus_witness_supply_init(w, genesis_supply, genesis_tx_hash) != 0) {
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

/* ── (d) Regression pin: the healthy path is unchanged ──────────────── */

/* The evidence that D2 did not change the accept set. compute_state_root
 * on a healthy DB must still be exactly the v3 combination of the five
 * per-subtree functions — the same composition it produced before the
 * sentinel fallbacks were deleted, because on a healthy DB no fallback
 * ever fired. Derived in-test rather than hard-coded so the pin cannot
 * silently rot against a leaf-layout change it is not meant to guard. */
static void test_healthy_root_unchanged(void) {
    printf("  (d) healthy DB: state_root == combine_v3(five real subtrees)\n");
    nodus_witness_t *w = fixture_new("healthy", 0);
    CHECK(w != NULL);
    if (!w) return;

    uint8_t utxo[64], validator[64], delegation[64], epoch[64], cc[64];
    CHECK_EQ(nodus_witness_merkle_compute_utxo_root(w, utxo), 0);
    CHECK_EQ(nodus_witness_merkle_compute_validator_root(w, validator), 0);
    CHECK_EQ(nodus_witness_merkle_compute_delegation_root(w, delegation), 0);
    CHECK_EQ(nodus_witness_merkle_compute_epoch_state_root(w, epoch), 0);
    CHECK_EQ(nodus_chain_config_compute_root(w, cc), 0);

    uint8_t expected[64];
    /* O15J Faz 3 — the v4 (6-leg) composition went with the activation
     * ceremony. state_root is v3 over the five real subtrees, in every
     * build; there is no longer a second composition to branch on. */
    nodus_merkle_combine_state_root_v3(utxo, validator, delegation,
                                        epoch, cc, expected);

    uint8_t got[64];
    CHECK_EQ(nodus_witness_merkle_compute_state_root(w, got), 0);
    CHECK(memcmp(got, expected, 64) == 0);

    /* Non-zero + stable across recomputation (an all-zero root would be
     * tautologically matchable by any peer mid-wipe). */
    uint8_t zero[64];
    memset(zero, 0, sizeof(zero));
    CHECK(memcmp(got, zero, 64) != 0);

    uint8_t again[64];
    CHECK_EQ(nodus_witness_merkle_compute_state_root(w, again), 0);
    CHECK(memcmp(got, again, 64) == 0);

    fixture_free(w);
}

/* ── (a) Each subtree fault fails closed, with no substituted root ──── */

/* Drops `table`, then asserts compute_state_root (1) returns non-zero and
 * (2) leaves root_out byte-for-byte untouched. The untouched-buffer check
 * is the "did NOT emit a substituted root" evidence: pre-fix, four of
 * these five faults returned 0 with a tagged-empty sentinel written into
 * the corresponding slot. */
static void assert_subtree_fails_closed(const char *label, const char *table) {
    printf("  (a) DROP %s -> compute_state_root fails closed\n", table);
    nodus_witness_t *w = fixture_new(label, 0);
    CHECK(w != NULL);
    if (!w) return;

    /* Healthy first, so the fault is the only difference. */
    uint8_t healthy[64];
    CHECK_EQ(nodus_witness_merkle_compute_state_root(w, healthy), 0);

    CHECK_EQ(drop_table(w, table), 0);

    uint8_t root[64];
    memset(root, 0x5A, sizeof(root));          /* sentinel canary */
    CHECK(nodus_witness_merkle_compute_state_root(w, root) != 0);

    uint8_t canary[64];
    memset(canary, 0x5A, sizeof(canary));
    CHECK(memcmp(root, canary, 64) == 0);      /* nothing was written */
    CHECK(memcmp(root, healthy, 64) != 0);     /* and it is not the real root */

    fixture_free(w);
}

/* The strongest form of the (a) claim, for the one fault where the other
 * four subtrees still compute: dropping `validators` must NOT yield the
 * root the deleted fallback would have produced. */
static void test_no_sentinel_substitution(void) {
    printf("  (a+) DROP validators -> not the old tagged-empty sentinel root\n");
    nodus_witness_t *w = fixture_new("sentinel", 0);
    CHECK(w != NULL);
    if (!w) return;

    uint8_t utxo[64], delegation[64], epoch[64], cc[64];
    CHECK_EQ(nodus_witness_merkle_compute_utxo_root(w, utxo), 0);
    CHECK_EQ(nodus_witness_merkle_compute_delegation_root(w, delegation), 0);
    CHECK_EQ(nodus_witness_merkle_compute_epoch_state_root(w, epoch), 0);
    CHECK_EQ(nodus_chain_config_compute_root(w, cc), 0);

    /* Exactly what the pre-D2 code emitted on this fault. */
    uint8_t sentinel_validator[64], old_behaviour[64];
    nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR, sentinel_validator);
    nodus_merkle_combine_state_root_v3(utxo, sentinel_validator, delegation,
                                        epoch, cc, old_behaviour);

    CHECK_EQ(drop_table(w, "validators"), 0);

    uint8_t root[64];
    memset(root, 0x5A, sizeof(root));
    CHECK(nodus_witness_merkle_compute_state_root(w, root) != 0);
    CHECK(memcmp(root, old_behaviour, 64) != 0);

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

/* ── (c) The supply gate is no longer skipped on a DB error ─────────── */

static void test_supply_gate_rejects_db_error(void) {
    printf("  (c) check_supply_invariant_v016 on a DB error\n");

    /* genesis_supply = 0 so expected == observed == 0 on the healthy DB;
     * the gate therefore PASSES and a later -1 is unambiguously the fault
     * we injected, not a real invariant violation. */
    nodus_witness_t *w = fixture_new("supplygate", 0);
    CHECK(w != NULL);
    if (!w) return;

    /* Healthy: the gate runs and holds. */
    CHECK_EQ(check_supply_invariant_v016(w), 0);

    /* Genuinely absent row (pre-genesis) — UNCHANGED behaviour: nothing
     * to conserve yet, so the gate legitimately passes. */
    CHECK_EQ(sqlite3_exec(w->db, "DELETE FROM supply_tracking WHERE id = 1",
                          NULL, NULL, NULL), SQLITE_OK);
    CHECK_EQ(check_supply_invariant_v016(w), 0);

    /* DB error — the pin. Pre-D1 this returned 0 and finalize_block
     * committed the block with the supply invariant never evaluated. */
    CHECK_EQ(drop_table(w, "supply_tracking"), 0);
    CHECK_EQ(check_supply_invariant_v016(w), -1);

    fixture_free(w);
}

/* D3 in isolation: the counters that go into every epoch_state leaf must
 * not be silently zeroed on a DB error. With supply_tracking dropped, the
 * epoch_state subtree itself must fail rather than hash zeros. */
static void test_epoch_state_root_fails_on_supply_error(void) {
    printf("  (c+) epoch_state_root refuses zeroed supply counters\n");
    nodus_witness_t *w = fixture_new("epochsupply", 4200);
    CHECK(w != NULL);
    if (!w) return;

    uint8_t healthy[64];
    CHECK_EQ(nodus_witness_merkle_compute_epoch_state_root(w, healthy), 0);

    CHECK_EQ(drop_table(w, "supply_tracking"), 0);

    uint8_t root[64];
    memset(root, 0x5A, sizeof(root));
    CHECK(nodus_witness_merkle_compute_epoch_state_root(w, root) != 0);

    uint8_t canary[64];
    memset(canary, 0x5A, sizeof(canary));
    CHECK(memcmp(root, canary, 64) == 0);

    fixture_free(w);
}

/* ── main ───────────────────────────────────────────────────────────── */

int main(void) {
    printf("\nWitness fail-close: state_root subtrees + supply gate (D1-D4)\n");

    test_healthy_root_unchanged();

    /* One per subtree that compute_state_root depends on. epoch_state is
     * covered twice: via its own table and via supply_tracking, which
     * feeds its leaves (D3). */
    assert_subtree_fails_closed("utxo",       "utxo_set");
    assert_subtree_fails_closed("validator",  "validators");
    assert_subtree_fails_closed("delegation", "delegations");
    assert_subtree_fails_closed("epoch",      "epoch_state");
    assert_subtree_fails_closed("chaincfg",   "chain_config_history");
    assert_subtree_fails_closed("supply",     "supply_tracking");
    test_no_sentinel_substitution();

    test_supply_get_three_valued();
    test_supply_gate_rejects_db_error();
    test_epoch_state_root_fails_on_supply_error();

    if (g_fail == 0) {
        printf("test_witness_state_root_failclose: ALL %d CHECKS PASSED\n",
               g_checks);
        return 0;
    }
    printf("test_witness_state_root_failclose: %d/%d CHECKS FAILED\n",
           g_fail, g_checks);
    return 1;
}
