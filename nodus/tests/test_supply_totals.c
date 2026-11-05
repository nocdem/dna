/**
 * @file nodus/tests/test_supply_totals.c
 * @brief HF-9 T-8 — the supply running totals (plan docs/plans/approved/
 *        2026-11-04-hf9.md §9.1, §12 row T-8; decisions D8, D27).
 *
 * The totals: v2_supply_totals (Σ utxo_set.amount per token_id) and
 * v2_bond_total (Σ v2_storage_nodes.bond over status ACTIVE / EXITING),
 * kept by six SQLite triggers (schema S20, nodus_witness_v2_schema.h) and
 * read by nodus_rt_core_invariant instead of a SUM over every row.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. TRIGGERS vs SUM. After every kind of write the stored totals equal
 *     the SUM recomputed from the tables, for the native token and for a
 *     second token: insert, delete, update of amount, update of token_id,
 *     an INSERT OR IGNORE that inserts nothing; INSERT OR REPLACE over an
 *     existing nullifier is pinned as a known SQLite limitation (the
 *     replaced row's delete trigger does not fire; no writer uses it;
 *     the drift is visible and the re-seed repairs it); registry insert, bond update, ACTIVE -> EXITING
 *     (still counted), EXITING -> RELEASED (leaves the term), delete.
 *  B. ROLLBACK. An item SAVEPOINT rolled back and a whole transaction
 *     rolled back (the two ways a block's writes are undone,
 *     nodus_witness_v2_apply.c item savepoints / the host's ROLLBACK)
 *     leave the totals exactly as before — the totals live in the same
 *     transaction as the rows. A released savepoint keeps them.
 *  C. RE-SEED. Totals overwritten with wrong values are rewritten from the
 *     tables by nodus_witness_db_s20_reseed; so does the production open
 *     path (nodus_witness_create_chain_db on the same file). A deleted
 *     native row and a deleted bond row come back (a re-seed always writes
 *     them). A DROPPED supply trigger is recreated by the re-seed; an
 *     ALTERED one (same name, other body) is refused (-1): the stored SQL
 *     is compared with this build's text.
 *  D. THE INVARIANT READS THE TOTALS (nodus_witness_v2_supply_check on a
 *     real derived chain, balanced at the start): a native total one off
 *     the equation fails it (so the check does not recompute the SUM);
 *     and it fails CLOSED, never as a value, on: an absent native row, an
 *     absent bond row, a REAL total, a TEXT total, a NEGATIVE total, a
 *     bond total of the wrong type (REAL, TEXT, negative, absent). A NULL
 *     total cannot be stored (NOT NULL). A total pushed past INT64_MAX by
 *     a trigger becomes REAL in SQLite and the check refuses it. After a
 *     re-seed the check passes again.
 *  E. THE OWNERSHIP GUARD (HF-9 amendment 2026-11-05, T-17a-d; the partial
 *     index idx_utxo_foreign ON utxo_set(domain_id) WHERE domain_id != 1,
 *     operator: "fihristekle."; the guard's SQL is unchanged).
 *     T-17a verdict table: on the balanced chain, one existing row gets each
 *     of 0, 2, -1, INT64_MAX, INT64_MIN, 1.5, 0.9999999999999999, 1e300,
 *     'abc', '', X'01' (all foreign) and '1', ' 1', '1.0', 1.0 (converted to
 *     1 by the column's INTEGER affinity: not foreign) as its domain_id;
 *     the check must be -1 exactly when the full-scan oracle
 *     `+domain_id != 1` counts > 0; every case is paired with a passing
 *     baseline before and a passing restore after; then two conserving
 *     (amount 0) foreign rows are inserted and deleted one by one. The
 *     whole table runs twice: with the index and with it dropped.
 *     T-17b plan pin: the guard statement is CAPTURED (sqlite3_trace_v2)
 *     from one real nodus_witness_v2_supply_check on a 1 000-row table; its
 *     EXPLAIN QUERY PLAN is exactly one row, `SCAN utxo_set USING COVERING
 *     INDEX idx_utxo_foreign` (a scan of the empty partial index, not a
 *     SEARCH); without the index it is `SCAN utxo_set`; the six production
 *     statements that filter on domain_id (point read, DELETE, the two
 *     owner lists, the balance query, the msig read) never use the index
 *     and have the same plan with and without it.
 *     T-17c growth: the guard's VM steps (sqlite3_stmt_status) are EQUAL at
 *     100 and at 100 000 planted rows; the `+domain_id` form (the control)
 *     steps at least 100 000 more than the guard at 100 000 rows; the
 *     progress-handler instruction count of one whole supply check differs
 *     by less than (100 000 - 100) / 10 between the two sizes (the rule of
 *     test_cmt_app hybrid_growth_probe G-f).
 *     T-17d schema: each S20 fault point (AFTER_BEGIN .. BEFORE_COMMIT) of
 *     the rung leaves no idx_utxo_foreign and version 19; the rung creates
 *     it with the exact stored text; the rung refuses a same-name index of
 *     another definition; the at-open function re-creates a dropped one;
 *     on the real derived chain a DROP followed by the production open path
 *     (reopen) re-creates it; a same-name index of another definition is
 *     neither refused nor replaced at open (DF-11) and the guard still
 *     catches a foreign row with it.
 *
 * ── FLAGS ───────────────────────────────────────────────────────────────
 *  Compiled by register_witness_test (NODUS_WITNESS_INTERNAL_API); no
 *  fault injection, no -DDNAC_EPOCH_LENGTH, no environment.
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 *  Directories /tmp/v2x_supplytot_XXXXXX, removed by v2x_chain_close, and
 *  /tmp/v2x_s20idx_XXXXXX (the T-17d scratch databases), removed by
 *  s19_close (a crash leaves either). Section E deletes the rows it plants
 *  (owner 'plant' / 'f' / 'one') and restores every domain_id and the
 *  index. The derived chain has NO utxo_set row (v2_genesis_fixture.h:820,
 *  :945), so T-17a and T-17d plant one conserving CORE row (amount 0,
 *  domain 1, owner 'one') to rewrite, with a baseline-still-passes check
 *  after planting and a removal check at the end. T-17b and T-17c plant
 *  their own rows and never rewrite an existing one.
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  - Section D passes vacuously if the baseline supply_check is not 0 for
 *    another reason: every failing case is therefore paired with a
 *    passing check on the same chain right before (the baseline) and
 *    after the re-seed (the restore).
 *  - Section A compares the triggers to SQL SUM over the same tables; a
 *    bug that moved both identically (a wrong amount bound by the test)
 *    would pass — the amounts are literal constants in this file.
 *  - Section B proves rollback of the totals only for SQLite's own
 *    transaction machinery, not for the engine's call sites.
 *  - T-17a: an oracle that shared a wrong literal with production would
 *    pass; the oracle's literal 1 is written in this file while production
 *    formats rt->domain_id (DNA_DOMAIN_CORE). Vacuous if the baseline is
 *    not 0: each case is paired with a baseline and a restore. A column
 *    affinity that did not convert '1' would make the converted group
 *    fail, not pass.
 *  - T-17b: the statement is captured from the real call, not rebuilt; the
 *    plan wording is that of the linked SQLite (3.40.1): a library change
 *    fails the test (a false fail, not a false pass). The six other
 *    statements are copies of the production texts and could drift from
 *    them; their equality with and without the index is the check.
 *  - T-17c: VM steps do not count B-tree page descents (O(log n)); the
 *    planted amount-0 rows are a state no writer produces (the guard's
 *    cost depends only on the row count). Skips nothing; a guard that
 *    scanned would fail the equality and the control proves the counter
 *    sees a scan.
 *  - T-17d: a reopen that did not run the at-open function would leave the
 *    index absent: absence is asserted before and presence after.
 *  - No test here exercises an engine writer of utxo_set (rtn_core_mutate
 *    and the others, plan §4.3); they are exercised by the existing block
 *    tests whose supply check now reads the totals.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_schema.h"
#include "dnac/ledger_roots_v2.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n  %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* one integer, -1 on any fault; the statement must return one row */
static sqlite3_int64 q1(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_int64 v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* a utxo row: nullifier = 63 zero bytes || nb, token = native (tok == 0)
 * or 63 zero bytes || 0x77 (tok == 1) */
static int put_utxo(sqlite3 *db, int nb, int tok, long long amount) {
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) VALUES (CAST(zeroblob(63)||x'%02x' AS BLOB), 'o', "
        "%lld, %s, zeroblob(63)||x'%02x', 0, 0, 0, 0, 1)",
        nb, amount,
        tok ? "CAST(zeroblob(63)||x'77' AS BLOB)" : "zeroblob(64)", nb);
    return run_sql(db, sql);
}

static int put_node(sqlite3 *db, int nb, long long bond, int status) {
    char sql[640];
    snprintf(sql, sizeof(sql),
        "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, bond, "
        "status, registered_height, exit_height, fail_streak, "
        "grace_until) VALUES (CAST(zeroblob(63)||x'%02x' AS BLOB), "
        "zeroblob(2592), zeroblob(64), %lld, %d, 1, 0, 0, 0)",
        nb, bond, status);
    return run_sql(db, sql);
}

/* 1 = every stored total equals the SUM over its table:
 *   each token_id group matches its row; a row with no group is 0;
 *   the native row exists; the bond row equals the ACTIVE/EXITING sum. */
static int totals_match(sqlite3 *db) {
    if (q1(db, "SELECT COUNT(*) FROM (SELECT token_id, SUM(amount) s FROM "
               "utxo_set GROUP BY token_id) g LEFT JOIN v2_supply_totals t "
               "ON t.token_id = g.token_id WHERE t.utxo_total IS NOT g.s "
               "OR typeof(t.utxo_total) != 'integer'") != 0) return 0;
    if (q1(db, "SELECT COUNT(*) FROM v2_supply_totals t WHERE "
               "t.utxo_total != 0 AND NOT EXISTS (SELECT 1 FROM utxo_set u "
               "WHERE u.token_id = t.token_id)") != 0) return 0;
    if (q1(db, "SELECT COUNT(*) FROM v2_supply_totals WHERE token_id = "
               "zeroblob(64)") != 1) return 0;
    if (q1(db, "SELECT COUNT(*) FROM v2_bond_total WHERE id = 1 AND "
               "typeof(total) = 'integer' AND total = (SELECT "
               "COALESCE(SUM(bond), 0) FROM v2_storage_nodes WHERE status "
               "IN (1, 2))") != 1) return 0;
    return 1;
}

static sqlite3_int64 native_total(sqlite3 *db) {
    return q1(db, "SELECT utxo_total FROM v2_supply_totals WHERE token_id "
                  "= zeroblob(64)");
}
static sqlite3_int64 bond_total(sqlite3 *db) {
    return q1(db, "SELECT total FROM v2_bond_total WHERE id = 1");
}

/* reopen the chain file through the production open path */
static int reopen(v2x_chain_t *c) {
    sqlite3_close(c->w->db);
    c->w->db = NULL;
    memset(c->w, 0, sizeof(*c->w));
    c->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(c->w->data_path, sizeof(c->w->data_path), "%s", c->dir);
    return nodus_witness_create_chain_db(c->w, c->chain32);
}

/* ── A. triggers vs SUM ─────────────────────────────────────────────── */
static int test_triggers(v2x_chain_t *c) {
    sqlite3 *db = c->w->db;
    CHECK(totals_match(db) == 1, "A0: totals match at the start");
    sqlite3_int64 n0 = native_total(db);

    CHECK(put_utxo(db, 0xA1, 0, 1000) == 0, "A1: insert native");
    CHECK(put_utxo(db, 0xA2, 0, 2500) == 0, "A1: insert native 2");
    CHECK(put_utxo(db, 0xA3, 1, 77) == 0, "A1: insert token");
    CHECK(totals_match(db) == 1 && native_total(db) == n0 + 3500,
          "A1: totals after inserts");
    CHECK(q1(db, "SELECT utxo_total FROM v2_supply_totals WHERE token_id = "
                 "CAST(zeroblob(63)||x'77' AS BLOB)") == 77,
          "A1: the second token has its own row");

    /* a duplicate primary key with INSERT OR IGNORE inserts nothing and
     * fires nothing (the utxo_add_locked shape) */
    CHECK(run_sql(db,
        "INSERT OR IGNORE INTO utxo_set (nullifier, owner, amount, "
        "token_id, tx_hash, output_index, block_height, created_at, "
        "unlock_block, domain_id) VALUES (CAST(zeroblob(63)||x'a1' AS "
        "BLOB), 'o', 999999, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)")
        == 0, "A2: ignored duplicate");
    CHECK(totals_match(db) == 1 && native_total(db) == n0 + 3500,
          "A2: the ignored duplicate moved nothing");

    /* INSERT OR REPLACE over an existing key: SQLite fires the delete
     * triggers of the replaced row only with PRAGMA recursive_triggers
     * on, which this build never sets, so the old amount stays counted.
     * No writer uses OR REPLACE on utxo_set or v2_storage_nodes (grep of
     * nodus/src, shared, dnac/src; plan §4.3). This pins the limitation:
     * the drift is VISIBLE (totals != SUM, so the supply check would stop
     * the node, never pass silently) and the open-time re-seed repairs it. */
    CHECK(run_sql(db,
        "INSERT OR REPLACE INTO utxo_set (nullifier, owner, amount, "
        "token_id, tx_hash, output_index, block_height, created_at, "
        "unlock_block, domain_id) VALUES (CAST(zeroblob(63)||x'a1' AS "
        "BLOB), 'o', 400, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)")
        == 0, "A3: replace");
    CHECK(totals_match(db) == 0,
          "A3: OR REPLACE leaves the replaced amount counted (SQLite)");
    CHECK(nodus_witness_db_s20_reseed(c->w) == 0 && totals_match(db) == 1,
          "A3: the re-seed repairs it");

    CHECK(run_sql(db, "UPDATE utxo_set SET amount = 4242 WHERE nullifier "
                      "= CAST(zeroblob(63)||x'a2' AS BLOB)") == 0,
          "A4: update amount");
    CHECK(totals_match(db) == 1, "A4: totals after update of amount");
    CHECK(run_sql(db, "UPDATE utxo_set SET token_id = zeroblob(64) WHERE "
                      "nullifier = CAST(zeroblob(63)||x'a3' AS BLOB)") == 0,
          "A5: update token_id");
    CHECK(totals_match(db) == 1, "A5: totals after a token moved to native");
    CHECK(run_sql(db, "UPDATE utxo_set SET owner = 'p' WHERE nullifier = "
                      "CAST(zeroblob(63)||x'a2' AS BLOB)") == 0,
          "A6: update of another column");
    CHECK(totals_match(db) == 1, "A6: another column moves nothing");

    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE nullifier IN ("
                      "CAST(zeroblob(63)||x'a1' AS BLOB), "
                      "CAST(zeroblob(63)||x'a3' AS BLOB))") == 0,
          "A7: delete");
    CHECK(totals_match(db) == 1, "A7: totals after delete");
    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE nullifier = "
                      "CAST(zeroblob(63)||x'a2' AS BLOB)") == 0,
          "A7: delete last");
    CHECK(totals_match(db) == 1 && native_total(db) == n0,
          "A7: back to the starting native total");

    /* bonds: status 1 ACTIVE, 2 EXITING, 3 RELEASED */
    sqlite3_int64 b0 = bond_total(db);
    CHECK(put_node(db, 0xB1, 5000, 1) == 0, "A8: register active");
    CHECK(put_node(db, 0xB2, 700, 1) == 0, "A8: register active 2");
    CHECK(put_node(db, 0xB3, 100, 3) == 0, "A8: a RELEASED row counts 0");
    CHECK(totals_match(db) == 1 && bond_total(db) == b0 + 5700,
          "A8: bond total after registers");
    CHECK(run_sql(db, "UPDATE v2_storage_nodes SET status = 2 WHERE "
                      "node_fp = CAST(zeroblob(63)||x'b1' AS BLOB)") == 0,
          "A9: ACTIVE -> EXITING");
    CHECK(totals_match(db) == 1 && bond_total(db) == b0 + 5700,
          "A9: EXITING still counts");
    CHECK(run_sql(db, "UPDATE v2_storage_nodes SET status = 3 WHERE "
                      "node_fp = CAST(zeroblob(63)||x'b1' AS BLOB)") == 0,
          "A10: EXITING -> RELEASED");
    CHECK(totals_match(db) == 1 && bond_total(db) == b0 + 700,
          "A10: RELEASED leaves the term");
    CHECK(run_sql(db, "UPDATE v2_storage_nodes SET bond = 900 WHERE "
                      "node_fp = CAST(zeroblob(63)||x'b2' AS BLOB)") == 0,
          "A11: bond update");
    CHECK(totals_match(db) == 1 && bond_total(db) == b0 + 900,
          "A11: bond total after a bond update");
    CHECK(run_sql(db, "UPDATE v2_storage_nodes SET fail_streak = 3") == 0,
          "A12: unrelated column");
    CHECK(totals_match(db) == 1, "A12: unrelated column moves nothing");
    CHECK(run_sql(db, "DELETE FROM v2_storage_nodes WHERE node_fp = "
                      "CAST(zeroblob(63)||x'b2' AS BLOB)") == 0,
          "A13: delete an active row");
    CHECK(totals_match(db) == 1 && bond_total(db) == b0,
          "A13: delete leaves the term");
    CHECK(run_sql(db, "DELETE FROM v2_storage_nodes WHERE node_fp IN ("
                      "CAST(zeroblob(63)||x'b1' AS BLOB), "
                      "CAST(zeroblob(63)||x'b3' AS BLOB))") == 0,
          "A13: delete the rest");
    CHECK(totals_match(db) == 1 && bond_total(db) == b0,
          "A13: released rows leave nothing behind");
    return 0;
}

/* ── B. rollback ────────────────────────────────────────────────────── */
static int test_rollback(v2x_chain_t *c) {
    sqlite3 *db = c->w->db;
    sqlite3_int64 n0 = native_total(db), b0 = bond_total(db);
    CHECK(totals_match(db) == 1, "B0: totals match");

    CHECK(run_sql(db, "BEGIN") == 0, "B1: begin");
    CHECK(put_utxo(db, 0xC1, 0, 50) == 0, "B1: block write");
    CHECK(run_sql(db, "SAVEPOINT item") == 0, "B1: savepoint");
    CHECK(put_utxo(db, 0xC2, 0, 60) == 0 && put_node(db, 0xC3, 8, 1) == 0,
          "B1: item writes");
    CHECK(native_total(db) == n0 + 110 && bond_total(db) == b0 + 8,
          "B1: totals inside the item");
    CHECK(run_sql(db, "ROLLBACK TO item; RELEASE item") == 0,
          "B1: item rolled back");
    CHECK(native_total(db) == n0 + 50 && bond_total(db) == b0 &&
          totals_match(db) == 1,
          "B1: an item rollback removes only the item's totals");
    CHECK(run_sql(db, "SAVEPOINT item2") == 0 &&
          put_utxo(db, 0xC4, 0, 7) == 0 &&
          run_sql(db, "RELEASE item2") == 0, "B2: released savepoint");
    CHECK(native_total(db) == n0 + 57 && totals_match(db) == 1,
          "B2: a released savepoint keeps its totals");
    CHECK(run_sql(db, "ROLLBACK") == 0, "B3: block rollback");
    CHECK(native_total(db) == n0 && bond_total(db) == b0 &&
          totals_match(db) == 1,
          "B3: a block rollback restores the totals");
    return 0;
}

/* ── C. re-seed ─────────────────────────────────────────────────────── */
static int test_reseed(v2x_chain_t *c) {
    sqlite3 *db = c->w->db;
    CHECK(put_utxo(db, 0xD1, 0, 123) == 0 && put_node(db, 0xD2, 456, 1) == 0,
          "C0: rows");
    CHECK(totals_match(db) == 1, "C0: totals match");

    CHECK(run_sql(db, "UPDATE v2_supply_totals SET utxo_total = 5; "
                      "UPDATE v2_bond_total SET total = 9") == 0,
          "C1: corrupt the totals");
    CHECK(totals_match(db) == 0, "C1: the corruption is visible");
    CHECK(nodus_witness_db_s20_reseed(c->w) == 0, "C1: reseed");
    CHECK(totals_match(db) == 1, "C1: a re-seed restores the sums");

    CHECK(run_sql(db, "UPDATE v2_supply_totals SET utxo_total = 5; "
                      "UPDATE v2_bond_total SET total = 9; "
                      "DELETE FROM v2_supply_totals WHERE token_id = "
                      "zeroblob(64)") == 0, "C2: corrupt again");
    CHECK(reopen(c) == 0, "C2: the production open path");
    db = c->w->db;
    CHECK(totals_match(db) == 1,
          "C2: the open path re-seeds the totals and the native row");

    CHECK(run_sql(db, "DELETE FROM v2_bond_total") == 0, "C3: drop the row");
    CHECK(nodus_witness_db_s20_reseed(c->w) == 0 && totals_match(db) == 1,
          "C3: the bond row is written again");

    /* a dropped trigger is recreated; the totals keep working after */
    CHECK(run_sql(db, "DROP TRIGGER v2_supply_utxo_ins") == 0,
          "C4: drop a trigger");
    CHECK(nodus_witness_db_s20_reseed(c->w) == 0, "C4: reseed");
    CHECK(q1(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                 "AND name LIKE 'v2_supply_%'") == 6,
          "C4: all six supply triggers exist again");
    CHECK(put_utxo(db, 0xD3, 0, 11) == 0 && totals_match(db) == 1,
          "C4: the recreated trigger works");

    /* an altered trigger (same name, other body) is refused */
    CHECK(run_sql(db, "DROP TRIGGER v2_supply_utxo_del; "
                      "CREATE TRIGGER v2_supply_utxo_del AFTER DELETE ON "
                      "utxo_set BEGIN SELECT 1; END") == 0,
          "C5: replace a trigger body");
    CHECK(nodus_witness_db_s20_reseed(c->w) == -1,
          "C5: an altered trigger is refused");
    CHECK(run_sql(db, "DROP TRIGGER v2_supply_utxo_del") == 0 &&
          nodus_witness_db_s20_reseed(c->w) == 0 && totals_match(db) == 1,
          "C5: dropping it lets the re-seed restore the exact text");

    /* remove the rows this section planted: section D needs the derived
     * chain's own (balanced) state */
    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE owner = 'o'; "
                      "DELETE FROM v2_storage_nodes") == 0, "C6: cleanup");
    CHECK(totals_match(db) == 1, "C6: totals match after the cleanup");
    return 0;
}

/* ── D. the invariant reads the totals, fails closed ────────────────── */
static int test_invariant(v2x_chain_t *c) {
    sqlite3 *db = c->w->db;
    CHECK(nodus_witness_db_s20_reseed(c->w) == 0 && totals_match(db) == 1,
          "D0: totals consistent");
    CHECK(nodus_witness_v2_supply_check(c->w) == 0,
          "D0: baseline: the derived chain balances");

    /* the check reads the total, it does not recompute the SUM */
    CHECK(run_sql(db, "UPDATE v2_supply_totals SET utxo_total = "
                      "utxo_total + 1 WHERE token_id = zeroblob(64)") == 0,
          "D1: native total one off");
    CHECK(nodus_witness_v2_supply_check(c->w) != 0,
          "D1: an off-by-one native total breaks the equation");
    CHECK(nodus_witness_db_s20_reseed(c->w) == 0 &&
          nodus_witness_v2_supply_check(c->w) == 0, "D1: restored");

    CHECK(run_sql(db, "UPDATE v2_bond_total SET total = total + 1") == 0,
          "D2: bond total one off");
    CHECK(nodus_witness_v2_supply_check(c->w) != 0,
          "D2: an off-by-one bond total breaks the equation");
    CHECK(nodus_witness_db_s20_reseed(c->w) == 0 &&
          nodus_witness_v2_supply_check(c->w) == 0, "D2: restored");

    /* fail closed: the stored value must be an INTEGER in 0..INT64_MAX */
    static const char *const bad_native[] = {
        "UPDATE v2_supply_totals SET utxo_total = 1.5 WHERE token_id = "
        "zeroblob(64)",                                  /* REAL         */
        "UPDATE v2_supply_totals SET utxo_total = 'abc' WHERE token_id = "
        "zeroblob(64)",                                  /* TEXT         */
        "UPDATE v2_supply_totals SET utxo_total = NULL WHERE token_id = "
        "zeroblob(64)",                                  /* NULL (the    *
                                                          * column is NOT *
                                                          * NULL: this   *
                                                          * statement    *
                                                          * must fail)   */
        "UPDATE v2_supply_totals SET utxo_total = -1 WHERE token_id = "
        "zeroblob(64)",                                  /* negative     */
        "DELETE FROM v2_supply_totals WHERE token_id = zeroblob(64)"
                                                         /* absent       */
    };
    for (size_t i = 0; i < sizeof(bad_native) / sizeof(bad_native[0]); i++) {
        int applied = run_sql(db, bad_native[i]) == 0;
        if (i == 2) {
            CHECK(!applied, "D3: a NULL total cannot even be stored");
            continue;
        }
        CHECK(applied, "D3: corrupt the native total");
        CHECK(nodus_witness_v2_supply_check(c->w) != 0,
              "D3: a malformed native total fails closed");
        CHECK(nodus_witness_db_s20_reseed(c->w) == 0 &&
              nodus_witness_v2_supply_check(c->w) == 0,
              "D3: restored by the re-seed");
    }
    static const char *const bad_bond[] = {
        "UPDATE v2_bond_total SET total = 0.5",
        "UPDATE v2_bond_total SET total = 'x'",
        "UPDATE v2_bond_total SET total = -3",
        "DELETE FROM v2_bond_total"
    };
    for (size_t i = 0; i < sizeof(bad_bond) / sizeof(bad_bond[0]); i++) {
        CHECK(run_sql(db, bad_bond[i]) == 0, "D4: corrupt the bond total");
        CHECK(nodus_witness_v2_supply_check(c->w) != 0,
              "D4: a malformed bond total fails closed");
        CHECK(nodus_witness_db_s20_reseed(c->w) == 0 &&
              nodus_witness_v2_supply_check(c->w) == 0,
              "D4: restored by the re-seed");
    }

    /* an integer sum past INT64_MAX turns REAL inside SQLite: the trigger
     * itself must not wrap, and the check refuses the REAL */
    CHECK(run_sql(db, "UPDATE v2_supply_totals SET utxo_total = "
                      "9223372036854775807 WHERE token_id = zeroblob(64)")
          == 0, "D5: native total at INT64_MAX");
    CHECK(put_utxo(db, 0xE1, 0, 1) == 0, "D5: one more unit");
    CHECK(q1(db, "SELECT typeof(utxo_total) = 'real' FROM "
                 "v2_supply_totals WHERE token_id = zeroblob(64)") == 1,
          "D5: the overflowed sum is stored as REAL, not wrapped");
    CHECK(nodus_witness_v2_supply_check(c->w) != 0,
          "D5: the check refuses an overflowed total");
    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE nullifier = "
                      "CAST(zeroblob(63)||x'e1' AS BLOB)") == 0 &&
          nodus_witness_db_s20_reseed(c->w) == 0 &&
          nodus_witness_v2_supply_check(c->w) == 0, "D5: restored");
    return 0;
}

/* ── E. the ownership guard (HF-9 amendment 2026-11-05, T-17a-d) ───────── */

/* the stored sqlite_master.sql SQLite keeps for the index of the amendment
 * (A4.1, measured on 3.40.1: the IF NOT EXISTS is not stored) */
#define FOREIGN_IDX_SQL \
    "CREATE INDEX idx_utxo_foreign ON utxo_set(domain_id) WHERE " \
    "domain_id != 1"

/* the guard's statement text, the oracle with the index made unusable by
 * the unary plus (a full scan: today's behaviour) */
#define ORACLE_SQL \
    "SELECT COUNT(*) FROM utxo_set WHERE +domain_id != 1"

/* 1 = the index exists, its stored text copied to `out`; 0 = absent */
static int foreign_idx_sql(sqlite3 *db, char *out, size_t cap) {
    sqlite3_stmt *st = NULL;
    int r = -1;
    if (sqlite3_prepare_v2(db, "SELECT sql FROM sqlite_master WHERE "
            "type='index' AND name='idx_utxo_foreign'", -1, &st, NULL)
        != SQLITE_OK) return -1;
    int s = sqlite3_step(st);
    if (s == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        snprintf(out, cap, "%s", t ? t : "");
        r = 1;
    } else if (s == SQLITE_DONE) {
        out[0] = 0;
        r = 0;
    }
    sqlite3_finalize(st);
    return r;
}

static int foreign_idx_exact(sqlite3 *db) {
    char sql[256];
    return foreign_idx_sql(db, sql, sizeof(sql)) == 1 &&
           strcmp(sql, FOREIGN_IDX_SQL) == 0;
}

/* all `detail` lines of EXPLAIN QUERY PLAN <sql>, one per line, into out;
 * *nrows = the number of plan rows; 0 / -1 */
static int plan_text(sqlite3 *db, const char *sql, char *out, size_t cap,
                     int *nrows) {
    char eqp[1536];
    sqlite3_stmt *st = NULL;
    int n = snprintf(eqp, sizeof(eqp), "EXPLAIN QUERY PLAN %s", sql);
    if (n <= 0 || (size_t)n >= sizeof(eqp)) return -1;
    if (sqlite3_prepare_v2(db, eqp, -1, &st, NULL) != SQLITE_OK) return -1;
    size_t len = 0;
    int rows = 0, rc;
    out[0] = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *d = (const char *)sqlite3_column_text(st, 3);
        int w = snprintf(out + len, cap - len, "%s\n", d ? d : "");
        if (w < 0 || (size_t)w >= cap - len) { sqlite3_finalize(st); return -1; }
        len += (size_t)w;
        rows++;
    }
    sqlite3_finalize(st);
    *nrows = rows;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* VM steps of one full run of `sql` (no parameters), -1 on a fault */
static sqlite3_int64 stmt_steps(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { }
    sqlite3_int64 n = rc == SQLITE_DONE ?
        (sqlite3_int64)sqlite3_stmt_status(st, SQLITE_STMTSTATUS_VM_STEP, 0)
        : -1;
    sqlite3_finalize(st);
    return n;
}

/* the statement the production guard runs, captured from the real call */
typedef struct { char sql[256]; int hits; } guard_trace_t;

static int guard_trace_cb(unsigned mask, void *ctx, void *p, void *x) {
    static const char prefix[] = "SELECT COUNT(*) FROM utxo_set WHERE domain_id";
    guard_trace_t *g = ctx;
    (void)p;
    if (mask == SQLITE_TRACE_STMT && x &&
        strncmp((const char *)x, prefix, sizeof(prefix) - 1) == 0) {
        if (g->hits == 0) snprintf(g->sql, sizeof(g->sql), "%s", (const char *)x);
        g->hits++;
    }
    return 0;
}

/* one real nodus_witness_v2_supply_check, its guard statement captured;
 * returns the check's verdict, or -2 if the capture is not exactly one */
static int capture_guard(nodus_witness_t *w, guard_trace_t *g) {
    memset(g, 0, sizeof(*g));
    if (sqlite3_trace_v2(w->db, SQLITE_TRACE_STMT, guard_trace_cb, g) != SQLITE_OK)
        return -2;
    int rc = nodus_witness_v2_supply_check(w);
    sqlite3_trace_v2(w->db, 0, NULL, NULL);
    return g->hits == 1 ? rc : -2;
}

/* a conserving (amount 0) row of `domain` with nullifier = 64 ASCII digits
 * of `i` - a state no writer produces (outputs are >= 1); the guard's cost
 * depends on the row count only */
static int plant_rows(sqlite3 *db, int first, int last, int domain) {
    char sql[900];
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE c(i) AS (SELECT %d UNION ALL SELECT i + 1 FROM c "
        "WHERE i < %d) INSERT INTO utxo_set (nullifier, owner, amount, "
        "token_id, tx_hash, output_index, block_height, created_at, "
        "unlock_block, domain_id) SELECT CAST(printf('%%064d', i) AS BLOB), "
        "'plant', 0, zeroblob(64), zeroblob(64), 0, 0, 0, 0, %d FROM c",
        first, last, domain);
    return run_sql(db, sql);
}

/* The derived chain has NO utxo_set row (v2_genesis_fixture.h: "This seeded
 * path writes NO genesis outputs", asserted by v2x_seed_genesis, :945), so a
 * test that rewrites "an existing row" plants one first: a conserving CORE
 * row (amount 0, domain 1), owner 'one', removed again by drop_one_row. */
static int plant_one_row(nodus_witness_t *w) {
    CHECK(nodus_witness_v2_supply_check(w) == 0,
          "E: baseline passes before the row is planted");
    CHECK(run_sql(w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, tx_hash, "
        "output_index, block_height, created_at, unlock_block, domain_id) "
        "VALUES (CAST(zeroblob(63)||x'e0' AS BLOB), 'one', 0, zeroblob(64), "
        "zeroblob(64), 0, 0, 0, 0, 1)") == 0, "E: plant one CORE row");
    CHECK(q1(w->db, "SELECT COUNT(*) FROM utxo_set") == 1 &&
          nodus_witness_v2_supply_check(w) == 0,
          "E: the planted row is the only one and the baseline still passes");
    return 0;
}

static int drop_one_row(nodus_witness_t *w) {
    CHECK(run_sql(w->db, "DELETE FROM utxo_set WHERE owner = 'one'") == 0 &&
          q1(w->db, "SELECT COUNT(*) FROM utxo_set") == 0 &&
          nodus_witness_v2_supply_check(w) == 0,
          "E: the planted row is removed, the chain balances");
    return 0;
}

/* the verdict table, one value: baseline passes, one existing row gets
 * `lit` as its domain_id (amount and token unchanged: the S20 totals do
 * not move, the guard is the only term that can fail), the check must
 * equal the full-scan oracle, the restore must pass again */
static int verdict_case(nodus_witness_t *w, const char *lit,
                        int expect_foreign) {
    sqlite3 *db = w->db;
    char sql[400];
    static const char *const row =
        "(SELECT nullifier FROM utxo_set ORDER BY nullifier LIMIT 1)";
    CHECK(nodus_witness_v2_supply_check(w) == 0, "T-17a: baseline passes");
    snprintf(sql, sizeof(sql), "UPDATE utxo_set SET domain_id = %s WHERE "
             "nullifier = %s", lit, row);
    CHECK(run_sql(db, sql) == 0, "T-17a: write the value");
    sqlite3_int64 o = q1(db, ORACLE_SQL);
    CHECK(o >= 0, "T-17a: the oracle runs");
    CHECK((o > 0) == (expect_foreign != 0),
          "T-17a: the value is foreign / converted as the table says");
    int r = nodus_witness_v2_supply_check(w);
    CHECK(o > 0 ? r == -1 : r == 0,
          "T-17a: the check equals the full-scan oracle");
    snprintf(sql, sizeof(sql), "UPDATE utxo_set SET domain_id = 1 WHERE "
             "nullifier = %s", row);
    CHECK(run_sql(db, sql) == 0, "T-17a: restore");
    CHECK(q1(db, ORACLE_SQL) == 0 && nodus_witness_v2_supply_check(w) == 0,
          "T-17a: after the restore the check passes again");
    return 0;
}

static int verdict_table(nodus_witness_t *w) {
    sqlite3 *db = w->db;
    static const char *const foreign[] = {
        "0", "2", "-1", "9223372036854775807", "-9223372036854775808",
        "1.5", "0.9999999999999999", "1e300", "'abc'", "''", "X'01'"
    };
    static const char *const converts[] = { "'1'", "' 1'", "'1.0'", "1.0" };
    CHECK(q1(db, "SELECT COUNT(*) FROM utxo_set") > 0,
          "T-17a: the chain has a row to rewrite");
    for (size_t i = 0; i < sizeof(foreign) / sizeof(foreign[0]); i++)
        if (verdict_case(w, foreign[i], 1)) return 1;
    for (size_t i = 0; i < sizeof(converts) / sizeof(converts[0]); i++)
        if (verdict_case(w, converts[i], 0)) return 1;

    /* conserving foreign rows (amount 0): inserted, deleted */
    static const char *const ins =
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) VALUES (CAST(zeroblob(63)||x'%02x' AS BLOB), 'f', 0, "
        "zeroblob(64), zeroblob(64), 0, 0, 0, 0, 2)";
    char sql[400];
    CHECK(nodus_witness_v2_supply_check(w) == 0, "T-17a: baseline");
    snprintf(sql, sizeof(sql), ins, 0xF1);
    CHECK(run_sql(db, sql) == 0, "T-17a: insert a foreign row");
    CHECK(nodus_witness_v2_supply_check(w) == -1, "T-17a: one foreign row");
    snprintf(sql, sizeof(sql), ins, 0xF2);
    CHECK(run_sql(db, sql) == 0, "T-17a: insert a second foreign row");
    CHECK(nodus_witness_v2_supply_check(w) == -1, "T-17a: two foreign rows");
    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE nullifier = "
                      "CAST(zeroblob(63)||x'f1' AS BLOB)") == 0,
          "T-17a: delete one");
    CHECK(q1(db, ORACLE_SQL) == 1 && nodus_witness_v2_supply_check(w) == -1,
          "T-17a: one foreign row is left");
    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE nullifier = "
                      "CAST(zeroblob(63)||x'f2' AS BLOB)") == 0,
          "T-17a: delete the other");
    CHECK(q1(db, ORACLE_SQL) == 0 && nodus_witness_v2_supply_check(w) == 0,
          "T-17a: no foreign row, the check passes");
    return 0;
}

/* T-17a: with the index, then with the index dropped (a plain scan) */
static int test_guard_verdicts(v2x_chain_t *c) {
    sqlite3 *db = c->w->db;
    CHECK(foreign_idx_exact(db), "T-17a: the index exists to start with");
    if (plant_one_row(c->w)) return 1;
    fprintf(stderr, "T-17a: verdict table with idx_utxo_foreign\n");
    if (verdict_table(c->w)) return 1;

    CHECK(run_sql(db, "DROP INDEX idx_utxo_foreign") == 0,
          "T-17a: drop the index");
    char sql[256];
    CHECK(foreign_idx_sql(db, sql, sizeof(sql)) == 0,
          "T-17a: the index is gone (the second pass is a scan)");
    fprintf(stderr, "T-17a: verdict table without idx_utxo_foreign\n");
    if (verdict_table(c->w)) return 1;

    CHECK(nodus_witness_db_s20_reseed(c->w) == 0 && foreign_idx_exact(db),
          "T-17a: the re-seed makes the index again");
    return drop_one_row(c->w);
}

/* T-17b: plan pin */
static int test_guard_plan(v2x_chain_t *c) {
    sqlite3 *db = c->w->db;
    guard_trace_t g;
    char plan[1024], with[6][1024], without[6][1024];
    int nrows = -1;
    static const char *const prod[6] = {
        /* S1 rtn point read (nodus_witness_rt_native.c) */
        "SELECT owner, amount, token_id, tx_hash, output_index, "
        "block_height, unlock_block FROM utxo_set "
        "WHERE nullifier = ?1 AND domain_id = ?2",
        /* S2 rtn DELETE */
        "DELETE FROM utxo_set WHERE nullifier = ?1 AND domain_id = ?2",
        /* S3 utxo_by_owner_impl, no token */
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index, "
        "block_height, unlock_block FROM utxo_set WHERE owner = ? AND "
        "domain_id = ? ORDER BY amount DESC, nullifier ASC LIMIT ?",
        /* S4 utxo_by_owner_impl, with token */
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index, "
        "block_height, unlock_block FROM utxo_set WHERE owner = ? AND "
        "domain_id = ? AND token_id = ? ORDER BY amount DESC, nullifier "
        "ASC LIMIT ?",
        /* S5 nodus_witness_utxo_balance_by_owner */
        "SELECT token_id, amount, unlock_block FROM utxo_set "
        "WHERE owner = ?1 AND domain_id = ?2 ORDER BY token_id, nullifier",
        /* S6 msig_utxo_by_nuls */
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index, "
        "block_height, unlock_block FROM utxo_set "
        "WHERE nullifier = ?1 AND owner = ?2 AND domain_id = ?3"
    };

    CHECK(plant_rows(db, 1, 1000, 1) == 0, "T-17b: plant 1000 rows");
    CHECK(foreign_idx_exact(db), "T-17b: the index exists");

    /* the real statement, from a real supply check */
    CHECK(capture_guard(c->w, &g) == 0,
          "T-17b: one real supply check ran exactly one guard statement");
    CHECK(strcmp(g.sql, "SELECT COUNT(*) FROM utxo_set WHERE domain_id != 1")
          == 0, "T-17b: the captured text is the CORE guard");
    CHECK(plan_text(db, g.sql, plan, sizeof(plan), &nrows) == 0 && nrows == 1,
          "T-17b: the guard plan has exactly one row");
    CHECK(strcmp(plan, "SCAN utxo_set USING COVERING INDEX idx_utxo_foreign\n")
          == 0, "T-17b: the guard is served by the partial index");

    for (int i = 0; i < 6; i++)
        CHECK(plan_text(db, prod[i], with[i], sizeof(with[i]), &nrows) == 0 &&
              nrows >= 1 && strstr(with[i], "idx_utxo_foreign") == NULL,
              "T-17b: no other statement uses the index");

    CHECK(run_sql(db, "DROP INDEX idx_utxo_foreign") == 0,
          "T-17b: drop the index");
    CHECK(plan_text(db, g.sql, plan, sizeof(plan), &nrows) == 0 && nrows == 1 &&
          strcmp(plan, "SCAN utxo_set\n") == 0,
          "T-17b: without the index the guard is a scan of utxo_set");
    for (int i = 0; i < 6; i++)
        CHECK(plan_text(db, prod[i], without[i], sizeof(without[i]),
                        &nrows) == 0 && strcmp(with[i], without[i]) == 0,
              "T-17b: the plan of another statement is the same without "
              "the index");
    CHECK(nodus_witness_db_s20_reseed(c->w) == 0 && foreign_idx_exact(db),
          "T-17b: the re-seed makes the index again");

    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE owner = 'plant'") == 0 &&
          nodus_witness_v2_supply_check(c->w) == 0,
          "T-17b: cleanup, the chain balances again");
    return 0;
}

static int ops_cb(void *p) { (*(uint64_t *)p)++; return 0; }

/* the progress handler counts EVERY VM instruction of one whole check */
static int check_ops(nodus_witness_t *w, uint64_t *ops) {
    *ops = 0;
    sqlite3_progress_handler(w->db, 1, ops_cb, ops);
    int rc = nodus_witness_v2_supply_check(w);
    sqlite3_progress_handler(w->db, 0, NULL, NULL);
    return rc;
}

/* T-17c: the guard does not grow with the row count */
static int test_guard_growth(v2x_chain_t *c) {
    sqlite3 *db = c->w->db;
    guard_trace_t g;
    uint64_t ops_small = 0, ops_big = 0;
    CHECK(foreign_idx_exact(db), "T-17c: the index exists");
    CHECK(capture_guard(c->w, &g) == 0, "T-17c: capture the real guard");

    CHECK(plant_rows(db, 1, 100, 1) == 0, "T-17c: plant 100 rows");
    sqlite3_int64 g_small = stmt_steps(db, g.sql);
    sqlite3_int64 c_small = stmt_steps(db, ORACLE_SQL);
    CHECK(check_ops(c->w, &ops_small) == 0 && ops_small > 0,
          "T-17c: the whole check passes at 100 rows, counter wired");

    CHECK(plant_rows(db, 101, 100000, 1) == 0, "T-17c: plant to 100 000");
    CHECK(q1(db, "SELECT COUNT(*) FROM utxo_set WHERE owner = 'plant'") ==
          100000, "T-17c: 100 000 planted rows");
    sqlite3_int64 g_big = stmt_steps(db, g.sql);
    sqlite3_int64 c_big = stmt_steps(db, ORACLE_SQL);
    CHECK(check_ops(c->w, &ops_big) == 0 && ops_big > 0,
          "T-17c: the whole check passes at 100 000 rows");

    fprintf(stderr, "T-17c: guard VM steps 1e2: %lld, 1e5: %lld; "
            "+domain_id control 1e2: %lld, 1e5: %lld; whole-check "
            "instructions 1e2: %llu, 1e5: %llu\n",
            (long long)g_small, (long long)g_big, (long long)c_small,
            (long long)c_big, (unsigned long long)ops_small,
            (unsigned long long)ops_big);
    CHECK(g_small > 0 && g_big > 0, "T-17c: the guard steps are counted");
    CHECK(g_small == g_big,
          "T-17c: the guard takes equal VM steps at 100 and 100 000 rows");
    CHECK(c_big >= g_big + 100000,
          "T-17c control: the +domain_id form steps at least one per row "
          "more");
    const uint64_t d = ops_big > ops_small ? ops_big - ops_small
                                           : ops_small - ops_big;
    CHECK(d < (100000u - 100u) / 10u,
          "T-17c: one whole supply check differs by less than a tenth of "
          "one instruction per added row (the G-f rule)");

    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE owner = 'plant'") == 0 &&
          nodus_witness_v2_supply_check(c->w) == 0,
          "T-17c: cleanup, the chain balances again");
    return 0;
}

/* a scratch database at S19 (the rung is not yet run), no genesis */
typedef struct { nodus_witness_t *w; char dir[64]; } s19_scratch_t;

static void s19_close(s19_scratch_t *s) {
    if (!s->w) return;
    if (s->w->db) sqlite3_close(s->w->db);
    free(s->w);
    s->w = NULL;
    if (s->dir[0]) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", s->dir);
        if (system(cmd) != 0) { /* best effort */ }
        s->dir[0] = 0;
    }
}

static int s19_open(s19_scratch_t *s) {
    uint8_t chain16[16];
    memset(s, 0, sizeof(*s));
    s->w = calloc(1, sizeof(*s->w));           /* multi-MB: heap */
    if (!s->w) return -1;
    snprintf(s->dir, sizeof(s->dir), "/tmp/v2x_s20idx_XXXXXX");
    if (!mkdtemp(s->dir)) { s->dir[0] = 0; s19_close(s); return -1; }
    snprintf(s->w->data_path, sizeof(s->w->data_path), "%s", s->dir);
    memset(chain16, 0x23, sizeof(chain16));
    if (nodus_witness_create_chain_db(s->w, chain16) != 0 ||
        nodus_witness_db_migrate_v2s19(s->w) != 0) {
        s19_close(s);
        return -1;
    }
    return 0;
}

/* T-17d: the schema */
static int test_guard_schema(v2x_chain_t *c) {
    char sql[256];
    uint32_t ver = 0;

    /* the rung, on a scratch database at S19 */
    {
        s19_scratch_t s;
        CHECK(s19_open(&s) == 0, "T-17d: scratch database at S19");
        CHECK(foreign_idx_sql(s.w->db, sql, sizeof(sql)) == 0,
              "T-17d: no index before the rung");
        for (int stage = V2S20MIG_FAIL_AFTER_BEGIN;
             stage <= V2S20MIG_FAIL_BEFORE_COMMIT; stage++) {
            CHECK(nodus_witness_db_migrate_v2s20_ex(s.w,
                      (nodus_v2s20_mig_fail_t)stage) == -1,
                  "T-17d: the staged S20 failure fails");
            CHECK(foreign_idx_sql(s.w->db, sql, sizeof(sql)) == 0,
                  "T-17d: a failed S20 stage leaves no idx_utxo_foreign");
            CHECK(nodus_witness_db_schema_version(s.w, &ver) == 0 &&
                  ver == NODUS_V2_SCHEMA_VERSION_S19,
                  "T-17d: a failed S20 stage keeps version 19");
        }
        CHECK(nodus_witness_db_migrate_v2s20(s.w) == 0,
              "T-17d: the rung runs");
        CHECK(foreign_idx_sql(s.w->db, sql, sizeof(sql)) == 1 &&
              strcmp(sql, FOREIGN_IDX_SQL) == 0,
              "T-17d: the rung created the index, stored text exact");
        /* the at-open function re-creates a dropped index */
        CHECK(run_sql(s.w->db, "DROP INDEX idx_utxo_foreign") == 0 &&
              foreign_idx_sql(s.w->db, sql, sizeof(sql)) == 0,
              "T-17d: dropped");
        CHECK(nodus_witness_db_s20_reseed(s.w) == 0 &&
              foreign_idx_exact(s.w->db),
              "T-17d: the at-open function creates it again");
        s19_close(&s);
    }
    /* the rung refuses a same-name index of another definition (the
     * rung's own exact check; the at-open path does not, DF-11) */
    {
        s19_scratch_t s;
        CHECK(s19_open(&s) == 0, "T-17d: second scratch database at S19");
        CHECK(run_sql(s.w->db, "CREATE INDEX idx_utxo_foreign ON "
                               "utxo_set(domain_id)") == 0,
              "T-17d: a same-name index with another definition");
        CHECK(nodus_witness_db_migrate_v2s20(s.w) == -1,
              "T-17d: the rung refuses it");
        CHECK(nodus_witness_db_schema_version(s.w, &ver) == 0 &&
              ver == NODUS_V2_SCHEMA_VERSION_S19,
              "T-17d: the refused rung keeps version 19");
        s19_close(&s);
    }

    /* the production open path, on the real derived chain */
    CHECK(foreign_idx_exact(c->w->db), "T-17d: present on the chain");
    CHECK(run_sql(c->w->db, "DROP INDEX idx_utxo_foreign") == 0 &&
          foreign_idx_sql(c->w->db, sql, sizeof(sql)) == 0,
          "T-17d: dropped on the chain (absent before the reopen)");
    CHECK(reopen(c) == 0, "T-17d: reopen through the production open path");
    CHECK(foreign_idx_exact(c->w->db),
          "T-17d: the open path created the index again");

    /* a same-name index of another definition opens (DF-11) and the guard
     * stays exact with it */
    CHECK(run_sql(c->w->db, "DROP INDEX idx_utxo_foreign; "
                            "CREATE INDEX idx_utxo_foreign ON "
                            "utxo_set(domain_id)") == 0,
          "T-17d: replace it with a plain index");
    CHECK(reopen(c) == 0, "T-17d: a same-name other index opens");
    CHECK(foreign_idx_sql(c->w->db, sql, sizeof(sql)) == 1 &&
          strcmp(sql, "CREATE INDEX idx_utxo_foreign ON utxo_set(domain_id)")
          == 0, "T-17d: the open neither refused nor replaced it");
    if (plant_one_row(c->w)) return 1;
    CHECK(nodus_witness_v2_supply_check(c->w) == 0 &&
          run_sql(c->w->db, "UPDATE utxo_set SET domain_id = 2 WHERE "
                  "nullifier = (SELECT nullifier FROM utxo_set ORDER BY "
                  "nullifier LIMIT 1)") == 0 &&
          nodus_witness_v2_supply_check(c->w) == -1,
          "T-17d: with the other index the guard still catches a foreign row");
    CHECK(run_sql(c->w->db, "UPDATE utxo_set SET domain_id = 1 WHERE "
                  "domain_id = 2") == 0 &&
          run_sql(c->w->db, "DROP INDEX idx_utxo_foreign") == 0,
          "T-17d: undo");
    if (drop_one_row(c->w)) return 1;
    CHECK(reopen(c) == 0 && foreign_idx_exact(c->w->db),
          "T-17d: the exact index is back");
    CHECK(nodus_witness_v2_supply_check(c->w) == 0,
          "T-17d: the chain balances");
    return 0;
}

int main(void) {
    v2x_chain_t c;
    if (v2x_chain_open(&c, "supplytot", 0x5B) != 0) {
        fprintf(stderr, "test_supply_totals: chain fixture failed\n");
        return 1;
    }
    int rc = 0;
    rc = test_triggers(&c);
    if (!rc) rc = test_rollback(&c);
    if (!rc) rc = test_reseed(&c);
    if (!rc) rc = test_invariant(&c);
    if (!rc) rc = test_guard_verdicts(&c);
    if (!rc) rc = test_guard_plan(&c);
    if (!rc) rc = test_guard_growth(&c);
    if (!rc) rc = test_guard_schema(&c);
    v2x_chain_close(&c);
    if (rc) {
        fprintf(stderr, "test_supply_totals: FAILED\n");
        return 1;
    }
    printf("test_supply_totals: %d checks passed\n", g_checks);
    return 0;
}
