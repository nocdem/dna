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
 *
 * ── FLAGS ───────────────────────────────────────────────────────────────
 *  Compiled by register_witness_test (NODUS_WITNESS_INTERNAL_API); no
 *  fault injection, no -DDNAC_EPOCH_LENGTH, no environment.
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 *  Directories /tmp/v2x_supplytot_XXXXXX, removed by v2x_chain_close (a
 *  crash leaves one).
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
    v2x_chain_close(&c);
    if (rc) {
        fprintf(stderr, "test_supply_totals: FAILED\n");
        return 1;
    }
    printf("test_supply_totals: %d checks passed\n", g_checks);
    return 0;
}
