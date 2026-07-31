/**
 * Nodus — validator-scan fail-close tests (F1a)
 *
 * nodus_witness_record_attendance (nodus_witness_bft.c) is a PRODUCER of
 * the rows state_root is built from. It walked the `validators` table
 * with `while (sqlite3_step(...) == SQLITE_ROW)` and threw the step
 * result away, so a mid-scan SQLITE_IOERR / SQLITE_BUSY /
 * SQLITE_CORRUPT was converted into a legitimate-looking value and
 * reported as SUCCESS: a dead scan left `matched == false`, read as
 * "the proposer is not a known validator", so the function returned 0,
 * commit_batch's rollback never fired, and last_signed_block /
 * signed_blocks_this_epoch did not advance on THIS node while every
 * peer advanced them. Both columns are hashed into the validator leaf
 * (preimage nodus_witness_merkle.c:895-896, digested at :1062-1065) —
 * a permanent validator_root / state_root fork with no Byzantine actor.
 *
 * ── PARKED: the same defect in nodus_validator_top_n (F2) ───────────
 *
 * nodus_validator_top_n (nodus_witness_validator.c:322) has the
 * identical dead-scan bug: a short candidate list indistinguishable
 * from "there were only that many validators". The guard for it was
 * written and then REVERTED, and the two tests that asserted it (a
 * fault-injection case and its non-vacuity twin) were removed with it.
 * The guard is not wrong — its CONSUMERS are not ready for a -1, and
 * two of the three make the -1 worse than the truncation it replaces:
 *
 *   1. It OPENS THE VOTE GATE. nodus_witness_bft.c:4431-4443 reads
 *      `if (load_committee_at_height(...) == 0 && count > 0) { …
 *      committee_find_pubkey … }`, with a trailing "else: pre-genesis,
 *      gossip_idx check above is sufficient". On -1 the membership
 *      check is SKIPPED, so on a live post-genesis chain any
 *      gossip-roster peer's vote is counted. Pre-fix a truncated
 *      committee rejected legitimate members; post-fix the -1 admits
 *      illegitimate ones. Five further sites share the
 *      `== 0 && count > 0` idiom (leader selection, proposal check,
 *      VIEW_CHANGE and NEW_VIEW gates).
 *   2. One TRANSIENT error LATCHES A PERMANENT HALT.
 *      nodus_witness_bft.c:6234-6241 — a post-commit
 *      refresh_bft_config_from_committee failure sets
 *      w->safety_halt = true, and halt_auto_recover defaults off.
 *   3. nodus_witness_epoch.c:275-282 SWALLOWS the -1 and hashes the
 *      canonical EMPTY snapshot, so the divergent block still commits —
 *      the snapshot_hash → state_root chain is interrupted there.
 *
 * Deciding what the vote gate, leader selection and the epoch boundary
 * each do on a DB error is a consensus design decision, scoped as its
 * own work. B1-B3 below survive as healthy-path characterisation, and
 * B3 carries the written-out `LIMIT ?` / `count < n` analysis the guard
 * rests on — including an explicit note on what that test can and
 * cannot prove while top_n stays unguarded — so the next author does
 * not have to re-derive it.
 *
 * ── THE F1a TRAP, which these tests exist to pin ────────────────────
 *
 * record_attendance BREAKS out of its loop on a hit, so on the SUCCESS
 * path the terminal step code is SQLITE_ROW, not SQLITE_DONE. A naive
 * `if (rc != SQLITE_DONE) return -1;` would reject EVERY honest block
 * on EVERY node. The guard is therefore `!matched && rc != SQLITE_DONE`
 * — "the loop was not terminated by our own break". A1 and A5 below
 * both fail under the naive form and pass under the correct one.
 *
 * ── Fault injection ─────────────────────────────────────────────────
 *
 * Purely structural — no sleeps, no timing, no randomness (flaky tests
 * are forbidden project-wide). Technique reused verbatim from
 * test_merkle_scan_fail_close.c: the scanned `validators` relation is a
 * VIEW over a raw table, and one flagged row projects
 * abs(-9223372036854775808), which has no int64 result and which SQLite
 * raises as "integer overflow" at step time, per row.
 *
 * record_attendance's SELECT has no ORDER BY, so the scan streams in
 * rowid order and the error lands mid-walk — rows before it are
 * returned first, which is what makes A5's "break before the poison"
 * case constructible at all (see A5's own note on that dependency).
 *
 * The poisoned column MUST be one the function under test actually
 * SELECTs, or SQLite flattens the view, drops the unused expression,
 * and no error is ever raised. record_attendance selects only
 * (pubkey, last_signed_block), so these fixtures poison
 * last_signed_block.
 *
 * Every fault case is paired with a NON-VACUITY twin: the identical
 * fixture with the fault disabled must still succeed, so a failure can
 * only come from the injected fault and not from the fixture.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_validator.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "nodus/nodus_types.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-58s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* SQL expression that raises SQLITE_ERROR ("integer overflow") when the
 * row is stepped over. abs() of the most negative int64 has no int64
 * result, and SQLite reports that at step time, per row. */
#define OVERFLOW_EXPR "abs(-9223372036854775808)"

#define FIXTURE_ROWS 4

/* nodus_witness_t is multi-MB — always heap-allocate the fixture. */
static nodus_witness_t *witness_new(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) {
        sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

static void witness_free(nodus_witness_t *w) {
    if (!w) return;
    sqlite3_close(w->db);
    free(w);
}

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql error: %s\n  in: %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ── Fixtures ──────────────────────────────────────────────────────── */

/* Row i (1-based) carries a pubkey of DNAC_PUBKEY_SIZE bytes all equal
 * to (uint8_t)i. 0x99 is deliberately NOT used by any row, so a
 * proposer_id derived from it is a validator the table does not hold. */
static void fixture_pubkey(int i, uint8_t out[DNAC_PUBKEY_SIZE]) {
    memset(out, (uint8_t)i, DNAC_PUBKEY_SIZE);
}

/* proposer_id = first NODUS_T3_WITNESS_ID_LEN bytes of
 * SHA3-512(pubkey) — the derivation record_attendance matches against
 * (nodus_witness_bft.c, inside the scan loop). */
static void fixture_proposer_id(int i, uint8_t out[NODUS_T3_WITNESS_ID_LEN]) {
    uint8_t pk[DNAC_PUBKEY_SIZE];
    uint8_t digest[64];
    fixture_pubkey(i, pk);
    qgp_sha3_512(pk, DNAC_PUBKEY_SIZE, digest);
    memcpy(out, digest, NODUS_T3_WITNESS_ID_LEN);
}

static const char *VALIDATOR_COLUMNS =
    "  pubkey BLOB PRIMARY KEY,"
    "  self_stake INTEGER NOT NULL,"
    "  total_delegated INTEGER NOT NULL,"
    "  external_delegated INTEGER NOT NULL,"
    "  commission_bps INTEGER NOT NULL,"
    "  pending_commission_bps INTEGER NOT NULL,"
    "  pending_effective_block INTEGER NOT NULL,"
    "  status INTEGER NOT NULL,"
    "  active_since_block INTEGER NOT NULL,"
    "  unstake_commit_block INTEGER NOT NULL,"
    "  unstake_destination_fp TEXT NOT NULL,"
    "  unstake_destination_pubkey BLOB NOT NULL,"
    "  last_validator_update_block INTEGER NOT NULL,"
    "  consecutive_missed_epochs INTEGER NOT NULL,"
    "  last_signed_block INTEGER NOT NULL,"
    "  signed_blocks_this_epoch INTEGER NOT NULL";

/* Insert `rows` validator rows into `table`.
 *
 *   status              — DNAC_VALIDATOR_ACTIVE for the top_n cases,
 *                         which filter on it; record_attendance accepts
 *                         ACTIVE and RETIRING alike.
 *   last_signed_seed    — row i gets last_signed_block = i * seed, so
 *                         A5 can place a row whose watermark is already
 *                         ahead of the block being credited.
 *   has_bad / bad_row   — the step-error flag column, view fixture only.
 */
static int insert_rows(nodus_witness_t *w, const char *table, int rows,
                       int status, uint64_t last_signed_seed,
                       int has_bad, int bad_row) {
    for (int i = 1; i <= rows; i++) {
        uint8_t pubkey[DNAC_PUBKEY_SIZE];
        fixture_pubkey(i, pubkey);

        char sql[768];
        snprintf(sql, sizeof(sql),
            "INSERT INTO %s (pubkey, self_stake, total_delegated,"
            " external_delegated, commission_bps, pending_commission_bps,"
            " pending_effective_block, status, active_since_block,"
            " unstake_commit_block, unstake_destination_fp,"
            " unstake_destination_pubkey, last_validator_update_block,"
            " consecutive_missed_epochs, last_signed_block,"
            " signed_blocks_this_epoch%s)"
            " VALUES (?, ?, 0, 0, 100, 0, 0, ?, 1, 0, 'fp', ?, 0, 0, ?, 0%s)",
            table, has_bad ? ", bad" : "", has_bad ? ", ?" : "");

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob (stmt, 1, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
        /* Distinct stakes so the ORDER BY is a total order — no tie
         * breaking, hence no ordering ambiguity in the count checks. */
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(i * 1000));
        sqlite3_bind_int  (stmt, 3, status);
        sqlite3_bind_blob (stmt, 4, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 5,
                           (sqlite3_int64)((uint64_t)i * last_signed_seed));
        if (has_bad) sqlite3_bind_int(stmt, 6, (i == bad_row) ? 1 : 0);

        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* Real, writable `validators` table. */
static int table_fixture(nodus_witness_t *w, int rows, int status,
                         uint64_t last_signed_seed) {
    char sql[2048];
    snprintf(sql, sizeof(sql), "CREATE TABLE validators (%s);",
             VALIDATOR_COLUMNS);
    if (exec_sql(w, sql) != 0) return -1;
    return insert_rows(w, "validators", rows, status, last_signed_seed, 0, 0);
}

/* `validators` as a VIEW over validators_raw, with the step-error
 * expression projected into ONE column.
 *
 * `poison_col` names the column the CASE replaces. It MUST be a column
 * the function under test actually SELECTs, otherwise SQLite flattens
 * the view and drops the unused expression — no error is ever raised.
 * record_attendance selects (pubkey, last_signed_block); top_n selects
 * all 16, so any of them works there. */
static int view_fixture(nodus_witness_t *w, int rows, int status,
                        uint64_t last_signed_seed,
                        const char *poison_col, int bad_row) {
    char sql[2048];
    snprintf(sql, sizeof(sql),
             "CREATE TABLE validators_raw (%s, bad INTEGER NOT NULL "
             "DEFAULT 0);", VALIDATOR_COLUMNS);
    if (exec_sql(w, sql) != 0) return -1;

    /* Name every column explicitly and swap only `poison_col`, so the
     * view's column ORDER matches the base table (and therefore the
     * column indices both functions read). */
    static const char *cols[16] = {
        "pubkey", "self_stake", "total_delegated", "external_delegated",
        "commission_bps", "pending_commission_bps",
        "pending_effective_block", "status", "active_since_block",
        "unstake_commit_block", "unstake_destination_fp",
        "unstake_destination_pubkey", "last_validator_update_block",
        "consecutive_missed_epochs", "last_signed_block",
        "signed_blocks_this_epoch"
    };

    char select[2048];
    size_t off = 0;
    int n = snprintf(select, sizeof(select), "CREATE VIEW validators AS SELECT");
    if (n < 0 || (size_t)n >= sizeof(select)) return -1;
    off = (size_t)n;

    int found = 0;
    for (int i = 0; i < 16; i++) {
        const char *sep = (i == 0) ? " " : ", ";
        if (strcmp(cols[i], poison_col) == 0) {
            found = 1;
            n = snprintf(select + off, sizeof(select) - off,
                         "%sCASE WHEN bad = 1 THEN " OVERFLOW_EXPR
                         " ELSE %s END AS %s", sep, cols[i], cols[i]);
        } else {
            n = snprintf(select + off, sizeof(select) - off,
                         "%s%s", sep, cols[i]);
        }
        if (n < 0 || (size_t)n >= sizeof(select) - off) return -1;
        off += (size_t)n;
    }
    if (!found) {
        fprintf(stderr, "view_fixture: unknown poison column '%s'\n",
                poison_col);
        return -1;
    }
    n = snprintf(select + off, sizeof(select) - off, " FROM validators_raw;");
    if (n < 0 || (size_t)n >= sizeof(select) - off) return -1;

    if (exec_sql(w, select) != 0) return -1;
    return insert_rows(w, "validators_raw", rows, status, last_signed_seed,
                       1, bad_row);
}

/* Read back one row's attendance counters from the real table. */
static int read_counters(nodus_witness_t *w, int row,
                         uint64_t *last_signed, uint64_t *signed_epoch) {
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    fixture_pubkey(row, pubkey);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db,
        "SELECT last_signed_block, signed_blocks_this_epoch FROM validators "
        "WHERE pubkey = ?", -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return -1; }
    *last_signed  = (uint64_t)sqlite3_column_int64(stmt, 0);
    *signed_epoch = (uint64_t)sqlite3_column_int64(stmt, 1);
    sqlite3_finalize(stmt);
    return 0;
}

/* ── F1a: nodus_witness_record_attendance ──────────────────────────── */

/* A1 — NON-VACUITY + TRAP GUARD. A clean table credits the proposer and
 * returns 0. The match is on row 2, so the loop BREAKS and the terminal
 * step code is SQLITE_ROW: a naive `rc != SQLITE_DONE` guard fails this
 * case, which is precisely why the shipped guard is `!matched && ...`. */
static void t_attendance_clean_credits(void) {
    TEST("A1 clean table credits the proposer (rc==ROW on break)");
    nodus_witness_t *w = witness_new();
    if (!w || table_fixture(w, FIXTURE_ROWS, DNAC_VALIDATOR_ACTIVE, 0) != 0) {
        FAIL("fixture"); witness_free(w); return;
    }

    uint8_t pid[NODUS_T3_WITNESS_ID_LEN];
    fixture_proposer_id(2, pid);

    int rc = nodus_witness_record_attendance(w, 5, pid);
    if (rc != 0) { FAIL("expected 0"); witness_free(w); return; }

    uint64_t last_signed = 0, signed_epoch = 0;
    if (read_counters(w, 2, &last_signed, &signed_epoch) != 0) {
        FAIL("readback"); witness_free(w); return;
    }
    if (last_signed != 5 || signed_epoch != 1) {
        FAIL("proposer not credited"); witness_free(w); return;
    }

    /* A non-proposer row must be untouched. */
    if (read_counters(w, 3, &last_signed, &signed_epoch) != 0 ||
        last_signed != 0 || signed_epoch != 0) {
        FAIL("non-proposer row mutated"); witness_free(w); return;
    }
    PASS();
    witness_free(w);
}

/* A2 — the LEGITIMATE !matched case. The proposer genuinely is not in
 * the table, the scan runs to exhaustion (SQLITE_DONE) and that is a
 * FACT, not a failure: still 0, still no mutation. This is the
 * regression guard for over-rejecting. */
static void t_attendance_absent_proposer_ok(void) {
    TEST("A2 absent proposer on a healthy table still returns 0");
    nodus_witness_t *w = witness_new();
    if (!w || table_fixture(w, FIXTURE_ROWS, DNAC_VALIDATOR_ACTIVE, 0) != 0) {
        FAIL("fixture"); witness_free(w); return;
    }

    uint8_t pid[NODUS_T3_WITNESS_ID_LEN];
    fixture_proposer_id(0x99, pid);   /* 0x99 is in no row */

    int rc = nodus_witness_record_attendance(w, 5, pid);
    if (rc != 0) { FAIL("expected 0"); witness_free(w); return; }

    for (int i = 1; i <= FIXTURE_ROWS; i++) {
        uint64_t last_signed = 0, signed_epoch = 0;
        if (read_counters(w, i, &last_signed, &signed_epoch) != 0 ||
            last_signed != 0 || signed_epoch != 0) {
            FAIL("row mutated"); witness_free(w); return;
        }
    }
    PASS();
    witness_free(w);
}

/* A3 — THE FIX. A mid-scan step error with no match found must NOT be
 * reported as "proposer is not a validator". Before F1a this returned
 * 0, commit_batch committed the block, and this node's validator
 * counters silently diverged from its peers'. */
static void t_attendance_scan_error_rejects(void) {
    TEST("A3 mid-scan step error rejects (no silent 'not a validator')");
    nodus_witness_t *w = witness_new();
    if (!w || view_fixture(w, FIXTURE_ROWS, DNAC_VALIDATOR_ACTIVE, 0,
                           "last_signed_block", 3) != 0) {
        FAIL("fixture"); witness_free(w); return;
    }

    uint8_t pid[NODUS_T3_WITNESS_ID_LEN];
    fixture_proposer_id(0x99, pid);   /* never matches → scan runs on */

    if (nodus_witness_record_attendance(w, 5, pid) == 0)
        FAIL("returned success on a dead scan");
    else
        PASS();
    witness_free(w);
}

/* A4 — NON-VACUITY twin of A3: the identical view with the fault
 * disabled must still return 0, so A3's failure can only come from the
 * injected error. */
static void t_attendance_view_clean_ok(void) {
    TEST("A4 same view, fault disabled, still returns 0");
    nodus_witness_t *w = witness_new();
    if (!w || view_fixture(w, FIXTURE_ROWS, DNAC_VALIDATOR_ACTIVE, 0,
                           "last_signed_block", 0) != 0) {
        FAIL("fixture"); witness_free(w); return;
    }

    uint8_t pid[NODUS_T3_WITNESS_ID_LEN];
    fixture_proposer_id(0x99, pid);

    if (nodus_witness_record_attendance(w, 5, pid) != 0)
        FAIL("expected 0");
    else
        PASS();
    witness_free(w);
}

/* A5 — TRAP GUARD, second form. The poisoned row is row 3, but the
 * proposer matches row 1, so the break happens BEFORE the scan ever
 * reaches the error. The block must still be accepted. Row 1's
 * last_signed_block is seeded to 100 (seed 100 × row 1) so the
 * monotonic guard returns 0 before any UPDATE — the view is read-only,
 * and this test is about the scan, not the write.
 *
 * IMPLICIT DEPENDENCY, stated so a future failure is diagnosable rather
 * than mysterious: "row 1 is reached before row 3" rests on SCAN ORDER,
 * and record_attendance's SELECT carries no ORDER BY. It is
 * deterministic today for two independent reasons — a full table scan
 * returns rowid order, which is insertion order here, and the implicit
 * sqlite_autoindex on the pubkey PRIMARY KEY would give the same order
 * anyway because the fixture's pubkeys are memset(pk, i, …) and so sort
 * bytewise by i. If a future SQLite planner change or an added index
 * reversed the walk, A5 would go red by reaching the poison first: that
 * is a FIXTURE fault, not a regression in the guard. A3 (which never
 * matches, so the scan order cannot matter) is the order-independent
 * half of the pair. */
static void t_attendance_error_after_break_ok(void) {
    TEST("A5 error in a row the break never reaches must not reject");
    nodus_witness_t *w = witness_new();
    if (!w || view_fixture(w, FIXTURE_ROWS, DNAC_VALIDATOR_ACTIVE, 100,
                           "last_signed_block", 3) != 0) {
        FAIL("fixture"); witness_free(w); return;
    }

    uint8_t pid[NODUS_T3_WITNESS_ID_LEN];
    fixture_proposer_id(1, pid);      /* row 1, last_signed_block = 100 */

    /* block_height 5 <= 100 → monotonic guard, returns 0 without the
     * UPDATE. Under a naive `rc != SQLITE_DONE` guard this would be -1. */
    if (nodus_witness_record_attendance(w, 5, pid) != 0)
        FAIL("rejected a block whose scan broke before the error");
    else
        PASS();
    witness_free(w);
}

/* ── nodus_validator_top_n — healthy-path characterisation ──────────
 *
 * The F2 fail-close guard is PARKED (header). These three assert only
 * what top_n does TODAY, unmodified, and they hold either way: none of
 * them injects a fault, so none of them changes verdict when the guard
 * eventually lands. B3 is the one that will become discriminating at
 * that point — read its note for what it does and does NOT prove
 * against the unguarded function. */

/* lookback must satisfy `active_since_block + DNAC_MIN_TENURE_BLOCKS <=
 * lookback`; the fixtures use active_since_block = 1. */
#define TOPN_LOOKBACK ((uint64_t)DNAC_MIN_TENURE_BLOCKS + 1000)

static void t_topn_healthy(void) {
    TEST("B1 healthy table returns 0 with the full count");
    nodus_witness_t *w = witness_new();
    dnac_validator_record_t *out = calloc(16, sizeof(*out));
    if (!w || !out ||
        table_fixture(w, FIXTURE_ROWS, DNAC_VALIDATOR_ACTIVE, 0) != 0) {
        FAIL("fixture"); free(out); witness_free(w); return;
    }

    int count = -1;
    int rc = nodus_validator_top_n(w, 16, TOPN_LOOKBACK, out, &count);
    if (rc != 0 || count != FIXTURE_ROWS)
        FAIL("expected 0 with 4 candidates");
    else
        PASS();
    free(out);
    witness_free(w);
}

/* B2 — fewer rows than requested is a FACT, not a truncation. */
static void t_topn_fewer_than_n(void) {
    TEST("B2 fewer validators than n still succeeds");
    nodus_witness_t *w = witness_new();
    dnac_validator_record_t *out = calloc(16, sizeof(*out));
    if (!w || !out ||
        table_fixture(w, 2, DNAC_VALIDATOR_ACTIVE, 0) != 0) {
        FAIL("fixture"); free(out); witness_free(w); return;
    }

    int count = -1;
    int rc = nodus_validator_top_n(w, 16, TOPN_LOOKBACK, out, &count);
    if (rc != 0 || count != 2)
        FAIL("expected 0 with 2 candidates");
    else
        PASS();
    free(out);
    witness_free(w);
}

/* B3 — the n < table-size case, which is where a future F2 guard is
 * most likely to go wrong.
 *
 * The analysis that guard rests on: the SQL carries `LIMIT ?` bound to
 * n (nodus_witness_validator.c:308, bound at :319), so SQLite caps the
 * result set itself; the step AFTER the n-th row returns SQLITE_DONE,
 * the `count < n` guard never gets to terminate the loop (&& evaluates
 * sqlite3_step first), and a bare `rc != SQLITE_DONE` is therefore
 * correct. Were the LIMIT absent, the loop would exit on `count < n`
 * with rc == SQLITE_ROW and a guarded top_n would return -1 here.
 *
 * HONEST LIMIT of what this test currently observes: against the
 * UNMODIFIED top_n it cannot discriminate those two worlds. Nothing
 * reads the terminal rc today, and `count == 2` is produced either by
 * the LIMIT or by the `count < n` guard — both give the same answer.
 * So B3 pins the OBSERVABLE half (asking for n from a larger table
 * yields exactly n, and success), and stands as the case that will
 * discriminate once a guard lands. It is not, today, evidence that the
 * terminal code is SQLITE_DONE. */
static void t_topn_limit_reached(void) {
    TEST("B3 n < table size ends at SQLITE_DONE (LIMIT analysis)");
    nodus_witness_t *w = witness_new();
    dnac_validator_record_t *out = calloc(16, sizeof(*out));
    if (!w || !out ||
        table_fixture(w, FIXTURE_ROWS, DNAC_VALIDATOR_ACTIVE, 0) != 0) {
        FAIL("fixture"); free(out); witness_free(w); return;
    }

    int count = -1;
    int rc = nodus_validator_top_n(w, 2, TOPN_LOOKBACK, out, &count);
    if (rc != 0 || count != 2)
        FAIL("expected 0 with exactly n candidates");
    else
        PASS();
    free(out);
    witness_free(w);
}

/* B4 / B5 — the two fault-injection cases (mid-scan error rejects, plus
 * its non-vacuity twin) were REMOVED, not forgotten. See the PARKED
 * section of this file's header. */

/* ── main ──────────────────────────────────────────────────────────── */

int main(void) {
    printf("\n=== F1a — nodus_witness_record_attendance scan ===\n");
    t_attendance_clean_credits();
    t_attendance_absent_proposer_ok();
    t_attendance_scan_error_rejects();
    t_attendance_view_clean_ok();
    t_attendance_error_after_break_ok();

    /* Characterisation only — the F2 guard itself is PARKED, see the
     * header. These pin the healthy-path behaviour and the `LIMIT ?`
     * analysis that whoever picks F2 up will need. */
    printf("\n=== nodus_validator_top_n — healthy-path characterisation ===\n");
    t_topn_healthy();
    t_topn_fewer_than_n();
    t_topn_limit_reached();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
