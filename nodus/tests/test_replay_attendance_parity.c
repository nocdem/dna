/**
 * Nodus — replay/live attendance parity at an epoch boundary (O15B.1).
 *
 * THE DEFECT THIS LOCKS OUT
 *
 * `nodus_witness_record_attendance` only matches validators whose status
 * is ACTIVE or RETIRING (nodus_witness_bft.c:3329-3348), and
 * `commit_batch` calls it BEFORE `finalize_block`
 * (nodus_witness_bft.c:6640, the C4 ordering) — so at an epoch boundary
 * it sees the ENDING epoch's statuses. A proposer that was ELIGIBLE in
 * the ending epoch and is flipped to ACTIVE by that same boundary block
 * is therefore given NO credit for it, canonically, on every node:
 * `last_signed_block` keeps its old value.
 *
 * The sync replay path used to make a SECOND record_attendance call for
 * the same height AFTER replay_block had computed, verified and committed
 * that block's state_root. It was believed inert because of the monotonic
 * guard (bft.c:3401, `block_height <= last_signed_block`). At the
 * boundary that guard is wide open — 33 <= 14 is false — so the call
 * fired and wrote `last_signed_block` and `signed_blocks_this_epoch`,
 * both hashed into the validator leaf (nodus_witness_merkle.c:894-896),
 * AFTER the root committing them had been calculated.
 *
 * Observed consequence: a node killed at h=30 re-synced, replayed 31-33
 * with byte-identical state_roots, ended h=33 holding a validator row no
 * live node had, and diverged on the next block —
 * `FATAL: state_root DIVERGED at h=34` — then safety-halted. The halt was
 * correct. The node could never rejoin.
 *
 * WHAT THIS TEST ASSERTS, in the order the boundary block performs it
 *
 *   1. pre-flip, ELIGIBLE proposer at the boundary height: NO credit
 *      (rc == 0, both counters untouched)   <- canonical commit_batch
 *   2. the settlement flip makes it ACTIVE
 *   3. a post-root call at the SAME height now MUTATES both counters
 *      <- this is exactly the removed sync write, and asserting that it
 *         changes state is what makes restoring it a test failure
 *   4. from the canonical post-h33 row, the FIRST valid credit is at
 *      h=34, once the validator is genuinely ACTIVE
 *   5. the monotonic guard still refuses a duplicate at h=34
 *
 * SCOPE, stated rather than implied: this drives the production
 * attendance function directly, which is where the asymmetry lives. It
 * does not carry a 35-block canonical chain, so the state_root half of
 * the parity claim is proven elsewhere and not here — by replaying the
 * frozen canonical chain 1..35 through commit_genesis + replay_block with
 * no post-root writer (every height matched, including 33 and 34), and by
 * the nine-node crash/replay scenario. See nodus/BUGS.md.
 */

/* mkdtemp is POSIX, not ISO C: without this the strict
 * -std=c11 -pedantic build has no declaration for it. */
#define _DEFAULT_SOURCE 1

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "crypto/hash/qgp_sha3.h"
#include "dnac/dnac.h"
#include "dnac/validator.h"     /* DNAC_VALIDATOR_ACTIVE / _ELIGIBLE */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-60s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* Multi-MB — static storage, never the stack. */
static nodus_witness_t w;

static uint8_t g_pubkey[DNAC_PUBKEY_SIZE];
static uint8_t g_proposer_id[NODUS_T3_WITNESS_ID_LEN];

/* The height the boundary block sits at, and the stale watermark the
 * proposer carries into it. Any pair with old_last < boundary reproduces
 * the case; these are the values the live incident showed. */
#define BOUNDARY_H   33
#define NEXT_H       34
#define OLD_LAST     14

static int seed_validator(int status, uint64_t last_signed, uint64_t sbe) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w.db,
            "INSERT OR REPLACE INTO validators "
            "(pubkey_hash, pubkey, self_stake, total_delegated, "
            " external_delegated, commission_bps, status, active_since_block, "
            " unstake_destination_fp, unstake_destination_pubkey, "
            " last_signed_block, signed_blocks_this_epoch) "
            "VALUES (?,?,?,0,0,500,?,1,'',x'',?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;

    uint8_t pkh[64];
    qgp_sha3_512(g_pubkey, sizeof(g_pubkey), pkh);

    sqlite3_bind_blob (st, 1, pkh, 64, SQLITE_STATIC);
    sqlite3_bind_blob (st, 2, g_pubkey, sizeof(g_pubkey), SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, 1000000000000000LL);
    sqlite3_bind_int  (st, 4, status);
    sqlite3_bind_int64(st, 5, (int64_t)last_signed);
    sqlite3_bind_int64(st, 6, (int64_t)sbe);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int read_row(uint64_t *last_out, uint64_t *sbe_out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w.db,
            "SELECT last_signed_block, signed_blocks_this_epoch "
            "FROM validators", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    *last_out = (uint64_t)sqlite3_column_int64(st, 0);
    *sbe_out  = (uint64_t)sqlite3_column_int64(st, 1);
    sqlite3_finalize(st);
    return 0;
}

static int set_status(int status) {
    char sql[128];
    snprintf(sql, sizeof(sql),
             "UPDATE validators SET status = %d", status);
    return sqlite3_exec(w.db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* ── the boundary sequence ──────────────────────────────────────── */

static void test_eligible_proposer_gets_no_credit(void) {
    TEST("boundary block: ELIGIBLE proposer receives NO credit");

    if (seed_validator((int)DNAC_VALIDATOR_ELIGIBLE, OLD_LAST, 0) != 0) {
        FAIL("seed"); return;
    }
    /* Exactly what commit_batch does before finalize_block. */
    if (nodus_witness_record_attendance(&w, BOUNDARY_H, g_proposer_id) != 0) {
        FAIL("record_attendance returned non-zero"); return;
    }
    uint64_t last = 0, sbe = 0;
    if (read_row(&last, &sbe) != 0) { FAIL("read"); return; }
    if (last != OLD_LAST || sbe != 0) {
        char m[128];
        snprintf(m, sizeof(m),
                 "counters moved: last=%llu sbe=%llu (expected %d/0)",
                 (unsigned long long)last, (unsigned long long)sbe, OLD_LAST);
        FAIL(m);
        return;
    }
    PASS();
}

static void test_post_root_call_mutates_committed_state(void) {
    TEST("post-root call at the same height MUTATES committed columns");

    /* State the boundary block leaves behind: the settlement flip has run,
     * so the proposer is ACTIVE, and the canonical counters are still the
     * pre-boundary ones because step 1 declined the credit. */
    if (seed_validator((int)DNAC_VALIDATOR_ELIGIBLE, OLD_LAST, 0) != 0) {
        FAIL("seed"); return;
    }
    if (nodus_witness_record_attendance(&w, BOUNDARY_H, g_proposer_id) != 0) {
        FAIL("pre-flip call"); return;
    }
    if (set_status((int)DNAC_VALIDATOR_ACTIVE) != 0) { FAIL("flip"); return; }

    uint64_t last_before = 0, sbe_before = 0;
    if (read_row(&last_before, &sbe_before) != 0) { FAIL("read"); return; }

    /* The write that used to sit in nodus_witness_sync.c after
     * replay_block had already computed and committed the root. */
    if (nodus_witness_record_attendance(&w, BOUNDARY_H, g_proposer_id) != 0) {
        FAIL("post-root call errored"); return;
    }

    uint64_t last_after = 0, sbe_after = 0;
    if (read_row(&last_after, &sbe_after) != 0) { FAIL("read"); return; }

    /* If this ever stops mutating, the premise of the fix changed and the
     * comment in nodus_witness_sync.c must be re-derived. */
    if (last_after == last_before && sbe_after == sbe_before) {
        FAIL("post-root call was inert — the monotonic guard now covers "
             "the boundary case, so re-derive the fix");
        return;
    }
    if (last_after != BOUNDARY_H || sbe_after != 1) {
        char m[160];
        snprintf(m, sizeof(m),
                 "unexpected mutation: last %llu->%llu sbe %llu->%llu",
                 (unsigned long long)last_before, (unsigned long long)last_after,
                 (unsigned long long)sbe_before, (unsigned long long)sbe_after);
        FAIL(m);
        return;
    }
    PASS();
}

static void test_first_valid_credit_is_next_block(void) {
    TEST("first valid credit lands at h=34, once genuinely ACTIVE");

    /* Canonical post-h33 row: flipped ACTIVE, counters untouched. */
    if (seed_validator((int)DNAC_VALIDATOR_ACTIVE, OLD_LAST, 0) != 0) {
        FAIL("seed"); return;
    }
    if (nodus_witness_record_attendance(&w, NEXT_H, g_proposer_id) != 0) {
        FAIL("credit at h=34 errored"); return;
    }
    uint64_t last = 0, sbe = 0;
    if (read_row(&last, &sbe) != 0) { FAIL("read"); return; }
    if (last != NEXT_H || sbe != 1) {
        char m[128];
        snprintf(m, sizeof(m), "last=%llu sbe=%llu (expected %d/1)",
                 (unsigned long long)last, (unsigned long long)sbe, NEXT_H);
        FAIL(m);
        return;
    }
    PASS();
}

static void test_monotonic_guard_refuses_duplicate(void) {
    TEST("monotonic guard refuses a duplicate credit at the same height");

    if (seed_validator((int)DNAC_VALIDATOR_ACTIVE, NEXT_H, 1) != 0) {
        FAIL("seed"); return;
    }
    if (nodus_witness_record_attendance(&w, NEXT_H, g_proposer_id) != 0) {
        FAIL("duplicate call errored"); return;
    }
    uint64_t last = 0, sbe = 0;
    if (read_row(&last, &sbe) != 0) { FAIL("read"); return; }
    if (last != NEXT_H || sbe != 1) {
        FAIL("duplicate call was not a no-op");
        return;
    }
    PASS();
}

int main(void) {
    printf("\n=== Nodus replay/live attendance parity at an epoch "
           "boundary (O15B.1) ===\n\n");

    /* Deterministic pubkey, and the witness_id record_attendance derives
     * from it (SHA3-512(pubkey), truncated to the witness id length). */
    for (size_t i = 0; i < sizeof(g_pubkey); i++)
        g_pubkey[i] = (uint8_t)(i * 7 + 3);
    uint8_t digest[64];
    qgp_sha3_512(g_pubkey, sizeof(g_pubkey), digest);
    memcpy(g_proposer_id, digest, NODUS_T3_WITNESS_ID_LEN);

    /* Production schema, via the production creation path. */
    char tmpl[] = "/tmp/o15b1_attend_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { printf("  mkdtemp failed\n"); return 1; }

    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", dir);

    uint8_t chain_id[32];
    memset(chain_id, 0x5A, sizeof(chain_id));
    if (nodus_witness_create_chain_db(&w, chain_id) != 0 || !w.db) {
        printf("  create_chain_db failed\n");
        return 1;
    }

    test_eligible_proposer_gets_no_credit();
    test_post_root_call_mutates_committed_state();
    test_first_valid_credit_is_next_block();
    test_monotonic_guard_refuses_duplicate();

    printf("\n  %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
