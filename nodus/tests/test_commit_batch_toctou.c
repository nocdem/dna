/**
 * Nodus — Faz 1D / Test 1.14 — commit_batch height TOCTOU (M-1)
 *
 * RED state — failing test by design until Faz 3.4 single-snapshot fix.
 *
 * Audit ref: M-1 (MAJOR). handle_commit reads chain_head, then
 * commit_batch re-reads it inside. Race window: between the two
 * reads, another COMMIT or sync replay can advance the head, leaving
 * the stale handle_commit assumption violated by the time
 * commit_batch starts mutating state.
 *
 * Mitigation: take chain_head snapshot once, pass as expected_height
 * parameter to commit_batch (already part of Faz 3.4); inside
 * commit_batch, verify expected_height == local_next under DB lock,
 * rollback if mismatched.
 *
 * Scenario (target after Faz 3.4):
 *   1. Setup witness at h=10
 *   2. Build COMMIT with cmt.block_height = 11 (matches local+1)
 *   3. SIMULATE concurrency: between handle_commit entry and
 *      commit_batch's expected_height check, advance chain to h=11
 *      via direct DB write (test-only hook)
 *   4. commit_batch should detect expected=11 != local_next=12
 *      → rollback, return -1
 *   5. Verify chain_head still 11, no double-commit, no halt
 *
 * Without the snapshot+check, commit_batch would happily apply at
 * h=12 thinking it's at h=11, producing wrong-height block.
 *
 * Blocked on Faz 3.4.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_commit_batch_toctou: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 3.4 expected_height\n"
        "  parameter + snapshot-under-lock guard.\n");
    return 1;
}
