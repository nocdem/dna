/**
 * Nodus — Faz 1A / Test 1.3 — legacy peer (block_height == 0) reject
 *
 * RED state — failing test by design until Faz 3 handler update.
 *
 * Scenario (target behavior after Faz 3):
 *   1. Setup witness at chain_head = 114
 *   2. Build COMMIT message with cmt.block_height = 0
 *      (legacy v0.17 peer that doesn't carry block_height)
 *   3. Call nodus_witness_bft_handle_commit(w, &msg)
 *   4. Expected: rc == -1 with log "missing block_height (legacy peer
 *      or malformed); sync needed" — no state mutation
 *   5. Current behavior (broken): handler accepts, applies block 115
 *      from possibly-mismatched leader claim
 *
 * Per Faz 2.5 design: NODUS_PROTOCOL_VERSION bump should ensure cross-
 * version messages reject at frame layer; this test is the inner
 * defense for cases where the version check is bypassed.
 *
 * Mirror of handle_propose A2 fix (nodus_witness_bft.c:3899-3905):
 *   "propose rejected — missing block_height (legacy peer or malformed
 *    proposal); sync needed"
 *
 * Blocked on Faz 2 + Faz 3.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_witness_commit_height_zero_legacy: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 2 wire format.\n");
    return 1;
}
