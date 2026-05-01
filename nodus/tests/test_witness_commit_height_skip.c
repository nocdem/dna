/**
 * Nodus — Faz 1A / Test 1.1 — round skip detection
 *
 * RED state — failing test by design until Faz 3 handler update.
 *
 * Scenario (target behavior after Faz 3):
 *   1. Setup witness at chain_head = 114 (block 114 committed)
 *   2. Build COMMIT message with hdr.round = 118, cmt.block_height = 116,
 *      batch_count = 1 (single TX)
 *   3. Call nodus_witness_bft_handle_commit(w, &msg)
 *   4. Expected: rc == -1 (reject — height mismatch with local_next=115)
 *      and chain head unchanged (still 114), no state mutation
 *   5. Current behavior (broken): rc == 0, applies block at wrong height,
 *      state_root divergence, safety halt latched
 *
 * Test cannot reach concrete COMMIT message construction until:
 *   - Faz 2: nodus_t3_commit_t.block_height field added to wire struct
 *   - Faz 3: handle_commit A2 simetri kontrolü implemented
 *
 * Bug ref: project_witness_commit_height_asymmetry (live cluster
 * 2026-05-01: US-1 halted at h=114 due to this exact path).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_witness_commit_height_skip: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 2 wire format addition\n"
        "  (nodus_t3_commit_t.block_height field).\n"
        "  Will be implemented when Faz 2.1 lands.\n");
    return 1;
}
