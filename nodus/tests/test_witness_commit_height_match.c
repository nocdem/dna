/**
 * Nodus — Faz 1A / Test 1.2 — happy-path commit height match
 *
 * RED state — failing test by design until Faz 3 handler update.
 *
 * Scenario (target behavior after Faz 3):
 *   1. Setup witness at chain_head = 114 (block 114 committed)
 *   2. Build COMMIT message with hdr.round = 115, cmt.block_height = 115,
 *      batch_count = 1 (matched TX entry)
 *   3. Call nodus_witness_bft_handle_commit(w, &msg)
 *   4. Expected: rc == 0, block 115 committed, chain_head = 115
 *
 * Mirror of test 1.1 but with correct height — verifies the symmetry
 * check does NOT regress the happy path.
 *
 * Blocked on:
 *   - Faz 2: nodus_t3_commit_t.block_height field
 *   - Faz 3: handle_commit kabul yolu
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_witness_commit_height_match: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 2 wire format.\n");
    return 1;
}
