/**
 * Nodus — Faz 1A / Test 1.4 — sync_rsp Byzantine peer rejection
 *
 * RED state — failing test by design until Faz 2+3 complete.
 *
 * Scenario (target behavior after Faz 2 + Faz 3.5):
 *   1. Setup witness at h=0 (pre-genesis)
 *   2. Apply genesis (block 1)
 *   3. Build w_sync_rsp from a "Byzantine peer" claiming block 2 with
 *      a fabricated state_root that does NOT match what local replay
 *      would compute
 *   4. Call nodus_witness_sync_handle_rsp(w, &msg)
 *   5. Expected: rc == -1, block 2 NOT inserted, sync.state.syncing
 *      cleared, log "block replay failed at height 2"
 *   6. Current behavior (broken): nodus_witness_sync.c:643 passes
 *      NULL as expected_state_root, so replay_block has no comparison
 *      target — Byzantine block silently accepted (only cert verify
 *      catches it, which has its own gaps per audit B-3)
 *
 * Reference: nodus_witness_sync.c:637-642 ("C3 fix: sync_rsp does not
 * currently include state_root on the wire — pass NULL ... Adding
 * state_root to sync_rsp is a wire format change — deferred to a
 * follow-up that also bumps sync protocol version.")
 *
 * Blocked on:
 *   - Faz 2: nodus_t3_sync_rsp_t.state_root field added to wire
 *   - Faz 3.5: replay_block invocation pass rsp->state_root (not NULL)
 *
 * The replay_block API itself (nodus_witness_bft.c:5774) already
 * accepts expected_state_root parameter and forwards it to commit_batch
 * → finalize_block where the mismatch check (line 3186-3212) latches
 * safety_halt. The test scaffolding waits for the wire field so that
 * sync_handle_rsp can populate it.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_witness_sync_rsp_state_root_verify: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 2 wire format addition\n"
        "  (nodus_t3_sync_rsp_t.state_root field) and Faz 3.5 sync\n"
        "  handler update (replay_block call site passes rsp->state_root\n"
        "  instead of NULL).\n");
    return 1;
}
