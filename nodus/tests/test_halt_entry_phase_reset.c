/**
 * Nodus — Faz 1D / Test 1.17 — halt entry phase reset (M-4)
 *
 * RED state — failing test by design until Faz 4.1 phase reset.
 *
 * Audit ref: M-4 (MAJOR). nodus_witness_sync_check returns early if
 * `phase != NODUS_W_PHASE_IDLE` (sync.c:165). When safety_halt is
 * latched mid-PRECOMMIT (the bug we hit on US-1 at 11:14:47), phase
 * stays at PRECOMMIT until view-change timeout reset. During this
 * window, halt_recovery_check (which reuses sync_check logic) would
 * silently skip recovery.
 *
 * Mitigation: at safety_halt entry (finalize_block:3209), explicitly
 * reset round_state.phase = NODUS_W_PHASE_IDLE so subsequent
 * sync_check / halt_recovery_check tick is not gated.
 *
 * Scenario (target after Faz 4.1):
 *   1. Setup witness, drive into PRECOMMIT phase via partial round
 *   2. Trigger state_root divergence (set expected_state_root != local)
 *   3. finalize_block returns -1, sets w->safety_halt = true
 *   4. Expected: w->round_state.phase == NODUS_W_PHASE_IDLE
 *      (reset at halt entry)
 *   5. Call halt_recovery_check (with auto_recover=true + clear quorum)
 *   6. Expected: NOT skipped due to phase guard
 *   7. Current (broken): phase stays PRECOMMIT, recovery silently
 *      skipped, halt persists indefinitely until manual restart
 *
 * Blocked on Faz 4.1.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_halt_entry_phase_reset: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 4.1 phase reset at halt.\n");
    return 1;
}
