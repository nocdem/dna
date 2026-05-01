/**
 * Nodus — Faz 1B / Test 1.6 — recovery_in_progress sentinel crash safety
 *
 * RED state — failing test by design until Faz 4.2 sentinel mechanism.
 *
 * Audit ref: B-2 (BLOCKER). Without the sentinel, a process crash
 * between drop_witness_db() success and safety_halt=false reset can
 * leave the node with empty DB but cleared halt latch on next boot,
 * making it silently join cluster as fresh node — same bug class as
 * F17 fee_pool rollback (memory: project_f17_status).
 *
 * Scenario (target after Faz 4.2):
 *   Sub-test A — sentinel created before drop:
 *     1. Setup witness with chain at h=10, simulated halt
 *     2. Trigger halt_recovery_check with majority disagreement
 *     3. Verify file /var/lib/nodus/.recovery_in_progress EXISTS
 *        before drop_witness_db() returns
 *     4. Verify sentinel content: chain_id (32B) + halt_height (8B)
 *
 *   Sub-test B — sentinel cleared after first sync block:
 *     1. Continue from A — sync replay block 1 successfully
 *     2. Verify sentinel REMOVED after first commit
 *
 *   Sub-test C — boot rejection if sentinel persists:
 *     1. Manually create sentinel file
 *     2. Call nodus_witness_init() / startup path
 *     3. Verify rc == -1 with log "recovery sentinel found —
 *        admin clear required"
 *
 * Test fixture uses tmpdir for data_path (not /var/lib/nodus) to
 * avoid pollution.
 *
 * Blocked on Faz 4.2.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_recovery_sentinel_crash_safety: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 4.2 sentinel mechanism\n"
        "  (recovery_in_progress file create/remove/boot-check).\n");
    return 1;
}
