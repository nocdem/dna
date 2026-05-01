/**
 * Nodus — Faz 1D / Test 1.15 — multi-round skip silent drop (M-2)
 *
 * RED state — failing test by design until Faz 3.7 silent drop logic.
 *
 * Audit ref: M-2 (MAJOR). When follower is N blocks behind during
 * active sync (e.g. h=110, peer at h=120 producing more), every
 * incoming COMMIT for h > local_next triggers a height-mismatch log
 * + sync_check call (with rate limit). This produces 6+ log lines
 * per round per peer — log spam during recovery.
 *
 * Mitigation: when (cmt->block_height > local_next + 1 && syncing),
 * silently drop the COMMIT without log + without sync_check trigger
 * (sync is already running). Threshold log only when delta > N or
 * sync is stalled.
 *
 * Scenario (target after Faz 3.7):
 *   Sub-test A — actively syncing, distant future COMMIT silent:
 *     1. Setup witness at h=110, peer at h=120
 *     2. w->sync_state.syncing = true, target=120, current=111
 *     3. Receive COMMIT with cmt.block_height = 119
 *     4. Expected: rejected, NO log line, NO sync_check called
 *
 *   Sub-test B — not syncing, mismatched COMMIT logs once:
 *     1. Setup at h=110, no active sync
 *     2. Receive COMMIT with cmt.block_height = 119
 *     3. Expected: 1 log line "height mismatch ... sync needed"
 *        + sync_check fired
 *
 *   Sub-test C — sync stalled threshold:
 *     1. Active sync but no progress for 60s
 *     2. Receive distant-future COMMIT
 *     3. Expected: log line emitted to flag stalled sync
 *
 * Blocked on Faz 3.7.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_multi_round_skip_silent_drop: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 3.7 silent drop logic.\n");
    return 1;
}
