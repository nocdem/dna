/**
 * Nodus — Faz 1C / Test 1.12 — replay_block historical committee (C-4)
 *
 * RED state — failing test by design until Faz 3.5 historical lookup.
 *
 * Audit ref: C-4 (CRITICAL). When sync replay applies block N, cert
 * verification must use the committee active AT block N, not the
 * current committee. Stake/delegate changes between H and H+5 mean
 * the validator set rotates; using current set against historical
 * certs would either:
 *   - Reject valid signatures from rotated-out validators
 *   - Accept invalid ones from rotated-in validators
 *
 * The committee accessor nodus_committee_get_for_block(w, h) (bft.c:286)
 * already supports per-height lookup; the design says replay_block
 * SHOULD use this. Test verifies it DOES.
 *
 * Scenario (target after Faz 3.5):
 *   1. Setup chain with 5 blocks. Block 1-3 committee = {C1..C7}.
 *   2. At block 4, stake change rotates: C1 retires, C8 joins.
 *      Committee = {C2..C8}.
 *   3. Drop witness DB (simulate halt recovery, or fresh sync)
 *   4. Replay block 1 from sync_rsp with cert from C1 (valid at h=1)
 *   5. Expected: block 1 accepted (C1 was committee member at h=1)
 *   6. Current behavior (potentially broken): if replay path uses
 *      current committee {C2..C8}, C1's cert would be rejected
 *      (not in current set) → replay fails → cluster permanently
 *      stuck at h=0 after halt
 *
 * Also verifies cmt->state_root path:
 *   - replay with state_root != NULL exercises new sync_rsp wire field
 *
 * Blocked on Faz 2 (sync_rsp.state_root) + Faz 3.5 (replay historical
 * committee lookup).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_replay_block_historical_committee: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 3.5 historical committee\n"
        "  lookup in replay_block path.\n");
    return 1;
}
