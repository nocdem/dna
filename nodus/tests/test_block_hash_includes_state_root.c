/**
 * Nodus — Faz 1B / Test 1.5 — block_hash MUST bind state_root in cert verify
 *
 * RED state — failing test by design until Faz 3.6 PRECOMMIT cert verify.
 *
 * Audit ref: B-1 (BLOCKER). Even though nodus_witness_compute_block_hash
 * already includes state_root in its preimage (test_compute_block_hash.c
 * lines 124-133 confirms 244-byte preimage with state_root), the B-1
 * concern is on the VERIFY side: when a follower verifies PRECOMMIT
 * certs in handle_commit, does it compute block_hash using its OWN
 * locally-recomputed state_root, or the leader's cmt->state_root?
 *
 * Threat model:
 *   - Byzantine leader collects 2f+1 valid PRECOMMITs over block_hash_X
 *     (signed against leader's claimed state_root_A).
 *   - Leader then mutates cmt->state_root to state_root_B in the
 *     broadcast COMMIT message.
 *   - If verifier computes block_hash using cmt->state_root_B, certs
 *     no longer verify (block_hash_Y ≠ block_hash_X). GOOD — reject.
 *   - If verifier computes block_hash using LOCAL state_root_C
 *     (its own recompute), certs also fail to verify. ALSO GOOD.
 *   - Either way, the attack is foiled — provided the verify path
 *     actually computes block_hash and re-signs the preimage.
 *
 * Scenario (target after Faz 3.6):
 *   1. Setup witness at chain_head = 1 with known state
 *   2. Build COMMIT with valid certs over true block_hash_X
 *   3. Tamper cmt->state_root with arbitrary bytes (state_root_B)
 *   4. Call nodus_witness_bft_handle_commit
 *   5. Expected: rc == -1 (PRECOMMIT cert sig verify fails because
 *      block_hash recomputation diverges)
 *   6. Current behavior (gap): cert verify in handle_commit only
 *      stores certs, does NOT actually call verify_witness_sig over
 *      the cert preimage (line 4727-4737 stores blindly)
 *
 * Blocked on Faz 3.6.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_block_hash_includes_state_root: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 3.6 PRECOMMIT cert verify\n"
        "  in handle_commit (currently certs are stored, not verified).\n");
    return 1;
}
