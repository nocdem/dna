/**
 * Nodus — Faz 1C / Test 1.9 — heartbeat checksum signed (C-1)
 *
 * RED state — failing test by design until Faz 4.6 signed heartbeat.
 *
 * Audit ref: C-1 (CRITICAL). Currently nodus_t3_ident_t carries an
 * unsigned `state_root` field used for same-height fork detection
 * (sync.c:197-222). A single Byzantine peer can spoof remote_checksum
 * to mislead halt-recovery quorum:
 *   - Pretend to AGREE with halted node's bad state → keeps it halted
 *   - Pretend to DISAGREE → pushes disagree count toward quorum,
 *     potentially triggers DB drop on honest halted node
 *
 * Mitigation per design §10.2 C-1: heartbeat checksum signed with
 * Dilithium5 over (height, state_root, chain_id, nonce, sender_id),
 * verified BEFORE counting toward agree/disagree.
 *
 * Scenario (target after Faz 4.6):
 *   1. Setup witness with valid roster of 7 peers
 *   2. Build w_ident message from peer P1 with valid signature
 *   3. Verify acceptance: peers[P1].remote_checksum updated
 *   4. Build w_ident from P1 with TAMPERED state_root (sig over
 *      original) — sig over different bytes
 *   5. Verify rejection: remote_checksum NOT updated
 *   6. Build w_ident from unauthorized identity (not in committee)
 *   7. Verify rejection
 *
 * Wire format change required: nodus_t3_ident_t.checksum_sig field.
 *
 * Blocked on Faz 2 wire format + Faz 4.6 verify path.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_heartbeat_signed_checksum: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 2 ident_t.checksum_sig\n"
        "  wire field + Faz 4.6 verify path.\n");
    return 1;
}
