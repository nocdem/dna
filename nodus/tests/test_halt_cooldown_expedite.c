/**
 * Nodus — Faz 1D / Test 1.16 — halt cooldown expedite path (M-3)
 *
 * RED state — failing test by design until Faz 4.5 cooldown expedite.
 *
 * Audit ref: M-3 (MAJOR). The 60s halt cooldown blocks all BFT
 * activity (5 latches reject PROPOSE/PREVOTE/PRECOMMIT/COMMIT/sync).
 * In a 5s round interval that's ~12 blocks lost during cooldown,
 * plus another ~6 minutes of per-block sync to catch up.
 *
 * If halt-recovery quorum is IMMEDIATELY clear (existing peer
 * checksums show majority disagree at halt time), there's no value
 * in waiting 60s. Bypass cooldown for this fast-path; reserve 60s
 * only for ambiguous cases (peer state inconclusive, partial roster).
 *
 * Scenario (target after Faz 4.5):
 *   Sub-test A — clear quorum immediately → no cooldown:
 *     1. Latch safety_halt at h=10 with halt_auto_recover=true
 *     2. Pre-populate peer_checksum cache: 5 of 6 peers disagree
 *        with halted node's local state_root (clear quorum)
 *     3. Call halt_recovery_check
 *     4. Expected: drop_witness_db invoked immediately,
 *        cooldown timer NOT consulted
 *
 *   Sub-test B — ambiguous → 60s cooldown:
 *     1. Same as A but only 2 of 6 peers disagree (no quorum)
 *     2. halt_recovery_check evaluates cooldown timer
 *     3. Expected: no immediate drop, wait 60s for re-evaluation
 *
 *   Sub-test C — cooldown re-evaluation:
 *     1. After 60s in B, more peer checksums arrive showing quorum
 *     2. Next halt_recovery_check tick → drop fires
 *
 * Blocked on Faz 4.5.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_halt_cooldown_expedite: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 4.5 cooldown expedite\n"
        "  fast-path for clear quorum disagreement.\n");
    return 1;
}
