/**
 * Nodus — Faz 1B / Test 1.8 — halt-recovery uses historical committee
 *
 * RED state — failing test by design until Faz 4.4 historical
 * committee snapshot at halt_block_height.
 *
 * Audit ref: B-3 (BLOCKER) + C-4 (CRITICAL).
 *
 * Threat: stake/delegate changes between block N (halt) and block N+5
 * (recovery attempt). If halt_recovery_check uses CURRENT roster
 * (gossip), an attacker can:
 *   - Spawn phantom committee members during halt window
 *   - Phantom members trivially "disagree" with halted node's valid
 *     state_root → quorum met → DB drop on honest node
 *
 * Mitigation: snapshot committee at halt_block_height when halt is
 * latched; only count `disagree` votes from members of THAT snapshot.
 *
 * Scenario (target after Faz 4.4):
 *   1. Setup 7-node cluster simulation, witness at h=100 with
 *      committee = {C1, C2, ..., C7}
 *   2. Latch safety_halt at h=100; verify w->halt_committee_snapshot
 *      captured = original 7
 *   3. Inject phantom peers C8, C9 (would-be majority if counted)
 *   4. C8, C9 send ident messages with conflicting state_root
 *   5. halt_recovery_check evaluates `disagree` count
 *   6. Expected: phantom C8, C9 NOT counted (not in halt_committee_
 *      snapshot); legitimate disagree count = 0; no DB drop
 *   7. Current (broken): would count phantoms via current roster,
 *      trigger spurious drop
 *
 * Also covers C-4 (replay_block historical lookup):
 *   - When sync replays h=N, committee for cert verify must be
 *     committee@N, not current
 *   - Subtest verifies nodus_committee_get_for_block(w, N) returns
 *     the correct historical set after stake changes at N+1
 *
 * Blocked on Faz 4.4 + Faz 3.5 (replay path historical lookup).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_halt_recovery_historical_committee: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 4.4 historical committee\n"
        "  snapshot at halt_block_height + Faz 3.5 replay path lookup.\n");
    return 1;
}
