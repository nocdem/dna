/**
 * Nodus — Faz 1C / Test 1.11 — sync_check rate-limit DoS (C-3)
 *
 * RED state — failing test by design until Faz 3.8 rate-limit fix.
 *
 * Audit ref: C-3 (CRITICAL). Two compounding gaps:
 *
 * Gap A — handle_commit fires sync_check on every height-mismatched
 * COMMIT BEFORE cert verify. A Byzantine leader (or any node spoofing
 * one) can broadcast malformed COMMITs at line rate → 7× sync storm
 * + Merkle recompute per node.
 *
 * Gap B — sync_check rate limit (SYNC_MIN_INTERVAL_SEC = 30s)
 * checks `now - last_sync_attempt < 30s`. But last_sync_attempt is
 * only SET in some paths (sync.c:213 inside the active sync init).
 * Early-return paths (no peer ahead, phase != IDLE, quorum 0,
 * peer_height <= local) do NOT update the timestamp → every COMMIT
 * pays the full peer-table walk + potential Merkle recompute cost.
 *
 * Scenario (target after Faz 3.8):
 *   Sub-test A — cert-invalid COMMIT does NOT trigger sync_check:
 *     1. Setup witness at h=10
 *     2. Build COMMIT with bad PRECOMMIT certs + height=15
 *     3. Call handle_commit
 *     4. Expected: rejected at cert verify (or before), sync_check
 *        NOT invoked (counter unchanged)
 *
 *   Sub-test B — cert-valid mismatched COMMIT triggers sync_check
 *     once, rate-limit honored:
 *     1. Build cert-valid COMMIT with height=15 (local=10)
 *     2. Call handle_commit 100 times in tight loop
 *     3. Expected: sync_check invoked AT MOST 1 time across loop
 *        (rate limit holds)
 *     4. Current: invoked 100 times (early-return paths bypass
 *        last_sync_attempt update)
 *
 *   Sub-test C — last_sync_attempt set in all early-return paths:
 *     1. Cover all early-return cases in sync_check (peer < local,
 *        phase != IDLE, quorum == 0, syncing == true, ...)
 *     2. After each, verify last_sync_attempt == now
 *
 * Blocked on Faz 3.2 (cert verify before sync trigger) + Faz 3.8
 * (rate-limit unconditional set).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_sync_check_dos_rate_limit: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 3.2 + 3.8\n"
        "  (cert verify ordering + last_sync_attempt unconditional set).\n");
    return 1;
}
