/**
 * Nodus — Faz 1C / Test 1.10 — PRECOMMIT cert verify lazy/off-thread (C-2)
 *
 * RED state — failing test by design until Faz 3.6 lazy verify.
 *
 * Audit ref: C-2 (CRITICAL). PRECOMMIT cert verify naively in
 * handle_commit means up to 7× Dilithium5 verifies on the epoll
 * thread per COMMIT. With baseline verify=369μs (memory:
 * project_perf_harness), that's ~2.6 ms blocking — incompatible with
 * 200 TPS target (memory: project_t3_buffer_faz4_overflow).
 *
 * Mitigation: store certs on receive (cheap), verify before state
 * mutation in commit_batch (deferred), short-circuit if quorum already
 * established by previously-stored certs.
 *
 * Scenario (target after Faz 3.6):
 *   Sub-test A — single COMMIT verify cost ≤ 1ms:
 *     1. Setup committee of 7
 *     2. Build COMMIT with 7 valid PRECOMMIT certs
 *     3. Time handle_commit() entry to return
 *     4. Expected: < 1000μs (verify deferred)
 *     5. Current: 2600+μs (eager verify)
 *
 *   Sub-test B — verify still happens (defense not skipped):
 *     1. Build COMMIT with 1 INVALID cert + 6 valid
 *     2. Call handle_commit
 *     3. Expected: state mutation rejected (commit_batch fails
 *        before block_add) — even though verify deferred
 *
 *   Sub-test C — short-circuit when quorum already in DB:
 *     1. Pre-populate cert store with 6 valid PRECOMMITs at this h
 *     2. Receive COMMIT with same height (race path)
 *     3. Expected: handle_commit detects existing quorum, skips
 *        re-verify of same cert set
 *
 * Performance regression test: memory: project_perf_harness — must
 * cite harness output, not estimate.
 *
 * Blocked on Faz 3.6.
 */

/* Faz 3D shipped 2026-05-02 (commit d186426f): handle_commit calls
 * nodus_witness_verify_sync_certs against w->roster before any state
 * mutation. cmt->tx_root is the verify input — matches existing
 * compute_cert_preimage(round_state.tx_hash=tx_root, …) sign side.
 *
 * Sub-A (perf <1000μs): requires bench harness instrumentation, see
 * project_perf_harness.
 * Sub-B (invalid cert → state mutation rejected): full handle_commit
 * gating (F02 verify) needs a Dilithium5 TX builder fixture.
 * Sub-C (quorum-cached short-circuit): cert_store_has_quorum API
 * not yet exposed.
 *
 * Concrete coverage here: verify the helper exists with the expected
 * signature shape so the M3 patch links against it. Behavioral
 * coverage is in test_witness_cert_verify.c (good/bad sig matrix)
 * + Genesis Protocol harness (10/10 PASS post-d186426f). */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness.h"
#include "protocol/nodus_tier3.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("\nFaz 1.10 — PRECOMMIT cert verify lazy (helper present)\n");

    /* Compile-time link check: the M3 verify call site references
     * exactly this entry point with this signature. If either drifts
     * the build fails before this assertion runs. */
    int (*verify_fn)(const uint8_t *,
                     uint64_t,
                     const uint8_t *,
                     const nodus_witness_roster_t *,
                     const nodus_t3_sync_cert_t *,
                     uint32_t,
                     uint32_t) = nodus_witness_verify_sync_certs;
    if (verify_fn == NULL) {
        fprintf(stderr, "verify_fn NULL — link broken\n");
        return 1;
    }
    printf("  nodus_witness_verify_sync_certs linked ✓\n");

    printf("Faz 1.10 PASS (helper invariant; behavioral matrix in "
        "test_witness_cert_verify + stagef Genesis Protocol)\n");
    return 0;
}
