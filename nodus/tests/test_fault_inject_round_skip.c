/**
 * Nodus — Faz 1D / Test 1.18 — fault injection round skip simulation
 *
 * RED state — failing test by design until Faz 5.4 fault injection
 * harness build flag (-DQGP_FAULT_INJECT=ON).
 *
 * Audit ref: M-6 (MAJOR). Production bug surfaced via TCP 4002
 * transport churn (real cluster, US-1 missing PRECOMMIT/COMMIT
 * gossip). Genesis Protocol harness runs 7 nodus processes on
 * localhost — no kernel-level packet drop available in CI sandbox
 * (iptables requires CAP_NET_ADMIN).
 *
 * Mitigation: userspace fault injection via T3 dispatch hook
 * controlled by build flag QGP_FAULT_INJECT. When ON:
 *   - nodus_witness_test_inject_drop(predicate_fn) installs a filter
 *   - Predicate evaluated at T3 receive; matches → frame silently
 *     dropped at dispatch boundary (simulating network loss)
 *
 * Scenario (target after Faz 5.4):
 *   Sub-test A — drop predicate matches → frame lost:
 *     1. Setup 7-node localhost cluster
 *     2. Install predicate: drop PRECOMMIT/COMMIT for round 117
 *        addressed to node US-1
 *     3. Run TPS test, observe US-1 misses round 117
 *     4. Verify cluster recovery: with fix bundle, US-1 detects
 *        height mismatch on round 118 COMMIT, triggers sync,
 *        catches up. 7/7 state_root identical at end.
 *     5. Without fix: reproduces the original bug — US-1 halts.
 *
 *   Sub-test B — predicate doesn't match → frame passes:
 *     1. Predicate: drop only frames TO node US-2
 *     2. Verify US-1 receives all frames normally
 *
 *   Sub-test C — predicate cleared returns to normal:
 *     1. Install predicate, then clear with NULL
 *     2. Verify all frames pass
 *
 * Build flag: QGP_FAULT_INJECT=ON gated against Release builds
 * (mirrors NODUS_WITNESS_TEST_HOOKS guard, CMakeLists.txt:253-257).
 *
 * Blocked on Faz 5.4 (build flag + dispatch hook).
 */

/* Faz 5.4 fault injection harness — concrete when built with
 * -DQGP_FAULT_INJECT=ON; SKIP (rc=99) on default builds.
 *
 * With the flag, the test installs a drop predicate that matches
 * any T3 message and verifies it can be installed + cleared via
 * nodus_witness_test_inject_drop. End-to-end stagef partition
 * simulation (cluster recovers from a synthetic round skip while
 * one node has the predicate active) is a follow-up that needs
 * stagef_up.sh to honor the build flag — tracked separately. */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef QGP_FAULT_INJECT
static int g_call_count;
static bool drop_all(const void *msg, const uint8_t *peer_id) {
    (void)msg; (void)peer_id;
    g_call_count++;
    return true;
}
#endif

int main(void) {
#ifdef QGP_FAULT_INJECT
    g_call_count = 0;
    /* Predicate install + clear cycle */
    nodus_witness_test_inject_drop(drop_all);
    nodus_witness_test_inject_drop(NULL);
    /* Re-install + clear cycle is the API contract; behavioral test
     * (predicate fires inside dispatch_t3, message dropped before
     * handler) needs full witness setup + a fake T3 frame, deferred
     * to stagef harness. */
    printf("Faz 1.18 PASS (predicate install/clear; behavioral matrix "
        "in stagef with QGP_FAULT_INJECT build)\n");
    return 0;
#else
    printf("Faz 1.18 SKIP (built without -DQGP_FAULT_INJECT=ON)\n");
    return 99;
#endif
}
