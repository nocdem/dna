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

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_fault_inject_round_skip: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 5.4 fault injection\n"
        "  harness (-DQGP_FAULT_INJECT=ON build flag).\n");
    return 1;
}
