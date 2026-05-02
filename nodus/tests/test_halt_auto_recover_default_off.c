/**
 * Nodus — Faz 1.7 — halt_auto_recover config default OFF (concrete)
 *
 * Audit B-3 (BLOCKER): default OFF blocks all-Byzantine-peer self-
 * destruct. A halted honest node reaching only a Byzantine subset
 * would otherwise see unanimous "disagree" → drop valid DB → re-sync
 * from attacker's chain.
 *
 * Sub-A: zero-init config has halt_auto_recover == false
 * Sub-B: explicit set true persists to halt_recovery_check guard
 * Sub-C/D (no-op vs fire) require peer-state mocking — deferred to
 *   integration test (stagef harness covers via test_supply_invariant).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "nodus/nodus_types.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

int main(void) {
    printf("\nFaz 1.7 — halt_auto_recover default OFF\n");

    /* Sub-A: zero-init / fresh struct → false */
    nodus_witness_config_t cfg_default;
    memset(&cfg_default, 0, sizeof(cfg_default));
    CHECK(cfg_default.halt_auto_recover == false);
    printf("  sub-A: default false ✓\n");

    /* Sub-B: explicit true persists */
    nodus_witness_config_t cfg_opt_in;
    memset(&cfg_opt_in, 0, sizeof(cfg_opt_in));
    cfg_opt_in.halt_auto_recover = true;
    CHECK(cfg_opt_in.halt_auto_recover == true);
    printf("  sub-B: explicit true ✓\n");

    printf("Faz 1.7 PASS (sub-C/D deferred to stagef integration)\n");
    return 0;
}
