/**
 * Nodus — BFT quorum formula tests
 *
 * Phase 8 / Tasks 8.1 + 8.2 + 8.3 — verifies the (2n)/3 + 1 formula
 * yields the correct quorum across the supported committee range.
 *
 * Ledger V2 S3 — nodus_witness_bft_config_init now clamps n at
 * DNAC_MAX_ACTIVE_VALIDATORS (128), not at DNAC_COMMITTEE_SIZE (7).
 * Consensus is still committee-bound, but the committee is dynamically
 * sized from chain state, so the clamp's job is only "quorum can never
 * exceed the number of vote slots that exist" — and those arrays are
 * DNAC_MAX_ACTIVE_VALIDATORS-sized (nodus_witness.h round_state).
 *
 * Clamping at 7 would have been a SAFETY break once the active set can
 * grow: a 9-member set would have produced quorum(7) = 5 instead of
 * quorum(9) = 7, i.e. a threshold below 2f+1 for the real set, so two
 * disjoint "quorums" could both commit. The n=8/9 rows below pin exactly
 * that. n=7 → 5 is retained unchanged: the live cluster's behaviour.
 */

#include "witness/nodus_witness_bft.h"
#include "dnac/dnac.h"   /* DNAC_COMMITTEE_SIZE, DNAC_MAX_ACTIVE_VALIDATORS */
#include "dnac/ledger_ids.h"  /* dna_bft_quorum — the shared formula */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* In-range cases (n <= DNAC_MAX_ACTIVE_VALIDATORS): config_init must
 * yield the exact (2n)/3 + 1 quorum. */
struct case_row { uint32_t n; uint32_t expected_q; };
static const struct case_row in_range_cases[] = {
    {0, 0}, {1, 0}, {2, 0}, {3, 0}, {4, 0},   /* below minimum */
    {5, 4},     /* safety upgrade: legacy q=3 was unsafe here */
    {6, 5},
    {7, 5},     /* n=3f+1 production committee — UNCHANGED by S3 */
    {8, 6},     /* S3: used to be clamped to 5 */
    {9, 7},     /* S3: used to be clamped to 5 — the safety break */
    {15, 11},
    {30, 21},
    {128, 86},  /* DNAC_MAX_ACTIVE_VALIDATORS, this release's ceiling */
};

/* Out-of-range cases: config_init clamps at DNAC_MAX_ACTIVE_VALIDATORS
 * so any n > 128 returns the same cfg as n = 128. */
static const uint32_t clamp_cases[] = {129, 200, 1000, UINT32_MAX};

static void test_in_range_quorum(void) {
    TEST("in-range quorum (n <= DNAC_MAX_ACTIVE_VALIDATORS)");

    for (size_t i = 0; i < sizeof(in_range_cases) / sizeof(in_range_cases[0]); i++) {
        nodus_witness_bft_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        nodus_witness_bft_config_init(&cfg, in_range_cases[i].n);

        if (cfg.quorum != in_range_cases[i].expected_q) {
            char buf[80];
            snprintf(buf, sizeof(buf), "n=%u expected q=%u got q=%u",
                     in_range_cases[i].n, in_range_cases[i].expected_q, cfg.quorum);
            FAIL(buf);
            return;
        }
    }
    PASS();
}

static void test_matches_shared_formula(void) {
    TEST("config_init agrees with dna_bft_quorum for every legal n");

    /* The witness-side quorum and shared/dnac/ledger_ids.h's
     * dna_bft_quorum are used by DIFFERENT consumers (BFT rounds vs the
     * chain-config vote gate and halt recovery). They MUST be the same
     * number for every n at or above the minimum, or a proposal could
     * clear one gate and fail the other. */
    for (uint32_t n = NODUS_T3_MIN_WITNESSES;
         n <= (uint32_t)DNAC_MAX_ACTIVE_VALIDATORS; n++) {
        nodus_witness_bft_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        nodus_witness_bft_config_init(&cfg, n);
        if (cfg.quorum != dna_bft_quorum(n)) {
            char buf[96];
            snprintf(buf, sizeof(buf),
                     "n=%u config_init q=%u != dna_bft_quorum q=%u",
                     n, cfg.quorum, dna_bft_quorum(n));
            FAIL(buf);
            return;
        }
    }
    PASS();
}

static void test_clamp_at_release_ceiling(void) {
    TEST("n > DNAC_MAX_ACTIVE_VALIDATORS clamps to ceiling quorum");

    /* S3 invariant: config_init clamps n at DNAC_MAX_ACTIVE_VALIDATORS,
     * so any larger n yields the same cfg as n=128. Vote arrays are
     * sized to that constant; a larger quorum would be unreachable. */
    nodus_witness_bft_config_t baseline;
    memset(&baseline, 0, sizeof(baseline));
    nodus_witness_bft_config_init(&baseline, DNAC_MAX_ACTIVE_VALIDATORS);
    if (baseline.quorum != 86) {
        FAIL("baseline quorum(128) != 86");
        return;
    }

    for (size_t i = 0; i < sizeof(clamp_cases) / sizeof(clamp_cases[0]); i++) {
        nodus_witness_bft_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        nodus_witness_bft_config_init(&cfg, clamp_cases[i]);

        if (cfg.quorum != baseline.quorum ||
            cfg.n_witnesses != (uint32_t)DNAC_MAX_ACTIVE_VALIDATORS) {
            char buf[96];
            snprintf(buf, sizeof(buf),
                     "n=%u clamp expected q=%u n=%d got q=%u n=%u",
                     clamp_cases[i], baseline.quorum,
                     DNAC_MAX_ACTIVE_VALIDATORS,
                     cfg.quorum, cfg.n_witnesses);
            FAIL(buf);
            return;
        }
    }
    PASS();
}

static void test_live_cluster_unchanged(void) {
    TEST("live 7-member cluster still yields quorum 5");

    /* The S3 clamp widening must not move the shipped chain's threshold.
     * DNAC_COMMITTEE_SIZE is now only the DEFAULT target, but it is the
     * value the live chain runs at. */
    nodus_witness_bft_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    nodus_witness_bft_config_init(&cfg, DNAC_COMMITTEE_SIZE);
    if (cfg.quorum != 5 || cfg.n_witnesses != 7 || cfg.f_tolerance != 2) {
        FAIL("n=7 no longer yields q=5 / f=2");
        return;
    }
    PASS();
}

static void test_formula_identity(void) {
    TEST("(2n)/3 + 1 == 2f+1 for all n = 3f+1 (pure math, no config_init)");

    /* For n = 3f+1, (2n)/3+1 == 2f+1 algebraically. This regression
     * test guards against accidental refactors that break the
     * production n=7 cluster's existing quorum. Pure math — does NOT
     * call config_init, so the clamp doesn't affect it. */
    uint32_t ns[] = {4, 7, 10, 13, 16, 19, 22, 25};
    for (size_t i = 0; i < sizeof(ns) / sizeof(ns[0]); i++) {
        uint32_t n = ns[i];
        uint32_t legacy_q = 2 * ((n - 1) / 3) + 1;
        uint32_t new_q = (2 * n) / 3 + 1;
        if (legacy_q != new_q) {
            char buf[80];
            snprintf(buf, sizeof(buf),
                     "n=%u legacy=%u new=%u", n, legacy_q, new_q);
            FAIL(buf);
            return;
        }
    }
    PASS();
}

static void test_below_minimum_disables(void) {
    TEST("n < NODUS_T3_MIN_WITNESSES disables consensus (q=0)");

    for (uint32_t n = 0; n < 5; n++) {
        nodus_witness_bft_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        nodus_witness_bft_config_init(&cfg, n);
        if (cfg.quorum != 0) { FAIL("q should be 0"); return; }
    }
    PASS();
}

int main(void) {
    printf("\nNodus BFT Quorum Formula Tests\n");
    printf("==========================================\n\n");

    test_below_minimum_disables();
    test_formula_identity();
    test_in_range_quorum();
    test_matches_shared_formula();
    test_clamp_at_release_ceiling();
    test_live_cluster_unchanged();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
