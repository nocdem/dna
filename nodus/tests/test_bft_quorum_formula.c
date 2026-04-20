/**
 * Nodus — BFT quorum formula tests
 *
 * Phase 8 / Tasks 8.1 + 8.2 + 8.3 — verifies the (2n)/3 + 1 formula
 * yields the correct quorum across the supported committee range.
 *
 * F17 A1 — nodus_witness_bft_config_init clamps n at DNAC_COMMITTEE_SIZE.
 * Consensus is committee-bound, so any n > 7 is compressed to the
 * committee-sized quorum. The pure formula math is still exercised
 * separately via test_formula_identity to guard against refactors.
 */

#include "witness/nodus_witness_bft.h"
#include "dnac/dnac.h"   /* DNAC_COMMITTEE_SIZE */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* In-range cases (n <= DNAC_COMMITTEE_SIZE): config_init must yield
 * the exact (2n)/3 + 1 quorum. */
struct case_row { uint32_t n; uint32_t expected_q; };
static const struct case_row in_range_cases[] = {
    {0, 0}, {1, 0}, {2, 0}, {3, 0}, {4, 0},   /* below minimum */
    {5, 4},   /* safety upgrade: legacy q=3 was unsafe here */
    {6, 5},
    {7, 5},   /* n=3f+1 production committee */
};

/* Out-of-range cases: config_init clamps at DNAC_COMMITTEE_SIZE so
 * any n > 7 returns the same cfg as n = 7. */
static const uint32_t clamp_cases[] = {8, 9, 10, 13, 21, 42, 100};

static void test_in_range_quorum(void) {
    TEST("in-range quorum (n <= DNAC_COMMITTEE_SIZE)");

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

static void test_clamp_at_committee_size(void) {
    TEST("n > DNAC_COMMITTEE_SIZE clamps to committee-sized quorum");

    /* F17 A1 invariant: config_init clamps n at DNAC_COMMITTEE_SIZE,
     * so any n > 7 yields the same cfg as n=7. Vote arrays are sized
     * to DNAC_COMMITTEE_SIZE; quorums larger than that would be
     * unreachable. */
    nodus_witness_bft_config_t baseline;
    memset(&baseline, 0, sizeof(baseline));
    nodus_witness_bft_config_init(&baseline, DNAC_COMMITTEE_SIZE);

    for (size_t i = 0; i < sizeof(clamp_cases) / sizeof(clamp_cases[0]); i++) {
        nodus_witness_bft_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        nodus_witness_bft_config_init(&cfg, clamp_cases[i]);

        if (cfg.quorum != baseline.quorum) {
            char buf[80];
            snprintf(buf, sizeof(buf),
                     "n=%u clamp expected q=%u got q=%u",
                     clamp_cases[i], baseline.quorum, cfg.quorum);
            FAIL(buf);
            return;
        }
    }
    PASS();
}

static void test_formula_identity(void) {
    TEST("(2n)/3 + 1 == 2f+1 for all n = 3f+1 (pure math, no config_init)");

    /* For n = 3f+1, (2n)/3+1 == 2f+1 algebraically. This regression
     * test guards against accidental refactors that break the
     * production n=7 cluster's existing quorum. Pure math — does NOT
     * call config_init, so the F17 clamp doesn't affect it. */
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
    test_clamp_at_committee_size();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
