/**
 * Nodus — BFT quorum formula tests
 *
 * Phase 8 / Tasks 8.1 + 8.2 + 8.3 — verifies the new (2n)/3 + 1
 * formula yields the correct quorum for every cluster size, including:
 *   - n below NODUS_T3_MIN_WITNESSES (consensus disabled, q=0)
 *   - n == 3f+1 (unchanged vs the legacy formula)
 *   - n not of the form 3f+1 (where the legacy 2f+1 was UNSAFE)
 */

#include "witness/nodus_witness_bft.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Expected quorums per (2n)/3 + 1, with n < NODUS_T3_MIN_WITNESSES(5)
 * disabled (q=0). */
struct case_row { uint32_t n; uint32_t expected_q; };
static const struct case_row cases[] = {
    {0, 0}, {1, 0}, {2, 0}, {3, 0}, {4, 0},   /* below minimum */
    {5, 4},   /* safety upgrade: legacy q=3 was unsafe here */
    {6, 5},
    {7, 5},   /* n=3f+1 unchanged */
    {8, 6},   /* safety upgrade: legacy q=5 was unsafe here */
    {9, 7},
    {10, 7},  /* n=3f+1 unchanged */
    {11, 8},  /* safety upgrade */
    {13, 9},  /* n=3f+1 unchanged */
    {21, 15},
    {22, 15},
    {42, 29},
    {100, 67},
};

static void test_quorum_table(void) {
    TEST("quorum formula yields expected value for every n");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        nodus_witness_bft_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        nodus_witness_bft_config_init(&cfg, cases[i].n);

        if (cfg.quorum != cases[i].expected_q) {
            char buf[80];
            snprintf(buf, sizeof(buf), "n=%u expected q=%u got q=%u",
                     cases[i].n, cases[i].expected_q, cfg.quorum);
            FAIL(buf);
            return;
        }
    }
    PASS();
}

static void test_n3f_plus_1_unchanged(void) {
    TEST("n ∈ {4,7,10,13} (3f+1) yields the same q as the legacy formula");

    /* For n = 3f+1, (2n)/3+1 == 2f+1 algebraically. This regression
     * test guards against accidental refactors that break the
     * production n=7 cluster's existing quorum. */
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

        /* Also verify the live config init matches, for n ≥ minimum. */
        if (n >= 5) {
            nodus_witness_bft_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            nodus_witness_bft_config_init(&cfg, n);
            if (cfg.quorum != new_q) {
                FAIL("config_init mismatch");
                return;
            }
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
    test_n3f_plus_1_unchanged();
    test_quorum_table();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
