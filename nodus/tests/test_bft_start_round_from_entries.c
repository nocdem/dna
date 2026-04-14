/**
 * Nodus — Phase 7 / Task 7.1 — bft_start_round_from_entries tests
 *
 * Guard tests for the new entry-based BFT round wrapper. Exercising the
 * full BFT round (roster, leader election, broadcast) requires a
 * network fixture that is out of scope for unit tests; these tests
 * confirm the signature guards and that the wrapper links correctly to
 * the shared batch body. Integration-level rounds are covered by the
 * existing ctest suite (test_bft_quorum_formula) and the cluster-level
 * post-deploy checks.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_mempool.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_null_witness_rejected(void) {
    TEST("from_entries rejects NULL witness");
    nodus_witness_mempool_entry_t *entries[1] = { NULL };
    int rc = nodus_witness_bft_start_round_from_entries(NULL, entries, 1);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

static void test_null_entries_rejected(void) {
    TEST("from_entries rejects NULL entries array");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    int rc = nodus_witness_bft_start_round_from_entries(&w, NULL, 1);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

static void test_zero_count_rejected(void) {
    TEST("from_entries rejects count=0");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    nodus_witness_mempool_entry_t *entries[1] = { NULL };
    int rc = nodus_witness_bft_start_round_from_entries(&w, entries, 0);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

static void test_negative_count_rejected(void) {
    TEST("from_entries rejects count<0");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    nodus_witness_mempool_entry_t *entries[1] = { NULL };
    int rc = nodus_witness_bft_start_round_from_entries(&w, entries, -1);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

int main(void) {
    printf("BFT start_round_from_entries guard tests\n");
    printf("========================================\n");

    test_null_witness_rejected();
    test_null_entries_rejected();
    test_zero_count_rejected();
    test_negative_count_rejected();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
