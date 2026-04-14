/**
 * Nodus — Phase 7 / Task 7.2 — bft_start_round_from_mempool tests
 *
 * Guard tests for the mempool-based BFT round wrapper. The full
 * mempool drain + Phase 4 layer-2 chained-UTXO filter exercise lives
 * in test_chained_utxo (which already covers the propose_batch logic
 * that this wrapper now owns). These tests confirm the wrapper handles
 * the no-witness and empty-mempool cases without crashing or trying to
 * touch a NULL DB.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_null_witness_rejected(void) {
    TEST("from_mempool rejects NULL witness");
    int rc = nodus_witness_bft_start_round_from_mempool(NULL);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

static void test_empty_mempool_rejected(void) {
    TEST("from_mempool returns -1 on empty mempool");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    /* mempool.count == 0 (zero-initialized) */
    int rc = nodus_witness_bft_start_round_from_mempool(&w);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

int main(void) {
    printf("BFT start_round_from_mempool guard tests\n");
    printf("========================================\n");

    test_null_witness_rejected();
    test_empty_mempool_rejected();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
