/**
 * @file test_pq_put_get.c
 * @brief Simple PQ DHT Put/Get Test
 *
 * Tests:
 * - Write value to PQ DHT (Dilithium5 signed)
 * - Read value back from PQ DHT
 * - Verify data integrity
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../dht/client/dht_singleton.h"
#include "../dht/core/dht_context.h"

#define TEST_KEY "pq_test_key_12345"
#define TEST_VALUE "Post-Quantum DHT Test Value - Dilithium5 Signed"

int main(void) {
    printf("=== PQ DHT Put/Get Test ===\n\n");

    // Initialize DHT
    printf("1. Initializing DHT singleton...\n");
    int ret = dht_singleton_init();
    assert(ret == 0 && "DHT initialization failed");
    printf("   ✓ DHT initialized\n\n");

    // Get DHT context
    dht_context_t* ctx = dht_singleton_get();
    assert(ctx != NULL && "Failed to get DHT context");

    // Wait for DHT to be ready
    printf("2. Waiting for DHT to connect...\n");
    int max_wait = 15; // 15 seconds
    int waited = 0;
    while (!dht_context_is_ready(ctx) && waited < max_wait) {
        printf("   Waiting... (%d/%d seconds)\n", waited + 1, max_wait);
        sleep(1);
        waited++;
    }

    if (!dht_context_is_ready(ctx)) {
        printf("   ⚠ DHT not ready after %d seconds\n", max_wait);
        printf("   This test requires network connectivity to bootstrap nodes\n");
        dht_singleton_cleanup();
        return 1;
    }
    printf("   ✓ DHT ready (connected to bootstrap nodes)\n\n");

    // Put value to DHT
    printf("3. Writing value to PQ DHT...\n");
    printf("   Key: %s\n", TEST_KEY);
    printf("   Value: %s\n", TEST_VALUE);

    ret = dht_put(ctx,
                  (uint8_t*)TEST_KEY, strlen(TEST_KEY),
                  (uint8_t*)TEST_VALUE, strlen(TEST_VALUE));

    assert(ret == 0 && "DHT put failed");
    printf("   ✓ Value written to DHT\n\n");

    // Wait for value to propagate
    printf("4. Waiting for value to propagate (5 seconds)...\n");
    sleep(5);
    printf("   ✓ Propagation time elapsed\n\n");

    // Get value from DHT
    printf("5. Reading value from PQ DHT...\n");
    uint8_t *retrieved_value = NULL;
    size_t retrieved_len = 0;

    ret = dht_get(ctx,
                  (uint8_t*)TEST_KEY, strlen(TEST_KEY),
                  &retrieved_value, &retrieved_len);

    if (ret != 0 || retrieved_value == NULL) {
        printf("   ⚠ DHT get failed\n");
        printf("   Note: Value may not have propagated yet\n");
        dht_singleton_cleanup();
        return 1;
    }

    printf("   ✓ Value retrieved from DHT\n");
    printf("   Retrieved length: %zu bytes\n", retrieved_len);
    printf("   Retrieved value: %.*s\n", (int)retrieved_len, retrieved_value);

    // Verify data integrity
    printf("\n6. Verifying data integrity...\n");
    assert(retrieved_len == strlen(TEST_VALUE) && "Length mismatch");
    assert(memcmp(retrieved_value, TEST_VALUE, retrieved_len) == 0 && "Value mismatch");
    printf("   ✓ Data integrity verified\n");
    printf("   ✓ Length matches: %zu bytes\n", retrieved_len);
    printf("   ✓ Content matches\n\n");

    // Cleanup
    free(retrieved_value);
    dht_singleton_cleanup();

    printf("=== All Tests Passed ===\n");
    printf("Summary:\n");
    printf("  - DHT Type: Post-Quantum (Dilithium5)\n");
    printf("  - Operations: Put + Get\n");
    printf("  - Data Integrity: Verified\n");
    printf("  - Security: NIST Category 5 (256-bit quantum)\n");

    return 0;
}
