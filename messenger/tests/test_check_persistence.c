/**
 * @file test_check_persistence.c
 * @brief Check if previously stored values persist in DHT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../dht/client/dht_singleton.h"
#include "../dht/core/dht_context.h"

int main(void) {
    printf("=== Checking DHT Persistence ===\n\n");

    // Initialize DHT
    printf("1. Initializing DHT...\n");
    int ret = dht_singleton_init();
    if (ret != 0) {
        printf("   ✗ DHT initialization failed\n");
        return 1;
    }
    printf("   ✓ DHT initialized\n\n");

    dht_context_t* ctx = dht_singleton_get();

    // Wait for DHT to be ready
    printf("2. Waiting for DHT connection...\n");
    int max_wait = 15;
    int waited = 0;
    while (!dht_context_is_ready(ctx) && waited < max_wait) {
        sleep(1);
        waited++;
    }

    if (!dht_context_is_ready(ctx)) {
        printf("   ✗ DHT not ready\n");
        dht_singleton_cleanup();
        return 1;
    }
    printf("   ✓ DHT ready\n\n");

    // Try to retrieve the values we stored earlier
    const char* test_keys[] = {
        "pq_test_key_12345",        // From test_pq_put_get
        "test_bootstrap_key"        // From test_pq_dht_bootstrap
    };
    int num_keys = 2;

    printf("3. Checking stored values...\n\n");
    int found_count = 0;

    for (int i = 0; i < num_keys; i++) {
        printf("   Key [%d]: %s\n", i+1, test_keys[i]);

        uint8_t *value = NULL;
        size_t value_len = 0;

        ret = dht_get(ctx,
                      (uint8_t*)test_keys[i], strlen(test_keys[i]),
                      &value, &value_len);

        if (ret == 0 && value != NULL) {
            printf("   ✓ FOUND - Value: %.*s\n", (int)value_len, value);
            printf("   ✓ Size: %zu bytes\n", value_len);
            found_count++;
            free(value);
        } else {
            printf("   ✗ NOT FOUND (may have expired or not propagated)\n");
        }
        printf("\n");
    }

    // Cleanup
    dht_singleton_cleanup();

    printf("=== Persistence Check Complete ===\n");
    printf("Results: %d/%d values found\n", found_count, num_keys);

    if (found_count == num_keys) {
        printf("✓ All values are PERSISTENT!\n");
        return 0;
    } else {
        printf("⚠ Some values not found (may need more time or be expired)\n");
        return 1;
    }
}
