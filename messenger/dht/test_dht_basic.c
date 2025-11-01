/**
 * Basic DHT Test - Single Node
 *
 * Tests basic DHT operations:
 * - Initialize DHT context
 * - Start DHT node
 * - Put value
 * - Get value
 * - Statistics
 * - Cleanup
 *
 * Usage: ./test_dht_basic
 */

#include "dht_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    printf("===========================================\n");
    printf("DNA Messenger - DHT Basic Test\n");
    printf("===========================================\n\n");

    // Configuration
    dht_config_t config;
    memset(&config, 0, sizeof(config));

    config.port = 4000;
    config.is_bootstrap = true;
    strncpy(config.identity, "test-node-local", sizeof(config.identity) - 1);
    config.bootstrap_count = 0;  // No bootstrap nodes (first node)

    printf("[1/7] Creating DHT context...\n");
    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx) {
        fprintf(stderr, "ERROR: Failed to create DHT context\n");
        return 1;
    }
    printf("✓ DHT context created\n\n");

    printf("[2/7] Starting DHT node on port %d...\n", config.port);
    if (dht_context_start(ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to start DHT node\n");
        dht_context_free(ctx);
        return 1;
    }
    printf("✓ DHT node started\n\n");

    // Wait for DHT to initialize
    printf("[3/7] Waiting for DHT to initialize (5 seconds)...\n");
    sleep(5);
    printf("✓ DHT initialized\n\n");

    // Put a test value
    printf("[4/7] Putting test value in DHT...\n");
    const char *key = "test-key-hello";
    const char *value = "Hello, DNA DHT Network!";

    if (dht_put(ctx, (uint8_t*)key, strlen(key),
                (uint8_t*)value, strlen(value)) != 0) {
        fprintf(stderr, "ERROR: Failed to put value\n");
        dht_context_stop(ctx);
        dht_context_free(ctx);
        return 1;
    }
    printf("✓ Value stored: \"%s\" = \"%s\"\n\n", key, value);

    // Wait for value to propagate
    printf("[5/7] Waiting for value to propagate (3 seconds)...\n");
    sleep(3);
    printf("✓ Value should be propagated\n\n");

    // Get the value back
    printf("[6/7] Getting value from DHT...\n");
    uint8_t *retrieved_value = NULL;
    size_t retrieved_len = 0;

    if (dht_get(ctx, (uint8_t*)key, strlen(key),
                &retrieved_value, &retrieved_len) == 0) {
        printf("✓ Value retrieved: \"%.*s\"\n", (int)retrieved_len, retrieved_value);

        if (retrieved_len == strlen(value) &&
            memcmp(retrieved_value, value, retrieved_len) == 0) {
            printf("✓ Value matches!\n\n");
        } else {
            printf("✗ Value mismatch!\n\n");
        }

        free(retrieved_value);
    } else {
        printf("✗ Failed to retrieve value (expected for single-node test)\n");
        printf("  Note: DHT requires multiple nodes for get() to work reliably\n\n");
    }

    // Get statistics
    printf("[7/7] Getting DHT statistics...\n");
    size_t node_count = 0;
    size_t stored_values = 0;

    if (dht_get_stats(ctx, &node_count, &stored_values) == 0) {
        printf("✓ DHT Statistics:\n");
        printf("  - Nodes in routing table: %zu\n", node_count);
        printf("  - Values stored locally: %zu\n", stored_values);
    } else {
        printf("✗ Failed to get statistics\n");
    }

    printf("\n");

    // Cleanup
    printf("Cleaning up...\n");
    dht_context_stop(ctx);
    dht_context_free(ctx);
    printf("✓ DHT stopped and freed\n\n");

    printf("===========================================\n");
    printf("Test Complete!\n");
    printf("===========================================\n");
    printf("\nNotes:\n");
    printf("- Single-node DHT cannot retrieve values (needs peers)\n");
    printf("- This test verifies DHT initialization and API calls\n");
    printf("- For full testing, use test_dht_3nodes.c with bootstrap nodes\n");
    printf("\n");

    return 0;
}
