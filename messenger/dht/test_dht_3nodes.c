/**
 * 3-Node DHT Network Test
 *
 * Tests DHT network with 3 bootstrap nodes:
 * - US node: Puts a value
 * - EU-1 node: Gets the value
 * - EU-2 node: Also gets the value
 *
 * Usage:
 *   Node 1 (putter):  ./test_dht_3nodes us-1 154.38.182.161:4000,164.68.105.227:4000,164.68.116.180:4000 put
 *   Node 2 (getter):  ./test_dht_3nodes eu-1 154.38.182.161:4000,164.68.105.227:4000,164.68.116.180:4000 get
 *   Node 3 (getter):  ./test_dht_3nodes eu-2 154.38.182.161:4000,164.68.105.227:4000,164.68.116.180:4000 get
 */

#include "dht_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void parse_bootstrap_nodes(const char *bootstrap_str, dht_config_t *config) {
    char *str_copy = strdup(bootstrap_str);
    char *token = strtok(str_copy, ",");

    config->bootstrap_count = 0;
    while (token != NULL && config->bootstrap_count < 5) {
        strncpy(config->bootstrap_nodes[config->bootstrap_count], token, 255);
        config->bootstrap_count++;
        token = strtok(NULL, ",");
    }

    free(str_copy);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <node-name> <bootstrap-nodes> <put|get>\n", argv[0]);
        fprintf(stderr, "Example: %s us-1 154.38.182.161:4000,164.68.105.227:4000 put\n", argv[0]);
        return 1;
    }

    const char *node_name = argv[1];
    const char *bootstrap_str = argv[2];
    const char *mode = argv[3];

    printf("===========================================\n");
    printf("DNA Messenger - 3-Node DHT Network Test\n");
    printf("===========================================\n\n");
    printf("Node: %s\n", node_name);
    printf("Mode: %s\n\n", mode);

    // Configuration
    dht_config_t config;
    memset(&config, 0, sizeof(config));

    config.port = 4000;
    config.is_bootstrap = true;
    strncpy(config.identity, node_name, sizeof(config.identity) - 1);

    // Parse bootstrap nodes
    parse_bootstrap_nodes(bootstrap_str, &config);

    printf("Bootstrap nodes (%zu):\n", config.bootstrap_count);
    for (size_t i = 0; i < config.bootstrap_count; i++) {
        printf("  %zu. %s\n", i + 1, config.bootstrap_nodes[i]);
    }
    printf("\n");

    // Create DHT context
    printf("[1/5] Creating DHT context...\n");
    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx) {
        fprintf(stderr, "ERROR: Failed to create DHT context\n");
        return 1;
    }
    printf("✓ DHT context created\n\n");

    // Start DHT node
    printf("[2/5] Starting DHT node on port %d...\n", config.port);
    if (dht_context_start(ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to start DHT node\n");
        dht_context_free(ctx);
        return 1;
    }
    printf("✓ DHT node started\n\n");

    // Wait for DHT to connect to network
    printf("[3/5] Waiting for DHT network connection (10 seconds)...\n");
    sleep(10);

    // Check if ready
    if (dht_context_is_ready(ctx)) {
        printf("✓ DHT connected to network\n\n");
    } else {
        printf("⚠ DHT not fully connected yet (may still work)\n\n");
    }

    // Get statistics
    size_t node_count = 0;
    size_t stored_values = 0;
    if (dht_get_stats(ctx, &node_count, &stored_values) == 0) {
        printf("DHT Statistics:\n");
        printf("  - Nodes in routing table: %zu\n", node_count);
        printf("  - Values stored locally: %zu\n\n", stored_values);
    }

    const char *test_key = "dna-3node-test";
    const char *test_value = "Hello from DNA 3-Node DHT Network!";

    if (strcmp(mode, "put") == 0) {
        // PUT mode: Store a value
        printf("[4/5] Putting test value in DHT...\n");
        if (dht_put(ctx, (uint8_t*)test_key, strlen(test_key),
                    (uint8_t*)test_value, strlen(test_value)) != 0) {
            fprintf(stderr, "ERROR: Failed to put value\n");
            dht_context_stop(ctx);
            dht_context_free(ctx);
            return 1;
        }
        printf("✓ Value stored: \"%s\" = \"%s\"\n\n", test_key, test_value);

        printf("[5/5] Waiting for value to propagate (5 seconds)...\n");
        sleep(5);
        printf("✓ Value should be propagated to network\n\n");

    } else if (strcmp(mode, "get") == 0) {
        // GET mode: Retrieve the value
        printf("[4/5] Waiting for network to stabilize (15 seconds)...\n");
        sleep(15);
        printf("✓ Network should be stable\n\n");

        printf("[5/5] Getting value from DHT...\n");
        uint8_t *retrieved_value = NULL;
        size_t retrieved_len = 0;

        if (dht_get(ctx, (uint8_t*)test_key, strlen(test_key),
                    &retrieved_value, &retrieved_len) == 0) {
            printf("✓ Value retrieved: \"%.*s\"\n", (int)retrieved_len, retrieved_value);

            if (retrieved_len == strlen(test_value) &&
                memcmp(retrieved_value, test_value, retrieved_len) == 0) {
                printf("✓ Value matches expected!\n\n");
                printf("===========================================\n");
                printf("SUCCESS! 3-Node DHT Network is working!\n");
                printf("===========================================\n\n");
            } else {
                printf("✗ Value mismatch!\n\n");
            }

            free(retrieved_value);
        } else {
            printf("✗ Failed to retrieve value\n");
            printf("  This may indicate network connectivity issues\n\n");
        }

    } else {
        fprintf(stderr, "ERROR: Invalid mode '%s' (use 'put' or 'get')\n", mode);
        dht_context_stop(ctx);
        dht_context_free(ctx);
        return 1;
    }

    // Cleanup
    printf("Cleaning up...\n");
    dht_context_stop(ctx);
    dht_context_free(ctx);
    printf("✓ DHT stopped and freed\n\n");

    return 0;
}
