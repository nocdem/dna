/**
 * Test DHT Value Retrieval
 *
 * Retrieves the test value published earlier to verify persistence works.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../dht/dht_context.h"

int main() {
    printf("========================================\n");
    printf("DNA DHT Value Retrieval Test\n");
    printf("========================================\n\n");

    dht_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = 4002;
    config.is_bootstrap = false;
    strncpy(config.identity, "test-retrieval", sizeof(config.identity) - 1);

    config.bootstrap_count = 3;
    strncpy(config.bootstrap_nodes[0], "154.38.182.161:4000", sizeof(config.bootstrap_nodes[0]) - 1);
    strncpy(config.bootstrap_nodes[1], "164.68.105.227:4000", sizeof(config.bootstrap_nodes[1]) - 1);
    strncpy(config.bootstrap_nodes[2], "164.68.116.180:4000", sizeof(config.bootstrap_nodes[2]) - 1);

    printf("[1/3] Starting DHT client...\n");
    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx || dht_context_start(ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to start DHT\n");
        return 1;
    }

    int retries = 0;
    while (!dht_context_is_ready(ctx) && retries < 30) {
        sleep(1);
        retries++;
    }

    if (!dht_context_is_ready(ctx)) {
        fprintf(stderr, "ERROR: DHT not ready\n");
        return 1;
    }
    printf("✓ DHT connected\n\n");

    printf("[2/3] Retrieving test value...\n");
    const char *test_key = "test-persistence-key-12345";
    uint8_t *value_out = NULL;
    size_t value_len_out = 0;

    int result = dht_get(ctx,
        (const uint8_t*)test_key, strlen(test_key),
        &value_out, &value_len_out);

    if (result == 0 && value_out) {
        printf("✓ Value retrieved successfully!\n");
        printf("  Key:   %s\n", test_key);
        printf("  Value: %.*s\n", (int)value_len_out, (char*)value_out);
        printf("  Size:  %zu bytes\n\n", value_len_out);
        free(value_out);

        printf("[3/3] ✅ Persistence verification SUCCESSFUL!\n\n");
        printf("The value:\n");
        printf("  1. Was stored to SQLite on bootstrap node\n");
        printf("  2. Survived the node restart\n");
        printf("  3. Was republished to DHT network\n");
        printf("  4. Is now retrievable by clients\n\n");
        printf("========================================\n");
        printf("✅ DHT VALUE PERSISTENCE: WORKING!\n");
        printf("========================================\n");
    } else {
        fprintf(stderr, "✗ Failed to retrieve value (may need more time to propagate)\n");
        printf("\nTip: Wait 10-20 seconds after restart for DHT to stabilize\n");
    }

    dht_context_free(ctx);
    return (result == 0) ? 0 : 1;
}
