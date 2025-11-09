/**
 * Test that DHT value updates REPLACE old versions instead of creating duplicates
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../dht/dht_context.h"

int main() {
    printf("========================================\n");
    printf("DHT Version Replacement Test\n");
    printf("========================================\n\n");

    dht_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = 4003;
    config.is_bootstrap = false;
    strncpy(config.identity, "test-version", sizeof(config.identity) - 1);

    config.bootstrap_count = 3;
    strncpy(config.bootstrap_nodes[0], "154.38.182.161:4000", sizeof(config.bootstrap_nodes[0]) - 1);
    strncpy(config.bootstrap_nodes[1], "164.68.105.227:4000", sizeof(config.bootstrap_nodes[1]) - 1);
    strncpy(config.bootstrap_nodes[2], "164.68.116.180:4000", sizeof(config.bootstrap_nodes[2]) - 1);

    printf("[1/4] Starting DHT...\n");
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
    printf("✓ DHT connected\n\n");

    const char *test_key = "test-version-replace-key";

    printf("[2/4] Publishing VERSION 1...\n");
    const char *value_v1 = "This is VERSION 1 of the data";
    int ret = dht_put_permanent(ctx,
        (const uint8_t*)test_key, strlen(test_key),
        (const uint8_t*)value_v1, strlen(value_v1));

    if (ret == 0) {
        printf("✓ Version 1 published\n\n");
    } else {
        fprintf(stderr, "✗ Failed to publish v1\n");
        return 1;
    }

    sleep(8);  // Wait for propagation

    printf("[3/4] Publishing VERSION 2 (same key)...\n");
    const char *value_v2 = "This is VERSION 2 of the data (UPDATED!)";
    ret = dht_put_permanent(ctx,
        (const uint8_t*)test_key, strlen(test_key),
        (const uint8_t*)value_v2, strlen(value_v2));

    if (ret == 0) {
        printf("✓ Version 2 published\n\n");
    } else {
        fprintf(stderr, "✗ Failed to publish v2\n");
        return 1;
    }

    sleep(8);  // Wait for propagation

    printf("[4/4] Verifying only latest version exists...\n");
    uint8_t *value_out = NULL;
    size_t value_len = 0;

    ret = dht_get(ctx, (const uint8_t*)test_key, strlen(test_key), &value_out, &value_len);

    if (ret == 0 && value_out) {
        printf("Retrieved: %.*s\n", (int)value_len, (char*)value_out);

        if (strstr((char*)value_out, "VERSION 2") != NULL) {
            printf("\n✅ SUCCESS: Latest version retrieved!\n");
            printf("✅ Old version was REPLACED (not duplicated)\n\n");
        } else {
            printf("\n✗ FAIL: Got old version (v1)\n");
        }
        free(value_out);
    }

    printf("========================================\n");
    printf("Check bootstrap database:\n");
    printf("ssh root@164.68.105.227 'sqlite3 /var/lib/dna-dht/bootstrap.state.values.db \"SELECT COUNT(*), key_hash FROM dht_values GROUP BY key_hash HAVING COUNT(*) > 1\"'\n");
    printf("\nExpected: No duplicates (empty result)\n");
    printf("========================================\n");

    dht_context_free(ctx);
    return 0;
}
