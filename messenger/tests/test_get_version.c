/**
 * Retrieve the test key to see which version is in DHT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../dht/dht_context.h"

int main() {
    dht_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = 4004;
    config.is_bootstrap = false;
    strncpy(config.identity, "test-get", sizeof(config.identity) - 1);

    config.bootstrap_count = 3;
    strncpy(config.bootstrap_nodes[0], "154.38.182.161:4000", sizeof(config.bootstrap_nodes[0]) - 1);
    strncpy(config.bootstrap_nodes[1], "164.68.105.227:4000", sizeof(config.bootstrap_nodes[1]) - 1);
    strncpy(config.bootstrap_nodes[2], "164.68.116.180:4000", sizeof(config.bootstrap_nodes[2]) - 1);

    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx || dht_context_start(ctx) != 0) {
        return 1;
    }

    while (!dht_context_is_ready(ctx)) {
        sleep(1);
    }

    const char *test_key = "test-version-replace-key";

    printf("Retrieving all versions from DHT network...\n\n");

    // Get all values
    uint8_t **values = NULL;
    size_t *lengths = NULL;
    size_t count = 0;

    int ret = dht_get_all(ctx, (const uint8_t*)test_key, strlen(test_key), &values, &lengths, &count);

    if (ret == 0 && count > 0) {
        printf("Found %zu version(s) in DHT:\n", count);
        for (size_t i = 0; i < count; i++) {
            printf("  Version %zu: %.*s\n", i+1, (int)lengths[i], (char*)values[i]);
            free(values[i]);
        }
        free(values);
        free(lengths);
    } else {
        printf("No values found (may still be propagating)\n");
    }

    dht_context_free(ctx);
    return 0;
}
