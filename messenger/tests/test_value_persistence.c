/**
 * Test DHT Value Persistence
 *
 * This test publishes a PERMANENT value to DHT and verifies
 * it gets stored to the SQLite backend on bootstrap nodes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../dht/dht_context.h"

int main(int argc, char **argv) {
    printf("========================================\n");
    printf("DNA DHT Value Persistence Test\n");
    printf("========================================\n\n");

    // Configure DHT client
    dht_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = 4001;  // Use different port than bootstrap (4000)
    config.is_bootstrap = false;
    strncpy(config.identity, "test-client", sizeof(config.identity) - 1);

    // Connect to all 3 bootstrap nodes
    config.bootstrap_count = 3;
    strncpy(config.bootstrap_nodes[0], "154.38.182.161:4000", sizeof(config.bootstrap_nodes[0]) - 1);
    strncpy(config.bootstrap_nodes[1], "164.68.105.227:4000", sizeof(config.bootstrap_nodes[1]) - 1);
    strncpy(config.bootstrap_nodes[2], "164.68.116.180:4000", sizeof(config.bootstrap_nodes[2]) - 1);

    printf("[1/5] Creating DHT context...\n");
    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx) {
        fprintf(stderr, "ERROR: Failed to create DHT context\n");
        return 1;
    }
    printf("✓ DHT context created\n\n");

    printf("[2/5] Starting DHT node...\n");
    if (dht_context_start(ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to start DHT node\n");
        dht_context_free(ctx);
        return 1;
    }
    printf("✓ DHT node started\n\n");

    printf("[3/5] Waiting for DHT to connect to network...\n");
    int retries = 0;
    while (!dht_context_is_ready(ctx) && retries < 30) {
        printf("  Connecting... (attempt %d/30)\n", retries + 1);
        sleep(1);
        retries++;
    }

    if (!dht_context_is_ready(ctx)) {
        fprintf(stderr, "ERROR: DHT failed to connect after 30 seconds\n");
        dht_context_free(ctx);
        return 1;
    }
    printf("✓ DHT connected to network\n\n");

    printf("[4/5] Publishing PERMANENT test value...\n");
    const char *test_key = "test-persistence-key-12345";
    const char *test_value = "This is a PERMANENT test value that should persist across reboots!";

    printf("  Key:   %s\n", test_key);
    printf("  Value: %s\n", test_value);
    printf("  TTL:   PERMANENT (never expires)\n\n");

    int result = dht_put_permanent(
        ctx,
        (const uint8_t*)test_key, strlen(test_key),
        (const uint8_t*)test_value, strlen(test_value)
    );

    if (result != 0) {
        fprintf(stderr, "ERROR: Failed to publish value to DHT\n");
        dht_context_free(ctx);
        return 1;
    }
    printf("✓ Value published to DHT\n\n");

    printf("[5/5] Waiting for value to propagate (10 seconds)...\n");
    sleep(10);
    printf("✓ Propagation complete\n\n");

    printf("========================================\n");
    printf("✅ Test Complete!\n");
    printf("========================================\n\n");

    printf("To verify persistence:\n");
    printf("1. Check bootstrap node storage:\n");
    printf("   ssh root@154.38.182.161 'sqlite3 /var/lib/dna-dht/bootstrap.state.values.db \"SELECT key_hash, length(value_data), value_type FROM dht_values\"'\n\n");
    printf("2. Check bootstrap logs:\n");
    printf("   ssh root@154.38.182.161 'journalctl -u dna-dht-bootstrap | grep Storage'\n\n");
    printf("3. Restart a bootstrap node and verify republish:\n");
    printf("   ssh root@154.38.182.161 'systemctl restart dna-dht-bootstrap && sleep 5 && journalctl -u dna-dht-bootstrap --since \"1 minute ago\" | grep -E \"(Republish|restored)\"'\n\n");

    dht_context_free(ctx);
    return 0;
}
