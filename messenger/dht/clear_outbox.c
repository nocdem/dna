/**
 * Clear specific sender's outbox to recipient
 * Usage: ./clear_outbox <sender_fingerprint> <recipient_fingerprint>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "core/dht_context.h"
#include "shared/dht_offline_queue.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <sender_fingerprint> <recipient_fingerprint>\n", argv[0]);
        printf("Example: %s deus dei\n", argv[0]);
        return 1;
    }

    const char *sender = argv[1];
    const char *recipient = argv[2];

    printf("Clearing sender's outbox (Model E):\n");
    printf("  Sender: %s\n", sender);
    printf("  Recipient: %s\n", recipient);
    printf("\n");

    // Initialize DHT
    dht_config_t config = {0};
    config.port = 4008;  // Different port to avoid conflicts
    config.is_bootstrap = false;
    snprintf(config.identity, sizeof(config.identity), "clear_tool");

    // Add bootstrap nodes
    snprintf(config.bootstrap_nodes[0], 256, "154.38.182.161:4000");
    snprintf(config.bootstrap_nodes[1], 256, "164.68.105.227:4000");
    snprintf(config.bootstrap_nodes[2], 256, "164.68.116.180:4000");
    config.bootstrap_count = 3;

    printf("[1] Initializing DHT...\n");
    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx) {
        fprintf(stderr, "Failed to create DHT context\n");
        return 1;
    }

    if (dht_context_start(ctx) != 0) {
        fprintf(stderr, "Failed to start DHT\n");
        dht_context_free(ctx);
        return 1;
    }

    printf("[2] Waiting for DHT bootstrap (10 seconds)...\n");
    sleep(10);

    if (!dht_context_is_ready(ctx)) {
        printf("Warning: DHT may not be fully connected\n");
    }

    // Generate outbox key
    uint8_t outbox_key[64];
    dht_generate_outbox_key(sender, recipient, outbox_key);

    printf("[3] Outbox key (SHA3-512):\n");
    printf("    ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", outbox_key[i]);
    }
    printf("\n\n");

    // Delete from DHT
    printf("[4] Deleting from DHT...\n");
    int result = dht_delete(ctx, outbox_key, 64);

    if (result == 0) {
        printf("✓ Outbox cleared successfully\n");
    } else {
        printf("✗ Failed to clear outbox (may not exist or network error)\n");
    }

    // Cleanup
    dht_context_free(ctx);
    return 0;
}
