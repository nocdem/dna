/**
 * Query specific sender's outbox to recipient
 * Usage: ./query_outbox <sender_fingerprint> <recipient_fingerprint>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dht_context.h"
#include "dht_offline_queue.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <sender_fingerprint> <recipient_fingerprint>\n", argv[0]);
        printf("Example: %s deus dei\n", argv[0]);
        return 1;
    }

    const char *sender = argv[1];
    const char *recipient = argv[2];

    printf("Querying sender's outbox (Model E):\n");
    printf("  Sender: %s\n", sender);
    printf("  Recipient: %s\n", recipient);
    printf("\n");

    // Initialize DHT
    dht_config_t config = {0};
    config.port = 4008;  // Different port to avoid conflicts
    config.is_bootstrap = false;
    snprintf(config.identity, sizeof(config.identity), "query_tool");

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

    // Query DHT
    printf("[4] Querying DHT...\n");
    uint8_t *data = NULL;
    size_t len = 0;

    int result = dht_get(ctx, outbox_key, 64, &data, &len);

    if (result == 0 && data && len > 0) {
        printf("✓ Found outbox data: %zu bytes\n\n", len);

        // Try to deserialize
        dht_offline_message_t *messages = NULL;
        size_t count = 0;

        if (dht_deserialize_messages(data, len, &messages, &count) == 0) {
            printf("Deserialized %zu message(s):\n", count);
            for (size_t i = 0; i < count; i++) {
                printf("  [%zu] From: %s\n", i+1, messages[i].sender);
                printf("       To: %s\n", messages[i].recipient);
                printf("       Timestamp: %lu\n", messages[i].timestamp);
                printf("       Expiry: %lu\n", messages[i].expiry);
                printf("       Size: %zu bytes\n", messages[i].ciphertext_len);
                printf("\n");
            }
            dht_offline_messages_free(messages, count);
        } else {
            printf("Failed to deserialize messages\n");
        }

        free(data);
    } else {
        printf("✗ No messages in this outbox (empty or not found)\n");
    }

    // Cleanup
    dht_context_free(ctx);
    return 0;
}
