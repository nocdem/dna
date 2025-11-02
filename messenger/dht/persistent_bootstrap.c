#include "dht_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static dht_context_t *global_ctx = NULL;

void signal_handler(int sig) {
    printf("\nShutting down...\n");
    if (global_ctx) {
        dht_context_stop(global_ctx);
        dht_context_free(global_ctx);
    }
    exit(0);
}

int main(int argc, char **argv) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("===========================================\n");
    printf("DNA Messenger - Persistent DHT Bootstrap Node\n");
    printf("===========================================\n\n");

    dht_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = 4000;
    config.is_bootstrap = true;
    strncpy(config.identity, "bootstrap-node", sizeof(config.identity) - 1);
    config.bootstrap_count = 0;  // First node - no bootstrap

    // Enable disk persistence for bootstrap nodes (hybrid approach)
    strncpy(config.persistence_path, "/var/lib/dna-dht/bootstrap.state",
            sizeof(config.persistence_path) - 1);

    printf("[1/3] Creating DHT context...\n");
    global_ctx = dht_context_new(&config);
    if (!global_ctx) {
        fprintf(stderr, "ERROR: Failed to create DHT context\n");
        return 1;
    }
    printf("✓ DHT context created\n\n");

    printf("[2/3] Starting DHT node on port %d...\n", config.port);
    if (dht_context_start(global_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to start DHT node\n");
        dht_context_free(global_ctx);
        return 1;
    }
    printf("✓ DHT node started\n\n");

    printf("[3/3] DHT Bootstrap node is now running...\n");
    printf("Press Ctrl+C to stop\n\n");

    // Run forever
    while (1) {
        sleep(10);
        
        // Print stats every 10 seconds
        size_t node_count = 0;
        size_t stored_values = 0;
        if (dht_get_stats(global_ctx, &node_count, &stored_values) == 0) {
            printf("[Stats] Nodes: %zu, Values: %zu\n", node_count, stored_values);
        }
    }

    return 0;
}
