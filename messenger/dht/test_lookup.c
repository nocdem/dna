#include "dht_context.h"
#include "dht_keyserver.h"
#include "dna_profile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name_or_fingerprint>\n", argv[0]);
        return 1;
    }

    const char *lookup_target = argv[1];

    printf("=== DHT Lookup Test ===\n");
    printf("Target: %s\n\n", lookup_target);

    // Setup DHT
    dht_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = 4002;
    config.is_bootstrap = false;
    strncpy(config.identity, "test-lookup", sizeof(config.identity) - 1);

    // Bootstrap to public nodes
    config.bootstrap_count = 3;
    strncpy(config.bootstrap_nodes[0], "154.38.182.161:4000", sizeof(config.bootstrap_nodes[0]) - 1);
    strncpy(config.bootstrap_nodes[1], "164.68.105.227:4000", sizeof(config.bootstrap_nodes[1]) - 1);
    strncpy(config.bootstrap_nodes[2], "164.68.116.180:4000", sizeof(config.bootstrap_nodes[2]) - 1);

    printf("[1/4] Creating DHT context...\n");
    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx) {
        fprintf(stderr, "ERROR: Failed to create context\n");
        return 1;
    }

    printf("[2/4] Starting DHT node...\n");
    if (dht_context_start(ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to start node\n");
        return 1;
    }

    printf("[3/4] Waiting for DHT to connect...\n");
    int retries = 0;
    while (!dht_context_is_ready(ctx) && retries < 30) {
        sleep(1);
        retries++;
        if (retries % 5 == 0) {
            printf("  Waiting... %d/30\n", retries);
        }
    }

    if (!dht_context_is_ready(ctx)) {
        fprintf(stderr, "ERROR: DHT not ready after 30 seconds\n");
        return 1;
    }

    printf("✓ DHT connected\n\n");

    // Lookup by name first
    printf("[4/4] Looking up '%s'...\n", lookup_target);
    char *fingerprint = NULL;
    int ret = dna_lookup_by_name(ctx, lookup_target, &fingerprint);

    if (ret == 0 && fingerprint) {
        printf("✓ Name found!\n");
        printf("  Fingerprint: %s\n\n", fingerprint);
    } else if (strlen(lookup_target) == 128) {
        // Maybe it's already a fingerprint
        printf("  Not found as name, trying as fingerprint...\n");
        fingerprint = strdup(lookup_target);
    } else {
        printf("✗ Name not found in DHT\n");
        dht_context_stop(ctx);
        dht_context_free(ctx);
        return 1;
    }

    // Load full identity/profile
    printf("Loading full identity from DHT...\n");
    dna_unified_identity_t *identity = NULL;
    ret = dna_load_identity(ctx, fingerprint, &identity);

    if (ret != 0 || !identity) {
        printf("✗ Identity not found or verification failed\n");
        free(fingerprint);
        dht_context_stop(ctx);
        dht_context_free(ctx);
        return 1;
    }

    printf("✓ Identity loaded and verified!\n\n");

    // Print metadata
    printf("========================================\n");
    printf("IDENTITY METADATA\n");
    printf("========================================\n");
    printf("Fingerprint:     %s\n", identity->fingerprint);

    if (identity->has_registered_name) {
        printf("Registered Name: %s\n", identity->registered_name);
        printf("Name Registered: %lu\n", identity->name_registered_at);
        printf("Name Expires:    %lu\n", identity->name_expires_at);
        printf("Registration TX: %s\n", identity->registration_tx_hash);
        printf("Network:         %s\n", identity->registration_network);
        printf("Name Version:    %u\n", identity->name_version);
    } else {
        printf("Registered Name: (none)\n");
    }

    printf("\n--- Wallet Addresses ---\n");
    if (identity->wallets.backbone[0]) printf("Backbone: %s\n", identity->wallets.backbone);
    if (identity->wallets.kelvpn[0]) printf("KelVPN:   %s\n", identity->wallets.kelvpn);
    if (identity->wallets.subzero[0]) printf("Subzero:  %s\n", identity->wallets.subzero);
    if (identity->wallets.riemann[0]) printf("Riemann:  %s\n", identity->wallets.riemann);
    if (identity->wallets.btc[0]) printf("Bitcoin:  %s\n", identity->wallets.btc);
    if (identity->wallets.eth[0]) printf("Ethereum: %s\n", identity->wallets.eth);

    printf("\n--- Social Links ---\n");
    if (identity->socials.x[0]) printf("X (Twitter): %s\n", identity->socials.x);
    if (identity->socials.telegram[0]) printf("Telegram:    %s\n", identity->socials.telegram);
    if (identity->socials.github[0]) printf("GitHub:      %s\n", identity->socials.github);

    printf("\n--- Profile ---\n");
    if (identity->bio[0]) {
        printf("Bio: %s\n", identity->bio);
    } else {
        printf("Bio: (empty)\n");
    }

    if (identity->profile_picture_ipfs[0]) {
        printf("Profile Picture: %s\n", identity->profile_picture_ipfs);
    }

    printf("\n--- Metadata ---\n");
    printf("Timestamp: %lu\n", identity->timestamp);
    printf("Version:   %u\n", identity->version);

    printf("========================================\n");

    // Cleanup
    dna_identity_free(identity);
    free(fingerprint);
    dht_context_stop(ctx);
    dht_context_free(ctx);

    return 0;
}
