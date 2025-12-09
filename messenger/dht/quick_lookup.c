#include "core/dht_context.h"
#include "dht_keyserver.h"
#include "dna_profile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

static int is_fingerprint(const char *str) {
    // Fingerprint is 128 hex chars (64 bytes)
    if (strlen(str) != 128) return 0;
    for (int i = 0; i < 128; i++) {
        if (!isxdigit(str[i])) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *query = (argc > 1) ? argv[1] : "deus";
    int is_fp = is_fingerprint(query);

    printf("=== DHT Lookup: %s (%s) ===\n\n", query, is_fp ? "fingerprint" : "name");

    dht_config_t config = {0};
    config.port = 4006;
    config.is_bootstrap = false;
    strncpy(config.identity, "lookup", sizeof(config.identity) - 1);
    config.bootstrap_count = 3;
    strncpy(config.bootstrap_nodes[0], "154.38.182.161:4000", sizeof(config.bootstrap_nodes[0]) - 1);
    strncpy(config.bootstrap_nodes[1], "164.68.105.227:4000", sizeof(config.bootstrap_nodes[1]) - 1);
    strncpy(config.bootstrap_nodes[2], "164.68.116.180:4000", sizeof(config.bootstrap_nodes[2]) - 1);

    dht_context_t *ctx = dht_context_new(&config);
    dht_context_start(ctx);

    printf("Waiting for DHT...\n");
    int i = 0;
    while (!dht_context_is_ready(ctx) && i++ < 30) sleep(1);

    char *fp = NULL;

    if (is_fp) {
        // Direct fingerprint lookup
        fp = strdup(query);
        printf("\nUsing fingerprint: %s\n", fp);
    } else {
        // Name to fingerprint lookup
        dna_lookup_by_name(ctx, query, &fp);
        if (fp) {
            printf("\nName resolved: %s → %s\n", query, fp);
        } else {
            printf("Name not found\n");
        }
    }

    if (fp) {
        dna_unified_identity_t *id = NULL;
        dna_load_identity(ctx, fp, &id);

        if (id) {
            printf("\n========================================\n");
            printf("Fingerprint: %s\n", fp);
            printf("Name: %s\n", id->has_registered_name ? id->registered_name : "(none)");
            printf("Registered: %lu\n", id->name_registered_at);
            printf("Expires: %lu\n", id->name_expires_at);
            printf("Version: %u\n", id->version);
            printf("Timestamp: %lu\n", id->timestamp);

            printf("\n--- Public Keys ---\n");
            printf("Dilithium5 pubkey (2592 bytes): ");
            for (int i = 0; i < 32; i++) printf("%02x", id->dilithium_pubkey[i]);
            printf("...");
            for (int i = 2560; i < 2592; i++) printf("%02x", id->dilithium_pubkey[i]);
            printf("\n");

            printf("Kyber1024 pubkey (1568 bytes): ");
            for (int i = 0; i < 32; i++) printf("%02x", id->kyber_pubkey[i]);
            printf("...");
            for (int i = 1536; i < 1568; i++) printf("%02x", id->kyber_pubkey[i]);
            printf("\n");

            printf("\n--- Wallet Addresses ---\n");
            if (id->wallets.backbone[0]) printf("Backbone: %s\n", id->wallets.backbone);
            if (id->wallets.kelvpn[0]) printf("KelVPN: %s\n", id->wallets.kelvpn);
            if (id->wallets.btc[0]) printf("Bitcoin: %s\n", id->wallets.btc);
            if (id->wallets.eth[0]) printf("Ethereum: %s\n", id->wallets.eth);
            if (id->wallets.sol[0]) printf("Solana: %s\n", id->wallets.sol);

            printf("\n--- Social Links ---\n");
            if (id->socials.x[0]) printf("X: %s\n", id->socials.x);
            if (id->socials.telegram[0]) printf("Telegram: %s\n", id->socials.telegram);
            if (id->socials.github[0]) printf("GitHub: %s\n", id->socials.github);

            printf("\n--- Profile ---\n");
            if (id->bio[0]) printf("Bio: %s\n", id->bio);

            printf("\n--- Avatar ---\n");
            if (id->avatar_base64[0] != '\0') {
                size_t avatar_len = strlen(id->avatar_base64);
                printf("✓ Avatar found: %zu bytes base64\n", avatar_len);
                printf("  First 80 chars: %.80s...\n", id->avatar_base64);
                printf("  Last 80 chars: ...%s\n", id->avatar_base64 + (avatar_len > 80 ? avatar_len - 80 : 0));
            } else {
                printf("✗ No avatar\n");
            }

            printf("========================================\n");
            dna_identity_free(id);
        }

        // Offline messages check disabled for quick lookup
        // (function signature changed, not needed for profile verification)

        free(fp);
    }

    dht_context_stop(ctx);
    dht_context_free(ctx);
    return 0;
}
