#include "core/dht_context.h"
#include "dht_keyserver.h"
#include "dna_profile.h"
#include "shared/dht_offline_queue.h"
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
            if (id->wallets.subzero[0]) printf("Subzero: %s\n", id->wallets.subzero);
            if (id->wallets.btc[0]) printf("Bitcoin: %s\n", id->wallets.btc);
            if (id->wallets.eth[0]) printf("Ethereum: %s\n", id->wallets.eth);

            printf("\n--- Social Links ---\n");
            if (id->socials.x[0]) printf("X: %s\n", id->socials.x);
            if (id->socials.telegram[0]) printf("Telegram: %s\n", id->socials.telegram);
            if (id->socials.github[0]) printf("GitHub: %s\n", id->socials.github);

            printf("\n--- Profile ---\n");
            if (id->bio[0]) printf("Bio: %s\n", id->bio);

            printf("========================================\n");
            dna_identity_free(id);
        }

        // Check for offline messages
        printf("\n--- Offline Messages ---\n");
        dht_offline_message_t *messages = NULL;
        size_t msg_count = 0;
        int ret = dht_retrieve_queued_messages(ctx, fp, &messages, &msg_count);

        if (ret == 0 && msg_count > 0) {
            printf("📬 Found %zu offline message(s):\n\n", msg_count);
            for (size_t i = 0; i < msg_count; i++) {
                printf("  Message #%zu:\n", i + 1);

                // Try to resolve sender identity
                char *sender_name = NULL;
                if (strlen(messages[i].sender) == 128) {
                    // It's a fingerprint, try reverse lookup
                    dna_unified_identity_t *sender_id = NULL;
                    if (dna_load_identity(ctx, messages[i].sender, &sender_id) == 0 && sender_id) {
                        if (sender_id->has_registered_name) {
                            sender_name = strdup(sender_id->registered_name);
                        }
                        dna_identity_free(sender_id);
                    }
                }

                if (sender_name) {
                    printf("    From: %s (%s...%s)\n", sender_name,
                           messages[i].sender, messages[i].sender + 118);
                    free(sender_name);
                } else {
                    printf("    From: %s\n", messages[i].sender);
                }

                printf("    To: %s\n", messages[i].recipient);
                printf("    Timestamp: %lu\n", messages[i].timestamp);
                printf("    Expires: %lu\n", messages[i].expiry);
                printf("    Ciphertext size: %zu bytes\n", messages[i].ciphertext_len);
                printf("    Ciphertext (first 32 bytes): ");
                size_t display_len = messages[i].ciphertext_len < 32 ? messages[i].ciphertext_len : 32;
                for (size_t j = 0; j < display_len; j++) {
                    printf("%02x", messages[i].ciphertext[j]);
                }
                if (messages[i].ciphertext_len > 32) printf("...");
                printf("\n\n");
            }
            dht_offline_messages_free(messages, msg_count);
        } else if (ret == 0 && msg_count == 0) {
            printf("✓ No offline messages\n");
        } else {
            printf("✗ Failed to retrieve offline messages (error %d)\n", ret);
        }

        free(fp);
    }

    dht_context_stop(ctx);
    dht_context_free(ctx);
    return 0;
}
