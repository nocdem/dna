/*
 * DNA Messenger - CLI Client
 * Post-quantum end-to-end encrypted messaging
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../messenger.h"
#include "../dna_config.h"

void print_main_menu(void) {
    printf("\n");
    printf("=========================================\n");
    printf(" DNA Messenger\n");
    printf("=========================================\n");
    printf("\n");
    printf("1. Create new identity\n");
    printf("2. Choose existing identity\n");
    printf("3. Lookup identity (from server)\n");
    printf("4. Configure server\n");
    printf("5. Exit\n");
    printf("\n");
    printf("Choice: ");
}

void print_user_menu(const char *identity) {
    printf("\n");
    printf("=========================================\n");
    printf(" DNA Messenger (Logged in as: %s)\n", identity);
    printf("=========================================\n");
    printf("\n");
    printf("1. Send message\n");
    printf("2. List inbox\n");
    printf("3. List sent messages\n");
    printf("4. List keyserver\n");
    printf("5. Logout\n");
    printf("\n");
    printf("Choice: ");
}

void list_local_identities(void) {
    const char *home = getenv("HOME");
    if (!home) {
        printf("Cannot get home directory\n");
        return;
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    printf("\n=== Local Identities (Private Keys) ===\n\n");

    // Simple approach: list .pqkey files
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ls %s/*-dilithium.pqkey 2>/dev/null | sed 's/.*\\///;s/-dilithium.pqkey$//' || echo '  (no identities found)'", dna_dir);
    system(cmd);

    printf("\n");
}

int main(void) {
    messenger_context_t *ctx = NULL;
    char current_identity[100] = {0};

    while (1) {
        // Not logged in
        if (current_identity[0] == '\0') {
            print_main_menu();

            char input[256];
            if (!fgets(input, sizeof(input), stdin)) break;
            int choice = atoi(input);

            switch (choice) {
                case 1: {
                    // Create new identity
                    printf("\nNew identity name: ");
                    char new_id[100];
                    if (!fgets(new_id, sizeof(new_id), stdin)) break;
                    new_id[strcspn(new_id, "\n")] = 0;

                    // Initialize temporary context for keygen
                    messenger_context_t *temp_ctx = messenger_init("system");
                    if (temp_ctx) {
                        messenger_generate_keys(temp_ctx, new_id);
                        messenger_free(temp_ctx);
                    }
                    break;
                }

                case 2: {
                    // Choose existing identity
                    list_local_identities();
                    printf("Identity to login as: ");
                    char identity[100];
                    if (!fgets(identity, sizeof(identity), stdin)) break;
                    identity[strcspn(identity, "\n")] = 0;

                    // Check if private keys exist
                    const char *home = getenv("HOME");
                    char key_path[512];
                    snprintf(key_path, sizeof(key_path), "%s/.dna/%s-dilithium.pqkey", home, identity);

                    FILE *f = fopen(key_path, "rb");
                    if (!f) {
                        printf("Error: Identity '%s' not found\n", identity);
                        break;
                    }
                    fclose(f);

                    // Login
                    ctx = messenger_init(identity);
                    if (ctx) {
                        strcpy(current_identity, identity);
                        printf("\n✓ Logged in as '%s'\n", identity);
                    }
                    break;
                }

                case 3: {
                    // Lookup identity from server
                    printf("\nIdentity to lookup: ");
                    char lookup_id[100];
                    if (!fgets(lookup_id, sizeof(lookup_id), stdin)) break;
                    lookup_id[strcspn(lookup_id, "\n")] = 0;

                    messenger_context_t *temp_ctx = messenger_init("system");
                    if (temp_ctx) {
                        uint8_t *sign_pk = NULL, *enc_pk = NULL;
                        size_t sign_len = 0, enc_len = 0;

                        if (messenger_load_pubkey(temp_ctx, lookup_id, &sign_pk, &sign_len,
                                                   &enc_pk, &enc_len) == 0) {
                            printf("\n✓ Identity '%s' found in keyserver\n", lookup_id);
                            printf("  Signing key: %zu bytes\n", sign_len);
                            printf("  Encryption key: %zu bytes\n\n", enc_len);
                            free(sign_pk);
                            free(enc_pk);
                        } else {
                            printf("\n✗ Identity '%s' not found in keyserver\n\n", lookup_id);
                        }
                        messenger_free(temp_ctx);
                    }
                    break;
                }

                case 4: {
                    // Configure server
                    dna_config_t config;
                    if (dna_config_setup(&config) == 0) {
                        if (dna_config_save(&config) == 0) {
                            printf("\n✓ Server configuration saved\n");
                            printf("✓ Please restart messenger to use new settings\n");
                        }
                    }
                    break;
                }

                case 5:
                    printf("\nGoodbye!\n\n");
                    return 0;

                default:
                    printf("Invalid choice\n");
                    break;
            }
        }
        // Logged in
        else {
            print_user_menu(current_identity);

            char input[256];
            if (!fgets(input, sizeof(input), stdin)) break;
            int choice = atoi(input);

            switch (choice) {
                case 1: {
                    // Send message (format: identity@message)
                    printf("\nFormat: identity@message\n");
                    printf("Example: bob@Hey Bob, how are you?\n");
                    printf("\n> ");

                    char line[2048];
                    if (!fgets(line, sizeof(line), stdin)) break;
                    line[strcspn(line, "\n")] = 0;

                    // Parse identity@message
                    char *at_sign = strchr(line, '@');
                    if (!at_sign) {
                        printf("Error: Invalid format. Use: identity@message\n");
                        break;
                    }

                    *at_sign = '\0';
                    char *recipient = line;
                    char *message = at_sign + 1;

                    if (strlen(recipient) == 0 || strlen(message) == 0) {
                        printf("Error: Both identity and message required\n");
                        break;
                    }

                    messenger_send_message(ctx, recipient, message);
                    break;
                }

                case 2:
                    messenger_list_messages(ctx);
                    break;

                case 3:
                    messenger_list_sent_messages(ctx);
                    break;

                case 4:
                    messenger_list_pubkeys(ctx);
                    break;

                case 5:
                    // Logout
                    messenger_free(ctx);
                    ctx = NULL;
                    current_identity[0] = '\0';
                    printf("\n✓ Logged out\n");
                    break;

                default:
                    printf("Invalid choice\n");
                    break;
            }
        }
    }

    if (ctx) {
        messenger_free(ctx);
    }

    return 0;
}
