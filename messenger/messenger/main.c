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
    printf("1. Create new identity (auto-login)\n");
    printf("2. Lookup identity (from server)\n");
    printf("3. Configure server\n");
    printf("4. Exit\n");
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
    printf("3. Read message\n");
    printf("4. List sent messages\n");
    printf("5. List keyserver\n");
    printf("6. Logout\n");
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

char* get_local_identity(void) {
    const char *home = getenv("HOME");
    if (!home) return NULL;

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Check for *-dilithium.pqkey files
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ls %s/*-dilithium.pqkey 2>/dev/null | head -1 | sed 's/.*\\///;s/-dilithium.pqkey$//'", dna_dir);

    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    static char identity[100];
    if (fgets(identity, sizeof(identity), fp)) {
        identity[strcspn(identity, "\n")] = 0;
        pclose(fp);
        return strlen(identity) > 0 ? identity : NULL;
    }
    pclose(fp);
    return NULL;
}

int main(void) {
    messenger_context_t *ctx = NULL;
    char current_identity[100] = {0};

    // Check for existing local identity
    char *existing_identity = get_local_identity();
    if (existing_identity) {
        // Auto-login with existing identity
        ctx = messenger_init(existing_identity);
        if (ctx) {
            strcpy(current_identity, existing_identity);
            printf("\n✓ Auto-logged in as '%s'\n", existing_identity);
        }
    }

    while (1) {
        // Not logged in
        if (current_identity[0] == '\0') {
            print_main_menu();

            char input[256];
            if (!fgets(input, sizeof(input), stdin)) break;
            int choice = atoi(input);

            switch (choice) {
                case 1: {
                    // Create new identity and auto-login
                    printf("\nNew identity name: ");
                    char new_id[100];
                    if (!fgets(new_id, sizeof(new_id), stdin)) break;
                    new_id[strcspn(new_id, "\n")] = 0;

                    if (strlen(new_id) == 0) {
                        printf("Error: Identity name cannot be empty\n");
                        break;
                    }

                    // Initialize temporary context for keygen
                    messenger_context_t *temp_ctx = messenger_init("system");
                    if (temp_ctx) {
                        if (messenger_generate_keys(temp_ctx, new_id) == 0) {
                            messenger_free(temp_ctx);

                            // Auto-login after successful key generation
                            ctx = messenger_init(new_id);
                            if (ctx) {
                                strcpy(current_identity, new_id);
                                printf("\n✓ Logged in as '%s'\n", new_id);
                            }
                        } else {
                            messenger_free(temp_ctx);
                        }
                    }
                    break;
                }

                case 2: {
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

                case 3: {
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

                case 4:
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

                case 3: {
                    // Read message
                    printf("\nMessage ID: ");
                    char id_input[32];
                    if (!fgets(id_input, sizeof(id_input), stdin)) break;
                    int message_id = atoi(id_input);

                    if (message_id > 0) {
                        messenger_read_message(ctx, message_id);
                    } else {
                        printf("Error: Invalid message ID\n");
                    }
                    break;
                }

                case 4:
                    messenger_list_sent_messages(ctx);
                    break;

                case 5:
                    messenger_list_pubkeys(ctx);
                    break;

                case 6:
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
