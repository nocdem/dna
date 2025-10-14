/*
 * DNA Messenger - CLI Client
 * Post-quantum end-to-end encrypted messaging
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../messenger.h"
#include "../dna_config.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <glob.h>
#endif

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
    printf("6. Check for updates\n");
    printf("7. Exit\n");
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
    if (!home) {
        // Windows fallback
        home = getenv("USERPROFILE");
        if (!home) return NULL;
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Platform-independent: directly check for dilithium key files
    static char identity[100];

#ifdef _WIN32
    // Windows: use FindFirstFile
    char search_path[600];
    snprintf(search_path, sizeof(search_path), "%s\\*-dilithium.pqkey", dna_dir);

    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    // Extract identity from filename (remove -dilithium.pqkey suffix)
    strncpy(identity, find_data.cFileName, sizeof(identity) - 1);
    identity[sizeof(identity) - 1] = '\0';

    char *suffix = strstr(identity, "-dilithium.pqkey");
    if (suffix) {
        *suffix = '\0';
    }

    FindClose(hFind);
    return strlen(identity) > 0 ? identity : NULL;
#else
    // Unix: use glob
    char pattern[600];
    snprintf(pattern, sizeof(pattern), "%s/*-dilithium.pqkey", dna_dir);

    glob_t glob_result;
    if (glob(pattern, GLOB_NOSORT, NULL, &glob_result) == 0 && glob_result.gl_pathc > 0) {
        // Extract filename from path
        const char *path = glob_result.gl_pathv[0];
        const char *filename = strrchr(path, '/');
        if (filename) {
            filename++; // Skip the '/'
        } else {
            filename = path;
        }

        // Extract identity (remove -dilithium.pqkey suffix)
        strncpy(identity, filename, sizeof(identity) - 1);
        identity[sizeof(identity) - 1] = '\0';

        char *suffix = strstr(identity, "-dilithium.pqkey");
        if (suffix) {
            *suffix = '\0';
        }

        globfree(&glob_result);
        return strlen(identity) > 0 ? identity : NULL;
    }

    globfree(&glob_result);
    return NULL;
#endif
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

                case 6: {
                    // Check for updates
                    printf("\n=== Check for Updates ===\n");
                    printf("Current version: %s\n", PQSIGNUM_VERSION);
                    printf("Checking latest version on GitHub...\n");

                    // Get latest commit count from GitHub
                    char version_cmd[512];
                    snprintf(version_cmd, sizeof(version_cmd),
                            "git ls-remote https://github.com/nocdem/dna-messenger.git HEAD 2>/dev/null | "
                            "cut -f1 | xargs -I{} git rev-list --count {} 2>/dev/null || echo 'unknown'");

                    FILE *fp = popen(version_cmd, "r");
                    char latest_version[32] = "unknown";
                    if (fp) {
                        if (fgets(latest_version, sizeof(latest_version), fp)) {
                            latest_version[strcspn(latest_version, "\n")] = 0;
                        }
                        pclose(fp);
                    }

                    if (strcmp(latest_version, "unknown") != 0) {
                        printf("Latest version: 0.1.%s\n", latest_version);

                        int current = atoi(PQSIGNUM_VERSION + 4); // Skip "0.1."
                        int latest = atoi(latest_version);

                        if (current >= latest) {
                            printf("\n✓ You are up to date!\n");
                            break;
                        }
                    } else {
                        printf("Latest version: Could not fetch from GitHub\n");
                    }

                    printf("\nThis will pull latest code from GitHub and rebuild.\n");
                    printf("Continue? (Y/N): ");

                    char confirm[10];
                    if (fgets(confirm, sizeof(confirm), stdin) &&
                        (confirm[0] == 'Y' || confirm[0] == 'y')) {

                        printf("\nUpdating DNA Messenger...\n\n");

                        // Find git repository root (where .git directory is)
                        char update_cmd[2048];

#ifdef _WIN32
                        // Windows: run installer script
                        snprintf(update_cmd, sizeof(update_cmd),
                                "cd C:\\dna-messenger && install_windows.bat");
#else
                        // Linux: find repo and update
                        snprintf(update_cmd, sizeof(update_cmd),
                                "REPO=$(git rev-parse --show-toplevel 2>/dev/null); "
                                "if [ -n \"$REPO\" ]; then "
                                "cd \"$REPO\" && git pull origin main && "
                                "cd build && cmake .. && make -j$(nproc); "
                                "else echo 'Not a git repository'; fi");
#endif

                        int result = system(update_cmd);

                        if (result == 0) {
                            printf("\n✓ Update complete!\n");
                            printf("Please restart DNA Messenger to use the new version.\n");
                        } else {
                            printf("\n✗ Update failed!\n");
                            printf("Make sure you're running from the git repository.\n");
                        }

                        messenger_free(ctx);
                        return 0;
                    } else {
                        printf("Update cancelled.\n");
                    }
                    break;
                }

                case 7:
                    // Exit
                    messenger_free(ctx);
                    printf("\nGoodbye!\n\n");
                    return 0;

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
