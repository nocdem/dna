/*
 * DNA Messenger - CLI Client
 * Post-quantum end-to-end encrypted messaging
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../messenger.h"
#include "../dna_config.h"
#include "keyserver_register.h"

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
    printf("2. Restore identity from seed phrase\n");
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
    printf("3. Read message\n");
    printf("4. Delete message\n");
    printf("5. List sent messages\n");
    printf("6. List keyserver\n");
    printf("7. Search messages\n");
    printf("8. Check for updates\n");
    printf("9. Exit\n");
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

    // Simple approach: list .dsa files
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ls %s/*.dsa 2>/dev/null | sed 's/.*\\///;s/.dsa$//' || echo '  (no identities found)'", dna_dir);
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
    snprintf(search_path, sizeof(search_path), "%s\\*.dsa", dna_dir);

    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    // Extract identity from filename (remove .dsa suffix)
    strncpy(identity, find_data.cFileName, sizeof(identity) - 1);
    identity[sizeof(identity) - 1] = '\0';

    char *suffix = strstr(identity, ".dsa");
    if (suffix) {
        *suffix = '\0';
    }

    FindClose(hFind);
    return strlen(identity) > 0 ? identity : NULL;
#else
    // Unix: use glob
    char pattern[600];
    snprintf(pattern, sizeof(pattern), "%s/*.dsa", dna_dir);

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

        // Extract identity (remove .dsa suffix)
        strncpy(identity, filename, sizeof(identity) - 1);
        identity[sizeof(identity) - 1] = '\0';

        char *suffix = strstr(identity, ".dsa");
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

void print_usage(const char *prog) {
    printf("DNA Messenger - Post-quantum encrypted messaging\n\n");
    printf("Usage:\n");
    printf("  %s                    # Interactive mode\n", prog);
    printf("  %s -n <identity>     # Create new identity and register to keyserver\n", prog);
    printf("  %s -r recipient -m \"message\"   # Send message\n", prog);
    printf("  %s -i                # List inbox\n", prog);
    printf("  %s -g <id>           # Get message by ID\n", prog);
    printf("  %s -l                # List keyserver users\n", prog);
    printf("  %s -k                # Register to keyserver\n\n", prog);
    printf("Options:\n");
    printf("  -n <identity>   Create new identity (generates keys, shows seed phrase, registers to keyserver)\n");
    printf("  -r <recipient>  Recipient identity (can be comma-separated for multiple)\n");
    printf("  -m <message>    Message to send\n");
    printf("  -i              List inbox messages\n");
    printf("  -g <id>         Get and display message by ID\n");
    printf("  -l              List all users in keyserver\n");
    printf("  -k              Register current identity to keyserver\n");
    printf("  -h              Show this help\n\n");
}

int main(int argc, char *argv[]) {
    messenger_context_t *ctx = NULL;
    char current_identity[100] = {0};

    // Parse command-line arguments first
    char *new_identity = NULL;
    char *recipient = NULL;
    char *message = NULL;
    bool list_inbox = false;
    bool list_keyserver = false;
    bool register_keyserver = false;
    int get_message_id = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            new_identity = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            recipient = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            message = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0) {
            list_inbox = true;
        } else if (strcmp(argv[i], "-l") == 0) {
            list_keyserver = true;
        } else if (strcmp(argv[i], "-k") == 0) {
            register_keyserver = true;
        } else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
            get_message_id = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Handle new identity creation first (doesn't require existing identity)
    if (new_identity) {
        printf("\n=== Creating New Identity: %s ===\n\n", new_identity);

        // Initialize temporary context for keygen
        messenger_context_t *temp_ctx = messenger_init("system");
        if (!temp_ctx) {
            printf("Error: Failed to initialize messenger\n");
            return 1;
        }

        // Generate keys (this will show the seed phrase to the user)
        if (messenger_generate_keys(temp_ctx, new_identity) != 0) {
            printf("\n✗ Failed to generate keys\n");
            messenger_free(temp_ctx);
            return 1;
        }

        messenger_free(temp_ctx);

        // Register to cpunk.io keyserver API
        if (register_to_keyserver(new_identity) != 0) {
            printf("\n✗ Failed to register to cpunk.io keyserver\n");
            printf("Keys were generated locally, but not uploaded to keyserver.\n");
            printf("You can retry with: ./dna_messenger -k\n\n");
            return 1;
        }

        printf("✓ Identity '%s' created and registered to keyserver\n\n", new_identity);
        return 0;
    }

    // CLI mode: execute command and exit
    if (recipient || list_inbox || list_keyserver || register_keyserver || get_message_id > 0) {
        // For CLI mode, we need an identity
        char *existing_identity = get_local_identity();
        if (!existing_identity) {
            printf("Error: No identity found. Please create one first.\n");
            printf("Run without arguments to enter interactive mode and create an identity.\n");
            return 1;
        }

        ctx = messenger_init(existing_identity);
        if (!ctx) {
            printf("Error: Failed to initialize messenger\n");
            return 1;
        }

        strcpy(current_identity, existing_identity);

        // Execute command
        if (recipient && message) {
            // Send message
            // Parse recipients (comma-separated)
            const char *recipients[64]; // Max 64 recipients
            int recipient_count = 0;

            char *recipient_copy = strdup(recipient);
            char *token = strtok(recipient_copy, ",");
            while (token && recipient_count < 64) {
                // Trim whitespace
                while (*token == ' ') token++;
                recipients[recipient_count++] = token;
                token = strtok(NULL, ",");
            }

            if (recipient_count > 0) {
                messenger_send_message(ctx, recipients, recipient_count, message);
            }
            free(recipient_copy);
        } else if (list_inbox) {
            // List inbox
            messenger_list_messages(ctx);
        } else if (list_keyserver) {
            // List keyserver users
            messenger_list_pubkeys(ctx);
        } else if (register_keyserver) {
            // Register to keyserver
            int result = register_to_keyserver(existing_identity);
            messenger_free(ctx);
            return result;
        } else if (get_message_id > 0) {
            // Get specific message
            messenger_read_message(ctx, get_message_id);
        } else {
            printf("Error: Invalid command combination\n");
            print_usage(argv[0]);
            messenger_free(ctx);
            return 1;
        }

        messenger_free(ctx);
        return 0;
    }

    // Interactive mode
    char *existing_identity = get_local_identity();
    if (existing_identity) {
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
                    // Restore identity from seed phrase
                    printf("\nRestore identity name: ");
                    char restore_id[100];
                    if (!fgets(restore_id, sizeof(restore_id), stdin)) break;
                    restore_id[strcspn(restore_id, "\n")] = 0;

                    if (strlen(restore_id) == 0) {
                        printf("Error: Identity name cannot be empty\n");
                        break;
                    }

                    // Ask for restore method: file or interactive
                    printf("\nRestore from:\n");
                    printf("  1. File (24 words + optional passphrase)\n");
                    printf("  2. Interactive (manual input)\n");
                    printf("\nChoice: ");

                    char method_input[10];
                    if (!fgets(method_input, sizeof(method_input), stdin)) break;
                    int restore_method = atoi(method_input);

                    messenger_context_t *temp_ctx = messenger_init("system");
                    if (!temp_ctx) break;

                    int restore_result = -1;

                    if (restore_method == 1) {
                        // File-based restore
                        printf("\nSeed file path: ");
                        char seed_file[512];
                        if (!fgets(seed_file, sizeof(seed_file), stdin)) {
                            messenger_free(temp_ctx);
                            break;
                        }
                        seed_file[strcspn(seed_file, "\n")] = 0;

                        if (strlen(seed_file) == 0) {
                            printf("Error: File path cannot be empty\n");
                            messenger_free(temp_ctx);
                            break;
                        }

                        restore_result = messenger_restore_keys_from_file(temp_ctx, restore_id, seed_file);
                    } else if (restore_method == 2) {
                        // Interactive restore
                        restore_result = messenger_restore_keys(temp_ctx, restore_id);
                    } else {
                        printf("Error: Invalid choice\n");
                        messenger_free(temp_ctx);
                        break;
                    }

                    if (restore_result == 0) {
                        messenger_free(temp_ctx);

                        // Auto-login after successful key restoration
                        ctx = messenger_init(restore_id);
                        if (ctx) {
                            strcpy(current_identity, restore_id);
                            printf("\n✓ Logged in as '%s'\n", restore_id);
                        }
                    } else {
                        messenger_free(temp_ctx);
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

                    // Send to single recipient (multi-recipient support can be added later)
                    const char *recipients[] = {recipient};
                    messenger_send_message(ctx, recipients, 1, message);
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

                case 4: {
                    // Delete message
                    printf("\nMessage ID to delete: ");
                    char id_input[32];
                    if (!fgets(id_input, sizeof(id_input), stdin)) break;
                    int message_id = atoi(id_input);

                    if (message_id > 0) {
                        printf("Delete message %d? (Y/N): ", message_id);
                        char confirm[10];
                        if (fgets(confirm, sizeof(confirm), stdin) &&
                            (confirm[0] == 'Y' || confirm[0] == 'y')) {
                            messenger_delete_message(ctx, message_id);
                        } else {
                            printf("Cancelled.\n");
                        }
                    } else {
                        printf("Error: Invalid message ID\n");
                    }
                    break;
                }

                case 5:
                    messenger_list_sent_messages(ctx);
                    break;

                case 6:
                    messenger_list_pubkeys(ctx);
                    break;

                case 7: {
                    // Search messages submenu
                    printf("\n=== Search Messages ===\n");
                    printf("1. Search by sender\n");
                    printf("2. Show conversation\n");
                    printf("3. Search by date range\n");
                    printf("\nChoice: ");

                    char search_input[10];
                    if (!fgets(search_input, sizeof(search_input), stdin)) break;
                    int search_choice = atoi(search_input);

                    switch (search_choice) {
                        case 1: {
                            // Search by sender
                            printf("\nSender identity: ");
                            char sender[100];
                            if (!fgets(sender, sizeof(sender), stdin)) break;
                            sender[strcspn(sender, "\n")] = 0;

                            if (strlen(sender) > 0) {
                                messenger_search_by_sender(ctx, sender);
                            } else {
                                printf("Error: Sender identity required\n");
                            }
                            break;
                        }

                        case 2: {
                            // Show conversation
                            printf("\nOther identity: ");
                            char other[100];
                            if (!fgets(other, sizeof(other), stdin)) break;
                            other[strcspn(other, "\n")] = 0;

                            if (strlen(other) > 0) {
                                messenger_show_conversation(ctx, other);
                            } else {
                                printf("Error: Identity required\n");
                            }
                            break;
                        }

                        case 3: {
                            // Search by date range
                            printf("\nStart date (YYYY-MM-DD or leave empty): ");
                            char start[20];
                            if (!fgets(start, sizeof(start), stdin)) break;
                            start[strcspn(start, "\n")] = 0;

                            printf("End date (YYYY-MM-DD or leave empty): ");
                            char end[20];
                            if (!fgets(end, sizeof(end), stdin)) break;
                            end[strcspn(end, "\n")] = 0;

                            printf("Include sent messages? (Y/N): ");
                            char sent_input[10];
                            if (!fgets(sent_input, sizeof(sent_input), stdin)) break;
                            bool include_sent = (sent_input[0] == 'Y' || sent_input[0] == 'y');

                            printf("Include received messages? (Y/N): ");
                            char recv_input[10];
                            if (!fgets(recv_input, sizeof(recv_input), stdin)) break;
                            bool include_received = (recv_input[0] == 'Y' || recv_input[0] == 'y');

                            messenger_search_by_date(ctx,
                                strlen(start) > 0 ? start : NULL,
                                strlen(end) > 0 ? end : NULL,
                                include_sent,
                                include_received);
                            break;
                        }

                        default:
                            printf("Invalid search option\n");
                            break;
                    }
                    break;
                }

                case 8: {
                    // Check for updates
                    printf("\n=== Check for Updates ===\n");
                    printf("Current version: %s\n", PQSIGNUM_VERSION);
                    printf("Checking latest version on GitHub...\n");

                    // Get latest commit count from GitHub
                    char latest_version[32] = "unknown";
                    char version_cmd[512];

#ifdef _WIN32
                    // Windows: use PowerShell to fetch version
                    snprintf(version_cmd, sizeof(version_cmd),
                            "powershell -Command \"$sha = (git ls-remote https://github.com/nocdem/dna-messenger.git HEAD 2>$null).Split()[0]; "
                            "if ($sha) { git rev-list --count $sha 2>$null } else { Write-Output 'unknown' }\"");
                    FILE *fp = _popen(version_cmd, "r");
                    if (fp) {
                        if (fgets(latest_version, sizeof(latest_version), fp)) {
                            latest_version[strcspn(latest_version, "\r\n")] = 0;
                        }
                        _pclose(fp);
                    }
#else
                    // Linux: fetch version from GitHub
                    snprintf(version_cmd, sizeof(version_cmd),
                            "git ls-remote https://github.com/nocdem/dna-messenger.git HEAD 2>/dev/null | "
                            "cut -f1 | xargs -I{} git rev-list --count {} 2>/dev/null || echo 'unknown'");
                    FILE *fp = popen(version_cmd, "r");
                    if (fp) {
                        if (fgets(latest_version, sizeof(latest_version), fp)) {
                            latest_version[strcspn(latest_version, "\n")] = 0;
                        }
                        pclose(fp);
                    }
#endif

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
                        // Windows: Exit and run installer script in background
                        printf("Exiting and launching update...\n");
                        messenger_free(ctx);

                        // Launch installer in background and exit
                        snprintf(update_cmd, sizeof(update_cmd),
                                "start /min cmd /c \"cd C:\\dna-messenger && install_windows.bat\"");
                        system(update_cmd);
                        return 0;
#else
                        // Linux: find repo and update
                        snprintf(update_cmd, sizeof(update_cmd),
                                "REPO=$(git rev-parse --show-toplevel 2>/dev/null); "
                                "if [ -n \"$REPO\" ]; then "
                                "cd \"$REPO\" && git pull origin main && "
                                "cd build && cmake .. && make -j$(nproc); "
                                "else echo 'Not a git repository'; fi");

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
#endif
                    } else {
                        printf("Update cancelled.\n");
                    }
                    break;
                }

                case 9:
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
