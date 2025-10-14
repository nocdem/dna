/*
 * pqsignum - Post-Quantum File Signing Tool
 * Main entry point and command-line parsing
 */

#include <getopt.h>
#include "qgp.h"
#include "bip39.h"

static struct option const long_options[] = {
    {"gen-key", no_argument, 0, 'g'},
    {"restore", no_argument, 0, 'R'},
    {"sign", no_argument, 0, 's'},
    {"verify", no_argument, 0, 'v'},
    {"export", no_argument, 0, 'x'},
    {"encrypt", no_argument, 0, 'e'},
    {"decrypt", no_argument, 0, 'd'},
    {"import", no_argument, 0, 'I'},
    {"list-keys", no_argument, 0, 'L'},
    {"delete-key", no_argument, 0, 'D'},
    {"set-default", required_argument, 0, 'M'},
    {"config-create", no_argument, 0, 'C'},
    {"from-seed", no_argument, 0, 'F'},
    {"name", required_argument, 0, 'n'},
    {"algo", required_argument, 0, 'a'},
    {"key", required_argument, 0, 'k'},
    {"output", required_argument, 0, 'o'},
    {"file", required_argument, 0, 'f'},
    {"sig", required_argument, 0, 'S'},
    {"recipient", required_argument, 0, 'r'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0}
};

typedef enum {
    CMD_NONE,
    CMD_GEN_KEY,
    CMD_RESTORE,
    CMD_SIGN,
    CMD_VERIFY,
    CMD_EXPORT,
    CMD_ENCRYPT,
    CMD_DECRYPT,
    CMD_IMPORT,
    CMD_LIST_KEYS,
    CMD_DELETE_KEY,
    CMD_SET_DEFAULT,
    CMD_CONFIG_CREATE
} command_t;

int main(int argc, char *argv[]) {
    // Load configuration file (if it exists)
    qgp_config_load();
    const qgp_config_t *config = qgp_config_get();

    int opt;
    command_t command = CMD_NONE;

    // Command parameters
    char *name = NULL;
    char *algo = NULL;  // Will use config default if not specified
    char *key_path = NULL;
    char *output_dir = NULL;
    char *input_file = NULL;
    char *output_sig = NULL;
    char *sig_file = NULL;
    char *set_default_key_name = NULL;
    int from_seed = 0;  // BIP39 seed-based key generation flag

    // Multi-recipient support (up to 255 recipients)
    #define MAX_RECIPIENTS 255
    char *recipients[MAX_RECIPIENTS];
    size_t recipient_count = 0;

    // Parse command line
    while ((opt = getopt_long(argc, argv, "gRsvxedILDM:CFn:a:k:o:f:S:r:hV", long_options, NULL)) != -1) {
        switch (opt) {
            case 'g':
                command = CMD_GEN_KEY;
                break;
            case 'R':
                command = CMD_RESTORE;
                break;
            case 's':
                command = CMD_SIGN;
                break;
            case 'v':
                command = CMD_VERIFY;
                break;
            case 'x':
                command = CMD_EXPORT;
                break;
            case 'e':
                command = CMD_ENCRYPT;
                break;
            case 'd':
                command = CMD_DECRYPT;
                break;
            case 'I':
                command = CMD_IMPORT;
                break;
            case 'L':
                command = CMD_LIST_KEYS;
                break;
            case 'D':
                command = CMD_DELETE_KEY;
                break;
            case 'M':
                command = CMD_SET_DEFAULT;
                set_default_key_name = optarg;
                break;
            case 'C':
                command = CMD_CONFIG_CREATE;
                break;
            case 'F':
                from_seed = 1;
                break;
            case 'n':
                name = optarg;
                break;
            case 'a':
                algo = optarg;
                break;
            case 'k':
                key_path = optarg;
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 'f':
                input_file = optarg;
                break;
            case 'S':
                sig_file = optarg;
                break;
            case 'r':
                if (recipient_count >= MAX_RECIPIENTS) {
                    fprintf(stderr, "Error: Maximum %d recipients allowed\n", MAX_RECIPIENTS);
                    return EXIT_ERROR;
                }
                recipients[recipient_count++] = optarg;
                break;
            case 'h':
                print_help();
                return EXIT_SUCCESS;
            case 'V':
                print_version();
                return EXIT_SUCCESS;
            default:
                print_help();
                return EXIT_ERROR;
        }
    }

    // Handle positional arguments (for simple usage)
    if (command == CMD_NONE && optind < argc) {
        // First positional arg is the file to sign/verify
        input_file = argv[optind];

        // If there's a key before the file, use it
        if (optind > 1 && argv[optind - 1][0] != '-') {
            key_path = argv[optind - 1];
            input_file = argv[optind];
        }
    }

    // Apply configuration defaults (only if command-line didn't specify)
    if (!algo && config->default_algorithm) {
        algo = (char *)config->default_algorithm;
    }
    if (!algo) {
        algo = "dilithium";  // Fallback default
    }

    if (!key_path && config->default_key_name) {
        // Use config default key name
        key_path = config->default_key_name;
    }

    // Execute command
    switch (command) {
        case CMD_GEN_KEY:
            if (!name) {
                fprintf(stderr, "Error: --name required for key generation\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!output_dir) {
                output_dir = get_home_dir();
                char *keyring_dir = build_path(output_dir, DEFAULT_KEYRING_DIR);
                output_dir = keyring_dir;
            }
            if (from_seed) {
                return cmd_gen_key_from_seed(name, algo, output_dir);
            } else {
                return cmd_gen_key(name, algo, output_dir);
            }

        case CMD_RESTORE:
            if (!name) {
                fprintf(stderr, "Error: --name required for key restoration\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!output_dir) {
                output_dir = get_home_dir();
                char *keyring_dir = build_path(output_dir, DEFAULT_KEYRING_DIR);
                output_dir = keyring_dir;
            }
            return cmd_restore_key_from_seed(name, algo, output_dir);

        case CMD_SIGN: {
            if (!input_file) {
                fprintf(stderr, "Error: --file required for signing\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!key_path) {
                fprintf(stderr, "Error: --key required for signing\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!output_sig) {
                // Auto-generate sig filename (always ASCII armored)
                output_sig = malloc(strlen(input_file) + strlen(DEFAULT_ASC_EXT) + 1);
                sprintf(output_sig, "%s%s", input_file, DEFAULT_ASC_EXT);
            }

            // Resolve key path (supports keyring name or full path)
            char *resolved_signing_key = resolve_key_path(key_path, "signing");
            if (!resolved_signing_key) {
                return EXIT_KEY_ERROR;
            }
            int result = cmd_sign_file(input_file, resolved_signing_key, output_sig);
            free(resolved_signing_key);
            return result;
        }

        case CMD_VERIFY:
            if (!input_file) {
                fprintf(stderr, "Error: --file required for verification\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!sig_file) {
                // Auto-detect sig file: try .asc first, then .sig
                char *asc_file = malloc(strlen(input_file) + strlen(DEFAULT_ASC_EXT) + 1);
                sprintf(asc_file, "%s%s", input_file, DEFAULT_ASC_EXT);

                if (file_exists(asc_file)) {
                    sig_file = asc_file;
                } else {
                    free(asc_file);
                    sig_file = malloc(strlen(input_file) + strlen(DEFAULT_SIG_EXT) + 1);
                    sprintf(sig_file, "%s%s", input_file, DEFAULT_SIG_EXT);
                }
            }
            return cmd_verify_file(input_file, sig_file);

        case CMD_EXPORT:
            if (!name) {
                fprintf(stderr, "Error: --name required for public key export\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!key_path) {
                // Use default keyring directory
                key_path = get_home_dir();
                char *keyring_dir = build_path(key_path, DEFAULT_KEYRING_DIR);
                key_path = keyring_dir;
            }
            if (!output_dir) {
                // Auto-generate filename (always ASCII armored)
                output_dir = malloc(strlen(name) + 5);  // ".asc" + null
                sprintf(output_dir, "%s.asc", name);
            }
            return cmd_export_pubkey(name, key_path, output_dir);

        case CMD_ENCRYPT: {
            if (!input_file) {
                fprintf(stderr, "Error: --file required for encryption\n");
                print_help();
                return EXIT_ERROR;
            }
            if (recipient_count == 0) {
                fprintf(stderr, "Error: At least one --recipient <pubkey.pub> required for encryption\n");
                fprintf(stderr, "       Use multiple --recipient flags for multi-recipient encryption\n");
                fprintf(stderr, "       Example: qgp --encrypt --file secret.txt -r alice.pub -r bob.pub --key sender.pqkey\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!key_path) {
                fprintf(stderr, "Error: --key <signing-key.pqkey> required for encryption (to sign the file)\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!output_dir) {
                // Auto-generate: input_file.enc
                output_dir = malloc(strlen(input_file) + 5);  // ".enc" + null
                sprintf(output_dir, "%s.enc", input_file);
            }

            // Resolve signing key path (supports keyring name or full path)
            char *resolved_signing_key = resolve_key_path(key_path, "signing");
            if (!resolved_signing_key) {
                return EXIT_KEY_ERROR;
            }

            // Auto-add sender to recipients list (so sender can decrypt their own message)
            char *sender_pubkey = resolve_recipient_path(key_path);
            if (!sender_pubkey) {
                fprintf(stderr, "Warning: Could not add sender to recipients (sender won't be able to decrypt)\n");
            }

            // Resolve recipient paths (supports keyring names or full paths)
            char *resolved_recipients[MAX_RECIPIENTS];
            size_t total_recipients = 0;

            // Add sender as first recipient (if available)
            if (sender_pubkey) {
                resolved_recipients[total_recipients++] = sender_pubkey;
            }

            // Add all other recipients
            for (size_t i = 0; i < recipient_count; i++) {
                resolved_recipients[total_recipients] = resolve_recipient_path(recipients[i]);
                if (!resolved_recipients[total_recipients]) {
                    // Clean up already resolved recipients
                    for (size_t j = 0; j < total_recipients; j++) {
                        free(resolved_recipients[j]);
                    }
                    free(resolved_signing_key);
                    return EXIT_KEY_ERROR;
                }
                total_recipients++;
            }

            // Use unified encryption format (supports 1-255 recipients)
            int encrypt_result = cmd_encrypt_file(input_file, output_dir, (const char **)resolved_recipients, total_recipients, resolved_signing_key);

            // Clean up resolved paths
            for (size_t i = 0; i < total_recipients; i++) {
                free(resolved_recipients[i]);
            }
            free(resolved_signing_key);
            return encrypt_result;
        }

        case CMD_DECRYPT: {
            if (!input_file) {
                fprintf(stderr, "Error: --file required for decryption\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!key_path) {
                fprintf(stderr, "Error: --key <name-kyber512.pqkey> required for decryption\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!output_dir) {
                // Auto-generate: remove .enc extension
                size_t len = strlen(input_file);
                if (len > 4 && strcmp(input_file + len - 4, ".enc") == 0) {
                    output_dir = malloc(len);  // -4 + null = -3, but we allocate more
                    memcpy(output_dir, input_file, len - 4);
                    output_dir[len - 4] = '\0';
                } else {
                    // Add .dec suffix
                    output_dir = malloc(len + 5);  // ".dec" + null
                    sprintf(output_dir, "%s.dec", input_file);
                }
            }

            // Resolve encryption key path (supports keyring name or full path)
            char *resolved_encryption_key = resolve_key_path(key_path, "encryption");
            if (!resolved_encryption_key) {
                return EXIT_KEY_ERROR;
            }
            int decrypt_result = cmd_decrypt_file(input_file, output_dir, resolved_encryption_key);
            free(resolved_encryption_key);
            return decrypt_result;
        }

        case CMD_IMPORT:
            if (!input_file) {
                fprintf(stderr, "Error: --file required for import\n");
                print_help();
                return EXIT_ERROR;
            }
            if (!name) {
                fprintf(stderr, "Error: --name required for import\n");
                print_help();
                return EXIT_ERROR;
            }
            return cmd_keyring_import(input_file, name);

        case CMD_LIST_KEYS:
            return cmd_keyring_list();

        case CMD_DELETE_KEY:
            if (!name) {
                fprintf(stderr, "Error: --name required for delete-key\n");
                print_help();
                return EXIT_ERROR;
            }
            return cmd_keyring_delete(name);

        case CMD_SET_DEFAULT:
            if (!set_default_key_name) {
                fprintf(stderr, "Error: Key name required for --set-default\n");
                print_help();
                return EXIT_ERROR;
            }
            return qgp_config_set_default_key(set_default_key_name);

        case CMD_CONFIG_CREATE:
            return qgp_config_create_default();

        default:
            fprintf(stderr, "Error: No command specified\n");
            print_help();
            return EXIT_ERROR;
    }

    // Clean up configuration resources
    qgp_config_free();

    return EXIT_SUCCESS;
}
