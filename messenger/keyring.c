/*
 * pqsignum - Keyring Management (Cross-Platform)
 *
 * Protocol Mode: PGP-like keyring for managing public keys
 * - Import public keys with friendly names
 * - List all imported keys with fingerprints
 * - Delete keys from keyring
 * - Find keys by name for encryption/verification
 * - Cross-platform directory operations via platform abstraction layer
 */

#include "qgp.h"
#include "qgp_types.h"  // For qgp_hash_t and qgp_hash_from_bytes()
#include "qgp_compiler.h"
#include "qgp_platform.h"
#include <time.h>
#include <dirent.h>
#include <errno.h>

// Windows uses _unlink instead of unlink
#ifdef _MSC_VER
#include <io.h>
#define unlink _unlink
#else
#include <unistd.h>  // For unlink() on Unix/Linux
#endif

#define KEYRING_DIR ".qgp/keyring"
#define KEYRING_INDEX ".qgp/keyring/keyring.index"

/**
 * Get keyring directory path
 * Returns: allocated string with keyring path (caller must free)
 */
char* get_keyring_dir(void) {
    char *home = get_home_dir();
    return build_path(home, KEYRING_DIR);
}

/**
 * Get keyring index file path
 * Returns: allocated string with index path (caller must free)
 */
char* get_keyring_index_path(void) {
    char *home = get_home_dir();
    return build_path(home, KEYRING_INDEX);
}

/**
 * Ensure keyring directory exists
 * Returns: 0 on success, -1 on error
 */
int ensure_keyring_dir(void) {
    char *keyring_dir = get_keyring_dir();

    // Create ~/.qgp if it doesn't exist
    char *home = get_home_dir();
    char *pqsignum_dir = build_path(home, DEFAULT_KEYRING_DIR);
    qgp_platform_mkdir(pqsignum_dir);  // Ignore errors, may already exist
    free(pqsignum_dir);

    // Create keyring directory
    int ret = qgp_platform_mkdir(keyring_dir);
    free(keyring_dir);

    if (ret != 0 && errno != EEXIST) {
        fprintf(stderr, "Error: Cannot create keyring directory\n");
        return -1;
    }

    return 0;
}

/**
 * Calculate SHA256 fingerprint of public key file
 * Returns: allocated hex string (64 chars + null), caller must free
 */
char* calculate_fingerprint(const char *pubkey_file) {
    uint8_t *data = NULL;
    size_t size = 0;

    if (read_file_data(pubkey_file, &data, &size) != 0) {
        return NULL;
    }

    qgp_hash_t hash;
    qgp_hash_from_bytes(&hash, data, size);
    free(data);

    // Convert to hex string
    char *hex = malloc(65); // 32 bytes * 2 + null
    if (!hex) return NULL;

    for (int i = 0; i < 32; i++) {
        sprintf(hex + (i * 2), "%02x", hash.hash[i]);
    }
    hex[64] = '\0';

    return hex;
}

/**
 * Add public key entry to keyring index
 * Format: name|type|fingerprint|path|path2|date
 * For public keys: type=public, path=pubkey file, path2=empty
 */
int add_to_index(const char *name, const char *fingerprint, const char *filename) {
    char *index_path = get_keyring_index_path();

    FILE *f = fopen(index_path, "a");
    free(index_path);

    if (!f) {
        fprintf(stderr, "Error: Cannot open keyring index for writing\n");
        return -1;
    }

    // Get current date
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char date_str[11];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);

    // Format: name|type|fingerprint|path1|path2|date
    fprintf(f, "%s|public|%s|%s||%s\n", name, fingerprint, filename, date_str);
    fclose(f);

    return 0;
}

/**
 * Check if name already exists in keyring
 * Returns: true if exists, false otherwise
 */
bool keyring_name_exists(const char *name) {
    char *index_path = get_keyring_index_path();
    FILE *f = fopen(index_path, "r");
    free(index_path);

    if (!f) return false;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue; // Skip comments

        char *pipe = strchr(line, '|');
        if (!pipe) continue;

        size_t name_len = pipe - line;
        if (strncmp(line, name, name_len) == 0 && strlen(name) == name_len) {
            fclose(f);
            return true;
        }
    }

    fclose(f);
    return false;
}

/**
 * Register private key pair in keyring
 * Format: name|type|fingerprint|signing_path|encryption_path|date
 * For private keys: type=private, both signing and encryption paths
 */
int keyring_register_private_key(const char *name, const char *signing_key_path,
                                   const char *encryption_key_path) {
    // Ensure keyring directory exists
    if (ensure_keyring_dir() != 0) {
        return -1;
    }

    // Check if name already exists
    if (keyring_name_exists(name)) {
        // Key already registered, skip silently
        return 0;
    }

    // Calculate fingerprint from signing key
    char *fingerprint = calculate_fingerprint(signing_key_path);
    if (!fingerprint) {
        return -1;
    }

    char *index_path = get_keyring_index_path();
    FILE *f = fopen(index_path, "a");
    free(index_path);

    if (!f) {
        free(fingerprint);
        return -1;
    }

    // Get current date
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char date_str[11];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);

    // Format: name|type|fingerprint|signing_path|encryption_path|date
    fprintf(f, "%s|private|%s|%s|%s|%s\n",
            name, fingerprint, signing_key_path, encryption_key_path, date_str);
    fclose(f);

    free(fingerprint);
    return 0;
}

/**
 * Import a public key into keyring
 *
 * @param pubkey_file: Path to .pub or .asc file to import
 * @param name: Friendly name for this key
 * @return: 0 on success, non-zero on error
 */
int cmd_keyring_import(const char *pubkey_file, const char *name) {
    printf("Importing public key to keyring...\n");
    printf("  Source: %s\n", pubkey_file);
    printf("  Name: %s\n", name);

    // Check if source file exists
    if (!file_exists(pubkey_file)) {
        fprintf(stderr, "Error: Public key file not found: %s\n", pubkey_file);
        return EXIT_ERROR;
    }

    // Ensure keyring directory exists
    if (ensure_keyring_dir() != 0) {
        return EXIT_ERROR;
    }

    // Check if public key with this name already exists
    // Note: Private keys are allowed to have the same name (for self-import during keygen)
    char *index_path_check = get_keyring_index_path();
    FILE *f_check = fopen(index_path_check, "r");
    free(index_path_check);

    if (f_check) {
        char line[1024];
        while (fgets(line, sizeof(line), f_check)) {
            if (line[0] == '#') continue;

            // Parse: name|type|fingerprint|path1|path2|date
            char entry_name[256], entry_type[16];
            if (sscanf(line, "%255[^|]|%15[^|]", entry_name, entry_type) == 2) {
                if (strcmp(entry_name, name) == 0 && strcmp(entry_type, "public") == 0) {
                    fprintf(stderr, "Error: Public key with name '%s' already exists in keyring\n", name);
                    fprintf(stderr, "Use --delete-key to remove it first, or choose a different name\n");
                    fclose(f_check);
                    return EXIT_ERROR;
                }
            }
        }
        fclose(f_check);
    }

    // Calculate fingerprint
    printf("\nCalculating fingerprint...\n");
    char *fingerprint = calculate_fingerprint(pubkey_file);
    if (!fingerprint) {
        fprintf(stderr, "Error: Failed to calculate key fingerprint\n");
        return EXIT_ERROR;
    }
    printf("  Fingerprint: %s\n", fingerprint);

    // Copy file to keyring
    char *keyring_dir = get_keyring_dir();
    char dest_filename[512];
    snprintf(dest_filename, sizeof(dest_filename), "%s.pub", name);
    char *dest_path = build_path(keyring_dir, dest_filename);
    free(keyring_dir);

    printf("\nCopying to keyring...\n");
    uint8_t *data = NULL;
    size_t size = 0;
    if (read_file_data(pubkey_file, &data, &size) != 0) {
        free(fingerprint);
        free(dest_path);
        return EXIT_ERROR;
    }

    if (write_file_data(dest_path, data, size) != 0) {
        free(data);
        free(fingerprint);
        free(dest_path);
        return EXIT_ERROR;
    }
    free(data);
    printf("  Saved to: %s\n", dest_path);
    free(dest_path);

    // Add to index
    if (add_to_index(name, fingerprint, dest_filename) != 0) {
        free(fingerprint);
        return EXIT_ERROR;
    }

    printf("\n✓ Public key imported successfully!\n");
    printf("\nYou can now encrypt files for '%s' by name:\n", name);
    printf("  qgp --encrypt --file secret.txt --recipient %s\n", name);

    free(fingerprint);
    return EXIT_SUCCESS;
}

/**
 * List all keys in keyring (private and public)
 * Shows default key indicator based on configuration
 *
 * @return: 0 on success, non-zero on error
 */
int cmd_keyring_list(void) {
    // Get default key name from config
    const qgp_config_t *config = qgp_config_get();
    const char *default_key = config ? config->default_key_name : NULL;
    char *index_path = get_keyring_index_path();
    FILE *f = fopen(index_path, "r");
    free(index_path);

    if (!f) {
        printf("Keyring is empty.\n");
        printf("\nTo add your own key:\n");
        printf("  qgp --gen-key --name mykey\n");
        printf("\nTo import someone's public key:\n");
        printf("  qgp --import --file alice.asc --name alice\n");
        return EXIT_SUCCESS;
    }

    // First pass: read all entries into memory
    typedef struct {
        char name[256];
        char type[16];
        char fingerprint[65];
        char path1[512];
        char path2[512];
        char date[16];
    } KeyEntry;

    KeyEntry *entries = NULL;
    int entry_count = 0;
    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue; // Skip comments

        // Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';

        // Manual parsing to handle empty fields between pipes
        // Format: name|type|fingerprint|path1|path2|date
        char *fields[6] = {NULL};
        char *pos = line;
        int field_idx = 0;

        while (field_idx < 6 && pos) {
            fields[field_idx] = pos;
            char *pipe = strchr(pos, '|');
            if (pipe) {
                *pipe = '\0';  // Terminate current field
                pos = pipe + 1;  // Move to next field
            } else {
                pos = NULL;  // Last field
            }
            field_idx++;
        }

        // We need at least 6 fields (name, type, fingerprint, path1, path2, date)
        if (field_idx == 6) {
            entries = realloc(entries, (entry_count + 1) * sizeof(KeyEntry));

            // Copy fields with safe string termination
            // Truncation is expected and safe if fields exceed buffer sizes
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
            snprintf(entries[entry_count].name, sizeof(entries[entry_count].name), "%s", fields[0]);
            snprintf(entries[entry_count].type, sizeof(entries[entry_count].type), "%s", fields[1]);
            snprintf(entries[entry_count].fingerprint, sizeof(entries[entry_count].fingerprint), "%s", fields[2]);
            snprintf(entries[entry_count].path1, sizeof(entries[entry_count].path1), "%s", fields[3]);
            snprintf(entries[entry_count].path2, sizeof(entries[entry_count].path2), "%s", fields[4]);
            snprintf(entries[entry_count].date, sizeof(entries[entry_count].date), "%s", fields[5]);
#pragma GCC diagnostic pop

            entry_count++;
        }
    }
    fclose(f);

    if (entry_count == 0) {
        free(entries);
        printf("Keyring is empty.\n");
        printf("\nTo add your own key:\n");
        printf("  qgp --gen-key --name mykey\n");
        printf("\nTo import someone's public key:\n");
        printf("  qgp --import --file alice.asc --name alice\n");
        return EXIT_SUCCESS;
    }

    printf("Keyring:\n");
    printf("═══════════════════════════════════════════════════════════════════════\n\n");

    // Second pass: display private keys first
    int total_count = 0;
    int private_count = 0;
    int public_count = 0;

    printf("YOUR PRIVATE KEYS:\n");
    printf("-------------------------------------------------------------------\n\n");

    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].type, "private") == 0) {
            private_count++;
            total_count++;
            bool is_default = (default_key && strcmp(entries[i].name, default_key) == 0);
            printf("Key #%d: %s%s\n", private_count, entries[i].name,
                   is_default ? " [DEFAULT]" : "");
            printf("  Type: Private Identity\n");
            printf("  Signing: %s\n", entries[i].path1);
            printf("  Encryption: %s\n", entries[i].path2);
            printf("  Fingerprint: %.16s...\n", entries[i].fingerprint);
            printf("  Created: %s\n", entries[i].date);
            printf("\n");
        }
    }

    if (private_count == 0) {
        printf("  (none)\n\n");
    }

    // Third pass: display public keys
    printf("IMPORTED PUBLIC KEYS:\n");
    printf("-------------------------------------------------------------------\n\n");

    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].type, "public") == 0) {
            public_count++;
            total_count++;
            printf("Key #%d: %s\n", public_count, entries[i].name);
            printf("  Type: Public Key (imported)\n");

            // For public keys, path1 is relative to keyring dir
            char *keyring_dir = get_keyring_dir();
            char *full_path = build_path(keyring_dir, entries[i].path1);
            printf("  File: %s\n", full_path);
            free(full_path);
            free(keyring_dir);

            printf("  Fingerprint: %.16s...\n", entries[i].fingerprint);
            printf("  Imported: %s\n", entries[i].date);
            printf("\n");
        }
    }

    if (public_count == 0) {
        printf("  (none)\n\n");
    }

    free(entries);

    if (total_count == 0) {
        printf("Keyring is empty.\n");
    } else {
        printf("═══════════════════════════════════════════════════════════════════════\n");
        printf("Total: %d key%s", total_count, total_count == 1 ? "" : "s");
        if (private_count > 0 && public_count > 0) {
            printf(" (%d private, %d public)", private_count, public_count);
        }
        printf("\n");
    }

    return EXIT_SUCCESS;
}

/**
 * Delete a key from keyring
 *
 * @param name: Name of key to delete
 * @return: 0 on success, non-zero on error
 */
int cmd_keyring_delete(const char *name) {
    printf("Deleting key from keyring: %s\n", name);

    char *index_path = get_keyring_index_path();
    FILE *f = fopen(index_path, "r");

    if (!f) {
        fprintf(stderr, "Error: Keyring is empty\n");
        free(index_path);
        return EXIT_ERROR;
    }

    // Read all entries
    char line[1024];
    char **lines = NULL;
    size_t line_count = 0;
    bool found = false;
    char filename_to_delete[256] = "";

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') {
            // Keep comments
            lines = realloc(lines, (line_count + 1) * sizeof(char*));
            lines[line_count++] = strdup(line);
            continue;
        }

        // Parse name
        char entry_name[256];
        char entry_fingerprint[65];
        char entry_filename[256];
        char entry_date[11];

        if (sscanf(line, "%255[^|]|%64[^|]|%255[^|]|%10s",
                   entry_name, entry_fingerprint, entry_filename, entry_date) == 4) {

            if (strcmp(entry_name, name) == 0) {
                // Found the key to delete
                found = true;
                strncpy(filename_to_delete, entry_filename, sizeof(filename_to_delete) - 1);
                filename_to_delete[sizeof(filename_to_delete) - 1] = '\0';  // Ensure null termination
                printf("  Found: %s (fingerprint: %.16s...)\n", name, entry_fingerprint);
                // Don't add this line to the new index
            } else {
                // Keep this entry
                lines = realloc(lines, (line_count + 1) * sizeof(char*));
                lines[line_count++] = strdup(line);
            }
        }
    }

    fclose(f);

    if (!found) {
        fprintf(stderr, "Error: Key '%s' not found in keyring\n", name);
        fprintf(stderr, "Use --list-keys to see available keys\n");
        for (size_t i = 0; i < line_count; i++) free(lines[i]);
        free(lines);
        free(index_path);
        return EXIT_ERROR;
    }

    // Write updated index
    f = fopen(index_path, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot write keyring index\n");
        for (size_t i = 0; i < line_count; i++) free(lines[i]);
        free(lines);
        free(index_path);
        return EXIT_ERROR;
    }

    for (size_t i = 0; i < line_count; i++) {
        fputs(lines[i], f);
        free(lines[i]);
    }
    free(lines);
    fclose(f);
    free(index_path);

    // Delete the key file
    char *keyring_dir = get_keyring_dir();
    char *key_path = build_path(keyring_dir, filename_to_delete);
    free(keyring_dir);

    if (unlink(key_path) != 0) {
        fprintf(stderr, "Warning: Could not delete key file: %s\n", key_path);
    }
    free(key_path);

    printf("\n✓ Key '%s' deleted from keyring\n", name);
    return EXIT_SUCCESS;
}

/**
 * Find a public key in keyring by name
 *
 * @param name: Name of key to find
 * @return: allocated path to key file, or NULL if not found (caller must free)
 */
char* keyring_find_key(const char *name) {
    char *index_path = get_keyring_index_path();
    FILE *f = fopen(index_path, "r");
    free(index_path);

    if (!f) return NULL;

    char line[1024];
    char *result = NULL;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;

        // Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';

        // Parse: name|type|fingerprint|path1|path2|date
        char *fields[6] = {NULL};
        char *pos = line;
        int field_idx = 0;

        while (field_idx < 6 && pos) {
            fields[field_idx] = pos;
            char *pipe = strchr(pos, '|');
            if (pipe) {
                *pipe = '\0';
                pos = pipe + 1;
            } else {
                pos = NULL;
            }
            field_idx++;
        }

        if (field_idx == 6) {
            char *entry_name = fields[0];
            char *entry_type = fields[1];
            char *entry_path1 = fields[3];

            // Match name and only return public keys
            if (strcmp(entry_name, name) == 0 && strcmp(entry_type, "public") == 0) {
                // Build full path
                char *keyring_dir = get_keyring_dir();
                result = build_path(keyring_dir, entry_path1);
                free(keyring_dir);
                break;
            }
        }
    }

    fclose(f);
    return result;
}

/**
 * Find a private key in keyring by name (signing or encryption)
 *
 * @param name: Name of key to find
 * @param key_type: "signing" or "encryption"
 * @return: allocated path to key file, or NULL if not found (caller must free)
 */
char* keyring_find_private_key(const char *name, const char *key_type) {
    char *index_path = get_keyring_index_path();
    FILE *f = fopen(index_path, "r");
    free(index_path);

    if (!f) return NULL;

    char line[1024];
    char *result = NULL;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;

        // Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';

        // Parse: name|type|fingerprint|path1|path2|date
        char *fields[6] = {NULL};
        char *pos = line;
        int field_idx = 0;

        while (field_idx < 6 && pos) {
            fields[field_idx] = pos;
            char *pipe = strchr(pos, '|');
            if (pipe) {
                *pipe = '\0';
                pos = pipe + 1;
            } else {
                pos = NULL;
            }
            field_idx++;
        }

        if (field_idx == 6) {
            char *entry_name = fields[0];
            char *entry_type = fields[1];
            char *entry_signing_path = fields[3];
            char *entry_encryption_path = fields[4];

            // Match name and only return private keys
            if (strcmp(entry_name, name) == 0 && strcmp(entry_type, "private") == 0) {
                // Return appropriate key path based on key_type
                if (strcmp(key_type, "signing") == 0) {
                    result = strdup(entry_signing_path);
                } else if (strcmp(key_type, "encryption") == 0) {
                    result = strdup(entry_encryption_path);
                }
                break;
            }
        }
    }

    fclose(f);
    return result;
}
