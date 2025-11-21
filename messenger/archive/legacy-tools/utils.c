/*
 * pqsignum - Utility functions (Cross-Platform)
 */

#include "../qgp.h"
#include "../crypto/utils/qgp_platform.h"

char* get_home_dir(void) {
    return (char*)qgp_platform_home_dir();
}

char* build_path(const char *dir, const char *filename) {
    return qgp_platform_join_path(dir, filename);
}

bool file_exists(const char *path) {
    return qgp_platform_file_exists(path);
}

int read_file_data(const char *path, uint8_t **data, size_t *size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file: %s\n", path);
        return -1;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Allocate buffer
    *data = malloc(*size);
    if (!*data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(f);
        return -1;
    }

    // Read data
    size_t read_bytes = fread(*data, 1, *size, f);
    fclose(f);

    if (read_bytes != *size) {
        fprintf(stderr, "Error: Failed to read complete file\n");
        free(*data);
        return -1;
    }

    return 0;
}

int write_file_data(const char *path, const uint8_t *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot create file: %s\n", path);
        return -1;
    }

    size_t written = fwrite(data, 1, size, f);
    fclose(f);

    if (written != size) {
        fprintf(stderr, "Error: Failed to write complete file\n");
        return -1;
    }

    return 0;
}

void print_version(void) {
    printf("dna version %s\n", PQSIGNUM_VERSION);
    printf("Build date: %s\n", BUILD_TS);
    printf("Git commit: %s\n", BUILD_HASH);
    printf("\nDNA Messenger - Post-quantum encrypted messaging (fork preparation phase)\n");
    printf("Forked from: QGP (Quantum Good Privacy)\n");
    printf("Signatures: ML-DSA-87 (FIPS 204)\n");
    printf("Encryption: ML-KEM-1024 + AES-256-GCM (AEAD)\n");
}

void print_help(void) {
    // Show version info at the top
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("DNA Messenger - Post-Quantum Encrypted Messaging Platform\n");
    printf("Version: %s (Fork Preparation Phase)\n", PQSIGNUM_VERSION);
    printf("Build: %s (commit: %s)\n", BUILD_TS, BUILD_HASH);
    printf("Forked from: QGP (Quantum Good Privacy)\n");
    printf("═══════════════════════════════════════════════════════════════════════\n\n");

    printf("USAGE:\n");
    printf("  Generate key pair:\n");
    printf("    qgp --gen-key --name <name> [--algo <algorithm>] [--output <dir>]\n");
    printf("    qgp --gen-key --from-seed --name <name> [--algo <algorithm>]\n\n");
    printf("  Export public keys:\n");
    printf("    qgp --export --name <name> [--output <file>]\n\n");
    printf("  Sign a file:\n");
    printf("    qgp --sign --file <file> --key <name|path>\n\n");
    printf("  Verify a signature:\n");
    printf("    qgp --verify --file <file> [--sig <sig_file>]\n\n");
    printf("  Encrypt a file (single recipient):\n");
    printf("    qgp --encrypt --file <file> --recipient <name|path> --key <name|path>\n\n");
    printf("  Encrypt a file (multiple recipients):\n");
    printf("    qgp --encrypt --file <file> -r <name1> -r <name2> -r <name3> --key <name|path>\n\n");
    printf("  Decrypt a file:\n");
    printf("    qgp --decrypt --file <file> --key <name|path> [--output <file>]\n\n");
    printf("  Keyring management:\n");
    printf("    qgp --import --file <pubkey.asc> --name <name>\n");
    printf("    qgp --list-keys\n");
    printf("    qgp --delete-key --name <name>\n\n");
    printf("  Configuration:\n");
    printf("    qgp --config-create       # Create default config file at ~/.qgp/config\n\n");
    printf("OPTIONS:\n");
    printf("  -g, --gen-key         Generate a new key pair (signing + encryption)\n");
    printf("  -F, --from-seed       Generate keys from BIP39 mnemonic (use with --gen-key)\n");
    printf("  -x, --export          Export public keys for sharing (ASCII armored)\n");
    printf("  -s, --sign            Sign a file (ASCII armored signature)\n");
    printf("  -v, --verify          Verify a file signature\n");
    printf("  -e, --encrypt         Encrypt a file (public key encryption)\n");
    printf("  -d, --decrypt         Decrypt a file\n");
    printf("  -I, --import          Import a public key to keyring\n");
    printf("  -L, --list-keys       List all keys in keyring\n");
    printf("  -D, --delete-key      Delete a key from keyring\n");
    printf("  -C, --config-create   Create default configuration file (~/.qgp/config)\n");
    printf("  -n, --name <name>     Key name (for generation/export/keyring)\n");
    printf("  -a, --algo <algo>     Algorithm: dilithium (FIPS 204 / ML-DSA-65)\n");
    printf("  -k, --key <name|path> Keyring name OR path to private key (.dsa/.kem)\n");
    printf("  -r, --recipient <key> Keyring name OR public key file (.asc)\n");
    printf("                        Use multiple -r flags for multi-recipient encryption\n");
    printf("  -o, --output <path>   Output directory or file\n");
    printf("  -f, --file <path>     File to sign, verify, encrypt, or decrypt\n");
    printf("  -S, --sig <path>      Signature file (default: <file>.asc)\n");
    printf("  -h, --help            Show this help\n");
    printf("  -V, --version         Show version\n\n");
    printf("EXAMPLES:\n");
    printf("  ┌─ Key Generation & Setup ──────────────────────────────────────────┐\n");
    printf("  │                                                                    │\n");
    printf("  │ # Generate keys (automatically registered in keyring)             │\n");
    printf("  │ qgp --gen-key --name alice                                    │\n");
    printf("  │ # Creates: ~/.qgp/alice.dsa                                   │\n");
    printf("  │ #          ~/.qgp/alice.kem                                   │\n");
    printf("  │ #          ~/.qgp/keyring/alice.pub (auto-registered)         │\n");
    printf("  │                                                                    │\n");
    printf("  │ # Generate keys from BIP39 mnemonic (recoverable!)                │\n");
    printf("  │ qgp --gen-key --from-seed --name alice                       │\n");
    printf("  │ # Prompts for 24-word mnemonic + optional passphrase              │\n");
    printf("  │ # Same mnemonic always generates same keys (deterministic)        │\n");
    printf("  │                                                                    │\n");
    printf("  │ # List all keys in keyring                                         │\n");
    printf("  │ qgp --list-keys                                               │\n");
    printf("  │                                                                    │\n");
    printf("  └────────────────────────────────────────────────────────────────────┘\n\n");
    printf("  ┌─ File Signing ─────────────────────────────────────────────────────┐\n");
    printf("  │                                                                    │\n");
    printf("  │ # Sign a file (using keyring name)                                │\n");
    printf("  │ qgp --sign --file document.pdf --key alice                    │\n");
    printf("  │ # Creates: document.pdf.asc                                        │\n");
    printf("  │                                                                    │\n");
    printf("  │ # Verify a signature                                               │\n");
    printf("  │ qgp --verify --file document.pdf                              │\n");
    printf("  │                                                                    │\n");
    printf("  └────────────────────────────────────────────────────────────────────┘\n\n");
    printf("  ┌─ Single-Recipient Encryption ──────────────────────────────────────┐\n");
    printf("  │                                                                    │\n");
    printf("  │ # Encrypt a file for Bob (using keyring names)                    │\n");
    printf("  │ qgp --encrypt --file secret.txt --recipient bob --key alice   │\n");
    printf("  │ # Creates: secret.txt.enc                                          │\n");
    printf("  │                                                                    │\n");
    printf("  │ # Bob decrypts the file (using keyring name)                      │\n");
    printf("  │ qgp --decrypt --file secret.txt.enc --key bob                 │\n");
    printf("  │ # Creates: secret.txt (verified signature from alice)              │\n");
    printf("  │                                                                    │\n");
    printf("  └────────────────────────────────────────────────────────────────────┘\n\n");
    printf("  ┌─ Multi-Recipient Encryption (NEW!) ────────────────────────────────┐\n");
    printf("  │                                                                    │\n");
    printf("  │ # Encrypt for multiple recipients (using keyring names)           │\n");
    printf("  │ qgp --encrypt --file confidential.pdf \\                       │\n");
    printf("  │   --recipient alice \\                                              │\n");
    printf("  │   --recipient bob \\                                                │\n");
    printf("  │   --recipient charlie \\                                            │\n");
    printf("  │   --key sender                                                     │\n");
    printf("  │ # Creates: confidential.pdf.enc                                    │\n");
    printf("  │                                                                    │\n");
    printf("  │ # Any recipient can decrypt (alice, bob, or charlie)              │\n");
    printf("  │ qgp --decrypt --file confidential.pdf.enc --key alice         │\n");
    printf("  │ # Creates: confidential.pdf (verified signature from sender)       │\n");
    printf("  │                                                                    │\n");
    printf("  │ # Short form with multiple -r flags                               │\n");
    printf("  │ pqsignum -e -f secret.txt -r alice -r bob -r charlie -k sender     │\n");
    printf("  │                                                                    │\n");
    printf("  └────────────────────────────────────────────────────────────────────┘\n\n");
    printf("  ┌─ Keyring Management ───────────────────────────────────────────────┐\n");
    printf("  │                                                                    │\n");
    printf("  │ # Import someone's public key                                      │\n");
    printf("  │ qgp --import --file bob.asc --name bob                        │\n");
    printf("  │                                                                    │\n");
    printf("  │ # Delete a key from keyring                                        │\n");
    printf("  │ qgp --delete-key --name bob                                   │\n");
    printf("  │                                                                    │\n");
    printf("  └────────────────────────────────────────────────────────────────────┘\n\n");
    printf("  ┌─ Configuration (NEW!) ─────────────────────────────────────────────┐\n");
    printf("  │                                                                    │\n");
    printf("  │ # Create default configuration file                                │\n");
    printf("  │ qgp --config-create                                           │\n");
    printf("  │ # Creates: ~/.qgp/config                                           │\n");
    printf("  │                                                                    │\n");
    printf("  │ # Edit config to set defaults:                                     │\n");
    printf("  │ # default_key_name = alice     # Default identity for ops         │\n");
    printf("  │ # default_algorithm = dilithium # Default signature algorithm      │\n");
    printf("  │                                                                    │\n");
    printf("  │ # After setting config, omit --key flag:                           │\n");
    printf("  │ qgp --sign --file document.pdf   # Uses alice key from config │\n");
    printf("  │                                                                    │\n");
    printf("  └────────────────────────────────────────────────────────────────────┘\n\n");
    printf("ALGORITHMS:\n");
    printf("  Signatures: ML-DSA-87 (FIPS 204)\n");
    printf("  Encryption: ML-KEM-1024 + AES-256-CBC\n");
    printf("  Multi-Recipient: RFC 3394 AES Key Wrap\n\n");
    printf("For more information, visit: https://github.com/nocdem/qgp\n");
}

/**
 * Resolve key parameter to full path
 * If it's a path that exists, return it as-is
 * Otherwise, lookup in keyring
 *
 * @param key_param: Either a path or a keyring name
 * @param key_type: "signing" or "encryption"
 * @return: allocated path string (caller must free), or NULL if not found
 */
char* resolve_key_path(const char *key_param, const char *key_type) {
    // If it's a valid file path, use it directly
    if (file_exists(key_param)) {
        return strdup(key_param);
    }

    // Otherwise, try to find in keyring
    char *path = keyring_find_private_key(key_param, key_type);
    if (path) {
        return path;
    }

    // Not found
    fprintf(stderr, "Error: Key '%s' not found (not a valid path and not in keyring)\n", key_param);
    fprintf(stderr, "  Use --list-keys to see available keys\n");
    return NULL;
}

/**
 * Resolve recipient parameter to full path
 * If it's a path that exists, return it as-is
 * Otherwise, lookup in keyring
 *
 * @param recipient_param: Either a path or a keyring name
 * @return: allocated path string (caller must free), or NULL if not found
 */
char* resolve_recipient_path(const char *recipient_param) {
    // If it's a valid file path, use it directly
    if (file_exists(recipient_param)) {
        return strdup(recipient_param);
    }

    // Otherwise, try to find in keyring
    char *path = keyring_find_key(recipient_param);
    if (path) {
        return path;
    }

    // Not found
    fprintf(stderr, "Error: Recipient '%s' not found (not a valid path and not in keyring)\n", recipient_param);
    fprintf(stderr, "  Use --list-keys to see available keys\n");
    fprintf(stderr, "  Or import the key with: qgp --import --file <pubkey.asc> --name %s\n", recipient_param);
    return NULL;
}


// All key deletion now uses qgp_key_free() from qgp_key.c
