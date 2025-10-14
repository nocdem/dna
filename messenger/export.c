/*
 * pqsignum - Export public keys for sharing
 *
 * - qgp_key_load() for loading keys (QGP format)
 * - Extracts public keys from loaded keys
 * - Bundles signing + encryption public keys
 * - Saves in shareable format
 */

#include "qgp.h"
#include "qgp_types.h"
#include "qgp_compiler.h"
#include <time.h>  // For time() and timestamp generation

// Public key bundle file format
#define PQSIGNUM_PUBKEY_MAGIC "PQPUBKEY"
#define PQSIGNUM_PUBKEY_VERSION 0x01

PACK_STRUCT_BEGIN
typedef struct {
    char magic[8];              // "PQPUBKEY"
    uint8_t version;            // 0x01
    uint8_t sign_key_type;      // Signing algorithm type
    uint8_t enc_key_type;       // Encryption algorithm type (always Kyber512)
    uint8_t reserved;           // Reserved
    uint32_t sign_pubkey_size;  // Signing public key size
    uint32_t enc_pubkey_size;   // Encryption public key size (800 bytes for Kyber512)
} PACK_STRUCT_END pqsignum_pubkey_header_t;

/**
 * Get signing algorithm name from type
 */
static const char* get_sign_algorithm_name(qgp_key_type_t type) {
    switch (type) {
        case QGP_KEY_TYPE_DILITHIUM3:
            return "Dilithium";
        case QGP_KEY_TYPE_KYBER512:
            return "Kyber512";
        default:
            return "Unknown";
    }
}

/**
 * Export public keys from certificates to shareable file
 *
 * Creates a .pub file containing:
 * - Header with metadata
 * - Signing public key
 * - Kyber512 encryption public key
 *
 * @param name: Certificate name (without .dcert extension)
 * @param cert_dir: Directory containing certificates
 * @param output_file: Output .pub file path
 * @param armor: If true, output ASCII armored format
 * @return: 0 on success, non-zero on error
 */
int cmd_export_pubkey(const char *name, const char *key_dir, const char *output_file) {
    qgp_key_t *sign_key = NULL;
    qgp_key_t *enc_key = NULL;
    uint8_t *sign_pubkey = NULL;
    uint8_t *enc_pubkey = NULL;
    uint64_t sign_pubkey_size = 0;
    uint64_t enc_pubkey_size = 0;
    int ret = EXIT_ERROR;

    printf("Exporting public keys for: %s\n", name);
    printf("  Key directory: %s\n", key_dir);
    printf("  Output file: %s\n", output_file);

    // Load signing key
    printf("\n[1/3] Loading signing key...\n");
    char sign_filename[512];
    snprintf(sign_filename, sizeof(sign_filename), "%s-dilithium3.pqkey", name);
    char *sign_key_path = build_path(key_dir, sign_filename);

    if (!file_exists(sign_key_path)) {
        fprintf(stderr, "Error: Signing key not found: %s\n", sign_key_path);
        fprintf(stderr, "Make sure you've generated keys with: qgp --gen-key --name %s\n", name);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }


    if (qgp_key_load(sign_key_path, &sign_key) != 0) {
        fprintf(stderr, "Error: Failed to load signing key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }
    printf("  ✓ Signing key loaded\n");

    // Load encryption key
    printf("\n[2/3] Loading encryption key...\n");
    char enc_filename[512];
    snprintf(enc_filename, sizeof(enc_filename), "%s-kyber512.pqkey", name);
    char *enc_key_path = build_path(key_dir, enc_filename);

    if (!file_exists(enc_key_path)) {
        fprintf(stderr, "Error: Encryption key not found: %s\n", enc_key_path);
        fprintf(stderr, "Make sure you've generated keys with: qgp --gen-key --name %s\n", name);
        free(sign_key_path);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }


    if (qgp_key_load(enc_key_path, &enc_key) != 0) {
        fprintf(stderr, "Error: Failed to load encryption key\n");
        free(sign_key_path);
        free(enc_key_path);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }
    printf("  ✓ Encryption key loaded\n");

    free(sign_key_path);
    free(enc_key_path);

    // Extract public keys
    printf("\n[3/3] Extracting public keys...\n");


    if (sign_key->type == QGP_KEY_TYPE_DILITHIUM3) {
        sign_pubkey_size = sign_key->public_key_size;
        sign_pubkey = malloc(sign_pubkey_size);
        if (!sign_pubkey) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            ret = EXIT_ERROR;
            goto cleanup;
        }
        memcpy(sign_pubkey, sign_key->public_key, sign_pubkey_size);
        printf("  ✓ Dilithium3 public key extracted (%lu bytes)\n", sign_pubkey_size);
    }

    // For Kyber, use raw public_key
    enc_pubkey_size = enc_key->public_key_size;
    if (enc_pubkey_size != 800) {
        fprintf(stderr, "Error: Invalid Kyber512 public key size (expected 800 bytes, got %lu)\n", enc_pubkey_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }
    enc_pubkey = malloc(enc_pubkey_size);
    if (!enc_pubkey) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }
    memcpy(enc_pubkey, enc_key->public_key, enc_pubkey_size);
    printf("  ✓ Encryption public key extracted (%lu bytes, Kyber512)\n", enc_pubkey_size);

    // Build header
    pqsignum_pubkey_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, PQSIGNUM_PUBKEY_MAGIC, 8);
    header.version = PQSIGNUM_PUBKEY_VERSION;
    header.sign_key_type = (uint8_t)sign_key->type;
    header.enc_key_type = (uint8_t)enc_key->type;
    header.reserved = 0;
    header.sign_pubkey_size = (uint32_t)sign_pubkey_size;
    header.enc_pubkey_size = (uint32_t)enc_pubkey_size;

    // Calculate total size
    size_t total_size = sizeof(header) + sign_pubkey_size + enc_pubkey_size;

    // ASCII armor output (always)
    printf("\n[4/4] Creating ASCII armored output...\n");

    // Assemble complete binary bundle in memory
    uint8_t *bundle = malloc(total_size);
    if (!bundle) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Copy all components to bundle
    memcpy(bundle, &header, sizeof(header));
    memcpy(bundle + sizeof(header), sign_pubkey, sign_pubkey_size);
    memcpy(bundle + sizeof(header) + sign_pubkey_size, enc_pubkey, enc_pubkey_size);

    // Build headers for armor
    static char header_buf[10][128];
    const char *armor_headers[10];
    size_t header_count = 0;

    snprintf(header_buf[0], sizeof(header_buf[0]), "Version: qgp 1.1");
    armor_headers[header_count++] = header_buf[0];

    snprintf(header_buf[1], sizeof(header_buf[1]), "Name: %s", name);
    armor_headers[header_count++] = header_buf[1];

    snprintf(header_buf[2], sizeof(header_buf[2]), "SigningAlgorithm: %s",
             get_sign_algorithm_name(sign_key->type));
    armor_headers[header_count++] = header_buf[2];

    snprintf(header_buf[3], sizeof(header_buf[3]), "EncryptionAlgorithm: Kyber512");
    armor_headers[header_count++] = header_buf[3];

    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", tm_info);
    snprintf(header_buf[4], sizeof(header_buf[4]), "Created: %s", time_str);
    armor_headers[header_count++] = header_buf[4];

    // Write armored file
    if (write_armored_file(output_file, "PUBLIC KEY", bundle, total_size,
                          armor_headers, header_count) != 0) {
        fprintf(stderr, "Error: Failed to write ASCII armored file\n");
        free(bundle);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    free(bundle);
    printf("  ✓ ASCII armored public key created\n");

    printf("\n✓ Public keys exported successfully!\n");
    printf("\nExported file: %s\n", output_file);
    printf("  Format: ASCII armored\n");
    printf("  Total size: %zu bytes\n", total_size);
    printf("\nShare this file with others so they can:\n");
    printf("  - Verify your signatures\n");
    printf("  - Encrypt files for you\n");
    printf("\nExample usage by others:\n");
    printf("  # Encrypt a file for you:\n");
    printf("  qgp --encrypt --file secret.txt --recipient %s\n", output_file);
    printf("\n  # Verify your signature:\n");
    printf("  qgp --verify --file document.pdf --pubkey %s\n", output_file);

    ret = EXIT_SUCCESS;

cleanup:
    if (sign_pubkey) free(sign_pubkey);
    if (enc_pubkey) free(enc_pubkey);


    if (sign_key) qgp_key_free(sign_key);
    if (enc_key) qgp_key_free(enc_key);

    return ret;
}
