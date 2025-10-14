/*
 * pqsignum - File encryption using Kyber512 KEM + AES-256
 *
 * - qgp_key_load() for loading signing keys (QGP format)
 * - qgp_kyber512_enc() for Kyber512 encapsulation (vendored)
 * - qgp_dilithium3_signature() for signing (vendored)
 * - qgp_aes256_encrypt() for AES encryption (standalone)
 *
 * Security Model:
 * - Kyber512 public key encapsulation (800-byte pubkey → 768-byte ciphertext)
 * - 32-byte shared secret derived via KEM
 * - AES-256-GCM encryption of file with derived key (AEAD)
 * - Header authenticated via AAD
 * - Round-trip verification mandatory
 */

#include "qgp.h"
#include "qgp_types.h"
#include "qgp_compiler.h"
#include "qgp_random.h"
#include "aes_keywrap.h"
#include "qgp_aes.h"
#include "qgp_kyber.h"
#include "qgp_dilithium.h"

// File format for Kyber-encrypted files
#define PQSIGNUM_ENC_MAGIC "PQSIGENC"
#define PQSIGNUM_ENC_VERSION 0x05  // Version 5: Multi-recipient with AES-GCM (AEAD)

// Unified header (supports 1-255 recipients)
PACK_STRUCT_BEGIN
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x05 (GCM)
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t reserved;
    uint32_t encrypted_size;    // Size of encrypted data (exact plaintext size, no padding)
    uint32_t signature_size;    // Size of signature
} PACK_STRUCT_END pqsignum_enc_header_t;

// Recipient entry for multi-recipient encryption
PACK_STRUCT_BEGIN
typedef struct {
    uint8_t kyber_ciphertext[768];    // Kyber512 ciphertext (encapsulated shared secret)
    uint8_t wrapped_dek[40];          // AES-wrapped DEK (32-byte DEK + 8-byte IV)
} PACK_STRUCT_END recipient_entry_t;

/**
 * Load recipient's public key from .pub file (binary or ASCII armored)
 *
 * Reads .pub file created by --export command
 * Extracts Kyber512 encryption public key (800 bytes)
 * Supports both binary and ASCII armored formats
 *
 * @param pubkey_file: Path to recipient's .pub file
 * @param pubkey_out: Output buffer for public key (caller must free)
 * @param pubkey_size_out: Output size of public key
 * @return: 0 on success, non-zero on error
 */
static int load_recipient_pubkey(const char *pubkey_file, uint8_t **pubkey_out, size_t *pubkey_size_out) {
    // Public key header structure (defined in export.c)
    PACK_STRUCT_BEGIN
    typedef struct {
        char magic[8];
        uint8_t version;
        uint8_t sign_key_type;
        uint8_t enc_key_type;
        uint8_t reserved;
        uint32_t sign_pubkey_size;
        uint32_t enc_pubkey_size;
    } PACK_STRUCT_END pqsignum_pubkey_header_t;

    uint8_t *bundle_data = NULL;
    size_t bundle_size = 0;
    pqsignum_pubkey_header_t header;
    char *recipient_name = NULL;

    // Check if file is ASCII armored
    if (is_armored_file(pubkey_file)) {
        printf("  Detected ASCII armored public key\n");

        // Read armored file
        char *type = NULL;
        char **headers = NULL;
        size_t header_count = 0;

        if (read_armored_file(pubkey_file, &type, &bundle_data, &bundle_size,
                             &headers, &header_count) != 0) {
            fprintf(stderr, "Error: Failed to read ASCII armored public key\n");
            return EXIT_ERROR;
        }

        // Verify type
        if (strcmp(type, "PUBLIC KEY") != 0) {
            fprintf(stderr, "Error: Expected PUBLIC KEY, got: %s\n", type);
            free(type);
            free(bundle_data);
            for (size_t i = 0; i < header_count; i++) free(headers[i]);
            free(headers);
            return EXIT_ERROR;
        }

        // Extract name from armor headers
        for (size_t i = 0; i < header_count; i++) {
            if (strncmp(headers[i], "Name: ", 6) == 0) {
                recipient_name = strdup(headers[i] + 6);
                break;
            }
        }

        // Cleanup armor metadata
        free(type);
        for (size_t i = 0; i < header_count; i++) free(headers[i]);
        free(headers);

        // Extract header from bundle
        if (bundle_size < sizeof(pqsignum_pubkey_header_t)) {
            fprintf(stderr, "Error: ASCII armored data too small for public key\n");
            free(bundle_data);
            return EXIT_ERROR;
        }

        memcpy(&header, bundle_data, sizeof(header));

    } else {
        // Binary format
        FILE *fp = fopen(pubkey_file, "rb");
        if (!fp) {
            fprintf(stderr, "Error: Cannot open recipient public key file: %s\n", pubkey_file);
            return EXIT_ERROR;
        }

        // Read header
        if (fread(&header, 1, sizeof(header), fp) != sizeof(header)) {
            fprintf(stderr, "Error: Failed to read public key file header\n");
            fclose(fp);
            return EXIT_ERROR;
        }

        // Calculate bundle size and read entire file
        bundle_size = sizeof(header) + header.sign_pubkey_size + header.enc_pubkey_size;
        bundle_data = malloc(bundle_size);
        if (!bundle_data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            fclose(fp);
            return EXIT_ERROR;
        }

        // Copy header and read rest of file
        memcpy(bundle_data, &header, sizeof(header));
        size_t remaining = bundle_size - sizeof(header);
        if (fread(bundle_data + sizeof(header), 1, remaining, fp) != remaining) {
            fprintf(stderr, "Error: Failed to read public key data\n");
            fclose(fp);
            free(bundle_data);
            return EXIT_ERROR;
        }

        fclose(fp);
    }

    // Validate header
    if (memcmp(header.magic, "PQPUBKEY", 8) != 0) {
        fprintf(stderr, "Error: Invalid public key file format (bad magic)\n");
        free(bundle_data);
        return EXIT_ERROR;
    }

    if (header.version != 0x01) {
        fprintf(stderr, "Error: Unsupported public key file version: 0x%02x\n", header.version);
        free(bundle_data);
        return EXIT_ERROR;
    }


    if (header.enc_key_type != QGP_KEY_TYPE_KYBER512) {
        fprintf(stderr, "Error: Public key does not contain Kyber512 encryption key (got type: %d)\n", header.enc_key_type);
        free(bundle_data);
        return EXIT_ERROR;
    }

    if (header.enc_pubkey_size != 800) {
        fprintf(stderr, "Error: Invalid Kyber512 public key size: %u (expected 800)\n", header.enc_pubkey_size);
        free(bundle_data);
        return EXIT_ERROR;
    }

    // Extract encryption public key from bundle
    size_t enc_pubkey_offset = sizeof(header) + header.sign_pubkey_size;
    if (enc_pubkey_offset + header.enc_pubkey_size > bundle_size) {
        fprintf(stderr, "Error: Bundle data truncated\n");
        free(bundle_data);
        return EXIT_ERROR;
    }

    uint8_t *pubkey = malloc(header.enc_pubkey_size);
    if (!pubkey) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(bundle_data);
        return EXIT_ERROR;
    }

    memcpy(pubkey, bundle_data + enc_pubkey_offset, header.enc_pubkey_size);
    free(bundle_data);

    if (recipient_name) {
        printf("✓ Loaded recipient public key: %s\n", recipient_name);
        free(recipient_name);
    } else {
        printf("✓ Loaded recipient public key\n");
    }
    printf("  Kyber512 public key: %u bytes\n", header.enc_pubkey_size);

    *pubkey_out = pubkey;
    *pubkey_size_out = header.enc_pubkey_size;
    return EXIT_SUCCESS;
}

/**
 * Encrypt and sign file using Kyber512 KEM + AES-256 (unified format)
 *
 * Unified encryption workflow (supports 1-255 recipients):
 * 1. Load all recipient public keys
 * 2. Load sender's signing key
 * 3. Sign the plaintext file
 * 4. Generate random 32-byte DEK (Data Encryption Key)
 * 5. Encrypt file with DEK using AES-256-GCM (AEAD with header as AAD)
 * 6. For each recipient:
 *    - Encapsulate: Kyber512.Encap(recipient_pubkey) → shared_secret + ciphertext
 *    - Wrap DEK with KEK using AES Key Wrap (RFC 3394)
 *    - Store recipient entry: [kyber_ciphertext | wrapped_dek]
 * 7. Save: [header | recipient_entries | nonce | encrypted_data | tag | signature]
 *
 * @param input_file: File to encrypt
 * @param output_file: Output encrypted file (.enc)
 * @param recipient_pubkey_files: Array of recipient .pub files or keyring names
 * @param recipient_count: Number of recipients (1-255)
 * @param signing_key_path: Sender's signing private key
 * @return: 0 on success, non-zero on error
 */
int cmd_encrypt_file(const char *input_file, const char *output_file,
                     const char **recipient_pubkey_files, size_t recipient_count,
                     const char *signing_key_path) {

    // Validate recipient count
    if (recipient_count == 0 || recipient_count > 255) {
        fprintf(stderr, "Error: Invalid recipient count: %zu (must be 1-255)\n", recipient_count);
        return EXIT_ERROR;
    }

    uint8_t **recipient_pubkeys = NULL;
    size_t *recipient_pubkey_sizes = NULL;
    char **resolved_pubkey_paths = NULL;
    qgp_key_t *sign_key = NULL;
    qgp_signature_t *signature = NULL;
    uint8_t *sig_bytes = NULL;  // Serialized signature
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *dek = NULL;
    recipient_entry_t *recipient_entries = NULL;
    FILE *out_fp = NULL;
    int ret = EXIT_ERROR;
    size_t plaintext_size = 0;
    size_t ciphertext_size = 0;
    size_t signature_size = 0;

    printf("Encrypting and signing file for %zu recipient(s) with Kyber512 KEM + AES-256\n", recipient_count);
    printf("  Input file: %s\n", input_file);
    printf("  Output file: %s\n", output_file);
    printf("  Signing key: %s\n", signing_key_path);

    // ======================================================================
    // STEP 1: Allocate arrays for recipients
    // ======================================================================

    recipient_pubkeys = calloc(recipient_count, sizeof(uint8_t*));
    recipient_pubkey_sizes = calloc(recipient_count, sizeof(size_t));
    resolved_pubkey_paths = calloc(recipient_count, sizeof(char*));
    recipient_entries = calloc(recipient_count, sizeof(recipient_entry_t));

    if (!recipient_pubkeys || !recipient_pubkey_sizes || !resolved_pubkey_paths || !recipient_entries) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // ======================================================================
    // STEP 2: Resolve and load all recipient public keys
    // ======================================================================

    printf("\n[1/7] Loading %zu recipient public key(s)...\n", recipient_count);

    for (size_t i = 0; i < recipient_count; i++) {
        printf("\nRecipient %zu/%zu: %s\n", i+1, recipient_count, recipient_pubkey_files[i]);

        // Check if recipient is a file that exists
        if (!file_exists(recipient_pubkey_files[i])) {
            // Not a file - try keyring lookup
            printf("  Searching keyring for '%s'...\n", recipient_pubkey_files[i]);
            resolved_pubkey_paths[i] = keyring_find_key(recipient_pubkey_files[i]);

            if (!resolved_pubkey_paths[i]) {
                fprintf(stderr, "Error: Recipient not found in keyring and not a valid file: %s\n",
                       recipient_pubkey_files[i]);
                fprintf(stderr, "To import a key: qgp --import --file <pubkey.asc> --name %s\n",
                       recipient_pubkey_files[i]);
                ret = EXIT_ERROR;
                goto cleanup;
            }

            printf("  ✓ Found in keyring: %s\n", resolved_pubkey_paths[i]);
        } else {
            // Recipient is an existing file
            resolved_pubkey_paths[i] = (char*)recipient_pubkey_files[i];
        }

        // Load recipient's public key
        if (load_recipient_pubkey(resolved_pubkey_paths[i],
                                 &recipient_pubkeys[i],
                                 &recipient_pubkey_sizes[i]) != EXIT_SUCCESS) {
            ret = EXIT_ERROR;
            goto cleanup;
        }
    }

    printf("\n✓ All recipient public keys loaded successfully\n");

    // ======================================================================
    // STEP 3: Load signing key
    // ======================================================================

    printf("\n[2/7] Loading signing key...\n");
    if (!file_exists(signing_key_path)) {
        fprintf(stderr, "Error: Signing key not found: %s\n", signing_key_path);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }


    if (qgp_key_load(signing_key_path, &sign_key) != 0) {
        fprintf(stderr, "Error: Failed to load signing key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }
    printf("  ✓ Signing key loaded\n");

    // ======================================================================
    // STEP 4: Read input file
    // ======================================================================

    printf("\n[3/7] Reading input file...\n");

    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fseek(in_fp, 0, SEEK_END);
    plaintext_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);

    plaintext = malloc(plaintext_size);
    if (!plaintext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fread(plaintext, 1, plaintext_size, in_fp) != plaintext_size) {
        fprintf(stderr, "Error: Failed to read input file\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(in_fp);
    printf("  ✓ Read %zu bytes from input file\n", plaintext_size);

    // ======================================================================
    // ======================================================================

    printf("\n[4/7] Signing file...\n");


    if (sign_key->type != QGP_KEY_TYPE_DILITHIUM3) {
        fprintf(stderr, "Error: Only Dilithium3 signatures are supported\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    size_t dilithium_sig_size = QGP_DILITHIUM3_BYTES;
    size_t pkey_size = QGP_DILITHIUM3_PUBLICKEYBYTES;

    // Allocate QGP signature structure
    signature = qgp_signature_new(QGP_SIG_TYPE_DILITHIUM, pkey_size, dilithium_sig_size);
    if (!signature) {
        fprintf(stderr, "Error: Memory allocation failed for signature\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Copy public key to signature data
    memcpy(qgp_signature_get_pubkey(signature), sign_key->public_key, pkey_size);

    // Create Dilithium3 signature
    size_t actual_sig_len = 0;
    if (qgp_dilithium3_signature(
            qgp_signature_get_bytes(signature),  // Output after public key
            &actual_sig_len,
            plaintext, plaintext_size,
            sign_key->private_key) != 0) {
        fprintf(stderr, "Error: Dilithium3 signature creation failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Update signature size with actual length
    signature->signature_size = actual_sig_len;

    // Protocol Mode: MANDATORY round-trip verification
    if (qgp_dilithium3_verify(
            qgp_signature_get_bytes(signature),  // Signature after public key
            actual_sig_len,
            plaintext, plaintext_size,
            qgp_signature_get_pubkey(signature)) != 0) {  // Public key at start
        fprintf(stderr, "Error: Round-trip verification FAILED\n");
        fprintf(stderr, "Signature is invalid - will not save\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Get signature size and serialize
    signature_size = qgp_signature_get_size(signature);
    if (signature_size == 0) {
        fprintf(stderr, "Error: Failed to get signature size\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Serialize signature for writing
    sig_bytes = QGP_MALLOC(signature_size);
    if (!sig_bytes) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (qgp_signature_serialize(signature, sig_bytes) == 0) {
        fprintf(stderr, "Error: Signature serialization failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File signed successfully\n");
    printf("  ✓ Signature size: %zu bytes\n", signature_size);
    printf("  ✓ Algorithm: Dilithium3\n");

    // ======================================================================
    // STEP 6: Generate random DEK (Data Encryption Key)
    // ======================================================================

    printf("\n[5/7] Generating random 32-byte DEK (Data Encryption Key)...\n");

    dek = malloc(32);
    if (!dek) {
        fprintf(stderr, "Error: Memory allocation failed for DEK\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Generate random 32-byte DEK using QGP's random function
    if (qgp_randombytes(dek, 32) != 0) {
        fprintf(stderr, "Error: Failed to generate random DEK\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ Random DEK generated: 32 bytes\n");

    // ======================================================================
    // STEP 7: Encrypt file with DEK using AES-256-GCM (AEAD)
    // ======================================================================

    printf("\n[6/7] Encrypting file with AES-256-GCM using DEK...\n");

    // Allocate buffers for GCM
    uint8_t nonce[12];  // GCM nonce (12 bytes)
    uint8_t tag[16];    // GCM authentication tag (16 bytes)

    // Prepare header as AAD (Additional Authenticated Data)
    // This authenticates the header without encrypting it
    pqsignum_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, PQSIGNUM_ENC_MAGIC, 8);
    header_for_aad.version = PQSIGNUM_ENC_VERSION;
    header_for_aad.enc_key_type = (uint8_t)DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header_for_aad.recipient_count = (uint8_t)recipient_count;
    header_for_aad.encrypted_size = (uint32_t)plaintext_size;  // GCM: exact plaintext size
    header_for_aad.signature_size = (uint32_t)signature_size;

    // Allocate exact size for ciphertext (GCM has no padding)
    ciphertext = malloc(plaintext_size);
    if (!ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed for ciphertext\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Encrypt with AES-256-GCM using OpenSSL
    // DEK is 32 bytes (256 bits) - perfect for AES-256
    // Header is authenticated (AAD) but not encrypted
    if (qgp_aes256_encrypt(dek, plaintext, plaintext_size,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           ciphertext, &ciphertext_size,
                           nonce, tag) != 0) {
        fprintf(stderr, "Error: AES-256-GCM encryption failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File encrypted successfully\n");
    printf("  ✓ Encrypted size: %zu bytes (exact plaintext size, no padding)\n", ciphertext_size);
    printf("  ✓ GCM nonce: 12 bytes\n");
    printf("  ✓ GCM authentication tag: 16 bytes\n");

    // ======================================================================
    // STEP 8: Create recipient entries (wrap DEK for each recipient)
    // ======================================================================

    printf("\n[7/7] Creating recipient entries (wrapping DEK for each recipient)...\n");

    for (size_t i = 0; i < recipient_count; i++) {
        printf("\nRecipient %zu/%zu:\n", i+1, recipient_count);


        // Allocate buffers for Kyber ciphertext and shared secret (KEK)
        uint8_t *kyber_ciphertext = malloc(QGP_KYBER512_CIPHERTEXTBYTES);
        uint8_t *kek = malloc(QGP_KYBER512_BYTES);  // KEK = shared secret

        if (!kyber_ciphertext || !kek) {
            fprintf(stderr, "Error: Memory allocation failed for recipient %zu\n", i+1);
            if (kyber_ciphertext) free(kyber_ciphertext);
            if (kek) free(kek);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        // Perform Kyber512 encapsulation: KEM.Encaps(recipient_pubkey) → (ciphertext, shared_secret/KEK)
        if (qgp_kyber512_enc(kyber_ciphertext, kek, recipient_pubkeys[i]) != 0) {
            fprintf(stderr, "Error: Kyber512 encapsulation failed for recipient %zu\n", i+1);
            free(kyber_ciphertext);
            memset(kek, 0, QGP_KYBER512_BYTES);  // Wipe KEK before freeing
            free(kek);
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        printf("  ✓ Kyber512 encapsulation successful\n");

        // Wrap DEK with KEK using AES Key Wrap (RFC 3394)
        uint8_t wrapped_dek[40];  // 32-byte DEK + 8-byte IV
        if (aes256_wrap_key(dek, 32, kek, wrapped_dek) != 0) {
            fprintf(stderr, "Error: Failed to wrap DEK for recipient %zu\n", i+1);
            free(kyber_ciphertext);
            memset(kek, 0, QGP_KYBER512_BYTES);  // Wipe KEK before freeing
            free(kek);
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        printf("  ✓ DEK wrapped successfully (AES Key Wrap)\n");

        // Store recipient entry
        memcpy(recipient_entries[i].kyber_ciphertext, kyber_ciphertext, 768);
        memcpy(recipient_entries[i].wrapped_dek, wrapped_dek, 40);

        // Cleanup for this recipient (securely wipe KEK)
        free(kyber_ciphertext);
        memset(kek, 0, QGP_KYBER512_BYTES);  // Wipe KEK
        free(kek);
    }

    printf("\n✓ All recipient entries created successfully\n");

    // ======================================================================
    // STEP 9: Write output file
    // ======================================================================

    printf("\n[8/8] Writing output file...\n");

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write unified header
    pqsignum_enc_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, PQSIGNUM_ENC_MAGIC, 8);
    header.version = PQSIGNUM_ENC_VERSION;
    header.enc_key_type = (uint8_t)DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header.recipient_count = (uint8_t)recipient_count;
    header.encrypted_size = (uint32_t)ciphertext_size;
    header.signature_size = (uint32_t)signature_size;

    if (fwrite(&header, 1, sizeof(header), out_fp) != sizeof(header)) {
        fprintf(stderr, "Error: Failed to write header\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write all recipient entries
    for (size_t i = 0; i < recipient_count; i++) {
        if (fwrite(&recipient_entries[i], 1, sizeof(recipient_entry_t), out_fp) != sizeof(recipient_entry_t)) {
            fprintf(stderr, "Error: Failed to write recipient entry %zu\n", i+1);
            ret = EXIT_ERROR;
            goto cleanup;
        }
    }

    // Write GCM nonce (12 bytes)
    if (fwrite(nonce, 1, 12, out_fp) != 12) {
        fprintf(stderr, "Error: Failed to write GCM nonce\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write encrypted file data
    if (fwrite(ciphertext, 1, ciphertext_size, out_fp) != ciphertext_size) {
        fprintf(stderr, "Error: Failed to write encrypted data\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write GCM authentication tag (16 bytes)
    if (fwrite(tag, 1, 16, out_fp) != 16) {
        fprintf(stderr, "Error: Failed to write GCM authentication tag\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write signature (appended at end)
    if (fwrite(sig_bytes, 1, signature_size, out_fp) != signature_size) {
        fprintf(stderr, "Error: Failed to write signature\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(out_fp);
    out_fp = NULL;

    printf("  ✓ Output file written\n");

    size_t total_size = sizeof(header) + (sizeof(recipient_entry_t) * recipient_count) + 12 + ciphertext_size + 16 + signature_size;
    size_t recipient_overhead = sizeof(recipient_entry_t) * recipient_count;

    printf("\n✓ File encrypted and signed for %zu recipient(s)!\n", recipient_count);
    printf("\nOutput file: %s\n", output_file);
    printf("  Total size: %zu bytes\n", total_size);
    printf("  Header: %zu bytes\n", sizeof(header));
    printf("  Recipient entries: %zu bytes (%zu bytes × %zu recipients)\n",
           recipient_overhead, sizeof(recipient_entry_t), recipient_count);
    printf("  GCM nonce: 12 bytes\n");
    printf("  Encrypted data: %zu bytes\n", ciphertext_size);
    printf("  GCM tag: 16 bytes\n");
    printf("  Signature: %zu bytes (%s)\n", signature_size, get_signature_algorithm_name(signature));
    printf("\nFormat: v0.05 (AES-GCM AEAD)\n");
    printf("Any of the %zu recipient(s) can decrypt this file and verify it came from you.\n", recipient_count);

    ret = EXIT_SUCCESS;

cleanup:
    if (recipient_pubkeys) {
        for (size_t i = 0; i < recipient_count; i++) {
            if (recipient_pubkeys[i]) free(recipient_pubkeys[i]);
        }
        free(recipient_pubkeys);
    }
    if (recipient_pubkey_sizes) free(recipient_pubkey_sizes);
    if (resolved_pubkey_paths) {
        for (size_t i = 0; i < recipient_count; i++) {
            if (resolved_pubkey_paths[i] && resolved_pubkey_paths[i] != recipient_pubkey_files[i]) {
                free(resolved_pubkey_paths[i]);  // Only free if allocated by keyring_find_key()
            }
        }
        free(resolved_pubkey_paths);
    }
    if (sign_key) qgp_key_free(sign_key);
    if (sig_bytes) QGP_FREE(sig_bytes);
    if (signature) qgp_signature_free(signature);
    if (plaintext) {
        memset(plaintext, 0, plaintext_size);  // Wipe plaintext
        free(plaintext);
    }
    if (dek) {
        memset(dek, 0, 32);  // Wipe DEK
        free(dek);
    }
    if (ciphertext) free(ciphertext);
    if (recipient_entries) free(recipient_entries);
    if (out_fp) fclose(out_fp);

    return ret;
}
