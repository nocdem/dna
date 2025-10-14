/*
 * pqsignum - File decryption using Kyber512 KEM + AES-256-GCM (AEAD)
 *
 * - qgp_key_load() for loading encryption keys (QGP format)
 * - qgp_kyber512_dec() for Kyber512 decapsulation (vendored)
 * - qgp_dilithium3_verify() for signature verification (vendored)
 * - qgp_aes256_decrypt() for AES-GCM decryption with AAD (standalone)
 *
 * Security Model:
 * - Kyber512 private key decapsulation (768-byte ciphertext → 32-byte shared secret)
 * - AES-256-GCM (AEAD) decryption of file with derived key
 * - Header authenticated via AAD (Additional Authenticated Data)
 * - GCM authentication tag verification (integrity + authenticity)
 * - Signature verification mandatory for authenticated files
 */

#include "qgp.h"
#include "qgp_types.h"
#include "qgp_compiler.h"
#include "aes_keywrap.h"
#include "qgp_aes.h"
#include "qgp_kyber.h"
#include "qgp_dilithium.h"

// File format for Kyber-encrypted files (must match encrypt.c)
#define PQSIGNUM_ENC_MAGIC "PQSIGENC"
#define PQSIGNUM_ENC_VERSION 0x05  // Version 5: Multi-recipient with AES-256-GCM (AEAD)

// Unified header (supports 1-255 recipients)
PACK_STRUCT_BEGIN
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x05
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t reserved;
    uint32_t encrypted_size;    // Size of encrypted data (GCM ciphertext, exact plaintext size)
    uint32_t signature_size;    // Size of signature
} PACK_STRUCT_END pqsignum_enc_header_t;

// Recipient entry for multi-recipient encryption
PACK_STRUCT_BEGIN
typedef struct {
    uint8_t kyber_ciphertext[768];    // Kyber512 ciphertext (encapsulated shared secret)
    uint8_t wrapped_dek[40];          // AES-wrapped DEK (32-byte DEK + 8-byte IV)
} PACK_STRUCT_END recipient_entry_t;

/**
 * Decrypt file using Kyber512 KEM + AES-256-GCM (AEAD)
 *
 * Protocol Mode decryption workflow:
 * 1. Load recipient's private Kyber512 key
 * 2. Read encrypted file: [header | recipient_entries | nonce | ciphertext | tag | signature]
 * 3. Try each recipient entry: Kyber512.Decap(ciphertext, privkey) → KEK
 * 4. Unwrap DEK using KEK: AES-Unwrap(wrapped_dek, KEK) → DEK
 * 5. Reconstruct header as AAD for authentication
 * 6. Decrypt with AES-256-GCM: AES-GCM.Decrypt(ciphertext, DEK, nonce, tag, AAD) → plaintext
 * 7. GCM automatically verifies tag (integrity + authenticity)
 * 8. Verify signature (sender authentication)
 * 9. Save decrypted file
 *
 * @param input_file: Encrypted file (.enc)
 * @param output_file: Output decrypted file
 * @param key_path: Path to recipient's encryption key
 * @return: 0 on success, non-zero on error
 */
int cmd_decrypt_file(const char *input_file, const char *output_file, const char *key_path) {
    qgp_key_t *enc_key = NULL;
    recipient_entry_t *recipient_entries = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *decrypted_data = NULL;
    uint8_t *signature_data = NULL;
    uint8_t *dek = NULL;
    qgp_signature_t *signature = NULL;
    uint8_t nonce[12];              // GCM nonce
    uint8_t tag[16];                // GCM authentication tag
    size_t encrypted_size = 0;
    size_t decrypted_size = 0;
    size_t signature_size = 0;
    uint8_t recipient_count = 0;
    FILE *out_fp = NULL;
    int ret = EXIT_ERROR;
    int found_entry = -1;

    printf("Decrypting file with Kyber512 KEM + AES-256-GCM (AEAD)\n");
    printf("  Input file: %s\n", input_file);
    printf("  Output file: %s\n", output_file);
    printf("  Encryption key: %s\n", key_path);

    // ======================================================================
    // STEP 1: Load encryption key
    // ======================================================================

    printf("\n[1/6] Loading encryption key...\n");

    if (!file_exists(key_path)) {
        fprintf(stderr, "Error: Encryption key not found: %s\n", key_path);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }


    if (qgp_key_load(key_path, &enc_key) != 0) {
        fprintf(stderr, "Error: Failed to load encryption key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    // Verify it's a Kyber512 encryption key
    if (enc_key->type != QGP_KEY_TYPE_KYBER512) {
        fprintf(stderr, "Error: Key is not a Kyber512 encryption key (type: %d)\n", enc_key->type);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    printf("  ✓ Encryption key loaded\n");

    // ======================================================================
    // STEP 2: Read file header
    // ======================================================================

    printf("\n[2/6] Reading file header...\n");

    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Read unified header
    pqsignum_enc_header_t header;
    if (fread(&header, 1, sizeof(header), in_fp) != sizeof(header)) {
        fprintf(stderr, "Error: Failed to read file header\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Validate header
    if (memcmp(header.magic, PQSIGNUM_ENC_MAGIC, 8) != 0) {
        fprintf(stderr, "Error: Invalid file format (bad magic)\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (header.version != PQSIGNUM_ENC_VERSION) {
        fprintf(stderr, "Error: Unsupported file version: 0x%02x (expected 0x%02x)\n", header.version, PQSIGNUM_ENC_VERSION);
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (header.enc_key_type != DAP_ENC_KEY_TYPE_KEM_KYBER512) {
        fprintf(stderr, "Error: File not encrypted with Kyber512 KEM\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    recipient_count = header.recipient_count;
    encrypted_size = header.encrypted_size;
    signature_size = header.signature_size;

    printf("  ✓ File format: Unified (supports 1-255 recipients)\n");
    printf("  ✓ Recipients: %u\n", recipient_count);
    printf("  ✓ Encrypted size: %zu bytes\n", encrypted_size);
    printf("  ✓ Signature size: %zu bytes\n", signature_size);

    // ======================================================================
    // STEP 3: Read all recipient entries
    // ======================================================================

    printf("\n[3/6] Reading recipient entries...\n");

    recipient_entries = calloc(recipient_count, sizeof(recipient_entry_t));
    if (!recipient_entries) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    for (int i = 0; i < recipient_count; i++) {
        if (fread(&recipient_entries[i], 1, sizeof(recipient_entry_t), in_fp) != sizeof(recipient_entry_t)) {
            fprintf(stderr, "Error: Failed to read recipient entry %d\n", i+1);
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }
    }

    printf("  ✓ Read %u recipient entries (%zu bytes each)\n", recipient_count, sizeof(recipient_entry_t));

    // ======================================================================
    // STEP 4: Try each recipient entry to find ours
    // ======================================================================

    printf("\n[4/6] Finding matching recipient entry...\n");

    // Get private key
    uint8_t *privkey_bytes = enc_key->private_key;
    size_t privkey_size = enc_key->private_key_size;

    if (!privkey_bytes || privkey_size != 1632) {
        fprintf(stderr, "Error: Invalid private key (expected 1632 bytes, got %zu)\n", privkey_size);
        fclose(in_fp);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    dek = malloc(32);
    if (!dek) {
        fprintf(stderr, "Error: Memory allocation failed for DEK\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    for (int i = 0; i < recipient_count; i++) {
        printf("  Trying recipient entry %d/%u...\n", i+1, recipient_count);


        // Decapsulate to get KEK using our private key
        uint8_t *kek = malloc(QGP_KYBER512_BYTES);
        if (!kek) {
            fprintf(stderr, "Error: Memory allocation failed for KEK\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        // Perform Kyber512 decapsulation: KEM.Decaps(ciphertext, privkey) → KEK (shared secret)
        if (qgp_kyber512_dec(kek, recipient_entries[i].kyber_ciphertext, privkey_bytes) != 0) {
            printf("    ✗ Decapsulation failed\n");
            memset(kek, 0, QGP_KYBER512_BYTES);  // Wipe KEK before freeing
            free(kek);
            continue;
        }

        // Try to unwrap DEK with this KEK
        if (aes256_unwrap_key(recipient_entries[i].wrapped_dek, 40, kek, dek) == 0) {
            // Success! This is our entry
            printf("    ✓ Found matching entry: %d/%u\n", i+1, recipient_count);
            found_entry = i;
            memset(kek, 0, QGP_KYBER512_BYTES);  // Wipe KEK
            free(kek);
            break;
        }

        printf("    ✗ DEK unwrap failed\n");
        memset(kek, 0, QGP_KYBER512_BYTES);  // Wipe KEK before freeing
        free(kek);
    }

    if (found_entry == -1) {
        fprintf(stderr, "Error: File not encrypted for your key\n");
        fprintf(stderr, "Tried all %u recipient entries - none matched\n", recipient_count);
        fclose(in_fp);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ DEK unwrapped successfully\n");

    // ======================================================================
    // STEP 5: Read nonce, encrypted data, and tag (ONLY - not signature yet)
    // ======================================================================

    printf("\n[5/8] Reading encrypted data...\n");

    // Read GCM nonce (12 bytes)
    if (fread(nonce, 1, 12, in_fp) != 12) {
        fprintf(stderr, "Error: Failed to read GCM nonce\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }
    printf("  ✓ Nonce read: 12 bytes\n");

    // Read encrypted data
    encrypted_data = malloc(encrypted_size);
    if (!encrypted_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fread(encrypted_data, 1, encrypted_size, in_fp) != encrypted_size) {
        fprintf(stderr, "Error: Failed to read encrypted data\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }
    printf("  ✓ Encrypted data read: %zu bytes\n", encrypted_size);

    // Read GCM authentication tag (16 bytes)
    if (fread(tag, 1, 16, in_fp) != 16) {
        fprintf(stderr, "Error: Failed to read GCM tag\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }
    printf("  ✓ Authentication tag read: 16 bytes\n");

    // ======================================================================
    // STEP 6: Decrypt and verify GCM IMMEDIATELY (fail-fast)
    // ======================================================================

    printf("\n[6/8] Decrypting and verifying file with AES-256-GCM...\n");

    // Reconstruct header as AAD for authentication
    pqsignum_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, PQSIGNUM_ENC_MAGIC, 8);
    header_for_aad.version = PQSIGNUM_ENC_VERSION;
    header_for_aad.enc_key_type = DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header_for_aad.recipient_count = recipient_count;
    header_for_aad.reserved = 0;
    header_for_aad.encrypted_size = encrypted_size;
    header_for_aad.signature_size = signature_size;

    // GCM produces exact plaintext size (no padding)
    size_t decrypt_buf_size = encrypted_size;

    decrypted_data = malloc(decrypt_buf_size);
    if (!decrypted_data) {
        fprintf(stderr, "Error: Memory allocation failed for decrypted data\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Decrypt with AES-256-GCM (AEAD)
    // This will verify the authentication tag and AAD
    // If tag verification fails, decryption will fail (tamper detection)
    // FAIL-FAST: This happens BEFORE reading signature data
    if (qgp_aes256_decrypt(dek, encrypted_data, encrypted_size,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           nonce, tag,
                           decrypted_data, &decrypted_size) != 0) {
        fprintf(stderr, "\n✗ SECURITY ERROR: GCM authentication failed\n");
        fprintf(stderr, "✗ File has been tampered with - aborting immediately\n");
        fprintf(stderr, "\nThis means:\n");
        fprintf(stderr, "  - Ciphertext was modified, OR\n");
        fprintf(stderr, "  - Header was modified, OR\n");
        fprintf(stderr, "  - Wrong key/nonce/tag\n");
        fprintf(stderr, "\nDecryption aborted - no file will be saved\n");
        fclose(in_fp);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File decrypted successfully\n");
    printf("  ✓ GCM authentication tag verified (ciphertext integrity confirmed)\n");
    printf("  ✓ Decrypted size: %zu bytes\n", decrypted_size);

    // ======================================================================
    // STEP 7: Read and parse signature (only after successful GCM verification)
    // ======================================================================

    if (signature_size > 0) {
        printf("\n[7/8] Reading signature...\n");

        signature_data = malloc(signature_size);
        if (!signature_data) {
            fprintf(stderr, "Error: Memory allocation failed for signature\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        if (fread(signature_data, 1, signature_size, in_fp) != signature_size) {
            fprintf(stderr, "Error: Failed to read signature\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        printf("  ✓ Signature read: %zu bytes\n", signature_size);

        if (qgp_signature_deserialize(signature_data, signature_size, &signature) != 0) {
            fprintf(stderr, "Error: Invalid signature structure\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }
    }

    fclose(in_fp);

    // ======================================================================
    // STEP 8: Verify signature (sender authentication)
    // ======================================================================

    if (signature) {
        printf("\n[8/9] Verifying signature...\n");


        if (signature->type != QGP_SIG_TYPE_DILITHIUM) {
            fprintf(stderr, "  ✗ Error: Only Dilithium3 signatures are supported\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        // Extract public key and signature bytes from qgp_signature_t structure
        uint8_t *public_key = qgp_signature_get_pubkey(signature);
        uint8_t *sig_bytes = qgp_signature_get_bytes(signature);
        size_t sig_size = signature->signature_size;

        printf("  Public key size: %u bytes\n", signature->public_key_size);
        printf("  Signature size: %zu bytes\n", sig_size);

        // Verify signature against decrypted data using vendored Dilithium3
        if (qgp_dilithium3_verify(sig_bytes, sig_size, decrypted_data, decrypted_size, public_key) == 0) {
            printf("  ✓ Signature verified successfully\n");
            printf("  ✓ File authenticity confirmed\n");
            printf("  ✓ Algorithm: Dilithium3\n");
        } else {
            fprintf(stderr, "  ✗ ERROR: Signature verification FAILED\n");
            fprintf(stderr, "  ✗ File has been tampered with or sent by wrong sender\n");
            fprintf(stderr, "  ✗ Aborting for security reasons\n");
            fprintf(stderr, "\nThis means:\n");
            fprintf(stderr, "  - File was tampered with after encryption, OR\n");
            fprintf(stderr, "  - Wrong sender (signature doesn't match claimed sender), OR\n");
            fprintf(stderr, "  - Signature was stripped/replaced\n");
            fprintf(stderr, "\nDecrypted data will NOT be saved (security violation)\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }
    } else {
        printf("\n[8/9] No signature present\n");
    }

    // ======================================================================
    // STEP 9: Write output file
    // ======================================================================

    printf("\n[9/9] Writing decrypted file...\n");

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fwrite(decrypted_data, 1, decrypted_size, out_fp) != decrypted_size) {
        fprintf(stderr, "Error: Failed to write decrypted data\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(out_fp);
    out_fp = NULL;

    printf("  ✓ Decrypted file written\n");

    printf("\n✓ File decrypted successfully!\n");
    printf("\nOutput file: %s\n", output_file);
    printf("  Decrypted size: %zu bytes\n", decrypted_size);
    if (recipient_count > 1) {
        printf("  You were recipient %d/%u\n", found_entry + 1, recipient_count);
    }

    ret = EXIT_SUCCESS;

cleanup:
    if (recipient_entries) free(recipient_entries);
    if (encrypted_data) free(encrypted_data);
    if (decrypted_data) {
        memset(decrypted_data, 0, decrypted_size);  // Wipe decrypted data
        free(decrypted_data);
    }
    if (dek) {
        memset(dek, 0, 32);  // Wipe DEK
        free(dek);
    }
    if (signature_data) free(signature_data);
    if (signature) qgp_signature_free(signature);
    if (out_fp) fclose(out_fp);
    if (enc_key) qgp_key_free(enc_key);

    return ret;
}
