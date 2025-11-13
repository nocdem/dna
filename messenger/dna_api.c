/*
 * DNA Messenger - API Implementation
 *
 * Memory-based message encryption/decryption for messenger use
 * Phase 2: Library API (wraps QGP crypto operations)
 */

#include "dna_api.h"
#include "qgp.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_aes.h"
#include "crypto/utils/qgp_kyber.h"
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/aes_keywrap.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * DNA Context (opaque to user)
 */
struct dna_context {
    char keyring_path[512];  // Path to keyring directory
    int last_error;          // Last error code
};

// File format constants (same as QGP)
#define DNA_ENC_MAGIC "PQSIGENC"
#define DNA_ENC_VERSION 0x06  // Version 6: Category 5 (Kyber1024 + Dilithium5 + SHA3-512)
#define DAP_ENC_KEY_TYPE_KEM_KYBER512 23

// Header structure (same as encrypt.c/decrypt.c)
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    char magic[8];
    uint8_t version;
    uint8_t enc_key_type;
    uint8_t recipient_count;
    uint8_t reserved;
    uint32_t encrypted_size;
    uint32_t signature_size;
}
#ifndef _MSC_VER
__attribute__((packed))
#endif
dna_enc_header_t;

// Recipient entry
typedef struct {
    uint8_t kyber_ciphertext[1568];  // Kyber1024 ciphertext size
    uint8_t wrapped_dek[40];
}
#ifndef _MSC_VER
__attribute__((packed))
#endif
dna_recipient_entry_t;

// Public key bundle header (for parsing .pub files)
typedef struct {
    char magic[8];
    uint8_t version;
    uint8_t sign_key_type;
    uint8_t enc_key_type;
    uint8_t reserved;
    uint32_t sign_pubkey_size;
    uint32_t enc_pubkey_size;
}
#ifndef _MSC_VER
__attribute__((packed))
#endif
pubkey_bundle_header_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

// ============================================================================
// VERSION AND ERROR HANDLING
// ============================================================================

const char* dna_version(void) {
    return DNA_VERSION_STRING;
}

const char* dna_error_string(dna_error_t error) {
    switch (error) {
        case DNA_OK: return "Success";
        case DNA_ERROR_MEMORY: return "Memory allocation failed";
        case DNA_ERROR_INVALID_ARG: return "Invalid argument";
        case DNA_ERROR_KEY_LOAD: return "Failed to load key";
        case DNA_ERROR_KEY_INVALID: return "Invalid key type or format";
        case DNA_ERROR_CRYPTO: return "Cryptographic operation failed";
        case DNA_ERROR_VERIFY: return "Signature verification failed";
        case DNA_ERROR_DECRYPT: return "Decryption failed";
        case DNA_ERROR_NOT_FOUND: return "Resource not found";
        case DNA_ERROR_INTERNAL: return "Internal error";
        default: return "Unknown error";
    }
}

// ============================================================================
// CONTEXT MANAGEMENT
// ============================================================================

dna_context_t* dna_context_new(void) {
    dna_context_t *ctx = calloc(1, sizeof(dna_context_t));
    if (!ctx) {
        return NULL;
    }

    // Use QGP keyring for Phase 2
    const char *home = get_home_dir();
    if (!home) {
        free(ctx);
        return NULL;
    }

    snprintf(ctx->keyring_path, sizeof(ctx->keyring_path),
             "%s/.qgp", home);
    ctx->last_error = DNA_OK;

    return ctx;
}

void dna_context_free(dna_context_t *ctx) {
    if (ctx) {
        memset(ctx, 0, sizeof(dna_context_t));
        free(ctx);
    }
}

// ============================================================================
// BUFFER MANAGEMENT
// ============================================================================

dna_buffer_t dna_buffer_new(size_t size) {
    dna_buffer_t buf;
    buf.data = calloc(1, size);
    buf.size = buf.data ? size : 0;
    return buf;
}

void dna_buffer_free(dna_buffer_t *buffer) {
    if (buffer && buffer->data) {
        memset(buffer->data, 0, buffer->size);  // Secure wipe
        free(buffer->data);
        buffer->data = NULL;
        buffer->size = 0;
    }
}

// ============================================================================
// KEY MANAGEMENT
// ============================================================================

dna_error_t dna_load_key(
    dna_context_t *ctx,
    const char *key_name,
    const char *key_type,
    uint8_t **key_out,
    size_t *key_len_out)
{
    if (!ctx || !key_name || !key_type || !key_out || !key_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    // Use QGP's keyring_find_private_key
    char *key_path = keyring_find_private_key(key_name, key_type);
    if (!key_path) {
        return DNA_ERROR_NOT_FOUND;
    }

    // Load key using QGP's key loader
    qgp_key_t *qgp_key = NULL;
    if (qgp_key_load(key_path, &qgp_key) != 0) {
        free(key_path);
        return DNA_ERROR_KEY_LOAD;
    }
    free(key_path);

    // Extract private key bytes
    *key_len_out = qgp_key->private_key_size;
    *key_out = malloc(*key_len_out);
    if (!*key_out) {
        qgp_key_free(qgp_key);
        return DNA_ERROR_MEMORY;
    }

    memcpy(*key_out, qgp_key->private_key, *key_len_out);
    qgp_key_free(qgp_key);

    return DNA_OK;
}

dna_error_t dna_load_pubkey(
    dna_context_t *ctx,
    const char *contact_name,
    uint8_t **pubkey_out,
    size_t *pubkey_len_out)
{
    if (!ctx || !contact_name || !pubkey_out || !pubkey_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    // Use QGP's keyring_find_key
    char *pubkey_path = keyring_find_key(contact_name);
    if (!pubkey_path) {
        return DNA_ERROR_NOT_FOUND;
    }

    // Load public key using QGP's key loader
    qgp_key_t *qgp_key = NULL;
    if (qgp_pubkey_load(pubkey_path, &qgp_key) != 0) {
        free(pubkey_path);
        return DNA_ERROR_KEY_LOAD;
    }
    free(pubkey_path);

    // Extract public key bytes
    *pubkey_len_out = qgp_key->public_key_size;
    *pubkey_out = malloc(*pubkey_len_out);
    if (!*pubkey_out) {
        qgp_key_free(qgp_key);
        return DNA_ERROR_MEMORY;
    }

    memcpy(*pubkey_out, qgp_key->public_key, *pubkey_len_out);
    qgp_key_free(qgp_key);

    return DNA_OK;
}

// ============================================================================
// MESSAGE ENCRYPTION (Memory-based)
// ============================================================================

dna_error_t dna_encrypt_message(
    dna_context_t *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const char **recipient_names,
    size_t recipient_count,
    const char *sender_key_name,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out)
{
    if (!ctx || !plaintext || !recipient_names || !sender_key_name ||
        !ciphertext_out || !ciphertext_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    if (recipient_count == 0 || recipient_count > 255) {
        return DNA_ERROR_INVALID_ARG;
    }

    dna_error_t result = DNA_ERROR_INTERNAL;
    qgp_key_t *sign_key = NULL;
    qgp_signature_t *signature = NULL;
    uint8_t **recipient_pubkeys = NULL;
    uint8_t *dek = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *output_buffer = NULL;
    dna_recipient_entry_t *recipient_entries = NULL;
    uint8_t nonce[12];
    uint8_t tag[16];
    size_t encrypted_size = 0;
    size_t signature_size = 0;

    // Allocate arrays for recipients
    recipient_pubkeys = calloc(recipient_count, sizeof(uint8_t*));
    recipient_entries = calloc(recipient_count, sizeof(dna_recipient_entry_t));

    if (!recipient_pubkeys || !recipient_entries) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    // Load all recipient public keys (using keyring lookup + bundle parsing)
    for (size_t i = 0; i < recipient_count; i++) {
        char *pubkey_path = keyring_find_key(recipient_names[i]);
        if (!pubkey_path) {
            result = DNA_ERROR_NOT_FOUND;
            goto cleanup;
        }

        // Load encryption public key from bundle (handles ASCII armor)
        // This uses the same logic as encrypt.c: load_recipient_pubkey()
        // The .pub files are bundles containing both signing + encryption keys

        // Read armored file
        uint8_t *bundle_data = NULL;
        size_t bundle_size = 0;
        char *type = NULL;
        char **headers = NULL;
        size_t header_count = 0;

        if (is_armored_file(pubkey_path)) {
            if (read_armored_file(pubkey_path, &type, &bundle_data, &bundle_size,
                                 &headers, &header_count) != 0) {
                free(pubkey_path);
                result = DNA_ERROR_KEY_LOAD;
                goto cleanup;
            }

            // Cleanup armor metadata
            if (type) free(type);
            if (headers) {
                for (size_t j = 0; j < header_count; j++) free(headers[j]);
                free(headers);
            }
        } else {
            // Binary format - read entire file
            if (read_file_data(pubkey_path, &bundle_data, &bundle_size) != 0) {
                free(pubkey_path);
                result = DNA_ERROR_KEY_LOAD;
                goto cleanup;
            }
        }

        free(pubkey_path);

        // Parse bundle header
        if (bundle_size < sizeof(pubkey_bundle_header_t)) {
            free(bundle_data);
            result = DNA_ERROR_KEY_INVALID;
            goto cleanup;
        }

        pubkey_bundle_header_t header;
        memcpy(&header, bundle_data, sizeof(header));

        // Validate and extract encryption key
        if (memcmp(header.magic, "PQPUBKEY", 8) != 0 ||
            header.enc_key_type != QGP_KEY_TYPE_KEM1024 ||
            header.enc_pubkey_size != 1568) {  // Kyber1024 public key size
            free(bundle_data);
            result = DNA_ERROR_KEY_INVALID;
            goto cleanup;
        }

        // Extract encryption public key from bundle
        size_t enc_offset = sizeof(header) + header.sign_pubkey_size;
        if (enc_offset + 1568 > bundle_size) {  // Kyber1024 public key size
            free(bundle_data);
            result = DNA_ERROR_KEY_INVALID;
            goto cleanup;
        }

        recipient_pubkeys[i] = malloc(1568);  // Kyber1024 public key size
        if (!recipient_pubkeys[i]) {
            free(bundle_data);
            result = DNA_ERROR_MEMORY;
            goto cleanup;
        }

        memcpy(recipient_pubkeys[i], bundle_data + enc_offset, 1568);  // Kyber1024 public key size
        free(bundle_data);
    }

    // Load sender's signing key
    char *sign_key_path = keyring_find_private_key(sender_key_name, "signing");
    if (!sign_key_path) {
        result = DNA_ERROR_NOT_FOUND;
        goto cleanup;
    }

    if (qgp_key_load(sign_key_path, &sign_key) != 0) {
        free(sign_key_path);
        result = DNA_ERROR_KEY_LOAD;
        goto cleanup;
    }
    free(sign_key_path);

    // Verify it's Dilithium3
    if (sign_key->type != QGP_KEY_TYPE_DSA87) {
        result = DNA_ERROR_KEY_INVALID;
        goto cleanup;
    }

    // Create signature
    signature = qgp_signature_new(QGP_SIG_TYPE_DILITHIUM,
                                   QGP_DSA87_PUBLICKEYBYTES,
                                   QGP_DSA87_SIGNATURE_BYTES);
    if (!signature) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    memcpy(qgp_signature_get_pubkey(signature), sign_key->public_key,
           QGP_DSA87_PUBLICKEYBYTES);

    size_t actual_sig_len = 0;
    if (qgp_dsa87_sign(qgp_signature_get_bytes(signature),
                                  &actual_sig_len, plaintext, plaintext_len,
                                  sign_key->private_key) != 0) {
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    signature->signature_size = actual_sig_len;
    signature_size = qgp_signature_get_size(signature);

    // Generate random DEK (32 bytes)
    dek = malloc(32);
    if (!dek || qgp_randombytes(dek, 32) != 0) {
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // Encrypt with AES-256-GCM
    dna_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, DNA_ENC_MAGIC, 8);
    header_for_aad.version = DNA_ENC_VERSION;
    header_for_aad.enc_key_type = DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header_for_aad.recipient_count = (uint8_t)recipient_count;
    header_for_aad.encrypted_size = (uint32_t)plaintext_len;
    header_for_aad.signature_size = (uint32_t)signature_size;

    encrypted_data = malloc(plaintext_len);
    if (!encrypted_data) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    if (qgp_aes256_encrypt(dek, plaintext, plaintext_len,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           encrypted_data, &encrypted_size,
                           nonce, tag) != 0) {
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // Create recipient entries (wrap DEK for each recipient)
    for (size_t i = 0; i < recipient_count; i++) {
        uint8_t kyber_ct[QGP_KEM1024_CIPHERTEXTBYTES];
        uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];

        if (qgp_kem1024_encapsulate(kyber_ct, kek, recipient_pubkeys[i]) != 0) {
            memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
            result = DNA_ERROR_CRYPTO;
            goto cleanup;
        }

        if (aes256_wrap_key(dek, 32, kek, recipient_entries[i].wrapped_dek) != 0) {
            memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
            result = DNA_ERROR_CRYPTO;
            goto cleanup;
        }

        memcpy(recipient_entries[i].kyber_ciphertext, kyber_ct, 1568);  // Kyber1024 ciphertext size
        memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
    }

    // Serialize signature
    uint8_t *sig_bytes = malloc(signature_size);
    if (!sig_bytes || qgp_signature_serialize(signature, sig_bytes) == 0) {
        free(sig_bytes);
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // Calculate total output size
    size_t total_size = sizeof(dna_enc_header_t) +
                       (sizeof(dna_recipient_entry_t) * recipient_count) +
                       12 + encrypted_size + 16 + signature_size;

    output_buffer = malloc(total_size);
    if (!output_buffer) {
        free(sig_bytes);
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    // Assemble output buffer
    size_t offset = 0;

    // Header
    dna_enc_header_t header;
    memcpy(&header, &header_for_aad, sizeof(header));
    memcpy(output_buffer + offset, &header, sizeof(header));
    offset += sizeof(header);

    // Recipient entries
    memcpy(output_buffer + offset, recipient_entries,
           sizeof(dna_recipient_entry_t) * recipient_count);
    offset += sizeof(dna_recipient_entry_t) * recipient_count;

    // Nonce
    memcpy(output_buffer + offset, nonce, 12);
    offset += 12;

    // Encrypted data
    memcpy(output_buffer + offset, encrypted_data, encrypted_size);
    offset += encrypted_size;

    // Tag
    memcpy(output_buffer + offset, tag, 16);
    offset += 16;

    // Signature
    memcpy(output_buffer + offset, sig_bytes, signature_size);
    offset += signature_size;

    free(sig_bytes);

    *ciphertext_out = output_buffer;
    *ciphertext_len_out = total_size;
    result = DNA_OK;

cleanup:
    if (recipient_pubkeys) {
        for (size_t i = 0; i < recipient_count; i++) {
            if (recipient_pubkeys[i]) free(recipient_pubkeys[i]);
        }
        free(recipient_pubkeys);
    }
    if (recipient_entries) free(recipient_entries);
    if (sign_key) qgp_key_free(sign_key);
    if (signature) qgp_signature_free(signature);
    if (dek) {
        memset(dek, 0, 32);
        free(dek);
    }
    if (encrypted_data) free(encrypted_data);
    if (result != DNA_OK && output_buffer) free(output_buffer);

    return result;
}

/**
 * Encrypt message with raw keys (for PostgreSQL integration)
 * Single recipient version
 */
dna_error_t dna_encrypt_message_raw(
    dna_context_t *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *recipient_enc_pubkey,
    const uint8_t *sender_sign_pubkey,
    const uint8_t *sender_sign_privkey,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out)
{
    if (!ctx || !plaintext || !recipient_enc_pubkey || !sender_sign_pubkey ||
        !sender_sign_privkey || !ciphertext_out || !ciphertext_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    dna_error_t result = DNA_ERROR_INTERNAL;
    qgp_signature_t *signature = NULL;
    uint8_t *dek = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *output_buffer = NULL;
    dna_recipient_entry_t recipient_entry;
    uint8_t nonce[12];
    uint8_t tag[16];
    size_t encrypted_size = 0;
    size_t signature_size = 0;

    // Create signature
    signature = qgp_signature_new(QGP_SIG_TYPE_DILITHIUM,
                                   QGP_DSA87_PUBLICKEYBYTES,
                                   QGP_DSA87_SIGNATURE_BYTES);
    if (!signature) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    memcpy(qgp_signature_get_pubkey(signature), sender_sign_pubkey,
           QGP_DSA87_PUBLICKEYBYTES);

    size_t actual_sig_len = 0;
    if (qgp_dsa87_sign(qgp_signature_get_bytes(signature),
                                  &actual_sig_len, plaintext, plaintext_len,
                                  sender_sign_privkey) != 0) {
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    signature->signature_size = actual_sig_len;
    signature_size = qgp_signature_get_size(signature);

    // Generate random DEK (32 bytes)
    dek = malloc(32);
    if (!dek || qgp_randombytes(dek, 32) != 0) {
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // Encrypt with AES-256-GCM
    dna_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, DNA_ENC_MAGIC, 8);
    header_for_aad.version = DNA_ENC_VERSION;
    header_for_aad.enc_key_type = DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header_for_aad.recipient_count = 1;
    header_for_aad.encrypted_size = (uint32_t)plaintext_len;
    header_for_aad.signature_size = (uint32_t)signature_size;

    encrypted_data = malloc(plaintext_len);
    if (!encrypted_data) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    if (qgp_aes256_encrypt(dek, plaintext, plaintext_len,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           encrypted_data, &encrypted_size,
                           nonce, tag) != 0) {
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // Create recipient entry (wrap DEK for recipient)
    uint8_t kyber_ct[QGP_KEM1024_CIPHERTEXTBYTES];
    uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];

    if (qgp_kem1024_encapsulate(kyber_ct, kek, recipient_enc_pubkey) != 0) {
        memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    if (aes256_wrap_key(dek, 32, kek, recipient_entry.wrapped_dek) != 0) {
        memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    memcpy(recipient_entry.kyber_ciphertext, kyber_ct, 1568);  // Kyber1024 ciphertext size
    memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);

    // Serialize signature
    uint8_t *sig_bytes = malloc(signature_size);
    if (!sig_bytes || qgp_signature_serialize(signature, sig_bytes) == 0) {
        free(sig_bytes);
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // Calculate total output size
    size_t total_size = sizeof(dna_enc_header_t) +
                       sizeof(dna_recipient_entry_t) +
                       12 + encrypted_size + 16 + signature_size;

    output_buffer = malloc(total_size);
    if (!output_buffer) {
        free(sig_bytes);
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    // Assemble output buffer
    size_t offset = 0;

    // Header
    dna_enc_header_t header;
    memcpy(&header, &header_for_aad, sizeof(header));
    memcpy(output_buffer + offset, &header, sizeof(header));
    offset += sizeof(header);

    // Recipient entry (single)
    memcpy(output_buffer + offset, &recipient_entry, sizeof(dna_recipient_entry_t));
    offset += sizeof(dna_recipient_entry_t);

    // Nonce
    memcpy(output_buffer + offset, nonce, 12);
    offset += 12;

    // Encrypted data
    memcpy(output_buffer + offset, encrypted_data, encrypted_size);
    offset += encrypted_size;

    // Tag
    memcpy(output_buffer + offset, tag, 16);
    offset += 16;

    // Signature
    memcpy(output_buffer + offset, sig_bytes, signature_size);
    offset += signature_size;

    free(sig_bytes);

    *ciphertext_out = output_buffer;
    *ciphertext_len_out = total_size;
    result = DNA_OK;

cleanup:
    if (signature) qgp_signature_free(signature);
    if (dek) {
        memset(dek, 0, 32);
        free(dek);
    }
    if (encrypted_data) free(encrypted_data);
    if (result != DNA_OK && output_buffer) free(output_buffer);

    return result;
}

/**
 * Decrypt message with raw keys (for PostgreSQL integration)
 */
dna_error_t dna_decrypt_message_raw(
    dna_context_t *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *recipient_enc_privkey,
    uint8_t **plaintext_out,
    size_t *plaintext_len_out,
    uint8_t **sender_sign_pubkey_out,
    size_t *sender_sign_pubkey_len_out)
{
    if (!ctx || !ciphertext || !recipient_enc_privkey ||
        !plaintext_out || !plaintext_len_out ||
        !sender_sign_pubkey_out || !sender_sign_pubkey_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    dna_error_t result = DNA_ERROR_INTERNAL;
    qgp_signature_t *signature = NULL;
    uint8_t *dek = NULL;
    uint8_t *decrypted = NULL;
    dna_recipient_entry_t *recipient_entries = NULL;
    size_t offset = 0;

    // Parse header
    if (ciphertext_len < sizeof(dna_enc_header_t)) {
        return DNA_ERROR_INVALID_ARG;
    }

    dna_enc_header_t header;
    memcpy(&header, ciphertext + offset, sizeof(header));
    offset += sizeof(header);

    // Validate header
    if (memcmp(header.magic, DNA_ENC_MAGIC, 8) != 0) {
        fprintf(stderr, "[DEBUG] Invalid magic bytes in header\n");
        return DNA_ERROR_DECRYPT;
    }
    if (header.version != DNA_ENC_VERSION) {
        fprintf(stderr, "[DEBUG] Version mismatch: got 0x%02x, expected 0x%02x\n", header.version, DNA_ENC_VERSION);
        return DNA_ERROR_DECRYPT;
    }
    fprintf(stderr, "[DEBUG] Header validated: version 0x%02x, %u recipients\n", header.version, header.recipient_count);

    uint8_t recipient_count = header.recipient_count;
    size_t encrypted_size = header.encrypted_size;
    size_t signature_size = header.signature_size;

    // Read recipient entries
    size_t entries_size = sizeof(dna_recipient_entry_t) * recipient_count;
    if (offset + entries_size > ciphertext_len) {
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }

    recipient_entries = malloc(entries_size);
    if (!recipient_entries) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    memcpy(recipient_entries, ciphertext + offset, entries_size);
    offset += entries_size;

    // Try each recipient entry with provided private key
    dek = malloc(32);
    if (!dek) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    int found_entry = -1;
    for (int i = 0; i < recipient_count; i++) {
        uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];

        if (qgp_kem1024_decapsulate(kek, recipient_entries[i].kyber_ciphertext,
                            recipient_enc_privkey) == 0) {
            if (aes256_unwrap_key(recipient_entries[i].wrapped_dek, 40, kek, dek) == 0) {
                found_entry = i;
                memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
                break;
            }
        }
        memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
    }

    if (found_entry == -1) {
        fprintf(stderr, "[DEBUG] Kyber decapsulation failed for all %d recipients - wrong key or corrupted ciphertext\n", recipient_count);
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }
    fprintf(stderr, "[DEBUG] Kyber decapsulation succeeded for recipient %d\n", found_entry);

    // Read nonce, encrypted data, tag
    if (offset + 12 + encrypted_size + 16 > ciphertext_len) {
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }

    uint8_t nonce[12];
    uint8_t tag[16];
    memcpy(nonce, ciphertext + offset, 12);
    offset += 12;

    const uint8_t *encrypted_data = ciphertext + offset;
    offset += encrypted_size;

    memcpy(tag, ciphertext + offset, 16);
    offset += 16;

    // Decrypt with AES-256-GCM
    dna_enc_header_t header_for_aad;
    memcpy(&header_for_aad, &header, sizeof(header));

    decrypted = malloc(encrypted_size);
    if (!decrypted) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    size_t decrypted_size = 0;
    if (qgp_aes256_decrypt(dek, encrypted_data, encrypted_size,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           nonce, tag, decrypted, &decrypted_size) != 0) {
        fprintf(stderr, "[DEBUG] AES-256-GCM decryption failed - wrong DEK or corrupted ciphertext\n");
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }
    fprintf(stderr, "[DEBUG] AES-256-GCM decryption succeeded (%zu bytes)\n", decrypted_size);

    // Parse and verify signature
    if (signature_size > 0 && offset + signature_size <= ciphertext_len) {
        const uint8_t *sig_data = ciphertext + offset;

        if (qgp_signature_deserialize(sig_data, signature_size, &signature) == 0 &&
            signature != NULL) {

            uint8_t *sig_pubkey = qgp_signature_get_pubkey(signature);
            uint8_t *sig_bytes = qgp_signature_get_bytes(signature);

            fprintf(stderr, "[DEBUG] Verifying Dilithium signature (%zu bytes)...\n", signature->signature_size);
            if (qgp_dsa87_verify(sig_bytes, signature->signature_size,
                                     decrypted, decrypted_size, sig_pubkey) != 0) {
                fprintf(stderr, "[DEBUG] Dilithium signature verification FAILED\n");
                result = DNA_ERROR_VERIFY;
                goto cleanup;
            }

            // Return sender's public key
            *sender_sign_pubkey_len_out = signature->public_key_size;
            *sender_sign_pubkey_out = malloc(*sender_sign_pubkey_len_out);
            if (*sender_sign_pubkey_out) {
                memcpy(*sender_sign_pubkey_out, sig_pubkey, *sender_sign_pubkey_len_out);
            }
        }
    }

    *plaintext_out = decrypted;
    *plaintext_len_out = decrypted_size;
    result = DNA_OK;
    decrypted = NULL;  // Don't free on cleanup

cleanup:
    if (recipient_entries) free(recipient_entries);
    if (signature) qgp_signature_free(signature);
    if (dek) {
        memset(dek, 0, 32);
        free(dek);
    }
    if (decrypted) free(decrypted);

    return result;
}

// ============================================================================
// MESSAGE DECRYPTION (Memory-based)
// ============================================================================

dna_error_t dna_decrypt_message(
    dna_context_t *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const char *recipient_key_name,
    uint8_t **plaintext_out,
    size_t *plaintext_len_out,
    uint8_t **sender_pubkey_out,
    size_t *sender_pubkey_len_out)
{
    if (!ctx || !ciphertext || !recipient_key_name ||
        !plaintext_out || !plaintext_len_out ||
        !sender_pubkey_out || !sender_pubkey_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    dna_error_t result = DNA_ERROR_INTERNAL;
    qgp_key_t *enc_key = NULL;
    qgp_signature_t *signature = NULL;
    uint8_t *dek = NULL;
    uint8_t *decrypted = NULL;
    dna_recipient_entry_t *recipient_entries = NULL;
    size_t offset = 0;

    // Parse header
    if (ciphertext_len < sizeof(dna_enc_header_t)) {
        return DNA_ERROR_INVALID_ARG;
    }

    dna_enc_header_t header;
    memcpy(&header, ciphertext + offset, sizeof(header));
    offset += sizeof(header);

    // Validate header
    if (memcmp(header.magic, DNA_ENC_MAGIC, 8) != 0) {
        fprintf(stderr, "[DEBUG] Invalid magic bytes in header\n");
        return DNA_ERROR_DECRYPT;
    }
    if (header.version != DNA_ENC_VERSION) {
        fprintf(stderr, "[DEBUG] Version mismatch: got 0x%02x, expected 0x%02x\n", header.version, DNA_ENC_VERSION);
        return DNA_ERROR_DECRYPT;
    }
    fprintf(stderr, "[DEBUG] Header validated: version 0x%02x, %u recipients\n", header.version, header.recipient_count);

    uint8_t recipient_count = header.recipient_count;
    size_t encrypted_size = header.encrypted_size;
    size_t signature_size = header.signature_size;

    // Load recipient's encryption key
    char *enc_key_path = keyring_find_private_key(recipient_key_name, "encryption");
    if (!enc_key_path) {
        return DNA_ERROR_NOT_FOUND;
    }

    if (qgp_key_load(enc_key_path, &enc_key) != 0) {
        free(enc_key_path);
        return DNA_ERROR_KEY_LOAD;
    }
    free(enc_key_path);

    if (enc_key->type != QGP_KEY_TYPE_KEM1024) {
        result = DNA_ERROR_KEY_INVALID;
        goto cleanup;
    }

    // Read recipient entries
    size_t entries_size = sizeof(dna_recipient_entry_t) * recipient_count;
    if (offset + entries_size > ciphertext_len) {
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }

    recipient_entries = malloc(entries_size);
    if (!recipient_entries) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    memcpy(recipient_entries, ciphertext + offset, entries_size);
    offset += entries_size;

    // Try each recipient entry
    dek = malloc(32);
    if (!dek) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    int found_entry = -1;
    for (int i = 0; i < recipient_count; i++) {
        uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];

        if (qgp_kem1024_decapsulate(kek, recipient_entries[i].kyber_ciphertext,
                            enc_key->private_key) == 0) {
            if (aes256_unwrap_key(recipient_entries[i].wrapped_dek, 40, kek, dek) == 0) {
                found_entry = i;
                memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
                break;
            }
        }
        memset(kek, 0, QGP_KEM1024_SHAREDSECRET_BYTES);
    }

    if (found_entry == -1) {
        fprintf(stderr, "[DEBUG] Kyber decapsulation failed for all %d recipients - wrong key or corrupted ciphertext\n", recipient_count);
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }
    fprintf(stderr, "[DEBUG] Kyber decapsulation succeeded for recipient %d\n", found_entry);

    // Read nonce, encrypted data, tag
    if (offset + 12 + encrypted_size + 16 > ciphertext_len) {
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }

    uint8_t nonce[12];
    uint8_t tag[16];
    memcpy(nonce, ciphertext + offset, 12);
    offset += 12;

    const uint8_t *encrypted_data = ciphertext + offset;
    offset += encrypted_size;

    memcpy(tag, ciphertext + offset, 16);
    offset += 16;

    // Decrypt with AES-256-GCM
    dna_enc_header_t header_for_aad;
    memcpy(&header_for_aad, &header, sizeof(header));

    decrypted = malloc(encrypted_size);
    if (!decrypted) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    size_t decrypted_size = 0;
    if (qgp_aes256_decrypt(dek, encrypted_data, encrypted_size,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           nonce, tag, decrypted, &decrypted_size) != 0) {
        fprintf(stderr, "[DEBUG] AES-256-GCM decryption failed - wrong DEK or corrupted ciphertext\n");
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }
    fprintf(stderr, "[DEBUG] AES-256-GCM decryption succeeded (%zu bytes)\n", decrypted_size);

    // Parse and verify signature
    if (signature_size > 0 && offset + signature_size <= ciphertext_len) {
        const uint8_t *sig_data = ciphertext + offset;

        if (qgp_signature_deserialize(sig_data, signature_size, &signature) == 0 &&
            signature != NULL) {

            uint8_t *sig_pubkey = qgp_signature_get_pubkey(signature);
            uint8_t *sig_bytes = qgp_signature_get_bytes(signature);

            fprintf(stderr, "[DEBUG] Verifying Dilithium signature (%zu bytes)...\n", signature->signature_size);
            if (qgp_dsa87_verify(sig_bytes, signature->signature_size,
                                     decrypted, decrypted_size, sig_pubkey) != 0) {
                fprintf(stderr, "[DEBUG] Dilithium signature verification FAILED\n");
                result = DNA_ERROR_VERIFY;
                goto cleanup;
            }

            // Return sender's public key
            *sender_pubkey_len_out = signature->public_key_size;
            *sender_pubkey_out = malloc(*sender_pubkey_len_out);
            if (*sender_pubkey_out) {
                memcpy(*sender_pubkey_out, sig_pubkey, *sender_pubkey_len_out);
            }
        }
    }

    *plaintext_out = decrypted;
    *plaintext_len_out = decrypted_size;
    result = DNA_OK;
    decrypted = NULL;  // Don't free on cleanup

cleanup:
    if (recipient_entries) free(recipient_entries);
    if (enc_key) qgp_key_free(enc_key);
    if (signature) qgp_signature_free(signature);
    if (dek) {
        memset(dek, 0, 32);
        free(dek);
    }
    if (decrypted) free(decrypted);

    return result;
}

// ============================================================================
// SIGNATURE OPERATIONS
// ============================================================================

dna_error_t dna_sign_message(
    dna_context_t *ctx,
    const uint8_t *message,
    size_t message_len,
    const char *signer_key_name,
    uint8_t **signature_out,
    size_t *signature_len_out)
{
    // TODO: Implement standalone signing
    return DNA_ERROR_INTERNAL;
}

dna_error_t dna_verify_message(
    dna_context_t *ctx,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *signer_pubkey,
    size_t signer_pubkey_len)
{
    // TODO: Implement standalone verification
    return DNA_ERROR_INTERNAL;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

dna_error_t dna_key_fingerprint(
    const uint8_t *key_data,
    size_t key_len,
    uint8_t fingerprint_out[32])
{
    if (!key_data || !fingerprint_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    qgp_hash_t hash;
    qgp_hash_from_bytes(&hash, key_data, key_len);
    memcpy(fingerprint_out, hash.hash, 32);

    return DNA_OK;
}

dna_error_t dna_fingerprint_to_hex(
    const uint8_t fingerprint[32],
    char hex_out[65])
{
    if (!fingerprint || !hex_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    qgp_hash_t hash;
    memcpy(hash.hash, fingerprint, 32);
    qgp_hash_to_hex(&hash, hex_out, 65);

    return DNA_OK;
}
