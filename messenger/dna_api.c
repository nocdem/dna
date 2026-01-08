/*
 * DNA Messenger - API Implementation
 *
 * Memory-based message encryption/decryption for messenger use
 * Phase 2: Library API (wraps QGP crypto operations)
 */

#include "dna_api.h"
#include "qgp.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DNA_API"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_aes.h"
#include "crypto/utils/qgp_kyber.h"
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/aes_keywrap.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Windows byte order conversion macros (be64toh, htobe64 not available)
#ifdef _WIN32
#include <winsock2.h>

// 64-bit big-endian conversions for Windows
#define htobe64(x) ( \
    ((uint64_t)(htonl((uint32_t)((x) & 0xFFFFFFFF))) << 32) | \
    ((uint64_t)(htonl((uint32_t)((x) >> 32)))) \
)
#define be64toh(x) htobe64(x)  // Same operation for bidirectional conversion

#else
#include <arpa/inet.h>  // For htonl, htons, ntohl, ntohs
#include <endian.h>      // For htobe64, be64toh
#endif

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
#define DNA_ENC_VERSION 0x08  // Version 8: Encrypted timestamp (fingerprint + timestamp + plaintext)

// Header structure (same as encrypt.c/decrypt.c)
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    char magic[8];
    uint8_t version;
    uint8_t enc_key_type;
    uint8_t recipient_count;
    uint8_t message_type;
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
    const char *home = qgp_platform_home_dir();
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
// NOTE: dna_load_key() and dna_load_pubkey() removed in v0.3.150
// These used the legacy keyring which is no longer supported.
// Use dna_engine API with fingerprint-based key storage instead.

// NOTE: dna_encrypt_message() removed in v0.3.150 - used legacy keyring
// Use dna_encrypt_message_raw() instead

/**
 * Encrypt message with raw keys (for offline delivery)
 * Single recipient version
 */
dna_error_t dna_encrypt_message_raw(
    dna_context_t *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *recipient_enc_pubkey,
    const uint8_t *sender_sign_pubkey,
    const uint8_t *sender_sign_privkey,
    uint64_t timestamp,
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

    // v0.07: Compute sender fingerprint (SHA3-512 of Dilithium5 pubkey)
    uint8_t sender_fingerprint[64];
    if (qgp_sha3_512(sender_sign_pubkey, QGP_DSA87_PUBLICKEYBYTES, sender_fingerprint) != 0) {
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // v0.08: Build payload = fingerprint(64) || timestamp(8) || plaintext
    size_t payload_len = 64 + 8 + plaintext_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    // Copy fingerprint
    memcpy(payload, sender_fingerprint, 64);

    // Copy timestamp (big-endian for network byte order)
    uint64_t timestamp_be = htobe64(timestamp);
    memcpy(payload + 64, &timestamp_be, 8);

    // Copy plaintext
    memcpy(payload + 64 + 8, plaintext, plaintext_len);

    // Generate random DEK (32 bytes)
    dek = malloc(32);
    if (!dek || qgp_randombytes(dek, 32) != 0) {
        qgp_secure_memzero(payload, payload_len);
        free(payload);
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // Encrypt payload with AES-256-GCM
    dna_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, DNA_ENC_MAGIC, 8);
    header_for_aad.version = DNA_ENC_VERSION;
    header_for_aad.enc_key_type = QGP_KEY_TYPE_KEM1024;
    header_for_aad.recipient_count = 1;
    header_for_aad.message_type = MSG_TYPE_DIRECT_PQC;
    header_for_aad.encrypted_size = (uint32_t)payload_len;  // v0.08: encrypt fingerprint + timestamp + plaintext
    header_for_aad.signature_size = (uint32_t)signature_size;

    encrypted_data = malloc(payload_len);
    if (!encrypted_data) {
        qgp_secure_memzero(payload, payload_len);
        free(payload);
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }

    if (qgp_aes256_encrypt(dek, payload, payload_len,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           encrypted_data, &encrypted_size,
                           nonce, tag) != 0) {
        qgp_secure_memzero(payload, payload_len);
        free(payload);
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    // Clean up payload (contains fingerprint)
    qgp_secure_memzero(payload, payload_len);
    free(payload);

    // Create recipient entry (wrap DEK for recipient)
    uint8_t kyber_ct[QGP_KEM1024_CIPHERTEXTBYTES];
    uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];

    if (qgp_kem1024_encapsulate(kyber_ct, kek, recipient_enc_pubkey) != 0) {
        qgp_secure_memzero(kek, QGP_KEM1024_SHAREDSECRET_BYTES);
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    if (aes256_wrap_key(dek, 32, kek, recipient_entry.wrapped_dek) != 0) {
        qgp_secure_memzero(kek, QGP_KEM1024_SHAREDSECRET_BYTES);
        result = DNA_ERROR_CRYPTO;
        goto cleanup;
    }

    memcpy(recipient_entry.kyber_ciphertext, kyber_ct, 1568);  // Kyber1024 ciphertext size
    qgp_secure_memzero(kek, QGP_KEM1024_SHAREDSECRET_BYTES);

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
        qgp_secure_memzero(dek, 32);
        free(dek);
    }
    if (encrypted_data) free(encrypted_data);
    if (result != DNA_OK && output_buffer) free(output_buffer);

    return result;
}

/**
 * Decrypt message with raw keys (for offline delivery)
 */
dna_error_t dna_decrypt_message_raw(
    dna_context_t *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *recipient_enc_privkey,
    uint8_t **plaintext_out,
    size_t *plaintext_len_out,
    uint8_t **sender_sign_pubkey_out,
    size_t *sender_sign_pubkey_len_out,
    uint8_t **signature_out,
    size_t *signature_len_out,
    uint64_t *timestamp_out)
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
        QGP_LOG_WARN(LOG_TAG, "Decrypt failed: invalid magic (expected PQSIGENC)");
        return DNA_ERROR_DECRYPT;
    }
    if (header.version != DNA_ENC_VERSION) {
        QGP_LOG_WARN(LOG_TAG, "Decrypt failed: version mismatch (got 0x%02x, expected 0x%02x)",
                     header.version, DNA_ENC_VERSION);
        return DNA_ERROR_DECRYPT;
    }
    if (header.message_type != MSG_TYPE_DIRECT_PQC) {
        QGP_LOG_WARN(LOG_TAG, "Decrypt failed: invalid message type (got %d)", header.message_type);
        return DNA_ERROR_DECRYPT;
    }

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
                qgp_secure_memzero(kek, QGP_KEM1024_SHAREDSECRET_BYTES);
                break;
            }
        }
        qgp_secure_memzero(kek, QGP_KEM1024_SHAREDSECRET_BYTES);
    }

    if (found_entry == -1) {
        QGP_LOG_WARN(LOG_TAG, "Decrypt failed: no matching recipient entry (tried %d entries)", recipient_count);
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }

    // Read nonce, encrypted data, tag
    if (offset + 12 + encrypted_size + 16 > ciphertext_len) {
        QGP_LOG_WARN(LOG_TAG, "Decrypt failed: truncated message (need %zu, have %zu)",
                     offset + 12 + encrypted_size + 16, ciphertext_len);
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

    // Parse signature (v0.07: type(1) + sig_size(2) + sig_bytes)
    if (signature_size > 0 && offset + signature_size <= ciphertext_len) {
        if (qgp_signature_deserialize(ciphertext + offset, signature_size,
                                       &signature) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Decrypt failed: signature deserialization failed (sig_size=%zu)", signature_size);
            result = DNA_ERROR_DECRYPT;
            goto cleanup;
        }
        offset += signature_size;
    } else {
        QGP_LOG_WARN(LOG_TAG, "Decrypt failed: no signature in message (sig_size=%zu, offset=%zu, len=%zu)",
                     signature_size, offset, ciphertext_len);
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }

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
        QGP_LOG_WARN(LOG_TAG, "Decrypt failed: AES-256-GCM decrypt failed (enc_size=%zu)", encrypted_size);
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }

    // v0.08: Extract fingerprint + timestamp from decrypted payload
    if (decrypted_size < 72) {  // 64 (fingerprint) + 8 (timestamp)
        QGP_LOG_WARN(LOG_TAG, "Decrypt failed: payload too small (got %zu, need >= 72)", decrypted_size);
        result = DNA_ERROR_DECRYPT;
        goto cleanup;
    }

    // Extract sender fingerprint (first 64 bytes)
    *sender_sign_pubkey_len_out = 64;
    *sender_sign_pubkey_out = malloc(64);
    if (!*sender_sign_pubkey_out) {
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }
    memcpy(*sender_sign_pubkey_out, decrypted, 64);

    // Extract timestamp (bytes 64-71, big-endian)
    if (timestamp_out) {
        uint64_t timestamp_be;
        memcpy(&timestamp_be, decrypted + 64, 8);
        *timestamp_out = be64toh(timestamp_be);
    }

    // Extract actual plaintext (everything after fingerprint + timestamp)
    size_t actual_plaintext_len = decrypted_size - 72;  // 64 + 8
    *plaintext_len_out = actual_plaintext_len;
    *plaintext_out = malloc(actual_plaintext_len);
    if (!*plaintext_out) {
        free(*sender_sign_pubkey_out);
        *sender_sign_pubkey_out = NULL;
        result = DNA_ERROR_MEMORY;
        goto cleanup;
    }
    memcpy(*plaintext_out, decrypted + 72, actual_plaintext_len);

    // v0.07: Return signature to caller for verification
    if (signature_out && signature_len_out && signature) {
        // Get signature bytes from parsed signature
        size_t sig_bytes_len = signature->signature_size;
        *signature_len_out = sig_bytes_len;
        *signature_out = malloc(sig_bytes_len);
        if (!*signature_out) {
            free(*plaintext_out);
            free(*sender_sign_pubkey_out);
            *plaintext_out = NULL;
            *sender_sign_pubkey_out = NULL;
            result = DNA_ERROR_MEMORY;
            goto cleanup;
        }
        memcpy(*signature_out, qgp_signature_get_bytes(signature), sig_bytes_len);
    }

    // v0.07: Signature verification must be done by caller
    // Caller must:
    // 1. Query keyserver for pubkey using returned fingerprint
    // 2. Verify signature against plaintext using qgp_dilithium5_verify()

    result = DNA_OK;

cleanup:
    if (recipient_entries) free(recipient_entries);
    if (signature) qgp_signature_free(signature);
    if (dek) {
        qgp_secure_memzero(dek, 32);
        free(dek);
    }
    if (decrypted) free(decrypted);

    return result;
}

// NOTE: dna_decrypt_message() removed in v0.3.150 - used legacy keyring
// Use dna_decrypt_message_raw() instead

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
    // Phase 6.3: Standalone message signing API
    if (!ctx || !message || !signer_key_name || !signature_out || !signature_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* v0.3.0: Flat structure - keys/identity.dsa */
    char key_path[512];
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        return DNA_ERROR_INTERNAL;
    }
    (void)signer_key_name;  /* Unused in v0.3.0 flat structure */
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    // Load signing key
    qgp_key_t *sign_key = NULL;
    if (qgp_key_load(key_path, &sign_key) != 0 || !sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load signing key from %s", key_path);
        return DNA_ERROR_KEY_LOAD;
    }

    // Verify key type
    if (sign_key->type != QGP_KEY_TYPE_DSA87 || sign_key->purpose != QGP_KEY_PURPOSE_SIGNING) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid key type (expected DSA87 signing key)");
        qgp_key_free(sign_key);
        return DNA_ERROR_INTERNAL;
    }

    // Allocate signature buffer
    uint8_t *sig = malloc(QGP_DSA87_SIGNATURE_BYTES);
    if (!sig) {
        qgp_key_free(sign_key);
        return DNA_ERROR_MEMORY;
    }

    // Sign message
    size_t siglen = 0;
    int result = qgp_dsa87_sign(sig, &siglen, message, message_len, sign_key->private_key);
    qgp_key_free(sign_key);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signature generation failed");
        free(sig);
        return DNA_ERROR_INTERNAL;
    }

    *signature_out = sig;
    *signature_len_out = siglen;
    return DNA_OK;
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
    // Phase 6.4: Standalone message verification API
    if (!ctx || !message || !signature || !signer_pubkey) {
        return DNA_ERROR_INVALID_ARG;
    }

    // Verify public key size (Dilithium5)
    if (signer_pubkey_len != QGP_DSA87_PUBLICKEYBYTES) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid public key size: %zu (expected %d)",
                signer_pubkey_len, QGP_DSA87_PUBLICKEYBYTES);
        return DNA_ERROR_INVALID_ARG;
    }

    // Verify signature
    int result = qgp_dsa87_verify(signature, signature_len, message, message_len, signer_pubkey);

    if (result == 0) {
        return DNA_OK;  // Signature is valid
    } else {
        return DNA_ERROR_VERIFY;  // Signature verification failed
    }
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

// ============================================================================
// GROUP MESSAGING WITH GSK (Phase 13 - v0.09)
// ============================================================================

/**
 * Encrypt message with Group Symmetric Key (GSK)
 */
dna_error_t dna_encrypt_message_gsk(
    dna_context_t *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const char *group_uuid,
    const uint8_t gsk[32],
    uint32_t gsk_version,
    const uint8_t sender_fingerprint[64],
    const uint8_t *sender_sign_privkey,
    uint64_t timestamp,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out
) {
    if (!ctx || !plaintext || !group_uuid || !gsk || !sender_fingerprint ||
        !sender_sign_privkey || !ciphertext_out || !ciphertext_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }


    // === PREPARE PAYLOAD ===
    // Payload: sender_fingerprint(64) || timestamp(8) || plaintext
    size_t payload_len = 64 + 8 + plaintext_len;
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) {
        return DNA_ERROR_MEMORY;
    }

    // Copy sender fingerprint
    memcpy(payload, sender_fingerprint, 64);

    // Copy timestamp (network byte order)
    uint64_t timestamp_net = htobe64(timestamp);
    memcpy(payload + 64, &timestamp_net, 8);

    // Copy plaintext
    memcpy(payload + 72, plaintext, plaintext_len);

    // === ENCRYPT WITH AES-256-GCM ===
    uint8_t *encrypted_payload = (uint8_t *)malloc(payload_len);
    if (!encrypted_payload) {
        free(payload);
        return DNA_ERROR_MEMORY;
    }

    uint8_t nonce[12];
    uint8_t tag[16];
    size_t encrypted_len = payload_len;

    int enc_ret = qgp_aes256_encrypt(
        gsk,                    // Key
        payload, payload_len,   // Plaintext
        NULL, 0,                // No AAD for GSK mode
        encrypted_payload, &encrypted_len,  // Ciphertext output
        nonce,                  // Nonce output (generated by function)
        tag                     // Tag output
    );

    free(payload);

    if (enc_ret != 0) {
        free(encrypted_payload);
        return DNA_ERROR_CRYPTO;
    }

    // === SIGN THE MESSAGE ===
    // Data to sign: group_uuid(37) || gsk_version(4) || nonce(12) || encrypted_payload || tag(16)
    size_t data_to_sign_len = 37 + 4 + 12 + payload_len + 16;
    uint8_t *data_to_sign = (uint8_t *)malloc(data_to_sign_len);
    if (!data_to_sign) {
        free(encrypted_payload);
        return DNA_ERROR_MEMORY;
    }

    size_t offset = 0;
    memcpy(data_to_sign + offset, group_uuid, 37);
    offset += 37;

    uint32_t gsk_version_net = htonl(gsk_version);
    memcpy(data_to_sign + offset, &gsk_version_net, 4);
    offset += 4;

    memcpy(data_to_sign + offset, nonce, 12);
    offset += 12;

    memcpy(data_to_sign + offset, encrypted_payload, payload_len);
    offset += payload_len;

    memcpy(data_to_sign + offset, tag, 16);
    offset += 16;

    uint8_t signature[QGP_DSA87_SIGNATURE_BYTES];
    size_t signature_len = 0;
    int sign_ret = qgp_dsa87_sign(signature, &signature_len, data_to_sign, data_to_sign_len, sender_sign_privkey);
    free(data_to_sign);

    if (sign_ret != 0) {
        free(encrypted_payload);
        return DNA_ERROR_CRYPTO;
    }

    // === BUILD FINAL CIPHERTEXT ===
    // Format:
    // [Header(12)] [Group UUID(37)] [GSK Version(4)] [Nonce(12)]
    // [Encrypted Payload] [Tag(16)] [Sig Type(1)] [Sig Size(2)] [Signature]

    dna_enc_header_t header;
    header.version = DNA_ENC_VERSION;
    header.enc_key_type = 0;  // Not used for GSK mode
    header.recipient_count = 0;  // Not used for GSK mode
    header.message_type = MSG_TYPE_GROUP_GSK;
    header.encrypted_size = (uint32_t)payload_len;
    header.signature_size = (uint32_t)signature_len;

    size_t total_len = 12 + 37 + 4 + 12 + payload_len + 16 + 1 + 2 + signature_len;
    uint8_t *final_ciphertext = (uint8_t *)malloc(total_len);
    if (!final_ciphertext) {
        free(encrypted_payload);
        return DNA_ERROR_MEMORY;
    }

    offset = 0;

    // Header
    final_ciphertext[offset++] = header.version;
    final_ciphertext[offset++] = header.enc_key_type;
    final_ciphertext[offset++] = header.recipient_count;
    final_ciphertext[offset++] = header.message_type;
    uint32_t enc_size_net = htonl(header.encrypted_size);
    memcpy(final_ciphertext + offset, &enc_size_net, 4);
    offset += 4;
    uint32_t sig_size_net = htonl(header.signature_size);
    memcpy(final_ciphertext + offset, &sig_size_net, 4);
    offset += 4;

    // Group UUID
    memcpy(final_ciphertext + offset, group_uuid, 37);
    offset += 37;

    // GSK Version
    memcpy(final_ciphertext + offset, &gsk_version_net, 4);
    offset += 4;

    // Nonce
    memcpy(final_ciphertext + offset, nonce, 12);
    offset += 12;

    // Encrypted payload
    memcpy(final_ciphertext + offset, encrypted_payload, payload_len);
    offset += payload_len;

    // Tag
    memcpy(final_ciphertext + offset, tag, 16);
    offset += 16;

    // Signature type
    final_ciphertext[offset++] = 23;  // Dilithium5

    // Signature size (network byte order)
    uint16_t sig_size_16_net = htons((uint16_t)signature_len);
    memcpy(final_ciphertext + offset, &sig_size_16_net, 2);
    offset += 2;

    // Signature
    memcpy(final_ciphertext + offset, signature, signature_len);
    offset += signature_len;

    free(encrypted_payload);


    *ciphertext_out = final_ciphertext;
    *ciphertext_len_out = total_len;
    return DNA_OK;
}

/**
 * Decrypt message with Group Symmetric Key (GSK)
 */
dna_error_t dna_decrypt_message_gsk(
    dna_context_t *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t gsk[32],
    const uint8_t *sender_dilithium_pubkey,
    uint8_t **plaintext_out,
    size_t *plaintext_len_out,
    uint8_t sender_fingerprint_out[64],
    uint64_t *timestamp_out,
    char group_uuid_out[37],
    uint32_t *gsk_version_out
) {
    if (!ctx || !ciphertext || !gsk || !sender_dilithium_pubkey ||
        !plaintext_out || !plaintext_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    if (ciphertext_len < 12 + 37 + 4 + 12 + 16 + 1 + 2) {
        return DNA_ERROR_DECRYPT;
    }


    size_t offset = 0;

    // === PARSE HEADER ===
    dna_enc_header_t header;
    header.version = ciphertext[offset++];
    header.enc_key_type = ciphertext[offset++];
    header.recipient_count = ciphertext[offset++];
    header.message_type = ciphertext[offset++];
    memcpy(&header.encrypted_size, ciphertext + offset, 4);
    header.encrypted_size = ntohl(header.encrypted_size);
    offset += 4;
    memcpy(&header.signature_size, ciphertext + offset, 4);
    header.signature_size = ntohl(header.signature_size);
    offset += 4;

    if (header.version != DNA_ENC_VERSION) {
        return DNA_ERROR_DECRYPT;
    }
    if (header.message_type != MSG_TYPE_GROUP_GSK) {
        return DNA_ERROR_DECRYPT;
    }

    // === PARSE GROUP UUID ===
    char group_uuid[37];
    memcpy(group_uuid, ciphertext + offset, 37);
    offset += 37;

    if (group_uuid_out) {
        memcpy(group_uuid_out, group_uuid, 37);
    }

    // === PARSE GSK VERSION ===
    uint32_t gsk_version;
    memcpy(&gsk_version, ciphertext + offset, 4);
    gsk_version = ntohl(gsk_version);
    offset += 4;

    if (gsk_version_out) {
        *gsk_version_out = gsk_version;
    }

    // === PARSE NONCE ===
    uint8_t nonce[12];
    memcpy(nonce, ciphertext + offset, 12);
    offset += 12;

    // === PARSE ENCRYPTED PAYLOAD + TAG ===
    size_t encrypted_payload_len = header.encrypted_size;
    if (offset + encrypted_payload_len + 16 > ciphertext_len) {
        return DNA_ERROR_DECRYPT;
    }

    const uint8_t *encrypted_payload = ciphertext + offset;
    offset += encrypted_payload_len;

    const uint8_t *tag = ciphertext + offset;
    offset += 16;

    // === PARSE SIGNATURE ===
    if (offset + 3 > ciphertext_len) {
        return DNA_ERROR_DECRYPT;
    }

    uint8_t sig_type = ciphertext[offset++];
    if (sig_type != 23) {
        return DNA_ERROR_DECRYPT;
    }

    uint16_t sig_size_16;
    memcpy(&sig_size_16, ciphertext + offset, 2);
    size_t sig_size = ntohs(sig_size_16);
    offset += 2;

    if (offset + sig_size > ciphertext_len) {
        return DNA_ERROR_DECRYPT;
    }

    const uint8_t *signature = ciphertext + offset;

    // === VERIFY SIGNATURE ===
    // Data signed: group_uuid(37) || gsk_version(4) || nonce(12) || encrypted_payload || tag(16)
    size_t data_to_verify_len = 37 + 4 + 12 + encrypted_payload_len + 16;
    uint8_t *data_to_verify = (uint8_t *)malloc(data_to_verify_len);
    if (!data_to_verify) {
        return DNA_ERROR_MEMORY;
    }

    offset = 0;
    memcpy(data_to_verify + offset, group_uuid, 37);
    offset += 37;
    uint32_t gsk_version_net = htonl(gsk_version);
    memcpy(data_to_verify + offset, &gsk_version_net, 4);
    offset += 4;
    memcpy(data_to_verify + offset, nonce, 12);
    offset += 12;
    memcpy(data_to_verify + offset, encrypted_payload, encrypted_payload_len);
    offset += encrypted_payload_len;
    memcpy(data_to_verify + offset, tag, 16);

    int verify_ret = qgp_dsa87_verify(signature, sig_size, data_to_verify, data_to_verify_len, sender_dilithium_pubkey);
    free(data_to_verify);

    if (verify_ret != 0) {
        return DNA_ERROR_VERIFY;
    }

    // === DECRYPT PAYLOAD ===
    uint8_t *decrypted_payload = (uint8_t *)malloc(encrypted_payload_len);
    if (!decrypted_payload) {
        return DNA_ERROR_MEMORY;
    }

    size_t decrypted_len = encrypted_payload_len;
    int dec_ret = qgp_aes256_decrypt(
        gsk,                              // Key
        encrypted_payload, encrypted_payload_len,  // Ciphertext
        NULL, 0,                          // No AAD
        nonce,                            // Nonce (12 bytes)
        tag,                              // Tag (16 bytes)
        decrypted_payload, &decrypted_len // Plaintext output
    );

    if (dec_ret != 0) {
        free(decrypted_payload);
        return DNA_ERROR_DECRYPT;
    }

    // === EXTRACT PAYLOAD FIELDS ===
    if (encrypted_payload_len < 72) {
        free(decrypted_payload);
        return DNA_ERROR_DECRYPT;
    }

    // Sender fingerprint (64 bytes)
    if (sender_fingerprint_out) {
        memcpy(sender_fingerprint_out, decrypted_payload, 64);
    }

    // Timestamp (8 bytes)
    uint64_t timestamp_net;
    memcpy(&timestamp_net, decrypted_payload + 64, 8);
    uint64_t timestamp = be64toh(timestamp_net);
    if (timestamp_out) {
        *timestamp_out = timestamp;
    }

    // Plaintext (remaining bytes)
    size_t plaintext_len = encrypted_payload_len - 72;
    uint8_t *plaintext = (uint8_t *)malloc(plaintext_len);
    if (!plaintext) {
        free(decrypted_payload);
        return DNA_ERROR_MEMORY;
    }

    memcpy(plaintext, decrypted_payload + 72, plaintext_len);
    free(decrypted_payload);


    *plaintext_out = plaintext;
    *plaintext_len_out = plaintext_len;
    return DNA_OK;
}

// NOTE: Legacy keyring stubs removed in v0.3.150 - keyring not used in DNA Messenger
