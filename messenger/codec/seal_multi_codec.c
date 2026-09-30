/*
 * DNA Connect - Multi-recipient Seal encoder (codec unit)
 *
 * NC-1: moved verbatim from messenger/messages.c (only `static` dropped so
 * messages.c can keep calling it). No network I/O, no database.
 */

#include "seal_multi_codec.h"
#include <stdlib.h>
#include <string.h>

// Windows byte order conversion macros (be64toh, htobe64 not available)
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>

// 64-bit big-endian conversions for Windows
#define htobe64(x) ( \
    ((uint64_t)(htonl((uint32_t)((x) & 0xFFFFFFFF))) << 32) | \
    ((uint64_t)(htonl((uint32_t)((x) >> 32)))) \
)
#define be64toh(x) htobe64(x)  // Same operation for bidirectional conversion

#else
#include <endian.h>
#endif

#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/enc/qgp_aes.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/enc/aes_keywrap.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "MSG"

// Multi-recipient encryption header and entry structures
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x08 (Category 5 + encrypted timestamp)
    uint8_t enc_key_type;       // QGP_KEY_TYPE_KEM1024
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t message_type;       // MSG_TYPE_DIRECT_PQC or MSG_TYPE_GROUP_GEK
    uint32_t encrypted_size;    // Size of encrypted data
    uint32_t signature_size;    // Size of signature
} messenger_enc_header_t;

typedef struct {
    uint8_t kyber_ciphertext[1568];   // Kyber1024 ciphertext
    uint8_t wrapped_dek[40];          // AES-wrapped DEK (32-byte + 8-byte IV)
} messenger_recipient_entry_t;

/**
 * Multi-recipient encryption (adapted from encrypt.c)
 *
 * @param plaintext: Message to encrypt
 * @param plaintext_len: Message length
 * @param recipient_enc_pubkeys: Array of recipient public keys (1568 bytes
 *        each) OF THE GIVEN alg — round-3 Kyber1024 pubkeys for alg 2, or
 *        ML-KEM-1024 pubkeys for alg 3 (KEM Faz 1, R7)
 * @param recipient_count: Number of recipients (including sender)
 * @param sender_sign_key: Sender's Dilithium5 signing key (ML-DSA-87)
 * @param alg: QGP_KEY_TYPE_KEM1024 (2) or QGP_KEY_TYPE_MLKEM1024 (3) —
 *        written into the header's enc_key_type byte and selects the
 *        encapsulation primitive (KEM Faz 1, R7)
 * @param ciphertext_out: Output ciphertext (caller must free)
 * @param ciphertext_len_out: Output ciphertext length
 * @return: 0 on success, -1 on error
 */
int messenger_encrypt_multi_recipient(
    const char *plaintext,
    size_t plaintext_len,
    uint8_t **recipient_enc_pubkeys,
    size_t recipient_count,
    qgp_key_t *sender_sign_key,
    uint64_t timestamp,
    uint8_t alg,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out
) {
    uint8_t *dek = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *payload = NULL;
    messenger_recipient_entry_t *recipient_entries = NULL;
    uint8_t *signature_data = NULL;
    uint8_t *output_buffer = NULL;
    uint8_t nonce[12];
    uint8_t tag[16];
    size_t encrypted_size = 0;
    size_t signature_size = 0;
    int ret = -1;

    // Step 1: Generate random 32-byte DEK
    dek = malloc(32);
    if (!dek) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for DEK");
        goto cleanup;
    }

    if (qgp_randombytes(dek, 32) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate random DEK");
        goto cleanup;
    }

    // Step 2: Sign plaintext with Dilithium5 (ML-DSA-87)
    qgp_signature_t *signature = qgp_signature_new(QGP_SIG_TYPE_DILITHIUM,
                                                     QGP_DSA87_PUBLICKEYBYTES,
                                                     QGP_DSA87_SIGNATURE_BYTES);
    if (!signature) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for signature");
        goto cleanup;
    }

    memcpy(qgp_signature_get_pubkey(signature), sender_sign_key->public_key,
           QGP_DSA87_PUBLICKEYBYTES);

    size_t actual_sig_len = 0;
    if (qgp_dsa87_sign(qgp_signature_get_bytes(signature), &actual_sig_len,
                                  (const uint8_t*)plaintext, plaintext_len,
                                  sender_sign_key->private_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DSA-87 signature creation failed");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature->signature_size = actual_sig_len;

    // Round-trip verification
    if (qgp_dsa87_verify(qgp_signature_get_bytes(signature), actual_sig_len,
                               (const uint8_t*)plaintext, plaintext_len,
                               qgp_signature_get_pubkey(signature)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Round-trip verification FAILED");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature_size = qgp_signature_get_size(signature);
    signature_data = malloc(signature_size);
    if (!signature_data) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        qgp_signature_free(signature);
        goto cleanup;
    }

    if (qgp_signature_serialize(signature, signature_data) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signature serialization failed");
        qgp_signature_free(signature);
        goto cleanup;
    }
    qgp_signature_free(signature);

    // Step 3a: Compute sender fingerprint (SHA3-512 of Dilithium5 pubkey)
    uint8_t sender_fingerprint[64];
    if (qgp_sha3_512(sender_sign_key->public_key, QGP_DSA87_PUBLICKEYBYTES, sender_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute fingerprint");
        goto cleanup;
    }

    // Step 3b: Build v0.08 payload = fingerprint(64) || timestamp(8) || plaintext
    size_t payload_len = 64 + 8 + plaintext_len;
    payload = malloc(payload_len);
    if (!payload) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for payload");
        goto cleanup;
    }

    // Copy fingerprint
    memcpy(payload, sender_fingerprint, 64);

    // Copy timestamp (big-endian)
    uint64_t timestamp_be = htobe64(timestamp);
    memcpy(payload + 64, &timestamp_be, 8);

    // Copy plaintext
    memcpy(payload + 64 + 8, plaintext, plaintext_len);

    // Step 3c: Encrypt payload with AES-256-GCM using DEK
    messenger_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, "PQSIGENC", 8);
    header_for_aad.version = 0x08;  // v0.08: encrypted timestamp
    header_for_aad.enc_key_type = alg;
    header_for_aad.recipient_count = (uint8_t)recipient_count;
    header_for_aad.encrypted_size = (uint32_t)payload_len;  // fingerprint + timestamp + plaintext
    header_for_aad.signature_size = (uint32_t)signature_size;

    encrypted_data = malloc(payload_len);
    if (!encrypted_data) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for ciphertext");
        goto cleanup;
    }

    if (qgp_aes256_encrypt(dek, payload, payload_len,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           encrypted_data, &encrypted_size,
                           nonce, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM encryption failed");
        goto cleanup;
    }

    // Payload encrypted, can free now
    free(payload);
    payload = NULL;

    // Step 4: Create recipient entries (wrap DEK for each recipient)
    recipient_entries = calloc(recipient_count, sizeof(messenger_recipient_entry_t));
    if (!recipient_entries) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for recipient entries");
        goto cleanup;
    }

    for (size_t i = 0; i < recipient_count; i++) {
        uint8_t kyber_ciphertext[1568];  // ct size, identical for both algs
        uint8_t kek[32];  // KEK = shared secret from the KEM

        // KEM encapsulation — round-3 (alg 2) or ML-KEM-1024 (alg 3, KEM Faz 1)
        int encaps_rc = (alg == (uint8_t)QGP_KEY_TYPE_MLKEM1024)
            ? qgp_mlkem1024_encapsulate(kyber_ciphertext, kek, recipient_enc_pubkeys[i])
            : qgp_kem1024_encapsulate(kyber_ciphertext, kek, recipient_enc_pubkeys[i]);
        if (encaps_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "KEM encapsulation failed for recipient %zu (alg=%u)", i+1, (unsigned)alg);
            qgp_secure_memzero(kek, 32);
            goto cleanup;
        }

        // Wrap DEK with KEK
        uint8_t wrapped_dek[40];
        if (aes256_wrap_key(dek, 32, kek, wrapped_dek) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to wrap DEK for recipient %zu", i+1);
            qgp_secure_memzero(kek, 32);
            goto cleanup;
        }

        // Store recipient entry
        memcpy(recipient_entries[i].kyber_ciphertext, kyber_ciphertext, 1568);  // Kyber1024 ciphertext size
        memcpy(recipient_entries[i].wrapped_dek, wrapped_dek, 40);

        // Wipe KEK
        qgp_secure_memzero(kek, 32);
    }

    // Step 5: Build output buffer
    // Format: [header | recipient_entries | nonce | ciphertext | tag | signature]
    size_t total_size = sizeof(messenger_enc_header_t) +
                       (sizeof(messenger_recipient_entry_t) * recipient_count) +
                       12 + encrypted_size + 16 + signature_size;

    output_buffer = malloc(total_size);
    if (!output_buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for output");
        goto cleanup;
    }

    size_t offset = 0;

    // Header
    messenger_enc_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "PQSIGENC", 8);
    header.version = 0x08;  // v0.08: fingerprint + timestamp + plaintext
    header.enc_key_type = alg;
    header.recipient_count = (uint8_t)recipient_count;
    header.message_type = MSG_TYPE_DIRECT_PQC;  // Per-recipient KEM
    header.encrypted_size = (uint32_t)encrypted_size;
    header.signature_size = (uint32_t)signature_size;

    memcpy(output_buffer + offset, &header, sizeof(header));
    offset += sizeof(header);

    // Recipient entries
    memcpy(output_buffer + offset, recipient_entries,
           sizeof(messenger_recipient_entry_t) * recipient_count);
    offset += sizeof(messenger_recipient_entry_t) * recipient_count;

    // Nonce (12 bytes)
    memcpy(output_buffer + offset, nonce, 12);
    offset += 12;

    // Encrypted data
    memcpy(output_buffer + offset, encrypted_data, encrypted_size);
    offset += encrypted_size;

    // Tag (16 bytes)
    memcpy(output_buffer + offset, tag, 16);
    offset += 16;

    // Signature
    memcpy(output_buffer + offset, signature_data, signature_size);

    *ciphertext_out = output_buffer;
    *ciphertext_len_out = total_size;
    ret = 0;

cleanup:
    if (dek) {
        qgp_secure_memzero(dek, 32);
        free(dek);
    }
    if (payload) free(payload);
    if (encrypted_data) free(encrypted_data);
    if (recipient_entries) free(recipient_entries);
    if (signature_data) free(signature_data);
    if (ret != 0 && output_buffer) free(output_buffer);

    return ret;
}
