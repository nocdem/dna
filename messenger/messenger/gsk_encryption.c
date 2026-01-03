/**
 * @file gsk_encryption.c
 * @brief GSK Encryption Implementation using Kyber1024 KEM + AES-256-GCM
 *
 * @author DNA Messenger Team
 * @date 2026-01-03
 */

#include "gsk_encryption.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../crypto/utils/qgp_aes.h"
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_log.h"

#include <string.h>

#define LOG_TAG "GSK_ENC"

/* ============================================================================
 * PUBLIC FUNCTIONS
 * ============================================================================ */

int gsk_encrypt(
    const uint8_t gsk[32],
    const uint8_t kem_pubkey[1568],
    uint8_t encrypted_out[GSK_ENC_TOTAL_SIZE]
) {
    if (!gsk || !kem_pubkey || !encrypted_out) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_encrypt: NULL parameter");
        return -1;
    }

    /* Buffers for KEM and AES */
    uint8_t kem_ciphertext[GSK_ENC_KEM_CT_SIZE];
    uint8_t shared_secret[32];  /* Kyber1024 shared secret is 32 bytes */
    uint8_t nonce[GSK_ENC_NONCE_SIZE];
    uint8_t tag[GSK_ENC_TAG_SIZE];
    uint8_t encrypted_gsk[GSK_ENC_KEY_SIZE];
    size_t encrypted_len = 0;

    /* Step 1: Kyber1024 encapsulation */
    QGP_LOG_DEBUG(LOG_TAG, "Performing KEM encapsulation for GSK...");
    if (qgp_kem1024_encapsulate(kem_ciphertext, shared_secret, kem_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM encapsulation failed");
        return -1;
    }

    /* Step 2: AES-256-GCM encryption of GSK */
    QGP_LOG_DEBUG(LOG_TAG, "Encrypting GSK with AES-256-GCM...");
    if (qgp_aes256_encrypt(
            shared_secret,              /* 32-byte key from KEM */
            gsk, GSK_ENC_KEY_SIZE,      /* plaintext: GSK */
            NULL, 0,                    /* no AAD */
            encrypted_gsk, &encrypted_len,
            nonce, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM encryption failed");
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    if (encrypted_len != GSK_ENC_KEY_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected encrypted length: %zu (expected %d)",
                      encrypted_len, GSK_ENC_KEY_SIZE);
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    /* Step 3: Pack into output buffer */
    /* Format: kem_ciphertext (1568) || nonce (12) || tag (16) || encrypted_gsk (32) */
    size_t offset = 0;
    memcpy(encrypted_out + offset, kem_ciphertext, GSK_ENC_KEM_CT_SIZE);
    offset += GSK_ENC_KEM_CT_SIZE;
    memcpy(encrypted_out + offset, nonce, GSK_ENC_NONCE_SIZE);
    offset += GSK_ENC_NONCE_SIZE;
    memcpy(encrypted_out + offset, tag, GSK_ENC_TAG_SIZE);
    offset += GSK_ENC_TAG_SIZE;
    memcpy(encrypted_out + offset, encrypted_gsk, GSK_ENC_KEY_SIZE);

    /* Securely wipe sensitive data */
    qgp_secure_memzero(shared_secret, sizeof(shared_secret));
    qgp_secure_memzero(encrypted_gsk, sizeof(encrypted_gsk));

    QGP_LOG_DEBUG(LOG_TAG, "GSK encrypted successfully (%d bytes)", GSK_ENC_TOTAL_SIZE);
    return 0;
}

int gsk_decrypt(
    const uint8_t *encrypted,
    size_t encrypted_len,
    const uint8_t kem_privkey[3168],
    uint8_t gsk_out[32]
) {
    if (!encrypted || !kem_privkey || !gsk_out) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_decrypt: NULL parameter");
        return -1;
    }

    if (encrypted_len != GSK_ENC_TOTAL_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid encrypted GSK size: %zu (expected %d)",
                      encrypted_len, GSK_ENC_TOTAL_SIZE);
        return -1;
    }

    /* Buffers for KEM and AES */
    uint8_t shared_secret[32];
    size_t decrypted_len = 0;

    /* Parse encrypted buffer */
    size_t offset = 0;
    const uint8_t *kem_ciphertext = encrypted + offset;
    offset += GSK_ENC_KEM_CT_SIZE;
    const uint8_t *nonce = encrypted + offset;
    offset += GSK_ENC_NONCE_SIZE;
    const uint8_t *tag = encrypted + offset;
    offset += GSK_ENC_TAG_SIZE;
    const uint8_t *encrypted_gsk = encrypted + offset;

    /* Step 1: Kyber1024 decapsulation */
    QGP_LOG_DEBUG(LOG_TAG, "Performing KEM decapsulation for GSK...");
    if (qgp_kem1024_decapsulate(shared_secret, kem_ciphertext, kem_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM decapsulation failed");
        return -1;
    }

    /* Step 2: AES-256-GCM decryption */
    QGP_LOG_DEBUG(LOG_TAG, "Decrypting GSK with AES-256-GCM...");
    if (qgp_aes256_decrypt(
            shared_secret,
            encrypted_gsk, GSK_ENC_KEY_SIZE,
            NULL, 0,  /* no AAD */
            nonce, tag,
            gsk_out, &decrypted_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM decryption failed (auth tag mismatch?)");
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        qgp_secure_memzero(gsk_out, 32);
        return -1;
    }

    if (decrypted_len != GSK_ENC_KEY_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected decrypted length: %zu (expected %d)",
                      decrypted_len, GSK_ENC_KEY_SIZE);
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        qgp_secure_memzero(gsk_out, 32);
        return -1;
    }

    /* Securely wipe sensitive data */
    qgp_secure_memzero(shared_secret, sizeof(shared_secret));

    QGP_LOG_DEBUG(LOG_TAG, "GSK decrypted successfully");
    return 0;
}
