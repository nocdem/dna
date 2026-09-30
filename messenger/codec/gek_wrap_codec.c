/**
 * @file gek_wrap_codec.c
 * @brief KEM-wrap of a 32-byte secret (GEK / per-contact salt) — codec unit
 *
 * NC-1 (Web Connect design rev 5 §1.3, operator decision 2026-09-30 Q2 = a):
 * gek_encrypt_alg / gek_encrypt / gek_decrypt_alg / gek_decrypt moved
 * verbatim out of messenger/gek.c (which also holds the group database and
 * DHT sync) so the native library and the web thin core compile the same
 * code. Declarations stay in messenger/gek.h. No network I/O, no database.
 *
 * Blob = KEM ct(1568) || nonce(12) || tag(16) || enc(32) = 1628 bytes.
 */

#include "messenger/gek.h"
#include <string.h>
#include "crypto/utils/qgp_platform.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/enc/qgp_aes.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "MSG_GEK"

/* ============================================================================
 * ENCRYPTION / DECRYPTION
 * ============================================================================ */

int gek_encrypt_alg(
    uint8_t alg,
    const uint8_t gek[32],
    const uint8_t pubkey[1568],
    uint8_t encrypted_out[GEK_ENC_TOTAL_SIZE]
) {
    if (!gek || !pubkey || !encrypted_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_encrypt_alg: NULL parameter");
        return -1;
    }
    if (alg != IKP_ALG_KYBER_R3 && alg != IKP_ALG_MLKEM1024) {
        QGP_LOG_ERROR(LOG_TAG, "gek_encrypt_alg: unknown alg %u", (unsigned)alg);
        return -1;
    }

    /* Buffers for KEM and AES */
    uint8_t kem_ciphertext[GEK_ENC_KEM_CT_SIZE];
    uint8_t shared_secret[32];  /* Kyber1024 / ML-KEM-1024 shared secret is 32 bytes */
    uint8_t nonce[GEK_ENC_NONCE_SIZE];
    uint8_t tag[GEK_ENC_TAG_SIZE];
    uint8_t encrypted_gek[GEK_ENC_KEY_SIZE];
    size_t encrypted_len = 0;

    /* Step 1: KEM encapsulation (round-3 or ML-KEM-1024, same ct/ss sizes) */
    QGP_LOG_DEBUG(LOG_TAG, "Performing KEM encapsulation for GEK (alg=%u)...", (unsigned)alg);
    int encaps_rc = (alg == IKP_ALG_MLKEM1024)
        ? qgp_mlkem1024_encapsulate(kem_ciphertext, shared_secret, pubkey)
        : qgp_kem1024_encapsulate(kem_ciphertext, shared_secret, pubkey);
    if (encaps_rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM encapsulation failed");
        return -1;
    }

    /* Step 2: AES-256-GCM encryption of GEK */
    QGP_LOG_DEBUG(LOG_TAG, "Encrypting GEK with AES-256-GCM...");
    if (qgp_aes256_encrypt(
            shared_secret,              /* 32-byte key from KEM */
            gek, GEK_ENC_KEY_SIZE,      /* plaintext: GEK */
            NULL, 0,                    /* no AAD */
            encrypted_gek, &encrypted_len,
            nonce, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM encryption failed");
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    if (encrypted_len != GEK_ENC_KEY_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected encrypted length: %zu (expected %d)",
                      encrypted_len, GEK_ENC_KEY_SIZE);
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    /* Step 3: Pack into output buffer */
    /* Format: kem_ciphertext (1568) || nonce (12) || tag (16) || encrypted_gek (32) */
    size_t offset = 0;
    memcpy(encrypted_out + offset, kem_ciphertext, GEK_ENC_KEM_CT_SIZE);
    offset += GEK_ENC_KEM_CT_SIZE;
    memcpy(encrypted_out + offset, nonce, GEK_ENC_NONCE_SIZE);
    offset += GEK_ENC_NONCE_SIZE;
    memcpy(encrypted_out + offset, tag, GEK_ENC_TAG_SIZE);
    offset += GEK_ENC_TAG_SIZE;
    memcpy(encrypted_out + offset, encrypted_gek, GEK_ENC_KEY_SIZE);

    /* Securely wipe sensitive data */
    qgp_secure_memzero(shared_secret, sizeof(shared_secret));
    qgp_secure_memzero(encrypted_gek, sizeof(encrypted_gek));

    QGP_LOG_DEBUG(LOG_TAG, "GEK encrypted successfully (%d bytes)", GEK_ENC_TOTAL_SIZE);
    return 0;
}

int gek_encrypt(
    const uint8_t gek[32],
    const uint8_t kem_pubkey[1568],
    uint8_t encrypted_out[GEK_ENC_TOTAL_SIZE]
) {
    return gek_encrypt_alg(IKP_ALG_KYBER_R3, gek, kem_pubkey, encrypted_out);
}

int gek_decrypt_alg(
    uint8_t alg,
    const uint8_t *encrypted,
    size_t encrypted_len,
    const uint8_t privkey[3168],
    uint8_t gek_out[32]
) {
    if (!encrypted || !privkey || !gek_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_decrypt_alg: NULL parameter");
        return -1;
    }
    if (alg != IKP_ALG_KYBER_R3 && alg != IKP_ALG_MLKEM1024) {
        QGP_LOG_ERROR(LOG_TAG, "gek_decrypt_alg: unknown alg %u", (unsigned)alg);
        return -1;
    }

    if (encrypted_len != GEK_ENC_TOTAL_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid encrypted GEK size: %zu (expected %d)",
                      encrypted_len, GEK_ENC_TOTAL_SIZE);
        return -1;
    }

    /* Buffers for KEM and AES */
    uint8_t shared_secret[32];
    size_t decrypted_len = 0;

    /* Parse encrypted buffer */
    size_t offset = 0;
    const uint8_t *kem_ciphertext = encrypted + offset;
    offset += GEK_ENC_KEM_CT_SIZE;
    const uint8_t *nonce = encrypted + offset;
    offset += GEK_ENC_NONCE_SIZE;
    const uint8_t *tag = encrypted + offset;
    offset += GEK_ENC_TAG_SIZE;
    const uint8_t *encrypted_gek = encrypted + offset;

    /* Step 1: KEM decapsulation (round-3 or ML-KEM-1024) */
    QGP_LOG_DEBUG(LOG_TAG, "Performing KEM decapsulation for GEK (alg=%u)...", (unsigned)alg);
    int decaps_rc = (alg == IKP_ALG_MLKEM1024)
        ? qgp_mlkem1024_decapsulate(shared_secret, kem_ciphertext, privkey)
        : qgp_kem1024_decapsulate(shared_secret, kem_ciphertext, privkey);
    if (decaps_rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM decapsulation failed");
        return -1;
    }

    /* Step 2: AES-256-GCM decryption */
    QGP_LOG_DEBUG(LOG_TAG, "Decrypting GEK with AES-256-GCM...");
    if (qgp_aes256_decrypt(
            shared_secret,
            encrypted_gek, GEK_ENC_KEY_SIZE,
            NULL, 0,  /* no AAD */
            nonce, tag,
            gek_out, &decrypted_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM decryption failed (auth tag mismatch?)");
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        qgp_secure_memzero(gek_out, 32);
        return -1;
    }

    if (decrypted_len != GEK_ENC_KEY_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected decrypted length: %zu (expected %d)",
                      decrypted_len, GEK_ENC_KEY_SIZE);
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        qgp_secure_memzero(gek_out, 32);
        return -1;
    }

    /* Securely wipe sensitive data */
    qgp_secure_memzero(shared_secret, sizeof(shared_secret));

    QGP_LOG_DEBUG(LOG_TAG, "GEK decrypted successfully");
    return 0;
}

int gek_decrypt(
    const uint8_t *encrypted,
    size_t encrypted_len,
    const uint8_t kem_privkey[3168],
    uint8_t gek_out[32]
) {
    return gek_decrypt_alg(IKP_ALG_KYBER_R3, encrypted, encrypted_len, kem_privkey, gek_out);
}
