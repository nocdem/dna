/**
 * Nodus — Channel Crypto Implementation
 *
 * AES-256-GCM with counter-based nonces for frame-level encryption.
 * Key derived from Kyber1024 shared secret via HKDF-SHA3-256.
 *
 * Uses EVP API directly (not qgp_aes wrapper) because:
 * - Counter-based nonce (wrapper generates random nonce)
 * - Empty payload support (wrapper rejects len=0)
 *
 * @file nodus_channel_crypto.c
 */

#include "crypto/nodus_channel_crypto.h"
#include "crypto/hash/hkdf_sha3.h"
#include "crypto/utils/qgp_log.h"
#include <openssl/evp.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "CH_CRYPTO"

extern void qgp_secure_memzero(void *ptr, size_t len);

static const char *CHANNEL_HKDF_INFO = "nodus-channel-v1";

int nodus_channel_crypto_init(nodus_channel_crypto_t *cc,
                               const uint8_t shared_secret[32],
                               const uint8_t nonce_c[32],
                               const uint8_t nonce_s[32])
{
    if (!cc || !shared_secret || !nonce_c || !nonce_s)
        return -1;

    memset(cc, 0, sizeof(*cc));

    /* salt = nonce_c || nonce_s (64 bytes) */
    uint8_t salt[64];
    memcpy(salt, nonce_c, 32);
    memcpy(salt + 32, nonce_s, 32);

    int rc = hkdf_sha3_256(salt, sizeof(salt),
                           shared_secret, 32,
                           (const uint8_t *)CHANNEL_HKDF_INFO,
                           strlen(CHANNEL_HKDF_INFO),
                           cc->key, NODUS_CHANNEL_KEY_LEN);

    qgp_secure_memzero(salt, sizeof(salt));

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "HKDF key derivation failed");
        return -1;
    }

    cc->tx_counter = 0;
    cc->rx_counter = 0;
    cc->established = true;

    QGP_LOG_INFO(LOG_TAG, "Channel crypto established");
    return 0;
}

/**
 * Build 12-byte AES-GCM nonce from 8-byte counter.
 * Format: [8 bytes counter LE][4 bytes zero]
 */
static void counter_to_nonce(uint64_t counter, uint8_t nonce[12])
{
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        nonce[i] = (uint8_t)(counter >> (i * 8));
}

int nodus_channel_encrypt(nodus_channel_crypto_t *cc,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *out, size_t out_cap,
                           size_t *out_len)
{
    if (!cc || !cc->established || !out || !out_len)
        return -1;
    if (!plaintext && plaintext_len > 0)
        return -1;

    size_t needed = plaintext_len + NODUS_CHANNEL_OVERHEAD;
    if (out_cap < needed)
        return -1;

    /* Build nonce from counter */
    uint8_t nonce[NODUS_CHANNEL_NONCE_LEN];
    counter_to_nonce(cc->tx_counter, nonce);

    /* Output layout: [nonce(12)][ciphertext][tag(16)] */
    memcpy(out, nonce, NODUS_CHANNEL_NONCE_LEN);

    uint8_t *ct_out = out + NODUS_CHANNEL_NONCE_LEN;
    uint8_t *tag_out = out + NODUS_CHANNEL_NONCE_LEN + plaintext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, cc->key, nonce) != 1)
        goto cleanup;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ct_out, &len, plaintext, (int)plaintext_len) != 1)
            goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, ct_out + len, &len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, NODUS_CHANNEL_TAG_LEN, tag_out) != 1)
        goto cleanup;

    cc->tx_counter++;
    *out_len = needed;
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (ret != 0)
        QGP_LOG_ERROR(LOG_TAG, "AES-GCM encrypt failed (counter=%llu)",
                      (unsigned long long)cc->tx_counter);
    return ret;
}

int nodus_channel_decrypt(nodus_channel_crypto_t *cc,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap,
                           size_t *out_len)
{
    if (!cc || !cc->established || !in || !out || !out_len)
        return -1;

    if (in_len < NODUS_CHANNEL_OVERHEAD)
        return -1;

    size_t ct_len = in_len - NODUS_CHANNEL_OVERHEAD;
    if (ct_len > 0 && out_cap < ct_len)
        return -1;

    /* Extract nonce, ciphertext, tag */
    const uint8_t *nonce = in;
    const uint8_t *ct = in + NODUS_CHANNEL_NONCE_LEN;
    const uint8_t *tag = in + NODUS_CHANNEL_NONCE_LEN + ct_len;

    /* Extract counter from nonce for replay check */
    uint64_t msg_counter = 0;
    for (int i = 7; i >= 0; i--)
        msg_counter = (msg_counter << 8) | nonce[i];

    if (msg_counter < cc->rx_counter) {
        QGP_LOG_ERROR(LOG_TAG,
                      "Replay detected: counter=%llu < expected=%llu cc=%p tx=%llu",
                      (unsigned long long)msg_counter,
                      (unsigned long long)cc->rx_counter,
                      (void *)cc,
                      (unsigned long long)cc->tx_counter);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, cc->key, nonce) != 1)
        goto cleanup;

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, out, &len, ct, (int)ct_len) != 1)
            goto cleanup;
    }

    /* Set expected tag (copy to mutable buffer — OpenSSL API requires non-const) */
    uint8_t tag_copy[NODUS_CHANNEL_TAG_LEN];
    memcpy(tag_copy, tag, NODUS_CHANNEL_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, NODUS_CHANNEL_TAG_LEN, tag_copy) != 1)
        goto cleanup;

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, out + len, &final_len) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "AES-GCM auth failed (tampered or wrong key)");
        goto cleanup;
    }

    cc->rx_counter = msg_counter + 1;
    *out_len = (size_t)(len + final_len);
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void nodus_channel_crypto_clear(nodus_channel_crypto_t *cc)
{
    if (!cc) return;
    qgp_secure_memzero(cc, sizeof(*cc));
}
