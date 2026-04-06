/**
 * HKDF-SHA3-256 Key Derivation Function
 *
 * Implementation using OpenSSL 3.x EVP_MAC API for HMAC-SHA3-256.
 *
 * @file hkdf_sha3.c
 */

#include "crypto/hash/hkdf_sha3.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

#define LOG_TAG "HKDF"

/* Forward declaration for secure zeroing */
extern void qgp_secure_memzero(void *ptr, size_t len);

int hmac_sha3_256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t *mac_out, size_t *mac_len)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch HMAC implementation");
        return -1;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create HMAC context");
        EVP_MAC_free(mac);
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA3-256", 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(ctx, key, key_len, params) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "HMAC-SHA3-256 init failed");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    if (EVP_MAC_update(ctx, data, data_len) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "HMAC-SHA3-256 update failed");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    if (EVP_MAC_final(ctx, mac_out, mac_len, QGP_SHA3_256_DIGEST_LENGTH) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "HMAC-SHA3-256 final failed");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return 0;
}

int hkdf_sha3_256(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len)
{
    if (!salt || !ikm || !info || !okm) {
        QGP_LOG_ERROR(LOG_TAG, "hkdf_sha3_256: NULL parameter");
        return -1;
    }

    if (okm_len > QGP_SHA3_256_DIGEST_LENGTH) {
        QGP_LOG_ERROR(LOG_TAG, "hkdf_sha3_256: okm_len %zu exceeds SHA3-256 output (32)",
                      okm_len);
        return -1;
    }

    /* HKDF-Extract: PRK = HMAC-SHA3-256(salt, IKM) */
    uint8_t prk[QGP_SHA3_256_DIGEST_LENGTH];
    size_t prk_len = 0;

    if (hmac_sha3_256(salt, salt_len, ikm, ikm_len, prk, &prk_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "HKDF-Extract failed");
        return -1;
    }

    /* HKDF-Expand: OKM = HMAC-SHA3-256(PRK, info || 0x01)
     * Since we only need <= 32 bytes (= hash output), one iteration suffices */
    uint8_t expand_input[256];
    if (info_len + 1 > sizeof(expand_input)) {
        QGP_LOG_ERROR(LOG_TAG, "HKDF info too long");
        qgp_secure_memzero(prk, sizeof(prk));
        return -1;
    }

    memcpy(expand_input, info, info_len);
    expand_input[info_len] = 0x01;

    uint8_t okm_full[QGP_SHA3_256_DIGEST_LENGTH];
    size_t okm_full_len = 0;

    if (hmac_sha3_256(prk, prk_len, expand_input, info_len + 1,
                      okm_full, &okm_full_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "HKDF-Expand failed");
        qgp_secure_memzero(prk, sizeof(prk));
        return -1;
    }

    memcpy(okm, okm_full, okm_len);

    qgp_secure_memzero(prk, sizeof(prk));
    qgp_secure_memzero(okm_full, sizeof(okm_full));
    qgp_secure_memzero(expand_input, sizeof(expand_input));

    return 0;
}
