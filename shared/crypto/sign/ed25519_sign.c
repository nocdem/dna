/**
 * @file ed25519_sign.c
 * @brief Ed25519 signing utility (OpenSSL EVP)
 *
 * Extracted from sol_wallet.c to be shared across all Ed25519 usage.
 */

#include "crypto/sign/ed25519_sign.h"
#include "crypto/utils/qgp_log.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#define LOG_TAG "ED25519_SIGN"

int ed25519_sign(
    const uint8_t private_key[32],
    const uint8_t *message,
    size_t message_len,
    uint8_t sig_out[64]
) {
    if (!private_key || !message || !sig_out) {
        return -1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, private_key, 32
    );
    if (!pkey) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create Ed25519 key: %s",
                     ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    size_t sig_len = 64;
    int ret = -1;

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(md_ctx, sig_out, &sig_len, message, message_len) == 1) {
        ret = 0;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Ed25519 signing failed: %s",
                     ERR_error_string(ERR_get_error(), NULL));
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

int ed25519_pubkey_from_private(
    const uint8_t private_key[32],
    uint8_t pubkey_out[32]
) {
    if (!private_key || !pubkey_out) {
        return -1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, private_key, 32
    );
    if (!pkey) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create Ed25519 key: %s",
                     ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    size_t pubkey_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey_out, &pubkey_len) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get Ed25519 public key");
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_free(pkey);
    return 0;
}
