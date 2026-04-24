/*
 * DNA Engine - Signing Module
 *
 * Dilithium5 signing API for QR Auth and external authentication.
 *
 * Functions:
 *   - dna_engine_sign_data()             // Sign arbitrary data
 *   - dna_engine_get_signing_public_key() // Get signing public key
 */

#define DNA_ENGINE_SIGNING_IMPL
#include "engine_includes.h"

/* ============================================================================
 * SIGNING API (for QR Auth and external authentication)
 * ============================================================================ */

/**
 * Sign arbitrary data with the loaded identity's Dilithium5 key
 */
int dna_engine_sign_data(
    dna_engine_t *engine,
    const uint8_t *data,
    size_t data_len,
    uint8_t *signature_out,
    size_t *sig_len_out)
{
    if (!engine || !data || !signature_out || !sig_len_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    if (!engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "sign_data: no identity loaded");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Load the private signing key */
    qgp_key_t *sign_key = dna_load_private_key(engine);
    if (!sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "sign_data: failed to load private key");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Verify key has private key data */
    if (!sign_key->private_key || sign_key->private_key_size == 0) {
        QGP_LOG_ERROR(LOG_TAG, "sign_data: key has no private key data");
        qgp_key_free(sign_key);
        return DNA_ERROR_CRYPTO;
    }

    /* Sign with Dilithium5 */
    int ret = qgp_dsa87_sign(signature_out, sig_len_out,
                             data, data_len,
                             sign_key->private_key);

    qgp_key_free(sign_key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "sign_data: qgp_dsa87_sign failed");
        return DNA_ERROR_CRYPTO;
    }

    QGP_LOG_DEBUG(LOG_TAG, "sign_data: signed %zu bytes, signature length %zu",
                  data_len, *sig_len_out);
    return 0;
}

/**
 * Get the loaded identity's Dilithium5 signing public key
 */
int dna_engine_get_signing_public_key(
    dna_engine_t *engine,
    uint8_t *pubkey_out,
    size_t pubkey_out_len)
{
    if (!engine || !pubkey_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    if (!engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "get_signing_public_key: no identity loaded");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Load the signing key (contains public key) */
    qgp_key_t *sign_key = dna_load_private_key(engine);
    if (!sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "get_signing_public_key: failed to load key");
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Verify key has public key data */
    if (!sign_key->public_key || sign_key->public_key_size == 0) {
        QGP_LOG_ERROR(LOG_TAG, "get_signing_public_key: key has no public key data");
        qgp_key_free(sign_key);
        return DNA_ERROR_CRYPTO;
    }

    /* Check buffer size */
    if (pubkey_out_len < sign_key->public_key_size) {
        QGP_LOG_ERROR(LOG_TAG, "get_signing_public_key: buffer too small (%zu < %zu)",
                      pubkey_out_len, sign_key->public_key_size);
        qgp_key_free(sign_key);
        return DNA_ERROR_INVALID_ARG;
    }

    /* Copy public key to output buffer */
    memcpy(pubkey_out, sign_key->public_key, sign_key->public_key_size);
    size_t result = sign_key->public_key_size;

    qgp_key_free(sign_key);

    QGP_LOG_DEBUG(LOG_TAG, "get_signing_public_key: returned %zu bytes", result);
    return (int)result;
}

/**
 * Compute SHA3-512(pubkey) hex-encoded fingerprint (128 chars + NUL).
 *
 * Pure function — no engine state touched. Exposed so the Flutter FFI
 * layer can correlate fp-keyed records (delegations, history sender_fp)
 * with validator entries that only carry the raw pubkey. Avoids
 * shipping a pure-Dart SHA3-512 implementation.
 */
int dna_engine_pubkey_to_fingerprint(const uint8_t *pubkey,
                                       size_t pubkey_len,
                                       char *out_hex,
                                       size_t out_hex_size) {
    /* Hard-bound pubkey_len — Dilithium5 is the only identity key used
     * anywhere in the project, so accepting arbitrary lengths would
     * create a footgun for UI callers that accidentally pass a
     * truncated/padded buffer. */
    if (!pubkey || !out_hex) return DNA_ERROR_INVALID_ARG;
    if (pubkey_len != QGP_DSA87_PUBLICKEYBYTES) return DNA_ERROR_INVALID_ARG;
    if (out_hex_size < 129) return DNA_ERROR_INVALID_ARG;

    uint8_t raw[QGP_SHA3_512_DIGEST_LENGTH];
    if (qgp_sha3_512(pubkey, pubkey_len, raw) != 0) return DNA_ERROR_CRYPTO;

    static const char hex[16] = "0123456789abcdef";
    for (size_t i = 0; i < QGP_SHA3_512_DIGEST_LENGTH; i++) {
        out_hex[2 * i]     = hex[(raw[i] >> 4) & 0xF];
        out_hex[2 * i + 1] = hex[raw[i] & 0xF];
    }
    out_hex[128] = '\0';
    return 0;
}
