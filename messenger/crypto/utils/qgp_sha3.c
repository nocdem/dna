#include "crypto/utils/qgp_sha3.h"
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

/**
 * Compute SHA3-512 hash of data
 *
 * Uses OpenSSL EVP interface for SHA3-512.
 * Requires OpenSSL 1.1.1 or later (SHA3 support).
 *
 * @param data Input data to hash
 * @param len Length of input data in bytes
 * @param hash_out Output buffer for hash (must be at least 64 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out) {
    if (!data || !hash_out) {
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return -1;
    }

    // Initialize SHA3-512 digest
    if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Update with input data
    if (EVP_DigestUpdate(mdctx, data, len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Finalize and get digest
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash_out, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);

    // Verify we got the expected length
    if (hash_len != QGP_SHA3_512_DIGEST_LENGTH) {
        return -1;
    }

    return 0;
}

/**
 * Compute SHA3-512 hash and convert to hexadecimal string
 *
 * @param data Input data to hash
 * @param len Length of input data in bytes
 * @param hex_out Output buffer for hex string (must be at least 129 bytes: 128 hex + null)
 * @param hex_size Size of hex_out buffer (must be >= 129)
 * @return 0 on success, -1 on error
 */
int qgp_sha3_512_hex(const uint8_t *data, size_t len, char *hex_out, size_t hex_size) {
    if (!data || !hex_out || hex_size < QGP_SHA3_512_HEX_LENGTH) {
        return -1;
    }

    uint8_t hash[QGP_SHA3_512_DIGEST_LENGTH];
    if (qgp_sha3_512(data, len, hash) != 0) {
        return -1;
    }

    // Convert to hex string
    for (int i = 0; i < QGP_SHA3_512_DIGEST_LENGTH; i++) {
        snprintf(hex_out + (i * 2), 3, "%02x", hash[i]);
    }
    hex_out[128] = '\0';  // Null terminate

    return 0;
}

/**
 * Compute SHA3-512 fingerprint of public key
 * Convenience wrapper for qgp_sha3_512_hex with validation
 *
 * @param pubkey Public key bytes
 * @param pubkey_len Length of public key
 * @param fingerprint_out Output buffer for fingerprint (must be at least 129 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_sha3_512_fingerprint(const uint8_t *pubkey, size_t pubkey_len, char *fingerprint_out) {
    if (!pubkey || pubkey_len == 0 || !fingerprint_out) {
        return -1;
    }

    return qgp_sha3_512_hex(pubkey, pubkey_len, fingerprint_out, QGP_SHA3_512_HEX_LENGTH);
}
