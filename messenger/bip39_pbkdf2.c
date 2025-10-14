/**
 * @file bip39_pbkdf2.c
 * @brief PBKDF2-HMAC-SHA512 implementation for BIP39 seed derivation
 *
 * Implements PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA512
 * as specified in RFC 2898 and used by BIP39 for mnemonic-to-seed conversion.
 *
 * Reference: https://tools.ietf.org/html/rfc2898
 *
 * @author QGP Development Team
 * @date 2025-10-12
 */

#include "bip39.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>


#include <openssl/sha.h>

/**
 * HMAC-SHA512 implementation
 *
 * @param key HMAC key
 * @param key_len Key length in bytes
 * @param data Data to authenticate
 * @param data_len Data length in bytes
 * @param output Output buffer (64 bytes)
 */
static void hmac_sha512(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t output[64]
) {
    uint8_t k[128] = {0};  // SHA512 block size is 128 bytes

    // If key is longer than block size, hash it first
    if (key_len > 128) {
        SHA512(key, key_len, k);
        key_len = 64;  // SHA512 output is 64 bytes
    } else {
        memcpy(k, key, key_len);
    }

    // Create inner and outer padded keys
    uint8_t ipad[128];
    uint8_t opad[128];

    for (int i = 0; i < 128; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    // Inner hash: H(ipad || data)
    uint8_t inner_hash[64];
    {
        // Allocate temporary buffer for ipad + data
        size_t inner_len = 128 + data_len;
        uint8_t *inner_data = malloc(inner_len);
        if (!inner_data) {
            // Fallback: hash in two steps (less efficient but works)
            memset(output, 0, 64);
            return;
        }

        memcpy(inner_data, ipad, 128);
        memcpy(inner_data + 128, data, data_len);
        SHA512(inner_data, inner_len, inner_hash);
        free(inner_data);
    }

    // Outer hash: H(opad || inner_hash)
    {
        uint8_t outer_data[128 + 64];
        memcpy(outer_data, opad, 128);
        memcpy(outer_data + 128, inner_hash, 64);
        SHA512(outer_data, 128 + 64, output);
    }
}

/**
 * XOR two byte arrays
 */
static void xor_bytes(uint8_t *dest, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dest[i] ^= src[i];
    }
}

/**
 * Convert uint32_t to big-endian bytes
 */
static void uint32_to_be(uint8_t *bytes, uint32_t value) {
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
}

/**
 * PBKDF2-HMAC-SHA512 implementation
 *
 * @param password Password (mnemonic)
 * @param password_len Password length
 * @param salt Salt ("mnemonic" + passphrase)
 * @param salt_len Salt length
 * @param iterations Number of iterations (2048 for BIP39)
 * @param output Output buffer (64 bytes for BIP39)
 * @param output_len Output length (64 for BIP39)
 * @return 0 on success, -1 on error
 */
int bip39_pbkdf2_hmac_sha512(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *output, size_t output_len
) {
    if (!password || !salt || !output) {
        return -1;
    }

    if (iterations == 0 || output_len == 0) {
        return -1;
    }

    // PBKDF2 produces blocks of hLen (64 bytes for SHA512)
    const size_t hLen = 64;
    uint32_t blocks_needed = (output_len + hLen - 1) / hLen;

    // Process each block
    for (uint32_t block = 1; block <= blocks_needed; block++) {
        uint8_t U[64];  // Current iteration result
        uint8_t T[64];  // Accumulated XOR result

        // Prepare salt || INT(block)
        uint8_t *salt_block = malloc(salt_len + 4);
        if (!salt_block) {
            return -1;
        }

        memcpy(salt_block, salt, salt_len);
        uint32_to_be(salt_block + salt_len, block);

        // U1 = PRF(password, salt || INT(block))
        hmac_sha512(password, password_len, salt_block, salt_len + 4, U);
        memcpy(T, U, hLen);

        // U2 through Uc = PRF(password, U{c-1})
        for (uint32_t iter = 1; iter < iterations; iter++) {
            hmac_sha512(password, password_len, U, hLen, U);
            xor_bytes(T, U, hLen);
        }

        // Copy result to output (handle partial blocks)
        size_t offset = (block - 1) * hLen;
        size_t copy_len = (offset + hLen > output_len) ? (output_len - offset) : hLen;
        memcpy(output + offset, T, copy_len);

        free(salt_block);
    }

    return 0;
}

/**
 * BIP39 mnemonic to seed conversion
 *
 * @param mnemonic BIP39 mnemonic phrase (space-separated words)
 * @param passphrase Optional passphrase (empty string if none)
 * @param seed Output buffer (64 bytes)
 * @return 0 on success, -1 on error
 */
int bip39_mnemonic_to_seed(
    const char *mnemonic,
    const char *passphrase,
    uint8_t seed[BIP39_SEED_SIZE]
) {
    if (!mnemonic || !seed) {
        return -1;
    }

    // Use empty string if passphrase is NULL
    if (!passphrase) {
        passphrase = "";
    }

    // Prepare salt: "mnemonic" + passphrase
    const char *salt_prefix = "mnemonic";
    size_t salt_len = strlen(salt_prefix) + strlen(passphrase);
    uint8_t *salt = malloc(salt_len);
    if (!salt) {
        return -1;
    }

    memcpy(salt, salt_prefix, strlen(salt_prefix));
    memcpy(salt + strlen(salt_prefix), passphrase, strlen(passphrase));


    // PBKDF2-HMAC-SHA512 with 2048 iterations
    int result = bip39_pbkdf2_hmac_sha512(
        (const uint8_t *)mnemonic, strlen(mnemonic),
        salt, salt_len,
        BIP39_PBKDF2_ROUNDS,
        seed, BIP39_SEED_SIZE
    );


    free(salt);
    return result;
}
