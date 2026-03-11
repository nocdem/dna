/*
 * RFC 3394 - AES Key Wrap Algorithm (OpenSSL Implementation)
 *
 * - EVP_aes_256_wrap() for wrapping (encryption)
 * - EVP_aes_256_wrap() for unwrapping (decryption)
 *
 * NIST-approved key wrapping using AES encryption.
 * Used for multi-recipient encryption to wrap the DEK (Data Encryption Key).
 *
 * References:
 * - RFC 3394: https://www.rfc-editor.org/rfc/rfc3394
 * - NIST SP 800-38F: Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping
 * - OpenSSL EVP_aes_256_wrap documentation
 *
 * Security: AES-256 provides 128-bit quantum security (via Grover's algorithm)
 */

#include "aes_keywrap.h"
#include <openssl/evp.h>
#include <string.h>

/**
 * RFC 3394 AES Key Wrap using OpenSSL
 *
 * Wraps a 256-bit key using AES-256 in Key Wrap mode (RFC 3394).
 *
 * OpenSSL Implementation:
 *   - Uses EVP_aes_256_wrap() cipher
 *   - Automatically handles RFC 3394 algorithm (6*n iterations)
 *   - Adds integrity check value (0xA6A6A6A6A6A6A6A6)
 *   - Returns wrapped key with 8-byte overhead
 *
 * @param key_to_wrap: 32-byte key to wrap (DEK)
 * @param key_size: Must be 32 bytes
 * @param kek: 32-byte Key Encryption Key (from Kyber512 shared secret)
 * @param wrapped_out: Output buffer (40 bytes: 8-byte IV + 32-byte wrapped key)
 * @return: 0 on success, -1 on error
 */
int aes256_wrap_key(const uint8_t *key_to_wrap, size_t key_size,
                   const uint8_t *kek, uint8_t *wrapped_out) {

    if (!key_to_wrap || !kek || !wrapped_out) {
        return -1;
    }

    // Only support 32-byte keys (256 bits)
    if (key_size != 32) {
        return -1;
    }

    // Create and initialize cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    // Initialize for AES-256 Key Wrap encryption
    // NULL IV parameter - RFC 3394 uses default IV (0xA6...)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set flag to allow key wrapping (required by OpenSSL)
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    // Perform key wrap operation
    // Output will be input_size + 8 bytes (8-byte integrity check value)
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, wrapped_out, &outlen, key_to_wrap, key_size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Verify output size (should be 40 bytes: 32 + 8)
    if (outlen != 40) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // No need for EVP_EncryptFinal_ex - key wrap is a single operation
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/**
 * RFC 3394 AES Key Unwrap using OpenSSL
 *
 * Unwraps a key encrypted with aes256_wrap_key, verifying integrity.
 *
 * OpenSSL Implementation:
 *   - Uses EVP_aes_256_wrap() cipher in decrypt mode
 *   - Automatically verifies RFC 3394 integrity check value
 *   - Returns error if integrity check fails (wrong KEK or corrupted data)
 *   - Removes 8-byte overhead to recover original key
 *
 * @param wrapped_key: 40-byte wrapped key (from aes256_wrap_key)
 * @param wrapped_size: Must be 40 bytes
 * @param kek: 32-byte Key Encryption Key
 * @param unwrapped_out: Output buffer for 32-byte unwrapped key
 * @return: 0 on success, -1 on error or integrity check failure
 */
int aes256_unwrap_key(const uint8_t *wrapped_key, size_t wrapped_size,
                     const uint8_t *kek, uint8_t *unwrapped_out) {

    if (!wrapped_key || !kek || !unwrapped_out) {
        return -1;
    }

    // Expected size: 8-byte IV + 32-byte wrapped key = 40 bytes
    if (wrapped_size != 40) {
        return -1;
    }

    // Create and initialize cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    // Initialize for AES-256 Key Wrap decryption
    // NULL IV parameter - RFC 3394 uses default IV (0xA6...)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set flag to allow key unwrapping (required by OpenSSL)
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    // Perform key unwrap operation
    // Output will be input_size - 8 bytes (removes 8-byte integrity check)
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, unwrapped_out, &outlen, wrapped_key, wrapped_size) != 1) {
        // Decryption failed - either wrong KEK or integrity check failed
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Verify output size (should be 32 bytes)
    if (outlen != 32) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // No need for EVP_DecryptFinal_ex - key unwrap is a single operation
    EVP_CIPHER_CTX_free(ctx);

    // Success - integrity check passed
    return 0;
}
