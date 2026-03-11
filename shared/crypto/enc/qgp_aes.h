/*
 * QGP AES-256-GCM Encryption (AEAD)
 *
 * AES-256 Galois/Counter Mode encryption using OpenSSL EVP interface.
 *
 * Security:
 * - AES-256-GCM (Authenticated Encryption with Associated Data)
 * - Random 12-byte nonce per encryption
 * - 16-byte authentication tag (integrity + authenticity)
 * - No padding required (stream cipher mode)
 * - Metadata authentication via AAD
 */

#ifndef QGP_AES_H
#define QGP_AES_H

#include <stdint.h>
#include <stddef.h>

/**
 * Calculate required buffer size for AES-256-GCM encryption
 *
 * @param plaintext_len Length of plaintext to encrypt
 * @return Required ciphertext buffer size (exact plaintext length, no padding)
 *
 * GCM is a stream cipher - ciphertext is same size as plaintext.
 * Nonce (12 bytes) and tag (16 bytes) are stored separately.
 */
size_t qgp_aes256_encrypt_size(size_t plaintext_len);

/**
 * Encrypt data with AES-256-GCM (AEAD)
 *
 * @param key 32-byte AES-256 key
 * @param plaintext Input plaintext data
 * @param plaintext_len Length of plaintext
 * @param aad Additional Authenticated Data (metadata to authenticate but not encrypt)
 * @param aad_len Length of AAD (can be 0 if no AAD)
 * @param ciphertext Output buffer (must be >= plaintext_len)
 * @param ciphertext_len Output: actual ciphertext length (same as plaintext_len)
 * @param nonce Output: 12-byte nonce (caller provides buffer)
 * @param tag Output: 16-byte authentication tag (caller provides buffer)
 * @return 0 on success, -1 on error
 *
 * Format: Ciphertext, nonce, and tag are stored separately.
 * Caller must save [nonce || ciphertext || tag] for decryption.
 */
int qgp_aes256_encrypt(const uint8_t *key,
                       const uint8_t *plaintext, size_t plaintext_len,
                       const uint8_t *aad, size_t aad_len,
                       uint8_t *ciphertext, size_t *ciphertext_len,
                       uint8_t *nonce,
                       uint8_t *tag);

/**
 * Decrypt data with AES-256-GCM (AEAD)
 *
 * @param key 32-byte AES-256 key
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Length of ciphertext
 * @param aad Additional Authenticated Data (must match encryption AAD)
 * @param aad_len Length of AAD
 * @param nonce 12-byte nonce (from encryption)
 * @param tag 16-byte authentication tag (from encryption)
 * @param plaintext Output buffer (must be >= ciphertext_len)
 * @param plaintext_len Output: actual plaintext length
 * @return 0 on success, -1 on authentication failure or error
 *
 * Authentication failure means:
 * - Ciphertext was tampered with, OR
 * - AAD was tampered with, OR
 * - Wrong key/nonce/tag
 *
 * On authentication failure, plaintext output is INVALID and must be discarded.
 */
int qgp_aes256_decrypt(const uint8_t *key,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *nonce,
                       const uint8_t *tag,
                       uint8_t *plaintext, size_t *plaintext_len);

#endif /* QGP_AES_H */
