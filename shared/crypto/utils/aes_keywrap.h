/*
 * AES Key Wrapping (RFC 3394) for pqsignum
 *
 * Used for multi-recipient encryption:
 * - Wrap Data Encryption Key (DEK) with Key Encryption Key (KEK)
 * - Each recipient gets their own wrapped DEK
 *
 * Protocol Mode: Uses standard AES Key Wrap algorithm
 */

#ifndef QGP_AES_KEYWRAP_H
#define QGP_AES_KEYWRAP_H

#include <stdint.h>
#include <stddef.h>

/**
 * AES-256 Key Wrap (RFC 3394)
 *
 * Wraps a key (typically 32-byte DEK) with a KEK (Key Encryption Key).
 * Output is 8 bytes larger than input (adds IV/integrity check).
 *
 * @param key_to_wrap: Key to wrap (e.g., DEK)
 * @param key_size: Size of key to wrap (must be multiple of 8, typically 32)
 * @param kek: Key Encryption Key (32 bytes for AES-256)
 * @param wrapped_out: Output buffer (must be key_size + 8 bytes)
 * @return: 0 on success, -1 on error
 */
int aes256_wrap_key(const uint8_t *key_to_wrap, size_t key_size,
                   const uint8_t *kek, uint8_t *wrapped_out);

/**
 * AES-256 Key Unwrap (RFC 3394)
 *
 * Unwraps a wrapped key, verifying integrity.
 *
 * @param wrapped_key: Wrapped key data
 * @param wrapped_size: Size of wrapped key (must be multiple of 8, >= 16)
 * @param kek: Key Encryption Key (32 bytes for AES-256)
 * @param unwrapped_out: Output buffer (must be wrapped_size - 8 bytes)
 * @return: 0 on success, -1 on error (including integrity check failure)
 */
int aes256_unwrap_key(const uint8_t *wrapped_key, size_t wrapped_size,
                     const uint8_t *kek, uint8_t *unwrapped_out);

#endif /* QGP_AES_KEYWRAP_H */
