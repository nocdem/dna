/**
 * @file ed25519_sign.h
 * @brief Ed25519 signing utility (OpenSSL EVP)
 *
 * Shared signing function for Solana and any future Ed25519 usage.
 */

#ifndef ED25519_SIGN_H
#define ED25519_SIGN_H

#include <stdint.h>
#include <stddef.h>

/**
 * Sign message with Ed25519 (OpenSSL EVP).
 *
 * @param private_key  32-byte Ed25519 private key (seed)
 * @param message      Message bytes to sign
 * @param message_len  Message length
 * @param sig_out      Output: 64-byte Ed25519 signature
 * @return             0 on success, -1 on error
 */
int ed25519_sign(
    const uint8_t private_key[32],
    const uint8_t *message,
    size_t message_len,
    uint8_t sig_out[64]
);

/**
 * Derive Ed25519 public key from private key.
 *
 * @param private_key  32-byte Ed25519 private key
 * @param pubkey_out   Output: 32-byte public key
 * @return             0 on success, -1 on error
 */
int ed25519_pubkey_from_private(
    const uint8_t private_key[32],
    uint8_t pubkey_out[32]
);

#endif /* ED25519_SIGN_H */
