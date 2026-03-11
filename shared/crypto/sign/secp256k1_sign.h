/**
 * @file secp256k1_sign.h
 * @brief secp256k1 ECDSA recoverable signing utility
 *
 * Shared signing function for ETH, TRON, and EIP-712.
 */

#ifndef SECP256K1_SIGN_H
#define SECP256K1_SIGN_H

#include <stdint.h>

/**
 * Sign a 32-byte hash with secp256k1 ECDSA (recoverable).
 *
 * Output: sig_out = r(32) + s(32) + v(1) where v = 27 + recovery_id
 * For EIP-155 (ETH TX): caller uses recovery_id_out to compute v = recovery_id + chainId*2 + 35
 * For TRON/EIP-712: sig_out[64] is ready to use directly (v = 27 + recovery_id)
 *
 * @param private_key      32-byte private key
 * @param hash             32-byte hash to sign
 * @param sig_out          Output: 65 bytes (r + s + v)
 * @param recovery_id_out  Output: raw recovery_id (0 or 1). Pass NULL if not needed.
 * @return                 0 on success, -1 on error
 */
int secp256k1_sign_hash(
    const uint8_t private_key[32],
    const uint8_t hash[32],
    uint8_t sig_out[65],
    int *recovery_id_out
);

#endif /* SECP256K1_SIGN_H */
