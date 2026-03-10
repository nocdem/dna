/**
 * Nodus — Dilithium5 Crypto Wrapper
 *
 * Thin wrapper around shared/crypto qgp_dsa87_* functions.
 * Provides Nodus-typed API for sign/verify/hash operations.
 *
 * @file nodus_sign.h
 */

#ifndef NODUS_SIGN_H
#define NODUS_SIGN_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sign data with Dilithium5 secret key.
 *
 * @param sig_out   Output signature
 * @param data      Data to sign
 * @param data_len  Data length
 * @param sk        Secret key
 * @return 0 on success, -1 on error
 */
int nodus_sign(nodus_sig_t *sig_out,
               const uint8_t *data, size_t data_len,
               const nodus_seckey_t *sk);

/**
 * Verify Dilithium5 signature.
 *
 * @param sig       Signature to verify
 * @param data      Signed data
 * @param data_len  Data length
 * @param pk        Public key
 * @return 0 if valid, -1 if invalid
 */
int nodus_verify(const nodus_sig_t *sig,
                 const uint8_t *data, size_t data_len,
                 const nodus_pubkey_t *pk);

/**
 * Compute SHA3-512 hash.
 *
 * @param data      Input data
 * @param data_len  Input length
 * @param hash_out  Output hash (64 bytes)
 * @return 0 on success, -1 on error
 */
int nodus_hash(const uint8_t *data, size_t data_len, nodus_key_t *hash_out);

/**
 * Compute SHA3-512 hash of data and return hex string.
 *
 * @param data      Input data
 * @param data_len  Input length
 * @param hex_out   Output hex string (must be >= NODUS_KEY_HEX_LEN)
 * @return 0 on success, -1 on error
 */
int nodus_hash_hex(const uint8_t *data, size_t data_len,
                   char *hex_out);

/**
 * Compute fingerprint (SHA3-512) of a public key.
 *
 * @param pk        Public key
 * @param fp_out    Output key (SHA3-512 of pk bytes)
 * @return 0 on success, -1 on error
 */
int nodus_fingerprint(const nodus_pubkey_t *pk, nodus_key_t *fp_out);

/**
 * Compute fingerprint hex string.
 *
 * @param pk        Public key
 * @param hex_out   Output (must be >= NODUS_KEY_HEX_LEN)
 * @return 0 on success, -1 on error
 */
int nodus_fingerprint_hex(const nodus_pubkey_t *pk, char *hex_out);

/**
 * Generate random bytes.
 *
 * @param buf  Output buffer
 * @param len  Number of bytes
 * @return 0 on success, -1 on error
 */
int nodus_random(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_SIGN_H */
