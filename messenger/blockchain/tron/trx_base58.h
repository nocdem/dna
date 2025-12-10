/**
 * @file trx_base58.h
 * @brief Base58Check encoding for TRON addresses
 *
 * TRON uses Base58Check encoding (same as Bitcoin) for addresses.
 * Address format: Base58Check(0x41 || Keccak256(pubkey)[-20:])
 *
 * @author DNA Messenger Team
 * @date 2025-12-11
 */

#ifndef TRX_BASE58_H
#define TRX_BASE58_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Base58 alphabet (Bitcoin/TRON standard) */
#define BASE58_ALPHABET "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

/**
 * Encode data as Base58
 *
 * @param data      Input data
 * @param data_len  Length of input data
 * @param out       Output buffer for Base58 string
 * @param out_size  Size of output buffer
 * @return          Length of encoded string, or -1 on error
 */
int trx_base58_encode(
    const uint8_t *data,
    size_t data_len,
    char *out,
    size_t out_size
);

/**
 * Decode Base58 string to data
 *
 * @param str       Base58 encoded string
 * @param out       Output buffer for decoded data
 * @param out_size  Size of output buffer
 * @return          Length of decoded data, or -1 on error
 */
int trx_base58_decode(
    const char *str,
    uint8_t *out,
    size_t out_size
);

/**
 * Encode data as Base58Check (with double SHA256 checksum)
 *
 * Appends 4-byte checksum: SHA256(SHA256(data))[0:4]
 *
 * @param data      Input data (including version byte)
 * @param data_len  Length of input data
 * @param out       Output buffer for Base58Check string
 * @param out_size  Size of output buffer
 * @return          Length of encoded string, or -1 on error
 */
int trx_base58check_encode(
    const uint8_t *data,
    size_t data_len,
    char *out,
    size_t out_size
);

/**
 * Decode Base58Check string and verify checksum
 *
 * @param str       Base58Check encoded string
 * @param out       Output buffer for decoded data (without checksum)
 * @param out_size  Size of output buffer
 * @return          Length of decoded data (without checksum), or -1 on error/invalid checksum
 */
int trx_base58check_decode(
    const char *str,
    uint8_t *out,
    size_t out_size
);

/**
 * Verify Base58Check string checksum
 *
 * @param str       Base58Check encoded string
 * @return          1 if valid, 0 if invalid
 */
int trx_base58check_verify(const char *str);

#ifdef __cplusplus
}
#endif

#endif /* TRX_BASE58_H */
