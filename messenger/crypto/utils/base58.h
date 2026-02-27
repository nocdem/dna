/*
 * base58.h - Base58 encoding/decoding
 *
 * Copied from Cellframe SDK (GPL-3.0)
 * Authors: Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 */

#ifndef BASE58_H
#define BASE58_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Calculates encode size from input size
 */
#define BASE58_ENCODE_SIZE(a_in_size) ((size_t)((137 * a_in_size / 100) + 2))
#define BASE58_DECODE_SIZE(a_in_size) ((size_t)(2 * a_in_size + 1))

/**
 * @brief base58_encode - Encode binary data to base58 string
 * @param a_in - input binary data
 * @param a_in_size - input data size
 * @param a_out - output buffer (must be at least BASE58_ENCODE_SIZE(a_in_size) bytes)
 * @return size of encoded string (without null terminator), or 0 on error
 */
size_t base58_encode(const void *a_in, size_t a_in_size, char *a_out);

/**
 * @brief base58_decode - Decode base58 string to binary data
 * @param a_in - input base58 string
 * @param a_out - output buffer (must be at least BASE58_DECODE_SIZE(strlen(a_in)) bytes)
 * @return size of decoded data, or 0 on error
 */
size_t base58_decode(const char *a_in, void *a_out);

#ifdef __cplusplus
}
#endif

#endif /* BASE58_H */
