/*
 * cellframe_json_minimal.h - Minimal JSON Conversion for Cellframe Transactions
 *
 * Converts signed binary transactions to JSON format for RPC submission.
 */

#ifndef CELLFRAME_JSON_MINIMAL_H
#define CELLFRAME_JSON_MINIMAL_H

#include "blockchain_minimal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Convert signed transaction binary to JSON
 *
 * Produces JSON matching cellframe-tool-sign output:
 * {
 *   "datum_hash": "0x...",
 *   "ts_created": 1760943452,
 *   "datum_type": "tx",
 *   "items": [...]
 * }
 *
 * @param tx_data Complete transaction binary (with signature)
 * @param tx_size Transaction size
 * @param json_out Output JSON string (caller must free)
 * @return 0 on success, -1 on error
 */
int cellframe_tx_to_json(const uint8_t *tx_data, size_t tx_size, char **json_out);

/**
 * Base64 encode data
 * @param data Input data
 * @param data_len Input length
 * @param base64_out Output Base64 string (caller must free)
 * @return Length of Base64 string, or -1 on error
 */
int cellframe_base64_encode(const uint8_t *data, size_t data_len, char **base64_out);

/**
 * Convert hash to hex string with 0x prefix
 * @param hash Hash (32 bytes)
 * @param hex_out Output hex string (must be at least 67 bytes: "0x" + 64 + null)
 */
void cellframe_hash_to_hex(const cellframe_hash_t *hash, char *hex_out);

/**
 * Format uint256_t as decimal string
 * @param value uint256_t value
 * @param str_out Output string (must be at least 80 bytes)
 */
void cellframe_uint256_to_str(const uint256_t *value, char *str_out);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_JSON_MINIMAL_H */
