/**
 * @file eth_rlp.h
 * @brief Recursive Length Prefix (RLP) Encoding for Ethereum
 *
 * RLP is Ethereum's serialization format for transactions and data.
 *
 * Rules:
 * - Single byte 0x00-0x7f: encoded as itself
 * - String 0-55 bytes: 0x80 + len, then string
 * - String >55 bytes: 0xb7 + len_of_len, then len (big-endian), then string
 * - List 0-55 bytes: 0xc0 + len, then items
 * - List >55 bytes: 0xf7 + len_of_len, then len (big-endian), then items
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#ifndef ETH_RLP_H
#define ETH_RLP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum encoded transaction size */
#define ETH_RLP_MAX_TX_SIZE     4096

/**
 * RLP encoding buffer
 */
typedef struct {
    uint8_t *data;          /* Encoded data */
    size_t len;             /* Current length */
    size_t capacity;        /* Buffer capacity */
} eth_rlp_buffer_t;

/**
 * Initialize RLP buffer
 *
 * @param buf       Buffer to initialize
 * @param capacity  Initial capacity (0 for default)
 * @return          0 on success, -1 on error
 */
int eth_rlp_init(eth_rlp_buffer_t *buf, size_t capacity);

/**
 * Free RLP buffer
 */
void eth_rlp_free(eth_rlp_buffer_t *buf);

/**
 * Reset buffer for reuse
 */
void eth_rlp_reset(eth_rlp_buffer_t *buf);

/**
 * Encode bytes/string
 *
 * @param buf       Output buffer
 * @param data      Data to encode (can be NULL if len is 0)
 * @param len       Length of data
 * @return          0 on success, -1 on error
 */
int eth_rlp_encode_bytes(eth_rlp_buffer_t *buf, const uint8_t *data, size_t len);

/**
 * Encode uint64 as RLP
 *
 * @param buf       Output buffer
 * @param value     Value to encode
 * @return          0 on success, -1 on error
 */
int eth_rlp_encode_uint64(eth_rlp_buffer_t *buf, uint64_t value);

/**
 * Encode 256-bit integer (big-endian, 32 bytes)
 * Strips leading zeros.
 *
 * @param buf       Output buffer
 * @param value     32-byte big-endian value
 * @return          0 on success, -1 on error
 */
int eth_rlp_encode_uint256(eth_rlp_buffer_t *buf, const uint8_t value[32]);

/**
 * Begin encoding a list
 * Returns position to patch length later with eth_rlp_end_list.
 *
 * @param buf       Output buffer
 * @return          Position marker, or -1 on error
 */
int eth_rlp_begin_list(eth_rlp_buffer_t *buf);

/**
 * End list encoding
 * Patches the list header at position returned by eth_rlp_begin_list.
 *
 * @param buf       Output buffer
 * @param pos       Position from eth_rlp_begin_list
 * @return          0 on success, -1 on error
 */
int eth_rlp_end_list(eth_rlp_buffer_t *buf, int pos);

/**
 * Wrap existing encoded data in a list
 *
 * @param items     Already encoded items (concatenated)
 * @param items_len Length of items
 * @param out       Output buffer
 * @return          0 on success, -1 on error
 */
int eth_rlp_wrap_list(const uint8_t *items, size_t items_len, eth_rlp_buffer_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ETH_RLP_H */
