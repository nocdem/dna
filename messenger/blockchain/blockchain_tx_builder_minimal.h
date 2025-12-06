/*
 * cellframe_tx_builder_minimal.h - Minimal Transaction Builder
 *
 * Builds binary transactions matching Cellframe SDK format exactly.
 */

#ifndef CELLFRAME_TX_BUILDER_MINIMAL_H
#define CELLFRAME_TX_BUILDER_MINIMAL_H

#include "blockchain_minimal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Transaction builder context
 */
typedef struct {
    uint8_t *data;          // Transaction binary data
    size_t size;            // Current size (includes header)
    size_t capacity;        // Allocated capacity
    uint64_t timestamp;     // Transaction timestamp
} cellframe_tx_builder_t;

/**
 * Create new transaction builder
 * @return Builder context, or NULL on error
 */
cellframe_tx_builder_t* cellframe_tx_builder_new(void);

/**
 * Free transaction builder
 * @param builder Builder context
 */
void cellframe_tx_builder_free(cellframe_tx_builder_t *builder);

/**
 * Set transaction timestamp
 * @param builder Builder context
 * @param timestamp Unix timestamp (seconds since epoch)
 * @return 0 on success, -1 on error
 */
int cellframe_tx_set_timestamp(cellframe_tx_builder_t *builder, uint64_t timestamp);

/**
 * Add IN item
 * @param builder Builder context
 * @param prev_hash Previous transaction hash
 * @param prev_idx Previous output index
 * @return 0 on success, -1 on error
 */
int cellframe_tx_add_in(cellframe_tx_builder_t *builder,
                        const cellframe_hash_t *prev_hash,
                        uint32_t prev_idx);

/**
 * Add OUT item (type 0x12 - current format, NO token field)
 * Use for native CELL token only.
 * @param builder Builder context
 * @param addr Recipient address (77 bytes)
 * @param value Amount in datoshi
 * @return 0 on success, -1 on error
 */
int cellframe_tx_add_out(cellframe_tx_builder_t *builder,
                         const cellframe_addr_t *addr,
                         uint256_t value);

/**
 * Add OUT_EXT item (type 0x11 - has token field)
 * Use for non-native tokens (CPUNK, etc.)
 * @param builder Builder context
 * @param addr Recipient address (77 bytes)
 * @param value Amount in datoshi
 * @param token Token ticker (max 10 chars, e.g., "CPUNK")
 * @return 0 on success, -1 on error
 */
int cellframe_tx_add_out_ext(cellframe_tx_builder_t *builder,
                              const cellframe_addr_t *addr,
                              uint256_t value,
                              const char *token);

/**
 * Add OUT_COND item (type 0x61 - fee)
 * @param builder Builder context
 * @param value Fee amount in datoshi
 * @return 0 on success, -1 on error
 */
int cellframe_tx_add_fee(cellframe_tx_builder_t *builder, uint256_t value);

/**
 * Add TSD (Type-Specific Data) item to transaction
 *
 * Adds custom data to the transaction. TSD items can contain arbitrary data
 * with a type identifier.
 *
 * @param builder Builder context
 * @param tsd_type TSD type identifier (e.g., TSD_TYPE_CUSTOM_STRING = 0xf003)
 * @param data Data to include (will be copied)
 * @param data_size Size of data in bytes
 * @return 0 on success, -1 on error
 */
int cellframe_tx_add_tsd(cellframe_tx_builder_t *builder, uint16_t tsd_type,
                         const uint8_t *data, size_t data_size);

/**
 * Get transaction binary data for signing
 *
 * CRITICAL: Returns a COPY with tx_items_size = 0 (SDK requirement)
 * MEMORY: Caller MUST free() the returned pointer!
 * This is what must be hashed and signed.
 *
 * @param builder Builder context
 * @param size_out Output size
 * @return Pointer to transaction data, or NULL on error
 */
const uint8_t* cellframe_tx_get_signing_data(cellframe_tx_builder_t *builder, size_t *size_out);

/**
 * Get complete transaction data (after signature added)
 * @param builder Builder context
 * @param size_out Output size
 * @return Pointer to transaction data, or NULL on error
 */
const uint8_t* cellframe_tx_get_data(cellframe_tx_builder_t *builder, size_t *size_out);

/**
 * Add signature item
 * @param builder Builder context
 * @param dap_sign dap_sign_t structure (3306 bytes for Dilithium MODE_1)
 * @param dap_sign_size Size of dap_sign_t
 * @return 0 on success, -1 on error
 */
int cellframe_tx_add_signature(cellframe_tx_builder_t *builder,
                                const uint8_t *dap_sign,
                                size_t dap_sign_size);

/**
 * Parse CELL amount string to uint256_t datoshi (for USER INPUT)
 * Converts CELL to datoshi: "3000" or "3000.0" -> 3000 * 10^18 datoshi
 * @param value_str CELL amount (e.g., "0.01", "3000", "3000.0")
 * @param value_out Output uint256_t in datoshi
 * @return 0 on success, -1 on error
 */
int cellframe_uint256_from_str(const char *value_str, uint256_t *value_out);

/**
 * Parse raw datoshi string to uint256_t (for RPC/UTXO values)
 * NO conversion - value is already in datoshi: "2419239505821527777" -> same value
 * @param str Raw datoshi string from blockchain
 * @param out Output uint256_t
 * @return 0 on success, -1 on error
 */
int cellframe_uint256_scan_uninteger(const char *str, uint256_t *out);

/**
 * Hex string to binary
 * @param hex Hex string (with or without 0x prefix)
 * @param bin Output binary buffer
 * @param bin_size Size of binary buffer
 * @return Number of bytes written, or -1 on error
 */
int cellframe_hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_TX_BUILDER_MINIMAL_H */
