/*
 * cellframe_tx.h - Cellframe Transaction Binary Serialization
 *
 * Implements binary transaction format for Cellframe blockchain.
 * Used for local transaction signing before submission to public RPC.
 */

#ifndef CELLFRAME_TX_H
#define CELLFRAME_TX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Transaction item types (from Cellframe SDK)
#define TX_ITEM_TYPE_IN         0x00
#define TX_ITEM_TYPE_OUT        0x12  // Current format (matches RPC)
#define TX_ITEM_TYPE_OUT_EXT    0x11  // Old format (deprecated)
#define TX_ITEM_TYPE_OUT_STD    0x13  // DO NOT USE (causes hash mismatch)
#define TX_ITEM_TYPE_OUT_COND   0x61
#define TX_ITEM_TYPE_SIG        0x30

// OUT_COND subtypes
#define TX_OUT_COND_SUBTYPE_FEE 0x04

// Signature types (from Cellframe SDK dap_sign.h)
#define SIG_TYPE_DILITHIUM      0x0102

// Network IDs
#define CELLFRAME_NET_BACKBONE  0x0404202200000000ULL

// Constants
#define CELLFRAME_TICKER_SIZE_MAX 10

// uint256_t definition (32 bytes)
typedef struct {
    uint64_t lo[4];  // Little-endian 256-bit value
} __attribute__((packed)) uint256_t;

// Hash structure (32 bytes)
typedef struct {
    uint8_t raw[32];
} __attribute__((packed)) cellframe_hash_t;

// Address structure (Wire format - 77 bytes total as used in base58-encoded addresses)
// NOTE: SDK dap_chain_addr_t is 75 bytes logically but 77 bytes with compiler padding
typedef struct {
    uint8_t addr_ver;           // 1 byte - Address version (1 for current)
    uint64_t net_id;            // 8 bytes - Network ID (e.g. 0x0404202200000000 for backbone)
    uint16_t sig_type;          // 2 bytes - Signature type (0x0102 for Dilithium)
    uint16_t padding;           // 2 bytes - Padding (matches actual wire format)
    uint8_t hash[32];           // 32 bytes - Public key hash (SHA3-256)
    uint8_t checksum[32];       // 32 bytes - Checksum (SHA3-256)
} __attribute__((packed)) cellframe_addr_t;  // Total: 77 bytes

// Signature structure (from Cellframe SDK dap_sign.h)
// CRITICAL: This structure is BASE64-encoded in its ENTIRETY for JSON transactions
typedef struct {
    struct {
        uint32_t type;           // SIG_TYPE_DILITHIUM (0x0102)
        uint8_t hash_type;       // 0x01 for SHA3-256 (REQUIRED by Cellframe)
        uint8_t padding;         // 0x00
        uint32_t sign_size;      // Dilithium signature size (2044 for MODE_1)
        uint32_t sign_pkey_size; // Dilithium public key size (1184 for MODE_1)
    } __attribute__((packed)) header;  // 14 bytes total
    uint8_t pkey_n_sign[];      // [1184-byte public_key][2044-byte signature] = 3228 bytes
} __attribute__((packed)) dap_sign_t;  // Total: 14 + 1184 + 2044 = 3242 bytes

// Transaction header
typedef struct {
    uint64_t ts_created;     // Timestamp
    uint32_t tx_items_size;  // Total size of all items
} __attribute__((packed)) cellframe_tx_header_t;

// IN item structure
typedef struct {
    uint8_t type;                    // TX_ITEM_TYPE_IN (0x00)
    cellframe_hash_t tx_prev_hash;   // Previous transaction hash
    uint32_t tx_out_prev_idx;        // Previous output index
} __attribute__((packed)) cellframe_tx_in_t;

// OUT item structure (CURRENT FORMAT - matches Cellframe RPC expectation!)
// This is what Cellframe RPC creates when parsing signed JSON with "type":"out"
// CRITICAL: Uses nested structure layout to match SDK exactly
typedef struct {
    struct {
        uint8_t type;            // TX_ITEM_TYPE_OUT (0x12)
        uint256_t value;         // Amount to transfer (32 bytes)
    } __attribute__((packed)) header;
    cellframe_addr_t addr;       // Recipient address (77 bytes)
} __attribute__((packed)) cellframe_tx_out_t;

// OUT_EXT item structure (OLD FORMAT - deprecated)
typedef struct {
    uint8_t type;                           // TX_ITEM_TYPE_OUT_EXT (0x11)
    uint256_t value;                        // Amount to transfer
    cellframe_addr_t addr;                  // Recipient address
    char token[CELLFRAME_TICKER_SIZE_MAX];  // Token ticker
} __attribute__((packed)) cellframe_tx_out_ext_t;

// OUT_STD item structure (DO NOT USE - causes hash mismatch)
typedef struct {
    uint8_t type;                           // TX_ITEM_TYPE_OUT_STD (0x13)
    uint8_t version;                        // Output version (always 0)
    char token[CELLFRAME_TICKER_SIZE_MAX];  // Token ticker
    uint256_t value;                        // Amount to transfer
    cellframe_addr_t addr;                  // Recipient address
    uint64_t ts_unlock;                     // Time to unlock (0 = unlocked)
} __attribute__((aligned(1),packed)) cellframe_tx_out_std_t;

// OUT_COND item structure (simplified for fee)
typedef struct {
    uint8_t item_type;      // TX_ITEM_TYPE_OUT_COND (0x61)
    uint8_t subtype;        // TX_OUT_COND_SUBTYPE_FEE (0x04)
    uint256_t value;        // Fee amount
    uint8_t padding_ext[6];
    uint64_t ts_expires;    // Expiration timestamp (0 = never)
    uint64_t srv_uid;       // Service UID
    uint8_t padding[8];
    // For fee subtype, union is empty (272 bytes of free_space)
    uint8_t free_space[272];
    uint32_t tsd_size;      // TSD data size (0 for simple fee)
    // tsd[] would follow if tsd_size > 0
} __attribute__((packed)) cellframe_tx_out_cond_t;

// SIG item structure (from Cellframe SDK)
typedef struct {
    uint8_t type;       // TX_ITEM_TYPE_SIG (0x30)
    uint8_t version;    // Version (1)
    uint32_t sig_size;  // Total size of dap_sign_t structure
    // dap_sign_t follows
} __attribute__((packed)) cellframe_tx_sig_header_t;

// Transaction builder context
typedef struct {
    uint8_t *data;          // Binary transaction data
    size_t size;            // Current size
    size_t capacity;        // Allocated capacity
    size_t items_size;      // Size of items (excluding header)
} cellframe_tx_builder_t;

/**
 * Create new transaction builder
 */
cellframe_tx_builder_t* cellframe_tx_builder_new(void);

/**
 * Free transaction builder
 */
void cellframe_tx_builder_free(cellframe_tx_builder_t *builder);

/**
 * Add IN item to transaction
 */
int cellframe_tx_add_in(cellframe_tx_builder_t *builder, const cellframe_hash_t *prev_hash, uint32_t prev_idx);

/**
 * Add OUT_EXT item to transaction
 */
int cellframe_tx_add_out_ext(cellframe_tx_builder_t *builder, const cellframe_addr_t *addr,
                              const char *value_str, const char *token);

/**
 * Add OUT_COND (fee) item to transaction
 */
int cellframe_tx_add_fee(cellframe_tx_builder_t *builder, const char *fee_str);

/**
 * Get transaction binary data (for signing)
 * Returns pointer to transaction data and size
 */
const uint8_t* cellframe_tx_get_data(cellframe_tx_builder_t *builder, size_t *size_out);

/**
 * Sign transaction with Dilithium private key
 * Returns RAW signature (NOT dap_sign_t structure)
 *
 * @param tx_data - Transaction binary data
 * @param tx_size - Transaction data size
 * @param priv_key - Dilithium private key
 * @param priv_key_size - Private key size
 * @param sig_out - Output RAW signature (caller must free)
 * @param sig_size_out - Output signature size
 * @return 0 on success, -1 on error
 */
int cellframe_tx_sign(const uint8_t *tx_data, size_t tx_size,
                      const uint8_t *priv_key, size_t priv_key_size,
                      uint8_t **sig_out, size_t *sig_size_out);

/**
 * Build dap_sign_t structure from public key and signature
 *
 * This builds the complete structure expected by Cellframe:
 * [14-byte header][public_key][signature]
 *
 * This ENTIRE structure must be BASE64-encoded for JSON transactions.
 *
 * @param pub_key - Public key (can have 12-byte header, will be stripped)
 * @param pub_key_size - Public key size
 * @param signature - Raw signature bytes
 * @param sig_size - Signature size
 * @param dap_sign_out - Output dap_sign_t structure (caller must free)
 * @param dap_sign_size_out - Output dap_sign_t size
 * @return 0 on success, -1 on error
 */
int cellframe_build_dap_sign_t(const uint8_t *pub_key, size_t pub_key_size,
                                 const uint8_t *signature, size_t sig_size,
                                 uint8_t **dap_sign_out, size_t *dap_sign_size_out);

/**
 * Parse uint256 from decimal string
 */
int cellframe_uint256_from_str(const char *value_str, uint256_t *value_out);

/**
 * UTXO query result
 */
typedef struct {
    cellframe_hash_t prev_hash;
    uint32_t out_prev_idx;
    uint256_t value;
} cellframe_utxo_t;

typedef struct {
    cellframe_utxo_t *utxos;
    size_t count;
    uint256_t total_value;
} cellframe_utxo_list_t;

/**
 * Query UTXOs from public RPC
 *
 * @param rpc_url - RPC endpoint (e.g., "http://rpc.cellframe.net/connect")
 * @param network - Network name (e.g., "Backbone")
 * @param addr_str - Wallet address (Base58)
 * @param token - Token ticker (e.g., "CPUNK")
 * @param list_out - Output UTXO list (caller must free with cellframe_utxo_list_free)
 * @return 0 on success, -1 on error
 */
int cellframe_query_utxos(const char *rpc_url, const char *network,
                           const char *addr_str, const char *token,
                           cellframe_utxo_list_t **list_out);

/**
 * Query network fee from public RPC
 *
 * @param rpc_url - RPC endpoint
 * @param network - Network name
 * @param fee_out - Output fee amount (datoshi)
 * @param fee_addr_out - Output fee address (Base58, must be at least 120 bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_query_network_fee(const char *rpc_url, const char *network,
                                 uint256_t *fee_out, char *fee_addr_out);

/**
 * Free UTXO list
 */
void cellframe_utxo_list_free(cellframe_utxo_list_t *list);

/**
 * Add SIG item to transaction with Dilithium signature
 *
 * CRITICAL: Transaction MUST be signed with tx_items_size = 0 in header!
 *
 * @param builder - Transaction builder
 * @param pub_key - Dilithium public key
 * @param pub_key_size - Public key size
 * @param priv_key - Dilithium private key
 * @param priv_key_size - Private key size
 * @return 0 on success, -1 on error
 */
int cellframe_tx_add_signature(cellframe_tx_builder_t *builder,
                                 const uint8_t *pub_key, size_t pub_key_size,
                                 const uint8_t *priv_key, size_t priv_key_size);

/**
 * Convert signed transaction to JSON for RPC submission
 *
 * @param tx_data - Complete transaction binary (with SIG item)
 * @param tx_size - Transaction size
 * @param network - Network name
 * @param chain - Chain name (e.g., "main")
 * @param json_out - Output JSON string (caller must free)
 * @return 0 on success, -1 on error
 */
int cellframe_tx_to_json(const uint8_t *tx_data, size_t tx_size,
                          const char *network, const char *chain,
                          char **json_out);

/**
 * Convert binary transaction to JSON (direct conversion)
 *
 * @param tx_data - Complete transaction binary
 * @param tx_size - Transaction size
 * @param json_out - Output JSON string (caller must free)
 * @return 0 on success, -1 on error
 */
int cellframe_tx_binary_to_json(const uint8_t *tx_data, size_t tx_size, char **json_out);

/**
 * Build JSON transaction directly (without binary conversion)
 *
 * @param utxos - List of UTXOs to use as inputs
 * @param recipient_addr - Recipient address (base58)
 * @param amount - Amount to send (decimal string)
 * @param network_fee - Network fee amount (decimal string, can be NULL)
 * @param network_fee_addr - Network fee address (base58, can be NULL)
 * @param validator_fee - Validator fee (decimal string)
 * @param change_addr - Change address (base58, can be NULL)
 * @param change_amount - Change amount (decimal string, can be NULL)
 * @param token - Token ticker
 * @param json_out - Output JSON string (caller must free)
 * @return 0 on success, -1 on error
 */
int cellframe_build_json_tx(const cellframe_utxo_list_t *utxos,
                              const char *recipient_addr,
                              const char *amount,
                              const char *network_fee,
                              const char *network_fee_addr,
                              const char *validator_fee,
                              const char *change_addr,
                              const char *change_amount,
                              const char *token,
                              char **json_out);

/**
 * Build signed JSON transaction for RPC submission
 *
 * @param utxos - List of UTXOs to use as inputs
 * @param recipient_addr - Recipient address (base58)
 * @param amount - Amount to send (decimal string)
 * @param network_fee - Network fee amount (decimal string, can be NULL)
 * @param network_fee_addr - Network fee address (base58, can be NULL)
 * @param validator_fee - Validator fee (decimal string)
 * @param change_addr - Change address (base58, can be NULL)
 * @param change_amount - Change amount (decimal string, can be NULL)
 * @param token - Token ticker
 * @param pub_key - Dilithium public key for signing
 * @param pub_key_size - Public key size
 * @param priv_key - Dilithium private key for signing
 * @param priv_key_size - Private key size
 * @param json_out - Output signed JSON string (caller must free)
 * @return 0 on success, -1 on error
 */
int cellframe_build_signed_json_tx(const cellframe_utxo_list_t *utxos,
                                     const char *recipient_addr,
                                     const char *amount,
                                     const char *network_fee,
                                     const char *network_fee_addr,
                                     const char *validator_fee,
                                     const char *change_addr,
                                     const char *change_amount,
                                     const char *token,
                                     const uint8_t *pub_key, size_t pub_key_size,
                                     const uint8_t *priv_key, size_t priv_key_size,
                                     char **json_out);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_TX_H */
