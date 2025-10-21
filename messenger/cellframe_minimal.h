/*
 * cellframe_minimal.h - Minimal Cellframe Structures for Transaction Signing
 *
 * AUTHORITATIVE SOURCE: Cellframe SDK
 * Location: /opt/cpunk/cellframe-repos/cellframe-tool-sign/cellframe-sdk/
 *
 * All structures verified byte-for-byte against SDK source code.
 * See CELLFRAME_BINARY_FORMAT.md for detailed documentation.
 */

#ifndef CELLFRAME_MINIMAL_H
#define CELLFRAME_MINIMAL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// FUNDAMENTAL CONSTANTS
// ============================================================================

#define CELLFRAME_HASH_SIZE 32
#define CELLFRAME_NET_ID_SIZE 8
#define CELLFRAME_TICKER_SIZE_MAX 10

// Network IDs
#define CELLFRAME_NET_BACKBONE 0x0404202200000000ULL
#define CELLFRAME_NET_KELVPN  0x1807202300000000ULL

// Signature types
#define CELLFRAME_SIG_DILITHIUM 0x0102

// Transaction item types (from SDK dap_chain_common.h)
#define TX_ITEM_TYPE_IN         0x00
#define TX_ITEM_TYPE_OUT        0x12  // Current format (NO token field)
#define TX_ITEM_TYPE_OUT_EXT    0x11  // Has token field
#define TX_ITEM_TYPE_OUT_STD    0x13  // Has token + version + ts_unlock
#define TX_ITEM_TYPE_OUT_COND   0x61  // Conditional output (fees)
#define TX_ITEM_TYPE_SIG        0x30  // Signature

// OUT_COND subtypes
#define TX_OUT_COND_SUBTYPE_FEE 0x04

// ============================================================================
// FUNDAMENTAL TYPES (Matching SDK Exactly)
// ============================================================================

/**
 * 32-byte hash (SHA3-256)
 * SDK: dap_chain_hash_fast_t
 */
typedef struct {
    uint8_t raw[CELLFRAME_HASH_SIZE];
} __attribute__((packed)) cellframe_hash_t;

/**
 * 8-byte network identifier
 * SDK: dap_chain_net_id_t
 */
typedef union {
    uint64_t uint64;
    uint8_t raw[CELLFRAME_NET_ID_SIZE];
} __attribute__((packed)) cellframe_net_id_t;

/**
 * 4-byte signature type
 * SDK: dap_sign_type_t
 */
typedef union {
    uint32_t type;
    uint32_t raw;
} __attribute__((packed)) cellframe_sign_type_t;

/**
 * 128-bit unsigned integer
 * SDK: uint128_t (dap-sdk/core/include/dap_math_ops.h:31-35)
 */
typedef union {
    struct {
        uint64_t lo;  // bytes 0-7 within the uint128_t
        uint64_t hi;  // bytes 8-15 within the uint128_t
    } __attribute__((packed));
} __attribute__((packed)) uint128_t;

/**
 * 32-byte 256-bit unsigned integer
 * SDK: uint256_t (dap-sdk/core/include/dap_math_ops.h:54-85)
 *
 * Binary Layout (little-endian):
 * Bytes  0- 7: hi.lo
 * Bytes  8-15: hi.hi
 * Bytes 16-23: lo.lo ← Value goes here for amounts < 2^64
 * Bytes 24-31: lo.hi
 */
typedef struct {
    union {
        struct {
            uint128_t hi;  // bytes 0-15
            uint128_t lo;  // bytes 16-31
        } __attribute__((packed));
        struct {
            struct {
                uint64_t a;  // bytes 0-7
                uint64_t b;  // bytes 8-15
            } __attribute__((packed)) _hi;
            struct {
                uint64_t a;  // bytes 16-23
                uint64_t b;  // bytes 24-31
            } __attribute__((packed)) _lo;
        } __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed)) uint256_t;

// ============================================================================
// ADDRESS STRUCTURE (77 bytes)
// ============================================================================

/**
 * Cellframe address structure
 * SDK: dap_chain_addr_t (cellframe-sdk/modules/common/include/dap_chain_common.h:111)
 *
 * CRITICAL: This is 77 bytes, NOT 49 bytes!
 *
 * Byte Layout:
 * - addr_ver:  1 byte (offset 0)
 * - net_id:    8 bytes (offset 1)
 * - sig_type:  4 bytes (offset 9)
 * - data.hash: 32 bytes (offset 13)
 * - checksum:  32 bytes (offset 45)
 * Total: 77 bytes
 */
typedef struct {
    uint8_t addr_ver;              // Address version (0 for default)
    cellframe_net_id_t net_id;     // Network ID (e.g., 0x0404202200000000 for Backbone)
    cellframe_sign_type_t sig_type; // Signature type (0x0102 for Dilithium)
    union {
        uint8_t key[CELLFRAME_HASH_SIZE];  // Public key hash
        uint8_t hash[CELLFRAME_HASH_SIZE];
        cellframe_hash_t hash_fast;
    } __attribute__((packed)) data;
    cellframe_hash_t checksum;     // SHA3-256 of first 45 bytes
} __attribute__((packed)) cellframe_addr_t;

// Size verification at compile time
_Static_assert(sizeof(cellframe_addr_t) == 77, "cellframe_addr_t must be 77 bytes");

// ============================================================================
// TRANSACTION HEADER
// ============================================================================

/**
 * Transaction header
 * SDK: dap_chain_datum_tx_t.header
 *
 * Size: 12 bytes (8 + 4)
 *
 * CRITICAL: When signing, tx_items_size MUST be 0!
 * After signing, it contains the actual size of all items.
 */
typedef struct {
    uint64_t ts_created;     // Timestamp (Unix time, seconds)
    uint32_t tx_items_size;  // Total size of all items (0 when signing!)
} __attribute__((packed)) cellframe_tx_header_t;

_Static_assert(sizeof(cellframe_tx_header_t) == 12, "cellframe_tx_header_t must be 12 bytes");

// ============================================================================
// TRANSACTION ITEMS
// ============================================================================

/**
 * IN item - References a previous transaction output
 * SDK: dap_chain_tx_in_t
 *
 * Size: 37 bytes (1 + 32 + 4)
 */
typedef struct {
    uint8_t type;                    // TX_ITEM_TYPE_IN (0x00)
    cellframe_hash_t tx_prev_hash;   // Previous transaction hash
    uint32_t tx_out_prev_idx __attribute__((aligned(4)));  // Previous output index (4-byte aligned)
} __attribute__((packed)) cellframe_tx_in_t;

_Static_assert(sizeof(cellframe_tx_in_t) == 40, "cellframe_tx_in_t must be 40 bytes (1+32+3padding+4)");

/**
 * OUT item - Current format (type 0x12)
 * SDK: dap_chain_tx_out_t
 *
 * Size: 110 bytes (1 + 32 + 77)
 *
 * CRITICAL: This is what RPC expects for {"type":"out"} in JSON!
 * NO token field, NO version field, NO ts_unlock field.
 */
typedef struct {
    struct {
        uint8_t type;        // TX_ITEM_TYPE_OUT (0x12)
        uint256_t value;     // Amount in datoshi
    } __attribute__((packed)) header;
    cellframe_addr_t addr;   // Recipient address (77 bytes)
} __attribute__((packed)) cellframe_tx_out_t;

_Static_assert(sizeof(cellframe_tx_out_t) == 110, "cellframe_tx_out_t must be 110 bytes");

/**
 * OUT_EXT item - Has token field (type 0x11)
 * SDK: dap_chain_tx_out_ext_t
 *
 * Size: 120 bytes (1 + 32 + 77 + 10)
 *
 * Used when {"type":"out_ext"} in JSON (rare, mostly deprecated).
 */
typedef struct {
    struct {
        uint8_t type;        // TX_ITEM_TYPE_OUT_EXT (0x11)
        uint256_t value;     // Amount in datoshi
    } __attribute__((packed)) header;
    cellframe_addr_t addr;   // Recipient address
    char token[CELLFRAME_TICKER_SIZE_MAX]; // Token ticker
} __attribute__((packed)) cellframe_tx_out_ext_t;

_Static_assert(sizeof(cellframe_tx_out_ext_t) == 120, "cellframe_tx_out_ext_t must be 120 bytes");

/**
 * OUT_COND item - Conditional output (type 0x61)
 * SDK: dap_chain_tx_out_cond_t
 *
 * Size: 340 bytes
 *
 * Used for fees: {"type":"out_cond", "subtype":"fee", ...}
 */
typedef struct {
    uint8_t item_type;      // TX_ITEM_TYPE_OUT_COND (0x61)
    uint8_t subtype;        // TX_OUT_COND_SUBTYPE_FEE (0x04)
    uint256_t value;        // Fee amount
    uint8_t padding[6];     // Padding
    uint64_t ts_expires;    // Expiration timestamp (0 = never)
    uint64_t srv_uid;       // Service UID (0 for fee)
    uint8_t padding2[8];    // More padding
    uint8_t free_space[272]; // Union space (empty for fee)
    uint32_t tsd_size;      // TSD data size (0 for fee)
} __attribute__((packed)) cellframe_tx_out_cond_t;

_Static_assert(sizeof(cellframe_tx_out_cond_t) == 340, "cellframe_tx_out_cond_t must be 340 bytes");

// ============================================================================
// SIGNATURE STRUCTURES
// ============================================================================

/**
 * SIG item header
 * SDK: dap_chain_tx_sig_t
 *
 * Size: 6 bytes (1 + 1 + 4)
 *
 * Followed by dap_sign_t structure.
 */
typedef struct {
    uint8_t type;       // TX_ITEM_TYPE_SIG (0x30)
    uint8_t version;    // Version (1)
    uint32_t sig_size;  // Size of following dap_sign_t structure
} __attribute__((packed)) cellframe_tx_sig_header_t;

_Static_assert(sizeof(cellframe_tx_sig_header_t) == 6, "cellframe_tx_sig_header_t must be 6 bytes");

/**
 * dap_sign_t structure (Dilithium)
 * SDK: dap_sign_t (cellframe-sdk/dap-sdk/crypto/include/dap_sign.h)
 *
 * Total Size (Dilithium MODE_1): 3306 bytes
 * - Header: 14 bytes
 * - Public key (serialized): 1196 bytes (12-byte header + 1184-byte key)
 * - Signature (serialized): 2096 bytes (20-byte wrapper + 2076-byte ATTACHED sig)
 *
 * Layout:
 * [14-byte header][1196-byte pubkey][2096-byte signature]
 *
 * This ENTIRE structure is Base64-encoded for "sig_b64" field in JSON.
 */
typedef struct {
    struct {
        uint32_t type;           // SIG_TYPE_DILITHIUM (0x0102)
        uint8_t hash_type;       // 0x01 for SHA3-256
        uint8_t padding;         // 0x00
        uint32_t sign_size;      // Signature size (2096 for Dilithium MODE_1)
        uint32_t sign_pkey_size; // Public key size (1196 for Dilithium MODE_1)
    } __attribute__((packed)) header;  // 14 bytes
    uint8_t pkey_n_sign[];      // [public_key][signature]
} __attribute__((packed)) dap_sign_t;

_Static_assert(sizeof(dap_sign_t) == 14, "dap_sign_t header must be 14 bytes");

// ============================================================================
// HELPER CONSTANTS AND FUNCTIONS
// ============================================================================

/**
 * Zero uint128_t constant
 */
static const uint128_t uint128_0 = {{ .lo = 0, .hi = 0 }};

/**
 * Construct uint128_t from uint64_t
 * SDK: GET_128_FROM_64 (dap_math_ops.h:117)
 */
static inline uint128_t GET_128_FROM_64(uint64_t n) {
    uint128_t result = {{ .lo = n, .hi = 0 }};
    return result;
}

/**
 * Construct uint256_t from uint64_t
 * SDK: GET_256_FROM_64 (dap_math_ops.h:129-130)
 *
 * Binary layout:
 * Bytes  0-15: all zeros (hi)
 * Bytes 16-23: value (lo.lo)
 * Bytes 24-31: all zeros (lo.hi)
 */
static inline uint256_t GET_256_FROM_64(uint64_t n) {
    uint256_t result;
    result.hi = uint128_0;
    result.lo = GET_128_FROM_64(n);
    return result;
}

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * Convert CELL to datoshi
 * 1 CELL = 10^18 datoshi
 */
#define CELL_TO_DATOSHI(cell) ((uint64_t)((cell) * 1000000000000000000ULL))

/**
 * Convert datoshi to CELL (lossy)
 */
#define DATOSHI_TO_CELL(datoshi) ((double)(datoshi) / 1000000000000000000.0)

// ============================================================================
// SIZE REFERENCE TABLE
// ============================================================================

/*
 * Structure Size Reference (bytes):
 *
 * cellframe_hash_t             32
 * cellframe_net_id_t            8
 * cellframe_sign_type_t         4
 * uint256_t                    32
 * cellframe_addr_t             77  ✅ VERIFIED
 * cellframe_tx_header_t        12
 * cellframe_tx_in_t            37
 * cellframe_tx_out_t          110  ✅ VERIFIED (type 0x12)
 * cellframe_tx_out_ext_t      120  (type 0x11)
 * cellframe_tx_out_cond_t     340  (type 0x61)
 * cellframe_tx_sig_header_t     6
 * dap_sign_t (header)          14
 * dap_sign_t (Dilithium)     3306  (14 + 1196 + 2096)
 *
 * Complete SIG item:         3312  (6 + 3306)
 */

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_MINIMAL_H */
