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

// Static assert compatibility for C/C++
#ifndef __cplusplus
    // C mode
    #define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
    // C++ mode
    #define STATIC_ASSERT(cond, msg) static_assert(cond, msg)
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
#define TX_ITEM_TYPE_TSD        0x80  // Type-Specific Data (custom data)
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
STATIC_ASSERT(sizeof(cellframe_addr_t) == 77, "cellframe_addr_t must be 77 bytes");

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

STATIC_ASSERT(sizeof(cellframe_tx_header_t) == 12, "cellframe_tx_header_t must be 12 bytes");

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

STATIC_ASSERT(sizeof(cellframe_tx_in_t) == 40, "cellframe_tx_in_t must be 40 bytes (1+32+3padding+4)");

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

STATIC_ASSERT(sizeof(cellframe_tx_out_t) == 110, "cellframe_tx_out_t must be 110 bytes");

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

STATIC_ASSERT(sizeof(cellframe_tx_out_ext_t) == 120, "cellframe_tx_out_ext_t must be 120 bytes");

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

STATIC_ASSERT(sizeof(cellframe_tx_out_cond_t) == 340, "cellframe_tx_out_cond_t must be 340 bytes");

// ============================================================================
// TSD (TYPE-SPECIFIC DATA) STRUCTURES
// ============================================================================

/**
 * TSD (Type-Specific Data) - Custom data in transactions
 * SDK: dap_tsd_t (dap-sdk/core/include/dap_tsd.h)
 *
 * Base TSD structure (inner content)
 * Size: 6 bytes + data_size
 */
typedef struct {
    uint16_t type;      // TSD type (e.g., 0xf003 for custom string)
    uint32_t size;      // Data size in bytes
    uint8_t data[];     // Variable-length data
} __attribute__((packed)) cellframe_tsd_t;

STATIC_ASSERT(sizeof(cellframe_tsd_t) == 6, "cellframe_tsd_t header must be 6 bytes");

/**
 * TSD transaction item (outer wrapper)
 * SDK: dap_chain_tx_tsd_t (cellframe-sdk/modules/common/include/dap_chain_datum_tx_tsd.h)
 *
 * Size: 16 bytes + tsd_content_size
 *
 * Full item size = sizeof(cellframe_tx_tsd_t) + size
 *                = 16 + (6 + data_size)
 */
typedef struct {
    uint8_t type;       // TX_ITEM_TYPE_TSD (0x80)
    uint64_t size __attribute__((aligned(8)));  // Size of tsd[] content (6 + data_size)
    uint8_t tsd[];      // Contains cellframe_tsd_t + data
} __attribute__((packed)) cellframe_tx_tsd_t;

STATIC_ASSERT(sizeof(cellframe_tx_tsd_t) == 16, "cellframe_tx_tsd_t header must be 16 bytes");

// TSD type constants
// NOTE: 0xf003 is for OUT_COND embedded TSD, not standalone items!
// Using 0x01 for generic text/comment (like voting questions)
#define TSD_TYPE_CUSTOM_STRING 0x0001  // Custom string/comment data

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

STATIC_ASSERT(sizeof(cellframe_tx_sig_header_t) == 6, "cellframe_tx_sig_header_t must be 6 bytes");

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

STATIC_ASSERT(sizeof(dap_sign_t) == 14, "dap_sign_t header must be 14 bytes");

// ============================================================================
// HELPER CONSTANTS AND FUNCTIONS
// ============================================================================

/**
 * Construct uint128_t from uint64_t
 * SDK: GET_128_FROM_64 (dap_math_ops.h:117)
 */
static inline uint128_t GET_128_FROM_64(uint64_t n) {
    uint128_t result;
    result.lo = n;
    result.hi = 0;
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
 *
 * NOTE: Uses _hi/_lo named members for C++ compatibility (avoids designated initializers)
 */
static inline uint256_t GET_256_FROM_64(uint64_t n) {
    uint256_t result;
    result.hi.lo = 0;  // bytes 0-7
    result.hi.hi = 0;  // bytes 8-15
    result.lo.lo = n;  // bytes 16-23 (VALUE GOES HERE)
    result.lo.hi = 0;  // bytes 24-31
    return result;
}

// ============================================================================
// 256-BIT MATH OPERATIONS (Ported from Cellframe SDK dap_math_ops.h)
// ============================================================================

/**
 * Zero constants
 */
static const uint128_t uint128_0 = {{ .lo = 0, .hi = 0 }};
static const uint256_t uint256_0 = {{{ .hi = {{ .lo = 0, .hi = 0 }}, .lo = {{ .lo = 0, .hi = 0 }} }}};
static const uint256_t uint256_1 = {{{ .hi = {{ .lo = 0, .hi = 0 }}, .lo = {{ .lo = 1, .hi = 0 }} }}};

/**
 * Compare two uint128_t values
 * Returns: 1 if a > b, 0 if a == b, -1 if a < b
 */
static inline int compare128(uint128_t a, uint128_t b) {
    return (((a.hi > b.hi) || ((a.hi == b.hi) && (a.lo > b.lo))) ? 1 : 0)
         - (((a.hi < b.hi) || ((a.hi == b.hi) && (a.lo < b.lo))) ? 1 : 0);
}

/**
 * Check if uint128_t equals zero
 */
static inline int EQUAL_128(uint128_t a, uint128_t b) {
    return a.lo == b.lo && a.hi == b.hi;
}

static inline int IS_ZERO_128(uint128_t a) {
    return EQUAL_128(a, uint128_0);
}

/**
 * Check if uint256_t equals zero
 */
static inline int EQUAL_256(uint256_t a, uint256_t b) {
    return a.lo.lo == b.lo.lo && a.lo.hi == b.lo.hi &&
           a.hi.lo == b.hi.lo && a.hi.hi == b.hi.hi;
}

static inline int IS_ZERO_256(uint256_t a) {
    return EQUAL_256(a, uint256_0);
}

/**
 * Compare two uint256_t values
 * Returns: 1 if a > b, 0 if a == b, -1 if a < b
 */
static inline int compare256(uint256_t a, uint256_t b) {
    return ((compare128(a.hi, b.hi) == 1 || (compare128(a.hi, b.hi) == 0 && compare128(a.lo, b.lo) == 1)) ? 1 : 0)
         - ((compare128(a.hi, b.hi) == -1 || (compare128(a.hi, b.hi) == 0 && compare128(a.lo, b.lo) == -1)) ? 1 : 0);
}

/**
 * OR two uint128_t values
 */
static inline uint128_t OR_128(uint128_t a, uint128_t b) {
    uint128_t result;
    result.hi = a.hi | b.hi;
    result.lo = a.lo | b.lo;
    return result;
}

/**
 * OR two uint256_t values
 */
static inline uint256_t OR_256(uint256_t a, uint256_t b) {
    uint256_t result;
    result.hi = OR_128(a.hi, b.hi);
    result.lo = OR_128(a.lo, b.lo);
    return result;
}

/**
 * Left shift uint128_t by n bits
 */
static inline void LEFT_SHIFT_128(uint128_t a, uint128_t* b, int n) {
    if (n >= 64) {
        a.hi = a.lo;
        a.lo = 0;
        LEFT_SHIFT_128(a, b, n - 64);
    } else if (n == 0) {
        b->hi = a.hi;
        b->lo = a.lo;
    } else {
        b->lo = a.lo << n;
        b->hi = (a.hi << n) | (a.lo >> (64 - n));
    }
}

/**
 * Right shift uint128_t by n bits
 */
static inline void RIGHT_SHIFT_128(uint128_t a, uint128_t* b, int n) {
    if (n >= 64) {
        a.lo = a.hi;
        a.hi = 0;
        RIGHT_SHIFT_128(a, b, n - 64);
    } else if (n == 0) {
        b->hi = a.hi;
        b->lo = a.lo;
    } else {
        b->hi = a.hi >> n;
        b->lo = (a.lo >> n) | (a.hi << (64 - n));
    }
}

/**
 * Left shift uint256_t by n bits
 */
static inline void LEFT_SHIFT_256(uint256_t a, uint256_t* b, int n) {
    if (n >= 128) {
        a.hi = a.lo;
        a.lo = uint128_0;
        LEFT_SHIFT_256(a, b, n - 128);
    } else if (n == 0) {
        b->hi = a.hi;
        b->lo = a.lo;
    } else if (n < 128) {
        uint128_t shift_temp = uint128_0;
        LEFT_SHIFT_128(a.lo, &shift_temp, n);
        b->lo = shift_temp;
        uint128_t shift_temp_or_left = uint128_0;
        uint128_t shift_temp_or_right = uint128_0;
        LEFT_SHIFT_128(a.hi, &shift_temp_or_left, n);
        RIGHT_SHIFT_128(a.lo, &shift_temp_or_right, 128 - n);
        b->hi = OR_128(shift_temp_or_left, shift_temp_or_right);
    }
}

/**
 * Right shift uint256_t by n bits
 */
static inline void RIGHT_SHIFT_256(uint256_t a, uint256_t* b, int n) {
    if (n >= 128) {
        a.lo = a.hi;
        a.hi = uint128_0;
        RIGHT_SHIFT_256(a, b, n - 128);
    } else if (n == 0) {
        b->hi = a.hi;
        b->lo = a.lo;
    } else if (n < 128) {
        uint128_t shift_temp = uint128_0;
        RIGHT_SHIFT_128(a.hi, &shift_temp, n);
        b->hi = shift_temp;
        uint128_t shift_temp_or_left = uint128_0;
        uint128_t shift_temp_or_right = uint128_0;
        RIGHT_SHIFT_128(a.lo, &shift_temp_or_left, n);
        LEFT_SHIFT_128(a.hi, &shift_temp_or_right, 128 - n);
        b->lo = OR_128(shift_temp_or_left, shift_temp_or_right);
    }
}

/**
 * Sum two uint64_t values, returns overflow flag
 */
static inline int SUM_64_64(uint64_t a, uint64_t b, uint64_t* c) {
    *c = a + b;
    return (int)(*c < a);
}

/**
 * Sum two uint128_t values, returns overflow flag
 */
static inline int SUM_128_128(uint128_t a, uint128_t b, uint128_t* c) {
    int overflow_flag = 0;
    int overflow_flag_intermediate;
    uint64_t temp = 0;
    overflow_flag = SUM_64_64(a.lo, b.lo, &temp);
    c->lo = temp;
    uint64_t carry_in_64 = overflow_flag;
    uint64_t intermediate_value = 0;
    overflow_flag = 0;
    overflow_flag = SUM_64_64(carry_in_64, a.hi, &intermediate_value);
    overflow_flag_intermediate = SUM_64_64(intermediate_value, b.hi, &temp);
    c->hi = temp;
    return overflow_flag | overflow_flag_intermediate;
}

/**
 * Sum two uint256_t values, returns overflow flag
 * SDK: SUM_256_256 (dap_math_ops.h:460-490)
 */
static inline int SUM_256_256(uint256_t a, uint256_t b, uint256_t* c) {
    int overflow_flag = 0;
    uint128_t intermediate_value = uint128_0;
    uint256_t tmp = uint256_0;
    overflow_flag = SUM_128_128(a.lo, b.lo, &tmp.lo);
    uint128_t carry_in_128;
    carry_in_128.hi = 0;
    carry_in_128.lo = overflow_flag;
    overflow_flag = 0;
    overflow_flag = SUM_128_128(carry_in_128, a.hi, &intermediate_value);
    int overflow_flag_bis = 0;
    overflow_flag_bis = SUM_128_128(intermediate_value, b.hi, &tmp.hi);
    c->hi = tmp.hi;
    c->lo = tmp.lo;
    overflow_flag |= overflow_flag_bis;
    return overflow_flag;
}

/**
 * Subtract uint256_t b from a, result in c (c = a - b)
 * Returns 1 if underflow (b > a), 0 otherwise
 * SDK: SUBTRACT_256_256 (dap_math_ops.h)
 */
static inline int SUBTRACT_256_256(uint256_t a, uint256_t b, uint256_t* c) {
    uint256_t result = uint256_0;
    int borrow = 0;

    // Subtract lo.lo
    if (a.lo.lo >= b.lo.lo) {
        result.lo.lo = a.lo.lo - b.lo.lo;
    } else {
        result.lo.lo = (UINT64_MAX - b.lo.lo) + a.lo.lo + 1;
        borrow = 1;
    }

    // Subtract lo.hi with borrow
    uint64_t b_lo_hi = b.lo.hi + borrow;
    borrow = (b_lo_hi < b.lo.hi) ? 1 : 0;  // Check if adding borrow overflowed
    if (a.lo.hi >= b_lo_hi) {
        result.lo.hi = a.lo.hi - b_lo_hi;
    } else {
        result.lo.hi = (UINT64_MAX - b_lo_hi) + a.lo.hi + 1;
        borrow = 1;
    }

    // Subtract hi.lo with borrow
    uint64_t b_hi_lo = b.hi.lo + borrow;
    borrow = (b_hi_lo < b.hi.lo) ? 1 : 0;
    if (a.hi.lo >= b_hi_lo) {
        result.hi.lo = a.hi.lo - b_hi_lo;
    } else {
        result.hi.lo = (UINT64_MAX - b_hi_lo) + a.hi.lo + 1;
        borrow = 1;
    }

    // Subtract hi.hi with borrow
    uint64_t b_hi_hi = b.hi.hi + borrow;
    borrow = (b_hi_hi < b.hi.hi) ? 1 : 0;
    if (a.hi.hi >= b_hi_hi) {
        result.hi.hi = a.hi.hi - b_hi_hi;
    } else {
        result.hi.hi = (UINT64_MAX - b_hi_hi) + a.hi.hi + 1;
        borrow = 1;
    }

    *c = result;
    return borrow;  // 1 if underflow (b > a)
}

/**
 * Multiply two uint64_t values to uint128_t result
 */
static inline void MULT_64_128(uint64_t a, uint64_t b, uint128_t* c) {
    uint64_t a_lo = (a & 0xffffffff);
    uint64_t b_lo = (b & 0xffffffff);
    uint64_t prod_lo = (a_lo * b_lo);
    uint64_t w3 = (prod_lo & 0xffffffff);
    uint64_t prod_lo_shift = (prod_lo >> 32);

    a >>= 32;
    prod_lo = (a * b_lo) + prod_lo_shift;
    prod_lo_shift = (prod_lo & 0xffffffff);
    uint64_t w1 = (prod_lo >> 32);

    b >>= 32;
    prod_lo = (a_lo * b) + prod_lo_shift;
    prod_lo_shift = (prod_lo >> 32);

    c->hi = (a * b) + w1 + prod_lo_shift;
    c->lo = (prod_lo << 32) + w3;
}

/**
 * Multiply two uint128_t values to uint256_t result
 */
static inline void MULT_128_256(uint128_t a, uint128_t b, uint256_t* c) {
    // Product of .hi terms - stored in .hi field of c
    MULT_64_128(a.hi, b.hi, &c->hi);

    // Product of .lo terms - stored in .lo field of c
    MULT_64_128(a.lo, b.lo, &c->lo);

    uint128_t cross_product_one = uint128_0;
    uint128_t cross_product_two = uint128_0;
    MULT_64_128(a.hi, b.lo, &cross_product_one);
    c->lo.hi += cross_product_one.lo;
    if (c->lo.hi < cross_product_one.lo) {
        c->hi.lo++;
        if (c->hi.lo == 0) c->hi.hi++;
    }
    c->hi.lo += cross_product_one.hi;
    if (c->hi.lo < cross_product_one.hi) {
        c->hi.hi++;
    }

    MULT_64_128(a.lo, b.hi, &cross_product_two);
    c->lo.hi += cross_product_two.lo;
    if (c->lo.hi < cross_product_two.lo) {
        c->hi.lo++;
        if (c->hi.lo == 0) c->hi.hi++;
    }
    c->hi.lo += cross_product_two.hi;
    if (c->hi.lo < cross_product_two.hi) {
        c->hi.hi++;
    }
}

/**
 * 512-bit type for multiplication overflow
 */
typedef struct {
    uint256_t hi;
    uint256_t lo;
} __attribute__((packed)) uint512_t;

static const uint512_t uint512_0 = { .hi = {{{ .hi = {{ .lo = 0, .hi = 0 }}, .lo = {{ .lo = 0, .hi = 0 }} }}},
                                     .lo = {{{ .hi = {{ .lo = 0, .hi = 0 }}, .lo = {{ .lo = 0, .hi = 0 }} }}} };

/**
 * Multiply two uint256_t values to uint512_t result
 */
static inline void MULT_256_512(uint256_t a, uint256_t b, uint512_t* c) {
    // Product of .hi terms
    MULT_128_256(a.hi, b.hi, &c->hi);
    // Product of .lo terms
    MULT_128_256(a.lo, b.lo, &c->lo);

    // Cross products
    uint256_t cross_product_first = uint256_0;
    uint256_t cross_product_second = uint256_0;
    uint256_t cross_product = uint256_0;
    uint256_t cross_product_shift = uint256_0;
    uint256_t temp_copy = uint256_0;

    MULT_128_256(a.hi, b.lo, &cross_product_first);
    MULT_128_256(a.lo, b.hi, &cross_product_second);
    SUM_256_256(cross_product_first, cross_product_second, &cross_product);

    LEFT_SHIFT_256(cross_product, &cross_product_shift, 128);
    temp_copy = c->lo;
    SUM_256_256(temp_copy, cross_product_shift, &c->lo);

    cross_product_shift.hi = uint128_0;
    cross_product_shift.lo = uint128_0;
    RIGHT_SHIFT_256(cross_product, &cross_product_shift, 128);
    temp_copy = c->hi;
    SUM_256_256(temp_copy, cross_product_shift, &c->hi);
}

/**
 * Multiply two uint256_t values, returns overflow flag
 * SDK: MULT_256_256 (dap_math_ops.h:693-705)
 */
static inline int MULT_256_256(uint256_t a, uint256_t b, uint256_t* c) {
    int overflow = 0;
    uint512_t full_product = uint512_0;
    MULT_256_512(a, b, &full_product);
    *c = full_product.lo;
    if (!EQUAL_256(full_product.hi, uint256_0)) {
        overflow = 1;
    }
    return overflow;
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
