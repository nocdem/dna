/*
 * cellframe_tx_builder_minimal.c - Minimal Transaction Builder Implementation
 *
 * Builds binary transactions matching Cellframe SDK format exactly.
 */

#include "cellframe_tx_builder_minimal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

// Initial capacity for transaction buffer
#define INITIAL_CAPACITY 4096

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/**
 * Ensure buffer has enough capacity
 */
static int ensure_capacity(cellframe_tx_builder_t *builder, size_t required) {
    if (builder->capacity >= required) {
        return 0;
    }

    size_t new_capacity = builder->capacity * 2;
    while (new_capacity < required) {
        new_capacity *= 2;
    }

    uint8_t *new_data = realloc(builder->data, new_capacity);
    if (!new_data) {
        return -1;
    }

    builder->data = new_data;
    builder->capacity = new_capacity;
    return 0;
}

/**
 * Append data to transaction
 */
static int append_data(cellframe_tx_builder_t *builder, const void *data, size_t size) {
    if (ensure_capacity(builder, builder->size + size) != 0) {
        return -1;
    }

    memcpy(builder->data + builder->size, data, size);
    builder->size += size;
    return 0;
}

/**
 * Calculate padding needed to align offset to boundary
 */
static size_t calc_padding(size_t offset, size_t alignment) {
    size_t remainder = offset % alignment;
    if (remainder == 0) {
        return 0;
    }
    return alignment - remainder;
}

/**
 * Add padding bytes to transaction
 */
static int append_padding(cellframe_tx_builder_t *builder, size_t padding) {
    if (padding == 0) {
        return 0;
    }

    uint8_t zeros[16] = {0};
    if (padding > sizeof(zeros)) {
        return -1;  // Too much padding requested
    }

    return append_data(builder, zeros, padding);
}

// ============================================================================
// PUBLIC API
// ============================================================================

cellframe_tx_builder_t* cellframe_tx_builder_new(void) {
    cellframe_tx_builder_t *builder = calloc(1, sizeof(cellframe_tx_builder_t));
    if (!builder) {
        return NULL;
    }

    builder->data = malloc(INITIAL_CAPACITY);
    if (!builder->data) {
        free(builder);
        return NULL;
    }

    builder->capacity = INITIAL_CAPACITY;
    builder->size = 0;
    builder->timestamp = (uint64_t)time(NULL);

    // Write header (will be updated when finalizing)
    cellframe_tx_header_t header = {
        .ts_created = builder->timestamp,
        .tx_items_size = 0  // CRITICAL: Must be 0 when signing!
    };

    if (append_data(builder, &header, sizeof(header)) != 0) {
        cellframe_tx_builder_free(builder);
        return NULL;
    }

    return builder;
}

void cellframe_tx_builder_free(cellframe_tx_builder_t *builder) {
    if (!builder) {
        return;
    }

    if (builder->data) {
        // Securely zero transaction data before freeing
        memset(builder->data, 0, builder->capacity);
        free(builder->data);
    }

    free(builder);
}

int cellframe_tx_set_timestamp(cellframe_tx_builder_t *builder, uint64_t timestamp) {
    if (!builder || builder->size < sizeof(cellframe_tx_header_t)) {
        return -1;
    }

    builder->timestamp = timestamp;

    // Update timestamp in header
    cellframe_tx_header_t *header = (cellframe_tx_header_t*)builder->data;
    header->ts_created = timestamp;

    return 0;
}

int cellframe_tx_add_in(cellframe_tx_builder_t *builder,
                        const cellframe_hash_t *prev_hash,
                        uint32_t prev_idx) {
    if (!builder || !prev_hash) {
        return -1;
    }

    // Write fields manually with dynamic alignment
    uint8_t type = TX_ITEM_TYPE_IN;

    // 1. Write type (1 byte)
    if (append_data(builder, &type, 1) != 0) {
        return -1;
    }

    // 2. Write prev_hash (32 bytes)
    if (append_data(builder, prev_hash, sizeof(cellframe_hash_t)) != 0) {
        return -1;
    }

    // 3. Add padding for tx_out_prev_idx (needs 4-byte alignment)
    size_t padding = calc_padding(builder->size, 4);
    if (append_padding(builder, padding) != 0) {
        return -1;
    }

    // 4. Write tx_out_prev_idx (4 bytes)
    return append_data(builder, &prev_idx, sizeof(uint32_t));
}

int cellframe_tx_add_out(cellframe_tx_builder_t *builder,
                         const cellframe_addr_t *addr,
                         uint256_t value) {
    if (!builder || !addr) {
        return -1;
    }

    cellframe_tx_out_t item = {
        .header = {
            .type = TX_ITEM_TYPE_OUT,  // 0x12 - CRITICAL!
            .value = value
        }
    };

    memcpy(&item.addr, addr, sizeof(cellframe_addr_t));

    return append_data(builder, &item, sizeof(item));
}

int cellframe_tx_add_fee(cellframe_tx_builder_t *builder, uint256_t value) {
    if (!builder) {
        return -1;
    }

    cellframe_tx_out_cond_t item;
    memset(&item, 0, sizeof(item));

    item.item_type = TX_ITEM_TYPE_OUT_COND;  // 0x61
    item.subtype = TX_OUT_COND_SUBTYPE_FEE;  // 0x04
    item.value = value;
    item.ts_expires = 0;  // Never expires
    item.srv_uid = 0;     // No service
    item.tsd_size = 0;    // No TSD data

    return append_data(builder, &item, sizeof(item));
}

int cellframe_tx_add_tsd(cellframe_tx_builder_t *builder, uint16_t tsd_type,
                         const uint8_t *data, size_t data_size) {
    if (!builder || !data || data_size == 0) {
        return -1;
    }

    // Calculate sizes
    // Inner TSD: 6 bytes (type + size) + data
    size_t tsd_content_size = sizeof(cellframe_tsd_t) + data_size;

    // Full item: 16 bytes (tx item header) + tsd content
    size_t item_size = sizeof(cellframe_tx_tsd_t) + tsd_content_size;

    // Allocate TSD item
    uint8_t *tsd_item = malloc(item_size);
    if (!tsd_item) {
        return -1;
    }
    memset(tsd_item, 0, item_size);

    // Build transaction item header
    cellframe_tx_tsd_t *tx_tsd = (cellframe_tx_tsd_t*)tsd_item;
    tx_tsd->type = TX_ITEM_TYPE_TSD;
    tx_tsd->size = tsd_content_size;

    // Build inner TSD structure
    cellframe_tsd_t *tsd = (cellframe_tsd_t*)tx_tsd->tsd;
    tsd->type = tsd_type;
    tsd->size = (uint32_t)data_size;
    memcpy(tsd->data, data, data_size);

    // Append to transaction
    int result = append_data(builder, tsd_item, item_size);
    free(tsd_item);

    return result;
}

const uint8_t* cellframe_tx_get_signing_data(cellframe_tx_builder_t *builder, size_t *size_out) {
    if (!builder || !size_out || builder->size < sizeof(cellframe_tx_header_t)) {
        return NULL;
    }

    // CRITICAL: Create a COPY and set tx_items_size to ZERO in the copy!
    // Source: dap_chain_datum_tx_items.c:482-486
    // "dap_chain_datum_tx_t *l_tx = DAP_DUP_SIZE(...);"
    // "l_tx->header.tx_items_size = 0;"
    // "dap_sign_t *ret = dap_sign_create(a_key, l_tx, l_tx_size);"
    // "DAP_DELETE(l_tx);"

    // Create temporary copy
    uint8_t *temp_copy = malloc(builder->size);
    if (!temp_copy) {
        return NULL;
    }

    memcpy(temp_copy, builder->data, builder->size);

    // Set tx_items_size to ZERO in the copy
    cellframe_tx_header_t *header = (cellframe_tx_header_t*)temp_copy;
    header->tx_items_size = 0;

    *size_out = builder->size;

    // IMPORTANT: Caller must free() the returned pointer!
    return temp_copy;
}

const uint8_t* cellframe_tx_get_data(cellframe_tx_builder_t *builder, size_t *size_out) {
    if (!builder || !size_out || builder->size < sizeof(cellframe_tx_header_t)) {
        return NULL;
    }

    // Update tx_items_size with actual size (excludes 12-byte header)
    cellframe_tx_header_t *header = (cellframe_tx_header_t*)builder->data;
    header->tx_items_size = (uint32_t)(builder->size - sizeof(cellframe_tx_header_t));

    *size_out = builder->size;
    return builder->data;
}

int cellframe_tx_add_signature(cellframe_tx_builder_t *builder,
                                const uint8_t *dap_sign,
                                size_t dap_sign_size) {
    if (!builder || !dap_sign || dap_sign_size == 0) {
        return -1;
    }

    // Add SIG item header
    cellframe_tx_sig_header_t sig_header = {
        .type = TX_ITEM_TYPE_SIG,  // 0x30
        .version = 1,
        .sig_size = (uint32_t)dap_sign_size
    };

    if (append_data(builder, &sig_header, sizeof(sig_header)) != 0) {
        return -1;
    }

    // Add dap_sign_t structure
    return append_data(builder, dap_sign, dap_sign_size);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

int cellframe_uint256_from_str(const char *value_str, uint256_t *value_out) {
    if (!value_str || !value_out) {
        return -1;
    }

    uint64_t datoshi;

    // Handle decimal strings (e.g., "0.01")
    const char *dot = strchr(value_str, '.');
    if (dot != NULL) {
        // Parse decimal CELL amount WITHOUT floating point to avoid precision loss
        // 1 CELL = 10^18 datoshi

        // Extract integer part
        char int_part[32] = {0};
        size_t int_len = dot - value_str;
        if (int_len >= sizeof(int_part)) {
            return -1;
        }
        strncpy(int_part, value_str, int_len);

        // Extract fractional part (max 18 digits for datoshi precision)
        char frac_part[32] = {0};
        const char *frac_start = dot + 1;
        size_t frac_len = strlen(frac_start);
        if (frac_len > 18) {
            frac_len = 18;  // Truncate to 18 decimal places
        }
        strncpy(frac_part, frac_start, frac_len);

        // Pad fractional part to 18 digits with zeros
        while (strlen(frac_part) < 18) {
            strcat(frac_part, "0");
        }

        // Parse integer and fractional parts
        uint64_t int_value = strtoull(int_part, NULL, 10);
        uint64_t frac_value = strtoull(frac_part, NULL, 10);

        // Calculate total datoshi: (int_value * 10^18) + frac_value
        // Check for overflow
        if (int_value > 18) {  // Max ~18 CELL fits in uint64_t
            fprintf(stderr, "[ERROR] Amount too large: %s CELL (max ~18 CELL)\n", value_str);
            return -1;
        }

        datoshi = (int_value * 1000000000000000000ULL) + frac_value;

        printf("[DEBUG cellframe_uint256_from_str] Input: '%s' -> int:%lu frac:%lu -> datoshi: %lu (0x%lx)\n",
               value_str, int_value, frac_value, datoshi, datoshi);
    } else {
        // Parse as integer datoshi string
        datoshi = strtoull(value_str, NULL, 10);
        if (datoshi == 0 && errno == EINVAL) {
            return -1;
        }
        printf("[DEBUG cellframe_uint256_from_str] Input: '%s' -> datoshi: %lu (0x%lx)\n",
               value_str, datoshi, datoshi);
    }

    // Construct uint256_t using SDK method
    // Binary layout: bytes 0-15 = 0, bytes 16-23 = datoshi, bytes 24-31 = 0
    *value_out = GET_256_FROM_64(datoshi);

    printf("[DEBUG cellframe_uint256_from_str] After GET_256_FROM_64:\n");
    printf("  _hi.a = %lu (0x%lx)\n", value_out->_hi.a, value_out->_hi.a);
    printf("  _hi.b = %lu (0x%lx)\n", value_out->_hi.b, value_out->_hi.b);
    printf("  _lo.a = %lu (0x%lx)\n", value_out->_lo.a, value_out->_lo.a);
    printf("  _lo.b = %lu (0x%lx)\n", value_out->_lo.b, value_out->_lo.b);
    printf("  lo.lo = %lu (0x%lx)\n", value_out->lo.lo, value_out->lo.lo);

    return 0;
}

int cellframe_hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size) {
    if (!hex || !bin || bin_size == 0) {
        return -1;
    }

    // Skip "0x" prefix if present
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return -1;  // Hex string must have even length
    }

    size_t required_size = hex_len / 2;
    if (required_size > bin_size) {
        return -1;  // Output buffer too small
    }

    for (size_t i = 0; i < required_size; i++) {
        char high = hex[i * 2];
        char low = hex[i * 2 + 1];

        if (!isxdigit(high) || !isxdigit(low)) {
            return -1;  // Invalid hex character
        }

        int high_val = (high >= 'a') ? (high - 'a' + 10) :
                       (high >= 'A') ? (high - 'A' + 10) : (high - '0');
        int low_val = (low >= 'a') ? (low - 'a' + 10) :
                      (low >= 'A') ? (low - 'A' + 10) : (low - '0');

        bin[i] = (uint8_t)((high_val << 4) | low_val);
    }

    return (int)required_size;
}
