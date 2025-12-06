/*
 * cellframe_tx_builder_minimal.c - Minimal Transaction Builder Implementation
 *
 * Builds binary transactions matching Cellframe SDK format exactly.
 */

#include "cellframe_tx_builder.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

// Initial capacity for transaction buffer
#define INITIAL_CAPACITY 4096

// ============================================================================
// DATOSHI CONSTANTS (from Cellframe SDK dap_math_convert.h)
// ============================================================================

#define DATOSHI_DEGREE 18      // 18 decimal places (1 CELL = 10^18 datoshi)
#define DATOSHI_POW256 78      // Max digits for uint256 decimal representation

/**
 * Pre-computed powers of 10 for 256-bit decimal parsing
 * SDK: c_pow10_double (dap_math_convert.c:5-178)
 *
 * Each entry is 10^i as a 256-bit value stored as 4 x uint64_t
 * Layout: {u64[0], u64[1], u64[2], u64[3]} where u64[3] is the lowest 64 bits
 *
 * Using non-__int128 format for portability (matches SDK #else branch)
 */
static const union {
    uint64_t u64[4];
    uint32_t u32[8];
} c_pow10_double[DATOSHI_POW256] = {
    {.u64 = {0, 0, 0, 1ULL}},                          // 0
    {.u64 = {0, 0, 0, 10ULL}},                         // 1
    {.u64 = {0, 0, 0, 100ULL}},                        // 2
    {.u64 = {0, 0, 0, 1000ULL}},                       // 3
    {.u64 = {0, 0, 0, 10000ULL}},                      // 4
    {.u64 = {0, 0, 0, 100000ULL}},                     // 5
    {.u64 = {0, 0, 0, 1000000ULL}},                    // 6
    {.u64 = {0, 0, 0, 10000000ULL}},                   // 7
    {.u64 = {0, 0, 0, 100000000ULL}},                  // 8
    {.u64 = {0, 0, 0, 1000000000ULL}},                 // 9
    {.u64 = {0, 0, 0, 10000000000ULL}},                // 10
    {.u64 = {0, 0, 0, 100000000000ULL}},               // 11
    {.u64 = {0, 0, 0, 1000000000000ULL}},              // 12
    {.u64 = {0, 0, 0, 10000000000000ULL}},             // 13
    {.u64 = {0, 0, 0, 100000000000000ULL}},            // 14
    {.u64 = {0, 0, 0, 1000000000000000ULL}},           // 15
    {.u64 = {0, 0, 0, 10000000000000000ULL}},          // 16
    {.u64 = {0, 0, 0, 100000000000000000ULL}},         // 17
    {.u64 = {0, 0, 0, 1000000000000000000ULL}},        // 18
    {.u64 = {0, 0, 0, 10000000000000000000ULL}},       // 19
    {.u64 = {0, 0, 5ULL, 7766279631452241920ULL}},                    // 20
    {.u64 = {0, 0, 54ULL, 3875820019684212736ULL}},                   // 21
    {.u64 = {0, 0, 542ULL, 1864712049423024128ULL}},                  // 22
    {.u64 = {0, 0, 5421ULL, 200376420520689664ULL}},                  // 23
    {.u64 = {0, 0, 54210ULL, 2003764205206896640ULL}},                // 24
    {.u64 = {0, 0, 542101ULL, 1590897978359414784ULL}},               // 25
    {.u64 = {0, 0, 5421010ULL, 15908979783594147840ULL}},             // 26
    {.u64 = {0, 0, 54210108ULL, 11515845246265065472ULL}},            // 27
    {.u64 = {0, 0, 542101086ULL, 4477988020393345024ULL}},            // 28
    {.u64 = {0, 0, 5421010862ULL, 7886392056514347008ULL}},           // 29
    {.u64 = {0, 0, 54210108624ULL, 5076944270305263616ULL}},          // 30
    {.u64 = {0, 0, 542101086242ULL, 13875954555633532928ULL}},        // 31
    {.u64 = {0, 0, 5421010862427ULL, 9632337040368467968ULL}},        // 32
    {.u64 = {0, 0, 54210108624275ULL, 4089650035136921600ULL}},       // 33
    {.u64 = {0, 0, 542101086242752ULL, 4003012203950112768ULL}},      // 34
    {.u64 = {0, 0, 5421010862427522ULL, 3136633892082024448ULL}},     // 35
    {.u64 = {0, 0, 54210108624275221ULL, 12919594847110692864ULL}},   // 36
    {.u64 = {0, 0, 542101086242752217ULL, 68739955140067328ULL}},     // 37
    {.u64 = {0, 0, 5421010862427522170ULL, 687399551400673280ULL}},   // 38
    {.u64 = {0, 2ULL, 17316620476856118468ULL, 6873995514006732800ULL}},              // 39
    {.u64 = {0, 29ULL, 7145508105175220139ULL, 13399722918938673152ULL}},             // 40
    {.u64 = {0, 293ULL, 16114848830623546549ULL, 4870020673419870208ULL}},            // 41
    {.u64 = {0, 2938ULL, 13574535716559052564ULL, 11806718586779598848ULL}},          // 42
    {.u64 = {0, 29387ULL, 6618148649623664334ULL, 7386721425538678784ULL}},           // 43
    {.u64 = {0, 293873ULL, 10841254275107988496ULL, 80237960548581376ULL}},           // 44
    {.u64 = {0, 2938735ULL, 16178822382532126880ULL, 802379605485813760ULL}},         // 45
    {.u64 = {0, 29387358ULL, 14214271235644855872ULL, 8023796054858137600ULL}},       // 46
    {.u64 = {0, 293873587ULL, 13015503840481697412ULL, 6450984253743169536ULL}},      // 47
    {.u64 = {0, 2938735877ULL, 1027829888850112811ULL, 9169610316303040512ULL}},      // 48
    {.u64 = {0, 29387358770ULL, 10278298888501128114ULL, 17909126868192198656ULL}},   // 49
    {.u64 = {0, 293873587705ULL, 10549268516463523069ULL, 13070572018536022016ULL}},  // 50
    {.u64 = {0, 2938735877055ULL, 13258964796087472617ULL, 1578511669393358848ULL}},  // 51
    {.u64 = {0, 29387358770557ULL, 3462439444907864858ULL, 15785116693933588480ULL}}, // 52
    {.u64 = {0, 293873587705571ULL, 16177650375369096972ULL, 10277214349659471872ULL}},   // 53
    {.u64 = {0, 2938735877055718ULL, 14202551164014556797ULL, 10538423128046960640ULL}},  // 54
    {.u64 = {0, 29387358770557187ULL, 12898303124178706663ULL, 13150510911921848320ULL}}, // 55
    {.u64 = {0, 293873587705571876ULL, 18302566799529756941ULL, 2377900603251621888ULL}}, // 56
    {.u64 = {0, 2938735877055718769ULL, 17004971331911604867ULL, 5332261958806667264ULL}},// 57
    {.u64 = {1, 10940614696847636083ULL, 4029016655730084128ULL, 16429131440647569408ULL}},   // 58
    {.u64 = {15ULL, 17172426599928602752ULL, 3396678409881738056ULL, 16717361816799281152ULL}},   // 59
    {.u64 = {159ULL, 5703569335900062977ULL, 15520040025107828953ULL, 1152921504606846976ULL}},   // 60
    {.u64 = {1593ULL, 1695461137871974930ULL, 7626447661401876602ULL, 11529215046068469760ULL}},  // 61
    {.u64 = {15930ULL, 16954611378719749304ULL, 2477500319180559562ULL, 4611686018427387904ULL}}, // 62
    {.u64 = {159309ULL, 3525417123811528497ULL, 6328259118096044006ULL, 9223372036854775808ULL}}, // 63
    {.u64 = {1593091ULL, 16807427164405733357ULL, 7942358959831785217ULL, 0ULL}},                 // 64
    {.u64 = {15930919ULL, 2053574980671369030ULL, 5636613303479645706ULL, 0ULL}},                 // 65
    {.u64 = {159309191ULL, 2089005733004138687ULL, 1025900813667802212ULL, 0ULL}},                // 66
    {.u64 = {1593091911ULL, 2443313256331835254ULL, 10259008136678022120ULL, 0ULL}},              // 67
    {.u64 = {15930919111ULL, 5986388489608800929ULL, 10356360998232463120ULL, 0ULL}},             // 68
    {.u64 = {159309191113ULL, 4523652674959354447ULL, 11329889613776873120ULL, 0ULL}},            // 69
    {.u64 = {1593091911132ULL, 8343038602174441244ULL, 2618431695511421504ULL, 0ULL}},            // 70
    {.u64 = {15930919111324ULL, 9643409726906205977ULL, 7737572881404663424ULL, 0ULL}},           // 71
    {.u64 = {159309191113245ULL, 4200376900514301694ULL, 3588752519208427776ULL, 0ULL}},          // 72
    {.u64 = {1593091911132452ULL, 5110280857723913709ULL, 17440781118374726144ULL, 0ULL}},        // 73
    {.u64 = {15930919111324522ULL, 14209320429820033867ULL, 8387114520361296896ULL, 0ULL}},       // 74
    {.u64 = {159309191113245227ULL, 12965995782233477362ULL, 10084168908774762496ULL, 0ULL}},     // 75
    {.u64 = {1593091911132452277ULL, 532749306367912313ULL, 8607968719199866880ULL, 0ULL}},       // 76
    {.u64 = {15930919111324522770ULL, 5327493063679123134ULL, 12292710897160462336ULL, 0ULL}},    // 77
};

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

int cellframe_tx_add_out_ext(cellframe_tx_builder_t *builder,
                              const cellframe_addr_t *addr,
                              uint256_t value,
                              const char *token) {
    if (!builder || !addr || !token) {
        return -1;
    }

    cellframe_tx_out_ext_t item = {
        .header = {
            .type = TX_ITEM_TYPE_OUT_EXT,  // 0x11 - has token field
            .value = value
        }
    };

    memcpy(&item.addr, addr, sizeof(cellframe_addr_t));

    // Copy token ticker (max 10 chars, null-padded)
    memset(item.token, 0, CELLFRAME_TICKER_SIZE_MAX);
    strncpy(item.token, token, CELLFRAME_TICKER_SIZE_MAX - 1);

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

/**
 * Parse uninteger string (no decimal point) to uint256_t
 * SDK: dap_uint256_scan_uninteger (dap_math_convert.c:233-378)
 *
 * Uses pre-computed c_pow10_double table for proper 256-bit arithmetic.
 * Supports numbers up to 78 digits (full uint256_t range).
 */
int cellframe_uint256_scan_uninteger(const char *str, uint256_t *out) {
    if (!str || !out) {
        return -1;
    }

    uint256_t result = uint256_0;
    int len = (int)strlen(str);

    // Check length limit
    if (len > DATOSHI_POW256) {
        fprintf(stderr, "[ERROR] Too many digits in '%s' (%d > %d)\n", str, len, DATOSHI_POW256);
        return -1;
    }

    // Process each digit from right to left
    for (int i = 0; i < len; i++) {
        char c = str[len - i - 1];
        if (!isdigit(c)) {
            fprintf(stderr, "[ERROR] Non-digit character in amount: '%c'\n", c);
            return -1;
        }

        uint8_t digit = c - '0';
        if (digit == 0) {
            continue;  // Skip zeros for efficiency
        }

        // Build uint256_t from lookup table entry for 10^i
        // SDK uses 8x uint32_t in non-__int128 mode, we use 4x uint64_t
        uint256_t pow10_val;
        pow10_val.hi.hi = c_pow10_double[i].u64[0];
        pow10_val.hi.lo = c_pow10_double[i].u64[1];
        pow10_val.lo.hi = c_pow10_double[i].u64[2];
        pow10_val.lo.lo = c_pow10_double[i].u64[3];

        // Multiply pow10 by digit
        uint256_t term = uint256_0;
        uint256_t digit_256 = GET_256_FROM_64(digit);
        if (MULT_256_256(pow10_val, digit_256, &term)) {
            fprintf(stderr, "[ERROR] Overflow multiplying by digit %d at position %d\n", digit, i);
            return -1;
        }

        // Add to result
        if (SUM_256_256(result, term, &result)) {
            fprintf(stderr, "[ERROR] Overflow adding digit %d at position %d\n", digit, i);
            return -1;
        }
    }

    *out = result;
    return 0;
}

/**
 * Parse decimal string (with decimal point) to uint256_t datoshi
 * SDK: dap_uint256_scan_decimal (dap_math_convert.c:380-416)
 *
 * Converts "123.456" -> 123456000000000000000 datoshi (with 18 decimal places)
 * REQUIRES decimal point - returns error if not present.
 *
 * Full 256-bit support - no more ~18 CELL limit!
 */
int cellframe_uint256_from_str(const char *value_str, uint256_t *value_out) {
    if (!value_str || !value_out) {
        return -1;
    }

    int len = (int)strlen(value_str);

    // Check max length (78 digits + 1 decimal point)
    if (len > DATOSHI_POW256 + 1) {
        fprintf(stderr, "[ERROR] Amount string too long: '%s' (%d > %d)\n",
                value_str, len, DATOSHI_POW256 + 1);
        return -1;
    }

    // Make local copy for manipulation
    char buf[DATOSHI_POW256 + 8];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, value_str, len);

    // Find decimal point
    char *point = strchr(buf, '.');
    if (!point) {
        // SDK requires decimal point - treat integer as CELL amount
        // Append ".0" to make "3000" -> "3000.0"
        fprintf(stderr, "[INFO] No decimal point in '%s', treating as CELL amount\n", value_str);
        buf[len] = '.';
        buf[len + 1] = '0';
        len += 2;
        point = &buf[len - 2];
    }

    // Calculate position of decimal point and digits after it
    int point_pos = (int)(point - buf);
    int frac_len = len - point_pos - 1;

    // Check precision
    if (frac_len > DATOSHI_DEGREE) {
        fprintf(stderr, "[ERROR] Too much precision in '%s' (%d > %d decimals)\n",
                value_str, frac_len, DATOSHI_DEGREE);
        return -1;
    }

    // Remove decimal point: "123.456" -> "123456"
    memmove(point, point + 1, frac_len + 1);  // +1 for null terminator
    len--;

    // Pad with trailing zeros to reach 18 decimal places
    // "123456" -> "123456000000000000000" (if frac_len was 3)
    int zeros_to_add = DATOSHI_DEGREE - frac_len;
    for (int i = 0; i < zeros_to_add; i++) {
        buf[len + i] = '0';
    }
    buf[len + zeros_to_add] = '\0';

    // Now parse as uninteger
    int result = cellframe_uint256_scan_uninteger(buf, value_out);

    if (result == 0) {
        printf("[DEBUG cellframe_uint256_from_str] Input: '%s' -> datoshi string: '%s'\n",
               value_str, buf);
        printf("[DEBUG] uint256 = {hi.hi=%llu, hi.lo=%llu, lo.hi=%llu, lo.lo=%llu}\n",
               (unsigned long long)value_out->hi.hi,
               (unsigned long long)value_out->hi.lo,
               (unsigned long long)value_out->lo.hi,
               (unsigned long long)value_out->lo.lo);
    }

    return result;
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
