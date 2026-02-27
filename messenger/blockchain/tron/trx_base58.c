/**
 * @file trx_base58.c
 * @brief Base58Check encoding implementation for TRON addresses
 *
 * @author DNA Messenger Team
 * @date 2025-12-11
 */

#include "trx_base58.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

/* Base58 alphabet */
static const char BASE58_CHARS[] = BASE58_ALPHABET;

/* Reverse lookup table for Base58 decoding */
static const int8_t BASE58_MAP[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,  /* 0-9 */
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,  /* A-O */
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,  /* P-Z */
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,  /* a-o */
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,  /* p-z */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

int trx_base58_encode(
    const uint8_t *data,
    size_t data_len,
    char *out,
    size_t out_size
) {
    if (!data || !out || out_size == 0) {
        return -1;
    }

    /* Count leading zeros */
    size_t leading_zeros = 0;
    while (leading_zeros < data_len && data[leading_zeros] == 0) {
        leading_zeros++;
    }

    /* Allocate enough space for base58 encoding
     * Base58 encoding expands data by factor of ~1.37 (log(256)/log(58))
     */
    size_t max_len = data_len * 138 / 100 + 1;
    uint8_t *buf = (uint8_t *)calloc(max_len, 1);
    if (!buf) {
        return -1;
    }

    size_t buf_len = 0;

    /* Convert from base256 to base58 */
    for (size_t i = leading_zeros; i < data_len; i++) {
        int carry = data[i];
        for (size_t j = 0; j < buf_len; j++) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            buf[buf_len++] = carry % 58;
            carry /= 58;
        }
    }

    /* Calculate output length */
    size_t out_len = leading_zeros + buf_len;
    if (out_len >= out_size) {
        free(buf);
        return -1;
    }

    /* Build output string */
    size_t idx = 0;

    /* Add '1' for each leading zero byte */
    for (size_t i = 0; i < leading_zeros; i++) {
        out[idx++] = '1';
    }

    /* Add base58 digits (reversed) */
    for (size_t i = buf_len; i > 0; i--) {
        out[idx++] = BASE58_CHARS[buf[i - 1]];
    }

    out[idx] = '\0';
    free(buf);

    return (int)idx;
}

int trx_base58_decode(
    const char *str,
    uint8_t *out,
    size_t out_size
) {
    if (!str || !out || out_size == 0) {
        return -1;
    }

    size_t str_len = strlen(str);
    if (str_len == 0) {
        return -1;
    }

    /* Count leading '1's (zeros in output) */
    size_t leading_ones = 0;
    while (leading_ones < str_len && str[leading_ones] == '1') {
        leading_ones++;
    }

    /* Allocate buffer for base256 conversion */
    size_t max_len = str_len * 733 / 1000 + 1;  /* log(58)/log(256) */
    uint8_t *buf = (uint8_t *)calloc(max_len, 1);
    if (!buf) {
        return -1;
    }

    size_t buf_len = 0;

    /* Convert from base58 to base256 */
    for (size_t i = leading_ones; i < str_len; i++) {
        int8_t digit = BASE58_MAP[(unsigned char)str[i]];
        if (digit < 0) {
            free(buf);
            return -1;  /* Invalid character */
        }

        int carry = digit;
        for (size_t j = 0; j < buf_len; j++) {
            carry += 58 * buf[j];
            buf[j] = carry & 0xFF;
            carry >>= 8;
        }
        while (carry) {
            buf[buf_len++] = carry & 0xFF;
            carry >>= 8;
        }
    }

    /* Calculate output length */
    size_t out_len = leading_ones + buf_len;
    if (out_len > out_size) {
        free(buf);
        return -1;
    }

    /* Build output (leading zeros + reversed buffer) */
    memset(out, 0, leading_ones);
    for (size_t i = 0; i < buf_len; i++) {
        out[leading_ones + i] = buf[buf_len - 1 - i];
    }

    free(buf);
    return (int)out_len;
}

/**
 * Double SHA256 hash (used for Base58Check checksum)
 */
static void double_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    uint8_t first_hash[32];
    SHA256(data, len, first_hash);
    SHA256(first_hash, 32, hash);
}

int trx_base58check_encode(
    const uint8_t *data,
    size_t data_len,
    char *out,
    size_t out_size
) {
    if (!data || !out || out_size == 0 || data_len == 0) {
        return -1;
    }

    /* Allocate buffer for data + 4-byte checksum */
    size_t total_len = data_len + 4;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) {
        return -1;
    }

    /* Copy data */
    memcpy(buf, data, data_len);

    /* Calculate and append checksum */
    uint8_t hash[32];
    double_sha256(data, data_len, hash);
    memcpy(buf + data_len, hash, 4);

    /* Encode as Base58 */
    int result = trx_base58_encode(buf, total_len, out, out_size);

    free(buf);
    return result;
}

int trx_base58check_decode(
    const char *str,
    uint8_t *out,
    size_t out_size
) {
    if (!str || !out || out_size == 0) {
        return -1;
    }

    /* Decode Base58 */
    uint8_t buf[128];
    int decoded_len = trx_base58_decode(str, buf, sizeof(buf));
    if (decoded_len < 5) {  /* Minimum: 1 byte data + 4 byte checksum */
        return -1;
    }

    /* Verify checksum */
    size_t data_len = (size_t)decoded_len - 4;
    uint8_t hash[32];
    double_sha256(buf, data_len, hash);

    if (memcmp(hash, buf + data_len, 4) != 0) {
        return -1;  /* Invalid checksum */
    }

    /* Copy data (without checksum) to output */
    if (data_len > out_size) {
        return -1;
    }

    memcpy(out, buf, data_len);
    return (int)data_len;
}

int trx_base58check_verify(const char *str) {
    if (!str) {
        return 0;
    }

    uint8_t buf[128];
    int decoded_len = trx_base58_decode(str, buf, sizeof(buf));
    if (decoded_len < 5) {
        return 0;
    }

    size_t data_len = (size_t)decoded_len - 4;
    uint8_t hash[32];
    double_sha256(buf, data_len, hash);

    return (memcmp(hash, buf + data_len, 4) == 0) ? 1 : 0;
}
