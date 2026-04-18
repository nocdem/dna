/**
 * @file qgp_fingerprint.c
 * @brief Implementation of fingerprint hex <-> raw byte converters.
 *
 * See qgp_fingerprint.h for rationale. Tight, portable C — no stdio,
 * no allocations.
 */

#include "crypto/utils/qgp_fingerprint.h"

#include <string.h>

/* Lowercase hex alphabet. Matches the project convention (128 lowercase
 * hex characters for fingerprints). */
static const char qgp_fp_hex_digits[16] = "0123456789abcdef";

void qgp_fp_raw_to_hex(const uint8_t raw[QGP_FP_RAW_BYTES],
                       char out[QGP_FP_HEX_BUFFER]) {
    for (size_t i = 0; i < QGP_FP_RAW_BYTES; i++) {
        out[2 * i]     = qgp_fp_hex_digits[(raw[i] >> 4) & 0x0F];
        out[2 * i + 1] = qgp_fp_hex_digits[raw[i] & 0x0F];
    }
    out[QGP_FP_HEX_CHARS] = '\0';
}

int qgp_fp_hex_to_raw(const char *hex,
                      uint8_t raw_out[QGP_FP_RAW_BYTES]) {
    if (!hex) return -1;

    /* Enforce exact length FIRST to avoid reading past a short string
     * (which would be OOB for inputs like ""). Using strnlen with an
     * upper bound cap keeps worst-case work bounded even for pathological
     * unterminated input in debug builds — in practice callers always
     * pass NUL-terminated data. */
    size_t n = 0;
    while (n <= QGP_FP_HEX_CHARS && hex[n] != '\0') n++;
    if (n != QGP_FP_HEX_CHARS) return -1;

    for (size_t i = 0; i < QGP_FP_RAW_BYTES; i++) {
        char h = hex[2 * i];
        char l = hex[2 * i + 1];
        int hi, lo;

        if      (h >= '0' && h <= '9') hi = h - '0';
        else if (h >= 'a' && h <= 'f') hi = h - 'a' + 10;
        else                           return -1;

        if      (l >= '0' && l <= '9') lo = l - '0';
        else if (l >= 'a' && l <= 'f') lo = l - 'a' + 10;
        else                           return -1;

        raw_out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}
