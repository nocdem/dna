/**
 * @file stark_proof_codec.c
 * @brief Additive DZKS STARK/PCS wire wrapper — implementation.
 *
 * Mirrors the fri_proof_codec conventions (LE integers, canonical u64-LE
 * Goldilocks, bounded length prefixes, total_len self-check, no-partial-leak
 * decode). Independent of fri_proof_codec: the inner DZKF is an opaque blob.
 * See stark_proof_codec.h for the wire layout + source map.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stark_proof_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"

/* ---- little-endian primitives (self-contained) ---- */
static void wr_u16_le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}
static void wr_u32_le(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
}
static void wr_u64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
}
static uint16_t rd_u16_le(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t rd_u32_le(const uint8_t *p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= (uint32_t)p[i] << (8 * i);
    return v;
}
static uint64_t rd_u64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

dnac_stark_wire_status_t dnac_stark_proof_encode(
    size_t           degree_bits,
    const gold_fp_t *public_values,
    size_t           num_public_values,
    const uint8_t   *inner_dzkf,
    size_t           inner_dzkf_len,
    uint8_t        **out_buf,
    size_t          *out_len) {
    if (out_buf == NULL || out_len == NULL) return DNAC_STARK_WIRE_ERR_NULL;
    *out_buf = NULL;
    if (num_public_values > 0 && public_values == NULL) return DNAC_STARK_WIRE_ERR_NULL;
    if (inner_dzkf_len > 0 && inner_dzkf == NULL) return DNAC_STARK_WIRE_ERR_NULL;

    if (num_public_values > DNAC_STARK_WIRE_MAX_PUBLIC_VALUES) return DNAC_STARK_WIRE_ERR_LENGTH_OVERFLOW;
    if (inner_dzkf_len > DNAC_STARK_WIRE_MAX_INNER_LEN) return DNAC_STARK_WIRE_ERR_TOO_LARGE;
    /* degree_bits / num_public_values / inner_dzkf_len are serialized as u32. */
    if (degree_bits > 0xFFFFFFFFu) return DNAC_STARK_WIRE_ERR_TOO_LARGE;

    /* total = header(18) + 8*num_public + u32 inner_len(4) + inner bytes */
    size_t total = (size_t)DNAC_STARK_WIRE_HEADER_MIN + 8u * num_public_values + 4u + inner_dzkf_len;
    if (total > DNAC_STARK_WIRE_MAX_TOTAL_LEN) return DNAC_STARK_WIRE_ERR_TOO_LARGE;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (buf == NULL) return DNAC_STARK_WIRE_ERR_OOM;

    size_t p = 0;
    buf[p++] = DNAC_STARK_WIRE_MAGIC0;
    buf[p++] = DNAC_STARK_WIRE_MAGIC1;
    buf[p++] = DNAC_STARK_WIRE_MAGIC2;
    buf[p++] = DNAC_STARK_WIRE_MAGIC3;
    wr_u16_le(buf + p, (uint16_t)DNAC_STARK_WIRE_VERSION); p += 2;
    wr_u32_le(buf + p, (uint32_t)total); p += 4;
    wr_u32_le(buf + p, (uint32_t)degree_bits); p += 4;
    wr_u32_le(buf + p, (uint32_t)num_public_values); p += 4;
    for (size_t i = 0; i < num_public_values; ++i) {
        wr_u64_le(buf + p, gold_fp_to_u64(public_values[i])); /* canonical [0,p) */
        p += 8;
    }
    wr_u32_le(buf + p, (uint32_t)inner_dzkf_len); p += 4;
    if (inner_dzkf_len > 0) { memcpy(buf + p, inner_dzkf, inner_dzkf_len); p += inner_dzkf_len; }

    *out_buf = buf;
    *out_len = total;
    return DNAC_STARK_WIRE_OK;
}

dnac_stark_wire_status_t dnac_stark_proof_decode(
    const uint8_t              *buf,
    size_t                      len,
    dnac_stark_wire_decoded_t **out) {
    if (buf == NULL || out == NULL) return DNAC_STARK_WIRE_ERR_NULL;
    *out = NULL;

    if (len < DNAC_STARK_WIRE_HEADER_MIN) return DNAC_STARK_WIRE_ERR_TRUNCATED;
    if (buf[0] != DNAC_STARK_WIRE_MAGIC0 || buf[1] != DNAC_STARK_WIRE_MAGIC1 ||
        buf[2] != DNAC_STARK_WIRE_MAGIC2 || buf[3] != DNAC_STARK_WIRE_MAGIC3) {
        return DNAC_STARK_WIRE_ERR_BAD_MAGIC;
    }
    size_t p = 4;
    uint16_t ver = rd_u16_le(buf + p); p += 2;
    if (ver != DNAC_STARK_WIRE_VERSION) return DNAC_STARK_WIRE_ERR_BAD_VERSION;
    uint32_t total = rd_u32_le(buf + p); p += 4;
    if (total > DNAC_STARK_WIRE_MAX_TOTAL_LEN) return DNAC_STARK_WIRE_ERR_TOO_LARGE;
    if ((size_t)total != len) return DNAC_STARK_WIRE_ERR_INCONSISTENT_LENGTH;
    uint32_t degree_bits = rd_u32_le(buf + p); p += 4;
    uint32_t num_pub = rd_u32_le(buf + p); p += 4;
    if (num_pub > DNAC_STARK_WIRE_MAX_PUBLIC_VALUES) return DNAC_STARK_WIRE_ERR_LENGTH_OVERFLOW;
    /* num_pub * 8 bytes must remain (computed without overflow). */
    if ((size_t)num_pub > (len - p) / 8u) return DNAC_STARK_WIRE_ERR_LENGTH_OVERFLOW;

    gold_fp_t *pub = NULL;
    if (num_pub > 0) {
        pub = (gold_fp_t *)malloc((size_t)num_pub * sizeof(gold_fp_t));
        if (pub == NULL) return DNAC_STARK_WIRE_ERR_OOM;
    }
    for (uint32_t i = 0; i < num_pub; ++i) {
        uint64_t v = rd_u64_le(buf + p); p += 8;
        if (v >= GOLDILOCKS_P) { free(pub); return DNAC_STARK_WIRE_ERR_NONCANONICAL; }
        pub[i] = gold_fp_from_u64(v);
    }

    if (len - p < 4u) { free(pub); return DNAC_STARK_WIRE_ERR_TRUNCATED; }
    uint32_t inner_len = rd_u32_le(buf + p); p += 4;
    if ((size_t)inner_len > len - p) { free(pub); return DNAC_STARK_WIRE_ERR_LENGTH_OVERFLOW; }

    uint8_t *inner = NULL;
    if (inner_len > 0) {
        inner = (uint8_t *)malloc(inner_len);
        if (inner == NULL) { free(pub); return DNAC_STARK_WIRE_ERR_OOM; }
        memcpy(inner, buf + p, inner_len);
        p += inner_len;
    }

    if (p != len) { free(pub); free(inner); return DNAC_STARK_WIRE_ERR_TRAILING; }

    dnac_stark_wire_decoded_t *d =
        (dnac_stark_wire_decoded_t *)calloc(1, sizeof(dnac_stark_wire_decoded_t));
    if (d == NULL) { free(pub); free(inner); return DNAC_STARK_WIRE_ERR_OOM; }
    d->degree_bits = (size_t)degree_bits;
    d->public_values = pub;
    d->num_public_values = (size_t)num_pub;
    d->inner_dzkf = inner;
    d->inner_dzkf_len = (size_t)inner_len;
    *out = d;
    return DNAC_STARK_WIRE_OK;
}

void dnac_stark_wire_free(dnac_stark_wire_decoded_t *dec) {
    if (dec == NULL) return;
    free(dec->public_values);
    free(dec->inner_dzkf);
    free(dec);
}
