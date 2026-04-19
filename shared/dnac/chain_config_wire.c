/**
 * @file shared/dnac/chain_config_wire.c
 * @brief Implementation of dnac_cc_wire_{encode,decode}.
 *
 * Hard-Fork v1. See chain_config_wire.h for wire layout. Pure C, no
 * crypto / sqlite / libdna dependencies — compiled into both libdna
 * (via messenger/CMakeLists.txt) and libnodus (via nodus/CMakeLists.txt).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/chain_config_wire.h"

#include <string.h>

/* Internal big-endian helpers — scoped to this file to avoid leaking a
 * third definition into the header include graph. */
static void be64_store(uint64_t v, uint8_t out[8]) {
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)(v);
}

static uint64_t be64_load(const uint8_t in[8]) {
    return ((uint64_t)in[0] << 56) |
           ((uint64_t)in[1] << 48) |
           ((uint64_t)in[2] << 40) |
           ((uint64_t)in[3] << 32) |
           ((uint64_t)in[4] << 24) |
           ((uint64_t)in[5] << 16) |
           ((uint64_t)in[6] << 8)  |
           ((uint64_t)in[7]);
}

size_t dnac_cc_wire_encoded_size(const dnac_cc_wire_ext_t *fields) {
    if (!fields) return 0;
    uint8_t n = fields->committee_sig_count;
    if (n > DNAC_CC_WIRE_COMMITTEE_SIZE) n = DNAC_CC_WIRE_COMMITTEE_SIZE;
    return DNAC_CC_WIRE_FIXED_LEN + (size_t)n * DNAC_CC_WIRE_PER_VOTE;
}

int dnac_cc_wire_encode(const dnac_cc_wire_ext_t *fields,
                         uint8_t *dst, size_t dst_cap,
                         size_t *bytes_written_out) {
    if (!fields || !dst || !bytes_written_out) return -1;

    uint8_t n = fields->committee_sig_count;
    if (n > DNAC_CC_WIRE_COMMITTEE_SIZE) n = DNAC_CC_WIRE_COMMITTEE_SIZE;
    size_t need = DNAC_CC_WIRE_FIXED_LEN + (size_t)n * DNAC_CC_WIRE_PER_VOTE;
    if (dst_cap < need) return -1;

    uint8_t *p = dst;
    *p++ = fields->param_id;
    be64_store(fields->new_value,              p); p += 8;
    be64_store(fields->effective_block_height, p); p += 8;
    be64_store(fields->proposal_nonce,         p); p += 8;
    be64_store(fields->signed_at_block,        p); p += 8;
    be64_store(fields->valid_before_block,     p); p += 8;
    *p++ = n;

    for (uint8_t i = 0; i < n; i++) {
        memcpy(p, fields->votes[i].witness_id,
               DNAC_CC_WIRE_WITNESS_ID_SIZE);
        p += DNAC_CC_WIRE_WITNESS_ID_SIZE;
        memcpy(p, fields->votes[i].signature,
               DNAC_CC_WIRE_SIGNATURE_SIZE);
        p += DNAC_CC_WIRE_SIGNATURE_SIZE;
    }

    *bytes_written_out = (size_t)(p - dst);
    return 0;
}

int dnac_cc_wire_decode(const uint8_t *src, size_t src_len,
                         dnac_cc_wire_ext_t *out,
                         size_t *bytes_consumed_out) {
    if (!src || !out || !bytes_consumed_out) return -1;
    if (src_len < DNAC_CC_WIRE_FIXED_LEN) return -1;

    const uint8_t *p = src;
    out->param_id               = *p++;
    out->new_value              = be64_load(p); p += 8;
    out->effective_block_height = be64_load(p); p += 8;
    out->proposal_nonce         = be64_load(p); p += 8;
    out->signed_at_block        = be64_load(p); p += 8;
    out->valid_before_block     = be64_load(p); p += 8;
    out->committee_sig_count    = *p++;

    if (out->committee_sig_count > DNAC_CC_WIRE_COMMITTEE_SIZE) return -1;

    size_t votes_len = (size_t)out->committee_sig_count *
                        DNAC_CC_WIRE_PER_VOTE;
    if ((size_t)(p - src) + votes_len > src_len) return -1;

    memset(out->votes, 0, sizeof(out->votes));
    for (uint8_t i = 0; i < out->committee_sig_count; i++) {
        memcpy(out->votes[i].witness_id, p,
               DNAC_CC_WIRE_WITNESS_ID_SIZE);
        p += DNAC_CC_WIRE_WITNESS_ID_SIZE;
        memcpy(out->votes[i].signature, p,
               DNAC_CC_WIRE_SIGNATURE_SIZE);
        p += DNAC_CC_WIRE_SIGNATURE_SIZE;
    }

    *bytes_consumed_out = (size_t)(p - src);
    return 0;
}
