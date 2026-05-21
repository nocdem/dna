/**
 * @file transcript.c
 * @brief Fiat-Shamir transcript for STARK range proofs (DNAC v3).
 *
 * Implements design doc § 4.3 + F4 fix: T₀ binds chain_id + block_height +
 * tx_index to prevent intra-block proof replay.
 *
 *   Init:   T₀ = SHA3-512( "DNAC_RP_TRANSCRIPT_V1\0\0\0" ||
 *                          chain_id[32] || height_BE_u64 || tx_idx_BE_u32 ||
 *                          public_input )
 *   Absorb: T_{i+1} = SHA3-512( T_i || msg_i )
 *   challenge_fp2:
 *     seed = SHA3-512( T || "CHAL" || ctr_BE_u32 )
 *     counter++
 *     Rejection-sample 2 u64 components from 8-byte BE chunks of seed.
 *     If exhausted, re-squeeze with incremented counter (extremely rare).
 *   challenge_query_index:
 *     seed = SHA3-512( T || "QRY\0" || ctr_BE_u32 )
 *     counter++
 *     Rejection-sample u32 in [0, max_index) using threshold (no modulo bias).
 *
 * Cross-validated against tools/vectors/transcript.json.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "transcript.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* ============================================================================
 * Internal helpers
 * ========================================================================== */

static void u32_to_be(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)((v >> 24) & 0xff);
    out[1] = (uint8_t)((v >> 16) & 0xff);
    out[2] = (uint8_t)((v >> 8) & 0xff);
    out[3] = (uint8_t)(v & 0xff);
}

static void u64_to_be(uint64_t v, uint8_t out[8]) {
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)((v >> (56 - 8 * i)) & 0xff);
    }
}

static uint64_t be_to_u64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)in[i];
    }
    return v;
}

static uint32_t be_to_u32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  | (uint32_t)in[3];
}

/** Squeeze a tagged seed from current transcript state + counter (without modifying state). */
static void squeeze_seed(const transcript_t *t,
                        const uint8_t tag[4],
                        uint32_t counter,
                        uint8_t out[TRANSCRIPT_HASH_SIZE]) {
    uint8_t buf[TRANSCRIPT_HASH_SIZE + 4 + 4];
    memcpy(buf, t->state, TRANSCRIPT_HASH_SIZE);
    memcpy(buf + TRANSCRIPT_HASH_SIZE, tag, 4);
    u32_to_be(counter, buf + TRANSCRIPT_HASH_SIZE + 4);
    (void)qgp_sha3_512(buf, sizeof(buf), out);
}

/* ============================================================================
 * Init
 * ========================================================================== */

void transcript_init(transcript_t *t,
                     const uint8_t chain_id[32],
                     uint64_t block_height,
                     uint32_t tx_index,
                     const uint8_t *public_input,
                     size_t public_input_len) {
    if (!t) return;

    /* T₀ = SHA3-512( domain || chain_id || height || tx_index || public_input ) */
    size_t buf_len = TRANSCRIPT_PROTOCOL_DOMAIN_LEN + 32 + 8 + 4 + public_input_len;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    if (!buf) {
        /* OOM — zero state to make failure loud. */
        memset(t->state, 0, TRANSCRIPT_HASH_SIZE);
        t->challenge_counter = 0;
        return;
    }

    size_t off = 0;
    memcpy(buf + off, TRANSCRIPT_PROTOCOL_DOMAIN, TRANSCRIPT_PROTOCOL_DOMAIN_LEN);
    off += TRANSCRIPT_PROTOCOL_DOMAIN_LEN;
    memcpy(buf + off, chain_id, 32);
    off += 32;
    u64_to_be(block_height, buf + off);
    off += 8;
    u32_to_be(tx_index, buf + off);
    off += 4;
    if (public_input_len > 0) {
        memcpy(buf + off, public_input, public_input_len);
        off += public_input_len;
    }

    (void)qgp_sha3_512(buf, off, t->state);
    free(buf);
    t->challenge_counter = 0;
}

/* ============================================================================
 * Absorb
 * ========================================================================== */

void transcript_absorb(transcript_t *t, const uint8_t *msg, size_t msg_len) {
    if (!t || (msg_len > 0 && !msg)) return;

    size_t buf_len = TRANSCRIPT_HASH_SIZE + msg_len;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    if (!buf) { return; }

    memcpy(buf, t->state, TRANSCRIPT_HASH_SIZE);
    if (msg_len > 0) {
        memcpy(buf + TRANSCRIPT_HASH_SIZE, msg, msg_len);
    }
    (void)qgp_sha3_512(buf, buf_len, t->state);
    free(buf);
}

/* ============================================================================
 * Challenge: Goldilocks² element
 * ========================================================================== */

#define GOLDILOCKS_P_LOCAL ((uint64_t)0xFFFFFFFF00000001ULL)

gold_fp2_t transcript_challenge_fp2(transcript_t *t) {
    if (!t) return gold_fp2_zero();

    /* Loop: in vanishingly rare cases (≈ 2^-256), all 8 chunks fail.
     * Re-squeeze with the next counter. Bounded to 16 iterations as paranoia. */
    for (int iter = 0; iter < 16; iter++) {
        uint8_t tag[4] = {'C', 'H', 'A', 'L'};
        uint8_t seed[TRANSCRIPT_HASH_SIZE];
        squeeze_seed(t, tag, t->challenge_counter, seed);
        t->challenge_counter++;

        uint64_t got_a0 = 0;
        uint64_t got_a1 = 0;
        int have_a0 = 0, have_a1 = 0;
        for (int ci = 0; ci < 8; ci++) {
            uint64_t v = be_to_u64(seed + ci * 8);
            if (v < GOLDILOCKS_P_LOCAL) {
                if (!have_a0) {
                    got_a0 = v;
                    have_a0 = 1;
                } else {
                    got_a1 = v;
                    have_a1 = 1;
                    break;
                }
            }
        }
        if (have_a0 && have_a1) {
            return gold_fp2_new(gold_fp_from_u64(got_a0),
                                gold_fp_from_u64(got_a1));
        }
        /* else: re-loop, counter already incremented */
    }
    /* Unreachable in practice. Return zero as fallback (caller should never see this). */
    return gold_fp2_zero();
}

/* ============================================================================
 * Challenge: query index (uniform u32 in [0, max_index))
 * ========================================================================== */

uint32_t transcript_challenge_query_index(transcript_t *t, uint32_t max_index) {
    if (!t || max_index == 0) return 0;

    /* Threshold per Rust oracle: (u32::MAX / max_index) * max_index.
     * For max_index = 1: threshold = 0xFFFFFFFF, so only v = 0xFFFFFFFF
     * rejected, otherwise v % 1 = 0. Wastes ~2^-32 of input space — OK. */
    uint32_t threshold = (UINT32_MAX / max_index) * max_index;

    for (int iter = 0; iter < 16; iter++) {
        uint8_t tag[4] = {'Q', 'R', 'Y', '\0'};
        uint8_t seed[TRANSCRIPT_HASH_SIZE];
        squeeze_seed(t, tag, t->challenge_counter, seed);
        t->challenge_counter++;

        for (int ci = 0; ci < 16; ci++) {
            uint32_t v = be_to_u32(seed + ci * 4);
            if (v < threshold) {
                return v % max_index;
            }
        }
    }
    return 0; /* unreachable in practice */
}
