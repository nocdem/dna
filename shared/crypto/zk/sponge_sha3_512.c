/**
 * @file sponge_sha3_512.c
 * @brief FIPS-202 SHA3-512 sponge over keccak_p3 permutation backend.
 *
 * Reference (NIST FIPS PUB 202, `refs/NIST.FIPS.202.pdf`):
 *   § 4   Sponge Construction        (Algorithm 8, XOR absorb)
 *   § 5.1 Specification of pad10*1   (Algorithm 9)
 *   § 6.1 SHA-3 Hash Functions       (SHA3-512(M) = KECCAK[1024](M||01, 512))
 *   § B.2 Hexadecimal Form of Padding Bits (Table 6 — byte-level pattern)
 * Permutation backend: keccak_p3 trace (Plonky3-byte-matched 24-row Keccak-f[1600]).
 *
 * Lane encoding (FIPS-202 § B.1): bytes M[8j], M[8j+1], ..., M[8j+7] form lane j
 * interpreted little-endian as a u64. Both absorb and squeeze use this mapping.
 *
 * Stack pressure note: each keccak_p3 trace allocation is ~500 KB on the stack.
 * For SHA3-512 of input length N, the function calls Keccak-f[1600] ceil((N+1)/72)+1
 * times sequentially; peak stack usage is 500 KB per call (transient, released
 * immediately). Mobile (Android default 1 MB thread stack) is safe; if any caller
 * deepens the stack significantly we should revisit.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sponge_sha3_512.h"

#include <string.h>

#include "keccak_p3_cols.h"
#include "keccak_p3_trace.h"

/* ============================================================================
 * Lane byte-order helpers (FIPS-202 little-endian)
 * ========================================================================== */

static uint64_t le_bytes_to_u64(const uint8_t b[8]) {
    return  (uint64_t)b[0]
         | ((uint64_t)b[1] << 8)
         | ((uint64_t)b[2] << 16)
         | ((uint64_t)b[3] << 24)
         | ((uint64_t)b[4] << 32)
         | ((uint64_t)b[5] << 40)
         | ((uint64_t)b[6] << 48)
         | ((uint64_t)b[7] << 56);
}

static void u64_to_le_bytes(uint64_t v, uint8_t b[8]) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    b[4] = (uint8_t)(v >> 32);
    b[5] = (uint8_t)(v >> 40);
    b[6] = (uint8_t)(v >> 48);
    b[7] = (uint8_t)(v >> 56);
}

/* ============================================================================
 * Permutation backend (keccak_p3 trace)
 *
 * Calls keccak_p3_generate_trace_one_perm + keccak_p3_extract_output to apply
 * one Keccak-f[1600] round-set in place. The intermediate trace rows are
 * stack-resident and discarded after extraction.
 * ========================================================================== */

static void permute_via_keccak_p3(uint64_t state[SHA3_512_STATE_LANES]) {
    keccak_p3_cols_t rows[KECCAK_P3_NUM_ROUNDS];
    keccak_p3_generate_trace_one_perm(rows, state);
    keccak_p3_extract_output(rows, state);
}

/* XOR a full rate-sized block (72 bytes = 9 lanes) into state[0..9]. */
static void absorb_block(uint64_t state[SHA3_512_STATE_LANES],
                         const uint8_t block[SHA3_512_RATE_BYTES]) {
    for (size_t i = 0; i < SHA3_512_RATE_LANES; i++) {
        state[i] ^= le_bytes_to_u64(&block[i * 8]);
    }
}

/* ============================================================================
 * Public API
 * ========================================================================== */

void sha3_512_init(sha3_512_ctx_t *ctx) {
    memset(ctx, 0, sizeof *ctx);
}

void sha3_512_absorb(sha3_512_ctx_t *ctx, const uint8_t *data, size_t len) {
    while (len > 0) {
        const size_t want = SHA3_512_RATE_BYTES - ctx->buf_len;
        const size_t take = (len < want) ? len : want;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == SHA3_512_RATE_BYTES) {
            absorb_block(ctx->state, ctx->buf);
            permute_via_keccak_p3(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

void sha3_512_squeeze(sha3_512_ctx_t *ctx,
                      uint8_t out[SHA3_512_OUT_BYTES]) {
    /* FIPS-202 § B.2 Table 6 padding rule (= § 5.1 pad10*1 + § 6.1 SHA-3 suffix "01"
     * collapsed to byte form for byte-aligned input).
     *   - q > 2: M || 0x06 || 0x00... || 0x80     (Table 6 row 3)
     *   - q = 2: M || 0x0680                       (Table 6 row 2)
     *   - q = 1: M || 0x86 = 0x06 XOR 0x80         (Table 6 row 1)
     * Implementation: zero-fill rate tail; XOR 0x06 at buf_len; XOR 0x80 at byte 71.
     * Edge case buf_len == 71 (q == 1): both XORs collide → byte 71 = 0x86. */
    memset(ctx->buf + ctx->buf_len, 0,
           SHA3_512_RATE_BYTES - ctx->buf_len);
    ctx->buf[ctx->buf_len] ^= 0x06;
    ctx->buf[SHA3_512_RATE_BYTES - 1] ^= 0x80;
    absorb_block(ctx->state, ctx->buf);
    permute_via_keccak_p3(ctx->state);

    /* Squeeze: first 8 lanes (64 bytes) of state, little-endian. */
    for (size_t i = 0; i < SHA3_512_OUT_BYTES / 8; i++) {
        u64_to_le_bytes(ctx->state[i], &out[i * 8]);
    }
    ctx->finalized = 1;
}

void sha3_512_oneshot(const uint8_t *input, size_t len,
                      uint8_t out[SHA3_512_OUT_BYTES]) {
    sha3_512_ctx_t ctx;
    sha3_512_init(&ctx);
    sha3_512_absorb(&ctx, input, len);
    sha3_512_squeeze(&ctx, out);
}
