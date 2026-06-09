/**
 * @file sponge_sha3_512.h
 * @brief FIPS-202 SHA3-512 sponge over keccak_p3 permutation backend (Sprint 3.3b.7 rework).
 *
 * Implements standard FIPS-202 SHA3-512 hashing — byte-identical to OpenSSL,
 * NIST KAT, and the existing keccak_ref module — but uses keccak_p3's
 * AIR-encoded Keccak-f[1600] trace generator as the permutation backend.
 *
 * This module is the **bridge** between out-of-AIR SHA3-512 computation
 * (what the wallet/witness does) and the in-AIR keccak_p3 constraint encoding
 * (what range_proof_air's 'M' commitment-match constraint will reference).
 * Both paths produce the same bytes; this module makes the structural
 * equivalence concrete and testable.
 *
 * Per the locked v3.0 hash decision (project_v3_zk_bitcoin_style memory +
 * design doc § 4.2 Option B revision 2026-05-21): **uniform FIPS-202
 * SHA3-512 everywhere, including in-AIR.**  We do NOT use the strict
 * overwrite-mode PaddingFreeSponge variant — that would deviate from the
 * locked spec.
 *
 * Reference (NIST FIPS PUB 202, `refs/NIST.FIPS.202.pdf`):
 *   § 4   Sponge Construction        (doc p. 17 — Algorithm 8 SPONGE[f, pad, r])
 *   § 5.1 Specification of pad10*1   (doc p. 19 — Algorithm 9: P = 1 || 0^j || 1)
 *   § 6.1 SHA-3 Hash Functions       (doc p. 20 — SHA3-512(M) = KECCAK[1024](M||01, 512))
 *   § B.2 Hexadecimal Form of Padding Bits (doc p. 28 — Table 6: q>2 → M||0x06||0x00...||0x80)
 *
 * Triple cross-validation in test_sponge_sha3_512.c:
 *   (A) C output  ==  Plonky3 sha3 crate (tools/vectors/sha3_512_sponge.json)
 *   (B) C output  ==  keccak_ref (existing OpenSSL-validated FIPS-202)
 *   (C) Incremental absorb (chunk-by-chunk) == oneshot
 *
 * **When to use this module vs keccak_ref:**
 *   - Use this module (`sponge_sha3_512`) when you need byte-equivalence with
 *     the keccak_p3 AIR encoding — i.e., the wallet/witness side of an
 *     in-AIR commitment check, where both sides must agree on the same
 *     permutation invocation.
 *   - Use `keccak_ref_sha3_512` when you only need a fast standard SHA3-512
 *     (chain-level tx_hash, nullifier, etc.). Same output bytes, but
 *     keccak_ref skips the ~500KB-per-permutation trace allocation.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_SPONGE_SHA3_512_H
#define DNAC_ZK_SPONGE_SHA3_512_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** SHA3-512 rate: 576 bits = 72 bytes = 9 lanes. */
#define SHA3_512_RATE_BYTES   ((size_t)72)

/** SHA3-512 capacity: 1024 bits = 128 bytes = 16 lanes. */
#define SHA3_512_CAP_BYTES    ((size_t)128)

/** SHA3-512 output: 512 bits = 64 bytes = 8 lanes. */
#define SHA3_512_OUT_BYTES    ((size_t)64)

/** Full Keccak-f[1600] state: 1600 bits = 200 bytes = 25 lanes. */
#define SHA3_512_STATE_BYTES  ((size_t)200)

/** Number of 64-bit lanes in the state. */
#define SHA3_512_STATE_LANES  ((size_t)25)

/** Number of state lanes consumed by the rate (= SHA3_512_RATE_BYTES / 8). */
#define SHA3_512_RATE_LANES   ((size_t)9)

/* ============================================================================
 * Streaming context
 * ========================================================================== */

/**
 * @brief Incremental SHA3-512 hash context.
 *
 * State is stored as 25 u64 lanes interpreted little-endian per FIPS-202 § B.1.
 * Pending bytes are buffered until a full rate-sized block is available;
 * see sha3_512_absorb for the absorption protocol.
 */
typedef struct {
    /** Keccak-f[1600] state: 25 lanes (200 bytes). FIPS-202 lane is little-endian. */
    uint64_t state[SHA3_512_STATE_LANES];
    /** Pending input bytes waiting for a full rate-sized block. buf_len < RATE. */
    uint8_t  buf[SHA3_512_RATE_BYTES];
    /** Number of valid bytes in `buf`. */
    size_t   buf_len;
    /** True once squeeze has been called; further absorb/squeeze are undefined. */
    int      finalized;
} sha3_512_ctx_t;

/* ============================================================================
 * API
 * ========================================================================== */

/**
 * @brief Initialize a SHA3-512 hash context (state to all-zero, empty buffer).
 *
 * @param ctx Context to initialize. MUST NOT be NULL.
 */
void sha3_512_init(sha3_512_ctx_t *ctx);

/**
 * @brief Absorb input bytes into the sponge.
 *
 * Bytes are accumulated in `buf` until a full rate-sized block (72 bytes) is
 * available; each full block is XOR'd into state[0..9] (little-endian lane
 * encoding) and a Keccak-f[1600] permutation is applied via the keccak_p3
 * trace backend. Partial-block tail bytes remain in `buf` for subsequent
 * absorb or final squeeze.
 *
 * @param ctx  Context. MUST NOT be NULL. MUST NOT be finalized.
 * @param data Input bytes. MAY be NULL only if len == 0.
 * @param len  Number of bytes to absorb.
 */
void sha3_512_absorb(sha3_512_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Apply FIPS-202 padding, final permute, and extract the digest.
 *
 * Padding rule (FIPS-202 § B.1):
 *   - The byte immediately after the last message byte is XOR'd with 0x06
 *     (SHA-3 domain suffix "01" + leading "1" of pad10*1).
 *   - The final byte of the rate block (offset 71) is XOR'd with 0x80
 *     (trailing "1" of pad10*1). If only one byte of pad is available
 *     (i.e., last message byte at offset 71), both XORs land on byte 71,
 *     producing 0x06 | 0x80 = 0x86.
 *   - The padded rate block is XOR'd into state, then permuted.
 *   - The first 8 lanes (64 bytes) of state are read little-endian as output.
 *
 * After squeeze, the context is finalized; further calls are undefined.
 *
 * @param ctx Context. MUST NOT be NULL. MUST NOT be finalized.
 * @param out Output buffer of SHA3_512_OUT_BYTES (64) bytes.
 */
void sha3_512_squeeze(sha3_512_ctx_t *ctx, uint8_t out[SHA3_512_OUT_BYTES]);

/**
 * @brief One-shot hash: init + absorb(input, len) + squeeze.
 *
 * Convenience wrapper. Produces FIPS-202 SHA3-512 output byte-identical
 * to OpenSSL EVP_DigestUpdate/EVP_DigestFinal with EVP_sha3_512.
 *
 * @param input  Input bytes. MAY be NULL only if len == 0.
 * @param len    Number of input bytes.
 * @param out    Output buffer of SHA3_512_OUT_BYTES (64) bytes.
 */
void sha3_512_oneshot(const uint8_t *input, size_t len,
                      uint8_t out[SHA3_512_OUT_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SPONGE_SHA3_512_H */
