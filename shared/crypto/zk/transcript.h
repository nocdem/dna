/**
 * @file transcript.h
 * @brief DNAC SHA3-512 Fiat-Shamir transcript / challenger (Phase T2)
 *
 * C port of the Plonky3 composition:
 *   SerializingChallenger64<
 *       Goldilocks,
 *       HashChallenger<u8, DnacSha3_512Hasher, 64>
 *   >
 *
 * The transcript is the byte-level wire-format anchor of the DNAC v3
 * STARK/FRI verifier. Byte-identity with the Rust oracle is enforced by
 * the Phase T3 replay tests against `tools/vectors/transcript.json`.
 *
 * Hash backend: FIPS-202 SHA3-512 only (per DNAC SHA3 policy, design
 * doc § 4). No Poseidon. No Plonky3 Keccak256Hash. No incremental sponge
 * state — every flush is a fresh one-shot SHA3-512 of the entire input
 * buffer, mirroring HashChallenger::flush (Plonky3
 * challenger/src/hash_challenger.rs:36-43).
 *
 * Initial state policy: production transcripts use the ASCII byte string
 * `DNAC|ZK|FRI|TRANSCRIPT|V1` (25 bytes, no NUL, no length prefix, no
 * pre-hash). Q1 decision approved 2026-05-26. See
 * `dnac_transcript_init_default`.
 *
 * Source-of-truth references:
 *   - docs/plans/2026-05-26-transcript-design.md (this module's spec)
 *   - tools/vectors/transcript.json (T3 replay vectors, 13 cases)
 *   - Plonky3 commit 82cfad73:
 *       challenger/src/hash_challenger.rs
 *       challenger/src/serializing_challenger.rs
 *       challenger/src/grinding_challenger.rs
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_TRANSCRIPT_H
#define DNAC_ZK_TRANSCRIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Type aliases — design doc § 14 mandates `fp_t` / `fp2_t` in the API.
 * ========================================================================== */

/** Goldilocks base field element (alias of gold_fp_t for the verifier API). */
typedef gold_fp_t  fp_t;

/** Goldilocks² extension field element (alias of gold_fp2_t). */
typedef gold_fp2_t fp2_t;

/* ============================================================================
 * Constants
 * ========================================================================== */

/** SHA3-512 digest size (= HashChallenger OUT_LEN). */
#define DNAC_TRANSCRIPT_DIGEST_BYTES ((size_t)64)

/** Cap on input_buffer growth — DoS guard. A realistic FRI verify session
 *  accumulates ≲ 100 KB; 16 MiB is generous. Cap overflow aborts (design
 *  doc § 16 Q4). */
#define DNAC_TRANSCRIPT_MAX_INPUT_BYTES ((size_t)(16 * 1024 * 1024))

/**
 * @brief Production initial-state bytes per Q1 decision (2026-05-26).
 *
 * Raw ASCII `DNAC|ZK|FRI|TRANSCRIPT|V1` — 25 bytes, no NUL terminator,
 * no length prefix, no pre-hashing. Passed directly as
 * `HashChallenger::new` initial input_buffer.
 */
extern const uint8_t  DNAC_TRANSCRIPT_PROD_INIT_STATE[];
extern const size_t   DNAC_TRANSCRIPT_PROD_INIT_STATE_LEN;

/* ============================================================================
 * Opaque context
 * ========================================================================== */

/** Opaque transcript context. Allocated via the init functions, freed via
 *  `dnac_transcript_free`. Internal state is the input_buffer +
 *  output_buffer pair mirroring HashChallenger
 *  (Plonky3 hash_challenger.rs:10-21). */
typedef struct dnac_transcript_s dnac_transcript_t;

/* ============================================================================
 * Lifecycle
 * ========================================================================== */

/**
 * @brief Construct a transcript with caller-chosen initial state.
 *
 * Mirrors `HashChallenger::new(initial_state, hasher)` from
 * Plonky3 hash_challenger.rs:28-34.
 *
 * @param init_state      Bytes to seed input_buffer. MAY be NULL iff
 *                        `init_state_len == 0`.
 * @param init_state_len  Length of init_state. May be 0.
 * @return Heap-allocated transcript, or NULL on allocation failure.
 *
 * Cap behavior: `init_state_len` must be ≤ DNAC_TRANSCRIPT_MAX_INPUT_BYTES,
 * otherwise this function aborts.
 */
dnac_transcript_t *dnac_transcript_init(const uint8_t *init_state, size_t init_state_len);

/**
 * @brief Construct a transcript with the production initial state.
 *
 * Convenience wrapper that calls
 *   dnac_transcript_init(DNAC_TRANSCRIPT_PROD_INIT_STATE,
 *                        DNAC_TRANSCRIPT_PROD_INIT_STATE_LEN).
 *
 * Use this in all DNAC production verifier paths.
 */
dnac_transcript_t *dnac_transcript_init_default(void);

/**
 * @brief Free a transcript and all owned buffers. Safe to call with NULL.
 */
void dnac_transcript_free(dnac_transcript_t *t);

/* ============================================================================
 * Observe (absorb into the transcript)
 * ========================================================================== */

/**
 * @brief Observe a raw byte buffer.
 *
 * Mirrors the byte path that the FRI verifier reaches when observing
 * `Hash<F, u8, N>` / `MerkleCap<F, [u8; N]>` commitments: at the
 * `HashChallenger` layer it appears as a sequence of single-byte observes
 * (Plonky3 hash_challenger.rs:51-57), driven by the trait-default
 * `CanObserve::observe_slice` loop (Plonky3 challenger/src/lib.rs:32-39).
 *
 * Effect:
 *   - len > 0: clear output_buffer, append `bytes[0..len]` to input_buffer.
 *   - len == 0: no-op (matches Plonky3's `observe_slice` default — the
 *               loop body never executes for an empty slice, so NO clear
 *               and NO append occurs). Verified at design doc § 5.2 +
 *               primary source 2026-05-26 audit.
 *
 * @param t      Non-NULL transcript.
 * @param bytes  Input bytes. MAY be NULL iff `len == 0`.
 * @param len    Number of bytes to absorb. May be 0.
 *
 * Cap behavior: if `input_len + len > DNAC_TRANSCRIPT_MAX_INPUT_BYTES`,
 * this function aborts.
 */
void dnac_transcript_observe_bytes(dnac_transcript_t *t, const uint8_t *bytes, size_t len);

/**
 * @brief Observe a base-field element.
 *
 * Mirrors `SerializingChallenger64::observe(F)` from Plonky3
 * serializing_challenger.rs:254-259:
 *   inner.observe_slice(&value.to_unique_u64().to_le_bytes())
 *
 * The value is canonicalized (gold_fp_to_u64) to its representative in
 * [0, p) before serialization, then emitted as 8 little-endian bytes via
 * explicit shifts (no `memcpy` of u64 — design doc § 6.1, D3, R8).
 *
 * @param t  Non-NULL transcript.
 * @param v  Field element. Internal representation may exceed p; the
 *           canonical form is what is serialized.
 */
void dnac_transcript_observe_fp(dnac_transcript_t *t, fp_t v);

/**
 * @brief Observe an extension-field element.
 *
 * Mirrors the FieldChallenger trait default
 * `observe_algebra_element` (Plonky3 challenger/src/lib.rs:106-108):
 *   self.observe_slice(alg_elem.as_basis_coefficients_slice());
 *
 * For Goldilocks² this is two `observe_fp` calls in basis order:
 * `c0` first, then `c1`. 16 bytes total. See design doc § 6.2.
 *
 * @param t  Non-NULL transcript.
 * @param v  Extension element (a + b·X).
 */
void dnac_transcript_observe_fp2(dnac_transcript_t *t, fp2_t v);

/* ============================================================================
 * Sample (extract challenges)
 * ========================================================================== */

/**
 * @brief Sample one base-field challenge via rejection sampling.
 *
 * Mirrors `SerializingChallenger64::sample` for `F = Goldilocks`
 * (Plonky3 serializing_challenger.rs:327-346): repeatedly read 8 LIFO
 * bytes from the inner challenger, assemble as little-endian u64, and
 * accept iff the result is in [0, p). For Goldilocks the
 * `pow_of_two_bound` mask is `0xFFFF_FFFF_FFFF_FFFF` (log2_ceil_u64(p) =
 * 64), i.e. a no-op; see design doc § 7.1.
 *
 * Rejected 8-byte groups are CONSUMED (not re-read) — invariant D9.
 *
 * @param t  Non-NULL transcript.
 * @return   Canonical field element in [0, p).
 */
fp_t dnac_transcript_sample_fp(dnac_transcript_t *t);

/**
 * @brief Sample one extension-field challenge.
 *
 * Mirrors `CanSample<GoldFp2>::sample` on `SerializingChallenger64`
 * (Plonky3 serializing_challenger.rs:321-346 with `EF = fp2`):
 * `EF::from_basis_coefficients_fn(|_| sample_base(...))`. For
 * Goldilocks² this is exactly two `sample_fp` calls in basis order.
 *
 * @param t  Non-NULL transcript.
 * @return   Extension element (c0 + c1·X).
 */
fp2_t dnac_transcript_sample_fp2(dnac_transcript_t *t);

/**
 * @brief Sample `bits` random bits as a low-bits-masked u64.
 *
 * Mirrors `SerializingChallenger64::sample_bits` from Plonky3
 * serializing_challenger.rs:348-359:
 *   u64::from_le_bytes(inner.sample_array::<8>()) & ((1u64 << bits) - 1)
 *
 * Always consumes 8 bytes (LIFO from the output buffer, possibly
 * triggering a flush). For `bits == 0` returns 0 but STILL consumes 8
 * bytes — this contrasts with `check_witness(0, _)` which is a no-op
 * (design doc § 7.3 + § 8.1).
 *
 * Precondition: `bits < 64`. Asserted.
 *
 * @param t     Non-NULL transcript.
 * @param bits  Bit width in [0, 63].
 * @return      Random integer in [0, 2^bits).
 */
uint64_t dnac_transcript_sample_bits(dnac_transcript_t *t, size_t bits);

/* ============================================================================
 * Grinding witness check
 * ========================================================================== */

/**
 * @brief Verify a proof-of-work witness against the transcript.
 *
 * Mirrors `GrindingChallenger::check_witness` default body (Plonky3
 * challenger/src/grinding_challenger.rs:39-46):
 *   if bits == 0 { return true; }
 *   self.observe(witness);
 *   self.sample_bits(bits) == 0
 *
 * Critical short-circuit (design doc § 8.1, invariant D8, red-team R6):
 * for `bits == 0` the function returns `true` WITHOUT observing the
 * witness and WITHOUT sampling. Transcript state is unchanged. Any
 * implementation that "always observes" silently desyncs from the
 * prover and is a ship-blocker.
 *
 * @param t        Non-NULL transcript.
 * @param bits     PoW difficulty in [0, 63].
 * @param witness  Field element supplied by the prover as the witness.
 * @return         true iff the witness is accepted at the requested bits.
 */
bool dnac_transcript_check_witness(dnac_transcript_t *t, size_t bits, fp_t witness);

/* ============================================================================
 * Test-only state inspection (Phase T3 replay support)
 *
 * Compiled in ONLY when DNAC_TRANSCRIPT_TESTING is defined. Production
 * verifier builds MUST omit this define. The Phase T3 replay test
 * (`tools/vectors/transcript.json`) uses these to compare against the
 * `input_buf` and `output_buf_remaining` snapshot fields per design doc
 * § 13.2.
 * ========================================================================== */

#ifdef DNAC_TRANSCRIPT_TESTING

/** Pointer to the current `input_buffer` contents (read-only). */
const uint8_t *dnac_transcript_test_input_buf_ptr(const dnac_transcript_t *t);

/** Length of the current `input_buffer` contents. */
size_t         dnac_transcript_test_input_buf_len(const dnac_transcript_t *t);

/** Pointer to the underlying 64-byte output_buffer (storage order;
 *  LIFO pop is from the end of the still-valid prefix). */
const uint8_t *dnac_transcript_test_output_buf_ptr(const dnac_transcript_t *t);

/** Number of bytes still poppable from output_buffer (= storage prefix
 *  length, i.e. `output_buf[0..remaining]` is the same byte sequence the
 *  `output_buf_remaining` field of a transcript.json snapshot encodes). */
size_t         dnac_transcript_test_output_buf_remaining(const dnac_transcript_t *t);

#endif /* DNAC_TRANSCRIPT_TESTING */

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_TRANSCRIPT_H */
