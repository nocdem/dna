/**
 * @file duplex_challenger.h
 * @brief Poseidon2 DuplexChallenger over Goldilocks, width 8 / rate 4 (P1a).
 *
 * Grounded C port of Plonky3 @ 82cfad73:
 *   DuplexChallenger<Goldilocks, Poseidon2Goldilocks<8>, WIDTH=8, RATE=4>
 * (challenger/src/duplex_challenger.rs) with the GrindingChallenger surface
 * (challenger/src/grinding_challenger.rs). Types per the canonical Goldilocks
 * Poseidon2 STARK config (keccak-air/examples/prove_goldilocks_poseidon2.rs:57);
 * permutation INSTANCE = default_goldilocks_poseidon2_8()
 * (goldilocks/src/poseidon2.rs:570) = the byte-matched
 * `poseidon2_goldilocks8_permute` — NOT the example's SmallRng instance
 * (P1 design doc §0 F4 pin).
 *
 * Pinned semantics (P1 design doc §0, 2026-07-22 v2):
 *   - observe: CLEARS output_buffer, buffers the field element, duplexes
 *     EAGERLY when the buffer reaches RATE (duplex_challenger.rs:148-157).
 *   - duplexing: OVERWRITE state[0..input_len] (not add), permute the full
 *     width-8 state, output_buffer = state[0..RATE] (:86-99).
 *   - sample: pops from the END of output_buffer (LIFO — first sample after a
 *     duplex is state[RATE-1], NOT state[0]; :243-245, unit test :677-682);
 *     duplexes first if input is pending or output is empty (:235-247).
 *   - sample_fp2: EF::from_basis_coefficients_fn => two base pops, c0 first.
 *   - sample_bits: ONE field sample -> canonical u64 -> low-bit mask
 *     (:264-270).
 *   - check_witness: bits==0 => early true, NO observe, NO sample; else
 *     observe(witness-as-field) then sample_bits(bits)==0
 *     (grinding_challenger.rs:40-46, Witness = F :104).
 *   - grind: bits==0 => witness 0, state untouched (:116-119); else the LEAST
 *     witness w = 0,1,2,... passing check_witness, applied to the transcript.
 *     (Least-witness is the DNAC determinization contracted since the SHA3
 *     transcript — Plonky3's rayon find_map_any returns ANY witness; per-witness
 *     semantics are identical and any passing witness verifies.)
 *
 * Production initial state (G-SEC-P1-7, user-locked 2026-07-22): the approved
 * Q1 domain separator "DNAC|ZK|FRI|TRANSCRIPT|V1" (25 ASCII bytes) encoded as
 * 4 little-endian u64 limbs (8-byte chunks, last zero-padded; all canonical)
 * and PRE-ABSORBED as the first 4 observes of every production transcript —
 * exactly one RATE block => one permutation. This is a DECLARED DNAC-owned
 * deviation (DuplexChallenger::new has no initial-state hook,
 * duplex_challenger.rs:71-84); the Rust oracle observes the same prefix, so
 * byte-match evidence covers it.
 *
 * Byte-match gate: tools/vectors/duplex_challenger.json
 * (`plonky3_oracle dump-duplex-challenger`, 12 scenarios / full state
 * snapshots) + tests/test_duplex_challenger.c.
 *
 * WIRED (P1c, 2026-07-22): this is the LIVE proof-internal challenger — the
 * transcript.h wrapper is a thin heap wrapper over dnac_duplex_t, and every
 * production prover + the shielded verifier prime via dnac_transcript_init_default
 * (DS-prefix pre-absorb). The SHA3 HashChallenger was deleted at P1c.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_DUPLEX_CHALLENGER_H
#define DNAC_ZK_DUPLEX_CHALLENGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Sponge width (state size) — DuplexChallenger WIDTH const generic. */
#define DNAC_DUPLEX_WIDTH 8

/** Sponge rate — DuplexChallenger RATE const generic (capacity = 4 lanes
 *  = 2^128 target, matching the note_commit sponge rationale). */
#define DNAC_DUPLEX_RATE 4

/** Production DS prefix limbs (G-SEC-P1-7): "DNAC|ZK|FRI|TRANSCRIPT|V1" as
 *  4 LE u64 chunks, zero-padded. Values pinned in the P1 design doc §0 and
 *  cross-checked against the oracle vector's `ds_prefix` field by the KAT. */
extern const uint64_t DNAC_DUPLEX_DS_PREFIX[DNAC_DUPLEX_RATE];

/**
 * @brief DuplexChallenger state. All lanes canonical Goldilocks (< p).
 *
 * Transparent (not opaque) by design: fixed-size, no heap, clone = struct
 * assignment (used by grind), and the byte-match KAT snapshots the fields
 * directly. Mirrors the pub fields of the Rust struct
 * (duplex_challenger.rs:30-64).
 */
typedef struct {
    uint64_t sponge_state[DNAC_DUPLEX_WIDTH]; /**< full sponge state */
    uint64_t input_buffer[DNAC_DUPLEX_RATE];  /**< observed, not yet absorbed */
    size_t   input_len;                       /**< elements in input_buffer */
    uint64_t output_buffer[DNAC_DUPLEX_RATE]; /**< squeezed outputs, storage
                                                   order; pop from END (LIFO) */
    size_t   output_len;                      /**< still-poppable count */
} dnac_duplex_t;

/** Zero-state constructor — DuplexChallenger::new (duplex_challenger.rs:71-84):
 *  all-zero sponge state, empty buffers. Use ONLY for oracle-parity tests;
 *  production paths use dnac_duplex_init_default. */
void dnac_duplex_init(dnac_duplex_t *c);

/** Production constructor: init + pre-absorb the 4 DS prefix limbs (exactly
 *  one RATE block => one permutation fires). G-SEC-P1-7. */
void dnac_duplex_init_default(dnac_duplex_t *c);

/** Observe one base-field element (duplex_challenger.rs:148-157): clears
 *  output_buffer, buffers v (canonicalized), eager duplex at RATE. */
void dnac_duplex_observe_fp(dnac_duplex_t *c, gold_fp_t v);

/** Observe an extension element = c0 then c1 (observe_algebra_element,
 *  challenger/src/lib.rs:106-108: basis-coefficient order). */
void dnac_duplex_observe_fp2(dnac_duplex_t *c, gold_fp2_t v);

/** Sample one base-field challenge (duplex_challenger.rs:235-247): duplex if
 *  input pending or output empty, then LIFO pop. Returns canonical. */
gold_fp_t dnac_duplex_sample_fp(dnac_duplex_t *c);

/** Sample one extension challenge = two base samples, c0 first
 *  (EF::from_basis_coefficients_fn order). */
gold_fp2_t dnac_duplex_sample_fp2(dnac_duplex_t *c);

/**
 * @brief Sample `bits` random bits (duplex_challenger.rs:264-270).
 *
 * ONE base sample -> canonical u64 -> mask low `bits`. bits==0 returns 0 but
 * STILL consumes a sample (mask is 0) — mirrors the Rust body; contrast
 * check_witness(0,_) which is a full no-op.
 *
 * Preconditions (Rust asserts, here fail-close abort): bits < 64 and
 * (1u64 << bits) < p — for Goldilocks every bits <= 63 satisfies the order
 * bound, so the effective precondition is bits < 64.
 */
uint64_t dnac_duplex_sample_bits(dnac_duplex_t *c, size_t bits);

/** PoW witness check (grinding_challenger.rs:40-46): bits==0 => true with NO
 *  state change; else observe(witness) then sample_bits(bits)==0. State
 *  advances on failure too (the observe+sample happened). */
bool dnac_duplex_check_witness(dnac_duplex_t *c, size_t bits, gold_fp_t witness);

/** PoW grind: least witness w with check_witness(bits, w) true, applied to
 *  `c` (observe + sample). bits==0 => returns 0, state untouched
 *  (grinding_challenger.rs:116-119). See header note on the least-witness
 *  determinization. */
gold_fp_t dnac_duplex_grind(dnac_duplex_t *c, size_t bits);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_DUPLEX_CHALLENGER_H */
