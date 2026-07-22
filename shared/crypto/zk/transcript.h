/**
 * @file transcript.h
 * @brief DNAC Fiat-Shamir transcript / challenger — Poseidon2 DuplexChallenger
 *        backend (P1c cutover, 2026-07-22).
 *
 * C port of the Plonky3 composition (82cfad73):
 *   DuplexChallenger<Goldilocks, Poseidon2Goldilocks<8>, WIDTH=8, RATE=4>
 * — the canonical Goldilocks Poseidon2 STARK challenger
 * (keccak-air/examples/prove_goldilocks_poseidon2.rs:57). This header is a
 * thin heap-handle wrapper over the byte-matched primitive in
 * duplex_challenger.{c,h} (P1a, KAT: tools/vectors/duplex_challenger.json).
 *
 * HISTORY / CUTOVER (G-SEC-P1-5): through P1b this was the SHA3-512
 * SerializingChallenger64<HashChallenger> port (a declared Plonky3-ungrounded
 * stopgap, 2026-05-26 design). P1c REPLACED the backend wholesale — the byte
 * observe surface (observe_bytes / byte init-state / 64-byte digests) is GONE:
 * DuplexChallenger observes FIELD ELEMENTS; Merkle digests are 4 Goldilocks
 * lanes observed lane-by-lane (MerkleCap observe, duplex_challenger.rs:
 * 186-210). There is no byte path left — a caller that needs one is a bug.
 *
 * Production initial state (G-SEC-P1-7, user-locked): the Q1 domain separator
 * "DNAC|ZK|FRI|TRANSCRIPT|V1" (25 ASCII bytes, kept exported below for
 * documentation/derivation checks) is PRE-ABSORBED as 4 LE u64 limbs — the
 * first 4 observes of every production transcript (exactly one RATE block).
 * See duplex_challenger.h DNAC_DUPLEX_DS_PREFIX. Declared DNAC-owned
 * deviation; the Rust oracle observes the same prefix.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_TRANSCRIPT_H
#define DNAC_ZK_TRANSCRIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "duplex_challenger.h"
#include "field_goldilocks.h"
#include "poseidon2_mmcs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Type aliases — the verifier API uses `fp_t` / `fp2_t`.
 * ========================================================================== */

/** Goldilocks base field element (alias of gold_fp_t for the verifier API). */
typedef gold_fp_t  fp_t;

/** Goldilocks² extension field element (alias of gold_fp2_t). */
typedef gold_fp2_t fp2_t;

/* ============================================================================
 * Constants
 * ========================================================================== */

/**
 * @brief The Q1 production domain-separator BYTES (documentation constant).
 *
 * Raw ASCII `DNAC|ZK|FRI|TRANSCRIPT|V1` — 25 bytes, no NUL. Under the
 * Poseidon2 backend this is NOT absorbed as bytes; its 4 LE u64 limbs
 * (DNAC_DUPLEX_DS_PREFIX) are the first 4 field observes of
 * dnac_transcript_init_default. Exported so derivation KATs can re-check
 * limbs-vs-bytes.
 */
extern const uint8_t  DNAC_TRANSCRIPT_PROD_INIT_STATE[];
extern const size_t   DNAC_TRANSCRIPT_PROD_INIT_STATE_LEN;

/* ============================================================================
 * Opaque context
 * ========================================================================== */

/** Opaque transcript handle — heap wrapper over dnac_duplex_t. */
typedef struct dnac_transcript_s dnac_transcript_t;

/* ============================================================================
 * Lifecycle
 * ========================================================================== */

/**
 * @brief Zero-state transcript — DuplexChallenger::new (all-zero sponge,
 *        empty buffers). ORACLE-PARITY / TEST use only; production paths use
 *        dnac_transcript_init_default (DS prefix).
 * @return Heap-allocated transcript, or NULL on allocation failure.
 */
dnac_transcript_t *dnac_transcript_init_empty(void);

/**
 * @brief Production transcript: zero state + the 4-limb DS prefix pre-absorb
 *        (G-SEC-P1-7; exactly one permutation fires). Use in ALL production
 *        prover/verifier paths.
 */
dnac_transcript_t *dnac_transcript_init_default(void);

/** Deep-copy (independent state). Used by the grinding search and codec
 *  probe paths. NULL on allocation failure. */
dnac_transcript_t *dnac_transcript_clone(const dnac_transcript_t *src);

/** Free a transcript. Safe on NULL. */
void dnac_transcript_free(dnac_transcript_t *t);

/* ============================================================================
 * Observe (absorb into the transcript) — FIELD ELEMENTS ONLY
 * ========================================================================== */

/** Observe one base-field element (duplex_challenger.rs:148-157: clears the
 *  output buffer, buffers the element, eager duplex at RATE=4). */
void dnac_transcript_observe_fp(dnac_transcript_t *t, fp_t v);

/** Observe an extension element = c0 then c1 (observe_algebra_element basis
 *  order, challenger/src/lib.rs:106-108). */
void dnac_transcript_observe_fp2(dnac_transcript_t *t, fp2_t v);

/** Observe a 4-lane Poseidon2 Merkle digest lane-by-lane (the MerkleCap /
 *  Hash<F,F,4> observe path, duplex_challenger.rs:186-210). Replaces the
 *  SHA3-era 64-byte commitment observe. */
void dnac_transcript_observe_digest(dnac_transcript_t *t,
                                    const dnac_p2_digest_t *d);

/* ============================================================================
 * Sample (extract challenges)
 * ========================================================================== */

/** Sample one base-field challenge (duplex if input pending or output empty,
 *  then LIFO pop — duplex_challenger.rs:235-247). Canonical result. */
fp_t dnac_transcript_sample_fp(dnac_transcript_t *t);

/** Sample one extension challenge = two base samples, c0 first
 *  (EF::from_basis_coefficients_fn order). */
fp2_t dnac_transcript_sample_fp2(dnac_transcript_t *t);

/**
 * @brief Sample `bits` random bits (duplex_challenger.rs:264-270): ONE base
 *        sample -> canonical u64 -> low-bit mask. bits==0 returns 0 but still
 *        consumes the sample; contrast check_witness(0,_) which is a full
 *        no-op. Precondition bits < 64 (fail-close abort).
 */
uint64_t dnac_transcript_sample_bits(dnac_transcript_t *t, size_t bits);

/* ============================================================================
 * Grinding (proof-of-work)
 * ========================================================================== */

/** PoW witness check (grinding_challenger.rs:40-46): bits==0 => true with NO
 *  state change; else observe(witness-as-field) then sample_bits(bits)==0.
 *  State advances on failure too. */
bool dnac_transcript_check_witness(dnac_transcript_t *t, size_t bits, fp_t witness);

/** PoW grind: the LEAST witness w with check_witness(bits, w) true, applied
 *  to `t`. bits==0 => witness 0, state untouched (grinding_challenger.rs:
 *  116-119). Least-witness is the DNAC determinization (Plonky3's parallel
 *  find_map_any returns ANY witness; any passing witness verifies). */
fp_t dnac_transcript_grind(dnac_transcript_t *t, size_t bits);

/* ============================================================================
 * Test-only state inspection
 *
 * Compiled ONLY under DNAC_TRANSCRIPT_TESTING. Exposes the underlying duplex
 * state so replay tests can compare sponge_state / buffers against oracle
 * milestone snapshots (field-lane form — the SHA3 byte-buffer accessors are
 * gone with the backend).
 * ========================================================================== */

#ifdef DNAC_TRANSCRIPT_TESTING
const dnac_duplex_t *dnac_transcript_test_duplex(const dnac_transcript_t *t);
#endif

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_TRANSCRIPT_H */
