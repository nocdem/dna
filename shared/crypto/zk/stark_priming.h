/**
 * @file stark_priming.h
 * @brief STARK/PCS transcript-priming helper (DNAC v3 ZK stack, Phase B8 / P3).
 *
 * Produces the "milestone-0 seed": the Fiat-Shamir transcript state that
 * `dnac_fri_verify` (fri_verifier.h) consumes. It is the STARK/PCS front-half of
 * Plonky3 `p3_uni_stark::verify` up to — but NOT including — the call into
 * `verify_fri`. This module is transcript priming ONLY: it does NOT verify
 * constraints, recompose the quotient, or run FRI (those are the deferred STARK
 * verifier wrapper, design § 6 scope fence).
 *
 * Strict mirror of Plonky3 at pinned commit
 *   82cfad73cd734d37a0d51953094f970c531817ec:
 *     uni-stark/src/verifier.rs:360-391  (instance + commitment + public observes,
 *                                          sample alpha, sample zeta)
 *     uni-stark/src/verifier.rs:398       (zeta_next = init_trace_domain.next_point)
 *     fri/src/two_adic_pcs.rs:687-693      (PCS observe opened values)
 *     challenger/src/serializing_challenger.rs (byte serialization)
 *
 * Validated by tools/vectors/stark_priming.json — produced by a REAL
 * p3_uni_stark::prove over a vendored FibonacciAir (oracle choice A) — replayed
 * in tests/test_stark_priming.c (byte-match of the primed transcript +
 * alpha/zeta/zeta_next).
 *
 * Source of truth: docs/plans/2026-05-30-pcs-transcript-priming-design.md.
 *
 * Field choice (LOCKED, project_v3_zk_bitcoin_style): Val = Goldilocks,
 * Challenge = Goldilocks², hash/transcript = SHA3-512. DNAC v3.0 is NON-ZK
 * (TwoAdicFriPcs::ZK = false, two_adic_pcs.rs:279).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_PRIMING_H
#define DNAC_ZK_STARK_PRIMING_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h" /* gold_fp_t (Val), gold_fp2_t (Challenge) */
#include "merkle_smt.h"       /* dnac_merkle_digest_t (MerkleCap root)   */
#include "transcript.h"       /* dnac_transcript_t (Fiat-Shamir state)   */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 1. Status enum
 *
 * Separate from `dnac_fri_status_t` (fri_verifier.h), which is a byte-exact
 * Plonky3 FriError mirror and MUST NOT be reused or modified. Null arguments are
 * a caller PRECONDITION (assert), never a status — matching the fri_verifier
 * pure-mirror convention.
 * ========================================================================== */
typedef enum {
    DNAC_STARK_PRIMING_OK = 0,
    /* is_zk != 0. DNAC v3.0 is non-ZK; the ZK random-commitment branch
     * (verifier.rs:382-386) must never execute. ZK support is a future change
     * with its own design + vectors. */
    DNAC_STARK_PRIMING_ERR_ZK_UNSUPPORTED = 1
} dnac_stark_priming_status_t;

/* ============================================================================
 * 2. Priming input
 *
 * The STARK `Proof`'s pre-FRI portion (uni-stark/proof.rs:18-25 minus
 * `opening_proof`), plus the two config scalars the verifier owns.
 *
 * WIRE-TRUST boundary (design § 8): of the three instance scalars, only
 * `degree_bits` is wire-carried. `is_zk` and `preprocessed_width` are config
 * constants supplied by the AIR/verifier and MUST NOT be trusted from a proof
 * wire — wiring them is the same trust hazard as trusting a wire-supplied `zeta`.
 * `base_degree_bits` is DERIVED (degree_bits - is_zk, verifier.rs:52), never an
 * input field.
 * ========================================================================== */
typedef struct {
    size_t degree_bits;        /* observed; the one wire-carried instance scalar */
    size_t is_zk;              /* config: 0 for v3.0 (TwoAdicFriPcs::ZK=false)    */
    size_t preprocessed_width; /* config (AIR): 0 for range_air / FibonacciAir    */

    /* Commitments — MerkleCap roots; cap_height=0 ⇒ observed as raw 64 bytes
     * (CanObserve<MerkleCap<F,[u64;8]>>, serializing_challenger.rs:301-311). */
    dnac_merkle_digest_t        trace_commit;     /* verifier.rs:369 */
    dnac_merkle_digest_t        quotient_commit;  /* verifier.rs:380 */
    const dnac_merkle_digest_t *preprocessed_commit; /* non-NULL iff preprocessed_width>0 */

    /* Public values — base-field Goldilocks, fixed AIR public-input order
     * (verifier.rs:373). NOT extension elements. */
    const gold_fp_t *public_values;
    size_t           num_public_values;

    /* Opened values (claimed evaluations) — observed at the PCS layer
     * (two_adic_pcs.rs:687-693), in coms_to_verify order. */
    const gold_fp2_t        *trace_local;       /* @ zeta                        */
    size_t                   trace_local_len;
    const gold_fp2_t        *trace_next;         /* @ zeta_next; NULL iff main_next==false */
    size_t                   trace_next_len;
    const gold_fp2_t *const *quotient_chunks;    /* [chunk][coeff], each @ zeta   */
    const size_t            *quotient_chunk_lens;
    size_t                   num_quotient_chunks;
    const gold_fp2_t        *preprocessed_local;  /* non-NULL iff preprocessed_width>0 */
    size_t                   preprocessed_local_len;
    const gold_fp2_t        *preprocessed_next;   /* may be NULL */
    size_t                   preprocessed_next_len;
} dnac_stark_priming_input_t;

/* ============================================================================
 * 3. Priming output
 *
 * The three verifier-DERIVED challenges + base_degree_bits. Together with the
 * caller's commitments + opened values, this is enough to assemble the
 * CommitmentWithOpeningPoints fed to `dnac_fri_verify`:
 *   - trace round opens at (zeta, trace_local) [+ (zeta_next, trace_next) if present]
 *     over the trace domain (natural, shift=ONE, log_size = base_degree_bits);
 *   - each quotient chunk opens at (zeta, chunk) over its randomized opening
 *     domain (natural_domain_for_degree(chunk_size), shift=ONE — NEVER the
 *     create_disjoint/split domains, which are recompose-only; verifier.rs:314-317).
 *
 * `zeta` / `zeta_next` are verifier-derived; a wire-supplied opening coordinate
 * `z` must NEVER be trusted (design § 5 note C, Security-G3).
 * ========================================================================== */
typedef struct {
    gold_fp2_t alpha;            /* STARK constraint-combining challenge (verifier.rs:379) */
    gold_fp2_t zeta;             /* out-of-domain opening point          (verifier.rs:391) */
    gold_fp2_t zeta_next;        /* zeta · two_adic_generator(base_degree_bits) (verifier.rs:398) */
    size_t     base_degree_bits; /* derived: degree_bits - is_zk */
} dnac_stark_priming_out_t;

/* ============================================================================
 * 4. Entry point
 *
 * Drives the priming sequence on `transcript` (caller-initialised, e.g. via
 * `dnac_transcript_init_default()`), advancing it in place to the verify_fri
 * entry state, and fills `out` with the sampled challenges. The transcript is
 * then ready to be handed to `dnac_fri_verify`.
 *
 * Determinism: the observe/sample order is a fixed total order; identical input
 * ⇒ byte-identical primed state (design § 1, BFT consensus path).
 *
 * Preconditions (assert): transcript, input, out all non-NULL; if
 * preprocessed_width>0 then preprocessed_commit non-NULL.
 *
 * @return DNAC_STARK_PRIMING_OK, or DNAC_STARK_PRIMING_ERR_ZK_UNSUPPORTED if
 *         is_zk != 0.
 * ========================================================================== */
dnac_stark_priming_status_t dnac_stark_prime_transcript(
    dnac_transcript_t                *transcript,
    const dnac_stark_priming_input_t *input,
    dnac_stark_priming_out_t         *out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_PRIMING_H */
