/**
 * @file stark_prover_prove.h
 * @brief C STARK prover — P1: instance-generic end-to-end prove + assemble.
 *
 * The library-level top of the C prover. `dnac_prover_prove` takes an arbitrary
 * valid RangeProofAir instance (any n_real / power-of-two height ≤ 1024),
 * derives EVERY shape from the instance (base_degree_bits, degree_bits,
 * log_max_height, num_qc, num FRI rounds, query index width, coms domains,
 * Merkle depths — all from `height`, per the P1 grounding, Plonky3 82cfad73),
 * runs the full S1→S12 stage pipeline, assembles a `dnac_fri_proof_t` + 3-round
 * coms + priming input from its own outputs, and SELF-VERIFIES
 * (`dnac_stark_prime_transcript` → cross-check out.zeta == prover zeta →
 * `dnac_fri_verify == DNAC_FRI_OK`) before returning.
 *
 * This generalizes the M3a-hardcoded S13 test scaffolding (which baked in
 * LOG_H=5, NUM_QUERIES=2, single FRI round, degree_bits=3, depths 5/4). An
 * n_real=8 instance exercises the multi-round FRI commit phase + generalized
 * `answer_query` — the paths the S13 red-team flagged as byte-unverified.
 *
 * Randomness (design pin D1-B): the caller supplies the full SmallRng-order
 * draw stream (KAT: oracle dump; production: OS entropy). Hiding (G2) depends
 * on it; soundness does not.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_PROVER_PROVE_H
#define DNAC_ZK_STARK_PROVER_PROVE_H

#include <stddef.h>
#include <stdint.h>

#include "fri_verifier.h"
#include "stark_prover.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Total SmallRng draws consumed for a fully-populated is_zk=1 RangeProofAir
 *  instance of the given base height (P1 grounding G6): 110·height. */
#define DNAC_PROVER_TOTAL_DRAWS(height) ((size_t)110 * (size_t)(height))

/**
 * A prove request. `amounts[0..n_real)` are the output amounts (each < 2^52);
 * `height` is the padded trace height (power of two, n_real ≤ height ≤ 1024);
 * `fee` is the committed fee (public). `draws` is the caller's random stream in
 * SmallRng consumption order (length must equal DNAC_PROVER_TOTAL_DRAWS(height),
 * each < Goldilocks p): trace(64h) ‖ codeword(16h) ‖ blinding(18h) ‖ R(12h).
 */
typedef struct {
    const uint64_t *amounts;
    size_t          n_real;
    size_t          height;
    uint64_t        fee;
    const uint64_t *draws;
    size_t          num_draws;
} dnac_prover_instance_t;

/** Opaque produced proof: owns all storage referenced by the assembled
 *  proof/coms/priming. Free with `dnac_prover_proof_free`. */
typedef struct dnac_prover_proof_s dnac_prover_proof_t;

/**
 * Prove an arbitrary valid instance and self-verify.
 *
 * On success `*out_proof` owns a proof that already passed
 * `dnac_fri_verify == DNAC_FRI_OK`. Returns DNAC_PROVER_ERR_PARAM on a bad
 * instance (non-power-of-two height, n_real out of range, wrong draw count,
 * amount ≥ 2^52), DNAC_PROVER_ERR_NONCANONICAL on a non-canonical draw, or
 * DNAC_PROVER_ERR_VERIFY if the self-verify unexpectedly fails (an internal
 * inconsistency — the prover rejects its own broken proof, fail-close).
 */
dnac_prover_status_t dnac_prover_prove(
    const dnac_prover_instance_t *inst,
    dnac_prover_proof_t         **out_proof);

/**
 * Re-verify a produced proof (idempotent; prove already self-verified). Returns
 * DNAC_FRI_OK on success. Useful for an independent verify pass.
 */
dnac_fri_status_t dnac_prover_proof_verify(const dnac_prover_proof_t *p);

/** Instance shape accessors (derived, for tests / callers). */
size_t dnac_prover_proof_degree_bits(const dnac_prover_proof_t *p);
size_t dnac_prover_proof_num_fri_rounds(const dnac_prover_proof_t *p);
size_t dnac_prover_proof_log_max_height(const dnac_prover_proof_t *p);

/** Cross-check accessors: the prover's own zeta/zeta_next (Goldilocks^2) and
 *  the three commit roots — for byte-matching against a reference proof. */
void dnac_prover_proof_zeta(const dnac_prover_proof_t *p, gold_fp2_t *zeta,
                            gold_fp2_t *zeta_next);
void dnac_prover_proof_roots(const dnac_prover_proof_t *p,
                             uint8_t trace_root[DNAC_MERKLE_DIGEST_BYTES],
                             uint8_t quot_root[DNAC_MERKLE_DIGEST_BYTES],
                             uint8_t rand_root[DNAC_MERKLE_DIGEST_BYTES]);
/** The final_poly coefficients (final_poly_len fp2 values, borrowed). */
const gold_fp2_t *dnac_prover_proof_final_poly(const dnac_prover_proof_t *p,
                                               size_t *out_len);

/** Copy the sampled query indices into out[0..min(num_queries,max)); returns
 *  num_queries. For byte-matching the query phase against a reference proof. */
size_t dnac_prover_proof_query_indices(const dnac_prover_proof_t *p,
                                       uint64_t *out, size_t max);

void dnac_prover_proof_free(dnac_prover_proof_t *p);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_PROVER_PROVE_H */
