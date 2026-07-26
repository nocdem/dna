/**
 * @file batch_prover.h
 * @brief Batched STARK prover — port of Plonky3 batch-stark `prove_batch`
 *        (P2L-d d3, in-memory entry; the DZKF v4 wire codec lands at d4).
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 * Source of truth: batch-stark/src/prover.rs:96-670 (prove_batch +
 * quotient_values), fri/src/hiding_pcs.rs (commit :106-132, get_quotient_ldes
 * :169-257, commit_preprocessing :134-153, randomization poly :404-424, open
 * split :314-359), fri/src/two_adic_pcs.rs (plain commit :301-325, plain
 * get_quotient_ldes :327-349, open :402-673), fri/src/prover.rs (prove_fri
 * :44-140, commit_phase :171-266 incl. the :238-245 roll-in, answer_query
 * :286-343, open_input :357-387). P2-lookup design 2026-07-23 §4 P2L-d.
 *
 * Pipeline (prove_batch order, 1:1 — the transcript calls interleave with the
 * commits exactly as in the reference; the composed dnac_batch_priming_run
 * cannot be used here because it wants every commit upfront):
 *   1. observe instance count + bindings          (prover.rs:200-209)
 *   2. MAIN commit: per instance [zk: randomize trace via with_random_cols
 *      layout, draws consumed IN ORDER] → coset LDE (bitrev) → ONE
 *      mixed-height Poseidon2 commit               (:211-219, d1a commit_mixed)
 *   3. observe main + publics; observe preprocessed widths + commit
 *      (preprocessed commit = commit_preprocessing: zk pads with ZERO rows,
 *      no draws)                                   (:221-222)
 *   4. sample per-instance (α,β) via the P2L-b bus memo (:227)
 *   5. permutation traces: logup generate_permutation → flatten to base
 *      ([c0,c1] per EF cell) → [zk: randomize, draws] → LDE → mixed commit
 *                                                  (:229-302)
 *   6. observe perm commit + cumulative sums, sample constraint-α (:305-308)
 *   7. per-instance quotient: selectors_on_coset over the disjoint domain
 *      (shift GENERATOR) → per-point constraint chain (air.eval FIRST then
 *      lookups, ONE serial Horner stream acc = acc·α + C_i — VALUE-EQUAL to
 *      decompose_alpha's α^{K−1−i} emission-order weights, air/src/symbolic/
 *      builder.rs:401-423; perm window rows (i, i+next_step) mod q_rows,
 *      prover.rs:850-868) → ·inv_vanishing (:911) → flatten + round-robin
 *      split → chunk LDEs ([zk: +1 blowup + codeword cols + blinding tail,
 *      hiding_pcs.rs:169-257; draws]; plain: log_blowup, no randomization)
 *      → ONE mixed commit over ALL instances' chunks (:319-420)
 *   8. observe quotient commit; [zk: R matrices from draws → LDE → mixed
 *      commit → observe]; sample ζ                 (:421-447)
 *   9. N2 opening rounds ([random] → main → quotient → [preprocessed] →
 *      [permutation]) — per (round, matrix, point): barycentric open of the
 *      FULL committed width (incl. zk codeword columns), observe ALL opened
 *      values in order (two_adic_pcs.rs:546), THEN split the codeword tails
 *      into the hiding rand-openings (hiding_pcs.rs:333-358; the
 *      preprocessed round splits 0)                (:450-537)
 *  10. FRI: per-height reduced openings (independent alpha counters per
 *      height, two_adic_pcs.rs:588-658) → mixed commit phase with roll-in →
 *      query phase (sample_bits; per query: per-round mixed input openings at
 *      reduced indices + answer_query chain)       (fri/src/prover.rs)
 *  11. SELF-VERIFY: the assembled proof must pass dnac_batch_verify
 *      (fail-close DNAC_PROVER_ERR_VERIFY otherwise).
 *
 * Randomness (v3 design pin D1-B carried over): the caller supplies the FULL
 * SmallRng-consumption-order draw stream (KAT: the oracle batch_proof.json
 * zk_rng dump; production: OS entropy). Draw order is pinned at source —
 * B1 main (h·(w+2·nrc) per instance, dense.rs:573-597) → [perm, same layout
 * over the flattened aux] → B2 per-instance quotient (chunk cols then
 * blinding tail, hiding_pcs.rs:186-199) → B3 R (ext_h·(nrc+DIM) per
 * instance, dense.rs:527-533). Hiding depends on it; soundness does not.
 *
 * SALTED mode (d4.c, M3b hiding leaves): salt_elems > 0 commits every
 * in-prove input matrix with SE appended salt lanes (leaf = row ‖ salts,
 * hiding_mmcs.rs:167-170; salts drawn per commit call, per matrix in order,
 * lde rows × SE row-major — the v3 stream-A layout, stark_prover_agg.c
 * :713-720) and salts the FRI commit-phase leaves from the INDEPENDENT
 * stream B (P1e-HIGH1; NULL falls back to salt_draws@0 — the oracle
 * clone-seed parity). FAIL-CLOSE: salted+preprocessed is rejected (the
 * reference commits preprocessed at SETUP time, common.rs — its salt-stream
 * position is not exercised by any vector) and salted+lookups is rejected
 * (no byte-match vector yet; lift when a salted+permutation vector lands).
 *
 * NOT in scope here: wire encode (see fri_proof_codec.h DZKF v4).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_BATCH_PROVER_H
#define DNAC_BATCH_PROVER_H

#include <stddef.h>
#include <stdint.h>

#include "batch_verify.h"
#include "stark_prover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Witness for one instance: canonical u64 row-major base traces. Heights are
 * derived from the paired dnac_batch_vinstance_t (base_h = 1 << (degree_bits
 * − is_zk)); widths from air.main_width / preprocessed_width. */
typedef struct {
    const uint64_t *main_trace; /* [base_h][main_width]                     */
    const uint64_t *prep_trace; /* [base_h][preprocessed_width] or NULL     */
} dnac_batch_pwitness_t;

/** Opaque batched proof: owns every buffer referenced by the assembled
 *  proof/opened/rand-openings. Free with dnac_batch_proof_free. */
typedef struct dnac_batch_proof_s dnac_batch_proof_t;

/**
 * Prove a batch of instances and self-verify.
 *
 * @param insts        Per-instance descriptions (airs + lookups + geometry —
 *                     the SAME struct dnac_batch_verify consumes; degree_bits
 *                     INCLUDES the ZK +1).
 * @param wits         Per-instance witness traces.
 * @param num_instances 1..32.
 * @param is_zk        0 or 1 (HidingFriPcs).
 * @param fri_params   FRI parameters.
 * @param num_random_codewords  >0 iff is_zk (fixtures: 4).
 * @param draws        SmallRng-consumption-order random stream iff is_zk
 *                     (each < p), else NULL.
 * @param num_draws    must equal the derived total iff is_zk, else 0.
 * @param salt_draws   M3b input-MMCS salt stream A iff salt_elems > 0
 *                     (>= dnac_batch_prove_num_salt_draws), else NULL.
 * @param num_salt_draws  stream A length (0 when unsalted).
 * @param fri_salt_draws  FRI-MMCS salt stream B, or NULL => fall back to
 *                     salt_draws@0 (oracle clone-seed parity; production
 *                     MUST pass an INDEPENDENT entropy region, P1e-HIGH1).
 * @param num_fri_salt_draws  stream B length (0 when NULL/unsalted).
 * @param salt_elems   0 = plain leaves (byte-identical to pre-d4.c);
 *                     > 0 = salted leaves (consensus pin: the caller pins
 *                     the value — DNAC_SHIELDED_SALT_ELEMS at the shielded
 *                     entry, G-SEC-P1-6).
 * @param out_proof    receives the owned proof (already self-verified).
 */
dnac_prover_status_t dnac_batch_prove(
    const dnac_batch_vinstance_t *insts,
    const dnac_batch_pwitness_t  *wits,
    uint32_t                      num_instances,
    int                           is_zk,
    const dnac_fri_params_t      *fri_params,
    uint32_t                      num_random_codewords,
    const uint64_t               *draws,
    size_t                        num_draws,
    const uint64_t               *salt_draws,
    size_t                        num_salt_draws,
    const uint64_t               *fri_salt_draws,
    size_t                        num_fri_salt_draws,
    size_t                        salt_elems,
    dnac_batch_proof_t          **out_proof);

/** The derived draw total for a batch (0 when !is_zk) — for callers filling
 *  production entropy. Returns SIZE_MAX on inconsistent inputs. */
size_t dnac_batch_prove_num_draws(const dnac_batch_vinstance_t *insts,
                                  uint32_t num_instances, int is_zk,
                                  uint32_t num_random_codewords);

#ifdef DNAC_ZK_ENABLE_TEST_WIRE
/** C2.1 CRIT-1 isolating forge (test-wire ONLY — absent from consensus builds).
 *  Identical to dnac_batch_prove except instance-0's Fiat-Shamir/priming publics
 *  are `fs_pub_override` (insts[0].num_publics wide) while the quotient folds the
 *  TRUE insts[0].public_values; self-verify is skipped. The proof passes FRI but
 *  FAILS the N-chunk constraint check at the true publics. */
dnac_prover_status_t dnac_batch_prove_forged_fs_testonly(
    const dnac_batch_vinstance_t *insts,
    const dnac_batch_pwitness_t  *wits,
    uint32_t                      num_instances,
    int                           is_zk,
    const dnac_fri_params_t      *fri_params,
    uint32_t                      num_random_codewords,
    const uint64_t               *draws,
    size_t                        num_draws,
    const uint64_t               *salt_draws,
    size_t                        num_salt_draws,
    const uint64_t               *fri_salt_draws,
    size_t                        num_fri_salt_draws,
    size_t                        salt_elems,
    const gold_fp_t              *fs_pub_override,
    dnac_batch_proof_t          **out_proof);
#endif /* DNAC_ZK_ENABLE_TEST_WIRE */

/** The derived stream-A salt total (main + quotient + [random] commits, per
 *  matrix lde rows × salt_elems). 0 when salt_elems == 0; SIZE_MAX on
 *  inconsistent inputs. Stream B needs >= salt_elems << log_gmh (the
 *  commit-phase layer-height sum bound). */
size_t dnac_batch_prove_num_salt_draws(const dnac_batch_vinstance_t *insts,
                                       uint32_t num_instances, int is_zk,
                                       size_t log_blowup, size_t salt_elems);

/* ── accessors (borrowed views into the owned proof) ── */

/** Commit lanes (4 gold_fp_t each; absent commits are NULL). */
void dnac_batch_proof_commits(const dnac_batch_proof_t *p,
                              dnac_batch_vcommits_t    *out);

/** Per-instance opened values (BatchProof shape, unmerged). */
const dnac_batch_vopened_t *dnac_batch_proof_opened(
    const dnac_batch_proof_t *p, uint32_t instance);

/** The FRI opening proof. */
const dnac_fri_proof_t *dnac_batch_proof_fri(const dnac_batch_proof_t *p);

/** Random-codeword openings (NULL when !is_zk). */
const dnac_batch_rand_openings_t *dnac_batch_proof_rand_openings(
    const dnac_batch_proof_t *p);

/** Preprocessed matrix→instance map (num may be 0). */
const uint32_t *dnac_batch_proof_prep_map(const dnac_batch_proof_t *p,
                                          uint32_t *out_num);

/** The sampled constraint-α and ζ (byte-match targets). */
void dnac_batch_proof_alpha_zeta(const dnac_batch_proof_t *p,
                                 gold_fp2_t *alpha, gold_fp2_t *zeta);

/** Copy query indices into out[0..min(nq,max)); returns nq. */
size_t dnac_batch_proof_query_indices(const dnac_batch_proof_t *p,
                                      uint64_t *out, size_t max);

void dnac_batch_proof_free(dnac_batch_proof_t *p);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_BATCH_PROVER_H */
