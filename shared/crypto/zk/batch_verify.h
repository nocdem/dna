/**
 * @file batch_verify.h
 * @brief Batched STARK verify — port of Plonky3 batch-stark `verify_batch`
 *        (P2L-d d2, in-memory entry; the DZKF v4 wire codec lands at d4).
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 * Source of truth: batch-stark/src/verifier/mod.rs:29-646 (+ verifier/data.rs
 * verify_constraints_with_lookups), lookup/src/{folder.rs,protocol.rs,logup.rs},
 * fri/src/two_adic_pcs.rs:676-707 (PCS observe) + hiding_pcs.rs:361-402 (the
 * random-codeword merge). P2-lookup design 2026-07-23 §4 P2L-d.
 *
 * Pipeline (verifier/mod.rs order, 1:1):
 *   1. sanity + random-vs-ZK checks             (:60-84)
 *   2. per-instance shape validation             (:96-267, via
 *      dnac_batch_proof_shape_check + the binding arithmetic)
 *   3. full batched priming                      (:143-300, via
 *      dnac_batch_priming_run) → (α,β) per instance, constraint-α, ζ
 *   4. opening-round assembly (N2 order)         (:302-499):
 *        [Round 0 random iff is_zk (each instance @ ζ)] → Round 1 main
 *        (ζ, + g·ζ iff main_next) → Round 2 quotient chunks (ζ) →
 *        [Round 3 preprocessed (ζ, + g·ζ iff prep_next; matrix order =
 *        matrix_to_instance)] → [Round 4 permutation (ζ AND g·ζ, always)]
 *      Every matrix's opening domain has log_size = degree_bits[i]
 *      (ext): random/main/permutation open on the EXT trace domain
 *      (:316-356, :474-499), each quotient chunk's randomized domain is
 *      natural_domain_for_degree(((1<<(ext_db+lq)) / 2^(lq+is_zk)) << is_zk)
 *      = 2^ext_db (:360-385), preprocessed = 2^meta_db = 2^ext_db (:447).
 *      ζ_next(i) = ζ · two_adic_generator(degree_bits[i] − is_zk)
 *      (:341-343; base trace domain, :306-310).
 *   5. hiding merge iff is_zk: the random-codeword openings
 *      (opening_proof.0, [round][mat][point]) are appended to each point's
 *      claimed evals (hiding_pcs.rs:382-401 zip_eq; the preprocessed round
 *      carries empty entries — hiding_pcs.rs:343-348 splits 0 there)
 *   6. PCS observe: every (round, mat, point)'s MERGED evals in order
 *      (two_adic_pcs.rs:687-693), then dnac_fri_verify (mixed-height input
 *      batches supported since d2 via the d1a mixed MMCS)
 *   7. per-instance constraint check at ζ        (:507-621): N-chunk quotient
 *      recompose (UNMERGED chunk pairs) → selectors on the base trace domain
 *      → air.eval FIRST then lookups (protocol.rs:64-81), ONE fold stream
 *      acc = acc·α + x for base AND ext constraints (folder.rs:169-181);
 *      the permutation window at ζ is the RECOMPOSED EF matrix (aux_width
 *      wide; opened lens = aux_width·2, :524-541, recompose :543-559);
 *      final acc·inv_vanishing == quotient (data.rs:99-103)
 *   8. per-bus global-sum check                  (:623-643, via
 *      dnac_logup_bus_verify_global_sums — G-DET-L4, never a flat sum)
 *
 * NOT in scope here: wire decode (d4), the batched prover (d3), the
 * shielded_verify re-base (d4, atomic with the v4 codec + vector regen —
 * the v3 single-instance path stays live until then).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_BATCH_VERIFY_H
#define DNAC_BATCH_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#include "batch_priming.h"
#include "fri_verifier.h"
#include "logup.h"
#include "logup_bus.h"
#include "stark_constraints.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Status (fail-close; classes mirror VerificationError variants). */
typedef enum {
    DNAC_BV_OK = 0,
    DNAC_BV_ERR_NULL = -1,          /* required pointer missing              */
    DNAC_BV_ERR_SHAPE = -2,         /* InvalidProofShapeError class          */
    DNAC_BV_ERR_RANDOMIZATION = -3, /* RandomizationError (:77-84, :201-209) */
    DNAC_BV_ERR_PARAM = -4,         /* inconsistent caller inputs            */
    DNAC_BV_ERR_OOM = -5,           /* scratch allocation failed             */
    DNAC_BV_ERR_FRI = -6,           /* InvalidOpeningArgument — the PCS/FRI
                                       verify rejected; see out->fri_status  */
    DNAC_BV_ERR_OOD = -7,           /* OodEvaluationMismatch — constraint
                                       check failed; see out->bad_instance   */
    DNAC_BV_ERR_LOOKUP_SUM = -8,    /* LookupError — a bus group's cumulative
                                       sums don't cancel; see out->failed_bus */
} dnac_batch_verify_status_t;

/* Per-instance verifier description — the (air, lookups) bundle the
 * reference verifier gets from `airs` + `CommonData.lookups`. */
typedef struct {
    dnac_stark_air_t air;          /* base-constraint eval + widths + main_next */
    uint32_t preprocessed_width;   /* 0 = no preprocessed columns            */
    int      prep_next;            /* preprocessed_next_row_columns non-empty */
    /* Lookup declarations (verifier side): expression pool + finalized
     * lookups (locals first, columns 0..; types.rs:59-89) + the bus view. */
    const dnac_logup_expr_t   *pool;
    uint32_t                   pool_len;
    const dnac_logup_lookup_t *lookups;
    uint32_t                   num_lookups;
    dnac_logup_bus_view_t      view;
    /* Instance geometry (verifier-derived in the reference; pinned by the
     * caller here — get_log_num_quotient_chunks is symbolic analysis). */
    uint32_t degree_bits;   /* proof degree_bits[i], INCLUDING is_zk (+1)    */
    uint32_t log_num_qc;    /* pre-ZK log2 chunk count; num_qc must equal
                               1 << (log_num_qc + is_zk)                     */
    const gold_fp_t *public_values;
    uint32_t         num_publics;
} dnac_batch_vinstance_t;

/* Per-instance opened values — UNMERGED, exactly the BatchProof shape
 * (proof.rs:39-55). The hiding merge happens inside the verify (step 5). */
typedef struct {
    const gold_fp2_t *trace_local;        /* [trace_local_len]              */
    uint32_t          trace_local_len;    /* proof-side len (== width gate) */
    const gold_fp2_t *trace_next;         /* or NULL                        */
    uint32_t          trace_next_len;     /* 0 = absent                     */
    const gold_fp2_t *preprocessed_local; /* or NULL                        */
    uint32_t          preprocessed_local_len;
    const gold_fp2_t *preprocessed_next;  /* or NULL                        */
    uint32_t          preprocessed_next_len;
    const gold_fp2_t *quotient_chunks;    /* [num_qc][2] flattened stride 2 */
    uint32_t          num_quotient_chunks;
    const gold_fp2_t *random;             /* or NULL (present iff is_zk)    */
    uint32_t          random_len;         /* 2 iff is_zk else 0             */
    const gold_fp2_t *permutation_local;  /* [permutation_len] flat or NULL */
    const gold_fp2_t *permutation_next;   /* [permutation_len] flat or NULL */
    uint32_t          permutation_len;    /* == aux_width*2                 */
    /* global_lookup_data (proof side): values in global-lookup order plus
     * the (name, aux_column) metadata the verifier cross-checks (:233-267). */
    const gold_fp2_t  *cumulative_sums;   /* [num_globals]                  */
    const char *const *entry_names;       /* [num_globals]                  */
    const uint32_t    *entry_aux_columns; /* [num_globals]                  */
    uint32_t           num_globals;
} dnac_batch_vopened_t;

/* Batch commitments (proof.rs:26-37), each 4 canonical lanes. */
typedef struct {
    const gold_fp_t *main_commit;
    const gold_fp_t *preprocessed_commit; /* or NULL */
    const gold_fp_t *permutation_commit;  /* or NULL */
    const gold_fp_t *quotient_commit;
    const gold_fp_t *random_commit;       /* or NULL */
} dnac_batch_vcommits_t;

/* Random-codeword openings (HidingFriPcs opening_proof.0) — REQUIRED iff
 * is_zk. Entry order = every (round, matrix, point) of the ASSEMBLED
 * opening rounds, round-major (the same nesting serde emits). Entries for
 * the preprocessed round must have len 0 (hiding_pcs.rs:343-348); all
 * others carry the num_random_codewords values to append (merge,
 * hiding_pcs.rs:382-401). num_entries MUST equal the total assembled
 * point count (the zip_eq mirror — fail-close SHAPE otherwise). */
typedef struct {
    const gold_fp2_t *const *vals; /* [num_entries][lens[k]]                */
    const uint32_t          *lens; /* [num_entries]                         */
    uint32_t                 num_entries;
} dnac_batch_rand_openings_t;

/* Optional diagnostics (nullable). */
typedef struct {
    gold_fp2_t        alpha;        /* constraint-α                          */
    gold_fp2_t        zeta;         /* OOD point                             */
    dnac_fri_status_t fri_status;   /* set when DNAC_BV_ERR_FRI              */
    uint32_t          bad_instance; /* set when DNAC_BV_ERR_OOD              */
    const char       *failed_bus;   /* set when DNAC_BV_ERR_LOOKUP_SUM       */
} dnac_batch_verify_out_t;

/**
 * @brief Verify a batched STARK proof (verify_batch mirror, in-memory).
 *
 * @param insts        Per-instance descriptions (airs + lookups + geometry).
 * @param opened       Per-instance UNMERGED opened values (BatchProof shape).
 * @param num_instances Instance count.
 * @param is_zk        0 or 1 (HidingFriPcs). Gates random commit/opens and
 *                     the merge step.
 * @param commits      The 4-lane batch commitments.
 * @param prep_matrix_to_instance / num_prep_matrices
 *                     The global preprocessed mapping (common.preprocessed.
 *                     matrix_to_instance; NULL/0 when absent). Instance i has
 *                     preprocessed columns iff it appears here — must be
 *                     consistent with insts[i].preprocessed_width (:410-445).
 * @param fri_params   FRI parameters (the consensus pin at the shielded
 *                     entry; fixture params in KATs).
 * @param num_random_codewords
 *                     REQUIRED instance pin, no default. The number of hiding
 *                     random-codeword values appended to EVERY non-preprocessed
 *                     opening point. Must be 0 when !is_zk. Mirrors the
 *                     prover's parameter of the same name (batch_prover.h) so
 *                     both sides read the count from the caller, never from the
 *                     proof.
 * @param salt_elems   REQUIRED instance pin, no default. The number of hiding
 *                     leaf-salt lanes every input-batch opening and every
 *                     commit-phase step of `fri_proof` must declare. Mirrors
 *                     the prover's `salt_elems` (batch_prover.h).
 * @param fri_proof    The FRI opening proof (dnac_fri_proof_t).
 * @param rand_openings Random-codeword openings iff is_zk, else NULL.
 * @param out          Optional diagnostics (α, ζ, failure detail).
 *
 * WHY THESE TWO ARE PARAMETERS AND NOT DEFAULTS (S2'-d, 2026-07-27):
 *
 *   Under the Poseidon2 PaddingFreeSponge leaf hash the whole batch's rows are
 *   flattened into ONE element stream with no separator, count or length, so
 *   the digest is a pure function of (lane sequence, total length) and the row
 *   boundaries are authenticated only by the widths the verifier asserts. Half
 *   of each width was a protocol constant and half — the hiding tail — was read
 *   off the wire and compared against another wire field. A prover could
 *   therefore REPARTITION a same-height group at constant total: declare the 8
 *   quotient rows as 7,5,6,6,6,6,6,6 instead of 6x8 and obtain a byte-identical
 *   leaf against the same committed root.
 *
 *   Pinning both counts here rather than at one caller is deliberate: the pin
 *   used to live only in the shielded entry, so any SECOND consumer of the same
 *   decode -> verify pair (P2 recursion is the one being built) inherited the
 *   hole. Requiring the caller to state them closes the class.
 *
 *   HONEST LABEL — this is STRICTER THAN UPSTREAM, not a port. Plonky3's hiding
 *   PCS checks only the NESTING SHAPE of the random openings (one set per
 *   round, per matrix, per point — v0.6.2 fri/src/hiding_pcs.rs:398-428) and
 *   never the per-point tail LENGTH, and the inner verifier then pins each
 *   matrix width to `values.len()` (v0.6.2 fri/src/verifier.rs:698-711) which
 *   is public + that unpinned tail. The reference carries the same freedom.
 *   Honest proofs are unaffected either way: the prover emits exactly
 *   num_random_codewords on every non-preprocessed point and 0 on preprocessed
 *   ones (batch_prover.c BP_OPEN_MAT), so no KAT vector moves.
 */
dnac_batch_verify_status_t dnac_batch_verify(
    const dnac_batch_vinstance_t     *insts,
    const dnac_batch_vopened_t       *opened,
    uint32_t                          num_instances,
    int                               is_zk,
    const dnac_batch_vcommits_t      *commits,
    const uint32_t                   *prep_matrix_to_instance,
    uint32_t                          num_prep_matrices,
    const dnac_fri_params_t          *fri_params,
    uint32_t                          num_random_codewords,
    size_t                            salt_elems,
    const dnac_fri_proof_t           *fri_proof,
    const dnac_batch_rand_openings_t *rand_openings,
    dnac_batch_verify_out_t          *out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_BATCH_VERIFY_H */
