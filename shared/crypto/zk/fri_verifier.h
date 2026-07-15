/**
 * @file fri_verifier.h
 * @brief FRI verifier — C ABI / structure skeleton (DNAC v3 ZK stack, Phase F2).
 *
 * Strict mirror of Plonky3's FRI verifier at pinned commit
 *   82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * ---------------------------------------------------------------------------
 * STATUS (read first)
 * ---------------------------------------------------------------------------
 *   - This header is F2 (structure / ABI only). The FRI verifier
 *     IMPLEMENTATION IS NOT YET PRESENT: there is no `fri_verifier.c` and no
 *     verification logic anywhere in the DNAC tree as of this header.
 *     `dnac_fri_verify` is a forward prototype only — it has no definition.
 *   - Current Merkle / MMCS support is Phase 2A same-height multi-matrix batch
 *     (`merkle_smt.h` :: `dnac_merkle_batch_verify`, design §13 B2).
 *   - Phase 2B mixed-height multi-matrix MMCS is DEFERRED and out of v3.0
 *     scope (design §13 B4). The FRI verifier will pre-check that all matrices
 *     in an input batch share the same `num_rows` before delegating to the
 *     same-height batch verify.
 *
 * F2 carry-over notes (from the F1 oracle source-lock audit, APPROVED — no
 * KAFADAN / BLOCKER):
 *   - Terminal Horner vectors (`tools/vectors/fri_verifier_terminal_horner.json`)
 *     have NO live Plonky3 cross-check at F1 (they are a verified source-mirror
 *     of `verifier.rs:308-321` over synthetic inputs). They MUST be replayed in
 *     C at Phase F6, where the C Horner becomes the real cross-check.
 *   - `FinalPolyMismatch` is produced at TWO sites in Plonky3:
 *       (1) terminal Horner check  — `verifier.rs:323-325`,
 *       (2) `open_input`           — `verifier.rs:647-651`
 *           (height-1 constant trace yields a nonzero reduced opening; this
 *            path is NOT transcript-desync-blocked).
 *     The C verifier (F5 `open_input` + F6 terminal Horner) must handle BOTH.
 *
 * ---------------------------------------------------------------------------
 * SOURCE OF TRUTH
 * ---------------------------------------------------------------------------
 *   - docs/plans/2026-05-27-fri-verifier-design.md (whole document)
 *   - Plonky3 82cfad73:
 *       fri/src/proof.rs          (FriProof / QueryProof / CommitPhaseProofStep)
 *       fri/src/config.rs         (FriParameters)
 *       fri/src/two_adic_pcs.rs   (CommitmentWithOpeningPoints, TwoAdicFriFolding)
 *       fri/src/verifier.rs       (verify_fri, FriError)
 *       commit/src/mmcs.rs        (BatchOpening)
 *       field/src/coset.rs        (TwoAdicMultiplicativeCoset)
 *
 * Module-boundary rule (design §9): ONE public module `fri_verifier.{c,h}` with
 * a single entry `dnac_fri_verify`. The `fri_commit` / `fri_query` split is
 * REJECTED — those module-level types do not exist in Plonky3 and were deleted
 * 2026-05-23 as a kafadan boundary. DO NOT reintroduce `fri_commit_t`,
 * `fri_query_t`, `fri_commit_phase_t`, or `fri_query_phase_t`.
 *
 * Field choice (design §11 C1/C4, LOCKED by project_v3_zk_bitcoin_style):
 *   Val = Goldilocks (gold_fp_t), Challenge = Goldilocks² (gold_fp2_t),
 *   hash/transcript = SHA3-512.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_VERIFIER_H
#define DNAC_ZK_FRI_VERIFIER_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"  /* gold_fp_t (Val), gold_fp2_t (Challenge) */
#include "merkle_smt.h"        /* dnac_merkle_digest_t (commitment/root),
                                  dnac_merkle_proof_t (MMCS opening proof) */
#include "transcript.h"        /* dnac_transcript_t (Fiat-Shamir challenger) */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 1. Status / error enum
 *
 * Mirrors Plonky3 `FriError` (fri/src/verifier.rs:18-97) in EXACT declaration
 * order, plus `DNAC_FRI_OK` for the success path. 20 values total = 1 OK + 19
 * errors (design §3 S7, §10).
 *
 * Naming: `DNAC_FRI_*` follows the in-directory convention (cf.
 * `DNAC_MERKLE_OK` / `DNAC_MERKLE_ERR_*` in merkle_smt.h). The design-doc
 * sketch (§3 S7) used `FRI_OK` / `FRI_ERR_*`; the `DNAC_FRI_` prefix supersedes
 * it for codebase consistency. Each value lists its Plonky3 `FriError` variant.
 * ========================================================================== */
typedef enum {
    DNAC_FRI_OK = 0,                                       /* Ok(())                                */

    DNAC_FRI_ERR_INVALID_PROOF_SHAPE = 1,                 /* InvalidProofShape (hiding-pcs only;   */
                                                          /*   not reachable in DNAC path)         */
    DNAC_FRI_ERR_QUERY_COMMIT_PHASE_OPENINGS_COUNT_MISMATCH = 2,  /* QueryCommitPhaseOpeningsCountMismatch */
    DNAC_FRI_ERR_QUERY_LOG_ARITIES_MISMATCH = 3,          /* QueryLogAritiesMismatch               */
    DNAC_FRI_ERR_COMMIT_POW_WITNESS_COUNT_MISMATCH = 4,   /* CommitPowWitnessCountMismatch         */
    DNAC_FRI_ERR_FINAL_POLY_LENGTH_MISMATCH = 5,          /* FinalPolyLengthMismatch               */
    DNAC_FRI_ERR_QUERY_PROOF_COUNT_MISMATCH = 6,          /* QueryProofCountMismatch               */
    DNAC_FRI_ERR_MISSING_INITIAL_REDUCED_OPENING = 7,     /* MissingInitialReducedOpening          */
    DNAC_FRI_ERR_INITIAL_REDUCED_OPENING_HEIGHT_MISMATCH = 8, /* InitialReducedOpeningHeightMismatch */
    DNAC_FRI_ERR_SIBLING_VALUES_LENGTH_MISMATCH = 9,      /* SiblingValuesLengthMismatch           */
    DNAC_FRI_ERR_INVALID_LOG_ARITY = 10,                  /* InvalidLogArity                       */
    DNAC_FRI_ERR_FINAL_FOLD_HEIGHT_MISMATCH = 11,         /* FinalFoldHeightMismatch               */
    DNAC_FRI_ERR_UNCONSUMED_REDUCED_OPENINGS = 12,        /* UnconsumedReducedOpenings             */
    DNAC_FRI_ERR_INPUT_PROOF_BATCH_COUNT_MISMATCH = 13,   /* InputProofBatchCountMismatch          */
    DNAC_FRI_ERR_BATCH_OPENED_VALUES_COUNT_MISMATCH = 14, /* BatchOpenedValuesCountMismatch        */
    DNAC_FRI_ERR_POINT_EVALUATION_COUNT_MISMATCH = 15,    /* PointEvaluationCountMismatch          */
    DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR = 16,            /* CommitPhaseMmcsError(_)               */
    DNAC_FRI_ERR_INPUT_ERROR = 17,                        /* InputError(_)                         */
    DNAC_FRI_ERR_FINAL_POLY_MISMATCH = 18,                /* FinalPolyMismatch (two sites — see    */
                                                          /*   file carry-over note)               */
    DNAC_FRI_ERR_INVALID_POW_WITNESS = 19,                /* InvalidPowWitness                     */

    /* DNAC-specific pre-consensus safety guard (NOT a Plonky3 mirror variant).
     * Rejects wire-supplied FRI params that are degenerate or would cause
     * undefined behavior in the verifier, independent of the chosen security
     * level: num_queries == 0 (the low-degree test never runs — an accept-any-
     * garbage downgrade), or log_global_max_height >= 64 (shift-count UB feeding
     * transcript sample_bits / domain_index >>= sum_la → nondeterministic verdict
     * across builds = chain-split class), or a mixed-height input batch (Phase 2B,
     * unsupported). A FULL production param pin (exact-match to a grounded secure
     * FriParameters set) remains a MUST-FIX before consensus wiring — see
     * dnac/docs/plans/2026-07-11-...-design.md §5.4. */
    DNAC_FRI_ERR_UNSUPPORTED_PARAMS = 20
} dnac_fri_status_t;

/* ============================================================================
 * 2. FRI parameters
 *
 * Mirrors Plonky3 `FriParameters<M>` (fri/src/config.rs:9-22).
 *
 * NOTE on the omitted `mmcs` field: Plonky3's `FriParameters.mmcs` (config.rs:21)
 * is the commit-phase MMCS instance, used as `params.mmcs.verify_batch(...)`.
 * DNAC's Merkle verify is STATELESS — `dnac_merkle_batch_verify(root, ...)`
 * takes the root directly (merkle_smt.h), with the root coming from
 * `commit_phase_commits[]`. There is therefore no per-instance MMCS handle to
 * store at verify time. The user's F2 field spec also lists exactly these six
 * scalar fields and no handle. (Deviation from design §3 S6 sketch, which named
 * an "MMCS handle"; superseded by the user spec + the stateless DNAC API.)
 *
 * Conjectured soundness (config.rs:42-44, ethSTARK):
 *   log_blowup * num_queries + query_proof_of_work_bits.
 * Concrete DNAC values are operational policy, deferred (design §11 C6 / §13 B6).
 * ========================================================================== */
typedef struct {
    size_t log_blowup;                 /* config.rs:10 */
    size_t log_final_poly_len;         /* config.rs:12 */
    size_t max_log_arity;              /* config.rs:15 — default 1 (binary folding) */
    size_t num_queries;                /* config.rs:16 */
    size_t commit_proof_of_work_bits;  /* config.rs:18 */
    size_t query_proof_of_work_bits;   /* config.rs:20 */
} dnac_fri_params_t;

/* ============================================================================
 * 3. Commitment + opening-points input
 *
 * Mirrors Plonky3 `CommitmentWithOpeningPoints<Challenge, Commitment, Domain>`
 * (fri/src/two_adic_pcs.rs:83-92):
 *
 *   ( Commitment,
 *     Vec<( Domain,                         // per matrix
 *           Vec<(Challenge, Vec<Challenge>)> // (point z, claimed evals [f_i(z)])
 *         )> )
 *
 * All `Vec<T>` are lowered to a `const T* ptr; size_t len;` pair. Memory
 * ownership model is deferred to the F3+ implementation (caller-owned, borrowed
 * by the verifier — design §10).
 * ========================================================================== */

/**
 * Two-adic multiplicative coset domain of a committed matrix.
 *
 * Mirrors Plonky3 `TwoAdicMultiplicativeCoset<Val>` (field/src/coset.rs:55-62),
 * instantiated over Val = Goldilocks (verify_fri arg, verifier.rs:121). The
 * coset is s·<g> = {s, s·g, ..., s·g^(2^log_size - 1)} where g is the generator
 * of order 2^log_size (coset.rs:56-58).
 *
 * The full Plonky3 layout is mirrored here; the exact subset the verifier reads
 * (via `open_input`) is pinned at F5.
 */
typedef struct {
    gold_fp_t shift;          /* coset.rs:59 — s          */
    gold_fp_t shift_inverse;  /* coset.rs:60 — s^{-1} (precomputed) */
    size_t    log_size;       /* coset.rs:61 — log2 of subgroup order */
} dnac_fri_domain_t;

/**
 * One opening point and its claimed evaluations: `(Challenge, Vec<Challenge>)`
 * (two_adic_pcs.rs:90). `point` is z; `claimed_evals[i]` is f_i(z) for each of
 * the matrix's committed columns.
 */
typedef struct {
    gold_fp2_t        point;          /* z  (Challenge)            */
    const gold_fp2_t *claimed_evals;  /* [f_i(z)] (Challenge)      */
    size_t            num_claimed_evals;
} dnac_fri_opening_point_t;

/**
 * Per-matrix entry: `(Domain, Vec<(Challenge, Vec<Challenge>)>)`
 * (two_adic_pcs.rs:86-91).
 */
typedef struct {
    dnac_fri_domain_t               domain;       /* the matrix's domain        */
    const dnac_fri_opening_point_t *points;       /* (z, [f_i(z)]) pairs        */
    size_t                          num_points;
} dnac_fri_matrix_openings_t;

/**
 * Joint commitment to a collection of matrices and their openings.
 * Mirrors `CommitmentWithOpeningPoints` (two_adic_pcs.rs:83-92).
 */
typedef struct {
    dnac_merkle_digest_t              commitment;  /* InputMmcs::Commitment (root) */
    const dnac_fri_matrix_openings_t *matrices;    /* per-matrix (domain, openings) */
    size_t                            num_matrices;
} dnac_fri_commitment_with_opening_points_t;

/* ============================================================================
 * 4. Proof structures (strict Plonky3 mirror, design §3)
 *
 * In `verify_fri` the proof is `FriProof<Challenge, FriMmcs, Witness, InputProof>`
 * (verifier.rs:116), so:
 *   - `final_poly`     elements are Challenge  => gold_fp2_t
 *   - `sibling_values` elements are Challenge  => gold_fp2_t
 *   - `opened_values`  elements are Val (base) => gold_fp_t  (BatchOpening<Val,_>)
 *   - PoW `Witness`    = base field            => gold_fp_t
 *     (Challenger::Witness; cf. dnac_transcript_check_witness(t, bits, fp_t))
 *   - MMCS commitments / opening proofs => dnac_merkle_digest_t / dnac_merkle_proof_t
 * ========================================================================== */

/**
 * Mirrors `CommitPhaseProofStep<F, M>` (fri/src/proof.rs:34-42).
 * `sibling_values` length is `(1 << log_arity) - 1` (proof.rs:38-39).
 * `log_arity` bound check (1..=max_log_arity) is Plonky3 `checked_log_arity`
 * (proof.rs:44-55), performed by the verifier (F4), not stored here.
 */
typedef struct {
    uint8_t             log_arity;       /* proof.rs:36 (u8)              */
    const gold_fp2_t   *sibling_values;  /* proof.rs:39 (Vec<F>=Challenge) */
    size_t              num_sibling_values;
    dnac_merkle_proof_t opening_proof;   /* proof.rs:41 (M::Proof)        */
    /* M3b salted-leaf hiding (0 = unsalted / plain MMCS, backward-compatible).
     * When the FRI challenge mmcs is a MerkleTreeHidingMmcs, the leaf preimage is
     * the arity fp2 evals (BASE-flattened by ExtensionMmcs, extension_mmcs.rs:
     * 77-95) followed by `salt_elems` BASE salt elements (hiding_mmcs.rs:169-170).
     * The verifier appends salt bytes to the leaf and MUST reject a non-canonical
     * salt (SEC-M3b-2) and a salt count != salt_elems (SEC-M3b-1). */
    const gold_fp_t    *salts;           /* [salt_elems] base-field, or NULL */
    size_t              salt_elems;      /* SALT_ELEMS, or 0 if unsalted     */
} dnac_fri_commit_phase_proof_step_t;

/**
 * Mirrors `BatchOpening<T, InputMmcs>` (commit/src/mmcs.rs:163-169).
 * `opened_values` is `Vec<Vec<F>>` (per-matrix opened row, base field):
 * `opened_values[m]` is matrix m's opened row; `opened_values_lens[m]` its
 * length. `num_matrices` is the batch's matrix count.
 */
typedef struct {
    const gold_fp_t * const *opened_values;       /* [matrix][col] (Vec<Vec<Val>>) */
    const size_t            *opened_values_lens;  /* per-matrix column count        */
    size_t                   num_matrices;
    dnac_merkle_proof_t      opening_proof;        /* InputMmcs::Proof               */
    /* M3b salted-leaf hiding (0 = unsalted, backward-compatible). Per matrix, the
     * leaf preimage is opened_values[m] (canonical u64-LE) followed by
     * `salt_elems` BASE salt elements salts[m][0..salt_elems) (hiding_mmcs.rs:
     * 169-170). SEC-M3b-1: the caller/parser MUST pin salts[m] to exactly
     * salt_elems per matrix (fail-close); the verifier rejects non-canonical
     * salts (SEC-M3b-2). */
    const gold_fp_t * const *salts;                /* [matrix][salt_elems], or NULL */
    size_t                   salt_elems;           /* SALT_ELEMS, or 0 if unsalted  */
} dnac_fri_batch_opening_t;

/**
 * Mirrors `QueryProof<F, M, InputProof>` (fri/src/proof.rs:25-30).
 * For TwoAdicFriFolding, `InputProof = Vec<BatchOpening<Val, InputMmcs>>`
 * (two_adic_pcs.rs:96-97 / verify_fri bound, verifier.rs:135).
 */
typedef struct {
    const dnac_fri_batch_opening_t           *input_proof;           /* proof.rs:26 */
    size_t                                    num_input_batches;
    const dnac_fri_commit_phase_proof_step_t *commit_phase_openings; /* proof.rs:29 */
    size_t                                    num_commit_phase_openings;
} dnac_fri_query_proof_t;

/**
 * Mirrors `FriProof<F, M, Witness, InputProof>` (fri/src/proof.rs:12-18).
 * `commit_phase_commits` are FriMmcs commitments (one per commit-phase round);
 * `commit_pow_witnesses` are one PoW witness per round; `final_poly` are the
 * extension-field final-polynomial coefficients; `query_pow_witness` is the
 * single query-phase PoW witness.
 */
typedef struct {
    const dnac_merkle_digest_t   *commit_phase_commits;     /* proof.rs:13 (Vec<M::Commitment>) */
    size_t                        num_commit_phase_commits;
    const gold_fp_t              *commit_pow_witnesses;     /* proof.rs:14 (Vec<Witness>)       */
    size_t                        num_commit_pow_witnesses;
    const dnac_fri_query_proof_t *query_proofs;             /* proof.rs:15 (Vec<QueryProof>)    */
    size_t                        num_query_proofs;
    const gold_fp2_t             *final_poly;               /* proof.rs:16 (Vec<F>=Challenge)   */
    size_t                        num_final_poly;
    gold_fp_t                     query_pow_witness;        /* proof.rs:17 (Witness)            */
} dnac_fri_proof_t;

/* ============================================================================
 * 5. Public entry prototype
 *
 * Mirrors `verify_fri` (fri/src/verifier.rs:104-124). Two of Plonky3's six
 * runtime arguments are FIXED in DNAC and therefore implicit (no parameter):
 *   - `folding` : the FRI folding strategy is fixed to TwoAdicFriFolding with
 *                 `extra_query_index_bits = 0` (two_adic_pcs.rs:105-107, §11 C2).
 *   - `input_mmcs` : DNAC Merkle verify is stateless (no handle); see §2 note.
 *
 * IMPLEMENTATION IS NOT YET PRESENT — this is a forward declaration only.
 * Coding of `fri_verifier.c` is gated on explicit user approval (F3+).
 *
 * @param params       FRI instance parameters (mirrors config.rs FriParameters).
 * @param proof        The proof to verify (mirrors FriProof).
 * @param transcript   Fiat-Shamir challenger; consumed/advanced in place
 *                     (mirrors `challenger: &mut Challenger`, verifier.rs:117).
 * @param commitments_with_opening_points  Array of joint commitments + openings
 *                     (mirrors the `&[CommitmentWithOpeningPoints<...>]` slice,
 *                     verifier.rs:118-122).
 * @param num_commitments  Length of `commitments_with_opening_points`.
 *
 * @return DNAC_FRI_OK on acceptance, or a DNAC_FRI_ERR_* status mirroring the
 *         corresponding Plonky3 `FriError` variant.
 */
dnac_fri_status_t dnac_fri_verify(
    const dnac_fri_params_t                         *params,
    const dnac_fri_proof_t                          *proof,
    dnac_transcript_t                               *transcript,
    const dnac_fri_commitment_with_opening_points_t *commitments_with_opening_points,
    size_t                                           num_commitments);

/* Intermediate-value capture for the integrated oracle cross-checks (F4 alpha/
 * betas/query indices, F5 reduced_index, F6 folded_eval). Populated only via the
 * test-only dnac_fri_test_verify_capture entry; not used by production callers. */
typedef struct {
    gold_fp2_t alpha;
    gold_fp2_t betas[16];
    size_t     num_betas;
    uint64_t   query_index[16];
    uint64_t   reduced_index[16];
    gold_fp2_t folded_eval[16];
    size_t     num_queries;
} dnac_fri_debug_t;

/* ============================================================================
 * F3 TEST-ONLY hook — NOT production verifier API.
 *
 * Compiled only when DNAC_FRI_TESTING is defined. Exposes the pre-transcript
 * STRUCTURAL shape-check prefix of verify_fri (the shape subset of
 * verifier.rs:146-246) so the F3 oracle test can replay the applicable
 * fri_verifier_errors cases WITHOUT the not-yet-implemented transcript / MMCS /
 * fold / terminal-Horner stages.
 *
 * Returns DNAC_FRI_OK iff every structural shape check passes — this is NOT a
 * verification accept, only structural well-formedness — else the DNAC_FRI_ERR_*
 * for the FIRST failing check, in Plonky3 source order. Per the pure-mirror enum
 * decision (2026-05-29): null arguments are a CALLER PRECONDITION (debug assert),
 * never mapped into the FriError mirror; there is no DNAC-specific status code.
 *
 * Fidelity boundary: faithful for single-fault inputs whose skipped transcript
 * checks (commit PoW verifier.rs:222, query PoW verifier.rs:254) would pass —
 * i.e. exactly the isolated F1.1 vectors. Multi-fault fidelity requires F4.
 *
 * `commitments_with_opening_points` / `num_commitments` are NOT parameters here:
 * the shape prefix does not touch them (they feed open_input at F5).
 * ========================================================================== */
#ifdef DNAC_FRI_TESTING
dnac_fri_status_t dnac_fri_test_shape_prefix(
    const dnac_fri_params_t *params,
    const dnac_fri_proof_t  *proof);

/* ----------------------------------------------------------------------------
 * F4 TEST-ONLY transcript-flow hook — NOT production verifier API.
 *
 * Drives the Fiat-Shamir transcript SEQUENCE of verify_fri (verifier.rs:143-268)
 * so the F4 oracle test can replay the 18 transcript milestones. Does NOT verify
 * the proof: no open_input / MMCS verify_batch / fri_fold / verify_query loop /
 * terminal Horner. The transcript primitives themselves are the already-oracle-
 * grounded `dnac_transcript_*` (transcript.{c,h}).
 * -------------------------------------------------------------------------- */

/* Values the transcript flow produces that LATER phases (F5+) consume. */
typedef struct {
    size_t   log_global_max_height;  /* sum(log_arities)+log_blowup+log_final_poly_len (verifier.rs:201-204) */
    uint64_t query_indices[16];      /* sample_bits result per query (verifier.rs:268) */
    size_t   num_query_indices;
} dnac_fri_flow_out_t;

/* Fired after every transcript operation in the flow, for milestone inspection. */
typedef void (*dnac_fri_milestone_cb)(void *ctx, dnac_transcript_t *t);

/* Runs the verify_fri transcript sequence on `t`: F3 shape prefix first, then
 * sample alpha; per commit round observe(commitment)+check_witness+sample(beta);
 * observe(final_poly); observe each log_arity; check query PoW; sample one query
 * index per query. Fires `after_op` (if non-NULL) after each transcript op.
 * Fills `out` (log_global_max_height + sampled query indices).
 *
 * Returns `true` when the sequence COMPLETED — this is NOT a verification accept
 * (no MMCS/fold/verify_query/Horner runs). Returns `false` and sets *out_err to
 * the first real DNAC_FRI_ERR_* on a shape or PoW failure. */
bool dnac_fri_test_transcript_flow(
    dnac_transcript_t       *t,
    const dnac_fri_params_t *params,
    const dnac_fri_proof_t  *proof,
    dnac_fri_milestone_cb    after_op,
    void                    *ctx,
    dnac_fri_flow_out_t     *out,
    dnac_fri_status_t       *out_err);

/* ----------------------------------------------------------------------------
 * F5 TEST-ONLY hooks — NOT production verifier API.
 * -------------------------------------------------------------------------- */

/* F5 Part A — replay one captured FRI MMCS verify_batch call through DNAC merkle.
 * Maps a single-matrix verify_batch (verifier.rs:446-455 commit-phase /
 * verifier.rs:589-597 input) to dnac_merkle_verify: root = commitment,
 * leaf_bytes = the opened row in canonical u64-LE wire form, leaf_index = the
 * (post-shift) query index, siblings = the opening proof (depth = log2(height)).
 * DNAC merkle exposes no Dimensions{width,height}; `width` (0 for input, arity
 * for commit-phase) is metadata only — height is verified via the sibling-path
 * depth, index via leaf_index, opening via the siblings. Returns the
 * dnac_merkle_status_t (DNAC_MERKLE_OK on accept). Accept-only: rejection
 * soundness is covered independently by the merkle_mmcs reject cases. */
dnac_merkle_status_t dnac_fri_test_mmcs_verify_single(
    const dnac_merkle_digest_t *root,
    const uint8_t              *leaf_bytes,
    size_t                      leaf_byte_len,
    uint64_t                    leaf_index,
    uint32_t                    depth,
    const dnac_merkle_digest_t *siblings);

/* F5 Part B — verify_query shape checks for the ZERO-fold-round case
 * (verifier.rs:378-398 + 483-497; the fold loop body 402-481 is NOT executed).
 * The three defense-in-depth shape errors depend only on the reduced-opening
 * LOG-HEIGHTS (eval values are unused when no fold runs). The full fold loop is
 * deferred (F6+). Returns DNAC_FRI_OK if the zero-round shape is consistent,
 * else the DNAC_FRI_ERR_* for the first failing check, in source order. */
dnac_fri_status_t dnac_fri_test_verify_query_shape(
    const size_t *reduced_opening_log_heights,
    size_t        num_reduced_openings,
    size_t        log_global_max_height,
    size_t        log_final_height);

/* ----------------------------------------------------------------------------
 * F6 TEST-ONLY hooks — NOT production verifier API.
 * -------------------------------------------------------------------------- */

/* F6 Part A — terminal final-polynomial Horner evaluation (verifier.rs:308-321).
 *   x    = two_adic_generator(log_global_max_height)
 *          ^ reverse_bits_len(domain_index, log_global_max_height)   [base field]
 *   eval = 0; for coeff in final_poly REVERSED: eval = eval * x + coeff   [fp2]
 * x is lifted to fp2 (GoldFp2::from(x)); EF*F at verifier.rs:320 is the same
 * constant-by-extension multiply. The height MUST be log_global_max_height, never
 * log_final_height (design § M1 D7). If `out_x` is non-NULL it receives x. */
gold_fp2_t dnac_fri_test_terminal_horner_eval(
    const gold_fp2_t *final_poly,
    size_t            final_poly_len,
    size_t            log_global_max_height,
    uint64_t          domain_index,
    gold_fp_t        *out_x);

/* F6 Part B — terminal FinalPolyMismatch check (verifier.rs:323-325):
 *   eval == folded_eval -> DNAC_FRI_OK, else DNAC_FRI_ERR_FINAL_POLY_MISMATCH.
 * This is the terminal-Horner site only; the open_input FinalPolyMismatch site
 * (verifier.rs:647-651) is deferred (it lives inside open_input, F7). */
dnac_fri_status_t dnac_fri_test_terminal_horner_check(
    gold_fp2_t computed_eval,
    gold_fp2_t folded_eval);

/* F7 — same as dnac_fri_verify but captures intermediate values into `dbg` for
 * the integrated test's F4/F5/F6 oracle cross-checks. */
dnac_fri_status_t dnac_fri_test_verify_capture(
    const dnac_fri_params_t                         *params,
    const dnac_fri_proof_t                          *proof,
    dnac_transcript_t                               *transcript,
    const dnac_fri_commitment_with_opening_points_t *commitments_with_opening_points,
    size_t                                           num_commitments,
    dnac_fri_debug_t                                *dbg);
#endif /* DNAC_FRI_TESTING */

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_VERIFIER_H */
