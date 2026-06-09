/**
 * @file stark_constraints.h
 * @brief Generic STARK constraint-check primitives (DNAC v3 — phase S3).
 *
 * The AIR-INDEPENDENT half of the two functions that remain after B8 priming +
 * dnac_fri_verify: selectors_at_point, the num_qc=1 quotient recompose, and the
 * alpha-fold accumulator helpers. NO AIR-specific eval and NO full verify glue
 * (those are S4). Ground truth = Plonky3 commit 82cfad73:
 *   - selectors_at_point         commit/src/domain.rs:262-271 (vanishing :251-253)
 *   - recompose (num_qc=1)        uni-stark/src/verifier.rs:59-96
 *   - alpha-fold (assert_zero)    uni-stark/src/folder.rs:215-218
 *   - assert_eq / bool / when     air/src/builder.rs:147-149,191-193 + filtered.rs:60-62
 *   - final OOD check             uni-stark/src/verifier.rs:157-159
 * Byte-matched against tools/vectors/stark_verify_constraints{,_no_next}.json
 * (real-Plonky3 verifier-side oracle, phase S2).
 *
 * Design: docs/plans/2026-05-30-stark-constraint-check-implementation-design.md.
 * The status enum is SEPARATE from dnac_fri_status_t (which stays locked, a pure
 * FriError mirror) — exactly as stark_priming / stark_proof_codec introduced their
 * own enums.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_CONSTRAINTS_H
#define DNAC_ZK_STARK_CONSTRAINTS_H

#include <stddef.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Status — SEPARATE from dnac_fri_status_t (do NOT modify that one).
 * ========================================================================== */

typedef enum {
    DNAC_STARK_VERIFY_OK = 0,
    /** folded_constraints * inv_vanishing != quotient(zeta) (verifier.rs:158,
     *  VerificationError::OodEvaluationMismatch). */
    DNAC_STARK_VERIFY_ERR_OOD_MISMATCH = 1,
    /** Proof-shape mismatch: trace width / num_quotient_chunks / chunk dimension /
     *  trace_next presence (verifier.rs:327-358). Reserved for the S4 glue; the S3
     *  primitives do not emit it. */
    DNAC_STARK_VERIFY_ERR_SHAPE = 2,
} dnac_stark_verify_status_t;

/* ============================================================================
 * Lagrange selectors at an out-of-domain point (domain.rs:22-31, 262-271).
 *
 * UNNORMALIZED (domain.rs:19-20): is_first_row does NOT equal 1 on the first row.
 * The prover folds the quotient with the matching unnormalized selectors_on_coset
 * (prover.rs:418); normalizing here would reject valid proofs.
 * ========================================================================== */

typedef struct {
    gold_fp2_t z_h;            /**< zeta^(2^bdb) - 1  (= vanishing_poly_at_point) */
    gold_fp2_t is_first_row;   /**< z_h / (zeta - 1) */
    gold_fp2_t is_last_row;    /**< z_h / (zeta - g^-1) */
    gold_fp2_t is_transition;  /**< zeta - g^-1 */
    gold_fp2_t inv_vanishing;  /**< 1 / z_h */
} dnac_stark_selectors_t;

/**
 * @brief Selectors at `zeta` for the trace domain of size 2^base_degree_bits.
 *
 * Trace shift = ONE (two_adic_pcs.rs:286), so unshifted_point = zeta and
 * g = gold_fp_two_adic_generator(base_degree_bits). domain.rs:262-271 verbatim:
 *   z_h           = zeta^(2^bdb) - 1
 *   is_first_row  = z_h / (zeta - 1)
 *   is_last_row   = z_h / (zeta - g^-1)
 *   is_transition = zeta - g^-1
 *   inv_vanishing = 1 / z_h
 * All fp2. Requires zeta not in the trace subgroup (else z_h = 0); zeta is sampled
 * out-of-domain (verifier.rs:391) so this holds w.h.p. — caller responsibility.
 */
dnac_stark_selectors_t dnac_stark_selectors_at_point(gold_fp2_t zeta,
                                                     size_t base_degree_bits);

/* ============================================================================
 * Quotient recomposition — num_qc=1 (all degree-2 DNAC/fib/square AIRs).
 * ========================================================================== */

/**
 * @brief Recompose quotient(zeta) from a SINGLE quotient chunk (verifier.rs:59-96).
 *
 * For num_quotient_chunks == 1 the Lagrange weight is the empty product = 1, so no
 * split/disjoint-domain machinery is needed (verifier.rs:67-95). The chunk is the
 * "extension element committed as DIMENSION base columns" form:
 *   quotient(zeta) = chunk0[0] + chunk0[1] * X,   X = (0, 1) = the fp2 basis elem
 * (from_ext_basis_coefficients over the [1, X] basis, verifier.rs:87-95).
 *
 * @param chunk0  The 2 opened fp2 values of the single quotient chunk at zeta.
 * @return        quotient(zeta).
 */
gold_fp2_t dnac_stark_recompose_quotient_1chunk(const gold_fp2_t chunk0[2]);

/* ============================================================================
 * Generic alpha-fold accumulator (folder.rs:59-84, 215-228).
 *
 * The AIR-independent fold state. S4 supplies the trace window + selectors +
 * public values as the air_eval context and drives these helpers. Constraint
 * EMISSION ORDER is the caller/AIR's responsibility — the fold is order-sensitive.
 * No early-exit; no per-constraint status (verifier.rs:153-159 sums every
 * constraint before the single final compare).
 * ========================================================================== */

typedef struct {
    gold_fp2_t alpha;   /**< constraint-combining challenge */
    gold_fp2_t acc;     /**< running accumulator (init to ZERO via dnac_stark_fold_init) */
} dnac_stark_fold_t;

/** acc <- ZERO; alpha <- alpha. */
void dnac_stark_fold_init(dnac_stark_fold_t *f, gold_fp2_t alpha);

/** acc <- acc * alpha + x  (folder.rs:216-217). */
void dnac_stark_fold_assert_zero(dnac_stark_fold_t *f, gold_fp2_t x);

/** assert_zero(a - b)  (builder.rs:147-149). */
void dnac_stark_fold_assert_eq(dnac_stark_fold_t *f, gold_fp2_t a, gold_fp2_t b);

/** assert_zero(x * (x - 1))  (builder.rs:191-193, bool_check). */
void dnac_stark_fold_assert_bool(dnac_stark_fold_t *f, gold_fp2_t x);

/** assert_zero(selector * x)  (filtered.rs:60-62, FilteredAirBuilder). */
void dnac_stark_fold_when(dnac_stark_fold_t *f, gold_fp2_t selector, gold_fp2_t x);

/* ============================================================================
 * Final out-of-domain check (verifier.rs:157-159).
 * ========================================================================== */

/**
 * @brief Returns DNAC_STARK_VERIFY_OK iff folded * inv_vanishing == quotient,
 *        else DNAC_STARK_VERIFY_ERR_OOD_MISMATCH.
 */
dnac_stark_verify_status_t dnac_stark_final_check(gold_fp2_t folded,
                                                  gold_fp2_t inv_vanishing,
                                                  gold_fp2_t quotient);

/* ============================================================================
 * S4 — verify_constraints glue + the AIR callback interface.
 *
 * AIR dispatch is a CALLBACK function pointer (mirrors Plonky3 `Air::eval`,
 * air.rs:199-209): one generic `dnac_stark_verify_constraints` drives any AIR's
 * `air_eval`, which emits its constraints (in a PINNED order — the alpha-fold is
 * order-sensitive) via the folder-level helpers below. Chosen over an enum-switch
 * for fidelity to Plonky3 and to keep the glue AIR-agnostic; deterministic either
 * way (the pointer is fixed per AIR at compile time).
 * ========================================================================== */

/** Largest main-trace width the glue's zero-window buffer supports
 *  (fib/square = 2; the future combined range_proof_air = 66). */
#define DNAC_STARK_MAX_MAIN_WIDTH ((size_t)256)

/** One captured fold step (test instrumentation only). */
typedef struct {
    gold_fp2_t received;  /**< value passed to assert_zero (= selector-applied) */
    gold_fp2_t after;     /**< accumulator after this constraint */
} dnac_stark_fold_step_t;

/**
 * @brief The `air_eval` evaluation context — the row window + selectors + public
 *        values + the alpha-fold accumulator. Mirrors VerifierConstraintFolder
 *        (folder.rs:59-84) but with `Val` public values and a separate fold state.
 *
 * `capture` is OPTIONAL test instrumentation: when non-NULL, each folder-level
 * fold helper appends a (received, after) step. NULL in production
 * (dnac_stark_verify_constraints sets it NULL), so the production path records
 * nothing. The S3 `dnac_stark_fold_t` and its ops are UNCHANGED by this.
 */
typedef struct {
    const gold_fp2_t *trace_local;       /**< [main_width] @ zeta */
    const gold_fp2_t *trace_next;        /**< [main_width] @ zeta_next; zero-window if main_next==0 */
    size_t            main_width;
    const gold_fp_t  *public_values;     /**< [num_public_values], base field (promoted in-expr) */
    size_t            num_public_values;
    gold_fp2_t        is_first_row;      /**< selectors at zeta (UNnormalized) */
    gold_fp2_t        is_last_row;
    gold_fp2_t        is_transition;
    dnac_stark_fold_t fold;              /**< {alpha, acc} */
    /* optional per-constraint capture (test instrumentation; NULL => off) */
    dnac_stark_fold_step_t *capture;
    size_t                  capture_cap;
    size_t                  capture_len;
} dnac_stark_folder_t;

/** An AIR for the constraint check: shape metadata + the eval callback. */
typedef struct {
    size_t main_width;          /**< air.rs:11 */
    size_t num_public_values;   /**< air.rs:188 */
    int    main_next;           /**< 1 iff the AIR reads the next row (air.rs:122) */
    void (*air_eval)(dnac_stark_folder_t *folder);  /**< emits constraints in PINNED order */
} dnac_stark_air_t;

/* Folder-level fold helpers (the air_eval API). Each wraps the S3 dnac_stark_fold_*
 * op on &folder->fold and records the step when folder->capture != NULL. */
void dnac_stark_folder_assert_zero(dnac_stark_folder_t *f, gold_fp2_t x);
void dnac_stark_folder_assert_eq(dnac_stark_folder_t *f, gold_fp2_t a, gold_fp2_t b);
void dnac_stark_folder_assert_bool(dnac_stark_folder_t *f, gold_fp2_t x);
void dnac_stark_folder_when(dnac_stark_folder_t *f, gold_fp2_t selector, gold_fp2_t x);

/**
 * @brief Generic STARK constraint check (the two remaining functions composed):
 *        recompose quotient(zeta) (num_qc=1) -> selectors_at_point -> air_eval
 *        alpha-fold -> final OOD check (verifier.rs:463-498).
 *
 * Shape (verifier.rs:327-358 subset): trace_local_len == main_width;
 * num_public_values == air->num_public_values; if main_next: trace_next non-NULL
 * and trace_next_len == main_width; if !main_next: trace_next may be NULL/0 (a
 * zero-window is supplied, verifier.rs:469-476). quotient_chunk is exactly 2 by API.
 *
 * @return DNAC_STARK_VERIFY_OK | _ERR_SHAPE | _ERR_OOD_MISMATCH.
 */
dnac_stark_verify_status_t dnac_stark_verify_constraints(
    const dnac_stark_air_t *air,
    const gold_fp2_t *trace_local, size_t trace_local_len,
    const gold_fp2_t *trace_next, size_t trace_next_len,
    const gold_fp_t *public_values, size_t num_public_values,
    gold_fp2_t zeta,
    size_t base_degree_bits,
    gold_fp2_t alpha,
    const gold_fp2_t quotient_chunk[2]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_CONSTRAINTS_H */
