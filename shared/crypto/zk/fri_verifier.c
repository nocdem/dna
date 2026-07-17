/**
 * @file fri_verifier.c
 * @brief FRI verifier — integrated path (Phase F7 consolidation).
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 * Source of truth: fri_verifier.h, docs/plans/2026-05-27-fri-verifier-design.md,
 *                  Plonky3 fri/src/verifier.rs (verify_fri / open_input /
 *                  verify_query / terminal Horner).
 *
 * dnac_fri_verify is now DEFINED: it runs the shape prefix, the Fiat-Shamir
 * transcript sequence (keeping alpha/betas/query indices), open_input +
 * verify_query per query, and the terminal Horner final check — returning
 * DNAC_FRI_OK only when the proof verifies end-to-end. Null pointers remain a
 * caller precondition (assert), never a FriError. dnac_fri_status_t is unchanged
 * (DNAC_FRI_OK + exactly 19 Plonky3 FriError-equivalent values).
 *
 * The F3-F6 test hooks (under DNAC_FRI_TESTING) now WRAP the same always-compiled
 * static helpers the real verifier uses, so those tests exercise production code.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_verifier.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "zk_field_helpers.h" /* reverse_bits_len_u64 */
#include "fri_fold.h"         /* fri_fold_row_fp2 */

/* Goldilocks multiplicative GENERATOR = 7 (Plonky3 goldilocks/src/goldilocks.rs:400;
 * test :772 asserts as_canonical_u64() == 7). Used as the LDE coset shift in
 * open_input's x (verifier.rs:614). */
#define FRI_GOLDILOCKS_GENERATOR ((uint64_t)7)

/* Fixed bounds (V6-class proofs are tiny; generous caps). */
#define FRI_MAX_ROUNDS 64
#define FRI_MAX_RO     64
#define FRI_MAX_ARITY  256
/* Leaf byte capacity: max over (a) an INPUT-mmcs row = width*8 + salt*8 and
 * (b) a commit-phase leaf = arity*16 + salt*8. Sized for the widest AIR: the S4
 * AGGREGATE Action trace is 1919 wide (1915 + 4 random) → 15352 B; +2 salts →
 * 15368 B; capped at 1936 cols = 15488 B. (Raised 2026-07-17 from 6656, which was
 * sized for the 817-wide conf_action trace and UNDER-sizes the 1919-wide
 * conf_action_agg input row → DNAC_FRI_ERR_INPUT_ERROR. rowbuf[64][CAP] =
 * 64*15488 ≈ 990 KB stack, within the 8 MB default.) */
#define FRI_LEAF_CAP   15488

/* ============================================================================
 * Always-compiled internal helpers (shared by dnac_fri_verify AND test hooks).
 * ========================================================================== */

/* params.final_poly_len() = 1 << log_final_poly_len (config.rs:29-31). */
static size_t fri_final_poly_len(const dnac_fri_params_t *params) {
    return (size_t)1u << params->log_final_poly_len;
}

/* checked_log_arity (proof.rs:44-55): valid iff 1 <= log_arity <= max_log_arity. */
static bool fri_log_arity_ok(uint8_t log_arity, size_t max_log_arity) {
    return (size_t)log_arity >= (size_t)1 && (size_t)log_arity <= max_log_arity;
}

/* Pre-transcript structural shape-check prefix of verify_fri (shape subset of
 * verifier.rs:146-246, in source order). Returns DNAC_FRI_OK iff all pass. */
static dnac_fri_status_t fri_shape_prefix(
    const dnac_fri_params_t *params,
    const dnac_fri_proof_t  *proof)
{
    assert(params != NULL);
    assert(proof != NULL);

    const size_t rounds = proof->num_commit_phase_commits;

    /* (1) verifier.rs:146-156 */
    for (size_t q = 0; q < proof->num_query_proofs; ++q) {
        if (proof->query_proofs[q].num_commit_phase_openings != rounds) {
            return DNAC_FRI_ERR_QUERY_COMMIT_PHASE_OPENINGS_COUNT_MISMATCH;
        }
    }
    if (proof->num_query_proofs > 0) {
        const dnac_fri_query_proof_t *q0 = &proof->query_proofs[0];
        /* (2) verifier.rs:159-175 */
        for (size_t r = 0; r < q0->num_commit_phase_openings; ++r) {
            if (!fri_log_arity_ok(q0->commit_phase_openings[r].log_arity, params->max_log_arity)) {
                return DNAC_FRI_ERR_INVALID_LOG_ARITY;
            }
        }
        /* (3) verifier.rs:177-199 */
        for (size_t q = 1; q < proof->num_query_proofs; ++q) {
            const dnac_fri_query_proof_t *qp = &proof->query_proofs[q];
            for (size_t r = 0; r < qp->num_commit_phase_openings; ++r) {
                if (!fri_log_arity_ok(qp->commit_phase_openings[r].log_arity, params->max_log_arity)) {
                    return DNAC_FRI_ERR_INVALID_LOG_ARITY;
                }
            }
            for (size_t r = 0; r < qp->num_commit_phase_openings; ++r) {
                if (qp->commit_phase_openings[r].log_arity != q0->commit_phase_openings[r].log_arity) {
                    return DNAC_FRI_ERR_QUERY_LOG_ARITIES_MISMATCH;
                }
            }
        }
    }
    /* (4) verifier.rs:206-211 */
    if (proof->num_commit_pow_witnesses != rounds) {
        return DNAC_FRI_ERR_COMMIT_POW_WITNESS_COUNT_MISMATCH;
    }
    /* (5) verifier.rs:229-235 */
    if (proof->num_final_poly != fri_final_poly_len(params)) {
        return DNAC_FRI_ERR_FINAL_POLY_LENGTH_MISMATCH;
    }
    /* (6) verifier.rs:240-246 */
    if (proof->num_query_proofs != params->num_queries) {
        return DNAC_FRI_ERR_QUERY_PROOF_COUNT_MISMATCH;
    }
    return DNAC_FRI_OK;
}

/* Terminal final-polynomial Horner evaluation (verifier.rs:308-321). */
static gold_fp2_t fri_terminal_horner_eval(
    const gold_fp2_t *final_poly,
    size_t            final_poly_len,
    size_t            log_global_max_height,
    uint64_t          domain_index,
    gold_fp_t        *out_x)
{
    gold_fp_t x = gold_fp_pow(
        gold_fp_two_adic_generator((unsigned)log_global_max_height),
        reverse_bits_len_u64(domain_index, (unsigned)log_global_max_height));
    if (out_x) {
        *out_x = x;
    }
    gold_fp2_t x_ext = gold_fp2_from_base(x);
    gold_fp2_t eval = gold_fp2_zero();
    for (size_t i = final_poly_len; i > 0; --i) {
        eval = gold_fp2_add(gold_fp2_mul(eval, x_ext), final_poly[i - 1]);
    }
    return eval;
}

/* Terminal FinalPolyMismatch compare (verifier.rs:323-325). */
static dnac_fri_status_t fri_terminal_horner_check(gold_fp2_t computed_eval, gold_fp2_t folded_eval) {
    if (!gold_fp2_eq(computed_eval, folded_eval)) {
        return DNAC_FRI_ERR_FINAL_POLY_MISMATCH;
    }
    return DNAC_FRI_OK;
}

/* Serialize n fp2 elements as the MMCS leaf wire form: per element, c0 then c1,
 * each a canonical u64 little-endian (ExtensionMmcs flatten fp2 -> base). */
static void fri_put_u64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static void fri_serialize_fp2_row(const gold_fp2_t *evals, size_t n, uint8_t *out) {
    for (size_t i = 0; i < n; ++i) {
        fri_put_u64_le(out + i * 16,     gold_fp_to_u64(evals[i].a));
        fri_put_u64_le(out + i * 16 + 8, gold_fp_to_u64(evals[i].b));
    }
}
static void fri_serialize_base_row(const gold_fp_t *vals, size_t n, uint8_t *out) {
    for (size_t i = 0; i < n; ++i) {
        fri_put_u64_le(out + i * 8, gold_fp_to_u64(vals[i]));
    }
}

/* A reduced-opening accumulator entry, keyed by log_height. */
typedef struct { size_t log_height; gold_fp2_t alpha_pow; gold_fp2_t ro; } fri_ro_t;

static fri_ro_t *fri_ro_entry(fri_ro_t *ros, size_t *n, size_t log_height) {
    for (size_t i = 0; i < *n; ++i) {
        if (ros[i].log_height == log_height) return &ros[i];
    }
    if (*n >= FRI_MAX_RO) return NULL;
    ros[*n].log_height = log_height;
    ros[*n].alpha_pow = gold_fp2_from_base(gold_fp_one());
    ros[*n].ro = gold_fp2_zero();
    return &ros[(*n)++];
}

/*
 * open_input (verifier.rs:524-660). Verifies each batch's input MMCS opening and
 * accumulates the reduced openings ro += alpha_pow*(p(z)-p(x))/(z-x). Writes the
 * result DESCENDING by log_height into out_ro[], sets *out_num. Returns status.
 * `out_reduced_index` (nullable) receives the first batch's MMCS reduced_index.
 */
static dnac_fri_status_t fri_open_input(
    const dnac_fri_params_t                          *params,
    size_t                                            log_global_max_height,
    uint64_t                                          index,
    const dnac_fri_query_proof_t                     *qp,
    gold_fp2_t                                        alpha,
    const dnac_fri_commitment_with_opening_points_t  *commitments,
    size_t                                            num_commitments,
    fri_ro_t                                         *out_ro,
    size_t                                           *out_num,
    uint64_t                                         *out_reduced_index)
{
    fri_ro_t ros[FRI_MAX_RO];
    size_t nro = 0;

    /* verifier.rs:547-552 */
    if (qp->num_input_batches != num_commitments) {
        return DNAC_FRI_ERR_INPUT_PROOF_BATCH_COUNT_MISMATCH;
    }

    for (size_t batch = 0; batch < num_commitments; ++batch) {
        const dnac_fri_batch_opening_t                  *bo = &qp->input_proof[batch];
        const dnac_fri_commitment_with_opening_points_t *cw = &commitments[batch];

        /* batch heights = domain.size() << log_blowup (verifier.rs:563-566).
         * All matrices in a batch must share one height (Phase 2A same-height);
         * mixed-height injection is Phase 2B and out of v3.0 scope. */
        size_t max_log_height = 0;
        bool have_height = false;
        for (size_t m = 0; m < cw->num_matrices; ++m) {
            size_t lh = (size_t)cw->matrices[m].domain.log_size + params->log_blowup;
            if (!have_height) { max_log_height = lh; have_height = true; }
            /* Mixed-height (Phase 2B) is unsupported. This was a debug-only
             * assert() — stripped under -DNDEBUG, which the messenger Release
             * build defines — so a release verifier silently accepted mixed
             * heights. Reject at runtime instead (2026-07-12 council red-team). */
            else if (lh != max_log_height) { return DNAC_FRI_ERR_UNSUPPORTED_PARAMS; }
        }

        /* Guard the shift below: max_log_height > log_global_max_height would make
         * (log_global_max_height - max_log_height) underflow size_t → shift-count
         * UB. A well-formed proof always has max_log_height <= log_global_max_height. */
        if (have_height && max_log_height > log_global_max_height) {
            return DNAC_FRI_ERR_UNSUPPORTED_PARAMS;
        }

        /* reduced_index = index >> (log_global_max_height - log2(max_height)) (verifier.rs:576-580). */
        uint64_t reduced_index = have_height
            ? (index >> (log_global_max_height - max_log_height))
            : 0;
        if (batch == 0 && out_reduced_index) *out_reduced_index = reduced_index;

        /* verifier.rs:582-588 */
        if (bo->num_matrices != cw->num_matrices) {
            return DNAC_FRI_ERR_BATCH_OPENED_VALUES_COUNT_MISMATCH;
        }

        /* Input MMCS verify_batch (verifier.rs:590-597) via DNAC same-height batch
         * merkle. Leaf = each matrix's opened row serialized canonical u64-LE. */
        const uint8_t *opened_rows[FRI_MAX_RO];
        size_t         row_byte_lens[FRI_MAX_RO];
        uint8_t        rowbuf[FRI_MAX_RO][FRI_LEAF_CAP];
        if (cw->num_matrices > FRI_MAX_RO) return DNAC_FRI_ERR_INPUT_ERROR;
        for (size_t m = 0; m < cw->num_matrices; ++m) {
            size_t cols = bo->opened_values_lens[m];
            /* M3b: salted leaf = opened row ‖ salt_elems base salts
             * (hiding_mmcs.rs:169-170). salt_elems==0 -> plain (backward-compat). */
            const size_t se = bo->salt_elems;
            if ((cols + se) * 8 > FRI_LEAF_CAP) return DNAC_FRI_ERR_INPUT_ERROR;
            fri_serialize_base_row(bo->opened_values[m], cols, rowbuf[m]);
            if (se > 0) {
                /* SEC-M3b-1: salts[m] present, per matrix. A missing salts row is
                 * a malformed proof (fail-close). */
                if (bo->salts == NULL || bo->salts[m] == NULL) {
                    return DNAC_FRI_ERR_INPUT_ERROR;
                }
                /* SEC-M3b-2 canonicality is a `gold_fp_t` TYPE INVARIANT — every
                 * field element is canonical-by-construction (gold_fp_from_u64 =
                 * canonicalize_u64, field_goldilocks.c:39-56), so gold_fp_to_u64
                 * here is already in [0,p). Canonicality of RAW wire bytes is
                 * enforced at DECODE by rd_base's `>= p` reject (fri_proof_codec.c),
                 * exactly like every other proof field; the salt wire codec is the
                 * next increment (M3b-prover), so no raw-salt path reaches here yet.
                 * (Red-team M3b: an in-struct `gold_fp_to_u64 >= p` guard would be
                 * DEAD CODE — canonicalize_u64 can never return >= p — so it is
                 * NOT written here; the honest invariant is stated instead.) */
                for (size_t s = 0; s < se; ++s) {
                    fri_put_u64_le(rowbuf[m] + (cols + s) * 8,
                                   gold_fp_to_u64(bo->salts[m][s]));
                }
            }
            opened_rows[m] = rowbuf[m];
            row_byte_lens[m] = (cols + se) * 8;
        }
        if (have_height) {
            /* The verifier supplies the computed reduced_index + height; only the
             * sibling path comes from the proof (verifier.rs:590-597). */
            dnac_merkle_proof_t iproof;
            iproof.leaf_index   = reduced_index;
            iproof.depth        = (uint32_t)max_log_height;
            iproof.num_matrices = cw->num_matrices;
            iproof.siblings     = bo->opening_proof.siblings;
            dnac_merkle_status_t ms = dnac_merkle_batch_verify(
                &cw->commitment, opened_rows, row_byte_lens,
                cw->num_matrices, (size_t)1u << max_log_height, &iproof);
            if (ms != DNAC_MERKLE_OK) return DNAC_FRI_ERR_INPUT_ERROR;
        }

        /* Per-matrix reduced-opening accumulation (verifier.rs:599-642). */
        for (size_t m = 0; m < cw->num_matrices; ++m) {
            const dnac_fri_matrix_openings_t *mo = &cw->matrices[m];
            size_t log_height = (size_t)mo->domain.log_size + params->log_blowup;
            size_t bits_reduced = log_global_max_height - log_height;
            uint64_t rev = reverse_bits_len_u64(index >> bits_reduced, (unsigned)log_height);

            /* x = GENERATOR * two_adic_generator(log_height)^rev  (verifier.rs:614-615). */
            gold_fp_t x = gold_fp_mul(
                gold_fp_from_u64(FRI_GOLDILOCKS_GENERATOR),
                gold_fp_pow(gold_fp_two_adic_generator((unsigned)log_height), rev));
            gold_fp2_t x_ext = gold_fp2_from_base(x);

            fri_ro_t *e = fri_ro_entry(ros, &nro, log_height);
            if (!e) return DNAC_FRI_ERR_INPUT_ERROR;

            for (size_t point = 0; point < mo->num_points; ++point) {
                const dnac_fri_opening_point_t *pt = &mo->points[point];
                /* PointEvaluationCountMismatch (verifier.rs:625-633). */
                if (bo->opened_values_lens[m] != pt->num_claimed_evals) {
                    return DNAC_FRI_ERR_POINT_EVALUATION_COUNT_MISMATCH;
                }
                gold_fp2_t quotient = gold_fp2_inv(gold_fp2_sub(pt->point, x_ext)); /* (z - x)^-1 */
                for (size_t j = 0; j < pt->num_claimed_evals; ++j) {
                    gold_fp2_t p_at_z = pt->claimed_evals[j];
                    gold_fp2_t p_at_x = gold_fp2_from_base(bo->opened_values[m][j]);
                    gold_fp2_t diff = gold_fp2_sub(p_at_z, p_at_x);
                    gold_fp2_t term = gold_fp2_mul(gold_fp2_mul(e->alpha_pow, diff), quotient);
                    e->ro = gold_fp2_add(e->ro, term);
                    e->alpha_pow = gold_fp2_mul(e->alpha_pow, alpha);
                }
            }
        }

        /* open_input FinalPolyMismatch site (verifier.rs:647-651): a height-1
         * (log_blowup) constant trace must produce a zero reduced opening. */
        for (size_t i = 0; i < nro; ++i) {
            if (ros[i].log_height == params->log_blowup &&
                !gold_fp2_eq(ros[i].ro, gold_fp2_zero())) {
                return DNAC_FRI_ERR_FINAL_POLY_MISMATCH;
            }
        }
    }

    /* Sort descending by log_height (verifier.rs:654-659) — selection sort. */
    for (size_t i = 0; i < nro; ++i) {
        size_t best = i;
        for (size_t j = i + 1; j < nro; ++j) {
            if (ros[j].log_height > ros[best].log_height) best = j;
        }
        fri_ro_t tmp = ros[i]; ros[i] = ros[best]; ros[best] = tmp;
    }
    for (size_t i = 0; i < nro; ++i) out_ro[i] = ros[i];
    *out_num = nro;
    return DNAC_FRI_OK;
}

/*
 * verify_query (verifier.rs:363-502). Folds the reduced openings down through the
 * commit-phase openings and returns the terminal folded evaluation.
 */
static dnac_fri_status_t fri_verify_query(
    const dnac_fri_params_t      *params,
    uint64_t                      start_index,
    const dnac_fri_query_proof_t *qp,
    const dnac_merkle_digest_t   *commit_phase_commits,
    size_t                        num_commits,
    const gold_fp2_t             *betas,
    size_t                        num_betas,
    const fri_ro_t               *ro,
    size_t                        num_ro,
    size_t                        log_global_max_height,
    size_t                        log_final_height,
    gold_fp2_t                   *out_folded_eval)
{
    (void)num_commits;
    /* verifier.rs:378-394 */
    if (num_ro == 0) return DNAC_FRI_ERR_MISSING_INITIAL_REDUCED_OPENING;
    if (ro[0].log_height != log_global_max_height) {
        return DNAC_FRI_ERR_INITIAL_REDUCED_OPENING_HEIGHT_MISMATCH;
    }
    gold_fp2_t folded_eval = ro[0].ro;      /* :395 */
    size_t ro_i = 1;
    size_t log_current_height = log_global_max_height; /* :398 */
    uint64_t idx = start_index;

    for (size_t round = 0; round < qp->num_commit_phase_openings; ++round) {
        const dnac_fri_commit_phase_proof_step_t *step = &qp->commit_phase_openings[round];

        /* verifier.rs:403-410 — max_log_arity is clamped to log_current_height. */
        size_t max_la = params->max_log_arity < log_current_height ? params->max_log_arity : log_current_height;
        if (!fri_log_arity_ok(step->log_arity, max_la)) return DNAC_FRI_ERR_INVALID_LOG_ARITY;
        size_t log_arity = step->log_arity;
        size_t arity = (size_t)1u << log_arity;
        if (arity > FRI_MAX_ARITY) return DNAC_FRI_ERR_INVALID_LOG_ARITY;

        /* verifier.rs:413-420 */
        if (step->num_sibling_values != arity - 1) {
            return DNAC_FRI_ERR_SIBLING_VALUES_LENGTH_MISMATCH;
        }

        /* Reconstruct the evaluation row (verifier.rs:422-433). index_in_group
         * uses the PRE-shift index. */
        size_t index_in_group = (size_t)(idx % arity);
        gold_fp2_t evals[FRI_MAX_ARITY];
        evals[index_in_group] = folded_eval;
        size_t sib = 0;
        for (size_t j = 0; j < arity; ++j) {
            if (j != index_in_group) evals[j] = step->sibling_values[sib++];
        }

        size_t log_folded_height = log_current_height - log_arity; /* :436 */
        idx >>= log_arity;                                         /* :444 */

        /* Commit-phase MMCS verify (verifier.rs:446-455): leaf = the arity evals,
         * at the post-shift index, depth = log_folded_height. M3b: when the FRI
         * mmcs is hiding, ExtensionMmcs BASE-flattens the fp2 evals then the
         * hiding mmcs appends salt_elems BASE salts (extension_mmcs.rs:77-95 +
         * hiding_mmcs.rs:169-170): leaf = fp2 row (arity*16 B) ‖ salts (se*8 B). */
        const size_t cse = step->salt_elems;
        if (arity * 16 + cse * 8 > FRI_LEAF_CAP) return DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR;
        uint8_t leaf[FRI_LEAF_CAP];
        fri_serialize_fp2_row(evals, arity, leaf);
        if (cse > 0) {
            if (step->salts == NULL) return DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR;
            /* Salt canonicality is the gold_fp_t type invariant (see the input-open
             * salt block above); enforced at wire-decode by rd_base, not by a dead
             * in-struct `>= p` guard (red-team M3b). */
            for (size_t s = 0; s < cse; ++s) {
                fri_put_u64_le(leaf + arity * 16 + s * 8,
                               gold_fp_to_u64(step->salts[s]));
            }
        }
        dnac_merkle_proof_t mproof;
        mproof.leaf_index   = idx;
        mproof.depth        = (uint32_t)log_folded_height;
        mproof.num_matrices = 1;
        mproof.siblings     = step->opening_proof.siblings;
        if (dnac_merkle_verify(&commit_phase_commits[round], leaf, arity * 16 + cse * 8, &mproof) != DNAC_MERKLE_OK) {
            return DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR;
        }

        /* Fold (verifier.rs:458-464). */
        folded_eval = fri_fold_row_fp2((size_t)idx, (unsigned)log_folded_height,
                                       (unsigned)log_arity, betas[round], evals, arity);
        log_current_height = log_folded_height; /* :467 */

        /* Roll in any reduced opening newly at this height (verifier.rs:477-480).
         * beta^arity = beta^(2^log_arity) via log_arity squarings. */
        if (ro_i < num_ro && ro[ro_i].log_height == log_folded_height) {
            gold_fp2_t beta_pow = betas[round];
            for (size_t s = 0; s < log_arity; ++s) beta_pow = gold_fp2_sqr(beta_pow);
            folded_eval = gold_fp2_add(folded_eval, gold_fp2_mul(beta_pow, ro[ro_i].ro));
            ro_i++;
        }
    }

    /* verifier.rs:483-488 */
    if (log_current_height != log_final_height) {
        return DNAC_FRI_ERR_FINAL_FOLD_HEIGHT_MISMATCH;
    }
    /* verifier.rs:491-496 */
    if (ro_i < num_ro) {
        return DNAC_FRI_ERR_UNCONSUMED_REDUCED_OPENINGS;
    }
    *out_folded_eval = folded_eval;
    return DNAC_FRI_OK; /* :501 */
}

/*
 * Integrated verify_fri (verifier.rs:113-329). `dbg` (nullable) captures
 * intermediate values for the integrated oracle cross-checks.
 */
static dnac_fri_status_t fri_verify_impl(
    const dnac_fri_params_t                         *params,
    const dnac_fri_proof_t                          *proof,
    dnac_transcript_t                               *transcript,
    const dnac_fri_commitment_with_opening_points_t *commitments,
    size_t                                           num_commitments,
    dnac_fri_debug_t                                *dbg)
{
    /* Null/invalid C input is a caller precondition (pure-mirror enum decision). */
    assert(params != NULL);
    assert(proof != NULL);
    assert(transcript != NULL);

    dnac_fri_status_t st = fri_shape_prefix(params, proof);
    if (st != DNAC_FRI_OK) return st;

    /* log_global_max_height = sum(log_arities) + log_blowup + log_final_poly_len
     * (verifier.rs:201-204); log_final_height = log_blowup + log_final_poly_len. */
    size_t sum_la = 0;
    if (proof->num_query_proofs > 0) {
        const dnac_fri_query_proof_t *q0 = &proof->query_proofs[0];
        for (size_t r = 0; r < q0->num_commit_phase_openings; ++r) {
            sum_la += (size_t)q0->commit_phase_openings[r].log_arity;
        }
    }
    size_t lgmh = sum_la + params->log_blowup + params->log_final_poly_len;
    size_t log_final_height = params->log_blowup + params->log_final_poly_len;
    const size_t extra_query_index_bits = 0; /* TwoAdicFriFolding (two_adic_pcs.rs:105-107) */

    /* Pre-consensus param-safety guards (2026-07-12 council red-team: Sun Tzu
     * num_queries=0 downgrade + Taleb shift-UB). These reject provably-broken
     * wire params, NOT a chosen security level:
     *  - num_queries == 0 → the query loop below (and low-degree test) never
     *    runs → verifier accepts any polynomial. Real FRI has num_queries > 0.
     *  - lgmh >= 64 → sample_bits(lgmh) does 1u64<<bits (transcript.c) and
     *    domain_index >>= sum_la (sum_la <= lgmh) are shift-count UB; two builds
     *    can diverge on identical bytes (chain-split). A real trace has lgmh far
     *    below 64 (2^lgmh rows). Guarding lgmh covers all downstream shifts. */
    if (params->num_queries == 0 || lgmh >= 64) {
        return DNAC_FRI_ERR_UNSUPPORTED_PARAMS;
    }

    /* T1 — alpha (verifier.rs:143). */
    gold_fp2_t alpha = dnac_transcript_sample_fp2(transcript);

    /* Commit-phase loop (verifier.rs:213-227): observe, check PoW, sample beta. */
    gold_fp2_t betas[FRI_MAX_ROUNDS];
    size_t num_betas = proof->num_commit_phase_commits;
    if (num_betas > FRI_MAX_ROUNDS) return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    for (size_t round = 0; round < num_betas; ++round) {
        dnac_transcript_observe_bytes(transcript, proof->commit_phase_commits[round].bytes,
                                      DNAC_MERKLE_DIGEST_BYTES);
        if (!dnac_transcript_check_witness(transcript, params->commit_proof_of_work_bits,
                                           proof->commit_pow_witnesses[round])) {
            return DNAC_FRI_ERR_INVALID_POW_WITNESS;
        }
        betas[round] = dnac_transcript_sample_fp2(transcript);
    }

    /* observe final_poly (verifier.rs:238). */
    for (size_t i = 0; i < proof->num_final_poly; ++i) {
        dnac_transcript_observe_fp2(transcript, proof->final_poly[i]);
    }
    /* observe log_arities (verifier.rs:249-251). */
    if (proof->num_query_proofs > 0) {
        const dnac_fri_query_proof_t *q0 = &proof->query_proofs[0];
        for (size_t r = 0; r < q0->num_commit_phase_openings; ++r) {
            dnac_transcript_observe_fp(transcript,
                gold_fp_from_u64((uint64_t)q0->commit_phase_openings[r].log_arity));
        }
    }
    /* query PoW (verifier.rs:253-256). */
    if (!dnac_transcript_check_witness(transcript, params->query_proof_of_work_bits,
                                       proof->query_pow_witness)) {
        return DNAC_FRI_ERR_INVALID_POW_WITNESS;
    }

    if (dbg) {
        dbg->alpha = alpha;
        dbg->num_betas = num_betas;
        for (size_t i = 0; i < num_betas && i < 16; ++i) dbg->betas[i] = betas[i];
        dbg->num_queries = params->num_queries;
    }

    /* Per-query loop (verifier.rs:261-326). */
    for (size_t q = 0; q < params->num_queries; ++q) {
        uint64_t index = dnac_transcript_sample_bits(transcript, lgmh + extra_query_index_bits); /* :268 */

        fri_ro_t ro[FRI_MAX_RO];
        size_t num_ro = 0;
        uint64_t reduced_index = 0;
        st = fri_open_input(params, lgmh, index, &proof->query_proofs[q], alpha,
                            commitments, num_commitments, ro, &num_ro, &reduced_index); /* :271 */
        if (st != DNAC_FRI_OK) return st;

        uint64_t domain_index = index >> extra_query_index_bits; /* :287 */
        gold_fp2_t folded;
        st = fri_verify_query(params, domain_index, &proof->query_proofs[q],
                              proof->commit_phase_commits, proof->num_commit_phase_commits,
                              betas, num_betas, ro, num_ro, lgmh, log_final_height, &folded); /* :298-306 */
        if (st != DNAC_FRI_OK) return st;

        /* verify_query opens the final polynomial at the POST-FOLD index. Plonky3
         * passes domain_index by &mut into verify_query, which shifts it right by
         * each round's log_arity (verifier.rs:301 + :444), then evaluates the final
         * poly at reverse_bits_len(domain_index, log_global_max_height) (verifier.rs:
         * 308-312). fri_verify_query above shifted a BY-VALUE copy, so the caller's
         * domain_index is still pre-fold; apply the same total shift (sum of the
         * per-round log_arities, consistent across queries by the
         * QueryLogAritiesMismatch check) before the terminal. Previously masked by
         * V6/roll-in (log_final_poly_len=0 -> length-1 constant final_poly, x-
         * independent); surfaced by the first log_final_poly_len>0 integration. */
        domain_index >>= sum_la;

        /* Terminal Horner final check (verifier.rs:308-325). */
        gold_fp2_t eval = fri_terminal_horner_eval(proof->final_poly, proof->num_final_poly,
                                                   lgmh, domain_index, NULL);
        st = fri_terminal_horner_check(eval, folded);
        if (st != DNAC_FRI_OK) return st;

        if (dbg && q < 16) {
            dbg->query_index[q] = index;
            dbg->reduced_index[q] = reduced_index;
            dbg->folded_eval[q] = folded;
        }
    }

    return DNAC_FRI_OK; /* verify_fri Ok(()) — proof verified end-to-end (verifier.rs:328). */
}

/* ============================================================================
 * Public entry.
 * ========================================================================== */
dnac_fri_status_t dnac_fri_verify(
    const dnac_fri_params_t                         *params,
    const dnac_fri_proof_t                          *proof,
    dnac_transcript_t                               *transcript,
    const dnac_fri_commitment_with_opening_points_t *commitments_with_opening_points,
    size_t                                           num_commitments)
{
    return fri_verify_impl(params, proof, transcript,
                           commitments_with_opening_points, num_commitments, NULL);
}

/* ============================================================================
 * Test-only hooks (DNAC_FRI_TESTING) — wrap the SAME production helpers above.
 * ========================================================================== */
#ifdef DNAC_FRI_TESTING

dnac_fri_status_t dnac_fri_test_shape_prefix(
    const dnac_fri_params_t *params,
    const dnac_fri_proof_t  *proof)
{
    return fri_shape_prefix(params, proof);
}

bool dnac_fri_test_transcript_flow(
    dnac_transcript_t       *t,
    const dnac_fri_params_t *params,
    const dnac_fri_proof_t  *proof,
    dnac_fri_milestone_cb    after_op,
    void                    *ctx,
    dnac_fri_flow_out_t     *out,
    dnac_fri_status_t       *out_err)
{
    assert(t != NULL);
    assert(params != NULL);
    assert(proof != NULL);
    assert(out != NULL);

    dnac_fri_status_t shape = fri_shape_prefix(params, proof);
    if (shape != DNAC_FRI_OK) {
        if (out_err) *out_err = shape;
        return false;
    }

    size_t sum_log_arities = 0;
    if (proof->num_query_proofs > 0) {
        const dnac_fri_query_proof_t *q0 = &proof->query_proofs[0];
        for (size_t r = 0; r < q0->num_commit_phase_openings; ++r) {
            sum_log_arities += (size_t)q0->commit_phase_openings[r].log_arity;
        }
    }
    out->log_global_max_height = sum_log_arities + params->log_blowup + params->log_final_poly_len;
    out->num_query_indices = 0;
    const size_t extra_query_index_bits = 0;

    (void)dnac_transcript_sample_fp2(t);
    if (after_op) after_op(ctx, t);

    for (size_t round = 0; round < proof->num_commit_phase_commits; ++round) {
        dnac_transcript_observe_bytes(t, proof->commit_phase_commits[round].bytes, DNAC_MERKLE_DIGEST_BYTES);
        if (after_op) after_op(ctx, t);
        if (!dnac_transcript_check_witness(t, params->commit_proof_of_work_bits,
                                           proof->commit_pow_witnesses[round])) {
            if (out_err) *out_err = DNAC_FRI_ERR_INVALID_POW_WITNESS;
            return false;
        }
        if (after_op) after_op(ctx, t);
        (void)dnac_transcript_sample_fp2(t);
        if (after_op) after_op(ctx, t);
    }

    for (size_t i = 0; i < proof->num_final_poly; ++i) {
        dnac_transcript_observe_fp2(t, proof->final_poly[i]);
    }
    if (after_op) after_op(ctx, t);

    if (proof->num_query_proofs > 0) {
        const dnac_fri_query_proof_t *q0 = &proof->query_proofs[0];
        for (size_t r = 0; r < q0->num_commit_phase_openings; ++r) {
            dnac_transcript_observe_fp(
                t, gold_fp_from_u64((uint64_t)q0->commit_phase_openings[r].log_arity));
            if (after_op) after_op(ctx, t);
        }
    }

    if (!dnac_transcript_check_witness(t, params->query_proof_of_work_bits,
                                       proof->query_pow_witness)) {
        if (out_err) *out_err = DNAC_FRI_ERR_INVALID_POW_WITNESS;
        return false;
    }
    if (after_op) after_op(ctx, t);

    for (size_t q = 0; q < params->num_queries; ++q) {
        uint64_t idx = dnac_transcript_sample_bits(
            t, out->log_global_max_height + extra_query_index_bits);
        if (out->num_query_indices < 16) out->query_indices[out->num_query_indices++] = idx;
        if (after_op) after_op(ctx, t);
    }
    return true;
}

dnac_merkle_status_t dnac_fri_test_mmcs_verify_single(
    const dnac_merkle_digest_t *root,
    const uint8_t              *leaf_bytes,
    size_t                      leaf_byte_len,
    uint64_t                    leaf_index,
    uint32_t                    depth,
    const dnac_merkle_digest_t *siblings)
{
    assert(root != NULL);
    assert(leaf_bytes != NULL);
    assert(depth == 0 || siblings != NULL);
    dnac_merkle_proof_t proof;
    proof.leaf_index   = leaf_index;
    proof.depth        = depth;
    proof.num_matrices = 1;
    proof.siblings     = (dnac_merkle_digest_t *)siblings;
    return dnac_merkle_verify(root, leaf_bytes, leaf_byte_len, &proof);
}

dnac_fri_status_t dnac_fri_test_verify_query_shape(
    const size_t *ro_log_heights,
    size_t        num_ro,
    size_t        log_global_max_height,
    size_t        log_final_height)
{
    if (num_ro == 0) return DNAC_FRI_ERR_MISSING_INITIAL_REDUCED_OPENING;
    if (ro_log_heights[0] != log_global_max_height) {
        return DNAC_FRI_ERR_INITIAL_REDUCED_OPENING_HEIGHT_MISMATCH;
    }
    if (log_global_max_height != log_final_height) {
        return DNAC_FRI_ERR_FINAL_FOLD_HEIGHT_MISMATCH;
    }
    if (num_ro > 1) return DNAC_FRI_ERR_UNCONSUMED_REDUCED_OPENINGS;
    return DNAC_FRI_OK;
}

gold_fp2_t dnac_fri_test_terminal_horner_eval(
    const gold_fp2_t *final_poly,
    size_t            final_poly_len,
    size_t            log_global_max_height,
    uint64_t          domain_index,
    gold_fp_t        *out_x)
{
    return fri_terminal_horner_eval(final_poly, final_poly_len, log_global_max_height, domain_index, out_x);
}

dnac_fri_status_t dnac_fri_test_terminal_horner_check(
    gold_fp2_t computed_eval,
    gold_fp2_t folded_eval)
{
    return fri_terminal_horner_check(computed_eval, folded_eval);
}

dnac_fri_status_t dnac_fri_test_verify_capture(
    const dnac_fri_params_t                         *params,
    const dnac_fri_proof_t                          *proof,
    dnac_transcript_t                               *transcript,
    const dnac_fri_commitment_with_opening_points_t *commitments_with_opening_points,
    size_t                                           num_commitments,
    dnac_fri_debug_t                                *dbg)
{
    return fri_verify_impl(params, proof, transcript,
                           commitments_with_opening_points, num_commitments, dbg);
}

#endif /* DNAC_FRI_TESTING */
