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
/* Leaf LANE capacity (P1c: leaves are Goldilocks lanes, not bytes): max over
 * (a) an INPUT-mmcs row = width + salt lanes and (b) a commit-phase leaf =
 * arity*2 (fp2 base-flattened) + salt lanes. Sized for the widest AIR: the F3
 * AGGREGATE Action ZK trace is 2318 wide (ak/nk 4-lane, 2026-07-22), merged
 * with 4 random codewords → 2322 lanes; +2 salts → 2324. Capped at 2560 lanes
 * (== DNAC_STARK_MAX_MAIN_WIDTH) for headroom. (History as bytes: 15488 →
 * 16384 → 20480 B; converted to 2560 LANES at the P1c Poseidon2 cutover —
 * same memory footprint, rowbuf[64][2560]·8 = 1.25 MB stack.) */
#define FRI_LEAF_CAP   2560

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
    /* P1e-E (S8-MED1): ALWAYS-ON fail-close (survives -DNDEBUG). */
    if (params == NULL || proof == NULL) return DNAC_FRI_ERR_INPUT_ERROR;

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

/* Lay out n fp2 elements as MMCS leaf LANES: per element c0 then c1
 * (ExtensionMmcs base-flatten order, extension_mmcs.rs:77-95). P1c: the
 * Poseidon2 MMCS consumes canonical lanes directly — no byte serialization. */
static void fri_lanes_fp2_row(const gold_fp2_t *evals, size_t n, uint64_t *out) {
    for (size_t i = 0; i < n; ++i) {
        out[i * 2]     = gold_fp_to_u64(evals[i].a);
        out[i * 2 + 1] = gold_fp_to_u64(evals[i].b);
    }
}
static void fri_lanes_base_row(const gold_fp_t *vals, size_t n, uint64_t *out) {
    for (size_t i = 0; i < n; ++i) {
        out[i] = gold_fp_to_u64(vals[i]);
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
         * P2L-d d2: matrices in a batch MAY have different heights — the
         * batch-stark mixed commit (merkle_tree.rs:127-176 layer injection).
         * The max height drives the reduced index (verifier.rs:567-580); a
         * mixed batch verifies through the d1a mixed MMCS below. (The
         * pre-P2L-d same-height reject — Phase 2A, 2026-07-12 council
         * red-team — is superseded by the byte-matched mixed verify.) */
        if (cw->num_matrices > FRI_MAX_RO) return DNAC_FRI_ERR_INPUT_ERROR;
        /* ⚠ FAIL-OPEN CLOSED (S2'-d, 2026-07-27; red-team lens 3). An empty
         * batch left `have_height` false, which gated OUT the entire MMCS verify
         * block below — the batch was then admitted with its opening proof never
         * checked at all. Upstream calls `input_mmcs.verify_batch`
         * UNCONDITIONALLY (82cfad73 fri/src/verifier.rs:590-597); DNAC's
         * `if (have_height)` was a local deviation that failed OPEN.
         * Rejecting outright is the fail-close form and is stricter than
         * upstream: every real batch carries >= 1 matrix (batch_verify.c gives
         * each round n >= 1 / total_qc >= 1), so no honest proof reaches this.
         * Not reachable through dnac_batch_verify today — but dnac_fri_verify is
         * a PUBLIC entry point, so the guard belongs here, not in the caller. */
        if (cw->num_matrices == 0) return DNAC_FRI_ERR_INPUT_ERROR;
        size_t max_log_height = 0;
        bool have_height = false;
        bool mixed_heights = false;
        size_t mat_log_heights[FRI_MAX_RO];
        for (size_t m = 0; m < cw->num_matrices; ++m) {
            size_t lh = (size_t)cw->matrices[m].domain.log_size + params->log_blowup;
            mat_log_heights[m] = lh;
            if (!have_height) { max_log_height = lh; have_height = true; }
            else if (lh != max_log_height) {
                mixed_heights = true;
                if (lh > max_log_height) max_log_height = lh;
            }
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

        /* Input MMCS verify_batch (verifier.rs:590-597) via the Poseidon2 batch
         * MMCS (P1c). Leaf = each matrix's opened row as canonical LANES. */
        const uint64_t *opened_rows[FRI_MAX_RO];
        size_t          row_lane_lens[FRI_MAX_RO];
        uint64_t        rowbuf[FRI_MAX_RO][FRI_LEAF_CAP];
        for (size_t m = 0; m < cw->num_matrices; ++m) {
            size_t cols = bo->opened_values_lens[m];
            /* M3b: salted leaf = opened row ‖ salt_elems base salts
             * (hiding_mmcs.rs:169-170). salt_elems==0 -> plain.
             *
             * ⚠ THE OLD COMMENT HERE WAS FALSE and is corrected in place
             * (S2'-d, 2026-07-27; refuted independently by red-team lenses 1, 2
             * and 3). It claimed "cols is pinned by the shape checks +
             * PointEvaluationCountMismatch below" and that salt_elems is
             * "pinned upstream (shielded wire pin, fri_proof_codec.c)".
             * Both halves were wrong:
             *   - the shape prefix never RECEIVES this data (fri_verifier.h
             *     documents that commitments_with_opening_points is not even a
             *     parameter), so it contributes nothing to any pin;
             *   - the count check below compares `cols` against
             *     `num_claimed_evals`, which is `BASE_LEN + rand tail` where the
             *     tail is wire-decoded and unpinned in the is_zk path — the ONLY
             *     path the shielded verifier uses. Wire-vs-wire is not a pin;
             *   - fri_proof_codec.c pins NO salt count. The function that
             *     comment named, dnac_fri_verify_wire_shielded, was DELETED at
             *     d4.d.
             * Under the Poseidon2 PaddingFreeSponge leaf hash the preimage
             * length must be protocol-fixed (G-SEC-P1-6). BOTH halves of that
             * length are now pinned, but NOT here — the final S2'-d block moved
             * them into `dnac_batch_verify`, which takes `salt_elems` and
             * `num_random_codewords` as REQUIRED caller-stated arguments and
             * enforces them over the whole proof before any transcript work
             * (batch_verify.h carries the rationale and the repartition attack
             * that motivated it). So this function still sees an unpinned
             * `cols`/`se` pair when called through the PUBLIC dnac_fri_verify
             * entry with a caller that pins neither; the pin belongs to the
             * batch layer because that is where the instance's shape is known. */
            /* ── check_widths: the matrix width is PINNED TO THE CLAIMED
             *    EVALUATION COUNT, never read from the proof (S2'-f, option A;
             *    v0.6.2 fri/src/verifier.rs:695-712 builds
             *    `Dimensions { width: values.len(), height }` from the FIRST
             *    opening point, and merkle-tree/src/mmcs/geometry.rs:16-30
             *    `check_widths` then rejects a row whose length disagrees).
             *
             *    Upstream's own reason (geometry.rs:12-15): "The leaf hash
             *    flattens all rows at one height into a single element stream,
             *    so a digest match alone does not pin where one row ends and
             *    the next begins."
             *
             *    ORDER IS THE POINT. Upstream runs check_widths at
             *    mmcs/batch.rs:184 — BEFORE any hashing. DNAC previously built
             *    the leaf from the proof-supplied `opened_values_lens[m]` and
             *    only compared it against `num_claimed_evals` afterwards, in
             *    the per-point loop below, so the same malformed proof surfaced
             *    as PointEvaluationCountMismatch instead of an InputError. Both
             *    REJECT — this was an error-taxonomy divergence, not a
             *    soundness gap — but the KAT pins the variant, and matching the
             *    reference is what keeps that pin meaningful.
             *
             *    The per-point check below SURVIVES and is still reachable:
             *    upstream keeps PointEvaluationCountMismatch (v0.6.2
             *    verifier.rs:749-757) for opening points 1..N-1, whose counts
             *    are NOT what pinned the width. Only point 0 moves here.
             *
             *    num_points == 0 is already rejected as MatrixWithoutOpeningPoints
             *    (S2'-d), which is what makes `points[0]` safe to read. */
            const dnac_fri_matrix_openings_t *mw = &cw->matrices[m];
            if (mw->num_points == 0) {
                return DNAC_FRI_ERR_MATRIX_WITHOUT_OPENING_POINTS;
            }
            if (cols != mw->points[0].num_claimed_evals) {
                return DNAC_FRI_ERR_INPUT_ERROR; /* MerkleTreeError::WrongWidth */
            }

            const size_t se = bo->salt_elems;
            if (cols + se > FRI_LEAF_CAP) return DNAC_FRI_ERR_INPUT_ERROR;
            fri_lanes_base_row(bo->opened_values[m], cols, rowbuf[m]);
            if (se > 0) {
                /* SEC-M3b-1: salts[m] present, per matrix. A missing salts row is
                 * a malformed proof (fail-close). */
                if (bo->salts == NULL || bo->salts[m] == NULL) {
                    return DNAC_FRI_ERR_INPUT_ERROR;
                }
                /* SEC-M3b-2 canonicality is a `gold_fp_t` TYPE INVARIANT — every
                 * field element is canonical-by-construction; raw wire lanes are
                 * `>= p`-rejected at DECODE (rd_base, fri_proof_codec.c). The
                 * Poseidon2 MMCS re-checks lanes fail-close (G-DET-P1-5). */
                for (size_t s = 0; s < se; ++s) {
                    rowbuf[m][cols + s] = gold_fp_to_u64(bo->salts[m][s]);
                }
            }
            opened_rows[m] = rowbuf[m];
            row_lane_lens[m] = cols + se;
        }
        if (have_height) {
            /* The verifier supplies the computed reduced_index + height; only the
             * sibling path comes from the proof (verifier.rs:590-597). Same-height
             * batches keep the P1b path (KATs frozen); mixed batches go through
             * the d1a mixed MMCS (per-matrix reduced indices + layer injection,
             * mmcs.rs:1052-1180 / merkle_tree.rs:127-176).
             *
             * ⚠ HEAP OVERREAD CLOSED (S2'-d, 2026-07-27; red-team lens 4). The
             * path is handed over as the WHOLE `bo->opening_proof`, so its
             * length travels with its pointer. Previously the bare
             * `.siblings` pointer was paired with the DERIVED `max_log_height`
             * while the array had been allocated to exactly the WIRE-declared
             * `.depth` (fri_proof_codec.c:352-360, whose own comment states it
             * "does NOT check depth == verifier-derived height"). Patching the
             * wire depth 13 -> 1 therefore made the MMCS walk read 12 digests
             * — 384 bytes — past a 32-byte allocation, and nothing else caught
             * it: query proofs are never observed into the transcript, so the
             * PoW witness still validated. The verdict stayed deterministic
             * (ROOT_MISMATCH), so this was memory-safety, not a soundness
             * break — but Android is a declared target and its hardened
             * allocator turns that read into a probabilistic SIGSEGV.
             * The MMCS now rejects depth != log2(height) itself, which is what
             * upstream has always done (82cfad73 mmcs.rs:1110-1116 /
             * v0.6.2 mmcs/batch.rs:174-179, WrongHeight). */
            dnac_p2_mmcs_status_t ms;
            if (!mixed_heights) {
                ms = dnac_p2_mmcs_verify(
                    &cw->commitment, opened_rows, row_lane_lens,
                    cw->num_matrices, (size_t)1u << max_log_height,
                    reduced_index, &bo->opening_proof);
            } else {
                size_t mat_heights[FRI_MAX_RO];
                for (size_t m = 0; m < cw->num_matrices; ++m) {
                    mat_heights[m] = (size_t)1u << mat_log_heights[m];
                }
                ms = dnac_p2_mmcs_verify_mixed(
                    &cw->commitment, opened_rows, row_lane_lens, mat_heights,
                    cw->num_matrices, reduced_index, &bo->opening_proof);
            }
            if (ms != DNAC_P2M_OK) return DNAC_FRI_ERR_INPUT_ERROR;
        }

        /* Per-matrix reduced-opening accumulation (verifier.rs:599-642). */
        for (size_t m = 0; m < cw->num_matrices; ++m) {
            const dnac_fri_matrix_openings_t *mo = &cw->matrices[m];
            /* ZERO-POINT MATRIX REJECTED — upstream's
             * FriError::MatrixWithoutOpeningPoints, whose reason is that "a
             * matrix opened at no points carries no claim to pin its width"
             * (v0.6.2 fri/src/verifier.rs:702-707). The PROVER already rejected
             * this (stark_prover.c:1055-1057); the verifier did not until S2'-d.
             *
             * ⚠ THIS IS NOW A REDUNDANT BACKSTOP, NOT THE LIVE GUARD (S2'-f).
             * The width pin added to the leaf-assembly loop above runs the same
             * `num_points == 0` test over the same cw->matrices[m], for every m,
             * before any hashing — and cw->num_matrices == 0 is rejected earlier
             * still. So this branch is unreachable for every input, and the
             * ERRCHK("MatrixWithoutOpeningPoints") in test_fri_verifier_valid.c
             * now trips up there, not here.
             * KEPT DELIBERATELY rather than deleted: it is a fail-close guard,
             * and its reachability depends on the two loops staying coupled in
             * their current order. Dropping it would make a future reordering
             * silently reopen the hole. Documented as redundant so nobody reads
             * it as the enforcing check. */
            if (mo->num_points == 0) {
                return DNAC_FRI_ERR_MATRIX_WITHOUT_OPENING_POINTS;
            }
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
                /* PointEvaluationCountMismatch (v0.6.2 verifier.rs:748-757;
                 * the ":625-633" this used to cite is 82cfad73 numbering).
                 * Point 0 can no longer reach this — the width pin above
                 * compares exactly this quantity first — but points 1..N-1
                 * still can, which is precisely upstream's reachability. */
                if (bo->opened_values_lens[m] != pt->num_claimed_evals) {
                    return DNAC_FRI_ERR_POINT_EVALUATION_COUNT_MISMATCH;
                }
                /* ⚠ FAIL-OPEN CLOSED (S2'-d, 2026-07-27). z == x makes the
                 * quotient denominator zero. Upstream rejects it explicitly —
                 * "batch_multiplicative_inverse panics on a zero input, so
                 * reject a coinciding opening point (`z == x`, making the
                 * quotient undefined) here" (v0.6.2 fri/src/verifier.rs:642-662,
                 * FriError::OpeningPointMatchesQueryPoint). DNAC did not panic;
                 * it failed OPEN. gold_fp_inv(0) returns 0 by its own documented
                 * contract ("inv(0) is undefined — caller MUST check (returns 0
                 * silently here)", field_goldilocks.c:170-181), so gold_fp2_inv
                 * yields (0,0), every `term` below becomes 0, and this matrix's
                 * claimed evaluations at this point contribute NOTHING to the
                 * reduced opening — untested — while alpha_pow still advances.
                 * A dropped claim, not a corrupted one.
                 * Unreachable in the shielded instance today (z is the
                 * transcript-sampled zeta and x is fixed by the query index, so
                 * a collision is a ~2^-64 accident, not a choice), but
                 * dnac_fri_verify is a PUBLIC entry and P2 recursion supplies
                 * its own opening points. */
                const gold_fp2_t denom = gold_fp2_sub(pt->point, x_ext);
                if (gold_fp2_eq(denom, gold_fp2_zero())) {
                    return DNAC_FRI_ERR_OPENING_POINT_MATCHES_QUERY_POINT;
                }
                gold_fp2_t quotient = gold_fp2_inv(denom); /* (z - x)^-1 */
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
    const dnac_p2_digest_t       *commit_phase_commits,
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
         * hiding_mmcs.rs:169-170): leaf LANES = [c0,c1]×arity ‖ salts (P1c). */
        const size_t cse = step->salt_elems;
        if (arity * 2 + cse > FRI_LEAF_CAP) return DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR;
        uint64_t leaf[FRI_LEAF_CAP];
        fri_lanes_fp2_row(evals, arity, leaf);
        if (cse > 0) {
            if (step->salts == NULL) return DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR;
            /* Salt canonicality is the gold_fp_t type invariant (see the input-open
             * salt block above); wire lanes are rd_base `>= p`-rejected at decode;
             * the Poseidon2 MMCS re-checks fail-close (G-DET-P1-5). */
            for (size_t s = 0; s < cse; ++s) {
                leaf[arity * 2 + s] = gold_fp_to_u64(step->salts[s]);
            }
        }
        {
            const uint64_t *leaf_rows[1] = { leaf };
            const size_t    leaf_lens[1] = { arity * 2 + cse };
            /* Path handed over whole, same rule as the input MMCS above: the
             * commit-phase siblings array is likewise allocated to the
             * wire-declared depth (fri_proof_codec.c:410-419) while the walk
             * used to be bounded by the derived log_folded_height. */
            if (dnac_p2_mmcs_verify(&commit_phase_commits[round], leaf_rows,
                                    leaf_lens, 1,
                                    (size_t)1u << log_folded_height, idx,
                                    &step->opening_proof) != DNAC_P2M_OK) {
                return DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR;
            }
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
    /* Null/invalid C input is a caller precondition. P1e-E (S8-MED1): ALWAYS-ON
     * fail-close (survives -DNDEBUG) instead of a debug-only assert. */
    if (params == NULL || proof == NULL || transcript == NULL)
        return DNAC_FRI_ERR_INPUT_ERROR;

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
     * wire params, NOT a chosen security level. Both carried upstream's own
     * names as of S2'-d (2026-07-27); the second also TIGHTENED its bound:
     *
     *  - num_queries == 0 → the query loop below (and the low-degree test)
     *    never runs → the verifier accepts any polynomial. Upstream rejects
     *    this first thing, before any transcript work (v0.6.2
     *    fri/src/verifier.rs:183-188, FriError::ZeroQueries); DNAC's check
     *    already sat before the alpha sample below, so only the name moved.
     *
     *  - lgmh > GOLDILOCKS_TWO_ADICITY (32) → upstream's bound
     *    (v0.6.2 verifier.rs:258-268, FriError::GlobalMaxHeightTooLarge:
     *    "the query phase evaluates the final polynomial at a
     *    2^log_global_max_height-th root of unity, which does not exist past
     *    the two-adicity and would panic"). DNAC previously bounded at >= 64,
     *    which only closed the shift-count UB (sample_bits does 1u64<<bits;
     *    domain_index >>= sum_la) — a chain-split class, but it left 33..63
     *    accepted, and THERE gold_fp_two_adic_generator returns gold_fp_one()
     *    (field_goldilocks.c:206-209 — it does not panic, it degrades).
     *    The point that degenerates is the FRI TERMINAL one: fri_terminal_
     *    horner_eval takes x = two_adic_generator(lgmh)^rev with NO generator
     *    coset factor (:126-133), so past 32 it is 1 for EVERY query and the
     *    final polynomial is only ever tested at a single fixed point — the
     *    low-degree test stops testing anything. (The per-matrix x at :382-384
     *    does carry the GENERATOR factor and uses its own log_height, so it is
     *    not the one that collapses; the terminal point is.) 32 closes both
     *    failures: strictly stronger than the old bound, and equal to upstream.
     *    Honest shielded lgmh is 13 — sum_la + log_blowup + log_final_poly_len
     *    with log_blowup 2 and log_final_poly_len 0 (shielded_fri_params.h),
     *    matching the prover's log_gmh = ext_db + lb = 11 + 2
     *    (batch_prover.c). No configuration this prover can produce reaches 33
     *    at all: it rejects degree_bits >= 30 outright (batch_prover.c). */
    if (params->num_queries == 0) {
        return DNAC_FRI_ERR_ZERO_QUERIES;
    }
    if (lgmh > GOLDILOCKS_TWO_ADICITY) {
        return DNAC_FRI_ERR_GLOBAL_MAX_HEIGHT_TOO_LARGE;
    }

    /* T1 — alpha (verifier.rs:143). */
    gold_fp2_t alpha = dnac_transcript_sample_fp2(transcript);

    /* Commit-phase loop (verifier.rs:213-227): observe, check PoW, sample beta. */
    gold_fp2_t betas[FRI_MAX_ROUNDS];
    size_t num_betas = proof->num_commit_phase_commits;
    if (num_betas > FRI_MAX_ROUNDS) return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    for (size_t round = 0; round < num_betas; ++round) {
        /* P1c: 4-lane digest observed as field elements (MerkleCap observe). */
        dnac_transcript_observe_digest(transcript, &proof->commit_phase_commits[round]);
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
        dnac_transcript_observe_digest(t, &proof->commit_phase_commits[round]);
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

dnac_p2_mmcs_status_t dnac_fri_test_mmcs_verify_single(
    const dnac_p2_digest_t *root,
    const uint64_t         *leaf_lanes,
    size_t                  leaf_lane_len,
    uint64_t                leaf_index,
    uint32_t                depth,
    const dnac_p2_digest_t *siblings)
{
    assert(root != NULL);
    assert(leaf_lanes != NULL);
    assert(depth == 0 || siblings != NULL);
    const uint64_t *rows[1] = { leaf_lanes };
    const size_t    lens[1] = { leaf_lane_len };
    /* `depth` here IS the caller's array length (the vector's `nsib`), so the
     * path object is well-formed by construction. leaf_index/num_matrices are
     * not read by the verify — see poseidon2_mmcs.h. */
    const dnac_p2_proof_t pr = {
        .leaf_index   = leaf_index,
        .depth        = depth,
        .num_matrices = 1,
        .siblings     = (dnac_p2_digest_t *)siblings,
    };
    return dnac_p2_mmcs_verify(root, rows, lens, 1,
                               (size_t)1u << depth, leaf_index, &pr);
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
