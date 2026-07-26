/**
 * @file stark_prover.c
 * @brief C STARK prover — stage S1: RangeProofAir witness-trace builder.
 *
 * Port of oracle `generate_range_proof_trace` (tools/plonky3_oracle/src/
 * main.rs::generate_range_proof_trace — the trace handed unmodified to p3_uni_stark::prove).
 * See stark_prover.h for the layout contract and scope boundary.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stark_prover.h"

#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "fri_fold.h"
#include "ntt_goldilocks.h"
#include "transcript.h"
#include "zk_field_helpers.h"

dnac_prover_status_t dnac_prover_build_range_proof_trace(
    const uint64_t *amounts,
    size_t n_real,
    size_t height,
    uint64_t *out_trace,
    uint64_t *out_total) {
    const size_t w = STARK_PROVER_RANGE_PROOF_WIDTH;

    if (amounts == NULL || out_trace == NULL) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* Power of two (prover.rs::prove log2_strict_usize) + wrap-safety bound
     * (main.rs:10211-10212). */
    if (height == 0 || (height & (height - 1)) != 0 ||
        height > STARK_PROVER_MAX_HEIGHT) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* n_real == 0 fails closed (matches the sum_balance n==0 fail-close rule);
     * n_real > height would drop rows silently. */
    if (n_real == 0 || n_real > height) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* Every amount must fit RANGE_AIR_BITS (generate_range_proof_trace amount
     * < 2^RANGE_AIR_BITS assert). Reject
     * BEFORE writing anything — never canonicalize an out-of-range amount. */
    for (size_t i = 0; i < n_real; i++) {
        if (amounts[i] >= (UINT64_C(1) << RANGE_AIR_BITS)) {
            return DNAC_PROVER_ERR_RANGE;
        }
    }

    /* Goldilocks::zero_vec (field.rs:386): padding-row bits/amount/is_real
     * stay zero from here. */
    memset(out_trace, 0, height * w * sizeof(uint64_t));

    /* Real rows, cols 0..SUM_BALANCE_ACC_OFF: bits + amount (range_air) and
     * the running acc (sum_balance) — byte-identical to the oracle loop
     * (main.rs:10220-10225) for in-range amounts. */
    sum_balance_build_trace(amounts, n_real, out_trace, w);

    /* Real rows: is_real = 1, cnt = row + 1 (main.rs:10226-10228; count only
     * advances on real rows). */
    for (size_t r = 0; r < n_real; r++) {
        uint64_t *cells = &out_trace[r * w];
        cells[STARK_PROVER_IS_REAL_OFF] = 1;
        cells[STARK_PROVER_CNT_OFF] = (uint64_t)(r + 1);
    }

    /* Padding rows: acc and cnt stay FLAT at the last real row's values
     * (main.rs:10224-10228 with amt=0, real=0); is_real/bits/amount remain 0
     * from the memset. total < n_real * 2^RANGE_AIR_BITS <= 2^62 < p, so the
     * canonical field value IS the integer sum (sum_balance.h bound). */
    const uint64_t total = out_trace[(n_real - 1) * w + SUM_BALANCE_ACC_OFF];
    for (size_t r = n_real; r < height; r++) {
        uint64_t *cells = &out_trace[r * w];
        cells[SUM_BALANCE_ACC_OFF] = total;
        cells[STARK_PROVER_CNT_OFF] = (uint64_t)n_real;
    }

    if (out_total != NULL) {
        *out_total = total;
    }
    return DNAC_PROVER_OK;
}

/* ============================================================================
 * S2 — is_zk trace randomization (hiding_pcs.rs:110-129 + dense.rs:573-597)
 * ========================================================================== */

dnac_prover_status_t dnac_prover_randomize_trace(
    const uint64_t *base,
    size_t height,
    size_t width,
    size_t num_random,
    const uint64_t *rand_vals,
    uint64_t *out) {
    if (base == NULL || rand_vals == NULL || out == NULL ||
        height == 0 || width == 0 || num_random == 0) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* size_t-overflow guard (red-team S2 LOW): a hostile height*width would
     * wrap the draw-validation bound + mis-address writes. Bound by the
     * pipeline's real ceilings (MAX_HEIGHT rows; width ≤ the AIR-agnostic
     * DNAC_PROVER_MAX_TRACE_WIDTH = 640, raised 2026-07-15 for the width-614
     * combined conf AIR); reject anything that could overflow the
     * per_row / height*per_row products. */
    /* num_random is bounded INDEPENDENTLY of width (d3): Plonky3's
     * with_random_cols has no num_random <= width constraint (dense.rs:
     * 573-597 just appends columns) — the batched fib trace is width 2 with
     * 4 random codewords. The pre-d3 `num_random > width` reject was a v3
     * artifact (every v3 caller had width >= 56); the overflow bound only
     * needs both factors capped. */
    if (width > DNAC_PROVER_MAX_TRACE_WIDTH ||
        num_random > DNAC_PROVER_MAX_TRACE_WIDTH ||
        height > STARK_PROVER_MAX_HEIGHT) {
        return DNAC_PROVER_ERR_PARAM;
    }

    const size_t per_row = width + 2 * num_random; /* draws per base row */
    const size_t out_w = width + num_random;

    /* Plonky3's draws are rejection-sampled canonical (goldilocks.rs:184-193);
     * a non-canonical supplied value can only be a caller bug — fail closed. */
    for (size_t i = 0; i < height * per_row; i++) {
        if (rand_vals[i] >= GOLDILOCKS_P) {
            return DNAC_PROVER_ERR_NONCANONICAL;
        }
    }

    /* with_random_cols(width + 2*num_random) + width := width + num_random
     * reshape (hiding_pcs.rs:117-123): per base row i, the widened row
     * [base_row_i | per_row draws] splits into out rows 2i and 2i+1. */
    for (size_t i = 0; i < height; i++) {
        const uint64_t *d = &rand_vals[i * per_row];
        uint64_t *even = &out[(2 * i) * out_w];
        uint64_t *odd = &out[(2 * i + 1) * out_w];
        memcpy(even, &base[i * width], width * sizeof(uint64_t));
        memcpy(even + width, d, num_random * sizeof(uint64_t));
        memcpy(odd, d + num_random, out_w * sizeof(uint64_t));
    }
    return DNAC_PROVER_OK;
}

/* ============================================================================
 * S2 — per-column coset LDE + bit-reversed rows (two_adic_pcs.rs:301-325)
 * ========================================================================== */

dnac_prover_status_t dnac_prover_coset_lde_bitrev(
    const uint64_t *mat,
    size_t height,
    size_t width,
    unsigned log_blowup,
    uint64_t shift,
    uint64_t *out) {
    if (mat == NULL || out == NULL || width == 0 || log_blowup == 0 ||
        height < 2 || (height & (height - 1)) != 0 || shift >= GOLDILOCKS_P) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const unsigned log_h = (unsigned)log2_strict_usize(height);
    const unsigned log_lde = log_h + log_blowup;
    /* Reject log_lde >= 32: ntt_goldilocks uses `1u << log_n` (32-bit), which
     * is UB at a 32-bit shift width (red-team S2). Unreachable in-pipeline
     * (MAX_HEIGHT=1024 ⇒ log_lde <= 13) but the standalone contract must
     * fail-close, not compute garbage. */
    if (log_lde >= GOLDILOCKS_TWO_ADICITY) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t lde_h = height << log_blowup;

    /* shift^j scaling table for the coefficient vector (traits.rs:83-91;
     * gold_fp_shifted_powers is the oracle-gated Powers{} port). */
    gold_fp_t *pow = (gold_fp_t *)malloc(lde_h * sizeof(gold_fp_t));
    gold_fp_t *col = (gold_fp_t *)malloc(lde_h * sizeof(gold_fp_t));
    if (pow == NULL || col == NULL) {
        free(pow);
        free(col);
        return DNAC_PROVER_ERR_PARAM;
    }
    gold_fp_shifted_powers(gold_fp_from_u64(1), gold_fp_from_u64(shift), pow,
                           lde_h);

    for (size_t c = 0; c < width; c++) {
        /* gather column c (evaluations over the size-`height` subgroup) */
        for (size_t r = 0; r < height; r++) {
            col[r] = gold_fp_from_u64(mat[r * width + c]);
        }
        /* iNTT -> natural-order coefficients (traits.rs idft equivalent;
         * ntt_goldilocks_inverse is the exact inverse of the Radix2Dit-gated
         * forward NTT, incl. the 1/N factor) */
        ntt_goldilocks_inverse(col, log_h);
        /* zero-pad coefficients to lde_h (traits.rs:254-261) */
        for (size_t j = height; j < lde_h; j++) {
            col[j] = gold_fp_from_u64(0);
        }
        /* coset shift on coefficients BEFORE the forward DFT (traits.rs:89-90) */
        for (size_t j = 0; j < height; j++) {
            col[j] = gold_fp_mul(col[j], pow[j]);
        }
        /* forward NTT over the size-lde_h subgroup -> natural-order evals */
        ntt_goldilocks_forward(col, log_lde);
        /* scatter into the output column */
        for (size_t r = 0; r < lde_h; r++) {
            out[r * width + c] = gold_fp_to_u64(col[r]);
        }
    }
    free(pow);
    free(col);

    /* Bit-reverse the ROW order (two_adic_pcs.rs:318 bit_reverse_rows,
     * matrix/src/util.rs:36-57): swap whole width-wide rows i <-> rev(i). */
    for (size_t i = 0; i < lde_h; i++) {
        const size_t j = (size_t)reverse_bits_len_u64((uint64_t)i, log_lde);
        if (j > i) {
            uint64_t *ri = &out[i * width];
            uint64_t *rj = &out[j * width];
            for (size_t c = 0; c < width; c++) {
                const uint64_t tmp = ri[c];
                ri[c] = rj[c];
                rj[c] = tmp;
            }
        }
    }
    return DNAC_PROVER_OK;
}

/* ============================================================================
 * S3 — matrix commit (Merkle BUILD; merkle_tree.rs:302-322 leaf serialization)
 * ========================================================================== */

dnac_prover_status_t dnac_prover_commit_matrix(
    const uint64_t *mat,
    size_t height,
    size_t width,
    const uint64_t *salts,
    size_t salt_elems,
    dnac_p2_digest_t *out_root,
    dnac_p2_mmcs_tree_t **out_tree) {
    if (mat == NULL || out_root == NULL || out_tree == NULL || width == 0 ||
        height < 2 || (height & (height - 1)) != 0) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* M3b: salt_elems=0 -> unsalted (plain leaf); >0 -> salted leaf =
     * row ‖ salt_elems salts (hiding_mmcs.rs:167-170). salts is a flat
     * height*salt_elems array; row i's salts are salts[i*salt_elems ..]. */
    if (salt_elems > 0 && salts == NULL) return DNAC_PROVER_ERR_PARAM;

    /* P1c: the Poseidon2 MMCS consumes canonical LANES directly — no byte
     * serialization. Leaf = row lanes ‖ salt lanes (same order as the old
     * byte layout, /8 offsets). Non-canonical lanes are fail-close rejected
     * by dnac_p2_mmcs_commit itself (G-DET-P1-5); the pre-checks here keep
     * the prover's own NONCANONICAL status for its callers. */
    const size_t cols = width + salt_elems;
    uint64_t *buf;
    const uint64_t *mats1[1];
    size_t w1[1];
    dnac_p2_mmcs_status_t st;

    if (salt_elems == 0) {
        for (size_t i = 0; i < height * width; i++) {
            if (mat[i] >= GOLDILOCKS_P) return DNAC_PROVER_ERR_NONCANONICAL;
        }
        mats1[0] = mat;
        w1[0] = width;
        st = dnac_p2_mmcs_commit(mats1, w1, 1, height, out_root, out_tree);
        if (st != DNAC_P2M_OK) return DNAC_PROVER_ERR_PARAM;
        return DNAC_PROVER_OK;
    }

    buf = (uint64_t *)malloc(height * cols * sizeof(uint64_t));
    if (buf == NULL) {
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t i = 0; i < height; i++) {
        for (size_t c = 0; c < width; c++) {
            const uint64_t v = mat[i * width + c];
            if (v >= GOLDILOCKS_P) { free(buf); return DNAC_PROVER_ERR_NONCANONICAL; }
            buf[i * cols + c] = v;
        }
        for (size_t s = 0; s < salt_elems; s++) {
            const uint64_t v = salts[i * salt_elems + s];
            if (v >= GOLDILOCKS_P) { free(buf); return DNAC_PROVER_ERR_NONCANONICAL; }
            buf[i * cols + width + s] = v;
        }
    }

    mats1[0] = buf;
    w1[0] = cols;
    st = dnac_p2_mmcs_commit(mats1, w1, 1, height, out_root, out_tree);
    free(buf);
    if (st != DNAC_P2M_OK) {
        return DNAC_PROVER_ERR_PARAM;
    }
    return DNAC_PROVER_OK;
}

/* ============================================================================
 * S5 — Fiat-Shamir to alpha (prover.rs:161-195 sequence, prover side)
 * ========================================================================== */

dnac_prover_status_t dnac_prover_fs_to_alpha(
    dnac_transcript_t *t,
    uint64_t log_ext_degree,
    uint64_t log_degree,
    uint64_t preprocessed_width,
    const dnac_p2_digest_t *trace_root,
    const uint64_t *publics,
    size_t n_publics,
    gold_fp2_t *out_alpha) {
    if (t == NULL || trace_root == NULL || out_alpha == NULL ||
        (n_publics > 0 && publics == NULL)) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* preprocessed_width>0 cannot be honored here (no preprocessed-commit
     * observe, prover.rs:168-170) — fail-close rather than emit a transcript
     * that diverges from p3 + the C verifier (red-team S5/X2). RangeProofAir
     * has none; a preprocessed AIR needs a commit parameter added first. */
    if (preprocessed_width != 0) {
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t i = 0; i < n_publics; i++) {
        if (publics[i] >= GOLDILOCKS_P) {
            return DNAC_PROVER_ERR_NONCANONICAL;
        }
    }

    /* prover.rs:161-163 — instance scalars as Goldilocks elements. */
    dnac_transcript_observe_fp(t, gold_fp_from_u64(log_ext_degree));
    dnac_transcript_observe_fp(t, gold_fp_from_u64(log_degree));
    dnac_transcript_observe_fp(t, gold_fp_from_u64(preprocessed_width));
    /* prover.rs:167 — trace commitment (cap_height=0: one 4-lane digest,
     * lane-by-lane field observes — duplex_challenger.rs:186-210, P1c).
     * Preprocessed commit skipped: width 0 (prover.rs:168-170). */
    dnac_transcript_observe_digest(t, trace_root);
    /* prover.rs:173 — public values, element-wise, AIR order. */
    for (size_t i = 0; i < n_publics; i++) {
        dnac_transcript_observe_fp(t, gold_fp_from_u64(publics[i]));
    }
    /* prover.rs:195 — sample alpha in Goldilocks^2 (c0 then c1). */
    *out_alpha = dnac_transcript_sample_fp2(t);
    return DNAC_PROVER_OK;
}

/* ============================================================================
 * S6 — quotient computation (prover.rs:200-235 / :399-513, domain.rs:277-317)
 * ========================================================================== */

dnac_prover_status_t dnac_prover_quotient_selectors(
    unsigned log_n,
    unsigned log_coset,
    uint64_t shift,
    uint64_t *is_first_row,
    uint64_t *is_last_row,
    uint64_t *is_transition,
    uint64_t *inv_vanishing) {
    /* Reference bounds (domain.rs:278-281): trace domain shift ONE, coset
     * shift != ONE, coset size >= trace size — EQUAL sizes are legal
     * (rate_bits = 0, the num_qc=1 batched case; the pre-d3 `log_coset <=
     * log_n` guard was stricter than the source). shift==1 stays rejected
     * (assert_ne!(coset.shift, ONE)). */
    if (is_first_row == NULL || is_last_row == NULL || is_transition == NULL ||
        inv_vanishing == NULL || log_coset < log_n ||
        log_coset > GOLDILOCKS_TWO_ADICITY || shift <= 1 ||
        shift >= GOLDILOCKS_P) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t n = (size_t)1 << log_n;
    const size_t cs = (size_t)1 << log_coset;
    const unsigned rate_bits = log_coset - log_n;
    const size_t rate = (size_t)1 << rate_bits;

    gold_fp_t *zh = (gold_fp_t *)malloc(rate * sizeof(gold_fp_t));
    gold_fp_t *zh_inv = (gold_fp_t *)malloc(rate * sizeof(gold_fp_t));
    gold_fp_t *xs = (gold_fp_t *)malloc(cs * sizeof(gold_fp_t));
    gold_fp_t *den = (gold_fp_t *)malloc(cs * sizeof(gold_fp_t));
    gold_fp_t *den_inv = (gold_fp_t *)malloc(cs * sizeof(gold_fp_t));
    if (!zh || !zh_inv || !xs || !den || !den_inv) {
        free(zh); free(zh_inv); free(xs); free(den); free(den_inv);
        return DNAC_PROVER_ERR_PARAM;
    }

    const gold_fp_t s = gold_fp_from_u64(shift);
    const gold_fp_t one = gold_fp_from_u64(1);
    /* zh[k] = shift^n * g_rate^k − 1  (domain.rs:283-289). */
    const gold_fp_t s_pow_n = gold_fp_pow(s, (uint64_t)n);
    const gold_fp_t g_rate = gold_fp_two_adic_generator(rate_bits);
    gold_fp_t acc = s_pow_n;
    for (size_t k = 0; k < rate; k++) {
        zh[k] = gold_fp_sub(acc, one);
        acc = gold_fp_mul(acc, g_rate);
    }
    /* x[i] = shift * g_coset^i, natural order (domain.rs:291). */
    gold_fp_shifted_powers(s, gold_fp_two_adic_generator(log_coset), xs, cs);

    const gold_fp_t g_n = gold_fp_two_adic_generator(log_n);
    const gold_fp_t g_n_last = gold_fp_inv(g_n); /* gN^{n−1} = gN^{-1} */

    /* is_first_row: zh[i%rate] / (x[i] − 1)  (single_point_selector(0)). */
    for (size_t i = 0; i < cs; i++) den[i] = gold_fp_sub(xs[i], one);
    gold_fp_batch_inv_general(den, den_inv, cs);
    for (size_t i = 0; i < cs; i++) {
        is_first_row[i] = gold_fp_to_u64(gold_fp_mul(zh[i & (rate - 1)], den_inv[i]));
    }
    /* is_last_row: zh[i%rate] / (x[i] − gN^{-1}). */
    for (size_t i = 0; i < cs; i++) den[i] = gold_fp_sub(xs[i], g_n_last);
    gold_fp_batch_inv_general(den, den_inv, cs);
    for (size_t i = 0; i < cs; i++) {
        is_last_row[i] = gold_fp_to_u64(gold_fp_mul(zh[i & (rate - 1)], den_inv[i]));
        /* is_transition: x[i] − gN^{-1} (domain.rs:310) — same denominator. */
        is_transition[i] = gold_fp_to_u64(den[i]);
    }
    /* inv_vanishing: 1/zh[i%rate], cycled (domain.rs:311-315). */
    gold_fp_batch_inv_general(zh, zh_inv, rate);
    for (size_t i = 0; i < cs; i++) {
        inv_vanishing[i] = gold_fp_to_u64(zh_inv[i & (rate - 1)]);
    }

    free(zh); free(zh_inv); free(xs); free(den); free(den_inv);
    return DNAC_PROVER_OK;
}

dnac_prover_status_t dnac_prover_trace_on_quotient_domain(
    const uint64_t *lde_bitrev,
    size_t lde_height,
    size_t lde_width,
    size_t q_rows,
    size_t out_width,
    uint64_t *out) {
    if (lde_bitrev == NULL || out == NULL || q_rows == 0 ||
        lde_height < q_rows || (lde_height % q_rows) != 0 ||
        (lde_height & (lde_height - 1)) != 0 ||
        (q_rows & (q_rows - 1)) != 0 || out_width == 0 ||
        out_width > lde_width) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const unsigned log_lde = (unsigned)log2_strict_usize(lde_height);
    const size_t stride = lde_height / q_rows;
    /* natural row j*stride lives at stored index reverse_bits(j*stride)
     * (two_adic_pcs.rs:373-374: first q_rows bit-reversed rows,
     * un-bit-reversed == natural rows 0, stride, 2*stride, ...). */
    for (size_t j = 0; j < q_rows; j++) {
        const size_t src =
            (size_t)reverse_bits_len_u64((uint64_t)(j * stride), log_lde);
        memcpy(&out[j * out_width], &lde_bitrev[src * lde_width],
               out_width * sizeof(uint64_t));
    }
    return DNAC_PROVER_OK;
}

dnac_prover_status_t dnac_prover_quotient_values_range_zk(
    const uint64_t *trace_q,
    size_t q_rows,
    size_t next_step,
    const uint64_t publics[3],
    gold_fp2_t alpha,
    const uint64_t *is_first_row,
    const uint64_t *is_last_row,
    const uint64_t *is_transition,
    const uint64_t *inv_vanishing,
    uint64_t *out_q) {
    if (trace_q == NULL || publics == NULL || is_first_row == NULL ||
        is_last_row == NULL || is_transition == NULL ||
        inv_vanishing == NULL || out_q == NULL || q_rows == 0 ||
        next_step == 0 || next_step >= q_rows) {
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t i = 0; i < 3; i++) {
        if (publics[i] >= GOLDILOCKS_P) {
            return DNAC_PROVER_ERR_NONCANONICAL;
        }
    }
    const size_t w = STARK_PROVER_RANGE_PROOF_WIDTH; /* 56 */
    const gold_fp_t one = gold_fp_from_u64(1);
    const gold_fp_t claimed = gold_fp_from_u64(publics[0]);
    const gold_fp_t fee = gold_fp_from_u64(publics[1]);
    const gold_fp_t n_real = gold_fp_from_u64(publics[2]);
    const gold_fp_t claimed_minus_fee = gold_fp_sub(claimed, fee);

    for (size_t i = 0; i < q_rows; i++) {
        const uint64_t *lrow = &trace_q[i * w];
        const uint64_t *nrow = &trace_q[((i + next_step) % q_rows) * w];
        const gold_fp_t sel_first = gold_fp_from_u64(is_first_row[i]);
        const gold_fp_t sel_last = gold_fp_from_u64(is_last_row[i]);
        const gold_fp_t sel_trans = gold_fp_from_u64(is_transition[i]);

        const gold_fp_t amount = gold_fp_from_u64(lrow[RANGE_AIR_AMOUNT_OFF]);
        const gold_fp_t acc_c = gold_fp_from_u64(lrow[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t is_real = gold_fp_from_u64(lrow[STARK_PROVER_IS_REAL_OFF]);
        const gold_fp_t cnt = gold_fp_from_u64(lrow[STARK_PROVER_CNT_OFF]);
        const gold_fp_t amount_n = gold_fp_from_u64(nrow[RANGE_AIR_AMOUNT_OFF]);
        const gold_fp_t acc_n = gold_fp_from_u64(nrow[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t is_real_n = gold_fp_from_u64(nrow[STARK_PROVER_IS_REAL_OFF]);
        const gold_fp_t cnt_n = gold_fp_from_u64(nrow[STARK_PROVER_CNT_OFF]);

        /* Horner fold with descending alpha powers: acc = acc*alpha + C_j
         * (folder.rs:216 == builder.rs:420-423 reversed powers). Constraint
         * order pinned by oracle main.rs:10148-10192 (same formulas as the
         * GREEN verifier-side range_proof_air_eval, base field here). */
        gold_fp2_t facc = gold_fp2_from_base(gold_fp_from_u64(0));
        gold_fp_t bit_sum = gold_fp_from_u64(0);
        gold_fp_t weight = one;
        for (size_t j = 0; j < RANGE_AIR_BITS; j++) {
            const gold_fp_t b = gold_fp_from_u64(lrow[j]);
            /* B_j: b*(b−1), unfiltered */
            const gold_fp_t cj = gold_fp_mul(b, gold_fp_sub(b, one));
            facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
            bit_sum = gold_fp_add(bit_sum, gold_fp_mul(b, weight));
            weight = gold_fp_add(weight, weight);
        }
        /* S: Σ b·2^j − amount */
        gold_fp_t cj = gold_fp_sub(bit_sum, amount);
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
        /* R: is_real·(is_real−1) */
        cj = gold_fp_mul(is_real, gold_fp_sub(is_real, one));
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
        /* P: (1−is_real)·amount */
        cj = gold_fp_mul(gold_fp_sub(one, is_real), amount);
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
        /* I (first row): acc − amount */
        cj = gold_fp_mul(sel_first, gold_fp_sub(acc_c, amount));
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
        /* U (transition): acc' − acc − amount' */
        cj = gold_fp_mul(sel_trans,
                         gold_fp_sub(gold_fp_sub(acc_n, acc_c), amount_n));
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
        /* F (last row): acc − (claimed − fee) */
        cj = gold_fp_mul(sel_last, gold_fp_sub(acc_c, claimed_minus_fee));
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
        /* CI (first row): cnt − is_real */
        cj = gold_fp_mul(sel_first, gold_fp_sub(cnt, is_real));
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
        /* CU (transition): cnt' − cnt − is_real' */
        cj = gold_fp_mul(sel_trans,
                         gold_fp_sub(gold_fp_sub(cnt_n, cnt), is_real_n));
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));
        /* CF (last row): cnt − n_real */
        cj = gold_fp_mul(sel_last, gold_fp_sub(cnt, n_real));
        facc = gold_fp2_add(gold_fp2_mul(facc, alpha), gold_fp2_from_base(cj));

        /* out[i] = folded · inv_vanishing[i] (prover.rs:508). */
        const gold_fp_t ivan = gold_fp_from_u64(inv_vanishing[i]);
        out_q[2 * i] = gold_fp_to_u64(gold_fp_mul(facc.a, ivan));
        out_q[2 * i + 1] = gold_fp_to_u64(gold_fp_mul(facc.b, ivan));
    }
    return DNAC_PROVER_OK;
}

dnac_prover_status_t dnac_prover_quotient_split(
    const uint64_t *flat,
    size_t rows,
    size_t num_chunks,
    uint64_t *out_chunks) {
    if (flat == NULL || out_chunks == NULL || num_chunks == 0 ||
        rows == 0 || (rows % num_chunks) != 0) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t rows_per_chunk = rows / num_chunks;
    /* split_evals round-robin (domain.rs:230-238): chunk c row i = global
     * row i*num_chunks + c; each row is the 2-column fp2 flatten. */
    for (size_t c = 0; c < num_chunks; c++) {
        uint64_t *dst = &out_chunks[c * rows_per_chunk * 2];
        for (size_t i = 0; i < rows_per_chunk; i++) {
            const size_t r = i * num_chunks + c;
            dst[2 * i] = flat[2 * r];
            dst[2 * i + 1] = flat[2 * r + 1];
        }
    }
    return DNAC_PROVER_OK;
}

/* ============================================================================
 * S7 — quotient blinding + chunk LDEs + ONE multi-matrix commit
 * (hiding_pcs.rs:169-261 + two_adic_pcs.rs commit_ldes)
 * ========================================================================== */

/* Natural-order coset LDE of one h x w matrix (iNTT -> shift^j scale ->
 * zero-pad -> forward NTT), NO bit-reversal — the S7 blinding is added on the
 * natural-order evaluations before the final bit-reverse
 * (hiding_pcs.rs:216-252). */
static dnac_prover_status_t coset_lde_natural(
    const uint64_t *mat, size_t height, size_t width, unsigned added_bits,
    gold_fp_t lde_shift, uint64_t *out) {
    const unsigned log_h = (unsigned)log2_strict_usize(height);
    const unsigned log_lde = log_h + added_bits;
    const size_t lde_h = height << added_bits;
    gold_fp_t *pow = (gold_fp_t *)malloc(lde_h * sizeof(gold_fp_t));
    gold_fp_t *col = (gold_fp_t *)malloc(lde_h * sizeof(gold_fp_t));
    if (pow == NULL || col == NULL) {
        free(pow);
        free(col);
        return DNAC_PROVER_ERR_PARAM;
    }
    gold_fp_shifted_powers(gold_fp_from_u64(1), lde_shift, pow, height);
    for (size_t c = 0; c < width; c++) {
        for (size_t r = 0; r < height; r++) {
            col[r] = gold_fp_from_u64(mat[r * width + c]);
        }
        ntt_goldilocks_inverse(col, log_h);
        for (size_t j = 0; j < height; j++) {
            col[j] = gold_fp_mul(col[j], pow[j]);
        }
        for (size_t j = height; j < lde_h; j++) {
            col[j] = gold_fp_from_u64(0);
        }
        ntt_goldilocks_forward(col, log_lde);
        for (size_t r = 0; r < lde_h; r++) {
            out[r * width + c] = gold_fp_to_u64(col[r]);
        }
    }
    free(pow);
    free(col);
    return DNAC_PROVER_OK;
}

dnac_prover_status_t dnac_prover_quotient_commit(
    const uint64_t *quotient_flat,
    size_t q_rows,
    size_t num_chunks,
    size_t num_random,
    unsigned log_blowup,
    uint64_t q_shift,
    const uint64_t *codeword_rand,
    const uint64_t *blinding_rand,
    const uint64_t *salts,      /* M3b: [num_chunks*lde_h*salt_elems] or NULL */
    size_t          salt_elems,
    uint64_t *out_chunk_ldes,
    dnac_p2_digest_t *out_root,
    dnac_p2_mmcs_tree_t **out_tree) {
    if (quotient_flat == NULL || codeword_rand == NULL ||
        blinding_rand == NULL || out_chunk_ldes == NULL || out_root == NULL ||
        out_tree == NULL || num_chunks < 2 || num_random == 0 ||
        log_blowup == 0 || q_rows == 0 || (q_rows % num_chunks) != 0 ||
        (q_rows & (q_rows - 1)) != 0 || q_shift == 0 ||
        q_shift >= GOLDILOCKS_P) {
        return DNAC_PROVER_ERR_PARAM;
    }
    if (salt_elems > 0 && salts == NULL) return DNAC_PROVER_ERR_PARAM;
    const size_t h = q_rows / num_chunks;         /* rows per chunk (4)   */
    const size_t w = 2 + num_random;              /* chunk width (6)      */
    const unsigned added_bits = log_blowup + 1;   /* hiding_pcs.rs:224    */
    const size_t lde_h = h << added_bits;         /* 32                   */
    if ((h & (h - 1)) != 0 || h < 2) {
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t i = 0; i < num_chunks * h * num_random; i++) {
        if (codeword_rand[i] >= GOLDILOCKS_P) return DNAC_PROVER_ERR_NONCANONICAL;
    }
    for (size_t i = 0; i < (num_chunks - 1) * h * w; i++) {
        if (blinding_rand[i] >= GOLDILOCKS_P) return DNAC_PROVER_ERR_NONCANONICAL;
    }
    /* quotient_flat canonicality (red-team S7 LOW — was the one input not
     * checked; the in-house S6 output is always canonical, but fail-close
     * symmetrically so a foreign non-canonical value can't flow into the
     * field arithmetic). Length = 2*q_rows (fp2 flatten, 2 base cols/row). */
    for (size_t i = 0; i < 2 * q_rows; i++) {
        if (quotient_flat[i] >= GOLDILOCKS_P) return DNAC_PROVER_ERR_NONCANONICAL;
    }

    const unsigned log_q = (unsigned)log2_strict_usize(q_rows);
    const gold_fp_t k = gold_fp_two_adic_generator(log_q);
    const gold_fp_t gen = gold_fp_from_u64(7); /* GENERATOR, goldilocks.rs:400 */
    const gold_fp_t one = gold_fp_from_u64(1);

    dnac_prover_status_t rc = DNAC_PROVER_ERR_PARAM;
    gold_fp_t *shifts = (gold_fp_t *)malloc(num_chunks * sizeof(gold_fp_t));
    gold_fp_t *cis_raw = (gold_fp_t *)malloc(num_chunks * sizeof(gold_fp_t));
    gold_fp_t *cis = (gold_fp_t *)malloc(num_chunks * sizeof(gold_fp_t));
    uint64_t *all_random = (uint64_t *)malloc(num_chunks * h * w * 8);
    uint64_t *widened = (uint64_t *)malloc(h * w * 8);
    uint64_t *lde_nat = (uint64_t *)malloc(lde_h * w * 8);
    gold_fp_t *vcoef = (gold_fp_t *)malloc(lde_h * w * sizeof(gold_fp_t));
    const size_t cw = w + salt_elems;  /* salted chunk row width (lanes) */
    /* P1c: lane matrices (row lanes ‖ salt lanes), no byte serialization. */
    uint64_t *lanes = (uint64_t *)malloc(num_chunks * lde_h * cw * sizeof(uint64_t));
    const uint64_t **mat_ptrs =
        (const uint64_t **)malloc(num_chunks * sizeof(uint64_t *));
    size_t *lane_widths = (size_t *)malloc(num_chunks * sizeof(size_t));
    if (!shifts || !cis_raw || !cis || !all_random || !widened || !lde_nat ||
        !vcoef || !lanes || !mat_ptrs || !lane_widths) {
        goto out;
    }

    /* Split-domain shifts: shift_i = q_shift * k^i (domain.rs:199-211). */
    gold_fp_shifted_powers(gold_fp_from_u64(q_shift), k, shifts, num_chunks);

    /* cis (get_zp_cis, hiding_pcs.rs:451-469): cis_raw[i] =
     * prod_{j!=i} Z_{D_j}(shift_i), Z_D(x) = (x/shift_D)^h − 1; cis =
     * batch inverse. mul_coeffs[j] = cis[j]/cis[last] = cis[j]*cis_raw[last]. */
    for (size_t i = 0; i < num_chunks; i++) {
        gold_fp_t prod = one;
        for (size_t j = 0; j < num_chunks; j++) {
            if (j == i) continue;
            const gold_fp_t ratio = gold_fp_mul(shifts[i], gold_fp_inv(shifts[j]));
            prod = gold_fp_mul(prod, gold_fp_sub(gold_fp_pow(ratio, (uint64_t)h), one));
        }
        cis_raw[i] = prod;
    }
    gold_fp_batch_inv_general(cis_raw, cis, num_chunks);

    /* all_random blocks (hiding_pcs.rs:194-208): blocks 0..last-1 = caller
     * draws; last block derived: -= mul_coeffs[j] * block_j. */
    memcpy(all_random, blinding_rand, (num_chunks - 1) * h * w * 8);
    {
        uint64_t *lastb = &all_random[(num_chunks - 1) * h * w];
        memset(lastb, 0, h * w * 8);
        for (size_t j = 0; j + 1 < num_chunks; j++) {
            const gold_fp_t mc = gold_fp_mul(cis[j], cis_raw[num_chunks - 1]);
            for (size_t kk = 0; kk < h * w; kk++) {
                const gold_fp_t t =
                    gold_fp_mul(gold_fp_from_u64(all_random[j * h * w + kk]), mc);
                lastb[kk] = gold_fp_to_u64(
                    gold_fp_sub(gold_fp_from_u64(lastb[kk]), t));
            }
        }
    }

    for (size_t c = 0; c < num_chunks; c++) {
        /* chunk evals (round-robin) + codeword columns (chunk-major draws,
         * row-major fill: dense.rs:588-593). */
        for (size_t r = 0; r < h; r++) {
            const size_t gr = r * num_chunks + c;
            widened[r * w] = quotient_flat[2 * gr];
            widened[r * w + 1] = quotient_flat[2 * gr + 1];
            for (size_t j = 0; j < num_random; j++) {
                widened[r * w + 2 + j] =
                    codeword_rand[(c * h + r) * num_random + j];
            }
        }
        /* natural-order coset LDE, lde_shift = GENERATOR / shift_c
         * (hiding_pcs.rs:216-227). */
        const gold_fp_t lde_shift = gold_fp_mul(gen, gold_fp_inv(shifts[c]));
        if (coset_lde_natural(widened, h, w, added_bits, lde_shift, lde_nat) !=
            DNAC_PROVER_OK) {
            goto out;
        }
        /* v_H(X)*t_c(X) coefficients (hiding_pcs.rs:229-247): row r gets
         * −7^r·t, row h+r gets p·7^r·t, p = lde_shift^h; rest zero; plain
         * forward DFT per column. */
        const gold_fp_t p = gold_fp_pow(lde_shift, (uint64_t)h);
        for (size_t i = 0; i < lde_h * w; i++) vcoef[i] = gold_fp_from_u64(0);
        {
            const uint64_t *rblk = &all_random[c * h * w];
            gold_fp_t p_i = one; /* GENERATOR^0 */
            for (size_t r = 0; r < h; r++) {
                for (size_t j = 0; j < w; j++) {
                    const gold_fp_t m =
                        gold_fp_mul(p_i, gold_fp_from_u64(rblk[r * w + j]));
                    vcoef[r * w + j] = gold_fp_neg(m);
                    vcoef[(h + r) * w + j] = gold_fp_mul(p, m);
                }
                p_i = gold_fp_mul(p_i, gen);
            }
        }
        /* per-column plain forward NTT of the coefficient matrix, then
         * elementwise add onto the LDE (hiding_pcs.rs:243-252). */
        {
            const unsigned log_lde = (unsigned)log2_strict_usize(lde_h);
            gold_fp_t *col = (gold_fp_t *)malloc(lde_h * sizeof(gold_fp_t));
            if (col == NULL) goto out;
            for (size_t j = 0; j < w; j++) {
                for (size_t r = 0; r < lde_h; r++) col[r] = vcoef[r * w + j];
                ntt_goldilocks_forward(col, log_lde);
                for (size_t r = 0; r < lde_h; r++) {
                    lde_nat[r * w + j] = gold_fp_to_u64(gold_fp_add(
                        gold_fp_from_u64(lde_nat[r * w + j]), col[r]));
                }
            }
            free(col);
        }
        /* bit-reverse rows (hiding_pcs.rs:254) into the output + lane buffer. */
        {
            const unsigned log_lde = (unsigned)log2_strict_usize(lde_h);
            uint64_t *dst = &out_chunk_ldes[c * lde_h * w];
            for (size_t r = 0; r < lde_h; r++) {
                const size_t src =
                    (size_t)reverse_bits_len_u64((uint64_t)r, log_lde);
                memcpy(&dst[r * w], &lde_nat[src * w], w * 8);
            }
            uint64_t *lm = &lanes[c * lde_h * cw];
            for (size_t r = 0; r < lde_h; r++) {
                memcpy(&lm[r * cw], &dst[r * w], w * sizeof(uint64_t));
                for (size_t s = 0; s < salt_elems; s++) {
                    /* stream A quotient section: chunk c, row r salt. */
                    const uint64_t sv = salts[(c * lde_h + r) * salt_elems + s];
                    if (sv >= GOLDILOCKS_P) { rc = DNAC_PROVER_ERR_NONCANONICAL; goto out; }
                    lm[r * cw + w + s] = sv;
                }
            }
            mat_ptrs[c] = lm;
            lane_widths[c] = cw;
        }
    }

    /* ONE multi-matrix commit (equal heights; univariate commit_quotient ->
     * commit_ldes -> mmcs.commit; Poseidon2 batch == MerkleTreeMmcs, P1c). */
    if (dnac_p2_mmcs_commit(mat_ptrs, lane_widths, num_chunks, lde_h,
                            out_root, out_tree) != DNAC_P2M_OK) {
        goto out;
    }
    rc = DNAC_PROVER_OK;

out:
    free(shifts);
    free(cis_raw);
    free(cis);
    free(all_random);
    free(widened);
    free(lde_nat);
    free(vcoef);
    free(lanes);
    free(mat_ptrs);
    free(lane_widths);
    return rc;
}

/* ============================================================================
 * S8 — randomization-poly commit + FS to zeta (prover.rs:257-302)
 * ========================================================================== */

dnac_prover_status_t dnac_prover_random_commit(
    const uint64_t *r_draws,
    size_t height,
    size_t width,
    unsigned log_blowup,
    const uint64_t *salts,
    size_t salt_elems,
    uint64_t *out_lde,
    dnac_p2_digest_t *out_root,
    dnac_p2_mmcs_tree_t **out_tree) {
    if (r_draws == NULL || out_lde == NULL || out_root == NULL ||
        out_tree == NULL || width == 0 || height < 2 ||
        (height & (height - 1)) != 0 || log_blowup == 0) {
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t i = 0; i < height * width; i++) {
        if (r_draws[i] >= GOLDILOCKS_P) {
            return DNAC_PROVER_ERR_NONCANONICAL;
        }
    }
    /* Inner commit (hiding_pcs.rs:421-422 delegates to the input mmcs, which
     * under M3b is the salted HidingValMmcs): natural domain shift ONE -> lde
     * shift = GENERATOR = 7 (two_adic_pcs.rs:313). Salts (stream A random
     * section) go on the committed LDE leaves. */
    dnac_prover_status_t st = dnac_prover_coset_lde_bitrev(
        r_draws, height, width, log_blowup, 7, out_lde);
    if (st != DNAC_PROVER_OK) {
        return st;
    }
    return dnac_prover_commit_matrix(out_lde, height << log_blowup, width,
                                     salts, salt_elems, out_root, out_tree);
}

dnac_prover_status_t dnac_prover_fs_to_zeta(
    dnac_transcript_t *t,
    const dnac_p2_digest_t *quotient_root,
    const dnac_p2_digest_t *random_root,
    uint64_t base_degree_bits,
    gold_fp2_t *out_zeta,
    gold_fp2_t *out_zeta_next) {
    if (t == NULL || quotient_root == NULL || out_zeta == NULL ||
        out_zeta_next == NULL || base_degree_bits > GOLDILOCKS_TWO_ADICITY) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* prover.rs:257 — observe quotient commitment (4-lane digest, P1c). */
    dnac_transcript_observe_digest(t, quotient_root);
    /* prover.rs:284-286 — observe random commitment (is_zk only), strictly
     * AFTER quotient, BEFORE zeta. */
    if (random_root != NULL) {
        dnac_transcript_observe_digest(t, random_root);
    }
    /* prover.rs:299 — sample zeta; :300-302 zeta_next = zeta * g of the
     * INITIAL trace subgroup (size 2^base_degree_bits). */
    *out_zeta = dnac_transcript_sample_fp2(t);
    *out_zeta_next = gold_fp2_mul(
        *out_zeta, gold_fp2_from_base(gold_fp_two_adic_generator(
                       (unsigned)base_degree_bits)));
    return DNAC_PROVER_OK;
}

/* ============================================================================
 * S9 — open at zeta (two_adic_pcs.rs:505-543 barycentric)
 * ========================================================================== */

dnac_prover_status_t dnac_prover_open_matrix_at(
    const uint64_t *lde_bitrev,
    size_t height,
    size_t width,
    unsigned log_blowup,
    gold_fp2_t z,
    gold_fp2_t *out_opened) {
    if (lde_bitrev == NULL || out_opened == NULL || width == 0 ||
        log_blowup == 0 || height < ((size_t)1 << log_blowup) ||
        (height & (height - 1)) != 0) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t h = height >> log_blowup;
    const unsigned log_h = (unsigned)log2_strict_usize(h);

    /* xs[i] = GENERATOR · w_h^{bitrev(i)} — the first h bit-reversed points of
     * the size-`height` GENERATOR coset are exactly the size-h coset g·K_h in
     * bit-reversed order (two_adic_pcs.rs:482-491). */
    gold_fp_t *xs = (gold_fp_t *)malloc(h * sizeof(gold_fp_t));
    gold_fp2_t *ys = (gold_fp2_t *)malloc(h * sizeof(gold_fp2_t));
    if (xs == NULL || ys == NULL) {
        free(xs);
        free(ys);
        return DNAC_PROVER_ERR_PARAM;
    }
    const gold_fp_t gen = gold_fp_from_u64(7);
    const gold_fp_t w_h = gold_fp_two_adic_generator(log_h);
    for (size_t i = 0; i < h; i++) {
        const uint64_t rev = reverse_bits_len_u64((uint64_t)i, log_h);
        xs[i] = gold_fp_mul(gen, gold_fp_pow(w_h, rev));
    }
    for (size_t c = 0; c < width; c++) {
        for (size_t i = 0; i < h; i++) {
            ys[i] = gold_fp2_from_base(gold_fp_from_u64(lde_bitrev[i * width + c]));
        }
        out_opened[c] = fri_fold_test_lagrange_at_fp_fp2(xs, ys, h, z);
    }
    free(xs);
    free(ys);
    return DNAC_PROVER_OK;
}

void dnac_prover_observe_opened(dnac_transcript_t *t, const gold_fp2_t *opened,
                                size_t n) {
    for (size_t i = 0; i < n; i++) {
        dnac_transcript_observe_fp2(t, opened[i]);
    }
}

/* ============================================================================
 * S10 — FRI commit phase (two_adic_pcs.rs:595-658 + fri/prover.rs:180-257)
 * ========================================================================== */

/* fp2 dot product of ascending alpha powers with a base-field row segment. */
static gold_fp2_t alpha_dot_base(const gold_fp2_t *alpha_pows,
                                 const uint64_t *row, size_t width) {
    gold_fp2_t acc = gold_fp2_zero();
    for (size_t i = 0; i < width; i++) {
        acc = gold_fp2_add(
            acc, gold_fp2_mul(alpha_pows[i],
                              gold_fp2_from_base(gold_fp_from_u64(row[i]))));
    }
    return acc;
}

/* fp2 dot product of ascending alpha powers with an fp2 opened vector. */
static gold_fp2_t alpha_dot_fp2(const gold_fp2_t *alpha_pows,
                                const gold_fp2_t *ys, size_t width) {
    gold_fp2_t acc = gold_fp2_zero();
    for (size_t i = 0; i < width; i++) {
        acc = gold_fp2_add(acc, gold_fp2_mul(alpha_pows[i], ys[i]));
    }
    return acc;
}

dnac_prover_status_t dnac_prover_fri_reduced_openings(
    const dnac_prover_fri_input_round_t *rounds,
    size_t n_rounds,
    unsigned log_height,
    gold_fp2_t alpha,
    gold_fp2_t *out_ro) {
    if (rounds == NULL || out_ro == NULL || n_rounds == 0 ||
        log_height == 0 || log_height > GOLDILOCKS_TWO_ADICITY) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t hgt = (size_t)1 << log_height;

    /* Widest matrix → alpha power table size. */
    size_t max_w = 0;
    for (size_t r = 0; r < n_rounds; r++) {
        if (rounds[r].height != hgt) return DNAC_PROVER_ERR_PARAM;
        if (rounds[r].width > max_w) max_w = rounds[r].width;
    }
    gold_fp2_t *apow = (gold_fp2_t *)malloc((max_w + 1) * sizeof(gold_fp2_t));
    gold_fp_t *coset = (gold_fp_t *)malloc(hgt * sizeof(gold_fp_t));
    /* inv_denoms per opening point: reuse a scratch of size hgt per point via
     * a small cache keyed by pointer identity is overkill — recompute per
     * (round,point). To match Plonky3's per-point batch inverse we compute it
     * lazily inside the loop. */
    gold_fp2_t *den = (gold_fp2_t *)malloc(hgt * sizeof(gold_fp2_t));
    gold_fp2_t *inv = (gold_fp2_t *)malloc(hgt * sizeof(gold_fp2_t));
    if (!apow || !coset || !den || !inv) {
        free(apow); free(coset); free(den); free(inv);
        return DNAC_PROVER_ERR_PARAM;
    }

    /* alpha^0..alpha^max_w. */
    gold_fp2_shifted_powers(gold_fp2_from_base(gold_fp_from_u64(1)), alpha,
                            apow, max_w + 1);

    /* coset[x] = GENERATOR · w_H^x, then bit-reversed (two_adic_pcs.rs:485-491). */
    gold_fp_shifted_powers(gold_fp_from_u64(7),
                           gold_fp_two_adic_generator(log_height), coset, hgt);
    reverse_slice_index_bits_fp(coset, hgt);

    for (size_t x = 0; x < hgt; x++) out_ro[x] = gold_fp2_zero();

    gold_fp2_t offset = gold_fp2_from_base(gold_fp_from_u64(1)); /* alpha^0 */
    for (size_t r = 0; r < n_rounds; r++) {
        const dnac_prover_fri_input_round_t *rd = &rounds[r];
        for (size_t p = 0; p < rd->num_points; p++) {
            const gold_fp2_t z = rd->points[p];
            /* inv_denoms[z][x] = 1/(z − coset[x]) (batch). */
            for (size_t x = 0; x < hgt; x++) {
                den[x] = gold_fp2_sub(z, gold_fp2_from_base(coset[x]));
            }
            gold_fp2_batch_inv_general(den, inv, hgt);
            const gold_fp2_t mred_z =
                alpha_dot_fp2(apow, rd->opened[p], rd->width);
            for (size_t x = 0; x < hgt; x++) {
                const gold_fp2_t mred_x = alpha_dot_base(
                    apow, &rd->lde_bitrev[x * rd->width], rd->width);
                const gold_fp2_t term = gold_fp2_mul(
                    offset,
                    gold_fp2_mul(gold_fp2_sub(mred_z, mred_x), inv[x]));
                out_ro[x] = gold_fp2_add(out_ro[x], term);
            }
            /* num_reduced += width ⇒ offset *= alpha^width. */
            offset = gold_fp2_mul(offset, apow[rd->width]);
        }
    }

    free(apow); free(coset); free(den); free(inv);
    return DNAC_PROVER_OK;
}

void dnac_prover_fri_ro_mixed_free(dnac_prover_fri_ro_mixed_t *ro) {
    if (ro == NULL) return;
    for (unsigned lh = 0; lh <= GOLDILOCKS_TWO_ADICITY; lh++) {
        free(ro->ro[lh]);
        ro->ro[lh] = NULL;
        ro->num_reduced[lh] = 0;
    }
}

dnac_prover_status_t dnac_prover_fri_reduced_openings_mixed(
    const dnac_prover_fri_input_round_t *rounds,
    size_t n_rounds,
    gold_fp2_t alpha,
    dnac_prover_fri_ro_mixed_t *out) {
    if (rounds == NULL || out == NULL || n_rounds == 0) {
        return DNAC_PROVER_ERR_PARAM;
    }
    memset(out, 0, sizeof(*out));

    /* Validate + size the scratch: every entry a pow2 height >= 2, width > 0. */
    size_t max_w = 0, max_h = 0;
    for (size_t r = 0; r < n_rounds; r++) {
        const size_t h = rounds[r].height;
        if (rounds[r].lde_bitrev == NULL || rounds[r].width == 0 || h < 2 ||
            (h & (h - 1)) != 0 || rounds[r].num_points == 0 ||
            rounds[r].points == NULL || rounds[r].opened == NULL) {
            return DNAC_PROVER_ERR_PARAM;
        }
        if ((size_t)log2_strict_usize(h) > GOLDILOCKS_TWO_ADICITY) {
            return DNAC_PROVER_ERR_PARAM;
        }
        if (rounds[r].width > max_w) max_w = rounds[r].width;
        if (h > max_h) max_h = h;
    }

    gold_fp2_t *apow = (gold_fp2_t *)malloc((max_w + 1) * sizeof(gold_fp2_t));
    gold_fp_t *coset = (gold_fp_t *)malloc(max_h * sizeof(gold_fp_t));
    gold_fp2_t *den = (gold_fp2_t *)malloc(max_h * sizeof(gold_fp2_t));
    gold_fp2_t *inv = (gold_fp2_t *)malloc(max_h * sizeof(gold_fp2_t));
    /* per-height running alpha offset = alpha^{num_reduced[lh]} (:628). */
    gold_fp2_t offsets[GOLDILOCKS_TWO_ADICITY + 1];
    for (unsigned lh = 0; lh <= GOLDILOCKS_TWO_ADICITY; lh++) {
        offsets[lh] = gold_fp2_from_base(gold_fp_from_u64(1));
    }
    if (!apow || !coset || !den || !inv) {
        free(apow); free(coset); free(den); free(inv);
        return DNAC_PROVER_ERR_PARAM;
    }
    gold_fp2_shifted_powers(gold_fp2_from_base(gold_fp_from_u64(1)), alpha,
                            apow, max_w + 1);

    dnac_prover_status_t rc = DNAC_PROVER_ERR_PARAM;
    for (size_t r = 0; r < n_rounds; r++) {
        const dnac_prover_fri_input_round_t *rd = &rounds[r];
        const size_t hgt = rd->height;
        const unsigned lh = (unsigned)log2_strict_usize(hgt);

        if (out->ro[lh] == NULL) {
            out->ro[lh] = (gold_fp2_t *)calloc(hgt, sizeof(gold_fp2_t));
            if (out->ro[lh] == NULL) goto fail;
        }
        gold_fp2_t *ro_h = out->ro[lh];

        /* coset[x] = GENERATOR · w_H^x bit-reversed — the size-h prefix
         * property of the global coset (two_adic_pcs.rs:485-491) makes the
         * per-height recomputation value-identical. */
        gold_fp_shifted_powers(gold_fp_from_u64(7),
                               gold_fp_two_adic_generator(lh), coset, hgt);
        reverse_slice_index_bits_fp(coset, hgt);

        for (size_t p = 0; p < rd->num_points; p++) {
            const gold_fp2_t z = rd->points[p];
            for (size_t x = 0; x < hgt; x++) {
                den[x] = gold_fp2_sub(z, gold_fp2_from_base(coset[x]));
            }
            gold_fp2_batch_inv_general(den, inv, hgt);
            const gold_fp2_t mred_z =
                alpha_dot_fp2(apow, rd->opened[p], rd->width);
            for (size_t x = 0; x < hgt; x++) {
                const gold_fp2_t mred_x = alpha_dot_base(
                    apow, &rd->lde_bitrev[x * rd->width], rd->width);
                const gold_fp2_t term = gold_fp2_mul(
                    offsets[lh],
                    gold_fp2_mul(gold_fp2_sub(mred_z, mred_x), inv[x]));
                ro_h[x] = gold_fp2_add(ro_h[x], term);
            }
            /* num_reduced[lh] += width ⇒ offset[lh] *= alpha^width (:651). */
            offsets[lh] = gold_fp2_mul(offsets[lh], apow[rd->width]);
            out->num_reduced[lh] += rd->width;
        }
    }
    rc = DNAC_PROVER_OK;

fail:
    if (rc != DNAC_PROVER_OK) dnac_prover_fri_ro_mixed_free(out);
    free(apow); free(coset); free(den); free(inv);
    return rc;
}

void dnac_prover_fri_result_free(dnac_prover_fri_result_t *res) {
    if (res == NULL) return;
    for (size_t r = 0; r < res->num_rounds; r++) {
        free(res->layer_leaves[r]);
        res->layer_leaves[r] = NULL;
        dnac_p2_mmcs_tree_free(res->layer_trees[r]);
        res->layer_trees[r] = NULL;
    }
    res->num_rounds = 0;
}

/* compute_log_arity_for_round (config.rs:152-179): min over the three bounds. */
static unsigned fri_log_arity(unsigned log_current, int has_next,
                              unsigned next_log_h, unsigned log_final_height,
                              unsigned max_log_arity) {
    unsigned a = log_current - log_final_height;
    if (has_next && (log_current - next_log_h) < a) {
        a = log_current - next_log_h;
    }
    if (max_log_arity < a) a = max_log_arity;
    return a;
}

dnac_prover_status_t dnac_prover_fri_commit_phase(
    gold_fp2_t *ro,
    size_t ro_len,
    unsigned log_blowup,
    unsigned log_final_poly_len,
    unsigned max_log_arity,
    unsigned commit_pow_bits,   /* P1: per-round commit PoW (0 = grind no-op) */
    unsigned query_pow_bits,    /* P1: query PoW (0 = grind no-op) */
    const uint64_t *salt_draws, /* M3b: stream B (FRI-mmcs), or NULL */
    size_t          salt_elems,
    dnac_transcript_t *t,
    dnac_prover_fri_result_t *res) {
    /* P2L-d d3: thin wrapper over the mixed-height general form. A single
     * input means the roll-in branch never fires, so the transcript/commit
     * sequence is byte-identical to the pre-d3 body (v3 KATs frozen). */
    if (ro == NULL) return DNAC_PROVER_ERR_PARAM;
    const gold_fp2_t *inputs[1] = { ro };
    const size_t lens[1] = { ro_len };
    return dnac_prover_fri_commit_phase_mixed(
        inputs, lens, 1, log_blowup, log_final_poly_len, max_log_arity,
        commit_pow_bits, query_pow_bits, salt_draws, salt_elems, t, res);
}

dnac_prover_status_t dnac_prover_fri_commit_phase_mixed(
    const gold_fp2_t *const *inputs,  /* descending heights */
    const size_t            *input_lens,
    size_t                   num_inputs,
    unsigned log_blowup,
    unsigned log_final_poly_len,
    unsigned max_log_arity,
    unsigned commit_pow_bits,
    unsigned query_pow_bits,
    const uint64_t *salt_draws,
    size_t          salt_elems,
    dnac_transcript_t *t,
    dnac_prover_fri_result_t *res) {
    if (inputs == NULL || input_lens == NULL || num_inputs == 0 ||
        t == NULL || res == NULL || max_log_arity == 0) {
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t i = 0; i < num_inputs; i++) {
        if (inputs[i] == NULL || input_lens[i] == 0 ||
            (input_lens[i] & (input_lens[i] - 1)) != 0) {
            return DNAC_PROVER_ERR_PARAM;
        }
        /* strictly descending (prover.rs:69-75 sorted assert; equal heights
         * were already summed into ONE reduced opening upstream). */
        if (i > 0 && input_lens[i] >= input_lens[i - 1]) {
            return DNAC_PROVER_ERR_PARAM;
        }
    }
    if (salt_elems > 0 && salt_draws == NULL) return DNAC_PROVER_ERR_PARAM;
    /* running offset into salt_draws (stream B): layer r consumes rows*salt_elems
     * draws in commit order (hiding_mmcs.rs:129 RowMajorMatrix::rand). */
    size_t salt_off = 0;
    memset(res, 0, sizeof(*res));
    const size_t final_poly_len = (size_t)1 << log_final_poly_len;
    const size_t stop_len = ((size_t)1 << log_blowup) * final_poly_len;
    if (final_poly_len > DNAC_PROVER_MAX_FINAL_POLY) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* Reject len <= stop_len (red-team S10 + completeness-critic C3):
     *  - len < stop_len: the final-poly truncate reads past `folded` (heap
     *    overread).
     *  - len == stop_len: the fold loop `while(len > stop_len)` never runs
     *    ⇒ 0 FRI commit-phase rounds ⇒ no folding low-degree binding, which
     *    Plonky3 PANICS on (strict assert log_min_height > log_final_poly_len +
     *    log_blowup, fri/prover.rs:79-81). Fail-close, symmetric with the S2
     *    log_lde>= guard and the P1 height<4 guard.
     * Mixed form: the SMALLEST input must still be foldable-into, else it
     * would silently never roll in (unsound drop) — same fail-close bar. */
    if (input_lens[num_inputs - 1] <= stop_len) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const unsigned log_final_height = log_blowup + log_final_poly_len;

    /* working codeword (owned copy so inputs stay caller-owned). */
    size_t len = input_lens[0];
    size_t next_in = 1; /* roll-in cursor (inputs_iter, prover.rs:190) */
    gold_fp2_t *folded = (gold_fp2_t *)malloc(len * sizeof(gold_fp2_t));
    if (folded == NULL) return DNAC_PROVER_ERR_PARAM;
    memcpy(folded, inputs[0], len * sizeof(gold_fp2_t));

    size_t round = 0;
    while (len > stop_len) {
        if (round >= DNAC_PROVER_MAX_FRI_ROUNDS) {
            free(folded);
            dnac_prover_fri_result_free(res);
            return DNAC_PROVER_ERR_PARAM;
        }
        const unsigned log_current = (unsigned)log2_strict_usize(len);
        const int has_next = next_in < num_inputs;
        const unsigned next_lh =
            has_next ? (unsigned)log2_strict_usize(input_lens[next_in]) : 0;
        const unsigned log_arity = fri_log_arity(
            log_current, has_next, next_lh, log_final_height, max_log_arity);
        const size_t arity = (size_t)1 << log_arity;
        const size_t rows = len >> log_arity;

        /* Retain the pre-fold layer matrix (rows x arity fp2) for S12. */
        gold_fp2_t *leaves = (gold_fp2_t *)malloc(len * sizeof(gold_fp2_t));
        if (leaves == NULL) {
            free(folded);
            dnac_prover_fri_result_free(res);
            return DNAC_PROVER_ERR_PARAM;
        }
        memcpy(leaves, folded, len * sizeof(gold_fp2_t));

        /* ExtensionMmcs commit: leaf row = arity fp2 base-flattened to 2*arity
         * LANES [c0,c1]×arity (extension_mmcs.rs:44-47). M3b: the hiding
         * FRI-mmcs appends salt_elems BASE salt lanes after the flattened row
         * (hiding_mmcs.rs:169-170; extension_mmcs passes the proof through
         * unflattened). P1c: lanes direct, no byte serialization. */
        const size_t leaf_u64 = arity * 2;
        const size_t leaf_cols = leaf_u64 + salt_elems;
        uint64_t *lanebuf = (uint64_t *)malloc(rows * leaf_cols * sizeof(uint64_t));
        if (lanebuf == NULL) {
            free(leaves);
            free(folded);
            dnac_prover_fri_result_free(res);
            return DNAC_PROVER_ERR_PARAM;
        }
        for (size_t rr = 0; rr < rows; rr++) {
            for (size_t j = 0; j < arity; j++) {
                const gold_fp2_t v = leaves[rr * arity + j];
                lanebuf[rr * leaf_cols + j * 2]     = gold_fp_to_u64(v.a);
                lanebuf[rr * leaf_cols + j * 2 + 1] = gold_fp_to_u64(v.b);
            }
            for (size_t s = 0; s < salt_elems; s++) {
                const uint64_t sv = salt_draws[salt_off + rr * salt_elems + s];
                if (sv >= GOLDILOCKS_P) {
                    free(lanebuf); free(leaves); free(folded);
                    dnac_prover_fri_result_free(res);
                    return DNAC_PROVER_ERR_NONCANONICAL;
                }
                lanebuf[rr * leaf_cols + leaf_u64 + s] = sv;
            }
        }
        salt_off += rows * salt_elems;
        dnac_p2_digest_t root;
        dnac_p2_mmcs_tree_t *tree = NULL;
        const uint64_t *lmats[1] = { lanebuf };
        const size_t lws[1] = { leaf_cols };
        dnac_p2_mmcs_status_t mst =
            dnac_p2_mmcs_commit(lmats, lws, 1, rows, &root, &tree);
        free(lanebuf);
        if (mst != DNAC_P2M_OK) {
            free(leaves);
            free(folded);
            dnac_prover_fri_result_free(res);
            return DNAC_PROVER_ERR_PARAM;
        }

        /* observe root, grind commit PoW, sample beta (prover.rs:218-228). */
        dnac_transcript_observe_digest(t, &root);
        res->commit_pow_witnesses[round] =
            dnac_transcript_grind(t, commit_pow_bits); /* no-op at 0 */
        const gold_fp2_t beta = dnac_transcript_sample_fp2(t);

        /* fold with beta (fri_fold_matrix_fp2, arity path already byte-matched). */
        gold_fp2_t *next = (gold_fp2_t *)malloc(rows * sizeof(gold_fp2_t));
        if (next == NULL) {
            free(leaves);
            free(folded);
            dnac_p2_mmcs_tree_free(tree);
            dnac_prover_fri_result_free(res);
            return DNAC_PROVER_ERR_PARAM;
        }
        fri_fold_matrix_fp2(beta, log_arity, rows, leaves, next);

        res->roots[round] = root;
        res->betas[round] = beta;
        res->log_arities[round] = log_arity;
        res->layer_leaves[round] = leaves;
        res->layer_heights[round] = rows;
        res->layer_log_arities[round] = log_arity;
        res->layer_trees[round] = tree;
        res->num_rounds = round + 1;

        free(folded);
        folded = next;
        len = rows;
        round++;

        /* ROLL-IN (prover.rs:238-245 next_if): if the next reduced-opening
         * codeword has reached the folded length, add it in scaled by
         * beta^{2^log_arity} (beta.exp_power_of_2(log_arity) — independence
         * factor; the fri_verifier.c:477-480 verify-side mirror). */
        if (next_in < num_inputs && input_lens[next_in] == len) {
            gold_fp2_t beta_pow = beta;
            for (unsigned s = 0; s < log_arity; s++) {
                beta_pow = gold_fp2_mul(beta_pow, beta_pow);
            }
            const gold_fp2_t *in = inputs[next_in];
            for (size_t j = 0; j < len; j++) {
                folded[j] =
                    gold_fp2_add(folded[j], gold_fp2_mul(beta_pow, in[j]));
            }
            next_in++;
        }
    }
    /* every input must have been consumed (fail-close: a never-rolled-in
     * codeword would drop its openings from the low-degree binding). */
    if (next_in != num_inputs) {
        free(folded);
        dnac_prover_fri_result_free(res);
        return DNAC_PROVER_ERR_PARAM;
    }

    /* final poly: truncate, bit-reverse, inverse-NTT (prover.rs:248-254). */
    res->final_poly_len = final_poly_len;
    for (size_t i = 0; i < final_poly_len; i++) res->final_poly[i] = folded[i];
    reverse_slice_index_bits_fp2(res->final_poly, final_poly_len);
    ntt_goldilocks_ext_inverse(res->final_poly,
                               (unsigned)log2_strict_usize(final_poly_len));
    /* observe all coefficients (c0,c1 each). */
    for (size_t i = 0; i < final_poly_len; i++) {
        dnac_transcript_observe_fp2(t, res->final_poly[i]);
    }
    /* observe each round's log_arity (prover.rs:92-94) + grind the query PoW. */
    for (size_t r = 0; r < res->num_rounds; r++) {
        dnac_transcript_observe_fp(
            t, gold_fp_from_u64((uint64_t)res->log_arities[r]));
    }
    res->query_pow_witness = dnac_transcript_grind(t, query_pow_bits); /* no-op at 0 */

    free(folded);
    return DNAC_PROVER_OK;
}
