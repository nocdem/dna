/**
 * @file stark_constraints.c
 * @brief Generic STARK constraint-check primitives — Plonky3 82cfad73 port.
 *
 * See stark_constraints.h for the source-line map. Every operation is fp2 over
 * the pinned field_goldilocks primitives (themselves Plonky3 byte-matched).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stark_constraints.h"

/* ============================================================================
 * Selectors (domain.rs:262-271; trace shift = ONE, two_adic_pcs.rs:286)
 * ========================================================================== */

dnac_stark_selectors_t dnac_stark_selectors_at_point(gold_fp2_t zeta,
                                                     size_t base_degree_bits) {
    /* unshifted_point = zeta * shift_inverse, shift = ONE -> unshifted = zeta. */
    /* z_h = zeta^(2^base_degree_bits) - 1  (exp_power_of_2 = square bdb times). */
    gold_fp2_t pow = zeta;
    for (size_t i = 0; i < base_degree_bits; i++) {
        pow = gold_fp2_sqr(pow);
    }
    const gold_fp2_t one = gold_fp2_one();
    const gold_fp2_t z_h = gold_fp2_sub(pow, one);

    /* g = subgroup_generator = two_adic_generator(base_degree_bits) (base field);
     * g^-1 promoted to fp2. */
    const gold_fp_t g = gold_fp_two_adic_generator((unsigned)base_degree_bits);
    const gold_fp2_t g_inv = gold_fp2_from_base(gold_fp_inv(g));

    const gold_fp2_t zeta_minus_one = gold_fp2_sub(zeta, one);
    const gold_fp2_t zeta_minus_ginv = gold_fp2_sub(zeta, g_inv);

    dnac_stark_selectors_t s;
    s.z_h = z_h;
    s.is_first_row = gold_fp2_mul(z_h, gold_fp2_inv(zeta_minus_one)); /* z_h/(zeta-1) */
    s.is_last_row = gold_fp2_mul(z_h, gold_fp2_inv(zeta_minus_ginv)); /* z_h/(zeta-g^-1) */
    s.is_transition = zeta_minus_ginv;                               /* zeta - g^-1 */
    s.inv_vanishing = gold_fp2_inv(z_h);                             /* 1/z_h */
    return s;
}

/* ============================================================================
 * Quotient recompose, num_qc=1 (verifier.rs:87-95)
 * ========================================================================== */

gold_fp2_t dnac_stark_recompose_quotient_1chunk(const gold_fp2_t chunk0[2]) {
    /* X = the fp2 basis element (0, 1) = 0 + 1*X. */
    const gold_fp2_t x = gold_fp2_new(gold_fp_zero(), gold_fp_one());
    /* quotient(zeta) = chunk0[0]*1 + chunk0[1]*X. */
    return gold_fp2_add(chunk0[0], gold_fp2_mul(chunk0[1], x));
}

/* ============================================================================
 * Quotient recompose, N chunks (B1 Stage-2; verifier.rs:59-96, 305-312, 463-467)
 * ========================================================================== */

/* Z_j(pt) = (pt * shift_inv_j)^(2^chunk_log) - 1 (domain.rs:248-253), fp2 pt. */
static gold_fp2_t conf_vanish_fp2(gold_fp2_t pt, gold_fp_t shift_inv,
                                  size_t chunk_log) {
    gold_fp2_t x = gold_fp2_mul(pt, gold_fp2_from_base(shift_inv));
    for (size_t i = 0; i < chunk_log; i++) x = gold_fp2_sqr(x);
    return gold_fp2_sub(x, gold_fp2_one());
}

/* Same in the base field (first_point args are fp; field.rs:1171-1188 makes the
 * denominator a pure base-field computation). */
static gold_fp_t conf_vanish_fp(gold_fp_t pt, gold_fp_t shift_inv,
                                size_t chunk_log) {
    gold_fp_t x = gold_fp_mul(pt, shift_inv);
    for (size_t i = 0; i < chunk_log; i++) x = gold_fp_sqr(x);
    return gold_fp_sub(x, gold_fp_one());
}

dnac_stark_verify_status_t dnac_stark_recompose_quotient_nchunk(
    gold_fp2_t zeta,
    size_t degree_bits,
    size_t log_num_qc,
    size_t is_zk,
    const gold_fp2_t *chunks,
    size_t num_qc,
    size_t chunk_stride,
    gold_fp2_t *quotient_out) {

    /* Fail-close shape gates (verifier.rs:294-296, 347-357 analogue). */
    if (!chunks || !quotient_out || chunk_stride < 2) {
        return DNAC_STARK_VERIFY_ERR_SHAPE;
    }
    if (is_zk > 1 || degree_bits < is_zk) return DNAC_STARK_VERIFY_ERR_SHAPE;
    if (log_num_qc + is_zk >= 63 ||
        num_qc != ((size_t)1 << (log_num_qc + is_zk)) ||
        num_qc > DNAC_STARK_MAX_QUOTIENT_CHUNKS) {
        return DNAC_STARK_VERIFY_ERR_SHAPE;
    }
    const size_t q_log = degree_bits + log_num_qc; /* verifier.rs:305-311 */
    if (q_log > GOLDILOCKS_TWO_ADICITY) return DNAC_STARK_VERIFY_ERR_SHAPE;
    /* chunk_log = Q_log - (log_num_qc + is_zk) = degree_bits - is_zk
     * (domain.rs:199-211 split of the size-2^Q_log quotient domain into
     * num_qc = 2^(log_num_qc+is_zk) chunks). */
    const size_t chunk_log = degree_bits - is_zk;

    /* Chunk-domain shifts: shift_i = GENERATOR * g_Q^i (domain.rs:180-193 gives
     * the quotient domain shift = 1 * GENERATOR; :199-211 multiplies by the
     * subgroup generator power). Ascending wire order i = 0..num_qc-1
     * (verifier.rs:434-444, 463-467). */
    const gold_fp_t g_q = gold_fp_two_adic_generator((unsigned)q_log);
    gold_fp_t shift[DNAC_STARK_MAX_QUOTIENT_CHUNKS];
    gold_fp_t shift_inv[DNAC_STARK_MAX_QUOTIENT_CHUNKS];
    gold_fp_t s = gold_fp_from_u64(GOLDILOCKS_GENERATOR);
    for (size_t i = 0; i < num_qc; i++) {
        shift[i] = s;
        shift_inv[i] = gold_fp_inv(s);
        s = gold_fp_mul(s, g_q);
    }

    /* Precompute Z_j(zeta) (fp2 numerators). */
    gold_fp2_t vz[DNAC_STARK_MAX_QUOTIENT_CHUNKS];
    for (size_t j = 0; j < num_qc; j++) {
        vz[j] = conf_vanish_fp2(zeta, shift_inv[j], chunk_log);
    }

    /* zps[i] = prod_{j != i} Z_j(zeta) * Z_j(first_point_i)^-1, first_point_i =
     * shift_i (domain.rs:164-166); ascending j (verifier.rs:67-83). */
    const gold_fp2_t x_basis = gold_fp2_new(gold_fp_zero(), gold_fp_one());
    gold_fp2_t quotient = gold_fp2_zero();
    for (size_t i = 0; i < num_qc; i++) {
        gold_fp2_t zps_i = gold_fp2_one();
        for (size_t j = 0; j < num_qc; j++) {
            if (j == i) continue;
            const gold_fp_t den = conf_vanish_fp(shift[i], shift_inv[j], chunk_log);
            if (gold_fp_eq(den, gold_fp_zero())) {
                /* Unreachable for disjoint cosets (domain.rs:100-109); reject
                 * defensively rather than invert zero. */
                return DNAC_STARK_VERIFY_ERR_SHAPE;
            }
            const gold_fp2_t term =
                gold_fp2_mul(vz[j], gold_fp2_from_base(gold_fp_inv(den)));
            zps_i = gold_fp2_mul(zps_i, term);
        }
        /* val_i = chunk_i[0] + chunk_i[1] * X (from_ext_basis_coefficients,
         * field.rs:1159-1167; only the first DIMENSION=2 values are read — the
         * merged random-codeword tail is PCS data, hiding_pcs.rs:349). */
        const gold_fp2_t val = gold_fp2_add(
            chunks[i * chunk_stride],
            gold_fp2_mul(chunks[i * chunk_stride + 1], x_basis));
        quotient = gold_fp2_add(quotient, gold_fp2_mul(zps_i, val));
    }
    *quotient_out = quotient;
    return DNAC_STARK_VERIFY_OK;
}

/* ============================================================================
 * Alpha-fold accumulator (folder.rs:215-218)
 * ========================================================================== */

void dnac_stark_fold_init(dnac_stark_fold_t *f, gold_fp2_t alpha) {
    f->alpha = alpha;
    f->acc = gold_fp2_zero();
}

void dnac_stark_fold_assert_zero(dnac_stark_fold_t *f, gold_fp2_t x) {
    /* folder.rs:216-217: accumulator *= alpha; accumulator += x. */
    f->acc = gold_fp2_add(gold_fp2_mul(f->acc, f->alpha), x);
}

void dnac_stark_fold_assert_eq(dnac_stark_fold_t *f, gold_fp2_t a, gold_fp2_t b) {
    /* builder.rs:147-149: assert_zero(a - b). */
    dnac_stark_fold_assert_zero(f, gold_fp2_sub(a, b));
}

void dnac_stark_fold_assert_bool(dnac_stark_fold_t *f, gold_fp2_t x) {
    /* builder.rs:191-193: assert_zero(x.bool_check()) = assert_zero(x*(x-1)). */
    const gold_fp2_t x_minus_one = gold_fp2_sub(x, gold_fp2_one());
    dnac_stark_fold_assert_zero(f, gold_fp2_mul(x, x_minus_one));
}

void dnac_stark_fold_when(dnac_stark_fold_t *f, gold_fp2_t selector, gold_fp2_t x) {
    /* filtered.rs:60-62: inner.assert_zero(condition * x). */
    dnac_stark_fold_assert_zero(f, gold_fp2_mul(selector, x));
}

/* ============================================================================
 * Final out-of-domain check (verifier.rs:157-159)
 * ========================================================================== */

dnac_stark_verify_status_t dnac_stark_final_check(gold_fp2_t folded,
                                                  gold_fp2_t inv_vanishing,
                                                  gold_fp2_t quotient) {
    const gold_fp2_t lhs = gold_fp2_mul(folded, inv_vanishing);
    return gold_fp2_eq(lhs, quotient) ? DNAC_STARK_VERIFY_OK
                                      : DNAC_STARK_VERIFY_ERR_OOD_MISMATCH;
}

/* ============================================================================
 * S4 — folder-level fold helpers (the air_eval API) + verify_constraints glue.
 * ========================================================================== */

void dnac_stark_folder_assert_zero(dnac_stark_folder_t *f, gold_fp2_t x) {
    dnac_stark_fold_assert_zero(&f->fold, x);          /* acc = acc*alpha + x */
    if (f->capture && f->capture_len < f->capture_cap) {
        f->capture[f->capture_len].received = x;
        f->capture[f->capture_len].after = f->fold.acc;
        f->capture_len++;
    }
}

void dnac_stark_folder_assert_eq(dnac_stark_folder_t *f, gold_fp2_t a, gold_fp2_t b) {
    dnac_stark_folder_assert_zero(f, gold_fp2_sub(a, b));            /* builder.rs:147-149 */
}

void dnac_stark_folder_assert_bool(dnac_stark_folder_t *f, gold_fp2_t x) {
    const gold_fp2_t x_minus_one = gold_fp2_sub(x, gold_fp2_one()); /* builder.rs:191-193 */
    dnac_stark_folder_assert_zero(f, gold_fp2_mul(x, x_minus_one));
}

void dnac_stark_folder_when(dnac_stark_folder_t *f, gold_fp2_t selector, gold_fp2_t x) {
    dnac_stark_folder_assert_zero(f, gold_fp2_mul(selector, x));    /* filtered.rs:60-62 */
}

/* Shared shape gate + fold/OOD core for the 1-chunk and N-chunk entry points.
 * `quotient` is the already-recomposed quotient(zeta). */
static dnac_stark_verify_status_t stark_verify_constraints_core(
    const dnac_stark_air_t *air,
    const gold_fp2_t *trace_local, size_t trace_local_len,
    const gold_fp2_t *trace_next, size_t trace_next_len,
    const gold_fp_t *public_values, size_t num_public_values,
    gold_fp2_t zeta,
    size_t base_degree_bits,
    gold_fp2_t alpha,
    gold_fp2_t quotient);

dnac_stark_verify_status_t dnac_stark_verify_constraints(
    const dnac_stark_air_t *air,
    const gold_fp2_t *trace_local, size_t trace_local_len,
    const gold_fp2_t *trace_next, size_t trace_next_len,
    const gold_fp_t *public_values, size_t num_public_values,
    gold_fp2_t zeta,
    size_t base_degree_bits,
    gold_fp2_t alpha,
    const gold_fp2_t quotient_chunk[2]) {

    if (!quotient_chunk) return DNAC_STARK_VERIFY_ERR_SHAPE;
    /* quotient(zeta) (num_qc=1). */
    const gold_fp2_t quotient = dnac_stark_recompose_quotient_1chunk(quotient_chunk);
    return stark_verify_constraints_core(air, trace_local, trace_local_len,
                                         trace_next, trace_next_len,
                                         public_values, num_public_values, zeta,
                                         base_degree_bits, alpha, quotient);
}

dnac_stark_verify_status_t dnac_stark_verify_constraints_nchunk(
    const dnac_stark_air_t *air,
    const gold_fp2_t *trace_local, size_t trace_local_len,
    const gold_fp2_t *trace_next, size_t trace_next_len,
    const gold_fp_t *public_values, size_t num_public_values,
    gold_fp2_t zeta,
    size_t degree_bits,
    size_t log_num_qc,
    size_t is_zk,
    gold_fp2_t alpha,
    const gold_fp2_t *chunks, size_t num_qc, size_t chunk_stride) {

    gold_fp2_t quotient;
    const dnac_stark_verify_status_t rs = dnac_stark_recompose_quotient_nchunk(
        zeta, degree_bits, log_num_qc, is_zk, chunks, num_qc, chunk_stride,
        &quotient);
    if (rs != DNAC_STARK_VERIFY_OK) return rs;
    /* Selectors live on init_trace_domain: size 2^(degree_bits - is_zk), shift
     * ONE (verifier.rs:303, 488) — NOT the chunk-domain size. */
    return stark_verify_constraints_core(air, trace_local, trace_local_len,
                                         trace_next, trace_next_len,
                                         public_values, num_public_values, zeta,
                                         degree_bits - is_zk, alpha, quotient);
}

static dnac_stark_verify_status_t stark_verify_constraints_core(
    const dnac_stark_air_t *air,
    const gold_fp2_t *trace_local, size_t trace_local_len,
    const gold_fp2_t *trace_next, size_t trace_next_len,
    const gold_fp_t *public_values, size_t num_public_values,
    gold_fp2_t zeta,
    size_t base_degree_bits,
    gold_fp2_t alpha,
    gold_fp2_t quotient) {

    /* 1. shape (verifier.rs:327-358 subset). */
    if (!air || !air->air_eval || !trace_local) {
        return DNAC_STARK_VERIFY_ERR_SHAPE;
    }
    if (air->main_width == 0 || air->main_width > DNAC_STARK_MAX_MAIN_WIDTH) {
        return DNAC_STARK_VERIFY_ERR_SHAPE;
    }
    if (trace_local_len != air->main_width) return DNAC_STARK_VERIFY_ERR_SHAPE;
    if (num_public_values != air->num_public_values) return DNAC_STARK_VERIFY_ERR_SHAPE;
    if (air->main_next) {
        /* main_next=true => trace_next present at full width (verifier.rs:339-343). */
        if (!trace_next || trace_next_len != air->main_width) {
            return DNAC_STARK_VERIFY_ERR_SHAPE;
        }
    }

    /* 3. selectors at zeta. */
    const dnac_stark_selectors_t sels =
        dnac_stark_selectors_at_point(zeta, base_degree_bits);

    /* main_next=false => zero-window trace_next (verifier.rs:469-476). The AIR
     * never reads it, but we supply a valid full-width buffer defensively.
     *
     * INTENTIONAL LENIENCY (per S4 design Part B; red-team JUDGMENT 2026-06-01):
     * Plonky3 `valid_shape` additionally REJECTS a present-but-unneeded trace_next
     * when main_next==false (verifier.rs:344-345 require `trace_next.is_none()`).
     * This glue instead silently ignores a stray non-NULL trace_next and substitutes
     * the zero-window. This is benign and never verdict-flipping: a main_next=false
     * AIR's eval never reads trace_next, and in the full proof no zeta_next trace
     * opening is committed (verifier.rs:417-425), so a real unrequested opening is
     * caught by the separate PCS/FRI layer, not here. The DNAC production AIR
     * (range_proof, main_next=true) never hits this path. If this glue is reused for
     * an AIR whose eval DOES read the next row under main_next==false, add the
     * `trace_next == NULL` reject here to restore exact Plonky3 strictness. */
    gold_fp2_t zeros[DNAC_STARK_MAX_MAIN_WIDTH];
    const gold_fp2_t *tn = trace_next;
    if (!air->main_next) {
        for (size_t i = 0; i < air->main_width; i++) zeros[i] = gold_fp2_zero();
        tn = zeros;
    }

    /* 4-5. build the folder (no capture in production) and run the AIR's eval. */
    dnac_stark_folder_t folder;
    folder.trace_local = trace_local;
    folder.trace_next = tn;
    folder.main_width = air->main_width;
    folder.public_values = public_values;
    folder.num_public_values = num_public_values;
    folder.is_first_row = sels.is_first_row;
    folder.is_last_row = sels.is_last_row;
    folder.is_transition = sels.is_transition;
    dnac_stark_fold_init(&folder.fold, alpha);
    folder.capture = NULL;
    folder.capture_cap = 0;
    folder.capture_len = 0;
    air->air_eval(&folder);

    /* 6. final OOD check (verifier.rs:157-159). */
    return dnac_stark_final_check(folder.fold.acc, sels.inv_vanishing, quotient);
}
