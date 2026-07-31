/**
 * @file transcript_air_fold.c
 * @brief s1a — the P2a transcript control-AIR in verifier-fold (fp2) form.
 *
 * TRANSCRIPTION, not design. Every block below is the fold image of the block
 * with the SAME LETTER in `transcript_air.c`, in the SAME order, and cites the
 * exact line range it transcribes. No constraint is added, removed or
 * strengthened; the two deviations forced by the form are named where they
 * occur:
 *   (1) everything the u64 evaluates only when `next != NULL`
 *       (transcript_air.c:224 onwards) is multiplied by `is_transition`;
 *   (2) the trace-level terminality gate (transcript_air.c:444-460) becomes an
 *       explicit `is_last_row` boundary constraint, emitted last.
 * See transcript_air_fold.h for the API contract, the degree consequence and the
 * s1b entry duties this module deliberately does not carry.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "transcript_air_fold.h"

#include "duplex_challenger.h" /* DNAC_DUPLEX_DS_PREFIX */
#include "field_goldilocks.h"
#include "poseidon2_air_cols.h"
#include "poseidon2_fold.h" /* dnac_poseidon2_fold_eval */

/* ── local fp2 shorthands (conf_action_fold.c idiom) ─────────────────────── */
static inline gold_fp2_t fp2u(uint64_t v) {
    return gold_fp2_from_base(gold_fp_from_u64(v));
}
static inline gold_fp2_t add(gold_fp2_t a, gold_fp2_t b) { return gold_fp2_add(a, b); }
static inline gold_fp2_t sub(gold_fp2_t a, gold_fp2_t b) { return gold_fp2_sub(a, b); }
static inline gold_fp2_t mul(gold_fp2_t a, gold_fp2_t b) { return gold_fp2_mul(a, b); }

/* ═══════════════ binding — CALLER-OWNED state, no module static ═══════════
 * FLEET 034: `air_eval`'s signature still takes no ctx, but the FOLDER carries
 * one (`folder->ctx`), so the pinned cfg + script snapshot lives in a
 * caller-owned `dnac_tair_fold_state_t` (header). Pure function of the cfg — no
 * clock, no RNG, no wire data — so two nodes binding the same pair emit the
 * identical constraint stream. See the header for the lifetime contract. */

/* The field-shape precondition of the canonicality ADAPTATION
 * (transcript_air.c:74-84 verbatim): p-1 must be [ones][trailing zeros].
 * Checked ONCE at bind instead of once per row — the property is a compile-time
 * fact about the field, not about a row. Returns 0 on reject. */
static int tair_fold_field_shape(unsigned *trailing_out) {
    const uint64_t c_max = GOLDILOCKS_P - 1u;
    unsigned trailing = 0;
    while (trailing < 64 && ((c_max >> trailing) & 1u) == 0u) trailing++;
    if (trailing == 0 || trailing >= 64) return 0;
    for (unsigned i = trailing; i < 64; i++)
        if (((c_max >> i) & 1u) == 0u) return 0;
    *trailing_out = trailing;
    return 1;
}

/* s3a: the cfg/script gate, resolved THROUGH the table module's public
 * accessors — the ONE schedule authority, exactly as mmcs_air_fold.c:56-80
 * resolves through the u64 module's accessors. Returns 0 on reject. */
static int tair_fold_resolve(const dnac_tair_config_t *cfg,
                             const dnac_tair_script_t *sched,
                             size_t *out_npub) {
    if (cfg == NULL || sched == NULL) return 0;
    if (cfg->pow_bits > (size_t)TAIR_MAX_NUM_BITS) return 0;

    const size_t npub = dnac_tair_num_publics(sched);
    if (npub == 0) return 0;
    if (sched->n_ops > TAIR_TBL_MAX_STEPS) return 0;

    size_t script_pow = 0;
    if (dnac_tair_script_pow_bits(sched, &script_pow) != DNAC_TAIR_TABLE_OK) {
        return 0;
    }
    if (script_pow != 0 && script_pow != cfg->pow_bits) return 0;

    *out_npub = npub;
    return 1;
}

size_t dnac_transcript_air_fold_control_steps(const dnac_tair_config_t *cfg,
                                              const dnac_tair_script_t *sched) {
    size_t npub = 0;
    if (!tair_fold_resolve(cfg, sched, &npub)) return 0;
    return TAIR_FOLD_SCRIPT_FREE_STEPS + cfg->pow_bits +
           dnac_tair_total_bits(sched);
}

int dnac_transcript_air_fold_bind(const dnac_tair_config_t *cfg,
                                  const dnac_tair_script_t *sched,
                                  dnac_tair_fold_state_t *state,
                                  dnac_stark_air_t *out_air) {
    /* Fail-close: ANY rejected bind DISARMS the DESCRIPTOR (`out_air->ctx =
     * NULL`) as well as the state it was handed — see the same block in
     * mmcs_air_fold.c for why the state alone is not enough. Only the ARMING is
     * cleared; the shape fields are the caller's and are left untouched. */
    if (out_air != NULL) out_air->ctx = NULL;
    if (state != NULL) state->bound = 0;
    if (state == NULL || out_air == NULL) return -1;

    size_t npub = 0;
    if (!tair_fold_resolve(cfg, sched, &npub)) return -1;

    unsigned trailing = 0;
    if (!tair_fold_field_shape(&trailing)) return -1;

    state->pow_bits = cfg->pow_bits;
    state->trailing = trailing;
    state->sched = sched;
    state->num_publics = npub;
    state->bound = 1;

    out_air->main_width = (size_t)TAIR_WIDTH;
    out_air->num_public_values = npub;
    out_air->main_next = 1; /* blocks F..L read the next row */
    out_air->air_eval = dnac_transcript_air_fold_eval;
    out_air->ctx = state;
    return 0;
}

/* ══════════════════════════ constraint emission ══════════════════════════ */

void dnac_transcript_air_fold_eval(dnac_stark_folder_t *f) {
    /* Shape / binding gate. `air_eval` cannot report an error, so an
     * out-of-contract call emits ONE unsatisfiable constraint rather than
     * folding nothing (which would ACCEPT everything). `ctx == NULL` (no
     * binding at all) joins the same gate — the exact analogue of the retired
     * `!g_tair_fold.bound`. (`ST`, not `S`: block D already owns `S`.) */
    const dnac_tair_fold_state_t *const ST =
        (const dnac_tair_fold_state_t *)f->ctx;
    if (ST == NULL || !ST->bound || ST->sched == NULL ||
        f->trace_local == NULL || f->trace_next == NULL ||
        f->main_width != (size_t)TAIR_WIDTH ||
        f->num_public_values != ST->num_publics ||
        f->public_values == NULL || f->preprocessed_local == NULL ||
        f->prep_width < TAIR_TBL_COLS) {
        dnac_stark_folder_assert_zero(f, gold_fp2_one());
        return;
    }

    const gold_fp2_t *L = f->trace_local;
    const gold_fp2_t *N = f->trace_next;
    const gold_fp2_t *PL = f->preprocessed_local;
    const dnac_tair_script_t *const SC = ST->sched;

    /* Publics are BASE field in the folder (stark_constraints.h:265-266);
     * promote in-expression, the conf_root_fold / mmcs_air_fold idiom. */
#define TFPUB(i) gold_fp2_from_base(f->public_values[(i)])
    const gold_fp2_t one = gold_fp2_one();
    const gold_fp2_t zero = gold_fp2_zero();
    const gold_fp2_t tr = f->is_transition;
    const unsigned trailing = ST->trailing;

    /* ══ Column reads (transcript_air.c:90-112) ═══════════════════════════ */
    gold_fp2_t sel[TAIR_NUM_SEL], il[TAIR_LEN_SLOTS], ol[TAIR_LEN_SLOTS];
    gold_fp2_t pc[TAIR_PREFIX_SLOTS];
    for (size_t s = 0; s < TAIR_NUM_SEL; s++) sel[s] = L[tair_sel_off(s)];
    for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) {
        il[k] = L[tair_il_off(k)];
        ol[k] = L[tair_ol_off(k)];
    }
    for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++) pc[k] = L[tair_prefix_off(k)];

    const gold_fp2_t s_start = sel[TAIR_SEL_START];
    const gold_fp2_t s_obs = sel[TAIR_SEL_OBS];
    const gold_fp2_t s_obsd = sel[TAIR_SEL_OBS_DUP];
    const gold_fp2_t s_smp = sel[TAIR_SEL_SAMPLE];
    const gold_fp2_t s_smpd = sel[TAIR_SEL_SAMPLE_DUP];
    const gold_fp2_t s_fill = sel[TAIR_SEL_FILLER];

    const gold_fp2_t g_observe = add(s_obs, s_obsd);
    const gold_fp2_t g_sampling = add(s_smp, s_smpd);
    const gold_fp2_t g_op = add(g_observe, g_sampling);

    const gold_fp2_t lane = L[TAIR_LANE_OFF];
    const gold_fp2_t is_pow = L[TAIR_ISPOW_OFF];

    /* ══ A. Structural one-hots (transcript_air.c:114-157) ════════════════ */
    {
        gold_fp2_t sum = zero;
        for (size_t s = 0; s < TAIR_NUM_SEL; s++) {
            dnac_stark_folder_assert_bool(f, sel[s]);
            sum = add(sum, sel[s]);
        }
        dnac_stark_folder_assert_zero(f, sub(sum, one));
    }
    {
        gold_fp2_t isum = zero, osum = zero, psum = zero;
        for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) {
            dnac_stark_folder_assert_bool(f, il[k]);
            dnac_stark_folder_assert_bool(f, ol[k]);
            isum = add(isum, il[k]);
            osum = add(osum, ol[k]);
        }
        dnac_stark_folder_assert_zero(f, sub(isum, one));
        dnac_stark_folder_assert_zero(f, sub(osum, one));
        for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++) {
            dnac_stark_folder_assert_bool(f, pc[k]);
            psum = add(psum, pc[k]);
        }
        dnac_stark_folder_assert_zero(f, sub(psum, one));
    }
    /* A2 — input_len == RATE is unreachable as a row-entry state (:144-151). */
    dnac_stark_folder_when(f, g_op, il[TAIR_RATE]);
    /* A3 — is_pow: boolean, sampling rows only (:153-157). */
    dnac_stark_folder_assert_bool(f, is_pow);
    dnac_stark_folder_when(f, is_pow, sub(one, g_sampling));

    /* ══ B. Embedded poseidon2_air block — UNGATED (:159-164) ═════════════
     * The shipped shared emission source (poseidon2_fold.c), exactly as the
     * shipped inline precedent conf_action_fold.c:133-134 uses it. */
    dnac_poseidon2_fold_eval(f, (size_t)TAIR_PERM_OFF);

    /* ══ C. Boundary: trace row 0 MUST be sel_start (:166-167) ════════════ */
    dnac_stark_folder_when(f, f->is_first_row, sub(one, s_start));

    /* ══ D. Sampling rows: canonical bit exposure (:169-206) ══════════════ */
    {
        gold_fp2_t recomp = zero, weight = one;
        gold_fp2_t hi_ones = zero, low_sum = zero;
        for (size_t i = 0; i < TAIR_BITS; i++) {
            const gold_fp2_t b = L[tair_bit_off(i)];
            dnac_stark_folder_when(f, g_sampling, mul(b, sub(b, one))); /* :180 */
            recomp = add(recomp, mul(b, weight));
            weight = add(weight, weight);
            if (i < trailing) low_sum = add(low_sum, b);
            else hi_ones = add(hi_ones, b);
        }
        dnac_stark_folder_when(f, g_sampling, sub(recomp, lane)); /* :187 */

        const gold_fp2_t S = sub(fp2u((uint64_t)(64u - trailing)), hi_ones);
        const gold_fp2_t isz = L[TAIR_CANON_ISZ_OFF];
        const gold_fp2_t inv = L[TAIR_CANON_INV_OFF];
        dnac_stark_folder_when(f, g_sampling, mul(isz, sub(isz, one)));      /* :195 */
        dnac_stark_folder_when(f, g_sampling, sub(mul(S, inv), sub(one, isz))); /* :196 */
        dnac_stark_folder_when(f, g_sampling, mul(S, isz));                  /* :197 */
        dnac_stark_folder_when(f, g_sampling, mul(isz, low_sum));            /* :200 */

        /* PoW: the exposed low `pow_bits` of the challenge are zero (:204-205). */
        for (size_t i = 0; i < ST->pow_bits; i++)
            dnac_stark_folder_when(f, is_pow, L[tair_bit_off(i)]);
    }

    /* ══ E. DS-prefix, row-local half (:208-222) ══════════════════════════ */
    {
        const gold_fp2_t pre_active = sub(one, pc[4]);
        dnac_stark_folder_when(f, pre_active, sub(one, add(g_observe, s_start)));
        for (size_t k = 0; k < TAIR_RATE; k++)
            dnac_stark_folder_when(
                f, g_observe, mul(pc[k], sub(lane, fp2u(DNAC_DUPLEX_DS_PREFIX[k]))));
    }

    /* ══ T. Preprocessed-table conformance + payload binding (the fold image of
     * transcript_air.c block T — CT-1 / CT-2 / CT-3a / CT-3b / CT-4, in that
     * order, ROW-LOCAL so no `is_transition` factor applies). ═══════════════ */
    {
        for (size_t t = 0; t < TAIR_NUM_SEL; t++) /* CT-1 */
            dnac_stark_folder_assert_zero(f, sub(PL[tair_tbl_col_type(t)], sel[t]));

        dnac_stark_folder_assert_zero(f, sub(PL[TAIR_TBL_COL_IS_POW], is_pow)); /* CT-2 */

        {
            gold_fp2_t possum = zero, acc = zero;
            for (size_t k = 0; k < SC->n_ops; k++) {
                const gold_fp2_t p = PL[tair_tbl_col_pos(k)];
                possum = add(possum, p);
                acc = add(acc, mul(p, TFPUB(k)));
            }
            dnac_stark_folder_assert_zero(f, sub(possum, g_op)); /* CT-3a */
            dnac_stark_folder_assert_zero(f, sub(lane, acc));    /* CT-3b */
        }

        for (size_t k = 0; k < SC->n_ops; k++) { /* CT-4 */
            const size_t nb = SC->ops[k].num_bits;
            if (nb == 0) continue;
            const size_t boff = dnac_tair_op_bit_off(SC, k);
            if (boff == (size_t)-1) { /* unreachable under the bind gate */
                dnac_stark_folder_assert_zero(f, one);
                continue;
            }
            const gold_fp2_t g = PL[tair_tbl_col_pos(k)];
            for (size_t j = 0; j < nb; j++)
                dnac_stark_folder_when(f, g,
                                       sub(L[tair_bit_off(j)], TFPUB(boff + j)));
        }
    }

    /* ═══════════════════════════════════════════════════════════════════════
     * Everything below is the u64's post-`if (!next) return v;` half
     * (transcript_air.c:224). Each residual is multiplied by `is_transition`,
     * which is what makes "no transition constraints on the last row" true in
     * the fold form (spec §3.2).
     * ═══════════════════════════════════════════════════════════════════════ */

    gold_fp2_t nil_[TAIR_LEN_SLOTS], nol[TAIR_LEN_SLOTS], npc[TAIR_PREFIX_SLOTS];
    for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) {
        nil_[k] = N[tair_il_off(k)];
        nol[k] = N[tair_ol_off(k)];
    }
    for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++) npc[k] = N[tair_prefix_off(k)];

    /* ══ F. sel_start — instance boundary (:234-246) ══════════════════════ */
    for (size_t i = 0; i < TAIR_STATE_LANES; i++)
        dnac_stark_folder_when(f, tr, mul(s_start, N[tair_state_off(i)]));
    dnac_stark_folder_when(f, tr, mul(s_start, sub(one, nil_[0])));
    dnac_stark_folder_when(f, tr, mul(s_start, sub(one, nol[0])));
    dnac_stark_folder_when(f, tr, mul(s_start, sub(one, npc[0])));

    /* ══ G. DS-prefix counter threading (:248-258) ════════════════════════ */
    {
        for (size_t k = 0; k < TAIR_RATE; k++)
            dnac_stark_folder_when(f, tr,
                                   mul(g_observe, mul(pc[k], sub(one, npc[k + 1]))));
        dnac_stark_folder_when(f, tr, mul(g_observe, mul(pc[4], sub(one, npc[4]))));
        const gold_fp2_t g_copy = add(g_sampling, s_fill);
        for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++)
            dnac_stark_folder_when(f, tr, mul(g_copy, sub(npc[k], pc[k])));
    }

    /* ══ H. sel_obs — observe, input_len < 3 (:260-283) ═══════════════════ */
    {
        dnac_stark_folder_when(f, tr, mul(s_obs, il[3]));
        dnac_stark_folder_when(f, tr, mul(s_obs, sub(one, nol[0])));
        for (size_t j = 0; j < TAIR_RATE; j++) {
            const gold_fp2_t nb = N[tair_inbuf_off(j)];
            const gold_fp2_t b = L[tair_inbuf_off(j)];
            dnac_stark_folder_when(f, tr, mul(s_obs, mul(il[j], sub(nb, lane))));
            dnac_stark_folder_when(f, tr,
                                   mul(s_obs, mul(sub(one, il[j]), sub(nb, b))));
        }
        for (size_t j = 0; j < TAIR_RATE; j++)
            dnac_stark_folder_when(f, tr,
                                   mul(s_obs, mul(il[j], sub(one, nil_[j + 1]))));
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            dnac_stark_folder_when(
                f, tr, mul(s_obs, sub(N[tair_state_off(i)], L[tair_state_off(i)])));
    }

    /* ══ I. sel_obs_dup — 4th observe + eager duplex (:285-321) ═══════════ */
    {
        dnac_stark_folder_when(f, tr, mul(s_obsd, sub(one, il[3])));
        for (size_t j = 0; j < TAIR_RATE - 1; j++)
            dnac_stark_folder_when(
                f, tr,
                mul(s_obsd, sub(L[tair_perm_in_off(j)], L[tair_inbuf_off(j)])));
        dnac_stark_folder_when(
            f, tr, mul(s_obsd, sub(L[tair_perm_in_off(TAIR_RATE - 1)], lane)));
        dnac_stark_folder_when(
            f, tr,
            mul(s_obsd, sub(L[tair_perm_in_off(TAIR_RATE)],
                            add(L[tair_state_off(TAIR_RATE)],
                                fp2u((uint64_t)TAIR_RATE)))));
        for (size_t j = TAIR_RATE + 1; j < TAIR_STATE_LANES; j++)
            dnac_stark_folder_when(
                f, tr,
                mul(s_obsd, sub(L[tair_perm_in_off(j)], L[tair_state_off(j)])));
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            dnac_stark_folder_when(
                f, tr,
                mul(s_obsd, sub(N[tair_state_off(i)], L[tair_perm_out_off(i)])));
        for (size_t j = 0; j < TAIR_RATE - 1; j++)
            dnac_stark_folder_when(
                f, tr,
                mul(s_obsd, sub(N[tair_inbuf_off(j)], L[tair_inbuf_off(j)])));
        dnac_stark_folder_when(
            f, tr, mul(s_obsd, sub(N[tair_inbuf_off(TAIR_RATE - 1)], lane)));
        dnac_stark_folder_when(f, tr, mul(s_obsd, sub(one, nil_[0])));
        dnac_stark_folder_when(f, tr, mul(s_obsd, sub(one, nol[TAIR_RATE])));
    }

    /* ══ J. sel_sample — pop only (:323-349) ══════════════════════════════ */
    {
        dnac_stark_folder_when(f, tr, mul(s_smp, sub(one, il[0])));
        dnac_stark_folder_when(f, tr, mul(s_smp, ol[0]));
        for (size_t k = 1; k < TAIR_LEN_SLOTS; k++) {
            dnac_stark_folder_when(
                f, tr, mul(s_smp, mul(ol[k], sub(lane, L[tair_state_off(k - 1)]))));
            dnac_stark_folder_when(f, tr,
                                   mul(s_smp, mul(ol[k], sub(one, nol[k - 1]))));
        }
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            dnac_stark_folder_when(
                f, tr, mul(s_smp, sub(N[tair_state_off(i)], L[tair_state_off(i)])));
        for (size_t j = 0; j < TAIR_RATE; j++)
            dnac_stark_folder_when(
                f, tr, mul(s_smp, sub(N[tair_inbuf_off(j)], L[tair_inbuf_off(j)])));
        dnac_stark_folder_when(f, tr, mul(s_smp, sub(one, nil_[0])));
    }

    /* ══ K. sel_sample_dup — duplex then pop (:351-405) ═══════════════════ */
    {
        dnac_stark_folder_when(f, tr, mul(s_smpd, mul(il[0], sub(one, ol[0]))));

        for (size_t j = 0; j < TAIR_RATE; j++) {
            const gold_fp2_t pin = L[tair_perm_in_off(j)];
            dnac_stark_folder_when(
                f, tr, mul(s_smpd, mul(il[0], sub(pin, L[tair_state_off(j)]))));
            for (size_t k = 1; k < TAIR_RATE; k++) {
                if (j < k)
                    dnac_stark_folder_when(
                        f, tr,
                        mul(s_smpd, mul(il[k], sub(pin, L[tair_inbuf_off(j)]))));
                else
                    dnac_stark_folder_when(f, tr, mul(s_smpd, mul(il[k], pin)));
            }
        }
        {
            const gold_fp2_t cap_in = L[tair_perm_in_off(TAIR_RATE)];
            const gold_fp2_t cap = L[tair_state_off(TAIR_RATE)];
            dnac_stark_folder_when(f, tr, mul(s_smpd, mul(il[0], sub(cap_in, cap))));
            for (size_t k = 1; k < TAIR_RATE; k++)
                dnac_stark_folder_when(
                    f, tr,
                    mul(s_smpd, mul(il[k], sub(cap_in, add(cap, fp2u((uint64_t)k))))));
        }
        for (size_t j = TAIR_RATE + 1; j < TAIR_STATE_LANES; j++)
            dnac_stark_folder_when(
                f, tr,
                mul(s_smpd, sub(L[tair_perm_in_off(j)], L[tair_state_off(j)])));
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            dnac_stark_folder_when(
                f, tr,
                mul(s_smpd, sub(N[tair_state_off(i)], L[tair_perm_out_off(i)])));
        dnac_stark_folder_when(
            f, tr, mul(s_smpd, sub(lane, L[tair_perm_out_off(TAIR_RATE - 1)])));
        dnac_stark_folder_when(f, tr, mul(s_smpd, sub(one, nol[TAIR_RATE - 1])));
        dnac_stark_folder_when(f, tr, mul(s_smpd, sub(one, nil_[0])));
        for (size_t j = 0; j < TAIR_RATE; j++)
            dnac_stark_folder_when(
                f, tr, mul(s_smpd, sub(N[tair_inbuf_off(j)], L[tair_inbuf_off(j)])));
    }

    /* ══ L. sel_filler — inert and TERMINAL (:407-421) ════════════════════ */
    {
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            dnac_stark_folder_when(
                f, tr, mul(s_fill, sub(N[tair_state_off(i)], L[tair_state_off(i)])));
        for (size_t j = 0; j < TAIR_RATE; j++)
            dnac_stark_folder_when(
                f, tr, mul(s_fill, sub(N[tair_inbuf_off(j)], L[tair_inbuf_off(j)])));
        for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) {
            dnac_stark_folder_when(f, tr, mul(s_fill, sub(nil_[k], il[k])));
            dnac_stark_folder_when(f, tr, mul(s_fill, sub(nol[k], ol[k])));
        }
        dnac_stark_folder_when(
            f, tr, mul(s_fill, sub(one, N[tair_sel_off(TAIR_SEL_FILLER)])));
    }

    /* ══ M. TERMINALITY — the fold image of the trace-level gate at
     * transcript_air.c:444-460 (i3/A2-F1, the shipped HIGH). The final row gets
     * no transition constraints, so a trace ending in a SAMPLING row leaves the
     * popped challenge free; the u64 catches that in `eval_trace`, which a
     * row-AIR does not have. Carried here as an explicit boundary. Emitted LAST,
     * mirroring the u64 order (eval_row's steps, then the trace-level rule). ══ */
    dnac_stark_folder_when(f, f->is_last_row, sub(one, s_fill));

#undef TFPUB
}
