/**
 * @file fri_air_fold.c
 * @brief Composition s1a — FRI fold-walk control AIR, verifier-fold (fp2) form.
 *
 * TRANSCRIPTION of `dnac_fair_eval_row` / `dnac_fair_eval_trace` (fri_air.c).
 * Every block below cites the `fri_air.c` line it mirrors and keeps the design
 * §0.5 form label; the EMISSION ORDER is the u64 evaluator's order, which is
 * the contract (the alpha-fold is order-sensitive) and is what the count test
 * pins. See fri_air_fold.h for the bind contract, the s1b entry duties, the
 * degree consequence of the is_transition factor and the shape rail.
 *
 * NOTHING here re-derives the schedule: the row counts, the public-region
 * offsets and the roll-in ranks come from the SAME authorities the u64
 * evaluator uses (fri_air_table.c's generator + fri_air.c's public helpers),
 * read once at bind time.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_air_fold.h"

#include <string.h>

#include "field_goldilocks.h"

/* ── fp2 shorthands (the conf_*_fold.c idiom) ─────────────────────────────── */
static inline gold_fp2_t f2u(uint64_t v) {
    return gold_fp2_from_base(gold_fp_from_u64(v));
}
static inline gold_fp2_t add2(gold_fp2_t a, gold_fp2_t b) {
    return gold_fp2_add(a, b);
}
static inline gold_fp2_t sub2(gold_fp2_t a, gold_fp2_t b) {
    return gold_fp2_sub(a, b);
}
static inline gold_fp2_t mul2(gold_fp2_t a, gold_fp2_t b) {
    return gold_fp2_mul(a, b);
}

/** Local alias for the header's sentinel (fri_air.c:87's FAIR_NO_ROLLIN). */
#define FAIR_FOLD_NO_ROLLIN DNAC_FAIR_FOLD_NO_ROLLIN

/* ═══════════════ binding — CALLER-OWNED state, no module static ═══════════
 * FLEET 034: `dnac_fair_fold_state_t` lives in the header and the caller owns
 * the storage; `air_eval` reads it back out of `folder->ctx`. Nothing about the
 * derivation moved. */

/**
 * Derive the snapshot for `cfg`. Mirrors `fair_schedule` (fri_air.c:124-169)
 * through the module's PUBLIC accessors, so the two cannot disagree about which
 * configs are acceptable: each accessor returns 0 for a cfg the table module
 * rejects (gates G1/G2/G3/G7 live in `p2c_cfg_check`, fri_air_table.c:47-102).
 *
 * @return 1 on success, 0 on reject (fail-close; `out` is left indeterminate).
 */
static int fair_fold_derive(const dnac_p2c_table_cfg_t *cfg,
                            dnac_fair_fold_state_t *out) {
    if (cfg == NULL || out == NULL) return 0;
    /* Zero FIRST: every early return then leaves a fully-initialised (and
     * unbound) snapshot, so no caller can copy indeterminate bytes. */
    memset(out, 0, sizeof(*out));

    const size_t n_chain = dnac_p2c_chain_rows(cfg);
    const size_t n_fold = dnac_p2c_fold_rows(cfg);
    const size_t rows = dnac_p2c_table_rows(cfg);
    if (n_chain == 0 || n_fold == 0 || rows == 0) return 0;

    /* Capacity of `rollin_rank` (fri_air.c:134-137). */
    if (n_fold > DNAC_P2C_MAX_LGMH) return 0;
    /* A padding row MUST exist: C5 lives on it and the last fold row's C4l
     * needs a successor (fri_air.c:141-142). */
    if (n_chain + n_fold >= rows) return 0;

    const size_t pub_beta = dnac_fair_pub_beta_off(cfg);
    const size_t pub_finit = dnac_fair_pub_finit_off(cfg);
    const size_t pub_ro = dnac_fair_pub_ro_off(cfg);
    const size_t pub_final = dnac_fair_pub_final_off(cfg);
    const size_t num_publics = dnac_fair_num_publics(cfg);
    /* 0 from any of these is "the cfg was rejected" (fri_air.h:329-334). */
    if (pub_beta == 0 || pub_finit == 0 || pub_ro == 0 || pub_final == 0 ||
        num_publics == 0)
        return 0;

    /* Roll-in placement, read back out of the schedule authority. */
    size_t rank = 0;
    for (size_t r = 0; r < n_fold; r++) {
        dnac_p2c_row_t rec;
        if (dnac_p2c_table_row(cfg, n_chain + r, &rec) != DNAC_P2C_TABLE_OK)
            return 0;
        /* A generator/this-file disagreement is a contract break, not something
         * to guess through (fri_air.c:150-152). */
        if (rec.type != DNAC_P2C_ROW_FOLD || rec.type_step != r) return 0;
        out->rollin_rank[r] = rec.is_rollin ? rank++ : FAIR_FOLD_NO_ROLLIN;
    }
    if (rank != cfg->num_rollin) return 0;

    out->bound = 1;
    out->lgmh = cfg->lgmh;
    out->n_chain = n_chain;
    out->n_fold = n_fold;
    out->sched = n_chain + n_fold;
    out->pub_beta = pub_beta;
    out->pub_finit = pub_finit;
    out->pub_ro = pub_ro;
    out->pub_final = pub_final;
    out->num_publics = num_publics;
    out->num_rollin = cfg->num_rollin;
    return 1;
}

/* ══════════════════════════ public helpers ═══════════════════════════════ */

size_t dnac_fair_fold_num_constraints(const dnac_p2c_table_cfg_t *cfg) {
    dnac_fair_fold_state_t s;
    if (!fair_fold_derive(cfg, &s)) return 0;
    return FAIR_FOLD_FIXED_STEPS + s.sched + FAIR_EXT_LANES * s.n_fold +
           FAIR_EXT_LANES * s.num_rollin;
}

int dnac_fair_fold_bind(const dnac_p2c_table_cfg_t *cfg,
                        dnac_fair_fold_state_t *state,
                        dnac_stark_air_t *out_air) {
    /* Fail-close: ANY rejected bind DISARMS the DESCRIPTOR (`out_air->ctx =
     * NULL`) as well as the state it was handed, so a caller that ignores the
     * return code cannot silently keep evaluating the OLD cfg's constraint
     * system (FLEET 027 verifier-B H1). Disarming only the state misses the
     * case where `out_air` was armed by a PREVIOUS bind onto a DIFFERENT state.
     * Only the ARMING is cleared; the shape fields are the caller's. */
    if (out_air != NULL) out_air->ctx = NULL;
    if (state != NULL) state->bound = 0;
    if (state == NULL || cfg == NULL || out_air == NULL)
        return DNAC_FAIR_FOLD_ERR_PARAM;

    dnac_fair_fold_state_t s;
    if (!fair_fold_derive(cfg, &s)) return DNAC_FAIR_FOLD_ERR_CFG;

    *state = s;

    out_air->main_width = FAIR_NUM_COLS;
    out_air->num_public_values = s.num_publics;
    out_air->main_next = 1;
    out_air->air_eval = dnac_fair_fold_air_eval;
    out_air->ctx = state;
    return DNAC_FAIR_FOLD_OK;
}

/* ══════════════════════════ constraint evaluation ════════════════════════ */

/** assert_zero(is_transition * gate * x) — the §3.2 transition wrapper. */
static inline void when_t(dnac_stark_folder_t *f, gold_fp2_t tr, gold_fp2_t gate,
                          gold_fp2_t x) {
    dnac_stark_folder_when(f, mul2(tr, gate), x);
}

void dnac_fair_fold_air_eval(dnac_stark_folder_t *f) {
    const gold_fp2_t one = gold_fp2_one();

    /* ── SHAPE RAIL (fail-close; see the header) ───────────────────────────
     * `air_eval` has no error channel, so an out-of-contract window emits ONE
     * unsatisfiable constraint instead of reading out of bounds. `ctx == NULL`
     * (no binding at all) joins the same gate — the exact analogue of the
     * retired `!g_fair.bound`. Note this is NOT the s1b G6 duty: it is a bound
     * check, not publics canonicality. */
    const dnac_fair_fold_state_t *const S =
        (const dnac_fair_fold_state_t *)f->ctx;
    if (S == NULL || !S->bound || f->main_width != FAIR_NUM_COLS ||
        f->num_public_values != S->num_publics ||
        f->public_values == NULL || f->trace_local == NULL ||
        f->trace_next == NULL || f->preprocessed_local == NULL ||
        f->preprocessed_next == NULL ||
        f->prep_width < (size_t)DNAC_P2C_TABLE_COLS) {
        dnac_stark_folder_assert_zero(f, one);
        return;
    }

    const gold_fp2_t *L = f->trace_local;
    const gold_fp2_t *N = f->trace_next;
    const gold_fp2_t *P = f->preprocessed_local;
    const gold_fp2_t *PN = f->preprocessed_next;
    const gold_fp2_t tr = f->is_transition;

    /* ══ Column reads (fri_air.c:298-317) ═════════════════════════════════ */
    const gold_fp2_t b = L[FAIR_COL_B];
    const gold_fp2_t g = L[FAIR_COL_G];
    const gold_fp2_t g_sq = L[FAIR_COL_G_SQ];
    const gold_fp2_t inv = L[FAIR_COL_INV];
    const gold_fp2_t f0 = L[FAIR_COL_F];
    const gold_fp2_t f1 = L[FAIR_COL_F + 1];
    const gold_fp2_t s0 = L[FAIR_COL_S];
    const gold_fp2_t s1 = L[FAIR_COL_S + 1];
    const gold_fp2_t be0 = L[FAIR_COL_BETA];
    const gold_fp2_t be1 = L[FAIR_COL_BETA + 1];
    const gold_fp2_t bs0 = L[FAIR_COL_BETA_SQ];
    const gold_fp2_t bs1 = L[FAIR_COL_BETA_SQ + 1];
    const gold_fp2_t t10 = L[FAIR_COL_T1];
    const gold_fp2_t t11 = L[FAIR_COL_T1 + 1];
    const gold_fp2_t t20 = L[FAIR_COL_T2];
    const gold_fp2_t t21 = L[FAIR_COL_T2 + 1];
    const gold_fp2_t rt0 = L[FAIR_COL_RTERM];
    const gold_fp2_t rt1 = L[FAIR_COL_RTERM + 1];
    const gold_fp2_t ro0 = L[FAIR_COL_RO];
    const gold_fp2_t ro1 = L[FAIR_COL_RO + 1];

    /* ══ Preprocessed reads — RAW, exactly as fri_air.c:319-326 reads them
     * (booleanity/one-hotness is the generator's obligation under PIN-1-P2c). */
    const gold_fp2_t p_chain = P[DNAC_P2C_COL_IS_CHAIN];
    const gold_fp2_t p_fold = P[DNAC_P2C_COL_IS_FOLD];
    const gold_fp2_t p_pad = P[DNAC_P2C_COL_IS_PAD];
    const gold_fp2_t p_cpair = P[DNAC_P2C_COL_IS_CHAINPAIR];
    const gold_fp2_t p_hand = P[DNAC_P2C_COL_IS_HANDOFF];
    const gold_fp2_t p_fpair = P[DNAC_P2C_COL_IS_FOLDPAIR];
    const gold_fp2_t p_term = P[DNAC_P2C_COL_IS_TERMINAL];
    const gold_fp2_t p_roll = P[DNAC_P2C_COL_IS_ROLLIN];
    const gold_fp2_t p_gpow = P[DNAC_P2C_COL_G_POW2];
    /* TYPED == chain or fold; padding rows carry no main-trace constraint
     * (C6, fri_air.c:327-331). */
    const gold_fp2_t typed = add2(p_chain, p_fold);
    /* W = 7 = GOLDILOCKS_EXT_W — fp2 = F[u]/(u^2 - W) (fri_air.c:332-334). */
    const gold_fp2_t W = f2u(GOLDILOCKS_EXT_W);

    /* ══ G4b TERMINALITY (fri_air.c:572-590) ══════════════════════════════
     * The u64 form is a fail-close GATE in eval_trace, evaluated BEFORE any
     * per-row constraint; a row-uniform AIR cannot see the trace height, so it
     * becomes an is_last_row boundary — one constraint per cell the u64 gate
     * reads. Emitted first, matching the u64 order. */
    dnac_stark_folder_when(f, f->is_last_row, sub2(p_pad, one));
    dnac_stark_folder_when(f, f->is_last_row, p_chain);
    dnac_stark_folder_when(f, f->is_last_row, p_fold);

    /* ══ C2a — bit booleanity (fri_air.c:336-342) ═════════════════════════ */
    dnac_stark_folder_when(f, typed, mul2(b, sub2(b, one)));

    /* ══ C2b — bit <-> public binding, gated by the step one-hot
     * (fri_air.c:344-362). Chain row j reads public bit lgmh-1-j (MSB-first),
     * fold row r reads bit r (LSB-first); the overlap is read TWICE, which is
     * what forces chain and walk onto ONE index. */
    for (size_t k = 0; k < S->sched; k++) {
        const size_t bit =
            (k < S->n_chain) ? (S->lgmh - 1 - k) : (k - S->n_chain);
        dnac_stark_folder_when(
            f, P[dnac_p2c_col_pos(k)],
            sub2(b, gold_fp2_from_base(f->public_values[FAIR_PUB_BITS_OFF + bit])));
    }

    /* ══ C3a — the x0 chain's ROW-0 BOUNDARY (fri_air.c:364-380) ══════════
     * `g = 1 + b*(G_0 - 1)`: a MULTIPLY FROM 1 (the FLEET 020 A2-F4 fix). The
     * u64 evaluator applies it under its `is_first_row` PARAMETER; here it is
     * the COMPOSED system's own row-0 selector — that wiring IS OBL-P2c-3
     * (fri_air.h:132-139). Dropping it frees g[0] and with it the whole chain. */
    dnac_stark_folder_when(f, f->is_first_row,
                           sub2(g, add2(one, mul2(b, sub2(p_gpow, one)))));

    /* ══ C4a — the div form: g * inv = -1/2 (fri_air.c:382-388) ═══════════ */
    dnac_stark_folder_when(f, p_fold, sub2(mul2(g, inv), f2u(FAIR_NEG_HALF)));

    /* ══ C4b — g_sq = g*g (fri_air.c:390-391) ═════════════════════════════ */
    dnac_stark_folder_when(f, p_fold, sub2(g_sq, mul2(g, g)));

    /* ══ C4c — t1 = (1 - 2b) * (s - f), lanewise (fri_air.c:393-407) ══════
     * ⚠ SIGN: (1 - 2b), NOT (2b - 1) — the FLEET 020 A2-F1 CRITICAL. The
     * flipped sign folds at the REFLECTED challenge 2*x0 - beta. */
    {
        const gold_fp2_t one_m_2b = sub2(one, add2(b, b));
        dnac_stark_folder_when(f, p_fold,
                               sub2(t10, mul2(one_m_2b, sub2(s0, f0))));
        dnac_stark_folder_when(f, p_fold,
                               sub2(t11, mul2(one_m_2b, sub2(s1, f1))));
    }

    /* ══ C4d — t2 = (beta - x0) * t1, the WRITTEN two-lane form
     * (fri_air.c:409-422). x0 (column g) is the one BASE-field actor and enters
     * the c0 lane only. */
    {
        const gold_fp2_t a0 = sub2(be0, g); /* (beta - x0).c0 */
        dnac_stark_folder_when(
            f, p_fold, sub2(t20, add2(mul2(a0, t10), mul2(W, mul2(be1, t11)))));
        dnac_stark_folder_when(f, p_fold,
                               sub2(t21, add2(mul2(a0, t11), mul2(be1, t10))));
    }

    /* ══ C4e — beta_sq = beta * beta (fri_air.c:424-429) ══════════════════ */
    dnac_stark_folder_when(
        f, p_fold, sub2(bs0, add2(mul2(be0, be0), mul2(W, mul2(be1, be1)))));
    dnac_stark_folder_when(f, p_fold,
                           sub2(bs1, add2(mul2(be0, be1), mul2(be1, be0))));

    /* ══ C4f — rterm = beta_sq * ro (fri_air.c:431-435) ═══════════════════ */
    dnac_stark_folder_when(
        f, p_fold, sub2(rt0, add2(mul2(bs0, ro0), mul2(W, mul2(bs1, ro1)))));
    dnac_stark_folder_when(f, p_fold,
                           sub2(rt1, add2(mul2(bs0, ro1), mul2(bs1, ro0))));

    /* ══ C4g / C4h — beta and roll-in <-> publics (fri_air.c:437-460) ═════
     * Fold row r takes beta pair r (transcript order) and, iff the cfg pins a
     * roll-in at its post-fold height, roll-in slot `rank` (the descending-list
     * rank == the native's monotone consumption order). */
    for (size_t r = 0; r < S->n_fold; r++) {
        const gold_fp2_t pk = P[dnac_p2c_col_pos(S->n_chain + r)];
        const size_t bo = S->pub_beta + FAIR_EXT_LANES * r;
        dnac_stark_folder_when(
            f, pk, sub2(be0, gold_fp2_from_base(f->public_values[bo])));
        dnac_stark_folder_when(
            f, pk, sub2(be1, gold_fp2_from_base(f->public_values[bo + 1])));
        if (S->rollin_rank[r] != FAIR_FOLD_NO_ROLLIN) {
            const size_t ao =
                S->pub_ro + FAIR_EXT_LANES * S->rollin_rank[r];
            dnac_stark_folder_when(
                f, pk, sub2(ro0, gold_fp2_from_base(f->public_values[ao])));
            dnac_stark_folder_when(
                f, pk, sub2(ro1, gold_fp2_from_base(f->public_values[ao + 1])));
        }
    }

    /* ══ C4i — ro == 0 on every NON-roll-in fold row (fri_air.c:462-471) ══
     * `is_fold - is_rollin` is a degree-1 linear combination, never a product. */
    {
        const gold_fp2_t not_roll = sub2(p_fold, p_roll);
        dnac_stark_folder_when(f, not_roll, ro0);
        dnac_stark_folder_when(f, not_roll, ro1);
    }

    /* ══ C5 — TERMINAL boundary: f == final_poly[0] (fri_air.c:473-485) ═══ */
    dnac_stark_folder_when(
        f, p_term,
        sub2(f0, gold_fp2_from_base(f->public_values[S->pub_final])));
    dnac_stark_folder_when(
        f, p_term,
        sub2(f1, gold_fp2_from_base(f->public_values[S->pub_final + 1])));

    /* ══════════════ transitions (fri_air.c:487-555) ══════════════════════
     * The u64 evaluator RETURNS before this block when there is no next row
     * (fri_air.c:487); in fold form the same restriction is the explicit
     * `is_transition` factor (§3.2) — load-bearing here, because G4b only pins
     * the last row's is_pad / is_chain / is_fold, NOT its pair gates, so a
     * table with is_handoff set on the final row would otherwise wrap the
     * transition onto row 0 of the cyclic domain. */
    const gold_fp2_t nb = N[FAIR_COL_B];
    const gold_fp2_t ng = N[FAIR_COL_G];
    const gold_fp2_t ngb = N[FAIR_COL_GB];
    const gold_fp2_t nf0 = N[FAIR_COL_F];
    const gold_fp2_t nf1 = N[FAIR_COL_F + 1];
    const gold_fp2_t pn_gpow = PN[DNAC_P2C_COL_G_POW2];

    /* ══ C3b / C3c — chain transition (fri_air.c:496-504) ═════════════════
     *     gb' = g * b'                     (degree relief)
     *     g'  = g + gb' * (G_{j+1} - 1)
     * G_{j+1} is the NEXT row's preprocessed literal — this read is why PIN-2
     * (`prep_next = 1`) is mandatory. */
    when_t(f, tr, p_cpair, sub2(ngb, mul2(g, nb)));
    when_t(f, tr, p_cpair, sub2(ng, add2(g, mul2(ngb, sub2(pn_gpow, one)))));

    /* ══ C3d — HANDOFF: chain -> fold row 0 is a COPY (fri_air.c:506-512) ═ */
    when_t(f, tr, p_hand, sub2(ng, g));

    /* ══ C4j — FOLD-ROW-0 BOUNDARY: f' == publics[f_init] (fri_air.c:514-523)
     * Closes FLEET 020 A2-F2: without it the walk's starting value is FREE. */
    when_t(f, tr, p_hand,
           sub2(nf0, gold_fp2_from_base(f->public_values[S->pub_finit])));
    when_t(f, tr, p_hand,
           sub2(nf1, gold_fp2_from_base(f->public_values[S->pub_finit + 1])));

    /* ══ C4k — x0 RECURRENCE, fold -> fold ONLY (fri_air.c:525-536) ═══════
     *     x_{i+1} = x_i^2 * (1 - 2*b_{i+1}) */
    when_t(f, tr, p_fpair, sub2(ng, mul2(g_sq, sub2(one, add2(nb, nb)))));

    /* ══ C4l — the FOLD TRANSITION (fri_air.c:538-555) ════════════════════
     *     f' = f + b*(s - f) + t2*inv + rterm
     * ⚠ GATING IS LOAD-BEARING (FLEET 020 A2-F3): is_fold LOCAL, not
     * is_foldpair — including the last fold row, whose successor is the first
     * PADDING row, which is what delivers the final value onto the row C5 reads. */
    {
        const gold_fp2_t e0_0 = add2(f0, mul2(b, sub2(s0, f0)));
        const gold_fp2_t e0_1 = add2(f1, mul2(b, sub2(s1, f1)));
        when_t(f, tr, p_fold, sub2(nf0, add2(add2(e0_0, mul2(t20, inv)), rt0)));
        when_t(f, tr, p_fold, sub2(nf1, add2(add2(e0_1, mul2(t21, inv)), rt1)));
    }
}
