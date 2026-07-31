/**
 * @file fri_oi_air_fold.c
 * @brief Composition s1a — FRI reduced-opening accumulation (open_input) control
 *        AIR, verifier-fold (fp2) form.
 *
 * TRANSCRIPTION of `dnac_foi_eval_row` / `dnac_foi_eval_trace` (fri_oi_air.c).
 * Every block cites the `fri_oi_air.c` line it mirrors and keeps the
 * BUILDABLE-v3 C-label; the EMISSION ORDER is the u64 evaluator's order, which
 * is the contract (the alpha-fold is order-sensitive) and is what the count test
 * pins. See fri_oi_air_fold.h for the bind contract, the preserved A2 closures
 * (C2e ungated HOLD, C3f one-sided carry), the s1b entry duties, the degree
 * consequence of the is_transition factor and the shape rail.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_oi_air_fold.h"

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

/** Local alias for the header's sentinel (fri_oi_air.c:131-135). */
#define FOI_FOLD_NO_MAP DNAC_FOI_FOLD_NO_MAP

/* ═══════════════ binding — CALLER-OWNED state, no module static ═══════════
 * FLEET 034: `dnac_foi_fold_state_t` lives in the header and the caller owns
 * the storage; `air_eval` reads it back out of `folder->ctx`. Nothing about the
 * derivation moved. */

/**
 * Derive the snapshot for `cfg`. This is `foi_schedule` (fri_oi_air.c:104-188)
 * driven through the module's PUBLIC accessors and the SAME schedule authority
 * (`dnac_p2c_oi_table_row`), so the two cannot disagree about which configs are
 * acceptable or about what a scheduled step IS.
 *
 * ⚠ The three per-step MAPS (chain-bit, global acc index, lb per-batch
 * boundary) are not exposed by any public accessor, so the derivation rule is
 * transcribed here from fri_oi_air.c:137-187 — same authority, same rule. A
 * drift between the two would show up immediately as a fold-vs-u64 disagreement
 * (that is exactly what tests/test_fri_oi_air_fold.c compares).
 *
 * @return 1 on success, 0 on reject (fail-close).
 */
static int foi_fold_derive(const dnac_p2c_oi_table_cfg_t *cfg,
                           dnac_foi_fold_state_t *out) {
    if (cfg == NULL || out == NULL) return 0;
    /* Zero FIRST: every early return then leaves a fully-initialised (and
     * unbound) snapshot, so no caller can copy indeterminate bytes. The
     * per-step sentinel fill below overwrites the map arrays. */
    memset(out, 0, sizeof(*out));

    const size_t n_chain = dnac_p2c_oi_chain_rows(cfg); /* == lgmh, or 0     */
    const size_t rows = dnac_p2c_oi_table_rows(cfg);
    const size_t sched = dnac_p2c_oi_sched_rows(cfg);
    const size_t total_acc = dnac_foi_total_acc(cfg);
    const size_t num_cols = dnac_foi_num_cols(cfg);
    if (n_chain == 0 || rows == 0 || sched == 0 || num_cols == 0) return 0;
    if (sched > DNAC_P2C_OI_MAX_STEPS) return 0; /* fail-close rail          */
    if (cfg->num_heights == 0 || cfg->num_heights > DNAC_P2C_OI_MAX_HEIGHTS)
        return 0;

    const size_t pub_alpha = dnac_foi_pub_alpha_off(cfg);
    const size_t pub_zpz = dnac_foi_pub_zpz_off(cfg);
    const size_t pub_ro = dnac_foi_pub_ro_off(cfg);
    const size_t pub_px = dnac_foi_pub_px_off(cfg);
    const size_t num_publics = dnac_foi_num_publics(cfg);
    /* 0 from any of these is "the cfg was rejected" (fri_oi_air.h:220-234). */
    if (pub_alpha == 0 || pub_zpz == 0 || pub_ro == 0 || pub_px == 0 ||
        num_publics == 0)
        return 0;

    out->lgmh = cfg->lgmh;
    out->num_heights = cfg->num_heights;
    out->sched = sched;
    out->num_cols = num_cols;
    out->total_acc = total_acc;
    out->pub_alpha = pub_alpha;
    out->pub_zpz = pub_zpz;
    out->pub_ro = pub_ro;
    out->pub_px = pub_px;
    out->num_publics = num_publics;
    out->n_lb_zero = 0;

    for (size_t k = 0; k < DNAC_P2C_OI_MAX_STEPS; k++) {
        out->bit[k] = FOI_FOLD_NO_MAP;
        out->accidx[k] = FOI_FOLD_NO_MAP;
        out->lb_zero[k] = 0;
    }

    /* Walk the schedule authority and fill the per-step maps the prep cells do
     * NOT carry (fri_oi_air.c:137-187 verbatim). */
    size_t j_chain = 0;   /* chain-row ordinal                               */
    size_t a_global = 0;  /* global acc index across all groups              */
    size_t local_a = 0;   /* acc index within the current group              */
    size_t batch_sz = 0;  /* matrices*points*columns of the current group    */
    int    cur_is_lb = 0; /* current group is the lb (final) group           */
    for (size_t r = 0; r < sched; r++) {
        dnac_p2c_oi_row_t rec;
        if (dnac_p2c_oi_table_row(cfg, r, &rec) != DNAC_P2C_OI_TABLE_OK)
            return 0;
        if (rec.step != r) return 0; /* generator/this-file contract break   */

        switch (rec.type) {
        case DNAC_P2C_OI_ROW_CHAIN:
            /* chain row j consumes index bit lgmh-1-j (MSB-first). */
            if (j_chain >= out->lgmh) return 0;
            out->bit[r] = out->lgmh - 1 - j_chain;
            j_chain++;
            break;
        case DNAC_P2C_OI_ROW_ACC: {
            const size_t i = rec.h_index;
            if (i >= cfg->num_heights) return 0;
            if (rec.is_group_start) {
                local_a = 0;
                const dnac_p2c_oi_height_desc_t *d = &cfg->heights[i];
                batch_sz = d->num_matrices * d->num_points * d->num_columns;
                cur_is_lb = (d->log_height == cfg->log_blowup);
            }
            if (batch_sz == 0) return 0; /* fail-close rail                   */
            out->accidx[r] = a_global;
            /* per-batch lb-zero (C5): the incoming ro must be 0 at each batch
             * boundary of the lb group. a == 0 is covered by C3a. A height AT
             * lb is OPTIONAL (FLEET 029): without one `cur_is_lb` never turns
             * true and n_lb_zero stays 0, so no C5 step is emitted at all. */
            if (cur_is_lb && local_a > 0 && (local_a % batch_sz) == 0) {
                out->lb_zero[r] = 1;
                out->n_lb_zero++;
            }
            a_global++;
            local_a++;
            break;
        }
        case DNAC_P2C_OI_ROW_CAPTURE:
        case DNAC_P2C_OI_ROW_CLOSEOUT:
        case DNAC_P2C_OI_ROW_PAD:
        default:
            break;
        }
    }
    if (j_chain != out->lgmh) return 0;
    if (a_global != total_acc) return 0;

    out->bound = 1;
    return 1;
}

/* ══════════════════════════ public helpers ═══════════════════════════════ */

size_t dnac_foi_fold_num_constraints(const dnac_p2c_oi_table_cfg_t *cfg) {
    dnac_foi_fold_state_t s;
    if (!foi_fold_derive(cfg, &s)) return 0;
    /* 5 per height: C2c(1) + C3b(1) + C4a(2) + C2e(1).
     * Per acc row: C3c(4) + C3g(1, s2) == 5. */
    return FOI_FOLD_FIXED_STEPS + 5 * s.num_heights + s.lgmh +
           4 * s.total_acc + s.total_acc + FOI_EXT_LANES * s.n_lb_zero;
}

int dnac_foi_fold_bind(const dnac_p2c_oi_table_cfg_t *cfg,
                       dnac_foi_fold_state_t *state,
                       dnac_stark_air_t *out_air) {
    /* Fail-close: ANY rejected bind DISARMS the DESCRIPTOR (`out_air->ctx =
     * NULL`) as well as the state it was handed — see the same block in
     * fri_air_fold.c. Only the ARMING is cleared; the shape fields are the
     * caller's and are left untouched. */
    if (out_air != NULL) out_air->ctx = NULL;
    if (state != NULL) state->bound = 0;
    if (state == NULL || cfg == NULL || out_air == NULL)
        return DNAC_FOI_FOLD_ERR_PARAM;

    dnac_foi_fold_state_t s;
    if (!foi_fold_derive(cfg, &s)) return DNAC_FOI_FOLD_ERR_CFG;

    *state = s;

    out_air->main_width = s.num_cols;
    out_air->num_public_values = s.num_publics;
    out_air->main_next = 1;
    out_air->air_eval = dnac_foi_fold_air_eval;
    out_air->ctx = state;
    return DNAC_FOI_FOLD_OK;
}

/* ══════════════════════════ constraint evaluation ════════════════════════ */

/** assert_zero(is_transition * gate * x) — the §3.2 transition wrapper. */
static inline void when_t(dnac_stark_folder_t *f, gold_fp2_t tr, gold_fp2_t gate,
                          gold_fp2_t x) {
    dnac_stark_folder_when(f, mul2(tr, gate), x);
}

/** publics[i] promoted into fp2 (base-field constants in the fold expression). */
static inline gold_fp2_t pub2(const dnac_stark_folder_t *f, size_t i) {
    return gold_fp2_from_base(f->public_values[i]);
}

void dnac_foi_fold_air_eval(dnac_stark_folder_t *f) {
    const gold_fp2_t one = gold_fp2_one();

    /* ── SHAPE RAIL (fail-close; see the header). NOT the s1b publics duty.
     * `ctx == NULL` (no binding at all) joins the same gate — the exact
     * analogue of the retired `!g_foi.bound`. ───────────────────────────── */
    const dnac_foi_fold_state_t *const S =
        (const dnac_foi_fold_state_t *)f->ctx;
    if (S == NULL || !S->bound || f->main_width != S->num_cols ||
        f->num_public_values != S->num_publics ||
        f->public_values == NULL || f->trace_local == NULL ||
        f->trace_next == NULL || f->preprocessed_local == NULL ||
        f->preprocessed_next == NULL ||
        f->prep_width < (size_t)DNAC_P2C_OI_TABLE_COLS) {
        dnac_stark_folder_assert_zero(f, one);
        return;
    }

    const gold_fp2_t *L = f->trace_local;
    const gold_fp2_t *N = f->trace_next;
    const gold_fp2_t *P = f->preprocessed_local;
    const gold_fp2_t *PN = f->preprocessed_next;
    const gold_fp2_t tr = f->is_transition;
    const gold_fp2_t W = f2u(GOLDILOCKS_EXT_W);   /* fp2 = F[u]/(u^2 - W)    */
    const gold_fp2_t GEN = f2u(GOLDILOCKS_GENERATOR); /* coset shift 7 (C2c) */

    /* ══ main column reads (fri_oi_air.c:298-315) ═════════════════════════ */
    const gold_fp2_t b = L[FOI_COL_B];
    const gold_fp2_t g = L[FOI_COL_G];
    const gold_fp2_t y = L[FOI_COL_Y];
    const gold_fp2_t ap0 = L[FOI_COL_ALPHA_POW];
    const gold_fp2_t ap1 = L[FOI_COL_ALPHA_POW + 1];
    const gold_fp2_t ro0 = L[FOI_COL_RO];
    const gold_fp2_t ro1 = L[FOI_COL_RO + 1];
    const gold_fp2_t z0 = L[FOI_COL_Z];
    const gold_fp2_t z1 = L[FOI_COL_Z + 1];
    const gold_fp2_t pz0 = L[FOI_COL_PZ];
    const gold_fp2_t pz1 = L[FOI_COL_PZ + 1];
    const gold_fp2_t px = L[FOI_COL_PX];
    const gold_fp2_t x = L[FOI_COL_X];
    const gold_fp2_t q0 = L[FOI_COL_QUOT];
    const gold_fp2_t q1 = L[FOI_COL_QUOT + 1];
    const gold_fp2_t t0 = L[FOI_COL_T];
    const gold_fp2_t t1 = L[FOI_COL_T + 1];

    /* ══ prep cell reads — RAW (fri_oi_air.c:317-328) ═════════════════════ */
    const gold_fp2_t p_chain = P[DNAC_P2C_OI_COL_IS_CHAIN];
    const gold_fp2_t p_cap = P[DNAC_P2C_OI_COL_IS_CAPTURE];
    const gold_fp2_t p_acc = P[DNAC_P2C_OI_COL_IS_ACC];
    const gold_fp2_t p_close = P[DNAC_P2C_OI_COL_IS_CLOSEOUT];
    const gold_fp2_t p_pad = P[DNAC_P2C_OI_COL_IS_PAD];
    const gold_fp2_t p_sq = P[DNAC_P2C_OI_COL_IS_SQPAIR];
    const gold_fp2_t p_store = P[DNAC_P2C_OI_COL_IS_STORE];
    const gold_fp2_t p_gs = P[DNAC_P2C_OI_COL_IS_GROUP_START];
    const gold_fp2_t p_fc = P[DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT];
    const gold_fp2_t p_gpow = P[DNAC_P2C_OI_COL_G_POW2];
    /* seed selector = is_capture AND NOT sqpair AND NOT store (C2a). */
    const gold_fp2_t p_seed = sub2(sub2(p_cap, p_sq), p_store);

    /* ══ TERMINALITY (fri_oi_air.c:517-528) ═══════════════════════════════
     * The u64 form is a fail-close GATE in eval_trace, run BEFORE any per-row
     * constraint; a row-uniform AIR cannot see the trace height, so it becomes
     * an is_last_row boundary — one constraint per cell the u64 gate reads.
     * Without it every transition-anchored form is void on the final row. */
    dnac_stark_folder_when(f, f->is_last_row, sub2(p_pad, one));
    dnac_stark_folder_when(f, f->is_last_row, p_chain);
    dnac_stark_folder_when(f, f->is_last_row, p_cap);
    dnac_stark_folder_when(f, f->is_last_row, p_acc);
    dnac_stark_folder_when(f, f->is_last_row, p_close);

    /* ══ C1a — the x0 chain's ROW-0 BOUNDARY (fri_oi_air.c:330-335) ═══════
     * `g = 1 + b*(G_0 - 1)`: a MULTIPLY FROM 1. The u64 evaluator applies it
     * under its `is_first_row` PARAMETER; here it is the COMPOSED system's own
     * row-0 selector — that wiring IS OBL-P2c-3. */
    dnac_stark_folder_when(f, f->is_first_row,
                           sub2(g, add2(one, mul2(b, sub2(p_gpow, one)))));

    /* ══ C1c-b — bit booleanity on chain rows (fri_oi_air.c:337-339) ══════ */
    dnac_stark_folder_when(f, p_chain, mul2(b, sub2(b, one)));

    /* ══ C2a — capture SEED anchor: y == g (fri_oi_air.c:341-344) ═════════ */
    dnac_stark_folder_when(f, p_seed, sub2(y, g));

    /* ══ C2c — capture STORE: x_reg[h] == 7*y (fri_oi_air.c:346-354) ══════ */
    for (size_t i = 0; i < S->num_heights; i++) {
        const gold_fp2_t hs = P[dnac_p2c_oi_col_hsel(i)];
        const gold_fp2_t xr = L[dnac_foi_col_xreg(i)];
        dnac_stark_folder_when(f, mul2(p_store, hs), sub2(xr, mul2(GEN, y)));
    }

    /* ══ C3a — accumulation GROUP START, ROW-LOCAL (fri_oi_air.c:356-361) ══
     * alpha_pow == 1 (fp2 (1,0)), ro == 0. */
    dnac_stark_folder_when(f, p_gs, sub2(ap0, one));
    dnac_stark_folder_when(f, p_gs, ap1);
    dnac_stark_folder_when(f, p_gs, ro0);
    dnac_stark_folder_when(f, p_gs, ro1);

    /* ══ C3b — x binding: x == x_reg[h(row)] (fri_oi_air.c:363-368) ═══════ */
    for (size_t i = 0; i < S->num_heights; i++) {
        const gold_fp2_t hs = P[dnac_p2c_oi_col_hsel(i)];
        const gold_fp2_t xr = L[dnac_foi_col_xreg(i)];
        dnac_stark_folder_when(f, mul2(p_acc, hs), sub2(x, xr));
    }

    /* ══ C3d — quotient: (z - x)*quot = 1 (fri_oi_air.c:370-377) ══════════
     * z fp2, x base (c0 only). z == x is UNSAT (denominator zero). */
    {
        const gold_fp2_t a0 = sub2(z0, x); /* (z - x).c0 */
        dnac_stark_folder_when(
            f, p_acc, sub2(add2(mul2(a0, q0), mul2(W, mul2(z1, q1))), one));
        dnac_stark_folder_when(f, p_acc, add2(mul2(a0, q1), mul2(z1, q0)));
    }

    /* ══ C3e — degree relief t = alpha_pow*(p_z - p_x) (fri_oi_air.c:379-385)
     * p_x is base -> enters the c0 lane only. ROW-LOCAL. */
    {
        const gold_fp2_t d0 = sub2(pz0, px); /* (p_z - p_x).c0 */
        dnac_stark_folder_when(
            f, p_acc, sub2(t0, add2(mul2(ap0, d0), mul2(W, mul2(ap1, pz1)))));
        dnac_stark_folder_when(f, p_acc,
                               sub2(t1, add2(mul2(ap0, pz1), mul2(ap1, d0))));
    }

    /* ══ C1c-p / C3c / C3g / C5 — the pos-gated publics + lb-zero forms
     * (fri_oi_air.c:387-421). `pos` is PREPROCESSED (a degree-1 selector), so
     * exactly one term per row survives; the loop stops at `sched` because
     * padding steps carry pos == 0 (generator obligation under PIN-1-OI). */
    for (size_t k = 0; k < S->sched; k++) {
        const gold_fp2_t pk = P[dnac_p2c_oi_col_pos(k)];

        /* C1c public binding: chain step k reads index bit bit[k]. */
        if (S->bit[k] != FOI_FOLD_NO_MAP) {
            dnac_stark_folder_when(
                f, pk, sub2(b, pub2(f, FOI_PUB_BITS_OFF + S->bit[k])));
        }

        /* C3c z / p_z binding, then C3g's p_x binding — SAME ORDER as the u64
         * evaluator emits them (z0, z1, pz0, pz1, px), inside the same pos gate.
         * The order is the contract: the alpha-fold is order-sensitive and the
         * count test pins it. C3g is row-local, so no is_transition factor. */
        if (S->accidx[k] != FOI_FOLD_NO_MAP) {
            const size_t zo = S->pub_zpz + 4 * S->accidx[k];
            dnac_stark_folder_when(f, pk, sub2(z0, pub2(f, zo)));
            dnac_stark_folder_when(f, pk, sub2(z1, pub2(f, zo + 1)));
            dnac_stark_folder_when(f, pk, sub2(pz0, pub2(f, zo + 2)));
            dnac_stark_folder_when(f, pk, sub2(pz1, pub2(f, zo + 3)));
            dnac_stark_folder_when(
                f, pk, sub2(px, pub2(f, S->pub_px + S->accidx[k])));
        }

        /* C5 per-batch lb-zero: incoming ro == 0 at each lb batch boundary. */
        if (S->lb_zero[k]) {
            dnac_stark_folder_when(f, pk, ro0);
            dnac_stark_folder_when(f, pk, ro1);
        }
    }

    /* ══ C4a — CLOSEOUT ro export (fri_oi_air.c:415-423) ══════════════════ */
    for (size_t i = 0; i < S->num_heights; i++) {
        const gold_fp2_t hs = P[dnac_p2c_oi_col_hsel(i)];
        const size_t ao = S->pub_ro + FOI_EXT_LANES * i;
        dnac_stark_folder_when(f, mul2(p_close, hs), sub2(ro0, pub2(f, ao)));
        dnac_stark_folder_when(f, mul2(p_close, hs), sub2(ro1, pub2(f, ao + 1)));
    }

    /* ══ C4b — FINAL closeout (h == lb): ro == 0 ══════════════════════════
     * Gated by the `p_fc` prep cell, so — exactly as in the u64 form — this is
     * CONDITIONAL on the cfg having a height AT lb and VACUOUS when it has none
     * (FLEET 029; the native condition, fri_verifier.c:482-487). */
    dnac_stark_folder_when(f, p_fc, ro0);
    dnac_stark_folder_when(f, p_fc, ro1);

    /* ══════════════ transitions (fri_oi_air.c:432-500) ═══════════════════
     * The u64 evaluator RETURNS before this block when there is no next row
     * (fri_oi_air.c:432); in fold form the same restriction is the explicit
     * `is_transition` factor (§3.2). */
    const gold_fp2_t nb = N[FOI_COL_B];
    const gold_fp2_t ng = N[FOI_COL_G];
    const gold_fp2_t ngb = N[FOI_COL_GB];
    const gold_fp2_t ny = N[FOI_COL_Y];
    const gold_fp2_t nap0 = N[FOI_COL_ALPHA_POW];
    const gold_fp2_t nap1 = N[FOI_COL_ALPHA_POW + 1];
    const gold_fp2_t nro0 = N[FOI_COL_RO];
    const gold_fp2_t nro1 = N[FOI_COL_RO + 1];
    const gold_fp2_t pn_chain = PN[DNAC_P2C_OI_COL_IS_CHAIN];
    const gold_fp2_t pn_cap = PN[DNAC_P2C_OI_COL_IS_CAPTURE];
    const gold_fp2_t pn_sq = PN[DNAC_P2C_OI_COL_IS_SQPAIR];
    const gold_fp2_t pn_store = PN[DNAC_P2C_OI_COL_IS_STORE];
    const gold_fp2_t pn_gpow = PN[DNAC_P2C_OI_COL_G_POW2];

    /* ══ C1b — chain transition, gated by NEXT row is_chain
     * (fri_oi_air.c:448-455):
     *     gb' = g * b'                    (degree relief)
     *     g'  = g + gb'*(G' - 1)
     * G' is the next row's g_pow2 — the read that makes prep_next mandatory. */
    when_t(f, tr, pn_chain, sub2(ngb, mul2(g, nb)));
    when_t(f, tr, pn_chain, sub2(ng, add2(g, mul2(ngb, sub2(pn_gpow, one)))));

    /* ══ C2b — capture squaring + store copy (fri_oi_air.c:457-461) ═══════ */
    when_t(f, tr, pn_sq, sub2(ny, mul2(y, y)));
    when_t(f, tr, pn_store, sub2(ny, y));

    /* ══ C2d — chain-resume across the capture block (fri_oi_air.c:463-467) */
    when_t(f, tr, pn_cap, sub2(ng, g));

    /* ══ C2e — register HOLD, UNGATED BY ROW TYPE (fri_oi_air.c:469-477) ══
     * ⚠ The is_transition factor is the mechanical §3.2 wrapper, NOT a row-type
     * gate: x_reg[i] is still held on EVERY transition, so it stays globally
     * constant and pinned by its single C2c write. Weakening this to the spec's
     * store-row-exempt form reopens the A2-F2 write-key/read-key hole (N-F2). */
    for (size_t i = 0; i < S->num_heights; i++) {
        const gold_fp2_t xr = L[dnac_foi_col_xreg(i)];
        const gold_fp2_t nxr = N[dnac_foi_col_xreg(i)];
        dnac_stark_folder_when(f, tr, sub2(nxr, xr));
    }

    /* ══ C3f — the ONE-SIDED carry (fri_oi_air.c:479-500) ═════════════════
     * ⚠ Gated on the CURRENT row's is_acc (NOT this-AND-next): it fires on the
     * last-acc -> closeout transition, so the closeout's ro IS the group's final
     * accumulation (A2-F1 / N-F1), and it is OFF on closeout -> next group
     * start, so C3a's reset is unconflicted.
     *   ro'        = ro + t*quot
     *   alpha_pow' = alpha_pow * alpha   (alpha from publics) */
    {
        /* t * quot (fp2). */
        const gold_fp2_t tq0 = add2(mul2(t0, q0), mul2(W, mul2(t1, q1)));
        const gold_fp2_t tq1 = add2(mul2(t0, q1), mul2(t1, q0));
        when_t(f, tr, p_acc, sub2(nro0, add2(ro0, tq0)));
        when_t(f, tr, p_acc, sub2(nro1, add2(ro1, tq1)));

        /* alpha_pow * alpha (fp2), alpha public. */
        const gold_fp2_t al0 = pub2(f, S->pub_alpha);
        const gold_fp2_t al1 = pub2(f, S->pub_alpha + 1);
        const gold_fp2_t ma0 = add2(mul2(ap0, al0), mul2(W, mul2(ap1, al1)));
        const gold_fp2_t ma1 = add2(mul2(ap0, al1), mul2(ap1, al0));
        when_t(f, tr, p_acc, sub2(nap0, ma0));
        when_t(f, tr, p_acc, sub2(nap1, ma1));
    }
}
