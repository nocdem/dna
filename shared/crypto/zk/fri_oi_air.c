/**
 * @file fri_oi_air.c
 * @brief P2c open_input slice — the FRI reduced-opening accumulation control
 *        AIR: constraint evaluation.
 *
 * Every block below names (a) the BUILDABLE-v3 C-label it discharges
 * (dnac/docs/plans/2026-07-29-p2c-oi-BUILDABLE-v3.md, local-only) and (b) the
 * native `fri_open_input` (fri_verifier.c) line whose semantics it mirrors.
 *
 * See fri_oi_air.h for the layout contract, the public-value layout, the
 * PIN-1-OI prerequisite, the declared seams and the fail-close contract, and
 * the two DELIBERATE divergences from the spec column list (gb added; x_reg
 * last).
 *
 * ── ONE DELIBERATE STRENGTHENING vs the spec's C2e literal realization ───────
 * Spec C2e (:71-74) realizes the register HOLD as "on every row that is NOT the
 * store row of height h, x_reg[h]' == x_reg[h]" — i.e. it EXEMPTS the store->next
 * transition. That exemption reopens the very hole it closes: C2c pins x_reg[h]
 * ON the store row, but the exempt store->next edge then lets x_reg[h] jump to a
 * FREE value that the acc rows read. This file HOLDS x_reg[h] on EVERY
 * transition (ungated). x_reg[h] is then globally constant, pinned by its single
 * C2c write, and the honest prover sets x_reg[h] = x_h on every row — no
 * over-constraint, no freedom. Strictly sound; documented and tested (N-F2).
 *
 * ── DEGREE TABLE (<= 3 inclusive of ONE prep gate; the FRI log_blowup = 2
 * envelope, shielded_fri_params.h) ──────────────────────────────────────────
 *
 *   block  form                                             gate  inner  total
 *   ------------------------------------------------------------------------
 *   C1a    row 0: g - (1 + b*(G_0 - 1))                     -      2      2
 *   C1b-1  pn_chain * (ngb - g*nb)                          1      2      3
 *   C1b-2  pn_chain * (ng - g - ngb*(nG - 1))               1      2      3
 *   C1c-b  is_chain * b*(b-1)                               1      2      3
 *   C1c-p  pos_k * (b - publics[bit])                       1      1      2
 *   C2a    p_seed * (y - g)                                 1      1      2
 *   C2b-sq pn_sqpair * (ny - y*y)                           1      2      3
 *   C2b-st pn_store  * (ny - y)                             1      1      2
 *   C2c    is_store * h_sel_i * (x_reg_i - 7*y)             2      1      3
 *   C2d    pn_capture * (ng - g)                            1      1      2
 *   C2e    (nx_reg_i - x_reg_i)                             -      1      1
 *   C3a    is_group_start * (alpha_pow==1, ro==0)           1      1      2
 *   C3b    is_acc * h_sel_i * (x - x_reg_i)                 2      1      3
 *   C3c    pos_k * (z==pub, p_z==pub)                       1      1      2
 *   C3g    pos_k * (p_x - pub_px[accidx(k)])                1      1      2
 *   C3d    is_acc * ((z - x)*quot - 1)  [2 lanes]           1      2      3
 *   C3e    is_acc * (t - alpha_pow*(p_z - p_x))  [2 lanes]  1      2      3
 *   C3f-ro is_acc * (nro - ro - t*quot)  [2 lanes]          1      2      3
 *   C3f-ap is_acc * (nalpha_pow - alpha_pow*alpha) [2 lanes]1      1      2
 *   C4a    is_closeout * h_sel_i * (ro - pub_ro_i) [2 lanes]2      1      3
 *   C4b    is_final_closeout * ro  [2 lanes]                1      1      2
 *   C5     pos_k * ro  [2 lanes, lb per-batch boundary]     1      1      2
 *   C6     (padding rows carry NO main-trace constraint)    -      -      -
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_oi_air.h"

#include "field_goldilocks.h"

/* ── local field shorthands (fri_air.c / mmcs_air.c idiom) ─────────────────── */
static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/** Assert a constraint residual is zero; count the violation otherwise. */
static inline void az(int *v, gold_fp_t residual) {
    if (!gold_fp_is_zero(residual)) (*v)++;
}

/* ══════════════════════════ schedule (from the generator) ═════════════════
 * The row schedule has exactly ONE authority: `dnac_p2c_oi_table_row` /
 * `dnac_p2c_oi_table_generate`. This file reads the row COUNTS and the
 * per-step MAPS back out of it (the chain-bit map for C1c, the global acc index
 * for C3c, the lb per-batch boundary for C5). Everything routed by row TYPE or
 * height is read live from the prep window (is_chain, h_sel, pos, ...). Pure
 * function of `cfg`: no clock, no RNG, no witness input.
 *
 * Calling the shape accessors is ALSO how the cfg gates run: every accessor
 * returns 0 for a config the table module rejects (h_max != lgmh, lgmh out of
 * [2,32], a zero count, num_queries 0/over, n_sched > MAX_STEPS, ...), so a cfg
 * the TABLE rejects is a BAD_CONFIG for the AIR by construction — the two can
 * never drift apart. */
typedef struct {
    size_t lgmh;
    size_t num_heights;
    size_t n_chain;    /* == lgmh                                            */
    size_t sched;      /* chain + captures + groups (non-padding prefix)     */
    size_t rows;       /* padded table height (== trace height)              */
    size_t num_cols;   /* FOI_NUM_FIXED_COLS + num_heights                   */
    size_t total_acc;  /* Σ_i n_acc(h_i)                                     */
    size_t pub_alpha;  /* public-region offsets (fri_oi_air.h layout)        */
    size_t pub_zpz;
    size_t pub_ro;
    size_t pub_px;
    size_t num_publics;
    /* Per SCHEDULED step k (< sched); padding steps carry the sentinels. */
    size_t bit[DNAC_P2C_OI_MAX_STEPS];    /* chain step: index bit; else -1  */
    size_t accidx[DNAC_P2C_OI_MAX_STEPS]; /* acc step: global acc index; -1  */
    int    lb_zero[DNAC_P2C_OI_MAX_STEPS];/* lb-group acc step at a per-batch
                                             boundary (a>0, a%batch==0): 1    */
} foi_sched_t;

static int foi_schedule(const dnac_p2c_oi_table_cfg_t *cfg, foi_sched_t *s) {
    if (cfg == NULL) return 0;

    const size_t n_chain = dnac_p2c_oi_chain_rows(cfg); /* == lgmh, or 0     */
    const size_t rows = dnac_p2c_oi_table_rows(cfg);
    const size_t sched = dnac_p2c_oi_sched_rows(cfg);
    const size_t total_acc = dnac_foi_total_acc(cfg);
    /* 0 from any accessor == "the table module rejected this cfg". */
    if (n_chain == 0 || rows == 0 || sched == 0) return 0;
    if (sched > DNAC_P2C_OI_MAX_STEPS) return 0; /* fail-close rail          */
    if (cfg->num_heights == 0 || cfg->num_heights > DNAC_P2C_OI_MAX_HEIGHTS)
        return 0;

    s->lgmh = cfg->lgmh;
    s->num_heights = cfg->num_heights;
    s->n_chain = n_chain;
    s->sched = sched;
    s->rows = rows;
    s->total_acc = total_acc;
    s->num_cols = FOI_NUM_FIXED_COLS + cfg->num_heights;

    /* Public layout (fri_oi_air.h):
     * bits | alpha | (z,p_z)*total_acc | ro*k | p_x*total_acc
     * The p_x region is APPENDED LAST (s2), so every earlier offset is exactly
     * what it was before the region existed. */
    s->pub_alpha = cfg->lgmh;
    s->pub_zpz = s->pub_alpha + FOI_EXT_LANES;
    s->pub_ro = s->pub_zpz + 2 * FOI_EXT_LANES * total_acc; /* 4 lanes/row   */
    s->pub_px = s->pub_ro + FOI_EXT_LANES * cfg->num_heights;
    s->num_publics = s->pub_px + total_acc; /* ONE base lane per acc row     */

    for (size_t k = 0; k < DNAC_P2C_OI_MAX_STEPS; k++) {
        s->bit[k] = (size_t)-1;
        s->accidx[k] = (size_t)-1;
        s->lb_zero[k] = 0;
    }

    /* Walk the schedule authority and fill the per-step maps the prep cells do
     * NOT carry. Height-routed forms read h_sel live; only the chain-bit map,
     * the global acc index and the lb per-batch boundary are derived here. */
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
            if (j_chain >= s->lgmh) return 0;
            s->bit[r] = s->lgmh - 1 - j_chain;
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
            if (batch_sz == 0) return 0; /* gated >= 1, fail-close rail       */
            s->accidx[r] = a_global;
            /* per-batch lb-zero (C5): the incoming ro must be 0 at each batch
             * boundary of the lb group (native fri_verifier.c:480-487 checks
             * height==lb ro==0 after EACH batch). a==0 is covered by C3a.
             * `cur_is_lb` is derived from the cfg, and a height at lb is
             * OPTIONAL (FLEET 029) — a cfg without one produces no lb_zero step
             * at all, mirroring the native condition. */
            if (cur_is_lb && local_a > 0 && (local_a % batch_sz) == 0)
                s->lb_zero[r] = 1;
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
    if (j_chain != s->lgmh) return 0;
    if (a_global != total_acc) return 0;
    return 1;
}

/* ══════════════════════════ public helpers ═══════════════════════════════ */

size_t dnac_foi_total_acc(const dnac_p2c_oi_table_cfg_t *cfg) {
    /* dnac_p2c_oi_group_rows == Σ(n_acc + 1 closeout); subtract the closeouts. */
    const size_t grp = dnac_p2c_oi_group_rows(cfg);
    if (grp == 0) return 0;
    return grp - cfg->num_heights; /* one closeout per height                 */
}

size_t dnac_foi_num_cols(const dnac_p2c_oi_table_cfg_t *cfg) {
    foi_sched_t s;
    if (!foi_schedule(cfg, &s)) return 0;
    return s.num_cols;
}

size_t dnac_foi_pub_alpha_off(const dnac_p2c_oi_table_cfg_t *cfg) {
    foi_sched_t s;
    if (!foi_schedule(cfg, &s)) return 0;
    return s.pub_alpha;
}

size_t dnac_foi_pub_zpz_off(const dnac_p2c_oi_table_cfg_t *cfg) {
    foi_sched_t s;
    if (!foi_schedule(cfg, &s)) return 0;
    return s.pub_zpz;
}

size_t dnac_foi_pub_ro_off(const dnac_p2c_oi_table_cfg_t *cfg) {
    foi_sched_t s;
    if (!foi_schedule(cfg, &s)) return 0;
    return s.pub_ro;
}

size_t dnac_foi_pub_px_off(const dnac_p2c_oi_table_cfg_t *cfg) {
    foi_sched_t s;
    if (!foi_schedule(cfg, &s)) return 0;
    return s.pub_px;
}

size_t dnac_foi_num_publics(const dnac_p2c_oi_table_cfg_t *cfg) {
    foi_sched_t s;
    if (!foi_schedule(cfg, &s)) return 0;
    return s.num_publics;
}

bool dnac_foi_layout_check(void) {
    /* Fixed column blocks, in order, no overlap and no gap. */
    if (FOI_COL_B != (size_t)0) return false;
    if (FOI_COL_G != FOI_COL_B + 1) return false;
    if (FOI_COL_Y != FOI_COL_G + 1) return false;
    if (FOI_COL_GB != FOI_COL_Y + 1) return false;
    if (FOI_COL_ALPHA_POW != FOI_COL_GB + 1) return false;
    if (FOI_COL_RO != FOI_COL_ALPHA_POW + FOI_EXT_LANES) return false;
    if (FOI_COL_Z != FOI_COL_RO + FOI_EXT_LANES) return false;
    if (FOI_COL_PZ != FOI_COL_Z + FOI_EXT_LANES) return false;
    if (FOI_COL_PX != FOI_COL_PZ + FOI_EXT_LANES) return false;
    if (FOI_COL_X != FOI_COL_PX + 1) return false;
    if (FOI_COL_QUOT != FOI_COL_X + 1) return false;
    if (FOI_COL_T != FOI_COL_QUOT + FOI_EXT_LANES) return false;
    if (FOI_COL_XREG != FOI_COL_T + FOI_EXT_LANES) return false;
    if (FOI_NUM_FIXED_COLS != FOI_COL_XREG) return false;
    if (FOI_NUM_FIXED_COLS != (size_t)18) return false;
    if (FOI_EXT_LANES != (size_t)2) return false;

    /* Reference cfg: lgmh 4, H={4,2}, total_acc 2. */
    {
        const dnac_p2c_oi_table_cfg_t *ref = dnac_p2c_oi_ref_cfg();
        if (dnac_foi_total_acc(ref) != 2) return false;
        if (dnac_foi_num_cols(ref) != FOI_NUM_FIXED_COLS + 2) return false;
        if (dnac_foi_pub_alpha_off(ref) != DNAC_P2C_OI_REF_LGMH) return false;
        if (dnac_foi_pub_zpz_off(ref) != DNAC_P2C_OI_REF_LGMH + 2) return false;
        if (dnac_foi_pub_ro_off(ref) != DNAC_P2C_OI_REF_LGMH + 2 + 4 * 2)
            return false;
        /* p_x is APPENDED after ro: 4 + 2 + 8 + 4 == 18 */
        if (dnac_foi_pub_px_off(ref) != DNAC_P2C_OI_REF_LGMH + 2 + 4 * 2 + 2 * 2)
            return false;
        /* 4 + 2 + 8 + 4 + 2 == 20 */
        if (dnac_foi_num_publics(ref) != (size_t)20) return false;
        if (FOI_PUB_BITS_OFF != 0) return false;
    }
    return true;
}

/* ══════════════════════════ constraint evaluation ════════════════════════ */

int dnac_foi_eval_row(const uint64_t *main_local, const uint64_t *main_next,
                      const uint64_t *prep_local, const uint64_t *prep_next,
                      int is_first_row, const dnac_p2c_oi_table_cfg_t *cfg,
                      const uint64_t *publics, size_t num_publics) {
    if (!main_local || !prep_local || !cfg || !publics)
        return FOI_VIOL_BAD_CONFIG;

    /* Shape gate (PIN-2 analog): main and preprocessed windows are ONE window.
     * A next-MAIN-without-next-PREP call is exactly the `prep_next = 0` shape
     * the transition gates would evaluate against nothing. */
    if ((main_next == NULL) != (prep_next == NULL)) return FOI_VIOL_BAD_CONFIG;

    /* cfg gates + schedule (h_max==lgmh, lgmh range, counts, num_queries, ...
     * all run inside the table module the accessors call). */
    foi_sched_t s;
    if (!foi_schedule(cfg, &s)) return FOI_VIOL_BAD_CONFIG;

    /* num_publics EXACT (also what pins the publics SHAPE today; the table root
     * does not — OBL-4c-OI). Not ">=": a longer vector leaves an unread tail. */
    if (num_publics != s.num_publics) return FOI_VIOL_BAD_CONFIG;

    /* publics canonicality, FAIL-CLOSE (OBL-2 / P2b A2-F1): fp() aliases x and
     * x+p, while every downstream u64 consumer of a public is
     * representation-sensitive. Reject a non-canonical public. */
    for (size_t i = 0; i < num_publics; i++)
        if (publics[i] >= GOLDILOCKS_P) return FOI_VIOL_BAD_CONFIG;

    int v = 0;
    const gold_fp_t one = gold_fp_one();
    const gold_fp_t W = fp(GOLDILOCKS_EXT_W); /* fp2 = F[u]/(u^2 - W), W = 7  */
    const gold_fp_t GEN = fp(GOLDILOCKS_GENERATOR); /* coset shift 7 (C2c)    */

    /* ══ main column reads ═════════════════════════════════════════════════ */
    const gold_fp_t b = fp(main_local[FOI_COL_B]);
    const gold_fp_t g = fp(main_local[FOI_COL_G]);
    const gold_fp_t y = fp(main_local[FOI_COL_Y]);
    const gold_fp_t ap0 = fp(main_local[FOI_COL_ALPHA_POW]);
    const gold_fp_t ap1 = fp(main_local[FOI_COL_ALPHA_POW + 1]);
    const gold_fp_t ro0 = fp(main_local[FOI_COL_RO]);
    const gold_fp_t ro1 = fp(main_local[FOI_COL_RO + 1]);
    const gold_fp_t z0 = fp(main_local[FOI_COL_Z]);
    const gold_fp_t z1 = fp(main_local[FOI_COL_Z + 1]);
    const gold_fp_t pz0 = fp(main_local[FOI_COL_PZ]);
    const gold_fp_t pz1 = fp(main_local[FOI_COL_PZ + 1]);
    const gold_fp_t px = fp(main_local[FOI_COL_PX]);
    const gold_fp_t x = fp(main_local[FOI_COL_X]);
    const gold_fp_t q0 = fp(main_local[FOI_COL_QUOT]);
    const gold_fp_t q1 = fp(main_local[FOI_COL_QUOT + 1]);
    const gold_fp_t t0 = fp(main_local[FOI_COL_T]);
    const gold_fp_t t1 = fp(main_local[FOI_COL_T + 1]);

    /* ══ prep cell reads (current row) ═════════════════════════════════════ */
    const gold_fp_t p_chain = fp(prep_local[DNAC_P2C_OI_COL_IS_CHAIN]);
    const gold_fp_t p_cap = fp(prep_local[DNAC_P2C_OI_COL_IS_CAPTURE]);
    const gold_fp_t p_acc = fp(prep_local[DNAC_P2C_OI_COL_IS_ACC]);
    const gold_fp_t p_close = fp(prep_local[DNAC_P2C_OI_COL_IS_CLOSEOUT]);
    const gold_fp_t p_sq = fp(prep_local[DNAC_P2C_OI_COL_IS_SQPAIR]);
    const gold_fp_t p_store = fp(prep_local[DNAC_P2C_OI_COL_IS_STORE]);
    const gold_fp_t p_gs = fp(prep_local[DNAC_P2C_OI_COL_IS_GROUP_START]);
    const gold_fp_t p_fc = fp(prep_local[DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT]);
    const gold_fp_t p_gpow = fp(prep_local[DNAC_P2C_OI_COL_G_POW2]);
    /* seed selector = is_capture AND NOT sqpair AND NOT store (spec C2a). */
    const gold_fp_t p_seed = sub(sub(p_cap, p_sq), p_store);

    /* ══ C1a — the x0 chain's ROW-0 BOUNDARY (spec C1a :53-54) ═════════════
     * g = 1 + b*(G_0 - 1): a MULTIPLY FROM 1 (the fri_air C3a / FLEET-020 A2-F4
     * form). G_0 is THIS row's preprocessed `g_pow2`. Applied unconditionally on
     * the first row (row 0 IS chain row 0 under the pinned table), which is
     * strictly stronger than gating it (OBL-P2c-3: the caller wires is_first_row). */
    if (is_first_row) az(&v, sub(g, add(one, mul(b, sub(p_gpow, one)))));

    /* ══ C1c — bit booleanity + public binding ═════════════════════════════
     * Booleanity on every is_chain row (spec C1c :57, owned IN-OI, FIX F5). */
    az(&v, mul(p_chain, mul(b, sub(b, one))));

    /* ══ C2a — capture SEED anchor: y == g (spec C2a :62-64) ═══════════════
     * The seed's g is the live chain value pinned by C2d from the height prefix
     * (no free seed — closes A2-F3). */
    az(&v, mul(p_seed, sub(y, g)));

    /* ══ C2c — capture STORE: x_reg[h] == 7*y (spec C2c :66) ═══════════════
     * y at the store == g^{2^{cum_h}} (seed g, then cum_h squarings), so
     * x_reg[h] == 7*g^{2^{cum_h}} == x_h (native fri_verifier.c:427-431). Routed
     * to the height's register by the h one-hot. */
    for (size_t i = 0; i < s.num_heights; i++) {
        const gold_fp_t hs = fp(prep_local[dnac_p2c_oi_col_hsel(i)]);
        const gold_fp_t xr = fp(main_local[dnac_foi_col_xreg(i)]);
        az(&v, mul(mul(p_store, hs), sub(xr, mul(GEN, y))));
    }

    /* ══ C3a — accumulation GROUP START (spec C3a :77-78, ROW-LOCAL) ═══════
     * alpha_pow == 1 (fp2 (1,0)), ro == 0. Not fed by a transition (FIX F5). */
    az(&v, mul(p_gs, sub(ap0, one)));
    az(&v, mul(p_gs, ap1));
    az(&v, mul(p_gs, ro0));
    az(&v, mul(p_gs, ro1));

    /* ══ C3b — x binding: x == x_reg[h(row)] (spec C3b :79-80) ═════════════ */
    for (size_t i = 0; i < s.num_heights; i++) {
        const gold_fp_t hs = fp(prep_local[dnac_p2c_oi_col_hsel(i)]);
        const gold_fp_t xr = fp(main_local[dnac_foi_col_xreg(i)]);
        az(&v, mul(mul(p_acc, hs), sub(x, xr)));
    }

    /* ══ C3d — quotient: (z - x)*quot = 1 (spec C3d :83) ══════════════════
     * z fp2, x base (c0 only). z == x is UNSAT (denominator zero), mirroring
     * fri_verifier.c:464-467. (A0+A1 u)(B0+B1 u) with u^2 = W, A = z - x, B = q. */
    {
        const gold_fp_t a0 = sub(z0, x); /* (z - x).c0 */
        az(&v, mul(p_acc, sub(add(mul(a0, q0), mul(W, mul(z1, q1))), one)));
        az(&v, mul(p_acc, add(mul(a0, q1), mul(z1, q0))));
    }

    /* ══ C3e — degree relief t = alpha_pow*(p_z - p_x) (spec C3e :84-85) ═══
     * p_x base -> enters the c0 lane only (fri_verifier.c:471). ROW-LOCAL. */
    {
        const gold_fp_t d0 = sub(pz0, px); /* (p_z - p_x).c0 */
        az(&v, mul(p_acc, sub(t0, add(mul(ap0, d0), mul(W, mul(ap1, pz1))))));
        az(&v, mul(p_acc, sub(t1, add(mul(ap0, pz1), mul(ap1, d0)))));
    }

    /* ══ C1c-p / C3c / C3g / C5 — the pos-gated publics + lb-zero forms ════
     * `pos` is PREPROCESSED (a degree-1 selector); only the row whose step is k
     * has pos[k]=1, so exactly one term per row survives. Loop stops at `sched`
     * because padding steps carry pos == 0 (generator obligation under PIN-1-OI). */
    for (size_t k = 0; k < s.sched; k++) {
        const gold_fp_t pk = fp(prep_local[dnac_p2c_oi_col_pos(k)]);

        /* C1c public binding: chain step k reads index bit s.bit[k]. */
        if (s.bit[k] != (size_t)-1) {
            az(&v, mul(pk, sub(b, fp(publics[FOI_PUB_BITS_OFF + s.bit[k]]))));
        }

        /* C3c z / p_z binding: acc step k -> its own (z, p_z) public pair.
         * ══ C3g (s2) — p_x binding, EMITTED IMMEDIATELY AFTER C3c and inside
         * the same pos gate, so the two share one selector read and the emission
         * ORDER (z0, z1, pz0, pz1, px) is a pinned property the fold form
         * transcribes verbatim (the alpha-fold is order-sensitive).
         * `p_x` was a free witness through s1c; it is now bound to the public
         * the composition sources from the MMCS opened row
         * (native: p_at_x = bo->opened_values[m][j], fri_verifier.c:469-476).
         * ONE lane, base field, degree 2 (pos selector x linear). */
        if (s.accidx[k] != (size_t)-1) {
            const size_t zo = s.pub_zpz + 4 * s.accidx[k];
            az(&v, mul(pk, sub(z0, fp(publics[zo]))));
            az(&v, mul(pk, sub(z1, fp(publics[zo + 1]))));
            az(&v, mul(pk, sub(pz0, fp(publics[zo + 2]))));
            az(&v, mul(pk, sub(pz1, fp(publics[zo + 3]))));
            az(&v, mul(pk, sub(px, fp(publics[s.pub_px + s.accidx[k]]))));
        }

        /* C5 per-batch lb-zero: incoming ro == 0 at each lb batch boundary. */
        if (s.lb_zero[k]) {
            az(&v, mul(pk, ro0));
            az(&v, mul(pk, ro1));
        }
    }

    /* ══ C4a — CLOSEOUT ro export: ro == publics[ro_slot_h] (spec C4a :94-95)
     * ro here IS the group's final accumulation (the one-sided C3f carry made
     * the last-acc -> closeout transition fire). Exported height-descending. */
    for (size_t i = 0; i < s.num_heights; i++) {
        const gold_fp_t hs = fp(prep_local[dnac_p2c_oi_col_hsel(i)]);
        const size_t ao = s.pub_ro + FOI_EXT_LANES * i;
        az(&v, mul(mul(p_close, hs), sub(ro0, fp(publics[ao]))));
        az(&v, mul(mul(p_close, hs), sub(ro1, fp(publics[ao + 1]))));
    }

    /* ══ C4b — FINAL closeout (h == lb): ro == 0 (spec C4b :96-98) ════════
     * The native FinalPolyMismatch zero rule (fri_verifier.c:482-487) — which is
     * CONDITIONAL there: the native checks it only for a reduced opening that
     * exists AT log_blowup. The mirror here is the `p_fc` prep gate: the
     * generator sets is_final_closeout only on a group whose log_height == lb,
     * so on a cfg with no such height NO row carries it and this form is
     * VACUOUS — exactly the native's condition, not a schedule requirement
     * (FLEET 029). When an lb group IS present, C4b together with C4a also
     * forces publics[ro_slot_lb] == 0, so fri_air's final-height slot reads the
     * zero (OBL roll-in set-equality). */
    az(&v, mul(p_fc, ro0));
    az(&v, mul(p_fc, ro1));

    if (!main_next) return v; /* last row: no transition constraints */

    const gold_fp_t nb = fp(main_next[FOI_COL_B]);
    const gold_fp_t ng = fp(main_next[FOI_COL_G]);
    const gold_fp_t ngb = fp(main_next[FOI_COL_GB]);
    const gold_fp_t ny = fp(main_next[FOI_COL_Y]);
    const gold_fp_t nap0 = fp(main_next[FOI_COL_ALPHA_POW]);
    const gold_fp_t nap1 = fp(main_next[FOI_COL_ALPHA_POW + 1]);
    const gold_fp_t nro0 = fp(main_next[FOI_COL_RO]);
    const gold_fp_t nro1 = fp(main_next[FOI_COL_RO + 1]);
    const gold_fp_t pn_chain = fp(prep_next[DNAC_P2C_OI_COL_IS_CHAIN]);
    const gold_fp_t pn_cap = fp(prep_next[DNAC_P2C_OI_COL_IS_CAPTURE]);
    const gold_fp_t pn_sq = fp(prep_next[DNAC_P2C_OI_COL_IS_SQPAIR]);
    const gold_fp_t pn_store = fp(prep_next[DNAC_P2C_OI_COL_IS_STORE]);
    const gold_fp_t pn_gpow = fp(prep_next[DNAC_P2C_OI_COL_G_POW2]);

    /* ══ C1b — chain transition, gated by NEXT row is_chain (spec C1b :55-56)
     *     gb' = g * b'                    (intermediate; degree relief)
     *     g'  = g + gb'*(G' - 1)          == g * (1 + b'*(G' - 1))
     * The predecessor of a chain row is a chain row OR a capture STORE row (end
     * of a block); either way g is the carried chain value. G' = next g_pow2 —
     * this read is why prep_next is mandatory (the PIN-2 analog). */
    az(&v, mul(pn_chain, sub(ngb, mul(g, nb))));
    az(&v, mul(pn_chain, sub(ng, add(g, mul(ngb, sub(pn_gpow, one))))));

    /* ══ C2b — capture squaring + store copy (spec C2b :65 / C2c thread) ═══
     * Into a sqpair row: y' = y*y (one squaring per is_sqpair row => cum_h). The
     * seed's y feeds sq_1, ..., sq_{cum}; sq_{cum}'s y feeds the store by COPY. */
    az(&v, mul(pn_sq, sub(ny, mul(y, y))));
    az(&v, mul(pn_store, sub(ny, y)));

    /* ══ C2d — chain-resume: g' = g across the capture block (spec C2d :67-70)
     * Gated by NEXT row is_capture, so g is copied from the height prefix into
     * every capture row and continues UNCHANGED (the squaring lives in y, not g
     * — closes A2-F3). Mutually exclusive with C1b (next row is one type). */
    az(&v, mul(pn_cap, sub(ng, g)));

    /* ══ C2e — register HOLD (spec C2e :71-74, STRENGTHENED to ungated) ════
     * x_reg[i] held on EVERY transition => globally constant, pinned by its one
     * C2c write (see the header note: the spec's store-row exemption reopens the
     * hole; holding everywhere is strictly sound). */
    for (size_t i = 0; i < s.num_heights; i++) {
        const gold_fp_t xr = fp(main_local[dnac_foi_col_xreg(i)]);
        const gold_fp_t nxr = fp(main_next[dnac_foi_col_xreg(i)]);
        az(&v, sub(nxr, xr));
    }

    /* ══ C3f — the ONE-SIDED carry (spec C3f :86-91, FIX F1) ═══════════════
     * Gated on the CURRENT row's is_acc (NOT this-AND-next). Fires on every acc
     * row INCLUDING the last-acc -> closeout transition, so the closeout's ro IS
     * the group's final accumulation; OFF on closeout -> next-group-start
     * (closeout is not is_acc), so C3a's reset is unconflicted.
     *   ro'        = ro + t*quot            (t*quot fp2, W = 7)
     *   alpha_pow' = alpha_pow * alpha      (alpha from publics) */
    {
        /* t * quot (fp2). */
        const gold_fp_t tq0 = add(mul(t0, q0), mul(W, mul(t1, q1)));
        const gold_fp_t tq1 = add(mul(t0, q1), mul(t1, q0));
        az(&v, mul(p_acc, sub(nro0, add(ro0, tq0))));
        az(&v, mul(p_acc, sub(nro1, add(ro1, tq1))));

        /* alpha_pow * alpha (fp2), alpha public. */
        const gold_fp_t al0 = fp(publics[s.pub_alpha]);
        const gold_fp_t al1 = fp(publics[s.pub_alpha + 1]);
        const gold_fp_t ma0 = add(mul(ap0, al0), mul(W, mul(ap1, al1)));
        const gold_fp_t ma1 = add(mul(ap0, al1), mul(ap1, al0));
        az(&v, mul(p_acc, sub(nap0, ma0)));
        az(&v, mul(p_acc, sub(nap1, ma1)));
    }

    return v;
}

int dnac_foi_eval_trace(const uint64_t *main_trace, const uint64_t *prep_table,
                        size_t n_rows, const dnac_p2c_oi_table_cfg_t *cfg,
                        const uint64_t *publics, size_t num_publics) {
    if (!main_trace || !prep_table || n_rows == 0) return FOI_VIOL_BAD_CONFIG;

    foi_sched_t s;
    if (!foi_schedule(cfg, &s)) return FOI_VIOL_BAD_CONFIG;

    /* SCHEDULE CONFORMANCE: the row count is the PINNED schedule, not a
     * witnessed length (a shorter walk is a different statement). */
    if (n_rows != s.rows) return FOI_VIOL_BAD_CONFIG;

    /* TERMINALITY: the last row MUST be a padding row, so no transition-anchored
     * form can be skipped by ending early (the P2a-i3 shipped-HIGH shape).
     * Fail-close (fri_air's stricter posture). */
    {
        const uint64_t *last =
            prep_table + (n_rows - 1) * (size_t)DNAC_P2C_OI_TABLE_COLS;
        if (last[DNAC_P2C_OI_COL_IS_PAD] != 1u) return FOI_VIOL_BAD_CONFIG;
        if (last[DNAC_P2C_OI_COL_IS_CHAIN] != 0u) return FOI_VIOL_BAD_CONFIG;
        if (last[DNAC_P2C_OI_COL_IS_CAPTURE] != 0u) return FOI_VIOL_BAD_CONFIG;
        if (last[DNAC_P2C_OI_COL_IS_ACC] != 0u) return FOI_VIOL_BAD_CONFIG;
        if (last[DNAC_P2C_OI_COL_IS_CLOSEOUT] != 0u) return FOI_VIOL_BAD_CONFIG;
    }

    int total = 0;
    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *local = main_trace + r * s.num_cols;
        const uint64_t *pl = prep_table + r * (size_t)DNAC_P2C_OI_TABLE_COLS;
        const uint64_t *next = (r + 1 < n_rows) ? local + s.num_cols : NULL;
        const uint64_t *pn =
            (r + 1 < n_rows) ? pl + (size_t)DNAC_P2C_OI_TABLE_COLS : NULL;
        const int rv = dnac_foi_eval_row(local, next, pl, pn, r == 0, cfg,
                                         publics, num_publics);
        if (rv >= FOI_VIOL_BAD_CONFIG) return FOI_VIOL_BAD_CONFIG;
        /* Saturate rather than overflow (signed overflow is UB; the sentinel
         * band must stay distinguishable — the P2a i3/A2-F5 contract). */
        if (total >= FOI_VIOL_BAD_CONFIG - 1 - rv) {
            total = FOI_VIOL_BAD_CONFIG - 1;
        } else {
            total += rv;
        }
    }
    return total;
}
