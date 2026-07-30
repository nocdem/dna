/**
 * @file test_fri_oi_air.c
 * @brief P2c open_input slice — FRI reduced-opening accumulation control-AIR
 *        construction gate (TDD).
 *
 * Build spec: dnac/docs/plans/2026-07-29-p2c-oi-BUILDABLE-v3.md (local-only) —
 * constraints C1..C6, the eval-entry gates, and the MANDATORY A2 second-witness
 * negatives N-F1..N-F7.
 *
 * ── HONEST LABEL ────────────────────────────────────────────────────────────
 * This test performs a NATIVE-FORMULA REPLAY: it drives the exact field
 * expressions of `fri_open_input` (fri_verifier.c) test-side —
 *   - x_h = GENERATOR * two_adic_generator(h)^rev, rev = reverse_bits_len(
 *     index >> (lgmh-h), h)   (fri_verifier.c:423-431), and
 *   - ro += alpha_pow*(p_z - p_x)/(z - x), alpha_pow *= alpha
 *     (fri_verifier.c:469-476), reset per height (fri_verifier.c:176-177) —
 * and requires the AIR to accept exactly the trace that chain produces. The
 * AIR-INDEPENDENT cross-check is the x_h identity: every capture block computes
 * x_h a SECOND way, as 7*g^{2^{cum_h}} from the MSB-first chain state g, and the
 * build asserts 7*g^{2^{cum_h}} == GENERATOR*two_adic_generator(h)^rev at every
 * store row — two independent computations of the same eval point. What is
 * proved HERE is that the AIR's accepted language CONTAINS the native one
 * (accepts) and EXCLUDES each single-form deviation (negatives).
 *
 * Deterministic fixtures only — NO rand() anywhere (root CLAUDE.md).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../fri_oi_air.h"
#include "../fri_oi_air_table.h"

#define T_MAX_ROWS 256
#define T_MAX_PUB  512

static int fails = 0;

/* ══════════════════════════ field shorthands ═════════════════════════════ */

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline uint64_t u(gold_fp_t x) { return gold_fp_to_u64(x); }
static inline gold_fp2_t emb(gold_fp_t a) { return gold_fp2_from_base(a); }

static void wr2(uint64_t *row, size_t off, gold_fp2_t x) {
    row[off] = u(x.a);
    row[off + 1] = u(x.b);
}

/** Deterministic field fixture — a fixed affine function of its coordinates. */
static gold_fp_t tfp(uint64_t a, uint64_t c) {
    return fp(a * UINT64_C(0x00000001ABCDEF01) + c * UINT64_C(0x0000000100000007) +
              UINT64_C(0x0123456789ABCDEF));
}
static gold_fp2_t tfp2(uint64_t a, uint64_t c) {
    return gold_fp2_new(tfp(a, c), tfp(a, c + 1));
}

/** +1 in the field, kept CANONICAL. */
static uint64_t bump(uint64_t v) { return u(gold_fp_add(fp(v), gold_fp_one())); }

/** reverse_bits_len (fri_verifier.c oracle; zk_field_helpers.c port), local so
 *  the test links nothing beyond the AIR + its table + the field. */
static uint64_t rev_bits(uint64_t v, unsigned bits) {
    uint64_t r = 0;
    for (unsigned i = 0; i < bits; i++) r = (r << 1) | ((v >> i) & 1u);
    return r;
}

/* ══════════════════════════ honest trace builder ═════════════════════════ */

typedef struct {
    const dnac_p2c_oi_table_cfg_t *cfg;
    size_t    lgmh, num_heights, rows, sched, num_cols, num_pub;
    size_t    pub_alpha, pub_zpz, pub_ro, pub_px;
    uint64_t  index;
    uint64_t *trace; /* rows * num_cols                */
    uint64_t *prep;  /* rows * DNAC_P2C_OI_TABLE_COLS  */
    uint64_t *pub;   /* num_pub                        */
    gold_fp_t  x_h[DNAC_P2C_OI_MAX_HEIGHTS];
    gold_fp2_t alpha;
    size_t     a_of_row[T_MAX_ROWS]; /* acc rows -> global acc index; else -1 */
} built_t;

static uint64_t *row_of(const built_t *B, size_t r) {
    return B->trace + r * B->num_cols;
}
static void built_free(built_t *B) {
    free(B->trace);
    free(B->prep);
    free(B->pub);
    B->trace = B->prep = B->pub = NULL;
}

/* zoff / px / pz fixtures as a pure function of the global acc index. */
static gold_fp2_t zoff_of(size_t a) { return tfp2(a + 1, 13); }

/**
 * OPTIONAL EXTERNAL p_x SOURCE (s2). NULL — the shipped default for every test
 * in THIS file — means "use the deterministic fixture below", so nothing about
 * this gate's own behaviour changes. The composition gate
 * (tests/test_fri_statement.c) points it at the MMCS opened lanes for the main
 * input batch's acc rows, which is the only way to drive an honest oi trace
 * whose p_x publics ARE the mmix instance's opened row. Must be [total_acc]
 * CANONICAL lanes, and must be cleared after the build.
 */
static const uint64_t *g_px_ext = NULL;

static gold_fp_t px_of(size_t a) {
    if (g_px_ext != NULL) return fp(g_px_ext[a]);
    return tfp(a + 2, 17);
}

/**
 * OPTIONAL EXTERNAL alpha SOURCE (s3b) — the same shape as `g_px_ext` above and
 * for the same reason. NULL is the shipped default for every test in THIS file,
 * so nothing about this gate's own behaviour changes.
 *
 * The composition gate (tests/test_fri_statement.c) points it at the challenge
 * the TRANSCRIPT instance pops for the FRI batch-combine alpha. That value is a
 * CONSTANT of the protocol — `dnac_duplex_init_default` absorbs the pinned DS
 * prefix (duplex_challenger.c:96-103) and the AIR pins those observed lanes
 * (transcript_air.c:279), so the first two pops are fixed — and the fixture
 * family `tfp2(seed, 3)` below cannot reach it for ANY seed: both of its lanes
 * move together, so `b - a` is always 0x0000000100000007 while the transcript's
 * is 0x4c42e371b14a9ec8. Without this hook there is no honest oi trace at the
 * aliased alpha, and the 5-instance round-trip is unprovable.
 * Must be TWO CANONICAL lanes [c0, c1], and must be cleared after the build.
 */
static const uint64_t *g_alpha_ext = NULL;

static gold_fp2_t alpha_of(uint64_t seed) {
    if (g_alpha_ext != NULL) return gold_fp2_new(fp(g_alpha_ext[0]), fp(g_alpha_ext[1]));
    return tfp2(seed, 3);
}

static int build_honest(built_t *B, const dnac_p2c_oi_table_cfg_t *cfg,
                        uint64_t index, uint64_t seed) {
    memset(B, 0, sizeof(*B));
    B->cfg = cfg;
    B->index = index;
    B->lgmh = cfg->lgmh;
    B->num_heights = cfg->num_heights;
    B->rows = dnac_p2c_oi_table_rows(cfg);
    B->sched = dnac_p2c_oi_sched_rows(cfg);
    B->num_cols = dnac_foi_num_cols(cfg);
    B->num_pub = dnac_foi_num_publics(cfg);
    B->pub_alpha = dnac_foi_pub_alpha_off(cfg);
    B->pub_zpz = dnac_foi_pub_zpz_off(cfg);
    B->pub_ro = dnac_foi_pub_ro_off(cfg);
    B->pub_px = dnac_foi_pub_px_off(cfg);
    if (B->rows == 0 || B->num_cols == 0 || B->num_pub == 0) return 0;
    if (B->rows > T_MAX_ROWS || B->num_pub > T_MAX_PUB) return 0;

    B->trace = (uint64_t *)calloc(B->rows * B->num_cols, sizeof(uint64_t));
    B->prep = (uint64_t *)calloc(B->rows * (size_t)DNAC_P2C_OI_TABLE_COLS,
                                 sizeof(uint64_t));
    B->pub = (uint64_t *)calloc(B->num_pub, sizeof(uint64_t));
    if (!B->trace || !B->prep || !B->pub) {
        built_free(B);
        return 0;
    }
    for (size_t r = 0; r < T_MAX_ROWS; r++) B->a_of_row[r] = (size_t)-1;

    if (dnac_p2c_oi_table_generate(cfg, B->prep,
                                   B->rows * (size_t)DNAC_P2C_OI_TABLE_COLS) !=
        DNAC_P2C_OI_TABLE_OK) {
        built_free(B);
        return 0;
    }
    {
        dnac_p2c_oi_table_defect_t d;
        if (dnac_p2c_oi_table_validate(cfg, B->prep, B->rows, &d) !=
            DNAC_P2C_OI_TABLE_OK) {
            built_free(B);
            return 0;
        }
    }

    const gold_fp_t GEN = fp(GOLDILOCKS_GENERATOR);
    /* x_h per height, the NATIVE formula (fri_verifier.c:423-431). */
    for (size_t i = 0; i < B->num_heights; i++) {
        const size_t h = cfg->heights[i].log_height;
        const uint64_t rv = rev_bits(index >> (B->lgmh - h), (unsigned)h);
        B->x_h[i] = gold_fp_mul(
            GEN, gold_fp_pow(gold_fp_two_adic_generator((unsigned)h), rv));
    }
    B->alpha = alpha_of(seed);

    gold_fp_t  gacc = gold_fp_zero();
    gold_fp_t  ycur = gold_fp_zero();
    size_t     j_chain = 0, a_global = 0;
    gold_fp2_t ap = gold_fp2_one(), ro = gold_fp2_zero();
    int        cur_is_lb = 0;
    const gold_fp_t one = gold_fp_one();

    for (size_t r = 0; r < B->rows; r++) {
        dnac_p2c_oi_row_t rec;
        if (dnac_p2c_oi_table_row(cfg, r, &rec) != DNAC_P2C_OI_TABLE_OK) {
            built_free(B);
            return 0;
        }
        uint64_t *row = row_of(B, r);
        /* x_reg[i] = x_h[i] on EVERY row (the ungated global hold, C2e). */
        for (size_t i = 0; i < B->num_heights; i++)
            row[dnac_foi_col_xreg(i)] = u(B->x_h[i]);

        switch (rec.type) {
        case DNAC_P2C_OI_ROW_CHAIN: {
            const size_t bit = B->lgmh - 1 - j_chain;
            const uint64_t bb = (index >> bit) & 1u;
            const gold_fp_t Gj =
                gold_fp_two_adic_generator((unsigned)(B->lgmh - j_chain));
            uint64_t gbv = 0;
            if (j_chain == 0) {
                gacc = bb ? Gj : one;
            } else {
                const gold_fp_t gb = bb ? gacc : gold_fp_zero();
                gbv = u(gb);
                gacc = gold_fp_add(gacc, gold_fp_mul(gb, gold_fp_sub(Gj, one)));
            }
            row[FOI_COL_B] = bb;
            row[FOI_COL_G] = u(gacc);
            row[FOI_COL_GB] = gbv;
            j_chain++;
            break;
        }
        case DNAC_P2C_OI_ROW_CAPTURE: {
            if (rec.is_sqpair) {
                ycur = gold_fp_mul(ycur, ycur);
            } else if (!rec.is_store) { /* seed */
                ycur = gacc;
            } /* store: ycur unchanged (copied) */
            row[FOI_COL_G] = u(gacc);
            row[FOI_COL_Y] = u(ycur);
            if (rec.is_store) {
                /* AIR-INDEPENDENT cross-check: 7*g^{2^cum} == x_h formula. */
                if (u(gold_fp_mul(GEN, ycur)) != u(B->x_h[rec.h_index])) {
                    printf("  [xchk] store h_index %zu x_h MISMATCH — FAIL\n",
                           rec.h_index);
                    fails++;
                }
            }
            break;
        }
        case DNAC_P2C_OI_ROW_ACC: {
            const size_t i = rec.h_index;
            if (rec.is_group_start) {
                cur_is_lb =
                    (cfg->heights[i].log_height == cfg->log_blowup) ? 1 : 0;
                ap = gold_fp2_one();
                ro = gold_fp2_zero();
            }
            const gold_fp_t x = B->x_h[i];
            const gold_fp2_t zoff = zoff_of(a_global);
            const gold_fp2_t z = gold_fp2_add(emb(x), zoff); /* z - x = zoff  */
            const gold_fp_t  px = px_of(a_global);
            const gold_fp2_t pz =
                cur_is_lb ? emb(px) : tfp2(a_global + 3, 19); /* lb: term 0   */
            const gold_fp2_t quot = gold_fp2_inv(zoff);       /* (z-x)^-1     */
            const gold_fp2_t t = gold_fp2_mul(ap, gold_fp2_sub(pz, emb(px)));

            wr2(row, FOI_COL_ALPHA_POW, ap);
            wr2(row, FOI_COL_RO, ro);
            wr2(row, FOI_COL_Z, z);
            wr2(row, FOI_COL_PZ, pz);
            row[FOI_COL_PX] = u(px);
            row[FOI_COL_X] = u(x);
            wr2(row, FOI_COL_QUOT, quot);
            wr2(row, FOI_COL_T, t);

            const size_t zo = B->pub_zpz + 4 * a_global;
            B->pub[zo] = u(z.a);
            B->pub[zo + 1] = u(z.b);
            B->pub[zo + 2] = u(pz.a);
            B->pub[zo + 3] = u(pz.b);
            /* s2 — the p_x public this acc row's C3g binds to. Published from
             * the SAME value the trace column carries, so the honest walk is
             * honest under C3g by construction. */
            B->pub[B->pub_px + a_global] = u(px);
            B->a_of_row[r] = a_global;

            ro = gold_fp2_add(ro, gold_fp2_mul(t, quot));
            ap = gold_fp2_mul(ap, B->alpha);
            a_global++;
            break;
        }
        case DNAC_P2C_OI_ROW_CLOSEOUT: {
            const size_t i = rec.h_index;
            wr2(row, FOI_COL_RO, ro);
            wr2(row, FOI_COL_ALPHA_POW, ap);
            const size_t so = B->pub_ro + 2 * i;
            if (rec.is_final_closeout) {
                if (!gold_fp2_eq(ro, gold_fp2_zero())) {
                    printf("  [xchk] final closeout ro != 0 — FAIL\n");
                    fails++;
                }
                B->pub[so] = 0;
                B->pub[so + 1] = 0;
            } else {
                B->pub[so] = u(ro.a);
                B->pub[so + 1] = u(ro.b);
            }
            break;
        }
        case DNAC_P2C_OI_ROW_PAD:
        default:
            break;
        }
    }

    for (size_t i = 0; i < B->lgmh; i++)
        B->pub[FOI_PUB_BITS_OFF + i] = (index >> i) & 1u;
    B->pub[B->pub_alpha] = u(B->alpha.a);
    B->pub[B->pub_alpha + 1] = u(B->alpha.b);
    return 1;
}

/* ══════════════════════════ helpers / reporting ══════════════════════════ */

static int eval_b(const built_t *B) {
    return dnac_foi_eval_trace(B->trace, B->prep, B->rows, B->cfg, B->pub,
                               B->num_pub);
}

static void expect_reject(const char *name, const built_t *B, int want_exact) {
    const int v = eval_b(B);
    if (v < 1 || v >= FOI_VIOL_BAD_CONFIG) {
        printf("  [reject] %-52s NOT caught (%d) — FAIL\n", name, v);
        fails++;
        return;
    }
    if (want_exact > 0 && v != want_exact) {
        printf("  [reject] %-52s caught but %d viol (want %d) — FAIL\n", name, v,
               want_exact);
        fails++;
        return;
    }
    printf("  [reject] %-52s caught (%d viol) — OK\n", name, v);
}

static void expect_bad_config(const char *name, int v) {
    if (v == FOI_VIOL_BAD_CONFIG) {
        printf("  [reject] %-52s fails closed — OK\n", name);
    } else {
        printf("  [reject] %-52s returned %d — FAIL\n", name, v);
        fails++;
    }
}

static void check(const char *name, int ok) {
    printf("  [gate]   %-52s %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) fails++;
}

/* Find the r-th (0-based) acc row whose h_index == hidx. -1 if none. */
static long acc_row_for_height(const built_t *B, size_t hidx, size_t nth) {
    size_t seen = 0;
    for (size_t r = 0; r < B->sched; r++) {
        dnac_p2c_oi_row_t rec;
        if (dnac_p2c_oi_table_row(B->cfg, r, &rec) != DNAC_P2C_OI_TABLE_OK)
            continue;
        if (rec.type == DNAC_P2C_OI_ROW_ACC && rec.h_index == hidx) {
            if (seen == nth) return (long)r;
            seen++;
        }
    }
    return -1;
}
static long closeout_row_for_height(const built_t *B, size_t hidx) {
    for (size_t r = 0; r < B->sched; r++) {
        dnac_p2c_oi_row_t rec;
        if (dnac_p2c_oi_table_row(B->cfg, r, &rec) != DNAC_P2C_OI_TABLE_OK)
            continue;
        if (rec.type == DNAC_P2C_OI_ROW_CLOSEOUT && rec.h_index == hidx)
            return (long)r;
    }
    return -1;
}
static long first_sq_row(const built_t *B, size_t hidx) {
    for (size_t r = 0; r < B->sched; r++) {
        dnac_p2c_oi_row_t rec;
        if (dnac_p2c_oi_table_row(B->cfg, r, &rec) != DNAC_P2C_OI_TABLE_OK)
            continue;
        if (rec.type == DNAC_P2C_OI_ROW_CAPTURE && rec.is_sqpair &&
            rec.h_index == hidx)
            return (long)r;
    }
    return -1;
}
static long first_seed_row(const built_t *B, size_t hidx) {
    for (size_t r = 0; r < B->sched; r++) {
        dnac_p2c_oi_row_t rec;
        if (dnac_p2c_oi_table_row(B->cfg, r, &rec) != DNAC_P2C_OI_TABLE_OK)
            continue;
        if (rec.type == DNAC_P2C_OI_ROW_CAPTURE && !rec.is_sqpair &&
            !rec.is_store && rec.h_index == hidx)
            return (long)r;
    }
    return -1;
}

/* ══════════════════════════════ configs ══════════════════════════════════ */

/* wider accept cfg: lgmh 6, H = {6, 4, 2}, each {1,1,1,1}. */
static const dnac_p2c_oi_height_desc_t WIDE_H[3] = {
    {6, 1, 1, 1, 1}, {4, 1, 1, 1, 1}, {2, 1, 1, 1, 1}};
static const dnac_p2c_oi_table_cfg_t CFG_WIDE = {6, 2, 3, WIDE_H, 50};

/* REF-PROOF-SHAPED cfgs (FLEET 029): lgmh 5, lb = 2, H = {5, 4} — NO height AT
 * lb, which is the shape a real inner proof actually has (a matrix at
 * log_height == log_blowup would be a degree-0 polynomial). The native lb-zero
 * rule is CONDITIONAL on such a height existing (fri_verifier.c:482-487), so the
 * schedule carries NO is_final_closeout row here and C4b/C5 are both vacuous.
 *   NOLB    : each height {1,1,1,1}  => 14 scheduled rows, 16 total
 *   NOLB_MB : the LAST group has TWO batches, i.e. a per-batch boundary. If the
 *             derivation still equated "last group" with "the lb group", C5
 *             would demand ro == 0 at that boundary and this honest walk (whose
 *             ro is non-zero there) would be REJECTED — so its acceptance is
 *             what pins n_lb_zero == 0.  => 15 scheduled rows, 16 total. */
static const dnac_p2c_oi_height_desc_t NOLB_H[2] = {{5, 1, 1, 1, 1},
                                                    {4, 1, 1, 1, 1}};
static const dnac_p2c_oi_table_cfg_t CFG_NOLB = {5, 2, 2, NOLB_H, 50};
static const dnac_p2c_oi_height_desc_t NOLB_MB_H[2] = {{5, 1, 1, 1, 1},
                                                       {4, 2, 1, 1, 1}};
static const dnac_p2c_oi_table_cfg_t CFG_NOLB_MB = {5, 2, 2, NOLB_MB_H, 50};

/* multi-batch lb cfg (N-F4): lb height has num_batches = 2 => lb group has
 * 2 acc rows, one batch boundary at local index 1. */
static const dnac_p2c_oi_height_desc_t MB_H[2] = {{4, 1, 1, 1, 1},
                                                  {2, 2, 1, 1, 1}};
static const dnac_p2c_oi_table_cfg_t CFG_MB = {4, 2, 2, MB_H, 7};

/* bad cfgs for the eval-entry gates. */
static const dnac_p2c_oi_height_desc_t H33[1] = {{33, 1, 1, 1, 1}};
static const dnac_p2c_oi_table_cfg_t CFG_LGMH33 = {33, 2, 1, H33, 7};
static const dnac_p2c_oi_height_desc_t HQ0[2] = {{4, 1, 1, 1, 1},
                                                 {2, 1, 1, 1, 1}};
static const dnac_p2c_oi_table_cfg_t CFG_Q0 = {4, 2, 2, HQ0, 0};
/* N-F7: h_max (heights[0]) != lgmh. */
static const dnac_p2c_oi_height_desc_t HF7[2] = {{3, 1, 1, 1, 1},
                                                 {2, 1, 1, 1, 1}};
static const dnac_p2c_oi_table_cfg_t CFG_F7 = {4, 2, 2, HF7, 7};

/* ═══════════════════════════════ accepts ═════════════════════════════════ */

static int accept_case(const dnac_p2c_oi_table_cfg_t *cfg, uint64_t index,
                       uint64_t seed, const char *label) {
    built_t B;
    if (!build_honest(&B, cfg, index, seed)) {
        printf("  [accept] %-28s honest trace build          FAIL\n", label);
        fails++;
        return 0;
    }
    const int v = eval_b(&B);
    int ok = 1;
    if (v != 0) {
        printf("  [accept] %-28s %2zu rows  %d viol — FAIL\n", label, B.rows, v);
        fails++;
        ok = 0;
    } else {
        printf("  [accept] %-28s idx %6" PRIu64 "  %2zu rows  0 viol — OK\n",
               label, index, B.rows);
    }
    built_free(&B);
    return ok;
}

/* ════════════════════════════════ main ═══════════════════════════════════ */

int main(void) {
    const dnac_p2c_oi_table_cfg_t *REF = dnac_p2c_oi_ref_cfg();

    printf("============================================================\n");
    printf("P2c open_input slice — reduced-opening accumulation AIR\n");
    printf("============================================================\n");

    /* ── layout / offset contract ── */
    check("column layout + public regions (REF)", dnac_foi_layout_check());
    check("num_cols(REF) == 20 (18 fixed + 2 heights)",
          dnac_foi_num_cols(REF) == 20);
    check("num_publics(REF) == 20 (4 + 2 + 8 + 4 + 2)",
          dnac_foi_num_publics(REF) == 20);
    check("total_acc(REF) == 2", dnac_foi_total_acc(REF) == 2);
    check("pub_alpha(REF) == 4", dnac_foi_pub_alpha_off(REF) == 4);
    check("pub_zpz(REF) == 6", dnac_foi_pub_zpz_off(REF) == 6);
    check("pub_ro(REF) == 14", dnac_foi_pub_ro_off(REF) == 14);
    /* s2 — the p_x region is APPENDED, so every offset above is unmoved. */
    check("pub_px(REF) == 18 (appended after ro)",
          dnac_foi_pub_px_off(REF) == 18);
    check("pub_px(REF) == pub_ro + 2*num_heights",
          dnac_foi_pub_px_off(REF) ==
              dnac_foi_pub_ro_off(REF) + 2 * REF->num_heights);
    check("table rows(REF) == 16", dnac_p2c_oi_table_rows(REF) == 16);
    check("num_cols(WIDE) == 21, total_acc == 3",
          dnac_foi_num_cols(&CFG_WIDE) == 21 &&
              dnac_foi_total_acc(&CFG_WIDE) == 3);
    check("total_acc(MB) == 3 (lb 2 batches)",
          dnac_foi_total_acc(&CFG_MB) == 3);

    /* ── accepts (native-formula replay + x_h cross-check at every store) ── */
    printf("\n-- honest walks (native x_h/accumulation replay) ------------\n");
    accept_case(REF, 0, 1, "REF idx 0");
    accept_case(REF, 11, 2, "REF idx 11 (hand-set)");
    accept_case(REF, 13, 3, "REF idx 13 (non-palin)");
    accept_case(&CFG_WIDE, UINT64_C(0x2D), 4, "WIDE lgmh 6 idx 45");
    accept_case(&CFG_MB, 6, 5, "MB lgmh 4 (2-batch lb)");
    accept_case(&CFG_NOLB, 21, 6, "NOLB lgmh 5 H={5,4} (no lb)");
    accept_case(&CFG_NOLB_MB, 21, 7, "NOLB_MB (no lb, 2-batch last)");

    /* FLEET 029 structural pin: on an lb-LESS schedule NO row carries
     * is_final_closeout, so C4b is vacuous — exactly the native's conditional
     * lb-zero rule (fri_verifier.c:482-487) rather than a schedule requirement.
     * The NOLB_MB acceptance just above is the companion n_lb_zero == 0 pin (its
     * last group HAS a per-batch boundary and a NON-zero incoming ro there). */
    {
        built_t B;
        if (build_honest(&B, &CFG_NOLB_MB, 21, 7)) {
            size_t n_fc = 0, n_close = 0;
            for (size_t r = 0; r < B.rows; r++) {
                const uint64_t *pr =
                    B.prep + r * (size_t)DNAC_P2C_OI_TABLE_COLS;
                n_fc += (size_t)pr[DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT];
                n_close += (size_t)pr[DNAC_P2C_OI_COL_IS_CLOSEOUT];
            }
            check("NOLB_MB: 2 closeouts, ZERO is_final_closeout (C4b vacuous)",
                  n_close == 2 && n_fc == 0);
            /* The boundary the C5 pin rests on really exists: the last group
             * has 2 acc rows and its second one carries a NON-zero incoming ro
             * (an lb group would have been forced to 0 there). */
            const long r1 = acc_row_for_height(&B, 1, 1);
            check("NOLB_MB: last group has a 2nd acc row (batch boundary)",
                  r1 >= 0);
            if (r1 >= 0) {
                const uint64_t *ar = row_of(&B, (size_t)r1);
                check("NOLB_MB: incoming ro at that boundary is NON-zero",
                      (ar[FOI_COL_RO] | ar[FOI_COL_RO + 1]) != 0);
            }
            built_free(&B);
        } else {
            check("NOLB_MB structural build", 0);
        }
    }

    /* Keep a primary REF fixture for the publics/gate negatives. */
    built_t W;
    if (!build_honest(&W, REF, 13, 2)) {
        printf("primary fixture unusable — aborting\n");
        return 1;
    }
    check("primary REF fixture accepts (0 viol)", eval_b(&W) == 0);

    /* Row landmarks in the REF schedule. */
    const long r_acc_h4 = acc_row_for_height(&W, 0, 0);   /* group0 acc      */
    const long r_clo_h4 = closeout_row_for_height(&W, 0); /* group0 closeout */
    const long r_acc_h2 = acc_row_for_height(&W, 1, 0);   /* lb group acc    */
    const long r_seed_h4 = first_seed_row(&W, 0);         /* cum0 seed       */
    const long r_sq_h2 = first_sq_row(&W, 1);             /* h2 squaring     */
    check("landmarks resolved",
          r_acc_h4 >= 0 && r_clo_h4 >= 0 && r_acc_h2 >= 0 && r_seed_h4 >= 0 &&
              r_sq_h2 >= 0);

    printf("\n-- MANDATORY A2 second-witness negatives (spec :123-136) ----\n");

    /* N-F1 — one-sided carry (C3f). A NON-final closeout's ro is set to an
     * attacker value; publics[ro_slot] is moved to match so C4a stays
     * satisfied. The last-acc -> closeout carry (C3f, gated on the CURRENT acc
     * row) forces the closeout ro == the accumulation, so C3f-ro fires. */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *cr = row_of(&B, (size_t)r_clo_h4);
        cr[FOI_COL_RO] = bump(cr[FOI_COL_RO]);       /* attacker ro.c0        */
        B.pub[B.pub_ro] = bump(B.pub[B.pub_ro]);     /* keep C4a satisfied     */
        expect_reject("N-F1 non-final closeout ro forged (C3f one-sided)", &B, 1);
        built_free(&B);
    }

    /* N-F2 — register HOLD (C2e). x_reg[0] is changed on a CHAIN row (mid-span,
     * store untouched); the ungated hold forces x_reg constant, so the single
     * transition edge out of that row fires. */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *r0 = row_of(&B, 0);
        r0[dnac_foi_col_xreg(0)] = bump(r0[dnac_foi_col_xreg(0)]);
        expect_reject("N-F2 x_reg changed mid-span, store honest (C2e HOLD)", &B,
                      1);
        built_free(&B);
    }

    /* N-F3 — capture SEED free (C2a). The seed y is set != prefix g; C2a fires,
     * and the store copy (cum_h = 0 block) also fires against the moved seed. */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *sr = row_of(&B, (size_t)r_seed_h4);
        sr[FOI_COL_Y] = bump(sr[FOI_COL_Y]);
        expect_reject("N-F3 capture seed y != prefix g (C2a + store copy)", &B,
                      2);
        built_free(&B);
    }

    /* N-F4 — per-batch lb-zero (C5). Multi-batch lb: batch 0's contribution is
     * made delta, batch 1's -delta, so ro is delta AFTER batch 0 and 0 at the
     * end. Everything (C3d/C3e/C3f/C4b) stays satisfied; only C5's incoming
     * ro == 0 at the batch boundary fires. */
    {
        built_t B;
        if (build_honest(&B, &CFG_MB, 6, 5)) {
            const long r0 = acc_row_for_height(&B, 1, 0); /* lb a=0 (gs)     */
            const long r1 = acc_row_for_height(&B, 1, 1); /* lb a=1 (bnd)    */
            check("N-F4 lb group has 2 acc rows", r0 >= 0 && r1 >= 0);
            const gold_fp2_t delta = gold_fp2_new(fp(3), fp(5)); /* both lanes */
            /* row0: ap = 1, quot = 1/zoff(a0). term0 = (pz-px)*quot = delta =>
             * pz - px = delta*zoff(a0). */
            {
                uint64_t    *rr = row_of(&B, (size_t)r0);
                const size_t a = B.a_of_row[(size_t)r0];
                const gold_fp2_t zoff = zoff_of(a);
                const gold_fp_t  px = px_of(a);
                const gold_fp2_t pz =
                    gold_fp2_add(emb(px), gold_fp2_mul(delta, zoff));
                const gold_fp2_t t = gold_fp2_sub(pz, emb(px)); /* ap = 1     */
                wr2(rr, FOI_COL_PZ, pz);
                wr2(rr, FOI_COL_T, t);
                B.pub[B.pub_zpz + 4 * a + 2] = u(pz.a);
                B.pub[B.pub_zpz + 4 * a + 3] = u(pz.b);
                /* incoming ro on the boundary row is now delta. */
                wr2(row_of(&B, (size_t)r1), FOI_COL_RO, delta);
            }
            /* row1: ap = alpha, quot = 1/zoff(a1). term1 = alpha*(pz-px)*quot =
             * -delta => pz - px = -delta*inv(alpha)*zoff(a1). */
            {
                uint64_t    *rr = row_of(&B, (size_t)r1);
                const size_t a = B.a_of_row[(size_t)r1];
                const gold_fp2_t zoff = zoff_of(a);
                const gold_fp_t  px = px_of(a);
                const gold_fp2_t neg = gold_fp2_neg(delta);
                const gold_fp2_t coeff =
                    gold_fp2_mul(gold_fp2_mul(neg, gold_fp2_inv(B.alpha)), zoff);
                const gold_fp2_t pz = gold_fp2_add(emb(px), coeff);
                const gold_fp2_t t = gold_fp2_mul(B.alpha, gold_fp2_sub(pz, emb(px)));
                wr2(rr, FOI_COL_PZ, pz);
                wr2(rr, FOI_COL_T, t);
                B.pub[B.pub_zpz + 4 * a + 2] = u(pz.a);
                B.pub[B.pub_zpz + 4 * a + 3] = u(pz.b);
            }
            expect_reject("N-F4 lb nonzero after batch 0, zeroed at end (C5)", &B,
                          2);
            built_free(&B);
        } else {
            check("N-F4 build", 0);
        }
    }

    /* N-F5 — non-boolean b on a chain row (C1c). Booleanity + the public
     * binding fire, plus the predecessor's C1b-1 (which reads this b as b'). */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        /* chain row 1 (predecessor row 0 is a chain row). */
        row_of(&B, 1)[FOI_COL_B] = 2;
        expect_reject("N-F5 non-boolean b on a chain row (C1c + C1b-1)", &B, 3);
        built_free(&B);
    }

    /* N-F7 — cfg with h_max != lgmh: rejected at the eval entry (table gate). */
    expect_bad_config("N-F7 h_max != lgmh (heights[0] != lgmh)",
                      dnac_foi_eval_trace(W.trace, W.prep, W.rows, &CFG_F7,
                                          W.pub, W.num_pub));

    printf("\n-- per-intermediate constraint-form negatives ---------------\n");

    /* N6 quot on an LB acc row (t == 0 there, so the term is 0 regardless and
     * C3f is untouched): exactly C3d's two lanes. */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *ar = row_of(&B, (size_t)r_acc_h2);
        ar[FOI_COL_QUOT] = bump(ar[FOI_COL_QUOT]);
        expect_reject("N6 quot tampered on lb acc row (C3d)", &B, 2);
        built_free(&B);
    }

    /* N7 t on an LB acc row: C3e c0 + the C3f-ro carry it feeds (2 lanes). */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *ar = row_of(&B, (size_t)r_acc_h2);
        ar[FOI_COL_T] = bump(ar[FOI_COL_T]);
        expect_reject("N7 t tampered on lb acc row (C3e + C3f-ro)", &B, 3);
        built_free(&B);
    }

    /* N8 ro on a group-start acc row: C3a (ro == 0) + the C3f-ro carry. */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *ar = row_of(&B, (size_t)r_acc_h4);
        ar[FOI_COL_RO] = bump(ar[FOI_COL_RO]);
        expect_reject("N8 ro != 0 on group-start row (C3a + C3f-ro)", &B, 2);
        built_free(&B);
    }

    /* N9 alpha_pow on a group-start acc row: C3a (== 1) plus every form that
     * reads alpha_pow (C3e, C3f-ap). Caught (count not pinned — it rests on
     * several fixture lanes being non-zero). */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *ar = row_of(&B, (size_t)r_acc_h4);
        ar[FOI_COL_ALPHA_POW] = bump(ar[FOI_COL_ALPHA_POW]);
        expect_reject("N9 alpha_pow != 1 on group-start row (C3a + ...)", &B, 0);
        built_free(&B);
    }

    /* N10 x (eval point) on an LB acc row: C3b (x == x_reg) + C3d (denom uses
     * x); term stays 0 (lb t == 0) so C3f is untouched. */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *ar = row_of(&B, (size_t)r_acc_h2);
        ar[FOI_COL_X] = bump(ar[FOI_COL_X]);
        expect_reject("N10 x tampered on lb acc row (C3b + C3d)", &B, 3);
        built_free(&B);
    }

    /* N11 y on a SQUARING row: the squaring INTO it and the squaring OUT of it
     * both fire (C2b). */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *sr = row_of(&B, (size_t)r_sq_h2);
        sr[FOI_COL_Y] = bump(sr[FOI_COL_Y]);
        expect_reject("N11 y tampered on a squaring row (C2b x2)", &B, 2);
        built_free(&B);
    }

    /* N12 gb on a chain row: the predecessor C1b-1 and C1b-2 both read it. */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *cr = row_of(&B, 1); /* chain row 1, predecessor row 0 */
        cr[FOI_COL_GB] = bump(cr[FOI_COL_GB]);
        expect_reject("N12 gb tampered on chain row 1 (C1b-1 + C1b-2)", &B, 2);
        built_free(&B);
    }

    /* N33 (s2) p_x TRACE column on an lb acc row. Before C3g existed this was
     * the free-witness hole: p_x could be anything as long as t moved with it.
     * Here only the column moves, so C3g fires against the (untouched) public,
     * and C3e's c0 lane fires because t no longer equals ap*(p_z - p_x). The c1
     * lane does NOT — this row is a group start, so ap == (1,0) and c1 reads
     * ap0*pz1 + ap1*d0, which p_x does not enter. C3f-ro reads t and quot only,
     * both untouched. Exactly 2. */
    {
        built_t B;
        build_honest(&B, REF, 13, 2);
        uint64_t *ar = row_of(&B, (size_t)r_acc_h2);
        ar[FOI_COL_PX] = bump(ar[FOI_COL_PX]);
        expect_reject("N33 p_x trace column tampered (C3g + C3e-c0)", &B, 2);
        built_free(&B);
    }

    printf("\n-- publics-binding negatives --------------------------------\n");

    /* N13 index bit public flipped: exactly C1c-p on its chain row. */
    {
        const uint64_t sv = W.pub[3]; /* bit 3 read by chain row 0 */
        W.pub[3] ^= 1u;
        expect_reject("N13 index-bit public flipped (C1c-p)", &W, 1);
        W.pub[3] = sv;
    }
    /* N14 z public lane moved: exactly C3c on its acc row. */
    {
        const uint64_t sv = W.pub[W.pub_zpz];
        W.pub[W.pub_zpz] = bump(sv);
        expect_reject("N14 z public lane moved (C3c)", &W, 1);
        W.pub[W.pub_zpz] = sv;
    }
    /* N15 p_z public lane moved: exactly C3c on its acc row. */
    {
        const uint64_t sv = W.pub[W.pub_zpz + 2];
        W.pub[W.pub_zpz + 2] = bump(sv);
        expect_reject("N15 p_z public lane moved (C3c)", &W, 1);
        W.pub[W.pub_zpz + 2] = sv;
    }
    /* N16 exported-ro public moved (non-final height): exactly C4a. */
    {
        const uint64_t sv = W.pub[W.pub_ro]; /* height 0 (non-lb) */
        W.pub[W.pub_ro] = bump(sv);
        expect_reject("N16 exported-ro public moved, non-final (C4a)", &W, 1);
        W.pub[W.pub_ro] = sv;
    }
    /* N17 alpha public lane moved: C3f-ap fires on each group-start acc row
     * (both REF groups have ap1 == 0, so only the c0 lane of each). */
    {
        const uint64_t sv = W.pub[W.pub_alpha];
        W.pub[W.pub_alpha] = bump(sv);
        expect_reject("N17 alpha public lane moved (C3f-ap, both groups)", &W, 2);
        W.pub[W.pub_alpha] = sv;
    }
    /* N34 (s2) p_x PUBLIC lane moved: exactly C3g on its acc row. Nothing else
     * reads the p_x public — C3e reads the trace column — so the count is 1,
     * and that is what pins C3g as its own form rather than a side effect. */
    {
        const uint64_t sv = W.pub[W.pub_px];
        W.pub[W.pub_px] = bump(sv);
        expect_reject("N34 p_x public lane moved (C3g)", &W, 1);
        W.pub[W.pub_px] = sv;
    }
    /* N34b the SECOND acc row's p_x public: the per-row slot really is per-row
     * (a single shared slot would have been caught by neither N34 alone). */
    {
        const uint64_t sv = W.pub[W.pub_px + 1];
        W.pub[W.pub_px + 1] = bump(sv);
        expect_reject("N34b p_x public lane 1 moved (C3g, per-row slot)", &W, 1);
        W.pub[W.pub_px + 1] = sv;
    }
    check("N13-N17/N34 publics restored", eval_b(&W) == 0);

    printf("\n-- fail-close negatives (canonicality / shape / terminality) \n");

    /* N18-N22 + N35 publics canonicality, ONE per public region (OBL-2). */
    {
        const size_t region[6] = {0, W.pub_alpha, W.pub_zpz, W.pub_zpz + 2,
                                   W.pub_ro, W.pub_px};
        const char  *name[6] = {"N18 public >= p: index bit",
                                "N19 public >= p: alpha lane",
                                "N20 public >= p: z lane",
                                "N21 public >= p: p_z lane",
                                "N22 public >= p: exported ro",
                                "N35 public >= p: p_x lane (s2 region)"};
        for (int i = 0; i < 6; i++) {
            const uint64_t sv = W.pub[region[i]];
            W.pub[region[i]] = GOLDILOCKS_P + (sv & 0xFFu); /* aliases, no wrap */
            expect_bad_config(name[i], eval_b(&W));
            W.pub[region[i]] = sv;
        }
        check("N18-N22/N35 publics restored", eval_b(&W) == 0);
    }

    /* N23/N24 num_publics EXACT, not a bound. */
    expect_bad_config("N23 num_publics + 1",
                      dnac_foi_eval_trace(W.trace, W.prep, W.rows, W.cfg, W.pub,
                                          W.num_pub + 1));
    expect_bad_config("N24 num_publics - 1",
                      dnac_foi_eval_trace(W.trace, W.prep, W.rows, W.cfg, W.pub,
                                          W.num_pub - 1));

    /* N25 schedule conformance: n_rows one short of the pinned schedule. */
    expect_bad_config("N25 n_rows one short (schedule conformance)",
                      dnac_foi_eval_trace(W.trace, W.prep, W.rows - 1, W.cfg,
                                          W.pub, W.num_pub));

    /* N26 terminality: the last row made typed. */
    {
        uint64_t *last = W.prep + (W.rows - 1) * (size_t)DNAC_P2C_OI_TABLE_COLS;
        const uint64_t sp = last[DNAC_P2C_OI_COL_IS_PAD];
        const uint64_t sc = last[DNAC_P2C_OI_COL_IS_CHAIN];
        last[DNAC_P2C_OI_COL_IS_PAD] = 0;
        last[DNAC_P2C_OI_COL_IS_CHAIN] = 1;
        expect_bad_config("N26 last row typed (terminality)", eval_b(&W));
        last[DNAC_P2C_OI_COL_IS_PAD] = sp;
        last[DNAC_P2C_OI_COL_IS_CHAIN] = sc;
        check("N26 prep restored", eval_b(&W) == 0);
    }

    /* N27/N28 PIN-2 shape: mixed main_next / prep_next (via eval_row). */
    expect_bad_config("N27 main_next without prep_next (PIN-2 shape)",
                      dnac_foi_eval_row(W.trace, W.trace + W.num_cols, W.prep,
                                        NULL, 1, W.cfg, W.pub, W.num_pub));
    expect_bad_config("N28 prep_next without main_next",
                      dnac_foi_eval_row(W.trace, NULL, W.prep,
                                        W.prep + DNAC_P2C_OI_TABLE_COLS, 1, W.cfg,
                                        W.pub, W.num_pub));

    /* N29-N32 eval-entry cfg gates. */
    expect_bad_config("N29 NULL cfg",
                      dnac_foi_eval_trace(W.trace, W.prep, W.rows, NULL, W.pub,
                                          W.num_pub));
    expect_bad_config("N30 lgmh > 32 (two-adicity)",
                      dnac_foi_eval_trace(W.trace, W.prep, W.rows, &CFG_LGMH33,
                                          W.pub, W.num_pub));
    expect_bad_config("N31 num_queries == 0",
                      dnac_foi_eval_trace(W.trace, W.prep, W.rows, &CFG_Q0, W.pub,
                                          W.num_pub));

    /* N32 (POSITIVE) — C6: a non-terminal padding row carries no GATED
     * main-trace constraint, so garbage in its FREE columns still evaluates
     * to 0. ⚠ The x_reg[k] block is the ONE exception: the STRENGTHENED
     * (ungated) C2e HOLD pins x_reg globally-constant across EVERY transition,
     * padding included, so it is NOT free — that is the deliberate F2 fix, not
     * a defect (O9 root-cause 2026-07-29, ORCHESTRATOR; the honest builder sets
     * x_reg constant everywhere, so all 5 accepts hold). N32b below proves the
     * hold DOES fire on a padding row's x_reg. */
    {
        if (W.rows - W.sched >= 2) {
            uint64_t *pr = row_of(&W, W.sched);
            /* garbage in every FREE column (all but the x_reg block). */
            for (size_t c = 0; c < W.num_cols; c++) {
                if (c >= FOI_COL_XREG && c < FOI_COL_XREG + W.num_heights)
                    continue; /* held by C2e — leave at its constant value */
                pr[c] = u(tfp((uint64_t)c + 3, 77));
            }
            check("N32 garbage on a non-terminal padding row's FREE columns "
                  "accepted (C6)", eval_b(&W) == 0);
            /* N32b — the ungated C2e HOLD fires even on padding: corrupt one
             * x_reg cell on this padding row → the pad->pad transition catches
             * it (exactly the F2 mid-span protection, extended). */
            const uint64_t saved = pr[FOI_COL_XREG];
            pr[FOI_COL_XREG] = u(tfp(0x9999, 5));
            check("N32b padding x_reg corruption caught by ungated C2e (>=1 viol)",
                  eval_b(&W) >= 1);
            pr[FOI_COL_XREG] = saved;
            memset(pr, 0, W.num_cols * sizeof(uint64_t));
        } else {
            check("N32 (skipped: no non-terminal padding row)", 1);
        }
    }

    built_free(&W);

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("P2c open_input AIR: %d FAIL\n", fails);
        return 1;
    }
    /* Roster, audited by ENUMERATION one-by-one (count-KAFADAN discipline):
     *   accepts     7   REF@0, REF@11, REF@13, WIDE lgmh6, MB 2-batch-lb,
     *                   NOLB (lb-less), NOLB_MB (lb-less, 2-batch last group)
     *   negatives  36   N-F1..N-F5, N-F7 (6 mandatory) + N6..N12, N33 (8 form,
     *                   N33 is the s2 p_x trace column) + N13..N17, N34, N34b
     *                   (7 publics) + N18..N22, N35 (6 canonicality) +
     *                   N23..N26 (4 shape) + N27..N28 (2 PIN-2) +
     *                   N29..N31 (3 cfg gates) = 6+8+7+6+4+2+3 = 36
     *                   pinned exact-count (19): N-F1(1) N-F2(1) N-F3(2)
     *                     N-F4(2) N-F5(3) N6(2) N7(3) N8(2) N10(3) N11(2)
     *                     N12(2) N13(1) N14(1) N15(1) N16(1) N17(2) N33(2)
     *                     N34(1) N34b(1)
     *                   caught-without-count (1): N9
     *                   fail-close (16): N-F7 N18 N19 N20 N21 N22 N35 N23 N24
     *                     N25 N26 N27 N28 N29 N30 N31
     *   assertions      layout/offset (12, incl. the 2 s2 p_x-region pins) +
     *                   fixture-accept + landmarks + N-F4 lb-row + the 3
     *                   FLEET-029 lb-less structural pins + restore/positive
     *                   (N13-17/N34, N18-22/N35, N26, N32 C6 padding-freedom) */
    printf("P2c open_input AIR: 7 honest walks (native x_h + accumulation\n"
           "  replay, x_h cross-checked at every store row) + 36 negatives\n"
           "  (19 exact-count pinned, 1 caught, 16 fail-close; N-F1..N-F5/N-F7\n"
           "  are the MANDATORY A2 catches, N33/N34/N34b/N35 the s2 p_x\n"
           "  binding) + layout/restore assertions — PASS\n");
    return 0;
}
