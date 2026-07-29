/**
 * @file fri_air.c
 * @brief P2c slice 1 — the FRI fold-walk control AIR: constraint evaluation.
 *
 * Every block below names (a) the design-doc §0.5 form it discharges —
 * dnac/docs/plans/2026-07-29-p2c-fri-in-air-design.md, local-only — and (b) the
 * native `fri_verifier.c` / `fri_fold.c` line whose semantics it mirrors, or
 * the pinned upstream line it ports.
 *
 * Pinned references used by the citations:
 *   P3rec  = Plonky3/Plonky3-recursion @ b36339709a7a67ee9760fb578b3d4339fd983709
 *            (`recursion/circuit/src/fri/verifier.rs` unless stated otherwise)
 *   P3     = Plonky3 @ 82cfad73 (bare cites), v0.6.2 @ 11cc5849 where stated
 *
 * See fri_air.h for the layout contract, the public-value layout, the
 * PIN-1-P2c / PIN-2 prerequisites, the OBL ledger and the fail-close contract.
 *
 * ── DOC-CITE BASELINE (FLEET 022 A1-F5): `design §0.5 :NNN` cites in this
 * file and its header are against the doc AS OF 2026-07-29 IMPLEMENTATION
 * TIME; the doc has since gained fold-record lines, so exact numbers drift
 * by a few lines while every cited CLAIM is intact (A1-verified). Resolve
 * drifted cites by the stable §/constraint-form anchors (C2a..C5, G1-G7),
 * the RESUME "CITATION BASELINE" practice. ──────────────────────────────────
 *
 * ── DEGREE TABLE (design §0.5 :327-329: <= 3 INCLUSIVE of the single prep
 * gate; every transition is gated by exactly ONE degree-1 prep cell, never a
 * product of two — that is why the pair gates are generator-emitted) ─────────
 *
 *   block  form                                          gate  inner  total
 *   ---------------------------------------------------------------------
 *   C2a    b*(b-1)                                        1      2      3
 *   C2b    pos_k * (b - publics[bit])                     1      1      2
 *   C3a    row 0: g - (1 + b*(G_0 - 1))                   -      2      2
 *   C3b    is_chainpair * (gb' - g*b')                    1      2      3
 *   C3c    is_chainpair * (g' - g - gb'*(G' - 1))         1      2      3
 *   C3d    is_handoff   * (g' - g)                        1      1      2
 *   C4a    is_fold * (g*inv - NEG_HALF)                   1      2      3
 *   C4b    is_fold * (g_sq - g*g)                         1      2      3
 *   C4c    is_fold * (t1_c - (1-2b)*(s_c - f_c))          1      2      3
 *   C4d    is_fold * (t2 - (beta - g)*t1)   [2 lanes]     1      2      3
 *   C4e    is_fold * (beta_sq - beta*beta)  [2 lanes]     1      2      3
 *   C4f    is_fold * (rterm - beta_sq*ro)   [2 lanes]     1      2      3
 *   C4g    pos_k * (beta_c - publics[beta])               1      1      2
 *   C4h    pos_k * (ro_c - publics[ro])                   1      1      2
 *   C4i    (is_fold - is_rollin) * ro_c                   1      1      2
 *   C4j    is_handoff * (f'_c - publics[f_init])          1      1      2
 *   C4k    is_foldpair * (g' - g_sq*(1 - 2b'))            1      2      3
 *   C4l    is_fold * (f'_c - f_c - b*(s_c-f_c)
 *                          - t2_c*inv - rterm_c)          1      2      3
 *   C5     is_terminal * (f_c - publics[final_poly0])     1      1      2
 *   C6     (padding rows carry NO main-trace constraint)  -      -      -
 *
 * Max degree 3, inside the FRI log_blowup = 2 envelope
 * (shielded_fri_params.h:138). C1 (type discipline) is NOT here: it moved to
 * the table generator + static validator + root pin (design §0.5 :330-332, the
 * FLEET 020 A2-F5 fold).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_air.h"

#include "field_goldilocks.h"

/* NEG_HALF's defining identity, pinned at COMPILE time so the literal cannot
 * rot (the derivation is in fri_air.h). p is odd, hence (p-1)/2 is an integer
 * and 2*(p-1)/2 + 1 == p == 0 (mod p). Both computations below are exact in
 * u64: p < 2^64 and 2*NEG_HALF == p - 1. */
_Static_assert(GOLDILOCKS_P % UINT64_C(2) == UINT64_C(1),
               "Goldilocks p must be odd for -1/2 == (p-1)/2");
_Static_assert(UINT64_C(2) * FAIR_NEG_HALF + UINT64_C(1) == GOLDILOCKS_P,
               "FAIR_NEG_HALF must satisfy 2*x + 1 == 0 (mod p)");

/* ── local field shorthands (mmcs_air.c / transcript_air.c idiom) ─────────── */
static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/** Assert a constraint residual is zero; count the violation otherwise. */
static inline void az(int *v, gold_fp_t residual) {
    if (!gold_fp_is_zero(residual)) (*v)++;
}

/** Sentinel in `rollin_rank`: this fold row carries no roll-in slot. */
#define FAIR_NO_ROLLIN ((size_t)-1)

/* ══════════════════════════ schedule (from the generator) ═════════════════
 * The row schedule has exactly ONE authority: `dnac_p2c_table_generate` /
 * `dnac_p2c_table_row` (fri_air_table.c:167-253). This file does NOT re-derive
 * it — it asks the generator for the shape and reads the ROLL-IN PLACEMENT back
 * out of it row by row, exactly as mmcs_air.c reads the leaf-row count back out
 * of its generator (mmcs_air.c:77-84). Pure function of `cfg`: no clock, no
 * RNG, no witness input (design §1 D-1/D-2).
 *
 * Calling the three shape accessors is ALSO how gates G1/G2/G3/G7 are run: all
 * four live in the table module's single `p2c_cfg_check` (fri_air_table.c:47-102
 * — max_log_arity != 1, log_final_poly_len != 0, lgmh outside [2,32], R
 * underflow, roll-in heights out of range or not strictly descending,
 * num_queries 0 or > MAX), and every accessor returns 0 for a config it
 * rejects. A cfg the TABLE rejects is a BAD_CONFIG for the AIR, by
 * construction, so the two can never drift apart.
 */
typedef struct {
    size_t lgmh;
    size_t n_chain;     /* lgmh - 1                                        */
    size_t n_fold;      /* R = lgmh - log_blowup - log_final_poly_len      */
    size_t sched;       /* n_chain + n_fold — the non-padding prefix       */
    size_t rows;        /* padded table height (== trace height)           */
    size_t pub_beta;    /* public-region offsets (fri_air.h layout)        */
    size_t pub_finit;
    size_t pub_ro;
    size_t pub_final;
    size_t num_publics;
    /* Roll-in RANK of fold row r among the cfg's height-descending roll-in
     * set, or FAIR_NO_ROLLIN. The rank IS the public slot index: the cfg's
     * heights are strictly descending (fri_air_table.c:87-91) and fold row r
     * has post-fold height lgmh-1-r (fri_verifier.c:596), so descending
     * heights == ascending fold rows and the two orders agree. */
    size_t rollin_rank[DNAC_P2C_MAX_LGMH];
} fair_sched_t;

static int fair_schedule(const dnac_p2c_table_cfg_t *cfg, fair_sched_t *s) {
    if (cfg == NULL) return 0;

    const size_t n_chain = dnac_p2c_chain_rows(cfg);
    const size_t n_fold = dnac_p2c_fold_rows(cfg);
    const size_t rows = dnac_p2c_table_rows(cfg);
    /* 0 from any accessor == "the table module rejected this cfg" (G1/G2/G3/G7).
     * n_chain >= 1 and n_fold >= 1 hold for every accepted cfg. */
    if (n_chain == 0 || n_fold == 0 || rows == 0) return 0;

    /* Capacity of `rollin_rank`. R <= lgmh <= DNAC_P2C_MAX_LGMH holds for every
     * accepted cfg (R = lgmh - lb - lfpl <= lgmh); kept fail-close so raising
     * MAX_LGMH cannot silently overrun this array instead of rejecting. */
    if (n_fold > DNAC_P2C_MAX_LGMH) return 0;

    /* A padding row MUST exist: the terminal boundary C5 lives on it and the
     * last fold row's C4l transition needs a successor. The table always pads
     * (fri_air_table.c:160), so this is a fail-close rail, not a filter. */
    if (n_chain + n_fold >= rows) return 0;

    /* Roll-in placement, READ BACK OUT of the schedule authority. */
    size_t rank = 0;
    for (size_t r = 0; r < n_fold; r++) {
        dnac_p2c_row_t rec;
        if (dnac_p2c_table_row(cfg, n_chain + r, &rec) != DNAC_P2C_TABLE_OK)
            return 0;
        /* The generator and this file must agree about what row n_chain+r IS.
         * A disagreement is a contract break, not something to guess through. */
        if (rec.type != DNAC_P2C_ROW_FOLD || rec.type_step != r) return 0;
        s->rollin_rank[r] = rec.is_rollin ? rank++ : FAIR_NO_ROLLIN;
    }
    if (rank != cfg->num_rollin) return 0;

    s->lgmh = cfg->lgmh;
    s->n_chain = n_chain;
    s->n_fold = n_fold;
    s->sched = n_chain + n_fold;
    s->rows = rows;
    /* Public layout (fri_air.h): bits | betas | f_init | roll-ins | final_poly0 */
    s->pub_beta = cfg->lgmh;
    s->pub_finit = s->pub_beta + FAIR_EXT_LANES * n_fold;
    s->pub_ro = s->pub_finit + FAIR_EXT_LANES;
    s->pub_final = s->pub_ro + FAIR_EXT_LANES * cfg->num_rollin;
    s->num_publics = s->pub_final + FAIR_EXT_LANES;
    return 1;
}

/* ══════════════════════════ public helpers ═══════════════════════════════ */

size_t dnac_fair_pub_beta_off(const dnac_p2c_table_cfg_t *cfg) {
    fair_sched_t s;
    if (!fair_schedule(cfg, &s)) return 0;
    return s.pub_beta;
}

size_t dnac_fair_pub_finit_off(const dnac_p2c_table_cfg_t *cfg) {
    fair_sched_t s;
    if (!fair_schedule(cfg, &s)) return 0;
    return s.pub_finit;
}

size_t dnac_fair_pub_ro_off(const dnac_p2c_table_cfg_t *cfg) {
    fair_sched_t s;
    if (!fair_schedule(cfg, &s)) return 0;
    return s.pub_ro;
}

size_t dnac_fair_pub_final_off(const dnac_p2c_table_cfg_t *cfg) {
    fair_sched_t s;
    if (!fair_schedule(cfg, &s)) return 0;
    return s.pub_final;
}

size_t dnac_fair_num_publics(const dnac_p2c_table_cfg_t *cfg) {
    fair_sched_t s;
    if (!fair_schedule(cfg, &s)) return 0;
    return s.num_publics;
}

bool dnac_fair_layout_check(void) {
    /* Column blocks, in the design's order, no overlap and no gap. */
    if (FAIR_COL_B != (size_t)0) return false;
    if (FAIR_COL_G != FAIR_COL_B + 1) return false;
    if (FAIR_COL_G_SQ != FAIR_COL_G + 1) return false;
    if (FAIR_COL_GB != FAIR_COL_G_SQ + 1) return false;
    if (FAIR_COL_F != FAIR_COL_GB + 1) return false;
    if (FAIR_COL_S != FAIR_COL_F + FAIR_EXT_LANES) return false;
    if (FAIR_COL_INV != FAIR_COL_S + FAIR_EXT_LANES) return false;
    if (FAIR_COL_BETA != FAIR_COL_INV + 1) return false;
    if (FAIR_COL_BETA_SQ != FAIR_COL_BETA + FAIR_EXT_LANES) return false;
    if (FAIR_COL_T1 != FAIR_COL_BETA_SQ + FAIR_EXT_LANES) return false;
    if (FAIR_COL_T2 != FAIR_COL_T1 + FAIR_EXT_LANES) return false;
    if (FAIR_COL_RTERM != FAIR_COL_T2 + FAIR_EXT_LANES) return false;
    if (FAIR_COL_RO != FAIR_COL_RTERM + FAIR_EXT_LANES) return false;
    if (FAIR_NUM_COLS != FAIR_COL_RO + FAIR_EXT_LANES) return false;
    /* The re-counted width (design §4 item 2): 5 base lanes (b, g, g_sq, gb,
     * inv) + 8 fp2 blocks x 2 = 21. The doc's summary number said 20; the LIST
     * says 21 and the list is what is implemented. */
    if (FAIR_NUM_COLS != (size_t)21) return false;
    if (FAIR_EXT_LANES != (size_t)2) return false;
    /* fp2 lane accessor stays inside its block. */
    if (fair_ext_off(FAIR_COL_F, 0) != FAIR_COL_F) return false;
    if (fair_ext_off(FAIR_COL_F, FAIR_EXT_LANES - 1) != FAIR_COL_F + 1)
        return false;

    /* NEG_HALF: 2*x + 1 == 0 (mod p), re-derived through the field API rather
     * than trusted from the literal. */
    {
        const gold_fp_t h = fp(FAIR_NEG_HALF);
        if (!gold_fp_is_zero(add(add(h, h), gold_fp_one()))) return false;
    }

    /* Public regions disjoint and ordered on the PINNED reference cfg
     * (lgmh 13, R 11, 2 roll-ins => 13 + 22 + 2 + 4 + 2 = 43). */
    {
        const dnac_p2c_table_cfg_t *ref = dnac_p2c_ref_cfg();
        const size_t beta = dnac_fair_pub_beta_off(ref);
        const size_t fin = dnac_fair_pub_finit_off(ref);
        const size_t ro = dnac_fair_pub_ro_off(ref);
        const size_t fpoly = dnac_fair_pub_final_off(ref);
        const size_t n = dnac_fair_num_publics(ref);
        if (FAIR_PUB_BITS_OFF != 0) return false;
        if (beta != DNAC_P2C_REF_LGMH) return false;
        if (fin != beta + FAIR_EXT_LANES * dnac_p2c_fold_rows(ref)) return false;
        if (ro != fin + FAIR_EXT_LANES) return false;
        if (fpoly != ro + FAIR_EXT_LANES * DNAC_P2C_REF_NUM_ROLLIN) return false;
        if (n != fpoly + FAIR_EXT_LANES) return false;
        if (n != (size_t)43) return false;
    }
    return true;
}

/* ══════════════════════════ constraint evaluation ════════════════════════ */

int dnac_fair_eval_row(const uint64_t *main_local, const uint64_t *main_next,
                       const uint64_t *prep_local, const uint64_t *prep_next,
                       int is_first_row, const dnac_p2c_table_cfg_t *cfg,
                       const uint64_t *publics, size_t num_publics) {
    if (!main_local || !prep_local || !cfg || !publics)
        return FAIR_VIOL_BAD_CONFIG;

    /* ── G5 (PIN-2 shape, design §0.5 :283) ────────────────────────────────
     * The main and preprocessed windows are ONE window. A caller that has the
     * next MAIN row but not the next PREPROCESSED row is exactly the
     * `prep_next = 0` shape; C3's chain transition reads the NEXT row's
     * `g_pow2` literal, so evaluating against nothing would make the chain
     * multiply vacuous. Rejected rather than silently evaluated. */
    if ((main_next == NULL) != (prep_next == NULL)) return FAIR_VIOL_BAD_CONFIG;

    /* ── G1 / G2 / G3 / G7 (cfg gates, run through the table module) ──────── */
    fair_sched_t s;
    if (!fair_schedule(cfg, &s)) return FAIR_VIOL_BAD_CONFIG;

    /* ── G6a: num_publics EXACT (design §0.5 :284) ────────────────────────
     * This is also what pins the publics SHAPE today — the table root does not
     * (OBL-4c, fri_air.h). Not ">=": a longer public vector would leave a tail
     * no constraint reads. */
    if (num_publics != s.num_publics) return FAIR_VIOL_BAD_CONFIG;

    /* ── G6b: publics canonicality, FAIL-CLOSE (OBL-2 / P2b A2-F1) ────────
     * `fp()` reduces mod p, so x and x+p alias inside the field view, while
     * every downstream u64 consumer of a public is representation-sensitive
     * (a bit public's low bit, a beta lane re-observed into a transcript, a
     * final_poly lane memcmp'd). Accepting a non-canonical public would let the
     * AIR prove a statement about publics the consumer reads DIFFERENTLY.
     * Mirror the native posture (the wire layer's rd_base >= p reject —
     * fri_proof_codec.c, which fri_verifier.c relies on): reject. */
    for (size_t i = 0; i < num_publics; i++)
        if (publics[i] >= GOLDILOCKS_P) return FAIR_VIOL_BAD_CONFIG;

    int v = 0;
    const gold_fp_t one = gold_fp_one();

    /* ══ Column reads ═════════════════════════════════════════════════════ */
    const gold_fp_t b = fp(main_local[FAIR_COL_B]);
    const gold_fp_t g = fp(main_local[FAIR_COL_G]);
    const gold_fp_t g_sq = fp(main_local[FAIR_COL_G_SQ]);
    const gold_fp_t inv = fp(main_local[FAIR_COL_INV]);
    const gold_fp_t f0 = fp(main_local[FAIR_COL_F]);
    const gold_fp_t f1 = fp(main_local[FAIR_COL_F + 1]);
    const gold_fp_t s0 = fp(main_local[FAIR_COL_S]);
    const gold_fp_t s1 = fp(main_local[FAIR_COL_S + 1]);
    const gold_fp_t be0 = fp(main_local[FAIR_COL_BETA]);
    const gold_fp_t be1 = fp(main_local[FAIR_COL_BETA + 1]);
    const gold_fp_t bs0 = fp(main_local[FAIR_COL_BETA_SQ]);
    const gold_fp_t bs1 = fp(main_local[FAIR_COL_BETA_SQ + 1]);
    const gold_fp_t t10 = fp(main_local[FAIR_COL_T1]);
    const gold_fp_t t11 = fp(main_local[FAIR_COL_T1 + 1]);
    const gold_fp_t t20 = fp(main_local[FAIR_COL_T2]);
    const gold_fp_t t21 = fp(main_local[FAIR_COL_T2 + 1]);
    const gold_fp_t rt0 = fp(main_local[FAIR_COL_RTERM]);
    const gold_fp_t rt1 = fp(main_local[FAIR_COL_RTERM + 1]);
    const gold_fp_t ro0 = fp(main_local[FAIR_COL_RO]);
    const gold_fp_t ro1 = fp(main_local[FAIR_COL_RO + 1]);

    const gold_fp_t p_chain = fp(prep_local[DNAC_P2C_COL_IS_CHAIN]);
    const gold_fp_t p_fold = fp(prep_local[DNAC_P2C_COL_IS_FOLD]);
    const gold_fp_t p_cpair = fp(prep_local[DNAC_P2C_COL_IS_CHAINPAIR]);
    const gold_fp_t p_hand = fp(prep_local[DNAC_P2C_COL_IS_HANDOFF]);
    const gold_fp_t p_fpair = fp(prep_local[DNAC_P2C_COL_IS_FOLDPAIR]);
    const gold_fp_t p_term = fp(prep_local[DNAC_P2C_COL_IS_TERMINAL]);
    const gold_fp_t p_roll = fp(prep_local[DNAC_P2C_COL_IS_ROLLIN]);
    const gold_fp_t p_gpow = fp(prep_local[DNAC_P2C_COL_G_POW2]);
    /* A row is TYPED iff it is a chain row or a fold row. Padding rows have
     * both zero, hence carry NO main-trace constraint (C6, design §0.5
     * :388-391 — the v1 "unchanged/zeroed" reading was REMOVED because zeroing
     * collided with `g*inv = -1/2`). */
    const gold_fp_t typed = add(p_chain, p_fold);
    /* W = 7 = GOLDILOCKS_EXT_W (field_goldilocks.h:38-40) — fp2 = F[u]/(u^2 - W),
     * design §0.5 :292-302. Written once; every fp2 product below uses it. */
    const gold_fp_t W = fp(GOLDILOCKS_EXT_W);

    /* ══ C2a — bit booleanity (design §0.5 :331-338) ═══════════════════════
     * Upstream's `select(b,t,s)` does NOT imply booleanity
     * (P3rec circuit_builder.rs:713-735, "Call assert_bool(b) beforehand"), and
     * `assert_bool` emits exactly `b*(b-1) = 0` (:658-664). We own the rule
     * here rather than inherit an assumption, on every TYPED row — which via
     * C2b makes the public bits boolean transitively (OBL-3). */
    az(&v, mul(typed, mul(b, sub(b, one))));

    /* ══ C2b — bit <-> public binding, gated by the step one-hot ═══════════
     * Chain row j reads public bit lgmh-1-j (MSB-first accumulation of the x0
     * anchor); fold row r reads public bit r (LSB-first, the native's own
     * order: `idx >>= log_arity` per phase, fri_verifier.c:558). The overlap
     * [1, R-1] is read TWICE — a strength: it forces the chain and the walk
     * onto ONE index. `pos` is PREPROCESSED here (unlike P2b's main-trace
     * one-hot), so it is a degree-1 selector, and the within-type index is
     * recovered at cfg-constant offsets (fri_air_table.h:81-98).
     *
     * Positions k >= sched carry pos[k] = 0 in every generated table
     * (validator check 6, fri_air_table.c:347-355) and address no public, so
     * the loop stops at `sched`. Under PIN-1-P2c that zeroing is the
     * generator's obligation, frozen by the root pin — the same posture the
     * whole preprocessed window has. */
    for (size_t k = 0; k < s.sched; k++) {
        const gold_fp_t pk = fp(prep_local[dnac_p2c_col_pos(k)]);
        const size_t bit = (k < s.n_chain) ? (s.lgmh - 1 - k) : (k - s.n_chain);
        az(&v, mul(pk, sub(b, fp(publics[FAIR_PUB_BITS_OFF + bit]))));
    }

    /* ══ C3a — the x0 chain's ROW-0 BOUNDARY (design §0.5 :344-345) ════════
     * `g = 1 + b*(G_0 - 1)`: a MULTIPLY FROM 1, not a bare `g = 1`. This is the
     * FLEET 020 A2-F4 fix — reading the chain->fold handoff as a plain copy
     * while row 0 only *initialised* g silently drops bit_{lgmh-1}'s factor,
     * giving the wrong x0 for half of all indices, self-consistently and
     * (at lfpl = 0) invisibly. The multiplication COUNT is the invariant:
     * 1 (this form) + (n_chain - 1) chain transitions = lgmh - 1 bits absorbed,
     * and the table's static validator checks exactly that identity
     * (fri_air_table.c:357-367, DNAC_P2C_DEFECT_MULCOUNT).
     *
     * `G_0` is THIS row's preprocessed `g_pow2` literal; the port is upstream's
     * per-step `g' = g * (1 + b*(G_j - 1))` select-mul chain
     * (P3rec verifier.rs:524-527, `precompute_subgroup_starts` :475-541).
     * Ungated by row type: trace row 0 IS chain row 0 under the pinned table
     * (validator checks 4+5 pin the typed-prefix layout), so applying it
     * unconditionally on the first row is strictly stronger than gating it. */
    if (is_first_row) az(&v, sub(g, add(one, mul(b, sub(p_gpow, one)))));

    /* ══ C4a — the div form: g * inv = -1/2 (design §0.5 :356-357) ═════════
     * Ports `inv = div(-1/2, x0)` (P3rec verifier.rs:619) through
     * `div(lhs,rhs)`'s emitted constraint `rhs*out = lhs`
     * (P3rec circuit_builder.rs:637-649). The numerator is a NONZERO constant, so
     * x0 = 0 is UNSATISFIABLE: division by zero is fail-close by construction,
     * which is security goal G3 (no column of the x0 chain is free). */
    az(&v, mul(p_fold, sub(mul(g, inv), fp(FAIR_NEG_HALF))));

    /* ══ C4b — g_sq = g*g (degree relief for the x0 recurrence C4k) ════════ */
    az(&v, mul(p_fold, sub(g_sq, mul(g, g))));

    /* ══ C4c — t1 = (1 - 2b) * (s - f), lanewise ═══════════════════════════
     * ⚠ SIGN. The reference factor is `two_b_m1 = 2*(1-b) - 1 = 1 - 2b`, from
     * `sibling_is_right = 1 - b` (P3rec verifier.rs:615) fed into
     * `e1_minus_e0 = (2*sibling_is_right - 1) * (sibling - folded)` (:621-623).
     * The design's v1 had (2b-1); FLEET 020 found it INDEPENDENTLY through both
     * lenses (A1-F1 KAFADAN == A2-F1 CRITICAL, with a numeric second witness at
     * b = 0, beta = 0) — the flipped sign folds at the REFLECTED challenge
     * 2*x0 - beta, which is a different, still-satisfiable statement. Root
     * cause was a sign lost across a sibling_is_right -> b rename. The
     * test suite carries this exact negative. */
    {
        const gold_fp_t one_m_2b = sub(one, add(b, b));
        az(&v, mul(p_fold, sub(t10, mul(one_m_2b, sub(s0, f0)))));
        az(&v, mul(p_fold, sub(t11, mul(one_m_2b, sub(s1, f1)))));
    }

    /* ══ C4d — t2 = (beta - x0) * t1, the WRITTEN two-lane form ════════════
     * design §0.5 :296-302, written out ONCE in the doc so no per-site choice
     * exists. x0 (column g) is the one BASE-field actor and enters the c0 lane
     * only; expanding (A0 + A1*u)(B0 + B1*u) with u^2 = W over
     * A = beta - x0, B = t1 gives exactly:
     *     t2.c0 = (beta.c0 - g)*t1.c0 + W*beta.c1*t1.c1
     *     t2.c1 = (beta.c0 - g)*t1.c1 +   beta.c1*t1.c0
     * (the same product `gold_fp2_mul` computes, field_goldilocks.h:165-171). */
    {
        const gold_fp_t a0 = sub(be0, g); /* (beta - x0).c0 */
        az(&v, mul(p_fold,
                   sub(t20, add(mul(a0, t10), mul(W, mul(be1, t11))))));
        az(&v, mul(p_fold, sub(t21, add(mul(a0, t11), mul(be1, t10)))));
    }

    /* ══ C4e — beta_sq = beta * beta (fp2 square) ══════════════════════════
     * beta^arity at arity 2, the native's `log_arity` squarings of beta
     * (fri_verifier.c:601-602; upstream `exp_power_of_2(beta, 1)`,
     * P3rec verifier.rs:629-632). */
    az(&v, mul(p_fold, sub(bs0, add(mul(be0, be0), mul(W, mul(be1, be1))))));
    az(&v, mul(p_fold, sub(bs1, add(mul(be0, be1), mul(be1, be0)))));

    /* ══ C4f — rterm = beta_sq * ro (fp2), the roll-in contribution ═════════
     * Native: `folded += beta_pow * ro[ro_i].ro` (fri_verifier.c:603). Split
     * out as its own column purely for degree relief (A2 note-1). */
    az(&v, mul(p_fold, sub(rt0, add(mul(bs0, ro0), mul(W, mul(bs1, ro1))))));
    az(&v, mul(p_fold, sub(rt1, add(mul(bs0, ro1), mul(bs1, ro0)))));

    /* ══ C4g / C4h — beta and roll-in <-> publics, gated by the step one-hot ═
     * Fold row r takes beta pair r (transcript order) and, iff the cfg pins a
     * roll-in at its post-fold height, roll-in slot `rank` — the rank of that
     * height in the cfg's DESCENDING list, which is the native's monotone
     * consumption order (`ro_i` only advances, fri_verifier.c:600-605).
     *
     * DIVERGENCE D1 IS STRUCTURAL HERE (design §0.3 :112-124): the AIR carries
     * a roll-in slot ONLY where the cfg pins one, and C4i forces ro = 0
     * everywhere else, so an unconsumed reduced opening is cfg-IMPOSSIBLE.
     * DNAC native REJECTS one (fri_verifier.c:613-615) and so does UPSTREAM
     * NATIVE (`FriError::UnconsumedReducedOpenings`, P3 fri/src/verifier.rs
     * :492-497); the upstream CIRCUIT's connect-to-zero
     * (P3rec verifier.rs:1640-1643) is the relaxation, not our strictness. */
    for (size_t r = 0; r < s.n_fold; r++) {
        const gold_fp_t pk = fp(prep_local[dnac_p2c_col_pos(s.n_chain + r)]);
        const size_t bo = s.pub_beta + FAIR_EXT_LANES * r;
        az(&v, mul(pk, sub(be0, fp(publics[bo]))));
        az(&v, mul(pk, sub(be1, fp(publics[bo + 1]))));
        if (s.rollin_rank[r] != FAIR_NO_ROLLIN) {
            const size_t ao = s.pub_ro + FAIR_EXT_LANES * s.rollin_rank[r];
            az(&v, mul(pk, sub(ro0, fp(publics[ao]))));
            az(&v, mul(pk, sub(ro1, fp(publics[ao + 1]))));
        }
    }

    /* ══ C4i — ro == 0 on every NON-roll-in fold row ═══════════════════════
     * `is_fold - is_rollin` is a degree-1 linear combination of two prep cells,
     * so the gate stays degree 1 (never a product). With C4f this also forces
     * rterm = 0 there, so a roll-in cannot be smuggled onto a phase the cfg
     * does not name. */
    {
        const gold_fp_t not_roll = sub(p_fold, p_roll);
        az(&v, mul(not_roll, ro0));
        az(&v, mul(not_roll, ro1));
    }

    /* ══ C5 — TERMINAL boundary (design §0.5 :383-387) ═════════════════════
     * On the FIRST padding row: `f == final_poly[0]`. At log_final_poly_len = 0
     * this is the ENTIRE terminal check — the Horner evaluation degenerates to
     * the single constant and is x-INDEPENDENT (fri_terminal_horner_eval,
     * fri_verifier.c:122-142; upstream early-returns `coefficients[0]`,
     * P3rec verifier.rs:847-849), so no terminal-x machinery is needed.
     *
     * The value ARRIVING here is phase R-1's output, carried by C4l firing on
     * the LAST fold row (see C4l's gating note). That pairing is the P2a-i3
     * last-row lesson: a boundary must live on a row that EXISTS and is REACHED
     * by a constraint. */
    az(&v, mul(p_term, sub(f0, fp(publics[s.pub_final]))));
    az(&v, mul(p_term, sub(f1, fp(publics[s.pub_final + 1]))));

    if (!main_next) return v; /* last row: no transition constraints */

    const gold_fp_t nb = fp(main_next[FAIR_COL_B]);
    const gold_fp_t ng = fp(main_next[FAIR_COL_G]);
    const gold_fp_t ngb = fp(main_next[FAIR_COL_GB]);
    const gold_fp_t nf0 = fp(main_next[FAIR_COL_F]);
    const gold_fp_t nf1 = fp(main_next[FAIR_COL_F + 1]);
    const gold_fp_t pn_gpow = fp(prep_next[DNAC_P2C_COL_G_POW2]);

    /* ══ C3b / C3c — chain transition (design §0.5 :346-348) ═══════════════
     *     gb' = g * b'                     (intermediate; degree relief)
     *     g'  = g + gb' * (G_{j+1} - 1)    == g * (1 + b'*(G_{j+1} - 1))
     * i.e. the select-mul step of `precompute_subgroup_starts`
     * (P3rec verifier.rs:524-527) split across two degree-3 forms so the single
     * is_chainpair gate is affordable. G_{j+1} is the NEXT row's preprocessed
     * literal — this read is why PIN-2 (`prep_next = 1`) is mandatory. */
    az(&v, mul(p_cpair, sub(ngb, mul(g, nb))));
    az(&v, mul(p_cpair, sub(ng, add(g, mul(ngb, sub(pn_gpow, one))))));

    /* ══ C3d — HANDOFF: chain -> fold row 0 is a COPY (design §0.5 :349-352) ═
     * Legal ONLY because C3a's row-0 boundary already performed the first
     * multiply, so all lgmh-1 bits are absorbed by the time this fires.
     * At the handoff, g == x_0 == g_lgmh^{rev(idx>>1, lgmh-1)} (design §0.5b;
     * the native's own subgroup_start, fri_fold.c:215-222 evaluated with
     * fri_verifier.c:594's post-shift index). */
    az(&v, mul(p_hand, sub(ng, g)));

    /* ══ C4j — FOLD-ROW-0 BOUNDARY: f' == publics[f_init] ══════════════════
     * Closes FLEET 020 A2-F2 (CRITICAL): design v1 carried f_init in publics
     * but NO constraint read it, leaving the walk's starting value FREE — any
     * start X with final_poly[0] re-published as the propagated end satisfied
     * everything (the classic write-key/read-key hole). The native binds the
     * start at fri_verifier.c:523-527 (`folded_eval = ro[0].ro` after the
     * initial-height check); upstream at P3rec verifier.rs:1605-1611.
     * Gated from the CHAIN side by is_handoff, so it lands on fold row 0. */
    az(&v, mul(p_hand, sub(nf0, fp(publics[s.pub_finit]))));
    az(&v, mul(p_hand, sub(nf1, fp(publics[s.pub_finit + 1]))));

    /* ══ C4k — x0 RECURRENCE, fold -> fold ONLY (design §0.5b, :374-376) ════
     *     x_{i+1} = x_i^2 * (1 - 2*b_{i+1})
     * DERIVED (author's algebra, CONFIRMED by FLEET 020 A1's independent
     * derivation and A2's could-not-break A/B): with
     * rev(v,m) = b*2^{m-1} + rev(v>>1, m-1) and g_{lgmh}^{2^{lgmh-1}} = -1,
     * squaring x_i = g_{lgmh-i}^{rev(idx>>(i+1), lgmh-1-i)} peels exactly the
     * next bit's (-1) factor. Cross-checked against the native closed form
     * (fri_fold.c:215-222) at every phase by the test suite.
     *
     * The LAST fold row intentionally has NO successor x0 — is_foldpair is
     * clear there (fri_air_table.c:197) — which is stated, not accidental. */
    az(&v, mul(p_fpair, sub(ng, mul(g_sq, sub(one, add(nb, nb))))));

    /* ══ C4l — the FOLD TRANSITION (design §0.5 :377-382) ══════════════════
     *     f' = f + b*(s - f) + t2*inv + rterm
     * which is upstream's `new = e0 + (beta - x0)*e1_minus_e0*inv` (+ roll-in)
     * with e0 = select(sibling_is_right, folded, sibling) expanded:
     *     e0 = s + (1-b)*(f - s) = f + b*(s - f)          (P3rec :615-617)
     * `t2*inv` is the fp2 t2 scaled by the BASE witness inv, lanewise.
     *
     * ⚠ GATING IS LOAD-BEARING (FLEET 020 A2-F3, HIGH): this fires on is_fold
     * LOCAL — INCLUDING the last fold row, whose successor is the first PADDING
     * row. The natural is_foldpair reading would leave phase R-1 unchecked; the
     * asymmetry with C4k (is_foldpair) is deliberate and is what delivers the
     * final value onto the row C5 reads. */
    {
        const gold_fp_t e0_0 = add(f0, mul(b, sub(s0, f0)));
        const gold_fp_t e0_1 = add(f1, mul(b, sub(s1, f1)));
        az(&v, mul(p_fold, sub(nf0, add(add(e0_0, mul(t20, inv)), rt0))));
        az(&v, mul(p_fold, sub(nf1, add(add(e0_1, mul(t21, inv)), rt1))));
    }

    return v;
}

int dnac_fair_eval_trace(const uint64_t *main_trace, const uint64_t *prep_table,
                         size_t n_rows, const dnac_p2c_table_cfg_t *cfg,
                         const uint64_t *publics, size_t num_publics) {
    if (!main_trace || !prep_table || n_rows == 0) return FAIR_VIOL_BAD_CONFIG;

    /* ── G4a SCHEDULE CONFORMANCE (design §0.5 :280-283) ────────────────────
     * The row count comes from the PINNED schedule, never from a witnessed
     * length: a shorter trace is a shorter walk, i.e. a different statement. */
    fair_sched_t s;
    if (!fair_schedule(cfg, &s)) return FAIR_VIOL_BAD_CONFIG;
    if (n_rows != s.rows) return FAIR_VIOL_BAD_CONFIG;

    /* ── G4b TERMINALITY (the P2a-i3 shipped-HIGH shape) ────────────────────
     * The final trace row gets NO transition constraints, so every effect a row
     * pins on its SUCCESSOR is void there. Requiring the last row to be PADDING
     * makes "every typed row has a successor" structurally true, so no
     * transition-anchored form can be skipped by ending the trace early.
     *
     * Checked as a ROW TYPE, not "all cells zero": P2c padding rows carry
     * is_pad = 1 (fri_air_table.c:203-205), and the FIRST padding row also
     * carries is_terminal = 1 — which IS the last row whenever the pad block
     * has length 1 (e.g. lgmh 5 / log_blowup 2 => 4 + 3 + 1 = 8 rows exactly).
     * Fail-close (P2b counted this as one violation instead; here the table is
     * generated and root-pinned as a whole, so a typed last row is an
     * out-of-contract TABLE, not a trace defect). */
    {
        const uint64_t *last = prep_table + (n_rows - 1) * DNAC_P2C_TABLE_COLS;
        if (last[DNAC_P2C_COL_IS_PAD] != 1u) return FAIR_VIOL_BAD_CONFIG;
        if (last[DNAC_P2C_COL_IS_CHAIN] != 0u) return FAIR_VIOL_BAD_CONFIG;
        if (last[DNAC_P2C_COL_IS_FOLD] != 0u) return FAIR_VIOL_BAD_CONFIG;
    }

    int total = 0;
    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *local = main_trace + r * FAIR_NUM_COLS;
        const uint64_t *pl = prep_table + r * (size_t)DNAC_P2C_TABLE_COLS;
        const uint64_t *next = (r + 1 < n_rows) ? local + FAIR_NUM_COLS : NULL;
        const uint64_t *pn =
            (r + 1 < n_rows) ? pl + (size_t)DNAC_P2C_TABLE_COLS : NULL;
        const int v = dnac_fair_eval_row(local, next, pl, pn, r == 0, cfg,
                                         publics, num_publics);
        if (v >= FAIR_VIOL_BAD_CONFIG) return FAIR_VIOL_BAD_CONFIG;
        /* Saturate instead of overflowing: a long, wholly-corrupt trace can sum
         * past INT_MAX (signed overflow is UB) and the sentinel band must stay
         * distinguishable (the P2a i3/A2-F5 contract). */
        if (total >= FAIR_VIOL_BAD_CONFIG - 1 - v) {
            total = FAIR_VIOL_BAD_CONFIG - 1;
        } else {
            total += v;
        }
    }
    return total;
}
