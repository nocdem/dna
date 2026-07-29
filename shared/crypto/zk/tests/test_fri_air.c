/**
 * @file test_fri_air.c
 * @brief P2c slice 1 — FRI fold-walk control-AIR construction gate (TDD).
 *
 * Design contract: dnac/docs/plans/2026-07-29-p2c-fri-in-air-design.md
 * (local-only) §0.5 "Constraint forms" C2-C6, §0.5b (the x0 recurrence),
 * §0.5 gates G1-G7, §4 item 2 (the MANDATORY negatives from FLEET 020).
 *
 * ── HONEST LABEL (read this before believing the word "byte-match") ────────
 * This test does NOT byte-match anything against Plonky3 itself. It performs a
 * NATIVE REPLAY: it drives the SHIPPED, already-byte-matched primitives
 *   - `fri_fold_row_fp2` (fri_fold.c:194-247, oracle-byte-matched at Phase D.2
 *     against real Plonky3 `two_adic_pcs.rs:109-132` vectors —
 *     tools/vectors/fri_fold_row.json),
 *   - `gold_fp_two_adic_generator` / `gold_fp_pow` (field_goldilocks.c, KAT'd
 *     33/33 by test_two_adic_gens),
 *   - `reverse_bits_len_u64` (zk_field_helpers.c, Phase A port),
 * and requires the AIR to accept exactly the trace that chain produces. The
 * byte-match is INHERITED; what is proved HERE is that the AIR's accepted
 * language CONTAINS the native one (accepts) and EXCLUDES each single-form
 * deviation (negatives). Same basis as P2b slice 1 (user-approved precedent,
 * design §4 item 5).
 *
 * (accept) FIVE honest walks over THREE configs:
 *   - the PINNED reference cfg (lgmh 13, log_blowup 2, roll-ins {11, 9},
 *     32 rows — the cfg DNAC_P2C_PREP_ROOT is pinned against) at THREE index
 *     vectors: 0, all-ones (8191) and the non-palindromic 4660;
 *   - the RECURSION shape (lgmh 19, roll-in {17}, 64 rows);
 *   - a SMALL hand-checkable cfg (lgmh 4 => 3 chain + 2 fold rows) whose x0
 *     chain is computed by hand in the comment at CFG_SMALL.
 * Each accept additionally runs TWO cross-checks that are INDEPENDENT of the
 * AIR: (1) every fold row's `g` equals the NATIVE closed-form subgroup start
 *   g_{lgmh-r}^{rev(idx>>(r+1), lgmh-1-r)}  (fri_fold.c:215-222 evaluated with
 * fri_verifier.c:594's post-shift index) — i.e. the recurrence-built chain
 * equals the closed form on every accept vector; and (2) every fold row's
 * output `f'` equals `fri_fold_row_fp2` + the roll-in addition
 * (fri_verifier.c:549-605).
 *
 * (reject) 37 negatives (N1, N2, N3, N4a, N4b, N5..N36) + 8 eval-entry config
 * gates. Every negative flips exactly ONE thing; 24 pin an EXACT violation
 * count, which is what proves they hit that form and only that form (the P2b
 * N4/N11 exact-isolation pattern), 11 are fail-close, and 2 (N4a, N21) are
 * caught without a pinned count because pinning one there would rest on a
 * fixture value being non-zero — a fake isolation claim. The four MANDATORY
 * FLEET 020 negatives are N1 (t1 SIGN / A2-F1), N2 (FREE f_init / A2-F2),
 * N3 (handoff-as-copy / A2-F4) and N4b (last fold phase free / A2-F3). N37 is
 * a POSITIVE property check: C6 says padding rows carry no main-trace
 * constraint, so garbage on a non-terminal padding row must STILL evaluate
 * to 0. The exact roster and its split are enumerated at the end of main().
 *
 * Deterministic fixtures only — NO rand() anywhere (root CLAUDE.md).
 *
 * Build (via Makefile):  ./build/test_fri_air        (no vector files)
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
#include "../fri_air.h"
#include "../fri_air_table.h"
#include "../fri_fold.h"
#include "../zk_field_helpers.h"

#define T_MAX_R      32  /* R <= lgmh <= DNAC_P2C_MAX_LGMH                   */
#define T_MAX_ROLLIN DNAC_P2C_MAX_ROLLIN
#define T_MAX_PUB    200 /* 32 + 2*32 + 2 + 2*32 + 2 = 164 worst case        */

static int fails = 0;

/* ══════════════════════════ field shorthands ═════════════════════════════ */

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }

static gold_fp2_t rd2(const uint64_t *row, size_t off) {
    return gold_fp2_new(fp(row[off]), fp(row[off + 1]));
}

static void wr2(uint64_t *row, size_t off, gold_fp2_t x) {
    row[off] = gold_fp_to_u64(x.a);
    row[off + 1] = gold_fp_to_u64(x.b);
}

/** base * fp2, lanewise — the one scaling shape the AIR uses (t2*inv, b*(s-f),
 *  (1-2b)*(s-f)). */
static gold_fp2_t scale2(gold_fp_t k, gold_fp2_t x) {
    return gold_fp2_new(gold_fp_mul(k, x.a), gold_fp_mul(k, x.b));
}

/** +1 in the field, kept CANONICAL (a tampered public must stay < p or the
 *  test would be measuring gate G6 instead of the constraint under test). */
static uint64_t bump(uint64_t v) {
    return gold_fp_to_u64(gold_fp_add(fp(v), gold_fp_one()));
}

/* ══════════════════════════ deterministic fixtures ═══════════════════════
 * No RNG anywhere. Every value is a fixed affine function of its coordinates,
 * canonicalized into [0, p) by `gold_fp_from_u64`.
 */
static gold_fp_t tfp(uint64_t a, uint64_t c) {
    return fp(a * UINT64_C(0x00000001ABCDEF01) + c * UINT64_C(0x0000000100000007) +
              UINT64_C(0x0123456789ABCDEF));
}

static gold_fp2_t tfp2(uint64_t a, uint64_t c) {
    return gold_fp2_new(tfp(a, c), tfp(a, c + 1));
}

typedef struct {
    gold_fp2_t beta[T_MAX_R];
    gold_fp2_t sib[T_MAX_R];
    gold_fp2_t f_init;
    gold_fp2_t ro[T_MAX_ROLLIN];
} fixture_t;

static void fill_fixture(fixture_t *F, uint64_t seed) {
    for (size_t r = 0; r < T_MAX_R; r++) {
        F->beta[r] = tfp2(seed * 7 + r + 1, 11);
        F->sib[r] = tfp2(seed * 13 + r + 1, 23);
    }
    for (size_t k = 0; k < T_MAX_ROLLIN; k++) F->ro[k] = tfp2(seed * 17 + k + 1, 41);
    F->f_init = tfp2(seed + 101, 31);
}

/* ══════════════════════════ honest trace builder ═════════════════════════
 * Lives TEST-SIDE so the constraint file cannot "help" the witness it checks
 * (the P2b slice-1 rule, mmcs_air.h:106-110).
 *
 * The `variant_t` knobs build a trace that is SELF-CONSISTENT under a WRONG
 * rule — that is what makes the four MANDATORY negatives exact-count isolable:
 * everything downstream of the deviation is rebuilt honestly, so only the one
 * form under test can fire.
 */
typedef struct {
    int t1_sign_flip_row; /* build t1 as (2b-1)*(s-f) at this fold row; -1 off */
    int x0_sign_flip;     /* build the x0 recurrence as g_sq*(2b'-1)           */
    int free_finit;       /* start the walk at f_init + (1,1)                  */
    int no_row0_mul;      /* chain row 0: g := 1 (drop the multiply)           */
    int x0_bump;          /* fold row 0: x0 := chain_g + 1 (break the handoff) */
} variant_t;

static const variant_t V_HONEST = {-1, 0, 0, 0, 0};

typedef struct {
    const dnac_p2c_table_cfg_t *cfg;
    size_t    lgmh, rows, n_chain, R, sched, num_pub;
    size_t    pub_beta, pub_finit, pub_ro, pub_final;
    uint64_t  index;
    uint64_t *trace; /* rows * FAIR_NUM_COLS            */
    uint64_t *prep;  /* rows * DNAC_P2C_TABLE_COLS      */
    uint64_t *pub;   /* num_pub                         */
    int       is_rollin[T_MAX_R];
    size_t    rank[T_MAX_R];
} built_t;

static uint64_t *row_of(const built_t *B, size_t r) {
    return B->trace + r * FAIR_NUM_COLS;
}

static void built_free(built_t *B) {
    free(B->trace);
    free(B->prep);
    free(B->pub);
    B->trace = NULL;
    B->prep = NULL;
    B->pub = NULL;
}

static int build_trace(built_t *B, const dnac_p2c_table_cfg_t *cfg,
                       uint64_t index, const fixture_t *F, const variant_t *V) {
    memset(B, 0, sizeof(*B));
    B->cfg = cfg;
    B->index = index;
    B->lgmh = cfg->lgmh;
    B->rows = dnac_p2c_table_rows(cfg);
    B->n_chain = dnac_p2c_chain_rows(cfg);
    B->R = dnac_p2c_fold_rows(cfg);
    B->num_pub = dnac_fair_num_publics(cfg);
    if (B->rows == 0 || B->n_chain == 0 || B->R == 0 || B->num_pub == 0) return 0;
    if (B->R > T_MAX_R) return 0;
    B->sched = B->n_chain + B->R;
    B->pub_beta = dnac_fair_pub_beta_off(cfg);
    B->pub_finit = dnac_fair_pub_finit_off(cfg);
    B->pub_ro = dnac_fair_pub_ro_off(cfg);
    B->pub_final = dnac_fair_pub_final_off(cfg);

    B->trace = (uint64_t *)calloc(B->rows * FAIR_NUM_COLS, sizeof(uint64_t));
    B->prep = (uint64_t *)calloc(B->rows * (size_t)DNAC_P2C_TABLE_COLS,
                                 sizeof(uint64_t));
    B->pub = (uint64_t *)calloc(B->num_pub, sizeof(uint64_t));
    if (!B->trace || !B->prep || !B->pub) {
        built_free(B);
        return 0;
    }

    /* Preprocessed table — the ONE schedule authority, plus its own structural
     * validator so a generator regression cannot masquerade as an AIR bug. */
    if (dnac_p2c_table_generate(cfg, B->prep,
                                B->rows * (size_t)DNAC_P2C_TABLE_COLS) !=
        DNAC_P2C_TABLE_OK) {
        built_free(B);
        return 0;
    }
    {
        dnac_p2c_table_defect_t d;
        if (dnac_p2c_table_validate(cfg, B->prep, B->rows, &d) !=
            DNAC_P2C_TABLE_OK) {
            built_free(B);
            return 0;
        }
    }
    /* Roll-in placement + rank, read back out of the generator. */
    {
        size_t rank = 0;
        for (size_t r = 0; r < B->R; r++) {
            dnac_p2c_row_t rec;
            if (dnac_p2c_table_row(cfg, B->n_chain + r, &rec) !=
                DNAC_P2C_TABLE_OK) {
                built_free(B);
                return 0;
            }
            B->is_rollin[r] = rec.is_rollin;
            B->rank[r] = rec.is_rollin ? rank++ : (size_t)-1;
        }
    }

    const gold_fp_t one = gold_fp_one();
    const gold_fp_t zero = gold_fp_zero();

    /* ── chain rows: the MSB-first x0 anchor (design §0.5 C3) ──────────────
     * g_0 = 1 + b_0*(G_0 - 1)                       (multiply FROM 1)
     * g_j = g_{j-1} + (g_{j-1}*b_j)*(G_j - 1)       (== g_{j-1}*(1 + b_j*(G_j-1)))
     * chain row j consumes index bit lgmh-1-j; G_j = g_lgmh^{2^j} = g_{lgmh-j}
     * (fri_air_table.c:120-123). */
    gold_fp_t gacc = one;
    for (size_t j = 0; j < B->n_chain; j++) {
        uint64_t       *row = row_of(B, j);
        const uint64_t  bit = (index >> (B->lgmh - 1 - j)) & 1u;
        const gold_fp_t G = gold_fp_two_adic_generator((unsigned)(B->lgmh - j));
        row[FAIR_COL_B] = bit;
        if (j == 0) {
            gacc = V->no_row0_mul ? one : (bit ? G : one);
            /* `gb` on row 0 is pinned by NOTHING (no predecessor is_chainpair);
             * left at 0, which is the honest prover's choice. */
        } else {
            const gold_fp_t gb = bit ? gacc : zero;
            row[FAIR_COL_GB] = gold_fp_to_u64(gb);
            gacc = gold_fp_add(gacc, gold_fp_mul(gb, gold_fp_sub(G, one)));
        }
        row[FAIR_COL_G] = gold_fp_to_u64(gacc);
    }

    /* ── fold rows: the LSB-first walk ─────────────────────────────────────── */
    gold_fp2_t f = F->f_init;
    if (V->free_finit) f = gold_fp2_add(f, gold_fp2_new(one, one));
    gold_fp_t x = gacc; /* the handoff copy (design §0.5 C3 :349-352) */
    if (V->x0_bump) x = gold_fp_add(x, one);

    for (size_t r = 0; r < B->R; r++) {
        uint64_t        *row = row_of(B, B->n_chain + r);
        const uint64_t   bit = (index >> r) & 1u;
        const gold_fp2_t beta = F->beta[r];
        const gold_fp2_t sib = F->sib[r];
        const gold_fp2_t roval =
            B->is_rollin[r] ? F->ro[B->rank[r]] : gold_fp2_zero();

        if (gold_fp_is_zero(x)) { /* x0 = 0 has no inverse — never honest */
            built_free(B);
            return 0;
        }
        const gold_fp_t inv = gold_fp_mul(fp(FAIR_NEG_HALF), gold_fp_inv(x));
        const gold_fp_t gsq = gold_fp_mul(x, x);

        /* (1 - 2b), or its NEGATION at the sign-flip row (the FLEET 020 A2-F1
         * reflected-challenge shape). */
        gold_fp_t sgn = gold_fp_sub(one, gold_fp_add(fp(bit), fp(bit)));
        if (V->t1_sign_flip_row == (int)r) sgn = gold_fp_neg(sgn);

        const gold_fp2_t t1 = scale2(sgn, gold_fp2_sub(sib, f));
        const gold_fp2_t t2 =
            gold_fp2_mul(gold_fp2_sub(beta, gold_fp2_from_base(x)), t1);
        const gold_fp2_t bsq = gold_fp2_mul(beta, beta);
        const gold_fp2_t rterm = gold_fp2_mul(bsq, roval);

        row[FAIR_COL_B] = bit;
        row[FAIR_COL_G] = gold_fp_to_u64(x);
        row[FAIR_COL_G_SQ] = gold_fp_to_u64(gsq);
        row[FAIR_COL_INV] = gold_fp_to_u64(inv);
        wr2(row, FAIR_COL_F, f);
        wr2(row, FAIR_COL_S, sib);
        wr2(row, FAIR_COL_BETA, beta);
        wr2(row, FAIR_COL_BETA_SQ, bsq);
        wr2(row, FAIR_COL_T1, t1);
        wr2(row, FAIR_COL_T2, t2);
        wr2(row, FAIR_COL_RTERM, rterm);
        wr2(row, FAIR_COL_RO, roval);

        /* f' = f + b*(s - f) + t2*inv + rterm  (design §0.5 C4 :377-382) */
        const gold_fp2_t e0 = gold_fp2_add(f, scale2(fp(bit), gold_fp2_sub(sib, f)));
        f = gold_fp2_add(gold_fp2_add(e0, scale2(inv, t2)), rterm);

        /* x_{r+1} = x_r^2 * (1 - 2*b_{r+1})  (design §0.5b) */
        if (r + 1 < B->R) {
            const uint64_t nbit = (index >> (r + 1)) & 1u;
            gold_fp_t nsgn = gold_fp_sub(one, gold_fp_add(fp(nbit), fp(nbit)));
            if (V->x0_sign_flip) nsgn = gold_fp_neg(nsgn);
            x = gold_fp_mul(gsq, nsgn);
        }
    }

    /* ── padding: the FIRST padding row carries the walk's output (C5 reads it,
     * C4l on the last fold row writes it); every later padding row stays zero,
     * which C6 says is unconstrained anyway. ─────────────────────────────── */
    wr2(row_of(B, B->sched), FAIR_COL_F, f);

    /* ── publics (fri_air.h layout) ────────────────────────────────────────── */
    for (size_t i = 0; i < B->lgmh; i++)
        B->pub[FAIR_PUB_BITS_OFF + i] = (index >> i) & 1u;
    for (size_t r = 0; r < B->R; r++) {
        B->pub[B->pub_beta + 2 * r] = gold_fp_to_u64(F->beta[r].a);
        B->pub[B->pub_beta + 2 * r + 1] = gold_fp_to_u64(F->beta[r].b);
    }
    /* f_init is published HONEST even in the free_finit variant — that is the
     * A2-F2 attack: publish the real start, walk from another one. */
    B->pub[B->pub_finit] = gold_fp_to_u64(F->f_init.a);
    B->pub[B->pub_finit + 1] = gold_fp_to_u64(F->f_init.b);
    for (size_t k = 0; k < cfg->num_rollin; k++) {
        B->pub[B->pub_ro + 2 * k] = gold_fp_to_u64(F->ro[k].a);
        B->pub[B->pub_ro + 2 * k + 1] = gold_fp_to_u64(F->ro[k].b);
    }
    B->pub[B->pub_final] = gold_fp_to_u64(f.a);
    B->pub[B->pub_final + 1] = gold_fp_to_u64(f.b);
    return 1;
}

/* ══════════════════════ AIR-INDEPENDENT cross-checks ═════════════════════ */

/**
 * (1) x0 CLOSED FORM. The trace's `g` on fold row r is built by the DERIVED
 * recurrence (design §0.5b); the native computes the same quantity as
 *     subgroup_start = g_{log_height + log_arity}^{rev(index, log_height)}
 * with log_height = lgmh-1-r, log_arity = 1 and `index` the POST-shift
 * idx >> (r+1) (fri_fold.c:215-222 driven by fri_verifier.c:557-558, :594).
 * Comparing them proves the recurrence-built chain equals the closed form on
 * this vector — independently of the AIR.
 *
 * (2) NATIVE FOLD. Replays fri_verifier.c:549-605 with `fri_fold_row_fp2` and
 * requires each fold row's OUTPUT (== the next row's `f`) to match.
 */
static int crosscheck_native(const built_t *B, const fixture_t *F,
                             const char *label) {
    int        bad = 0;
    gold_fp2_t f = F->f_init;
    size_t     rank = 0;

    for (size_t r = 0; r < B->R; r++) {
        const uint64_t *row = row_of(B, B->n_chain + r);

        /* (1) x0 */
        const unsigned  lf = (unsigned)(B->lgmh - 1 - r);
        const uint64_t  idx_post = B->index >> (r + 1);
        const gold_fp_t want_x =
            gold_fp_pow(gold_fp_two_adic_generator((unsigned)(B->lgmh - r)),
                        reverse_bits_len_u64(idx_post, lf));
        if (row[FAIR_COL_G] != gold_fp_to_u64(want_x)) {
            printf("  [xchk]  %-24s phase %2zu x0 MISMATCH — FAIL\n", label, r);
            bad = 1;
        }

        /* (2) native fold: evals[index_in_group] = folded, PRE-shift index
         *     (fri_verifier.c:549-555). */
        const size_t index_in_group = (size_t)((B->index >> r) & 1u);
        gold_fp2_t   evals[2];
        evals[index_in_group] = f;
        evals[1 - index_in_group] = F->sib[r];
        gold_fp2_t folded =
            fri_fold_row_fp2((size_t)idx_post, lf, 1u, F->beta[r], evals, 2);
        if (B->is_rollin[r]) {
            const gold_fp2_t bp = gold_fp2_sqr(F->beta[r]); /* beta^arity */
            folded = gold_fp2_add(folded, gold_fp2_mul(bp, F->ro[rank]));
            rank++;
        }
        f = folded;

        const uint64_t  *nrow = row_of(B, B->n_chain + r + 1);
        const gold_fp2_t got = rd2(nrow, FAIR_COL_F);
        if (!gold_fp2_eq(got, f)) {
            printf("  [xchk]  %-24s phase %2zu fold MISMATCH — FAIL\n", label, r);
            bad = 1;
        }
    }
    /* The published terminal constant must be the walk's end. */
    if (B->pub[B->pub_final] != gold_fp_to_u64(f.a) ||
        B->pub[B->pub_final + 1] != gold_fp_to_u64(f.b)) {
        printf("  [xchk]  %-24s final_poly[0] MISMATCH — FAIL\n", label);
        bad = 1;
    }
    if (bad) fails++;
    return !bad;
}

/* ══════════════════════════ helpers / reporting ══════════════════════════ */

static int eval_built(const built_t *B) {
    return dnac_fair_eval_trace(B->trace, B->prep, B->rows, B->cfg, B->pub,
                                B->num_pub);
}

/** Reject with a violation count; `want_exact` > 0 additionally PINS the count
 *  — that is what proves the negative hits THAT form and nothing else. */
static void expect_reject(const char *name, const built_t *B, int want_exact) {
    const int v = eval_built(B);
    if (v < 1 || v >= FAIR_VIOL_BAD_CONFIG) {
        printf("  [reject] %-54s NOT caught (%d) — FAIL\n", name, v);
        fails++;
        return;
    }
    if (want_exact > 0 && v != want_exact) {
        printf("  [reject] %-54s caught but %d viol (want %d) — FAIL\n", name, v,
               want_exact);
        fails++;
        return;
    }
    printf("  [reject] %-54s caught (%d viol) — OK\n", name, v);
}

static void expect_bad_config(const char *name, int v) {
    if (v == FAIR_VIOL_BAD_CONFIG) {
        printf("  [reject] %-54s fails closed — OK\n", name);
    } else {
        printf("  [reject] %-54s returned %d — FAIL\n", name, v);
        fails++;
    }
}

static void check(const char *name, int ok) {
    printf("  [gate]   %-54s %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) fails++;
}

/** Recompute the LAST fold row's t2 from its (possibly tampered) t1/beta/g. */
static void relast_t2(built_t *B) {
    uint64_t        *fr = row_of(B, B->sched - 1);
    const gold_fp2_t beta = rd2(fr, FAIR_COL_BETA);
    const gold_fp_t  g = fp(fr[FAIR_COL_G]);
    const gold_fp2_t t1 = rd2(fr, FAIR_COL_T1);
    wr2(fr, FAIR_COL_T2,
        gold_fp2_mul(gold_fp2_sub(beta, gold_fp2_from_base(g)), t1));
}

/** Recompute the LAST fold row's rterm from its (possibly tampered) beta_sq/ro. */
static void relast_rterm(built_t *B) {
    uint64_t *fr = row_of(B, B->sched - 1);
    wr2(fr, FAIR_COL_RTERM,
        gold_fp2_mul(rd2(fr, FAIR_COL_BETA_SQ), rd2(fr, FAIR_COL_RO)));
}

/**
 * Recompute the LAST fold row's C4l output from its (possibly tampered) cells,
 * write it onto the terminal padding row and republish final_poly[0]. This is
 * what makes the last-fold-row negatives EXACT-count: every form except the one
 * under test stays satisfied, so the count IS the isolation proof.
 */
static void relast(built_t *B) {
    uint64_t        *fr = row_of(B, B->sched - 1);
    const gold_fp_t  b = fp(fr[FAIR_COL_B]);
    const gold_fp_t  inv = fp(fr[FAIR_COL_INV]);
    const gold_fp2_t f = rd2(fr, FAIR_COL_F);
    const gold_fp2_t s = rd2(fr, FAIR_COL_S);
    const gold_fp2_t t2 = rd2(fr, FAIR_COL_T2);
    const gold_fp2_t rt = rd2(fr, FAIR_COL_RTERM);
    const gold_fp2_t e0 = gold_fp2_add(f, scale2(b, gold_fp2_sub(s, f)));
    const gold_fp2_t nf = gold_fp2_add(gold_fp2_add(e0, scale2(inv, t2)), rt);
    wr2(row_of(B, B->sched), FAIR_COL_F, nf);
    B->pub[B->pub_final] = gold_fp_to_u64(nf.a);
    B->pub[B->pub_final + 1] = gold_fp_to_u64(nf.b);
}

/* ══════════════════════════════ configs ══════════════════════════════════ */

/* RECURSION shape (design §0.1 table :52-60 right column): lgmh 19 = 17 + 2,
 * log_blowup 2, R = 17, n_chain = 18, sched 35 => 64 rows, one roll-in at
 * post-fold height 17 (fold row 19-1-17 = 1), num_queries 59. */
static const size_t               REC_ROLLIN[1] = {17};
static const dnac_p2c_table_cfg_t CFG_REC = {19, 2, 0, 1, 1, REC_ROLLIN, 59};

/* SMALL hand-checkable cfg: lgmh 4, log_blowup 2 => R = 2, n_chain = 3,
 * sched = 5 => 8 rows (3 padding). No roll-ins.
 *
 * HAND CHECK at index 11 = 0b1011 (bits LSB-first b0=1 b1=1 b2=0 b3=1):
 *   chain row 0 reads b3 = 1, G_0 = g_4      => g = 1 + 1*(g_4 - 1) = g_4
 *   chain row 1 reads b2 = 0, G_1 = g_3      => gb = 0, g = g_4 + 0 = g_4
 *   chain row 2 reads b1 = 1, G_2 = g_2      => gb = g_4,
 *                                               g = g_4 + g_4*(g_2 - 1)
 *                                                 = g_4 * g_2 = g_4^{1+4} = g_4^5
 *   handoff       x_0 = g_4^5
 *   closed form   rev(11>>1, 3) = rev(0b101, 3) = 0b101 = 5, x_0 = g_4^5   ✓
 *   recurrence    x_1 = x_0^2 * (1 - 2*b_1) = g_4^{10} * (-1) = g_4^{10+8}
 *                     = g_4^{18 mod 16} = g_4^2
 *   closed form   x_1 = g_3^{rev(11>>2, 2)} = g_3^{rev(0b10,2)} = g_3^1
 *                     = g_4^2                                              ✓
 * (using g_4^8 = -1, the order-2 element of the order-16 subgroup, and
 *  G_j = g_lgmh^{2^j} = g_{lgmh-j}). */
static const dnac_p2c_table_cfg_t CFG_SMALL = {4, 2, 0, 1, 0, NULL, 1};

/* Fail-close configs for the eval-entry gates G1/G2/G3/G7 + D2. */
static const dnac_p2c_table_cfg_t CFG_G1 = {13, 2, 0, 2, 0, NULL, 100}; /* arity  */
static const dnac_p2c_table_cfg_t CFG_G2 = {13, 2, 1, 1, 0, NULL, 100}; /* lfpl   */
static const dnac_p2c_table_cfg_t CFG_G3 = {33, 2, 0, 1, 0, NULL, 100}; /* lgmh>32*/
static const dnac_p2c_table_cfg_t CFG_G7A = {3, 3, 0, 1, 0, NULL, 100}; /* R < 1  */
static const dnac_p2c_table_cfg_t CFG_G7B = {1, 0, 0, 1, 0, NULL, 100}; /* lgmh<2 */
static const dnac_p2c_table_cfg_t CFG_Q0 = {13, 2, 0, 1, 0, NULL, 0};   /* D2     */
static const size_t               BAD_ROLLIN[2] = {9, 11};              /* ascend */
static const dnac_p2c_table_cfg_t CFG_RI = {13, 2, 0, 1, 2, BAD_ROLLIN, 100};

/* ═══════════════════════════════ accepts ═════════════════════════════════ */

static int accept_case(const dnac_p2c_table_cfg_t *cfg, uint64_t index,
                       uint64_t seed, const char *label, built_t *keep) {
    fixture_t F;
    built_t   B;
    fill_fixture(&F, seed);
    if (!build_trace(&B, cfg, index, &F, &V_HONEST)) {
        printf("  [accept] %-24s honest trace build              FAIL\n", label);
        fails++;
        return 0;
    }
    const int ok_x = crosscheck_native(&B, &F, label);
    const int v = eval_built(&B);
    int       ok = ok_x;
    if (v != 0) {
        printf("  [accept] %-24s %2zu rows  %d viol — FAIL\n", label, B.rows, v);
        fails++;
        ok = 0;
    } else {
        printf("  [accept] %-24s idx %7" PRIu64 "  %2zu rows (%zu chain + %zu "
               "fold + %zu pad)  0 viol — OK\n",
               label, index, B.rows, B.n_chain, B.R, B.rows - B.sched);
    }
    if (keep && ok) {
        *keep = B; /* ownership moves to the caller */
    } else {
        built_free(&B);
    }
    return ok;
}

/* ════════════════════════════════ main ═══════════════════════════════════ */

int main(void) {
    const dnac_p2c_table_cfg_t *REF = dnac_p2c_ref_cfg();

    printf("============================================================\n");
    printf("P2c slice 1 — FRI fold-walk control AIR (fri_air.{c,h})\n");
    printf("============================================================\n");

    /* ── Gate 0: layout + public-offset binding contract ── */
    check("column layout / NEG_HALF / public regions", dnac_fair_layout_check());
    check("FAIR_NUM_COLS == 21 (re-counted; doc corrected 20->21)",
          FAIR_NUM_COLS == 21);
    check("num_publics(REF) == 43 (13 + 22 + 2 + 4 + 2)",
          dnac_fair_num_publics(REF) == 43);
    check("pub_beta(REF) == lgmh == 13", dnac_fair_pub_beta_off(REF) == 13);
    check("pub_finit(REF) == 35", dnac_fair_pub_finit_off(REF) == 35);
    check("pub_ro(REF) == 37", dnac_fair_pub_ro_off(REF) == 37);
    check("pub_final(REF) == 41", dnac_fair_pub_final_off(REF) == 41);
    check("table rows(REF) == 32", dnac_p2c_table_rows(REF) == 32);
    check("R(REF) == 11, chain(REF) == 12",
          dnac_p2c_fold_rows(REF) == 11 && dnac_p2c_chain_rows(REF) == 12);
    check("rows(REC) == 64, R == 17, chain == 18",
          dnac_p2c_table_rows(&CFG_REC) == 64 &&
              dnac_p2c_fold_rows(&CFG_REC) == 17 &&
              dnac_p2c_chain_rows(&CFG_REC) == 18);
    check("rows(SMALL) == 8, R == 2, chain == 3",
          dnac_p2c_table_rows(&CFG_SMALL) == 8 &&
              dnac_p2c_fold_rows(&CFG_SMALL) == 2 &&
              dnac_p2c_chain_rows(&CFG_SMALL) == 3);

    /* ── Gate 1: eval-entry config fail-close (G1/G2/G3/G7 + D2 + roll-in) ── */
    printf("\n-- eval-entry config gates (G1/G2/G3/G7) --------------------\n");
    {
        fixture_t F;
        built_t   G;
        fill_fixture(&F, 1);
        if (!build_trace(&G, REF, 4660, &F, &V_HONEST)) {
            printf("  gate fixture build FAILED\n");
            return 1;
        }
        expect_bad_config("G0 NULL cfg",
                          dnac_fair_eval_trace(G.trace, G.prep, G.rows, NULL,
                                               G.pub, G.num_pub));
        expect_bad_config("G1 max_log_arity != 1",
                          dnac_fair_eval_trace(G.trace, G.prep, G.rows, &CFG_G1,
                                               G.pub, G.num_pub));
        expect_bad_config("G2 log_final_poly_len != 0",
                          dnac_fair_eval_trace(G.trace, G.prep, G.rows, &CFG_G2,
                                               G.pub, G.num_pub));
        expect_bad_config("G3 lgmh > 32 (two-adicity)",
                          dnac_fair_eval_trace(G.trace, G.prep, G.rows, &CFG_G3,
                                               G.pub, G.num_pub));
        expect_bad_config("G7a R underflow (lgmh < lb + lfpl + 1)",
                          dnac_fair_eval_trace(G.trace, G.prep, G.rows, &CFG_G7A,
                                               G.pub, G.num_pub));
        expect_bad_config("G7b lgmh < 2 (no chain anchor)",
                          dnac_fair_eval_trace(G.trace, G.prep, G.rows, &CFG_G7B,
                                               G.pub, G.num_pub));
        expect_bad_config("D2 num_queries == 0",
                          dnac_fair_eval_trace(G.trace, G.prep, G.rows, &CFG_Q0,
                                               G.pub, G.num_pub));
        expect_bad_config("roll-in heights not strictly descending",
                          dnac_fair_eval_trace(G.trace, G.prep, G.rows, &CFG_RI,
                                               G.pub, G.num_pub));
        built_free(&G);
    }

    /* ── accepts ──────────────────────────────────────────────────────────── */
    printf("\n-- honest walks (native replay + x0 closed-form cross-check) -\n");
    built_t W; /* kept: REF cfg at the non-palindromic index 4660 */
    memset(&W, 0, sizeof(W));
    accept_case(REF, 0, 1, "REF idx 0 (all bits 0)", NULL);
    accept_case(REF, 8191, 2, "REF idx 8191 (all ones)", NULL);
    accept_case(&CFG_REC, UINT64_C(0x5A5A5), 4, "RECURSION lgmh 19", NULL);
    accept_case(&CFG_SMALL, 11, 5, "SMALL lgmh 4 (hand-checked)", NULL);
    if (!accept_case(REF, 4660, 1, "REF idx 4660 (non-palin)", &W)) {
        printf("primary fixture unusable — aborting\n");
        return 1;
    }
    /* The two index properties the negatives below depend on, asserted rather
     * than assumed: bit 12 (chain-only, set) and bit 10 (== b_{R-1}, clear). */
    check("idx 4660: bit 12 == 1 (chain-only bit set)", ((4660u >> 12) & 1u) == 1);
    check("idx 4660: bit 10 == 0 (b_{R-1} clear, for the t1-sign witness)",
          ((4660u >> 10) & 1u) == 0);
    check("REF roll-in fold rows are r = 1 and r = 3",
          W.is_rollin[1] && W.is_rollin[3] && !W.is_rollin[0] &&
              !W.is_rollin[10]);

    /* ══════════════════════════ negatives ═════════════════════════════════ */
    printf("\n-- the four MANDATORY FLEET 020 negatives (design §4 item 2) -\n");

    /* N1 — t1 SIGN (A1-F1 KAFADAN == A2-F1 CRITICAL). Built with the REFLECTED
     * factor (2b-1) at fold row R-1, where b = 0 and beta = 0 (A2's numeric
     * witness shape); t2, f' and final_poly[0] are all rebuilt CONSISTENTLY
     * with the wrong sign, so the ONLY thing that can fire is C4c's two lanes.
     * If the AIR carried the v1 sign this trace would VERIFY. */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        F.beta[10] = gold_fp2_zero(); /* beta = 0 at the flip row */
        V.t1_sign_flip_row = 10;      /* R - 1 */
        if (build_trace(&B, REF, 4660, &F, &V)) {
            const gold_fp2_t t1 = rd2(row_of(&B, B.sched - 1), FAIR_COL_T1);
            check("N1 precondition: t1 both lanes non-zero (else vacuous)",
                  !gold_fp_is_zero(t1.a) && !gold_fp_is_zero(t1.b));
            expect_reject("N1 t1 SIGN flipped -> reflected challenge (A2-F1)",
                          &B, 2);
            built_free(&B);
        } else {
            check("N1 build", 0);
        }
    }

    /* N2 — FREE f_init (A2-F2 CRITICAL). The walk starts at f_init + (1,1) and
     * propagates HONESTLY; final_poly[0] is republished as the propagated end,
     * so the terminal equality holds. Only the is_handoff f_init boundary can
     * fire — which is precisely the constraint design v1 did not have. */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        V.free_finit = 1;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            expect_reject("N2 walk starts off f_init, end republished (A2-F2)",
                          &B, 2);
            built_free(&B);
        } else {
            check("N2 build", 0);
        }
    }

    /* N3 — HANDOFF-AS-COPY (A2-F4 HIGH). Chain row 0 sets g := 1 instead of
     * 1 + b*(G_0 - 1) while b_{lgmh-1} = 1, and the rest of the chain + the
     * whole walk are rebuilt self-consistently from there. Only C3a's row-0
     * boundary can fire — the multiply the "copy" reading silently drops. */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        V.no_row0_mul = 1;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            expect_reject("N3 row-0 multiply dropped, chain rebuilt (A2-F4)",
                          &B, 1);
            built_free(&B);
        } else {
            check("N3 build", 0);
        }
    }

    /* N4a — the dispatch's sibling form: phase R-1's sibling is tampered and
     * its row-local t1/t2 are recomputed, but the walk's OUTPUT and
     * final_poly[0] are left honest. Caught by C4l on the LAST fold row. Count
     * not pinned: how many of the two output lanes move depends on
     * (beta - x0)'s lanes, and pinning a count that rests on a fixture value
     * being non-zero would be a fake isolation claim. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t        *fr = row_of(&B, B.sched - 1);
            const gold_fp_t  b = fp(fr[FAIR_COL_B]);
            const gold_fp2_t f = rd2(fr, FAIR_COL_F);
            gold_fp2_t       s = rd2(fr, FAIR_COL_S);
            s = gold_fp2_add(s, gold_fp2_new(gold_fp_one(), gold_fp_one()));
            wr2(fr, FAIR_COL_S, s);
            /* recompute the row-local t1 = (1-2b)(s-f), then t2 */
            wr2(fr, FAIR_COL_T1,
                scale2(gold_fp_sub(gold_fp_one(), gold_fp_add(b, b)),
                       gold_fp2_sub(s, f)));
            relast_t2(&B);
            expect_reject("N4a last phase sibling moved, output NOT (A2-F3)", &B,
                          0);
            built_free(&B);
        } else {
            check("N4a build", 0);
        }
    }

    /* N4b — the SAME hole, exact-count form: phase R-1's OUTPUT is moved by
     * (1,1) and final_poly[0] is moved with it, so C5 still holds. If C4l were
     * gated on is_foldpair (the "natural" reading FLEET 020 flagged), phase
     * R-1's output would be free and this trace would VERIFY. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t        *tr = row_of(&B, B.sched);
            const gold_fp2_t nf = gold_fp2_add(
                rd2(tr, FAIR_COL_F), gold_fp2_new(gold_fp_one(), gold_fp_one()));
            wr2(tr, FAIR_COL_F, nf);
            B.pub[B.pub_final] = gold_fp_to_u64(nf.a);
            B.pub[B.pub_final + 1] = gold_fp_to_u64(nf.b);
            expect_reject("N4b last phase output free, terminal consistent", &B,
                          2);
            built_free(&B);
        } else {
            check("N4b build", 0);
        }
    }

    printf("\n-- constraint-form negatives --------------------------------\n");

    /* N5 — x0 RECURRENCE SIGN (design §0.5b). Built with g' = g_sq*(2b'-1);
     * everything downstream (inv, g_sq, t1, t2, f, final_poly[0]) rebuilt. Only
     * C4k can fire, once per is_foldpair row => exactly R-1 = 10. */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        V.x0_sign_flip = 1;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            expect_reject("N5 x0 recurrence sign flipped (R-1 foldpairs)", &B,
                          10);
            built_free(&B);
        } else {
            check("N5 build", 0);
        }
    }

    /* N6 — non-boolean `b` on the LAST fold row, with t1/t2/f'/final rebuilt
     * from the literal b = 2. Fires C2a (booleanity) + C2b (public binding)
     * + the PREDECESSOR fold row's C4k, which reads this row's b as b'
     * (`ng = g_sq*(1-2*nb)`, fri_air.c C4k) against a g-chain built with the
     * honest bit — the same incoming-edge accounting N7 already does for the
     * chain side (its predecessor C3b). Expectation was 2 in v1; the AIR
     * correctly caught 3 (O9 root-cause 2026-07-29, ORCHESTRATOR). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t        *fr = row_of(&B, B.sched - 1);
            const gold_fp2_t f = rd2(fr, FAIR_COL_F);
            const gold_fp2_t s = rd2(fr, FAIR_COL_S);
            fr[FAIR_COL_B] = 2;
            wr2(fr, FAIR_COL_T1,
                scale2(gold_fp_sub(gold_fp_one(), fp(4)), gold_fp2_sub(s, f)));
            relast_t2(&B);
            relast(&B);
            expect_reject("N6 non-boolean b (fold row), rest rebuilt", &B, 3);
            built_free(&B);
        } else {
            check("N6 build", 0);
        }
    }

    /* N7 — non-boolean `b` on the LAST CHAIN row: C2a + C2b + the predecessor's
     * C3b (`gb' = g*b'`, whose gb cell is untouched). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            row_of(&B, B.n_chain - 1)[FAIR_COL_B] = 2;
            expect_reject("N7 non-boolean b (last chain row)", &B, 3);
            built_free(&B);
        } else {
            check("N7 build", 0);
        }
    }

    /* N8/N9/N10 — the bit publics, three ways. The chain reads bits
     * [1, lgmh-1] MSB-first and the walk reads [0, R-1] LSB-first, so at
     * lb = 2 / lfpl = 0 there are chain-ONLY bits {11, 12}, a fold-ONLY bit {0}
     * and an overlap [1, 10] that is read TWICE (design §0.5 C2 :331-338). */
    {
        const uint64_t saved12 = W.pub[12], saved0 = W.pub[0], saved5 = W.pub[5];
        W.pub[12] ^= 1u;
        expect_reject("N8 chain-ONLY bit public flipped (bit 12)", &W, 1);
        W.pub[12] = saved12;
        W.pub[0] ^= 1u;
        expect_reject("N9 fold-ONLY bit public flipped (bit 0)", &W, 1);
        W.pub[0] = saved0;
        W.pub[5] ^= 1u;
        expect_reject("N10 OVERLAP bit public flipped (bit 5, dual read)", &W, 2);
        W.pub[5] = saved5;
        check("N8-N10 publics restored", eval_built(&W) == 0);
    }

    /* N11 — `inv` tampered on the last fold row, f'/final rebuilt: only C4a
     * (`g*inv = -1/2`, the div form that also makes x0 = 0 unsatisfiable). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *fr = row_of(&B, B.sched - 1);
            fr[FAIR_COL_INV] = bump(fr[FAIR_COL_INV]);
            relast(&B);
            expect_reject("N11 inv tampered (C4a div form)", &B, 1);
            built_free(&B);
        } else {
            check("N11 build", 0);
        }
    }

    /* N12 — `g_sq` tampered on the LAST fold row. Its only consumer is C4k,
     * which is gated by is_foldpair and therefore CLEAR there, so exactly C4b
     * fires. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *fr = row_of(&B, B.sched - 1);
            fr[FAIR_COL_G_SQ] = bump(fr[FAIR_COL_G_SQ]);
            expect_reject("N12 g_sq tampered (C4b)", &B, 1);
            built_free(&B);
        } else {
            check("N12 build", 0);
        }
    }

    /* N13 — `gb` tampered on chain row 1: fires the predecessor's C3b
     * (gb' = g*b') AND C3c (g' = g + gb'*(G'-1), G_1 != 1). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *cr = row_of(&B, 1);
            cr[FAIR_COL_GB] = bump(cr[FAIR_COL_GB]);
            expect_reject("N13 gb tampered on chain row 1 (C3b + C3c)", &B, 2);
            built_free(&B);
        } else {
            check("N13 build", 0);
        }
    }

    /* N14 — `beta_sq` tampered on a NON-roll-in fold row (ro = 0 there, so
     * C4f's product is unchanged and f' is untouched): exactly C4e's c0 lane. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *fr = row_of(&B, B.sched - 1);
            fr[FAIR_COL_BETA_SQ] = bump(fr[FAIR_COL_BETA_SQ]);
            expect_reject("N14 beta_sq tampered, non-roll-in row (C4e)", &B, 1);
            built_free(&B);
        } else {
            check("N14 build", 0);
        }
    }

    /* N15 — `rterm` tampered: C4f's c0 lane AND C4l's c0 lane (rterm enters the
     * transition additively). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *fr = row_of(&B, B.sched - 1);
            fr[FAIR_COL_RTERM] = bump(fr[FAIR_COL_RTERM]);
            expect_reject("N15 rterm tampered (C4f + C4l)", &B, 2);
            built_free(&B);
        } else {
            check("N15 build", 0);
        }
    }

    /* N16 — `t1` tampered with t2 and f'/final rebuilt from it: exactly C4c's
     * c0 lane. (N1 is the SIGN version of the same form.) */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *fr = row_of(&B, B.sched - 1);
            fr[FAIR_COL_T1] = bump(fr[FAIR_COL_T1]);
            relast_t2(&B);
            relast(&B);
            expect_reject("N16 t1 tampered, t2 + f' rebuilt (C4c)", &B, 1);
            built_free(&B);
        } else {
            check("N16 build", 0);
        }
    }

    /* N17 — `t2` tampered with f'/final rebuilt from it: exactly C4d's c0 lane
     * (the written two-lane (beta - x0)*t1 form). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *fr = row_of(&B, B.sched - 1);
            fr[FAIR_COL_T2] = bump(fr[FAIR_COL_T2]);
            relast(&B);
            expect_reject("N17 t2 tampered, f' rebuilt (C4d)", &B, 1);
            built_free(&B);
        } else {
            check("N17 build", 0);
        }
    }

    /* N18 — a beta PUBLIC lane moved: exactly C4g on that phase's fold row. */
    {
        const uint64_t saved = W.pub[W.pub_beta + 2 * 4];
        W.pub[W.pub_beta + 2 * 4] = bump(saved);
        expect_reject("N18 beta public lane moved (C4g)", &W, 1);
        W.pub[W.pub_beta + 2 * 4] = saved;
    }

    /* N19 — a roll-in PUBLIC slot moved: exactly C4h on its roll-in fold row. */
    {
        const uint64_t saved = W.pub[W.pub_ro];
        W.pub[W.pub_ro] = bump(saved);
        expect_reject("N19 roll-in public slot moved (C4h)", &W, 1);
        W.pub[W.pub_ro] = saved;
    }

    /* N20 — `ro` non-zero on a NON-roll-in fold row (rterm and f'/final rebuilt
     * from it): exactly C4i, the constraint that makes divergence D1
     * structural — an unconsumed reduced opening is cfg-IMPOSSIBLE. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *fr = row_of(&B, B.sched - 1);
            fr[FAIR_COL_RO] = 1;
            relast_rterm(&B);
            relast(&B);
            expect_reject("N20 ro != 0 on a non-roll-in row (C4i / D1)", &B, 1);
            built_free(&B);
        } else {
            check("N20 build", 0);
        }
    }

    /* N21 — a roll-in VALUE moved to a phase the cfg does not name (cleared on
     * fold row 1, written on fold row 0). Count not pinned: several forms fire
     * on both rows, which is the point — there is no way to relocate a roll-in
     * that leaves the system satisfied. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *src = row_of(&B, B.n_chain + 1); /* is_rollin */
            uint64_t *dst = row_of(&B, B.n_chain + 0); /* not is_rollin */
            wr2(dst, FAIR_COL_RO, rd2(src, FAIR_COL_RO));
            wr2(src, FAIR_COL_RO, gold_fp2_zero());
            expect_reject("N21 roll-in value moved to another phase (D1)", &B, 0);
            built_free(&B);
        } else {
            check("N21 build", 0);
        }
    }

    /* N22 — the HANDOFF broken: fold row 0's x0 is chain_g + 1 and the entire
     * walk is rebuilt from it. Only C3d (`g' = g`) can fire. */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        V.x0_bump = 1;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            expect_reject("N22 handoff copy broken, walk rebuilt (C3d)", &B, 1);
            built_free(&B);
        } else {
            check("N22 build", 0);
        }
    }

    /* N23 — the LAST CHAIN row's `g` moved: fires its predecessor's C3c and the
     * handoff C3d (fold row 0's g is untouched). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *cr = row_of(&B, B.n_chain - 1);
            cr[FAIR_COL_G] = bump(cr[FAIR_COL_G]);
            expect_reject("N23 last chain row g moved (C3c + C3d)", &B, 2);
            built_free(&B);
        } else {
            check("N23 build", 0);
        }
    }

    /* N24 — the TERMINAL row's f moved in ONE lane, final_poly[0] untouched:
     * C4l's c0 lane AND C5's c0 lane. This is the pairing the P2a-i3 last-row
     * lesson demands: the boundary lives on a row a constraint actually reaches. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *tr = row_of(&B, B.sched);
            tr[FAIR_COL_F] = bump(tr[FAIR_COL_F]);
            expect_reject("N24 terminal row f moved (C4l + C5)", &B, 2);
            built_free(&B);
        } else {
            check("N24 build", 0);
        }
    }

    /* N25 — final_poly[0] public moved: exactly C5. */
    {
        const uint64_t saved = W.pub[W.pub_final];
        W.pub[W.pub_final] = bump(saved);
        expect_reject("N25 final_poly[0] public moved (C5)", &W, 1);
        W.pub[W.pub_final] = saved;
    }

    printf("\n-- fail-close negatives (G4/G5/G6) --------------------------\n");

    /* N26-N30 — publics canonicality, ONE per public region (OBL-2 / A2-F1).
     * p + v aliases v inside the field view while every downstream u64 consumer
     * is representation-sensitive; the entry rejects instead of reducing. */
    {
        const size_t region[5] = {0, W.pub_beta, W.pub_finit, W.pub_ro,
                                  W.pub_final};
        const char  *name[5] = {"N26 public >= p: index bit",
                                "N27 public >= p: beta lane",
                                "N28 public >= p: f_init",
                                "N29 public >= p: roll-in value",
                                "N30 public >= p: final_poly[0]"};
        for (int i = 0; i < 5; i++) {
            const uint64_t saved = W.pub[region[i]];
            /* p + (saved & 0xFF): non-canonical, aliases (saved & 0xFF) inside
             * the field view, and CANNOT wrap u64 (p + 255 < 2^64, the gap is
             * 2^32 - 1). Using p + saved would overflow for a full-width lane
             * and silently land back below p — testing nothing. */
            W.pub[region[i]] = GOLDILOCKS_P + (saved & 0xFFu);
            expect_bad_config(name[i], eval_built(&W));
            W.pub[region[i]] = saved;
        }
        check("N26-N30 publics restored", eval_built(&W) == 0);
    }

    /* N31/N32 — num_publics is EXACT, not a lower bound (G6a). */
    expect_bad_config("N31 num_publics + 1",
                      dnac_fair_eval_trace(W.trace, W.prep, W.rows, W.cfg, W.pub,
                                           W.num_pub + 1));
    expect_bad_config("N32 num_publics - 1",
                      dnac_fair_eval_trace(W.trace, W.prep, W.rows, W.cfg, W.pub,
                                           W.num_pub - 1));

    /* N33 — schedule conformance (G4a): the row count comes from the PINNED
     * schedule, never from a witnessed length. */
    expect_bad_config("N33 n_rows one short of the pinned schedule",
                      dnac_fair_eval_trace(W.trace, W.prep, W.rows - 1, W.cfg,
                                           W.pub, W.num_pub));

    /* N34 — terminality (G4b): a trace that ENDS on a typed row would silently
     * skip every transition-anchored form (the P2a-i3 shipped-HIGH shape). */
    {
        uint64_t *last = W.prep + (W.rows - 1) * (size_t)DNAC_P2C_TABLE_COLS;
        const uint64_t sp = last[DNAC_P2C_COL_IS_PAD];
        const uint64_t sf = last[DNAC_P2C_COL_IS_FOLD];
        last[DNAC_P2C_COL_IS_PAD] = 0;
        last[DNAC_P2C_COL_IS_FOLD] = 1;
        expect_bad_config("N34 last row typed (terminality)", eval_built(&W));
        last[DNAC_P2C_COL_IS_PAD] = sp;
        last[DNAC_P2C_COL_IS_FOLD] = sf;
        check("N34 prep restored", eval_built(&W) == 0);
    }

    /* N35 — PIN-2 shape (G5): a next MAIN row without a next PREPROCESSED row
     * is the `prep_next = 0` window C3c would evaluate against nothing. */
    expect_bad_config("N35 main_next without prep_next (PIN-2 shape)",
                      dnac_fair_eval_row(W.trace, W.trace + FAIR_NUM_COLS,
                                         W.prep, NULL, 1, W.cfg, W.pub,
                                         W.num_pub));
    /* N36 — and the mirror: prep_next without main_next. */
    expect_bad_config("N36 prep_next without main_next",
                      dnac_fair_eval_row(W.trace, NULL, W.prep,
                                         W.prep + DNAC_P2C_TABLE_COLS, 1, W.cfg,
                                         W.pub, W.num_pub));

    /* ── N37 (POSITIVE) — C6: padding rows carry NO main-trace constraint ──
     * design §0.5 :388-391 removed v1's "unchanged/zeroed" ambiguity precisely
     * because the zeroed reading collided with `g*inv = -1/2`. Garbage in every
     * column of a NON-terminal padding row must still evaluate to 0. */
    {
        uint64_t *pr = row_of(&W, W.sched + 1);
        for (size_t c = 0; c < FAIR_NUM_COLS; c++)
            pr[c] = gold_fp_to_u64(tfp((uint64_t)c + 3, 77));
        const int v = eval_built(&W);
        check("N37 garbage on a non-terminal padding row still accepted (C6)",
              v == 0);
        memset(pr, 0, FAIR_NUM_COLS * sizeof(uint64_t));
    }

    built_free(&W);

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("P2c FRI fold-walk AIR: %d FAIL\n", fails);
        return 1;
    }
    /* Counts audited by ENUMERATION against the blocks above, not by memory
     * (the count-KAFADAN class this project has now tripped four times — and
     * this very block was wrong on its first draft, which is why the numbers
     * below name their members):
     *
     *   accepts    5   REF@0, REF@8191, RECURSION, SMALL, REF@4660
     *   cfg gates  8   G0 NULL, G1, G2, G3, G7a, G7b, D2 queries, roll-in order
     *   negatives 37   N1, N2, N3, N4a, N4b, N5..N36, split as:
     *                  - 24 with a PINNED exact violation count: N1 N2 N3 N4b
     *                    N5 N6 N7 N8 N9 N10 N11 N12 N13 N14 N15 N16 N17 N18
     *                    N19 N20 N22 N23 N24 N25
     *                  -  2 caught WITHOUT a pinned count (the count would rest
     *                     on a fixture value being non-zero — a fake isolation
     *                     claim): N4a, N21
     *                  - 11 fail-close (FAIR_VIOL_BAD_CONFIG): N26..N36
     *   assertions 19  11 layout/shape + 3 fixture properties + the N1
     *                  precondition + 3 restore checks + N37 (C6 property) */
    printf("P2c FRI fold-walk AIR: 5 honest walks accepted (3 configs, native\n"
           "  fold + x0 closed-form cross-checked at every phase) +\n"
           "  8 eval-entry config gates + 37 negatives (24 exact-count pinned,\n"
           "  11 fail-close, 2 caught-without-count; N1-N4b are the MANDATORY\n"
           "  FLEET 020 catches) + 19 layout/shape/restore assertions\n"
           "  (incl. N37, the C6 padding-freedom property) — PASS\n");
    return 0;
}
