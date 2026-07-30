/**
 * @file mmcs_air_fold.c
 * @brief s1a — the P2b slice-1 same-height MMCS-verify control AIR in
 *        verifier-fold (fp2) form.
 *
 * TRANSCRIPTION, not design. Every block below is the fold image of the block
 * with the SAME LETTER in `mmcs_air.c`, in the SAME order, and cites the line
 * range it transcribes. No constraint is added, removed or strengthened; the two
 * deviations forced by the form are named where they occur:
 *   (1) everything the u64 evaluates only when `main_next != NULL`
 *       (mmcs_air.c:322 onwards) is multiplied by `is_transition`;
 *   (2) the trace-level terminality gate (mmcs_air.c:445-451) becomes an
 *       explicit `is_last_row` boundary constraint, emitted last.
 * See mmcs_air_fold.h for the API contract, the degree consequence, the s1b
 * entry duties and the PIN-1 / PIN-2 prerequisites this module inherits.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmcs_air_fold.h"

#include "field_goldilocks.h"
#include "mmcs_air_table.h"
#include "poseidon2_air_cols.h"
#include "poseidon2_fold.h" /* dnac_poseidon2_fold_eval */

/* ── local fp2 shorthands (conf_action_fold.c / transcript_air_fold.c idiom) ─ */
static inline gold_fp2_t add(gold_fp2_t a, gold_fp2_t b) { return gold_fp2_add(a, b); }
static inline gold_fp2_t sub(gold_fp2_t a, gold_fp2_t b) { return gold_fp2_sub(a, b); }
static inline gold_fp2_t mul(gold_fp2_t a, gold_fp2_t b) { return gold_fp2_mul(a, b); }

/* ══════════════════════════ module-static binding ════════════════════════ */

typedef struct {
    int    bound;
    size_t leaf;        /* leaf-hash rows                                   */
    size_t depth;       /* compress rows                                    */
    size_t total_width; /* Σ widths[m] — the sponge input length            */
    size_t pub_open;    /* first public index of the opened-rows region     */
    size_t num_publics;
} mair_fold_state_t;

static mair_fold_state_t g_mair_fold; /* zero-initialized: unbound */

/* Elements absorbed by leaf block `blk` — `mair_absorb_count`'s formula
 * (mmcs_air.c:110-114) over the scalars the public accessors hand back. */
static inline size_t mair_fold_absorb(const mair_fold_state_t *s, size_t blk) {
    return (blk + 1 < s->leaf) ? (size_t)MAIR_RATE
                               : s->total_width - (size_t)MAIR_RATE * (s->leaf - 1);
}

/* Resolve the schedule scalars THROUGH the u64 module's public accessors — the
 * ONE schedule authority (mmcs_air.c:118-140, each of which runs the static
 * `mair_schedule` and returns 0 on reject). Returns 0 on reject. */
static int mair_fold_resolve(const dnac_p2b_table_cfg_t *cfg,
                             mair_fold_state_t *s) {
    if (cfg == NULL) return 0;
    const size_t leaf = dnac_mmcs_air_leaf_rows(cfg);
    const size_t total = dnac_mmcs_air_total_width(cfg);
    const size_t pub_open = dnac_mmcs_air_pub_opened_off(cfg);
    const size_t npub = dnac_mmcs_air_num_publics(cfg);
    if (leaf == 0 || total == 0 || pub_open == 0 || npub == 0) return 0;
    /* `pub_open == MAIR_PUB_DIR_OFF + depth` (mmcs_air.c:130-134) is how the
     * depth is read back out of the authority rather than off the raw cfg; the
     * two MUST agree, else this module and the u64 module disagree about the
     * schedule and the only safe answer is to reject. */
    if (pub_open <= (size_t)MAIR_PUB_DIR_OFF) return 0;
    const size_t depth = pub_open - (size_t)MAIR_PUB_DIR_OFF;
    if (depth != cfg->depth) return 0;
    if (npub != pub_open + total) return 0;
    if (leaf + depth + 1 > (size_t)MAIR_MAX_STEPS) return 0;

    s->leaf = leaf;
    s->depth = depth;
    s->total_width = total;
    s->pub_open = pub_open;
    s->num_publics = npub;
    return 1;
}

size_t dnac_mmcs_air_fold_control_steps(const dnac_p2b_table_cfg_t *cfg) {
    mair_fold_state_t s;
    s.bound = 0;
    if (!mair_fold_resolve(cfg, &s)) return 0;

    size_t n = 0;
    n += 2;                                  /* B  */
    n += 2 * (size_t)MAIR_MAX_STEPS + 1;     /* C  one-hot + typed sum */
    n += 1;                                  /* C  row-0 anchor */
    n += s.total_width;                      /* D  absorbed lanes */
    n += (size_t)MAIR_PERM_WIDTH - mair_fold_absorb(&s, 0); /* D  zero fill */
    n += s.depth;                            /* E  */
    n += (size_t)MAIR_DIGEST_LANES;          /* F  */
    n += (size_t)MAIR_MAX_STEPS;             /* G  advance + overflow guard */
    for (size_t blk = 1; blk < s.leaf; blk++) /* H */
        n += (size_t)MAIR_PERM_WIDTH - mair_fold_absorb(&s, blk);
    n += 2 * (size_t)MAIR_DIGEST_LANES;      /* I  */
    n += (size_t)MAIR_DIGEST_LANES;          /* J  */
    n += 1;                                  /* M  terminality */
    return n;
}

int dnac_mmcs_air_fold_bind(const dnac_p2b_table_cfg_t *cfg,
                            dnac_stark_air_t *out_air) {
    /* Fail-close: a rejected bind DISARMS, so a stale cfg cannot survive it. */
    g_mair_fold.bound = 0;
    if (cfg == NULL || out_air == NULL) return -1;

    mair_fold_state_t s;
    s.bound = 0;
    if (!mair_fold_resolve(cfg, &s)) return -1;

    s.bound = 1;
    g_mair_fold = s;

    out_air->main_width = (size_t)MAIR_WIDTH;
    out_air->num_public_values = s.num_publics;
    out_air->main_next = 1; /* blocks G..J read the next row */
    out_air->air_eval = dnac_mmcs_air_fold_eval;
    return 0;
}

/* ══════════════════════════ constraint emission ══════════════════════════ */

void dnac_mmcs_air_fold_eval(dnac_stark_folder_t *f) {
    /* Shape / binding gate. `air_eval` cannot report an error, so an
     * out-of-contract call emits ONE unsatisfiable constraint rather than
     * folding nothing (which would ACCEPT everything). The preprocessed window
     * requirement is PIN-2's shape: a REAL next-row window, never a zero fill
     * (batch_verify.c:696-707). */
    if (!g_mair_fold.bound || f->trace_local == NULL || f->trace_next == NULL ||
        f->main_width != (size_t)MAIR_WIDTH ||
        f->num_public_values != g_mair_fold.num_publics ||
        f->public_values == NULL || f->preprocessed_local == NULL ||
        f->preprocessed_next == NULL ||
        f->prep_width < (size_t)DNAC_P2B_TABLE_COLS) {
        dnac_stark_folder_assert_zero(f, gold_fp2_one());
        return;
    }

    const mair_fold_state_t *const S = &g_mair_fold;
    const gold_fp2_t *L = f->trace_local;
    const gold_fp2_t *N = f->trace_next;
    const gold_fp2_t *PL = f->preprocessed_local;
    const gold_fp2_t *PN = f->preprocessed_next;
    const gold_fp2_t one = gold_fp2_one();
    const gold_fp2_t zero = gold_fp2_zero();
    const gold_fp2_t tr = f->is_transition;

    /* Publics are BASE field in the folder (stark_constraints.h:265-266);
     * promote in-expression, the conf_root_fold idiom. */
#define MFPUB(i) gold_fp2_from_base(f->public_values[(i)])

    /* ══ Column reads (mmcs_air.c:202-207) ════════════════════════════════ */
    const gold_fp2_t dir = L[MAIR_DIR_OFF];
    const gold_fp2_t pl_leaf = PL[DNAC_P2B_COL_IS_LEAF];
    const gold_fp2_t pl_comp = PL[DNAC_P2B_COL_IS_COMPRESS];
    const gold_fp2_t pl_fin = PL[DNAC_P2B_COL_IS_FINAL];
    const gold_fp2_t pl_sum = add(add(pl_leaf, pl_comp), pl_fin);

    /* ══ A. Embedded poseidon2_air block — UNGATED (mmcs_air.c:209-214) ═══ */
    dnac_poseidon2_fold_eval(f, (size_t)MAIR_PERM_OFF);

    /* ══ B. `dir` — boolean, and ZERO off compress rows (:216-226) ════════ */
    dnac_stark_folder_assert_zero(f, mul(dir, sub(dir, one)));
    dnac_stark_folder_assert_zero(f, mul(sub(one, pl_comp), dir));

    /* ══ C. Step index — one-hot, typed, anchored (:228-260) ══════════════ */
    {
        gold_fp2_t sum = zero;
        for (size_t i = 0; i < (size_t)MAIR_MAX_STEPS; i++) {
            const gold_fp2_t p = L[mair_pos_off(i)];
            dnac_stark_folder_assert_zero(f, mul(p, sub(p, one)));
            sum = add(sum, p);
            if (i < S->leaf) {
                dnac_stark_folder_assert_zero(f, mul(p, sub(one, pl_leaf)));
            } else if (i < S->leaf + S->depth) {
                dnac_stark_folder_assert_zero(f, mul(p, sub(one, pl_comp)));
            } else if (i == S->leaf + S->depth) {
                dnac_stark_folder_assert_zero(f, mul(p, sub(one, pl_fin)));
            } else {
                dnac_stark_folder_assert_zero(f, p);
            }
        }
        dnac_stark_folder_assert_zero(f, sub(sum, pl_sum));
    }
    /* Boundary: trace row 0 is step 0 (:258-260). */
    dnac_stark_folder_when(f, f->is_first_row, sub(one, L[mair_pos_off(0)]));

    /* ══ D. Leaf rows — PaddingFreeSponge absorb (:262-290) ═══════════════ */
    for (size_t blk = 0; blk < S->leaf; blk++) {
        const gold_fp2_t g = L[mair_pos_off(blk)];
        const size_t k = mair_fold_absorb(S, blk);
        for (size_t j = 0; j < k; j++)
            dnac_stark_folder_when(
                f, g,
                sub(L[mair_perm_in_off(j)],
                    MFPUB(S->pub_open + (size_t)MAIR_RATE * blk + j)));
        if (blk == 0)
            for (size_t j = k; j < (size_t)MAIR_PERM_WIDTH; j++)
                dnac_stark_folder_when(f, g, L[mair_perm_in_off(j)]);
    }

    /* ══ E. Index binding — A1, LSB-first, bits as PUBLICS (:292-308) ════ */
    for (size_t l = 0; l < S->depth; l++)
        dnac_stark_folder_when(f, L[mair_pos_off(S->leaf + l)],
                               sub(dir, MFPUB((size_t)MAIR_PUB_DIR_OFF + l)));

    /* ══ F. Final row — root equality (:310-320) ══════════════════════════ */
    for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++)
        dnac_stark_folder_when(
            f, pl_fin,
            sub(L[mair_perm_in_off(j)], MFPUB((size_t)MAIR_PUB_ROOT_OFF + j)));

    /* ═══════════════════════════════════════════════════════════════════════
     * Everything below is the u64's post-`if (!main_next) return v;` half
     * (mmcs_air.c:322). Each residual is multiplied by `is_transition`.
     * ═══════════════════════════════════════════════════════════════════════ */

    const gold_fp2_t pn_leaf = PN[DNAC_P2B_COL_IS_LEAF];
    const gold_fp2_t pn_comp = PN[DNAC_P2B_COL_IS_COMPRESS];
    const gold_fp2_t pn_fin = PN[DNAC_P2B_COL_IS_FINAL];
    const gold_fp2_t pn_sum = add(add(pn_leaf, pn_comp), pn_fin);
    const gold_fp2_t ndir = N[MAIR_DIR_OFF];

    /* ══ G. Step advance — exactly one per scheduled row (:330-339) ═══════ */
    for (size_t i = 0; i + 1 < (size_t)MAIR_MAX_STEPS; i++) {
        const gold_fp2_t g = mul(L[mair_pos_off(i)], pn_sum);
        dnac_stark_folder_when(f, tr, mul(g, sub(N[mair_pos_off(i + 1)], one)));
    }
    dnac_stark_folder_when(
        f, tr, mul(L[mair_pos_off((size_t)MAIR_MAX_STEPS - 1)], pn_sum));

    /* ══ H. Leaf state threading — OVERWRITE absorb (:341-354) ════════════ */
    for (size_t blk = 1; blk < S->leaf; blk++) {
        const gold_fp2_t g = L[mair_pos_off(blk - 1)];
        const size_t k = mair_fold_absorb(S, blk);
        for (size_t j = k; j < (size_t)MAIR_PERM_WIDTH; j++)
            dnac_stark_folder_when(
                f, tr, mul(g, sub(N[mair_perm_in_off(j)], L[mair_perm_out_off(j)])));
    }

    /* ══ I. Placement pair — the ported core (:356-387) ═══════════════════ */
    for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++) {
        const gold_fp2_t out = L[mair_perm_out_off(j)];
        dnac_stark_folder_when(
            f, tr,
            mul(mul(pn_comp, sub(one, ndir)), sub(N[mair_perm_in_off(j)], out)));
        dnac_stark_folder_when(
            f, tr,
            mul(mul(pn_comp, ndir),
                sub(N[mair_perm_in_off((size_t)MAIR_DIGEST_LANES + j)], out)));
    }

    /* ══ J. Final-row threading (:389-397) ════════════════════════════════ */
    for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++)
        dnac_stark_folder_when(
            f, tr,
            mul(pn_fin, sub(N[mair_perm_in_off(j)], L[mair_perm_out_off(j)])));

    /* ══ M. TERMINALITY — the fold image of the trace-level gate at
     * mmcs_air.c:445-451. The final trace row gets NO transition constraints, so
     * requiring it to be PADDING (all three preprocessed selectors zero, i.e.
     * their SUM zero) is what makes "every row carrying a row type has a
     * successor" structurally true. Emitted LAST, mirroring the u64 order. ══ */
    dnac_stark_folder_when(f, f->is_last_row, pl_sum);

#undef MFPUB
}
