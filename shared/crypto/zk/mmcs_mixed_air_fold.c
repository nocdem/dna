/**
 * @file mmcs_mixed_air_fold.c
 * @brief s1a — the P2b slice-2 mixed-height MMCS-verify control AIR in
 *        verifier-fold (fp2) form.
 *
 * TRANSCRIPTION, not design. Every block below is the fold image of the block
 * with the SAME LETTER in `mmcs_mixed_air.c`, in the SAME order, and cites the
 * line range it transcribes. No constraint is added, removed or strengthened;
 * the deviations forced by the form are named where they occur:
 *   (1) everything the u64 evaluates only when `main_next != NULL`
 *       (mmcs_mixed_air.c:379 onwards) is multiplied by `is_transition`;
 *   (2) the trace-level terminality gate (mmcs_mixed_air.c:472-486) becomes an
 *       explicit `is_last_row` boundary — narrower than the u64 gate, by spec;
 *       see the ⚠ block in mmcs_mixed_air_fold.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmcs_mixed_air_fold.h"

#include <string.h>

#include "field_goldilocks.h"
#include "mmcs_mixed_air_table.h"
#include "poseidon2_air_cols.h"
#include "poseidon2_fold.h" /* dnac_poseidon2_fold_eval */

/* ── local fp2 shorthands (mmcs_air_fold.c / conf_action_fold.c idiom) ────── */
static inline gold_fp2_t sub(gold_fp2_t a, gold_fp2_t b) { return gold_fp2_sub(a, b); }
static inline gold_fp2_t mul(gold_fp2_t a, gold_fp2_t b) { return gold_fp2_mul(a, b); }

#define MMIX_FOLD_INF ((size_t)-1)

/* ═══════════════ binding — CALLER-OWNED state, no module static ═══════════
 * FLEET 034: `dnac_mmix_fold_state_t` lives in the header and the caller owns
 * the storage; `air_eval` reads it back out of `folder->ctx`. Nothing about the
 * derivation moved: the per-step map is still DECODED from the table module's
 * own row decoder (the schedule authority), and the absorb concat /
 * stream->public map are still re-derived from the cfg scalars and
 * cross-checked. See the header's DECLARED DUPLICATION note. Pure function of
 * the cfg: no clock, no RNG, no wire input. */

/* Elements absorbed by (inject-)leaf block `blk` of group `g`
 * (mmcs_mixed_air.c:212-217). */
static inline size_t mmixf_absorb(const dnac_mmix_fold_state_t *S, size_t g,
                                  size_t blk) {
    const size_t lg = S->g_lg[g];
    return (blk + 1 < lg) ? (size_t)MMIX_RATE
                          : S->g_concat[g] - (size_t)MMIX_RATE * (lg - 1);
}

/* Public index a group's absorb-stream position maps to, or MMIX_FOLD_INF for a
 * SALT lane (free witness). Re-derivation of mmcs_mixed_air.c:196-208. */
static size_t mmixf_stream_pub(const dnac_mmix_fold_state_t *S, size_t g,
                               size_t stream_pos) {
    const size_t gh = S->g_height[g];
    size_t off = 0;
    for (size_t m = 0; m < S->num_matrices; m++) {
        if (S->heights[m] != gh) continue;
        if (stream_pos < off + S->widths[m])
            return S->pub_opened + S->prefix_w[m] + (stream_pos - off);
        off += S->widths[m];
        if (stream_pos < off + S->salt_elems) return MMIX_FOLD_INF; /* salt */
        off += S->salt_elems;
    }
    return MMIX_FOLD_INF; /* out of range — unreachable for a scheduled slot */
}

/* Resolve the schedule. Returns 0 on reject (fail-close, never a guess). */
static int mmixf_resolve(const dnac_p2c_mmix_table_cfg_t *cfg,
                         dnac_mmix_fold_state_t *S) {
    if (cfg == NULL || S == NULL || cfg->widths == NULL ||
        cfg->heights == NULL)
        return 0;
    /* Zero FIRST: every early return then leaves a fully-initialised (and
     * unbound) snapshot, so no caller can copy indeterminate bytes. Matches
     * `fair_fold_derive` (fri_air_fold.c) and `foi_fold_derive`
     * (fri_oi_air_fold.c). Load-bearing since FLEET 034: the target used to be
     * a file-scope static (zeroed by C), and is now the CALLER'S storage, which
     * may be an uninitialised automatic. The per-step arrays are only written
     * for k < sched, so without this the tail stays indeterminate. */
    memset(S, 0, sizeof(*S));

    /* Every table accessor re-runs the module's cfg gate and returns 0 on
     * reject, so a bad cfg dies here. */
    const size_t rows = dnac_p2c_mmix_table_rows(cfg);
    const size_t sched = dnac_p2c_mmix_sched_rows(cfg);
    const size_t ng = dnac_p2c_mmix_num_groups(cfg);
    if (rows == 0 || sched == 0 || sched > DNAC_P2C_MMIX_MAX_STEPS) return 0;
    if (ng == 0 || ng > DNAC_P2C_MMIX_MAX_GROUPS) return 0;
    if (sched >= rows) return 0; /* the mandatory terminal padding row */
    if (cfg->num_matrices == 0 ||
        cfg->num_matrices > DNAC_P2C_MMIX_MAX_MATRICES)
        return 0;
    if (cfg->depth == 0 || cfg->depth > DNAC_P2C_MMIX_MAX_LEVELS) return 0;

    const size_t npub = dnac_mmix_air_num_publics(cfg);
    const size_t pub_opened = dnac_mmix_air_pub_opened_off(cfg);
    const size_t total = dnac_mmix_air_total_opened(cfg);
    if (npub == 0 || pub_opened == 0 || total == 0) return 0;
    if (pub_opened != (size_t)MMIX_DIGEST_LANES + cfg->depth) return 0;
    if (npub != pub_opened + total) return 0;

    S->sched = sched;
    S->depth = cfg->depth;
    S->num_groups = ng;
    S->total_opened = total;
    S->pub_opened = pub_opened;
    S->num_publics = npub;
    S->salt_elems = cfg->salt_elems;
    S->num_matrices = cfg->num_matrices;

    size_t acc = 0;
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        if (cfg->widths[m] == 0) return 0;
        S->widths[m] = cfg->widths[m];
        S->heights[m] = cfg->heights[m];
        S->prefix_w[m] = acc;
        acc += cfg->widths[m];
    }
    if (acc != total) return 0; /* this module vs dnac_mmix_air_total_opened */

    for (size_t g = 0; g < ng; g++) {
        const size_t gh = dnac_p2c_mmix_group_height(cfg, g);
        const size_t lg = dnac_p2c_mmix_group_leaf_rows(cfg, g);
        if (gh == 0 || lg == 0) return 0;
        size_t concat = 0;
        for (size_t m = 0; m < cfg->num_matrices; m++)
            if (cfg->heights[m] == gh) concat += cfg->widths[m] + cfg->salt_elems;
        if (concat == 0) return 0;
        /* The re-derived concat MUST reproduce the table module's own leaf-row
         * count (ceil(concat / RATE), no trailing permutation on an exact
         * multiple) — otherwise the two derivations disagree and the only safe
         * answer is to reject. */
        const size_t want_lg = (concat % (size_t)MMIX_RATE == 0)
                                   ? concat / (size_t)MMIX_RATE
                                   : concat / (size_t)MMIX_RATE + 1;
        if (want_lg != lg) return 0;
        S->g_height[g] = gh;
        S->g_lg[g] = lg;
        S->g_concat[g] = concat;
    }

    /* Per-step map, DECODED from the table module's row decoder: scheduled row
     * k carries pos[k] = 1 (mmcs_mixed_air_table.h:500-501), so the row index IS
     * the step index over the scheduled prefix. */
    size_t seen_leaf_rows[DNAC_P2C_MMIX_MAX_GROUPS];
    for (size_t g = 0; g < DNAC_P2C_MMIX_MAX_GROUPS; g++) seen_leaf_rows[g] = 0;

    for (size_t k = 0; k < sched; k++) {
        dnac_p2c_mmix_row_t rec;
        if (dnac_p2c_mmix_table_row(cfg, k, &rec) != DNAC_P2C_MMIX_TABLE_OK)
            return 0;
        if (rec.step != k) return 0; /* prefix-order assumption, verified */
        S->slevel[k] = rec.level;
        S->sgroup[k] = rec.group;
        S->sblk[k] = MMIX_FOLD_INF;
        switch (rec.type) {
        case DNAC_P2C_MMIX_ROW_LEAF:
        case DNAC_P2C_MMIX_ROW_INJECT_LEAF:
            if (rec.group >= ng) return 0;
            S->stype[k] = DNAC_MMIXF_T_LEAF;
            S->sblk[k] = seen_leaf_rows[rec.group]++;
            if (S->sblk[k] >= S->g_lg[rec.group]) return 0;
            break;
        case DNAC_P2C_MMIX_ROW_COMPRESS:
            if (rec.level >= S->depth) return 0;
            S->stype[k] = DNAC_MMIXF_T_COMPRESS;
            break;
        case DNAC_P2C_MMIX_ROW_INJECT_COMPRESS:
        case DNAC_P2C_MMIX_ROW_FINAL:
            S->stype[k] = DNAC_MMIXF_T_OTHER;
            break;
        default: /* a PAD row inside the scheduled prefix is a contradiction */
            return 0;
        }
    }
    /* Every group's leaf rows must all have been scheduled — otherwise this
     * module's absorb loops would be aimed at a shorter stream than the u64's. */
    for (size_t g = 0; g < ng; g++)
        if (seen_leaf_rows[g] != S->g_lg[g]) return 0;

    return 1;
}

size_t dnac_mmix_air_fold_control_steps(const dnac_p2c_mmix_table_cfg_t *cfg) {
    /* SCRATCH ONLY — multi-KB, so not a stack fixture. Unlike the retired
     * `g_mmix_fold` this carries NO cross-call meaning: `mmixf_resolve` writes
     * every field this function then reads, and a rejected cfg returns 0 before
     * any read. It is not a binding and `air_eval` never sees it. */
    static dnac_mmix_fold_state_t S;
    S.bound = 0;
    if (!mmixf_resolve(cfg, &S)) return 0;

    size_t n = 0;
    n += 2;                                    /* B */
    for (size_t k = 0; k < S.sched; k++) {     /* C */
        if (S.stype[k] != DNAC_MMIXF_T_LEAF) continue;
        const size_t g = S.sgroup[k], b = S.sblk[k];
        const size_t kab = mmixf_absorb(&S, g, b);
        for (size_t s = 0; s < kab; s++)
            if (mmixf_stream_pub(&S, g, (size_t)MMIX_RATE * b + s) != MMIX_FOLD_INF)
                n++;
        if (b == 0) n += (size_t)MMIX_PERM_WIDTH - kab;
    }
    n += S.depth;                              /* D */
    n += (size_t)MMIX_DIGEST_LANES;            /* E */
    n += (size_t)MMIX_DIGEST_LANES;            /* F */
    n += 6 * (size_t)MMIX_DIGEST_LANES;        /* G(2) + H + I + J + K, per lane */
    for (size_t k = 0; k < S.sched; k++) {     /* L */
        if (S.stype[k] != DNAC_MMIXF_T_LEAF) continue;
        const size_t b = S.sblk[k];
        if (b == 0) continue;
        n += (size_t)MMIX_PERM_WIDTH - mmixf_absorb(&S, S.sgroup[k], b);
    }
    n += 1;                                    /* M terminality */
    return n;
}

int dnac_mmix_air_fold_bind(const dnac_p2c_mmix_table_cfg_t *cfg,
                            dnac_mmix_fold_state_t *state,
                            dnac_stark_air_t *out_air) {
    /* Fail-close: ANY rejected bind DISARMS the DESCRIPTOR (`out_air->ctx =
     * NULL`) as well as the state it was handed — see the same block in
     * mmcs_air_fold.c for why the state alone is not enough. Only the ARMING is
     * cleared; the shape fields are the caller's and are left untouched. */
    if (out_air != NULL) out_air->ctx = NULL;
    if (state != NULL) state->bound = 0;
    if (state == NULL || cfg == NULL || out_air == NULL) return -1;

    if (!mmixf_resolve(cfg, state)) {
        state->bound = 0;
        return -1;
    }
    state->bound = 1;

    out_air->main_width = (size_t)MMIX_WIDTH;
    out_air->num_public_values = state->num_publics;
    out_air->main_next = 1; /* blocks G..L read the next row */
    out_air->air_eval = dnac_mmix_air_fold_eval;
    out_air->ctx = state;
    return 0;
}

/* ══════════════════════════ constraint emission ══════════════════════════ */

void dnac_mmix_air_fold_eval(dnac_stark_folder_t *f) {
    /* Shape / binding gate — fail-close (an `air_eval` cannot report an error,
     * and folding nothing would ACCEPT everything). `ctx == NULL` (no binding
     * at all) joins the same gate: the exact analogue of the retired
     * `!g_mmix_fold.bound`. The preprocessed-window requirement is PIN-2's
     * shape: a REAL next-row window, never a zero fill (batch_verify.c:696-707)
     * — the u64 rejects the same mismatch at mmcs_mixed_air.c:278. */
    const dnac_mmix_fold_state_t *const S =
        (const dnac_mmix_fold_state_t *)f->ctx;
    if (S == NULL || !S->bound || f->trace_local == NULL ||
        f->trace_next == NULL || f->main_width != (size_t)MMIX_WIDTH ||
        f->num_public_values != S->num_publics ||
        f->public_values == NULL || f->preprocessed_local == NULL ||
        f->preprocessed_next == NULL ||
        f->prep_width < (size_t)DNAC_P2C_MMIX_TABLE_COLS) {
        dnac_stark_folder_assert_zero(f, gold_fp2_one());
        return;
    }

    const gold_fp2_t *L = f->trace_local;
    const gold_fp2_t *N = f->trace_next;
    const gold_fp2_t *PL = f->preprocessed_local;
    const gold_fp2_t *PN = f->preprocessed_next;
    const gold_fp2_t one = gold_fp2_one();
    const gold_fp2_t tr = f->is_transition;

    /* Publics are BASE field in the folder (stark_constraints.h:265-266). */
#define MXPUB(i) gold_fp2_from_base(f->public_values[(i)])

    /* ══ Column reads (mmcs_mixed_air.c:295-299) ══════════════════════════ */
    const gold_fp2_t dir = L[MMIX_DIR_OFF];
    const gold_fp2_t pl_comp = PL[DNAC_P2C_MMIX_COL_IS_COMPRESS];
    const gold_fp2_t pl_fin = PL[DNAC_P2C_MMIX_COL_IS_FINAL];
    const gold_fp2_t pl_icomp = PL[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS];

    /* ══ A. Embedded poseidon2_air block — UNGATED (:301-306) ═════════════ */
    dnac_poseidon2_fold_eval(f, (size_t)MMIX_PERM_OFF);

    /* ══ B. `dir` — boolean, and ZERO off compress rows (:308-316) ════════ */
    dnac_stark_folder_assert_zero(f, mul(dir, sub(dir, one)));
    dnac_stark_folder_assert_zero(f, mul(sub(one, pl_comp), dir));

    /* ══ C. Leaf & inject-leaf rows — OVERWRITE absorb (:318-347) ═════════
     * Gated by the PREPROCESSED step one-hot pos[k]; DATA slots are pinned to
     * their public opened element, SALT slots emit nothing (free witness,
     * OBL-6); the FIRST block of each group starts from an ALL-ZERO state. */
    for (size_t k = 0; k < S->sched; k++) {
        if (S->stype[k] != DNAC_MMIXF_T_LEAF) continue;
        const size_t g = S->sgroup[k];
        const size_t b = S->sblk[k];
        const size_t kab = mmixf_absorb(S, g, b);
        const gold_fp2_t gate = PL[dnac_p2c_mmix_col_pos(k)];
        for (size_t s = 0; s < kab; s++) {
            const size_t pub = mmixf_stream_pub(S, g, (size_t)MMIX_RATE * b + s);
            if (pub != MMIX_FOLD_INF)
                dnac_stark_folder_when(f, gate,
                                       sub(L[mmix_perm_in_off(s)], MXPUB(pub)));
        }
        if (b == 0)
            for (size_t j = kab; j < (size_t)MMIX_PERM_WIDTH; j++)
                dnac_stark_folder_when(f, gate, L[mmix_perm_in_off(j)]);
    }

    /* ══ D. Index binding — A1, LSB-first, bits as PUBLICS (:349-359) ═════ */
    for (size_t k = 0; k < S->sched; k++) {
        if (S->stype[k] != DNAC_MMIXF_T_COMPRESS) continue;
        dnac_stark_folder_when(
            f, PL[dnac_p2c_mmix_col_pos(k)],
            sub(dir, MXPUB((size_t)MMIX_PUB_DIR_OFF + S->slevel[k])));
    }

    /* ══ E. Final row — root equality (:361-367) ══════════════════════════ */
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
        dnac_stark_folder_when(
            f, pl_fin,
            sub(L[mmix_perm_in_off(j)], MXPUB((size_t)MMIX_PUB_ROOT_OFF + j)));

    /* ══ F. Inject-compress LEFT input == the carried running digest
     * (:369-377; the native combine order is running FIRST,
     * poseidon2_mmcs.c:522) ══════════════════════════════════════════════ */
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
        dnac_stark_folder_when(
            f, pl_icomp, sub(L[mmix_perm_in_off(j)], L[mmix_rdig_off(j)]));

    /* ═══════════════════════════════════════════════════════════════════════
     * Everything below is the u64's post-`if (!main_next) return v;` half
     * (mmcs_mixed_air.c:379). Each residual is multiplied by `is_transition`.
     * ═══════════════════════════════════════════════════════════════════════ */

    const gold_fp2_t pn_comp = PN[DNAC_P2C_MMIX_COL_IS_COMPRESS];
    const gold_fp2_t pn_fin = PN[DNAC_P2C_MMIX_COL_IS_FINAL];
    const gold_fp2_t pn_icomp = PN[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS];
    const gold_fp2_t pl_hasinj = PL[DNAC_P2C_MMIX_COL_HAS_INJECT];
    const gold_fp2_t pl_ileaf = PL[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF];
    const gold_fp2_t ndir = N[MMIX_DIR_OFF];

    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++) {
        const gold_fp2_t out = L[mmix_perm_out_off(j)];

        /* ══ G. Running-digest PLACEMENT into the next compress row (:391-402) */
        dnac_stark_folder_when(
            f, tr,
            mul(mul(pn_comp, sub(one, ndir)), sub(N[mmix_perm_in_off(j)], out)));
        dnac_stark_folder_when(
            f, tr,
            mul(mul(pn_comp, ndir),
                sub(N[mmix_perm_in_off((size_t)MMIX_DIGEST_LANES + j)], out)));

        /* ══ H. Final-row threading (:404-409) ════════════════════════════ */
        dnac_stark_folder_when(
            f, tr, mul(pn_fin, sub(N[mmix_perm_in_off(j)], out)));

        /* ══ I. Inject-compress RIGHT == the last inject-leaf's output
         * (:411-417) ═════════════════════════════════════════════════════ */
        dnac_stark_folder_when(
            f, tr,
            mul(pn_icomp,
                sub(N[mmix_perm_in_off((size_t)MMIX_DIGEST_LANES + j)], out)));

        /* ══ J. RDIG SEED (:419-423) ══════════════════════════════════════ */
        dnac_stark_folder_when(f, tr,
                               mul(pl_hasinj, sub(N[mmix_rdig_off(j)], out)));

        /* ══ K. RDIG CARRY (:425-431) ═════════════════════════════════════ */
        dnac_stark_folder_when(
            f, tr, mul(pl_ileaf, sub(N[mmix_rdig_off(j)], L[mmix_rdig_off(j)])));
    }

    /* ══ L. Leaf & inject-leaf state threading (:434-453) ═════════════════
     * Anchored at the PREDECESSOR (pos[k-1]) so it never fires on a
     * last-leaf -> compress / inject-compress step. */
    for (size_t k = 0; k < S->sched; k++) {
        if (S->stype[k] != DNAC_MMIXF_T_LEAF) continue;
        const size_t b = S->sblk[k];
        if (b == 0) continue;
        const size_t kab = mmixf_absorb(S, S->sgroup[k], b);
        const gold_fp2_t gate = PL[dnac_p2c_mmix_col_pos(k - 1)];
        for (size_t j = kab; j < (size_t)MMIX_PERM_WIDTH; j++)
            dnac_stark_folder_when(
                f, tr,
                mul(gate, sub(N[mmix_perm_in_off(j)], L[mmix_perm_out_off(j)])));
    }

    /* ══ M. TERMINALITY — the fold image of the trace-level gate at
     * mmcs_mixed_air.c:472-486. The final trace row gets NO transition
     * constraints, so requiring it to be a PADDING row is what makes "every row
     * carrying a row type has a successor" structurally true. NARROWER than the
     * u64 gate by spec (`is_pad` only); the residual five type-flag zeros are
     * the generator's TYPE-EXCLUSIVITY obligation under PIN-1-MMIX — see the ⚠
     * block in mmcs_mixed_air_fold.h. ═══════════════════════════════════════ */
    dnac_stark_folder_when(f, f->is_last_row,
                           sub(one, PL[DNAC_P2C_MMIX_COL_IS_PAD]));

#undef MXPUB
}
