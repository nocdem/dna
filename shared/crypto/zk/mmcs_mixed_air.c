/**
 * @file mmcs_mixed_air.c
 * @brief P2b slice 2 — mixed-height binary MMCS-verify control AIR: constraint
 *        evaluation.
 *
 * Every block below names the native `dnac_p2_mmcs_verify_mixed`
 * (poseidon2_mmcs.c:454-529, byte-matched to Plonky3 82cfad73) line whose
 * semantics it mirrors, or the slice-1 `mmcs_air.c` form it reuses (the SAME
 * leaf-sponge + compress machinery). See mmcs_mixed_air.h for the layout
 * contract, the INLINE-embedding decision, the RDIG-carry rationale, the
 * PIN-1-MMIX / PIN-2 prerequisites, the public-value layout and the OBL ledger.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmcs_mixed_air.h"

#include "field_goldilocks.h"
#include "poseidon2_air.h"

/* ── local field shorthands (mmcs_air.c / transcript_air.c idiom) ──────────── */
static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/** Assert a constraint residual is zero; count the violation otherwise. */
static inline void az(int *v, gold_fp_t residual) {
    if (!gold_fp_is_zero(residual)) (*v)++;
}

/* ══════════════════════════ schedule (from the table module) ══════════════
 * The row schedule has exactly ONE authority: `mmcs_mixed_air_table` (the
 * mmcs_air.c:34-40 posture). This file does NOT re-derive the SHAPE — it reads
 * the group counts / heights / leaf-row counts / scheduled-row count back OUT of
 * the table accessors, then reconstructs the PREFIX ORDER (which the accessors
 * pin implicitly) and cross-checks its own scheduled-row total against
 * `dnac_p2c_mmix_sched_rows`. Pure function of `cfg`: no clock, no RNG, no
 * witness input, fixed-bound loops.
 * ========================================================================== */

enum {
    MMIX_T_LEAF = 0,
    MMIX_T_COMPRESS,
    MMIX_T_INJECT_LEAF,
    MMIX_T_INJECT_COMPRESS,
    MMIX_T_FINAL
};

typedef struct {
    size_t sched;         /* scheduled (non-padding) rows                     */
    size_t rows;          /* padded table height (== trace height)            */
    size_t depth;         /* Merkle depth == log2(max_h)                      */
    size_t num_groups;    /* distinct present heights                         */
    size_t max_h;         /* tallest height                                   */
    size_t total_opened;  /* Σ widths[m] (semantic) — opened-rows public len  */
    size_t salt_elems;    /* per-matrix leaf-absorb salt                      */
    size_t num_matrices;
    const size_t *widths;
    const size_t *heights;
    size_t pub_opened_off; /* == MMIX_DIGEST_LANES + depth                    */
    size_t num_publics;    /* == pub_opened_off + total_opened                */
    /* per-matrix public prefix (matrix order): matrix m's data lanes live at
     * publics[pub_opened_off + prefix_w[m] .. + widths[m]). */
    size_t prefix_w[DNAC_P2C_MMIX_MAX_MATRICES];
    /* per group (descending distinct height, group 0 == tallest) */
    size_t g_height[DNAC_P2C_MMIX_MAX_GROUPS];
    size_t g_lg[DNAC_P2C_MMIX_MAX_GROUPS];     /* (inject-)leaf rows          */
    size_t g_concat[DNAC_P2C_MMIX_MAX_GROUPS]; /* Σ (width+salt) over members */
    /* per-step arrays follow */
    /* per scheduled step k < sched */
    uint8_t stype[DNAC_P2C_MMIX_MAX_STEPS];
    size_t  slevel[DNAC_P2C_MMIX_MAX_STEPS]; /* compress/inject level, else ∞ */
    size_t  sgroup[DNAC_P2C_MMIX_MAX_STEPS]; /* leaf/inject group, else ∞     */
    size_t  sblk[DNAC_P2C_MMIX_MAX_STEPS];   /* within-group leaf block, else ∞*/
} mmix_sched_t;

#define MMIX_INF ((size_t)-1)

/* Fail-close schedule resolution. Returns 1 on success. */
static int mmix_build(const dnac_p2c_mmix_table_cfg_t *cfg, mmix_sched_t *S) {
    if (cfg == NULL) return 0;

    /* Every accessor re-runs the table module's cfg gate (NULL / depth /
     * heights-pow2 / widths / depth==log2(max_h) / bounds) and returns 0 on
     * reject — so a bad cfg makes rows == 0 here. */
    const size_t rows = dnac_p2c_mmix_table_rows(cfg);
    if (rows == 0) return 0;
    const size_t sched = dnac_p2c_mmix_sched_rows(cfg);
    if (sched == 0 || sched > DNAC_P2C_MMIX_MAX_STEPS) return 0;
    const size_t ng = dnac_p2c_mmix_num_groups(cfg);
    if (ng == 0 || ng > DNAC_P2C_MMIX_MAX_GROUPS) return 0;
    if (cfg->num_matrices == 0 ||
        cfg->num_matrices > DNAC_P2C_MMIX_MAX_MATRICES)
        return 0;

    S->rows = rows;
    S->sched = sched;
    S->num_groups = ng;
    S->depth = cfg->depth;
    S->num_matrices = cfg->num_matrices;
    S->widths = cfg->widths;
    S->heights = cfg->heights;
    S->salt_elems = cfg->salt_elems;

    const size_t max_h = dnac_p2c_mmix_group_height(cfg, 0);
    if (max_h == 0) return 0;
    S->max_h = max_h;

    /* per-matrix public prefix + total opened width */
    size_t total = 0;
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        S->prefix_w[m] = total;
        if (cfg->widths[m] == 0) return 0; /* cfg gate already forbids, belt+brace */
        total += cfg->widths[m];
    }
    S->total_opened = total;
    S->pub_opened_off = (size_t)MMIX_DIGEST_LANES + S->depth;
    S->num_publics = S->pub_opened_off + total;

    /* group shapes */
    for (size_t g = 0; g < ng; g++) {
        const size_t gh = dnac_p2c_mmix_group_height(cfg, g);
        const size_t lg = dnac_p2c_mmix_group_leaf_rows(cfg, g);
        if (gh == 0 || lg == 0) return 0;
        S->g_height[g] = gh;
        S->g_lg[g] = lg;
        size_t concat = 0;
        for (size_t m = 0; m < cfg->num_matrices; m++)
            if (cfg->heights[m] == gh)
                concat += cfg->widths[m] + cfg->salt_elems;
        if (concat == 0) return 0;
        S->g_concat[g] = concat;
    }

    /* Reconstruct the PREFIX schedule (mmcs_mixed_air_table.c:252-331 order):
     * tallest-group leaf | per level (compress [+ inject block]) | final. */
    size_t cur = 0;
    for (size_t i = 0; i < S->g_lg[0]; i++) {
        if (cur >= sched) return 0;
        S->stype[cur] = MMIX_T_LEAF;
        S->slevel[cur] = MMIX_INF;
        S->sgroup[cur] = 0;
        S->sblk[cur] = i;
        cur++;
    }
    for (size_t l = 0; l < S->depth; l++) {
        const size_t cur_after = max_h >> (l + 1);
        if (cur >= sched) return 0;
        S->stype[cur] = MMIX_T_COMPRESS;
        S->slevel[cur] = l;
        S->sgroup[cur] = MMIX_INF;
        S->sblk[cur] = MMIX_INF;
        cur++;

        /* the injecting group at this level (if any present height == cur_after;
         * cur_after < max_h always, so group 0 is never injected). */
        size_t gi = MMIX_INF;
        for (size_t g = 0; g < ng; g++)
            if (S->g_height[g] == cur_after) { gi = g; break; }
        if (gi != MMIX_INF) {
            for (size_t i = 0; i < S->g_lg[gi]; i++) {
                if (cur >= sched) return 0;
                S->stype[cur] = MMIX_T_INJECT_LEAF;
                S->slevel[cur] = l;
                S->sgroup[cur] = gi;
                S->sblk[cur] = i;
                cur++;
            }
            if (cur >= sched) return 0;
            S->stype[cur] = MMIX_T_INJECT_COMPRESS;
            S->slevel[cur] = l;
            S->sgroup[cur] = gi;
            S->sblk[cur] = MMIX_INF;
            cur++;
        }
    }
    if (cur >= sched) return 0;
    S->stype[cur] = MMIX_T_FINAL;
    S->slevel[cur] = MMIX_INF;
    S->sgroup[cur] = MMIX_INF;
    S->sblk[cur] = MMIX_INF;
    cur++;

    /* Consistency with the table module's own scheduled-row count: this file's
     * reconstruction and the accessor MUST agree, else fail closed (never guess)
     * — the mmcs_air.c:83-84 discipline. */
    if (cur != sched) return 0;
    return 1;
}

/* Public index a group's absorb-stream position maps to, or MMIX_INF for a SALT
 * lane (free witness). The stream is, per member matrix in MATRIX order,
 * [ data(widths[m]) ‖ salt(salt_elems) ] — matching the native concat
 * (poseidon2_mmcs.c:296-310 over the physical row = data ‖ salt). */
static size_t mmix_stream_pub(const mmix_sched_t *S, size_t g, size_t stream_pos) {
    const size_t gh = S->g_height[g];
    size_t off = 0;
    for (size_t m = 0; m < S->num_matrices; m++) {
        if (S->heights[m] != gh) continue;
        if (stream_pos < off + S->widths[m])
            return S->pub_opened_off + S->prefix_w[m] + (stream_pos - off);
        off += S->widths[m];
        if (stream_pos < off + S->salt_elems) return MMIX_INF; /* salt */
        off += S->salt_elems;
    }
    return MMIX_INF; /* out of range — unreachable for a scheduled absorb slot */
}

/* Elements absorbed by (inject-)leaf block `blk` of group `g`
 * (poseidon2_mmcs.c:53-68 — RATE per block, remainder on the last). */
static size_t mmix_absorb_count(const mmix_sched_t *S, size_t g, size_t blk) {
    const size_t lg = S->g_lg[g];
    const size_t concat = S->g_concat[g];
    return (blk + 1 < lg) ? (size_t)MMIX_RATE
                          : concat - (size_t)MMIX_RATE * (lg - 1);
}

/* ══════════════════════════ public helpers ═══════════════════════════════ */

size_t dnac_mmix_air_total_opened(const dnac_p2c_mmix_table_cfg_t *cfg) {
    mmix_sched_t S;
    if (!mmix_build(cfg, &S)) return 0;
    return S.total_opened;
}

size_t dnac_mmix_air_pub_opened_off(const dnac_p2c_mmix_table_cfg_t *cfg) {
    mmix_sched_t S;
    if (!mmix_build(cfg, &S)) return 0;
    return S.pub_opened_off;
}

size_t dnac_mmix_air_num_publics(const dnac_p2c_mmix_table_cfg_t *cfg) {
    mmix_sched_t S;
    if (!mmix_build(cfg, &S)) return 0;
    return S.num_publics;
}

bool dnac_mmix_air_layout_check(void) {
    if (MMIX_DIR_OFF != 0) return false;
    if (MMIX_RDIG_OFF != (size_t)MMIX_DIR_OFF + 1) return false;
    if (MMIX_PERM_OFF != MMIX_RDIG_OFF + (size_t)MMIX_DIGEST_LANES) return false;
    if (MMIX_WIDTH != MMIX_PERM_OFF + (size_t)P2AIR_NUM_COLS) return false;
    /* Accessors land inside their own blocks. */
    if (mmix_rdig_off(0) != (size_t)MMIX_RDIG_OFF) return false;
    if (mmix_rdig_off(MMIX_DIGEST_LANES - 1) != MMIX_PERM_OFF - 1) return false;
    if (mmix_perm_in_off(0) != MMIX_PERM_OFF) return false;
    if (mmix_perm_in_off(MMIX_PERM_WIDTH - 1) !=
        MMIX_PERM_OFF + (size_t)MMIX_PERM_WIDTH - 1)
        return false;
    if (mmix_perm_out_off(MMIX_PERM_WIDTH - 1) != MMIX_WIDTH - 1) return false;
    /* Public-value blocks are disjoint and ordered. */
    if (MMIX_PUB_ROOT_OFF != 0) return false;
    if (MMIX_PUB_DIR_OFF != (size_t)MMIX_DIGEST_LANES) return false;
    /* Dimensions mirror the native primitives. */
    if (MMIX_DIGEST_LANES != DNAC_P2M_DIGEST_LANES) return false;
    if (MMIX_PERM_WIDTH != P2AIR_WIDTH) return false;
    if (MMIX_RATE != DNAC_P2C_MMIX_SPONGE_RATE) return false;
    if ((size_t)MMIX_RATE > (size_t)MMIX_PERM_WIDTH) return false;
    if (MMIX_DIGEST_LANES != MMIX_RATE) return false; /* compress: out = pre[0..4] */
    return true;
}

/* ══════════════════════════ constraint evaluation ════════════════════════ */

int dnac_mmix_air_eval_row(const uint64_t *main_local, const uint64_t *main_next,
                           const uint64_t *prep_local, const uint64_t *prep_next,
                           int is_first_row,
                           const dnac_p2c_mmix_table_cfg_t *cfg,
                           const uint64_t *publics, size_t num_publics) {
    (void)is_first_row; /* the row-0 anchor is PREPROCESSED here (header note). */
    if (!main_local || !prep_local || !cfg || !publics)
        return MMIX_VIOL_BAD_CONFIG;
    /* main and preprocessed windows are one window: a caller that has the next
     * MAIN row but not the next PREPROCESSED row is exactly the PIN-2 shape
     * (prep_next = 0 => zero-filled next window, batch_verify.c:696-707) and is
     * rejected rather than silently evaluated against nothing. */
    if ((main_next == NULL) != (prep_next == NULL)) return MMIX_VIOL_BAD_CONFIG;

    mmix_sched_t S;
    if (!mmix_build(cfg, &S)) return MMIX_VIOL_BAD_CONFIG;

    if (num_publics != S.num_publics) return MMIX_VIOL_BAD_CONFIG;

    /* Publics canonicality — FAIL-CLOSE, not a precondition (OBL-2; the P2b
     * A2-F1 shape). `fp()` reduces mod p, so x and x+p alias inside the field
     * view while the NATIVE seam is representation-sensitive (opened-rows sweep
     * poseidon2_mmcs.c:476-477, root memcmp :528). Mirror the native: reject. */
    for (size_t i = 0; i < num_publics; i++)
        if (publics[i] >= GOLDILOCKS_P) return MMIX_VIOL_BAD_CONFIG;

    int v = 0;
    const gold_fp_t one = gold_fp_one();

    /* ── Column reads ─────────────────────────────────────────────────────── */
    const gold_fp_t dir = fp(main_local[MMIX_DIR_OFF]);
    const gold_fp_t pl_comp = fp(prep_local[DNAC_P2C_MMIX_COL_IS_COMPRESS]);
    const gold_fp_t pl_fin = fp(prep_local[DNAC_P2C_MMIX_COL_IS_FINAL]);
    const gold_fp_t pl_icomp = fp(prep_local[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS]);

    /* ══ A. Embedded poseidon2_air block — UNGATED (mmcs_air.c:209-214) ═════
     * Binding is by COLUMN IDENTITY: every pin below references these cells.
     * Evaluating the block unconditionally leaves no gate to aim at; leaf,
     * compress, inject, final and padding rows all carry a valid permutation
     * witness. Degree 3 (the block's own max). */
    v += poseidon2_air_eval_row(main_local + MMIX_PERM_OFF);

    /* ══ B. `dir` — boolean, and ZERO off compress rows (mmcs_air.c block B) ═
     * Upstream leaves booleanity of its own `mmcs_bit` to an AIR-owned rule
     * (P3rec air.rs:937). The "dir == 0 off compress rows" half settles that
     * there is exactly ONE `dir` per level, on that level's compress row: the
     * placement pair (block G) reads it as `next.dir`, the index binding (block
     * D) reads it row-locally, and inject-compress / leaf / final / pad rows
     * carry no direction bit. Degree 2 each. */
    az(&v, mul(dir, sub(dir, one)));
    az(&v, mul(sub(one, pl_comp), dir));

    /* ══ C. Leaf & inject-leaf rows — PaddingFreeSponge OVERWRITE absorb
     * (native dnac_p2_mmcs_hash_iter, poseidon2_mmcs.c:41-72; reuses the
     * slice-1 mmcs_air.c block D form, generalized to a per-GROUP concat that
     * INTERLEAVES data lanes (bound to a public) and salt lanes (free)) ══════
     *
     * Gated by the PREPROCESSED step one-hot `pos[k]` (pinned under PIN-1-MMIX):
     * exactly one row carries pos[k] = 1, and that row's type / group / block
     * are cfg constants. The absorbed lanes of a DATA position ARE the public
     * opened elements (the only thing connecting the AIR's leaf preimage to what
     * the consumer opened, OBL-3); SALT positions are free witness (OBL-6). The
     * FIRST block of each group starts from an ALL-ZERO state (poseidon2_mmcs.c:
     * 49-50): the leftover rate slots AND the whole capacity are pinned to zero.
     * Degree 2 (pos · main). */
    for (size_t k = 0; k < S.sched; k++) {
        if (S.stype[k] != MMIX_T_LEAF && S.stype[k] != MMIX_T_INJECT_LEAF)
            continue;
        const size_t g = S.sgroup[k];
        const size_t b = S.sblk[k];
        const size_t kab = mmix_absorb_count(&S, g, b);
        const gold_fp_t gate = fp(prep_local[dnac_p2c_mmix_col_pos(k)]);
        for (size_t s = 0; s < kab; s++) {
            const size_t pub = mmix_stream_pub(&S, g, (size_t)MMIX_RATE * b + s);
            if (pub != MMIX_INF)
                az(&v, mul(gate, sub(fp(main_local[mmix_perm_in_off(s)]),
                                     fp(publics[pub]))));
        }
        if (b == 0)
            for (size_t j = kab; j < (size_t)MMIX_PERM_WIDTH; j++)
                az(&v, mul(gate, fp(main_local[mmix_perm_in_off(j)])));
    }

    /* ══ D. Index binding — A1, LSB-first, bits as PUBLICS (mmcs_air.c block E)
     * The compress row at level l carries level l's direction bit, and that bit
     * IS public bit l. Native: `(idx & 1)` selects the side, `idx >>= 1` per
     * level (poseidon2_mmcs.c:501-511) — LSB-first, bit l on level l. Gated by
     * the preprocessed pos[k] of the compress step. Degree 2. */
    for (size_t k = 0; k < S.sched; k++) {
        if (S.stype[k] != MMIX_T_COMPRESS) continue;
        const size_t l = S.slevel[k];
        az(&v, mul(fp(prep_local[dnac_p2c_mmix_col_pos(k)]),
                   sub(dir, fp(publics[MMIX_PUB_DIR_OFF + l]))));
    }

    /* ══ E. Final row — root equality (native memcmp, poseidon2_mmcs.c:528) ══
     * The final row's permutation PRE-image lanes 0..4 are the received running
     * digest; they must equal the public root lanes. Threading the last
     * combination's OUTPUT into these cells is block H below. Degree 2. */
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
        az(&v, mul(pl_fin, sub(fp(main_local[mmix_perm_in_off(j)]),
                               fp(publics[MMIX_PUB_ROOT_OFF + j]))));

    /* ══ F. Inject-compress LEFT input == the carried running digest ═════════
     * The native inject combines `C(running_digest, rows_digest)` with the
     * RUNNING digest FIRST (poseidon2_mmcs.c:522). LEFT (perm_in[0..4]) is the
     * running digest, carried in RDIG across the inject-leaf rows (blocks J/K).
     * A SWAPPED order (rows_digest first) puts rows_digest here and is caught by
     * this equality (and its RIGHT half is caught by block I). Degree 2. */
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
        az(&v, mul(pl_icomp, sub(fp(main_local[mmix_perm_in_off(j)]),
                                 fp(main_local[mmix_rdig_off(j)]))));

    if (!main_next) return v; /* last row: no transition constraints */

    const gold_fp_t pn_comp = fp(prep_next[DNAC_P2C_MMIX_COL_IS_COMPRESS]);
    const gold_fp_t pn_fin = fp(prep_next[DNAC_P2C_MMIX_COL_IS_FINAL]);
    const gold_fp_t pn_icomp = fp(prep_next[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS]);
    const gold_fp_t pl_hasinj = fp(prep_local[DNAC_P2C_MMIX_COL_HAS_INJECT]);
    const gold_fp_t pl_ileaf = fp(prep_local[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF]);
    const gold_fp_t ndir = fp(main_next[MMIX_DIR_OFF]);

    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++) {
        const gold_fp_t out = fp(main_local[mmix_perm_out_off(j)]);

        /* ══ G. Running-digest PLACEMENT into the next compress row (the ported
         * core; native side selection poseidon2_mmcs.c:505-508 over
         * pre = left‖right, :80-83). The predecessor of a compress row ALWAYS
         * holds the running digest in perm_out[0..4]: it is the last tallest-
         * group leaf row (leaf digest), or a compress row (its output), or an
         * inject-compress row (its output). dir 0 => running is LEFT, dir 1 =>
         * RIGHT; the other half is the free-witness sibling. Degree 3. */
        az(&v, mul(mul(pn_comp, sub(one, ndir)),
                   sub(fp(main_next[mmix_perm_in_off(j)]), out)));
        az(&v, mul(mul(pn_comp, ndir),
                   sub(fp(main_next[mmix_perm_in_off((size_t)MMIX_DIGEST_LANES + j)]),
                       out)));

        /* ══ H. Final-row threading (mmcs_air.c block J): the final row's
         * received digest is the predecessor's output (last compress OR last
         * inject-compress). With block E (== public root) this stops a prover
         * garbaging the last combination and writing the true root straight into
         * the final row. Degree 2. */
        az(&v, mul(pn_fin, sub(fp(main_next[mmix_perm_in_off(j)]), out)));

        /* ══ I. Inject-compress RIGHT input == the last inject-leaf's output
         * (rows_digest). The predecessor of an inject-compress is the last
         * inject-leaf row, whose perm_out[0..4] is the group's leaf digest
         * (native :521). RIGHT (perm_in[4..8]) must equal it. Degree 2. */
        az(&v, mul(pn_icomp,
                   sub(fp(main_next[mmix_perm_in_off((size_t)MMIX_DIGEST_LANES + j)]),
                       out)));

        /* ══ J. RDIG SEED — an injecting compress row's output is the pre-inject
         * running digest; carry it into the FIRST inject-leaf row's RDIG. Gated
         * by the local `has_inject` (set only on injecting compress rows, whose
         * successor is always the first inject-leaf). Degree 2. */
        az(&v, mul(pl_hasinj, sub(fp(main_next[mmix_rdig_off(j)]), out)));

        /* ══ K. RDIG CARRY — hold the running digest UNCHANGED across the
         * inject-leaf rows (which run a SEPARATE sponge over the injecting
         * group's rows) so it reaches the inject-compress LEFT (block F). Gated
         * by local `is_inject_leaf`; the successor is another inject-leaf or the
         * inject-compress. Degree 2. */
        az(&v, mul(pl_ileaf, sub(fp(main_next[mmix_rdig_off(j)]),
                                 fp(main_local[mmix_rdig_off(j)]))));
    }

    /* ══ L. Leaf & inject-leaf state threading — OVERWRITE absorb carries
     * everything else (mmcs_air.c block H; poseidon2_mmcs.c:53-68) ═══════════
     * Between two consecutive (inject-)leaf rows of ONE group, the successor
     * block overwrites only its absorbed rate slots; every other slot — the
     * leftover rate of a partial block and the whole capacity — keeps the
     * previous permutation's output. Anchored at the PREDECESSOR (step k-1,
     * gated by pos[k-1]) so it never fires on a last-leaf -> compress /
     * inject-compress step. Degree 2. */
    for (size_t k = 0; k < S.sched; k++) {
        if (S.stype[k] != MMIX_T_LEAF && S.stype[k] != MMIX_T_INJECT_LEAF)
            continue;
        const size_t b = S.sblk[k];
        if (b == 0) continue; /* first block has no predecessor to carry from */
        const size_t g = S.sgroup[k];
        const size_t kab = mmix_absorb_count(&S, g, b);
        const gold_fp_t gate = fp(prep_local[dnac_p2c_mmix_col_pos(k - 1)]);
        for (size_t j = kab; j < (size_t)MMIX_PERM_WIDTH; j++)
            az(&v, mul(gate, sub(fp(main_next[mmix_perm_in_off(j)]),
                                 fp(main_local[mmix_perm_out_off(j)]))));
    }

    return v;
}

int dnac_mmix_air_eval_trace(const uint64_t *main_trace,
                             const uint64_t *prep_table, size_t n_rows,
                             const dnac_p2c_mmix_table_cfg_t *cfg,
                             const uint64_t *publics, size_t num_publics) {
    if (!main_trace || !prep_table || n_rows == 0) return MMIX_VIOL_BAD_CONFIG;

    mmix_sched_t S;
    if (!mmix_build(cfg, &S)) return MMIX_VIOL_BAD_CONFIG;

    /* SCHEDULE CONFORMANCE (fail-close, before any constraint): the row count is
     * a PINNED constant, never a witnessed length — a shorter walk is a
     * different statement. */
    if (n_rows != S.rows) return MMIX_VIOL_BAD_CONFIG;

    /* TERMINALITY (fail-close, fri_oi_air's stricter posture): the LAST row's
     * preprocessed window MUST be a PADDING row, so no transition-anchored form
     * (placement, RDIG carry, final threading, state carry) can be skipped by
     * ending the trace on a typed row. */
    {
        const uint64_t *last =
            prep_table + (n_rows - 1) * (size_t)DNAC_P2C_MMIX_TABLE_COLS;
        if (last[DNAC_P2C_MMIX_COL_IS_PAD] != 1 ||
            last[DNAC_P2C_MMIX_COL_IS_LEAF] != 0 ||
            last[DNAC_P2C_MMIX_COL_IS_COMPRESS] != 0 ||
            last[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF] != 0 ||
            last[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS] != 0 ||
            last[DNAC_P2C_MMIX_COL_IS_FINAL] != 0)
            return MMIX_VIOL_BAD_CONFIG;
    }

    int total = 0;
    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *local = main_trace + r * MMIX_WIDTH;
        const uint64_t *pl = prep_table + r * (size_t)DNAC_P2C_MMIX_TABLE_COLS;
        const uint64_t *next = (r + 1 < n_rows) ? local + MMIX_WIDTH : NULL;
        const uint64_t *pn =
            (r + 1 < n_rows) ? pl + (size_t)DNAC_P2C_MMIX_TABLE_COLS : NULL;
        const int vr = dnac_mmix_air_eval_row(local, next, pl, pn, r == 0, cfg,
                                              publics, num_publics);
        if (vr >= MMIX_VIOL_BAD_CONFIG) return MMIX_VIOL_BAD_CONFIG;
        /* Saturate instead of overflowing: a long, wholly-corrupt trace can sum
         * past INT_MAX (signed overflow is UB) and the sentinel band must stay
         * distinguishable (the P2a i3/A2-F5 contract). */
        if (total >= MMIX_VIOL_BAD_CONFIG - 1 - vr)
            total = MMIX_VIOL_BAD_CONFIG - 1;
        else
            total += vr;
    }
    return total;
}
