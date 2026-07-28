/**
 * @file mmcs_air.c
 * @brief P2b slice 1 — same-height binary MMCS-verify control AIR: constraint
 *        evaluation.
 *
 * Every block below names the design-doc §0.5 form it discharges and the
 * native `poseidon2_mmcs.c` (byte-matched to Plonky3 82cfad73) line whose
 * semantics it mirrors, or the P3rec upstream line it ports (pinned commit
 * b36339709a7a67ee9760fb578b3d4339fd983709, `poseidon2-circuit-air/src/air.rs`).
 *
 * See mmcs_air.h for the layout contract, the INLINE-embedding decision, the
 * PIN-1 / PIN-2 prerequisites, the public-value layout and the degree budget.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmcs_air.h"

#include "field_goldilocks.h"
#include "poseidon2_air.h"

/* ── local field shorthands (transcript_air.c / conf_action_fold.c idiom) ─── */
static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/** Assert a constraint residual is zero; count the violation otherwise. */
static inline void az(int *v, gold_fp_t residual) {
    if (!gold_fp_is_zero(residual)) (*v)++;
}

/* ══════════════════════════ schedule (from the generator) ═════════════════
 * The row schedule has exactly ONE authority: `dnac_p2b_table_generate`
 * (mmcs_air_table.c:86-113). This file does NOT re-derive it — it generates
 * the pinned table for `cfg` and reads the leaf-row count back out, then
 * cross-checks that the derived absorb schedule closes over `total_width`.
 * Pure function of `cfg`: no clock, no RNG, no witness input.
 */
typedef struct {
    size_t leaf;        /* leaf-hash rows == leaf permutations              */
    size_t depth;       /* compress rows                                    */
    size_t total_width; /* Σ widths[m] — the sponge input length            */
    size_t rows;        /* padded table height (== trace height)            */
} mair_sched_t;

/* Σ widths[m] with the same bounds the table module enforces
 * (mmcs_air_table.c:30-48). Returns 0 on reject. */
static size_t mair_total_width(const dnac_p2b_table_cfg_t *cfg) {
    if (cfg == NULL || cfg->widths == NULL) return 0;
    if (cfg->num_matrices == 0 || cfg->num_matrices > DNAC_P2B_MAX_MATRICES) return 0;
    if (cfg->depth == 0 || cfg->depth > DNAC_P2B_MAX_DEPTH) return 0;

    size_t total = 0;
    for (size_t m = 0; m < cfg->num_matrices; m++) {
        if (cfg->widths[m] == 0) return 0;
        if (cfg->widths[m] > DNAC_P2B_MAX_TOTAL_WIDTH - total) return 0;
        total += cfg->widths[m];
    }
    if (total == 0 || total > DNAC_P2B_MAX_TOTAL_WIDTH) return 0;
    return total;
}

/* Fail-close schedule resolution. Returns 1 on success. */
static int mair_schedule(const dnac_p2b_table_cfg_t *cfg, mair_sched_t *s) {
    uint64_t table[MAIR_MAX_STEPS * DNAC_P2B_TABLE_COLS];

    const size_t rows = dnac_p2b_table_rows(cfg);
    if (rows == 0 || rows > MAIR_MAX_STEPS) return 0;
    const size_t total = mair_total_width(cfg);
    if (total == 0) return 0;
    if (dnac_p2b_table_generate(cfg, table, sizeof(table) / sizeof(table[0])) !=
        DNAC_P2B_TABLE_OK)
        return 0;

    size_t leaf = 0, comp = 0, fin = 0;
    for (size_t r = 0; r < rows; r++) {
        leaf += (table[r * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_LEAF] == 1);
        comp += (table[r * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_COMPRESS] == 1);
        fin += (table[r * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_FINAL] == 1);
    }
    /* Consistency with the generator's own contract (mmcs_air_table.h:49-57). */
    if (leaf == 0 || comp != cfg->depth || fin != 1) return 0;
    if (leaf + cfg->depth + 1 > rows) return 0;

    /* The absorb schedule must close over total_width: MAIR_RATE elements per
     * block except the last, whose remainder is in [1, RATE]
     * (poseidon2_mmcs.c:53-68 — OVERWRITE absorb, permute on a full block,
     * permute on a partial final block, NO extra permute at exact boundary
     * exhaustion). A leaf count that does not satisfy this means this file and
     * the generator disagree — fail closed rather than guess. */
    if (MAIR_RATE * (leaf - 1) >= total) return 0;
    if (total - MAIR_RATE * (leaf - 1) > MAIR_RATE) return 0;

    /* TERMINALITY needs a padding row to exist in the pinned schedule: the
     * final row must have a successor (see the eval_trace contract). A config
     * whose scheduled rows exactly fill a power of two is rejected here rather
     * than accepted into a trace whose last row carries a row type. */
    for (size_t c = 0; c < DNAC_P2B_TABLE_COLS; c++)
        if (table[(rows - 1) * DNAC_P2B_TABLE_COLS + c] != 0) return 0;

    s->leaf = leaf;
    s->depth = cfg->depth;
    s->total_width = total;
    s->rows = rows;
    return 1;
}

/* Elements absorbed by leaf block `blk` (poseidon2_mmcs.c:55-59). */
static inline size_t mair_absorb_count(const mair_sched_t *s, size_t blk) {
    return (blk + 1 < s->leaf) ? MAIR_RATE
                               : s->total_width - MAIR_RATE * (s->leaf - 1);
}

/* ══════════════════════════ public helpers ═══════════════════════════════ */

size_t dnac_mmcs_air_total_width(const dnac_p2b_table_cfg_t *cfg) {
    mair_sched_t s;
    if (!mair_schedule(cfg, &s)) return 0;
    return s.total_width;
}

size_t dnac_mmcs_air_leaf_rows(const dnac_p2b_table_cfg_t *cfg) {
    mair_sched_t s;
    if (!mair_schedule(cfg, &s)) return 0;
    return s.leaf;
}

size_t dnac_mmcs_air_pub_opened_off(const dnac_p2b_table_cfg_t *cfg) {
    mair_sched_t s;
    if (!mair_schedule(cfg, &s)) return 0;
    return MAIR_PUB_DIR_OFF + s.depth;
}

size_t dnac_mmcs_air_num_publics(const dnac_p2b_table_cfg_t *cfg) {
    mair_sched_t s;
    if (!mair_schedule(cfg, &s)) return 0;
    return MAIR_PUB_DIR_OFF + s.depth + s.total_width;
}

bool dnac_mmcs_air_layout_check(void) {
    if (MAIR_DIR_OFF != 0) return false;
    if ((size_t)MAIR_POS_OFF != (size_t)MAIR_DIR_OFF + 1) return false;
    if (MAIR_PERM_OFF != (size_t)MAIR_POS_OFF + MAIR_MAX_STEPS) return false;
    if (MAIR_WIDTH != MAIR_PERM_OFF + (size_t)P2AIR_NUM_COLS) return false;
    /* Accessors land inside their own blocks. */
    if (mair_pos_off(0) != (size_t)MAIR_POS_OFF) return false;
    if (mair_pos_off(MAIR_MAX_STEPS - 1) != MAIR_PERM_OFF - 1) return false;
    if (mair_perm_in_off(0) != MAIR_PERM_OFF) return false;
    if (mair_perm_in_off(MAIR_PERM_WIDTH - 1) !=
        MAIR_PERM_OFF + (size_t)MAIR_PERM_WIDTH - 1)
        return false;
    if (mair_perm_out_off(MAIR_PERM_WIDTH - 1) != MAIR_WIDTH - 1) return false;
    /* Public-value blocks are disjoint and ordered. */
    if (MAIR_PUB_ROOT_OFF != 0) return false;
    if (MAIR_PUB_DIR_OFF != (size_t)MAIR_DIGEST_LANES) return false;
    /* Dimensions mirror the native primitives. */
    if (MAIR_DIGEST_LANES != DNAC_P2M_DIGEST_LANES) return false;
    if (MAIR_PERM_WIDTH != P2AIR_WIDTH) return false;
    if (MAIR_RATE != DNAC_P2B_SPONGE_RATE) return false;
    if ((size_t)MAIR_RATE > (size_t)MAIR_PERM_WIDTH) return false;
    if (MAIR_DIGEST_LANES != MAIR_RATE) return false; /* compress: out = pre[0..4] */
    return true;
}

/* ══════════════════════════ constraint evaluation ════════════════════════ */

int dnac_mmcs_air_eval_row(const uint64_t *main_local, const uint64_t *main_next,
                           const uint64_t *prep_local, const uint64_t *prep_next,
                           int is_first_row,
                           const dnac_p2b_table_cfg_t *cfg,
                           const uint64_t *publics, size_t num_publics) {
    if (!main_local || !prep_local || !cfg || !publics) return MAIR_VIOL_BAD_CONFIG;
    /* main and preprocessed windows are one window: a caller that has the next
     * MAIN row but not the next PREPROCESSED row is exactly the PIN-2 shape
     * (prep_next = 0 => zero-filled next window, batch_verify.c:696-707) and is
     * rejected rather than silently evaluated against nothing. */
    if ((main_next == NULL) != (prep_next == NULL)) return MAIR_VIOL_BAD_CONFIG;

    mair_sched_t s;
    if (!mair_schedule(cfg, &s)) return MAIR_VIOL_BAD_CONFIG;

    const size_t pub_open = MAIR_PUB_DIR_OFF + s.depth;
    if (num_publics != pub_open + s.total_width) return MAIR_VIOL_BAD_CONFIG;

    /* Publics canonicality — FAIL-CLOSE, not a precondition (red-verify
     * A2-F1). `fp()` reduces mod p, so x and x+p alias inside the field view
     * while the NATIVE seam is representation-sensitive: the opened-rows sweep
     * rejects non-canonical input (poseidon2_mmcs.c:557-562) and the root
     * compare is a raw memcmp (:593). Accepting a non-canonical public here
     * would let the AIR prove a statement about publics a downstream u64
     * consumer reads DIFFERENTLY (e.g. p+1's low bit is 0 as a field element's
     * canonical form but 1 as a raw u64). Mirror the native posture: reject. */
    for (size_t i = 0; i < num_publics; i++)
        if (publics[i] >= GOLDILOCKS_P) return MAIR_VIOL_BAD_CONFIG;

    int v = 0;
    const gold_fp_t one = gold_fp_one();
    const gold_fp_t zero = gold_fp_zero();

    /* ══ Column reads ═════════════════════════════════════════════════════ */
    const gold_fp_t dir = fp(main_local[MAIR_DIR_OFF]);
    const gold_fp_t pl_leaf = fp(prep_local[DNAC_P2B_COL_IS_LEAF]);
    const gold_fp_t pl_comp = fp(prep_local[DNAC_P2B_COL_IS_COMPRESS]);
    const gold_fp_t pl_fin = fp(prep_local[DNAC_P2B_COL_IS_FINAL]);
    const gold_fp_t pl_sum = add(add(pl_leaf, pl_comp), pl_fin);

    /* ══ A. Embedded poseidon2_air block — UNGATED (design §0.5 A1-F5) ═════
     * Binding is by COLUMN IDENTITY: every pin below references these very
     * cells. Evaluating the block unconditionally mirrors the shipped inline
     * precedent (transcript_air.c:159-164) and leaves no gate to aim at; leaf,
     * final and padding rows carry a valid dummy permutation witness. */
    v += poseidon2_air_eval_row(main_local + MAIR_PERM_OFF);

    /* ══ B. `dir` — boolean, and ZERO off compress rows ════════════════════
     * Upstream leaves booleanity of its own `mmcs_bit` to an AIR-owned rule
     * (P3rec air.rs:937, with the comment at :934-935 that PREPROCESSED flags
     * need no such check because they are setup-time constants); we do the
     * same and do NOT inherit any assumption about the preprocessed cells.
     * The "dir == 0 off compress rows" half settles design §4.6 item 6: there
     * is exactly ONE `dir` per level, it lives on that level's compress row,
     * and both the placement pair (which reads it as `next.dir`) and the index
     * binding (which reads it row-locally) key on that same cell. */
    az(&v, mul(dir, sub(dir, one)));
    az(&v, mul(sub(one, pl_comp), dir));

    /* ══ C. Step index — one-hot, typed, and anchored (BEYOND-DOC column) ══
     * See mmcs_air.h: the row-index-dependent forms (A1 index binding, leaf
     * absorb offsets) have no other carrier in a row-uniform AIR, and the
     * pinned 3-column preprocessed table cannot hold them. Fully constrained
     * here so it grants the prover no freedom. */
    {
        gold_fp_t sum = zero;
        for (size_t i = 0; i < MAIR_MAX_STEPS; i++) {
            const gold_fp_t p = fp(main_local[mair_pos_off(i)]);
            az(&v, mul(p, sub(p, one))); /* boolean */
            sum = add(sum, p);
            /* Position <-> preprocessed ROW TYPE agreement. Without it a
             * prover could put a compress row's data at a leaf position (the
             * design §3 target-2 attack: "the schedule says compress but the
             * main columns carry leaf-hash data"). */
            if (i < s.leaf) {
                az(&v, mul(p, sub(one, pl_leaf)));
            } else if (i < s.leaf + s.depth) {
                az(&v, mul(p, sub(one, pl_comp)));
            } else if (i == s.leaf + s.depth) {
                az(&v, mul(p, sub(one, pl_fin)));
            } else {
                az(&v, p); /* no scheduled step lives here */
            }
        }
        /* Exactly one step index on a typed row; NONE on a padding row. */
        az(&v, sub(sum, pl_sum));
    }

    /* Boundary: trace row 0 is step 0 — the first leaf-hash permutation. The
     * schedule always begins with a leaf row (leaf >= 1, since total_width >= 1
     * — mmcs_air_table.c:56-60). */
    if (is_first_row) az(&v, sub(one, fp(main_local[mair_pos_off(0)])));

    /* ══ D. Leaf rows — PaddingFreeSponge absorb (design §0.5 A1-F2/A1-F3/
     * A1-F6; native `dnac_p2_mmcs_hash_iter`, poseidon2_mmcs.c:41-72) ══════
     *
     * D1 — the absorbed lanes ARE the public opened rows. With INLINE
     * embedding there is no bus and no CTL, so this equality is the ONLY thing
     * connecting the AIR's leaf preimage to what the consumer opened
     * (round-1 A1-F2). The native stream is the concatenation of every
     * matrix's opened row, in matrix order (poseidon2_mmcs.c:567-573), and
     * block `blk` absorbs elements [RATE*blk, RATE*blk + k) by OVERWRITING
     * rate slot j (poseidon2_mmcs.c:56). The schedule is a constant of the
     * constraint system — never witnessed.
     *
     * D2 — the FIRST leaf row starts from an ALL-ZERO state: every slot the
     * first block does not absorb (leftover rate AND the whole capacity) is
     * pinned to zero (poseidon2_mmcs.c:49-50 `memset`). DNAC's PaddingFreeSponge
     * has NO length tag — upstream seeds its capacity with `cap_tag`
     * (P3rec air.rs:1004-1018 "capacity is never witness-fed"), we take DNAC's
     * convention, stated rather than inherited. Without this the AIR's accepted
     * language would be strictly larger than the native verifier's. */
    for (size_t blk = 0; blk < s.leaf; blk++) {
        const gold_fp_t g = fp(main_local[mair_pos_off(blk)]);
        const size_t k = mair_absorb_count(&s, blk);
        for (size_t j = 0; j < k; j++)
            az(&v, mul(g, sub(fp(main_local[mair_perm_in_off(j)]),
                              fp(publics[pub_open + MAIR_RATE * blk + j]))));
        if (blk == 0)
            for (size_t j = k; j < (size_t)MAIR_PERM_WIDTH; j++)
                az(&v, mul(g, fp(main_local[mair_perm_in_off(j)])));
    }

    /* ══ E. Index binding — A1, LSB-first, bits as PUBLICS ═════════════════
     * The compress row at schedule step (leaf + l) carries level l's direction
     * bit, and that bit IS public bit l. Native: `(idx & 1)` selects the side
     * and `idx >>= 1` per level (poseidon2_mmcs.c:581-590), i.e. level l uses
     * bit l — LSB-first. Upstream production wires the same way
     * (`path_bits = &index_bits[..path_depth]`, P3rec recursion/src/pcs/mmcs.rs
     * :365, zipped level-by-level at circuit/src/ops/mmcs.rs:117); its
     * `2*acc + bit` accumulator (air.rs:1027) is a production-constrained
     * column upstream, but the production MMCS op DISABLES it (`mmcs_index_sum:
     * None` at ops/mmcs.rs:137/:158/:181 — red-verify A2-F4 corrected an
     * earlier "example-only" mislabel here), and composed naively it would
     * yield the BIT-REVERSAL of the native index (design §0.5 / G-DET-P2b-3).
     * There is NO accumulator column here. `dir` being boolean (block B) makes
     * the public bits boolean transitively. */
    for (size_t l = 0; l < s.depth; l++)
        az(&v, mul(fp(main_local[mair_pos_off(s.leaf + l)]),
                   sub(dir, fp(publics[MAIR_PUB_DIR_OFF + l]))));

    /* ══ F. Final row — root equality (design §0.5; native memcmp at
     * poseidon2_mmcs.c:593-594) ═══════════════════════════════════════════
     * The final row's permutation PRE-image lanes 0..4 are the received
     * digest; they must equal the public root lanes. The rest of that row's
     * block is a dummy witness (the block is evaluated ungated). Threading the
     * last compression's OUTPUT into these very cells is block J below — the
     * two together are what stop a prover garbaging the last compression and
     * writing the true root straight into the final row (round-1 A1-F4). */
    for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++)
        az(&v, mul(pl_fin, sub(fp(main_local[mair_perm_in_off(j)]),
                               fp(publics[MAIR_PUB_ROOT_OFF + j]))));

    if (!main_next) return v; /* last row: no transition constraints */

    const gold_fp_t pn_leaf = fp(prep_next[DNAC_P2B_COL_IS_LEAF]);
    const gold_fp_t pn_comp = fp(prep_next[DNAC_P2B_COL_IS_COMPRESS]);
    const gold_fp_t pn_fin = fp(prep_next[DNAC_P2B_COL_IS_FINAL]);
    const gold_fp_t pn_sum = add(add(pn_leaf, pn_comp), pn_fin);
    const gold_fp_t ndir = fp(main_next[MAIR_DIR_OFF]);

    /* ══ G. Step advance — exactly one per scheduled row ═══════════════════
     * A typed successor row is step i+1. A padding successor pins nothing here
     * and its own row-local block (block C on that row) forces all of its
     * `pos` cells to zero, since its preprocessed sum is 0. Degree 3. */
    for (size_t i = 0; i + 1 < MAIR_MAX_STEPS; i++) {
        const gold_fp_t g = mul(fp(main_local[mair_pos_off(i)]), pn_sum);
        az(&v, mul(g, sub(fp(main_next[mair_pos_off(i + 1)]), one)));
    }
    /* The schedule cannot continue past the last representable step. */
    az(&v, mul(fp(main_local[mair_pos_off(MAIR_MAX_STEPS - 1)]), pn_sum));

    /* ══ H. Leaf state threading — OVERWRITE absorb, everything else carries
     * (design §0.5 A1-F6; poseidon2_mmcs.c:53-68) ═════════════════════════
     * Block `blk` (blk >= 1) overwrites only its k absorbed rate slots; every
     * other slot — the leftover rate slots of a PARTIAL final block and the
     * whole capacity — keeps the PREVIOUS permutation's output. Anchored at
     * the predecessor row (step blk-1), so with block G it lands on step blk.
     */
    for (size_t blk = 1; blk < s.leaf; blk++) {
        const gold_fp_t g = fp(main_local[mair_pos_off(blk - 1)]);
        const size_t k = mair_absorb_count(&s, blk);
        for (size_t j = k; j < (size_t)MAIR_PERM_WIDTH; j++)
            az(&v, mul(g, sub(fp(main_next[mair_perm_in_off(j)]),
                              fp(main_local[mair_perm_out_off(j)]))));
    }

    /* ══ I. Placement pair — THE ported core (P3rec air.rs:984-1002) ═══════
     *
     *   is_left = 1 - next_bit
     *   for i in 0..RATE: when(merkle_chain_i · is_left ) : next_in[i]        == local_out[i]
     *                     when(merkle_chain_i · next_bit) : next_in[RATE + i] == local_out[i]
     *
     * with `merkle_chain_i` taken from the NEXT row's PREPROCESSED window
     * (`let s = next_preprocessed` is bound at air.rs:945; the :986-989 gates
     * read it) — which is precisely why
     * PIN-2 (`prep_next = 1`) is mandatory. Here the row type IS the gate:
     * `is_compress` of the next row. The running hash lands in the LEFT half
     * when the bit is 0 and in the RIGHT half when it is 1 — the native
     * `(idx & 1) == 0 ? compress(digest, sib) : compress(sib, digest)`
     * (poseidon2_mmcs.c:584-587), over `pre = left ‖ right` filling the full
     * width (poseidon2_mmcs.c:80-83). Degree 3.
     *
     * This ONE rule covers both the last-leaf-row -> first-compress-row step
     * (the leaf digest is `state[0..4]` after the final leaf permutation,
     * poseidon2_mmcs.c:71) and every compress -> compress step, so the walk is
     * threaded end to end (the P2a-F3 lesson: a row-AIR must constrain what a
     * circuit DAG gets structurally).
     *
     * The half the running hash does NOT claim is the SIBLING: unconstrained
     * witness, by design — soundness comes from the root equality plus
     * collision resistance (design G-SEC-P2b-4, upstream's model too). */
    for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++) {
        const gold_fp_t out = fp(main_local[mair_perm_out_off(j)]);
        az(&v, mul(mul(pn_comp, sub(one, ndir)),
                   sub(fp(main_next[mair_perm_in_off(j)]), out)));
        az(&v, mul(mul(pn_comp, ndir),
                   sub(fp(main_next[mair_perm_in_off(MAIR_DIGEST_LANES + j)]), out)));
    }

    /* ══ J. Final-row threading (design §0.5, round-1 A1-F4) ═══════════════
     * `is_final` is a distinct row type, so no placement rule carries the LAST
     * compress row's output into it — that omission is the same structural
     * shape as P2a's shipped HIGH. The final row's received digest is pinned
     * to the predecessor's permutation output here, and to the public root in
     * block F. Transition-gated, as every upstream analogue is. */
    for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++)
        az(&v, mul(pn_fin, sub(fp(main_next[mair_perm_in_off(j)]),
                               fp(main_local[mair_perm_out_off(j)]))));

    return v;
}

int dnac_mmcs_air_eval_trace(const uint64_t *main_trace,
                             const uint64_t *prep_table, size_t n_rows,
                             const dnac_p2b_table_cfg_t *cfg,
                             const uint64_t *publics, size_t num_publics) {
    if (!main_trace || !prep_table || n_rows == 0) return MAIR_VIOL_BAD_CONFIG;

    /* SCHEDULE CONFORMANCE (design §0.5 A1-F6): the row count comes from the
     * PINNED schedule, never from a witnessed length. A shorter trace would be
     * a shorter absorb — i.e. a different statement. */
    mair_sched_t s;
    if (!mair_schedule(cfg, &s)) return MAIR_VIOL_BAD_CONFIG;
    if (n_rows != s.rows) return MAIR_VIOL_BAD_CONFIG;

    int total = 0;
    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *local = main_trace + r * MAIR_WIDTH;
        const uint64_t *pl = prep_table + r * (size_t)DNAC_P2B_TABLE_COLS;
        const uint64_t *next = (r + 1 < n_rows) ? local + MAIR_WIDTH : NULL;
        const uint64_t *pn =
            (r + 1 < n_rows) ? pl + (size_t)DNAC_P2B_TABLE_COLS : NULL;
        const int v = dnac_mmcs_air_eval_row(local, next, pl, pn, r == 0, cfg,
                                             publics, num_publics);
        if (v >= MAIR_VIOL_BAD_CONFIG) return MAIR_VIOL_BAD_CONFIG;
        /* Saturate instead of overflowing: a long, wholly-corrupt trace can
         * sum past INT_MAX (signed overflow is UB) and the sentinel band must
         * stay distinguishable (the P2a i3/A2-F5 contract). */
        if (total >= MAIR_VIOL_BAD_CONFIG - 1 - v) {
            total = MAIR_VIOL_BAD_CONFIG - 1;
        } else {
            total += v;
        }
    }

    /* LAST-ROW BOUNDARY (the P2a-i3 shipped-HIGH shape, transcript_air.c:444).
     * The final trace row gets NO transition constraints, so every effect a
     * row pins on its SUCCESSOR is void there. Requiring the last row to be
     * PADDING (all three preprocessed selectors zero) makes "every row that
     * carries a row type has a successor" structurally true, so no
     * transition-anchored form — the placement pair, the leaf-state carry, the
     * final-row threading — can be silently skipped by ending the trace early.
     * Fail-close, and it costs the honest prover nothing: the pinned table
     * already pads to a power of two (mmcs_air_table.c:64-72) and a config
     * that leaves no padding row is rejected at `mair_schedule`. */
    {
        const uint64_t *last = prep_table + (n_rows - 1) * (size_t)DNAC_P2B_TABLE_COLS;
        int typed = 0;
        for (size_t c = 0; c < DNAC_P2B_TABLE_COLS; c++)
            if (last[c] != 0) typed = 1;
        if (typed && total < MAIR_VIOL_BAD_CONFIG - 1) total += 1;
    }
    return total;
}
