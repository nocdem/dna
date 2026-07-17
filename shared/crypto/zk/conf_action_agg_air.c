/**
 * @file conf_action_agg_air.c
 * @brief Dual-mode S4 — aggregate Action AIR (C1 ⊕ C3 ⊕ C4). S4a.1 scaffold +
 *        S4a.2 C3 membership (with §3 POSACC init/stop/wrap gating).
 *
 * See conf_action_agg_air.h for the layout, phase schedule, and build roadmap.
 * is_zk=0 construction-gate style. The C1 AIR is reused losslessly (scatter on
 * generate, gather on eval); the C3 membership is embedded at φ∈[1,D] consuming
 * C1's frozen cm_carry/pos_carry, poseidon always-on + pins gated on
 * [φ∈1..D]·IS_INPUT.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_action_agg_air.h"

#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "poseidon2_air.h"       /* poseidon2_air_eval_row */
#include "poseidon2_air_cols.h"  /* p2air offsets */
#include "poseidon2_air_trace.h" /* poseidon2_air_generate_row */
#include "shielded_domsep.h"     /* DNAC_DOMSEP_RHO / DNAC_DOMSEP_NF (C4) */

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }
static gold_fp_t bool_res(gold_fp_t s) {
    return mul(s, sub(s, gold_fp_one()));
}

/* poseidon2-air block output lane k (end_post of the final full round). */
static uint64_t p2_out(const uint64_t *blk, size_t k) {
    return blk[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, k)];
}

/* Fixed-length PaddingFreeSponge<8,4,4> over in[8] (== S0 sponge / C4
 * sponge8_blocks): block1 absorbs in[0..4] with zero capacity, block2 absorbs
 * in[4..8] with block1's capacity carry; digest = block2.out[0..4]. Writes both
 * poseidon2-air blocks. Used for the C4 nullifier ρ/nf (S4a.3a). */
static void agg_sponge8(const uint64_t in[8], uint64_t *blk1, uint64_t *blk2,
                        uint64_t out[CONF_NF_LANES]) {
    uint64_t in1[8] = {in[0], in[1], in[2], in[3], 0, 0, 0, 0};
    poseidon2_air_generate_row(in1, blk1);
    uint64_t s1[8];
    for (unsigned k = 0; k < 8; k++) s1[k] = p2_out(blk1, (size_t)k);
    uint64_t in2[8] = {in[4], in[5], in[6], in[7], s1[4], s1[5], s1[6], s1[7]};
    poseidon2_air_generate_row(in2, blk2);
    for (unsigned k = 0; k < CONF_NF_LANES; k++) out[k] = p2_out(blk2, (size_t)k);
}

/* Within-row pointer to the nullifier region of a wide row. */
#define NFR(row) ((row) + CONF_AGG_NF_OFF)

/* The forced nullifier-phase index φ = D+1. */
#define CONF_AGG_NF_PHI ((uint64_t)(CONF_AGG_TREE_DEPTH + 1))
#define D_DEPTH ((unsigned)CONF_AGG_TREE_DEPTH)

/* Within-row pointer to the membership region of a wide row. */
#define MEMB(row) ((row) + CONF_AGG_MEMB_OFF)
/* C1 frozen-carry cells of a wide row. */
#define C1CELL(row, off) ((row)[CONF_AGG_C1_OFF + (off)])

bool conf_action_agg_air_generate(unsigned log_height, const uint64_t *value,
                                  const uint64_t *addr, const uint64_t *rcm,
                                  const uint8_t *roles, const uint64_t *pos,
                                  const uint64_t *nk, const uint64_t *ak,
                                  size_t num_notes,
                                  const uint64_t *memb_siblings,
                                  uint64_t anchor_out[CONF_MEMB_LANES],
                                  uint64_t *nf_out, uint64_t *trace_out) {
    if (log_height < CONF_ACTION_MIN_LOG_HEIGHT ||
        log_height > CONF_ACTION_MAX_LOG_HEIGHT)
        return false;
    if (!trace_out || !anchor_out || !nf_out) return false;

    const size_t rows = (size_t)1 << log_height;
    const size_t K = CONF_ACTION_K;

    /* Zero the whole aggregate trace (nullifier region stays 0). */
    for (size_t i = 0; i < rows * CONF_AGG_WIDTH; i++) trace_out[i] = 0;

    /* Generate the standalone C1 trace into an 813-wide scratch buffer. */
    uint64_t *c1 = (uint64_t *)calloc(rows * CONF_ACTION_WIDTH, sizeof(uint64_t));
    if (!c1) return false;
    if (!conf_action_air_generate(log_height, value, addr, rcm, roles, pos, nk,
                                  ak, num_notes, c1)) {
        free(c1);
        return false;
    }

    /* poseidon2 of the all-zero input — the inert filler for non-active membership
     * rows (a valid permutation so poseidon2_air_eval_row passes every row). */
    uint64_t zero_in[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t zero_blk[P2AIR_NUM_COLS];
    poseidon2_air_generate_row(zero_in, zero_blk);

    /* Scatter the C1 region + fill is_nf + default-inert membership blocks. */
    for (size_t r = 0; r < rows; r++) {
        uint64_t *row = trace_out + r * CONF_AGG_WIDTH;
        memcpy(row + CONF_AGG_C1_OFF, c1 + r * CONF_ACTION_WIDTH,
               CONF_ACTION_WIDTH * sizeof(uint64_t));

        const uint64_t phi = (uint64_t)(r % K);
        const uint64_t is_nf = (phi == CONF_AGG_NF_PHI) ? 1u : 0u;
        const gold_fp_t d = sub(fp(phi), fp(CONF_AGG_NF_PHI));
        row[CONF_AGG_ISNF_OFF] = is_nf;
        row[CONF_AGG_INVNF_OFF] = is_nf ? 0 : gold_fp_to_u64(gold_fp_inv(d));

        /* default inert membership poseidon blocks (valid zero-perm). */
        uint64_t *m = MEMB(row);
        memcpy(m + CONF_MEMB_MC1_OFF, zero_blk, sizeof zero_blk);
        memcpy(m + CONF_MEMB_MC2_OFF, zero_blk, sizeof zero_blk);
        /* default inert nullifier poseidon blocks (valid zero-perm). */
        uint64_t *nfr = NFR(row);
        memcpy(nfr + CONF_NF_RHO1_OFF, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_NF_RHO2_OFF, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_NF_NF1_OFF, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_NF_NF2_OFF, zero_blk, sizeof zero_blk);
    }

    /* nf outputs zeroed (OUTPUT/FEE/dummy slots stay 0). */
    for (size_t i = 0; i < num_notes * CONF_NF_LANES; i++) nf_out[i] = 0;

    /* ── S4a.2: fill the C3 membership walk for each INPUT note-block ── */
    int have_anchor = 0;
    for (size_t blk = 0; blk < num_notes; blk++) {
        if (roles[blk] != CONF_ACTION_ROLE_INPUT) continue;
        if (!memb_siblings) { free(c1); return false; }

        /* cm = the block's frozen commitment (C1 cm_carry at any block row). */
        uint64_t cur[CONF_MEMB_LANES], cm0[CONF_MEMB_LANES];
        const uint64_t *blk0 = trace_out + (blk * K) * CONF_AGG_WIDTH;
        for (unsigned j = 0; j < CONF_MEMB_LANES; j++)
            cur[j] = C1CELL(blk0, CONF_ACTION_CMCARRY_OFF + j);
        memcpy(cm0, cur, sizeof cm0);

        const uint64_t note_pos = pos[blk];
        const uint64_t *sibs = memb_siblings + blk * D_DEPTH * CONF_MEMB_LANES;
        uint64_t pacc = 0;

        for (unsigned i = 0; i < D_DEPTH; i++) {
            const size_t r = blk * K + (i + 1); /* φ = i+1 */
            uint64_t *m = MEMB(trace_out + r * CONF_AGG_WIDTH);
            const uint64_t *sib = sibs + (size_t)i * CONF_MEMB_LANES;
            const uint64_t bit = (note_pos >> i) & 1u;

            for (unsigned j = 0; j < CONF_MEMB_LANES; j++) {
                m[CONF_MEMB_CUR_OFF + j] = cur[j];
                m[CONF_MEMB_SIB_OFF + j] = sib[j];
            }
            m[CONF_MEMB_BIT_OFF] = bit;

            uint64_t left[CONF_MEMB_LANES], right[CONF_MEMB_LANES];
            for (unsigned j = 0; j < CONF_MEMB_LANES; j++) {
                left[j] = bit ? sib[j] : cur[j];
                right[j] = bit ? cur[j] : sib[j];
            }
            /* compress = S0 note_merkle_compress: MC1 absorbs left (zero cap),
             * MC2 absorbs right with MC1 capacity carry; next = MC2.out[0..4]. */
            uint64_t in1[8] = {left[0], left[1], left[2], left[3], 0, 0, 0, 0};
            poseidon2_air_generate_row(in1, m + CONF_MEMB_MC1_OFF);
            uint64_t s1[8];
            for (unsigned k = 0; k < 8; k++)
                s1[k] = p2_out(m + CONF_MEMB_MC1_OFF, (size_t)k);
            uint64_t in2[8] = {right[0], right[1], right[2], right[3],
                               s1[4], s1[5], s1[6], s1[7]};
            poseidon2_air_generate_row(in2, m + CONF_MEMB_MC2_OFF);
            for (unsigned j = 0; j < CONF_MEMB_LANES; j++)
                cur[j] = p2_out(m + CONF_MEMB_MC2_OFF, (size_t)j);

            pacc += (uint64_t)bit << i;
            m[CONF_MEMB_POSACC_OFF] = pacc;
        }

        /* cur is now the block's root; all INPUT blocks must share ONE anchor. */
        if (!have_anchor) {
            memcpy(anchor_out, cur, sizeof cur);
            have_anchor = 1;
        } else {
            for (unsigned j = 0; j < CONF_MEMB_LANES; j++)
                if (cur[j] != anchor_out[j]) { free(c1); return false; }
        }

        /* ── S4a.3a: C4 nullifier at φ=D+1 — nf = PRF(nk_carry, CRH(cm_carry,
         * pos_carry)). cm/pos/nk are the block's frozen carries (== pos[blk]/
         * nk[blk], which C1 froze into pos_carry/nk_carry). ── */
        {
            const size_t nfrow = blk * K + (size_t)(D_DEPTH + 1); /* φ=D+1 */
            uint64_t *nfr = NFR(trace_out + nfrow * CONF_AGG_WIDTH);
            const uint64_t np = pos[blk], nnk = nk[blk];
            for (unsigned j = 0; j < CONF_NF_LANES; j++)
                nfr[CONF_NF_CM_OFF + j] = cm0[j];
            nfr[CONF_NF_POS_OFF] = np;
            nfr[CONF_NF_NK_OFF] = nnk;

            uint64_t rho_in[8] = {cm0[0], cm0[1], cm0[2], cm0[3], np,
                                  DNAC_DOMSEP_RHO, 0, 0};
            uint64_t rho[CONF_NF_LANES];
            agg_sponge8(rho_in, nfr + CONF_NF_RHO1_OFF, nfr + CONF_NF_RHO2_OFF, rho);

            uint64_t nf_in[8] = {nnk, rho[0], rho[1], rho[2], rho[3],
                                 DNAC_DOMSEP_NF, 0, 0};
            uint64_t nf[CONF_NF_LANES];
            agg_sponge8(nf_in, nfr + CONF_NF_NF1_OFF, nfr + CONF_NF_NF2_OFF, nf);

            for (unsigned j = 0; j < CONF_NF_LANES; j++) {
                nfr[CONF_NF_NF_OFF + j] = nf[j];
                nf_out[blk * CONF_NF_LANES + j] = nf[j];
            }
        }
    }
    if (!have_anchor)
        for (unsigned j = 0; j < CONF_MEMB_LANES; j++) anchor_out[j] = 0;

    free(c1);
    return true;
}

int conf_action_agg_air_eval(const uint64_t *trace, size_t n_rows,
                             const uint64_t anchor[CONF_MEMB_LANES]) {
    if (!trace || n_rows == 0 || !anchor) return 1;
    int viol = 0;
    const gold_fp_t one = gold_fp_one();

    /* ── C1 constraints: gather the C1 region + reuse conf_action_air_eval ── */
    uint64_t *c1 = (uint64_t *)calloc(n_rows * CONF_ACTION_WIDTH, sizeof(uint64_t));
    if (!c1) return 1;
    for (size_t r = 0; r < n_rows; r++)
        memcpy(c1 + r * CONF_ACTION_WIDTH,
               trace + r * CONF_AGG_WIDTH + CONF_AGG_C1_OFF,
               CONF_ACTION_WIDTH * sizeof(uint64_t));
    viol += conf_action_air_eval(c1, n_rows);
    free(c1);

    /* Precompute the verifier-known level weights 2^level, level ∈ [0, D). */
    gold_fp_t pw[CONF_AGG_TREE_DEPTH];
    pw[0] = one;
    for (unsigned i = 1; i < D_DEPTH; i++) pw[i] = add(pw[i - 1], pw[i - 1]);

    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *row = trace + r * CONF_AGG_WIDTH;
        const uint64_t *m = MEMB(row);
        const uint64_t *mc1 = m + CONF_MEMB_MC1_OFF;
        const uint64_t *mc2 = m + CONF_MEMB_MC2_OFF;

        const uint64_t phi = row[CONF_AGG_C1_OFF + CONF_ACTION_PHI_OFF]; /* canonical 0..K−1 */
        const gold_fp_t is_nf = fp(row[CONF_AGG_ISNF_OFF]);
        const gold_fp_t inv = fp(row[CONF_AGG_INVNF_OFF]);

        /* ── Forced is_nf phase selector: is_zero(φ − (D+1)). ── */
        {
            const gold_fp_t d = sub(fp(phi), fp(CONF_AGG_NF_PHI));
            if (!gold_fp_is_zero(bool_res(is_nf))) viol++;
            if (!gold_fp_eq(mul(d, inv), sub(one, is_nf))) viol++;
            if (!gold_fp_is_zero(mul(d, is_nf))) viol++;
        }

        /* ── C3 membership (always-on poseidon; pins gated on active). ── */
        viol += poseidon2_air_eval_row(mc1);
        viol += poseidon2_air_eval_row(mc2);

        /* active ⟺ φ ∈ [1,D] AND the block is an INPUT (field-value gate, MF-1).
         * φ is canonical (forced by C1's E1/E2/E3), IS_INPUT is per-block const. */
        const int is_memb = (phi >= 1 && phi <= (uint64_t)D_DEPTH);
        const int is_input =
            gold_fp_eq(fp(C1CELL(row, CONF_ACTION_ISIN_OFF)), one);
        const int active = is_memb && is_input;

        const gold_fp_t pacc = fp(m[CONF_MEMB_POSACC_OFF]);

        /* POSACC inert when NOT active: (1 − active)·POSACC == 0 (no leak over the
         * φ=0 seam or the K-wrap; design red-team F6). */
        if (!active) {
            if (!gold_fp_is_zero(pacc)) viol++;
        } else {
        const unsigned level = (unsigned)(phi - 1);
        const gold_fp_t bit = fp(m[CONF_MEMB_BIT_OFF]);

        /* BIT boolean. */
        if (!gold_fp_is_zero(bool_res(bit))) viol++;

        /* Ordering (dm-c3 F2): MC1.in = left, MC2.in = right; capacity carry. */
        for (unsigned j = 0; j < CONF_MEMB_LANES; j++) {
            const gold_fp_t cur = fp(m[CONF_MEMB_CUR_OFF + j]);
            const gold_fp_t sib = fp(m[CONF_MEMB_SIB_OFF + j]);
            const gold_fp_t left = add(cur, mul(bit, sub(sib, cur)));
            const gold_fp_t right = add(sib, mul(bit, sub(cur, sib)));
            if (!gold_fp_eq(fp(mc1[p2air_input_off((size_t)j)]), left)) viol++;
            if (!gold_fp_eq(fp(mc2[p2air_input_off((size_t)j)]), right)) viol++;
        }
        for (size_t k = 4; k < 8; k++) {
            if (mc1[p2air_input_off(k)] != 0) viol++;              /* MC1 zero-cap */
            if (mc2[p2air_input_off(k)] != p2_out(mc1, k)) viol++; /* MC2 cap carry */
        }

        /* Leaf (φ=1): CUR == cm_carry (the frozen note commitment — G-S4-1). */
        if (phi == 1) {
            for (unsigned j = 0; j < CONF_MEMB_LANES; j++)
                if (m[CONF_MEMB_CUR_OFF + j] !=
                    C1CELL(row, CONF_ACTION_CMCARRY_OFF + j))
                    viol++;
        } else {
            /* Chaining: CUR == previous row's MC2.out (φ−1, a membership row). */
            const uint64_t *pm2 = MEMB(trace + (r - 1) * CONF_AGG_WIDTH) +
                                  CONF_MEMB_MC2_OFF;
            for (unsigned j = 0; j < CONF_MEMB_LANES; j++)
                if (m[CONF_MEMB_CUR_OFF + j] != p2_out(pm2, (size_t)j)) viol++;
        }

        /* POSACC §3 gating (design red-team F6 double-spend fix):
         *   φ=1 PURE-INIT: POSACC == bit·2^0 (NEVER reads the φ=0 C1 row);
         *   φ>1 chain:     POSACC == prev.POSACC + bit·2^(φ−1). */
        if (phi == 1) {
            if (!gold_fp_eq(pacc, mul(bit, pw[0]))) viol++;
        } else {
            const gold_fp_t pprev =
                fp(MEMB(trace + (r - 1) * CONF_AGG_WIDTH)[CONF_MEMB_POSACC_OFF]);
            if (!gold_fp_eq(pacc, add(pprev, mul(bit, pw[level])))) viol++;
        }

        /* Last level (φ=D): root == public anchor; POSACC == pos_carry. */
        if (phi == (uint64_t)D_DEPTH) {
            for (unsigned j = 0; j < CONF_MEMB_LANES; j++)
                if (p2_out(mc2, (size_t)j) != anchor[j]) viol++;
            if (!gold_fp_eq(pacc, fp(C1CELL(row, CONF_ACTION_POSCARRY_OFF))))
                viol++;
        }
        } /* end membership-active else */

        /* ── S4a.3a: C4 nullifier (always-on poseidon; pins gated on
         * is_nf·IS_INPUT). At φ=D+1 of an INPUT block, nf = PRF(nk_carry,
         * CRH(cm_carry, pos_carry)) — the cm/pos/nk cells wired to the C1 frozen
         * carries (G-S4-3 cross-region bind). ── */
        {
            const uint64_t *nfr = NFR(row);
            const uint64_t *rho1 = nfr + CONF_NF_RHO1_OFF;
            const uint64_t *rho2 = nfr + CONF_NF_RHO2_OFF;
            const uint64_t *nf1 = nfr + CONF_NF_NF1_OFF;
            const uint64_t *nf2 = nfr + CONF_NF_NF2_OFF;
            viol += poseidon2_air_eval_row(rho1);
            viol += poseidon2_air_eval_row(rho2);
            viol += poseidon2_air_eval_row(nf1);
            viol += poseidon2_air_eval_row(nf2);

            const int active_nf = gold_fp_eq(is_nf, one) && is_input;
            if (active_nf) {
                /* cm/pos/nk cells == C1 frozen carries (cross-region bind). */
                for (unsigned j = 0; j < CONF_NF_LANES; j++)
                    if (nfr[CONF_NF_CM_OFF + j] !=
                        C1CELL(row, CONF_ACTION_CMCARRY_OFF + j)) viol++;
                if (nfr[CONF_NF_POS_OFF] != C1CELL(row, CONF_ACTION_POSCARRY_OFF))
                    viol++;
                if (nfr[CONF_NF_NK_OFF] != C1CELL(row, CONF_ACTION_NKCARRY_OFF))
                    viol++;
                /* ρ = CRH(cm, pos): RHO1.in = [cm(cells), 0,0,0,0];
                 * RHO2.in = [pos(cell), DOMSEP_RHO, 0, 0, RHO1 cap carry]. */
                for (unsigned j = 0; j < CONF_NF_LANES; j++)
                    if (rho1[p2air_input_off((size_t)j)] != nfr[CONF_NF_CM_OFF + j])
                        viol++;
                for (size_t k = 4; k < 8; k++)
                    if (rho1[p2air_input_off(k)] != 0) viol++;
                if (rho2[p2air_input_off(0)] != nfr[CONF_NF_POS_OFF]) viol++;
                if (rho2[p2air_input_off(1)] != DNAC_DOMSEP_RHO) viol++;
                if (rho2[p2air_input_off(2)] != 0) viol++;
                if (rho2[p2air_input_off(3)] != 0) viol++;
                for (size_t k = 4; k < 8; k++)
                    if (rho2[p2air_input_off(k)] != p2_out(rho1, k)) viol++;
                uint64_t rho[CONF_NF_LANES];
                for (unsigned j = 0; j < CONF_NF_LANES; j++)
                    rho[j] = p2_out(rho2, (size_t)j);
                /* nf = PRF(nk, ρ): NF1.in = [nk(cell), ρ0..2, 0,0,0,0];
                 * NF2.in = [ρ3, DOMSEP_NF, 0, 0, NF1 cap carry]. */
                if (nf1[p2air_input_off(0)] != nfr[CONF_NF_NK_OFF]) viol++;
                if (nf1[p2air_input_off(1)] != rho[0]) viol++;
                if (nf1[p2air_input_off(2)] != rho[1]) viol++;
                if (nf1[p2air_input_off(3)] != rho[2]) viol++;
                for (size_t k = 4; k < 8; k++)
                    if (nf1[p2air_input_off(k)] != 0) viol++;
                if (nf2[p2air_input_off(0)] != rho[3]) viol++;
                if (nf2[p2air_input_off(1)] != DNAC_DOMSEP_NF) viol++;
                if (nf2[p2air_input_off(2)] != 0) viol++;
                if (nf2[p2air_input_off(3)] != 0) viol++;
                for (size_t k = 4; k < 8; k++)
                    if (nf2[p2air_input_off(k)] != p2_out(nf1, k)) viol++;
                /* nf cell == NF2.out (G4 single-source). */
                for (unsigned j = 0; j < CONF_NF_LANES; j++)
                    if (nfr[CONF_NF_NF_OFF + j] != p2_out(nf2, (size_t)j)) viol++;
            } else {
                /* inert nf row: the input/output cells carry nothing. */
                for (unsigned j = 0; j < CONF_NF_LANES; j++)
                    if (nfr[CONF_NF_CM_OFF + j] != 0) viol++;
                if (nfr[CONF_NF_POS_OFF] != 0) viol++;
                if (nfr[CONF_NF_NK_OFF] != 0) viol++;
                for (unsigned j = 0; j < CONF_NF_LANES; j++)
                    if (nfr[CONF_NF_NF_OFF + j] != 0) viol++;
            }
        }
    }

    return viol;
}
