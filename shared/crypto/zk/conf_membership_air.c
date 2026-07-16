/**
 * @file conf_membership_air.c
 * @brief Dual-mode C3 Poseidon2 Merkle-path membership AIR — is_zk=0 gate.
 *
 * See conf_membership_air.h for the construction + grounding. Construction-gate
 * style (like conf_balance_air): generate an honest path trace, eval returns the
 * count of violated constraints (0 == valid membership witness).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_membership_air.h"

#include <string.h>

#include "field_goldilocks.h"
#include "note_commit.h"         /* note_merkle_compress (honest root) */
#include "poseidon2_air.h"       /* poseidon2_air_eval_row */
#include "poseidon2_air_cols.h"
#include "poseidon2_air_trace.h" /* poseidon2_air_generate_row */

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

static gold_fp_t bool_res(gold_fp_t s) { return mul(s, sub(s, gold_fp_one())); }

static uint64_t mc_out(const uint64_t *blk, size_t k) {
    return blk[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, k)];
}

/* One in-circuit 2-to-1 compress (== S0 note_merkle_compress): MC1 absorbs
 * left[4] with zero capacity, MC2 absorbs right[4] with MC1's capacity carry;
 * digest = MC2.out[0..4]. Writes MC1/MC2 blocks. */
static void compress_blocks(const uint64_t left[4], const uint64_t right[4],
                            uint64_t *mc1, uint64_t *mc2,
                            uint64_t out[CONF_MEMB_LANES]) {
    uint64_t in1[8] = {left[0], left[1], left[2], left[3], 0, 0, 0, 0};
    poseidon2_air_generate_row(in1, mc1);
    uint64_t s1[8];
    for (int k = 0; k < 8; k++) s1[k] = mc_out(mc1, (size_t)k);

    uint64_t in2[8] = {right[0], right[1], right[2], right[3],
                       s1[4], s1[5], s1[6], s1[7]};
    poseidon2_air_generate_row(in2, mc2);
    for (int k = 0; k < CONF_MEMB_LANES; k++) out[k] = mc_out(mc2, (size_t)k);
}

bool conf_membership_air_generate(unsigned depth, const uint64_t leaf[CONF_MEMB_LANES],
                                  uint64_t pos, const uint64_t *siblings,
                                  uint64_t *trace_out,
                                  uint64_t root_out[CONF_MEMB_LANES]) {
    if (depth == 0 || depth > CONF_MEMB_MAX_DEPTH) return false;
    if (!leaf || !siblings || !trace_out || !root_out) return false;

    for (size_t i = 0; i < (size_t)depth * CONF_MEMB_WIDTH; i++) trace_out[i] = 0;

    uint64_t cur[CONF_MEMB_LANES];
    memcpy(cur, leaf, sizeof cur);
    uint64_t pacc = 0;

    for (unsigned i = 0; i < depth; i++) {
        uint64_t *row = trace_out + (size_t)i * CONF_MEMB_WIDTH;
        const uint64_t *sib = siblings + (size_t)i * CONF_MEMB_LANES;
        uint64_t bit = (pos >> i) & 1u;

        for (int j = 0; j < CONF_MEMB_LANES; j++) {
            row[CONF_MEMB_CUR_OFF + j] = cur[j];
            row[CONF_MEMB_SIB_OFF + j] = sib[j];
        }
        row[CONF_MEMB_BIT_OFF] = bit;

        /* Ordered pair by the direction bit. */
        uint64_t left[CONF_MEMB_LANES], right[CONF_MEMB_LANES];
        for (int j = 0; j < CONF_MEMB_LANES; j++) {
            left[j] = bit ? sib[j] : cur[j];
            right[j] = bit ? cur[j] : sib[j];
        }

        uint64_t next[CONF_MEMB_LANES];
        compress_blocks(left, right, row + CONF_MEMB_MC1_OFF,
                        row + CONF_MEMB_MC2_OFF, next);

        /* POSACC running sum Σ bit_j·2^j (verifier-known 2^i weight). */
        pacc += bit << i;
        row[CONF_MEMB_POSACC_OFF] = pacc;

        memcpy(cur, next, sizeof cur);
    }
    memcpy(root_out, cur, sizeof(uint64_t) * CONF_MEMB_LANES);
    return true;
}

int conf_membership_air_eval(const uint64_t *trace, unsigned depth,
                             const uint64_t leaf[CONF_MEMB_LANES], uint64_t pos,
                             const uint64_t anchor[CONF_MEMB_LANES]) {
    if (!trace || depth == 0 || depth > CONF_MEMB_MAX_DEPTH || !leaf || !anchor)
        return 1;
    int viol = 0;

    /* Precompute 2^i (verifier-known level weights, F3). */
    gold_fp_t pw[CONF_MEMB_MAX_DEPTH];
    pw[0] = gold_fp_one();
    for (unsigned i = 1; i < depth; i++) pw[i] = add(pw[i - 1], pw[i - 1]);

    for (unsigned i = 0; i < depth; i++) {
        const uint64_t *row = trace + (size_t)i * CONF_MEMB_WIDTH;
        const uint64_t *mc1 = row + CONF_MEMB_MC1_OFF;
        const uint64_t *mc2 = row + CONF_MEMB_MC2_OFF;
        gold_fp_t bit = fp(row[CONF_MEMB_BIT_OFF]);

        /* BIT boolean. */
        if (!gold_fp_is_zero(bool_res(bit))) viol++;

        /* Both compress permutations internally consistent (every row). */
        viol += poseidon2_air_eval_row(mc1);
        viol += poseidon2_air_eval_row(mc2);

        /* Ordering (dm-c3 F2 — the SAME bit cell drives walk AND position):
         *   MC1.in[j] (left)  = cur_j + bit·(sib_j − cur_j)
         *   MC2.in[j] (right) = sib_j + bit·(cur_j − sib_j)
         * and MC1 zero-capacity, MC2 capacity carry from MC1. */
        for (int j = 0; j < CONF_MEMB_LANES; j++) {
            gold_fp_t cur = fp(row[CONF_MEMB_CUR_OFF + j]);
            gold_fp_t sib = fp(row[CONF_MEMB_SIB_OFF + j]);
            gold_fp_t left = add(cur, mul(bit, sub(sib, cur)));
            gold_fp_t right = add(sib, mul(bit, sub(cur, sib)));
            if (!gold_fp_eq(fp(mc1[p2air_input_off((size_t)j)]), left)) viol++;
            if (!gold_fp_eq(fp(mc2[p2air_input_off((size_t)j)]), right)) viol++;
        }
        for (size_t k = 4; k < 8; k++) {
            if (mc1[p2air_input_off(k)] != 0) viol++;              /* MC1 zero-cap IV */
            if (mc2[p2air_input_off(k)] != mc_out(mc1, k)) viol++; /* MC2 capacity carry */
        }

        /* Level-0 CUR == public leaf. */
        if (i == 0) {
            for (int j = 0; j < CONF_MEMB_LANES; j++)
                if (row[CONF_MEMB_CUR_OFF + j] != leaf[j]) viol++;
        } else {
            /* Chaining: this row's CUR == previous row's MC2.out (cur_i). */
            const uint64_t *prev = trace + (size_t)(i - 1) * CONF_MEMB_WIDTH;
            const uint64_t *pmc2 = prev + CONF_MEMB_MC2_OFF;
            for (int j = 0; j < CONF_MEMB_LANES; j++)
                if (row[CONF_MEMB_CUR_OFF + j] != mc_out(pmc2, (size_t)j)) viol++;
        }

        /* POSACC: row0 = bit_0; row i = POSACC_{i-1} + bit_i·2^i. */
        gold_fp_t pacc = fp(row[CONF_MEMB_POSACC_OFF]);
        gold_fp_t term = mul(bit, pw[i]);
        if (i == 0) {
            if (!gold_fp_eq(pacc, term)) viol++;
        } else {
            gold_fp_t pacc_prev = fp(trace[(size_t)(i - 1) * CONF_MEMB_WIDTH +
                                            CONF_MEMB_POSACC_OFF]);
            if (!gold_fp_eq(pacc, add(pacc_prev, term))) viol++;
        }

        /* Last level: MC2.out == public anchor; POSACC == public pos. */
        if (i == depth - 1) {
            for (int j = 0; j < CONF_MEMB_LANES; j++)
                if (mc_out(mc2, (size_t)j) != anchor[j]) viol++;
            if (!gold_fp_eq(pacc, fp(pos))) viol++;
        }
    }
    return viol;
}
