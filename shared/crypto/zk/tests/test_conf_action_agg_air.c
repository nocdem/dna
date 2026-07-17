/**
 * @file test_conf_action_agg_air.c
 * @brief Dual-mode S4a — aggregate Action AIR construction gate.
 *
 * S4a.1 scaffold: honest eval==0, C1 reused losslessly (gather), forced is_nf.
 * S4a.2 membership: honest membership walk accepted (root==computed anchor), and
 * the §3 POSACC gating closes the design red-team F6 double-spend (a free
 * accumulator base) — plus leaf / root / BIT tampers rejected.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "conf_action_agg_air.h"
#include "field_goldilocks.h"

#define D CONF_AGG_TREE_DEPTH

/* row/col helpers into the wide trace. */
static size_t memb_cell(size_t r, size_t off) {
    return r * CONF_AGG_WIDTH + CONF_AGG_MEMB_OFF + off;
}
static size_t nf_cell(size_t r, size_t off) {
    return r * CONF_AGG_WIDTH + CONF_AGG_NF_OFF + off;
}

int main(void) {
    const unsigned log_height = 7; /* H=128, 4 blocks */
    const size_t rows = (size_t)1 << log_height;

    /* C1 conserving instance: INPUT 100 = OUTPUT 70 + FEE 30 + dummy-last. */
    const uint64_t value[3] = {100, 70, 30};
    const uint64_t addr[3 * 4] = {0, 0, 0, 0, 0xAA01, 0xAA02, 0xAA03, 0xAA04,
                                  0xFEE1, 0xFEE2, 0xFEE3, 0xFEE4};
    const uint64_t rcm[3 * 2] = {0x11, 0x12, 0x21, 0x22, 0x31, 0x32};
    const uint8_t roles[3] = {CONF_ACTION_ROLE_INPUT, CONF_ACTION_ROLE_OUTPUT,
                              CONF_ACTION_ROLE_FEE};
    const uint64_t pos[3] = {5, 0, 0}; /* INPUT at tree position 5 = 0b0101 */
    const uint64_t nk[3] = {0x2222, 0, 0};
    const uint64_t ak[3] = {0x1111, 0, 0};

    /* Membership siblings for the INPUT note (block 0), D levels × 4 lanes;
     * OUTPUT/FEE blocks unused (arbitrary canonical values). */
    uint64_t siblings[3 * D * 4];
    for (size_t i = 0; i < 3 * D * 4; i++) siblings[i] = 0x1000 + i;

    uint64_t anchor[4];
    uint64_t nf_out[3 * 4];
    const size_t num_blocks = rows / CONF_ACTION_K; /* 4 */
    uint64_t *pub_nf = (uint64_t *)calloc(num_blocks * 4, sizeof(uint64_t));
    uint64_t *trace = (uint64_t *)calloc(rows * CONF_AGG_WIDTH, sizeof(uint64_t));
    if (!trace || !pub_nf) return 2;

    int fails = 0;
    printf("test_conf_action_agg_air: S4a (WIDTH=%d, D=%d)\n", CONF_AGG_WIDTH, D);

    /* ── honest ── */
    if (!conf_action_agg_air_generate(log_height, value, addr, rcm, roles, pos, nk,
                                      ak, 3, siblings, anchor, nf_out, pub_nf,
                                      trace)) {
        printf("  generate FAILED\n");
        free(trace);
        return 1;
    }
    int v = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
    printf("  honest (C1 + is_nf + membership walk): eval == 0    %s (%d)\n",
           v == 0 ? "PASS" : "FAIL", v);
    if (v != 0) fails++;

    /* ── C1 reuse: tamper a C1 BAL cell -> C1 constraint fires ── */
    {
        const size_t off = CONF_AGG_C1_OFF + CONF_ACTION_BAL_OFF; /* row 0 */
        uint64_t s = trace[off];
        trace[off] = gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(s), gold_fp_one()));
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  C1 BAL tamper -> caught (reuse)                     %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── is_nf forge on φ=0 row -> caught ── */
    {
        const size_t off = CONF_AGG_ISNF_OFF; /* row 0, φ=0 */
        uint64_t s = trace[off];
        trace[off] = 1;
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  is_nf forged on φ=0 -> caught                       %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── §3 POSACC F6 DOUBLE-SPEND: tamper the φ=1 accumulator BASE. The design
     * red-team's attack was a FREE base (POSACC = real + δ) giving a distinct
     * pos_carry ⇒ distinct nullifier for the same note. The φ=1 pure-init
     * (POSACC == bit·2^0) FORCES the base, so any δ is caught. ── */
    {
        const size_t off = memb_cell(1, CONF_MEMB_POSACC_OFF); /* block0 φ=1 */
        uint64_t s = trace[off];
        trace[off] = gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(s), gold_fp_one()));
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  F6 POSACC free-base (double-spend) -> caught        %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── Leaf bind: tamper φ=1 CUR ≠ cm_carry -> leaf + ordering fire ── */
    {
        const size_t off = memb_cell(1, CONF_MEMB_CUR_OFF);
        uint64_t s = trace[off];
        trace[off] = gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(s), gold_fp_one()));
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  leaf φ=1 CUR != cm_carry -> caught (G-S4-1)         %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── Root bind: eval with a WRONG anchor -> root check fires ── */
    {
        uint64_t bad[4] = {anchor[0] ^ 1u, anchor[1], anchor[2], anchor[3]};
        int t = conf_action_agg_air_eval(trace, rows, bad, pub_nf);
        printf("  wrong anchor -> root check fires (membership real)  %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
    }

    /* ── BIT tamper on a membership row -> ordering + POSACC fire ── */
    {
        const size_t off = memb_cell(2, CONF_MEMB_BIT_OFF); /* block0 φ=2 */
        uint64_t s = trace[off];
        trace[off] = s ^ 1u; /* flip the direction bit */
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  membership BIT flip -> caught                       %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── POSACC inert: forge POSACC on a NON-membership row (φ=0) -> fires ── */
    {
        const size_t off = memb_cell(0, CONF_MEMB_POSACC_OFF); /* block0 φ=0 */
        uint64_t s = trace[off];
        trace[off] = 7;
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  POSACC forged on φ=0 (inert) -> caught              %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── S4a.3a nullifier: nf cell != NF2.out -> G4 single-source fires ──
     * The nf-phase row of the INPUT block (block 0) is φ=D+1. */
    {
        const size_t nfrow = (size_t)(D + 1); /* block 0, φ=D+1 */
        const size_t off = nf_cell(nfrow, CONF_NF_NF_OFF);
        uint64_t s = trace[off];
        trace[off] = gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(s), gold_fp_one()));
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  nf cell != NF2.out -> caught                        %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── nullifier cross-region bind: CM cell != cm_carry -> G-S4-3 fires ── */
    {
        const size_t nfrow = (size_t)(D + 1);
        const size_t off = nf_cell(nfrow, CONF_NF_CM_OFF);
        uint64_t s = trace[off];
        trace[off] = gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(s), gold_fp_one()));
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  nf CM cell != cm_carry -> caught (G-S4-3)           %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── nullifier inert: forge a CM cell on a non-nf row (φ=0) -> fires ── */
    {
        const size_t off = nf_cell(0, CONF_NF_CM_OFF); /* block 0, φ=0 */
        uint64_t s = trace[off];
        trace[off] = 0x1234;
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  nf CM forged on φ=0 (inert) -> caught               %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = s;
    }

    /* ── nf_out is the derived nullifier of the INPUT (block 0), nonzero;
     * OUTPUT/FEE slots zero. ── */
    {
        int ok = 0;
        for (int j = 0; j < 4; j++) ok |= (nf_out[0 * 4 + j] != 0);
        int zero_out = 1;
        for (int j = 0; j < 4; j++) zero_out &= (nf_out[1 * 4 + j] == 0);
        printf("  nf_out: INPUT nf nonzero + OUTPUT slot zero          %s\n",
               (ok && zero_out) ? "PASS" : "FAIL");
        if (!(ok && zero_out)) fails++;
    }

    /* ── S4a.3b nf public DROP: zero the INPUT block's public nf slot -> the
     * per-block bind (NF cell == pub_nf[blk]) fires (can't drop a real nf). ── */
    {
        uint64_t save[4];
        for (int j = 0; j < 4; j++) { save[j] = pub_nf[0 * 4 + j]; pub_nf[0 * 4 + j] = 0; }
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  nf public DROP (zeroed INPUT slot) -> caught         %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        for (int j = 0; j < 4; j++) pub_nf[0 * 4 + j] = save[j];
    }

    /* ── S4a.3b nf public ADD: set a DUMMY block's public nf slot nonzero -> the
     * bind fires (the dummy block's NF cell is 0, can't add a spurious nf). ── */
    {
        const size_t dblk = num_blocks - 1; /* dummy-last block */
        uint64_t save = pub_nf[dblk * 4 + 0];
        pub_nf[dblk * 4 + 0] = 0x9999;
        int t = conf_action_agg_air_eval(trace, rows, anchor, pub_nf);
        printf("  nf public ADD (spurious on dummy slot) -> caught     %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        pub_nf[dblk * 4 + 0] = save;
    }

    free(trace);
    free(pub_nf);
    if (fails) {
        printf("test_conf_action_agg_air: FAIL (%d)\n", fails);
        return 1;
    }
    printf("test_conf_action_agg_air: PASS\n");
    printf("  S4a COMPLETE: C1 + C3 membership (F6-gated) + C4 nullifier (carry-\n");
    printf("  bound) + nf public interface (DET-S4-4, drop/add rejected).\n");
    return 0;
}
