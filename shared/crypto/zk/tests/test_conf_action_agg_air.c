/**
 * @file test_conf_action_agg_air.c
 * @brief Dual-mode S4a.1 — aggregate Action AIR scaffold gate.
 *
 * Verifies: (1) an honest aggregate trace (C1 conserving instance embedded) evals
 * to 0 violations; (2) the C1 region is reused LOSSLESSLY (a C1-cell tamper is
 * caught via the gather+conf_action_air_eval path); (3) the forced is_nf phase
 * selector is sound (is_nf/inv_nf tampers rejected).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "conf_action_agg_air.h"
#include "field_goldilocks.h"

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
    const uint64_t pos[3] = {5, 0, 0};
    const uint64_t nk[3] = {0x2222, 0, 0};
    const uint64_t ak[3] = {0x1111, 0, 0};

    uint64_t *trace = (uint64_t *)calloc(rows * CONF_AGG_WIDTH, sizeof(uint64_t));
    if (!trace) return 2;

    int fails = 0;
    printf("test_conf_action_agg_air: S4a.1 aggregate scaffold (WIDTH=%d)\n",
           CONF_AGG_WIDTH);

    /* ── honest ── */
    if (!conf_action_agg_air_generate(log_height, value, addr, rcm, roles, pos, nk,
                                      ak, 3, trace)) {
        printf("  generate FAILED\n");
        free(trace);
        return 1;
    }
    int v = conf_action_agg_air_eval(trace, rows);
    printf("  honest aggregate trace: eval == 0                    %s (%d)\n",
           v == 0 ? "PASS" : "FAIL", v);
    if (v != 0) fails++;

    /* ── C1 reuse: tamper a C1 BAL cell -> C1 constraint fires (gather path) ── */
    {
        const size_t off = 0 * CONF_AGG_WIDTH + CONF_AGG_C1_OFF + CONF_ACTION_BAL_OFF;
        uint64_t save = trace[off];
        trace[off] = gold_fp_to_u64(
            gold_fp_add(gold_fp_from_u64(save), gold_fp_one()));
        int t = conf_action_agg_air_eval(trace, rows);
        printf("  C1 BAL tamper -> caught (C1 reuse)                    %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = save;
    }

    /* ── is_nf phase selector: flip is_nf on a non-nf row (φ≠D+1) -> fires ── */
    {
        const size_t off = 0 * CONF_AGG_WIDTH + CONF_AGG_ISNF_OFF; /* φ=0 row */
        uint64_t save = trace[off];
        trace[off] = 1; /* claim is_nf=1 where φ=0 ≠ D+1 */
        int t = conf_action_agg_air_eval(trace, rows);
        printf("  is_nf forged=1 on φ=0 row -> caught                   %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = save;
    }

    /* ── is_nf on the real nf row (φ=D+1): drop it to 0 -> fires ── */
    {
        const size_t nf_row = (size_t)(CONF_AGG_TREE_DEPTH + 1); /* φ=D+1 in block 0 */
        const size_t off = nf_row * CONF_AGG_WIDTH + CONF_AGG_ISNF_OFF;
        uint64_t save = trace[off];
        if (save != 1) { printf("  (setup) expected is_nf=1 at φ=D+1, got %llu\n",
                                (unsigned long long)save); fails++; }
        trace[off] = 0; /* drop the nf-phase flag */
        int t = conf_action_agg_air_eval(trace, rows);
        printf("  is_nf dropped=0 on φ=D+1 row -> caught                %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = save;
    }

    /* ── inv_nf tamper on a non-nf row -> is_zero relation fires ── */
    {
        const size_t off = 1 * CONF_AGG_WIDTH + CONF_AGG_INVNF_OFF; /* φ=1 row */
        uint64_t save = trace[off];
        trace[off] = gold_fp_to_u64(
            gold_fp_add(gold_fp_from_u64(save), gold_fp_one()));
        int t = conf_action_agg_air_eval(trace, rows);
        printf("  inv_nf tamper -> caught                               %s (%d)\n",
               t > 0 ? "PASS" : "FAIL", t);
        if (t == 0) fails++;
        trace[off] = save;
    }

    free(trace);
    if (fails) {
        printf("test_conf_action_agg_air: FAIL (%d)\n", fails);
        return 1;
    }
    printf("test_conf_action_agg_air: PASS\n");
    printf("  S4a.1 scaffold: C1 reused losslessly (gather/scatter) + forced\n");
    printf("  is_nf=[φ==D+1] phase selector sound. Membership+nullifier: S4a.2/3.\n");
    return 0;
}
