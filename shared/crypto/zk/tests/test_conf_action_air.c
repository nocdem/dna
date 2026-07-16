/**
 * @file test_conf_action_air.c
 * @brief C1 (dual-mode) S1a — forced phase-counter construction gate (is_zk=0).
 *
 * Proves the forced φ-counter (E1/E2/E3/E13) soundness BY CONSTRUCTION:
 *   (accept) an honest cycling trace ⇒ 0 constraint violations;
 *   (reject) every deviation a malicious prover could attempt to escape the
 *            prover-independent positioning — skip a phase, stall at K−1, reset
 *            early/late, forge w or inv, non-boolean bit, φ[0]≠0 — ⇒ ≥1 violation.
 *
 * This is the crux primitive (dm-c1 §4d): if φ is truly forced at every row, the
 * later freeze-carry bindings inherit prover-independent block structure.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "../conf_action_air.h"
#include "../field_goldilocks.h"

/* log_height = 7 → H = 128 = 4 full K=32 blocks (exercises the wrap 3×). */
#define LOG_H 7u
#define ROWS  (1u << LOG_H)

static int fails = 0;

static void expect_reject(const char *name, const uint64_t *bad) {
    int v = conf_action_air_eval(bad, ROWS);
    if (v >= 1) {
        printf("  [reject] %-40s caught (%d viol) — OK\n", name, v);
    } else {
        printf("  [reject] %-40s NOT caught — FAIL\n", name);
        fails++;
    }
}

/* Overwrite a cell with a canonical field value. */
static void set(uint64_t *t, size_t row, size_t off, uint64_t val) {
    t[row * CONF_ACTION_WIDTH + off] = val;
}

int main(void) {
    /* H=128 = 4 blocks of K=32. 3 real notes (blocks 0-2) + dummy-last (block 3). */
    const uint64_t cm[3][CONF_ACTION_CM_LANES] = {
        {111, 112, 113, 114},
        {221, 222, 223, 224},
        {331, 332, 333, 334},
    };
    uint64_t honest[ROWS * CONF_ACTION_WIDTH];
    if (!conf_action_air_generate(LOG_H, &cm[0][0], 3, honest)) {
        printf("FAIL: honest generate failed\n");
        return 1;
    }

    printf("============================================================\n");
    printf("C1 S1a+S1b — phase-counter + freeze-carry, K=%d, H=%u\n",
           CONF_ACTION_K, ROWS);
    printf("============================================================\n");

    /* ACCEPT: honest trace. */
    int v = conf_action_air_eval(honest, ROWS);
    if (v == 0) {
        printf("  [accept] honest cycling trace                    0 viol — OK\n");
    } else {
        printf("  [accept] honest cycling trace                    %d viol — FAIL\n", v);
        fails++;
    }

    /* Sanity: honest φ actually cycles (row 31 = K−1, row 32 wraps to 0). */
    if (honest[31 * CONF_ACTION_WIDTH + CONF_ACTION_PHI_OFF] != 31 ||
        honest[32 * CONF_ACTION_WIDTH + CONF_ACTION_PHI_OFF] != 0 ||
        honest[31 * CONF_ACTION_WIDTH + CONF_ACTION_W_OFF] != 1) {
        printf("  [accept] φ wrap sanity (31→0, w@31=1)            FAIL\n");
        fails++;
    } else {
        printf("  [accept] φ wrap sanity (31→0, w@31=1)            OK\n");
    }

    /* REJECT 1: skip a phase (φ jumps 5→7 at an interior climb row). Breaks E3
     * climb AND E1 recomposition (bits still encode 6). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 6, CONF_ACTION_PHI_OFF, 7); /* was 6 */
        expect_reject("skip phase (φ 6→7 mid-block)", bad);
    }

    /* REJECT 2: stall at K−1 (φ stays 31 past the wrap instead of resetting). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 32, CONF_ACTION_PHI_OFF, 31); /* was 0 (post-wrap reset) */
        /* keep bits consistent so only E3 reset fires, not E1 */
        for (unsigned i = 0; i < CONF_ACTION_LOG_K; i++)
            set(bad, 32, CONF_ACTION_PHIBITS_OFF + i, (31u >> i) & 1u);
        expect_reject("stall at K-1 (no reset after wrap)", bad);
    }

    /* REJECT 3: early reset (φ resets to 0 mid-block without a wrap). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 10, CONF_ACTION_PHI_OFF, 0); /* was 10 */
        for (unsigned i = 0; i < CONF_ACTION_LOG_K; i++)
            set(bad, 10, CONF_ACTION_PHIBITS_OFF + i, 0);
        expect_reject("early reset (φ→0 mid-block, no wrap)", bad);
    }

    /* REJECT 4: forge w=1 at a non-wrap row (claim wrap where φ≠K−1). Breaks E2
     * (d·w=0 with d≠0). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 5, CONF_ACTION_W_OFF, 1); /* φ=5, d=5-31≠0 */
        expect_reject("forge w=1 at non-wrap row", bad);
    }

    /* REJECT 5: forge w=0 at the wrap row (hide the wrap). Breaks E2
     * (d·inv=1−w with d=0 forces w=1). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 31, CONF_ACTION_W_OFF, 0); /* φ=31, d=0 → must have w=1 */
        set(bad, 31, CONF_ACTION_INV_OFF, 0);
        expect_reject("forge w=0 at wrap row (hide wrap)", bad);
    }

    /* REJECT 6: non-boolean φ bit. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 3, CONF_ACTION_PHIBITS_OFF, 2); /* bit must be 0/1 */
        expect_reject("non-boolean phi bit", bad);
    }

    /* REJECT 7: bits inconsistent with φ (recomposition mismatch). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 4, CONF_ACTION_PHIBITS_OFF + 0, 1); /* φ=4 bits=00100; flip b0 */
        expect_reject("phi-bits recomposition mismatch", bad);
    }

    /* ── S1b freeze-carry attacks ──────────────────────────────────────────
     * Sanity: cm_carry holds block 1's commitment across its whole block
     * (rows 32..63), loaded at row 32 (φ=0). */
    {
        int ok = 1;
        for (size_t r = 32; r < 64; r++)
            for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++)
                if (honest[r * CONF_ACTION_WIDTH + CONF_ACTION_CMCARRY_OFF + j] !=
                    cm[1][j]) ok = 0;
        printf("  [accept] cm_carry frozen == block-1 cm across block  %s\n",
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }

    /* REJECT 10: mutate cm_carry mid-block (row 40, block 1) — breaks E4 freeze. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 40, CONF_ACTION_CMCARRY_OFF + 0, 999);
        expect_reject("mutate cm_carry mid-block (E4 freeze)", bad);
    }

    /* REJECT 11: desync the block-start load — change a real block's φ=0 carry so
     * it != cm_output (breaks E11 wrap-load at row 32). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 32, CONF_ACTION_CMCARRY_OFF + 1, 777);
        expect_reject("desync block-start load (E11 wrap-load)", bad);
    }

    /* REJECT 12: block-0 carry != cm_output (breaks E8′ is_first_row init). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_CMCARRY_OFF + 0, 555);
        expect_reject("block-0 carry != output (E8' init)", bad);
    }

    /* REJECT 13: flip IS_REAL mid-block (row 10, block 0) — breaks E6 block-const. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 10, CONF_ACTION_ISREAL_OFF, 0);
        expect_reject("flip IS_REAL mid-block (E6 block-const)", bad);
    }

    /* REJECT 14: non-dummy last block — make the last block real (E7). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, ROWS - 1, CONF_ACTION_ISREAL_OFF, 1);
        expect_reject("non-dummy last block (E7)", bad);
    }

    /* REJECT 15: inject a commitment into a dummy block's carry (row 100, block 3)
     * — breaks PZ padding-zero. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 100, CONF_ACTION_CMCARRY_OFF + 2, 42);
        expect_reject("inject carry into dummy block (padding-zero)", bad);
    }

    /* REJECT 8: φ[0] ≠ 0 (anchor E13). Set row 0 to a self-consistent φ=1 cell
     * (E1 bits, E2 w=0 + inv=1/(1−31)); the E13 anchor fires (and the row0→1
     * climb too — rejection is the assertion, not which constraint). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_PHI_OFF, 1);
        for (unsigned i = 0; i < CONF_ACTION_LOG_K; i++)
            set(bad, 0, CONF_ACTION_PHIBITS_OFF + i, (1u >> i) & 1u);
        set(bad, 0, CONF_ACTION_W_OFF, 0);
        gold_fp_t d0 = gold_fp_sub(gold_fp_from_u64(1),
                                   gold_fp_from_u64(CONF_ACTION_K - 1));
        set(bad, 0, CONF_ACTION_INV_OFF, gold_fp_to_u64(gold_fp_inv(d0)));
        expect_reject("phi[0] != 0 (anchor E13)", bad);
    }

    /* REJECT 9: forge inv at a non-wrap row (break the is_zero binding so a
     * prover could later fake w). d·inv must equal 1−w. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 7, CONF_ACTION_INV_OFF, 12345); /* φ=7, wrong inverse */
        expect_reject("forge inv (is_zero binding broken)", bad);
    }

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("C1 S1a+S1b: %d FAIL\n", fails);
        return 1;
    }
    printf("C1 S1a+S1b: honest accepted + phase-counter & freeze-carry deviations "
           "rejected — PASS\n");
    return 0;
}
