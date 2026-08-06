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
#include "../note_commit.h"

/* log_height = 7 → H = 128 = 4 full K=32 blocks (exercises the wrap 3×). */
#define LOG_H 7u
#define ROWS  (1u << LOG_H)

static int fails = 0;

/* Every reject vector below is a mutation of the CONSERVING honest trace, whose
 * S8 Gate-2 terminal is BAL == boundary_out − boundary_in with both legs 0 —
 * i.e. exactly the historical BAL == 0. The boundary-bound terminal itself is
 * exercised by the S8 block near the end of main(). */
static void expect_reject(const char *name, const uint64_t *bad) {
    int v = conf_action_air_eval(bad, ROWS, 0, 0);
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
    /* H=128 = 4 blocks of K=32. 3 real notes (blocks 0-2) + dummy-last (block 3).
     * Conserving instance: INPUT 100 = OUTPUT 90 + OUTPUT 10, at
     * boundary_in == boundary_out == 0.
     * ⚠ LEDGER-V2 S8 Gate 2: block 2 used to be a CONF_ACTION_ROLE_FEE note.
     * IS_FEE is now PINNED ZERO in the constraint system and
     * conf_action_air_generate REJECTS a FEE-role block outright
     * (conf_action_air.c:118-121), so it became a second OUTPUT of the SAME
     * value. The note set stays conserving, so every downstream expectation
     * (cm byte-match, frozen carries, BAL == 0 at the last row, all 40+ reject
     * vectors) keeps its exact meaning. The FEE-role rejection itself is
     * asserted in the S8 block below. */
    const uint64_t value[3] = {100, 90, 10};
    const uint8_t roles[3] = {CONF_ACTION_ROLE_INPUT, CONF_ACTION_ROLE_OUTPUT,
                              CONF_ACTION_ROLE_OUTPUT};
    const uint64_t addr[3][CONF_ACTION_ADDR_LANES] = {
        {11, 22, 33, 44}, {51, 52, 53, 54}, {91, 92, 93, 94},
    };
    const uint64_t rcm[3][CONF_ACTION_RCM_LANES] = {
        {0xdead, 0xbeef}, {123, 456}, {777, 888},
    };
    const uint64_t pos[3] = {5, 99, 4096};      /* E15 pos_carry sources */
    /* F3: nk/ak are 4-lane-per-block arrays ([blk*4 + lane], all lanes distinct
     * nonzero on the blocks that use them so per-lane bugs can't hide). */
    const uint64_t nk[3 * CONF_ACTION_NK_LANES] = {
        0xA11CE, 0xA11CF, 0xA11D0, 0xA11D1,  /* block 0 (INPUT) */
        0xB0B, 0xB0C, 0xB0D, 0xB0E,          /* block 1 */
        42, 43, 44, 45,                      /* block 2 */
    };
    const uint64_t ak[3 * CONF_ACTION_AK_LANES] = {
        0xACE, 0xACF, 0xAD0, 0xAD1,          /* block 0 (INPUT) */
        0, 0, 0, 0, 0, 0, 0, 0,              /* OUTPUT/FEE unused */
    };

    /* The INPUT note (block 0) is addressed to (ak0[4], nk0[4]): addr =
     * Poseidon2 sponge. generate derives it; the test mirrors that for the cm
     * byte-match target. OUTPUT notes keep their passed addresses. */
    uint64_t eff_addr[3][CONF_ACTION_ADDR_LANES];
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < CONF_ACTION_ADDR_LANES; j++) eff_addr[i][j] = addr[i][j];
    conf_action_derive_addr(&ak[0], &nk[0], eff_addr[0]); /* block 0 is INPUT */

    /* Expected commitments via the S0 note_commit sponge (byte-match target). */
    uint64_t expect_cm[3][CONF_ACTION_CM_LANES];
    for (int i = 0; i < 3; i++)
        note_commit(value[i], eff_addr[i], rcm[i], expect_cm[i]);

    uint64_t honest[ROWS * CONF_ACTION_WIDTH];
    if (!conf_action_air_generate(LOG_H, value, &addr[0][0], &rcm[0][0], roles,
                                  pos, nk, ak, 3, /*boundary_in=*/0,
                                  /*boundary_out=*/0, honest)) {
        printf("FAIL: honest generate failed\n");
        return 1;
    }

    printf("============================================================\n");
    printf("C1 complete — phase-counter+freeze-carry+note-commitment+balance+carries+spend-auth\n");
    printf("  K=%d, H=%u, WIDTH=%d\n", CONF_ACTION_K, ROWS, CONF_ACTION_WIDTH);
    printf("============================================================\n");

    /* ACCEPT: honest trace. */
    int v = conf_action_air_eval(honest, ROWS, 0, 0);
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

    /* ── S1c byte-match: in-circuit cm_output == S0 note_commit() ────────────
     * The whole point of E9′ — the AIR-computed commitment equals the trusted S0
     * sponge, so value is bound to cm by a collision-resistant hash. */
    {
        int ok = 1;
        const size_t blk0_row[3] = {0, 32, 64};
        for (int i = 0; i < 3; i++)
            for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++)
                if (honest[blk0_row[i] * CONF_ACTION_WIDTH + CONF_ACTION_CMOUT_OFF + j] !=
                    expect_cm[i][j]) ok = 0;
        printf("  [accept] in-circuit cm_output == S0 note_commit()   %s\n",
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }

    /* ── S1b freeze-carry attacks ──────────────────────────────────────────
     * Sanity: cm_carry holds block 1's commitment across its whole block
     * (rows 32..63), loaded at row 32 (φ=0). */
    {
        int ok = 1;
        for (size_t r = 32; r < 64; r++)
            for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++)
                if (honest[r * CONF_ACTION_WIDTH + CONF_ACTION_CMCARRY_OFF + j] !=
                    expect_cm[1][j]) ok = 0;
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

    /* ── S1c note-commitment attacks ──────────────────────────────────────── */

    /* REJECT 16: the §4b MINT — inflate block-1's value cell (real value 90).
     * Change ONLY the value cell: the poseidon2 blocks still hash the real 90, so
     * NC1.in[0] (=90) != the forged value (=1000); also breaks range + balance. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 32, CONF_ACTION_VALUE_OFF, 1000); /* block-1 real value is 90 */
        expect_reject("MINT: value cell != hashed value (§4b)", bad);
    }

    /* REJECT 17: swap the DOMSEP_NOTE pad cell in NC2 (domain confusion). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_NC2_OFF + p2air_input_off(3), 999);
        expect_reject("wrong DOMSEP_NOTE pad cell (NC2.in[3])", bad);
    }

    /* REJECT 18: break NC1 all-zero-IV capacity (NC1.in[4] != 0). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_NC1_OFF + p2air_input_off(4), 7);
        expect_reject("NC1 capacity IV != 0 (absorb-pad pin)", bad);
    }

    /* REJECT 19: break the capacity carry (NC2.in[5] != NC1.out[5]). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_NC2_OFF + p2air_input_off(5), 123456);
        expect_reject("capacity carry NC2.in != NC1.out", bad);
    }

    /* REJECT 20: desync cm_output from NC2.out (cm_output != the sponge output). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_CMOUT_OFF + 0, 424242);
        expect_reject("cm_output != NC2.out (E9' bind)", bad);
    }

    /* REJECT 21: tamper a poseidon2 internal cell (breaks poseidon2_air_eval). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_NC1_OFF + p2air_end_post_off(0, 0),
            honest[CONF_ACTION_NC1_OFF + p2air_end_post_off(0, 0)] + 1);
        expect_reject("tampered poseidon2 NC1 internal cell", bad);
    }

    /* ── S1d balance-conservation attacks ─────────────────────────────────── */

    /* Sanity: BAL == 0 at the last row (Σin = Σout, boundaries both 0). */
    {
        uint64_t last_bal =
            honest[(ROWS - 1) * CONF_ACTION_WIDTH + CONF_ACTION_BAL_OFF];
        printf("  [accept] BAL == 0 at last row (100 = 90 + 10)       %s\n",
               last_bal == 0 ? "OK" : "FAIL");
        if (last_bal != 0) fails++;
    }

    /* REJECT 22: BAL-consistent MINT — inflate the INPUT value AND its bits AND
     * re-hash would be needed; here we tamper the running BAL at the last row to
     * fake conservation while the accumulator disagrees. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, ROWS - 1, CONF_ACTION_BAL_OFF, 5); /* was 0 */
        expect_reject("BAL != 0 at last row (non-conservation)", bad);
    }

    /* REJECT 23: value ≥ 2^52 (range overflow) — set VALUE past the 52-bit gate;
     * the 52 bits cannot recompose it. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_VALUE_OFF, (uint64_t)1 << 52);
        expect_reject("value >= 2^52 (range gate)", bad);
    }

    /* REJECT 24: two roles on one block (IS_OUTPUT=1 on the INPUT block row 0).
     * Role sum 2 != IS_REAL. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_ISOUT_OFF, 1); /* block 0 is INPUT */
        expect_reject("two roles on one block (role-sum)", bad);
    }

    /* REJECT 25: role flip mid-block (E17) — change IS_INPUT at row 5 of block 0. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 5, CONF_ACTION_ISIN_OFF, 0);
        expect_reject("role flip mid-block (E17)", bad);
    }

    /* REJECT 26: forge IS_BAL_CONTRIB at a non-φ=0 row (double-count a value). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 3, CONF_ACTION_BALCON_OFF, 1); /* φ=3, should be 0 */
        expect_reject("forge IS_BAL_CONTRIB off-φ=0 (E10')", bad);
    }

    /* REJECT 27: forge phi_is0=1 at a non-zero φ (break the is_zero indicator). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH];
        memcpy(bad, honest, sizeof bad);
        set(bad, 4, CONF_ACTION_PHI0_OFF, 1); /* φ=4 */
        set(bad, 4, CONF_ACTION_INV0_OFF, 0);
        expect_reject("forge phi_is0 at φ!=0 (is_zero)", bad);
    }

    /* ── E15 frozen-carry attacks (pos/nk/addr) ───────────────────────────── */

    /* Sanity: pos/nk/addr carries hold block-1's sources across its block
     * (nk per-lane since F3). */
    {
        int ok = 1;
        for (size_t r = 32; r < 64; r++) {
            if (honest[r * CONF_ACTION_WIDTH + CONF_ACTION_POSCARRY_OFF] != pos[1]) ok = 0;
            for (unsigned j = 0; j < CONF_ACTION_NK_LANES; j++)
                if (honest[r * CONF_ACTION_WIDTH + CONF_ACTION_NKCARRY_OFF + j] !=
                    nk[1 * CONF_ACTION_NK_LANES + j]) ok = 0;
            for (unsigned j = 0; j < CONF_ACTION_ADDR_LANES; j++)
                if (honest[r * CONF_ACTION_WIDTH + CONF_ACTION_ADDRCARRY_OFF + j] != addr[1][j]) ok = 0;
        }
        printf("  [accept] pos/nk/addr carries frozen == block-1 src %s\n", ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }
    /* REJECT 28: mutate pos_carry mid-block (E4 freeze). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 40, CONF_ACTION_POSCARRY_OFF, 777);
        expect_reject("mutate pos_carry mid-block (E15/E4)", bad);
    }
    /* REJECT 29: desync nk_carry block-start load (E11), lane 0. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 32, CONF_ACTION_NKCARRY_OFF, 555);
        expect_reject("desync nk_carry load (E15/E11)", bad);
    }
    /* REJECT 30: inject into a dummy block's addr_carry (padding-zero). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 100, CONF_ACTION_ADDRCARRY_OFF + 1, 9);
        expect_reject("inject dummy addr_carry (E15 padding-zero)", bad);
    }
    /* REJECT 31: block-0 nk_carry != source (E8' init), lane 0. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_NKCARRY_OFF, 333);
        expect_reject("block-0 nk_carry != src (E15/E8')", bad);
    }
    /* REJECT F3-a: EVERY nk_carry lane obeys the E15 freeze — tamper each of the
     * 3 NEW lanes mid-block independently (a free lane across the φ-seam would be
     * a theft/double-spend vector; F3 red-team charter item 4). */
    for (unsigned lane = 1; lane < CONF_ACTION_NK_LANES; lane++) {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        char name[64];
        snprintf(name, sizeof name, "mutate nk_carry lane %u mid-block (F3)", lane);
        set(bad, 40, CONF_ACTION_NKCARRY_OFF + lane, 606 + lane);
        expect_reject(name, bad);
    }
    /* REJECT F3-b: per-lane block-start load desync on a NEW lane (E11). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 32, CONF_ACTION_NKCARRY_OFF + 3, 556);
        expect_reject("desync nk_carry lane 3 load (F3/E11)", bad);
    }

    /* ── condition-3 spend-authority attacks (block 0 = INPUT) ────────────── */

    /* Sanity: the input note's committed ADDR == Poseidon2(ak0, nk0). */
    {
        int ok = 1;
        for (unsigned j = 0; j < CONF_ACTION_ADDR_LANES; j++)
            if (honest[0 * CONF_ACTION_WIDTH + CONF_ACTION_ADDR_OFF + j] != eff_addr[0][j]) ok = 0;
        printf("  [accept] input ADDR == Poseidon2(ak,nk) (cond-3)   %s\n", ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }
    /* REJECT 32: THEFT — forge ak lane 0 (AC1.in[0]) so addr_pub != committed
     * ADDR. A spender who does NOT know the note's (ak,nk) is rejected. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_AC1_OFF + p2air_input_off(0), 0xBAD); /* wrong ak */
        expect_reject("THEFT: wrong ak != addr preimage (cond-3)", bad);
    }
    /* REJECT F3-c: THEFT via a NEW ak lane (AC1.in[3] — knowing 3 of 4 lanes must
     * not be enough; every lane is pinned to the AK cells). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_AC1_OFF + p2air_input_off(3), 0xBAD3);
        expect_reject("THEFT: wrong ak lane 3 (F3 cond-3)", bad);
    }
    /* REJECT 33: nk lane used in cond-3 != nk_src lane (per-lane bind, F3:
     * nk lanes moved to AC2.in[0..4)). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_AC2_OFF + p2air_input_off(0), nk[0] + 1);
        expect_reject("cond-3 nk != nk_src (per-lane)", bad);
    }
    /* REJECT F3-d: a NEW nk lane diverges from its nk_src cell (AC2.in[3]). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_AC2_OFF + p2air_input_off(3), nk[3] + 1);
        expect_reject("cond-3 nk lane 3 != nk_src (F3)", bad);
    }
    /* REJECT 34: wrong DOMSEP_ADDR pad cell (F3: moved to AC3.in[0]). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_AC3_OFF + p2air_input_off(0), 999);
        expect_reject("wrong DOMSEP_ADDR (AC3.in[0])", bad);
    }
    /* REJECT 35: break AC2 capacity carry (AC2.in[5] != AC1.out[5]). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_AC2_OFF + p2air_input_off(5), 12345);
        expect_reject("AC2 capacity-carry break (cond-3)", bad);
    }
    /* REJECT F3-e: break the NEW AC3 capacity carry (AC3.in[5] != AC2.out[5]). */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_AC3_OFF + p2air_input_off(5), 54321);
        expect_reject("AC3 capacity-carry break (F3 cond-3)", bad);
    }
    /* REJECT 36: forge the committed ADDR to a different value (addr_pub mismatch).
     * (Also changes cm, but the cond-3 addr_pub==ADDR binding fires directly.) */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_ADDR_OFF + 0, honest[CONF_ACTION_ADDR_OFF + 0] + 1);
        expect_reject("committed ADDR != Poseidon2(ak,nk)", bad);
    }

    /* REJECT 37 (red-team MF-1): NON-CANONICAL selector bypass. Set IS_INPUT at the
     * φ=0 auth row to p+1 (≡ field-1, so the balance still credits it as an input)
     * AND corrupt ak. A raw `==1` gate would read !=1 and SKIP the spend-auth check
     * → theft with zero key knowledge. The field-value gate (fp/gold_fp_eq) fires
     * on the field-1, so the corrupt ak is caught. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_ISIN_OFF, GOLDILOCKS_P + 1); /* ≡ 1 in the field */
        set(bad, 0, CONF_ACTION_AC1_OFF + p2air_input_off(0), 0xBAD); /* wrong ak */
        expect_reject("MF-1: non-canonical IS_INPUT + wrong ak", bad);
    }
    /* REJECT 38 (MF-1): non-canonical W hiding a block-start to skip note-commit. */
    {
        uint64_t bad[ROWS * CONF_ACTION_WIDTH]; memcpy(bad, honest, sizeof bad);
        set(bad, 0, CONF_ACTION_ISREAL_OFF, GOLDILOCKS_P + 1); /* ≡ 1 field */
        set(bad, 0, CONF_ACTION_CMOUT_OFF + 0, 0xBAD); /* corrupt cm_output */
        expect_reject("MF-1: non-canonical IS_REAL + corrupt cm", bad);
    }

    /* ── F3 per-lane canonical fail-close (D1): generate must reject when ANY
     * single ak/nk lane is ≥ p (the S1f-F1 rule, extended per-lane — a p+x lane
     * would desync the raw cell from the field-reduced poseidon input). ── */
    {
        uint64_t scratch[ROWS * CONF_ACTION_WIDTH];
        int ok = 1;
        for (unsigned lane = 0; lane < CONF_ACTION_NK_LANES; lane++) {
            uint64_t nk_bad[3 * CONF_ACTION_NK_LANES];
            memcpy(nk_bad, nk, sizeof nk_bad);
            nk_bad[lane] = GOLDILOCKS_P; /* block 0, this lane non-canonical */
            if (conf_action_air_generate(LOG_H, value, &addr[0][0], &rcm[0][0],
                                         roles, pos, nk_bad, ak, 3, 0, 0,
                                         scratch))
                ok = 0;
        }
        for (unsigned lane = 0; lane < CONF_ACTION_AK_LANES; lane++) {
            uint64_t ak_bad[3 * CONF_ACTION_AK_LANES];
            memcpy(ak_bad, ak, sizeof ak_bad);
            ak_bad[lane] = GOLDILOCKS_P;
            if (conf_action_air_generate(LOG_H, value, &addr[0][0], &rcm[0][0],
                                         roles, pos, nk, ak_bad, 3, 0, 0,
                                         scratch))
                ok = 0;
        }
        printf("  [accept] F3 per-lane non-canonical ak/nk fail-close (8/8) %s\n",
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }

    /* ── F3 lane-order sanity: derive_addr is injective in lane POSITION — the
     * pinned §3b preimage order means swapping two nk lanes changes the address
     * (an order-insensitive packing would collapse the keyspace). ── */
    {
        uint64_t nk_sw[CONF_ACTION_NK_LANES] = {nk[1], nk[0], nk[2], nk[3]};
        uint64_t a_sw[CONF_ACTION_ADDR_LANES];
        conf_action_derive_addr(&ak[0], nk_sw, a_sw);
        int diff = memcmp(a_sw, eff_addr[0], sizeof a_sw) != 0;
        printf("  [accept] F3 nk lane-swap changes addr (order pinned)   %s\n",
               diff ? "OK" : "FAIL");
        if (!diff) fails++;
    }

    /* ══ LEDGER-V2 S8 Gate 2 — the boundary-bound terminal + the IS_FEE zero-pin
     * The last-row terminal is now BAL == boundary_out − boundary_in
     * (conf_action_air.c:593-595); the historical BAL == 0 is the
     * boundary_in == boundary_out case. generate carries the SAME relation as
     * an honest-prover precondition (conf_action_air.c:149-153) and refuses a
     * CONF_ACTION_ROLE_FEE block outright (conf_action_air.c:118-121, because
     * conf_action_air.c:566 pins IS_FEE ≡ 0). ══ */

    /* S8-1 (matrix 9): a note set whose Σ(sign·value) does NOT equal
     * boundary_out − boundary_in is REJECTED by generate. The SAME note set at
     * a pair that DOES satisfy the terminal is accepted — so the rejection is
     * the RELATION, not a blanket refusal of non-zero boundaries. */
    {
        uint64_t scratch[ROWS * CONF_ACTION_WIDTH];
        /* Σ = +100 − 90 − 10 = 0, so the terminal wants bout − bin == 0. */
        int ok = !conf_action_air_generate(LOG_H, value, &addr[0][0], &rcm[0][0],
                                           roles, pos, nk, ak, 3, 0, 5, scratch);
        ok = ok && !conf_action_air_generate(LOG_H, value, &addr[0][0],
                                             &rcm[0][0], roles, pos, nk, ak, 3,
                                             5, 0, scratch);
        ok = ok && conf_action_air_generate(LOG_H, value, &addr[0][0],
                                            &rcm[0][0], roles, pos, nk, ak, 3,
                                            7, 7, scratch);
        ok = ok && conf_action_air_eval(scratch, ROWS, 7, 7) == 0;
        printf("  [accept] S8 conservation mismatch rejected by generate  %s\n",
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }

    /* S8-2 (matrix 1): the ZERO-INPUT SHIELD shape at the C1 level — no INPUT
     * note, ONE OUTPUT of 100 ⇒ Σ = −100, satisfied EXACTLY at
     * boundary_in = 100, boundary_out = 0 (100 transparent enters the pool).
     * The same trace at any other boundary pair violates the terminal, and
     * generate refuses to build the mismatched pair. */
    {
        uint64_t scratch[ROWS * CONF_ACTION_WIDTH];
        const uint64_t sv[1] = {100};
        const uint8_t sr[1] = {CONF_ACTION_ROLE_OUTPUT};
        const uint64_t sa[1 * CONF_ACTION_ADDR_LANES] = {0xB1, 0xB2, 0xB3, 0xB4};
        const uint64_t sc[1 * CONF_ACTION_RCM_LANES] = {0xC1, 0xC2};
        const uint64_t sp[1] = {0};
        const uint64_t snk[1 * CONF_ACTION_NK_LANES] = {0, 0, 0, 0};
        const uint64_t sak[1 * CONF_ACTION_AK_LANES] = {0, 0, 0, 0};
        int ok = conf_action_air_generate(LOG_H, sv, sa, sc, sr, sp, snk, sak, 1,
                                          100, 0, scratch);
        ok = ok && conf_action_air_eval(scratch, ROWS, 100, 0) == 0;
        ok = ok && conf_action_air_eval(scratch, ROWS, 0, 0) >= 1;
        ok = ok && conf_action_air_eval(scratch, ROWS, 100, 1) >= 1;
        ok = ok && !conf_action_air_generate(LOG_H, sv, sa, sc, sr, sp, snk, sak,
                                             1, 0, 0, scratch);
        printf("  [accept] S8 zero-input SHIELD (bin=100 bout=0) terminal %s\n",
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }

    /* S8-3 (matrix 2 + 3): FOUR outputs and NO notes at all. Four outputs
     * (10+20+30+40) give Σ = −100, so the same bin=100/bout=0 turnstile holds;
     * with NO note the terminal degenerates to boundary_in == boundary_out.
     * H=256 (8 blocks) because E7 needs num_notes + 1 <= H/K and H=128 leaves
     * room for only 3 real notes. */
    {
        const unsigned LOG_H8 = 8u;
        const unsigned ROWS8 = 1u << 8;
        uint64_t scratch[(1u << 8) * CONF_ACTION_WIDTH];
        const uint64_t qv[4] = {10, 20, 30, 40};
        const uint8_t qr[4] = {CONF_ACTION_ROLE_OUTPUT, CONF_ACTION_ROLE_OUTPUT,
                               CONF_ACTION_ROLE_OUTPUT, CONF_ACTION_ROLE_OUTPUT};
        const uint64_t qa[4 * CONF_ACTION_ADDR_LANES] = {
            0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
            0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0};
        const uint64_t qc[4 * CONF_ACTION_RCM_LANES] = {0xE1, 0xE2, 0xE3, 0xE4,
                                                        0xE5, 0xE6, 0xE7, 0xE8};
        const uint64_t qp[4] = {0, 0, 0, 0};
        const uint64_t qnk[4 * CONF_ACTION_NK_LANES] = {0};
        const uint64_t qak[4 * CONF_ACTION_AK_LANES] = {0};
        int ok = conf_action_air_generate(LOG_H8, qv, qa, qc, qr, qp, qnk, qak,
                                          4, 100, 0, scratch);
        ok = ok && conf_action_air_eval(scratch, ROWS8, 100, 0) == 0;
        ok = ok && !conf_action_air_generate(LOG_H8, qv, qa, qc, qr, qp, qnk,
                                             qak, 4, 99, 0, scratch);
        /* zero notes: the terminal forces boundary_in == boundary_out */
        ok = ok && conf_action_air_generate(LOG_H8, NULL, NULL, NULL, NULL, NULL,
                                            NULL, NULL, 0, 9, 9, scratch);
        ok = ok && conf_action_air_eval(scratch, ROWS8, 9, 9) == 0;
        ok = ok && conf_action_air_eval(scratch, ROWS8, 9, 10) >= 1;
        ok = ok && !conf_action_air_generate(LOG_H8, NULL, NULL, NULL, NULL,
                                             NULL, NULL, NULL, 0, 9, 10,
                                             scratch);
        printf("  [accept] S8 zero-input 4-output + zero-note turnstile    %s\n",
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }

    /* S8-4 (matrix 11): a CONF_ACTION_ROLE_FEE note is UNSATISFIABLE — generate
     * returns false rather than emitting a trace the pinned IS_FEE ≡ 0
     * constraint would reject. An unknown role tag fails the same way. */
    {
        uint64_t scratch[ROWS * CONF_ACTION_WIDTH];
        const uint8_t fee_roles[3] = {CONF_ACTION_ROLE_INPUT,
                                      CONF_ACTION_ROLE_OUTPUT,
                                      CONF_ACTION_ROLE_FEE};
        const uint8_t unk_roles[3] = {CONF_ACTION_ROLE_INPUT,
                                      CONF_ACTION_ROLE_OUTPUT, 9};
        int ok = !conf_action_air_generate(LOG_H, value, &addr[0][0], &rcm[0][0],
                                           fee_roles, pos, nk, ak, 3, 0, 0,
                                           scratch);
        ok = ok && !conf_action_air_generate(LOG_H, value, &addr[0][0],
                                             &rcm[0][0], unk_roles, pos, nk, ak,
                                             3, 0, 0, scratch);
        printf("  [accept] S8 ROLE_FEE / unknown role rejected by generate %s\n",
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("C1 complete: %d FAIL\n", fails);
        return 1;
    }
    printf("C1 complete: honest accepted (cm byte-matches S0, BAL=0, addr=H(ak,nk)) + phase-counter,"
           " freeze-carry, note-commitment & balance deviations rejected,"
           " S8 boundary terminal + IS_FEE zero-pin enforced — PASS\n");
    return 0;
}
