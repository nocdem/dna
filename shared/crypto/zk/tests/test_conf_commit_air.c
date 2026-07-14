/**
 * @file test_conf_commit_air.c
 * @brief B1 Stage-1 increment 2 — VC composition construction gate (is_zk=0).
 *
 * Proves the SEC-2 amount↔commitment binding BY CONSTRUCTION:
 *   (accept) honest combined trace ⇒ 0 violations, and c_i == the real Poseidon2
 *            commitment of [amount, blind, DOMSEP, hash_id];
 *   (reject) commit-X-but-range/balance-Y, wrong capacity IV / hash_id, tampered
 *            VC block, pad-cell grind — every one ⇒ ≥1 violation.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "../conf_commit_air.h"
#include "../poseidon2_air_cols.h"
#include "../poseidon2_air_trace.h"
#include "../poseidon2_goldilocks.h"

#define ROWS 8u /* log_height = 3 */

static int fails = 0;

static void expect_reject(const char *name, const uint64_t *bad) {
    int v = conf_commit_air_eval(bad, ROWS);
    if (v >= 1) printf("  [reject] %-40s caught (%d viol) — OK\n", name, v);
    else { printf("  [reject] %-40s NOT caught — FAIL\n", name); fails++; }
}

int main(void) {
    const uint64_t outputs[3] = {100, 200, 300};
    uint64_t blind[2 * ROWS];
    for (unsigned i = 0; i < 2 * ROWS; i++) blind[i] = 0x1000 + i; /* deterministic */

    uint64_t honest[ROWS * CONF_COMMIT_WIDTH];
    if (!conf_commit_air_generate(outputs, 3, 650, 50, blind, 3, honest)) {
        fprintf(stderr, "FAIL: generate honest trace\n");
        return 1;
    }

    int v = conf_commit_air_eval(honest, ROWS);
    if (v == 0) printf("  [accept] honest combined trace                 0 viol — OK\n");
    else { printf("  [accept] honest combined trace                 %d viol — FAIL\n", v); fails++; }

    /* Cross-check: c_0 == real Poseidon2 permutation of row 0's VC input. */
    {
        uint64_t in[8] = {100, blind[0], blind[1], 0, CONF_COMMIT_DOMSEP_VAL,
                          CONF_COMMIT_HASH_ID, 0, 0};
        poseidon2_goldilocks8_permute(in);
        uint64_t c0[CONF_COMMIT_C_LANES];
        conf_commit_air_get_commitment(honest, 0, c0);
        int ok = 1;
        for (int j = 0; j < CONF_COMMIT_C_LANES; j++) if (c0[j] != in[j]) ok = 0;
        if (ok) printf("  [check ] c_0 == Poseidon2(amount,blind,IV)      match — OK\n");
        else { printf("  [check ] c_0 mismatch — FAIL\n"); fails++; }
    }

    uint64_t bad[ROWS * CONF_COMMIT_WIDTH];
    #define CLONE() memcpy(bad, honest, sizeof(bad))
    #define VC(r, off) bad[(size_t)(r) * CONF_COMMIT_WIDTH + CONF_COMMIT_VC_OFF + (off)]
    #define BALCELL(r, off) bad[(size_t)(r) * CONF_COMMIT_WIDTH + CONF_COMMIT_BAL_OFF + (off)]

    /* KAT-A (SEC-2 CORE): commit a DIFFERENT amount than range/balance. Regenerate
     * row 0's VC block from a tampered amount (999) while the balance cell stays 100
     * ⇒ same-window copy VC.inputs[0]=999 != amount=100 rejects. */
    CLONE();
    {
        uint64_t in[8] = {999, blind[0], blind[1], 0, CONF_COMMIT_DOMSEP_VAL,
                          CONF_COMMIT_HASH_ID, 0, 0};
        poseidon2_air_generate_row(in, &VC(0, 0));
    }
    expect_reject("SEC-2: commit X != range/balance Y", bad);

    /* KAT-B: wrong capacity IV. */
    CLONE();
    VC(0, p2air_input_off(4)) = 12345;
    expect_reject("wrong capacity IV (DOMSEP)", bad);

    /* KAT-C: tamper a VC block interior column (a sbox cell). */
    CLONE();
    VC(1, p2air_beg_sbox_off(0, 0)) ^= 1;
    expect_reject("tampered VC Poseidon2 block", bad);

    /* KAT-D: pad cell VC.inputs[3] != 0. */
    CLONE();
    VC(0, p2air_input_off(3)) = 5;
    expect_reject("VC pad cell inputs[3] != 0", bad);

    /* KAT-E: wrong hash_id. */
    CLONE();
    VC(2, p2air_input_off(5)) = 2;
    expect_reject("wrong hash_id dispatch", bad);

    /* KAT-F: mutate the balance amount cell only (VC still commits old amount) ⇒
     * copy + balance recomposition both reject. */
    CLONE();
    BALCELL(0, CONF_BAL_AMOUNT_OFF) = 101;
    expect_reject("balance amount != committed amount", bad);

    /* KAT-G: the balance-layer padding-MINT still caught through composition. */
    CLONE();
    BALCELL(5, CONF_BAL_AMOUNT_OFF) = 100; /* padding row carries value */
    expect_reject("padding-MINT (via composition)", bad);

    if (fails) { printf("conf_commit_air: %d FAIL\n", fails); return 1; }
    printf("conf_commit_air: honest accepted + c-check + 7/7 attacks rejected "
           "(SEC-2 amount==commitment CONSTRUCTED) — PASS\n");
    return 0;
}
