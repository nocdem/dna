/**
 * @file test_conf_balance_air.c
 * @brief B1 Stage-1 — conf_balance_air construction gate (is_zk=0).
 *
 * Proves the balance/selector layer soundness BY CONSTRUCTION (the layer the
 * v3.1 re-red-team flagged as build-to-settle):
 *   (accept) an honest trace ⇒ 0 constraint violations;
 *   (reject) every attack from the re-red-team + the SEC-1/SEC-2 boundary ⇒ ≥1
 *            violation. In particular the padding-MINT attack (exclude a
 *            value-bearing row from the balance) is caught by the padding-zero
 *            constraint (1−is_real)·amount==0.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "../conf_balance_air.h"

#define ROWS 8u /* log_height = 3 */

static int fails = 0;

static void expect_reject(const char *name, const uint64_t *bad) {
    int v = conf_balance_air_eval(bad, ROWS);
    if (v >= 1) {
        printf("  [reject] %-38s caught (%d viol) — OK\n", name, v);
    } else {
        printf("  [reject] %-38s NOT caught — FAIL\n", name);
        fails++;
    }
}

int main(void) {
    /* Honest instance: outputs {100,200,300}, fee 50, claimed 650 = 600+50. */
    const uint64_t outputs[3] = {100, 200, 300};
    uint64_t honest[ROWS * CONF_BAL_WIDTH];
    if (!conf_balance_air_generate(outputs, 3, 650, 50, 3, honest)) {
        fprintf(stderr, "FAIL: generate honest trace\n");
        return 1;
    }

    int v = conf_balance_air_eval(honest, ROWS);
    if (v == 0) {
        printf("  [accept] honest trace                          0 viol — OK\n");
    } else {
        printf("  [accept] honest trace                          %d viol — FAIL\n", v);
        fails++;
    }

    uint64_t bad[ROWS * CONF_BAL_WIDTH];
    #define CLONE() memcpy(bad, honest, sizeof(bad))
    #define CELL(r, off) bad[(size_t)(r) * CONF_BAL_WIDTH + (off)]

    /* KAT1 — padding-MINT (the re-red-team core attack): a padding row (row 5)
     * carries value while staying is_real=0. Must be caught by padding-zero. */
    CLONE();
    CELL(5, CONF_BAL_AMOUNT_OFF) = 100; /* padding row, selectors still 0 */
    expect_reject("padding row carries value (MINT)", bad);

    /* KAT2 — selector non-boolean. */
    CLONE();
    CELL(0, CONF_BAL_IS_OUTPUT_OFF) = 2;
    expect_reject("non-boolean selector", bad);

    /* KAT3 — two row-types on one row (is_real=2). */
    CLONE();
    CELL(0, CONF_BAL_IS_CLAIMED_OFF) = 1; /* row 0 already is_output=1 */
    CELL(0, CONF_BAL_IS_REAL_OFF) = 2;
    expect_reject("double row-type (output+claimed)", bad);

    /* KAT4 — claimed free-cell: mutate the claimed amount cell (row 3). */
    CLONE();
    CELL(3, CONF_BAL_AMOUNT_OFF) = 999;
    expect_reject("claimed amount free-cell mutation", bad);

    /* KAT5 — over-range output: set bit[55] on an output row (amount ≥ 2^52). */
    CLONE();
    CELL(1, CONF_BAL_BITS_OFF + 55) = 1;
    expect_reject("output bit[55] set (>2^52)", bad);

    /* KAT6 — balance tamper: mutate the last-row BAL cell. */
    CLONE();
    CELL(ROWS - 1, CONF_BAL_BAL_OFF) = 7;
    expect_reject("last-row balance tampered", bad);

    /* KAT7 — drop the claimed row's is_claimed (n_claimed ≠ 1). */
    CLONE();
    CELL(3, CONF_BAL_IS_CLAIMED_OFF) = 0;
    CELL(3, CONF_BAL_IS_REAL_OFF) = 0;
    expect_reject("claimed row dropped (n_claimed!=1)", bad);

    /* KAT8 — inject a second claimed on a padding row (n_claimed = 2). */
    CLONE();
    CELL(5, CONF_BAL_IS_CLAIMED_OFF) = 1;
    CELL(5, CONF_BAL_IS_REAL_OFF) = 1;
    expect_reject("second claimed injected (n_claimed=2)", bad);

    /* KAT9 — recomposition tamper: flip amount without fixing bits. */
    CLONE();
    CELL(0, CONF_BAL_AMOUNT_OFF) = 101;
    expect_reject("amount vs bit-recomposition mismatch", bad);

    if (fails) {
        printf("conf_balance_air: %d FAIL\n", fails);
        return 1;
    }
    printf("conf_balance_air: honest accepted + 9/9 attacks rejected "
           "(padding-MINT closed by construction) — PASS\n");
    return 0;
}
