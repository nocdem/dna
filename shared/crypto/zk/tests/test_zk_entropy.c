/**
 * @file test_zk_entropy.c
 * @brief G2 — production draw-stream filler, STRUCTURAL checks only.
 *
 * dnac_zk_fill_draws reads OS entropy, so its OUTPUT VALUES are
 * non-deterministic by design (prover-side hiding randomness; never in
 * consensus). Per the no-flaky rule, every assertion here is
 * VALUE-INDEPENDENT: canonicality, count, error paths. No gate depends on
 * which random values arrive.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "zk_entropy.h"

int main(void) {
    int fails = 0;

    /* T1: n=0 is a no-op success (NULL out allowed). */
    if (dnac_zk_fill_draws(NULL, 0) != 0) {
        printf("  T1 n=0 no-op                                   FAIL\n");
        fails++;
    } else {
        printf("  T1 n=0 no-op                                   PASS\n");
    }

    /* T2: NULL out with n>0 fails closed. */
    if (dnac_zk_fill_draws(NULL, 8) != -1) {
        printf("  T2 NULL out fail-close                         FAIL\n");
        fails++;
    } else {
        printf("  T2 NULL out fail-close                         PASS\n");
    }

    /* T3: 4096 draws — every value canonical (< p), buffer fully written.
     * Canary prefill with p (non-canonical) proves each slot was overwritten. */
    enum { N = 4096 };
    uint64_t *buf = (uint64_t *)malloc(N * sizeof(uint64_t));
    if (!buf) return 2;
    for (size_t i = 0; i < N; i++) buf[i] = GOLDILOCKS_P; /* canary */
    int ok = dnac_zk_fill_draws(buf, N) == 0;
    for (size_t i = 0; ok && i < N; i++) {
        if (buf[i] >= GOLDILOCKS_P) ok = 0; /* canonical AND overwritten */
    }
    printf("  T3 4096 draws all canonical + fully written        %s\n",
           ok ? "PASS" : "FAIL");
    if (!ok) fails++;

    /* T4: two independent fills differ somewhere (identical 32-KB entropy
     * streams have probability ~2^-262144 — deterministic in practice; a
     * failure here means the entropy source is returning a constant). */
    uint64_t *buf2 = (uint64_t *)malloc(N * sizeof(uint64_t));
    if (!buf2) return 2;
    ok = dnac_zk_fill_draws(buf2, N) == 0 &&
         memcmp(buf, buf2, N * sizeof(uint64_t)) != 0;
    printf("  T4 two fills differ (entropy source is live)       %s\n",
           ok ? "PASS" : "FAIL");
    if (!ok) fails++;

    free(buf);
    free(buf2);
    if (fails) {
        printf("test_zk_entropy: FAIL (%d)\n", fails);
        return 1;
    }
    printf("test_zk_entropy: PASS\n");
    printf("  production CSPRNG fill: rejection-sampled canonical Goldilocks from\n");
    printf("  getrandom(2) with /dev/urandom fallback; fail-close; prover-side only (G2).\n");
    return 0;
}
