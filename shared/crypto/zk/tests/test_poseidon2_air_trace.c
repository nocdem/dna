/**
 * @file test_poseidon2_air_trace.c
 * @brief FP1c.2 — byte-match the C Poseidon2-AIR trace row vs the Plonky3 oracle.
 *
 * Loads tools/vectors/poseidon2_air_trace.json (REAL p3_poseidon2_air::
 * generate_trace_rows over Poseidon2Cols<8,7,1,4,22> @ 82cfad73). For each case:
 *   (1) poseidon2_air_generate_row(input) must reproduce all 180 columns exactly;
 *   (2) the final ending-round post columns must equal
 *       poseidon2_goldilocks8_permute(input) — cross-check of the two modules.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../poseidon2_air_cols.h"
#include "../poseidon2_air_trace.h"
#include "../poseidon2_goldilocks.h"

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    return buf;
}

static bool find_key(const char *s, size_t *pos, const char *key) {
    const char *hit = strstr(s + *pos, key);
    if (!hit) return false;
    *pos = (size_t)(hit - s) + strlen(key);
    return true;
}

/* From *pos, expect the next `[` then read exactly n quoted decimal u64 values,
 * advancing *pos past the closing `]`. */
static bool read_u64_array(const char *s, size_t *pos, uint64_t *out, size_t n) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    for (size_t i = 0; i < n; i++) {
        const char *q = strchr(s + p, '"');
        if (!q) return false;
        p = (size_t)(q - s) + 1;
        out[i] = strtoull(s + p, NULL, 10);
        const char *qe = strchr(s + p, '"');
        if (!qe) return false;
        p = (size_t)(qe - s) + 1;
    }
    const char *rb = strchr(s + p, ']');
    if (!rb) return false;
    *pos = (size_t)(rb - s) + 1;
    return true;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <poseidon2_air_trace.json>\n", argv[0]);
        return 2;
    }
    char *json = slurp(argv[1]);
    if (!json) {
        fprintf(stderr, "FAIL: cannot read %s\n", argv[1]);
        return 2;
    }

    size_t pos = 0;
    int cases = 0, fails = 0;
    while (find_key(json, &pos, "\"input\"")) {
        uint64_t input[P2AIR_WIDTH];
        uint64_t expect[P2AIR_NUM_COLS];
        uint64_t row[P2AIR_NUM_COLS];

        if (!read_u64_array(json, &pos, input, P2AIR_WIDTH)) {
            fprintf(stderr, "FAIL: bad input array (case %d)\n", cases);
            fails++;
            break;
        }
        if (!find_key(json, &pos, "\"row\"") ||
            !read_u64_array(json, &pos, expect, P2AIR_NUM_COLS)) {
            fprintf(stderr, "FAIL: bad row array (case %d)\n", cases);
            fails++;
            break;
        }

        poseidon2_air_generate_row(input, row);

        for (size_t c = 0; c < P2AIR_NUM_COLS; c++) {
            if (row[c] != expect[c]) {
                fprintf(stderr,
                        "FAIL case %d col %zu: got %" PRIu64 " expected %" PRIu64
                        "\n",
                        cases, c, row[c], expect[c]);
                fails++;
            }
        }

        /* Cross-check: final ending-round post == permutation output. */
        uint64_t perm[P2AIR_WIDTH];
        memcpy(perm, input, sizeof(perm));
        poseidon2_goldilocks8_permute(perm);
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            size_t off = p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, i);
            if (row[off] != perm[i]) {
                fprintf(stderr,
                        "FAIL case %d: final post[%zu]=%" PRIu64
                        " != permute[%zu]=%" PRIu64 "\n",
                        cases, i, row[off], i, perm[i]);
                fails++;
            }
        }
        cases++;
    }

    free(json);

    if (cases == 0) {
        fprintf(stderr, "FAIL: no cases parsed\n");
        return 1;
    }
    if (fails) {
        printf("Poseidon2-AIR trace: %d case(s), %d MISMATCH — FAIL\n", cases, fails);
        return 1;
    }
    printf("Poseidon2-AIR trace: %d/%d cases byte-match Plonky3 generate_trace_rows "
           "(+ final post == permute) — PASS\n",
           cases, cases);
    return 0;
}
