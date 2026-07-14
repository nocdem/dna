/**
 * @file test_poseidon2_goldilocks.c
 * @brief Byte-match the C Poseidon2-Goldilocks-8 permutation vs the Plonky3 oracle.
 *
 * Loads tools/vectors/poseidon2_goldilocks.json (produced by
 * `plonky3_oracle dump-poseidon2-goldilocks`, which runs the REAL
 * `default_goldilocks_poseidon2_8().permute(...)` @ 82cfad73) and asserts that
 * poseidon2_goldilocks8_permute reproduces every output element exactly.
 *
 * This is the grounding gate for the FP1.2 port (ANA HEDEF: KAFADAN KRİPTO):
 * the C constants + algorithm are correct iff the output byte-matches the
 * reference permutation on every case.
 *
 * Build (via Makefile):
 *   ./build/test_poseidon2_goldilocks tools/vectors/poseidon2_goldilocks.json
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

#include "../poseidon2_goldilocks.h"

/* Read the whole file into a heap buffer (NUL-terminated). */
static char *slurp(const char *path, size_t *out_len) {
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
    if (out_len) *out_len = rd;
    return buf;
}

/* Find the next occurrence of `key` (a quoted JSON key like "input") starting
 * at *pos; on success advance *pos past it and return true. */
static bool find_key(const char *s, size_t *pos, const char *key) {
    const char *hit = strstr(s + *pos, key);
    if (!hit) return false;
    *pos = (size_t)(hit - s) + strlen(key);
    return true;
}

/* From *pos, expect the next `[` then read exactly 8 quoted decimal u64 values
 * into out[8], advancing *pos past the closing `]`. Returns false on shape err. */
static bool read_u64_array8(const char *s, size_t *pos, uint64_t out[8]) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    for (int i = 0; i < 8; i++) {
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
        fprintf(stderr, "usage: %s <poseidon2_goldilocks.json>\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    char *json = slurp(argv[1], &len);
    if (!json) {
        fprintf(stderr, "FAIL: cannot read %s\n", argv[1]);
        return 2;
    }

    size_t pos = 0;
    int cases = 0, fails = 0;
    while (find_key(json, &pos, "\"input\"")) {
        uint64_t input[8], expect[8], state[8];
        if (!read_u64_array8(json, &pos, input)) {
            fprintf(stderr, "FAIL: malformed input array (case %d)\n", cases);
            fails++;
            break;
        }
        if (!find_key(json, &pos, "\"output\"") ||
            !read_u64_array8(json, &pos, expect)) {
            fprintf(stderr, "FAIL: malformed output array (case %d)\n", cases);
            fails++;
            break;
        }

        memcpy(state, input, sizeof(state));
        poseidon2_goldilocks8_permute(state);

        for (int i = 0; i < 8; i++) {
            if (state[i] != expect[i]) {
                fprintf(stderr,
                        "FAIL case %d lane %d: got %" PRIu64 " expected %" PRIu64
                        "\n",
                        cases, i, state[i], expect[i]);
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
        printf("Poseidon2-Goldilocks-8: %d case(s), %d MISMATCH — FAIL\n", cases,
               fails);
        return 1;
    }
    printf("Poseidon2-Goldilocks-8: %d/%d cases byte-match Plonky3 oracle — PASS\n",
           cases, cases);
    return 0;
}
