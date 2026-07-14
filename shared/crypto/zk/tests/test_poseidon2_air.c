/**
 * @file test_poseidon2_air.c
 * @brief FP1c.3 — Poseidon2-AIR constraint evaluation grounding.
 *
 * Loads the REAL Plonky3 trace rows (tools/vectors/poseidon2_air_trace.json,
 * from generate_trace_rows @ 82cfad73) and asserts:
 *   (accept) poseidon2_air_eval_row(valid row) == 0 violations — a valid
 *            Plonky3 witness satisfies the ported constraints exactly;
 *   (reject) tampering EACH of the 180 columns (+1 mod p) yields ≥1 violation —
 *            every column is constrained (the constraints have teeth).
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

#include "../poseidon2_air.h"
#include "../poseidon2_air_cols.h"

/* p = 2^64 - 2^32 + 1 */
#define GOLD_P ((uint64_t)0xFFFFFFFF00000001ULL)

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
    long accept_ok = 0, tamper_caught = 0, tamper_total = 0;

    while (find_key(json, &pos, "\"row\"")) {
        uint64_t row[P2AIR_NUM_COLS];
        if (!read_u64_array(json, &pos, row, P2AIR_NUM_COLS)) {
            fprintf(stderr, "FAIL: bad row (case %d)\n", cases);
            fails++;
            break;
        }

        /* (accept) real valid trace → 0 violations. */
        int v = poseidon2_air_eval_row(row);
        if (v != 0) {
            fprintf(stderr, "FAIL case %d: valid row has %d violation(s)\n", cases, v);
            fails++;
        } else {
            accept_ok++;
        }

        /* (reject) tamper each column by +1 mod p → must be caught. */
        for (size_t c = 0; c < P2AIR_NUM_COLS; c++) {
            uint64_t orig = row[c];
            row[c] = (orig + 1) % GOLD_P;
            tamper_total++;
            if (poseidon2_air_eval_row(row) >= 1) {
                tamper_caught++;
            } else {
                fprintf(stderr,
                        "FAIL case %d: tampering col %zu was NOT caught\n", cases, c);
                fails++;
            }
            row[c] = orig; /* restore */
        }
        cases++;
    }

    free(json);

    if (cases == 0) {
        fprintf(stderr, "FAIL: no cases parsed\n");
        return 1;
    }
    if (fails) {
        printf("Poseidon2-AIR eval: %d case(s) — %d FAIL\n", cases, fails);
        return 1;
    }
    printf("Poseidon2-AIR eval: %d/%d valid rows accepted (0 viol), "
           "%ld/%ld single-col tampers caught — PASS\n",
           (int)accept_ok, cases, tamper_caught, tamper_total);
    return 0;
}
