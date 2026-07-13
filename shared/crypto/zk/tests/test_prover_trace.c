/**
 * @file test_prover_trace.c
 * @brief S1 (C prover) — witness-trace builder byte-match KAT.
 *
 * Loads tools/vectors/prover_trace_range_zk.json (oracle
 * `generate_range_proof_trace` output for the M3a instance, the exact matrix
 * handed to p3_uni_stark::prove @ 82cfad73) and asserts
 * dnac_prover_build_range_proof_trace reproduces every cell byte-for-byte,
 * plus the returned total and the public-values relation claimed == total+fee.
 *
 * Also checks the padding-row semantics (oracle main.rs:10208-10228: bits/
 * amount/is_real zero, acc/cnt flat) on a height-8 build, and the fail-close
 * guards (power-of-two height, height bound, n_real bounds, amount range).
 *
 * Build (via Makefile):
 *   make build/test_prover_trace
 *   ./build/test_prover_trace tools/vectors/prover_trace_range_zk.json
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

#include "../stark_prover.h"

/* Compile-time layout binding (C99 negative-array trick): reopening any of
 * these constants breaks the build, not just the test run. */
typedef char sp_assert_width[(STARK_PROVER_RANGE_PROOF_WIDTH == 56) ? 1 : -1];
typedef char sp_assert_is_real[(STARK_PROVER_IS_REAL_OFF == 54) ? 1 : -1];
typedef char sp_assert_cnt[(STARK_PROVER_CNT_OFF == 55) ? 1 : -1];
typedef char sp_assert_max_h[(STARK_PROVER_MAX_HEIGHT == 1024) ? 1 : -1];

#define M3A_HEIGHT 4u
#define M3A_WIDTH 56u
#define M3A_CELLS (M3A_HEIGHT * M3A_WIDTH)

/* ---------- minimal helpers over the flat vector JSON ---------- */

static char *load_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(buf);
        return NULL;
    }
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

/* Position just after `"key":` (keys are unique in this vector). */
static const char *find_value(const char *src, const char *key) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(src, needle);
    if (!p) {
        /* serde_json pretty prints `"key": value` — try with the space. */
        snprintf(needle, sizeof(needle), "\"%s\" :", key);
        p = strstr(src, needle);
        if (!p) return NULL;
    }
    return p + strlen(needle);
}

/* Read a bare or quoted decimal u64 at/after p. */
static bool read_u64(const char *p, uint64_t *out) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '"') p++;
    if (*p < '0' || *p > '9') return false;
    *out = strtoull(p, NULL, 10);
    return true;
}

static bool parse_u64_field(const char *src, const char *key, uint64_t *out) {
    const char *p = find_value(src, key);
    return p != NULL && read_u64(p, out);
}

/* Parse `"key": [ "123", "456", ... ]` into out[0..expect). */
static bool parse_u64_array(const char *src, const char *key, uint64_t *out,
                            size_t expect) {
    const char *p = find_value(src, key);
    if (!p) return false;
    while (*p && *p != '[') p++;
    if (*p != '[') return false;
    p++;
    for (size_t i = 0; i < expect; i++) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')
            p++;
        if (*p != '"') return false;
        p++;
        if (*p < '0' || *p > '9') return false;
        out[i] = strtoull(p, (char **)&p, 10);
        if (*p != '"') return false;
        p++;
    }
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return *p == ']';
}

int main(int argc, char **argv) {
    const char *path = "tools/vectors/prover_trace_range_zk.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) return 2;
    printf("loaded %s (%zu bytes)\n", path, len);

    int failed = 0;

    /* ---- T1: header fields pin the M3a shape ---- */
    uint64_t width = 0, height = 0, n_real = 0, fee = 0, claimed = 0,
             total_vec = 0;
    if (!parse_u64_field(src, "width", &width) ||
        !parse_u64_field(src, "height", &height) ||
        !parse_u64_field(src, "n_real", &n_real) ||
        !parse_u64_field(src, "fee", &fee) ||
        !parse_u64_field(src, "claimed", &claimed) ||
        !parse_u64_field(src, "total", &total_vec)) {
        fprintf(stderr, "T1 FAIL: missing header field\n");
        free(src);
        return 2;
    }
    if (width != M3A_WIDTH || height != M3A_HEIGHT || n_real != M3A_HEIGHT) {
        fprintf(stderr, "T1 FAIL: shape %" PRIu64 "x%" PRIu64 " n_real=%" PRIu64
                        " (want 4x56 n_real=4)\n", height, width, n_real);
        failed++;
    }

    static uint64_t amounts[M3A_HEIGHT];
    static uint64_t publics[3];
    static uint64_t trace_vec[M3A_CELLS];
    if (!parse_u64_array(src, "amounts", amounts, M3A_HEIGHT) ||
        !parse_u64_array(src, "public_values", publics, 3) ||
        !parse_u64_array(src, "trace", trace_vec, M3A_CELLS)) {
        fprintf(stderr, "T1 FAIL: array parse (amounts/public_values/trace)\n");
        free(src);
        return 2;
    }
    printf("T1 header: 4x56, n_real=4, fee=%" PRIu64 ", claimed=%" PRIu64
           ", total=%" PRIu64 "%s\n",
           fee, claimed, total_vec, failed ? "  FAIL" : "  PASS");

    /* ---- T2: byte-match KAT — C builder vs oracle trace ---- */
    static uint64_t trace_c[M3A_CELLS];
    uint64_t total_c = 0;
    dnac_prover_status_t st = dnac_prover_build_range_proof_trace(
        amounts, (size_t)n_real, (size_t)height, trace_c, &total_c);
    int cell_mismatch = 0;
    if (st != DNAC_PROVER_OK) {
        fprintf(stderr, "T2 FAIL: builder status %d (want OK)\n", (int)st);
        failed++;
    } else {
        for (size_t i = 0; i < M3A_CELLS; i++) {
            if (trace_c[i] != trace_vec[i]) {
                if (cell_mismatch < 5) {
                    fprintf(stderr,
                            "T2 cell MISMATCH row=%zu col=%zu: C=%" PRIu64
                            " oracle=%" PRIu64 "\n",
                            i / M3A_WIDTH, i % M3A_WIDTH, trace_c[i],
                            trace_vec[i]);
                }
                cell_mismatch++;
            }
        }
        if (cell_mismatch) failed++;
        if (total_c != total_vec) {
            fprintf(stderr, "T2 FAIL: total C=%" PRIu64 " oracle=%" PRIu64 "\n",
                    total_c, total_vec);
            failed++;
        }
        if (claimed != total_vec + fee) {
            fprintf(stderr, "T2 FAIL: claimed != total + fee\n");
            failed++;
        }
        if (publics[0] != claimed || publics[1] != fee || publics[2] != n_real) {
            fprintf(stderr, "T2 FAIL: public_values order != [claimed,fee,n_real]\n");
            failed++;
        }
    }
    printf("T2 byte-match: %u/%u cells, total, claimed==total+fee, publics order"
           "  %s\n",
           (unsigned)(M3A_CELLS - (unsigned)cell_mismatch), (unsigned)M3A_CELLS,
           (st == DNAC_PROVER_OK && !cell_mismatch) ? "PASS" : "FAIL");

    /* ---- T3: padding semantics (height 8, same 4 real rows) ----
     * Oracle main.rs:10208-10228: padding rows carry bits=amount=is_real=0,
     * acc and cnt flat at the last real row's values. */
    {
        static uint64_t t8[8 * M3A_WIDTH];
        uint64_t tot8 = 0;
        int bad = 0;
        if (dnac_prover_build_range_proof_trace(amounts, 4, 8, t8, &tot8) !=
                DNAC_PROVER_OK ||
            tot8 != total_vec) {
            bad++;
        } else {
            /* Real-row region must equal the height-4 KAT trace. */
            if (memcmp(t8, trace_vec, sizeof(trace_vec)) != 0) bad++;
            for (size_t r = 4; r < 8 && !bad; r++) {
                const uint64_t *cells = &t8[r * M3A_WIDTH];
                for (size_t c = 0; c <= RANGE_AIR_AMOUNT_OFF; c++) {
                    if (cells[c] != 0) bad++;
                }
                if (cells[SUM_BALANCE_ACC_OFF] != total_vec) bad++;
                if (cells[STARK_PROVER_IS_REAL_OFF] != 0) bad++;
                if (cells[STARK_PROVER_CNT_OFF] != n_real) bad++;
            }
        }
        if (bad) failed++;
        printf("T3 padding rows (h=8): bits/amount/is_real=0, acc/cnt flat  %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T4: fail-close guards ---- */
    {
        static uint64_t tmp[8 * M3A_WIDTH];
        uint64_t big[1] = { UINT64_C(1) << RANGE_AIR_BITS }; /* == 2^52 */
        int bad = 0;
        if (dnac_prover_build_range_proof_trace(NULL, 4, 4, tmp, NULL) !=
            DNAC_PROVER_ERR_PARAM) bad++;
        if (dnac_prover_build_range_proof_trace(amounts, 4, 4, NULL, NULL) !=
            DNAC_PROVER_ERR_PARAM) bad++;
        if (dnac_prover_build_range_proof_trace(amounts, 0, 4, tmp, NULL) !=
            DNAC_PROVER_ERR_PARAM) bad++;
        if (dnac_prover_build_range_proof_trace(amounts, 5, 4, tmp, NULL) !=
            DNAC_PROVER_ERR_PARAM) bad++;
        if (dnac_prover_build_range_proof_trace(amounts, 4, 0, tmp, NULL) !=
            DNAC_PROVER_ERR_PARAM) bad++;
        if (dnac_prover_build_range_proof_trace(amounts, 3, 3, tmp, NULL) !=
            DNAC_PROVER_ERR_PARAM) bad++; /* non-power-of-two height */
        if (dnac_prover_build_range_proof_trace(amounts, 4, 2048, tmp, NULL) !=
            DNAC_PROVER_ERR_PARAM) bad++; /* > MAX_HEIGHT */
        if (dnac_prover_build_range_proof_trace(big, 1, 4, tmp, NULL) !=
            DNAC_PROVER_ERR_RANGE) bad++; /* amount == 2^52 */
        if (bad) failed++;
        printf("T4 fail-close guards: 8/8 rejects  %s\n", bad ? "FAIL" : "PASS");
    }

    free(src);
    if (failed == 0) {
        printf("test_prover_trace: PASS\n");
        printf("S1 PROVER-TRACE GATE: GREEN — C trace byte-matches "
               "generate_range_proof_trace (oracle, Plonky3 82cfad73 prove input); "
               "padding + fail-close guards held\n");
        return 0;
    }
    printf("S1 PROVER-TRACE GATE: RED — %d failures\n", failed);
    return 1;
}
