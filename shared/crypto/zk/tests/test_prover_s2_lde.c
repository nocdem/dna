/**
 * @file test_prover_s2_lde.c
 * @brief S2 (C prover) — is_zk randomization + coset LDE byte-match KAT.
 *
 * Loads tools/vectors/prover_s2_lde_zk.json (oracle-gated: G1 real is_zk=1
 * prove+verify, G2 recomputed LDE == committed LDE, G3 standalone commit root
 * == proof trace root, G4 base+draws reshape == with_random_cols output) and
 * asserts:
 *
 *   T1  S1 tie-in: C trace builder reproduces base_trace.
 *   T2  dnac_prover_randomize_trace(base, draws) == randomized_matrix
 *       (hiding_pcs.rs:110-129 interleave layout, SmallRng(1) draws as input).
 *   T3  dnac_prover_coset_lde_bitrev(randomized, 2, 7) == lde_bitrev — the
 *       EXACT committed matrix inside the real Plonky3 prove (32x60).
 *   T4  fail-close guards (non-canonical draw, bad dims/shift).
 *
 * Build (via Makefile):
 *   make build/test_prover_s2_lde
 *   ./build/test_prover_s2_lde tools/vectors/prover_s2_lde_zk.json
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

#include "../field_goldilocks.h"
#include "../stark_prover.h"

#define S2_H 4u
#define S2_W 56u
#define S2_R 4u
#define S2_RAND_W 60u          /* W + R */
#define S2_DRAWS (S2_H * (S2_W + 2u * S2_R)) /* 256 */
#define S2_LDE_H 32u
#define S2_BASE_CELLS (S2_H * S2_W)
#define S2_RANDOMIZED_CELLS (2u * S2_H * S2_RAND_W)
#define S2_LDE_CELLS (S2_LDE_H * S2_RAND_W)

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

static const char *find_value(const char *src, const char *key) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(src, needle);
    if (!p) return NULL;
    return p + strlen(needle);
}

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

static int compare_cells(const char *tag, const uint64_t *got,
                         const uint64_t *want, size_t n, size_t width) {
    int mism = 0;
    for (size_t i = 0; i < n; i++) {
        if (got[i] != want[i]) {
            if (mism < 3) {
                fprintf(stderr, "%s MISMATCH row=%zu col=%zu: C=%" PRIu64
                                " oracle=%" PRIu64 "\n",
                        tag, i / width, i % width, got[i], want[i]);
            }
            mism++;
        }
    }
    return mism;
}

int main(int argc, char **argv) {
    const char *path = "tools/vectors/prover_s2_lde_zk.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) return 2;
    printf("loaded %s (%zu bytes)\n", path, len);

    int failed = 0;

    /* params pin */
    uint64_t width = 0, num_random = 0, rand_width = 0, log_blowup = 0,
             degree = 0, ext_degree = 0, lde_height = 0, shift = 0;
    if (!parse_u64_field(src, "width", &width) ||
        !parse_u64_field(src, "num_random_codewords", &num_random) ||
        !parse_u64_field(src, "rand_width", &rand_width) ||
        !parse_u64_field(src, "log_blowup", &log_blowup) ||
        !parse_u64_field(src, "degree", &degree) ||
        !parse_u64_field(src, "ext_degree", &ext_degree) ||
        !parse_u64_field(src, "lde_height", &lde_height) ||
        !parse_u64_field(src, "shift", &shift)) {
        fprintf(stderr, "params parse FAIL\n");
        free(src);
        return 2;
    }
    if (width != S2_W || num_random != S2_R || rand_width != S2_RAND_W ||
        log_blowup != 2 || degree != S2_H || ext_degree != 2 * S2_H ||
        lde_height != S2_LDE_H || shift != 7) {
        fprintf(stderr, "params pin FAIL (unexpected M3a S2 shape)\n");
        free(src);
        return 2;
    }

    static uint64_t base_vec[S2_BASE_CELLS];
    static uint64_t draws[S2_DRAWS];
    static uint64_t randomized_vec[S2_RANDOMIZED_CELLS];
    static uint64_t lde_vec[S2_LDE_CELLS];
    if (!parse_u64_array(src, "base_trace", base_vec, S2_BASE_CELLS) ||
        !parse_u64_array(src, "random_draws", draws, S2_DRAWS) ||
        !parse_u64_array(src, "randomized_matrix", randomized_vec,
                         S2_RANDOMIZED_CELLS) ||
        !parse_u64_array(src, "lde_bitrev", lde_vec, S2_LDE_CELLS)) {
        fprintf(stderr, "array parse FAIL\n");
        free(src);
        return 2;
    }

    /* ---- T1: S1 tie-in — C trace builder reproduces base_trace ---- */
    {
        static uint64_t base_c[S2_BASE_CELLS];
        const uint64_t amounts[4] = {10, 20, 30, 40};
        int mism = 1;
        if (dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) ==
            DNAC_PROVER_OK) {
            mism = compare_cells("T1", base_c, base_vec, S2_BASE_CELLS, S2_W);
        }
        if (mism) failed++;
        printf("T1 S1 tie-in (base trace 4x56)                          %s\n",
               mism ? "FAIL" : "PASS");
    }

    /* ---- T2: randomize == oracle randomized_matrix ---- */
    static uint64_t randomized_c[S2_RANDOMIZED_CELLS];
    {
        int mism = 1;
        dnac_prover_status_t st = dnac_prover_randomize_trace(
            base_vec, S2_H, S2_W, S2_R, draws, randomized_c);
        if (st == DNAC_PROVER_OK) {
            mism = compare_cells("T2", randomized_c, randomized_vec,
                                 S2_RANDOMIZED_CELLS, S2_RAND_W);
        } else {
            fprintf(stderr, "T2 status %d\n", (int)st);
        }
        if (mism) failed++;
        printf("T2 randomize interleave (8x60, %u draws)               %s\n",
               (unsigned)S2_DRAWS, mism ? "FAIL" : "PASS");
    }

    /* ---- T3: coset LDE + bit-rev == the REAL committed matrix ---- */
    {
        static uint64_t lde_c[S2_LDE_CELLS];
        int mism = 1;
        dnac_prover_status_t st = dnac_prover_coset_lde_bitrev(
            randomized_c, 2 * S2_H, S2_RAND_W, 2, 7, lde_c);
        if (st == DNAC_PROVER_OK) {
            mism = compare_cells("T3", lde_c, lde_vec, S2_LDE_CELLS, S2_RAND_W);
        } else {
            fprintf(stderr, "T3 status %d\n", (int)st);
        }
        if (mism) failed++;
        printf("T3 coset LDE (blowup 4x, shift 7) + bit-rev rows (32x60) %s\n",
               mism ? "FAIL" : "PASS");
    }

    /* ---- T4: fail-close guards ---- */
    {
        static uint64_t tmp[S2_RANDOMIZED_CELLS];
        static uint64_t tmp_lde[S2_LDE_CELLS];
        static uint64_t bad_draws[S2_DRAWS];
        int bad = 0;
        memcpy(bad_draws, draws, sizeof(bad_draws));
        bad_draws[100] = GOLDILOCKS_P; /* non-canonical */
        if (dnac_prover_randomize_trace(base_vec, S2_H, S2_W, S2_R, bad_draws,
                                        tmp) != DNAC_PROVER_ERR_NONCANONICAL)
            bad++;
        if (dnac_prover_randomize_trace(base_vec, 0, S2_W, S2_R, draws, tmp) !=
            DNAC_PROVER_ERR_PARAM)
            bad++;
        if (dnac_prover_randomize_trace(base_vec, S2_H, S2_W, 0, draws, tmp) !=
            DNAC_PROVER_ERR_PARAM)
            bad++;
        if (dnac_prover_coset_lde_bitrev(randomized_c, 6, S2_RAND_W, 2, 7,
                                         tmp_lde) != DNAC_PROVER_ERR_PARAM)
            bad++; /* non-power-of-two height */
        if (dnac_prover_coset_lde_bitrev(randomized_c, 2 * S2_H, S2_RAND_W, 0,
                                         7, tmp_lde) != DNAC_PROVER_ERR_PARAM)
            bad++; /* log_blowup 0 */
        if (dnac_prover_coset_lde_bitrev(randomized_c, 2 * S2_H, S2_RAND_W, 2,
                                         GOLDILOCKS_P, tmp_lde) !=
            DNAC_PROVER_ERR_PARAM)
            bad++; /* non-canonical shift */
        if (bad) failed++;
        printf("T4 fail-close guards: 6/6 rejects                        %s\n",
               bad ? "FAIL" : "PASS");
    }

    free(src);
    if (failed == 0) {
        printf("test_prover_s2_lde: PASS\n");
        printf("S2 PROVER-LDE GATE: GREEN — C randomize+LDE byte-match the REAL "
               "committed trace matrix (HidingFriPcs commit, Plonky3 82cfad73; "
               "oracle gates G1-G4 held)\n");
        return 0;
    }
    printf("S2 PROVER-LDE GATE: RED — %d failures\n", failed);
    return 1;
}
