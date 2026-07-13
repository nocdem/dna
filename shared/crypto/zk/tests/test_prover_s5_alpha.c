/**
 * @file test_prover_s5_alpha.c
 * @brief S5 (C prover) — Fiat-Shamir-to-alpha byte-match KAT.
 *
 * Two vectors:
 *   - tools/vectors/prover_s2_lde_zk.json  — SmallRng(1) draws (D1-B input)
 *     to rebuild the trace commitment via the C chain S1->S2->S3.
 *   - tools/vectors/range_proof_air_zk.json — the REAL is_zk=1 M3a proof
 *     vector: trace_commit_root_hex + challenges.stark_alpha_fp2 sampled by
 *     the REAL p3_uni_stark::prove/verify transcript.
 *
 * Asserts:
 *   T1  C chain root == the M3a vector's trace_commit_root_hex (cross-vector
 *       tie: the S2 KAT instance IS the M3a proof instance).
 *   T2  dnac_prover_fs_to_alpha on a fresh default transcript reproduces the
 *       REAL alpha (c0, c1) — the prover-side transcript drive is
 *       byte-identical to Plonky3's challenger up to the first sample.
 *   T3  fail-close guards.
 *
 * Build (via Makefile):
 *   make build/test_prover_s5_alpha
 *   ./build/test_prover_s5_alpha tools/vectors/prover_s2_lde_zk.json \
 *                                tools/vectors/range_proof_air_zk.json
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

#define S5_H 4u
#define S5_W 56u
#define S5_R 4u
#define S5_RAND_W 60u
#define S5_DRAWS (S5_H * (S5_W + 2u * S5_R))
#define S5_LDE_H 32u
#define S5_LDE_CELLS (S5_LDE_H * S5_RAND_W)

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

static bool read_u64_at(const char *p, uint64_t *out) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '"') p++;
    if (*p < '0' || *p > '9') return false;
    *out = strtoull(p, NULL, 10);
    return true;
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
    return true;
}

static bool parse_hex_bytes_at(const char *p, uint8_t *out,
                               size_t expect_bytes) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return false;
    p++;
    for (size_t i = 0; i < expect_bytes; i++) {
        unsigned hi, lo;
        if (sscanf(p, "%1x%1x", &hi, &lo) != 2) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    return *p == '"';
}

int main(int argc, char **argv) {
    const char *s2_path = "tools/vectors/prover_s2_lde_zk.json";
    const char *m3a_path = "tools/vectors/range_proof_air_zk.json";
    if (argc >= 3) {
        s2_path = argv[1];
        m3a_path = argv[2];
    }

    size_t s2_len = 0, m3a_len = 0;
    char *s2 = load_file(s2_path, &s2_len);
    char *m3a = load_file(m3a_path, &m3a_len);
    if (!s2 || !m3a) {
        free(s2);
        free(m3a);
        return 2;
    }
    printf("loaded %s (%zu bytes) + %s (%zu bytes)\n", s2_path, s2_len,
           m3a_path, m3a_len);

    int failed = 0;

    /* M3a vector: real trace root + real alpha (anchored under
     * "stark_alpha_fp2" — c0_decimal recurs across the file). */
    uint8_t root_m3a[DNAC_MERKLE_DIGEST_BYTES];
    uint64_t alpha_c0 = 0, alpha_c1 = 0;
    {
        const char *root_p = find_value(m3a, "trace_commit_root_hex");
        const char *anchor = strstr(m3a, "\"stark_alpha_fp2\"");
        if (!root_p ||
            !parse_hex_bytes_at(root_p, root_m3a, sizeof(root_m3a)) ||
            !anchor) {
            fprintf(stderr, "M3a vector parse FAIL (root/alpha anchor)\n");
            free(s2);
            free(m3a);
            return 2;
        }
        const char *c0 = find_value(anchor, "c0_decimal");
        const char *c1 = find_value(anchor, "c1_decimal");
        if (!c0 || !c1 || !read_u64_at(c0, &alpha_c0) ||
            !read_u64_at(c1, &alpha_c1)) {
            fprintf(stderr, "M3a vector parse FAIL (alpha c0/c1)\n");
            free(s2);
            free(m3a);
            return 2;
        }
    }

    /* ---- T1: C chain S1->S2->S3 root == the M3a proof's trace root ---- */
    uint8_t root_c[DNAC_MERKLE_DIGEST_BYTES];
    {
        static uint64_t draws[S5_DRAWS];
        static uint64_t base_c[S5_H * S5_W];
        static uint64_t randomized_c[2u * S5_H * S5_RAND_W];
        static uint64_t lde_c[S5_LDE_CELLS];
        dnac_merkle_tree_t *tree = NULL;
        const uint64_t amounts[4] = {10, 20, 30, 40};
        int bad = 1;
        if (parse_u64_array(s2, "random_draws", draws, S5_DRAWS) &&
            dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) ==
                DNAC_PROVER_OK &&
            dnac_prover_randomize_trace(base_c, S5_H, S5_W, S5_R, draws,
                                        randomized_c) == DNAC_PROVER_OK &&
            dnac_prover_coset_lde_bitrev(randomized_c, 2 * S5_H, S5_RAND_W, 2,
                                         7, lde_c) == DNAC_PROVER_OK &&
            dnac_prover_commit_matrix(lde_c, S5_LDE_H, S5_RAND_W, root_c,
                                      &tree) == DNAC_PROVER_OK) {
            bad = memcmp(root_c, root_m3a, sizeof(root_c)) != 0;
        }
        dnac_merkle_tree_free(tree);
        if (bad) failed++;
        printf("T1 chain root == M3a proof trace root (cross-vector)   %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T2: fs_to_alpha reproduces the REAL alpha ---- */
    {
        const uint64_t publics[3] = {107, 7, 4};
        gold_fp2_t alpha;
        dnac_transcript_t *t = dnac_transcript_init_default();
        int bad = 1;
        if (t != NULL &&
            dnac_prover_fs_to_alpha(t, 3, 2, 0, root_m3a, publics, 3,
                                    &alpha) == DNAC_PROVER_OK) {
            bad = !(gold_fp_to_u64(alpha.a) == alpha_c0 &&
                    gold_fp_to_u64(alpha.b) == alpha_c1);
            if (bad) {
                fprintf(stderr,
                        "T2 alpha MISMATCH: C=(%" PRIu64 ",%" PRIu64
                        ") real=(%" PRIu64 ",%" PRIu64 ")\n",
                        gold_fp_to_u64(alpha.a), gold_fp_to_u64(alpha.b),
                        alpha_c0, alpha_c1);
            }
        }
        dnac_transcript_free(t);
        if (bad) failed++;
        printf("T2 fs_to_alpha == REAL p3 alpha (c0,c1)                %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T3: fail-close guards ---- */
    {
        const uint64_t publics_bad[3] = {107, GOLDILOCKS_P, 4};
        const uint64_t publics[3] = {107, 7, 4};
        gold_fp2_t alpha;
        dnac_transcript_t *t = dnac_transcript_init_default();
        int bad = 0;
        if (t == NULL) bad++;
        if (dnac_prover_fs_to_alpha(t, 3, 2, 0, root_m3a, publics_bad, 3,
                                    &alpha) != DNAC_PROVER_ERR_NONCANONICAL)
            bad++;
        if (dnac_prover_fs_to_alpha(t, 3, 2, 0, NULL, publics, 3, &alpha) !=
            DNAC_PROVER_ERR_PARAM)
            bad++;
        if (dnac_prover_fs_to_alpha(t, 3, 2, 0, root_m3a, NULL, 3, &alpha) !=
            DNAC_PROVER_ERR_PARAM)
            bad++;
        dnac_transcript_free(t);
        if (bad) failed++;
        printf("T3 fail-close guards: 3/3 rejects                       %s\n",
               bad ? "FAIL" : "PASS");
    }

    free(s2);
    free(m3a);
    if (failed == 0) {
        printf("test_prover_s5_alpha: PASS\n");
        printf("S5 PROVER-ALPHA GATE: GREEN — C prover transcript drive "
               "reproduces the REAL p3_uni_stark alpha (Plonky3 82cfad73) on "
               "the C-built trace root\n");
        return 0;
    }
    printf("S5 PROVER-ALPHA GATE: RED — %d failures\n", failed);
    return 1;
}
