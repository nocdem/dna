/**
 * @file test_prover_s6_quotient.c
 * @brief S6 (C prover) — quotient computation byte-match KAT.
 *
 * Vectors:
 *   - tools/vectors/prover_s6_quotient_zk.json — REAL Plonky3 ground truth
 *     (selectors_on_coset, trace-on-quotient-domain, pub quotient_values,
 *     flat + round-robin chunk split; oracle gates G1+G3).
 *   - tools/vectors/prover_s2_lde_zk.json — SmallRng(1) draws to rebuild the
 *     committed LDE via the C chain (S1->S2), and the S3 root for alpha.
 *
 * Asserts:
 *   T1  chain alpha: S1->S2->S3 root + fs_to_alpha == the vector alpha (the
 *       REAL p3 alpha — same value as range_proof_air_zk stark_alpha_fp2).
 *   T2  dnac_prover_quotient_selectors == the 4 REAL selector vectors.
 *   T3  dnac_prover_trace_on_quotient_domain(chain LDE) == the REAL 16x56.
 *   T4  dnac_prover_quotient_values_range_zk == the REAL quotient (16 fp2)
 *       and the flat view matches byte-for-byte.
 *   T5  dnac_prover_quotient_split == the REAL 4 chunk matrices.
 *   T6  teeth: a tampered trace cell changes the quotient (non-vacuous).
 *
 * Build (via Makefile):
 *   make build/test_prover_s6_quotient
 *   ./build/test_prover_s6_quotient tools/vectors/prover_s6_quotient_zk.json \
 *                                   tools/vectors/prover_s2_lde_zk.json
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

#define S6_H 4u
#define S6_W 56u
#define S6_R 4u
#define S6_RAND_W 60u
#define S6_DRAWS (S6_H * (S6_W + 2u * S6_R))
#define S6_LDE_H 32u
#define S6_LDE_CELLS (S6_LDE_H * S6_RAND_W)
#define S6_QS 16u
#define S6_TRACE_Q_CELLS (S6_QS * S6_W)
#define S6_NQ 4u

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

/* Parse `[ "n", ... ]` starting at/after p; returns end pointer or NULL. */
static const char *parse_arr_at(const char *p, uint64_t *out, size_t expect) {
    while (*p && *p != '[') p++;
    if (*p != '[') return NULL;
    p++;
    for (size_t i = 0; i < expect; i++) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')
            p++;
        if (*p != '"') return NULL;
        p++;
        if (*p < '0' || *p > '9') return NULL;
        out[i] = strtoull(p, (char **)&p, 10);
        if (*p != '"') return NULL;
        p++;
    }
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return (*p == ']') ? p + 1 : NULL;
}

static bool parse_u64_array(const char *src, const char *key, uint64_t *out,
                            size_t expect) {
    const char *p = find_value(src, key);
    return p != NULL && parse_arr_at(p, out, expect) != NULL;
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
    const char *s6_path = "tools/vectors/prover_s6_quotient_zk.json";
    const char *s2_path = "tools/vectors/prover_s2_lde_zk.json";
    if (argc >= 3) {
        s6_path = argv[1];
        s2_path = argv[2];
    }

    size_t s6_len = 0, s2_len = 0;
    char *s6 = load_file(s6_path, &s6_len);
    char *s2 = load_file(s2_path, &s2_len);
    if (!s6 || !s2) {
        free(s6);
        free(s2);
        return 2;
    }
    printf("loaded %s (%zu bytes) + %s (%zu bytes)\n", s6_path, s6_len,
           s2_path, s2_len);

    /* vector fields */
    uint64_t alpha_vec[2];
    static uint64_t sel_first_v[S6_QS], sel_last_v[S6_QS], sel_trans_v[S6_QS],
        sel_ivan_v[S6_QS];
    static uint64_t trace_q_v[S6_TRACE_Q_CELLS];
    static uint64_t qvals_v[2 * S6_QS];
    static uint64_t qflat_v[2 * S6_QS];
    static uint64_t chunks_v[2 * S6_QS];
    static uint64_t draws[S6_DRAWS];
    if (!parse_u64_array(s6, "alpha", alpha_vec, 2) ||
        !parse_u64_array(s6, "is_first_row", sel_first_v, S6_QS) ||
        !parse_u64_array(s6, "is_last_row", sel_last_v, S6_QS) ||
        !parse_u64_array(s6, "is_transition", sel_trans_v, S6_QS) ||
        !parse_u64_array(s6, "inv_vanishing", sel_ivan_v, S6_QS) ||
        !parse_u64_array(s6, "trace_on_quotient_domain", trace_q_v,
                         S6_TRACE_Q_CELLS) ||
        !parse_u64_array(s6, "quotient_values", qvals_v, 2 * S6_QS) ||
        !parse_u64_array(s6, "quotient_flat", qflat_v, 2 * S6_QS) ||
        !parse_u64_array(s2, "random_draws", draws, S6_DRAWS)) {
        fprintf(stderr, "vector parse FAIL\n");
        free(s6);
        free(s2);
        return 2;
    }
    /* quotient_chunks: 4 nested arrays of 8 */
    {
        const char *p = find_value(s6, "quotient_chunks");
        if (!p) {
            fprintf(stderr, "chunks parse FAIL\n");
            free(s6);
            free(s2);
            return 2;
        }
        while (*p && *p != '[') p++;
        p++; /* outer '[' */
        for (size_t c = 0; c < S6_NQ; c++) {
            p = parse_arr_at(p, &chunks_v[c * 8], 8);
            if (!p) {
                fprintf(stderr, "chunk %zu parse FAIL\n", c);
                free(s6);
                free(s2);
                return 2;
            }
            while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' ||
                   *p == ',')
                p++;
        }
    }

    int failed = 0;

    /* Rebuild the C chain: S1 -> S2 (randomize + LDE bitrev) -> S3 root. */
    static uint64_t base_c[S6_H * S6_W];
    static uint64_t randomized_c[2u * S6_H * S6_RAND_W];
    static uint64_t lde_c[S6_LDE_CELLS];
    uint8_t root_c[DNAC_MERKLE_DIGEST_BYTES];
    {
        dnac_merkle_tree_t *tree = NULL;
        const uint64_t amounts[4] = {10, 20, 30, 40};
        if (dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) !=
                DNAC_PROVER_OK ||
            dnac_prover_randomize_trace(base_c, S6_H, S6_W, S6_R, draws,
                                        randomized_c) != DNAC_PROVER_OK ||
            dnac_prover_coset_lde_bitrev(randomized_c, 2 * S6_H, S6_RAND_W, 2,
                                         7, lde_c) != DNAC_PROVER_OK ||
            dnac_prover_commit_matrix(lde_c, S6_LDE_H, S6_RAND_W, root_c,
                                      &tree) != DNAC_PROVER_OK) {
            fprintf(stderr, "chain rebuild FAIL\n");
            free(s6);
            free(s2);
            return 2;
        }
        dnac_merkle_tree_free(tree);
    }

    /* ---- T1: chain alpha == the REAL vector alpha ---- */
    {
        const uint64_t publics[3] = {107, 7, 4};
        gold_fp2_t alpha;
        dnac_transcript_t *t = dnac_transcript_init_default();
        int bad = 1;
        if (t != NULL &&
            dnac_prover_fs_to_alpha(t, 3, 2, 0, root_c, publics, 3, &alpha) ==
                DNAC_PROVER_OK) {
            bad = !(gold_fp_to_u64(alpha.a) == alpha_vec[0] &&
                    gold_fp_to_u64(alpha.b) == alpha_vec[1]);
        }
        dnac_transcript_free(t);
        if (bad) failed++;
        printf("T1 chain alpha == REAL vector alpha                     %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T2: selectors byte-match ---- */
    static uint64_t sf[S6_QS], sl[S6_QS], st[S6_QS], iv[S6_QS];
    {
        int bad = 1;
        if (dnac_prover_quotient_selectors(2, 4, 7, sf, sl, st, iv) ==
            DNAC_PROVER_OK) {
            bad = compare_cells("T2.first", sf, sel_first_v, S6_QS, S6_QS) +
                  compare_cells("T2.last", sl, sel_last_v, S6_QS, S6_QS) +
                  compare_cells("T2.trans", st, sel_trans_v, S6_QS, S6_QS) +
                  compare_cells("T2.ivan", iv, sel_ivan_v, S6_QS, S6_QS);
        }
        if (bad) failed++;
        printf("T2 selectors_on_coset 4x16 byte-match                   %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T3: trace-on-quotient-domain from the chain LDE ---- */
    static uint64_t trace_q_c[S6_TRACE_Q_CELLS];
    {
        int bad = 1;
        if (dnac_prover_trace_on_quotient_domain(lde_c, S6_LDE_H, S6_RAND_W,
                                                 S6_QS, S6_W, trace_q_c) ==
            DNAC_PROVER_OK) {
            bad = compare_cells("T3", trace_q_c, trace_q_v, S6_TRACE_Q_CELLS,
                                S6_W);
        }
        if (bad) failed++;
        printf("T3 trace-on-quotient-domain 16x56 byte-match            %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T4: quotient values + flat ---- */
    static uint64_t qvals_c[2 * S6_QS];
    {
        const uint64_t publics[3] = {107, 7, 4};
        const gold_fp2_t alpha = {gold_fp_from_u64(alpha_vec[0]),
                                  gold_fp_from_u64(alpha_vec[1])};
        int bad = 1;
        if (dnac_prover_quotient_values_range_zk(trace_q_c, S6_QS, 4, publics,
                                                 alpha, sf, sl, st, iv,
                                                 qvals_c) == DNAC_PROVER_OK) {
            bad = compare_cells("T4.q", qvals_c, qvals_v, 2 * S6_QS, 2) +
                  compare_cells("T4.flat", qvals_c, qflat_v, 2 * S6_QS, 2);
        }
        if (bad) failed++;
        printf("T4 quotient_values 16xfp2 == REAL p3 quotient           %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T5: round-robin chunk split ---- */
    {
        static uint64_t chunks_c[2 * S6_QS];
        int bad = 1;
        if (dnac_prover_quotient_split(qvals_c, S6_QS, S6_NQ, chunks_c) ==
            DNAC_PROVER_OK) {
            bad = compare_cells("T5", chunks_c, chunks_v, 2 * S6_QS, 2);
        }
        if (bad) failed++;
        printf("T5 split_evals 4 chunks (4x2) byte-match                %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T6: teeth — tampered trace cell changes the quotient ---- */
    {
        static uint64_t tampered[S6_TRACE_Q_CELLS];
        static uint64_t q_t[2 * S6_QS];
        const uint64_t publics[3] = {107, 7, 4};
        const gold_fp2_t alpha = {gold_fp_from_u64(alpha_vec[0]),
                                  gold_fp_from_u64(alpha_vec[1])};
        memcpy(tampered, trace_q_c, sizeof(tampered));
        tampered[3 * S6_W + RANGE_AIR_AMOUNT_OFF] ^= 1; /* flip amount bit */
        int bad = 1;
        if (dnac_prover_quotient_values_range_zk(tampered, S6_QS, 4, publics,
                                                 alpha, sf, sl, st, iv,
                                                 q_t) == DNAC_PROVER_OK) {
            bad = (memcmp(q_t, qvals_v, sizeof(q_t)) == 0);
        }
        if (bad) failed++;
        printf("T6 teeth: tampered trace -> quotient differs            %s\n",
               bad ? "FAIL" : "PASS");
    }

    free(s6);
    free(s2);
    if (failed == 0) {
        printf("test_prover_s6_quotient: PASS\n");
        printf("S6 PROVER-QUOTIENT GATE: GREEN — C selectors + trace-gather + "
               "61-constraint domain-wide fold + Z_H division + chunk split "
               "byte-match the REAL p3_uni_stark quotient (Plonky3 82cfad73)\n");
        return 0;
    }
    printf("S6 PROVER-QUOTIENT GATE: RED — %d failures\n", failed);
    return 1;
}
