/**
 * @file test_prover_s9_open.c
 * @brief S9 (C prover) — open at zeta byte-match KAT.
 *
 * Chains the full C prover S1->S8 (trace + quotient + random commits, alpha,
 * zeta/zeta_next), then opens every committed LDE at zeta (trace also at
 * zeta_next) via barycentric interpolation and asserts:
 *
 *   T1  merged opened vectors (random 6, trace 60, trace_next 60, 4x quotient
 *       6) byte-match prover_s9_open_zk.json (reconstructed from the REAL proof).
 *   T2  observing them into the live transcript and sampling reproduces the
 *       REAL FRI batch alpha (transcript-state gate).
 *   T3  teeth: a tampered committed LDE cell changes an opened value.
 *
 * Build (via Makefile):
 *   make build/test_prover_s9_open
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

#define H 4u
#define W 56u
#define R 4u
#define RAND_W 60u
#define TRACE_DRAWS (H * (W + 2u * R))
#define LDE_H 32u
#define LDE_CELLS (LDE_H * RAND_W)
#define QS 16u
#define NQ 4u
#define CW 6u
#define CODEWORD 64u
#define BLINDING 72u
#define RD 48u
#define R_LDE_CELLS (LDE_H * CW)
#define CHUNK_LDE_CELLS (LDE_H * CW)

static char *load_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

static const char *find_value(const char *src, const char *key) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(src, needle);
    return p ? p + strlen(needle) : NULL;
}

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

/* Compare a width-`n` fp2 opened vector against a flat [c0,c1,...] u64 array. */
static int cmp_opened(const char *tag, const gold_fp2_t *got,
                      const uint64_t *want, size_t n) {
    int mism = 0;
    for (size_t i = 0; i < n; i++) {
        if (gold_fp_to_u64(got[i].a) != want[2 * i] ||
            gold_fp_to_u64(got[i].b) != want[2 * i + 1]) {
            if (mism < 3) {
                fprintf(stderr, "%s MISMATCH col=%zu: C=(%" PRIu64 ",%" PRIu64
                                ") oracle=(%" PRIu64 ",%" PRIu64 ")\n",
                        tag, i, gold_fp_to_u64(got[i].a),
                        gold_fp_to_u64(got[i].b), want[2 * i], want[2 * i + 1]);
            }
            mism++;
        }
    }
    return mism;
}

int main(int argc, char **argv) {
    const char *s9 = "tools/vectors/prover_s9_open_zk.json";
    const char *s8 = "tools/vectors/prover_s8_random_zk.json";
    const char *s7 = "tools/vectors/prover_s7_quotient_commit_zk.json";
    const char *s2 = "tools/vectors/prover_s2_lde_zk.json";
    const char *m3a = "tools/vectors/range_proof_air_zk.json";
    if (argc >= 6) { s9 = argv[1]; s8 = argv[2]; s7 = argv[3]; s2 = argv[4]; m3a = argv[5]; }

    size_t a, b, c, d, e;
    char *j9 = load_file(s9, &a), *j8 = load_file(s8, &b), *j7 = load_file(s7, &c),
         *j2 = load_file(s2, &d), *jm = load_file(m3a, &e);
    if (!j9 || !j8 || !j7 || !j2 || !jm) {
        free(j9); free(j8); free(j7); free(j2); free(jm);
        return 2;
    }
    printf("loaded 5 vectors\n");

    static uint64_t r_at_zeta_v[2 * CW], t_at_zeta_v[2 * RAND_W],
        t_at_zn_v[2 * RAND_W], q_at_zeta_v[NQ * 2 * CW], fri_alpha_v[2];
    static uint64_t r_draws[RD], trace_draws[TRACE_DRAWS], codeword[CODEWORD],
        blinding[BLINDING];
    if (!parse_u64_array(j9, "random_at_zeta", r_at_zeta_v, 2 * CW) ||
        !parse_u64_array(j9, "trace_at_zeta", t_at_zeta_v, 2 * RAND_W) ||
        !parse_u64_array(j9, "trace_at_zeta_next", t_at_zn_v, 2 * RAND_W) ||
        !parse_u64_array(j9, "fri_batch_alpha", fri_alpha_v, 2) ||
        !parse_u64_array(j8, "r_draws", r_draws, RD) ||
        !parse_u64_array(j7, "codeword_rand", codeword, CODEWORD) ||
        !parse_u64_array(j7, "blinding_rand", blinding, BLINDING) ||
        !parse_u64_array(j2, "random_draws", trace_draws, TRACE_DRAWS)) {
        fprintf(stderr, "vector parse FAIL\n");
        free(j9); free(j8); free(j7); free(j2); free(jm);
        return 2;
    }
    { /* quotient_at_zeta: 4 nested arrays of 12 */
        const char *p = find_value(j9, "quotient_at_zeta");
        while (p && *p && *p != '[') p++;
        if (p) p++;
        for (size_t k = 0; k < NQ && p; k++) {
            p = parse_arr_at(p, &q_at_zeta_v[k * 2 * CW], 2 * CW);
            while (p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' ||
                         *p == ','))
                p++;
        }
        if (!p) {
            fprintf(stderr, "quotient_at_zeta parse FAIL\n");
            free(j9); free(j8); free(j7); free(j2); free(jm);
            return 2;
        }
    }

    int failed = 0;

    /* Rebuild the C chain S1->S8 with a LIVE transcript. */
    static uint64_t base_c[H * W], randomized_c[2u * H * RAND_W], lde_c[LDE_CELLS],
        trace_q[QS * W], qflat[2 * QS], chunk_ldes[NQ * CHUNK_LDE_CELLS],
        r_lde[R_LDE_CELLS];
    static uint64_t sf[QS], sl[QS], st[QS], iv[QS];
    uint8_t troot[DNAC_MERKLE_DIGEST_BYTES], qroot[DNAC_MERKLE_DIGEST_BYTES],
        rroot[DNAC_MERKLE_DIGEST_BYTES];
    dnac_merkle_tree_t *ttree = NULL, *rtree = NULL;
    dnac_merkle_batch_tree_t *qtree = NULL;
    dnac_transcript_t *t = dnac_transcript_init_default();
    gold_fp2_t alpha, zeta, zeta_next;
    {
        const uint64_t amounts[4] = {10, 20, 30, 40};
        const uint64_t publics[3] = {107, 7, 4};
        if (!(t &&
              dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) == DNAC_PROVER_OK &&
              dnac_prover_randomize_trace(base_c, H, W, R, trace_draws, randomized_c) == DNAC_PROVER_OK &&
              dnac_prover_coset_lde_bitrev(randomized_c, 2 * H, RAND_W, 2, 7, lde_c) == DNAC_PROVER_OK &&
              dnac_prover_commit_matrix(lde_c, LDE_H, RAND_W, NULL, 0, troot, &ttree) == DNAC_PROVER_OK &&
              dnac_prover_fs_to_alpha(t, 3, 2, 0, troot, publics, 3, &alpha) == DNAC_PROVER_OK &&
              dnac_prover_quotient_selectors(2, 4, 7, sf, sl, st, iv) == DNAC_PROVER_OK &&
              dnac_prover_trace_on_quotient_domain(lde_c, LDE_H, RAND_W, QS, W, trace_q) == DNAC_PROVER_OK &&
              dnac_prover_quotient_values_range_zk(trace_q, QS, 4, publics, alpha, sf, sl, st, iv, qflat) == DNAC_PROVER_OK &&
              dnac_prover_quotient_commit(qflat, QS, NQ, 4, 2, 7, codeword, blinding, NULL, 0, chunk_ldes, qroot, &qtree) == DNAC_PROVER_OK &&
              dnac_prover_random_commit(r_draws, 8, CW, 2, NULL, 0, r_lde, rroot, &rtree) == DNAC_PROVER_OK &&
              dnac_prover_fs_to_zeta(t, qroot, rroot, 2, &zeta, &zeta_next) == DNAC_PROVER_OK)) {
            fprintf(stderr, "chain S1->S8 FAIL\n");
            free(j9); free(j8); free(j7); free(j2); free(jm);
            return 2;
        }
    }

    /* ---- T1: open every matrix at zeta / zeta_next, byte-match merged ---- */
    static gold_fp2_t r_open[CW], t_open[RAND_W], t_open_n[RAND_W],
        q_open[NQ * CW];
    {
        int bad = 1;
        if (dnac_prover_open_matrix_at(r_lde, LDE_H, CW, 2, zeta, r_open) == DNAC_PROVER_OK &&
            dnac_prover_open_matrix_at(lde_c, LDE_H, RAND_W, 2, zeta, t_open) == DNAC_PROVER_OK &&
            dnac_prover_open_matrix_at(lde_c, LDE_H, RAND_W, 2, zeta_next, t_open_n) == DNAC_PROVER_OK) {
            bad = cmp_opened("T1.rand", r_open, r_at_zeta_v, CW) +
                  cmp_opened("T1.trace", t_open, t_at_zeta_v, RAND_W) +
                  cmp_opened("T1.trace_next", t_open_n, t_at_zn_v, RAND_W);
            for (size_t k = 0; k < NQ; k++) {
                if (dnac_prover_open_matrix_at(&chunk_ldes[k * CHUNK_LDE_CELLS],
                                               LDE_H, CW, 2, zeta,
                                               &q_open[k * CW]) != DNAC_PROVER_OK) {
                    bad++;
                    continue;
                }
                bad += cmp_opened("T1.quot", &q_open[k * CW],
                                  &q_at_zeta_v[k * 2 * CW], CW);
            }
        }
        if (bad) failed++;
        printf("T1 open at zeta: merged 6+60+60+4x6 fp2 byte-match     %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T2: observe merged + sample FRI batch alpha == REAL ---- */
    {
        dnac_prover_observe_opened(t, r_open, CW);
        dnac_prover_observe_opened(t, t_open, RAND_W);
        dnac_prover_observe_opened(t, t_open_n, RAND_W);
        for (size_t k = 0; k < NQ; k++)
            dnac_prover_observe_opened(t, &q_open[k * CW], CW);
        gold_fp2_t fri_alpha = dnac_transcript_sample_fp2(t);
        int bad = !(gold_fp_to_u64(fri_alpha.a) == fri_alpha_v[0] &&
                    gold_fp_to_u64(fri_alpha.b) == fri_alpha_v[1]);
        if (bad) {
            fprintf(stderr, "T2 FRI alpha MISMATCH: C=(%" PRIu64 ",%" PRIu64
                            ") real=(%" PRIu64 ",%" PRIu64 ")\n",
                    gold_fp_to_u64(fri_alpha.a), gold_fp_to_u64(fri_alpha.b),
                    fri_alpha_v[0], fri_alpha_v[1]);
            failed++;
        }
        printf("T2 observe merged -> FRI batch alpha == REAL           %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T3: teeth — tampered committed cell moves an opened value ---- */
    {
        static uint64_t tampered[LDE_CELLS];
        static gold_fp2_t open_t[RAND_W];
        memcpy(tampered, lde_c, sizeof(tampered));
        tampered[7 * RAND_W + 3] ^= 1;
        int bad = 1;
        if (dnac_prover_open_matrix_at(tampered, LDE_H, RAND_W, 2, zeta,
                                       open_t) == DNAC_PROVER_OK) {
            bad = (cmp_opened("T3", open_t, t_at_zeta_v, RAND_W) == 0);
        }
        if (bad) failed++;
        printf("T3 teeth: tampered LDE -> opened value differs         %s\n",
               bad ? "FAIL" : "PASS");
    }

    dnac_transcript_free(t);
    dnac_merkle_tree_free(ttree);
    dnac_merkle_tree_free(rtree);
    dnac_merkle_batch_tree_free(qtree);
    free(j9); free(j8); free(j7); free(j2); free(jm);
    if (failed == 0) {
        printf("test_prover_s9_open: PASS\n");
        printf("S9 PROVER-OPEN GATE: GREEN — C barycentric open at zeta "
               "reproduces the REAL merged opened values + FRI batch alpha "
               "(Plonky3 82cfad73)\n");
        return 0;
    }
    printf("S9 PROVER-OPEN GATE: RED — %d failures\n", failed);
    return 1;
}
