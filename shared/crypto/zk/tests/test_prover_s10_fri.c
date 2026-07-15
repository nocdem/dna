/**
 * @file test_prover_s10_fri.c
 * @brief S10 (C prover) — FRI commit phase byte-match KAT.
 *
 * Chains the full C prover S1->S9, builds the reduced-opening codeword, runs
 * the commit phase, and asserts against prover_s10_fri_zk.json (from the REAL
 * proof + transcript replay):
 *
 *   T1  commit-phase layer root(s) == proof.commit_phase_commits.
 *   T2  per-round beta(s) == the replayed betas.
 *   T3  final_poly (4 fp2) == proof.final_poly.
 *   T4  PoW witnesses all zero (commit + query).
 *
 * Build (via Makefile):
 *   make build/test_prover_s10_fri
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
#define LOG_H 5u

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

/* Parse first hex string inside the array under `key`. */
static bool parse_first_hex(const char *src, const char *key, uint8_t *out,
                            size_t nbytes) {
    const char *p = find_value(src, key);
    if (!p) return false;
    while (*p && *p != '"') p++;
    if (*p != '"') return false;
    p++;
    for (size_t i = 0; i < nbytes; i++) {
        unsigned hi, lo;
        if (sscanf(p, "%1x%1x", &hi, &lo) != 2) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    return *p == '"';
}

/* Open all matrices, observe, sample FRI alpha; returns alpha + committed
 * LDEs + merged opened vectors via out params. */
int main(int argc, char **argv) {
    const char *s10 = "tools/vectors/prover_s10_fri_zk.json";
    const char *s8 = "tools/vectors/prover_s8_random_zk.json";
    const char *s7 = "tools/vectors/prover_s7_quotient_commit_zk.json";
    const char *s2 = "tools/vectors/prover_s2_lde_zk.json";
    if (argc >= 5) { s10 = argv[1]; s8 = argv[2]; s7 = argv[3]; s2 = argv[4]; }

    size_t a, b, c, d;
    char *j10 = load_file(s10, &a), *j8 = load_file(s8, &b),
         *j7 = load_file(s7, &c), *j2 = load_file(s2, &d);
    if (!j10 || !j8 || !j7 || !j2) {
        free(j10); free(j8); free(j7); free(j2);
        return 2;
    }
    printf("loaded 4 vectors\n");

    static uint64_t betas_v[2], final_poly_v[8], commit_pow_v[1];
    uint64_t query_pow_v = 1;
    static uint64_t r_draws[RD], trace_draws[TRACE_DRAWS], codeword[CODEWORD],
        blinding[BLINDING];
    uint8_t root0_v[DNAC_MERKLE_DIGEST_BYTES];
    if (!parse_u64_array(j10, "betas", betas_v, 2) ||
        !parse_u64_array(j10, "final_poly", final_poly_v, 8) ||
        !parse_u64_array(j10, "commit_pow_witnesses", commit_pow_v, 1) ||
        !parse_first_hex(j10, "commit_phase_roots_hex", root0_v,
                         DNAC_MERKLE_DIGEST_BYTES) ||
        !parse_u64_array(j8, "r_draws", r_draws, RD) ||
        !parse_u64_array(j7, "codeword_rand", codeword, CODEWORD) ||
        !parse_u64_array(j7, "blinding_rand", blinding, BLINDING) ||
        !parse_u64_array(j2, "random_draws", trace_draws, TRACE_DRAWS)) {
        fprintf(stderr, "vector parse FAIL\n");
        free(j10); free(j8); free(j7); free(j2);
        return 2;
    }

    int failed = 0;

    /* ---- Chain S1->S9: committed LDEs, opened values, alpha, transcript ---- */
    static uint64_t base_c[H * W], randomized_c[2u * H * RAND_W], lde_c[LDE_CELLS],
        trace_q[QS * W], qflat[2 * QS], chunk_ldes[NQ * CHUNK_LDE_CELLS],
        r_lde[R_LDE_CELLS];
    static uint64_t sf[QS], sl[QS], st[QS], iv[QS];
    static gold_fp2_t r_open[CW], t_open[RAND_W], t_open_n[RAND_W], q_open[NQ * CW];
    uint8_t troot[DNAC_MERKLE_DIGEST_BYTES], qroot[DNAC_MERKLE_DIGEST_BYTES],
        rroot[DNAC_MERKLE_DIGEST_BYTES];
    dnac_merkle_tree_t *ttree = NULL, *rtree = NULL;
    dnac_merkle_batch_tree_t *qtree = NULL;
    dnac_transcript_t *t = dnac_transcript_init_default();
    gold_fp2_t alpha, zeta, zeta_next, fri_alpha;
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
              dnac_prover_fs_to_zeta(t, qroot, rroot, 2, &zeta, &zeta_next) == DNAC_PROVER_OK &&
              dnac_prover_open_matrix_at(r_lde, LDE_H, CW, 2, zeta, r_open) == DNAC_PROVER_OK &&
              dnac_prover_open_matrix_at(lde_c, LDE_H, RAND_W, 2, zeta, t_open) == DNAC_PROVER_OK &&
              dnac_prover_open_matrix_at(lde_c, LDE_H, RAND_W, 2, zeta_next, t_open_n) == DNAC_PROVER_OK)) {
            fprintf(stderr, "chain S1->S9 FAIL\n");
            free(j10); free(j8); free(j7); free(j2);
            return 2;
        }
        for (size_t k = 0; k < NQ; k++) {
            if (dnac_prover_open_matrix_at(&chunk_ldes[k * CHUNK_LDE_CELLS],
                                           LDE_H, CW, 2, zeta,
                                           &q_open[k * CW]) != DNAC_PROVER_OK) {
                fprintf(stderr, "chunk open FAIL\n");
                free(j10); free(j8); free(j7); free(j2);
                return 2;
            }
        }
        dnac_prover_observe_opened(t, r_open, CW);
        dnac_prover_observe_opened(t, t_open, RAND_W);
        dnac_prover_observe_opened(t, t_open_n, RAND_W);
        for (size_t k = 0; k < NQ; k++)
            dnac_prover_observe_opened(t, &q_open[k * CW], CW);
        fri_alpha = dnac_transcript_sample_fp2(t);
    }

    /* ---- Build reduced opening + commit phase ---- */
    static gold_fp2_t ro[LDE_H];
    dnac_prover_fri_result_t res;
    {
        const gold_fp2_t zpts[2] = {zeta, zeta_next};
        const gold_fp2_t *r_ov[1] = {r_open};
        const gold_fp2_t *t_ov[2] = {t_open, t_open_n};
        dnac_prover_fri_input_round_t rounds[2 + NQ];
        const gold_fp2_t *q_ov[NQ][1];
        rounds[0] = (dnac_prover_fri_input_round_t){r_lde, LDE_H, CW, 1, &zeta, r_ov};
        rounds[1] = (dnac_prover_fri_input_round_t){lde_c, LDE_H, RAND_W, 2, zpts, t_ov};
        for (size_t k = 0; k < NQ; k++) {
            q_ov[k][0] = &q_open[k * CW];
            rounds[2 + k] = (dnac_prover_fri_input_round_t){
                &chunk_ldes[k * CHUNK_LDE_CELLS], LDE_H, CW, 1, &zeta, q_ov[k]};
        }
        if (dnac_prover_fri_reduced_openings(rounds, 2 + NQ, LOG_H, fri_alpha,
                                             ro) != DNAC_PROVER_OK) {
            fprintf(stderr, "reduced openings FAIL\n");
            failed++;
        } else if (dnac_prover_fri_commit_phase(ro, LDE_H, 2, 2, 1, NULL, 0, t, &res) !=
                   DNAC_PROVER_OK) {
            fprintf(stderr, "commit phase FAIL\n");
            failed++;
        } else {
            /* T1: layer root == proof commit_phase_commits[0]. */
            int bad1 = (res.num_rounds != 1) ||
                       memcmp(res.roots[0], root0_v, sizeof(root0_v)) != 0;
            if (bad1) failed++;
            printf("T1 commit-phase layer root == proof commit           %s\n",
                   bad1 ? "FAIL" : "PASS");
            /* T2: beta. */
            int bad2 = !(gold_fp_to_u64(res.betas[0].a) == betas_v[0] &&
                         gold_fp_to_u64(res.betas[0].b) == betas_v[1]);
            if (bad2) failed++;
            printf("T2 round-0 beta == replayed beta                     %s\n",
                   bad2 ? "FAIL" : "PASS");
            /* T3: final poly. */
            int bad3 = 0;
            for (size_t i = 0; i < 4; i++) {
                if (gold_fp_to_u64(res.final_poly[i].a) != final_poly_v[2 * i] ||
                    gold_fp_to_u64(res.final_poly[i].b) != final_poly_v[2 * i + 1]) {
                    bad3++;
                }
            }
            if (bad3) failed++;
            printf("T3 final_poly 4 fp2 == proof.final_poly              %s\n",
                   bad3 ? "FAIL" : "PASS");
            dnac_prover_fri_result_free(&res);
        }
    }

    /* T4: PoW witnesses are zero. */
    {
        const char *qp = find_value(j10, "query_pow_witness");
        if (qp) {
            while (*qp == ' ' || *qp == '"') qp++;
            query_pow_v = strtoull(qp, NULL, 10);
        }
        int bad = (commit_pow_v[0] != 0 || query_pow_v != 0);
        if (bad) failed++;
        printf("T4 PoW witnesses (commit + query) == 0                 %s\n",
               bad ? "FAIL" : "PASS");
    }

    dnac_transcript_free(t);
    dnac_merkle_tree_free(ttree);
    dnac_merkle_tree_free(rtree);
    dnac_merkle_batch_tree_free(qtree);
    free(j10); free(j8); free(j7); free(j2);
    if (failed == 0) {
        printf("test_prover_s10_fri: PASS\n");
        printf("S10 PROVER-FRI GATE: GREEN — C reduced-opening build + "
               "commit-phase fold/commit + final poly reproduce the REAL FRI "
               "commit-phase roots/betas/final_poly (Plonky3 82cfad73)\n");
        return 0;
    }
    printf("S10 PROVER-FRI GATE: RED — %d failures\n", failed);
    return 1;
}
