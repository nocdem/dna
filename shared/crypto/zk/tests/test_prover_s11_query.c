/**
 * @file test_prover_s11_query.c
 * @brief S11+S12 (C prover) — query index sampling + Merkle query openings.
 *
 * Chains the full C prover S1->S10 (commit phase), then:
 *   T1  sample_bits(5) x num_queries == the REAL query indices [4, 23]
 *       (prover_s11_indices_zk.json — the transcript-state ground truth).
 *   T2  S12 input openings: open each retained input tree (random, trace,
 *       quotient batch) at each index and verify the opening roundtrips
 *       against the retained commit root (Merkle path production works).
 *   T3  S12 commit-phase openings: open the layer tree at group_index =
 *       index>>1 and verify against the S10 layer root; sibling = the
 *       (1-index&1)-th fp2 of the opened arity-2 row.
 *
 * The FULL query-proof byte-match happens implicitly in S13 (dnac_fri_verify).
 *
 * Build (via Makefile):
 *   make build/test_prover_s11_query
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
#define NUM_QUERIES 2u

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

int main(int argc, char **argv) {
    const char *s11 = "tools/vectors/prover_s11_indices_zk.json";
    const char *s8 = "tools/vectors/prover_s8_random_zk.json";
    const char *s7 = "tools/vectors/prover_s7_quotient_commit_zk.json";
    const char *s2 = "tools/vectors/prover_s2_lde_zk.json";
    if (argc >= 5) { s11 = argv[1]; s8 = argv[2]; s7 = argv[3]; s2 = argv[4]; }

    size_t a, b, c, d;
    char *j11 = load_file(s11, &a), *j8 = load_file(s8, &b),
         *j7 = load_file(s7, &c), *j2 = load_file(s2, &d);
    if (!j11 || !j8 || !j7 || !j2) {
        free(j11); free(j8); free(j7); free(j2);
        return 2;
    }
    printf("loaded 4 vectors\n");

    uint64_t idx_v[NUM_QUERIES];
    static uint64_t r_draws[RD], trace_draws[TRACE_DRAWS], codeword[CODEWORD],
        blinding[BLINDING];
    if (!parse_u64_array(j11, "query_indices", idx_v, NUM_QUERIES) ||
        !parse_u64_array(j8, "r_draws", r_draws, RD) ||
        !parse_u64_array(j7, "codeword_rand", codeword, CODEWORD) ||
        !parse_u64_array(j7, "blinding_rand", blinding, BLINDING) ||
        !parse_u64_array(j2, "random_draws", trace_draws, TRACE_DRAWS)) {
        fprintf(stderr, "vector parse FAIL\n");
        free(j11); free(j8); free(j7); free(j2);
        return 2;
    }

    int failed = 0;

    /* Chain S1->S10. */
    static uint64_t base_c[H * W], randomized_c[2u * H * RAND_W], lde_c[LDE_CELLS],
        trace_q[QS * W], qflat[2 * QS], chunk_ldes[NQ * CHUNK_LDE_CELLS],
        r_lde[R_LDE_CELLS];
    static uint64_t sf[QS], sl[QS], st[QS], iv[QS];
    static gold_fp2_t r_open[CW], t_open[RAND_W], t_open_n[RAND_W], q_open[NQ * CW];
    static gold_fp2_t ro[LDE_H];
    uint8_t troot[DNAC_MERKLE_DIGEST_BYTES], qroot[DNAC_MERKLE_DIGEST_BYTES],
        rroot[DNAC_MERKLE_DIGEST_BYTES];
    dnac_merkle_tree_t *ttree = NULL, *rtree = NULL;
    dnac_merkle_batch_tree_t *qtree = NULL;
    dnac_transcript_t *t = dnac_transcript_init_default();
    dnac_prover_fri_result_t res;
    memset(&res, 0, sizeof(res));
    gold_fp2_t alpha, zeta, zeta_next, fri_alpha;
    {
        const uint64_t amounts[4] = {10, 20, 30, 40};
        const uint64_t publics[3] = {107, 7, 4};
        if (!(t &&
              dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) == DNAC_PROVER_OK &&
              dnac_prover_randomize_trace(base_c, H, W, R, trace_draws, randomized_c) == DNAC_PROVER_OK &&
              dnac_prover_coset_lde_bitrev(randomized_c, 2 * H, RAND_W, 2, 7, lde_c) == DNAC_PROVER_OK &&
              dnac_prover_commit_matrix(lde_c, LDE_H, RAND_W, troot, &ttree) == DNAC_PROVER_OK &&
              dnac_prover_fs_to_alpha(t, 3, 2, 0, troot, publics, 3, &alpha) == DNAC_PROVER_OK &&
              dnac_prover_quotient_selectors(2, 4, 7, sf, sl, st, iv) == DNAC_PROVER_OK &&
              dnac_prover_trace_on_quotient_domain(lde_c, LDE_H, RAND_W, QS, W, trace_q) == DNAC_PROVER_OK &&
              dnac_prover_quotient_values_range_zk(trace_q, QS, 4, publics, alpha, sf, sl, st, iv, qflat) == DNAC_PROVER_OK &&
              dnac_prover_quotient_commit(qflat, QS, NQ, 4, 2, 7, codeword, blinding, chunk_ldes, qroot, &qtree) == DNAC_PROVER_OK &&
              dnac_prover_random_commit(r_draws, 8, CW, 2, r_lde, rroot, &rtree) == DNAC_PROVER_OK &&
              dnac_prover_fs_to_zeta(t, qroot, rroot, 2, &zeta, &zeta_next) == DNAC_PROVER_OK &&
              dnac_prover_open_matrix_at(r_lde, LDE_H, CW, 2, zeta, r_open) == DNAC_PROVER_OK &&
              dnac_prover_open_matrix_at(lde_c, LDE_H, RAND_W, 2, zeta, t_open) == DNAC_PROVER_OK &&
              dnac_prover_open_matrix_at(lde_c, LDE_H, RAND_W, 2, zeta_next, t_open_n) == DNAC_PROVER_OK)) {
            fprintf(stderr, "chain S1->S9 FAIL\n");
            free(j11); free(j8); free(j7); free(j2);
            return 2;
        }
        for (size_t k = 0; k < NQ; k++)
            dnac_prover_open_matrix_at(&chunk_ldes[k * CHUNK_LDE_CELLS], LDE_H, CW, 2, zeta, &q_open[k * CW]);
        dnac_prover_observe_opened(t, r_open, CW);
        dnac_prover_observe_opened(t, t_open, RAND_W);
        dnac_prover_observe_opened(t, t_open_n, RAND_W);
        for (size_t k = 0; k < NQ; k++)
            dnac_prover_observe_opened(t, &q_open[k * CW], CW);
        fri_alpha = dnac_transcript_sample_fp2(t);

        const gold_fp2_t zpts[2] = {zeta, zeta_next};
        const gold_fp2_t *r_ov[1] = {r_open};
        const gold_fp2_t *t_ov[2] = {t_open, t_open_n};
        const gold_fp2_t *q_ov[NQ][1];
        dnac_prover_fri_input_round_t rounds[2 + NQ];
        rounds[0] = (dnac_prover_fri_input_round_t){r_lde, LDE_H, CW, 1, &zeta, r_ov};
        rounds[1] = (dnac_prover_fri_input_round_t){lde_c, LDE_H, RAND_W, 2, zpts, t_ov};
        for (size_t k = 0; k < NQ; k++) {
            q_ov[k][0] = &q_open[k * CW];
            rounds[2 + k] = (dnac_prover_fri_input_round_t){&chunk_ldes[k * CHUNK_LDE_CELLS], LDE_H, CW, 1, &zeta, q_ov[k]};
        }
        if (dnac_prover_fri_reduced_openings(rounds, 2 + NQ, LOG_H, fri_alpha, ro) != DNAC_PROVER_OK ||
            dnac_prover_fri_commit_phase(ro, LDE_H, 2, 2, 1, t, &res) != DNAC_PROVER_OK) {
            fprintf(stderr, "commit phase FAIL\n");
            free(j11); free(j8); free(j7); free(j2);
            return 2;
        }
    }

    /* ---- T1: sample query indices == REAL [4, 23] ---- */
    uint64_t idx_c[NUM_QUERIES];
    {
        int bad = 0;
        for (size_t q = 0; q < NUM_QUERIES; q++) {
            idx_c[q] = dnac_transcript_sample_bits(t, LOG_H);
            if (idx_c[q] != idx_v[q]) {
                fprintf(stderr, "T1 index[%zu] C=%" PRIu64 " real=%" PRIu64 "\n",
                        q, idx_c[q], idx_v[q]);
                bad++;
            }
        }
        if (bad) failed++;
        printf("T1 query indices == REAL [%" PRIu64 ",%" PRIu64 "]            %s\n",
               idx_v[0], idx_v[1], bad ? "FAIL" : "PASS");
    }

    /* ---- T2: S12 input openings — open + verify each tree at each index ---- */
    {
        int bad = 0;
        dnac_merkle_digest_t troot_d, rroot_d, qroot_d;
        memcpy(troot_d.bytes, troot, 64);
        memcpy(rroot_d.bytes, rroot, 64);
        memcpy(qroot_d.bytes, qroot, 64);
        for (size_t q = 0; q < NUM_QUERIES; q++) {
            uint64_t index = idx_c[q];
            dnac_merkle_digest_t sib[5];
            dnac_merkle_proof_t pr;
            const uint8_t *leaf = NULL;
            size_t leaf_len = 0;
            /* random tree */
            memset(&pr, 0, sizeof(pr)); pr.siblings = sib; pr.depth = 5;
            if (dnac_merkle_open(rtree, index, &leaf, &leaf_len, &pr) != DNAC_MERKLE_OK ||
                leaf_len != CW * 8 ||
                dnac_merkle_verify(&rroot_d, leaf, leaf_len, &pr) != DNAC_MERKLE_OK)
                bad++;
            /* trace tree */
            memset(&pr, 0, sizeof(pr)); pr.siblings = sib; pr.depth = 5;
            if (dnac_merkle_open(ttree, index, &leaf, &leaf_len, &pr) != DNAC_MERKLE_OK ||
                leaf_len != RAND_W * 8 ||
                dnac_merkle_verify(&troot_d, leaf, leaf_len, &pr) != DNAC_MERKLE_OK)
                bad++;
            /* quotient batch tree (4 matrices) */
            memset(&pr, 0, sizeof(pr)); pr.siblings = sib; pr.depth = 5;
            const uint8_t *rows[NQ];
            size_t row_lens[NQ];
            if (dnac_merkle_batch_open(qtree, index, rows, &pr) != DNAC_MERKLE_OK)
                bad++;
            else {
                for (size_t m = 0; m < NQ; m++) row_lens[m] = CW * 8;
                if (dnac_merkle_batch_verify(&qroot_d, rows, row_lens, NQ, LDE_H, &pr) != DNAC_MERKLE_OK)
                    bad++;
            }
        }
        if (bad) failed++;
        printf("T2 input openings (random/trace/quotient) verify       %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T3: S12 commit-phase openings — layer tree at group_index ---- */
    {
        int bad = 0;
        dnac_merkle_digest_t cproot_d;
        memcpy(cproot_d.bytes, res.roots[0], 64);
        for (size_t q = 0; q < NUM_QUERIES; q++) {
            uint64_t group_index = idx_c[q] >> 1; /* log_arity 1 */
            dnac_merkle_digest_t sib[4]; /* height-16 tree depth 4 */
            dnac_merkle_proof_t pr;
            memset(&pr, 0, sizeof(pr)); pr.siblings = sib; pr.depth = 4;
            const uint8_t *leaf = NULL;
            size_t leaf_len = 0;
            if (dnac_merkle_open(res.layer_trees[0], group_index, &leaf, &leaf_len, &pr) != DNAC_MERKLE_OK ||
                leaf_len != 4 * 8 || /* arity 2 fp2 = 4 base u64 */
                dnac_merkle_verify(&cproot_d, leaf, leaf_len, &pr) != DNAC_MERKLE_OK)
                bad++;
        }
        if (bad) failed++;
        printf("T3 commit-phase openings verify (layer tree)           %s\n",
               bad ? "FAIL" : "PASS");
    }

    dnac_prover_fri_result_free(&res);
    dnac_transcript_free(t);
    dnac_merkle_tree_free(ttree);
    dnac_merkle_tree_free(rtree);
    dnac_merkle_batch_tree_free(qtree);
    free(j11); free(j8); free(j7); free(j2);
    if (failed == 0) {
        printf("test_prover_s11_query: PASS\n");
        printf("S11+S12 PROVER-QUERY GATE: GREEN — C samples the REAL query "
               "indices after the commit phase + produces valid Merkle query "
               "openings from the retained trees (Plonky3 82cfad73)\n");
        return 0;
    }
    printf("S11+S12 PROVER-QUERY GATE: RED — %d failures\n", failed);
    return 1;
}
