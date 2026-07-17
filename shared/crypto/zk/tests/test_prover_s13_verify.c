/**
 * @file test_prover_s13_verify.c
 * @brief S13 (C prover) — MILESTONE: C prove -> C verify == DNAC_FRI_OK.
 *
 * Runs the ENTIRE C prover S1->S12 for the M3a is_zk=1 RangeProofAir instance,
 * assembles the priming input + 3-round coms + dnac_fri_proof_t from its own
 * outputs (no Rust, no oracle JSON for the proof body), then:
 *
 *   1. dnac_transcript_init("DNAC|ZK|FRI|TRANSCRIPT|V1")
 *   2. dnac_stark_prime_transcript(is_zk=1)  — cross-check out.zeta/zeta_next
 *      == the prover's own zeta/zeta_next (fail-close on any divergence)
 *   3. build coms with out.zeta/out.zeta_next
 *   4. dnac_fri_verify(...) == DNAC_FRI_OK
 *
 * This is the Rust-free, end-to-end confidential-amount demo: hidden amounts,
 * range+balance proven, C-proved and C-verified.
 *
 * Build (via Makefile):
 *   make build/test_prover_s13_verify
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
#include "../fri_verifier.h"
#include "../stark_priming.h"
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
#define INPUT_DEPTH 5u
#define CP_DEPTH 4u

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
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p != '"') return false;
        p++;
        if (*p < '0' || *p > '9') return false;
        out[i] = strtoull(p, (char **)&p, 10);
        if (*p != '"') return false;
        p++;
    }
    return true;
}

/* Per-query proof storage. */
typedef struct {
    /* input batches: [0]=random (1 mat), [1]=trace (1 mat), [2]=quotient (4 mats) */
    gold_fp_t rand_row[CW];
    gold_fp_t trace_row[RAND_W];
    gold_fp_t quot_row[NQ][CW];
    const gold_fp_t *rand_rowptr[1];
    const gold_fp_t *trace_rowptr[1];
    const gold_fp_t *quot_rowptr[NQ];
    size_t rand_len[1], trace_len[1], quot_len[NQ];
    dnac_merkle_digest_t rand_sib[INPUT_DEPTH], trace_sib[INPUT_DEPTH],
        quot_sib[INPUT_DEPTH];
    dnac_fri_batch_opening_t batches[3];
    /* commit-phase step */
    gold_fp2_t cp_sib[1];
    dnac_merkle_digest_t cp_psib[CP_DEPTH];
    dnac_fri_commit_phase_proof_step_t cp[1];
    dnac_fri_query_proof_t qp;
} query_store_t;

int main(int argc, char **argv) {
    const char *s8 = "tools/vectors/prover_s8_random_zk.json";
    const char *s7 = "tools/vectors/prover_s7_quotient_commit_zk.json";
    const char *s2 = "tools/vectors/prover_s2_lde_zk.json";
    if (argc >= 4) { s8 = argv[1]; s7 = argv[2]; s2 = argv[3]; }

    size_t b, c, d;
    char *j8 = load_file(s8, &b), *j7 = load_file(s7, &c), *j2 = load_file(s2, &d);
    if (!j8 || !j7 || !j2) { free(j8); free(j7); free(j2); return 2; }

    static uint64_t r_draws[RD], trace_draws[TRACE_DRAWS], codeword[CODEWORD],
        blinding[BLINDING];
    if (!parse_u64_array(j8, "r_draws", r_draws, RD) ||
        !parse_u64_array(j7, "codeword_rand", codeword, CODEWORD) ||
        !parse_u64_array(j7, "blinding_rand", blinding, BLINDING) ||
        !parse_u64_array(j2, "random_draws", trace_draws, TRACE_DRAWS)) {
        fprintf(stderr, "vector parse FAIL\n");
        free(j8); free(j7); free(j2);
        return 2;
    }

    /* ===== FULL C PROVER CHAIN S1->S12 ===== */
    static uint64_t base_c[H * W], randomized_c[2u * H * RAND_W], lde_c[LDE_CELLS],
        trace_q[QS * W], qflat[2 * QS], chunk_ldes[NQ * CHUNK_LDE_CELLS],
        r_lde[R_LDE_CELLS];
    static uint64_t sf[QS], sl[QS], st[QS], iv[QS];
    static gold_fp2_t r_open[CW], t_open[RAND_W], t_open_n[RAND_W], q_open[NQ * CW];
    static gold_fp2_t ro[LDE_H];
    uint8_t troot[64], qroot[64], rroot[64];
    dnac_merkle_tree_t *ttree = NULL, *rtree = NULL;
    dnac_merkle_batch_tree_t *qtree = NULL;
    dnac_transcript_t *t = dnac_transcript_init_default();
    dnac_prover_fri_result_t res;
    memset(&res, 0, sizeof(res));
    gold_fp2_t alpha, zeta, zeta_next, fri_alpha;
    const uint64_t amounts[4] = {10, 20, 30, 40};
    const uint64_t publics_u[3] = {107, 7, 4};
    if (!(t &&
          dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) == DNAC_PROVER_OK &&
          dnac_prover_randomize_trace(base_c, H, W, R, trace_draws, randomized_c) == DNAC_PROVER_OK &&
          dnac_prover_coset_lde_bitrev(randomized_c, 2 * H, RAND_W, 2, 7, lde_c) == DNAC_PROVER_OK &&
          dnac_prover_commit_matrix(lde_c, LDE_H, RAND_W, NULL, 0, troot, &ttree) == DNAC_PROVER_OK &&
          dnac_prover_fs_to_alpha(t, 3, 2, 0, troot, publics_u, 3, &alpha) == DNAC_PROVER_OK &&
          dnac_prover_quotient_selectors(2, 4, 7, sf, sl, st, iv) == DNAC_PROVER_OK &&
          dnac_prover_trace_on_quotient_domain(lde_c, LDE_H, RAND_W, QS, W, trace_q) == DNAC_PROVER_OK &&
          dnac_prover_quotient_values_range_zk(trace_q, QS, 4, publics_u, alpha, sf, sl, st, iv, qflat) == DNAC_PROVER_OK &&
          dnac_prover_quotient_commit(qflat, QS, NQ, 4, 2, 7, codeword, blinding, NULL, 0, chunk_ldes, qroot, &qtree) == DNAC_PROVER_OK &&
          dnac_prover_random_commit(r_draws, 8, CW, 2, NULL, 0, r_lde, rroot, &rtree) == DNAC_PROVER_OK &&
          dnac_prover_fs_to_zeta(t, qroot, rroot, 2, &zeta, &zeta_next) == DNAC_PROVER_OK &&
          dnac_prover_open_matrix_at(r_lde, LDE_H, CW, 2, zeta, r_open) == DNAC_PROVER_OK &&
          dnac_prover_open_matrix_at(lde_c, LDE_H, RAND_W, 2, zeta, t_open) == DNAC_PROVER_OK &&
          dnac_prover_open_matrix_at(lde_c, LDE_H, RAND_W, 2, zeta_next, t_open_n) == DNAC_PROVER_OK)) {
        fprintf(stderr, "prover chain S1->S9 FAIL\n");
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
    {
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
            dnac_prover_fri_commit_phase(ro, LDE_H, 2, 2, 1, 0, 0, NULL, 0, t, &res) != DNAC_PROVER_OK) {
            fprintf(stderr, "commit phase FAIL\n");
            return 2;
        }
    }
    /* sample query indices (S11) */
    uint64_t qidx[NUM_QUERIES];
    for (size_t q = 0; q < NUM_QUERIES; q++)
        qidx[q] = dnac_transcript_sample_bits(t, LOG_H);
    dnac_transcript_free(t);
    t = NULL;

    /* ===== S12: build per-query openings into proof structures ===== */
    static query_store_t qs[NUM_QUERIES];
    static dnac_fri_query_proof_t query_proofs[NUM_QUERIES];
    for (size_t q = 0; q < NUM_QUERIES; q++) {
        query_store_t *Q = &qs[q];
        uint64_t index = qidx[q];
        dnac_merkle_proof_t pr;
        const uint8_t *leaf = NULL;
        size_t leaf_len = 0;
        /* batch 0: random (1 matrix) */
        for (size_t i = 0; i < CW; i++) Q->rand_row[i] = gold_fp_from_u64(r_lde[index * CW + i]);
        Q->rand_rowptr[0] = Q->rand_row; Q->rand_len[0] = CW;
        memset(&pr, 0, sizeof(pr)); pr.siblings = Q->rand_sib; pr.depth = INPUT_DEPTH;
        dnac_merkle_open(rtree, index, &leaf, &leaf_len, &pr);
        Q->batches[0].opened_values = Q->rand_rowptr; Q->batches[0].opened_values_lens = Q->rand_len;
        Q->batches[0].num_matrices = 1;
        Q->batches[0].opening_proof.leaf_index = 0; Q->batches[0].opening_proof.depth = INPUT_DEPTH;
        Q->batches[0].opening_proof.num_matrices = 1; Q->batches[0].opening_proof.siblings = Q->rand_sib;
        /* batch 1: trace (1 matrix) */
        for (size_t i = 0; i < RAND_W; i++) Q->trace_row[i] = gold_fp_from_u64(lde_c[index * RAND_W + i]);
        Q->trace_rowptr[0] = Q->trace_row; Q->trace_len[0] = RAND_W;
        memset(&pr, 0, sizeof(pr)); pr.siblings = Q->trace_sib; pr.depth = INPUT_DEPTH;
        dnac_merkle_open(ttree, index, &leaf, &leaf_len, &pr);
        Q->batches[1].opened_values = Q->trace_rowptr; Q->batches[1].opened_values_lens = Q->trace_len;
        Q->batches[1].num_matrices = 1;
        Q->batches[1].opening_proof.leaf_index = 0; Q->batches[1].opening_proof.depth = INPUT_DEPTH;
        Q->batches[1].opening_proof.num_matrices = 1; Q->batches[1].opening_proof.siblings = Q->trace_sib;
        /* batch 2: quotient (4 matrices, shared path) */
        for (size_t m = 0; m < NQ; m++) {
            for (size_t i = 0; i < CW; i++)
                Q->quot_row[m][i] = gold_fp_from_u64(chunk_ldes[m * CHUNK_LDE_CELLS + index * CW + i]);
            Q->quot_rowptr[m] = Q->quot_row[m]; Q->quot_len[m] = CW;
        }
        {
            const uint8_t *rows[NQ];
            memset(&pr, 0, sizeof(pr)); pr.siblings = Q->quot_sib; pr.depth = INPUT_DEPTH;
            dnac_merkle_batch_open(qtree, index, rows, &pr);
        }
        Q->batches[2].opened_values = Q->quot_rowptr; Q->batches[2].opened_values_lens = Q->quot_len;
        Q->batches[2].num_matrices = NQ;
        Q->batches[2].opening_proof.leaf_index = 0; Q->batches[2].opening_proof.depth = INPUT_DEPTH;
        Q->batches[2].opening_proof.num_matrices = NQ; Q->batches[2].opening_proof.siblings = Q->quot_sib;

        /* commit-phase step (1 round, log_arity 1) */
        uint64_t group_index = index >> 1;
        uint64_t in_group = index & 1;
        Q->cp_sib[0] = res.layer_leaves[0][group_index * 2 + (1 - in_group)];
        memset(&pr, 0, sizeof(pr)); pr.siblings = Q->cp_psib; pr.depth = CP_DEPTH;
        dnac_merkle_open(res.layer_trees[0], group_index, &leaf, &leaf_len, &pr);
        Q->cp[0].log_arity = 1; Q->cp[0].sibling_values = Q->cp_sib; Q->cp[0].num_sibling_values = 1;
        Q->cp[0].opening_proof.leaf_index = 0; Q->cp[0].opening_proof.depth = CP_DEPTH;
        Q->cp[0].opening_proof.num_matrices = 1; Q->cp[0].opening_proof.siblings = Q->cp_psib;

        Q->qp.input_proof = Q->batches; Q->qp.num_input_batches = 3;
        Q->qp.commit_phase_openings = Q->cp; Q->qp.num_commit_phase_openings = 1;
        query_proofs[q] = Q->qp;
    }

    /* ===== assemble dnac_fri_proof_t ===== */
    dnac_fri_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    static dnac_merkle_digest_t cp_commits[DNAC_PROVER_MAX_FRI_ROUNDS];
    for (size_t r = 0; r < res.num_rounds; r++)
        memcpy(cp_commits[r].bytes, res.roots[r], 64);
    static gold_fp_t commit_pow[DNAC_PROVER_MAX_FRI_ROUNDS]; /* all 0 */
    proof.commit_phase_commits = cp_commits; proof.num_commit_phase_commits = res.num_rounds;
    proof.commit_pow_witnesses = commit_pow; proof.num_commit_pow_witnesses = res.num_rounds;
    proof.query_proofs = query_proofs; proof.num_query_proofs = NUM_QUERIES;
    proof.final_poly = res.final_poly; proof.num_final_poly = res.final_poly_len;
    proof.query_pow_witness = gold_fp_from_u64(0);

    /* ===== priming input ===== */
    static gold_fp_t publics[3];
    for (size_t i = 0; i < 3; i++) publics[i] = gold_fp_from_u64(publics_u[i]);
    dnac_merkle_digest_t trace_c, quot_c, rand_c;
    memcpy(trace_c.bytes, troot, 64);
    memcpy(quot_c.bytes, qroot, 64);
    memcpy(rand_c.bytes, rroot, 64);

    dnac_stark_priming_input_t in;
    memset(&in, 0, sizeof(in));
    in.degree_bits = 3; in.is_zk = 1; in.preprocessed_width = 0;
    in.trace_commit = trace_c; in.quotient_commit = quot_c; in.random_commit = &rand_c;
    in.random_local = r_open; in.random_local_len = CW;
    in.public_values = publics; in.num_public_values = 3;
    in.trace_local = t_open; in.trace_local_len = RAND_W;
    in.trace_next = t_open_n; in.trace_next_len = RAND_W;
    const gold_fp2_t *qcptr[NQ]; size_t qclen[NQ];
    for (size_t k = 0; k < NQ; k++) { qcptr[k] = &q_open[k * CW]; qclen[k] = CW; }
    in.quotient_chunks = qcptr; in.quotient_chunk_lens = qclen; in.num_quotient_chunks = NQ;

    /* ===== prime + cross-check zeta ===== */
    dnac_transcript_t *vt =
        dnac_transcript_init((const uint8_t *)"DNAC|ZK|FRI|TRANSCRIPT|V1", 25);
    dnac_stark_priming_out_t out;
    memset(&out, 0, sizeof(out));
    int failed = 0;
    if (dnac_stark_prime_transcript(vt, &in, &out) != DNAC_STARK_PRIMING_OK) {
        fprintf(stderr, "priming FAILED\n");
        failed++;
    }
    int zbad = !(gold_fp_to_u64(out.zeta.a) == gold_fp_to_u64(zeta.a) &&
                 gold_fp_to_u64(out.zeta.b) == gold_fp_to_u64(zeta.b) &&
                 gold_fp_to_u64(out.zeta_next.a) == gold_fp_to_u64(zeta_next.a) &&
                 gold_fp_to_u64(out.zeta_next.b) == gold_fp_to_u64(zeta_next.b));
    if (zbad) failed++;
    printf("T1 priming out.zeta/zeta_next == prover zeta            %s\n",
           zbad ? "FAIL" : "PASS");

    /* ===== build coms + dnac_fri_verify (THE MILESTONE) ===== */
    dnac_fri_opening_point_t rand_pt[1], trace_pt[2], quot_pt[NQ];
    dnac_fri_matrix_openings_t rand_mx, trace_mx, quot_mx[NQ];
    dnac_fri_commitment_with_opening_points_t coms[3];
    rand_pt[0].point = out.zeta; rand_pt[0].claimed_evals = r_open; rand_pt[0].num_claimed_evals = CW;
    rand_mx.domain.shift = gold_fp_from_u64(0); rand_mx.domain.shift_inverse = gold_fp_from_u64(0);
    rand_mx.domain.log_size = 3; rand_mx.points = rand_pt; rand_mx.num_points = 1;
    coms[0].commitment = rand_c; coms[0].matrices = &rand_mx; coms[0].num_matrices = 1;
    trace_pt[0].point = out.zeta; trace_pt[0].claimed_evals = t_open; trace_pt[0].num_claimed_evals = RAND_W;
    trace_pt[1].point = out.zeta_next; trace_pt[1].claimed_evals = t_open_n; trace_pt[1].num_claimed_evals = RAND_W;
    trace_mx.domain.shift = gold_fp_from_u64(0); trace_mx.domain.shift_inverse = gold_fp_from_u64(0);
    trace_mx.domain.log_size = 3; trace_mx.points = trace_pt; trace_mx.num_points = 2;
    coms[1].commitment = trace_c; coms[1].matrices = &trace_mx; coms[1].num_matrices = 1;
    for (size_t k = 0; k < NQ; k++) {
        quot_pt[k].point = out.zeta; quot_pt[k].claimed_evals = &q_open[k * CW]; quot_pt[k].num_claimed_evals = CW;
        quot_mx[k].domain.shift = gold_fp_from_u64(0); quot_mx[k].domain.shift_inverse = gold_fp_from_u64(0);
        quot_mx[k].domain.log_size = 3; quot_mx[k].points = &quot_pt[k]; quot_mx[k].num_points = 1;
    }
    coms[2].commitment = quot_c; coms[2].matrices = quot_mx; coms[2].num_matrices = NQ;

    dnac_fri_params_t params;
    memset(&params, 0, sizeof(params));
    params.log_blowup = 2; params.log_final_poly_len = 2; params.max_log_arity = 1;
    params.num_queries = 2; params.commit_proof_of_work_bits = 0; params.query_proof_of_work_bits = 0;

    dnac_fri_status_t fs = dnac_fri_verify(&params, &proof, vt, coms, 3);
    dnac_transcript_free(vt);
    if (fs != DNAC_FRI_OK) {
        fprintf(stderr, "MILESTONE GATE FAILED: dnac_fri_verify -> %d (want 0)\n", (int)fs);
        failed++;
    }
    printf("T2 MILESTONE: C prove -> dnac_fri_verify == DNAC_FRI_OK  %s\n",
           (fs == DNAC_FRI_OK) ? "PASS" : "FAIL");

    dnac_prover_fri_result_free(&res);
    dnac_merkle_tree_free(ttree);
    dnac_merkle_tree_free(rtree);
    dnac_merkle_batch_tree_free(qtree);
    free(j8); free(j7); free(j2);
    if (failed == 0) {
        printf("test_prover_s13_verify: PASS\n");
        printf("S13 MILESTONE GATE: GREEN — the pure-C prover produces an "
               "is_zk=1 RangeProofAir proof (hidden amounts) that the C "
               "verifier accepts (DNAC_FRI_OK). Rust-free, end-to-end.\n");
        return 0;
    }
    printf("S13 MILESTONE GATE: RED — %d failures\n", failed);
    return 1;
}
