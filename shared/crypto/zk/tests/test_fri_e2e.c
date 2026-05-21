/**
 * @file test_fri_e2e.c
 * @brief End-to-end FRI prove → verify self-test (Sub-sprint 2.3).
 *
 * Tests:
 *   1. Commit + open + verify on a low-degree input → assert ACCEPT.
 *   2. Tamper opening's lo_value → assert REJECT.
 *   3. Tamper opening's Merkle path → assert REJECT.
 *   4. Tamper a layer root in commit output → assert REJECT.
 *   5. Tamper beta → assert REJECT.
 *   6. Mismatched transcript init → assert REJECT (verifier draws different
 *      query indices and fails position check).
 *
 * Does NOT cross-validate against Plonky3 oracle bytes — fri_commit (1.4 + 2.2)
 * already byte-locks the layer roots + betas, and fri_fold (2.1) byte-locks
 * the fold math. This test exercises the prover-verifier protocol assembly
 * and adversarial tamper rejection.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../merkle_smt.h"
#include "../transcript.h"
#include "../fri_commit.h"
#include "../fri_query.h"
#include "../fri_fold.h"

/* ============================================================================
 * Test fixture: a known low-degree polynomial evaluated on a coset.
 * ========================================================================== */

static gold_fp2_t mk_fp2(uint64_t a, uint64_t b) {
    return gold_fp2_new(gold_fp_from_u64(a), gold_fp_from_u64(b));
}

/* Generate a synthetic input layer of size 2^log_size.
 * Values are deterministic but not actually low-degree — FRI test still works
 * because we're testing the protocol, not the soundness against high-degree
 * inputs. (Soundness is a probabilistic statement about random query positions;
 * for our self-test with completeness-only assertions, any input works as long
 * as prover and verifier process it consistently.) */
static void generate_layer(uint32_t log_size, uint64_t seed, gold_fp2_t *out) {
    uint32_t n = 1u << log_size;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t a = (seed * 0x9E3779B97F4A7C15ULL) ^ ((uint64_t)i * 0xBF58476D1CE4E5B9ULL);
        uint64_t b = (seed * 0xC2B2AE3D27D4EB4FULL) ^ ((uint64_t)(i + 1) * 0x94D049BB133111EBULL);
        out[i] = mk_fp2(a, b);
    }
}

/* ============================================================================
 * Setup helpers
 * ========================================================================== */

typedef struct {
    uint32_t initial_log_size;
    uint32_t cap_height_log;
    uint32_t num_queries;
    gold_fp2_t *initial_values;
    /* Captured intermediate layers (each layer's values BEFORE its fold).
     * all_layers[0] = initial_values
     * all_layers[i] = layer i values (size = 2^(initial_log - i)) for i in 0..num_layers-1
     * Index num_layers is the final layer = commit.final_values.
     * We retain num_layers pointers so the prover can open Merkle paths in each. */
    gold_fp2_t **all_layers;
    uint32_t num_layers;
} fri_setup_t;

/* Run commit phase AND capture all intermediate layer values for proof opening.
 *
 * This is a debug/test version of the commit phase that retains all layers.
 * The production fri_commit_phase only emits Merkle roots + final values to
 * save memory; here we keep everything for prover-side Merkle proof building. */
static int run_commit_capture(transcript_t *t,
                              const gold_fp2_t *initial_values,
                              uint32_t initial_log_size,
                              uint32_t cap_height_log,
                              fri_commit_output_t *out,
                              gold_fp2_t ***out_all_layers,
                              uint32_t *out_num_layers) {
    uint32_t num_layers = initial_log_size - cap_height_log;
    gold_fp2_t **all = (gold_fp2_t **)calloc(num_layers + 1, sizeof(gold_fp2_t *));
    if (!all) return -1;

    /* Copy initial layer. */
    size_t cur_size = 1u << initial_log_size;
    all[0] = (gold_fp2_t *)malloc(cur_size * sizeof(gold_fp2_t));
    memcpy(all[0], initial_values, cur_size * sizeof(gold_fp2_t));

    uint32_t cur_log = initial_log_size;
    out->num_layers = 0;

    /* Worst-case halve_inv_powers. */
    size_t max_h = (size_t)1 << (initial_log_size - 1);
    gold_fp_t *hip = (gold_fp_t *)malloc(max_h * sizeof(gold_fp_t));
    if (!hip) { free(all[0]); free(all); return -1; }

    while (cur_log > cap_height_log) {
        gold_fp2_t *cur = all[out->num_layers];
        size_t layer_size = (size_t)1 << cur_log;

        /* Compute layer root. */
        uint8_t *leaves = (uint8_t *)malloc(layer_size * MERKLE_SMT_HASH_SIZE);
        for (size_t i = 0; i < layer_size; i++) {
            uint8_t buf[16];
            uint64_t a = gold_fp_to_u64(cur[i].a);
            uint64_t b = gold_fp_to_u64(cur[i].b);
            for (int k = 0; k < 8; k++) buf[k]   = (uint8_t)((a >> (56 - 8 * k)) & 0xff);
            for (int k = 0; k < 8; k++) buf[8+k] = (uint8_t)((b >> (56 - 8 * k)) & 0xff);
            merkle_smt_hash_leaf((uint32_t)i, buf, 16, leaves + i * MERKLE_SMT_HASH_SIZE);
        }
        merkle_smt_compute_root(leaves, layer_size, cur_log,
                                out->layer_roots[out->num_layers]);
        free(leaves);

        transcript_absorb(t, out->layer_roots[out->num_layers], MERKLE_SMT_HASH_SIZE);
        gold_fp2_t beta = transcript_challenge_fp2(t);
        out->layer_betas[out->num_layers] = beta;

        /* halve_inv_powers. */
        size_t h = layer_size / 2;
        gold_fp_t g = gold_fp_two_adic_generator(cur_log);
        gold_fp_t g_inv = gold_fp_inv(g);
        gold_fp_t two = gold_fp_from_u64(2);
        gold_fp_t half = gold_fp_inv(two);
        gold_fp_t acc = half;
        for (size_t i = 0; i < h; i++) { hip[i] = acc; acc = gold_fp_mul(acc, g_inv); }

        /* Allocate next layer + fold. */
        all[out->num_layers + 1] = (gold_fp2_t *)malloc(h * sizeof(gold_fp2_t));
        fri_fold_arity2(cur, hip, beta, h, all[out->num_layers + 1]);

        out->num_layers++;
        cur_log -= 1;
    }
    out->final_log_size = cur_log;
    /* Copy final layer to out->final_values (caller-owned). */
    size_t final_size = (size_t)1 << cur_log;
    memcpy(out->final_values, all[out->num_layers], final_size * sizeof(gold_fp2_t));

    free(hip);
    *out_all_layers = all;
    *out_num_layers = out->num_layers;
    return 0;
}

static void free_all_layers(gold_fp2_t **all, uint32_t num_layers) {
    if (!all) return;
    for (uint32_t i = 0; i <= num_layers; i++) free(all[i]);
    free(all);
}

/* ============================================================================
 * Helper: init transcript with a fixed test config
 * ========================================================================== */

static void init_test_transcript(transcript_t *t, uint64_t seed) {
    uint8_t chain_id[32];
    for (int i = 0; i < 32; i++) chain_id[i] = (uint8_t)(seed * 31 + i);
    uint8_t pubin[] = "FRI_E2E_TEST";
    transcript_init(t, chain_id, seed * 1000, (uint32_t)(seed & 0xFFFF),
                    pubin, sizeof(pubin));
}

/* ============================================================================
 * Test bodies
 * ========================================================================== */

static int run_commit_and_open(uint32_t initial_log_size,
                               uint32_t cap_height_log,
                               uint32_t num_queries,
                               uint64_t seed,
                               fri_commit_output_t *out_commit,
                               gold_fp2_t **out_initial,
                               gold_fp2_t ***out_all_layers,
                               uint32_t *out_num_layers,
                               fri_query_proof_t **out_proofs) {
    /* Generate input. */
    uint32_t initial_size = 1u << initial_log_size;
    gold_fp2_t *initial = (gold_fp2_t *)malloc(initial_size * sizeof(gold_fp2_t));
    generate_layer(initial_log_size, seed, initial);

    /* Prepare commit output. */
    uint32_t final_size = 1u << cap_height_log;
    out_commit->final_values = (gold_fp2_t *)malloc(final_size * sizeof(gold_fp2_t));

    /* Run commit phase with intermediate layer capture. */
    transcript_t t_prove;
    init_test_transcript(&t_prove, seed);
    if (run_commit_capture(&t_prove, initial, initial_log_size, cap_height_log,
                           out_commit, out_all_layers, out_num_layers) != 0) {
        free(initial); return -1;
    }

    /* Open queries. */
    *out_proofs = (fri_query_proof_t *)calloc(num_queries, sizeof(fri_query_proof_t));
    if (fri_query_open(&t_prove, *out_all_layers, initial_log_size, cap_height_log,
                       num_queries, *out_proofs) != 0) {
        free(initial); return -1;
    }
    *out_initial = initial;
    return 0;
}

static bool verify_with_fresh_transcript(uint64_t seed,
                                         uint32_t initial_log_size,
                                         const fri_commit_output_t *commit,
                                         const fri_query_proof_t *proofs,
                                         uint32_t num_queries) {
    transcript_t t_verify;
    init_test_transcript(&t_verify, seed);
    /* Replay commit phase absorbs to get to post-commit state. */
    for (uint32_t i = 0; i < commit->num_layers; i++) {
        transcript_absorb(&t_verify, commit->layer_roots[i], MERKLE_SMT_HASH_SIZE);
        /* Burn the same challenge_fp2 to advance counter. */
        (void)transcript_challenge_fp2(&t_verify);
    }
    return fri_query_verify(&t_verify, commit, proofs, num_queries);
    (void)initial_log_size;
}

typedef struct {
    const char *label;
    bool expected_pass;
    int passed; /* output */
} test_case_t;

static int run_full_suite(uint32_t initial_log_size, uint32_t cap_height_log,
                          uint32_t num_queries, uint64_t seed,
                          int *out_passed, int *out_failed) {
    fri_commit_output_t commit = {0};
    gold_fp2_t *initial = NULL;
    gold_fp2_t **all_layers = NULL;
    uint32_t num_layers = 0;
    fri_query_proof_t *proofs = NULL;

    if (run_commit_and_open(initial_log_size, cap_height_log, num_queries, seed,
                            &commit, &initial, &all_layers, &num_layers,
                            &proofs) != 0) {
        fprintf(stderr, "  prove failed\n");
        return -1;
    }

    int passed = 0, failed = 0;

    /* Test 1: clean verify should ACCEPT. */
    {
        bool ok = verify_with_fresh_transcript(seed, initial_log_size,
                                               &commit, proofs, num_queries);
        printf("  T1 clean prove+verify:   %s\n", ok ? "PASS" : "FAIL");
        if (ok) passed++; else failed++;
    }

    /* Test 2: tamper lo_value of first query, first layer. */
    {
        fri_query_proof_t saved = proofs[0];
        proofs[0].layers[0].lo_value =
            gold_fp2_add(proofs[0].layers[0].lo_value, gold_fp2_one());
        bool ok = verify_with_fresh_transcript(seed, initial_log_size,
                                               &commit, proofs, num_queries);
        proofs[0] = saved;
        printf("  T2 tamper lo_value:      %s (REJECT expected)\n", ok ? "ACCEPTED bad!" : "REJECTED ok");
        if (!ok) passed++; else failed++;
    }

    /* Test 3: tamper Merkle path. */
    {
        fri_query_proof_t saved = proofs[0];
        proofs[0].layers[0].lo_path.path[0][0] ^= 0x01;
        bool ok = verify_with_fresh_transcript(seed, initial_log_size,
                                               &commit, proofs, num_queries);
        proofs[0] = saved;
        printf("  T3 tamper Merkle path:   %s (REJECT expected)\n", ok ? "ACCEPTED bad!" : "REJECTED ok");
        if (!ok) passed++; else failed++;
    }

    /* Test 4: tamper layer root in commit output. */
    {
        uint8_t saved_root[MERKLE_SMT_HASH_SIZE];
        memcpy(saved_root, commit.layer_roots[0], MERKLE_SMT_HASH_SIZE);
        commit.layer_roots[0][0] ^= 0x01;
        bool ok = verify_with_fresh_transcript(seed, initial_log_size,
                                               &commit, proofs, num_queries);
        memcpy(commit.layer_roots[0], saved_root, MERKLE_SMT_HASH_SIZE);
        printf("  T4 tamper layer root:    %s (REJECT expected)\n", ok ? "ACCEPTED bad!" : "REJECTED ok");
        if (!ok) passed++; else failed++;
    }

    /* Test 5: tamper beta. */
    {
        gold_fp2_t saved_beta = commit.layer_betas[0];
        commit.layer_betas[0] = gold_fp2_add(commit.layer_betas[0], gold_fp2_one());
        bool ok = verify_with_fresh_transcript(seed, initial_log_size,
                                               &commit, proofs, num_queries);
        commit.layer_betas[0] = saved_beta;
        printf("  T5 tamper beta:          %s (REJECT expected)\n", ok ? "ACCEPTED bad!" : "REJECTED ok");
        if (!ok) passed++; else failed++;
    }

    /* Test 6: wrong transcript seed → verifier samples different indices,
     * position-check should fail. */
    {
        bool ok = verify_with_fresh_transcript(seed + 1, initial_log_size,
                                               &commit, proofs, num_queries);
        printf("  T6 wrong transcript:     %s (REJECT expected)\n", ok ? "ACCEPTED bad!" : "REJECTED ok");
        if (!ok) passed++; else failed++;
    }

    /* Cleanup. */
    free(initial);
    free_all_layers(all_layers, num_layers);
    free(proofs);
    free(commit.final_values);

    *out_passed += passed;
    *out_failed += failed;
    return 0;
}

int main(void) {
    int total_passed = 0, total_failed = 0;

    struct { uint32_t init_log; uint32_t cap_log; uint32_t nq; uint64_t seed; } configs[] = {
        {6, 2, 3, 11},
        {8, 2, 5, 22},
        {10, 4, 8, 33},
    };

    for (size_t ci = 0; ci < sizeof(configs)/sizeof(configs[0]); ci++) {
        printf("\nConfig: init_log=%u cap_log=%u num_queries=%u seed=%llu\n",
               configs[ci].init_log, configs[ci].cap_log, configs[ci].nq,
               (unsigned long long)configs[ci].seed);
        run_full_suite(configs[ci].init_log, configs[ci].cap_log,
                       configs[ci].nq, configs[ci].seed,
                       &total_passed, &total_failed);
    }

    printf("\nTotal: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 2.3 (fri_e2e) GATE: GREEN — prove+verify works; all tamper attempts rejected\n");
        return 0;
    } else {
        printf("SUB-SPRINT 2.3 (fri_e2e) GATE: RED — %d failures\n", total_failed);
        return 1;
    }
}
