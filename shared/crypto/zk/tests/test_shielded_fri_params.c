/**
 * @file test_shielded_fri_params.c
 * @brief S0/C5 — the pinned shielded FRI parameter set and its exact compare.
 *
 * Asserts (and ONLY these two — see the coverage note below):
 *   1. dnac_shielded_fri_params() == the grounded new_benchmark_zk set
 *      (config.rs:102-113): log_blowup=2, log_final_poly_len=0, max_log_arity=1,
 *      num_queries=100, commit_pow=0, query_pow=16; conjectured soundness
 *      = log_blowup·num_queries + query_pow = 216 ≥ target 100. Plus the height
 *      pins: base 10, COMMITTED 11 == base + is_zk.
 *   2. dnac_fri_params_eq() is exact (reflexive + rejects any single-field diff
 *      + NULL-rejecting).
 *
 * COVERAGE NOTE (d4.d, 2026-07-26): this file used to carry a third assertion —
 * that dnac_fri_verify_wire_shielded() rejects an off-pin wire proof with
 * DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH, driven by the TEST-params
 * fri_proof_wire.json vector. That v3 wrapper and that vector are both retired.
 * The substitution guard it proved now lives on the v4 batched path — params
 * equality then SUBSTITUTION of the pinned struct, shielded_verify.c:188-204
 * and :252 — and is covered STRICTLY BETTER by tests/test_shielded_verify.c
 * T-R6 (:333-342), which drives the REAL consensus entry
 * dnac_shielded_verify_statement with a TEST-params (2-query) proof built at
 * the pinned height, so the parameter pin is the ONLY thing that can fire, and
 * asserts DNAC_SHIELDED_VERIFY_ERR_FRI. What remains here is the parameter PIN
 * itself: the constants no other test asserts field-by-field.
 *
 * Takes NO arguments.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include "../shielded_fri_params.h"

int main(void) {
    int fails = 0;

    /* (1) Pinned constants == grounded config.rs new_benchmark_zk. */
    const dnac_fri_params_t *p = dnac_shielded_fri_params();
    if (p->log_blowup != 2) { fprintf(stderr, "FAIL log_blowup %zu != 2\n", p->log_blowup); fails++; }
    if (p->log_final_poly_len != 0) { fprintf(stderr, "FAIL log_final_poly_len != 0\n"); fails++; }
    if (p->max_log_arity != 1) { fprintf(stderr, "FAIL max_log_arity != 1\n"); fails++; }
    if (p->num_queries != 100) { fprintf(stderr, "FAIL num_queries %zu != 100\n", p->num_queries); fails++; }
    if (p->commit_proof_of_work_bits != 0) { fprintf(stderr, "FAIL commit_pow != 0\n"); fails++; }
    if (p->query_proof_of_work_bits != 16) { fprintf(stderr, "FAIL query_pow %zu != 16\n", p->query_proof_of_work_bits); fails++; }
    size_t soundness = p->log_blowup * p->num_queries + p->query_proof_of_work_bits;
    if (soundness != DNAC_SHIELDED_FRI_SOUNDNESS_BITS) {
        fprintf(stderr, "FAIL soundness %zu != %zu\n", soundness, (size_t)DNAC_SHIELDED_FRI_SOUNDNESS_BITS);
        fails++;
    }
    if (soundness < DNAC_SHIELDED_FRI_SOUNDNESS_TARGET) {
        fprintf(stderr, "FAIL soundness %zu below target\n", soundness);
        fails++;
    }
    /* Height pin: physical base 10, but the COMMITTED domain the verifier reads
     * is base + is_zk = 11 (is_zk doubling; conf_root_air_zk.json base+1). The
     * guard MUST compare against 11, not the physical 10 (red-team S0-H1). */
    if (DNAC_SHIELDED_BASE_LOG_HEIGHT != 10) {
        fprintf(stderr, "FAIL pinned base height != 10\n");
        fails++;
    }
    if (DNAC_SHIELDED_COMMITTED_LOG_HEIGHT != 11) {
        fprintf(stderr, "FAIL pinned committed height %zu != 11 (base+is_zk)\n",
                (size_t)DNAC_SHIELDED_COMMITTED_LOG_HEIGHT);
        fails++;
    }
    if (DNAC_SHIELDED_COMMITTED_LOG_HEIGHT !=
        DNAC_SHIELDED_BASE_LOG_HEIGHT + DNAC_SHIELDED_IS_ZK) {
        fprintf(stderr, "FAIL committed height != base + is_zk\n");
        fails++;
    }

    /* (2) params_eq exactness. */
    if (!dnac_fri_params_eq(p, p)) { fprintf(stderr, "FAIL params_eq not reflexive\n"); fails++; }
    {
        dnac_fri_params_t q = *p;
        q.num_queries = 99;
        if (dnac_fri_params_eq(p, &q)) { fprintf(stderr, "FAIL params_eq missed num_queries diff\n"); fails++; }
        q = *p;
        q.log_blowup = 1;
        if (dnac_fri_params_eq(p, &q)) { fprintf(stderr, "FAIL params_eq missed log_blowup diff\n"); fails++; }
    }
    if (dnac_fri_params_eq(NULL, p) || dnac_fri_params_eq(p, NULL)) {
        fprintf(stderr, "FAIL params_eq NULL not rejected\n");
        fails++;
    }

    if (fails) {
        printf("shielded FRI params: %d FAIL\n", fails);
        return 1;
    }
    printf("shielded FRI params: pinned set grounded (216-bit) + exact "
           "params_eq — PASS\n");
    return 0;
}
