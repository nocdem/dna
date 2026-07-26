/**
 * @file bench_prover.c
 * @brief P2 — perf bench for the BATCHED C STARK pipeline (dnac_batch_prove /
 *        dnac_batch_verify).
 *
 * Measures, per instance height, the WALL-CLOCK prove time, the verify time
 * (dnac_batch_verify — the chain-side cost), and the on-chain wire proof size
 * (DZKF v4 bytes from dnac_batch_wire_encode). Used to judge the confidential
 * track's viability at 1 TPS today and against the 100-TPS future target:
 *
 *   - verify_ms  → chain throughput bottleneck (committee verifies every TX).
 *   - proof_bytes → full-history storage growth (TPS × bytes).
 *   - prove_ms   → wallet UX (client-side; NOT the chain TPS bound).
 *
 * d4.d (2026-07-26): re-based off the retired v3 uni-stark entry
 * (dnac_prover_prove / stark_prover_prove.c) onto the batched pipeline that
 * actually ships — the same dnac_batch_prove the shielded aggregate prover
 * delegates to (stark_prover_agg.c) and the same dnac_batch_verify the
 * consensus entry runs (shielded_verify.c).
 *
 * FIXTURE (deliberate, and NOT a byte-match KAT): a ONE-instance is_zk=1
 * FibonacciAir batch, reusing the in-tree AIR + witness builders from
 * tests/batch_test_util.h (fib_air_eval / fib_trace) so no new oracle vector is
 * needed. The geometry mirrors the oracle's `fib_zk` scenario in
 * tools/vectors/batch_proof.json — log_num_qc = 1 (num_qc = 1<<(1+is_zk) = 4),
 * num_random_codewords = 4, log_blowup 2, log_final_poly_len 2, 2 queries, no
 * PoW — swept over base heights instead of the vector's fixed 8/16. Leaves are
 * UNSALTED (salt_elems = 0), matching that scenario; the shielded consensus
 * profile (100 queries, 16-bit query PoW, SALT_ELEMS = 2, h = 1024) is
 * measured end-to-end by tests/test_prover_shielded_production.c instead.
 *
 * Randomness is an arbitrary canonical stream: any canonical draws produce a
 * proof that self-verifies; only a byte-match against Plonky3 needs the real
 * SmallRng stream. NOT part of `make test`. Manual perf tool:
 *   make bench-prover && ./build/bench_prover
 *
 * Timing wall-clock is fine here: the prover is client-side, never in a
 * consensus state_root path, so this is not a determinism concern.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 199309L /* clock_gettime / CLOCK_MONOTONIC under -std=c99 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../batch_prover.h"
#include "../batch_verify.h"
#include "../field_goldilocks.h"
#include "../fri_proof_codec.h"
#include "../tests/batch_test_util.h" /* fib_air_eval + fib_trace fixtures */

/* The oracle fib_zk geometry (tools/vectors/batch_proof.json). */
#define BP_IS_ZK      1
#define BP_LOG_NUM_QC 1u /* num_qc = 1 << (log_num_qc + is_zk) = 4 */
#define BP_NRC        4u /* num_random_codewords                   */

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1.0e6;
}

/* A canonical, deterministic draw stream (any canonical values self-verify;
 * only byte-match to Plonky3 needs the real SmallRng stream). */
static void fill_draws(uint64_t *draws, size_t n) {
    uint64_t x = 0x9e3779b97f4a7c15ULL; /* splitmix-ish, kept < p */
    for (size_t i = 0; i < n; i++) {
        x += 0x9e3779b97f4a7c15ULL;
        uint64_t z = x;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        z ^= z >> 31;
        draws[i] = z % GOLDILOCKS_P; /* canonical */
    }
}

/* Fill the 1-instance FibonacciAir descriptor for a base height of 1<<log_h. */
static void bp_fill_instance(dnac_batch_vinstance_t *vi, unsigned log_h,
                             const gold_fp_t *publics) {
    memset(vi, 0, sizeof(*vi));
    vi->air.main_width = 2;
    vi->air.num_public_values = 3;
    vi->air.main_next = 1;
    vi->air.air_eval = fib_air_eval;
    vi->preprocessed_width = 0;
    vi->prep_next = 0;
    vi->pool = NULL;
    vi->pool_len = 0;
    vi->lookups = NULL;
    vi->num_lookups = 0;
    /* degree_bits INCLUDES the is_zk +1 (batch_verify.h). */
    vi->degree_bits = (uint32_t)log_h + (uint32_t)BP_IS_ZK;
    vi->log_num_qc = BP_LOG_NUM_QC;
    vi->public_values = publics;
    vi->num_publics = 3;
}

int main(void) {
    const unsigned log_heights[] = {3, 4, 5, 6, 7, 8, 9, 10};
    const size_t nh = sizeof(log_heights) / sizeof(log_heights[0]);
    const int reps = 3; /* best-of a few reps for stable timing */
    int failures = 0;

    dnac_fri_params_t params;
    memset(&params, 0, sizeof(params));
    params.log_blowup = 2;
    params.log_final_poly_len = 2;
    params.max_log_arity = 1;
    params.num_queries = 2;
    params.commit_proof_of_work_bits = 0;
    params.query_proof_of_work_bits = 0;

    printf("DNAC ZK — batched C prover perf bench "
           "(dnac_batch_prove / dnac_batch_verify)\n");
    printf("1 instance, FibonacciAir, is_zk=1, unsalted, %d-query test params; "
           "best-of-%d\n", (int)params.num_queries, reps);
    printf("prove=wallet UX, verify=chain cost, bytes=DZKF v4 storage\n\n");
    printf("%6s %5s %6s %11s %11s %11s\n", "height", "db", "rounds",
           "prove_ms", "verify_ms", "proof_B");
    printf("%6s %5s %6s %11s %11s %11s\n", "------", "--", "------",
           "--------", "---------", "-------");

    for (size_t h = 0; h < nh; h++) {
        const unsigned log_h = log_heights[h];
        const size_t   base_h = (size_t)1 << log_h;

        uint64_t *trace = (uint64_t *)malloc(base_h * 2 * sizeof(uint64_t));
        if (!trace) return 2;
        fib_trace(0, 1, base_h, trace);

        gold_fp_t publics[3];
        publics[0] = gold_fp_from_u64(0);
        publics[1] = gold_fp_from_u64(1);
        publics[2] = gold_fp_from_u64(trace[2 * base_h - 1]);

        dnac_batch_vinstance_t vi;
        bp_fill_instance(&vi, log_h, publics);
        dnac_batch_pwitness_t wit;
        wit.main_trace = trace;
        wit.prep_trace = NULL;

        const size_t ndraws = dnac_batch_prove_num_draws(&vi, 1, BP_IS_ZK, BP_NRC);
        if (ndraws == SIZE_MAX) {
            printf("%6zu   (draw-count derivation FAILED)\n", base_h);
            free(trace);
            failures++;
            continue;
        }
        uint64_t *draws = (uint64_t *)malloc(ndraws * sizeof(uint64_t));
        if (!draws) { free(trace); return 2; }
        fill_draws(draws, ndraws);

        double best_prove = 1e18, best_verify = 1e18;
        size_t proof_bytes = 0, rounds = 0;
        int ok = 1;
        for (int r = 0; r < reps; r++) {
            dnac_batch_proof_t *bp = NULL;
            double t0 = now_ms();
            dnac_prover_status_t st =
                dnac_batch_prove(&vi, &wit, 1, BP_IS_ZK, &params, BP_NRC,
                                 draws, ndraws, NULL, 0, NULL, 0, 0, &bp);
            double t1 = now_ms();
            if (st != DNAC_PROVER_OK || bp == NULL) {
                printf("%6zu   (prove FAILED, status=%d)\n", base_h, (int)st);
                ok = 0;
                break;
            }

            dnac_batch_vcommits_t commits;
            dnac_batch_proof_commits(bp, &commits);
            const dnac_batch_vopened_t *opened = dnac_batch_proof_opened(bp, 0);
            const dnac_fri_proof_t     *fri = dnac_batch_proof_fri(bp);
            const dnac_batch_rand_openings_t *ro =
                dnac_batch_proof_rand_openings(bp);

            dnac_batch_verify_out_t vo;
            memset(&vo, 0, sizeof(vo));
            double v0 = now_ms();
            dnac_batch_verify_status_t vs =
                dnac_batch_verify(&vi, opened, 1, BP_IS_ZK, &commits, NULL, 0,
                                  &params, fri, ro, &vo);
            double v1 = now_ms();
            if (vs != DNAC_BV_OK) {
                printf("%6zu   (verify FAILED, status=%d fri=%d)\n", base_h,
                       (int)vs, (int)vo.fri_status);
                dnac_batch_proof_free(bp);
                ok = 0;
                break;
            }

            uint8_t *wire = NULL;
            size_t   wire_len = 0;
            dnac_fri_codec_status_t cs =
                dnac_batch_wire_encode(BP_IS_ZK, 1, &commits, opened, ro,
                                       &params, fri, &wire, &wire_len);
            if (cs != DNAC_FRI_CODEC_OK) {
                printf("%6zu   (wire encode FAILED, codec=%d)\n", base_h,
                       (int)cs);
                dnac_batch_proof_free(bp);
                ok = 0;
                break;
            }
            proof_bytes = wire_len;
            free(wire);

            rounds = fri->num_commit_phase_commits;
            if (t1 - t0 < best_prove) best_prove = t1 - t0;
            if (v1 - v0 < best_verify) best_verify = v1 - v0;
            dnac_batch_proof_free(bp);
        }
        free(draws);
        free(trace);
        if (!ok) { failures++; continue; }

        printf("%6zu %5u %6zu %11.2f %11.2f %11zu\n", base_h, vi.degree_bits,
               rounds, best_prove, best_verify, proof_bytes);
    }

    printf("\nNotes:\n");
    printf("  - prove_ms INCLUDES dnac_batch_prove's own self-verify "
           "(batch_prover.h step 11);\n");
    printf("    verify_ms is a second, isolated dnac_batch_verify — that one is\n");
    printf("    the per-TX chain cost. 100 TPS budget = block_time /\n");
    printf("    txs_per_block per witness (serial). prove_ms is wallet-only.\n");
    printf("  - proof_B is the DZKF v4 wire size; it grows with FRI rounds\n");
    printf("    (commit-phase steps) + degree_bits, NOT with the witness count.\n");
    printf("  - TEST-grade FRI params (2 queries, no PoW, ~4-bit soundness) and\n");
    printf("    UNSALTED leaves. The pinned shielded consensus set (100 queries,\n");
    printf("    16-bit query PoW, SALT_ELEMS=2) is materially slower and larger —\n");
    printf("    see tests/test_prover_shielded_production.c for that profile.\n");
    return failures ? 1 : 0;
}
