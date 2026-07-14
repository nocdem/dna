/**
 * @file bench_prover.c
 * @brief P2 — perf bench for the C STARK prover (dnac_prover_prove).
 *
 * Measures, per instance height, the WALL-CLOCK prove time, the verify time
 * (dnac_prover_proof_verify = prime + dnac_fri_verify — the chain-side cost),
 * and the on-chain wire proof size (DZKS bytes). Used to judge the confidential
 * track's viability at 1 TPS today and against the 100-TPS future target:
 *
 *   - verify_ms  → chain throughput bottleneck (committee verifies every TX).
 *   - proof_bytes → full-history storage growth (TPS × bytes).
 *   - prove_ms   → wallet UX (client-side; NOT the chain TPS bound).
 *
 * NOT a correctness/byte-match test (uses arbitrary canonical draws, which
 * still self-verify) and NOT part of `make test`. Manual perf tool:
 *   make bench-prover && ./build/bench_prover
 *
 * Timing wall-clock is fine here: the prover is client-side, never in a
 * consensus state_root path, so this is not a determinism concern.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 199309L /* clock_gettime / CLOCK_MONOTONIC under -std=c99 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../field_goldilocks.h"
#include "../stark_prover_prove.h"

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

int main(void) {
    const size_t heights[] = {4, 8, 16, 32, 64, 128, 256, 512, 1024};
    const size_t nh = sizeof(heights) / sizeof(heights[0]);
    const int reps = 3; /* median of a few reps for stable timing */

    printf("DNAC v3 ZK — C prover perf bench (dnac_prover_prove)\n");
    printf("wall-clock, best-of-%d; prove=wallet UX, verify=chain cost, "
           "bytes=storage\n\n", reps);
    printf("%6s %5s %6s %11s %11s %11s\n", "height", "db", "rounds",
           "prove_ms", "verify_ms", "proof_B");
    printf("%6s %5s %6s %11s %11s %11s\n", "------", "--", "------",
           "--------", "---------", "-------");

    for (size_t h = 0; h < nh; h++) {
        const size_t height = heights[h];
        const size_t n_real = height;               /* fully populated */
        const size_t ndraws = DNAC_PROVER_TOTAL_DRAWS(height);

        uint64_t *amounts = (uint64_t *)malloc(n_real * sizeof(uint64_t));
        uint64_t *draws = (uint64_t *)malloc(ndraws * sizeof(uint64_t));
        if (!amounts || !draws) { free(amounts); free(draws); return 2; }
        for (size_t i = 0; i < n_real; i++) amounts[i] = (uint64_t)(i + 1);
        fill_draws(draws, ndraws);

        dnac_prover_instance_t inst = {amounts, n_real, height, 7, draws, ndraws};

        double best_prove = 1e18, best_verify = 1e18;
        size_t proof_bytes = 0, db = 0, rounds = 0;
        int ok = 1;
        for (int r = 0; r < reps; r++) {
            dnac_prover_proof_t *proof = NULL;
            double t0 = now_ms();
            dnac_prover_status_t st = dnac_prover_prove(&inst, &proof);
            double t1 = now_ms();
            if (st != DNAC_PROVER_OK || !proof) { ok = 0; break; }
            double v0 = now_ms();
            dnac_fri_status_t vs = dnac_prover_proof_verify(proof);
            double v1 = now_ms();
            if (vs != 0) { dnac_prover_proof_free(proof); ok = 0; break; }
            if (t1 - t0 < best_prove) best_prove = t1 - t0;
            if (v1 - v0 < best_verify) best_verify = v1 - v0;
            proof_bytes = dnac_prover_proof_wire_size(proof);
            db = dnac_prover_proof_degree_bits(proof);
            rounds = dnac_prover_proof_num_fri_rounds(proof);
            dnac_prover_proof_free(proof);
        }
        free(amounts);
        free(draws);
        if (!ok) {
            printf("%6zu   (prove/verify FAILED)\n", height);
            return 1;
        }
        printf("%6zu %5zu %6zu %11.2f %11.2f %11zu\n", height, db, rounds,
               best_prove, best_verify, proof_bytes);
    }

    printf("\nNotes:\n");
    printf("  - proof size is fixed-ish (num_queries=2, final_poly=4) — it grows\n");
    printf("    with FRI rounds (commit-phase steps) + degree_bits, NOT n_real.\n");
    printf("  - verify_ms is the per-TX chain cost; 100 TPS budget = block_time /\n");
    printf("    txs_per_block per witness (serial). prove_ms is wallet-only.\n");
    printf("  - test-grade FRI params (num_queries=2, pow=0, ~4-bit soundness).\n");
    printf("    Production params (more queries) grow proof size + verify time.\n");
    return 0;
}
