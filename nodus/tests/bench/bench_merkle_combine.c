/**
 * Bench: Merkle tx_root compute cost.
 *
 * Builds a flat array of N fake 64-byte tx_hash values and times
 * `nodus_witness_merkle_tx_root` — the RFC 6962 merkle root used
 * per block over the committed TX hashes.
 *
 * This scales with batch size; at NODUS_W_MAX_BLOCK_TXS = 10 it is
 * trivial, but as that cap is raised the per-block merkle cost
 * becomes relevant for round budget.
 *
 * Two size points are measured: the current cap (10) and a
 * forward-looking larger batch (100) so the scaling curve is
 * visible at baseline.
 */

#include "bench_common.h"
#include "witness/nodus_witness_merkle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BENCH_N 1000

static int bench_one_size(const char *label, size_t n_txs) {
    uint8_t *hashes = calloc(n_txs, 64);
    if (!hashes) return -1;
    /* Fill each 64-byte hash with deterministic pseudo-random bytes. */
    for (size_t i = 0; i < n_txs * 64; i++) {
        hashes[i] = (uint8_t)((i * 131 + 17) & 0xFF);
    }

    uint8_t root[64];

    bench_histogram_t hist;
    if (bench_histogram_init(&hist, BENCH_N) != 0) {
        free(hashes);
        return -1;
    }

    /* Warm-up. */
    for (int i = 0; i < 10; i++) {
        (void)nodus_witness_merkle_tx_root(hashes, n_txs, root);
    }

    uint64_t t0 = bench_now_ns();
    for (size_t i = 0; i < BENCH_N; i++) {
        uint64_t start = bench_now_ns();
        int rc = nodus_witness_merkle_tx_root(hashes, n_txs, root);
        uint64_t end = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "tx_root failed at i=%zu (n=%zu)\n", i, n_txs);
            free(hashes);
            bench_histogram_free(&hist);
            return -1;
        }
        bench_histogram_record(&hist, end - start);
    }
    uint64_t total = bench_now_ns() - t0;

    char extra[64];
    snprintf(extra, sizeof(extra), "\"n_txs\":%zu", n_txs);
    bench_emit_json(label, BENCH_N, total, &hist, extra);

    bench_histogram_free(&hist);
    free(hashes);
    return 0;
}

int main(void) {
    /* nodus_witness_merkle_tx_root is hard-capped at
     * NODUS_W_MAX_BLOCK_TXS (currently 10) — see witness_merkle.c:270.
     * A few sub-cap sizes give the scaling curve up to the current
     * production ceiling. Larger sizes (100, 1000) will be added when
     * NODUS_W_MAX_BLOCK_TXS is bumped in a future optimization pass. */
    if (bench_one_size("merkle_tx_root_1",  1)  != 0) return 1;
    if (bench_one_size("merkle_tx_root_5",  5)  != 0) return 1;
    if (bench_one_size("merkle_tx_root_10", 10) != 0) return 1;
    return 0;
}
