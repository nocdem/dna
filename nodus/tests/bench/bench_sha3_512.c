/**
 * Bench: SHA3-512 hash cost.
 *
 * Measures SHA3-512 throughput over two message sizes:
 *   - 64 bytes: typical per-leaf hash (nullifier size)
 *   - 1024 bytes: typical serialized TX preimage chunk
 *
 * SHA3-512 shows up in every BFT path: TX hash preimage, merkle
 * leaf hashes, state_root combine, cert preimage. Knowing the per-op
 * cost bounds any merkle/preimage refactoring claim.
 */

#include "bench_common.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BENCH_N 100000

static int bench_one_size(const char *label, size_t msg_len) {
    uint8_t *msg = calloc(1, msg_len);
    if (!msg) return -1;
    /* Fill with pseudo-random-ish bytes so compiler can't fold. */
    for (size_t i = 0; i < msg_len; i++) msg[i] = (uint8_t)(i * 31 + 7);

    uint8_t digest[QGP_SHA3_512_DIGEST_LENGTH];

    bench_histogram_t hist;
    if (bench_histogram_init(&hist, BENCH_N) != 0) {
        free(msg);
        return -1;
    }

    /* Warm-up. */
    for (int i = 0; i < 100; i++) {
        (void)qgp_sha3_512(msg, msg_len, digest);
    }

    uint64_t t0 = bench_now_ns();
    for (size_t i = 0; i < BENCH_N; i++) {
        uint64_t start = bench_now_ns();
        int rc = qgp_sha3_512(msg, msg_len, digest);
        uint64_t end = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "sha3_512 failed at i=%zu\n", i);
            free(msg);
            bench_histogram_free(&hist);
            return -1;
        }
        bench_histogram_record(&hist, end - start);
    }
    uint64_t total = bench_now_ns() - t0;

    char extra[64];
    snprintf(extra, sizeof(extra), "\"msg_bytes\":%zu", msg_len);
    bench_emit_json(label, BENCH_N, total, &hist, extra);

    bench_histogram_free(&hist);
    free(msg);
    return 0;
}

int main(void) {
    if (bench_one_size("sha3_512_64B",   64)   != 0) return 1;
    if (bench_one_size("sha3_512_1KB", 1024)   != 0) return 1;
    return 0;
}
