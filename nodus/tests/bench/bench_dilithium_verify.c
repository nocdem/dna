/**
 * Bench: Dilithium5 (ML-DSA-87) verify cost.
 *
 * Generates a keypair, signs one message, then measures N verifies
 * of that signature. Reports per-op us with p50/p95/p99.
 *
 * This is the primary number referenced in all BFT round budget
 * calculations. With the ref implementation on a modern x86 CPU we
 * expect ~100-400 us per verify; AVX2 variant (if ever added) would
 * drop to ~30-100 us.
 */

#include "bench_common.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BENCH_N 10000

int main(void) {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t sig[QGP_DSA87_SIGNATURE_BYTES];
    size_t siglen = 0;

    if (qgp_dsa87_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }

    uint8_t msg[64];
    memset(msg, 0x42, sizeof(msg));

    if (qgp_dsa87_sign(sig, &siglen, msg, sizeof(msg), sk) != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }

    bench_histogram_t hist;
    if (bench_histogram_init(&hist, BENCH_N) != 0) {
        fprintf(stderr, "histogram init failed\n");
        return 1;
    }

    /* Warm-up: prime caches, discard 100 iterations. */
    for (int i = 0; i < 100; i++) {
        (void)qgp_dsa87_verify(sig, siglen, msg, sizeof(msg), pk);
    }

    uint64_t t0 = bench_now_ns();
    for (size_t i = 0; i < BENCH_N; i++) {
        uint64_t start = bench_now_ns();
        int rc = qgp_dsa87_verify(sig, siglen, msg, sizeof(msg), pk);
        uint64_t end = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "verify failed at i=%zu\n", i);
            bench_histogram_free(&hist);
            return 1;
        }
        bench_histogram_record(&hist, end - start);
    }
    uint64_t total = bench_now_ns() - t0;

    bench_emit_json("dilithium5_verify", BENCH_N, total, &hist,
                    "\"impl\":\"ref\",\"siglen\":4627,\"msglen\":64");
    bench_histogram_free(&hist);
    return 0;
}
