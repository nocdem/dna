/**
 * Bench: Dilithium5 (ML-DSA-87) sign cost.
 *
 * Generates a keypair, then measures N signings of a fresh message.
 * Sign is usually 2-4x slower than verify; these numbers matter when
 * clients submit many TXs concurrently (each TX needs 1 signer sig).
 */

#include "bench_common.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BENCH_N 1000

int main(void) {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];

    if (qgp_dsa87_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }

    uint8_t msg[64];
    memset(msg, 0x42, sizeof(msg));

    bench_histogram_t hist;
    if (bench_histogram_init(&hist, BENCH_N) != 0) {
        fprintf(stderr, "histogram init failed\n");
        return 1;
    }

    /* Warm-up. */
    for (int i = 0; i < 10; i++) {
        uint8_t sig[QGP_DSA87_SIGNATURE_BYTES];
        size_t siglen = 0;
        (void)qgp_dsa87_sign(sig, &siglen, msg, sizeof(msg), sk);
    }

    uint64_t t0 = bench_now_ns();
    for (size_t i = 0; i < BENCH_N; i++) {
        /* Vary message per iteration so the signer does fresh work;
         * ref Dilithium is deterministic w.r.t. sk+msg but fresh
         * input exercises the full pipeline. */
        msg[0] = (uint8_t)(i & 0xFF);
        msg[1] = (uint8_t)((i >> 8) & 0xFF);

        uint8_t sig[QGP_DSA87_SIGNATURE_BYTES];
        size_t siglen = 0;

        uint64_t start = bench_now_ns();
        int rc = qgp_dsa87_sign(sig, &siglen, msg, sizeof(msg), sk);
        uint64_t end = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "sign failed at i=%zu\n", i);
            bench_histogram_free(&hist);
            return 1;
        }
        bench_histogram_record(&hist, end - start);
    }
    uint64_t total = bench_now_ns() - t0;

    bench_emit_json("dilithium5_sign", BENCH_N, total, &hist,
                    "\"impl\":\"ref\",\"msglen\":64");
    bench_histogram_free(&hist);
    return 0;
}
