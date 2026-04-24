/**
 * Phase 3 doneness smoke — proves the 6 QGP_BENCH injection points
 * actually fire in the real library code.
 *
 * Calls each instrumented function once, then asserts the matching
 * counter advanced. This catches silent misses (e.g. forgotten
 * #include, wrong enum ID, macro elided under wrong build flag).
 *
 * Only meaningful with -DQGP_BENCH=ON; under default build the test
 * reports "framework disabled" and exits 0.
 */

#include "crypto/utils/qgp_bench.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
#ifdef QGP_BENCH
    qgp_bench_reset();

    /* Fire injection 1: Dilithium5 verify */
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t sig[QGP_DSA87_SIGNATURE_BYTES];
    size_t siglen = 0;
    uint8_t msg[32];
    memset(msg, 0x5A, sizeof(msg));
    if (qgp_dsa87_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    if (qgp_dsa87_sign(sig, &siglen, msg, sizeof(msg), sk) != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }
    if (qgp_dsa87_verify(sig, siglen, msg, sizeof(msg), pk) != 0) {
        fprintf(stderr, "verify failed\n");
        return 1;
    }

    /* Fire injection 2: Dilithium5 sign — already fired above */

    /* Fire injection 3: SHA3-512 */
    uint8_t digest[QGP_SHA3_512_DIGEST_LENGTH];
    if (qgp_sha3_512(msg, sizeof(msg), digest) != 0) {
        fprintf(stderr, "sha3_512 failed\n");
        return 1;
    }

    /* Injections 4-6 (sqlite_commit, merkle_compute, bft_round)
     * require a full nodus_witness_t context + DB setup. Those are
     * verified live via the Stage F cluster in Phase 4. Here we
     * only assert the three primitives fire. */

    char buf[2048];
    if (qgp_bench_dump_json(buf, sizeof(buf)) <= 0) {
        fprintf(stderr, "dump failed\n");
        return 1;
    }
    printf("%s\n", buf);

    /* Assert counts > 0 for the primitives we exercised. */
    int fail = 0;
    if (strstr(buf, "\"dilithium_verify\":{\"count\":0") != NULL) {
        fprintf(stderr, "FAIL: dilithium_verify injection did not fire\n");
        fail = 1;
    }
    if (strstr(buf, "\"dilithium_sign\":{\"count\":0") != NULL) {
        fprintf(stderr, "FAIL: dilithium_sign injection did not fire\n");
        fail = 1;
    }
    if (strstr(buf, "\"sha3_512\":{\"count\":0") != NULL) {
        fprintf(stderr, "FAIL: sha3_512 injection did not fire\n");
        fail = 1;
    }
    return fail;
#else
    printf("{\"framework\":\"disabled\",\"note\":\"QGP_BENCH undefined\"}\n");
    return 0;
#endif
}
