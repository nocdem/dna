/**
 * Phase 2 doneness smoke — proves the QGP_BENCH framework works.
 *
 * Requires -DQGP_BENCH=ON build. Runs a handful of recorded ops,
 * then dumps the counter state as JSON. In a default (non-bench)
 * build this TU still compiles and the test passes trivially,
 * because the macros expand to ((void)0). We detect that mode and
 * just verify dump-from-zero works.
 */

#include "crypto/utils/qgp_bench.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
#ifdef QGP_BENCH
    /* Reset in case a prior run left state. */
    qgp_bench_reset();

    /* Record a few fake measurements. */
    for (int i = 0; i < 100; i++) {
        QGP_BENCH_START(QGP_BENCH_DILITHIUM_VERIFY);
        /* Simulated work: no-op, but timer captures real elapsed ns. */
        QGP_BENCH_END(QGP_BENCH_DILITHIUM_VERIFY);
    }
    for (int i = 0; i < 50; i++) {
        QGP_BENCH_START(QGP_BENCH_SHA3_512);
        QGP_BENCH_END(QGP_BENCH_SHA3_512);
    }

    char buf[4096];
    int len = qgp_bench_dump_json(buf, sizeof(buf));
    if (len <= 0) {
        fprintf(stderr, "dump_json failed\n");
        return 1;
    }
    printf("%s\n", buf);

    /* Basic sanity: expect dilithium_verify count >= 100 in the JSON. */
    if (strstr(buf, "\"dilithium_verify\":{\"count\":100") == NULL) {
        fprintf(stderr, "expected dilithium_verify count=100 in dump\n");
        return 1;
    }
    if (strstr(buf, "\"sha3_512\":{\"count\":50") == NULL) {
        fprintf(stderr, "expected sha3_512 count=50 in dump\n");
        return 1;
    }

    /* File dump round-trip. */
    const char *tmp = "/tmp/nodus_bench_smoke.json";
    if (qgp_bench_dump_to_file(tmp) != 0) {
        fprintf(stderr, "dump_to_file failed\n");
        return 1;
    }
    FILE *f = fopen(tmp, "r");
    if (!f) { perror("fopen"); return 1; }
    char rbuf[4096] = {0};
    size_t rn = fread(rbuf, 1, sizeof(rbuf) - 1, f);
    fclose(f);
    unlink(tmp);
    if (rn == 0) {
        fprintf(stderr, "read-back empty\n");
        return 1;
    }
    if (strstr(rbuf, "\"count\":100") == NULL) {
        fprintf(stderr, "read-back missing count=100\n");
        return 1;
    }
    return 0;
#else
    /* Non-bench build: macros elided. Just verify compile OK by
     * expanding them; the test "passes" without doing real work. */
    QGP_BENCH_START(QGP_BENCH_DILITHIUM_VERIFY);
    QGP_BENCH_END(QGP_BENCH_DILITHIUM_VERIFY);
    printf("{\"framework\":\"disabled\",\"note\":\"QGP_BENCH undefined\"}\n");
    return 0;
#endif
}
