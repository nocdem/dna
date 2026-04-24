/**
 * QGP bench — counter storage + dump implementation.
 *
 * Compiled into the nodus library ONLY when -DQGP_BENCH is set. In
 * production builds the file is still compiled (the CMake option
 * defaults OFF), but the header expansions are void so no injection
 * points exist. The counters exist regardless; they just never get
 * written.
 *
 * Thread-safety: counters are C11 atomics; no locks. Dump is a
 * sequence of atomic loads — slightly racy across IDs but accurate
 * per-ID (never a torn 64-bit read on LP64 x86_64).
 */

#define _POSIX_C_SOURCE 200809L

#include "crypto/utils/qgp_bench.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#ifdef QGP_BENCH

static _Atomic uint64_t g_count[QGP_BENCH_MAX];
static _Atomic uint64_t g_total_ns[QGP_BENCH_MAX];

/* ID name table — order must match enum qgp_bench_id. */
static const char *const g_id_names[QGP_BENCH_MAX] = {
    "dilithium_verify",
    "dilithium_sign",
    "sha3_512",
    "sqlite_commit",
    "merkle_compute",
    "bft_round",
};

const char *qgp_bench_id_name(int id) {
    if (id < 0 || id >= QGP_BENCH_MAX) return "unknown";
    return g_id_names[id];
}

uint64_t qgp_bench_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void qgp_bench_record(int id, uint64_t ns) {
    if (id < 0 || id >= QGP_BENCH_MAX) return;
    atomic_fetch_add_explicit(&g_count[id], 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_total_ns[id], ns, memory_order_relaxed);
}

void qgp_bench_reset(void) {
    for (int i = 0; i < QGP_BENCH_MAX; i++) {
        atomic_store_explicit(&g_count[i], 0, memory_order_relaxed);
        atomic_store_explicit(&g_total_ns[i], 0, memory_order_relaxed);
    }
}

int qgp_bench_dump_json(char *buf, size_t buflen) {
    if (!buf || buflen == 0) return -1;

    size_t off = 0;
    int n = snprintf(buf + off, buflen - off, "{");
    if (n < 0 || (size_t)n >= buflen - off) return -1;
    off += (size_t)n;

    for (int i = 0; i < QGP_BENCH_MAX; i++) {
        uint64_t c = atomic_load_explicit(&g_count[i],
                                          memory_order_relaxed);
        uint64_t t = atomic_load_explicit(&g_total_ns[i],
                                          memory_order_relaxed);
        double avg_us = c ? ((double)t / (double)c) / 1000.0 : 0.0;

        n = snprintf(buf + off, buflen - off,
            "%s\"%s\":{\"count\":%llu,\"total_ns\":%llu,\"avg_us\":%.3f}",
            i > 0 ? "," : "",
            qgp_bench_id_name(i),
            (unsigned long long)c,
            (unsigned long long)t,
            avg_us);
        if (n < 0 || (size_t)n >= buflen - off) return -1;
        off += (size_t)n;
    }

    n = snprintf(buf + off, buflen - off, "}");
    if (n < 0 || (size_t)n >= buflen - off) return -1;
    off += (size_t)n;

    return (int)off;
}

int qgp_bench_dump_to_file(const char *path) {
    if (!path) return -1;

    char buf[2048];
    int len = qgp_bench_dump_json(buf, sizeof(buf));
    if (len < 0) return -1;

    /* Atomic write via temp + rename. */
    char tmp[1024];
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    if (tn < 0 || (size_t)tn >= sizeof(tmp)) return -1;

    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    size_t wrote = fwrite(buf, 1, (size_t)len, f);
    if (fputc('\n', f) == EOF) wrote = 0;
    if (fflush(f) != 0) wrote = 0;
    int fd = fileno(f);
    if (fd >= 0) (void)fsync(fd);
    fclose(f);

    if (wrote != (size_t)len) {
        unlink(tmp);
        return -1;
    }

    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

#else /* !QGP_BENCH */

/* When QGP_BENCH is disabled, this file still compiles but emits
 * no symbols. Keeps the CMake target list identical between build
 * modes so downstream linkage doesn't bifurcate. */

#endif /* QGP_BENCH */
