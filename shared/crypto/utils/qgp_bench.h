/**
 * QGP bench — conditional instrumentation macros + counter API.
 *
 * Enabled only when the compile unit is built with -DQGP_BENCH.
 * Production builds leave this header defining `((void)0)` expansions,
 * so the macros are semantically invisible and add zero instructions.
 *
 * Usage:
 *     #include "crypto/utils/qgp_bench.h"
 *
 *     int qgp_dsa87_verify(...) {
 *         QGP_BENCH_START(QGP_BENCH_DILITHIUM_VERIFY);
 *         int rc = real_verify(...);
 *         QGP_BENCH_END(QGP_BENCH_DILITHIUM_VERIFY);
 *         return rc;
 *     }
 *
 * Aggregates per-ID counters (call count + total_ns) atomically.
 * Dump via qgp_bench_dump_json() into a caller-provided buffer, or
 * via qgp_bench_dump_to_file() for side-channel pickup by bench
 * harness / CLI tooling.
 *
 * Macro expansion:
 *   QGP_BENCH=ON  -> START captures CLOCK_MONOTONIC ns, END records
 *                    the delta into an atomic counter for the given
 *                    bench ID.
 *   QGP_BENCH     -> both macros expand to `((void)0)`.
 */

#ifndef QGP_BENCH_H
#define QGP_BENCH_H

#include <stdint.h>
#include <stddef.h>

/* Bench IDs — additions append to the end so serialized counter
 * order is stable across builds. Keep in sync with the name table
 * in qgp_bench.c. */
enum qgp_bench_id {
    QGP_BENCH_DILITHIUM_VERIFY = 0,
    QGP_BENCH_DILITHIUM_SIGN,
    QGP_BENCH_SHA3_512,
    QGP_BENCH_SQLITE_COMMIT,
    QGP_BENCH_MERKLE_COMPUTE,
    QGP_BENCH_BFT_ROUND,
    QGP_BENCH_MAX
};

#ifdef QGP_BENCH

/* Monotonic timer (private helper exposed so macro can inline the
 * call without depending on bench_common in production trees). */
uint64_t qgp_bench_now_ns(void);

/* Record one measurement for the given bench ID. Thread-safe
 * (atomic fetch-add). No-op for out-of-range ID. */
void qgp_bench_record(int id, uint64_t ns);

/* Serialize current counter state as a single-line JSON object into
 * buf. Returns number of bytes written (excluding trailing NUL),
 * or -1 if buflen is too small. Expect ~512 bytes typical. */
int qgp_bench_dump_json(char *buf, size_t buflen);

/* Convenience — dump to a path atomically (temp + rename). Used by
 * a signal handler in nodus-server for side-channel pickup. */
int qgp_bench_dump_to_file(const char *path);

/* Reset all counters to zero. Useful between bench runs on a live
 * process. Thread-safe. */
void qgp_bench_reset(void);

/* Human-readable name for a bench ID, for JSON keys. Returns
 * "unknown" for out-of-range. Stable string — do not free. */
const char *qgp_bench_id_name(int id);

#define QGP_BENCH_START(id) \
    uint64_t _qb_t_##id = qgp_bench_now_ns()

#define QGP_BENCH_END(id) \
    qgp_bench_record((id), qgp_bench_now_ns() - _qb_t_##id)

#else /* !QGP_BENCH */

#define QGP_BENCH_START(id) ((void)0)
#define QGP_BENCH_END(id)   ((void)0)

#endif /* QGP_BENCH */

#endif /* QGP_BENCH_H */
