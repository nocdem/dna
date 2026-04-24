/**
 * Nodus bench harness — common utilities.
 *
 * Shared helpers for micro-benchmarks under nodus/tests/bench/. Each
 * bench binary times N operations, records per-op latencies into a
 * histogram, and emits a single-line JSON summary to stdout suitable
 * for `jq` parsing and committed baselines.
 *
 * Output JSON shape:
 *   {"op":"X","n":N,"total_us":T,"per_op_us":O,
 *    "p50_us":P50,"p95_us":P95,"p99_us":P99,
 *    "min_us":MIN,"max_us":MAX,
 *    "cpu":"...","timestamp":"..."}
 */

#ifndef NODUS_BENCH_COMMON_H
#define NODUS_BENCH_COMMON_H

#include <stdint.h>
#include <stddef.h>

/* Monotonic high-resolution clock. Returns nanoseconds since an
 * unspecified epoch; only differences are meaningful. */
uint64_t bench_now_ns(void);

typedef struct {
    uint64_t *samples;   /* per-op latency in ns */
    size_t cap;
    size_t count;
} bench_histogram_t;

int  bench_histogram_init(bench_histogram_t *h, size_t cap);
void bench_histogram_free(bench_histogram_t *h);
void bench_histogram_record(bench_histogram_t *h, uint64_t ns);

/* Compute percentile (p in [0,100]) over recorded samples. Sorts
 * in-place on first call and caches the sorted flag. Returns ns. */
uint64_t bench_histogram_percentile(bench_histogram_t *h, double p);
uint64_t bench_histogram_min(bench_histogram_t *h);
uint64_t bench_histogram_max(bench_histogram_t *h);

/* ISO-8601 UTC timestamp. buf must be >= 21 bytes. */
void bench_timestamp(char *buf, size_t n);

/* Best-effort CPU model string from /proc/cpuinfo. Falls back to
 * "unknown" on error. buf should be >= 128 bytes. */
void bench_cpu_model(char *buf, size_t n);

/* Emit single-line JSON summary to stdout.
 *   op:     operation name (e.g. "dilithium5_verify")
 *   n_ops:  number of ops timed
 *   total_ns: wall-clock ns for all ops combined
 *   hist:   histogram of per-op ns (may be NULL to skip percentiles)
 *   extra_json_fields: optional extra JSON fields to include (without
 *                      the leading comma); pass NULL for none. Caller
 *                      is responsible for correct JSON escaping. */
void bench_emit_json(const char *op,
                     size_t n_ops,
                     uint64_t total_ns,
                     bench_histogram_t *hist,
                     const char *extra_json_fields);

#endif /* NODUS_BENCH_COMMON_H */
