/**
 * Nodus bench harness — common utilities implementation.
 */

#define _POSIX_C_SOURCE 200809L

#include "bench_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Timer ─────────────────────────────────────────────────────── */

uint64_t bench_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── Histogram ─────────────────────────────────────────────────── */

int bench_histogram_init(bench_histogram_t *h, size_t cap) {
    if (!h || cap == 0) return -1;
    h->samples = calloc(cap, sizeof(uint64_t));
    if (!h->samples) return -1;
    h->cap = cap;
    h->count = 0;
    return 0;
}

void bench_histogram_free(bench_histogram_t *h) {
    if (!h) return;
    free(h->samples);
    h->samples = NULL;
    h->cap = 0;
    h->count = 0;
}

void bench_histogram_record(bench_histogram_t *h, uint64_t ns) {
    if (!h || !h->samples) return;
    if (h->count >= h->cap) return;  /* silently drop overflow */
    h->samples[h->count++] = ns;
}

static int u64_cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

static void ensure_sorted(bench_histogram_t *h) {
    if (!h || h->count <= 1) return;
    /* Always re-sort; cheap for our sizes, avoids stale-sort bugs. */
    qsort(h->samples, h->count, sizeof(uint64_t), u64_cmp);
}

uint64_t bench_histogram_percentile(bench_histogram_t *h, double p) {
    if (!h || h->count == 0) return 0;
    if (p < 0) p = 0;
    if (p > 100) p = 100;
    ensure_sorted(h);
    size_t idx = (size_t)((p / 100.0) * (double)(h->count - 1));
    return h->samples[idx];
}

uint64_t bench_histogram_min(bench_histogram_t *h) {
    if (!h || h->count == 0) return 0;
    ensure_sorted(h);
    return h->samples[0];
}

uint64_t bench_histogram_max(bench_histogram_t *h) {
    if (!h || h->count == 0) return 0;
    ensure_sorted(h);
    return h->samples[h->count - 1];
}

/* ── Metadata ──────────────────────────────────────────────────── */

void bench_timestamp(char *buf, size_t n) {
    if (!buf || n < 21) return;
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

void bench_cpu_model(char *buf, size_t n) {
    if (!buf || n == 0) return;
    strncpy(buf, "unknown", n - 1);
    buf[n - 1] = '\0';

    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (!colon) continue;
            char *val = colon + 1;
            while (*val == ' ' || *val == '\t') val++;
            size_t len = strlen(val);
            while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == ' '))
                val[--len] = '\0';
            strncpy(buf, val, n - 1);
            buf[n - 1] = '\0';
            break;
        }
    }
    fclose(f);
}

/* ── JSON emit ─────────────────────────────────────────────────── */

static void escape_json_string(const char *in, char *out, size_t out_cap) {
    if (!in || !out || out_cap == 0) return;
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 2 < out_cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (oi + 3 >= out_cap) break;
            out[oi++] = '\\';
            out[oi++] = (char)c;
        } else if (c < 0x20) {
            /* Drop control chars for simplicity. */
            continue;
        } else {
            out[oi++] = (char)c;
        }
    }
    out[oi] = '\0';
}

void bench_emit_json(const char *op,
                     size_t n_ops,
                     uint64_t total_ns,
                     bench_histogram_t *hist,
                     const char *extra_json_fields) {
    char cpu_raw[256];
    char cpu_esc[512];
    char ts[32];

    bench_cpu_model(cpu_raw, sizeof(cpu_raw));
    escape_json_string(cpu_raw, cpu_esc, sizeof(cpu_esc));
    bench_timestamp(ts, sizeof(ts));

    double per_op_us = (n_ops > 0)
        ? ((double)total_ns / (double)n_ops) / 1000.0
        : 0.0;
    double total_us = (double)total_ns / 1000.0;

    printf("{\"op\":\"%s\",\"n\":%zu,"
           "\"total_us\":%.1f,\"per_op_us\":%.3f",
           op, n_ops, total_us, per_op_us);

    if (hist && hist->count > 0) {
        uint64_t p50 = bench_histogram_percentile(hist, 50);
        uint64_t p95 = bench_histogram_percentile(hist, 95);
        uint64_t p99 = bench_histogram_percentile(hist, 99);
        uint64_t mn  = bench_histogram_min(hist);
        uint64_t mx  = bench_histogram_max(hist);
        printf(",\"p50_us\":%.3f,\"p95_us\":%.3f,\"p99_us\":%.3f,"
               "\"min_us\":%.3f,\"max_us\":%.3f",
               p50 / 1000.0, p95 / 1000.0, p99 / 1000.0,
               mn  / 1000.0, mx  / 1000.0);
    }

    if (extra_json_fields && *extra_json_fields) {
        printf(",%s", extra_json_fields);
    }

    printf(",\"cpu\":\"%s\",\"timestamp\":\"%s\"}\n", cpu_esc, ts);
    fflush(stdout);
}
