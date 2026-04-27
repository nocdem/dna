/* dna_bench_output.c — live stderr tick + JSONL stream + final JSON.
 *
 * Phase 1.A scaffolding: stub implementations. Real impl in 1.D.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "dna_bench_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void dna_bench_print_iso_utc(char *buf, size_t n, time_t t) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

struct dna_bench_stream { FILE *fp; };

dna_bench_stream_t *dna_bench_stream_open(const char *path) {
    if (!path || !*path) return NULL;
    dna_bench_stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->fp = fopen(path, "a");
    if (!s->fp) { free(s); return NULL; }
    return s;
}

void dna_bench_stream_round(dna_bench_stream_t *s,
                            const struct dna_bench_round_stats *r) {
    if (!s || !s->fp) return;
    char ts[32];
    dna_bench_print_iso_utc(ts, sizeof(ts), time(NULL));
    fprintf(s->fp,
        "{\"ts\":\"%s\",\"round\":%d,\"phase\":\"%s\",\"tps_target\":%d,"
        "\"submit\":%d,\"commit_h\":%d,\"fail\":%d,"
        "\"round_dt_ms\":%llu,\"min_dt_ms\":%llu,\"p50_dt_ms\":%llu,"
        "\"p95_dt_ms\":%llu,\"max_dt_ms\":%llu}\n",
        ts, r->round, r->phase ? r->phase : "?", r->tps_target,
        r->submit, r->commit_h, r->fail,
        (unsigned long long)r->round_dt_ms,
        (unsigned long long)r->min_dt_ms,
        (unsigned long long)r->p50_dt_ms,
        (unsigned long long)r->p95_dt_ms,
        (unsigned long long)r->max_dt_ms);
    fflush(s->fp);
}

void dna_bench_stream_close(dna_bench_stream_t *s) {
    if (!s) return;
    if (s->fp) fclose(s->fp);
    free(s);
}

void dna_bench_live_start(struct dna_bench_live_counters *c, int interval_s) {
    (void)c; (void)interval_s;
    /* Phase 1.D: implement worker thread. */
}

void dna_bench_live_stop(void) {
    /* Phase 1.D: implement worker thread. */
}

void dna_bench_live_record(uint64_t submit, uint64_t commit_h, uint64_t fail) {
    (void)submit; (void)commit_h; (void)fail;
}

int dna_bench_final_emit(const struct dna_bench_final_args *a) {
    (void)a;
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}
