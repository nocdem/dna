/**
 * Bench: HF-4 name_root cost — the pre-vote cost gate (design
 * docs/plans/2026-10-02-onchain-names-design.md rev 4 §2 "Cost").
 *
 * What it measures. The names leg (names_root_v2) is static inside
 * nodus_witness_roots_v2.c, so this bench times the smallest EXPORTED
 * function that contains it: nodus_witness_core_root_v2 — the full CORE
 * domain root a block commit computes (utxo / token / pools / claims /
 * names / supply / accrual legs). Every other leg is EMPTY here, so the
 * difference between a filled-table run and the empty baseline is the
 * cost of scanning and hashing `v2_names` (plus a constant).
 *
 * Fixture. A real witness database opened through the PRODUCTION open
 * path (nodus_witness_create_chain_db — the base schema creates v2_names
 * with NODUS_V2_NAMES_DDL and the per-open shape check runs), into which
 * N valid rows are inserted in ONE transaction:
 *   name  = "z" + i in base 36, zero-padded to 7 digits (8 bytes; the
 *           leading 'z' keeps it out of the all-hex rule, and every
 *           name passes dnac_name_bytes_ok — checked per row);
 *   owner = SHA3-512(i as u64 BE) — 64 distinct bytes per row;
 *   registered_height = 1 + (i mod 1 000 000).
 * The rows are inserted in index order; the root reads them in BINARY
 * name order (the table's primary key), exactly as a node does.
 *
 * Usage:  bench_hf4_name_root [--reps R] [N ...]
 *   defaults: R = 5, sizes 100000 and 1000000. The empty-table baseline
 *   always runs first. Output: one human line per size (N, R, min /
 *   median / max ms per call, peak RSS in MiB) and the bench_common
 *   single-line JSON. Timing is CLOCK_MONOTONIC (bench_now_ns) — bench
 *   code only, never consensus code.
 *
 * Leaves behind: nothing (each size uses its own /tmp directory,
 * removed at the end; left behind if the process is killed).
 *
 * How it can lie: the other six CORE legs are empty, so a mainnet-sized
 * utxo_set's cost is NOT in these numbers; the database is freshly
 * written (hot page cache) — a cold-cache node pays the read from disk
 * on top; peak RSS is the PROCESS high-water mark across all sizes run
 * so far (getrusage), not the root's own allocation.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "bench_common.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_roots_v2.h"
#include "dnac/dnac.h"
#include "crypto/hash/qgp_sha3.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define DEFAULT_REPS 5u

static double peak_rss_mib(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1.0;
    return (double)ru.ru_maxrss / 1024.0;          /* Linux: KiB */
}

static void rmrf(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

/* name i: "z" + base36(i) padded to 7 digits -> 8 bytes */
static int make_name(uint64_t i, char out[9]) {
    static const char d36[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    out[0] = 'z';
    for (int k = 7; k >= 1; k--) {
        out[k] = d36[i % 36u];
        i /= 36u;
    }
    out[8] = '\0';
    if (i != 0) return -1;                 /* > 36^7 rows: out of range */
    return dnac_name_bytes_ok((const uint8_t *)out, 8) ? 0 : -1;
}

static int fill(nodus_witness_t *w, uint64_t n) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_exec(w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_prepare_v2(w->db, "INSERT INTO v2_names (name, owner, "
                           "registered_height) VALUES (?1, ?2, ?3)", -1,
                           &st, NULL) != SQLITE_OK)
        goto fail;
    for (uint64_t i = 0; i < n; i++) {
        char name[9];
        uint8_t be[8], owner[64];
        if (make_name(i, name) != 0) goto fail;
        for (int b = 0; b < 8; b++) be[b] = (uint8_t)(i >> (56 - 8 * b));
        if (qgp_sha3_512(be, sizeof(be), owner) != 0) goto fail;
        sqlite3_bind_blob(st, 1, name, 8, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, owner, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)(1u + (i % 1000000u)));
        if (sqlite3_step(st) != SQLITE_DONE) goto fail;
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    return sqlite3_exec(w->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK
               ? 0 : -1;
fail:
    sqlite3_finalize(st);
    sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}

/* One size: fresh DB, n rows, R timed core-root calls. 0 / -1. */
static int run_size(uint64_t n, unsigned reps) {
    char dir[96];
    uint8_t cid[16];
    int ret = -1;
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    snprintf(dir, sizeof(dir), "/tmp/bench_hf4_name_root_XXXXXX");
    if (!mkdtemp(dir)) { free(w); return -1; }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    memset(cid, 0x4E, sizeof(cid));

    bench_histogram_t h;
    int have_h = 0;
    do {
        if (nodus_witness_create_chain_db(w, cid) != 0 || !w->db) {
            fprintf(stderr, "bench_hf4_name_root: production open failed\n");
            break;
        }
        uint64_t t_fill = bench_now_ns();
        if (n > 0 && fill(w, n) != 0) {
            fprintf(stderr, "bench_hf4_name_root: insert of %llu rows "
                    "failed\n", (unsigned long long)n);
            break;
        }
        t_fill = bench_now_ns() - t_fill;
        if (bench_histogram_init(&h, reps) != 0) break;
        have_h = 1;

        uint8_t root[64], first[64];
        uint64_t total = 0;
        int ok = 1;
        for (unsigned r = 0; r < reps; r++) {
            uint64_t t0 = bench_now_ns();
            int rc = nodus_witness_core_root_v2(w, root);
            uint64_t dt = bench_now_ns() - t0;
            if (rc != 0) { ok = 0; break; }
            if (r == 0) memcpy(first, root, 64);
            else if (memcmp(first, root, 64) != 0) { ok = 0; break; }
            bench_histogram_record(&h, dt);
            total += dt;
        }
        if (!ok) {
            fprintf(stderr, "bench_hf4_name_root: core root failed or "
                    "changed between calls at N=%llu\n",
                    (unsigned long long)n);
            break;
        }
        printf("name_root N=%llu R=%u core_root ms/call min %.3f median "
               "%.3f max %.3f | insert %.1f ms | peak RSS %.1f MiB\n",
               (unsigned long long)n, reps,
               (double)bench_histogram_min(&h) / 1e6,
               (double)bench_histogram_percentile(&h, 50.0) / 1e6,
               (double)bench_histogram_max(&h) / 1e6,
               (double)t_fill / 1e6, peak_rss_mib());
        char extra[128];
        snprintf(extra, sizeof(extra), "\"rows\":%llu,\"peak_rss_mib\":%.1f",
                 (unsigned long long)n, peak_rss_mib());
        bench_emit_json("hf4_core_root_with_names", reps, total, &h, extra);
        fflush(stdout);
        ret = 0;
    } while (0);

    if (have_h) bench_histogram_free(&h);
    if (w->db) sqlite3_close(w->db);
    free(w);
    rmrf(dir);
    return ret;
}

int main(int argc, char **argv) {
    unsigned reps = DEFAULT_REPS;
    uint64_t sizes[16];
    size_t n_sizes = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--reps") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 10);
            if (v < 1 || v > 100000) {
                fprintf(stderr, "--reps must be 1..100000\n");
                return 2;
            }
            reps = (unsigned)v;
        } else if (n_sizes < sizeof(sizes) / sizeof(sizes[0])) {
            char *end = NULL;
            unsigned long long v = strtoull(argv[i], &end, 10);
            if (!end || *end != '\0' || v == 0) {
                fprintf(stderr, "usage: %s [--reps R] [N ...]\n", argv[0]);
                return 2;
            }
            sizes[n_sizes++] = (uint64_t)v;
        }
    }
    if (n_sizes == 0) {
        sizes[n_sizes++] = 100000u;
        sizes[n_sizes++] = 1000000u;
    }

    if (run_size(0, reps) != 0) return 1;              /* the baseline */
    for (size_t k = 0; k < n_sizes; k++)
        if (run_size(sizes[k], reps) != 0) return 1;
    return 0;
}
