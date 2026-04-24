/**
 * Bench: SQLite commit cost across sync modes.
 *
 * The nodus witness DB uses WAL + synchronous=NORMAL
 * (nodus_storage.c:219-220). This bench measures the COMMIT cost
 * across three sync settings so any proposal to relax (OFF) or
 * tighten (FULL) has measured backing.
 *
 * Workload mimics a witness finalize: begin transaction, insert N
 * nullifier rows (64-byte blob + int row id), commit.
 */

#include "bench_common.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BENCH_ROUNDS      100    /* N commits per mode */
#define NULLIFIERS_PER_TX 16     /* per-block, matches max inputs */

/* Small wrapper — runs a zero-result SQL statement via prepare/step.
 * Avoids the literal sqlite3_exec() call site pattern. */
static int run_sql(sqlite3 *db, const char *sql) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    return (rc == SQLITE_DONE || rc == SQLITE_ROW) ? 0 : -1;
}

static int run_mode(const char *label,
                    const char *sync_mode,
                    const char *journal_mode) {
    char tmp_path[] = "/tmp/bench_sqlite_XXXXXX.db";
    int fd = mkstemps(tmp_path, 3);
    if (fd < 0) {
        fprintf(stderr, "mkstemps failed\n");
        return -1;
    }
    close(fd);
    unlink(tmp_path);

    sqlite3 *db = NULL;
    if (sqlite3_open(tmp_path, &db) != SQLITE_OK) {
        fprintf(stderr, "sqlite3_open failed\n");
        return -1;
    }

    char pragma[128];
    snprintf(pragma, sizeof(pragma), "PRAGMA journal_mode=%s;", journal_mode);
    run_sql(db, pragma);
    snprintf(pragma, sizeof(pragma), "PRAGMA synchronous=%s;", sync_mode);
    run_sql(db, pragma);

    run_sql(db,
        "CREATE TABLE nullifiers (id INTEGER PRIMARY KEY, n BLOB NOT NULL);");

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO nullifiers(n) VALUES(?);",
            -1, &ins, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed\n");
        sqlite3_close(db);
        unlink(tmp_path);
        return -1;
    }

    bench_histogram_t hist;
    if (bench_histogram_init(&hist, BENCH_ROUNDS) != 0) {
        sqlite3_finalize(ins);
        sqlite3_close(db);
        unlink(tmp_path);
        return -1;
    }

    uint8_t nullifier[64];
    memset(nullifier, 0xA5, sizeof(nullifier));

    /* Warm-up: 5 commits to touch WAL / FS. */
    for (int w = 0; w < 5; w++) {
        run_sql(db, "BEGIN;");
        for (int i = 0; i < NULLIFIERS_PER_TX; i++) {
            sqlite3_bind_blob(ins, 1, nullifier, 64, SQLITE_STATIC);
            sqlite3_step(ins);
            sqlite3_reset(ins);
        }
        run_sql(db, "COMMIT;");
    }

    uint64_t t0 = bench_now_ns();
    for (size_t r = 0; r < BENCH_ROUNDS; r++) {
        run_sql(db, "BEGIN;");
        /* Perturb blob so rows are unique. */
        nullifier[0] = (uint8_t)(r & 0xFF);
        nullifier[1] = (uint8_t)((r >> 8) & 0xFF);
        for (int i = 0; i < NULLIFIERS_PER_TX; i++) {
            nullifier[2] = (uint8_t)i;
            sqlite3_bind_blob(ins, 1, nullifier, 64, SQLITE_STATIC);
            sqlite3_step(ins);
            sqlite3_reset(ins);
        }
        uint64_t start = bench_now_ns();
        int rc = run_sql(db, "COMMIT;");
        uint64_t end = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "commit failed at r=%zu: %s\n",
                    r, sqlite3_errmsg(db));
            bench_histogram_free(&hist);
            sqlite3_finalize(ins);
            sqlite3_close(db);
            unlink(tmp_path);
            return -1;
        }
        bench_histogram_record(&hist, end - start);
    }
    uint64_t total = bench_now_ns() - t0;

    char extra[160];
    snprintf(extra, sizeof(extra),
             "\"sync\":\"%s\",\"journal\":\"%s\",\"inserts_per_commit\":%d",
             sync_mode, journal_mode, NULLIFIERS_PER_TX);
    bench_emit_json(label, BENCH_ROUNDS, total, &hist, extra);

    bench_histogram_free(&hist);
    sqlite3_finalize(ins);
    sqlite3_close(db);
    unlink(tmp_path);
    return 0;
}

int main(void) {
    /* Production setting. */
    if (run_mode("sqlite_commit_wal_normal", "NORMAL", "WAL") != 0)
        return 1;
    /* Aggressive (unsafe in production — no fsync guarantee). */
    if (run_mode("sqlite_commit_wal_off",    "OFF",    "WAL") != 0)
        return 1;
    /* Conservative (fsync every commit — upper bound on cost). */
    if (run_mode("sqlite_commit_wal_full",   "FULL",   "WAL") != 0)
        return 1;
    return 0;
}
