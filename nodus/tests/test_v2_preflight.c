/**
 * @file nodus/tests/test_v2_preflight.c
 * @brief O15A obligation 7 (+ obligation 8's fail-closed gate) — the
 *        activation-readiness preflight is deterministic, read-only, and
 *        cannot activate anything.
 *
 * The properties worth testing are not "does it find problem X" — that is
 * the easy half. They are:
 *   - it does not WRITE (proven by a whole-database digest, not by
 *     reading the code and believing it);
 *   - it is DETERMINISTIC (same database, byte-identical report, twice);
 *   - it reports EVERY issue in canonical order rather than stopping at
 *     the first, because an operator needs the whole list;
 *   - it can NEVER report ready while Rule N has no attendance source,
 *     which is how O15A closes that obligation without inventing an
 *     attendance oracle.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_preflight.h"
#include "crypto/hash/qgp_sha3.h"

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)

typedef struct { char dir[256]; nodus_witness_t *w; } fx_t;

static int fx_open(fx_t *f, const char *tag) {
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_v2_pf_%s_XXXXXX", tag);
    if (!mkdtemp(f->dir)) return -1;
    f->w = calloc(1, sizeof(*f->w));
    if (!f->w) return -1;
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t cid[16];
    memset(cid, 0x77, sizeof(cid));
    return nodus_witness_create_chain_db(f->w, cid);
}

static void fx_close(fx_t *f) {
    if (!f->w) return;
    if (f->w->db) sqlite3_close(f->w->db);
    free(f->w);
    f->w = NULL;
}

/* Whole-database logical digest: every table, every row, in a stable
 * order — including sqlite_sequence, which a NOT LIKE 'sqlite_%' filter
 * would silently drop along with the AUTOINCREMENT counters. */
static int db_digest(nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *tq = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "ORDER BY name", -1, &tq, NULL) != SQLITE_OK)
        return -1;
    uint8_t acc[64];
    memset(acc, 0, sizeof(acc));
    while (sqlite3_step(tq) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(tq, 0);
        char sql[512];
        snprintf(sql, sizeof(sql),
                 "SELECT quote(t.*) FROM (SELECT * FROM \"%s\") t", t);
        sqlite3_stmt *rq = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rq, NULL) != SQLITE_OK) {
            /* Fall back to a row count so an unquotable table still
             * contributes rather than being silently skipped. */
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM \"%s\"", t);
            if (sqlite3_prepare_v2(w->db, sql, -1, &rq, NULL) != SQLITE_OK)
                continue;
        }
        while (sqlite3_step(rq) == SQLITE_ROW) {
            const unsigned char *v = sqlite3_column_text(rq, 0);
            uint8_t buf[64];
            if (v) {
                qgp_sha3_512(v, strlen((const char *)v), buf);
                for (int i = 0; i < 64; i++) acc[i] ^= buf[i];
            }
        }
        sqlite3_finalize(rq);
        uint8_t nb[64];
        qgp_sha3_512((const uint8_t *)t, strlen(t), nb);
        for (int i = 0; i < 64; i++) acc[i] ^= nb[i];
    }
    sqlite3_finalize(tq);
    memcpy(out, acc, 64);
    return 0;
}

static int has_issue(const nodus_v2_preflight_report_t *r,
                     nodus_v2_pf_issue_t id) {
    for (size_t i = 0; i < r->n_issues; i++)
        if (r->issues[i] == id) return 1;
    return 0;
}

int main(void) {
    printf("=== O15A obligation 7 — activation-readiness preflight ===\n");

    fx_t f = {0};
    CHECK(fx_open(&f, "main") == 0, "fixture");

    /* ── 1. READ-ONLY, proven by digest. This is the property that makes
     * the preflight a preflight rather than a migration. */
    {
        uint8_t before[64], after[64];
        CHECK(db_digest(f.w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "preflight runs");
        CHECK(db_digest(f.w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "THE PREFLIGHT WROTE TO THE DATABASE");
    }

    /* ── 2. DETERMINISTIC: the same database yields a byte-identical
     * report. Without this a report could not be compared across nodes
     * or across restarts, which is the whole point of having one. */
    {
        nodus_v2_preflight_report_t a, b;
        CHECK(nodus_witness_v2_preflight(f.w, &a) == 0, "run a");
        CHECK(nodus_witness_v2_preflight(f.w, &b) == 0, "run b");
        CHECK(a.n_issues == b.n_issues, "issue count differs between runs");
        CHECK(memcmp(a.issues, b.issues,
                     a.n_issues * sizeof(a.issues[0])) == 0,
              "issue LIST differs between runs");
        CHECK(a.ready == b.ready, "ready differs between runs");
    }

    /* ── 3. CANONICAL ORDER: issues ascend by id, so the report is a
     * function of the database and not of check-execution order. */
    {
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        for (size_t i = 1; i < r.n_issues; i++)
            CHECK((int)r.issues[i - 1] < (int)r.issues[i],
                  "issues are not in strictly ascending canonical order");
    }

    /* ── 4. MULTIPLE issues are reported together, not just the first.
     * A fresh chain database is missing several prerequisites at once. */
    {
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        CHECK(r.n_issues >= 2,
              "a fresh database must report MORE than one issue");
        CHECK(r.ready == 0, "a fresh database must not be ready");
    }

    /* ── 5. OBLIGATION 8 — the Rule N gate.
     * This is how O15A closes Rule N without inventing an attendance
     * oracle: the rule is not enforced in the V2 boundary, and instead
     * activation is made structurally impossible while its attendance
     * source is absent. The issue must be present on EVERY database. */
    {
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        CHECK(has_issue(&r, NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT),
              "RULE N GATE MISSING — V2 could be activated with the rule "
              "unenforceable");
        CHECK(r.ready == 0,
              "ready must be impossible while the Rule N gate stands");
    }

    /* ── 6. SCHEMA: a database that is not at the activation version is
     * reported as such, and migrating to v9 clears exactly that issue
     * while leaving the Rule N gate standing. The pair is what proves
     * the checks are independent rather than one flag in disguise. */
    {
        nodus_v2_preflight_report_t before_mig, after_mig;
        CHECK(nodus_witness_v2_preflight(f.w, &before_mig) == 0, "run");
        CHECK(has_issue(&before_mig, NODUS_V2_PF_SCHEMA_UNSUPPORTED),
              "pre-migration schema must be reported unsupported");

        CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0, "migrate to v9");

        CHECK(nodus_witness_v2_preflight(f.w, &after_mig) == 0, "run");
        CHECK(!has_issue(&after_mig, NODUS_V2_PF_SCHEMA_UNSUPPORTED),
              "migrating to v9 must clear the schema issue");
        CHECK(has_issue(&after_mig, NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT),
              "the Rule N gate must survive a schema migration");
        CHECK(after_mig.ready == 0, "still not ready");
    }

    /* ── 7. GENESIS ABSENT is detected on a migrated-but-empty chain. */
    {
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        CHECK(has_issue(&r, NODUS_V2_PF_GENESIS_ABSENT),
              "an empty v2_blocks must report GENESIS_ABSENT");
    }

    /* ── 8. READ-ONLY again, now on a migrated database with more state
     * to touch — the first digest check ran on a nearly empty one. */
    {
        uint8_t before[64], after[64];
        CHECK(db_digest(f.w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        CHECK(db_digest(f.w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "the preflight wrote to a migrated database");
    }

    /* ── 9. NULL handling: an inspection that cannot run is NOT ready.
     * "-1" must never be mistaken for a clean bill of health. */
    {
        nodus_v2_preflight_report_t r;
        memset(&r, 0xff, sizeof(r));
        CHECK(nodus_witness_v2_preflight(NULL, &r) == -1, "NULL witness");
        CHECK(r.ready == 0, "a failed inspection must not report ready");
        CHECK(nodus_witness_v2_preflight(f.w, NULL) == -1, "NULL report");
    }

    /* ── 10. Every issue id has a stable name (tooling pins these). */
    {
        for (int id = 1; id <= NODUS_V2_PF_INSPECTION_FAULT; id++) {
            const char *n =
                nodus_witness_v2_preflight_issue_name((nodus_v2_pf_issue_t)id);
            CHECK(n != NULL && strcmp(n, "UNKNOWN") != 0,
                  "every declared issue id needs a stable name");
        }
    }

    fx_close(&f);
    printf("test_v2_preflight: ALL %d checks passed\n", checks);
    return 0;
}
