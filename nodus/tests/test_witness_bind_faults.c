/**
 * @file nodus/tests/test_witness_bind_faults.c
 * @brief Z-50 — a failed sqlite3_bind_* in a shared reader is a FAULT (-1),
 *        never an absent row / a default value.
 *
 * nodus/CLAUDE.md: "A DB failure is never a value". A bind that fails leaves
 * its parameter NULL; the statement then finds no row and the reader used to
 * answer "absent" / "no override" / "not committed". Four readers are
 * covered (the return codes are each reader's own contract):
 *
 *   nodus_chain_config_get_u64               cold-cache path: 1 (default) -> -1
 *   nodus_witness_vset_get                   1 (absent)                   -> -1
 *   nodus_witness_storage_set_get            1 (absent)                   -> -1
 *   nodus_witness_stprobe_report_committed   0 (not committed)            -> -1
 *
 * ── FAULT INJECTION ──────────────────────────────────────────────────
 * A natural bind failure needs SQLITE_RANGE / SQLITE_MISUSE / SQLITE_NOMEM,
 * none of which a fixture can provoke. The target therefore links with
 * -Wl,--wrap=sqlite3_bind_int -Wl,--wrap=sqlite3_bind_int64: while
 * g_fail_sql is set, a bind whose statement text contains that substring
 * returns SQLITE_RANGE and binds nothing (exactly what a failed bind does);
 * every other bind goes to the real function. The production code under test
 * is unchanged; nothing is timed.
 *
 * ── WHAT EACH CASE PROVES ────────────────────────────────────────────
 * For every reader: (control) with no injection the empty-table answer is the
 * reader's ordinary "absent" code; (fault) with the bind of THAT statement
 * failing the answer is -1. Before the fix the fault case returns the absent
 * code, so the check fails.
 *
 * Compile flags: -DNODUS_WITNESS_INTERNAL_API (as test_chain_config_failclose);
 * environment: none. Leaves behind: its mkdtemp dirs under /tmp are removed.
 *
 * How it can falsely pass:
 *   - The fault is injected by statement text: if a reader's SQL changed so
 *     the substring no longer matches, the injection would never fire and the
 *     fault case would see the ordinary "absent" answer and FAIL (never pass).
 *   - get_u64's cold-cache path is forced by a poisoned VIEW row of ANOTHER
 *     parameter (the technique of test_chain_config_failclose.c); if the
 *     warm-up ever stopped failing on it, the call would be served from the
 *     cache and the control would still pass but the fault case would FAIL.
 *   - The other bind failure class (a blob bind failing with SQLITE_NOMEM) is
 *     not driven; the same return-code check covers every bind of a reader.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "nodus/nodus_chain_config.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_storage_reporter.h"

#include "dnac/dnac.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-62s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* ── bind failure seam (-Wl,--wrap=...) ──────────────────────────── */

extern int __real_sqlite3_bind_int(sqlite3_stmt *st, int i, int v);
extern int __real_sqlite3_bind_int64(sqlite3_stmt *st, int i, sqlite3_int64 v);

static const char *g_fail_sql = NULL;

static int should_fail(sqlite3_stmt *st) {
    if (!g_fail_sql) return 0;
    const char *sql = sqlite3_sql(st);
    return sql && strstr(sql, g_fail_sql) != NULL;
}

int __wrap_sqlite3_bind_int(sqlite3_stmt *st, int i, int v) {
    if (should_fail(st)) return SQLITE_RANGE;
    return __real_sqlite3_bind_int(st, i, v);
}

int __wrap_sqlite3_bind_int64(sqlite3_stmt *st, int i, sqlite3_int64 v) {
    if (should_fail(st)) return SQLITE_RANGE;
    return __real_sqlite3_bind_int64(st, i, v);
}

/* ── fixture ─────────────────────────────────────────────────────── */

#define OVERFLOW_EXPR "abs(-9223372036854775808)"
#define P_TXS ((uint8_t)DNAC_CFG_MAX_TXS_PER_BLOCK)
#define P_TAC ((uint8_t)DNAC_CFG_TARGET_ACTIVE_COUNT)

typedef struct {
    nodus_witness_t *w;
    char             dir[80];
} fx_t;

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql error: %s\n  in: %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static void fx_free(fx_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    if (fx->dir[0]) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", fx->dir);
        if (system(cmd) != 0) { /* leftovers are only /tmp files */ }
    }
}

static int fx_up(fx_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));       /* multi-MB: never the stack */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_bind_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; fx->dir[0] = '\0'; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    uint8_t chain_id[16];
    memset(chain_id, 0xC3, sizeof(chain_id));
    if (nodus_witness_create_chain_db(fx->w, chain_id) != 0) return -1;
    return fx->w->db ? 0 : -1;
}

/* ── cases ───────────────────────────────────────────────────────── */

/* get_u64: the cold-cache fallback is reached only when the cache warm-up
 * fails, so chain_config_history becomes a VIEW whose row for ANOTHER param
 * raises "integer overflow" when the warm-up scan evaluates it; the queried
 * param has no row and its own SELECT is clean. */
static void t_get_u64(void) {
    TEST("get_u64 cold path: a failed bind is -1, not the default");
    fx_t fx;
    if (fx_up(&fx, "cc") != 0) { FAIL("fixture"); fx_free(&fx); return; }
    nodus_witness_t *w = fx.w;
    if (exec_sql(w, "ALTER TABLE chain_config_history RENAME TO cch_raw;") != 0 ||
        exec_sql(w, "ALTER TABLE cch_raw ADD COLUMN bad INTEGER NOT NULL DEFAULT 0;") != 0)
    { FAIL("fixture view"); fx_free(&fx); return; }
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO cch_raw (param_id, new_value, effective_block,"
        " commit_block, tx_hash, proposal_nonce, created_at_unix, bad)"
        " VALUES (%u, 7, 1, 1, x'00', 1, 0, 1);", (unsigned)P_TAC);
    if (exec_sql(w, sql) != 0 ||
        exec_sql(w, "CREATE VIEW chain_config_history AS SELECT param_id,"
                    "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE new_value END"
                    "    AS new_value,"
                    "  effective_block, commit_block, tx_hash, proposal_nonce,"
                    "  created_at_unix FROM cch_raw;") != 0)
    { FAIL("fixture view"); fx_free(&fx); return; }
    w->chain_config_cache_warm = false;

    uint64_t v = 0x5A5A5A5A5A5A5A5AULL;
    g_fail_sql = NULL;
    int rc = nodus_chain_config_get_u64(w, P_TXS, 1000, 42ULL, &v);
    if (rc != 1 || v != 42ULL) { FAIL("control: expected ABSENT + default"); fx_free(&fx); return; }
    if (w->chain_config_cache_warm) { FAIL("fixture: cache warmed, cold path not driven"); fx_free(&fx); return; }

    v = 0x5A5A5A5A5A5A5A5AULL;
    g_fail_sql = "FROM chain_config_history WHERE param_id";
    rc = nodus_chain_config_get_u64(w, P_TXS, 1000, 42ULL, &v);
    g_fail_sql = NULL;
    if (rc == -1 && v == 0x5A5A5A5A5A5A5A5AULL) PASS();
    else FAIL("a failed bind did not answer -1 (or wrote the out value)");
    fx_free(&fx);
}

static void t_vset_get(void) {
    TEST("vset_get: a failed bind is -1, not absent (1)");
    fx_t fx;
    if (fx_up(&fx, "vs") != 0) { FAIL("fixture"); fx_free(&fx); return; }
    dna_vset_snapshot_t *snap = NULL;
    uint8_t h[DNA_VSET_HASH_LEN];

    g_fail_sql = NULL;
    int rc = nodus_witness_vset_get(fx.w, 123456, &snap, h);
    if (rc != 1) { FAIL("control: an empty table is ABSENT (1)"); fx_free(&fx); return; }

    g_fail_sql = "FROM validator_set_snapshots WHERE epoch_start";
    rc = nodus_witness_vset_get(fx.w, 123456, &snap, h);
    g_fail_sql = NULL;
    if (rc == -1 && snap == NULL) PASS();
    else FAIL("a failed bind did not answer -1");
    fx_free(&fx);
}

static void t_storage_set_get(void) {
    TEST("storage_set_get: a failed bind is -1, not absent (1)");
    fx_t fx;
    if (fx_up(&fx, "st") != 0) { FAIL("fixture"); fx_free(&fx); return; }
    nodus_storage_set_t out;

    g_fail_sql = NULL;
    int rc = nodus_witness_storage_set_get(fx.w, 720, &out);
    if (rc != 1) { FAIL("control: an empty table is ABSENT (1)"); fx_free(&fx); return; }

    g_fail_sql = "FROM v2_storage_sets";
    rc = nodus_witness_storage_set_get(fx.w, 720, &out);
    g_fail_sql = NULL;
    if (rc == -1) PASS();
    else FAIL("a failed bind did not answer -1");
    fx_free(&fx);
}

static void t_report_committed(void) {
    TEST("stprobe_report_committed: a failed bind is -1, not 0");
    fx_t fx;
    if (fx_up(&fx, "rp") != 0) { FAIL("fixture"); fx_free(&fx); return; }

    g_fail_sql = NULL;
    int rc = nodus_witness_stprobe_report_committed(fx.w, 720, 3);
    if (rc != 0) { FAIL("control: nothing committed is 0"); fx_free(&fx); return; }

    g_fail_sql = "FROM v2_storage_reports";
    rc = nodus_witness_stprobe_report_committed(fx.w, 720, 3);
    g_fail_sql = NULL;
    if (rc == -1) PASS();
    else FAIL("a failed bind did not answer -1");
    fx_free(&fx);
}

int main(void) {
    printf("=== Witness readers: a failed bind is a fault (Z-50) ===\n");
    t_get_u64();
    t_vset_get();
    t_storage_set_get();
    t_report_committed();
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed ? 1 : 0;
}
