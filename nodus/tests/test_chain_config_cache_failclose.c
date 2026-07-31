/**
 * Nodus — chain_config cache fail-close (round-3 item 6)
 *
 * cc_cache_warm_from_db walked chain_config_history with
 * `while (sqlite3_step(stmt) == SQLITE_ROW)` and no post-loop rc check,
 * then set chain_config_cache_warm = true unconditionally. A mid-scan
 * SQLITE_IOERR / SQLITE_CORRUPT therefore produced a PARTIAL cache that
 * nodus_chain_config_get_u64 served as authoritative from its fast path:
 * an override row that got truncated away simply stopped existing, so
 * that node used a different max_txs_per_block / block_interval_sec /
 * inflation_start_block than its peers. Fee and block-time parameters
 * diverging silently is a consensus split with no Byzantine actor.
 *
 * The fix keeps the cache COLD on a failed scan, which routes every
 * lookup through the DB-direct fallback the function already had.
 *
 * DETERMINISM: the fault is structural, not timed. chain_config_history
 * is a VIEW whose param-2 row projects abs(-9223372036854775808) —
 * SQLite raises "integer overflow" when that row is stepped over. An
 * index on (param_id, effective_block) makes the ORDER BY stream off the
 * index instead of a sorter, so the param-1 row IS returned first and the
 * error lands genuinely MID-scan: pre-fix the cache held exactly one row
 * and was still marked warm. No sleeps, no timing, no randomness.
 *
 * FIXTURE: nodus_witness_t is multi-MB — calloc, never the stack.
 */

#include "witness/nodus_witness.h"
#include "nodus/nodus_chain_config.h"
#include "dnac/dnac.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-58s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* Same step-time fault as test_merkle_scan_fail_close.c. */
#define OVERFLOW_EXPR "abs(-9223372036854775808)"

#define P_TXS   ((uint8_t)DNAC_CFG_MAX_TXS_PER_BLOCK)      /* 1 */
#define P_INTV  ((uint8_t)DNAC_CFG_BLOCK_INTERVAL_SEC)     /* 2 */

#define TXS_OVERRIDE   7ULL
#define INTV_OVERRIDE  30ULL
#define TXS_DEFAULT    3ULL
#define INTV_DEFAULT   11ULL

static nodus_witness_t *witness_new(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) {
        sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

static void witness_free(nodus_witness_t *w) {
    if (!w) return;
    sqlite3_close(w->db);
    free(w);
}

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql error: %s\n  in: %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* chain_config_history as a VIEW over cch_raw. `poison_param` (0 = none)
 * names the param_id whose new_value raises at step time. Two override
 * rows, one per param, so a truncated scan is observable: the param-1 row
 * is cached, the param-2 row is not. */
static int fixture(nodus_witness_t *w, int poison_param) {
    if (exec_sql(w,
        "CREATE TABLE cch_raw ("
        "  param_id INTEGER NOT NULL,"
        "  new_value INTEGER NOT NULL,"
        "  effective_block INTEGER NOT NULL,"
        "  commit_block INTEGER NOT NULL,"
        "  proposal_nonce INTEGER NOT NULL,"
        "  bad INTEGER NOT NULL DEFAULT 0"
        ");") != 0) return -1;

    /* Index so the loader's ORDER BY param_id, effective_block streams off
     * the index — without it SQLite sorts first and the fault would fire
     * before any row is returned, which is a weaker (not mid-scan) case. */
    if (exec_sql(w,
        "CREATE INDEX idx_cch ON cch_raw(param_id, effective_block);") != 0)
        return -1;

    if (exec_sql(w,
        "CREATE VIEW chain_config_history AS SELECT param_id,"
        "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE new_value END"
        "    AS new_value,"
        "  effective_block, commit_block, proposal_nonce FROM cch_raw;") != 0)
        return -1;

    struct { uint8_t param; uint64_t value; } rows[2] = {
        { P_TXS,  TXS_OVERRIDE  },
        { P_INTV, INTV_OVERRIDE },
    };

    for (int i = 0; i < 2; i++) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
            "INSERT INTO cch_raw (param_id, new_value, effective_block,"
            " commit_block, proposal_nonce, bad) VALUES (?, ?, 1, 1, ?, ?)",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
        sqlite3_bind_int(stmt, 1, (int)rows[i].param);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)rows[i].value);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)(i + 1));
        sqlite3_bind_int(stmt, 4,
                         (poison_param && rows[i].param == poison_param) ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* Non-vacuity: a healthy table warms the cache and serves both overrides. */
static void test_healthy_warms_and_serves(void) {
    TEST("healthy chain_config warms the cache and serves overrides");

    nodus_witness_t *w = witness_new();
    if (!w) { FAIL("alloc"); return; }
    if (fixture(w, 0) != 0) { FAIL("fixture"); witness_free(w); return; }

    uint64_t txs = nodus_chain_config_get_u64(w, P_TXS, 100, TXS_DEFAULT);
    if (txs != TXS_OVERRIDE) { FAIL("param 1 override not served"); goto done; }
    if (!w->chain_config_cache_warm) { FAIL("cache not warm"); goto done; }
    if (w->chain_config_cache_count[P_TXS] != 1) { FAIL("param 1 not cached"); goto done; }
    if (w->chain_config_cache_count[P_INTV] != 1) { FAIL("param 2 not cached"); goto done; }

    uint64_t intv = nodus_chain_config_get_u64(w, P_INTV, 100, INTV_DEFAULT);
    if (intv != INTV_OVERRIDE) { FAIL("param 2 override not served"); goto done; }

    PASS();
done:
    witness_free(w);
}

/* The fix: a mid-scan step error must NOT leave a partial cache marked
 * warm. Pre-fix, cache_warm was true with exactly one row cached, and
 * every later lookup was answered from that truncated set. */
static void test_scan_error_leaves_cache_cold(void) {
    TEST("mid-scan step error leaves the cache COLD, not partial+warm");

    nodus_witness_t *w = witness_new();
    if (!w) { FAIL("alloc"); return; }
    if (fixture(w, P_INTV) != 0) { FAIL("fixture"); witness_free(w); return; }

    /* This call performs the warm attempt. */
    uint64_t txs = nodus_chain_config_get_u64(w, P_TXS, 100, TXS_DEFAULT);

    if (w->chain_config_cache_warm) {
        FAIL("cache marked warm after a failed scan");
        goto done;
    }
    for (int i = 0; i < 4; i++) {
        if (w->chain_config_cache_count[i] != 0) {
            FAIL("partial cache retained after a failed scan");
            goto done;
        }
    }

    /* And the fallback still answers correctly for the readable param:
     * the DB-direct query filters on param_id before projecting
     * new_value, so the poisoned param-2 row is never evaluated. */
    if (txs != TXS_OVERRIDE) {
        FAIL("DB-direct fallback did not serve the readable override");
        goto done;
    }

    /* Repeat: still cold, still correct — the failed warm must not be
     * latched into a wrong answer on any later call either. */
    uint64_t again = nodus_chain_config_get_u64(w, P_TXS, 100, TXS_DEFAULT);
    if (again != TXS_OVERRIDE || w->chain_config_cache_warm) {
        FAIL("second lookup diverged from the first");
        goto done;
    }

    PASS();
done:
    witness_free(w);
}

int main(void) {
    printf("\nNodus chain_config cache fail-close (round-3 item 6)\n");
    printf("============================================================\n\n");

    test_healthy_warms_and_serves();
    test_scan_error_leaves_cache_cold();

    printf("\n============================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
