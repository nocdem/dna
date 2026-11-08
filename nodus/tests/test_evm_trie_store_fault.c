/**
 * @file test_evm_trie_store_fault.c
 * @brief HF-9 review T-3 (Z-51): a failed sqlite3_bind_blob in the EVM trie
 *        node store (ts_get / ts_put in nodus_witness_rt_evm.c) is -2 before
 *        the statement is stepped.
 *
 * Plan: docs/plans/approved/2026-11-04-hf9.md §3.1 row Z-51, §12 row T-3.
 * Rule: nodus/CLAUDE.md "A DB failure is never a value".
 *
 * WHAT IT PROVES (ts_put binds: #1 the SELECT digest, #2 the INSERT digest,
 * #3 the INSERT body; ts_get binds: #1 the SELECT digest):
 *   1. control: with no bind armed, ts_put of a fresh node returns 0, makes
 *      exactly 3 bind calls and leaves one row; ts_put of the same node
 *      again returns 0 (idempotent) and ts_get returns it with 1 bind call
 *      - so the hit counter counts what it claims to and the injection is
 *      not the only way these calls could return -2;
 *   2. ts_put with bind #1, #2 or #3 failing returns -2, the hit counter
 *      equals the failed bind's number (the statement stopped at the failed
 *      bind, no later bind was made), no row was written, and a
 *      sqlite3_trace_v2 step observer saw no INSERT stepped, and the SELECT
 *      stepped only when bind #1 had passed - so removing the bind-result
 *      check of any put bind is caught even where the step would have
 *      failed anyway (a NULL body breaks NOT NULL);
 *   3. ts_get with bind #1 failing returns -2 although the row exists, with
 *      hit counter 1 and no statement stepped;
 *   4. through the trie: a commit whose first put bind fails returns -2 and
 *      the handle is sticky (a later get is -2 with no further store call).
 *
 * COMPILE FLAGS (apart from environment): needs -DQGP_FAULT_INJECT=ON on
 * the cmake line of the nodus build (option in nodus/CMakeLists.txt, which
 * also refuses a Release build with it). The target exists only then, and
 * only where NODUS_EVM_ENABLED. No environment variable is read.
 *
 * LEAVES BEHIND: nothing - an in-memory sqlite database, closed at exit.
 *
 * HOW IT CAN FALSELY PASS OR SKIP:
 *   - Without the flag the target is not registered, so nothing runs and
 *     ctest does not list it: that is missing coverage, not a pass. If this
 *     file is compiled without the flag by hand, #error stops it.
 *   - A hook that counted nothing would fail case 1 (3 and 1 hits asserted)
 *     and every case asserts the hit count after the call; a store that
 *     returned -2 for every input would fail the control.
 *   - The step observer counts statements whose SQL text starts with SELECT
 *     or INSERT; if ts_put's SQL were reworded to start otherwise, the
 *     observer would count nothing, and the control (1 SELECT and 1 INSERT
 *     stepped by a fresh put) would fail.
 *   - The table definition below is a copy of nodus_witness_v2_schema.c
 *     (evm_trie_nodes); if the schema changes without this copy, the test
 *     checks the store against the old shape.
 *   - The hook prototypes are declared here, not in a header: they are
 *     test-only and live in nodus_witness_rt_evm.c under QGP_FAULT_INJECT.
 */
#ifndef QGP_FAULT_INJECT
#error "test_evm_trie_store_fault needs -DQGP_FAULT_INJECT=ON"
#endif

#include "evm_trie.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* nodus_witness_rt_evm.c, QGP_FAULT_INJECT only */
int nodus_rt_evm_test_ts_bind_arm(int nth);
int nodus_rt_evm_test_ts_bind_hits(void);
int nodus_rt_evm_test_trie_store(sqlite3 *db, evm_trie_store_t *out);

static int g_fail;

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                     \
            printf(__VA_ARGS__);                                            \
            printf("\n");                                                   \
            g_fail++;                                                       \
        }                                                                   \
    } while (0)

static sqlite3 *open_db(void)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return NULL;
    /* copy of nodus_witness_v2_schema.c evm_trie_nodes */
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS evm_trie_nodes ("
            "  digest BLOB PRIMARY KEY,"
            "  rlp BLOB NOT NULL"
            ");", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

/* Statement-step observer: sqlite3_trace_v2 SQLITE_TRACE_STMT fires when a
 * statement is first stepped, so a statement that was prepared but never
 * stepped is not counted. Counts the SELECT and INSERT of the node store. */
static int g_stepped_select;
static int g_stepped_insert;

static int trace_cb(unsigned type, void *ctx, void *p, void *x)
{
    (void)ctx; (void)p;
    if (type == SQLITE_TRACE_STMT && x) {
        const char *sql = (const char *)x;
        if (strncmp(sql, "SELECT", 6) == 0) g_stepped_select++;
        else if (strncmp(sql, "INSERT", 6) == 0) g_stepped_insert++;
    }
    return 0;
}

static void trace_reset(void)
{
    g_stepped_select = 0;
    g_stepped_insert = 0;
}

static int row_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM evm_trie_nodes", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static void fill_node(uint8_t digest[64], uint8_t rlp[70])
{
    for (int i = 0; i < 64; i++) digest[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 70; i++) rlp[i] = (uint8_t)(i * 7 + 1);
}

static void test_control(void)
{
    sqlite3 *db = open_db();
    evm_trie_store_t s;
    uint8_t d[64], r[70];
    fill_node(d, r);
    CHECK(db && nodus_rt_evm_test_trie_store(db, &s) == 0, "setup");
    if (!db) return;

    CHECK(sqlite3_trace_v2(db, SQLITE_TRACE_STMT, trace_cb, NULL) ==
          SQLITE_OK, "trace setup");
    trace_reset();
    nodus_rt_evm_test_ts_bind_arm(0);
    CHECK(s.put(s.ctx, d, r, 70) == 0, "control: fresh put is 0");
    CHECK(g_stepped_select == 1 && g_stepped_insert == 1,
          "control: fresh put steps 1 SELECT and 1 INSERT (SELECT %d, "
          "INSERT %d) - the observer sees what it claims to",
          g_stepped_select, g_stepped_insert);
    CHECK(nodus_rt_evm_test_ts_bind_hits() == 3,
          "control: fresh put makes 3 binds, got %d",
          nodus_rt_evm_test_ts_bind_hits());
    CHECK(row_count(db) == 1, "control: one row");

    nodus_rt_evm_test_ts_bind_arm(0);
    CHECK(s.put(s.ctx, d, r, 70) == 0, "control: the same put again is 0");
    CHECK(nodus_rt_evm_test_ts_bind_hits() == 1,
          "control: idempotent put makes 1 bind (SELECT only), got %d",
          nodus_rt_evm_test_ts_bind_hits());

    nodus_rt_evm_test_ts_bind_arm(0);
    uint8_t *got = NULL;
    size_t gl = 0;
    CHECK(s.get(s.ctx, d, &got, &gl) == 0 && gl == 70 && got &&
          memcmp(got, r, 70) == 0, "control: get returns the node");
    free(got);
    CHECK(nodus_rt_evm_test_ts_bind_hits() == 1,
          "control: get makes 1 bind, got %d",
          nodus_rt_evm_test_ts_bind_hits());
    sqlite3_close(db);
    printf("ok   control (no bind armed)\n");
}

static void test_put_bind_failures(void)
{
    for (int nth = 1; nth <= 3; nth++) {
        sqlite3 *db = open_db();
        evm_trie_store_t s;
        uint8_t d[64], r[70];
        fill_node(d, r);
        CHECK(db && nodus_rt_evm_test_trie_store(db, &s) == 0, "setup");
        if (!db) return;
        CHECK(sqlite3_trace_v2(db, SQLITE_TRACE_STMT, trace_cb, NULL) ==
              SQLITE_OK, "trace setup");
        trace_reset();
        nodus_rt_evm_test_ts_bind_arm(nth);
        CHECK(s.put(s.ctx, d, r, 70) == -2, "put with bind #%d failing is -2",
              nth);
        /* the SELECT is stepped only if bind #1 passed; the INSERT never */
        CHECK(g_stepped_select == (nth == 1 ? 0 : 1),
              "put bind #%d: SELECT stepped %d time(s)", nth,
              g_stepped_select);
        CHECK(g_stepped_insert == 0,
              "put bind #%d: INSERT stepped %d time(s) after a failed bind",
              nth, g_stepped_insert);
        CHECK(nodus_rt_evm_test_ts_bind_hits() == nth,
              "put bind #%d: reached, and nothing after it (hits %d)", nth,
              nodus_rt_evm_test_ts_bind_hits());
        CHECK(row_count(db) == 0, "put bind #%d: no row written", nth);
        nodus_rt_evm_test_ts_bind_arm(0);
        sqlite3_close(db);
    }
    printf("ok   ts_put: each of its 3 binds failing -> -2, no row\n");
}

static void test_get_bind_failure(void)
{
    sqlite3 *db = open_db();
    evm_trie_store_t s;
    uint8_t d[64], r[70];
    fill_node(d, r);
    CHECK(db && nodus_rt_evm_test_trie_store(db, &s) == 0, "setup");
    if (!db) return;
    nodus_rt_evm_test_ts_bind_arm(0);
    CHECK(s.put(s.ctx, d, r, 70) == 0, "get setup: put");

    CHECK(sqlite3_trace_v2(db, SQLITE_TRACE_STMT, trace_cb, NULL) ==
          SQLITE_OK, "trace setup");
    trace_reset();
    nodus_rt_evm_test_ts_bind_arm(1);
    uint8_t *got = NULL;
    size_t gl = 0;
    CHECK(s.get(s.ctx, d, &got, &gl) == -2,
          "get with its bind failing is -2 although the row exists");
    CHECK(g_stepped_select == 0 && g_stepped_insert == 0,
          "get: no statement stepped after the failed bind (SELECT %d, "
          "INSERT %d)", g_stepped_select, g_stepped_insert);
    CHECK(got == NULL, "get with a failed bind returns no buffer");
    free(got);
    CHECK(nodus_rt_evm_test_ts_bind_hits() == 1, "get bind reached (hits %d)",
          nodus_rt_evm_test_ts_bind_hits());
    nodus_rt_evm_test_ts_bind_arm(0);
    sqlite3_close(db);
    printf("ok   ts_get: its bind failing -> -2\n");
}

static void test_through_trie(void)
{
    sqlite3 *db = open_db();
    evm_trie_store_t s;
    CHECK(db && nodus_rt_evm_test_trie_store(db, &s) == 0, "setup");
    if (!db) return;

    uint8_t empty[64], root[64];
    CHECK(evm_trie_empty_root(empty) == 0, "empty root");
    evm_trie_t *t = NULL;
    CHECK(evm_trie_open(&s, empty, &t) == 0 && t, "open");
    if (!t) { sqlite3_close(db); return; }
    uint8_t key[3] = { 1, 2, 3 }, val[64];
    memset(val, 0x5A, sizeof(val));      /* 64-byte value: the leaf is hashed */
    CHECK(evm_trie_set(t, key, sizeof(key), val, sizeof(val)) == 0, "set");

    nodus_rt_evm_test_ts_bind_arm(1);
    CHECK(evm_trie_commit(t, root) == -2, "commit with the first put bind "
          "failing is -2");
    CHECK(nodus_rt_evm_test_ts_bind_hits() == 1, "commit reached the bind "
          "(hits %d)", nodus_rt_evm_test_ts_bind_hits());
    CHECK(row_count(db) == 0, "commit: no row written");

    uint8_t *v = NULL;
    size_t vl = 0;
    nodus_rt_evm_test_ts_bind_arm(0);
    CHECK(evm_trie_get(t, key, sizeof(key), &v, &vl) == -2,
          "the handle is sticky after the store fault");
    free(v);
    CHECK(nodus_rt_evm_test_ts_bind_hits() == 0,
          "sticky: no further store call (hits %d)",
          nodus_rt_evm_test_ts_bind_hits());
    evm_trie_close(t);
    sqlite3_close(db);
    printf("ok   through the trie: commit -2, handle sticky\n");
}

int main(void)
{
    test_control();
    test_put_bind_failures();
    test_get_bind_failure();
    test_through_trie();
    printf("%s: %d failure(s)\n", g_fail ? "FAILED" : "PASSED", g_fail);
    return g_fail ? 1 : 0;
}
