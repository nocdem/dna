/**
 * Nodus — DHT hinted-handoff caps (DHT Package A, F4)
 *
 * Proves: nodus_storage_hinted_insert never lets the hint table grow past
 * NODUS_DHT_HINT_PEER_MAX_ROWS rows or NODUS_DHT_HINT_PEER_MAX_BYTES frame
 * bytes for one target node id, nor past NODUS_DHT_HINT_TOTAL_MAX_BYTES over
 * the whole table — a refused insert returns exactly NODUS_STORAGE_RC_QUOTA
 * and stores nothing; a duplicate frame at the cap is still "ignored, 0";
 * caps of one peer do not block another; new hints expire after
 * NODUS_DHT_HINT_TTL_SEC (24 h); hinted_get keeps its signature and returns
 * the capped rows; the whole-table total the global cap reads (a one-row
 * table kept by SQLite triggers) equals SUM(LENGTH(frame_data)) after
 * insert, ignored duplicate, hinted_delete and hinted_cleanup, and a delete
 * frees room under the global cap; the per-peer usage query is a SEARCH on
 * node_id (EXPLAIN QUERY PLAN of the prepared statement's own SQL).
 * The per-peer-before-total ORDER inside hinted_insert is not observable
 * from outside; it is read in the code, not proven here.
 *
 * Requires: default build. Leaves behind: nothing (fixture DB unlinked).
 * The global-cap case writes 128 MiB of frames into the fixture DB under
 * /tmp (removed on close) — needs that much free disk.
 * How it can lie: none known — every refusal is checked against the row
 * count / byte totals read back through hinted_get / hinted_count.
 */

#include "core/nodus_storage.h"
#include "test_storage_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static uint8_t *g_buf;   /* NODUS_DHT_HINT_PEER_MAX_BYTES + 1 bytes, heap */

static nodus_key_t make_key(uint8_t fill) {
    nodus_key_t k;
    memset(k.bytes, fill, NODUS_KEY_BYTES);
    return k;
}

/* Distinct frame of len bytes: tag in the first 4 bytes defeats the dedup. */
static const uint8_t *frame(uint32_t tag, size_t len) {
    memset(g_buf, 0xEE, len);
    if (len >= 4) memcpy(g_buf, &tag, 4);
    else if (len > 0) g_buf[0] = (uint8_t)tag;
    return g_buf;
}

static int64_t query_i64(nodus_storage_t *st, const char *sql) {
    sqlite3_stmt *s = NULL;
    int64_t v = -1;
    if (sqlite3_prepare_v2(st->db, sql, -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

/* The trigger-kept whole-table total the global cap reads. */
static int64_t hint_total(nodus_storage_t *st) {
    return query_i64(st, "SELECT total_bytes FROM dht_hint_totals WHERE id = 1");
}

/* 1 if the kept total equals the table's real frame byte sum. */
static int total_consistent(nodus_storage_t *st) {
    int64_t real = query_i64(st,
        "SELECT COALESCE(SUM(LENGTH(frame_data)), 0) FROM dht_hinted_handoff");
    return real >= 0 && real == hint_total(st);
}

static void test_row_cap(void) {
    TEST("64 hints for one peer stored, 65th refused");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t node = make_key(0xA1);
    int ok = 1;
    for (uint32_t i = 0; i < NODUS_DHT_HINT_PEER_MAX_ROWS; i++)
        if (nodus_storage_hinted_insert(&st, &node, "10.0.0.1", 4002,
                                        frame(i, 64), 64) != 0) ok = 0;
    int rc = nodus_storage_hinted_insert(&st, &node, "10.0.0.1", 4002,
                                         frame(9999, 64), 64);
    int n = nodus_storage_hinted_count(&st);
    if (ok && rc == NODUS_STORAGE_RC_QUOTA && n == NODUS_DHT_HINT_PEER_MAX_ROWS) PASS();
    else FAIL("65th hint must be refused, table stays at 64");
    test_storage_close(&st);
}

static void test_row_cap_duplicate_ok(void) {
    TEST("at the row cap, a duplicate frame -> 0 (ignored)");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t node = make_key(0xA2);
    int ok = 1;
    for (uint32_t i = 0; i < NODUS_DHT_HINT_PEER_MAX_ROWS; i++)
        if (nodus_storage_hinted_insert(&st, &node, "10.0.0.2", 4002,
                                        frame(i, 64), 64) != 0) ok = 0;
    int rc = nodus_storage_hinted_insert(&st, &node, "10.0.0.2", 4002,
                                         frame(0, 64), 64);
    int n = nodus_storage_hinted_count(&st);
    if (ok && rc == 0 && n == NODUS_DHT_HINT_PEER_MAX_ROWS) PASS();
    else FAIL("duplicate at cap must stay ignored (0)");
    test_storage_close(&st);
}

static void test_row_cap_other_peer(void) {
    TEST("peer A at row cap does not block peer B");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t a = make_key(0xA3), b = make_key(0xB3);
    for (uint32_t i = 0; i < NODUS_DHT_HINT_PEER_MAX_ROWS; i++)
        nodus_storage_hinted_insert(&st, &a, "10.0.0.3", 4002, frame(i, 64), 64);
    int rc = nodus_storage_hinted_insert(&st, &b, "10.0.0.4", 4002,
                                         frame(1, 64), 64);
    if (rc == 0) PASS(); else FAIL("other peer must still queue");
    test_storage_close(&st);
}

static void test_peer_byte_cap(void) {
    TEST("one peer: 16 MiB stored, +1 byte refused");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t node = make_key(0xA4);
    size_t half = (size_t)(NODUS_DHT_HINT_PEER_MAX_BYTES / 2);
    int rc1 = nodus_storage_hinted_insert(&st, &node, "10.0.0.5", 4002,
                                          frame(1, half), half);
    int rc2 = nodus_storage_hinted_insert(&st, &node, "10.0.0.5", 4002,
                                          frame(2, half), half);
    int rc3 = nodus_storage_hinted_insert(&st, &node, "10.0.0.5", 4002,
                                          frame(3, 1), 1);
    nodus_dht_hint_t *e = NULL;
    size_t cnt = 0;
    int grc = nodus_storage_hinted_get(&st, &node, 100, &e, &cnt);
    size_t total = 0;
    for (size_t i = 0; i < cnt; i++) total += e[i].frame_len;
    if (rc1 == 0 && rc2 == 0 && rc3 == NODUS_STORAGE_RC_QUOTA && grc == 0 && cnt == 2 &&
        total == (size_t)NODUS_DHT_HINT_PEER_MAX_BYTES)
        PASS();
    else
        FAIL("per-peer byte cap must hold at exactly 16 MiB");
    if (e) nodus_storage_hinted_free(e, cnt);
    test_storage_close(&st);
}

static void test_single_oversized_frame(void) {
    TEST("one frame of 16 MiB + 1 refused, nothing stored");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t node = make_key(0xA5);
    size_t len = (size_t)NODUS_DHT_HINT_PEER_MAX_BYTES + 1;
    int rc = nodus_storage_hinted_insert(&st, &node, "10.0.0.6", 4002,
                                         frame(1, len), len);
    if (rc == NODUS_STORAGE_RC_QUOTA && nodus_storage_hinted_count(&st) == 0) PASS();
    else FAIL("oversized frame must be refused");
    test_storage_close(&st);
}

static void test_global_byte_cap(void) {
    TEST("8 peers x 16 MiB = 128 MiB stored; 9th peer refused");
    nodus_storage_t st;
    test_storage_open(&st);
    size_t len = (size_t)NODUS_DHT_HINT_PEER_MAX_BYTES;
    int n_peers = (int)(NODUS_DHT_HINT_TOTAL_MAX_BYTES / NODUS_DHT_HINT_PEER_MAX_BYTES);
    int ok = 1;
    for (int p = 0; p < n_peers; p++) {
        nodus_key_t node = make_key((uint8_t)(0x10 + p));
        if (nodus_storage_hinted_insert(&st, &node, "10.0.1.1", 4002,
                                        frame((uint32_t)p, len), len) != 0) ok = 0;
    }
    nodus_key_t extra = make_key(0xF0);
    int rc = nodus_storage_hinted_insert(&st, &extra, "10.0.1.2", 4002,
                                         frame(77, 1), 1);
    int ok2 = total_consistent(&st) &&
              hint_total(&st) == (int64_t)NODUS_DHT_HINT_TOTAL_MAX_BYTES;
    /* deleting one peer's hint frees its bytes in the total */
    nodus_key_t first = make_key(0x10);
    nodus_dht_hint_t *e = NULL;
    size_t cnt = 0;
    int ok3 = nodus_storage_hinted_get(&st, &first, 10, &e, &cnt) == 0 && cnt == 1 &&
              nodus_storage_hinted_delete(&st, e[0].id) == 0;
    if (e) nodus_storage_hinted_free(e, cnt);
    int rc2 = nodus_storage_hinted_insert(&st, &extra, "10.0.1.2", 4002,
                                          frame(77, 1), 1);
    if (ok && rc == NODUS_STORAGE_RC_QUOTA && ok2 && ok3 && rc2 == 0 &&
        nodus_storage_hinted_count(&st) == n_peers && total_consistent(&st))
        PASS();
    else
        FAIL("global 128 MiB cap must refuse the next byte; delete frees");
    test_storage_close(&st);
}

static void test_total_tracks_every_path(void) {
    TEST("trigger total == SUM(frame bytes): insert/dup/delete/cleanup");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t a = make_key(0xA7), b = make_key(0xB7);
    int ok = hint_total(&st) == 0 && total_consistent(&st);
    ok = ok && nodus_storage_hinted_insert(&st, &a, "10.0.0.8", 4002, frame(1, 100), 100) == 0;
    ok = ok && nodus_storage_hinted_insert(&st, &a, "10.0.0.8", 4002, frame(2, 50), 50) == 0;
    ok = ok && nodus_storage_hinted_insert(&st, &b, "10.0.0.9", 4002, frame(3, 7), 7) == 0;
    /* duplicate: ignored, total unchanged */
    ok = ok && nodus_storage_hinted_insert(&st, &a, "10.0.0.8", 4002, frame(1, 100), 100) == 0;
    ok = ok && hint_total(&st) == 157 && total_consistent(&st);

    nodus_dht_hint_t *e = NULL;
    size_t cnt = 0;
    ok = ok && nodus_storage_hinted_get(&st, &b, 10, &e, &cnt) == 0 && cnt == 1 &&
         nodus_storage_hinted_delete(&st, e[0].id) == 0;
    if (e) nodus_storage_hinted_free(e, cnt);
    ok = ok && hint_total(&st) == 150 && total_consistent(&st);

    /* cleanup of expired rows (forced into the past) moves the total too */
    ok = ok && sqlite3_exec(st.db, "UPDATE dht_hinted_handoff SET expires_at = 1",
                            NULL, NULL, NULL) == SQLITE_OK;
    ok = ok && nodus_storage_hinted_cleanup(&st) == 2;
    ok = ok && hint_total(&st) == 0 && total_consistent(&st) &&
         nodus_storage_hinted_count(&st) == 0;
    if (ok) PASS(); else FAIL("the trigger-kept total must equal the table");
    test_storage_close(&st);
}

static void test_peer_usage_plan(void) {
    TEST("per-peer usage query is a SEARCH on node_id");
    nodus_storage_t st;
    test_storage_open(&st);
    const char *sql = sqlite3_sql(st.stmt_hint_peer_usage);
    char q[512];
    int found = 0;
    if (sql && strlen(sql) + 20 < sizeof(q)) {
        snprintf(q, sizeof(q), "EXPLAIN QUERY PLAN %s", sql);
        sqlite3_stmt *e = NULL;
        if (sqlite3_prepare_v2(st.db, q, -1, &e, NULL) == SQLITE_OK) {
            while (sqlite3_step(e) == SQLITE_ROW) {
                const char *d = (const char *)sqlite3_column_text(e, 3);
                /* sqlite 3.44: "SEARCH dht_hinted_handoff USING INDEX
                 * idx_dht_hint_dedup (node_id=?)" */
                if (d && strstr(d, "SEARCH dht_hinted_handoff") && strstr(d, "node_id=?"))
                    found = 1;
            }
        }
        sqlite3_finalize(e);
    }
    if (found) PASS(); else FAIL("per-peer usage must not scan the hint table");
    test_storage_close(&st);
}

static void test_ttl_24h(void) {
    TEST("new hint expires 24 h after creation");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t node = make_key(0xA6);
    nodus_storage_hinted_insert(&st, &node, "10.0.0.7", 4002, frame(1, 8), 8);
    nodus_dht_hint_t *e = NULL;
    size_t cnt = 0;
    int rc = nodus_storage_hinted_get(&st, &node, 10, &e, &cnt);
    if (rc == 0 && cnt == 1 &&
        e[0].expires_at - e[0].created_at == (uint64_t)NODUS_DHT_HINT_TTL_SEC &&
        NODUS_DHT_HINT_TTL_SEC == 86400)
        PASS();
    else
        FAIL("hint TTL must be 24 h");
    if (e) nodus_storage_hinted_free(e, cnt);
    test_storage_close(&st);
}

int main(void) {
    printf("=== Nodus DHT hinted-handoff caps ===\n");
    g_buf = malloc((size_t)NODUS_DHT_HINT_PEER_MAX_BYTES + 1);
    if (!g_buf) { printf("alloc failed\n"); return 1; }

    test_row_cap();
    test_row_cap_duplicate_ok();
    test_row_cap_other_peer();
    test_peer_byte_cap();
    test_single_oversized_frame();
    test_global_byte_cap();
    test_ttl_24h();
    test_total_tracks_every_path();
    test_peer_usage_plan();

    free(g_buf);
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
