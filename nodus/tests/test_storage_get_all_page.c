/**
 * Nodus — owner-scoped and paged reads (DHT Package A, S2/S3 storage half)
 *
 * Proves:
 *  - nodus_storage_get_owner returns that owner's newest row at the key
 *    (highest seq, then highest SHA3-256(data)) and -1 when it has none;
 *  - nodus_storage_get_all_page walks every row at a key exactly once, in
 *    PRIMARY KEY order (owner_fp bytewise ASC, value_id ASC as SIGNED int64),
 *    rows strictly after the cursor, with more=1 until the last page;
 *  - the page budget counts NODUS_VALUE_SERIALIZED_EST bytes, a first row
 *    larger than the budget comes back alone, an empty page is rc 0;
 *  - the owner filter combines with the cursor;
 *  - nodus_storage_get_all is unchanged (still returns every row);
 *  - a SQLite read fault is NODUS_STORAGE_RC_FAULT (-5) from get_owner,
 *    get_all_page and get — distinct from the miss code -1 — with the out
 *    parameters cleared (forced by swapping in a statement that fails at
 *    step).
 *
 * Requires: default build. Leaves behind: nothing (fixture DB unlinked).
 * How it can lie: the expected order is computed here with the same
 * (memcmp, int64) rule the header documents — if both were wrong in the
 * same way the test would agree with itself; the negative value_id row is
 * there so an unsigned order would be caught.
 */

#include "core/nodus_storage.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"
#include "test_storage_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

#define N_OWNERS 3
#define N_VIDS   3
#define N_ROWS   (N_OWNERS * N_VIDS)
#define DATA_LEN 32

static nodus_identity_t ids[N_OWNERS];
static nodus_key_t fps[N_OWNERS];
static const uint64_t vids[N_VIDS] = { 1, 2, 0x8000000000000001ULL /* < 0 as int64 */ };
static nodus_key_t g_key;

typedef struct { nodus_key_t fp; uint64_t vid; } pk_t;
static pk_t expected[N_ROWS];

static int pk_cmp(const void *a, const void *b) {
    const pk_t *x = a, *y = b;
    int c = memcmp(x->fp.bytes, y->fp.bytes, NODUS_KEY_BYTES);
    if (c) return c;
    int64_t vx = (int64_t)x->vid, vy = (int64_t)y->vid;
    return (vx < vy) ? -1 : (vx > vy) ? 1 : 0;
}

static nodus_value_t *make_val(int owner, const nodus_key_t *kh, uint64_t vid,
                               uint64_t seq, const char *tag, size_t len) {
    uint8_t *data = calloc(1, len);
    if (!data) return NULL;
    snprintf((char *)data, len, "%s", tag);
    nodus_value_t *v = NULL;
    if (nodus_value_create(kh, data, len, NODUS_VALUE_EPHEMERAL, 3600,
                           vid, seq, &ids[owner].pk, &v) != 0) { free(data); return NULL; }
    free(data);
    if (nodus_value_sign(v, &ids[owner].sk) != 0) { nodus_value_free(v); return NULL; }
    return v;
}

static int put_free(nodus_storage_t *st, nodus_value_t *v) {
    if (!v) return -100;
    int rc = nodus_storage_put(st, v);
    nodus_value_free(v);
    return rc;
}

static void free_vals(nodus_value_t **vals, size_t n) {
    for (size_t i = 0; i < n; i++) nodus_value_free(vals[i]);
    free(vals);
}

/* Store N_ROWS values (DATA_LEN bytes each) at g_key. */
static int populate(nodus_storage_t *st) {
    int k = 0;
    for (int o = 0; o < N_OWNERS; o++) {
        for (int j = 0; j < N_VIDS; j++) {
            char tag[16];
            snprintf(tag, sizeof(tag), "o%d-v%d", o, j);
            if (put_free(st, make_val(o, &g_key, vids[j], 1, tag, DATA_LEN)) != 0)
                return -1;
            expected[k].fp = fps[o];
            expected[k].vid = vids[j];
            k++;
        }
    }
    qsort(expected, N_ROWS, sizeof(pk_t), pk_cmp);
    return 0;
}

static int same_pk(const nodus_value_t *v, const pk_t *p) {
    return memcmp(v->owner_fp.bytes, p->fp.bytes, NODUS_KEY_BYTES) == 0 &&
           v->value_id == p->vid;
}

/* Walk every page with `budget`; check order, uniqueness, per-page size. */
static int walk(nodus_storage_t *st, size_t budget, size_t per_page) {
    size_t seen = 0;
    const nodus_key_t *after = NULL;
    nodus_key_t cur_fp;
    uint64_t cur_vid = 0;
    for (int guard = 0; guard < N_ROWS + 2; guard++) {
        nodus_value_t **vals = NULL;
        size_t cnt = 0;
        int more = -1;
        if (nodus_storage_get_all_page(st, &g_key, NULL, after, cur_vid, budget,
                                       &vals, &cnt, &more) != 0) return -1;
        if (cnt == 0 || cnt > per_page) { free_vals(vals, cnt); return -1; }
        for (size_t i = 0; i < cnt; i++) {
            if (seen >= N_ROWS || !same_pk(vals[i], &expected[seen])) {
                free_vals(vals, cnt); return -1;
            }
            seen++;
        }
        cur_fp = vals[cnt - 1]->owner_fp;
        cur_vid = vals[cnt - 1]->value_id;
        after = &cur_fp;
        free_vals(vals, cnt);
        if (!more) return (seen == N_ROWS) ? 0 : -1;
        if (seen == N_ROWS) return -1;   /* more=1 with nothing left */
        if (cnt != per_page) return -1;  /* a non-final page must be full */
    }
    return -1;
}

static void test_walk_one_per_page(void) {
    TEST("budget = 1 row: 9 pages, PK order (signed vid), more flags");
    nodus_storage_t st;
    test_storage_open(&st);
    size_t est = NODUS_VALUE_SERIALIZED_EST(DATA_LEN);
    int ok = populate(&st) == 0 && walk(&st, est, 1) == 0 &&
             walk(&st, 2 * est - 1, 1) == 0;
    if (ok) PASS(); else FAIL("1-row pages must walk all rows in PK order");
    test_storage_close(&st);
}

static void test_walk_two_per_page(void) {
    TEST("budget = exactly 2 rows: pages of 2, last of 1");
    nodus_storage_t st;
    test_storage_open(&st);
    size_t est = NODUS_VALUE_SERIALIZED_EST(DATA_LEN);
    int ok = populate(&st) == 0 && walk(&st, 2 * est, 2) == 0;
    if (ok) PASS(); else FAIL("2-row pages must walk all rows in PK order");
    test_storage_close(&st);
}

static void test_walk_all_in_one(void) {
    TEST("large budget: one page, all 9 rows, more = 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = populate(&st) == 0 &&
             walk(&st, NODUS_GET_ALL_PAGE_MAX_BYTES, N_ROWS) == 0;
    if (ok) PASS(); else FAIL("single page must hold every row");
    test_storage_close(&st);
}

static void test_cursor_strictly_after(void) {
    TEST("cursor at an existing row excludes that row");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = populate(&st) == 0;
    nodus_value_t **vals = NULL;
    size_t cnt = 0;
    int more = -1;
    int rc = nodus_storage_get_all_page(&st, &g_key, NULL, &expected[3].fp,
                                        expected[3].vid,
                                        NODUS_GET_ALL_PAGE_MAX_BYTES,
                                        &vals, &cnt, &more);
    ok = ok && rc == 0 && cnt == N_ROWS - 4 && more == 0;
    for (size_t i = 0; ok && i < cnt; i++)
        if (!same_pk(vals[i], &expected[4 + i])) ok = 0;
    if (ok) PASS(); else FAIL("rows must start strictly after the cursor");
    free_vals(vals, cnt);
    test_storage_close(&st);
}

static void test_cursor_past_end(void) {
    TEST("cursor at the last row: empty page, rc 0, more 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = populate(&st) == 0;
    nodus_value_t **vals = NULL;
    size_t cnt = 99;
    int more = -1;
    int rc = nodus_storage_get_all_page(&st, &g_key, NULL, &expected[N_ROWS - 1].fp,
                                        expected[N_ROWS - 1].vid,
                                        NODUS_GET_ALL_PAGE_MAX_BYTES,
                                        &vals, &cnt, &more);
    if (ok && rc == 0 && cnt == 0 && more == 0 && vals == NULL) PASS();
    else FAIL("empty page must be rc 0 / count 0 / more 0");
    free_vals(vals, cnt == 99 ? 0 : cnt);
    test_storage_close(&st);
}

static void test_empty_key(void) {
    TEST("key with no rows: rc 0, count 0, more 0");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t other;
    nodus_hash((const uint8_t *)"page-nothing", 12, &other);
    nodus_value_t **vals = NULL;
    size_t cnt = 99;
    int more = -1;
    int rc = nodus_storage_get_all_page(&st, &other, NULL, NULL, 0,
                                        NODUS_GET_ALL_PAGE_MAX_BYTES,
                                        &vals, &cnt, &more);
    if (rc == 0 && cnt == 0 && more == 0 && vals == NULL) PASS();
    else FAIL("empty key must be an empty page");
    test_storage_close(&st);
}

static void test_oversized_first_row(void) {
    TEST("first row larger than budget: returned alone, more = 1");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t kh;
    nodus_hash((const uint8_t *)"page-big", 8, &kh);
    /* owner order decides which row is first: put a big row for every owner */
    int ok = 1;
    for (int o = 0; o < N_OWNERS; o++)
        if (put_free(&st, make_val(o, &kh, 1, 1, "big", 100000)) != 0) ok = 0;
    nodus_value_t **vals = NULL;
    size_t cnt = 0;
    int more = -1;
    int rc = nodus_storage_get_all_page(&st, &kh, NULL, NULL, 0, 1000,
                                        &vals, &cnt, &more);
    if (ok && rc == 0 && cnt == 1 && more == 1 && vals[0]->data_len == 100000)
        PASS();
    else
        FAIL("oversized first row must come back alone with more=1");
    free_vals(vals, cnt);
    /* budget 0 behaves the same */
    vals = NULL; cnt = 0; more = -1;
    rc = nodus_storage_get_all_page(&st, &kh, NULL, NULL, 0, 0, &vals, &cnt, &more);
    TEST("budget 0: first row alone, more = 1");
    if (rc == 0 && cnt == 1 && more == 1) PASS(); else FAIL("budget 0");
    free_vals(vals, cnt);
    test_storage_close(&st);
}

static void test_owner_filter(void) {
    TEST("owner filter: only that owner's rows, vid order; + cursor");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = populate(&st) == 0;
    const nodus_key_t *fb = &fps[1];
    pk_t mine[N_VIDS];
    int m = 0;
    for (int i = 0; i < N_ROWS; i++)
        if (memcmp(expected[i].fp.bytes, fb->bytes, NODUS_KEY_BYTES) == 0)
            mine[m++] = expected[i];
    nodus_value_t **vals = NULL;
    size_t cnt = 0;
    int more = -1;
    int rc = nodus_storage_get_all_page(&st, &g_key, fb, NULL, 0,
                                        NODUS_GET_ALL_PAGE_MAX_BYTES,
                                        &vals, &cnt, &more);
    ok = ok && m == N_VIDS && rc == 0 && cnt == N_VIDS && more == 0;
    for (size_t i = 0; ok && i < cnt; i++)
        if (!same_pk(vals[i], &mine[i])) ok = 0;
    free_vals(vals, cnt);

    /* filter + cursor at the owner's first row, 1-row budget */
    vals = NULL; cnt = 0; more = -1;
    rc = nodus_storage_get_all_page(&st, &g_key, fb, &mine[0].fp, mine[0].vid,
                                    NODUS_VALUE_SERIALIZED_EST(DATA_LEN),
                                    &vals, &cnt, &more);
    ok = ok && rc == 0 && cnt == 1 && more == 1 && same_pk(vals[0], &mine[1]);
    free_vals(vals, cnt);

    /* filter + cursor at the owner's last row: nothing of another owner leaks */
    vals = NULL; cnt = 0; more = -1;
    rc = nodus_storage_get_all_page(&st, &g_key, fb, &mine[N_VIDS - 1].fp,
                                    mine[N_VIDS - 1].vid,
                                    NODUS_GET_ALL_PAGE_MAX_BYTES,
                                    &vals, &cnt, &more);
    ok = ok && rc == 0 && cnt == 0 && more == 0;
    free_vals(vals, cnt);

    if (ok) PASS(); else FAIL("owner filter with/without cursor");
    test_storage_close(&st);
}

static void test_get_all_unchanged(void) {
    TEST("get_all still returns every row");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = populate(&st) == 0;
    nodus_value_t **vals = NULL;
    size_t cnt = 0;
    int rc = nodus_storage_get_all(&st, &g_key, &vals, &cnt);
    if (ok && rc == 0 && cnt == N_ROWS) PASS(); else FAIL("get_all count");
    if (rc == 0) free_vals(vals, cnt);
    test_storage_close(&st);
}

static void test_get_owner_newest(void) {
    TEST("get_owner: highest seq, then highest data hash; -1 if none");
    nodus_storage_t st;
    test_storage_open(&st);
    nodus_key_t kh;
    nodus_hash((const uint8_t *)"owner-newest", 12, &kh);
    int ok = put_free(&st, make_val(0, &kh, 1, 5, "old", DATA_LEN)) == 0 &&
             put_free(&st, make_val(0, &kh, 2, 9, "nine-a", DATA_LEN)) == 0 &&
             put_free(&st, make_val(0, &kh, 3, 9, "nine-b", DATA_LEN)) == 0 &&
             put_free(&st, make_val(1, &kh, 1, 50, "other", DATA_LEN)) == 0;

    /* expected among the two seq-9 rows: higher SHA3-256(data) */
    uint8_t da[DATA_LEN] = {0}, db[DATA_LEN] = {0}, ha[32], hb[32];
    snprintf((char *)da, DATA_LEN, "%s", "nine-a");
    snprintf((char *)db, DATA_LEN, "%s", "nine-b");
    qgp_sha3_256(da, DATA_LEN, ha);
    qgp_sha3_256(db, DATA_LEN, hb);
    uint64_t want_vid = (memcmp(ha, hb, 32) > 0) ? 2 : 3;

    nodus_value_t *got = NULL;
    int rc = nodus_storage_get_owner(&st, &kh, &fps[0], &got);
    ok = ok && rc == 0 && got && got->seq == 9 && got->value_id == want_vid &&
         memcmp(got->owner_fp.bytes, fps[0].bytes, NODUS_KEY_BYTES) == 0;
    if (got) nodus_value_free(got);

    got = NULL;
    rc = nodus_storage_get_owner(&st, &kh, &fps[2], &got);
    ok = ok && rc == -1 && got == NULL;

    if (ok) PASS(); else FAIL("newest-row selection");
    test_storage_close(&st);
}

/* Replace a prepared statement with one that fails at sqlite3_step
 * (abs(INT64_MIN) raises "integer overflow" at run time — checked with the
 * sqlite3 3.44 CLI; the build links the system libsqlite3, 3.40.1 here, the behaviour
 * has been the same for many releases). It binds ?1..?4 like the originals.
 * nodus_storage_close finalizes the replacement. */
static int break_stmt(nodus_storage_t *st, sqlite3_stmt **slot) {
    sqlite3_finalize(*slot);
    *slot = NULL;
    return sqlite3_prepare_v2(st->db,
        "SELECT abs(-9223372036854775807 - 1), ?1, ?2, ?3, ?4",
        -1, slot, NULL) == SQLITE_OK ? 0 : -1;
}

static void test_read_fault_code(void) {
    TEST("read fault -> -5 (get_owner, get_all_page, get); miss -> -1");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = populate(&st) == 0;

    /* misses before breaking anything */
    nodus_key_t none;
    nodus_hash((const uint8_t *)"fault-none", 10, &none);
    nodus_value_t *got = NULL;
    ok = ok && nodus_storage_get(&st, &none, &got) == -1 && got == NULL;
    ok = ok && nodus_storage_get_owner(&st, &none, &fps[0], &got) == -1 && got == NULL;

    ok = ok && break_stmt(&st, &st.stmt_get_owner) == 0 &&
         break_stmt(&st, &st.stmt_get_all_page) == 0 &&
         break_stmt(&st, &st.stmt_get) == 0;

    got = (nodus_value_t *)1;   /* must be cleared */
    int rc1 = nodus_storage_get_owner(&st, &g_key, &fps[0], &got);
    ok = ok && rc1 == NODUS_STORAGE_RC_FAULT && got == NULL;

    nodus_value_t **vals = NULL;
    size_t cnt = 99;
    int more = -1;
    int rc2 = nodus_storage_get_all_page(&st, &g_key, NULL, NULL, 0,
                                         NODUS_GET_ALL_PAGE_MAX_BYTES,
                                         &vals, &cnt, &more);
    ok = ok && rc2 == NODUS_STORAGE_RC_FAULT && vals == NULL && cnt == 0 && more == 0;

    got = NULL;
    int rc3 = nodus_storage_get(&st, &g_key, &got);
    ok = ok && rc3 == NODUS_STORAGE_RC_FAULT && got == NULL;

    /* invalid arguments stay -1 */
    int rc4 = nodus_storage_get_all_page(&st, NULL, NULL, NULL, 0, 1, &vals, &cnt, &more);
    ok = ok && rc4 == -1;

    if (ok) PASS(); else FAIL("a read fault must be -5, never the miss code");
    test_storage_close(&st);
}

int main(void) {
    printf("=== Nodus get_owner / get_all_page ===\n");
    for (int o = 0; o < N_OWNERS; o++) {
        uint8_t seed[32];
        memset(seed, 0x71 + o, sizeof(seed));
        nodus_identity_from_seed(seed, &ids[o]);
        nodus_fingerprint(&ids[o].pk, &fps[o]);
    }
    nodus_hash((const uint8_t *)"page-key", 8, &g_key);

    test_walk_one_per_page();
    test_walk_two_per_page();
    test_walk_all_in_one();
    test_cursor_strictly_after();
    test_cursor_past_end();
    test_empty_key();
    test_oversized_first_row();
    test_owner_filter();
    test_get_all_unchanged();
    test_get_owner_newest();
    test_read_fault_code();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
