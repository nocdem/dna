/**
 * Nodus — DHT Package A S3: opt-in get_all paging at the originator.
 *
 * Drives the pure page helpers the forwarded get_all uses
 * (nodus_dht_merge_rows with a cursor, nodus_dht_page_note_source,
 * nodus_dht_page_finish — nodus_server.h internal section).
 *
 * Pins down:
 *   1. The page is in storage PK order with value_id as SIGNED int64:
 *      value_id 2^63 sorts BEFORE value_id 5 (uint64 order would invert).
 *   2. The byte budget is counted in NODUS_VALUE_SERIALIZED_EST units;
 *      when it cuts, more = true and next = last kept PK.
 *   3. A first row larger than the budget is returned alone.
 *   4. next = min(last included, min over sources with more=true of that
 *      source's last valid PK): rows past that bound are left for the
 *      next page.
 *   5. A peer that ignores "after" (old peer) cannot re-inject rows at or
 *      below the cursor.
 *   6. Two sources, two pages: every row exactly once, none lost.
 *   7. A source answering more=true with only invalid rows cannot pull
 *      the bound below honest rows (page never empty while rows exist);
 *      an empty page reports more = false.
 *
 * RED on the tree before Package A: the helpers do not exist and get_all
 * had no paging (one result_multi of up to 10000 rows).
 */

#include "server/nodus_server.h"
#include "core/nodus_storage.h"
#include "core/nodus_value.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t id_a;
static nodus_key_t key_x;

/* Unsigned value of id_a (these tests merge with verify_rows = false
 * unless stated). */
static nodus_value_t *mk(uint64_t vid, uint64_t seq, size_t data_len) {
    uint8_t *data = malloc(data_len ? data_len : 1);
    if (!data) return NULL;
    memset(data, (int)(vid & 0xFF), data_len ? data_len : 1);
    nodus_value_t *v = NULL;
    int rc = nodus_value_create(&key_x, data, data_len, NODUS_VALUE_PERMANENT, 0,
                                vid, seq, &id_a.pk, &v);
    free(data);
    return rc == 0 ? v : NULL;
}

static void free_rows(nodus_value_t **rows, size_t n) {
    for (size_t i = 0; i < n; i++) nodus_value_free(rows[i]);
}

static void free_set(nodus_value_t **set, size_t n) {
    if (!set) return;
    free_rows(set, n);
    free(set);
}

static void test_signed_order(void) {
    TEST("page order: value_id 2^63 before 5 (signed)");
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[3] = { mk(5, 1, 4), mk(0x8000000000000000ULL, 1, 4), mk(1, 1, 4) };
    nodus_dht_page_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    nodus_t2_page_info_t pg;
    CHECK(src[0] && src[1] && src[2], "values");
    CHECK(nodus_dht_merge_rows(&set, &n, src, 3, &key_x, NULL, NULL, false, NULL) == 0, "merge");
    nodus_dht_page_finish(set, &n, &acc, NODUS_GET_ALL_PAGE_MAX_BYTES, &pg);
    CHECK(n == 3, "count");
    CHECK(set[0]->value_id == 0x8000000000000000ULL && set[1]->value_id == 1 &&
          set[2]->value_id == 5, "not signed PK order");
    CHECK(!pg.more && !pg.has_next, "complete page has no next");
    PASS();
out:
    free_rows(src, 3);
    free_set(set, n);
}

static void test_budget_cut(void) {
    TEST("budget in SERIALIZED_EST units; cut sets more + next");
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[4] = { mk(1, 1, 100), mk(2, 1, 100), mk(3, 1, 100), mk(4, 1, 100) };
    nodus_dht_page_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    nodus_t2_page_info_t pg;
    size_t budget = 2 * NODUS_VALUE_SERIALIZED_EST(100) + 10;   /* room for 2 */
    CHECK(src[0] && src[1] && src[2] && src[3], "values");
    CHECK(nodus_dht_merge_rows(&set, &n, src, 4, &key_x, NULL, NULL, false, NULL) == 0, "merge");
    nodus_dht_page_finish(set, &n, &acc, budget, &pg);
    CHECK(n == 2 && set[0]->value_id == 1 && set[1]->value_id == 2, "page rows");
    CHECK(pg.more && pg.has_next && pg.next.vid == 2 &&
          nodus_key_cmp(&pg.next.owner, &id_a.node_id) == 0, "next");
    PASS();
out:
    free_rows(src, 4);
    free_set(set, n);
}

static void test_oversized_first_row(void) {
    TEST("first row larger than the budget is returned alone");
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[2] = { mk(1, 1, 50000), mk(2, 1, 10) };
    nodus_dht_page_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    nodus_t2_page_info_t pg;
    CHECK(src[0] && src[1], "values");
    CHECK(nodus_dht_merge_rows(&set, &n, src, 2, &key_x, NULL, NULL, false, NULL) == 0, "merge");
    nodus_dht_page_finish(set, &n, &acc, 1000, &pg);
    CHECK(n == 1 && set[0]->value_id == 1, "first row not alone");
    CHECK(pg.more && pg.next.vid == 1, "more/next");
    PASS();
out:
    free_rows(src, 2);
    free_set(set, n);
}

static void test_bound_from_source(void) {
    TEST("next = min(last included, more-source's last PK)");
    nodus_value_t **set = NULL;
    size_t n = 0;
    /* source A: rows 1..3, more = true (it holds more after 3) */
    nodus_value_t *a[3] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8) };
    /* source B: rows 2..6, complete */
    nodus_value_t *b[5] = { mk(2, 1, 8), mk(3, 1, 8), mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    nodus_dht_page_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    nodus_dht_merge_stats_t st;
    nodus_t2_page_info_t pg;
    for (int i = 0; i < 3; i++) CHECK(a[i], "a values");
    for (int i = 0; i < 5; i++) CHECK(b[i], "b values");

    CHECK(nodus_dht_merge_rows(&set, &n, a, 3, &key_x, NULL, NULL, false, &st) == 0, "mA");
    nodus_dht_page_note_source(&acc, true, &st);
    CHECK(nodus_dht_merge_rows(&set, &n, b, 5, &key_x, NULL, NULL, false, &st) == 0, "mB");
    nodus_dht_page_note_source(&acc, false, &st);
    nodus_dht_page_finish(set, &n, &acc, NODUS_GET_ALL_PAGE_MAX_BYTES, &pg);
    CHECK(n == 3 && set[2]->value_id == 3, "rows past A's last PK were included");
    CHECK(pg.more && pg.has_next && pg.next.vid == 3, "next must be A's last PK");
    PASS();
out:
    free_rows(a, 3);
    free_rows(b, 5);
    free_set(set, n);
}

static void test_two_pages_no_loss(void) {
    TEST("two sources, two pages: every row once, none lost");
    nodus_value_t **p1 = NULL, **p2 = NULL;
    size_t n1 = 0, n2 = 0;
    nodus_dht_page_acc_t acc1, acc2;
    memset(&acc1, 0, sizeof(acc1));
    memset(&acc2, 0, sizeof(acc2));
    nodus_dht_merge_stats_t st;
    nodus_t2_page_info_t pg1, pg2;
    /* page 1: A (new peer) returns 1..3 more=true, B (old peer) all 1..6 */
    nodus_value_t *a1[3] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8) };
    nodus_value_t *b1[6] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8),
                             mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    /* page 2 (after = 3): A returns 4..7 complete, B ignores "after" */
    nodus_value_t *a2[4] = { mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8), mk(7, 1, 8) };
    nodus_value_t *b2[6] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8),
                             mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    nodus_t2_cursor_t after;

    CHECK(nodus_dht_merge_rows(&p1, &n1, a1, 3, &key_x, NULL, NULL, false, &st) == 0, "1A");
    nodus_dht_page_note_source(&acc1, true, &st);
    CHECK(nodus_dht_merge_rows(&p1, &n1, b1, 6, &key_x, NULL, NULL, false, &st) == 0, "1B");
    nodus_dht_page_note_source(&acc1, false, &st);
    nodus_dht_page_finish(p1, &n1, &acc1, NODUS_GET_ALL_PAGE_MAX_BYTES, &pg1);
    CHECK(n1 == 3 && pg1.more && pg1.has_next, "page 1");

    after = pg1.next;
    CHECK(nodus_dht_merge_rows(&p2, &n2, a2, 4, &key_x, NULL, &after, false, &st) == 0, "2A");
    nodus_dht_page_note_source(&acc2, false, &st);
    CHECK(nodus_dht_merge_rows(&p2, &n2, b2, 6, &key_x, NULL, &after, false, &st) == 0, "2B");
    CHECK(st.below_cursor == 3, "old peer's rows <= cursor not dropped");
    nodus_dht_page_note_source(&acc2, false, &st);
    nodus_dht_page_finish(p2, &n2, &acc2, NODUS_GET_ALL_PAGE_MAX_BYTES, &pg2);
    CHECK(!pg2.more && !pg2.has_next, "page 2 must be the last");
    CHECK(n2 == 4, "page 2 rows");
    /* union is exactly 1..7, each once */
    {
        int seen[8] = {0};
        for (size_t i = 0; i < n1; i++) seen[p1[i]->value_id]++;
        for (size_t i = 0; i < n2; i++) seen[p2[i]->value_id]++;
        for (int v = 1; v <= 7; v++) CHECK(seen[v] == 1, "row lost or duplicated");
    }
    PASS();
out:
    free_rows(a1, 3); free_rows(b1, 6); free_rows(a2, 4); free_rows(b2, 6);
    free_set(p1, n1);
    free_set(p2, n2);
}

static void test_bad_source_cannot_stall(void) {
    TEST("more=true with only invalid rows cannot empty the page");
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_dht_page_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    nodus_dht_merge_stats_t st;
    nodus_t2_page_info_t pg;
    /* honest (signed) rows 10..12, complete */
    nodus_value_t *honest[3] = { mk(10, 1, 8), mk(11, 1, 8), mk(12, 1, 8) };
    /* bad source: one unsigned row at vid 2 (below every honest row), more=true */
    nodus_value_t *bad[1] = { mk(2, 1, 8) };
    for (int i = 0; i < 3; i++) {
        CHECK(honest[i], "honest");
        CHECK(nodus_value_sign(honest[i], &id_a.sk) == 0, "sign");
    }
    CHECK(bad[0], "bad");

    CHECK(nodus_dht_merge_rows(&set, &n, bad, 1, &key_x, NULL, NULL, true, &st) == 0, "mBad");
    CHECK(st.bad == 1 && !st.has_last, "invalid row counted as valid");
    nodus_dht_page_note_source(&acc, true, &st);
    CHECK(!acc.has_bound, "bound set from an invalid row");
    CHECK(nodus_dht_merge_rows(&set, &n, honest, 3, &key_x, NULL, NULL, true, &st) == 0, "mH");
    nodus_dht_page_note_source(&acc, false, &st);
    nodus_dht_page_finish(set, &n, &acc, NODUS_GET_ALL_PAGE_MAX_BYTES, &pg);
    CHECK(n == 3, "honest rows not on the page");
    free_set(set, n);
    set = NULL;
    n = 0;

    /* nothing valid at all, a source still claims more → empty, more = false */
    memset(&acc, 0, sizeof(acc));
    acc.any_more = true;
    nodus_dht_page_finish(set, &n, &acc, NODUS_GET_ALL_PAGE_MAX_BYTES, &pg);
    CHECK(n == 0 && !pg.more && !pg.has_next, "empty page claims more");
    PASS();
out:
    free_rows(honest, 3);
    free_rows(bad, 1);
    free_set(set, n);
}

int main(void) {
    printf("=== DHT Package A S3: get_all paging (originator) ===\n");
    uint8_t seed[32];
    memset(seed, 0x61, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_a) != 0) { printf("FATAL: identity\n"); return 1; }
    nodus_hash((const uint8_t *)"pkg-a:paging", 12, &key_x);

    test_signed_order();
    test_budget_cut();
    test_oversized_first_row();
    test_bound_from_source();
    test_two_pages_no_loss();
    test_bad_source_cannot_stall();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
