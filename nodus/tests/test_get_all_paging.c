/**
 * Nodus — DHT Package A S3: opt-in get_all paging at the originator.
 *
 * Drives the pure keyset helpers the forwarded get_all uses
 * (nodus_dht_keyset_add with a cursor, nodus_dht_keyset_note_page,
 * nodus_dht_keyset_resolve — nodus_server.h internal section).
 *
 * Pins down:
 *   1. The page is in storage PK order with value_id as SIGNED int64:
 *      value_id 2^63 sorts BEFORE value_id 5 (uint64 order would invert).
 *   2. The byte budget is counted in NODUS_VALUE_SERIALIZED_EST units;
 *      when it cuts, more = true and next = last kept PK.
 *   3. A first row larger than the budget is returned alone.
 *   4. A more=true source whose rows FILLED its page bounds ours: rows
 *      past its last PK are left for the next page, next = that PK.
 *   5. Rev 2 item 12: a more=true source that sent ONE small row (its
 *      page not filled) does not hold the page to that row; more stays
 *      true (a source said so), next = the last row kept.
 *   6. A peer that ignores "after" (old peer) cannot re-inject rows at or
 *      below the cursor.
 *   7. Two sources, two pages: every row exactly once, none lost.
 *   8. A filled more=true source whose bounding PK has no VALID row
 *      (forged rows: signed then altered, so R-c lets them in) loses its
 *      bound — the page is never pulled below the honest rows; an empty
 *      page reports more = false.
 *   9. The verify budget running out closes the page there: more = true,
 *      next = the last row kept (the rest comes on the next page).
 *  10. The local store is a trusted source: its more=true always bounds.
 *  11. Rev 3 R-d: a source that sends "nx" (the size of the row it stopped
 *      on) bounds the page when est_bytes + nx > its budget — an honest
 *      source stopping before a LARGE row holds the page there, and over
 *      three pages every row is returned exactly once.
 *  12. Rev 3 R-e: a source over its row cap keeps its smallest PKs, and the
 *      cut source says more and bounds.
 *  13. Rev 3 R-a (paged): with the budget spent the page closes before the
 *      first undecided PK, even with a local row above it (deferred to the
 *      next page, never skipped).
 *
 * Requires: default build. Leaves behind: nothing (in-process).
 * RED on the tree before rev 2: any more=true source bounded the page
 * (a 1-row answer held the page to 1 row) and the bound was taken from
 * rows that had not been verified. RED before rev 3: no "nx" rule (11
 * loses row 3), no per-source cap (12 runs the page to 6).
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

/* Value of id_a with data_len bytes; signed unless sign == false. */
static nodus_value_t *mk_s(uint64_t vid, uint64_t seq, size_t data_len, bool sign) {
    uint8_t *data = malloc(data_len ? data_len : 1);
    if (!data) return NULL;
    memset(data, (int)(vid & 0xFF), data_len ? data_len : 1);
    nodus_value_t *v = NULL;
    int rc = nodus_value_create(&key_x, data, data_len, NODUS_VALUE_PERMANENT, 0,
                                vid, seq, &id_a.pk, &v);
    free(data);
    if (rc != 0) return NULL;
    if (sign && nodus_value_sign(v, &id_a.sk) != 0) { nodus_value_free(v); return NULL; }
    return v;
}

static nodus_value_t *mk(uint64_t vid, uint64_t seq, size_t data_len) {
    return mk_s(vid, seq, data_len, true);
}

static void free_rows(nodus_value_t **rows, size_t n) {
    for (size_t i = 0; i < n; i++) nodus_value_free(rows[i]);
}

static void free_set(nodus_value_t **set, size_t n) {
    if (!set) return;
    free_rows(set, n);
    free(set);
}

/* One forwarded (untrusted) source: add + page note; nx = the "nx" the
 * responder sent (NULL = absent, a peer that predates it). */
static int source_nx(nodus_dht_keyset_t *ks, nodus_value_t **rows, size_t n,
                     const nodus_t2_cursor_t *after, bool more, size_t responder_budget,
                     const uint64_t *nx, nodus_dht_merge_stats_t *st) {
    /* The page note needs THIS source's stats (last PK, est_bytes): keep
     * them even when the caller does not ask for them. */
    nodus_dht_merge_stats_t local_st;
    if (!st) st = &local_st;
    if (nodus_dht_keyset_add(ks, rows, n, &key_x, NULL, after, false, st) != 0) return -1;
    nodus_dht_keyset_note_page(ks, more, false, responder_budget, nx, st);
    return 0;
}

static int source(nodus_dht_keyset_t *ks, nodus_value_t **rows, size_t n,
                  const nodus_t2_cursor_t *after, bool more, size_t responder_budget,
                  nodus_dht_merge_stats_t *st) {
    return source_nx(ks, rows, n, after, more, responder_budget, NULL, st);
}

/* Signed, then the data altered: carries an owner key and a signature
 * (passes R-c) but fails nodus_value_verify. */
static nodus_value_t *mk_forged(uint64_t vid, uint64_t seq, size_t data_len) {
    nodus_value_t *v = mk(vid, seq, data_len ? data_len : 1);
    if (v && v->data && v->data_len > 0) v->data[0] ^= 0x01;
    return v;
}

static int page(nodus_dht_keyset_t *ks, size_t budget, nodus_value_t ***set, size_t *n,
                nodus_t2_page_info_t *pg, bool *capped, int *left) {
    int l = NODUS_DHT_VERIFY_CAP;
    if (!left) left = &l;
    return nodus_dht_keyset_resolve(ks, true, budget, left, set, n, pg, capped);
}

static void test_signed_order(void) {
    TEST("page order: value_id 2^63 before 5 (signed)");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[3] = { mk(5, 1, 4), mk(0x8000000000000000ULL, 1, 4), mk(1, 1, 4) };
    nodus_t2_page_info_t pg;
    CHECK(src[0] && src[1] && src[2], "values");
    CHECK(source(&ks, src, 3, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "add");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, NULL, NULL) == 0, "resolve");
    CHECK(n == 3, "count");
    CHECK(set[0]->value_id == 0x8000000000000000ULL && set[1]->value_id == 1 &&
          set[2]->value_id == 5, "not signed PK order");
    CHECK(!pg.more && !pg.has_next, "complete page has no next");
    PASS();
out:
    free_rows(src, 3);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_budget_cut(void) {
    TEST("budget in SERIALIZED_EST units; cut sets more + next");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[4] = { mk(1, 1, 100), mk(2, 1, 100), mk(3, 1, 100), mk(4, 1, 100) };
    nodus_t2_page_info_t pg;
    size_t budget = 2 * NODUS_VALUE_SERIALIZED_EST(100) + 10;   /* room for 2 */
    CHECK(src[0] && src[1] && src[2] && src[3], "values");
    CHECK(source(&ks, src, 4, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "add");
    CHECK(page(&ks, budget, &set, &n, &pg, NULL, NULL) == 0, "resolve");
    CHECK(n == 2 && set[0]->value_id == 1 && set[1]->value_id == 2, "page rows");
    CHECK(pg.more && pg.has_next && pg.next.vid == 2 &&
          nodus_key_cmp(&pg.next.owner, &id_a.node_id) == 0, "next");
    PASS();
out:
    free_rows(src, 4);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_oversized_first_row(void) {
    TEST("first row larger than the budget is returned alone");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[2] = { mk(1, 1, 50000), mk(2, 1, 10) };
    nodus_t2_page_info_t pg;
    CHECK(src[0] && src[1], "values");
    CHECK(source(&ks, src, 2, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "add");
    CHECK(page(&ks, 1000, &set, &n, &pg, NULL, NULL) == 0, "resolve");
    CHECK(n == 1 && set[0]->value_id == 1, "first row not alone");
    CHECK(pg.more && pg.next.vid == 1, "more/next");
    PASS();
out:
    free_rows(src, 2);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_bound_from_filled_source(void) {
    TEST("filled more=true source bounds: next = its last PK");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    /* source A: rows 1..3, more = true, and they filled A's page */
    nodus_value_t *a[3] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8) };
    /* source B: rows 2..6, complete */
    nodus_value_t *b[5] = { mk(2, 1, 8), mk(3, 1, 8), mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    size_t a_budget = 3 * NODUS_VALUE_SERIALIZED_EST(8);   /* exactly A's rows */
    nodus_t2_page_info_t pg;
    for (int i = 0; i < 3; i++) CHECK(a[i], "a values");
    for (int i = 0; i < 5; i++) CHECK(b[i], "b values");

    CHECK(source(&ks, a, 3, NULL, true, a_budget, NULL) == 0, "A");
    CHECK(ks.src[0].bounds, "a filled page must bound");
    CHECK(source(&ks, b, 5, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "B");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, NULL, NULL) == 0, "resolve");
    CHECK(n == 3 && set[2]->value_id == 3, "rows past A's last PK were included");
    CHECK(pg.more && pg.has_next && pg.next.vid == 3, "next must be A's last PK");
    PASS();
out:
    free_rows(a, 3);
    free_rows(b, 5);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_one_row_source_does_not_bound(void) {
    TEST("item 12: 1-row more=true source does not hold the page");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *a[1] = { mk(1, 1, 8) };                        /* 1 row, more */
    nodus_value_t *b[6] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8),
                            mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    nodus_t2_page_info_t pg;
    CHECK(a[0], "a");
    for (int i = 0; i < 6; i++) CHECK(b[i], "b values");
    CHECK(source(&ks, a, 1, NULL, true, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "A");
    CHECK(!ks.src[0].bounds, "an unfilled page must not bound");
    CHECK(source(&ks, b, 6, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "B");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, NULL, NULL) == 0, "resolve");
    CHECK(n == 6, "page held to the 1-row source");
    CHECK(pg.more && pg.has_next && pg.next.vid == 6, "more / next");
    PASS();
out:
    free_rows(a, 1);
    free_rows(b, 6);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_two_pages_no_loss(void) {
    TEST("two sources, two pages: every row once, none lost");
    nodus_dht_keyset_t k1, k2;
    memset(&k1, 0, sizeof(k1));
    memset(&k2, 0, sizeof(k2));
    nodus_value_t **p1 = NULL, **p2 = NULL;
    size_t n1 = 0, n2 = 0;
    nodus_dht_merge_stats_t st;
    nodus_t2_page_info_t pg1, pg2;
    size_t a_budget = 3 * NODUS_VALUE_SERIALIZED_EST(8);
    /* page 1: A (new peer) returns 1..3 more=true (filled), B (old peer) all 1..6 */
    nodus_value_t *a1[3] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8) };
    nodus_value_t *b1[6] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8),
                             mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    /* page 2 (after = 3): A returns 4..7 complete, B ignores "after" */
    nodus_value_t *a2[4] = { mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8), mk(7, 1, 8) };
    nodus_value_t *b2[6] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8),
                             mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    nodus_t2_cursor_t after;

    CHECK(source(&k1, a1, 3, NULL, true, a_budget, NULL) == 0, "1A");
    CHECK(source(&k1, b1, 6, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "1B");
    CHECK(page(&k1, NODUS_GET_ALL_PAGE_MAX_BYTES, &p1, &n1, &pg1, NULL, NULL) == 0, "p1");
    CHECK(n1 == 3 && pg1.more && pg1.has_next, "page 1");

    after = pg1.next;
    CHECK(source(&k2, a2, 4, &after, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "2A");
    CHECK(source(&k2, b2, 6, &after, false, NODUS_GET_ALL_PAGE_MAX_BYTES, &st) == 0, "2B");
    CHECK(st.below_cursor == 3, "old peer's rows <= cursor not dropped");
    CHECK(page(&k2, NODUS_GET_ALL_PAGE_MAX_BYTES, &p2, &n2, &pg2, NULL, NULL) == 0, "p2");
    CHECK(!pg2.more && !pg2.has_next, "page 2 must be the last");
    CHECK(n2 == 4, "page 2 rows");
    {
        int seen[8] = {0};
        for (size_t i = 0; i < n1; i++) seen[p1[i]->value_id]++;
        for (size_t i = 0; i < n2; i++) seen[p2[i]->value_id]++;
        for (int v = 1; v <= 7; v++) CHECK(seen[v] == 1, "row lost or duplicated");
    }
    PASS();
out:
    free_rows(a1, 3); free_rows(b1, 6); free_rows(a2, 4); free_rows(b2, 6);
    nodus_dht_keyset_clear(&k1); nodus_dht_keyset_clear(&k2);
    free_set(p1, n1);
    free_set(p2, n2);
}

static void test_bad_source_cannot_stall(void) {
    TEST("filled more=true source of forged rows loses its bound");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_t2_page_info_t pg;
    /* honest (signed) rows 10..12, complete */
    nodus_value_t *honest[3] = { mk(10, 1, 8), mk(11, 1, 8), mk(12, 1, 8) };
    /* bad source: two forged rows at vid 2, 3 (below every honest row),
     * more=true and "filled" (responder budget = exactly its rows). Rev 3:
     * signed-then-altered, so they pass R-c (an unsigned row would be
     * refused at add and never claim a bound). */
    nodus_value_t *bad[2] = { mk_forged(2, 1, 8), mk_forged(3, 1, 8) };
    size_t bad_budget = 2 * NODUS_VALUE_SERIALIZED_EST(8);
    for (int i = 0; i < 3; i++) CHECK(honest[i], "honest");
    CHECK(bad[0] && bad[1], "bad");

    CHECK(source(&ks, bad, 2, NULL, true, bad_budget, NULL) == 0, "bad source");
    CHECK(ks.src[0].bounds, "precondition: the bad source claims a bound");
    CHECK(source(&ks, honest, 3, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "honest");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, NULL, NULL) == 0, "resolve");
    CHECK(n == 3 && set[0]->value_id == 10, "honest rows not on the page");
    free_set(set, n);
    set = NULL;
    n = 0;

    /* nothing valid at all, a source still claims more → empty, more = false */
    nodus_value_t *only_bad[1] = { mk_forged(4, 1, 8) };
    CHECK(only_bad[0], "only_bad");
    CHECK(source(&ks, only_bad, 1, NULL, true, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "ob");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, NULL, NULL) == 0, "resolve2");
    nodus_value_free(only_bad[0]);
    CHECK(n == 0 && !pg.more && !pg.has_next, "empty page claims more");
    PASS();
out:
    free_rows(honest, 3);
    free_rows(bad, 2);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_verify_budget_closes_page(void) {
    TEST("verify budget spent: page closes, more + next = last kept");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_t2_page_info_t pg;
    bool capped = false;
    int left = 2;
    nodus_value_t *src[4] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8), mk(4, 1, 8) };
    for (int i = 0; i < 4; i++) CHECK(src[i], "values");
    CHECK(source(&ks, src, 4, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "add");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, &capped, &left) == 0,
          "resolve");
    CHECK(capped && n == 2, "two rows before the budget ran out");
    CHECK(pg.more && pg.has_next && pg.next.vid == 2, "page must continue after row 2");
    PASS();
out:
    free_rows(src, 4);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_local_trusted_bounds(void) {
    TEST("local store (trusted) more=true always bounds");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_t2_page_info_t pg;
    nodus_dht_merge_stats_t st;
    /* local: 1 row (its next row is large → page not "filled"), more */
    nodus_value_t *local[1] = { mk(1, 1, 8) };
    nodus_value_t *fwd[3] = { mk(1, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    CHECK(local[0] && fwd[0] && fwd[1] && fwd[2], "values");
    CHECK(nodus_dht_keyset_add(&ks, local, 1, &key_x, NULL, NULL, true, &st) == 0, "local");
    nodus_dht_keyset_note_page(&ks, true, true, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL, &st);
    CHECK(source(&ks, fwd, 3, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "fwd");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, NULL, NULL) == 0, "resolve");
    CHECK(n == 1 && set[0]->value_id == 1, "local bound ignored");
    CHECK(pg.more && pg.next.vid == 1, "next");
    PASS();
out:
    free_rows(local, 1);
    free_rows(fwd, 3);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

/* Rev 3 R-d. An honest source A stops BEFORE a large row (row 3) that does
 * not fit its responder budget; its two small rows are far from filling
 * the budget. Source B never had row 3. Page 1 must stop at A's last row
 * (2), or the cursor would pass row 3 and nobody would ever return it.
 * FAILS WITHOUT R-d: drop the nx rule from nodus_dht_keyset_note_page and A
 * no longer bounds (2*EST(8) + EST(0) <= its budget) — page 1 becomes
 * 1,2,4,5 with next = 5 and row 3 is seen 0 times. */
static void test_nx_large_next_row(void) {
    TEST("R-d: nx bounds the page; no row skipped across pages");
    nodus_dht_keyset_t k1, k2, k3;
    memset(&k1, 0, sizeof(k1));
    memset(&k2, 0, sizeof(k2));
    memset(&k3, 0, sizeof(k3));
    nodus_value_t **p1 = NULL, **p2 = NULL, **p3 = NULL;
    size_t n1 = 0, n2 = 0, n3 = 0;
    nodus_t2_page_info_t pg1, pg2, pg3;
    const size_t rb = 3 * NODUS_VALUE_SERIALIZED_EST(8) + 100;   /* A's budget */
    const uint64_t nx_big = NODUS_VALUE_SERIALIZED_EST(1000);    /* row 3 */
    const uint64_t nx_small = NODUS_VALUE_SERIALIZED_EST(8);     /* row 5 */
    nodus_value_t *a1[2] = { mk(1, 1, 8), mk(2, 1, 8) };
    nodus_value_t *b1[4] = { mk(1, 1, 8), mk(2, 1, 8), mk(4, 1, 8), mk(5, 1, 8) };
    nodus_value_t *a2[2] = { mk(3, 1, 1000), mk(4, 1, 8) };
    nodus_value_t *b2[2] = { mk(4, 1, 8), mk(5, 1, 8) };
    nodus_value_t *a3[1] = { mk(5, 1, 8) };
    nodus_value_t *b3[1] = { mk(5, 1, 8) };
    nodus_t2_cursor_t after;
    int seen[6] = {0};
    for (int i = 0; i < 2; i++) CHECK(a1[i] && a2[i] && b2[i], "values");
    for (int i = 0; i < 4; i++) CHECK(b1[i], "values");
    CHECK(a3[0] && b3[0], "values");
    /* Preconditions that make the case real: A's honest stop rule, and the
     * old rule not counting A as full. */
    CHECK(2 * NODUS_VALUE_SERIALIZED_EST(8) + nx_big > rb, "row 3 must not fit A's page");
    CHECK(2 * NODUS_VALUE_SERIALIZED_EST(8) + NODUS_VALUE_SERIALIZED_EST(0) <= rb,
          "without nx A must look unfilled");

    CHECK(source_nx(&k1, a1, 2, NULL, true, rb, &nx_big, NULL) == 0, "1A");
    CHECK(k1.src[0].bounds, "A with nx must bound");
    CHECK(source(&k1, b1, 4, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "1B");
    CHECK(page(&k1, NODUS_GET_ALL_PAGE_MAX_BYTES, &p1, &n1, &pg1, NULL, NULL) == 0, "p1");
    CHECK(n1 == 2 && pg1.more && pg1.has_next && pg1.next.vid == 2, "page 1 must stop at 2");

    after = pg1.next;
    CHECK(source_nx(&k2, a2, 2, &after, true, rb, &nx_small, NULL) == 0, "2A");
    CHECK(source(&k2, b2, 2, &after, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "2B");
    CHECK(page(&k2, NODUS_GET_ALL_PAGE_MAX_BYTES, &p2, &n2, &pg2, NULL, NULL) == 0, "p2");
    CHECK(pg2.more && pg2.has_next, "page 2 continues");

    after = pg2.next;
    CHECK(source(&k3, a3, 1, &after, false, rb, NULL) == 0, "3A");
    CHECK(source(&k3, b3, 1, &after, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "3B");
    CHECK(page(&k3, NODUS_GET_ALL_PAGE_MAX_BYTES, &p3, &n3, &pg3, NULL, NULL) == 0, "p3");
    CHECK(!pg3.more, "page 3 is the last");

    for (size_t i = 0; i < n1; i++) seen[p1[i]->value_id]++;
    for (size_t i = 0; i < n2; i++) seen[p2[i]->value_id]++;
    for (size_t i = 0; i < n3; i++) seen[p3[i]->value_id]++;
    for (int v = 1; v <= 5; v++) CHECK(seen[v] == 1, "row lost or duplicated across pages");
    PASS();
out:
    free_rows(a1, 2); free_rows(b1, 4); free_rows(a2, 2); free_rows(b2, 2);
    free_rows(a3, 1); free_rows(b3, 1);
    nodus_dht_keyset_clear(&k1); nodus_dht_keyset_clear(&k2); nodus_dht_keyset_clear(&k3);
    free_set(p1, n1); free_set(p2, n2); free_set(p3, n3);
}

/* Rev 3 R-e. A source sends more rows than its cap: the cap keeps its
 * SMALLEST PKs (whatever order they came in), and the cut source bounds
 * the page at its last kept PK even though it said more = false — so the
 * rows it was not allowed to give are not skipped by the cursor.
 * FAILS WITHOUT R-e: with no cap every row is taken (over_cap 0) and the
 * page runs to 6. */
static void test_source_row_cap(void) {
    TEST("R-e: per-source cap keeps the smallest PKs and bounds");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_t2_page_info_t pg;
    nodus_dht_merge_stats_t st;
    nodus_value_t *a[5] = { mk(5, 1, 8), mk(1, 1, 8), mk(4, 1, 8), mk(2, 1, 8), mk(3, 1, 8) };
    nodus_value_t *b[6] = { mk(1, 1, 8), mk(2, 1, 8), mk(3, 1, 8),
                            mk(4, 1, 8), mk(5, 1, 8), mk(6, 1, 8) };
    for (int i = 0; i < 5; i++) CHECK(a[i], "a values");
    for (int i = 0; i < 6; i++) CHECK(b[i], "b values");
    CHECK(nodus_dht_keyset_add_ex(&ks, a, 5, &key_x, NULL, NULL, false, 3, NULL, &st) == 0,
          "add A");
    CHECK(st.over_cap == 2 && st.truncated && st.added == 3, "cap not applied");
    CHECK(st.has_last && st.last.vid == 3, "the smallest PKs must be kept");
    CHECK(a[0] != NULL && a[2] != NULL, "rows past the cap must stay with the caller");
    nodus_dht_keyset_note_page(&ks, false, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL, &st);
    CHECK(ks.src[0].more && ks.src[0].bounds, "a cut source must say more and bound");
    CHECK(source(&ks, b, 6, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "B");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, NULL, NULL) == 0, "resolve");
    CHECK(n == 3 && set[2]->value_id == 3, "page must stop at the cut source's last PK");
    CHECK(pg.more && pg.has_next && pg.next.vid == 3, "more / next");
    PASS();
out:
    free_rows(a, 5);
    free_rows(b, 6);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

/* Rev 3 R-a, paged half. With the budget spent, a paged page must CLOSE
 * before the first PK nobody could check, even when a local (trusted) row
 * sits above it: the cursor must not pass vid 2. The local row is not
 * dropped — it is past next, so the next page returns it.
 * FAILS if the paged walk skipped undecided groups the way the unpaged one
 * does: the page would carry vid 10 with next = 10, and vid 2 would never
 * be returned. */
static void test_paged_undecided_closes_page(void) {
    TEST("R-a paged: page closes before an undecided PK");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_t2_page_info_t pg;
    nodus_dht_merge_stats_t st;
    bool capped = false;
    int left = 1;
    nodus_value_t *local[1] = { mk(10, 1, 8) };
    nodus_value_t *fwd[2] = { mk(1, 1, 8), mk(2, 1, 8) };
    CHECK(local[0] && fwd[0] && fwd[1], "values");
    CHECK(nodus_dht_keyset_add(&ks, local, 1, &key_x, NULL, NULL, true, &st) == 0, "local");
    nodus_dht_keyset_note_page(&ks, false, true, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL, &st);
    CHECK(source(&ks, fwd, 2, NULL, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL) == 0, "fwd");
    CHECK(page(&ks, NODUS_GET_ALL_PAGE_MAX_BYTES, &set, &n, &pg, &capped, &left) == 0,
          "resolve");
    CHECK(capped && n == 1 && set[0]->value_id == 1, "only vid 1 may be on the page");
    CHECK(pg.more && pg.has_next && pg.next.vid == 1, "next must stay before vid 2");
    PASS();
out:
    free_rows(local, 1);
    free_rows(fwd, 2);
    nodus_dht_keyset_clear(&ks);
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
    test_bound_from_filled_source();
    test_one_row_source_does_not_bound();
    test_two_pages_no_loss();
    test_bad_source_cannot_stall();
    test_verify_budget_closes_page();
    test_local_trusted_bounds();
    test_nx_large_next_row();
    test_source_row_cap();
    test_paged_undecided_closes_page();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
