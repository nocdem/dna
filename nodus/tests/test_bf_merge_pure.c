/**
 * Nodus — DHT Package A: forwarded-read merge (S1) + forwarded-value
 * verification (F6), driven in-process through the pure helpers the BF
 * forward path uses (nodus_server.h, internal section).
 *
 * Pins down:
 *   1. PK order compares value_id as SIGNED int64 (storage PK order).
 *   2. The replica predicate: higher seq wins; equal seq → higher
 *      SHA3-256(data) wins; identical → no replace.
 *   3. Dedup is by (owner_fp, value_id): two owners with the SAME
 *      value_id both survive (the old merge deduped on value_id alone
 *      and dropped one of them).
 *   4. The newer row is kept whatever order the sources answer in; the
 *      merged set is the same for both orders.
 *   5. F6: a forwarded row with a bad signature, or with a key_hash other
 *      than the asked key, is dropped; the rest are kept.
 *   6. A row that loses to a present row is never signature-verified
 *      (a forged older copy is counted dup, not bad).
 *   7. Owner filter drops other owners' rows (S2 re-applied at the merge).
 *   8. Single GET picks the newest VERIFIED row, not the first arrived, and
 *      not a forged newer one.
 *
 * RED on the tree before Package A: the helpers do not exist, and the old
 * merge (nodus_server.c BF_RECV_RESULT) deduped on value_id only, took
 * rows unverified and matched them to keys by position.
 */

#include "server/nodus_server.h"
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

static nodus_identity_t id_a, id_b;
static nodus_key_t key_x, key_y;

static nodus_value_t *mk(const nodus_identity_t *id, const nodus_key_t *key,
                         uint64_t vid, uint64_t seq, const char *data, bool sign) {
    nodus_value_t *v = NULL;
    if (nodus_value_create(key, (const uint8_t *)data, strlen(data),
                           NODUS_VALUE_PERMANENT, 0, vid, seq, &id->pk, &v) != 0)
        return NULL;
    if (sign && nodus_value_sign(v, &id->sk) != 0) { nodus_value_free(v); return NULL; }
    return v;
}

static void free_rows(nodus_value_t **rows, size_t n) {
    if (!rows) return;
    for (size_t i = 0; i < n; i++) nodus_value_free(rows[i]);
}

static void free_set(nodus_value_t **set, size_t n) {
    free_rows(set, n);
    free(set);
}

static nodus_value_t *find(nodus_value_t **set, size_t n, const nodus_key_t *owner,
                           uint64_t vid) {
    for (size_t i = 0; i < n; i++)
        if (nodus_key_cmp(&set[i]->owner_fp, owner) == 0 && set[i]->value_id == vid)
            return set[i];
    return NULL;
}

static void test_pk_signed_order(void) {
    TEST("PK order: value_id compared as signed int64");
    nodus_key_t o;
    memset(o.bytes, 0x10, NODUS_KEY_BYTES);
    CHECK(nodus_dht_pk_cmp(&o, 0x8000000000000000ULL, &o, 1) < 0, "2^63 must sort before 1");
    CHECK(nodus_dht_pk_cmp(&o, 0xFFFFFFFFFFFFFFFFULL, &o, 0) < 0, "-1 must sort before 0");
    CHECK(nodus_dht_pk_cmp(&o, 7, &o, 7) == 0, "equal");
    nodus_key_t o2;
    memset(o2.bytes, 0x11, NODUS_KEY_BYTES);
    CHECK(nodus_dht_pk_cmp(&o, 0x7FFFFFFFFFFFFFFFULL, &o2, 0x8000000000000000ULL) < 0,
          "owner first");
    PASS();
out:
    return;
}

static void test_value_newer(void) {
    TEST("replica predicate: seq, then SHA3-256(data)");
    nodus_value_t *s1 = mk(&id_a, &key_x, 1, 5, "aaa", false);
    nodus_value_t *s2 = mk(&id_a, &key_x, 1, 6, "aaa", false);
    nodus_value_t *h1 = mk(&id_a, &key_x, 1, 5, "bbb", false);
    nodus_value_t *neg = mk(&id_a, &key_x, 1, 0xFFFFFFFFFFFFFFFFULL, "zzz", false);
    CHECK(s1 && s2 && h1 && neg, "values");
    CHECK(nodus_dht_value_newer(s2, s1) == 1 && nodus_dht_value_newer(s1, s2) == 0, "seq");
    CHECK(nodus_dht_value_newer(s1, s1) == 0, "identical is not newer");
    /* equal seq: exactly one of the two directions wins */
    CHECK(nodus_dht_value_newer(s1, h1) + nodus_dht_value_newer(h1, s1) == 1, "hash tiebreak");
    /* seq is a SQLite INTEGER: 0xFF..FF is -1, older than 5 */
    CHECK(nodus_dht_value_newer(neg, s1) == 0 && nodus_dht_value_newer(s1, neg) == 1,
          "signed seq");
    PASS();
out:
    nodus_value_free(s1); nodus_value_free(s2); nodus_value_free(h1); nodus_value_free(neg);
}

static void test_same_vid_two_owners(void) {
    TEST("same value_id, two owners: both kept (dedup by PK)");
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src1[1] = { mk(&id_a, &key_x, 42, 1, "from-a", true) };
    nodus_value_t *src2[1] = { mk(&id_b, &key_x, 42, 1, "from-b", true) };
    nodus_dht_merge_stats_t st;
    CHECK(src1[0] && src2[0], "values");
    CHECK(nodus_dht_merge_rows(&set, &n, src1, 1, &key_x, NULL, NULL, true, &st) == 0, "m1");
    CHECK(nodus_dht_merge_rows(&set, &n, src2, 1, &key_x, NULL, NULL, true, &st) == 0, "m2");
    CHECK(n == 2, "one of the two owners was dropped");
    CHECK(find(set, n, &id_a.node_id, 42) && find(set, n, &id_b.node_id, 42), "owners");
    PASS();
out:
    free_rows(src1, 1); free_rows(src2, 1);
    free_set(set, n);
}

/* Build one merge in the given source order, return the set. */
static int merge_two(nodus_value_t **first, nodus_value_t **second,
                     nodus_value_t ***set, size_t *n) {
    if (nodus_dht_merge_rows(set, n, first, 2, &key_x, NULL, NULL, true, NULL) != 0) return -1;
    if (nodus_dht_merge_rows(set, n, second, 2, &key_x, NULL, NULL, true, NULL) != 0) return -1;
    return 0;
}

static void test_newer_wins_any_order(void) {
    TEST("newer row kept in either source order; same set");
    nodus_value_t **s_ab = NULL, **s_ba = NULL;
    size_t n_ab = 0, n_ba = 0;
    nodus_value_t *old_a[2] = { mk(&id_a, &key_x, 1, 10, "old", true),
                                mk(&id_b, &key_x, 2, 3, "b-only", true) };
    nodus_value_t *new_a[2] = { mk(&id_a, &key_x, 1, 11, "new", true),
                                mk(&id_a, &key_x, 9, 1, "a9", true) };
    nodus_value_t *old_b[2] = { mk(&id_a, &key_x, 1, 10, "old", true),
                                mk(&id_b, &key_x, 2, 3, "b-only", true) };
    nodus_value_t *new_b[2] = { mk(&id_a, &key_x, 1, 11, "new", true),
                                mk(&id_a, &key_x, 9, 1, "a9", true) };
    CHECK(old_a[0] && old_a[1] && new_a[0] && new_a[1] &&
          old_b[0] && old_b[1] && new_b[0] && new_b[1], "values");

    CHECK(merge_two(old_a, new_a, &s_ab, &n_ab) == 0, "merge old→new");
    CHECK(merge_two(new_b, old_b, &s_ba, &n_ba) == 0, "merge new→old");
    CHECK(n_ab == 3 && n_ba == 3, "row count");
    nodus_value_t *r1 = find(s_ab, n_ab, &id_a.node_id, 1);
    nodus_value_t *r2 = find(s_ba, n_ba, &id_a.node_id, 1);
    CHECK(r1 && r1->seq == 11 && r2 && r2->seq == 11, "newer row not kept");
    for (size_t i = 0; i < n_ab; i++) {
        nodus_value_t *o = find(s_ba, n_ba, &s_ab[i]->owner_fp, s_ab[i]->value_id);
        CHECK(o && o->seq == s_ab[i]->seq && o->data_len == s_ab[i]->data_len &&
              memcmp(o->data, s_ab[i]->data, o->data_len) == 0, "sets differ");
    }
    PASS();
out:
    free_rows(old_a, 2); free_rows(new_a, 2); free_rows(old_b, 2); free_rows(new_b, 2);
    free_set(s_ab, n_ab); free_set(s_ba, n_ba);
}

static void test_bad_rows_dropped(void) {
    TEST("F6: bad signature / wrong key dropped, rest kept");
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[4] = {
        mk(&id_a, &key_x, 1, 1, "good", true),
        mk(&id_a, &key_x, 2, 1, "forged", true),
        mk(&id_a, &key_y, 3, 1, "other-key", true),   /* valid sig, wrong key */
        mk(&id_b, &key_x, 4, 1, "good-b", true),
    };
    nodus_dht_merge_stats_t st;
    CHECK(src[0] && src[1] && src[2] && src[3], "values");
    src[1]->data[0] ^= 0x01;   /* signature no longer covers the data */
    CHECK(nodus_dht_merge_rows(&set, &n, src, 4, &key_x, NULL, NULL, true, &st) == 0, "merge");
    CHECK(n == 2, "wrong row count");
    CHECK(find(set, n, &id_a.node_id, 1) && find(set, n, &id_b.node_id, 4), "good rows");
    CHECK(!find(set, n, &id_a.node_id, 2), "forged row kept");
    CHECK(!find(set, n, &id_a.node_id, 3), "other key row kept");
    CHECK(st.bad == 2 && st.kept == 2, "stats");
    PASS();
out:
    free_rows(src, 4);
    free_set(set, n);
}

static void test_loser_not_verified(void) {
    TEST("a row losing to a present row is not verified");
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *s1[1] = { mk(&id_a, &key_x, 1, 9, "valid-newer", true) };
    nodus_value_t *s2[1] = { mk(&id_a, &key_x, 1, 3, "forged-older", false) };
    nodus_dht_merge_stats_t st;
    CHECK(s1[0] && s2[0], "values");
    CHECK(nodus_dht_merge_rows(&set, &n, s1, 1, &key_x, NULL, NULL, true, &st) == 0, "m1");
    CHECK(nodus_dht_merge_rows(&set, &n, s2, 1, &key_x, NULL, NULL, true, &st) == 0, "m2");
    CHECK(st.dup == 1 && st.bad == 0 && st.kept == 0, "older row was verified or kept");
    CHECK(n == 1 && set[0]->seq == 9, "set");
    /* its PK is present → it still counts toward the source's last_valid */
    CHECK(st.has_last && st.last_valid.vid == 1, "last_valid");
    PASS();
out:
    free_rows(s1, 1); free_rows(s2, 1);
    free_set(set, n);
}

static void test_owner_filter(void) {
    TEST("owner filter re-applied at the merge");
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[3] = { mk(&id_a, &key_x, 1, 1, "a1", true),
                              mk(&id_b, &key_x, 2, 1, "b2", true),
                              mk(&id_a, &key_x, 3, 1, "a3", true) };
    nodus_dht_merge_stats_t st;
    CHECK(src[0] && src[1] && src[2], "values");
    CHECK(nodus_dht_merge_rows(&set, &n, src, 3, &key_x, &id_a.node_id, NULL, true, &st) == 0,
          "merge");
    CHECK(n == 2 && !find(set, n, &id_b.node_id, 2), "foreign owner kept");
    PASS();
out:
    free_rows(src, 3);
    free_set(set, n);
}

static void test_single_get_newest_verified(void) {
    TEST("single GET: newest verified row, not first arrived");
    nodus_value_t *best = NULL;
    nodus_value_t *first[1]  = { mk(&id_a, &key_x, 1, 4, "first-old", true) };
    nodus_value_t *forged[1] = { mk(&id_b, &key_x, 2, 99, "forged-newest", true) };
    nodus_value_t *later[1]  = { mk(&id_b, &key_x, 3, 7, "later-newer", true) };
    nodus_dht_merge_stats_t st;
    CHECK(first[0] && forged[0] && later[0], "values");
    forged[0]->data[0] ^= 0x01;

    nodus_dht_pick_best(&best, first, 1, &key_x, NULL, true, &st);
    CHECK(best && best->seq == 4, "first");
    nodus_dht_pick_best(&best, forged, 1, &key_x, NULL, true, &st);
    CHECK(best && best->seq == 4 && st.bad == 1, "forged row picked");
    nodus_dht_pick_best(&best, later, 1, &key_x, NULL, true, &st);
    CHECK(best && best->seq == 7, "newer row not picked");

    /* owner filter: only id_a's rows count */
    nodus_value_t *own_best = NULL;
    nodus_value_t *mix[2] = { mk(&id_b, &key_x, 5, 50, "b", true),
                              mk(&id_a, &key_x, 6, 2, "a", true) };
    CHECK(mix[0] && mix[1], "mix values");
    nodus_dht_pick_best(&own_best, mix, 2, &key_x, &id_a.node_id, true, &st);
    CHECK(own_best && nodus_key_cmp(&own_best->owner_fp, &id_a.node_id) == 0, "owner pick");
    nodus_value_free(own_best);
    free_rows(mix, 2);
    PASS();
out:
    nodus_value_free(best);
    free_rows(first, 1); free_rows(forged, 1); free_rows(later, 1);
}

int main(void) {
    printf("=== DHT Package A: forwarded-read merge (S1/F6) ===\n");
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_a) != 0) { printf("FATAL: id_a\n"); return 1; }
    memset(seed, 0x43, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_b) != 0) { printf("FATAL: id_b\n"); return 1; }
    nodus_hash((const uint8_t *)"pkg-a:key-x", 11, &key_x);
    nodus_hash((const uint8_t *)"pkg-a:key-y", 11, &key_y);

    test_pk_signed_order();
    test_value_newer();
    test_same_vid_two_owners();
    test_newer_wins_any_order();
    test_bad_rows_dropped();
    test_loser_not_verified();
    test_owner_filter();
    test_single_get_newest_verified();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
