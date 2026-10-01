/**
 * Nodus — DHT Package A: forwarded-read candidate sets (S1) + forwarded-
 * value verification (F6, rev 2 item 11), driven in-process through the
 * pure helpers the BF forward path uses (nodus_server.h, internal section).
 *
 * Pins down:
 *   1. PK order compares value_id as SIGNED int64 (storage PK order).
 *   2. The replica predicate: higher seq wins; equal seq → higher
 *      SHA3-256(data) wins; identical → no replace.
 *   3. Rows are told apart by (owner_fp, value_id): two owners with the
 *      SAME value_id both survive.
 *   4. The newer row is returned whatever order the sources answer in; the
 *      resolved set is the same for both orders.
 *   5. F6: a row with a key_hash other than the asked key is dropped when
 *      added; a row with a bad signature is dropped at resolution; the
 *      rest are returned.
 *   6. Rev 2 item 11: nothing is verified when added; resolution verifies
 *      only the row it returns per PK — a valid newer row makes the forged
 *      older copy behind it cost no verify.
 *   7. Rev 2 item 11: a forged NEWER row does not evict the valid older
 *      row of the same PK — the older one is returned.
 *   8. A forged copy with the same PK, seq and data but a bad signature,
 *      arriving FIRST, does not hide the valid copy arriving later (exact
 *      duplicates are collapsed only when everything verify reads is
 *      equal); an exact copy is collapsed and costs nothing.
 *   9. Owner filter drops other owners' rows (S2 re-applied at the merge).
 *  10. Unpaged replies keep the arrival order of the PKs (local rows
 *      first, then forwarded) — the order these replies had before.
 *  11. The verify budget: with it spent, the undecided rows are left out
 *      and the resolution says so (capped); local (trusted) rows cost
 *      nothing.
 *  12. Single GET picks the newest VERIFIED row, not the first arrived,
 *      and not a forged newer one; the owner filter applies; with the
 *      verify budget spent before any candidate is decided it returns
 *      NULL AND reports capped (answered UNAVAILABLE, not "not found").
 *  13. Rev 3 R-c (round-2 HIGH): 1025 rows without a signature from one
 *      source are refused at add — no verify spent, the local row above
 *      them returned.
 *  14. Rev 3 R-a: with the budget spent the unpaged walk goes on; local
 *      rows above undecided ones are returned, and for a PK whose newer
 *      forwarded row is undecided the local row is taken. Same for the
 *      single GET.
 *  15. Rev 3 R-b: a source's first failed verify drops all its undecided
 *      rows (no further verify) and its page note (bound, more).
 *  16. Rev 3 R-f: exact copies → the smallest created_at in either order;
 *      a trusted copy's created_at stands.
 *  17. Rev 3 R-g: a stored data_hash is the candidate hash; an absent one
 *      is computed.
 *
 * Requires: default build. Leaves behind: nothing (in-process).
 * RED on the tree before rev 2: rows were verified as they arrived and a
 * newer row replaced the present one at merge time; the keyset API does
 * not exist. RED before rev 3: 13-17 (each test names what fails without
 * its subject).
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

/* Byte-exact copy (the wire round-trip a second replica's answer takes). */
static nodus_value_t *clone(const nodus_value_t *v) {
    uint8_t *buf = NULL;
    size_t len = 0;
    nodus_value_t *out = NULL;
    if (!v || nodus_value_serialize(v, &buf, &len) != 0) return NULL;
    if (nodus_value_deserialize(buf, len, &out) != 0) out = NULL;
    free(buf);
    return out;
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

/* Resolve unpaged with a fresh verify budget. */
static int resolve_all(nodus_dht_keyset_t *ks, nodus_value_t ***rows, size_t *n,
                       int *spent) {
    int left = NODUS_DHT_VERIFY_CAP;
    bool capped = false;
    int rc = nodus_dht_keyset_resolve(ks, false, 0, &left, rows, n, NULL, &capped);
    if (spent) *spent = NODUS_DHT_VERIFY_CAP - left;
    return (rc == 0 && !capped) ? 0 : -1;
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
    CHECK(nodus_dht_value_newer(s1, h1) + nodus_dht_value_newer(h1, s1) == 1, "hash tiebreak");
    CHECK(nodus_dht_value_newer(neg, s1) == 0 && nodus_dht_value_newer(s1, neg) == 1,
          "signed seq");
    PASS();
out:
    nodus_value_free(s1); nodus_value_free(s2); nodus_value_free(h1); nodus_value_free(neg);
}

static void test_same_vid_two_owners(void) {
    TEST("same value_id, two owners: both kept (PK identity)");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src1[1] = { mk(&id_a, &key_x, 42, 1, "from-a", true) };
    nodus_value_t *src2[1] = { mk(&id_b, &key_x, 42, 1, "from-b", true) };
    CHECK(src1[0] && src2[0], "values");
    CHECK(nodus_dht_keyset_add(&ks, src1, 1, &key_x, NULL, NULL, false, NULL) == 0, "m1");
    CHECK(nodus_dht_keyset_add(&ks, src2, 1, &key_x, NULL, NULL, false, NULL) == 0, "m2");
    CHECK(resolve_all(&ks, &set, &n, NULL) == 0, "resolve");
    CHECK(n == 2, "one of the two owners was dropped");
    CHECK(find(set, n, &id_a.node_id, 42) && find(set, n, &id_b.node_id, 42), "owners");
    PASS();
out:
    free_rows(src1, 1); free_rows(src2, 1);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static int add_two(nodus_dht_keyset_t *ks, nodus_value_t **first, nodus_value_t **second) {
    if (nodus_dht_keyset_add(ks, first, 2, &key_x, NULL, NULL, false, NULL) != 0) return -1;
    if (nodus_dht_keyset_add(ks, second, 2, &key_x, NULL, NULL, false, NULL) != 0) return -1;
    return 0;
}

static void test_newer_wins_any_order(void) {
    TEST("newer row returned in either source order; same set");
    nodus_dht_keyset_t k_ab, k_ba;
    memset(&k_ab, 0, sizeof(k_ab));
    memset(&k_ba, 0, sizeof(k_ba));
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

    CHECK(add_two(&k_ab, old_a, new_a) == 0, "add old→new");
    CHECK(add_two(&k_ba, new_b, old_b) == 0, "add new→old");
    CHECK(resolve_all(&k_ab, &s_ab, &n_ab, NULL) == 0 &&
          resolve_all(&k_ba, &s_ba, &n_ba, NULL) == 0, "resolve");
    CHECK(n_ab == 3 && n_ba == 3, "row count");
    nodus_value_t *r1 = find(s_ab, n_ab, &id_a.node_id, 1);
    nodus_value_t *r2 = find(s_ba, n_ba, &id_a.node_id, 1);
    CHECK(r1 && r1->seq == 11 && r2 && r2->seq == 11, "newer row not returned");
    for (size_t i = 0; i < n_ab; i++) {
        nodus_value_t *o = find(s_ba, n_ba, &s_ab[i]->owner_fp, s_ab[i]->value_id);
        CHECK(o && o->seq == s_ab[i]->seq && o->data_len == s_ab[i]->data_len &&
              memcmp(o->data, s_ab[i]->data, o->data_len) == 0, "sets differ");
    }
    PASS();
out:
    free_rows(old_a, 2); free_rows(new_a, 2); free_rows(old_b, 2); free_rows(new_b, 2);
    nodus_dht_keyset_clear(&k_ab); nodus_dht_keyset_clear(&k_ba);
    free_set(s_ab, n_ab); free_set(s_ba, n_ba);
}

static void test_bad_rows_dropped(void) {
    TEST("F6: wrong key dropped at add, bad signature at resolve");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    /* Rev 3 R-b: a source whose row fails verification loses its other
     * undecided rows too, so the forged row comes from its own source. */
    nodus_value_t *src[3] = {
        mk(&id_a, &key_x, 1, 1, "good", true),
        mk(&id_a, &key_y, 3, 1, "other-key", true),   /* valid sig, wrong key */
        mk(&id_b, &key_x, 4, 1, "good-b", true),
    };
    nodus_value_t *forged[1] = { mk(&id_a, &key_x, 2, 1, "forged", true) };
    nodus_dht_merge_stats_t st;
    CHECK(src[0] && src[1] && src[2] && forged[0], "values");
    forged[0]->data[0] ^= 0x01;   /* signature no longer covers the data */
    CHECK(nodus_dht_keyset_add(&ks, src, 3, &key_x, NULL, NULL, false, &st) == 0, "add");
    CHECK(st.bad == 1 && st.added == 2, "add stats (only the wrong key is refused here)");
    CHECK(nodus_dht_keyset_add(&ks, forged, 1, &key_x, NULL, NULL, false, &st) == 0, "add2");
    CHECK(st.added == 1 && st.refused == 0, "a signed-then-altered row is a candidate");
    CHECK(resolve_all(&ks, &set, &n, NULL) == 0, "resolve");
    CHECK(n == 2, "wrong row count");
    CHECK(find(set, n, &id_a.node_id, 1) && find(set, n, &id_b.node_id, 4), "good rows");
    CHECK(!find(set, n, &id_a.node_id, 2), "forged row returned");
    CHECK(!find(set, n, &id_a.node_id, 3), "other key row returned");
    PASS();
out:
    free_rows(src, 3);
    free_rows(forged, 1);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_loser_not_verified(void) {
    TEST("only the returned row of a PK is verified");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    int spent = -1;
    nodus_value_t *s1[1] = { mk(&id_a, &key_x, 1, 9, "valid-newer", true) };
    nodus_value_t *s2[1] = { mk(&id_a, &key_x, 1, 3, "forged-older", false) };
    CHECK(s1[0] && s2[0], "values");
    CHECK(nodus_dht_keyset_add(&ks, s1, 1, &key_x, NULL, NULL, false, NULL) == 0, "m1");
    CHECK(nodus_dht_keyset_add(&ks, s2, 1, &key_x, NULL, NULL, false, NULL) == 0, "m2");
    CHECK(resolve_all(&ks, &set, &n, &spent) == 0, "resolve");
    CHECK(n == 1 && set[0]->seq == 9, "set");
    CHECK(spent == 1, "the losing older row was verified");
    PASS();
out:
    free_rows(s1, 1); free_rows(s2, 1);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_forged_newer_keeps_older(void) {
    TEST("item 11: forged newer row does not evict the valid older");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *honest[1] = { mk(&id_a, &key_x, 7, 3, "valid-older", true) };
    nodus_value_t *forged[1] = { mk(&id_a, &key_x, 7, 99, "forged-newer", true) };
    CHECK(honest[0] && forged[0], "values");
    forged[0]->data[0] ^= 0x01;
    CHECK(nodus_dht_keyset_add(&ks, honest, 1, &key_x, NULL, NULL, false, NULL) == 0, "m1");
    CHECK(nodus_dht_keyset_add(&ks, forged, 1, &key_x, NULL, NULL, false, NULL) == 0, "m2");
    CHECK(resolve_all(&ks, &set, &n, NULL) == 0, "resolve");
    CHECK(n == 1 && set[0]->seq == 3, "valid older row lost to a forged newer one");
    PASS();
out:
    free_rows(honest, 1); free_rows(forged, 1);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_bad_copy_first_no_poison(void) {
    TEST("bad-signature copy first does not hide the valid copy");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_dht_merge_stats_t st;
    nodus_value_t *bad[1]  = { mk(&id_a, &key_x, 5, 4, "same-data", true) };
    nodus_value_t *good[1] = { mk(&id_a, &key_x, 5, 4, "same-data", true) };
    nodus_value_t *copy[1] = { clone(good[0]) };
    CHECK(bad[0] && good[0] && copy[0], "values");
    bad[0]->signature.bytes[10] ^= 0x01;   /* same PK, seq, data; signature broken */
    CHECK(nodus_dht_keyset_add(&ks, bad, 1, &key_x, NULL, NULL, false, &st) == 0, "m1");
    CHECK(nodus_dht_keyset_add(&ks, good, 1, &key_x, NULL, NULL, false, &st) == 0, "m2");
    CHECK(st.added == 1 && st.dup == 0, "a differing signature was collapsed as a copy");
    CHECK(nodus_dht_keyset_add(&ks, copy, 1, &key_x, NULL, NULL, false, &st) == 0, "m3");
    CHECK(st.added == 0 && st.dup == 1, "an exact copy was not collapsed");
    CHECK(resolve_all(&ks, &set, &n, NULL) == 0, "resolve");
    CHECK(n == 1 && nodus_value_verify(set[0]) == 0, "the valid copy was not returned");
    PASS();
out:
    free_rows(bad, 1); free_rows(good, 1); free_rows(copy, 1);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_owner_filter(void) {
    TEST("owner filter re-applied at the merge");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    nodus_value_t *src[3] = { mk(&id_a, &key_x, 1, 1, "a1", true),
                              mk(&id_b, &key_x, 2, 1, "b2", true),
                              mk(&id_a, &key_x, 3, 1, "a3", true) };
    CHECK(src[0] && src[1] && src[2], "values");
    CHECK(nodus_dht_keyset_add(&ks, src, 3, &key_x, &id_a.node_id, NULL, false, NULL) == 0,
          "add");
    CHECK(resolve_all(&ks, &set, &n, NULL) == 0, "resolve");
    CHECK(n == 2 && !find(set, n, &id_b.node_id, 2), "foreign owner kept");
    PASS();
out:
    free_rows(src, 3);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_unpaged_arrival_order(void) {
    TEST("unpaged reply keeps the arrival order of the PKs");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    /* local (trusted) rows in storage order vid 9, 2; forwarded vid 5, then
     * a newer copy of vid 9 (the PK keeps its first position). */
    nodus_value_t *local[2] = { mk(&id_a, &key_x, 9, 1, "l9", true),
                                mk(&id_a, &key_x, 2, 1, "l2", true) };
    nodus_value_t *fwd[2]   = { mk(&id_a, &key_x, 5, 1, "f5", true),
                                mk(&id_a, &key_x, 9, 2, "f9-newer", true) };
    CHECK(local[0] && local[1] && fwd[0] && fwd[1], "values");
    CHECK(nodus_dht_keyset_add(&ks, local, 2, &key_x, NULL, NULL, true, NULL) == 0, "local");
    CHECK(nodus_dht_keyset_add(&ks, fwd, 2, &key_x, NULL, NULL, false, NULL) == 0, "fwd");
    CHECK(resolve_all(&ks, &set, &n, NULL) == 0, "resolve");
    CHECK(n == 3, "count");
    CHECK(set[0]->value_id == 9 && set[0]->seq == 2 && set[1]->value_id == 2 &&
          set[2]->value_id == 5, "order is not the arrival order of the PKs");
    PASS();
out:
    free_rows(local, 2); free_rows(fwd, 2);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_verify_budget(void) {
    TEST("verify budget: spent → rest dropped, capped; local rows free");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    bool capped = false;
    int left = 1;
    nodus_value_t *local[1] = { mk(&id_a, &key_x, 1, 1, "local", true) };
    nodus_value_t *fwd[3] = { mk(&id_a, &key_x, 2, 1, "f2", true),
                              mk(&id_a, &key_x, 3, 1, "f3", true),
                              mk(&id_a, &key_x, 4, 1, "f4", true) };
    CHECK(local[0] && fwd[0] && fwd[1] && fwd[2], "values");
    CHECK(nodus_dht_keyset_add(&ks, local, 1, &key_x, NULL, NULL, true, NULL) == 0, "local");
    CHECK(nodus_dht_keyset_add(&ks, fwd, 3, &key_x, NULL, NULL, false, NULL) == 0, "fwd");
    CHECK(nodus_dht_keyset_resolve(&ks, false, 0, &left, &set, &n, NULL, &capped) == 0,
          "resolve");
    CHECK(capped, "budget exhaustion not reported");
    CHECK(left == 0, "budget not spent");
    CHECK(n == 2 && find(set, n, &id_a.node_id, 1) && find(set, n, &id_a.node_id, 2),
          "local row + one verified row expected");
    PASS();
out:
    free_rows(local, 1); free_rows(fwd, 3);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

static void test_single_get_newest_verified(void) {
    TEST("single GET: newest verified row, not first arrived");
    nodus_dht_keyset_t ks, ko, kc;
    memset(&ks, 0, sizeof(ks));
    memset(&ko, 0, sizeof(ko));
    memset(&kc, 0, sizeof(kc));
    nodus_value_t *best = NULL, *own_best = NULL;
    int left = NODUS_DHT_VERIFY_CAP;
    nodus_value_t *first[1]  = { mk(&id_a, &key_x, 1, 4, "first-old", true) };
    nodus_value_t *forged[1] = { mk(&id_b, &key_x, 2, 99, "forged-newest", true) };
    nodus_value_t *later[1]  = { mk(&id_b, &key_x, 3, 7, "later-newer", true) };
    nodus_value_t *mix[2] = { mk(&id_b, &key_x, 5, 50, "b", true),
                              mk(&id_a, &key_x, 6, 2, "a", true) };
    nodus_value_t *lone[1] = { mk(&id_a, &key_x, 8, 1, "lone", true) };
    CHECK(first[0] && forged[0] && later[0] && mix[0] && mix[1] && lone[0], "values");
    forged[0]->data[0] ^= 0x01;

    CHECK(nodus_dht_keyset_add(&ks, first, 1, &key_x, NULL, NULL, false, NULL) == 0, "a1");
    CHECK(nodus_dht_keyset_add(&ks, forged, 1, &key_x, NULL, NULL, false, NULL) == 0, "a2");
    CHECK(nodus_dht_keyset_add(&ks, later, 1, &key_x, NULL, NULL, false, NULL) == 0, "a3");
    bool capped = true;
    best = nodus_dht_keyset_pick_best(&ks, true, &left, &capped);
    CHECK(best && best->seq == 7, "newest verified row not picked");
    CHECK(!capped, "capped with budget left");
    CHECK(left == NODUS_DHT_VERIFY_CAP - 2, "verified more than forged + winner");

    /* owner filter: only id_a's rows count */
    CHECK(nodus_dht_keyset_add(&ko, mix, 2, &key_x, &id_a.node_id, NULL, false, NULL) == 0,
          "own add");
    own_best = nodus_dht_keyset_pick_best(&ko, false, &left, NULL);
    CHECK(own_best && nodus_key_cmp(&own_best->owner_fp, &id_a.node_id) == 0, "owner pick");

    /* verify budget gone with an undecided candidate: NULL + capped (the
     * reply layer answers UNAVAILABLE, not "not found") */
    {
        int none = 0;
        CHECK(nodus_dht_keyset_add(&kc, lone, 1, &key_x, NULL, NULL, false, NULL) == 0,
              "lone add");
        capped = false;
        nodus_value_t *got = nodus_dht_keyset_pick_best(&kc, true, &none, &capped);
        CHECK(got == NULL && capped, "spent budget must report capped, not a miss");
    }
    PASS();
out:
    nodus_value_free(best);
    nodus_value_free(own_best);
    nodus_dht_keyset_clear(&ks);
    nodus_dht_keyset_clear(&ko);
    nodus_dht_keyset_clear(&kc);
    free_rows(first, 1); free_rows(forged, 1); free_rows(later, 1); free_rows(mix, 2);
    free_rows(lone, 1);
}

/* Rev 3 R-c — the round-2 HIGH. One forward target sends 1025 rows with an
 * owner key but no signature, all at PKs BELOW a local (trusted) row. They
 * must be refused before they become candidates: nothing is verified and
 * the local row is returned, not capped.
 * FAILS WITHOUT R-c: the rows become candidates (590 after the R-e cap)
 * and at least one verify is spent (spent == 0 fails; refused == 1025
 * fails). Before rev 3 the flood spent the whole budget and the walk
 * stopped before the local row (n == 0, capped). */
static void test_sigless_flood_refused(void) {
    TEST("R-c: 1025 sig-less rows refused; local row returned");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    int spent = -1;
    enum { FLOOD = NODUS_DHT_VERIFY_CAP + 1 };
    nodus_value_t **flood = calloc(FLOOD, sizeof(nodus_value_t *));
    nodus_value_t *local[1] = { mk(&id_a, &key_x, 5000, 1, "local-above", true) };
    nodus_dht_merge_stats_t st;
    CHECK(flood && local[0], "alloc");
    for (int i = 0; i < FLOOD; i++) {
        flood[i] = mk(&id_a, &key_x, (uint64_t)(i + 1), 1, "x", false);  /* no signature */
        CHECK(flood[i], "flood value");
    }
    CHECK(nodus_dht_keyset_add(&ks, local, 1, &key_x, NULL, NULL, true, NULL) == 0, "local");
    CHECK(nodus_dht_keyset_add(&ks, flood, FLOOD, &key_x, NULL, NULL, false, &st) == 0, "flood");
    CHECK(st.refused == FLOOD && st.added == 0, "sig-less rows became candidates");
    CHECK(resolve_all(&ks, &set, &n, &spent) == 0, "resolve (capped)");
    CHECK(n == 1 && set[0]->value_id == 5000, "local row not returned");
    CHECK(spent == 0, "a refused row was verified");
    PASS();
out:
    if (flood) { free_rows(flood, FLOOD); free(flood); }
    free_rows(local, 1);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

/* Rev 3 R-a (unpaged) — the HIGH's mechanism, budget already spent. Valid
 * forwarded rows sit at PKs below local rows; one forwarded row is the
 * NEWER version of a local row's PK. With verify_left = 0 every forwarded
 * row is undecided: the walk must go on past them and return both local
 * rows (for vid 7 the local seq 1, the undecided seq 2 passed over).
 * FAILS WITHOUT R-a: the walk stopped at the first undecided group (vid 1)
 * and returned nothing (n == 0). */
static void test_budget_spent_keeps_trusted(void) {
    TEST("R-a: budget spent → walk goes on, local rows returned");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t **set = NULL;
    size_t n = 0;
    bool capped = false;
    int left = 0;
    nodus_value_t *local[2] = { mk(&id_a, &key_x, 7, 1, "local-7", true),
                                mk(&id_a, &key_x, 1000, 1, "local-1000", true) };
    nodus_value_t *fwd[4] = { mk(&id_a, &key_x, 1, 1, "f1", true),
                              mk(&id_a, &key_x, 2, 1, "f2", true),
                              mk(&id_a, &key_x, 3, 1, "f3", true),
                              mk(&id_a, &key_x, 7, 2, "f7-newer", true) };
    CHECK(local[0] && local[1] && fwd[0] && fwd[1] && fwd[2] && fwd[3], "values");
    CHECK(nodus_dht_keyset_add(&ks, local, 2, &key_x, NULL, NULL, true, NULL) == 0, "local");
    CHECK(nodus_dht_keyset_add(&ks, fwd, 4, &key_x, NULL, NULL, false, NULL) == 0, "fwd");
    CHECK(nodus_dht_keyset_resolve(&ks, false, 0, &left, &set, &n, NULL, &capped) == 0,
          "resolve");
    CHECK(capped, "skipped undecided rows must report capped");
    CHECK(n == 2, "both local rows must be returned");
    {
        nodus_value_t *r7 = find(set, n, &id_a.node_id, 7);
        CHECK(r7 && r7->seq == 1, "vid 7 must be the local (settled) row");
        CHECK(find(set, n, &id_a.node_id, 1000), "local row above the undecided ones lost");
    }
    PASS();
out:
    free_rows(local, 2);
    free_rows(fwd, 4);
    nodus_dht_keyset_clear(&ks);
    free_set(set, n);
}

/* Rev 3 R-b. Source X sends 50 forged rows (signed then altered: they pass
 * R-c) and one VALID row; source Y one valid row; the local store one row.
 * X's first failed verify discards X: its other undecided rows — the valid
 * one included — are dropped without a verify. Unpaged: 2 verifies (X's
 * first row, Y's row), rows Y + local. Paged: X claimed a filled page with
 * more = true; its page note is dropped too, so the page is not held to
 * X's last PK and does not say more.
 * FAILS WITHOUT R-b: 51 forged verifies + X's valid row (spent 52, n 3);
 * paged, X's bound at vid 60 holds the page to [60] with more = true. */
static void test_source_discarded_on_first_fail(void) {
    TEST("R-b: a source's first failed verify drops all its rows");
    nodus_dht_keyset_t ks, kp;
    memset(&ks, 0, sizeof(ks));
    memset(&kp, 0, sizeof(kp));
    nodus_value_t **set = NULL, **pset = NULL;
    size_t n = 0, pn = 0;
    int spent = -1;
    enum { NX = 51 };
    nodus_value_t *x1[NX], *x2[NX];
    memset(x1, 0, sizeof(x1));
    memset(x2, 0, sizeof(x2));
    nodus_value_t *y1[1] = { mk(&id_a, &key_x, 70, 1, "y70", true) };
    nodus_value_t *y2[1] = { mk(&id_a, &key_x, 70, 1, "y70", true) };
    nodus_value_t *l1[1] = { mk(&id_a, &key_x, 100, 1, "l100", true) };
    nodus_value_t *l2[1] = { mk(&id_a, &key_x, 100, 1, "l100", true) };
    nodus_t2_page_info_t pg;
    nodus_dht_merge_stats_t st;
    CHECK(y1[0] && y2[0] && l1[0] && l2[0], "values");
    for (int i = 0; i < NX; i++) {
        bool valid = (i == NX - 1);               /* vid 60: X's one valid row */
        uint64_t vid = valid ? 60 : (uint64_t)(i + 1);
        x1[i] = mk(&id_a, &key_x, vid, 1, "xrow", true);
        x2[i] = mk(&id_a, &key_x, vid, 1, "xrow", true);
        CHECK(x1[i] && x2[i], "x values");
        if (!valid) { x1[i]->data[0] ^= 0x01; x2[i]->data[0] ^= 0x01; }
    }

    /* unpaged */
    CHECK(nodus_dht_keyset_add(&ks, l1, 1, &key_x, NULL, NULL, true, NULL) == 0, "l");
    CHECK(nodus_dht_keyset_add(&ks, x1, NX, &key_x, NULL, NULL, false, NULL) == 0, "x");
    CHECK(nodus_dht_keyset_add(&ks, y1, 1, &key_x, NULL, NULL, false, NULL) == 0, "y");
    CHECK(resolve_all(&ks, &set, &n, &spent) == 0, "resolve");
    CHECK(spent == 2, "rows of a discarded source were verified");
    CHECK(n == 2 && find(set, n, &id_a.node_id, 70) && find(set, n, &id_a.node_id, 100),
          "Y's row and the local row expected");
    CHECK(!find(set, n, &id_a.node_id, 60), "a discarded source's undecided row was returned");

    /* paged: X says more with a filled page (tiny responder budget) */
    {
        int left = NODUS_DHT_VERIFY_CAP;
        bool capped = false;
        CHECK(nodus_dht_keyset_add(&kp, l2, 1, &key_x, NULL, NULL, true, &st) == 0, "pl");
        nodus_dht_keyset_note_page(&kp, false, true, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL, &st);
        CHECK(nodus_dht_keyset_add(&kp, x2, NX, &key_x, NULL, NULL, false, &st) == 0, "px");
        nodus_dht_keyset_note_page(&kp, true, false, 1, NULL, &st);
        CHECK(kp.src[1].bounds, "precondition: X claims a bound");
        CHECK(nodus_dht_keyset_add(&kp, y2, 1, &key_x, NULL, NULL, false, &st) == 0, "py");
        nodus_dht_keyset_note_page(&kp, false, false, NODUS_GET_ALL_PAGE_MAX_BYTES, NULL, &st);
        CHECK(nodus_dht_keyset_resolve(&kp, true, NODUS_GET_ALL_PAGE_MAX_BYTES, &left,
                                       &pset, &pn, &pg, &capped) == 0, "presolve");
        CHECK(pn >= 2 && find(pset, pn, &id_a.node_id, 70) &&
              find(pset, pn, &id_a.node_id, 100), "page held to the discarded source");
        CHECK(!pg.more, "a discarded source's more still counted");
    }
    PASS();
out:
    for (int i = 0; i < NX; i++) { nodus_value_free(x1[i]); nodus_value_free(x2[i]); }
    free_rows(y1, 1); free_rows(y2, 1); free_rows(l1, 1); free_rows(l2, 1);
    nodus_dht_keyset_clear(&ks);
    nodus_dht_keyset_clear(&kp);
    free_set(set, n);
    free_set(pset, pn);
}

/* Rev 3 R-f. Exact copies that differ only in created_at (not signed):
 * without a trusted copy the result carries the SMALLEST created_at,
 * whatever order the copies arrived in; with a trusted (local) copy its
 * created_at stands.
 * FAILS WITHOUT R-f: the first copy's created_at stayed — the order
 * (500 first, 300 second) returns 500, and the trusted case returns
 * whichever came first. */
static void test_created_at_min(void) {
    TEST("R-f: exact copies → min created_at; trusted copy stands");
    nodus_dht_keyset_t k1, k2, k3;
    memset(&k1, 0, sizeof(k1));
    memset(&k2, 0, sizeof(k2));
    memset(&k3, 0, sizeof(k3));
    nodus_value_t **s1 = NULL, **s2 = NULL, **s3 = NULL;
    size_t n1 = 0, n2 = 0, n3 = 0;
    nodus_value_t *base = mk(&id_a, &key_x, 9, 1, "same", true);
    nodus_value_t *a[1] = { clone(base) }, *b[1] = { clone(base) };
    nodus_value_t *c[1] = { clone(base) }, *d[1] = { clone(base) };
    nodus_value_t *fwd[1] = { clone(base) }, *loc[1] = { clone(base) };
    CHECK(base && a[0] && b[0] && c[0] && d[0] && fwd[0] && loc[0], "values");
    a[0]->created_at = 500; b[0]->created_at = 300;
    c[0]->created_at = 300; d[0]->created_at = 500;
    fwd[0]->created_at = 100; loc[0]->created_at = 900;
    CHECK(nodus_dht_keyset_add(&k1, a, 1, &key_x, NULL, NULL, false, NULL) == 0 &&
          nodus_dht_keyset_add(&k1, b, 1, &key_x, NULL, NULL, false, NULL) == 0, "k1");
    CHECK(nodus_dht_keyset_add(&k2, c, 1, &key_x, NULL, NULL, false, NULL) == 0 &&
          nodus_dht_keyset_add(&k2, d, 1, &key_x, NULL, NULL, false, NULL) == 0, "k2");
    CHECK(nodus_dht_keyset_add(&k3, fwd, 1, &key_x, NULL, NULL, false, NULL) == 0 &&
          nodus_dht_keyset_add(&k3, loc, 1, &key_x, NULL, NULL, true, NULL) == 0, "k3");
    CHECK(resolve_all(&k1, &s1, &n1, NULL) == 0 && resolve_all(&k2, &s2, &n2, NULL) == 0 &&
          resolve_all(&k3, &s3, &n3, NULL) == 0, "resolve");
    CHECK(n1 == 1 && n2 == 1 && n3 == 1, "copies not collapsed");
    CHECK(s1[0]->created_at == 300 && s2[0]->created_at == 300,
          "created_at must be the minimum in either arrival order");
    CHECK(s3[0]->created_at == 900, "the trusted copy's created_at must stand");
    PASS();
out:
    nodus_value_free(base);
    free_rows(a, 1); free_rows(b, 1); free_rows(c, 1); free_rows(d, 1);
    free_rows(fwd, 1); free_rows(loc, 1);
    nodus_dht_keyset_clear(&k1); nodus_dht_keyset_clear(&k2); nodus_dht_keyset_clear(&k3);
    free_set(s1, n1); free_set(s2, n2); free_set(s3, n3);
}

/* Rev 3 R-a (single GET). Budget spent: the forwarded newer row is
 * undecided, the local row is settled valid → the local row is returned
 * (and capped reported), not NULL.
 * FAILS WITHOUT R-a: pick_best stopped at the undecided best candidate and
 * returned NULL (answered UNAVAILABLE although the node holds the row). */
static void test_single_get_budget_keeps_local(void) {
    TEST("R-a single GET: budget spent → local row returned");
    nodus_dht_keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    nodus_value_t *best = NULL;
    bool capped = false;
    int left = 0;
    nodus_value_t *local[1] = { mk(&id_a, &key_x, 1, 1, "local", true) };
    nodus_value_t *fwd[1] = { mk(&id_a, &key_x, 1, 5, "newer", true) };
    CHECK(local[0] && fwd[0], "values");
    CHECK(nodus_dht_keyset_add(&ks, local, 1, &key_x, &id_a.node_id, NULL, true, NULL) == 0,
          "local");
    CHECK(nodus_dht_keyset_add(&ks, fwd, 1, &key_x, &id_a.node_id, NULL, false, NULL) == 0,
          "fwd");
    best = nodus_dht_keyset_pick_best(&ks, false, &left, &capped);
    CHECK(best && best->seq == 1, "the local row must be returned");
    CHECK(capped, "the passed-over candidate must report capped");
    PASS();
out:
    nodus_value_free(best);
    free_rows(local, 1);
    free_rows(fwd, 1);
    nodus_dht_keyset_clear(&ks);
}

/* Rev 3 R-g. A stored data_hash given for a local row is the candidate's
 * hash (no re-hash); a row whose stored hash is absent (legacy NULL) is
 * hashed. FAILS WITHOUT R-g: the candidate hash would be SHA3-256(data),
 * not the stored bytes (0xAB...). */
static void test_stored_hash_used(void) {
    TEST("R-g: stored data_hash used for local rows");
    nodus_dht_keyset_t ks, ref;
    memset(&ks, 0, sizeof(ks));
    memset(&ref, 0, sizeof(ref));
    nodus_value_t *rows[2] = { mk(&id_a, &key_x, 1, 1, "r1", true),
                               mk(&id_a, &key_x, 2, 1, "r2", true) };
    nodus_value_t *rrow[1] = { clone(rows[1]) };
    nodus_storage_data_hash_t h[2];
    memset(h, 0, sizeof(h));
    memset(h[0].bytes, 0xAB, 32);
    h[0].present = true;
    h[1].present = false;
    CHECK(rows[0] && rows[1] && rrow[0], "values");
    CHECK(nodus_dht_keyset_add_ex(&ks, rows, 2, &key_x, NULL, NULL, true, 0, h, NULL) == 0,
          "add_ex");
    CHECK(nodus_dht_keyset_add(&ref, rrow, 1, &key_x, NULL, NULL, true, NULL) == 0, "ref");
    CHECK(ks.n == 2 && ks.c[0].v->value_id == 1 && ks.c[1].v->value_id == 2, "sorted");
    {
        uint8_t ab[32];
        memset(ab, 0xAB, sizeof(ab));
        CHECK(memcmp(ks.c[0].hash, ab, 32) == 0, "the stored hash was not used");
        CHECK(memcmp(ks.c[1].hash, ref.c[0].hash, 32) == 0, "absent stored hash not computed");
    }
    PASS();
out:
    free_rows(rows, 2);
    free_rows(rrow, 1);
    nodus_dht_keyset_clear(&ks);
    nodus_dht_keyset_clear(&ref);
}

int main(void) {
    printf("=== DHT Package A: forwarded-read candidate sets (S1/F6/item 11) ===\n");
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
    test_forged_newer_keeps_older();
    test_bad_copy_first_no_poison();
    test_owner_filter();
    test_unpaged_arrival_order();
    test_verify_budget();
    test_single_get_newest_verified();
    test_sigless_flood_refused();
    test_budget_spent_keeps_trusted();
    test_source_discarded_on_first_fail();
    test_created_at_min();
    test_single_get_budget_keeps_local();
    test_stored_hash_used();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
