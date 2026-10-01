/**
 * Nodus — write caps inside the storage layer (DHT Package A, F5 + rev 2
 * storage items 1-4 + rev 3 S-a / S-b / S-c)
 *
 * Proves:
 *  - one owner cannot hold more than NODUS_STORAGE_OWNER_MAX_BYTES (16 MiB)
 *    on a node, through EITHER write path (nodus_storage_put for clients,
 *    nodus_storage_put_if_newer for replicas), each row charged
 *    NODUS_STORAGE_ROW_CHARGE(data_len) = data + owner_pk + signature +
 *    NODUS_STORAGE_ROW_FIXED_BYTES — a 0-byte or 1-byte row is not free;
 *  - growth-only: a replace of a stored row that does not grow always
 *    passes (byte quota, owner row cap, global row cap, global byte cap); a
 *    growing replace is checked for its growth; a new row is checked for
 *    its full charge and for the row caps;
 *  - the owner row cap NODUS_STORAGE_MAX_PER_OWNER holds in put AND
 *    put_if_newer; the global caps NODUS_STORAGE_MAX_VALUES /
 *    NODUS_STORAGE_MAX_BYTES (data bytes) hold in put;
 *  - rev 3 S-a: EXPIRED rows still on disk COUNT against every cap (owner
 *    rows, owner bytes, global rows); a ttl=1 flood fills the quota and
 *    keeps it full after the values expire, until cleanup; replacing an
 *    expired row of the same (key, owner, value_id) is a REPLACE (growth
 *    only), not a new row;
 *  - rev 3 S-b: a value already expired on arrival (expires_at > 0 AND
 *    expires_at <= now) is refused with exactly NODUS_STORAGE_RC_EXPIRED
 *    (-6) by put AND put_if_newer (replica value with a past created_at),
 *    before the EXCLUSIVE lock (-2) and before the replica skip (1);
 *    nothing is stored; expires_at 0 and a future expires_at are accepted;
 *  - every cap refusal is exactly NODUS_STORAGE_RC_QUOTA (-3);
 *  - the owner quota query SEARCHes idx_nodus_values_owner (EXPLAIN QUERY
 *    PLAN on the prepared statement's own SQL text), and neither cap query
 *    takes a clock parameter.
 *
 * Filler rows are written with direct SQL (zeroblob owner_pk / signature,
 * not signed): the caps only read owner_fp, LENGTH(data) and the row count.
 *
 * Requires: default build. The global byte case writes 500 MiB of zeroblob
 * filler into the fixture DB under /tmp (removed on close) — needs that much
 * free disk. Leaves behind: nothing (fixture DB unlinked).
 * How it can lie: if NODUS_STORAGE_OWNER_MAX_BYTES were not a multiple of
 * CHUNK the fill would not land on the boundary — the first case asserts
 * N_FILL * CHUNK == the constant and fails otherwise. The clock passing a
 * value's expiry is SIMULATED with UPDATE expires_at = 1 (no sleep): the
 * ttl=1 values are stored with created_at an hour in the future so a
 * second boundary between create and put can never make them -6 (neither
 * created_at nor expires_at is covered by the signature); the cases prove
 * the caps' arithmetic over expired rows, not the wall clock.
 */

#include "core/nodus_storage.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "test_storage_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t id_a;
static nodus_identity_t id_b;
static nodus_key_t fp_a;

#define CHUNK (4u * 1024u * 1024u)   /* charge of one fill row: 4 MiB */
#define N_FILL ((int)(NODUS_STORAGE_OWNER_MAX_BYTES / CHUNK))
#define RC0   ((size_t)NODUS_STORAGE_ROW_CHARGE(0))   /* charge of a 0-byte row */
#define DLEN  ((size_t)CHUNK - RC0)   /* data length whose charge is exactly CHUNK */

static uint8_t *g_buf;   /* CHUNK bytes, heap */

static void init_ids(void) {
    uint8_t seed[32];
    memset(seed, 0x51, sizeof(seed));
    nodus_identity_from_seed(seed, &id_a);
    memset(seed, 0x52, sizeof(seed));
    nodus_identity_from_seed(seed, &id_b);
    nodus_fingerprint(&id_a.pk, &fp_a);
}

/* key index -> key "quota-key-<i>", value_id 1; data = len bytes of `fill` */
static nodus_value_t *make_val(const nodus_identity_t *id, int key_i,
                               size_t len, uint8_t fill, uint64_t seq) {
    char key_str[32];
    snprintf(key_str, sizeof(key_str), "quota-key-%d", key_i);
    nodus_key_t kh;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &kh);
    if (len > 0) memset(g_buf, fill, len);
    nodus_value_t *v = NULL;
    if (nodus_value_create(&kh, len ? g_buf : NULL, len, NODUS_VALUE_PERMANENT, 0,
                           1, seq, &id->pk, &v) != 0)
        return NULL;
    if (nodus_value_sign(v, &id->sk) != 0) { nodus_value_free(v); return NULL; }
    return v;
}

/* Value of `type` with `ttl`, then created_at set explicitly and expires_at
 * derived as nodus_value_deserialize does (0 when ttl is 0, else
 * created_at + ttl). The signature covers neither field
 * (nodus_value_sign_payload), so this is what a replica may carry. */
static nodus_value_t *make_timed(const nodus_identity_t *id, int key_i,
                                 size_t len, uint8_t fill, uint64_t seq,
                                 nodus_value_type_t type, uint32_t ttl,
                                 uint64_t created_at) {
    char key_str[32];
    snprintf(key_str, sizeof(key_str), "quota-key-%d", key_i);
    nodus_key_t kh;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &kh);
    if (len > 0) memset(g_buf, fill, len);
    nodus_value_t *v = NULL;
    if (nodus_value_create(&kh, len ? g_buf : NULL, len, type, ttl,
                           1, seq, &id->pk, &v) != 0)
        return NULL;
    if (nodus_value_sign(v, &id->sk) != 0) { nodus_value_free(v); return NULL; }
    v->created_at = created_at;
    v->expires_at = ttl ? created_at + ttl : 0;
    return v;
}

typedef int (*put_fn)(nodus_storage_t *, const nodus_value_t *);

static int put_and_free(put_fn fn, nodus_storage_t *st, nodus_value_t *v) {
    if (!v) return -100;
    int rc = fn(st, v);
    nodus_value_free(v);
    return rc;
}

/* Fill owner A through `fn` with N_FILL rows charged exactly CHUNK each
 * (keys 0..N_FILL-1) = exactly NODUS_STORAGE_OWNER_MAX_BYTES; all must store. */
static int fill_owner(put_fn fn, nodus_storage_t *st) {
    for (int i = 0; i < N_FILL; i++) {
        if (put_and_free(fn, st, make_val(&id_a, i, DLEN, 0x10, 10)) != 0)
            return -1;
    }
    return 0;
}

/* Direct SQL filler: n rows for `owner` (64 bytes), data = zeroblob(data_len),
 * key_hash = zeroblob(64) with value_id start_vid.., expires_at as given.
 * Not signed, 1-byte owner_pk / signature placeholders — the caps read only
 * owner_fp, LENGTH(data), expires_at and the row count (the pk + signature
 * part of NODUS_STORAGE_ROW_CHARGE is charged per row, not measured), so the
 * 100 000-row global fill stays small on disk. */
static int sql_fill(nodus_storage_t *st, const uint8_t *owner, int n,
                    size_t data_len, sqlite3_int64 start_vid,
                    sqlite3_int64 expires_at) {
    static const char *sql =
        "WITH RECURSIVE c(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM c WHERE n + 1 < ?2) "
        "INSERT INTO nodus_values (key_hash, owner_fp, value_id, data, type, ttl, "
        "  created_at, expires_at, seq, owner_pk, signature) "
        "SELECT zeroblob(64), ?1, ?3 + n, zeroblob(?4), 1, 0, 0, ?5, 1, "
        "  zeroblob(1), zeroblob(1) FROM c";
    if (n <= 0) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(st->db, sql, -1, &s, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(s, 1, owner, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, n);
    sqlite3_bind_int64(s, 3, start_vid);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)data_len);
    sqlite3_bind_int64(s, 5, expires_at);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int sql_exec(nodus_storage_t *st, const char *sql) {
    return sqlite3_exec(st->db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* Owner A holds rows charged OWNER_MAX - headroom, via SQL. */
static int fill_to_headroom(nodus_storage_t *st, size_t headroom) {
    if (sql_fill(st, fp_a.bytes, N_FILL - 1, DLEN, 1000, 0) != 0) return -1;
    return sql_fill(st, fp_a.bytes, 1, DLEN - headroom, 2000, 0);
}

/* ── byte quota through the API ──────────────────────────────────── */

static void test_put_quota(void) {
    TEST("put: exactly 16 MiB charged stores; 0-byte new row -> -3");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = (N_FILL * (uint64_t)CHUNK == NODUS_STORAGE_OWNER_MAX_BYTES) &&
             fill_owner(nodus_storage_put, &st) == 0;
    int rc = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1000, 0, 0, 10));
    if (ok && rc == NODUS_STORAGE_RC_QUOTA) PASS();
    else FAIL("expected fill ok and -3 for a 0-byte row");
    test_storage_close(&st);
}

static void test_put_replace_not_growing(void) {
    TEST("put: at quota, same-size and shrinking replace -> 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put, &st) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 0, DLEN, 0x20, 11));
    /* free exactly the charge of a 100-byte row */
    size_t freed = (size_t)NODUS_STORAGE_ROW_CHARGE(100);
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, DLEN - freed, 0x21, 11));
    int rc3 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2000, 100, 0x22, 1));
    /* now exactly full again */
    int rc4 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2001, 0, 0, 1));
    if (ok && rc1 == 0 && rc2 == 0 && rc3 == 0 && rc4 == NODUS_STORAGE_RC_QUOTA) PASS();
    else FAIL("non-growing replace / freed space must pass, then full");
    test_storage_close(&st);
}

static void test_put_replace_growing(void) {
    TEST("put: at quota, replace growing by 1 byte -> -3, row kept");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put, &st) == 0;
    int rc = put_and_free(nodus_storage_put, &st, make_val(&id_a, 0, DLEN + 1, 0x30, 11));
    nodus_value_t *probe = make_val(&id_a, 0, 1, 0, 0);
    nodus_value_t *got = NULL;
    int grc = probe ? nodus_storage_get(&st, &probe->key_hash, &got) : -1;
    if (ok && rc == NODUS_STORAGE_RC_QUOTA && grc == 0 && got && got->seq == 10 &&
        got->data_len == DLEN)
        PASS();
    else
        FAIL("growth over quota must be refused, old row kept");
    if (got) nodus_value_free(got);
    if (probe) nodus_value_free(probe);
    test_storage_close(&st);
}

static void test_put_other_owner(void) {
    TEST("put: owner A at quota does not limit owner B");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put, &st) == 0;
    int rc = put_and_free(nodus_storage_put, &st, make_val(&id_b, 3000, DLEN, 0x40, 1));
    if (ok && rc == 0) PASS(); else FAIL("owner B must store");
    test_storage_close(&st);
}

static void test_put_if_newer_quota(void) {
    TEST("put_if_newer: exactly 16 MiB charged stores; 0-byte new -> -3");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put_if_newer, &st) == 0;
    int rc = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 1000, 0, 0, 10));
    if (ok && rc == NODUS_STORAGE_RC_QUOTA) PASS(); else FAIL("expected fill ok and -3");
    test_storage_close(&st);
}

static void test_put_if_newer_replace_not_growing(void) {
    TEST("put_if_newer: at quota, newer same-size replace -> 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put_if_newer, &st) == 0;
    int rc = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 0, DLEN, 0x60, 11));
    if (ok && rc == 0) PASS(); else FAIL("non-growing newer replace must store");
    test_storage_close(&st);
}

static void test_put_if_newer_growing(void) {
    TEST("put_if_newer: at quota, newer replace growing -> -3");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put_if_newer, &st) == 0;
    int rc = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 0, DLEN + 1, 0x70, 11));
    if (ok && rc == NODUS_STORAGE_RC_QUOTA) PASS(); else FAIL("growing newer replace must be -3");
    test_storage_close(&st);
}

static void test_put_if_newer_stale_is_skip(void) {
    TEST("put_if_newer: at quota, OLDER larger replica -> 1 (skip)");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put_if_newer, &st) == 0;
    int rc = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 0, DLEN + 1, 0x80, 9));
    if (ok && rc == 1) PASS(); else FAIL("stale replica must report skipped");
    test_storage_close(&st);
}

/* ── per-row overhead at the boundary ────────────────────────────── */

static void test_zero_byte_row_overhead(void) {
    TEST("0-byte new row: headroom RC0-1 -> -3, headroom RC0 -> 0");
    nodus_storage_t st1, st2;
    test_storage_open(&st1);
    test_storage_open(&st2);
    int ok = fill_to_headroom(&st1, RC0 - 1) == 0 && fill_to_headroom(&st2, RC0) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st1, make_val(&id_a, 1, 0, 0, 1));
    int rc2 = put_and_free(nodus_storage_put, &st2, make_val(&id_a, 1, 0, 0, 1));
    int rc3 = put_and_free(nodus_storage_put_if_newer, &st1, make_val(&id_a, 1, 0, 0, 1));
    if (ok && rc1 == NODUS_STORAGE_RC_QUOTA && rc2 == 0 && rc3 == NODUS_STORAGE_RC_QUOTA)
        PASS();
    else
        FAIL("a 0-byte row must be charged NODUS_STORAGE_ROW_CHARGE(0)");
    test_storage_close(&st1);
    test_storage_close(&st2);
}

static void test_one_byte_row_overhead(void) {
    TEST("1-byte new row: headroom RC0 -> -3, headroom RC0+1 -> 0");
    nodus_storage_t st1, st2;
    test_storage_open(&st1);
    test_storage_open(&st2);
    int ok = fill_to_headroom(&st1, RC0) == 0 && fill_to_headroom(&st2, RC0 + 1) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st1, make_val(&id_a, 1, 1, 0x01, 1));
    int rc2 = put_and_free(nodus_storage_put, &st2, make_val(&id_a, 1, 1, 0x01, 1));
    int rc3 = put_and_free(nodus_storage_put_if_newer, &st1, make_val(&id_a, 1, 1, 0x01, 1));
    if (ok && rc1 == NODUS_STORAGE_RC_QUOTA && rc2 == 0 && rc3 == NODUS_STORAGE_RC_QUOTA)
        PASS();
    else
        FAIL("a 1-byte row must be charged NODUS_STORAGE_ROW_CHARGE(1)");
    test_storage_close(&st1);
    test_storage_close(&st2);
}

/* ── owner row cap ───────────────────────────────────────────────── */

static void test_put_owner_row_cap(void) {
    TEST("put: owner row cap; replace at cap passes");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = sql_fill(&st, fp_a.bytes, NODUS_STORAGE_MAX_PER_OWNER - 1, 1, 1000, 0) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x01, 5)); /* 1000th */
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2, 10, 0x02, 5)); /* 1001st */
    int rc3 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x03, 6)); /* same size */
    int rc4 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 9, 0x04, 7));  /* shrink */
    int rc5 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 20, 0x05, 8)); /* grow */
    int n = nodus_storage_count(&st);
    if (ok && rc1 == 0 && rc2 == NODUS_STORAGE_RC_QUOTA && rc3 == 0 && rc4 == 0 &&
        rc5 == 0 && n == (int)NODUS_STORAGE_MAX_PER_OWNER)
        PASS();
    else
        FAIL("new row at the owner row cap -3, replaces pass");
    test_storage_close(&st);
}

static void test_put_if_newer_owner_row_cap(void) {
    TEST("put_if_newer: owner row cap; newer replace at cap -> 0");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = sql_fill(&st, fp_a.bytes, NODUS_STORAGE_MAX_PER_OWNER - 1, 1, 1000, 0) == 0;
    int rc1 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 1, 10, 0x01, 5));
    int rc2 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 2, 10, 0x02, 5));
    int rc3 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 1, 10, 0x03, 6));
    int rc4 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 2, 10, 0x02, 1));
    if (ok && rc1 == 0 && rc2 == NODUS_STORAGE_RC_QUOTA && rc3 == 0 &&
        rc4 == NODUS_STORAGE_RC_QUOTA)
        PASS();
    else
        FAIL("replica new row at the owner row cap must be -3");
    test_storage_close(&st);
}

/* ── expired rows still on disk (rev 3 S-a) ──────────────────────── */

/* Simulate the clock passing the expiry of the row(s) at "quota-key-<i>":
 * expires_at = 1 (what nodus_storage_cleanup deletes). Returns the number of
 * rows changed, or -1. */
static int expire_key(nodus_storage_t *st, int key_i) {
    char key_str[32];
    snprintf(key_str, sizeof(key_str), "quota-key-%d", key_i);
    nodus_key_t kh;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &kh);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(st->db,
            "UPDATE nodus_values SET expires_at = 1 WHERE key_hash = ?",
            -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(s, 1, kh.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    int rc = sqlite3_step(s);
    int n = (rc == SQLITE_DONE) ? sqlite3_changes(st->db) : -1;
    sqlite3_finalize(s);
    return n;
}

static void test_expired_counted(void) {
    TEST("expired rows count (row cap, byte quota) until cleanup");
    nodus_storage_t st1, st2;
    test_storage_open(&st1);
    test_storage_open(&st2);
    /* st1: 1000 expired 1-byte rows; st2: exactly 16 MiB charged, expired */
    int ok = sql_fill(&st1, fp_a.bytes, NODUS_STORAGE_MAX_PER_OWNER, 1, 1000, 1) == 0 &&
             sql_fill(&st2, fp_a.bytes, N_FILL, DLEN, 5000, 1) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st1, make_val(&id_a, 1, 10, 0x01, 1));
    int rc2 = put_and_free(nodus_storage_put_if_newer, &st1, make_val(&id_a, 2, 10, 0x02, 1));
    int rc3 = put_and_free(nodus_storage_put, &st2, make_val(&id_a, 3, 0, 0, 1));
    int rc4 = put_and_free(nodus_storage_put_if_newer, &st2, make_val(&id_a, 4, 0, 0, 1));
    /* cleanup removes them; then the same writes store */
    int c1 = nodus_storage_cleanup(&st1);
    int c2 = nodus_storage_cleanup(&st2);
    int rc5 = put_and_free(nodus_storage_put, &st1, make_val(&id_a, 1, 10, 0x05, 1));
    int rc6 = put_and_free(nodus_storage_put_if_newer, &st2, make_val(&id_a, 4, 0, 0, 1));
    if (ok && rc1 == NODUS_STORAGE_RC_QUOTA && rc2 == NODUS_STORAGE_RC_QUOTA &&
        rc3 == NODUS_STORAGE_RC_QUOTA && rc4 == NODUS_STORAGE_RC_QUOTA &&
        c1 == (int)NODUS_STORAGE_MAX_PER_OWNER && c2 == N_FILL && rc5 == 0 && rc6 == 0)
        PASS();
    else
        FAIL("expired rows on disk must count until cleanup removes them");
    test_storage_close(&st1);
    test_storage_close(&st2);
}

static void test_ttl1_flood(void) {
    TEST("ttl=1 flood fills the quota and stays full once expired");
    put_fn fns[2] = { nodus_storage_put, nodus_storage_put_if_newer };
    int good = 1;
    for (int p = 0; p < 2; p++) {
        nodus_storage_t st;
        test_storage_open(&st);
        /* created an hour ahead: never expired on arrival (see header) */
        uint64_t future = (uint64_t)time(NULL) + 3600;
        int stored = 0;
        for (int i = 0; i < N_FILL; i++) {
            if (put_and_free(fns[p], &st, make_timed(&id_a, i, DLEN, 0x10, 10,
                                                     NODUS_VALUE_EPHEMERAL, 1, future)) == 0)
                stored++;
        }
        /* the clock passes every value's expiry */
        int expired = 0;
        for (int i = 0; i < N_FILL; i++)
            if (expire_key(&st, i) == 1) expired++;
        int rc1 = put_and_free(fns[p], &st, make_timed(&id_a, 1000, 0, 0, 10,
                                                       NODUS_VALUE_EPHEMERAL, 1, future));
        int rc2 = put_and_free(fns[p], &st, make_timed(&id_a, 1001, 1, 0x01, 10,
                                                       NODUS_VALUE_EPHEMERAL, 1, future));
        int c = nodus_storage_cleanup(&st);
        int rc3 = put_and_free(fns[p], &st, make_timed(&id_a, 1000, 0, 0, 10,
                                                       NODUS_VALUE_EPHEMERAL, 1, future));
        if (!(stored == N_FILL && expired == N_FILL && rc1 == NODUS_STORAGE_RC_QUOTA &&
              rc2 == NODUS_STORAGE_RC_QUOTA && c == N_FILL && rc3 == 0))
            good = 0;
        test_storage_close(&st);
    }
    if (good) PASS();
    else FAIL("expired ttl=1 rows must keep the owner at the quota (both paths)");
}

static void test_replace_expired_is_replace(void) {
    TEST("replace of an expired row at the row cap -> 0 (replace)");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = sql_fill(&st, fp_a.bytes, NODUS_STORAGE_MAX_PER_OWNER - 1, 1, 1000, 0) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x01, 5));
    /* expire the API row: the owner still holds 1000 rows on disk */
    int ok2 = expire_key(&st, 1) == 1;
    /* same size, higher seq: a replace of a stored row, not a new row */
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x02, 6));
    int ok3 = expire_key(&st, 1) == 1;
    int rc3 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 1, 10, 0x03, 7));
    /* a new key is still a new row: refused */
    int rc4 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2, 10, 0x04, 1));
    int rc5 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 2, 10, 0x05, 1));
    int n = nodus_storage_count(&st);
    if (ok && rc1 == 0 && ok2 && rc2 == 0 && ok3 && rc3 == 0 &&
        rc4 == NODUS_STORAGE_RC_QUOTA && rc5 == NODUS_STORAGE_RC_QUOTA &&
        n == (int)NODUS_STORAGE_MAX_PER_OWNER)
        PASS();
    else
        FAIL("replacing an expired row of the same key/owner/vid is a replace");
    test_storage_close(&st);
}

static void test_replace_expired_growth(void) {
    TEST("at byte quota: expired row same-size replace 0, growth -3");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = fill_owner(nodus_storage_put, &st) == 0;
    int ok2 = expire_key(&st, 0) == 1;
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 0, DLEN, 0x20, 11));
    int ok3 = expire_key(&st, 0) == 1;
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 0, DLEN + 1, 0x21, 12));
    int rc3 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 0, DLEN + 1, 0x22, 12));
    if (ok && ok2 && rc1 == 0 && ok3 && rc2 == NODUS_STORAGE_RC_QUOTA &&
        rc3 == NODUS_STORAGE_RC_QUOTA)
        PASS();
    else
        FAIL("an expired row's charge stays; only its growth is checked");
    test_storage_close(&st);
}

/* ── already expired on arrival (rev 3 S-b) ──────────────────────── */

static void test_expired_on_arrival(void) {
    TEST("already expired on arrival -> -6, nothing stored");
    nodus_storage_t st;
    test_storage_open(&st);
    uint64_t now = (uint64_t)time(NULL);
    /* replica-style value with a past created_at: expires_at = 3601 */
    int rc1 = put_and_free(nodus_storage_put, &st, make_timed(&id_a, 1, 10, 0x01, 1,
                           NODUS_VALUE_EPHEMERAL, 3600, 1));
    int rc2 = put_and_free(nodus_storage_put_if_newer, &st, make_timed(&id_a, 1, 10, 0x01, 1,
                           NODUS_VALUE_EPHEMERAL, 3600, 1));
    /* boundary: expires_at == this test's now (storage's now is >= it) */
    int rc3 = put_and_free(nodus_storage_put, &st, make_timed(&id_a, 2, 10, 0x02, 1,
                           NODUS_VALUE_EPHEMERAL, 3600, now - 3600));
    int rc4 = put_and_free(nodus_storage_put_if_newer, &st, make_timed(&id_a, 2, 10, 0x02, 1,
                           NODUS_VALUE_EPHEMERAL, 3600, now - 3600));
    int n0 = nodus_storage_count(&st);
    /* future expiry and expires_at 0 are stored */
    int rc5 = put_and_free(nodus_storage_put, &st, make_timed(&id_a, 3, 10, 0x03, 1,
                           NODUS_VALUE_EPHEMERAL, 3600, now));
    int rc6 = put_and_free(nodus_storage_put_if_newer, &st, make_timed(&id_a, 4, 10, 0x04, 1,
                           NODUS_VALUE_EPHEMERAL, 3600, now));
    int rc7 = put_and_free(nodus_storage_put, &st, make_timed(&id_a, 5, 10, 0x05, 1,
                           NODUS_VALUE_PERMANENT, 0, 1));
    int rc8 = put_and_free(nodus_storage_put_if_newer, &st, make_timed(&id_a, 6, 10, 0x06, 1,
                           NODUS_VALUE_PERMANENT, 0, 1));
    int n1 = nodus_storage_count(&st);
    if (rc1 == NODUS_STORAGE_RC_EXPIRED && rc2 == NODUS_STORAGE_RC_EXPIRED &&
        rc3 == NODUS_STORAGE_RC_EXPIRED && rc4 == NODUS_STORAGE_RC_EXPIRED && n0 == 0 &&
        rc5 == 0 && rc6 == 0 && rc7 == 0 && rc8 == 0 && n1 == 4)
        PASS();
    else
        FAIL("expired-on-arrival must be -6 on both paths; live / permanent stored");
    test_storage_close(&st);
}

static void test_expired_on_arrival_order(void) {
    TEST("expired on arrival: -6 before lock (-2) and replica skip (1)");
    nodus_storage_t st;
    test_storage_open(&st);
    uint64_t now = (uint64_t)time(NULL);
    /* B locks key 50 */
    int rc0 = put_and_free(nodus_storage_put, &st, make_timed(&id_b, 50, 4, 0x50, 1,
                           NODUS_VALUE_EXCLUSIVE, 0, now));
    int rc1 = put_and_free(nodus_storage_put, &st, make_timed(&id_a, 50, 4, 0x51, 9,
                           NODUS_VALUE_EPHEMERAL, 3600, 1));
    int rc2 = put_and_free(nodus_storage_put_if_newer, &st, make_timed(&id_a, 50, 4, 0x51, 9,
                           NODUS_VALUE_EPHEMERAL, 3600, 1));
    /* A holds key 60 at seq 9; an older expired replica would be skipped */
    int rc3 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 60, 4, 0x60, 9));
    int rc4 = put_and_free(nodus_storage_put_if_newer, &st, make_timed(&id_a, 60, 4, 0x61, 1,
                           NODUS_VALUE_EPHEMERAL, 3600, 1));
    /* control: the same replica not expired is the skip */
    int rc5 = put_and_free(nodus_storage_put_if_newer, &st, make_timed(&id_a, 60, 4, 0x61, 1,
                           NODUS_VALUE_EPHEMERAL, 3600, now));
    if (rc0 == 0 && rc1 == NODUS_STORAGE_RC_EXPIRED && rc2 == NODUS_STORAGE_RC_EXPIRED &&
        rc3 == 0 && rc4 == NODUS_STORAGE_RC_EXPIRED && rc5 == 1)
        PASS();
    else
        FAIL("-6 is checked first, before any DB read");
    test_storage_close(&st);
}

/* ── global caps (put only) ──────────────────────────────────────── */

static void test_global_row_cap(void) {
    TEST("put: global row cap; replace passes; expired still counts");
    nodus_storage_t st;
    test_storage_open(&st);
    uint8_t other[NODUS_KEY_BYTES];
    memset(other, 0xC7, sizeof(other));
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x01, 5));
    int ok = sql_fill(&st, other, (int)NODUS_STORAGE_MAX_VALUES - 1, 1, 1, 0) == 0 &&
             nodus_storage_count(&st) == (int)NODUS_STORAGE_MAX_VALUES;
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2, 10, 0x02, 5));
    int rc3 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x03, 6));
    int rc4 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 11, 0x04, 7));
    /* the replica path has no global caps */
    int rc5 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 3, 10, 0x05, 5));
    /* 100001 rows now (rc5); expiring two filler rows leaves them on disk:
     * still counted (rev 3 S-a) — until cleanup removes them */
    int ok2 = sql_exec(&st, "UPDATE nodus_values SET expires_at = 1 WHERE value_id <= 2 "
                            "AND key_hash = zeroblob(64)") == 0 &&
              sqlite3_changes(st.db) == 2;
    int rc6 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2, 10, 0x06, 5));
    int c = nodus_storage_cleanup(&st);   /* 99999 rows left */
    int rc7 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2, 10, 0x07, 5));
    if (rc1 == 0 && ok && rc2 == NODUS_STORAGE_RC_QUOTA && rc3 == 0 && rc4 == 0 &&
        rc5 == 0 && ok2 && rc6 == NODUS_STORAGE_RC_QUOTA && c == 2 && rc7 == 0)
        PASS();
    else
        FAIL("global row cap growth-only, expired rows counted");
    test_storage_close(&st);
}

static void test_global_byte_cap(void) {
    TEST("put: global byte cap (data bytes) at exactly 500 MiB");
    nodus_storage_t st;
    test_storage_open(&st);
    uint8_t other[NODUS_KEY_BYTES];
    memset(other, 0xC8, sizeof(other));
    const size_t big = 4u * 1024u * 1024u;
    int n_big = (int)(NODUS_STORAGE_MAX_BYTES / big);   /* 125 */
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x01, 5));
    /* table data = MAX_BYTES - 1 after the fill */
    int ok = ((uint64_t)n_big * big == NODUS_STORAGE_MAX_BYTES) &&
             sql_fill(&st, other, n_big - 1, big, 1, 0) == 0 &&
             sql_fill(&st, other, 1, big - 10 - 1, 1000, 0) == 0;
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2, 1, 0x02, 5)); /* == MAX */
    int rc3 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 3, 1, 0x03, 5)); /* MAX + 1 */
    int rc4 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x04, 6)); /* same size */
    int rc5 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 11, 0x05, 7)); /* grows */
    int rc6 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 3, 0, 0, 5));     /* 0 data bytes */
    if (rc1 == 0 && ok && rc2 == 0 && rc3 == NODUS_STORAGE_RC_QUOTA && rc4 == 0 &&
        rc5 == NODUS_STORAGE_RC_QUOTA && rc6 == 0)
        PASS();
    else
        FAIL("global byte cap growth-only, data bytes");
    test_storage_close(&st);
}

/* ── query plan ──────────────────────────────────────────────────── */

/* 1 if EXPLAIN QUERY PLAN of `stmt`'s own SQL has a detail containing `want`. */
static int plan_contains(nodus_storage_t *st, sqlite3_stmt *stmt, const char *want) {
    const char *sql = sqlite3_sql(stmt);
    if (!sql) return 0;
    size_t n = strlen(sql) + 32;
    char *q = malloc(n);
    if (!q) return 0;
    snprintf(q, n, "EXPLAIN QUERY PLAN %s", sql);
    sqlite3_stmt *e = NULL;
    int found = 0;
    if (sqlite3_prepare_v2(st->db, q, -1, &e, NULL) == SQLITE_OK) {
        while (sqlite3_step(e) == SQLITE_ROW) {
            const char *detail = (const char *)sqlite3_column_text(e, 3);
            if (detail && strstr(detail, want)) found = 1;
        }
    }
    sqlite3_finalize(e);
    free(q);
    return found;
}

static void test_owner_index_plan(void) {
    TEST("owner quota query SEARCHes idx_nodus_values_owner");
    nodus_storage_t st;
    test_storage_open(&st);
    /* Seen with the sqlite3 3.44 CLI (the build links the system
     * libsqlite3, 3.40.1 on this host — this assertion is the check there):
     * "SEARCH nodus_values USING INDEX idx_nodus_values_owner
     * (owner_fp=?)" — a SEARCH on the owner index, never a SCAN. */
    const char *want = "idx_nodus_values_owner (owner_fp=?)";
    if (plan_contains(&st, st.stmt_quota_owner_usage, "SEARCH nodus_values") &&
        plan_contains(&st, st.stmt_quota_owner_usage, want))
        PASS();
    else
        FAIL("owner quota query must use the owner_fp index");
    test_storage_close(&st);
}

static void test_cap_queries_no_clock(void) {
    TEST("cap queries take no clock (owner: 1 param, global: 0)");
    nodus_storage_t st;
    test_storage_open(&st);
    /* rev 3 S-a: the caps count every stored row — no `now` is bound */
    if (sqlite3_bind_parameter_count(st.stmt_quota_owner_usage) == 1 &&
        sqlite3_bind_parameter_count(st.stmt_quota_global_usage) == 0)
        PASS();
    else
        FAIL("a cap query still filters by expiry");
    test_storage_close(&st);
}

int main(void) {
    printf("=== Nodus storage write caps ===\n");
    g_buf = malloc(CHUNK);
    if (!g_buf) { printf("alloc failed\n"); return 1; }
    init_ids();

    test_put_quota();
    test_put_replace_not_growing();
    test_put_replace_growing();
    test_put_other_owner();
    test_put_if_newer_quota();
    test_put_if_newer_replace_not_growing();
    test_put_if_newer_growing();
    test_put_if_newer_stale_is_skip();
    test_zero_byte_row_overhead();
    test_one_byte_row_overhead();
    test_put_owner_row_cap();
    test_put_if_newer_owner_row_cap();
    test_expired_counted();
    test_ttl1_flood();
    test_replace_expired_is_replace();
    test_replace_expired_growth();
    test_expired_on_arrival();
    test_expired_on_arrival_order();
    test_global_row_cap();
    test_global_byte_cap();
    test_owner_index_plan();
    test_cap_queries_no_clock();

    free(g_buf);
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
