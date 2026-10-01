/**
 * Nodus — write caps inside the storage layer (DHT Package A, F5 + rev 2
 * storage items 1-4)
 *
 * Proves:
 *  - one owner cannot hold more than NODUS_STORAGE_OWNER_MAX_BYTES (16 MiB)
 *    on a node, through EITHER write path (nodus_storage_put for clients,
 *    nodus_storage_put_if_newer for replicas), each row charged
 *    NODUS_STORAGE_ROW_CHARGE(data_len) = data + owner_pk + signature +
 *    NODUS_STORAGE_ROW_FIXED_BYTES — a 0-byte or 1-byte row is not free;
 *  - growth-only: a replace of a live row that does not grow always passes
 *    (byte quota, owner row cap, global row cap, global byte cap); a
 *    growing replace is checked for its growth; a new row is checked for
 *    its full charge and for the row caps;
 *  - the owner row cap NODUS_STORAGE_MAX_PER_OWNER holds in put AND
 *    put_if_newer; the global caps NODUS_STORAGE_MAX_VALUES /
 *    NODUS_STORAGE_MAX_BYTES (data bytes) hold in put;
 *  - expired rows (the rows nodus_storage_cleanup would delete) are not
 *    counted, and replacing an expired row is a NEW row for the caps;
 *  - every cap refusal is exactly NODUS_STORAGE_RC_QUOTA (-3);
 *  - nodus_storage_check_quota is unchanged (still refuses at the owner row
 *    cap even though put now accepts a non-growing replace there);
 *  - the owner quota queries SEARCH idx_nodus_values_owner (EXPLAIN QUERY
 *    PLAN on the prepared statements' own SQL text).
 *
 * Filler rows are written with direct SQL (zeroblob owner_pk / signature,
 * not signed): the caps only read owner_fp, LENGTH(data) and expires_at.
 *
 * Requires: default build. The global byte case writes 500 MiB of zeroblob
 * filler into the fixture DB under /tmp (removed on close) — needs that much
 * free disk. Leaves behind: nothing (fixture DB unlinked).
 * How it can lie: if NODUS_STORAGE_OWNER_MAX_BYTES were not a multiple of
 * CHUNK the fill would not land on the boundary — the first case asserts
 * N_FILL * CHUNK == the constant and fails otherwise.
 */

#include "core/nodus_storage.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "test_storage_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
    TEST("put: owner row cap; replace at cap passes; check_quota -1");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = sql_fill(&st, fp_a.bytes, NODUS_STORAGE_MAX_PER_OWNER - 1, 1, 1000, 0) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x01, 5)); /* 1000th */
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2, 10, 0x02, 5)); /* 1001st */
    int rc3 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x03, 6)); /* same size */
    int rc4 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 9, 0x04, 7));  /* shrink */
    int rc5 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 20, 0x05, 8)); /* grow */
    int q = nodus_storage_check_quota(&st, &fp_a);   /* unchanged: refuses at the cap */
    int n = nodus_storage_count(&st);
    if (ok && rc1 == 0 && rc2 == NODUS_STORAGE_RC_QUOTA && rc3 == 0 && rc4 == 0 &&
        rc5 == 0 && q == -1 && n == (int)NODUS_STORAGE_MAX_PER_OWNER)
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

/* ── expired rows ────────────────────────────────────────────────── */

static void test_expired_not_counted(void) {
    TEST("expired rows not counted (row cap and byte quota)");
    nodus_storage_t st;
    test_storage_open(&st);
    /* 1000 expired 1-byte rows + 16 MiB expired: nothing live */
    int ok = sql_fill(&st, fp_a.bytes, NODUS_STORAGE_MAX_PER_OWNER, 1, 1000, 1) == 0 &&
             sql_fill(&st, fp_a.bytes, N_FILL, DLEN, 5000, 1) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, DLEN, 0x01, 1));
    int rc2 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 2, DLEN, 0x02, 1));
    /* expires_at 0 (never expires) and expires_at in the future count */
    int ok2 = sql_exec(&st, "UPDATE nodus_values SET expires_at = 0 WHERE value_id = 5000") == 0 &&
              sql_exec(&st, "UPDATE nodus_values SET expires_at = 9000000000000 WHERE value_id = 5001") == 0;
    int rc3 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 3, 0, 0, 1));
    if (ok && rc1 == 0 && rc2 == 0 && ok2 && rc3 == NODUS_STORAGE_RC_QUOTA) PASS();
    else FAIL("expired rows must not count; live ones must");
    test_storage_close(&st);
}

static void test_replace_expired_is_new_row(void) {
    TEST("replacing an expired row at the row cap -> -3 (new row)");
    nodus_storage_t st;
    test_storage_open(&st);
    int ok = sql_fill(&st, fp_a.bytes, NODUS_STORAGE_MAX_PER_OWNER - 1, 1, 1000, 0) == 0;
    int rc1 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x01, 5));
    /* expire the API row, then take its slot with a live filler row */
    nodus_value_t *probe = make_val(&id_a, 1, 1, 0, 0);
    int ok2 = probe != NULL;
    if (probe) {
        sqlite3_stmt *s = NULL;
        ok2 = sqlite3_prepare_v2(st.db,
                  "UPDATE nodus_values SET expires_at = 1 WHERE key_hash = ?",
                  -1, &s, NULL) == SQLITE_OK;
        if (ok2) {
            sqlite3_bind_blob(s, 1, probe->key_hash.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
            ok2 = sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(st.db) == 1;
        }
        sqlite3_finalize(s);
        nodus_value_free(probe);
    }
    ok2 = ok2 && sql_fill(&st, fp_a.bytes, 1, 1, 9000, 0) == 0;
    /* same size, higher seq: non-growing, but the stored row is expired */
    int rc2 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 1, 10, 0x02, 6));
    int rc3 = put_and_free(nodus_storage_put_if_newer, &st, make_val(&id_a, 1, 10, 0x03, 7));
    if (ok && rc1 == 0 && ok2 && rc2 == NODUS_STORAGE_RC_QUOTA &&
        rc3 == NODUS_STORAGE_RC_QUOTA)
        PASS();
    else
        FAIL("an expired row must not lend its slot to a replace");
    test_storage_close(&st);
}

/* ── global caps (put only) ──────────────────────────────────────── */

static void test_global_row_cap(void) {
    TEST("put: global row cap; replace at cap passes; expired frees");
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
    /* 100001 rows now (rc5); expiring two filler rows leaves 99999 live */
    int ok2 = sql_exec(&st, "UPDATE nodus_values SET expires_at = 1 WHERE value_id <= 2 "
                            "AND key_hash = zeroblob(64)") == 0 &&
              sqlite3_changes(st.db) == 2;
    int rc6 = put_and_free(nodus_storage_put, &st, make_val(&id_a, 2, 10, 0x06, 5));
    if (rc1 == 0 && ok && rc2 == NODUS_STORAGE_RC_QUOTA && rc3 == 0 && rc4 == 0 &&
        rc5 == 0 && ok2 && rc6 == 0)
        PASS();
    else
        FAIL("global row cap growth-only");
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
    TEST("owner quota queries SEARCH idx_nodus_values_owner");
    nodus_storage_t st;
    test_storage_open(&st);
    /* sqlite 3.44: "SEARCH nodus_values USING INDEX idx_nodus_values_owner
     * (owner_fp=?)" for the usage query, "... USING COVERING INDEX ..." for
     * the count — both a SEARCH on the owner index, never a SCAN. */
    const char *want = "idx_nodus_values_owner (owner_fp=?)";
    if (plan_contains(&st, st.stmt_quota_owner_usage, "SEARCH nodus_values") &&
        plan_contains(&st, st.stmt_quota_owner_usage, want) &&
        plan_contains(&st, st.stmt_quota_owner_count, "SEARCH nodus_values") &&
        plan_contains(&st, st.stmt_quota_owner_count, want))
        PASS();
    else
        FAIL("owner quota query must use the owner_fp index");
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
    test_expired_not_counted();
    test_replace_expired_is_new_row();
    test_global_row_cap();
    test_global_byte_cap();
    test_owner_index_plan();

    free(g_buf);
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
