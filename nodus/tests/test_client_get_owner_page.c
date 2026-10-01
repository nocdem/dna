/**
 * Nodus — client side of DHT Package A: nodus_client_get_owner and
 * nodus_client_get_all_page reply handling.
 *
 * What it proves (would be false if it failed):
 *   1. A get_all reply WITHOUT "more" (a node that predates paging) is a
 *      complete answer: more = false, cursor zeroed, rows returned.
 *   2. Rows at or before the request cursor are dropped (a node that
 *      predates paging ignores "after" and resends page 1). The order is
 *      the storage PK order with value_id SIGNED: a row with value_id
 *      2^63 (= INT64_MIN) sorts BEFORE value_id 1 and is dropped.
 *   3. With an owner filter, rows of other owners are dropped (a node that
 *      predates "own" ignores it); rows of another key are always dropped.
 *   4. With more = true, rows past "next" are dropped and next is returned
 *      as the cursor; more without "next", or a next that does not advance
 *      past the request cursor, is NODUS_ERR_PROTOCOL_ERROR.
 *   5. Error replies NODUS_ERR_UNAVAILABLE (21) and NODUS_ERR_STALE (20)
 *      come back as those codes — never collapsed to not-found / empty.
 *   6. get_owner: the owner's row is returned; no row = NOT_FOUND; a row of
 *      another owner = NODUS_ERR_UNAVAILABLE (not absent); a row of another
 *      key = NODUS_ERR_PROTOCOL_ERROR; UNAVAILABLE surfaced.
 *
 * Seam: the reply handlers are static in nodus_client.c. This target
 * compiles nodus_client.c itself with NODUS_CLIENT_TEST_SEAM=1, which adds
 * nodus_client_test_owner_reply / nodus_client_test_page_reply (they run
 * nodus_t2_decode + the same handler the request functions run, and bypass
 * nothing); libnodus is static, so its own nodus_client.o is never pulled —
 * see nodus/CMakeLists.txt (test_client_dup_array uses the same seam).
 * Reply frames are built with the node's own encoders (nodus_t2_result_*,
 * nodus_t2_error).
 *
 * Requires: a default standalone nodus build; no environment.
 * Leaves behind: nothing (in-process, no sockets, no files).
 * How it can lie: only the reply handling is exercised, not the request
 * frame (pinned by test_tier2_owner_page.c) nor the send / wait path
 * (shared with nodus_client_get_all). Values are unsigned test rows; the
 * client does not verify signatures, so nothing here depends on that.
 */

#include "nodus/nodus.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"
#include "crypto/nodus_identity.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TEST_CLIENT_OWNER_PAGE"

/* Defined in nodus_client.c under NODUS_CLIENT_TEST_SEAM. */
int nodus_client_test_owner_reply(const uint8_t *raw, size_t raw_len,
                                  const nodus_key_t *key,
                                  const nodus_key_t *owner_fp,
                                  nodus_value_t **val_out);
int nodus_client_test_page_reply(const uint8_t *raw, size_t raw_len,
                                 const nodus_key_t *key,
                                 const nodus_key_t *owner_fp,
                                 const nodus_dht_page_cursor_t *after,
                                 nodus_value_t ***vals_out, size_t *count_out,
                                 bool *more_out,
                                 nodus_dht_page_cursor_t *cursor_out);

static int passed = 0;
static int failed = 0;

#define CHECK(cond, name) do {                                          \
    if (cond) { passed++; }                                             \
    else { failed++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s (%s:%d): %s",      \
                                   (name), __FILE__, __LINE__, #cond); } \
} while (0)

static uint8_t g_frame[262144];
static size_t  g_len;

static nodus_identity_t id_a;
static nodus_key_t key_k, key_other, own_a, own_lo, own_hi;

static void fill_key(nodus_key_t *k, uint8_t b) { memset(k->bytes, b, NODUS_KEY_BYTES); }

/* A row of `key` with owner_fp forced to `owner` (the client filters on the
 * wire owner_fp; signatures are not involved). */
static nodus_value_t *mk_row(const nodus_key_t *key, const nodus_key_t *owner,
                             uint64_t vid) {
    nodus_value_t *v = NULL;
    if (nodus_value_create(key, (const uint8_t *)"d", 1, NODUS_VALUE_PERMANENT,
                           0, vid, 1, &id_a.pk, &v) != 0)
        return NULL;
    v->owner_fp = *owner;
    return v;
}

static void free_rows(nodus_value_t **rows, size_t n) {
    for (size_t i = 0; i < n; i++) nodus_value_free(rows[i]);
}

static void free_out(nodus_value_t **vals, size_t n) {
    if (!vals) return;
    free_rows(vals, n);
    free(vals);
}

/* ── get_all_page ──────────────────────────────────────────────────── */

static void test_no_more_is_complete(void) {
    nodus_value_t *rows[2] = { mk_row(&key_k, &own_lo, 1), mk_row(&key_k, &own_hi, 2) };
    CHECK(rows[0] && rows[1], "absent-more: rows");
    /* Legacy get_all reply: "vals" only. */
    CHECK(nodus_t2_result_multi(5, rows, 2, g_frame, sizeof(g_frame), &g_len) == 0,
          "absent-more: encode");
    free_rows(rows, 2);

    nodus_value_t **vals = NULL; size_t n = 0; bool more = true;
    nodus_dht_page_cursor_t cur;
    memset(&cur, 0xEE, sizeof(cur));
    int rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, NULL,
                                          &vals, &n, &more, &cur);
    nodus_dht_page_cursor_t zero;
    memset(&zero, 0, sizeof(zero));
    CHECK(rc == 0, "absent-more: rc");
    CHECK(n == 2 && vals != NULL, "absent-more: both rows");
    CHECK(more == false, "absent-more: more = false (complete)");
    CHECK(memcmp(&cur, &zero, sizeof(cur)) == 0, "absent-more: cursor zeroed");
    free_out(vals, n);
}

static void test_rows_at_or_before_cursor_dropped(void) {
    /* Cursor (own_hi, 5). Old node resends page 1 ignoring "after":
     *   (own_lo, 9)        owner below cursor owner      -> drop
     *   (own_hi, 2^63)     signed INT64_MIN < 5          -> drop
     *   (own_hi, 5)        equal to the cursor           -> drop
     *   (own_hi, 6)        after                         -> keep
     *   (own_hi, 100)      after                         -> keep */
    nodus_value_t *rows[5] = {
        mk_row(&key_k, &own_lo, 9),
        mk_row(&key_k, &own_hi, 0x8000000000000000ULL),
        mk_row(&key_k, &own_hi, 5),
        mk_row(&key_k, &own_hi, 6),
        mk_row(&key_k, &own_hi, 100),
    };
    CHECK(rows[0] && rows[1] && rows[2] && rows[3] && rows[4], "cursor: rows");
    CHECK(nodus_t2_result_multi(6, rows, 5, g_frame, sizeof(g_frame), &g_len) == 0,
          "cursor: encode");
    free_rows(rows, 5);

    nodus_dht_page_cursor_t after = { .owner_fp = own_hi, .value_id = 5 };
    nodus_value_t **vals = NULL; size_t n = 0; bool more = true;
    nodus_dht_page_cursor_t cur;
    int rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, &after,
                                          &vals, &n, &more, &cur);
    CHECK(rc == 0, "cursor: rc");
    CHECK(n == 2, "cursor: two rows kept");
    if (n == 2) {
        CHECK(vals[0]->value_id == 6 && vals[1]->value_id == 100,
              "cursor: kept rows are the ones past the cursor");
    }
    CHECK(more == false, "cursor: old node reply is complete");
    free_out(vals, n);
}

static void test_foreign_owner_and_key_dropped(void) {
    nodus_value_t *rows[4] = {
        mk_row(&key_k, &own_lo, 1),       /* other owner -> drop */
        mk_row(&key_k, &own_a, 2),        /* asked owner -> keep */
        mk_row(&key_other, &own_a, 3),    /* other key   -> drop */
        mk_row(&key_k, &own_hi, 4),       /* other owner -> drop */
    };
    CHECK(rows[0] && rows[1] && rows[2] && rows[3], "own: rows");
    CHECK(nodus_t2_result_multi(7, rows, 4, g_frame, sizeof(g_frame), &g_len) == 0,
          "own: encode");
    free_rows(rows, 4);

    nodus_value_t **vals = NULL; size_t n = 0; bool more = true;
    nodus_dht_page_cursor_t cur;
    int rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, &own_a, NULL,
                                          &vals, &n, &more, &cur);
    CHECK(rc == 0, "own: rc");
    CHECK(n == 1 && vals && vals[0]->value_id == 2 &&
          nodus_key_cmp(&vals[0]->owner_fp, &own_a) == 0,
          "own: only the asked owner's row of the asked key");
    free_out(vals, n);

    /* Without an owner filter a row of another key is still dropped. */
    rows[0] = mk_row(&key_other, &own_a, 1);
    rows[1] = mk_row(&key_k, &own_a, 2);
    CHECK(rows[0] && rows[1], "key: rows");
    CHECK(nodus_t2_result_multi(8, rows, 2, g_frame, sizeof(g_frame), &g_len) == 0,
          "key: encode");
    free_rows(rows, 2);
    vals = NULL; n = 0;
    rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, NULL,
                                      &vals, &n, &more, &cur);
    CHECK(rc == 0 && n == 1 && vals && vals[0]->value_id == 2,
          "key: row of another key dropped");
    free_out(vals, n);
}

static void test_more_and_next(void) {
    /* more = true, next = (own_hi, 3): the row (own_hi, 9) is past next. */
    nodus_value_t *rows[3] = {
        mk_row(&key_k, &own_lo, 1),
        mk_row(&key_k, &own_hi, 3),
        mk_row(&key_k, &own_hi, 9),
    };
    CHECK(rows[0] && rows[1] && rows[2], "more: rows");
    nodus_t2_page_info_t pg;
    memset(&pg, 0, sizeof(pg));
    pg.more = true;
    pg.has_next = true;
    pg.next.owner = own_hi;
    pg.next.vid = 3;
    CHECK(nodus_t2_result_page(9, rows, 3, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "more: encode");

    nodus_value_t **vals = NULL; size_t n = 0; bool more = false;
    nodus_dht_page_cursor_t cur;
    int rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, NULL,
                                          &vals, &n, &more, &cur);
    CHECK(rc == 0, "more: rc");
    CHECK(more == true, "more: more = true");
    CHECK(nodus_key_cmp(&cur.owner_fp, &own_hi) == 0 && cur.value_id == 3,
          "more: cursor = next");
    CHECK(n == 2, "more: row past next dropped");
    free_out(vals, n);

    /* more = false reply ("more" present): complete, cursor zeroed. */
    pg.more = false;
    pg.has_next = false;
    CHECK(nodus_t2_result_page(10, rows, 3, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "last: encode");
    vals = NULL; n = 0; more = true;
    rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, NULL,
                                      &vals, &n, &more, &cur);
    CHECK(rc == 0 && more == false && n == 3, "last: more = false, all rows");
    free_out(vals, n);

    /* A next that does not advance past the request cursor. */
    pg.more = true;
    pg.has_next = true;
    pg.next.owner = own_hi;
    pg.next.vid = 3;
    CHECK(nodus_t2_result_page(11, rows, 0, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "stuck: encode");
    nodus_dht_page_cursor_t after = { .owner_fp = own_hi, .value_id = 3 };
    vals = NULL; n = 0; more = false;
    rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, &after,
                                      &vals, &n, &more, &cur);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "stuck: non-advancing next refused");
    CHECK(vals == NULL && n == 0 && more == false, "stuck: outputs empty");
    free_rows(rows, 3);
}

/* {t, y:"r", q:"result", r:{vals:[], more:true}} — more without next. */
static void test_more_without_next(void) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, g_frame, sizeof(g_frame));
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 12);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "result");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "vals"); cbor_encode_array(&e, 0);
    cbor_encode_cstr(&e, "more"); cbor_encode_bool(&e, true);
    g_len = cbor_encoder_len(&e);

    nodus_value_t **vals = NULL; size_t n = 0; bool more = false;
    nodus_dht_page_cursor_t cur;
    int rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, NULL,
                                          &vals, &n, &more, &cur);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "more-no-next: protocol error");
}

static void test_error_codes_surfaced(void) {
    nodus_value_t **vals = NULL; size_t n = 0; bool more = false;
    nodus_dht_page_cursor_t cur;

    CHECK(nodus_t2_error(13, NODUS_ERR_UNAVAILABLE, "unavailable",
                         g_frame, sizeof(g_frame), &g_len) == 0, "err21: encode");
    int rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, NULL,
                                          &vals, &n, &more, &cur);
    CHECK(rc == NODUS_ERR_UNAVAILABLE, "page: UNAVAILABLE surfaced");
    CHECK(rc != NODUS_ERR_NOT_FOUND && vals == NULL && n == 0, "page: not empty-success");

    CHECK(nodus_t2_error(14, NODUS_ERR_STALE, "stale",
                         g_frame, sizeof(g_frame), &g_len) == 0, "err20: encode");
    rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, NULL, NULL,
                                      &vals, &n, &more, &cur);
    CHECK(rc == NODUS_ERR_STALE, "page: STALE surfaced");

    CHECK(nodus_t2_error(15, NODUS_ERR_UNAVAILABLE, "unavailable",
                         g_frame, sizeof(g_frame), &g_len) == 0, "err21b: encode");
    nodus_value_t *v = NULL;
    rc = nodus_client_test_owner_reply(g_frame, g_len, &key_k, &own_a, &v);
    CHECK(rc == NODUS_ERR_UNAVAILABLE && v == NULL, "owner: UNAVAILABLE surfaced");
}

/* ── get_owner ─────────────────────────────────────────────────────── */

static void test_get_owner(void) {
    nodus_value_t *v = NULL;
    int rc;

    /* The owner's row. */
    nodus_value_t *row = mk_row(&key_k, &own_a, 42);
    CHECK(row != NULL, "owner: row");
    CHECK(nodus_t2_result(16, row, g_frame, sizeof(g_frame), &g_len) == 0, "owner: encode");
    nodus_value_free(row);
    rc = nodus_client_test_owner_reply(g_frame, g_len, &key_k, &own_a, &v);
    CHECK(rc == 0 && v && v->value_id == 42, "owner: row returned");
    nodus_value_free(v); v = NULL;

    /* No row. */
    CHECK(nodus_t2_result_empty(17, g_frame, sizeof(g_frame), &g_len) == 0, "empty: encode");
    rc = nodus_client_test_owner_reply(g_frame, g_len, &key_k, &own_a, &v);
    CHECK(rc == NODUS_ERR_NOT_FOUND && v == NULL, "owner: no row = NOT_FOUND");

    /* A node that ignores "own" returns another owner's row. */
    row = mk_row(&key_k, &own_hi, 43);
    CHECK(row != NULL, "foreign: row");
    CHECK(nodus_t2_result(18, row, g_frame, sizeof(g_frame), &g_len) == 0, "foreign: encode");
    nodus_value_free(row);
    rc = nodus_client_test_owner_reply(g_frame, g_len, &key_k, &own_a, &v);
    CHECK(rc == NODUS_ERR_UNAVAILABLE && v == NULL,
          "owner: foreign-owner row = UNAVAILABLE, not absent");

    /* A row of another key. */
    row = mk_row(&key_other, &own_a, 44);
    CHECK(row != NULL, "other-key: row");
    CHECK(nodus_t2_result(19, row, g_frame, sizeof(g_frame), &g_len) == 0, "other-key: encode");
    nodus_value_free(row);
    rc = nodus_client_test_owner_reply(g_frame, g_len, &key_k, &own_a, &v);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && v == NULL, "owner: other-key row refused");
}

int main(void) {
    uint8_t seed[32];
    memset(seed, 0x3C, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_a) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "FATAL: identity");
        return 1;
    }
    fill_key(&key_k, 0x11);
    fill_key(&key_other, 0x22);
    fill_key(&own_lo, 0x10);
    fill_key(&own_a, 0x40);
    fill_key(&own_hi, 0x90);

    test_no_more_is_complete();
    test_rows_at_or_before_cursor_dropped();
    test_foreign_owner_and_key_dropped();
    test_more_and_next();
    test_more_without_next();
    test_error_codes_surfaced();
    test_get_owner();

    QGP_LOG_INFO(LOG_TAG, "%d passed, %d failed", passed, failed);
    return failed > 0 ? 1 : 0;
}
