/**
 * Nodus — client side of DHT Package A: nodus_client_get_owner,
 * nodus_client_get_all_page and nodus_client_get_batch_ex reply handling.
 *
 * What it proves (would be false if it failed):
 *   1. A get_all reply WITHOUT "more" (a node that predates paging) is NOT
 *      reported as complete: legacy = true, more = false, cursor zeroed,
 *      the rows it sent are returned (rev 2 item 18).
 *   2. A legacy reply with no row left after filtering (empty, or only rows
 *      the client drops) is NODUS_ERR_UNAVAILABLE with every output empty —
 *      never an empty success. A paging node's empty page (more = false
 *      present) stays rc 0, legacy = false.
 *   3. Rows at or before the request cursor are dropped (a node that
 *      predates paging ignores "after" and resends page 1). The order is
 *      the storage PK order with value_id SIGNED: a row with value_id
 *      2^63 (= INT64_MIN) sorts BEFORE value_id 1 and is dropped.
 *   4. With an owner filter, rows of other owners are dropped (a node that
 *      predates "own" ignores it); rows of another key are always dropped.
 *   5. With more = true, rows past "next" are dropped and next is returned
 *      as the cursor. Refused as NODUS_ERR_PROTOCOL_ERROR: more without
 *      "next"; "next" without more = true (absent or false); a next equal
 *      to or BEFORE the request cursor (lower owner; same owner with a
 *      signed-lower value_id); "more" not a bool; a "next" without "v".
 *   6. Error replies NODUS_ERR_UNAVAILABLE (21) and NODUS_ERR_STALE (20)
 *      come back as those codes — never collapsed to not-found / empty. An
 *      error reply whose code is 0, absent, or a uint past INT_MAX is
 *      NODUS_ERR_PROTOCOL_ERROR in all three handlers (rev 2 item 19) and
 *      in the strict getters nodus_client_get_strict / get_all_strict
 *      (rev 3 R-h) — never 0 with no value. The lenient getters
 *      (nodus_client_get / get_all, frozen app) still return the decoded
 *      code unchanged.
 *   7. get_owner: the owner's row is returned; no row = NOT_FOUND; a row of
 *      another owner = NODUS_ERR_UNAVAILABLE (not absent); a row of another
 *      key = NODUS_ERR_PROTOCOL_ERROR; UNAVAILABLE surfaced.
 *   8. get_batch_ex: the per-entry "u": true marker comes back in
 *      unavail_out at the entry's position; unmarked and legacy entries are
 *      false; writes stay inside key_count; a reply with more entries than
 *      asked is NODUS_ERR_PROTOCOL_ERROR with no results (it would index
 *      past the caller array) (rev 2 item 20); rev 3 R-h: so is a reply
 *      with FEWER entries than asked, or with an entry whose key is not the
 *      key asked at that position.
 *   9. get_all_page_strict (the Nodus Connect reader): rows of another
 *      owner and of another key are RETURNED (the caller counts them), not
 *      dropped; a "vals" item that does not decode is counted in
 *      undecodable; rows outside the page bounds (at or before "after",
 *      past "next") are dropped AND counted in undecodable; a legacy empty
 *      reply is rc 0 / count 0 / legacy true (the caller decides — Connect
 *      reads it as unreadable); an error 21 comes back as 21; the
 *      protocol checks on more / next are the non-strict handler's.
 *
 * Seam: the reply handlers are static in nodus_client.c. This target
 * compiles nodus_client.c itself with NODUS_CLIENT_TEST_SEAM=1, which adds
 * nodus_client_test_owner_reply / nodus_client_test_page_reply /
 * nodus_client_test_page_reply_strict / nodus_client_test_batch_reply / nodus_client_test_get_error_rc (they run
 * nodus_t2_decode + the same handler the request functions run, and bypass
 * nothing); libnodus is
 * static, so its own nodus_client.o is never pulled — see
 * nodus/CMakeLists.txt (test_client_dup_array uses the same seam).
 * Reply frames are built with the node's own encoders (nodus_t2_result_*,
 * nodus_t2_error), or by hand with the raw CBOR encoder where the case is
 * one no encoder produces.
 *
 * Requires: a default standalone nodus build; no environment.
 * Leaves behind: nothing (in-process, no sockets, no files).
 * How it can lie: only the reply handling is exercised, not the request
 * frame (pinned by test_tier2_owner_page.c) nor the send / wait path
 * (shared with nodus_client_get_all / get_batch). Values are unsigned test
 * rows; the client does not verify signatures, so nothing here depends on
 * that. The hand-built error frames are first checked to decode as 'e' with
 * error_code 0 / negative, so a PROTOCOL_ERROR there is the guard's, not a
 * decode refusal's.
 */

#include "nodus/nodus.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"
#include "crypto/nodus_identity.h"
#include "crypto/utils/qgp_log.h"

#include <stdint.h>
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
                                 nodus_dht_page_cursor_t *cursor_out,
                                 bool *legacy_out);
int nodus_client_test_page_reply_strict(const uint8_t *raw, size_t raw_len,
                                        const nodus_key_t *key,
                                        const nodus_key_t *owner_fp,
                                        const nodus_dht_page_cursor_t *after,
                                        nodus_value_t ***vals_out,
                                        size_t *count_out, bool *more_out,
                                        nodus_dht_page_cursor_t *cursor_out,
                                        bool *legacy_out,
                                        size_t *undecodable_out);
int nodus_client_test_batch_reply(const uint8_t *raw, size_t raw_len,
                                  const nodus_key_t *keys, int key_count,
                                  nodus_batch_result_t **results_out,
                                  int *result_count_out, bool *unavail_out);
int nodus_client_test_get_error_rc(const uint8_t *raw, size_t raw_len,
                                   bool strict, int *rc_out);

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

/* Run the page handler on g_frame; outputs pre-poisoned so a handler that
 * forgets to write one is caught. */
typedef struct {
    nodus_value_t **vals;
    size_t n;
    bool more;
    bool legacy;
    nodus_dht_page_cursor_t cur;
    int rc;
} page_out_t;

static void run_page(const nodus_key_t *own, const nodus_dht_page_cursor_t *after,
                     page_out_t *o) {
    o->vals = (nodus_value_t **)(uintptr_t)1;
    o->n = 99;
    o->more = true;
    o->legacy = true;
    memset(&o->cur, 0xEE, sizeof(o->cur));
    o->rc = nodus_client_test_page_reply(g_frame, g_len, &key_k, own, after,
                                         &o->vals, &o->n, &o->more, &o->cur,
                                         &o->legacy);
}

static bool page_empty(const page_out_t *o) {
    nodus_dht_page_cursor_t zero;
    memset(&zero, 0, sizeof(zero));
    return o->vals == NULL && o->n == 0 && !o->more && !o->legacy &&
           memcmp(&o->cur, &zero, sizeof(zero)) == 0;
}

/* ── get_all_page: legacy replies ──────────────────────────────────── */

static void test_no_more_is_legacy(void) {
    nodus_value_t *rows[2] = { mk_row(&key_k, &own_lo, 1), mk_row(&key_k, &own_hi, 2) };
    CHECK(rows[0] && rows[1], "legacy: rows");
    /* Legacy get_all reply: "vals" only. */
    CHECK(nodus_t2_result_multi(5, rows, 2, g_frame, sizeof(g_frame), &g_len) == 0,
          "legacy: encode");
    free_rows(rows, 2);

    page_out_t o;
    run_page(NULL, NULL, &o);
    nodus_dht_page_cursor_t zero;
    memset(&zero, 0, sizeof(zero));
    CHECK(o.rc == 0, "legacy: rc");
    CHECK(o.n == 2 && o.vals != NULL, "legacy: both rows");
    CHECK(o.legacy == true, "legacy: flagged, completeness unknown");
    CHECK(o.more == false, "legacy: more = false");
    CHECK(memcmp(&o.cur, &zero, sizeof(o.cur)) == 0, "legacy: cursor zeroed");
    free_out(o.vals, o.n);
}

static void test_legacy_empty_is_unavailable(void) {
    page_out_t o;

    /* "vals": [] and no "more". */
    CHECK(nodus_t2_result_multi(20, NULL, 0, g_frame, sizeof(g_frame), &g_len) == 0,
          "legacy-empty: encode");
    run_page(NULL, NULL, &o);
    CHECK(o.rc == NODUS_ERR_UNAVAILABLE, "legacy-empty: UNAVAILABLE, not empty");
    CHECK(page_empty(&o), "legacy-empty: outputs empty");

    /* A get reply with no "vals" at all. */
    CHECK(nodus_t2_result_empty(21, g_frame, sizeof(g_frame), &g_len) == 0,
          "legacy-novals: encode");
    run_page(NULL, NULL, &o);
    CHECK(o.rc == NODUS_ERR_UNAVAILABLE, "legacy-novals: UNAVAILABLE");
    CHECK(page_empty(&o), "legacy-novals: outputs empty");

    /* Only rows the owner filter drops. */
    nodus_value_t *rows[2] = { mk_row(&key_k, &own_lo, 1), mk_row(&key_k, &own_hi, 2) };
    CHECK(rows[0] && rows[1], "legacy-foreign: rows");
    CHECK(nodus_t2_result_multi(22, rows, 2, g_frame, sizeof(g_frame), &g_len) == 0,
          "legacy-foreign: encode");
    free_rows(rows, 2);
    run_page(&own_a, NULL, &o);
    CHECK(o.rc == NODUS_ERR_UNAVAILABLE, "legacy-foreign: UNAVAILABLE");
    CHECK(page_empty(&o), "legacy-foreign: outputs empty");

    /* Only rows at or before the cursor (old node resent page 1). */
    rows[0] = mk_row(&key_k, &own_lo, 1);
    rows[1] = mk_row(&key_k, &own_hi, 2);
    CHECK(rows[0] && rows[1], "legacy-behind: rows");
    CHECK(nodus_t2_result_multi(23, rows, 2, g_frame, sizeof(g_frame), &g_len) == 0,
          "legacy-behind: encode");
    free_rows(rows, 2);
    nodus_dht_page_cursor_t after = { .owner_fp = own_hi, .value_id = 2 };
    run_page(NULL, &after, &o);
    CHECK(o.rc == NODUS_ERR_UNAVAILABLE, "legacy-behind: UNAVAILABLE");
    CHECK(page_empty(&o), "legacy-behind: outputs empty");

    /* A PAGING node's empty last page ("more": false present) is empty. */
    nodus_t2_page_info_t pg;
    memset(&pg, 0, sizeof(pg));
    CHECK(nodus_t2_result_page(24, NULL, 0, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "paged-empty: encode");
    run_page(NULL, NULL, &o);
    CHECK(o.rc == 0, "paged-empty: rc 0");
    CHECK(o.vals == NULL && o.n == 0 && !o.more && !o.legacy,
          "paged-empty: empty, not legacy");
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
    page_out_t o;
    run_page(NULL, &after, &o);
    CHECK(o.rc == 0, "cursor: rc");
    CHECK(o.n == 2, "cursor: two rows kept");
    if (o.n == 2) {
        CHECK(o.vals[0]->value_id == 6 && o.vals[1]->value_id == 100,
              "cursor: kept rows are the ones past the cursor");
    }
    CHECK(o.more == false && o.legacy == true,
          "cursor: old node reply is legacy, not complete");
    free_out(o.vals, o.n);
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

    page_out_t o;
    run_page(&own_a, NULL, &o);
    CHECK(o.rc == 0, "own: rc");
    CHECK(o.n == 1 && o.vals && o.vals[0]->value_id == 2 &&
          nodus_key_cmp(&o.vals[0]->owner_fp, &own_a) == 0,
          "own: only the asked owner's row of the asked key");
    CHECK(o.legacy == true, "own: legacy flagged");
    free_out(o.vals, o.n);

    /* Without an owner filter a row of another key is still dropped. */
    rows[0] = mk_row(&key_other, &own_a, 1);
    rows[1] = mk_row(&key_k, &own_a, 2);
    CHECK(rows[0] && rows[1], "key: rows");
    CHECK(nodus_t2_result_multi(8, rows, 2, g_frame, sizeof(g_frame), &g_len) == 0,
          "key: encode");
    free_rows(rows, 2);
    run_page(NULL, NULL, &o);
    CHECK(o.rc == 0 && o.n == 1 && o.vals && o.vals[0]->value_id == 2,
          "key: row of another key dropped");
    free_out(o.vals, o.n);
}

/* ── get_all_page: paging node replies ─────────────────────────────── */

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

    page_out_t o;
    run_page(NULL, NULL, &o);
    CHECK(o.rc == 0, "more: rc");
    CHECK(o.more == true && o.legacy == false, "more: more = true, not legacy");
    CHECK(nodus_key_cmp(&o.cur.owner_fp, &own_hi) == 0 && o.cur.value_id == 3,
          "more: cursor = next");
    CHECK(o.n == 2, "more: row past next dropped");
    free_out(o.vals, o.n);

    /* more = false reply ("more" present): complete, cursor zeroed. */
    pg.more = false;
    pg.has_next = false;
    CHECK(nodus_t2_result_page(10, rows, 3, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "last: encode");
    run_page(NULL, NULL, &o);
    CHECK(o.rc == 0 && o.more == false && o.legacy == false && o.n == 3,
          "last: more = false, not legacy, all rows");
    free_out(o.vals, o.n);

    /* A next equal to the request cursor does not advance. */
    pg.more = true;
    pg.has_next = true;
    pg.next.owner = own_hi;
    pg.next.vid = 3;
    CHECK(nodus_t2_result_page(11, rows, 0, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "stuck: encode");
    nodus_dht_page_cursor_t after = { .owner_fp = own_hi, .value_id = 3 };
    run_page(NULL, &after, &o);
    CHECK(o.rc == NODUS_ERR_PROTOCOL_ERROR, "stuck: non-advancing next refused");
    CHECK(page_empty(&o), "stuck: outputs empty");

    /* A next BEFORE the request cursor: lower owner. */
    pg.next.owner = own_lo;
    pg.next.vid = 1000;
    CHECK(nodus_t2_result_page(25, rows, 0, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "back-owner: encode");
    run_page(NULL, &after, &o);
    CHECK(o.rc == NODUS_ERR_PROTOCOL_ERROR, "back-owner: next < after refused");
    CHECK(page_empty(&o), "back-owner: outputs empty");

    /* A next BEFORE the request cursor: same owner, value_id 2^63 is
     * INT64_MIN in the signed PK order, below 3. */
    pg.next.owner = own_hi;
    pg.next.vid = 0x8000000000000000ULL;
    CHECK(nodus_t2_result_page(26, rows, 0, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "back-vid: encode");
    run_page(NULL, &after, &o);
    CHECK(o.rc == NODUS_ERR_PROTOCOL_ERROR, "back-vid: signed-lower next refused");
    CHECK(page_empty(&o), "back-vid: outputs empty");
    free_rows(rows, 3);
}

/* {t, y:"r", q:"result", r:{vals:[], <extra keys>}} built by hand: the cases
 * no node encoder produces. kind selects the extra "r" keys. */
enum {
    R_MORE_NO_NEXT,     /* more: true                      */
    R_NEXT_NO_MORE,     /* next: {o, v}                    */
    R_NEXT_MORE_FALSE,  /* more: false, next: {o, v}       */
    R_MORE_UINT,        /* more: 1                         */
    R_NEXT_NO_V,        /* more: true, next: {o}           */
};

static void build_r(uint32_t txn, int kind) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, g_frame, sizeof(g_frame));
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, txn);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "result");
    cbor_encode_cstr(&e, "r");
    size_t n = (kind == R_MORE_NO_NEXT || kind == R_NEXT_NO_MORE ||
                kind == R_MORE_UINT) ? 2 : 3;
    cbor_encode_map(&e, n);
    cbor_encode_cstr(&e, "vals"); cbor_encode_array(&e, 0);
    switch (kind) {
    case R_MORE_NO_NEXT:
        cbor_encode_cstr(&e, "more"); cbor_encode_bool(&e, true);
        break;
    case R_NEXT_NO_MORE:
        cbor_encode_cstr(&e, "next");
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "o"); cbor_encode_bstr(&e, own_hi.bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&e, "v"); cbor_encode_uint(&e, 7);
        break;
    case R_NEXT_MORE_FALSE:
        cbor_encode_cstr(&e, "more"); cbor_encode_bool(&e, false);
        cbor_encode_cstr(&e, "next");
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "o"); cbor_encode_bstr(&e, own_hi.bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&e, "v"); cbor_encode_uint(&e, 7);
        break;
    case R_MORE_UINT:
        cbor_encode_cstr(&e, "more"); cbor_encode_uint(&e, 1);
        break;
    default: /* R_NEXT_NO_V */
        cbor_encode_cstr(&e, "more"); cbor_encode_bool(&e, true);
        cbor_encode_cstr(&e, "next");
        cbor_encode_map(&e, 1);
        cbor_encode_cstr(&e, "o"); cbor_encode_bstr(&e, own_hi.bytes, NODUS_KEY_BYTES);
        break;
    }
    g_len = cbor_encoder_len(&e);
}

static void test_malformed_more_next(void) {
    static const struct { int kind; const char *name; } cases[] = {
        { R_MORE_NO_NEXT,    "more-no-next: protocol error" },
        { R_NEXT_NO_MORE,    "next-no-more: protocol error" },
        { R_NEXT_MORE_FALSE, "next-more-false: protocol error" },
        { R_MORE_UINT,       "more-uint: protocol error" },
        { R_NEXT_NO_V,       "next-no-v: protocol error" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        build_r((uint32_t)(30 + i), cases[i].kind);
        page_out_t o;
        run_page(NULL, NULL, &o);
        CHECK(o.rc == NODUS_ERR_PROTOCOL_ERROR, cases[i].name);
        CHECK(page_empty(&o), cases[i].name);
    }
}

/* ── get_all_page_strict ───────────────────────────────────────────── */

typedef struct {
    page_out_t p;
    size_t     und;
} strict_out_t;

static void run_page_strict(const nodus_key_t *own,
                            const nodus_dht_page_cursor_t *after,
                            strict_out_t *o) {
    o->p.vals = (nodus_value_t **)(uintptr_t)1;
    o->p.n = 99;
    o->p.more = true;
    o->p.legacy = true;
    memset(&o->p.cur, 0xEE, sizeof(o->p.cur));
    o->und = 99;
    o->p.rc = nodus_client_test_page_reply_strict(g_frame, g_len, &key_k, own,
                                                  after, &o->p.vals, &o->p.n,
                                                  &o->p.more, &o->p.cur,
                                                  &o->p.legacy, &o->und);
}

static void test_page_strict(void) {
    strict_out_t o;
    nodus_t2_page_info_t pg;
    memset(&pg, 0, sizeof(pg));

    /* Paging node, more = false, owner filter own_a: the rows of another
     * owner and of another key come back to the caller. */
    nodus_value_t *rows[4] = {
        mk_row(&key_k, &own_lo, 1),       /* other owner -> returned */
        mk_row(&key_k, &own_a, 2),        /* asked owner -> returned */
        mk_row(&key_other, &own_a, 3),    /* other key   -> returned */
        mk_row(&key_k, &own_hi, 4),       /* other owner -> returned */
    };
    CHECK(rows[0] && rows[1] && rows[2] && rows[3], "strict-keep: rows");
    CHECK(nodus_t2_result_page(60, rows, 4, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "strict-keep: encode");
    free_rows(rows, 4);
    run_page_strict(&own_a, NULL, &o);
    CHECK(o.p.rc == 0 && o.p.n == 4 && o.p.vals && o.und == 0 &&
          !o.p.more && !o.p.legacy,
          "strict-keep: foreign-owner and other-key rows returned, not dropped");
    if (o.p.rc == 0 && o.p.n == 4) {
        CHECK(o.p.vals[0]->value_id == 1 && o.p.vals[1]->value_id == 2 &&
              o.p.vals[2]->value_id == 3 && o.p.vals[3]->value_id == 4,
              "strict-keep: reply order kept");
        CHECK(nodus_key_cmp(&o.p.vals[2]->key_hash, &key_other) == 0,
              "strict-keep: the other-key row is the caller's to count");
    }
    free_out(o.p.vals, o.p.n);

    /* A "vals" item that does not decode, next to a good row: counted. */
    {
        nodus_value_t *row = mk_row(&key_k, &own_a, 5);
        uint8_t *vb = NULL;
        size_t vl = 0;
        CHECK(row && nodus_value_serialize(row, &vb, &vl) == 0, "strict-junk: row");
        nodus_value_free(row);
        static const uint8_t junk[3] = { 1, 2, 3 };
        cbor_encoder_t e;
        cbor_encoder_init(&e, g_frame, sizeof(g_frame));
        cbor_encode_map(&e, 4);
        cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 61);
        cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
        cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "result");
        cbor_encode_cstr(&e, "r");
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "vals");
        cbor_encode_array(&e, 2);
        cbor_encode_bstr(&e, junk, sizeof(junk));
        if (vb) cbor_encode_bstr(&e, vb, vl);
        else cbor_encode_bstr(&e, junk, sizeof(junk));
        cbor_encode_cstr(&e, "more"); cbor_encode_bool(&e, false);
        g_len = cbor_encoder_len(&e);
        free(vb);
        run_page_strict(&own_a, NULL, &o);
        CHECK(o.p.rc == 0 && o.p.n == 1 && o.und == 1 && !o.p.legacy,
              "strict-junk: the good row returned, the undecodable item counted");
        free_out(o.p.vals, o.p.n);
    }

    /* Page bounds: after = (own_hi, 5), more = true, next = (own_hi, 7).
     *   (own_lo, 9)   before the cursor owner  -> dropped, counted
     *   (own_hi, 6)   inside the page          -> returned
     *   (own_hi, 9)   past next                -> dropped, counted */
    nodus_value_t *b[3] = {
        mk_row(&key_k, &own_lo, 9),
        mk_row(&key_k, &own_hi, 6),
        mk_row(&key_k, &own_hi, 9),
    };
    CHECK(b[0] && b[1] && b[2], "strict-bounds: rows");
    pg.more = true;
    pg.has_next = true;
    pg.next.owner = own_hi;
    pg.next.vid = 7;
    CHECK(nodus_t2_result_page(62, b, 3, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "strict-bounds: encode");
    free_rows(b, 3);
    nodus_dht_page_cursor_t after = { .owner_fp = own_hi, .value_id = 5 };
    run_page_strict(NULL, &after, &o);
    CHECK(o.p.rc == 0 && o.p.n == 1 && o.p.vals && o.p.vals[0]->value_id == 6 &&
          o.und == 2,
          "strict-bounds: rows outside the page dropped and counted as undecodable");
    CHECK(o.p.more && nodus_key_cmp(&o.p.cur.owner_fp, &own_hi) == 0 &&
          o.p.cur.value_id == 7, "strict-bounds: more and cursor = next");
    free_out(o.p.vals, o.p.n);

    /* The non-strict protocol checks hold: a next that does not advance. */
    pg.next.vid = 5;
    CHECK(nodus_t2_result_page(63, NULL, 0, &pg, g_frame, sizeof(g_frame), &g_len) == 0,
          "strict-stuck: encode");
    run_page_strict(NULL, &after, &o);
    CHECK(o.p.rc == NODUS_ERR_PROTOCOL_ERROR && page_empty(&o.p) && o.und == 0,
          "strict-stuck: non-advancing next refused");

    /* Legacy empty reply: rc 0, count 0, legacy true — not UNAVAILABLE. */
    CHECK(nodus_t2_result_multi(64, NULL, 0, g_frame, sizeof(g_frame), &g_len) == 0,
          "strict-legacy: encode");
    run_page_strict(&own_a, NULL, &o);
    CHECK(o.p.rc == 0 && o.p.n == 0 && o.p.vals == NULL && o.p.legacy &&
          !o.p.more && o.und == 0,
          "strict-legacy: empty legacy reply = rc 0, count 0, legacy (caller decides)");

    /* Error 21 surfaced. */
    CHECK(nodus_t2_error(65, NODUS_ERR_UNAVAILABLE, "unavailable",
                         g_frame, sizeof(g_frame), &g_len) == 0, "strict-err21: encode");
    run_page_strict(&own_a, NULL, &o);
    CHECK(o.p.rc == NODUS_ERR_UNAVAILABLE && page_empty(&o.p) && o.und == 0,
          "strict-err21: UNAVAILABLE surfaced");
}

/* ── error replies ─────────────────────────────────────────────────── */

/* {t, y:"e", r:{msg:"x"}} — an error frame with no "code". With
 * code_kind 1: r:{code: 0xFFFFFFFF, msg} (a uint past INT_MAX). */
static void build_error_frame(uint32_t txn, int code_kind) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, g_frame, sizeof(g_frame));
    cbor_encode_map(&e, 3);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, txn);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "e");
    cbor_encode_cstr(&e, "r");
    if (code_kind == 1) {
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "code"); cbor_encode_uint(&e, 0xFFFFFFFFULL);
    } else {
        cbor_encode_map(&e, 1);
    }
    cbor_encode_cstr(&e, "msg"); cbor_encode_cstr(&e, "x");
    g_len = cbor_encoder_len(&e);
}

/* The three Package A handlers and the strict getters (rev 3 R-h) on the
 * current g_frame must all answer `want`. */
static void check_all_handlers(int want, const char *name) {
    page_out_t o;
    run_page(NULL, NULL, &o);
    CHECK(o.rc == want, name);
    CHECK(page_empty(&o), name);

    nodus_value_t *v = (nodus_value_t *)(uintptr_t)1;
    int rc = nodus_client_test_owner_reply(g_frame, g_len, &key_k, &own_a, &v);
    CHECK(rc == want && v == NULL, name);

    nodus_batch_result_t *res = (nodus_batch_result_t *)(uintptr_t)1;
    int rn = 7;
    bool u[2] = { true, true };
    nodus_key_t bkeys[2] = { key_k, key_other };
    rc = nodus_client_test_batch_reply(g_frame, g_len, bkeys, 2, &res, &rn, u);
    CHECK(rc == want && res == NULL && rn == 0 && !u[0] && !u[1], name);

    /* Rev 3 R-h: nodus_client_get_strict / get_all_strict use the same
     * rule. FAILS WITHOUT R-h for a code-less frame: the strict getters
     * returned the decoded code (0 = "success" with no value). */
    rc = -12345;
    CHECK(nodus_client_test_get_error_rc(g_frame, g_len, true, &rc) == 0 && rc == want,
          name);
}

/* The lenient getters (nodus_client_get / get_all — the frozen app) keep
 * returning the decoded code unchanged. */
static void check_lenient_unchanged(int decoded_code, const char *name) {
    int rc = -12345;
    CHECK(nodus_client_test_get_error_rc(g_frame, g_len, false, &rc) == 0 &&
          rc == decoded_code, name);
}

static void test_error_codes_surfaced(void) {
    CHECK(nodus_t2_error(13, NODUS_ERR_UNAVAILABLE, "unavailable",
                         g_frame, sizeof(g_frame), &g_len) == 0, "err21: encode");
    check_all_handlers(NODUS_ERR_UNAVAILABLE, "UNAVAILABLE surfaced");

    CHECK(nodus_t2_error(14, NODUS_ERR_STALE, "stale",
                         g_frame, sizeof(g_frame), &g_len) == 0, "err20: encode");
    check_all_handlers(NODUS_ERR_STALE, "STALE surfaced");
}

static void test_error_without_valid_code(void) {
    nodus_tier2_msg_t m;

    /* code 0 — the node's own encoder. */
    CHECK(nodus_t2_error(40, 0, "zero", g_frame, sizeof(g_frame), &g_len) == 0,
          "code0: encode");
    memset(&m, 0, sizeof(m));
    CHECK(nodus_t2_decode(g_frame, g_len, &m) == 0 && m.type == 'e' &&
          m.error_code == 0, "code0: decodes as 'e' with code 0");
    nodus_t2_msg_free(&m);
    check_all_handlers(NODUS_ERR_PROTOCOL_ERROR, "code0: protocol error, not 0");
    check_lenient_unchanged(0, "code0: lenient getter unchanged");

    /* code absent. */
    build_error_frame(41, 0);
    memset(&m, 0, sizeof(m));
    CHECK(nodus_t2_decode(g_frame, g_len, &m) == 0 && m.type == 'e' &&
          m.error_code == 0, "nocode: decodes as 'e' with code 0");
    nodus_t2_msg_free(&m);
    check_all_handlers(NODUS_ERR_PROTOCOL_ERROR, "nocode: protocol error, not 0");
    check_lenient_unchanged(0, "nocode: lenient getter unchanged");

    /* code past INT_MAX lands negative in the decoder's int. */
    build_error_frame(42, 1);
    memset(&m, 0, sizeof(m));
    CHECK(nodus_t2_decode(g_frame, g_len, &m) == 0 && m.type == 'e' &&
          m.error_code <= 0, "bigcode: decodes as 'e' with code <= 0");
    {
        int decoded = m.error_code;
        nodus_t2_msg_free(&m);
        check_all_handlers(NODUS_ERR_PROTOCOL_ERROR, "bigcode: protocol error");
        check_lenient_unchanged(decoded, "bigcode: lenient getter unchanged");
    }
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

/* ── get_batch_ex ──────────────────────────────────────────────────── */

static void test_get_batch_ex_unavail(void) {
    nodus_key_t keys[3];
    fill_key(&keys[0], 0x61);
    fill_key(&keys[1], 0x62);
    fill_key(&keys[2], 0x63);
    nodus_value_t *v = mk_row(&keys[1], &own_a, 3);
    CHECK(v != NULL, "batch: row");
    nodus_value_t *row[1] = { v };
    nodus_value_t **vpk[2] = { NULL, row };
    size_t cnt[2] = { 0, 1 };

    /* Entry 0 marked "u": true, entry 1 carries a row; 2 keys asked. */
    bool u_wire[2] = { true, false };
    CHECK(nodus_t2_result_get_batch_ex(50, keys, 2, vpk, cnt, NULL, u_wire,
                                        g_frame, sizeof(g_frame), &g_len) == 0,
          "batch-u: encode");
    nodus_batch_result_t *res = NULL;
    int rn = 0;
    bool u[3] = { true, true, true };
    int rc = nodus_client_test_batch_reply(g_frame, g_len, keys, 2, &res, &rn, u);
    CHECK(rc == 0 && res != NULL && rn == 2, "batch-u: two results");
    CHECK(u[0] == true, "batch-u: entry 0 marked could-not-look");
    CHECK(u[1] == false, "batch-u: entry 1 not marked");
    CHECK(u[2] == true, "batch-u: writes stay inside key_count");
    if (res && rn == 2) {
        CHECK(nodus_key_cmp(&res[0].key, &keys[0]) == 0 && res[0].count == 0,
              "batch-u: entry 0 empty");
        CHECK(nodus_key_cmp(&res[1].key, &keys[1]) == 0 && res[1].count == 1 &&
              res[1].vals && res[1].vals[0]->value_id == 3,
              "batch-u: entry 1 row handed out");
    }
    nodus_client_free_batch_result(res, rn);

    /* Rev 3 R-h: 3 keys asked, 2 entries answered — the missing entry
     * cannot be told from "no values": refused, outputs zeroed.
     * FAILS WITHOUT R-h: rc 0 with two results (the old rule refused only
     * MORE entries than asked). */
    res = (nodus_batch_result_t *)(uintptr_t)1; rn = 7;
    u[0] = u[1] = u[2] = true;
    rc = nodus_client_test_batch_reply(g_frame, g_len, keys, 3, &res, &rn, u);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "batch-under: fewer entries than asked refused");
    CHECK(res == NULL && rn == 0 && !u[0] && !u[1] && !u[2], "batch-under: outputs empty");

    /* A legacy batch reply (no "u"): nothing marked. */
    CHECK(nodus_t2_result_get_batch(51, keys, 2, vpk, cnt,
                                     g_frame, sizeof(g_frame), &g_len) == 0,
          "batch-legacy: encode");
    res = NULL; rn = 0;
    u[0] = u[1] = u[2] = true;
    rc = nodus_client_test_batch_reply(g_frame, g_len, keys, 2, &res, &rn, u);
    CHECK(rc == 0 && rn == 2 && !u[0] && !u[1], "batch-legacy: nothing marked");
    CHECK(u[2] == true, "batch-legacy: writes stay inside key_count");
    nodus_client_free_batch_result(res, rn);

    /* Rev 3 R-h: entries for the asked keys in the WRONG positions —
     * refused. FAILS WITHOUT R-h: rc 0, results[0].key != keys[0]. */
    {
        nodus_key_t swapped[2] = { keys[1], keys[0] };
        nodus_value_t **vps[2] = { row, NULL };
        CHECK(nodus_t2_result_get_batch(53, swapped, 2, vps, cnt,
                                         g_frame, sizeof(g_frame), &g_len) == 0,
              "batch-swap: encode");
        res = (nodus_batch_result_t *)(uintptr_t)1; rn = 7;
        u[0] = u[1] = true;
        rc = nodus_client_test_batch_reply(g_frame, g_len, keys, 2, &res, &rn, u);
        CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "batch-swap: key mismatch refused");
        CHECK(res == NULL && rn == 0 && !u[0] && !u[1], "batch-swap: outputs empty");
    }

    /* More entries than asked: refused, nothing handed out. */
    nodus_value_t **vpk3[3] = { NULL, row, NULL };
    size_t cnt3[3] = { 0, 1, 0 };
    CHECK(nodus_t2_result_get_batch(52, keys, 3, vpk3, cnt3,
                                     g_frame, sizeof(g_frame), &g_len) == 0,
          "batch-over: encode");
    res = (nodus_batch_result_t *)(uintptr_t)1; rn = 7;
    bool u2[3] = { true, true, true };
    rc = nodus_client_test_batch_reply(g_frame, g_len, keys, 2, &res, &rn, u2);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "batch-over: more entries than asked refused");
    CHECK(res == NULL && rn == 0 && !u2[0] && !u2[1], "batch-over: outputs empty");
    CHECK(u2[2] == true, "batch-over: writes stay inside key_count");

    nodus_value_free(v);
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

    test_no_more_is_legacy();
    test_legacy_empty_is_unavailable();
    test_rows_at_or_before_cursor_dropped();
    test_foreign_owner_and_key_dropped();
    test_more_and_next();
    test_malformed_more_next();
    test_page_strict();
    test_error_codes_surfaced();
    test_error_without_valid_code();
    test_get_owner();
    test_get_batch_ex_unavail();

    QGP_LOG_INFO(LOG_TAG, "%d passed, %d failed", passed, failed);
    return failed > 0 ? 1 : 0;
}
