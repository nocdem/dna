/**
 * @file shared/dht2/dht2_msg.c
 * @brief DHT v2 package 2 — wire messages. See dht2_msg.h for the design
 *        rows, the decision records and the error-code readings.
 *
 * Shape of every message: one `*_emit` (the ONE emission path: WRITE,
 * COUNT and COMPARE all run through it, as in dht2_data / dht2_list) and
 * one `*_parse` that reads the keys IN CANONICAL ORDER by matching them
 * against the expected literals — an unknown, missing, repeated or
 * unsorted key fails the match (and dht2_cbor_rd_key refuses unsorted /
 * duplicate keys on its own). A decode is: parse, require every byte
 * consumed, re-emit in COMPARE mode against the input.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dht2/dht2_msg.h"
#include "dht2/dht2_cbor.h"

#include <string.h>

/* ══ shared plumbing ═══════════════════════════════════════════════════ */

/* A map being read key by key, in canonical order. `left` is the number of
 * keys the head promised; a key read but not yet matched is `pend`. */
typedef struct {
    dht2_cbor_rd_t *r;
    uint64_t        left;
    const uint8_t  *prev;
    size_t          prev_len;
    bool            pend;
    const uint8_t  *k;
    size_t          kl;
} map_t;

static int map_open(map_t *m, dht2_cbor_rd_t *r)
{
    m->r = r;
    m->prev = NULL;
    m->prev_len = 0;
    m->pend = false;
    m->k = NULL;
    m->kl = 0;
    return dht2_cbor_rd_map(r, &m->left);
}

/* 1 = the next key is `lit` (consumed); 0 = it is another key (kept
 * pending) or the map has no more keys; -1 = read fault. */
static int map_match(map_t *m, const char *lit)
{
    if (!m->pend) {
        if (m->left == 0) {
            return 0;
        }
        if (dht2_cbor_rd_key(m->r, m->prev, m->prev_len, &m->k, &m->kl) != 0) {
            return -1;
        }
        m->left--;
        m->prev = m->k;
        m->prev_len = m->kl;
        m->pend = true;
    }
    if (dht2_cbor_key_is(m->k, m->kl, lit)) {
        m->pend = false;
        return 1;
    }
    return 0;
}

static int map_expect(map_t *m, const char *lit)
{
    return (map_match(m, lit) == 1) ? 0 : -1;
}

/* All keys the head promised were matched. */
static int map_finish(const map_t *m)
{
    return (m->left == 0 && !m->pend) ? 0 : -1;
}

static int rd_fixed(dht2_cbor_rd_t *r, uint8_t *dst, size_t want)
{
    const uint8_t *p;
    size_t         n;

    if (dht2_cbor_rd_bytes(r, &p, &n) != 0 || n != want) {
        return -1;
    }
    memcpy(dst, p, want);
    return 0;
}

/* Array head whose count is bounded BEFORE any element is read. */
static int rd_array_max(dht2_cbor_rd_t *r, uint64_t max, size_t *count)
{
    uint64_t c;

    if (dht2_cbor_rd_array(r, &c) != 0 || c > max) {
        return -1;
    }
    *count = (size_t)c;
    return 0;
}

typedef int (*emit_fn)(const void *m, dht2_cbor_wr_t *w, size_t ctx);
typedef int (*parse_fn)(dht2_cbor_rd_t *r, void *m, size_t ctx);

/* Encode: `bad` for content the message cannot carry, DHT2_E_ARG for a
 * NULL argument or a buffer that is too small. */
static int encode_with(emit_fn emit, const void *m, size_t ctx, int bad,
                       uint8_t *out, size_t cap, size_t *out_len)
{
    dht2_cbor_wr_t w;

    if (m == NULL || out_len == NULL) {
        return DHT2_E_ARG;
    }
    if (out == NULL) {
        dht2_cbor_wr_init_count(&w);
    } else {
        dht2_cbor_wr_init(&w, out, cap);
    }
    if (emit(m, &w, ctx) != 0) {
        return bad;
    }
    if (!dht2_cbor_wr_ok(&w)) {
        return DHT2_E_ARG;
    }
    *out_len = w.len;
    return DHT2_OK;
}

/* Decode: strict parse, no trailing byte, then the re-encode identity. */
static int decode_with(parse_fn parse, emit_fn emit, size_t ctx, int bad,
                       const uint8_t *in, size_t len, void *m, size_t m_size)
{
    dht2_cbor_rd_t r;
    dht2_cbor_wr_t w;

    if (m == NULL || (in == NULL && len != 0)) {
        return DHT2_E_ARG;
    }
    memset(m, 0, m_size);
    dht2_cbor_rd_init(&r, in, len);
    if (parse(&r, m, ctx) != 0 || !dht2_cbor_rd_done(&r)) {
        return bad;
    }
    dht2_cbor_wr_init_compare(&w, in, len);
    if (emit(m, &w, ctx) != 0 || !dht2_cbor_wr_ok(&w)) {
        return bad;
    }
    return DHT2_OK;
}

/* ══ row 7: the per-key result ═════════════════════════════════════════ */

#define RV_LIST_CODE DHT2_E_NOT_OWNER   /* the one code a LIST result may be */

/* Row 7 per-key codes: 1…13, 16, 17. 14 / 15 are call-level (refusal) and
 * 18 appears only as [18, through]; 0 is not a wire code. */
static bool code_valid(uint64_t c)
{
    return (c >= 1u && c <= 13u) || c == 16u || c == 17u;
}

static bool result_valid(const dht2_result_t *x, dht2_rctx_t ctx)
{
    switch (x->kind) {
    case DHT2_RV_HASH:
        return true;
    case DHT2_RV_NULL:
        return ctx == DHT2_RCTX_READ;     /* "NEVER a PUT result" */
    case DHT2_RV_CODE:
        return code_valid(x->code) &&
               (ctx != DHT2_RCTX_LIST || x->code == RV_LIST_CODE);
    case DHT2_RV_HANDLED:
        return ctx != DHT2_RCTX_LIST;
    }
    return false;
}

static int result_emit(const dht2_result_t *x, dht2_rctx_t ctx,
                       dht2_cbor_wr_t *w)
{
    if (!result_valid(x, ctx)) {
        return -1;
    }
    dht2_cbor_wr_map(w, 2);
    dht2_cbor_wr_key(w, "k");
    dht2_cbor_wr_bytes(w, x->key, DHT2_HASH_LEN);
    dht2_cbor_wr_key(w, "v");
    switch (x->kind) {
    case DHT2_RV_HASH:
        dht2_cbor_wr_bytes(w, x->hash, DHT2_HASH_LEN);
        break;
    case DHT2_RV_NULL:
        dht2_cbor_wr_null(w);
        break;
    case DHT2_RV_CODE:
        dht2_cbor_wr_uint(w, x->code);
        break;
    case DHT2_RV_HANDLED:
        dht2_cbor_wr_array(w, 2);
        dht2_cbor_wr_uint(w, DHT2_E_HANDLED);
        dht2_cbor_wr_uint(w, x->through);
        break;
    }
    return 0;
}

static int result_parse(dht2_cbor_rd_t *r, dht2_rctx_t ctx, dht2_result_t *x)
{
    map_t    m;
    uint64_t u;
    size_t   cnt;
    int      mt;

    if (map_open(&m, r) != 0 || map_expect(&m, "k") != 0 ||
        rd_fixed(r, x->key, DHT2_HASH_LEN) != 0 ||
        map_expect(&m, "v") != 0) {
        return -1;
    }
    mt = dht2_cbor_rd_peek_mt(r);
    if (mt == 2) {
        x->kind = DHT2_RV_HASH;
        if (rd_fixed(r, x->hash, DHT2_HASH_LEN) != 0) {
            return -1;
        }
    } else if (dht2_cbor_rd_peek_null(r)) {
        x->kind = DHT2_RV_NULL;
        if (dht2_cbor_rd_null(r) != 0) {
            return -1;
        }
    } else if (mt == 0) {
        x->kind = DHT2_RV_CODE;
        if (dht2_cbor_rd_uint(r, &x->code) != 0) {
            return -1;                    /* 18 bare, 14, 15 → result_valid */
        }
    } else if (mt == 4) {
        x->kind = DHT2_RV_HANDLED;
        if (rd_array_max(r, 2, &cnt) != 0 || cnt != 2 ||
            dht2_cbor_rd_uint(r, &u) != 0 || u != DHT2_E_HANDLED ||
            dht2_cbor_rd_uint(r, &x->through) != 0) {
            return -1;
        }
    } else {
        return -1;
    }
    if (map_finish(&m) != 0 || !result_valid(x, ctx)) {
        return -1;
    }
    return 0;
}

/* ══ row 14: requests ══════════════════════════════════════════════════ */

#define OP_GET "get"
#define OP_PUT "put"

static int req_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_req_t *q = (const dht2_req_t *)vm;
    size_t            i;

    (void)ctx;
    if (q->count > DHT2_REQ_KEYS_MAX ||
        (q->kind != DHT2_REQ_GET && q->kind != DHT2_REQ_PUT)) {
        return -1;
    }
    if (q->kind == DHT2_REQ_PUT) {
        for (i = 0; i < q->count; i++) {
            if (q->env_lens[i] > DHT2_ENVELOPE_MAX ||
                (q->envs[i] == NULL && q->env_lens[i] != 0)) {
                return -1;
            }
        }
    }
    dht2_cbor_wr_map(w, 3);
    dht2_cbor_wr_key(w, "n");
    dht2_cbor_wr_bytes(w, q->nonce, DHT2_NONCE_LEN);
    dht2_cbor_wr_key(w, "op");
    if (q->kind == DHT2_REQ_GET) {
        dht2_cbor_wr_text(w, (const uint8_t *)OP_GET, strlen(OP_GET));
        dht2_cbor_wr_key(w, "keys");
        dht2_cbor_wr_array(w, q->count);
        for (i = 0; i < q->count; i++) {
            dht2_cbor_wr_bytes(w, q->keys[i], DHT2_HASH_LEN);
        }
    } else {
        dht2_cbor_wr_text(w, (const uint8_t *)OP_PUT, strlen(OP_PUT));
        dht2_cbor_wr_key(w, "envs");
        dht2_cbor_wr_array(w, q->count);
        for (i = 0; i < q->count; i++) {
            dht2_cbor_wr_bytes(w, q->envs[i], q->env_lens[i]);
        }
    }
    return 0;
}

static int req_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_req_t    *q = (dht2_req_t *)vm;
    map_t          m;
    const uint8_t *p;
    size_t         n, i;

    (void)ctx;
    if (map_open(&m, r) != 0 || map_expect(&m, "n") != 0 ||
        rd_fixed(r, q->nonce, DHT2_NONCE_LEN) != 0 ||
        map_expect(&m, "op") != 0 || dht2_cbor_rd_text(r, &p, &n) != 0) {
        return -1;
    }
    if (dht2_cbor_key_is(p, n, OP_GET)) {
        q->kind = DHT2_REQ_GET;
        if (map_expect(&m, "keys") != 0 ||
            rd_array_max(r, DHT2_REQ_KEYS_MAX, &q->count) != 0) {
            return -1;
        }
        for (i = 0; i < q->count; i++) {
            if (rd_fixed(r, q->keys[i], DHT2_HASH_LEN) != 0) {
                return -1;
            }
        }
    } else if (dht2_cbor_key_is(p, n, OP_PUT)) {
        q->kind = DHT2_REQ_PUT;
        if (map_expect(&m, "envs") != 0 ||
            rd_array_max(r, DHT2_REQ_KEYS_MAX, &q->count) != 0) {
            return -1;
        }
        for (i = 0; i < q->count; i++) {
            if (dht2_cbor_rd_bytes(r, &q->envs[i], &q->env_lens[i]) != 0 ||
                q->env_lens[i] > DHT2_ENVELOPE_MAX) {
                return -1;
            }
        }
    } else {
        return -1;                        /* unknown operation */
    }
    return map_finish(&m);
}

int dht2_req_encode(const dht2_req_t *req, uint8_t *out, size_t cap,
                    size_t *out_len)
{
    return encode_with(req_emit, req, 0, DHT2_E_MALFORMED_REQ, out, cap,
                       out_len);
}

int dht2_req_decode(const uint8_t *in, size_t len, dht2_req_t *req)
{
    return decode_with(req_parse, req_emit, 0, DHT2_E_MALFORMED_REQ, in, len,
                       req, sizeof(*req));
}

/* ══ row 18: read answer / receipt ═════════════════════════════════════ */

/* ctx = dht2_rctx_t (READ for an answer, WRITE for a receipt). */
static int answer_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_answer_t *a = (const dht2_answer_t *)vm;
    size_t               i;

    if (a->r_count > DHT2_REQ_KEYS_MAX) {
        return -1;
    }
    for (i = 0; i < a->r_count; i++) {
        if (!result_valid(&a->r[i], (dht2_rctx_t)ctx)) {
            return -1;
        }
    }
    dht2_cbor_wr_map(w, 6);
    dht2_cbor_wr_key(w, "c");
    dht2_cbor_wr_bytes(w, a->c, DHT2_CHAIN_LEN);
    dht2_cbor_wr_key(w, "h");
    dht2_cbor_wr_uint(w, a->h);
    dht2_cbor_wr_key(w, "n");
    dht2_cbor_wr_bytes(w, a->n, DHT2_FP_LEN);
    dht2_cbor_wr_key(w, "q");
    dht2_cbor_wr_bytes(w, a->q, DHT2_NONCE_LEN);
    dht2_cbor_wr_key(w, "r");
    dht2_cbor_wr_array(w, a->r_count);
    for (i = 0; i < a->r_count; i++) {
        if (result_emit(&a->r[i], (dht2_rctx_t)ctx, w) != 0) {
            return -1;
        }
    }
    dht2_cbor_wr_key(w, "t");
    dht2_cbor_wr_uint(w, a->t);
    return 0;
}

static int answer_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_answer_t *a = (dht2_answer_t *)vm;
    map_t          m;
    size_t         i;

    if (map_open(&m, r) != 0 ||
        map_expect(&m, "c") != 0 || rd_fixed(r, a->c, DHT2_CHAIN_LEN) != 0 ||
        map_expect(&m, "h") != 0 || dht2_cbor_rd_uint(r, &a->h) != 0 ||
        map_expect(&m, "n") != 0 || rd_fixed(r, a->n, DHT2_FP_LEN) != 0 ||
        map_expect(&m, "q") != 0 || rd_fixed(r, a->q, DHT2_NONCE_LEN) != 0 ||
        map_expect(&m, "r") != 0 ||
        rd_array_max(r, DHT2_REQ_KEYS_MAX, &a->r_count) != 0) {
        return -1;
    }
    for (i = 0; i < a->r_count; i++) {
        if (result_parse(r, (dht2_rctx_t)ctx, &a->r[i]) != 0) {
            return -1;
        }
    }
    if (map_expect(&m, "t") != 0 || dht2_cbor_rd_uint(r, &a->t) != 0) {
        return -1;
    }
    return map_finish(&m);
}

int dht2_answer_encode(const dht2_answer_t *a, uint8_t *out, size_t cap,
                       size_t *out_len)
{
    return encode_with(answer_emit, a, DHT2_RCTX_READ, DHT2_E_BAD_ENCODING,
                       out, cap, out_len);
}

int dht2_answer_decode(const uint8_t *in, size_t len, dht2_answer_t *a)
{
    return decode_with(answer_parse, answer_emit, DHT2_RCTX_READ,
                       DHT2_E_BAD_ENCODING, in, len, a, sizeof(*a));
}

int dht2_receipt_encode(const dht2_answer_t *a, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    return encode_with(answer_emit, a, DHT2_RCTX_WRITE, DHT2_E_BAD_ENCODING,
                       out, cap, out_len);
}

int dht2_receipt_decode(const uint8_t *in, size_t len, dht2_answer_t *a)
{
    return decode_with(answer_parse, answer_emit, DHT2_RCTX_WRITE,
                       DHT2_E_BAD_ENCODING, in, len, a, sizeof(*a));
}

/* ══ row 18: LIST answer ═══════════════════════════════════════════════ */

/* Row 11 / §4.4 / decision 4 — exactly these rules, nothing more. */
static bool list_rules_ok(const dht2_list_answer_t *a)
{
    size_t i;

    if (a->list_count > DHT2_LIST_PAGE_MAX ||
        !result_valid(&a->r, DHT2_RCTX_LIST)) {
        return false;
    }
    for (i = 1; i < a->list_count; i++) {
        if (memcmp(a->list[i - 1].w, a->list[i].w, DHT2_FP_LEN) >= 0) {
            return false;                 /* strictly ascending writer fp */
        }
    }
    if (a->list_count == 0) {
        return a->complete && !a->has_cursor;   /* an empty page */
    }
    if (a->has_cursor &&
        memcmp(a->cursor, a->list[a->list_count - 1].w, DHT2_FP_LEN) != 0) {
        return false;                     /* cursor EXCLUSIVE = last w */
    }
    if (a->has_req_cursor &&
        memcmp(a->list[0].w, a->req_cursor, DHT2_FP_LEN) <= 0) {
        return false;                     /* the page starts strictly after
                                           * the request's cursor (row 11) */
    }
    return true;
}

static int list_answer_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_list_answer_t *a = (const dht2_list_answer_t *)vm;
    size_t                    i;

    (void)ctx;
    if (!list_rules_ok(a)) {
        return -1;
    }
    dht2_cbor_wr_map(w, 9u + (a->has_cursor ? 1u : 0u) +
                        (a->has_req_cursor ? 1u : 0u));
    dht2_cbor_wr_key(w, "c");
    dht2_cbor_wr_bytes(w, a->c, DHT2_CHAIN_LEN);
    dht2_cbor_wr_key(w, "h");
    dht2_cbor_wr_uint(w, a->h);
    dht2_cbor_wr_key(w, "n");
    dht2_cbor_wr_bytes(w, a->n, DHT2_FP_LEN);
    dht2_cbor_wr_key(w, "q");
    dht2_cbor_wr_bytes(w, a->q, DHT2_NONCE_LEN);
    dht2_cbor_wr_key(w, "r");
    dht2_cbor_wr_array(w, 1);
    if (result_emit(&a->r, DHT2_RCTX_LIST, w) != 0) {
        return -1;
    }
    dht2_cbor_wr_key(w, "t");
    dht2_cbor_wr_uint(w, a->t);
    dht2_cbor_wr_key(w, "ctl");
    if (a->has_ctl) {
        dht2_cbor_wr_bytes(w, a->ctl, DHT2_HASH_LEN);
    } else {
        dht2_cbor_wr_null(w);
    }
    dht2_cbor_wr_key(w, "list");
    dht2_cbor_wr_array(w, a->list_count);
    for (i = 0; i < a->list_count; i++) {
        dht2_cbor_wr_map(w, 2);
        dht2_cbor_wr_key(w, "d");
        dht2_cbor_wr_bytes(w, a->list[i].d, DHT2_HASH_LEN);
        dht2_cbor_wr_key(w, "w");
        dht2_cbor_wr_bytes(w, a->list[i].w, DHT2_FP_LEN);
    }
    if (a->has_cursor) {
        dht2_cbor_wr_key(w, "cursor");
        dht2_cbor_wr_bytes(w, a->cursor, DHT2_FP_LEN);
    }
    dht2_cbor_wr_key(w, "complete");
    dht2_cbor_wr_bool(w, a->complete);
    if (a->has_req_cursor) {
        dht2_cbor_wr_key(w, "req_cursor");
        dht2_cbor_wr_bytes(w, a->req_cursor, DHT2_FP_LEN);
    }
    return 0;
}

static int list_answer_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_list_answer_t *a = (dht2_list_answer_t *)vm;
    map_t               m;
    size_t              i, cnt;
    int                 s;

    (void)ctx;
    if (map_open(&m, r) != 0 ||
        map_expect(&m, "c") != 0 || rd_fixed(r, a->c, DHT2_CHAIN_LEN) != 0 ||
        map_expect(&m, "h") != 0 || dht2_cbor_rd_uint(r, &a->h) != 0 ||
        map_expect(&m, "n") != 0 || rd_fixed(r, a->n, DHT2_FP_LEN) != 0 ||
        map_expect(&m, "q") != 0 || rd_fixed(r, a->q, DHT2_NONCE_LEN) != 0 ||
        map_expect(&m, "r") != 0 || rd_array_max(r, 1, &cnt) != 0 ||
        cnt != 1 || result_parse(r, DHT2_RCTX_LIST, &a->r) != 0 ||
        map_expect(&m, "t") != 0 || dht2_cbor_rd_uint(r, &a->t) != 0 ||
        map_expect(&m, "ctl") != 0) {
        return -1;
    }
    if (dht2_cbor_rd_peek_null(r)) {
        a->has_ctl = false;
        if (dht2_cbor_rd_null(r) != 0) {
            return -1;
        }
    } else {
        a->has_ctl = true;
        if (rd_fixed(r, a->ctl, DHT2_HASH_LEN) != 0) {
            return -1;
        }
    }
    if (map_expect(&m, "list") != 0 ||
        rd_array_max(r, DHT2_LIST_PAGE_MAX, &a->list_count) != 0) {
        return -1;
    }
    for (i = 0; i < a->list_count; i++) {
        map_t e;

        if (map_open(&e, r) != 0 || map_expect(&e, "d") != 0 ||
            rd_fixed(r, a->list[i].d, DHT2_HASH_LEN) != 0 ||
            map_expect(&e, "w") != 0 ||
            rd_fixed(r, a->list[i].w, DHT2_FP_LEN) != 0 ||
            map_finish(&e) != 0) {
            return -1;
        }
    }
    s = map_match(&m, "cursor");
    if (s < 0) {
        return -1;
    }
    if (s == 1) {
        a->has_cursor = true;
        if (rd_fixed(r, a->cursor, DHT2_FP_LEN) != 0) {
            return -1;
        }
    }
    if (map_expect(&m, "complete") != 0 ||
        dht2_cbor_rd_bool(r, &a->complete) != 0) {
        return -1;
    }
    s = map_match(&m, "req_cursor");
    if (s < 0) {
        return -1;
    }
    if (s == 1) {
        a->has_req_cursor = true;
        if (rd_fixed(r, a->req_cursor, DHT2_FP_LEN) != 0) {
            return -1;
        }
    }
    if (map_finish(&m) != 0 || !list_rules_ok(a)) {
        return -1;
    }
    return 0;
}

int dht2_list_answer_encode(const dht2_list_answer_t *a, uint8_t *out,
                            size_t cap, size_t *out_len)
{
    return encode_with(list_answer_emit, a, 0, DHT2_E_BAD_ENCODING, out, cap,
                       out_len);
}

int dht2_list_answer_decode(const uint8_t *in, size_t len,
                            dht2_list_answer_t *a)
{
    return decode_with(list_answer_parse, list_answer_emit, 0,
                       DHT2_E_BAD_ENCODING, in, len, a, sizeof(*a));
}

/* ══ row 18: refusal ═══════════════════════════════════════════════════ */

static int refusal_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_refusal_t *m = (const dht2_refusal_t *)vm;

    (void)ctx;
    if (m->e != DHT2_E_BUSY && m->e != DHT2_E_NOT_CAUGHT_UP) {
        return -1;
    }
    dht2_cbor_wr_map(w, 4);
    dht2_cbor_wr_key(w, "c");
    dht2_cbor_wr_bytes(w, m->c, DHT2_CHAIN_LEN);
    dht2_cbor_wr_key(w, "e");
    dht2_cbor_wr_uint(w, m->e);
    dht2_cbor_wr_key(w, "n");
    dht2_cbor_wr_bytes(w, m->n, DHT2_FP_LEN);
    dht2_cbor_wr_key(w, "q");
    dht2_cbor_wr_bytes(w, m->q, DHT2_NONCE_LEN);
    return 0;
}

static int refusal_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_refusal_t *m = (dht2_refusal_t *)vm;
    map_t           mp;

    (void)ctx;
    if (map_open(&mp, r) != 0 ||
        map_expect(&mp, "c") != 0 || rd_fixed(r, m->c, DHT2_CHAIN_LEN) != 0 ||
        map_expect(&mp, "e") != 0 || dht2_cbor_rd_uint(r, &m->e) != 0 ||
        map_expect(&mp, "n") != 0 || rd_fixed(r, m->n, DHT2_FP_LEN) != 0 ||
        map_expect(&mp, "q") != 0 ||
        rd_fixed(r, m->q, DHT2_NONCE_LEN) != 0) {
        return -1;
    }
    if (m->e != DHT2_E_BUSY && m->e != DHT2_E_NOT_CAUGHT_UP) {
        return -1;
    }
    return map_finish(&mp);
}

int dht2_refusal_encode(const dht2_refusal_t *m, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    return encode_with(refusal_emit, m, 0, DHT2_E_BAD_ENCODING, out, cap,
                       out_len);
}

int dht2_refusal_decode(const uint8_t *in, size_t len, dht2_refusal_t *m)
{
    return decode_with(refusal_parse, refusal_emit, 0, DHT2_E_BAD_ENCODING,
                       in, len, m, sizeof(*m));
}

/* ══ §4.4: seal / open ═════════════════════════════════════════════════ */

static bool answer_pt_ok(const char *pt)
{
    return pt != NULL &&
           (strcmp(pt, DHT2_PT_ANSWER) == 0 ||
            strcmp(pt, DHT2_PT_RECEIPT) == 0 ||
            strcmp(pt, DHT2_PT_REFUSAL) == 0);
}

int dht2_answer_seal(const char *payload_type, const uint8_t *payload,
                     size_t payload_len, const uint8_t *sk,
                     const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out,
                     size_t cap, size_t *out_len)
{
    if (!answer_pt_ok(payload_type)) {
        return DHT2_E_ARG;
    }
    return dht2_env_seal(DHT2_DOMAIN_ANSWER, (const uint8_t *)payload_type,
                         strlen(payload_type), payload, payload_len, sk, pk,
                         out, cap, out_len);
}

int dht2_answer_open(const uint8_t *in, size_t len, const char *payload_type,
                     dht2_env_t *env)
{
    int rc;

    if (!answer_pt_ok(payload_type) || env == NULL) {
        return DHT2_E_ARG;
    }
    rc = dht2_env_decode(in, len, DHT2_ENVELOPE_MAX, env);
    if (rc != DHT2_OK) {
        return rc;
    }
    if (env->payload_type_len != strlen(payload_type) ||
        memcmp(env->payload_type, payload_type, env->payload_type_len) != 0) {
        return DHT2_E_BAD_ENCODING;
    }
    return dht2_env_verify(env, DHT2_DOMAIN_ANSWER);
}

/* ══ row 12: pull-sync ═════════════════════════════════════════════════ */

static int p_hello_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_p_hello_t *m = (const dht2_p_hello_t *)vm;

    (void)ctx;
    dht2_cbor_wr_map(w, 2);
    dht2_cbor_wr_key(w, "g");
    dht2_cbor_wr_uint(w, m->g);
    dht2_cbor_wr_key(w, "top");
    dht2_cbor_wr_uint(w, m->top);
    return 0;
}

static int p_hello_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_p_hello_t *m = (dht2_p_hello_t *)vm;
    map_t           mp;

    (void)ctx;
    if (map_open(&mp, r) != 0 ||
        map_expect(&mp, "g") != 0 || dht2_cbor_rd_uint(r, &m->g) != 0 ||
        map_expect(&mp, "top") != 0 || dht2_cbor_rd_uint(r, &m->top) != 0) {
        return -1;
    }
    return map_finish(&mp);
}

int dht2_p_hello_encode(const dht2_p_hello_t *m, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    return encode_with(p_hello_emit, m, 0, DHT2_E_BAD_ENCODING, out, cap,
                       out_len);
}

int dht2_p_hello_decode(const uint8_t *in, size_t len, dht2_p_hello_t *m)
{
    return decode_with(p_hello_parse, p_hello_emit, 0, DHT2_E_BAD_ENCODING,
                       in, len, m, sizeof(*m));
}

static int p_get_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_p_get_t *m = (const dht2_p_get_t *)vm;

    (void)ctx;
    dht2_cbor_wr_map(w, 2);
    dht2_cbor_wr_key(w, "g");
    dht2_cbor_wr_uint(w, m->g);
    dht2_cbor_wr_key(w, "s");
    dht2_cbor_wr_uint(w, m->s);
    return 0;
}

static int p_get_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_p_get_t *m = (dht2_p_get_t *)vm;
    map_t         mp;

    (void)ctx;
    if (map_open(&mp, r) != 0 ||
        map_expect(&mp, "g") != 0 || dht2_cbor_rd_uint(r, &m->g) != 0 ||
        map_expect(&mp, "s") != 0 || dht2_cbor_rd_uint(r, &m->s) != 0) {
        return -1;
    }
    return map_finish(&mp);
}

int dht2_p_get_encode(const dht2_p_get_t *m, uint8_t *out, size_t cap,
                      size_t *out_len)
{
    return encode_with(p_get_emit, m, 0, DHT2_E_BAD_ENCODING, out, cap,
                       out_len);
}

int dht2_p_get_decode(const uint8_t *in, size_t len, dht2_p_get_t *m)
{
    return decode_with(p_get_parse, p_get_emit, 0, DHT2_E_BAD_ENCODING, in,
                       len, m, sizeof(*m));
}

static int p_offer_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_p_offer_t *m = (const dht2_p_offer_t *)vm;
    size_t                i;

    (void)ctx;
    if (m->e_count > DHT2_PULL_PAGE_MAX) {
        return -1;
    }
    dht2_cbor_wr_map(w, 3);
    dht2_cbor_wr_key(w, "e");
    dht2_cbor_wr_array(w, m->e_count);
    for (i = 0; i < m->e_count; i++) {
        dht2_cbor_wr_map(w, 3);
        dht2_cbor_wr_key(w, "a");
        dht2_cbor_wr_bytes(w, m->e[i].a, DHT2_HASH_LEN);
        dht2_cbor_wr_key(w, "h");
        dht2_cbor_wr_bytes(w, m->e[i].h, DHT2_HASH_LEN);
        dht2_cbor_wr_key(w, "p");
        dht2_cbor_wr_bytes(w, m->e[i].p, DHT2_HASH_LEN);
    }
    dht2_cbor_wr_key(w, "g");
    dht2_cbor_wr_uint(w, m->g);
    dht2_cbor_wr_key(w, "top");
    dht2_cbor_wr_uint(w, m->top);
    return 0;
}

static int p_offer_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_p_offer_t *m = (dht2_p_offer_t *)vm;
    map_t           mp;
    size_t          i;

    (void)ctx;
    if (map_open(&mp, r) != 0 || map_expect(&mp, "e") != 0 ||
        rd_array_max(r, DHT2_PULL_PAGE_MAX, &m->e_count) != 0) {
        return -1;
    }
    for (i = 0; i < m->e_count; i++) {
        map_t e;

        if (map_open(&e, r) != 0 ||
            map_expect(&e, "a") != 0 ||
            rd_fixed(r, m->e[i].a, DHT2_HASH_LEN) != 0 ||
            map_expect(&e, "h") != 0 ||
            rd_fixed(r, m->e[i].h, DHT2_HASH_LEN) != 0 ||
            map_expect(&e, "p") != 0 ||
            rd_fixed(r, m->e[i].p, DHT2_HASH_LEN) != 0 ||
            map_finish(&e) != 0) {
            return -1;
        }
    }
    if (map_expect(&mp, "g") != 0 || dht2_cbor_rd_uint(r, &m->g) != 0 ||
        map_expect(&mp, "top") != 0 || dht2_cbor_rd_uint(r, &m->top) != 0) {
        return -1;
    }
    return map_finish(&mp);
}

int dht2_p_offer_encode(const dht2_p_offer_t *m, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    return encode_with(p_offer_emit, m, 0, DHT2_E_BAD_ENCODING, out, cap,
                       out_len);
}

int dht2_p_offer_decode(const uint8_t *in, size_t len, dht2_p_offer_t *m)
{
    return decode_with(p_offer_parse, p_offer_emit, 0, DHT2_E_BAD_ENCODING,
                       in, len, m, sizeof(*m));
}

/* ── bit-vector ────────────────────────────────────────────────────────── */

size_t dht2_bits_len(size_t n)
{
    return n / 8u + ((n % 8u) != 0u ? 1u : 0u);       /* ⌈n/8⌉, no overflow */
}

bool dht2_bits_get(const uint8_t *b, size_t i)
{
    return (b[i / 8u] & (uint8_t)(1u << (i % 8u))) != 0;
}

void dht2_bits_set(uint8_t *b, size_t i)
{
    b[i / 8u] = (uint8_t)(b[i / 8u] | (uint8_t)(1u << (i % 8u)));
}

/* Row 12: exactly ⌈n/8⌉ bytes, bits ≥ n zero, n = the offer's entry count
 * (≤ 250). */
static bool want_valid(const uint8_t *b, size_t b_len, size_t n)
{
    if (n > DHT2_PULL_PAGE_MAX || b_len != dht2_bits_len(n)) {
        return false;
    }
    if ((n % 8u) != 0u && (b[b_len - 1u] >> (n % 8u)) != 0u) {
        return false;                     /* a set bit ≥ n */
    }
    return true;
}

/* ctx = n, the offer's entry count. */
static int p_want_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_p_want_t *m = (const dht2_p_want_t *)vm;

    if ((m->b == NULL && m->b_len != 0) || !want_valid(m->b, m->b_len, ctx)) {
        return -1;
    }
    dht2_cbor_wr_map(w, 1);
    dht2_cbor_wr_key(w, "b");
    dht2_cbor_wr_bytes(w, m->b, m->b_len);
    return 0;
}

static int p_want_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_p_want_t *m = (dht2_p_want_t *)vm;
    map_t          mp;

    if (map_open(&mp, r) != 0 || map_expect(&mp, "b") != 0 ||
        dht2_cbor_rd_bytes(r, &m->b, &m->b_len) != 0 ||
        !want_valid(m->b, m->b_len, ctx)) {
        return -1;
    }
    return map_finish(&mp);
}

int dht2_p_want_encode(const dht2_p_want_t *m, size_t n, uint8_t *out,
                       size_t cap, size_t *out_len)
{
    return encode_with(p_want_emit, m, n, DHT2_E_BAD_ENCODING, out, cap,
                       out_len);
}

int dht2_p_want_decode(const uint8_t *in, size_t len, size_t n,
                       dht2_p_want_t *m)
{
    return decode_with(p_want_parse, p_want_emit, n, DHT2_E_BAD_ENCODING, in,
                       len, m, sizeof(*m));
}

static int p_deliver_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_p_deliver_t *m = (const dht2_p_deliver_t *)vm;

    (void)ctx;
    if (m->i >= DHT2_PULL_PAGE_MAX) {
        return -1;                        /* i indexes an offer of ≤ 250 */
    }
    if (m->has_v && (m->v_len > DHT2_ENVELOPE_MAX ||
                     (m->v == NULL && m->v_len != 0))) {
        return -1;
    }
    dht2_cbor_wr_map(w, 2);
    dht2_cbor_wr_key(w, "i");
    dht2_cbor_wr_uint(w, m->i);
    dht2_cbor_wr_key(w, "v");
    if (m->has_v) {
        dht2_cbor_wr_bytes(w, m->v, m->v_len);
    } else {
        dht2_cbor_wr_null(w);
    }
    return 0;
}

static int p_deliver_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_p_deliver_t *m = (dht2_p_deliver_t *)vm;
    map_t             mp;

    (void)ctx;
    if (map_open(&mp, r) != 0 ||
        map_expect(&mp, "i") != 0 || dht2_cbor_rd_uint(r, &m->i) != 0 ||
        m->i >= DHT2_PULL_PAGE_MAX || map_expect(&mp, "v") != 0) {
        return -1;
    }
    if (dht2_cbor_rd_peek_null(r)) {
        m->has_v = false;
        if (dht2_cbor_rd_null(r) != 0) {
            return -1;
        }
    } else {
        m->has_v = true;
        if (dht2_cbor_rd_bytes(r, &m->v, &m->v_len) != 0 ||
            m->v_len > DHT2_ENVELOPE_MAX) {
            return -1;
        }
    }
    return map_finish(&mp);
}

int dht2_p_deliver_encode(const dht2_p_deliver_t *m, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    return encode_with(p_deliver_emit, m, 0, DHT2_E_BAD_ENCODING, out, cap,
                       out_len);
}

int dht2_p_deliver_decode(const uint8_t *in, size_t len, dht2_p_deliver_t *m)
{
    return decode_with(p_deliver_parse, p_deliver_emit, 0,
                       DHT2_E_BAD_ENCODING, in, len, m, sizeof(*m));
}

static int pull_receipt_emit(const void *vm, dht2_cbor_wr_t *w, size_t ctx)
{
    const dht2_pull_receipt_t *m = (const dht2_pull_receipt_t *)vm;
    size_t                     i;

    (void)ctx;
    if (m->e_count > DHT2_PULL_PAGE_MAX) {
        return -1;
    }
    dht2_cbor_wr_map(w, 7);
    dht2_cbor_wr_key(w, "c");
    dht2_cbor_wr_bytes(w, m->c, DHT2_CHAIN_LEN);
    dht2_cbor_wr_key(w, "e");
    dht2_cbor_wr_array(w, m->e_count);
    for (i = 0; i < m->e_count; i++) {
        dht2_cbor_wr_map(w, 2);
        dht2_cbor_wr_key(w, "a");
        dht2_cbor_wr_bytes(w, m->e[i].a, DHT2_HASH_LEN);
        dht2_cbor_wr_key(w, "h");
        dht2_cbor_wr_bytes(w, m->e[i].h, DHT2_HASH_LEN);
    }
    dht2_cbor_wr_key(w, "g");
    dht2_cbor_wr_uint(w, m->g);
    dht2_cbor_wr_key(w, "s");
    dht2_cbor_wr_uint(w, m->s);
    dht2_cbor_wr_key(w, "pf");
    dht2_cbor_wr_bytes(w, m->pf, DHT2_FP_LEN);
    dht2_cbor_wr_key(w, "sf");
    dht2_cbor_wr_bytes(w, m->sf, DHT2_FP_LEN);
    dht2_cbor_wr_key(w, "top");
    dht2_cbor_wr_uint(w, m->top);
    return 0;
}

static int pull_receipt_parse(dht2_cbor_rd_t *r, void *vm, size_t ctx)
{
    dht2_pull_receipt_t *m = (dht2_pull_receipt_t *)vm;
    map_t                mp;
    size_t               i;

    (void)ctx;
    if (map_open(&mp, r) != 0 ||
        map_expect(&mp, "c") != 0 || rd_fixed(r, m->c, DHT2_CHAIN_LEN) != 0 ||
        map_expect(&mp, "e") != 0 ||
        rd_array_max(r, DHT2_PULL_PAGE_MAX, &m->e_count) != 0) {
        return -1;
    }
    for (i = 0; i < m->e_count; i++) {
        map_t e;

        if (map_open(&e, r) != 0 ||
            map_expect(&e, "a") != 0 ||
            rd_fixed(r, m->e[i].a, DHT2_HASH_LEN) != 0 ||
            map_expect(&e, "h") != 0 ||
            rd_fixed(r, m->e[i].h, DHT2_HASH_LEN) != 0 ||
            map_finish(&e) != 0) {
            return -1;
        }
    }
    if (map_expect(&mp, "g") != 0 || dht2_cbor_rd_uint(r, &m->g) != 0 ||
        map_expect(&mp, "s") != 0 || dht2_cbor_rd_uint(r, &m->s) != 0 ||
        map_expect(&mp, "pf") != 0 || rd_fixed(r, m->pf, DHT2_FP_LEN) != 0 ||
        map_expect(&mp, "sf") != 0 || rd_fixed(r, m->sf, DHT2_FP_LEN) != 0 ||
        map_expect(&mp, "top") != 0 || dht2_cbor_rd_uint(r, &m->top) != 0) {
        return -1;
    }
    return map_finish(&mp);
}

int dht2_pull_receipt_encode(const dht2_pull_receipt_t *m, uint8_t *out,
                             size_t cap, size_t *out_len)
{
    return encode_with(pull_receipt_emit, m, 0, DHT2_E_BAD_ENCODING, out, cap,
                       out_len);
}

int dht2_pull_receipt_decode(const uint8_t *in, size_t len,
                             dht2_pull_receipt_t *m)
{
    return decode_with(pull_receipt_parse, pull_receipt_emit, 0,
                       DHT2_E_BAD_ENCODING, in, len, m, sizeof(*m));
}

/* ══ row 15: inbox control `_data` ═════════════════════════════════════ */

static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    size_t   k;

    for (k = 0; k < 8; k++) {
        v = (v << 8) | p[k];
    }
    return v;
}

static bool mark_valid(uint8_t mark)
{
    return mark == DHT2_CTL_HANDLED || mark == DHT2_CTL_DENIED;
}

int dht2_ctl_encode(const dht2_ctl_entry_t *e, size_t count, uint8_t *out,
                    size_t cap, size_t *out_len)
{
    size_t i, k, off = 0;

    if ((e == NULL && count != 0) || out_len == NULL) {
        return DHT2_E_ARG;
    }
    if (count > DHT2_CTL_ENTRIES_MAX) {
        return DHT2_E_BAD_ENCODING;
    }
    for (i = 0; i < count; i++) {
        if (!mark_valid(e[i].mark) ||
            (i > 0 && memcmp(e[i - 1].fp, e[i].fp, DHT2_FP_LEN) >= 0)) {
            return DHT2_E_BAD_ENCODING;
        }
    }
    /* count ≤ 3,500 and 73 B each: no overflow. */
    if (out == NULL) {
        *out_len = count * DHT2_CTL_ENTRY_LEN;
        return DHT2_OK;
    }
    if (cap < count * DHT2_CTL_ENTRY_LEN) {
        return DHT2_E_ARG;
    }
    for (i = 0; i < count; i++) {
        memcpy(out + off, e[i].fp, DHT2_FP_LEN);
        off += DHT2_FP_LEN;
        out[off++] = e[i].mark;
        for (k = 0; k < 8; k++) {
            out[off++] = (uint8_t)(e[i].through >> (8u * (7u - (unsigned)k)));
        }
    }
    *out_len = off;
    return DHT2_OK;
}

int dht2_ctl_check(const uint8_t *data, size_t len, size_t *count)
{
    size_t n, i;

    if (data == NULL && len != 0) {
        return DHT2_E_ARG;
    }
    if (len % DHT2_CTL_ENTRY_LEN != 0) {
        return DHT2_E_BAD_ENCODING;
    }
    n = len / DHT2_CTL_ENTRY_LEN;
    if (n > DHT2_CTL_ENTRIES_MAX) {
        return DHT2_E_BAD_ENCODING;
    }
    for (i = 0; i < n; i++) {
        const uint8_t *ent = data + i * DHT2_CTL_ENTRY_LEN;

        if (!mark_valid(ent[DHT2_FP_LEN]) ||
            (i > 0 && memcmp(ent - DHT2_CTL_ENTRY_LEN, ent, DHT2_FP_LEN) >= 0)) {
            return DHT2_E_BAD_ENCODING;
        }
    }
    if (count != NULL) {
        *count = n;
    }
    return DHT2_OK;
}

static void ctl_read(const uint8_t *ent, dht2_ctl_entry_t *out)
{
    memcpy(out->fp, ent, DHT2_FP_LEN);
    out->mark = ent[DHT2_FP_LEN];
    out->through = be64(ent + DHT2_FP_LEN + 1u);
}

int dht2_ctl_at(const uint8_t *data, size_t len, size_t idx,
                dht2_ctl_entry_t *out)
{
    if (data == NULL || out == NULL || idx >= len / DHT2_CTL_ENTRY_LEN) {
        return DHT2_E_ARG;
    }
    ctl_read(data + idx * DHT2_CTL_ENTRY_LEN, out);
    return DHT2_OK;
}

int dht2_ctl_lookup(const uint8_t *data, size_t len,
                    const uint8_t fp[DHT2_FP_LEN], bool *found,
                    dht2_ctl_entry_t *out)
{
    size_t n = 0, lo, hi;
    int    rc;

    if (fp == NULL || found == NULL) {
        return DHT2_E_ARG;
    }
    rc = dht2_ctl_check(data, len, &n);
    if (rc != DHT2_OK) {
        return rc;
    }
    *found = false;
    lo = 0;
    hi = n;                               /* binary search over [lo, hi) */
    while (lo < hi) {
        size_t         mid = lo + (hi - lo) / 2u;
        const uint8_t *ent = data + mid * DHT2_CTL_ENTRY_LEN;
        int            c = memcmp(fp, ent, DHT2_FP_LEN);

        if (c == 0) {
            *found = true;
            if (out != NULL) {
                ctl_read(ent, out);
            }
            return DHT2_OK;
        }
        if (c < 0) {
            hi = mid;
        } else {
            lo = mid + 1u;
        }
    }
    return DHT2_OK;
}
