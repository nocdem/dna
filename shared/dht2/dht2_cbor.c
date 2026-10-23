/**
 * @file shared/dht2/dht2_cbor.c
 * @brief DHT v2 — strict DAG-CBOR token reader and canonical writer.
 *        See dht2_cbor.h for the rules and their citations.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dht2/dht2_cbor.h"

#include <string.h>

/* RFC 8949 major types, as dag-cbor/spec.md uses them. */
#define MT_UINT  0u
#define MT_NEG   1u
#define MT_BYTES 2u
#define MT_TEXT  3u
#define MT_ARRAY 4u
#define MT_MAP   5u
#define MT_TAG   6u
#define MT_7     7u

/* ══ reader ═══════════════════════════════════════════════════════════ */

void dht2_cbor_rd_init(dht2_cbor_rd_t *r, const uint8_t *buf, size_t len)
{
    r->buf = buf;
    r->len = (buf == NULL) ? 0 : len;
    r->pos = 0;
    r->err = false;
}

static int rd_fail(dht2_cbor_rd_t *r)
{
    r->err = true;
    return -1;
}

/* Read one item head: major type and argument, enforcing the shortest
 * form of dag-cbor/spec.md :55-56 and refusing indefinite lengths (:59,
 * additional information 31). Additional information 28-30 has no
 * argument width at all and is refused with it. */
static int rd_head(dht2_cbor_rd_t *r, unsigned *mt, uint64_t *arg)
{
    uint8_t  ib;
    unsigned ai;
    size_t   n;
    uint64_t v = 0;
    size_t   k;

    if (r->err || r->pos >= r->len) {
        return rd_fail(r);
    }
    ib  = r->buf[r->pos++];
    *mt = (unsigned)(ib >> 5);
    ai  = (unsigned)(ib & 0x1Fu);

    if (ai < 24u) {
        *arg = ai;
        return 0;
    }
    switch (ai) {
    case 24u: n = 1; break;
    case 25u: n = 2; break;
    case 26u: n = 4; break;
    case 27u: n = 8; break;
    default:  return rd_fail(r);      /* 28-30 reserved, 31 indefinite */
    }
    if (r->len - r->pos < n) {
        return rd_fail(r);
    }
    for (k = 0; k < n; k++) {
        v = (v << 8) | (uint64_t)r->buf[r->pos + k];
    }
    r->pos += n;

    /* Shortest form: each width only for values the narrower one cannot
     * hold (spec :55-56). */
    if ((n == 1 && v < 24u) ||
        (n == 2 && v <= 0xFFu) ||
        (n == 4 && v <= 0xFFFFu) ||
        (n == 8 && v <= 0xFFFFFFFFu)) {
        return rd_fail(r);
    }
    /* Major type 7 with a 1-byte argument is a "simple value"; with 2/4/8
     * bytes it is a float. dag-cbor's simple values are only false /
     * true / null (:60-61) and no DHT v2 schema of this package carries a
     * float — refused; false / true / null are read by dht2_cbor_rd_bool /
     * _true / _null alone (single byte, no argument). */
    if (*mt == MT_7) {
        return rd_fail(r);
    }
    *arg = v;
    return 0;
}

int dht2_cbor_rd_map(dht2_cbor_rd_t *r, uint64_t *count)
{
    unsigned mt;

    if (rd_head(r, &mt, count) != 0) {
        return -1;
    }
    if (mt != MT_MAP) {
        return rd_fail(r);
    }
    return 0;
}

int dht2_cbor_rd_array(dht2_cbor_rd_t *r, uint64_t *count)
{
    unsigned mt;

    if (rd_head(r, &mt, count) != 0) {
        return -1;
    }
    if (mt != MT_ARRAY) {
        return rd_fail(r);
    }
    return 0;
}

int dht2_cbor_rd_uint(dht2_cbor_rd_t *r, uint64_t *v)
{
    unsigned mt;

    if (rd_head(r, &mt, v) != 0) {
        return -1;
    }
    if (mt != MT_UINT) {
        return rd_fail(r);              /* incl. MT_NEG: row 6 */
    }
    return 0;
}

static int rd_string(dht2_cbor_rd_t *r, unsigned want_mt,
                     const uint8_t **p, size_t *n)
{
    unsigned mt;
    uint64_t len;

    if (rd_head(r, &mt, &len) != 0) {
        return -1;
    }
    if (mt != want_mt) {
        return rd_fail(r);
    }
    if (len > (uint64_t)(r->len - r->pos)) {
        return rd_fail(r);
    }
    *p = r->buf + r->pos;
    *n = (size_t)len;
    r->pos += (size_t)len;
    return 0;
}

int dht2_cbor_rd_bytes(dht2_cbor_rd_t *r, const uint8_t **p, size_t *n)
{
    return rd_string(r, MT_BYTES, p, n);
}

int dht2_cbor_rd_text(dht2_cbor_rd_t *r, const uint8_t **p, size_t *n)
{
    return rd_string(r, MT_TEXT, p, n);
}

int dht2_cbor_rd_key(dht2_cbor_rd_t *r, const uint8_t *prev, size_t prev_len,
                     const uint8_t **key, size_t *key_len)
{
    if (dht2_cbor_rd_text(r, key, key_len) != 0) {
        return -1;
    }
    /* "sorted in (byte-wise) lexical order, including their major type 3
     * and length. Therefore, the keys are sorted by length first"
     * (spec :58). With shortest-form heads, comparing (length, bytes) is
     * the same as comparing the encoded keys. STRICTLY ascending, so a
     * repeated key is refused. */
    if (prev != NULL) {
        int c;

        if (*key_len < prev_len) {
            return rd_fail(r);
        }
        if (*key_len == prev_len) {
            c = (prev_len == 0) ? 0 : memcmp(*key, prev, prev_len);
            if (c <= 0) {
                return rd_fail(r);
            }
        }
    }
    return 0;
}

int dht2_cbor_rd_true(dht2_cbor_rd_t *r)
{
    if (r->err || r->pos >= r->len) {
        return rd_fail(r);
    }
    if (r->buf[r->pos] != 0xF5u) {
        return rd_fail(r);
    }
    r->pos++;
    return 0;
}

int dht2_cbor_rd_bool(dht2_cbor_rd_t *r, bool *v)
{
    if (r->err || r->pos >= r->len) {
        return rd_fail(r);
    }
    if (r->buf[r->pos] == 0xF4u) {
        *v = false;
    } else if (r->buf[r->pos] == 0xF5u) {
        *v = true;
    } else {
        return rd_fail(r);
    }
    r->pos++;
    return 0;
}

int dht2_cbor_rd_null(dht2_cbor_rd_t *r)
{
    if (r->err || r->pos >= r->len) {
        return rd_fail(r);
    }
    if (r->buf[r->pos] != 0xF6u) {
        return rd_fail(r);
    }
    r->pos++;
    return 0;
}

int dht2_cbor_rd_peek_mt(const dht2_cbor_rd_t *r)
{
    if (r->err || r->pos >= r->len) {
        return -1;
    }
    return (int)(r->buf[r->pos] >> 5);
}

bool dht2_cbor_rd_peek_null(const dht2_cbor_rd_t *r)
{
    return !r->err && r->pos < r->len && r->buf[r->pos] == 0xF6u;
}

bool dht2_cbor_rd_done(const dht2_cbor_rd_t *r)
{
    return !r->err && r->pos == r->len;
}

bool dht2_cbor_key_is(const uint8_t *key, size_t key_len, const char *lit)
{
    size_t n = strlen(lit);

    return key_len == n && memcmp(key, lit, n) == 0;
}

/* ══ writer ═══════════════════════════════════════════════════════════ */

void dht2_cbor_wr_init(dht2_cbor_wr_t *w, uint8_t *buf, size_t cap)
{
    w->mode = DHT2_WR_WRITE;
    w->buf  = buf;
    w->ref  = NULL;
    w->cap  = (buf == NULL) ? 0 : cap;
    w->len  = 0;
    w->err  = (buf == NULL);
}

void dht2_cbor_wr_init_count(dht2_cbor_wr_t *w)
{
    w->mode = DHT2_WR_COUNT;
    w->buf  = NULL;
    w->ref  = NULL;
    w->cap  = SIZE_MAX;
    w->len  = 0;
    w->err  = false;
}

void dht2_cbor_wr_init_compare(dht2_cbor_wr_t *w, const uint8_t *ref,
                               size_t ref_len)
{
    w->mode = DHT2_WR_COMPARE;
    w->buf  = NULL;
    w->ref  = ref;
    w->cap  = (ref == NULL) ? 0 : ref_len;
    w->len  = 0;
    w->err  = (ref == NULL && ref_len != 0);
}

bool dht2_cbor_wr_ok(const dht2_cbor_wr_t *w)
{
    if (w->err) {
        return false;
    }
    if (w->mode == DHT2_WR_COMPARE) {
        return w->len == w->cap;
    }
    return true;
}

size_t dht2_cbor_head_size(uint64_t v)
{
    if (v < 24u) {
        return 1;
    }
    if (v <= 0xFFu) {
        return 2;
    }
    if (v <= 0xFFFFu) {
        return 3;
    }
    if (v <= 0xFFFFFFFFu) {
        return 5;
    }
    return 9;
}

static void wr_raw(dht2_cbor_wr_t *w, const uint8_t *p, size_t n)
{
    if (w->err) {
        return;
    }
    if (n > w->cap - w->len) {
        w->err = true;
        return;
    }
    if (n != 0) {
        if (w->mode == DHT2_WR_WRITE) {
            memcpy(w->buf + w->len, p, n);
        } else if (w->mode == DHT2_WR_COMPARE) {
            if (memcmp(w->ref + w->len, p, n) != 0) {
                w->err = true;
                return;
            }
        }
    }
    w->len += n;
}

/* The shortest head for (major type, argument) — the encoder half of
 * dag-cbor/spec.md :55-56. */
static void wr_head(dht2_cbor_wr_t *w, unsigned mt, uint64_t v)
{
    uint8_t tmp[9];
    size_t  hs = dht2_cbor_head_size(v);
    size_t  k;

    if (hs == 1) {
        tmp[0] = (uint8_t)((mt << 5) | (unsigned)v);
    } else {
        unsigned ai = (hs == 2) ? 24u : (hs == 3) ? 25u : (hs == 5) ? 26u : 27u;

        tmp[0] = (uint8_t)((mt << 5) | ai);
        for (k = 1; k < hs; k++) {
            tmp[k] = (uint8_t)(v >> (8u * (unsigned)(hs - 1 - k)));
        }
    }
    wr_raw(w, tmp, hs);
}

void dht2_cbor_wr_map(dht2_cbor_wr_t *w, uint64_t count)
{
    wr_head(w, MT_MAP, count);
}

void dht2_cbor_wr_uint(dht2_cbor_wr_t *w, uint64_t v)
{
    wr_head(w, MT_UINT, v);
}

void dht2_cbor_wr_bytes(dht2_cbor_wr_t *w, const uint8_t *p, size_t n)
{
    if (p == NULL && n != 0) {
        w->err = true;
        return;
    }
    wr_head(w, MT_BYTES, (uint64_t)n);
    wr_raw(w, p, n);
}

void dht2_cbor_wr_text(dht2_cbor_wr_t *w, const uint8_t *p, size_t n)
{
    if (p == NULL && n != 0) {
        w->err = true;
        return;
    }
    wr_head(w, MT_TEXT, (uint64_t)n);
    wr_raw(w, p, n);
}

void dht2_cbor_wr_key(dht2_cbor_wr_t *w, const char *lit)
{
    dht2_cbor_wr_text(w, (const uint8_t *)lit, strlen(lit));
}

void dht2_cbor_wr_true(dht2_cbor_wr_t *w)
{
    static const uint8_t t = 0xF5u;

    wr_raw(w, &t, 1);
}

void dht2_cbor_wr_bool(dht2_cbor_wr_t *w, bool v)
{
    uint8_t b = v ? 0xF5u : 0xF4u;

    wr_raw(w, &b, 1);
}

void dht2_cbor_wr_null(dht2_cbor_wr_t *w)
{
    static const uint8_t n = 0xF6u;

    wr_raw(w, &n, 1);
}

void dht2_cbor_wr_array(dht2_cbor_wr_t *w, uint64_t count)
{
    wr_head(w, MT_ARRAY, count);
}
