/**
 * @file shared/dnac/cmt_pb.c
 * @brief cometbft @709fd12b's proto3 wire encoding in C — see cmt_pb.h.
 *
 * ── How the encoder is shaped, and why ─────────────────────────────────
 * The generated `MarshalToSizedBuffer` writes a message BACKWARDS from the
 * end of the buffer: the last field first, and each length-delimited field
 * as body, then length, then tag. That order is what lets it emit a nested
 * message without a separate size pass — the size is simply how far the
 * cursor moved. This file does the same, so every `_wr` function below
 * writes its fields in DESCENDING field-number order and the finished
 * bytes come out in ascending order, exactly as the reference's do. The
 * public `_marshal` entry points then move the result to the front of the
 * caller's buffer.
 *
 * ── How the decoder is shaped ──────────────────────────────────────────
 * Each `_merge` function is the message's generated `Unmarshal`: a
 * tag loop, a wire-type check per known field, `skipTypes` for anything
 * unknown, scalars last-one-wins, repeated fields appended, and a
 * non-repeated embedded message MERGED into what is already there. The
 * public `_unmarshal` calls `_init` first, exactly as Go allocates a zero
 * message before calling Unmarshal.
 *
 * Every bounds check the Go runtime performs implicitly is written out
 * here (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * ── Where the reference citations sit ──────────────────────────────────
 * Each message's `_wr` carries its generated MarshalToSizedBuffer range
 * and each `_merge` (or, where there is none, the public `_unmarshal`)
 * carries its generated Unmarshal range. The `_init` and `_marshal`
 * wrappers carry none, because they have no Go counterpart of their own:
 * `_init` is Go's zero value for the struct and `_marshal` is the
 * generated `Marshal()` shim that only sizes a buffer and calls
 * MarshalToSizedBuffer, which is cited on the `_wr` it calls.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_pb.h"

#include <string.h>

/* ══ writer (backward, mirroring MarshalToSizedBuffer) ════════════════ */

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   i;      /* cursor; bytes live in [i, cap) */
    int      err;
} pb_w_t;

static void w_init(pb_w_t *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->i   = cap;
    w->err = CMT_OK;
}

/* Prepend n bytes. */
static void w_raw(pb_w_t *w, const uint8_t *src, size_t n)
{
    if (w->err != CMT_OK) {
        return;
    }
    if (n > w->i) {
        w->err = CMT_REJECT;
        return;
    }
    w->i -= n;
    if (n != 0) {
        memcpy(w->buf + w->i, src, n);
    }
}

/* cometbft@709fd12b types.pb.go:2520-2522 — sovTypes(),
 * (bits.Len64(x|1) + 6) / 7 */
size_t cmt_pb_uvarint_size(uint64_t v)
{
    size_t n = 1;

    while (v >= 0x80u) {
        v >>= 7;
        n++;
    }
    return n;
}

/* cometbft's `encodeVarintTypes`, writing backwards. */
static void w_uvarint(pb_w_t *w, uint64_t v)
{
    uint8_t tmp[10];
    size_t  n = 0;

    while (v >= 0x80u) {
        tmp[n++] = (uint8_t)((v & 0x7Fu) | 0x80u);
        v >>= 7;
    }
    tmp[n++] = (uint8_t)v;
    w_raw(w, tmp, n);
}

static void w_tag(pb_w_t *w, uint32_t field, uint32_t wt)
{
    w_uvarint(w, ((uint64_t)field << 3) | (uint64_t)wt);
}

/* sfixed64 — 8 bytes little-endian (canonical height/round). */
static void w_fixed64(pb_w_t *w, uint64_t v)
{
    uint8_t tmp[8];
    int     k;

    for (k = 0; k < 8; k++) {
        tmp[k] = (uint8_t)((v >> (unsigned)(8 * k)) & 0xFFu);
    }
    w_raw(w, tmp, 8);
}

/* ── field writers. Each is a no-op when the field is zero/empty, which
 *    is K-1 rev 2 rule (a). ──────────────────────────────────────────── */

static void wf_varint(pb_w_t *w, uint32_t field, uint64_t v)
{
    if (v == 0) {
        return;
    }
    w_uvarint(w, v);
    w_tag(w, field, 0);
}

static void wf_sfixed64(pb_w_t *w, uint32_t field, int64_t v)
{
    if (v == 0) {
        return;
    }
    w_fixed64(w, (uint64_t)v);
    w_tag(w, field, 1);
}

static void wf_bytes(pb_w_t *w, uint32_t field, const uint8_t *b, size_t n)
{
    if (n == 0) {
        return;
    }
    if (b == NULL) {
        w->err = CMT_REJECT;
        return;
    }
    w_raw(w, b, n);
    w_uvarint(w, (uint64_t)n);
    w_tag(w, field, 2);
}

/* An ELEMENT of a `repeated bytes` field, written UNCONDITIONALLY — an
 * empty element is a real `tag ‖ 00` on the wire, not an omission.
 * The generated code guards only the SLICE (`if len(m.Txs) > 0`) and
 * never the element inside the loop: types.pb.go:1552-1560 (Data.txs)
 * and crypto/proof.pb.go:373-381 (Proof.aunts) both write
 * `copy; encodeVarint(len); tag` for every iteration, len 0 included.
 * wf_bytes() above omits an empty value, which is rule (a) for a
 * SINGULAR field and WRONG for an element of a repeated one. */
static void wf_bytes_elem(pb_w_t *w, uint32_t field, const uint8_t *b,
                          size_t n)
{
    if (n != 0) {
        if (b == NULL) {
            w->err = CMT_REJECT;
            return;
        }
        w_raw(w, b, n);
    }
    w_uvarint(w, (uint64_t)n);
    w_tag(w, field, 2);
}

/* Frame whatever was written since `before` as field `field`. Used for
 * both ALWAYS-emitted (called unconditionally) and POINTER (called only
 * when present) embedded messages. */
static void wf_close_msg(pb_w_t *w, uint32_t field, size_t before)
{
    size_t size;

    if (w->err != CMT_OK) {
        return;
    }
    size = before - w->i;
    w_uvarint(w, (uint64_t)size);
    w_tag(w, field, 2);
}

/* Move the finished message to the front of the caller's buffer. */
static int w_finish(pb_w_t *w, size_t *out_len)
{
    size_t n;

    if (w->err != CMT_OK) {
        return w->err;
    }
    n = w->cap - w->i;
    if (n != 0 && w->i != 0) {
        memmove(w->buf, w->buf + w->i, n);
    }
    if (out_len != NULL) {
        *out_len = n;
    }
    return CMT_OK;
}

/* cometbft@709fd12b types.pb.go:2145-2155 — encodeVarintTypes(), written
 * forwards here because this entry point has no backward cursor. */
int cmt_pb_put_uvarint(uint8_t *out, size_t cap, size_t *off, uint64_t v)
{
    size_t need;

    if (out == NULL || off == NULL) {
        return CMT_FAULT;
    }
    need = cmt_pb_uvarint_size(v);
    if (*off > cap || need > cap - *off) {
        return CMT_REJECT;
    }
    while (v >= 0x80u) {
        out[(*off)++] = (uint8_t)((v & 0x7Fu) | 0x80u);
        v >>= 7;
    }
    out[(*off)++] = (uint8_t)v;
    return CMT_OK;
}

/* ══ reader (forward, mirroring the generated Unmarshal) ══════════════ */

/* cometbft@709fd12b types.pb.go:3395-3406 — the generated varint reader
 * that opens every Unmarshal tag loop: `shift >= 64` is ErrIntOverflow
 * and running past the end is io.ErrUnexpectedEOF. */
int cmt_pb_get_uvarint(const uint8_t *in, size_t len, size_t *off,
                       uint64_t *v)
{
    unsigned shift = 0;
    uint64_t acc = 0;

    if (in == NULL || off == NULL || v == NULL) {
        return CMT_FAULT;
    }
    for (;;) {
        uint8_t b;

        if (shift >= 64u) {
            return CMT_REJECT;          /* ErrIntOverflow */
        }
        if (*off >= len) {
            return CMT_REJECT;          /* io.ErrUnexpectedEOF */
        }
        b = in[*off];
        (*off)++;
        acc |= (uint64_t)(b & 0x7Fu) << shift;
        if (b < 0x80u) {
            break;
        }
        shift += 7u;
    }
    *v = acc;
    return CMT_OK;
}

/* cometbft's `skipTypes`, advancing *off past one whole field. Group
 * markers (wire types 3 and 4) are handled with the same depth counter;
 * every index arithmetic is bounds-checked BEFORE it is used, where Go
 * lets the value run past the end and rejects it in the caller. */
static int pb_skip(const uint8_t *in, size_t len, size_t *off)
{
    int depth = 0;

    while (*off < len) {
        uint64_t wire;
        uint32_t wt;

        if (cmt_pb_get_uvarint(in, len, off, &wire) != CMT_OK) {
            return CMT_REJECT;
        }
        wt = (uint32_t)(wire & 7u);
        switch (wt) {
        case 0: {
            uint64_t dummy;

            if (cmt_pb_get_uvarint(in, len, off, &dummy) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
        case 1:
            if (len - *off < 8u) {
                return CMT_REJECT;
            }
            *off += 8u;
            break;
        case 2: {
            uint64_t length;

            if (cmt_pb_get_uvarint(in, len, off, &length) != CMT_OK) {
                return CMT_REJECT;
            }
            if (length > (uint64_t)(len - *off)) {
                return CMT_REJECT;
            }
            *off += (size_t)length;
            break;
        }
        case 3:
            depth++;
            break;
        case 4:
            if (depth == 0) {
                return CMT_REJECT;      /* ErrUnexpectedEndOfGroup */
            }
            depth--;
            break;
        case 5:
            if (len - *off < 4u) {
                return CMT_REJECT;
            }
            *off += 4u;
            break;
        default:
            return CMT_REJECT;          /* illegal wireType */
        }
        if (depth == 0) {
            return CMT_OK;
        }
    }
    return CMT_REJECT;                  /* io.ErrUnexpectedEOF */
}

/* Read a length-delimited field's payload. */
static int r_ld(const uint8_t *in, size_t len, size_t *off,
                const uint8_t **p, size_t *n)
{
    uint64_t length;

    if (cmt_pb_get_uvarint(in, len, off, &length) != CMT_OK) {
        return CMT_REJECT;
    }
    if (length > (uint64_t)(len - *off)) {
        return CMT_REJECT;              /* io.ErrUnexpectedEOF */
    }
    *p = in + *off;
    *n = (size_t)length;
    *off += (size_t)length;
    return CMT_OK;
}

static int r_fixed64(const uint8_t *in, size_t len, size_t *off, uint64_t *v)
{
    uint64_t acc = 0;
    int      k;

    if (len - *off < 8u) {
        return CMT_REJECT;
    }
    for (k = 7; k >= 0; k--) {
        acc = (acc << 8) | (uint64_t)in[*off + (size_t)k];
    }
    *off += 8u;
    *v = acc;
    return CMT_OK;
}

/* Copy a wire byte field into a fixed-capacity destination. A length
 * beyond the destination is REFUSED — a capacity rule, not a semantic
 * one; see cmt_pb.h. */
static int r_copy_fixed(uint8_t *dst, size_t cap, size_t *dst_len,
                        const uint8_t *src, size_t n)
{
    if (n > cap) {
        return CMT_REJECT;
    }
    if (n != 0) {
        memcpy(dst, src, n);
    }
    *dst_len = n;
    return CMT_OK;
}

/* Copy a variable-length payload into the caller's arena. No pointer into
 * the input buffer survives (see cmt_pb.h). */
static int r_copy_arena(cmt_pb_arena_t *a, const uint8_t *src, size_t n,
                        cmt_pb_bytes_t *out)
{
    if (n == 0) {
        out->data = NULL;
        out->len  = 0;
        return CMT_OK;
    }
    if (a == NULL || a->buf == NULL || a->used > a->cap ||
        n > a->cap - a->used) {
        return CMT_REJECT;
    }
    memcpy(a->buf + a->used, src, n);
    out->data = a->buf + a->used;
    out->len  = n;
    a->used += n;
    return CMT_OK;
}

/* The head of every generated Unmarshal's tag loop. Returns CMT_OK and
 * sets *fieldnum / *wt, or CMT_REJECT.
 *
 * NOTE reference quirk: the generated code computes
 * `fieldNum := int32(wire >> 3)` — a TRUNCATION — and then switches on it.
 * A tag whose field number exceeds 32 bits therefore aliases a real field
 * in the reference. Reproduced here rather than tightened, because
 * "unknown-field handling exactly as the generated code does it" is the
 * rule; recorded as a malleability note. */
static int r_tag(const uint8_t *in, size_t len, size_t *off,
                 int32_t *fieldnum, uint32_t *wt)
{
    uint64_t wire;

    if (cmt_pb_get_uvarint(in, len, off, &wire) != CMT_OK) {
        return CMT_REJECT;
    }
    *wt = (uint32_t)(wire & 7u);
    if (*wt == 4u) {
        return CMT_REJECT;              /* end group for non-group */
    }
    *fieldnum = (int32_t)(uint32_t)(wire >> 3);
    if (*fieldnum <= 0) {
        return CMT_REJECT;              /* illegal tag */
    }
    return CMT_OK;
}

/* ══ MarshalDelimited ═════════════════════════════════════════════════ */

/* cometbft@709fd12b libs/protoio/writer.go:96-103, :78-86 */
int cmt_pb_marshal_delimited(const uint8_t *msg, size_t msg_len,
                             uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = 0;
    int    rc;

    if (out == NULL || out_len == NULL || (msg == NULL && msg_len != 0)) {
        return CMT_FAULT;
    }
    rc = cmt_pb_put_uvarint(out, cap, &n, (uint64_t)msg_len);   /* :80 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (msg_len > cap - n) {
        return CMT_REJECT;
    }
    if (msg_len != 0) {
        memcpy(out + n, msg, msg_len);                          /* :85 */
    }
    *out_len = n + msg_len;
    return CMT_OK;
}

/* ══ Timestamp ════════════════════════════════════════════════════════ */

void cmt_pb_timestamp_init(cmt_time_t *m)
{
    if (m != NULL) {
        *m = CMT_TIME_ZERO;
    }
}

/* gogoproto timestamp.pb.go:325-334 — Timestamp.MarshalToSizedBuffer,
 * reached through StdTimeMarshalTo (timestamp_gogo.go:75-81), which first
 * runs TimestampProto (timestamp.go:111-120) → validateTimestamp (called
 * at :116) and fails on an out-of-range value. */
static int ts_wr(pb_w_t *w, const cmt_time_t *m)
{
    if (cmt_time_validate(*m) != CMT_OK) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    wf_varint(w, 2, (uint64_t)(int64_t)m->nanos);   /* tag 0x10 */
    wf_varint(w, 1, (uint64_t)m->seconds);          /* tag 0x08 */
    return CMT_OK;
}

int cmt_pb_timestamp_marshal(const cmt_time_t *m, uint8_t *out, size_t cap,
                             size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (ts_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b gogoproto timestamp.pb.go:373-461 —
 * Timestamp.Unmarshal, then TimestampFromProto (timestamp.go:88-98) →
 * validateTimestamp, which it returns at :97. */
static int ts_merge(const uint8_t *in, size_t len, cmt_time_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->seconds = (int64_t)v;
        } else if (fieldnum == 2) {
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            /* int32 field: Go accumulates in an int32 whose high bits
             * shift out; the truncation is written explicitly here
             * because shifting a 32-bit type by 32 or more is undefined
             * in C. The resulting value is identical. */
            m->nanos = (int32_t)(uint32_t)v;
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_timestamp_unmarshal(const uint8_t *in, size_t len, cmt_time_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    /* An absent Timestamp message is the proto zero {0, 0}, i.e. the Unix
     * epoch — NOT Go's zero time. TimestampFromProto builds exactly that
     * from an all-default Timestamp: `time.Unix(ts.Seconds,
     * int64(ts.Nanos)).UTC()` at timestamp.go:95, so the decode default
     * here is {0, 0} and not CMT_TIME_ZERO. */
    m->seconds = 0;
    m->nanos   = 0;
    if (ts_merge(in, len, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return cmt_time_validate(*m);        /* timestamp.go:97 */
}

/* ══ wrappers / cdcEncode (K-1 rev 2 rule d) ══════════════════════════ */

/* cometbft@709fd12b gogoproto wrappers.pb.go:1331-1346 Int64Value,
 * :1496-1513 StringValue, :1530-1547 BytesValue — each a single field 1,
 * omit-zero. cmt_pb_cdc_encode_string and _bytes below are the two
 * length-delimited branches of this same comment, via cdc_encode_ld. */
int cmt_pb_cdc_encode_int64(int64_t v, uint8_t *out, size_t cap,
                            size_t *out_len, bool *is_nil)
{
    pb_w_t w;

    if (out_len == NULL) {
        return CMT_FAULT;
    }
    /* encoding_helper.go:23-31: an int64 is never isEmpty (utils.go falls
     * to its default for a non-container), so this branch is always taken
     * and Int64Value{0} is a NON-nil, zero-length encoding. */
    if (is_nil != NULL) {
        *is_nil = false;
    }
    w_init(&w, out, cap);
    wf_varint(&w, 1, (uint64_t)v);
    return w_finish(&w, out_len);
}

static int cdc_encode_ld(const uint8_t *b, size_t b_len, uint8_t *out,
                         size_t cap, size_t *out_len, bool *is_nil)
{
    pb_w_t w;

    if (out_len == NULL) {
        return CMT_FAULT;
    }
    /* encoding_helper.go:12 — isEmpty() is true for a zero-length string
     * or byte slice, and cdcEncode then returns nil (:46). */
    if (b_len == 0) {
        if (is_nil != NULL) {
            *is_nil = true;
        }
        *out_len = 0;
        return CMT_OK;
    }
    if (is_nil != NULL) {
        *is_nil = false;
    }
    w_init(&w, out, cap);
    wf_bytes(&w, 1, b, b_len);
    return w_finish(&w, out_len);
}

int cmt_pb_cdc_encode_string(const uint8_t *s, size_t s_len, uint8_t *out,
                             size_t cap, size_t *out_len, bool *is_nil)
{
    return cdc_encode_ld(s, s_len, out, cap, out_len, is_nil);
}

int cmt_pb_cdc_encode_bytes(const uint8_t *b, size_t b_len, uint8_t *out,
                            size_t cap, size_t *out_len, bool *is_nil)
{
    return cdc_encode_ld(b, b_len, out, cap, out_len, is_nil);
}

/* ══ version.Consensus ════════════════════════════════════════════════ */

void cmt_pb_consensus_init(cmt_pb_consensus_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* version/types.pb.go:238-254 */
static int consensus_wr(pb_w_t *w, const cmt_pb_consensus_t *m)
{
    wf_varint(w, 2, m->app);
    wf_varint(w, 1, m->block);
    return CMT_OK;
}

int cmt_pb_consensus_marshal(const cmt_pb_consensus_t *m, uint8_t *out,
                             size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    consensus_wr(&w, m);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b version/types.pb.go:405-492 — Consensus.Unmarshal */
static int consensus_merge(const uint8_t *in, size_t len,
                           cmt_pb_consensus_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1 || fieldnum == 2) {
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                m->block = v;
            } else {
                m->app = v;
            }
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_consensus_unmarshal(const uint8_t *in, size_t len,
                               cmt_pb_consensus_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_consensus_init(m);
    return consensus_merge(in, len, m);
}

/* ══ PartSetHeader / CanonicalPartSetHeader ═══════════════════════════ */

void cmt_pb_part_set_header_init(cmt_pb_part_set_header_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* cometbft@709fd12b types.pb.go:1301-1319 —
 * PartSetHeader.MarshalToSizedBuffer; canonical.pb.go's
 * CanonicalPartSetHeader is byte-identical ({uint32 total = 1,
 * bytes hash = 2}). */
static int psh_wr(pb_w_t *w, const cmt_pb_part_set_header_t *m)
{
    wf_bytes(w, 2, m->hash, m->hash_len);
    wf_varint(w, 1, (uint64_t)m->total);
    return CMT_OK;
}

int cmt_pb_part_set_header_marshal(const cmt_pb_part_set_header_t *m,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->hash_len > CMT_PB_HASH_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    psh_wr(&w, m);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:2526-2628 PartSetHeader.Unmarshal;
 * canonical.pb.go:938-1040 CanonicalPartSetHeader.Unmarshal is the same
 * two fields and shares this function. */
static int psh_merge(const uint8_t *in, size_t len,
                     cmt_pb_part_set_header_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            uint64_t v;

            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->total = (uint32_t)v;     /* Go truncates to uint32 too */
        } else if (fieldnum == 2) {
            const uint8_t *p;
            size_t         n;

            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->hash, CMT_PB_HASH_MAX, &m->hash_len, p, n)
                != CMT_OK) {
                return CMT_REJECT;
            }
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_part_set_header_unmarshal(const uint8_t *in, size_t len,
                                     cmt_pb_part_set_header_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_part_set_header_init(m);
    return psh_merge(in, len, m);
}

void cmt_pb_canonical_part_set_header_init(
    cmt_pb_canonical_part_set_header_t *m)
{
    cmt_pb_part_set_header_init(m);
}

int cmt_pb_canonical_part_set_header_marshal(
    const cmt_pb_canonical_part_set_header_t *m, uint8_t *out, size_t cap,
    size_t *out_len)
{
    return cmt_pb_part_set_header_marshal(m, out, cap, out_len);
}

int cmt_pb_canonical_part_set_header_unmarshal(
    const uint8_t *in, size_t len, cmt_pb_canonical_part_set_header_t *m)
{
    return cmt_pb_part_set_header_unmarshal(in, len, m);
}

/* ══ BlockID / CanonicalBlockID ═══════════════════════════════════════ */

void cmt_pb_block_id_init(cmt_pb_block_id_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* types.pb.go:1386-1395 — part_set_header is (nullable) = false and is
 * ALWAYS emitted; a zero BlockID is therefore `12 00`, never empty. */
static int block_id_wr(pb_w_t *w, const cmt_pb_block_id_t *m)
{
    size_t before = w->i;

    psh_wr(w, &m->part_set_header);
    wf_close_msg(w, 2, before);
    wf_bytes(w, 1, m->hash, m->hash_len);
    return CMT_OK;
}

int cmt_pb_block_id_marshal(const cmt_pb_block_id_t *m, uint8_t *out,
                            size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->hash_len > CMT_PB_HASH_MAX ||
        m->part_set_header.hash_len > CMT_PB_HASH_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    block_id_wr(&w, m);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:2765-2881 BlockID.Unmarshal;
 * canonical.pb.go:821-937 CanonicalBlockID.Unmarshal is the same two
 * fields and shares this function. */
static int block_id_merge(const uint8_t *in, size_t len,
                          cmt_pb_block_id_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->hash, CMT_PB_HASH_MAX, &m->hash_len, p, n)
                != CMT_OK) {
                return CMT_REJECT;
            }
        } else if (fieldnum == 2) {
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            /* Non-repeated embedded message: MERGE, as the generated code
             * does by calling Unmarshal on the existing sub-message. */
            if (psh_merge(p, n, &m->part_set_header) != CMT_OK) {
                return CMT_REJECT;
            }
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_block_id_unmarshal(const uint8_t *in, size_t len,
                              cmt_pb_block_id_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_block_id_init(m);
    return block_id_merge(in, len, m);
}

void cmt_pb_canonical_block_id_init(cmt_pb_canonical_block_id_t *m)
{
    cmt_pb_block_id_init(m);
}

int cmt_pb_canonical_block_id_marshal(const cmt_pb_canonical_block_id_t *m,
                                      uint8_t *out, size_t cap,
                                      size_t *out_len)
{
    return cmt_pb_block_id_marshal(m, out, cap, out_len);
}

int cmt_pb_canonical_block_id_unmarshal(const uint8_t *in, size_t len,
                                        cmt_pb_canonical_block_id_t *m)
{
    return cmt_pb_block_id_unmarshal(in, len, m);
}

/* ══ crypto.Proof ═════════════════════════════════════════════════════ */

void cmt_pb_proof_init(cmt_proof_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* crypto/proof.pb.go:373-381 — aunts is `repeated bytes`, one tag each,
 * emitted in order (the generated code walks the slice backwards so the
 * finished bytes are in forward order). */
static int proof_wr(pb_w_t *w, const cmt_proof_t *m)
{
    size_t k;

    if (m->aunts_len > CMT_MERKLE_MAX_AUNTS) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = m->aunts_len; k > 0; k--) {
        if (m->aunt_len[k - 1] > CMT_TMHASH_SIZE) {
            w->err = CMT_REJECT;
            return CMT_REJECT;
        }
        wf_bytes_elem(w, 4, m->aunts[k - 1], m->aunt_len[k - 1]);
    }
    wf_bytes(w, 3, m->leaf_hash, m->leaf_hash_len);
    wf_varint(w, 2, (uint64_t)m->index);
    wf_varint(w, 1, (uint64_t)m->total);
    return CMT_OK;
}

int cmt_pb_proof_marshal(const cmt_proof_t *m, uint8_t *out, size_t cap,
                         size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->leaf_hash_len > CMT_TMHASH_SIZE) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    if (proof_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b crypto/proof.pb.go:685-838 — Proof.Unmarshal */
static int proof_merge(const uint8_t *in, size_t len, cmt_proof_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
        case 2:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                m->total = (int64_t)v;
            } else {
                m->index = (int64_t)v;
            }
            break;
        case 3:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->leaf_hash, CMT_TMHASH_SIZE,
                             &m->leaf_hash_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            /* Bounded by MaxAunts here, where Go would append without a
             * limit and let ValidateBasic complain afterwards. Refusing at
             * the message boundary is the INVARIANT; the count that
             * ValidateBasic checks is the same 100. */
            if (m->aunts_len >= CMT_MERKLE_MAX_AUNTS) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->aunts[m->aunts_len], CMT_TMHASH_SIZE,
                             &m->aunt_len[m->aunts_len], p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            m->aunts_len++;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_proof_unmarshal(const uint8_t *in, size_t len, cmt_proof_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_proof_init(m);
    return proof_merge(in, len, m);
}

/* crypto/merkle/proof.go:134-146 — ToProto(): a field-for-field copy. */
int cmt_proof_to_proto(const cmt_proof_t *sp, cmt_proof_t *out)
{
    if (sp == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *sp;
    return CMT_OK;
}

/* crypto/merkle/proof.go:148-161 — ProofFromProto(): decode, then :160
 * `return sp, sp.ValidateBasic()`. */
int cmt_proof_from_proto(const uint8_t *in, size_t len, cmt_proof_t *out)
{
    int rc = cmt_pb_proof_unmarshal(in, len, out);

    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_proof_validate_basic(out);
}

/* ══ types.Part ═══════════════════════════════════════════════════════ */

void cmt_pb_part_init(cmt_pb_part_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* types.pb.go:1341-1350 — proof is (nullable) = false, ALWAYS emitted. */
static int part_wr(pb_w_t *w, const cmt_pb_part_t *m)
{
    size_t before = w->i;

    if (proof_wr(w, &m->proof) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(w, 3, before);
    wf_bytes(w, 2, m->bytes.data, m->bytes.len);
    wf_varint(w, 1, (uint64_t)m->index);
    return CMT_OK;
}

int cmt_pb_part_marshal(const cmt_pb_part_t *m, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (part_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:2629-2764 — Part.Unmarshal */
static int part_merge(const uint8_t *in, size_t len, cmt_pb_part_t *m,
                      cmt_pb_arena_t *a)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->index = (uint32_t)v;
            break;
        case 2:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_arena(a, p, n, &m->bytes) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (proof_merge(p, n, &m->proof) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_part_unmarshal(const uint8_t *in, size_t len, cmt_pb_part_t *m,
                          cmt_pb_arena_t *arena)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_part_init(m);
    return part_merge(in, len, m, arena);
}

/* ══ crypto.PublicKey (K-2: ML-DSA-87 is branch 9) ════════════════════ */

void cmt_pb_public_key_init(cmt_pb_public_key_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* keys.pb.go:354-386 writes the chosen branch's own tag. Branch 9,
 * wire type 2, tag byte 0x4a (K-2). */
static int public_key_wr(pb_w_t *w, const cmt_pb_public_key_t *m)
{
    if (!m->present) {
        return CMT_OK;              /* a nil oneof writes nothing */
    }
    wf_bytes(w, 9, m->key, CMT_PB_PUBKEY_LEN);
    return CMT_OK;
}

int cmt_pb_public_key_marshal(const cmt_pb_public_key_t *m, uint8_t *out,
                              size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    public_key_wr(&w, m);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b crypto/keys.pb.go:457-572 — PublicKey.Unmarshal.
 * DEVIATION: the generated decoder skips an unknown branch; this one
 * REFUSES every field but 9, per K-2 (ML-DSA-87 is the only branch). */
static int public_key_merge(const uint8_t *in, size_t len,
                            cmt_pb_public_key_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        /* K-2: branches 1 (ed25519) and 2 (secp256k1) stay in the pinned
         * .proto but are never produced here, and any other field number
         * is refused rather than skipped — a PublicKey this chain did not
         * write must not decode into a validator identity. */
        if (fieldnum != 9) {
            return CMT_REJECT;
        }
        if (wt != 2u) {
            return CMT_REJECT;
        }
        if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
            return CMT_REJECT;
        }
        /* The size rule of crypto/encoding/codec.go:42-63, with the
         * ML-DSA-87 length. */
        if (n != CMT_PB_PUBKEY_LEN) {
            return CMT_REJECT;
        }
        memcpy(m->key, p, CMT_PB_PUBKEY_LEN);
        m->present = true;
    }
    return CMT_OK;
}

int cmt_pb_public_key_unmarshal(const uint8_t *in, size_t len,
                                cmt_pb_public_key_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_public_key_init(m);
    return public_key_merge(in, len, m);
}

/* ══ validator.SimpleValidator ════════════════════════════════════════ */

void cmt_pb_simple_validator_init(cmt_pb_simple_validator_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* validator.pb.go:403-426 — pub_key is a POINTER: omitted when nil. */
static int simple_validator_wr(pb_w_t *w, const cmt_pb_simple_validator_t *m)
{
    wf_varint(w, 2, (uint64_t)m->voting_power);
    if (m->pub_key.present) {
        size_t before = w->i;

        public_key_wr(w, &m->pub_key);
        wf_close_msg(w, 1, before);
    }
    return CMT_OK;
}

int cmt_pb_simple_validator_marshal(const cmt_pb_simple_validator_t *m,
                                    uint8_t *out, size_t cap,
                                    size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    simple_validator_wr(&w, m);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b validator.pb.go:798-902 — SimpleValidator.Unmarshal */
static int simple_validator_merge(const uint8_t *in, size_t len,
                                  cmt_pb_simple_validator_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (public_key_merge(p, n, &m->pub_key) != CMT_OK) {
                return CMT_REJECT;
            }
        } else if (fieldnum == 2) {
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->voting_power = (int64_t)v;
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_simple_validator_unmarshal(const uint8_t *in, size_t len,
                                      cmt_pb_simple_validator_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_simple_validator_init(m);
    return simple_validator_merge(in, len, m);
}

/* ══ validator.Validator ══════════════════════════════════════════════ */

void cmt_pb_validator_init(cmt_pb_validator_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* validator.pb.go:368-377 — pub_key is (nullable) = false, ALWAYS. */
static int validator_wr(pb_w_t *w, const cmt_pb_validator_t *m)
{
    size_t before;

    wf_varint(w, 4, (uint64_t)m->proposer_priority);
    wf_varint(w, 3, (uint64_t)m->voting_power);
    before = w->i;
    public_key_wr(w, &m->pub_key);
    wf_close_msg(w, 2, before);
    wf_bytes(w, 1, m->address, m->address_len);
    return CMT_OK;
}

int cmt_pb_validator_marshal(const cmt_pb_validator_t *m, uint8_t *out,
                             size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->address_len > CMT_PB_ADDRESS_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    validator_wr(&w, m);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b validator.pb.go:643-797 — Validator.Unmarshal */
static int validator_merge(const uint8_t *in, size_t len,
                           cmt_pb_validator_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->address, CMT_PB_ADDRESS_MAX,
                             &m->address_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (public_key_merge(p, n, &m->pub_key) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
        case 4:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 3) {
                m->voting_power = (int64_t)v;
            } else {
                m->proposer_priority = (int64_t)v;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_validator_unmarshal(const uint8_t *in, size_t len,
                               cmt_pb_validator_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_validator_init(m);
    return validator_merge(in, len, m);
}

/* ══ validator.ValidatorSet ═══════════════════════════════════════════ */

void cmt_pb_validator_set_init(cmt_pb_validator_set_t *m)
{
    cmt_pb_validator_t *slots;
    size_t              cap;

    if (m == NULL) {
        return;
    }
    /* The caller's storage survives init; only the contents reset. */
    slots = m->validators;
    cap   = m->validators_cap;
    memset(m, 0, sizeof(*m));
    m->validators     = slots;
    m->validators_cap = cap;
}

/* validator.pb.go:321-334 — validators is repeated (one tag each);
 * proposer is a POINTER. */
static int validator_set_wr(pb_w_t *w, const cmt_pb_validator_set_t *m)
{
    size_t k;

    wf_varint(w, 3, (uint64_t)m->total_voting_power);
    if (m->has_proposer) {
        size_t before = w->i;

        validator_wr(w, &m->proposer);
        wf_close_msg(w, 2, before);
    }
    if (m->validators_len != 0 && m->validators == NULL) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = m->validators_len; k > 0; k--) {
        size_t before = w->i;

        validator_wr(w, &m->validators[k - 1]);
        wf_close_msg(w, 1, before);
    }
    return CMT_OK;
}

int cmt_pb_validator_set_marshal(const cmt_pb_validator_set_t *m,
                                 uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (validator_set_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b validator.pb.go:504-642 — ValidatorSet.Unmarshal */
static int validator_set_merge(const uint8_t *in, size_t len,
                               cmt_pb_validator_set_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            /* Repeated message: append into the caller's storage. An
             * overflow REFUSES the message; it never grows anything. */
            if (m->validators == NULL ||
                m->validators_len >= m->validators_cap) {
                return CMT_REJECT;
            }
            cmt_pb_validator_init(&m->validators[m->validators_len]);
            if (validator_merge(p, n, &m->validators[m->validators_len])
                != CMT_OK) {
                return CMT_REJECT;
            }
            m->validators_len++;
            break;
        case 2:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (!m->has_proposer) {
                cmt_pb_validator_init(&m->proposer);
                m->has_proposer = true;
            }
            if (validator_merge(p, n, &m->proposer) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->total_voting_power = (int64_t)v;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_validator_set_unmarshal(const uint8_t *in, size_t len,
                                   cmt_pb_validator_set_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_validator_set_init(m);
    return validator_set_merge(in, len, m);
}

/* ══ types.HashedParams ═══════════════════════════════════════════════ */

void cmt_pb_hashed_params_init(cmt_pb_hashed_params_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* params.pb.go:919-935. A MaxGas of -1 is the 10-byte negative varint. */
static int hashed_params_wr(pb_w_t *w, const cmt_pb_hashed_params_t *m)
{
    wf_varint(w, 2, (uint64_t)m->block_max_gas);
    wf_varint(w, 1, (uint64_t)m->block_max_bytes);
    return CMT_OK;
}

int cmt_pb_hashed_params_marshal(const cmt_pb_hashed_params_t *m,
                                 uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    hashed_params_wr(&w, m);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b params.pb.go:1779-1866 — HashedParams.Unmarshal */
static int hashed_params_merge(const uint8_t *in, size_t len,
                               cmt_pb_hashed_params_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1 || fieldnum == 2) {
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                m->block_max_bytes = (int64_t)v;
            } else {
                m->block_max_gas = (int64_t)v;
            }
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_hashed_params_unmarshal(const uint8_t *in, size_t len,
                                   cmt_pb_hashed_params_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_hashed_params_init(m);
    return hashed_params_merge(in, len, m);
}

/* ══ types.Header ═════════════════════════════════════════════════════ */

void cmt_pb_header_init(cmt_pb_header_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    /* Go's zero Header has a zero time.Time, which is NOT {0, 0}. */
    m->time = CMT_TIME_ZERO;
}

/* types.pb.go:1426-1528 — fields 1 (version), 4 (time) and 5
 * (last_block_id) are (nullable) = false and are ALWAYS emitted. */
static int header_wr(pb_w_t *w, const cmt_pb_header_t *m)
{
    size_t before;

    wf_bytes(w, 14, m->proposer_address, m->proposer_address_len);
    wf_bytes(w, 13, m->evidence_hash, m->evidence_hash_len);
    wf_bytes(w, 12, m->last_results_hash, m->last_results_hash_len);
    wf_bytes(w, 11, m->app_hash, m->app_hash_len);
    wf_bytes(w, 10, m->consensus_hash, m->consensus_hash_len);
    wf_bytes(w, 9, m->next_validators_hash, m->next_validators_hash_len);
    wf_bytes(w, 8, m->validators_hash, m->validators_hash_len);
    wf_bytes(w, 7, m->data_hash, m->data_hash_len);
    wf_bytes(w, 6, m->last_commit_hash, m->last_commit_hash_len);

    before = w->i;
    block_id_wr(w, &m->last_block_id);
    wf_close_msg(w, 5, before);

    before = w->i;
    if (ts_wr(w, &m->time) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(w, 4, before);

    wf_varint(w, 3, (uint64_t)m->height);
    wf_bytes(w, 2, m->chain_id, m->chain_id_len);

    before = w->i;
    consensus_wr(w, &m->version);
    wf_close_msg(w, 1, before);
    return CMT_OK;
}

int cmt_pb_header_marshal(const cmt_pb_header_t *m, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->chain_id_len > CMT_PB_CHAINID_MAX ||
        m->proposer_address_len > CMT_PB_ADDRESS_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    if (header_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:2882-3387 — Header.Unmarshal */
static int header_merge(const uint8_t *in, size_t len, cmt_pb_header_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;
        uint8_t *dst = NULL;
        size_t   dst_cap = 0;
        size_t  *dst_len = NULL;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (consensus_merge(p, n, &m->version) != CMT_OK) {
                return CMT_REJECT;
            }
            continue;
        case 3:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->height = (int64_t)v;
            continue;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            /* StdTimeUnmarshal (timestamp_gogo.go:83-94) starts from a
             * FRESH Timestamp, so this field replaces rather than merges,
             * and it validates the range. */
            if (cmt_pb_timestamp_unmarshal(p, n, &m->time) != CMT_OK) {
                return CMT_REJECT;
            }
            continue;
        case 5:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (block_id_merge(p, n, &m->last_block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            continue;
        case 2:
            dst = m->chain_id; dst_cap = CMT_PB_CHAINID_MAX;
            dst_len = &m->chain_id_len; break;
        case 6:
            dst = m->last_commit_hash; dst_cap = CMT_PB_HASH_MAX;
            dst_len = &m->last_commit_hash_len; break;
        case 7:
            dst = m->data_hash; dst_cap = CMT_PB_HASH_MAX;
            dst_len = &m->data_hash_len; break;
        case 8:
            dst = m->validators_hash; dst_cap = CMT_PB_HASH_MAX;
            dst_len = &m->validators_hash_len; break;
        case 9:
            dst = m->next_validators_hash; dst_cap = CMT_PB_HASH_MAX;
            dst_len = &m->next_validators_hash_len; break;
        case 10:
            dst = m->consensus_hash; dst_cap = CMT_PB_HASH_MAX;
            dst_len = &m->consensus_hash_len; break;
        case 11:
            dst = m->app_hash; dst_cap = CMT_PB_HASH_MAX;
            dst_len = &m->app_hash_len; break;
        case 12:
            dst = m->last_results_hash; dst_cap = CMT_PB_HASH_MAX;
            dst_len = &m->last_results_hash_len; break;
        case 13:
            dst = m->evidence_hash; dst_cap = CMT_PB_HASH_MAX;
            dst_len = &m->evidence_hash_len; break;
        case 14:
            dst = m->proposer_address; dst_cap = CMT_PB_ADDRESS_MAX;
            dst_len = &m->proposer_address_len; break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            continue;
        }
        /* the eleven bytes/string fields */
        if (wt != 2u) {
            return CMT_REJECT;
        }
        if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
            return CMT_REJECT;
        }
        if (r_copy_fixed(dst, dst_cap, dst_len, p, n) != CMT_OK) {
            return CMT_REJECT;
        }
    }
    return CMT_OK;
}

int cmt_pb_header_unmarshal(const uint8_t *in, size_t len,
                            cmt_pb_header_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_header_init(m);
    return header_merge(in, len, m);
}

/* ══ types.Data ═══════════════════════════════════════════════════════ */

void cmt_pb_data_init(cmt_pb_data_t *m)
{
    cmt_pb_bytes_t *slots;
    size_t          cap;

    if (m == NULL) {
        return;
    }
    slots = m->txs;
    cap   = m->txs_cap;
    memset(m, 0, sizeof(*m));
    m->txs     = slots;
    m->txs_cap = cap;
}

/* types.pb.go:1552-1560 — repeated bytes, one tag per element. */
static int data_wr(pb_w_t *w, const cmt_pb_data_t *m)
{
    size_t k;

    if (m->txs_len != 0 && m->txs == NULL) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = m->txs_len; k > 0; k--) {
        wf_bytes_elem(w, 1, m->txs[k - 1].data, m->txs[k - 1].len);
    }
    return CMT_OK;
}

int cmt_pb_data_marshal(const cmt_pb_data_t *m, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (data_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:3388-3469 — Data.Unmarshal */
static int data_merge(const uint8_t *in, size_t len, cmt_pb_data_t *m,
                      cmt_pb_arena_t *a)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (m->txs == NULL || m->txs_len >= m->txs_cap) {
                return CMT_REJECT;
            }
            /* An empty tx is still ONE element: types.pb.go:3446-3447
             * appends `make([]byte, postIndex-iNdEx)` for every tag,
             * length 0 included, and data_wr writes it back out as
             * `0a 00` via wf_bytes_elem. Here it is a cmt_pb_bytes_t with
             * data NULL and len 0, and txs_len still advances. */
            if (r_copy_arena(a, p, n, &m->txs[m->txs_len]) != CMT_OK) {
                return CMT_REJECT;
            }
            m->txs_len++;
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_data_unmarshal(const uint8_t *in, size_t len, cmt_pb_data_t *m,
                          cmt_pb_arena_t *arena)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_data_init(m);
    return data_merge(in, len, m, arena);
}

/* ══ types.Vote ═══════════════════════════════════════════════════════ */

void cmt_pb_vote_init(cmt_pb_vote_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    m->timestamp = CMT_TIME_ZERO;
}

/* types.pb.go:1617-1744 — fields 4 (block_id) and 5 (timestamp) are
 * (nullable) = false and are ALWAYS emitted. */
static int vote_wr(pb_w_t *w, const cmt_pb_vote_t *m)
{
    size_t before;

    wf_bytes(w, 10, m->extension_signature, m->extension_signature_len);
    wf_bytes(w, 9, m->extension.data, m->extension.len);
    wf_bytes(w, 8, m->signature, m->signature_len);
    wf_varint(w, 7, (uint64_t)(int64_t)m->validator_index);
    wf_bytes(w, 6, m->validator_address, m->validator_address_len);

    before = w->i;
    if (ts_wr(w, &m->timestamp) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(w, 5, before);

    before = w->i;
    block_id_wr(w, &m->block_id);
    wf_close_msg(w, 4, before);

    wf_varint(w, 3, (uint64_t)(int64_t)m->round);
    wf_varint(w, 2, (uint64_t)m->height);
    wf_varint(w, 1, (uint64_t)(int64_t)m->type);
    return CMT_OK;
}

int cmt_pb_vote_marshal(const cmt_pb_vote_t *m, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->validator_address_len > CMT_PB_ADDRESS_MAX ||
        m->signature_len > CMT_PB_SIG_MAX ||
        m->extension_signature_len > CMT_PB_SIG_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    if (vote_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:3470-3797 — Vote.Unmarshal */
static int vote_merge(const uint8_t *in, size_t len, cmt_pb_vote_t *m,
                      cmt_pb_arena_t *a)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
        case 2:
        case 3:
        case 7:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                m->type = (int32_t)(uint32_t)v;
            } else if (fieldnum == 2) {
                m->height = (int64_t)v;
            } else if (fieldnum == 3) {
                m->round = (int32_t)(uint32_t)v;
            } else {
                m->validator_index = (int32_t)(uint32_t)v;
            }
            break;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (block_id_merge(p, n, &m->block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 5:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (cmt_pb_timestamp_unmarshal(p, n, &m->timestamp) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 6:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->validator_address, CMT_PB_ADDRESS_MAX,
                             &m->validator_address_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 8:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->signature, CMT_PB_SIG_MAX,
                             &m->signature_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 9:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_arena(a, p, n, &m->extension) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 10:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->extension_signature, CMT_PB_SIG_MAX,
                             &m->extension_signature_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_vote_unmarshal(const uint8_t *in, size_t len, cmt_pb_vote_t *m,
                          cmt_pb_arena_t *arena)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_vote_init(m);
    return vote_merge(in, len, m, arena);
}

/* ══ types.CommitSig ══════════════════════════════════════════════════ */

void cmt_pb_commit_sig_init(cmt_pb_commit_sig_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    m->timestamp = CMT_TIME_ZERO;
}

/* types.pb.go:1737-1744 — timestamp is (nullable) = false, ALWAYS. An
 * Absent CommitSig is therefore 08 01 1a 0b 08 <zero time>, 15 bytes. */
static int commit_sig_wr(pb_w_t *w, const cmt_pb_commit_sig_t *m)
{
    size_t before;

    wf_bytes(w, 4, m->signature, m->signature_len);
    before = w->i;
    if (ts_wr(w, &m->timestamp) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(w, 3, before);
    wf_bytes(w, 2, m->validator_address, m->validator_address_len);
    wf_varint(w, 1, (uint64_t)(int64_t)m->block_id_flag);
    return CMT_OK;
}

int cmt_pb_commit_sig_marshal(const cmt_pb_commit_sig_t *m, uint8_t *out,
                              size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->validator_address_len > CMT_PB_ADDRESS_MAX ||
        m->signature_len > CMT_PB_SIG_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    if (commit_sig_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:3953-4122 — CommitSig.Unmarshal */
static int commit_sig_merge(const uint8_t *in, size_t len,
                            cmt_pb_commit_sig_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->block_id_flag = (int32_t)(uint32_t)v;
            break;
        case 2:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->validator_address, CMT_PB_ADDRESS_MAX,
                             &m->validator_address_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (cmt_pb_timestamp_unmarshal(p, n, &m->timestamp) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->signature, CMT_PB_SIG_MAX,
                             &m->signature_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_commit_sig_unmarshal(const uint8_t *in, size_t len,
                                cmt_pb_commit_sig_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_commit_sig_init(m);
    return commit_sig_merge(in, len, m);
}

/* ══ types.Commit ═════════════════════════════════════════════════════ */

void cmt_pb_commit_init(cmt_pb_commit_t *m)
{
    cmt_pb_commit_sig_t *slots;
    size_t               cap;

    if (m == NULL) {
        return;
    }
    slots = m->signatures;
    cap   = m->signatures_cap;
    memset(m, 0, sizeof(*m));
    m->signatures     = slots;
    m->signatures_cap = cap;
}

/* types.pb.go:1673-1696 — block_id ALWAYS; signatures repeated. */
static int commit_wr(pb_w_t *w, const cmt_pb_commit_t *m)
{
    size_t before;
    size_t k;

    if (m->signatures_len != 0 && m->signatures == NULL) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = m->signatures_len; k > 0; k--) {
        before = w->i;
        if (commit_sig_wr(w, &m->signatures[k - 1]) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 4, before);
    }
    before = w->i;
    block_id_wr(w, &m->block_id);
    wf_close_msg(w, 3, before);
    wf_varint(w, 2, (uint64_t)(int64_t)m->round);
    wf_varint(w, 1, (uint64_t)m->height);
    return CMT_OK;
}

int cmt_pb_commit_marshal(const cmt_pb_commit_t *m, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (commit_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:3798-3952 — Commit.Unmarshal */
static int commit_merge(const uint8_t *in, size_t len, cmt_pb_commit_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
        case 2:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                m->height = (int64_t)v;
            } else {
                m->round = (int32_t)(uint32_t)v;
            }
            break;
        case 3:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (block_id_merge(p, n, &m->block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (m->signatures == NULL ||
                m->signatures_len >= m->signatures_cap) {
                return CMT_REJECT;
            }
            cmt_pb_commit_sig_init(&m->signatures[m->signatures_len]);
            if (commit_sig_merge(p, n, &m->signatures[m->signatures_len])
                != CMT_OK) {
                return CMT_REJECT;
            }
            m->signatures_len++;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_commit_unmarshal(const uint8_t *in, size_t len,
                            cmt_pb_commit_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_commit_init(m);
    return commit_merge(in, len, m);
}

/* ══ types.Proposal ═══════════════════════════════════════════════════ */

void cmt_pb_proposal_init(cmt_pb_proposal_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    m->timestamp = CMT_TIME_ZERO;
}

/* types.pb.go:1908-1925 — fields 5 and 6 are ALWAYS emitted. */
static int proposal_wr(pb_w_t *w, const cmt_pb_proposal_t *m)
{
    size_t before;

    wf_bytes(w, 7, m->signature, m->signature_len);
    before = w->i;
    if (ts_wr(w, &m->timestamp) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(w, 6, before);
    before = w->i;
    block_id_wr(w, &m->block_id);
    wf_close_msg(w, 5, before);
    wf_varint(w, 4, (uint64_t)(int64_t)m->pol_round);
    wf_varint(w, 3, (uint64_t)(int64_t)m->round);
    wf_varint(w, 2, (uint64_t)m->height);
    wf_varint(w, 1, (uint64_t)(int64_t)m->type);
    return CMT_OK;
}

int cmt_pb_proposal_marshal(const cmt_pb_proposal_t *m, uint8_t *out,
                            size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->signature_len > CMT_PB_SIG_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    if (proposal_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:4516-4741 — Proposal.Unmarshal */
static int proposal_merge(const uint8_t *in, size_t len,
                          cmt_pb_proposal_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
        case 2:
        case 3:
        case 4:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                m->type = (int32_t)(uint32_t)v;
            } else if (fieldnum == 2) {
                m->height = (int64_t)v;
            } else if (fieldnum == 3) {
                m->round = (int32_t)(uint32_t)v;
            } else {
                m->pol_round = (int32_t)(uint32_t)v;
            }
            break;
        case 5:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (block_id_merge(p, n, &m->block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 6:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (cmt_pb_timestamp_unmarshal(p, n, &m->timestamp) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 7:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->signature, CMT_PB_SIG_MAX,
                             &m->signature_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_proposal_unmarshal(const uint8_t *in, size_t len,
                              cmt_pb_proposal_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_proposal_init(m);
    return proposal_merge(in, len, m);
}

/* ══ canonical.CanonicalVote ══════════════════════════════════════════ */

void cmt_pb_canonical_vote_init(cmt_pb_canonical_vote_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    m->timestamp = CMT_TIME_ZERO;
}

/* canonical.pb.go:595-640 — height and round are SFIXED64 and are
 * themselves omit-zero (:622-633: `if m.Round != 0`); block_id is a
 * POINTER (:610-621); timestamp is ALWAYS (:602-609). */
static int canonical_vote_wr(pb_w_t *w, const cmt_pb_canonical_vote_t *m)
{
    size_t before;

    wf_bytes(w, 6, m->chain_id, m->chain_id_len);
    before = w->i;
    if (ts_wr(w, &m->timestamp) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(w, 5, before);
    if (m->has_block_id) {
        before = w->i;
        block_id_wr(w, &m->block_id);
        wf_close_msg(w, 4, before);
    }
    wf_sfixed64(w, 3, m->round);
    wf_sfixed64(w, 2, m->height);
    wf_varint(w, 1, (uint64_t)(int64_t)m->type);
    return CMT_OK;
}

int cmt_pb_canonical_vote_marshal(const cmt_pb_canonical_vote_t *m,
                                  uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->chain_id_len > CMT_PB_CHAINID_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    if (canonical_vote_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b canonical.pb.go:1250-1439 — CanonicalVote.Unmarshal */
static int canonical_vote_merge(const uint8_t *in, size_t len,
                                cmt_pb_canonical_vote_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->type = (int32_t)(uint32_t)v;
            break;
        case 2:
        case 3:
            if (wt != 1u) {
                return CMT_REJECT;
            }
            if (r_fixed64(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 2) {
                m->height = (int64_t)v;
            } else {
                m->round = (int64_t)v;
            }
            break;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (!m->has_block_id) {
                cmt_pb_canonical_block_id_init(&m->block_id);
                m->has_block_id = true;
            }
            if (block_id_merge(p, n, &m->block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 5:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (cmt_pb_timestamp_unmarshal(p, n, &m->timestamp) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 6:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->chain_id, CMT_PB_CHAINID_MAX,
                             &m->chain_id_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_canonical_vote_unmarshal(const uint8_t *in, size_t len,
                                    cmt_pb_canonical_vote_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_canonical_vote_init(m);
    return canonical_vote_merge(in, len, m);
}

/* ══ canonical.CanonicalProposal ══════════════════════════════════════ */

void cmt_pb_canonical_proposal_init(cmt_pb_canonical_proposal_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    m->timestamp = CMT_TIME_ZERO;
}

/* canonical.pb.go:520-570 — same shape as CanonicalVote plus pol_round,
 * which is INT64 (field 4), not the int32 of types.Proposal. */
static int canonical_proposal_wr(pb_w_t *w,
                                 const cmt_pb_canonical_proposal_t *m)
{
    size_t before;

    wf_bytes(w, 7, m->chain_id, m->chain_id_len);
    before = w->i;
    if (ts_wr(w, &m->timestamp) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(w, 6, before);
    if (m->has_block_id) {
        before = w->i;
        block_id_wr(w, &m->block_id);
        wf_close_msg(w, 5, before);
    }
    wf_varint(w, 4, (uint64_t)m->pol_round);
    wf_sfixed64(w, 3, m->round);
    wf_sfixed64(w, 2, m->height);
    wf_varint(w, 1, (uint64_t)(int64_t)m->type);
    return CMT_OK;
}

int cmt_pb_canonical_proposal_marshal(const cmt_pb_canonical_proposal_t *m,
                                      uint8_t *out, size_t cap,
                                      size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->chain_id_len > CMT_PB_CHAINID_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    if (canonical_proposal_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b canonical.pb.go:1041-1249 —
 * CanonicalProposal.Unmarshal */
static int canonical_proposal_merge(const uint8_t *in, size_t len,
                                    cmt_pb_canonical_proposal_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->type = (int32_t)(uint32_t)v;
            break;
        case 2:
        case 3:
            if (wt != 1u) {
                return CMT_REJECT;
            }
            if (r_fixed64(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 2) {
                m->height = (int64_t)v;
            } else {
                m->round = (int64_t)v;
            }
            break;
        case 4:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->pol_round = (int64_t)v;
            break;
        case 5:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (!m->has_block_id) {
                cmt_pb_canonical_block_id_init(&m->block_id);
                m->has_block_id = true;
            }
            if (block_id_merge(p, n, &m->block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 6:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (cmt_pb_timestamp_unmarshal(p, n, &m->timestamp) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 7:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->chain_id, CMT_PB_CHAINID_MAX,
                             &m->chain_id_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_canonical_proposal_unmarshal(const uint8_t *in, size_t len,
                                        cmt_pb_canonical_proposal_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_canonical_proposal_init(m);
    return canonical_proposal_merge(in, len, m);
}

/* ══ canonical.CanonicalVoteExtension ═════════════════════════════════ */

void cmt_pb_canonical_vote_extension_init(
    cmt_pb_canonical_vote_extension_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* cometbft@709fd12b canonical.pb.go:657-689 (canonical.proto:41-46).
 * No ALWAYS field; every field omit-zero, height and round SFIXED64. */
static int canonical_vote_extension_wr(
    pb_w_t *w, const cmt_pb_canonical_vote_extension_t *m)
{
    wf_bytes(w, 4, m->chain_id, m->chain_id_len);
    wf_sfixed64(w, 3, m->round);
    wf_sfixed64(w, 2, m->height);
    wf_bytes(w, 1, m->extension.data, m->extension.len);
    return CMT_OK;
}

int cmt_pb_canonical_vote_extension_marshal(
    const cmt_pb_canonical_vote_extension_t *m, uint8_t *out, size_t cap,
    size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->chain_id_len > CMT_PB_CHAINID_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    canonical_vote_extension_wr(&w, m);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b canonical.pb.go:1440-1575 —
 * CanonicalVoteExtension.Unmarshal. Small enough that the tag loop lives
 * in the public entry point; there is no separate _merge. */
int cmt_pb_canonical_vote_extension_unmarshal(
    const uint8_t *in, size_t len, cmt_pb_canonical_vote_extension_t *m,
    cmt_pb_arena_t *arena)
{
    size_t i = 0;

    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_canonical_vote_extension_init(m);
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_arena(arena, p, n, &m->extension) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
        case 3:
            if (wt != 1u) {
                return CMT_REJECT;
            }
            if (r_fixed64(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 2) {
                m->height = (int64_t)v;
            } else {
                m->round = (int64_t)v;
            }
            break;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->chain_id, CMT_PB_CHAINID_MAX,
                             &m->chain_id_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* ══ evidence.DuplicateVoteEvidence ═══════════════════════════════════ */

void cmt_pb_duplicate_vote_evidence_init(
    cmt_pb_duplicate_vote_evidence_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    m->timestamp = CMT_TIME_ZERO;
    cmt_pb_vote_init(&m->vote_a);
    cmt_pb_vote_init(&m->vote_b);
    m->has_vote_a = false;
    m->has_vote_b = false;
}

/* evidence.pb.go:454-495 — vote_a and vote_b are POINTERS (:472-495),
 * timestamp is ALWAYS (:454-461). */
static int dve_wr(pb_w_t *w, const cmt_pb_duplicate_vote_evidence_t *m)
{
    size_t before;

    before = w->i;
    if (ts_wr(w, &m->timestamp) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(w, 5, before);
    wf_varint(w, 4, (uint64_t)m->validator_power);
    wf_varint(w, 3, (uint64_t)m->total_voting_power);
    if (m->has_vote_b) {
        before = w->i;
        if (vote_wr(w, &m->vote_b) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 2, before);
    }
    if (m->has_vote_a) {
        before = w->i;
        if (vote_wr(w, &m->vote_a) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 1, before);
    }
    return CMT_OK;
}

int cmt_pb_duplicate_vote_evidence_marshal(
    const cmt_pb_duplicate_vote_evidence_t *m, uint8_t *out, size_t cap,
    size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (dve_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b evidence.pb.go:843-1035 —
 * DuplicateVoteEvidence.Unmarshal */
static int dve_merge(const uint8_t *in, size_t len,
                     cmt_pb_duplicate_vote_evidence_t *m, cmt_pb_arena_t *a)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
        case 2:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                if (!m->has_vote_a) {
                    cmt_pb_vote_init(&m->vote_a);
                    m->has_vote_a = true;
                }
                if (vote_merge(p, n, &m->vote_a, a) != CMT_OK) {
                    return CMT_REJECT;
                }
            } else {
                if (!m->has_vote_b) {
                    cmt_pb_vote_init(&m->vote_b);
                    m->has_vote_b = true;
                }
                if (vote_merge(p, n, &m->vote_b, a) != CMT_OK) {
                    return CMT_REJECT;
                }
            }
            break;
        case 3:
        case 4:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 3) {
                m->total_voting_power = (int64_t)v;
            } else {
                m->validator_power = (int64_t)v;
            }
            break;
        case 5:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (cmt_pb_timestamp_unmarshal(p, n, &m->timestamp) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_duplicate_vote_evidence_unmarshal(
    const uint8_t *in, size_t len, cmt_pb_duplicate_vote_evidence_t *m,
    cmt_pb_arena_t *arena)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_duplicate_vote_evidence_init(m);
    return dve_merge(in, len, m, arena);
}

/* ══ evidence.Evidence (oneof) ════════════════════════════════════════ */

void cmt_pb_evidence_init(cmt_pb_evidence_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    cmt_pb_duplicate_vote_evidence_init(&m->duplicate_vote_evidence);
    m->has_duplicate_vote_evidence = false;
}

int cmt_pb_evidence_marshal(const cmt_pb_evidence_t *m, uint8_t *out,
                            size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (m->has_duplicate_vote_evidence) {
        size_t before = w.i;

        if (dve_wr(&w, &m->duplicate_vote_evidence) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(&w, 1, before);
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b evidence.pb.go:723-842 — Evidence.Unmarshal (the
 * oneof wrapper). No separate _merge: the tag loop is here. */
int cmt_pb_evidence_unmarshal(const uint8_t *in, size_t len,
                              cmt_pb_evidence_t *m, cmt_pb_arena_t *arena)
{
    size_t i = 0;

    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_evidence_init(m);
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        /* Branch 2 (LightClientAttackEvidence) is out of scope and is
         * REFUSED, not skipped — see cmt_pb.h. Any other field number is
         * refused for the same reason: an evidence item nobody can decode
         * must not silently vanish from a list that gets hashed. */
        if (fieldnum != 1 || wt != 2u) {
            return CMT_REJECT;
        }
        if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
            return CMT_REJECT;
        }
        if (!m->has_duplicate_vote_evidence) {
            cmt_pb_duplicate_vote_evidence_init(&m->duplicate_vote_evidence);
            m->has_duplicate_vote_evidence = true;
        }
        if (dve_merge(p, n, &m->duplicate_vote_evidence, arena) != CMT_OK) {
            return CMT_REJECT;
        }
    }
    return CMT_OK;
}

/* ══ abci.ExecTxResult (deterministic subset) ═════════════════════════ */

void cmt_pb_exec_tx_result_init(cmt_pb_exec_tx_result_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

/* abci/types/types.pb.go:7034-7097, restricted to the four fields
 * deterministicExecTxResult keeps (types/results.go:47-54). */
int cmt_pb_exec_tx_result_marshal(const cmt_pb_exec_tx_result_t *m,
                                  uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    wf_varint(&w, 6, (uint64_t)m->gas_used);
    wf_varint(&w, 5, (uint64_t)m->gas_wanted);
    wf_bytes(&w, 2, m->data.data, m->data.len);
    wf_varint(&w, 1, (uint64_t)m->code);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b abci/types/types.pb.go:15272-15542 —
 * ExecTxResult.Unmarshal, restricted to fields 1/2/5/6. No separate
 * _merge.
 *
 * DEVIATION. The generated decoder does NOT skip the other four fields:
 * it PARSES them, with an explicit `case 3` Log (:15354), `case 4` Info
 * (:15386), `case 7` Events (:15456) and `case 8` Codespace (:15490),
 * each assigning into the struct. What discards them is a later step —
 * `deterministicExecTxResult` (types/results.go:47-54) rebuilds the
 * message from Code, Data, GasWanted and GasUsed alone before anything
 * is hashed, and the .proto marks 3, 4 and 7 `// nondeterministic`
 * (proto/tendermint/abci/types.proto:411,412,416).
 *
 * This port never stores or transports those four, so it has nowhere to
 * put them, and REFUSES a message that carries one rather than dropping
 * it silently. Consequence to know: bytes the reference accepts are
 * rejected here. That is deliberate — a result carrying a
 * nondeterministic field is not something this chain should have
 * produced — but it is a real interop difference, not a safety-only
 * tightening. */
int cmt_pb_exec_tx_result_unmarshal(const uint8_t *in, size_t len,
                                    cmt_pb_exec_tx_result_t *m,
                                    cmt_pb_arena_t *arena)
{
    size_t i = 0;

    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_exec_tx_result_init(m);
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->code = (uint32_t)v;
            break;
        case 2:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_arena(arena, p, n, &m->data) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 5:
        case 6:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 5) {
                m->gas_wanted = (int64_t)v;
            } else {
                m->gas_used = (int64_t)v;
            }
            break;
        default:
            /* Fields 3 (log), 4 (info), 7 (events) and 8 (codespace) are
             * stripped before hashing and are never stored or transported
             * by this port; a message carrying one is not ours. Stated
             * deviation — see cmt_pb.h. */
            return CMT_REJECT;
        }
    }
    return CMT_OK;
}

/* ══ libs.bits.BitArray ═══════════════════════════════════════════════ */

/* cometbft@709fd12b libs/bits/bit_array.go:475-484 — ToProto(), with the
 * marshal of libs/bits/types.pb.go:113-140 folded in: `elems` is PACKED
 * (:118-135), one tag 0x12 with a total length. */
int cmt_bits_to_proto(const cmt_bit_array_t *ba, uint8_t *out, size_t cap,
                      size_t *out_len)
{
    pb_w_t w;
    size_t before;
    size_t k;

    if (out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (ba == NULL || ba->n_elems == 0) {
        *out_len = 0;
        return CMT_BITS_NIL;                          /* :476-478 */
    }
    if (ba->n_elems > CMT_BITS_MAX_ELEMS || ba->bits < 0) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    before = w.i;
    for (k = ba->n_elems; k > 0; k--) {
        w_uvarint(&w, ba->elems[k - 1]);
    }
    if (w.err != CMT_OK) {
        return w.err;
    }
    w_uvarint(&w, (uint64_t)(before - w.i));
    w_tag(&w, 2, 2);
    wf_varint(&w, 1, (uint64_t)ba->bits);
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b libs/bits/bit_array.go:487-497 — FromProto(), with
 * libs/bits/types.pb.go:180-324 BitArray.Unmarshal folded in (a repeated
 * uint64 is accepted both PACKED and unpacked, exactly as the generated
 * decoder does), plus the length agreement the reference omits — see
 * cmt_pb.h. */
int cmt_bits_from_proto(const uint8_t *in, size_t len, cmt_bit_array_t *ba)
{
    size_t   i = 0;
    int64_t  bits = 0;
    uint64_t elems[CMT_BITS_MAX_ELEMS];
    size_t   n_elems = 0;

    if (ba == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    memset(ba, 0, sizeof(*ba));
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            bits = (int64_t)v;
        } else if (fieldnum == 2 && wt == 0u) {
            /* unpacked form */
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (n_elems >= CMT_BITS_MAX_ELEMS) {
                return CMT_REJECT;
            }
            elems[n_elems++] = v;
        } else if (fieldnum == 2 && wt == 2u) {
            const uint8_t *p;
            size_t         n;
            size_t         j = 0;

            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            /* NOTE deviation: the generated packed loop
             * (libs/bits/types.pb.go:283-300) iterates `for iNdEx <
             * postIndex` but bounds each INNER varint byte against the
             * WHOLE buffer — `if iNdEx >= l` at :289, not postIndex. A
             * varint whose continuation bytes run past the end of the
             * packed block is therefore READ ON, consuming bytes that
             * belong to the next field, and Go accepts it. Here the
             * varint is bounded by the packed block `n`, so it is
             * REFUSED. Stricter on malformed input only — a well-formed
             * packed block never straddles — and consistent with the
             * bounds INVARIANT. */
            while (j < n) {
                if (cmt_pb_get_uvarint(p, n, &j, &v) != CMT_OK) {
                    return CMT_REJECT;
                }
                if (n_elems >= CMT_BITS_MAX_ELEMS) {
                    return CMT_REJECT;
                }
                elems[n_elems++] = v;
            }
        } else if (fieldnum == 2) {
            return CMT_REJECT;             /* wrong wire type for elems */
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }

    /* The check the reference does NOT make (:493-496) — see cmt_pb.h. */
    if (bits < 0 || bits > (int64_t)CMT_BITS_MAX_BITS) {
        return CMT_REJECT;
    }
    if (n_elems != cmt_bits_num_elems((int)bits)) {
        return CMT_REJECT;
    }
    ba->bits    = (int)bits;
    ba->n_elems = n_elems;
    if (n_elems != 0) {
        memcpy(ba->elems, elems, n_elems * sizeof(uint64_t));
    }
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * WAVE R1-B ADDITION — types.ExtendedCommitSig and types.ExtendedCommit.
 *
 * Appended, not edited: nothing above this banner changed. These two
 * messages are the only ones of types.proto that wave R1-A left out, and
 * they are needed by cmt_block.c's ExtendedCommit family.
 * ══════════════════════════════════════════════════════════════════════ */

/* ══ types.ExtendedCommitSig ══════════════════════════════════════════ */

void cmt_pb_extended_commit_sig_init(cmt_pb_extended_commit_sig_t *m)
{
    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    /* The embedded CommitSig carries the ALWAYS-emitted timestamp, whose
     * zero value is Go's zero time.Time, NOT a memset. */
    cmt_pb_commit_sig_init(&m->commit_sig);
}

/* cometbft@709fd12b types.pb.go:1832-1879 —
 * ExtendedCommitSig.MarshalToSizedBuffer.
 *
 * Fields 6 and 5 are singular `bytes` and follow rule (a) (omit when
 * empty: :1837, :1844). Fields 4..1 are the embedded CommitSig's and are
 * written by commit_sig_wr, which reproduces :1851-1877 byte for byte —
 * including the ALWAYS-emitted timestamp of :1858-1865. */
static int ecs_wr(pb_w_t *w, const cmt_pb_extended_commit_sig_t *m)
{
    wf_bytes(w, 6, m->extension_signature, m->extension_signature_len);
    wf_bytes(w, 5, m->extension.data, m->extension.len);
    return commit_sig_wr(w, &m->commit_sig);
}

int cmt_pb_extended_commit_sig_marshal(const cmt_pb_extended_commit_sig_t *m,
                                       uint8_t *out, size_t cap,
                                       size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->commit_sig.validator_address_len > CMT_PB_ADDRESS_MAX ||
        m->commit_sig.signature_len > CMT_PB_SIG_MAX ||
        m->extension_signature_len > CMT_PB_SIG_MAX) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    if (ecs_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:4278-4515 — ExtendedCommitSig.Unmarshal.
 *
 * The generated decoder is its OWN full tag loop, not a delegation to
 * CommitSig.Unmarshal, so this one is too: cases 1-4 repeat the CommitSig
 * bodies (:4307-:4426) and cases 5-6 are the extension fields
 * (:4427-:4494); :4495-4508 is the default/skip arm. */
static int ecs_merge(const uint8_t *in, size_t len,
                     cmt_pb_extended_commit_sig_t *m, cmt_pb_arena_t *arena)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->commit_sig.block_id_flag = (int32_t)(uint32_t)v;
            break;
        case 2:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->commit_sig.validator_address,
                             CMT_PB_ADDRESS_MAX,
                             &m->commit_sig.validator_address_len,
                             p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (cmt_pb_timestamp_unmarshal(p, n, &m->commit_sig.timestamp)
                != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->commit_sig.signature, CMT_PB_SIG_MAX,
                             &m->commit_sig.signature_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 5:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_arena(arena, p, n, &m->extension) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 6:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (r_copy_fixed(m->extension_signature, CMT_PB_SIG_MAX,
                             &m->extension_signature_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_extended_commit_sig_unmarshal(const uint8_t *in, size_t len,
                                         cmt_pb_extended_commit_sig_t *m,
                                         cmt_pb_arena_t *arena)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_extended_commit_sig_init(m);
    return ecs_merge(in, len, m, arena);
}

/* ══ types.ExtendedCommit ═════════════════════════════════════════════ */

void cmt_pb_extended_commit_init(cmt_pb_extended_commit_t *m)
{
    cmt_pb_extended_commit_sig_t *slots;
    size_t                        cap;

    if (m == NULL) {
        return;
    }
    slots = m->extended_signatures;
    cap   = m->extended_signatures_cap;
    memset(m, 0, sizeof(*m));
    m->extended_signatures     = slots;
    m->extended_signatures_cap = cap;
}

/* cometbft@709fd12b types.pb.go:1775-1815 —
 * ExtendedCommit.MarshalToSizedBuffer. block_id (field 3) is ALWAYS
 * emitted (:1794-1803, no guard); every element of field 4 carries its
 * own tag (:1780-1792). */
static int ec_wr(pb_w_t *w, const cmt_pb_extended_commit_t *m)
{
    size_t before;
    size_t k;

    if (m->extended_signatures_len != 0 && m->extended_signatures == NULL) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = m->extended_signatures_len; k > 0; k--) {
        before = w->i;
        if (ecs_wr(w, &m->extended_signatures[k - 1]) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 4, before);
    }
    before = w->i;
    block_id_wr(w, &m->block_id);
    wf_close_msg(w, 3, before);
    wf_varint(w, 2, (uint64_t)(int64_t)m->round);
    wf_varint(w, 1, (uint64_t)m->height);
    return CMT_OK;
}

int cmt_pb_extended_commit_marshal(const cmt_pb_extended_commit_t *m,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (ec_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* cometbft@709fd12b types.pb.go:4123-4277 — ExtendedCommit.Unmarshal */
static int ec_merge(const uint8_t *in, size_t len,
                    cmt_pb_extended_commit_t *m, cmt_pb_arena_t *arena)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
        case 2:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                m->height = (int64_t)v;
            } else {
                m->round = (int32_t)(uint32_t)v;
            }
            break;
        case 3:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (block_id_merge(p, n, &m->block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:
            if (wt != 2u) {
                return CMT_REJECT;
            }
            if (r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            /* INVARIANT 7495d337: the wire cannot make this module write
             * past the caller's storage. Go appends and grows. */
            if (m->extended_signatures == NULL ||
                m->extended_signatures_len >= m->extended_signatures_cap) {
                return CMT_REJECT;
            }
            cmt_pb_extended_commit_sig_init(
                &m->extended_signatures[m->extended_signatures_len]);
            if (ecs_merge(p, n,
                          &m->extended_signatures[m->extended_signatures_len],
                          arena) != CMT_OK) {
                return CMT_REJECT;
            }
            m->extended_signatures_len++;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_extended_commit_unmarshal(const uint8_t *in, size_t len,
                                     cmt_pb_extended_commit_t *m,
                                     cmt_pb_arena_t *arena)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_extended_commit_init(m);
    return ec_merge(in, len, m, arena);
}
