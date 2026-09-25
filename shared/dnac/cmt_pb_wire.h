/**
 * @file shared/dnac/cmt_pb_wire.h
 * @brief cometbft @709fd12b proto3 wire primitives — the ONE definition,
 *        shared by every `cmt_pb*` codec translation unit.
 *
 * ═══ INTERNAL ═══════════════════════════════════════════════════════════
 * This is NOT part of the codec's public surface (`cmt_pb.h` is). Nothing
 * outside a `shared/dnac/cmt_pb*.c` includes it, and no consumer of the
 * codecs needs it: it holds the backward writer and the forward reader
 * helpers that every generated-encoder port repeats — varint, tag, bytes,
 * skip, length-delimited payload, arena copy.
 * ════════════════════════════════════════════════════════════════════════
 *
 * WHY IT EXISTS. R1/R2 put these fourteen helpers inside `cmt_pb.c` as
 * file-local statics, which was right while there was one codec TU. R3's
 * wave W1 added two more (`cmt_pb_store.c` for the stored values of
 * D-17 rev 5, `cmt_pb_mempool.c` for the mempool's Txs) and both had to
 * copy them verbatim; the two executors reported the copies and asked for
 * a merge. Two copies of a varint reader is a decode divergence waiting to
 * be written: the copies were byte-identical when they landed (measured),
 * and nothing would have kept them so. One definition removes the question
 * — and R3's later waves (blocksync, evidence, light client, state sync)
 * each add another codec TU that would otherwise have added another copy.
 *
 * WHY `static inline` AND NOT EXPORTED SYMBOLS. Exporting would put names
 * like `w_init` / `r_tag` into every binary that links the chain library —
 * generic names with a real collision surface — or force a rename of every
 * call site inside `cmt_pb.c`'s 6 000 lines. A header-defined `static
 * inline` gives each TU one copy of ONE text, which is exactly the
 * property that was wanted, and an unused helper costs a warning nowhere.
 *
 * THE RULES THESE ENCODE (K-1 rev 2, atlas-dec-3ba8153088b0d60c63083028023b61be):
 *   · the writer runs BACKWARD, mirroring the generated
 *     `MarshalToSizedBuffer`; `w_finish` moves the message to the front;
 *   · a zero/empty SINGULAR field is OMITTED (`wf_varint`, `wf_bytes`),
 *     while an ELEMENT of a `repeated bytes` is written unconditionally
 *     (`wf_bytes_elem`) — the generated code guards the slice, never the
 *     element;
 *   · the reader mirrors the generated `Unmarshal` tag loop, including its
 *     `int32(wire >> 3)` truncation quirk (`r_tag`), and every index
 *     arithmetic is bounds-checked BEFORE use (INVARIANT
 *     atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PB_WIRE_H
#define SHARED_DNAC_CMT_PB_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "dnac/cmt_pb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ writer (backward, mirroring MarshalToSizedBuffer) ════════════════ */

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   i;      /* cursor; bytes live in [i, cap) */
    int      err;
} pb_w_t;

static inline void w_init(pb_w_t *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->i   = cap;
    w->err = CMT_OK;
}

/* Prepend n bytes. */
static inline void w_raw(pb_w_t *w, const uint8_t *src, size_t n)
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

/* cometbft's `encodeVarintTypes`, writing backwards. */
static inline void w_uvarint(pb_w_t *w, uint64_t v)
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

static inline void w_tag(pb_w_t *w, uint32_t field, uint32_t wt)
{
    w_uvarint(w, ((uint64_t)field << 3) | (uint64_t)wt);
}

static inline void wf_varint(pb_w_t *w, uint32_t field, uint64_t v)
{
    if (v == 0) {
        return;
    }
    w_uvarint(w, v);
    w_tag(w, field, 0);
}

static inline void wf_bytes(pb_w_t *w, uint32_t field, const uint8_t *b,
                            size_t n)
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
static inline void wf_bytes_elem(pb_w_t *w, uint32_t field, const uint8_t *b,
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
static inline void wf_close_msg(pb_w_t *w, uint32_t field, size_t before)
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
static inline int w_finish(pb_w_t *w, size_t *out_len)
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

/* ══ reader (forward, mirroring the generated Unmarshal) ══════════════ */

/* cometbft's `skipTypes`, advancing *off past one whole field. Group
 * markers (wire types 3 and 4) are handled with the same depth counter;
 * every index arithmetic is bounds-checked BEFORE it is used, where Go
 * lets the value run past the end and rejects it in the caller. */
static inline int pb_skip(const uint8_t *in, size_t len, size_t *off)
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
static inline int r_ld(const uint8_t *in, size_t len, size_t *off,
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

/* Copy a wire byte field into a fixed-capacity destination. A length
 * beyond the destination is REFUSED — a capacity rule, not a semantic
 * one; see cmt_pb.h. */
static inline int r_copy_fixed(uint8_t *dst, size_t cap, size_t *dst_len,
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
static inline int r_copy_arena(cmt_pb_arena_t *a, const uint8_t *src, size_t n,
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
static inline int r_tag(const uint8_t *in, size_t len, size_t *off,
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

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PB_WIRE_H */
