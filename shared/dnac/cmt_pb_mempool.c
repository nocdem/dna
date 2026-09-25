/**
 * @file shared/dnac/cmt_pb_mempool.c
 * @brief cometbft @709fd12b `proto/tendermint/mempool` in C — see the
 *        header.
 *
 * Built on cmt_pb's PUBLIC surface only: `cmt_pb_data_*` for the Txs body
 * (the same generated shape), `cmt_pb_uvarint_size` / `cmt_pb_put_uvarint`
 * / `cmt_pb_get_uvarint` for the framing. The one helper this file needs
 * that cmt_pb.c keeps `static` — the field skipper — is duplicated below
 * and marked for the merge at O7; cmt_pb.{h,c} are not on this wave's
 * whitelist.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_pb_mempool.h"
#include "dnac/cmt_pb_wire.h"   /* the shared wire primitives */

#include <string.h>

/* ══ reader helpers ═══════════════════════════════════════════════════ */

/* `pb_skip` and `r_tag` come from cmt_pb_wire.h — ONE definition for every
 * cmt_pb* codec (merged at O7 from this file's own QUESTION; R3-M had to
 * copy them because cmt_pb.{h,c} were outside its whitelist). The Go
 * originals for THIS codec are mempool/types.pb.go:474-552 (skipTypes) and
 * :393-416 (the tag loop head, including the `int32(wire >> 3)`
 * truncation the shared helper reproduces). */

/* ══ Txs ══════════════════════════════════════════════════════════════ */

void cmt_pb_mempool_txs_init(cmt_pb_mempool_txs_t *m)
{
    cmt_pb_data_init(m);
}

/* cometbft@709fd12b proto/tendermint/mempool/types.pb.go:180-195 —
 * Txs.MarshalToSizedBuffer. The same generated loop as Data's
 * (types.pb.go:1552-1560); cmt_pb_data_marshal writes it. */
int cmt_pb_mempool_txs_marshal(const cmt_pb_mempool_txs_t *m, uint8_t *out,
                               size_t cap, size_t *out_len)
{
    return cmt_pb_data_marshal(m, out, cap, out_len);
}

/* cometbft@709fd12b proto/tendermint/mempool/types.pb.go:307-388 —
 * Txs.Unmarshal. The same generated tag loop as Data's
 * (types.pb.go:3388-3469); cmt_pb_data_unmarshal runs it. */
int cmt_pb_mempool_txs_unmarshal(const uint8_t *in, size_t len,
                                 cmt_pb_mempool_txs_t *m,
                                 cmt_pb_arena_t *arena)
{
    return cmt_pb_data_unmarshal(in, len, m, arena);
}

/* cometbft@709fd12b proto/tendermint/mempool/types.pb.go:261-274 —
 * Txs.Size(). */
size_t cmt_pb_mempool_txs_size(const cmt_pb_mempool_txs_t *m)
{
    size_t n = 0;
    size_t k;

    if (m == NULL) {                                          /* :262-264 */
        return 0;
    }
    if (m->txs_len != 0 && m->txs == NULL) {
        return 0;
    }
    for (k = 0; k < m->txs_len; k++) {                        /* :267-272 */
        size_t l = m->txs[k].len;

        n += 1u + l + cmt_pb_uvarint_size((uint64_t)l);       /* :270 */
    }
    return n;
}

/* ══ Message ══════════════════════════════════════════════════════════ */

void cmt_pb_mempool_message_init(cmt_pb_mempool_message_t *m)
{
    if (m == NULL) {
        return;
    }
    m->sum = CMT_PB_MEMPOOL_MSG_NONE;
    cmt_pb_mempool_txs_init(&m->txs);
}

/* cometbft@709fd12b proto/tendermint/mempool/types.pb.go:276-286 —
 * Message.Size(), with :288-299 Message_Txs.Size() folded in. */
size_t cmt_pb_mempool_message_size(const cmt_pb_mempool_message_t *m)
{
    size_t l;

    if (m == NULL || m->sum == CMT_PB_MEMPOOL_MSG_NONE) {     /* :277-279, :282 */
        return 0;
    }
    if (m->sum != CMT_PB_MEMPOOL_MSG_TXS) {
        return 0;
    }
    l = cmt_pb_mempool_txs_size(&m->txs);                     /* :295 */
    return 1u + l + cmt_pb_uvarint_size((uint64_t)l);         /* :296 */
}

/* cometbft@709fd12b proto/tendermint/mempool/types.pb.go:212-227 —
 * Message.MarshalToSizedBuffer, and :234-249 Message_Txs.MarshalToSizedBuffer.
 *
 * Forward form: `0a`, uvarint(Txs.Size()), then the Txs body. The
 * generated writer produces the body first and frames it with the size
 * it measured; because `Txs.Size()` is exact the two are the same bytes,
 * and the body length is checked against the size after writing so a
 * disagreement can never leave the frame lying. */
int cmt_pb_mempool_message_marshal(const cmt_pb_mempool_message_t *m,
                                   uint8_t *out, size_t cap,
                                   size_t *out_len)
{
    size_t off = 0;
    size_t body_size;
    size_t body_len = 0;
    int    rc;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    switch (m->sum) {
    case CMT_PB_MEMPOOL_MSG_NONE:                              /* :217 nil */
        *out_len = 0;
        return CMT_OK;
    case CMT_PB_MEMPOOL_MSG_TXS:
        break;
    default:
        /* A `sum` outside {0, 1} is not a branch the reference can hold:
         * its Sum is a typed interface. CMT_REJECT, never silence. */
        return CMT_REJECT;
    }
    body_size = cmt_pb_mempool_txs_size(&m->txs);
    if (cap < 1u) {
        return CMT_REJECT;
    }
    out[off++] = 0x0a;                                         /* :246 */
    rc = cmt_pb_put_uvarint(out, cap, &off, (uint64_t)body_size); /* :243 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_pb_mempool_txs_marshal(&m->txs, out + off, cap - off,
                                    &body_len);                /* :238 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (body_len != body_size) {
        return CMT_REJECT;
    }
    *out_len = off + body_len;
    return CMT_OK;
}

/* cometbft@709fd12b proto/tendermint/mempool/types.pb.go:389-473 —
 * Message.Unmarshal. */
static int mem_message_merge(const uint8_t *in, size_t len,
                             cmt_pb_mempool_message_t *m, cmt_pb_arena_t *a)
{
    size_t i = 0;

    while (i < len) {                                          /* :392 */
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {                                   /* :418 */
            uint64_t msglen;

            if (wt != 2u) {                                    /* :419-421 */
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &msglen) != CMT_OK) {
                return CMT_REJECT;                             /* :422-436 */
            }
            if (msglen > (uint64_t)(len - i)) {                /* :444-446 */
                return CMT_REJECT;
            }
            /* :447-451 — `v := &Txs{}` then `v.Unmarshal(...)`: a FRESH
             * Txs each time (cmt_pb_data_unmarshal re-initialises with
             * the slots kept), and Sum replaced, never merged. */
            if (cmt_pb_mempool_txs_unmarshal(in + i, (size_t)msglen,
                                             &m->txs, a) != CMT_OK) {
                return CMT_REJECT;
            }
            m->sum = CMT_PB_MEMPOOL_MSG_TXS;
            i += (size_t)msglen;
        } else {                                               /* :453-466 */
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_mempool_message_unmarshal(const uint8_t *in, size_t len,
                                     cmt_pb_mempool_message_t *m,
                                     cmt_pb_arena_t *arena)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_mempool_message_init(m);
    return mem_message_merge(in, len, m, arena);
}

/* ══ message.go ═══════════════════════════════════════════════════════ */

/* cometbft@709fd12b proto/tendermint/mempool/message.go:29-33 — Wrap() */
int cmt_pb_mempool_txs_wrap(const cmt_pb_mempool_txs_t *m,
                            cmt_pb_mempool_message_t *out)
{
    if (m == NULL || out == NULL) {
        return CMT_FAULT;
    }
    out->sum = CMT_PB_MEMPOOL_MSG_TXS;                         /* :31 */
    out->txs = *m;
    return CMT_OK;
}

/* cometbft@709fd12b proto/tendermint/mempool/message.go:37-45 — Unwrap() */
int cmt_pb_mempool_message_unwrap(const cmt_pb_mempool_message_t *m,
                                  const cmt_pb_mempool_txs_t **out)
{
    if (m == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (m->sum == CMT_PB_MEMPOOL_MSG_TXS) {                    /* :39-40 */
        *out = &m->txs;
        return CMT_OK;
    }
    *out = NULL;
    return CMT_REJECT;                                         /* :42-43 */
}
