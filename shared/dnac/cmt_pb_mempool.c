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
 * The raw-bytes filter at the end (cometbft@v0.38.26 mempool/filter.go
 * over internal/protowire) walks the SAME wire this codec decodes; it is
 * called by the mempool reactor before the decode (cmt_memr.c).
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

/* ══ cometbft@v0.38.26 internal/protowire/protowire.go — the cursor ════
 *
 * A minimal bounds-checked reader over raw protobuf bytes (:1-2), used
 * only by the filter below. Kept file-local: the package is `internal`
 * in the reference and its one user is filter.go. Every read advances
 * `pos`; a read past the end is an error, never an out-of-bounds access.
 * `:NNN` in this section and the next are v0.38.26 lines. */

/* :12-15 — wire types (the low 3 bits of a tag). */
#define PW_WIRE_VARINT  0
#define PW_WIRE_FIXED64 1
#define PW_WIRE_BYTES   2
#define PW_WIRE_FIXED32 5

/* :38-41 — WireCursor */
typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} pw_cursor_t;

/* :44-46 — NewWireCursor */
static void pw_init(pw_cursor_t *c, const uint8_t *buf, size_t len)
{
    c->buf = buf;
    c->len = len;
    c->pos = 0;
}

/* :49 — AtEnd */
static bool pw_at_end(const pw_cursor_t *c)
{
    return c->pos >= c->len;
}

/* :52-68 — ReadVarint. At most ten bytes are read: the eleventh
 * iteration has shift 70 ≥ 64 and is ErrVarintOverflow (:55-56), as in
 * the reference; the tenth byte's high bits are shifted out, not checked,
 * as in the reference. */
static int pw_read_varint(pw_cursor_t *c, uint64_t *out,
                          cmt_pb_mempool_filter_err_t *err)
{
    uint64_t v = 0;
    unsigned shift;

    for (shift = 0; ; shift += 7u) {                              /* :54 */
        uint8_t b;

        if (shift >= 64u) {                                       /* :55 */
            *err = CMT_PB_MEMPOOL_FILTER_VARINT_OVERFLOW;         /* :56 */
            return CMT_REJECT;
        }
        if (c->pos >= c->len) {                                   /* :58 */
            *err = CMT_PB_MEMPOOL_FILTER_TRUNCATED_VARINT;        /* :59 */
            return CMT_REJECT;
        }
        b = c->buf[c->pos];                                       /* :61 */
        c->pos++;                                                 /* :62 */
        v |= (uint64_t)(b & 0x7fu) << shift;                      /* :63 */
        if (b < 0x80u) {                                          /* :64 */
            *out = v;
            return CMT_OK;                                        /* :65 */
        }
    }
}

/* :71-82 — ReadTag. `int(int32(v >> 3))` (:76) — the 32-bit truncation
 * of #5948, the SAME as the generated decoder's `r_tag` (cmt_pb_wire.h),
 * so a tag like `8a 80 80 80 80 01` names field 1 to both. A wire type of
 * 4 is NOT refused here (the reference does not); SkipField refuses it. */
static int pw_read_tag(pw_cursor_t *c, int32_t *field_num, int *wire_type,
                       cmt_pb_mempool_filter_err_t *err)
{
    uint64_t v;

    if (pw_read_varint(c, &v, err) != CMT_OK) {                   /* :72-75 */
        return CMT_REJECT;
    }
    *field_num = (int32_t)(uint32_t)(v >> 3);                     /* :76 */
    *wire_type = (int)(v & 0x7u);                                 /* :77 */
    if (*field_num <= 0) {                                        /* :78 */
        *err = CMT_PB_MEMPOOL_FILTER_ILLEGAL_FIELD_NUMBER;        /* :79 */
        return CMT_REJECT;
    }
    return CMT_OK;                                                /* :81 */
}

/* :86-98 — ReadLengthDelimited: a sub-slice of the buffer, no copy. The
 * reference's `end < start` guard (:93) catches `int(length)` going
 * negative; comparing the length with what remains is the same test
 * without the conversion. */
static int pw_read_length_delimited(pw_cursor_t *c, const uint8_t **out,
                                    size_t *out_len,
                                    cmt_pb_mempool_filter_err_t *err)
{
    uint64_t length;

    if (pw_read_varint(c, &length, err) != CMT_OK) {              /* :87-90 */
        return CMT_REJECT;
    }
    if (length > (uint64_t)(c->len - c->pos)) {                   /* :93 */
        *err = CMT_PB_MEMPOOL_FILTER_OUT_OF_BOUNDS;               /* :94 */
        return CMT_REJECT;
    }
    *out     = c->buf + c->pos;                                   /* :97 */
    *out_len = (size_t)length;
    c->pos  += (size_t)length;                                    /* :96 */
    return CMT_OK;
}

/* :120-127 — advance */
static int pw_advance(pw_cursor_t *c, size_t n,
                      cmt_pb_mempool_filter_err_t *err)
{
    if (n > c->len - c->pos) {                                    /* :122 */
        *err = CMT_PB_MEMPOOL_FILTER_OUT_OF_BOUNDS;               /* :123 */
        return CMT_REJECT;
    }
    c->pos += n;                                                  /* :125 */
    return CMT_OK;
}

/* :102-117 — SkipField. Group wire types (3, 4) and the undefined 6, 7
 * are ErrUnsupportedWireType (:114-115). */
static int pw_skip_field(pw_cursor_t *c, int wire_type,
                         cmt_pb_mempool_filter_err_t *err)
{
    uint64_t       ignored;
    const uint8_t *p;
    size_t         n;

    switch (wire_type) {                                          /* :103 */
    case PW_WIRE_VARINT:                                          /* :104 */
        return pw_read_varint(c, &ignored, err);                  /* :105-106 */
    case PW_WIRE_FIXED64:                                         /* :107 */
        return pw_advance(c, 8u, err);                            /* :108 */
    case PW_WIRE_BYTES:                                           /* :109 */
        return pw_read_length_delimited(c, &p, &n, err);          /* :110-111 */
    case PW_WIRE_FIXED32:                                         /* :112 */
        return pw_advance(c, 4u, err);                            /* :113 */
    default:                                                      /* :114 */
        *err = CMT_PB_MEMPOOL_FILTER_UNSUPPORTED_WIRE_TYPE;       /* :115 */
        return CMT_REJECT;
    }
}

/* ══ cometbft@v0.38.26 mempool/filter.go — filterMempoolMsgBytes ═══════ */

/* :12-15 — both field numbers happen to be 1. */
#define FILTER_FIELD_MESSAGE_TXS 1   /* Message.sum: `Txs txs = 1` */
#define FILTER_FIELD_TXS_ENTRY   1   /* Txs: `repeated bytes txs = 1` */

/* :23-26 — batchTally. Go's `int` is 64-bit; so is this sum. */
typedef struct {
    int64_t count;         /* number of transaction entries */
    int64_t total_bytes;   /* sum of their sizes */
} filter_tally_t;

/* :111-129 — applyRules: rules 2-4 for one transaction. */
static int filter_apply_rules(size_t tx_len, int max_tx_bytes,
                              int batch_budget, filter_tally_t *tally,
                              cmt_pb_mempool_filter_err_t *err)
{
    if (tx_len == 0u) {                                           /* :113 */
        *err = CMT_PB_MEMPOOL_FILTER_EMPTY_TRANSACTION;           /* :114 */
        return CMT_REJECT;
    }
    if (max_tx_bytes > 0 && tx_len > (size_t)max_tx_bytes) {      /* :117 */
        *err = CMT_PB_MEMPOOL_FILTER_TX_TOO_LARGE;                /* :118 */
        return CMT_REJECT;
    }
    tally->count++;                                               /* :121 */
    tally->total_bytes += (int64_t)tx_len;                        /* :122 */
    if (batch_budget > 0 &&
        tally->total_bytes > (int64_t)batch_budget) {             /* :125 */
        *err = CMT_PB_MEMPOOL_FILTER_BATCH_TOO_LARGE;             /* :126 */
        return CMT_REJECT;
    }
    return CMT_OK;                                                /* :128 */
}

/* :84-108 — scanTxsSubmessage: every `repeated bytes txs = 1` entry of
 * one Txs body; any other field is skipped. */
static int filter_scan_txs_submessage(const uint8_t *txs_bytes, size_t len,
                                      int max_tx_bytes, int batch_budget,
                                      filter_tally_t *tally,
                                      cmt_pb_mempool_filter_err_t *err)
{
    pw_cursor_t txs;

    pw_init(&txs, txs_bytes, len);                                /* :85 */
    while (!pw_at_end(&txs)) {                                    /* :86 */
        int32_t        field_num;
        int            wire_type;
        const uint8_t *tx;
        size_t         tx_len;

        if (pw_read_tag(&txs, &field_num, &wire_type, err) != CMT_OK) {
            return CMT_REJECT;                                    /* :87-90 */
        }
        if (field_num != FILTER_FIELD_TXS_ENTRY ||
            wire_type != PW_WIRE_BYTES) {                         /* :92 */
            if (pw_skip_field(&txs, wire_type, err) != CMT_OK) {  /* :93-95 */
                return CMT_REJECT;
            }
            continue;                                             /* :96 */
        }
        if (pw_read_length_delimited(&txs, &tx, &tx_len, err) != CMT_OK) {
            return CMT_REJECT;                                    /* :99-102 */
        }
        if (filter_apply_rules(tx_len, max_tx_bytes, batch_budget, tally,
                               err) != CMT_OK) {                  /* :103-105 */
            return CMT_REJECT;
        }
    }
    return CMT_OK;                                                /* :107 */
}

/* :46-79 — filterMempoolMsgBytes */
int cmt_pb_mempool_filter_msg_bytes(const uint8_t *msg, size_t len,
                                    int max_tx_bytes, int max_batch_bytes,
                                    cmt_pb_mempool_filter_err_t *out_err)
{
    cmt_pb_mempool_filter_err_t err = CMT_PB_MEMPOOL_FILTER_OK;
    filter_tally_t              tally;
    pw_cursor_t                 c;
    int                         batch_budget;
    int                         rc = CMT_OK;

    if (out_err != NULL) {
        *out_err = CMT_PB_MEMPOOL_FILTER_OK;
    }
    if (msg == NULL && len != 0u) {
        return CMT_FAULT;
    }
    /* :47 — `max(maxTxBytes, maxBatchBytes)` */
    batch_budget = (max_tx_bytes > max_batch_bytes) ? max_tx_bytes
                                                    : max_batch_bytes;
    tally.count       = 0;
    tally.total_bytes = 0;

    pw_init(&c, msg, len);                                        /* :50 */
    while (rc == CMT_OK && !pw_at_end(&c)) {                      /* :51 */
        int32_t        field_num;
        int            wire_type;
        const uint8_t *txs_bytes;
        size_t         txs_len;

        rc = pw_read_tag(&c, &field_num, &wire_type, &err);       /* :52-55 */
        if (rc != CMT_OK) {
            break;
        }
        /* :57-64 — anything that is not the Txs submessage is skipped, so
         * unknown or future fields do not break the scan. */
        if (field_num != FILTER_FIELD_MESSAGE_TXS ||
            wire_type != PW_WIRE_BYTES) {                         /* :59 */
            rc = pw_skip_field(&c, wire_type, &err);              /* :60-62 */
            continue;                                             /* :63 */
        }
        rc = pw_read_length_delimited(&c, &txs_bytes, &txs_len, &err); /* :66-69 */
        if (rc != CMT_OK) {
            break;
        }
        rc = filter_scan_txs_submessage(txs_bytes, txs_len, max_tx_bytes,
                                        batch_budget, &tally, &err); /* :70-72 */
    }
    if (rc == CMT_OK && tally.count == 0) {                       /* :75 */
        err = CMT_PB_MEMPOOL_FILTER_NO_TRANSACTIONS;              /* :76 */
        rc  = CMT_REJECT;
    }
    if (out_err != NULL) {
        *out_err = err;
    }
    return rc;                                                    /* :78 */
}
