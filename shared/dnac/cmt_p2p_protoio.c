/**
 * @file shared/dnac/cmt_p2p_protoio.c
 * @brief cometbft @709fd12b `libs/protoio/reader.go` — the delimited
 *        reader, byte-fed. Contract and grounding in cmt_p2p_protoio.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_protoio.h"

/* Go src/encoding/binary/varint.go:132-153 `ReadUvarint`. The reference's
 * io.EOF / io.ErrUnexpectedEOF (:137-142) is a read that has not
 * happened yet here: CMT_P2P_PROTOIO_MORE. */
int cmt_p2p_protoio_read_uvarint(const uint8_t *in, size_t len, size_t *off,
                                 uint64_t *v)
{
    uint64_t x = 0;
    unsigned s = 0;
    size_t   i;

    if ((in == NULL && len != 0) || off == NULL || v == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < CMT_P2P_PROTOIO_MAX_VARINT_LEN; i++) {     /* :135 */
        uint8_t b;

        if (*off + i >= len) {
            return CMT_P2P_PROTOIO_MORE;                       /* :137-142 */
        }
        b = in[*off + i];
        if (b < 0x80u) {                                       /* :143 */
            if (i == CMT_P2P_PROTOIO_MAX_VARINT_LEN - 1 && b > 1u) {
                return CMT_REJECT;                             /* :144-146 */
            }
            *v = x | ((uint64_t)b << s);                       /* :147 */
            *off += i + 1;
            return CMT_OK;
        }
        x |= (uint64_t)(b & 0x7Fu) << s;                       /* :149 */
        s += 7u;
    }
    return CMT_REJECT;                                         /* :152 */
}

/* reader.go:67-95 `varintReader.ReadMsg`, framing only. */
int cmt_p2p_protoio_read_msg(const uint8_t *in, size_t len, size_t max_size,
                             size_t *body_off, size_t *body_len,
                             size_t *n_read)
{
    size_t   off = 0;
    uint64_t l;
    int      rc;

    if ((in == NULL && len != 0) || body_off == NULL || body_len == NULL) {
        return CMT_FAULT;
    }
    if (n_read != NULL) {
        *n_read = 0;
    }

    rc = cmt_p2p_protoio_read_uvarint(in, len, &off, &l);      /* :69 */
    if (rc == CMT_P2P_PROTOIO_MORE) {
        return CMT_P2P_PROTOIO_MORE;
    }
    if (rc != CMT_OK) {
        /* :70-73 — n is the bytes ReadByte consumed; an overflow read
         * every byte of the 10 (or up to and including the bad 10th). */
        if (n_read != NULL) {
            *n_read = CMT_P2P_PROTOIO_MAX_VARINT_LEN;
        }
        return rc;
    }
    if (n_read != NULL) {
        *n_read = off;                                         /* :70 */
    }

    /* :77-80 — the native int range, and n + length must not overflow. */
    if (l >= (uint64_t)(SIZE_MAX >> 1) || (size_t)l > (SIZE_MAX >> 1) - off) {
        return CMT_REJECT;
    }
    if ((size_t)l > max_size) {                                /* :81-83 */
        return CMT_REJECT;
    }
    if ((size_t)l > len - off) {                               /* :89 ReadFull */
        if (n_read != NULL) {
            *n_read = 0;
        }
        return CMT_P2P_PROTOIO_MORE;
    }
    *body_off = off;
    *body_len = (size_t)l;
    if (n_read != NULL) {
        *n_read = off + (size_t)l;                             /* :90 */
    }
    return CMT_OK;
}
