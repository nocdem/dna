/**
 * @file shared/dnac/cmt_p2p_protoio.h
 * @brief cometbft @709fd12b `libs/protoio/reader.go` ported to C — the
 *        uvarint-delimited message READER the MConnection receives its
 *        packets with, as a byte-fed parser.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F2 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row 4). Its only consumer is cmt_p2p_mconn (same phase). Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHY A NEW FILE (the design's "executor checks") ────────────────────
 * The WRITER already exists: `cmt_pb_marshal_delimited` (cmt_pb.h:447,
 * writer.go:78-86 / :96-103) and `cmt_pb_put_uvarint` (cmt_pb.h:432) —
 * the MConnection uses those. The tree has NO delimited READER: the only
 * varint reader, `cmt_pb_get_uvarint` (cmt_pb.h:438), is the GENERATED
 * decoder's (shift >= 64 → overflow, end of buffer → REJECT). The
 * delimited reader's length prefix is read by a different function —
 * the Go standard library's `binary.ReadUvarint` (reader.go:69) — with
 * two properties the generated one lacks:
 *   · a stream reader must tell "not all bytes have arrived yet" (the
 *     reference simply blocks in ReadByte / ReadFull, reader.go:69, :89)
 *     from "these bytes are wrong"; an event loop that REJECTed a prefix
 *     split across two TCP reads would drop every peer whose packets do
 *     not arrive whole;
 *   · the 10th byte of the uvarint may only be 0 or 1
 *     (Go src/encoding/binary/varint.go:143-146; Go 1.21.5, the local
 *     toolchain — the standard library is not in the pinned tarball).
 * Hence this file: ReadUvarint and ReadMsg's framing, byte-fed.
 *
 * ── WHAT IS PORTED ─────────────────────────────────────────────────────
 *   reader.go:67-95 `varintReader.ReadMsg` → cmt_p2p_protoio_read_msg:
 *     :68-73  read the uvarint length (binary.ReadUvarint)
 *     :75-80  length out of the native int range → error
 *     :81-83  length > maxSize → error ("message exceeds max size")
 *     :85-94  the body, whole — `proto.Unmarshal` is the CALLER's (the
 *             MConnection decodes `tendermint.p2p.Packet` itself)
 * NOT ported: the Reader/Writer interfaces and closers (io.go:9-27,
 * reader.go:97-102, writer.go:89-94), `getSize` / `byteReader`
 * (io.go:29-101 — the stream mechanics this byte-fed form replaces),
 * `UnmarshalDelimited` (reader.go:104-107; no consumer here).
 *
 * The byte count the reference returns as `n` (reader.go:70, :90 — the
 * prefix plus the body bytes read) is `*n_read` here; the MConnection
 * feeds it to its recv Monitor (connection.go:617-618), also when the
 * read fails.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_PROTOIO_H
#define CMT_P2P_PROTOIO_H

#include <stdint.h>
#include <stddef.h>

#include "cmt_tmhash.h"                    /* CMT_OK / CMT_REJECT / CMT_FAULT */

#ifdef __cplusplus
extern "C" {
#endif

/** "The bytes seen so far are a valid PREFIX of a message; offer more."
 *  Positive, so it never collides with CMT_OK / CMT_REJECT / CMT_FAULT. */
#define CMT_P2P_PROTOIO_MORE  1

/** binary.MaxVarintLen64 (Go src/encoding/binary/varint.go:36). */
#define CMT_P2P_PROTOIO_MAX_VARINT_LEN 10

/**
 * binary.ReadUvarint (Go src/encoding/binary/varint.go:132-153) over a
 * buffer: reads from `in[*off]`.
 * @return CMT_OK (value in `*v`, `*off` past it); CMT_P2P_PROTOIO_MORE
 *         (the buffer ends inside the varint — `*off` unchanged);
 *         CMT_REJECT (errOverflow: an 11th byte would be needed, or the
 *         10th byte is > 1); CMT_FAULT on NULL.
 */
int cmt_p2p_protoio_read_uvarint(const uint8_t *in, size_t len, size_t *off,
                                 uint64_t *v);

/**
 * reader.go:67-95 `ReadMsg`, byte-fed. Looks at `in[0 .. len)` — the
 * bytes of the stream from the start of the next message on — and never
 * consumes a partial message.
 *
 * @param max_size  reader.go:81 `maxSize`
 * @param body_off  receives the offset of the body inside `in` (CMT_OK)
 * @param body_len  receives the body length (CMT_OK)
 * @param n_read    receives the reference's `n` (reader.go:70, :90): on
 *                  CMT_OK the whole message (prefix + body); on
 *                  CMT_REJECT the prefix bytes read before the refusal;
 *                  on CMT_P2P_PROTOIO_MORE 0. May be NULL.
 * @return CMT_OK — a whole message is present (it occupies
 *         `body_off + body_len` bytes); CMT_P2P_PROTOIO_MORE — the bytes
 *         present are a valid beginning, more are needed; CMT_REJECT —
 *         varint overflow (:69-73), out-of-range length (:78-80) or
 *         length > max_size (:81-83), decided as soon as the prefix is
 *         complete, before any body byte; CMT_FAULT on NULL.
 */
int cmt_p2p_protoio_read_msg(const uint8_t *in, size_t len, size_t max_size,
                             size_t *body_off, size_t *body_len,
                             size_t *n_read);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_PROTOIO_H */
