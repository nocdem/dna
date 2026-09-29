/**
 * @file shared/dnac/cmt_pb_mempool.h
 * @brief cometbft @709fd12b `proto/tendermint/mempool` — the two wire
 *        messages of the Flood mempool, in C under K-1 rev 2.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R3-M of the cometbft → C consensus port. No transport delivers
 * these bytes yet (the tier3 verb is R3-C2's); additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * types.proto:1-14 declares exactly two messages:
 *
 *     message Txs     { repeated bytes txs = 1; }
 *     message Message { oneof sum { Txs txs = 1; } }
 *
 * `Txs` is WIRE-IDENTICAL to `tendermint.types.Data` (types/types.proto:
 * 74-79, `repeated bytes txs = 1`): the same field number, the same
 * generated shape — `if len(m.Txs) > 0` around a loop that writes EVERY
 * element unconditionally (types.pb.go:180-195 here, K-1 rev 2 rule (f)
 * and cmt_pb.c's `wf_bytes_elem` note for Data). So `cmt_pb_mempool_txs_t`
 * is a typedef of `cmt_pb_data_t` with its own entry points, exactly as
 * cmt_pb.h:179-190 shares one struct between PartSetHeader and
 * CanonicalPartSetHeader and cmt_block.h:666 aliases Data. Each reference
 * message keeps its own row; nothing in cmt_pb.{h,c} is touched.
 *
 * ── THE ONEOF ──────────────────────────────────────────────────────────
 * `Message.MarshalToSizedBuffer` (types.pb.go:212-227) writes NOTHING for
 * a nil `Sum`, and `Message_Txs.MarshalToSizedBuffer` (:234-249) writes
 * `0a ‖ len ‖ body` whenever the branch's `Txs` POINTER is non-nil — an
 * EMPTY Txs is therefore `0a 00`, and the reference's `Message_Txs{Txs:
 * nil}` (a branch holding a nil pointer, which nothing in the pinned tree
 * constructs and which the decoder never produces — :447 allocates) is
 * NOT representable here: `sum == CMT_PB_MEMPOOL_MSG_TXS` always carries
 * a Txs, empty or not.
 *
 * ── DECODE CONTRACT — cmt_pb.h's, unchanged ────────────────────────────
 * `_unmarshal` mirrors the generated `Unmarshal` (:307-388, :389-473):
 * unknown field numbers are SKIPPED by wire type (:368-381, :453-466), a
 * repeated oneof field is last-one-wins with a FRESH branch each time
 * (:447-451), every wire-derived length is checked before it is used
 * (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07), and no pointer
 * into the input survives: each tx is copied into the caller's arena.
 * A `Message` whose `sum` is nil after decoding is REFUSED where the
 * reference refuses it — `Unwrap` (message.go:37-45), ported below as
 * `cmt_pb_mempool_message_unwrap` — not by the decoder, whose generated
 * counterpart accepts it.
 *
 * ── SIZES ──────────────────────────────────────────────────────────────
 * `Txs.Size()` (:261-274), `Message.Size()` (:276-286) and
 * `Message_Txs.Size()` (:288-299) are ported as functions and are EXACT,
 * not upper bounds: the generated encoder sizes its buffer with them and
 * fills it completely. `RecvMessageCapacity` (mempool/reactor.go:71-89)
 * is computed with them, never by hand.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Pure functions of the struct / of the input buffer; no map, no clock,
 * no randomness, no floating point.
 *
 * Reference @709fd12b (SHA-256 verified before use; pin record rev 12 →
 * rev 15, atlas-dec-483ec17cbb352ef0ec2267ccd953339c):
 *   proto/tendermint/mempool/types.proto    14 lines  47977b93…
 *   proto/tendermint/mempool/types.pb.go   557 lines  0975d433…
 *   proto/tendermint/mempool/message.go     31 lines  d21f89b0…
 * Added by the v0.38.26 re-pin (decisions/2026-09-30-cometbft-pin-
 * v0.38.26.md) for `cmt_pb_mempool_filter_msg_bytes`; local copy
 * /home/nocdem/refs/cometbft-v0.38.26, SHA-256 of that copy:
 *   mempool/filter.go                      129 lines  76de8095…
 *   internal/protowire/protowire.go        127 lines  668b3246…
 * Governing records: umbrella rev 4 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * D-4 rev 3 (atlas-dec-d5ddcba654eb48d861c03a0ecd170718).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PB_MEMPOOL_H
#define SHARED_DNAC_CMT_PB_MEMPOOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"   /* cmt_pb_data_t, cmt_pb_bytes_t, cmt_pb_arena_t, CMT_* codes */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * mempool/types.proto:6-8 — `Txs`. The struct is `cmt_pb_data_t`
 * (cmt_pb.h:273-278): `txs` is CALLER-OWNED slot storage of `txs_cap`
 * entries, `txs_len` of them used, each element's bytes in an arena or
 * wherever the caller keeps them.
 */
typedef cmt_pb_data_t cmt_pb_mempool_txs_t;

/** mempool/types.proto:10-14 — the `Message` oneof's field numbers. 0 is
 *  the reference's nil `Sum`, which marshals to zero bytes
 *  (types.pb.go:217-225). */
typedef enum {
    CMT_PB_MEMPOOL_MSG_NONE = 0,
    CMT_PB_MEMPOOL_MSG_TXS  = 1
} cmt_pb_mempool_msg_kind_t;

/**
 * mempool/types.proto:10-14 — `Message`.
 *
 * DECODE: the generated Unmarshal REPLACES `Sum` with a freshly allocated
 * `Txs` on every field-1 occurrence (types.pb.go:447-451), so a repeated
 * oneof field is last-one-wins with no merge. This decoder does the same:
 * `txs` is re-initialised (its slot storage kept, its length zeroed) and
 * decoded again.
 *
 * BUILDING ONE BY HAND: `cmt_pb_mempool_message_init` sets `sum` to NONE
 * and initialises `txs` with its slots preserved. Because the init READS
 * `txs.txs`/`txs.txs_cap` to preserve them, a caller sets those two
 * fields BEFORE calling it on a fresh local (they are the only fields
 * read). A caller that selects the Txs branch then fills `txs` and sets
 * `sum`; `cmt_pb_mempool_txs_wrap` does both.
 */
typedef struct {
    cmt_pb_mempool_msg_kind_t sum;
    cmt_pb_mempool_txs_t      txs;   /* branch 1 */
} cmt_pb_mempool_message_t;

/* ── Txs ────────────────────────────────────────────────────────────── */

/** Go's zero `Txs{}` with the caller's slot storage preserved — the
 *  `cmt_pb_data_init` contract (cmt_pb.c:1901-1914). */
void cmt_pb_mempool_txs_init(cmt_pb_mempool_txs_t *m);

/** cometbft@709fd12b proto/tendermint/mempool/types.pb.go:180-195 —
 *  `Txs.MarshalToSizedBuffer`: one `0a ‖ len ‖ bytes` per element, every
 *  element written, empty ones included. Byte-identical to
 *  `cmt_pb_data_marshal` (types.pb.go:1552-1560) and produced by it.
 *  @return CMT_OK, CMT_REJECT if it does not fit or an element has a
 *          length with no bytes, CMT_FAULT on NULL. */
int cmt_pb_mempool_txs_marshal(const cmt_pb_mempool_txs_t *m, uint8_t *out,
                               size_t cap, size_t *out_len);

/** cometbft@709fd12b proto/tendermint/mempool/types.pb.go:307-388 —
 *  `Txs.Unmarshal`. Each element is COPIED into `arena` (:365-366
 *  allocates a fresh slice per element); an element beyond `txs_cap`
 *  or beyond the arena is REFUSED (INVARIANT 7495d337).
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_pb_mempool_txs_unmarshal(const uint8_t *in, size_t len,
                                 cmt_pb_mempool_txs_t *m,
                                 cmt_pb_arena_t *arena);

/** cometbft@709fd12b proto/tendermint/mempool/types.pb.go:261-274 —
 *  `Txs.Size()`: Σ (1 + len + sovTypes(len)) over the elements; 0 for
 *  NULL (:262-264). Reads only the LENGTHS, never the bytes, so a
 *  descriptor may be sized with `{NULL, n}` elements. */
size_t cmt_pb_mempool_txs_size(const cmt_pb_mempool_txs_t *m);

/* ── Message ────────────────────────────────────────────────────────── */

/** Go's zero `Message{}`: nil `Sum`, and the branch's slot storage
 *  preserved as `cmt_pb_mempool_txs_init` preserves it. */
void cmt_pb_mempool_message_init(cmt_pb_mempool_message_t *m);

/** cometbft@709fd12b proto/tendermint/mempool/types.pb.go:212-227 —
 *  `Message.MarshalToSizedBuffer` (nil Sum writes nothing) and :234-249
 *  `Message_Txs.MarshalToSizedBuffer` (`0a ‖ len ‖ Txs body`). Written
 *  FORWARDS here — tag, then the exact `Txs.Size()`, then the body
 *  through `cmt_pb_mempool_txs_marshal` — which is byte-identical to the
 *  backward generated writer because the size is exact.
 *  @return CMT_OK, CMT_REJECT if it does not fit or `sum` is outside
 *          {NONE, TXS} (the reference's `Sum` is a typed interface and
 *          can hold nothing else), CMT_FAULT on NULL. */
int cmt_pb_mempool_message_marshal(const cmt_pb_mempool_message_t *m,
                                   uint8_t *out, size_t cap,
                                   size_t *out_len);

/** cometbft@709fd12b proto/tendermint/mempool/types.pb.go:389-473 —
 *  `Message.Unmarshal`. Field 1 → a FRESH Txs decoded from the delimited
 *  body (:447-451); any other field skipped by wire type (:453-466). A
 *  nil `sum` after decoding is NOT refused here (the generated decoder
 *  accepts it); `cmt_pb_mempool_message_unwrap` refuses it.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_pb_mempool_message_unmarshal(const uint8_t *in, size_t len,
                                     cmt_pb_mempool_message_t *m,
                                     cmt_pb_arena_t *arena);

/** cometbft@709fd12b proto/tendermint/mempool/types.pb.go:276-286 —
 *  `Message.Size()`, with :288-299 `Message_Txs.Size()` folded in:
 *  0 for a nil Sum, else 1 + l + sovTypes(l) where l = Txs.Size(). */
size_t cmt_pb_mempool_message_size(const cmt_pb_mempool_message_t *m);

/* ── message.go — the p2p Wrapper / Unwrapper pair ──────────────────── */

/** cometbft@709fd12b proto/tendermint/mempool/message.go:29-33 —
 *  `(*Txs) Wrap()`: a Message whose Sum is this Txs. A SHALLOW copy —
 *  `out->txs` shares `m`'s slot storage, exactly as the Go wrapper shares
 *  the pointer.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_pb_mempool_txs_wrap(const cmt_pb_mempool_txs_t *m,
                            cmt_pb_mempool_message_t *out);

/** cometbft@709fd12b proto/tendermint/mempool/message.go:37-45 —
 *  `(*Message) Unwrap()`: the Txs branch, or the error "unknown message"
 *  for anything else (:42-43) — CMT_REJECT here. The p2p layer calls this
 *  on every received Message (p2p/peer.go:417-421) and a refused one
 *  stops the peer; the reactor port does the same.
 *  @param out receives a pointer INTO `m`; valid while `m` is.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_pb_mempool_message_unwrap(const cmt_pb_mempool_message_t *m,
                                  const cmt_pb_mempool_txs_t **out);

/* ── cometbft@v0.38.26 mempool/filter.go — the raw-bytes filter ─────── */

/**
 * Why `cmt_pb_mempool_filter_msg_bytes` refused, one value per error the
 * reference returns: the five sentinel errors of internal/protowire
 * (protowire.go:17-34) and the four of mempool/filter.go (:18-19, :118,
 * :126). Pure diagnosis — every non-OK value is the same refusal.
 */
typedef enum {
    CMT_PB_MEMPOOL_FILTER_OK                    = 0,
    CMT_PB_MEMPOOL_FILTER_VARINT_OVERFLOW       = 1, /* protowire.go:21 ErrVarintOverflow      */
    CMT_PB_MEMPOOL_FILTER_TRUNCATED_VARINT      = 2, /* protowire.go:23 ErrTruncatedVarint     */
    CMT_PB_MEMPOOL_FILTER_OUT_OF_BOUNDS         = 3, /* protowire.go:26 ErrOutOfBounds         */
    CMT_PB_MEMPOOL_FILTER_ILLEGAL_FIELD_NUMBER  = 4, /* protowire.go:29 ErrIllegalFieldNumber  */
    CMT_PB_MEMPOOL_FILTER_UNSUPPORTED_WIRE_TYPE = 5, /* protowire.go:32 ErrUnsupportedWireType */
    CMT_PB_MEMPOOL_FILTER_NO_TRANSACTIONS       = 6, /* filter.go:18 errNoTransactions         */
    CMT_PB_MEMPOOL_FILTER_EMPTY_TRANSACTION     = 7, /* filter.go:19 errEmptyTransaction       */
    CMT_PB_MEMPOOL_FILTER_TX_TOO_LARGE          = 8, /* filter.go:118 "exceeds max_tx_bytes"   */
    CMT_PB_MEMPOOL_FILTER_BATCH_TOO_LARGE       = 9  /* filter.go:126 "exceeds %d byte budget" */
} cmt_pb_mempool_filter_err_t;

/**
 * cometbft@v0.38.26 mempool/filter.go:46-79 — `filterMempoolMsgBytes`
 * (#5946, with #5948's 32-bit tag truncation), over the raw wire bytes of
 * a `tendermint.mempool.Message`, BEFORE any decode. Rules (filter.go:
 * 35-45): every varint / tag / length within the buffer; no EMPTY
 * transaction; none above `max_tx_bytes`; their sum at most
 * max(max_tx_bytes, max_batch_bytes); at least one transaction. A
 * non-positive limit disables that size check (:32-33).
 *
 * The walk is the reference's internal/protowire cursor, ported beside it
 * (cmt_pb_mempool.c): it names a field with `int32(wire >> 3)` exactly as
 * the generated decoder above does (`r_tag`, cmt_pb_wire.h), so the filter
 * and `cmt_pb_mempool_message_unmarshal` always agree on which bytes are a
 * transaction; and unlike the decoder's skipper it REFUSES group wire
 * types 3/4 (protowire.go:114-115).
 *
 * @param out_err may be NULL; receives why on CMT_REJECT, OK otherwise.
 * @return CMT_OK; CMT_REJECT (peer-reachable) on any rule; CMT_FAULT for
 *         NULL bytes with a non-zero length.
 */
int cmt_pb_mempool_filter_msg_bytes(const uint8_t *msg, size_t len,
                                    int max_tx_bytes, int max_batch_bytes,
                                    cmt_pb_mempool_filter_err_t *out_err);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PB_MEMPOOL_H */
