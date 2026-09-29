/**
 * @file shared/dnac/cmt_bsync_msgs.h
 * @brief cometbft @709fd12b `blocksync/msgs.go` + `blocksync/errors.go` +
 *        `proto/tendermint/blocksync/types.proto` (its generated
 *        `types.pb.go` codec) ported to C — the five messages of the
 *        block sync channel 0x40.
 *
 * Governing records: docs/plans/decisions/2026-09-29-blocksync-before-testnet.md
 * (operator, "Referanstan gidelim": MaxMsgSize = MaxBlockSizeBytes + 5,
 * msgs.go:14-18), docs/plans/2026-09-29-blocksync-port-design.md §1.
 *
 * ── THE WIRE (types.proto:118-152, types.pb.go:424-1497) ───────────────
 *   Message { oneof sum {
 *     BlockRequest    block_request     = 1;   { int64 height = 1; }
 *     NoBlockResponse no_block_response = 2;   { int64 height = 1; }
 *     BlockResponse   block_response    = 3;   { Block block = 1;
 *                                                ExtendedCommit ext_commit = 2; }
 *     StatusRequest   status_request    = 4;   { }
 *     StatusResponse  status_response   = 5;   { int64 height = 1;
 *                                                int64 base   = 2; } } }
 * Byte rules, each from the generated code:
 *   · a present oneof member is ALWAYS framed, even when its body is empty
 *     (types.pb.go:620-634 … :704-718 write `tag ‖ len ‖ body` whenever the
 *     member pointer is non-nil) — StatusRequest is `22 00`,
 *     BlockRequest{0} is `0a 00`;
 *   · a zero int64 is OMITTED inside the body (:444, :472, :570, :575); a
 *     negative one is a 10-byte varint (`uint64(m.Height)`);
 *   · BlockResponse writes ext_commit (field 2) only when non-nil (:500)
 *     and block (field 1) only when non-nil (:512); on the wire field 1
 *     comes first because the writer runs backward.
 * Decoder rules (types.pb.go:1273-1497, :875-1272):
 *   · every sum field must be wire type 2 (:1303, :1338, :1373, :1408,
 *     :1443) and every int64 field wire type 0 (:905, :974, :1215, :1234);
 *   · each sum occurrence builds a FRESH member (`v := &X{}`, :1331, :1366,
 *     :1401, :1436, :1471) and replaces `m.Sum` — the LAST occurrence wins,
 *     across fields and within one field;
 *   · inside ONE BlockResponse, a repeated field 1 or field 2 MERGES into
 *     the same Block / ExtendedCommit (`if m.Block == nil { new }` then
 *     `m.Block.Unmarshal(...)` without a reset, :1071-1076, :1107-1112).
 *     Protobuf defines merging two encodings of a message as parsing their
 *     CONCATENATION, which is what this port keeps: `block` / `ext_commit`
 *     are the concatenated payloads of every occurrence (a view into the
 *     input when there is one occurrence — the only case an honest encoder
 *     produces — and an owned copy otherwise). The Block and the
 *     ExtendedCommit themselves are decoded by the REACTOR
 *     (`cmt_pb_block_unmarshal` + `cmt_block_from_proto`,
 *     `cmt_pb_extended_commit_unmarshal` + `cmt_extended_commit_from_proto`),
 *     where the reference decodes them inside `Message.Unmarshal`. Either
 *     way a malformed Block stops the peer (p2p/peer.go:407-412 for the
 *     reference; reactor.go:265-270 here) and nothing else happens first:
 *     `ValidateMsg` returns nil for a BlockResponse (msgs.go:32-35).
 *   · unknown fields are skipped (:1477-1489); wire type 4 and a field
 *     number <= 0 are errors (:1295-1300).
 *
 * ── MaxMsgSize (msgs.go:12-19) ─────────────────────────────────────────
 * `types.MaxBlockSizeBytes + BlockResponseMessagePrefixSize (4) +
 * BlockResponseMessageFieldKeySize (1)` = 104 857 605 bytes, the channel's
 * `RecvMessageCapacity` (reactor.go:184). The operator chose the
 * reference's value over the chain's Block.MaxBytes (decision record,
 * "Mesaj sınırı referansla aynı").
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Pure functions of their arguments: no clock, no randomness, no map. A
 * message decides nothing about the chain by itself; the reactor verifies
 * every block it carries against a commit before anything is stored.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · the `Error()` string methods of errors.go:15-53 — display only; the
 *     error KINDS survive as `cmt_bsync_msg_err_t`;
 *   · `ErrReactorValidation.Unwrap` (errors.go:51-53) — Go error
 *     wrapping, no C counterpart;
 *   · types.pb.go's `String` / `Descriptor` / `XXX_*` / getters — Go
 *     reflection scaffolding.
 *
 * Reference @709fd12b: blocksync/msgs.go 56 lines, blocksync/errors.go 53
 * lines, proto/tendermint/blocksync/types.proto 43 lines, types.pb.go 1581
 * lines (/tmp/r2-a-ref/cometbft-709fd12b4b18cf1442d43c5d34009392c7d674ed).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_BSYNC_MSGS_H
#define SHARED_DNAC_CMT_BSYNC_MSGS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_params.h"   /* CMT_MAX_BLOCK_SIZE_BYTES */

#ifdef __cplusplus
extern "C" {
#endif

/** blocksync/reactor.go:20 — `BlocksyncChannel`. */
#define CMT_BSYNC_CHANNEL 0x40

/** msgs.go:14 — `BlockResponseMessagePrefixSize`. */
#define CMT_BSYNC_BLOCK_RESPONSE_MESSAGE_PREFIX_SIZE    4
/** msgs.go:15 — `BlockResponseMessageFieldKeySize`. */
#define CMT_BSYNC_BLOCK_RESPONSE_MESSAGE_FIELD_KEY_SIZE 1
/** msgs.go:16-18 — `MaxMsgSize`. */
#define CMT_BSYNC_MAX_MSG_SIZE                                  \
    ((size_t)CMT_MAX_BLOCK_SIZE_BYTES +                         \
     (size_t)CMT_BSYNC_BLOCK_RESPONSE_MESSAGE_PREFIX_SIZE +     \
     (size_t)CMT_BSYNC_BLOCK_RESPONSE_MESSAGE_FIELD_KEY_SIZE)

/** types.proto:144-151 — the oneof `sum`, by field number. NONE is the
 *  reference's nil `Sum` (an empty Message). */
typedef enum {
    CMT_BSYNC_MSG_NONE              = 0,
    CMT_BSYNC_MSG_BLOCK_REQUEST     = 1,
    CMT_BSYNC_MSG_NO_BLOCK_RESPONSE = 2,
    CMT_BSYNC_MSG_BLOCK_RESPONSE    = 3,
    CMT_BSYNC_MSG_STATUS_REQUEST    = 4,
    CMT_BSYNC_MSG_STATUS_RESPONSE   = 5
} cmt_bsync_msg_kind_t;

/**
 * One decoded (or to-be-encoded) Message. Only the fields of `kind` are
 * meaningful.
 *
 *   BLOCK_REQUEST / NO_BLOCK_RESPONSE : `height`
 *   STATUS_RESPONSE                   : `height`, `base`
 *   BLOCK_RESPONSE                    : `has_block` + `block`/`block_len`
 *                                       (the marshalled Block — the
 *                                       reference's non-nil `Block`),
 *                                       `has_ext_commit` + `ext_commit`/
 *                                       `ext_commit_len` (the marshalled
 *                                       ExtendedCommit, or nil)
 *
 * After `cmt_bsync_msg_unmarshal`, `block` / `ext_commit` point into the
 * input or into `block_owned` / `ext_owned` (file header, merge rule);
 * `cmt_bsync_msg_release` frees the latter. For marshalling the caller
 * sets the views and leaves the owned pointers NULL.
 */
typedef struct {
    cmt_bsync_msg_kind_t kind;
    int64_t              height;
    int64_t              base;
    bool                 has_block;
    const uint8_t       *block;
    size_t               block_len;
    bool                 has_ext_commit;
    const uint8_t       *ext_commit;
    size_t               ext_commit_len;
    uint8_t             *block_owned;   /* C-only: merged copy, or NULL */
    uint8_t             *ext_owned;     /* C-only: merged copy, or NULL */
} cmt_bsync_msg_t;

/** blocksync/errors.go — the error KINDS `ValidateMsg` returns. */
typedef enum {
    CMT_BSYNC_MSG_ERR_NONE           = 0,
    CMT_BSYNC_MSG_ERR_NIL_MESSAGE    = 1,  /* errors.go:10-13 ErrNilMessage   */
    CMT_BSYNC_MSG_ERR_INVALID_HEIGHT = 2,  /* errors.go:15-23 ErrInvalidHeight */
    CMT_BSYNC_MSG_ERR_INVALID_BASE   = 3,  /* errors.go:25-33 ErrInvalidBase   */
    CMT_BSYNC_MSG_ERR_UNKNOWN_TYPE   = 4   /* errors.go:35-41 ErrUnknownMessageType */
} cmt_bsync_msg_err_t;

/** C-only: a zeroed message (kind NONE, no views, nothing owned). */
void cmt_bsync_msg_init(cmt_bsync_msg_t *m);

/** C-only: frees `block_owned` / `ext_owned` and re-initialises `m`.
 *  NULL is a no-op. */
void cmt_bsync_msg_release(cmt_bsync_msg_t *m);

/**
 * types.pb.go:796-867 — `Message.Size()` for `m`: the exact byte length
 * `cmt_bsync_msg_marshal` produces. 0 for kind NONE (an empty Message).
 */
size_t cmt_bsync_msg_size(const cmt_bsync_msg_t *m);

/**
 * types.pb.go:583-718 — `Message.Marshal()` with the member of `m->kind`
 * as `Sum` (and the member bodies of :424-581). A BlockResponse is framed
 * from the ALREADY-MARSHALLED Block / ExtendedCommit bytes in the views.
 * @return CMT_OK; CMT_REJECT when it does not fit in `cap`; CMT_FAULT on
 *         NULL or a view that is NULL with a non-zero length.
 */
int cmt_bsync_msg_marshal(const cmt_bsync_msg_t *m, uint8_t *out, size_t cap,
                          size_t *out_len);

/**
 * types.pb.go:1273-1497 — `Message.Unmarshal()`, with the member bodies of
 * :875-1272 (file header: last-wins across sum occurrences, merge-as-
 * concatenation inside one BlockResponse). `out` is released first, so a
 * previously owned copy is never leaked; on failure `out` is left
 * released.
 * @return CMT_OK; CMT_REJECT for bytes the generated decoder refuses;
 *         CMT_FAULT on NULL or allocation failure.
 */
int cmt_bsync_msg_unmarshal(const uint8_t *in, size_t len,
                            cmt_bsync_msg_t *out);

/**
 * msgs.go:21-56 — `ValidateMsg(pb)`.
 *   · BlockRequest: height < 0 → ErrInvalidHeight (:29-31);
 *   · BlockResponse: nil — decoding is left to the reactor (:32-35);
 *   · NoBlockResponse: height < 0 → ErrInvalidHeight (:36-39);
 *   · StatusResponse: base < 0 → ErrInvalidBase (:41-43); height < 0 →
 *     ErrInvalidHeight (:44-46); base > height → ErrInvalidHeight (:47-49);
 *   · StatusRequest: nil (:50-51);
 *   · NONE (the nil Sum): ErrNilMessage (:23-25) — the reference reaches
 *     that only for a nil message, and p2p/peer.go:417-422's Unwrap of an
 *     empty Message stops the peer before ValidateMsg runs; both are "stop
 *     the peer", so the kind is reported here as NIL.
 * @param err may be NULL; receives the kind.
 * @return CMT_OK or CMT_REJECT (CMT_FAULT on NULL `m`).
 */
int cmt_bsync_validate_msg(const cmt_bsync_msg_t *m, cmt_bsync_msg_err_t *err);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_BSYNC_MSGS_H */
