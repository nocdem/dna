/**
 * @file shared/dnac/cmt_wal.h
 * @brief cometbft @709fd12b `consensus/wal.go`'s RECORD TYPES and the
 *        WAL codec of `consensus/msgs.go:240-347`, in C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-B of the cometbft → C consensus port. Nothing in the running
 * chain calls anything here yet; additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS FILE IS, AND WHAT IT DELIBERATELY IS NOT ─────────────────
 * It is the RECORD: the four things a WAL row can hold, the conversion
 * between them and their proto3 form, and the encode/decode of one
 * `TimedWALMessage` to and from the bytes `P`.
 *
 * It is NOT the log. The reference stores those bytes in an autofile group
 * behind a four-byte CRC32c and a four-byte length
 * (`WALEncoder.Encode` wal.go:288-330, `WALDecoder.Decode` :356-420); this
 * chain stores them as a SQLite row `SHA3-512(P) ‖ P` with the WALMessage
 * oneof's field number in the row's `kind` column (D-15 rev 5,
 * atlas-dec-c0bfc5344204b9282ceaaa5e06042350 — PROPOSED at the time this
 * file was written; the wave report says so). Everything on that side is
 * the HOST's and belongs to wave R3.
 *
 * taşınmadı, with the reason:
 *   · `WALEncoder` (:289-296) with `NewWALEncoder` (:294-296) and `Encode`
 *     (:301-330), and `WALDecoder` (:356-363) with `NewWALDecoder`
 *     (:361-363) and `Decode` (:366-420) — the FILE CONTAINER. The crc32c
 *     frame is replaced by the row digest; the MESSAGE half of Encode and
 *     Decode is `cmt_timed_wal_message_encode` / `_decode` below.
 *   · the `WAL` interface (:58-69) — a Go interface.
 *   · `BaseWAL` (:76-85) and every method on it: `NewWAL` (:91-...),
 *     `SetFlushInterval` (:111), `Group` (:115), `SetLogger` (:119),
 *     `OnStart` (:124), `processFlushTicks` (:142), `FlushAndSync`
 *     (:157), `OnStop` (:164), `Wait` (:177), `Write` (:184),
 *     `WriteSync` (:201), `SearchForEndHeight` (:231) and
 *     `WALSearchOptions` (:221) — HOST (storage, sync classes, search).
 *   · `nilWAL` (:422-434) — a no-op implementation of the same interface.
 *   · `init()` (:48-52) — amino/JSON type registration; this port has no
 *     JSON codec.
 *   · `IsDataCorruptionError` (:333-336) and `DataCorruptionError` with
 *     its `Error` and `Cause` (:339-349) — the error type the file
 *     container raises. The row digest raises the equivalent at the host,
 *     as CMT_FAULT (D-15: digest mismatch = stop, no skip).
 *   · `maxMsgSizeBytes` (:25) is REPRODUCED below because it bounds a
 *     record, but the check that uses it (:318-320, :385-390) is the file
 *     container's and is the host's to make.
 *
 * ── THE TIMESTAMP ──────────────────────────────────────────────────────
 * `TimedWALMessage.Time` is stamped by the HOST when it appends, through
 * the one clock callback (`wal.go:189` — `cmttime.Now()` inside
 * `BaseWAL.Write`), and the reference's own comment says what it is for:
 * "adds Time for debugging purposes" (:34). REPLAY NEVER READS IT —
 * `readReplayMessage` (replay.go:39-90) switches on `msg.Msg` and touches
 * `msg.Time` nowhere. The codec here only encodes what it is given.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Pure functions of their arguments. No clock, no allocation, no global
 * state. The `kind` values are fixed by the .proto and are the row's.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/wal.go   434 lines
 *                      f6bd6d512bbda08f31231d535b97df3c9c6feb3ddaf01a2054e2f0cf994f2a2d
 *   consensus/msgs.go  347 lines (:239-347)
 *                      7acb318c8910da0c0f4d874b9bd6bb4fdc7212736919939fc933dd405b8e4ada
 *   types/events.go    188 lines (:93-97, EventDataRoundState) — NOT in
 *                      any pin table; opened for that one range, SHA-256
 *                      13d8f653492d87fb90d1512ed0495d7d178839b371884e785b2620c29aae3cd5
 *   consensus/reactor.go:30 — maxMsgSize.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-15 rev 5 (atlas-dec-c0bfc5344204b9282ceaaa5e06042350, PROPOSED),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_WAL_H
#define SHARED_DNAC_CMT_WAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_time.h"
#include "cmt_msgs.h"    /* cmt_msg_info_t, cmt_timeout_info_t */

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@709fd12b consensus/reactor.go:30 — `maxMsgSize`, 1 MiB. */
#define CMT_MAX_MSG_SIZE 1048576

/** cometbft@709fd12b consensus/wal.go:25 — `maxMsgSizeBytes`,
 *  "time.Time + max consensus msg size". The bound on ONE record's bytes;
 *  the check itself is the file container's (see the header). */
#define CMT_WAL_MAX_MSG_SIZE_BYTES (CMT_MAX_MSG_SIZE + 24)

/**
 * cometbft@709fd12b types/events.go:93-97 —
 * `type EventDataRoundState struct` {Height int64, Round int32,
 * Step string}.
 *
 * Field-identical to the proto message of types/events.proto:6-10, and
 * msgs.go:247-251 / :306-310 copy the three fields straight across, so it
 * is that type. `step` is bounded by CMT_PB_ROUND_STEP_STR_MAX — see
 * cmt_pb.h for where the bound comes from.
 */
typedef cmt_pb_event_data_round_state_t cmt_event_data_round_state_t;

/** cometbft@709fd12b consensus/wal.go:42-44 —
 *  `type EndHeightMessage struct`. */
typedef struct {
    int64_t height;   /* wal.go:43 */
} cmt_end_height_msg_t;

/**
 * cometbft@709fd12b consensus/wal.go:46 — `type WALMessage interface{}`,
 * as a tagged union of the FOUR kinds the oneof admits.
 *
 * THE TAG IS THE ONEOF FIELD NUMBER, 1-4 (consensus/wal.proto:33-40), and
 * it is the value the host stores in the row's `kind` column (D-15 rev 5).
 * `CMT_PB_WAL_NONE` is Go's nil interface, which both directions refuse:
 * `WALToProto` falls to its default (msgs.go:290-291) and `WALFromProto`
 * refuses a nil message (:299-301).
 *
 * ⚠ LARGE — the MSG_INFO branch carries a whole `cmt_msg_t`. Heap-
 * allocate it.
 */
typedef cmt_pb_wal_kind_t cmt_wal_kind_t;

typedef struct {
    cmt_wal_kind_t kind;
    union {
        cmt_event_data_round_state_t event_data_round_state; /* 1 */
        cmt_msg_info_t               msg_info;               /* 2 */
        cmt_timeout_info_t           timeout_info;           /* 3 */
        cmt_end_height_msg_t         end_height;             /* 4 */
    } u;
} cmt_wal_message_t;

/**
 * cometbft@709fd12b consensus/wal.go:35-38 —
 * `type TimedWALMessage struct`.
 *
 * `time` is Go's `time.Time`: use CMT_TIME_ZERO for its zero value, never
 * a memset (cmt_time.h). A `msg` whose kind is NONE is Go's nil interface
 * and is refused by the encoder.
 */
typedef struct {
    cmt_time_t        time;   /* wal.go:36 */
    cmt_wal_message_t msg;    /* wal.go:37 */
} cmt_timed_wal_message_t;

/* ══ msgs.go — the WAL codec ══════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/msgs.go:240-295 — `WALToProto()`.
 *
 * The four cases in the reference's order. The MsgInfo case (:254-270)
 * runs `MsgToProto` and then the p2p `Wrap()` of
 * proto/tendermint/consensus/message.go:21-74, which is the oneof
 * assignment `cmt_msg_to_proto` already performs — the two steps are one
 * here, and the `cm := consMsg.(*cmtcons.Message)` assertion of :262
 * cannot fail because the C function's output type IS that message.
 *
 * @return CMT_OK, CMT_REJECT (:290-291 "wal message not recognized", or a
 *         message that will not convert), CMT_FAULT on NULL or on the
 *         MsgToProto FAULT site (cmt_msgs.h).
 */
int cmt_wal_to_proto(const cmt_wal_message_t *msg,
                     cmt_pb_wal_message_t *out);

/**
 * cometbft@709fd12b consensus/msgs.go:298-347 — `WALFromProto()`.
 *
 * The four cases in the reference's order: the round-state event
 * (:305-310), MsgInfo through `Unwrap()` (message.go:78-109) and
 * `MsgFromProto` (:311-323), TimeoutInfo with `SafeConvertUint8` on Step
 * (:325-337), and EndHeight (:338-342).
 *
 * ⚠ The MsgInfo branch inherits `cmt_msg_from_proto`'s gap: the reference
 * would have run `ValidateBasic` inside it (msgs.go:232-234) and this port
 * does not. See cmt_msgs.h.
 *
 * @return CMT_OK; CMT_REJECT for :343-344 (a kind this build does not
 *         recognise) and for a message that will not convert; CMT_FAULT on
 *         a NULL argument, which is a caller bug and NOT the reference's
 *         :299-301. The reference's nil message is an ABSENT field 2 on
 *         the wire and is refused one frame out, in
 *         `cmt_timed_wal_message_decode`.
 */
int cmt_wal_from_proto(const cmt_pb_wal_message_t *msg,
                       cmt_wal_message_t *out);

/**
 * The MESSAGE half of `WALEncoder.Encode` (cometbft@709fd12b
 * consensus/wal.go:301-314): `WALToProto` (:302), the TimedWALMessage
 * built around it (:306-309) and `proto.Marshal` (:311).
 *
 * Produces `P` — the bytes the reference then frames with a CRC and a
 * length (:316-326) and this chain stores as `SHA3-512(P) ‖ P`. NO CRC,
 * NO LENGTH PREFIX, NO FRAME.
 *
 * `v->time` is whatever the caller stamped; this function reads no clock.
 *
 * ALLOCATES one `cmt_pb_timed_wal_message_t` on the HEAP and frees it
 * before returning: the wire form embeds a whole Message union, whose
 * widest branch is a BlockPart carrying a 64 KiB part and a 100-aunt
 * proof, which is not a stack local. A failed allocation is CMT_FAULT.
 *
 * @param cap the caller's buffer; CMT_WAL_MAX_MSG_SIZE_BYTES always
 *        suffices for a record the reference would accept.
 * @return CMT_OK, CMT_REJECT (it does not fit, or the message will not
 *         convert — the reference's :303-305 error and its :312-314
 *         panic), CMT_FAULT on NULL, on a WALToProto FAULT, or on a
 *         failed allocation.
 */
int cmt_timed_wal_message_encode(const cmt_timed_wal_message_t *v,
                                 uint8_t *out, size_t cap, size_t *out_len);

/**
 * The MESSAGE half of `WALDecoder.Decode` (cometbft@709fd12b
 * consensus/wal.go:404-419): `proto.Unmarshal` into a TimedWALMessage
 * (:404-408) and `WALFromProto` on its `Msg` (:410-413), then the pair
 * `{Time, Msg}` of :414-417.
 *
 * The caller has already checked the row digest and knows the length; the
 * CRC and length reads of :367-402 are the container's.
 *
 * ALLOCATES and frees one `cmt_pb_timed_wal_message_t`, for the reason
 * `cmt_timed_wal_message_encode` gives. The ARENA is separate and is the
 * caller's; nothing decoded points into the temporary.
 *
 * @param arena receives every variable-length payload the record carries
 *        (a block part's bytes, a vote extension). It must outlive `*out`;
 *        no pointer into `in` survives (cmt_pb.h).
 * @return CMT_OK, CMT_REJECT (malformed bytes, or a message the reference
 *         would have refused), CMT_FAULT on NULL or a failed allocation.
 */
int cmt_timed_wal_message_decode(const uint8_t *in, size_t len,
                                 cmt_timed_wal_message_t *out,
                                 cmt_pb_arena_t *arena);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_WAL_H */
