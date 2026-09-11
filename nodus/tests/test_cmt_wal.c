/**
 * Nodus — cometbft @709fd12b C port, wave R2-B: the WAL record codec
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That one WAL record converts to its proto3 form and back without
 * changing a byte, and that its KIND — the WALMessage oneof's field
 * number, which is the value the host stores in the row's `kind` column
 * (D-15 rev 5, atlas-dec-c0bfc5344204b9282ceaaa5e06042350) — is 1 for a
 * round-state event, 2 for a peer or own message, 3 for a timeout and 4
 * for an end-of-height marker. If this file failed, one of these would be
 * false:
 *   · all four kinds survive WALToProto → encode → decode → WALFromProto
 *     with an identical encoding;
 *   · a kind whose body is EMPTY is still written, so the kind is
 *     recoverable from the row: EndHeight{0} is `22 00` and a zero
 *     TimeoutInfo duration is `0a 00`;
 *   · TimeoutInfo's duration is a NANOSECOND count that survives the
 *     google.protobuf.Duration round trip, negatives included, and a
 *     duration the reference's validateDuration refuses is refused here;
 *   · a peer id is exactly 0 or 32 bytes and nothing else;
 *   · TimedWALMessage's time is ALWAYS emitted, so Go's ZERO time is the
 *     eleven bytes of K-1 rev 2 rule (c) and not an omission;
 *   · an unrecognised WAL message is refused in both directions
 *     (msgs.go:290-291, :343-344).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, no clock, no RNG, no database. Safe under
 * `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. Records are HEAP-allocated because a `cmt_wal_message_t`
 * carries a whole `cmt_msg_t`; every allocation is freed on the success
 * path and a CHECK failure returns early and leaks.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. IT TESTS NO STORAGE. The reference's file container — the four-byte
 *     CRC32c, the four-byte length, the autofile group, `SearchForEnd-
 *     Height`, the sync classes — is not in this port at all (cmt_wal.h),
 *     and this chain's replacement (a SQLite row `SHA3-512(P) ‖ P`) is the
 *     HOST's and is wave R3's. A green here says nothing about durability,
 *     ordering, pruning or the startup table.
 *  2. It does not validate. The MsgInfo branch goes through
 *     `cmt_msg_from_proto`, which stops before the reference's
 *     `ValidateBasic` (msgs.go:232-234), so a record this file accepts may
 *     still be one the reference would refuse.
 *  3. `TimedWALMessage.Time` is only carried, never interpreted: the
 *     reference stamps it "for debugging purposes" (wal.go:34) and replay
 *     never reads it. A test that passed with the field ignored entirely
 *     would look the same except for the two byte-level assertions here.
 *
 * ── REFERENCE TEST CASES PORTED ────────────────────────────────────────
 * consensus/msgs_test.go `TestWALMsgProto` (:198-301) — the four kinds and
 * the failure case; UNPINNED at the time of writing, SHA-256
 * ffdb0d011f00ff58643eacdeaf36ece417f532dc36eecf6667d5cd760ba7e3ec.
 * consensus/wal_test.go `TestWALEncoderDecoder` (:83-108) — an encode
 * followed by a decode, ported as a CODEC round trip: its file writer and
 * reader halves are the container's and are not ported (wal_test.go is
 * pinned by rev 6, SHA-256
 * ed299b4395ccc7f0d40e85321dcd54ba7ac9a25c997f878bb38f0b773a0d922b).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_wal.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static uint8_t HASH_A[64], HASH_B[64];
static uint8_t ADDR_A[32];
static uint8_t SIG_S[9];
static const cmt_time_t TS_A = { 1700000000LL, 123456789 };
static const uint8_t TEST_BYTES[4] = { 't', 'e', 's', 't' };
static const uint8_t RONIES[6] = { 'r', 'o', 'n', 'i', 'e', 's' };

static void pat(uint8_t *out, size_t n, unsigned seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static void build_fixtures(void)
{
    pat(HASH_A, sizeof(HASH_A), 0x10);
    pat(HASH_B, sizeof(HASH_B), 0x20);
    pat(ADDR_A, sizeof(ADDR_A), 0x40);
    pat(SIG_S,  sizeof(SIG_S),  0x60);
}

static uint8_t g_buf[16384];
static uint8_t g_buf2[16384];
static uint8_t g_arena_bytes[8192];
static cmt_pb_arena_t g_arena;

static void arena_reset(void)
{
    g_arena.buf  = g_arena_bytes;
    g_arena.cap  = sizeof(g_arena_bytes);
    g_arena.used = 0;
}

/**
 * One record through the whole codec: encode to P, decode P, re-encode,
 * and the two byte strings must be identical. This is the message half of
 * wal_test.go's TestWALEncoderDecoder (:83-108) — the file frame it wraps
 * around P is not part of this port.
 */
static int record_round_trip(const char *what,
                             const cmt_timed_wal_message_t *v,
                             size_t *out_len, cmt_wal_kind_t *out_kind)
{
    cmt_timed_wal_message_t *back;
    size_t                   n1 = 0;
    size_t                   n2 = 0;
    int                      ok = 0;

    back = (cmt_timed_wal_message_t *)malloc(sizeof(*back));
    if (back == NULL) {
        fprintf(stderr, "%s: out of memory\n", what);
        return 0;
    }
    if (cmt_timed_wal_message_encode(v, g_buf, sizeof(g_buf), &n1)
            != CMT_OK) {
        fprintf(stderr, "%s: encode failed\n", what);
        goto done;
    }
    arena_reset();
    if (cmt_timed_wal_message_decode(g_buf, n1, back, &g_arena) != CMT_OK) {
        fprintf(stderr, "%s: decode failed\n", what);
        goto done;
    }
    if (cmt_timed_wal_message_encode(back, g_buf2, sizeof(g_buf2), &n2)
            != CMT_OK) {
        fprintf(stderr, "%s: re-encode failed\n", what);
        goto done;
    }
    if (n1 != n2 || memcmp(g_buf, g_buf2, n1) != 0) {
        fprintf(stderr, "%s: round trip differs (%zu vs %zu)\n", what, n1,
                n2);
        goto done;
    }
    if (back->msg.kind != v->msg.kind) {
        fprintf(stderr, "%s: kind changed\n", what);
        goto done;
    }
    if (back->time.seconds != v->time.seconds ||
        back->time.nanos != v->time.nanos) {
        fprintf(stderr, "%s: time changed\n", what);
        goto done;
    }
    if (out_len != NULL)  { *out_len = n1; }
    if (out_kind != NULL) { *out_kind = back->msg.kind; }
    ok = 1;
done:
    free(back);
    return ok;
}

/* ══ the four kinds ═══════════════════════════════════════════════════ */

static int test_four_kinds(void)
{
    cmt_timed_wal_message_t *v;
    cmt_wal_kind_t           kind = CMT_PB_WAL_NONE;
    size_t                   n = 0;

    v = (cmt_timed_wal_message_t *)malloc(sizeof(*v));
    CHECK(v != NULL, "allocation");

    /* KIND 1 — types.EventDataRoundState (msgs.go:244-253 / :305-310).
     * msgs_test.go:219-231 uses Height 2, Round 1, Step "ronies". */
    memset(v, 0, sizeof(*v));
    v->time = TS_A;
    v->msg.kind = CMT_PB_WAL_EVENT_DATA_ROUND_STATE;
    v->msg.u.event_data_round_state.height = 2;
    v->msg.u.event_data_round_state.round  = 1;
    memcpy(v->msg.u.event_data_round_state.step, RONIES, sizeof(RONIES));
    v->msg.u.event_data_round_state.step_len = sizeof(RONIES);
    CHECK(record_round_trip("kind 1", v, &n, &kind), "round trip");
    CHECK(kind == 1, "the round-state event is kind 1");
    OK();

    /* KIND 2 — msgInfo (msgs.go:254-270 / :311-323). msgs_test.go:232-254
     * wraps a BlockPartMessage with a peer id. */
    memset(v, 0, sizeof(*v));
    v->time = TS_A;
    v->msg.kind = CMT_PB_WAL_MSG_INFO;
    v->msg.u.msg_info.msg.kind = CMT_PB_CONS_MSG_BLOCK_PART;
    v->msg.u.msg_info.msg.u.block_part.height = 100;
    v->msg.u.msg_info.msg.u.block_part.round  = 1;
    cmt_pb_part_init(&v->msg.u.msg_info.msg.u.block_part.part);
    v->msg.u.msg_info.msg.u.block_part.part.index      = 1;
    v->msg.u.msg_info.msg.u.block_part.part.bytes.data = TEST_BYTES;
    v->msg.u.msg_info.msg.u.block_part.part.bytes.len  =
        sizeof(TEST_BYTES);
    v->msg.u.msg_info.msg.u.block_part.part.proof.total = 1;
    v->msg.u.msg_info.msg.u.block_part.part.proof.index = 1;
    memcpy(v->msg.u.msg_info.msg.u.block_part.part.proof.leaf_hash,
           HASH_A, 64);
    v->msg.u.msg_info.msg.u.block_part.part.proof.leaf_hash_len = 64;
    memcpy(v->msg.u.msg_info.peer_id, ADDR_A, 32);
    v->msg.u.msg_info.peer_id_len = 32;
    CHECK(record_round_trip("kind 2", v, &n, &kind), "round trip");
    CHECK(kind == 2, "a message from a peer is kind 2");
    OK();

    /* The node's OWN message: an EMPTY peer id, which is the reference's
     * `PeerID: ""` (state.go:839) and is omitted on the wire. */
    v->msg.u.msg_info.peer_id_len = 0;
    CHECK(record_round_trip("kind 2 own", v, &n, &kind), "round trip");
    CHECK(kind == 2, "the node's own message is still kind 2");
    OK();

    /* KIND 3 — timeoutInfo (msgs.go:271-281 / :325-337).
     * msgs_test.go:255-269 uses Duration(100), 1, 1, 1. */
    memset(v, 0, sizeof(*v));
    v->time = TS_A;
    v->msg.kind = CMT_PB_WAL_TIMEOUT_INFO;
    v->msg.u.timeout_info.duration = 100;
    v->msg.u.timeout_info.height   = 1;
    v->msg.u.timeout_info.round    = 1;
    v->msg.u.timeout_info.step     = 1;
    CHECK(record_round_trip("kind 3", v, &n, &kind), "round trip");
    CHECK(kind == 3, "a timeout is kind 3");
    OK();

    /* KIND 4 — EndHeightMessage (msgs.go:282-289 / :338-342). */
    memset(v, 0, sizeof(*v));
    v->time = TS_A;
    v->msg.kind = CMT_PB_WAL_END_HEIGHT;
    v->msg.u.end_height.height = 1;
    CHECK(record_round_trip("kind 4", v, &n, &kind), "round trip");
    CHECK(kind == 4, "the end-of-height marker is kind 4");
    OK();

    /* THE TWO EMPTY-BODY CASES, which are the ones that could lose their
     * kind if a field were omitted. */
    v->msg.u.end_height.height = 0;
    CHECK(record_round_trip("kind 4 at height 0", v, &n, &kind),
          "round trip");
    CHECK(kind == 4,
          "EndHeight{0} has an EMPTY body and still decodes as kind 4");
    OK();

    memset(v, 0, sizeof(*v));
    v->time = TS_A;
    v->msg.kind = CMT_PB_WAL_TIMEOUT_INFO;
    v->msg.u.timeout_info.duration = 0;      /* the zero Duration */
    CHECK(record_round_trip("kind 3 all zero", v, &n, &kind), "round trip");
    CHECK(kind == 3,
          "a TimeoutInfo with a zero duration and zero H/R/S is still"
          " kind 3 — its Duration field is written unconditionally");
    OK();

    free(v);
    return 0;
}

/* ══ TimedWALMessage's stamp ══════════════════════════════════════════ */

static int test_time_field(void)
{
    cmt_timed_wal_message_t *v;
    cmt_timed_wal_message_t *back;
    size_t                   n_zero = 0;
    size_t                   n_ts = 0;

    v    = (cmt_timed_wal_message_t *)malloc(sizeof(*v));
    back = (cmt_timed_wal_message_t *)malloc(sizeof(*back));
    CHECK(v != NULL && back != NULL, "allocation");

    memset(v, 0, sizeof(*v));
    v->msg.kind = CMT_PB_WAL_END_HEIGHT;
    v->msg.u.end_height.height = 7;

    /* Go's ZERO time is seconds = -62135596800, which is ELEVEN bytes.
     * A memset would have given 1970, which is ZERO bytes — the mistake
     * cmt_time.h warns about, and the difference is visible in the
     * length. */
    v->time = CMT_TIME_ZERO;
    CHECK(cmt_timed_wal_message_encode(v, g_buf, sizeof(g_buf), &n_zero)
          == CMT_OK, "encode with the zero time");
    v->time.seconds = 0;
    v->time.nanos   = 0;
    CHECK(cmt_timed_wal_message_encode(v, g_buf2, sizeof(g_buf2), &n_ts)
          == CMT_OK, "encode with the Unix epoch");
    CHECK(n_zero == n_ts + 11u,
          "Go's zero time costs eleven bytes that the Unix epoch does"
          " not — they are NOT the same value");
    OK();

    /* The stamp is carried, not interpreted: it comes back unchanged. */
    v->time = TS_A;
    CHECK(cmt_timed_wal_message_encode(v, g_buf, sizeof(g_buf), &n_ts)
          == CMT_OK, "encode");
    arena_reset();
    CHECK(cmt_timed_wal_message_decode(g_buf, n_ts, back, &g_arena)
          == CMT_OK && back->time.seconds == TS_A.seconds &&
          back->time.nanos == TS_A.nanos,
          "and the stamp survives the round trip exactly");
    OK();

    /* A record whose Msg field is ABSENT is refused: the reference's
     * WALFromProto refuses a nil message (msgs.go:299-301). */
    {
        /* HEAP, like every other record in this file: the struct carries a
         * whole cmt_pb_wal_message_t and does not belong on the stack. */
        cmt_pb_timed_wal_message_t *pv =
            (cmt_pb_timed_wal_message_t *)malloc(sizeof(*pv));
        size_t                      n = 0;

        if (pv == NULL) {
            fprintf(stderr, "out of memory\n");
            free(v);
            free(back);
            return 1;
        }
        cmt_pb_timed_wal_message_init(pv);
        pv->time    = TS_A;
        pv->has_msg = false;
        CHECK(cmt_pb_timed_wal_message_marshal(pv, g_buf, sizeof(g_buf),
                                               &n) == CMT_OK, "marshal");
        arena_reset();
        CHECK(cmt_timed_wal_message_decode(g_buf, n, back, &g_arena)
              == CMT_REJECT, "a record with no message must REJECT");
        OK();
        free(pv);
    }

    free(v);
    free(back);
    return 0;
}

/* ══ TimeoutInfo's duration ═══════════════════════════════════════════ */

static int test_duration_cases(void)
{
    cmt_timed_wal_message_t *v;
    cmt_timed_wal_message_t *back;
    size_t                   n = 0;
    size_t                   i;
    static const int64_t     cases[] = {
        0, 1, -1, 100, 1000000000LL, -1000000000LL, 1500000000LL,
        -1500000000LL, 999999999LL, -999999999LL,
        9223372036854775807LL,        /* the largest time.Duration */
        -9223372036854775807LL - 1LL  /* and the smallest          */
    };

    v    = (cmt_timed_wal_message_t *)malloc(sizeof(*v));
    back = (cmt_timed_wal_message_t *)malloc(sizeof(*back));
    CHECK(v != NULL && back != NULL, "allocation");

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(v, 0, sizeof(*v));
        v->time = TS_A;
        v->msg.kind = CMT_PB_WAL_TIMEOUT_INFO;
        v->msg.u.timeout_info.duration = cases[i];
        v->msg.u.timeout_info.height   = 3;
        v->msg.u.timeout_info.round    = 2;
        v->msg.u.timeout_info.step     = 4;
        CHECK(cmt_timed_wal_message_encode(v, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "a nanosecond count always encodes");
        arena_reset();
        CHECK(cmt_timed_wal_message_decode(g_buf, n, back, &g_arena)
              == CMT_OK &&
              back->msg.u.timeout_info.duration == cases[i] &&
              back->msg.u.timeout_info.height == 3 &&
              back->msg.u.timeout_info.round == 2 &&
              back->msg.u.timeout_info.step == 4,
              "and comes back as the same count, sign included");
    }
    OK();

    /* A Duration on the wire that validateDuration refuses
     * (gogoproto duration.go:54-69) must refuse the whole record. The
     * body below is Duration{seconds = 0, nanos = 1e9}. */
    {
        static const uint8_t bad_nanos[6] = {
            0x10, 0x80, 0x94, 0xeb, 0xdc, 0x03
        };
        uint8_t  rec[64];
        size_t   off = 0;

        /* TimedWALMessage{time = Unix epoch (omitted), msg = WALMessage{
         *   timeout_info = TimeoutInfo{duration = bad}}} */
        rec[off++] = 0x0a;                 /* TimedWALMessage field 1 */
        rec[off++] = 0x00;                 /* zero-length Timestamp    */
        rec[off++] = 0x12;                 /* field 2, WALMessage      */
        rec[off++] = (uint8_t)(2u + 2u + sizeof(bad_nanos));
        rec[off++] = 0x1a;                 /* WALMessage kind 3        */
        rec[off++] = (uint8_t)(2u + sizeof(bad_nanos));
        rec[off++] = 0x0a;                 /* TimeoutInfo field 1      */
        rec[off++] = (uint8_t)sizeof(bad_nanos);
        memcpy(rec + off, bad_nanos, sizeof(bad_nanos));
        off += sizeof(bad_nanos);
        arena_reset();
        CHECK(cmt_timed_wal_message_decode(rec, off, back, &g_arena)
              == CMT_REJECT,
              "a Duration with nanos = 1e9 must refuse the record");
        OK();
    }

    free(v);
    free(back);
    return 0;
}

/* ══ the peer id, and the refusals ════════════════════════════════════ */

static int test_peer_id_and_refusals(void)
{
    cmt_wal_message_t    *w;
    cmt_pb_wal_message_t *pb;

    w  = (cmt_wal_message_t *)malloc(sizeof(*w));
    pb = (cmt_pb_wal_message_t *)malloc(sizeof(*pb));
    CHECK(w != NULL && pb != NULL, "allocation");

    memset(w, 0, sizeof(*w));
    w->kind = CMT_PB_WAL_MSG_INFO;
    w->u.msg_info.msg.kind = CMT_PB_CONS_MSG_HAS_VOTE;
    w->u.msg_info.msg.u.has_vote.height = 1;
    w->u.msg_info.msg.u.has_vote.type   = 1;

    w->u.msg_info.peer_id_len = 0;
    CHECK(cmt_wal_to_proto(w, pb) == CMT_OK, "an empty peer id is allowed");
    memcpy(w->u.msg_info.peer_id, ADDR_A, 32);
    w->u.msg_info.peer_id_len = 32;
    CHECK(cmt_wal_to_proto(w, pb) == CMT_OK,
          "and so is the 32-byte witness id");
    w->u.msg_info.peer_id_len = 31;
    CHECK(cmt_wal_to_proto(w, pb) == CMT_REJECT, "31 bytes must REJECT");
    w->u.msg_info.peer_id_len = 1;
    CHECK(cmt_wal_to_proto(w, pb) == CMT_REJECT, "one byte must REJECT");
    OK();

    /* msgs.go:290-291 — an unrecognised WAL message. */
    memset(w, 0, sizeof(*w));
    w->kind = CMT_PB_WAL_NONE;
    CHECK(cmt_wal_to_proto(w, pb) == CMT_REJECT,
          "a record with no kind is refused");
    w->kind = (cmt_wal_kind_t)9;
    CHECK(cmt_wal_to_proto(w, pb) == CMT_REJECT,
          "and so is an unknown kind");
    OK();

    /* msgs.go:343-344 — the same on the way back. */
    cmt_pb_wal_message_init(pb);
    CHECK(cmt_wal_from_proto(pb, w) == CMT_REJECT,
          "a wire record with no branch is refused");
    pb->sum = (cmt_pb_wal_kind_t)9;
    CHECK(cmt_wal_from_proto(pb, w) == CMT_REJECT,
          "and so is one on an unknown branch");
    OK();

    /* msgs.go:326-330 — SafeConvertUint8 on TimeoutInfo.Step, the same
     * denial MsgFromProto makes on NewRoundStep.Step. */
    cmt_pb_wal_message_init(pb);
    pb->sum = CMT_PB_WAL_TIMEOUT_INFO;
    cmt_pb_timeout_info_init(&pb->u.timeout_info);
    pb->u.timeout_info.step = 255;
    CHECK(cmt_wal_from_proto(pb, w) == CMT_OK &&
          w->u.timeout_info.step == 255, "Step 255 converts");
    pb->u.timeout_info.step = 256;
    CHECK(cmt_wal_from_proto(pb, w) == CMT_REJECT, "Step 256 is denied");
    OK();

    /* NULL arguments are FAULT. */
    CHECK(cmt_wal_to_proto(NULL, pb) == CMT_FAULT, "NULL record");
    CHECK(cmt_wal_from_proto(NULL, w) == CMT_FAULT, "NULL proto");
    CHECK(cmt_timed_wal_message_encode(NULL, g_buf, sizeof(g_buf), NULL)
          == CMT_FAULT, "NULL record to encode");
    OK();

    free(w);
    free(pb);
    return 0;
}

int main(void)
{
    build_fixtures();
    arena_reset();

    if (test_four_kinds() != 0)           { return 1; }
    if (test_time_field() != 0)           { return 1; }
    if (test_duration_cases() != 0)       { return 1; }
    if (test_peer_id_and_refusals() != 0) { return 1; }

    printf("test_cmt_wal: OK (%d groups)\n", g_checks);
    return 0;
}
