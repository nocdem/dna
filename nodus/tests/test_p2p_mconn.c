/**
 * @file nodus/tests/test_p2p_mconn.c
 * @brief Tests for shared/dnac/cmt_p2p_mconn (+ cmt_flowrate,
 *        cmt_p2p_protoio) — cometbft @709fd12b p2p/conn/connection.go,
 *        libs/flowrate, libs/timer/throttle_timer.go and libs/protoio's
 *        reader ported to C (fleet P2P-PORT, F2).
 *
 * Governing: docs/plans/2026-09-26-p2p-port-design.md §1, §2 rows 2-4, §5
 * (R-P2P-2, R-P2P-15..21 proposed by this phase), §6;
 * docs/plans/decisions/2026-09-26-witness-port-session.md.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · Packet bytes are the reference's: TestConnVectors
 *     (connection_test.go:568-589) byte-exact; `maxPacketMsgSize` = 1034
 *     at payload 1024 (connection.go:705-715); a PacketMsg on channel 0x00
 *     carries no field 1 and is still received.
 *   · send / receive over a loopback pair (TestMConnectionSend/Receive),
 *     and a PacketMsg reaches `out` only when the flush throttle fires
 *     (100 ms, not 99) — ping / pong are flushed at once.
 *   · a message larger than the payload is split into ceil(len / 1024)
 *     packets, EOF on the last only, and reassembled byte-identical — also
 *     when the stream arrives ONE BYTE per recv call.
 *   · TrySend on a full queue returns false and changes nothing; CanSend's
 *     constant-1 rule (TestMConnectionTrySend); an unknown channel is
 *     refused on send (TestMConnectionSend).
 *   · receive errors, each → on_error once with its reason, connection
 *     stopped: RecvMessageCapacity exceeded; unknown channel
 *     (TestMConnectionReadErrorUnknownChannel); packet longer than
 *     maxPacketMsgSize (TestMConnectionReadErrorLongMessage, the 1024
 *     payload itself accepted); channel id 1025 and -1
 *     (TestMConnectionChannelOverflow); bad encoding
 *     (TestMConnectionReadErrorBadEncoding); a Packet with no member and a
 *     Header-like body (TestMConnectionReadErrorUnknownMsgType).
 *   · the int32 channel-id truncation quirk: a varint whose low 32 bits
 *     are 1 is delivered on channel 1.
 *   · an empty message is delivered as a zero-length message.
 *   · ping at PingInterval, answered with pong, no error after the pong
 *     timeout (TestMConnectionPingPongs); no pong → PONG_TIMEOUT
 *     (TestMConnectionPongTimeoutResultsInError); pongs before any ping are
 *     harmless (TestMConnectionMultiplePongsInTheBeginning); three pings
 *     in one read → ONE pong (the cap-1 `pong` channel), and ping-by-ping
 *     each is answered (TestMConnectionMultiplePings).
 *   · priority: selectChannelToGossipOn's recentlySent / priority rule,
 *     ties to the earlier channel, and the wire order A,B,B,B,A,A for
 *     priorities 1 vs 10; updateStats' ×0.8.
 *   · flowrate: clock() rounding, Limit's per-sample budget (non-blocking
 *     and the would-block / retry form), and the MConnection's send AND
 *     receive routines held by it until the next 100 ms sample.
 *   · FlushStop writes every queued message out and flushes at once; Stop
 *     drops everything; init refuses the reference's panics.
 *   · end to end: two REAL F1 SecretConnections (ML-KEM-1024 + ML-DSA-87)
 *     carrying two MConnections, messages both ways on two channels
 *     (one of them split over several sealed frames), all delivered in
 *     order.
 *
 * WHAT IT REQUIRES: nothing beyond a default nodus build (no compile
 * flags, no environment). WHAT IT LEAVES BEHIND: nothing (no files, no
 * sockets, no threads).
 *
 * HOW IT CAN LIE: time is a FAKE clock advanced by the test, so the
 * timer cases prove the ORDER and the thresholds of the timers, not their
 * behaviour under a real, jittery clock. The reference's goroutine
 * concurrency (a Send racing the send routine, a timer firing mid-case) is
 * not reproducible here by construction; the fixed select order
 * (R-P2P-18) is one of the reference's schedules, not all of them. The
 * wire vectors are checked against connection_test.go:575-577; the other
 * byte layouts are checked for self-consistency plus the reference's
 * generated size functions, not against a live cometbft peer.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_mconn.h"
#include "dnac/cmt_p2p_protoio.h"
#include "dnac/cmt_flowrate.h"
#include "dnac/cmt_p2p_secret.h"
#include "dnac/cmt_pb.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define MS (1000LL * 1000)

/* ══ the fake clock and the host ═════════════════════════════════════ */

static int64_t g_now = 1000 * MS;

static int64_t host_now(void *ctx)
{
    (void)ctx;
    return g_now;
}

#define MAX_RMSGS 64

typedef struct {
    uint8_t  ch;
    size_t   len;
    uint8_t *b;
} rmsg_t;

typedef struct {
    cmt_p2p_mconn_t mc;
    rmsg_t msgs[MAX_RMSGS];
    int    n_msgs;
    int    n_errors;
    int    last_error;
} conn_t;

static void host_recv(void *ctx, uint8_t ch, const uint8_t *m, size_t len)
{
    conn_t *c = (conn_t *)ctx;

    if (c->n_msgs >= MAX_RMSGS) {
        return;
    }
    c->msgs[c->n_msgs].ch = ch;
    c->msgs[c->n_msgs].len = len;
    c->msgs[c->n_msgs].b = (uint8_t *)malloc(len > 0 ? len : 1);
    if (len > 0 && c->msgs[c->n_msgs].b != NULL) {
        memcpy(c->msgs[c->n_msgs].b, m, len);
    }
    c->n_msgs++;
}

static void host_err(void *ctx, int reason)
{
    conn_t *c = (conn_t *)ctx;

    c->n_errors++;
    c->last_error = reason;
}

static void test_cfg(cmt_p2p_mconn_config_t *cfg)
{
    /* connection_test.go:37-39: DefaultMConnConfig with ping 90 ms /
     * pong 45 ms. */
    cmt_p2p_mconn_default_config(cfg);
    cfg->ping_interval_ns = 90 * MS;
    cfg->pong_timeout_ns = 45 * MS;
}

/* connection_test.go:40 — one channel {0x01, priority 1, queue 1}. */
static const cmt_p2p_ch_desc_t DESC1[] = { { 0x01, 1, 1, 0, 0 } };

static conn_t *conn_new(const cmt_p2p_ch_desc_t *d, int n,
                        const cmt_p2p_mconn_config_t *cfg)
{
    conn_t *c = (conn_t *)calloc(1, sizeof(conn_t));
    cmt_p2p_mconn_host_t h;

    if (c == NULL) {
        return NULL;
    }
    h.ctx = c;
    h.now_ns = host_now;
    h.on_receive = host_recv;
    h.on_error = host_err;
    if (cmt_p2p_mconn_init(&c->mc, &h, d, n, cfg) != CMT_OK ||
        cmt_p2p_mconn_start(&c->mc) != CMT_OK) {
        free(c);
        return NULL;
    }
    return c;
}

static void conn_free(conn_t *c)
{
    int i;

    if (c == NULL) {
        return;
    }
    for (i = 0; i < c->n_msgs; i++) {
        free(c->msgs[i].b);
    }
    cmt_p2p_mconn_free(&c->mc);
    free(c);
}

/* ══ a byte pipe ═════════════════════════════════════════════════════ */

typedef struct {
    uint8_t *b;
    size_t len;
    size_t cap;
} pipe_t;

static void pipe_init(pipe_t *p)
{
    p->cap = 1u << 21;
    p->b = (uint8_t *)malloc(p->cap);
    p->len = 0;
}

static void pipe_free(pipe_t *p)
{
    free(p->b);
    p->b = NULL;
}

static int pipe_push(pipe_t *p, const uint8_t *b, size_t n)
{
    if (p->b == NULL || n > p->cap - p->len) {
        return -1;
    }
    memcpy(p->b + p->len, b, n);
    p->len += n;
    return 0;
}

static void pipe_pop(pipe_t *p, size_t n)
{
    if (n >= p->len) {
        p->len = 0;
        return;
    }
    memmove(p->b, p->b + n, p->len - n);
    p->len -= n;
}

/* Move everything `c` has flushed into `p`. */
static size_t drain_out(conn_t *c, pipe_t *p)
{
    size_t n = 0;
    const uint8_t *o = cmt_p2p_mconn_out(&c->mc, &n);

    if (n == 0 || pipe_push(p, o, n) != 0) {
        return 0;
    }
    cmt_p2p_mconn_out_consume(&c->mc, n);
    return n;
}

/* Offer `p` to `c` (at most `chunk` bytes per recv call, 0 = all).
 * `*moved` (may be NULL) receives the bytes consumed. */
static int feed_n(conn_t *c, pipe_t *p, size_t chunk, size_t *moved)
{
    int rc = CMT_OK;
    size_t total = 0;

    while (p->len > 0) {
        size_t n = (chunk == 0 || chunk > p->len) ? p->len : chunk;
        size_t used = 0;

        rc = cmt_p2p_mconn_recv(&c->mc, p->b, n, &used);
        pipe_pop(p, used);
        total += used;
        if (rc != CMT_OK || used == 0) {
            break;
        }
    }
    if (moved != NULL) {
        *moved = total;
    }
    return rc;
}

static int feed(conn_t *c, pipe_t *p, size_t chunk)
{
    return feed_n(c, p, chunk, NULL);
}

/* One event-loop pass on both sides at the current clock: tick, write,
 * read, until a whole round moves no byte (bounded). A fixed number of
 * ticks would let the keep-alives (each flushes at once and parks the
 * send routine until `out` is drained) starve the data case. */
static void pass(conn_t *a, conn_t *b, pipe_t *ab, pipe_t *ba, size_t chunk)
{
    int round;

    for (round = 0; round < 32; round++) {
        size_t moved = 0, m = 0;

        cmt_p2p_mconn_tick(&a->mc);
        cmt_p2p_mconn_tick(&b->mc);
        moved += drain_out(a, ab);
        moved += drain_out(b, ba);
        (void)feed_n(b, ab, chunk, &m);
        moved += m;
        (void)feed_n(a, ba, chunk, &m);
        moved += m;
        if (moved == 0) {
            break;
        }
    }
}

/* `steps` passes, advancing the clock `step` before each. */
static void run(conn_t *a, conn_t *b, pipe_t *ab, pipe_t *ba, int steps,
                int64_t step, size_t chunk)
{
    int i;

    for (i = 0; i < steps; i++) {
        g_now += step;
        pass(a, b, ab, ba, chunk);
    }
}

static int hex_eq(const uint8_t *b, size_t n, const char *hex)
{
    size_t i;

    if (strlen(hex) != 2 * n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned v;

        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || (uint8_t)v != b[i]) {
            return 0;
        }
    }
    return 1;
}

/* A delimited PacketMsg with a RAW channel varint (for the overflow and
 * truncation cases). `with_ch` false omits field 1. */
static size_t raw_msg_packet(uint8_t *out, size_t cap, bool with_ch,
                             uint64_t ch_varint, bool eof,
                             const uint8_t *data, size_t len)
{
    uint8_t body[4096];
    uint8_t pkt[4200];
    size_t b = 0, k = 0, o = 0;

    if (with_ch) {
        body[b++] = 0x08;
        cmt_pb_put_uvarint(body, sizeof(body), &b, ch_varint);
    }
    if (eof) {
        body[b++] = 0x10;
        body[b++] = 0x01;
    }
    if (len > 0) {
        body[b++] = 0x1a;
        cmt_pb_put_uvarint(body, sizeof(body), &b, (uint64_t)len);
        memcpy(body + b, data, len);
        b += len;
    }
    pkt[k++] = 0x1a;
    cmt_pb_put_uvarint(pkt, sizeof(pkt), &k, (uint64_t)b);
    memcpy(pkt + k, body, b);
    k += b;
    cmt_pb_put_uvarint(out, cap, &o, (uint64_t)k);
    memcpy(out + o, pkt, k);
    return o + k;
}

/* ══ connection_test.go:568-589 — TestConnVectors ════════════════════ */

static void test_vectors(void)
{
    static const char DATA[] = "data transmitted over the wire";
    cmt_p2p_packet_t p;
    uint8_t buf[128];
    size_t n = 0;
    int ok = 1;

    TEST("ConnVectors: ping 0a00, pong 1200, PacketMsg bytes");
    memset(&p, 0, sizeof(p));
    p.kind = CMT_P2P_PACKET_PING;
    ok &= cmt_p2p_packet_marshal(&p, buf, sizeof(buf), &n) == CMT_OK &&
          hex_eq(buf, n, "0a00");
    p.kind = CMT_P2P_PACKET_PONG;
    ok &= cmt_p2p_packet_marshal(&p, buf, sizeof(buf), &n) == CMT_OK &&
          hex_eq(buf, n, "1200");
    p.kind = CMT_P2P_PACKET_MSG;
    p.channel_id = 1;
    p.eof = false;
    p.data = (const uint8_t *)DATA;
    p.data_len = strlen(DATA);
    ok &= cmt_p2p_packet_marshal(&p, buf, sizeof(buf), &n) == CMT_OK &&
          hex_eq(buf, n, "1a2208011a1e64617461207472616e736d6974746564206f766572207468652077697265");
    ok &= n == cmt_p2p_packet_msg_size(1, false, strlen(DATA));
    if (ok) {
        PASS();
    } else {
        FAIL("vector mismatch");
    }
}

static void test_packet_roundtrip(void)
{
    cmt_p2p_packet_t p, q;
    uint8_t buf[64];
    size_t n = 0;
    int ok = 1;

    TEST("PacketMsg channel 0x00 omits field 1, decodes back to 0");
    memset(&p, 0, sizeof(p));
    p.kind = CMT_P2P_PACKET_MSG;
    p.channel_id = 0;
    p.eof = true;
    p.data = (const uint8_t *)"x";
    p.data_len = 1;
    ok &= cmt_p2p_packet_marshal(&p, buf, sizeof(buf), &n) == CMT_OK &&
          hex_eq(buf, n, "1a0510011a0178");
    ok &= cmt_p2p_packet_unmarshal(buf, n, &q) == CMT_OK &&
          q.kind == CMT_P2P_PACKET_MSG && q.channel_id == 0 && q.eof &&
          q.data_len == 1 && q.data[0] == 'x';
    /* an empty Packet and one with only an unknown field: no member */
    ok &= cmt_p2p_packet_unmarshal(buf, 0, &q) == CMT_OK &&
          q.kind == CMT_P2P_PACKET_NONE;
    buf[0] = 0x20;
    buf[1] = 0x01;
    ok &= cmt_p2p_packet_unmarshal(buf, 2, &q) == CMT_OK &&
          q.kind == CMT_P2P_PACKET_NONE;
    /* wrong wire type for a member */
    buf[0] = 0x08;
    buf[1] = 0x01;
    ok &= cmt_p2p_packet_unmarshal(buf, 2, &q) == CMT_REJECT;
    if (ok) {
        PASS();
    } else {
        FAIL("round trip");
    }
}

static void test_max_packet_size(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *c;

    TEST("maxPacketMsgSize = 1034 at payload 1024 (connection.go:705-715)");
    cmt_p2p_mconn_p2p_default_config(&cfg);
    c = conn_new(DESC1, 1, &cfg);
    if (c != NULL && c->mc.max_packet_msg_size == CMT_P2P_MCONN_DEFAULT_MAX_PACKET_MSG_SIZE &&
        CMT_P2P_MCONN_DEFAULT_MAX_PACKET_MSG_SIZE == 1034 &&
        cmt_p2p_packet_msg_size(1, true, 1024) == 1034) {
        PASS();
    } else {
        FAIL("size");
    }
    conn_free(c);
}

/* ══ protoio / flowrate units ════════════════════════════════════════ */

static void test_protoio(void)
{
    uint8_t b[16];
    size_t off, boff, blen, nr;
    uint64_t v;
    int ok = 1;

    TEST("protoio: ReadUvarint MORE / overflow; ReadMsg max size early");
    memset(b, 0x80, sizeof(b));
    off = 0;
    ok &= cmt_p2p_protoio_read_uvarint(b, 3, &off, &v) == CMT_P2P_PROTOIO_MORE && off == 0;
    b[9] = 0x01;                                    /* 10th byte 1: max */
    off = 0;
    ok &= cmt_p2p_protoio_read_uvarint(b, 10, &off, &v) == CMT_OK && off == 10 &&
          v == (1ULL << 63);
    b[9] = 0x02;                                    /* 10th byte > 1 */
    off = 0;
    ok &= cmt_p2p_protoio_read_uvarint(b, 10, &off, &v) == CMT_REJECT;
    b[9] = 0x80;                                    /* 11 bytes */
    off = 0;
    ok &= cmt_p2p_protoio_read_uvarint(b, 16, &off, &v) == CMT_REJECT;
    /* length 1035 > max 1034, refused from the prefix alone */
    off = 0;
    cmt_pb_put_uvarint(b, sizeof(b), &off, 1035);
    ok &= cmt_p2p_protoio_read_msg(b, off, 1034, &boff, &blen, &nr) == CMT_REJECT &&
          nr == off;
    off = 0;
    cmt_pb_put_uvarint(b, sizeof(b), &off, 3);
    ok &= cmt_p2p_protoio_read_msg(b, off + 2, 1034, &boff, &blen, &nr) ==
          CMT_P2P_PROTOIO_MORE;
    ok &= cmt_p2p_protoio_read_msg(b, off + 3, 1034, &boff, &blen, &nr) == CMT_OK &&
          boff == 1 && blen == 3 && nr == 4;
    if (ok) {
        PASS();
    } else {
        FAIL("protoio");
    }
}

static void test_flowrate_unit(void)
{
    cmt_flowrate_t m;
    bool wb = false;
    int64_t retry = 0;
    int n;
    int ok = 1;

    TEST("flowrate: clock rounding, Limit budget, would-block + retry");
    ok &= cmt_flowrate_clock(9 * MS) == 0 && cmt_flowrate_clock(10 * MS) == 20 * MS &&
          cmt_flowrate_clock(29 * MS) == 20 * MS;
    ok &= cmt_flowrate_round(2.5) == 3 && cmt_flowrate_round(2.49) == 2;
    cmt_flowrate_init(&m, 0, 0, 0);
    ok &= m.s_rate == 100 * MS;
    ok &= cmt_flowrate_limit(&m, 0, 10000, true, 0, &wb, &retry) == 0 && !wb;
    ok &= cmt_flowrate_limit(&m, 500, 0, true, 0, &wb, &retry) == 500 && !wb;
    /* rate 10000 B/s × 0.1 s = 1000 bytes per sample */
    ok &= cmt_flowrate_limit(&m, 1034, 10000, false, 0, NULL, NULL) == 1000;
    cmt_flowrate_update(&m, 400, 0);
    ok &= cmt_flowrate_limit(&m, 1034, 10000, false, 0, NULL, NULL) == 600;
    cmt_flowrate_update(&m, 600, 0);
    /* at 40 ms (clock() exact): waitNextSample would sleep sLast + sRate -
     * now = 60 ms → retry at 100 ms. (At 50 ms clock() reads 60 ms and the
     * retry instant is 90 ms — whose clock() is 100 ms.) */
    n = cmt_flowrate_limit(&m, 1034, 10000, true, 40 * MS, &wb, &retry);
    ok &= n == 0 && wb && retry == 100 * MS;
    n = cmt_flowrate_limit(&m, 1034, 10000, true, 50 * MS, &wb, &retry);
    ok &= n == 0 && wb && retry == 90 * MS;
    n = cmt_flowrate_limit(&m, 1034, 10000, true, 100 * MS, &wb, &retry);
    ok &= n == 1000 && !wb && m.s_bytes == 0 && m.bytes == 1000 && m.samples == 1;
    if (ok) {
        PASS();
    } else {
        FAIL("flowrate");
    }
}

/* ══ connection_test.go:84-149 — Send / Receive / flush throttle ═════ */

static void test_send_receive(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *a, *b;
    pipe_t ab, ba;
    size_t n = 0;
    int ok = 1;

    TEST("Send/Receive: throttled flush at 100 ms, then delivered");
    cmt_p2p_mconn_p2p_default_config(&cfg);
    a = conn_new(DESC1, 1, &cfg);
    b = conn_new(DESC1, 1, &cfg);
    pipe_init(&ab);
    pipe_init(&ba);
    if (a == NULL || b == NULL) {
        FAIL("init");
        goto out;
    }
    ok &= cmt_p2p_mconn_send(&a->mc, 0x01, (const uint8_t *)"Cyclops", 7);
    cmt_p2p_mconn_tick(&a->mc);
    (void)cmt_p2p_mconn_out(&a->mc, &n);
    ok &= n == 0 && a->mc.w_len > 0;          /* staged, not flushed */
    g_now += 99 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    (void)cmt_p2p_mconn_out(&a->mc, &n);
    ok &= n == 0;
    g_now += 1 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    (void)cmt_p2p_mconn_out(&a->mc, &n);
    ok &= n == a->mc.w_len && n > 0;
    drain_out(a, &ab);
    ok &= feed(b, &ab, 0) == CMT_OK;
    ok &= b->n_msgs == 1 && b->msgs[0].ch == 0x01 && b->msgs[0].len == 7 &&
          memcmp(b->msgs[0].b, "Cyclops", 7) == 0;
    ok &= a->n_errors == 0 && b->n_errors == 0;
    ok &= !cmt_p2p_mconn_can_send(&a->mc, 0x05);
    ok &= !cmt_p2p_mconn_send(&a->mc, 0x05, (const uint8_t *)"Absorbing Man", 13);
    if (ok) {
        PASS();
    } else {
        FAIL("send/receive");
    }
out:
    conn_free(a);
    conn_free(b);
    pipe_free(&ab);
    pipe_free(&ba);
}

/* ══ connection_test.go:540-565 — TestMConnectionTrySend ═════════════ */

static void test_try_send(void)
{
    cmt_p2p_mconn_config_t cfg;
    cmt_p2p_mconn_channel_t *ch;
    conn_t *a;
    int ok = 1;
    int sq_len, sqs, head;
    bool token;

    TEST("TrySend: full queue -> false, nothing changes; CanSend rule");
    cmt_p2p_mconn_p2p_default_config(&cfg);
    a = conn_new(DESC1, 1, &cfg);
    if (a == NULL) {
        FAIL("init");
        return;
    }
    ch = &a->mc.channels[0];
    ok &= cmt_p2p_mconn_try_send(&a->mc, 0x01, (const uint8_t *)"Semicolon-Woman", 15);
    ok &= !cmt_p2p_mconn_can_send(&a->mc, 0x01);
    sq_len = ch->sq_len;
    sqs = ch->send_queue_size;
    head = ch->sq_head;
    token = a->mc.send_token;
    ok &= !cmt_p2p_mconn_try_send(&a->mc, 0x01, (const uint8_t *)"Semicolon-Woman", 15);
    ok &= !cmt_p2p_mconn_send(&a->mc, 0x01, (const uint8_t *)"x", 1);
    ok &= ch->sq_len == sq_len && ch->send_queue_size == sqs && ch->sq_head == head &&
          a->mc.send_token == token && sq_len == 1 && sqs == 1;
    /* the send routine takes it (packet built, EOF): room again */
    cmt_p2p_mconn_tick(&a->mc);
    ok &= cmt_p2p_mconn_can_send(&a->mc, 0x01) && ch->sq_len == 0;
    ok &= cmt_p2p_mconn_try_send(&a->mc, 0x01, (const uint8_t *)"Semicolon-Woman", 15);
    ok &= !cmt_p2p_mconn_can_send(&a->mc, 0x01);
    ok &= !cmt_p2p_mconn_try_send(&a->mc, 0x01, (const uint8_t *)"Semicolon-Woman", 15);
    if (ok) {
        PASS();
    } else {
        FAIL("try send");
    }
    conn_free(a);
}

/* ══ split / reassembly ══════════════════════════════════════════════ */

static void test_split(const char *name, size_t chunk)
{
    static const cmt_p2p_ch_desc_t D[] = { { 0x01, 1, 1, 0, 0 } };
    cmt_p2p_mconn_config_t cfg;
    conn_t *a, *b;
    pipe_t ab, ba;
    uint8_t msg[5000];
    size_t i, n = 0, off = 0;
    int packets = 0, eofs = 0;
    int ok = 1;
    const uint8_t *o;

    TEST(name);
    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i * 7 + 3);
    }
    cmt_p2p_mconn_p2p_default_config(&cfg);
    a = conn_new(D, 1, &cfg);
    b = conn_new(D, 1, &cfg);
    pipe_init(&ab);
    pipe_init(&ba);
    if (a == NULL || b == NULL) {
        FAIL("init");
        goto out;
    }
    ok &= cmt_p2p_mconn_send(&a->mc, 0x01, msg, sizeof(msg));
    cmt_p2p_mconn_tick(&a->mc);
    g_now += 100 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    o = cmt_p2p_mconn_out(&a->mc, &n);
    /* walk the wire: ceil(5000 / 1024) = 5 PacketMsgs, EOF on the last */
    while (o != NULL && off < n) {
        size_t boff = 0, blen = 0, nr = 0;
        cmt_p2p_packet_t p;

        if (cmt_p2p_protoio_read_msg(o + off, n - off, 1034, &boff, &blen, &nr) != CMT_OK ||
            cmt_p2p_packet_unmarshal(o + off + boff, blen, &p) != CMT_OK ||
            p.kind != CMT_P2P_PACKET_MSG || p.channel_id != 1) {
            ok = 0;
            break;
        }
        packets++;
        eofs += p.eof ? 1 : 0;
        ok &= (p.eof == (packets == 5)) && p.data_len == (packets < 5 ? 1024u : 5000u - 4 * 1024u);
        off += nr;
    }
    ok &= packets == 5 && eofs == 1 && off == n;
    drain_out(a, &ab);
    ok &= feed(b, &ab, chunk) == CMT_OK && ab.len == 0;
    ok &= b->n_msgs == 1 && b->msgs[0].len == sizeof(msg) &&
          memcmp(b->msgs[0].b, msg, sizeof(msg)) == 0 && b->n_errors == 0;
    if (ok) {
        PASS();
    } else {
        FAIL("split");
    }
out:
    conn_free(a);
    conn_free(b);
    pipe_free(&ab);
    pipe_free(&ba);
}

static void test_empty_message(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *a, *b;
    pipe_t ab, ba;
    int ok = 1;

    TEST("empty message -> PacketMsg{eof} -> zero-length delivery");
    cmt_p2p_mconn_p2p_default_config(&cfg);
    a = conn_new(DESC1, 1, &cfg);
    b = conn_new(DESC1, 1, &cfg);
    pipe_init(&ab);
    pipe_init(&ba);
    if (a == NULL || b == NULL) {
        FAIL("init");
        goto out;
    }
    ok &= cmt_p2p_mconn_send(&a->mc, 0x01, NULL, 0);
    run(a, b, &ab, &ba, 3, 100 * MS, 0);
    ok &= b->n_msgs == 1 && b->msgs[0].len == 0 && b->msgs[0].ch == 0x01 &&
          b->n_errors == 0;
    if (ok) {
        PASS();
    } else {
        FAIL("empty");
    }
out:
    conn_free(a);
    conn_free(b);
    pipe_free(&ab);
    pipe_free(&ba);
}

/* ══ receive errors ══════════════════════════════════════════════════ */

/* Feed raw bytes to a fresh server with DESC1; returns the conn. */
static conn_t *feed_raw(const uint8_t *bytes, size_t n, int *rc_out)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *s;
    size_t used = 0;

    test_cfg(&cfg);
    s = conn_new(DESC1, 1, &cfg);
    if (s == NULL) {
        *rc_out = CMT_FAULT;
        return NULL;
    }
    *rc_out = cmt_p2p_mconn_recv(&s->mc, bytes, n, &used);
    return s;
}

static int stopped_with(conn_t *s, int rc, int reason)
{
    return s != NULL && rc == CMT_REJECT && s->n_errors == 1 &&
           s->last_error == reason && !cmt_p2p_mconn_is_running(&s->mc) &&
           !cmt_p2p_mconn_send(&s->mc, 0x01, (const uint8_t *)"x", 1);
}

static void test_recv_capacity(void)
{
    static const cmt_p2p_ch_desc_t D[] = { { 0x01, 1, 1, 0, 100 } };
    cmt_p2p_mconn_config_t cfg;
    conn_t *s;
    uint8_t data[101], buf[512];
    size_t n, used = 0;
    int rc, ok = 1;

    TEST("RecvMessageCapacity: 100 ok, 101 -> RECV_CAPACITY, stopped");
    memset(data, 0xAB, sizeof(data));
    test_cfg(&cfg);
    s = conn_new(D, 1, &cfg);
    if (s == NULL) {
        FAIL("init");
        return;
    }
    n = raw_msg_packet(buf, sizeof(buf), true, 1, true, data, 100);
    rc = cmt_p2p_mconn_recv(&s->mc, buf, n, &used);
    ok &= rc == CMT_OK && used == n && s->n_msgs == 1 && s->msgs[0].len == 100;
    /* 60 + 41 across two packets: the SUM is checked (:895) */
    n = raw_msg_packet(buf, sizeof(buf), true, 1, false, data, 60);
    rc = cmt_p2p_mconn_recv(&s->mc, buf, n, &used);
    ok &= rc == CMT_OK;
    n = raw_msg_packet(buf, sizeof(buf), true, 1, true, data, 41);
    rc = cmt_p2p_mconn_recv(&s->mc, buf, n, &used);
    ok &= stopped_with(s, rc, CMT_P2P_MCONN_ERR_RECV_CAPACITY) && s->n_msgs == 1;
    rc = cmt_p2p_mconn_recv(&s->mc, buf, n, &used);
    ok &= rc == CMT_REJECT && used == 0 && s->n_errors == 1;
    if (ok) {
        PASS();
    } else {
        FAIL("capacity");
    }
    conn_free(s);
}

/* red-team H3 — cmt_p2p_mconn_recv_n: the receive gate's unit. With
 * max 1 it hands exactly ONE whole message to on_receive and consumes
 * nothing past the packet that completed it (the next message's bytes
 * stay with the caller, so a message that may not be delivered yet is
 * never read and never dropped); a message split over two packets is ONE
 * delivery; max 0 reads nothing; the unbounded form (cmt_p2p_mconn_recv)
 * takes the rest. RED before H3: there was no bound — one call delivered
 * every whole message it was offered. */
static void test_recv_n_one_message(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *s;
    uint8_t buf[4096], d[3][8];
    size_t n1, n2, n3a, n3b, off = 0, used = 0, got = 0;
    int rc, ok = 1, i;

    TEST("recv_n max 1: one message per call, nothing read past it");
    for (i = 0; i < 3; i++) {
        memset(d[i], 'a' + i, sizeof(d[i]));
    }
    test_cfg(&cfg);
    s = conn_new(DESC1, 1, &cfg);
    if (s == NULL) {
        FAIL("init");
        return;
    }
    n1 = raw_msg_packet(buf, sizeof(buf), true, 1, true, d[0], 8);
    n2 = raw_msg_packet(buf + n1, sizeof(buf) - n1, true, 1, true, d[1], 8);
    n3a = raw_msg_packet(buf + n1 + n2, sizeof(buf) - n1 - n2, true, 1, false,
                         d[2], 4);
    n3b = raw_msg_packet(buf + n1 + n2 + n3a, sizeof(buf) - n1 - n2 - n3a,
                         true, 1, true, d[2] + 4, 4);

    rc = cmt_p2p_mconn_recv_n(&s->mc, buf, n1 + n2 + n3a + n3b, &used, 0, &got);
    ok &= rc == CMT_OK && used == 0 && got == 0 && s->n_msgs == 0;

    rc = cmt_p2p_mconn_recv_n(&s->mc, buf, n1 + n2 + n3a + n3b, &used, 1, &got);
    ok &= rc == CMT_OK && used == n1 && got == 1 && s->n_msgs == 1 &&
          s->msgs[0].len == 8 && memcmp(s->msgs[0].b, d[0], 8) == 0;
    off += used;

    rc = cmt_p2p_mconn_recv_n(&s->mc, buf + off, n2 + n3a + n3b, &used, 1, &got);
    ok &= rc == CMT_OK && used == n2 && got == 1 && s->n_msgs == 2 &&
          memcmp(s->msgs[1].b, d[1], 8) == 0;
    off += used;

    /* the third message spans two packets: one delivery, both consumed */
    rc = cmt_p2p_mconn_recv_n(&s->mc, buf + off, n3a + n3b, &used, 1, &got);
    ok &= rc == CMT_OK && used == n3a + n3b && got == 1 && s->n_msgs == 3 &&
          s->msgs[2].len == 8 && memcmp(s->msgs[2].b, d[2], 8) == 0;

    /* the unbounded form over two more whole messages takes both */
    n1 = raw_msg_packet(buf, sizeof(buf), true, 1, true, d[0], 8);
    n2 = raw_msg_packet(buf + n1, sizeof(buf) - n1, true, 1, true, d[1], 8);
    rc = cmt_p2p_mconn_recv(&s->mc, buf, n1 + n2, &used);
    ok &= rc == CMT_OK && used == n1 + n2 && s->n_msgs == 5 && s->n_errors == 0;
    if (ok) {
        PASS();
    } else {
        FAIL("recv_n");
    }
    conn_free(s);
}

/* connection_test.go:463-488 */
static void test_unknown_channel_recv(void)
{
    static const cmt_p2p_ch_desc_t D2[] = { { 0x01, 1, 1, 0, 0 },
                                            { 0x02, 1, 1, 0, 0 } };
    cmt_p2p_mconn_config_t cfg;
    conn_t *c, *s;
    pipe_t ab, ba;
    int ok = 1;

    TEST("ReadErrorUnknownChannel: peer sends on 0x02 -> UNKNOWN_CHANNEL");
    /* connection_test.go:411 — the client is NewMConnection (the default
     * config, 60 s ping); :422 — the server has the 90 ms test config. */
    cmt_p2p_mconn_default_config(&cfg);
    c = conn_new(D2, 2, &cfg);
    test_cfg(&cfg);
    s = conn_new(DESC1, 1, &cfg);
    pipe_init(&ab);
    pipe_init(&ba);
    if (c == NULL || s == NULL) {
        FAIL("init");
        goto out;
    }
    ok &= !cmt_p2p_mconn_send(&c->mc, 0x03, (const uint8_t *)"Ant-Man", 7);
    ok &= cmt_p2p_mconn_send(&c->mc, 0x02, (const uint8_t *)"Ant-Man", 7);
    run(c, s, &ab, &ba, 3, 100 * MS, 0);
    ok &= s->n_errors == 1 && s->last_error == CMT_P2P_MCONN_ERR_UNKNOWN_CHANNEL &&
          s->n_msgs == 0 && !cmt_p2p_mconn_is_running(&s->mc);
    if (ok) {
        PASS();
    } else {
        FAIL("unknown channel");
    }
out:
    conn_free(c);
    conn_free(s);
    pipe_free(&ab);
    pipe_free(&ba);
}

/* connection_test.go:490-526 */
static void test_long_message(void)
{
    uint8_t data[1124], buf[1300];
    size_t n;
    conn_t *s;
    int rc, ok = 1;

    TEST("ReadErrorLongMessage: payload 1024 ok, 1124 -> READ");
    memset(data, 0, sizeof(data));
    n = raw_msg_packet(buf, sizeof(buf), true, 1, true, data, 1024);
    s = feed_raw(buf, n, &rc);
    ok &= s != NULL && rc == CMT_OK && s->n_msgs == 1 && s->msgs[0].len == 1024;
    if (s != NULL) {
        size_t used = 0;

        n = raw_msg_packet(buf, sizeof(buf), true, 1, true, data, 1124);
        rc = cmt_p2p_mconn_recv(&s->mc, buf, n, &used);
        ok &= stopped_with(s, rc, CMT_P2P_MCONN_ERR_READ) && used < n;
    }
    if (ok) {
        PASS();
    } else {
        FAIL("long message");
    }
    conn_free(s);
}

/* connection_test.go:591-619 + the int32 truncation quirk */
static void test_channel_overflow(void)
{
    uint8_t buf[64];
    size_t n;
    conn_t *s;
    int rc, ok = 1;

    TEST("ChannelOverflow: 1025 and -1 refused; low-32-bit alias accepted");
    n = raw_msg_packet(buf, sizeof(buf), true, 1, true, (const uint8_t *)"42", 2);
    s = feed_raw(buf, n, &rc);
    ok &= s != NULL && rc == CMT_OK && s->n_msgs == 1;
    if (s != NULL) {
        size_t used = 0;

        n = raw_msg_packet(buf, sizeof(buf), true, 1025, true, (const uint8_t *)"42", 2);
        rc = cmt_p2p_mconn_recv(&s->mc, buf, n, &used);
        ok &= stopped_with(s, rc, CMT_P2P_MCONN_ERR_UNKNOWN_CHANNEL) && s->n_msgs == 1;
    }
    conn_free(s);

    n = raw_msg_packet(buf, sizeof(buf), true, (uint64_t)(int64_t)-1, true,
                       (const uint8_t *)"42", 2);
    s = feed_raw(buf, n, &rc);
    ok &= stopped_with(s, rc, CMT_P2P_MCONN_ERR_UNKNOWN_CHANNEL);
    conn_free(s);

    /* (1 << 32) | 1: the generated int32 decode keeps the low 32 bits */
    n = raw_msg_packet(buf, sizeof(buf), true, (1ULL << 32) | 1u, true,
                       (const uint8_t *)"42", 2);
    s = feed_raw(buf, n, &rc);
    ok &= s != NULL && rc == CMT_OK && s->n_msgs == 1 && s->msgs[0].ch == 0x01 &&
          s->n_errors == 0;
    conn_free(s);
    if (ok) {
        PASS();
    } else {
        FAIL("overflow");
    }
}

/* connection_test.go:439-461 and :528-538 */
static void test_bad_encoding(void)
{
    static const uint8_t BAD[] = { 1, 2, 3, 4, 5 };
    /* uvarint 0: an EMPTY Packet — no member */
    static const uint8_t EMPTY[] = { 0x00 };
    /* only an unknown field (4, varint) — no member */
    static const uint8_t UNKNOWN[] = { 0x02, 0x20, 0x01 };
    /* Header{ChainID:"x"}'s first fields (version ALWAYS 0a 00, chain_id
     * 12 01 78): Packet field 2 = PacketPong with body "x" — malformed */
    static const uint8_t HEADER[] = { 0x05, 0x0a, 0x00, 0x12, 0x01, 0x78 };
    conn_t *s;
    int rc, ok = 1;

    TEST("bad encoding -> READ; no member -> UNKNOWN_MSG");
    s = feed_raw(BAD, sizeof(BAD), &rc);
    ok &= stopped_with(s, rc, CMT_P2P_MCONN_ERR_READ);
    conn_free(s);
    s = feed_raw(EMPTY, sizeof(EMPTY), &rc);
    ok &= stopped_with(s, rc, CMT_P2P_MCONN_ERR_UNKNOWN_MSG);
    conn_free(s);
    s = feed_raw(UNKNOWN, sizeof(UNKNOWN), &rc);
    ok &= stopped_with(s, rc, CMT_P2P_MCONN_ERR_UNKNOWN_MSG);
    conn_free(s);
    s = feed_raw(HEADER, sizeof(HEADER), &rc);
    ok &= stopped_with(s, rc, CMT_P2P_MCONN_ERR_READ);
    conn_free(s);
    if (ok) {
        PASS();
    } else {
        FAIL("bad encoding");
    }
}

/* ══ ping / pong (connection_test.go:166-365) ════════════════════════ */

static const uint8_t PING_WIRE[] = { 0x02, 0x0a, 0x00 };
static const uint8_t PONG_WIRE[] = { 0x02, 0x12, 0x00 };

static void test_ping_pong(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *a, *b;
    pipe_t ab, ba;
    size_t n = 0;
    const uint8_t *o;
    int ok = 1;

    TEST("PingPongs: ping at interval, pong at once, no error after timeout");
    test_cfg(&cfg);
    a = conn_new(DESC1, 1, &cfg);
    b = conn_new(DESC1, 1, &cfg);
    pipe_init(&ab);
    pipe_init(&ba);
    if (a == NULL || b == NULL) {
        FAIL("init");
        goto out;
    }
    g_now += 89 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    (void)cmt_p2p_mconn_out(&a->mc, &n);
    ok &= n == 0;
    g_now += 1 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    o = cmt_p2p_mconn_out(&a->mc, &n);
    ok &= n == 3 && memcmp(o, PING_WIRE, 3) == 0 && a->mc.pong_timer_armed;
    drain_out(a, &ab);
    (void)feed(b, &ab, 0);
    cmt_p2p_mconn_tick(&b->mc);
    o = cmt_p2p_mconn_out(&b->mc, &n);
    ok &= n >= 3 && memcmp(o, PONG_WIRE, 3) == 0;
    drain_out(b, &ba);
    (void)feed(a, &ba, 0);
    cmt_p2p_mconn_tick(&a->mc);
    ok &= !a->mc.pong_timer_armed;
    run(a, b, &ab, &ba, 10, 20 * MS, 0);        /* two more ping rounds */
    ok &= a->n_errors == 0 && b->n_errors == 0 && cmt_p2p_mconn_is_running(&a->mc) &&
          cmt_p2p_mconn_is_running(&b->mc);
    if (ok) {
        PASS();
    } else {
        FAIL("ping pong");
    }
out:
    conn_free(a);
    conn_free(b);
    pipe_free(&ab);
    pipe_free(&ba);
}

static void test_pong_timeout(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *a;
    int ok = 1;

    TEST("PongTimeoutResultsInError: no pong within 45 ms -> PONG_TIMEOUT");
    test_cfg(&cfg);
    a = conn_new(DESC1, 1, &cfg);
    if (a == NULL) {
        FAIL("init");
        return;
    }
    g_now += 90 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    cmt_p2p_mconn_out_consume(&a->mc, 3);       /* the peer read the ping */
    g_now += 44 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    ok &= a->n_errors == 0 && cmt_p2p_mconn_is_running(&a->mc);
    g_now += 1 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    ok &= a->n_errors == 1 && a->last_error == CMT_P2P_MCONN_ERR_PONG_TIMEOUT &&
          !cmt_p2p_mconn_is_running(&a->mc);
    if (ok) {
        PASS();
    } else {
        FAIL("pong timeout");
    }
    conn_free(a);
}

static void test_multiple_pongs(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *a;
    uint8_t three[9];
    size_t used = 0;
    int ok = 1;

    TEST("MultiplePongsInTheBeginning: harmless, then ping/pong ok");
    test_cfg(&cfg);
    a = conn_new(DESC1, 1, &cfg);
    if (a == NULL) {
        FAIL("init");
        return;
    }
    memcpy(three, PONG_WIRE, 3);
    memcpy(three + 3, PONG_WIRE, 3);
    memcpy(three + 6, PONG_WIRE, 3);
    ok &= cmt_p2p_mconn_recv(&a->mc, three, sizeof(three), &used) == CMT_OK &&
          used == sizeof(three);
    cmt_p2p_mconn_tick(&a->mc);
    g_now += 90 * MS;
    cmt_p2p_mconn_tick(&a->mc);                 /* ping */
    cmt_p2p_mconn_out_consume(&a->mc, 3);
    ok &= cmt_p2p_mconn_recv(&a->mc, PONG_WIRE, 3, &used) == CMT_OK;
    cmt_p2p_mconn_tick(&a->mc);
    g_now += 65 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    ok &= a->n_errors == 0 && cmt_p2p_mconn_is_running(&a->mc);
    if (ok) {
        PASS();
    } else {
        FAIL("multiple pongs");
    }
    conn_free(a);
}

static void test_multiple_pings(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *a;
    uint8_t three[9];
    size_t used = 0, n = 0;
    const uint8_t *o;
    int ok = 1;
    int k;

    TEST("MultiplePings: 3 in one read -> 1 pong; ping by ping -> 1 each");
    test_cfg(&cfg);
    a = conn_new(DESC1, 1, &cfg);
    if (a == NULL) {
        FAIL("init");
        return;
    }
    memcpy(three, PING_WIRE, 3);
    memcpy(three + 3, PING_WIRE, 3);
    memcpy(three + 6, PING_WIRE, 3);
    ok &= cmt_p2p_mconn_recv(&a->mc, three, sizeof(three), &used) == CMT_OK &&
          used == sizeof(three);
    cmt_p2p_mconn_tick(&a->mc);
    o = cmt_p2p_mconn_out(&a->mc, &n);
    ok &= n == 3 && memcmp(o, PONG_WIRE, 3) == 0;
    cmt_p2p_mconn_out_consume(&a->mc, n);
    for (k = 0; k < 3; k++) {
        ok &= cmt_p2p_mconn_recv(&a->mc, PING_WIRE, 3, &used) == CMT_OK && used == 3;
        cmt_p2p_mconn_tick(&a->mc);
        o = cmt_p2p_mconn_out(&a->mc, &n);
        ok &= n == 3 && memcmp(o, PONG_WIRE, 3) == 0;
        cmt_p2p_mconn_out_consume(&a->mc, n);
    }
    ok &= a->n_errors == 0 && cmt_p2p_mconn_is_running(&a->mc);
    if (ok) {
        PASS();
    } else {
        FAIL("multiple pings");
    }
    conn_free(a);
}

/* ══ priority (connection.go:549-570, :915-919) ══════════════════════ */

static void test_priority(void)
{
    static const cmt_p2p_ch_desc_t D[] = { { 0x01, 1, 10, 0, 0 },
                                           { 0x02, 10, 10, 0, 0 } };
    cmt_p2p_mconn_config_t cfg;
    conn_t *a;
    uint8_t order[8];
    int n_order = 0;
    size_t n = 0, off = 0;
    const uint8_t *o;
    int ok = 1;
    int k;

    TEST("priority: recentlySent/priority, ties earlier; A,B,B,B,A,A");
    cmt_p2p_mconn_p2p_default_config(&cfg);
    a = conn_new(D, 2, &cfg);
    if (a == NULL) {
        FAIL("init");
        return;
    }
    /* direct rule */
    ok &= cmt_p2p_mconn_select_channel(&a->mc) == -1;
    ok &= cmt_p2p_mconn_try_send(&a->mc, 0x01, (const uint8_t *)"a", 1);
    ok &= cmt_p2p_mconn_try_send(&a->mc, 0x02, (const uint8_t *)"b", 1);
    ok &= cmt_p2p_mconn_select_channel(&a->mc) == 0;          /* tie */
    a->mc.channels[0].recently_sent = 100;                    /* ratio 100 */
    a->mc.channels[1].recently_sent = 500;                    /* ratio 50  */
    ok &= cmt_p2p_mconn_select_channel(&a->mc) == 1;
    a->mc.channels[1].recently_sent = 1100;                   /* ratio 110 */
    ok &= cmt_p2p_mconn_select_channel(&a->mc) == 0;
    a->mc.channels[1].recently_sent = 1000;                   /* ratio 100: tie */
    ok &= cmt_p2p_mconn_select_channel(&a->mc) == 0;
    cmt_p2p_mconn_update_stats(&a->mc);
    ok &= a->mc.channels[0].recently_sent == 80 && a->mc.channels[1].recently_sent == 800;
    a->mc.channels[0].recently_sent = 0;
    a->mc.channels[1].recently_sent = 0;
    /* on the wire: "a" queued first on A; then 2 more on A, 2 more on B */
    for (k = 0; k < 2; k++) {
        ok &= cmt_p2p_mconn_try_send(&a->mc, 0x01, (const uint8_t *)"a", 1);
        ok &= cmt_p2p_mconn_try_send(&a->mc, 0x02, (const uint8_t *)"b", 1);
    }
    cmt_p2p_mconn_tick(&a->mc);
    g_now += 100 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    o = cmt_p2p_mconn_out(&a->mc, &n);
    while (o != NULL && off < n && n_order < 8) {
        size_t boff = 0, blen = 0, nr = 0;
        cmt_p2p_packet_t p;

        if (cmt_p2p_protoio_read_msg(o + off, n - off, 1034, &boff, &blen, &nr) != CMT_OK ||
            cmt_p2p_packet_unmarshal(o + off + boff, blen, &p) != CMT_OK) {
            ok = 0;
            break;
        }
        order[n_order++] = (uint8_t)p.channel_id;
        off += nr;
    }
    ok &= n_order == 6 && order[0] == 1 && order[1] == 2 && order[2] == 2 &&
          order[3] == 2 && order[4] == 1 && order[5] == 1;
    if (ok) {
        PASS();
    } else {
        FAIL("priority");
    }
    conn_free(a);
}

/* ══ flowrate inside the MConnection ═════════════════════════════════ */

static void test_send_rate(void)
{
    static const cmt_p2p_ch_desc_t D[] = { { 0x01, 1, 12, 0, 0 } };
    cmt_p2p_mconn_config_t cfg;
    conn_t *a;
    uint8_t m[100];
    size_t per;
    int k, ok = 1;

    TEST("send rate: 10 packets, then held until the next 100 ms sample");
    memset(m, 0x5A, sizeof(m));
    cmt_p2p_mconn_p2p_default_config(&cfg);
    cfg.send_rate = 10000;                  /* 1000 bytes per sample */
    a = conn_new(D, 1, &cfg);
    if (a == NULL) {
        FAIL("init");
        return;
    }
    for (k = 0; k < 12; k++) {
        ok &= cmt_p2p_mconn_try_send(&a->mc, 0x01, m, sizeof(m));
    }
    per = cmt_p2p_packet_msg_size(1, true, sizeof(m));
    per += cmt_pb_uvarint_size((uint64_t)per);
    cmt_p2p_mconn_tick(&a->mc);
    ok &= a->mc.w_len == 10 * per && a->mc.send_in_limit;
    g_now += 50 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    ok &= a->mc.w_len == 10 * per;
    g_now += 50 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    ok &= a->mc.w_len == 12 * per && !a->mc.send_in_limit && a->n_errors == 0;
    if (ok) {
        PASS();
    } else {
        FAIL("send rate");
    }
    conn_free(a);
}

static void test_recv_rate(void)
{
    cmt_p2p_mconn_config_t cfg;
    conn_t *s;
    uint8_t data[1000], buf[4000];
    size_t one, n = 0, used = 0;
    int ok = 1;

    TEST("recv rate: one packet per 100 ms sample, the rest left unconsumed");
    memset(data, 1, sizeof(data));
    test_cfg(&cfg);
    cfg.recv_rate = 10000;
    s = conn_new(DESC1, 1, &cfg);
    if (s == NULL) {
        FAIL("init");
        return;
    }
    one = raw_msg_packet(buf, sizeof(buf), true, 1, true, data, sizeof(data));
    n = one;
    n += raw_msg_packet(buf + n, sizeof(buf) - n, true, 1, true, data, sizeof(data));
    n += raw_msg_packet(buf + n, sizeof(buf) - n, true, 1, true, data, sizeof(data));
    ok &= cmt_p2p_mconn_recv(&s->mc, buf, n, &used) == CMT_OK && used == one &&
          s->n_msgs == 1;
    g_now += 50 * MS;
    ok &= cmt_p2p_mconn_recv(&s->mc, buf + one, n - one, &used) == CMT_OK && used == 0;
    g_now += 50 * MS;
    ok &= cmt_p2p_mconn_recv(&s->mc, buf + one, n - one, &used) == CMT_OK && used == one &&
          s->n_msgs == 2 && s->n_errors == 0;
    if (ok) {
        PASS();
    } else {
        FAIL("recv rate");
    }
    conn_free(s);
}

/* ══ Stop / FlushStop / Status / init refusals ═══════════════════════ */

static void test_flush_stop(void)
{
    cmt_p2p_mconn_config_t cfg;
    cmt_p2p_mconn_status_t st;
    cmt_p2p_mconn_channel_status_t chs[1];
    conn_t *a, *b;
    pipe_t ab, ba;
    size_t n = 0;
    int ok = 1;

    TEST("Status; FlushStop sends + flushes at once; Stop drops out");
    cmt_p2p_mconn_p2p_default_config(&cfg);
    a = conn_new(DESC1, 1, &cfg);
    b = conn_new(DESC1, 1, &cfg);
    pipe_init(&ab);
    pipe_init(&ba);
    if (a == NULL || b == NULL) {
        FAIL("init");
        goto out;
    }
    cmt_p2p_mconn_status(&a->mc, &st, chs, 1);                /* :151-164 */
    ok &= st.n_channels == 1 && chs[0].send_queue_size == 0 &&
          chs[0].send_queue_capacity == 1 && chs[0].priority == 1;
    ok &= cmt_p2p_mconn_send(&a->mc, 0x01, (const uint8_t *)"abc", 3);
    cmt_p2p_mconn_status(&a->mc, &st, chs, 1);
    ok &= chs[0].send_queue_size == 1;
    cmt_p2p_mconn_flush_stop(&a->mc);
    ok &= cmt_p2p_mconn_is_running(&a->mc);   /* FlushStop keeps IsRunning */
    cmt_p2p_mconn_tick(&a->mc);
    (void)cmt_p2p_mconn_out(&a->mc, &n);
    ok &= cmt_p2p_mconn_flush_stop_done(&a->mc) && n > 0;
    drain_out(a, &ab);
    ok &= feed(b, &ab, 0) == CMT_OK && b->n_msgs == 1 && b->msgs[0].len == 3;
    /* nothing more ever leaves a flushed-and-closed connection */
    (void)cmt_p2p_mconn_send(&a->mc, 0x01, (const uint8_t *)"late", 4);
    g_now += 200 * MS;
    cmt_p2p_mconn_tick(&a->mc);
    (void)cmt_p2p_mconn_out(&a->mc, &n);
    ok &= n == 0 && a->n_errors == 0;

    /* plain Stop: queued and staged bytes are dropped, recv is refused */
    ok &= cmt_p2p_mconn_send(&b->mc, 0x01, (const uint8_t *)"zzz", 3);
    cmt_p2p_mconn_tick(&b->mc);
    cmt_p2p_mconn_stop(&b->mc);
    g_now += 200 * MS;
    cmt_p2p_mconn_tick(&b->mc);
    (void)cmt_p2p_mconn_out(&b->mc, &n);
    ok &= n == 0 && !cmt_p2p_mconn_send(&b->mc, 0x01, (const uint8_t *)"x", 1);
    {
        size_t used = 7;

        ok &= cmt_p2p_mconn_recv(&b->mc, PING_WIRE, 3, &used) == CMT_REJECT && used == 0;
    }
    ok &= b->n_errors == 0;   /* Stop is not an error */
    if (ok) {
        PASS();
    } else {
        FAIL("flush stop");
    }
out:
    conn_free(a);
    conn_free(b);
    pipe_free(&ab);
    pipe_free(&ba);
}

static void test_init_refusals(void)
{
    static const cmt_p2p_ch_desc_t BADP[] = { { 0x01, 0, 1, 0, 0 } };
    cmt_p2p_mconn_config_t cfg;
    cmt_p2p_mconn_host_t h;
    cmt_p2p_mconn_t *mc = (cmt_p2p_mconn_t *)calloc(1, sizeof(*mc));
    cmt_p2p_ch_desc_t d;
    int ok = 1;

    TEST("init refuses pong >= ping, priority 0, payload 0; FillDefaults");
    if (mc == NULL) {
        FAIL("alloc");
        return;
    }
    h.ctx = NULL;
    h.now_ns = host_now;
    h.on_receive = host_recv;
    h.on_error = host_err;
    test_cfg(&cfg);
    cfg.pong_timeout_ns = cfg.ping_interval_ns;
    ok &= cmt_p2p_mconn_init(mc, &h, DESC1, 1, &cfg) == CMT_FAULT;
    test_cfg(&cfg);
    ok &= cmt_p2p_mconn_init(mc, &h, BADP, 1, &cfg) == CMT_FAULT;
    cfg.max_packet_msg_payload_size = 0;
    ok &= cmt_p2p_mconn_init(mc, &h, DESC1, 1, &cfg) == CMT_FAULT;
    memset(&d, 0, sizeof(d));
    d = cmt_p2p_ch_desc_fill_defaults(d);
    ok &= d.send_queue_capacity == 1 && d.recv_buffer_capacity == 4096 &&
          d.recv_message_capacity == 22020096;
    if (ok) {
        PASS();
    } else {
        FAIL("init refusals");
    }
    free(mc);
}

/* ══ end to end over two REAL SecretConnections (F1) ═════════════════ */

static const uint8_t CHAIN[32] = { 0x9a, 0xbf, 0x84, 0x37 };

typedef struct {
    nodus_identity_t id;
} node_t;

static int sc_host_sign(void *ctx, const uint8_t *msg, size_t msg_len,
                        uint8_t sig_out[CMT_P2P_SC_SIG_SIZE])
{
    node_t *n = (node_t *)ctx;
    nodus_sig_t sig;
    int rc = nodus_sign_session_auth(&sig, msg, msg_len, &n->id.sk);

    memcpy(sig_out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    return rc;
}

static int sc_host_verify(void *ctx, const uint8_t sig_in[CMT_P2P_SC_SIG_SIZE],
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t pk_in[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_SC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, CMT_P2P_SC_DSA_PK_SIZE);
    return nodus_verify_session_auth(&sig, msg, msg_len, &pk);
}

typedef struct {
    cmt_p2p_sc_t *sc;
    cmt_p2p_sc_host_t host;
    conn_t *c;
    uint8_t hold[CMT_P2P_SC_DATA_MAX_SIZE * 4];  /* plaintext not yet consumed */
    size_t  hold_len;
    uint8_t *seal;                               /* sealing scratch */
    size_t  seal_cap;
} e2e_side_t;

static void sc_shuttle(e2e_side_t *s, pipe_t *out, pipe_t *in)
{
    size_t n = 0;
    const uint8_t *o = cmt_p2p_sc_out(s->sc, &n);
    const cmt_p2p_sc_job_t *job;

    if (n > 0 && pipe_push(out, o, n) == 0) {
        cmt_p2p_sc_out_consume(s->sc, n);
    }
    if (!cmt_p2p_sc_is_authenticated(s->sc) && in->len > 0) {
        size_t c = 0;

        (void)cmt_p2p_sc_recv(s->sc, in->b, in->len, &c);
        pipe_pop(in, c);
    }
    while ((job = cmt_p2p_sc_job(s->sc)) != NULL) {
        (void)cmt_p2p_sc_job_done(s->sc, cmt_p2p_sc_job_run(job, &s->host));
    }
}

/* MConnection → secret connection → pipe. */
static void e2e_send(e2e_side_t *s, pipe_t *out)
{
    size_t n = 0, olen = 0;
    const uint8_t *o;

    cmt_p2p_mconn_tick(&s->c->mc);
    o = cmt_p2p_mconn_out(&s->c->mc, &n);
    if (n == 0) {
        return;
    }
    if (cmt_p2p_sc_write(s->sc, o, n, s->seal, s->seal_cap, &olen) == CMT_OK &&
        pipe_push(out, s->seal, olen) == 0) {
        cmt_p2p_mconn_out_consume(&s->c->mc, n);
    }
}

/* pipe → secret connection → MConnection, keeping what it cannot take. */
static void e2e_recv(e2e_side_t *s, pipe_t *in)
{
    for (;;) {
        size_t used = 0, c = 0, n = 0;

        if (s->hold_len > 0) {
            if (cmt_p2p_mconn_recv(&s->c->mc, s->hold, s->hold_len, &used) != CMT_OK) {
                return;
            }
            memmove(s->hold, s->hold + used, s->hold_len - used);
            s->hold_len -= used;
            if (s->hold_len > 0) {
                return;                 /* held by the rate limit */
            }
        }
        if (in->len == 0) {
            return;
        }
        if (cmt_p2p_sc_read(s->sc, in->b, in->len, &c, s->hold,
                            sizeof(s->hold), &n) != CMT_OK) {
            return;
        }
        pipe_pop(in, c);
        s->hold_len = n;
        if (n == 0 && c == 0) {
            return;
        }
    }
}

static void test_e2e(void)
{
    static const cmt_p2p_ch_desc_t D[] = { { 0x20, 6, 100, 0, 0 },
                                           { 0x21, 10, 100, 0, 0 } };
    node_t *na = (node_t *)calloc(1, sizeof(node_t));
    node_t *nb = (node_t *)calloc(1, sizeof(node_t));
    e2e_side_t *I = (e2e_side_t *)calloc(1, sizeof(e2e_side_t));
    e2e_side_t *R = (e2e_side_t *)calloc(1, sizeof(e2e_side_t));
    cmt_p2p_mconn_config_t cfg;
    pipe_t ir, ri;
    uint8_t *big = (uint8_t *)malloc(3000);
    int ok = 1, guard;
    size_t k;

    TEST("end to end: 2 SecretConnections + 2 MConnections, 2 channels");
    pipe_init(&ir);
    pipe_init(&ri);
    if (na == NULL || nb == NULL || I == NULL || R == NULL || big == NULL ||
        nodus_identity_generate(&na->id) != 0 ||
        nodus_identity_generate(&nb->id) != 0 || !nb->id.has_mlkem) {
        FAIL("identities");
        goto out;
    }
    for (k = 0; k < 3000; k++) {
        big[k] = (uint8_t)(k ^ 0x5Au);
    }
    I->sc = (cmt_p2p_sc_t *)calloc(1, sizeof(cmt_p2p_sc_t));
    R->sc = (cmt_p2p_sc_t *)calloc(1, sizeof(cmt_p2p_sc_t));
    I->seal_cap = R->seal_cap = 1u << 18;
    I->seal = (uint8_t *)malloc(I->seal_cap);
    R->seal = (uint8_t *)malloc(R->seal_cap);
    if (I->sc == NULL || R->sc == NULL || I->seal == NULL || R->seal == NULL) {
        FAIL("alloc");
        goto out;
    }
    I->host.ctx = na;
    I->host.sign = sc_host_sign;
    I->host.verify = sc_host_verify;
    R->host.ctx = nb;
    R->host.sign = sc_host_sign;
    R->host.verify = sc_host_verify;
    if (cmt_p2p_sc_init(I->sc, CMT_P2P_SC_ROLE_INITIATOR, &I->host, na->id.pk.bytes,
                        NULL, NULL, 8u, CHAIN) != CMT_OK ||
        cmt_p2p_sc_init(R->sc, CMT_P2P_SC_ROLE_RESPONDER, &R->host, nb->id.pk.bytes,
                        nb->id.mlkem_pk, nb->id.mlkem_sk, 8u, CHAIN) != CMT_OK) {
        FAIL("sc init");
        goto out;
    }
    for (guard = 0; guard < 100; guard++) {
        sc_shuttle(I, &ir, &ri);
        sc_shuttle(R, &ri, &ir);
        if (cmt_p2p_sc_is_authenticated(I->sc) && cmt_p2p_sc_is_authenticated(R->sc)) {
            break;
        }
    }
    if (!cmt_p2p_sc_is_authenticated(I->sc) || !cmt_p2p_sc_is_authenticated(R->sc)) {
        FAIL("handshake");
        goto out;
    }

    cmt_p2p_mconn_p2p_default_config(&cfg);
    I->c = conn_new(D, 2, &cfg);
    R->c = conn_new(D, 2, &cfg);
    if (I->c == NULL || R->c == NULL) {
        FAIL("mconn init");
        goto out;
    }
    ok &= cmt_p2p_mconn_send(&I->c->mc, 0x20, (const uint8_t *)"state-1", 7);
    ok &= cmt_p2p_mconn_send(&I->c->mc, 0x21, big, 3000);
    ok &= cmt_p2p_mconn_send(&I->c->mc, 0x20, (const uint8_t *)"state-2", 7);
    ok &= cmt_p2p_mconn_send(&R->c->mc, 0x21, (const uint8_t *)"data-r", 6);
    ok &= cmt_p2p_mconn_send(&R->c->mc, 0x20, (const uint8_t *)"state-r", 7);
    for (guard = 0; guard < 50; guard++) {
        g_now += 100 * MS;
        e2e_send(I, &ir);
        e2e_send(R, &ri);
        e2e_recv(R, &ir);
        e2e_recv(I, &ri);
    }
    /* R: channel 0x20 in order, 0x21 whole; I: both of R's */
    {
        int s1 = -1, s2 = -1, bg = -1, i;

        for (i = 0; i < R->c->n_msgs; i++) {
            rmsg_t *m = &R->c->msgs[i];

            if (m->ch == 0x20 && m->len == 7 && memcmp(m->b, "state-1", 7) == 0) {
                s1 = i;
            } else if (m->ch == 0x20 && m->len == 7 && memcmp(m->b, "state-2", 7) == 0) {
                s2 = i;
            } else if (m->ch == 0x21 && m->len == 3000 && memcmp(m->b, big, 3000) == 0) {
                bg = i;
            }
        }
        ok &= R->c->n_msgs == 3 && s1 >= 0 && s2 > s1 && bg >= 0;
    }
    ok &= I->c->n_msgs == 2;
    ok &= I->c->n_errors == 0 && R->c->n_errors == 0 &&
          cmt_p2p_mconn_is_running(&I->c->mc) && cmt_p2p_mconn_is_running(&R->c->mc);
    if (ok) {
        PASS();
    } else {
        FAIL("e2e delivery");
    }
out:
    if (I != NULL) {
        conn_free(I->c);
        if (I->sc != NULL) {
            cmt_p2p_sc_clear(I->sc);
        }
        free(I->sc);
        free(I->seal);
    }
    if (R != NULL) {
        conn_free(R->c);
        if (R->sc != NULL) {
            cmt_p2p_sc_clear(R->sc);
        }
        free(R->sc);
        free(R->seal);
    }
    free(I);
    free(R);
    free(na);
    free(nb);
    free(big);
    pipe_free(&ir);
    pipe_free(&ri);
}

/* ══ main ════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("test_p2p_mconn — connection.go / flowrate / protoio port (P2P-PORT F2)\n");

    test_vectors();
    test_packet_roundtrip();
    test_max_packet_size();
    test_protoio();
    test_flowrate_unit();
    test_send_receive();
    test_try_send();
    test_split("split 5000 bytes -> 5 packets, reassembled", 0);
    test_split("split, stream fed ONE byte per recv call", 1);
    test_empty_message();
    test_recv_capacity();
    test_recv_n_one_message();
    test_unknown_channel_recv();
    test_long_message();
    test_channel_overflow();
    test_bad_encoding();
    test_ping_pong();
    test_pong_timeout();
    test_multiple_pongs();
    test_multiple_pings();
    test_priority();
    test_send_rate();
    test_recv_rate();
    test_flush_stop();
    test_init_refusals();
    test_e2e();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
