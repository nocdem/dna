/**
 * Nodus — DHT v2 sub-package 3b-1: the SecretConnection layer of the TCP /
 * WebSocket transport (nodus/src/transport/nodus_tcp_sc.{h,c}, nodus_tcp.c).
 *
 * Governing: docs/plans/2026-10-23-dht-v2-session-package-design.md rev 1,
 * decisions/2026-10-23-kurultay-43-summary.md, decisions/2026-10-23-dht-v2-
 * session-bytes.md, decisions/2026-09-26-witness-port-session.md.
 *
 * ── WHAT IT PROVES (each would be false if its case failed) ────────────
 *   1. CLIENT profile + purpose 0x0C on both ends: a real loopback TCP pair
 *      authenticates (on_session fires on both, each sees the other's
 *      public key) and exchanges nodus frames both ways, a 1-byte one and
 *      one of exactly NODUS_MAX_FRAME_TCP (5 MiB = 5,121 sealed frames,
 *      more than the plain write buffer) in each direction, byte-exact.
 *   2. The same for the NODE profile + purpose 0x0D.
 *   3. A client on the CLIENT profile against a server on the NODE profile
 *      never authenticates: both sides close, no on_session, no frame.
 *   4. The initiator's pin: a wrong expected identity closes the dialing
 *      connection before any session exists (and a send on it is refused).
 *   5. A nodus_tcp_send before AUTHENTICATED is refused and moves no
 *      counter; enable refuses the WITNESS profile, an unpinned initiator
 *      and a second enable.
 *   6. Nothing reaches the frame parser before AUTHENTICATED: a plaintext
 *      nodus frame sent to a layer-enabled responder closes it, on_frame
 *      never runs.
 *   7. Reserve before seal: with the receiver stalled, sends fill the write
 *      buffer and the pending queue and then are REFUSED (-1) with the send
 *      counter exactly where it was; with on_pending_full installed the
 *      callback gets the PLAINTEXT payload (never sealed bytes) and the
 *      counter is again unmoved; afterwards every queued frame arrives in
 *      order and byte-exact, and a further send works — a counter gap would
 *      fail the receiver's AES-GCM and close the connection.
 *   8. A job result is applied by (slot, generation): a result for an empty
 *      slot, a wrong generation, a layer not waiting for a job, a closed
 *      connection, and a REUSED slot (same index, new generation) is
 *      discarded and nothing of the live connection changes.
 *   9. WebSocket: the same layer on a WS connection (Upgrade, then WS bytes
 *      → SecretConnection → nodus frames): a raw peer driving a
 *      cmt_p2p_sc_t initiator over masked WS binary frames authenticates, a
 *      frame goes in, a 100,000-byte frame comes out in exactly 4 WS binary
 *      frames (98 sealed frames in groups of at most 32), and a WS ping is
 *      still answered by a pong outside the sealed stream.
 *  10. Without the layer, a connection's bytes are those of today: a raw
 *      peer reads exactly 4E 44 02 ‖ len LE ‖ payload, and a frame it
 *      writes that way is delivered.
 *
 * WHAT IT REQUIRES: a default nodus build (no compile flags, no
 * environment). Loopback sockets on ephemeral ports (127.0.0.1:0), threads
 * (the layer's handshake worker). Heap: 5 MiB receive buffers, ~40 MiB peak
 * in case 7.
 * WHAT IT LEAVES BEHIND: nothing (all sockets closed, workers joined).
 *
 * HOW IT CAN LIE: every wait is a ROUND count of nodus_tcp_poll calls on
 * both ends, not a timing claim — a stuck handshake FAILs, it never passes
 * by waiting. Case 7's "refused" point depends on the host's socket buffers
 * (it sends 1 MiB frames until the first refusal, bounded at 300 sends);
 * the assertions are about what happens AT that point, wherever it is. The
 * WS peer (case 9) shares the process with the server and is driven from
 * the same thread. The AUTHSIG-tail drain (plaintext the machine holds when
 * no socket byte is waiting) is not driven here: our own sender seals the
 * AUTHSIG alone, so no tail ever exists on these connections. A full
 * handshake-job queue closing its connection is not driven (no way to hold
 * the worker without a test hook in production code). The Windows and
 * Emscripten arms of nodus_tcp.c / nodus_tcp_sc.c are not built or run.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "transport/nodus_ws.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "dnac/cmt_p2p_secret.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>      /* seal_by_hand: one sealed frame the machine would refuse to write */

#define TEST(name) do { printf("  %-72s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define PROTO_VER   0x00010001u
#define MAX_ROUNDS  3000          /* liveness bound per wait (rounds, not time) */
#define BIG_ROUNDS  20000

static const uint8_t CHAIN[CMT_P2P_SC_CHAIN_ID_SIZE] = {
    0xc1, 0x0a, 0x4e, 0x71, 0x22, 0x9b, 0x03, 0xd8, 0x55, 0x6f, 0xe0, 0x17,
    0x38, 0xaa, 0x91, 0x0c, 0x42, 0xbd, 0x6e, 0x05, 0xf3, 0x8c, 0x29, 0x74,
    0x1d, 0xb6, 0x50, 0xe9, 0x07, 0xca, 0x83, 0x3f
};

/* ══ identities and one side of a connection ═════════════════════════ */

static nodus_identity_t *g_a;   /* the server / responder identity */
static nodus_identity_t *g_b;   /* the client / initiator identity */
static nodus_identity_t *g_c;   /* a third identity (the wrong pin) */

typedef struct side {
    nodus_tcp_t         tcp;
    nodus_tcp_sc_cfg_t  cfg;
    bool                enable_on_accept;
    int                 enable_rc;
    const uint8_t      *peer_pk;      /* what on_session must see */
    nodus_tcp_conn_t   *conn;
    int                 accepted, disconnected, sessions, peer_ok, frames;
    int                 frames_at_session;   /* frames delivered when on_session ran */
    int                 frames_at_close;     /* ... and when on_disconnect ran */
    uint8_t            *rx;           /* the last frame delivered */
    size_t              rx_len;
    bool                seq_mode;     /* verify idx-tagged frames in order */
    uint64_t            next_idx;
    int                 seq_ok, seq_bad;
    int                 pf_calls, pf_match;
    uint64_t            pf_idx;
    size_t              pf_len;
} side_t;

static side_t g_srv;
static side_t g_cli;

/* Frame body: u64 LE index ‖ a pattern that depends on index and offset. */
static void fill_seq(uint8_t *buf, size_t len, uint64_t idx)
{
    for (int i = 0; i < 8; i++)
        buf[i] = (uint8_t)(idx >> (8 * i));
    for (size_t k = 8; k < len; k++)
        buf[k] = (uint8_t)(idx * 131u + k * 7u + (k >> 8));
}

static void cb_accept(nodus_tcp_conn_t *c, void *ctx)
{
    side_t *s = (side_t *)ctx;

    s->accepted++;
    s->conn = c;
    if (s->enable_on_accept)
        s->enable_rc = nodus_tcp_sc_enable(&s->tcp, c, &s->cfg);
}

static void cb_disconnect(nodus_tcp_conn_t *c, void *ctx)
{
    side_t *s = (side_t *)ctx;

    s->disconnected++;
    s->frames_at_close = s->frames;
    if (s->conn == c)
        s->conn = NULL;
}

static void cb_session(nodus_tcp_conn_t *c, void *ctx)
{
    side_t *s = (side_t *)ctx;
    uint8_t pk[NODUS_PK_BYTES];     /* a COPY: the machine's key is never handed out */

    s->sessions++;
    s->frames_at_session = s->frames;
    if (nodus_tcp_sc_peer_pubkey(c, pk) == 0 && s->peer_pk != NULL &&
        memcmp(pk, s->peer_pk, NODUS_PK_BYTES) == 0)
        s->peer_ok++;
}

static void cb_frame(nodus_tcp_conn_t *c, const uint8_t *payload, size_t len, void *ctx)
{
    side_t *s = (side_t *)ctx;

    (void)c;
    s->frames++;
    if (len <= NODUS_MAX_FRAME_TCP) {
        memcpy(s->rx, payload, len);
        s->rx_len = len;
    } else {
        s->rx_len = (size_t)-1;
    }
    if (s->seq_mode) {
        uint8_t *exp = (uint8_t *)malloc(len > 8 ? len : 8);
        uint64_t idx = 0;

        for (int i = 0; i < 8 && (size_t)i < len; i++)
            idx |= (uint64_t)payload[i] << (8 * i);
        if (exp != NULL && len >= 8 && idx == s->next_idx) {
            fill_seq(exp, len, idx);
            if (memcmp(exp, payload, len) == 0)
                s->seq_ok++;
            else
                s->seq_bad++;
        } else {
            s->seq_bad++;
        }
        free(exp);
        s->next_idx++;
    }
}

static void cb_pending_full(nodus_tcp_conn_t *c, const uint8_t *payload, size_t len, void *ctx)
{
    side_t *s = (side_t *)ctx;
    uint8_t *exp = (uint8_t *)malloc(len > 8 ? len : 8);

    (void)c;
    s->pf_calls++;
    s->pf_len = len;
    /* Plaintext means: exactly the bytes the caller handed to the send. */
    s->pf_match = exp != NULL && len >= 8 &&
                  (fill_seq(exp, len, s->pf_idx), memcmp(exp, payload, len) == 0);
    free(exp);
}

static bool g_level;            /* the next side_init makes a level-triggered transport */

static void side_init(side_t *s)
{
    memset(s, 0, sizeof(*s));
    s->rx = (uint8_t *)malloc(NODUS_MAX_FRAME_TCP);
    nodus_tcp_init(&s->tcp, -1);
    s->tcp.level_triggered = g_level;
    s->tcp.on_accept = cb_accept;
    s->tcp.on_disconnect = cb_disconnect;
    s->tcp.on_session = cb_session;
    s->tcp.on_frame = cb_frame;
    s->tcp.cb_ctx = s;
}

static void side_close(side_t *s)
{
    nodus_tcp_close(&s->tcp);
    free(s->rx);
    s->rx = NULL;
}

static void cfg_fill(nodus_tcp_sc_cfg_t *cfg, cmt_p2p_sc_role_t role,
                     const cmt_p2p_sc_profile_t *profile, const nodus_identity_t *id,
                     const nodus_key_t *pin)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->role = role;
    cfg->profile = profile;
    cfg->id = id;
    cfg->proto_ver = PROTO_VER;
    memcpy(cfg->chain_id, CHAIN, sizeof(cfg->chain_id));
    cfg->expected_peer = pin;
}

static void poll_both(void)
{
    nodus_tcp_poll(&g_srv.tcp, 1);
    nodus_tcp_poll(&g_cli.tcp, 1);
}

/* Poll both ends until *counter >= target; 1 if it got there. */
static int pump_until(const int *counter, int target, int rounds)
{
    for (int i = 0; i < rounds; i++) {
        if (*counter >= target)
            return 1;
        poll_both();
    }
    return *counter >= target;
}

/* A listening server (responder) and a connected client (initiator) of the
 * given profiles; the client dials the server's identity (or `pin`). The
 * caller pumps. */
static int pair_up(const cmt_p2p_sc_profile_t *srv_prof,
                   const cmt_p2p_sc_profile_t *cli_prof, const nodus_key_t *pin)
{
    side_init(&g_srv);
    side_init(&g_cli);
    cfg_fill(&g_srv.cfg, CMT_P2P_SC_ROLE_RESPONDER, srv_prof, g_a, NULL);
    g_srv.enable_on_accept = true;
    g_srv.peer_pk = g_b->pk.bytes;
    g_cli.peer_pk = g_a->pk.bytes;
    if (nodus_tcp_listen(&g_srv.tcp, "127.0.0.1", 0) != 0)
        return -1;
    g_cli.conn = nodus_tcp_connect(&g_cli.tcp, "127.0.0.1", g_srv.tcp.port);
    if (g_cli.conn == NULL)
        return -1;
    cfg_fill(&g_cli.cfg, CMT_P2P_SC_ROLE_INITIATOR, cli_prof, g_b,
             pin != NULL ? pin : &g_a->node_id);
    g_cli.enable_rc = nodus_tcp_sc_enable(&g_cli.tcp, g_cli.conn, &g_cli.cfg);
    return g_cli.enable_rc;
}

static void pair_down(void)
{
    side_close(&g_cli);
    side_close(&g_srv);
}

/* Send `buf` from `from` and wait until `to` delivered it, byte-exact. */
static int send_and_check(side_t *from, side_t *to, const uint8_t *buf, size_t len)
{
    int before = to->frames;

    if (from->conn == NULL || nodus_tcp_send(from->conn, buf, len) != 0)
        return 0;
    if (!pump_until(&to->frames, before + 1, BIG_ROUNDS))
        return 0;
    return to->rx_len == len && memcmp(to->rx, buf, len) == 0;
}

/* ══ 1, 2: a matched pair, both profiles ═════════════════════════════ */

static void test_matched_pair(const char *label, const cmt_p2p_sc_profile_t *prof)
{
    char name[96];
    uint8_t one = 0x5a;
    uint8_t *big = (uint8_t *)malloc(NODUS_MAX_FRAME_TCP);
    int ok;

    snprintf(name, sizeof(name), "%s: handshake, both on_session, peer keys seen", label);
    TEST(name);
    ok = big != NULL && pair_up(prof, prof, NULL) == 0 &&
         pump_until(&g_srv.sessions, 1, MAX_ROUNDS) &&
         pump_until(&g_cli.sessions, 1, MAX_ROUNDS) &&
         g_srv.peer_ok == 1 && g_cli.peer_ok == 1 &&
         nodus_tcp_sc_authenticated(g_srv.conn) && nodus_tcp_sc_authenticated(g_cli.conn);
    if (ok) PASS(); else FAIL("no session / wrong peer key");

    if (ok) {
        snprintf(name, sizeof(name), "%s: 1-byte nodus frame both ways", label);
        TEST(name);
        if (send_and_check(&g_cli, &g_srv, &one, 1) && send_and_check(&g_srv, &g_cli, &one, 1))
            PASS();
        else FAIL("small frame lost or altered");

        snprintf(name, sizeof(name), "%s: 5 MiB nodus frame (5,121 sealed frames) both ways", label);
        TEST(name);
        for (size_t i = 0; i < NODUS_MAX_FRAME_TCP; i++)
            big[i] = (uint8_t)(i * 31u + (i >> 12) + 7u);
        if (send_and_check(&g_cli, &g_srv, big, NODUS_MAX_FRAME_TCP)) {
            big[0] ^= 0xff;
            if (send_and_check(&g_srv, &g_cli, big, NODUS_MAX_FRAME_TCP)) PASS();
            else FAIL("5 MiB frame server->client");
        } else FAIL("5 MiB frame client->server");

        snprintf(name, sizeof(name), "%s: no connection was closed", label);
        TEST(name);
        if (g_srv.disconnected == 0 && g_cli.disconnected == 0) PASS();
        else FAIL("a connection closed");
    }
    pair_down();
    free(big);
}

/* ══ 3: mixed profiles ═══════════════════════════════════════════════ */

static void test_mixed_profiles(void)
{
    TEST("mixed profiles (client CLIENT, server NODE): no session, both close");
    int ok = pair_up(&CMT_P2P_SC_PROFILE_NODE, &CMT_P2P_SC_PROFILE_CLIENT, NULL) == 0 &&
             pump_until(&g_cli.disconnected, 1, MAX_ROUNDS) &&
             pump_until(&g_srv.disconnected, 1, MAX_ROUNDS);
    if (ok && g_srv.sessions == 0 && g_cli.sessions == 0 &&
        g_srv.frames == 0 && g_cli.frames == 0) PASS();
    else FAIL("a session or frame appeared, or a side did not close");
    pair_down();
}

/* ══ 4, 5: the pin, refusals ═════════════════════════════════════════ */

static void test_wrong_pin(void)
{
    TEST("wrong dial pin: the initiator closes before any session");
    int ok = pair_up(&CMT_P2P_SC_PROFILE_CLIENT, &CMT_P2P_SC_PROFILE_CLIENT, &g_c->node_id) == 0;
    uint8_t x = 1;

    /* Not authenticated yet: a send is refused and seals nothing. */
    ok = ok && g_cli.conn != NULL && nodus_tcp_send(g_cli.conn, &x, 1) == -1 &&
         nodus_tcp_sc_send_counter(g_cli.conn) == 0 &&
         pump_until(&g_cli.disconnected, 1, MAX_ROUNDS) &&
         pump_until(&g_srv.disconnected, 1, MAX_ROUNDS);
    if (ok && g_cli.sessions == 0 && g_srv.sessions == 0 && g_srv.frames == 0) PASS();
    else FAIL("session formed, or the pin did not stop the dial");
    pair_down();
}

static void test_enable_refusals(void)
{
    nodus_tcp_sc_cfg_t cfg;
    nodus_tcp_conn_t *c;

    side_init(&g_srv);
    side_init(&g_cli);
    nodus_tcp_listen(&g_srv.tcp, "127.0.0.1", 0);
    c = nodus_tcp_connect(&g_cli.tcp, "127.0.0.1", g_srv.tcp.port);

    TEST("enable refuses WITNESS profile, an unpinned initiator, NULL arguments");
    cfg_fill(&cfg, CMT_P2P_SC_ROLE_INITIATOR, &CMT_P2P_SC_PROFILE_WITNESS, g_b, &g_a->node_id);
    int ok = c != NULL && nodus_tcp_sc_enable(&g_cli.tcp, c, &cfg) == -1;
    cfg_fill(&cfg, CMT_P2P_SC_ROLE_INITIATOR, &CMT_P2P_SC_PROFILE_CLIENT, g_b, NULL);
    ok = ok && nodus_tcp_sc_enable(&g_cli.tcp, c, &cfg) == -1;
    ok = ok && nodus_tcp_sc_enable(&g_cli.tcp, c, NULL) == -1 &&
         nodus_tcp_sc_enable(NULL, c, &cfg) == -1;
    if (ok) PASS(); else FAIL("a bad enable was accepted");

    TEST("enable once; a second enable on the same connection is refused");
    cfg_fill(&cfg, CMT_P2P_SC_ROLE_INITIATOR, &CMT_P2P_SC_PROFILE_NODE, g_b, &g_a->node_id);
    ok = nodus_tcp_sc_enable(&g_cli.tcp, c, &cfg) == 0 &&
         nodus_tcp_sc_enable(&g_cli.tcp, c, &cfg) == -1 &&
         nodus_tcp_sc_generation(c) != 0;
    if (ok) PASS(); else FAIL("enable not once-only");

    side_close(&g_cli);
    side_close(&g_srv);
}

/* ══ 6: nothing reaches the parser before AUTHENTICATED ══════════════ */

static int raw_connect(uint16_t port)
{
    struct sockaddr_in a;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;

    while (n > 0) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static void test_plain_frame_before_session(void)
{
    uint8_t wire[64];
    size_t n;
    int fd, ok;

    TEST("a plaintext nodus frame to a layer-enabled responder closes it, no on_frame");
    side_init(&g_srv);
    cfg_fill(&g_srv.cfg, CMT_P2P_SC_ROLE_RESPONDER, &CMT_P2P_SC_PROFILE_CLIENT, g_a, NULL);
    g_srv.enable_on_accept = true;
    nodus_tcp_listen(&g_srv.tcp, "127.0.0.1", 0);
    fd = raw_connect(g_srv.tcp.port);
    n = nodus_frame_encode(wire, sizeof(wire), (const uint8_t *)"hi", 2);
    ok = fd >= 0 && n == 9 && send_all(fd, wire, n) == 0;
    for (int i = 0; ok && i < MAX_ROUNDS && g_srv.disconnected == 0; i++)
        nodus_tcp_poll(&g_srv.tcp, 1);
    if (ok && g_srv.enable_rc == 0 && g_srv.disconnected == 1 && g_srv.frames == 0) PASS();
    else FAIL("frame reached the parser, or the connection stayed open");
    if (fd >= 0) close(fd);
    side_close(&g_srv);
}

/* ══ 7: reserve before seal ══════════════════════════════════════════ */

#define Q_FRAME_LEN (1024 * 1024)

static void test_full_queue(void)
{
    uint8_t *buf = (uint8_t *)malloc(Q_FRAME_LEN);
    int ok, n_ok = 0, refused = -1;
    uint64_t before = 0;

    TEST("full queue: the refused send moves no counter");
    ok = buf != NULL && pair_up(&CMT_P2P_SC_PROFILE_CLIENT, &CMT_P2P_SC_PROFILE_CLIENT, NULL) == 0 &&
         pump_until(&g_srv.sessions, 1, MAX_ROUNDS) && pump_until(&g_cli.sessions, 1, MAX_ROUNDS);
    g_srv.seq_mode = true;
    /* The receiver stalls: nobody polls the server from here until the drain. */
    for (int i = 0; ok && i < 300; i++) {
        int rc;

        fill_seq(buf, Q_FRAME_LEN, (uint64_t)i);
        before = nodus_tcp_sc_send_counter(g_cli.conn);
        rc = nodus_tcp_send(g_cli.conn, buf, Q_FRAME_LEN);
        if (rc != 0) {
            refused = i;
            break;
        }
        n_ok++;
    }
    if (ok && refused >= 0 && refused == n_ok && nodus_tcp_sc_send_counter(g_cli.conn) == before &&
        g_cli.conn->pending_count >= NODUS_PENDING_MAX_FRAMES && g_cli.disconnected == 0) PASS();
    else FAIL("no refusal, or the refusal moved the counter");

    TEST("full queue: on_pending_full gets the PLAINTEXT payload, counter unmoved");
    if (ok && refused >= 0) {
        g_cli.tcp.on_pending_full = cb_pending_full;
        g_cli.tcp.pending_full_ctx = &g_cli;
        g_cli.pf_idx = (uint64_t)refused;
        fill_seq(buf, Q_FRAME_LEN, (uint64_t)refused);
        before = nodus_tcp_sc_send_counter(g_cli.conn);
        if (nodus_tcp_send(g_cli.conn, buf, Q_FRAME_LEN) == 0 && g_cli.pf_calls == 1 &&
            g_cli.pf_match && g_cli.pf_len == Q_FRAME_LEN &&
            nodus_tcp_sc_send_counter(g_cli.conn) == before) PASS();
        else FAIL("callback missing, payload not plaintext, or counter moved");
    } else FAIL("no refusal point to test");

    TEST("full queue: every queued frame arrives in order, byte-exact, no counter gap");
    ok = ok && refused > 0 && pump_until(&g_srv.frames, n_ok, BIG_ROUNDS);
    if (ok && g_srv.seq_ok == n_ok && g_srv.seq_bad == 0 && g_srv.disconnected == 0 &&
        g_cli.disconnected == 0) PASS();
    else FAIL("frames lost, reordered, or the session broke");

    TEST("full queue: the session continues with a further send");
    if (ok) {
        fill_seq(buf, Q_FRAME_LEN, (uint64_t)n_ok);
        if (nodus_tcp_send(g_cli.conn, buf, Q_FRAME_LEN) == 0 &&
            pump_until(&g_srv.frames, n_ok + 1, BIG_ROUNDS) &&
            g_srv.seq_ok == n_ok + 1 && g_srv.seq_bad == 0 && g_srv.disconnected == 0) PASS();
        else FAIL("the session did not continue");
    } else FAIL("drain failed");

    pair_down();
    free(buf);
}

/* ══ 8: a completion is applied by (slot, generation) ════════════════ */

static nodus_sc_job_t *fake_job(int slot, uint64_t gen, cmt_p2p_sc_job_kind_t kind)
{
    nodus_sc_job_t *j = (nodus_sc_job_t *)calloc(1, sizeof(*j));

    if (j != NULL) {
        j->slot = slot;
        j->gen = gen;
        j->kind = kind;
        j->rc = 0;
    }
    return j;
}

static int discarded(nodus_tcp_t *tcp, int slot, uint64_t gen)
{
    nodus_tcp_conn_t *c = (nodus_tcp_conn_t *)0x1;   /* must be overwritten */
    nodus_sc_job_t *j = fake_job(slot, gen, CMT_P2P_SC_JOB_VERIFY);

    return j != NULL && nodus_tcp_sc_job_apply(tcp, j, &c) == NODUS_SC_APPLY_DISCARDED &&
           c == NULL;
}

static void test_stale_completion(void)
{
    nodus_tcp_conn_t *c1, *c2;
    int slot1;
    uint64_t gen1;
    int ok;

    side_init(&g_srv);
    side_init(&g_cli);
    nodus_tcp_listen(&g_srv.tcp, "127.0.0.1", 0);   /* never polled: no handshake runs */
    cfg_fill(&g_cli.cfg, CMT_P2P_SC_ROLE_INITIATOR, &CMT_P2P_SC_PROFILE_CLIENT, g_b, &g_a->node_id);
    c1 = nodus_tcp_connect(&g_cli.tcp, "127.0.0.1", g_srv.tcp.port);
    ok = c1 != NULL && nodus_tcp_sc_enable(&g_cli.tcp, c1, &g_cli.cfg) == 0;
    slot1 = ok ? c1->slot : -1;
    gen1 = ok ? nodus_tcp_sc_generation(c1) : 0;

    TEST("stale result: empty slot, wrong generation, layer not waiting -> discarded");
    ok = ok && discarded(&g_cli.tcp, NODUS_TCP_MAX_CONNS - 1, 1) &&
         discarded(&g_cli.tcp, slot1, gen1 + 1000) &&
         discarded(&g_cli.tcp, slot1, gen1) &&          /* right slot+gen, no job out */
         discarded(&g_cli.tcp, -1, 1) && discarded(&g_cli.tcp, NODUS_TCP_MAX_CONNS, 1) &&
         g_cli.tcp.pool[slot1] == c1 && nodus_tcp_sc_generation(c1) == gen1 &&
         nodus_tcp_sc_outstanding(&g_cli.tcp) == 0;
    if (ok) PASS(); else FAIL("a stale result was applied or disturbed the connection");

    TEST("stale result: closed connection, then the REUSED slot (new generation)");
    nodus_tcp_disconnect(&g_cli.tcp, c1);
    ok = ok && g_cli.tcp.pool[slot1] == NULL && discarded(&g_cli.tcp, slot1, gen1);
    c2 = nodus_tcp_connect(&g_cli.tcp, "127.0.0.1", g_srv.tcp.port);
    ok = ok && c2 != NULL && nodus_tcp_sc_enable(&g_cli.tcp, c2, &g_cli.cfg) == 0 &&
         c2->slot == slot1 && nodus_tcp_sc_generation(c2) != gen1 &&
         discarded(&g_cli.tcp, slot1, gen1) &&
         nodus_tcp_sc_generation(c2) != 0 && g_cli.tcp.pool[slot1] == c2;
    if (ok) PASS(); else FAIL("a result for a closed / reused slot was applied");

    side_close(&g_cli);
    side_close(&g_srv);
}

/* ══ 10: without the layer, the bytes are today's ════════════════════ */

static void test_layer_off_bytes(void)
{
    static const uint8_t p_in[5] = { 'a', 'b', 'c', 'd', 'e' };
    static const uint8_t p_out[3] = { 0x01, 0x02, 0x03 };
    static const uint8_t lit_out[10] = { 0x4e, 0x44, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03 };
    uint8_t wire[32];
    uint8_t got[32];
    size_t n, have = 0;
    int fd, ok;

    TEST("layer off: a raw peer's frame is delivered; the reply is exactly 4E 44 02 ‖ len LE ‖ payload");
    side_init(&g_srv);                    /* enable_on_accept stays false */
    nodus_tcp_listen(&g_srv.tcp, "127.0.0.1", 0);
    fd = raw_connect(g_srv.tcp.port);
    n = nodus_frame_encode(wire, sizeof(wire), p_in, sizeof(p_in));
    ok = fd >= 0 && n == 12 && send_all(fd, wire, n) == 0;
    for (int i = 0; ok && i < MAX_ROUNDS && g_srv.frames == 0; i++)
        nodus_tcp_poll(&g_srv.tcp, 1);
    ok = ok && g_srv.frames == 1 && g_srv.rx_len == sizeof(p_in) &&
         memcmp(g_srv.rx, p_in, sizeof(p_in)) == 0 && g_srv.conn != NULL &&
         nodus_tcp_sc_authenticated(g_srv.conn) == false &&
         nodus_tcp_send(g_srv.conn, p_out, sizeof(p_out)) == 0;
    for (int i = 0; ok && i < MAX_ROUNDS && have < sizeof(lit_out); i++) {
        ssize_t r;

        nodus_tcp_poll(&g_srv.tcp, 1);
        r = recv(fd, got + have, sizeof(got) - have, MSG_DONTWAIT);
        if (r > 0) have += (size_t)r;
    }
    n = nodus_frame_encode(wire, sizeof(wire), p_out, sizeof(p_out));
    if (ok && have == sizeof(lit_out) && memcmp(got, lit_out, sizeof(lit_out)) == 0 &&
        n == sizeof(lit_out) && memcmp(wire, lit_out, n) == 0) PASS();
    else FAIL("bytes differ from the plain frame layout");
    if (fd >= 0) close(fd);
    side_close(&g_srv);
}

/* ══ 9: the layer on a WebSocket connection ══════════════════════════ */

#define WSRX_CAP (512 * 1024)
#define WS_XFF "198.51.100.9"

/* The raw peer's SecretConnection host: CLIENT purpose 0x0C. */
static int peer_sign(void *ctx, const uint8_t *msg, size_t n, uint8_t out[CMT_P2P_SC_SIG_SIZE])
{
    nodus_sig_t sig;
    int rc = nodus_sign_client_session_auth(&sig, msg, n, (const nodus_seckey_t *)ctx);

    memcpy(out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    return rc;
}

static int peer_verify(void *ctx, const uint8_t sig_in[CMT_P2P_SC_SIG_SIZE],
                       const uint8_t *msg, size_t n, const uint8_t pk_in[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_SC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, CMT_P2P_SC_DSA_PK_SIZE);
    return nodus_verify_client_session_auth(&sig, msg, n, &pk);
}

typedef struct {
    int       fd;
    cmt_p2p_sc_t *m;
    cmt_p2p_sc_host_t host;
    uint8_t  *rx;            /* bytes from the server, WS-framed */
    size_t    rx_len;
    uint8_t  *plain;         /* what the machine opened */
    size_t    plain_len;
    int       bin_frames;    /* WS binary frames received */
    int       pongs;
    int       pin_bad;
} wspeer_t;

/* Masked client frame (RFC 6455 §5.3), payload up to 65535 bytes. */
static size_t ws_client_frame(uint8_t *out, uint8_t first, const uint8_t *p, size_t n)
{
    static const uint8_t key[4] = { 0x37, 0xfa, 0x21, 0x3d };
    size_t o = 0;

    out[o++] = first;
    if (n < 126) {
        out[o++] = (uint8_t)(0x80 | n);
    } else {
        out[o++] = 0x80 | 126;
        out[o++] = (uint8_t)(n >> 8);
        out[o++] = (uint8_t)n;
    }
    memcpy(out + o, key, 4);
    o += 4;
    for (size_t i = 0; i < n; i++)
        out[o + i] = (uint8_t)(p[i] ^ key[i & 3]);
    return o + n;
}

static void peer_run_job(wspeer_t *w)
{
    const cmt_p2p_sc_job_t *sj;

    while ((sj = cmt_p2p_sc_job(w->m)) != NULL) {
        if (sj->kind == CMT_P2P_SC_JOB_ENCAPS) {
            nodus_pubkey_t pk;
            nodus_key_t fp;

            memcpy(pk.bytes, cmt_p2p_sc_remote_pubkey(w->m), sizeof(pk.bytes));
            if (nodus_fingerprint(&pk, &fp) != 0 || nodus_key_cmp(&fp, &g_a->node_id) != 0)
                w->pin_bad++;
        }
        if (cmt_p2p_sc_job_done(w->m, cmt_p2p_sc_job_run(sj, &w->host)) != CMT_OK)
            return;
    }
}

/* Feed WS payload bytes to the peer's machine. */
static int peer_feed(wspeer_t *w, const uint8_t *p, size_t len)
{
    size_t off = 0;
    uint8_t buf[CMT_P2P_SC_DATA_MAX_SIZE];

    for (;;) {
        size_t c = 0, got = 0;
        int rc;

        if (!cmt_p2p_sc_is_authenticated(w->m)) {
            bool had_job;

            rc = cmt_p2p_sc_recv(w->m, p + off, len - off, &c);
            off += c;
            if (rc != CMT_OK) return -1;
            had_job = cmt_p2p_sc_job(w->m) != NULL;
            peer_run_job(w);
            if (!had_job && c == 0 && !cmt_p2p_sc_is_authenticated(w->m)) break;
            continue;
        }
        rc = cmt_p2p_sc_read(w->m, p + off, len - off, &c, buf, sizeof(buf), &got);
        off += c;
        if (rc != CMT_OK) return -1;
        if (got > 0) {
            if (w->plain_len + got > WSRX_CAP) return -1;
            memcpy(w->plain + w->plain_len, buf, got);
            w->plain_len += got;
            continue;
        }
        if (c == 0) break;
    }
    return 0;
}

/* Receive from the socket, cut server WS frames, act on them. */
static int peer_rx(wspeer_t *w)
{
    ssize_t r = recv(w->fd, w->rx + w->rx_len, WSRX_CAP - w->rx_len, MSG_DONTWAIT);
    size_t off = 0;

    if (r > 0)
        w->rx_len += (size_t)r;
    for (;;) {
        const uint8_t *b = w->rx + off;
        size_t avail = w->rx_len - off, h = 2;
        uint64_t l;

        if (avail < 2) break;
        if (b[1] & 0x80) return -1;               /* server frames are never masked */
        l = b[1] & 0x7F;
        if (l == 126) {
            if (avail < 4) break;
            l = ((uint64_t)b[2] << 8) | b[3];
            h = 4;
        } else if (l == 127) {
            return -1;                            /* groups are far below 64 KiB */
        }
        if (avail < h + l) break;
        if ((b[0] & 0x0F) == NODUS_WS_OP_BINARY) {
            w->bin_frames++;
            if (l > (uint64_t)NODUS_TCP_SC_WS_GROUP_FRAMES * CMT_P2P_SC_SEALED_FRAME_SIZE &&
                cmt_p2p_sc_is_authenticated(w->m))
                return -1;
            if (peer_feed(w, b + h, (size_t)l) != 0) return -1;
        } else if ((b[0] & 0x0F) == NODUS_WS_OP_PONG) {
            w->pongs++;
        }
        off += h + (size_t)l;
    }
    if (off > 0) {
        memmove(w->rx, w->rx + off, w->rx_len - off);
        w->rx_len -= off;
    }
    return 0;
}

/* Put the machine's pending output on the wire, one masked WS frame. */
static int peer_tx(wspeer_t *w)
{
    size_t n = 0;
    const uint8_t *out = cmt_p2p_sc_out(w->m, &n);
    uint8_t *fr;
    int rc;

    if (n == 0)
        return 0;
    fr = (uint8_t *)malloc(n + 8);
    if (fr == NULL) return -1;
    rc = send_all(w->fd, fr, ws_client_frame(fr, 0x82, out, n));
    free(fr);
    cmt_p2p_sc_out_consume(w->m, n);
    return rc;
}

static void test_websocket(void)
{
    static nodus_ws_origins_t origins;
    wspeer_t w;
    char req[512], head[512] = { 0 };     /* initialised: read only after a good setup */
    size_t hl = 0;
    int ok;

    memset(&w, 0, sizeof(w));
    TEST("ws: Upgrade, then the layer authenticates a raw masked-WS initiator");
    side_init(&g_srv);
    cfg_fill(&g_srv.cfg, CMT_P2P_SC_ROLE_RESPONDER, &CMT_P2P_SC_PROFILE_CLIENT, g_a, NULL);
    g_srv.enable_on_accept = true;
    g_srv.peer_pk = g_b->pk.bytes;
    nodus_ws_origins_default(&origins);
    ok = nodus_tcp_ws_listen(&g_srv.tcp, 0, &origins) == 0;
    w.rx = (uint8_t *)malloc(WSRX_CAP);
    w.plain = (uint8_t *)malloc(WSRX_CAP);
    w.m = (cmt_p2p_sc_t *)calloc(1, sizeof(*w.m));
    ok = ok && w.rx && w.plain && w.m;
    if (ok) {
        w.host.ctx = &g_b->sk;
        w.host.sign = peer_sign;
        w.host.verify = peer_verify;
        w.fd = raw_connect(g_srv.tcp.ws_port);
        ok = w.fd >= 0 &&
             cmt_p2p_sc_init_profile(w.m, CMT_P2P_SC_ROLE_INITIATOR, &w.host,
                                     &CMT_P2P_SC_PROFILE_CLIENT, g_b->pk.bytes, NULL, NULL,
                                     PROTO_VER, CHAIN) == CMT_OK;
    }
    if (ok) {
        int n = snprintf(req, sizeof(req),
            "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\nOrigin: %s\r\n"
            "Sec-WebSocket-Protocol: binary\r\nX-Forwarded-For: " WS_XFF "\r\n\r\n",
            (unsigned)g_srv.tcp.ws_port, NODUS_WS_DEFAULT_ORIGIN);
        ok = n > 0 && (size_t)n < sizeof(req) && send_all(w.fd, req, (size_t)n) == 0;
    }
    /* Read the 101 head; anything after it is WS data. */
    for (int i = 0; ok && i < MAX_ROUNDS; i++) {
        ssize_t r;

        nodus_tcp_poll(&g_srv.tcp, 1);
        r = recv(w.fd, head + hl, sizeof(head) - 1 - hl, MSG_DONTWAIT);
        if (r > 0) hl += (size_t)r;
        head[hl] = '\0';
        if (strstr(head, "\r\n\r\n") != NULL) break;
    }
    if (ok) {                              /* a failed setup parses nothing */
        const char *end = strstr(head, "\r\n\r\n");

        ok = end != NULL && strncmp(head, "HTTP/1.1 101", 12) == 0;
        if (ok) {
            size_t eoh = (size_t)(end - head) + 4;

            memcpy(w.rx, head + eoh, hl - eoh);
            w.rx_len = hl - eoh;
        }
    }
    for (int i = 0; ok && i < MAX_ROUNDS && !cmt_p2p_sc_is_authenticated(w.m); i++) {
        nodus_tcp_poll(&g_srv.tcp, 1);
        if (peer_tx(&w) != 0 || peer_rx(&w) != 0) { ok = 0; break; }
        peer_run_job(&w);
    }
    for (int i = 0; ok && i < MAX_ROUNDS && g_srv.sessions == 0; i++) {
        nodus_tcp_poll(&g_srv.tcp, 1);
        if (peer_tx(&w) != 0 || peer_rx(&w) != 0) { ok = 0; break; }
    }
    if (ok && w.pin_bad == 0 && cmt_p2p_sc_is_authenticated(w.m) && g_srv.sessions == 1 &&
        g_srv.peer_ok == 1 && g_srv.enable_rc == 0) PASS();
    else FAIL("no WS session");

    TEST("ws: a nodus frame inside the sealed stream reaches on_frame");
    if (ok) {
        uint8_t plain[64], sealed[CMT_P2P_SC_SEALED_FRAME_SIZE * 2], fr[CMT_P2P_SC_SEALED_FRAME_SIZE * 2 + 16];
        size_t pl = nodus_frame_encode(plain, sizeof(plain), (const uint8_t *)"over-ws", 7);
        size_t sl = 0;

        ok = pl == 14 && cmt_p2p_sc_write(w.m, plain, pl, sealed, sizeof(sealed), &sl) == CMT_OK &&
             sl == CMT_P2P_SC_SEALED_FRAME_SIZE &&
             send_all(w.fd, fr, ws_client_frame(fr, 0x82, sealed, sl)) == 0;
        for (int i = 0; ok && i < MAX_ROUNDS && g_srv.frames == 0; i++)
            nodus_tcp_poll(&g_srv.tcp, 1);
        if (ok && g_srv.frames == 1 && g_srv.rx_len == 7 && memcmp(g_srv.rx, "over-ws", 7) == 0) PASS();
        else FAIL("frame not delivered");
    } else FAIL("no session to send on");

    TEST("ws: a 100,000-byte frame comes out as 4 WS binary frames of sealed groups");
    if (ok) {
        uint8_t *big = (uint8_t *)malloc(100000);
        nodus_frame_t f;
        int bins = w.bin_frames;

        w.plain_len = 0;
        if (big != NULL) {
            for (size_t i = 0; i < 100000; i++) big[i] = (uint8_t)(i * 13u + (i >> 9));
            ok = nodus_tcp_send(g_srv.conn, big, 100000) == 0;
            for (int i = 0; ok && i < MAX_ROUNDS && w.plain_len < 100007; i++) {
                nodus_tcp_poll(&g_srv.tcp, 1);
                if (peer_tx(&w) != 0 || peer_rx(&w) != 0) { ok = 0; break; }
            }
            if (ok && w.plain_len == 100007 && w.bin_frames - bins == 4 &&
                nodus_frame_decode(w.plain, w.plain_len, &f) == 100007 &&
                f.payload_len == 100000 && memcmp(f.payload, big, 100000) == 0) PASS();
            else FAIL("frame wrong, or not cut into 4 groups");
        } else FAIL("alloc");
        free(big);
    } else FAIL("no session to send on");

    TEST("ws: a WS ping is still answered by a pong, outside the sealed stream");
    if (ok) {
        uint8_t fr[16];
        int pongs = w.pongs;

        ok = send_all(w.fd, fr, ws_client_frame(fr, 0x89, (const uint8_t *)"hi", 2)) == 0;
        for (int i = 0; ok && i < MAX_ROUNDS && w.pongs == pongs; i++) {
            nodus_tcp_poll(&g_srv.tcp, 1);
            if (peer_rx(&w) != 0) { ok = 0; break; }
        }
        if (ok && w.pongs == pongs + 1 && g_srv.disconnected == 0) PASS();
        else FAIL("no pong, or the connection closed");
    } else FAIL("no session");

    if (w.fd > 0) close(w.fd);
    if (w.m != NULL) cmt_p2p_sc_clear(w.m);
    free(w.m);
    free(w.rx);
    free(w.plain);
    side_close(&g_srv);
}

/* ══ 11: a WS Close behind input a handshake job is holding ═════════ */

/* Seal ONE frame the way the machine's Write does (cmt_p2p_secret.c
 * sc_seal_frame), by hand, so a peer that is not yet AUTHENTICATED can put
 * application data into the same TCP segment as its AUTHSIG — which the
 * machine itself refuses to do. nonce = role ‖ 00 00 00 ‖ counter (u64 BE). */
static int seal_by_hand(const cmt_p2p_sc_t *m, uint64_t ctr, const uint8_t *chunk,
                        size_t n, uint8_t out[CMT_P2P_SC_SEALED_FRAME_SIZE])
{
    uint8_t frame[CMT_P2P_SC_TOTAL_FRAME_SIZE];
    uint8_t nonce[CMT_P2P_SC_AEAD_NONCE_SIZE] = { 0 };
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ok = 0;

    memset(frame, 0, sizeof(frame));
    frame[0] = (uint8_t)n;
    frame[1] = (uint8_t)(n >> 8);
    memcpy(frame + CMT_P2P_SC_DATA_LEN_SIZE, chunk, n);
    nonce[0] = (uint8_t)m->role;
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(ctr >> (56 - 8 * i));
    if (ctx != NULL &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CMT_P2P_SC_AEAD_NONCE_SIZE, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, m->key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, out, &len, frame, (int)sizeof(frame)) == 1 &&
        EVP_EncryptFinal_ex(ctx, out + len, &len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CMT_P2P_SC_AEAD_OVERHEAD,
                            out + CMT_P2P_SC_TOTAL_FRAME_SIZE) == 1)
        ok = 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static void test_ws_close_behind_data(void)
{
    static nodus_ws_origins_t origins;
    wspeer_t w;
    char req[512], head[512] = { 0 };
    size_t hl = 0;
    int ok;

    TEST("ws: KEYX + AUTHSIG + data + Close in one go: data after on_session, then closed");
    memset(&w, 0, sizeof(w));
    side_init(&g_srv);
    cfg_fill(&g_srv.cfg, CMT_P2P_SC_ROLE_RESPONDER, &CMT_P2P_SC_PROFILE_CLIENT, g_a, NULL);
    g_srv.enable_on_accept = true;
    g_srv.peer_pk = g_b->pk.bytes;
    nodus_ws_origins_default(&origins);
    ok = nodus_tcp_ws_listen(&g_srv.tcp, 0, &origins) == 0;
    w.rx = (uint8_t *)malloc(WSRX_CAP);
    w.plain = (uint8_t *)malloc(WSRX_CAP);
    w.m = (cmt_p2p_sc_t *)calloc(1, sizeof(*w.m));
    ok = ok && w.rx && w.plain && w.m;
    if (ok) {
        int n;

        w.host.ctx = &g_b->sk;
        w.host.sign = peer_sign;
        w.host.verify = peer_verify;
        w.fd = raw_connect(g_srv.tcp.ws_port);
        ok = w.fd >= 0 &&
             cmt_p2p_sc_init_profile(w.m, CMT_P2P_SC_ROLE_INITIATOR, &w.host,
                                     &CMT_P2P_SC_PROFILE_CLIENT, g_b->pk.bytes, NULL, NULL,
                                     PROTO_VER, CHAIN) == CMT_OK;
        n = snprintf(req, sizeof(req),
            "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\nOrigin: %s\r\n"
            "Sec-WebSocket-Protocol: binary\r\nX-Forwarded-For: " WS_XFF "\r\n\r\n",
            (unsigned)g_srv.tcp.ws_port, NODUS_WS_DEFAULT_ORIGIN);
        ok = ok && n > 0 && (size_t)n < sizeof(req) && send_all(w.fd, req, (size_t)n) == 0;
    }
    for (int i = 0; ok && i < MAX_ROUNDS; i++) {      /* the 101 head */
        ssize_t r;

        nodus_tcp_poll(&g_srv.tcp, 1);
        r = recv(w.fd, head + hl, sizeof(head) - 1 - hl, MSG_DONTWAIT);
        if (r > 0) hl += (size_t)r;
        head[hl] = '\0';
        if (strstr(head, "\r\n\r\n") != NULL) break;
    }
    if (ok) {
        const char *end = strstr(head, "\r\n\r\n");

        ok = end != NULL && strncmp(head, "HTTP/1.1 101", 12) == 0;
        if (ok) {
            size_t eoh = (size_t)(end - head) + 4;

            memcpy(w.rx, head + eoh, hl - eoh);
            w.rx_len = hl - eoh;
        }
    }
    /* HELLO goes out; HELLO_R comes back; the peer runs ENCAPS and SIGN and
     * stops at WAIT_AUTHSIG with KEYX + its sealed AUTHSIG still unsent. */
    for (int i = 0; ok && i < MAX_ROUNDS; i++) {
        nodus_tcp_poll(&g_srv.tcp, 1);
        if (w.m->state == CMT_P2P_SC_ST_WAIT_AUTHSIG) break;
        if (peer_tx(&w) != 0 || peer_rx(&w) != 0) { ok = 0; break; }
    }
    ok = ok && w.m->state == CMT_P2P_SC_ST_WAIT_AUTHSIG && w.pin_bad == 0 &&
         w.m->send_counter == CMT_P2P_SC_AUTHSIG_FRAMES_MAX;
    if (ok) {
        size_t n = 0, flight_len;
        const uint8_t *out = cmt_p2p_sc_out(w.m, &n);
        uint8_t *flight = (uint8_t *)malloc(n + CMT_P2P_SC_SEALED_FRAME_SIZE + 64);
        uint8_t *wire = (uint8_t *)malloc(n + CMT_P2P_SC_SEALED_FRAME_SIZE + 128);
        uint8_t plain[32];
        size_t pl = nodus_frame_encode(plain, sizeof(plain), (const uint8_t *)"behind-close", 12);
        static const uint8_t close_body[2] = { 0x03, 0xe8 };    /* 1000 */
        size_t wl;

        ok = flight != NULL && wire != NULL && n > 0 && pl == 19;
        if (ok) {
            memcpy(flight, out, n);
            cmt_p2p_sc_out_consume(w.m, n);
            ok = seal_by_hand(w.m, w.m->send_counter, plain, pl, flight + n) == 0;
            flight_len = n + CMT_P2P_SC_SEALED_FRAME_SIZE;
            wl = ws_client_frame(wire, 0x82, flight, flight_len);
            wl += ws_client_frame(wire + wl, 0x88, close_body, sizeof(close_body));
            /* ONE write: the final AUTHSIG frame, the data frame behind it
             * and the Close arrive together while VERIFY is outstanding. */
            ok = ok && send_all(w.fd, wire, wl) == 0;
        }
        free(flight);
        free(wire);
    }
    for (int i = 0; ok && i < MAX_ROUNDS && g_srv.disconnected == 0; i++)
        nodus_tcp_poll(&g_srv.tcp, 1);
    if (ok && g_srv.sessions == 1 && g_srv.peer_ok == 1 && g_srv.frames == 1 &&
        g_srv.rx_len == 12 && memcmp(g_srv.rx, "behind-close", 12) == 0 &&
        g_srv.frames_at_session == 0 &&       /* on_session came BEFORE the frame */
        g_srv.disconnected == 1 && g_srv.frames_at_close == 1) PASS();
    else FAIL("data lost, dispatched before on_session, or the connection stayed open");

    if (w.fd > 0) close(w.fd);
    if (w.m != NULL) cmt_p2p_sc_clear(w.m);
    free(w.m);
    free(w.rx);
    free(w.plain);
    side_close(&g_srv);
}

/* ══ 12: enable only on a connection that never carried a byte ═════ */

static void test_enable_dirty_conn(void)
{
    nodus_tcp_sc_cfg_t cfg;
    nodus_tcp_conn_t *c1, *c2;
    uint8_t x = 7;
    int ok;

    TEST("enable refused after I/O started, and on leftover auth state");
    side_init(&g_srv);
    side_init(&g_cli);
    cfg_fill(&cfg, CMT_P2P_SC_ROLE_INITIATOR, &CMT_P2P_SC_PROFILE_CLIENT, g_b, &g_a->node_id);
    nodus_tcp_listen(&g_srv.tcp, "127.0.0.1", 0);
    c1 = nodus_tcp_connect(&g_cli.tcp, "127.0.0.1", g_srv.tcp.port);
    for (int i = 0; c1 != NULL && i < MAX_ROUNDS && c1->state != NODUS_CONN_CONNECTED; i++)
        poll_both();
    /* Plain bytes written: the (now empty) buffers prove nothing. */
    ok = c1 != NULL && c1->state == NODUS_CONN_CONNECTED && nodus_tcp_send(c1, &x, 1) == 0;
    for (int i = 0; ok && i < 50; i++)
        poll_both();
    ok = ok && c1->io_started && c1->wlen == 0 && nodus_tcp_sc_enable(&g_cli.tcp, c1, &cfg) == -1;

    c2 = nodus_tcp_connect(&g_cli.tcp, "127.0.0.1", g_srv.tcp.port);
    ok = ok && c2 != NULL && !c2->io_started;
    if (ok) {
        c2->auth_state = NODUS_CONN_AUTH_HELLO_SENT;
        ok = nodus_tcp_sc_enable(&g_cli.tcp, c2, &cfg) == -1;
        c2->auth_state = NODUS_CONN_AUTH_NONE;
        c2->peer_id_set = true;
        ok = ok && nodus_tcp_sc_enable(&g_cli.tcp, c2, &cfg) == -1;
        c2->peer_id_set = false;
        c2->session_token[3] = 1;
        ok = ok && nodus_tcp_sc_enable(&g_cli.tcp, c2, &cfg) == -1;
        c2->session_token[3] = 0;
        /* ... and with all of that cleared the same connection is eligible. */
        ok = ok && nodus_tcp_sc_enable(&g_cli.tcp, c2, &cfg) == 0;
    }
    if (ok) PASS(); else FAIL("a used connection was accepted, or a clean one refused");
    side_close(&g_cli);
    side_close(&g_srv);
}

/* ══ 13: level-triggered transport (a blocked conn leaves the read set) ══ */

static void test_level_triggered(void)
{
    uint8_t *big = (uint8_t *)malloc(100000);
    int ok;

    TEST("level-triggered transports: handshake + frames both ways still complete");
    g_level = true;
    ok = big != NULL && pair_up(&CMT_P2P_SC_PROFILE_CLIENT, &CMT_P2P_SC_PROFILE_CLIENT, NULL) == 0 &&
         pump_until(&g_srv.sessions, 1, MAX_ROUNDS) && pump_until(&g_cli.sessions, 1, MAX_ROUNDS);
    if (ok) {
        for (size_t i = 0; i < 100000; i++) big[i] = (uint8_t)(i * 7u + (i >> 8));
        ok = send_and_check(&g_cli, &g_srv, big, 100000) &&
             send_and_check(&g_srv, &g_cli, big, 100000) &&
             g_srv.disconnected == 0 && g_cli.disconnected == 0;
    }
    if (ok) PASS(); else FAIL("level-triggered pair did not complete");
    pair_down();
    g_level = false;
    free(big);
}

/* ══ main ════════════════════════════════════════════════════════════ */

static nodus_identity_t *new_identity(void)
{
    nodus_identity_t *id = (nodus_identity_t *)calloc(1, sizeof(*id));

    if (id == NULL || nodus_identity_generate(id) != 0 || !id->has_mlkem) {
        free(id);
        return NULL;
    }
    return id;
}

int main(void)
{
    printf("nodus_tcp SecretConnection layer (DHT v2 3b-1)\n");
    g_a = new_identity();
    g_b = new_identity();
    g_c = new_identity();
    if (g_a == NULL || g_b == NULL || g_c == NULL) {
        printf("  identity generation failed\n");
        return 1;
    }

    test_matched_pair("CLIENT profile / 0x0C", &CMT_P2P_SC_PROFILE_CLIENT);
    test_matched_pair("NODE profile / 0x0D", &CMT_P2P_SC_PROFILE_NODE);
    test_mixed_profiles();
    test_wrong_pin();
    test_enable_refusals();
    test_plain_frame_before_session();
    test_full_queue();
    test_stale_completion();
    test_websocket();
    test_ws_close_behind_data();
    test_enable_dirty_conn();
    test_level_triggered();
    test_layer_off_bytes();

    free(g_a);
    free(g_b);
    free(g_c);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
