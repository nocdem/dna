/**
 * @file nodus/tests/test_p2p_switch.c
 * @brief Tests for shared/dnac/cmt_p2p_{netaddr,nodeinfo,peer,transport,
 *        switch} — cometbft @709fd12b p2p/netaddress.go, key.go,
 *        errors.go, node_info.go, peer.go, peer_set.go, conn_set.go,
 *        transport.go and switch.go ported to C (fleet P2P-PORT, F3).
 *
 * Governing: docs/plans/2026-09-26-p2p-port-design.md §1, §2, §4, §5
 * (R-P2P-3, -7, -8, -14, -17, -23 … -32), §6;
 * docs/plans/decisions/2026-09-26-witness-port-session.md (K2);
 * docs/plans/2026-09-26-witness-port-session-design.md §2R3 N2, N5,
 * §2R4 P2, P3.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · netaddress: "id@ip:port" parses (protocol prefix, IPv6 in brackets);
 *     no-ID / bad-ID / bad-port / host-name inputs get the reference's
 *     error types (a host name is ErrNetAddressLookup — R-P2P-24);
 *     String / DialString / Equals / Same; Valid / Routable / Local and
 *     the RFC ranges; Go's IPv4 leading-zero refusal and RFC 5952 IPv6
 *     formatting; the ID is hex(SHA3-512(pk)[0..31]) — the nodus node_id
 *     prefix.
 *   · NodeInfo: the empty message is `0a 00 42 00` (both embedded
 *     messages always written) and a filled one is byte-exact to the
 *     generated encoder's field order; unmarshal round-trips, skips an
 *     unknown field, lets the last string win and MERGES a repeated
 *     ProtocolVersion; Validate's refusals (moniker empty / all spaces /
 *     a tab, version with a tab, 17 channels, a duplicate channel,
 *     tx_index, a bad listen address); CompatibleWith refuses another
 *     Block version, another network, no common channel, accepts when we
 *     list no channel — and does NOT look at the P2P version.
 *   · two switches over in-memory pipes with REAL ML-DSA-87 / ML-KEM-1024
 *     keys: handshake, NodeInfo exchange (the peer's moniker arrives),
 *     reactor messages both ways on a test channel (one of them split
 *     over several sealed frames), outbound / inbound flags, jobs in the
 *     right class (dialer OUTBOUND, acceptor INBOUND).
 *   · refusals: another chain id (at the secret connection, N9); the same
 *     chain id but another NodeInfo network (CompatibleWith); a peer on
 *     P2P version 7 (the secret connection's HELLO, before any job); a
 *     dial to ID X answered by key Y — aborted with NO Encaps job at all
 *     (R-P2P-14); a duplicate ID (same identity from a second address),
 *     also when that identity is bonded; a duplicate IP (and admitted
 *     with `allow_duplicate_ip`); an inbound handshake whose job queue is
 *     full is closed (§2R4 P3).
 *   · the listener limit refuses in `accept` before anything is
 *     allocated, and the configured unconditional IDs and the bonded
 *     count each raise it; a bonded ID is admitted after authentication
 *     when the unbonded inbound slots are full (K2), and NumPeers does
 *     not count it.
 *   · the handshake deadline: alive at 2.999 s, closed at 3.000 s on both
 *     sides (fake clock).
 *   · the SECOND 3 s window (transport.go:447 / :546): against a raw peer
 *     that completes the secret connection and never sends its NodeInfo,
 *     the connection's deadline is re-armed at the instant the secret
 *     connection completed, it is alive at +2.999 s and closed at
 *     +3.000 s — as acceptor and as dialer.
 *   · a dial to an address with no ID (or a malformed one) is refused by
 *     the transport and the switch before the host is asked to connect
 *     and before any job (R-P2P-33).
 *   · a job result whose generation is stale (its connection timed out
 *     and a NEW connection took the slot) is discarded, and the new
 *     connection completes (R-P2P-3 / N2).
 *   · StopPeerForError from a reactor's Receive removes the peer from the
 *     reactors (with the reason) and the peer set, on both ends.
 *   · a persistent peer is redialed at once, then every 5 s + jitter
 *     (fixed rand 500 ms → 5.5 s) for 20 attempts, then with the
 *     backoff 3^i s + jitter, and reconnects when the peer is back.
 *   · a cross-dial ends with ONE connection on both ends — the one dialed
 *     by the lower ID (R-P2P-23).
 *   · the nodus 4004 SOCKET HOST (nodus_p2p_io, nodus_witness_p2p.c) reads
 *     and writes CONTINUOUSLY within one pass (R-P2P-17, the reference's
 *     recvRoutine / sendRoutine, connection.go:590-694 / :429-507): one
 *     256 KiB reactor message crosses real loopback TCP between two
 *     switches in <= 8 counted passes, byte-exact, and the connection
 *     survives. The former io_read took at most one 4-frame read buffer
 *     per pass and would need >= 64 passes (derived at the case), so this
 *     bound fails it.
 *   · the BLOCKED RECEIVE (transport host row `may_receive`, the single-
 *     loop form of consensus/reactor.go:324/:330/:350 blocking on a full
 *     queue): while the receiver's row answers false for 10 counted
 *     passes, nothing is delivered, its connection buffers stay EMPTY (no
 *     socket byte was read) and both peers stay connected; once it answers
 *     true the 256 KiB message arrives byte-exact within the same <= 8
 *     pass bound. It does NOT prove the witness host's own predicate
 *     (h_may_receive over cmt_cs's peer queue) — no state machine runs
 *     here.
 *   · RECEIVE FAIRNESS (red-team H3): with a modelled 2-entry queue
 *     drained between passes, two peers flooding one receiver lose no
 *     message to a full queue (the room-for-ONE gate is asked before
 *     every message), every message arrives once in its sender's order,
 *     and the lower transport slot never gets more than two deliveries in
 *     a row while the higher one waits (one message per peer per pump
 *     once near full; the tick starts just past the slot last served).
 *     The queue and its near-full rule are the test's model of the
 *     witness host's rows, not cmt_cs itself; the socket host's own walk
 *     (nodus_p2p_io_pump's last-served start) is not driven here.
 *
 * WHAT IT REQUIRES: nothing beyond a default nodus build (no compile
 * flags, no environment). The socket-host case needs loopback TCP on
 * 127.0.0.1 (two ephemeral listening ports) and Linux epoll; elsewhere it
 * prints SKIPPED (not a pass). WHAT IT
 * LEAVES BEHIND: nothing (no files, no threads; the socket-host case's
 * sockets are closed by world_reset).
 *
 * HOW IT CAN LIE: time is a FAKE clock and the network is in-memory
 * pipes driven in a fixed order, so the cases prove the ORDER and the
 * thresholds of the timers and the admission rules, not behaviour under
 * real sockets, real latency or a real worker thread (jobs run inline
 * between ticks). The socket-host case is the exception to "in-memory":
 * its pass count depends on the kernel delivering loopback segments
 * while the receiver reads (the TCP window update its recv(2) sends lets
 * the sender's queued segments through at once, normally inside the same
 * pass). A host whose loopback delivery is deferred (softirq pushed to
 * ksoftirqd under load) or whose TCP buffers are unusually small can need
 * more passes and then FAILS the bound — it cannot pass for the wrong
 * reason: the old per-pass cap cannot deliver more than 8 × 4096 bytes in
 * 8 passes. It counts passes, not time; the fake clock steps one flush
 * throttle (100 ms) per pass, so it proves nothing about the recv / send
 * flowrate at the real clock or at 32 peers. The NodeInfo vectors are hand-derived from
 * types.pb.go's MarshalToSizedBuffer, not taken from a live cometbft
 * peer. The IP-parsing cases follow Go 1.21.5's standard library (the
 * local toolchain), not the reference's go.mod 1.22.11.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_netaddr.h"
#include "dnac/cmt_p2p_nodeinfo.h"
#include "dnac/cmt_p2p_peer.h"
#include "dnac/cmt_p2p_transport.h"
#include "dnac/cmt_p2p_switch.h"
#include "dnac/cmt_block.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#ifdef __linux__
#include "witness/nodus_witness_p2p.h"      /* the 4004 socket host (epoll) */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef __linux__
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)
#define CHECK(c)   do { if (!(c)) { ok = 0; printf("\n    check failed: %s (line %d)", #c, __LINE__); } } while (0)

static int passed = 0;
static int failed = 0;

#define MS (1000LL * 1000)

static int64_t g_now = 1000 * MS;
static int64_t g_rand_val = 0;

static const uint8_t CHAIN_A[32] = { 0x9a, 0xbf, 0x84, 0x37, 0xe7, 0x29 };
static const uint8_t CHAIN_B[32] = { 0x11, 0x22, 0x33 };

#define TEST_CH 0x40

/* ══ the in-memory network ═══════════════════════════════════════════ */

typedef struct {
    uint8_t *b;
    size_t   len;
    size_t   cap;
} pipe_t;

static void pipe_push(pipe_t *p, const uint8_t *b, size_t n)
{
    if (n == 0) {
        return;
    }
    if (p->len + n > p->cap) {
        size_t ncap = p->cap == 0 ? 65536 : p->cap;

        while (ncap < p->len + n) {
            ncap *= 2;
        }
        p->b = (uint8_t *)realloc(p->b, ncap);
        p->cap = ncap;
    }
    memcpy(p->b + p->len, b, n);
    p->len += n;
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

typedef struct node node_t;

#define MAX_NODES   10
#define MAX_WIRES   64
#define MAX_PENDING 32
#define JOBQ        16
#define MAX_RMSGS   32

typedef struct {
    bool     used;
    node_t  *a;            /* dialer   */
    int      a_slot;
    uint64_t a_gen;
    bool     a_open;
    bool     a_eof;        /* a was told the other side closed */
    node_t  *b;            /* acceptor */
    int      b_slot;
    uint64_t b_gen;
    bool     b_open;
    bool     b_eof;
    pipe_t   ab;
    pipe_t   ba;
} wire_t;

typedef struct {
    bool              used;
    node_t           *src;
    int               slot;
    uint64_t          gen;
    cmt_p2p_netaddr_t to;
} pending_t;

typedef struct {
    uint8_t  ch;
    char     src[CMT_P2P_ID_CAP];
    size_t   len;
    uint8_t *b;
} rmsg_t;

struct node {
    const char       *name;
    nodus_identity_t  id;
    char              idhex[CMT_P2P_ID_CAP];
    cmt_p2p_ip_t      ip;
    uint16_t          port;
    cmt_p2p_node_info_t *ni;
    cmt_p2p_transport_t  t;
    cmt_p2p_switch_t     sw;
    bool up;
    bool run_jobs;
    bool frozen;
    cmt_p2p_hs_job_t *jobs[2][JOBQ];
    int  njobs[2];
    int  job_cap[2];
    int  jobs_seen_kind[5];
    int  jobs_seen_class[2];
    int  n_dials;
    int64_t dial_times[64];
    const char *bonded[4];
    int  n_bonded;
    /* the test reactor */
    rmsg_t msgs[MAX_RMSGS];
    int  n_msgs;
    int  n_add;
    int  n_remove;
    int  last_remove_reason;
    /* the transport's `may_receive` answers !block_recv (false = every
     * test before the blocked-receive case) */
    bool block_recv;
    /* a model of the consensus peer queue behind `may_receive` /
     * `recv_near_full` (the H3 fairness case; q_cap 0 = no queue): every
     * TEST_CH message the reactor receives takes one entry; q_overflow
     * counts a message that arrived with the queue already full — one
     * the witness host would have DROPPED. */
    int  q_cap;
    int  q_len;
    int  q_overflow;
#ifdef __linux__
    /* non-NULL: the node's bytes go through the nodus 4004 socket host
     * over real loopback TCP instead of the in-memory pipes */
    nodus_p2p_io_t *io;
#endif
};

static node_t   *g_nodes[MAX_NODES];
static int       g_n_nodes;
static uint16_t  g_next_eph = 40000;      /* ephemeral ports, unique per run */
static wire_t    g_wires[MAX_WIRES];
static pending_t g_pending[MAX_PENDING];

static node_t *find_node(const cmt_p2p_ip_t *ip, uint16_t port)
{
    int i;

    for (i = 0; i < g_n_nodes; i++) {
        if (g_nodes[i] != NULL && g_nodes[i]->port == port &&
            cmt_p2p_ip_equal(&g_nodes[i]->ip, ip)) {
            return g_nodes[i];
        }
    }
    return NULL;
}

/* ── transport host ── */

static int64_t h_now(void *ctx)
{
    (void)ctx;
    return g_now;
}

/* A dial to this address is not wired to a node: the test drives the
 * connection itself against a raw secret connection. */
static struct {
    bool              active;
    cmt_p2p_ip_t      ip;
    uint16_t          port;
    int               slot;
    uint64_t          gen;
} g_raw_dial;

static int h_dial(void *ctx, int slot, uint64_t gen, const cmt_p2p_netaddr_t *addr,
                  uint64_t *handle)
{
    node_t *n = (node_t *)ctx;
    node_t *to = find_node(&addr->ip, addr->port);
    int i;

    if (n->n_dials < 64) {
        n->dial_times[n->n_dials] = g_now;
    }
    n->n_dials++;
    *handle = 0;
#ifdef __linux__
    if (n->io != NULL) {
        return nodus_p2p_io_dial(n->io, slot, gen, addr);
    }
#endif
    if (g_raw_dial.active && addr->port == g_raw_dial.port &&
        cmt_p2p_ip_equal(&addr->ip, &g_raw_dial.ip)) {
        g_raw_dial.slot = slot;
        g_raw_dial.gen = gen;
        return 0;
    }
    if (to == NULL || !to->up) {
        return -1;                          /* connection refused at once */
    }
    for (i = 0; i < MAX_PENDING; i++) {
        if (!g_pending[i].used) {
            g_pending[i].used = true;
            g_pending[i].src = n;
            g_pending[i].slot = slot;
            g_pending[i].gen = gen;
            g_pending[i].to = *addr;
            return 0;
        }
    }
    return -1;
}

static void h_close(void *ctx, int slot, uint64_t gen, uint64_t handle)
{
    node_t *n = (node_t *)ctx;
    int i;

    (void)handle;
#ifdef __linux__
    if (n->io != NULL) {
        nodus_p2p_io_close(n->io, slot, gen);
        return;
    }
#endif
    for (i = 0; i < MAX_WIRES; i++) {
        wire_t *w = &g_wires[i];

        if (!w->used) {
            continue;
        }
        if (w->a == n && w->a_slot == slot && w->a_gen == gen) {
            w->a_open = false;
        }
        if (w->b == n && w->b_slot == slot && w->b_gen == gen) {
            w->b_open = false;
        }
    }
    for (i = 0; i < MAX_PENDING; i++) {
        if (g_pending[i].used && g_pending[i].src == n &&
            g_pending[i].slot == slot && g_pending[i].gen == gen) {
            g_pending[i].used = false;
        }
    }
}

static int h_submit(void *ctx, cmt_p2p_hs_job_t *job)
{
    node_t *n = (node_t *)ctx;
    int c = (int)job->job_class;

    if (n->njobs[c] >= n->job_cap[c]) {
        return -1;
    }
    n->jobs[c][n->njobs[c]++] = job;
    n->jobs_seen_kind[job->kind]++;
    n->jobs_seen_class[c]++;
    return 0;
}

/* The transport's `may_receive` row: false while the test "blocks" the
 * node's reactor Receive, or while the modelled queue has no room for
 * ONE message (the witness host's h_may_receive). */
static bool h_may_receive(void *ctx)
{
    const node_t *n = (const node_t *)ctx;

    return !n->block_recv && (n->q_cap == 0 || n->q_len < n->q_cap);
}

/* The transport's `recv_near_full` row, the witness host's rule: fewer
 * free entries than connected peers. */
static bool h_recv_near_full(void *ctx)
{
    const node_t *n = (const node_t *)ctx;

    return n->q_cap > 0 &&
           n->q_cap - n->q_len <
               cmt_p2p_peer_set_size(cmt_p2p_switch_peers(&n->sw));
}

static int h_bonded_count(void *ctx)
{
    return ((node_t *)ctx)->n_bonded;
}

/* ── switch host ── */

static int64_t h_rand(void *ctx, int64_t n)
{
    (void)ctx;
    return g_rand_val < n ? g_rand_val : n - 1;
}

static bool h_is_bonded(void *ctx, const char *id)
{
    node_t *n = (node_t *)ctx;
    int i;

    for (i = 0; i < n->n_bonded; i++) {
        if (strcmp(n->bonded[i], id) == 0) {
            return true;
        }
    }
    return false;
}

/* ── the test reactor ── */

static const cmt_p2p_ch_desc_t TEST_DESCS[] = { { TEST_CH, 1, 10, 0, 0 } };

static const cmt_p2p_ch_desc_t *r_channels(void *ctx, int *n)
{
    (void)ctx;
    *n = 1;
    return TEST_DESCS;
}

static void r_add(void *ctx, cmt_p2p_peer_t *p)
{
    (void)p;
    ((node_t *)ctx)->n_add++;
}

static void r_remove(void *ctx, cmt_p2p_peer_t *p, int reason)
{
    node_t *n = (node_t *)ctx;

    (void)p;
    n->n_remove++;
    n->last_remove_reason = reason;
}

static void r_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch,
                      const uint8_t *msg, size_t len)
{
    node_t *n = (node_t *)ctx;
    rmsg_t *m;

    if (len == 3 && memcmp(msg, "bad", 3) == 0) {
        cmt_p2p_switch_stop_peer_for_error(&n->sw, src, 42);
        return;
    }
    if (n->q_cap > 0) {
        if (n->q_len >= n->q_cap) {
            n->q_overflow++;            /* the host would drop it */
            return;
        }
        n->q_len++;
    }
    if (n->n_msgs >= MAX_RMSGS) {
        return;
    }
    m = &n->msgs[n->n_msgs++];
    m->ch = ch;
    snprintf(m->src, sizeof(m->src), "%s", cmt_p2p_peer_id(src));
    m->len = len;
    m->b = (uint8_t *)malloc(len > 0 ? len : 1);
    if (len > 0) {
        memcpy(m->b, msg, len);
    }
}

/* ── F1 sign / verify through the nodus identity (purpose 0x0A) ── */

static int sc_sign(void *ctx, const uint8_t *msg, size_t len,
                   uint8_t sig_out[CMT_P2P_SC_SIG_SIZE])
{
    node_t *n = (node_t *)ctx;
    nodus_sig_t sig;
    int rc = nodus_sign_session_auth(&sig, msg, len, &n->id.sk);

    memcpy(sig_out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    return rc;
}

static int sc_verify(void *ctx, const uint8_t sig_in[CMT_P2P_SC_SIG_SIZE],
                     const uint8_t *msg, size_t len,
                     const uint8_t pk_in[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_SC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, CMT_P2P_SC_DSA_PK_SIZE);
    return nodus_verify_session_auth(&sig, msg, len, &pk);
}

/* ── node construction ── */

typedef struct {
    const char    *ip;
    uint16_t       port;
    const uint8_t *chain;             /* secret connection (N9)          */
    const uint8_t *ni_chain;          /* NodeInfo network (NULL = chain) */
    int            max_in_transport;  /* LimitListener base               */
    int            n_uncond_cfg;      /* configured unconditional count   */
    int            max_in_switch;
    bool           allow_dup_ip;
    const nodus_identity_t *identity; /* NULL = a fresh one              */
} node_params_t;

static void params_default(node_params_t *p, const char *ip, uint16_t port)
{
    memset(p, 0, sizeof(*p));
    p->ip = ip;
    p->port = port;
    p->chain = CHAIN_A;
    p->max_in_transport = 40;
    p->max_in_switch = 40;
}

static node_t *node_new(const char *name, const node_params_t *prm)
{
    node_t *n = (node_t *)calloc(1, sizeof(node_t));
    cmt_p2p_transport_host_t th;
    cmt_p2p_transport_config_t tc;
    cmt_p2p_switch_host_t sh;
    cmt_p2p_switch_config_t sc;
    cmt_p2p_node_info_params_t nip;
    cmt_p2p_reactor_t r;
    cmt_p2p_netaddr_t laddr;
    char listen[64];
    static const uint8_t chans[] = { TEST_CH };

    if (n == NULL) {
        return NULL;
    }
    n->name = name;
    if (prm->identity != NULL) {
        n->id = *prm->identity;
    } else if (nodus_identity_generate(&n->id) != 0 || !n->id.has_mlkem) {
        free(n);
        return NULL;
    }
    if (cmt_p2p_pubkey_to_id(n->id.pk.bytes, n->idhex) != CMT_OK ||
        !cmt_p2p_ip_parse(prm->ip, strlen(prm->ip), &n->ip)) {
        free(n);
        return NULL;
    }
    n->port = prm->port;
    n->up = true;
    n->run_jobs = true;
    n->job_cap[0] = JOBQ;
    n->job_cap[1] = JOBQ;

    n->ni = (cmt_p2p_node_info_t *)calloc(1, sizeof(*n->ni));
    snprintf(listen, sizeof(listen), "%s:%u", prm->ip, (unsigned)prm->port);
    memset(&nip, 0, sizeof(nip));
    nip.block_version = CMT_BLOCK_PROTOCOL;
    nip.node_id = n->idhex;
    nip.chain_id = prm->ni_chain != NULL ? prm->ni_chain : prm->chain;
    nip.version = "0.19.80";
    nip.channels = chans;
    nip.n_channels = 1;
    nip.moniker = name;
    nip.tx_index = "off";
    nip.rpc_address = "";
    nip.listen_addr = listen;
    if (n->ni == NULL || cmt_p2p_node_info_make(n->ni, &nip) != CMT_P2P_ERR_NONE) {
        free(n->ni);
        free(n);
        return NULL;
    }

    memset(&th, 0, sizeof(th));
    th.ctx = n;
    th.now_ns = h_now;
    th.dial = h_dial;
    th.close = h_close;
    th.submit_job = h_submit;
    th.bonded_count = h_bonded_count;
    th.may_receive = h_may_receive;
    th.recv_near_full = h_recv_near_full;
    memset(&tc, 0, sizeof(tc));
    tc.dsa_pk = n->id.pk.bytes;
    tc.kem_pk = n->id.mlkem_pk;
    tc.kem_sk = n->id.mlkem_sk;
    tc.sc_host.ctx = n;
    tc.sc_host.sign = sc_sign;
    tc.sc_host.verify = sc_verify;
    tc.chain_id = prm->chain;
    tc.node_info = n->ni;
    cmt_p2p_mconn_p2p_default_config(&tc.mconn);
    tc.max_num_inbound_peers = prm->max_in_transport;
    tc.n_unconditional_ids = prm->n_uncond_cfg;
    tc.allow_duplicate_ip = prm->allow_dup_ip;
    if (cmt_p2p_transport_init(&n->t, &th, &tc) != CMT_OK) {
        free(n->ni);
        free(n);
        return NULL;
    }
    laddr = cmt_p2p_netaddr_new_ip_port(&n->ip, n->port);
    memcpy(laddr.id, n->idhex, sizeof(laddr.id));
    cmt_p2p_transport_listen(&n->t, &laddr);

    memset(&sh, 0, sizeof(sh));
    sh.ctx = n;
    sh.rand_int63n = h_rand;
    sh.is_bonded = h_is_bonded;
    cmt_p2p_switch_default_config(&sc);
    sc.max_num_inbound_peers = prm->max_in_switch;
    sc.allow_duplicate_ip = prm->allow_dup_ip;
    if (cmt_p2p_switch_init(&n->sw, &sc, &n->t, &sh) != CMT_OK) {
        cmt_p2p_transport_free(&n->t);
        free(n->ni);
        free(n);
        return NULL;
    }
    memset(&r, 0, sizeof(r));
    r.name = "TEST";
    r.ctx = n;
    r.get_channels = r_channels;
    r.add_peer = r_add;
    r.remove_peer = r_remove;
    r.receive = r_receive;
    if (cmt_p2p_switch_add_reactor(&n->sw, &r) != CMT_OK ||
        cmt_p2p_switch_start(&n->sw) != CMT_OK) {
        cmt_p2p_switch_free(&n->sw);
        cmt_p2p_transport_free(&n->t);
        free(n->ni);
        free(n);
        return NULL;
    }
    g_nodes[g_n_nodes++] = n;
    return n;
}

/* Hand every held job back (as failed) so the transport frees it. */
static void drop_jobs(node_t *n)
{
    int c, i;

    for (c = 0; c < 2; c++) {
        for (i = 0; i < n->njobs[c]; i++) {
            n->jobs[c][i]->rc = -1;
            (void)cmt_p2p_transport_job_done(&n->t, n->jobs[c][i]);
        }
        n->njobs[c] = 0;
    }
}

static void world_reset(void)
{
    int i;

    for (i = 0; i < g_n_nodes; i++) {
        node_t *n = g_nodes[i];
        int k;

        drop_jobs(n);
        cmt_p2p_switch_free(&n->sw);
        cmt_p2p_transport_free(&n->t);
#ifdef __linux__
        if (n->io != NULL) {
            /* after the transport: its frees close sockets through h_close */
            nodus_p2p_io_free(n->io);
            free(n->io);
        }
#endif
        for (k = 0; k < n->n_msgs; k++) {
            free(n->msgs[k].b);
        }
        free(n->ni);
        free(n);
        g_nodes[i] = NULL;
    }
    g_n_nodes = 0;
    for (i = 0; i < MAX_WIRES; i++) {
        free(g_wires[i].ab.b);
        free(g_wires[i].ba.b);
    }
    memset(g_wires, 0, sizeof(g_wires));
    memset(g_pending, 0, sizeof(g_pending));
    memset(&g_raw_dial, 0, sizeof(g_raw_dial));
    g_rand_val = 0;
}

static void run_jobs(node_t *n)
{
    int c;

    if (!n->run_jobs) {
        return;
    }
    for (c = 1; c >= 0; c--) {                  /* outbound class first */
        while (n->njobs[c] > 0) {
            cmt_p2p_hs_job_t *j = n->jobs[c][0];

            memmove(&n->jobs[c][0], &n->jobs[c][1],
                    (size_t)(n->njobs[c] - 1) * sizeof(cmt_p2p_hs_job_t *));
            n->njobs[c]--;
            (void)cmt_p2p_hs_job_run(j);
            (void)cmt_p2p_transport_job_done(&n->t, j);
        }
    }
}

static void move_bytes(node_t *from, int fs, uint64_t fg, bool from_open,
                       pipe_t *p, node_t *to, int ts, uint64_t tg, bool to_open)
{
    if (from_open && !from->frozen) {
        size_t len = 0;
        const uint8_t *o = cmt_p2p_transport_write_buf(&from->t, fs, fg, &len);

        if (o != NULL && len > 0) {
            pipe_push(p, o, len);
            cmt_p2p_transport_write_done(&from->t, fs, fg, len);
        }
    }
    if (to_open && !to->frozen && p->len > 0) {
        size_t room = 0;
        uint8_t *in = cmt_p2p_transport_read_buf(&to->t, ts, tg, &room);

        if (in != NULL && room > 0) {
            size_t k = p->len < room ? p->len : room;

            memcpy(in, p->b, k);
            pipe_pop(p, k);
            cmt_p2p_transport_read_done(&to->t, ts, tg, k);
        }
    }
}

static void net_step(void)
{
    int i;

    /* connects */
    for (i = 0; i < MAX_PENDING; i++) {
        pending_t *pd = &g_pending[i];
        node_t *to;
        int slot = -1, w, rc;
        uint64_t gen = 0;
        uint16_t eph;

        if (!pd->used) {
            continue;
        }
        to = find_node(&pd->to.ip, pd->to.port);
        if (to == NULL || !to->up) {
            pd->used = false;
            cmt_p2p_transport_conn_failed(&pd->src->t, pd->slot, pd->gen);
            continue;
        }
        if (!cmt_p2p_transport_can_accept(&to->t)) {
            continue;                                   /* the backlog */
        }
        eph = g_next_eph++;
        rc = cmt_p2p_transport_accept(&to->t, &pd->src->ip, eph, 0, &slot, &gen);
        pd->used = false;
        if (rc != CMT_P2P_ERR_NONE) {
            cmt_p2p_transport_conn_failed(&pd->src->t, pd->slot, pd->gen);
            continue;
        }
        for (w = 0; w < MAX_WIRES; w++) {
            if (!g_wires[w].used) {
                break;
            }
        }
        if (w == MAX_WIRES) {
            continue;
        }
        g_wires[w].used = true;
        g_wires[w].a = pd->src;
        g_wires[w].a_slot = pd->slot;
        g_wires[w].a_gen = pd->gen;
        g_wires[w].a_open = true;
        g_wires[w].a_eof = false;
        g_wires[w].b = to;
        g_wires[w].b_slot = slot;
        g_wires[w].b_gen = gen;
        g_wires[w].b_open = true;
        g_wires[w].b_eof = false;
        g_wires[w].ab.len = 0;
        g_wires[w].ba.len = 0;
        cmt_p2p_transport_dial_connected(&pd->src->t, pd->slot, pd->gen,
                                         &to->ip, to->port);
    }
    for (i = 0; i < g_n_nodes; i++) {
        run_jobs(g_nodes[i]);
    }
    for (i = 0; i < MAX_WIRES; i++) {
        wire_t *w = &g_wires[i];

        if (!w->used) {
            continue;
        }
        move_bytes(w->a, w->a_slot, w->a_gen, w->a_open, &w->ab,
                   w->b, w->b_slot, w->b_gen, w->b_open);
        move_bytes(w->b, w->b_slot, w->b_gen, w->b_open, &w->ba,
                   w->a, w->a_slot, w->a_gen, w->a_open);
        /* EOF once the closed side's bytes are all delivered */
        if (!w->a_open && w->b_open && !w->b_eof && w->ab.len == 0) {
            w->b_eof = true;
            cmt_p2p_transport_conn_failed(&w->b->t, w->b_slot, w->b_gen);
        }
        if (!w->b_open && w->a_open && !w->a_eof && w->ba.len == 0) {
            w->a_eof = true;
            cmt_p2p_transport_conn_failed(&w->a->t, w->a_slot, w->a_gen);
        }
        if (!w->a_open && !w->b_open) {
            w->used = false;
        }
    }
    for (i = 0; i < g_n_nodes; i++) {
        cmt_p2p_switch_tick(&g_nodes[i]->sw);
    }
}

static void run(int rounds, int64_t step_ns)
{
    int i;

    for (i = 0; i < rounds; i++) {
        g_now += step_ns;
        net_step();
    }
}

static cmt_p2p_netaddr_t addr_of(const node_t *n)
{
    cmt_p2p_netaddr_t a = cmt_p2p_netaddr_new_ip_port(&n->ip, n->port);

    memcpy(a.id, n->idhex, sizeof(a.id));
    return a;
}

static int n_peers(const node_t *n)
{
    return cmt_p2p_peer_set_size(cmt_p2p_switch_peers(&n->sw));
}

static cmt_p2p_peer_t *peer_of(node_t *n, const node_t *other)
{
    return cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&n->sw), other->idhex);
}

static int live_slots(const node_t *n)
{
    int i, k = 0;

    for (i = 0; i < n->t.n_slots; i++) {
        if (n->t.slots[i] != NULL) {
            k++;
        }
    }
    return k;
}

/* ══ netaddress ══════════════════════════════════════════════════════ */

static const char ID64[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static void test_netaddr_parse(void)
{
    cmt_p2p_netaddr_t a, b;
    char s[CMT_P2P_NETADDR_STR_MAX], in[256];
    int ok = 1;

    TEST("netaddress: NewNetAddressString, String, DialString, errors");
    snprintf(in, sizeof(in), "%s@1.2.3.4:26656", ID64);
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &a) == CMT_P2P_ERR_NONE);
    CHECK(cmt_p2p_netaddr_string(&a, s, sizeof(s)) > 0 && strcmp(s, in) == 0);
    CHECK(cmt_p2p_netaddr_dial_string(&a, s, sizeof(s)) > 0 &&
          strcmp(s, "1.2.3.4:26656") == 0);
    snprintf(in, sizeof(in), "tcp://%s@[2001:db8:0:0:0:0:0:1]:80", ID64);
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &b) == CMT_P2P_ERR_NONE);
    CHECK(cmt_p2p_netaddr_dial_string(&b, s, sizeof(s)) > 0 &&
          strcmp(s, "[2001:db8::1]:80") == 0);
    CHECK(cmt_p2p_netaddr_new_string("1.2.3.4:26656", 13, &b) ==
          CMT_P2P_ERR_NETADDR_NO_ID);
    snprintf(in, sizeof(in), "%s@a@1.2.3.4:1", ID64);
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &b) == CMT_P2P_ERR_NETADDR_NO_ID);
    CHECK(cmt_p2p_netaddr_new_string("abc@1.2.3.4:1", 13, &b) ==
          CMT_P2P_ERR_NETADDR_INVALID);
    snprintf(in, sizeof(in), "%s@1.2.3.4:65536", ID64);
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &b) == CMT_P2P_ERR_NETADDR_INVALID);
    snprintf(in, sizeof(in), "%s@1.2.3.4:+1", ID64);
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &b) == CMT_P2P_ERR_NETADDR_INVALID);
    snprintf(in, sizeof(in), "%s@1.2.3.4", ID64);
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &b) == CMT_P2P_ERR_NETADDR_INVALID);
    snprintf(in, sizeof(in), "%s@:80", ID64);
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &b) == CMT_P2P_ERR_NETADDR_INVALID);
    snprintf(in, sizeof(in), "%s@node.example.org:80", ID64);
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &b) == CMT_P2P_ERR_NETADDR_LOOKUP);
    snprintf(in, sizeof(in), "%s@01.2.3.4:80", ID64);   /* leading zero */
    CHECK(cmt_p2p_netaddr_new_string(in, strlen(in), &b) == CMT_P2P_ERR_NETADDR_LOOKUP);
    /* uppercase hex validates (hex.DecodeString) */
    CHECK(cmt_p2p_validate_id("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
                              64) == CMT_P2P_ERR_NONE);
    CHECK(cmt_p2p_validate_id(ID64, 63) == CMT_P2P_ERR_NETADDR_INVALID);
    CHECK(cmt_p2p_validate_id("", 0) == CMT_P2P_ERR_NETADDR_INVALID);
    /* Equals / Same */
    snprintf(in, sizeof(in), "%s@1.2.3.4:26656", ID64);
    (void)cmt_p2p_netaddr_new_string(in, strlen(in), &b);
    CHECK(cmt_p2p_netaddr_equals(&a, &b));
    b.port = 1;
    CHECK(!cmt_p2p_netaddr_equals(&a, &b) && cmt_p2p_netaddr_same(&a, &b));
    b.id[0] = '\0';
    CHECK(!cmt_p2p_netaddr_same(&a, &b));
    b.port = 26656;
    CHECK(cmt_p2p_netaddr_same(&a, &b));
    if (ok) {
        PASS();
    } else {
        FAIL("netaddr parse");
    }
}

static void test_netaddr_ranges(void)
{
    cmt_p2p_netaddr_t a;
    cmt_p2p_ip_t ip;
    char s[CMT_P2P_IP_STR_MAX];
    int ok = 1;

#define SETIP(str) do { memset(&a, 0, sizeof(a)); memcpy(a.id, ID64, 65); \
        CHECK(cmt_p2p_ip_parse(str, strlen(str), &a.ip)); a.port = 1; } while (0)

    TEST("netaddress: Valid / Routable / Local / RFC ranges / IP strings");
    SETIP("8.8.8.8");
    CHECK(cmt_p2p_netaddr_valid(&a) == CMT_P2P_ERR_NONE && cmt_p2p_netaddr_routable(&a));
    SETIP("10.1.2.3");
    CHECK(cmt_p2p_netaddr_rfc1918(&a) && !cmt_p2p_netaddr_routable(&a));
    SETIP("172.31.0.1");
    CHECK(cmt_p2p_netaddr_rfc1918(&a));
    SETIP("172.32.0.1");
    CHECK(!cmt_p2p_netaddr_rfc1918(&a));
    SETIP("192.168.9.9");
    CHECK(cmt_p2p_netaddr_rfc1918(&a));
    SETIP("169.254.1.1");
    CHECK(cmt_p2p_netaddr_rfc3927(&a) && !cmt_p2p_netaddr_routable(&a));
    SETIP("127.0.0.1");
    CHECK(cmt_p2p_netaddr_local(&a) && !cmt_p2p_netaddr_routable(&a) &&
          cmt_p2p_netaddr_valid(&a) == CMT_P2P_ERR_NONE);
    SETIP("0.1.2.3");
    CHECK(cmt_p2p_netaddr_local(&a));
    SETIP("0.0.0.0");
    CHECK(cmt_p2p_netaddr_valid(&a) == CMT_P2P_ERR_NETADDR_INVALID);
    SETIP("255.255.255.255");
    CHECK(cmt_p2p_netaddr_valid(&a) == CMT_P2P_ERR_NETADDR_INVALID);
    SETIP("2001:db8::5");
    CHECK(cmt_p2p_netaddr_rfc3849(&a) && cmt_p2p_netaddr_valid(&a) != CMT_P2P_ERR_NONE);
    SETIP("fe80::1");
    CHECK(cmt_p2p_netaddr_rfc4862(&a) && !cmt_p2p_netaddr_routable(&a));
    SETIP("fc00::1");
    CHECK(cmt_p2p_netaddr_rfc4193(&a));
    SETIP("fd87:d87e:eb43::1");
    CHECK(cmt_p2p_netaddr_onion_cat_tor(&a) && cmt_p2p_netaddr_rfc4193(&a));
    SETIP("2001:10::1");
    CHECK(cmt_p2p_netaddr_rfc4843(&a));
    SETIP("2002::1");
    CHECK(cmt_p2p_netaddr_rfc3964(&a));
    SETIP("2001::1");
    CHECK(cmt_p2p_netaddr_rfc4380(&a));
    SETIP("64:ff9b::1.2.3.4");
    CHECK(cmt_p2p_netaddr_rfc6052(&a));
    SETIP("::1");
    CHECK(cmt_p2p_netaddr_local(&a));
    SETIP("::");
    CHECK(cmt_p2p_netaddr_valid(&a) == CMT_P2P_ERR_NETADDR_INVALID);
    SETIP("2a01:4f8::1");
    CHECK(cmt_p2p_netaddr_routable(&a));
    a.id[5] = 'x';
    CHECK(cmt_p2p_netaddr_valid(&a) == CMT_P2P_ERR_NETADDR_INVALID);
    /* ParseIP / String */
    CHECK(cmt_p2p_ip_parse("::ffff:1.2.3.4", 14, &ip) &&
          cmt_p2p_ip_string(&ip, s, sizeof(s)) > 0 && strcmp(s, "1.2.3.4") == 0);
    CHECK(cmt_p2p_ip_parse("2001:0db8:0000:0000:0001:0000:0000:0001", 39, &ip) &&
          cmt_p2p_ip_string(&ip, s, sizeof(s)) > 0 && strcmp(s, "2001:db8::1:0:0:1") == 0);
    CHECK(cmt_p2p_ip_parse("1:0:1:0:1:0:1:0", 15, &ip) &&
          cmt_p2p_ip_string(&ip, s, sizeof(s)) > 0 && strcmp(s, "1:0:1:0:1:0:1:0") == 0);
    CHECK(!cmt_p2p_ip_parse("1.2.3", 5, &ip));
    CHECK(!cmt_p2p_ip_parse("1.2.3.256", 9, &ip));
    CHECK(!cmt_p2p_ip_parse("fe80::1%eth0", 12, &ip));
    CHECK(!cmt_p2p_ip_parse("1::2::3", 7, &ip));
    CHECK(!cmt_p2p_ip_parse("1:2:3:4:5:6:7:8::", 17, &ip));
    {
        cmt_p2p_ip_t v4a, v4b;

        memset(&v4a, 0, sizeof(v4a));
        v4a.b[0] = 1; v4a.b[1] = 2; v4a.b[2] = 3; v4a.b[3] = 4;
        v4a.len = 4;
        v4b = cmt_p2p_ip_v4(1, 2, 3, 4);
        CHECK(cmt_p2p_ip_equal(&v4a, &v4b));
    }
#undef SETIP
    if (ok) {
        PASS();
    } else {
        FAIL("netaddr ranges");
    }
}

static void test_id_derivation(void)
{
    nodus_identity_t *id = (nodus_identity_t *)calloc(1, sizeof(*id));
    char hex[CMT_P2P_ID_CAP], expect[CMT_P2P_ID_CAP];
    int ok = 1, i;

    TEST("key.go PubKeyToID = hex(SHA3-512(pk)[0..31]) = node_id prefix");
    if (id == NULL || nodus_identity_generate(id) != 0) {
        FAIL("identity");
        free(id);
        return;
    }
    for (i = 0; i < 32; i++) {
        snprintf(expect + 2 * i, 3, "%02x", id->node_id.bytes[i]);
    }
    CHECK(cmt_p2p_pubkey_to_id(id->pk.bytes, hex) == CMT_OK);
    CHECK(strcmp(hex, expect) == 0);
    CHECK(cmt_p2p_validate_id(hex, strlen(hex)) == CMT_P2P_ERR_NONE);
    free(id);
    if (ok) {
        PASS();
    } else {
        FAIL("id");
    }
}

/* ══ NodeInfo ════════════════════════════════════════════════════════ */

static void test_node_info_codec(void)
{
    cmt_p2p_node_info_t *ni = (cmt_p2p_node_info_t *)calloc(1, sizeof(*ni));
    cmt_p2p_node_info_t *back = (cmt_p2p_node_info_t *)calloc(1, sizeof(*back));
    uint8_t buf[512];
    size_t n = 0, len;
    const uint8_t *f;
    static const uint8_t empty[] = { 0x0a, 0x00, 0x42, 0x00 };
    static const uint8_t filled[] = {
        0x0a, 0x04, 0x08, 0x08, 0x10, 0x0b,         /* protocol_version {8, 11} */
        0x22, 0x01, 'n',                            /* network  */
        0x32, 0x01, 0x40,                           /* channels */
        0x3a, 0x01, 'm',                            /* moniker  */
        0x42, 0x04, 0x0a, 0x02, 'o', 'n'            /* other.tx_index */
    };
    /* unknown field 9, network twice (last wins), protocol_version twice
     * (merged: p2p from the first, block from the second) */
    static const uint8_t tricky[] = {
        0x0a, 0x02, 0x08, 0x08,
        0x4a, 0x01, 0x7a,
        0x22, 0x01, 'x',
        0x22, 0x01, 'y',
        0x0a, 0x02, 0x10, 0x0b
    };
    int ok = 1;

    TEST("NodeInfo codec: 0a00 4200, field order, merge, last-wins, skip");
    if (ni == NULL || back == NULL) {
        FAIL("alloc");
        free(ni);
        free(back);
        return;
    }
    cmt_p2p_node_info_init(ni);
    CHECK(cmt_p2p_node_info_marshal(ni, buf, sizeof(buf), &n) == CMT_OK);
    CHECK(n == sizeof(empty) && memcmp(buf, empty, n) == 0);
    ni->protocol_version.p2p = 8;
    ni->protocol_version.block = 11;
    CHECK(cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_NETWORK, "n") == CMT_OK);
    CHECK(cmt_p2p_node_info_set(ni, CMT_P2P_NI_CHANNELS, "\x40", 1) == CMT_OK);
    CHECK(cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_MONIKER, "m") == CMT_OK);
    CHECK(cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_TX_INDEX, "on") == CMT_OK);
    CHECK(cmt_p2p_node_info_marshal(ni, buf, sizeof(buf), &n) == CMT_OK);
    CHECK(n == sizeof(filled) && memcmp(buf, filled, n) == 0);
    CHECK(cmt_p2p_node_info_unmarshal(buf, n, back) == CMT_OK);
    CHECK(back->protocol_version.p2p == 8 && back->protocol_version.block == 11);
    CHECK(cmt_p2p_node_info_field_eq(back, CMT_P2P_NI_MONIKER, "m", 1));
    CHECK(cmt_p2p_node_info_field_eq(back, CMT_P2P_NI_TX_INDEX, "on", 2));
    CHECK(cmt_p2p_node_info_has_channel(back, 0x40) &&
          !cmt_p2p_node_info_has_channel(back, 0x20));
    CHECK(cmt_p2p_node_info_unmarshal(tricky, sizeof(tricky), back) == CMT_OK);
    CHECK(back->protocol_version.p2p == 8 && back->protocol_version.block == 11);
    f = cmt_p2p_node_info_get(back, CMT_P2P_NI_NETWORK, &len);
    CHECK(len == 1 && f[0] == 'y');
    /* truncated / wrong wire type */
    CHECK(cmt_p2p_node_info_unmarshal(filled, sizeof(filled) - 1, back) == CMT_REJECT);
    {
        static const uint8_t wt[] = { 0x20, 0x01 };   /* field 4 as varint */

        CHECK(cmt_p2p_node_info_unmarshal(wt, sizeof(wt), back) == CMT_REJECT);
    }
    free(ni);
    free(back);
    if (ok) {
        PASS();
    } else {
        FAIL("codec");
    }
}

static void make_ni(cmt_p2p_node_info_t *ni, const char *moniker,
                    const uint8_t *chans, size_t n_ch, const uint8_t *chain)
{
    cmt_p2p_node_info_params_t p;
    static const uint8_t def_ch[] = { TEST_CH };

    memset(&p, 0, sizeof(p));
    p.block_version = CMT_BLOCK_PROTOCOL;
    p.node_id = ID64;
    p.chain_id = chain;
    p.version = "1.0";
    p.channels = chans != NULL ? chans : def_ch;
    p.n_channels = chans != NULL ? n_ch : 1;
    p.moniker = moniker;
    p.tx_index = "";
    p.rpc_address = "";
    p.listen_addr = "tcp://0.0.0.0:4004";
    (void)cmt_p2p_node_info_make(ni, &p);
}

static void test_node_info_validate(void)
{
    cmt_p2p_node_info_t *a = (cmt_p2p_node_info_t *)calloc(1, sizeof(*a));
    cmt_p2p_node_info_t *b = (cmt_p2p_node_info_t *)calloc(1, sizeof(*b));
    uint8_t many[17];
    char net[CMT_P2P_NETWORK_CAP];
    int ok = 1, i;

    TEST("NodeInfo Validate + CompatibleWith (no P2P-version check)");
    if (a == NULL || b == NULL) {
        FAIL("alloc");
        free(a);
        free(b);
        return;
    }
    make_ni(a, "alpha", NULL, 0, CHAIN_A);
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_NONE);
    cmt_p2p_network_from_chain_id(CHAIN_A, net);
    CHECK(cmt_p2p_node_info_field_eq(a, CMT_P2P_NI_NETWORK, net, 64));
    CHECK(a->protocol_version.p2p == CMT_P2P_PROTOCOL_VERSION);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_MONIKER, "");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_MONIKER, "   ");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_MONIKER, "a\tb");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_MONIKER, "ok name");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_NONE);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_VERSION, "1\t0");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_VERSION, "");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_NONE);
    for (i = 0; i < 17; i++) {
        many[i] = (uint8_t)i;
    }
    (void)cmt_p2p_node_info_set(a, CMT_P2P_NI_CHANNELS, many, 17);
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);
    (void)cmt_p2p_node_info_set(a, CMT_P2P_NI_CHANNELS, many, 16);
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_NONE);
    many[3] = 1;
    (void)cmt_p2p_node_info_set(a, CMT_P2P_NI_CHANNELS, many, 16);
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);
    (void)cmt_p2p_node_info_set(a, CMT_P2P_NI_CHANNELS, "\x40", 1);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_TX_INDEX, "maybe");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_TX_INDEX, "on");
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_LISTEN_ADDR, "localhost:4004");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_LISTEN_ADDR, "1.2.3.4:4004");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_NONE);
    (void)cmt_p2p_node_info_set_str(a, CMT_P2P_NI_ID, "zz");
    CHECK(cmt_p2p_node_info_validate(a) == CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID);

    /* CompatibleWith */
    make_ni(a, "alpha", NULL, 0, CHAIN_A);
    make_ni(b, "beta", NULL, 0, CHAIN_A);
    CHECK(cmt_p2p_node_info_compatible_with(a, b) == CMT_P2P_ERR_NONE);
    b->protocol_version.p2p = 7;                        /* not compared */
    CHECK(cmt_p2p_node_info_compatible_with(a, b) == CMT_P2P_ERR_NONE);
    b->protocol_version.block = 12;
    CHECK(cmt_p2p_node_info_compatible_with(a, b) == CMT_P2P_ERR_REJECTED_INCOMPATIBLE);
    make_ni(b, "beta", NULL, 0, CHAIN_B);
    CHECK(cmt_p2p_node_info_compatible_with(a, b) == CMT_P2P_ERR_REJECTED_INCOMPATIBLE);
    make_ni(b, "beta", (const uint8_t *)"\x20\x21", 2, CHAIN_A);
    CHECK(cmt_p2p_node_info_compatible_with(a, b) == CMT_P2P_ERR_REJECTED_INCOMPATIBLE);
    (void)cmt_p2p_node_info_set(a, CMT_P2P_NI_CHANNELS, NULL, 0);
    CHECK(cmt_p2p_node_info_compatible_with(a, b) == CMT_P2P_ERR_NONE);
    free(a);
    free(b);
    if (ok) {
        PASS();
    } else {
        FAIL("validate / compatible");
    }
}

/* ══ two switches ════════════════════════════════════════════════════ */

static void test_connect_and_exchange(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    cmt_p2p_peer_t *pAB, *pBA;
    cmt_p2p_netaddr_t addr;
    uint8_t *big = (uint8_t *)malloc(3000);
    int ok = 1, i, got_big = 0, got_hello = 0, got_bcast = 0;
    size_t k;

    TEST("two switches: handshake, NodeInfo, reactor messages both ways");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL || big == NULL) {
        FAIL("setup");
        free(big);
        world_reset();
        return;
    }
    for (k = 0; k < 3000; k++) {
        big[k] = (uint8_t)(k * 7u);
    }
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) ==
          CMT_P2P_ERR_CURRENTLY_DIALING_OR_EXISTING);
    run(40, 10 * MS);
    pAB = peer_of(A, B);
    pBA = peer_of(B, A);
    CHECK(n_peers(A) == 1 && n_peers(B) == 1 && pAB != NULL && pBA != NULL);
    if (pAB != NULL && pBA != NULL) {
        CHECK(cmt_p2p_peer_is_outbound(pAB) && !cmt_p2p_peer_is_outbound(pBA));
        CHECK(cmt_p2p_node_info_field_eq(cmt_p2p_peer_node_info(pAB),
                                         CMT_P2P_NI_MONIKER, "B", 1));
        CHECK(cmt_p2p_node_info_field_eq(cmt_p2p_peer_node_info(pBA),
                                         CMT_P2P_NI_MONIKER, "A", 1));
        CHECK(A->n_add == 1 && B->n_add == 1);
        CHECK(A->jobs_seen_class[CMT_P2P_JOB_CLASS_OUTBOUND] > 0 &&
              A->jobs_seen_class[CMT_P2P_JOB_CLASS_INBOUND] == 0);
        CHECK(B->jobs_seen_class[CMT_P2P_JOB_CLASS_INBOUND] > 0 &&
              B->jobs_seen_class[CMT_P2P_JOB_CLASS_OUTBOUND] == 0);
        CHECK(A->jobs_seen_kind[CMT_P2P_SC_JOB_ENCAPS] == 1 &&
              B->jobs_seen_kind[CMT_P2P_SC_JOB_DECAPS] == 1);
        CHECK(cmt_p2p_peer_send(pAB, TEST_CH, (const uint8_t *)"hello", 5));
        CHECK(cmt_p2p_switch_broadcast(&B->sw, TEST_CH, (const uint8_t *)"bcast", 5) == 1);
        /* a channel the peer does not list is refused (peer.go:273) */
        CHECK(!cmt_p2p_peer_send(pAB, 0x21, (const uint8_t *)"x", 1));
        run(20, 20 * MS);
        CHECK(cmt_p2p_peer_send(pAB, TEST_CH, big, 3000));
        run(40, 20 * MS);
        for (i = 0; i < B->n_msgs; i++) {
            if (B->msgs[i].len == 5 && memcmp(B->msgs[i].b, "hello", 5) == 0 &&
                strcmp(B->msgs[i].src, A->idhex) == 0) {
                got_hello = 1;
            }
            if (B->msgs[i].len == 3000 && memcmp(B->msgs[i].b, big, 3000) == 0) {
                got_big = 1;
            }
        }
        for (i = 0; i < A->n_msgs; i++) {
            if (A->msgs[i].len == 5 && memcmp(A->msgs[i].b, "bcast", 5) == 0 &&
                strcmp(A->msgs[i].src, B->idhex) == 0) {
                got_bcast = 1;
            }
        }
        CHECK(got_hello && got_big && got_bcast);
    }
    free(big);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("exchange");
    }
}

static void test_wrong_network(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    cmt_p2p_netaddr_t addr;
    int ok = 1;

    TEST("wrong chain id (secret conn) / wrong NodeInfo network: refused");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    pb.chain = CHAIN_B;
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(A) == 0 && n_peers(B) == 0);
    CHECK(A->jobs_seen_kind[CMT_P2P_SC_JOB_ENCAPS] == 0);   /* before any KEM */
    CHECK(live_slots(A) == 0 && live_slots(B) == 0);
    world_reset();

    /* same chain for N9, another network in NodeInfo */
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    pb.ni_chain = CHAIN_B;
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup 2");
        world_reset();
        return;
    }
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(A->jobs_seen_kind[CMT_P2P_SC_JOB_ENCAPS] == 1);   /* got to NodeInfo */
    CHECK(n_peers(A) == 0 && n_peers(B) == 0 && A->n_add == 0 && B->n_add == 0);
    CHECK(live_slots(A) == 0 && live_slots(B) == 0);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("network");
    }
}

/* A raw secret-connection initiator speaking P2P version 7. */
static void test_wrong_p2p_version(void)
{
    node_params_t pb;
    node_t *B;
    nodus_identity_t *rid = (nodus_identity_t *)calloc(1, sizeof(*rid));
    cmt_p2p_sc_t *sc = (cmt_p2p_sc_t *)calloc(1, sizeof(*sc));
    cmt_p2p_sc_host_t h;
    cmt_p2p_ip_t rip;
    int slot = -1, i, ok = 1;
    uint64_t gen = 0;

    TEST("P2P version 7 refused at HELLO (N9), before any job");
    params_default(&pb, "10.0.0.2", 4004);
    B = node_new("B", &pb);
    if (B == NULL || rid == NULL || sc == NULL || nodus_identity_generate(rid) != 0) {
        FAIL("setup");
        free(rid);
        free(sc);
        world_reset();
        return;
    }
    memset(&h, 0, sizeof(h));
    h.sign = sc_sign;
    h.verify = sc_verify;
    CHECK(cmt_p2p_sc_init(sc, CMT_P2P_SC_ROLE_INITIATOR, &h, rid->pk.bytes, NULL,
                          NULL, 7u, CHAIN_A) == CMT_OK);
    (void)cmt_p2p_ip_parse("10.0.0.9", 8, &rip);
    CHECK(cmt_p2p_transport_accept(&B->t, &rip, 5555, 0, &slot, &gen) ==
          CMT_P2P_ERR_NONE);
    for (i = 0; i < 10; i++) {
        size_t n = 0, room = 0;
        const uint8_t *o = cmt_p2p_sc_out(sc, &n);
        uint8_t *in = cmt_p2p_transport_read_buf(&B->t, slot, gen, &room);

        if (n > 0 && in != NULL) {
            size_t k = n < room ? n : room;

            memcpy(in, o, k);
            cmt_p2p_transport_read_done(&B->t, slot, gen, k);
            cmt_p2p_sc_out_consume(sc, k);
        }
        g_now += MS;
        cmt_p2p_switch_tick(&B->sw);
    }
    CHECK(cmt_p2p_transport_conn(&B->t, slot, gen) == NULL);
    CHECK(B->jobs_seen_kind[CMT_P2P_SC_JOB_DECAPS] == 0 && B->t.n_inbound == 0);
    CHECK(n_peers(B) == 0);
    cmt_p2p_sc_clear(sc);
    free(sc);
    free(rid);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("p2p version");
    }
}

static void test_dial_pin(void)
{
    node_params_t pa, pb, pc;
    node_t *A, *B, *C;
    cmt_p2p_netaddr_t addr;
    int ok = 1;

    TEST("dial to ID X answered by key Y: aborted before Encaps (R-P2P-14)");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    params_default(&pc, "10.0.0.3", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    C = node_new("C", &pc);
    if (A == NULL || B == NULL || C == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    addr = addr_of(B);
    memcpy(addr.id, C->idhex, sizeof(addr.id));        /* C's ID, B's address */
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(A) == 0 && n_peers(B) == 0);
    CHECK(A->jobs_seen_kind[CMT_P2P_SC_JOB_ENCAPS] == 0);
    CHECK(B->jobs_seen_kind[CMT_P2P_SC_JOB_DECAPS] == 0);
    CHECK(A->sw.n_dialing == 0 && live_slots(A) == 0);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("pin");
    }
}

static void test_duplicate_id(void)
{
    node_params_t pa, pa2, pb;
    node_t *A, *A2, *B;
    cmt_p2p_netaddr_t addr;
    int ok = 1;

    TEST("duplicate ID refused for everyone (bonded included)");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    params_default(&pa2, "10.0.0.5", 4004);
    pa2.identity = &A->id;
    A2 = node_new("A2", &pa2);
    if (A2 == NULL) {
        FAIL("setup A2");
        world_reset();
        return;
    }
    B->bonded[B->n_bonded++] = A->idhex;               /* bonded ≠ exempt here */
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(A) == 1 && n_peers(B) == 1);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A2->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(B) == 1 && n_peers(A2) == 0 && B->n_add == 1);
    {
        cmt_p2p_peer_t *p = peer_of(B, A);

        CHECK(p != NULL && cmt_p2p_ip_equal(cmt_p2p_peer_remote_ip(p), &A->ip));
    }
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("dup id");
    }
}

static void test_duplicate_ip(void)
{
    node_params_t pa, pc, pb;
    node_t *A, *C, *B;
    cmt_p2p_netaddr_t addr;
    int ok = 1;

    TEST("duplicate IP refused before identity; allowed with the test knob");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pc, "10.0.0.1", 4005);             /* same IP as A */
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    C = node_new("C", &pc);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL || C == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(B) == 1);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&C->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(B) == 1 && n_peers(C) == 0);
    CHECK(C->jobs_seen_kind[CMT_P2P_SC_JOB_ENCAPS] == 0 && B->t.n_inbound == 1);
    world_reset();

    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pc, "10.0.0.1", 4005);
    params_default(&pb, "10.0.0.2", 4004);
    pb.allow_dup_ip = true;
    A = node_new("A", &pa);
    C = node_new("C", &pc);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL || C == NULL) {
        FAIL("setup 2");
        world_reset();
        return;
    }
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&C->sw, &addr) == CMT_P2P_ERR_NONE);
    run(60, 10 * MS);
    CHECK(n_peers(B) == 2 && n_peers(A) == 1 && n_peers(C) == 1);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("dup ip");
    }
}

static void test_inbound_limit(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    cmt_p2p_netaddr_t addr;
    cmt_p2p_ip_t other;
    int slot = -1, before, ok = 1;
    uint64_t gen = 0;

    TEST("listener limit refuses before allocation; uncond. + bonded raise it");
    (void)cmt_p2p_ip_parse("10.9.9.9", 8, &other);
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    pb.max_in_transport = 1;
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    CHECK(cmt_p2p_transport_max_incoming(&B->t) == 1);
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(B) == 1 && B->t.n_inbound == 1);
    CHECK(!cmt_p2p_transport_can_accept(&B->t));
    before = live_slots(B);
    CHECK(cmt_p2p_transport_accept(&B->t, &other, 7, 0, &slot, &gen) == CMT_P2P_ERR_LIMIT);
    CHECK(live_slots(B) == before && B->t.n_inbound == 1);
    B->n_bonded = 1;                                   /* the bonded set grows */
    B->bonded[0] = "not-a-real-id";
    CHECK(cmt_p2p_transport_max_incoming(&B->t) == 2 && cmt_p2p_transport_can_accept(&B->t));
    world_reset();

    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    pb.max_in_transport = 1;
    pb.n_uncond_cfg = 1;
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup 2");
        world_reset();
        return;
    }
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(cmt_p2p_transport_max_incoming(&B->t) == 2 && cmt_p2p_transport_can_accept(&B->t));
    CHECK(cmt_p2p_transport_accept(&B->t, &other, 7, 0, &slot, &gen) == CMT_P2P_ERR_NONE);
    CHECK(!cmt_p2p_transport_can_accept(&B->t));
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("limit");
    }
}

static void test_bonded_admitted(void)
{
    node_params_t pa, pb, pc, pd;
    node_t *A, *B, *C, *D;
    cmt_p2p_netaddr_t addr;
    int ok = 1, out = -1, in = -1;

    TEST("inbound cap full: unbonded refused after auth, bonded admitted (K2)");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    params_default(&pc, "10.0.0.3", 4004);
    params_default(&pd, "10.0.0.4", 4004);
    pb.max_in_switch = 1;
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    C = node_new("C", &pc);
    D = node_new("D", &pd);
    if (A == NULL || B == NULL || C == NULL || D == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    B->bonded[B->n_bonded++] = D->idhex;
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(B) == 1);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&C->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(B) == 1 && peer_of(B, C) == NULL && n_peers(C) == 0);
    CHECK(C->jobs_seen_kind[CMT_P2P_SC_JOB_ENCAPS] == 1);   /* refused AFTER auth */
    CHECK(cmt_p2p_switch_dial_peer_with_address(&D->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(B) == 2 && peer_of(B, D) != NULL && n_peers(D) == 1);
    cmt_p2p_switch_num_peers(&B->sw, &out, &in, NULL);
    CHECK(in == 1 && out == 0);                          /* D not counted */
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("bonded");
    }
}

static void test_inbound_queue_full(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    cmt_p2p_netaddr_t addr;
    int ok = 1;

    TEST("inbound handshake job queue full: the connection is closed (P3)");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    B->job_cap[CMT_P2P_JOB_CLASS_INBOUND] = 0;
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(A) == 0 && n_peers(B) == 0 && B->t.n_inbound == 0);
    CHECK(live_slots(A) == 0 && live_slots(B) == 0);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("queue full");
    }
}

static void test_handshake_timeout(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    cmt_p2p_netaddr_t addr;
    int ok = 1, a_slot = -1, b_slot = -1, i;
    uint64_t a_gen = 0, b_gen = 0;
    int64_t t0;

    TEST("handshake deadline: alive at 2.999 s, closed at 3.000 s");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    B->frozen = true;                     /* B's host moves no byte */
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    net_step();                           /* connect + accept at g_now */
    t0 = g_now;
    for (i = 0; i < MAX_WIRES; i++) {
        if (g_wires[i].used) {
            a_slot = g_wires[i].a_slot;
            a_gen = g_wires[i].a_gen;
            b_slot = g_wires[i].b_slot;
            b_gen = g_wires[i].b_gen;
        }
    }
    CHECK(a_slot >= 0 && b_slot >= 0);
    g_now = t0 + 2999 * MS;
    net_step();
    CHECK(cmt_p2p_transport_conn(&A->t, a_slot, a_gen) != NULL);
    CHECK(cmt_p2p_transport_conn(&B->t, b_slot, b_gen) != NULL);
    g_now = t0 + 3000 * MS;
    net_step();
    CHECK(cmt_p2p_transport_conn(&A->t, a_slot, a_gen) == NULL);
    CHECK(cmt_p2p_transport_conn(&B->t, b_slot, b_gen) == NULL);
    CHECK(A->sw.n_dialing == 0 && B->t.n_inbound == 0);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("timeout");
    }
}

/* ── a raw secret-connection peer that completes the handshake and then
 *    never sends its NodeInfo (and drops ours) ── */

typedef struct {
    node_t           *holder;      /* only its identity is used (sc_sign) */
    cmt_p2p_sc_t     *sc;
    cmt_p2p_sc_host_t host;
} raw_t;

static raw_t *raw_new(cmt_p2p_sc_role_t role)
{
    raw_t *r = (raw_t *)calloc(1, sizeof(*r));

    if (r == NULL) {
        return NULL;
    }
    r->holder = (node_t *)calloc(1, sizeof(node_t));
    r->sc = (cmt_p2p_sc_t *)calloc(1, sizeof(cmt_p2p_sc_t));
    if (r->holder == NULL || r->sc == NULL ||
        nodus_identity_generate(&r->holder->id) != 0 || !r->holder->id.has_mlkem ||
        cmt_p2p_pubkey_to_id(r->holder->id.pk.bytes, r->holder->idhex) != CMT_OK) {
        free(r->holder);
        free(r->sc);
        free(r);
        return NULL;
    }
    r->host.ctx = r->holder;
    r->host.sign = sc_sign;
    r->host.verify = sc_verify;
    if (cmt_p2p_sc_init(r->sc, role, &r->host, r->holder->id.pk.bytes,
                        role == CMT_P2P_SC_ROLE_RESPONDER ? r->holder->id.mlkem_pk : NULL,
                        role == CMT_P2P_SC_ROLE_RESPONDER ? r->holder->id.mlkem_sk : NULL,
                        CMT_P2P_PROTOCOL_VERSION, CHAIN_A) != CMT_OK) {
        free(r->holder);
        free(r->sc);
        free(r);
        return NULL;
    }
    return r;
}

static void raw_free(raw_t *r)
{
    if (r == NULL) {
        return;
    }
    cmt_p2p_sc_clear(r->sc);
    free(r->sc);
    free(r->holder);
    free(r);
}

/* One pass between the raw peer and connection (slot, gen) of node `n`. */
static void raw_pump(raw_t *r, node_t *n, int slot, uint64_t gen)
{
    const cmt_p2p_sc_job_t *j;
    const uint8_t *o;
    size_t len = 0;

    o = cmt_p2p_sc_out(r->sc, &len);
    if (len > 0) {
        size_t room = 0;
        uint8_t *in = cmt_p2p_transport_read_buf(&n->t, slot, gen, &room);

        if (in != NULL && room > 0) {
            size_t k = len < room ? len : room;

            memcpy(in, o, k);
            cmt_p2p_transport_read_done(&n->t, slot, gen, k);
            cmt_p2p_sc_out_consume(r->sc, k);
        }
    }
    o = cmt_p2p_transport_write_buf(&n->t, slot, gen, &len);
    if (o != NULL && len > 0) {
        if (!cmt_p2p_sc_is_authenticated(r->sc)) {
            size_t used = 0;

            (void)cmt_p2p_sc_recv(r->sc, o, len, &used);
            cmt_p2p_transport_write_done(&n->t, slot, gen, used);
        } else {
            cmt_p2p_transport_write_done(&n->t, slot, gen, len);   /* ignored */
        }
    }
    while ((j = cmt_p2p_sc_job(r->sc)) != NULL) {
        (void)cmt_p2p_sc_job_done(r->sc, cmt_p2p_sc_job_run(j, &r->host));
    }
}

/* Drive until the node's connection has entered the NodeInfo exchange
 * and the raw side is authenticated. @return the instant the node's
 * connection entered it (its secret connection completed), or 0. */
static int64_t raw_until_node_info(raw_t *r, node_t *n, int slot, uint64_t gen)
{
    int64_t entered = 0;
    int i;

    for (i = 0; i < 400; i++) {
        cmt_p2p_conn_t *c;

        g_now += MS;
        raw_pump(r, n, slot, gen);
        run_jobs(n);
        cmt_p2p_switch_tick(&n->sw);
        c = cmt_p2p_transport_conn(&n->t, slot, gen);
        if (c == NULL) {
            return 0;
        }
        if (entered == 0 && c->state == CMT_P2P_CONN_NODE_INFO) {
            entered = g_now;
        }
        if (entered != 0 && cmt_p2p_sc_is_authenticated(r->sc)) {
            return entered;
        }
    }
    return 0;
}

static void test_node_info_timeout(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    raw_t *ri = NULL, *rr = NULL;
    cmt_p2p_ip_t rip;
    cmt_p2p_netaddr_t addr;
    cmt_p2p_conn_t *c;
    int ok = 1, slot = -1;
    uint64_t gen = 0;
    int64_t t;

    TEST("NodeInfo deadline (2nd 3 s window): 2.999 s alive, 3.000 s closed");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    ri = raw_new(CMT_P2P_SC_ROLE_INITIATOR);
    rr = raw_new(CMT_P2P_SC_ROLE_RESPONDER);
    if (A == NULL || B == NULL || ri == NULL || rr == NULL) {
        FAIL("setup");
        raw_free(ri);
        raw_free(rr);
        world_reset();
        return;
    }
    (void)cmt_p2p_ip_parse("10.0.0.9", 8, &rip);

    /* acceptor side: B accepts the raw initiator */
    CHECK(cmt_p2p_transport_accept(&B->t, &rip, 5555, 0, &slot, &gen) ==
          CMT_P2P_ERR_NONE);
    t = raw_until_node_info(ri, B, slot, gen);
    CHECK(t != 0);
    c = cmt_p2p_transport_conn(&B->t, slot, gen);
    CHECK(c != NULL && c->deadline_ns == t + 3000 * MS);
    g_now = t + 2999 * MS;
    raw_pump(ri, B, slot, gen);
    cmt_p2p_switch_tick(&B->sw);
    c = cmt_p2p_transport_conn(&B->t, slot, gen);
    CHECK(c != NULL && c->state == CMT_P2P_CONN_NODE_INFO);
    g_now = t + 3000 * MS;
    raw_pump(ri, B, slot, gen);
    cmt_p2p_switch_tick(&B->sw);
    CHECK(cmt_p2p_transport_conn(&B->t, slot, gen) == NULL);
    CHECK(n_peers(B) == 0 && B->t.n_inbound == 0 && B->n_add == 0);

    /* dialer side: A dials the raw responder */
    g_raw_dial.active = true;
    g_raw_dial.ip = rip;
    g_raw_dial.port = 7777;
    addr = cmt_p2p_netaddr_new_ip_port(&rip, 7777);
    memcpy(addr.id, rr->holder->idhex, sizeof(addr.id));
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    cmt_p2p_transport_dial_connected(&A->t, g_raw_dial.slot, g_raw_dial.gen,
                                     &rip, 7777);
    t = raw_until_node_info(rr, A, g_raw_dial.slot, g_raw_dial.gen);
    CHECK(t != 0);
    c = cmt_p2p_transport_conn(&A->t, g_raw_dial.slot, g_raw_dial.gen);
    CHECK(c != NULL && c->deadline_ns == t + 3000 * MS);
    g_now = t + 2999 * MS;
    raw_pump(rr, A, g_raw_dial.slot, g_raw_dial.gen);
    cmt_p2p_switch_tick(&A->sw);
    c = cmt_p2p_transport_conn(&A->t, g_raw_dial.slot, g_raw_dial.gen);
    CHECK(c != NULL && c->state == CMT_P2P_CONN_NODE_INFO);
    g_now = t + 3000 * MS;
    raw_pump(rr, A, g_raw_dial.slot, g_raw_dial.gen);
    cmt_p2p_switch_tick(&A->sw);
    CHECK(cmt_p2p_transport_conn(&A->t, g_raw_dial.slot, g_raw_dial.gen) == NULL);
    CHECK(n_peers(A) == 0 && A->sw.n_dialing == 0 && A->n_add == 0);

    raw_free(ri);
    raw_free(rr);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("node info timeout");
    }
}

static void test_dial_without_id(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    cmt_p2p_netaddr_t addr;
    int ok = 1;

    TEST("dial to an address without / with a bad ID: refused before any job");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    addr = addr_of(B);
    addr.id[0] = '\0';
    CHECK(cmt_p2p_transport_dial(&A->t, &addr) == CMT_P2P_ERR_NETADDR_NO_ID);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) ==
          CMT_P2P_ERR_NETADDR_NO_ID);
    snprintf(addr.id, sizeof(addr.id), "zz");
    CHECK(cmt_p2p_transport_dial(&A->t, &addr) == CMT_P2P_ERR_NETADDR_INVALID);
    run(20, 10 * MS);
    CHECK(A->n_dials == 0 && live_slots(A) == 0 && A->sw.n_dialing == 0);
    CHECK(A->jobs_seen_class[0] == 0 && A->jobs_seen_class[1] == 0);
    CHECK(n_peers(A) == 0 && n_peers(B) == 0 && B->t.n_inbound == 0);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("dial without id");
    }
}

static void test_stale_job(void)
{
    node_params_t pa, pb, pc;
    node_t *A, *B, *C;
    cmt_p2p_netaddr_t addr;
    cmt_p2p_hs_job_t *held = NULL;
    int ok = 1, i;

    TEST("stale generation: the old job result is discarded, slot reused OK");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    params_default(&pc, "10.0.0.3", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    C = node_new("C", &pc);
    if (A == NULL || B == NULL || C == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    B->run_jobs = false;                  /* B's worker is stuck */
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    for (i = 0; i < 20 && B->njobs[CMT_P2P_JOB_CLASS_INBOUND] == 0; i++) {
        run(1, 10 * MS);
    }
    CHECK(B->njobs[CMT_P2P_JOB_CLASS_INBOUND] == 1);
    if (B->njobs[CMT_P2P_JOB_CLASS_INBOUND] == 1) {
        int old_slot;
        uint64_t old_gen;
        cmt_p2p_conn_t *nc;

        held = B->jobs[CMT_P2P_JOB_CLASS_INBOUND][0];
        B->njobs[CMT_P2P_JOB_CLASS_INBOUND] = 0;
        CHECK(held->kind == CMT_P2P_SC_JOB_DECAPS);
        old_slot = held->slot;
        old_gen = held->gen;
        run(1, 3000 * MS);                /* the 3 s deadline passes */
        CHECK(cmt_p2p_transport_conn(&B->t, old_slot, old_gen) == NULL);
        B->run_jobs = true;
        addr = addr_of(B);
        CHECK(cmt_p2p_switch_dial_peer_with_address(&C->sw, &addr) == CMT_P2P_ERR_NONE);
        B->run_jobs = false;
        net_step();                       /* C's connection takes the slot */
        nc = B->t.slots[old_slot];
        CHECK(nc != NULL && nc->gen != old_gen);
        (void)cmt_p2p_hs_job_run(held);
        CHECK(cmt_p2p_transport_job_done(&B->t, held) == CMT_REJECT);
        held = NULL;
        B->run_jobs = true;
        run(40, 10 * MS);
        CHECK(n_peers(C) == 1 && peer_of(B, C) != NULL && peer_of(B, A) == NULL);
    }
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("stale job");
    }
}

static void test_stop_peer_for_error(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    cmt_p2p_netaddr_t addr;
    cmt_p2p_peer_t *p;
    int ok = 1;

    TEST("StopPeerForError from Receive: out of reactors + peer set, both ends");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    p = peer_of(A, B);
    CHECK(p != NULL && n_peers(B) == 1);
    if (p != NULL) {
        CHECK(cmt_p2p_peer_send(p, TEST_CH, (const uint8_t *)"bad", 3));
        run(40, 20 * MS);
        CHECK(n_peers(B) == 0 && B->n_remove == 1 && B->last_remove_reason == 42);
        CHECK(n_peers(A) == 0 && A->n_remove == 1 && A->last_remove_reason != 0);
        CHECK(live_slots(A) == 0 && live_slots(B) == 0);
        CHECK(!cmt_p2p_switch_is_reconnecting(&A->sw, B->idhex));  /* not persistent */
    }
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("stop for error");
    }
}

static void test_persistent_redial(void)
{
    node_params_t pa, pb;
    node_t *A, *B;
    char paddr[200];
    const char *list[1];
    cmt_p2p_peer_t *pb_a;
    int ok = 1, i, d0;
    int64_t t_first;

    TEST("persistent peer: redial now, 20 x (5 s + jitter), then 3^i s backoff");
    params_default(&pa, "10.0.0.1", 4004);
    params_default(&pb, "10.0.0.2", 4004);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    snprintf(paddr, sizeof(paddr), "%s@10.0.0.2:4004", B->idhex);
    list[0] = paddr;
    CHECK(cmt_p2p_switch_add_persistent_peers(&A->sw, list, 1) == CMT_P2P_ERR_NONE);
    g_rand_val = 0;
    CHECK(cmt_p2p_switch_dial_peers_async(&A->sw, list, 1) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(n_peers(A) == 1 && cmt_p2p_peer_is_persistent(peer_of(A, B)));
    /* B goes away */
    g_rand_val = 500;
    B->up = false;
    pb_a = peer_of(B, A);
    CHECK(pb_a != NULL);
    if (pb_a == NULL) {
        world_reset();
        FAIL("setup 2");
        return;
    }
    d0 = A->n_dials;
    cmt_p2p_switch_stop_peer_gracefully(&B->sw, pb_a);
    for (i = 0; i < 20 && A->n_dials == d0; i++) {
        run(1, 10 * MS);
    }
    CHECK(A->n_dials == d0 + 1 && cmt_p2p_switch_is_reconnecting(&A->sw, B->idhex));
    t_first = A->dial_times[d0];
    /* attempts 2..20, each 5.5 s after the previous */
    while (A->n_dials < d0 + 20 && g_now < t_first + 200LL * 1000 * MS) {
        run(1, 100 * MS);
    }
    CHECK(A->n_dials == d0 + 20);
    for (i = 1; i < 20 && d0 + i < 64; i++) {
        CHECK(A->dial_times[d0 + i] - A->dial_times[d0 + i - 1] == 5500 * MS);
    }
    /* 20th failure: +5.5 s into backoff, +3.5 s (3^1 + 0.5) → attempt 21,
     * then +9.5 s (3^2 + 0.5) → attempt 22 */
    while (A->n_dials < d0 + 22 && g_now < t_first + 400LL * 1000 * MS) {
        run(1, 100 * MS);
    }
    CHECK(A->n_dials == d0 + 22);
    if (d0 + 21 < 64) {
        CHECK(A->dial_times[d0 + 20] - A->dial_times[d0 + 19] == 9000 * MS);
        CHECK(A->dial_times[d0 + 21] - A->dial_times[d0 + 20] == 9500 * MS);
    }
    /* B is back: attempt 23 (+27.5 s) connects and the loop ends */
    B->up = true;
    for (i = 0; i < 400 && n_peers(A) == 0; i++) {
        run(1, 100 * MS);
    }
    CHECK(A->n_dials == d0 + 23 && n_peers(A) == 1 && n_peers(B) == 1);
    CHECK(A->dial_times[d0 + 22] - A->dial_times[d0 + 21] == 27500 * MS);
    run(5, 100 * MS);
    CHECK(!cmt_p2p_switch_is_reconnecting(&A->sw, B->idhex));
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("redial");
    }
}

static void test_cross_dial(void)
{
    node_params_t pa, pb;
    node_t *A, *B, *lo, *hi;
    cmt_p2p_netaddr_t ab, ba;
    cmt_p2p_peer_t *p_lo, *p_hi;
    int ok = 1;

    TEST("cross-dial: one connection on both ends, the lower ID's (R-P2P-23)");
    params_default(&pa, "127.0.0.1", 4004);
    params_default(&pb, "127.0.0.1", 4005);
    pa.allow_dup_ip = true;
    pb.allow_dup_ip = true;
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    ab = addr_of(B);
    ba = addr_of(A);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &ab) == CMT_P2P_ERR_NONE);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&B->sw, &ba) == CMT_P2P_ERR_NONE);
    run(80, 10 * MS);
    CHECK(n_peers(A) == 1 && n_peers(B) == 1);
    lo = strcmp(A->idhex, B->idhex) < 0 ? A : B;
    hi = lo == A ? B : A;
    p_lo = peer_of(lo, hi);
    p_hi = peer_of(hi, lo);
    CHECK(p_lo != NULL && p_hi != NULL);
    if (p_lo != NULL && p_hi != NULL) {
        CHECK(cmt_p2p_peer_is_outbound(p_lo) && !cmt_p2p_peer_is_outbound(p_hi));
        CHECK(lo->n_add - lo->n_remove == 1 && hi->n_add - hi->n_remove == 1);
        /* and it carries traffic */
        CHECK(cmt_p2p_peer_send(p_hi, TEST_CH, (const uint8_t *)"x-dial", 6));
        run(20, 20 * MS);
        CHECK(lo->n_msgs == 1 && lo->msgs[0].len == 6);
    }
    CHECK(live_slots(A) == 1 && live_slots(B) == 1);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("cross dial");
    }
}

/* ══ the 4004 socket host: continuous read / write (R-P2P-17) ════════ */

#ifdef __linux__
/* One reactor message far larger than one read buffer. */
#define SOCK_PAYLOAD        (256 * 1024)
/* The OLD io_read read at most one full rbuf per pass — CMT_P2P_CONN_RBUF_CAP
 * = 4 sealed frames (cmt_p2p_peer.h:100), each carrying at most
 * CMT_P2P_SC_DATA_MAX_SIZE (1024) plaintext bytes — and nothing read that
 * socket again until the next pass. So it delivered at most 4 × 1024 =
 * 4096 message bytes per receiver pass (less: packet framing rides in the
 * same frames), and 256 KiB needed at least ceil(262144 / 4096) = 64
 * passes. */
#define SOCK_OLD_BYTES_PER_PASS \
    ((CMT_P2P_CONN_RBUF_CAP / CMT_P2P_SC_SEALED_FRAME_SIZE) * CMT_P2P_SC_DATA_MAX_SIZE)
#define SOCK_OLD_MIN_PASSES \
    ((SOCK_PAYLOAD + SOCK_OLD_BYTES_PER_PASS - 1) / SOCK_OLD_BYTES_PER_PASS)
_Static_assert(SOCK_OLD_MIN_PASSES >= 60,
               "the old per-pass read cap needs >= 60 passes for the payload");
/* The bound asserted now. The floor is 2: the payload's last partial
 * bufio chunk leaves the sender only when its flush throttle fires
 * (connection.go:440-443, 100 ms), i.e. in the pass after the one that
 * queued it. The rest is slack for loopback segments the kernel delivers
 * after the receiver's recv(2) already returned EAGAIN (HOW IT CAN LIE). */
#define SOCK_MAX_PASSES     8
_Static_assert(SOCK_MAX_PASSES < SOCK_OLD_MIN_PASSES,
               "the bound must fail the old per-pass read cap");
/* Guards against a hang only; never part of what is asserted. */
#define SOCK_HANDSHAKE_GUARD_MS 30000
#define SOCK_PASS_GUARD         200

static int64_t sock_mono_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A node whose bytes go through nodus_p2p_io on 127.0.0.1 (an ephemeral
 * port — its NodeInfo must carry it, so the listener comes first; the
 * witness host's own order, nodus_witness_p2p.c nodus_witness_p2p_new). */
static node_t *sock_node_new(const char *name)
{
    nodus_p2p_io_t *io = (nodus_p2p_io_t *)calloc(1, sizeof(*io));
    struct sockaddr_in sin;
    socklen_t sl = (socklen_t)sizeof(sin);
    node_params_t prm;
    node_t *n;

    if (io == NULL) {
        return NULL;
    }
    if (nodus_p2p_io_init(io, false) != 0) {
        free(io);
        return NULL;
    }
    if (nodus_p2p_io_listen(io, "127.0.0.1", 0) != 0 ||
        getsockname(io->listen_fd, (struct sockaddr *)&sin, &sl) != 0) {
        nodus_p2p_io_free(io);
        free(io);
        return NULL;
    }
    params_default(&prm, "127.0.0.1", ntohs(sin.sin_port));
    n = node_new(name, &prm);
    if (n == NULL) {
        nodus_p2p_io_free(io);
        free(io);
        return NULL;
    }
    n->io = io;
    io->t = &n->t;
    return n;
}

/* One pass of a node, in nodus_witness_p2p_poll's order (worker results,
 * wait, worker results, I/O, the switch's tick, the final write). */
static void sock_pass(node_t *n, int wait_ms)
{
    run_jobs(n);
    nodus_p2p_io_wait(n->io, wait_ms);
    run_jobs(n);
    nodus_p2p_io_pump(n->io);
    cmt_p2p_switch_tick(&n->sw);
    nodus_p2p_io_flush(n->io);
}

static void test_socket_continuous_read(void)
{
    node_t *A, *B;
    cmt_p2p_netaddr_t addr;
    cmt_p2p_peer_t *pAB;
    uint8_t *payload = (uint8_t *)malloc(SOCK_PAYLOAD);
    int ok = 1, passes = 0, before;
    int64_t end;
    size_t k;

    TEST("4004 socket host: 256 KiB crosses loopback in <= 8 passes (old >= 64)");
    A = sock_node_new("A");
    B = sock_node_new("B");
    if (A == NULL || B == NULL || payload == NULL) {
        FAIL("setup");
        free(payload);
        world_reset();
        return;
    }
    for (k = 0; k < SOCK_PAYLOAD; k++) {
        payload[k] = (uint8_t)(k * 131u + (k >> 9));
    }
    addr = addr_of(B);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    /* The handshake over real sockets with the FAKE clock standing still:
     * no 3 s deadline can pass. The real-time guard only bounds a hang. */
    end = sock_mono_ms() + SOCK_HANDSHAKE_GUARD_MS;
    while (!(n_peers(A) == 1 && n_peers(B) == 1) && sock_mono_ms() < end) {
        sock_pass(A, 5);
        sock_pass(B, 5);
    }
    CHECK(n_peers(A) == 1 && n_peers(B) == 1);
    pAB = peer_of(A, B);
    CHECK(pAB != NULL);
    if (pAB != NULL) {
        before = B->n_msgs;
        CHECK(cmt_p2p_peer_send(pAB, TEST_CH, payload, SOCK_PAYLOAD));
        /* One counted pass = the fake clock moves one flush throttle
         * (100 ms, config.go:577), then the sender's pass, then the
         * receiver's. The receiver's wait (real time, up to 200 ms) only
         * lets bytes in flight arrive; it counts as nothing. */
        while (B->n_msgs == before && passes < SOCK_PASS_GUARD) {
            g_now += CMT_P2P_CONFIG_DEFAULT_FLUSH_THROTTLE_NS;
            sock_pass(A, 0);
            sock_pass(B, 200);
            passes++;
        }
        CHECK(B->n_msgs == before + 1);
        if (B->n_msgs == before + 1) {
            CHECK(B->msgs[before].ch == TEST_CH &&
                  B->msgs[before].len == SOCK_PAYLOAD &&
                  memcmp(B->msgs[before].b, payload, SOCK_PAYLOAD) == 0 &&
                  strcmp(B->msgs[before].src, A->idhex) == 0);
        }
        CHECK(passes <= SOCK_MAX_PASSES);
        if (passes > SOCK_MAX_PASSES) {
            printf("\n    delivered after %d passes (bound %d, old floor %d)",
                   passes, SOCK_MAX_PASSES, (int)SOCK_OLD_MIN_PASSES);
        }
        /* the connection survived the burst */
        CHECK(n_peers(A) == 1 && n_peers(B) == 1);
    }
    free(payload);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("continuous read");
    }
}

/* Passes the receiver stays "blocked" for. The payload's sender flushes
 * its last chunk in pass 2 (the flush throttle), so 10 passes cover the
 * whole send; 10 × 100 ms fake time stays far below the 60 s ping and
 * 45 s pong timers (config.go / connection.go:146-155). */
#define SOCK_BLOCKED_PASSES 10

/* A dials B over the socket host; handshake with the fake clock still. */
static bool sock_link(node_t *A, node_t *B)
{
    cmt_p2p_netaddr_t addr = addr_of(B);
    int64_t end;

    if (cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) != CMT_P2P_ERR_NONE) {
        return false;
    }
    end = sock_mono_ms() + SOCK_HANDSHAKE_GUARD_MS;
    while (!(n_peers(A) == 1 && n_peers(B) == 1) && sock_mono_ms() < end) {
        sock_pass(A, 5);
        sock_pass(B, 5);
    }
    return n_peers(A) == 1 && n_peers(B) == 1;
}

/* The blocked Receive (transport host row `may_receive`, the single-loop
 * form of consensus/reactor.go:324/:330/:350's blocking queue send): while
 * B's row answers false, B reads NOTHING from A's socket and delivers
 * nothing, yet both peers stay connected; once it answers true the whole
 * message arrives within the continuous-read bound. */
static void test_socket_blocked_receive(void)
{
    node_t *A, *B;
    cmt_p2p_peer_t *pAB, *pBA;
    uint8_t *payload = (uint8_t *)malloc(SOCK_PAYLOAD);
    int ok = 1, passes = 0, before, i;
    size_t k;

    TEST("4004 socket host: a blocked Receive reads nothing, keeps the peer, "
         "then delivers");
    A = sock_node_new("A");
    B = sock_node_new("B");
    if (A == NULL || B == NULL || payload == NULL) {
        FAIL("setup");
        free(payload);
        world_reset();
        return;
    }
    for (k = 0; k < SOCK_PAYLOAD; k++) {
        payload[k] = (uint8_t)(k * 29u + 7u);
    }
    CHECK(sock_link(A, B));
    pAB = peer_of(A, B);
    pBA = peer_of(B, A);
    CHECK(pAB != NULL && pBA != NULL);
    if (pAB != NULL && pBA != NULL) {
        before = B->n_msgs;
        B->block_recv = true;
        CHECK(cmt_p2p_peer_send(pAB, TEST_CH, payload, SOCK_PAYLOAD));
        for (i = 0; i < SOCK_BLOCKED_PASSES; i++) {
            g_now += CMT_P2P_CONFIG_DEFAULT_FLUSH_THROTTLE_NS;
            sock_pass(A, 0);
            sock_pass(B, 20);
        }
        CHECK(B->n_msgs == before);
        /* nothing was read from the socket, nothing opened */
        pBA = peer_of(B, A);
        CHECK(pBA != NULL && pBA->conn != NULL &&
              pBA->conn->rbuf_len == 0 && pBA->conn->pbuf_len == 0);
        CHECK(n_peers(A) == 1 && n_peers(B) == 1);

        B->block_recv = false;
        while (B->n_msgs == before && passes < SOCK_PASS_GUARD) {
            g_now += CMT_P2P_CONFIG_DEFAULT_FLUSH_THROTTLE_NS;
            sock_pass(A, 0);
            sock_pass(B, 200);
            passes++;
        }
        CHECK(B->n_msgs == before + 1);
        if (B->n_msgs == before + 1) {
            CHECK(B->msgs[before].len == SOCK_PAYLOAD &&
                  memcmp(B->msgs[before].b, payload, SOCK_PAYLOAD) == 0);
        }
        CHECK(passes <= SOCK_MAX_PASSES);
        if (passes > SOCK_MAX_PASSES) {
            printf("\n    delivered after %d passes once unblocked (bound %d)",
                   passes, SOCK_MAX_PASSES);
        }
        CHECK(n_peers(A) == 1 && n_peers(B) == 1);
    }
    free(payload);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("blocked receive");
    }
}
#else
/* The socket host is Linux-only (epoll; nodus/CMakeLists.txt's
 * NOT WIN32 source list). A skip is printed and counted as neither pass
 * nor fail — it is coverage that did not happen. */
static void test_socket_continuous_read(void)
{
    TEST("4004 socket host: 256 KiB crosses loopback in <= 8 passes (old >= 64)");
    printf("SKIPPED (Linux only)\n");
}

static void test_socket_blocked_receive(void)
{
    TEST("4004 socket host: a blocked Receive reads nothing, keeps the peer, "
         "then delivers");
    printf("SKIPPED (Linux only)\n");
}
#endif

/* ══ receive fairness under a nearly full queue (red-team H3) ═════════ */

#define FAIR_MSGS   8          /* per sender; TEST_CH's send queue holds 10 */
#define FAIR_QCAP   2
#define FAIR_PASSES 200

/* The index of `id` among A and B (0 / 1), or -1. */
static int fair_who(const char *id, const node_t *A, const node_t *B)
{
    return strcmp(id, A->idhex) == 0 ? 0 : strcmp(id, B->idhex) == 0 ? 1 : -1;
}

/*
 * R holds a modelled consensus queue of FAIR_QCAP entries, drained
 * completely between two passes (the lane tick between two polls). A
 * connects FIRST — the lower transport slot on R — and B second; each
 * queues FAIR_MSGS messages at once.
 *   · NOTHING READ IS DROPPED: the queue never receives a message while
 *     full (q_overflow == 0) — the gate is asked before every message
 *     (cmt_p2p_peer_pump / cmt_p2p_mconn_recv_n max 1), not once per
 *     step; RED before H3 for any step that delivered past the room.
 *   · EVERY message arrives once, in its sender's order.
 *   · A LOW SLOT CANNOT STARVE A HIGHER ONE: while both still have
 *     messages in flight, neither is delivered more than twice in a row
 *     (near full = room < peers → one message per peer per pump, and the
 *     tick starts just past the slot last served, atlas-dec-efa4d29c),
 *     and B's first message arrives within the first 3 passes that
 *     deliver anything. RED on the pre-H3 walk (always from slot 0, the
 *     whole step's messages at once): A's backlog would fill every pass.
 * PRECONDITIONS (the author never ran it): A's connection takes a lower
 * slot on R than B's because A dialed and was accepted first (the
 * transport hands out the lowest free slot), and R holds exactly two
 * peers, so the near-full threshold is room < 2.
 */
static void test_receive_fairness(void)
{
    node_params_t pr, pa, pb;
    node_t *R, *A, *B;
    cmt_p2p_peer_t *pAR, *pBR;
    cmt_p2p_netaddr_t addr;
    int ok = 1, i, pass, base, run_len = 0, run_who = -1, max_run = 0;
    int next[2] = { 0, 0 }, delivering_passes = 0, b_first_pass = -1;
    char m[16];

    TEST("receive fairness: room-for-one gate, one message per peer near full");
    params_default(&pr, "10.0.0.1", 4004);
    params_default(&pa, "10.0.0.2", 4004);
    params_default(&pb, "10.0.0.3", 4004);
    R = node_new("R", &pr);
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (R == NULL || A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    addr = addr_of(R);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&A->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    CHECK(cmt_p2p_switch_dial_peer_with_address(&B->sw, &addr) == CMT_P2P_ERR_NONE);
    run(40, 10 * MS);
    pAR = peer_of(A, R);
    pBR = peer_of(B, R);
    CHECK(n_peers(R) == 2 && pAR != NULL && pBR != NULL);
    if (pAR == NULL || pBR == NULL) {
        world_reset();
        FAIL("link");
        return;
    }
    base = R->n_msgs;
    R->q_cap = FAIR_QCAP;
    R->q_len = 0;
    for (i = 0; i < FAIR_MSGS; i++) {
        snprintf(m, sizeof(m), "A%02d", i);
        CHECK(cmt_p2p_peer_send(pAR, TEST_CH, (const uint8_t *)m, 3));
        snprintf(m, sizeof(m), "B%02d", i);
        CHECK(cmt_p2p_peer_send(pBR, TEST_CH, (const uint8_t *)m, 3));
    }
    for (pass = 0; pass < FAIR_PASSES && R->n_msgs - base < 2 * FAIR_MSGS; pass++) {
        int before = R->n_msgs;

        run(1, 20 * MS);
        if (R->n_msgs > before) {
            delivering_passes++;
        }
        for (i = before; i < R->n_msgs; i++) {
            int who = fair_who(R->msgs[i].src, A, B);
            bool both_pending;

            CHECK(who >= 0);
            if (who < 0 || next[who] >= FAIR_MSGS) {
                CHECK(who >= 0 && next[who] < FAIR_MSGS);   /* never twice */
                continue;
            }
            if (who == 1 && b_first_pass < 0) {
                b_first_pass = delivering_passes;
            }
            /* per-sender order, each message once */
            snprintf(m, sizeof(m), "%c%02d", who == 0 ? 'A' : 'B', next[who]);
            CHECK(R->msgs[i].len == 3 && memcmp(R->msgs[i].b, m, 3) == 0);
            /* runs count only while BOTH still had messages to deliver */
            both_pending = next[0] < FAIR_MSGS && next[1] < FAIR_MSGS;
            next[who]++;
            if (both_pending) {
                run_len = who == run_who ? run_len + 1 : 1;
                run_who = who;
                if (run_len > max_run) {
                    max_run = run_len;
                }
            }
        }
        CHECK(R->q_overflow == 0);
        R->q_len = 0;                        /* the lane drains the queue */
    }
    CHECK(R->q_overflow == 0);
    CHECK(next[0] == FAIR_MSGS && next[1] == FAIR_MSGS);
    CHECK(max_run <= 2);
    CHECK(b_first_pass >= 1 && b_first_pass <= 3);
    if (!ok) {
        printf("\n    delivered A %d B %d, longest run %d, B first on "
               "delivering pass %d, overflow %d", next[0], next[1], max_run,
               b_first_pass, R->q_overflow);
    }
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("fairness");
    }
}

/* ══ main ════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("test_p2p_switch — netaddress / node_info / peer / transport / switch "
           "port (P2P-PORT F3)\n");

    test_netaddr_parse();
    test_netaddr_ranges();
    test_id_derivation();
    test_node_info_codec();
    test_node_info_validate();
    test_connect_and_exchange();
    test_wrong_network();
    test_wrong_p2p_version();
    test_dial_pin();
    test_duplicate_id();
    test_duplicate_ip();
    test_inbound_limit();
    test_bonded_admitted();
    test_inbound_queue_full();
    test_handshake_timeout();
    test_node_info_timeout();
    test_dial_without_id();
    test_stale_job();
    test_stop_peer_for_error();
    test_persistent_redial();
    test_cross_dial();
    test_receive_fairness();
    test_socket_continuous_read();
    test_socket_blocked_receive();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
