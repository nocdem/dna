/**
 * @file nodus/tests/test_p2p_host.c
 * @brief The witness-free 4004 host (net/nodus_p2p_host.{h,c}, net-layer
 *        design 2026-10-19 §11, package N3) on its own: no witness, no
 *        chain, no bonded set — REAL loopback sockets, REAL ML-DSA-87 /
 *        ML-KEM-1024 keys and the REAL worker threads.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *  (1) THE HOST STANDS ALONE: two hosts A and B are built with
 *      nodus_p2p_host_init + nodus_p2p_host_start from fresh identities
 *      and an all-NULL policy (every row takes its neutral answer); no
 *      nodus_witness_t exists in this process. A listens on 127.0.0.1
 *      (port 0, the bound port read back); B names A as its only
 *      persistent peer, PEX off on both.
 *  (2) THE PERSISTENT DIAL CONNECTS: driving both hosts with
 *      nodus_p2p_host_poll, B's start-time dial (node.go:562-563) ends in
 *      a secret connection both switches admit — each peer set holds the
 *      other's ID, and that ID is the one derived from the other's ML-DSA
 *      key (cmt_p2p_pubkey_to_id), which only an authenticated handshake
 *      could produce.
 *  (3) A CALLER'S REACTOR CARRIES MESSAGES BOTH WAYS, EXACTLY ONCE: each
 *      host registers one test reactor on channel TEST_CH and lists
 *      TEST_CH in its NodeInfo (the caller's channel list); A sends a
 *      37-byte payload to B and B a 1500-byte payload to A (longer than
 *      one 1024-byte packet, so it is split and reassembled), then each a
 *      sentinel message behind it on the same channel. Each receiver's
 *      reactor gets exactly TWO messages, both on TEST_CH from the other
 *      host's ID: first the payload byte for byte, then the sentinel. The
 *      channel is ordered, so a duplicated payload would arrive before the
 *      sentinel and fail the count or the second message's bytes.
 *  (4) RESTART WITH THE PERSISTENT IDENTITY (design §8, Astra r1 #6): A
 *      is freed; B observes the loss (its peer set empties); A is built
 *      again with the SAME identity, data directory and port; B's
 *      persistent-peer redial (switch.go:344-358 reconnectToPeer) connects
 *      to it again, B's peer is A's same key-derived ID, the new A holds
 *      B, and (3) holds again over the new connection.
 *  (5) LIFECYCLE: a second nodus_p2p_host_start on a running host is
 *      refused; _start on a host whose init failed is refused;
 *      nodus_p2p_host_poll on a freed host answers -1.
 *  (6) FREE: both hosts are freed (switch stop, worker join, sockets
 *      closed) with no crash; nodus_p2p_host_free after a FAILED init
 *      releases nothing twice — both an init refused before anything is
 *      built (an identity without ML-KEM) and one refused AFTER the
 *      listener socket and the worker mutex exist (external_ip "x", not an
 *      IP literal), each freed twice.
 *  (7) CLEANUP: the temporary directory is removed — checked, a leftover
 *      file fails the test.
 *
 * TEST_CH = 0x7E: collides with no channel the 4004 host or the reference
 * uses — the reference's 0x00, 0x20-0x23, 0x30, 0x38, 0x40, 0x60, 0x61
 * (decision 2026-09-26-witness-port-session.md, "bayt/biçim onayları"
 * item 3) and nodus's 0x70-0x73 (nodus_witness_p2p.h). Its descriptor
 * values (priority 1, send queue 4, receive capacity 4096) are test
 * choices — ⚠ NOT GROUNDED, no reference channel carries this message.
 *
 * ── REQUIREMENTS ───────────────────────────────────────────────────────
 * The default nodus build (no compile flag, no environment variable).
 * Linux only (the CMake target is in the Linux test list). Two loopback
 * TCP ports chosen by the kernel (port 0) — no fixed port, so it can run
 * beside other tests; A's port is bound a second time for the restart
 * (SO_REUSEADDR, as the host always sets on Linux).
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * A temporary directory /tmp/test_p2p_host_XXXXXX with A/ and B/, each
 * holding the own-record seq file nodus.addr_seq (127.0.0.1 is a
 * specified address, so each host signs an ADDR record at start; A twice).
 * Removed on success (the removal is a CHECK); kept (its path logged) on
 * failure.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  · The waits are bounded by PASSES (MAX_PASSES rounds of one
 *    nodus_p2p_host_poll per host, 1 ms socket wait each), not by a clock;
 *    an expired cap is a FAIL, never a skip. The switch's timers run on the
 *    monotonic clock while the passes run: the start dial's randomizer (up
 *    to 3 s, CMT_P2P_DIAL_RANDOMIZER_INTERVAL_MS) and, in (4), B's redial —
 *    the first attempt runs at once and finds A's port closed, the next
 *    one comes CMT_P2P_RECONNECT_INTERVAL_NS (5 s) plus up to 3 s later.
 *    The cap is not tuned to a measurement: an idle pass waits at least
 *    1 ms per host, so MAX_PASSES covers ≥ 120 s, many times those 8 s.
 *  · The receive check is set ONLY by the test reactor's `receive` row
 *    (rx_t, written nowhere else) and compares against the exact buffers
 *    sent; a stale or foreign delivery fails the length / byte / sender
 *    check or the count. A duplicate arriving AFTER the sentinel and
 *    after the wait has ended is not seen.
 *  · (4) proves B reconnects to a host with the same identity on the same
 *    port; it does not prove the restarted A signs a NEWER ADDR record
 *    (PEX is off, no record is exchanged).
 *  · It does not exercise PEX, the address book file, an inbound limit, a
 *    bonded peer, backpressure (`may_receive`) or Windows — the host's
 *    witness path is test_witness_p2p's, its Windows build is a compile
 *    check only.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "net/nodus_p2p_host.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/utils/qgp_log.h"
#include "dnac/cmt_p2p_peer.h"

#define LOG_TAG "TEST_P2P_HOST"

/* The test channel (file header). */
#define TEST_CH        0x7E
/* Passes of the drive loop before a wait counts as failed (file header,
 * "HOW IT CAN LIE"). */
#define MAX_PASSES     60000

static int g_checks = 0;

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        QGP_LOG_ERROR(LOG_TAG, "CHECK failed at %s:%d: %s", __FILE__,      \
                      __LINE__, (msg));                                    \
        rc = 1;                                                            \
        goto out;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

/* ── identities: deterministic REAL ML-DSA-87 + ML-KEM-1024 pairs
 *    (test_witness_p2p.c ident_make's shape) ────────────────────────── */

static int ident_make(nodus_identity_t *id, uint8_t dsa_seed, uint8_t kem_coin)
{
    uint8_t seed[32];
    uint8_t coins[QGP_MLKEM1024_COINS_BYTES];

    memset(id, 0, sizeof(*id));
    memset(seed, dsa_seed, sizeof(seed));
    if (qgp_dsa87_keypair_derand(id->pk.bytes, id->sk.bytes, seed) != 0) {
        return -1;
    }
    if (qgp_sha3_512(id->pk.bytes, NODUS_PK_BYTES, id->node_id.bytes) != 0) {
        return -1;
    }
    memset(coins, kem_coin, sizeof(coins));
    if (qgp_mlkem1024_keypair_derand(id->mlkem_pk, id->mlkem_sk, coins) != 0) {
        return -1;
    }
    id->has_mlkem = true;
    return 0;
}

/* ── the test reactor on TEST_CH ────────────────────────────────────── */

#define RX_CAP  4096
/* Messages kept per receiver: the payload and the sentinel. Later ones
 * are counted, not kept. */
#define RX_KEEP 2

typedef struct {
    uint8_t ch;
    char    from[CMT_P2P_ID_CAP];
    uint8_t buf[RX_CAP];
    size_t  len;
} rx_msg_t;

typedef struct {
    int      n;                             /* messages received          */
    rx_msg_t m[RX_KEEP];                    /* the first RX_KEEP, in order */
} rx_t;

static const cmt_p2p_ch_desc_t g_test_desc[1] = { {
    .id = TEST_CH,
    .priority = 1,
    .send_queue_capacity = 4,
    .recv_buffer_capacity = 0,
    .recv_message_capacity = RX_CAP,
} };

static const cmt_p2p_ch_desc_t *t_channels(void *ctx, int *n)
{
    (void)ctx;
    *n = 1;
    return g_test_desc;
}

static void t_add_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    (void)ctx;
    (void)peer;
}

static void t_remove_peer(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    (void)ctx;
    (void)peer;
    (void)reason;
}

static void t_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                      const uint8_t *msg, size_t len)
{
    rx_t *rx = (rx_t *)ctx;

    if (rx->n < RX_KEEP) {
        rx_msg_t *m = &rx->m[rx->n];

        m->ch = ch_id;
        snprintf(m->from, sizeof(m->from), "%s", cmt_p2p_peer_id(src));
        m->len = len <= sizeof(m->buf) ? len : sizeof(m->buf);
        memcpy(m->buf, msg, m->len);
    }
    rx->n++;
}

/* ── hosts ─────────────────────────────────────────────────────────── */

/* Init + start one host on 127.0.0.1:`port` with the test reactor and an
 * all-NULL policy. `ext` = the external address ("" = none).
 * @return 0, or -1 (init or start refused). */
static int host_build(nodus_p2p_host_t *h, const nodus_identity_t *id,
                      const uint8_t chain[32], const nodus_p2p_config_t *cfg,
                      const char *dir, rx_t *rx, const char *ext,
                      uint16_t port)
{
    static const uint8_t chans[1] = { TEST_CH };
    nodus_p2p_host_params_t prm;
    cmt_p2p_reactor_t r;

    memset(&r, 0, sizeof(r));
    r.name = "TEST";
    r.ctx = rx;
    r.get_channels = t_channels;
    r.add_peer = t_add_peer;
    r.remove_peer = t_remove_peer;
    r.receive = t_receive;

    memset(&prm, 0, sizeof(prm));
    prm.identity = id;
    prm.chain_id = chain;
    prm.cfg = cfg;
    prm.listen_ip = "127.0.0.1";
    prm.listen_port = port;
    prm.external_ip = ext;
    prm.data_path = dir;
    prm.seq_dir = dir;
    prm.open_listener = true;
    prm.n_workers = 0;
    prm.channels = chans;
    prm.n_channels = 1;
    prm.reactors = &r;
    prm.n_reactors = 1;
    /* prm.policy all NULL: a witness-free host (PEX must then be off,
     * nodus_p2p_host.h (e)). */
    if (nodus_p2p_host_init(h, &prm) != 0) {
        return -1;
    }
    return nodus_p2p_host_start(h);
}

static void cfg_local(nodus_p2p_config_t *c)
{
    nodus_p2p_config_default(c);
    c->pex = false;
    c->addr_book_strict = false;
    c->allow_duplicate_ip = true;
}

typedef bool (*pred_fn)(void *ctx);

/* Poll both hosts in turn until `pred` holds; false after MAX_PASSES or
 * when a host is not running (poll answers -1). `a` may be NULL: then B
 * alone is driven. */
static bool drive(nodus_p2p_host_t *a, nodus_p2p_host_t *b, pred_fn pred,
                  void *ctx)
{
    int pass;

    for (pass = 0; pass < MAX_PASSES; pass++) {
        if ((a != NULL && nodus_p2p_host_poll(a, 1) != 0) ||
            nodus_p2p_host_poll(b, 1) != 0) {
            return false;
        }
        if (pred(ctx)) {
            return true;
        }
    }
    return false;
}

typedef struct {
    nodus_p2p_host_t *a, *b;
    rx_t *rxa, *rxb;
} pair_t;

static bool pred_linked(void *ctx)
{
    pair_t *x = (pair_t *)ctx;

    return nodus_p2p_host_has_peer(x->a, nodus_p2p_host_id(x->b)) &&
           nodus_p2p_host_has_peer(x->b, nodus_p2p_host_id(x->a));
}

static bool pred_b_alone(void *ctx)
{
    pair_t *x = (pair_t *)ctx;

    return nodus_p2p_host_peer_count(x->b) == 0;
}

static bool pred_both_rx2(void *ctx)
{
    pair_t *x = (pair_t *)ctx;

    return x->rxa->n >= RX_KEEP && x->rxb->n >= RX_KEEP;
}

/* One received message equals what `from` sent: channel, sender, bytes. */
static bool msg_is(const rx_msg_t *m, const char *from, const uint8_t *b,
                   size_t len)
{
    return m->ch == TEST_CH && strcmp(m->from, from) == 0 && m->len == len &&
           memcmp(m->buf, b, len) == 0;
}

/*
 * (3): A → B `ab` then the sentinel, B → A `ba` then the sentinel; drive
 * until each side holds two messages; each side must hold EXACTLY two —
 * the payload, then the sentinel. @return NULL, or what failed.
 */
static const char *exchange(pair_t *x, const char *ida, const char *idb,
                            const uint8_t *ab, size_t ab_len,
                            const uint8_t *ba, size_t ba_len)
{
    static const uint8_t sent_ab[3] = { 0x5E, 0xAB, 0x5E };
    static const uint8_t sent_ba[3] = { 0x5E, 0xBA, 0x5E };

    memset(x->rxa, 0, sizeof(*x->rxa));
    memset(x->rxb, 0, sizeof(*x->rxb));
    if (!nodus_p2p_host_send(x->a, idb, TEST_CH, ab, ab_len) ||
        !nodus_p2p_host_send(x->a, idb, TEST_CH, sent_ab, sizeof(sent_ab))) {
        return "A could not queue its payload + sentinel";
    }
    if (!nodus_p2p_host_send(x->b, ida, TEST_CH, ba, ba_len) ||
        !nodus_p2p_host_send(x->b, ida, TEST_CH, sent_ba, sizeof(sent_ba))) {
        return "B could not queue its payload + sentinel";
    }
    if (!drive(x->a, x->b, pred_both_rx2, x)) {
        return "the two messages each way did not all arrive";
    }
    if (x->rxb->n != RX_KEEP || x->rxa->n != RX_KEEP) {
        return "a receiver got more than two messages";
    }
    if (!msg_is(&x->rxb->m[0], ida, ab, ab_len)) {
        return "B's first message is not A's payload, byte for byte";
    }
    if (!msg_is(&x->rxb->m[1], ida, sent_ab, sizeof(sent_ab))) {
        return "B's second message is not A's sentinel";
    }
    if (!msg_is(&x->rxa->m[0], idb, ba, ba_len)) {
        return "A's first message is not B's payload, byte for byte";
    }
    if (!msg_is(&x->rxa->m[1], idb, sent_ba, sizeof(sent_ba))) {
        return "A's second message is not B's sentinel";
    }
    return NULL;
}

/* Remove the temporary tree (file header, "WHAT IT LEAVES BEHIND").
 * @return rmdir's answer for the root: non-zero when anything is left. */
static int rmrf(const char *root)
{
    char p[512];
    static const char *const sub[2] = { "A", "B" };
    int i;

    for (i = 0; i < 2; i++) {
        snprintf(p, sizeof(p), "%s/%s/nodus.addr_seq", root, sub[i]);
        (void)unlink(p);
        snprintf(p, sizeof(p), "%s/%s/nodus.addr_seq.tmp", root, sub[i]);
        (void)unlink(p);
        snprintf(p, sizeof(p), "%s/%s", root, sub[i]);
        (void)rmdir(p);
    }
    return rmdir(root);
}

int main(void)
{
    int rc = 0;
    static const uint8_t chain[32] = {
        0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
        0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
        0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
        0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c };
    static nodus_identity_t idA, idB, idX;
    static nodus_p2p_host_t A, B, X;
    static rx_t rxA, rxB, rxX;
    static uint8_t msgAB[37], msgBA[1500];
    char root[] = "/tmp/test_p2p_host_XXXXXX";
    char dirA[256], dirB[256], sA[CMT_P2P_NETADDR_STR_MAX];
    char wantA[CMT_P2P_ID_CAP], wantB[CMT_P2P_ID_CAP];
    nodus_p2p_config_t cfgA, cfgB;
    bool have_root = false;
    uint16_t portA;
    pair_t pr;
    const char *why;
    size_t i;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    have_root = true;
    snprintf(dirA, sizeof(dirA), "%s/A", root);
    snprintf(dirB, sizeof(dirB), "%s/B", root);
    CHECK(mkdir(dirA, 0700) == 0 && mkdir(dirB, 0700) == 0, "host dirs");

    CHECK(ident_make(&idA, 0xA1, 0xC1) == 0, "identity A");
    CHECK(ident_make(&idB, 0xB2, 0xC2) == 0, "identity B");
    CHECK(cmt_p2p_pubkey_to_id(idA.pk.bytes, wantA) == CMT_OK &&
          cmt_p2p_pubkey_to_id(idB.pk.bytes, wantB) == CMT_OK, "ids");

    /* (6) a failed init before anything is built — no ML-KEM key — then
     * free twice; (5) _start on it is refused. */
    CHECK(ident_make(&idX, 0xD3, 0xC3) == 0, "identity X");
    idX.has_mlkem = false;
    cfg_local(&cfgA);
    CHECK(host_build(&X, &idX, chain, &cfgA, dirA, &rxX, "", 0) != 0,
          "(6) a host without an ML-KEM key is refused");
    CHECK(nodus_p2p_host_start(&X) != 0, "(5) _start after a failed init is refused");
    nodus_p2p_host_free(&X);
    nodus_p2p_host_free(&X);               /* nothing is released twice */

    /* (6) a failed init that holds real resources: the listener socket
     * and the worker mutex exist when the external address "x" (not an IP
     * literal) is refused. */
    idX.has_mlkem = true;
    CHECK(host_build(&X, &idX, chain, &cfgA, dirA, &rxX, "x", 0) != 0,
          "(6) external_ip \"x\" is refused");
    nodus_p2p_host_free(&X);
    nodus_p2p_host_free(&X);               /* nothing is released twice */

    /* (1) A: listener, no peers. */
    cfg_local(&cfgA);
    CHECK(host_build(&A, &idA, chain, &cfgA, dirA, &rxA, "", 0) == 0, "(1) host A");
    CHECK(strcmp(nodus_p2p_host_id(&A), wantA) == 0, "(1) A's id is its key's");
    portA = nodus_p2p_host_listen_port(&A);
    CHECK(portA != 0, "(1) A listens");
    CHECK(nodus_p2p_host_start(&A) != 0, "(5) a second _start is refused");

    /* (1) B: A as its persistent peer. */
    cfg_local(&cfgB);
    snprintf(sA, sizeof(sA), "%s@127.0.0.1:%u", wantA, (unsigned)portA);
    CHECK(nodus_p2p_config_add_persistent(&cfgB, sA) == 0, "(1) B persistent A");
    CHECK(host_build(&B, &idB, chain, &cfgB, dirB, &rxB, "", 0) == 0, "(1) host B");

    /* (2) the persistent dial connects. */
    memset(&pr, 0, sizeof(pr));
    pr.a = &A;
    pr.b = &B;
    pr.rxa = &rxA;
    pr.rxb = &rxB;
    CHECK(drive(&A, &B, pred_linked, &pr), "(2) A and B connected");
    CHECK(nodus_p2p_host_peer_count(&A) == 1 &&
          nodus_p2p_host_peer_count(&B) == 1, "(2) one peer each");
    {
        char got[CMT_P2P_ID_CAP];

        CHECK(nodus_p2p_host_peer_id_at(&A, 0, got) && strcmp(got, wantB) == 0,
              "(2) A's peer is B's key's ID");
        CHECK(nodus_p2p_host_peer_id_at(&B, 0, got) && strcmp(got, wantA) == 0,
              "(2) B's peer is A's key's ID");
    }
    CHECK(rxA.n == 0 && rxB.n == 0, "(3) nothing received before sending");

    /* (3) payload + sentinel each way on TEST_CH, exactly once. */
    for (i = 0; i < sizeof(msgAB); i++) {
        msgAB[i] = (uint8_t)(0x11 + 3 * i);
    }
    for (i = 0; i < sizeof(msgBA); i++) {
        msgBA[i] = (uint8_t)(0xE7 ^ (i * 7));
    }
    why = exchange(&pr, wantA, wantB, msgAB, sizeof(msgAB), msgBA, sizeof(msgBA));
    CHECK(why == NULL, why);

    /* (4) restart A with its persistent identity. */
    nodus_p2p_host_free(&A);
    CHECK(nodus_p2p_host_poll(&A, 1) == -1, "(5) poll on a freed host is -1");
    CHECK(nodus_p2p_host_listen_port(&A) == 0, "(5) a freed host answers neutral");
    CHECK(drive(NULL, &B, pred_b_alone, &pr), "(4) B saw A go");
    memset(&rxA, 0, sizeof(rxA));
    cfg_local(&cfgA);
    CHECK(host_build(&A, &idA, chain, &cfgA, dirA, &rxA, "", portA) == 0,
          "(4) A rebuilt: same identity, data directory and port");
    CHECK(nodus_p2p_host_listen_port(&A) == portA, "(4) A listens on its old port");
    CHECK(strcmp(nodus_p2p_host_id(&A), wantA) == 0, "(4) A's id is unchanged");
    CHECK(drive(&A, &B, pred_linked, &pr), "(4) B reconnected to A");
    CHECK(nodus_p2p_host_peer_count(&A) == 1 &&
          nodus_p2p_host_peer_count(&B) == 1, "(4) one peer each");
    {
        char got[CMT_P2P_ID_CAP];

        CHECK(nodus_p2p_host_peer_id_at(&B, 0, got) && strcmp(got, wantA) == 0,
              "(4) B's peer is A's same key-derived ID");
        CHECK(nodus_p2p_host_peer_id_at(&A, 0, got) && strcmp(got, wantB) == 0,
              "(4) the new A's peer is B");
    }
    why = exchange(&pr, wantA, wantB, msgAB, sizeof(msgAB), msgBA, sizeof(msgBA));
    CHECK(why == NULL, why);

    /* (6) free; (5) a freed host does not run; (7) the tree is gone. */
    nodus_p2p_host_free(&B);
    nodus_p2p_host_free(&A);
    CHECK(nodus_p2p_host_poll(&B, 1) == -1, "(5) poll on a freed host is -1");
    CHECK(rmrf(root) == 0, "(7) the temporary directory is removed");
    have_root = false;

out:
    /* (6) free — also after a failed build (the header's contract); a
     * host never built is all zero (static), which _free treats as empty;
     * a host freed above is freed again harmlessly. */
    nodus_p2p_host_free(&B);
    nodus_p2p_host_free(&A);
    nodus_p2p_host_free(&X);
    if (rc == 0) {
        QGP_LOG_INFO(LOG_TAG, "test_p2p_host: all %d checks passed", g_checks);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "test_p2p_host: FAILED (%d checks passed "
                      "before the failure; %s left behind)", g_checks,
                      have_root ? root : "nothing");
    }
    return rc;
}
