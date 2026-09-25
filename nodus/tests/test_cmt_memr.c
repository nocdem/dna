/**
 * Nodus — cometbft @709fd12b C port, wave R3-M: the mempool reactor of
 * `shared/dnac/cmt_memr.c`, ported from `mempool/reactor_test.go`
 * (INACTIVE layer).
 *
 * Every case names the Go `func Test…` it comes from and its line; an
 * assertion STRONGER or WEAKER than the reference's is labelled at the
 * site. The reference connects N reactors through N real p2p switches
 * (`makeAndConnectReactors`, :321-340, `p2p.MakeConnectedSwitches` and
 * `Connect2Switches`, which this wave did not open); here the switch is
 * an IN-MEMORY one inside this file, described under "THE SWITCH".
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the ported reactor floods every transaction to every peer that
 * did not send it, in mempool order, one per message, and stops where
 * the reference stops. If this file failed, one of these would be false:
 *   · a thousand transactions given to one node arrive at its peer IN
 *     THE SAME ORDER (:41-64), through a link that refuses most sends —
 *     so the R3-M-1 "sleep 100 ms and retry the SAME transaction" path
 *     (:243-246) is exercised on nearly every message, and the peer
 *     never sends them back to the node that sent them (:238);
 *   · transactions whose sender id is the peer's are never sent to that
 *     peer (:128-148);
 *   · a transaction of exactly MaxTxBytes crosses the wire and arrives;
 *     one byte more is refused at CheckTx (:150-187);
 *   · sixty-five thousand five hundred and thirty-seven peers can be
 *     initialised, refused for a bad message, added and removed without
 *     a FAULT and without exhausting the id space (:237-260, INTENT —
 *     see the case);
 *   · with the experimental non-persistent limit at 1, only the first
 *     peer in slot order is gossiped to; when it is removed the next
 *     waiting peer takes its place and the last stays silent (:267-305);
 *   · a peer added AFTER a slot was released but WHILE another peer is
 *     still waiting does not take the slot — it waits behind the waiter,
 *     the tick serves the waiter first, and a newcomer with nobody
 *     waiting starts at once (golang.org/x/sync v0.11.0 semaphore.go:52,
 *     :69-71, :133-160 — pin rev 17, lines as corrected in rev 18; the
 *     port's own case, no reference test drives that moment);
 *   · removing a peer ends its routine and releases its semaphore slot;
 *     stopping the reactor ends every routine (:189-231, as cursor-ended
 *     checks — see the cases);
 *   · the channel descriptor is {0x30, 5, Message{Txs{[MaxTxBytes]}}
 *     .Size()} and that size is the oracle's (:71-89);
 *   · on receive: undecodable bytes, a Message with no sum, and a
 *     payload above the capacity STOP THE PEER; an empty Txs does not;
 *     an unknown field is skipped; a multi-tx Txs is admitted whole;
 *     the sender id recorded on a received transaction is the peer's
 *     mempool id (:140-177 and p2p/peer.go:407-422);
 *   · the three sleep sites (:219, :231, :244) each defer the routine by
 *     exactly 100 ms of the host's clock and leave the cursor where it
 *     was, and the tick reports the earliest deadline;
 *   · a cursor resting on an element that Update then removes restarts
 *     from the front on the next tick (:195-208), and — reference quirk,
 *     reproduced — a removed element the cursor was sleeping on is still
 *     SENT once the sleep ends (:238-247 never consult Removed()).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION`, which the nodus build defines
 *   for every cmt_* target (cmt_memr.c does not read it). NOTHING ELSE —
 *   a DEFAULT BUILD is enough; `QGP_FAULT_INJECT` does not matter.
 * ENVIRONMENT: none. No variable is read or written.
 * No network, no files, no threads, NO WALL CLOCK — `now` is this file's
 * counter, advanced by 100 ms per round — no randomness.
 * CONFIG: `cmt_mempool_config_default()` unless a case sets a field (the
 * reference's `cfg.TestConfig()` differs only in CacheSize, which no
 * case here depends on). The application is the kvstore stand-in of
 * test_cmt_mem.c (kvstore.go:130-158; a TEST STAND-IN).
 * MEMORY: a 4-node network is four reactors of ≈ 10.4 MB decode storage
 * each (cmt_memr.h "DECODE STORAGE") plus the 1 MiB transaction case —
 * all heap, nothing large on the stack.
 *
 * ── THE SWITCH ─────────────────────────────────────────────────────────
 * N nodes, indices 0..N-1. At node i, peer j sits in SLOT j (slot index
 * == node index), so node 0's first peer in slot order is node 1 and
 * every other node's first peer is node 0 — the ordering
 * TestMempoolReactorMaxActiveOutboundConnections observes (:264-266 says
 * the reference's own outcome depends on the p2p add order). Every
 * ordered pair (i, j) has a LINK: a bounded FIFO of message copies
 * (LINK_QUEUE_CAP); `send` returns false when it is full, which is the
 * non-blocking substitute of R3-M-1. A ROUND is: every reactor ticks in
 * node order; every link delivers everything it holds, in (src, dst,
 * FIFO) order, through `cmt_memr_receive`; the clock advances 100 ms.
 * "Wait for N txs" is a bounded number of rounds whose exhaustion is a
 * CHECK failure — never a silent pass. Peer heights are the test's
 * table (`peerState{1}`, :56-60). `stop_peer_for_error` only COUNTS;
 * the test removes the peer itself when the case needs it.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. Every node and every queued message is freed on the success
 * path; a CHECK failure returns early and leaks, which is acceptable in
 * a failing test process.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The switch is this file's, not p2p's. Delivery order within a
 *     round, the add order of peers and the FIFO of a link are choices
 *     made here to be deterministic; where the reference's own outcome
 *     depends on its p2p order (the semaphore case), this file pins the
 *     port's rule (slot order among waiters), not the reference's
 *     arrival order — only the "no newcomer overtakes a waiter" half of
 *     semaphore.go's FIFO is pinned as the library states it.
 *  2. "Arrives in order" is proven through `ReapMaxTxs` on the receiving
 *     mempool, exactly as the reference's `checkTxsInOrder` (:394-403);
 *     the reactor's own cursor is not read for it.
 *  3. The convergence bound (MAX_ROUNDS) is generous; a regression that
 *     merely makes gossip slower would still pass.
 *  4. The stand-in application accepts everything the tests send; a
 *     defect in the reactor's handling of an application REFUSAL on the
 *     receiving side is not exercised (the mempool tests cover it).
 *  5. NO GO IMPLEMENTATION IS RUN.
 *
 * ── NOT PORTED — BLOCKED BY ────────────────────────────────────────────
 *   · `TestReactorConcurrency` (:67-124): a regression for a data race
 *     between `Update` under `Lock` and `Flush` running in goroutines
 *     (cometbft#5408); its content is the race, which has no meaning
 *     single-threaded. The sequential calls it makes are covered by
 *     test_cmt_mem.c's Update/Flush cases.
 *   · `TestBroadcastTxForPeerStopsWhenPeerStops` (:189-212) and
 *     `TestBroadcastTxForPeerStopsWhenReactorStops` (:214-231) are
 *     goroutine-LEAK checks (`leaktest`); their whole content — "the
 *     routine ends" — is ported as the cursor-ended checks below, which
 *     is what a routine ending looks like here.
 *
 * @file test_cmt_memr.c
 */

#include "dnac/cmt_memr.h"
#include "dnac/cmt_mem.h"
#include "dnac/cmt_pb_mempool.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define V_MEM_RECV_MESSAGE_CAPACITY 1048584   /* cmt_pb_oracle.py, R3-M */

/* ══ the application stand-in (kvstore.go:130-158, as test_cmt_mem.c) ═ */

typedef struct {
    int check_tx_calls;
    int recheck_calls;
} tapp_t;

static bool kv_is_valid_tx(const uint8_t *tx, size_t len)
{
    size_t colons = 0, equals = 0, i;

    for (i = 0; i < len; i++) {
        if (tx[i] == ':') { colons++; }
        if (tx[i] == '=') { equals++; }
    }
    if (colons == 1 && equals == 0) {
        return !(len > 0 && tx[0] == ':') && !(len > 0 && tx[len - 1] == ':');
    }
    if (equals == 1 && colons == 0) {
        return !(len > 0 && tx[0] == '=') && !(len > 0 && tx[len - 1] == '=');
    }
    return false;
}

static int tapp_check_tx(void *ctx, const cmt_mem_request_check_tx_t *req,
                         cmt_mem_response_check_tx_t *res)
{
    tapp_t *a = (tapp_t *)ctx;

    a->check_tx_calls++;
    if (req->type == CMT_MEM_CHECK_TX_TYPE_RECHECK) {
        a->recheck_calls++;
    }
    if (!kv_is_valid_tx(req->tx, req->tx_len)) {
        res->code = 2u;   /* kvstore/code.go:7 CodeTypeInvalidTxFormat */
        return CMT_OK;
    }
    res->code       = CMT_MEM_CODE_TYPE_OK;
    res->gas_wanted = 1;
    return CMT_OK;
}

static int tapp_error(void *ctx) { (void)ctx; return CMT_OK; }
static int tapp_flush(void *ctx) { (void)ctx; return CMT_OK; }

/* ══ transactions (helpers.go, as test_cmt_mem.c) ═════════════════════ */

static const char ALPHABET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* helpers.go:66-68 — NewTxFromID(i) */
static size_t tx_from_id(uint8_t *out, size_t cap, int i)
{
    int n = snprintf((char *)out, cap, "%d=%d", i, i);

    return (n < 0) ? 0 : (size_t)n;
}

/* helpers.go:51-56 — NewRandomTx(size), deterministic (test_cmt_mem.c). */
static size_t tx_random(uint8_t *out, size_t size, unsigned seq)
{
    size_t vlen = size - 3u;
    size_t i;

    out[0] = (uint8_t)ALPHABET[(seq / 62u) % 62u];
    out[1] = (uint8_t)ALPHABET[seq % 62u];
    out[2] = '=';
    if (vlen >= 10u) {
        char dec[16];

        snprintf(dec, sizeof(dec), "%010u", seq);
        memcpy(out + 3, dec, 10);
        for (i = 10; i < vlen; i++) {
            out[3 + i] = (uint8_t)ALPHABET[(seq * 7u + (unsigned)i * 13u) % 62u];
        }
    } else {
        for (i = 0; i < vlen; i++) {
            out[3 + i] = (uint8_t)ALPHABET[(seq * 7u + (unsigned)i * 13u) % 62u];
        }
    }
    return size;
}

typedef struct {
    uint8_t        *buf;
    cmt_pb_bytes_t *v;
    size_t          n;
} txlist_t;

static unsigned g_seq = 1;

static int txlist_random(txlist_t *l, size_t n, size_t tx_len)
{
    size_t i;

    l->buf = (uint8_t *)malloc(n * tx_len + 1u);
    l->v   = (cmt_pb_bytes_t *)calloc(n + 1u, sizeof(*l->v));
    l->n   = n;
    if (l->buf == NULL || l->v == NULL) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        l->v[i].data = l->buf + i * tx_len;
        l->v[i].len  = tx_random(l->buf + i * tx_len, tx_len, g_seq++);
    }
    return 0;
}

/* reactor_test.go:342-348 — newUniqueTxs(n) */
static int txlist_unique(txlist_t *l, size_t n)
{
    size_t i;

    l->buf = (uint8_t *)malloc(n * 32u + 1u);
    l->v   = (cmt_pb_bytes_t *)calloc(n + 1u, sizeof(*l->v));
    l->n   = n;
    if (l->buf == NULL || l->v == NULL) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        l->v[i].data = l->buf + i * 32u;
        l->v[i].len  = tx_from_id(l->buf + i * 32u, 32u, (int)i);
    }
    return 0;
}

static void txlist_free(txlist_t *l)
{
    free(l->buf);
    free(l->v);
    memset(l, 0, sizeof(*l));
}

/* ══ THE SWITCH ═══════════════════════════════════════════════════════ */

#define NET_MAX_NODES  4
#define LINK_QUEUE_CAP 16
#define MAX_ROUNDS     20000
#define CAPTURE_CAP    8

typedef struct {
    uint8_t *buf;
    size_t   len;
} qmsg_t;

typedef struct {
    qmsg_t q[LINK_QUEUE_CAP];
    size_t head;
    size_t count;
    size_t sent_total;       /* every successful send, ever */
    size_t refused_total;    /* every send that returned false */
} link_t;

typedef struct net net_t;

typedef struct {
    net_t                *net;
    int                   idx;
    cmt_mempool_config_t  cfg;
    tapp_t                app;
    cmt_mem_app_t         app_if;
    cmt_mem_t             mem;
    cmt_memr_host_t       host;
    cmt_memr_t            memR;
    int64_t               peer_height[CMT_MEM_MAX_PEERS];
    bool                  peer_known[CMT_MEM_MAX_PEERS];
    int                   stop_calls;
    int                   last_stopped_slot;
    bool                  link_full_override;   /* every send returns false */
    /* a solo node (no links) captures what it sends */
    qmsg_t                captured[CAPTURE_CAP];
    size_t                captured_n;
    int                   captured_slot;
} node_t;

struct net {
    node_t    *nodes[NET_MAX_NODES];
    int        n;
    link_t     links[NET_MAX_NODES][NET_MAX_NODES];
    cmt_time_t now;
};

static bool host_send(void *ctx, int peer_slot, uint8_t channel_id,
                      const uint8_t *msg, size_t msg_len)
{
    node_t *node = (node_t *)ctx;
    net_t  *net  = node->net;
    link_t *link;
    qmsg_t *m;

    if (channel_id != (uint8_t)CMT_MEM_CHANNEL) {
        return false;
    }
    if (node->link_full_override) {
        if (peer_slot >= net->n) {
            /* a solo node: nothing to count */
        } else {
            net->links[node->idx][peer_slot].refused_total++;
        }
        return false;
    }
    if (peer_slot >= net->n || peer_slot == node->idx) {
        /* a solo node's "peer": capture the message */
        if (node->captured_n >= CAPTURE_CAP) {
            return false;
        }
        m = &node->captured[node->captured_n];
        m->buf = (uint8_t *)malloc(msg_len + 1u);
        if (m->buf == NULL) {
            return false;
        }
        memcpy(m->buf, msg, msg_len);
        m->len = msg_len;
        node->captured_n++;
        node->captured_slot = peer_slot;
        return true;
    }
    link = &net->links[node->idx][peer_slot];
    if (link->count >= LINK_QUEUE_CAP) {
        link->refused_total++;
        return false;
    }
    m = &link->q[(link->head + link->count) % LINK_QUEUE_CAP];
    m->buf = (uint8_t *)malloc(msg_len + 1u);
    if (m->buf == NULL) {
        return false;
    }
    memcpy(m->buf, msg, msg_len);
    m->len = msg_len;
    link->count++;
    link->sent_total++;
    return true;
}

static void host_stop_peer_for_error(void *ctx, int peer_slot)
{
    node_t *node = (node_t *)ctx;

    node->stop_calls++;
    node->last_stopped_slot = peer_slot;
}

static int64_t host_peer_height(void *ctx, int peer_slot, bool *out_known)
{
    node_t *node = (node_t *)ctx;

    if (peer_slot < 0 || peer_slot >= (int)CMT_MEM_MAX_PEERS) {
        *out_known = false;
        return 0;
    }
    *out_known = node->peer_known[peer_slot];
    return node->peer_height[peer_slot];
}

static int host_now(void *ctx, cmt_time_t *out)
{
    node_t *node = (node_t *)ctx;

    *out = node->net->now;
    return CMT_OK;
}

static void net_advance_ms(net_t *net, int64_t ms)
{
    int64_t nanos = (int64_t)net->now.nanos + ms * (int64_t)1000000;

    net->now.seconds += nanos / (int64_t)1000000000;
    net->now.nanos    = (int32_t)(nanos % (int64_t)1000000000);
}

/* reactor_test.go:321-340 — makeAndConnectReactors, minus the switches. */
static int net_make(net_t *net, int n, const cmt_mempool_config_t *cfg)
{
    int i;

    memset(net, 0, sizeof(*net));
    net->n = n;
    net->now.seconds = 1700000000;   /* an arbitrary frozen start */
    net->now.nanos   = 0;
    for (i = 0; i < n; i++) {
        node_t *node = (node_t *)calloc(1, sizeof(*node));
        size_t  s;

        if (node == NULL) {
            return 1;
        }
        net->nodes[i] = node;
        node->net = net;
        node->idx = i;
        node->cfg = *cfg;
        node->app_if.ctx      = &node->app;
        node->app_if.error    = tapp_error;
        node->app_if.check_tx = tapp_check_tx;
        node->app_if.flush    = tapp_flush;
        if (cmt_mem_init(&node->mem, &node->cfg, &node->app_if, 0, NULL, NULL) != CMT_OK) {
            return 1;                                         /* :325-327 */
        }
        node->host.ctx                 = node;
        node->host.send                = host_send;
        node->host.stop_peer_for_error = host_stop_peer_for_error;
        node->host.peer_height         = host_peer_height;
        node->host.now                 = host_now;
        if (cmt_memr_init(&node->memR, &node->cfg, &node->mem, &node->host) != CMT_OK) {
            return 1;                                         /* :330 */
        }
        for (s = 0; s < CMT_MEM_MAX_PEERS; s++) {             /* :56-60 peerState{1} */
            node->peer_height[s] = 1;
            node->peer_known[s]  = true;
        }
    }
    return 0;
}

/* Start every reactor, then connect every ordered pair: InitPeer then
 * AddPeer (the switch's order), peers in ascending node order. */
static int net_connect_full(net_t *net)
{
    int i, j;

    for (i = 0; i < net->n; i++) {
        if (cmt_memr_start(&net->nodes[i]->memR) != CMT_OK) {
            return 1;
        }
    }
    for (i = 0; i < net->n; i++) {
        for (j = 0; j < net->n; j++) {
            if (j == i) {
                continue;
            }
            if (cmt_memr_init_peer(&net->nodes[i]->memR, j) != CMT_OK) {
                return 1;
            }
            if (cmt_memr_add_peer(&net->nodes[i]->memR, j, false, false) != CMT_OK) {
                return 1;
            }
        }
    }
    return 0;
}

/* One round: tick, deliver, advance. Returns 0 or a FAULT count. */
static int net_round(net_t *net)
{
    int faults = 0;
    int i, src, dst;

    for (i = 0; i < net->n; i++) {
        if (cmt_memr_tick(&net->nodes[i]->memR, NULL, NULL) != CMT_OK) {
            faults++;
        }
    }
    for (src = 0; src < net->n; src++) {
        for (dst = 0; dst < net->n; dst++) {
            link_t *link = &net->links[src][dst];

            while (link->count > 0) {
                qmsg_t *m = &link->q[link->head];
                int     rc;

                rc = cmt_memr_receive(&net->nodes[dst]->memR, src, m->buf, m->len,
                                      NULL, 0);
                if (rc == CMT_FAULT) {
                    faults++;
                }
                free(m->buf);
                m->buf = NULL;
                link->head = (link->head + 1u) % LINK_QUEUE_CAP;
                link->count--;
            }
        }
    }
    net_advance_ms(net, 100);
    return faults;
}

/* reactor_test.go:375-380 — waitForNumTxsInMempool, bounded. Returns 0
 * when the pool holds at least n; 1 on the bound or a FAULT. */
static int net_wait_for_num_txs(net_t *net, int node, size_t n)
{
    int r;

    for (r = 0; r < MAX_ROUNDS; r++) {
        if ((size_t)cmt_mem_size(&net->nodes[node]->mem) >= n) {
            return 0;
        }
        if (net_round(net) != 0) {
            return 1;
        }
    }
    return 1;
}

/* reactor_test.go:394-403 — checkTxsInOrder: ReapMaxTxs(len) equals txs
 * element for element. */
static int net_check_txs_in_order(net_t *net, int node, const txlist_t *txs)
{
    cmt_pb_bytes_t *reaped = (cmt_pb_bytes_t *)calloc(txs->n + 2u, sizeof(*reaped));
    size_t          n = 0;
    size_t          i;
    int             bad = 0;

    if (reaped == NULL) {
        return 1;
    }
    if (net_wait_for_num_txs(net, node, txs->n) != 0) {
        free(reaped);
        return 1;
    }
    if (cmt_mem_reap_max_txs(&net->nodes[node]->mem, (int)txs->n, reaped, txs->n + 2u, &n) != CMT_OK) {
        free(reaped);
        return 1;
    }
    for (i = 0; i < txs->n; i++) {                            /* :399-402 */
        if (i >= n || reaped[i].len != txs->v[i].len ||
            memcmp(reaped[i].data, txs->v[i].data, reaped[i].len) != 0) {
            bad = 1;
            break;
        }
    }
    free(reaped);
    return bad;
}

static void net_free(net_t *net)
{
    int i, j;

    for (i = 0; i < net->n; i++) {
        for (j = 0; j < net->n; j++) {
            link_t *link = &net->links[i][j];

            while (link->count > 0) {
                free(link->q[link->head].buf);
                link->head = (link->head + 1u) % LINK_QUEUE_CAP;
                link->count--;
            }
        }
    }
    for (i = 0; i < net->n; i++) {
        node_t *node = net->nodes[i];
        size_t  k;

        if (node == NULL) {
            continue;
        }
        for (k = 0; k < node->captured_n; k++) {
            free(node->captured[k].buf);
        }
        cmt_memr_free(&node->memR);
        cmt_mem_free(&node->mem);
        free(node);
        net->nodes[i] = NULL;
    }
}

static void node_clear_captures(node_t *node)
{
    size_t k;

    for (k = 0; k < node->captured_n; k++) {
        free(node->captured[k].buf);
        node->captured[k].buf = NULL;
    }
    node->captured_n = 0;
}

/* clist_mempool_test.go:101-133 — addRandomTxs(count, peerID) */
static int add_random_txs(cmt_mem_t *mem, size_t count, uint16_t peer_id, txlist_t *out)
{
    cmt_mem_tx_info_t info;
    size_t            i;

    if (txlist_random(out, count, 20) != 0) {
        return 1;
    }
    memset(&info, 0, sizeof(info));
    info.sender_id = peer_id;
    for (i = 0; i < out->n; i++) {
        cmt_mem_error_t err;
        int rc = cmt_mem_check_tx(mem, out->v[i].data, out->v[i].len, &info, NULL, &err);

        if (rc == CMT_REJECT && cmt_mem_is_pre_check_error(&err)) {
            continue;
        }
        if (rc != CMT_OK) {
            return 1;
        }
    }
    return 0;
}

/* Expected wire of one tx: Message{Txs{[tx]}} (reactor.go:239-242). */
static int expected_msg(const uint8_t *tx, size_t len, uint8_t *out, size_t cap, size_t *out_len)
{
    cmt_pb_bytes_t           one;
    cmt_pb_mempool_message_t m;

    one.data = tx;
    one.len  = len;
    m.txs.txs = &one; m.txs.txs_cap = 1;   /* slots first: `_init` keeps them */
    cmt_pb_mempool_message_init(&m);
    m.sum = CMT_PB_MEMPOOL_MSG_TXS;
    m.txs.txs_len = 1;
    return cmt_pb_mempool_message_marshal(&m, out, cap, out_len);
}

/* ══ cases ════════════════════════════════════════════════════════════ */

/* reactor.go:71-89 — GetChannels */
static int t_get_channels(void)
{
    net_t *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    cmt_memr_channel_descriptor_t d;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 1, &cfg) == 0, "one node");
    CHECK(cmt_memr_get_channels(&net->nodes[0]->memR, &d) == CMT_OK, "GetChannels");
    CHECK(d.id == 0x30, "MempoolChannel 0x30 (mempool.go:13, reactor.go:81)");
    CHECK(d.priority == 5, "Priority 5 (:82)");
    CHECK(d.recv_message_capacity == V_MEM_RECV_MESSAGE_CAPACITY,
          "RecvMessageCapacity = Message{Txs{[1 MiB]}}.Size() = 1048584 (:83, oracle)");
    CHECK(net->nodes[0]->memR.recv_message_capacity == V_MEM_RECV_MESSAGE_CAPACITY,
          "the reactor sized its storage from it");
    CHECK(cmt_memr_get_channels(NULL, &d) == CMT_FAULT && cmt_memr_get_channels(&net->nodes[0]->memR, NULL) == CMT_FAULT,
          "NULL");
    net_free(net);

    /* MaxTxBytes 0: 1 + 1 + (1 + 1 + 0) = 4. */
    cfg.max_tx_bytes = 0;
    CHECK(net_make(net, 1, &cfg) == 0, "one node");
    CHECK(cmt_memr_get_channels(&net->nodes[0]->memR, &d) == CMT_OK && d.recv_message_capacity == 4,
          "capacity 4 at MaxTxBytes 0");
    net_free(net);
    OK();

    /* Init refusals. */
    {
        node_t *node = (node_t *)calloc(1, sizeof(*node));
        cmt_memr_t r;

        CHECK(node != NULL, "alloc");
        cfg.max_tx_bytes = -1;
        CHECK(cmt_memr_init(&r, &cfg, &node->mem, &node->host) == CMT_FAULT, "negative MaxTxBytes");
        CHECK(cmt_memr_init(NULL, &cfg, &node->mem, &node->host) == CMT_FAULT, "NULL");
        CHECK(cmt_memr_init(&r, &cfg, NULL, &node->host) == CMT_FAULT, "NULL mempool");
        cmt_memr_free(NULL);
        free(node);
    }
    OK();
    free(net);
    return 0;
}

/* reactor_test.go:41-64 — TestReactorBroadcastTxsMessage. N = 2,
 * numTxs = 1000 (:27), all to reactor 0 with UnknownPeerID, checked in
 * order on both (:62-63). */
static int t_broadcast_txs_message(void)
{
    net_t   *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    txlist_t txs;
    int      r;
    bool     saw_deadline = false;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 2, &cfg) == 0, "makeAndConnectReactors(2)");
    CHECK(net_connect_full(net) == 0, "connect");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 1) == CMT_MEMR_ROUTINE_RUNNING,
          "node 0's routine for node 1 is running (unlimited: no semaphore)");

    CHECK(add_random_txs(&net->nodes[0]->mem, 1000, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0,
          "addRandomTxs(1000) (:62)");
    CHECK(cmt_mem_size(&net->nodes[0]->mem) == 1000, "all admitted at node 0");

    /* Run rounds until node 1 has them, watching the tick's deadline so
     * the R3-M-1 path is known to have run. */
    for (r = 0; r < MAX_ROUNDS && cmt_mem_size(&net->nodes[1]->mem) < 1000; r++) {
        int64_t dl = 0;
        bool    has = false;
        int     i, src, dst;

        for (i = 0; i < net->n; i++) {
            CHECK(cmt_memr_tick(&net->nodes[i]->memR, &dl, &has) == CMT_OK, "tick");
            if (i == 0 && has) {
                saw_deadline = true;
                CHECK(dl == cmt_time_unix_nano(net->now) + CMT_MEMR_PEER_CATCHUP_SLEEP_NS,
                      "the deadline is now + 100 ms (R3-M-1, :244)");
            }
        }
        for (src = 0; src < net->n; src++) {
            for (dst = 0; dst < net->n; dst++) {
                link_t *link = &net->links[src][dst];

                while (link->count > 0) {
                    qmsg_t *m = &link->q[link->head];

                    CHECK(cmt_memr_receive(&net->nodes[dst]->memR, src, m->buf, m->len, NULL, 0) == CMT_OK,
                          "receive");
                    free(m->buf);
                    m->buf = NULL;
                    link->head = (link->head + 1u) % LINK_QUEUE_CAP;
                    link->count--;
                }
            }
        }
        net_advance_ms(net, 100);
    }
    CHECK(r < MAX_ROUNDS, "Timed out waiting for txs (:370)");
    CHECK(net_check_txs_in_order(net, 1, &txs) == 0, "checkTxsInOrder on reactor 1 (:63)");
    CHECK(net_check_txs_in_order(net, 0, &txs) == 0, "checkTxsInOrder on reactor 0 (:63)");
    OK();

    /* STRONGER than the reference: the link refused most sends (the
     * queue holds 16 of 1000), so the retry-same-tx path ran; and
     * nothing went back from 1 to 0 (:238). */
    CHECK(net->links[0][1].refused_total > 0 && saw_deadline,
          "R3-M-1 exercised: sends were refused and the tick reported a deadline");
    CHECK(net->links[0][1].sent_total == 1000, "exactly one message per tx, 0 → 1");
    CHECK(net->links[1][0].sent_total == 0, "nothing sent back to the sender (:238)");
    CHECK(net->nodes[0]->stop_calls == 0 && net->nodes[1]->stop_calls == 0, "no peer stopped");
    CHECK(net->nodes[1]->app.check_tx_calls == 1000, "node 1 asked its app once per tx");
    OK();

    /* After a few quiet rounds both routines are still RUNNING and
     * parked on their own list's tail (:250): node 1 gossips to node 0,
     * the sender of every tx, so it walks without sending. */
    for (r = 0; r < 3; r++) {
        CHECK(net_round(net) == 0, "quiet round");
    }
    CHECK(net->links[0][1].sent_total == 1000 && net->links[1][0].sent_total == 0,
          "nothing more was sent in the quiet rounds");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 1) == CMT_MEMR_ROUTINE_RUNNING &&
          cmt_memr_peer_cursor(&net->nodes[0]->memR, 1) == cmt_clist_back(&net->nodes[0]->mem.txs),
          "node 0's cursor waits on its tail");
    CHECK(cmt_memr_peer_cursor(&net->nodes[1]->memR, 0) == cmt_clist_back(&net->nodes[1]->mem.txs),
          "node 1's cursor waits on its tail");
    OK();
    txlist_free(&txs);
    net_free(net);
    free(net);
    return 0;
}

/* reactor_test.go:128-148 — TestReactorNoBroadcastToSender: peerID 1 is
 * the id node 0 reserved for its first peer (node 1); txs claimed from
 * it are never sent to it. `ensureNoTxs(100 ms)` (:406-409) → rounds. */
static int t_no_broadcast_to_sender(void)
{
    net_t   *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    txlist_t txs;
    int      r;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 2, &cfg) == 0, "makeAndConnectReactors(2)");
    CHECK(net_connect_full(net) == 0, "connect");
    CHECK(cmt_mem_ids_get_for_peer(&net->nodes[0]->memR.ids, 1) == 1,
          "node 0 reserved id 1 for node 1 (:145 peerID = 1)");
    CHECK(add_random_txs(&net->nodes[0]->mem, 1000, 1, &txs) == 0, "addRandomTxs(1000, peerID 1) (:146)");
    for (r = 0; r < 50; r++) {                                /* generously past 100 ms */
        CHECK(net_round(net) == 0, "round");
    }
    CHECK(cmt_mem_size(&net->nodes[1]->mem) == 0, "ensureNoTxs on reactor 1 (:147)");
    CHECK(net->links[0][1].sent_total == 0, "not one message was sent to the sender");
    /* The routine walked the whole list — its cursor sits on the tail. */
    CHECK(cmt_memr_peer_cursor(&net->nodes[0]->memR, 1) == cmt_clist_back(&net->nodes[0]->mem.txs),
          "the cursor advanced past every tx without sending (:238, :252)");
    OK();
    txlist_free(&txs);
    net_free(net);
    free(net);
    return 0;
}

/* reactor_test.go:150-187 — TestMempoolReactorMaxTxBytes */
static int t_max_tx_bytes(void)
{
    net_t   *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    uint8_t *tx1, *tx2;
    size_t   l1, l2;
    cmt_mem_tx_info_t info;
    cmt_mem_response_check_tx_t res;
    cmt_mem_error_t err;
    txlist_t one;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 2, &cfg) == 0, "makeAndConnectReactors(2)");
    CHECK(net_connect_full(net) == 0, "connect");
    memset(&info, 0, sizeof(info));
    info.sender_id = CMT_MEM_UNKNOWN_PEER_ID;

    /* A tx of the max size crosses (:168-175). Heap: 1 MiB. */
    tx1 = (uint8_t *)malloc((size_t)cfg.max_tx_bytes + 2u);
    tx2 = (uint8_t *)malloc((size_t)cfg.max_tx_bytes + 2u);
    CHECK(tx1 != NULL && tx2 != NULL, "alloc");
    l1 = tx_random(tx1, (size_t)cfg.max_tx_bytes, 777);       /* :170 */
    CHECK(cmt_mem_check_tx(&net->nodes[0]->mem, tx1, l1, &info, &res, &err) == CMT_OK &&
          res.code == CMT_MEM_CODE_TYPE_OK, "CheckTx(tx1) (:171-174)");
    one.buf = NULL;
    one.v   = (cmt_pb_bytes_t *)calloc(1, sizeof(*one.v));
    CHECK(one.v != NULL, "alloc");
    one.v[0].data = tx1; one.v[0].len = l1; one.n = 1;
    CHECK(net_check_txs_in_order(net, 1, &one) == 0, "waitForTxsOnReactors (:175)");
    CHECK(net->links[0][1].sent_total == 1, "one message");
    free(one.v);
    CHECK(cmt_mem_flush(&net->nodes[0]->mem) == CMT_OK && cmt_mem_flush(&net->nodes[1]->mem) == CMT_OK,
          "Flush both (:177-178)");
    OK();

    /* One byte more is refused at CheckTx (:180-186). */
    l2 = tx_random(tx2, (size_t)cfg.max_tx_bytes + 1u, 778);  /* :182 */
    CHECK(cmt_mem_check_tx(&net->nodes[0]->mem, tx2, l2, &info, &res, &err) == CMT_REJECT &&
          err.kind == CMT_MEM_ERR_TX_TOO_LARGE, "require.Error (:186)");
    CHECK(net_round(net) == 0 && net_round(net) == 0, "rounds");
    CHECK(cmt_mem_size(&net->nodes[1]->mem) == 0, "ensure it's not sent (:181)");
    OK();
    free(tx1);
    free(tx2);
    net_free(net);
    free(net);
    return 0;
}

/* reactor_test.go:237-260 — TestDontExhaustMaxActiveIDs. INTENT PORT,
 * labelled: the reference sends a wrong-typed message from a fresh mock
 * peer and then AddPeer, MaxActiveIDs+1 times, and never calls InitPeer
 * or RemovePeer (:250-259) — so it actually reserves no ids at all,
 * whatever its comment (:233-236) intends. With 128 slots a slot must
 * be removed before it is re-added (cmt_memr.h "Panics"), so this case
 * does the full peer lifecycle — InitPeer, the bad message, AddPeer,
 * RemovePeer — 65 536 + 1 times over the slots, which is STRONGER: it
 * proves the id space is not exhausted BECAUSE ids are reclaimed, and
 * that the counter wraps past 65 535 without a FAULT. */
static int t_dont_exhaust_max_active_ids(void)
{
    net_t *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    node_t *node;
    int     i;
    uint16_t max_id_seen = 0;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 1, &cfg) == 0, "makeAndConnectReactors(1) (:239-240)");
    node = net->nodes[0];
    CHECK(cmt_memr_start(&node->memR) == CMT_OK, "start");

    for (i = 0; i < (int)CMT_MEM_MAX_ACTIVE_IDS + 1 + 1; i++) {   /* :250 MaxActiveIDs+1 */
        int      slot = i % (int)CMT_MEM_MAX_PEERS;
        uint16_t id;

        CHECK(cmt_memr_init_peer(&node->memR, slot) == CMT_OK, "InitPeer never FAULTs");
        id = cmt_mem_ids_get_for_peer(&node->memR.ids, slot);
        CHECK(id != 0, "an id was generated for each peer (:233-234)");
        if (id > max_id_seen) {
            max_id_seen = id;
        }
        /* :252-257 — `&memproto.Message{}`: a Message with no sum; the
         * reactor stops the peer for error. */
        CHECK(cmt_memr_receive(&node->memR, slot, NULL, 0, NULL, 0) == CMT_REJECT,
              "Receive of a Message with no sum → REJECT");
        CHECK(node->stop_calls == i + 1 && node->last_stopped_slot == slot,
              "StopPeerForError was called for that peer (:172)");
        CHECK(cmt_memr_add_peer(&node->memR, slot, false, false) == CMT_OK, "AddPeer (:258)");
        CHECK(cmt_memr_remove_peer(&node->memR, slot) == CMT_OK, "RemovePeer (the switch's)");
    }
    CHECK(max_id_seen == 65535, "the counter reached the top of the uint16 space");
    CHECK(node->memR.ids.active_count == 1, "only id 0 is active at the end: every id was reclaimed");
    OK();
    net_free(net);
    free(net);
    return 0;
}

/* reactor_test.go:267-305 — TestMempoolReactorMaxActiveOutboundConnections.
 * N = 4, ExperimentalMaxGossipConnectionsToNonPersistentPeers = 1 (:269).
 * The "second reactor" is node 1: node 0's first peer in slot order. The
 * disconnect (`StopPeerGracefully`, :296-297) is symmetric — both
 * switches call RemovePeer — and so is it here. */
static int t_max_active_outbound_connections(void)
{
    net_t   *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    txlist_t txs;
    int      r;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    cfg.experimental_max_gossip_connections_to_non_persistent_peers = 1;   /* :269 */
    CHECK(net_make(net, 4, &cfg) == 0, "makeAndConnectReactors(4) (:270)");
    CHECK(net_connect_full(net) == 0, "connect");

    /* The semaphore: at node 0, slot 1 runs, slots 2 and 3 wait. */
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 1) == CMT_MEMR_ROUTINE_RUNNING,
          "node 0 → node 1 acquired (:111)");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 2) == CMT_MEMR_ROUTINE_WAITING &&
          cmt_memr_peer_routine_state(&net->nodes[0]->memR, 3) == CMT_MEMR_ROUTINE_WAITING,
          "node 0 → nodes 2, 3 wait (:104-121)");
    CHECK(net->nodes[0]->memR.active_non_persistent_peers == 1, "one held");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[1]->memR, 0) == CMT_MEMR_ROUTINE_RUNNING &&
          cmt_memr_peer_routine_state(&net->nodes[2]->memR, 0) == CMT_MEMR_ROUTINE_RUNNING &&
          cmt_memr_peer_routine_state(&net->nodes[3]->memR, 0) == CMT_MEMR_ROUTINE_RUNNING,
          "every other node's first peer is node 0 (THE SWITCH)");
    OK();

    CHECK(txlist_unique(&txs, 100) == 0, "newUniqueTxs(100) (:285)");
    {
        cmt_mem_tx_info_t info;
        size_t i;

        memset(&info, 0, sizeof(info));
        for (i = 0; i < txs.n; i++) {
            cmt_mem_error_t err;

            CHECK(cmt_mem_check_tx(&net->nodes[0]->mem, txs.v[i].data, txs.v[i].len, &info, NULL, &err) == CMT_OK,
                  "callCheckTx (:286)");
        }
    }
    /* :288-293 — node 1 gets them; nodes 2 and 3 get none. */
    CHECK(net_wait_for_num_txs(net, 1, 100) == 0, "checkTxsInMempool(reactors[1]) (:290)");
    CHECK(cmt_mem_size(&net->nodes[1]->mem) == 100, "exactly 100");
    for (r = 0; r < 20; r++) {
        CHECK(net_round(net) == 0, "extra rounds");
    }
    CHECK(cmt_mem_size(&net->nodes[2]->mem) == 0 && cmt_mem_size(&net->nodes[3]->mem) == 0,
          "require.Zero for reactors[2:] (:291-293)");
    OK();

    /* :295-297 — disconnect node 1 from node 0 (both sides). */
    CHECK(cmt_memr_remove_peer(&net->nodes[0]->memR, 1) == CMT_OK, "RemovePeer at node 0");
    CHECK(cmt_memr_remove_peer(&net->nodes[1]->memR, 0) == CMT_OK, "RemovePeer at node 1");
    CHECK(net->nodes[0]->memR.active_non_persistent_peers == 0, "the slot was released (:119)");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 1) == CMT_MEMR_ROUTINE_NONE,
          "node 0's routine for node 1 ended");
    /* :299-304 — node 2 (the next in slot order) takes the slot and
     * receives; node 3 stays empty. */
    CHECK(net_wait_for_num_txs(net, 2, 100) == 0, "checkTxsInMempool(reactors[2]) (:301)");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 2) == CMT_MEMR_ROUTINE_RUNNING &&
          cmt_memr_peer_routine_state(&net->nodes[0]->memR, 3) == CMT_MEMR_ROUTINE_WAITING,
          "slot 2 acquired, slot 3 still waits (slot order — the port's rule)");
    for (r = 0; r < 20; r++) {
        CHECK(net_round(net) == 0, "extra rounds");
    }
    CHECK(cmt_mem_size(&net->nodes[2]->mem) == 100, "exactly 100 at node 2");
    CHECK(cmt_mem_size(&net->nodes[3]->mem) == 0, "require.Zero for reactors[3:] (:302-304)");
    OK();
    txlist_free(&txs);
    net_free(net);
    free(net);
    return 0;
}

/* reactor_test.go:189-231 — the two "routine stops" leak checks, as
 * cursor-ended checks (header). Also AddPeer's host contract. */
static int t_routine_stops(void)
{
    net_t   *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    txlist_t txs;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 2, &cfg) == 0, "makeAndConnectReactors(2)");
    CHECK(net_connect_full(net) == 0, "connect");
    CHECK(add_random_txs(&net->nodes[1]->mem, 3, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0, "3 txs at node 1");
    CHECK(net_round(net) == 0, "round");
    CHECK(cmt_memr_peer_cursor(&net->nodes[1]->memR, 0) != NULL, "node 1's cursor for node 0 is on an element");

    /* :189-212 TestBroadcastTxForPeerStopsWhenPeerStops: the switch
     * stops peer 0 at node 1 (StopPeerForError → RemovePeer). */
    CHECK(cmt_memr_remove_peer(&net->nodes[1]->memR, 0) == CMT_OK, "RemovePeer (:207)");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[1]->memR, 0) == CMT_MEMR_ROUTINE_NONE &&
          cmt_memr_peer_cursor(&net->nodes[1]->memR, 0) == NULL,
          "broadcastTxRoutine finishes when peer is stopped (:209-211): cursor released");
    CHECK(cmt_mem_ids_get_for_peer(&net->nodes[1]->memR.ids, 0) == 0, "the id was reclaimed (:134)");
    CHECK(cmt_memr_remove_peer(&net->nodes[1]->memR, 0) == CMT_OK, "removing again is a no-op");
    CHECK(net_round(net) == 0, "a round after removal is harmless");
    OK();

    /* :214-231 TestBroadcastTxForPeerStopsWhenReactorStops. */
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 1) == CMT_MEMR_ROUTINE_RUNNING, "running");
    CHECK(cmt_memr_stop(&net->nodes[0]->memR) == CMT_OK, "s.Stop() (:225)");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 1) == CMT_MEMR_ROUTINE_NONE &&
          cmt_memr_peer_cursor(&net->nodes[0]->memR, 1) == NULL,
          "broadcastTxRoutine finishes when reactor is stopped (:228-230)");
    CHECK(!net->nodes[0]->memR.running, "not running");
    /* A peer added to a stopped reactor gets a routine that ends on its
     * first pass (:191-193). */
    CHECK(cmt_memr_remove_peer(&net->nodes[0]->memR, 1) == CMT_OK, "remove");
    CHECK(cmt_memr_add_peer(&net->nodes[0]->memR, 1, false, false) == CMT_OK, "re-add");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 1) == CMT_MEMR_ROUTINE_RUNNING, "started");
    CHECK(cmt_memr_tick(&net->nodes[0]->memR, NULL, NULL) == CMT_OK, "tick");
    CHECK(cmt_memr_peer_routine_state(&net->nodes[0]->memR, 1) == CMT_MEMR_ROUTINE_NONE,
          "and ended at once: !memR.IsRunning() (:191)");
    OK();

    /* The host contract: a present slot re-added is a FAULT; slots out
     * of range are REJECT; Broadcast false adds no routine (:92). */
    CHECK(cmt_memr_add_peer(&net->nodes[0]->memR, 1, false, false) == CMT_FAULT, "double add → FAULT");
    CHECK(cmt_memr_add_peer(&net->nodes[0]->memR, 128, false, false) == CMT_REJECT &&
          cmt_memr_remove_peer(&net->nodes[0]->memR, -1) == CMT_REJECT, "slot range");
    CHECK(cmt_memr_add_peer(NULL, 0, false, false) == CMT_FAULT && cmt_memr_stop(NULL) == CMT_FAULT &&
          cmt_memr_start(NULL) == CMT_FAULT && cmt_memr_init_peer(NULL, 0) == CMT_FAULT, "NULL");
    {
        node_t *nb = (node_t *)calloc(1, sizeof(*nb));
        cmt_mempool_config_t cb;

        CHECK(nb != NULL, "alloc");
        (void)cmt_mempool_config_default(&cb);
        cb.broadcast = false;                                 /* :63, :92 */
        nb->cfg = cb;
        nb->app_if.ctx = &nb->app; nb->app_if.error = tapp_error;
        nb->app_if.check_tx = tapp_check_tx; nb->app_if.flush = tapp_flush;
        CHECK(cmt_mem_init(&nb->mem, &nb->cfg, &nb->app_if, 0, NULL, NULL) == CMT_OK, "mem");
        nb->host.ctx = nb; nb->host.send = host_send; nb->host.stop_peer_for_error = host_stop_peer_for_error;
        nb->host.peer_height = host_peer_height; nb->host.now = host_now;
        nb->net = net;
        CHECK(cmt_memr_init(&nb->memR, &nb->cfg, &nb->mem, &nb->host) == CMT_OK, "memR");
        CHECK(cmt_memr_start(&nb->memR) == CMT_OK, "OnStart logs 'Tx broadcasting is disabled' (:63-65)");
        CHECK(cmt_memr_add_peer(&nb->memR, 0, false, false) == CMT_OK, "AddPeer");
        CHECK(cmt_memr_peer_routine_state(&nb->memR, 0) == CMT_MEMR_ROUTINE_NONE,
              "no broadcast routine when Broadcast is false (:92)");
        CHECK(nb->memR.peers[0].present, "but the peer is present for receive");
        cmt_memr_free(&nb->memR);
        cmt_mem_free(&nb->mem);
        free(nb);
    }
    OK();
    txlist_free(&txs);
    net_free(net);
    free(net);
    return 0;
}

/* reactor.go:140-177 with p2p/peer.go:407-422 — Receive. A solo node;
 * slot 5 is a peer with a reserved id. */
static int t_receive(void)
{
    net_t  *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    node_t *node;
    static const uint8_t truncated[]  = { 0x0a, 0x05, 0x0a, 0x01 };
    static const uint8_t empty_txs[]  = { 0x0a, 0x00 };
    static const uint8_t unknown_fld[] = { 0x10, 0x07, 0x0a, 0x05, 0x0a, 0x03, 'a', '=', 'b' };
    static const uint8_t two_txs[]    = { 0x0a, 0x0a, 0x0a, 0x03, 'c', '=', 'd', 0x0a, 0x03, 'e', '=', 'f' };
    static const uint8_t bad_tx[]     = { 0x0a, 0x05, 0x0a, 0x03, 'n', 'o', 'p' };
    uint8_t key[CMT_MEM_TX_KEY_SIZE];
    const cmt_mem_tx_t *mt;
    uint8_t *huge;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 1, &cfg) == 0, "one node");
    node = net->nodes[0];
    CHECK(cmt_memr_start(&node->memR) == CMT_OK, "start");
    CHECK(cmt_memr_init_peer(&node->memR, 5) == CMT_OK, "InitPeer(5)");
    CHECK(cmt_mem_ids_get_for_peer(&node->memR.ids, 5) == 1, "id 1");

    /* Undecodable bytes: peer.go:409-411 → StopPeerForError. */
    CHECK(cmt_memr_receive(&node->memR, 5, truncated, sizeof(truncated), NULL, 0) == CMT_REJECT,
          "truncated → REJECT");
    CHECK(node->stop_calls == 1 && node->last_stopped_slot == 5, "peer 5 stopped for error");
    /* No sum: peer.go:417-421 / reactor.go:170-173 → StopPeerForError. */
    CHECK(cmt_memr_receive(&node->memR, 5, NULL, 0, NULL, 0) == CMT_REJECT, "no sum → REJECT");
    CHECK(node->stop_calls == 2, "stopped again");
    /* Above the capacity → StopPeerForError. */
    huge = (uint8_t *)calloc(V_MEM_RECV_MESSAGE_CAPACITY + 1u, 1);
    CHECK(huge != NULL, "alloc");
    CHECK(cmt_memr_receive(&node->memR, 5, huge, V_MEM_RECV_MESSAGE_CAPACITY + 1u, NULL, 0) == CMT_REJECT,
          "capacity + 1 → REJECT");
    CHECK(node->stop_calls == 3, "stopped");
    free(huge);
    OK();

    /* An empty Txs: logged, ignored, NOT a disconnect (:145-148). */
    CHECK(cmt_memr_receive(&node->memR, 5, empty_txs, sizeof(empty_txs), NULL, 0) == CMT_OK,
          "empty Txs → OK");
    CHECK(node->stop_calls == 3 && cmt_mem_size(&node->mem) == 0, "no stop, nothing added");
    OK();

    /* An unknown field is skipped and the tx admitted, with the peer's
     * sender id recorded (:149, :157). */
    CHECK(cmt_memr_receive(&node->memR, 5, unknown_fld, sizeof(unknown_fld), NULL, 0) == CMT_OK,
          "unknown field skipped");
    CHECK(cmt_mem_size(&node->mem) == 1, "a=b admitted");
    CHECK(cmt_mem_tx_key((const uint8_t *)"a=b", 3, key) == CMT_OK, "key");
    mt = cmt_mem_get_mem_tx(&node->mem, key);
    CHECK(mt != NULL && cmt_mem_tx_is_sender(mt, 1) && !cmt_mem_tx_is_sender(mt, 0),
          "sender id 1 (peer 5's) recorded, not 0");
    OK();

    /* A multi-tx Txs is admitted whole (:155-169); a tx the app refuses
     * is logged, not a disconnect; a duplicate is ErrTxInCache → debug. */
    CHECK(cmt_memr_receive(&node->memR, 5, two_txs, sizeof(two_txs), NULL, 0) == CMT_OK, "two txs");
    CHECK(cmt_mem_size(&node->mem) == 3, "c=d and e=f admitted");
    CHECK(cmt_memr_receive(&node->memR, 5, bad_tx, sizeof(bad_tx), NULL, 0) == CMT_OK, "app-refused tx");
    CHECK(cmt_mem_size(&node->mem) == 3 && node->stop_calls == 3, "refused by the app: no stop");
    CHECK(cmt_memr_receive(&node->memR, 5, two_txs, sizeof(two_txs), NULL, 0) == CMT_OK,
          "duplicates → ErrTxInCache, logged (:160-161)");
    CHECK(cmt_mem_size(&node->mem) == 3, "unchanged");
    /* From an unreserved slot: sender id 0 (ids.go:62). */
    CHECK(cmt_memr_receive(&node->memR, 9, unknown_fld, sizeof(unknown_fld), NULL, 0) == CMT_OK,
          "from slot 9 (unreserved)");
    CHECK(mt == cmt_mem_get_mem_tx(&node->mem, key) && cmt_mem_tx_is_sender(mt, 0),
          "the duplicate from slot 9 recorded sender 0 on the resident tx (:262-263)");
    CHECK(cmt_memr_receive(&node->memR, 128, empty_txs, 2, NULL, 0) == CMT_REJECT, "slot range");
    CHECK(cmt_memr_receive(NULL, 5, empty_txs, 2, NULL, 0) == CMT_FAULT, "NULL");
    OK();
    net_free(net);
    free(net);
    return 0;
}

/* R3-M-1 — the three sleep sites (:219, :231, :244), on a solo node
 * whose sends are captured. The peer is slot 0, id 1. */
static int t_sleeps(void)
{
    net_t  *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    node_t *node;
    txlist_t txs;
    int64_t dl;
    bool    has;
    uint8_t exp[64];
    size_t  exp_len;
    int64_t t0;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 1, &cfg) == 0, "one node");
    node = net->nodes[0];
    CHECK(cmt_memr_start(&node->memR) == CMT_OK, "start");
    CHECK(cmt_memr_init_peer(&node->memR, 0) == CMT_OK, "InitPeer(0)");
    CHECK(cmt_memr_add_peer(&node->memR, 0, false, false) == CMT_OK, "AddPeer(0)");
    CHECK(add_random_txs(&node->mem, 1, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0, "one tx");
    CHECK(expected_msg(txs.v[0].data, txs.v[0].len, exp, sizeof(exp), &exp_len) == CMT_OK, "expected");

    /* An empty tick with nothing to do reports no deadline. */
    {
        net_t *e = (net_t *)calloc(1, sizeof(*e));

        CHECK(e != NULL && net_make(e, 1, &cfg) == 0, "empty node");
        CHECK(cmt_memr_start(&e->nodes[0]->memR) == CMT_OK, "start");
        CHECK(cmt_memr_tick(&e->nodes[0]->memR, &dl, &has) == CMT_OK && !has,
              "no peers: no deadline");
        net_free(e);
        free(e);
    }

    /* (a) :212-221 — peer state unknown: sleep 100 ms, cursor kept. */
    node->peer_known[0] = false;
    t0 = cmt_time_unix_nano(net->now);
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK, "tick");
    CHECK(has && dl == t0 + CMT_MEMR_PEER_CATCHUP_SLEEP_NS, "deadline now + 100 ms (:219)");
    CHECK(node->captured_n == 0, "nothing sent");
    CHECK(cmt_memr_peer_cursor(&node->memR, 0) == cmt_mem_txs_front(&node->mem),
          "the cursor was taken from TxsFront and kept (:201)");
    net_advance_ms(net, 50);
    node->peer_known[0] = true;
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK && has && dl == t0 + CMT_MEMR_PEER_CATCHUP_SLEEP_NS,
          "50 ms later: still sleeping, same deadline");
    CHECK(node->captured_n == 0, "still nothing sent");
    net_advance_ms(net, 50);
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK && !has, "at the deadline: runs, no new sleep");
    CHECK(node->captured_n == 1 && node->captured_slot == 0 &&
          node->captured[0].len == exp_len && memcmp(node->captured[0].buf, exp, exp_len) == 0,
          "the tx was sent as Message{Txs{[tx]}} (:239-242)");
    CHECK(cmt_memr_peer_cursor(&node->memR, 0) == cmt_clist_back(&node->mem.txs),
          "cursor waits on the tail (:250)");
    node_clear_captures(node);
    OK();

    /* (b) :238-246 — send refused: sleep 100 ms and retry the SAME tx.
     * The routine is parked on the first tx (:249-257); the second tx
     * wakes it and it advances WITHOUT re-sending the first. */
    txlist_free(&txs);
    CHECK(add_random_txs(&node->mem, 1, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0, "a second tx");
    CHECK(expected_msg(txs.v[0].data, txs.v[0].len, exp, sizeof(exp), &exp_len) == CMT_OK, "expected");
    node->link_full_override = true;
    t0 = cmt_time_unix_nano(net->now);
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK, "tick");
    CHECK(has && dl == t0 + CMT_MEMR_PEER_CATCHUP_SLEEP_NS, "refused send → deadline (:244)");
    CHECK(node->captured_n == 0, "nothing captured");
    CHECK(cmt_memr_peer_cursor(&node->memR, 0) == cmt_clist_back(&node->mem.txs),
          "the cursor did NOT advance (:245 continue)");
    node->link_full_override = false;
    net_advance_ms(net, 100);
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK && !has, "retry");
    CHECK(node->captured_n == 1 && node->captured[0].len == exp_len &&
          memcmp(node->captured[0].buf, exp, exp_len) == 0, "the SAME tx was sent");
    node_clear_captures(node);
    OK();

    /* (c) :229-233 — a lagging peer: tx validated at height 5, peer at
     * 3 → sleep; peer at 4 → send. */
    CHECK(cmt_mem_update(&node->mem, 5, NULL, 0, NULL, 0, NULL, NULL) == CMT_OK, "height 5");
    txlist_free(&txs);
    CHECK(add_random_txs(&node->mem, 1, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0, "a tx at height 5");
    CHECK(expected_msg(txs.v[0].data, txs.v[0].len, exp, sizeof(exp), &exp_len) == CMT_OK, "expected");
    CHECK(cmt_mem_tx_height((const cmt_mem_tx_t *)cmt_clist_elem_value(cmt_clist_back(&node->mem.txs))) == 5,
          "memTx.Height() 5 (:440)");
    node->peer_height[0] = 3;
    t0 = cmt_time_unix_nano(net->now);
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK, "tick");
    CHECK(has && dl == t0 + CMT_MEMR_PEER_CATCHUP_SLEEP_NS && node->captured_n == 0,
          "3 < 5 - 1: sleep, no send (:230-231)");
    node->peer_height[0] = 4;
    net_advance_ms(net, 100);
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK && !has, "tick");
    CHECK(node->captured_n == 1 && node->captured[0].len == exp_len &&
          memcmp(node->captured[0].buf, exp, exp_len) == 0, "4 < 4 is false: sent");
    node_clear_captures(node);
    OK();

    /* A clock that fails is a FAULT; NULL rows are FAULTs. */
    {
        cmt_memr_host_t broken = node->host;

        broken.now = NULL;
        node->memR.host = &broken;
        CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_FAULT, "NULL now → FAULT");
        node->memR.host = &node->host;
        CHECK(cmt_memr_tick(NULL, &dl, &has) == CMT_FAULT, "NULL");
    }
    OK();
    txlist_free(&txs);
    net_free(net);
    free(net);
    return 0;
}

/* reactor.go:195-208 — a cursor whose element was removed restarts from
 * the front; and the quirk at :238-247: a removed element the cursor
 * was sleeping on is still sent. Solo node with captures. */
static int t_cursor_after_removal(void)
{
    net_t  *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    node_t *node;
    txlist_t txs, more;
    int64_t dl;
    bool    has;
    uint8_t exp[64];
    size_t  exp_len;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    CHECK(net_make(net, 1, &cfg) == 0, "one node");
    node = net->nodes[0];
    CHECK(cmt_memr_start(&node->memR) == CMT_OK, "start");
    CHECK(cmt_memr_init_peer(&node->memR, 0) == CMT_OK, "InitPeer(0)");
    CHECK(cmt_memr_add_peer(&node->memR, 0, false, false) == CMT_OK, "AddPeer(0)");

    /* Two txs sent; the cursor rests on the tail. Update removes both;
     * the next tick finds the cursor's element removed with no next
     * (:250 ready), steps to nil (:252), and — the list being empty —
     * ends the pass (:198-208). A new tx is then sent from the front. */
    CHECK(add_random_txs(&node->mem, 2, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0, "two txs");
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK && !has, "tick");
    CHECK(node->captured_n == 2, "both sent");
    CHECK(cmt_memr_peer_cursor(&node->memR, 0) == cmt_clist_back(&node->mem.txs), "on the tail");
    node_clear_captures(node);
    {
        cmt_pb_exec_tx_result_t r[2];

        memset(r, 0, sizeof(r));
        CHECK(cmt_mem_update(&node->mem, 1, txs.v, 2, r, 2, NULL, NULL) == CMT_OK, "Update commits both");
    }
    CHECK(cmt_mem_size(&node->mem) == 0, "empty");
    CHECK(cmt_memr_peer_cursor(&node->memR, 0) != NULL &&
          cmt_clist_elem_removed(cmt_memr_peer_cursor(&node->memR, 0)),
          "the cursor still holds the removed tail (kept alive by its reference)");
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK && !has, "tick");
    CHECK(cmt_memr_peer_cursor(&node->memR, 0) == NULL, "stepped to nil: next tick restarts (:195-197)");
    CHECK(node->captured_n == 0, "nothing sent");
    CHECK(add_random_txs(&node->mem, 1, CMT_MEM_UNKNOWN_PEER_ID, &more) == 0, "a new tx");
    CHECK(expected_msg(more.v[0].data, more.v[0].len, exp, sizeof(exp), &exp_len) == CMT_OK, "expected");
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK, "tick");
    CHECK(node->captured_n == 1 && node->captured[0].len == exp_len &&
          memcmp(node->captured[0].buf, exp, exp_len) == 0, "sent from the front (:201)");
    node_clear_captures(node);
    txlist_free(&more);
    OK();

    /* The quirk: sleeping on X (send refused); X is committed and
     * removed; the sleep ends; X is sent anyway (:238-247 do not consult
     * Removed()). Then the cursor steps to nil. */
    CHECK(cmt_mem_flush(&node->mem) == CMT_OK, "flush");
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK, "settle the cursor");
    txlist_free(&txs);
    CHECK(add_random_txs(&node->mem, 1, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0, "X");
    CHECK(expected_msg(txs.v[0].data, txs.v[0].len, exp, sizeof(exp), &exp_len) == CMT_OK, "expected");
    node->link_full_override = true;
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK && has, "refused: sleeping on X");
    node->link_full_override = false;
    {
        cmt_pb_exec_tx_result_t r[1];

        memset(r, 0, sizeof(r));
        CHECK(cmt_mem_update(&node->mem, 2, txs.v, 1, r, 1, NULL, NULL) == CMT_OK, "Update commits X");
    }
    CHECK(cmt_mem_size(&node->mem) == 0, "X removed from the pool");
    net_advance_ms(net, 100);
    CHECK(cmt_memr_tick(&node->memR, &dl, &has) == CMT_OK && !has, "the sleep ended");
    CHECK(node->captured_n == 1 && node->captured[0].len == exp_len &&
          memcmp(node->captured[0].buf, exp, exp_len) == 0,
          "NOTE reference quirk: the REMOVED X was sent (:238-247)");
    CHECK(cmt_memr_peer_cursor(&node->memR, 0) == NULL, "then stepped off it to nil");
    node_clear_captures(node);
    OK();
    txlist_free(&txs);
    net_free(net);
    free(net);
    return 0;
}

/* golang.org/x/sync v0.11.0 semaphore/semaphore.go (pin rev 17, lines
 * as corrected in rev 18): the `Acquire` of reactor.go:111 takes a slot
 * AT ONCE only when capacity is
 * free AND `s.waiters.Len() == 0` (:52); otherwise the caller is appended
 * to the BACK of the waiter list (:69-71) and `Release` (:122-131) →
 * `notifyWaiters` (:133-160) serves that list from the FRONT while
 * capacity allows (:141). So a peer that arrives after a slot was freed
 * but while another peer is still waiting does NOT overtake it. No
 * reference test drives that moment (reactor_test.go:267-305 removes a
 * peer and then waits); this case is the port's own (LABELLED), on ONE
 * node whose peers are bare slots over an EMPTY mempool, so a tick does
 * nothing but serve the queue (cmt_memr.c: the WAITING loop of the tick
 * is the queue, in ascending slot order — R3-M-6). The old add_peer
 * checked capacity alone and failed the "C waits" assertion. */
static int t_semaphore_newcomer_waits(void)
{
    net_t  *net = (net_t *)calloc(1, sizeof(*net));
    cmt_mempool_config_t cfg;
    node_t *node;

    CHECK(net != NULL, "alloc");
    (void)cmt_mempool_config_default(&cfg);
    cfg.experimental_max_gossip_connections_to_non_persistent_peers = 1;   /* capacity 1 */
    CHECK(net_make(net, 1, &cfg) == 0, "one node");
    node = net->nodes[0];
    CHECK(cmt_memr_start(&node->memR) == CMT_OK, "start");

    /* A (slot 1) acquires; B (slot 2) finds no capacity and waits. */
    CHECK(cmt_memr_init_peer(&node->memR, 1) == CMT_OK &&
          cmt_memr_add_peer(&node->memR, 1, false, false) == CMT_OK, "AddPeer(A)");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 1) == CMT_MEMR_ROUTINE_RUNNING,
          "A acquired: capacity free, no waiters (semaphore.go:52)");
    CHECK(cmt_memr_init_peer(&node->memR, 2) == CMT_OK &&
          cmt_memr_add_peer(&node->memR, 2, false, false) == CMT_OK, "AddPeer(B)");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 2) == CMT_MEMR_ROUTINE_WAITING,
          "B waits: no capacity (semaphore.go:52 false, :69-71 PushBack)");
    CHECK(node->memR.active_non_persistent_peers == 1, "one held");
    OK();

    /* A's routine ends — the deferred Release of reactor.go:119 — BEFORE
     * the next tick; then C (slot 3) arrives. Capacity is free, but B is
     * still in the waiter list, so C must wait behind it. */
    CHECK(cmt_memr_remove_peer(&node->memR, 1) == CMT_OK, "RemovePeer(A) → Release");
    CHECK(node->memR.active_non_persistent_peers == 0, "the slot is free (:124)");
    CHECK(cmt_memr_init_peer(&node->memR, 3) == CMT_OK &&
          cmt_memr_add_peer(&node->memR, 3, false, false) == CMT_OK, "AddPeer(C)");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 3) == CMT_MEMR_ROUTINE_WAITING,
          "C WAITS: a newcomer does not overtake a waiter (semaphore.go:52 `waiters.Len() == 0`)");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 2) == CMT_MEMR_ROUTINE_WAITING,
          "B still waits: the queue is served by the tick, not at arrival");
    CHECK(node->memR.active_non_persistent_peers == 0, "nothing acquired at arrival");
    OK();

    /* notifyWaiters (:133-160): the FRONT of the queue — B, the lowest
     * waiting slot — takes the slot on the tick; C stays (:141). */
    CHECK(net_round(net) == 0, "tick");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 2) == CMT_MEMR_ROUTINE_RUNNING,
          "B running: the front waiter is served first (:135-158; slot order here)");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 3) == CMT_MEMR_ROUTINE_WAITING,
          "C still waits: no capacity left for the next waiter (:141-153)");
    CHECK(node->memR.active_non_persistent_peers == 1, "one held");
    /* B ends; the next tick serves C. */
    CHECK(cmt_memr_remove_peer(&node->memR, 2) == CMT_OK, "RemovePeer(B) → Release");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 3) == CMT_MEMR_ROUTINE_WAITING,
          "C waits for the tick that serves the queue");
    CHECK(net_round(net) == 0, "tick");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 3) == CMT_MEMR_ROUTINE_RUNNING,
          "C running");
    CHECK(node->memR.active_non_persistent_peers == 1, "one held");
    OK();

    /* CONTROL — nobody waiting and capacity free: a newcomer starts at
     * once (semaphore.go:52, both terms true) — today's behaviour, kept. */
    CHECK(cmt_memr_remove_peer(&node->memR, 3) == CMT_OK, "RemovePeer(C) → Release");
    CHECK(node->memR.active_non_persistent_peers == 0, "free, no waiters");
    CHECK(cmt_memr_init_peer(&node->memR, 4) == CMT_OK &&
          cmt_memr_add_peer(&node->memR, 4, false, false) == CMT_OK, "AddPeer(D)");
    CHECK(cmt_memr_peer_routine_state(&node->memR, 4) == CMT_MEMR_ROUTINE_RUNNING,
          "D acquired at once: capacity free AND no waiters (semaphore.go:52)");
    CHECK(node->memR.active_non_persistent_peers == 1, "one held");
    OK();
    net_free(net);
    free(net);
    return 0;
}

typedef struct {
    const char *name;
    int       (*fn)(void);
} s_case_t;

int main(void)
{
    static const s_case_t cases[] = {
        { "get_channels (GetChannels)",                          t_get_channels },
        { "broadcast_txs_message (TestReactorBroadcastTxsMessage)", t_broadcast_txs_message },
        { "no_broadcast_to_sender (TestReactorNoBroadcastToSender)", t_no_broadcast_to_sender },
        { "max_tx_bytes (TestMempoolReactorMaxTxBytes)",         t_max_tx_bytes },
        { "dont_exhaust_max_active_ids (TestDontExhaustMaxActiveIDs, intent)",
          t_dont_exhaust_max_active_ids },
        { "max_active_outbound_connections (TestMempoolReactorMaxActiveOutboundConnections)",
          t_max_active_outbound_connections },
        { "routine_stops (TestBroadcastTxForPeerStopsWhen{Peer,Reactor}Stops, as cursor checks)",
          t_routine_stops },
        { "receive (Receive + the p2p decode)",                  t_receive },
        { "sleeps (R3-M-1: the three time.Sleep sites)",         t_sleeps },
        { "cursor_after_removal (:195-208, :238-247)",           t_cursor_after_removal },
        { "semaphore_newcomer_waits (x/sync semaphore.go:52, :69-71, :133-160; port's own)",
          t_semaphore_newcomer_waits },
    };
    size_t i;
    size_t n = sizeof(cases) / sizeof(cases[0]);
    size_t failed = 0u;

    for (i = 0u; i < n; i++) {
        if (cases[i].fn() != 0) {
            fprintf(stderr, "FAIL %s\n", cases[i].name);
            failed++;
        } else {
            printf("ok   %s\n", cases[i].name);
        }
    }
    printf("test_cmt_memr: %zu/%zu cases, %d groups\n", n - failed, n, g_checks);
    return (failed == 0u) ? 0 : 1;
}
