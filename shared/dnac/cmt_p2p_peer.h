/**
 * @file shared/dnac/cmt_p2p_peer.h
 * @brief cometbft @v0.38.26 `p2p/peer.go`, `p2p/peer_set.go` and
 *        `p2p/conn_set.go` ported to C — the raw connection (`peerConn`),
 *        the peer (MConnection + NodeInfo + flags), the peer set and the
 *        connection set.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F3 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row "peer.go, peer_set.go, conn_set.go", §9). Constructed only by
 * cmt_p2p_transport / cmt_p2p_switch (same phase); nothing in the running
 * node does yet. Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── THE CONNECTION (`cmt_p2p_conn_t`) ──────────────────────────────────
 * The reference's `net.Conn` is a socket the goroutines block on. Here
 * the HOST owns the socket and moves bytes; the connection is two byte
 * buffers and the F1 secret connection:
 *   host socket → `rbuf` (wire bytes) → cmt_p2p_sc_recv / cmt_p2p_sc_read
 *     → `pbuf` (plaintext) → NodeInfo reader / cmt_p2p_mconn_recv
 *   cmt_p2p_mconn_out / NodeInfo → cmt_p2p_sc_write → `wbuf` → host socket
 * The host reads INTO `rbuf` (`cmt_p2p_transport_read_buf`) and writes
 * FROM `wbuf` (`cmt_p2p_transport_write_buf`) — cmt_p2p_transport.h. Each
 * buffer is bounded; a full buffer is the event-loop form of a blocked
 * `Read` / `Write` (TCP backpressure), never a drop.
 *   · `rbuf` before the secret connection authenticates: at most
 *     CMT_P2P_SC_HS_MSG_MAX bytes — the largest handshake message (session
 *     design §2R4 P3 "a pre-session connection's read buffer is capped at
 *     the largest handshake message").
 *   · `pbuf` holds a whole delimited NodeInfo (10240 + prefix) — the
 *     reference's reader cap (transport.go:563) — and afterwards the
 *     plaintext the MConnection has not consumed yet.
 * The connection also carries the transport's upgrade state (the
 * reference keeps it on the goroutine's stack, transport.go:309-351,
 * :411-498); those fields are the transport's and nothing else touches
 * them.
 *
 * Every connection has a GENERATION (DEVIATION R-P2P-3): a transport-wide
 * counter value assigned at allocation and never reused. The host names a
 * connection by (slot, generation); a call whose generation is not the
 * slot's current one is ignored — so a deferred close, a late socket event
 * or a late job result (R-P2P-8) can never reach a newer connection that
 * reused the slot (session design §2R3 N2).
 *
 * ── DEVIATIONS / NOT PORTED ────────────────────────────────────────────
 *   · `peer.send` (peer.go:270-295) marshals a proto.Message; here the
 *     reactor hands BYTES (the consensus port's rule, cmt_conr.h R3-A-1:
 *     "the reactor has ALREADY marshalled the message"), and `onReceive`
 *     (:400-438) hands bytes to the reactor — the Wrapper/Unwrapper and
 *     msgTypeByChID step is the reactor's. The reference's panic on an
 *     unknown channel (:403-405, caught by `_recover` → onPeerError) is a
 *     direct `on_peer_error` here.
 *   · `Send` ≡ `TrySend` (R-P2P-19, cmt_p2p_mconn.h).
 *   · metrics (peer.go:124-126, :200, :276-293, :364-385), `SetLogger`,
 *     `String` — not ported.
 *   · peer_set / conn_set mutexes (peer_set.go:23, conn_set.go:21) — one
 *     event loop owns them.
 *   · `RemoteIP` (peer.go:85-103) resolves the remote address with
 *     `net.LookupIP` and caches it; the host gives the IP (no DNS,
 *     R-P2P-24).
 *   · conn_set's `resolveIPs` (transport.go:600-618) is the connection's
 *     one remote IP (no resolver, R-P2P-24).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Node-local transport state (design §6 D1). Per connection, bytes are
 * handled in arrival order and reach the MConnection whole and in order
 * (D2); a failed AEAD open stops the peer, it never skips. No clock is
 * read here except through the MConnection's host `now_ns` (monotonic,
 * D3).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_PEER_H
#define CMT_P2P_PEER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_p2p_secret.h"
#include "cmt_p2p_mconn.h"
#include "cmt_p2p_netaddr.h"
#include "cmt_p2p_nodeinfo.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cmt_p2p_peer;
struct cmt_p2p_hs_job;

/* ══ the connection ═══════════════════════════════════════════════════ */

/** `rbuf` capacity once the secret connection is authenticated: four
 *  sealed frames. ⚠ NOT GROUNDED — a size, not a reference value (the
 *  reference reads through bufio's 4096, connection.go:186). */
#define CMT_P2P_CONN_RBUF_CAP   (4 * CMT_P2P_SC_SEALED_FRAME_SIZE)
/** `rbuf` capacity before authentication (§2R4 P3). */
#define CMT_P2P_CONN_RBUF_PRE_AUTH_CAP CMT_P2P_SC_HS_MSG_MAX
/** `rbuf` ALLOCATION: the larger of the two caps. The pre-auth cap
 *  (HELLO_R, 4231 bytes) exceeds four sealed frames (4176); the room the
 *  host is offered may never exceed what was allocated (F3 fix round 1:
 *  a 4231-byte read into a 4176-byte buffer). */
#define CMT_P2P_CONN_RBUF_ALLOC \
    (CMT_P2P_CONN_RBUF_CAP > CMT_P2P_CONN_RBUF_PRE_AUTH_CAP ? \
     CMT_P2P_CONN_RBUF_CAP : CMT_P2P_CONN_RBUF_PRE_AUTH_CAP)
_Static_assert(CMT_P2P_CONN_RBUF_ALLOC >= CMT_P2P_CONN_RBUF_CAP &&
               CMT_P2P_CONN_RBUF_ALLOC >= CMT_P2P_CONN_RBUF_PRE_AUTH_CAP,
               "rbuf allocation must cover both read caps");
/** `pbuf`: a whole delimited NodeInfo (10240 + a 2-byte uvarint) plus one
 *  opened frame. */
#define CMT_P2P_CONN_PBUF_CAP   (CMT_P2P_MAX_NODE_INFO_SIZE + 16 + \
                                 CMT_P2P_SC_DATA_MAX_SIZE)
/** `wbuf`: every byte the handshake queues (CMT_P2P_SC_OUT_CAP) fits, and
 *  sixteen sealed frames of MConnection output. ⚠ NOT GROUNDED — a size. */
#define CMT_P2P_CONN_WBUF_CAP   (CMT_P2P_SC_OUT_CAP + \
                                 16 * CMT_P2P_SC_SEALED_FRAME_SIZE)

/** Where a connection is in its life (the transport's upgrade steps,
 *  transport.go:212-241, :309-351, :411-498). */
typedef enum {
    CMT_P2P_CONN_DIALING = 1,  /* outbound, waiting for connect (:216)       */
    CMT_P2P_CONN_SECRET,       /* upgradeSecretConn (:421, :583-598)          */
    CMT_P2P_CONN_NODE_INFO,    /* handshake(): NodeInfo exchange (:447, :541) */
    CMT_P2P_CONN_UPGRADED,     /* upgraded; waiting for the switch (acceptc)  */
    CMT_P2P_CONN_PEER,         /* owned by a peer (wrapPeer, :500-539)        */
    CMT_P2P_CONN_CLOSED
} cmt_p2p_conn_state_t;

/** peer.go:52-62 `peerConn` + the socket and the upgrade state. */
typedef struct cmt_p2p_conn {
    /* ── identity for the host (R-P2P-3) ── */
    int      slot;
    uint64_t gen;
    uint64_t host_handle;          /* the host's own token, echoed in close */

    /* ── peerConn (peer.go:52-62) ── */
    bool               outbound;
    cmt_p2p_netaddr_t  remote;     /* RemoteAddr: ip + port, no ID          */
    cmt_p2p_netaddr_t  dialed;     /* outbound: the address dialed (+ ID)   */

    /* ── the transport's upgrade state ── */
    cmt_p2p_conn_state_t state;
    int64_t   deadline_ns;         /* 0 = none (SetDeadline(time.Time{}))   */
    bool      in_conn_set;         /* mt.conns.Set happened (:406)          */
    bool      counted_inbound;     /* holds a LimitListener slot            */
    cmt_p2p_sc_t *sc;
    struct cmt_p2p_hs_job *job;    /* submitted, not yet returned           */
    int       job_class;
    char      remote_id[CMT_P2P_ID_CAP];  /* PubKeyToID(RemotePubKey)       */
    cmt_p2p_node_info_t *peer_ni;  /* the NodeInfo read (:564)              */
    uint8_t  *ni_out;              /* our delimited NodeInfo, not yet sealed */
    size_t    ni_out_off;
    size_t    ni_out_len;
    bool      sock_failed;         /* the host reported EOF / an error      */
    int       err;                 /* why it failed (cmt_p2p_err_t)         */
    /* The transport tick's contended sweeps (cmt_p2p_transport_tick): this
     * peer connection delivered a queue-entering message in the tick's
     * latest sweep, so the next sweep asks it again. */
    bool      recv_again;

    /* ── byte buffers ── */
    uint8_t  *rbuf;
    size_t    rbuf_len;
    uint8_t  *pbuf;
    size_t    pbuf_len;
    uint8_t  *wbuf;
    size_t    wbuf_off;
    size_t    wbuf_len;

    struct cmt_p2p_peer *peer;     /* set by wrapPeer                       */
} cmt_p2p_conn_t;

/** Allocate a connection with its three buffers and its secret-connection
 *  machine (not yet initialised). @return NULL on allocation failure. */
cmt_p2p_conn_t *cmt_p2p_conn_new(void);

/** Zero the secret connection's keys and free everything. NULL-safe. */
void cmt_p2p_conn_free(cmt_p2p_conn_t *c);

/** Room left in `rbuf` for the host to read into (the pre-auth cap
 *  applies until the secret connection is authenticated). */
size_t cmt_p2p_conn_rbuf_room(const cmt_p2p_conn_t *c);

/** Move the secret connection's handshake output into `wbuf`, as much as
 *  fits. */
void cmt_p2p_conn_take_sc_out(cmt_p2p_conn_t *c);

/**
 * Open sealed frames from `rbuf` into `pbuf` while `pbuf` has room for a
 * whole frame's chunk (secret_connection.go:232-273 Read).
 * @return CMT_OK; CMT_REJECT — the secret connection refused a frame (the
 *         connection is dead); CMT_FAULT.
 */
int cmt_p2p_conn_fill_plain(cmt_p2p_conn_t *c);

/**
 * secret_connection.go:194-229 Write: seal the longest prefix of `data`
 * whose frames fit in `wbuf` (whole frames only; the last frame may be
 * short) and report how many plaintext bytes that was.
 * @return CMT_OK; CMT_REJECT (the secret connection is dead); CMT_FAULT.
 */
int cmt_p2p_conn_write_plain(cmt_p2p_conn_t *c, const uint8_t *data,
                             size_t len, size_t *taken);

/** Drop `n` plaintext bytes from the front of `pbuf`. */
void cmt_p2p_conn_pbuf_consume(cmt_p2p_conn_t *c, size_t n);

/* ══ conn_set.go ══════════════════════════════════════════════════════ */

/** One entry: the connection's RemoteAddr().String() and its IPs
 *  (conn_set.go:18-21; one IP here, R-P2P-24). */
typedef struct {
    char         addr[CMT_P2P_NETADDR_STR_MAX];
    cmt_p2p_ip_t ip;
} cmt_p2p_conn_set_item_t;

/** conn_set.go:23-35 `connSet` — keyed by RemoteAddr().String(). */
typedef struct {
    cmt_p2p_conn_set_item_t *items;
    int n;
    int cap;
} cmt_p2p_conn_set_t;

void cmt_p2p_conn_set_init(cmt_p2p_conn_set_t *cs);
void cmt_p2p_conn_set_free(cmt_p2p_conn_set_t *cs);
/** conn_set.go:36-43 `Has` — by the remote address string. */
bool cmt_p2p_conn_set_has(const cmt_p2p_conn_set_t *cs,
                          const cmt_p2p_netaddr_t *remote);
/** conn_set.go:45-58 `HasIP`. */
bool cmt_p2p_conn_set_has_ip(const cmt_p2p_conn_set_t *cs,
                             const cmt_p2p_ip_t *ip);
/** conn_set.go:74-82 `Set`. @return CMT_OK or CMT_FAULT (memory). */
int cmt_p2p_conn_set_set(cmt_p2p_conn_set_t *cs,
                         const cmt_p2p_netaddr_t *remote);
/** conn_set.go:60-65 `Remove` / :67-72 `RemoveAddr` (the same key here). */
void cmt_p2p_conn_set_remove(cmt_p2p_conn_set_t *cs,
                             const cmt_p2p_netaddr_t *remote);

/* ══ peer.go ══════════════════════════════════════════════════════════ */

typedef struct cmt_p2p_peer cmt_p2p_peer_t;

/**
 * transport.go:45-57 `peerConfig` — what the switch hands the transport
 * for `wrapPeer`. `on_receive` is the switch's reactorsByCh dispatch
 * (peer.go:400-438); `on_peer_error` its StopPeerForError (:440-442).
 */
typedef struct {
    void *ctx;
    const cmt_p2p_ch_desc_t *ch_descs;
    int n_ch_descs;
    void (*on_peer_error)(void *ctx, cmt_p2p_peer_t *p, int reason);
    void (*on_receive)(void *ctx, cmt_p2p_peer_t *p, uint8_t ch_id,
                       const uint8_t *msg, size_t len);
    bool (*is_persistent)(void *ctx, const cmt_p2p_netaddr_t *na);
    bool outbound;
} cmt_p2p_peer_config_t;

/** peer.go:122 Data — `Set(string, interface{})` / `Get` (:298-305). */
#define CMT_P2P_PEER_DATA_MAX 8
typedef struct {
    const char *key;               /* caller-owned, compared with strcmp */
    void       *val;
} cmt_p2p_peer_data_t;

/** Reason code for `on_peer_error` when a message arrives on a channel no
 *  reactor owns (peer.go:401-406). Outside cmt_p2p_mconn_err_t's range. */
#define CMT_P2P_PEER_ERR_UNKNOWN_CHANNEL 100

/** peer.go:105-130 `peer`. */
struct cmt_p2p_peer {
    /* peerConn */
    bool               outbound;
    bool               persistent;
    cmt_p2p_conn_t    *conn;
    cmt_p2p_netaddr_t  socket_addr;             /* :58 socketAddr        */

    cmt_p2p_mconn_t      mconn;
    cmt_p2p_mconn_host_t mhost;
    int64_t            (*now_fn)(void *ctx);    /* the host's monotonic clock */
    void                *now_ctx;
    cmt_p2p_node_info_t *node_info;             /* :118 (owned)          */
    char                 id[CMT_P2P_ID_CAP];    /* nodeInfo.ID()         */

    cmt_p2p_peer_config_t cfg;

    /* BaseService */
    bool started;
    bool stopped;

    bool removal_failed;                        /* :129 */
    cmt_p2p_peer_data_t data[CMT_P2P_PEER_DATA_MAX];

    /* the switch's bookkeeping */
    bool  buried;                               /* waiting to be freed   */
    struct cmt_p2p_peer *next_buried;
    void *sw;
};

/**
 * transport.go:500-539 `wrapPeer` + peer.go:134-170 `newPeer` +
 * :390-451 `createMConnection`. Takes ownership of `conn` and of
 * `node_info` (heap). The persistent flag (transport.go:507-517): an
 * outbound peer asks `is_persistent(socket address)`, an inbound peer
 * `is_persistent(NodeInfo.NetAddress())` (false if that does not parse).
 * @return the peer, or NULL (memory / MConnection init) — then nothing was
 *         taken.
 */
cmt_p2p_peer_t *cmt_p2p_peer_new(cmt_p2p_conn_t *conn,
                                 cmt_p2p_node_info_t *node_info,
                                 const cmt_p2p_peer_config_t *cfg,
                                 const cmt_p2p_mconn_config_t *mcfg,
                                 int64_t (*now_ns)(void *ctx),
                                 void *now_ctx);

/** Free the peer, its MConnection, its NodeInfo and its connection.
 *  NULL-safe. Never from inside one of the peer's own callbacks. */
void cmt_p2p_peer_free(cmt_p2p_peer_t *p);

/** peer.go:191-202 `OnStart` (BaseService.Start → mconn.Start).
 *  @return CMT_OK; CMT_REJECT if already started / stopped. */
int cmt_p2p_peer_start(cmt_p2p_peer_t *p);

/** peer.go:214-220 `OnStop` (mconn.Stop). Idempotent. */
void cmt_p2p_peer_stop(cmt_p2p_peer_t *p);

/** peer.go:207-211 `FlushStop`. */
void cmt_p2p_peer_flush_stop(cmt_p2p_peer_t *p);

/** BaseService.IsRunning. */
bool cmt_p2p_peer_is_running(const cmt_p2p_peer_t *p);

/** peer.go:226-228 `ID`. */
const char *cmt_p2p_peer_id(const cmt_p2p_peer_t *p);
/** peer.go:231-233 `IsOutbound`. */
bool cmt_p2p_peer_is_outbound(const cmt_p2p_peer_t *p);
/** peer.go:236-238 `IsPersistent`. */
bool cmt_p2p_peer_is_persistent(const cmt_p2p_peer_t *p);
/** peer.go:241-243 `NodeInfo`. */
const cmt_p2p_node_info_t *cmt_p2p_peer_node_info(const cmt_p2p_peer_t *p);
/** peer.go:249-251 `SocketAddr`. */
const cmt_p2p_netaddr_t *cmt_p2p_peer_socket_addr(const cmt_p2p_peer_t *p);
/** peer.go:85-103 `RemoteIP`. */
const cmt_p2p_ip_t *cmt_p2p_peer_remote_ip(const cmt_p2p_peer_t *p);

/** peer.go:260-262 `Send` (≡ TrySend, R-P2P-19). */
bool cmt_p2p_peer_send(cmt_p2p_peer_t *p, uint8_t ch_id,
                       const uint8_t *msg, size_t len);
/** peer.go:266-268 `TrySend`. False when not running, when the PEER's
 *  NodeInfo does not list the channel (:273, :309-325), or when the
 *  MConnection refuses. */
bool cmt_p2p_peer_try_send(cmt_p2p_peer_t *p, uint8_t ch_id,
                           const uint8_t *msg, size_t len);
/** peer.go:355-360 `CanSend`. */
bool cmt_p2p_peer_can_send(const cmt_p2p_peer_t *p, uint8_t ch_id);

/** peer.go:298-305 `Get` / `Set`. Set returns false when full. */
void *cmt_p2p_peer_get(const cmt_p2p_peer_t *p, const char *key);
bool  cmt_p2p_peer_set(cmt_p2p_peer_t *p, const char *key, void *val);

/** peer.go:332-338 */
void cmt_p2p_peer_set_removal_failed(cmt_p2p_peer_t *p);
bool cmt_p2p_peer_get_removal_failed(const cmt_p2p_peer_t *p);

/** The receive gate `cmt_p2p_peer_pump` asks (its "THE RECEIVE GATE"
 *  below): the transport host's `may_receive` / `recv_near_full` /
 *  `queue_mark` rows, and whether the receive half may run at all. */
typedef struct {
    void *ctx;
    /** Room for one more message? NULL = always. */
    bool (*may_receive)(void *ctx);
    /** Contended: one QUEUE-ENTERING message per call? NULL = never. */
    bool (*recv_near_full)(void *ctx);
    /** A value that changes exactly when a delivered message took an
     *  entry of the queue behind `may_receive`, and does not change
     *  otherwise during one delivery. NULL = every delivered message
     *  counts as queue-entering. */
    uint64_t (*queue_mark)(void *ctx);
    /** true: the SEND half only — no frame is opened, nothing is
     *  delivered (the host's write path, cmt_p2p_transport_pump_conn). */
    bool send_only;
} cmt_p2p_recv_gate_t;

/**
 * One event-loop pass over the peer's connection — the MConnection's
 * recvRoutine and sendRoutine (connection.go:429-507, :590-694) fed from
 * and into the connection's buffers: open sealed frames, hand the
 * plaintext to `cmt_p2p_mconn_recv`, run `cmt_p2p_mconn_tick`, and seal
 * EVERY byte of `cmt_p2p_mconn_out` that `wbuf` can take (R-P2P-17: the
 * MConnection's output is drained every pass). A frame the secret
 * connection refuses is `cmt_p2p_mconn_conn_failed` → on_error →
 * StopPeerForError. The callbacks it triggers may stop the peer; they
 * never free it. Called by the transport's tick and, between the host's
 * socket reads / writes, through `cmt_p2p_transport_pump_conn` (the
 * continuous read / write, cmt_p2p_transport.h "THE HOST'S BYTES").
 *
 * THE RECEIVE GATE (`gate`, the transport host's `may_receive` /
 * `recv_near_full` / `queue_mark` rows; NULL = receive without limit).
 * The reference's recvRoutine hands each message to `onReceive` and
 * BLOCKS there while a reactor's queue is full (connection.go:676-678 →
 * consensus/reactor.go:333, :339, :359 `peerMsgQueue <-`); the Go runtime
 * then gives each freed slot to the blocked senders in FIFO order. The
 * single-loop form (decision 2026-09-27-p2p-fix-2.md (4)):
 *   · `may_receive` is asked before EVERY message (cmt_p2p_mconn_recv_n
 *     with max 1). False = the routine is stalled: no frame is opened, no
 *     plaintext reaches the MConnection, only the SEND half runs (ping /
 *     pong / flush / queued messages still go out);
 *   · a delivered message is QUEUE-ENTERING when `queue_mark` moved
 *     across its delivery (compared right before and right after the one
 *     recv_n call that delivered it). Only such a message is a turn:
 *     after a queue-entering message was delivered while
 *     `recv_near_full` answers true, the receive half ends for THIS call
 *     — one queue-entering message per peer per call while the queue is
 *     contended, the caller moving on to the next peer (the FIFO hand-out
 *     of freed slots). A message that takes no entry (ping / pong,
 *     HasVote, NewRoundStep, mempool, PEX, 0x70 / 0x71) never ends a turn
 *     and never counts against a peer's share (RT2 A-F2); the call stays
 *     bounded by PEER_PUMP_ROUNDS, the buffers and the recv Monitor;
 *   · `send_only`: the receive half does not run at all.
 * Nothing that was read is ever dropped: a message reaches `on_receive`
 * only if `may_receive` was true right before the packets that completed
 * it were consumed, and the bytes of a message that may not be delivered
 * stay unconsumed in the connection's buffers.
 *
 * END OF STREAM (Codex 6): the socket's EOF / error
 * (`cmt_p2p_transport_conn_failed` → `sock_failed`) stops the peer only
 * once the receive half is EXHAUSTED — a pass that ran it unstalled,
 * moved nothing and left `pbuf` empty (every opened plaintext was taken
 * by the MConnection; what may remain in `rbuf` is less than one sealed
 * frame and can never complete — the reference's io.ReadFull
 * UnexpectedEOF). While `pbuf` still holds bytes (the recv Monitor
 * throttled, or the gate stalled the half) the buffered messages are
 * delivered first, in later calls — connection.go:590-694 hands every
 * packet bufio already holds to onReceive before the read error surfaces.
 * @return the number of QUEUE-ENTERING messages delivered (with a NULL
 *         `queue_mark`, every delivered message) — > 0 means this peer
 *         was SERVED on its receive half (the transport's last-served
 *         rotation and its repeated sweeps, cmt_p2p_transport_tick).
 */
size_t cmt_p2p_peer_pump(cmt_p2p_peer_t *p, const cmt_p2p_recv_gate_t *gate);

/* ══ peer_set.go ══════════════════════════════════════════════════════ */

/** peer_set.go:21-31 `PeerSet` — `list` in insertion order with the
 *  reference's swap-with-last removal (:107-143), so `List()` iterates in
 *  the same order the reference's does. */
typedef struct {
    cmt_p2p_peer_t **list;
    int n;
    int cap;
} cmt_p2p_peer_set_t;

void cmt_p2p_peer_set_init(cmt_p2p_peer_set_t *ps);
void cmt_p2p_peer_set_free(cmt_p2p_peer_set_t *ps);
/** peer_set.go:42-60 `Add`. @return CMT_P2P_ERR_NONE;
 *  CMT_P2P_ERR_SWITCH_DUPLICATE_PEER_ID; CMT_P2P_ERR_PEER_REMOVAL;
 *  CMT_FAULT (memory). */
int  cmt_p2p_peer_set_add(cmt_p2p_peer_set_t *ps, cmt_p2p_peer_t *p);
/** peer_set.go:63-69 `Has`. */
bool cmt_p2p_peer_set_has(const cmt_p2p_peer_set_t *ps, const char *id);
/** peer_set.go:73-90 `HasIP`. */
bool cmt_p2p_peer_set_has_ip(const cmt_p2p_peer_set_t *ps,
                             const cmt_p2p_ip_t *ip);
/** peer_set.go:94-102 `Get`. */
cmt_p2p_peer_t *cmt_p2p_peer_set_get(const cmt_p2p_peer_set_t *ps,
                                     const char *id);
/** peer_set.go:107-143 `Remove` — false (and SetRemovalFailed) when the
 *  peer is not in the set. */
bool cmt_p2p_peer_set_remove(cmt_p2p_peer_set_t *ps, cmt_p2p_peer_t *p);
/** peer_set.go:146-150 `Size`. */
int  cmt_p2p_peer_set_size(const cmt_p2p_peer_set_t *ps);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_PEER_H */
