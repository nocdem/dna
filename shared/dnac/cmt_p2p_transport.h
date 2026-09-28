/**
 * @file shared/dnac/cmt_p2p_transport.h
 * @brief cometbft @709fd12b `p2p/transport.go` ported to C — the
 *        MultiplexTransport: bounded inbound acceptance, the connection
 *        filters, the upgrade (secret connection + NodeInfo exchange +
 *        compatibility) and dialing.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F3 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row "transport.go", §9). Constructed only by the switch (same phase)
 * and its tests; the nodus glue that owns the 4004 sockets is F5.
 * Additive only; 4001/4002 and today's 4004 path are untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * Governing records: docs/plans/decisions/2026-09-26-witness-port-session.md
 * (K2: 3 s pre-identity deadline, one connection per IP with a test-only
 * exception, an inbound cap, bonded identities exempt from it, handshake
 * crypto off the loop in a bounded queue); session design
 * docs/plans/2026-09-26-witness-port-session-design.md §2R3 N2 (connection
 * generation), N6, §2R4 P3 (inbound bounded before identity, outbound
 * never starved, pre-session read buffer capped).
 *
 * ── GOROUTINES → ONE EVENT LOOP ────────────────────────────────────────
 * The reference's `Listen` / `acceptPeers` goroutine / per-connection
 * upgrade goroutine / blocking `Dial` become:
 *   · the HOST owns the listening socket. Before it calls accept(2) it
 *     asks `cmt_p2p_transport_can_accept`: `netutil.LimitListener`
 *     (transport.go:261-263) blocks Accept while the limit is reached, so
 *     the excess connections wait in the kernel's backlog; the host does
 *     the same by not accepting. A connection the host accepts anyway is
 *     refused by `cmt_p2p_transport_accept` before anything is allocated.
 *     The limit (node/setup.go:404-406) is
 *       max_num_inbound_peers + len(unconditional_peer_ids)
 *     where the unconditional IDs are the configured ones PLUS the bonded
 *     set (R-P2P-7, K2) — the host's `bonded_count`. A limit of 0 is
 *     unlimited (transport.go:261). Every accepted socket holds a slot
 *     until it is closed, established peers included (LimitListener
 *     releases on Close).
 *   · `filterConn` (transport.go:368-409) runs inside `accept` / at
 *     connect: the duplicate-connection check and ConnDuplicateIPFilter
 *     (:88-104, installed unless `allow_duplicate_ip`, setup.go:357-359).
 *   · `upgrade` (transport.go:411-498) is a per-connection state machine
 *     advanced by `cmt_p2p_transport_tick`, in the reference's order:
 *       1. the secret connection (F1) under a 3 s deadline (:421,
 *          :583-598, `defaultHandshakeTimeout` :22 — the p2p-port design
 *          §5 correction: NOT config.go's 20 s);
 *       2. for a dial, the responder's ID must equal the dialed ID
 *          (:430-445) — checked at the secret connection's ENCAPS job,
 *          BEFORE Encaps (R-P2P-14, session design §2.1 row 10), and
 *          again after authentication as the reference does (that second
 *          check can no longer fail);
 *       3. the NodeInfo exchange INSIDE the secret connection under a
 *          fresh 3 s deadline (:447, :541-581): ours written delimited, the
 *          peer's read delimited with the 10240-byte cap;
 *       4. `Validate` (:456-462), connection ID == NodeInfo ID
 *          (:465-476), not ourselves (:479-486), `CompatibleWith`
 *          (:488-495).
 *     An upgraded connection is queued for the switch — the reference's
 *     `acceptc` (:144, :343-350) — and taken with
 *     `cmt_p2p_transport_next_result`, together with every failed inbound
 *     upgrade (accept{err}) and every dial's outcome.
 *   · `Dial` (:212-241): `cmt_p2p_transport_dial` asks the host to
 *     connect; the connection has `defaultDialTimeout` = 1 s (:20) to
 *     connect (config.go's `dial_timeout` 3 s is unused by the reference's
 *     transport, like its `handshake_timeout`).
 *
 * ── THE HANDSHAKE'S ASYMMETRIC CRYPTO (DEVIATION R-P2P-8) ──────────────
 * The reference runs MakeSecretConnection inside the upgrade goroutine
 * (transport.go:304-309). Here each Encaps / Decaps / Sign / Verify the
 * secret connection asks for becomes a `cmt_p2p_hs_job_t` the transport
 * hands to the host's `submit_job`, in one of TWO classes so the host can
 * keep two bounded queues and our own outbound handshakes never wait
 * behind inbound ones (§2R4 P3):
 *     CMT_P2P_JOB_CLASS_INBOUND / CMT_P2P_JOB_CLASS_OUTBOUND.
 * A job is SELF-CONTAINED: it holds copies of its inputs and room for its
 * outputs, and no pointer into the connection — so the connection can be
 * closed and freed while a worker still runs the job. The host runs
 * `cmt_p2p_hs_job_run` (any thread; it touches only the job and the
 * sign/verify host) and then, on the loop thread,
 * `cmt_p2p_transport_job_done`, which applies the result only if
 * (slot, generation) still names the connection that asked (R-P2P-3,
 * session design N2) and discards it otherwise; either way the job is
 * freed there. `submit_job` answering "queue full" closes the connection
 * — for an INBOUND one that is the rule of §2R4 P3; for an OUTBOUND one
 * it is this port's choice (⚠ NOT GROUNDED, proposed R-P2P-26: the dial
 * fails and the switch's reconnect logic retries).
 *
 * ── THE HOST'S BYTES ───────────────────────────────────────────────────
 * The host names a connection by (slot, generation). It reads socket
 * bytes INTO `cmt_p2p_transport_read_buf` (at most the room offered —
 * before authentication that is the largest handshake message, §2R4 P3),
 * writes socket bytes FROM `cmt_p2p_transport_write_buf`, reports EOF /
 * errors with `cmt_p2p_transport_conn_failed`, and calls
 * `cmt_p2p_transport_tick` (usually through the switch's tick) on every
 * pass. A connection the transport gives up on is closed through the
 * host's `close` at once; from then on its (slot, generation) is dead and
 * every call naming it is ignored.
 * The reference's recvRoutine / sendRoutine read and write CONTINUOUSLY
 * (connection.go:590-694 through bufio :186; :429-507), bounded only by
 * the flowrate Monitors (:515, :598). The bounded `rbuf` / `wbuf` must
 * therefore not limit a connection to one buffer per loop pass: when
 * `read_buf` offers no room, or `write_buf` has nothing, the host calls
 * `cmt_p2p_transport_pump_conn` — the same per-connection step the tick
 * runs — and reads / writes again, until the socket would block or the
 * step frees no room / produces nothing (true backpressure: the recv
 * Monitor refused, the MConnection is parked, an upgrade holds for its
 * job). That step can close the connection or stop its peer (their
 * callbacks); the host names the connection again by (slot, generation)
 * after every call. The WRITE side calls it with `with_recv` false (the
 * send half only): only the read side and the tick deliver messages, so
 * the queue-share rotation has exactly two drivers (decision
 * 2026-09-27-p2p-fix-2.md (4)).
 *
 * ── DEVIATIONS (proposed rows) ─────────────────────────────────────────
 *   R-P2P-3   generation per connection (design).
 *   R-P2P-8   handshake crypto on host workers, two classes (design).
 *   R-P2P-14  dial pin at the ENCAPS job (F1).
 *   R-P2P-25  `filterTimeout` (5 s, transport.go:21, :400-402) is not
 *             ported: the filters run inline and cannot hang; the ABCI
 *             filters (`FilterPeers`, setup.go:362-402) have no consumer.
 *   R-P2P-26  an OUTBOUND job refused by a full queue fails the dial
 *             (above).
 *   R-P2P-27  the listener limit counts the bonded set through the host's
 *             `bonded_count`, read at every accept (K2: the set changes
 *             with the chain; the reference's list is fixed at start).
 *   R-P2P-33  a dial to an address with no (or a malformed) ID is refused
 *             at `cmt_p2p_transport_dial`, before any allocation; the
 *             reference fails it only after the secret connection
 *             (transport.go:432-445). Same outcome, earlier; the ENCAPS
 *             pin (R-P2P-14) is thereby unconditional.
 *   R-P2P-28  `Close` (transport.go:244-252) also closes every connection
 *             still being upgraded (the reference's goroutines close
 *             theirs when they find `closec` closed, :319-322, :346-349).
 * NOT ported: `TestFuzz` (:221-224), `AddChannel` (:277-284 — the host
 * builds the NodeInfo's channel list), `IPResolver` (no DNS, R-P2P-24).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here is consensus state (design §6 D1). Clock reads: the
 * handshake deadlines and the dial timeout only, through the host's
 * MONOTONIC `now_ns` (D3 — the reference's own reads). Randomness: none
 * here (the secret connection's nonces and Encaps coins are F1's, D4).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_TRANSPORT_H
#define CMT_P2P_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_p2p_secret.h"
#include "cmt_p2p_mconn.h"
#include "cmt_p2p_netaddr.h"
#include "cmt_p2p_nodeinfo.h"
#include "cmt_p2p_peer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMT_P2P_NS_PER_SEC (1000LL * 1000 * 1000)

/** transport.go:20 `defaultDialTimeout`. */
#define CMT_P2P_DEFAULT_DIAL_TIMEOUT_NS      (1LL * CMT_P2P_NS_PER_SEC)
/** transport.go:22 `defaultHandshakeTimeout` — once for the secret
 *  connection (:421), once more for the NodeInfo exchange (:447). */
#define CMT_P2P_DEFAULT_HANDSHAKE_TIMEOUT_NS (3LL * CMT_P2P_NS_PER_SEC)

/* ══ the asymmetric job (R-P2P-8) ═════════════════════════════════════ */

typedef enum {
    CMT_P2P_JOB_CLASS_INBOUND  = 0,   /* a handshake we accepted */
    CMT_P2P_JOB_CLASS_OUTBOUND = 1    /* a handshake we dialed   */
} cmt_p2p_job_class_t;

/** The longest `msg` a job carries (the 32-byte challenge, row 6). */
#define CMT_P2P_HS_JOB_MSG_MAX 64

/** A self-contained copy of one `cmt_p2p_sc_job_t` (file header). */
typedef struct cmt_p2p_hs_job {
    int                  slot;
    uint64_t             gen;
    cmt_p2p_job_class_t  job_class;
    cmt_p2p_sc_job_kind_t kind;
    int                  rc;          /* cmt_p2p_hs_job_run's result */

    /* the job as cmt_p2p_sc_job_run sees it — pointers into this struct */
    cmt_p2p_sc_job_t     job;
    const cmt_p2p_sc_host_t *sc_host; /* the transport's sign / verify */

    uint8_t kem_pk[CMT_P2P_SC_KEM_PK_SIZE];
    uint8_t kem_ct[CMT_P2P_SC_KEM_CT_SIZE];
    uint8_t msg[CMT_P2P_HS_JOB_MSG_MAX];
    size_t  msg_len;
    uint8_t dsa_pk[CMT_P2P_SC_DSA_PK_SIZE];
    uint8_t sig[CMT_P2P_SC_SIG_SIZE];
    uint8_t kem_ct_out[CMT_P2P_SC_KEM_CT_SIZE];
    uint8_t kem_ss_out[CMT_P2P_SC_KEM_SS_SIZE];
    uint8_t sig_out[CMT_P2P_SC_SIG_SIZE];
} cmt_p2p_hs_job_t;

/** Run a job: touches only `job` and its sign / verify host — any
 *  thread. Stores the result in `job->rc` and returns it. The DECAPS
 *  secret key is the transport's; the host must finish (or drop without
 *  running) every submitted job before `cmt_p2p_transport_free`. */
int cmt_p2p_hs_job_run(cmt_p2p_hs_job_t *job);

/* ══ the host ═════════════════════════════════════════════════════════ */

typedef struct {
    void *ctx;
    /** A MONOTONIC clock in nanoseconds (design §6 D3). */
    int64_t (*now_ns)(void *ctx);
    /** Start a non-blocking connect to `addr` for connection (slot, gen);
     *  the host answers later with `cmt_p2p_transport_dial_connected` or
     *  `cmt_p2p_transport_conn_failed`. `*host_handle` may be set.
     *  @return 0 = connecting; non-zero = failed at once. */
    int (*dial)(void *ctx, int slot, uint64_t gen,
                const cmt_p2p_netaddr_t *addr, uint64_t *host_handle);
    /** Close the socket of (slot, gen). The transport has already
     *  forgotten it. */
    void (*close)(void *ctx, int slot, uint64_t gen, uint64_t host_handle);
    /** Queue `job` in the host's queue for `job->job_class`.
     *  @return 0 = queued (the host now owns `job` until
     *  `cmt_p2p_transport_job_done`); non-zero = that queue is full. */
    int (*submit_job)(void *ctx, cmt_p2p_hs_job_t *job);
    /** The number of identities in the local bonded set (R-P2P-7 / -27).
     *  May be NULL (= 0). */
    int (*bonded_count)(void *ctx);
    /** Is there room for ONE more received message? The single-loop form
     *  of a reactor's Receive BLOCKING on a full queue — the consensus
     *  reactor's `conR.conS.peerMsgQueue <- msgInfo{…}` (consensus/
     *  reactor.go:324, :330, :350) stalls the recvRoutine, which stops
     *  reading the socket (TCP backpressure, never a drop). Asked before
     *  EVERY message a peer connection delivers (cmt_p2p_peer_pump's
     *  receive gate); while it answers false the pump runs only its SEND
     *  half (pings, pongs, gossip keep leaving) and the host must not read
     *  a peer connection's socket (`cmt_p2p_transport_may_receive`).
     *  Handshakes are never gated. May be NULL (= always true). */
    bool (*may_receive)(void *ctx);
    /** Is the queue behind `may_receive` CONTENDED (too little room left
     *  for every connected peer's share)? While true a peer connection
     *  delivers ONE queue-entering message per pump and the loop moves on
     *  to the next peer, sweep after sweep while room remains — the Go
     *  runtime's FIFO hand-out of freed channel slots to the blocked
     *  recvRoutines (decision 2026-09-27-p2p-fix-2.md (4)). May be NULL
     *  (= never). */
    bool (*recv_near_full)(void *ctx);
    /** A value that changes exactly when a delivered message takes an
     *  entry of the queue behind `may_receive` (cmt_p2p_recv_gate_t
     *  `queue_mark`): the pump tells a queue-entering message from one
     *  that takes none (ping / pong, HasVote, mempool, PEX, …), and only
     *  the first kind is a peer's turn. May be NULL (= every delivered
     *  message counts). */
    uint64_t (*queue_mark)(void *ctx);
} cmt_p2p_transport_host_t;

/** The node's own keys and the transport's settings. */
typedef struct {
    /* NodeKey (transport.go:155) — the nodus identity */
    const uint8_t *dsa_pk;           /* ML-DSA-87 public key (copied)        */
    const uint8_t *kem_pk;           /* ML-KEM-1024 public key (copied)      */
    const uint8_t *kem_sk;           /* ML-KEM-1024 secret key (copied,
                                        zeroed at free)                      */
    cmt_p2p_sc_host_t sc_host;       /* sign / verify, purpose 0x0A          */
    const uint8_t *chain_id;         /* 32 bytes — N9 and the NodeInfo       */
    const cmt_p2p_node_info_t *node_info;   /* ours (copied)                 */
    cmt_p2p_mconn_config_t mconn;    /* MConnConfig(p2p config), switch.go:36 */
    /* LimitListener (setup.go:404-406): max_num_inbound_peers + the
     * configured unconditional IDs (+ bonded_count at run time). */
    int  max_num_inbound_peers;
    int  n_unconditional_ids;
    bool allow_duplicate_ip;         /* setup.go:357-359                     */
    int64_t handshake_timeout_ns;    /* 0 = the 3 s default                  */
    int64_t dial_timeout_ns;         /* 0 = the 1 s default                  */
} cmt_p2p_transport_config_t;

/** One entry of the transport's output queue (the reference's `acceptc`
 *  and the return of `Dial`). */
typedef struct {
    bool              outbound;
    cmt_p2p_conn_t   *conn;           /* upgraded (NULL on error); the
                                         receiver owns it                   */
    int               err;            /* cmt_p2p_err_t                       */
    cmt_p2p_netaddr_t addr;           /* outbound: the address dialed;
                                         inbound IsSelf: NewNetAddress(id,
                                         remote) (transport.go:481)         */
} cmt_p2p_transport_result_t;

/** transport.go:139-162 `MultiplexTransport`. */
typedef struct {
    cmt_p2p_transport_host_t   host;
    cmt_p2p_transport_config_t cfg;
    uint8_t  dsa_pk[CMT_P2P_SC_DSA_PK_SIZE];
    uint8_t  kem_pk[CMT_P2P_SC_KEM_PK_SIZE];
    uint8_t  kem_sk[CMT_P2P_SC_KEM_SK_SIZE];
    uint8_t  chain_id[CMT_P2P_SC_CHAIN_ID_SIZE];
    char     id[CMT_P2P_ID_CAP];              /* nodeKey.ID()             */
    cmt_p2p_node_info_t *node_info;           /* ours                     */

    cmt_p2p_netaddr_t net_addr;               /* :140 (Listen)            */
    bool listening;
    bool closed;                              /* :145 closec              */

    cmt_p2p_conn_set_t conns;                 /* :148                     */
    cmt_p2p_conn_t   **slots;                 /* live sockets, by slot    */
    int      n_slots;
    uint64_t next_gen;
    int      n_inbound;                       /* LimitListener in use     */
    /* The slot whose peer the tick last SERVED (delivered >= 1
     * queue-entering message, cmt_p2p_peer_pump's count); the next tick
     * starts just past it (cmt_p2p_transport_tick). -1 =
     * none yet. */
    int      recv_last_served;

    cmt_p2p_transport_result_t *results;      /* FIFO                     */
    int      res_head;
    int      res_len;
    int      res_cap;
} cmt_p2p_transport_t;

/* ══ lifecycle ════════════════════════════════════════════════════════ */

/**
 * transport.go:169-186 `NewMultiplexTransport` + the options
 * setup.go:352-409 applies. Validates our NodeInfo (node.go:973) and
 * derives our ID from `dsa_pk` (key.go:36-38).
 * @return CMT_OK; CMT_FAULT — NULL, a missing host row, our NodeInfo
 *         invalid, its ID not ours, or out of memory.
 */
int cmt_p2p_transport_init(cmt_p2p_transport_t *t,
                           const cmt_p2p_transport_host_t *host,
                           const cmt_p2p_transport_config_t *cfg);

/** Close everything and zero the keys. The host must have completed or
 *  dropped every submitted job. */
void cmt_p2p_transport_free(cmt_p2p_transport_t *t);

/** transport.go:255-271 `Listen` — records the address; the host owns
 *  the socket. */
void cmt_p2p_transport_listen(cmt_p2p_transport_t *t,
                              const cmt_p2p_netaddr_t *addr);

/** transport.go:189-191 `NetAddress`. */
const cmt_p2p_netaddr_t *cmt_p2p_transport_net_address(
    const cmt_p2p_transport_t *t);

/** transport.go:244-252 `Close` (+ R-P2P-28). */
void cmt_p2p_transport_close(cmt_p2p_transport_t *t);

/** Our ID. */
const char *cmt_p2p_transport_id(const cmt_p2p_transport_t *t);

/* ══ inbound ══════════════════════════════════════════════════════════ */

/** The LimitListener limit now (0 = unlimited). */
int cmt_p2p_transport_max_incoming(const cmt_p2p_transport_t *t);

/** False while the LimitListener is full (or the transport is closed /
 *  not listening): the host must not accept(2). */
bool cmt_p2p_transport_can_accept(const cmt_p2p_transport_t *t);

/**
 * A socket the host accepted from `remote` (acceptPeers, transport.go:
 * 286-353 + filterConn :368-409). Refuses BEFORE allocating anything
 * when the limit is full or a filter refuses; otherwise allocates the
 * connection, starts the secret connection as RESPONDER and its 3 s
 * deadline.
 * @return CMT_P2P_ERR_NONE (`*slot`, `*gen` set);
 *         CMT_P2P_ERR_TRANSPORT_CLOSED; CMT_P2P_ERR_LIMIT (the listener
 *         limit is full); CMT_P2P_ERR_REJECTED_DUPLICATE (the same remote
 *         address is known, :376-378); CMT_P2P_ERR_REJECTED_FILTERED
 *         (ConnDuplicateIPFilter, :88-104 wrapped at :398);
 *         CMT_FAULT. On any refusal the host closes the socket itself.
 */
int cmt_p2p_transport_accept(cmt_p2p_transport_t *t,
                             const cmt_p2p_ip_t *remote_ip,
                             uint16_t remote_port, uint64_t host_handle,
                             int *slot, uint64_t *gen);

/* ══ outbound ═════════════════════════════════════════════════════════ */

/**
 * transport.go:212-241 `Dial` — starts it; the outcome arrives as a
 * result. An address without an ID is refused before anything is
 * allocated (CMT_P2P_ERR_NETADDR_NO_ID; a malformed ID
 * CMT_P2P_ERR_NETADDR_INVALID) — the reference's upgrade can never accept
 * one (`connID != dialedAddr.ID`, transport.go:432-433); here it fails
 * before the handshake, so no dial is ever unpinned (R-P2P-33).
 * @return CMT_P2P_ERR_NONE (pending); CMT_P2P_ERR_TRANSPORT_CLOSED;
 * CMT_P2P_ERR_NETADDR_NO_ID / _INVALID; CMT_P2P_ERR_NET (the host refused
 * at once); CMT_FAULT.
 */
int cmt_p2p_transport_dial(cmt_p2p_transport_t *t,
                           const cmt_p2p_netaddr_t *addr);

/** The host's connect for (slot, gen) completed; `local` side irrelevant.
 *  Runs filterConn (:227-229) and starts the secret connection as
 *  INITIATOR. */
void cmt_p2p_transport_dial_connected(cmt_p2p_transport_t *t, int slot,
                                      uint64_t gen,
                                      const cmt_p2p_ip_t *remote_ip,
                                      uint16_t remote_port);

/* ══ the host's bytes ═════════════════════════════════════════════════ */

/** Where the host may read up to `*room` socket bytes for (slot, gen).
 *  NULL (room 0) when it must not read now. */
uint8_t *cmt_p2p_transport_read_buf(cmt_p2p_transport_t *t, int slot,
                                    uint64_t gen, size_t *room);

/** The host read `n` bytes into the buffer `read_buf` gave. */
void cmt_p2p_transport_read_done(cmt_p2p_transport_t *t, int slot,
                                 uint64_t gen, size_t n);

/** Bytes the host should write for (slot, gen); NULL / 0 = none. */
const uint8_t *cmt_p2p_transport_write_buf(cmt_p2p_transport_t *t, int slot,
                                           uint64_t gen, size_t *len);

/** The host wrote `n` of them. */
void cmt_p2p_transport_write_done(cmt_p2p_transport_t *t, int slot,
                                  uint64_t gen, size_t n);

/** The socket of (slot, gen) failed or hit EOF (or the connect failed). */
void cmt_p2p_transport_conn_failed(cmt_p2p_transport_t *t, int slot,
                                   uint64_t gen);

/**
 * A job came back (file header). Applies `job->rc` to the connection that
 * asked if (slot, gen) still names it and it still waits for that job;
 * frees `job` in every case.
 * @return CMT_OK applied; CMT_REJECT discarded (stale generation / the
 *         connection is gone); CMT_FAULT on NULL.
 */
int cmt_p2p_transport_job_done(cmt_p2p_transport_t *t, cmt_p2p_hs_job_t *job);

/* ══ the loop ═════════════════════════════════════════════════════════ */

/** One pass: deadlines, upgrade steps and job submission for every
 *  connection being upgraded, and `cmt_p2p_peer_pump` for every peer
 *  connection, in slot order starting just past the slot last served
 *  (`recv_last_served`, atlas-dec-efa4d29c's round-robin form). While
 *  the host's queue is CONTENDED after that sweep (`recv_near_full`) and
 *  has room (`may_receive`), further sweeps in the same order ask again
 *  every peer that delivered a queue-entering message in the sweep
 *  before — one such message per peer per sweep — until the room is used
 *  or nobody delivers (decision 2026-09-27-p2p-fix-2.md (4)).
 *  (The host also runs the per-connection step
 *  between socket reads / writes: `cmt_p2p_transport_pump_conn`.) */
void cmt_p2p_transport_tick(cmt_p2p_transport_t *t);

/**
 * The tick's step for ONE connection, now, without its deadline checks
 * (the tick keeps those): `cmt_p2p_peer_pump` for a peer connection, the
 * upgrade step for one being upgraded (secret connection / NodeInfo
 * exchange); nothing for a dialing or an upgraded-not-yet-wrapped one, or
 * when (slot, gen) no longer names a connection. The host's continuous
 * read / write (file header, "THE HOST'S BYTES"). `with_recv` false runs
 * a peer connection's SEND half only (the gate's `send_only`): the
 * host's WRITE path must never deliver a message, or it would hand a peer
 * queue room outside the tick's and the read path's rotation (RT2 A-F3);
 * an upgrade step always runs whole (handshakes are never gated). It may
 * close the connection (the host's `close` runs inside) or stop its peer;
 * the peer object itself is freed only at the end of the switch's tick
 * (or by cmt_p2p_switch_free), never inside this call.
 */
void cmt_p2p_transport_pump_conn(cmt_p2p_transport_t *t, int slot,
                                 uint64_t gen, bool with_recv);

/** False only when (slot, gen) is a PEER connection and the host's
 *  `may_receive` answers false: the host must then not read that socket
 *  (its reactor's Receive is "blocked"). True for every other state,
 *  for a dead (slot, gen), and when the row is NULL. */
bool cmt_p2p_transport_may_receive(cmt_p2p_transport_t *t, int slot,
                                   uint64_t gen);

/** True only when (slot, gen) is a PEER connection and the host's
 *  `recv_near_full` answers true: the host's continuous read should
 *  move on to the next connection after ONE step (that step delivered
 *  at most one queue-entering message, cmt_p2p_peer_pump). False for
 *  every other state, for a dead (slot, gen), and when the row is NULL. */
bool cmt_p2p_transport_recv_near_full(cmt_p2p_transport_t *t, int slot,
                                      uint64_t gen);

/** Pop the next result. @return true if one was popped. */
bool cmt_p2p_transport_next_result(cmt_p2p_transport_t *t,
                                   cmt_p2p_transport_result_t *out);

/** transport.go:500-539 `wrapPeer` for an upgraded connection taken from
 *  a result; `cfg->outbound` is set here (:203, :236).
 *  @return the peer, or NULL — then the connection is closed and freed. */
cmt_p2p_peer_t *cmt_p2p_transport_wrap_peer(cmt_p2p_transport_t *t,
                                            cmt_p2p_conn_t *conn,
                                            const cmt_p2p_peer_config_t *cfg);

/** transport.go:357-360 `Cleanup(peer)`: forget its address in the
 *  connection set and close its socket. The peer (and the connection's
 *  memory) stays for its owner to free. Idempotent. */
void cmt_p2p_transport_cleanup(cmt_p2p_transport_t *t, cmt_p2p_peer_t *p);

/** Close and free an upgraded connection nobody will wrap (an error path
 *  of the switch). */
void cmt_p2p_transport_discard(cmt_p2p_transport_t *t, cmt_p2p_conn_t *conn);

/** The connection behind (slot, gen), or NULL. For the host / tests. */
cmt_p2p_conn_t *cmt_p2p_transport_conn(const cmt_p2p_transport_t *t, int slot,
                                       uint64_t gen);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_TRANSPORT_H */
