/**
 * @file nodus/src/net/nodus_p2p_host.h
 * @brief The witness-free HOST of the ported cometbft @v0.38.26 p2p layer
 *        (shared/dnac/cmt_p2p_*) on port 4004 — net-layer design
 *        2026-10-19 §11 (package N3).
 *
 * Moved out of nodus/src/witness/nodus_witness_p2p.c, logic unchanged
 * (K25-5: the Linux behaviour of the 4004 host does not change,
 * docs/plans/decisions/2026-10-16-kurultay-25-summary.md). The witness
 * (nodus_witness_p2p.c) EMBEDS this host and adds the bonded set, the
 * consensus seam and its seven reactors; a node that runs no witness (the
 * light storage node) can build this host alone. Governing records:
 * docs/plans/decisions/2026-09-26-witness-port-session.md (4004 = cometbft
 * p2p, K2 admission, channels, the address-book file),
 * docs/plans/decisions/2026-10-19-kurultay-26b-summary.md.
 *
 * ── WHAT THE HOST IS ───────────────────────────────────────────────────
 * The shared/dnac p2p layer is socket-free, clock-free and thread-free:
 * it is DRIVEN. This module is what drives it:
 *   · the 4004 SOCKETS (`nodus_p2p_io_t`): non-blocking TCP listen /
 *     accept / connect / read / write on its own readiness set
 *     (`nodus_net_poll_t`, nodus/src/net/nodus_net_poll.h: epoll on
 *     Linux, level-triggered; select on Windows), RAW byte streams into
 *     and out of `cmt_p2p_transport_read_buf` / `_write_buf` — nodus_tcp's
 *     frame layer is NOT used on 4004. `can_accept` is asked before every
 *     accept(2) (LimitListener, transport.go:261-263). Reads and writes are
 *     CONTINUOUS within a pass, as the reference's recvRoutine /
 *     sendRoutine goroutines are (connection.go:590-694, :429-507;
 *     R-P2P-17) — nodus_p2p_host.c io_read / io_write. At most
 *     NODUS_P2P_ACCEPT_BUDGET accept(2) calls per pass. IN is cleared only
 *     at true backpressure and re-armed before every wait once `read_buf`
 *     has room again. IP literals only (R-P2P-24).
 *   · the WORKER: N pthreads over three bounded queues — outbound
 *     handshakes, inbound handshakes (never the same queue, §2R4 P3) and
 *     received ADDR-record verifications (R-P2P-43). Results come back to
 *     the loop and are applied there by (slot, generation) (R-P2P-3/-8).
 *     Every submitted job is completed or dropped before the transport is
 *     freed.
 *   · the CLOCKS: a MONOTONIC clock for every p2p deadline (D3, R-P2P-15);
 *     WALL time only for the address book's persisted timestamps
 *     (R-P2P-35). Transport-local randomness comes from the OS (D4).
 *   · IDENTITY: the node key (ML-DSA-87) and the KEM key (ML-KEM-1024) of
 *     a `nodus_identity_t`. NodeInfo: network = the 32-byte chain id in
 *     hex, P2P version 8, the channels the CALLER lists (in its order),
 *     then 0x00 when PEX is on, a non-empty moniker, an IP-literal listen
 *     address.
 *   · our own signed ADDR record (N7 ADDR bytes, purpose 0x0B): its `seq`
 *     is persisted (seq_dir/nodus.addr_seq) BEFORE anything is signed; at
 *     start seq = max(stored, the highest own seq the book has seen) + 1.
 *     PEX pushes it only while `self_bonded` (written by the embedder —
 *     the witness's bonded-set refresh; a witness-free host never sets it).
 *   · the address book file (data_path/p2p_addrbook.pb), replaced
 *     atomically: POSIX temporary file + fsync + rename + directory fsync;
 *     Windows temporary file + _commit + MoveFileExW(REPLACE_EXISTING |
 *     WRITE_THROUGH).
 *   · the REACTORS: the caller's, registered in the order given, then PEX
 *     (0x00) when `cfg.pex`.
 *   · the POLICY (`nodus_p2p_host_policy_t`): what only an embedder knows —
 *     the bonded set (switch `is_bonded`, R-P2P-7; transport
 *     `bonded_count`, R-P2P-27; address book `bonded_pubkey`, R-P2P-4) and
 *     the consensus queue's backpressure (transport `may_receive`,
 *     `recv_near_full`, `queue_mark`). A NULL row is the neutral answer:
 *     not bonded / 0 / no key / may receive / not contended / 0.
 *
 * ── LIFECYCLE (the order nodus_witness_p2p_new / _poll / _free keep) ───
 *   _init  — listener, own address, NodeInfo, transport, switch, the
 *            caller's reactors, address book + PEX, the configured peer
 *            lists (node/node.go:283-421 / setup.go:349-491, p2p half).
 *   _start — worker threads, switch start (PEX → book load, R-P2P-38),
 *            own record, persistent-peer dial, the `p2p on …` INFO line
 *            (node.go:547-579 OnStart).
 *            The witness runs its bonded-set refresh between the two.
 *   _poll  — _poll_io (worker results, wait, worker results, I/O, switch
 *            tick), _pex_tick, _own_record_check, _flush. The witness
 *            calls the steps itself, its own steps in between.
 *   _free  — switch stop (book saved), worker stop, PEX, switch,
 *            transport, book, sockets, mutex, NodeInfo. Must also be
 *            called after a FAILED _init / _start (it releases exactly
 *            what was built, nothing twice); does not free `h` itself.
 *   STATE  — `init_ok` is set at the end of a successful _init, `started`
 *            on entry to _start; _free clears both, last. _start runs only
 *            on an init_ok host not yet started (a second call, or a call
 *            after a failed _init, is refused with -1 and no side effect).
 *            _poll_io, _pex_tick, _own_record_check, _flush, _send and the
 *            accessors do nothing / answer the neutral value (0, "", NULL,
 *            false) unless init_ok; nodus_p2p_host_poll answers -1 unless
 *            the host is init_ok AND started.
 *
 * ── THE CALLER'S OBLIGATIONS ──────────────────────────────────────────
 *   (a) The host points into itself (the transport's, switch's, book's
 *       and PEX's host rows take `h` as ctx; io.t = &h->t): it must not be
 *       moved or copied after _init — embed it, or hold it by pointer.
 *   (b) `identity`, `policy.ctx`, and every reactor's `ctx` and `name`
 *       (and its `get_channels` array) must outlive _free: the switch stop
 *       inside _free still calls the reactors' remove_peer rows.
 *   (c) Every host call from ONE thread. Never call _free or _start from
 *       inside a reactor or policy callback (they run inside _poll_io,
 *       _start and _free). The worker threads touch only handshake and
 *       ADDR-verification jobs, never the host's state.
 *   (d) _init only on a fresh (zeroed) host or one _free has released;
 *       _init on a live host leaks it (it is overwritten).
 *   (e) A host without `policy.bonded_pubkey` can verify no signed ADDR
 *       record (the book believes only a record signed by the key the row
 *       returns, R-P2P-4): _init refuses such a host with `cfg->pex` on —
 *       unsigned PEX entries could then poison a validator's ID until it is
 *       banned. Run it with PEX off (K25-11: the light host dials its
 *       verified persistent list).
 *   (f) NULL policy rows: nodus_p2p_host_policy_t, per row.
 *   (g) Paths (`data_path`, `seq_dir`) are UTF-8; on Windows the reader
 *       and the writer both convert them to UTF-16 for the wide calls. Each
 *       must fit the host's buffer (sizeof data_path / seq_dir, NUL
 *       included) — _init refuses a longer one.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here is consensus state (p2p-port design §6 D1). Peers and
 * reactors are visited in fixed order. The clock reads are the
 * reference's p2p reads (D3). Randomness is transport-local OS randomness
 * (D4).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_P2P_HOST_H
#define NODUS_P2P_HOST_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dnac/cmt_p2p_netaddr.h"
#include "dnac/cmt_p2p_nodeinfo.h"
#include "dnac/cmt_p2p_transport.h"
#include "dnac/cmt_p2p_switch.h"
#include "dnac/cmt_p2p_addrbook.h"
#include "dnac/cmt_p2p_pex.h"

#include "nodus/nodus_types.h"
#include "net/nodus_net_poll.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ config (reference config.go:562-639 names; nodus.json keys) ══════ */

#define NODUS_P2P_MAX_PEER_LIST   64

/**
 * The P2P section of the node's config. Every field is a reference
 * config.go P2P key under the same name (design §4). Defaults are the
 * reference's (`nodus_p2p_config_default`), except where the reference's
 * transport does not read its own config key — noted per field.
 */
typedef struct {
    /** config.go:580 `persistent_peers` — "id@ip:port", IP literals only
     *  (R-P2P-24). Dialed on every start (node.go:562-563) and redialed
     *  on loss (switch.go:344-358). */
    char     persistent_peers[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_NETADDR_STR_MAX];
    int      n_persistent_peers;
    /** config.go:594 `unconditional_peer_ids` (the bonded set is added at
     *  run time, R-P2P-7). */
    char     unconditional_peer_ids[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_ID_CAP];
    int      n_unconditional_peer_ids;
    /** config.go:603 `private_peer_ids` — never gossiped. */
    char     private_peer_ids[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_ID_CAP];
    int      n_private_peer_ids;
    /** config.go:597 `pex` (default true). */
    bool     pex;
    /** config.go:569 `addr_book_strict` (default true; false admits
     *  private / loopback addresses — the localhost harness). */
    bool     addr_book_strict;
    /** config.go:609 `allow_duplicate_ip` (default false; test only). */
    bool     allow_duplicate_ip;
    /** config.go:572 / :575 (defaults 40 / 10). */
    int      max_num_inbound_peers;
    int      max_num_outbound_peers;
    /** config.go:585 `flush_throttle_timeout` (default 100 ms). */
    int64_t  flush_throttle_timeout_ms;
    /** config.go:588 `max_packet_msg_payload_size` (default 1024). */
    int      max_packet_msg_payload_size;
    /** config.go:591 / :592 `send_rate` / `recv_rate` (default 5 120 000 B/s). */
    int64_t  send_rate;
    int64_t  recv_rate;
    /** config.go:613 `handshake_timeout` / :614 `dial_timeout`. NOT read by
     *  the reference's transport (it uses its own 3 s and 1 s constants,
     *  transport.go:20/:22 — design §5 "Correction"); here 0 = those
     *  constants (the default), a positive value overrides them. */
    int64_t  handshake_timeout_ms;
    int64_t  dial_timeout_ms;
    /** config.go base `moniker`; empty = "nodus-" + the first 16 hex
     *  digits of this node's ID. */
    char     moniker[64];
} nodus_p2p_config_t;

void nodus_p2p_config_default(nodus_p2p_config_t *c);

/**
 * Parse one "id@ip:port" / plain ID list entry into `c` (the config
 * loaders' shared helper). @return 0; -1 when the list is full or the
 * entry does not fit.
 */
int nodus_p2p_config_add_persistent(nodus_p2p_config_t *c, const char *s);
int nodus_p2p_config_add_unconditional(nodus_p2p_config_t *c, const char *id);
int nodus_p2p_config_add_private(nodus_p2p_config_t *c, const char *id);

/* ══ the socket host ══════════════════════════════════════════════════ */

/**
 * The most accept(2) calls ONE pass makes (nodus_p2p_io_pump's accept
 * step) — every call counts, the refused and the interrupted ones
 * included (Codex 1). The reference's acceptPeers (transport.go:268
 * `go mt.acceptPeers()`, :286-353) is its own goroutine and accepts
 * without end; here the listener shares the one loop with every
 * connection and the consensus lane, and a peer that keeps the backlog
 * full of connections the filters refuse (a duplicate IP, a known
 * address — each refused AFTER accept(2) returned it) would hold the loop
 * there. No reference counterpart: the bound exists only because the
 * goroutine does not.
 * ⚠ NOT GROUNDED as a number: the default inbound limit
 * (CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS, config.go:630) — a full
 * reconnect of the default inbound set is still taken in one pass. The
 * listener stays in the readiness set with NODUS_NET_IN (EPOLLIN,
 * level-triggered), so a
 * backlog left behind wakes the next wait at once and the next pass
 * continues: nothing is refused because of the budget, only deferred.
 */
#define NODUS_P2P_ACCEPT_BUDGET CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS

/** One transport slot's socket. */
typedef struct {
    nodus_sock_t fd;         /* NODUS_SOCK_INVALID = none                */
    uint64_t gen;
    bool     connecting;     /* non-blocking connect(2) in progress      */
    bool     failed;         /* conn_failed reported; no more I/O        */
    uint32_t events;         /* NODUS_NET_* mask the set watches for it  */
    uint32_t ready;          /* NODUS_NET_* bits the last wait reported  */
} nodus_p2p_sock_t;

/**
 * Non-blocking sockets for one `cmt_p2p_transport_t`, indexed by the
 * transport's slot, on one readiness set of their own (nodus_net_poll:
 * Linux epoll, level-triggered; its wake is the eventfd the worker
 * writes). A host built with `open_listener` false runs it without a
 * listener.
 */
typedef struct {
    cmt_p2p_transport_t *t;         /* set after cmt_p2p_transport_init  */
    nodus_net_poll_t     poll;      /* the set, + the wake when asked    */
    nodus_sock_t         listen_fd; /* NODUS_SOCK_INVALID = none         */
    bool                 listen_armed;
    nodus_p2p_sock_t    *socks;
    int                  n_socks;
    /** The socket slot nodus_p2p_io_pump last SERVED (read >= 1 byte);
     *  the next pump starts just past it (atlas-dec-efa4d29c's
     *  round-robin form). -1 = none yet. */
    int                  last_served;
} nodus_p2p_io_t;

int  nodus_p2p_io_init(nodus_p2p_io_t *io, bool with_wake);
void nodus_p2p_io_free(nodus_p2p_io_t *io);
/** Bind + listen on an IP literal (Linux SO_REUSEADDR, Windows
 *  SO_EXCLUSIVEADDRUSE). @return 0 or -1 (the failure's code kept: Linux
 *  errno; Windows nodus_net_errno()). */
int  nodus_p2p_io_listen(nodus_p2p_io_t *io, const char *ip, uint16_t port);
/** The transport host's `dial` row body: a non-blocking connect(2) to
 *  `addr`'s IP literal. @return 0 connecting; -1 failed at once. */
int  nodus_p2p_io_dial(nodus_p2p_io_t *io, int slot, uint64_t gen,
                       const cmt_p2p_netaddr_t *addr);
/** The transport host's `close` row body. */
void nodus_p2p_io_close(nodus_p2p_io_t *io, int slot, uint64_t gen);
/** Wait up to `timeout_ms` for socket / wake events (nodus_net_poll_wait,
 *  batch 64 — on Linux one epoll_wait). First re-arms NODUS_NET_IN
 *  (EPOLLIN) on every socket whose `read_buf` has room again (it
 *  was cleared at backpressure), so buffered socket bytes never sleep
 *  through the wait. */
void nodus_p2p_io_wait(nodus_p2p_io_t *io, int timeout_ms);
/** One I/O pass in slot order: accept while `can_accept`, finish the
 *  connects, then per socket the continuous read (read → the connection's
 *  step → read …) and the continuous write (write → step → write …) —
 *  file header. The steps run the connection's MConnection, so reactor
 *  callbacks run inside this call. */
void nodus_p2p_io_pump(nodus_p2p_io_t *io);
/** The continuous write of every socket (the pass's last step): what
 *  `write_buf` holds and whatever the connection's SEND step produces
 *  next (no message is delivered here), until send(2) would block or
 *  nothing is left. */
void nodus_p2p_io_flush(nodus_p2p_io_t *io);

/** The host clocks (file header). Nanoseconds. */
int64_t nodus_p2p_mono_ns(void *ctx);
int64_t nodus_p2p_wall_ns(void *ctx);
/** [0, n) from OS randomness (D4). */
int64_t nodus_p2p_rand_int63n(void *ctx, int64_t n);
/** The secret connection's sign / verify under purpose 0x0A, with the
 *  `nodus_identity_t *` given as `ctx` (sign) — safe on a worker thread
 *  (nodus_sign.c: per-call buffers; qgp_dilithium.c: no static state). */
int nodus_p2p_sc_sign(void *ctx, const uint8_t *msg, size_t msg_len,
                      uint8_t sig_out[CMT_P2P_SC_SIG_SIZE]);
int nodus_p2p_sc_verify(void *ctx, const uint8_t sig[CMT_P2P_SC_SIG_SIZE],
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t pk[CMT_P2P_SC_DSA_PK_SIZE]);

/* ══ the host ═════════════════════════════════════════════════════════ */

/** The worker's queue count (outbound, inbound, ADDR; §2R4 P3) and its
 *  thread bounds. */
#define NODUS_P2P_WQ_N            3
#define NODUS_P2P_WORKERS_DEFAULT 2
#define NODUS_P2P_WORKERS_MAX     8

/**
 * The embedder's answers (file header, "the POLICY"). Every row takes
 * `ctx`; a NULL row means what the shared layer itself means by a NULL
 * row (given after each).
 */
typedef struct {
    void *ctx;
    /** Switch `is_bonded` (R-P2P-7) and the own-record gate. NULL: false
     *  (cmt_p2p_switch.c is_bonded). */
    bool     (*is_bonded)(void *ctx, const char *id);
    /** Transport `bonded_count` (the listener limit, R-P2P-27). NULL: 0. */
    int      (*bonded_count)(void *ctx);
    /** Address book `bonded_pubkey` (R-P2P-4). NULL: no key for any ID —
     *  no signed ADDR record verifies, so _init refuses NULL with PEX on
     *  (file header (e)). */
    bool     (*bonded_pubkey)(void *ctx, const char *id,
                              uint8_t pk[QGP_DSA87_PUBLICKEYBYTES]);
    /** Transport `may_receive` (cmt_p2p_peer.h "THE RECEIVE GATE").
     *  NULL: true. */
    bool     (*may_receive)(void *ctx);
    /** Transport `recv_near_full`. NULL: false (never contended). */
    bool     (*recv_near_full)(void *ctx);
    /** Transport `queue_mark`. NULL: the transport gets NO queue_mark row
     *  — every delivered message counts as a peer's turn
     *  (cmt_p2p_transport.h `queue_mark`, cmt_p2p_peer.c gate_entered). */
    uint64_t (*queue_mark)(void *ctx);
} nodus_p2p_host_policy_t;

/** What the host is built from. Every pointer is borrowed and must outlive
 *  the call (`identity` the host). */
typedef struct {
    const nodus_identity_t   *identity;      /* has_mlkem required        */
    const uint8_t            *chain_id;      /* 32 bytes: chain id or pin */
    const nodus_p2p_config_t *cfg;
    const char *listen_ip;                   /* IP literal (bind)         */
    uint16_t    listen_port;
    const char *external_ip;                 /* "" = none                 */
    const char *data_path;                   /* the address book file     */
    const char *seq_dir;                     /* the own-record seq file   */
    bool        open_listener;               /* false: no accept (tests)  */
    int         n_workers;                   /* 0 = the default (2)       */
    /** NodeInfo channels in NodeInfo order; PEX (0x00) is appended by the
     *  host when `cfg->pex`. At most CMT_P2P_MAX_NUM_CHANNELS − 1. */
    const uint8_t           *channels;
    size_t                   n_channels;
    /** Registered on the switch in this order (copied), before PEX. Each
     *  reactor's `get_channels` array must outlive the host. */
    const cmt_p2p_reactor_t *reactors;
    int                      n_reactors;
    nodus_p2p_host_policy_t  policy;
} nodus_p2p_host_params_t;

struct nodus_p2p_wjob;                       /* a worker job (private) */

/**
 * The host. A complete type so an embedder can hold it by value; its
 * fields are the host's — an embedder reads them (the switch, the
 * config, the address book, PEX, the self ID) and writes only
 * `self_bonded`.
 */
typedef struct {
    const nodus_identity_t     *identity;
    nodus_p2p_config_t          cfg;
    uint8_t                     chain_id[32];
    char                        self_id[CMT_P2P_ID_CAP];
    char                        data_path[256];
    char                        seq_dir[256];
    char                        listen_ip[64];
    uint16_t                    listen_port;
    char                        external_ip[64];
    int                         n_workers;     /* params.n_workers       */
    nodus_p2p_host_policy_t     policy;

    nodus_p2p_io_t              io;
    bool                        io_init;       /* nodus_p2p_io_init ran  */
    cmt_p2p_node_info_t        *ni;
    cmt_p2p_transport_t         t;
    bool                        t_init;
    cmt_p2p_switch_t            sw;
    bool                        sw_init;
    cmt_p2p_addrbook_t         *book;
    cmt_p2p_addr_book_t         seam;
    cmt_p2p_pex_t              *pex;

    /* the worker */
    pthread_mutex_t             mu;
    pthread_cond_t              cv;
    bool                        mu_init;
    struct nodus_p2p_wjob      *qh[NODUS_P2P_WQ_N], *qt[NODUS_P2P_WQ_N];
    int                         qdepth[NODUS_P2P_WQ_N];
    struct nodus_p2p_wjob      *dh, *dt;
    bool                        stop;
    pthread_t                   th[NODUS_P2P_WORKERS_MAX];
    int                         n_th;

    /* our own ADDR record (N7) */
    bool                        have_own_addr;
    cmt_p2p_ip_t                own_ip;
    uint16_t                    own_port;
    uint64_t                    own_seq;
    bool                        own_seq_exhausted;   /* UINT64_MAX logged */
    bool                        have_own_rec;
    uint8_t                     own_rec[CMT_P2P_ADDR_REC_SIZE];
    /** This node's ID is in the embedder's bonded set: PEX pushes the own
     *  record only then (cmt_p2p_pex.h). Written by the embedder (the
     *  witness's bonded-set refresh); false for a witness-free host. */
    bool                        self_bonded;

    /* lifecycle (file header, STATE) */
    bool                        init_ok;       /* _init succeeded        */
    bool                        started;       /* _start was entered     */
} nodus_p2p_host_t;

/**
 * Build the host into `h` (zeroed here first): _init in the file
 * header. @return 0, or -1 (logged) — then call nodus_p2p_host_free(h).
 * Refused before anything is built (logged): a NULL required parameter,
 * n_channels over CMT_P2P_MAX_NUM_CHANNELS − 1, n_reactors < 0, a peer-list
 * count outside [0, NODUS_P2P_MAX_PEER_LIST], a data_path / seq_dir that
 * does not fit the host's buffer, `cfg->pex` without
 * `policy.bonded_pubkey`. Refused after the reactors are registered: a
 * NodeInfo channel set (`channels` + PEX) that is not exactly the union of
 * the registered reactors' channels.
 */
int  nodus_p2p_host_init(nodus_p2p_host_t *h, const nodus_p2p_host_params_t *prm);
/** Start a built host: _start in the file header. @return 0, or -1
 *  (logged) — then call nodus_p2p_host_free(h). -1 with no side effect
 *  when the host is not init_ok or was already started. */
int  nodus_p2p_host_start(nodus_p2p_host_t *h);
/** One whole pass for a witness-free caller: _poll_io, _pex_tick,
 *  _own_record_check, _flush. @return 0; -1 (nothing done) when the host
 *  is not running (not init_ok, not started, or freed). */
int  nodus_p2p_host_poll(nodus_p2p_host_t *h, int timeout_ms);
/** The pass's steps (file header, LIFECYCLE). */
void nodus_p2p_host_poll_io(nodus_p2p_host_t *h, int timeout_ms);
void nodus_p2p_host_pex_tick(nodus_p2p_host_t *h);
void nodus_p2p_host_own_record_check(nodus_p2p_host_t *h);
void nodus_p2p_host_flush(nodus_p2p_host_t *h);
/** Stop the switch (the book is saved), finish or drop every worker job,
 *  close every socket, release everything _init / _start built. NULL-safe;
 *  `h` itself is the caller's. */
void nodus_p2p_host_free(nodus_p2p_host_t *h);

/** The port actually listened on (0 = none) — tests bind port 0. */
uint16_t nodus_p2p_host_listen_port(const nodus_p2p_host_t *h);
/** This node's p2p ID. */
const char *nodus_p2p_host_id(const nodus_p2p_host_t *h);
/** The switch. */
cmt_p2p_switch_t *nodus_p2p_host_switch(nodus_p2p_host_t *h);
/** Connected peers, in the switch's peer-set order. */
int  nodus_p2p_host_peer_count(const nodus_p2p_host_t *h);
/** The ID of the i-th connected peer. @return false outside the set. */
bool nodus_p2p_host_peer_id_at(const nodus_p2p_host_t *h, int i,
                               char out[CMT_P2P_ID_CAP]);
/** Whether `peer_id` is in the switch's peer set now (a connected peer). */
bool nodus_p2p_host_has_peer(const nodus_p2p_host_t *h, const char *peer_id);
/** Send `msg` to the connected peer `peer_id` on channel `ch` (Send ≡
 *  TrySend, R-P2P-19). @return true when the channel's queue took it. */
bool nodus_p2p_host_send(nodus_p2p_host_t *h, const char *peer_id,
                         uint8_t ch, const uint8_t *msg, size_t len);
/**
 * The address the signed ADDR record of the identity with chain key `pk`
 * names, as "ip:port" (R-P2P-4: only a verified record is believed). Our
 * own identity answers from our own record.
 * @return true and `out`, or false (no record held).
 */
bool nodus_p2p_host_signed_addr(nodus_p2p_host_t *h,
                                const uint8_t pk[NODUS_PK_BYTES],
                                char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_P2P_HOST_H */
