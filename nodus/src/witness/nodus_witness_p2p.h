/**
 * @file nodus/src/witness/nodus_witness_p2p.h
 * @brief The nodus HOST of the ported cometbft @709fd12b p2p layer
 *        (shared/dnac/cmt_p2p_*) — the witness port 4004's ONLY
 *        transport (fleet P2P-PORT phase F5).
 *
 * Governing records: docs/plans/decisions/2026-09-26-witness-port-session.md
 * (K2 — the reference admission model with the chain's bonded identities
 * exempt from the inbound cap; N7 SON — validator addresses leave the DHT
 * and travel as self-signed ADDR records over PEX; the sentry knobs; the
 * "P2P portu bayt/biçim onayları" section — channels 0x70 / 0x71 and the
 * address-book file); docs/plans/2026-09-26-p2p-port-design.md §2 (the
 * glue row), §3 (channels and deletions), §4 (config), §5 (R-P2P-n);
 * docs/plans/2026-09-26-witness-port-session-design.md §2R3 N5 (the bonded
 * set), §2R4 P1 (the chain-quorum quarantine is DELETED), P3 (inbound and
 * outbound handshakes never share a queue), P4 (persistent peers dialed on
 * every start; persisted address book; own record pushed), P5.
 *
 * ── WHAT THE HOST IS ───────────────────────────────────────────────────
 * The shared/dnac p2p layer is socket-free, clock-free and thread-free:
 * it is DRIVEN. This module is what drives it on a live node:
 *   · the 4004 SOCKETS (`nodus_p2p_io_t`): non-blocking TCP listen /
 *     accept / connect / read / write on its own epoll set, RAW byte
 *     streams into and out of `cmt_p2p_transport_read_buf` /
 *     `_write_buf` — nodus_tcp's frame layer is NOT used on 4004.
 *     `can_accept` is asked before every accept(2) (LimitListener,
 *     transport.go:261-263). Reads and writes are CONTINUOUS within a pass,
 *     as the reference's recvRoutine / sendRoutine goroutines are
 *     (connection.go:590-694, :429-507; R-P2P-17): a socket is read into
 *     `read_buf`, and whenever that is full the connection's step
 *     (`cmt_p2p_transport_pump_conn`) consumes it and the socket is read
 *     again — until recv(2) would block, the step frees no room (true
 *     backpressure: the recv flowrate Monitor, connection.go:598, or the
 *     MConnection refuses), or one recv-Monitor sample's quota was taken
 *     (⚠ NOT GROUNDED per-call cap, nodus_witness_p2p.c io_read_budget);
 *     writes likewise refill `write_buf` from the step — its SEND half
 *     only: the write path delivers no message (decision
 *     2026-09-27-p2p-fix-2.md (4)) — between send(2)s until send would
 *     block or nothing is left. At most NODUS_P2P_ACCEPT_BUDGET accept(2)
 *     calls per pass. EPOLLIN is cleared only
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
 *   · IDENTITY: the node key is the nodus identity (nodus.pk / nodus.sk,
 *     ML-DSA-87), the KEM key nodus.mlkem_{pk,sk}. Our NodeInfo: network =
 *     the 32-byte version-3 chain id in hex (a joiner that has not adopted
 *     yet puts its genesis pin there — the same 32 bytes), P2P version 8,
 *     channels 0x20-0x23, 0x30, 0x70, 0x71 and 0x00 when PEX is on, a
 *     non-empty moniker, an IP-literal listen address.
 *   · the BONDED SET (K2 / N5): the local chain's `validators` rows with
 *     status ACTIVE (0) or ELIGIBLE (4), plus the members of the committees
 *     for tip + 1 and tip − 1 (the two committees the deleted B1 IDENT gate
 *     consulted) — recomputed whenever the local tip moves. It is the
 *     switch's `is_bonded` (unconditional, R-P2P-7), the transport's
 *     `bonded_count` (the listener limit, R-P2P-27) and the address book's
 *     `bonded_pubkey` (R-P2P-4).
 *   · our own signed ADDR record (N7 ADDR bytes, purpose 0x0B): its `seq`
 *     is persisted next to the identity BEFORE anything is signed; at
 *     start seq = max(stored, the highest own seq the book has seen) + 1.
 *   · the address book file, next to the chain database, replaced
 *     atomically (temporary file + fsync + rename).
 *   · the REACTORS: PEX (0x00), the consensus reactor cmt_conr
 *     (0x20-0x23), the mempool reactor cmt_memr (0x30), and two nodus
 *     reactors — 0x70 the genesis bundle (the former tier-3 verbs 24/25)
 *     and 0x71 the governance approval (the former verbs 40/41).
 *
 * ── THE CONSENSUS SEAM ─────────────────────────────────────────────────
 * cmt_conr / cmt_memr name a peer by an INDEX (0 .. CMT_CONR_MAX_PEERS−1).
 * This host keeps one table of that size: a peer the switch admits gets
 * the lowest free index; the index is released when the switch removes the
 * peer (the switch frees the peer at the end of the next tick — the table
 * drops its pointer at removal). `send` / `try_send` → the peer's
 * Send / TrySend (Send ≡ TrySend, R-P2P-19); `stop_peer_for_error` →
 * `cmt_p2p_switch_stop_peer_for_error`, deferred until the reactor call
 * that raised it has returned (cmt_memr.h: a host row must not re-enter
 * the reactor). The peer id handed to `cmt_conr_init_peer` is
 * SHA3-512(the peer's AUTHENTICATED ML-DSA-87 key)[0..31] — read from the
 * secret connection, never from a message field.
 * DEVIATION R-P2P-47 (proposed): the consensus and mempool reactors are
 * registered on the switch from the start, as SHIMS: before the node holds
 * a chain (a pinned joiner) or before genesis time, a peer is given its
 * index but the two reactors are not told (there is none yet, or it is not
 * running); `nodus_witness_p2p_lane_live` then runs, for every connected
 * peer in index order, the reference's addPeer order — every reactor's
 * InitPeer, then every reactor's AddPeer (switch.go:829-831, :858-860).
 * A consensus / mempool message from a peer the reactors do not know yet
 * is dropped. The reference has no such state: a node starts with its
 * genesis document and its reactors already built.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here is consensus state (p2p-port design §6 D1). The bonded set
 * is read from committed chain state and sorted by ID; peers, indices and
 * reactors are visited in fixed order. The clock reads are the reference's
 * p2p reads (D3). Randomness is transport-local OS randomness (D4).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_P2P_H
#define NODUS_WITNESS_P2P_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dnac/cmt_p2p_netaddr.h"
#include "dnac/cmt_p2p_transport.h"
#include "dnac/cmt_p2p_switch.h"
#include "dnac/cmt_conr.h"
#include "dnac/cmt_memr.h"
#include "dnac/cmt_time.h"

#include "nodus/nodus_types.h"
#include "witness/nodus_witness_cmt_store.h"

#ifdef __cplusplus
extern "C" {
#endif

struct nodus_witness;

/* ══ the nodus channels (R-P2P-5, OPERATOR-APPROVED 2026-09-26) ═══════ */

/** Genesis bundle — the former tier-3 verbs 24 (request) / 25 (response).
 *  The message is the verb's former `a` body, unchanged
 *  (nodus_tier3.h). */
#define NODUS_P2P_CH_GBUNDLE  0x70
/** Governance approval — the former tier-3 verbs 40 (request) / 41
 *  (response); the same rule. */
#define NODUS_P2P_CH_CC_APPR  0x71

/* The two nodus channels' descriptors (ChannelDescriptor fields,
 * connection.go:752-760). ⚠ NOT GROUNDED — no reference channel carries
 * these messages; each value is a choice, recorded for its register row.
 * RecvMessageCapacity is each channel's largest message
 * (NODUS_T3_GBUNDLE_MSG_MAX / NODUS_T3_CC_APPR_MSG_MAX, nodus_tier3.h). */
/** 1 = the lowest priority the reference uses (VoteSetBits,
 *  consensus/reactor.go:175): a bundle chunk must never starve votes. */
#define NODUS_P2P_GBUNDLE_PRIORITY     1
/** 4 chunks: a joiner asks for one 48 KB chunk per request interval, so a
 *  few queued chunks cover every joiner a node serves at once. */
#define NODUS_P2P_GBUNDLE_SEND_QUEUE   4
/** 1, as the bundle: a governance approval is rare and not latency-bound. */
#define NODUS_P2P_CCAPPR_PRIORITY      1
/** 2 messages: one request / one reply per approval collection (decision
 *  2026-09-26-cc-approval-via-own-node.md — a node asks each seat once),
 *  plus one slot of slack. */
#define NODUS_P2P_CCAPPR_SEND_QUEUE    2

/* ══ config (reference config.go:554-631 names; nodus.json keys) ══════ */

#define NODUS_P2P_MAX_PEER_LIST   64

/**
 * The P2P section of the node's config. Every field is a reference
 * config.go P2P key under the same name (design §4). Defaults are the
 * reference's (`nodus_p2p_config_default`), except where the reference's
 * transport does not read its own config key — noted per field.
 */
typedef struct {
    /** config.go:572 `persistent_peers` — "id@ip:port", IP literals only
     *  (R-P2P-24). Dialed on every start (node.go:563-564) and redialed
     *  on loss (switch.go:343-357). */
    char     persistent_peers[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_NETADDR_STR_MAX];
    int      n_persistent_peers;
    /** config.go:586 `unconditional_peer_ids` (the bonded set is added at
     *  run time, R-P2P-7). */
    char     unconditional_peer_ids[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_ID_CAP];
    int      n_unconditional_peer_ids;
    /** config.go:595 `private_peer_ids` — never gossiped. */
    char     private_peer_ids[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_ID_CAP];
    int      n_private_peer_ids;
    /** config.go:589 `pex` (default true). */
    bool     pex;
    /** config.go:561 `addr_book_strict` (default true; false admits
     *  private / loopback addresses — the localhost harness). */
    bool     addr_book_strict;
    /** config.go:601 `allow_duplicate_ip` (default false; test only). */
    bool     allow_duplicate_ip;
    /** config.go:564 / :567 (defaults 40 / 10). */
    int      max_num_inbound_peers;
    int      max_num_outbound_peers;
    /** config.go:577 `flush_throttle_timeout` (default 100 ms). */
    int64_t  flush_throttle_timeout_ms;
    /** config.go:580 `max_packet_msg_payload_size` (default 1024). */
    int      max_packet_msg_payload_size;
    /** config.go:583 / :584 `send_rate` / `recv_rate` (default 5 120 000 B/s). */
    int64_t  send_rate;
    int64_t  recv_rate;
    /** config.go:605 `handshake_timeout` / :606 `dial_timeout`. NOT read by
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
 * (CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS, config.go:622) — a full
 * reconnect of the default inbound set is still taken in one pass. The
 * listener stays in the epoll set with EPOLLIN (level-triggered), so a
 * backlog left behind wakes the next wait at once and the next pass
 * continues: nothing is refused because of the budget, only deferred.
 */
#define NODUS_P2P_ACCEPT_BUDGET CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS

/** One transport slot's socket. */
typedef struct {
    int      fd;             /* -1 = none                                */
    uint64_t gen;
    bool     connecting;     /* non-blocking connect(2) in progress      */
    bool     failed;         /* conn_failed reported; no more I/O        */
    uint32_t events;         /* what the epoll set watches for it        */
    uint32_t ready;          /* what the last epoll_wait reported        */
} nodus_p2p_sock_t;

/**
 * Non-blocking sockets for one `cmt_p2p_transport_t`, indexed by the
 * transport's slot. Linux (epoll); a host built with `open_listener`
 * false runs it without a listener.
 */
typedef struct {
    cmt_p2p_transport_t *t;         /* set after cmt_p2p_transport_init  */
    int                  epfd;
    int                  listen_fd; /* -1 = none                         */
    bool                 listen_armed;
    int                  wake_fd;   /* eventfd the worker writes, or -1  */
    nodus_p2p_sock_t    *socks;
    int                  n_socks;
    /** The socket slot nodus_p2p_io_pump last SERVED (read >= 1 byte);
     *  the next pump starts just past it (atlas-dec-efa4d29c's
     *  round-robin form). -1 = none yet. */
    int                  last_served;
} nodus_p2p_io_t;

int  nodus_p2p_io_init(nodus_p2p_io_t *io, bool with_wake);
void nodus_p2p_io_free(nodus_p2p_io_t *io);
/** Bind + listen on an IP literal. @return 0 or -1 (errno kept). */
int  nodus_p2p_io_listen(nodus_p2p_io_t *io, const char *ip, uint16_t port);
/** The transport host's `dial` row body: a non-blocking connect(2) to
 *  `addr`'s IP literal. @return 0 connecting; -1 failed at once. */
int  nodus_p2p_io_dial(nodus_p2p_io_t *io, int slot, uint64_t gen,
                       const cmt_p2p_netaddr_t *addr);
/** The transport host's `close` row body. */
void nodus_p2p_io_close(nodus_p2p_io_t *io, int slot, uint64_t gen);
/** Wait up to `timeout_ms` for socket / wake events (epoll_wait). First
 *  re-arms EPOLLIN on every socket whose `read_buf` has room again (it
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

/* ══ the witness host ═════════════════════════════════════════════════ */

typedef struct nodus_witness_p2p nodus_witness_p2p_t;

/** What the host is built from. Every pointer is borrowed and must outlive
 *  the host. */
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
} nodus_witness_p2p_params_t;

/**
 * Build the host for `w` (the chain, the bonded set, the 0x70 / 0x71
 * handlers) and start it: node/node.go:285-422's p2p half — transport,
 * switch, the reactors, the address book (loaded, R-P2P-38), PEX; then
 * OnStart (node.go:548-580): switch start, persistent peers dialed.
 * @return the host, or NULL (logged) — then nothing is left running.
 */
nodus_witness_p2p_t *nodus_witness_p2p_new(struct nodus_witness *w,
                                           const nodus_witness_p2p_params_t *prm);

/** Stop the switch (the book is saved), finish or drop every worker job,
 *  close every socket, free everything. NULL-safe. The consensus lane must
 *  be unbound first. */
void nodus_witness_p2p_free(nodus_witness_p2p_t *p);

/**
 * One pass of the host (the witness tick calls it every iteration):
 * worker results, the socket wait (at most `timeout_ms`) and I/O, the
 * switch's tick (handshakes, every peer's MConnection, accepts, dials,
 * reconnects), the PEX tick, the bonded-set and own-record refresh, and a
 * final write of everything the pass produced.
 */
void nodus_witness_p2p_poll(nodus_witness_p2p_t *p, int timeout_ms);

/** The port actually listened on (0 = none) — tests bind port 0. */
uint16_t nodus_witness_p2p_listen_port(const nodus_witness_p2p_t *p);
/** This node's p2p ID. */
const char *nodus_witness_p2p_id(const nodus_witness_p2p_t *p);
/** The switch (tests, the 0x70 joiner). */
cmt_p2p_switch_t *nodus_witness_p2p_switch(nodus_witness_p2p_t *p);

/** Connected peers, in the switch's peer-set order. */
int  nodus_witness_p2p_peer_count(const nodus_witness_p2p_t *p);
/** The ID of the i-th connected peer. @return false outside the set. */
bool nodus_witness_p2p_peer_id_at(const nodus_witness_p2p_t *p, int i,
                                  char out[CMT_P2P_ID_CAP]);
/** Whether `peer_id` is in the switch's peer set now (a connected peer). */
bool nodus_witness_p2p_has_peer(const nodus_witness_p2p_t *p, const char *peer_id);
/** Send `msg` to the connected peer `peer_id` on channel `ch` (Send ≡
 *  TrySend, R-P2P-19). @return true when the channel's queue took it. */
bool nodus_witness_p2p_send(nodus_witness_p2p_t *p, const char *peer_id,
                            uint8_t ch, const uint8_t *msg, size_t len);

/* ── channel 0x70 (red-team H2; no reference counterpart, R-P2P-5) ──── */

/** The joiner's genesis-bundle request: send `msg` to `peer_id` on 0x70
 *  and remember (peer_id, offset) as the ONE outstanding request (any
 *  earlier one is forgotten first). @return true when queued. */
bool nodus_witness_p2p_gb_request(nodus_witness_p2p_t *p, const char *peer_id,
                                  uint64_t offset, const uint8_t *msg,
                                  size_t len);
/** A 0x70 response from `peer_id` for `offset`: true — and the
 *  outstanding request is consumed — only when it answers exactly that
 *  request; false for everything else (the caller DROPS it, never stops
 *  the sender: a late honest chunk looks the same). */
bool nodus_witness_p2p_gb_take(nodus_witness_p2p_t *p, const char *peer_id,
                               uint64_t offset);
/** The serving side's per-requester gate: true (and the requester's slot
 *  stamped `now_ms`, monotonic) when `peer_id` was not served within the
 *  last 100 ms; false otherwise, or when the bounded table is full of
 *  requesters all served inside that gap. */
bool nodus_witness_p2p_gb_serve_allow(nodus_witness_p2p_t *p, const char *peer_id,
                                      uint64_t now_ms);
/** The serving side's in-memory copy of the genesis bundle of `chain`
 *  (RT2 B-F2): true and `*out` / `*len` (owned by the host, valid until
 *  the host is freed or the copy replaced) when it is held; false when
 *  nothing is held for that chain — the caller reads the database once
 *  and hands the bytes to nodus_witness_p2p_gb_bundle_keep. */
bool nodus_witness_p2p_gb_bundle(nodus_witness_p2p_t *p, const uint8_t chain[32],
                                 const uint8_t **out, size_t *len);
/** Keep `bytes` (malloc'd, `len` > 0; ownership passes to the host in
 *  every case — freed at once on refusal) as the bundle copy of `chain`,
 *  replacing any other. @return true kept; false refused (NULL / empty). */
bool nodus_witness_p2p_gb_bundle_keep(nodus_witness_p2p_t *p, const uint8_t chain[32],
                                      uint8_t *bytes, size_t len);

/** K2 / N5 — the bonded set (file header). */
bool nodus_witness_p2p_is_bonded(nodus_witness_p2p_t *p, const char *id);
int  nodus_witness_p2p_bonded_count(nodus_witness_p2p_t *p);
/** The bonded set, sorted by ID: the i-th entry's ID and chain pubkey.
 *  @return false outside the set. */
bool nodus_witness_p2p_bonded_at(nodus_witness_p2p_t *p, int i,
                                 char id[CMT_P2P_ID_CAP],
                                 uint8_t pk[NODUS_PK_BYTES]);

/**
 * The address the signed ADDR record of the bonded identity with chain
 * key `pk` names, as "ip:port" (R-P2P-4: only a verified record is
 * believed). Our own identity answers from our own record.
 * @return true and `out`, or false (no record held).
 */
bool nodus_witness_p2p_signed_addr(nodus_witness_p2p_t *p,
                                   const uint8_t pk[NODUS_PK_BYTES],
                                   char *out, size_t cap);

/** Recompute the bonded set now (the tip moved; a chain was adopted).
 *  Only the IDs that JOINED the set since the last refresh are handed to
 *  the address book's purge (cmt_p2p_addrbook_purge_bonded_ids; RT2
 *  D-F1): an unchanged set purges nothing. */
void nodus_witness_p2p_refresh_bonded(nodus_witness_p2p_t *p);
/** Diagnostic: the number of IDs that joined the bonded set, summed over
 *  every refresh since the host was built (what the purge was given; a
 *  refresh that found the same set adds 0). */
uint64_t nodus_witness_p2p_bonded_joined_total(const nodus_witness_p2p_t *p);

/* ══ the consensus lane (file header, "THE CONSENSUS SEAM") ═══════════ */

/**
 * Prepare the host rows the two reactors are built with: the block-store
 * rows read `store`; `now` is the consensus clock (the SAME callback as
 * the state machine's, cmt_conr.h). Call before cmt_conr_init /
 * cmt_memr_init. @return CMT_OK; CMT_FAULT (NULL / memory / already
 * prepared).
 */
int nodus_witness_p2p_lane_prepare(nodus_witness_p2p_t *p,
                                   nodus_cmt_store_t *store,
                                   cmt_now_fn now, void *now_ctx);
/** The host tables and the receive arena for cmt_conr_init /
 *  cmt_memr_init (valid for the host's life). */
const cmt_conr_host_t *nodus_witness_p2p_conr_host(nodus_witness_p2p_t *p);
const cmt_memr_host_t *nodus_witness_p2p_memr_host(nodus_witness_p2p_t *p);
cmt_pb_arena_t        *nodus_witness_p2p_recv_arena(nodus_witness_p2p_t *p);
/** The reactors the shims now feed (both constructed, not yet started). */
void nodus_witness_p2p_lane_bind(nodus_witness_p2p_t *p, cmt_conr_t *conr,
                                 cmt_memr_t *memr);
/** Both reactors are running: admit every connected peer (R-P2P-47). */
int  nodus_witness_p2p_lane_live(nodus_witness_p2p_t *p);
/** cmt_conr_tick + cmt_memr_tick, then the deferred StopPeerForErrors.
 *  @return CMT_OK or CMT_FAULT; `*next_deadline_ns` the earlier of the
 *  two reactors' deadlines (INT64_MAX = none). */
int  nodus_witness_p2p_lane_tick(nodus_witness_p2p_t *p,
                                 int64_t *next_deadline_ns);
/** Detach the reactors (before they are freed): every peer leaves them. */
void nodus_witness_p2p_lane_unbind(nodus_witness_p2p_t *p);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_P2P_H */
