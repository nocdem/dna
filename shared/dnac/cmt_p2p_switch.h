/**
 * @file shared/dnac/cmt_p2p_switch.h
 * @brief cometbft @v0.38.26 `p2p/switch.go` (+ `p2p/base_reactor.go`,
 *        `p2p/types.go`) ported to C — the Switch: reactors, the peer set,
 *        admission limits, dialing, persistent-peer reconnection.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F3 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row "switch.go", §9). Only its tests construct one; the nodus glue
 * (nodus_witness_p2p, F5) plugs the consensus / mempool reactors in
 * through `cmt_p2p_reactor_t`. Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * Governing records: docs/plans/decisions/2026-09-26-witness-port-session.md
 * K2 (the reference admission model — an inbound cap — with identities
 * that have a stake record on chain EXEMPT from it; one connection per
 * identity); session design §2R3 N5 (the bonded set), §2R4 P2 (one
 * connection per identity for everyone; the cross-dial tie-break).
 *
 * ── GOROUTINES → ONE EVENT LOOP ────────────────────────────────────────
 * `cmt_p2p_switch_tick` is one pass of every switch goroutine, in this
 * order: the transport's pass (handshakes, every peer's MConnection);
 * `acceptRoutine` (switch.go:636-724) over the upgraded inbound
 * connections and the dials that finished; the timers of
 * `dialPeersAsync` (:497-548) and `reconnectToPeer` (:400-448); then the
 * peers stopped during the pass are freed. The reference's blocking
 * `DialPeerWithAddress` (:554-563) is split: the call returns at once
 * (or with ErrCurrentlyDialingOrExistingAddress / a transport refusal),
 * the address stays in `dialing` until the dial's outcome arrives, and
 * then `addOutboundPeerWithConfig`'s tail (:752-781) runs.
 * `time.Sleep` in `randomSleep` (:566-569) becomes a deadline on the
 * host's MONOTONIC clock; its random part comes from the host's
 * `rand_int63n` — transport-local randomness (design §6 D4), never a
 * consensus value.
 *
 * ── THE REACTOR INTERFACE (base_reactor.go:15-44) ──────────────────────
 * `cmt_p2p_reactor_t` — GetChannels, InitPeer, AddPeer, RemovePeer,
 * Receive (+ optional Start / Stop). Messages are BYTES: the reactor
 * marshals what it sends and unmarshals what it receives (the Envelope's
 * proto.Message and the Wrapper / Unwrapper steps, types.go:13-35, are the
 * reactor's — cmt_conr / cmt_memr already work on bytes, cmt_conr.h
 * R3-A-1). `SetSwitch` (:19) is the reactor's own ctx.
 *
 * ── ADMISSION ──────────────────────────────────────────────────────────
 *   · IsPeerUnconditional(id) (:318-321) = the configured
 *     `unconditional_peer_ids` ∪ the host's `is_bonded(id)` — DEVIATION
 *     R-P2P-7 (K2): the chain's bonded set (session design N5: validators
 *     ACTIVE / ELIGIBLE + the committees the B1 gate consults) is added at
 *     run time. It is asked AFTER authentication only — an ID is unknown
 *     before (§2R4 P2).
 *   · inbound cap (:694-710): an inbound peer that is not unconditional is
 *     refused when `max_num_inbound_peers` non-unconditional inbound
 *     peers are connected. NumPeers (:301-316) does not count
 *     unconditional peers.
 *   · `MaxNumOutboundPeers` (:324-326) is only reported: the reference
 *     enforces it in the PEX reactor (pex_reactor.go, F4), not here.
 *   · duplicate ID (:784-788): refused for EVERY peer, unconditional and
 *     bonded included.
 *   · DEVIATION R-P2P-23 (cross-dial tie-break, §2R4 P2 — the reference
 *     has none): when the new peer's ID is already connected and the two
 *     connections run in OPPOSITE directions, the connection whose DIALER
 *     has the lower ID (strcmp of the two lowercase-hex IDs) is kept —
 *     the dialer of an outbound connection is this node, of an inbound one
 *     the peer. If the newcomer wins, the incumbent is removed with
 *     StopPeerGracefully (no reconnect) before the newcomer is added;
 *     otherwise the newcomer is refused as the reference refuses any
 *     duplicate. Both ends reach the same choice. Two connections in the
 *     SAME direction: the newcomer is refused (reference).
 *     NOTE (reference fact, unchanged here): with `allow_duplicate_ip`
 *     false the ConnDuplicateIPFilter (transport.go:88-104) refuses the
 *     crossing INBOUND connection on both sides before any identity is
 *     known — the dialing side's outbound connection already holds that
 *     IP in the connection set (transport.go:406) — so both crossed
 *     dials fail and the random redial (:424) sorts it out; the tie-break
 *     only ever sees crossings that passed the IP filter
 *     (`allow_duplicate_ip`, or distinct addresses).
 *
 * ── OTHER DEVIATIONS (proposed rows) ───────────────────────────────────
 *   R-P2P-29  `addPeer` on a switch that is not running (:823-827) returns
 *             nil in the reference and leaves the connection open with no
 *             owner; here it returns CMT_P2P_ERR_NOT_RUNNING so the caller
 *             closes and frees it.
 *   R-P2P-30  reactors are iterated in registration order (the reference
 *             ranges over a Go map, :237, :259, :374, :830, :859 — random
 *             order); `Broadcast` sends to the peers one after another in
 *             `List()` order instead of one goroutine each (:275-297) and
 *             returns the number that succeeded.
 *   R-P2P-31  the AddrBook (:52-61) is optional here (a table of callbacks,
 *             F4); the reference calls it without a nil check on the
 *             IsSelf paths (:653-655, :757-758) and in AddPrivatePeerIDs
 *             (:622).
 *   R-P2P-32  `peer_set_remove` refuses a DIFFERENT peer object that has
 *             the same ID (the reference's lookup is by ID only,
 *             peer_set.go:111) — the tie-break is the one place two peers
 *             with one ID coexist for an instant.
 * NOT ported: metrics, `SetLogger`, `TestDialFail` (:738-741, test-only),
 * `SwitchPeerFilters` / `filterTimeout` (:93-94, :790-807 — only the ABCI
 * `FilterPeers` hook uses them, setup.go:383-399; R-P2P-25), `NodeKey`
 * (the transport's).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here is consensus state (design §6 D1): peer choice, dial order
 * and jitter are node-local transport. Iteration over reactors and peers
 * is in a fixed order (R-P2P-30). Clock: the host's monotonic `now_ns`
 * (the transport's), for `randomSleep` deadlines only (D3).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_SWITCH_H
#define CMT_P2P_SWITCH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_p2p_mconn.h"
#include "cmt_p2p_netaddr.h"
#include "cmt_p2p_nodeinfo.h"
#include "cmt_p2p_peer.h"
#include "cmt_p2p_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ switch.go:19-33 — constants ══════════════════════════════════════ */

#define CMT_P2P_DIAL_RANDOMIZER_INTERVAL_MS   3000   /* :22 */
#define CMT_P2P_RECONNECT_ATTEMPTS            20     /* :26 */
#define CMT_P2P_RECONNECT_INTERVAL_NS  (5LL * CMT_P2P_NS_PER_SEC)   /* :27 */
#define CMT_P2P_RECONNECT_BACKOFF_ATTEMPTS    10     /* :31 */
#define CMT_P2P_RECONNECT_BACKOFF_BASE_SECONDS 3     /* :32 */

/** config.go:630-631 defaults. */
#define CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS  40
#define CMT_P2P_DEFAULT_MAX_NUM_OUTBOUND_PEERS 10

#define CMT_P2P_SWITCH_MAX_REACTORS 16

/* ══ base_reactor.go — the reactor interface ══════════════════════════ */

typedef struct {
    const char *name;                 /* AddReactor(name, …) :167       */
    void *ctx;
    /** :23 GetChannels. The array stays valid while the reactor is
     *  registered. */
    const cmt_p2p_ch_desc_t *(*get_channels)(void *ctx, int *n);
    /** service.Service Start / Stop (:16; switch.go:237-242, :259-263).
     *  Optional. Start returns 0 on success. */
    int  (*start)(void *ctx);
    void (*stop)(void *ctx);
    /** :31 InitPeer — before the peer starts. Optional. */
    void (*init_peer)(void *ctx, cmt_p2p_peer_t *p);
    /** :35 AddPeer — after the peer is started and in the peer set. */
    void (*add_peer)(void *ctx, cmt_p2p_peer_t *p);
    /** :39 RemovePeer — `reason` 0 is the reference's nil (graceful). */
    void (*remove_peer)(void *ctx, cmt_p2p_peer_t *p, int reason);
    /** :43 Receive — `msg` valid only during the call. May call
     *  `cmt_p2p_switch_stop_peer_for_error` / the peer's Send. */
    void (*receive)(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                    const uint8_t *msg, size_t len);
} cmt_p2p_reactor_t;

/* ══ the AddrBook seam (switch.go:52-61) — F4 fills it ════════════════ */

typedef struct {
    void *ctx;
    int  (*add_address)(void *ctx, const cmt_p2p_netaddr_t *addr,
                        const cmt_p2p_netaddr_t *src);
    void (*add_private_ids)(void *ctx, const char *const *ids, int n);
    void (*add_our_address)(void *ctx, const cmt_p2p_netaddr_t *addr);
    void (*mark_good)(void *ctx, const char *id);
    void (*remove_address)(void *ctx, const cmt_p2p_netaddr_t *addr);
    void (*save)(void *ctx);
} cmt_p2p_addr_book_t;

/* ══ config + host ════════════════════════════════════════════════════ */

/** The fields of config.go:548-621 the switch reads. */
typedef struct {
    int  max_num_inbound_peers;       /* :572, default 40 */
    int  max_num_outbound_peers;      /* :575, default 10 */
    bool allow_duplicate_ip;          /* :609 (test only)  */
} cmt_p2p_switch_config_t;

void cmt_p2p_switch_default_config(cmt_p2p_switch_config_t *cfg);

typedef struct {
    void *ctx;
    /** [0, n) — `sw.rng.Int63n` (:567) and `Perm` (:524). Transport-local
     *  (design §6 D4). Required. */
    int64_t (*rand_int63n)(void *ctx, int64_t n);
    /** R-P2P-7: true if `id` is in the local chain's bonded set (N5).
     *  May be NULL (= nobody). */
    bool (*is_bonded)(void *ctx, const char *id);
} cmt_p2p_switch_host_t;

/* ══ the switch ═══════════════════════════════════════════════════════ */

typedef struct {
    cmt_p2p_netaddr_t addr;
    int64_t at;
} cmt_p2p_sw_async_dial_t;

typedef struct {
    cmt_p2p_netaddr_t addr;
    int     phase;          /* 0 = fixed interval (:410-426), 1 = backoff (:430-446) */
    int     i;
    int64_t next_at;
    bool    awaiting;       /* its DialPeerWithAddress is in flight */
    int64_t start;
} cmt_p2p_sw_reconnect_t;

typedef struct {
    char id[CMT_P2P_ID_CAP];
} cmt_p2p_sw_id_t;

/** switch.go:73-100 `Switch`. */
typedef struct cmt_p2p_switch {
    cmt_p2p_switch_config_t cfg;
    cmt_p2p_switch_host_t   host;
    cmt_p2p_transport_t    *transport;            /* :91 (not owned)     */
    const cmt_p2p_addr_book_t *addr_book;         /* :86 (optional)      */

    cmt_p2p_reactor_t reactors[CMT_P2P_SWITCH_MAX_REACTORS];   /* :77 */
    int n_reactors;
    cmt_p2p_ch_desc_t ch_descs[256];              /* :78 */
    int n_ch_descs;
    int8_t reactor_by_ch[256];                    /* :79, -1 = none */

    cmt_p2p_peer_set_t peers;                     /* :81 */

    cmt_p2p_netaddr_t *dialing;                   /* :82 by ID */
    int n_dialing, cap_dialing;
    cmt_p2p_sw_reconnect_t *reconnecting;         /* :83 by ID */
    int n_reconnecting, cap_reconnecting;
    cmt_p2p_sw_async_dial_t *async_dials;         /* :526-547 goroutines */
    int n_async, cap_async;

    cmt_p2p_netaddr_t *persistent;                /* :88 */
    int n_persistent;
    cmt_p2p_sw_id_t *unconditional;               /* :89 */
    int n_unconditional;
    cmt_p2p_sw_id_t *private_ids;                 /* AddPrivatePeerIDs */
    int n_private;

    bool started;
    bool stopped;

    cmt_p2p_peer_t *graveyard;                    /* stopped, to free */

    /** The outcome of every DialPeerWithAddress (F4, for the PEX
     *  reactor's dialPeer — cmt_p2p_switch_set_dial_observer). */
    void (*dial_observer)(void *ctx, const cmt_p2p_netaddr_t *addr, int err);
    void  *dial_observer_ctx;
} cmt_p2p_switch_t;

/* ══ setup (switch.go:111-229) ════════════════════════════════════════ */

/** switch.go:112-145 `NewSwitch`. `transport` must outlive the switch.
 *  @return CMT_OK; CMT_FAULT on NULL / a missing host row. */
int cmt_p2p_switch_init(cmt_p2p_switch_t *sw, const cmt_p2p_switch_config_t *cfg,
                        cmt_p2p_transport_t *transport,
                        const cmt_p2p_switch_host_t *host);

/** Stop (if running), free every peer and list. The transport is the
 *  caller's to free afterwards. */
void cmt_p2p_switch_free(cmt_p2p_switch_t *sw);

/** switch.go:167-181 `AddReactor`. @return CMT_OK; CMT_FAULT — a channel
 *  already has a reactor (the reference panics, :171-173), too many
 *  reactors, or a missing row. */
int cmt_p2p_switch_add_reactor(cmt_p2p_switch_t *sw,
                               const cmt_p2p_reactor_t *reactor);

/** switch.go:185-199 `RemoveReactor`. */
void cmt_p2p_switch_remove_reactor(cmt_p2p_switch_t *sw, const char *name);

/** switch.go:451-453 `SetAddrBook`. */
void cmt_p2p_switch_set_addr_book(cmt_p2p_switch_t *sw,
                                  const cmt_p2p_addr_book_t *book);

/** The descriptors of every registered channel (`sw.chDescs`). */
const cmt_p2p_ch_desc_t *cmt_p2p_switch_ch_descs(const cmt_p2p_switch_t *sw,
                                                 int *n);

/* ══ service (switch.go:235-264) ══════════════════════════════════════ */

/** switch.go:235-248 `OnStart`. @return CMT_OK; CMT_REJECT if already
 *  started / stopped or a reactor failed to start. */
int cmt_p2p_switch_start(cmt_p2p_switch_t *sw);

/** switch.go:251-264 `OnStop`. */
void cmt_p2p_switch_stop(cmt_p2p_switch_t *sw);

bool cmt_p2p_switch_is_running(const cmt_p2p_switch_t *sw);

/** One pass of every switch goroutine (file header). */
void cmt_p2p_switch_tick(cmt_p2p_switch_t *sw);

/* ══ peers (switch.go:269-461) ════════════════════════════════════════ */

/** switch.go:275-297 `Broadcast` (R-P2P-30). @return the number of peers
 *  that accepted the message. */
int cmt_p2p_switch_broadcast(cmt_p2p_switch_t *sw, uint8_t ch_id,
                             const uint8_t *msg, size_t len);

/** switch.go:301-316 `NumPeers` (unconditional peers not counted). */
void cmt_p2p_switch_num_peers(cmt_p2p_switch_t *sw, int *outbound,
                              int *inbound, int *dialing);

/** switch.go:318-321 `IsPeerUnconditional` (+ R-P2P-7). */
bool cmt_p2p_switch_is_peer_unconditional(const cmt_p2p_switch_t *sw,
                                          const char *id);

/** switch.go:324-326 `MaxNumOutboundPeers`. */
int cmt_p2p_switch_max_num_outbound_peers(const cmt_p2p_switch_t *sw);

/** switch.go:329-331 `Peers`. */
const cmt_p2p_peer_set_t *cmt_p2p_switch_peers(const cmt_p2p_switch_t *sw);

/** switch.go:336-359 `StopPeerForError`. Safe from inside a reactor's
 *  Receive and from the peer's own MConnection callbacks: the peer is
 *  freed at the end of the next tick, never here. */
void cmt_p2p_switch_stop_peer_for_error(cmt_p2p_switch_t *sw,
                                        cmt_p2p_peer_t *p, int reason);

/** switch.go:363-366 `StopPeerGracefully`. */
void cmt_p2p_switch_stop_peer_gracefully(cmt_p2p_switch_t *sw,
                                         cmt_p2p_peer_t *p);

/** switch.go:457-461 `MarkPeerAsGood` → AddrBook.MarkGood (F4). */
void cmt_p2p_switch_mark_peer_as_good(cmt_p2p_switch_t *sw,
                                      const cmt_p2p_peer_t *p);

/* ══ dialing (switch.go:475-634) ══════════════════════════════════════ */

/**
 * switch.go:480-495 `DialPeersAsync`: parse, add to the AddrBook, and
 * dial each (in a random order, each after randomSleep(0)).
 * @return CMT_P2P_ERR_NONE, or the first parse error that is not
 *         CMT_P2P_ERR_NETADDR_LOOKUP (:487-492) — then nothing is dialed.
 */
int cmt_p2p_switch_dial_peers_async(cmt_p2p_switch_t *sw,
                                    const char *const *peers, int n);

/**
 * switch.go:554-563 `DialPeerWithAddress`, started.
 * @return CMT_P2P_ERR_NONE (the dial is in flight; its outcome is handled
 *         in a later tick); CMT_P2P_ERR_CURRENTLY_DIALING_OR_EXISTING;
 *         another error when the transport refused at once (the
 *         reference's error path :752-771 has then already run).
 */
int cmt_p2p_switch_dial_peer_with_address(cmt_p2p_switch_t *sw,
                                          const cmt_p2p_netaddr_t *addr);

/** switch.go:573-577 `IsDialingOrExistingAddress`. */
bool cmt_p2p_switch_is_dialing_or_existing_address(const cmt_p2p_switch_t *sw,
                                                   const cmt_p2p_netaddr_t *addr);

/** switch.go:582-598 `AddPersistentPeers`. @return as DialPeersAsync. */
int cmt_p2p_switch_add_persistent_peers(cmt_p2p_switch_t *sw,
                                        const char *const *addrs, int n);

/** switch.go:600-610 `AddUnconditionalPeerIDs`.
 *  @return CMT_P2P_ERR_NONE or CMT_P2P_ERR_NETADDR_INVALID (the first
 *  bad ID; those before it were added, as in the reference). */
int cmt_p2p_switch_add_unconditional_peer_ids(cmt_p2p_switch_t *sw,
                                              const char *const *ids, int n);

/** switch.go:612-625 `AddPrivatePeerIDs` (validated, kept here and handed
 *  to the AddrBook if one is set). */
int cmt_p2p_switch_add_private_peer_ids(cmt_p2p_switch_t *sw,
                                        const char *const *ids, int n);

/** True if `id` was given to AddPrivatePeerIDs (for F4's PEX). */
bool cmt_p2p_switch_is_private_peer_id(const cmt_p2p_switch_t *sw,
                                       const char *id);

/** switch.go:627-634 `IsPeerPersistent`. */
bool cmt_p2p_switch_is_peer_persistent(const cmt_p2p_switch_t *sw,
                                       const cmt_p2p_netaddr_t *na);

/** True while `reconnectToPeer` runs for `id` (tests, F4). */
bool cmt_p2p_switch_is_reconnecting(const cmt_p2p_switch_t *sw,
                                    const char *id);

/**
 * Phase F4 — the error `DialPeerWithAddress` (switch.go:554-563) returns
 * in the reference, delivered when it is known. The reference's PEX
 * `dialPeer` (pex_reactor.go:554-573) blocks on that call and then books
 * the outcome (MarkAttempt / MarkBad, attemptsToDial); here the call
 * returns at once (file header) and the outcome — CMT_P2P_ERR_NONE once
 * the peer was added, or the transport / addPeer error — is only known in
 * `addOutboundPeerWithConfig`'s tail (:752-781). The observer is called
 * there, for EVERY dial that got past `IsDialingOrExistingAddress`
 * (including the immediate transport refusals, synchronously from inside
 * `cmt_p2p_switch_dial_peer_with_address`), with the address dialed and
 * that error. Not called for ErrCurrentlyDialingOrExistingAddress, which
 * the call itself returns. One observer; NULL clears it.
 */
void cmt_p2p_switch_set_dial_observer(cmt_p2p_switch_t *sw,
    void (*fn)(void *ctx, const cmt_p2p_netaddr_t *addr, int err), void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_SWITCH_H */
