/**
 * @file shared/dnac/cmt_memr.h
 * @brief cometbft @709fd12b `mempool/reactor.go` ported to C — the Flood
 *        gossip of the mempool, receiver `memR`.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R3-M of the cometbft → C consensus port. No transport calls this
 * yet: R3-C2 binds `cmt_memr_receive` to the tier3 verb for channel 0x30,
 * `cmt_memr_tick` to the host's tick, and the host table to the witness
 * peer table. Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT IT DOES ───────────────────────────────────────────────────────
 * Every transaction that enters the local mempool is offered, one per
 * message, to every connected peer that did not send it, in mempool
 * order; every `Txs` message a peer sends is fed transaction by
 * transaction into `cmt_mem_check_tx`. Batching is DISABLED in the
 * reference (:235-236, tendermint#5796): one transaction per `Txs` on
 * send; receive accepts any number, as the reference does (:155-169).
 *
 * ── GOROUTINES → A TICK (umbrella rev 4, substitution item 7) ──────────
 * The reference runs one `broadcastTxRoutine` (:185-259) per peer, a
 * goroutine that walks the mempool's CList from `TxsFront()` and blocks
 * at five places: the empty list (:200), the three `time.Sleep(100 ms)`
 * sites (:219, :231, :244), the `NextWaitChan` at the tail (:250), and
 * — inside `peer.Send` (p2p/peer.go:260-262) — the MConnection's send
 * queue. Here every peer has a CURSOR (`next`, :187) and `cmt_memr_tick`
 * runs each peer's routine, in ascending slot order, from where it left
 * off until it would block; the blocking points become:
 *   · empty list                 → the pass ends; next tick re-reads Front
 *   · NextWaitChan not ready     → the pass ends PARKED IN THE SELECT on
 *                                  that element (`waiting_next`); the
 *                                  next tick re-reads `cmt_clist_elem_
 *                                  next_wait_ready` and, when ready,
 *                                  resumes at :252 (advance), never at
 *                                  the loop top — the goroutine does not
 *                                  re-send the element it is parked on
 *   · the three sleeps           → DEVIATION R3-M-1: a per-peer
 *                                  `not_before` deadline of now + 100 ms
 *                                  (PeerCatchupSleepIntervalMS,
 *                                  mempool.go:16); the routine is skipped
 *                                  until the host's clock passes it. The
 *                                  reactor takes `cmt_now_fn` for these
 *                                  three sites and for NOTHING ELSE.
 *   · `Send` blocking            → the host's `send` row is NON-BLOCKING
 *                                  and returns false when it cannot queue;
 *                                  the reference's `false` after the
 *                                  MConnection timeout (peer.go:258-259)
 *                                  and this false take the same branch
 *                                  (:243-246): sleep, and RETRY THE SAME
 *                                  TRANSACTION — the cursor does not move.
 * `peer.Quit()` / `memR.Quit()` (:204-207, :253-256) end a routine; here
 * `cmt_memr_remove_peer` and `cmt_memr_stop` end it. A routine that has
 * ended is not restarted by a later start, exactly as a returned
 * goroutine is not.
 *
 * ── THE EXPERIMENTAL GOSSIP LIMITS (:28-32, :43-44, :92-129) ───────────
 * `semaphore.Weighted` of capacity `ExperimentalMaxGossipConnectionsTo
 * {Persistent,NonPersistent}Peers` (0 = unlimited, config.go:778-779);
 * an unconditional peer skips it (:94-95). A routine that cannot acquire
 * WAITS (:104-121; the 30 s context timeout there only re-checks
 * `peer.IsRunning()` and re-acquires, so it needs no clock here: removal
 * ends the wait directly) and releases on exit (:119). Here the two
 * semaphores are COUNTERS; waiting peers try to acquire on every tick in
 * ASCENDING SLOT ORDER. The order in which `golang.org/x/sync/semaphore`
 * wakes waiters was NOT verified (the package is not pinned and was not
 * opened); slot order is this port's rule, stated here because
 * reactor_test.go:262-305 observes it.
 *
 * ── RECEIVE: what the p2p layer did before `Receive` ───────────────────
 * The reference's `Receive` (:140-177) is handed an already DECODED and
 * UNWRAPPED message: p2p/peer.go:400-430 unmarshals the channel's
 * `Message` (:407-412) and calls `Unwrap` (:417-422); an error at either
 * step panics into the connection's recover, which stops the peer for
 * error. Here `cmt_memr_receive` takes the raw bytes and does both steps,
 * so a payload that does not decode, or a `Message` with no `sum`
 * (message.go:42-43), calls the host's `stop_peer_for_error` and returns
 * CMT_REJECT — which is also what `Receive`'s own `default` branch
 * (:170-173) does for a message that is not a `Txs`. An EMPTY `Txs`
 * (:145-148) is logged and ignored: no disconnect. The descriptor's
 * `RecvMessageCapacity` (:83) is enforced by the reference's transport
 * (p2p/conn, deliberately unpinned — pin record rev 15); it is enforced
 * HERE at the reactor boundary, so the decoder never sees more bytes than
 * the descriptor allows, and a longer payload also stops the peer.
 *
 * ── DECODE STORAGE (D-14 rev 4 per-class heap rule) ────────────────────
 * `Txs.Unmarshal` allocates a fresh slice per element; here the reactor
 * owns, from init: an ARENA of `RecvMessageCapacity` bytes (every
 * element of a message that fits the capacity fits the arena), a SLOT
 * array of `RecvMessageCapacity / 2 + 1` entries (an element is at least
 * `0a 00`, two bytes, so no message within the capacity can carry more),
 * and a SEND buffer of `RecvMessageCapacity` bytes for the one-tx
 * `Message` of :239-242. At the default `MaxTxBytes` (1 MiB) that is
 * 1 048 584 + 16 × 524 293 + 1 048 584 ≈ 10.4 MB per reactor, allocated
 * once.
 *
 * ── Panics ─────────────────────────────────────────────────────────────
 * reactor.go has none of its own. The host-contract errors this port
 * adds are CMT_FAULT (node-local): `add_peer` on a slot already present
 * (a Go peer is a distinct object; a slot re-added without removal is the
 * host's defect), a NULL host row reached at run time, and a clock that
 * fails.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Slot order is the only order; the clock is read at the three sleep
 * sites and compared against deadlines it produced; no randomness; no
 * hash map. Nothing here decides a vote, a block or a stored row —
 * gossip order affects only which peer learns a transaction first.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `SetLogger` (:56-59)                    — QGP_LOG (port map YOK)
 *   · `TxsMessage` / `String` (:261-269)      — a log type (YOK)
 *   · `p2p.BaseReactor` embedding (:23, :42)  — the service scaffold; its
 *     `IsRunning` is the `running` flag, its Quit the stop
 *   · `metrics.ActiveOutboundConnections` (:125-126) — metrics (YOK)
 *
 * Reference @709fd12b (SHA-256 verified before use; pin record rev 12 →
 * rev 15, atlas-dec-483ec17cbb352ef0ec2267ccd953339c):
 *   mempool/reactor.go   269 lines  c8908583…
 *   mempool/mempool.go   149 lines  1fab7e19… (:13-22)
 *   p2p/peer.go          443 lines  35f34157… (:258-295 Send, :400-430 onReceive)
 * Governing records: D-4 rev 3 (atlas-dec-d5ddcba654eb48d861c03a0ecd170718),
 * umbrella rev 4 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * PQ POLICY (atlas-dec-652be084b95d02d253834906271e9fb0) — the p2p
 * security around these messages is Nodus's own and out of scope,
 * D-20 rev 3 (atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_MEMR_H
#define SHARED_DNAC_CMT_MEMR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_mem.h"          /* cmt_mem_t, cmt_mem_ids_t, cmt_mempool_config_t */
#include "cmt_pb_mempool.h"   /* the wire                                        */
#include "cmt_time.h"         /* cmt_now_fn, cmt_time_unix_nano                  */

#ifdef __cplusplus
extern "C" {
#endif

/** mempool.go:16 — `PeerCatchupSleepIntervalMS`, as nanoseconds. */
#define CMT_MEMR_PEER_CATCHUP_SLEEP_NS \
    ((int64_t)CMT_MEM_PEER_CATCHUP_SLEEP_INTERVAL_MS * (int64_t)1000000)

/** reactor.go:79-86 — the channel descriptor's fields this port carries
 *  (`MessageType` is the codec, cmt_pb_mempool). */
typedef struct {
    uint8_t id;                       /* :81 MempoolChannel 0x30 */
    int     priority;                 /* :82 5 */
    size_t  recv_message_capacity;    /* :83 Message{Txs{[MaxTxBytes]}}.Size() */
} cmt_memr_channel_descriptor_t;

/** The state of one peer's `broadcastTxRoutine`. */
typedef enum {
    CMT_MEMR_ROUTINE_NONE    = 0,   /* no routine: not started, or ended */
    CMT_MEMR_ROUTINE_WAITING = 1,   /* :104-121 blocked on the semaphore   */
    CMT_MEMR_ROUTINE_RUNNING = 2    /* :185-259 walking the list           */
} cmt_memr_routine_state_t;

/** Which semaphore (:31-32) a peer's routine holds or waits on. */
typedef enum {
    CMT_MEMR_SEM_NONE           = 0,
    CMT_MEMR_SEM_PERSISTENT     = 1,   /* :99  */
    CMT_MEMR_SEM_NON_PERSISTENT = 2    /* :101 */
} cmt_memr_semaphore_t;

/** One peer slot. Private; the accessors below are for the host and the
 *  tests. */
typedef struct {
    bool                     present;          /* peer.IsRunning() (:191)  */
    bool                     is_persistent;    /* peer.IsPersistent() (:98) */
    bool                     is_unconditional; /* IsPeerUnconditional (:95) */
    cmt_memr_routine_state_t state;
    cmt_memr_semaphore_t     semaphore;        /* held (RUNNING) or wanted (WAITING) */
    uint16_t                 peer_id;          /* :186, read when the routine starts */
    cmt_clist_elem_t        *next;             /* :187 — holds a cursor reference */
    /** The routine is parked in the `select` of :249-257, waiting for
     *  `next`'s NextWaitChan. It resumes at :252 — advancing — and NOT
     *  at the loop top, so the element it sits on is not sent twice. */
    bool                     waiting_next;
    bool                     sleeping;         /* R3-M-1 */
    int64_t                  not_before_ns;    /* R3-M-1 */
} cmt_memr_peer_t;

/**
 * Everything `mempool/reactor.go` reaches outside its package, as one
 * table. EVERY ROW IS REQUIRED; a NULL row reached at run time is
 * CMT_FAULT. A callback MUST NOT re-enter the reactor or the mempool.
 */
typedef struct {
    void *ctx;

    /** p2p/peer.go:260-262 `Send` → :270-295: the message is already
     *  wrapped and marshalled here (:277-280), so the host sees the
     *  bytes of a `Message` for channel `channel_id`. NON-BLOCKING:
     *  return true when queued, false when it cannot be (the queue is
     *  full, the peer is gone) — the header's R3-M-1. The bytes are
     *  valid only for the duration of the call. */
    bool (*send)(void *ctx, int peer_slot, uint8_t channel_id,
                 const uint8_t *msg, size_t msg_len);

    /** `Switch.StopPeerForError` (reactor.go:172; p2p/peer.go:410-421
     *  through the connection's recover). The host disconnects the
     *  peer; it will call `cmt_memr_remove_peer` for it as the switch
     *  calls `RemovePeer`. */
    void (*stop_peer_for_error)(void *ctx, int peer_slot);

    /** `peer.Get(types.PeerStateKey).(PeerState).GetHeight()`
     *  (reactor.go:180-182, :212-230). `*out_known` false is the
     *  "peer does not have a state yet" branch (:213-221) — the
     *  consensus reactor has not set the state — and the height is then
     *  ignored. R3-C2 wires this to the consensus peer state. */
    int64_t (*peer_height)(void *ctx, int peer_slot, bool *out_known);

    /** THE ONLY CLOCK IN THIS MODULE: the three `time.Sleep` sites
     *  (:219, :231, :244) under R3-M-1. Read at most once per tick. */
    cmt_now_fn now;
} cmt_memr_host_t;

/**
 * reactor.go:22-33 — `type Reactor struct`, plus the per-slot routine
 * state and the decode storage of the header. Private; use the
 * functions.
 */
typedef struct {
    const cmt_mempool_config_t *config;     /* :24, borrowed */
    cmt_mem_t                  *mempool;    /* :25, borrowed */
    cmt_mem_ids_t               ids;        /* :26 */
    int active_persistent_peers;            /* :31 — held count */
    int active_non_persistent_peers;        /* :32 — held count */
    const cmt_memr_host_t      *host;       /* borrowed */
    bool                        running;    /* BaseReactor.IsRunning() */
    cmt_memr_peer_t             peers[CMT_MEM_MAX_PEERS];

    /* decode / send storage (header) */
    size_t          recv_message_capacity;
    uint8_t        *arena_buf;
    cmt_pb_arena_t  arena;
    cmt_pb_bytes_t *rx_slots;
    size_t          rx_slots_cap;
    uint8_t        *tx_buf;
    size_t          tx_buf_cap;
} cmt_memr_t;

/**
 * reactor.go:36-47 — `NewReactor(config, mempool)`: the ids (:40), the
 * two semaphore capacities from the config (:43-44). `config`,
 * `mempool` and `host` are BORROWED and must outlive the reactor. The
 * decode storage of the header is allocated here, sized from the
 * descriptor's `RecvMessageCapacity`.
 * @return CMT_OK; CMT_FAULT on NULL, a negative `max_tx_bytes`, or
 *         allocation failure.
 */
int cmt_memr_init(cmt_memr_t *memR, const cmt_mempool_config_t *config,
                  cmt_mem_t *mempool, const cmt_memr_host_t *host);

/** C-only: ends every routine (releasing its cursor) and frees the
 *  storage. NULL is a no-op. */
void cmt_memr_free(cmt_memr_t *memR);

/** reactor.go:50-53 — `InitPeer(peer)`: `ids.ReserveForPeer` (:51).
 *  @return the reserve's result. */
int cmt_memr_init_peer(cmt_memr_t *memR, int peer_slot);

/** reactor.go:62-67 — `OnStart()`: the reactor is running; "Tx
 *  broadcasting is disabled" is logged when `!config.Broadcast` (:63-65).
 *  @return CMT_OK (the reference's nil), CMT_FAULT on NULL. */
int cmt_memr_start(cmt_memr_t *memR);

/** C-only — the reference's `Stop()` is `BaseService`'s: `memR.Quit()`
 *  closes and every routine returns (:191-193, :206-207, :255-256).
 *  Every cursor is released, every held semaphore slot given back.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_memr_stop(cmt_memr_t *memR);

/** reactor.go:71-89 — `GetChannels()`: id 0x30, priority 5, and the
 *  exact size of a `Message{Txs{[one tx of MaxTxBytes]}}` (:72-77, :83)
 *  computed by the ported `Size()` functions.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_memr_get_channels(const cmt_memr_t *memR,
                          cmt_memr_channel_descriptor_t *out);

/**
 * reactor.go:91-130 — `AddPeer(peer)`. When `config.Broadcast`: an
 * unconditional peer starts its routine at once (:94-95); otherwise the
 * semaphore for its persistence class is chosen (:96-102), acquired if
 * a slot is free or WAITED on (:104-122), and the routine starts
 * (:127). `is_persistent` and `is_unconditional` are the switch's
 * knowledge of the peer (p2p), supplied by the host.
 * @return CMT_OK; CMT_REJECT for a slot out of range; CMT_FAULT on NULL
 *         or a slot that is already present (host contract, header).
 */
int cmt_memr_add_peer(cmt_memr_t *memR, int peer_slot, bool is_persistent,
                      bool is_unconditional);

/** reactor.go:133-136 — `RemovePeer(peer, reason)`: `ids.Reclaim`
 *  (:134); the routine "checks if peer is gone and returns" (:135) —
 *  here it ends now, releasing its cursor and its semaphore slot (the
 *  deferred Release of :119).
 *  @return CMT_OK; CMT_REJECT for a slot out of range; CMT_FAULT on NULL.
 *  A slot that is not present is a no-op (the reference's RemovePeer
 *  for an unknown peer reclaims nothing). */
int cmt_memr_remove_peer(cmt_memr_t *memR, int peer_slot);

/**
 * reactor.go:140-177 — `Receive(envelope)`, preceded by the p2p decode
 * of the header. `peer_p2p_id`/`_len` is `e.Src.ID()` (:150-152), used
 * only for the log line; may be NULL/0. The slot need not be present:
 * an unreserved slot's sender id is 0 (:149, ids.go:62).
 *
 * @return CMT_OK when the message was a `Txs` (empty or not) and every
 *         transaction was offered to the mempool — a refused transaction
 *         is logged (:158-168), never returned; CMT_REJECT when the bytes
 *         did not decode, exceeded the capacity, or were not a `Txs`
 *         (the peer has been stopped for error); CMT_FAULT on NULL or a
 *         FAULT from `cmt_mem_check_tx`.
 */
int cmt_memr_receive(cmt_memr_t *memR, int peer_slot,
                     const uint8_t *bytes, size_t len,
                     const uint8_t *peer_p2p_id, size_t peer_p2p_id_len);

/**
 * reactor.go:185-259 — every peer's `broadcastTxRoutine`, one pass each
 * in ascending slot order, as the header describes. Waiting routines
 * (:104-121) try the semaphore first.
 *
 * @param out_next_deadline_ns the earliest `not_before` among sleeping
 *        peers, when `*out_has_deadline` — the host should tick again
 *        by then; otherwise nothing is sleeping and the next tick is
 *        due when the mempool changes or a peer changes. Either may be
 *        NULL.
 * @return CMT_OK; CMT_FAULT on NULL, a NULL host row, or a failed clock.
 */
int cmt_memr_tick(cmt_memr_t *memR, int64_t *out_next_deadline_ns,
                  bool *out_has_deadline);

/** Test and host accessors: the routine state of a slot, and its cursor
 *  (NULL when none). Out-of-range slots read as NONE / NULL. */
cmt_memr_routine_state_t cmt_memr_peer_routine_state(const cmt_memr_t *memR,
                                                     int peer_slot);
const cmt_clist_elem_t *cmt_memr_peer_cursor(const cmt_memr_t *memR,
                                             int peer_slot);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_MEMR_H */
