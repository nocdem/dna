/**
 * @file shared/dnac/cmt_bsync_pool.h
 * @brief cometbft `blocksync/pool.go` (pin v0.38.26, see "REFERENCE PIN"
 *        below) ported to C — the block pool: which peer is asked for
 *        which height, and the blocks that came back, until the reactor
 *        has verified and applied them.
 *
 * Governing records: docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md,
 * docs/plans/decisions/2026-09-29-blocksync-before-testnet.md,
 * docs/plans/2026-09-29-blocksync-port-design.md (§1 "Goroutine'ler YOK",
 * §2 D2/D3, §3 G2/G4), docs/plans/decisions/2026-09-25-consensus-clock-
 * scope-correction.md (the clock is read where the reference reads it,
 * only to schedule this node's own work).
 *
 * ── PEERS ARE KEYED BY THEIR P2P ID ────────────────────────────────────
 * `peers map[p2p.ID]*bpPeer` (:81), `bannedPeers map[p2p.ID]time.Time`
 * (:82) and every requester's `peerID` / `secondPeerID` / `gotBlockFrom`
 * (:653-655) are the peer's p2p ID — here the NUL-terminated hex string
 * `cmt_p2p_peer_id` returns (cmt_p2p_peer.c:462), CMT_P2P_ID_CAP bytes.
 * NEVER a transport or lane slot index: a slot is reused by the next peer
 * that connects, an ID names one identity (a ban must outlive the
 * connection, :464).
 *
 * ── GOROUTINES → ONE TICK (the cmt_memr pattern) ───────────────────────
 * The reference runs `makeRequestersRoutine` (:120-156), one
 * `requestRoutine` per requester (:838-902) and one `time.AfterFunc`
 * timer per peer (:597-603). Here nothing blocks and nothing runs by
 * itself: `cmt_bsync_pool_tick(now)` runs each of them until it would
 * wait, and every wait becomes a DEADLINE compared against the host's
 * `now`:
 *   · `time.Sleep(requestIntervalMS)` (:145, :148, :153, :792) → a
 *     `not_before` of now + 2 ms (the routine is skipped until then);
 *   · the `peerConnWait` sleep (:128-132) → the routine does nothing
 *     before `start + 3 s`;
 *   · `retryTimer` (:850, :892) → one armed deadline per requester,
 *     ONE-SHOT as a Go Timer is: after a block arrived it fires once, does
 *     nothing (:863) and is never re-armed;
 *   · `peer.timeout` (`time.AfterFunc(peerTimeout, onTimeout)`,
 *     :597-603) → one armed deadline per peer; firing is `onTimeout`
 *     (:623-631);
 *   · the three 1-deep channels of a requester (`gotBlockCh`, `redoCh`,
 *     `newHeightCh`, :664-666) → "at most one pending" flags; a send to a
 *     full channel is dropped exactly as the reference's `select {
 *     default: }` drops it (:698-701, :772-775, :830-833);
 *   · `requestsCh` / `errorsCh` (pool → reactor, :89-90, :523-535) → the
 *     host callbacks `send_request` / `send_error`, called at once (both
 *     are no-ops when the pool is not running, :524-526, :531-533).
 * `cmt_bsync_pool_tick` reports the earliest deadline it left pending, so
 * the host can wait exactly that long.
 *
 * ── THE CLOCK ──────────────────────────────────────────────────────────
 * The pool never reads a clock itself: every function that the reference
 * lets read `time.Now()` takes `now_ns`, the host's clock in unix
 * nanoseconds (the SAME `cmt_now_fn` the consensus state machine uses,
 * read once by the reactor per call). The reads, reference ↔ here:
 *   :114 startTime               → cmt_bsync_pool_start
 *   :128/:130 peerConnWait       → makeRequesters step in the tick
 *   :145/:148/:153/:792 sleeps   → the tick's not_before deadlines
 *   :219 IsCaughtUp's 5 s        → cmt_bsync_pool_is_caught_up
 *   :464 isPeerBanned / :470 banPeer → every function that bans or asks
 *   :592 flow.New (the Monitor)  → incrPending / decrPending
 *   :599/:601 peerTimeout        → incrPending / decrPending
 *   :850/:892 retryTimer         → the requester step
 * Every one schedules or rate-limits THIS node's requests. Nothing here
 * decides a block's validity, a vote or a stored row: a block is
 * accepted only by the reactor, and only after VerifyCommit (the full
 * check, cometbft@v0.38.26 blocksync/reactor.go:580-585).
 *
 * ── ORDER (design §2 D3) ───────────────────────────────────────────────
 * The reference's maps are iterated in Go's random order (`removePeer`
 * over requesters :415, `removeTimedoutPeers` over peers :162, over
 * bannedPeers :184, `updateMaxPeerHeight` :446). Here every table is an
 * array in insertion order (requesters by height), which is one of the
 * orders the reference could have produced. `sortPeers` (:503-507) uses
 * `sort.Slice`, which is NOT stable; here a STABLE sort by `curRate`
 * descending (ties keep their current order). None of this reaches the
 * chain: which peer serves a block does not change the block, which is
 * fixed by its commit.
 *
 * ── DEVIATIONS (labelled; none reaches a block, a vote or a root) ──────
 *   BS-1  goroutine `select` order: when several of a requester's
 *         channels are ready at once, Go picks at random (:853-899). The
 *         tick serves them in ONE fixed order — gotBlock, redo, newHeight,
 *         retryTimer — which is one order the reference can take and the
 *         one that keeps `gotBlock` equal to "the requester holds a
 *         block" (a redo that removed the block is seen after the
 *         gotBlock it cancels).
 *   BS-2  `pickIncrAvailablePeer` (:475-498) removes a timed-out peer
 *         INSIDE `for _, peer := range pool.sortedPeers`; Go's in-place
 *         slice deletion then makes the loop skip the peer after it and
 *         visit the last one twice. The port visits every remaining peer
 *         once. Only the choice of peer can differ.
 *   BS-3  `Stop` (BaseService) leaves the reference's requester map in
 *         place (each requester only stops, :855-859). Here
 *         `cmt_bsync_pool_stop` FREES the requesters and the blocks they
 *         hold: after the pool routine has ended nothing reads them, and
 *         `AddBlock` then finds no requester, which in the reference is an
 *         error return and a `sendError` that is a no-op on a stopped pool
 *         (:531-533) — log-only in both.
 *   BS-4  `decrPending` (:613-621) dereferences `recvMonitor` / `timeout`
 *         unguarded; they exist whenever `incrPending` ran on the SAME
 *         peer object first. A block from a re-added peer object whose ID
 *         a requester still names reaches `decrPending` with neither —
 *         a Go nil-pointer panic inside Receive. Here the Monitor update
 *         is skipped when it was never created, and stopping an unarmed
 *         timeout is a no-op.
 *   BS-10 OWN FIX, not the reference's (R1-2, red-team round 1; decision
 *         docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md and
 *         2026-09-29-blocksync-before-testnet.md "R1-2"). The reference —
 *         UNCHANGED in v0.38.26 (pool.go:360-364 AddBlock, :712-733
 *         setBlock, :643-651 decrPending) — decrements `numPending` and the
 *         sender's `numPending` for EVERY copy a matching peer sends, also
 *         when the requester already holds a block (setBlock returns true
 *         at :718-721). A peer that re-sends one block therefore drives
 *         both counters below zero and re-arms its own 15 s timeout with
 *         every copy: it is never timed out, and block sync never ends.
 *         Here:
 *           · each requester slot (`peer_id`, `second_peer_id`) carries a
 *             `delivered` flag, set when that slot's peer delivers, cleared
 *             when the slot is reset (`rq_reset`) or assigned anew;
 *           · the slot's PEER is decremented at most once per assignment;
 *           · the POOL counter is decremented only when the block is
 *             actually stored (the copy of the other slot, which the
 *             reference also counts, is not);
 *           · a copy from a slot that has already delivered, while the
 *             requester holds a block, is dropped SILENTLY — no
 *             send_error: an honest slow peer may legitimately answer a
 *             request twice (after a retry). A slot that already delivered
 *             but whose block was since discarded (the other peer's copy
 *             was kept and then refused, `rq_reset`) IS stored when it
 *             sends again — it is the only copy on offer — but its peer
 *             is not decremented a second time;
 *           · `decrPending` on a peer already at 0 changes nothing and does
 *             NOT re-arm its timeout (the counter never goes below 0).
 *         Node-local: which peer serves a block and when it is timed out;
 *         never which block is accepted (that is the commit's).
 *
 * ── REFERENCE PIN ──────────────────────────────────────────────────────
 * cometbft v0.38.26 since 2026-09-30 (decision
 * 2026-09-30-cometbft-pin-v0.38.26.md). Lines marked `v0.38.26` are read
 * from that tree; every other `:NNN` still names the @709fd12b pool.go
 * (renumbering pending). The v0.38.26 changes ported here:
 * HasPendingRequestFrom (:202-213), PopRequest's maxPeerHeight refresh
 * (:275-276), SetPeerRange's base > height ban (:388-396) and its
 * updateMaxPeerHeight tail (:425), updateMaxPeerHeight's skip of a peer
 * pruned beyond the pool height (:468-482).
 *
 * ── REPRODUCED QUIRKS (not fixed; node-local) ──────────────────────────
 *   · `reset("")` (:865-866 when `secondPeerID` is empty) matches an empty
 *     `gotBlockFrom` and bumps `numPending` (:751-757) — `numPending` is
 *     read only by `GetStatus` for a log line (reactor.go:383).
 *   · `reset` clears a requester's peer WITHOUT decrementing that peer's
 *     `numPending` (:746-766); only `AddBlock` decrements it (:345-348).
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `debug()` (:537-556) — `//nolint:unused`, a debugging aid;
 *   · `SetLogger`, loggers (:392, :572, :587-589) — QGP_LOG;
 *   · `RedoRequest` (:297-300) — deprecated alias; ported as the one-line
 *     delegation `cmt_bsync_pool_redo_request` anyway because the dispatch
 *     names it;
 *   · `service.BaseService` of pool and requester — the `running` flags.
 *
 * Reference @709fd12b: blocksync/pool.go 909 lines
 * (/tmp/r2-a-ref/cometbft-709fd12b4b18cf1442d43c5d34009392c7d674ed).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_BSYNC_POOL_H
#define SHARED_DNAC_CMT_BSYNC_POOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_block.h"          /* cmt_block_t, cmt_extended_commit_t */
#include "cmt_flowrate.h"       /* cmt_flowrate_t                      */
#include "cmt_p2p_netaddr.h"    /* CMT_P2P_ID_CAP                      */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ constants (pool.go:32-57) ════════════════════════════════════════ */

#define CMT_BSYNC_NS_PER_MS  ((int64_t)1000000)
#define CMT_BSYNC_NS_PER_S   ((int64_t)1000000000)

/** :33 `requestIntervalMS` = 2 ms. */
#define CMT_BSYNC_REQUEST_INTERVAL_NS      (2 * CMT_BSYNC_NS_PER_MS)
/** :34 `maxPendingRequestsPerPeer`. */
#define CMT_BSYNC_MAX_PENDING_REQUESTS_PER_PEER 20
/** :35 `requestRetrySeconds` = 30 s. */
#define CMT_BSYNC_REQUEST_RETRY_NS         (30 * CMT_BSYNC_NS_PER_S)
/** :44 `minRecvRate` = 128 KB/s. */
#define CMT_BSYNC_MIN_RECV_RATE            (128 * 1024)
/** :49 `peerConnWait` = 3 s. */
#define CMT_BSYNC_PEER_CONN_WAIT_NS        (3 * CMT_BSYNC_NS_PER_S)
/** :54 `minBlocksForSingleRequest`. */
#define CMT_BSYNC_MIN_BLOCKS_FOR_SINGLE_REQUEST 50
/** :57 `peerTimeout` = 15 s (a `var` in the reference so tests can
 *  override it — here the pool's `peer_timeout_ns` field). */
#define CMT_BSYNC_PEER_TIMEOUT_NS          (15 * CMT_BSYNC_NS_PER_S)
/** :464 — a ban lasts 60 s. */
#define CMT_BSYNC_BAN_NS                   (60 * CMT_BSYNC_NS_PER_S)
/** :219 — "received a block or waited 5 s". */
#define CMT_BSYNC_CAUGHT_UP_WAIT_NS        (5 * CMT_BSYNC_NS_PER_S)
/** :592 `flow.New(time.Second, time.Second*40)`. */
#define CMT_BSYNC_MONITOR_SAMPLE_NS        (1 * CMT_BSYNC_NS_PER_S)
#define CMT_BSYNC_MONITOR_WINDOW_NS        (40 * CMT_BSYNC_NS_PER_S)

/* ══ a received block (reactor.go:265-284 decodes it) ═════════════════ */

/**
 * What `AddBlock` stores (:311): `block *types.Block`, `extCommit
 * *types.ExtendedCommit` and `blockSize` (the reactor's
 * `msg.Block.Size()`, :284). The decoded structures point into the
 * storage members below, which this struct owns; the reactor fills it
 * (cmt_bsync_reactor.c) and `cmt_bsync_block_free` releases it. The pool
 * reads only `block.header.height`, `has_ext_commit`,
 * `ext_commit.height` and `size`.
 */
typedef struct {
    cmt_block_t           block;
    size_t                size;
    bool                  has_ext_commit;
    cmt_extended_commit_t ext_commit;

    /* C-only storage */
    cmt_pb_bytes_t             *txs;
    uint8_t                    *arena_buf;
    cmt_pb_evidence_t          *evidence;
    cmt_commit_sig_t           *sigs;
    cmt_commit_t                last_commit;
    cmt_extended_commit_sig_t  *ext_sigs;
    uint8_t                    *ext_arena_buf;
} cmt_bsync_block_t;

/** Frees `b` and everything it owns. NULL is a no-op. */
void cmt_bsync_block_free(cmt_bsync_block_t *b);

/* ══ the pool's two outputs (pool.go:89-90) ═══════════════════════════ */

/** Why the pool asks the reactor to stop a peer (the `err` of
 *  `sendError`, :530-535). */
typedef enum {
    CMT_BSYNC_PEER_ERR_SLOW           = 1, /* :167 "not sending us data fast enough" */
    CMT_BSYNC_PEER_ERR_TIMEOUT        = 2, /* :627 "peer did not send us anything"   */
    CMT_BSYNC_PEER_ERR_EXT_HEIGHT     = 3, /* :316 "block height != extCommit height" */
    CMT_BSYNC_PEER_ERR_UNEXPECTED     = 4, /* :329 "block we didn't expect"          */
    CMT_BSYNC_PEER_ERR_WRONG_SENDER   = 5  /* :339 "requested block from X, not Y"   */
} cmt_bsync_peer_err_t;

/**
 * `requestsCh` and `errorsCh` as calls. The reactor supplies both
 * (reactor.go:353-369). Every row is required. A row MUST NOT re-enter
 * the pool.
 */
typedef struct {
    void *ctx;
    /** pool.go:523-528 `sendRequest` → reactor.go:353-364: TrySend a
     *  BlockRequest{height} to `peer_id` (dropped if not connected). */
    void (*send_request)(void *ctx, int64_t height, const char *peer_id);
    /** pool.go:530-535 `sendError` → reactor.go:365-369:
     *  StopPeerForError on `peer_id` (if still connected). */
    void (*send_error)(void *ctx, const char *peer_id, cmt_bsync_peer_err_t err);
} cmt_bsync_pool_host_t;

/* ══ bpPeer (pool.go:560-631) ═════════════════════════════════════════ */

typedef struct {
    char            id[CMT_P2P_ID_CAP];   /* :567 */
    bool            did_timeout;          /* :561 */
    int64_t         cur_rate;             /* :562 */
    int32_t         num_pending;          /* :563 */
    int64_t         height;               /* :564 */
    int64_t         base;                 /* :565 */
    cmt_flowrate_t  recv_monitor;         /* :568 */
    bool            monitor_made;         /* recvMonitor != nil */
    bool            timeout_armed;        /* :570 the AfterFunc timer */
    int64_t         timeout_at_ns;
} cmt_bsync_peer_t;

/* ══ bpRequester (pool.go:643-658) ════════════════════════════════════ */

/** Where a requester's `requestRoutine` (:838-902) is parked. */
typedef enum {
    CMT_BSYNC_RQ_PICK = 0,   /* :843 pickPeerAndSendRequest's PICK_PEER_LOOP */
    CMT_BSYNC_RQ_WAIT = 1    /* :853-900 the inner select                    */
} cmt_bsync_rq_state_t;

typedef struct {
    int64_t              height;                       /* :647 */
    char                 peer_id[CMT_P2P_ID_CAP];      /* :653 */
    char                 second_peer_id[CMT_P2P_ID_CAP]; /* :654 */
    char                 got_block_from[CMT_P2P_ID_CAP]; /* :655 */
    cmt_bsync_block_t   *block;                        /* :656-657 block + extCommit */
    /* BS-10 (own fix, header): the slot's peer has delivered this height
     * since the slot was last assigned. */
    bool                 peer_delivered;
    bool                 second_delivered;

    /* the three 1-deep channels (:648-650) */
    bool                 got_block_ch;
    bool                 redo_ch;
    char                 redo_peer[CMT_P2P_ID_CAP];
    bool                 new_height_ch;
    int64_t              new_height_val;

    /* requestRoutine's locals and waits */
    cmt_bsync_rq_state_t state;
    bool                 got_block;                    /* :839 */
    bool                 retry_armed;                  /* :850 retryTimer */
    int64_t              retry_at_ns;
    int64_t              pick_not_before_ns;           /* :792 sleep */
} cmt_bsync_requester_t;

/* ══ BlockPool (pool.go:71-91) ════════════════════════════════════════ */

/** What `makeRequestersRoutine` (:120-156) does after its current sleep. */
typedef enum {
    CMT_BSYNC_MR_EVALUATE        = 0,   /* go round the loop (:121)            */
    CMT_BSYNC_MR_REMOVE_TIMEDOUT = 1    /* :145-146 sleep, then removeTimedout */
} cmt_bsync_mr_next_t;

typedef struct {
    bool                     running;         /* BaseService              */
    int64_t                  start_time_ns;   /* :73                      */
    int64_t                  start_height;    /* :74                      */

    /* :78-79 requesters, contiguous from `height`: requesters[i] is the
     * requester for height + i (a Go map whose keys are always exactly
     * that range — :138 `nextHeight = pool.height + len(requesters)`). */
    cmt_bsync_requester_t  **requesters;
    size_t                   n_requesters, cap_requesters;
    int64_t                  height;          /* :79                      */

    /* :81-84 */
    cmt_bsync_peer_t       **peers;           /* insertion order          */
    size_t                   n_peers, cap_peers;
    cmt_bsync_peer_t       **sorted_peers;    /* :83, curRate desc        */
    size_t                   n_sorted;
    char                   (*banned_ids)[CMT_P2P_ID_CAP]; /* :82          */
    int64_t                 *banned_at_ns;
    size_t                   n_banned, cap_banned;
    int64_t                  max_peer_height; /* :84                      */

    int32_t                  num_pending;     /* :87                      */

    cmt_bsync_pool_host_t    host;            /* :89-90                   */
    int64_t                  peer_timeout_ns; /* :57 `peerTimeout` (var)  */

    /* makeRequestersRoutine's wait */
    int64_t                  mr_not_before_ns;
    cmt_bsync_mr_next_t      mr_next;
} cmt_bsync_pool_t;

/**
 * pool.go:93-109 — `NewBlockPool(start, requestsCh, errorsCh)`: height =
 * startHeight = `start`, empty tables. `host` is copied.
 * @return CMT_OK; CMT_FAULT on NULL or a NULL host row.
 */
int cmt_bsync_pool_init(cmt_bsync_pool_t *pool, int64_t start,
                        const cmt_bsync_pool_host_t *host);

/** C-only: frees every requester (and the block it holds), every peer
 *  and every table. NULL is a no-op. */
void cmt_bsync_pool_free(cmt_bsync_pool_t *pool);

/**
 * pool.go:113-117 — `OnStart()`: startTime = now (:114), the routines
 * run from the next tick. A second start while running is ignored
 * (BaseService's ErrAlreadyStarted).
 * @return CMT_OK; CMT_FAULT on NULL.
 */
int cmt_bsync_pool_start(cmt_bsync_pool_t *pool, int64_t now_ns);

/** BaseService.Stop: `pool.Quit()` — every routine ends (:121-124,
 *  :855-859). Frees the requesters (deviation BS-3). NULL is a no-op. */
void cmt_bsync_pool_stop(cmt_bsync_pool_t *pool);

/** `pool.IsRunning()`. */
bool cmt_bsync_pool_is_running(const cmt_bsync_pool_t *pool);

/**
 * Every routine the reference runs as a goroutine, once each, until it
 * would wait (file header): `makeRequestersRoutine` (:120-156), every
 * peer's `onTimeout` timer (:597-603, :623-631), every requester's
 * `requestRoutine` (:838-902) in height order.
 * @param out_deadline_ns the earliest pending deadline (INT64_MAX when
 *        nothing is waiting on time); may be NULL.
 * @return CMT_OK; CMT_FAULT on NULL or an allocation failure.
 */
int cmt_bsync_pool_tick(cmt_bsync_pool_t *pool, int64_t now_ns,
                        int64_t *out_deadline_ns);

/** cometbft@v0.38.26 blocksync/pool.go:202-213 — `HasPendingRequestFrom(
 *  peerID)`: whether any requester names `peer_id` in either slot
 *  (`didRequestFrom`, :762-766). The reactor's FilterMsgBytes asks it
 *  before decoding a BlockResponse (reactor.go:311-314). */
bool cmt_bsync_pool_has_pending_request_from(const cmt_bsync_pool_t *pool,
                                             const char *peer_id);

/** pool.go:193-200 — `GetStatus()`. Any out pointer may be NULL. */
void cmt_bsync_pool_get_status(const cmt_bsync_pool_t *pool, int64_t *height,
                               int32_t *num_pending, size_t *len_requesters);

/** pool.go:202-223 — `IsCaughtUp()`: at least one peer (:209-212), and
 *  (height > 0 or 5 s since start) and (maxPeerHeight == 0 or
 *  height >= maxPeerHeight − 1) (:219-221). */
bool cmt_bsync_pool_is_caught_up(const cmt_bsync_pool_t *pool, int64_t now_ns);

/**
 * pool.go:225-244 — `PeekTwoBlocks()`: the blocks at `height` and
 * `height + 1` (either NULL when absent). The pool keeps ownership; the
 * pointers stay valid until the next call that changes the pool.
 */
void cmt_bsync_pool_peek_two_blocks(const cmt_bsync_pool_t *pool,
                                    cmt_bsync_block_t **first,
                                    cmt_bsync_block_t **second);

/**
 * pool.go:246-267 — `PopRequest()`: removes the requester at `height`,
 * `height++`, re-evaluates maxPeerHeight (cometbft@v0.38.26
 * blocksync/pool.go:275-276: a peer whose base was just beyond the old
 * height may now count), and notifies the next minBlocksForSingleRequest
 * requesters of the new height (:262-266). OWNERSHIP of the popped requester's block
 * passes to the caller through `*out_block` (the reference keeps using
 * `first` after the pop, reactor.go:534-549; Go's GC is what keeps it
 * alive there). The reference PANICS when there is no requester (:252-254)
 * → CMT_FAULT.
 * @return CMT_OK; CMT_FAULT.
 */
int cmt_bsync_pool_pop_request(cmt_bsync_pool_t *pool,
                               cmt_bsync_block_t **out_block);

/**
 * pool.go:269-282 — `RemovePeerAndRedoAllPeerRequests(height)`: the peer
 * that delivered the block at `height` is removed (every requester that
 * asked it is told to redo) and banned. Its ID is copied to `out_peer_id`
 * (CMT_P2P_ID_CAP bytes; "" when the requester had no block — the
 * reference then removes and bans the empty ID). A missing requester is a
 * Go nil dereference (:277) → CMT_FAULT.
 * @return CMT_OK; CMT_FAULT.
 */
int cmt_bsync_pool_remove_peer_and_redo_all_peer_requests(
        cmt_bsync_pool_t *pool, int64_t height, int64_t now_ns,
        char out_peer_id[CMT_P2P_ID_CAP]);

/** pool.go:297-300 — deprecated `RedoRequest`: the same call. */
int cmt_bsync_pool_redo_request(cmt_bsync_pool_t *pool, int64_t height,
                                int64_t now_ns,
                                char out_peer_id[CMT_P2P_ID_CAP]);

/** pool.go:284-295 — `RedoRequestFrom(height, peerID)`: when that height
 *  was requested from that peer, the requester redoes it. */
void cmt_bsync_pool_redo_request_from(cmt_bsync_pool_t *pool, int64_t height,
                                      const char *peer_id);

/**
 * pool.go:302-351 — `AddBlock(peerID, block, extCommit, blockSize)`.
 * TAKES OWNERSHIP of `b` in every case: it is either stored in the
 * requester or freed here (the reference drops the reference and lets GC
 * collect it — at :315-320, :328-335, :338-342 and the `bpr.block != nil`
 * branch of setBlock, :688-691). The counters follow BS-10 (header), not
 * the reference's :344-348.
 * @return CMT_OK (also for a copy BS-10 drops silently); CMT_REJECT for
 *         each of the reference's error returns (a `send_error` has been
 *         made where the reference makes one); CMT_FAULT on NULL.
 */
int cmt_bsync_pool_add_block(cmt_bsync_pool_t *pool, const char *peer_id,
                             cmt_bsync_block_t *b, int64_t now_ns);

/** pool.go:353-358 — `Height()`. */
int64_t cmt_bsync_pool_height(const cmt_bsync_pool_t *pool);

/** pool.go:360-365 — `MaxPeerHeight()`. */
int64_t cmt_bsync_pool_max_peer_height(const cmt_bsync_pool_t *pool);

/**
 * pool.go:367-402 — `SetPeerRange(peerID, base, height)`: a peer reporting
 * base > height is removed if known and banned (cometbft@v0.38.26
 * blocksync/pool.go:388-396); a known peer that reports a LOWER base or
 * height is removed and banned (:374-383); an unknown one is ignored while
 * banned (:387-390), otherwise added at the FRONT of the sorted list
 * (:391-396). maxPeerHeight is then recomputed (v0.38.26 :425).
 * @return CMT_OK; CMT_FAULT on NULL or allocation failure.
 */
int cmt_bsync_pool_set_peer_range(cmt_bsync_pool_t *pool, const char *peer_id,
                                  int64_t base, int64_t height, int64_t now_ns);

/** pool.go:404-411 — `RemovePeer(peerID)`; unknown ID is a no-op. */
void cmt_bsync_pool_remove_peer(cmt_bsync_pool_t *pool, const char *peer_id);

/** pool.go:454-459 — `IsPeerBanned(peerID)`. */
bool cmt_bsync_pool_is_peer_banned(const cmt_bsync_pool_t *pool,
                                   const char *peer_id, int64_t now_ns);

/* ── accessors for the reactor and the tests ───────────────────────── */

/** The peer with `peer_id`, or NULL. */
const cmt_bsync_peer_t *cmt_bsync_pool_peer(const cmt_bsync_pool_t *pool,
                                            const char *peer_id);
/** The requester for `height`, or NULL. */
const cmt_bsync_requester_t *cmt_bsync_pool_requester(
        const cmt_bsync_pool_t *pool, int64_t height);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_BSYNC_POOL_H */
