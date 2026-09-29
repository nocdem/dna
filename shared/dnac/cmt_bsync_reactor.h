/**
 * @file shared/dnac/cmt_bsync_reactor.h
 * @brief cometbft @709fd12b `blocksync/reactor.go` ported to C — the block
 *        sync reactor on channel 0x40: it serves stored blocks to peers,
 *        and while this node is behind it fetches blocks, verifies each
 *        with the next block's LastCommit, stores and applies it, then
 *        hands the resulting state to the consensus reactor.
 *
 * Governing records: docs/plans/decisions/2026-09-29-blocksync-before-testnet.md
 * (operator 2026-09-29: follow the reference — MaxMsgSize = MaxBlockSizeBytes
 * + 5, VerifyCommitLight ported, wait_sync = blockSync per node.go:375; D-23's
 * "no-blocksync deviation" is removed by this port),
 * docs/plans/2026-09-29-blocksync-port-design.md (D1: blocks are applied
 * through the SAME executor consensus uses; D2: validation reads no clock;
 * G1-G4), docs/plans/decisions/2026-09-25-consensus-clock-scope-correction.md.
 *
 * ── WHAT IT DOES, IN ORDER ─────────────────────────────────────────────
 *   · `AddPeer` (:190-203): send our StatusResponse{base, height}. A peer
 *     enters the POOL only when its own StatusResponse arrives
 *     (`SetPeerRange`, :296-298).
 *   · `Receive` (:251-305): serve a BlockRequest from the store
 *     (respondToPeer, :210-249), answer a StatusRequest, feed a
 *     BlockResponse to the pool (after decoding it — a block that does not
 *     decode stops the peer, :265-282), record a StatusResponse, redo a
 *     request on a NoBlockResponse. RECEIVE KEEPS SERVING AFTER THE SWITCH
 *     to consensus: the reference never unregisters the channel, so a
 *     node that has switched still answers other nodes' block requests.
 *   · `poolRoutine` (:318-572), only when `block_sync` (:134-145):
 *     every 10 ms (and immediately again after every processed block,
 *     :480) peek the two lowest blocks, verify the first with the second's
 *     LastCommit (`VerifyCommitLight`, :496-497), validate it (:501), check
 *     the extended-commit rule (:503-514), SAVE then APPLY it (:534-549);
 *     every 10 s ask all peers for their status (:325, :371-373); every
 *     1 s check whether to switch to consensus (:382-438).
 *
 * ── GOROUTINES → A TICK (the cmt_memr / cmt_conr pattern) ──────────────
 * `cmt_bsync_reactor_tick` runs the poolRoutine's select and its helper
 * goroutine (:346-377) once: the status ticker, the pool's own routines
 * (cmt_bsync_pool_tick), the trySync ticker, the didProcessCh loop and the
 * switch ticker, in that order (BS-5 below). A ticker is a `next` deadline
 * compared against the host's `now` (a Go ticker drops ticks it could not
 * deliver; here the next deadline is `now + period` after a firing — the
 * same "at most one pending tick" behaviour). The didProcessCh loop
 * processes blocks back to back as the reference's re-prime at :480 does,
 * BOUNDED per tick by `step_budget` (like WITNESS_CMT_STEP_BUDGET); while
 * the budget ran out with blocks still pending the tick reports a deadline
 * of NOW, so the host comes straight back. The tick returns the earliest
 * of every pending deadline.
 *
 * ── THE CLOCK (decision 2026-09-25, "where the reference reads it") ───
 * `host.now` — the SAME callback the consensus state machine uses — is
 * read once per `cmt_bsync_reactor_start` (pool.go:114 startTime, and the
 * three tickers' creation, reactor.go:322/:325/:331), once per
 * `cmt_bsync_reactor_tick` (the tickers and every pool deadline — the
 * tick form of the goroutines' sleeps and timers, pool.go:128-153, :219,
 * :592-602, :792, :850, :892) and once per `cmt_bsync_reactor_receive`
 * that reaches the pool (pool.go:345-348 decrPending's monitor/timer,
 * :387/:464 the ban check). Every read schedules or rate-limits THIS
 * node's own requests. `VerifyCommitLight`, ValidateBlock and the apply
 * never see a time. reactor.go:339/:558/:561 (the blocks/s log rate) is
 * log-only and NOT ported — the cmt_cs.c:1920-1921 precedent for
 * state.go:1064.
 *
 * ── THE HOST (everything reactor.go reaches outside its package) ───────
 * Two contexts: `ctx` for the p2p rows (the witness p2p host) and
 * `exec_ctx` for the store / state / executor / consensus rows (the node).
 * Every row except `switch_to_consensus` is required; a NULL row reached at
 * run time is CMT_FAULT. A row MUST NOT re-enter the reactor. A peer is
 * named by its p2p ID (`cmt_p2p_peer_id`, cmt_p2p_peer.c:462), never by a
 * slot index.
 *
 * ── DEVIATIONS (labelled) ──────────────────────────────────────────────
 *   BS-5  select order: Go chooses at random among ready cases of the
 *         FOR_LOOP (:380-570) and of the helper goroutine (:347-376); the
 *         tick serves them in one fixed order (status, pool, trySync,
 *         didProcess, switch). Node-local: which peer is asked when.
 *   BS-6  blocks are decoded at RECEIVE into per-block heap storage sized
 *         from the message (capped at the node's own block limits — the
 *         same caps consensus decodes with, so a block consensus would
 *         refuse to hold is refused here too) and HELD until applied or
 *         discarded, as the reference holds `*types.Block`.
 *         `msg.Block.Size()` (:284) is the length of the Block's bytes on
 *         the wire — equal to Size() for a canonical encoding; it feeds only
 *         the pool's receive-rate Monitor.
 *   BS-7  `MakePartSet` (:482-488) marshals into a buffer that grows until
 *         the block fits (the reference's `[]byte` grows by itself); only a
 *         marshal that fails at MaxBlockSizeBytes × 2 takes the reference's
 *         `break FOR_LOOP` — which ENDS the pool routine for good (the node
 *         then never switches; reproduced, logged loudly).
 *   BS-8  the reference PANICS at :465, :469 (pool/state height mismatch),
 *         :552 (ApplyVerifiedBlock failed) and inside SaveBlock; here each
 *         is CMT_FAULT from the tick — node-local, the host stops this node.
 *         A host row's own CMT_FAULT (database error) is propagated the same
 *         way instead of being blamed on the peer.
 *   BS-9  SwitchToBlockSync (:148-164, the state-sync hand-off) and the
 *         metrics (:319-320, :554) are not ported: this port has no state
 *         sync and no metrics (port map YOK).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * The chain a node ends with is fixed by the commits, not by the path: a
 * block is stored only after `VerifyCommitLight` accepted more than two
 * thirds of the committed set's power for exactly its BlockID (hash + part
 * set header), and it is applied through the executor consensus itself
 * uses (`apply_verified_block`, design D1). Peer choice, timing and order
 * of arrival change only WHEN a node gets there.
 *
 * Reference @709fd12b: blocksync/reactor.go 580 lines, node/node.go:366-413,
 * node/setup.go:219-225 & :296, consensus/reactor.go:107-141 & :182-210
 * (/tmp/r2-a-ref/cometbft-709fd12b4b18cf1442d43c5d34009392c7d674ed).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_BSYNC_REACTOR_H
#define SHARED_DNAC_CMT_BSYNC_REACTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_bsync_msgs.h"
#include "cmt_bsync_pool.h"
#include "cmt_block.h"
#include "cmt_part_set.h"
#include "cmt_params.h"
#include "cmt_state.h"
#include "cmt_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/** reactor.go:22 `trySyncIntervalMS` = 10 ms. */
#define CMT_BSYNC_TRY_SYNC_INTERVAL_NS    (10 * CMT_BSYNC_NS_PER_MS)
/** reactor.go:29 `statusUpdateIntervalSeconds` = 10 s. */
#define CMT_BSYNC_STATUS_UPDATE_INTERVAL_NS (10 * CMT_BSYNC_NS_PER_S)
/** reactor.go:31 `switchToConsensusIntervalSeconds` = 1 s. */
#define CMT_BSYNC_SWITCH_TO_CONSENSUS_INTERVAL_NS (1 * CMT_BSYNC_NS_PER_S)

/** reactor.go:177-188 `GetChannels()` — the one descriptor. */
#define CMT_BSYNC_CHANNEL_PRIORITY             5
#define CMT_BSYNC_CHANNEL_SEND_QUEUE_CAPACITY  1000
#define CMT_BSYNC_CHANNEL_RECV_BUFFER_CAPACITY (50 * 4096)

/** The default per-tick bound of the didProcessCh loop (header): blocks
 *  verified-and-applied (or refused) in one tick. ⚠ NOT GROUNDED — no
 *  reference counterpart: the reference's goroutines run beside this
 *  loop, here the p2p I/O that delivers the next blocks waits for the
 *  tick to return. A choice, like WITNESS_CMT_STEP_BUDGET
 *  (nodus_witness.c); a tick that hit it reports a deadline of NOW. */
#define CMT_BSYNC_DEFAULT_STEP_BUDGET 16

/** StopPeerForError reasons the reactor passes to the host (logged by
 *  the switch). */
typedef enum {
    CMT_BSYNC_STOP_OVERSIZE        = 1,  /* RecvMessageCapacity (:184)        */
    CMT_BSYNC_STOP_UNDECODABLE     = 2,  /* p2p/peer.go:407-422               */
    CMT_BSYNC_STOP_INVALID_MSG     = 3,  /* :253-257 ValidateMsg              */
    CMT_BSYNC_STOP_INVALID_BLOCK   = 4,  /* :265-270 BlockFromProto           */
    CMT_BSYNC_STOP_INVALID_EXT     = 5,  /* :274-281 ExtendedCommitFromProto  */
    CMT_BSYNC_STOP_POOL_ERROR      = 6,  /* :365-369 errorsCh (+ the pool's err) */
    CMT_BSYNC_STOP_VALIDATION      = 7   /* :516-531 ErrReactorValidation     */
} cmt_bsync_stop_reason_t;

/** reactor.go:177-188 — the channel descriptor this port carries. */
typedef struct {
    uint8_t id;                     /* :180 BlocksyncChannel 0x40      */
    int     priority;               /* :181 5                          */
    int     send_queue_capacity;    /* :182 1000                       */
    int     recv_buffer_capacity;   /* :183 50 * 4096                  */
    size_t  recv_message_capacity;  /* :184 MaxMsgSize                 */
} cmt_bsync_channel_desc_t;

/**
 * Everything reactor.go reaches outside its package (file header, "THE
 * HOST"). Storage the host hands back through an out-pointer stays valid
 * until the next call of the SAME row.
 */
typedef struct {
    /* ── the p2p switch (`ctx`) ─────────────────────────────────────── */
    void *ctx;
    /** `Switch.Peers().Get(id).TrySend(e)` (:216, :242, :289, :354-361):
     *  false when the peer is not connected or its queue is full. The
     *  bytes are a whole marshalled `Message` for channel 0x40, valid for
     *  the call only. */
    bool (*try_send)(void *ctx, const char *peer_id, const uint8_t *msg,
                     size_t len);
    /** `peer.Send(e)` at AddPeer (:192-198) — Send ≡ TrySend under
     *  R-P2P-19; a separate row because the reference uses Send there. */
    bool (*send)(void *ctx, const char *peer_id, const uint8_t *msg,
                 size_t len);
    /** `Switch.Broadcast(e)` (:576-579). */
    void (*broadcast)(void *ctx, const uint8_t *msg, size_t len);
    /** `Switch.StopPeerForError(peer, err)` (:255, :268, :279, :368,
     *  :522, :529), with `Switch.Peers().Get(id)` first where the
     *  reference does (:366-369, :518-519, :525-526): a peer no longer
     *  connected is skipped. The host DEFERS the stop until the reactor
     *  call has returned. */
    void (*stop_peer_for_error)(void *ctx, const char *peer_id, int reason);

    /* ── store / state / executor / consensus (`exec_ctx`) ─────────── */
    void *exec_ctx;
    /** `store.Base()` / `store.Height()` (:195-196, :292-293). */
    int (*bs_base)(void *exec_ctx, int64_t *out);
    int (*bs_height)(void *exec_ctx, int64_t *out);
    /** `store.LoadBlock(height)` (:213): `*out_found` false is nil.
     *  `*out` points at host storage; `*out_size_hint` is the stored
     *  block's byte size (BlockMeta.BlockSize), used to size the marshal
     *  buffer. */
    int (*bs_load_block)(void *exec_ctx, int64_t height, cmt_block_t **out,
                         size_t *out_size_hint, bool *out_found);
    /** `store.LoadBlockExtendedCommit(height)` (:229, :344). */
    int (*bs_load_block_extended_commit)(void *exec_ctx, int64_t height,
                                         cmt_extended_commit_t *out,
                                         bool *out_found);
    /** `store.SaveBlock(block, parts, seenCommit)` (:544). */
    int (*bs_save_block)(void *exec_ctx, cmt_block_t *block,
                         const cmt_part_set_t *parts,
                         const cmt_commit_t *seen_commit);
    /** `store.SaveBlockWithExtendedCommit(block, parts, extCommit)` (:538). */
    int (*bs_save_block_with_extended_commit)(void *exec_ctx, cmt_block_t *block,
                                              const cmt_part_set_t *parts,
                                              const cmt_extended_commit_t *ec);
    /** `blockExec.Store().Load()` (:222) projected on the one field
     *  respondToPeer reads: `state.ConsensusParams.ABCI` (:228). */
    int (*ss_load_abci_params)(void *exec_ctx, cmt_abci_params_t *out);
    /** `blockExec.ValidateBlock(state, block)` (:501). CMT_OK accepts;
     *  CMT_REJECT is the reference's error; CMT_FAULT is node-local. */
    int (*validate_block)(void *exec_ctx, const cmt_state_t *state,
                          cmt_block_t *block);
    /** `blockExec.ApplyVerifiedBlock(state, blockID, block)` (:549):
     *  OVERWRITES `in_out_state` with the returned state. Anything but
     *  CMT_OK is the panic at :550-553. */
    int (*apply_verified_block)(void *exec_ctx, const cmt_block_id_t *block_id,
                                cmt_block_t *block, cmt_state_t *in_out_state);
    /** `conR.SwitchToConsensus(state, skipWAL)` (:429-432) — the consensus
     *  reactor's port (`cmt_conr_switch_to_consensus`) plus whatever the
     *  host records about it. NULL is the reference's `!ok` branch
     *  (:433-435, "should only happen during testing"). */
    int (*switch_to_consensus)(void *exec_ctx, const cmt_state_t *state,
                               bool skip_wal);

    /** THE CLOCK (file header). */
    cmt_now_fn now;
    void      *now_ctx;
} cmt_bsync_host_t;

/** The decode caps of BS-6: the largest transaction and evidence counts
 *  one block may carry on this node (the node's executor limits). */
typedef struct {
    size_t max_txs;
    size_t max_evidence;
} cmt_bsync_limits_t;

/**
 * reactor.go:49-69 — `type Reactor struct`, plus the poolRoutine's
 * locals (:322-344) that survive between ticks. Private; use the
 * functions.
 */
typedef struct {
    cmt_bsync_host_t     host;
    cmt_bsync_limits_t   limits;
    bool                 block_sync;                 /* :59 */
    uint8_t              local_addr[CMT_ADDRESS_SIZE]; /* :60 */
    size_t               local_addr_len;
    bool                 running;                    /* BaseReactor */
    cmt_bsync_pool_t     pool;                       /* :58 */
    int64_t              switch_to_consensus_ms;     /* :66 */
    size_t               step_budget;

    /* :336-337 `chainID`, `state` — the reactor's OWN evolving state,
     * a COPY of the node's (setup.go:296 `state.Copy()`). */
    cmt_state_t          state;
    cmt_state_storage_t *state_storage;

    /* poolRoutine (:318-572) */
    bool                 routine_running;
    bool                 routine_dead;               /* BS-7 */
    bool                 state_synced;               /* :318 — always false */
    uint64_t             blocks_synced;              /* :334 */
    bool                 initial_commit_has_extensions; /* :344 */
    bool                 did_process;                /* :342 1-deep */
    int64_t              try_sync_next_ns;           /* :322 */
    int64_t              status_next_ns;             /* :325 */
    int64_t              switch_next_ns;             /* :331 */
    bool                 switched;                   /* SwitchToConsensus ran */
} cmt_bsync_reactor_t;

/**
 * reactor.go:71-124 — `NewReactorWithAddr(state, blockExec, store,
 * blockSync, localAddr, …)`. `state` is COPIED into the reactor's own
 * storage (setup.go:296 `state.Copy()`). The store height must equal
 * `state->last_block_height` (:83-96; `offlineStateSyncHeight` is always
 * 0 — no state sync), else the reference panics → CMT_FAULT. The pool
 * starts at `storeHeight + 1`, or at `state.InitialHeight` for an empty
 * store (:105-109).
 * @param local_addr this node's validator address (`localAddr`, :60);
 *        may be NULL/0 (a node with no validator key).
 * @param limits BS-6's caps; required.
 * @return CMT_OK; CMT_FAULT on NULL, a NULL host row, allocation failure
 *         or the height mismatch.
 */
int cmt_bsync_reactor_init(cmt_bsync_reactor_t *bcR, const cmt_state_t *state,
                           bool block_sync, const uint8_t *local_addr,
                           size_t local_addr_len, const cmt_bsync_host_t *host,
                           const cmt_bsync_limits_t *limits);

/** C-only: frees the pool, the state storage and everything held. Does
 *  not call any host row. NULL is a no-op. */
void cmt_bsync_reactor_free(cmt_bsync_reactor_t *bcR);

/**
 * reactor.go:132-146 — `OnStart()`: when `block_sync`, the pool starts
 * (:135) and the poolRoutine starts (:139-143) — its three tickers and
 * `initialCommitHasExtensions` (:344) are set here. Without `block_sync`
 * only Receive/AddPeer/RemovePeer work (the node serves blocks).
 * @return CMT_OK; CMT_FAULT on NULL or a failed clock / store row.
 */
int cmt_bsync_reactor_start(cmt_bsync_reactor_t *bcR);

/** reactor.go:166-174 — `OnStop()`: the pool stops; the routine ends. */
void cmt_bsync_reactor_stop(cmt_bsync_reactor_t *bcR);

/** reactor.go:177-188 — `GetChannels()`. */
void cmt_bsync_reactor_get_channels(cmt_bsync_channel_desc_t *out);

/** reactor.go:190-203 — `AddPeer(peer)`: our StatusResponse to the peer
 *  ("it's OK if send fails", :199). @return CMT_OK; CMT_FAULT. */
int cmt_bsync_reactor_add_peer(cmt_bsync_reactor_t *bcR, const char *peer_id);

/** reactor.go:205-208 — `RemovePeer(peer, _)`: the pool forgets it. */
void cmt_bsync_reactor_remove_peer(cmt_bsync_reactor_t *bcR,
                                   const char *peer_id);

/**
 * reactor.go:251-305 — `Receive(e)`, preceded by the channel's
 * RecvMessageCapacity (:184) and the p2p decode (p2p/peer.go:407-422):
 * an oversize, undecodable or invalid message stops the peer.
 * @return CMT_OK when handled (including every outcome the reference only
 *         logs); CMT_REJECT when the peer was stopped for error;
 *         CMT_FAULT on NULL or a node-local failure.
 */
int cmt_bsync_reactor_receive(cmt_bsync_reactor_t *bcR, const char *peer_id,
                              const uint8_t *bytes, size_t len);

/**
 * The poolRoutine and its helper goroutine, once (file header).
 * @param out_deadline_ns the earliest pending deadline (INT64_MAX when
 *        none; `now` when blocks are still waiting to be processed);
 *        may be NULL.
 * @return CMT_OK; CMT_FAULT on the BS-8 cases or a failed row.
 */
int cmt_bsync_reactor_tick(cmt_bsync_reactor_t *bcR, int64_t *out_deadline_ns);

/** reactor.go:574-580 — `BroadcastStatusRequest()`. */
int cmt_bsync_reactor_broadcast_status_request(cmt_bsync_reactor_t *bcR);

/** Accessors for the host and the tests. */
bool cmt_bsync_reactor_is_syncing(const cmt_bsync_reactor_t *bcR);
bool cmt_bsync_reactor_switched(const cmt_bsync_reactor_t *bcR);
uint64_t cmt_bsync_reactor_blocks_synced(const cmt_bsync_reactor_t *bcR);
const cmt_state_t *cmt_bsync_reactor_state(const cmt_bsync_reactor_t *bcR);
cmt_bsync_pool_t *cmt_bsync_reactor_pool(cmt_bsync_reactor_t *bcR);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_BSYNC_REACTOR_H */
