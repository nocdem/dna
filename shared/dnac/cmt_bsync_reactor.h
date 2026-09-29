/**
 * @file shared/dnac/cmt_bsync_reactor.h
 * @brief cometbft `blocksync/reactor.go` (pin v0.38.26, see "REFERENCE
 *        PIN" below) ported to C — the block sync reactor on channel 0x40:
 *        it serves stored blocks to peers, and while this node is behind it
 *        fetches blocks, verifies each with the next block's LastCommit
 *        (EVERY signature), stores and applies it, then hands the
 *        resulting state to the consensus reactor.
 *
 * ── REFERENCE PIN ──────────────────────────────────────────────────────
 * cometbft v0.38.26 since 2026-09-30 (decision
 * docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md). Cites marked
 * `v0.38.26` are read from that tree; every other `:NNN` still names the
 * @709fd12b reactor.go (renumbering pending). The v0.38.26 changes ported
 * here, all security fixes upstream made after the old pin:
 *   · FULL commit verification of the second block's LastCommit —
 *     `VerifyCommit`, not `VerifyCommitLight` (v0.38.26 reactor.go:580-585;
 *     upstream #5711/#5753) — so the commit this node SAVES as the block's
 *     seen commit (:621-625) has had every non-absent signature checked,
 *     and the switch to consensus can no longer halt on it (red-team R1-1);
 *   · `VerifyCommitExtended` of the first block's extended commit when
 *     vote extensions are enabled (:587-595; #5629) — BS-12 below;
 *   · the vote-extension presence rule checked FIRST, then the commit, then
 *     ValidateBlock (:568-613), every refusal through
 *     `handleValidationFailure` (:655-677);
 *   · `FilterMsgBytes` + `validateMaxVotes` (:279-346; #5860, #5959): a
 *     BlockResponse is checked BEFORE it is decoded — refused when this
 *     node never ran block sync, when no request is outstanding to that
 *     peer, or when it carries more than MaxVotesCount signatures; after
 *     the switch to consensus only the signature cap applies, so an honest
 *     peer answering our last requests late is not disconnected;
 *   · `handlePeerResponse` (:256-277) as its own function.
 *
 * Governing records: docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md,
 * docs/plans/decisions/2026-09-29-blocksync-before-testnet.md
 * (operator 2026-09-29: follow the reference — MaxMsgSize = MaxBlockSizeBytes
 * + 5, VerifyCommitLight ported, wait_sync = blockSync per node.go:375; D-23's
 * "no-blocksync deviation" is removed by this port; its later section
 * "red-team tur 1 sonrası sertleştirme" (operator "a") orders the second
 * block's LastCommit FULLY verified — which v0.38.26's own VerifyCommit
 * now does, so block sync no longer calls VerifyCommitLight),
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
 *   · `FilterMsgBytes` (v0.38.26 :279-322) runs on every message first
 *     (cmt_bsync_reactor_filter_msg_bytes), after the channel's
 *     RecvMessageCapacity, exactly where p2p/peer.go:408-413 calls it.
 *   · `poolRoutine` (:318-572), only when `block_sync` (:134-145):
 *     every 10 ms (and immediately again after every processed block,
 *     :480) peek the two lowest blocks, check the extended-commit presence
 *     rule (v0.38.26 :568-578), verify the first with the second's
 *     LastCommit (`VerifyCommit`, every signature, v0.38.26 :580-585) and,
 *     when extensions are on, its extended commit (:587-595), validate it
 *     (:597-613), SAVE then APPLY it (:615-634); every 10 s ask all peers
 *     for their status (:325, :371-373); every 1 s check whether to switch
 *     to consensus (:382-438).
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
 * node's own requests. `VerifyCommit`, `VerifyCommitExtended`, the apply
 * and FilterMsgBytes never see a time. ValidateBlock DOES, once, since
 * the v0.38.26 pin: the executor behind `validate_block`
 * (nodus_cmt_host_validate_block) refuses a block whose time is not
 * before this node's wall clock + 60 s (state/validation.go:124-129;
 * decision 2026-09-25-consensus-clock-scope-correction.md, addendum "Ek —
 * pin v0.38.26"). Consequence, the reference's too: a node whose clock
 * LAGS the chain by more than 60 s refuses honest near-tip blocks as a
 * validation failure (reactor.go:597-613), and handle_validation_failure
 * removes, bans and disconnects the honest peers that delivered them
 * (reactor.go:655-677) — this node only, node-local, the chain does not
 * split; node NTP is an operational obligation. reactor.go:339/:558/:561 (the blocks/s log rate) is
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
 *         sync and no metrics (port map YOK). v0.38.26 turned `blockSync`
 *         into an `atomic.Bool` (reactor.go:64) because SwitchToBlockSync
 *         and FilterMsgBytes run on other goroutines; here one event loop
 *         owns the reactor, so it stays a plain bool.
 *   BS-11 v0.38.26 validates every block after the first with
 *         `ValidateBlockSkipLastCommit` (reactor.go:597-608, state/
 *         execution.go:206-212), skipping the re-verification of
 *         first.LastCommit because the previous iteration verified it as
 *         second.LastCommit. This port has no such host row (the executor,
 *         `nodus_cmt_host_validate_block`, is another package's): EVERY
 *         block goes through the full `validate_block`, which verifies
 *         block.LastCommit with VerifyCommit against the state's
 *         LastValidators and LastBlockID (nodus_witness_cmt_host.c
 *         :1026-1050). Same verdict on every input the reference accepts,
 *         and STRICTER where the held block at the new height is not the
 *         one whose LastCommit was verified (it was redone from another
 *         peer after the pop): one more commit verification per block.
 *   BS-12 PLACEMENT — MOVED (2026-09-30, red-team row 3-1):
 *         `VerifyCommitExtended` belongs to types (v0.38.26
 *         types/validator_set.go:717-757, a ValidatorSet method). It was
 *         first written here as a static copy; there is now ONE port,
 *         `cmt_validator_set_verify_commit_extended` (cmt_validator_set.c),
 *         and block sync calls it (reactor.go:591). The two copies had
 *         drifted: a NULL extended commit was REJECT here and FAULT there
 *         (the types rule, R1B-10, stands — block sync passes the address
 *         of the commit it holds, never NULL); a validator without a
 *         public key was refused here even at an ABSENT entry, which the
 *         reference passes (VerifyExtension never reads the key for it,
 *         vote.go:268-270, and VerifyCommit refuses a keyless signer of
 *         any non-absent entry first, validation.go:384-386) — the types
 *         behaviour, the reference's, stands; and the types copy took a
 *         caller-sized sign-bytes scratch, now sized per vote inside.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * The chain a node ends with is fixed by the commits, not by the path: a
 * block is stored only after `VerifyCommit` accepted more than two thirds
 * of the committed set's power for exactly its BlockID (hash + part set
 * header) AND verified every other non-absent signature of that commit,
 * and it is applied through the executor consensus itself uses
 * (`apply_verified_block`, design D1). Peer choice, timing and order of
 * arrival change only WHEN a node gets there; the filter decides only
 * which PEER is dropped, never which block is accepted.
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
    CMT_BSYNC_STOP_VALIDATION      = 7,  /* v0.38.26 :655-677 ErrReactorValidation */
    CMT_BSYNC_STOP_FILTER          = 8   /* v0.38.26 :299-319 FilterMsgBytes
                                          * (p2p/peer.go:408-413)             */
} cmt_bsync_stop_reason_t;

/** Why `cmt_bsync_reactor_filter_msg_bytes` refused (the reference's
 *  error strings, v0.38.26 reactor.go:279-346). */
typedef enum {
    CMT_BSYNC_FILTER_OK                  = 0,
    CMT_BSYNC_FILTER_MALFORMED           = 1, /* :290-292 stub.Unmarshal failed  */
    CMT_BSYNC_FILTER_NOT_ACTIVE          = 2, /* :300-302 "blocksync not active" */
    CMT_BSYNC_FILTER_UNSOLICITED         = 3, /* :312-314 no request to the peer */
    CMT_BSYNC_FILTER_TOO_MANY_COMMIT_SIGS = 4, /* :338-340                        */
    CMT_BSYNC_FILTER_TOO_MANY_EXT_SIGS   = 5  /* :341-343                        */
} cmt_bsync_filter_err_t;

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
 * cometbft@v0.38.26 blocksync/reactor.go:279-322 — `FilterMsgBytes(chID,
 * src, msgBytes)` for channel 0x40 (the `chID != BlocksyncChannel` branch,
 * :283, belongs to the switch here: only 0x40 bytes reach this reactor),
 * with `validateMaxVotes` (:324-346). In the reference's order:
 *   · empty bytes → accepted (:283-285, "will fail unmarshalling");
 *   · the SigCount stub does not decode → MALFORMED (:289-292);
 *   · not a BlockResponse → accepted (:293-297);
 *   · this reactor was built without block sync → NOT_ACTIVE (:300-302);
 *   · the pool has stopped (switched to consensus) → ONLY the signature
 *     cap (:307-309): "the peers are honest and must not be disconnected
 *     for answering our own requests";
 *   · no requester names the peer → UNSOLICITED (:312-314);
 *   · more than MaxVotesCount commit / extended signatures →
 *     TOO_MANY_COMMIT_SIGS / TOO_MANY_EXT_SIGS (:317-319, :338-343).
 * Reads no clock; changes nothing.
 * @param why may be NULL; receives the reason (FILTER_OK on CMT_OK).
 * @return CMT_OK (let it through); CMT_REJECT (drop it and stop the
 *         peer, p2p/peer.go:410-412); CMT_FAULT on NULL.
 */
int cmt_bsync_reactor_filter_msg_bytes(const cmt_bsync_reactor_t *bcR,
                                       const char *peer_id,
                                       const uint8_t *bytes, size_t len,
                                       cmt_bsync_filter_err_t *why);

/**
 * reactor.go:251-305 — `Receive(e)`, preceded by the channel's
 * RecvMessageCapacity (:184), FilterMsgBytes (above; a refusal stops the
 * peer — MALFORMED as UNDECODABLE, every other as FILTER) and the p2p
 * decode (p2p/peer.go:407-422): an oversize, filtered, undecodable or
 * invalid message stops the peer.
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
