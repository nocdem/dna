/**
 * @file shared/dnac/cmt_conr.h
 * @brief cometbft @709fd12b `consensus/reactor.go` ported to C — the
 *        consensus REACTOR: what the state machine says to its peers and
 *        what it hears from them.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R3-A of the cometbft → C consensus port: the FIRST LIVE CONSUMER
 * of `cmt_cs` (cmt_cs.h). Nothing in the running chain constructs a
 * `cmt_conr_t` yet — the host glue (tier3 verbs, the server tick, the
 * peer manager, the block store) is R3-C2's; additive only. The live
 * witness BFT is untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * The receiver in the reference is `conR`, so every function is
 * `cmt_conr_*`: `(conR *Reactor) Receive` → `cmt_conr_receive`. The
 * PeerState half of reactor.go (:1017-1482) is cmt_ps.h.
 *
 * ── WHAT THE REACTOR DOES ──────────────────────────────────────────────
 * Three things, all of them per peer and none of them consensus:
 *   1. It BROADCASTS what the state machine just did — a new round step,
 *      a valid block, a vote it holds — when the state machine's event
 *      switch fires (:411-433, :440-497).
 *   2. It GOSSIPS to each peer what that peer still lacks, judged from
 *      the peer's own announcements: block parts, the proposal, the POL,
 *      votes of the current height, the last commit, and — for a peer
 *      more than one height behind — a stored commit (:539-945).
 *   3. It RECEIVES a peer's messages, validates them, updates its picture
 *      of that peer, and hands proposals, block parts and votes to the
 *      state machine's peer queue (:231-391).
 * Nothing here decides a vote or a block. Two nodes with different gossip
 * choices still decide the same blocks.
 *
 * ── THREADS → TICKS (the one structural substitution) ──────────────────
 * The reference runs, per peer, three goroutines forever
 * (`gossipDataRoutine` :539, `gossipVotesRoutine` :698,
 * `queryMaj23Routine` :848), one round-state snapshot goroutine
 * (`updateRoundStateRoutine` :519) and receives on the p2p thread. Here
 * (umbrella rev 4 item 7) there is ONE thread, driven by the host's tick:
 *
 *   `cmt_conr_tick` runs, for every peer slot `AddPeer` started, in SLOT
 *   INDEX ORDER, the three routines IN THE REFERENCE'S START ORDER
 *   (:201-203: data, votes, maj23), each "as far as the reference would
 *   go before a `time.Sleep` or a false from `Send`":
 *     · a `continue OUTER_LOOP` after a successful send loops again
 *       inside the same tick;
 *     · a `time.Sleep(d)` records `not_before = now + d` for THAT routine
 *       of THAT peer and returns — the routine resumes on the first tick
 *       at or after `not_before`. Every one of reactor.go's fourteen
 *       Sleep sites maps to such a record: :585, :600, :641, :655, :660,
 *       :668, :690, :695, :783 (PeerGossipSleepDuration) and :872, :892,
 *       :913, :936, :941 (PeerQueryMaj23SleepDuration), the two config
 *       fields of D-4 (cmt_config.h:98-99; never a literal);
 *     · a `false` from `send`/`try_send` does exactly what the reference
 *       does with false at that site (e.g. :560-570: the part is NOT
 *       marked as sent; :1160: the vote is not marked) and then ENDS that
 *       routine's pass for this tick, so a full queue cannot spin the
 *       loop — see DEVIATION R3-A-1.
 *   `*out_next_deadline_ns` is the earliest `not_before` across every
 *   routine of every peer (INT64_MAX if none): the server's poll wait
 *   (R3-C2, S16) uses it.
 *
 *   ⚠ DEVIATION R3-A-1 — `Send` NEVER BLOCKS. The reference's `Send`
 *   (p2p/peer.go:258-262) blocks up to `defaultSendTimeout` (10 s,
 *   p2p/conn/connection.go:45 — infrastructure, not ported) when a
 *   channel's send queue is full and only then returns false; `TrySend`
 *   (:264-268) returns false at once. Both host rows here return false at
 *   once, and the wait becomes "the next tick". Also under R3-A-1: the two
 *   bare `continue`s at :758 and :763 (a stored commit the store cannot
 *   load — the reference busy-loops until it can) end the pass, because
 *   within one tick nothing can change the answer; and :580-591 with a
 *   BlockMeta whose PartSetHeader.Total is 0 (`bits.NewBitArray(0)` is
 *   nil, so `ProposalBlockParts` stays nil and the reference loops
 *   forever) ends the pass. Each such site says so.
 *
 *   `updateRoundStateRoutine` (:519-531) snapshots the round state every
 *   100 µs into `conR.rs` and `getRoundState` (:533-537) reads the
 *   snapshot. Single-threaded, there is nothing to snapshot:
 *   `cmt_conr_get_round_state` reads `cmt_cs_get_round_state` live at
 *   every use, which is the reference's value at most 100 µs fresher.
 *
 *   `conR.mtx` (:44), `conR.conS.mtx` (:112, :261, :276, :343, :365, :749)
 *   and every `ps.mtx` are dropped; each site carries a one-line note.
 *
 *   `IsRunning()` (:192, :214, :232, :523, :545, :707, :852, :949) is the
 *   `running` flag, set by `cmt_conr_start` BEFORE its body and cleared
 *   by `cmt_conr_stop` BEFORE its body, which is libs/service/service.go
 *   `BaseService.Start` (:131 sets `started`, :144 calls OnStart, :147
 *   reverts on error) and `Stop` (:168 sets `stopped`, :181 calls OnStop).
 *   `peer.IsRunning()` (:545, :707, :852) is the host's per-peer
 *   "connected" state, which this module learns through
 *   `cmt_conr_remove_peer`: the host calls it when the connection closes,
 *   the slot is freed and its routines stop — the reference's `RemovePeer`
 *   (:213-223) is a no-op precisely because its goroutines watch
 *   `peer.IsRunning()` themselves.
 *
 *   `Broadcast` (p2p/switch.go:274-296): one goroutine per peer of
 *   `sw.peers.List()`, order unspecified; the success channel it returns
 *   is discarded by all three reactor callers (:442, :457, :471). Here:
 *   every slot in the switch's peer SET — added at switch.go:846 after
 *   `InitPeer` (:830) and before `AddPeer` (:859), removed at :381 — in
 *   index order, `send`, nothing returned. A slot that is in the set but
 *   not yet started gets the send and the host answers false for a peer
 *   that is not running (peer.go:271-272), as the reference does.
 *
 * ── THE HOST TABLE ─────────────────────────────────────────────────────
 * `cmt_conr_host_t` — the transport and the block-store reads the REACTOR
 * makes, distinct from `cmt_cs_host_t` (the state machine's). Every row
 * carries its Go call site. The block-store rows follow the storage
 * contract of cmt_cs.h:419-448 word for word: the host fills the
 * out-parameter, including pointing any list at storage the host owns,
 * and that storage stays valid until the next call of the same row.
 *
 * ── THE RECEIVE ARENA ──────────────────────────────────────────────────
 * `cmt_conr_receive` takes a peer's BYTES and decodes them with
 * `cmt_pb_cons_message_unmarshal` into `recv_arena` (cmt_pb.h:62-66: a
 * decoded part's payload and a vote's extension are COPIED there and the
 * message points at them). Those pointers OUTLIVE the call:
 * `cmt_cs_add_proposal_block_part_input` copies the part STRUCT
 * (cmt_cs.c, `mi->msg.u.block_part.part = *part`), the queued message is
 * re-read when it is dequeued (the WAL write of state.go:831), and
 * `cmt_part_set_add_part` stores the struct into the height's part set
 * (cmt_part_set.h:46-50), which lives until `updateToState` releases it.
 * THE ARENA MAY THEREFORE BE RESET ONLY WHEN (a) the state machine's peer
 * queue holds no message decoded into it AND (b) every part set and vote
 * set of the height those bytes belong to has been released — the same
 * rule as `cs->ext_arena`'s (cmt_cs.h OWNERSHIP (2), whose text already
 * names "whatever decodes a peer's vote" as a writer) plus clause (a).
 * Passing `cs->ext_arena` itself is the designed wiring; a host that
 * wants two arenas must give both the same lifetime. The reset policy is
 * the host's (R3-C2) and is raised as a QUESTION in the wave report.
 * ⚠ WHAT HAPPENS IF IT IS NEVER RESET — register R3-A-5 (verifier A,
 * 2026-09-14): the arena is ONE for all peers, the decode consumes it
 * BEFORE ValidateBasic, before the `wait_sync` drop and before any height
 * check, and `r_copy_arena` answers exhaustion with the same CMT_REJECT
 * as malformed bytes, so `cmt_conr_receive` stops WHICHEVER peer's message
 * hit the wall as a DECODE error. A peer that fills the arena with
 * decodable junk parts (`Part.ValidateBasic` checks shape, not the block
 * root) therefore gets an HONEST peer disconnected. The reference has no
 * analogue (Go allocates per message). R3-C2 must both choose the reset
 * policy and make exhaustion a distinct outcome from a bad message.
 *
 * ── THE ValidateBasic GATE (msgs.go:232-234), NOW HERE ─────────────────
 * The reference's `Receive` calls `MsgFromProto` (:236), whose last act
 * is `pb.ValidateBasic()` (msgs.go:232-234), and then `msg.ValidateBasic()`
 * again (:243). R2's `cmt_msg_from_proto` stops before that line
 * (cmt_msgs.h:28-35); `cmt_msg_validate_basic` below IS that line, called
 * by `cmt_conr_receive` right after the decode, and its nine per-message
 * bodies are :1536, :1596, :1634, :1653, :1684, :1710, :1730, :1762 and
 * :1795. `NewRoundStepMessage.ValidateHeight` (:1560) is the tenth, run
 * by `Receive` at :264 against the chain's initial height.
 *
 * ── THE PANIC RULE (umbrella rev 4) ────────────────────────────────────
 *   · :255 "Peer %v has no state" — a Receive for a slot `InitPeer` never
 *     filled. NODE-LOCAL → CMT_FAULT: the host wired a connection past
 *     InitPeer; the reference's own test (reactor_test.go:278-305)
 *     expects the panic.
 *   · :198 "peer %v has no state" in AddPeer — same class, CMT_FAULT.
 *   · :297 and :377 "Bad VoteSetBitsMessage field Type. Forgot to add a
 *     check in ValidateBasic?" — unreachable once the gate has run
 *     (:1769, :1799 refuse the type); NODE-LOCAL → CMT_FAULT.
 *   · :557 `part.ToProto()` failing on a part of OUR OWN part set whose
 *     bit says it is held — NODE-LOCAL → CMT_FAULT.
 *   · :132-140 `conR.conS.Start()` failing inside SwitchToConsensus —
 *     NODE-LOCAL → CMT_FAULT (the reference dumps both objects and dies).
 *   Go `error` returns at :237-241, :243-247, :264-268 and :284-287 are
 *   the reference's four `StopPeerForError` sites: the host row is
 *   called with a reason code and Receive returns as the reference does.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * THE CLOCK is the host's `now` row, THE SAME CALLBACK as
 * `cs->host.now` (D-20 rev 3; the host passes one function into both
 * tables), read at exactly the reference's sites: :504
 * (`time.Since(rs.StartTime)` in `makeRoundStepMessage`), :1379
 * (`cmttime.Now()` in `ApplyNewRoundStepMessage`, read in `Receive` and
 * handed to cmt_ps as a value), and — C only, stated — once per
 * `cmt_conr_tick`, because the fourteen `time.Sleep` sites are
 * deadlines here and a deadline needs an instant. No other clock read.
 * THE ONLY RANDOMNESS is `PickRandom` (:553, :649, :1188) through
 * `cmt_bits_pick_random`, the recorded substitution — gossip choice
 * only. Iteration is by slot index and by validator/part index; no map,
 * no unordered collection. `Broadcast`'s goroutine order and Go's
 * scheduler order between the three routines and between peers are
 * REPLACED BY INDEX ORDER (umbrella rev 5 item 7 — the same class of
 * determinization cmt_cs.h "ONE THREAD, ONE ROTATING POLL" states for
 * `select`, which there is a rotating start rather than a fixed index
 * order because `select`'s guarantee is fairness among ready sources;
 * here nothing is starved by index order, since every slot is visited
 * on every tick).
 *
 * ── taşınmadı (not ported), with the reason — port map YOK rows ────────
 *   · `OnStart` (:74-91) / `OnStop` (:95-103) — BaseService hooks. Their
 *     CONTENT (subscribe, start the state machine; unsubscribe, stop it)
 *     is reached through the C-only `cmt_conr_start` / `cmt_conr_stop`,
 *     which do what :74-105 do minus BaseService. `peerStatsRoutine`'s
 *     start at :78 and `updateRoundStateRoutine`'s at :81 have nothing to
 *     start (see below and "THREADS → TICKS").
 *   · `SetEventBus` (:394-397) — the event bus is not ported.
 *   · `String` (:990-993), `StringIndented` (:996-1008), and the
 *     `String`s of :1041, :1484, :1489, :1577, :1621, :1639, :1670,
 *     :1698, :1715, :1747, :1779, :1813 — display.
 *   · `SetLogger` (:1063-1066), `MarshalJSON` (:1079-1085) — cmt_ps.h.
 *   · `init` (:1511-1521) — JSON type registration.
 *   · `peerStatsRoutine` (:947-985) — p2p peer scoring
 *     (`MarkPeerAsGood`); its feed `cs.statsMsgQueue` (state.go:913,
 *     :931) is not in cmt_cs (cmt_cs.c:1571, :1593). Consequence: `RecordVote` /
 *     `RecordBlockPart` (cmt_ps.h) have no caller.
 *   · `ReactorMetrics` (:1011-1013) and the `Metrics` field (:49, :61,
 *     :329) — metrics; `NopMetrics` is what the reference installs, and
 *     an option that installs nothing has no shape to keep.
 *   · `RemovePeer` (:213-223) IS ported, as the no-op it is — see
 *     `cmt_conr_remove_peer`, which quotes it.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/reactor.go                1817 lines
 *     b7b4fdd346d99d32b713e82f8dcc95a0ac1b1c3a4b25d7d8c3283fc33dd33427
 *   consensus/reactor_test.go           1165 lines
 *     012e907d3f5e785b9fe2d50365e72831c6a85bc75d1cab0ad9e0c9c69b1790db
 *   consensus/state.go                  2653 lines
 *     f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *     (read for the five event sites and SwitchToConsensus's callees)
 *   consensus/types/peer_round_state.go   68 lines
 *     b5bd1eb78629c8f868ee69bae888285217387237497635da69c80d1c02308408
 *   consensus/msgs.go                    347 lines
 *     7acb318c8910da0c0f4d874b9bd6bb4fdc7212736919939fc933dd405b8e4ada
 *     (read for :232-234, the ValidateBasic gate)
 *   libs/events/events.go                247 lines
 *     400e4b8a781dee7926200ce306fb7fcbf3c7ff4bd87cd90a5fa7a30e0eb9b4e0
 *   p2p/peer.go                          443 lines
 *     35f3415786016bcbbc156d7999d9686a4f21b85682cfd6378192b135c7260758
 *   p2p/switch.go                        865 lines
 *     5c6a08f26131b80cd8bdcf7bc2c673cc2d173e1a460e08a791db400070aa6fdf
 *     (read for :274-296 Broadcast, :335-388 StopPeerForError and
 *      stopAndRemovePeer, :813-865 addPeer)
 *   p2p/base_reactor.go                   67 lines
 *     49d72906c1590f35b2f44982e078127c53bed7ec3f92176b844d015157cfadce
 *   p2p/key.go                           120 lines
 *     db7c7cda77c95229b29e17bcf32e6bc44049510e200ff0e0b842c0761c7ce0bf
 *   config/config.go                    1283 lines
 *     f0c2f601d49e1a56b36e8d557387e96ee53ecc3616ecb79749b0f71c0f218c21
 *     (read for :1017-1035, the two sleep durations)
 *   libs/service/service.go              241 lines
 *     f12c172b48f03e95c3a69c2d71174c56e563d9e09ce6cc8d014560f407166a27
 *     (read for :130-158 Start, :167-190 Stop, :224-226 IsRunning —
 *      genuinely unpinned when R3-A opened it, pinned by rev 16)
 * Governing records: umbrella rev 5
 * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8), D-4 rev 3
 * (atlas-dec-d5ddcba654eb48d861c03a0ecd170718 — the sleep durations are
 * NODE settings read from `cs->config`), D-20 rev 3
 * (atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19), PQ POLICY
 * (atlas-dec-652be084b95d02d253834906271e9fb0 — the reference's p2p
 * security is out of scope; p2p files read for message semantics only),
 * pin record rev 16 (atlas-dec-483ec17cbb352ef0ec2267ccd953339c; rev 11
 * when R3-A was written).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_CONR_H
#define SHARED_DNAC_CMT_CONR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"        /* CMT_OK / CMT_REJECT / CMT_FAULT         */
#include "cmt_time.h"          /* cmt_now_fn                              */
#include "cmt_pb.h"            /* cmt_pb_arena_t, cmt_pb_cons_message_t   */
#include "cmt_block.h"         /* cmt_block_id_t, cmt_commit_t, ext commit*/
#include "cmt_part_set.h"      /* cmt_part_t                              */
#include "cmt_state.h"         /* cmt_state_t                             */
#include "cmt_round_state.h"   /* cmt_round_state_t                       */
#include "cmt_msgs.h"          /* cmt_msg_t and the nine messages         */
#include "cmt_vote_set.h"      /* CMT_PEER_MAX                            */
#include "cmt_cs.h"            /* cmt_cs_t, the listener                  */
#include "cmt_ps.h"            /* cmt_ps_t, channels, send rows           */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ constants (reactor.go:24-34) ═════════════════════════════════════ */

/** How many peer slots the reactor keeps. Umbrella substitution 9: the
 *  reference's `p2p.ID`-keyed peer set becomes fixed slots of
 *  `NODUS_T3_MAX_WITNESSES` (128, nodus/include/nodus/nodus_types.h:156),
 *  which shared/dnac names through CMT_PEER_MAX (cmt_vote_set.h:186,
 *  static-asserted to the same 128; the direction rule of
 *  cmt_vote_set.h:174-175 forbids including nodus/ here). */
#define CMT_CONR_MAX_PEERS CMT_PEER_MAX

/** cometbft@709fd12b consensus/reactor.go:32-33 — the two "good peer"
 *  thresholds. Their only consumer is `peerStatsRoutine` (:970, :974),
 *  which is YOK; kept so the constants of :24-34 are all accounted for. */
#define CMT_CONR_BLOCKS_TO_CONTRIBUTE_TO_BECOME_GOOD_PEER 10000
#define CMT_CONR_VOTES_TO_CONTRIBUTE_TO_BECOME_GOOD_PEER  10000

/* ══ GetChannels (reactor.go:143-180) — a static descriptor table ═════ */

/** p2p/conn.ChannelDescriptor, the five fields :147-178 set. The host's
 *  transport applies them (queue capacities, priorities, the receive
 *  bound); this module only publishes them. */
typedef struct {
    uint8_t id;                     /* :148 ID                            */
    int     priority;               /* :149 Priority                      */
    int     send_queue_capacity;    /* :150 SendQueueCapacity             */
    int     recv_buffer_capacity;   /* :159 RecvBufferCapacity (0 = the  */
                                    /*      descriptor left it unset)     */
    int     recv_message_capacity;  /* :151 RecvMessageCapacity           */
} cmt_conr_channel_desc_t;

/** The number of channels `GetChannels` returns (:146-179). */
#define CMT_CONR_NUM_CHANNELS 4

/**
 * cometbft@709fd12b consensus/reactor.go:144-180 — `GetChannels()`.
 * The four descriptors in the reference's order: State (0x20, priority 6,
 * queue 100), Data (0x21, 10, 100, recv buffer 50*4096), Vote (0x22, 7,
 * 100, recv buffer 100*100), VoteSetBits (0x23, 1, 2, recv buffer 1024);
 * every RecvMessageCapacity is `maxMsgSize` (:30, 1 048 576).
 * @param out_n receives CMT_CONR_NUM_CHANNELS; may be NULL.
 * @return a static table, never NULL.
 */
const cmt_conr_channel_desc_t *cmt_conr_get_channels(size_t *out_n);

/* ══ the host ═════════════════════════════════════════════════════════ */

/** The reason `stop_peer_for_error` is given — one per reference site,
 *  so the host can log what the reference logs at each. */
typedef enum {
    /** reactor.go:237-241 — `MsgFromProto` failed (bytes that do not
     *  decode, or a field that will not convert). */
    CMT_CONR_STOP_DECODE          = 1,
    /** reactor.go:243-247 — `msg.ValidateBasic()` refused the message. */
    CMT_CONR_STOP_VALIDATE_BASIC  = 2,
    /** reactor.go:264-268 — `ValidateHeight` refused a NewRoundStep. */
    CMT_CONR_STOP_VALIDATE_HEIGHT = 3,
    /** reactor.go:283-287 — `SetPeerMaj23` refused the peer's claim. */
    CMT_CONR_STOP_PEER_MAJ23      = 4
} cmt_conr_stop_reason_t;

/**
 * Everything `consensus/reactor.go` reaches outside its package that is
 * not the state machine: the transport (p2p) and the block store.
 *
 * ⚠ EVERY POINTER IS REQUIRED; a NULL row reached at run time is
 * CMT_FAULT. A callback MUST NOT re-enter this module or `cs`.
 */
typedef struct {
    /* ── p2p.Peer (p2p/peer.go:22-48) ──────────────────────────────── */

    /** p2p/peer.go:258-262 — `Send`. Non-blocking here: DEVIATION
     *  R3-A-1 (file header). The reactor has ALREADY marshalled the
     *  message (peer.go:277-280) — the host sees bytes. */
    cmt_ps_send_fn send;

    /** p2p/peer.go:264-268 — `TrySend`. Returns false at once when the
     *  queue is full, as the reference does. */
    cmt_ps_send_fn try_send;

    /* ── p2p.Switch (p2p/switch.go) ────────────────────────────────── */

    /** p2p/switch.go:335-358 — `StopPeerForError(peer, reason)`, reached
     *  from reactor.go:239, :245, :266, :285. The host disconnects the
     *  peer (:341 `stopAndRemovePeer`, whose :373-375 calls every
     *  reactor's `RemovePeer` — the host therefore calls
     *  `cmt_conr_remove_peer` for this slot, before or after returning);
     *  reconnection (:343-357 `reconnectToPeer`) is the host's peer
     *  manager's, as it is the switch's in the reference. */
    void (*stop_peer_for_error)(void *ctx, int peer_idx, int reason_code);

    /* ── sm.BlockStore (state/services.go) ─────────────────────────── */

    /** reactor.go:575, :654, :742, :925 — `blockStore.Base()`. The same
     *  shape as cmt_cs.h's `bs_height` row (rc + out), so one host
     *  function can serve both tables. */
    int (*bs_base)(void *ctx, int64_t *out);

    /** reactor.go:584, :654, :924 — `blockStore.Height()`. The same row as
     *  cmt_cs.h:422's; the host passes the same function. */
    int (*bs_height)(void *ctx, int64_t *out);

    /** reactor.go:581-587 and :651-663 — `blockStore.LoadBlockMeta(h)`,
     *  of which the ported code reads ONLY `blockMeta.BlockID` (:587,
     *  :657) and of that only the PartSetHeader — so the row hands back
     *  the BlockID. (cmt_cs.h:438-444's `bs_load_block_meta` hands back
     *  the HEADER for state.go:1131's `AppHash` read; two projections of
     *  one BlockMeta, each named for what its reader takes.)
     *  @param out_found false is the reference's nil (:582, :652). */
    int (*bs_load_block_meta_block_id)(void *ctx, int64_t height,
                                       cmt_block_id_t *out, bool *out_found);

    /** reactor.go:664 — `blockStore.LoadBlockPart(height, index)`.
     *  @param out the host fills it, including pointing `bytes` at
     *         storage the host owns; that storage must stay valid until
     *         the next call of this same row (it is marshalled and sent
     *         before the row is called again).
     *  @param out_found false is the reference's nil (:665). */
    int (*bs_load_block_part)(void *ctx, int64_t height, int index,
                              cmt_part_t *out, bool *out_found);

    /** reactor.go:756 — `blockStore.LoadBlockCommit(height)`. The same
     *  row and storage contract as cmt_cs.h:421-427's. */
    int (*bs_load_block_commit)(void *ctx, int64_t height,
                                cmt_commit_t *out, bool *out_found);

    /** reactor.go:754 — `blockStore.LoadBlockExtendedCommit(height)`.
     *  The same row and storage contract as cmt_cs.h:432-436's. */
    int (*bs_load_block_extended_commit)(void *ctx, int64_t height,
                                         cmt_extended_commit_t *out,
                                         bool *out_found);

    /* ── the clock ─────────────────────────────────────────────────── */

    /** reactor.go:504 (`time.Since(rs.StartTime)`) and :1379
     *  (`cmttime.Now()`), plus the tick's instant (file header). THE SAME
     *  CALLBACK as `cs->host.now`; the host passes it through. */
    cmt_now_fn now;
} cmt_conr_host_t;

/* ══ one peer slot (C only — the switch's peer set, per index) ════════ */

/** The three per-peer routines, in the reference's start order
 *  (reactor.go:201-203). Indexes `not_before_ns`. */
typedef enum {
    CMT_CONR_ROUTINE_DATA  = 0,   /* :539 gossipDataRoutine  */
    CMT_CONR_ROUTINE_VOTES = 1,   /* :698 gossipVotesRoutine */
    CMT_CONR_ROUTINE_MAJ23 = 2,   /* :848 queryMaj23Routine  */
    CMT_CONR_NUM_ROUTINES  = 3
} cmt_conr_routine_t;

typedef struct {
    /** In the switch's peer set: `InitPeer` ran and `RemovePeer` did not
     *  (switch.go:846 / :381). `Broadcast` reaches it. */
    bool      in_set;
    /** `AddPeer` ran (:191-210): the three routines are live. */
    bool      started;
    cmt_ps_t  ps;                       /* :184 NewPeerState, peer.Set   */
    /** The `time.Sleep` deadlines, one per routine, in unix nanoseconds
     *  of the host clock; meaningful only while `asleep[r]`. */
    int64_t   not_before_ns[CMT_CONR_NUM_ROUTINES];
    bool      asleep[CMT_CONR_NUM_ROUTINES];
    /** reactor.go:702 — gossipVotesRoutine's `sleeping` log throttle.
     *  Carried so the loop reads like the reference; the logs it
     *  throttles are not ported, so it changes nothing observable. */
    int       sleeping;
    /** Where `queryMaj23Routine` resumes after a mid-iteration sleep
     *  (:872, :892, :913, :936 each sleep and then CONTINUE to the next
     *  block; only :941 ends the iteration): 0..3 = the block of
     *  :857/:878/:898/:922 to run next, 4 = the :941 sleep. */
    int       maj23_pc;
} cmt_conr_peer_slot_t;

/* ══ the reactor (reactor.go:39-50) ═══════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:39-50 — `type Reactor struct`.
 * `BaseReactor` (:40) is the `running` flag; `mtx` (:44) is dropped;
 * `eventBus` (:46) is not ported; `rs` (:47) is read live; `Metrics`
 * (:49) is YOK.
 *
 * Small enough for the stack — every large thing hangs off a pointer
 * `cmt_conr_init` allocates: the CMT_CONR_MAX_PEERS slots (~190 KB), the
 * 1 MiB send buffer, the two ~10 KB message scratches and the
 * extended-commit signature scratch (CMT_PEER_MAX × ~9.4 KB).
 */
typedef struct {
    cmt_cs_t                  *cs;              /* :42 conS               */
    bool                       wait_sync;       /* :45 waitSync           */
    bool                       running;         /* BaseService (:40)      */
    cmt_conr_host_t            host;
    void                      *host_ctx;
    cmt_pb_arena_t            *recv_arena;      /* see the file header    */
    cmt_conr_peer_slot_t      *peers;           /* CMT_CONR_MAX_PEERS     */

    /* C-only scratch, heap — see cmt_ps_scratch_t and the note above. */
    cmt_ps_scratch_t           scratch;         /* send side              */
    cmt_pb_cons_message_t     *recv_pb;         /* :236 MsgFromProto's in */
    cmt_msg_t                 *recv_msg;        /* :236 MsgFromProto's out*/
    cmt_extended_commit_sig_t *ecsigs;          /* :760 WrappedExtendedCommit */
    size_t                     ecsigs_cap;
} cmt_conr_t;

/* ══ construction (reactor.go:54-70) ══════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:56-70 — `NewReactor()`.
 * `rs: consensusState.GetRoundState()` (:60) has no counterpart (live
 * reads); `NopMetrics` (:61) and the options loop (:65-67) are YOK.
 *
 * @param cs BORROWED; outlives the reactor. Its `host.now` is the clock
 *        this reactor's `host.now` must also be.
 * @param wait_sync the reference's `waitSync` (:56, :59): true when the
 *        node is block-syncing and `SwitchToConsensus` will start the
 *        state machine later.
 * @param recv_arena BORROWED; the lifetime rule is in the file header.
 * @return CMT_OK; CMT_FAULT on NULL or allocation failure.
 */
int cmt_conr_init(cmt_conr_t *conR, cmt_cs_t *cs, bool wait_sync,
                  const cmt_conr_host_t *host, void *host_ctx,
                  cmt_pb_arena_t *recv_arena);

/** C only — releases everything `cmt_conr_init` allocated. Does NOT stop
 *  anything; call `cmt_conr_stop` first if it was started. NULL is a
 *  no-op. */
void cmt_conr_free(cmt_conr_t *conR);

/* ══ lifecycle (reactor.go:72-141) — C-only entry points ══════════════ */

/**
 * C only — what `OnStart` (reactor.go:74-91) does, reached through
 * `BaseService.Start` (service.go:130-158): the `running` flag first
 * (:131), then `subscribeToBroadcastEvents` (:80 → :411-433, which is
 * `cmt_cs_add_listener`), then — unless `wait_sync` — `conR.conS.Start()`
 * (:83-88, `cmt_cs_start`). `peerStatsRoutine` (:78) is YOK and
 * `updateRoundStateRoutine` (:81) has nothing to start.
 * @return CMT_OK; the reference reverts the flag and returns the error
 *         of :84-87 — so does this, with `cmt_cs_start`'s code (:147).
 *         CMT_FAULT on NULL.
 */
int cmt_conr_start(cmt_conr_t *conR);

/**
 * C only — what `OnStop` (reactor.go:95-103) does, reached through
 * `BaseService.Stop` (service.go:167-190): the flag first (:168), then
 * `unsubscribeFromBroadcastEvents` (:96 → :435-438,
 * `cmt_cs_remove_listener`) and `conR.conS.Stop()` (:97, `cmt_cs_stop`;
 * the reference only logs its error). `conR.conS.Wait()` (:100-102)
 * waits for the receive goroutine, which does not exist here.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_conr_stop(cmt_conr_t *conR);

/**
 * cometbft@709fd12b consensus/reactor.go:107-141 — `SwitchToConsensus()`.
 * "It resets the state, turns off block_sync, and starts the consensus
 * state-machine." :112-113's lock is dropped; :115-117 →
 * `cmt_cs_reconstruct_last_commit`; :121 → `cmt_cs_update_to_state`;
 * :124-126 → `wait_sync = false`; :128-130 → `cs->do_wal_catchup =
 * false`; :131 → `cmt_cs_start`; its failure :132-140 is a panic —
 * NODE-LOCAL → CMT_FAULT.
 *
 * @param state the reference passes `sm.State` by value; `cmt_cs_update_
 *        to_state` refuses `&cs->state` itself (cmt_cs.c, "called with
 *        cs->state itself"), so a caller holding the state machine's own
 *        state passes a copy (`cmt_cs_get_state`), exactly as
 *        reactor_test.go:88 does with `GetState()`.
 * @return CMT_OK; CMT_FAULT at :116's or :121's panics, at :132-140 —
 *         ANY error from `cmt_cs_start`, the double-signing refusal of
 *         cmt_cs.h:937-939 included, because the reference panics on
 *         every error there — or on NULL.
 */
int cmt_conr_switch_to_consensus(cmt_conr_t *conR, const cmt_state_t *state,
                                 bool skip_wal);

/** cometbft@709fd12b consensus/reactor.go:400-404 — `WaitSync()`. */
bool cmt_conr_wait_sync(const cmt_conr_t *conR);

/* ══ peers (reactor.go:182-223) ═══════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:183-187 — `InitPeer()`. Creates
 * the PeerState (:184 `NewPeerState`) and attaches it to the peer (:185
 * `peer.Set(types.PeerStateKey, …)`): here, fills slot `peer_idx` and
 * puts it in the peer set (switch.go:846).
 * @param id the peer's 32-byte witness id (substitution 9).
 * @return CMT_OK; CMT_REJECT for an index outside [0, CMT_CONR_MAX_PEERS)
 *         or a slot already in the set; CMT_FAULT on NULL.
 */
int cmt_conr_init_peer(cmt_conr_t *conR, int peer_idx,
                       const uint8_t id[CMT_PB_PEER_ID_MAX]);

/**
 * cometbft@709fd12b consensus/reactor.go:191-210 — `AddPeer()`. A no-op
 * when not running (:192-194); starts the three routines (:201-203 —
 * here, marks the slot `started` so `cmt_conr_tick` runs them) and,
 * unless `wait_sync`, sends our NewRoundStep to the peer (:207-209).
 * @return CMT_OK; CMT_REJECT for an index outside the table; CMT_FAULT
 *         where the reference panics at :198 (no PeerState — InitPeer
 *         was skipped; NODE-LOCAL), or on NULL.
 */
int cmt_conr_add_peer(cmt_conr_t *conR, int peer_idx);

/**
 * cometbft@709fd12b consensus/reactor.go:213-223 — `RemovePeer()`, which
 * "is a noop":
 *
 *     if !conR.IsRunning() { return }
 *     // TODO
 *     // ps, ok := peer.Get(PeerStateKey).(*PeerState)
 *     // if !ok {
 *     // 	panic(fmt.Sprintf("Peer %v has no state", peer))
 *     // }
 *     // ps.Disconnect()
 *
 * PLUS the C-only consequence of the host's disconnect: the switch's
 * `sw.peers.Remove(peer)` (switch.go:381) takes the peer out of the set,
 * and `peer.IsRunning()` turns false for the three goroutines
 * (:545, :707, :852). Here that is one act: the slot leaves the set,
 * stops, and is cleared. Called by the host whenever a connection closes
 * (the switch calls it from `stopAndRemovePeer` :373-375, for an error
 * or otherwise). NOT gated on `running`: the reference's gate at :214
 * protects a body that does nothing, while the slot must be freed
 * regardless — stated deviation, see the wave report (R3-A-3).
 * @return CMT_OK (including for a slot not in the set — the switch's
 *         Remove of an unknown peer is a logged no-op :381-386);
 *         CMT_REJECT for an index outside the table; CMT_FAULT on NULL.
 */
int cmt_conr_remove_peer(cmt_conr_t *conR, int peer_idx);

/* ══ receive (reactor.go:225-391) ═════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:231-391 — `Receive()`, from the
 * BYTES of one envelope. "NOTE: We process these messages even when
 * we're block_syncing. Messages affect either a peer state or the
 * consensus state."
 *
 * In order: not running → return (:232-235); decode
 * (`cmt_pb_cons_message_unmarshal` into `recv_arena`, then
 * `cmt_msg_from_proto` — :236, MsgFromProto) → on failure
 * `stop_peer_for_error(DECODE)` (:239); `cmt_msg_validate_basic` (:243)
 * → on failure `stop_peer_for_error(VALIDATE_BASIC)` (:245); the peer's
 * state (:252-255 — a slot not in the set is the panic, CMT_FAULT); then
 * the channel switch (:257-390) with the message-type switch inside each,
 * exactly as written, including "Ignoring message received during sync"
 * for the Data, Vote and VoteSetBits channels while `wait_sync` (:317,
 * :336, :358) and the "Unknown message type" log-and-drop defaults
 * (:313, :332, :354, :385, :389 — "don't punish (leave room for soft
 * upgrades)").
 *
 * @param channel_id one of the four CMT_CONR_*_CHANNEL ids.
 * @return CMT_OK — the envelope was consumed as the reference's Receive
 *           consumes it, INCLUDING the four sites where the reference
 *           disconnects the peer (the disconnect is reported through the
 *           host row, as the reference reports it through the Switch,
 *           and Receive returns nothing);
 *         CMT_REJECT — DEVIATION R3-A-2: the message was valid but the
 *           state machine's peer queue is FULL (`cmt_cs_add_vote` /
 *           `cmt_cs_set_proposal_input` /
 *           `cmt_cs_add_proposal_block_part_input` returned CMT_REJECT,
 *           cmt_cs.h:74-81). The reference's reactor goroutine BLOCKS at
 *           :324, :330 and :350 until the queue drains; a single thread
 *           cannot, so the message is NOT queued, the peer state was
 *           already updated as at :323/:328/:346-348, no peer is
 *           disconnected, and the host decides (backpressure, or drop —
 *           R2's open question, cmt_cs.h:80-81). The reference's own
 *           blocking is a third behaviour neither answer reproduces.
 *         CMT_FAULT — NULL, a slot never `InitPeer`'d (:255), a fault
 *           from the state machine or a host row, or a marshal failure
 *           of our own VoteSetBits reply (:299-311).
 */
int cmt_conr_receive(cmt_conr_t *conR, int peer_idx, uint8_t channel_id,
                     const uint8_t *bytes, size_t len);

/* ══ the tick (C only — the three routines, see the file header) ══════ */

/**
 * C only. For every slot `AddPeer` started, in index order, run
 * `gossipDataRoutine` (:539-644), `gossipVotesRoutine` (:698-786) and
 * `queryMaj23Routine` (:848-945) — in that order (:201-203) — each as far
 * as the reference would go before a `time.Sleep` or a false from a send,
 * skipping a routine whose `not_before` has not arrived. Reads the clock
 * ONCE (the host's `now`).
 *
 * @param out_next_deadline_ns the earliest pending `not_before` in unix
 *        nanoseconds, INT64_MAX when nothing is pending; may be NULL.
 * @return CMT_OK; CMT_FAULT on NULL, a host-row fault, a state-machine
 *         fault, or one of the NODE-LOCAL panics of the file header.
 *         Never CMT_REJECT: a refused send is "not sent", not an error.
 */
int cmt_conr_tick(cmt_conr_t *conR, int64_t *out_next_deadline_ns);

/**
 * cometbft@709fd12b consensus/reactor.go:533-537 — `getRoundState()`, the
 * snapshot `updateRoundStateRoutine` (:519-531) refreshes every 100 µs.
 * Single-threaded, this reads `cmt_cs_get_round_state` LIVE: exact where
 * the reference's is at most 100 µs stale.
 */
int cmt_conr_get_round_state(const cmt_conr_t *conR, cmt_round_state_t *out);

/* ══ the ValidateBasic gate (msgs.go:232-234; reactor.go:1536-1810) ═══ */

/**
 * cometbft@709fd12b consensus/msgs.go:232-234 — the `pb.ValidateBasic()`
 * every decoded message passes in `MsgFromProto`, dispatched over the
 * nine `Message` implementations (reactor.go:1507-1509) to the nine
 * methods below. `kind` NONE or unknown is the `default` of
 * msgs.go:228-229 ("message not recognized").
 * @return CMT_OK, CMT_REJECT (the reference's error), CMT_FAULT on NULL.
 */
int cmt_msg_validate_basic(const cmt_msg_t *msg);

/** cometbft@709fd12b consensus/reactor.go:1536-1557 —
 *  `NewRoundStepMessage.ValidateBasic()`. Negative Height, negative
 *  Round, an invalid Step (`cmt_round_step_is_valid`) and a
 *  LastCommitRound below -1 refuse; "NOTE: SecondsSinceStartTime may be
 *  negative". */
int cmt_new_round_step_msg_validate_basic(const cmt_new_round_step_msg_t *m);

/** cometbft@709fd12b consensus/reactor.go:1560-1574 —
 *  `NewRoundStepMessage.ValidateHeight(initialHeight)`: Height below the
 *  initial height; LastCommitRound not -1 AT the initial height; a
 *  negative LastCommitRound ABOVE it. */
int cmt_new_round_step_msg_validate_height(const cmt_new_round_step_msg_t *m,
                                           int64_t initial_height);

/** cometbft@709fd12b consensus/reactor.go:1596-1618 —
 *  `NewValidBlockMessage.ValidateBasic()`: negative Height or Round, a
 *  bad PartSetHeader (`cmt_psh_validate_basic`), an empty bit array
 *  (nil counts), a bit array whose Size differs from the header's Total,
 *  or one wider than MaxBlockPartsCount (CMT_MAX_BLOCK_PARTS_COUNT). */
int cmt_new_valid_block_msg_validate_basic(const cmt_new_valid_block_msg_t *m);

/** cometbft@709fd12b consensus/reactor.go:1634-1636 —
 *  `ProposalMessage.ValidateBasic()`: `cmt_proposal_validate_basic`. */
int cmt_proposal_msg_validate_basic(const cmt_proposal_msg_t *m);

/** cometbft@709fd12b consensus/reactor.go:1653-1667 —
 *  `ProposalPOLMessage.ValidateBasic()`: negative Height or
 *  ProposalPOLRound, an empty bit array, one wider than MaxVotesCount
 *  (CMT_MAX_VOTES_COUNT). */
int cmt_proposal_pol_msg_validate_basic(const cmt_proposal_pol_msg_t *m);

/** cometbft@709fd12b consensus/reactor.go:1684-1695 —
 *  `BlockPartMessage.ValidateBasic()`: negative Height or Round, then
 *  `cmt_part_validate_basic`. */
int cmt_block_part_msg_validate_basic(const cmt_block_part_msg_t *m);

/** cometbft@709fd12b consensus/reactor.go:1710-1712 —
 *  `VoteMessage.ValidateBasic()`: `cmt_vote_validate_basic`. A message
 *  with NO vote (`has_vote` false — msgs.go:187 can produce one from a
 *  wire message whose field 1 is absent, cmt_msgs.h:157-163) is where the
 *  reference dereferences nil at types/vote.go:278 and panics;
 *  PEER-REACHABLE → CMT_REJECT. */
int cmt_vote_msg_validate_basic(const cmt_vote_msg_t *m);

/** cometbft@709fd12b consensus/reactor.go:1730-1744 —
 *  `HasVoteMessage.ValidateBasic()`: negative Height, Round or Index,
 *  or a Type that is not a vote type. */
int cmt_has_vote_msg_validate_basic(const cmt_has_vote_msg_t *m);

/** cometbft@709fd12b consensus/reactor.go:1762-1776 —
 *  `VoteSetMaj23Message.ValidateBasic()`: negative Height or Round, a
 *  Type that is not a vote type, a BlockID that fails
 *  `cmt_block_id_validate_basic`. */
int cmt_vote_set_maj23_msg_validate_basic(const cmt_vote_set_maj23_msg_t *m);

/** cometbft@709fd12b consensus/reactor.go:1795-1810 —
 *  `VoteSetBitsMessage.ValidateBasic()`: negative Height, a Type that is
 *  not a vote type, a bad BlockID, a bit array wider than MaxVotesCount.
 *  "NOTE: Votes.Size() can be zero if the node does not have any" — and
 *  Round is NOT checked, exactly as the reference does not. */
int cmt_vote_set_bits_msg_validate_basic(const cmt_vote_set_bits_msg_t *m);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_CONR_H */
