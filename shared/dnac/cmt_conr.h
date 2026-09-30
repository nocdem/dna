/**
 * @file shared/dnac/cmt_conr.h
 * @brief cometbft @v0.38.26 `consensus/reactor.go` ported to C — the
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
 * PeerState half of reactor.go (:1026-1491) is cmt_ps.h.
 *
 * ── WHAT THE REACTOR DOES ──────────────────────────────────────────────
 * Three things, all of them per peer and none of them consensus:
 *   1. It BROADCASTS what the state machine just did — a new round step,
 *      a valid block, a vote it holds — when the state machine's event
 *      switch fires (:420-442, :449-506).
 *   2. It GOSSIPS to each peer what that peer still lacks, judged from
 *      the peer's own announcements: block parts, the proposal, the POL,
 *      votes of the current height, the last commit, and — for a peer
 *      more than one height behind — a stored commit (:548-954).
 *   3. It RECEIVES a peer's messages, validates them, updates its picture
 *      of that peer, and hands proposals, block parts and votes to the
 *      state machine's peer queue (:231-400).
 * Nothing here decides a vote or a block. Two nodes with different gossip
 * choices still decide the same blocks.
 *
 * ── THREADS → TICKS (the one structural substitution) ──────────────────
 * The reference runs, per peer, three goroutines forever
 * (`gossipDataRoutine` :548, `gossipVotesRoutine` :707,
 * `queryMaj23Routine` :857), one round-state snapshot goroutine
 * (`updateRoundStateRoutine` :528) and receives on the p2p thread. Here
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
 *       Sleep sites maps to such a record: :594, :609, :650, :664, :669,
 *       :677, :699, :704, :792 (PeerGossipSleepDuration) and :881, :901,
 *       :922, :945, :950 (PeerQueryMaj23SleepDuration), the two config
 *       fields of D-4 (cmt_config.h:98-99; never a literal);
 *     · a `false` from `send`/`try_send` does exactly what the reference
 *       does with false at that site (e.g. :569-579: the part is NOT
 *       marked as sent; :1169: the vote is not marked) and then ENDS that
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
 *   bare `continue`s at :767 and :772 (a stored commit the store cannot
 *   load — the reference busy-loops until it can) end the pass, because
 *   within one tick nothing can change the answer; and :589-600 with a
 *   BlockMeta whose PartSetHeader.Total is 0 (`bits.NewBitArray(0)` is
 *   nil, so `ProposalBlockParts` stays nil and the reference loops
 *   forever) ends the pass. Each such site says so.
 *
 *   `updateRoundStateRoutine` (:528-540) snapshots the round state every
 *   100 µs into `conR.rs` and `getRoundState` (:542-546) reads the
 *   snapshot. Single-threaded, there is nothing to snapshot:
 *   `cmt_conr_get_round_state` reads `cmt_cs_get_round_state` live at
 *   every use, which is the reference's value at most 100 µs fresher.
 *
 *   `conR.mtx` (:44), `conR.conS.mtx` (:112, :261, :276, :352, :374, :758)
 *   and every `ps.mtx` are dropped; each site carries a one-line note.
 *
 *   `IsRunning()` (:192, :214, :232, :532, :554, :716, :861, :958) is the
 *   `running` flag, set by `cmt_conr_start` BEFORE its body and cleared
 *   by `cmt_conr_stop` BEFORE its body, which is libs/service/service.go
 *   `BaseService.Start` (:131 sets `started`, :144 calls OnStart, :147
 *   reverts on error) and `Stop` (:168 sets `stopped`, :181 calls OnStop).
 *   The `stopped` half of that pair is a SECOND flag here, and it is a
 *   LATCH: `cmt_conr_stop` sets it and nothing clears it, so
 *   `cmt_conr_start` after a stop returns CMT_REJECT, which is
 *   service.go:132-138's ErrAlreadyStopped. The reference's `Reset`
 *   (:200-215) is the only way back and is not ported — `OnReset` panics
 *   for this service (:217-220). Without the latch a stop→start kept
 *   every stale PeerState and re-entered `cmt_cs_start` (deviation
 *   register R3-AUD-20). The other three answers of the pair are ported
 *   too: Start while running is ErrAlreadyStarted (:153-158), Stop before
 *   any Start is ErrNotStarted and does NOT take the latch (:169-175),
 *   Stop twice is ErrAlreadyStopped (:185-190) — each CMT_REJECT, nothing
 *   changed (register R3-AUD-23).
 *   `peer.IsRunning()` (:554, :716, :861) is the host's per-peer
 *   "connected" state, which this module learns through
 *   `cmt_conr_remove_peer`: the host calls it when the connection closes,
 *   the slot is freed and its routines stop — the reference's `RemovePeer`
 *   (:213-223) is a no-op precisely because its goroutines watch
 *   `peer.IsRunning()` themselves.
 *
 *   `Broadcast` (p2p/switch.go:275-297): one goroutine per peer of
 *   `sw.peers.List()`, order unspecified; the success channel it returns
 *   is discarded by all three reactor callers (:451, :466, :480). Here:
 *   every slot in the switch's peer SET — added at switch.go:847 after
 *   `InitPeer` (:831) and before `AddPeer` (:860), removed at :382 — in
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
 * ── THE RECEIVE ARENA — PACKAGE C2e, CLOSING REGISTER R3-A-5 ────────────
 * `cmt_conr_receive` takes a peer's BYTES and decodes them with
 * `cmt_pb_cons_message_unmarshal` into `recv_arena` (cmt_pb.h:62-66: a
 * decoded part's payload and a vote's extension are COPIED there and the
 * message points at them). THE POLICY (operator-approved 2026-09-17,
 * replacing both the original wiring note this section used to carry and
 * the tree's later deviation to a separate, never-reset host arena —
 * register R3-W3-C2b-5): the mempool reactor's own pattern.
 * `cmt_conr_receive` resets `recv_arena->used = 0` at the TOP of every
 * call, before the decode (`cmt_memr_receive`, cmt_memr.c:392 does the
 * same for its own arena). After the reset the arena holds ONE decoded
 * message and NOTHING may keep a pointer into it past this function's
 * return — every consumer that used to rely on the arena outliving the
 * call now OWNS a copy of what it keeps:
 *   · `cs_q_push` (cmt_cs.c) copies the ONE variable-length payload a
 *     queued message can carry — a BlockPart's `part.bytes` or a Vote's
 *     `extension` — into the SAME allocation as the queue element
 *     (`mem_tx_new`'s idiom, cmt_mem.c:240-262), freed with it.
 *   · `cmt_part_set_add_part` (cmt_part_set.c), when the part set was
 *     built with a bound payload store (`cmt_part_set_bind_payload_store`,
 *     called by `cs_new_part_set_from_header`), copies the part's bytes
 *     into that store and stores the part pointing THERE instead of into
 *     the (now-recycled) arena.
 *   · `cmt_cs_try_add_vote` (cmt_cs.c) copies a vote's extension into
 *     `cs->ext_arena` before handing the vote to `cmt_hvs_add_vote` /
 *     `cmt_vote_set_add_vote`, which only ever share the extension
 *     DESCRIPTOR (cmt_cs.h OWNERSHIP (2)).
 *
 * THE BOUND: `NODUS_CMT_NET_RECV_ARENA_BYTES` (nodus_witness_cmt_net.h) is
 * exactly `CMT_CONR_MAX_MSG_SIZE` (1 048 576, tied by a `_Static_assert`),
 * the SAME bound the tier-3 wire decoder already enforces on every
 * consensus-channel envelope before it reaches this function
 * (`nodus_tier3.c`'s `dec_w_cmt_args`, `NODUS_T3_CMT_CONS_M_MAX`). Every
 * `r_copy_arena` call reachable from `cmt_pb_cons_message_unmarshal`
 * (cmt_pb.c: the BlockPart's `bytes` field at `part_merge`, the Vote's
 * `extension` field at `vote_merge`) copies a SUB-SLICE of the message it
 * is decoding, so the total bytes one decode can copy into the arena can
 * never exceed the message's own wire length — which the channel already
 * bounded to `CMT_CONR_MAX_MSG_SIZE`. AN ARENA OF THAT SIZE CAN THEREFORE
 * NEVER EXHAUST FOR A MESSAGE THE CHANNEL ADMITTED. (Two other
 * `r_copy_arena` sites in the same file — `data_merge`'s `Data.Txs[]` and
 * `ecs_merge`'s `ExtendedCommitSig.extension` — decode a whole Block and
 * an ExtendedCommit respectively, neither of which is one of the nine
 * reactor message kinds `cons_message_merge` can produce; they are not
 * reachable from this arena at all.)
 *
 * DUPLICATES cost one decode each and are dropped by `AddPart`'s
 * "already held" check (part_set.go:311-313, cmt_part_set.c) — nothing
 * accumulates across the several peers that gossip the same part; no
 * pre-decode dedup is added (the reference has none).
 *
 * ⚠ WHAT USED TO HAPPEN IF IT WAS NEVER RESET — register R3-A-5
 * (verifier A, 2026-09-14; measured in production at
 * `/tmp/stagef-20260917T024138Z`, seven nodes: the chain stopped at
 * height 347 after ≈ 1 hour): the arena was ONE for all peers, the decode
 * consumed it BEFORE ValidateBasic, before the `wait_sync` drop and
 * before any height check, and `r_copy_arena` answered exhaustion with
 * the same CMT_REJECT as malformed bytes, so `cmt_conr_receive` stopped
 * WHICHEVER peer's message hit the wall as a DECODE error — one block's
 * worth of parts (≈ 174 KB, one part gossiped from ≈ 5 peers) against a
 * 64 MiB runway exhausted it in ≈ 380 heights, and every honest peer that
 * gossiped after that point was disconnected as if it had sent garbage.
 * The reference has no analogue (Go allocates per message). This package
 * closes that: the arena is per-message and the bound above proves
 * exhaustion unreachable.
 *
 * WHY THE DECODE-ERROR RETURN AT `cmt_conr_receive`'s "Error decoding
 * message" branch DOES NOT NEED A SEPARATE CODE FOR "arena exhausted":
 * that outcome is now UNREACHABLE for a message the channel admitted (the
 * bound proof above), so the branch it used to share with arena
 * exhaustion is once again exactly what its name and its reference line
 * (:237-241) say it is — a malformed or field-oversized message. A
 * distinct return code would name an outcome that cannot occur; adding
 * one would be dead code the moment it was written.
 *
 * ── THE ValidateBasic GATE (msgs.go:232-234) ───────────────────────────
 * The reference's `Receive` calls `MsgFromProto` (:236), whose last act
 * is `pb.ValidateBasic()` (msgs.go:232-234), and then `msg.ValidateBasic()`
 * again (:243). R2's `cmt_msg_from_proto` stops before that line
 * (cmt_msgs.h:28-35); `cmt_msg_validate_basic` IS that line, called by
 * `cmt_conr_receive` right after the decode, and its nine per-message
 * bodies are :1545, :1605, :1646, :1671, :1705, :1731, :1751, :1783 and
 * :1816. They LIVE IN cmt_msgs.{h,c}, not here, because the WAL replay
 * path (cmt_cs.c, replay.go:147 → wal.go:410 → msgs.go:232-234) runs the
 * same gate and the consensus core must not depend on the reactor
 * (atlas-dec-b02c8de1f52854b20dbfd64f6c987b34, item 4).
 * `NewRoundStepMessage.ValidateHeight` (:1569) is the tenth and stays
 * here, run by `Receive` at :264 against the chain's initial height.
 *
 * ── THE PANIC RULE (umbrella rev 4) ────────────────────────────────────
 *   · :255 "Peer %v has no state" — a Receive for a slot `InitPeer` never
 *     filled. NODE-LOCAL → CMT_FAULT: the host wired a connection past
 *     InitPeer; the reference's own test (reactor_test.go:278-305)
 *     expects the panic.
 *   · :198 "peer %v has no state" in AddPeer — same class, CMT_FAULT.
 *   · :297 and :386 "Bad VoteSetBitsMessage field Type. Forgot to add a
 *     check in ValidateBasic?" — unreachable once the gate has run
 *     (:1790, :1820 refuse the type); NODE-LOCAL → CMT_FAULT.
 *   · :566 `part.ToProto()` failing on a part of OUR OWN part set whose
 *     bit says it is held — NODE-LOCAL → CMT_FAULT.
 *   · :132-140 `conR.conS.Start()` failing inside SwitchToConsensus —
 *     NODE-LOCAL → CMT_FAULT (the reference dumps both objects and dies).
 *   Go `error` returns at :237-241, :243-247, :264-268 and :284-287 are
 *   the reference's four `StopPeerForError` sites: the host row is
 *   called with a reason code and Receive returns as the reference does.
 *   v0.38.26 adds a fifth, the oversized-proposal gate
 *   (cometbft@v0.38.26 consensus/reactor.go:326-330,
 *   CMT_CONR_STOP_PROPOSAL_TOO_MANY_PARTS).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * TWO CLOCKS, split by what the reference's read is (decision
 * docs/plans/decisions/2026-09-30-monotonic-waits.md):
 *   · the WALL clock is the host's `now` row, THE SAME CALLBACK as
 *     `cs->host.now` (D-20 rev 3; the host passes one function into both
 *     tables), read at exactly the reference's two stamp sites: :513
 *     (`time.Since(rs.StartTime)` in `makeRoundStepMessage` — StartTime
 *     is a `cmttime.Now()` with no monotonic part, so this is a wall
 *     difference) and :1388 (`cmttime.Now()` in
 *     `ApplyNewRoundStepMessage`, read in `Receive` and handed to cmt_ps
 *     as a value);
 *   · the WAIT clock is the host's `mono` row (CLOCK_MONOTONIC), read —
 *     C only, stated — once per `cmt_conr_tick`, because the fourteen
 *     `time.Sleep` sites are deadlines here and a deadline needs an
 *     instant; a Go `time.Sleep` is a monotonic wait.
 * No other clock read.
 * THE ONLY RANDOMNESS is `PickRandom` (:562, :658, :1197) through
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
 *   · `SetEventBus` (:403-406) — the event bus is not ported.
 *   · `String` (:999-1002), `StringIndented` (:1005-1017), and the
 *     `String`s of :1050, :1493, :1498, :1586, :1633, :1657, :1691,
 *     :1719, :1736, :1768, :1800, :1837 — display.
 *   · `SetLogger` (:1072-1075), `MarshalJSON` (:1088-1094) — cmt_ps.h.
 *   · `init` (:1520-1530) — JSON type registration.
 *   · `peerStatsRoutine` (:956-994) — p2p peer scoring
 *     (`MarkPeerAsGood`); its feed `cs.statsMsgQueue` (state.go:913,
 *     :931 — 709fd12b; at v0.38.26: one send after the switch, :944-946) is not in cmt_cs (cmt_cs.c:1571, :1593). Consequence: `RecordVote` /
 *     `RecordBlockPart` (cmt_ps.h) have no caller.
 *   · `ReactorMetrics` (:1020-1022) and the `Metrics` field (:49, :61,
 *     :338) — metrics; `NopMetrics` is what the reference installs, and
 *     an option that installs nothing has no shape to keep.
 *   · `RemovePeer` (:213-223) IS ported, as the no-op it is — see
 *     `cmt_conr_remove_peer`, which quotes it.
 *
 * Reference @v0.38.26 (SHA-256 verified before use):
 *   consensus/reactor.go                1841 lines
 *     8001066f922198a75be28ccd5b0fa069fe0e9644b0196284102e3332b79e6ff0
 *   consensus/reactor_test.go           1189 lines
 *     3c18a944a14abf78dce066430084f79fad86c8157b089753720a2fdb724d9d7c
 *   consensus/state.go                  2646 lines
 *     ac2f65f60cdcfe971aba9c34322b03c031460382ec361e8d18023876d1a3e772
 *     (read for the five event sites and SwitchToConsensus's callees)
 *   consensus/types/peer_round_state.go   68 lines
 *     b5bd1eb78629c8f868ee69bae888285217387237497635da69c80d1c02308408
 *   consensus/msgs.go                    347 lines
 *     7acb318c8910da0c0f4d874b9bd6bb4fdc7212736919939fc933dd405b8e4ada
 *     (read for :232-234, the ValidateBasic gate)
 *   libs/events/events.go                247 lines
 *     400e4b8a781dee7926200ce306fb7fcbf3c7ff4bd87cd90a5fa7a30e0eb9b4e0
 *   p2p/peer.go                          451 lines
 *     de9d3744d2aa1bca3edc43eafdba326ddf34a24c1c6813c0298a71ffb6009ff2
 *   p2p/switch.go                        866 lines
 *     3c285b36faef93aa5687934e2f4448febd65c5f7688118c7b89d1ad22caedd78
 *     (read for :275-297 Broadcast, :336-389 StopPeerForError and
 *      stopAndRemovePeer, :814-866 addPeer)
 *   p2p/base_reactor.go                   75 lines
 *     6b37180625104b9299da50639ee2a8e4634f36935f9489f34259fc39bf6fdc9e
 *   p2p/key.go                           120 lines
 *     db7c7cda77c95229b29e17bcf32e6bc44049510e200ff0e0b842c0761c7ce0bf
 *   config/config.go                    1304 lines
 *     761c747fa0c41cbfd48aa840adad77d3559a64a6a4197b000f2cecb0be70d4f2
 *     (read for :1034-1053, the two sleep durations)
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
 * ── RE-PIN TO cometbft v0.38.26 (decisions/2026-09-30-cometbft-pin-v0.38.26.md)
 * The 709fd12b..v0.38.26 changes to consensus/reactor.go are ported and
 * cite `cometbft@v0.38.26 consensus/reactor.go:<line>` in full at their
 * sites: the oversized-proposal gate in Receive (:323-330, #5324), the
 * catch-up condition (:752), and the three `BitArray.ValidateBasic` calls
 * (:1615-1617, :1678-1680, :1826-1828, ASA-2025-003 — those live in
 * cmt_msgs.c with the other ValidateBasic bodies). Every BARE `:NNN` in
 * this module is a v0.38.26 line as well (renumbered from 709fd12b, whose
 * lines sit 9 lower after :320 (the gate), then lower again by each later
 * insertion (+3 per ValidateBasic call, +6 for the ProposalMessage
 * ValidateBlockSize method at :1650-1654). Local copy used:
 *   /home/nocdem/refs/cometbft-v0.38.26/consensus/reactor.go 1841 lines
 *     8001066f922198a75be28ccd5b0fa069fe0e9644b0196284102e3332b79e6ff0
 *   types/proposal.go 177 lines (read for :82-96 ValidateBlockSize)
 *     8c6e73fa3e5b00824a6b311b05d997c4d0e8039ec34d114421faa6c8418a85eb
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

/** cometbft@v0.38.26 consensus/reactor.go:32-33 — the two "good peer"
 *  thresholds. Their only consumer is `peerStatsRoutine` (:979, :983),
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
 * cometbft@v0.38.26 consensus/reactor.go:144-180 — `GetChannels()`.
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
    CMT_CONR_STOP_PEER_MAJ23      = 4,
    /** cometbft@v0.38.26 consensus/reactor.go:323-330 — a Proposal whose
     *  PartSetHeader.Total exceeds what `Block.MaxBytes` allows
     *  (`ErrProposalTooManyParts`, state.go:40; #5324). */
    CMT_CONR_STOP_PROPOSAL_TOO_MANY_PARTS = 5
} cmt_conr_stop_reason_t;

/**
 * Everything `consensus/reactor.go` reaches outside its package that is
 * not the state machine: the transport (p2p) and the block store.
 *
 * ⚠ EVERY POINTER IS REQUIRED; a NULL row reached at run time is
 * CMT_FAULT. A callback MUST NOT re-enter this module or `cs` — with
 * ONE exception, the one `stop_peer_for_error`'s own row text below
 * requires: that row MAY call `cmt_conr_remove_peer` for the slot it
 * was called about, because every one of its four call sites returns
 * at once after the row (cmt_conr.c:766-768, :789-791, :824-826,
 * :873-875) and reads neither the slot nor its PeerState afterwards
 * (verified R3 W3 C2b, 2026-09-16 — the first host to do it).
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

    /** p2p/switch.go:336-359 — `StopPeerForError(peer, reason)`, reached
     *  from reactor.go:239, :245, :266, :285. The host disconnects the
     *  peer (:342 `stopAndRemovePeer`, whose :373-375 calls every
     *  reactor's `RemovePeer` — the host therefore calls
     *  `cmt_conr_remove_peer` for this slot, before or after returning);
     *  reconnection (:344-358 `reconnectToPeer`) is the host's peer
     *  manager's, as it is the switch's in the reference. */
    void (*stop_peer_for_error)(void *ctx, int peer_idx, int reason_code);

    /* ── sm.BlockStore (state/services.go) ─────────────────────────── */

    /** reactor.go:584, :663, :751, :934 — `blockStore.Base()`. The same
     *  shape as cmt_cs.h's `bs_height` row (rc + out), so one host
     *  function can serve both tables. */
    int (*bs_base)(void *ctx, int64_t *out);

    /** reactor.go:593, :663, :933 — `blockStore.Height()`. The same row as
     *  cmt_cs.h:422's; the host passes the same function. */
    int (*bs_height)(void *ctx, int64_t *out);

    /** reactor.go:590-596 and :660-672 — `blockStore.LoadBlockMeta(h)`,
     *  of which the ported code reads ONLY `blockMeta.BlockID` (:596,
     *  :666) and of that only the PartSetHeader — so the row hands back
     *  the BlockID. (cmt_cs.h:438-444's `bs_load_block_meta` hands back
     *  the HEADER for state.go:1126's `AppHash` read; two projections of
     *  one BlockMeta, each named for what its reader takes.)
     *  @param out_found false is the reference's nil (:591, :661). */
    int (*bs_load_block_meta_block_id)(void *ctx, int64_t height,
                                       cmt_block_id_t *out, bool *out_found);

    /** reactor.go:673 — `blockStore.LoadBlockPart(height, index)`.
     *  @param out the host fills it, including pointing `bytes` at
     *         storage the host owns; that storage must stay valid until
     *         the next call of this same row (it is marshalled and sent
     *         before the row is called again).
     *  @param out_found false is the reference's nil (:674). */
    int (*bs_load_block_part)(void *ctx, int64_t height, int index,
                              cmt_part_t *out, bool *out_found);

    /** reactor.go:765 — `blockStore.LoadBlockCommit(height)`. The same
     *  row and storage contract as cmt_cs.h:421-427's. */
    int (*bs_load_block_commit)(void *ctx, int64_t height,
                                cmt_commit_t *out, bool *out_found);

    /** reactor.go:763 — `blockStore.LoadBlockExtendedCommit(height)`.
     *  The same row and storage contract as cmt_cs.h:432-436's. */
    int (*bs_load_block_extended_commit)(void *ctx, int64_t height,
                                         cmt_extended_commit_t *out,
                                         bool *out_found);

    /* ── the clocks (file header, "DETERMINISM") ───────────────────── */

    /** WALL: reactor.go:513 (`time.Since(rs.StartTime)`) and :1388
     *  (`cmttime.Now()`) only. THE SAME CALLBACK as `cs->host.now`; the
     *  host passes it through. */
    cmt_now_fn now;

    /** WAIT: CLOCK_MONOTONIC, the tick's instant — every `time.Sleep`
     *  deadline (`not_before_ns`) is armed and checked on it (decision
     *  2026-09-30-monotonic-waits.md). Called with `host_ctx`. REQUIRED:
     *  `cmt_conr_init` refuses NULL. */
    cmt_mono_fn mono;
} cmt_conr_host_t;

/* ══ one peer slot (C only — the switch's peer set, per index) ════════ */

/** The three per-peer routines, in the reference's start order
 *  (reactor.go:201-203). Indexes `not_before_ns`. */
typedef enum {
    CMT_CONR_ROUTINE_DATA  = 0,   /* :548 gossipDataRoutine  */
    CMT_CONR_ROUTINE_VOTES = 1,   /* :707 gossipVotesRoutine */
    CMT_CONR_ROUTINE_MAJ23 = 2,   /* :857 queryMaj23Routine  */
    CMT_CONR_NUM_ROUTINES  = 3
} cmt_conr_routine_t;

typedef struct {
    /** In the switch's peer set: `InitPeer` ran and `RemovePeer` did not
     *  (switch.go:847 / :382). `Broadcast` reaches it. */
    bool      in_set;
    /** `AddPeer` ran (:191-210): the three routines are live. */
    bool      started;
    cmt_ps_t  ps;                       /* :184 NewPeerState, peer.Set   */
    /** The `time.Sleep` deadlines, one per routine, in nanoseconds of
     *  the host's MONOTONIC clock (`host.mono`); meaningful only while
     *  `asleep[r]`. */
    int64_t   not_before_ns[CMT_CONR_NUM_ROUTINES];
    bool      asleep[CMT_CONR_NUM_ROUTINES];
    /** reactor.go:711 — gossipVotesRoutine's `sleeping` log throttle.
     *  Carried so the loop reads like the reference; the logs it
     *  throttles are not ported, so it changes nothing observable. */
    int       sleeping;
    /** Where `queryMaj23Routine` resumes after a mid-iteration sleep
     *  (:881, :901, :922, :945 each sleep and then CONTINUE to the next
     *  block; only :950 ends the iteration): 0..3 = the block of
     *  :866/:887/:907/:931 to run next, 4 = the :950 sleep. */
    int       maj23_pc;
} cmt_conr_peer_slot_t;

/* ══ the reactor (reactor.go:39-50) ═══════════════════════════════════ */

/**
 * cometbft@v0.38.26 consensus/reactor.go:39-50 — `type Reactor struct`.
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
    /** libs/service/service.go's `stopped` flag (:101), set by `Stop`
     *  (:168) and tested by `Start` (:132). Set by `cmt_conr_stop` and
     *  NEVER cleared: the reference's `Reset` (:200-215) is the only way
     *  back and is not ported (its `OnReset` panics, :217-219). */
    bool                       stopped;
    cmt_conr_host_t            host;
    void                      *host_ctx;
    cmt_pb_arena_t            *recv_arena;      /* see the file header    */
    cmt_conr_peer_slot_t      *peers;           /* CMT_CONR_MAX_PEERS     */

    /* C-only scratch, heap — see cmt_ps_scratch_t and the note above. */
    cmt_ps_scratch_t           scratch;         /* send side              */
    cmt_pb_cons_message_t     *recv_pb;         /* :236 MsgFromProto's in */
    cmt_msg_t                 *recv_msg;        /* :236 MsgFromProto's out*/
    cmt_extended_commit_sig_t *ecsigs;          /* :769 WrappedExtendedCommit */
    size_t                     ecsigs_cap;
} cmt_conr_t;

/* ══ construction (reactor.go:54-70) ══════════════════════════════════ */

/**
 * cometbft@v0.38.26 consensus/reactor.go:56-70 — `NewReactor()`.
 * `rs: consensusState.GetRoundState()` (:60) has no counterpart (live
 * reads); `NopMetrics` (:61) and the options loop (:65-67) are YOK.
 *
 * @param cs BORROWED; outlives the reactor. Its `host.now` is the wall
 *        clock this reactor's `host.now` must also be. The reactor's
 *        `host.mono` is its OWN wait clock (CLOCK_MONOTONIC; the state
 *        machine reads none — its timer is the host's, which runs on the
 *        same monotonic clock; decision 2026-09-30-monotonic-waits.md).
 * @param wait_sync the reference's `waitSync` (:56, :59): true when the
 *        node is block-syncing and `SwitchToConsensus` will start the
 *        state machine later. The live caller (nodus_witness.c) passes
 *        node.go:373's `blockSync` = !onlyValidatorIsUs; the block sync
 *        reactor (cmt_bsync_reactor.c) calls
 *        `cmt_conr_switch_to_consensus` when it has caught up.
 * @param recv_arena BORROWED; the lifetime rule is in the file header.
 * @return CMT_OK; CMT_FAULT on NULL, a NULL `host->mono`, or allocation
 *         failure.
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
 * (:131), then `subscribeToBroadcastEvents` (:80 → :420-442, which is
 * `cmt_cs_add_listener`), then — unless `wait_sync` — `conR.conS.Start()`
 * (:83-88, `cmt_cs_start`). `peerStatsRoutine` (:78) is YOK and
 * `updateRoundStateRoutine` (:81) has nothing to start.
 *
 * ⚠ ONE-WAY: once `cmt_conr_stop` has run, this REFUSES. That is
 * service.go:132-138's ErrAlreadyStopped, and the reference's only way
 * back — `Reset` (:200-215) — is not ported because its `OnReset` panics
 * for this service (:217-220). A host that wants a second reactor builds
 * a second one. A second Start while running is ErrAlreadyStarted
 * (:153-158) and changes nothing.
 *
 * @return CMT_OK; the reference reverts the flag and returns the error
 *         of :84-87 — so does this, with `cmt_cs_start`'s code (:147).
 *         CMT_REJECT after `cmt_conr_stop` (service.go:137) and while
 *         already running (:158). CMT_FAULT on NULL.
 */
int cmt_conr_start(cmt_conr_t *conR);

/**
 * C only — what `OnStop` (reactor.go:95-103) does, reached through
 * `BaseService.Stop` (service.go:167-190): the flag first (:168), then
 * `unsubscribeFromBroadcastEvents` (:96 → :444-447,
 * `cmt_cs_remove_listener`) and `conR.conS.Stop()` (:97, `cmt_cs_stop`;
 * the reference only logs its error). `conR.conS.Wait()` (:100-102)
 * waits for the receive goroutine, which does not exist here.
 * @return CMT_OK; CMT_REJECT before any Start (ErrNotStarted, :169-175 —
 *         the latch is NOT taken) and after a Stop (ErrAlreadyStopped,
 *         :185-190); CMT_FAULT on NULL.
 */
int cmt_conr_stop(cmt_conr_t *conR);

/**
 * cometbft@v0.38.26 consensus/reactor.go:107-141 — `SwitchToConsensus()`.
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

/** cometbft@v0.38.26 consensus/reactor.go:409-413 — `WaitSync()`. */
bool cmt_conr_wait_sync(const cmt_conr_t *conR);

/* ══ peers (reactor.go:182-223) ═══════════════════════════════════════ */

/**
 * cometbft@v0.38.26 consensus/reactor.go:183-187 — `InitPeer()`. Creates
 * the PeerState (:184 `NewPeerState`) and attaches it to the peer (:185
 * `peer.Set(types.PeerStateKey, …)`): here, fills slot `peer_idx` and
 * puts it in the peer set (switch.go:847).
 * @param id the peer's 32-byte witness id (substitution 9).
 * @return CMT_OK; CMT_REJECT for an index outside [0, CMT_CONR_MAX_PEERS)
 *         or a slot already in the set; CMT_FAULT on NULL.
 */
int cmt_conr_init_peer(cmt_conr_t *conR, int peer_idx,
                       const uint8_t id[CMT_PB_PEER_ID_MAX]);

/**
 * cometbft@v0.38.26 consensus/reactor.go:191-210 — `AddPeer()`. A no-op
 * when not running (:192-194); starts the three routines (:201-203 —
 * here, marks the slot `started` so `cmt_conr_tick` runs them) and,
 * unless `wait_sync`, sends our NewRoundStep to the peer (:207-209).
 * @return CMT_OK; CMT_REJECT for an index outside the table; CMT_FAULT
 *         where the reference panics at :198 (no PeerState — InitPeer
 *         was skipped; NODE-LOCAL), or on NULL.
 */
int cmt_conr_add_peer(cmt_conr_t *conR, int peer_idx);

/**
 * cometbft@v0.38.26 consensus/reactor.go:213-223 — `RemovePeer()`, which
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
 * `sw.peers.Remove(peer)` (switch.go:382) takes the peer out of the set,
 * and `peer.IsRunning()` turns false for the three goroutines
 * (:554, :716, :861). Here that is one act: the slot leaves the set,
 * stops, and is cleared. Called by the host whenever a connection closes
 * (the switch calls it from `stopAndRemovePeer` :374-376, for an error
 * or otherwise). NOT gated on `running`: the reference's gate at :214
 * protects a body that does nothing, while the slot must be freed
 * regardless — stated deviation, see the wave report (R3-A-3).
 * @return CMT_OK (including for a slot not in the set — the switch's
 *         Remove of an unknown peer is a logged no-op :382-387);
 *         CMT_REJECT for an index outside the table; CMT_FAULT on NULL.
 */
int cmt_conr_remove_peer(cmt_conr_t *conR, int peer_idx);

/* ══ receive (reactor.go:225-400) ═════════════════════════════════════ */

/**
 * cometbft@v0.38.26 consensus/reactor.go:231-400 — `Receive()`, from the
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
 * the channel switch (:257-399) with the message-type switch inside each,
 * exactly as written, including "Ignoring message received during sync"
 * for the Data, Vote and VoteSetBits channels while `wait_sync` (:317,
 * :345, :367) and the "Unknown message type" log-and-drop defaults
 * (:313, :341, :363, :394, :398 — "don't punish (leave room for soft
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
 *           :333, :339 and :359 until the queue drains; a single thread
 *           cannot, so the message is NOT queued, the peer state was
 *           already updated as at :332/:337/:355-357, no peer is
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
 * `gossipDataRoutine` (:548-653), `gossipVotesRoutine` (:707-795) and
 * `queryMaj23Routine` (:857-954) — in that order (:201-203) — each as far
 * as the reference would go before a `time.Sleep` or a false from a send,
 * skipping a routine whose `not_before` has not arrived. Reads the WAIT
 * clock ONCE (the host's `mono`, CLOCK_MONOTONIC).
 *
 * @param out_next_deadline_ns the earliest pending `not_before` in
 *        nanoseconds of the host's MONOTONIC clock, INT64_MAX when
 *        nothing is pending; may be NULL.
 * @return CMT_OK; CMT_FAULT on NULL, a host-row fault, a state-machine
 *         fault, or one of the NODE-LOCAL panics of the file header.
 *         Never CMT_REJECT: a refused send is "not sent", not an error.
 */
int cmt_conr_tick(cmt_conr_t *conR, int64_t *out_next_deadline_ns);

/**
 * cometbft@v0.38.26 consensus/reactor.go:542-546 — `getRoundState()`, the
 * snapshot `updateRoundStateRoutine` (:528-540) refreshes every 100 µs.
 * Single-threaded, this reads `cmt_cs_get_round_state` LIVE: exact where
 * the reference's is at most 100 µs stale.
 */
int cmt_conr_get_round_state(const cmt_conr_t *conR, cmt_round_state_t *out);

/* ══ ValidateHeight (reactor.go:1569-1583) ═══════════════════════════ */

/* `cmt_msg_validate_basic` and the nine per-message ValidateBasic bodies
 * used to be declared here. They are in cmt_msgs.{h,c} now (reached
 * through the include above), because the WAL REPLAY path in cmt_cs.c has
 * to run the same gate — msgs.go:232-234 through wal.go:410 from
 * replay.go:147 — and the consensus core must not include the reactor
 * (atlas-dec-b02c8de1f52854b20dbfd64f6c987b34, item 4). Nothing about
 * them changed; `cmt_conr_receive` still calls `cmt_msg_validate_basic`
 * at :243. ValidateHeight stays: it is `Receive`'s alone (:264). */

/** cometbft@v0.38.26 consensus/reactor.go:1569-1583 —
 *  `NewRoundStepMessage.ValidateHeight(initialHeight)`: Height below the
 *  initial height; LastCommitRound not -1 AT the initial height; a
 *  negative LastCommitRound ABOVE it. */
int cmt_new_round_step_msg_validate_height(const cmt_new_round_step_msg_t *m,
                                           int64_t initial_height);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_CONR_H */
