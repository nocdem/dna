/**
 * @file shared/dnac/cmt_cs.h
 * @brief cometbft @709fd12b `consensus/state.go` ported to C — the
 *        consensus state machine itself.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-C of the cometbft → C consensus port. Nothing in the running
 * chain constructs a `cmt_cs_t` yet; additive only. The live witness BFT
 * and the QC V2 path are untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * The receiver in `consensus/state.go` is `cs`, so every function here is
 * `cmt_cs_*`: `(cs *State) enterPrecommit` → `cmt_cs_enter_precommit`.
 * `cmt_state_*` is `state/state.go`, whose receiver is `state`, and is a
 * different module (cmt_state.h).
 *
 * ── ONE THREAD, ONE FIXED ORDER ────────────────────────────────────────
 * The reference is `receiveRoutine` (:784-872), a goroutine selecting over
 * five channels. Go's `select` picks a READY case at RANDOM; this port
 * replaces it with a FIXED poll order, which is the behavioural
 * determinization the umbrella record names (rev 3, atlas-dec-d5e766de…):
 *
 *   1. txs available   (:827-828)
 *   2. the peer queue  (:830-836)
 *   3. the internal queue (:838-856)
 *   4. the timer tock  (:858-865)
 *   5. quit            (:867-869)
 *
 * `cmt_cs_step` handles AT MOST ONE of them per call, because one
 * iteration of the reference's `for` handles exactly one case; draining a
 * queue inside a single call would change how queue work interleaves with
 * the timer.
 *
 * ⚠ NO RECURSION INTO `handle_msg`. This node's own proposal, block parts
 * and votes go onto the internal queue (:1244, :1248, :2472) and are
 * handled on a LATER `cmt_cs_step`, after the WriteSync at :839. Calling
 * `cmt_cs_handle_msg` from inside an `enter_*` function is exactly the
 * re-entrancy the queue exists to prevent, and this module never does it.
 *
 * ── THE INTERNAL QUEUE OVERFLOWS INTO A FAULT, DELIBERATELY ────────────
 * `sendInternalMessage` (:568-579) pushes, and on a full channel spawns a
 * goroutine to push later. The reference's own comment at :572-575 says
 * what that costs: "using the go-routine means our votes can be processed
 * out of order". Out of order is not available to a chain that must not
 * fork, so an overflow here is CMT_FAULT — the node stops rather than
 * reorder its own messages. Recorded as a deviation.
 *
 * ── THE PEER QUEUE REFUSES WHERE GO BLOCKS ─────────────────────────────
 * `AddVote`/`SetProposal`/`AddProposalBlockPart` (:477-510) send on an
 * unbuffered-once-full channel, so the REACTOR GOROUTINE BLOCKS. A single
 * event loop has nobody to block, so `cmt_cs_enqueue_peer_msg` returns
 * CMT_REJECT when the queue is full and the host applies backpressure to
 * that peer. REJECT rather than FAULT because a peer must never be able to
 * stop this node. QUESTION for the operator: the reference's blocking is a
 * third behaviour, and neither C answer reproduces it.
 *
 * ── WHAT IS HOST ───────────────────────────────────────────────────────
 * Everything `state.go` reaches outside its own package is a function
 * pointer in `cmt_cs_host_t`, each row carrying the Go call site. Three
 * rows are NOT in the wave's dispatch table and are named here as
 * additions, with the reason:
 *   · `decode_block` — :2005-2019 is `io.ReadAll` + `proto.Unmarshal` +
 *     `types.BlockFromProto`. cmt_pb.h:1043 states there is deliberately
 *     no `cmt_pb_block_unmarshal` in this tree, so the wire decoder does
 *     not exist to be called; the host supplies it and owns the storage
 *     the decoded block points into.
 *   · `wal_search_end_height` — replay.go:106 and :129.
 *   · `wal_read_next` — replay.go:147.
 *   The dispatch's table covers only the WAL WRITE side; `catchupReplay`
 *   cannot be ported without the read side.
 *
 * NOT host and NOT ported, deliberately: `eventBus.PublishEvent*`,
 * `evsw.FireEvent` and every `metrics.*` call. They are neither PORT nor
 * HOST rows of the port map, and no consensus decision reads them.
 *
 * ── OWNERSHIP, AND THE THREE WAYS IT CAN GO WRONG ──────────────────────
 *
 * (1) BLOCK AND PART-SET SLOTS. Go aliases three block pointers freely —
 *     `LockedBlock = ProposalBlock` (:1531-1532), `ProposalBlock =
 *     LockedBlock` (:1631-1632), `ValidBlock = ProposalBlock` (:2046-2047,
 *     :2285-2286) — and the GC keeps whatever is still named. Here the
 *     storage is the HOST's `cmt_cs_slots_t`: THREE block slots and THREE
 *     part-set slots, because at most three names exist (proposal, locked,
 *     valid) and therefore at most three distinct objects are alive.
 *     THE RULE: a slot may be rewritten only while NO name points at it.
 *     `cs` enforces it by clearing the name first and then taking a slot
 *     no name refers to; if none is free that is CMT_FAULT, because the
 *     derivation above says it cannot happen.
 *     Blocks and part sets are allocated INDEPENDENTLY: :2298-2300
 *     replaces `ProposalBlockParts` while `ValidBlockParts` still aliases
 *     the old one and `ProposalBlock` is untouched.
 *
 * (2) THE VOTE EXTENSION ARENA. `cmt_vote_copy` copies a vote's extension
 *     DESCRIPTOR and SHARES its bytes (cmt_vote.h:241, wave R2-A register
 *     row R2A-3). Every vote this module hands to `cmt_hvs_add_vote` or
 *     `cmt_vote_set_add_vote` therefore leaves a pointer inside the vote
 *     set. THE HOST SUPPLIES `ext_arena`, AND IT MUST BE PER-HEIGHT: it
 *     has to outlive every vote set of the height it serves, which means
 *     it may be reset only after `cmt_cs_update_to_state` has replaced the
 *     height vote set AND released the previous height's (see (3)). The
 *     host writes extension bytes into it from `extend_vote` (:2400) and
 *     from whatever decodes a peer's vote.
 *
 * (3) `LastCommit` HAS THREE POSSIBLE OWNERS. :701 points it INTO the
 *     current height vote set, which :743-746 then replaces; Go's GC keeps
 *     the old set alive, `cmt_hvs_free` would not. So `cs` keeps
 *     `prev_votes` — the height vote set the current `last_commit` points
 *     into — and frees it one height later. `last_commit_owner` says which
 *     of the three cases holds: nothing (:692), the previous height vote
 *     set (:701), or a standalone set this module allocated
 *     (`reconstructSeenCommit` :590, `reconstructLastCommit` :607).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * No randomness anywhere. No unordered iteration: every collection this
 * module walks is an array in validator-index order or a queue in arrival
 * order. THE CLOCK IS READ THROUGH `host.now` AND NOWHERE ELSE, at exactly
 * SIX sites, each of which the reference has:
 *   state.go:558, :728, :1033, :1614, :2417 — the five `cmttime.Now()`
 *   calls in the ported bodies; and
 *   types/proposal.go:44, reached from state.go:1238 — `NewProposal`
 *   stamps the proposal. The reference reads the clock INSIDE
 *   NewProposal; this tree's `cmt_new_proposal` takes the instant as an
 *   argument (cmt_proposal.h:98-101) so that every clock read sits at a
 *   call site, which is why the read appears here rather than there. It
 *   is the same instant the reference stamps, and it is a site the
 *   dispatch's own five-item list did not enumerate.
 * (:1064 is a log line the port does not carry; wal.go:189's record stamp
 * is the HOST's, taken from the same callback.)
 * Two nodes with different timeouts still decide the same blocks: the
 * durations here are a LOCAL scheduling policy, not consensus state.
 *
 * ── ⚠ THE ValidateBasic GATE IS NOT HERE YET ───────────────────────────
 * In the reference a peer's message becomes a `msgInfo` only after
 * `MsgFromProto` has run `pb.ValidateBasic()` (msgs.go:232-234), which is
 * where a vote with a non-positive height (types/vote.go:283-285), an
 * invalid type or an out-of-range index is refused. THIS PORT STOPS
 * BEFORE THAT CALL (cmt_msgs.h:28-35) and the gate is R3's, so until R3
 * wires it every field of every message reaching this module is a raw
 * peer number.
 * Two consequences are already handled here and neither should be undone
 * when the gate lands: the `vote.Height+1` of :2137 is formed as
 * `cs.Height - 1` so a height of INT64_MAX cannot overflow, and a peer id
 * that is neither empty nor 32 bytes is refused at the message boundary.
 * Anything else this module assumes about a peer's numbers is stated at
 * the site that assumes it.
 *
 * ── THE PANIC RULE ─────────────────────────────────────────────────────
 * Umbrella revision 4 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8 — see
 * the note below): a Go `panic` a PEER'S INPUT can reach becomes
 * CMT_REJECT; one that guards a NODE-LOCAL invariant becomes CMT_FAULT and
 * the node stops. Every ported panic site says which class it is and why,
 * in a comment at the site. Return contract: CMT_OK 0, CMT_REJECT −1,
 * CMT_FAULT −2 (cmt_tmhash.h:109-111).
 *
 * Revision 4 was APPROVED by the operator on 2026-09-10, after this wave
 * was written against it; waves R2-A and R2-B shipped under the same
 * rule.
 *
 * ── FAIL POINTS ────────────────────────────────────────────────────────
 * The six `fail.Fail()` calls at :852, :1727, :1744, :1767, :1787 and
 * :1795 are `CMT_FAIL_POINT()`, compiled only under QGP_FAULT_INJECT
 * (nodus/CMakeLists.txt refuses that option in a Release build — the
 * `option(QGP_FAULT_INJECT …)` block, which moves as the file grows, so
 * it is named rather than pinned to a line).
 * Semantics are libs/fail/fail.go:9-47 exactly: the environment variable
 * `FAIL_TEST_INDEX` — the reference's own name — a process-global call
 * counter, and on a match the line `*** fail-test N ***` followed by
 * `exit(1)`.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 * The full Go → C closure table is in this wave's report; the entries a
 * reader of this header needs are:
 *   · `recordMetrics` (:1812-1899), `emitPrecommitTimeoutMetrics`
 *     (:2519-2547), `calculatePrecommitMessageDelayMetrics` (:2549-2570),
 *     `calculatePrevoteMessageDelayMetrics` (:2572-2596) — metrics only.
 *     `recordMetrics` contains ONE non-metric check, the panic at
 *     :1831-1834 (commit size against validator-set length). It is NOT
 *     ported, and NOTHING IS LOST BY THAT: the same property is enforced
 *     one call earlier, by `ValidateBlock` → `VerifyCommit`, which refuses
 *     a commit whose signature count differs from the validator set's size
 *     (types/validation.go:413-415, ported at cmt_validation.c:112-114).
 *     `finalizeCommit` runs that check at :1713 before it would ever reach
 *     :1832. Raised as a question by this wave and answered by the
 *     ORCHESTRATOR at O6 by opening both sites.
 *   · `String` (:234-237), `GetRoundStateJSON` (:263-267),
 *     `GetRoundStateSimpleJSON` (:270-274) — display and RPC.
 *   · `SetLogger` (:211-214), `SetEventBus` (:217-220), `StateMetrics`
 *     (:223-225), `OfflineStateSyncHeight` (:229-231) — logger, event bus
 *     and metrics wiring, none of which this port carries;
 *     `offline_state_sync_height` itself IS carried, because :194 branches
 *     on it.
 *   · `SetTimeoutTicker` (:298-302) — the reference swaps the ticker
 *     through an interface for its tests; the ticker is a value here
 *     (cmt_ticker.h) and there is nothing to swap.
 *   · `OpenWAL` (:452-467), `loadWalFile` (:420-429), `repairWalFile`
 *     (:2621-2653) and the WAL-repair loop inside OnStart (:339-385) —
 *     a file WAL. This port's WAL is SQLite rows written by the host
 *     (D-15, atlas-dec-c0bfc5344204b9282ceaaa5e06042350), so there is no
 *     file to repair.
 *   · `startRoutines` (:409-417), `Wait` (:446-448), the `recover()`
 *     handler and `onExit` (:785-812) — goroutine lifecycle.
 *   · `(ti *timeoutInfo) String()` (:61-63) — a two-line Sprintf for a log
 *     line. It falls in a gap between modules: cmt_msgs.h:66 scopes itself
 *     to ":45-59, msgInfo and timeoutInfo", one line short of it. Named
 *     here so the closure table has no silent hole (verifier C, claim 1).
 *   · `type StateOption` (:151) — the option type itself. Its two setters
 *     are named above; the only one whose value the port carries is
 *     `offline_state_sync_height`, which is a parameter of cmt_cs_init.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/state.go               2653 lines
 *     f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *   consensus/replay.go               565 lines
 *     5609c4d4174a536389cb2814bac09557a66e3299292141b54c635e31425284fe
 *     (only :39-167, readReplayMessage and catchupReplay)
 *   consensus/ticker.go               143 lines
 *     f08d7195f0a6ba820243d0e6aed9499f1cc334984a665d5d0bd6da394de1b26c
 *   consensus/wal.go                  434 lines
 *     f6bd6d512bbda08f31231d535b97df3c9c6feb3ddaf01a2054e2f0cf994f2a2d
 *   consensus/types/round_state.go    224 lines
 *     44404a9f7c8125449edc3756c50c5f7575a9de45db6fb2b568ead80ac3e8c354
 *   consensus/types/height_vote_set.go 286 lines
 *     d6793961c6f113acad7fa153cf2d912224191350f547860812d623e9ca13964c
 *   types/vote_set.go                 724 lines
 *     548a256c311755a4a2d83696c90030f144952c64c0e3a459ac86baf844c56880
 *   types/block.go                   1555 lines
 *     2094420e26fa23d4b6a592a06e7953025541973694bd96ff9c8e5d9911162109
 *   types/vote.go                     454 lines
 *     dd978df4530187c34902fad06ba1f7065896ece92b68d07d3a9bfc55ddb82e0f
 *   types/proposal.go                 161 lines
 *     0b56660bee6071267b75c9dabe148036cb96c814f640f4e4323baa59af44eba0
 *   types/validator_set.go           1053 lines
 *     6c3a663aaf84fbee94735731eaba27d1a8e5269dd6e316e0b175595e32902221
 *   config/config.go                 1283 lines
 *     f0c2f601d49e1a56b36e8d557387e96ee53ecc3616ecb79749b0f71c0f218c21
 *   state/execution.go                789 lines
 *     d12730b67e48c4863963c929067905d475543fcd135b99eaa909c502ebecae55
 *   state/state.go                    355 lines
 *     02dc0f209451d28202e1cc25c901af29eb48ca6e83ec5b8a69d88be10b1472fc
 *   libs/fail/fail.go                  47 lines
 *     c47b87d25a4232d825f4283d7bfe0dc2a81aaceb977e4ab8ea4dda42ac8a32a9
 *
 * Governing records, all APPROVED: umbrella rev 4
 * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8), K-1 rev 2
 * (atlas-dec-3ba8153088b0d60c63083028023b61be), INVARIANT explicit bounds
 * (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07), D-4 rev 2
 * (atlas-dec-d5ddcba654eb48d861c03a0ecd170718), D-15 rev 5
 * (atlas-dec-c0bfc5344204b9282ceaaa5e06042350), clock POLICY
 * (atlas-dec-4ac0423068085c100fdfa3e264ca16bc), pin record rev 7
 * (atlas-dec-483ec17cbb352ef0ec2267ccd953339c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_CS_H
#define SHARED_DNAC_CMT_CS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"        /* CMT_OK / CMT_REJECT / CMT_FAULT         */
#include "cmt_time.h"          /* cmt_time_t, cmt_now_fn                  */
#include "cmt_config.h"        /* cmt_config_t                            */
#include "cmt_state.h"         /* cmt_state_t, cmt_state_storage_t        */
#include "cmt_block.h"         /* cmt_block_t, cmt_commit_t, block id     */
#include "cmt_part_set.h"      /* cmt_part_set_t, cmt_part_t              */
#include "cmt_proposal.h"      /* cmt_proposal_t                          */
#include "cmt_vote.h"          /* cmt_vote_t, cmt_sign_vote_fn            */
#include "cmt_vote_set.h"      /* cmt_vote_set_t, cmt_peer_id_t           */
#include "cmt_hvs.h"           /* cmt_hvs_t                               */
#include "cmt_round_state.h"   /* cmt_round_state_t, the eight steps      */
#include "cmt_msgs.h"          /* cmt_msg_t, cmt_msg_info_t, timeout info */
#include "cmt_wal.h"           /* cmt_wal_message_t, timed WAL message    */
#include "cmt_ticker.h"        /* cmt_ticker_t                            */
#include "cmt_validator_set.h" /* cmt_validator_set_t, cmt_validator_t    */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ constants ════════════════════════════════════════════════════════ */

/** cometbft@709fd12b consensus/state.go:45 — `var msgQueueSize = 1000`.
 *  The capacity of BOTH queues (:168, :169). */
#define CMT_CS_MSG_QUEUE_SIZE 1000

/** Go's `time.Millisecond` in nanoseconds — the `timeIota` of :2420 and
 *  the "+1ms" of :1032. cmt_config.h defines the same value as
 *  CMT_MILLISECOND; this name is the reference's, at the two sites that
 *  use it as a time increment rather than as a timeout unit. */
#define CMT_CS_TIME_IOTA_NS ((int64_t)1000000)

/** How many block slots and part-set slots the host must supply. THREE,
 *  because `ProposalBlock`, `LockedBlock` and `ValidBlock` are the only
 *  names and Go keeps exactly what is named. See "OWNERSHIP" (1). */
#define CMT_CS_BLOCK_SLOTS 3

/* ══ the fail point (libs/fail/fail.go:9-47) ══════════════════════════ */

#ifdef QGP_FAULT_INJECT
/**
 * cometbft@709fd12b libs/fail/fail.go:28-39 — `fail.Fail()`.
 *
 * Reads `FAIL_TEST_INDEX` (:10, the reference's own variable name). Unset
 * or unparseable is −1 (:12-14, :17-20) and the call does nothing —
 * INCLUDING not advancing the counter, because :30-32 returns before the
 * increment at :38. On a match it prints `*** fail-test N ***` (:42) and
 * exits with status 1 (:43).
 */
void cmt_cs_fail_point(void);
#define CMT_FAIL_POINT() cmt_cs_fail_point()
#else
/** QGP_FAULT_INJECT is off: the six fail points compile to nothing. */
#define CMT_FAIL_POINT() ((void)0)
#endif

/* ══ the host ═════════════════════════════════════════════════════════ */

/**
 * Everything `consensus/state.go` reaches outside its own package, as one
 * table the caller supplies. Every row carries the Go call site.
 *
 * ⚠ EVERY POINTER IS REQUIRED unless its comment says otherwise; a NULL
 * row reached at run time is CMT_FAULT, not a silent no-op. A node that is
 * not a validator supplies the three privValidator rows anyway and calls
 * `cmt_cs_set_priv_validator(cs, false)` — that is the reference's
 * `cs.privValidator == nil` (:1170, :1280, :2445), a state of the STATE
 * machine rather than of the table.
 *
 * ⚠ A callback MUST NOT re-enter `cs`. The reference's callees are in
 * other packages and cannot; a C host that called back into
 * `cmt_cs_handle_msg` would break the no-recursion rule above.
 */
typedef struct {
    /* ── sm.BlockExecutor (state/execution.go) ─────────────────────── */

    /** state.go:1308 — `blockExec.CreateProposalBlock(ctx, height, state,
     *  lastExtCommit, proposerAddr)`. Writes into the block slot `out`,
     *  which `cs` has already taken and which no name points at yet; the
     *  host owns whatever storage the block's `data.txs`, evidence and
     *  `last_commit` point into and must keep it alive as long as the
     *  slot is named.
     *  @return CMT_OK; anything else is the reference's error at :1309,
     *          which :1310 turns into a panic — see the site. */
    int (*create_proposal_block)(void *ctx, int64_t height,
                                 const cmt_state_t *state,
                                 const cmt_extended_commit_t *last_ext_commit,
                                 const uint8_t *proposer_addr,
                                 size_t proposer_addr_len,
                                 cmt_block_t *out);

    /** state.go:1382 — `blockExec.ProcessProposal(block, state)`.
     *  @param out_accept the reference's `isAppValid`.
     *  @return CMT_OK; anything else is the error :1383-1387 panics on. */
    int (*process_proposal)(void *ctx, cmt_block_t *block,
                            const cmt_state_t *state, bool *out_accept);

    /** state.go:1363, :1526, :1713 — `blockExec.ValidateBlock(state,
     *  block)`. CMT_OK accepts; any other value is the reference's error.
     *  The three call sites treat that error very differently — see each
     *  one. */
    int (*validate_block)(void *ctx, const cmt_state_t *state,
                          cmt_block_t *block);

    /** state.go:1775 — `blockExec.ApplyVerifiedBlock(stateCopy, blockID,
     *  block)`. `in_out_state` arrives as the reference's `stateCopy`
     *  (:1770) and the host OVERWRITES it with the state the reference
     *  returns at :1775.
     *  @return CMT_OK; anything else is the error :1783-1785 panics on. */
    int (*apply_verified_block)(void *ctx, const cmt_block_id_t *block_id,
                                cmt_block_t *block,
                                cmt_state_t *in_out_state);

    /** state.go:2400 — `blockExec.ExtendVote(ctx, vote, block, state)`.
     *  The bytes MUST live in the per-height extension arena (see
     *  "OWNERSHIP" (2)); `cmt_vote_copy` shares them into every vote set
     *  the vote is added to.
     *  @param out_ext receives the descriptor. */
    int (*extend_vote)(void *ctx, const cmt_vote_t *vote, cmt_block_t *block,
                       const cmt_state_t *state, cmt_pb_bytes_t *out_ext);

    /** state.go:2210 — `blockExec.VerifyVoteExtension(ctx, vote)`.
     *  CMT_OK accepts; anything else is the error :2212-2214 returns. */
    int (*verify_vote_extension)(void *ctx, const cmt_vote_t *vote);

    /* ── sm.BlockStore (state/services.go) ─────────────────────────── */

    /** state.go:309, :1730 — `blockStore.Height()`. */
    int (*bs_height)(void *ctx, int64_t *out);

    /** state.go:313, :629 — `blockStore.LoadBlockCommit(height)`.
     *  @param out_found false is the reference's nil.
     *  @param out the host fills it, including pointing `signatures` at
     *         storage the host owns; that storage must stay valid until
     *         the next call of this same row. */
    int (*bs_load_block_commit)(void *ctx, int64_t height,
                                cmt_commit_t *out, bool *out_found);

    /** state.go:611 — `blockStore.LoadBlockExtendedCommit(height)`. Same
     *  storage contract as `bs_load_block_commit`. */
    int (*bs_load_block_extended_commit)(void *ctx, int64_t height,
                                         cmt_extended_commit_t *out,
                                         bool *out_found);

    /** state.go:1124 — `blockStore.LoadBlockMeta(height)`. The ported code
     *  reads exactly one field of the BlockMeta, `Header.AppHash` (:1131),
     *  so the row hands back the HEADER. (:1886, the other Go call site,
     *  is inside `recordMetrics`, which is not ported.)
     *  @param out_found false is the reference's nil (:1125). */
    int (*bs_load_block_meta)(void *ctx, int64_t height,
                              cmt_header_t *out, bool *out_found);

    /** state.go:310, :627, :2502 — `blockStore.LoadSeenCommit(height)`.
     *  Same storage contract as `bs_load_block_commit`. */
    int (*bs_load_seen_commit)(void *ctx, int64_t height,
                               cmt_commit_t *out, bool *out_found);

    /** state.go:1737 — `blockStore.SaveBlock(block, blockParts,
     *  seenExtendedCommit.ToCommit())`. */
    int (*bs_save_block)(void *ctx, cmt_block_t *block,
                         const cmt_part_set_t *parts,
                         const cmt_commit_t *seen_commit);

    /** state.go:1735 — `blockStore.SaveBlockWithExtendedCommit(block,
     *  blockParts, seenExtendedCommit)`. */
    int (*bs_save_block_with_extended_commit)(
            void *ctx, cmt_block_t *block, const cmt_part_set_t *parts,
            const cmt_extended_commit_t *seen_extended_commit);

    /* ── evidencePool (state.go:71-74) ─────────────────────────────── */

    /** state.go:2094 — `evpool.ReportConflictingVotes(voteA, voteB)`.
     *  The reference's method returns nothing; a non-CMT_OK here is
     *  treated as a local failure at the site. */
    int (*report_conflicting_votes)(void *ctx, const cmt_vote_t *vote_a,
                                    const cmt_vote_t *vote_b);

    /* ── types.PrivValidator ───────────────────────────────────────── */

    /** The signer `types.SignAndCheckVote` drives, reached from :2408.
     *  `cmt_vote.h:337-351` explains why the shape is the reference's
     *  interface and not a raw byte signer. */
    cmt_sign_vote_fn sign_vote;

    /** state.go:1240 — `privValidator.SignProposal(chainID, p)`. The host
     *  computes the sign bytes with `cmt_proposal_sign_bytes`, signs, and
     *  writes the signature into `p->signature` / `p->signature_len`.
     *  @return CMT_OK; anything else is the reference's error, which :1252
     *          only logs. */
    int (*sign_proposal)(void *ctx, const uint8_t *chain_id,
                         size_t chain_id_len, cmt_proposal_t *p);

    /** state.go:2484 — `privValidator.GetPubKey()`.
     *  @return CMT_OK; anything else is the reference's error at :2485,
     *          which leaves the memoized key UNCHANGED (:2486-2489 are
     *          not reached). */
    int (*get_pub_key)(void *ctx, cmt_pb_public_key_t *out);

    /* ── WAL, write side (D-15) ────────────────────────────────────── */

    /** state.go:760 (round state), :831 (a peer message), :859 (a
     *  timeout) — `wal.Write(...)`. The reference only LOGS a failure at
     *  all three sites, and so does this port.
     *  The `TimedWALMessage.Time` stamp is the HOST's, taken from the
     *  same `now` callback (wal.go:189; the field's own comment at
     *  wal.go:34 says it is for debugging). */
    int (*wal_write)(void *ctx, const cmt_wal_message_t *msg);

    /** state.go:839 (own message) and :1760 (EndHeight) —
     *  `wal.WriteSync(...)`. A failure at EITHER site is a panic in the
     *  reference (:841-844, :1761-1764) and CMT_FAULT here. */
    int (*wal_write_sync)(void *ctx, const cmt_wal_message_t *msg);

    /** state.go:1232 (before publishing our own proposal) and :2374
     *  (before signing a vote) — `wal.FlushAndSync()`. Every row written
     *  before this point must be durable before the signature exists. */
    int (*wal_flush_and_sync)(void *ctx);

    /* ── WAL, read side — ADDED, not in the wave dispatch's table ───── */

    /** replay.go:106 and :129 — `wal.SearchForEndHeight(height, …)`. On
     *  CMT_OK with `*out_found` true the read cursor is positioned just
     *  after that END_HEIGHT record, which is where `wal_read_next`
     *  continues from. */
    int (*wal_search_end_height)(void *ctx, int64_t height, bool *out_found);

    /** replay.go:147 — `dec.Decode()`. Reads the next record from the
     *  cursor `wal_search_end_height` left.
     *  @param out_eof true is the reference's `io.EOF` (:149-150), which
     *         ends the replay loop normally.
     *  @return CMT_OK; CMT_FAULT for a corrupted record — D-15 (rev 4
     *          APPROVED) makes a digest mismatch or an out-of-range kind
     *          a stop, which is stricter than replay.go:151-153's
     *          "return the error"; the strictness is the storage layer's
     *          and is stated here so a reader is not surprised. */
    int (*wal_read_next)(void *ctx, cmt_timed_wal_message_t *out,
                         bool *out_eof);

    /* ── the block wire decoder — ADDED; see the header ────────────── */

    /** state.go:2005-2019 — `io.ReadAll(GetReader())`,
     *  `proto.Unmarshal(bz, pbb)` and `types.BlockFromProto(pbb)` as one
     *  row, because this tree has no `cmt_pb_block_unmarshal`
     *  (cmt_pb.h:1043) for the middle step.
     *  @param out a block slot `cs` has already taken; the host owns the
     *         storage its `data.txs`, evidence and `last_commit` point at
     *         and must keep it alive while the slot is named.
     *  @return CMT_OK; CMT_REJECT for bytes that do not decode or a block
     *          that fails ValidateBasic — :2007/:2013/:2018 all return the
     *          error to `addProposalBlockPart`'s caller. */
    int (*decode_block)(void *ctx, const uint8_t *bytes, size_t len,
                        cmt_block_t *out);

    /* ── the clock and the timer ───────────────────────────────────── */

    /** THE ONLY CLOCK IN THIS MODULE. Reached at :558, :728, :1033, :1614
     *  and :2417 and nowhere else. */
    cmt_now_fn now;

    /** `ticker.timer.Reset(ti.Duration)` (ticker.go:126). The duration is
     *  NANOSECONDS and MAY BE ZERO OR NEGATIVE (ticker.go:16, :124); a
     *  non-positive duration must fire immediately. */
    int (*timer_arm)(void *ctx, int64_t duration_ns);

    /** `ticker.stopTimer()` (ticker.go:83-92): cancel, and DISCARD an
     *  expiry that has already happened but has not been delivered. That
     *  discard is the whole point of :88-90 — a fired-but-unread timeout
     *  must never reach the state machine. */
    int (*timer_disarm)(void *ctx);
} cmt_cs_host_t;

/* ══ host-owned block and part-set storage ════════════════════════════ */

/**
 * The three block slots and three part-set slots of "OWNERSHIP" (1),
 * plus the arrays a `cmt_part_set_t` needs, because `cmt_part_set_t.parts`
 * is caller-owned (cmt_part_set.h:225) and the parts POINT INTO the
 * marshalled block (cmt_part_set.h's payload note).
 *
 * ⚠ NEVER A STACK OBJECT — a block carries its transaction list and a
 * part set up to CMT_PART_SET_MAX_PARTS parts of 64 KiB each. The HOST
 * allocates every pointer below and owns every lifetime; `cmt_cs` only
 * chooses free indices, and never allocates or frees anything here.
 *
 * `payload[i]` is the buffer the assembled parts of slot `i` are read back
 * into before `decode_block` on the receiver's path (:2005). Its capacity
 * must cover `ConsensusParams.Block.MaxBytes`.
 *
 * ── WHY THE PROPOSER HAS ITS OWN BUFFER, AND WHAT THE HOST OWES IT ─────
 * `marshal_*` is NOT one of the three slots, and that is deliberate. On
 * the proposer's path :1223 marshals the block and splits it into parts
 * whose payloads POINT INTO that marshalled copy (cmt_part_set.h's
 * payload note), and :1246-1249 then queues those parts as messages. A
 * queued `cmt_part_t` carries only a POINTER to its bytes, so the bytes
 * must outlive the queue entry. If the proposer had marshalled into one
 * of the three slots, `defaultSetProposal` (:1945) — which runs on the
 * very next step, from the proposal this node just queued — could take
 * that same slot, because no name points at it, and overwrite the bytes
 * its own queued parts still refer to.
 *
 * ⚠ HOST OBLIGATION, STATED BECAUSE THIS PORT DOES NOT ENFORCE IT:
 * `marshal_scratch` must stay valid until every block part queued out of
 * it has been handled. One buffer is enough for a host that cannot begin
 * a second proposal before the internal queue has drained; a host that
 * can must double-buffer. The event loop polls the PEER queue (order 2)
 * before the INTERNAL queue (order 3), so a peer's vote can carry this
 * node into a new round — and a new proposal — while its own parts are
 * still queued. Raised as a RISK in this wave's report.
 */
typedef struct {
    cmt_block_t     blocks[CMT_CS_BLOCK_SLOTS];
    cmt_part_set_t  part_sets[CMT_CS_BLOCK_SLOTS];
    cmt_part_t     *parts[CMT_CS_BLOCK_SLOTS];
    size_t          parts_cap[CMT_CS_BLOCK_SLOTS];
    uint8_t        *payload[CMT_CS_BLOCK_SLOTS];
    size_t          payload_cap[CMT_CS_BLOCK_SLOTS];

    /** The proposer's own marshal target (:1223) — see above. */
    uint8_t        *marshal_scratch;
    size_t          marshal_scratch_cap;
    cmt_part_t     *marshal_parts;
    size_t          marshal_parts_cap;
    cmt_part_set_t  marshal_part_set;
} cmt_cs_slots_t;

/* ══ who owns cs.LastCommit ═══════════════════════════════════════════ */

/** The state machine, defined below. Named early because three of its own
 *  fields are function pointers that take it (state.go:132-134). */
typedef struct cmt_cs_s cmt_cs_t;

/** See "OWNERSHIP" (3). C only; Go has a garbage collector instead. */
typedef enum {
    /** `cs.LastCommit == nil` — state.go:692. */
    CMT_CS_LC_NONE = 0,
    /** It points INTO `cs->prev_votes`, the height vote set of the
     *  previous height — state.go:701. Freed with that set. */
    CMT_CS_LC_PREV_HVS = 1,
    /** A standalone vote set this module allocated with
     *  `cmt_commit_to_vote_set` / `cmt_extended_commit_to_extended_vote_set`
     *  — state.go:590, :607. Freed with `cmt_vote_set_free`. */
    CMT_CS_LC_OWNED = 2
} cmt_cs_lc_owner_t;

/* ══ the state ════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state.go:80-148 — `type State struct`.
 *
 * The embedded `cstypes.RoundState` (:102) is the `rs` field here; the
 * reference reads it as `cs.Height`, this port as `cs->rs.height`.
 *
 * ⚠ LARGE, AND NEVER A STACK OBJECT. `state` alone carries three
 * validator sets by value through its storage, and the two message queues
 * are rings of POINTERS to heap messages precisely so that the struct does
 * not carry 1000 × ~10 KB twice. Construct it with `cmt_cs_init` over
 * heap storage, exactly as the reference's `NewState` returns a pointer.
 */
struct cmt_cs_s {
    /* ── the reference's fields ────────────────────────────────────── */

    const cmt_config_t *config;              /* :84  */
    /** :85 — `privValidator types.PrivValidator`. A POINTER in Go, whose
     *  nil is a state the reference tests at :1170, :1280 and :2445; here
     *  the presence flag, set by `cmt_cs_set_priv_validator`. */
    bool                has_priv_validator;
    cmt_round_state_t   rs;                  /* :102 embedded */
    cmt_state_t         state;               /* :103 State until height-1 */
    /** :106 — the memoized `privValidatorPubKey`. `present` false is the
     *  reference's nil, which several sites test for. */
    cmt_pb_public_key_t priv_validator_pub_key;
    bool                priv_validator_pub_key_present;

    cmt_ticker_t        ticker;              /* :112 */
    bool                replay_mode;         /* :125 */
    bool                do_wal_catchup;      /* :126 */
    int                 n_steps;             /* :129 */
    int                 max_steps;           /* :784's argument, kept    */
    int64_t             offline_state_sync_height;   /* :147 */

    /** :132-134 — the three overridable functions. Defaulted by
     *  `cmt_cs_init` to the `cmt_cs_default_*` below, exactly as :183-185
     *  does; a caller may replace them, which is what the reference's own
     *  tests do. */
    int (*decide_proposal)(cmt_cs_t *cs, int64_t height, int32_t round);
    int (*do_prevote)(cmt_cs_t *cs, int64_t height, int32_t round);
    int (*set_proposal)(cmt_cs_t *cs, const cmt_proposal_t *proposal);

    /* ── the host ──────────────────────────────────────────────────── */

    cmt_cs_host_t       host;
    void               *host_ctx;
    cmt_cs_slots_t     *slots;

    /* ── the two queues (:110, :111) ───────────────────────────────── */

    /** Rings of POINTERS to heap `cmt_msg_info_t`, which is what a Go
     *  `chan msgInfo` really is: the channel buffer holds an interface
     *  word and the message lives on the heap. Each element is malloc'd on
     *  enqueue and freed on dequeue; a failed malloc is CMT_FAULT. */
    cmt_msg_info_t     *peer_q[CMT_CS_MSG_QUEUE_SIZE];
    size_t              peer_q_head;
    size_t              peer_q_len;
    cmt_msg_info_t     *internal_q[CMT_CS_MSG_QUEUE_SIZE];
    size_t              internal_q_head;
    size_t              internal_q_len;

    /** The reference's `<-cs.txNotifier.TxsAvailable()` (:827). A signal,
     *  set by `cmt_cs_notify_txs_available` and consumed by one
     *  `cmt_cs_step`. */
    bool                txs_available;
    /** The reference's `<-cs.Quit()` (:867). */
    bool                quit;
    /** The tock the ticker produced (ticker.go:137, state.go:858). One
     *  deep: the reference's `tockChan` carries one timeout at a time. */
    bool                tock_pending;
    cmt_timeout_info_t  tock;

    /* ── C-only lifetime bookkeeping ───────────────────────────────── */

    /** The height vote set the current `rs.last_commit` points into.
     *  See "OWNERSHIP" (3). */
    cmt_hvs_t          *prev_votes;
    cmt_cs_lc_owner_t   last_commit_owner;
    /** The standalone set of CMT_CS_LC_OWNED, so it can be freed. */
    cmt_vote_set_t     *last_commit_owned;

    /** Storage for `state` and for the `stateCopy` of :1770. Both are
     *  the caller's; `cmt_state_t` needs one `cmt_state_storage_t` each
     *  (cmt_state.h:229). */
    cmt_state_t         state_scratch;

    /** The two buffers the `validators.Copy()` of :1073 alternates
     *  between, so a copy never has its own source as its destination.
     *  `rs.validators` points at `&state.validators` or at one of these.
     *  Their storage is allocated by `cmt_cs_init` and freed by
     *  `cmt_cs_free`. */
    cmt_validator_set_t vals_buf[2];
    cmt_validator_t    *vals_buf_storage[2];
    size_t              vals_next;

    /** C-only. The validator set a CMT_CS_LC_OWNED `last_commit` borrows.
     *
     * In Go, `commit.ToVoteSet(state.ChainID, state.LastValidators)`
     * (:638) hands the vote set the SAME `*ValidatorSet` that `cs.state =
     * state` (:752) then names, so the two can never disagree and neither
     * can outlive the other. Here `cmt_state_t` is a value and the copy
     * into `cs->state` produces a second object, so a vote set borrowing
     * the caller's state would be left pointing at storage that
     * `finalizeCommit` reuses at :1770. This is that borrow's own copy; it
     * lives exactly as long as `last_commit_owned`. */
    cmt_validator_set_t last_commit_vals;
    cmt_validator_t    *last_commit_vals_storage;

    /** C-only. Storage for the proposal `rs.proposal` names.
     *
     * :1940 stores the caller's `*types.Proposal` POINTER, and in Go that
     * object is on the heap and outlives the `msgInfo` that carried it.
     * Here the message is a queue element this module frees the moment
     * `handleMsg` returns, so the proposal is COPIED into this field and
     * `rs.proposal` points here. Nothing else in the round state has this
     * problem: block parts and votes are copied into the part set and the
     * vote sets by the modules that own them. Their variable-length
     * payloads — a part's bytes and a vote's extension — are still the
     * HOST's arena, exactly as "OWNERSHIP" (2) states. */
    cmt_proposal_t      proposal_storage;

    /** The extension arena of "OWNERSHIP" (2). BORROWED from the host and
     *  never touched here; it is recorded so that the contract has a
     *  place to live and so the host can be asked for it once. */
    cmt_pb_arena_t     *ext_arena;
};

/* ══ construction (state.go:154-208) ══════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state.go:154-208 — `NewState()`.
 *
 * `config`, `host`, `slots` and the storages are BORROWED and must outlive
 * the state machine. The reference's `options ...StateOption` are two
 * setters (:223-231); `offline_state_sync_height` is the one the ported
 * code branches on (:194) and is a parameter here.
 *
 * The reference reconstructs `LastCommit` from the store when
 * `state.LastBlockHeight > 0` (:188-199) and then calls `updateToState`
 * (:201). Both happen here. It does NOT call `scheduleRound0` (:203) —
 * that is `cmt_cs_start`'s.
 *
 * @param state_storage storage for `cs->state`; must not be shared with
 *        `scratch_storage`.
 * @param scratch_storage storage for the `stateCopy` of :1770. The
 *        incoming `state` is copied here first, so that `cs->state` is
 *        still EMPTY when `updateToState` runs its :655-685 checks — the
 *        reference's `cs.state` is the OLD state at that point and a
 *        pre-copied one would trip the panic at :659.
 * @param ext_arena the per-height vote extension arena; see "OWNERSHIP"
 *        (2). May be NULL only on a chain where vote extensions are never
 *        enabled, and then `extend_vote` is never reached.
 * @return CMT_OK; CMT_REJECT from the state or vote sets it builds;
 *         CMT_FAULT on NULL, on allocation failure, or at the reference's
 *         panics in `reconstruct*Commit` (:588, :605) and `updateToState`.
 */
int cmt_cs_init(cmt_cs_t *cs,
                const cmt_config_t *config,
                const cmt_state_t *state,
                const cmt_cs_host_t *host, void *host_ctx,
                cmt_cs_slots_t *slots,
                cmt_state_storage_t *state_storage,
                cmt_state_storage_t *scratch_storage,
                cmt_pb_arena_t *ext_arena,
                int64_t offline_state_sync_height);

/** C only — releases everything `cs` allocated: both message queues, the
 *  height vote sets and any standalone LastCommit. Borrowed storage is not
 *  touched. NULL is a no-op. */
void cmt_cs_free(cmt_cs_t *cs);

/* ══ accessors (state.go:240-314) ═════════════════════════════════════ */

/** cometbft@709fd12b consensus/state.go:240-244 — `GetState()`. A COPY,
 *  as the reference's `cs.state.Copy()` is.
 *  @param out must already carry its own `cmt_state_storage_t`. */
int cmt_cs_get_state(const cmt_cs_t *cs, cmt_state_t *out);

/** cometbft@709fd12b consensus/state.go:248-252 — `GetLastHeight()`. */
int64_t cmt_cs_get_last_height(const cmt_cs_t *cs);

/** cometbft@709fd12b consensus/state.go:255-260 — `GetRoundState()`.
 *  The reference returns a SHALLOW copy; so does this, which means every
 *  pointer in it still refers to storage `cs` owns. */
int cmt_cs_get_round_state(const cmt_cs_t *cs, cmt_round_state_t *out);

/** cometbft@709fd12b consensus/state.go:277-281 — `GetValidators()`.
 *  @param out_height receives `state.LastBlockHeight`.
 *  @param out receives a COPY of the current validator set; it must
 *         already be `cmt_validator_set_init`ialised with storage. */
int cmt_cs_get_validators(const cmt_cs_t *cs, int64_t *out_height,
                          cmt_validator_set_t *out);

/** cometbft@709fd12b consensus/state.go:285-294 — `SetPrivValidator()`.
 *  Sets the presence flag and immediately refreshes the memoized public
 *  key (:291); a failure there is only logged, as at :292. */
int cmt_cs_set_priv_validator(cmt_cs_t *cs, bool present);

/** cometbft@709fd12b consensus/state.go:305-314 — `LoadCommit()`.
 *  @param out_found false is the reference's nil. */
int cmt_cs_load_commit(cmt_cs_t *cs, int64_t height, cmt_commit_t *out,
                       bool *out_found);

/* ══ lifecycle (state.go:318-441) ═════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state.go:318-405 — `OnStart()`, minus the
 * file-WAL half.
 *
 * PORTED: the catch-up replay when `do_wal_catchup` is set (:338-343,
 * :345-350), the double-signing check (:393-395) and `scheduleRound0`
 * (:402). NOT PORTED: the WAL repair loop (:352-385), `evsw.Start` (:388)
 * and `go cs.receiveRoutine` (:398) — the caller drives `cmt_cs_step`.
 *
 * The reference's classification at :344-350 is kept: a catch-up replay
 * that fails with something other than data corruption is LOGGED and the
 * state machine starts anyway (:348-350); a corruption error, which the
 * reference would try to repair, has no repair path here and is returned.
 *
 * @return CMT_OK; CMT_REJECT when the double-sign check found this key in
 *         a past block (:393-395 returning ErrSignatureFoundInPastBlocks);
 *         CMT_FAULT on NULL or a host failure.
 */
int cmt_cs_start(cmt_cs_t *cs);

/** cometbft@709fd12b consensus/state.go:432-441 — `OnStop()`. Stops the
 *  ticker (:437) and applies its action to the host's timer. The event
 *  switch of :433 is not ported. */
int cmt_cs_stop(cmt_cs_t *cs);

/* ══ inputs (state.go:477-532) ════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state.go:477-486 — `AddVote()`.
 *
 * The reference chooses the queue by `peerID == ""` (:478): an empty id is
 * internal. Here the empty id is `cmt_peer_id_self()` (cmt_vote_set.h:233)
 * and a message from this node carries `peer_id_len == 0`
 * (cmt_msgs.h:241-245).
 *
 * ⚠ The reference's two return values are `(false, nil)` ALWAYS (:485);
 * the vote has only been QUEUED. This returns CMT_OK for the same reason,
 * and CMT_REJECT when the peer queue is full — see the header.
 */
int cmt_cs_add_vote(cmt_cs_t *cs, const cmt_vote_t *vote,
                    const uint8_t *peer_id, size_t peer_id_len);

/** cometbft@709fd12b consensus/state.go:489-498 — `SetProposal()`. */
int cmt_cs_set_proposal_input(cmt_cs_t *cs, const cmt_proposal_t *proposal,
                              const uint8_t *peer_id, size_t peer_id_len);

/** cometbft@709fd12b consensus/state.go:501-510 — `AddProposalBlockPart()`. */
int cmt_cs_add_proposal_block_part_input(cmt_cs_t *cs, int64_t height,
                                         int32_t round,
                                         const cmt_part_t *part,
                                         const uint8_t *peer_id,
                                         size_t peer_id_len);

/** cometbft@709fd12b consensus/state.go:513-532 — `SetProposalAndBlock()`.
 *  The proposal, then every part of `parts` in index order (:524-529).
 *  The `block` parameter of :515 is unused in the reference too — its own
 *  TODO at :519 says so — and is not taken here. */
int cmt_cs_set_proposal_and_block(cmt_cs_t *cs, const cmt_proposal_t *proposal,
                                  const cmt_part_set_t *parts,
                                  const uint8_t *peer_id, size_t peer_id_len);

/** C only — the reference's `<-cs.txNotifier.TxsAvailable()` (:827) as a
 *  signal the host raises. One `cmt_cs_step` consumes it. */
void cmt_cs_notify_txs_available(cmt_cs_t *cs);

/** C only — the reference's `<-cs.Quit()` (:867). */
void cmt_cs_quit(cmt_cs_t *cs);

/**
 * C only — the host's timer expired. Takes the pending timeout out of the
 * ticker (ticker.go:130-137) and leaves it for the next `cmt_cs_step`,
 * which is the reference's `tockChan <- ti`.
 *
 * @return CMT_OK; CMT_FAULT when no timer was armed or a tock is already
 *         pending — both mean the HOST fired a timer this module did not
 *         ask for, which `stopTimer`'s drain (ticker.go:88-90) exists to
 *         prevent. A local defect, never a peer's doing.
 */
int cmt_cs_on_timer_expired(cmt_cs_t *cs);

/* ══ the event loop (state.go:784-872) ════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state.go:784-872 — `receiveRoutine`, one
 * iteration.
 *
 * Handles AT MOST ONE event, in the fixed order named in the file header.
 * The round state is snapshotted before the poll (:823) and the snapshot —
 * not the live one — is what `handleTimeout` compares against (:865).
 *
 * @param out_worked false means every source was empty; the caller waits.
 *        May be NULL.
 * @return CMT_OK; CMT_REJECT is never returned (the reference's `handleMsg`
 *         swallows every message error into a log line at :954-963);
 *         CMT_FAULT on NULL, a WriteSync failure (:841-844), an internal
 *         queue overflow, or any node-local invariant below.
 */
int cmt_cs_step(cmt_cs_t *cs, bool *out_worked);

/** True when `cmt_cs_step` would do something — a signal, a queued
 *  message, a tock or a quit. C only; Go blocks in `select` instead. */
bool cmt_cs_has_work(const cmt_cs_t *cs);

/* ══ the transitions (state.go:875-2066) ══════════════════════════════ */
/* Public because wave T's scenario suite drives them directly, exactly as
 * consensus/state_test.go does. Every one takes `cs` where the reference
 * has a receiver. */

/** cometbft@709fd12b consensus/state.go:875-964 — `handleMsg`. */
int cmt_cs_handle_msg(cmt_cs_t *cs, const cmt_msg_info_t *mi);

/** cometbft@709fd12b consensus/state.go:966-1014 — `handleTimeout`.
 *  @param rs the round state as it was when the tock was taken off the
 *         queue (:823, :865), NOT the live one. */
int cmt_cs_handle_timeout(cmt_cs_t *cs, const cmt_timeout_info_t *ti,
                          const cmt_round_state_t *rs);

/** cometbft@709fd12b consensus/state.go:1016-1039 — `handleTxsAvailable`. */
int cmt_cs_handle_txs_available(cmt_cs_t *cs);

/** cometbft@709fd12b consensus/state.go:1053-1115 — `enterNewRound`. */
int cmt_cs_enter_new_round(cmt_cs_t *cs, int64_t height, int32_t round);

/** cometbft@709fd12b consensus/state.go:1119-1132 — `needProofBlock`. */
int cmt_cs_need_proof_block(cmt_cs_t *cs, int64_t height, bool *out);

/** cometbft@709fd12b consensus/state.go:1140-1198 — `enterPropose`. */
int cmt_cs_enter_propose(cmt_cs_t *cs, int64_t height, int32_t round);

/** cometbft@709fd12b consensus/state.go:1204-1255 — `defaultDecideProposal`. */
int cmt_cs_default_decide_proposal(cmt_cs_t *cs, int64_t height,
                                   int32_t round);

/** cometbft@709fd12b consensus/state.go:1259-1270 — `isProposalComplete`. */
int cmt_cs_is_proposal_complete(cmt_cs_t *cs, bool *out);

/** cometbft@709fd12b consensus/state.go:1319-1343 — `enterPrevote`. */
int cmt_cs_enter_prevote(cmt_cs_t *cs, int64_t height, int32_t round);

/** cometbft@709fd12b consensus/state.go:1345-1403 — `defaultDoPrevote`. */
int cmt_cs_default_do_prevote(cmt_cs_t *cs, int64_t height, int32_t round);

/** cometbft@709fd12b consensus/state.go:1406-1434 — `enterPrevoteWait`. */
int cmt_cs_enter_prevote_wait(cmt_cs_t *cs, int64_t height, int32_t round);

/** cometbft@709fd12b consensus/state.go:1442-1561 — `enterPrecommit`. */
int cmt_cs_enter_precommit(cmt_cs_t *cs, int64_t height, int32_t round);

/** cometbft@709fd12b consensus/state.go:1564-1593 — `enterPrecommitWait`. */
int cmt_cs_enter_precommit_wait(cmt_cs_t *cs, int64_t height, int32_t round);

/** cometbft@709fd12b consensus/state.go:1596-1656 — `enterCommit`. */
int cmt_cs_enter_commit(cmt_cs_t *cs, int64_t height, int32_t commit_round);

/** cometbft@709fd12b consensus/state.go:1659-1684 — `tryFinalizeCommit`. */
int cmt_cs_try_finalize_commit(cmt_cs_t *cs, int64_t height);

/** cometbft@709fd12b consensus/state.go:1687-1810 — `finalizeCommit`. */
int cmt_cs_finalize_commit(cmt_cs_t *cs, int64_t height);

/** cometbft@709fd12b consensus/state.go:1903-1950 — `defaultSetProposal`. */
int cmt_cs_default_set_proposal(cmt_cs_t *cs, const cmt_proposal_t *proposal);

/** cometbft@709fd12b consensus/state.go:1955-2031 — `addProposalBlockPart`.
 *  @param out_added the reference's `added`; may be NULL. */
int cmt_cs_add_proposal_block_part(cmt_cs_t *cs,
                                   const cmt_block_part_msg_t *msg,
                                   const cmt_peer_id_t *peer,
                                   bool *out_added);

/** cometbft@709fd12b consensus/state.go:2033-2066 — `handleCompleteProposal`. */
int cmt_cs_handle_complete_proposal(cmt_cs_t *cs, int64_t block_height);

/** cometbft@709fd12b consensus/state.go:2069-2118 — `tryAddVote`.
 *
 *  `addVote` (:2120-2363) is NOT exported. In the reference it is a
 *  private method with exactly one caller, this one, and the only safe
 *  way to add a vote IS through this one: it is where a conflicting vote
 *  reaches the evidence pool (:2094). Wave C exported a wrapper around it
 *  "for wave T"; wave T never called it, and verifier BYZ found that the
 *  wrapper passed no conflict sink, so an equivocation entering through it
 *  would have been swallowed. Removed as dead code that bypassed the
 *  evidence pool. */
int cmt_cs_try_add_vote(cmt_cs_t *cs, const cmt_vote_t *vote,
                        const cmt_peer_id_t *peer, bool *out_added);

/** cometbft@709fd12b consensus/state.go:2416-2435 — `voteTime()`.
 *  `now`, raised to `LockedBlock.Time + 1ms` or `ProposalBlock.Time + 1ms`
 *  when either of those is later. THE ONLY CLOCK READ IN A VOTE'S LIFE
 *  besides the signer's. */
int cmt_cs_vote_time(cmt_cs_t *cs, cmt_time_t *out);

/** cometbft@709fd12b consensus/state.go:2439-2474 — `signAddVote`.
 *  Signs and pushes onto the internal queue; it never transitions. */
int cmt_cs_sign_add_vote(cmt_cs_t *cs, int32_t msg_type,
                         const uint8_t *hash, size_t hash_len,
                         const cmt_part_set_header_t *header,
                         cmt_block_t *block);

/** cometbft@709fd12b consensus/state.go:2479-2490 —
 *  `updatePrivValidatorPubKey`. */
int cmt_cs_update_priv_validator_pub_key(cmt_cs_t *cs);

/** cometbft@709fd12b consensus/state.go:2493-2515 —
 *  `checkDoubleSigningRisk`.
 *  @return CMT_OK; CMT_REJECT for the reference's
 *          ErrSignatureFoundInPastBlocks (:2507). */
int cmt_cs_check_double_signing_risk(cmt_cs_t *cs, int64_t height);

/** cometbft@709fd12b consensus/state.go:2600-2617 — `CompareHRS()`.
 *  −1, 0 or 1. Its consumer is the reactor (reactor.go:1368), wave R3.
 *  A free function in Go, so no `cs` in the name (the map's naming rule;
 *  it shipped as `cmt_cs_compare_hrs` and was renamed at the R2 close). */
int cmt_compare_hrs(int64_t h1, int32_t r1, cmt_round_step_t s1,
                    int64_t h2, int32_t r2, cmt_round_step_t s2);

/* ══ internal transitions the loop uses, exposed for wave T ═══════════ */

/** cometbft@709fd12b consensus/state.go:647-756 — `updateToState`. */
int cmt_cs_update_to_state(cmt_cs_t *cs, const cmt_state_t *state);

/** cometbft@709fd12b consensus/state.go:556-560 — `scheduleRound0`. */
int cmt_cs_schedule_round0(cmt_cs_t *cs, const cmt_round_state_t *rs);

/** cometbft@709fd12b consensus/state.go:563-565 — `scheduleTimeout`. */
int cmt_cs_schedule_timeout(cmt_cs_t *cs, int64_t duration_ns, int64_t height,
                            int32_t round, cmt_round_step_t step);

/* ══ replay (replay.go:39-167) ════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/replay.go:39-90 — `readReplayMessage`.
 *
 * One WAL record applied as if it had arrived in the event loop. An
 * END_HEIGHT record is skipped (:41-43); a round-state record is COMPARED
 * against the live one when `newStepSub` is set, and `catchupReplay`
 * passes nil (:161), so the comparison never runs on this path and the
 * `newStepSub` parameter has no C counterpart. A message record goes
 * through `handleMsg` (:82) and a timeout record through `handleTimeout`
 * against the LIVE round state (:85).
 *
 * @return CMT_OK; CMT_REJECT for a record kind the WAL should not contain
 *         (:86-88); CMT_FAULT on NULL or a node-local failure below.
 */
int cmt_cs_read_replay_message(cmt_cs_t *cs,
                               const cmt_timed_wal_message_t *msg);

/**
 * cometbft@709fd12b consensus/replay.go:94-167 — `catchupReplay`.
 *
 * THE END_HEIGHT RULE, which is the whole sanity check: a record for
 * `cs_height` must NOT exist (:106-117) and one for `cs_height − 1` MUST
 * (:129-137), except that at the initial height the marker looked for is 0
 * (:126-128). `replay_mode` is set for the duration (:97-98) so that
 * signing failures are not logged.
 *
 * ⚠ The reference APPENDS to the WAL during replay (wal.go:73-75) because
 * the ported core calls the same WAL callbacks it does live — D-15 rev 5
 * states the host must not suppress them. That is reproduced here.
 *
 * @return CMT_OK; CMT_REJECT when the END_HEIGHT rule is violated or the
 *         height is below the initial height (:122-124); CMT_FAULT on
 *         NULL or a host failure.
 */
int cmt_cs_catchup_replay(cmt_cs_t *cs, int64_t cs_height);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_CS_H */
