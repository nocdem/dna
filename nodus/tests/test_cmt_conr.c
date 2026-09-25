/**
 * Nodus — cometbft @709fd12b C port, wave R3-A: the test suite for
 * `shared/dnac/cmt_conr.c` (the consensus REACTOR) and
 * `shared/dnac/cmt_ps.c` (PeerState), ported from
 * `consensus/reactor_test.go`. Every scenario names the Go `func Test…`
 * it comes from and its line range; every assertion that is STRONGER or
 * WEAKER than the reference's says so at the site.
 *
 * The fixture behind each node is `test_cmt_common.h` (the C stand-in for
 * `consensus/common_test.go`, read-only here); the NETWORK — the
 * reference's in-process p2p switches (`p2p.MakeConnectedSwitches`,
 * reactor_test.go:77-81) — is the IN-MEMORY SWITCH written in this file:
 * N `cmt_cs_t` + N `cmt_conr_t` + a matrix of per-link, per-channel
 * message queues delivered in index order. Unlike `test_cmt_multinode.h`
 * (whose M1 says its router is NOT the reactor), the router here IS the
 * reactor: every byte a node receives went through `cmt_conr_receive`,
 * and every byte it sends left through the reactor's host `send` row.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *   · THE TEN ValidateBasic METHODS refuse exactly the rows the reference
 *     refuses (reactor_test.go:792-1100, :1131-1165), including the
 *     ValidateHeight gate against a non-1 initial height.
 *   · RECEIVE BEFORE AddPeer IS FINE AND RECEIVE BEFORE InitPeer IS A
 *     FAULT (:248-305) — the port's reading of the reference's panic at
 *     reactor.go:255 as NODE-LOCAL.
 *   · (W1.7) TWO PORT-ONLY REFUSALS, neither with a Go test row:
 *     `SetHasProposal` (reactor.go:1096-1119) applies NOTHING when the
 *     bit array it needs cannot be built — the reference's constructor
 *     cannot fail, so it writes the flag and the header first, and in
 *     that order a refusal left the PeerState half applied (R3-AUD-21);
 *     and a reactor that has been STOPPED refuses to start again, which
 *     is libs/service/service.go:132-137's ErrAlreadyStopped, since
 *     `Reset` (:200-215) is not ported (R3-AUD-20).
 *   · SwitchToConsensus REFUSES TO START ON A STORE THAT LACKS THE VOTE
 *     EXTENSIONS ITS PARAMS REQUIRE, and starts otherwise (:309-415) — the
 *     five rows, CMT_FAULT where the reference panics.
 *   · A NETWORK OF FOUR REACTORS MAKES BLOCKS (:112-122): proposals, block
 *     parts, votes, NewRoundStep / NewValidBlock / HasVote broadcasts,
 *     VoteSetMaj23 queries and VoteSetBits replies all cross the wire as
 *     proto3 BYTES through the reactor's receive path, the PeerState
 *     bookkeeping decides what to gossip, and every node commits height 1
 *     (and, in the voting-power scenario, thirteen heights).
 *   · IT MAKES BLOCKS WITH create_empty_blocks = false AND A TRANSACTION
 *     (:225-246), WITH skip_timeout_commit = false AND ONE VALIDATOR
 *     ABSENT (:637-653), AND ACROSS THREE VOTING-POWER CHANGES OF ONE
 *     VALIDATOR (:442-521), where every block's LastCommit carries every
 *     active validator's signature (`validateBlock`, :746-760).
 *   · THE FULL-QUEUE PATH IS WIRED, NOT BYPASSED: every link's queues are
 *     sized to the channels' SendQueueCapacity (100/100/100/2,
 *     reactor.go:150-174) and `send` returns false when one is full —
 *     but whether that ever happens on these schedules is NOT observed
 *     (HOW IT CAN LIE (R14)).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION`, defined by the nodus build for
 *   every cmt_* target (shared/dnac/cmt_state.h:150 refuses to compile
 *   without it). NOTHING ELSE — a DEFAULT BUILD. `QGP_FAULT_INJECT` is NOT
 *   set; the six fail points of cmt_cs.h:189-198 compile to `((void)0)`
 *   and nothing here depends on one.
 * ENVIRONMENT: none. No variable is read (`FAIL_TEST_INDEX` is never set).
 *   No network, no files, no database, no wall clock (the fixture's frozen
 *   `tc->now` is advanced by this file in fixed quanta — see HOW IT CAN
 *   LIE (R3)), no randomness beyond ML-DSA-87's internal signing
 *   randomness and `cmt_bits_pick_random` (gossip choice only).
 * ⚠ MEMORY, all heap: four fixtures at ~6 MB each (test_cmt_common.h),
 *   plus per node an 8 MiB receive arena, a 1 MiB reactor send buffer,
 *   a 32-height block store and a 1 MB state copy, plus the link queues.
 *   About 70 MB for four nodes; freed by `r_net_free`.
 * ⚠ TIME. Every vote is a real ML-DSA-87 signature verified by every node
 *   that receives it; the voting-power scenario walks thirteen heights
 *   on four nodes — on the order of 500 signatures and 1500
 *   verifications. It is the slow one.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on disk, nothing in the environment, no processes. ONE piece
 * of static state: `g_r_net`, the network currently alive, which the
 * fixture's host callbacks need because they receive the fixture (`tc`)
 * and not the node (the same shape as `g_mn_net` in
 * test_cmt_multinode.h). `r_net_free` clears it; two networks alive at
 * once is refused by `r_net_new`.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 * The fixture's twelve ways (test_cmt_common.h) all apply, per node.
 * These are this file's own:
 *  R1. THE SWITCH IS ONE LEGAL SCHEDULE. Per network round, node 0, 1, …
 *      in index order: deliver every frame queued for it (senders in
 *      index order, channels in descriptor order, FIFO), ONE `cmt_cs_step`
 *      if it has work, the timer rule, one `cmt_conr_tick`. The
 *      reference's goroutines interleave arbitrarily and its MConnection
 *      picks channels by priority; this is one of the schedules they
 *      could produce, fixed for reproducibility, not representative.
 *  R2. A FULL PEER QUEUE STOPS DELIVERY FROM THAT PEER FOR THE ROUND.
 *      `cmt_conr_receive` answering CMT_REJECT (R3-A-2: the state
 *      machine's peer queue is full) leaves the frame where it is and
 *      stops that sender's delivery until the next round — the
 *      reference's blocked recv goroutine. The frame is then RE-DELIVERED
 *      whole, so its PeerState side effects (SetHasVote, SetHasProposal
 *      …) are applied twice; they are idempotent. No scenario here fills
 *      the 1000-deep queue; the rule is stated, not exercised.
 *  R3. THE CLOCK ADVANCES IN FIXED QUANTA, ONE VALUE FOR ALL NODES. The
 *      reactor's fourteen `time.Sleep` sites are deadlines against the
 *      host clock (cmt_conr.h), so a frozen clock would put every routine
 *      to sleep forever. Each round advances every node's `tc->now` by
 *      R_ROUND_NS (5 ms = PeerGossipSleepDuration of the test config, so
 *      one gossip sleep is one round and one maj23 sleep is fifty). Real
 *      nodes have different clocks and different sleep/tick ratios; a
 *      defect that shows only under clock skew is invisible here.
 *  R4. `decode_block` LOOKS UP EVERY NODE'S REGISTRY. The fixture's
 *      decoder is a byte-for-byte lookup over the blocks it made itself
 *      (test_cmt_common.h HOW IT CAN LIE (1)); a block node i proposed is
 *      in node i's registry only. Instead of mirroring records into every
 *      node (test_cmt_multinode.h M7), this file's decoder searches ALL
 *      nodes' registries — the network is one process — and hands back
 *      the PROPOSER's record, whose `txs` and `last_commit` storage the
 *      receiver's block slot then points at ACROSS FIXTURES. Safe because
 *      every record lives until `r_net_free` tears all fixtures down
 *      together, and because nothing writes through those pointers. What
 *      it hides is what the fixture's (1) hides: a marshal/unmarshal
 *      asymmetry. It also keeps each registry at its own proposals, which
 *      is what lets the thirteen-height scenario fit TC_BLOCK_RECS = 12.
 *  R5. CATCH-UP PARTS COME FROM THE PROPOSER'S REGISTRY, NOT FROM A STORE
 *      THAT KEPT THEM (as test_cmt_multinode.h M8): `bs_load_block_part`
 *      finds the committed block's hash in the store's seen commit, the
 *      record with that hash in any registry, and a part set built over
 *      that record's marshalled bytes. Same bytes, different shelf.
 *  R6. THE BLOCK STORE IS THIS FILE'S, NOT THE FIXTURE'S. The fixture's
 *      store keeps TC_STORE_MAX = 8 heights and the voting-power scenario
 *      commits thirteen, so every `bs_*` row of BOTH host tables is
 *      replaced by the same logic over a 32-height array (`r_store_*`,
 *      copied line for line from the fixture's `tc_bs_*` with the
 *      capacity changed). The fixture's `tc->store` / `store_height` are
 *      never written and never read here.
 *  R7. THE `val=` TRANSACTION IS A TEST STAND-IN. The reference's
 *      TestReactorVotingPowerChange changes a validator's power through
 *      the kvstore application's `val=<type>!<base64 pubkey>!<power>`
 *      transaction (abci/example/kvstore/helpers.go:72-80 MakeValSetChangeTx;
 *      kvstore.go:413-444 isValidatorTx/parseValidatorTx; :220-225 the
 *      FinalizeBlock collection into ValidatorUpdates), which
 *      state/execution.go:603-617 `updateState` applies to
 *      NextValidators. The application is not part of the port (pin
 *      record rev 15: kvstore is pinned as a TEST STAND-IN, never a rule
 *      of the port); here `r_apply_verified_block` parses the same string
 *      out of the committed block's txs and applies the change set with
 *      `cmt_validator_set_update_with_change_set` exactly where
 *      execution.go does (update, THEN IncrementProposerPriority(1)). It
 *      does NOT call the fixture's `tc_apply_verified_block`, which
 *      increments before any update could be inserted; it reproduces its
 *      three copies and its bookkeeping instead. The kvstore's key type
 *      string is `mldsa87` (umbrella substitution 2; the reference's
 *      would be ed25519), its base64 is RFC 4648 standard with padding
 *      (Go's `base64.StdEncoding`), reimplemented here because
 *      `qgp_base64_encode` (shared/crypto/utils/qgp_utils_standalone.c) is
 *      not linked into the nodus test targets.
 *  R8. THE MEMPOOL IS `next_txs`. A transaction "CheckTx'd" into a node
 *      is appended to the fixture's `next_txs` (the fixture proposes what
 *      it holds); a committed transaction is removed from every node's
 *      pending list by the apply wrapper (the reference's
 *      `mempool.Update`). Nothing rechecks, nothing gossips transactions
 *      (R3-M's Flood mempool is not here), so a transaction reaches a
 *      block only through a node it was submitted to — which is why the
 *      wait helpers submit to EVERY node, as the reference's do (:672-678).
 *  R9. "EVERYONE MAKES A BLOCK" IS THE APPLY COUNTER. The reference waits
 *      on each node's NewBlock event subscription (:66, :119-121); here a
 *      per-node cursor over `tc->apply_calls` consumes one applied block
 *      per wait, in height order, and reads the block back from this
 *      file's store and the registry (R4). A node that applied a block
 *      without ever publishing an event is indistinguishable from one
 *      that did.
 * R10. TIMERS ARE THE MOCK TICKER'S (test_cmt_multinode.h M5): an armed
 *      timer fires iff its step is RoundStepNewHeight, immediately; with
 *      `only_once` (common_test.go:918-955, `newMockTickerFunc(true)`)
 *      only the FIRST such timeout ever fires, so every later height is
 *      entered through `SkipTimeoutCommit && HasAll` (state.go:2161,
 *      :2347) — which is also what makes every commit carry every
 *      validator, and what `validateBlock` then asserts. No honest node
 *      ever sees timeoutPropose/Prevote/Precommit here; exactly the
 *      reference's choice, and exactly as blind.
 * R11. THE VOTE-EXTENSION SCENARIO WRITES THE STATE MACHINE'S FIELDS
 *      DIRECTLY (`cs.state.LastBlockHeight`, `cs.Height`, … :359-370),
 *      because the reference test does; the fixture's "never behind its
 *      back" principle is set aside for exactly those five writes.
 * R12. THE STEP BUDGET IS A LIVENESS BOUND OF THIS SCHEDULE (as
 *      test_cmt_multinode.h M14). `timeoutWaitGroup`'s twenty seconds
 *      (:780) becomes R_BUDGET_ROUNDS network rounds per wait; exhausting
 *      it FAILS and dumps every node. Never a skip.
 * R13. NO PEER IS EVER DISCONNECTED FOR AN ERROR here, and the suite
 *      ASSERTS that (STRONGER than the reference, which never looks): a
 *      `stop_peer_for_error` call is a decode or validation failure of an
 *      honest peer's bytes, i.e. a codec or gate defect, and fails the
 *      scenario at once.
 * R14. A FULL SEND QUEUE IS NOT OBSERVED. `r_send` returns false when a
 *      link's per-channel FIFO is at SendQueueCapacity (the VoteSetBits
 *      queue holds two frames, reactor.go:174), and DEVIATION R3-A-1
 *      then ends the routine's pass to retry next tick — but no counter
 *      and no assertion records that a `send` ever returned false, so
 *      every scenario passes whether that retry path was taken or not.
 *
 * ── NOT PORTED — BLOCKED BY ────────────────────────────────────────────
 *   · `TestReactorWithEvidence` (:125-220) — BLOCKED BY R3-E: it needs an
 *     evidence pool whose `PendingEvidence` returns a duplicate-vote
 *     evidence for every proposer (:177-188) and a block executor that
 *     puts it in the block; the fixture has neither
 *     (test_cmt_common.h:693-694, "no evidence pool").
 *   · `TestReactorRecordsVotesAndBlockParts` (:418-437) — BLOCKED BY the
 *     port map's YOK of `peerStatsRoutine` (reactor.go:947-985) and by
 *     `cs.statsMsgQueue` not being in cmt_cs (cmt_cs.c:1533; state.go:913,
 *     :931): `RecordVote` / `RecordBlockPart` are ported (cmt_ps.h) but
 *     nothing calls them, so `VotesSent() > 0` (:435) can never hold.
 *   · `TestReactorValidatorSetChanges` (:523-634) — BLOCKED BY the
 *     fixture's TC_MAX_VALS = 4 (test_cmt_common.h:285): it runs SEVEN
 *     nodes, three of them non-validators that JOIN the set, so commits
 *     grow to five and then seven signatures; every commit-signature
 *     array of the fixture (`tc_block_rec_t.sigs`, `tc_store_ent_t.
 *     seen_sigs`/`ext_sigs`/`commit_sigs`, `ecsigs`, `cap_ecsigs`) holds
 *     four, and `tc_create_proposal_block` (:748-750) and the store rows
 *     (:1191) fault above it. The exact fixture hunk is in the wave
 *     report's QUESTIONS.
 *   · `TestMarshalJSONPeerState` (:1102-1129) — YOK (JSON is not ported).
 *   · `waitForBlockWithUpdatedValsAndValidateIt` (:716-743) — a helper
 *     only the blocked ValidatorSetChanges uses; not written (no caller).
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/reactor_test.go   1165 lines
 *     012e907d3f5e785b9fe2d50365e72831c6a85bc75d1cab0ad9e0c9c69b1790db
 *   consensus/reactor.go        1817 lines
 *     b7b4fdd346d99d32b713e82f8dcc95a0ac1b1c3a4b25d7d8c3283fc33dd33427
 *   consensus/common_test.go     991 lines
 *     3e3940e51975f030a0190bc2b5217d93ee768eef30097d8b14b379b006023a38
 *     (:48-92 startConsensusNet is reactor_test.go's; here :392-447,
 *      :767-800, :803-861, :918-955 — the net builders and the mock ticker)
 *   consensus/state.go          2653 lines
 *     f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *     (:647-756 updateToState, :1279-1313 createProposalBlock, :2161,
 *      :2347 the SkipTimeoutCommit entries)
 *   config/config.go            1283 lines
 *     f0c2f601d49e1a56b36e8d557387e96ee53ecc3616ecb79749b0f71c0f218c21
 *     (:1037-1052 TestConsensusConfig — the config every reactor test
 *      runs under, through internal/test/config.go:12-16, :41
 *      `config.TestConfig()`, 99 lines
 *      b667d850773dbad0cc60d9ea17a9783416a2ffab9e3d4e2d2271bfb07a5d6e28,
 *      pin revision 10)
 *   state/execution.go           789 lines
 *     d12730b67e48c4863963c929067905d475543fcd135b99eaa909c502ebecae55
 *     (:567-590 validateValidatorUpdates, :592-661 updateState)
 *   abci/example/kvstore/kvstore.go 553 lines — TEST STAND-IN (pin rev 15)
 *     2501edc6b5fb22ce9f7cd9c17e17d530fbeff9b7b1458a035ded29c786786901
 *     (:28 ValidatorPrefix "val=", :130-142 CheckTx, :218-229 FinalizeBlock's
 *      tx loop, :413-444 isValidatorTx / parseValidatorTx)
 *   abci/example/kvstore/helpers.go 80 lines
 *     5e1d0df891a32eb258bccad3e2c4b42fdea88c835d5dcc31214c52241c3c9b9c
 *     (:66-68 NewTxFromID, :72-80 MakeValSetChangeTx)
 *   abci/example/kvstore/code.go 10 lines
 *     166ac50ecdf78f0c02f50a6a9a76e9b70bb72ffd3ffce3114061a21c2c6be821
 *   p2p/switch.go                865 lines
 *     5c6a08f26131b80cd8bdcf7bc2c673cc2d173e1a460e08a791db400070aa6fdf
 *     (:813-865 addPeer — the InitPeer / Start / Add / AddPeer order the
 *      in-memory switch reproduces)
 *
 * ── CONFIG: THE REFERENCE'S TEST CONFIG, NOT ITS DEFAULTS ──────────────
 * `randConsensusNet` builds every state with `ResetConfig` →
 * `config.TestConfig()` → `TestConsensusConfig()` (config.go:1037-1052):
 * the defaults of :1017-1034 with the six timeouts shortened,
 * SkipTimeoutCommit = true, PeerGossipSleepDuration = 5 ms and
 * PeerQueryMaj23SleepDuration = 250 ms. `r_test_consensus_config` applies
 * exactly those lines over `cmt_config_default`. The chain's own values
 * (D-4 rev 3) are the HOST's and are deliberately not used.
 *
 * @file test_cmt_conr.c
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "test_cmt_common.h"

#include "dnac/cmt_conr.h"
#include "dnac/cmt_ps.h"

/* ══ dimensions ═══════════════════════════════════════════════════════ */

/** Every ported network scenario runs N = 4 (reactor_test.go:113, :226,
 *  :443, :638). Bounded by the fixture's validator count. */
#define R_MAX_NODES        TC_MAX_VALS

/** Heights this file's block store keeps (HOW IT CAN LIE (R6)). The
 *  voting-power scenario commits 13; a failed round or a transaction
 *  spread over two blocks adds a few. */
#define R_STORE_MAX        32

/** The receive arena per node (cmt_conr.h "THE RECEIVE ARENA"). PACKAGE
 *  C2e, register R3-A-5: `cmt_conr_receive` now resets `.used` to 0 at
 *  the top of every call, so this size is generous headroom rather than
 *  a cumulative budget — sized from: ~23 KB per block part at four
 *  validators, up to three copies per height, thirteen heights ≈ 1 MB;
 *  8 MiB is eight times that. `s_recv_arena_resets_every_receive` proves
 *  the reset directly by pushing several times this many bytes through
 *  ONE node without ever approaching exhaustion. A decode failure still
 *  reaches `stop_peer_for_error` → a LOUD failure (R13); it is no longer
 *  reachable via arena exhaustion for a message the channel admitted
 *  (cmt_conr.h "THE RECEIVE ARENA"). */
#define R_ARENA_CAP        (8u * 1024u * 1024u)

/** The clock quantum per network round (HOW IT CAN LIE (R3)):
 *  PeerGossipSleepDuration of the test config, config.go:1048. */
#define R_ROUND_NS         ((int64_t)5 * CMT_MILLISECOND)

/** `timeoutWaitGroup`'s 20 s (reactor_test.go:780) as network rounds
 *  (HOW IT CAN LIE (R12)). One height takes on the order of ten to
 *  forty rounds on this schedule (a proposal, its part, the prevotes and
 *  the precommits each cross the wire on their own round, and a gossip
 *  sleep is one round); a maj23 query sleeps fifty. Two thousand is an
 *  order of magnitude of slack per waited block. Exhaustion FAILS. */
#define R_BUDGET_ROUNDS    2000

/** Transactions pending in a node's stand-in mempool (R8): the fixture
 *  proposes at most TC_MAX_TXS. */
#define R_TX_MAX_LEN       4096u

/* ══ assertion plumbing ═══════════════════════════════════════════════ */

typedef struct r_net_s r_net_t;
static void r_net_free(r_net_t *net);

/** As test_cmt_cs.c's S_CHECK: report, free the network named `net`,
 *  return 1. Every scenario names its network `net`. */
#define R_CHECK(cond, msg) do {                                           \
    if (!(cond)) {                                                        \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n",                    \
                __FILE__, __LINE__, (msg));                               \
        r_net_free(net);                                                  \
        return 1;                                                         \
    }                                                                     \
    g_tc_checks++;                                                        \
} while (0)

/** Run a helper that already reported its own failure. */
#define R_STEP(expr) do {                                                 \
    if ((expr) != 0) {                                                    \
        r_net_free(net);                                                  \
        return 1;                                                         \
    }                                                                     \
} while (0)

/** A check inside a helper that has no network to free. */
#define R_HCHECK(cond, msg) do {                                          \
    if (!(cond)) {                                                        \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n",                    \
                __FILE__, __LINE__, (msg));                               \
        return 1;                                                         \
    }                                                                     \
    g_tc_checks++;                                                        \
} while (0)

#define R_PREVOTE   ((int32_t)CMT_PB_MSG_TYPE_PREVOTE)
#define R_PRECOMMIT ((int32_t)CMT_PB_MSG_TYPE_PRECOMMIT)

/* ══ the in-memory switch: frames and links ═══════════════════════════ */

/** One marshalled envelope in flight on a link, on one channel. */
typedef struct {
    uint8_t *buf;
    size_t   len;
} r_frame_t;

/** The four channels of reactor.go:144-180 by descriptor index. */
static int r_channel_index(uint8_t channel_id)
{
    switch (channel_id) {
    case CMT_CONR_STATE_CHANNEL:         return 0;
    case CMT_CONR_DATA_CHANNEL:          return 1;
    case CMT_CONR_VOTE_CHANNEL:          return 2;
    case CMT_CONR_VOTE_SET_BITS_CHANNEL: return 3;
    default:                             return -1;
    }
}

/** Per directed link i → j: one FIFO per channel, sized by the
 *  channel's SendQueueCapacity (reactor.go:150, :158, :166, :174) so that
 *  `send` can return false. */
typedef struct {
    r_frame_t *q[CMT_CONR_NUM_CHANNELS];
    size_t     cap[CMT_CONR_NUM_CHANNELS];
    size_t     head[CMT_CONR_NUM_CHANNELS];
    size_t     len[CMT_CONR_NUM_CHANNELS];
} r_link_t;

/* ══ one node ═════════════════════════════════════════════════════════ */

typedef struct {
    size_t                 index;
    tc_t                  *tc;
    cmt_conr_t             conR;
    /** The 32-byte id this node presents (substitution 9). Distinct per
     *  node and never all-zero (that is "self", cmt_vote_set.h:231-242). */
    uint8_t                id[CMT_PB_PEER_ID_MAX];
    cmt_pb_arena_t         recv_arena;
    /** common_test.go:929-935 — the mock ticker's `onlyOnce` and `fired`. */
    bool                   only_once;
    bool                   fired;
    /** Whether `startConsensusNet` gave this node a reactor and started
     *  it (TestReactorWithTimeoutCommit starts N-1 of N, :646). */
    bool                   started;
    /** `stop_peer_for_error` calls (R13). */
    int                    stop_calls;
    int                    last_stop_reason;
    /** This file's block store (R6). */
    tc_store_ent_t         store[R_STORE_MAX];
    int64_t                store_height;
    /** Catch-up parts (R5): a part set per record of THIS node's
     *  registry, built lazily over the record's marshalled bytes. */
    cmt_part_t            *rec_parts[TC_BLOCK_RECS];
    cmt_part_set_t         rec_ps[TC_BLOCK_RECS];
    bool                   rec_ps_built[TC_BLOCK_RECS];
    /** The stand-in mempool's transaction storage (R8). */
    uint8_t                tx_store[TC_MAX_TXS][R_TX_MAX_LEN];
    /** The `GetState()` copy `SwitchToConsensus` is handed (:88-89). */
    cmt_state_storage_t   *state_copy_storage;
    cmt_state_t           *state_copy;
    /** Scratch for the apply wrapper (R7): the change set. */
    cmt_validator_t       *changes;
    /** The per-node NewBlock-event cursor (R9). */
    int                    consumed_blocks;
    /** A `cmt_cs_step` that returned non-OK, for the dump. */
    int                    fault_rc;
} r_node_t;

/* ══ the network ══════════════════════════════════════════════════════ */

struct r_net_s {
    size_t     n;            /* nodes                         */
    size_t     nvals;        /* validators in the genesis      */
    r_node_t   nodes[R_MAX_NODES];
    bool       connected[R_MAX_NODES][R_MAX_NODES];
    r_link_t   links[R_MAX_NODES][R_MAX_NODES];
    /** One clock for every node (R3), unix nanoseconds. */
    int64_t    clock_ns;
    int64_t    rounds;
    /** Scratch for marshalling a hand-built message. */
    cmt_pb_cons_message_t *pb_scratch;
    cmt_msg_t             *msg_scratch;
    uint8_t               *buf_scratch;
};

/** The network alive right now — see WHAT IT LEAVES BEHIND. */
static r_net_t *g_r_net = NULL;

static r_node_t *r_node_of_tc(const tc_t *tc)
{
    size_t i;

    if (g_r_net == NULL) {
        return NULL;
    }
    for (i = 0u; i < g_r_net->n; i++) {
        if (g_r_net->nodes[i].tc == tc) {
            return &g_r_net->nodes[i];
        }
    }
    return NULL;
}

/* ══ the host: transport rows (cmt_conr_host_t) ═══════════════════════ */

/** p2p/peer.go:260-262 Send and :266-268 TrySend, over the in-memory
 *  switch: a copy of the bytes onto link (from → to) on the channel's
 *  FIFO; false when the peer is not connected (peer.go:271-272) or the
 *  FIFO holds SendQueueCapacity frames already. Both rows are this one
 *  function: DEVIATION R3-A-1 — neither blocks. */
static bool r_send(void *ctx, int peer_idx, uint8_t channel_id,
                   const uint8_t *bytes, size_t len)
{
    r_node_t  *from = (r_node_t *)ctx;
    r_net_t   *net  = g_r_net;
    r_link_t  *link;
    r_frame_t *f;
    int        ch;

    if (net == NULL || from == NULL || peer_idx < 0 ||
        (size_t)peer_idx >= net->n) {
        return false;
    }
    if (!net->connected[from->index][peer_idx]) {
        return false;                                  /* peer.go:271-272 */
    }
    ch = r_channel_index(channel_id);
    if (ch < 0) {
        return false;                                  /* peer.go:273-274 */
    }
    link = &net->links[from->index][peer_idx];
    if (link->len[ch] >= link->cap[ch]) {
        return false;                                  /* queue full     */
    }
    f = &link->q[ch][(link->head[ch] + link->len[ch]) % link->cap[ch]];
    f->buf = (uint8_t *)malloc(len == 0u ? 1u : len);
    if (f->buf == NULL) {
        return false;
    }
    if (len > 0u) {
        memcpy(f->buf, bytes, len);
    }
    f->len = len;
    link->len[ch]++;
    return true;
}

/** p2p/switch.go:335-358 — StopPeerForError. Counted (R13); the
 *  disconnect the switch performs is reproduced (both directions,
 *  `RemovePeer` on both reactors, switch.go:373-375 and :381). */
static void r_stop_peer_for_error(void *ctx, int peer_idx, int reason_code)
{
    r_node_t *from = (r_node_t *)ctx;
    r_net_t  *net  = g_r_net;

    if (net == NULL || from == NULL) {
        return;
    }
    from->stop_calls++;
    from->last_stop_reason = reason_code;
    fprintf(stderr, "SWITCH: node %zu stops peer %d for error (reason %d)\n",
            from->index, peer_idx, reason_code);
    if (peer_idx >= 0 && (size_t)peer_idx < net->n) {
        net->connected[from->index][peer_idx] = false;
        net->connected[peer_idx][from->index] = false;
        (void)cmt_conr_remove_peer(&from->conR, peer_idx);
        (void)cmt_conr_remove_peer(&net->nodes[peer_idx].conR, (int)from->index);
    }
}

/* ══ the host: this file's block store (R6), both tables ══════════════ */

static tc_store_ent_t *r_store_at(r_node_t *node, int64_t height)
{
    if (height < 1 || height > (int64_t)R_STORE_MAX) {
        return NULL;
    }
    return &node->store[height - 1];
}

/** store/store.go's Base(): the lowest height kept; 1 once anything is
 *  stored (this store never prunes), 0 while empty. reactor.go:575's
 *  `blockStoreBase > 0` gate is what reads it. */
static int r_bs_base(void *ctx, int64_t *out)
{
    r_node_t *node = (r_node_t *)ctx;

    *out = (node->store_height > 0) ? 1 : 0;
    return CMT_OK;
}

/** state.go:309, :1730 and reactor.go:584, :654, :924 — Height(). The cs
 *  table hands `tc`, the reactor table hands the node: two entry points
 *  over one store. */
static int r_bs_height_node(void *ctx, int64_t *out)
{
    *out = ((r_node_t *)ctx)->store_height;
    return CMT_OK;
}

static int r_bs_height_tc(void *ctx, int64_t *out)
{
    r_node_t *node = r_node_of_tc((const tc_t *)ctx);

    if (node == NULL) {
        return CMT_FAULT;
    }
    *out = node->store_height;
    return CMT_OK;
}

/** state.go:313, :629 and reactor.go:756 — LoadBlockCommit(height). */
static int r_store_load_block_commit(r_node_t *node, int64_t height,
                                     cmt_commit_t *out, bool *out_found)
{
    tc_store_ent_t *e = r_store_at(node, height);

    *out_found = false;
    if (e == NULL || !e->has_commit) {
        return CMT_OK;
    }
    *out       = e->commit;
    *out_found = true;
    return CMT_OK;
}

static int r_bs_load_block_commit_tc(void *ctx, int64_t height,
                                     cmt_commit_t *out, bool *out_found)
{
    r_node_t *node = r_node_of_tc((const tc_t *)ctx);

    return (node == NULL) ? CMT_FAULT
                          : r_store_load_block_commit(node, height, out, out_found);
}

static int r_bs_load_block_commit_node(void *ctx, int64_t height,
                                       cmt_commit_t *out, bool *out_found)
{
    return r_store_load_block_commit((r_node_t *)ctx, height, out, out_found);
}

/** state.go:611 and reactor.go:754 — LoadBlockExtendedCommit(height). */
static int r_store_load_block_extended_commit(r_node_t *node, int64_t height,
                                              cmt_extended_commit_t *out,
                                              bool *out_found)
{
    tc_store_ent_t *e = r_store_at(node, height);

    *out_found = false;
    if (e == NULL || !e->has_ext) {
        return CMT_OK;
    }
    *out       = e->ext;
    *out_found = true;
    return CMT_OK;
}

static int r_bs_load_block_extended_commit_tc(void *ctx, int64_t height,
                                              cmt_extended_commit_t *out,
                                              bool *out_found)
{
    r_node_t *node = r_node_of_tc((const tc_t *)ctx);

    return (node == NULL) ? CMT_FAULT
                          : r_store_load_block_extended_commit(node, height,
                                                               out, out_found);
}

static int r_bs_load_block_extended_commit_node(void *ctx, int64_t height,
                                                cmt_extended_commit_t *out,
                                                bool *out_found)
{
    return r_store_load_block_extended_commit((r_node_t *)ctx, height, out,
                                              out_found);
}

/** state.go:1124 — LoadBlockMeta(height).Header (the cs projection). */
static int r_bs_load_block_meta_tc(void *ctx, int64_t height,
                                   cmt_header_t *out, bool *out_found)
{
    r_node_t       *node = r_node_of_tc((const tc_t *)ctx);
    tc_store_ent_t *e;

    if (node == NULL) {
        return CMT_FAULT;
    }
    e = r_store_at(node, height);
    *out_found = false;
    if (e == NULL || !e->saved) {
        return CMT_OK;
    }
    *out       = e->header;
    *out_found = true;
    return CMT_OK;
}

/** reactor.go:581, :651 — LoadBlockMeta(height).BlockID (the reactor's
 *  projection): the seen commit's BlockID, which `SaveBlock` recorded
 *  alongside the block (store/store.go saves `BlockMeta{BlockID}` from
 *  the same call's `blockParts.Header()` and block hash; the seen
 *  commit's BlockID carries exactly that pair). */
static int r_bs_load_block_meta_block_id(void *ctx, int64_t height,
                                         cmt_block_id_t *out, bool *out_found)
{
    r_node_t       *node = (r_node_t *)ctx;
    tc_store_ent_t *e    = r_store_at(node, height);

    *out_found = false;
    if (e == NULL || !e->saved || !e->has_seen) {
        return CMT_OK;
    }
    *out       = e->seen.block_id;
    *out_found = true;
    return CMT_OK;
}

/** state.go:310, :627, :2502 — LoadSeenCommit(height). */
static int r_bs_load_seen_commit_tc(void *ctx, int64_t height,
                                    cmt_commit_t *out, bool *out_found)
{
    r_node_t       *node = r_node_of_tc((const tc_t *)ctx);
    tc_store_ent_t *e;

    if (node == NULL) {
        return CMT_FAULT;
    }
    e = r_store_at(node, height);
    *out_found = false;
    if (e == NULL || !e->has_seen) {
        return CMT_OK;
    }
    *out       = e->seen;
    *out_found = true;
    return CMT_OK;
}

/** test_cmt_common.h:1171-1204 `tc_store_put_block`, over this store. */
static int r_store_put_block(r_node_t *node, cmt_block_t *block)
{
    tc_store_ent_t *e = r_store_at(node, block->header.height);

    if (e == NULL) {
        return CMT_FAULT;
    }
    e->saved  = true;
    e->height = block->header.height;
    e->header = block->header;
    if (block->header.height > node->store_height) {
        node->store_height = block->header.height;
    }
    if (block->last_commit != NULL &&
        block->last_commit->signatures_len > 0u) {
        tc_store_ent_t *prev = r_store_at(node, block->header.height - 1);

        if (prev != NULL) {
            size_t n = block->last_commit->signatures_len;

            if (n > (size_t)TC_MAX_VALS) {
                return CMT_FAULT;
            }
            memcpy(prev->commit_sigs, block->last_commit->signatures,
                   n * sizeof(prev->commit_sigs[0]));
            prev->commit                = *block->last_commit;
            prev->commit.signatures     = prev->commit_sigs;
            prev->commit.signatures_cap = (size_t)TC_MAX_VALS;
            prev->commit.signatures_len = n;
            prev->has_commit            = true;
        }
    }
    return CMT_OK;
}

/** state.go:1737 — SaveBlock(block, blockParts, seenCommit)
 *  (test_cmt_common.h:1207-1234 over this store). */
static int r_bs_save_block_tc(void *ctx, cmt_block_t *block,
                              const cmt_part_set_t *parts,
                              const cmt_commit_t *seen_commit)
{
    r_node_t       *node = r_node_of_tc((const tc_t *)ctx);
    tc_store_ent_t *e;
    size_t          n;

    (void)parts;
    if (node == NULL) {
        return CMT_FAULT;
    }
    if (r_store_put_block(node, block) != CMT_OK) {
        return CMT_FAULT;
    }
    e = r_store_at(node, block->header.height);
    n = seen_commit->signatures_len;
    if (n > (size_t)TC_MAX_VALS) {
        return CMT_FAULT;
    }
    if (n > 0u) {
        memcpy(e->seen_sigs, seen_commit->signatures,
               n * sizeof(e->seen_sigs[0]));
    }
    e->seen                = *seen_commit;
    e->seen.signatures     = e->seen_sigs;
    e->seen.signatures_cap = (size_t)TC_MAX_VALS;
    e->seen.signatures_len = n;
    e->has_seen            = true;
    return CMT_OK;
}

/** state.go:1735 — SaveBlockWithExtendedCommit
 *  (test_cmt_common.h:1239-1266 over this store). */
static int r_bs_save_block_with_extended_commit_tc(
        void *ctx, cmt_block_t *block, const cmt_part_set_t *parts,
        const cmt_extended_commit_t *seen_ext)
{
    r_node_t       *node = r_node_of_tc((const tc_t *)ctx);
    tc_store_ent_t *e;
    size_t          n;

    (void)parts;
    if (node == NULL) {
        return CMT_FAULT;
    }
    if (r_store_put_block(node, block) != CMT_OK) {
        return CMT_FAULT;
    }
    e = r_store_at(node, block->header.height);
    n = seen_ext->extended_signatures_len;
    if (n > (size_t)TC_MAX_VALS) {
        return CMT_FAULT;
    }
    if (n > 0u) {
        memcpy(e->ext_sigs, seen_ext->extended_signatures,
               n * sizeof(e->ext_sigs[0]));
    }
    e->ext                         = *seen_ext;
    e->ext.extended_signatures     = e->ext_sigs;
    e->ext.extended_signatures_cap = (size_t)TC_MAX_VALS;
    e->ext.extended_signatures_len = n;
    e->has_ext                     = true;
    return CMT_OK;
}

/* ══ the registry across nodes (R4, R5) ═══════════════════════════════ */

/** The record with this block hash in ANY node's registry. */
static tc_block_rec_t *r_rec_by_hash(r_net_t *net, const uint8_t *hash,
                                     size_t len, r_node_t **out_owner)
{
    size_t i;
    size_t k;

    if (len != (size_t)CMT_TMHASH_SIZE) {
        return NULL;
    }
    for (i = 0u; i < net->n; i++) {
        tc_t *tc = net->nodes[i].tc;

        for (k = 0u; k < tc->recs_n; k++) {
            tc_block_rec_t *r = &tc->recs[k];

            if (r->used && memcmp(r->hash, hash, len) == 0) {
                if (out_owner != NULL) {
                    *out_owner = &net->nodes[i];
                }
                return r;
            }
        }
    }
    return NULL;
}

/** state.go:2005-2019 — `decode_block`, looked up in EVERY node's
 *  registry (R4). A miss is the reference's decode error, CMT_REJECT;
 *  the fixture's `decode_misses` counter is kept for the dump. */
static int r_decode_block(void *ctx, const uint8_t *bytes, size_t len,
                          cmt_block_t *out)
{
    tc_t    *tc  = (tc_t *)ctx;
    r_net_t *net = g_r_net;
    size_t   i;
    size_t   k;

    if (net == NULL) {
        return CMT_FAULT;
    }
    for (i = 0u; i < net->n; i++) {
        tc_t *src = net->nodes[i].tc;

        for (k = 0u; k < src->recs_n; k++) {
            tc_block_rec_t *rec = &src->recs[k];

            if (rec->used && rec->marshal_len == len &&
                memcmp(rec->marshal, bytes, len) == 0) {
                *out = rec->block;
                return CMT_OK;
            }
        }
    }
    tc->decode_misses++;
    return CMT_REJECT;
}

/** Build the part set over record `k` of `node`'s registry (R5; as
 *  test_cmt_multinode.h:693 `mn_rec_ps_build`). Idempotent. */
static int r_rec_ps_build(r_node_t *node, size_t k)
{
    tc_block_rec_t *rec = &node->tc->recs[k];

    if (node->rec_ps_built[k]) {
        return CMT_OK;
    }
    if (!rec->used || rec->marshal == NULL) {
        return CMT_FAULT;
    }
    memset(&node->rec_ps[k], 0, sizeof(node->rec_ps[k]));
    if (cmt_new_part_set_from_data(rec->marshal, rec->marshal_len,
                                   (uint32_t)CMT_BLOCK_PART_SIZE_BYTES,
                                   node->rec_parts[k], (size_t)TC_PARTS_CAP,
                                   &node->rec_ps[k]) != CMT_OK) {
        return CMT_FAULT;
    }
    node->rec_ps_built[k] = true;
    return CMT_OK;
}

/** reactor.go:664 — LoadBlockPart(height, index), from the proposer's
 *  registry copy of the committed block (R5). */
static int r_bs_load_block_part(void *ctx, int64_t height, int index,
                                cmt_part_t *out, bool *out_found)
{
    r_node_t         *node  = (r_node_t *)ctx;
    r_node_t         *owner = NULL;
    tc_store_ent_t   *e     = r_store_at(node, height);
    tc_block_rec_t   *rec;
    const cmt_part_t *part;
    size_t            k;

    *out_found = false;
    if (e == NULL || !e->saved || !e->has_seen) {
        return CMT_OK;
    }
    rec = r_rec_by_hash(g_r_net, e->seen.block_id.hash,
                        e->seen.block_id.hash_len, &owner);
    if (rec == NULL || owner == NULL) {
        return CMT_OK;
    }
    k = (size_t)(rec - owner->tc->recs);
    if (r_rec_ps_build(owner, k) != CMT_OK) {
        return CMT_FAULT;
    }
    if (index < 0) {
        return CMT_OK;
    }
    part = cmt_part_set_get_part(&owner->rec_ps[k], (size_t)index);
    if (part == NULL) {
        return CMT_OK;
    }
    *out       = *part;
    *out_found = true;
    return CMT_OK;
}

/* ══ the stand-in application: `val=` transactions (R7, R8) ═══════════ */

/** RFC 4648 §4 standard alphabet, with padding — Go's
 *  `base64.StdEncoding` (helpers.go:77, kvstore.go:428). */
static const char r_b64_alphabet[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t r_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap)
{
    size_t i;
    size_t o = 0u;

    for (i = 0u; i + 2u < n; i += 3u) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1u] << 8) |
                     (uint32_t)in[i + 2u];

        if (o + 4u > cap) {
            return 0u;
        }
        out[o++] = r_b64_alphabet[(v >> 18) & 63u];
        out[o++] = r_b64_alphabet[(v >> 12) & 63u];
        out[o++] = r_b64_alphabet[(v >> 6) & 63u];
        out[o++] = r_b64_alphabet[v & 63u];
    }
    if (i < n) {
        uint32_t v = (uint32_t)in[i] << 16;

        if (o + 4u > cap) {
            return 0u;
        }
        if (i + 1u < n) {
            v |= (uint32_t)in[i + 1u] << 8;
        }
        out[o++] = r_b64_alphabet[(v >> 18) & 63u];
        out[o++] = r_b64_alphabet[(v >> 12) & 63u];
        out[o++] = (i + 1u < n) ? r_b64_alphabet[(v >> 6) & 63u] : '=';
        out[o++] = '=';
    }
    return o;
}

static int r_b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/** @return the decoded length, or 0 on malformed input (Go's
 *  `DecodeString` error, kvstore.go:429-431). */
static size_t r_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap)
{
    size_t i;
    size_t o = 0u;

    if (n % 4u != 0u) {
        return 0u;
    }
    for (i = 0u; i < n; i += 4u) {
        int      a = r_b64_value(in[i]);
        int      b = r_b64_value(in[i + 1u]);
        int      c = (in[i + 2u] == '=') ? -2 : r_b64_value(in[i + 2u]);
        int      d = (in[i + 3u] == '=') ? -2 : r_b64_value(in[i + 3u]);
        uint32_t v;

        if (a < 0 || b < 0 || c == -1 || d == -1 || (c == -2 && d != -2)) {
            return 0u;
        }
        v = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
            ((uint32_t)(c < 0 ? 0 : c) << 6) | (uint32_t)(d < 0 ? 0 : d);
        if (o + 1u > cap) {
            return 0u;
        }
        out[o++] = (uint8_t)(v >> 16);
        if (c >= 0) {
            if (o + 1u > cap) {
                return 0u;
            }
            out[o++] = (uint8_t)(v >> 8);
        }
        if (d >= 0) {
            if (o + 1u > cap) {
                return 0u;
            }
            out[o++] = (uint8_t)v;
        }
        if (c == -2 && i + 4u < n) {
            return 0u;                          /* padding not at the end */
        }
    }
    return o;
}

/** kvstore.go:28 — `ValidatorPrefix = "val="`. */
#define R_VALIDATOR_PREFIX "val="

/**
 * abci/example/kvstore/helpers.go:72-80 — `MakeValSetChangeTx(pubkey,
 * power)`: `"val=" + pk.Type() + "!" + base64(pk.Bytes()) + "!" + power`.
 * The key type is the port's `mldsa87` (cmt_params.h:99, substitution 2).
 * @return the length written, 0 if `cap` is too small.
 */
static size_t r_make_val_set_change_tx(const uint8_t *pubkey, int64_t power,
                                       uint8_t *out, size_t cap)
{
    size_t o = 0u;
    size_t n;
    char   num[32];
    int    len;

    n = strlen(R_VALIDATOR_PREFIX) + strlen(CMT_PUBKEY_TYPE_MLDSA87_NAME) + 1u;
    if (n > cap) {
        return 0u;
    }
    memcpy(out + o, R_VALIDATOR_PREFIX, strlen(R_VALIDATOR_PREFIX));
    o += strlen(R_VALIDATOR_PREFIX);
    memcpy(out + o, CMT_PUBKEY_TYPE_MLDSA87_NAME,
           strlen(CMT_PUBKEY_TYPE_MLDSA87_NAME));
    o += strlen(CMT_PUBKEY_TYPE_MLDSA87_NAME);
    out[o++] = '!';
    n = r_b64_encode(pubkey, (size_t)CMT_PB_PUBKEY_LEN, (char *)out + o,
                     cap - o);
    if (n == 0u) {
        return 0u;
    }
    o += n;
    len = snprintf(num, sizeof(num), "!%lld", (long long)power);
    if (len <= 0 || o + (size_t)len > cap) {
        return 0u;
    }
    memcpy(out + o, num, (size_t)len);
    o += (size_t)len;
    return o;
}

/** kvstore.go:413-415 — `isValidatorTx`. */
static bool r_is_validator_tx(const uint8_t *tx, size_t len)
{
    return len >= strlen(R_VALIDATOR_PREFIX) &&
           memcmp(tx, R_VALIDATOR_PREFIX, strlen(R_VALIDATOR_PREFIX)) == 0;
}

/**
 * kvstore.go:417-444 — `parseValidatorTx`: strip the prefix, split on
 * "!" into exactly three (:421-424), base64-decode the key (:428-431),
 * parse the power (:434-437), refuse a negative power (:439-441).
 * @return CMT_OK with `out` a NewValidator(pubkey, power)
 *         (types/validator.go:27-35, address derived, priority 0), the
 *         key's type string checked to be the port's one; CMT_REJECT on
 *         any of the reference's errors.
 */
static int r_parse_validator_tx(const uint8_t *tx, size_t len,
                                cmt_validator_t *out)
{
    const char          *s;
    size_t               n;
    size_t               bang1 = 0u;
    size_t               bang2 = 0u;
    size_t               bangs = 0u;
    size_t               i;
    cmt_pb_public_key_t  pk;
    char                 num[32];
    long long            power;
    char                *end;

    s = (const char *)tx + strlen(R_VALIDATOR_PREFIX);           /* :418 */
    n = len - strlen(R_VALIDATOR_PREFIX);
    for (i = 0u; i < n; i++) {                                   /* :421 */
        if (s[i] == '!') {
            bangs++;
            if (bangs == 1u) {
                bang1 = i;
            } else if (bangs == 2u) {
                bang2 = i;
            }
        }
    }
    if (bangs != 2u) {                                           /* :422 */
        return CMT_REJECT;
    }
    /* keyType (:425): the only type this port knows. */
    if (bang1 != strlen(CMT_PUBKEY_TYPE_MLDSA87_NAME) ||
        memcmp(s, CMT_PUBKEY_TYPE_MLDSA87_NAME, bang1) != 0) {
        return CMT_REJECT;
    }
    memset(&pk, 0, sizeof(pk));
    if (r_b64_decode(s + bang1 + 1u, bang2 - bang1 - 1u, pk.key,
                     sizeof(pk.key)) != (size_t)CMT_PB_PUBKEY_LEN) { /* :428 */
        return CMT_REJECT;
    }
    pk.present = true;
    if (n - bang2 - 1u == 0u || n - bang2 - 1u >= sizeof(num)) {
        return CMT_REJECT;
    }
    memcpy(num, s + bang2 + 1u, n - bang2 - 1u);
    num[n - bang2 - 1u] = '\0';
    end   = NULL;
    power = strtoll(num, &end, 10);                              /* :434 */
    if (end == NULL || *end != '\0') {
        return CMT_REJECT;                                       /* :436 */
    }
    if (power < 0) {                                             /* :439 */
        return CMT_REJECT;
    }
    return cmt_validator_new(&pk, (int64_t)power, out);
}

/**
 * state/execution.go:592-661 — `updateState`, with the validator updates
 * the kvstore's FinalizeBlock (kvstore.go:218-229) collected from the
 * block's `val=` transactions (R7):
 *
 *   nValSet := state.NextValidators.Copy()                        (:603)
 *   if len(validatorUpdates) > 0 {
 *       nValSet.UpdateWithChangeSet(validatorUpdates)              (:608)
 *       lastHeightValsChanged = header.Height + 1 + 1              (:613)
 *   }
 *   nValSet.IncrementProposerPriority(1)                           (:617)
 *   NextValidators: nValSet, Validators: NextValidators.Copy(),
 *   LastValidators: Validators.Copy()                              (:652-654)
 *
 * The fixture's `tc_apply_verified_block` (test_cmt_common.h:963-1003)
 * does the same three copies and the increment but has no hook between
 * the copy and the increment, so it is not called; its bookkeeping
 * (`apply_calls`, `applied_height`, `applied_hash`) is reproduced.
 * `validateValidatorUpdates` (:567-590) is the negative-power check,
 * already refused by the parser (:439-441), and the key-type check,
 * which this port has one answer to. Then the stand-in mempool's
 * `Update` (R8): every pending transaction the block carries is dropped.
 */
static int r_apply_verified_block(void *ctx, const cmt_block_id_t *block_id,
                                  cmt_block_t *block, cmt_state_t *in_out_state)
{
    tc_t     *tc   = (tc_t *)ctx;
    r_node_t *node = r_node_of_tc(tc);
    size_t    n_changes = 0u;
    size_t    i;
    size_t    j;
    int       rc;

    if (node == NULL || block == NULL || in_out_state == NULL) {
        return CMT_FAULT;
    }
    tc->apply_calls++;
    tc->applied_height   = block->header.height;
    tc->applied_hash_len = 0u;
    if (block_id != NULL && block_id->hash_len == (size_t)CMT_TMHASH_SIZE) {
        memcpy(tc->applied_hash, block_id->hash, (size_t)CMT_TMHASH_SIZE);
        tc->applied_hash_len = (size_t)CMT_TMHASH_SIZE;
    }

    /* kvstore.go:218-229 — the FinalizeBlock loop over req.Txs. */
    for (i = 0u; i < block->data.txs_len && i < (size_t)TC_MAX_TXS; i++) {
        const cmt_pb_bytes_t *tx = &block->data.txs[i];

        if (r_is_validator_tx(tx->data, tx->len)) {              /* :220 */
            rc = r_parse_validator_tx(tx->data, tx->len,
                                      &node->changes[n_changes]); /* :221 */
            if (rc != CMT_OK) {
                /* :222-224 — panic(err): the application dies; here the
                 * block executor's error, which state.go:1783-1785
                 * panics on. NODE-LOCAL → CMT_FAULT. */
                fprintf(stderr, "APP: malformed val= tx in block %lld\n",
                        (long long)block->header.height);
                return CMT_FAULT;
            }
            n_changes++;                                         /* :225 */
        }
    }

    /* execution.go:652-654 — LastValidators = Validators.Copy() FIRST,
     * Validators = NextValidators.Copy(); nValSet is then what
     * next_validators still holds, updated in place. */
    if (cmt_validator_set_copy(&in_out_state->validators,
                               &in_out_state->last_validators) != CMT_OK) {
        return CMT_FAULT;
    }
    if (cmt_validator_set_copy(&in_out_state->next_validators,
                               &in_out_state->validators) != CMT_OK) {
        return CMT_FAULT;
    }
    if (n_changes > 0u) {                                        /* :607 */
        rc = cmt_validator_set_update_with_change_set(
                &in_out_state->next_validators, node->changes, n_changes,
                tc->valscratch);                                 /* :608 */
        if (rc != CMT_OK) {
            fprintf(stderr, "APP: UpdateWithChangeSet failed (%d)\n", rc); /* :610 */
            return CMT_FAULT;
        }
        in_out_state->last_height_validators_changed =
                block->header.height + 1 + 1;                    /* :613 */
    }
    if (cmt_validator_set_increment_proposer_priority(
            &in_out_state->next_validators, 1) != CMT_OK) {      /* :617 */
        return CMT_FAULT;
    }
    in_out_state->last_block_height = block->header.height;      /* :649 */
    in_out_state->last_block_id     = *block_id;                 /* :650 */
    in_out_state->last_block_time   = block->header.time;        /* :651 */

    /* R8 — mempool.Update: drop every pending tx the block carries. */
    for (i = 0u; i < block->data.txs_len; i++) {
        const cmt_pb_bytes_t *tx = &block->data.txs[i];

        for (j = 0u; j < tc->next_txs_n; j++) {
            if (tc->next_txs_len[j] == tx->len &&
                memcmp(tc->next_txs[j], tx->data, tx->len) == 0) {
                size_t k;

                for (k = j + 1u; k < tc->next_txs_n; k++) {
                    tc->next_txs[k - 1u]     = tc->next_txs[k];
                    tc->next_txs_len[k - 1u] = tc->next_txs_len[k];
                }
                tc->next_txs_n--;
                break;
            }
        }
    }
    return CMT_OK;
}

/** The mempool's CheckTx of the reference tests (reactor_test.go:236,
 *  :673) as R8: append to the node's pending list. */
static int r_submit_tx(r_node_t *node, const uint8_t *tx, size_t len)
{
    tc_t  *tc = node->tc;
    size_t k  = tc->next_txs_n;

    if (k >= (size_t)TC_MAX_TXS || len > (size_t)R_TX_MAX_LEN) {
        fprintf(stderr, "APP: node %zu cannot hold another tx\n", node->index);
        return 1;
    }
    memcpy(node->tx_store[k], tx, len);
    tc->next_txs[k]     = node->tx_store[k];
    tc->next_txs_len[k] = len;
    tc->next_txs_n      = k + 1u;
    return 0;
}

/* ══ the host: the clock, shared with the state machine ═══════════════ */

/** THE clock of the reactor's table — the fixture's `tc_now` reached
 *  through the node (cmt_conr.h: the same callback as `cs->host.now`,
 *  which IS `tc_now` with `tc`). */
static int r_now_node(void *ctx, cmt_time_t *out)
{
    return tc_now(((r_node_t *)ctx)->tc, out);
}

/* ══ configuration ════════════════════════════════════════════════════ */

/** config.go:1037-1052 — `TestConsensusConfig()` over the defaults
 *  (`cmt_config_default`, :1017-1034). :1045 "NOTE: when modifying, make
 *  sure to update time_iota_ms (testGenesisFmt) in toml.go" is the
 *  reference's own reminder and has no counterpart here. */
static void r_test_consensus_config(cmt_config_t *cfg)
{
    (void)cmt_config_default(cfg);                               /* :1038 */
    cfg->timeout_propose                 =   40 * CMT_MILLISECOND; /* :1039 */
    cfg->timeout_propose_delta           =    1 * CMT_MILLISECOND; /* :1040 */
    cfg->timeout_prevote                 =   10 * CMT_MILLISECOND; /* :1041 */
    cfg->timeout_prevote_delta           =    1 * CMT_MILLISECOND; /* :1042 */
    cfg->timeout_precommit               =   10 * CMT_MILLISECOND; /* :1043 */
    cfg->timeout_precommit_delta         =    1 * CMT_MILLISECOND; /* :1044 */
    cfg->timeout_commit                  =   10 * CMT_MILLISECOND; /* :1046 */
    cfg->skip_timeout_commit             = true;                   /* :1047 */
    cfg->peer_gossip_sleep_duration      =    5 * CMT_MILLISECOND; /* :1048 */
    cfg->peer_query_maj23_sleep_duration =  250 * CMT_MILLISECOND; /* :1049 */
    cfg->double_sign_check_height        = (int64_t)0;             /* :1050 */
}

/* ══ the network: construction ════════════════════════════════════════ */

/** Release everything `r_net_new` allocated. Safe on a partly built
 *  network. */
static void r_net_free(r_net_t *net)
{
    size_t i;
    size_t j;
    size_t k;
    int    c;

    if (net == NULL) {
        return;
    }
    for (i = 0u; i < (size_t)R_MAX_NODES; i++) {
        r_node_t *node = &net->nodes[i];

        if (node->tc != NULL) {
            if (node->started) {
                (void)cmt_conr_stop(&node->conR);
            }
            cmt_conr_free(&node->conR);
            tc_teardown(node->tc);
            free(node->tc);
            node->tc = NULL;
        }
        free(node->recv_arena.buf);
        for (k = 0u; k < (size_t)TC_BLOCK_RECS; k++) {
            free(node->rec_parts[k]);
        }
        free(node->state_copy_storage);
        free(node->state_copy);
        free(node->changes);
    }
    for (i = 0u; i < (size_t)R_MAX_NODES; i++) {
        for (j = 0u; j < (size_t)R_MAX_NODES; j++) {
            r_link_t *link = &net->links[i][j];

            for (c = 0; c < CMT_CONR_NUM_CHANNELS; c++) {
                if (link->q[c] != NULL) {
                    for (k = 0u; k < link->len[c]; k++) {
                        free(link->q[c][(link->head[c] + k) % link->cap[c]].buf);
                    }
                    free(link->q[c]);
                }
            }
        }
    }
    free(net->pb_scratch);
    free(net->msg_scratch);
    free(net->buf_scratch);
    if (g_r_net == net) {
        g_r_net = NULL;
    }
    free(net);
}

/**
 * common_test.go:767-800 `randConsensusNet` + reactor_test.go:59
 * `NewReactor(css[i], true)` for `n` nodes over ONE genesis of `nvals`
 * validators, node i holding validator i's key (as test_cmt_multinode.h's
 * `mn_net_new`: the fixture memoises validator 0's key, node i re-points
 * `self` and re-runs SetPrivValidator). `only_once` is
 * `newMockTickerFunc(onlyOnce)` (common_test.go:918-925).
 *
 * Every fixture is `tc_setup(tc, nvals, 0, 0)`: the reference's genesis
 * has nil params (:770 `randGenesisDoc(nValidators, false, 30, nil)` →
 * extensions disabled) and testMinPower where the reference gives 30;
 * with equal powers every threshold is the same fraction.
 *
 * After `tc_setup` the state machine's host rows this file replaces are
 * written into `cs->host` directly (the table is a struct copy,
 * cmt_cs.c `cs->host = *host`): the store rows (R6), `decode_block` (R4)
 * and `apply_verified_block` (R7); and the config becomes the test
 * config (`r_test_consensus_config`).
 *
 * @return the network, or NULL after reporting.
 */
static r_net_t *r_net_new(size_t n, size_t nvals, bool only_once)
{
    const cmt_conr_channel_desc_t *chans;
    r_net_t *net;
    size_t   n_ch = 0u;
    size_t   i;
    size_t   j;
    size_t   k;
    int      c;

    if (g_r_net != NULL) {
        fprintf(stderr, "r_net_new: a network is already alive\n");
        return NULL;
    }
    if (n == 0u || n > (size_t)R_MAX_NODES || nvals == 0u ||
        nvals > (size_t)TC_MAX_VALS || n > nvals) {
        fprintf(stderr, "r_net_new: n %zu / nvals %zu out of range\n", n, nvals);
        return NULL;
    }
    chans = cmt_conr_get_channels(&n_ch);
    if (chans == NULL || n_ch != (size_t)CMT_CONR_NUM_CHANNELS) {
        fprintf(stderr, "r_net_new: cmt_conr_get_channels\n");
        return NULL;
    }
    net = (r_net_t *)calloc(1u, sizeof(*net));
    if (net == NULL) {
        return NULL;
    }
    net->n     = n;
    net->nvals = nvals;
    g_r_net    = net;
    net->pb_scratch  = (cmt_pb_cons_message_t *)calloc(1u, sizeof(cmt_pb_cons_message_t));
    net->msg_scratch = (cmt_msg_t *)calloc(1u, sizeof(cmt_msg_t));
    net->buf_scratch = (uint8_t *)calloc((size_t)CMT_CONR_MAX_MSG_SIZE, 1u);
    if (net->pb_scratch == NULL || net->msg_scratch == NULL ||
        net->buf_scratch == NULL) {
        r_net_free(net);
        return NULL;
    }

    for (i = 0u; i < n; i++) {
        r_node_t        *node = &net->nodes[i];
        tc_t            *tc   = (tc_t *)calloc(1u, sizeof(tc_t));
        cmt_conr_host_t  host;

        node->index = i;
        if (tc == NULL) {
            r_net_free(net);
            return NULL;
        }
        if (tc_setup(tc, nvals, 0, 0) != 0) {
            free(tc);
            r_net_free(net);
            return NULL;
        }
        node->tc = tc;
        /* Node i IS validator i (common_test.go:791 privVals[i]). */
        tc->self = i;
        if (cmt_cs_set_priv_validator(tc->cs, true) != CMT_OK) {
            fprintf(stderr, "r_net_new: set_priv_validator failed\n");
            r_net_free(net);
            return NULL;
        }
        for (k = 0u; k < (size_t)CMT_PB_PEER_ID_MAX; k++) {
            node->id[k] = (uint8_t)(0x80u + i);
        }
        node->only_once = only_once;

        /* config.go:1037-1052 through ResetConfig (:780). */
        r_test_consensus_config(&tc->config);

        /* The rows this file replaces (R4, R6, R7). */
        tc->cs->host.bs_height                          = r_bs_height_tc;
        tc->cs->host.bs_load_block_commit               = r_bs_load_block_commit_tc;
        tc->cs->host.bs_load_block_extended_commit      = r_bs_load_block_extended_commit_tc;
        tc->cs->host.bs_load_block_meta                 = r_bs_load_block_meta_tc;
        tc->cs->host.bs_load_seen_commit                = r_bs_load_seen_commit_tc;
        tc->cs->host.bs_save_block                      = r_bs_save_block_tc;
        tc->cs->host.bs_save_block_with_extended_commit = r_bs_save_block_with_extended_commit_tc;
        tc->cs->host.decode_block                       = r_decode_block;
        tc->cs->host.apply_verified_block               = r_apply_verified_block;

        for (k = 0u; k < (size_t)TC_BLOCK_RECS; k++) {
            node->rec_parts[k] = (cmt_part_t *)calloc((size_t)TC_PARTS_CAP,
                                                      sizeof(cmt_part_t));
            if (node->rec_parts[k] == NULL) {
                r_net_free(net);
                return NULL;
            }
        }
        node->recv_arena.buf  = (uint8_t *)calloc((size_t)R_ARENA_CAP, 1u);
        node->recv_arena.cap  = (size_t)R_ARENA_CAP;
        node->recv_arena.used = 0u;
        node->state_copy_storage = (cmt_state_storage_t *)calloc(
                1u, sizeof(cmt_state_storage_t));
        node->state_copy = (cmt_state_t *)calloc(1u, sizeof(cmt_state_t));
        node->changes    = (cmt_validator_t *)calloc((size_t)TC_MAX_TXS,
                                                     sizeof(cmt_validator_t));
        if (node->recv_arena.buf == NULL || node->state_copy_storage == NULL ||
            node->state_copy == NULL || node->changes == NULL) {
            r_net_free(net);
            return NULL;
        }
        if (cmt_state_init(node->state_copy, node->state_copy_storage) != CMT_OK) {
            r_net_free(net);
            return NULL;
        }

        /* reactor_test.go:59 — NewReactor(css[i], true) "so we dont start
         * the consensus states". */
        memset(&host, 0, sizeof(host));
        host.send                          = r_send;
        host.try_send                      = r_send;
        host.stop_peer_for_error           = r_stop_peer_for_error;
        host.bs_base                       = r_bs_base;
        host.bs_height                     = r_bs_height_node;
        host.bs_load_block_meta_block_id   = r_bs_load_block_meta_block_id;
        host.bs_load_block_part            = r_bs_load_block_part;
        host.bs_load_block_commit          = r_bs_load_block_commit_node;
        host.bs_load_block_extended_commit = r_bs_load_block_extended_commit_node;
        host.now                           = r_now_node;
        if (cmt_conr_init(&node->conR, tc->cs, true, &host, node,
                          &node->recv_arena) != CMT_OK) {
            fprintf(stderr, "r_net_new: cmt_conr_init failed\n");
            r_net_free(net);
            return NULL;
        }
    }

    /* The links: one FIFO per channel per direction, at SendQueueCapacity. */
    for (i = 0u; i < n; i++) {
        for (j = 0u; j < n; j++) {
            r_link_t *link = &net->links[i][j];

            for (c = 0; c < CMT_CONR_NUM_CHANNELS; c++) {
                link->cap[c] = (size_t)chans[c].send_queue_capacity;
                link->q[c]   = (r_frame_t *)calloc(link->cap[c], sizeof(r_frame_t));
                if (link->q[c] == NULL) {
                    r_net_free(net);
                    return NULL;
                }
            }
        }
    }
    /* The shared clock starts at the fixture's frozen genesis instant. */
    net->clock_ns = (int64_t)TC_GENESIS_SECONDS * CMT_SECOND;
    return net;
}

/** p2p/switch.go:813-865 `addPeer` on BOTH switches of a pair
 *  (`p2p.Connect2Switches`, reactor_test.go:81): InitPeer (:830), start
 *  (:836), add to the set (:846), AddPeer (:859), on each side with the
 *  other as the peer. Both reactors must be running (`sw.Start()` of
 *  MakeConnectedSwitches precedes the connect). */
static int r_connect(r_net_t *net, size_t a, size_t b)
{
    if (a >= net->n || b >= net->n || a == b) {
        return 1;
    }
    R_HCHECK(cmt_conr_init_peer(&net->nodes[a].conR, (int)b, net->nodes[b].id)
             == CMT_OK, "InitPeer a←b");
    R_HCHECK(cmt_conr_init_peer(&net->nodes[b].conR, (int)a, net->nodes[a].id)
             == CMT_OK, "InitPeer b←a");
    net->connected[a][b] = true;                          /* peer started */
    net->connected[b][a] = true;
    R_HCHECK(cmt_conr_add_peer(&net->nodes[a].conR, (int)b) == CMT_OK,
             "AddPeer a←b");
    R_HCHECK(cmt_conr_add_peer(&net->nodes[b].conR, (int)a) == CMT_OK,
             "AddPeer b←a");
    return 0;
}

/**
 * reactor_test.go:48-92 — `startConsensusNet(t, css, n)` for the first
 * `n_start` nodes: start every reactor (`sw.Start()` inside
 * `MakeConnectedSwitches`, :77-81 → BaseService.Start → OnStart with
 * waitSync = true, so the state machines do NOT start), connect every
 * pair (:81 Connect2Switches), then — "now that everyone is connected,
 * start the state machines" (:83-90) — `SwitchToConsensus(GetState(),
 * false)` on each, in index order. :70-74 saves the genesis state into
 * the state STORE the block executor reads; this fixture has no state
 * store, nothing to save.
 *
 * `skipWAL = false` (:89): the fixture's WAL read rows answer "nothing"
 * (test_cmt_common.h:1380-1398), so `cmt_cs_start`'s catch-up replay
 * finds no END_HEIGHT marker for height 0, logs the reference's
 * "proceeding to start state anyway" (cmt_cs.c) and starts — the
 * reference replays the `EndHeight{0}` a fresh WAL is seeded with
 * (wal.go:125-132) and starts too.
 */
static int r_start_consensus_net(r_net_t *net, size_t n_start)
{
    size_t i;
    size_t j;

    if (n_start > net->n) {
        return 1;
    }
    for (i = 0u; i < n_start; i++) {
        R_HCHECK(cmt_conr_start(&net->nodes[i].conR) == CMT_OK,
                 "reactor Start (OnStart, waitSync)");
        net->nodes[i].started = true;
        R_HCHECK(cmt_conr_wait_sync(&net->nodes[i].conR), "waitSync stays set");
    }
    for (i = 0u; i < n_start; i++) {
        for (j = i + 1u; j < n_start; j++) {
            if (r_connect(net, i, j) != 0) {
                return 1;
            }
        }
    }
    for (i = 0u; i < n_start; i++) {
        r_node_t *node = &net->nodes[i];

        R_HCHECK(cmt_cs_get_state(node->tc->cs, node->state_copy) == CMT_OK,
                 "GetState()");                                  /* :88 */
        R_HCHECK(cmt_conr_switch_to_consensus(&node->conR, node->state_copy,
                                              false) == CMT_OK,
                 "SwitchToConsensus");                           /* :89 */
        R_HCHECK(!cmt_conr_wait_sync(&node->conR), "waitSync cleared");
    }
    return 0;
}

/* ══ the network: one round (R1) ══════════════════════════════════════ */

/** The mock ticker's rule (R10; test_cmt_multinode.h:1693 `mn_timers`, its
 *  MN_TICKER_MOCK branch — M5; the driver's other two modes, M5's
 *  when-idle and M16's quiescent, are not used here). */
static int r_timers(r_node_t *node)
{
    tc_t     *tc = node->tc;
    cmt_cs_t *cs = tc->cs;

    if (!node->started || !tc->armed || cs->tock_q_len != 0u) {
        return 0;
    }
    if (cs->ticker.ti.step != CMT_ROUND_STEP_NEW_HEIGHT) {
        return 0;                                /* common_test.go:951 dropped */
    }
    if (node->only_once && node->fired) {
        return 0;                                /* :948-950 */
    }
    tc->armed   = false;
    node->fired = true;                          /* :953 */
    if (cmt_cs_on_timer_expired(cs) != CMT_OK) {
        fprintf(stderr, "DRIVER: node %zu: on_timer_expired failed\n",
                node->index);
        return 1;
    }
    return 0;
}

/** Deliver every frame queued for node `i`: senders in index order,
 *  channels in descriptor order, FIFO. A CMT_REJECT stops that sender's
 *  delivery for the round (R2). */
static int r_deliver_to(r_net_t *net, size_t i)
{
    size_t j;
    int    c;

    for (j = 0u; j < net->n; j++) {
        r_link_t *link = &net->links[j][i];
        bool      blocked = false;

        if (j == i || !net->connected[j][i]) {
            continue;
        }
        for (c = 0; c < CMT_CONR_NUM_CHANNELS && !blocked; c++) {
            while (link->len[c] > 0u) {
                r_frame_t *f = &link->q[c][link->head[c]];
                int        rc;

                rc = cmt_conr_receive(&net->nodes[i].conR, (int)j,
                                      cmt_conr_get_channels(NULL)[c].id,
                                      f->buf, f->len);
                if (rc == CMT_REJECT) {
                    blocked = true;                      /* R2 */
                    break;
                }
                if (rc != CMT_OK) {
                    fprintf(stderr, "DRIVER: node %zu: cmt_conr_receive from %zu "
                                    "on channel %02x returned %d\n", i, j,
                            (unsigned)cmt_conr_get_channels(NULL)[c].id, rc);
                    return 1;
                }
                free(f->buf);
                f->buf = NULL;
                f->len = 0u;
                link->head[c] = (link->head[c] + 1u) % link->cap[c];
                link->len[c]--;
            }
        }
    }
    return 0;
}

/** Every node's state, for a failed or exhausted run. */
static void r_dump(const r_net_t *net, const char *why)
{
    size_t i;

    fprintf(stderr, "DRIVER dump (%s) after %lld rounds\n", why,
            (long long)net->rounds);
    for (i = 0u; i < net->n; i++) {
        const r_node_t *node = &net->nodes[i];
        const tc_t     *tc   = node->tc;
        cmt_cs_t       *cs;

        if (tc == NULL) {
            continue;
        }
        cs = tc->cs;
        fprintf(stderr,
                "  node %zu%s: h=%lld r=%d step=%u peer_q=%zu int_q=%zu "
                "tock=%d armed=%d(step %u) fired=%d applies=%d applied_h=%lld "
                "store_h=%lld recs=%zu decode_misses=%d stop_calls=%d "
                "arena=%zu/%zu pending_txs=%zu fault_rc=%d\n",
                i, node->started ? "" : " (not started)",
                (long long)cs->rs.height, (int)cs->rs.round,
                (unsigned)cs->rs.step, cs->peer_q_len, cs->internal_q_len,
                (int)cs->tock_q_len, tc->armed ? 1 : 0,
                (unsigned)cs->ticker.ti.step, node->fired ? 1 : 0,
                tc->apply_calls, (long long)tc->applied_height,
                (long long)node->store_height, tc->recs_n, tc->decode_misses,
                node->stop_calls, node->recv_arena.used, node->recv_arena.cap,
                tc->next_txs_n, node->fault_rc);
    }
}

/**
 * One network round (R1): advance the shared clock (R3); then node 0,
 * 1, … in index order: deliver, one `cmt_cs_step` if it has work, the
 * timer rule, one `cmt_conr_tick`.
 */
static int r_round(r_net_t *net)
{
    size_t i;

    net->clock_ns += R_ROUND_NS;
    for (i = 0u; i < net->n; i++) {
        tc_t *tc = net->nodes[i].tc;

        tc->now.seconds = net->clock_ns / CMT_SECOND;
        tc->now.nanos   = (int32_t)(net->clock_ns % CMT_SECOND);
    }
    for (i = 0u; i < net->n; i++) {
        r_node_t *node = &net->nodes[i];
        cmt_cs_t *cs   = node->tc->cs;
        int64_t   deadline = 0;

        if (!node->started) {
            continue;
        }
        if (r_deliver_to(net, i) != 0) {
            return 1;
        }
        if (cmt_cs_has_work(cs)) {
            bool worked = false;
            int  rc     = cmt_cs_step(cs, &worked);

            if (rc != CMT_OK) {
                node->fault_rc = rc;
                fprintf(stderr, "DRIVER: node %zu: cmt_cs_step returned %d\n",
                        i, rc);
                return 1;
            }
        }
        if (r_timers(node) != 0) {
            return 1;
        }
        if (cmt_conr_tick(&node->conR, &deadline) != CMT_OK) {
            fprintf(stderr, "DRIVER: node %zu: cmt_conr_tick failed\n", i);
            return 1;
        }
        if (node->stop_calls != 0) {                            /* R13 */
            fprintf(stderr, "DRIVER: node %zu disconnected a peer (reason %d)\n",
                    i, node->last_stop_reason);
            return 1;
        }
    }
    net->rounds++;
    return 0;
}

/**
 * reactor_test.go:762-787 — `timeoutWaitGroup(n, f)`'s deadline as a
 * ROUND BUDGET (R12): run rounds until `pred` holds; exhaustion dumps
 * the network and FAILS. Never a skip.
 */
typedef bool (*r_pred_fn)(const r_net_t *net, const void *ctx);

static int r_run_until(r_net_t *net, r_pred_fn pred, const void *ctx,
                       const char *what)
{
    int64_t r;

    for (r = 0; r < (int64_t)R_BUDGET_ROUNDS; r++) {
        if (pred(net, ctx)) {
            return 0;
        }
        if (r_round(net) != 0) {
            r_dump(net, what);
            return 1;
        }
    }
    if (pred(net, ctx)) {
        return 0;
    }
    fprintf(stderr, "DRIVER: ROUND BUDGET EXHAUSTED (%d rounds) waiting for: "
                    "%s\n", R_BUDGET_ROUNDS, what);
    r_dump(net, what);
    return 1;
}

/* ══ what a scenario reads (R9) ═══════════════════════════════════════ */

typedef struct {
    size_t node;
} r_next_block_ctx_t;

/** `<-blocksSubs[j].Out()` has something: node j applied a block its
 *  cursor has not consumed. */
static bool r_pred_next_block(const r_net_t *net, const void *ctx)
{
    const r_next_block_ctx_t *c = (const r_next_block_ctx_t *)ctx;
    const r_node_t           *node = &net->nodes[c->node];

    return node->tc->apply_calls > node->consumed_blocks;
}

/** Consume node j's next NewBlock event: run until it exists, then
 *  return its height (blocks apply in height order from 1). */
static int r_wait_next_block(r_net_t *net, size_t j, int64_t *out_height)
{
    r_next_block_ctx_t c;

    c.node = j;
    if (r_run_until(net, r_pred_next_block, &c, "next block at a node") != 0) {
        return 1;
    }
    net->nodes[j].consumed_blocks++;
    *out_height = (int64_t)net->nodes[j].consumed_blocks;
    R_HCHECK(net->nodes[j].tc->applied_height >= *out_height,
             "blocks apply in height order");
    return 0;
}

/** The active-validator set of reactor_test.go:456-462 — addresses. */
typedef struct {
    uint8_t addr[TC_MAX_VALS][CMT_ADDRESS_SIZE];
    size_t  n;
} r_active_vals_t;

static bool r_active_has(const r_active_vals_t *av, const uint8_t *addr,
                         size_t len)
{
    size_t i;

    if (len != (size_t)CMT_ADDRESS_SIZE) {
        return false;
    }
    for (i = 0u; i < av->n; i++) {
        if (memcmp(av->addr[i], addr, len) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * reactor_test.go:746-760 — `validateBlock(block, activeVals)`: the
 * block's LastCommit has exactly `len(activeVals)` signatures (:747) and
 * every one names an active validator (:754-758) — an ABSENT signature
 * has an empty address and fails that lookup, so the check demands that
 * EVERY active validator signed ("expects high synchrony!", :745).
 * The block at `height` on node `j` is read from this file's store: its
 * LastCommit is the commit recorded for `height - 1` when the block was
 * saved (`r_store_put_block`).
 */
static int r_validate_block(r_net_t *net, size_t j, int64_t height,
                            const r_active_vals_t *av)
{
    r_node_t       *node = &net->nodes[j];
    tc_store_ent_t *prev;
    size_t          i;

    R_HCHECK(height >= 2, "validateBlock needs a LastCommit (height >= 2)");
    prev = r_store_at(node, height - 1);
    R_HCHECK(prev != NULL && prev->has_commit, "the block's LastCommit is stored");
    if (prev->commit.signatures_len != av->n) {                  /* :747 */
        fprintf(stderr, "commit size doesn't match number of active "
                        "validators. Got %zu, expected %zu\n",
                prev->commit.signatures_len, av->n);
        return 1;
    }
    for (i = 0u; i < prev->commit.signatures_len; i++) {         /* :754 */
        const cmt_commit_sig_t *cs = &prev->commit.signatures[i];

        if (!r_active_has(av, cs->validator_address,
                          cs->validator_address_len)) {          /* :755 */
            fprintf(stderr, "found vote for inactive validator (entry %zu)\n", i);
            return 1;
        }
    }
    return 0;
}

/** The transactions of the block at `height` as node `j` committed it
 *  (through the registry, R4). */
static int r_block_txs(r_net_t *net, size_t j, int64_t height,
                       const cmt_pb_bytes_t **out_txs, size_t *out_n)
{
    r_node_t       *node = &net->nodes[j];
    tc_store_ent_t *e    = r_store_at(node, height);
    tc_block_rec_t *rec;

    *out_txs = NULL;
    *out_n   = 0u;
    R_HCHECK(e != NULL && e->saved && e->has_seen, "the block is stored");
    rec = r_rec_by_hash(net, e->seen.block_id.hash, e->seen.block_id.hash_len,
                        NULL);
    R_HCHECK(rec != NULL, "the committed block is in a registry");
    *out_txs = rec->block.data.txs;
    *out_n   = rec->block.data.txs_len;
    return 0;
}

/**
 * reactor_test.go:655-680 — `waitForAndValidateBlock(n, activeVals,
 * blocksSubs, css, txs...)`: for each node j, its next block; validate
 * it; then CheckTx every `tx` into node j (:672-678, R8).
 */
static int r_wait_for_and_validate_block(r_net_t *net, size_t n,
                                         const r_active_vals_t *av,
                                         const uint8_t *const *txs,
                                         const size_t *tx_lens, size_t n_txs)
{
    size_t j;
    size_t t;

    for (j = 0u; j < n; j++) {
        int64_t h = 0;

        if (r_wait_next_block(net, j, &h) != 0) {                /* :665 */
            return 1;
        }
        if (r_validate_block(net, j, h, av) != 0) {              /* :668 */
            return 1;
        }
        for (t = 0u; t < n_txs; t++) {                           /* :672 */
            if (r_submit_tx(&net->nodes[j], txs[t], tx_lens[t]) != 0) {
                return 1;
            }
        }
    }
    return 0;
}

/**
 * reactor_test.go:682-714 — `waitForAndValidateBlockWithTx`: for each
 * node j, blocks until the given txs have all been seen, in order
 * ("note they could be spread over multiple blocks, but they should be
 * in order", :702-703), validating each.
 */
static int r_wait_for_and_validate_block_with_tx(r_net_t *net, size_t n,
                                                 const r_active_vals_t *av,
                                                 const uint8_t *const *txs,
                                                 const size_t *tx_lens,
                                                 size_t n_txs)
{
    size_t j;

    for (j = 0u; j < n; j++) {
        size_t ntxs = 0u;                                        /* :691 */

        for (;;) {                                       /* :692 BLOCK_TX_LOOP */
            const cmt_pb_bytes_t *btxs = NULL;
            size_t                nb   = 0u;
            size_t                k;
            int64_t               h    = 0;

            if (r_wait_next_block(net, j, &h) != 0) {            /* :695 */
                return 1;
            }
            if (r_validate_block(net, j, h, av) != 0) {          /* :698 */
                return 1;
            }
            if (r_block_txs(net, j, h, &btxs, &nb) != 0) {
                return 1;
            }
            for (k = 0u; k < nb; k++) {                          /* :704 */
                R_HCHECK(ntxs < n_txs, "more txs in the block than expected");
                R_HCHECK(btxs[k].len == tx_lens[ntxs] &&
                         memcmp(btxs[k].data, txs[ntxs], tx_lens[ntxs]) == 0,
                         "block tx equals the submitted tx, in order"); /* :705 */
                ntxs++;
            }
            if (ntxs == n_txs) {                                 /* :709 */
                break;
            }
        }
    }
    return 0;
}

/** reactor_test.go:119-121, :243-245, :465-467, :650-652 —
 *  `timeoutWaitGroup(n, func(j) { <-blocksSubs[j].Out() })`. */
static int r_wait_everyone_next_block(r_net_t *net, size_t n)
{
    size_t  j;
    int64_t h;

    for (j = 0u; j < n; j++) {
        if (r_wait_next_block(net, j, &h) != 0) {
            return 1;
        }
    }
    return 0;
}

/* ══ hand-built messages on the wire ══════════════════════════════════ */

/** The bytes of a reactor message, as the p2p layer would carry them
 *  (msgs.go MsgToProto + proto.Marshal). */
static int r_marshal(r_net_t *net, const cmt_msg_t *msg, size_t *out_len)
{
    R_HCHECK(cmt_msg_to_proto(msg, net->pb_scratch) == CMT_OK, "MsgToProto");
    R_HCHECK(cmt_pb_cons_message_marshal(net->pb_scratch, net->buf_scratch,
                                         (size_t)CMT_CONR_MAX_MSG_SIZE,
                                         out_len) == CMT_OK, "Marshal");
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * ValidateBasic (reactor_test.go:789-1100, :1131-1165)
 * ════════════════════════════════════════════════════════════════════ */

/** cometbft@709fd12b consensus/reactor_test.go:792-828 —
 *  `TestNewRoundStepMessageValidateBasic`. Every row of the table. */
static int s_new_round_step_validate_basic(void)
{
    static const struct {
        bool    expect_err;
        int32_t round;
        int32_t last_commit_round;
        int64_t height;
        const char *name;
        uint8_t step;
    } rows[] = {                                                 /* :800-808 */
        { false,  0,  0,  0, "Valid Message",         CMT_ROUND_STEP_NEW_HEIGHT },
        { true,  -1,  0,  0, "Negative round",        CMT_ROUND_STEP_NEW_HEIGHT },
        { true,   0,  0, -1, "Negative height",       CMT_ROUND_STEP_NEW_HEIGHT },
        { true,   0,  0,  0, "Invalid Step",          CMT_ROUND_STEP_COMMIT + 1 },
        /* :805 "The following cases will be handled by ValidateHeight" */
        { false,  0,  0,  1, "H == 1 but LCR != -1 ", CMT_ROUND_STEP_NEW_HEIGHT },
        { false,  0, -1,  2, "H > 1 but LCR < 0",     CMT_ROUND_STEP_NEW_HEIGHT }
    };
    size_t i;

    for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); i++) {
        cmt_new_round_step_msg_t m;
        int                      rc;

        memset(&m, 0, sizeof(m));
        m.height            = rows[i].height;                    /* :814 */
        m.round             = rows[i].round;                     /* :815 */
        m.step              = rows[i].step;                      /* :816 */
        m.last_commit_round = rows[i].last_commit_round;         /* :817 */
        rc = cmt_new_round_step_msg_validate_basic(&m);          /* :820 */
        if (rows[i].expect_err) {
            R_HCHECK(rc == CMT_REJECT, rows[i].name);            /* :822 */
        } else {
            R_HCHECK(rc == CMT_OK, rows[i].name);                /* :824 */
        }
    }
    return 0;
}

/** cometbft@709fd12b consensus/reactor_test.go:830-863 —
 *  `TestNewRoundStepMessageValidateHeight`, initialHeight 10. */
static int s_new_round_step_validate_height(void)
{
    static const struct {
        bool    expect_err;
        int32_t last_commit_round;
        int64_t height;
        const char *name;
    } rows[] = {                                                 /* :837-843 */
        { false,  0, 11, "Valid Message" },
        { true,   0, -1, "Negative height" },
        { true,   0,  0, "Zero height" },
        { true,   0, 10, "Initial height but LCR != -1 " },
        { true,  -1, 11, "Normal height but LCR < 0" }
    };
    const int64_t initial_height = 10;                           /* :831 */
    size_t        i;

    for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); i++) {
        cmt_new_round_step_msg_t m;
        int                      rc;

        memset(&m, 0, sizeof(m));
        m.height            = rows[i].height;                    /* :849 */
        m.round             = 0;                                 /* :850 */
        m.step              = CMT_ROUND_STEP_NEW_HEIGHT;         /* :851 */
        m.last_commit_round = rows[i].last_commit_round;         /* :852 */
        rc = cmt_new_round_step_msg_validate_height(&m, initial_height); /* :855 */
        if (rows[i].expect_err) {
            R_HCHECK(rc == CMT_REJECT, rows[i].name);            /* :857 */
        } else {
            R_HCHECK(rc == CMT_OK, rows[i].name);                /* :859 */
        }
    }
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:865-909 —
 * `TestNewValidBlockMessageValidateBasic`. The base message (:893-900):
 * Height 1, Round 0, PartSetHeader{Total: 1} (no hash — legal,
 * part_set.go:138-144), BlockParts = NewBitArray(1). Six rows; the
 * reference asserts the error STRING (:904-905), this port asserts the
 * code and names the string at each row.
 *
 * Row #5 (:885-886): `NewBitArray(MaxBlockPartsCount + 1)` = 1602 bits,
 * built with the constructor — 1602 is below the module's capacity
 * (MaxVotesCount, cmt_bits.h) and only above the PART-SET bound. The
 * reference's error for the row is the SIZE MISMATCH of :1609 (1602 ≠ 1),
 * not the "too big" of :1614, and that is what is asserted.
 */
static int s_new_valid_block_validate_basic(void)
{
    cmt_new_valid_block_msg_t m;
    size_t                    i;

    for (i = 0u; i < 6u; i++) {
        int rc;

        memset(&m, 0, sizeof(m));
        m.height                       = 1;                      /* :894 */
        m.round                        = 0;                      /* :895 */
        m.block_part_set_header.total  = 1;                      /* :897 */
        R_HCHECK(cmt_bits_new(&m.block_parts, 1) == CMT_OK, "NewBitArray(1)"); /* :899 */
        m.has_block_parts = true;

        switch (i) {                                             /* :870-887 */
        case 0:                                                  /* valid */
            break;
        case 1:
            m.height = -1;                        /* "negative Height" */
            break;
        case 2:
            m.round = -1;                         /* "negative Round" */
            break;
        case 3:
            m.block_part_set_header.total = 2;    /* "blockParts bit array size
                                                   *  1 not equal to
                                                   *  BlockPartSetHeader.Total 2" */
            break;
        case 4:
            m.block_part_set_header.total = 0;    /* :879 */
            m.has_block_parts = false;            /* :880 NewBitArray(0) = nil */
            memset(&m.block_parts, 0, sizeof(m.block_parts));
            break;                                /* "empty blockParts" */
        case 5:
        default:
            /* :885 — 1602 bits (see above). */
            memset(&m.block_parts, 0, sizeof(m.block_parts));
            R_HCHECK(cmt_bits_new(&m.block_parts,
                                  (int)CMT_MAX_BLOCK_PARTS_COUNT + 1) == CMT_OK,
                     "1602 bits fit the module's capacity");
            break;                                /* "size 1602 not equal to
                                                   *  BlockPartSetHeader.Total 1" */
        }
        rc = cmt_new_valid_block_msg_validate_basic(&m);         /* :903 */
        if (i == 0u) {
            R_HCHECK(rc == CMT_OK, "NewValidBlock valid");
        } else {
            R_HCHECK(rc == CMT_REJECT, "NewValidBlock refused");
        }
    }
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:911-942 —
 * `TestProposalPOLMessageValidateBasic`. Base (:929-933): Height 1,
 * POLRound 1, POL = NewBitArray(1). Five rows, all five drivable.
 *
 * Row #4 (:921-922) is `NewBitArray(MaxVotesCount + 1)` = 10001 bits, and
 * it is the REASON the :1663 gate exists. It is hand-built — 10001 bits
 * need (10001+63)/64 = 157 words, which is exactly CMT_BITS_MAX_ELEMS, so
 * the struct holds it while `cmt_bits_new` refuses it — and the refusal
 * asserted is :1663's "proposalPOL bit array is too big: 10001, max:
 * 10000", not a constructor bound.
 *
 * RED at 7f21263c: CMT_BITS_MAX_BITS was MaxBlockPartsCount (1601), so the
 * 1602-bit case below could not be built at all and the 10001-bit case
 * would not fit the struct's 26 words; the :1663 gate was DEAD (deviation
 * register R3-AUD-19). Both are live at MaxVotesCount.
 */
static int s_proposal_pol_validate_basic(void)
{
    cmt_proposal_pol_msg_t m;
    cmt_bit_array_t        mid;
    cmt_bit_array_t        back;
    uint8_t                buf[CMT_BITS_MAX_ELEMS * 10 + 16];
    size_t                 n = 0u;
    size_t                 i;

    for (i = 0u; i < 5u; i++) {
        int rc;

        memset(&m, 0, sizeof(m));
        m.height            = 1;                                 /* :930 */
        m.proposal_pol_round = 1;                                /* :931 */
        R_HCHECK(cmt_bits_new(&m.proposal_pol, 1) == CMT_OK, "NewBitArray(1)"); /* :932 */
        m.has_proposal_pol = true;
        switch (i) {                                             /* :916-922 */
        case 0:
            break;
        case 1:
            m.height = -1;                        /* "negative Height" */
            break;
        case 2:
            m.proposal_pol_round = -1;            /* "negative ProposalPOLRound" */
            break;
        case 3:
            m.has_proposal_pol = false;           /* NewBitArray(0) = nil */
            memset(&m.proposal_pol, 0, sizeof(m.proposal_pol));
            break;                                /* "empty ProposalPOL bit array" */
        case 4:
        default:
            /* :921 — NewBitArray(MaxVotesCount + 1), hand-built. */
            memset(&m.proposal_pol, 0, sizeof(m.proposal_pol));
            m.proposal_pol.bits    = (int)CMT_MAX_VOTES_COUNT + 1;
            m.proposal_pol.n_elems = cmt_bits_num_elems(m.proposal_pol.bits);
            R_HCHECK(m.proposal_pol.n_elems <= (size_t)CMT_BITS_MAX_ELEMS,
                     "10001 bits fit the struct's 157 words");
            break;                                /* "proposalPOL bit array is
                                                   *  too big: 10001, max:
                                                   *  10000" */
        }
        rc = cmt_proposal_pol_msg_validate_basic(&m);            /* :936 */
        if (i == 0u) {
            R_HCHECK(rc == CMT_OK, "ProposalPOL valid");
        } else {
            R_HCHECK(rc == CMT_REJECT, "ProposalPOL refused");
        }
    }

    /* Between the two bounds: 1602 bits is above MaxBlockPartsCount and
     * below MaxVotesCount, so a reference peer may legally send it. It
     * must survive the DECODER and then pass ValidateBasic. */
    R_HCHECK(cmt_bits_new(&mid, (int)CMT_MAX_BLOCK_PARTS_COUNT + 1) == CMT_OK,
             "1602 bits must be constructible");
    R_HCHECK(cmt_bits_set_index(&mid, 1601, true) == 1, "highest bit");
    R_HCHECK(cmt_bits_to_proto(&mid, buf, sizeof(buf), &n) == CMT_OK,
             "ToProto(1602)");
    R_HCHECK(cmt_bits_from_proto(buf, n, &back) == CMT_OK,
             "the decoder must ACCEPT 1602 bits (cmt_pb.c:3206)");
    R_HCHECK(back.bits == (int)CMT_MAX_BLOCK_PARTS_COUNT + 1, "width survives");
    R_HCHECK(cmt_bits_get_index(&back, 1601) == 1, "bit 1601 survives");

    memset(&m, 0, sizeof(m));
    m.height             = 1;
    m.proposal_pol_round = 1;
    m.proposal_pol       = back;
    m.has_proposal_pol   = true;
    R_HCHECK(cmt_proposal_pol_msg_validate_basic(&m) == CMT_OK,
             "a 1602-bit ProposalPOL must pass ValidateBasic (:1663 is 10000)");
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:944-976 —
 * `TestBlockPartMessageValidateBasic`. `testPart` (:945-946) is an empty
 * Part whose Proof.LeafHash is `tmhash.Sum("leaf")` — here SHA3-512
 * (substitution 1). Three table rows and the trailing `Part{Index: 1}`
 * (:972-975), whose index disagrees with its proof's (part_set.go:53-55).
 */
static int s_block_part_validate_basic(void)
{
    static const struct {
        const char *name;
        int64_t     height;
        int32_t     round;
        bool        expect_err;
    } rows[] = {                                                 /* :954-956 */
        { "Valid Message",   0,  0, false },
        { "Invalid Message", -1, 0, true  },
        { "Invalid Message", 0, -1, true  }
    };
    cmt_part_t *test_part = (cmt_part_t *)calloc(1u, sizeof(cmt_part_t));
    size_t      i;

    R_HCHECK(test_part != NULL, "heap part");
    R_HCHECK(cmt_tmhash_sum((const uint8_t *)"leaf", 4u,
                            test_part->proof.leaf_hash) == CMT_OK,
             "tmhash.Sum(\"leaf\")");                            /* :946 */
    test_part->proof.leaf_hash_len = (size_t)CMT_TMHASH_SIZE;

    for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); i++) {
        cmt_block_part_msg_t *m = (cmt_block_part_msg_t *)calloc(1u, sizeof(*m));
        int                   rc;

        if (m == NULL) {
            free(test_part);
            return 1;
        }
        m->height = rows[i].height;                              /* :963 */
        m->round  = rows[i].round;                               /* :964 */
        m->part   = *test_part;                                  /* :965 */
        rc = cmt_block_part_msg_validate_basic(m);               /* :968 */
        free(m);
        if (rows[i].expect_err) {
            if (rc != CMT_REJECT) {
                fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,
                        __LINE__, rows[i].name);
                free(test_part);
                return 1;
            }
        } else if (rc != CMT_OK) {
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,
                    __LINE__, rows[i].name);
            free(test_part);
            return 1;
        }
        g_tc_checks++;
    }
    /* :972-975 — Part{Index: 1} with a zero proof: index != proof.index. */
    {
        cmt_block_part_msg_t *m = (cmt_block_part_msg_t *)calloc(1u, sizeof(*m));
        int                   rc;

        free(test_part);
        R_HCHECK(m != NULL, "heap message");
        m->part.index = 1;                                       /* :973 */
        rc = cmt_block_part_msg_validate_basic(m);               /* :975 */
        free(m);
        R_HCHECK(rc == CMT_REJECT, "Part{Index: 1} is refused");
    }
    return 0;
}

/** cometbft@709fd12b consensus/reactor_test.go:978-1012 —
 *  `TestHasVoteMessageValidateBasic`. Valid type 0x01, invalid 0x03. */
static int s_has_vote_validate_basic(void)
{
    static const struct {
        bool    expect_err;
        int32_t round;
        int32_t index;
        int64_t height;
        const char *name;
        int32_t type;
    } rows[] = {                                                 /* :991-997 */
        { false,  0,  0,  0, "Valid Message",   0x01 },
        { true,  -1,  0,  0, "Invalid Message", 0x01 },
        { true,   0, -1,  0, "Invalid Message", 0x01 },
        { true,   0,  0,  0, "Invalid Message", 0x03 },
        { true,   0,  0, -1, "Invalid Message", 0x01 }
    };
    size_t i;

    for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); i++) {
        cmt_has_vote_msg_t m;
        int                rc;

        memset(&m, 0, sizeof(m));
        m.height = rows[i].height;                               /* :1003 */
        m.round  = rows[i].round;                                /* :1004 */
        m.type   = rows[i].type;                                 /* :1005 */
        m.index  = rows[i].index;                                /* :1006 */
        rc = cmt_has_vote_msg_validate_basic(&m);                /* :1009 */
        R_HCHECK((rc != CMT_OK) == rows[i].expect_err, rows[i].name);
    }
    return 0;
}

/** The "invalid BlockID" of :1021-1027 and :1068-1074: an empty hash
 *  with a PartSetHeader{Total 1, Hash [0x00]} — a one-byte hash, which
 *  `PartSetHeader.ValidateBasic` refuses (part_set.go:140-142, "wrong
 *  Hash"). */
static void r_invalid_block_id(cmt_block_id_t *out)
{
    cmt_pb_block_id_init(out);
    out->hash_len                     = 0u;
    out->part_set_header.total        = 1;
    out->part_set_header.hash[0]      = 0u;
    out->part_set_header.hash_len     = 1u;
}

/** cometbft@709fd12b consensus/reactor_test.go:1014-1057 —
 *  `TestVoteSetMaj23MessageValidateBasic`. */
static int s_vote_set_maj23_validate_basic(void)
{
    static const struct {
        bool    expect_err;
        int32_t round;
        int64_t height;
        const char *name;
        int32_t type;
        bool    invalid_block_id;
    } rows[] = {                                                 /* :1036-1042 */
        { false,  0,  0, "Valid Message",   0x01, false },
        { true,  -1,  0, "Invalid Message", 0x01, false },
        { true,   0, -1, "Invalid Message", 0x01, false },
        { true,   0,  0, "Invalid Message", 0x03, false },
        { true,   0,  0, "Invalid Message", 0x01, true  }
    };
    size_t i;

    for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); i++) {
        cmt_vote_set_maj23_msg_t m;
        int                      rc;

        memset(&m, 0, sizeof(m));
        m.height = rows[i].height;                               /* :1048 */
        m.round  = rows[i].round;                                /* :1049 */
        m.type   = rows[i].type;                                 /* :1050 */
        if (rows[i].invalid_block_id) {
            r_invalid_block_id(&m.block_id);                     /* :1021 */
        } else {
            cmt_pb_block_id_init(&m.block_id);                   /* :1020 BlockID{} */
        }
        rc = cmt_vote_set_maj23_msg_validate_basic(&m);          /* :1054 */
        R_HCHECK((rc != CMT_OK) == rows[i].expect_err, rows[i].name);
    }
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:1059-1100 —
 * `TestVoteSetBitsMessageValidateBasic`. Base (:1085-1091): Height 1,
 * Round 0, Type 0x01, Votes NewBitArray(1), BlockID{}. Five rows.
 *
 * Row #4 (:1077-1078): `NewBitArray(MaxVotesCount + 1)` — WEAKER for the
 * same reason as ProposalPOL's row #4: the bound refuses the
 * construction, asserted instead of :1806's "votes bit array is too
 * big: 10001, max: 10000".
 */
static int s_vote_set_bits_validate_basic(void)
{
    cmt_vote_set_bits_msg_t m;
    cmt_bit_array_t         wide;
    size_t                  i;

    for (i = 0u; i < 4u; i++) {
        int rc;

        memset(&m, 0, sizeof(m));
        m.height = 1;                                            /* :1086 */
        m.round  = 0;                                            /* :1087 */
        m.type   = 0x01;                                         /* :1088 */
        R_HCHECK(cmt_bits_new(&m.votes, 1) == CMT_OK, "NewBitArray(1)"); /* :1089 */
        m.has_votes = true;
        cmt_pb_block_id_init(&m.block_id);                       /* :1090 */
        switch (i) {                                             /* :1064-1075 */
        case 0:
            break;
        case 1:
            m.height = -1;                        /* "negative Height" */
            break;
        case 2:
            m.type = 0x03;                        /* "invalid Type" */
            break;
        case 3:
        default:
            r_invalid_block_id(&m.block_id);      /* "wrong BlockID: wrong
                                                   *  PartSetHeader: wrong Hash:" */
            break;
        }
        rc = cmt_vote_set_bits_msg_validate_basic(&m);           /* :1094 */
        if (i == 0u) {
            R_HCHECK(rc == CMT_OK, "VoteSetBits valid");
        } else {
            R_HCHECK(rc == CMT_REJECT, "VoteSetBits refused");
        }
    }
    /* :1076-1079 — WEAKER (see above). */
    R_HCHECK(cmt_bits_new(&wide, (int)CMT_MAX_VOTES_COUNT + 1) == CMT_REJECT,
             "a 10001-bit array cannot be built (refused before ValidateBasic)");
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:1131-1165 —
 * `TestVoteMessageValidateBasic`. `randState(2)` gives two validator
 * stubs; `vss[1]` signs a precommit for a random 64-byte hash with a
 * one-part PartSetHeader carrying the same bytes, WITH an extension
 * (:1134-1142). Three rows: valid; ValidatorIndex -1 → "negative
 * ValidatorIndex"; ValidatorIndex 1000 → "INVALID, but passes
 * ValidateBasic, since the method does not know the number of active
 * validators" (:1150-1151).
 *
 * `cmtrand.Bytes(tmhash.Size)` is replaced by a FIXED 64-byte pattern:
 * nothing in the assertion depends on the bytes, and the suite draws no
 * randomness beyond signing (WHAT IT REQUIRES).
 */
static int s_vote_message_validate_basic(void)
{
    r_net_t              *net = r_net_new(1u, 2u, true);     /* randState(2) */
    tc_t                 *tc;
    cmt_vote_t           *vote;
    cmt_vote_msg_t       *m;
    cmt_part_set_header_t psh;
    uint8_t               rand_bytes[CMT_TMHASH_SIZE];
    size_t                i;

    R_CHECK(net != NULL, "network");
    tc = net->nodes[0].tc;
    for (i = 0u; i < sizeof(rand_bytes); i++) {
        rand_bytes[i] = (uint8_t)(0xC3u ^ (i * 7u));
    }
    memset(&psh, 0, sizeof(psh));
    psh.total = 1;                                               /* :1138 */
    memcpy(psh.hash, rand_bytes, sizeof(rand_bytes));            /* :1139 */
    psh.hash_len = sizeof(rand_bytes);
    vote = (cmt_vote_t *)calloc(1u, sizeof(*vote));
    m    = (cmt_vote_msg_t *)calloc(1u, sizeof(*m));
    R_CHECK(vote != NULL && m != NULL, "heap");
    /* :1142 — signVote(vss[1], PrecommitType, randBytes, psh, true) */
    if (tc_sign_vote(tc, &tc->vss[1], R_PRECOMMIT, rand_bytes,
                     sizeof(rand_bytes), &psh, true, vote) != 0) {
        free(vote);
        free(m);
        R_CHECK(false, "signVote");
    }
    for (i = 0u; i < 3u; i++) {
        int rc;

        m->has_vote = true;
        m->vote     = *vote;                                     /* :1156 */
        switch (i) {                                             /* :1148-1151 */
        case 0:
            break;
        case 1:
            m->vote.validator_index = -1;       /* "negative ValidatorIndex" */
            break;
        case 2:
        default:
            m->vote.validator_index = 1000;     /* passes: size unknown here */
            break;
        }
        rc = cmt_vote_msg_validate_basic(m);                     /* :1159 */
        if (i == 1u) {
            if (rc != CMT_REJECT) {
                free(vote);
                free(m);
                R_CHECK(false, "ValidatorIndex -1 is refused");
            }
        } else if (rc != CMT_OK) {
            free(vote);
            free(m);
            R_CHECK(false, "vote message passes ValidateBasic");
        }
        g_tc_checks++;
    }
    /* C-only, STRONGER than the reference: a VoteMessage with no vote
     * (cmt_msgs.h:157-163) is refused rather than dereferenced. */
    m->has_vote = false;
    if (cmt_vote_msg_validate_basic(m) != CMT_REJECT) {
        free(vote);
        free(m);
        R_CHECK(false, "a VoteMessage without a vote is refused");
    }
    g_tc_checks++;
    free(vote);
    free(m);
    r_net_free(net);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Receive before AddPeer / before InitPeer (reactor_test.go:248-305)
 * ════════════════════════════════════════════════════════════════════ */

/** The HasVote{Height 1, Round 1, Index 1, Type Prevote} of :266-272 and
 *  :296-302, marshalled. */
static int r_has_vote_bytes(r_net_t *net, size_t *out_len)
{
    cmt_msg_t *msg = net->msg_scratch;

    memset(msg, 0, sizeof(*msg));
    msg->kind             = CMT_PB_CONS_MSG_HAS_VOTE;
    msg->u.has_vote.height = 1;                                  /* :268 */
    msg->u.has_vote.round  = 1;                                  /* :269 */
    msg->u.has_vote.index  = 1;                                  /* :270 */
    msg->u.has_vote.type   = R_PREVOTE;                          /* :271 */
    return r_marshal(net, msg, out_len);
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:248-276 —
 * `TestReactorReceiveDoesNotPanicIfAddPeerHasntBeenCalledYet`. One
 * node, started; a mock peer (`p2pmock.NewPeer(nil)`) — here peer index
 * 1, a slot with no node behind it — is `InitPeer`'d; `Receive` of a
 * HasVote on the StateChannel BEFORE `AddPeer` must not panic (:263):
 * here, must not FAULT. Then `AddPeer` (:274) — which sends our
 * NewRoundStep to a peer the switch never connected, and the send row
 * answers false, as the reference's mock peer's Send does.
 */
static int s_receive_does_not_panic_if_add_peer_hasnt_been_called_yet(void)
{
    r_net_t *net = r_net_new(1u, 1u, true);                     /* :249-250 */
    uint8_t  mock_id[CMT_PB_PEER_ID_MAX];
    size_t   len = 0u;
    int      rc;

    R_CHECK(net != NULL, "network");
    R_STEP(r_start_consensus_net(net, 1u));                      /* :252 */
    memset(mock_id, 0x5A, sizeof(mock_id));                      /* :257 */
    R_CHECK(cmt_conr_init_peer(&net->nodes[0].conR, 1, mock_id) == CMT_OK,
            "InitPeer(peer)");                                   /* :260 */
    R_STEP(r_has_vote_bytes(net, &len));
    /* :262-273 — "simulate switch calling Receive before AddPeer" */
    rc = cmt_conr_receive(&net->nodes[0].conR, 1, CMT_CONR_STATE_CHANNEL,
                          net->buf_scratch, len);
    R_CHECK(rc == CMT_OK, "Receive before AddPeer does not fault");
    R_CHECK(net->nodes[0].stop_calls == 0, "the peer is not punished");
    R_CHECK(cmt_conr_add_peer(&net->nodes[0].conR, 1) == CMT_OK,
            "AddPeer(peer)");                                    /* :274 */
    r_net_free(net);
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:278-305 —
 * `TestReactorReceivePanicsIfInitPeerHasntBeenCalledYet`. As above but
 * WITHOUT `InitPeer` (:290 "we should call InitPeer here"): the
 * reference panics at reactor.go:255 (:293 `assert.Panics`); here the
 * NODE-LOCAL class of that panic is CMT_FAULT (cmt_conr.h).
 */
static int s_receive_panics_if_init_peer_hasnt_been_called_yet(void)
{
    r_net_t *net = r_net_new(1u, 1u, true);                     /* :279-280 */
    size_t   len = 0u;
    int      rc;

    R_CHECK(net != NULL, "network");
    R_STEP(r_start_consensus_net(net, 1u));                      /* :282 */
    R_STEP(r_has_vote_bytes(net, &len));
    rc = cmt_conr_receive(&net->nodes[0].conR, 1, CMT_CONR_STATE_CHANNEL,
                          net->buf_scratch, len);                /* :294 */
    R_CHECK(rc == CMT_FAULT, "Receive before InitPeer is the :255 panic → FAULT");
    R_CHECK(net->nodes[0].stop_calls == 0, "not a peer error");
    r_net_free(net);
    return 0;
}

/**
 * PACKAGE C2e (register R3-A-5, CLOSING) — the production defect measured
 * at `/tmp/stagef-20260917T024138Z` (seven nodes, production constants):
 * the chain stopped at height 347 after ≈ 1 hour because `recv_arena` was
 * never reset, exhausting after ≈ 380 heights' worth of block parts, at
 * which point `r_copy_arena`'s CMT_REJECT was read by `cmt_conr_receive`
 * as a DECODE error and stopped whichever honest peer's message hit the
 * wall.
 *
 * NO REFERENCE TEST — Go allocates per message and has no arena to
 * exhaust. This drives ≥ 3 × R_ARENA_CAP bytes of BlockPart messages
 * (65 536 B payloads each, the channel's `CMT_BLOCK_PART_SIZE_BYTES`)
 * through `cmt_conr_receive` directly, round-robining FOUR distinct mock
 * peer ids the way several peers gossiping the same part would, and
 * asserts `recv_arena.used` never exceeds one message's decoded size
 * after any receive, and that no peer is EVER stopped for DECODE.
 *
 * RED ON THE OLD CODE (no reset at the top of `cmt_conr_receive`):
 * `recv_arena.used` grows by 65 536 B per receive with nothing ever
 * lowering it, so it exhausts R_ARENA_CAP (8 MiB) exactly at the 129th
 * message (128 * 65536 = 8 388 608 = R_ARENA_CAP, leaving zero room for
 * the 129th's `r_copy_arena` call) — the 129th receive (and every one
 * after it) would return CMT_REJECT-turned-CMT_OK-with-a-log at
 * `cmt_conr_receive`'s decode-error branch, `stop_peer_for_error
 * (CMT_CONR_STOP_DECODE)` would fire for that call's peer, `stop_calls`
 * would end this test in the hundreds rather than 0, and the very first
 * `recv_arena.used` assertion at message 129 would already read
 * R_ARENA_CAP, not "one message's size".
 */
static int s_recv_arena_resets_every_receive(void)
{
    r_net_t  *net = r_net_new(1u, 1u, true);
    uint8_t   mock_id[4][CMT_PB_PEER_ID_MAX];
    uint8_t  *fill;
    cmt_msg_t *msg;
    size_t    len          = 0u;
    size_t    total_pushed = 0u;
    size_t    n_messages   = (3u * (size_t)R_ARENA_CAP) /
                             (size_t)CMT_BLOCK_PART_SIZE_BYTES + 8u;
    size_t    i;

    R_CHECK(net != NULL, "network");
    R_STEP(r_start_consensus_net(net, 1u));

    fill = (uint8_t *)malloc((size_t)CMT_BLOCK_PART_SIZE_BYTES);
    R_CHECK(fill != NULL, "alloc the part payload buffer");
    memset(fill, 0x37, (size_t)CMT_BLOCK_PART_SIZE_BYTES);

    for (i = 0; i < 4u; i++) {
        memset(mock_id[i], (int)(0x60 + i), sizeof(mock_id[i]));
        R_CHECK(cmt_conr_init_peer(&net->nodes[0].conR, (int)(i + 1u),
                                   mock_id[i]) == CMT_OK,
                "InitPeer(mock peer)");
    }

    msg = net->msg_scratch;
    for (i = 0; i < n_messages; i++) {
        int peer_idx = (int)((i % 4u) + 1u);
        int rc;

        memset(msg, 0, sizeof(*msg));
        msg->kind                          = CMT_PB_CONS_MSG_BLOCK_PART;
        msg->u.block_part.height           = 1;
        msg->u.block_part.round            = 0;
        msg->u.block_part.part.index       = 0;
        msg->u.block_part.part.bytes.data  = fill;
        msg->u.block_part.part.bytes.len   = (size_t)CMT_BLOCK_PART_SIZE_BYTES;
        R_CHECK(cmt_tmhash_sum((const uint8_t *)"leaf", 4u,
                               msg->u.block_part.part.proof.leaf_hash) ==
                    CMT_OK,
                "tmhash.Sum(\"leaf\")");
        msg->u.block_part.part.proof.leaf_hash_len = (size_t)CMT_TMHASH_SIZE;

        R_STEP(r_marshal(net, msg, &len));
        rc = cmt_conr_receive(&net->nodes[0].conR, peer_idx,
                              CMT_CONR_DATA_CHANNEL, net->buf_scratch, len);
        R_CHECK(rc == CMT_OK, "Receive of a well-formed BlockPart");
        R_CHECK(net->nodes[0].recv_arena.used <=
                    (size_t)CMT_BLOCK_PART_SIZE_BYTES + 4096u,
                "recv_arena.used never exceeds one message's decoded size");
        R_CHECK(net->nodes[0].stop_calls == 0,
                "no peer is ever stopped for DECODE");
        total_pushed += (size_t)CMT_BLOCK_PART_SIZE_BYTES;
    }
    R_CHECK(total_pushed >= 3u * (size_t)R_ARENA_CAP,
            "pushed at least 3x the arena's old runway");

    free(fill);
    r_net_free(net);
    return 0;
}

/**
 * NO REFERENCE TEST — this is a PORT-ONLY refusal (register R3-AUD-21).
 *
 * WHAT IT PROVES: that `SetHasProposal` (reactor.go:1096-1119) leaves the
 * PeerState UNTOUCHED when the bit array it needs cannot be built. The
 * reference cannot reach the case — `bits.NewBitArray` allocates whatever
 * `Total` asks and never fails — so it assigns `Proposal = true` (:1108)
 * and the header (:1115) before the array (:1116). This port's
 * constructor refuses a Total above the bit array's capacity, and in the
 * reference's order that left the peer flagged as having announced a
 * proposal with no parts array and a stale `ProposalPOLRound`.
 *
 * RED at 7f21263c: `ps->prs.proposal` and the header were written before
 * the refusal, so the first two assertions below failed.
 */
static int s_set_has_proposal_applies_nothing_on_refusal(void)
{
    cmt_ps_t        *ps;
    cmt_proposal_t  *p;
    cmt_ps_peer_t    peer;
    cmt_ps_scratch_t scratch;
    int              rc;

    /* Heap: a PeerState is several KB of bit arrays. */
    ps = (cmt_ps_t *)calloc(1u, sizeof(*ps));
    p  = (cmt_proposal_t *)calloc(1u, sizeof(*p));
    R_HCHECK(ps != NULL && p != NULL, "heap fixtures");

    /* `cmt_ps_init` FAULTs on a NULL scratch (cmt_ps.c, NewPeerState) —
     * the reactor always hands its own (cmt_conr.c, InitPeer). Nothing
     * here sends, so an empty scratch is enough. (Delta W17-1, found by
     * running: the first draft passed a zeroed peer and never reached
     * the assertions it was written for.) */
    memset(&scratch, 0, sizeof(scratch));
    memset(&peer, 0, sizeof(peer));
    peer.scratch = &scratch;
    R_HCHECK(cmt_ps_init(ps, &peer) == CMT_OK,
             "NewPeerState (reactor.go:1044-1058)");
    R_HCHECK(ps->prs.proposal_pol_round == -1,
             "NewPeerState leaves ProposalPOLRound -1 (:1053)");

    /* The peer is at the proposal's height and round, so :1100 does not
     * return early, and it has not announced a proposal yet (:1104). */
    ps->prs.height = 1;
    ps->prs.round  = 0;
    p->height      = 1;
    p->round       = 0;
    p->pol_round   = 7;
    p->block_id.part_set_header.total = (uint32_t)CMT_BITS_MAX_BITS + 1u;

    rc = cmt_ps_set_has_proposal(ps, p);
    R_HCHECK(rc == CMT_REJECT,
             "a Total above the bit array's capacity is refused");
    R_HCHECK(!ps->prs.proposal,
             "the Proposal flag of :1108 was NOT written");
    R_HCHECK(ps->prs.proposal_block_part_set_header.total == 0u,
             "the header of :1115 was NOT written");
    R_HCHECK(ps->prs.proposal_block_parts == NULL, "and there is no array");
    R_HCHECK(ps->prs.proposal_pol_round == -1,
             "ProposalPOLRound is still NewPeerState's -1, not the "
             "refused proposal's 7");

    /* The same call with a Total the constructor accepts applies ALL of
     * :1108-:1118, so the assertions above are about the REFUSAL and not
     * about the function doing nothing. */
    p->block_id.part_set_header.total = 4u;
    R_HCHECK(cmt_ps_set_has_proposal(ps, p) == CMT_OK, "a legal Total");
    R_HCHECK(ps->prs.proposal, "Proposal (:1108)");
    R_HCHECK(ps->prs.proposal_block_part_set_header.total == 4u,
             "the header (:1115)");
    R_HCHECK(ps->prs.proposal_block_parts != NULL &&
             cmt_bits_size(ps->prs.proposal_block_parts) == 4,
             "a four-bit parts array (:1116)");
    R_HCHECK(ps->prs.proposal_pol_round == 7, "ProposalPOLRound (:1117)");
    R_HCHECK(ps->prs.proposal_pol == NULL, "ProposalPOL nil (:1118)");

    free(p);
    free(ps);
    return 0;
}

/**
 * NO REFERENCE TEST FILE ROW — the rule is libs/service/service.go's, and
 * it is tested here because the reactor is what has it (register
 * R3-AUD-20).
 *
 * WHAT IT PROVES: that a reactor which has been stopped cannot be
 * started again. `BaseService.Start` loads the `stopped` flag (:132),
 * reverts `started` and returns ErrAlreadyStopped (:133-137); the only
 * way back is `Reset` (:200-215), whose `OnReset` panics for this service
 * (:217-220) and which is not ported.
 *
 * RED at 7f21263c: `cmt_conr_start` had no latch, so the second start
 * below returned CMT_OK and re-entered `cmt_cs_start` with every stale
 * PeerState still in the table.
 */
static int s_start_after_stop_is_refused(void)
{
    r_net_t *net = r_net_new(1u, 1u, true);

    R_CHECK(net != NULL, "network");

    /* service.go:169-175 — a Stop BEFORE any Start is ErrNotStarted and
     * REVERTS the `stopped` flag it just set, so the service can still be
     * started. (Verifier A, 2026-09-15: the first W1.7 latch was taken
     * here unconditionally — register R3-AUD-23.) */
    R_CHECK(!net->nodes[0].conR.running && !net->nodes[0].conR.stopped,
            "a fresh reactor is neither running nor stopped");
    R_CHECK(cmt_conr_stop(&net->nodes[0].conR) == CMT_REJECT,
            "Stop before Start is ErrNotStarted (service.go:169-175)");
    R_CHECK(!net->nodes[0].conR.stopped,
            "and the latch is NOT taken: `stopped` reverted (:173)");

    R_STEP(r_start_consensus_net(net, 1u));
    R_CHECK(net->nodes[0].conR.running, "the reactor is running");
    R_CHECK(!net->nodes[0].conR.stopped, "and has not been stopped");

    /* service.go:153-158 — a second Start is ErrAlreadyStarted, nothing
     * changes. */
    R_CHECK(cmt_conr_start(&net->nodes[0].conR) == CMT_REJECT,
            "Start twice is ErrAlreadyStarted (service.go:153-158)");
    R_CHECK(net->nodes[0].conR.running, "and it is still running");

    R_CHECK(cmt_conr_stop(&net->nodes[0].conR) == CMT_OK, "OnStop (:95-103)");
    R_CHECK(!net->nodes[0].conR.running, "no longer running");
    R_CHECK(net->nodes[0].conR.stopped, "the latch is set (service.go:168)");

    /* service.go:185-190 — a second Stop is ErrAlreadyStopped. */
    R_CHECK(cmt_conr_stop(&net->nodes[0].conR) == CMT_REJECT,
            "Stop twice is ErrAlreadyStopped (service.go:185-190)");

    R_CHECK(cmt_conr_start(&net->nodes[0].conR) == CMT_REJECT,
            "a stopped reactor refuses to start (service.go:132-138)");
    R_CHECK(!net->nodes[0].conR.running,
            "and it did NOT revive: `started` is not set (:136)");
    r_net_free(net);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * SwitchToConsensus and vote extensions (reactor_test.go:307-415)
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor_test.go:309-415 —
 * `TestSwitchToConsensusVoteExtensions`, the five rows of :310-352, each
 * on a fresh `randState(1)`. Per row (:357-412): the stub's height and
 * the state machine's `state.LastBlockHeight`, `LastValidators` and
 * `VoteExtensionsEnableHeight` are set DIRECTLY (R11); a proposal block
 * is created at the initial height (`createProposalBlock`, state.go:1287-
 * 1290: an empty last extended commit), then `cs.Height` and the block's
 * height are moved to the stored height; a precommit for it is signed
 * with or without an extension and put in a (extended) vote set; the
 * block is saved with an extended commit or a plain one; and
 * `SwitchToConsensus(cs.state, false)` must panic — CMT_FAULT here —
 * exactly when the store lacks the extensions the params require at the
 * stored height (`reconstructLastCommit`, state.go:597-608).
 *
 * `SwitchToConsensus` receives a COPY of `cs.state` (`cmt_cs_get_state`)
 * where the reference passes the object itself (:408, :411):
 * `cmt_cs_update_to_state` refuses its own `cs->state` (cmt_cs.c) and
 * copies whatever it is given, so nothing observable differs.
 */
static int s_switch_to_consensus_vote_extensions(void)
{
    static const struct {
        const char *name;
        int64_t     stored_height;
        int64_t     initial_required_height;
        bool        include_extensions;
        bool        should_panic;
    } rows[] = {                                                 /* :317-351 */
        { "no vote extensions but not required",           2, 0, false, false },
        { "no vote extensions but required this height",   2, 2, false, true  },
        { "no vote extensions and required in future",     2, 3, false, false },
        { "no vote extensions and required previous height", 2, 1, false, true },
        { "vote extensions and required previous height",  2, 1, true,  false }
    };
    size_t i;

    for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); i++) {
        r_net_t                   *net = r_net_new(1u, 1u, true); /* :357 randState(1) */
        r_node_t                  *node;
        tc_t                      *tc;
        cmt_cs_t                  *cs;
        cmt_block_t               *block;
        cmt_extended_commit_t      empty_ec;
        cmt_part_set_t            *parts = NULL;
        cmt_part_set_header_t      psh;
        cmt_vote_set_t            *vs    = NULL;
        cmt_vote_t                *vote;
        cmt_extended_commit_sig_t *ecsigs;
        cmt_commit_sig_t          *csigs;
        cmt_extended_commit_t      ec;
        cmt_commit_t               commit;
        cmt_abci_params_t          ve_param;
        uint8_t                    hash[CMT_TMHASH_SIZE];
        bool                       added = false;
        int                        rc;

        R_CHECK(net != NULL, rows[i].name);
        node = &net->nodes[0];
        tc   = node->tc;
        cs   = tc->cs;
        block  = (cmt_block_t *)calloc(1u, sizeof(*block));
        vote   = (cmt_vote_t *)calloc(1u, sizeof(*vote));
        ecsigs = (cmt_extended_commit_sig_t *)calloc((size_t)TC_MAX_VALS,
                                                     sizeof(*ecsigs));
        csigs  = (cmt_commit_sig_t *)calloc((size_t)TC_MAX_VALS, sizeof(*csigs));
        if (block == NULL || vote == NULL || ecsigs == NULL || csigs == NULL) {
            free(block); free(vote); free(ecsigs); free(csigs);
            R_CHECK(false, "heap");
        }

        /* :358-359 — validator := vs[0]; validator.Height = storedHeight */
        tc->vss[0].height = rows[i].stored_height;
        /* :361-363 — the state machine's state, written directly (R11). */
        cs->state.last_block_height = rows[i].stored_height;
        rc = cmt_validator_set_copy(&cs->state.validators,
                                    &cs->state.last_validators);
        cs->state.consensus_params.abci.vote_extensions_enable_height =
                rows[i].initial_required_height;
        /* :365 — cs.createProposalBlock(): at cs.Height == InitialHeight the
         * last extended commit is empty (state.go:1287-1290); the block
         * executor's row is the fixture's own. */
        memset(&empty_ec, 0, sizeof(empty_ec));
        if (rc == CMT_OK) {
            rc = tc_create_proposal_block(tc, cs->rs.height, &cs->state,
                                          &empty_ec, tc->addr[0],
                                          (size_t)CMT_ADDRESS_SIZE, block);
        }
        /* :368-370 — "Consensus is preparing to do the next height after
         * the stored height." */
        cs->rs.height        = rows[i].stored_height + 1;        /* :369 */
        block->header.height = rows[i].stored_height;            /* :370 */
        if (rc == CMT_OK && tc_make_part_set(tc, block, &parts) != 0) { /* :371 */
            rc = CMT_FAULT;
        }
        if (rc == CMT_OK) {
            rc = cmt_part_set_header(parts, &psh);
        }
        if (rc == CMT_OK) {
            rc = cmt_block_hash(block, hash);
        }
        /* :374-379 — the (extended) vote set for the stored height. */
        if (rc == CMT_OK) {
            if (rows[i].include_extensions) {
                rc = cmt_new_extended_vote_set(cs->state.chain_id,
                        cs->state.chain_id_len, rows[i].stored_height, 0,
                        R_PRECOMMIT, &cs->state.validators, &vs); /* :376 */
            } else {
                rc = cmt_vote_set_new(cs->state.chain_id, cs->state.chain_id_len,
                        rows[i].stored_height, 0, R_PRECOMMIT,
                        &cs->state.validators, &vs);             /* :378 */
            }
        }
        /* :380 — signVote(validator, Precommit, hash, header, includeExt) */
        if (rc == CMT_OK && tc_sign_vote(tc, &tc->vss[0], R_PRECOMMIT, hash,
                                         sizeof(hash), &psh,
                                         rows[i].include_extensions, vote) != 0) {
            rc = CMT_FAULT;
        }
        if (rc == CMT_OK) {
            /* :382-389 — the extension is there iff included. */
            if (rows[i].include_extensions) {
                if (vote->extension_signature_len == 0u) {
                    rc = CMT_FAULT;                              /* :384 */
                }
            } else if (vote->extension.len != 0u ||
                       vote->extension_signature_len != 0u) {
                rc = CMT_FAULT;                                  /* :387-388 */
            }
        }
        /* :391-393 — added, err := voteSet.AddVote(signedVote) */
        if (rc == CMT_OK) {
            rc = cmt_vote_set_add_vote(vs, vote, &added, NULL, NULL);
            if (rc == CMT_OK && !added) {
                rc = CMT_FAULT;
            }
        }
        /* :395 — veHeightParam */
        ve_param.vote_extensions_enable_height =
                rows[i].include_extensions ? rows[i].stored_height : 0;
        if (rc == CMT_OK) {
            rc = cmt_vote_set_make_extended_commit(vs, ve_param, ecsigs,
                                                   (size_t)TC_MAX_VALS, &ec);
        }
        /* :396-400 — SaveBlockWithExtendedCommit / SaveBlock(…ToCommit()) */
        if (rc == CMT_OK) {
            if (rows[i].include_extensions) {
                rc = r_bs_save_block_with_extended_commit_tc(tc, block, parts,
                                                             &ec);  /* :397 */
            } else {
                rc = cmt_extended_commit_to_commit(&ec, csigs, (size_t)TC_MAX_VALS,
                                                   &commit);
                if (rc == CMT_OK) {
                    rc = r_bs_save_block_tc(tc, block, parts, &commit); /* :399 */
                }
            }
        }
        if (rc != CMT_OK) {
            fprintf(stderr, "row \"%s\": setup failed (%d)\n", rows[i].name, rc);
            cmt_vote_set_free(vs);
            free(block); free(vote); free(ecsigs); free(csigs);
            R_CHECK(false, "vote-extension row setup");
        }
        /* :401-404 — reactor := NewReactor(cs, true): r_net_new already
         * built it with waitSync = true. :406-412 — SwitchToConsensus. */
        rc = cmt_cs_get_state(cs, node->state_copy);
        if (rc == CMT_OK) {
            rc = cmt_conr_switch_to_consensus(&node->conR, node->state_copy,
                                              false);            /* :408, :411 */
        }
        cmt_vote_set_free(vs);
        free(block); free(vote); free(ecsigs); free(csigs);
        if (rows[i].should_panic) {
            R_CHECK(rc == CMT_FAULT, rows[i].name);              /* :407 */
        } else {
            R_CHECK(rc == CMT_OK, rows[i].name);                 /* :411 */
            R_CHECK(!cmt_conr_wait_sync(&node->conR), "waitSync cleared");
            R_CHECK(cs->rs.height == rows[i].stored_height + 1,
                    "the state machine is at the height after the stored one");
        }
        r_net_free(net);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * The network scenarios (reactor_test.go:112-122, :225-246, :442-521,
 * :637-653)
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor_test.go:112-122 —
 * `TestReactorBasic`: "Ensure a testnet makes blocks". Four nodes, the
 * once-only mock ticker; wait till everyone makes the first new block.
 * STRONGER than the reference: also asserts that every node committed
 * the SAME block at height 1 and that no peer was disconnected (R13).
 */
static int s_reactor_basic(void)
{
    r_net_t       *net = r_net_new(4u, 4u, true);               /* :113-114 */
    cmt_block_id_t first;
    size_t         j;

    R_CHECK(net != NULL, "network");
    R_STEP(r_start_consensus_net(net, 4u));                      /* :116 */
    R_STEP(r_wait_everyone_next_block(net, 4u));                 /* :119-121 */
    memset(&first, 0, sizeof(first));
    for (j = 0u; j < 4u; j++) {
        tc_store_ent_t *e = r_store_at(&net->nodes[j], 1);

        R_CHECK(e != NULL && e->saved && e->has_seen, "height 1 stored");
        if (j == 0u) {
            first = e->seen.block_id;
        } else {
            R_CHECK(cmt_block_id_equals(&first, &e->seen.block_id),
                    "every node committed the same block at height 1");
        }
        R_CHECK(net->nodes[j].stop_calls == 0, "no peer disconnected");
    }
    r_net_free(net);
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:225-246 —
 * `TestReactorCreatesBlockWhenEmptyBlocksFalse`: "Ensure a testnet makes
 * blocks when there are txs". `CreateEmptyBlocks = false` on every node
 * (:228-230); `kvstore.NewTxFromID(1)` = "1=1" (helpers.go:66-68) is
 * CheckTx'd into node 3's mempool (:236, R8: `next_txs` plus
 * `cmt_cs_notify_txs_available`, the reference's TxsAvailable signal
 * that the mempool raises); wait till everyone makes the first block.
 *
 * NOTE, as in the reference: at the INITIAL height `needProofBlock` is
 * true (state.go:1119-1132), so the first block is proposed whether or
 * not the transaction has arrived — the scenario proves the network
 * makes block 1 under this config, not that the block carries the tx.
 */
static int s_reactor_creates_block_when_empty_blocks_false(void)
{
    r_net_t             *net = r_net_new(4u, 4u, true);         /* :226-227 */
    static const uint8_t tx[3] = { '1', '=', '1' };              /* :236 */
    size_t               j;

    R_CHECK(net != NULL, "network");
    for (j = 0u; j < 4u; j++) {
        net->nodes[j].tc->config.create_empty_blocks = false;    /* :229 */
    }
    R_STEP(r_start_consensus_net(net, 4u));                      /* :232 */
    R_STEP(r_submit_tx(&net->nodes[3], tx, sizeof(tx)));         /* :236 */
    cmt_cs_notify_txs_available(net->nodes[3].tc->cs);
    R_STEP(r_wait_everyone_next_block(net, 4u));                 /* :243-245 */
    for (j = 0u; j < 4u; j++) {
        R_CHECK(net->nodes[j].stop_calls == 0, "no peer disconnected");
    }
    r_net_free(net);
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:442-521 —
 * `TestReactorVotingPowerChange`: "ensure we can make blocks despite
 * cycling a validator set". Four nodes; validator 0's power is changed
 * to 25, then 2, then 26 by `val=` transactions (R7), each followed by
 * four blocks (:480-483, :495-498, :510-513) and a check that
 * `css[0].GetRoundState().LastValidators.TotalVotingPower()` moved
 * (:485-490, :500-505, :515-520). Every block from the second on is
 * `validateBlock`'d against the four validators (:746-760).
 *
 * `newPersistentKVStore` (:450) is the same stand-in as `newKVStore`
 * here (R7); persistence is immaterial in one process.
 */
static int s_reactor_voting_power_change(void)
{
    r_net_t         *net = r_net_new(4u, 4u, true);             /* :443-450 */
    r_active_vals_t  av;
    uint8_t         *tx;
    size_t           tx_len;
    const uint8_t   *txs[1];
    size_t           tx_lens[1];
    int64_t          previous_total;
    int64_t          total;
    size_t           i;
    static const int64_t powers[3] = { 25, 2, 26 };              /* :477, :492, :507 */

    R_CHECK(net != NULL, "network");
    tx = (uint8_t *)calloc((size_t)R_TX_MAX_LEN, 1u);
    R_CHECK(tx != NULL, "heap tx");
    R_STEP(r_start_consensus_net(net, 4u));                      /* :452 */

    /* :455-462 — the map of active validators: the four addresses. */
    av.n = 4u;
    for (i = 0u; i < 4u; i++) {
        memcpy(av.addr[i], net->nodes[i].tc->addr[i], (size_t)CMT_ADDRESS_SIZE);
    }
    /* :464-467 — wait till everyone makes block 1. */
    if (r_wait_everyone_next_block(net, 4u) != 0) {
        free(tx);
        R_CHECK(false, "block 1");
    }

    for (i = 0u; i < 3u; i++) {
        /* :472-477 — updateValidatorTx := MakeValSetChangeTx(val1PubKey, p) */
        tx_len = r_make_val_set_change_tx(net->nodes[0].tc->pk[0], powers[i],
                                          tx, (size_t)R_TX_MAX_LEN);
        if (tx_len == 0u) {
            free(tx);
            R_CHECK(false, "MakeValSetChangeTx");
        }
        txs[0]     = tx;
        tx_lens[0] = tx_len;
        /* :478 — previousTotalVotingPower */
        if (cmt_validator_set_total_voting_power(
                    net->nodes[0].tc->cs->rs.last_validators, &previous_total)
                != CMT_OK) {
            free(tx);
            R_CHECK(false, "TotalVotingPower");
        }
        /* :480-483 — four blocks: the first submits the tx, the second
         * must carry it, two more let it take effect. */
        if (r_wait_for_and_validate_block(net, 4u, &av, txs, tx_lens, 1u) != 0 ||
            r_wait_for_and_validate_block_with_tx(net, 4u, &av, txs, tx_lens, 1u) != 0 ||
            r_wait_for_and_validate_block(net, 4u, &av, NULL, NULL, 0u) != 0 ||
            r_wait_for_and_validate_block(net, 4u, &av, NULL, NULL, 0u) != 0) {
            free(tx);
            R_CHECK(false, "the four blocks of a power change");
        }
        /* :485-490 — "expected voting power to change" */
        if (cmt_validator_set_total_voting_power(
                    net->nodes[0].tc->cs->rs.last_validators, &total) != CMT_OK) {
            free(tx);
            R_CHECK(false, "TotalVotingPower");
        }
        if (total == previous_total) {
            fprintf(stderr, "expected voting power to change (before: %lld, "
                            "after: %lld)\n", (long long)previous_total,
                    (long long)total);
            free(tx);
            R_CHECK(false, "voting power changed");
        }
        g_tc_checks++;
        /* STRONGER than the reference: the total is exactly the four
         * equal powers with validator 0's replaced. */
        if (total != 3 * 10 + powers[i]) {
            fprintf(stderr, "total voting power %lld, expected %lld\n",
                    (long long)total, (long long)(30 + powers[i]));
            free(tx);
            R_CHECK(false, "total voting power is the changed set's");
        }
        g_tc_checks++;
    }
    for (i = 0u; i < 4u; i++) {
        if (net->nodes[i].stop_calls != 0) {
            free(tx);
            R_CHECK(false, "no peer disconnected");
        }
    }
    free(tx);
    r_net_free(net);
    return 0;
}

/**
 * cometbft@709fd12b consensus/reactor_test.go:637-653 —
 * `TestReactorWithTimeoutCommit`: "Check we can make blocks with
 * skip_timeout_commit=false". Four states, the mock ticker that fires
 * every NewHeight timeout (`newMockTickerFunc(false)`, :639),
 * `SkipTimeoutCommit = false` on all (:641-644), and only N-1 = 3 of
 * them started (:646); wait till those three make the first block.
 * With one validator silent no commit is ever complete, so every new
 * height is entered through the (immediately fired) NewHeight timeout
 * rather than `HasAll` (R10).
 */
static int s_reactor_with_timeout_commit(void)
{
    r_net_t *net = r_net_new(4u, 4u, false);                    /* :638-639 */
    size_t   j;

    R_CHECK(net != NULL, "network");
    for (j = 0u; j < 4u; j++) {
        net->nodes[j].tc->config.skip_timeout_commit = false;    /* :643 */
    }
    R_STEP(r_start_consensus_net(net, 3u));                      /* :646 */
    R_STEP(r_wait_everyone_next_block(net, 3u));                 /* :650-652 */
    for (j = 0u; j < 3u; j++) {
        R_CHECK(net->nodes[j].stop_calls == 0, "no peer disconnected");
    }
    R_CHECK(net->nodes[3].tc->apply_calls == 0, "the unstarted node did nothing");
    r_net_free(net);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * main
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *name;
    int (*fn)(void);
} s_case_t;

int main(void)
{
    static const s_case_t cases[] = {
        { "new_round_step_validate_basic",   s_new_round_step_validate_basic },
        { "new_round_step_validate_height",  s_new_round_step_validate_height },
        { "new_valid_block_validate_basic",  s_new_valid_block_validate_basic },
        { "proposal_pol_validate_basic",     s_proposal_pol_validate_basic },
        { "block_part_validate_basic",       s_block_part_validate_basic },
        { "has_vote_validate_basic",         s_has_vote_validate_basic },
        { "vote_set_maj23_validate_basic",   s_vote_set_maj23_validate_basic },
        { "vote_set_bits_validate_basic",    s_vote_set_bits_validate_basic },
        { "vote_message_validate_basic",     s_vote_message_validate_basic },
        { "receive_does_not_panic_if_add_peer_hasnt_been_called_yet",
          s_receive_does_not_panic_if_add_peer_hasnt_been_called_yet },
        { "receive_panics_if_init_peer_hasnt_been_called_yet",
          s_receive_panics_if_init_peer_hasnt_been_called_yet },
        { "recv_arena_resets_every_receive",
          s_recv_arena_resets_every_receive },
        { "set_has_proposal_applies_nothing_on_refusal",
          s_set_has_proposal_applies_nothing_on_refusal },
        { "start_after_stop_is_refused", s_start_after_stop_is_refused },
        { "switch_to_consensus_vote_extensions",
          s_switch_to_consensus_vote_extensions },
        { "reactor_basic",                   s_reactor_basic },
        { "reactor_creates_block_when_empty_blocks_false",
          s_reactor_creates_block_when_empty_blocks_false },
        { "reactor_with_timeout_commit",     s_reactor_with_timeout_commit },
        { "reactor_voting_power_change",     s_reactor_voting_power_change }
    };
    size_t i;
    size_t n = sizeof(cases) / sizeof(cases[0]);
    size_t failed = 0u;

    for (i = 0u; i < n; i++) {
        if (cases[i].fn() != 0) {
            fprintf(stderr, "FAIL %s\n", cases[i].name);
            failed++;
        } else {
            printf("ok   %s\n", cases[i].name);
        }
    }
    printf("test_cmt_conr: %zu/%zu scenarios, %d checks\n",
           n - failed, n, g_tc_checks);
    printf("test_cmt_conr: NOT PORTED — BLOCKED BY: TestReactorWithEvidence "
           "(R3-E), TestReactorRecordsVotesAndBlockParts (statsMsgQueue), "
           "TestReactorValidatorSetChanges (TC_MAX_VALS); YOK: "
           "TestMarshalJSONPeerState\n");
    return (failed == 0u) ? 0 : 1;
}
