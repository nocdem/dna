/**
 * Nodus — cometbft @709fd12b C port, wave R2-BYZ: the MULTI-NODE DRIVER.
 * N independent `tc_t` fixtures (test_cmt_common.h), one state machine
 * each, joined by a connectivity matrix and a message router that stands
 * in for `consensus/reactor.go`. It is the C answer to the p2p switches,
 * the reactors and the goroutines of `TestByzantineConflictingProposals-
 * WithPartition` (consensus/byzantine_test.go:300-458).
 *
 * HEADER-ONLY, every function `static`: exactly ONE translation unit
 * includes it (test_cmt_byzantine.c). It includes test_cmt_common.h and
 * DOES NOT MODIFY IT; everything it needed that the fixture does not
 * expose is built here and named in the wave report.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * By itself, nothing — like the fixture it drives, it asserts no property
 * of the port. What it makes TRUE, and what the scenarios therefore rest
 * on, is:
 *   · N state machines run over the SAME genesis (same chain id, same
 *     four validators, same params) with DIFFERENT keys — node i signs
 *     with validator i's key and presents a distinct 32-byte peer id;
 *   · nothing crosses a fixture boundary except by COPY through the state
 *     machine's public inputs (`cmt_cs_add_vote`,
 *     `cmt_cs_set_proposal_input`, `cmt_cs_add_proposal_block_part_input`)
 *     and the one synchronous peer-state call the reference itself makes
 *     synchronously (`cmt_hvs_set_peer_maj23`, reactor.go:274-283);
 *   · the whole run is a pure function of the scenario: no clock, no
 *     thread, no randomness, no unordered iteration, no timing branch.
 *     Every choice the reference leaves to Go's scheduler or to
 *     `PickRandom` is made here by INDEX ORDER and stated at the site.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: exactly the fixture's — `CMT_SOFTWARE_VERSION` from the
 *   nodus build (shared/dnac/cmt_state.h:150), nothing else; a DEFAULT
 *   BUILD. `QGP_FAULT_INJECT` is NOT set, so the six fail points of
 *   cmt_cs.h:159-168 compile to nothing.
 * ENVIRONMENT: none. No variable is read. `FAIL_TEST_INDEX` is never set.
 * No network, no files, no database, no wall clock.
 * CAPACITIES, all fixed at compile time and all checked at run time —
 * exceeding one is a LOUD failure, never a silent truncation:
 *   · MN_MAX_NODES = TC_MAX_VALS = 4 nodes;
 *   · TC_BLOCK_RECS = 12 registry records PER NODE, and every node
 *     mirrors every block any node makes (see "THE REGISTRY" below), so
 *     the whole network may make at most 12 distinct blocks per scenario;
 *   · MN_SENT_CAP = 128 sent-log entries per directed link;
 *   · the per-node peer queue is cmt_cs's own, 1000 deep (cmt_cs.h:287).
 * ⚠ MEMORY: N fixtures at ~6 MB each (test_cmt_common.h's estimate) plus
 * per node 12 × TC_PARTS_CAP `cmt_part_t` (a part carries a 100-aunt
 * Merkle proof, cmt_merkle.h:81 — about 7 KB each, so ~700 KB per node),
 * plus the sent logs. About 30 MB for four nodes. Heap; freed by
 * `mn_net_free`.
 * ⚠ TIME: every vote is a real ML-DSA-87 signature verified by every
 * node that receives it. Four nodes walking one height sign and verify
 * on the order of a hundred signatures.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on disk, nothing in the environment, no processes. ONE piece
 * of static state: `g_mn_net`, the network currently alive, which the
 * byzantine override needs because a `cmt_cs_t` callback has no way to
 * reach the driver except through the fixture it belongs to (the same
 * shape as the fixture's own `g_tc_checks`). `mn_net_free` clears it. Two
 * networks alive at once is not supported and is refused by
 * `mn_net_new`.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 * The fixture's ten ways (test_cmt_common.h) all apply, per node. These
 * are the driver's own:
 *  M1. THE ROUTER IS NOT THE REACTOR. It ports the reactor's THREE gossip
 *      routines and its VoteSetMaj23 query as RULES evaluated against the
 *      RECEIVER'S REAL ROUND STATE, read directly (`mn_gossip_data`,
 *      `mn_gossip_votes`, `mn_query_maj23`, each citing reactor.go). The
 *      reference's reactor never sees a peer's real state: it keeps a
 *      PeerState (reactor.go:1047-1482) fed by NewRoundStep, NewValidBlock,
 *      HasVote, ProposalPOL and VoteSetBits messages, all delayed and all
 *      approximate. Here the peer's height, round, step, proposal,
 *      part-set header, POL round and LastCommit round are EXACT and
 *      INSTANTANEOUS. What is kept per link is only what the reference's
 *      PeerState keeps that exact knowledge cannot replace: which messages
 *      have already crossed THIS link (the sent log, standing in for
 *      SetHasVote / SetHasProposalBlockPart / SetHasProposal after a send)
 *      and the catch-up commit round (:1241-1267). A defect that shows
 *      only when the peer state LAGS or is WRONG is invisible here. The
 *      reactor's peer-state bookkeeping, gossip rate limiting
 *      (PeerGossipSleepDuration, PeerQueryMaj23SleepDuration), its
 *      `TrySend` drops, its statistics and its catch-up from a block store
 *      more than one height behind (reactor.go:743-769) are NOT modelled;
 *      the last of these is a LOUD FAILURE if a scenario ever needs it.
 *  M2. LOWEST INDEX REPLACES PickRandom. reactor.go:553, :649 and :1188
 *      pick a random missing part or vote; this driver picks the lowest
 *      index. One legal choice out of many, fixed.
 *  M3. ONE INTERLEAVING. `mn_round` steps node 0, then 1, … each ONCE
 *      (one `receiveRoutine` iteration, cmt_cs.h:29-32), fires its timer
 *      by the rule in M5, mirrors new blocks, then runs the three gossip
 *      routines ONCE per connected link in the goroutine start order of
 *      reactor.go:201-203 (data, votes, maj23), links in peer-index
 *      order. The reference's goroutines interleave arbitrarily; this is
 *      one schedule they could produce, chosen because it is the simplest
 *      to reason about, not because it is representative.
 *  M4. THE BYZANTINE NODE IS BYZANTINE IN EXACTLY ONE WAY: it builds two
 *      blocks and sends each half of its peers a different proposal, its
 *      parts and a prevote and precommit for it (byzantine_test.go:459-
 *      554), and it prevotes nothing through its own state machine (:345).
 *      That is what the reference's node 0 does too — and the reference's
 *      `NewByzantineReactor` (:564-596) does ONE thing more that matters:
 *      its `AddPeer` (:573-587) starts NONE of the three gossip routines,
 *      so node 0 never relays anything between the partitions. This driver
 *      reproduces that (`byzantine` nodes skip gossip in `mn_round`). It
 *      does NOT reproduce a node that lies in its NewRoundStep, sends
 *      malformed messages, withholds parts selectively, or equivocates on
 *      prevotes only (byzantine_test.go:38-298, the OTHER test, which the
 *      single-node suite reduces).
 *  M5. TIMERS ARE THE MOCK TICKER'S FOR HONEST NODES AND "WHEN IDLE" FOR
 *      THE BYZANTINE ONE. The reference gives every honest node
 *      `newMockTickerFunc(false)` (byzantine_test.go:308), which drops
 *      every timeout except RoundStepNewHeight and delivers THAT the
 *      moment it is scheduled (common_test.go:945-955); node 0 alone gets
 *      a real ticker (:311-314). Here: an honest node's armed timer fires
 *      iff its step is NEW_HEIGHT, immediately; the byzantine node's fires
 *      whenever it is armed and the node has no queued work. So a real
 *      timeout that would fire MID-QUEUE in wall-clock time never does
 *      here, and no honest node ever sees timeoutPropose, timeoutPrevote
 *      or timeoutPrecommit — exactly the reference's choice, and exactly
 *      as blind.
 *  M6. THE IN-FLIGHT RULE. There is no wire. A message is delivered by
 *      pushing a COPY onto the receiver's peer queue at send time, so a
 *      message is "in flight" only inside the receiver's own queue and
 *      cutting a link afterwards never un-sends it. No scenario here cuts
 *      a link (the partition is initial and only heals), so the rule is
 *      stated, not exercised. A send that the receiver's queue REFUSES
 *      (CMT_REJECT: 1000 entries, cmt_cs.h:48-55) is treated as the
 *      reference's blocked reactor goroutine: not sent, retried next turn.
 *  M7. THE REGISTRY IS MIRRORED, AND THAT IS A FIXTURE ARTEFACT. The
 *      fixture's `decode_block` is a registry lookup over blocks the
 *      fixture itself marshalled (test_cmt_common.h HOW IT CAN LIE (1)), so
 *      a block node i made must be in node j's registry before node j can
 *      decode its parts. After every step this driver DEEP-COPIES every
 *      new record into every other node's registry — connectivity is NOT
 *      consulted, because the registry is the decoder, not the wire — and
 *      builds a part set over each node's own copy. A part routed i → j is
 *      then j's OWN part (same index, byte-compared against i's bytes AND
 *      proof at send time), so no pointer ever crosses a fixture and the
 *      payload outlives the receiver's slot as cmt_part_set.h:56-61
 *      requires. Consequences: a node "knows" the bytes of a block before
 *      any part has reached its state machine — but its STATE MACHINE
 *      still learns the block only through parts, and a wrong part set
 *      assembly still fails `decode_block` (a miss is counted in
 *      `decode_misses`). What this hides is exactly what the fixture's (1)
 *      hides: a marshal/unmarshal asymmetry.
 *  M8. CATCH-UP PARTS COME FROM THE REGISTRY, NOT FROM A STORE THAT KEPT
 *      THEM. The reference serves a lagging peer from
 *      `blockStore.LoadBlockPart` (reactor.go:664); the fixture's store
 *      keeps no parts (test_cmt_common.h HOW IT CAN LIE (10)). The
 *      committed block's IDENTITY is read from the store through
 *      `cmt_cs_load_commit` (state.go:305-314; the fixture's LoadBlockMeta
 *      row carries no BlockID) and its PARTS from the serving node's
 *      registry copy of that block. Same bytes, different shelf.
 *  M9. VoteSetBits IS EXACT KNOWLEDGE. When the reference announces a
 *      +2/3 (VoteSetMaj23) the peer replies with the bits it has for that
 *      block and the sender corrects its PeerState (reactor.go:288-311,
 *      :369-382, :1467-1482). Here the sender reads the receiver's
 *      `BitArrayByBlockID` directly and corrects its sent log by the same
 *      rule, in the same call. The round trip, and anything that could go
 *      wrong in it, does not exist here.
 *      ⚠ NOT quite the same rule, in two places verifier BYZ found:
 *      (a) for validators whose vote WE do not hold, the reference ORs the
 *      peer's positive bits into its PeerState (:1473-1479, `votes.Sub(
 *      ourVotes).Or(msg.Votes)`); `mn_announce_maj23` leaves the sent log
 *      untouched for them, so this driver may later re-send a vote the
 *      peer already had — a harmless duplicate, `(false, nil)` at the
 *      receiver. (b) the reference also learns what a peer holds from the
 *      peer's own HasVote messages (`ApplyHasVoteMessage`); this driver's
 *      `mn_pick_send_vote` consults only what IT sent, so a vote the peer
 *      got from a third party is sent again. Same effect. Neither changes
 *      what a node DECIDES; both make the driver chattier than the reactor.
 * M10. VOTE EXTENSIONS MUST BE DISABLED. `cmt_cs_add_vote` copies the vote
 *      STRUCT (cmt_cs.c:651) and an extension is a pointer into the
 *      sender's arena; routing one would point across fixtures.
 *      `mn_deliver_vote` refuses a vote with an extension. The reference
 *      test runs with extensions disabled too (randGenesisDoc passes nil
 *      params, common_test.go:770 → genesis.go:83-84 →
 *      params.go:127-132), so nothing is lost for THESE scenarios; a
 *      multi-node scenario with extensions on cannot be written on this
 *      driver.
 * M11. THE SYNCHRONOUS SENDS. `byzantineDecideProposalFunc` sends through
 *      `go sendProposalAndParts(...)` (byzantine_test.go:502, :504); here
 *      the sends happen synchronously inside node 0's `decide_proposal`
 *      callback, i.e. inside node 0's own `cmt_cs_step`. That is a legal
 *      schedule of the goroutines (they may run at once) and it touches
 *      only OTHER nodes' queues, never node 0's own state machine — which
 *      is what cmt_cs.h:332-334's re-entrancy rule protects.
 * M12. THE PEER ORDER OF THE SPLIT IS THIS DRIVER'S. byzantine_test.go:498
 *      takes `sw.Peers().List()`, whose order the p2p switch does not
 *      specify (:409 "note peers and switches order don't match"); here
 *      peers are in INDEX ORDER, so with N = 4 partition A is always node 1
 *      and partition B is {2, 3}. The reference could have put any of the
 *      three alone.
 * M13. START IS SETTLED. `mn_net_start` starts each honest node and lets
 *      it run to quiescence BEFORE the byzantine node starts — the
 *      reference's :395-405 ("these must be started before the byz"). It
 *      is done because this port polls the peer queue BEFORE the tock
 *      (cmt_cs.h:17-32): had the byzantine proposal reached a node before
 *      that node consumed its NEW_HEIGHT tock, the node would have
 *      installed the proposal at step NEW_HEIGHT and skipped
 *      `enterNewRound` for round 0 (state.go:1055-1062's guard), a path
 *      the reference permits but its test never takes.
 * M14. THE STEP BUDGET IS A LIVENESS BOUND OF THIS DRIVER'S SCHEDULE. The
 *      reference's ten-second deadline (byzantine_test.go:444-453)
 *      becomes a number of network rounds. Exhausting it is a FAILURE
 *      that dumps every node's state; it is never a skip. The number is
 *      generous (see MN_BUDGET_ROUNDS) and therefore says nothing about
 *      how many rounds the protocol NEEDS — only that it did not need
 *      more.
 * M15. THE LAG-≥2 CATCH-UP IS NOT MODELLED (reactor.go:743-769) and is a
 *      loud failure if reached. In the scenarios here partition B stalls
 *      at height 2 because the height-2 proposer is the partition-A node,
 *      so no node ever lags by two.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/byzantine_test.go  596 lines
 *     6d4bb54ca1997f882a24b7d507d5d94d560966ec977090007a00704f79e8e00f
 *   consensus/common_test.go     991 lines
 *     3e3940e51975f030a0190bc2b5217d93ee768eef30097d8b14b379b006023a38
 *   consensus/state.go          2653 lines
 *     f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *   consensus/reactor.go        1817 lines   (pinned: comet-port-map.md
 *     line 38; read for what a reactor sends, not ported as a reactor)
 *     b7b4fdd346d99d32b713e82f8dcc95a0ac1b1c3a4b25d7d8c3283fc33dd33427
 *   types/vote_set.go            724 lines
 *     548a256c311755a4a2d83696c90030f144952c64c0e3a459ac86baf844c56880
 *   types/priv_validator.go      158 lines
 *     b3b390493189c5ddbe28f1d41e3f4f1839c816e77ce4ea1208b8eae846de717c
 *   store/store.go               765 lines
 *     ec5df10c59582bb29e5032666317b77e176c5a9c7923def4626a3a5b501131e3
 *   consensus/mempool_test.go    211 lines   (deliverTxsRange, :110-116)
 *     44c21284460aa7102527ee55492fa8210c5348d5d917463f8871bbab17623a13
 *   types/genesis.go             137 lines   (map line 31; :83-84)
 *     3f3bd9169368cbd0757a1d6cd88f279569dfa652ca059bb503072b17c16065f4
 *   types/params.go              370 lines   (map line 30; :127-132)
 *     1766c8ec54f5932ce43c77f48a8358237b16428f3bddd69f2998e32a0c2e7746
 *   state/state.go               355 lines   (:317-321)
 *     02dc0f209451d28202e1cc25c901af29eb48ca6e83ec5b8a69d88be10b1472fc
 *
 * @file test_cmt_multinode.h
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_TESTS_TEST_CMT_MULTINODE_H
#define NODUS_TESTS_TEST_CMT_MULTINODE_H

#include "test_cmt_common.h"

/* ══ dimensions ═══════════════════════════════════════════════════════ */

/** byzantine_test.go:301 — `N := 4`. Bounded by the fixture's validator
 *  count, because every node is one validator of the same set. */
#define MN_MAX_NODES        TC_MAX_VALS

/** Sent-log entries per directed link. Each vote, part and proposal
 *  crosses a link at most once between two corrections (see M1), so four
 *  validators × two vote types × a few rounds × two blocks is a few
 *  dozen; overflow is a loud failure. */
#define MN_SENT_CAP         128

/** The reference's ten seconds (byzantine_test.go:444) as network rounds.
 *  Committing a height on this driver's schedule takes on the order of
 *  ten rounds (each round is one step per node); a thousand is two
 *  orders of magnitude of slack and still finishes in seconds, because a
 *  round with nothing to do costs nothing. Exhaustion is a FAILURE. */
#define MN_BUDGET_ROUNDS    1000

/** The bound on `tc_drain`-style settling at start (M13). */
#define MN_SETTLE_STEPS     8192

/** The one transaction `deliverTxsRange(t, cs, 0, 1)` delivers between
 *  the two byzantine blocks (byzantine_test.go:478, mempool_test.go:110-
 *  116). Its bytes are the kvstore's business and immaterial here: any
 *  non-empty transaction makes the two blocks differ. */
#define MN_BYZ_TX_LEN       6u

/* ══ the sent log — the reference's PeerState reduced to this link ════ */

typedef enum {
    MN_SENT_VOTE     = 1,
    MN_SENT_PART     = 2,
    MN_SENT_PROPOSAL = 3
} mn_sent_kind_t;

/**
 * One message identity that crossed a link. Votes are keyed by
 * (height, round, type, validator index, block hash) — so the byzantine
 * node's TWO precommits for the same block (the one it signs by hand and
 * the one its own state machine later signs, with different randomized
 * signatures) are one identity, as they are one bit in the reference's
 * PeerState. Parts by (height, part-set hash, part index). Proposals by
 * (height, round, block hash).
 */
typedef struct {
    uint8_t kind;                        /* mn_sent_kind_t              */
    int64_t height;
    int32_t round;
    int32_t vote_type;
    int32_t index;                       /* validator or part index     */
    uint8_t hash[CMT_TMHASH_SIZE];
    size_t  hash_len;
} mn_sent_t;

/**
 * Per directed link i → j: what this driver keeps of reactor.go's
 * PeerState (:1047-1061) once everything exact knowledge can replace has
 * been replaced (M1).
 */
typedef struct {
    mn_sent_t sent[MN_SENT_CAP];
    size_t    sent_len;
    /** The peer's (height, round) when this link last gossiped; a change
     *  is the reference's NewRoundStep reset (reactor.go:1384-1393,
     *  :1411). */
    int64_t   seen_height;
    int32_t   seen_round;
    /** The peer's part-set header when this link last gossiped; a change
     *  is the reference's NewValidBlock (reactor.go:1417-1432), which
     *  replaces the PeerState's part bits with the peer's real ones. */
    cmt_part_set_header_t seen_psh;
    /** PeerRoundState.CatchupCommitRound (reactor.go:1241-1267), valid
     *  while the peer is at `catchup_height`; -1 is the reference's -1. */
    int64_t   catchup_height;
    int32_t   catchup_round;
} mn_link_t;

/* ══ one node ═════════════════════════════════════════════════════════ */

typedef struct {
    size_t    index;
    tc_t     *tc;
    /** The 32-byte id this node presents as a SENDER. Distinct per node,
     *  never all-zero (that is "self", cmt_vote_set.h:231-242). */
    uint8_t   id[CMT_PB_PEER_ID_MAX];
    /** byzantine_test.go:335-346 and :362-364. */
    bool      byzantine;
    /** byzantine_test.go:311-314 — `css[0].SetTimeoutTicker(NewTimeoutTicker())`;
     *  every other node keeps the mock ticker of :308. See M5. */
    bool      real_ticker;
    /** Per registry record: a part set over THIS node's copy of the
     *  marshalled block, so a part delivered here points into this
     *  node's own storage (M7). */
    cmt_part_t     *rec_parts[TC_BLOCK_RECS];
    cmt_part_set_t  rec_ps[TC_BLOCK_RECS];
    bool            rec_ps_built[TC_BLOCK_RECS];
    /** Set by the byzantine override: the hashes of block1 and block2
     *  (byzantine_test.go:494-495), for the scenario's assertions. */
    bool      byz_hash_set;
    uint8_t   byz_hash[2][CMT_TMHASH_SIZE];
    uint8_t   byz_tx[MN_BYZ_TX_LEN];
    /** A `cmt_cs_step` that returned non-OK, recorded for the dump. */
    int       fault_rc;
} mn_node_t;

/* ══ the network ══════════════════════════════════════════════════════ */

typedef struct {
    size_t     n;
    mn_node_t  nodes[MN_MAX_NODES];
    /** byzantine_test.go:383-393, :418, :424-425 — `Connect2Switches`.
     *  Symmetric: `mn_connect` sets both directions. */
    bool       connected[MN_MAX_NODES][MN_MAX_NODES];
    mn_link_t  links[MN_MAX_NODES][MN_MAX_NODES];
    /** How many of node i's registry records have been mirrored into
     *  node j (M7). */
    size_t     mirrored[MN_MAX_NODES][MN_MAX_NODES];
    /** Network rounds run so far, for the report. */
    int64_t    rounds;
} mn_net_t;

/** The network alive right now — see WHAT IT LEAVES BEHIND. */
static mn_net_t *g_mn_net = NULL;

/* ══ failure plumbing ═════════════════════════════════════════════════ */

/** Report a driver failure at its site and return 1. Every driver
 *  function returns 0 on success and 1 on failure, like the fixture's. */
#define MN_FAIL(msg) do {                                                 \
    fprintf(stderr, "DRIVER failed at %s:%d: %s\n",                       \
            __FILE__, __LINE__, (msg));                                   \
    return 1;                                                             \
} while (0)

/* ══ small accessors ══════════════════════════════════════════════════ */

static cmt_cs_t *mn_cs(const mn_node_t *node)
{
    return node->tc->cs;
}

static mn_node_t *mn_node_of_cs(mn_net_t *net, const cmt_cs_t *cs)
{
    size_t i;

    for (i = 0u; i < net->n; i++) {
        if (net->nodes[i].tc != NULL && net->nodes[i].tc->cs == cs) {
            return &net->nodes[i];
        }
    }
    return NULL;
}

static cmt_peer_id_t mn_peer_id_of(const mn_node_t *node)
{
    cmt_peer_id_t p;

    memcpy(p.id, node->id, sizeof(p.id));
    return p;
}

/** The peer's ProposalBlockPartSetHeader as the reactor would know it —
 *  here the REAL one (M1); the zero header when there is no part set
 *  (part_set.go:237-239 via cmt_part_set_header). */
static void mn_j_psh(const mn_node_t *j, cmt_part_set_header_t *out)
{
    memset(out, 0, sizeof(*out));
    (void)cmt_part_set_header(mn_cs(j)->rs.proposal_block_parts, out);
}

/** PeerRoundState.ProposalPOLRound (reactor.go:1096-1120 sets it from the
 *  proposal the peer has) — here the peer's real proposal, -1 if none. */
static int32_t mn_j_pol_round(const mn_node_t *j)
{
    const cmt_proposal_t *p = mn_cs(j)->rs.proposal;

    return (p != NULL) ? p->pol_round : -1;
}

/** PeerRoundState.LastCommitRound (reactor.go:499-508 puts
 *  `rs.LastCommit.GetRound()` in NewRoundStep) — here the peer's real
 *  LastCommit; -1 for none (vote_set.go:124-126). */
static int32_t mn_j_last_commit_round(const mn_node_t *j)
{
    return cmt_vote_set_get_round(mn_cs(j)->rs.last_commit);
}

/** The block store height of node i (store/store.go's Height(), via the
 *  fixture's row). */
static int64_t mn_store_height(const mn_node_t *i)
{
    return i->tc->store_height;
}

/* ══ the sent log ═════════════════════════════════════════════════════ */

static bool mn_sent_match(const mn_sent_t *e, uint8_t kind, int64_t height,
                          int32_t round, int32_t vote_type, int32_t index,
                          const uint8_t *hash, size_t hash_len)
{
    if (e->kind != kind || e->height != height || e->round != round ||
        e->vote_type != vote_type || e->index != index ||
        e->hash_len != hash_len) {
        return false;
    }
    return hash_len == 0u || memcmp(e->hash, hash, hash_len) == 0;
}

static bool mn_sent_has(const mn_link_t *link, uint8_t kind, int64_t height,
                        int32_t round, int32_t vote_type, int32_t index,
                        const uint8_t *hash, size_t hash_len)
{
    size_t k;

    for (k = 0u; k < link->sent_len; k++) {
        if (mn_sent_match(&link->sent[k], kind, height, round, vote_type,
                          index, hash, hash_len)) {
            return true;
        }
    }
    return false;
}

static int mn_sent_add(mn_link_t *link, uint8_t kind, int64_t height,
                       int32_t round, int32_t vote_type, int32_t index,
                       const uint8_t *hash, size_t hash_len)
{
    mn_sent_t *e;

    if (mn_sent_has(link, kind, height, round, vote_type, index,
                    hash, hash_len)) {
        return 0;
    }
    if (link->sent_len >= (size_t)MN_SENT_CAP || hash_len > CMT_TMHASH_SIZE) {
        MN_FAIL("sent log full (MN_SENT_CAP) or hash too wide");
    }
    e = &link->sent[link->sent_len++];
    memset(e, 0, sizeof(*e));
    e->kind      = kind;
    e->height    = height;
    e->round     = round;
    e->vote_type = vote_type;
    e->index     = index;
    e->hash_len  = hash_len;
    if (hash_len > 0u) {
        memcpy(e->hash, hash, hash_len);
    }
    return 0;
}

/** Remove every entry `pred` selects. Order among the survivors is kept,
 *  so the log stays deterministic. */
static void mn_sent_erase_if(mn_link_t *link,
                             bool (*pred)(const mn_sent_t *e, const void *ctx),
                             const void *ctx)
{
    size_t r;
    size_t w = 0u;

    for (r = 0u; r < link->sent_len; r++) {
        if (!pred(&link->sent[r], ctx)) {
            if (w != r) {
                link->sent[w] = link->sent[r];
            }
            w++;
        }
    }
    link->sent_len = w;
}

static bool mn_pred_part_or_proposal(const mn_sent_t *e, const void *ctx)
{
    (void)ctx;
    return e->kind == (uint8_t)MN_SENT_PART ||
           e->kind == (uint8_t)MN_SENT_PROPOSAL;
}

typedef struct {
    int64_t height;
    int32_t round;
    int32_t vote_type;
    int32_t index;
} mn_vote_key_t;

static bool mn_pred_vote_index(const mn_sent_t *e, const void *ctx)
{
    const mn_vote_key_t *k = (const mn_vote_key_t *)ctx;

    return e->kind == (uint8_t)MN_SENT_VOTE && e->height == k->height &&
           e->round == k->round && e->vote_type == k->vote_type &&
           e->index == k->index;
}

/* ══ the registry mirror (M7) ═════════════════════════════════════════ */

/** Build the part set over record `k` of `node`'s registry — the stand-in
 *  for `MakePartSet` on the receiving side and for `LoadBlockPart` on the
 *  serving side (M8). Idempotent. */
static int mn_rec_ps_build(mn_node_t *node, size_t k)
{
    tc_block_rec_t *rec = &node->tc->recs[k];

    if (node->rec_ps_built[k]) {
        return 0;
    }
    if (!rec->used || rec->marshal == NULL) {
        MN_FAIL("registry record is not registered");
    }
    memset(&node->rec_ps[k], 0, sizeof(node->rec_ps[k]));
    if (cmt_new_part_set_from_data(rec->marshal, rec->marshal_len,
                                   (uint32_t)CMT_BLOCK_PART_SIZE_BYTES,
                                   node->rec_parts[k], (size_t)TC_PARTS_CAP,
                                   &node->rec_ps[k]) != CMT_OK) {
        MN_FAIL("cmt_new_part_set_from_data over a registry copy failed");
    }
    node->rec_ps_built[k] = true;
    return 0;
}

/**
 * Deep-copy one fixture registry record into another fixture's registry.
 *
 * A `cmt_block_t` carries exactly three pointers (cmt_block.h:779-784):
 * `data.txs`, `evidence.evidence` and `last_commit`; the fixture's
 * `tc_create_proposal_block` points the first at the record's own `txs`
 * array whose entries point into the record's `tx_storage` (test_cmt_
 * common.h:637-651), leaves evidence empty (:654), and points the third at
 * the record's own `last_commit`, whose `signatures` is the record's
 * `sigs` (:631-633). Every one of those is re-based onto the destination
 * record; the shape is CHECKED first and a record of any other shape is a
 * loud failure rather than a copy with a dangling pointer.
 */
static int mn_rec_copy(const tc_block_rec_t *src, tc_t *dst_tc)
{
    tc_block_rec_t *dst;
    size_t          k;
    size_t          tx_bytes = 0u;

    if (dst_tc->recs_n >= (size_t)TC_BLOCK_RECS) {
        MN_FAIL("destination registry is full (TC_BLOCK_RECS)");
    }
    if (src->block.evidence.evidence != NULL ||
        src->block.evidence.evidence_len != 0u) {
        MN_FAIL("registry record carries evidence; the fixture makes none");
    }
    if (src->block.data.txs != src->txs) {
        MN_FAIL("registry record's data.txs is not its own txs array");
    }
    if (src->block.last_commit != &src->last_commit) {
        MN_FAIL("registry record's last_commit is not its own");
    }
    if (src->last_commit.signatures_len > 0u &&
        src->last_commit.signatures != src->sigs) {
        MN_FAIL("registry record's signatures are not its own");
    }
    if (src->block.data.txs_len > (size_t)TC_MAX_TXS) {
        MN_FAIL("registry record has more txs than TC_MAX_TXS");
    }
    for (k = 0u; k < src->block.data.txs_len; k++) {
        /* :644-647 lay the txs out contiguously from offset 0. */
        if (src->txs[k].data != src->tx_storage + tx_bytes) {
            MN_FAIL("registry record's txs are not contiguous");
        }
        tx_bytes += src->txs[k].len;
    }
    dst = &dst_tc->recs[dst_tc->recs_n];
    if (dst->tx_storage == NULL || tx_bytes > dst->tx_storage_cap) {
        MN_FAIL("destination record cannot hold the txs");
    }

    dst->block       = src->block;
    dst->last_commit = src->last_commit;
    memcpy(dst->sigs, src->sigs, sizeof(dst->sigs));
    memcpy(dst->txs, src->txs, sizeof(dst->txs));
    if (tx_bytes > 0u) {
        memcpy(dst->tx_storage, src->tx_storage, tx_bytes);
    }
    tx_bytes = 0u;
    for (k = 0u; k < (size_t)TC_MAX_TXS; k++) {
        if (k < src->block.data.txs_len) {
            dst->txs[k].data = dst->tx_storage + tx_bytes;
            tx_bytes += src->txs[k].len;
        } else {
            /* Not part of the block; nothing reads them, and nothing
             * left pointing into the source either. */
            dst->txs[k].data = NULL;
            dst->txs[k].len  = 0u;
        }
    }
    dst->block.data.txs         = dst->txs;
    dst->last_commit.signatures = dst->sigs;
    dst->block.last_commit      = &dst->last_commit;

    free(dst->marshal);
    dst->marshal = (uint8_t *)malloc(src->marshal_len == 0u
                                     ? 1u : src->marshal_len);
    if (dst->marshal == NULL) {
        MN_FAIL("out of memory copying a marshalled block");
    }
    memcpy(dst->marshal, src->marshal, src->marshal_len);
    dst->marshal_len = src->marshal_len;
    memcpy(dst->hash, src->hash, sizeof(dst->hash));
    dst->used = true;
    dst_tc->recs_n++;
    return 0;
}

/** Does `tc` already hold a record with these exact marshalled bytes? */
static bool mn_rec_known(const tc_t *tc, const tc_block_rec_t *rec)
{
    size_t k;

    for (k = 0u; k < tc->recs_n; k++) {
        const tc_block_rec_t *r = &tc->recs[k];

        if (r->used && r->marshal_len == rec->marshal_len &&
            memcmp(r->marshal, rec->marshal, rec->marshal_len) == 0) {
            return true;
        }
    }
    return false;
}

/** Mirror every record any node has made into every other node, and
 *  build the part sets. Called after every step and from the byzantine
 *  override, so a block exists in every registry before any part of it
 *  is routed. */
static int mn_mirror(mn_net_t *net)
{
    size_t i;
    size_t j;
    size_t k;

    for (i = 0u; i < net->n; i++) {
        tc_t *src = net->nodes[i].tc;

        for (k = 0u; k < src->recs_n; k++) {
            if (mn_rec_ps_build(&net->nodes[i], k) != 0) {
                return 1;
            }
        }
        for (j = 0u; j < net->n; j++) {
            if (j == i) {
                continue;
            }
            while (net->mirrored[i][j] < src->recs_n) {
                const tc_block_rec_t *rec = &src->recs[net->mirrored[i][j]];

                if (!mn_rec_known(net->nodes[j].tc, rec)) {
                    if (mn_rec_copy(rec, net->nodes[j].tc) != 0) {
                        return 1;
                    }
                    if (mn_rec_ps_build(&net->nodes[j],
                                        net->nodes[j].tc->recs_n - 1u) != 0) {
                        return 1;
                    }
                }
                net->mirrored[i][j]++;
            }
        }
    }
    return 0;
}

/** The registry record of `node` whose part set has this header. */
static int mn_rec_by_psh(mn_node_t *node, const cmt_part_set_header_t *psh,
                         size_t *out_k)
{
    size_t k;

    for (k = 0u; k < node->tc->recs_n; k++) {
        cmt_part_set_header_t h;

        if (!node->rec_ps_built[k]) {
            continue;
        }
        if (cmt_part_set_header(&node->rec_ps[k], &h) == CMT_OK &&
            cmt_psh_equals(&h, psh)) {
            *out_k = k;
            return 0;
        }
    }
    return 1;
}

/** The registry record of `node` with this block hash. */
static int mn_rec_by_hash(mn_node_t *node, const uint8_t *hash, size_t len,
                          size_t *out_k)
{
    size_t k;

    if (len != (size_t)CMT_TMHASH_SIZE) {
        return 1;
    }
    for (k = 0u; k < node->tc->recs_n; k++) {
        const tc_block_rec_t *r = &node->tc->recs[k];

        if (r->used && memcmp(r->hash, hash, len) == 0) {
            *out_k = k;
            return 0;
        }
    }
    return 1;
}

/* ══ delivery — the peer-facing inputs of state.go:477-510 ════════════ */

/** Field-by-field equality of two parts, proof included. */
static bool mn_part_equal(const cmt_part_t *a, const cmt_part_t *b)
{
    size_t k;

    if (a->index != b->index || a->bytes.len != b->bytes.len) {
        return false;
    }
    if (a->bytes.len > 0u &&
        memcmp(a->bytes.data, b->bytes.data, a->bytes.len) != 0) {
        return false;
    }
    if (a->proof.total != b->proof.total || a->proof.index != b->proof.index ||
        a->proof.leaf_hash_len != b->proof.leaf_hash_len ||
        a->proof.aunts_len != b->proof.aunts_len) {
        return false;
    }
    if (memcmp(a->proof.leaf_hash, b->proof.leaf_hash,
               a->proof.leaf_hash_len) != 0) {
        return false;
    }
    for (k = 0u; k < a->proof.aunts_len; k++) {
        if (a->proof.aunt_len[k] != b->proof.aunt_len[k] ||
            memcmp(a->proof.aunts[k], b->proof.aunts[k],
                   a->proof.aunt_len[k]) != 0) {
            return false;
        }
    }
    return true;
}

/**
 * reactor.go:341-350 → state.go:477-486 — a vote arrives at `to` with
 * `from`'s id. The struct is COPIED by `cmt_cs_add_vote` (cmt_cs.c:651);
 * an extension would be a pointer into `from`'s arena (M10), refused.
 * @return CMT_OK queued; CMT_REJECT the receiver's queue is full (M6);
 *         CMT_FAULT anything else.
 */
static int mn_deliver_vote(const mn_node_t *from, mn_node_t *to,
                           const cmt_vote_t *v)
{
    if (v->extension.len != 0u) {
        fprintf(stderr, "DRIVER: a vote with an extension cannot be routed "
                        "(M10)\n");
        return CMT_FAULT;
    }
    return cmt_cs_add_vote(mn_cs(to), v, from->id, (size_t)CMT_PB_PEER_ID_MAX);
}

/** reactor.go:322-324 → state.go:489-498. No pointers in a proposal. */
static int mn_deliver_proposal(const mn_node_t *from, mn_node_t *to,
                               const cmt_proposal_t *p)
{
    return cmt_cs_set_proposal_input(mn_cs(to), p, from->id,
                                     (size_t)CMT_PB_PEER_ID_MAX);
}

/**
 * reactor.go:327-330 → state.go:501-510 — a block part arrives at `to`.
 * THE PART DELIVERED IS THE RECEIVER'S OWN COPY (M7): the record with
 * this part-set header is found in `to`'s registry, its part at the same
 * index is byte-compared with `part` (payload AND proof), and THAT part
 * is queued, so the payload the receiver's part set will point at
 * (cmt_part_set.h:56-61) is the receiver's own.
 * @return CMT_OK, CMT_REJECT (queue full), CMT_FAULT (a driver defect:
 *         the block is not mirrored, or the copies disagree).
 */
static int mn_deliver_part(const mn_node_t *from, mn_node_t *to,
                           int64_t height, int32_t round,
                           const cmt_part_t *part,
                           const cmt_part_set_header_t *psh)
{
    size_t            k = 0u;
    const cmt_part_t *own;

    if (mn_rec_by_psh(to, psh, &k) != 0) {
        fprintf(stderr, "DRIVER: node %zu has no registry copy of the block "
                        "whose part node %zu sends (mirroring defect)\n",
                to->index, from->index);
        return CMT_FAULT;
    }
    own = cmt_part_set_get_part(&to->rec_ps[k], (size_t)part->index);
    if (own == NULL) {
        fprintf(stderr, "DRIVER: registry copy has no part %u\n",
                (unsigned)part->index);
        return CMT_FAULT;
    }
    if (!mn_part_equal(part, own)) {
        fprintf(stderr, "DRIVER: node %zu's part %u differs from node %zu's "
                        "registry copy of the same block\n",
                from->index, (unsigned)part->index, to->index);
        return CMT_FAULT;
    }
    return cmt_cs_add_proposal_block_part_input(mn_cs(to), height, round, own,
                                                from->id,
                                                (size_t)CMT_PB_PEER_ID_MAX);
}

/* ══ the reactor's rules, evaluated against exact peer state (M1) ═════ */

static bool mn_pred_part(const mn_sent_t *e, const void *ctx)
{
    (void)ctx;
    return e->kind == (uint8_t)MN_SENT_PART;
}

/**
 * reactor.go:1363-1414 (`ApplyNewRoundStepMessage`) — what a change of
 * the peer's height or round does to the PeerState: the proposal flag and
 * the proposal-block-parts bits are reset (:1384-1393) and, on a height
 * change, the catch-up commit round (:1411). Here: the part and proposal
 * entries of the sent log are dropped, and the catch-up round on a height
 * change. Vote entries are keyed by (height, round) and need no reset.
 *
 * And reactor.go:1417-1432 (`ApplyNewValidBlockMessage`) — when the peer
 * announces a (new) part-set header its part bits become its REAL ones:
 * the part entries are dropped, and `mn_j_has_part` reads the real bits.
 * Without this a part sent while the peer had NO part set (dropped at
 * state.go:1966-1977) would stay marked sent after the peer installed one
 * (state.go:1642-1648) and never be sent again.
 */
static void mn_link_sync(mn_link_t *link, const mn_node_t *j)
{
    int64_t               h = mn_cs(j)->rs.height;
    int32_t               r = mn_cs(j)->rs.round;
    cmt_part_set_header_t psh;

    mn_j_psh(j, &psh);
    if (!cmt_psh_equals(&link->seen_psh, &psh)) {
        mn_sent_erase_if(link, mn_pred_part, NULL);          /* :1429-1430 */
        link->seen_psh = psh;
    }
    if (link->seen_height == h && link->seen_round == r) {
        return;
    }
    mn_sent_erase_if(link, mn_pred_part_or_proposal, NULL);  /* :1385-1387 */
    if (link->seen_height != h) {
        link->catchup_height = -1;                            /* :1411      */
        link->catchup_round  = -1;
    }
    link->seen_height = h;
    link->seen_round  = r;
}

/**
 * reactor.go:1194-1238 — `getVoteBitArray`: is there a bit array in the
 * PeerState for votes of (height, round, type), i.e. is this
 * "something worth sending" (:1185-1186)? The PeerState's Height, Round,
 * ProposalPOLRound and LastCommitRound are the peer's REAL ones here;
 * CatchupCommitRound is the link's (:1241-1267).
 */
static bool mn_bits_exist(const mn_node_t *j, const mn_link_t *link,
                          int64_t height, int32_t round, int32_t vote_type)
{
    int64_t jh = mn_cs(j)->rs.height;
    int32_t jr = mn_cs(j)->rs.round;

    if (vote_type != (int32_t)CMT_PB_MSG_TYPE_PREVOTE &&
        vote_type != (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT) {
        return false;                                        /* :1195-1197 */
    }
    if (jh == height) {                                      /* :1199      */
        if (jr == round) {
            return true;                                     /* :1200-1207 */
        }
        if (link->catchup_height == height && link->catchup_round == round) {
            return vote_type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
        }                                                    /* :1208-1215 */
        if (mn_j_pol_round(j) == round) {
            return vote_type == (int32_t)CMT_PB_MSG_TYPE_PREVOTE;
        }                                                    /* :1216-1223 */
        return false;                                        /* :1224      */
    }
    if (jh == height + 1) {                                  /* :1226      */
        if (mn_j_last_commit_round(j) == round) {
            return vote_type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
        }                                                    /* :1227-1234 */
        return false;                                        /* :1235      */
    }
    return false;                                            /* :1237      */
}

/** reactor.go:1241-1267 — `ensureCatchupCommitRound`. The bit-array
 *  aliasing of :1262-1266 is the sent log's business here. */
static void mn_ensure_catchup(mn_link_t *link, const mn_node_t *j,
                              int64_t height, int32_t round)
{
    if (mn_cs(j)->rs.height != height) {                     /* :1242-1244 */
        return;
    }
    if (link->catchup_height == height && link->catchup_round == round) {
        return;                                              /* :1258-1260 */
    }
    link->catchup_height = height;                           /* :1261      */
    link->catchup_round  = round;
}

/**
 * reactor.go:1148-1192 — `PickSendVote` / `PickVoteToSend`, with the
 * LOWEST missing index instead of `PickRandom` (:1188; M2) and "the peer
 * has it" meaning "it crossed this link already" (:1157 `SetHasVote`).
 * @param out_sent receives true when a vote was queued at `j`.
 */
static int mn_pick_send_vote(mn_node_t *i, mn_node_t *j, mn_link_t *link,
                             cmt_vote_set_t *votes, bool *out_sent)
{
    int64_t height;
    int32_t round;
    int32_t vote_type;
    int     size;
    int     k;

    *out_sent = false;
    if (votes == NULL) {
        return 0;
    }
    size = cmt_vote_set_size(votes);
    if (size <= 0) {
        return 0;                                            /* :1172-1174 */
    }
    height    = cmt_vote_set_get_height(votes);              /* :1176      */
    round     = cmt_vote_set_get_round(votes);
    vote_type = (int32_t)cmt_vote_set_type(votes);
    if (cmt_vote_set_is_commit(votes)) {                     /* :1179-1181 */
        mn_ensure_catchup(link, j, height, round);
    }
    if (!mn_bits_exist(j, link, height, round, vote_type)) { /* :1184-1187 */
        return 0;
    }
    for (k = 0; k < size; k++) {                             /* :1188      */
        const cmt_vote_t *v = NULL;
        int               rc;

        if (cmt_vote_set_get_by_index(votes, (int32_t)k, &v) != CMT_OK) {
            MN_FAIL("cmt_vote_set_get_by_index refused an in-range index");
        }
        if (v == NULL) {
            continue;                       /* no vote from this validator */
        }
        if (mn_sent_has(link, (uint8_t)MN_SENT_VOTE, height, round, vote_type,
                        (int32_t)k, v->block_id.hash, v->block_id.hash_len)) {
            continue;
        }
        rc = mn_deliver_vote(i, j, v);                       /* :1151-1156 */
        if (rc == CMT_REJECT) {
            return 0;               /* :1160 — the send did not go through */
        }
        if (rc != CMT_OK) {
            MN_FAIL("delivering a vote failed");
        }
        if (mn_sent_add(link, (uint8_t)MN_SENT_VOTE, height, round, vote_type,
                        (int32_t)k, v->block_id.hash,
                        v->block_id.hash_len) != 0) {        /* :1157      */
            return 1;
        }
        *out_sent = true;
        return 0;
    }
    return 0;
}

/** "Does the peer have part `index` of the set with header `psh`?" —
 *  the PeerState's ProposalBlockParts bit: set when the part crossed
 *  this link (reactor.go:568, :686) or, exactly here, when the peer's
 *  real part set of that header holds it (the reference learns that from
 *  NewValidBlock and from parts the peer sends, :328, :1429-1430). */
static bool mn_j_has_part(const mn_node_t *j, const mn_link_t *link,
                          int64_t height, const cmt_part_set_header_t *psh,
                          uint32_t index)
{
    const cmt_part_set_t *jps = mn_cs(j)->rs.proposal_block_parts;

    if (mn_sent_has(link, (uint8_t)MN_SENT_PART, height, 0, 0, (int32_t)index,
                    psh->hash, psh->hash_len)) {
        return true;
    }
    if (jps != NULL && cmt_part_set_has_header(jps, psh)) {
        cmt_bit_array_t ba;

        memset(&ba, 0, sizeof(ba));
        (void)cmt_part_set_bit_array(jps, &ba);
        return cmt_bits_get_index(&ba, (int)index) == 1;
    }
    return false;
}

/** Queue `part` (a part node i really holds) of the set with header
 *  `psh` at node j, and log it on the link — reactor.go:560-568 / :678-686
 *  `peer.Send` + `SetHasProposalBlockPart`. */
static int mn_send_part(mn_node_t *i, mn_node_t *j, mn_link_t *link,
                        const cmt_part_t *part, int64_t height, int32_t round,
                        const cmt_part_set_header_t *psh, bool *out_sent)
{
    int rc;

    *out_sent = false;
    rc = mn_deliver_part(i, j, height, round, part, psh);
    if (rc == CMT_REJECT) {
        return 0;                                    /* queue full, retry */
    }
    if (rc != CMT_OK) {
        MN_FAIL("delivering a block part failed");
    }
    if (mn_sent_add(link, (uint8_t)MN_SENT_PART, height, 0, 0,
                    (int32_t)part->index, psh->hash, psh->hash_len) != 0) {
        return 1;
    }
    *out_sent = true;
    return 0;
}

/**
 * reactor.go:539-644 — ONE iteration of `gossipDataRoutine`, plus
 * :646-696 `gossipDataForCatchup`. At most one message per call, as the
 * loop sends one and `continue`s.
 */
static int mn_gossip_data(mn_node_t *i, mn_node_t *j, mn_link_t *link)
{
    const cmt_round_state_t *rs = &mn_cs(i)->rs;
    cmt_part_set_header_t    j_psh;
    bool                     sent = false;

    mn_j_psh(j, &j_psh);

    /* :552-572 — "Send proposal Block parts?" Our part set has the header
     * the peer is collecting: send the lowest part it lacks. The height
     * and round in the message are OURS (:563-564). */
    if (rs->proposal_block_parts != NULL &&
        cmt_part_set_has_header(rs->proposal_block_parts, &j_psh)) {
        uint32_t total = cmt_part_set_total(rs->proposal_block_parts);
        uint32_t idx;

        for (idx = 0u; idx < total; idx++) {
            /* :554 — `rs.ProposalBlockParts.GetPart(index)`: the part WE
             * really hold; delivery checks it against the receiver's
             * registry copy and queues that copy (M7). */
            const cmt_part_t *part =
                    cmt_part_set_get_part(rs->proposal_block_parts,
                                          (size_t)idx);

            if (part == NULL) {
                continue;                          /* we do not have it */
            }
            if (mn_j_has_part(j, link, rs->height, &j_psh, idx)) {
                continue;
            }
            if (mn_send_part(i, j, link, part, rs->height, rs->round, &j_psh,
                             &sent) != 0) {
                return 1;
            }
            return 0;                                        /* :570      */
        }
    }

    /* :574-594 — "If the peer is on a previous height that we have, help
     * catch up." The fixture's store is never pruned, so its base is 1
     * whenever it holds anything (:575-576). */
    if (mn_store_height(i) >= 1 && 0 < mn_cs(j)->rs.height &&
        mn_cs(j)->rs.height < rs->height &&
        mn_cs(j)->rs.height <= mn_store_height(i)) {
        cmt_commit_t          commit;
        cmt_part_set_header_t target;
        bool                  found = false;
        uint32_t              idx;
        size_t                k = 0u;
        int64_t               ph = mn_cs(j)->rs.height;

        /* :581, :651 — LoadBlockMeta(prs.Height).BlockID. The fixture's
         * meta row has no BlockID, so the block's identity is read
         * through LoadCommit (state.go:305-314), which carries it (M8). */
        memset(&commit, 0, sizeof(commit));
        if (cmt_cs_load_commit(mn_cs(i), ph, &commit, &found) != CMT_OK ||
            !found) {
            MN_FAIL("a node above height h has no commit for h in its store");
        }
        /* :580-591 — a peer with no part set: the reference initialises
         * ITS view of the peer from the block meta and continues. */
        if (mn_cs(j)->rs.proposal_block_parts == NULL) {
            target = commit.block_id.part_set_header;        /* :587      */
        } else {
            target = j_psh;
        }
        /* :657-662 — the peer's header must be the committed block's. */
        if (!cmt_psh_equals(&commit.block_id.part_set_header, &target)) {
            return 0;                                 /* "sleeping" (:660) */
        }
        /* :649 — the lowest part the peer lacks; :664 — from our store,
         * here our registry copy of the committed block (M8). */
        if (mn_rec_by_hash(i, commit.block_id.hash, commit.block_id.hash_len,
                           &k) != 0) {
            MN_FAIL("we committed a block our registry does not hold");
        }
        for (idx = 0u; idx < target.total; idx++) {
            const cmt_part_t *part;

            if (mn_j_has_part(j, link, ph, &target, idx)) {
                continue;
            }
            part = cmt_part_set_get_part(&i->rec_ps[k], (size_t)idx); /* :664 */
            if (part == NULL) {
                MN_FAIL("the serving node's registry copy lacks the part");
            }
            /* :681-682 — the PEER's height and round, "not our height, so
             * it doesn't matter". */
            if (mn_send_part(i, j, link, part, ph, mn_cs(j)->rs.round,
                             &target, &sent) != 0) {
                return 1;
            }
            return 0;
        }
        return 0;                                            /* :694-695  */
    }

    /* :597-602 — "If height and round don't match, sleep." */
    if (rs->height != mn_cs(j)->rs.height || rs->round != mn_cs(j)->rs.round) {
        return 0;
    }

    /* :610-638 — "Send Proposal && ProposalPOL BitArray?" The peer "has"
     * the proposal when its real round state holds one (the reference
     * learns that from the proposal the peer sent it, :323) or when one
     * crossed this link (:619). The ProposalPOL message (:626-636) tells
     * the peer which POL prevotes WE have so that IT can update ITS view
     * of US; with exact peer state there is nothing for it to update, so
     * it is not modelled (M1). */
    if (rs->proposal != NULL && mn_cs(j)->rs.proposal == NULL &&
        !mn_sent_has(link, (uint8_t)MN_SENT_PROPOSAL, rs->height, rs->round,
                     0, 0, rs->proposal->block_id.hash,
                     rs->proposal->block_id.hash_len)) {
        int rc = mn_deliver_proposal(i, j, rs->proposal);    /* :614-617  */

        if (rc == CMT_REJECT) {
            return 0;
        }
        if (rc != CMT_OK) {
            MN_FAIL("delivering a proposal failed");
        }
        return mn_sent_add(link, (uint8_t)MN_SENT_PROPOSAL, rs->height,
                           rs->round, 0, 0, rs->proposal->block_id.hash,
                           rs->proposal->block_id.hash_len);  /* :619     */
    }
    return 0;                                                /* :640-642  */
}

/**
 * reactor.go:788-844 — `gossipVotesForHeight`, the six attempts in the
 * reference's order, against the peer's REAL step, round and POL round.
 * @param out_sent true when one of them sent.
 */
static int mn_gossip_votes_for_height(mn_node_t *i, mn_node_t *j,
                                      mn_link_t *link, bool *out_sent)
{
    const cmt_round_state_t *rs = &mn_cs(i)->rs;
    cmt_round_step_t         prs_step  = mn_cs(j)->rs.step;
    int32_t                  prs_round = mn_cs(j)->rs.round;
    int32_t                  prs_pol   = mn_j_pol_round(j);

    *out_sent = false;

    /* :795-800 — "If there are lastCommits to send..." */
    if (prs_step == CMT_ROUND_STEP_NEW_HEIGHT) {
        if (mn_pick_send_vote(i, j, link, rs->last_commit, out_sent) != 0) {
            return 1;
        }
        if (*out_sent) {
            return 0;
        }
    }
    /* :802-810 — POL prevotes for a peer still in Propose. */
    if (prs_step <= CMT_ROUND_STEP_PROPOSE && prs_round != -1 &&
        prs_round <= rs->round && prs_pol != -1) {
        if (mn_pick_send_vote(i, j, link, cmt_hvs_prevotes(rs->votes, prs_pol),
                              out_sent) != 0) {
            return 1;
        }
        if (*out_sent) {
            return 0;
        }
    }
    /* :812-817 — prevotes of the peer's round. */
    if (prs_step <= CMT_ROUND_STEP_PREVOTE_WAIT && prs_round != -1 &&
        prs_round <= rs->round) {
        if (mn_pick_send_vote(i, j, link,
                              cmt_hvs_prevotes(rs->votes, prs_round),
                              out_sent) != 0) {
            return 1;
        }
        if (*out_sent) {
            return 0;
        }
    }
    /* :819-824 — precommits of the peer's round. */
    if (prs_step <= CMT_ROUND_STEP_PRECOMMIT_WAIT && prs_round != -1 &&
        prs_round <= rs->round) {
        if (mn_pick_send_vote(i, j, link,
                              cmt_hvs_precommits(rs->votes, prs_round),
                              out_sent) != 0) {
            return 1;
        }
        if (*out_sent) {
            return 0;
        }
    }
    /* :826-831 — prevotes again, "Needed because of validBlock mechanism". */
    if (prs_round != -1 && prs_round <= rs->round) {
        if (mn_pick_send_vote(i, j, link,
                              cmt_hvs_prevotes(rs->votes, prs_round),
                              out_sent) != 0) {
            return 1;
        }
        if (*out_sent) {
            return 0;
        }
    }
    /* :833-841 — POL prevotes. */
    if (prs_pol != -1) {
        if (mn_pick_send_vote(i, j, link, cmt_hvs_prevotes(rs->votes, prs_pol),
                              out_sent) != 0) {
            return 1;
        }
    }
    return 0;                                                /* :843      */
}

/**
 * reactor.go:698-786 — ONE iteration of `gossipVotesRoutine`.
 */
static int mn_gossip_votes(mn_node_t *i, mn_node_t *j, mn_link_t *link)
{
    const cmt_round_state_t *rs = &mn_cs(i)->rs;
    int64_t                  jh = mn_cs(j)->rs.height;
    bool                     sent = false;

    /* :724-729 — same height. */
    if (rs->height == jh) {
        if (mn_gossip_votes_for_height(i, j, link, &sent) != 0) {
            return 1;
        }
        if (sent) {
            return 0;
        }
    }
    /* :731-738 — "If peer is lagging by height 1, send LastCommit." */
    if (jh != 0 && rs->height == jh + 1) {
        if (mn_pick_send_vote(i, j, link, rs->last_commit, &sent) != 0) {
            return 1;
        }
        if (sent) {
            return 0;
        }
    }
    /* :740-769 — lagging by two or more: the reference rebuilds a vote
     * set from the stored commit and gossips from it. NOT MODELLED (M15);
     * a scenario that reaches it fails here rather than stalling. */
    if (jh != 0 && rs->height >= jh + 2 && mn_store_height(i) >= jh) {
        MN_FAIL("a peer lags by two or more heights; the store-commit "
                "catch-up of reactor.go:743-769 is not modelled");
    }
    return 0;                                                /* :771-784  */
}

/**
 * reactor.go:274-311 (the receiver's `VoteSetMaj23` branch) and
 * :357-382 + :1467-1482 (the sender applying the `VoteSetBits` reply):
 * tell node j that node i has +2/3 of (height, round, type) for
 * `block_id`, then correct this link's sent log by what j REALLY holds
 * for that block (M9).
 *
 * `SetPeerMaj23` is applied SYNCHRONOUSLY here and that is faithful: the
 * reference applies it in `Receive` under the state's mutex (:276-283),
 * never through the message queue.
 */
static int mn_announce_maj23(mn_node_t *i, mn_node_t *j, mn_link_t *link,
                             int64_t height, int32_t round, int32_t vote_type,
                             const cmt_block_id_t *block_id)
{
    cmt_vote_set_err_t err = CMT_VOTE_SET_ERR_NONE;
    cmt_vote_set_t    *jvs;
    cmt_bit_array_t    jbits;
    cmt_bit_array_t    ours;
    bool               have_ours = false;
    size_t             k;
    int                rc;

    if (mn_cs(j)->rs.height != height) {                     /* :279-281  */
        return 0;
    }
    rc = cmt_hvs_set_peer_maj23(mn_cs(j)->rs.votes, round, vote_type,
                                mn_peer_id_of(i), block_id, &err);/* :283 */
    if (rc == CMT_FAULT) {
        MN_FAIL("cmt_hvs_set_peer_maj23 faulted");
    }
    if (rc != CMT_OK) {
        /* :284-286 — the reference stops the PEER for a conflicting claim.
         * An honest sender never changes its +2/3; here it is a driver
         * defect and fails loudly. */
        fprintf(stderr, "DRIVER: SetPeerMaj23 refused (err %d)\n", (int)err);
        return 1;
    }

    /* :288-311 — the receiver answers with the bits it has for this block;
     * :1471-1472 — only if the sender tracks that (height, round, type). */
    if (!mn_bits_exist(j, link, height, round, vote_type)) {
        return 0;
    }
    jvs = (vote_type == (int32_t)CMT_PB_MSG_TYPE_PREVOTE)
          ? cmt_hvs_prevotes(mn_cs(j)->rs.votes, round)
          : cmt_hvs_precommits(mn_cs(j)->rs.votes, round);    /* :293-295 */
    memset(&jbits, 0, sizeof(jbits));
    if (jvs != NULL) {
        rc = cmt_vote_set_bit_array_by_block_id(jvs, block_id, &jbits);
        if (rc == CMT_FAULT || rc == CMT_REJECT) {
            MN_FAIL("BitArrayByBlockID failed on the receiver");
        }
    }
    /* :369-381 — at the sender: `ourVotes` is our bits for the block when
     * the announced height is our height, nil otherwise. */
    memset(&ours, 0, sizeof(ours));
    if (mn_cs(i)->rs.height == height) {
        cmt_vote_set_t *ivs = (vote_type == (int32_t)CMT_PB_MSG_TYPE_PREVOTE)
                              ? cmt_hvs_prevotes(mn_cs(i)->rs.votes, round)
                              : cmt_hvs_precommits(mn_cs(i)->rs.votes, round);

        if (ivs != NULL) {
            rc = cmt_vote_set_bit_array_by_block_id(ivs, block_id, &ours);
            if (rc == CMT_FAULT || rc == CMT_REJECT) {
                MN_FAIL("BitArrayByBlockID failed on the sender");
            }
            have_ours = true;
        }
    }
    /* :1473-1479 — `votes.Update(msg.Votes)` when ourVotes is nil, else
     * `votes.Update(votes.Sub(ourVotes).Or(msg.Votes))`: for every
     * validator whose vote for the block WE hold (or every validator, when
     * ourVotes is nil) the peer's bit becomes exactly the peer's answer. */
    for (k = 0u; k < i->tc->nvals; k++) {
        mn_vote_key_t key;

        if (have_ours && cmt_bits_get_index(&ours, (int)k) != 1) {
            continue;
        }
        key.height    = height;
        key.round     = round;
        key.vote_type = vote_type;
        key.index     = (int32_t)k;
        if (cmt_bits_get_index(&jbits, (int)k) == 1) {
            if (mn_sent_add(link, (uint8_t)MN_SENT_VOTE, height, round,
                            vote_type, (int32_t)k, block_id->hash,
                            block_id->hash_len) != 0) {
                return 1;
            }
        } else {
            mn_sent_erase_if(link, mn_pred_vote_index, &key);
        }
    }
    return 0;
}

/** `votes.TwoThirdsMajority()` on a possibly-absent set, as the reference
 *  reads it on a nil `*VoteSet` (vote_set.go:471-473 → false). */
static bool mn_maj23(cmt_vote_set_t *vs, cmt_block_id_t *out)
{
    bool ok = false;

    memset(out, 0, sizeof(*out));
    if (vs == NULL) {
        return false;
    }
    if (cmt_vote_set_two_thirds_majority(vs, out, &ok) != CMT_OK) {
        return false;
    }
    return ok;
}

/**
 * reactor.go:848-945 — ONE iteration of `queryMaj23Routine`: its four
 * blocks, each a `TrySend` of a VoteSetMaj23 the receiver applies at
 * once. The reference sleeps between them; the sleeps are scheduling and
 * are dropped.
 */
static int mn_query_maj23(mn_node_t *i, mn_node_t *j, mn_link_t *link)
{
    const cmt_round_state_t *rs = &mn_cs(i)->rs;
    int64_t                  jh = mn_cs(j)->rs.height;
    int32_t                  jr = mn_cs(j)->rs.round;
    cmt_block_id_t           bid;

    if (rs->height == jh) {
        /* :856-875 — prevotes of the peer's round. */
        if (mn_maj23(cmt_hvs_prevotes(rs->votes, jr), &bid)) {
            if (mn_announce_maj23(i, j, link, jh, jr,
                                  (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bid) != 0) {
                return 1;
            }
        }
        /* :877-895 — precommits of the peer's round. */
        if (mn_maj23(cmt_hvs_precommits(rs->votes, jr), &bid)) {
            if (mn_announce_maj23(i, j, link, jh, jr,
                                  (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                                  &bid) != 0) {
                return 1;
            }
        }
        /* :897-916 — prevotes of the peer's ProposalPOLRound. */
        if (mn_j_pol_round(j) >= 0 &&
            mn_maj23(cmt_hvs_prevotes(rs->votes, mn_j_pol_round(j)), &bid)) {
            if (mn_announce_maj23(i, j, link, jh, mn_j_pol_round(j),
                                  (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bid) != 0) {
                return 1;
            }
        }
    }
    /* :921-939 — "Maybe send Height/CatchupCommitRound/CatchupCommit":
     * the peer is at a height our store has and we have started sending
     * it a commit (the link's CatchupCommitRound is set). LoadCommit is
     * state.go:305-314. */
    if (link->catchup_round != -1 && link->catchup_height == jh && jh > 0 &&
        jh <= mn_store_height(i) && mn_store_height(i) >= 1) {
        cmt_commit_t commit;
        bool         found = false;

        memset(&commit, 0, sizeof(commit));
        if (cmt_cs_load_commit(mn_cs(i), jh, &commit, &found) != CMT_OK) {
            MN_FAIL("cmt_cs_load_commit failed");
        }
        if (found) {                                         /* :926      */
            if (mn_announce_maj23(i, j, link, jh, commit.round,
                                  (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                                  &commit.block_id) != 0) {   /* :927-934 */
                return 1;
            }
        }
    }
    return 0;
}

/* ══ timers (M5) ══════════════════════════════════════════════════════ */

/**
 * Fire the node's armed timer if its ticker would have.
 *   · mock ticker (common_test.go:945-955): only a RoundStepNewHeight
 *     timeout, and it is put on the channel at schedule time — so it
 *     fires the first time this runs after it was armed;
 *   · real ticker (ticker.go): whatever is armed, once the node has
 *     nothing else to do (the determinization of "its duration elapsed").
 * `cmt_cs_on_timer_expired` is a FAULT while a tock is pending
 * (cmt_cs.c:1345-1350), so that is checked first. The fixture's own
 * `tc_fire_timeout` is NOT used: it drains, and a turn is one step.
 */
static int mn_timers(mn_node_t *node)
{
    tc_t     *tc = node->tc;
    cmt_cs_t *cs = tc->cs;

    if (!tc->armed || cs->tock_pending) {
        return 0;
    }
    if (node->real_ticker) {
        if (cmt_cs_has_work(cs)) {
            return 0;
        }
    } else if (cs->ticker.ti.step != CMT_ROUND_STEP_NEW_HEIGHT) {
        return 0;                                    /* :951 dropped     */
    }
    tc->armed = false;
    if (cmt_cs_on_timer_expired(cs) != CMT_OK) {
        MN_FAIL("cmt_cs_on_timer_expired failed");
    }
    return 0;
}

/* ══ the dump ═════════════════════════════════════════════════════════ */

static int mn_count_votes(cmt_vote_set_t *vs)
{
    cmt_bit_array_t ba;

    if (vs == NULL) {
        return 0;
    }
    memset(&ba, 0, sizeof(ba));
    if (cmt_vote_set_bit_array(vs, &ba) != CMT_OK) {
        return 0;
    }
    return cmt_bits_get_num_true_indices(&ba);
}

/** Every node's state, for a failed or exhausted run. */
static void mn_dump(const mn_net_t *net, const char *why)
{
    size_t i;

    fprintf(stderr, "DRIVER dump (%s) after %lld rounds\n", why,
            (long long)net->rounds);
    for (i = 0u; i < net->n; i++) {
        const mn_node_t *node = &net->nodes[i];
        const tc_t      *tc   = node->tc;
        cmt_cs_t        *cs;

        if (tc == NULL) {
            continue;
        }
        cs = tc->cs;
        fprintf(stderr,
                "  node %zu%s: h=%lld r=%d step=%u peer_q=%zu int_q=%zu "
                "tock=%d armed=%d(step %u) commits=%d last_applied_h=%lld "
                "store_h=%lld recs=%zu decode_misses=%d conflicts=%d "
                "prevotes(r)=%d precommits(r)=%d proposal=%d parts=%d/%u "
                "fault_rc=%d\n",
                i, node->byzantine ? " (byzantine)" : "",
                (long long)cs->rs.height, (int)cs->rs.round,
                (unsigned)cs->rs.step, cs->peer_q_len, cs->internal_q_len,
                cs->tock_pending ? 1 : 0, tc->armed ? 1 : 0,
                (unsigned)cs->ticker.ti.step, tc->apply_calls,
                (long long)tc->applied_height, (long long)tc->store_height,
                tc->recs_n, tc->decode_misses, tc->conflict_calls,
                mn_count_votes(cmt_hvs_prevotes(cs->rs.votes, cs->rs.round)),
                mn_count_votes(cmt_hvs_precommits(cs->rs.votes, cs->rs.round)),
                cs->rs.proposal != NULL ? 1 : 0,
                (int)cmt_part_set_count(cs->rs.proposal_block_parts),
                (unsigned)cmt_part_set_total(cs->rs.proposal_block_parts),
                node->fault_rc);
    }
}

/* ══ one network round (M3) ═══════════════════════════════════════════ */

/**
 * Node 0, 1, … in index order: one `cmt_cs_step` if there is work, the
 * timer rule, the registry mirror, then — unless the node is byzantine
 * (M4) — the three gossip routines once per connected peer in
 * peer-index order. A non-OK step is recorded and fails the round.
 */
static int mn_round(mn_net_t *net)
{
    size_t i;
    size_t j;

    for (i = 0u; i < net->n; i++) {
        mn_node_t *node = &net->nodes[i];
        cmt_cs_t  *cs   = mn_cs(node);

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
        if (mn_timers(node) != 0) {
            return 1;
        }
        if (mn_mirror(net) != 0) {
            return 1;
        }
        if (node->byzantine) {
            continue;                              /* reactor.go:573-587 */
        }
        for (j = 0u; j < net->n; j++) {
            mn_link_t *link = &net->links[i][j];

            if (j == i || !net->connected[i][j]) {
                continue;
            }
            mn_link_sync(link, &net->nodes[j]);
            if (mn_gossip_data(node, &net->nodes[j], link) != 0 ||
                mn_gossip_votes(node, &net->nodes[j], link) != 0 ||
                mn_query_maj23(node, &net->nodes[j], link) != 0) {
                return 1;
            }
        }
    }
    net->rounds++;
    return 0;
}

/** A scenario's stopping condition. */
typedef bool (*mn_pred_fn)(const mn_net_t *net, const void *ctx);

/**
 * The reference's `select { case <-done: case <-tick.C: t.Fatalf(...) }`
 * (byzantine_test.go:444-453) as a STEP BUDGET (M14): run rounds until
 * `pred` holds; exhausting the budget, or any node faulting, dumps the
 * network and FAILS. Never a skip.
 */
static int mn_run_until(mn_net_t *net, mn_pred_fn pred, const void *ctx,
                        int64_t budget_rounds, const char *what)
{
    int64_t r;

    for (r = 0; r < budget_rounds; r++) {
        if (pred(net, ctx)) {
            return 0;
        }
        if (mn_round(net) != 0) {
            mn_dump(net, what);
            return 1;
        }
    }
    if (pred(net, ctx)) {
        return 0;
    }
    fprintf(stderr, "DRIVER: STEP BUDGET EXHAUSTED (%lld rounds) waiting "
                    "for: %s\n", (long long)budget_rounds, what);
    mn_dump(net, what);
    return 1;
}

/** Run exactly `rounds` rounds with no stopping condition — the bound a
 *  "this must NOT happen" scenario runs out before looking. */
static int mn_run_rounds(mn_net_t *net, int64_t rounds, const char *what)
{
    int64_t r;

    for (r = 0; r < rounds; r++) {
        if (mn_round(net) != 0) {
            mn_dump(net, what);
            return 1;
        }
    }
    return 0;
}

/* ══ the byzantine node (byzantine_test.go:459-554) ═══════════════════ */

/** byzantine_test.go:345 — `css[i].doPrevote = func(height int64, round
 *  int32) {}`: the byzantine node prevotes nothing through its own state
 *  machine; its votes go out by hand from `sendProposalAndParts`. */
static int mn_byz_do_prevote(cmt_cs_t *cs, int64_t height, int32_t round)
{
    (void)cs;
    (void)height;
    (void)round;
    return CMT_OK;
}

/**
 * byzantine_test.go:509-554 — `sendProposalAndParts`, to ONE peer: the
 * proposal (:519-522), every part (:525-539), then a prevote and a
 * precommit for that block signed by hand (:541-553).
 *
 * The votes are signed with the fixture's MockPV port (`tc_sign_vote`,
 * types/priv_validator.go:73-100), which is what `cs.signVote` reaches
 * through `types.SignAndCheckVote` (state.go:2408) — `DisableChecks()` at
 * :338 is a documented no-op (priv_validator.go:133-136: "MockPV has no
 * safety checks at all"), so there is nothing to disable here either. The
 * timestamp is the frozen clock, which is what `voteTime()` (state.go:
 * 2416-2435) returns for a node that has neither a LockedBlock nor a
 * ProposalBlock, and node 0 has neither at this moment (:461 "Avoid
 * sending on internalMsgQueue and running consensus state").
 *
 * A REFUSED send here is a driver failure, not backpressure: the reference
 * queues these on the peer's connection; a byzantine message that silently
 * vanished would change the scenario.
 */
static int mn_byz_send_set(mn_node_t *byz, mn_node_t *peer,
                           const cmt_proposal_t *prop, size_t rec_k,
                           int64_t height, int32_t round)
{
    tc_t                  *tc = byz->tc;
    cmt_part_set_t        *ps = &byz->rec_ps[rec_k];
    const uint8_t         *hash = tc->recs[rec_k].hash;
    cmt_part_set_header_t  psh;
    cmt_vote_t            *v;
    uint32_t               total;
    uint32_t               k;
    int                    rc;

    if (!byz->rec_ps_built[rec_k]) {
        MN_FAIL("byzantine block has no part set");
    }
    if (cmt_part_set_header(ps, &psh) != CMT_OK) {
        MN_FAIL("cmt_part_set_header failed");
    }

    /* :519-522 — the proposal. */
    rc = mn_deliver_proposal(byz, peer, prop);
    if (rc != CMT_OK) {
        MN_FAIL("byzantine proposal was not accepted onto the peer queue");
    }
    /* :525-539 — the parts, each tagged with OUR height and round. */
    total = cmt_part_set_total(ps);
    for (k = 0u; k < total; k++) {
        const cmt_part_t *part = cmt_part_set_get_part(ps, (size_t)k);

        if (part == NULL) {
            MN_FAIL("byzantine part set is incomplete");
        }
        rc = mn_deliver_part(byz, peer, height, round, part, &psh);
        if (rc != CMT_OK) {
            MN_FAIL("byzantine block part was not accepted onto the peer queue");
        }
    }
    /* :541-553 — the votes. `signVote` stamps cs.Height / cs.Round
     * (state.go:2388-2389); the stub carries them. */
    v = (cmt_vote_t *)calloc(1u, sizeof(*v));
    if (v == NULL) {
        MN_FAIL("out of memory");
    }
    tc->vss[tc->self].height   = height;
    tc->vss[tc->self].round    = round;
    tc->vss[tc->self].has_last = false;
    if (tc_sign_vote(tc, &tc->vss[tc->self], (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
                     hash, (size_t)CMT_TMHASH_SIZE, &psh, false, v) != 0 ||
        mn_deliver_vote(byz, peer, v) != CMT_OK) {           /* :543, :546 */
        free(v);
        MN_FAIL("byzantine prevote was not signed and queued");
    }
    if (tc_sign_vote(tc, &tc->vss[tc->self],
                     (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, hash,
                     (size_t)CMT_TMHASH_SIZE, &psh, false, v) != 0 ||
        mn_deliver_vote(byz, peer, v) != CMT_OK) {           /* :544, :550 */
        free(v);
        MN_FAIL("byzantine precommit was not signed and queued");
    }
    free(v);
    return 0;
}

/**
 * byzantine_test.go:459-507 — `byzantineDecideProposalFunc`, installed as
 * the byzantine node's `decide_proposal` (:340-342; the seam is
 * cmt_cs.h:643-649, exactly as wave T's `s_mempool_progress_in_higher_
 * round` installs `set_proposal`).
 *
 * Two blocks from the same state, a transaction delivered in between so
 * that they differ (:477-478), two proposals signed by node 0, and each
 * peer gets one pair by its position in the peer list: the first half
 * block1, the rest block2 (:500-506). The blocks are built with the
 * fixture's `tc_decide_proposal` — the same `create_proposal_block` the
 * state machine would call, with node 0 as proposer and signer — because
 * `createProposalBlock` (:464, :481) is private to the module.
 *
 * Nothing here touches node 0's own state machine (:461); the proposals
 * never enter its queues, and its round state ends this call exactly as
 * it began it. Both blocks are mirrored into every registry BEFORE any
 * part is sent (M7).
 */
static int mn_byz_decide_proposal(cmt_cs_t *cs, int64_t height, int32_t round)
{
    mn_net_t       *net = g_mn_net;
    mn_node_t      *node;
    tc_t           *tc;
    cmt_proposal_t *prop1;
    cmt_proposal_t *prop2;
    cmt_block_t    *b1 = NULL;
    cmt_block_t    *b2 = NULL;
    size_t          k1;
    size_t          k2;
    size_t          peers[MN_MAX_NODES];
    size_t          npeers = 0u;
    size_t          p;

    if (net == NULL) {
        return CMT_FAULT;
    }
    node = mn_node_of_cs(net, cs);
    if (node == NULL) {
        return CMT_FAULT;
    }
    tc = node->tc;

    prop1 = (cmt_proposal_t *)calloc(1u, sizeof(*prop1));
    prop2 = (cmt_proposal_t *)calloc(1u, sizeof(*prop2));
    if (prop1 == NULL || prop2 == NULL) {
        free(prop1);
        free(prop2);
        return CMT_FAULT;
    }

    /* :464-475 — block1 and proposal1. The mempool holds nothing yet. */
    tc->next_txs_n = 0u;
    if (tc_decide_proposal(tc, tc->self, height, round, prop1, &b1, NULL) != 0) {
        free(prop1);
        free(prop2);
        return CMT_FAULT;
    }
    k1 = tc->recs_n - 1u;

    /* :477-478 — "some new transactions come in (this ensures that the
     * proposals are different)": deliverTxsRange(t, cs, 0, 1). */
    tc_set_next_tx(tc, node->byz_tx, (size_t)MN_BYZ_TX_LEN);

    /* :480-492 — block2 and proposal2. */
    if (tc_decide_proposal(tc, tc->self, height, round, prop2, &b2, NULL) != 0) {
        free(prop1);
        free(prop2);
        return CMT_FAULT;
    }
    k2 = tc->recs_n - 1u;
    (void)b1;
    (void)b2;

    /* M7 — every registry learns both blocks before a part is routed. */
    if (mn_mirror(net) != 0) {
        free(prop1);
        free(prop2);
        return CMT_FAULT;
    }
    /* :494-495 — block1Hash, block2Hash, kept for the scenario. */
    memcpy(node->byz_hash[0], tc->recs[k1].hash, (size_t)CMT_TMHASH_SIZE);
    memcpy(node->byz_hash[1], tc->recs[k2].hash, (size_t)CMT_TMHASH_SIZE);
    node->byz_hash_set = true;

    /* :498 — `sw.Peers().List()`, in INDEX ORDER here (M12). */
    for (p = 0u; p < net->n; p++) {
        if (p != node->index && net->connected[node->index][p]) {
            peers[npeers++] = p;
        }
    }
    /* :500-506 — the first half of the peers get block1, the rest block2.
     * :502/:504 are goroutines; the sends are synchronous here (M11). */
    for (p = 0u; p < npeers; p++) {
        bool first_half = (p < npeers / 2u);

        if (mn_byz_send_set(node, &net->nodes[peers[p]],
                            first_half ? prop1 : prop2,
                            first_half ? k1 : k2, height, round) != 0) {
            free(prop1);
            free(prop2);
            return CMT_FAULT;
        }
    }
    free(prop1);
    free(prop2);
    return CMT_OK;
}

/* ══ construction, connection, start, teardown ════════════════════════ */

/** Release everything `mn_net_new` allocated. Safe on a partly built
 *  network. */
static void mn_net_free(mn_net_t *net)
{
    size_t i;
    size_t k;

    if (net == NULL) {
        return;
    }
    for (i = 0u; i < (size_t)MN_MAX_NODES; i++) {
        mn_node_t *node = &net->nodes[i];

        for (k = 0u; k < (size_t)TC_BLOCK_RECS; k++) {
            free(node->rec_parts[k]);
            node->rec_parts[k] = NULL;
        }
        if (node->tc != NULL) {
            tc_teardown(node->tc);
            free(node->tc);
            node->tc = NULL;
        }
    }
    if (g_mn_net == net) {
        g_mn_net = NULL;
    }
    free(net);
}

/**
 * common_test.go:767-800 (`randConsensusNet`) and byzantine_test.go:
 * 307-346, as one function: N fixtures over ONE genesis, node i holding
 * validator i's key, node `byz_index` made byzantine (-1 for none).
 *
 * Every fixture is `tc_setup(tc, n, 0, 0)`: the SAME derandomised keys,
 * the same address order and therefore the same validator set and the
 * same chain id in every node (test_cmt_common.h:1497-1564, :1588-1592);
 * `vote_extensions_enable_height` 0 because the reference's genesis has
 * nil params (common_test.go:770 → genesis.go:83-84 → params.go:127-132;
 * M10). The fixture memoises validator 0's key (test_cmt_common.h:1404,
 * :1674); node i re-points `self` and re-runs `SetPrivValidator` so the
 * memoised key is its own (cmt_cs.c:573-583).
 *
 * The validators' power is the fixture's testMinPower = 10 where the
 * reference's `randGenesisDoc(nValidators, false, 30, nil)` (:770) gives
 * 30; with four equal powers every threshold is the same fraction and
 * nothing depends on the magnitude.
 *
 * @return the network, or NULL after reporting.
 */
static mn_net_t *mn_net_new(size_t n, int byz_index)
{
    mn_net_t *net;
    size_t    i;
    size_t    j;
    size_t    k;

    if (g_mn_net != NULL) {
        fprintf(stderr, "mn_net_new: a network is already alive\n");
        return NULL;
    }
    if (n == 0u || n > (size_t)MN_MAX_NODES) {
        fprintf(stderr, "mn_net_new: n %zu out of range\n", n);
        return NULL;
    }
    net = (mn_net_t *)calloc(1u, sizeof(*net));
    if (net == NULL) {
        return NULL;
    }
    net->n   = n;
    g_mn_net = net;

    for (i = 0u; i < n; i++) {
        mn_node_t *node = &net->nodes[i];
        tc_t      *tc   = (tc_t *)calloc(1u, sizeof(tc_t));

        node->index = i;
        if (tc == NULL) {
            mn_net_free(net);
            return NULL;
        }
        if (tc_setup(tc, n, 0, 0) != 0) {
            free(tc);
            mn_net_free(net);
            return NULL;
        }
        node->tc = tc;
        /* Node i IS validator i. */
        tc->self = i;
        if (cmt_cs_set_priv_validator(tc->cs, true) != CMT_OK) {
            fprintf(stderr, "mn_net_new: set_priv_validator failed\n");
            mn_net_free(net);
            return NULL;
        }
        for (k = 0u; k < (size_t)CMT_PB_PEER_ID_MAX; k++) {
            node->id[k] = (uint8_t)(0x80u + i);
        }
        for (k = 0u; k < (size_t)TC_BLOCK_RECS; k++) {
            node->rec_parts[k] = (cmt_part_t *)calloc((size_t)TC_PARTS_CAP,
                                                      sizeof(cmt_part_t));
            if (node->rec_parts[k] == NULL) {
                mn_net_free(net);
                return NULL;
            }
        }
        for (k = 0u; k < (size_t)MN_BYZ_TX_LEN; k++) {
            node->byz_tx[k] = (uint8_t)('0' + k);
        }
        node->byzantine   = (byz_index >= 0 && (size_t)byz_index == i);
        /* byzantine_test.go:308 gives every node the mock ticker and
         * :311-314 replaces node 0's with a real one. */
        node->real_ticker = node->byzantine;
        if (node->byzantine) {                                /* :335-346 */
            tc->cs->decide_proposal = mn_byz_decide_proposal; /* :340     */
            tc->cs->do_prevote      = mn_byz_do_prevote;      /* :345     */
        }
    }
    for (i = 0u; i < (size_t)MN_MAX_NODES; i++) {
        for (j = 0u; j < (size_t)MN_MAX_NODES; j++) {
            net->links[i][j].seen_height    = -1;
            net->links[i][j].seen_round     = -1;
            net->links[i][j].catchup_height = -1;
            net->links[i][j].catchup_round  = -1;
        }
    }
    return net;
}

/** p2p.Connect2Switches (byzantine_test.go:392, :418, :424-425): a
 *  link in both directions. */
static void mn_connect(mn_net_t *net, size_t a, size_t b)
{
    if (a < net->n && b < net->n && a != b) {
        net->connected[a][b] = true;
        net->connected[b][a] = true;
    }
}

/**
 * Start one node and let it settle (M13). `SwitchToConsensus(state,
 * skipWAL)` (reactor.go:107-142) → `cs.Start()` → OnStart (state.go:
 * 318-405), which is `cmt_cs_start`. The fixture has no WAL to replay
 * (its read rows answer "nothing", test_cmt_common.h:1238-1256), so
 * `do_wal_catchup` is cleared first — that is `skipWAL = true`, where the
 * reference passes false (byzantine_test.go:399, :405) over a WAL that a
 * fresh node seeds with EndHeight{0} (wal.go:125-132). What is skipped is
 * the replay of an empty log.
 *
 * Settling = firing the NEW_HEIGHT timeout `scheduleRound0` armed (with a
 * zero duration at the initial height, state.go:558/:728-736) and
 * stepping to quiescence, which runs `enterNewRound(h, 0)` and
 * `enterPropose`. For a byzantine node that is where the two proposals
 * are made and sent.
 */
static int mn_node_start(mn_node_t *node)
{
    cmt_cs_t *cs = mn_cs(node);
    int       n;

    cs->do_wal_catchup = false;
    if (cmt_cs_start(cs) != CMT_OK) {                        /* :398-405  */
        MN_FAIL("cmt_cs_start failed");
    }
    for (n = 0; n < MN_SETTLE_STEPS; n++) {
        bool worked = false;

        if (mn_timers(node) != 0) {
            return 1;
        }
        if (!cmt_cs_has_work(cs)) {
            return 0;
        }
        if (cmt_cs_step(cs, &worked) != CMT_OK) {
            MN_FAIL("cmt_cs_step failed while settling at start");
        }
        if (!worked) {
            return 0;
        }
    }
    MN_FAIL("a node did not settle at start (MN_SETTLE_STEPS)");
}

/**
 * byzantine_test.go:395-405 — "start the non-byz state machines. note
 * these must be started before the byz", then the byzantine one. Honest
 * nodes in index order, then the byzantine node. After every start the
 * registry is mirrored, so the byzantine blocks made during node 0's
 * settling are known everywhere (they already are — the override mirrors
 * before it sends — but the invariant is cheap to keep here too).
 */
static int mn_net_start(mn_net_t *net)
{
    size_t i;

    for (i = 0u; i < net->n; i++) {
        if (!net->nodes[i].byzantine) {
            if (mn_node_start(&net->nodes[i]) != 0) {
                return 1;
            }
            if (mn_mirror(net) != 0) {
                return 1;
            }
        }
    }
    for (i = 0u; i < net->n; i++) {
        if (net->nodes[i].byzantine) {
            if (mn_node_start(&net->nodes[i]) != 0) {
                return 1;
            }
            if (mn_mirror(net) != 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* ══ what a scenario reads ════════════════════════════════════════════ */

/**
 * The BlockID this node's store holds for `height`, i.e. what it
 * committed there — read from the seen commit `bs_save_block` recorded
 * (test_cmt_common.h:1064-1092), NOT from `applied_hash`, which is the
 * LAST applied block and may already be a later height's.
 * @return true when the height is committed here.
 */
static bool mn_committed_block_id(const mn_node_t *node, int64_t height,
                                  cmt_block_id_t *out)
{
    const tc_store_ent_t *e = tc_store_at(node->tc, height);

    if (e == NULL || !e->saved || !e->has_seen) {
        return false;
    }
    *out = e->seen.block_id;
    return true;
}

/** Every non-byzantine node has committed `height`. */
static bool mn_all_honest_committed(const mn_net_t *net, int64_t height)
{
    size_t i;

    for (i = 0u; i < net->n; i++) {
        cmt_block_id_t bid;

        if (net->nodes[i].byzantine) {
            continue;
        }
        if (!mn_committed_block_id(&net->nodes[i], height, &bid)) {
            return false;
        }
    }
    return true;
}

#endif /* NODUS_TESTS_TEST_CMT_MULTINODE_H */
