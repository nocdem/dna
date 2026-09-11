/**
 * Nodus — cometbft @709fd12b C port, wave R2-BYZ: the MULTI-NODE byzantine
 * partition scenario, ported from `consensus/byzantine_test.go:300-458`
 * (`TestByzantineConflictingProposalsWithPartition`), plus two C-ONLY
 * scenarios the driver makes cheap.
 *
 * The driver — N fixtures, a connectivity matrix and a router standing in
 * for the reactor — is `test_cmt_multinode.h`, which carries its own four
 * header items (M1-M15). The single-node fixture under each node is
 * `test_cmt_common.h`, which carries ten more. READ BOTH: what this file
 * cannot see is mostly a property of those two, not of the scenarios.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * The question every other scenario in this suite leaves open: given a
 * byzantine PROPOSER that sends CONFLICTING blocks to two halves of a
 * partitioned network, and prevotes and precommits for BOTH, do the
 * honest nodes still commit ONE block? Every scenario in test_cmt_cs.c
 * proves that ONE state machine reacts correctly to inputs handed to it.
 * This one runs FOUR of them against each other and asserts:
 *   · with the byzantine node connected to everyone and the honest nodes
 *     split into A = {one node} and B = {two nodes}, B commits a block
 *     and A commits NOTHING (byzantine_test.go:295-298 "B sees a commit,
 *     A doesn't");
 *   · after the partition heals, EVERY honest node has committed height 1,
 *     the three committed hashes are IDENTICAL, and the hash is one of
 *     the two blocks the byzantine node proposed — which the reference
 *     only implies (it waits for a NewBlock event per node, :421, :433,
 *     and would pass a fork); and it is the SECOND of the two, because
 *     the first can never reach +2/3 (see the derivation at the site);
 *   · the heal path really is the reactor's equivocation-liveness dance
 *     and not an accident: the lagging node commits a block it never had
 *     a proposal for, through LastCommit gossip, a VoteSetMaj23 that
 *     makes `vote_set.go:285-288` accept the equivocator's second
 *     precommit, and catch-up parts — if any of the three were missing the
 *     budget would run out and the dump would show node 1 parked at
 *     PRECOMMIT_WAIT or COMMIT with no block.
 * And, C-ONLY: that four honest nodes with no partition commit one block
 * (the driver's own sanity check), and that a partition that never heals
 * leaves the minority side with NOTHING committed while the majority side
 * commits the block the byzantine node fed it — the safety half of the
 * same question.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION` from the nodus build, as every
 *   cmt_* target has; nothing else — a DEFAULT BUILD. `QGP_FAULT_INJECT`
 *   is NOT set; the six fail points compile to nothing.
 * ENVIRONMENT: none. No variable is read. `FAIL_TEST_INDEX` is never set.
 * No network, no files, no database, no wall clock, no randomness beyond
 * what ML-DSA-87 signing does internally (and nothing here depends on a
 * signature's bytes — test_cmt_common.h HOW IT CAN LIE (4)).
 * The `test_cmt_byzantine` target in nodus/CMakeLists.txt, wired like
 * test_cmt_cs (`target_link_libraries(… nodus dsa nodus crypto)`) by the
 * ORCHESTRATOR in the same commit that landed these files.
 * ⚠ MEMORY: four fixtures plus the driver, about 30 MB of heap per
 * scenario, freed between scenarios (including on the failure path).
 * ⚠ TIME: on the order of a hundred real ML-DSA-87 signatures and their
 * verifications per scenario. Seconds, not minutes.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no environment
 * variables. `g_mn_net` (the driver's one static) is NULL again after
 * each scenario's `mn_net_free`, including on the failure path, so the
 * scenarios do not see each other.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 * The driver's fifteen (M1-M15) and the fixture's ten all apply. These
 * are the scenarios' own:
 *  S1. THE EVIDENCE-POOL CHECK FOUND A DEFECT IN THE PORT, AND THE SAME
 *      COMMIT FIXED IT — so it now PASSES, and its history is the reason
 *      it is last. In the reference the partition-A node reports exactly
 *      one conflicting pair — the byzantine node's two precommits —
 *      because `addVote` returns the ErrVoteConflictingVotes it got from
 *      `VoteSet.AddVote` EVEN WHEN the vote was added through the
 *      peer-maj23 path (vote_set.go:326 `return true, conflicting` →
 *      state.go:2229, :2362 → :2070-2072 `if err != nil` FIRST →
 *      :2094 ReportConflictingVotes). As first written, the port's
 *      `cmt_cs_try_add_vote` returned on `rc == CMT_OK` before looking at
 *      `conflict->present`, so on exactly that path the pool was never
 *      told: an equivocating validator whose second vote arrived after a
 *      VoteSetMaj23 went unreported. This check was placed AFTER every
 *      safety assertion so that its failure would mean everything above
 *      it had PASSED — which is what happened on the first run (14 of 15
 *      checks green, this one red). The ORCHESTRATOR verified the chain
 *      against the reference and moved the conflict test ahead of the
 *      `rc == CMT_OK` return (cmt_cs.c, `cmt_cs_try_add_vote`); the check
 *      then went green. HOW IT CAN LIE about it: it proves the peer-maj23
 *      path reports. The other three (added × conflicting) quadrants —
 *      not-added-and-conflicting in particular, which is the common one
 *      — are exercised by test_cmt_cs.c's `s_byzantine_prevote_equivocation`,
 *      not here.
 *  S2. THE SPLIT IS FIXED: A = {1}, B = {2, 3} (driver M12). The
 *      reference's `Peers().List()` could have isolated any of the three;
 *      a defect that shows only when the lone node is the height-2
 *      proposer (here it IS: node 1 proposes at height 2, so partition B
 *      stalls at (2, 0) waiting for it) or only when it is NOT would show
 *      here in exactly one of the two cases.
 *  S3. ONLY HEIGHT 1 IS ASSERTED. The reference's second wait (:427-436)
 *      consumes ONE NewBlock event per node in `blocksSubs[1..N-2]`; for
 *      the node whose height-1 event was already consumed at :421 that is
 *      its HEIGHT-2 event, so the reference sometimes proves that B moves
 *      on to height 2 after the heal. This port asserts every honest
 *      node's height-1 commit and nothing about height 2. It is stronger
 *      in one way (the reference's loop `for i := 1; i < N-1` at :430
 *      covers css[1] and css[2] only, never css[3] — which may be the
 *      partition-A node) and weaker in that one.
 *  S4. A BUDGET GREEN SAYS NOTHING ABOUT HOW MANY ROUNDS IT TOOK, only
 *      that MN_BUDGET_ROUNDS was enough (M14). The rounds used are printed
 *      on success so a drift toward the budget is visible in the log, not
 *      only at the cliff.
 *  S5. THE NEVER-HEALED SCENARIO'S "NEVER" IS B_NEVER_ROUNDS OF THIS
 *      DRIVER'S SCHEDULE — three hundred rounds after B committed, against
 *      the roughly ten a commit takes here. A liveness bound, not a proof;
 *      it is the same shape the reference's `ensureNoNewTimeout` /
 *      `ensureNoNewRoundStep` waits have (common_test.go), with a step
 *      count where they have milliseconds.
 *  S6. THE BYZANTINE NODE'S OWN OUTCOME IS NOT ASSERTED, as the reference
 *      does not assert it. It runs, it receives everything, it may commit
 *      block2 through the honest nodes' gossip; the only claim made about
 *      it is that it never FAULTS (the reference's node 0 never panics),
 *      which `mn_run_until` enforces for every node.
 *  S7. AT MOST ONE BYZANTINE NODE. `mn_net_new` takes a single byzantine
 *      index; two byzantine nodes cannot be expressed on this driver, so
 *      nothing here says what happens when f = 2 of 4 — which is beyond
 *      the +2/3 assumption and NOT expected to be safe, but is also not
 *      shown to be unsafe. Found by verifier BYZ.
 *  S8. THE BYZANTINE NODE PROPOSES EXACTLY ONCE, at (1, 0). With four
 *      equal powers it would propose again at (1, 4) or (5, 0); neither is
 *      reached (partition B stalls at (2, 0), M15). So `mn_byz_decide_
 *      proposal` at a later height — with a non-empty LastCommit, an
 *      extended commit to carry, a validator set that rotated — is never
 *      exercised. Found by verifier BYZ.
 *  S9. NO SCENARIO CUTS A LINK, AND NONE CAN: the driver has no
 *      disconnect primitive, only `mn_connect`. The partition is INITIAL
 *      and only ever heals. M6's in-flight rule is therefore stated about
 *      a situation this driver cannot produce. Found by verifier BYZ.
 *
 * ── CLOSURE against byzantine_test.go:300-458 ──────────────────────────
 *   :301        N := 4                              → mn_net_new(4, 0)
 *   :307-309    randConsensusNet(N, ..., mockTicker) → mn_net_new: four
 *               tc_setup over one genesis, mock tickers (driver M5)
 *   :311-314    real ticker for css[0]              → nodes[0].real_ticker
 *   :316-326    p2p switches                        → the driver's links
 *   :328-333    NewBlock subscriptions, EnableTxsAvailable → the store's
 *               committed BlockID (`mn_committed_block_id`); txs are the
 *               fixture's `next_txs`, no notifier needed (CreateEmptyBlocks
 *               is true at the reference defaults, config.go:1017-1034)
 *   :335-346    byzantine decideProposal / doPrevote / DisableChecks → the
 *               driver's mn_byz_decide_proposal, mn_byz_do_prevote; the
 *               no-op DisableChecks (priv_validator.go:133-136) is nothing
 *   :355-368    NewReactor / NewByzantineReactor / Store().Save → the
 *               driver IS the reactor stand-in (M1, M4); the genesis state
 *               is what tc_setup built
 *   :371-381    switch teardown                     → mn_net_free
 *   :383-393    MakeConnectedSwitches, node 0 to everyone → mn_connect(0,j)
 *   :395-405    start honest first, then byz        → mn_net_start (M13)
 *   :407-418    peers[0] alone, peers[1]+peers[2] connected → A = {1},
 *               B = {2,3}; mn_connect(2, 3) (M12)
 *   :420-421    <-blocksSubs[ind2].Out()            → mn_run_until(node 3
 *               committed height 1)
 *   :423-425    heal                                → mn_connect(1,2), (1,3)
 *   :427-453    wait for everyone, 10 s deadline    → mn_run_until(all
 *               honest committed height 1, MN_BUDGET_ROUNDS) (M14, S3)
 *   :459-507    byzantineDecideProposalFunc         → mn_byz_decide_proposal
 *   :509-554    sendProposalAndParts                → mn_byz_send_set
 *   :559-596    ByzantineReactor                    → `byzantine` nodes
 *               gossip nothing (M4)
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/byzantine_test.go  596 lines
 *     6d4bb54ca1997f882a24b7d507d5d94d560966ec977090007a00704f79e8e00f
 *   consensus/common_test.go     991 lines
 *     3e3940e51975f030a0190bc2b5217d93ee768eef30097d8b14b379b006023a38
 *   consensus/state.go          2653 lines
 *     f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *   consensus/reactor.go        1817 lines   (comet-port-map.md line 38)
 *     b7b4fdd346d99d32b713e82f8dcc95a0ac1b1c3a4b25d7d8c3283fc33dd33427
 *   types/vote_set.go            724 lines
 *     548a256c311755a4a2d83696c90030f144952c64c0e3a459ac86baf844c56880
 * The driver header lists the rest.
 *
 * @file test_cmt_byzantine.c
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "test_cmt_multinode.h"

/* ══ scenario plumbing ════════════════════════════════════════════════ */

/** As test_cmt_cs.c's S_CHECK, over a network: report, dump, free. Every
 *  scenario names its network `net`. */
#define B_CHECK(cond, msg) do {                                           \
    if (!(cond)) {                                                        \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n",                    \
                __FILE__, __LINE__, (msg));                               \
        mn_dump(net, "at the failed check");                              \
        mn_net_free(net);                                                 \
        return 1;                                                         \
    }                                                                     \
    g_tc_checks++;                                                        \
} while (0)

/** Run a driver step that already reported its own failure. */
#define B_STEP(expr) do {                                                 \
    if ((expr) != 0) {                                                    \
        mn_net_free(net);                                                 \
        return 1;                                                         \
    }                                                                     \
} while (0)

/** The liveness bound of the never-healed scenario (S5). */
#define B_NEVER_ROUNDS 300

/* ── stopping conditions ─────────────────────────────────────────────── */

typedef struct {
    size_t  node;
    int64_t height;
} b_node_height_t;

/** byzantine_test.go:421 — `<-blocksSubs[ind2].Out()`: that node has
 *  committed the height. */
static bool b_pred_node_committed(const mn_net_t *net, const void *ctx)
{
    const b_node_height_t *a = (const b_node_height_t *)ctx;
    cmt_block_id_t         bid;

    if (a->node >= net->n) {
        return false;
    }
    return mn_committed_block_id(&net->nodes[a->node], a->height, &bid);
}

/** byzantine_test.go:427-442 — every honest node has committed the
 *  height (stronger than the reference's loop, S3). */
static bool b_pred_all_honest_committed(const mn_net_t *net, const void *ctx)
{
    const int64_t *height = (const int64_t *)ctx;

    return mn_all_honest_committed(net, *height);
}

/* ══ the port ═════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/byzantine_test.go:300-458 —
 * `TestByzantineConflictingProposalsWithPartition`. The line-by-line
 * closure is in the file header.
 */
static int b_conflicting_proposals_with_partition(void)
{
    mn_net_t        *net = mn_net_new(4u, 0);                /* :301, :335 */
    b_node_height_t  wait_b;
    int64_t          height1 = 1;
    cmt_block_id_t   committed[MN_MAX_NODES];
    size_t           i;

    if (net == NULL) {
        fprintf(stderr, "byzantine_partition: setup failed\n");
        return 1;
    }

    /* :407 assumes node 0 is the proposer at (1, 0) — "byz proposer
     * sends one block to peers[0]...". Made explicit: the index
     * `tc_expected_proposer` DERIVES from validator_set.go is 0, and the
     * port's own set must elect it. */
    B_CHECK(tc_expected_proposer(net->nodes[0].tc, 1, 0) == 0u,
            "byzantine_partition: the derived (1,0) proposer is not node 0");
    B_STEP(tc_check_proposer(net->nodes[0].tc, 1, 0));

    /* :383-393 — "the network starts partitioned with globally active
     * adversary": node 0 is connected to everyone, nobody else to anyone. */
    mn_connect(net, 0u, 1u);
    mn_connect(net, 0u, 2u);
    mn_connect(net, 0u, 3u);

    /* :395-405 — start the honest state machines, then the byzantine one.
     * Node 0 proposes during its start: two blocks, two proposals, and
     * every peer gets one pair (:459-507). */
    B_STEP(mn_net_start(net));
    B_CHECK(net->nodes[0].byz_hash_set,
            "byzantine_partition: the byzantine proposer never ran");
    B_CHECK(memcmp(net->nodes[0].byz_hash[0], net->nodes[0].byz_hash[1],
                   (size_t)CMT_TMHASH_SIZE) != 0,
            "byzantine_partition: the two byzantine blocks are the same");

    /* :410-418 — peers[0] is partition A on its own; peers[1] and
     * peers[2] are connected into partition B. In this driver's peer
     * order (M12) A = {1}, B = {2, 3}. */
    mn_connect(net, 2u, 3u);

    /* :420-421 — "wait for someone in the big partition (B) to make a
     * block". ind2 is node 3 here. */
    wait_b.node   = 3u;
    wait_b.height = 1;
    B_STEP(mn_run_until(net, b_pred_node_committed, &wait_b,
                        (int64_t)MN_BUDGET_ROUNDS,
                        "partition B (node 3) commits height 1"));

    /* :295-298 — "B sees a commit, A doesn't." Node 1 has proposal1,
     * block1, its own prevote and the byzantine prevote and precommit for
     * block1: 2 of 4 prevotes and 1 of 4 precommits, below every
     * threshold, and no timeout ever fires for it (M5). */
    B_CHECK(net->nodes[1].tc->apply_calls == 0,
            "byzantine_partition: partition A committed while partitioned");
    B_CHECK(mn_cs(&net->nodes[1])->rs.height == 1,
            "byzantine_partition: partition A left height 1 while partitioned");

    /* :423-425 — "A block has been committed. Healing partition". */
    mn_connect(net, 1u, 2u);
    mn_connect(net, 1u, 3u);

    /* :427-453 — "wait till everyone makes the first new block", with the
     * ten-second deadline as a round budget (M14). Every honest node, not
     * only css[1] and css[2] (S3). */
    B_STEP(mn_run_until(net, b_pred_all_honest_committed, &height1,
                        (int64_t)MN_BUDGET_ROUNDS,
                        "every honest node commits height 1"));

    /* ── what the reference implies, asserted ─────────────────────── */

    /* Every honest node committed height 1, and the SAME block. */
    for (i = 1u; i < net->n; i++) {
        B_CHECK(mn_committed_block_id(&net->nodes[i], 1, &committed[i]),
                "byzantine_partition: an honest node has no height-1 commit");
        B_CHECK(committed[i].hash_len == (size_t)CMT_TMHASH_SIZE,
                "byzantine_partition: a committed BlockID has no hash");
    }
    for (i = 2u; i < net->n; i++) {
        B_CHECK(memcmp(committed[i].hash, committed[1].hash,
                       (size_t)CMT_TMHASH_SIZE) == 0,
                "byzantine_partition: FORK — two honest nodes committed "
                "different blocks at height 1");
    }
    /* And it is one of the two blocks the byzantine node proposed. */
    B_CHECK(memcmp(committed[1].hash, net->nodes[0].byz_hash[0],
                   (size_t)CMT_TMHASH_SIZE) == 0 ||
            memcmp(committed[1].hash, net->nodes[0].byz_hash[1],
                   (size_t)CMT_TMHASH_SIZE) == 0,
            "byzantine_partition: the committed block is neither byzantine "
            "block");
    /* And, DERIVED rather than read off the reference: it is block2. The
     * byzantine node sends block1 to the first half of its peers
     * (:500-503), which with three peers is ONE peer (3/2 = 1), so
     * block1's precommits are at most node 1's and node 0's — 2 of 4
     * equal powers, below +2/3 (vote_set.go:306 `TotalVotingPower*2/3+1`)
     * — while block2 reaches node 0, node 2 and node 3. Only block2 can
     * ever be committed by anyone. */
    B_CHECK(memcmp(committed[1].hash, net->nodes[0].byz_hash[1],
                   (size_t)CMT_TMHASH_SIZE) == 0,
            "byzantine_partition: the committed block is block1, which "
            "cannot have +2/3");

    /* Router sanity: no honest node ever failed to decode a block it
     * assembled (driver M7), and the byzantine node never faulted (S6 —
     * a fault would have ended the run above). */
    for (i = 0u; i < net->n; i++) {
        B_CHECK(net->nodes[i].tc->decode_misses == 0,
                "byzantine_partition: a node failed to decode an assembled "
                "block");
    }

    /* The evidence pool. Nodes 2 and 3 never see a conflicting pair: they
     * receive the byzantine votes for block2 directly and never a
     * block1 vote (node 1 gossips only to same-height peers, and it is a
     * height behind them until it commits — reactor.go:724, :733).
     * Node 0's conflicts are its OWN and are not reported (state.go:
     * 2082-2090). */
    B_CHECK(net->nodes[2].tc->conflict_calls == 0 &&
            net->nodes[3].tc->conflict_calls == 0,
            "byzantine_partition: partition B reported a conflict");
    B_CHECK(net->nodes[0].tc->conflict_calls == 0,
            "byzantine_partition: the byzantine node reported its own "
            "conflict");
    printf("     byzantine_partition: %lld rounds of %d\n",
           (long long)net->rounds, MN_BUDGET_ROUNDS);

    /* LAST, because it is the check that found a defect (S1): node 1
     * receives the byzantine precommit for block2 after node 2's
     * VoteSetMaj23 made its precommit set track block2, so `VoteSet.AddVote`
     * returns `(true, ErrVoteConflictingVotes)` (vote_set.go:285-288,
     * :326) and the reference's `tryAddVote` hands the pair to the
     * evidence pool (state.go:2362 → :2070-2072 → :2094): exactly ONE
     * call, with the byzantine node's block1 and block2 precommits. The
     * port dropped that report on its first run; it does not any more. */
    B_CHECK(net->nodes[1].tc->conflict_calls == 1,
            "byzantine_partition: partition A did not report the byzantine "
            "precommit pair to the evidence pool (see S1)");
    B_CHECK(net->nodes[1].tc->conflict_a->validator_index == 0 &&
            net->nodes[1].tc->conflict_b->validator_index == 0 &&
            net->nodes[1].tc->conflict_a->type ==
                (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT &&
            net->nodes[1].tc->conflict_b->type ==
                (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
            "byzantine_partition: the reported pair is not the byzantine "
            "node's two precommits");

    mn_net_free(net);
    return 0;
}

/* ══ C-ONLY: the driver's own sanity check ════════════════════════════ */

/**
 * C-ONLY, NOT A PORT. Four honest nodes, everyone connected, mock tickers
 * everywhere: they must commit ONE block at height 1, the one node 0
 * proposed. A router defect shows up here as a plain failure instead of
 * as a mysterious byzantine result.
 */
static int b_c_only_four_honest_all_connected(void)
{
    mn_net_t      *net = mn_net_new(4u, -1);
    int64_t        height1 = 1;
    cmt_block_id_t committed[MN_MAX_NODES];
    size_t         i;
    size_t         j;

    if (net == NULL) {
        fprintf(stderr, "four_honest: setup failed\n");
        return 1;
    }
    B_STEP(tc_check_proposer(net->nodes[0].tc, 1, 0));
    for (i = 0u; i < net->n; i++) {
        for (j = i + 1u; j < net->n; j++) {
            mn_connect(net, i, j);
        }
    }
    B_STEP(mn_net_start(net));
    /* Node 0 proposed exactly one block during its start (there is no
     * byzantine override: `cmt_cs_default_decide_proposal`). */
    B_CHECK(net->nodes[0].tc->create_calls == 1 && net->nodes[0].tc->recs_n >= 1u,
            "four_honest: node 0 did not propose exactly one block");

    B_STEP(mn_run_until(net, b_pred_all_honest_committed, &height1,
                        (int64_t)MN_BUDGET_ROUNDS,
                        "all four nodes commit height 1"));

    for (i = 0u; i < net->n; i++) {
        B_CHECK(mn_committed_block_id(&net->nodes[i], 1, &committed[i]),
                "four_honest: a node has no height-1 commit");
        B_CHECK(committed[i].hash_len == (size_t)CMT_TMHASH_SIZE,
                "four_honest: a committed BlockID has no hash");
    }
    for (i = 1u; i < net->n; i++) {
        B_CHECK(memcmp(committed[i].hash, committed[0].hash,
                       (size_t)CMT_TMHASH_SIZE) == 0,
                "four_honest: FORK — two nodes committed different blocks");
    }
    /* The block is node 0's first registry record — the one its
     * `create_proposal_block` made at (1, 0). */
    B_CHECK(memcmp(committed[0].hash, net->nodes[0].tc->recs[0].hash,
                   (size_t)CMT_TMHASH_SIZE) == 0,
            "four_honest: the committed block is not node 0's proposal");
    for (i = 0u; i < net->n; i++) {
        B_CHECK(net->nodes[i].tc->decode_misses == 0,
                "four_honest: a node failed to decode an assembled block");
        B_CHECK(net->nodes[i].tc->conflict_calls == 0,
                "four_honest: a conflict was reported with no byzantine node");
    }
    printf("     four_honest: %lld rounds of %d\n",
           (long long)net->rounds, MN_BUDGET_ROUNDS);
    mn_net_free(net);
    return 0;
}

/* ══ C-ONLY: the partition never heals ════════════════════════════════ */

/**
 * C-ONLY, NOT A PORT. The same four nodes, the same byzantine proposer,
 * the same initial partition — and it is NEVER healed. This is the
 * SAFETY half the reference's test walks past at :423: the minority side
 * must commit NOTHING, and nobody must ever commit block1.
 *
 * ⚠ THE DISPATCH ASKED FOR SOMETHING ELSE, AND IT CANNOT BE TRUE. It
 * described this scenario as "the two-node partition B has 2 of 4 = 50 %
 * of the power, which is below +2/3, so it must NOT commit, and the test
 * asserts that after the step budget no honest node has committed
 * anything". That counts only the honest votes. The byzantine node is
 * connected to B and sends B a prevote AND a precommit for block2
 * (byzantine_test.go:543-553), so B has 3 of 4 — which is exactly why the
 * reference's own test waits for B to commit at :420-421 ("wait for
 * someone in the big partition (B) to make a block") BEFORE it heals.
 * An assertion that no honest node commits would be falsified by the
 * reference's own scenario. What IS true, and asserted: B commits block2;
 * A (node 1: itself plus the byzantine node, 2 of 4) commits nothing and
 * never leaves (1, 0, PREVOTE); and no node's store ever holds block1.
 * Raised in the wave report as a QUESTION.
 *
 * Node 1's step is DERIVED: it prevotes block1 on the complete proposal
 * (state.go:2056-2058), its prevotes are then {itself, node 0} = 2 of 4,
 * which is neither a polka nor +2/3 of anything (:2309-2327 fall through),
 * its precommits are {node 0} = 1 of 4 (:2339-2356 fall through), and the
 * mock ticker delivers it no timeout (M5). PREVOTE is where it stays.
 */
static int b_c_only_partition_never_healed(void)
{
    mn_net_t        *net = mn_net_new(4u, 0);
    b_node_height_t  wait_b;
    cmt_block_id_t   bid2;
    cmt_block_id_t   bid3;
    cmt_block_id_t   bid;
    size_t           i;

    if (net == NULL) {
        fprintf(stderr, "never_healed: setup failed\n");
        return 1;
    }
    B_STEP(tc_check_proposer(net->nodes[0].tc, 1, 0));
    mn_connect(net, 0u, 1u);
    mn_connect(net, 0u, 2u);
    mn_connect(net, 0u, 3u);
    B_STEP(mn_net_start(net));
    B_CHECK(net->nodes[0].byz_hash_set,
            "never_healed: the byzantine proposer never ran");
    mn_connect(net, 2u, 3u);

    /* As the reference: B commits (:420-421). */
    wait_b.node   = 3u;
    wait_b.height = 1;
    B_STEP(mn_run_until(net, b_pred_node_committed, &wait_b,
                        (int64_t)MN_BUDGET_ROUNDS,
                        "partition B (node 3) commits height 1"));
    /* And then NOTHING is healed; the network runs on (S5). */
    B_STEP(mn_run_rounds(net, (int64_t)B_NEVER_ROUNDS, "never healed"));

    /* B: both nodes committed block2. */
    B_CHECK(mn_committed_block_id(&net->nodes[2], 1, &bid2) &&
            mn_committed_block_id(&net->nodes[3], 1, &bid3),
            "never_healed: partition B did not commit height 1");
    B_CHECK(bid2.hash_len == (size_t)CMT_TMHASH_SIZE &&
            memcmp(bid2.hash, bid3.hash, (size_t)CMT_TMHASH_SIZE) == 0,
            "never_healed: FORK inside partition B");
    B_CHECK(memcmp(bid2.hash, net->nodes[0].byz_hash[1],
                   (size_t)CMT_TMHASH_SIZE) == 0,
            "never_healed: partition B committed something other than block2");

    /* A: nothing, ever, and parked exactly where the derivation says. */
    B_CHECK(net->nodes[1].tc->apply_calls == 0,
            "never_healed: partition A committed with 2 of 4");
    B_CHECK(!mn_committed_block_id(&net->nodes[1], 1, &bid),
            "never_healed: partition A's store holds a height-1 commit");
    B_CHECK(mn_cs(&net->nodes[1])->rs.height == 1 &&
            mn_cs(&net->nodes[1])->rs.round == 0,
            "never_healed: partition A moved past (1, 0)");
    B_CHECK(mn_cs(&net->nodes[1])->rs.step == CMT_ROUND_STEP_PREVOTE,
            "never_healed: partition A is not parked at PREVOTE");
    B_CHECK(mn_count_votes(cmt_hvs_prevotes(mn_cs(&net->nodes[1])->rs.votes, 0))
                == 2 &&
            mn_count_votes(cmt_hvs_precommits(mn_cs(&net->nodes[1])->rs.votes, 0))
                == 1,
            "never_healed: partition A's vote sets are not {2 prevotes, "
            "1 precommit}");

    /* Nobody, the byzantine node included, ever committed block1. */
    for (i = 0u; i < net->n; i++) {
        if (mn_committed_block_id(&net->nodes[i], 1, &bid)) {
            B_CHECK(memcmp(bid.hash, net->nodes[0].byz_hash[0],
                           (size_t)CMT_TMHASH_SIZE) != 0,
                    "never_healed: a node committed block1");
        }
        B_CHECK(net->nodes[i].tc->decode_misses == 0,
                "never_healed: a node failed to decode an assembled block");
    }
    printf("     never_healed: %lld rounds (%d after B committed)\n",
           (long long)net->rounds, B_NEVER_ROUNDS);
    mn_net_free(net);
    return 0;
}

/* ══ the runner ═══════════════════════════════════════════════════════ */

typedef struct {
    const char *name;
    int       (*fn)(void);
} b_case_t;

int main(void)
{
    static const b_case_t cases[] = {
        { "byzantine_conflicting_proposals_with_partition",
          b_conflicting_proposals_with_partition },
        { "c_only_four_honest_all_connected",
          b_c_only_four_honest_all_connected },
        { "c_only_partition_never_healed",
          b_c_only_partition_never_healed }
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
    printf("test_cmt_byzantine: %zu/%zu scenarios, %d checks\n",
           n - failed, n, g_tc_checks);
    return (failed == 0u) ? 0 : 1;
}
