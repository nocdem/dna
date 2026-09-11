/**
 * Nodus — cometbft @709fd12b C port, wave R2-T: the SCENARIO SUITE for
 * `shared/dnac/cmt_cs.c`, ported from `consensus/state_test.go`,
 * `consensus/byzantine_test.go` and `consensus/mempool_test.go`.
 *
 * Every scenario names the Go `func Test…` it comes from and its line.
 * The fixture — the application, the signer, the block store, the WAL,
 * the clock and the timer — is `test_cmt_common.h`, which is the C
 * stand-in for `consensus/common_test.go` and carries its own four
 * header items. READ THAT FILE'S "HOW IT CAN LIE" TOO: ten of the
 * sixteen ways this suite can be wrong are properties of the fixture,
 * not of the scenarios.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the ported state machine walks WHOLE HEIGHTS the way cometbft's
 * does, driven only through its public surface. Wave R2-C's host-free
 * unit test reached none of this and said so; each item below is one of
 * the holes it named:
 *   · THE NODE IS A VALIDATOR. It signs, it proposes, it prevotes and it
 *     precommits with real ML-DSA-87 keys, and every vote it makes is
 *     verified by the vote set that accepts it. If this file failed,
 *     `signAddVote` (state.go:2439-2474), `signVote` (:2366-2414) or
 *     `cmt_sign_and_check_vote` would be wrong.
 *   · BLOCKS ARE PROPOSED, SPLIT, GOSSIPED, RE-ASSEMBLED AND COMMITTED.
 *     `createProposalBlock` → `MakePartSet` → the internal queue →
 *     `addProposalBlockPart` → the payload buffer → `decode_block` →
 *     `finalizeCommit` → `updateToState`, and the chain is at the next
 *     height with the previous height's precommits as its LastCommit.
 *   · THE SLOT ALLOCATOR IS REACHED. Locking takes a block slot, a new
 *     round takes another, a relock aliases two names onto one slot and
 *     the round after that frees it. If cmt_cs.c's "a slot may be
 *     rewritten only while NO name points at it" were wrong, the relock
 *     and round-skip scenarios would read a block that had been
 *     overwritten and their hash assertions would fail.
 *   · LOCKING AND UNLOCKING FOLLOW THE POLKA. A node locks on a block it
 *     prevoted with a polka (:1522-1539), relocks onto a NEW block when
 *     the next round polkas for it (:1509-1518 / :1522), unlocks on a nil
 *     polka (:1488-1503), and — the safety rule — a polka from a round
 *     it has already passed does not move its lock (:2261-2277).
 *   · ROUND SKIPPING AND COMMITTING FROM AN EARLIER ROUND. +2/3 of
 *     anything at a higher round moves the node there (:2311-2313); +2/3
 *     precommits for a block at a LOWER round still commits it
 *     (:2339-2349), even when the node does not have the block yet.
 *   · THE TICKER IS IN THE LOOP. Every timeout in this suite is armed by
 *     the state machine, delivered through `cmt_cs_on_timer_expired`, and
 *     acted on by `handleTimeout` against the round state as it was
 *     before the poll. Wave R2-C built its `cmt_timeout_info_t` by hand
 *     and never touched the ticker.
 *   · THE VOTE-EXTENSION PATH RUNS. With extensions enabled at height 1 —
 *     which is what the reference's own test parameters do
 *     (internal/test/params.go:9-13) — every non-nil precommit this node
 *     makes goes through `ExtendVote` and every peer's goes through
 *     `VerifyVoteExtension`, and a vote carrying an extension on a chain
 *     that has them disabled is refused.
 *   · THE PROPOSER ROTATES AS cometbft'S ARITHMETIC SAYS. The expected
 *     index is DERIVED from types/validator_set.go and written out in
 *     `tc_expected_proposer`, never asked of the code under test.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION`, which the nodus build defines
 *   for every cmt_* target (shared/dnac/cmt_state.h:150 refuses to
 *   compile without it). NOTHING ELSE — a DEFAULT BUILD is enough, and in
 *   particular `QGP_FAULT_INJECT` is NOT set, so all six fail points
 *   (cmt_cs.h:159-168) compile to `((void)0)` and NONE of them is
 *   exercised. There is no scenario here that depends on one; if there
 *   were, it would have to be skipped and reported as skipped.
 * ENVIRONMENT: none. No variable is read or written — in particular
 *   `FAIL_TEST_INDEX` is never set.
 * No network, no files, no database, no wall clock, no randomness beyond
 * what ML-DSA-87 signing does internally.
 *
 * ⚠ MEMORY AND TIME. About 6 MB of heap while one scenario runs, freed
 * between scenarios. The cost is ML-DSA-87: roughly 300 signatures and
 * as many verifications across the suite.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no environment
 * variables, no shared state between scenarios: each builds its own
 * fixture and tears it down, including on the failure path.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 * The fixture's ten ways are in test_cmt_common.h. These six are the
 * scenarios' own:
 *  11. SIX SCENARIOS ARE PARTIAL PORTS AND SAY SO IN THEIR OWN COMMENT.
 *      `s_lock_no_pol` stops after round 1 of the reference's four;
 *      `s_extend_vote_called_when_enabled` does not assert the CONTENT of
 *      the ExtendVote request (the port has no request object to
 *      inspect); `s_byzantine_prevote_equivocation` is one node, not
 *      four behind a partition; the three mempool scenarios drive
 *      `txs_available` by hand instead of through a mempool. A partial
 *      port proves the part it ports and NOTHING about the rest. Two
 *      more — `s_vote_extension_enable_height` and
 *      `s_mempool_progress_in_higher_round` — port every case of their
 *      Go test but RE-EXPRESS one assertion each, because the reference
 *      makes it about an event; both give the reason at the site.
 *  12. NO SCENARIO ASSERTS AN EVENT, BECAUSE THERE ARE NO EVENTS. Where
 *      the reference waits for `EventDataCompleteProposal`,
 *      `EventDataNewRound`, `EventValidBlock`, `EventUnlock` or
 *      `EventRelock`, this suite asserts the ROUND STATE that the event
 *      would have announced. Those five publications are among the rows
 *      cmt_cs.h:72-74 deliberately does not port, so a regression that
 *      broke only the events would be invisible here — and there is
 *      nothing to break, because they do not exist.
 *  13. TIMEOUT DURATIONS ARE CHECKED, TIMEOUT ORDERING IN REAL TIME IS
 *      NOT. `tc_fire_timeout` fires whatever the state machine last
 *      armed, immediately. A defect where two timeouts are armed in the
 *      wrong ORDER, or where one is armed with a duration that is right
 *      but scheduled from the wrong instant, would pass here.
 *  14. A SCENARIO THAT NEVER REACHES ITS SUBJECT STILL PASSES ITS EARLY
 *      ASSERTIONS. Every scenario therefore asserts the transition it is
 *      about (a lock, an unlock, a commit, a round skip) and not merely
 *      that nothing crashed. The one exception is
 *      `s_doesnt_crash_on_invalid_vote`, whose whole subject IS that
 *      nothing happened; it is stated as such at the site.
 *  15. `tc_ensure_new_round` IS WEAKER THAN THE REFERENCE'S
 *      `ensureNewRound`. The Go helper waits for the NewRound EVENT,
 *      which only `enterNewRound` publishes; this one compares
 *      `rs.height` and `rs.round`, and both are already correct at
 *      `RoundStepNewHeight` — the step finalizeCommit leaves behind
 *      before its NEW_HEIGHT timeout has been delivered. Every scenario
 *      that asserts a NEW HEIGHT therefore fires that timeout first, so
 *      the round really has been entered — except `s_full_round1`, where
 *      one validator would commit the whole of height 2 inside the same
 *      drain; there, and only there, the assertion proves the height
 *      moved and NOT that round 0 was entered. It is marked at the site.
 *  16. THE BLOCK-TIME RULES ARE EXERCISED WITH ONE SIGNER, NOT FOUR.
 *      `tc_validate_block` performs state/validation.go:120-140 in full
 *      — `block.Time > state.LastBlockTime` and `block.Time ==
 *      MedianTime(LastCommit, LastValidators)` — but only a scenario
 *      that PROPOSES at height ≥ 2 can reach the non-initial branch, and
 *      the only ones that do are the three single-validator mempool
 *      scenarios. There the median is this node's own vote, which
 *      `voteTime` (state.go:2417-2429) clamps to `blockTime + 1 ms`, so
 *      it is strictly increasing by construction. With four validators
 *      the stubs stamp the frozen clock and this node stamps one
 *      millisecond later, so a weighted median over them would NOT be
 *      strictly increasing — no ported scenario reaches that, and a
 *      defect in the median arithmetic that only shows up with several
 *      differing timestamps would pass here.
 *  17. A VOTE EXTENSION IS NEVER CHECKED TO SURVIVE A HEIGHT BOUNDARY.
 *      `tc_create_proposal_block` takes the extended commit the state
 *      machine hands it and passes it through
 *      `cmt_extended_commit_to_commit`, which converts an ExtendedCommit
 *      into a Commit and DROPS the extensions. No scenario inspects the
 *      extension bytes inside that argument. The reference has a test for
 *      exactly this — `TestPrepareProposalReceivesVoteExtensions`
 *      (state_test.go:1654) — and it is among the unported ones below.
 *      So a regression that lost extensions between the commit of one
 *      height and the proposal of the next is invisible here.
 *  18. `TC_PAYLOAD_CAP` IS DELIBERATELY UNDER-PROVISIONED
 *      (test_cmt_common.h's slot storage), so the MaxBytes refusal INSIDE
 *      the part-assembly path (cmt_cs.c's payload-buffer overrun REJECT)
 *      is never the check that fires; the earlier ByteSize refusal is.
 *
 * ── THE FIFTEEN TESTS THAT WERE NOT PORTED BY THIS WAVE ────────────────
 * Written here and not only in the wave's report, because a prerequisite
 * that lives in the author's head is a trap for whoever picks this up.
 * ONE of the fifteen has since been done: the byzantine partition test
 * below was ported by wave R2-BYZ as `test_cmt_byzantine.c` on the
 * multi-node driver `test_cmt_multinode.h`, exactly the shape described
 * under it. Its entry is kept as written, because the reasoning is what
 * made that driver's design; fourteen remain (four BLOCKED, ten DRIVABLE,
 * plus rounds 2-3 of one ported test).
 *
 * BLOCKED — something the port or a single-State fixture does not have:
 *   · `TestStateOutputsBlockPartsStats` (state_test.go:2465) and
 *     `TestStateOutputVoteStats` (:2507) assert on `cs.statsMsgQueue`,
 *     which cmt_cs.c:1511 and :1533 say is deliberately not ported.
 *   · `TestByzantineConflictingProposalsWithPartition`
 *     (byzantine_test.go:300) — DONE SINCE, see above; the text below is
 *     this wave's, left as the record of why the driver looks as it does.
 *     NOT impossible — the honest word is
 *     OUT OF THIS WAVE'S SHAPE. It needs FOUR independent state machines,
 *     a way to hand a message one of them produced to the others, and a
 *     connectivity matrix that starts partitioned and is healed halfway
 *     through. None of that needs a network, a thread or a clock: the
 *     reference's switches become an array of queues, its event
 *     subscriptions become the committed-block record this fixture
 *     already keeps, and its ten-second wall-clock deadline becomes a
 *     step budget, which is stricter. What it costs is a multi-node
 *     driver on top of `tc_t`, which this fixture is single-node by
 *     construction (one `cmt_cs_t`, three signer stubs that run no state
 *     machine).
 *     ⚠ IT IS ALSO THE ONLY TEST IN THIS FILE'S SOURCES THAT ASKS THE
 *     QUESTION THE WHOLE PROJECT IS ABOUT: given a byzantine proposer
 *     that sends CONFLICTING blocks to two halves of a partitioned
 *     network, do the honest nodes still commit ONE block? Every other
 *     scenario here proves ONE node reacts correctly to inputs handed to
 *     it. This one proves N nodes do not fork. Whether that driver
 *     belongs here or with the reactor in R3 — where the real message
 *     routing is written — is an operator decision, recorded in
 *     tasks/orchestration.md.
 *   · `TestMempoolTxConcurrentWithCommit` (mempool_test.go:118) and
 *     `TestMempoolRmBadTx` (:143) drive a real mempool from goroutines
 *     with a wall-clock wait.
 *
 * DRIVABLE WITH THIS FIXTURE, simply not done in this wave — budget, not
 * impossibility, and named so nobody has to re-derive it:
 *   · `TestPrepareProposalReceivesVoteExtensions` (state_test.go:1654).
 *     The port has no ABCI request object, but the request's fields ARE
 *     the callback's parameters: `create_proposal_block` already receives
 *     `last_ext_commit` (cmt_cs.h's host table) and
 *     `cmt_pb_extended_commit_sig_t` carries `extension` and
 *     `extension_signature`. What is missing is per-stub DISTINCT
 *     extension bytes (today `tc_ext_bytes` is one shared array) and a
 *     capture of that argument. See item 17 — this gap and that one are
 *     the same gap.
 *   · `TestStateLockPOLUnlockOnUnknownBlock` (:858),
 *     `TestStateLockPOLSafety1` (:990), `TestStateLockPOLSafety2` (:1116),
 *     `TestProposeValidBlock` (:1217),
 *     `TestSetValidBlockOnDelayedProposal` (:1372),
 *     `TestVerifyVoteExtensionNotCalledOnAbsentPrecommit` (:1582),
 *     `TestStartNextHeightCorrectlyAfterTimeout` (:2190),
 *     `TestResetTimeoutPrecommitUponNewHeight` (:2251),
 *     `TestStateHalt1` (:2397) — the last of which is NOT blocked by
 *     lifecycle: `cmt_cs_start` and `cmt_cs_stop` both exist.
 *   · Rounds 2 and 3 of `TestStateLockNoPOL` (:558-654).
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/state_test.go     2620 lines
 *     9b8080ecfc32198f2bfcbd7ebb3c7b9be3c44c7cf5f053b1eb365b6a24f652c3
 *   consensus/byzantine_test.go  596 lines
 *     6d4bb54ca1997f882a24b7d507d5d94d560966ec977090007a00704f79e8e00f
 *   consensus/mempool_test.go    211 lines
 *     44c21284460aa7102527ee55492fa8210c5348d5d917463f8871bbab17623a13
 *   consensus/common_test.go     991 lines
 *     3e3940e51975f030a0190bc2b5217d93ee768eef30097d8b14b379b006023a38
 *   consensus/state.go          2653 lines
 *     f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *   config/config.go            1283 lines
 *     f0c2f601d49e1a56b36e8d557387e96ee53ecc3616ecb79749b0f71c0f218c21
 * Opened by this wave and reported in the wave report. THREE of the five
 * turned out to be pinned already, in tasks/comet-port-map.md rather than
 * in a numbered revision of the pin record — state/validation.go (map
 * line 40), types/priv_validator.go (line 911) and types/validator.go
 * (line 27), all three with matching hashes, rechecked by the
 * ORCHESTRATOR at O6. The other two were genuinely absent and are pin
 * revision 9: internal/test/params.go and internal/test/block.go. Their
 * line counts and hashes are in test_cmt_common.h.
 *
 * ── CONFIG: THE REFERENCE DEFAULTS, NOT THE CHAIN'S ────────────────────
 * Every scenario runs at `cmt_config_default` — config.go:1017-1034's
 * `DefaultConsensusConfig` — so timeoutPropose is 3000 ms, its delta
 * 500 ms, timeoutPrevote and timeoutPrecommit 1000 ms with 500 ms deltas,
 * timeoutCommit 1000 ms, CreateEmptyBlocks true and its interval 0. The
 * chain's own block interval and 60 s idle interval (the APPROVED record
 * atlas-dec-d5ddcba654eb48d861c03a0ecd170718 rev 2) are the HOST's at
 * R3 and are deliberately NOT used here: a test that hard-coded either
 * would be testing the configuration rather than the state machine.
 * Consensus params are `cmt_default_consensus_params` (params.go:86-94)
 * with `ABCI.VoteExtensionsEnableHeight = 1` where the reference's
 * `randState` would use `internal/test.ConsensusParams()`
 * (internal/test/params.go:9-13), which sets exactly that.
 *
 * @file test_cmt_cs.c
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "test_cmt_common.h"

/* ══ scenario plumbing ════════════════════════════════════════════════ */

/** Build a fixture on the heap. `tc_t` carries four 2592-byte public keys
 *  and is far too large for a stack frame. */
static tc_t *tc_alloc(size_t nvals, int64_t ve_height, int64_t block_max)
{
    tc_t *tc = (tc_t *)calloc(1u, sizeof(tc_t));

    if (tc == NULL) {
        return NULL;
    }
    if (tc_setup(tc, nvals, ve_height, block_max) != 0) {
        free(tc);
        return NULL;
    }
    return tc;
}

static void tc_release(tc_t *tc)
{
    if (tc != NULL) {
        tc_teardown(tc);
        free(tc);
    }
}

/** As TC_CHECK, but frees the fixture first. Every scenario names its
 *  fixture `tc`, which is what makes this work. */
#define S_CHECK(cond, msg) do {                                           \
    if (!(cond)) {                                                        \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n",                    \
                __FILE__, __LINE__, (msg));                               \
        tc_release(tc);                                                   \
        return 1;                                                         \
    }                                                                     \
    g_tc_checks++;                                                        \
} while (0)

/** Run a helper that already reported its own failure. */
#define S_STEP(expr) do {                                                 \
    if ((expr) != 0) {                                                    \
        tc_release(tc);                                                   \
        return 1;                                                         \
    }                                                                     \
} while (0)

#define S_PREVOTE   ((int32_t)CMT_PB_MSG_TYPE_PREVOTE)
#define S_PRECOMMIT ((int32_t)CMT_PB_MSG_TYPE_PRECOMMIT)

/* ══════════════════════════════════════════════════════════════════════
 * ProposeSuite
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state_test.go:65-102 —
 * `TestStateProposerSelection0`.
 *
 * Round-robin ordering at round 0: we are the proposer at height 1, and
 * after the height is committed the NEXT validator is the proposer at
 * height 2. The second half is what makes this a test of
 * `updateState`'s validator rotation and not merely of
 * `NewValidatorSet`.
 */
static int s_proposer_selection0(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;

    S_CHECK(tc != NULL, "proposer_selection0: setup");

    S_STEP(tc_start_test_round(tc, 1, 0));               /* :72          */
    S_STEP(tc_ensure_new_round(tc, 1, 0));               /* :75          */
    S_STEP(tc_check_proposer(tc, 1, 0));                 /* :78-84       */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));            /* :87          */

    S_STEP(tc_proposal_block_hash(tc, hash));
    S_STEP(tc_proposal_parts_header(tc, &psh));
    /* :90 — the other three precommit the proposal, which is +2/3 and
     * commits the height even though we have cast no precommit. */
    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, hash, sizeof(hash),
                                   &psh, true, 1u, 4u));
    S_CHECK(tc->apply_calls == 1, "proposer_selection0: block not applied");
    S_STEP(tc_ensure_new_block_header(tc, 1, hash, sizeof(hash)));
    S_CHECK(tc->cs->rs.height == 2,
            "proposer_selection0: did not reach height 2");
    S_CHECK(tc->cs->rs.step == CMT_ROUND_STEP_NEW_HEIGHT,
            "proposer_selection0: should be waiting out timeoutCommit");

    /* :93 — the reference waits for the NewRound EVENT of height 2, which
     * only fires once the commit timeout has elapsed; here that timeout
     * is fired by hand. */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 2, 0));
    S_STEP(tc_check_proposer(tc, 2, 0));                 /* :95-101      */
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:105-138 —
 * `TestStateProposerSelection2`.
 *
 * The same rotation walked ROUND by round rather than height by height,
 * starting at round 2. Every round the four validators vote nil
 * precommits, the precommit timeout takes the node to the next round, and
 * the proposer must be the next validator round-robin.
 */
static int s_proposer_selection2(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    cmt_part_set_header_t zero;
    int32_t               round = 2;
    int                   i;

    S_CHECK(tc != NULL, "proposer_selection2: setup");
    tc_zero_psh(&zero);

    /* :111-112 — the stubs jump in at round 2 as well. */
    tc_increment_round(tc, 1u, 4u);
    tc_increment_round(tc, 1u, 4u);

    S_STEP(tc_start_test_round(tc, 1, round));           /* :115         */
    S_STEP(tc_ensure_new_round(tc, 1, round));           /* :117         */

    for (i = 0; i < 4; i++) {                            /* :120-137     */
        S_STEP(tc_check_proposer(tc, 1, round));         /* :121-131     */
        /* :134 — everyone votes nil, which is +2/3 of anything and takes
         * us into precommit-wait. */
        S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                       true, 1u, 4u));
        S_STEP(tc_ensure_new_timeout(tc, 1, round,
                                     cmt_config_precommit(&tc->config, round),
                                     CMT_ROUND_STEP_PRECOMMIT_WAIT));
        S_STEP(tc_fire_timeout(tc));                     /* :135         */
        round++;
        S_STEP(tc_ensure_new_round(tc, 1, round));
        tc_increment_round(tc, 1u, 4u);                  /* :136         */
    }
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:141-157 —
 * `TestStateEnterProposeNoPrivValidator`.
 *
 * A node that is not a validator schedules the propose timeout and makes
 * no proposal — state.go:1167 runs, :1170 returns.
 */
static int s_enter_propose_no_priv_validator(void)
{
    tc_t *tc = tc_alloc(1u, 1, 0);

    S_CHECK(tc != NULL, "enter_propose_no_priv: setup");
    /* :143 — `cs.SetPrivValidator(nil)`. */
    S_CHECK(cmt_cs_set_priv_validator(tc->cs, false) == CMT_OK,
            "enter_propose_no_priv: clearing the priv validator");
    tc->has_priv_validator = false;

    S_STEP(tc_start_test_round(tc, 1, 0));               /* :149         */
    /* :152 — the reference waits for the timeout to FIRE; this asserts
     * the timer the state machine armed, which is the same fact one step
     * earlier. */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_propose(&tc->config, 0),
                                 CMT_ROUND_STEP_PROPOSE));
    S_CHECK(tc->cs->rs.proposal == NULL,
            "enter_propose_no_priv: made a proposal without a key"); /* :154 */
    S_CHECK(tc->create_calls == 0,
            "enter_propose_no_priv: built a block without a key");
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:160-188 —
 * `TestStateEnterProposeYesPrivValidator`.
 *
 * A validator proposes: Proposal, ProposalBlock and ProposalBlockParts
 * are all set. The reference bounds the receive routine to three messages
 * (:170) so it can assert before the height rolls on; this steps until
 * the round state reaches Prevote, which is the same moment — the
 * proposal is complete and `handleCompleteProposal` has just called
 * `enterPrevote` (:2055-2065).
 *
 * ⚠ The reference's last assertion, `ensureNoNewTimeout` (:187), is NOT
 * ported: it says the propose timeout did not FIRE, and in this suite the
 * test owns the timer, so nothing fires unless a scenario fires it. The
 * fact underneath — that the timeout was scheduled but the proposal
 * arrived first — is asserted instead as "we are at Prevote with a
 * complete proposal".
 */
static int s_enter_propose_yes_priv_validator(void)
{
    tc_t                 *tc = tc_alloc(1u, 1, 0);
    cmt_part_set_header_t psh;

    S_CHECK(tc != NULL, "enter_propose_yes_priv: setup");

    S_CHECK(cmt_cs_enter_new_round(tc->cs, 1, 0) == CMT_OK,
            "enter_propose_yes_priv: enterNewRound");            /* :169 */
    S_STEP(tc_step_until_step(tc, CMT_ROUND_STEP_PREVOTE));      /* :170 */

    S_CHECK(tc->cs->rs.proposal != NULL,
            "enter_propose_yes_priv: rs.Proposal should be set");  /* :176 */
    S_CHECK(tc->cs->rs.proposal_block != NULL,
            "enter_propose_yes_priv: rs.ProposalBlock should be set");/*:179*/
    S_STEP(tc_proposal_parts_header(tc, &psh));
    S_CHECK(psh.total > 0u,
            "enter_propose_yes_priv: rs.ProposalBlockParts should be set");
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:190-257 —
 * `TestStateBadProposal`.
 *
 * Two validators. The other one proposes a block whose AppHash has been
 * tampered with, so `validateBlock` (state/validation.go:58-62) refuses
 * it and this node prevotes nil; a prevote for the bad block from the
 * other validator is +2/3 of ANYTHING but not a polka for one block, so
 * after the prevote timeout the node precommits nil and is locked on
 * nothing.
 */
static int s_bad_proposal(void)
{
    tc_t                 *tc = tc_alloc(2u, 1, 0);
    cmt_block_t          *block = NULL;
    cmt_part_set_t       *parts = NULL;
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;

    S_CHECK(tc != NULL, "bad_proposal: setup");

    /* :203-217 — build the block, then break it. The tamper happens
     * inside the block executor, between MakeBlock and the part set, so
     * the proposal is made over the BROKEN block's hash exactly as the
     * reference's :217-219 does. */
    tc->tamper_app_hash = true;
    S_STEP(tc_decide_proposal(tc, 1u, 1, 1, tc->prop, &block, &parts));
    tc->tamper_app_hash = false;
    tc_increment_round(tc, 1u, 2u);                              /* :208 */

    S_CHECK(cmt_block_hash(block, hash) == CMT_OK, "bad_proposal: hash");
    S_CHECK(cmt_part_set_header(parts, &psh) == CMT_OK, "bad_proposal: psh");

    /* :229 — queued, NOT handled: the reference's SetProposalAndBlock
     * only writes to the peer queue, and the round has not started. */
    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts));
    S_STEP(tc_start_test_round(tc, 1, 1));                       /* :234 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 1));                    /* :237 */

    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :240 */
    S_STEP(tc_validate_prevote(tc, 1, NULL, 0u));                /* :241 */

    /* :247 — the other validator prevotes the bad block. */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, hash, sizeof(hash),
                                &psh, false));
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_prevote(&tc->config, 1),
                                 CMT_ROUND_STEP_PREVOTE_WAIT));
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :251 */
    S_STEP(tc_validate_precommit(tc, 1, -1, NULL, 0u, NULL, 0u));/* :252 */
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:259-354 —
 * `TestStateOversizedBlock`, REDUCED to its "off-by-1 max size" case and
 * to the one refusal that case turns on.
 *
 * The reference searches for a transaction size that pushes the block
 * one byte over `ConsensusParams.Block.MaxBytes`
 * (`findBlockSizeLimit`, :2592-2620) and then checks, among other
 * things, `require.Nil(t, cs1.Proposal)` (:337-339) — the proposal was
 * refused because its part count exceeds what MaxBytes allows
 * (state.go:1931-1937). That refusal is what this ports: MaxBytes is set
 * to one part's worth, the block is made two parts wide, and the
 * proposal must be refused, leaving the node to time out into a nil
 * prevote.
 *
 * NOT ported from that test: the "max size, correct block" case and the
 * whole prevote/precommit/lock walk that follows it (:333-351), because
 * they need the size search, and the search is a property of
 * `MaxDataBytes` rather than of the state machine.
 */
static int s_oversized_block(void)
{
    tc_t                 *tc;
    uint8_t              *txbuf;
    cmt_part_set_t       *parts = NULL;
    cmt_part_set_header_t psh;

    /* :260, :277 — MaxBytes is one BlockPartSizeBytes. */
    tc = tc_alloc(2u, 1, (int64_t)CMT_BLOCK_PART_SIZE_BYTES);
    S_CHECK(tc != NULL, "oversized_block: setup");

    txbuf = (uint8_t *)calloc(1u, (size_t)CMT_BLOCK_PART_SIZE_BYTES);
    if (txbuf == NULL) {
        tc_release(tc);
        return 1;
    }
    /* A transaction of one whole part, so the block — that transaction
     * plus a header and a commit — is certainly wider than one part and
     * `maxParts` (:1935, one here because MaxBytes is one part) is
     * exceeded. The first draft used 65000 and the block came out at ONE
     * part: the margin has to cover the header, and this tree's header
     * carries 64-byte hashes rather than the reference's 32, so a
     * guess close to the boundary is not safe. Asserted below rather
     * than assumed. */
    tc_set_next_tx(tc, txbuf, (size_t)CMT_BLOCK_PART_SIZE_BYTES);

    if (tc_decide_proposal(tc, 1u, 1, 1, tc->prop, NULL, &parts) != 0) {
        free(txbuf);
        tc_release(tc);
        return 1;
    }
    tc->next_txs_n = 0u;
    if (cmt_part_set_header(parts, &psh) != CMT_OK) {
        free(txbuf);
        tc_release(tc);
        return 1;
    }
    if (psh.total < 2u) {
        fprintf(stderr, "oversized_block: expected >= 2 parts, got %u\n",
                (unsigned)psh.total);
        free(txbuf);
        tc_release(tc);
        return 1;
    }
    g_tc_checks++;

    tc_increment_round(tc, 1u, 2u);                              /* :290 */
    if (tc_set_proposal_and_block(tc, tc->prop, parts) != 0 ||
        tc_start_test_round(tc, 1, 1) != 0) {                    /* :317 */
        free(txbuf);
        tc_release(tc);
        return 1;
    }
    free(txbuf);

    /* :338 — the proposal was refused, so nothing is installed. */
    S_CHECK(tc->cs->rs.proposal == NULL,
            "oversized_block: a proposal with too many parts was accepted");
    /* :329 — and the node times out into a nil prevote. */
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_propose(&tc->config, 1),
                                 CMT_ROUND_STEP_PROPOSE));
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :333 */
    S_STEP(tc_validate_prevote(tc, 1, NULL, 0u));                /* :334 */
    tc_release(tc);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * FullRoundSuite
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state_test.go:360-397 —
 * `TestStateFullRound1`.
 *
 * One validator, one whole height: propose, prevote, precommit, commit,
 * and the precommit ends up in the next height's LastCommit.
 */
static int s_full_round1(void)
{
    tc_t *tc = tc_alloc(1u, 1, 0);

    S_CHECK(tc != NULL, "full_round1: setup");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :381 */
    /* The whole height runs inside that drain, because one validator is
     * its own +2/3 at every step. */
    S_CHECK(tc->recs_n >= 1u && tc->recs[0].used,
            "full_round1: no block was ever proposed");
    S_CHECK(tc->apply_calls == 1, "full_round1: the block was not applied");
    /* :393 `ensureNewBlockHeader` — WHICH block, not just that one was. */
    S_STEP(tc_ensure_new_block_header(tc, 1, tc->recs[0].hash,
                                      (size_t)CMT_TMHASH_SIZE));

    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :388 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :391 */
    /* ⚠ WEAKER THAN THE REFERENCE, and deliberately. Everywhere else the
     * suite fires the commit timeout before this assertion so that
     * enterNewRound has really run (see :447). Here it cannot: one
     * validator is its own +2/3, so the drain that follows the timeout
     * would run the WHOLE of height 2 and leave the machine at height 3.
     * So this asserts the height moved, not that round 0 was entered —
     * HOW IT CAN LIE (15). */
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :394 */
    /* :396 — our precommit for that block is the new height's
     * LastCommit, which is state.go:701's "LastCommit points INTO the
     * previous height vote set". */
    S_STEP(tc_validate_last_precommit(tc, tc->recs[0].hash,
                                      (size_t)CMT_TMHASH_SIZE));
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:400-411 —
 * `TestStateFullRoundNil`.
 *
 * `enterPrevote` is entered with no proposal at all, so the node prevotes
 * nil (state.go:1356-1360), its own nil prevote is a nil polka, and it
 * precommits nil (:1488-1503). The height does not move, which is why
 * both votes are still readable in the round state.
 */
static int s_full_round_nil(void)
{
    tc_t *tc = tc_alloc(1u, 1, 0);

    S_CHECK(tc != NULL, "full_round_nil: setup");

    S_CHECK(cmt_cs_enter_prevote(tc->cs, 1, 0) == CMT_OK,
            "full_round_nil: enterPrevote");                     /* :406 */
    S_STEP(tc_drain(tc));                                        /* :407 */

    S_STEP(tc_validate_prevote(tc, 0, NULL, 0u));                /* :409 */
    S_STEP(tc_validate_precommit(tc, 0, -1, NULL, 0u, NULL, 0u));/* :410 */
    S_CHECK(tc->cs->rs.height == 1, "full_round_nil: the height moved");
    S_CHECK(tc->apply_calls == 0, "full_round_nil: something was committed");
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:415-448 —
 * `TestStateFullRound2`.
 *
 * Two validators: this node cannot move without the other one. The
 * prevote from the second validator makes the polka that locks the
 * block, and its precommit makes the commit.
 */
static int s_full_round2(void)
{
    tc_t                 *tc = tc_alloc(2u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;

    S_CHECK(tc != NULL, "full_round2: setup");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :424 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :426 */
    S_CHECK(tc->apply_calls == 0,
            "full_round2: committed without the other validator"); /* :428 */

    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :430 */
    S_STEP(tc_proposal_parts_header(tc, &psh));

    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, hash, sizeof(hash),
                                &psh, false));                   /* :433 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :436 */
    /* :438 — locked on the proposal at round 0, precommitting it. */
    S_STEP(tc_validate_precommit(tc, 0, 0, hash, sizeof(hash),
                                 hash, sizeof(hash)));

    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, hash, sizeof(hash),
                                &psh, true));                    /* :443 */
    S_CHECK(tc->apply_calls == 1, "full_round2: the block was not applied");
    /* The commit timeout. finalizeCommit ends at cmt_cs.c:1804 by arming
     * a NEW_HEIGHT timeout (state.go:1804 scheduleRound0), and only
     * handleTimeout(NewHeight) runs enterNewRound — so firing it here is
     * what makes the assertion below mean what the reference's
     * `ensureNewRound` means. See HOW IT CAN LIE (15). */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :447 */
    tc_release(tc);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * LockSuite
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state_test.go:455-654 —
 * `TestStateLockNoPOL`, PARTIAL: rounds 0 and 1 of the reference's four.
 *
 * What it ports: this node locks on its own proposal at round 0, the
 * other validator precommits a DIFFERENT block so no commit happens, the
 * precommit timeout takes the node to round 1, where it prevotes THE
 * BLOCK IT IS LOCKED ON rather than the (absent) round-1 proposal
 * (state.go:1349-1353), and a conflicting prevote leaves no polka, so it
 * precommits nil WHILE STAYING LOCKED at round 0 (:1465-1474).
 *
 * ⚠ NOT PORTED: rounds 2 and 3 (:558-654). Round 2 has this node propose
 * its own locked block and round 3 has the other validator propose a
 * third block built by a SECOND consensus state (:604, `cs2, _ :=
 * randState(2)`). Both are portable in principle; they are left out to
 * keep one scenario from being a quarter of the file, and what they add
 * over rounds 0-1 is repetition of the same two rules. A green here says
 * NOTHING about them.
 */
static int s_lock_no_pol(void)
{
    tc_t                 *tc = tc_alloc(2u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    uint8_t               other[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;

    S_CHECK(tc != NULL, "lock_no_pol: setup");

    S_CHECK(cmt_cs_enter_new_round(tc->cs, 1, 0) == CMT_OK,
            "lock_no_pol: enterNewRound");                       /* :476 */
    S_STEP(tc_drain(tc));                                        /* :477 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :479 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :481 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :483 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :484 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :486 */

    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, hash, sizeof(hash),
                                &psh, false));                   /* :490 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :493 */
    S_STEP(tc_validate_precommit(tc, 0, 0, hash, sizeof(hash),
                                 hash, sizeof(hash)));           /* :495 */

    /* :499-501 — a precommit for a block that is not ours. */
    memcpy(other, hash, sizeof(other));
    other[0] = (uint8_t)((other[0] + 1u) % 255u);
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, other, sizeof(other),
                                &psh, true));                    /* :502 */
    /* :507 — two conflicting precommits are +2/3 of anything and no
     * majority, so the node waits out the precommit timeout. */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));
    S_CHECK(tc->apply_calls == 0,
            "lock_no_pol: committed on conflicting precommits");

    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :512 */
    tc_increment_round(tc, 1u, 2u);                              /* :518 */

    /* :521-525 — round 1's proposer is the other validator and it does
     * not propose, so we have no proposal block at all. */
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_propose(&tc->config, 1),
                                 CMT_ROUND_STEP_PROPOSE));
    S_CHECK(tc->cs->rs.proposal_block == NULL,
            "lock_no_pol: expected no proposal block at round 1");

    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :528 */
    /* :530 — WE PREVOTE OUR LOCKED BLOCK, not nil, even though this
     * round brought no proposal. */
    S_STEP(tc_validate_prevote(tc, 1, hash, sizeof(hash)));

    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, other, sizeof(other),
                                &psh, false));                   /* :536 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_prevote(&tc->config, 1),
                                 CMT_ROUND_STEP_PREVOTE_WAIT)); /* :541 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :543 */
    /* :546 — precommit nil, still locked on the round-0 block. */
    S_STEP(tc_validate_precommit(tc, 1, 0, NULL, 0u,
                                 hash, sizeof(hash)));
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:660-759 —
 * `TestStateLockPOLRelock`.
 *
 * Four validators. This node locks on its own block at round 0 but the
 * others precommit nil, so nothing commits. At round 1 another validator
 * proposes a DIFFERENT block; this node still prevotes its locked block
 * (:744-745), the others polka the new one, and the node RELOCKS onto it
 * (state.go:1522-1539) and precommits it. Two more precommits commit it.
 */
static int s_lock_pol_relock(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               the_hash[CMT_TMHASH_SIZE];
    uint8_t               prop_hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t the_psh;
    cmt_part_set_header_t prop_psh;
    cmt_part_set_header_t zero;
    cmt_block_t          *block = NULL;
    cmt_part_set_t       *parts = NULL;

    S_CHECK(tc != NULL, "lock_pol_relock: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :688 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :690 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :691 */
    S_STEP(tc_proposal_block_hash(tc, the_hash));                /* :693 */
    S_STEP(tc_proposal_parts_header(tc, &the_psh));              /* :694 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :696 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, the_hash, sizeof(the_hash),
                                   &the_psh, false, 1u, 4u));    /* :698 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :700 */
    S_STEP(tc_validate_precommit(tc, 0, 0, the_hash, sizeof(the_hash),
                                 the_hash, sizeof(the_hash)));   /* :702 */

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                   true, 1u, 4u));               /* :705 */
    S_CHECK(tc->apply_calls == 0,
            "lock_pol_relock: committed on nil precommits");

    /* :708-717 — the next round's proposal, made by another validator.
     * Its ProposerAddress differs from ours, so the block differs — the
     * same reason the reference needs a second State here. */
    S_STEP(tc_decide_proposal(tc, 1u, 1, 1, tc->prop, &block, &parts));
    S_CHECK(cmt_block_hash(block, prop_hash) == CMT_OK,
            "lock_pol_relock: hashing the round-1 block");
    S_CHECK(cmt_part_set_header(parts, &prop_psh) == CMT_OK,
            "lock_pol_relock: the round-1 part set header");
    S_CHECK(memcmp(prop_hash, the_hash, sizeof(the_hash)) != 0,
            "lock_pol_relock: the two blocks must differ");      /* :717 */

    tc_increment_round(tc, 1u, 4u);                              /* :719 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));/* :722 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts));      /* :726 */
    S_STEP(tc_drain(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :730 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 1));                    /* :741 */

    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :744 */
    /* :745 — the locked block, NOT the new proposal. */
    S_STEP(tc_validate_prevote(tc, 1, the_hash, sizeof(the_hash)));

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, prop_hash,
                                   sizeof(prop_hash), &prop_psh,
                                   false, 1u, 4u));              /* :748 */
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :750 */
    /* :752 — unlocked from the old block and locked on the new one. */
    S_STEP(tc_validate_precommit(tc, 1, 1, prop_hash, sizeof(prop_hash),
                                 prop_hash, sizeof(prop_hash)));

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, prop_hash,
                                   sizeof(prop_hash), &prop_psh,
                                   true, 1u, 3u));               /* :755 */
    /* :756 `ensureNewBlockHeader(newBlockCh, height, propBlockHash)` —
     * the reference asserts the committed header's HEIGHT AND HASH, not
     * just that a commit happened. A count alone would pass if the node
     * committed the block it was locked on BEFORE the relock, which is
     * exactly the regression this scenario exists to catch. */
    S_CHECK(tc->apply_calls == 1,
            "lock_pol_relock: the relocked block was not committed");
    S_STEP(tc_ensure_new_block_header(tc, 1, prop_hash, sizeof(prop_hash)));
    S_STEP(tc_fire_timeout(tc));      /* the commit timeout — see :447 */
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :758 */
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:762-852 —
 * `TestStateLockPOLUnlock`.
 *
 * Four validators. This node locks at round 0; at round 1 the others
 * polka NIL, which unlocks it (state.go:1488-1503) and makes it
 * precommit nil with LockedRound back at -1.
 *
 * ⚠ ONE DELIBERATE DIFFERENCE. The reference builds the round-1 proposal
 * from cs1 itself (:811 `decideProposal(ctx, t, cs1, vs2, …)`), so that
 * block carries CS1's proposer address and may equal the round-0 block.
 * `tc_decide_proposal` always stamps the SIGNER as the proposer, so here
 * the round-1 block differs. Nothing in the assertions turns on it: this
 * node prevotes its LOCKED block either way (:838), and the nil polka
 * that follows is what unlocks it.
 */
static int s_lock_pol_unlock(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               the_hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t the_psh;
    cmt_part_set_header_t zero;
    cmt_part_set_t       *parts = NULL;

    S_CHECK(tc != NULL, "lock_pol_unlock: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :789 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :792 */
    S_STEP(tc_proposal_block_hash(tc, the_hash));                /* :794 */
    S_STEP(tc_proposal_parts_header(tc, &the_psh));              /* :795 */
    S_STEP(tc_validate_prevote(tc, 0, the_hash, sizeof(the_hash)));/* :798 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, the_hash, sizeof(the_hash),
                                   &the_psh, false, 1u, 4u));    /* :800 */
    S_STEP(tc_validate_precommit(tc, 0, 0, the_hash, sizeof(the_hash),
                                 the_hash, sizeof(the_hash)));   /* :804 */

    /* :807-808 — two nil precommits and one for the block: no majority. */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, NULL, 0u, &zero, true));
    S_STEP(tc_sign_add_vote_one(tc, 3u, S_PRECOMMIT, NULL, 0u, &zero, true));
    S_STEP(tc_sign_add_vote_one(tc, 2u, S_PRECOMMIT, the_hash,
                                sizeof(the_hash), &the_psh, true));
    S_CHECK(tc->apply_calls == 0, "lock_pol_unlock: committed too early");

    S_STEP(tc_decide_proposal(tc, 1u, 1, 1, tc->prop, NULL, &parts));/* :811 */

    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));/* :816 */
    S_CHECK(tc->cs->rs.locked_block != NULL,
            "lock_pol_unlock: should still be locked");          /* :818 */

    tc_increment_round(tc, 1u, 4u);                              /* :820 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :823 */

    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts));      /* :830 */
    S_STEP(tc_drain(tc));
    S_STEP(tc_ensure_new_proposal(tc, 1, 1));                    /* :834 */

    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :837 */
    S_STEP(tc_validate_prevote(tc, 1, the_hash, sizeof(the_hash)));/* :838 */

    /* :840 — everyone else prevotes nil: a nil polka. */
    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, NULL, 0u, &zero,
                                   false, 1u, 4u));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :844 */
    /* :848 — unlocked, and NOT relocked on nil, so the lock round is -1. */
    S_STEP(tc_validate_precommit(tc, 1, -1, NULL, 0u, NULL, 0u));
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:1309-1367 —
 * `TestSetValidBlockOnDelayedPrevote`.
 *
 * The node misses the polka in time to lock — one prevote for the block
 * and one for nil is +2/3 of anything but no majority, so it precommits
 * nil with no ValidBlock. The LATE prevote then completes the polka, and
 * state.go:2281-2286 sets ValidBlock/ValidBlockParts/ValidRound without
 * changing the lock.
 */
static int s_set_valid_block_on_delayed_prevote(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    uint8_t               vhash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t vpsh;
    cmt_part_set_header_t zero;

    S_CHECK(tc != NULL, "set_valid_block_delayed_prevote: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1326 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1329 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :1332 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :1333 */
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));      /* :1337 */

    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, hash, sizeof(hash),
                                &psh, false));                   /* :1340 */
    S_STEP(tc_sign_add_vote_one(tc, 2u, S_PREVOTE, NULL, 0u, &zero,
                                false));                         /* :1343 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_prevote(&tc->config, 0),
                                 CMT_ROUND_STEP_PREVOTE_WAIT));  /* :1345 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :1347 */
    S_STEP(tc_validate_precommit(tc, 0, -1, NULL, 0u, NULL, 0u));/* :1349 */

    S_CHECK(tc->cs->rs.valid_block == NULL,
            "delayed_prevote: ValidBlock should be nil");        /* :1353 */
    S_CHECK(tc->cs->rs.valid_block_parts == NULL,
            "delayed_prevote: ValidBlockParts should be nil");   /* :1354 */
    S_CHECK(tc->cs->rs.valid_round == -1,
            "delayed_prevote: ValidRound should be -1");         /* :1355 */

    /* :1358 — the delayed prevote completes the polka. */
    S_STEP(tc_sign_add_vote_one(tc, 3u, S_PREVOTE, hash, sizeof(hash),
                                &psh, false));
    S_CHECK(tc->cs->rs.valid_block != NULL,
            "delayed_prevote: ValidBlock should now be set");
    S_CHECK(cmt_block_hash(tc->cs->rs.valid_block, vhash) == CMT_OK,
            "delayed_prevote: hashing the valid block");
    S_CHECK(memcmp(vhash, hash, sizeof(hash)) == 0,
            "delayed_prevote: the wrong block became valid");    /* :1364 */
    S_CHECK(tc->cs->rs.valid_block_parts != NULL &&
            cmt_part_set_header(tc->cs->rs.valid_block_parts,
                                &vpsh) == CMT_OK &&
            cmt_psh_equals(&vpsh, &psh),
            "delayed_prevote: the wrong part set became valid"); /* :1365 */
    S_CHECK(tc->cs->rs.valid_round == 0,
            "delayed_prevote: ValidRound should be 0");          /* :1366 */
    /* And the lock did NOT move: :2281-2286 sets only the Valid* names. */
    S_CHECK(tc->cs->rs.locked_round == -1 && tc->cs->rs.locked_block == NULL,
            "delayed_prevote: the lock moved on a late polka");
    tc_release(tc);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * ABCI: ProcessProposal, ExtendVote, VerifyVoteExtension, FinalizeBlock
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state_test.go:1429-1476 —
 * `TestProcessProposalAccept`, both of its cases.
 *
 * The application's verdict decides the prevote: ACCEPT prevotes the
 * block (state.go:1398-1402), REJECT prevotes nil (:1391-1396).
 */
static int s_process_proposal_accept_case(bool accept)
{
    tc_t    *tc = tc_alloc(4u, 1, 0);
    uint8_t  hash[CMT_TMHASH_SIZE];

    S_CHECK(tc != NULL, "process_proposal_accept: setup");
    tc->process_accept = accept;                                 /* :1452 */

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1464 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1465 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1467 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :1471 */
    S_CHECK(tc->process_calls == 1,
            "process_proposal_accept: ProcessProposal was not called once");

    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));
    if (accept) {
        S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash))); /* :1473 */
    } else {
        S_STEP(tc_validate_prevote(tc, 0, NULL, 0u));
    }
    tc_release(tc);
    return 0;
}

static int s_process_proposal_accept(void)
{
    if (s_process_proposal_accept_case(true) != 0) {
        return 1;
    }
    return s_process_proposal_accept_case(false);
}

/**
 * cometbft@709fd12b consensus/state_test.go:1480-1578 —
 * `TestExtendVoteCalledWhenEnabled`, both of its cases.
 *
 * With extensions enabled at height 1, `ExtendVote` is called exactly
 * once — when this node signs its own non-nil precommit (state.go:2400) —
 * and never before the precommit step (:1527). `VerifyVoteExtension` is
 * called for each OTHER validator's non-nil precommit that the state
 * machine actually processes at this height (:2210).
 *
 * ⚠ PARTIAL: the reference also asserts the CONTENT of the ExtendVote
 * request — its Height, Hash, Time, Txs, Misbehavior, NextValidatorsHash
 * and ProposerAddress (:1541-1550). This port has no request object:
 * cmt_cs.h's `extend_vote` row is handed the vote, the block and the
 * state, so the fields are all reachable but there is no message to
 * compare. Only the CALL is asserted here.
 *
 * The expected `VerifyVoteExtension` count is DERIVED, not observed: with
 * four validators of equal power, this node's own precommit plus two
 * others is 30 of 40, which is the +2/3 that commits the height
 * (state.go:2339-2346). Our own vote is skipped by the address test at
 * :2191. The third stub's precommit therefore arrives at the NEXT height
 * and takes the LastCommit path (:2137-2167), which does not verify
 * extensions. So two calls, not three — which is the same reasoning the
 * reference's own comment gives at :1559-1560.
 */
static int s_extend_vote_called_when_enabled_case(bool enabled)
{
    tc_t                 *tc = tc_alloc(4u, enabled ? 1 : 0, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;

    S_CHECK(tc != NULL, "extend_vote_when_enabled: setup");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1523 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1524 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1525 */
    S_CHECK(tc->extend_calls == 0,
            "extend_vote_when_enabled: ExtendVote before the precommit");
                                                                 /* :1527 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :1532 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :1533 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 1u, 4u));        /* :1535 */
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));      /* :1536 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :1538 */

    S_CHECK(tc->extend_calls == (enabled ? 1 : 0),
            "extend_vote_when_enabled: wrong ExtendVote count");
                                                             /* :1541-1552 */

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, hash, sizeof(hash),
                                   &psh, enabled, 1u, 4u));      /* :1555 */
    S_STEP(tc_fire_timeout(tc));      /* the commit timeout — see :447 */
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :1556 */
    S_CHECK(tc->apply_calls == 1,
            "extend_vote_when_enabled: the block was not committed");
    S_CHECK(tc->verify_ext_calls == (enabled ? 2 : 0),
            "extend_vote_when_enabled: wrong VerifyVoteExtension count");
                                                             /* :1561-1575 */
    tc_release(tc);
    return 0;
}

static int s_extend_vote_called_when_enabled(void)
{
    if (s_extend_vote_called_when_enabled_case(true) != 0) {
        return 1;
    }
    return s_extend_vote_called_when_enabled_case(false);
}

/**
 * cometbft@709fd12b consensus/state_test.go:1747-1825 —
 * `TestFinalizeBlockCalled`, both of its cases.
 *
 * The block is applied when it is committed and not otherwise. The
 * reference asserts on its mock's `FinalizeBlock`; this asserts on the
 * `apply_verified_block` row (state.go:1775), which is where the port
 * puts that call.
 */
static int s_finalize_block_called_case(bool vote_nil)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t zero;
    const uint8_t        *vh;
    size_t                vhl;
    cmt_part_set_header_t *vp;

    S_CHECK(tc != NULL, "finalize_block_called: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1792 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1793 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1794 */
    S_STEP(tc_proposal_block_hash(tc, hash));
    S_STEP(tc_proposal_parts_header(tc, &psh));

    /* :1797-1807 — the votes the others cast: for the block, or for nil. */
    if (vote_nil) {
        vh  = NULL;
        vhl = 0u;
        vp  = &zero;
    } else {
        vh  = hash;
        vhl = sizeof(hash);
        vp  = &psh;
    }

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, vh, vhl, vp,
                                   false, 1u, 4u));              /* :1809 */
    /* :1810 — we prevote OUR proposal in both cases. */
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, vh, vhl, vp,
                                   true, 1u, 4u));               /* :1812 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :1813 */

    if (vote_nil) {
        /* :1798 — a nil polka means a new ROUND at the same height,
         * reached through the precommit timeout. */
        S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                     cmt_config_precommit(&tc->config, 0),
                                     CMT_ROUND_STEP_PRECOMMIT_WAIT));
        S_STEP(tc_fire_timeout(tc));
        S_STEP(tc_ensure_new_round(tc, 1, 1));                   /* :1815 */
        S_CHECK(tc->apply_calls == 0,
                "finalize_block_called: applied a block nobody committed");
                                                                 /* :1819 */
    } else {
        S_STEP(tc_fire_timeout(tc));  /* the commit timeout — see :447 */
        S_STEP(tc_ensure_new_round(tc, 2, 0));                   /* :1815 */
        S_CHECK(tc->apply_calls == 1,
                "finalize_block_called: the committed block was not applied");
                                                                 /* :1821 */
    }
    tc_release(tc);
    return 0;
}

static int s_finalize_block_called(void)
{
    if (s_finalize_block_called_case(false) != 0) {
        return 1;
    }
    return s_finalize_block_called_case(true);
}

/**
 * cometbft@709fd12b consensus/state_test.go:1830-1937 —
 * `TestVoteExtensionEnableHeight`, one of its five table cases.
 *
 * THREE validators, as the reference's `numValidators := 3` (:1881): the
 * two stubs plus this node are the whole voting power, so a precommit
 * that is REFUSED is the difference between a commit and no commit —
 * which is exactly what the two negative cases turn on.
 *
 * The rule under test is state.go:2179-2226 (`cs_add_vote_check_extension`
 * in the port): with extensions OFF, a vote carrying one is malformed and
 * refused (cmt_cs.c:3240-3245); with them ON, a non-nil precommit from
 * another validator must carry an extension signature this node can
 * verify (:3283) before the application is ever asked (:3290). A refusal
 * is logged and dropped by handleMsg (state.go:954-962, cmt_cs.c:1541),
 * so the machine keeps running and the scenario reads the CONSEQUENCE.
 *
 * ⚠ ONE ASSERTION IS NOT THE REFERENCE'S. In the unsuccessful cases the
 * Go test asserts that no `EventDataTimeoutPropose` arrived within
 * `Precommit(round)` (:1933). That is an EVENT assertion, and it cannot
 * be re-expressed as "no propose timeout is scheduled": `enterPropose`
 * (state.go:1103) legitimately ARMS one at (1,0) at the start of every
 * round, and in these cases nothing later replaces it — it simply never
 * fires. `tc_ensure_no_timeout_for` would therefore report a failure for
 * a machine behaving correctly. What is asserted instead is the
 * observable the reference's "unsuccessful round" means: nothing was
 * committed and the height did not move.
 *
 * @param enable_height  ConsensusParams.ABCI.VoteExtensionsEnableHeight.
 * @param has_extension  whether the STUBS' precommits carry an extension,
 *                       independently of what the chain enables — the
 *                       reference's `testCase.hasExtension` (:1924).
 * @param expect_extend  expected `ExtendVote` calls (:1888).
 * @param expect_verify  expected `VerifyVoteExtension` calls (:1891-1893).
 * @param expect_success whether the round commits (:1928).
 */
static int s_vote_extension_enable_height_case(int64_t enable_height,
                                               bool has_extension,
                                               int expect_extend,
                                               int expect_verify,
                                               bool expect_success)
{
    tc_t                 *tc = tc_alloc(3u, enable_height, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;

    S_CHECK(tc != NULL, "vote_extension_enable_height: setup");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1909 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1910 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1911 */

    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :1912 */
    S_STEP(tc_proposal_parts_header(tc, &psh));

    /* :1915 — the two stubs prevote the proposal; with this node's own
     * prevote that is the whole set, so the polka is immediate. */
    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 1u, 3u));
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));      /* :1916 */

    /* This node's own precommit is made by the polka above, so ExtendVote
     * has already run (or not) by the time the stubs vote. */
    S_CHECK(tc->extend_calls == expect_extend,
            "vote_extension_enable_height: wrong ExtendVote count");
                                                                 /* :1888 */

    /* :1923-1927 — the stubs' precommits, carrying an extension or not
     * exactly as the case says, whatever the chain enables. */
    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, hash, sizeof(hash),
                                   &psh, has_extension, 1u, 3u));

    S_CHECK(tc->verify_ext_calls == expect_verify,
            "vote_extension_enable_height: wrong VerifyVoteExtension count");
                                                            /* :1891-1893 */

    if (expect_success) {
        S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));           /* :1929 */
        S_CHECK(tc->apply_calls == 1,
                "vote_extension_enable_height: the block was not committed");
        S_STEP(tc_fire_timeout(tc));  /* the commit timeout — see :447 */
        S_STEP(tc_ensure_new_round(tc, 2, 0));              /* :1930-1931 */
    } else {
        S_CHECK(tc->apply_calls == 0,
                "vote_extension_enable_height: a refused precommit "
                "still committed the block");
        S_CHECK(tc->cs->rs.height == 1 && tc->cs->rs.round == 0,
                "vote_extension_enable_height: the round moved on");
    }
    tc_release(tc);
    return 0;
}

/**
 * The five cases of the reference's table (:1832-1878), in its order.
 * Cases two and three overlap `s_extend_vote_called_when_enabled`, which
 * is a DIFFERENT Go test (`TestExtendVoteCalledWhenEnabled`, :1480) with
 * four validators; both are ported because neither subsumes the other.
 */
static int s_vote_extension_enable_height(void)
{
    /* :1839-1846 "extension present but not enabled" — the stubs' votes
     * are refused at cmt_cs.c:3243, so their power never counts. */
    if (s_vote_extension_enable_height_case(0, true, 0, 0, false) != 0) {
        return 1;
    }
    /* :1847-1854 "extension absent but not required". */
    if (s_vote_extension_enable_height_case(0, false, 0, 0, true) != 0) {
        return 1;
    }
    /* :1855-1862 "extension present and required" — one ExtendVote for
     * this node's own precommit, one VerifyVoteExtension per OTHER
     * validator (:1893 `Times(numValidators - 1)`). */
    if (s_vote_extension_enable_height_case(1, true, 1, 2, true) != 0) {
        return 1;
    }
    /* :1863-1870 "extension absent but required" — this node still
     * extends its own precommit, but each stub's extension-less precommit
     * fails `cmt_vote_verify_extension` (cmt_cs.c:3283) BEFORE the
     * application is asked, so VerifyVoteExtension is never called. */
    if (s_vote_extension_enable_height_case(1, false, 1, 0, false) != 0) {
        return 1;
    }
    /* :1871-1878 "extension absent but required in future height" — at
     * height 1 an enable height of 2 is not yet in force
     * (`cmt_abci_params_vote_extensions_enabled`, cmt_params.c:120), so
     * this is the disabled case. */
    return s_vote_extension_enable_height_case(2, false, 0, 0, true);
}

/* ══════════════════════════════════════════════════════════════════════
 * Bad input, timeouts and round skipping
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/state_test.go:1944-1971 —
 * `TestStateDoesntCrashOnInvalidVote`.
 *
 * ⚠ THE SUBJECT IS THAT NOTHING HAPPENS, which is the one place in this
 * file where "it passed" and "it never ran" look alike. Two things guard
 * against that: the vote is built and signed exactly as a good one is —
 * only its ValidatorIndex is changed, AFTER signing, so the signature
 * stays valid over the sign bytes (the index is not in a CanonicalVote) —
 * and the scenario asserts that the vote was NOT added, which it could
 * only do if the message really reached `tryAddVote`.
 */
static int s_doesnt_crash_on_invalid_vote(void)
{
    tc_t                 *tc = tc_alloc(2u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_vote_set_t       *precommits;

    S_CHECK(tc != NULL, "invalid_vote: setup");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1950 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));
    S_STEP(tc_proposal_block_hash(tc, hash));
    S_STEP(tc_proposal_parts_header(tc, &psh));

    /* :1956 — a well-formed precommit from the other validator … */
    S_STEP(tc_sign_vote(tc, &tc->vss[1], S_PRECOMMIT, hash, sizeof(hash),
                        &psh, true, tc->sv));
    /* :1959 — … whose ValidatorIndex is out of bounds. */
    tc->sv->validator_index = (int32_t)tc->nvals;

    S_STEP(tc_add_vote(tc, tc->sv));                             /* :1963 */
    S_STEP(tc_drain(tc));

    /* :1967 — `added` is false. The port's handleMsg swallows the error
     * (state.go:954-963), so the observable fact is that the vote is not
     * in the set and the round state has not moved. */
    S_CHECK(tc->cs->rs.height == 1 && tc->cs->rs.round == 0,
            "invalid_vote: the round state moved on a bad vote");
    precommits = cmt_hvs_precommits(tc->cs->rs.votes, 0);
    if (precommits != NULL) {
        const cmt_vote_t *v = NULL;

        S_CHECK(cmt_vote_set_get_by_address(precommits, tc->addr[1],
                                            (size_t)CMT_ADDRESS_SIZE,
                                            &v) != CMT_OK || v == NULL,
                "invalid_vote: the out-of-bounds vote was added");
    }
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:1976-1992 —
 * `TestWaitingTimeoutOnNilPolka`.
 *
 * +2/3 nil precommits do not commit and do not skip: the node waits out
 * `timeoutPrecommit` and only then starts the next round
 * (state.go:2350-2352).
 */
static int s_waiting_timeout_on_nil_polka(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    cmt_part_set_header_t zero;

    S_CHECK(tc != NULL, "waiting_timeout_on_nil_polka: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1985 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1986 */

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                   true, 1u, 4u));               /* :1988 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));/* :1990 */
    S_CHECK(tc->apply_calls == 0,
            "waiting_timeout_on_nil_polka: committed on a nil polka");
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :1991 */
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:1997-2028 —
 * `TestWaitingTimeoutProposeOnNewRound`.
 *
 * +2/3 prevotes at a HIGHER round skip the node into that round
 * (state.go:2311-2313), where it does NOT prevote until the propose
 * timeout has elapsed — the assertion at :2022 that the step is still
 * Propose is the whole point.
 */
static int s_waiting_timeout_propose_on_new_round(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    cmt_part_set_header_t zero;

    S_CHECK(tc != NULL, "waiting_timeout_propose_on_new_round: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :2010 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :2013 */

    tc_increment_round(tc, 1u, 4u);                              /* :2015 */
    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, NULL, 0u, &zero,
                                   false, 1u, 4u));              /* :2016 */

    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :2019 */
    S_CHECK(tc->cs->rs.step == CMT_ROUND_STEP_PROPOSE,
            "new_round: prevoted before timeoutPropose expired");/* :2022 */

    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_propose(&tc->config, 1),
                                 CMT_ROUND_STEP_PROPOSE));       /* :2024 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :2026 */
    S_STEP(tc_validate_prevote(tc, 1, NULL, 0u));                /* :2027 */
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:2033-2064 —
 * `TestRoundSkipOnNilPolkaFromHigherRound`.
 *
 * +2/3 nil PRECOMMITS at a higher round skip the node there, make it
 * precommit nil at that round, and start its precommit wait
 * (state.go:2339-2352).
 */
static int s_round_skip_on_nil_polka_from_higher_round(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    cmt_part_set_header_t zero;

    S_CHECK(tc != NULL, "round_skip_on_nil_polka: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :2046 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :2049 */

    tc_increment_round(tc, 1u, 4u);                              /* :2051 */
    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                   true, 1u, 4u));               /* :2052 */

    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :2055 */
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :2057 */
    S_STEP(tc_validate_precommit(tc, 1, -1, NULL, 0u, NULL, 0u));/* :2058 */

    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_precommit(&tc->config, 1),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));/* :2060 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 2));                       /* :2063 */
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:2069-2092 —
 * `TestWaitTimeoutProposeOnNilPolkaForTheCurrentRound`.
 *
 * +2/3 nil prevotes at the CURRENT round, while the node is still at the
 * Propose step, do nothing: state.go:2315's case requires
 * `RoundStepPrevote <= cs.Step`. The node waits out timeoutPropose and
 * then prevotes nil.
 */
static int s_wait_timeout_propose_on_nil_polka_current_round(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    cmt_part_set_header_t zero;

    S_CHECK(tc != NULL, "wait_timeout_propose_current_round: setup");
    tc_zero_psh(&zero);

    /* :2082 — start at round 1, where this node is not the proposer. */
    S_STEP(tc_start_test_round(tc, 1, 1));
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :2083 */
    S_CHECK(tc->cs->rs.step == CMT_ROUND_STEP_PROPOSE,
            "wait_timeout_propose_current_round: not at Propose");

    tc_increment_round(tc, 1u, 4u);                              /* :2085 */
    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, NULL, 0u, &zero,
                                   false, 1u, 4u));              /* :2086 */
    S_CHECK(tc->cs->rs.step == CMT_ROUND_STEP_PROPOSE,
            "wait_timeout_propose_current_round: a nil polka moved the step");

    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_propose(&tc->config, 1),
                                 CMT_ROUND_STEP_PROPOSE));       /* :2088 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :2090 */
    S_STEP(tc_validate_prevote(tc, 1, NULL, 0u));                /* :2091 */
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:2096-2128 —
 * `TestEmitNewValidBlockEventOnCommitWithoutBlock`.
 *
 * +2/3 precommits for a block this node has never seen take it to
 * RoundStepCommit with NO ProposalBlock and a ProposalBlockParts built
 * from the committed BlockID's part-set header (state.go:1637-1650).
 *
 * The reference names this after the event it emits; this port emits no
 * events (cmt_cs.h:72-74), so the round state the event would have
 * carried is asserted instead — which is what the reference itself
 * checks at :2124-2127.
 */
static int s_emit_new_valid_block_on_commit_without_block(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t got;
    cmt_block_t          *block = NULL;
    cmt_part_set_t       *parts = NULL;

    S_CHECK(tc != NULL, "commit_without_block: setup");

    tc_increment_round(tc, 1u, 4u);                              /* :2104 */
    /* :2111 — a block for round 1 that this node is never given. */
    S_STEP(tc_decide_proposal(tc, 1u, 1, 1, tc->prop, &block, &parts));
    S_CHECK(cmt_block_hash(block, hash) == CMT_OK,
            "commit_without_block: hashing");
    S_CHECK(cmt_part_set_header(parts, &psh) == CMT_OK,
            "commit_without_block: the part set header");

    S_STEP(tc_start_test_round(tc, 1, 1));                       /* :2117 */
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :2118 */

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, hash, sizeof(hash),
                                   &psh, true, 1u, 4u));         /* :2121 */

    S_CHECK(tc->cs->rs.step == CMT_ROUND_STEP_COMMIT,
            "commit_without_block: should be at RoundStepCommit"); /* :2125 */
    S_CHECK(tc->cs->rs.proposal_block == NULL,
            "commit_without_block: we should not have the block"); /* :2126 */
    S_CHECK(tc->cs->rs.proposal_block_parts != NULL &&
            cmt_part_set_header(tc->cs->rs.proposal_block_parts,
                                &got) == CMT_OK &&
            cmt_psh_equals(&got, &psh),
            "commit_without_block: wrong ProposalBlockParts header");/*:2127*/
    S_CHECK(tc->apply_calls == 0,
            "commit_without_block: applied a block we do not have");
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:2133-2173 —
 * `TestCommitFromPreviousRound`.
 *
 * +2/3 precommits for a block at round 0, seen while the node is at
 * round 1, put it at RoundStepCommit with CommitRound 0
 * (state.go:2339-2346). When the block finally arrives it is executed and
 * the chain moves on.
 *
 * ⚠ The reference's `ensureNewProposal` at :2171 is NOT ported, and could
 * not be: that event is published by `addProposalBlockPart`
 * (state.go:2026-2028) even though `defaultSetProposal` REFUSED the
 * proposal itself — its round is 0 and the node is at round 1, which
 * :1911 drops. This port publishes no events, so the same fact is
 * asserted one step later, as the height advancing.
 */
static int s_commit_from_previous_round(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t got;
    cmt_block_t          *block = NULL;
    cmt_part_set_t       *parts = NULL;

    S_CHECK(tc != NULL, "commit_from_previous_round: setup");

    /* :2147 — the stubs are still at round 0, so this is a round-0
     * proposal made by the round-0 proposer's neighbour. */
    S_STEP(tc_decide_proposal(tc, 1u, 1, 0, tc->prop, &block, &parts));
    S_CHECK(cmt_block_hash(block, hash) == CMT_OK,
            "commit_from_previous_round: hashing");
    S_CHECK(cmt_part_set_header(parts, &psh) == CMT_OK,
            "commit_from_previous_round: the part set header");

    S_STEP(tc_start_test_round(tc, 1, 1));                       /* :2153 */
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :2154 */

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, hash, sizeof(hash),
                                   &psh, true, 1u, 4u));         /* :2157 */

    S_CHECK(tc->cs->rs.step == CMT_ROUND_STEP_COMMIT,
            "commit_from_previous_round: not at RoundStepCommit"); /* :2162 */
    S_CHECK(tc->cs->rs.commit_round == 0,
            "commit_from_previous_round: wrong CommitRound");      /* :2163 */
    S_CHECK(tc->cs->rs.proposal_block == NULL,
            "commit_from_previous_round: we should not have the block");
                                                                 /* :2164 */
    S_CHECK(tc->cs->rs.proposal_block_parts != NULL &&
            cmt_part_set_header(tc->cs->rs.proposal_block_parts,
                                &got) == CMT_OK &&
            cmt_psh_equals(&got, &psh),
            "commit_from_previous_round: wrong parts header");   /* :2165 */

    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts));       /* :2167 */
    S_STEP(tc_drain(tc));
    S_CHECK(tc->apply_calls == 1,
            "commit_from_previous_round: the block was not applied");
    /* :2170 `ensureNewBlockHeader` — the block committed here arrived a
     * round LATE, so asserting its identity is the whole point. */
    S_STEP(tc_ensure_new_block_header(tc, 1, hash, sizeof(hash)));
    S_STEP(tc_fire_timeout(tc));      /* the commit timeout — see :447 */
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :2172 */
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:2539-2559 —
 * `TestSignSameVoteTwice`.
 *
 * ⚠ THIS TESTS THE FIXTURE, NOT THE PORT, and the reference's version is
 * the same: it exercises `validatorStub.signVote`'s reuse of the previous
 * signature when the sign data is unchanged (common_test.go:116-121). It
 * is ported because that reuse is what makes the suite's stub votes
 * reproducible under a RANDOMIZED signer — see the fixture's HOW IT CAN
 * LIE (4) — and a regression in it would make other scenarios flaky
 * rather than failing.
 */
static int s_sign_same_vote_twice(void)
{
    tc_t                 *tc = tc_alloc(2u, 1, 0);
    cmt_vote_t           *a;
    cmt_vote_t           *b;
    cmt_part_set_header_t psh;
    uint8_t               rand_bytes[CMT_TMHASH_SIZE];
    size_t                i;

    S_CHECK(tc != NULL, "sign_same_vote_twice: setup");

    /* :2542 — the reference uses random bytes; a fixed pattern is used
     * here, because nothing in this suite may depend on randomness. */
    for (i = 0u; i < sizeof(rand_bytes); i++) {
        rand_bytes[i] = (uint8_t)(0x30u + (i % 16u));
    }
    memset(&psh, 0, sizeof(psh));
    psh.total = 10u;                                             /* :2547 */
    memcpy(psh.hash, rand_bytes, sizeof(rand_bytes));
    psh.hash_len = sizeof(rand_bytes);

    a = (cmt_vote_t *)calloc(1u, sizeof(*a));
    b = (cmt_vote_t *)calloc(1u, sizeof(*b));
    if (a == NULL || b == NULL) {
        free(a);
        free(b);
        tc_release(tc);
        return 1;
    }
    if (tc_sign_vote(tc, &tc->vss[1], S_PRECOMMIT, rand_bytes,
                     sizeof(rand_bytes), &psh, true, a) != 0 ||
        tc_sign_vote(tc, &tc->vss[1], S_PRECOMMIT, rand_bytes,
                     sizeof(rand_bytes), &psh, true, b) != 0) {
        free(a);
        free(b);
        tc_release(tc);
        return 1;
    }

    /* :2558 — `require.Equal(t, vote, vote2)`, field by field. */
    if (a->type != b->type || a->height != b->height || a->round != b->round ||
        a->validator_index != b->validator_index ||
        a->timestamp.seconds != b->timestamp.seconds ||
        a->timestamp.nanos != b->timestamp.nanos ||
        a->block_id.hash_len != b->block_id.hash_len ||
        memcmp(a->block_id.hash, b->block_id.hash, a->block_id.hash_len) != 0 ||
        !cmt_psh_equals(&a->block_id.part_set_header,
                        &b->block_id.part_set_header) ||
        a->signature_len != b->signature_len ||
        memcmp(a->signature, b->signature, a->signature_len) != 0 ||
        a->extension.len != b->extension.len ||
        a->extension_signature_len != b->extension_signature_len ||
        memcmp(a->extension_signature, b->extension_signature,
               a->extension_signature_len) != 0) {
        fprintf(stderr, "sign_same_vote_twice: the two votes differ\n");
        free(a);
        free(b);
        tc_release(tc);
        return 1;
    }
    g_tc_checks++;
    free(a);
    free(b);
    tc_release(tc);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * byzantine_test.go
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/byzantine_test.go:38-298 —
 * `TestByzantinePrevoteEquivocation`, REDUCED to the path the dispatch
 * names: the conflicting-vote path that reaches the evidence pool.
 *
 * ⚠ WHAT IS AND IS NOT PORTED. The reference builds FOUR full nodes on a
 * p2p switch, makes node 0 sign two prevotes at height 2 and send each to
 * half the peers (:144-174), runs the chain until the evidence appears in
 * a committed block, and checks the evidence's timestamp against a
 * deliberately lazy proposer (:179-214). None of that is portable to a
 * single state machine with no reactor: there is no switch, no second
 * node and no evidence pool that produces blocks.
 * What IS ported is the one rule the port itself carries: when one
 * validator's two prevotes for different blocks at the same height and
 * round both reach this node, `types.VoteSet.AddVote` returns
 * `ErrVoteConflictingVotes` and `tryAddVote` hands both votes to
 * `evpool.ReportConflictingVotes` (state.go:2077-2094). A green here says
 * NOTHING about gossip, partitions, evidence blocks or timestamps.
 */
static int s_byzantine_prevote_equivocation(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t zero;
    cmt_vote_t           *second;

    S_CHECK(tc != NULL, "byzantine_equivocation: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));
    S_STEP(tc_proposal_block_hash(tc, hash));
    S_STEP(tc_proposal_parts_header(tc, &psh));

    /* byzantine_test.go:148 — the first prevote, for the proposal. */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, hash, sizeof(hash),
                                &psh, false));
    S_CHECK(tc->conflict_calls == 0,
            "byzantine_equivocation: reported a conflict too early");

    /* :150 — the second prevote, for nil, at the SAME height and round.
     * The stub's own lastVote reuse does not apply: the sign data
     * differs, so this is a genuinely different signed vote. */
    second = (cmt_vote_t *)calloc(1u, sizeof(*second));
    if (second == NULL) {
        tc_release(tc);
        return 1;
    }
    if (tc_sign_vote(tc, &tc->vss[1], S_PREVOTE, NULL, 0u, &zero,
                     false, second) != 0 ||
        tc_add_vote(tc, second) != 0 ||
        tc_drain(tc) != 0) {
        free(second);
        tc_release(tc);
        return 1;
    }
    free(second);

    /* state.go:2094 — both votes go to the evidence pool. */
    S_CHECK(tc->conflict_calls == 1,
            "byzantine_equivocation: the conflict was not reported");
    S_CHECK(tc->conflict_a->validator_index == 1 &&
            tc->conflict_b->validator_index == 1,
            "byzantine_equivocation: the wrong validator was reported");
    S_CHECK(tc->conflict_a->height == 1 && tc->conflict_b->height == 1 &&
            tc->conflict_a->round == 0 && tc->conflict_b->round == 0,
            "byzantine_equivocation: the reported votes are not the pair");
    S_CHECK(tc->conflict_a->block_id.hash_len !=
            tc->conflict_b->block_id.hash_len ||
            memcmp(tc->conflict_a->block_id.hash,
                   tc->conflict_b->block_id.hash,
                   tc->conflict_a->block_id.hash_len) != 0,
            "byzantine_equivocation: the two votes are not for two blocks");
    /* And the node itself is unharmed. */
    S_CHECK(tc->cs->rs.height == 1,
            "byzantine_equivocation: the equivocation moved the height");
    tc_release(tc);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * mempool_test.go
 * ════════════════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/mempool_test.go:28-49 —
 * `TestMempoolNoProgressUntilTxsAvailable`, REDUCED.
 *
 * With `CreateEmptyBlocks` false, `enterNewRound` does not go on to
 * `enterPropose` (state.go:1106-1114) unless a proof block is needed, so
 * after the first height the chain stops until `txsAvailable` fires.
 *
 * ⚠ REDUCED IN TWO WAYS. There is no mempool: the signal is raised with
 * `cmt_cs_notify_txs_available`, which IS the port's spelling of the
 * reference's `<-cs.txNotifier.TxsAvailable()` (state.go:827) but skips
 * everything upstream of it. And the reference expects TWO further
 * blocks (:47-48, "commit txs" then "commit updated app hash"), because
 * its kvstore changes its AppHash and that makes `needProofBlock` true
 * for the block after; this fixture's application never changes its app
 * hash, so only ONE further block follows. Both differences are the
 * fixture's, and the fixture names them.
 */
static int s_mempool_no_progress_until_txs_available(void)
{
    tc_t *tc = tc_alloc(1u, 1, 0);

    S_CHECK(tc != NULL, "mempool_no_progress: setup");
    /* :31 — CreateEmptyBlocks = false. */
    tc->config.create_empty_blocks = false;
    S_CHECK(cmt_config_wait_for_txs(&tc->config),
            "mempool_no_progress: WaitForTxs should now be true");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :41 */
    /* :43 — the first block is committed anyway, because at the initial
     * height `needProofBlock` is true (state.go:1120-1122). */
    S_CHECK(tc->apply_calls == 1,
            "mempool_no_progress: the first block was not committed");

    S_STEP(tc_fire_timeout(tc));   /* the commit timeout → enterNewRound */
    S_STEP(tc_ensure_new_round(tc, 2, 0));
    /* :44 — and there it stops: no proposal, no second block, and — the
     * difference from the interval scenario below — NO timeout scheduled
     * to restart it, because CreateEmptyBlocksInterval is 0
     * (state.go:1107-1111). */
    S_STEP(tc_ensure_no_timeout_for(tc, 2, 0, CMT_ROUND_STEP_NEW_ROUND));
    S_CHECK(tc->cs->rs.step == CMT_ROUND_STEP_NEW_ROUND,
            "mempool_no_progress: left RoundStepNewRound without txs");
    S_CHECK(tc->cs->rs.proposal == NULL,
            "mempool_no_progress: proposed without txs");
    S_CHECK(tc->apply_calls == 1,
            "mempool_no_progress: committed a second block without txs");

    /* :45 — transactions arrive. */
    cmt_cs_notify_txs_available(tc->cs);
    S_STEP(tc_drain(tc));
    S_CHECK(tc->apply_calls == 2,
            "mempool_no_progress: the tx block was not committed"); /* :46 */
    S_STEP(tc_ensure_new_round(tc, 3, 0));
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/mempool_test.go:51-71 —
 * `TestMempoolProgressAfterCreateEmptyBlocksInterval`, REDUCED.
 *
 * With `CreateEmptyBlocksInterval` positive, `WaitForTxs` is true
 * (config.go:1054-1057) but `enterNewRound` schedules a
 * `RoundStepNewRound` timeout for that interval (state.go:1108-1111)
 * instead of proposing at once — so the chain advances on the interval
 * even with an empty mempool. The reference waits 200 ms of real time for
 * it; here the timer the state machine armed is inspected and then fired.
 */
static int s_mempool_progress_after_create_empty_blocks_interval(void)
{
    tc_t   *tc = tc_alloc(1u, 1, 0);
    int64_t interval = 200 * CMT_MILLISECOND;                    /* :55 */

    S_CHECK(tc != NULL, "mempool_interval: setup");
    tc->config.create_empty_blocks_interval = interval;
    S_CHECK(cmt_config_wait_for_txs(&tc->config),
            "mempool_interval: WaitForTxs should be true");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :64 */
    S_CHECK(tc->apply_calls == 1,
            "mempool_interval: the first block was not committed"); /* :66 */

    S_STEP(tc_fire_timeout(tc));   /* the commit timeout → enterNewRound */
    S_STEP(tc_ensure_new_round(tc, 2, 0));
    /* :67 — no block yet; instead the interval timeout is armed. */
    S_CHECK(tc->apply_calls == 1,
            "mempool_interval: committed before the interval elapsed");
    S_STEP(tc_ensure_new_timeout(tc, 2, 0, interval,
                                 CMT_ROUND_STEP_NEW_ROUND));
    /* :68 — once it elapses, the empty block is made. */
    S_STEP(tc_fire_timeout(tc));
    S_CHECK(tc->apply_calls == 2,
            "mempool_interval: no block after the interval elapsed");
    tc_release(tc);
    return 0;
}

/**
 * mempool_test.go:84-92 — the `cs.setProposal` the reference installs on
 * the State itself. cmt_cs.h:643-649 keeps that seam: `set_proposal` is
 * one of the three overridable functions `cmt_cs_init` defaults, and the
 * header says in as many words that a caller may replace it "which is
 * what the reference's own tests do".
 */
static int s_skip_proposal_at_h2r0(cmt_cs_t *cs, const cmt_proposal_t *p)
{
    if (cs->rs.height == 2 && cs->rs.round == 0) {               /* :85 */
        /* :86-89 — "dont set the proposal in round 0 so we timeout and
         * go to next round". */
        return CMT_OK;                                           /* :89 */
    }
    return cmt_cs_default_set_proposal(cs, p);                   /* :91 */
}

/**
 * cometbft@709fd12b consensus/mempool_test.go:73-108 —
 * `TestMempoolProgressInHigherRound`, REDUCED in the same one way as its
 * two siblings: `cmt_cs_notify_txs_available` stands in for a mempool.
 *
 * What it proves that nothing else here does: a height whose FIRST round
 * produces no proposal still commits, in a LATER round, driven only by
 * timeouts. The whole chain is
 *   proposal swallowed → timeoutPropose fires → enterPrevote → prevote
 *   nil → nil polka → enterPrecommit → precommit nil → +2/3 for NIL, so
 *   `cs_add_vote_precommit` takes cmt_cs.c:2351 (state.go:2351) and
 *   enters PRECOMMIT_WAIT — it does NOT bump the round — → timeoutPrecommit
 *   fires → enterNewRound(2,1) → propose again → commit.
 * TWO timeouts, not one; the second is the same nil-polka path
 * `s_finalize_block_called` walks at four validators.
 *
 * ⚠ THE ROUND-1 ASSERTION IS INDIRECT. The reference watches the NewRound
 * event go past (:106) and then waits for the block (:107); a drain runs
 * to quiescence, so by the time control returns the chain is already at
 * height 3. What is asserted instead is this node's OWN precommits, read
 * off the WAL: a nil one in round 0 and one in round 1. Neither exists
 * unless that round really happened.
 */
static int s_mempool_progress_in_higher_round(void)
{
    tc_t *tc = tc_alloc(1u, 1, 0);

    S_CHECK(tc != NULL, "mempool_higher_round: setup");
    tc->config.create_empty_blocks = false;                      /* :76 */
    tc->cs->set_proposal           = s_skip_proposal_at_h2r0;    /* :84 */

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :93 */
    S_CHECK(tc->apply_calls == 1,
            "mempool_higher_round: the first block was not committed");
                                                                 /* :96 */
    S_STEP(tc_fire_timeout(tc));   /* the commit timeout → enterNewRound */
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :101 */

    /* :102 — the txs arrive, so this node proposes; its own proposal is
     * then swallowed by the override, so the round cannot complete. */
    cmt_cs_notify_txs_available(tc->cs);
    S_STEP(tc_drain(tc));
    S_CHECK(tc->cs->rs.proposal == NULL,
            "mempool_higher_round: the proposal was not ignored");
    S_CHECK(tc->apply_calls == 1,
            "mempool_higher_round: committed a proposal it never set");
    /* :103 — and so the propose timeout is what is left armed. */
    S_STEP(tc_ensure_new_timeout(tc, 2, 0,
                                 cmt_config_propose(&tc->config, 0),
                                 CMT_ROUND_STEP_PROPOSE));

    /* The propose timeout. It ends at PRECOMMIT_WAIT, NOT at round 1:
     * this node prevotes nil, its own nil polka makes it precommit nil,
     * and a +2/3 majority for NIL enters precommit-wait (cmt_cs.c:2351).
     * The reference never has to say so because it waits on events. */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_timeout(tc, 2, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));
    S_CHECK(tc->apply_calls == 1,
            "mempool_higher_round: committed without a proposal");

    /* :105-107 — and THAT timeout is what starts round 1, where the
     * override delegates and the block is committed. */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 2, 0, S_PRECOMMIT));   /* the nil one   */
    S_STEP(tc_ensure_vote(tc, 2, 1, S_PRECOMMIT));   /* the block one */
    S_CHECK(tc->apply_calls == 2,
            "mempool_higher_round: no block in the higher round");/* :107 */
    tc_release(tc);
    return 0;
}

/* ══ the runner ═══════════════════════════════════════════════════════ */

typedef struct {
    const char *name;
    int       (*fn)(void);
} s_case_t;

int main(void)
{
    static const s_case_t cases[] = {
        { "proposer_selection0",              s_proposer_selection0 },
        { "proposer_selection2",              s_proposer_selection2 },
        { "enter_propose_no_priv_validator",
          s_enter_propose_no_priv_validator },
        { "enter_propose_yes_priv_validator",
          s_enter_propose_yes_priv_validator },
        { "bad_proposal",                     s_bad_proposal },
        { "oversized_block",                  s_oversized_block },
        { "full_round1",                      s_full_round1 },
        { "full_round_nil",                   s_full_round_nil },
        { "full_round2",                      s_full_round2 },
        { "lock_no_pol",                      s_lock_no_pol },
        { "lock_pol_relock",                  s_lock_pol_relock },
        { "lock_pol_unlock",                  s_lock_pol_unlock },
        { "set_valid_block_on_delayed_prevote",
          s_set_valid_block_on_delayed_prevote },
        { "process_proposal_accept",          s_process_proposal_accept },
        { "extend_vote_called_when_enabled",
          s_extend_vote_called_when_enabled },
        { "finalize_block_called",            s_finalize_block_called },
        { "vote_extension_enable_height",     s_vote_extension_enable_height },
        { "doesnt_crash_on_invalid_vote",     s_doesnt_crash_on_invalid_vote },
        { "waiting_timeout_on_nil_polka",     s_waiting_timeout_on_nil_polka },
        { "waiting_timeout_propose_on_new_round",
          s_waiting_timeout_propose_on_new_round },
        { "round_skip_on_nil_polka_from_higher_round",
          s_round_skip_on_nil_polka_from_higher_round },
        { "wait_timeout_propose_on_nil_polka_for_the_current_round",
          s_wait_timeout_propose_on_nil_polka_current_round },
        { "emit_new_valid_block_on_commit_without_block",
          s_emit_new_valid_block_on_commit_without_block },
        { "commit_from_previous_round",       s_commit_from_previous_round },
        { "sign_same_vote_twice",             s_sign_same_vote_twice },
        { "byzantine_prevote_equivocation",
          s_byzantine_prevote_equivocation },
        { "mempool_no_progress_until_txs_available",
          s_mempool_no_progress_until_txs_available },
        { "mempool_progress_after_create_empty_blocks_interval",
          s_mempool_progress_after_create_empty_blocks_interval },
        { "mempool_progress_in_higher_round",
          s_mempool_progress_in_higher_round }
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
    printf("test_cmt_cs: %zu/%zu scenarios, %d checks\n",
           n - failed, n, g_tc_checks);
    return (failed == 0u) ? 0 : 1;
}
