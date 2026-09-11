/**
 * Nodus — cometbft @709fd12b C port, waves R2-T and R2-T2: the SCENARIO
 * SUITE for `shared/dnac/cmt_cs.c`, ported from `consensus/state_test.go`,
 * `consensus/byzantine_test.go` and `consensus/mempool_test.go`. R2-T
 * wrote the fixture and 29 scenarios; R2-T2 added the ten state_test.go
 * scenarios R2-T had left as "drivable, not done" and the last two rounds
 * of `TestStateLockNoPOL`, so that every live `func Test` in
 * state_test.go that a single-node fixture can drive is here — the four
 * that remain are listed at the bottom with the reason each cannot be.
 *
 * Every scenario names the Go `func Test…` it comes from and its line.
 * The fixture — the application, the signer, the block store, the WAL,
 * the clock and the timer — is `test_cmt_common.h`, which is the C
 * stand-in for `consensus/common_test.go` and carries its own four
 * header items. READ THAT FILE'S "HOW IT CAN LIE" TOO: twelve of the
 * twenty-three ways this suite can be wrong are properties of the fixture,
 * not of the scenarios. (Wave R2-T's version of this sentence said "ten of
 * the sixteen" while listing items 11-18; the numbers here were counted.)
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
 *   · (R2-T2) THE LOCK SURVIVES A POLKA FROM BELOW IT. A polka whose
 *     round is lower than LockedRound moves nothing — not the lock, not
 *     the step, not the Valid* names (:2263-2266, :2281; `s_lock_pol_
 *     safety1`, `s_lock_pol_safety2`) — while a polka from the current
 *     round for a block this node has never seen DOES unlock it and sets
 *     it up to fetch that block (:1542-1560, :2295-2300; `s_lock_pol_
 *     unlock_on_unknown_block`, `s_set_valid_block_on_delayed_proposal`).
 *   · (R2-T2) THE VALIDBLOCK IS WHAT GETS RE-PROPOSED. Unlocked by a nil
 *     polka and skipped two rounds ahead, the node's next proposal is its
 *     ValidBlock with POLRound = ValidRound (:1209-1211, :1238;
 *     `s_propose_valid_block`), and the same rule makes round 2 of
 *     `s_lock_no_pol` re-propose the locked block.
 *   · (R2-T2) VOTE EXTENSIONS SURVIVE THE HEIGHT BOUNDARY. Four distinct
 *     extensions precommitted at height 1 reach the proposer of height 2
 *     inside `createProposalBlock`'s ExtendedCommit (:1292-1294, :1308),
 *     in validator-index order, with extension signatures that verify
 *     under each validator's key over the CanonicalVoteExtension of height
 *     1 (`s_prepare_proposal_receives_vote_extensions`). And
 *     `VerifyVoteExtension` is called for exactly the validators whose
 *     precommits arrived (`s_verify_vote_extension_not_called_on_absent_
 *     precommit`).
 *   · (R2-T2) A LATE PRECOMMIT FROM A PAST ROUND COMMITS, AND THE NEW
 *     HEIGHT STARTS CLEAN. +2/3 precommits completed one round late commit
 *     the locked block (:2339-2346; `s_halt1`, `s_start_next_height_
 *     correctly_after_timeout`), and `TriggeredTimeoutPrecommit` is false
 *     at the next height whether or not the old one raised it (:750,
 *     :1098; both, and `s_reset_timeout_precommit_upon_new_height`).
 *   · (R2-T2) A FOUR-SIGNER BLOCK TIME. One scenario proposes and
 *     validates a height-2 block whose time is the weighted median of four
 *     DIFFERENT precommit timestamps (state/validation.go:120-140; see
 *     item 16 for what that does and does not prove).
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
 * between scenarios. The cost is ML-DSA-87: wave R2-T estimated roughly
 * 300 signatures and as many verifications for its 29 scenarios; the ten
 * R2-T2 added are four-validator, multi-round scenarios and add on the
 * order of half that again. Both numbers are estimates from reading the
 * scenarios, not counts from a run.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no environment
 * variables, no shared state between scenarios: each builds its own
 * fixture and tears it down, including on the failure path.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 * The fixture's twelve ways are in test_cmt_common.h. These eleven are the
 * scenarios' own:
 *  11. SIX SCENARIOS ARE PARTIAL PORTS AND SAY SO IN THEIR OWN COMMENT.
 *      `s_extend_vote_called_when_enabled` and `s_verify_vote_extension_
 *      not_called_on_absent_precommit` do not assert the CONTENT of the
 *      ExtendVote request (the port has no request object to inspect);
 *      `s_byzantine_prevote_equivocation` is one node, not four behind a
 *      partition; the three mempool scenarios drive `txs_available` by
 *      hand instead of through a mempool. A partial port proves the part
 *      it ports and NOTHING about the rest. (`s_lock_no_pol` was on this
 *      list at two of four rounds; R2-T2 ported the other two.) Several
 *      more port every case of their Go test but RE-EXPRESS one assertion
 *      each, because the reference makes it about an event, and give the
 *      reason at the site: `s_vote_extension_enable_height` and
 *      `s_mempool_progress_in_higher_round` (R2-T); `s_set_valid_block_on_
 *      delayed_proposal` (an `ensureNewProposal` whose proposal the
 *      reference itself drops as out-of-round), `s_lock_pol_safety1`
 *      (`ensureNoNewRoundStep` as an unchanged step triple),
 *      `s_lock_pol_safety2` and `s_propose_valid_block` (`ensureNoNewUnlock`
 *      / `ensureNewUnlock` as the lock fields) and `s_start_next_height_
 *      correctly_after_timeout` (item 19) (R2-T2).
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
 *      nothing happened; it is stated as such at the site. Two R2-T2
 *      scenarios have a "nothing happened" as their LAST step —
 *      `s_lock_pol_safety1` (no unlock, no step on an old polka) and
 *      `s_lock_pol_safety2` (no unlock on an old polka) — and both guard
 *      it the same way: they assert the old polka's votes ARE in the vote
 *      set, so a dropped delivery cannot pass as "nothing moved", and
 *      Safety2 additionally asserts the prevote that the polka's arrival
 *      is what triggered (state.go:2323-2326).
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
 *  16. THE FOUR-SIGNER BLOCK-TIME RULE IS EXERCISED ONCE, WITH ONE SPREAD
 *      OF TIMESTAMPS. `tc_validate_block` performs state/validation.go:
 *      120-140 in full — `block.Time > state.LastBlockTime` and
 *      `block.Time == MedianTime(LastCommit, LastValidators)` — but only a
 *      scenario that VALIDATES a block at height ≥ 2 reaches the
 *      non-initial branch. Wave R2-T's three single-validator mempool
 *      scenarios do, with a median that is this node's own `voteTime`
 *      stamp (state.go:2417-2429, `blockTime + 1 ms`), strictly increasing
 *      by construction. R2-T2's `s_reset_timeout_precommit_upon_new_height`
 *      is the first to do it with FOUR signers, and to do it at all it
 *      had to move the fixture's frozen clock: with every stub stamping
 *      the genesis instant, the height-2 median EQUALS block 1's time and
 *      state/validation.go:116-120 ("not greater than last block time")
 *      refuses the block. So that scenario advances `tc->now` by one
 *      second between this node's precommit and the stubs', making the
 *      commit's timestamps {+1 ms, +1 s, +1 s, +1 s}, and asserts block 2
 *      is valid and prevoted. What that proves: the median of one
 *      particular four-value spread with one NIL-flag signature counted
 *      (state/state.go's MedianTime skips ABSENT only), computed by
 *      `cmt_state_make_block` and recomputed by `tc_validate_block`
 *      through the SAME `cmt_state_median_time`. What it does not: the
 *      arithmetic against an independent oracle, other spreads, unequal
 *      powers, or an ABSENT entry — the fixture's stubs always vote.
 *      Every other four-validator scenario that reaches height 2 stops
 *      before a block is validated there.
 *  17. THE HEIGHT-BOUNDARY CHECK OF VOTE EXTENSIONS IS ONE SCENARIO, AND
 *      IT READS A FIXTURE CAPTURE. R2-T's fixture passed the extended
 *      commit through `cmt_extended_commit_to_commit`, which DROPS the
 *      extensions, and nothing looked at them; R2-T2's
 *      `tc_create_proposal_block` now COPIES the `last_ext_commit` it is
 *      handed (`cap_ext*`, fixture item 12) and `s_prepare_proposal_
 *      receives_vote_extensions` asserts on the copy: four entries in
 *      validator-index order, each with ITS OWN validator's extension
 *      bytes, a non-empty extension signature, and that signature
 *      verifying under that validator's key over the canonical extension
 *      of height 1 round 0 — state_test.go:1727-1744 in full. Two limits
 *      stand. The capture is instrumentation this fixture added, not the
 *      reference's `PrepareProposal` request: the port has no ABCI request
 *      object, so what the block executor would put into
 *      `LocalLastCommit` is asserted at the boundary where it would be
 *      built (state/execution.go:127-129), not inside it. And the block
 *      the proposal carries is still built from the DROPPED-extension
 *      commit, as the reference's is (:127 `ToCommit()`), so the scenario
 *      says nothing about extensions in blocks — the reference does not
 *      either.
 *  18. `TC_PAYLOAD_CAP` IS DELIBERATELY UNDER-PROVISIONED
 *      (test_cmt_common.h's slot storage), so the MaxBytes refusal INSIDE
 *      the part-assembly path (cmt_cs.c's payload-buffer overrun REJECT)
 *      is never the check that fires; the earlier ByteSize refusal is.
 *  19. ONE SCENARIO WALKS A PATH THE REFERENCE'S OWN RUN DOES NOT, BECAUSE
 *      OF FIXTURE ITEM 2. `s_start_next_height_correctly_after_timeout`
 *      pokes the tx notifier while the node waits out timeoutCommit
 *      (state_test.go:2241). `handleTxsAvailable` then asks
 *      `needProofBlock(2)` (state.go:1027; the function is :1117-1132):
 *      FALSE here, where the app hash never changes, so :1033-1034 re-arm
 *      the commit wait as a `(2, 0, NewRound)` timeout that goes straight
 *      to `enterPropose` without `enterNewRound` (:985-986). Which arm the
 *      REFERENCE'S own run takes depends on whether its test application
 *      changes the app hash at height 1; that application is outside the
 *      pinned set and was not read, so nothing is claimed about it — only
 *      that both arms arm the same propose timeout. The scenario asserts
 *      the re-armed timer explicitly, labelled as the fixture's path, then
 *      fires it and makes the reference's assertions. Both paths arm the
 *      propose timeout and both leave `TriggeredTimeoutPrecommit` false,
 *      so the reference's checks hold — but the NewHeight → NewRound →
 *      Propose route the reference takes there is exercised by the OTHER
 *      height-2 scenarios, not this one.
 *  20. ONE SCENARIO PROVES MORE THAN THE REFERENCE, ON PURPOSE, AND SAYS
 *      WHERE. In `s_lock_pol_safety2` the round-0 and round-1 blocks
 *      differ (the fixture stamps the signer as proposer); in the
 *      reference both come from cs1 and are, by reading, the SAME block.
 *      What the difference buys is ONE assertion: at :1209 the reference
 *      cannot tell "prevoted the locked block" from "prevoted the proposal"
 *      when the two are the same bytes, and this suite can. It does NOT
 *      reach the hash half of state.go:2263-2266 — that `&&` chain
 *      short-circuits at `LockedRound (1) < vote.Round (0)` in Go and in
 *      cmt_cs.c alike, so the polka's block is never compared; the lock is
 *      kept by the round test in both. (R2-T2's first wording implied the
 *      hash test ran here; verifier T2 corrected it.) The stub-vote
 *      assertions R2-T2 added to `s_lock_no_pol`'s rounds 0-1 are NOT an
 *      addition of this kind: that test's unfiltered `voteCh`
 *      (state_test.go:467) makes its `ensureVote` calls after a
 *      `signAddVotes` mean the STUB's vote, so they are the reference's
 *      own assertions, which R2-T had left out. Both are marked at the
 *      site; neither weakens a reference assertion.
 *  21. THE FIXTURE'S OWN PROPOSAL HELPERS SHARE ONE PART BUFFER (fixture
 *      item 11). Two R2-T2 scenarios build a second stub block while a
 *      part set assembled from the first is still named by the round
 *      state (`s_lock_pol_unlock_on_unknown_block`, `s_lock_pol_safety2`);
 *      both were walked by reading to confirm those bytes are never read
 *      again. A future scenario that RE-PROPOSES a fixture-made valid
 *      block after a second fixture block would fail for the fixture's
 *      reason, not the port's.
 *
 * ── THE FIFTEEN TESTS THAT WERE NOT PORTED BY WAVE R2-T ────────────────
 * Written here and not only in the wave's report, because a prerequisite
 * that lives in the author's head is a trap for whoever picks this up.
 * The count, kept honest: R2-T left fifteen entries — four BLOCKED, ten
 * DRIVABLE, and rounds 2-3 of one ported test. Since then:
 *   · the byzantine partition test below was ported by wave R2-BYZ as
 *     `test_cmt_byzantine.c` on the multi-node driver
 *     `test_cmt_multinode.h`, exactly the shape described under it. Its
 *     entry is kept as written, because the reasoning is what made that
 *     driver's design;
 *   · the ten DRIVABLE tests and the two missing rounds were ported by
 *     wave R2-T2, into this file. Each is named below with its scenario.
 * FOUR remain, all BLOCKED, and the reasons are unchanged.
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
 * DRIVABLE WITH THIS FIXTURE — R2-T named these as budget, not
 * impossibility; R2-T2 ported every one. Go test → scenario:
 *   · `TestPrepareProposalReceivesVoteExtensions` (state_test.go:1654) →
 *     `s_prepare_proposal_receives_vote_extensions`. R2-T's diagnosis
 *     stands as the record of what it took: per-stub DISTINCT extension
 *     bytes (`tc_ext_bytes_of`, static storage), the stub METHOD signer
 *     exposed as `tc_stub_sign_vote` so `signAddPrecommitWithExtension`
 *     could bypass the free function's rule, a configurable `ExtendVote`
 *     answer, and a capture of `create_proposal_block`'s `last_ext_commit`
 *     taken inside the callback (item 17, fixture item 12).
 *   · `TestStateLockPOLUnlockOnUnknownBlock` (:858) →
 *     `s_lock_pol_unlock_on_unknown_block`;
 *     `TestStateLockPOLSafety1` (:990) → `s_lock_pol_safety1`;
 *     `TestStateLockPOLSafety2` (:1116) → `s_lock_pol_safety2`;
 *     `TestProposeValidBlock` (:1217) → `s_propose_valid_block`;
 *     `TestSetValidBlockOnDelayedProposal` (:1372) →
 *     `s_set_valid_block_on_delayed_proposal`;
 *     `TestVerifyVoteExtensionNotCalledOnAbsentPrecommit` (:1582) →
 *     `s_verify_vote_extension_not_called_on_absent_precommit`;
 *     `TestStartNextHeightCorrectlyAfterTimeout` (:2190) →
 *     `s_start_next_height_correctly_after_timeout`;
 *     `TestResetTimeoutPrecommitUponNewHeight` (:2251) →
 *     `s_reset_timeout_precommit_upon_new_height`;
 *     `TestStateHalt1` (:2397) → `s_halt1` — which, read in full, calls
 *     neither Start nor Stop: "Halt" is its suite's name, and the test is
 *     about a late precommit committing from a past round.
 *   · Rounds 2 and 3 of `TestStateLockNoPOL` (:558-654) → `s_lock_no_pol`,
 *     now the whole test.
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
 *   consensus/ticker.go          143 lines   (R2-T2: :107-127, the rule
 *     f08d7195f0a6ba820243d0e6aed9499f1cc334984a665d5d0bd6da394de1b26c
 *     by which a later-step tick replaces an armed timer — item 19)
 * Opened by wave R2-T and reported in its wave report. THREE of the five
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
 * `TestStateLockNoPOL`, all four of its rounds. Rounds 0-1 are wave
 * R2-T's; rounds 2-3 (:558-654) were added by R2-T2.
 *
 * Two validators. This node locks on its own proposal at round 0; the
 * other validator precommits a DIFFERENT (non-existent) block so nothing
 * commits, and every round after that repeats the same two rules from a
 * different angle:
 *   · round 1 — no proposal at all; we prevote THE BLOCK WE ARE LOCKED ON
 *     (state.go:1349-1353); a conflicting prevote leaves no polka, so we
 *     precommit nil WHILE STAYING LOCKED at round 0 (:1465-1474);
 *   · round 2 — WE are the proposer again and propose our ValidBlock,
 *     which is the locked block (:1209-1211; asserted at :571-576); the
 *     same conflicting votes, the same nil precommit, the same lock;
 *   · round 3 — the OTHER validator proposes a third block, built by a
 *     SECOND consensus state in the reference (:604 `cs2, _ :=
 *     randState(2)`); we still prevote the locked block, not the proposal
 *     (:631), and precommit nil still locked at round 0 (:642).
 *
 * ⚠ THIS TEST'S `voteCh` IS UNFILTERED (:467, `subscribeUnBuffered(…,
 * EventQueryVote)`), unlike every other test here, which subscribes to
 * its own address. So half of its `ensurePrevote`/`ensurePrecommit` calls
 * — the ones right after a `signAddVotes(…, vs2)` — assert that VS2'S vote
 * was added, not ours. Those are `tc_ensure_stub_vote` below; wave R2-T's
 * rounds 0-1 had left them out and R2-T2 added them there too.
 *
 * ⚠ THE ROUND-3 BLOCK differs from the locked block here for a different
 * reason than in the reference. There it comes from `cs2, _ :=
 * randState(2)` (:604) — a SECOND consensus state over a FRESH genesis:
 * `randGenesisDoc` (common_test.go:878-902) draws new random validators
 * and stamps its own `GenesisTime`, so cs2's block differs from cs1's in
 * proposer address, ValidatorsHash and time at once, and the test's own
 * comment says the block exists only to be different ("needed so
 * generated block is different than locked block"). Here the fixture has
 * one genesis and one validator set; `tc_decide_proposal_from` builds the
 * block from THIS node's state and stamps the SIGNER (vs2) as proposer,
 * which is the one field that makes it differ from the locked block. Its
 * POL round is −1 in both: cs2 is fresh (state.go:740), and −1 is passed
 * explicitly. (Wave R2-T2's first version of this paragraph said cs2's
 * privValidator was vs2; verifier T2 read :604 and it is not.)
 *
 * NOT ported: nothing. The reference's `cs1.startRoutines(0)` at :477 is
 * `tc_drain`, as everywhere in this suite.
 */
static int s_lock_no_pol(void)
{
    tc_t                 *tc = tc_alloc(2u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    uint8_t               other[CMT_TMHASH_SIZE];
    uint8_t               hash2[CMT_TMHASH_SIZE];
    uint8_t               hash3[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t psh2;
    cmt_part_set_header_t psh3;
    cmt_block_t          *block3 = NULL;
    cmt_part_set_t       *parts3 = NULL;

    S_CHECK(tc != NULL, "lock_no_pol: setup");

    /* ── Round 0 (:471-507): "Round1 (cs1, B) // B B // B B2" ────────── */
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
    S_STEP(tc_ensure_stub_vote(tc, 1u, 0, S_PREVOTE));           /* :491 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :493 */
    S_STEP(tc_validate_precommit(tc, 0, 0, hash, sizeof(hash),
                                 hash, sizeof(hash)));           /* :495 */

    /* :499-501 — a precommit for a block that is not ours. */
    memcpy(other, hash, sizeof(other));
    other[0] = (uint8_t)((other[0] + 1u) % 255u);
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, other, sizeof(other),
                                &psh, true));                    /* :502 */
    S_STEP(tc_ensure_stub_vote(tc, 1u, 0, S_PRECOMMIT));         /* :503 */
    /* :507 — two conflicting precommits are +2/3 of anything and no
     * majority, so the node waits out the precommit timeout. */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));
    S_CHECK(tc->apply_calls == 0,
            "lock_no_pol: committed on conflicting precommits");

    /* ── Round 1 (:511-556): "Round2 (cs1, B) // B B2" ───────────────── */
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

    /* :533-536 — `rs.LockedBlock.MakePartSet(partSize)`: the locked
     * block's header, which is `psh`. */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, other, sizeof(other),
                                &psh, false));                   /* :536 */
    S_STEP(tc_ensure_stub_vote(tc, 1u, 1, S_PREVOTE));           /* :537 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_prevote(&tc->config, 1),
                                 CMT_ROUND_STEP_PREVOTE_WAIT)); /* :541 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :543 */
    /* :546 — precommit nil, still locked on the round-0 block. */
    S_STEP(tc_validate_precommit(tc, 1, 0, NULL, 0u,
                                 hash, sizeof(hash)));

    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, other, sizeof(other),
                                &psh, true));                    /* :551 */
    S_STEP(tc_ensure_stub_vote(tc, 1u, 1, S_PRECOMMIT));         /* :552 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_precommit(&tc->config, 1),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT)); /* :556 */

    /* ── Round 2 (:558-602): "Round3 (vs2, _) // B, B2" ──────────────── */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 2));                       /* :559 */
    tc_increment_round(tc, 1u, 2u);                              /* :565 */

    /* :567 — we are the proposer again (h−1+r = 2 ≡ 0 mod 2), and the
     * drain that followed the timeout has already run our proposal
     * through the internal queue. */
    S_STEP(tc_ensure_new_proposal(tc, 1, 2));
    /* :571-576 — "Expected proposal block to be locked block": with a
     * ValidBlock set by round 0's polka, `defaultDecideProposal` proposes
     * IT (state.go:1209-1211), and ValidBlock is the block we locked. */
    S_STEP(tc_proposal_block_hash(tc, hash2));
    S_CHECK(memcmp(hash2, hash, sizeof(hash)) == 0,
            "lock_no_pol: the round-2 proposal is not the locked block");
    S_STEP(tc_ensure_vote(tc, 1, 2, S_PREVOTE));                 /* :578 */
    S_STEP(tc_validate_prevote(tc, 2, hash, sizeof(hash)));      /* :579 */

    /* :581-583 — `bps0 := rs.ProposalBlock.MakePartSet(partSize)`: the
     * proposal block IS the locked block, so its header is `psh` again;
     * asserted rather than assumed, through the round state's own part set
     * (item 11 of the fixture: same block, same parts). */
    S_STEP(tc_proposal_parts_header(tc, &psh2));
    S_CHECK(cmt_psh_equals(&psh2, &psh),
            "lock_no_pol: the round-2 part-set header differs from round 0");
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, other, sizeof(other),
                                &psh2, false));                  /* :583 */
    S_STEP(tc_ensure_stub_vote(tc, 1u, 2, S_PREVOTE));           /* :584 */

    S_STEP(tc_ensure_new_timeout(tc, 1, 2,
                                 cmt_config_prevote(&tc->config, 2),
                                 CMT_ROUND_STEP_PREVOTE_WAIT)); /* :586 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 2, S_PRECOMMIT));               /* :587 */
    /* :589 — precommit nil but be locked on proposal. */
    S_STEP(tc_validate_precommit(tc, 2, 0, NULL, 0u,
                                 hash, sizeof(hash)));

    /* :591-599 — "NOTE: conflicting precommits at same height". */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, other, sizeof(other),
                                &psh2, true));
    S_STEP(tc_ensure_stub_vote(tc, 1u, 2, S_PRECOMMIT));         /* :600 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 2,
                                 cmt_config_precommit(&tc->config, 2),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT)); /* :602 */

    /* :604-609 — "needed so generated block is different than locked
     * block": a block from a second State, proposed by vs2 for round 3
     * (`vs2.Round+1`, vs2 being at round 2). POL round −1: see the header. */
    S_STEP(tc_decide_proposal_from(tc, 1u, 1, 3, -1, tc->prop,
                                   &block3, &parts3));
    S_CHECK(cmt_block_hash(block3, hash3) == CMT_OK,
            "lock_no_pol: hashing the round-3 block");
    S_CHECK(cmt_part_set_header(parts3, &psh3) == CMT_OK,
            "lock_no_pol: the round-3 part set header");
    S_CHECK(memcmp(hash3, hash, sizeof(hash)) != 0,
            "lock_no_pol: the round-3 block must differ from the locked one");

    tc_increment_round(tc, 1u, 2u);                              /* :611 */

    /* ── Round 3 (:613-654): "Round4 (vs2, C) // B C // B C" ─────────── */
    S_STEP(tc_fire_timeout(tc));                        /* :602's timeout */
    S_STEP(tc_ensure_new_round(tc, 1, 3));                       /* :614 */

    /* :620-626 — not the proposer this round, so the proposal is fed in;
     * `bps3` is `parts3`, the same part set the block was split into. */
    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts3));
    S_STEP(tc_drain(tc));
    S_STEP(tc_ensure_new_proposal(tc, 1, 3));                    /* :628 */
    S_STEP(tc_ensure_vote(tc, 1, 3, S_PREVOTE));                 /* :629 */
    /* :630-631 — "prevote for locked block (not proposal)". The reference
     * hard-codes the round as 3 here; it is the same round. */
    S_STEP(tc_validate_prevote(tc, 3, hash, sizeof(hash)));

    /* :633-637 — vs2 prevotes the block it proposed. `bps4` is parts3's
     * header once more. */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PREVOTE, hash3, sizeof(hash3),
                                &psh3, false));
    S_STEP(tc_ensure_stub_vote(tc, 1u, 3, S_PREVOTE));           /* :638 */

    S_STEP(tc_ensure_new_timeout(tc, 1, 3,
                                 cmt_config_prevote(&tc->config, 3),
                                 CMT_ROUND_STEP_PREVOTE_WAIT)); /* :640 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 3, S_PRECOMMIT));               /* :641 */
    /* :642 — precommit nil but locked on proposal — still the ROUND-0 lock,
     * after a third round of conflicting votes. */
    S_STEP(tc_validate_precommit(tc, 3, 0, NULL, 0u,
                                 hash, sizeof(hash)));

    /* :644-652 — "NOTE: conflicting precommits at same height". */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, hash3, sizeof(hash3),
                                &psh3, true));
    S_STEP(tc_ensure_stub_vote(tc, 1u, 3, S_PRECOMMIT));         /* :653 */
    /* The reference ends at :654 with that vote added. Its consequence —
     * asserted here because it is the observable the two conflicting
     * precommits produce, NOT an assertion the reference makes — is
     * another precommit wait, and no commit in four rounds. */
    S_STEP(tc_ensure_new_timeout(tc, 1, 3,
                                 cmt_config_precommit(&tc->config, 3),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));
    S_CHECK(tc->apply_calls == 0,
            "lock_no_pol: something was committed across four rounds");
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
 * cometbft@709fd12b consensus/state_test.go:858-984 —
 * `TestStateLockPOLUnlockOnUnknownBlock`.
 *
 * Four validators, three rounds. Round 0: we lock on our own block A; the
 * others precommit nil. Round 1: we miss the proposal for B and prevote
 * our locked A (:929-931); the others polka B — a block we do NOT have —
 * which UNLOCKS us through state.go:2263-2277 and leaves ProposalBlock
 * nil with a part set built from the polka's header (:2295-2300); with no
 * proposal and a polka for a block we lack, `enterPrecommit` takes
 * :1542-1560 and we precommit nil with LockedRound −1 (:938). B then
 * arrives late (:940) and becomes the ValidBlock (:2045-2047). Round 2:
 * vs3 proposes C; unlocked, we prevote it (:977), the others polka it,
 * and we lock on C (:983).
 *
 * The blocks for rounds 1 and 2 come from SECOND and THIRD States in the
 * reference (:902 `newState(cs1.state, vs2, …)`, :948 `newState(…, vs3,
 * …)`), each with a fresh ValidRound of −1; `tc_decide_proposal_from` is
 * given −1 and the signer's address, which is what those States' own
 * `createProposalBlock` would have stamped. :911 and :956 assert the
 * three blocks are pairwise different; so does this.
 *
 * Every `ensurePrevote`/`ensurePrecommit` here is on `subscribeToVoter`
 * (:873), so it is THIS node's vote. The two that follow a `signAddVotes`
 * at :930 and :936 are reached only after a timeout the reference lets
 * expire (40 ms and 10 ms in its test config): the propose timeout at
 * round 1 (we have no proposal) and the prevote-wait timeout (a polka for
 * a block we do not have does not complete the proposal, state.go:2317).
 * Both are fired by hand, as everywhere in this suite.
 */
static int s_lock_pol_unlock_on_unknown_block(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               first[CMT_TMHASH_SIZE];
    uint8_t               second[CMT_TMHASH_SIZE];
    uint8_t               third[CMT_TMHASH_SIZE];
    cmt_part_set_header_t first_psh;
    cmt_part_set_header_t second_psh;
    cmt_part_set_header_t third_psh;
    cmt_part_set_header_t zero;
    cmt_block_t          *block = NULL;
    cmt_part_set_t       *parts = NULL;

    S_CHECK(tc != NULL, "unlock_on_unknown_block: setup");
    tc_zero_psh(&zero);

    /* ── Round 0 (:877-899): "Round0 (cs1, A) // A A A A // A nil nil nil" */
    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :882 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :884 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :885 */
    S_STEP(tc_proposal_block_hash(tc, first));                   /* :887 */
    S_STEP(tc_proposal_parts_header(tc, &first_psh));            /* :888 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :890 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, first, sizeof(first),
                                   &first_psh, false, 1u, 4u));  /* :892 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :894 */
    S_STEP(tc_validate_precommit(tc, 0, 0, first, sizeof(first),
                                 first, sizeof(first)));         /* :896 */

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                   true, 1u, 4u));               /* :899 */
    S_CHECK(tc->apply_calls == 0,
            "unlock_on_unknown_block: committed on nil precommits");

    /* :901-911 — the round-1 block, from a second State (ValidRound −1),
     * proposed by vs2 for `vs2.Round+1` = 1. */
    S_STEP(tc_decide_proposal_from(tc, 1u, 1, 1, -1, tc->prop,
                                   &block, &parts));
    S_CHECK(cmt_block_hash(block, second) == CMT_OK,
            "unlock_on_unknown_block: hashing the second block");
    S_CHECK(cmt_part_set_header(parts, &second_psh) == CMT_OK,
            "unlock_on_unknown_block: the second part set header");
    S_CHECK(memcmp(second, first, sizeof(first)) != 0,
            "unlock_on_unknown_block: second == first");         /* :911 */

    tc_increment_round(tc, 1u, 4u);                              /* :913 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT)); /* :916 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :920 */

    /* ── Round 1 (:923-961): "Round1 (vs2, B) // A B B B // nil nil nil nil" */
    /* :927-931 — "v1 misses the proposal": nothing is fed in, the propose
     * timeout expires, and we prevote the LOCKED block. */
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_propose(&tc->config, 1),
                                 CMT_ROUND_STEP_PROPOSE));
    S_CHECK(tc->cs->rs.proposal == NULL && tc->cs->rs.proposal_block == NULL,
            "unlock_on_unknown_block: a proposal we never received");
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :930 */
    S_STEP(tc_validate_prevote(tc, 1, first, sizeof(first)));    /* :931 */

    /* :934 — a polka for B, which we do not have. state.go:2263-2266
     * unlocks (LockedRound 0 < 1 ≤ 1, and A is not B); :2295 clears
     * ProposalBlock; :2298-2300 builds ProposalBlockParts from B's header.
     * The proposal is not complete, so :2319-2320 enters prevote-wait. */
    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, second, sizeof(second),
                                   &second_psh, false, 1u, 4u));
    S_CHECK(tc->cs->rs.locked_block == NULL && tc->cs->rs.locked_round == -1,
            "unlock_on_unknown_block: the polka for B did not unlock");
    S_CHECK(tc->cs->rs.proposal_block == NULL &&
            tc->cs->rs.proposal_block_parts != NULL &&
            cmt_part_set_has_header(tc->cs->rs.proposal_block_parts,
                                    &second_psh),
            "unlock_on_unknown_block: not set up to fetch B (:2298-2300)");
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_prevote(&tc->config, 1),
                                 CMT_ROUND_STEP_PREVOTE_WAIT));
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :936 */
    /* :937-938 — "we should have unlocked": precommit nil, locked on
     * nothing. (The reference's comment says "and locked on the new
     * block"; its assertion says −1/nil, and the assertion is ported.) */
    S_STEP(tc_validate_precommit(tc, 1, -1, NULL, 0u, NULL, 0u));

    /* :940 — B arrives late. Its parts complete the part set built at
     * :2299 and `handleCompleteProposal` makes B the ValidBlock
     * (:2037-2047); the step is already Precommit, so nothing else moves. */
    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts));
    S_STEP(tc_drain(tc));
    S_STEP(tc_ensure_new_proposal(tc, 1, 1));
    S_CHECK(tc->cs->rs.valid_round == 1 && tc->cs->rs.valid_block != NULL &&
            cmt_block_hashes_to(tc->cs->rs.valid_block, second,
                                sizeof(second)),
            "unlock_on_unknown_block: B did not become the ValidBlock");
    S_CHECK(tc->cs->rs.locked_block == NULL,
            "unlock_on_unknown_block: B's arrival re-locked");

    /* :944-945 — the others precommit nil; +2/3 any, no majority. */
    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                   true, 1u, 4u));
    S_CHECK(tc->apply_calls == 0,
            "unlock_on_unknown_block: committed at round 1");

    /* :947-956 — the round-2 block, from a third State, proposed by vs3
     * for `vs3.Round+1` = 2. THIS overwrites the fixture's part buffer
     * that B's assembled part set still points into (fixture item 11);
     * B is never re-proposed, so nothing reads those bytes again. */
    S_STEP(tc_decide_proposal_from(tc, 2u, 1, 2, -1, tc->prop,
                                   &block, &parts));
    S_CHECK(cmt_block_hash(block, third) == CMT_OK,
            "unlock_on_unknown_block: hashing the third block");
    S_CHECK(cmt_part_set_header(parts, &third_psh) == CMT_OK,
            "unlock_on_unknown_block: the third part set header");
    S_CHECK(memcmp(third, second, sizeof(second)) != 0,
            "unlock_on_unknown_block: third == second");         /* :956 */

    tc_increment_round(tc, 1u, 4u);                              /* :958 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_precommit(&tc->config, 1),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT)); /* :961 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 2));                       /* :964 */

    /* ── Round 2 (:967-983): "Round2 (vs3, C) // C C C C // C nil nil nil" */
    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts));      /* :971 */
    S_STEP(tc_drain(tc));
    S_STEP(tc_ensure_vote(tc, 1, 2, S_PREVOTE));                 /* :975 */
    /* :976-977 — "we are no longer locked to the first block so we should
     * be able to prevote" the proposal. */
    S_STEP(tc_validate_prevote(tc, 2, third, sizeof(third)));

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, third, sizeof(third),
                                   &third_psh, false, 1u, 4u));  /* :979 */
    S_STEP(tc_ensure_vote(tc, 1, 2, S_PRECOMMIT));               /* :981 */
    /* :982-983 — "now vs1 can change lock to the third block". */
    S_STEP(tc_validate_precommit(tc, 2, 2, third, sizeof(third),
                                 third, sizeof(third)));
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:990-1107 —
 * `TestStateLockPOLSafety1`.
 *
 * "a polka at round 1 but we miss it / then a polka at round 2 that we
 * lock on / then we see the polka from round 1 but shouldn't unlock"
 * (:986-989; the reference's comment numbers rounds from 1). Four
 * validators. Round 0: the others sign a polka for our block that we never
 * see (:1024 `signVotes`, kept aside), and precommit nil. Round 1: vs2
 * proposes a new block; we prevote it, the others polka it, we LOCK on it
 * (:1074); the others precommit nil. Round 2: no proposal, so we prevote
 * our locked block (:1096); THEN the round-0 polka is delivered (:1102).
 * It is a polka for a DIFFERENT block from a round BELOW our LockedRound,
 * so state.go:2264's `LockedRound < vote.Round` is false and nothing moves
 * — no unlock, no step (:1106 `ensureNoNewRoundStep`).
 *
 * The round-1 proposal is `decideProposal(ctx, t, cs1, vs2, …)` (:1037) —
 * cs1's own State, whose ValidRound is −1 at that point (no polka seen),
 * so `tc_decide_proposal` reads the right POL round.
 */
static int s_lock_pol_safety1(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    uint8_t               prop_hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t prop_psh;
    cmt_part_set_header_t zero;
    cmt_block_t          *block = NULL;
    cmt_part_set_t       *parts = NULL;
    cmt_vote_t           *prevotes;
    cmt_round_step_t      step_before;

    S_CHECK(tc != NULL, "lock_pol_safety1: setup");
    tc_zero_psh(&zero);

    /* ── Round 0 (:1009-1033) ────────────────────────────────────────── */
    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1010 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1011 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1013 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :1015 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :1021 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :1017 */
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));      /* :1018 */

    /* :1020-1024 — "the others sign a polka but we don't see it". Signed
     * NOW, at round 0, and delivered at :1102. Heap: three votes. */
    prevotes = (cmt_vote_t *)calloc(3u, sizeof(cmt_vote_t));
    if (prevotes == NULL) {
        tc_release(tc);
        return 1;
    }
    if (tc_sign_votes_range(tc, S_PREVOTE, hash, sizeof(hash), &psh, false,
                            1u, 4u, prevotes) != 0) {
        free(prevotes);
        tc_release(tc);
        return 1;
    }

    /* :1028-1029 — "we do see them precommit nil": +2/3 nil precommits at
     * a round where we are still at Prevote take us through
     * enterPrecommit with no polka (state.go:1465-1473) to a nil
     * precommit, then into precommit-wait (:2351). */
    if (tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero, true,
                                1u, 4u) != 0 ||
        tc_ensure_vote(tc, 1, 0, S_PRECOMMIT) != 0 ||            /* :1032 */
        tc_validate_precommit(tc, 0, -1, NULL, 0u, NULL, 0u) != 0 ||
        tc_ensure_new_timeout(tc, 1, 0,
                              cmt_config_precommit(&tc->config, 0),
                              CMT_ROUND_STEP_PRECOMMIT_WAIT) != 0) {/* :1033 */
        free(prevotes);
        tc_release(tc);
        return 1;
    }

    /* :1037-1040 — the round-1 block, made by cs1 and signed by vs2. */
    if (tc_decide_proposal(tc, 1u, 1, 1, tc->prop, &block, &parts) != 0 ||
        cmt_block_hash(block, prop_hash) != CMT_OK ||
        cmt_part_set_header(parts, &prop_psh) != CMT_OK) {
        free(prevotes);
        tc_release(tc);
        return 1;
    }
    tc_increment_round(tc, 1u, 4u);                              /* :1042 */

    /* ── Round 1 (:1044-1078) ────────────────────────────────────────── */
    if (tc_fire_timeout(tc) != 0 ||
        tc_ensure_new_round(tc, 1, 1) != 0 ||                    /* :1045 */
        /* :1047-1050 — "XXX: this isnt guaranteed to get there before the
         * timeoutPropose": here it is, because nothing fires a timeout
         * unless the scenario does. */
        tc_set_proposal_and_block(tc, tc->prop, parts) != 0 ||
        tc_drain(tc) != 0 ||
        tc_ensure_new_proposal(tc, 1, 1) != 0) {                 /* :1056 */
        free(prevotes);
        tc_release(tc);
        return 1;
    }
    if (tc->cs->rs.locked_block != NULL) {                       /* :1060 */
        fprintf(stderr, "lock_pol_safety1: we should not be locked!\n");
        free(prevotes);
        tc_release(tc);
        return 1;
    }
    g_tc_checks++;
    if (tc_ensure_vote(tc, 1, 1, S_PREVOTE) != 0 ||              /* :1066 */
        tc_validate_prevote(tc, 1, prop_hash, sizeof(prop_hash)) != 0 ||
        /* :1069-1070 — "now we see the others prevote for it, so we should
         * lock on it". */
        tc_sign_add_votes_range(tc, S_PREVOTE, prop_hash, sizeof(prop_hash),
                                &prop_psh, false, 1u, 4u) != 0 ||
        tc_ensure_vote(tc, 1, 1, S_PRECOMMIT) != 0 ||            /* :1072 */
        tc_validate_precommit(tc, 1, 1, prop_hash, sizeof(prop_hash),
                              prop_hash, sizeof(prop_hash)) != 0 ||/* :1074 */
        tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero, true,
                                1u, 4u) != 0 ||                  /* :1076 */
        tc_ensure_new_timeout(tc, 1, 1,
                              cmt_config_precommit(&tc->config, 1),
                              CMT_ROUND_STEP_PRECOMMIT_WAIT) != 0) {/* :1078 */
        free(prevotes);
        tc_release(tc);
        return 1;
    }
    tc_increment_round(tc, 1u, 4u);                              /* :1080 */

    /* ── Round 2 (:1081-1106): "we see the polka from round 1 but we
     *    shouldn't unlock!" ─────────────────────────────────────────── */
    if (tc_fire_timeout(tc) != 0 ||
        tc_ensure_new_round(tc, 1, 2) != 0 ||                    /* :1083 */
        /* :1090-1091 — not the proposer, no proposal: timeout of propose. */
        tc_ensure_new_timeout(tc, 1, 2,
                              cmt_config_propose(&tc->config, 2),
                              CMT_ROUND_STEP_PROPOSE) != 0 ||
        tc_fire_timeout(tc) != 0 ||
        tc_ensure_vote(tc, 1, 2, S_PREVOTE) != 0 ||              /* :1094 */
        /* :1095-1096 — "we should prevote what we're locked on". */
        tc_validate_prevote(tc, 2, prop_hash, sizeof(prop_hash)) != 0) {
        free(prevotes);
        tc_release(tc);
        return 1;
    }

    /* :1098 — the reference subscribes to NewRoundStep HERE, so only a step
     * change AFTER this point would count; the snapshot is the C form. */
    step_before = tc->cs->rs.step;

    /* :1100-1102 — "add prevotes from the earlier round": the round-0 polka
     * for OUR round-0 block. LockedRound is 1 and the polka's round is 0,
     * so state.go:2264 refuses the unlock; :2281 refuses the Valid* update
     * (ValidRound 1 is not < 0); and none of :2311, :2315, :2323 applies. */
    if (tc_add_votes(tc, prevotes, 3u) != 0) {
        free(prevotes);
        tc_release(tc);
        return 1;
    }
    free(prevotes);

    /* :1106 — `ensureNoNewRoundStep`: nothing moved. And the reason the
     * test exists (:1086-1088): the lock did not move either. */
    S_STEP(tc_ensure_no_new_round_step(tc, 1, 2, step_before));
    S_STEP(tc_ensure_no_new_unlock(tc, 1, prop_hash, sizeof(prop_hash)));
    S_CHECK(tc_own_vote(tc, 2, S_PRECOMMIT) == NULL,
            "lock_pol_safety1: the old polka made us precommit");
    /* The round-0 polka IS in the vote set — the votes were added, they
     * just changed nothing. Asserted so that a run in which `tc_add_votes`
     * silently dropped them could not pass as "nothing moved". */
    S_STEP(tc_ensure_stub_vote(tc, 1u, 0, S_PREVOTE));
    S_STEP(tc_ensure_stub_vote(tc, 3u, 0, S_PREVOTE));
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:1116-1210 —
 * `TestStateLockPOLSafety2`.
 *
 * "dont see P0, lock on P1 at R1, dont unlock using P0 at R2" (:1114-1115).
 * Four validators. Before any round starts: block B0 is made and the
 * others sign a polka for it at round 0 that we never see (:1137-1144);
 * block B1 is made for round 1 (:1147). We jump in at round 1 (:1157),
 * receive B1, prevote it, see the polka, LOCK on it (:1172); two nil
 * precommits and one for B1 are +2/3 of anything (:1175-1176) and the
 * precommit timeout takes us to round 2. There vs3 re-proposes B0 with
 * POLRound 0 (:1185-1191) and the round-0 polka is delivered (:1198).
 * The proposal completes only once its POL is in (state.go:1265-1269,
 * reached through :2323-2326), and then we prevote — our LOCKED block B1,
 * not B0 (:1209), with no unlock in between (:1207): the polka's round 0
 * is below LockedRound 1, so :2264 refuses.
 *
 * ⚠ B0 AND B1 DIFFER HERE AND MAY NOT IN THE REFERENCE. Both are
 * `decideProposal(ctx, t, cs1, …)` (:1137, :1147), so the reference's
 * `createProposalBlock` stamps CS1's address into both; with no
 * transactions and the genesis time as block time the two blocks are
 * then byte-identical, by reading (state.go:1306, state/state.go's
 * MakeBlock). This fixture stamps the SIGNER (vss[0] for B0, vs2 for B1),
 * so B0 ≠ B1 — asserted below, labelled as not the reference's assertion.
 * What that buys is :1209's prevote check: with identical blocks the
 * reference cannot tell "prevoted the lock" from "prevoted the proposal";
 * here it can. It does NOT exercise the hash half of :2263-2266 — in Go
 * and in cmt_cs.c the `&&` chain stops at `LockedRound (1) < vote.Round
 * (0)` before the blocks are compared — so the refusal at :2264 is what
 * keeps the lock in both, which is the property the test's own comment
 * names.
 *
 * B0's part set is REBUILT at :1193 (`tc_make_part_set`) because B1's was
 * built into the same fixture buffer at :1147; B1's assembled part set
 * then points at B0's bytes (fixture item 11) and is never read again.
 */
static int s_lock_pol_safety2(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash0[CMT_TMHASH_SIZE];
    uint8_t               hash1[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh0;
    cmt_part_set_header_t psh1;
    cmt_part_set_header_t zero;
    cmt_block_id_t        bid0;
    cmt_block_t          *block0 = NULL;
    cmt_block_t          *block1 = NULL;
    cmt_part_set_t       *parts  = NULL;
    cmt_vote_t           *prevotes;
    cmt_proposal_t       *prop1;

    S_CHECK(tc != NULL, "lock_pol_safety2: setup");
    tc_zero_psh(&zero);

    prevotes = (cmt_vote_t *)calloc(3u, sizeof(cmt_vote_t));
    prop1    = (cmt_proposal_t *)calloc(1u, sizeof(cmt_proposal_t));
    if (prevotes == NULL || prop1 == NULL) {
        free(prevotes);
        free(prop1);
        tc_release(tc);
        return 1;
    }

    /* :1135-1141 — "the block for R0: gets polkad but we miss it (even
     * though we signed it, shhh)": made by cs1, signed by vss[0], and the
     * proposal itself discarded. */
    if (tc_decide_proposal(tc, 0u, 1, 0, tc->prop, &block0, &parts) != 0 ||
        cmt_block_hash(block0, hash0) != CMT_OK ||
        cmt_part_set_header(parts, &psh0) != CMT_OK) {
        free(prevotes);
        free(prop1);
        tc_release(tc);
        return 1;
    }
    memset(&bid0, 0, sizeof(bid0));
    memcpy(bid0.hash, hash0, sizeof(hash0));
    bid0.hash_len        = sizeof(hash0);
    bid0.part_set_header = psh0;

    /* :1143-1144 — the others sign a polka for B0 at round 0. */
    if (tc_sign_votes_range(tc, S_PREVOTE, hash0, sizeof(hash0), &psh0,
                            false, 1u, 4u, prevotes) != 0) {
        free(prevotes);
        free(prop1);
        tc_release(tc);
        return 1;
    }

    /* :1146-1150 — the block for round 1, made by cs1, signed by vs2. */
    if (tc_decide_proposal(tc, 1u, 1, 1, prop1, &block1, &parts) != 0 ||
        cmt_block_hash(block1, hash1) != CMT_OK ||
        cmt_part_set_header(parts, &psh1) != CMT_OK) {
        free(prevotes);
        free(prop1);
        tc_release(tc);
        return 1;
    }
    /* Not the reference's assertion — see the header. */
    if (memcmp(hash0, hash1, sizeof(hash0)) == 0) {
        fprintf(stderr, "lock_pol_safety2: B0 and B1 are the same block\n");
        free(prevotes);
        free(prop1);
        tc_release(tc);
        return 1;
    }
    g_tc_checks++;

    tc_increment_round(tc, 1u, 4u);                              /* :1152 */

    /* ── Round 1 (:1154-1181): "jump in at round 1" ──────────────────── */
    if (tc_start_test_round(tc, 1, 1) != 0 ||                    /* :1157 */
        tc_ensure_new_round(tc, 1, 1) != 0 ||                    /* :1158 */
        tc_set_proposal_and_block(tc, prop1, parts) != 0 ||      /* :1160 */
        tc_drain(tc) != 0 ||
        tc_ensure_new_proposal(tc, 1, 1) != 0 ||                 /* :1163 */
        tc_ensure_vote(tc, 1, 1, S_PREVOTE) != 0 ||              /* :1165 */
        tc_validate_prevote(tc, 1, hash1, sizeof(hash1)) != 0 || /* :1166 */
        tc_sign_add_votes_range(tc, S_PREVOTE, hash1, sizeof(hash1), &psh1,
                                false, 1u, 4u) != 0 ||           /* :1168 */
        tc_ensure_vote(tc, 1, 1, S_PRECOMMIT) != 0 ||            /* :1170 */
        /* :1171-1172 — "the proposed block should now be locked". */
        tc_validate_precommit(tc, 1, 1, hash1, sizeof(hash1),
                              hash1, sizeof(hash1)) != 0 ||
        /* :1174-1176 — two nil precommits and one for B1: +2/3 of anything
         * and no majority for either. */
        tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, NULL, 0u, &zero,
                             true) != 0 ||
        tc_sign_add_vote_one(tc, 3u, S_PRECOMMIT, NULL, 0u, &zero,
                             true) != 0 ||
        tc_sign_add_vote_one(tc, 2u, S_PRECOMMIT, hash1, sizeof(hash1),
                             &psh1, true) != 0) {
        free(prevotes);
        free(prop1);
        tc_release(tc);
        return 1;
    }
    tc_increment_round(tc, 1u, 4u);                              /* :1178 */
    if (tc_ensure_new_timeout(tc, 1, 1,
                              cmt_config_precommit(&tc->config, 1),
                              CMT_ROUND_STEP_PRECOMMIT_WAIT) != 0 ||/* :1181 */
        tc_fire_timeout(tc) != 0) {
        free(prevotes);
        free(prop1);
        tc_release(tc);
        return 1;
    }

    /* ── Round 2 (:1183-1209): "in round 2 we see the polkad block from
     *    round 0" ─────────────────────────────────────────────────── */
    /* :1185-1191 — a proposal for B0 at round 2 with POLRound 0, signed by
     * vs3, the round-2 proposer. */
    if (tc_make_signed_proposal(tc, 2u, 1, 2, 0, &bid0, tc->prop) != 0 ||
        /* :1193 — B0's parts, rebuilt (see the header). */
        tc_make_part_set(tc, block0, &parts) != 0 ||
        tc_set_proposal_and_block(tc, tc->prop, parts) != 0 ||
        /* :1197-1198 — "Add the pol votes". Queued behind the proposal and
         * its parts, exactly as the reference's peer channel orders them. */
        tc_add_votes(tc, prevotes, 3u) != 0) {
        free(prevotes);
        free(prop1);
        tc_release(tc);
        return 1;
    }
    free(prevotes);
    free(prop1);

    S_STEP(tc_ensure_new_round(tc, 1, 2));                       /* :1200 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 2));                    /* :1205 */
    /* :1207 — no unlock: still locked on B1 at round 1. */
    S_STEP(tc_ensure_no_new_unlock(tc, 1, hash1, sizeof(hash1)));
    S_STEP(tc_ensure_vote(tc, 1, 2, S_PREVOTE));                 /* :1208 */
    /* :1209 — and the prevote is for the LOCKED block, not the proposal. */
    S_STEP(tc_validate_prevote(tc, 2, hash1, sizeof(hash1)));
    /* The proposal for B0 was accepted and completed (its POL is in), and
     * B0 is what the round state calls the proposal block — so the prevote
     * above really chose the lock over a complete proposal. */
    S_CHECK(tc->cs->rs.proposal != NULL && tc->cs->rs.proposal->pol_round == 0,
            "lock_pol_safety2: the POLRound-0 proposal was not installed");
    S_CHECK(cmt_block_hashes_to(tc->cs->rs.proposal_block, hash0,
                                sizeof(hash0)),
            "lock_pol_safety2: the proposal block is not B0");
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:1217-1305 —
 * `TestProposeValidBlock`.
 *
 * "polka P0 at R0 for B0. We lock B0 on P0 at R0. P0 unlocks value at R1.
 * What we want: P0 proposes B0 at R3" (:1212-1216). Four validators.
 * Round 0: we propose B0, the others polka it, we lock (:1253); nil
 * precommits, timeout. Round 1: no proposal, we prevote our lock (:1270);
 * the others polka NIL, which UNLOCKS us (:1274, state.go:2263-2277 with
 * an empty hash) and we precommit nil unlocked (:1278). The others then
 * precommit nil at round 3 (:1280-1283), which skips us straight there
 * (:2339-2352), and the precommit timeout takes us to round 4, where we
 * are the proposer again and `defaultDecideProposal` proposes the
 * VALIDBLOCK — B0, with POLRound = ValidRound = 0 (state.go:1209-1211,
 * :1238) — even though we are locked on nothing. :1301-1304 are four
 * assertions and all four are here.
 *
 * `ensureNewUnlock` (:1274) is the round-state form: LockedRound −1 and
 * no LockedBlock at (1, 1). `ensureNewTimeout(timeoutProposeCh, …)` at
 * :1267 is the propose timeout of round 1, fired by hand.
 */
static int s_propose_valid_block(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    uint8_t               got[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t zero;

    S_CHECK(tc != NULL, "propose_valid_block: setup");
    tc_zero_psh(&zero);

    /* ── Round 0 (:1234-1257) ────────────────────────────────────────── */
    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1235 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1236 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1238 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :1241 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :1247 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :1243 */
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));      /* :1244 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 1u, 4u));        /* :1249 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :1251 */
    S_STEP(tc_validate_precommit(tc, 0, 0, hash, sizeof(hash),
                                 hash, sizeof(hash)));           /* :1253 */
    /* The polka also made B0 the ValidBlock (state.go:2281-2286) — which is
     * what round 4 will propose. Asserted here so the round-4 assertions
     * cannot pass with a ValidBlock set by some later path. */
    S_CHECK(tc->cs->rs.valid_round == 0 &&
            cmt_block_hashes_to(tc->cs->rs.valid_block, hash, sizeof(hash)),
            "propose_valid_block: B0 did not become the ValidBlock at R0");

    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                   true, 1u, 4u));               /* :1255 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT)); /* :1257 */
    tc_increment_round(tc, 1u, 4u);                              /* :1259 */

    /* ── Round 1 (:1260-1278): "ONTO ROUND 2" in the reference's count ── */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :1262 */
    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_propose(&tc->config, 1),
                                 CMT_ROUND_STEP_PROPOSE));       /* :1267 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :1269 */
    S_STEP(tc_validate_prevote(tc, 1, hash, sizeof(hash)));      /* :1270 */

    /* :1272 — a NIL polka at our round: `!LockedBlock.HashesTo(nil)` is
     * true, LockedRound 0 < 1 ≤ 1, so :2263-2277 unlocks. */
    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, NULL, 0u, &zero,
                                   false, 1u, 4u));
    S_STEP(tc_ensure_new_unlock(tc, 1, 1));                      /* :1274 */
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :1276 */
    S_STEP(tc_validate_precommit(tc, 1, -1, NULL, 0u, NULL, 0u));/* :1278 */
    /* Unlocking does not touch the Valid* names (:2270-2272 only). */
    S_CHECK(tc->cs->rs.valid_round == 0 && tc->cs->rs.valid_block != NULL,
            "propose_valid_block: the unlock cleared the ValidBlock");

    tc_increment_round(tc, 1u, 4u);                              /* :1280 */
    tc_increment_round(tc, 1u, 4u);                              /* :1281 */

    /* :1283 — +2/3 nil precommits at ROUND 3 while we are at round 1:
     * state.go:2342 enters round 3 (no proposal — vs4 is the proposer),
     * :2343 precommits nil there, :2351 enters precommit-wait. */
    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                   true, 1u, 4u));
    S_STEP(tc_ensure_new_round(tc, 1, 3));                       /* :1287 */
    S_STEP(tc_ensure_vote(tc, 1, 3, S_PRECOMMIT));
    S_STEP(tc_ensure_new_timeout(tc, 1, 3,
                                 cmt_config_precommit(&tc->config, 3),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT)); /* :1290 */

    /* ── Round 4 (:1292-1304): "ONTO ROUND 4" — we propose again ──────── */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 4));                       /* :1294 */
    S_STEP(tc_check_proposer(tc, 1, 4));                    /* (h−1+4) ≡ 0 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 4));                    /* :1298 */

    S_STEP(tc_proposal_block_hash(tc, got));
    S_CHECK(memcmp(got, hash, sizeof(hash)) == 0,
            "propose_valid_block: the round-4 proposal is not B0"); /* :1301 */
    S_CHECK(tc->cs->rs.valid_block != NULL &&
            cmt_block_hashes_to(tc->cs->rs.valid_block, got, sizeof(got)),
            "propose_valid_block: ProposalBlock != ValidBlock");   /* :1302 */
    S_CHECK(tc->cs->rs.proposal != NULL &&
            tc->cs->rs.proposal->pol_round == tc->cs->rs.valid_round,
            "propose_valid_block: Proposal.POLRound != ValidRound"); /* :1303 */
    S_CHECK(tc->cs->rs.proposal->block_id.hash_len == sizeof(got) &&
            memcmp(tc->cs->rs.proposal->block_id.hash, got,
                   sizeof(got)) == 0,
            "propose_valid_block: Proposal.BlockID.Hash != ValidBlock.Hash");
                                                                 /* :1304 */
    /* And we are still locked on nothing: the proposal came from the Valid*
     * names, not from a lock. */
    S_CHECK(tc->cs->rs.locked_round == -1 && tc->cs->rs.locked_block == NULL,
            "propose_valid_block: re-locked without a polka");
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

/**
 * cometbft@709fd12b consensus/state_test.go:1372-1427 —
 * `TestSetValidBlockOnDelayedProposal`.
 *
 * "P0 miss to lock B as Proposal Block is missing, but set valid block to
 * B after receiving delayed Block Proposal" (:1369-1371). Four
 * validators, round 1 (we are not the proposer). The propose timeout
 * expires and we prevote nil (:1401). The others polka B, which we do not
 * have: state.go:2295 clears ProposalBlock and :2298-2300 sets up a part
 * set from B's header (:1410 `ensureNewValidBlock`); the proposal is not
 * complete, so we wait out the prevote timeout and precommit nil,
 * unlocked (:1415). THEN B's proposal and parts arrive (:1417). The parts
 * fill the set built at :2299 and `handleCompleteProposal` makes B the
 * ValidBlock at round 1 (:2037-2047; :1424-1426).
 *
 * ⚠ :1421 `ensureNewProposal` CANNOT BE `tc_ensure_new_proposal` HERE, and
 * the reason is in the reference's own arithmetic: `decideProposal` at
 * :1403 is called with `vs2.Round+1`, and vs2 was already incremented to
 * round 1 at :1393, so the PROPOSAL is for ROUND 2 while cs1 is at round 1.
 * `defaultSetProposal` drops it as not applying (state.go:1911-1912) and
 * `rs.Proposal` stays nil. The EVENT the reference waits for is published
 * by `addProposalBlockPart` (:2026-2028) when the PARTS complete, whatever
 * became of the proposal — the same situation `s_commit_from_previous_round`
 * records for :2171. So what is asserted is what that event announces:
 * the block is assembled and it is B. The block parts are accepted because
 * `addProposalBlockPart` ignores the message's round (:1958 "Blocks might
 * be reused, so round mismatch is OK") and the part set from :2299 is
 * waiting for exactly these parts.
 */
static int s_set_valid_block_on_delayed_proposal(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t vpsh;
    cmt_block_t          *block = NULL;
    cmt_part_set_t       *parts = NULL;

    S_CHECK(tc != NULL, "delayed_proposal: setup");

    tc_increment_round(tc, 1u, 4u);                              /* :1393 */
    S_STEP(tc_start_test_round(tc, 1, 1));                       /* :1395 */
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :1396 */

    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_propose(&tc->config, 1),
                                 CMT_ROUND_STEP_PROPOSE));       /* :1398 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PREVOTE));                 /* :1400 */
    S_STEP(tc_validate_prevote(tc, 1, NULL, 0u));                /* :1401 */

    /* :1403-1406 — B, made by cs1 and signed by vs2 for `vs2.Round+1`,
     * which is 2 (see the header). cs1's ValidRound is −1. */
    S_STEP(tc_decide_proposal(tc, 1u, 1, 2, tc->prop, &block, &parts));
    S_CHECK(tc->prop->round == 2,
            "delayed_proposal: the reference's proposal is for round 2");
    S_CHECK(cmt_block_hash(block, hash) == CMT_OK,
            "delayed_proposal: hashing B");
    S_CHECK(cmt_part_set_header(parts, &psh) == CMT_OK,
            "delayed_proposal: B's part set header");

    /* :1408-1410 — the others prevote B; a polka for a block we lack. */
    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 1u, 4u));
    S_STEP(tc_ensure_new_valid_block(tc, 1, 1, &psh));           /* :1410 */
    S_CHECK(tc->cs->rs.proposal_block == NULL,
            "delayed_proposal: ProposalBlock should be nil (:2295)");
    S_CHECK(tc->cs->rs.valid_block == NULL && tc->cs->rs.valid_round == -1,
            "delayed_proposal: a block we do not have became valid");

    S_STEP(tc_ensure_new_timeout(tc, 1, 1,
                                 cmt_config_prevote(&tc->config, 1),
                                 CMT_ROUND_STEP_PREVOTE_WAIT));  /* :1412 */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 1, 1, S_PRECOMMIT));               /* :1414 */
    S_STEP(tc_validate_precommit(tc, 1, -1, NULL, 0u, NULL, 0u));/* :1415 */

    /* :1417 — the delayed proposal and block. */
    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts));
    S_STEP(tc_drain(tc));
    /* :1421 — see the header: the round-2 proposal itself was dropped
     * (state.go:1911), and the parts completed the set from :2299. */
    S_CHECK(tc->cs->rs.proposal == NULL,
            "delayed_proposal: a round-2 proposal was installed at round 1");
    S_CHECK(tc->cs->rs.proposal_block != NULL &&
            cmt_block_hashes_to(tc->cs->rs.proposal_block, hash, sizeof(hash)),
            "delayed_proposal: B was not assembled from its parts");

    S_CHECK(tc->cs->rs.valid_block != NULL &&
            cmt_block_hashes_to(tc->cs->rs.valid_block, hash, sizeof(hash)),
            "delayed_proposal: ValidBlock is not B");           /* :1424 */
    S_CHECK(tc->cs->rs.valid_block_parts != NULL &&
            cmt_part_set_header(tc->cs->rs.valid_block_parts,
                                &vpsh) == CMT_OK &&
            cmt_psh_equals(&vpsh, &psh),
            "delayed_proposal: ValidBlockParts header is not B's"); /* :1425 */
    S_CHECK(tc->cs->rs.valid_round == 1,
            "delayed_proposal: ValidRound should be 1");         /* :1426 */
    /* And still unlocked: :2045-2047 touches only the Valid* names. */
    S_CHECK(tc->cs->rs.locked_round == -1 && tc->cs->rs.locked_block == NULL,
            "delayed_proposal: the late block locked us");
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
 * cometbft@709fd12b consensus/state_test.go:1582-1646 —
 * `TestVerifyVoteExtensionNotCalledOnAbsentPrecommit`.
 *
 * "the VerifyVoteExtension method is not called for a validator's vote
 * that is never delivered" (:1580-1581). Four validators, extensions
 * enabled at height 1 (:1596). Everyone prevotes the proposal, we
 * precommit with an extension (:1617-1628), and only vs3 and vs4
 * precommit (:1630, `vss[2:]`) — with ours that is 30 of 40, the height
 * commits, and `VerifyVoteExtension` must have been called for THEIR two
 * addresses and NEVER for vs2's (:1640-1645), whose precommit did not
 * exist.
 *
 * :1614 signs prevotes for ALL of `vss`, INCLUDING vss[0] — the stub that
 * holds THIS node's key. That stub's Height is still 0 (`tc_setup`, as
 * common_test.go:492, increments only `vss[1:]`), so its vote is for a
 * height below ours and `addVote` ignores it at state.go:2172-2174 — it is
 * a prevote, so the LastCommit branch at :2137 does not apply either. In
 * the port the same two tests are cmt_cs.c's `cs_add_vote` (the height−1
 * test wants a PRECOMMIT; then the height mismatch). It is sent anyway,
 * because the reference sends it.
 *
 * ⚠ PARTIAL in the same way as `s_extend_vote_called_when_enabled`: the
 * reference's `AssertCalled(t, "ExtendVote", &RequestExtendVote{Height,
 * Hash, Time, Txs, …})` (:1619-1628) checks the request's CONTENT; the
 * port has no request object, so only the CALL is asserted — header item
 * 11. The `AssertNotCalled` at :1640-1645 IS ported in full: its only
 * discriminating field is the validator address, which the fixture
 * records per call (`tc_verify_ext_called_for`).
 */
static int s_verify_vote_extension_not_called_on_absent_precommit(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);           /* :1594, :1596 */
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;

    S_CHECK(tc != NULL, "verify_ext_absent_precommit: setup");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1605 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1606 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1607 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :1611 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :1612 */

    /* :1614 — `vss...`, all four, vss[0] at height 0 (see the header). */
    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 0u, 4u));
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));      /* :1615 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :1617 */
    S_STEP(tc_validate_precommit(tc, 0, 0, hash, sizeof(hash),
                                 hash, sizeof(hash)));
    S_CHECK(tc->extend_calls == 1,
            "verify_ext_absent_precommit: ExtendVote was not called once");
                                                            /* :1619-1628 */
    S_CHECK(tc->verify_ext_calls == 0,
            "verify_ext_absent_precommit: VerifyVoteExtension before any "
            "peer precommit");

    /* :1630 — `vss[2:]`: vs3 and vs4 precommit with extensions; vs2 never
     * does. 30 of 40 commits the height. */
    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, hash, sizeof(hash),
                                   &psh, true, 2u, 4u));
    S_CHECK(tc->apply_calls == 1,
            "verify_ext_absent_precommit: the height did not commit");
    S_STEP(tc_ensure_new_block_header(tc, 1, hash, sizeof(hash)));
    S_STEP(tc_fire_timeout(tc));      /* the commit timeout — see :447 */
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :1631 */

    /* :1632 `AssertExpectations` — every mocked method was reached, so
     * VerifyVoteExtension was called at all; and, from :1634-1645, for
     * WHOM. */
    S_CHECK(tc->verify_ext_calls == 2,
            "verify_ext_absent_precommit: expected exactly two "
            "VerifyVoteExtension calls");
    S_CHECK(tc_verify_ext_called_for(tc, 2u) && tc_verify_ext_called_for(tc, 3u),
            "verify_ext_absent_precommit: not called for vs3 and vs4");
    S_CHECK(!tc_verify_ext_called_for(tc, 1u),
            "verify_ext_absent_precommit: called for vs2, whose precommit "
            "was never delivered");                          /* :1640-1645 */
    S_CHECK(!tc_verify_ext_called_for(tc, 0u),
            "verify_ext_absent_precommit: called for our own vote (:2191)");
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:1654-1745 —
 * `TestPrepareProposalReceivesVoteExtensions`.
 *
 * "the PrepareProposal method is called with the vote extensions from the
 * previous height" (:1648-1653). Four validators, each with its OWN
 * extension bytes (:1656-1661): ours comes from `ExtendVote`
 * (`voteExtensions[0]`, :1664-1666), each stub's from
 * `signAddPrecommitWithExtension` (:1702-1704). Height 1 commits at round
 * 0. At height 2 we are not the proposer until round 3 ((h−1+r) mod 4 =
 * 0), so the others precommit nil at round 3 (:1721) and we skip there
 * (state.go:2339-2352) and propose. That proposal is built by
 * `createProposalBlock`, which turns `cs.LastCommit` into an
 * ExtendedCommit (:1292-1294) and hands it to the block executor (:1308)
 * — the reference's `PrepareProposal` receives it as `LocalLastCommit`
 * (state/execution.go:127-129); this port's `create_proposal_block` row
 * receives it as `last_ext_commit`, and the fixture captures it there.
 *
 * :1727-1744 then check, for every validator index i: the captured commit
 * has one entry per validator; entry i's extension is `voteExtensions[i]`;
 * its extension signature is non-empty; and that signature verifies over
 * `CanonicalVoteExtension{Extension, Height: height−1, Round:
 * LocalLastCommit.Round, ChainId}` with validator i's key. Here that is
 * `cmt_extended_commit_get_extended_vote` (types/block.go:1145-1162, which
 * rebuilds the vote from the entry with the commit's height and round)
 * followed by `cmt_vote_verify_extension` (types/vote.go:261-273). Because
 * the C sign bytes take the height and round FROM THE COMMIT, the commit's
 * own height and round are asserted first — `height−1` = 1 and round 0 —
 * so that a wrong-height commit whose signatures verify over their own
 * height could not pass.
 *
 * THIS CLOSES HEADER ITEM 17: it is the one scenario that checks an
 * extension SURVIVES the height boundary — from the vote set of height 1,
 * through `updateToState`'s LastCommit (state.go:701), into the proposal
 * of height 2.
 *
 * Two fixture facts this scenario depends on, both named in the fixture:
 * the round-3 votes at height 2 arrive while only rounds 0-1 are tracked
 * and take `peerCatchupRounds` against ONE synthetic peer id (fixture
 * item 7); and the capture is of the LAST `create_proposal_block`, which
 * here is the state machine's own, because no `tc_decide_proposal` follows
 * it (fixture item 12). The reference's `ensureNewRound(height+1, 0)` at
 * :1714 needs the commit timeout fired by hand — header item 15.
 */
static int s_prepare_proposal_receives_vote_extensions(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t zero;
    size_t                i;

    S_CHECK(tc != NULL, "prepare_proposal_ext: setup");
    tc_zero_psh(&zero);
    /* :1664-1666 — ExtendVote answers `voteExtensions[0]`. */
    tc->extend_ext     = tc_ext_bytes_of[0];
    tc->extend_ext_len = (size_t)TC_EXT_OF_LEN;

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :1690 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :1691 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :1692 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :1696 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :1697 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 1u, 4u));        /* :1699 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :1706 */
    /* Our own precommit — with `voteExtensions[0]` — is made by that polka,
     * before any stub precommit arrives. */
    S_CHECK(tc->extend_calls == 1,
            "prepare_proposal_ext: ExtendVote was not called once");

    /* :1701-1704 — "create a precommit for each validator with the
     * associated vote extension". The height commits at the second of
     * these (30 of 40); the third arrives at height 2 and takes the
     * LastCommit path (state.go:2137-2167), which is how it still ends up
     * in the commit the next proposal carries. */
    for (i = 1u; i < 4u; i++) {
        S_STEP(tc_sign_add_precommit_with_extension(tc, i, hash, sizeof(hash),
                                                    &psh, tc_ext_bytes_of[i],
                                                    (size_t)TC_EXT_OF_LEN));
    }
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :1709 */
    S_CHECK(tc->apply_calls == 1,
            "prepare_proposal_ext: height 1 did not commit");
    S_STEP(tc_ensure_new_block_header(tc, 1, hash, sizeof(hash)));
    /* :1709 `ensurePrecommitMatch(…, blockID.Hash)` — the height has moved,
     * so our precommit is read from LastCommit, as `s_full_round1` does. */
    S_STEP(tc_validate_last_precommit(tc, hash, sizeof(hash)));
    tc_increment_height(tc, 1u, 4u);                             /* :1710 */

    S_STEP(tc_fire_timeout(tc));      /* the commit timeout — see :447 */
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :1714 */
    /* All four precommits are in LastCommit — including vs4's, which
     * arrived after the commit and took the LastCommit path (:2144). If it
     * had not, the extended commit below would carry an ABSENT entry and
     * :1727's `Len == len(vss)` would still hold, so this is checked here
     * by `HasAll` (vote_set.go's HasAll: every validator has voted). */
    {
        bool has_all = false;

        S_CHECK(tc->cs->rs.last_commit != NULL &&
                cmt_vote_set_has_all(tc->cs->rs.last_commit, &has_all) == CMT_OK &&
                has_all,
                "prepare_proposal_ext: LastCommit lacks a validator's "
                "precommit");
    }
    tc_increment_round(tc, 1u, 4u);                              /* :1715 */
    tc_increment_round(tc, 1u, 4u);                              /* :1716 */
    tc_increment_round(tc, 1u, 4u);                              /* :1717 */

    /* :1720-1721 — nil precommits at round 3 (`blockID2 := types.BlockID{}`
     * with `extEnabled` true, which attaches no extension to a nil vote:
     * common_test.go:142). We skip to round 3 and, as its proposer, propose
     * — that is the `create_proposal_block` call the capture is for. */
    S_STEP(tc_sign_add_votes_range(tc, S_PRECOMMIT, NULL, 0u, &zero,
                                   true, 1u, 4u));
    S_STEP(tc_ensure_new_round(tc, 2, 3));                       /* :1722 */
    S_STEP(tc_check_proposer(tc, 2, 3));
    S_STEP(tc_ensure_new_proposal(tc, 2, 3));                    /* :1723 */

    /* :1725-1727 — "ensure that the proposer received the list of vote
     * extensions from the previous height". */
    S_CHECK(tc->cap_ext_ok && tc->cap_ext_for_height == 2,
            "prepare_proposal_ext: no capture of the height-2 proposal's "
            "last_ext_commit");
    S_CHECK(tc->cap_ext.height == 1 && tc->cap_ext.round == 0,
            "prepare_proposal_ext: LocalLastCommit is not height 1 round 0");
    S_CHECK(tc->cap_ext.extended_signatures_len == 4u,
            "prepare_proposal_ext: LocalLastCommit.Votes != len(vss)");
                                                                 /* :1727 */
    for (i = 0u; i < 4u; i++) {                                  /* :1728 */
        const cmt_extended_commit_sig_t *e = &tc->cap_ecsigs[i];
        uint8_t                          scratch[256];

        /* :1730 — `vote.VoteExtension == voteExtensions[i]`, by INDEX. */
        S_CHECK(e->commit_sig.block_id_flag ==
                        (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT &&
                e->commit_sig.validator_address_len == (size_t)CMT_ADDRESS_SIZE &&
                memcmp(e->commit_sig.validator_address, tc->addr[i],
                       (size_t)CMT_ADDRESS_SIZE) == 0,
                "prepare_proposal_ext: entry i is not validator i's commit");
        S_CHECK(e->extension.len == (size_t)TC_EXT_OF_LEN &&
                memcmp(e->extension.data, tc_ext_bytes_of[i],
                       (size_t)TC_EXT_OF_LEN) == 0,
                "prepare_proposal_ext: the wrong extension for this index");
        /* :1732 — `require.NotZero(t, len(vote.ExtensionSignature))`. */
        S_CHECK(e->extension_signature_len > 0u,
                "prepare_proposal_ext: an empty extension signature");
        /* :1733-1743 — the signature verifies over the canonical extension
         * of height 1, round 0, under validator i's key. */
        S_CHECK(cmt_extended_commit_get_extended_vote(&tc->cap_ext, (int32_t)i,
                                                      tc->sv) == CMT_OK,
                "prepare_proposal_ext: GetExtendedVote failed");
        S_CHECK(cmt_vote_verify_extension(tc->chain_id, tc->chain_id_len,
                                          tc->sv, tc->pk[i], scratch,
                                          sizeof(scratch)) == CMT_OK,
                "prepare_proposal_ext: the extension signature does not "
                "verify under this validator's key");
    }
    tc_release(tc);
    return 0;
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
 * cometbft@709fd12b consensus/state_test.go:2190-2249 —
 * `TestStartNextHeightCorrectlyAfterTimeout`.
 *
 * "2 vals precommit votes for a block but node times out waiting for the
 * third. Move to next round and third precommit arrives which leads to the
 * commit of that header and the correct start of the next round"
 * (:2187-2189). Four validators. Round 0: we lock; vs2 precommits nil and
 * vs3 the block (:2228-2229) — +2/3 of anything, no majority — and the
 * precommit timeout takes us to round 1 (:2232-2234). vs4's ROUND-0
 * precommit then arrives (:2237; vs4 was never incremented) and commits
 * height 1 from the previous round (state.go:2339-2346). :2241 pokes the
 * tx notifier; :2243 waits for the PROPOSE timeout of height 2 round 0;
 * :2245-2248 asserts `TriggeredTimeoutPrecommit` is false at the start of
 * the new height — it was set true by round 0's precommit-wait
 * (state.go:1587) and must have been reset (:750, :1098).
 *
 * :2191 `config.Consensus.SkipTimeoutCommit = false` — the reference's
 * test config has it TRUE (config.go:1047); `cmt_config_default` is
 * `DefaultConsensusConfig`, which already has it false (:1027), so there is
 * nothing to set and the fact is asserted instead. :2193 installs a fake
 * tx notifier; the port's notifier IS `cmt_cs_notify_txs_available`.
 *
 * ⚠ ONE STEP HERE IS THE FIXTURE'S, NOT THE REFERENCE'S, and it is
 * asserted so the divergence is visible. `Notify()` at :2241 reaches
 * `handleTxsAvailable` (state.go:1016-1039) at round 0, step NewHeight,
 * where it asks `needProofBlock(2)` (:1117-1132: TRUE when the state's
 * app hash differs from the one in block 1's header). Whether that is
 * TRUE in the reference's own run — the call then returns at :1029 with
 * nothing scheduled and the commit timeout fires as usual — depends on
 * its test application, which is outside the pinned set and was not
 * read; no claim is made about it. In THIS fixture the app hash never
 * changes (fixture item 2), so it is FALSE and :1033-1034 re-arm the commit wait
 * as a `(2, 0, NewRound)` timeout of `timeoutCommit + 1 ms`, which
 * REPLACES the NewHeight timer in the ticker (ticker.go:107-127: same
 * height and round, later step). Firing it takes `handleTimeout`'s
 * NewRound arm (:985-986) straight to `enterPropose(2, 0)`, WITHOUT
 * `enterNewRound` — a path the reference itself has and this fixture
 * happens to select. Both routes arm the round-0 propose timeout the
 * reference waits for at :2243, and both leave `TriggeredTimeoutPrecommit`
 * false: `updateToState` reset it at :750 whichever arm runs.
 */
static int s_start_next_height_correctly_after_timeout(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t zero;

    S_CHECK(tc != NULL, "start_next_height_after_timeout: setup");
    tc_zero_psh(&zero);
    S_CHECK(!tc->config.skip_timeout_commit,
            "start_next_height_after_timeout: SkipTimeoutCommit must be "
            "false (:2191)");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :2210 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :2211 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :2213 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :2215 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :2216 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :2218 */
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));      /* :2219 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 1u, 4u));        /* :2221 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :2223 */
    S_STEP(tc_validate_precommit(tc, 0, 0, hash, sizeof(hash),
                                 hash, sizeof(hash)));           /* :2225 */

    /* :2228-2229 — vs2 nil, vs3 the block: 30 of 40, no majority. */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, NULL, 0u, &zero, true));
    S_STEP(tc_sign_add_vote_one(tc, 2u, S_PRECOMMIT, hash, sizeof(hash),
                                &psh, true));
    S_CHECK(tc->apply_calls == 0,
            "start_next_height_after_timeout: committed on 20 of 40");
    S_CHECK(tc->cs->rs.triggered_timeout_precommit,
            "start_next_height_after_timeout: precommit-wait did not set "
            "TriggeredTimeoutPrecommit (state.go:1587)");

    /* :2231-2232 — `ensurePrecommitTimeout`: the reference waits for ANY
     * TimeoutWait event; the armed timer is asserted in full instead,
     * which is stronger, then fired. */
    S_STEP(tc_ensure_new_timeout(tc, 1, 0,
                                 cmt_config_precommit(&tc->config, 0),
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT));
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_new_round(tc, 1, 1));                       /* :2234 */

    /* :2236-2237 — "majority is now reached": vs4's precommit is for ROUND
     * 0 (its stub was never incremented), where 30 of 40 now name the
     * block; state.go:2339-2346 commits from the previous round, and we
     * have the block because it is our lock (:1629-1633). */
    S_STEP(tc_sign_add_vote_one(tc, 3u, S_PRECOMMIT, hash, sizeof(hash),
                                &psh, true));
    S_CHECK(tc->apply_calls == 1,
            "start_next_height_after_timeout: the late precommit did not "
            "commit");
    S_STEP(tc_ensure_new_block_header(tc, 1, hash, sizeof(hash)));/* :2239 */
    S_CHECK(tc->cs->rs.height == 2 && tc->cs->rs.round == 0 &&
            tc->cs->rs.step == CMT_ROUND_STEP_NEW_HEIGHT,
            "start_next_height_after_timeout: not waiting out timeoutCommit");
    S_STEP(tc_ensure_new_timeout(tc, 2, 0, tc->config.timeout_commit,
                                 CMT_ROUND_STEP_NEW_HEIGHT));

    /* :2241 — `Notify()`. NOT the reference's path from here to :2243: see
     * the header. `needProofBlock(2)` is false in this fixture, so
     * state.go:1033-1034 arm `(2, 0, NewRound)` for `StartTime − now + 1 ms`,
     * and StartTime is CommitTime + timeoutCommit with a frozen clock. */
    cmt_cs_notify_txs_available(tc->cs);
    S_STEP(tc_drain(tc));
    S_STEP(tc_ensure_new_timeout(tc, 2, 0,
                                 tc->config.timeout_commit + CMT_MILLISECOND,
                                 CMT_ROUND_STEP_NEW_ROUND));
    S_STEP(tc_fire_timeout(tc));                /* :985-986 → enterPropose */

    /* :2243 — the propose timeout of height 2, round 0: we are not the
     * proposer there ((h−1+r) mod 4 = 1). */
    S_STEP(tc_ensure_new_round(tc, 2, 0));
    S_STEP(tc_ensure_new_timeout(tc, 2, 0,
                                 cmt_config_propose(&tc->config, 0),
                                 CMT_ROUND_STEP_PROPOSE));
    /* :2244-2248 — "triggeredTimeoutPrecommit should be false at the
     * beginning of each round". */
    S_CHECK(!tc->cs->rs.triggered_timeout_precommit,
            "start_next_height_after_timeout: TriggeredTimeoutPrecommit "
            "carried into the new height");
    /* The reference's `ensureNewTimeout` means the timeout FIRED; firing it
     * here too keeps the two in step and proves the round can proceed. */
    S_STEP(tc_fire_timeout(tc));
    S_STEP(tc_ensure_vote(tc, 2, 0, S_PREVOTE));
    S_STEP(tc_validate_prevote(tc, 0, NULL, 0u));
    S_CHECK(!tc->cs->rs.triggered_timeout_precommit,
            "start_next_height_after_timeout: TriggeredTimeoutPrecommit "
            "set by a prevote");
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:2251-2310 —
 * `TestResetTimeoutPrecommitUponNewHeight`.
 *
 * Four validators. Round 0 of height 1 goes all the way — lock, one nil
 * precommit and two for the block (:2290-2292), commit (:2294) — and then
 * a proposal for HEIGHT 2, round 0 is fed in (:2296-2300) while the node
 * is still waiting out timeoutCommit. `ensureNewProposal(height+1, 0)`
 * (:2303) and `TriggeredTimeoutPrecommit == false` (:2306-2309) are the
 * assertions; the flag was NOT set at height 1 here (no precommit-wait
 * happened — the third precommit committed), so this is the negative
 * twin of `s_start_next_height_correctly_after_timeout`: the flag must be
 * false at the new height whether or not the old one raised it.
 *
 * :2255 `SkipTimeoutCommit = false` — already the default here (config.go:
 * :1027), asserted. :2296 `decideProposal(ctx, t, cs1, vs2, height+1, 0)`
 * is cs1 at HEIGHT 2: its ValidRound is the −1 `updateToState` left
 * (state.go:740), which `tc_decide_proposal` reads, and its LastCommit is
 * what the fixture turns into the block's commit — the same commit the
 * state machine's own `createProposalBlock` would use.
 *
 * ⚠ THE CLOCK IS MOVED, ONCE, BY A CONSTANT — the first scenario in this
 * suite to do so, and the first to reach header item 16. The height-2
 * block's time is the weighted median of height 1's precommit timestamps
 * (state/state.go's MedianTime, reached from MakeBlock), and
 * `tc_validate_block` refuses a block whose time is not strictly after
 * the previous block's (state/validation.go:116-120; the median-equality
 * check is :121-125). The stubs stamp
 * `tc->now`; with the clock frozen at the genesis time — which is also
 * block 1's time — their three stamps make the median EQUAL to
 * LastBlockTime and the block invalid, so this node would prevote nil
 * where the reference, whose stubs stamp real time that has moved on,
 * prevotes the block. The two assertions the reference makes hold either
 * way; but a scenario that walks a path the reference does not is the
 * kind item 14 warns about, so `tc->now` is advanced by exactly one
 * second after THIS NODE'S precommit and before the stubs' precommits —
 * "the stubs voted later than the proposer" rendered deterministically.
 * Our own precommit therefore carries `voteTime`'s stamp of block time
 * + 1 ms (state.go:2423-2434) and the stubs' carry the moved clock, so
 * the four timestamps are NOT all equal: the weighted median over
 * {+1 ms, +1 s, +1 s, +1 s} at equal power is the second, +1 s, and block
 * 2 is valid under :120-140. What this proves about the median is stated
 * in item 16.
 */
static int s_reset_timeout_precommit_upon_new_height(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    uint8_t               hash2[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t zero;
    cmt_block_t          *block = NULL;
    cmt_part_set_t       *parts = NULL;

    S_CHECK(tc != NULL, "reset_timeout_precommit_new_height: setup");
    tc_zero_psh(&zero);
    S_CHECK(!tc->config.skip_timeout_commit,
            "reset_timeout_precommit_new_height: SkipTimeoutCommit must be "
            "false (:2255)");

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :2273 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :2274 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :2276 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :2278 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :2279 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :2281 */
    S_STEP(tc_validate_prevote(tc, 0, hash, sizeof(hash)));      /* :2282 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 1u, 4u));        /* :2284 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :2286 */
    S_STEP(tc_validate_precommit(tc, 0, 0, hash, sizeof(hash),
                                 hash, sizeof(hash)));           /* :2287 */

    /* The clock moves forward by one second — see the header. AFTER our
     * own precommit, whose `voteTime` stamp is therefore block time + 1 ms
     * (state.go:2423-2434), and BEFORE the stubs', which stamp the moved
     * clock. Deterministic: a constant, applied once, read by nothing but
     * the fixture's own `tc_now` and `tc_sign_vote`. */
    tc->now.seconds += 1;

    /* :2289-2292 — vs2 nil, vs3 and vs4 the block: the third commits. */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, NULL, 0u, &zero, true));
    S_STEP(tc_sign_add_vote_one(tc, 2u, S_PRECOMMIT, hash, sizeof(hash),
                                &psh, true));
    S_CHECK(tc->apply_calls == 0,
            "reset_timeout_precommit_new_height: committed on 20 of 40");
    S_STEP(tc_sign_add_vote_one(tc, 3u, S_PRECOMMIT, hash, sizeof(hash),
                                &psh, true));
    S_CHECK(tc->apply_calls == 1,
            "reset_timeout_precommit_new_height: the third precommit did not "
            "commit");
    S_STEP(tc_ensure_new_block_header(tc, 1, hash, sizeof(hash)));/* :2294 */
    S_CHECK(tc->cs->rs.height == 2 && tc->cs->rs.round == 0 &&
            tc->cs->rs.step == CMT_ROUND_STEP_NEW_HEIGHT,
            "reset_timeout_precommit_new_height: not waiting out "
            "timeoutCommit");
    /* No precommit-wait happened at height 1, so the flag was never raised
     * there; the assertion at :2306 is about the NEW height regardless. */
    S_CHECK(!tc->cs->rs.triggered_timeout_precommit,
            "reset_timeout_precommit_new_height: flag raised at height 1");

    /* :2296-2298 — the height-2 proposal, by vs2 (the height-2 round-0
     * proposer: (h−1+r) mod 4 = 1), from cs1's own state and LastCommit. */
    S_STEP(tc_decide_proposal(tc, 1u, 2, 0, tc->prop, &block, &parts));
    S_CHECK(cmt_block_hash(block, hash2) == CMT_OK,
            "reset_timeout_precommit_new_height: hashing block 2");
    S_CHECK(block->header.height == 2 &&
            cmt_time_unix_nano(block->header.time) >
                    cmt_time_unix_nano(tc->cs->state.last_block_time),
            "reset_timeout_precommit_new_height: block 2's time is not after "
            "block 1's (the clock advance did not take)");

    /* :2300 — fed in while the step is still NewHeight. `defaultSetProposal`
     * accepts it (height 2, round 0 match; vs2 is the proposer) and the
     * parts complete it; `handleCompleteProposal` finds the step below
     * Propose (state.go:2056) and enters prevote at once. */
    S_STEP(tc_set_proposal_and_block(tc, tc->prop, parts));
    S_STEP(tc_drain(tc));
    S_STEP(tc_ensure_new_proposal(tc, 2, 0));                    /* :2303 */
    S_CHECK(cmt_block_hashes_to(tc->cs->rs.proposal_block, hash2,
                                sizeof(hash2)),
            "reset_timeout_precommit_new_height: the wrong block at height 2");

    /* :2305-2309 — "triggeredTimeoutPrecommit should be false at the
     * beginning of each height". */
    S_CHECK(!tc->cs->rs.triggered_timeout_precommit,
            "reset_timeout_precommit_new_height: TriggeredTimeoutPrecommit "
            "is set at the new height");
    /* Beyond the reference, and the reason the clock was moved: with a
     * valid block 2 this node PREVOTES IT at (2, 0), exactly as the
     * reference's node does — `tc_validate_block`'s median rule (fixture
     * item 3 / header item 16) accepted a four-signer commit. */
    S_STEP(tc_ensure_vote(tc, 2, 0, S_PREVOTE));
    S_STEP(tc_validate_prevote(tc, 0, hash2, sizeof(hash2)));
    tc_release(tc);
    return 0;
}

/**
 * cometbft@709fd12b consensus/state_test.go:2397-2463 — `TestStateHalt1`.
 *
 * "we receive a final precommit after going into next round, but others
 * might have gone to commit already!" (:2395-2396). Four validators.
 * Round 0: we lock on our block; vs2 precommits nil ("didnt receive
 * proposal", :2431) and vs3 the block (:2432) — +2/3 of anything, no
 * majority; vs4's precommit for the block is SIGNED at round 0 (:2434)
 * but held back. The precommit timeout takes us to round 1 (:2439-2443),
 * where we prevote our lock (:2453-2454). THEN vs4's round-0 precommit is
 * delivered (:2457): the round-0 precommits are now 30 of 40 for the
 * block, and state.go:2339-2346 commits it from the previous round —
 * "receiving that precommit should take us straight to commit" (:2459) —
 * and the next height starts (:2462).
 *
 * The "Halt" in the name is the reference's HaltSuite heading (:2393): it
 * is about a node that would otherwise HALT at round 1 while the others
 * commit. It does NOT call `Start`/`Stop`; nothing about lifecycle is
 * exercised or asserted here, and `cmt_cs_start`/`cmt_cs_stop` are not
 * called. `ensureNewBlock` (:2460) checks the height only; the hash is
 * asserted as well, because committing the LOCKED block a round late is
 * the whole point. `ensureNewRound(height+1, 0)` (:2462) needs the commit
 * timeout fired by hand — header item 15.
 */
static int s_halt1(void)
{
    tc_t                 *tc = tc_alloc(4u, 1, 0);
    uint8_t               hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t psh;
    cmt_part_set_header_t zero;
    cmt_vote_t           *precommit4;

    S_CHECK(tc != NULL, "halt1: setup");
    tc_zero_psh(&zero);

    S_STEP(tc_start_test_round(tc, 1, 0));                       /* :2413 */
    S_STEP(tc_ensure_new_round(tc, 1, 0));                       /* :2414 */
    S_STEP(tc_ensure_new_proposal(tc, 1, 0));                    /* :2416 */
    S_STEP(tc_proposal_block_hash(tc, hash));                    /* :2418 */
    S_STEP(tc_proposal_parts_header(tc, &psh));                  /* :2419 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PREVOTE));                 /* :2422 */

    S_STEP(tc_sign_add_votes_range(tc, S_PREVOTE, hash, sizeof(hash),
                                   &psh, false, 1u, 4u));        /* :2424 */
    S_STEP(tc_ensure_vote(tc, 1, 0, S_PRECOMMIT));               /* :2426 */
    S_STEP(tc_validate_precommit(tc, 0, 0, hash, sizeof(hash),
                                 hash, sizeof(hash)));           /* :2428 */

    /* :2430-2432 — vs2 nil, vs3 the block. */
    S_STEP(tc_sign_add_vote_one(tc, 1u, S_PRECOMMIT, NULL, 0u, &zero, true));
    S_STEP(tc_sign_add_vote_one(tc, 2u, S_PRECOMMIT, hash, sizeof(hash),
                                &psh, true));
    S_CHECK(tc->apply_calls == 0, "halt1: committed on 20 of 40");

    /* :2433-2434 — "we receive this later, but vs3 might receive it earlier
     * and with ours will go to commit!": signed NOW, at round 0, before
     * `incrementRound` at :2436. A vote is ~9.5 KB: heap. */
    precommit4 = (cmt_vote_t *)calloc(1u, sizeof(*precommit4));
    if (precommit4 == NULL) {
        tc_release(tc);
        return 1;
    }
    if (tc_sign_vote(tc, &tc->vss[3], S_PRECOMMIT, hash, sizeof(hash), &psh,
                     true, precommit4) != 0) {
        free(precommit4);
        tc_release(tc);
        return 1;
    }
    tc_increment_round(tc, 1u, 4u);                              /* :2436 */

    /* :2438-2443 — timeout to new round. */
    if (tc_ensure_new_timeout(tc, 1, 0,
                              cmt_config_precommit(&tc->config, 0),
                              CMT_ROUND_STEP_PRECOMMIT_WAIT) != 0 ||/* :2439 */
        tc_fire_timeout(tc) != 0 ||
        tc_ensure_new_round(tc, 1, 1) != 0) {                    /* :2443 */
        free(precommit4);
        tc_release(tc);
        return 1;
    }

    /* :2452-2454 — "we timeout and prevote our lock": round 1's proposer is
     * vs2 and no proposal comes, so the propose timeout expires. */
    if (tc_ensure_new_timeout(tc, 1, 1,
                              cmt_config_propose(&tc->config, 1),
                              CMT_ROUND_STEP_PROPOSE) != 0 ||
        tc_fire_timeout(tc) != 0 ||
        tc_ensure_vote(tc, 1, 1, S_PREVOTE) != 0 ||              /* :2453 */
        tc_validate_prevote(tc, 1, hash, sizeof(hash)) != 0) {   /* :2454 */
        free(precommit4);
        tc_release(tc);
        return 1;
    }
    S_CHECK(tc->apply_calls == 0, "halt1: committed before the late vote");

    /* :2456-2457 — "now we receive the precommit from the previous round". */
    if (tc_add_votes(tc, precommit4, 1u) != 0) {
        free(precommit4);
        tc_release(tc);
        return 1;
    }
    free(precommit4);

    /* :2459-2460 — "receiving that precommit should take us straight to
     * commit". The reference's `ensureNewBlock` checks the height; WHICH
     * block is checked too, because it must be the round-0 lock. */
    S_CHECK(tc->apply_calls == 1, "halt1: the late precommit did not commit");
    S_STEP(tc_ensure_new_block(tc, 1));                          /* :2460 */
    S_STEP(tc_ensure_new_block_header(tc, 1, hash, sizeof(hash)));
    S_STEP(tc_fire_timeout(tc));      /* the commit timeout — see :447 */
    S_STEP(tc_ensure_new_round(tc, 2, 0));                       /* :2462 */
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
        { "lock_pol_unlock_on_unknown_block",
          s_lock_pol_unlock_on_unknown_block },
        { "lock_pol_safety1",                 s_lock_pol_safety1 },
        { "lock_pol_safety2",                 s_lock_pol_safety2 },
        { "propose_valid_block",              s_propose_valid_block },
        { "set_valid_block_on_delayed_prevote",
          s_set_valid_block_on_delayed_prevote },
        { "set_valid_block_on_delayed_proposal",
          s_set_valid_block_on_delayed_proposal },
        { "process_proposal_accept",          s_process_proposal_accept },
        { "extend_vote_called_when_enabled",
          s_extend_vote_called_when_enabled },
        { "verify_vote_extension_not_called_on_absent_precommit",
          s_verify_vote_extension_not_called_on_absent_precommit },
        { "prepare_proposal_receives_vote_extensions",
          s_prepare_proposal_receives_vote_extensions },
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
        { "start_next_height_correctly_after_timeout",
          s_start_next_height_correctly_after_timeout },
        { "reset_timeout_precommit_upon_new_height",
          s_reset_timeout_precommit_upon_new_height },
        { "halt1",                            s_halt1 },
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
