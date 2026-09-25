/**
 * Nodus — cometbft @709fd12b C port, wave R2-BYZ: the MULTI-NODE byzantine
 * partition scenario, ported from `consensus/byzantine_test.go:300-458`
 * (`TestByzantineConflictingProposalsWithPartition`), plus two C-ONLY
 * scenarios the driver makes cheap; and, from R3 wave W3 package P0, two
 * more C-ONLY scenarios — no reference row, see their own comment block
 * above their functions — that satisfy OBLIGATION atlas-dec-
 * 247e5c0e9c6a5d02b258a026c34870cd, the multi-node counterpart of
 * test_cmt_cs.c's `s_part_set_bound_continues_the_round`.
 *
 * The driver — N fixtures, a connectivity matrix and a router standing in
 * for the reactor — is `test_cmt_multinode.h`, which carries its own
 * sixteen header items (M1-M16). The single-node fixture under each node
 * is `test_cmt_common.h`, which carries twelve more. READ BOTH: what this
 * file cannot see is mostly a property of those two, not of the scenarios.
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
 * And, the OBLIGATION pair: that a byzantine proposer PLUS byzantine
 * voters (a forged +2/3) driving a BlockID whose part-set header this
 * port's own bound refuses does NOT stop EVERY honest node — each signs
 * a nil precommit in that round, completes the step, never FAULTs, and a
 * later honest round still commits (`b_part_set_bound_round_recovers`);
 * and that when the forged +2/3 is a PRECOMMIT majority, the FOURTH
 * refusal site (enterCommit) parks the node at COMMIT with no block,
 * forever, rather than FAULTing or fabricating one
 * (`b_part_set_bound_commit_site_stalls`).
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
 * scenario, freed between scenarios (including on the failure path); the
 * two OBLIGATION scenarios add nothing new (one block each, not two).
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
 * The driver's sixteen (M1-M16) and the fixture's twelve all apply. These
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
 * The rest are the two OBLIGATION scenarios' own (R3 W3 P0, no reference
 * row — see the comment block above their functions for what each proves
 * line by line):
 * S10. THIS PORT'S OWN THIRD TICKER MODE (`MN_TICKER_QUIESCENT`, driver
 *      M16) HAS NO GO LINE — the reference's honest tickers are wall
 *      clocks (byzantine_test.go:308-314), which M5's mock rule already
 *      approximates as "never fires except NEW_HEIGHT" because every
 *      OTHER scenario's honest nodes complete a REAL, valid proposal on
 *      messages alone and never need a timeout. THIS scenario's proposal
 *      can NEVER complete either, for its own reason: the real block has
 *      exactly ONE part, and `g_mn_bad_total` names 9 (`TC_PARTS_CAP +
 *      1`, the parts_cap clause this scenario drives — see that
 *      variable's own doc comment), so parts 2 through 9 are named but
 *      never exist and nothing beyond the first is ever sent. So LEAVING
 *      round 0 needs an actual timeout: once +2/3
 *      precommits exist for anything, `cmt_cs_enter_precommit_wait` arms
 *      CMT_ROUND_STEP_PRECOMMIT_WAIT (state.go:1567-1592 →
 *      cmt_cs.c:2586-2617), and only that timer's own expiry moves the
 *      round forward (state.go:1002-1009 → cmt_cs.c:1703-1711,
 *      `cmt_cs_handle_timeout`'s PRECOMMIT_WAIT case calling
 *      `cmt_cs_enter_new_round(..., round + 1)`) — the mock rule never
 *      fires it, so round 0 would stall forever under M5 alone.
 *      The byzantine node's OWN rule (M5, "whenever armed and the node
 *      has no queued work": `mn_timers`, `cmt_cs_has_work`,
 *      cmt_cs.c:1393-1400) is per-node and BLIND to the rest of the
 *      network — right for THIS ONE round-0 transition, wrong for every
 *      LATER round in this topology: at most one message crosses a link
 *      per `mn_round` (M6), and node 2 hears from node 1 only by
 *      relaying through node 3 (no 1-2 link, below), so a real message
 *      can take several rounds to cross while an otherwise-idle honest
 *      node fires immediately and prevotes nil before it arrives.
 *      CONFIRMED BY RUNNING, not derived by hand (BUILDER class cannot
 *      run this driver): giving every honest node this rule for the
 *      WHOLE scenario got round 0 right and then produced 21 rounds with
 *      zero commits, ending in a per-link sent-log overflow
 *      (test_cmt_multinode.h's MN_SENT_CAP) from the resulting churn.
 *      MN_TICKER_QUIESCENT fires a non-NEW_HEIGHT timeout only when the
 *      WHOLE network produced no activity during the immediately
 *      PRECEDING `mn_round` — no `cmt_cs_step` reported `worked`, no
 *      timer fired anywhere, and no message was newly QUEUED anywhere,
 *      whether by gossip or by one of the byzantine overrides' by-hand
 *      sends (both route through `mn_deliver_vote` / `mn_deliver_
 *      proposal` / `mn_deliver_part`, driver M16 — search their own
 *      notes). THE BRANCH ITSELF CONSULTS ONLY THIS PRECEDING ROUND'S
 *      VERDICT — it does NOT re-check `cmt_cs_has_work` on the firing
 *      node or on anyone else in the CURRENT round. The guarantee that it
 *      therefore never pre-empts a message still in flight holds anyway,
 *      for a reason the mechanism supplies rather than a bare assertion:
 *      after a round with NO activity, nothing changed anywhere, so the
 *      FOLLOWING round has nothing new for any node to gossip and no
 *      queue holds anything unconsumed — `mn_round`'s own per-node order
 *      is step, THEN timers, THEN mirror, THEN gossip (test_cmt_
 *      multinode.h:1786-1863). The only events that following round can
 *      produce are the quiescent timers themselves firing, and each of
 *      those queues a tock on its OWN node's timer queue, which
 *      `cmt_cs_step` does not consume until the round AFTER THAT. So the
 *      earliest a message can be newly produced is one full round after
 *      the timers that produced it fired — never in the same round as a
 *      message it might otherwise have raced, and never before it.
 *      Exactly round 0's own problem, and exactly what the byzantine
 *      "when idle" rule ignored about every later one. Nodes 1, 2 and 3
 *      run under this mode from immediately after the star settles
 *      (S11), before either `mn_run_until` call; node 0 (byzantine) keeps
 *      M5's own "when idle" rule unchanged, and scenario 2 uses no timer
 *      at all (S13).
 * S11. THE SCENARIO RUNS IN TWO PHASES, AND THE ORDER IS LOAD-BEARING —
 *      an earlier, ONE-PHASE version of this scenario (heal links added
 *      BEFORE the ticker switch) deadlocked: node 3's gossip could then
 *      deliver a forged copy of validator 1's (or 2's) own vote BEFORE
 *      that validator's OWN timeoutPropose fired, so the OWN real nil
 *      prevote — arriving second — was the one refused as a self-conflict
 *      (cmt_cs.c:3368-3379), leaving nothing armed to move that node past
 *      PREVOTE, ever. CONFIRMED BY RUNNING, not derived by hand (BUILDER
 *      class cannot run this driver); the two-phase order below exists
 *      specifically to avoid it.
 *      PHASE 1 — star only (0-1, 0-2, 0-3), nodes 1-3 already switched to
 *      MN_TICKER_QUIESCENT (S10). The star delivers the bad-header
 *      PROPOSAL directly to every honest node, and EACH refuses it at
 *      setProposal's OWN bound the MOMENT it arrives — BEFORE any vote,
 *      its own or anyone else's (cmt_cs.c:3078-3096, clearing
 *      `rs.proposal` at :3093; the parts_cap clause this scenario drives,
 *      `g_mn_bad_total`'s own doc comment). Confirmed by the
 *      ORCHESTRATOR's run after delta 6: nodes 1, 2 AND 3 all hit this
 *      site while still at PROPOSE — EVERY honest node's FIRST refusal,
 *      not node 3's alone.
 *      The star ALSO delivers node 0's own vote pair for the bad BlockID
 *      to every honest node directly, and the two forged votes
 *      (validator 1's and validator 2's own keys, `mn_byz_decide_bad_
 *      header`) to node 3 ALONE — it hardcodes node 3 as their only
 *      direct recipient — so only node 3 starts with a path to both.
 *      Node 3 therefore ALSO holds three votes for the SAME bad BlockID
 *      (node 0's own, both forged) — already +2/3 of four — before it
 *      has cast anything of its own: this crosses the `addVote/prevote`
 *      threshold and refuses there too (cmt_cs.c:3603-3619), STILL at
 *      PROPOSE (confirmed by the ORCHESTRATOR's run after delta 6: node
 *      3's setProposal and first addVote/prevote refusals both land
 *      before its own prevote exists at all). Nodes 1 and 2, holding
 *      only node 0's one vote for the bad id at this point, do not cross
 *      +2/3 and reach no further site yet.
 *      Once the star goes quiet, EVERY honest node's timeoutPropose fires
 *      (S10) and each signs its OWN real nil prevote into its OWN
 *      validator slot as the FIRST occupant there. At node 3 this
 *      RE-TRIGGERS `addVote/prevote`'s own gate for the same,
 *      already-known polka block — a SECOND hit, now at PREVOTE
 *      (confirmed by the ORCHESTRATOR's run after delta 6) — and, once
 *      its timeoutPrevote next fires at quiescence, `enterPrecommit`'s
 *      polka-for-a-block-it-doesn't-have branch and that refusal
 *      (cmt_cs.c:2559-2579), now at PRECOMMIT — a nil precommit. This is
 *      phase 1's own wait (node 3 alone, `b_own_pc_range_t{3, 4, 0}`).
 *      Nodes 1 and 2, with only node 0's vote for the bad id and their
 *      own nil (two of four, never a polka), stay parked at PREVOTE with
 *      nothing armed beyond the timeoutPropose they already spent: the
 *      star alone can never finish round 0 for them, which is why phase
 *      2 exists.
 *      NODE 0 (byzantine, M4) is OUT OF SCOPE for the obligation (S6: its
 *      own outcome is never asserted) but, for the record and so this
 *      text does not contradict it: `mn_byz_decide_bad_header`'s peers
 *      loop excludes `node->index` (test_cmt_multinode.h:2310-2314), so
 *      neither the bad proposal nor node 0's own by-hand prevote/
 *      precommit pair is ever delivered to node 0 itself — its own
 *      `rs.proposal` stays NULL and it never reaches setProposal. Node 0
 *      sees the bad BlockID only through VOTES that arrive at its OWN
 *      vote set from elsewhere — including the two forged votes, which
 *      come back from node 3 over the 0-3 link once node 3 holds them
 *      (M9 (b): node 3 is not byzantine, so it gossips to every connected
 *      peer, node 0 included). Confirmed by the ORCHESTRATOR's run after
 *      delta 6: node 0 reaches TWO refusal sites, `addVote/prevote` (step
 *      4, and again at step 6) and `enterPrecommit` (step 5), then signs
 *      its own nil precommit, which self-conflicts with the bad
 *      precommit it sent BY HAND. Which three votes cross node 0's own
 *      +2/3 for the bad BlockID is not derived here. Checks (i)-(iv)
 *      never look at node 0.
 *      PHASE 2 — the heal (3-1, 3-2; NO 1-2 link, ever). THE MECHANISM IS
 *      THE REFERENCE'S OWN PEER-MAJ23 RULE, NOT A DRIVER GOSSIP RACE —
 *      verified against the pinned reference (vote_set.go) and the port,
 *      after GDB attribution (the ORCHESTRATOR's run after delta 6)
 *      showed nodes 1 and 2 reaching the SAME three sites node 3 does,
 *      which the ordering rationale above does not by itself explain.
 *      Once connected, node 3's `mn_query_maj23` (test_cmt_multinode.h:
 *      1608) → `mn_announce_maj23` (test_cmt_multinode.h:1500) tells node
 *      1 and node 2 "I have +2/3 prevotes for
 *      the bad BlockID at round 0" — `cmt_hvs_set_peer_maj23` →
 *      `cmt_vote_set_set_peer_maj23` (cmt_vote_set.c:718-778; vote_set.go
 *      `SetPeerMaj23`:334-367): the bad block's `votesByBlock` entry,
 *      which already exists at node 1 and node 2 from node 0's own vote
 *      delivered directly in phase 1, becomes PEER-VOUCHED
 *      (`peer_maj23 = true`, cmt_vote_set.c:778, vote_set.go :359). When
 *      the forged copy of validator 1's prevote then arrives at node 1
 *      (M9 (b), gossiped from node 3's own set — test_cmt_multinode.h:
 *      170-172, 1125-1187), it CONFLICTS with node 1's own real nil vote
 *      already at slot 1 — but the ONLY drop condition is "conflicting
 *      AND NOT peer-vouched" (cmt_vote_set.c:477, vote_set.go :285), and
 *      this block IS vouched now (its `votesByBlock` entry already
 *      exists, from node 0's own vote delivered in phase 1, so this
 *      takes the "bv already exists, not dropped" branch, NOT the
 *      "start tracking a new blockKey" one), so the vote is added
 *      (cmt_vote_set.c:475-482, 511-515, vote_set.go :283-289, :304-309).
 *      Once that crosses node 1's OWN +2/3 for the bad block (its vote,
 *      the forged copy just added, and — once node 3 relays the OTHER
 *      forged copy too — the third), every vote already recorded for
 *      that block is copied over the canonical `votes[]` array
 *      (cmt_vote_set.c:517-529, vote_set.go :311-323) — THIS is what
 *      REPLACES node 1's own real nil prevote in slot 1 with the forged
 *      one; it is the reference's own majority-copy rule, not a race in
 *      the driver's delivery order (the ordering rationale two
 *      paragraphs up is still why the heal must come AFTER the ticker
 *      switch — if the forged copy could arrive before node 1 ever cast
 *      a real vote there would be nothing in the slot to conflict with,
 *      and this whole mechanism, which NEEDS a conflict to detect, would
 *      not run at all). `cmt_cs_try_add_vote`'s own comment block (read
 *      for the primary scenario, S1) applies again: the vote IS added,
 *      the transition IS run, and — because the address matches node
 *      1's OWN — the conflict is logged as "found conflicting vote from
 *      ourselves" (cmt_cs.c:3375) and returned CMT_REJECT with no
 *      evidence report (cmt_cs.c:3368-3379); that silence is only about
 *      the EVIDENCE POOL, not about the vote set, which had already been
 *      updated by the time this check runs. The SAME transition that
 *      runs on every successful add sees the now-complete polka: the
 *      `addVote/prevote` refusal (again, once per triggering arrival),
 *      then `enterPrecommit`'s polka-for-a-block-it-doesn't-have branch
 *      and ITS refusal once timeoutPrevote fires at the next quiescence
 *      — a nil precommit, at node 1 exactly as at node 3 in phase 1.
 *      Symmetric for node 2. Combined with phase 1's setProposal refusal
 *      (already reached by all three honest nodes, above), nodes 1 and 2
 *      now ALSO reach `addVote/prevote` and `enterPrecommit` — so EVERY
 *      HONEST NODE REACHES ALL THREE REFUSAL SITES, but not in the same
 *      phase: setProposal in PHASE 1 for all three; `addVote/prevote` and
 *      `enterPrecommit` in PHASE 1 for node 3 alone, and only in PHASE 2
 *      for nodes 1 and 2.
 *      Consequence to STATE: after phase 2, each honest node's round-0
 *      PREVOTE slot for validators 1 and 2 holds the FORGED copy (the
 *      majority-copy rule above), while its own PRECOMMIT slot holds its
 *      real nil precommit — this scenario never forges precommits
 *      (`g_mn_forge_precommits_too = false`), so check (ii)'s lookup by
 *      validator index, ON THE PRECOMMIT SET, is on a slot nothing
 *      overwrites; this is WHY (ii) asserts precommits and never
 *      prevotes. (Scenario 2 forges precommits too and stalls at
 *      enterCommit instead — S13, untouched by this correction.)
 *      Node 1's and node 2's own real votes ALSO travel back to node 3
 *      over the same heal links and collide there with the forged copies
 *      node 3 has held since phase 1 — a GENUINE conflict at node 3 (its
 *      own address is validator 3, matching neither), so `cs_add_vote`
 *      reports both pairs through the ordinary path (cmt_cs.c:3381-3393,
 *      state.go:2094). Node 0 (byzantine) reports conflicting pairs
 *      too, for the same reason — again, out of scope (S6). None of this
 *      is asserted by count: the obligation does not ask for one, and a
 *      PRIOR version of this file's derived count check was itself
 *      refuted by running (S12) — it is recorded here only so a future
 *      reader is not surprised by a nonzero `conflict_calls` at node 3
 *      (or node 0). Phase 2's wait is every honest node
 *      (`b_own_pc_range_t{1, n, 0}`).
 *      Net effect on the obligation's "logs the refusal once per site
 *      reached": EVERY honest node — 1, 2 AND 3 — reaches all THREE sites
 *      (setProposal, addVote/prevote, enterPrecommit), split across the
 *      two phases: setProposal in PHASE 1, for all three, the moment the
 *      star delivers the proposal; addVote/prevote and enterPrecommit in
 *      PHASE 1 for node 3 alone (it alone starts with +2/3 on the bad
 *      BlockID) and only in PHASE 2 for nodes 1 and 2 (once the heal's
 *      peer-maj23 mechanism gives them the same +2/3). "Once per site
 *      reached" means once per REFUSAL EVENT, and `addVote/prevote`'s own
 *      gate re-triggers on every later prevote for an already-known polka
 *      block (node 3 alone hits it TWICE in phase 1 — S10/S11's own
 *      trace), which this file does not count (S14: no log line is
 *      asserted, by name or by number). Every honest node
 *      still signs a nil round-0 precommit, never FAULTs, and (checked
 *      separately, (iv)) still commits an honest proposal in a later
 *      round.
 * S12. WITHDRAWN, TWICE. An earlier version of this item derived an EXACT
 *      conflict count from S11's topology alone; running the scenario
 *      refuted it once (the gossip carried forged votes further than
 *      that derivation assumed), and the mechanism changed AGAIN when
 *      S11 was rewritten into the two-phase ordering above (now it is
 *      node 3 — and node 0 — not nodes 1 or 2, that report genuine
 *      conflicts, and the reason is the reference's peer-maj23 majority
 *      rule, not the driver's gossip order — see S11's phase 2). No
 *      conflict-count check is reinstated either time: the obligation
 *      does not ask for one, and this file has twice shown that
 *      hand-deriving one here is unreliable. S11 states what running the
 *      scenario showed, descriptively, instead.
 * S13. `b_part_set_bound_commit_site_stalls` NEEDS NO TIMER AT ALL. Its
 *      whole path is driven by `cs_add_vote_precommit`'s own state.go:
 *      2342-2346 chain the moment the third (forged) precommit completes
 *      a +2/3 majority, while processing node 0's override's own queued
 *      messages. Node 3's own vote is never cast in this scenario — it
 *      never reaches PREVOTE — consistent with not asserting liveness of
 *      nodes 1 and 2 either: this scenario is SAFETY-only. THE PRECOMMIT
 *      LEG CANNOT BE ANYTHING ELSE: a node holding +2/3 PRECOMMITS for a
 *      BlockID it can never complete has no path out of COMMIT except
 *      finalizing that exact block — `cmt_cs_enter_commit` completes the
 *      step and returns (cmt_cs.c:2717) but `cmt_cs_try_finalize_commit`
 *      declines with no block every time it is tried (cmt_cs.c:2751-2754)
 *      — so "commits a later honest proposal" in the obligation's own
 *      words is unsatisfiable for THIS node once it is parked here; the
 *      stall this scenario asserts is the only sound outcome, not a
 *      weaker substitute for one. Whether the obligation's wording should
 *      be read as applying only to the prevote leg, or amended, is the
 *      operator's question, not this file's to answer (raised
 *      separately, not here).
 * S14. NEITHER OBLIGATION SCENARIO ASSERTS A LOG LINE. `nodus_log_shim.c`
 *      writes to stderr with no ring buffer, so "logs the refusal once
 *      per site" is not counted in-process without a hook in cmt_cs.c,
 *      outside this wave's whitelist. Both assert the STATE each site
 *      leaves (both names NULL, the step, the vote cast) instead.
 *
 * ── CLOSURE against byzantine_test.go:300-458 ──────────────────────────
 *   :301        N := 4                              → mn_net_new(4, 0)
 *   :307-309    randConsensusNet(N, ..., mockTicker) → mn_net_new: four
 *               tc_setup over one genesis, mock tickers (driver M5)
 *   :311-314    real ticker for css[0]              → nodes[0].ticker_mode
 *               = MN_TICKER_WHEN_IDLE (driver M5, M16)
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

/** C-ONLY, no reference row: every node in [lo, hi)'s OWN round-`round`
 *  precommit vote is RECORDED in its own round-`round` precommit set —
 *  node i IS validator i (test_cmt_multinode.h:2503-2504), so "own" is
 *  looked up directly by validator index i. A step check alone is NOT
 *  equivalent: `enterPrecommit`'s nil-vote path (cmt_cs.c:2572; state.go:
 *  1560) signs through `cmt_cs_sign_add_vote`, which puts the vote on the
 *  INTERNAL queue rather than storing it directly — "our own vote goes
 *  onto the internal queue. It is handled on a LATER step... this
 *  function never transitions" (cmt_cs.c:4048-4050, enqueued at :4055) —
 *  and `cmt_cs_step` serves AT MOST ONE event per call, one source per
 *  poll (cmt_cs.c:1469). So a node's `rs.step` can already read
 *  `>= CMT_ROUND_STEP_PRECOMMIT` for one or more `mn_run_until` polls
 *  before the queued vote is dequeued and folded into the vote set —
 *  waiting on the step alone can stop the driver one event too early,
 *  with a node's own vote still in flight and absent from its set. The
 *  [lo, hi) RANGE, rather than a fixed node or a fixed "every honest
 *  node", lets `b_part_set_bound_round_recovers`'s two phases (S11) share
 *  ONE predicate: phase 1 waits on node 3 alone ([3, 4)), phase 2 on
 *  every honest node ([1, n)) — no second, near-duplicate predicate.
 *  Used to stop the instant the vote in question is actually there,
 *  rather than at a hand-picked round count (`feedback_no_timeout_tuning`).
 */
typedef struct {
    size_t  lo;
    size_t  hi;
    int32_t round;
} b_own_pc_range_t;

static bool b_pred_own_precommit_range_recorded(const mn_net_t *net,
                                                const void *ctx)
{
    const b_own_pc_range_t *a  = (const b_own_pc_range_t *)ctx;
    size_t                  hi = (a->hi <= net->n) ? a->hi : net->n;
    size_t                  i;

    for (i = a->lo; i < hi; i++) {
        cmt_vote_set_t   *pc;
        const cmt_vote_t *v = NULL;

        pc = cmt_hvs_precommits(mn_cs(&net->nodes[i])->rs.votes, a->round);
        if (cmt_vote_set_get_by_index(pc, (int32_t)i, &v) != CMT_OK ||
            v == NULL) {
            return false;
        }
    }
    return true;
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

/* ══ OBLIGATION atlas-dec-247e5c0e9c6a5d02b258a026c34870cd: the
 * part-set-bound multi-node scenarios (R3 wave W3, package P0) ═══════
 *
 * NO REFERENCE ROW — the reference allocates whatever `Total` a header
 * asks for (`types.NewPartSetFromHeader`) and so never reaches this
 * port's own bound (cmt_part_set.c:276-282); there is nothing to port.
 * These two scenarios are the multi-node half of test_cmt_cs.c's
 * `s_part_set_bound_continues_the_round`, which that test's own HOW IT
 * CAN LIE names as open (test_cmt_cs.c:3799-3801) and which the OBLIGATION
 * requires before R3 W3 makes the reactor live. The driver primitive is
 * `mn_byz_decide_bad_header` (test_cmt_multinode.h) — read its header
 * first; these two comments assume it. HOW IT CAN LIE for both is at the
 * top of this file, S10-S14 (kept there so it sits with S1-S9 rather than
 * being split across two lists).
 *
 * CLOSURE, by C-side refusal site — no Go line ports to any of these (the
 * bound is this port's own), so this maps the reference line each site's
 * OWN comment already cites to the C line these scenarios exercise it at:
 *   state.go:1938-1946 (setProposal)      → cmt_cs.c:3078-3096 — ONLY the
 *     parts_cap clause reaches this site; scenario 1's Total=9 does, and
 *     is refused here (clearing `rs.proposal`, cmt_cs.c:3093). The
 *     MAX_PARTS clause CANNOT reach it BY CONSTRUCTION: state.go:1931-
 *     1936's OWN max_parts check (cmt_cs.c:3060-3068, `(max_bytes-1)/
 *     BlockPartSizeBytes + 1` = 336 for this fixture's default block)
 *     precedes setProposal's part-set-bound attempt and REJECTS any
 *     Total above 336 first — 1601 (CMT_PART_SET_MAX_PARTS) is bigger
 *     than 336, so scenario 2's Total=1602 is refused at cmt_cs.c:3067
 *     BEFORE `rs.proposal` is ever assigned, and never reaches
 *     setProposal's OWN bound site at all. The single-node
 *     `s_part_set_bound_continues_the_round` (test_cmt_cs.c:3803-3854 —
 *     reported here, not this file's to fix) doesn't even reach THAT
 *     gate: its own proposal (test_cmt_cs.c:3814) is a REAL, valid one
 *     and `rs.proposal` IS assigned to it; the 1602 Total never appears
 *     in a proposal message there at all — it appears only in the VOTES
 *     the test signs directly for a different, unknown BlockID
 *     (`tc_sign_add_votes_range`, test_cmt_cs.c:3835-3836), driving the
 *     addVote/prevote refusal, never setProposal's.
 *   state.go:2290-2328 (addVote/prevote)  → cmt_cs.c:3603-3619
 *   state.go:1542-1560 (enterPrecommit)   → cmt_cs.c:2559-2579
 *   state.go:1629-1656 (enterCommit)      → cmt_cs.c:2689-2717
 *   state.go:2336-2362 (cs_add_vote_precommit's catch-up chain, scenario 2
 *     only — the forged precommit majority drives this) → cmt_cs.c:3690-3719
 *   state.go:1675-1683 (tryFinalizeCommit declines with no block, scenario
 *     2 only)                             → cmt_cs.c:2751-2754
 *   state.go:2082-2090 (a conflicting vote from ourselves, silently
 *     rejected — BUT the vote is already folded into the vote set and
 *     its transition already run before this check ever sees it, via the
 *     peer-vouched path of vote_set.go :285/:326 → cmt_vote_set.c:477;
 *     exercised at nodes 1 and 2 in scenario 1's phase 2, S11, not
 *     asserted by name) → cmt_cs.c:3368-3379
 *   state.go:2094 (a GENUINE conflicting pair, reported — exercised at
 *     node 3 and at node 0 in scenario 1's phase 2, S11, not asserted by
 *     count) → cmt_cs.c:3381-3393
 *   vote_set.go:334-367 SetPeerMaj23 (reactor.go's VoteSetMaj23 handling)
 *     — the mechanism scenario 1's phase 2 actually runs on, not a driver
 *     gossip-ordering race (S11) → driver `mn_announce_maj23`/
 *     `mn_query_maj23` (test_cmt_multinode.h:1500, :1608) →
 *     `cmt_hvs_set_peer_maj23` → cmt_vote_set.c:718-778
 */

/**
 * OBLIGATION atlas-dec-247e5c0e9c6a5d02b258a026c34870cd, scenario 1 of 2
 * — the ROUND RECOVERS, IN TWO PHASES (S11). A byzantine proposer plus
 * byzantine voters (node 0's override, forging validator 1's and
 * validator 2's own keys) drive +2/3 prevotes for a BlockID whose
 * part-set header this port's own bound refuses — at node 3 alone in
 * phase 1 (it alone starts with a direct path to both forged votes); at
 * nodes 1 and 2 too, once phase 2's heal lets node 3's peer-maj23
 * announcement vouch for the bad block in their own vote sets, so the
 * forged votes it then gossips are added and win the canonical slot
 * instead of being dropped (vote_set.go's own peer-maj23 rule, S11 —
 * NOT a driver gossip-ordering race). EVERY honest node therefore
 * reaches all THREE refusal sites (setProposal, addVote/prevote,
 * enterPrecommit — cmt_cs.c:3090, :3616, :2572), signs a nil precommit
 * in round 0, completes the step, never FAULTs, and a LATER, HONEST
 * round still commits on every honest node.
 */
static int b_part_set_bound_round_recovers(void)
{
    mn_net_t         *net = mn_net_new(4u, 0);
    b_own_pc_range_t  wait_precommit;
    int64_t           height1 = 1;
    cmt_block_id_t    committed[MN_MAX_NODES];
    cmt_vote_set_t   *pv3;
    size_t            i;

    if (net == NULL) {
        fprintf(stderr, "part_set_bound_round_recovers: setup failed\n");
        return 1;
    }
    g_mn_forge_precommits_too = false;
    /* The parts_cap clause (g_mn_bad_total's own doc comment): TC_PARTS_
     * CAP + 1 = 9 reaches setProposal's own bound site, unlike scenario
     * 2's MAX_PARTS + 1. */
    g_mn_bad_total = (uint32_t)TC_PARTS_CAP + 1u;
    net->nodes[0].tc->cs->decide_proposal = mn_byz_decide_bad_header;

    B_CHECK(tc_expected_proposer(net->nodes[0].tc, 1, 0) == 0u,
            "part_set_bound_round_recovers: the derived (1,0) proposer is "
            "not node 0");
    B_STEP(tc_check_proposer(net->nodes[0].tc, 1, 0));

    /* PHASE 1 (S11) — star only. */
    mn_connect(net, 0u, 1u);
    mn_connect(net, 0u, 2u);
    mn_connect(net, 0u, 3u);

    B_STEP(mn_net_start(net));
    B_CHECK(net->nodes[0].byz_hash_set,
            "part_set_bound_round_recovers: the byzantine proposer never "
            "ran");
    /* The override has fired; reset both globals now so an early return
     * BELOW this point never leaves either set for whatever scenario runs
     * next — narrower than before, not zero: a failure at `mn_net_start`
     * or at the `byz_hash_set` check just above still happens BEFORE this
     * reset runs, so it would still leave the globals set; `main` (below)
     * continues after a failed scenario, so only a scenario appended
     * AFTER this one that also uses `mn_byz_decide_bad_header` without
     * setting its own values first would ever see them — no scenario
     * does that today. */
    g_mn_forge_precommits_too = false;
    g_mn_bad_total            = 0u;

    /* S10/S11 — node 3 has cast no round-0 vote at all yet: it is still
     * on the mock ticker (M5), and its OWN settle ran before node 0
     * (started last, M13) ever sent it anything. Still observed under
     * the ORIGINAL mock rule — the switch to quiescent happens next. */
    pv3 = cmt_hvs_prevotes(mn_cs(&net->nodes[3])->rs.votes, 0);
    B_CHECK(mn_count_votes(pv3) == 0,
            "part_set_bound_round_recovers: node 3 already has a round-0 "
            "prevote");
    B_CHECK(mn_cs(&net->nodes[3])->rs.step < CMT_ROUND_STEP_PREVOTE,
            "part_set_bound_round_recovers: node 3 is already past "
            "PROPOSE");

    /* S10/S11 — nodes 1-3 switch to the quiescent ticker HERE, BEFORE the
     * heal links exist: each casts its OWN real nil prevote while the
     * star alone is quiet, and only THEN can a forged copy of it arrive
     * (phase 2) and find the slot already occupied. */
    for (i = 1u; i < net->n; i++) {
        net->nodes[i].ticker_mode = MN_TICKER_QUIESCENT;
    }

    /* Phase 1's wait: node 3 ALONE, [3, 4) — it alone has a direct path
     * to both forged votes (S11), so only node 3 can reach +2/3 on the
     * bad BlockID from the star alone; nodes 1 and 2 are still at
     * PREVOTE at this point. */
    wait_precommit.lo    = 3u;
    wait_precommit.hi    = 4u;
    wait_precommit.round = 0;
    B_STEP(mn_run_until(net, b_pred_own_precommit_range_recorded,
                        &wait_precommit, (int64_t)MN_BUDGET_ROUNDS,
                        "node 3's own round-0 precommit is recorded"));

    /* PHASE 2 (S11) — the heal. Nodes 1 and 2 already hold their OWN
     * real round-0 prevote as the first occupant of their own slot
     * (the wait above would not have passed otherwise for node 3, and
     * the same quiescent rule already gave 1 and 2 the same chance
     * before any link to node 3 existed). */
    mn_connect(net, 3u, 1u);
    mn_connect(net, 3u, 2u);

    /* Phase 2's wait: EVERY honest node, [1, n). */
    wait_precommit.lo = 1u;
    wait_precommit.hi = net->n;
    B_STEP(mn_run_until(net, b_pred_own_precommit_range_recorded,
                        &wait_precommit, (int64_t)MN_BUDGET_ROUNDS,
                        "every honest node's own round-0 precommit is "
                        "recorded"));

    /* (i) every honest node refused the byzantine proposal at
     * setProposal's OWN bound site (the parts_cap clause this scenario
     * drives, g_mn_bad_total's own doc comment), which CLEARS `rs.
     * proposal` (cmt_cs.c:3090, :3093) rather than never setting it —
     * true here because Total=9 passes setProposal's own max_parts gate
     * (cmt_cs.c:3065-3067) and is refused only once `cs_new_part_set_
     * from_header` is actually tried; scenario 2's Total=1602 fails that
     * EARLIER gate instead and never reaches this site at all (see that
     * scenario's own header). */
    for (i = 1u; i < net->n; i++) {
        B_CHECK(mn_cs(&net->nodes[i])->rs.proposal == NULL,
                "part_set_bound_round_recovers: an honest node kept the "
                "byzantine proposal");
    }

    /* (ii) EVERY honest node: both names NULL, step at or past PRECOMMIT
     * (test_cmt_cs.c:3855's own assertion shape), its own round-0
     * precommit PRESENT and nil. Looked up directly by validator index
     * (node i IS validator i, test_cmt_multinode.h:2503-2504) — NOT by
     * looping `k` from 0 to `mn_count_votes() - 1` the way an earlier
     * version of this check did: `cmt_vote_set_get_by_index`'s second
     * argument is a VALIDATOR index (cmt_vote_set.h:541-554), while
     * `mn_count_votes` returns the number of votes PRESENT, which is the
     * WRONG bound — with only 2 of 4 votes present, a loop over k=0..1
     * can never reach validator index 3, so a real nil vote sitting there
     * was invisible to the old check and it read as "not nil" instead of
     * "not found". */
    for (i = 1u; i < net->n; i++) {
        cmt_cs_t         *ncs = mn_cs(&net->nodes[i]);
        cmt_vote_set_t   *pc  = cmt_hvs_precommits(ncs->rs.votes, 0);
        const cmt_vote_t *own = NULL;

        B_CHECK(ncs->rs.proposal_block == NULL &&
                ncs->rs.proposal_block_parts == NULL,
                "part_set_bound_round_recovers: an honest node has a part "
                "set from somewhere");
        B_CHECK(ncs->rs.step >= CMT_ROUND_STEP_PRECOMMIT,
                "part_set_bound_round_recovers: an honest node did not "
                "advance past the refusal");
        B_CHECK(cmt_vote_set_get_by_index(pc, (int32_t)i, &own) == CMT_OK &&
                own != NULL,
                "part_set_bound_round_recovers: an honest node's own "
                "round-0 precommit is not recorded");
        B_CHECK(own->block_id.hash_len == 0u,
                "part_set_bound_round_recovers: an honest node's own "
                "round-0 precommit is not nil");
    }

    /* (iii) — restated; `mn_run_until` already enforces it (any FAULT
     * ends the run above). */
    for (i = 0u; i < net->n; i++) {
        B_CHECK(net->nodes[i].fault_rc == 0,
                "part_set_bound_round_recovers: a node recorded a "
                "fault_rc");
    }

    /* (iv) round 0 committed nothing yet, and a LATER round commits an
     * honest proposal on every honest node. Nodes 1-3 are STILL on
     * MN_TICKER_QUIESCENT here (never switched back): round 1's honest
     * proposer's REAL, complete proposal and every honest vote for it
     * reach every node on messages alone, exactly as every non-OBLIGATION
     * scenario's do, because quiescence only ever fires a timeout once
     * nothing further CAN be delivered (S10) — it cannot pre-empt a
     * message this round still has in flight. */
    B_STEP(mn_run_until(net, b_pred_all_honest_committed, &height1,
                        (int64_t)MN_BUDGET_ROUNDS,
                        "every honest node commits height 1 in a later "
                        "round"));
    for (i = 1u; i < net->n; i++) {
        B_CHECK(mn_committed_block_id(&net->nodes[i], 1, &committed[i]),
                "part_set_bound_round_recovers: an honest node has no "
                "height-1 commit");
        B_CHECK(committed[i].hash_len == (size_t)CMT_TMHASH_SIZE,
                "part_set_bound_round_recovers: a committed BlockID has no "
                "hash");
    }
    for (i = 2u; i < net->n; i++) {
        B_CHECK(memcmp(committed[i].hash, committed[1].hash,
                       (size_t)CMT_TMHASH_SIZE) == 0,
                "part_set_bound_round_recovers: FORK across honest nodes");
    }
    B_CHECK(memcmp(committed[1].hash, net->nodes[0].byz_hash[0],
                   (size_t)CMT_TMHASH_SIZE) != 0,
            "part_set_bound_round_recovers: the byzantine BlockID was "
            "committed");
    for (i = 0u; i < net->n; i++) {
        B_CHECK(net->nodes[i].tc->decode_misses == 0,
                "part_set_bound_round_recovers: a node failed to decode an "
                "assembled block");
    }

    printf("     part_set_bound_round_recovers: %lld rounds of %d\n",
           (long long)net->rounds, MN_BUDGET_ROUNDS);
    mn_net_free(net);
    return 0;
}

/**
 * OBLIGATION atlas-dec-247e5c0e9c6a5d02b258a026c34870cd, scenario 2 of 2
 * — THE COMMIT SITE STALLS. The same construction as scenario 1, but
 * with a DIFFERENT Total (`g_mn_bad_total` = `CMT_PART_SET_MAX_PARTS + 1`
 * = 1602, the MAX_PARTS clause, not scenario 1's parts_cap one — see that
 * variable's own doc comment), and node 3 ALSO receives forged PRECOMMITS
 * for validators 1 and 2 — a forged +2/3 that
 * exceeds even a single byzantine node's own budget (node 0 never
 * precommits honestly through its own state machine at all, M4, so the
 * two forged votes plus node 0's own by-hand one are the ONLY three of
 * four this scenario ever produces for that BlockID). This exercises
 * enterCommit's own refusal (cmt_cs.c:2706), the fourth and last of the
 * four sites — the one `s_part_set_bound_continues_the_round` and the
 * first scenario above never reach, because both drive only a PREVOTE
 * majority, never a PRECOMMIT one.
 *
 * SAFETY-only, per the design: nodes 1 and 2's liveness is not asserted
 * either way (S13).
 */
static int b_part_set_bound_commit_site_stalls(void)
{
    mn_net_t      *net = mn_net_new(4u, 0);
    cmt_block_id_t bid;
    size_t         i;

    if (net == NULL) {
        fprintf(stderr, "part_set_bound_commit_site_stalls: setup failed\n");
        return 1;
    }
    g_mn_forge_precommits_too = true;
    /* The MAX_PARTS clause (g_mn_bad_total's own doc comment): CMT_PART_
     * SET_MAX_PARTS + 1 = 1602 is refused INSIDE cmt_new_part_set_from_
     * header before setProposal's own bound site is ever reached, unlike
     * scenario 1's parts_cap clause. */
    g_mn_bad_total = (uint32_t)CMT_PART_SET_MAX_PARTS + 1u;
    net->nodes[0].tc->cs->decide_proposal = mn_byz_decide_bad_header;

    B_STEP(tc_check_proposer(net->nodes[0].tc, 1, 0));
    mn_connect(net, 0u, 1u);
    mn_connect(net, 0u, 2u);
    mn_connect(net, 0u, 3u);
    B_STEP(mn_net_start(net));
    B_CHECK(net->nodes[0].byz_hash_set,
            "part_set_bound_commit_site_stalls: the byzantine proposer "
            "never ran");
    /* The override has fired; reset both globals now so an early return
     * BELOW this point never leaves either set for whatever scenario runs
     * next — narrower than before, not zero: a failure at `mn_net_start`
     * or at the `byz_hash_set` check just above still happens BEFORE this
     * reset runs, so it would still leave the globals set; `main` (below)
     * continues after a failed scenario, so only a scenario appended
     * AFTER this one (there is none today — this is the LAST case in
     * `main`'s table) that also used `mn_byz_decide_bad_header` without
     * setting its own values first would ever see them. */
    g_mn_forge_precommits_too = false;
    g_mn_bad_total            = 0u;

    /* S13 — every step below is vote-driven; no timer, no extra link. */
    B_STEP(mn_run_rounds(net, (int64_t)B_NEVER_ROUNDS,
                         "part_set_bound_commit_site_stalls: settle"));

    /* node 3: both names NULL (enterCommit's own refusal, cmt_cs.c:2706),
     * parked at COMMIT with commit_round 0, and never actually committed
     * — tryFinalizeCommit declines with no block (cmt_cs.c:2751-2754). */
    B_CHECK(mn_cs(&net->nodes[3])->rs.proposal_block == NULL &&
            mn_cs(&net->nodes[3])->rs.proposal_block_parts == NULL,
            "part_set_bound_commit_site_stalls: node 3 has a part set from "
            "somewhere");
    B_CHECK(mn_cs(&net->nodes[3])->rs.step == CMT_ROUND_STEP_COMMIT,
            "part_set_bound_commit_site_stalls: node 3 is not parked at "
            "COMMIT");
    B_CHECK(mn_cs(&net->nodes[3])->rs.commit_round == 0,
            "part_set_bound_commit_site_stalls: node 3's commit_round is "
            "not 0");
    B_CHECK(!mn_committed_block_id(&net->nodes[3], 1, &bid),
            "part_set_bound_commit_site_stalls: node 3 committed height 1 "
            "with no block");
    B_CHECK(net->nodes[3].fault_rc == 0,
            "part_set_bound_commit_site_stalls: node 3 recorded a "
            "fault_rc");

    /* No node — the byzantine one included — ever committed the
     * byzantine hash. It is the only hash that exists here, so this is
     * "nobody committed anything". */
    for (i = 0u; i < net->n; i++) {
        if (mn_committed_block_id(&net->nodes[i], 1, &bid)) {
            B_CHECK(memcmp(bid.hash, net->nodes[0].byz_hash[0],
                           (size_t)CMT_TMHASH_SIZE) != 0,
                    "part_set_bound_commit_site_stalls: a node committed "
                    "the byzantine block");
        }
    }
    printf("     part_set_bound_commit_site_stalls: %lld rounds\n",
           (long long)net->rounds);
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
          b_c_only_partition_never_healed },
        { "part_set_bound_round_recovers",
          b_part_set_bound_round_recovers },
        { "part_set_bound_commit_site_stalls",
          b_part_set_bound_commit_site_stalls }
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
