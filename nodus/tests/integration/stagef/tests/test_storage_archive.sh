#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_storage_archive.sh — the archive storage reward on a 7-node chain:
# the storage rule-set generation voted in (param 18 RULESET_GEN_ROLES =
# D4 since HF-6 slice 8c — param 16 RETIRED —, generation 3 -> 4 on top
# of the Nodus EVM generation), two storage nodes registered by
# their OWNERS (HF-6 owner/node split), the first archive segment
# published, probed over channel 0x72, reported and SETTLED from treasury
# pool 1, one node taken out by its owner and its bond released
# (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/decisions/2026-10-05-storage-reward-is-
# for-archive.md (K1 block count, K2/K5/K5a fail_streak, K3 samples, K4
# R = 3, K6 channel 0x72, K7 report window, K9/K9a grace, K10 generation
# 4 on GEN_EVM — its param 16 superseded by param 18, design rev 6 §8 and
# 2026-10-09-kurultay-16-hf6-storage-summary.md item 1);
# 2026-10-05-archive-reward-bytes-approved.md
# (segment root bytes item 1); 2026-10-04-storage-reward-approved.md (S(H),
# register / report / exit); design docs/plans/2026-10-05-archive-reward-
# design.md rev 4; nodus/docs/DEPLOY_RUNBOOK.md §2.2 (height-activated
# votes) and §2.6 (the storage node). HF-6 slice 6b-3 (plan tasks/hf6-
# slice6b-plan.md §2 "6b-3"): design docs/plans/2026-10-03-hf5-validator-
# owner-stake-design.md rev 6 §11 (REGISTER 7299 B owner-signed with the
# node's op-3 consent, EXIT 64 B by the row's owner, F2 owner-OR-key
# exclusion and the three-state verdict, the khan decisions of 2026-10-12
# under §11.7); decision 2026-10-09-kurultay-16-hf6-storage-summary.md
# (khan 1, 2 "kural (a)", 3; D2 (a): the genesis validators are owned by
# the compiled Foundation owner after the generation-4 edge). TEMPLATE:
# test_cmt_evm.sh — its helpers are copied (one build here: no OLD/NEW
# pair, no rolling upgrade), every new part is marked "storage:"; the
# test-owner gate is test_hf6_edge.sh's (6f-2).
#
# WHY THE SEGMENT IS REACHABLE AT ALL: a segment is one payday period of
# 24 epochs (DNA_V2_SEGMENT_BLOCKS = 24 × DNAC_EPOCH_LENGTH,
# shared/dnac/ledger_roots_v2.h) — 17 280 blocks at the shipped E = 720
# (unchanged, asserted in ledger_roots_v2.c), 360 at the short-epoch
# build's E = 15. Segment 1 = heights 1..P, due at the first storage
# boundary >= P + 2E (nodus_witness_v2_storage.c st_publish:
# DNAC_STORAGE_SEGMENT_DELAY_EPOCHS = 2).
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): the server and the CLI print one version
#      banner; the CLI's chain-config usage names "EVM_ACTIVE exactly <D>"
#      and "RULESET_GEN_ROLES exactly <D4>" (its compiled literals —
#      never a script literal) and it has the `storage` command; and
#      (step 0) every node's newest start logged the startup banner "HF-6
#      rule-set generation 4 vote D4 0x<D4> (param 18 RULESET_GEN_ROLES,
#      switch spec v1)" with the CLI's D4 (nodus_witness.c).
#      HF-6 6b-3: it also names "storage consent --owner" and
#      "storage register --keys" (an older CLI FAILs here).
#   1. The chain commits; node 3 (the pump) and the two storage nodes 4
#      and 5 claim their genesis leaves (100M NODUS each — the bond is
#      exactly 10^14 raw, DNAC_HF6_STORAGE_BOND_DEFAULT, the value of the
#      chain's STORAGE_BOND seam rtn_storage_bond_at). TEST-OWNER MODE
#      only: node 5 pays the test owner 10^14 + 2 × 10^8 raw (the bond and
#      two fees), the coin found by the spend's intent_id.
#   2. The storage generation's prerequisites, in order, each row
#      identical 7/7 and committed below its effective height: HF2_ACTIVE,
#      HF3_ACTIVE, RULESET_GEN2 (generation 1 -> 2), EVM_ACTIVE
#      (generation 2 -> 3 + the EVM domain; H >= initial_height + 256 + 5,
#      red-team F5 rule (g)). A fresh chain is generation 1, and param 18
#      is votable only while the EVM generation judges the vote, with
#      HF-2 on (nodus_witness_chain_config.c, CC_PARAM_RULESET_GEN_ROLES
#      rules (b), (c)), whose own vote needs HF-2, HF-3 and generation 2
#      (rules (b)/(c)/(e)) — so all five votes are needed, not two.
#   3. Before the storage vote (generation 3): node 4's key signs a VALID
#      storage consent (`storage consent` warns about the generation and
#      signs), and `storage register --keys <node 4> --consent <it>
#      --dry-run` is refused by the CLI's generation gate ("storage
#      registration exists only from generation 4") with no envelope
#      built — the gate runs before the consent re-check (nodus-cli.c
#      cmd_v2_stake), so the generation is what refuses; `storage status`
#      says "not registered".
#   4. RULESET_GEN_ROLES = D4 voted at H_s (H_s % E == 2: neither H_s - 1
#      nor H_s is a boundary — rules (d), (e) — and the first storage
#      boundary is E - 2 blocks after it); round 1 7/7; the row identical
#      7/7, committed < H_s. Crossing H_s (pumped to H_s - 7, then idle):
#      7/7 identical blocks AT H_s - 1, H_s, H_s + 1; every node logged
#      "HF-6: rule-set generation 3 -> 4 and the validator migration at
#      the end of height H_s - 1 (param 18 RULESET_GEN_ROLES, D4 0x<D4>)"
#      (the generation-4 vote also runs the validator migration);
#      `ruleset-info` 7/7 = generation 4. 6b-3: the seven
#      v2_validator_roles rows all carry owner_fp = the build's Foundation
#      owner (the K8 address, or STAGEF_HF6_OWNER_FP_HEX), identical 7/7 —
#      the premise of item 9's verdicts (D2 (a)), and what names the build
#      in the PASS line.
#   5. The OWNER registers (design rev 6 §11.3): for each storage node k,
#      the node's key signs `storage consent --owner <owner_k>` (op 3) and
#      the consent FILE round-trips — its eight lines are exactly the
#      container (nodus_v2_stake.h): op 3, chain_id = $BASE_DIR/v2_chain_id,
#      a zero subject, owner_k, consensus_pk = the node's nodus.pk bytes,
#      the requested expiry, a 4627-byte signature; then `storage register
#      --keys <owner_k> --consent <file>` (node 4: a dry run first, which
#      prints "node <fp_4>" and "owner <owner_4>"; then --submit).
#      owner_4 = node 4's OWN key (kind 1; its validator seat is excluded
#      for it by the KEY clause, the other six count). owner_5 = the
#      test owner (TEST-OWNER MODE) or node 5's own key (default). The
#      CLI's own owner check: a consent naming another owner than the
#      --keys identity is refused before anything is built — tried with
#      node 5's NODE identity as --keys (TEST-OWNER MODE: node 5's real
#      consent, which names the test owner; default: a node-5 consent
#      naming node 1). Each v2_storage_nodes row lands (ACTIVE, bond 10^14,
#      owner column = owner_k, fail_streak 0, grace_until 0), the registry
#      identical on 7/7; both are members of the first frozen set that
#      contains them (B_in), and B_in <= the publication boundary (else
#      the layout broke — FAIL, see HOW IT CAN LIE).
#   6. Segment 1 is published at exactly H_pub = the first storage
#      boundary >= 26E: one v2_storage_segments row (k 1, root,
#      published_height) identical on 7/7, no k = 2; its root equals
#      SHA3-512("NDS.STSEG.v1" (16 B) ‖ k (8 BE) ‖ count = P (4 BE) ‖
#      block_id[1] ‖ … ‖ block_id[P]) recomputed by this script from
#      node 1's v2_blocks (bytes item 1 at P = 24E).
#   7. `storage status` during the epoch after H_pub, on each storage
#      node's own port with its own key: "registry: ACTIVE, bond
#      100000000000000 raw, fail_streak 0", "owner: <owner_k>" (the RPC's
#      "payee" key, which holds the owner since HF-6), "grace_until: 0 (never in
#      grace)" — K9a: no set(H − E) at the first storage boundary, and a
#      segment published at a boundary is not counted at it
#      (nodus_witness_v2_storage.c nodus_storage_grace_counts,
#      st_grace_update) — no "IN GRACE" note, "2 member(s), this node IS a
#      member", "eligible segments this epoch: 1 (P blocks): 1". Node 1
#      (not registered) reads "not registered" / "is NOT a member".
#   8. Validators report: for the probing epoch Hx (H_pub, or the next
#      epoch when H_pub + 2E is a payday), the committed
#      v2_storage_reports rows (read after the window (Hx+E, Hx+E+⌊E/2⌋]
#      closed and before Hx + 2E prunes them) are identical on 7/7, carry
#      set_hash = the frozen S(Hx), and come from at least
#      ⌊N/2⌋ + 2 seats: with node 4's own seat among the reporters its
#      independent power (6b-2, key clause) is N_rep − 1 seats, and only
#      2·(N_rep − 1) > N makes its verdict decidable from here (equal
#      validator power — after the edge every validator holds 2M + 8M).
#   9. The settlement at B = Hx + 2E (not a payday) pays the storage
#      OWNERS (v2_storage.c st_settle, 6b-2): from ONE-statement snapshots
#      before and after B, budget = pool1 >> NODUS_V2_GEN_REWARD_DIVISOR_
#      LOG2, SHARE = ⌊budget / 2⌋ (two members of equal weight P; W counts
#      BOTH, a NO_EVIDENCE member included — design §11.6),
#        Σaccrual_post − Σaccrual_pre == (reward_pool_pre − reward_pool_post)
#                                        + (pool1_pre − pool1_post),
#      and node 4's owner (its own key) rose by EXACTLY SHARE — after the
#      generation-4 edge a node key earns no validator reward (every
#      validator's earnings go to its owner, the Foundation; test_hf6_edge
#      step 8 "no node-key row"), so its only accrual is the storage share.
#      DEFAULT MODE: pool 1 fell by exactly 2 × SHARE and node 5's owner
#      (its own key) rose by exactly SHARE — both members OK.
#      TEST-OWNER MODE: node 5 is owned by the SAME address as every
#      validator, so every report about it is owner-excluded, I = 0 and
#      2·I <= P_total — NO_EVIDENCE: pool 1 fell by exactly ONE SHARE
#      (node 5's share stays in pool 1), and node 5's owner (= the
#      Foundation owner) rose by exactly the reward-pool debit (the
#      validator reward, no storage share).
#  10. fail_streak stays 0 and grace_until 0 for both storage nodes on 7/7
#      after the settlement (an OK epoch with eligible blocks resets to 0 —
#      K5a; a NOT OK one would have written 1; NO_EVIDENCE leaves it
#      untouched — so in TEST-OWNER MODE "one share AND fail_streak 0" is
#      NO_EVIDENCE, neither OK (two shares) nor NOT OK (1)); pool 1 and
#      the block AT B identical 7/7.
#  11. The OWNER takes node 5 out (design §11.5): `storage exit --keys
#      <node 4>` is refused by the CLI (node 4 does not own node 5);
#      `storage exit --keys <owner_5> --node-fp <fp_5> --submit` → the row
#      EXITING with exit_height x; at B_rel = the first boundary >= x, on
#      7/7: the row RELEASED (x kept), node 4's row still ACTIVE, and
#      exactly ONE storage release coin (utxo_set output_index 201,
#      DNA_V2_STORAGE_EXIT_OUT_IDX) — to owner_5, amount 10^14, created at
#      B_rel, unlock_block = B_rel + 12·E (DNAC_STORAGE_EXIT_LOCK_EPOCHS;
#      st_release); the block AT B_rel and the final floor identical 7/7.
#
# THE TWO MODES — which one ran is printed in the PASS line
#   DEFAULT (STAGEF_HF6_OWNER_KEYS unset): the build compiles the K8
#     Foundation owner (a 2-of-3 whose keys nobody in the harness holds),
#     so no storage node can be registered under the validators' owner:
#     node 5 is owned by its own key like node 4, both settle OK, and the
#     PASS line says "NO_EVIDENCE: not run" — coverage that did not happen.
#   TEST-OWNER (STAGEF_HF6_OWNER_KEYS set): the build compiles a single
#     test key made BEFORE the build by stagef_hf6_owner.sh as the
#     Foundation owner (test_hf6_edge.sh 6f-2's mechanism); the seven
#     validators are owned by it after the edge, and node 5 is registered
#     under it — the Foundation-owned storage node of design §11.6, which
#     must settle NO_EVIDENCE on 7/7.
#
# WHAT IT REQUIRES
#   Compile flags — ONE short-epoch + short-grace build, nodus-server AND
#   nodus-cli from the SAME tree, with NODUS_EVM_ENABLED (the default of
#   the standalone non-Windows nodus build, nodus/CMakeLists.txt; the
#   storage generation is compiled only there — K10 (a)):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9, 18 are ERGONOMIC; param 14 is SAFETY.)
#   Environment, ALL exported BEFORE stagef_up_v2.sh (hashed into the
#   genesis document) unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     STAGEF_TREASURY_POOL1_RAW=1000000000000000   (suggested 10^15 raw =
#         10M NODUS; pool 1 is 0 on a harness chain without it, and a
#         settlement then pays nothing — SKIP below 2^17)
#     STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15  (read by
#         this script only)
#   Leave STAGEF_PAYOUT_INTERVAL_EPOCHS unset (24): the script steps off a
#   payday by itself; 1 (every boundary a payday) is a SKIP.
#   The tree must carry HF-6 through slice 6b-3 (the owner-signed storage
#   calls 6b-1, the owner-aware settlement 6b-2, this CLI 6b-3).
#   Tools: sqlite3, xxd, openssl with SHA3-512, ss.
#   Exact command sequence, DEFAULT MODE (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-shortepoch -DCMAKE_C_FLAGS="$F"
#     make -C <TREE>/nodus/build-shortepoch -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-shortepoch/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-shortepoch/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     export STAGEF_TREASURY_POOL1_RAW=1000000000000000
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_storage_archive.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   TEST-OWNER MODE (NO_EVIDENCE) — the same, plus BEFORE the build:
#     bash $S/stagef_hf6_owner.sh /tmp/hf6-owner <TREE>/nodus/build/nodus-server
#       (prints the owner's 128-hex fp and the exact
#        -DDNAC_HF6_FOUNDATION_OWNER="{0x..,…}" flag — 64 bytes, no spaces)
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-hf6own \
#           -DCMAKE_C_FLAGS="$F -DDNAC_HF6_FOUNDATION_OWNER={0x..,…}"
#     make -C <TREE>/nodus/build-hf6own -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN = that build's binaries
#     export STAGEF_HF6_OWNER_FP_HEX=<the helper's 128 hex>
#     export STAGEF_HF6_OWNER_KEYS=/tmp/hf6-owner/identity
#   (both read by this script only; STAGEF_V2_CANDIDATES is NOT needed
#   here). Set STAGEF_HF6_OWNER_KEYS and the scenario FAILs at its gate,
#   before step 1, unless nodus.pk (2592 B) / nodus.sk exist, SHA3-512(
#   nodus.pk) == STAGEF_HF6_OWNER_FP_HEX != the K8 default, and the owner
#   fp is no node's; a build that did not compile that owner FAILs at
#   step 4's owner check.
#   SKIP (rc 99): a binary missing / not executable, STAGEF_EPOCH_LENGTH
#   or the genesis epoch_length != 15, a grace variable != 15, not a
#   Comet cluster, no $BASE_DIR/v2_genesis.conf, pool 1 below 2^17,
#   payout_interval_epochs = 1, a tool missing, any split STAGEF_MODE
#   (the storage RPCs were not checked through a split core). A skip is
#   not a pass.
#
# WHAT IT LEAVES BEHIND
#   HF-2 ACTIVE, HF-3 ACTIVE, rule-set generation 2, the EVM generation 3
#   + EVM domain and the storage generation 4 (and with it the HF-6
#   validator migration: the seven validators owned by the build's
#   Foundation owner) — all one-way; five chain_config_history rows
#   (params 7, 8, 9, 14, 18). Node 4 a registered storage node (ACTIVE,
#   bond 10^14 locked, owned by its own key); node 5 RELEASED (its bond
#   back as one coin to its owner, locked 12 epochs, output_index 201);
#   segment 1 published, segment files under node<4,5>/data/segments (if
#   the holder finished exporting), pool 1 debited by one paying settlement
#   (and by whatever node 4 earned at the boundaries pumped across to the
#   release), the owners' accrual raised. The leaves of nodes 3, 4, 5
#   claimed. TEST-OWNER MODE: the test owner holds the change of its
#   funding coin (≈ 1.03 NODUS after two fees) and node 5's released bond.
#   Every pump fee in the reward pool. $BASE_DIR/storage/ (every CLI log
#   and the consent files). Nothing restarted. Tear down with
#   stagef_down.sh before re-running (leaves and params 9 / 14 / 18 are
#   single-use).
#
# HOW IT CAN LIE
#   - **E = 15, grace 15/15, BPY 20 prove the LOGIC, not 720 / 17 280.**
#     A segment is 360 blocks here and 17 280 in production; the segment
#     file, the 0x72 samples and the 0x73 fetch run over 360 heights. The
#     production segment length is held only by the compile-time assert
#     (ledger_roots_v2.c) and the unit tests run at the default E = 720
#     (test_storage_*; their own headers say most of them run at any
#     E >= 8 — test_storage_b2.c:144-147 — and test_storage_probe.c loops
#     E = 720 and 15; whether every one passes at E = 15 is NOT verified).
#   - **With the DEFAULT build the Foundation-owned case is UNREACHABLE.**
#     The default compiles the K8 Foundation owner, a 2-of-3 whose keys
#     are not in the harness, so no storage node can be registered under
#     the validators' owner: both nodes settle OK and NO_EVIDENCE (design
#     §11.6, the three-state verdict's third state) is NOT exercised —
#     the PASS line says "NO_EVIDENCE: not run". Only the TEST-OWNER
#     build (stagef_hf6_owner.sh + -DDNAC_HF6_FOUNDATION_OWNER and that
#     owner's -DDNAC_CFG_RULESET_GEN_ROLES_D) proves it
#     on 7/7; the PASS line names which build ran (the validators' owner
#     read from v2_validator_roles at step 4, not taken from the env).
#   - **NO_EVIDENCE vs NOT OK vs "unpaid"**: a NO_EVIDENCE node is merely
#     "unpaid" unless its fail_streak is ALSO seen frozen. Step 10 asserts
#     fail_streak 0 after the paying settlement (NOT OK writes 1, K5a);
#     the counter frozen at 3 (K5 return paused) is the unit test's
#     (test_storage_b2), not driven here.
#   - **Both storage nodes are also validators** (the runbook §2.6
#     "both-roles node"). A storage node that is NOT a validator (serving
#     0x72 to validators over a persistent peer, earning only the storage
#     reward) is NOT exercised. F2 is exercised only as: node 4's OWN
#     seat excluded by the key clause (its owner, its own key, owns no
#     seat), and in TEST-OWNER MODE all seven excluded by the owner
#     clause for node 5. Mixed cases (a member excluded by owner on some
#     seats and by key on another, the exact 2·I == P_total split) are
#     test_storage_b2's.
#   - **The v1-snapshot owner bridge (6b-2, khan A1) is not asserted.**
#     The paying settlement reads snapshot(Hx), frozen long after the
#     edge — ruleset 2, the owner from the entry (JUDGMENT from the
#     layout: Hx >= 390, the first ruleset-2 snapshot is B0 + E with B0 the
#     first boundary after H_s). The first settlement after the edge may
#     run the bridge at B0 + 2E with zero weights (no segment yet); a FAULT
#     there would stall the chain (FAIL), its verdicts are not read.
#   - **The generation-4 trigger is the real one** (param 18
#     RULESET_GEN_ROLES = D4, HF-6 slice 8c), voted ONCE the legal way:
#     its stateful refusals (a second vote, a param-16 row, HF-2 off,
#     another judging generation, H or H − 1 on a boundary) are
#     test_hf4_params.c's; a param-16 proposal and a mixed fleet (an old
#     binary refusing param 18 / accepting 16) are not exercised — one
#     build.
#   - **Only the honest path otherwise.** No NOT OK verdict, no
#     fail_streak + 1, no skip at 3, no K5 return, no grace > 0, no
#     handoff of a segment to another holder, no 0x73 fetch (every holder
#     has the blocks in its own store), no re-registration of the released
#     node (the B_rel + E rule is test_storage_reg's), no kind-3 (multisig)
#     owner (the CLI builds kind 1 only). No fault knob for the 0x72
#     serving side exists in the tree (no getenv in
#     nodus_witness_storage_*.c); SIGSTOP of a storage node here would
#     also freeze a validator for >= 7 blocks, beyond the 5-block cap
#     test_cmt_blocksync.sh keeps to stay clear of Rule N — so the NOT OK
#     path is not driven. Unit tests (test_storage_b2, test_storage_probe,
#     test_storage_reg) are its proof.
#   - **The settlement checks are arithmetic on committed tables:** the
#     conservation sum, the exact pool 1 debit and the exact accrual step
#     of each owner. "Exact SHARE for a node-key owner" rests on the
#     generation-4 rule that validator earnings go to the validator's
#     OWNER (the Foundation), never to a node key — if that rule broke,
#     the step FAILs (false RED, never a false PASS). The per-seat report
#     bitmaps are PRINTED, not judged; the verdict per member is proved by
#     the exact debit.
#   - **F1 / the verdict floor are asserted in SEAT counts** (>= ⌊N/2⌋ + 2
#     reporters), which equal power counts only because every validator
#     holds the same 2M bond + 8M self-delegation after the edge; nothing
#     here delegates.
#   - **The exit is checked at B_rel only.** The released coin's lock (12
#     epochs) is read from its unlock_block, not exercised by a spend; the
#     boundaries crossed by the pump to B_rel run settlements for node 4
#     (and node 5 while still a member) whose verdicts are not asserted —
#     the post-exit check reads status, owner, bond and exit_height, not
#     fail_streak.
#   - **No payday is observed:** the settlement boundary is stepped off a
#     payday on purpose (a payday empties the accrual table in the same
#     block); the accrual -> coin step is test_v2_rewards.sh's subject.
#   - **The segment root is re-derived HERE** from the formula as the C
#     implements it (ledger_roots_v2.c dna_v2_segment_root) — a
#     self-consistency check at P = 360, not an independent KAT.
#   - **The registration layout:** both nodes must be in a frozen set no
#     later than the publication boundary, so that K9a gives grace 0. If a
#     slow machine lands a registration after it, the scenario FAILS with
#     "layout broke" (a false RED, never a false PASS); the grace > 0 path
#     is not exercised.
#   - **A report that misses its 7-block window** (⌊E/2⌋) loses that
#     seat's report; if more than half miss, nothing settles and the pay
#     assertions FAIL — a false RED. The probing epoch, the window and the
#     settlement are crossed on IDLE production (no pump spend in flight)
#     for that reason. Probes are localhost and the probe deadline is wall
#     clock (10 s) — NTP is trivially in sync here.
#   - **Segment files** (`seg-1.ok`) and the per-node "probe of … OK" /
#     "report for H=… committed" lines are REPORTED, not asserted.
#   - Every wait is progress- and height-bounded (stagef_cmt_wait_height /
#     _wait_row), never a bare sleep (the 0.5 s / 1 s attempt-bounded
#     polls are the template's). rc 99 = SKIP, coverage that did not
#     happen.
#   - Duration: ≈ 460 blocks (JUDGMENT, not measured): pumped to the EVM
#     edge's window floor (≈ 262) and on to the publication boundary
#     (≈ 390), idle across the GEN2, EVM and storage edges (≈ 8 blocks
#     each) and across the probing epoch, report window and settlement
#     (≈ 30 blocks), then pumped to the release boundary (≤ E + 2) — on
#     the order of 1.5-2 h.
#   - Run results: the PRE-HF-6 shape (node-key registration, no exit)
#     PASSED on 2026-10-06 at bf1c4c1f (104 [ok]) and at 49c7218f (103
#     [ok]), both E=15 / BPY 20 / grace 15/15, P=360, pool 1 = 10^15
#     (orchestration ledger, the two HARNESS BİTTİ lines). THIS shape (HF-6
#     6b-3: owner registration, NO_EVIDENCE, exit) is written against the
#     source and NOT yet run, in either mode.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# storage: the storage RPCs (dnac_storage_status, ruleset-info) were not
# checked through a split core — SKIP (99) in every split mode.
stagef_split_skip_if --reason "storage RPCs not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE (dnac.h), value exactly D
PARAM_HF6=18               # storage: DNAC_CFG_RULESET_GEN_ROLES, value exactly D4
PARAM_RET16=16             # DNAC_CFG_RULESET_GEN_STORAGE — RETIRED; a row refuses PARAM_HF6
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM (= NODUS_RT_GEN_STORAGE_BASE)
GEN_STOR=4                 # storage: NODUS_RT_GEN_STORAGE (nodus_witness_runtime.c)
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
E_REQ=15
E="$E_REQ"
P=$(( 24 * E ))            # storage: DNA_V2_SEGMENT_BLOCKS = 24 x DNAC_EPOCH_LENGTH
DELAY=$(( 2 * E ))         # storage: DNAC_STORAGE_SEGMENT_DELAY_EPOCHS x E
REPORT_CLOSE=$(( E / 2 ))  # storage: the report window (H+E, H+E+⌊E/2⌋]
DIV_LOG2=16                # storage: NODUS_V2_GEN_REWARD_DIVISOR_LOG2 (v2_gen.h)
BOND=100000000000000       # storage: DNAC_HF6_STORAGE_BOND_DEFAULT = 10^6 x 10^8 —
                           # chain_config param 21's no-row value (this
                           # scenario votes no param 21; slice 8a)
ST_A=4                     # storage: the two storage nodes (both validators)
ST_B=5
# 6b-3: the owner/node split. The K8 Foundation address (dnac/include/dnac/
# dnac.h DNAC_HF6_FOUNDATION_OWNER, the hex in its own comment — the
# test_hf6_edge.sh constant) is the default build's compiled owner.
K8_OWNER=8eff7f418ab7a4432118ff99e21f2c3d1baf186200c148a3bba7d274499386ac970e267a9c9b3bbc05bfff1c62a72d63f72a555db780feeaaad4fb49ba9f7b89
OWNER=$(printf '%s' "${STAGEF_HF6_OWNER_FP_HEX:-$K8_OWNER}" | tr 'A-F' 'a-f')
OWN_KEYS="${STAGEF_HF6_OWNER_KEYS:-}"   # set = TEST-OWNER MODE (header)
CONSENT_AHEAD=150          # consent expiry = tip + this (> the envelope's tip + 90;
                           # the chain's window is 720, DNA_VALBIND_MAX_EXPIRY_BLOCKS)
OWNER_FUND=$(( BOND + 200000000 ))   # TEST-OWNER: the bond + 2 NODUS for the
                           # REGISTER and EXIT fees (each 400 000 units x 121 =
                           # 0.484 NODUS at the harness gas price)
EXIT_LOCK_EPOCHS=12        # storage: DNAC_STORAGE_EXIT_LOCK_EPOCHS (dnac.h)
EXIT_OUT_IDX=201           # storage: DNA_V2_STORAGE_EXIT_OUT_IDX (ledger_roots_v2.h)
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/storage"
N="$STAGEF_COMMITTEE_SIZE"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN=$SRV" "STAGEF_NODUSCLI_BIN=$CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs the short-epoch"
        echo "       build of a tree with the storage generation; see the header"
        exit 99
    fi
done
if [ "${STAGEF_EPOCH_LENGTH:-720}" != "$E_REQ" ]; then
    echo "[SKIP] STAGEF_EPOCH_LENGTH=${STAGEF_EPOCH_LENGTH:-720} — this scenario is laid out for"
    echo "       E=$E_REQ (-DDNAC_EPOCH_LENGTH=$E_REQ + STAGEF_EPOCH_LENGTH=$E_REQ before bring-up)"
    exit 99
fi
if [ "${STAGEF_CC_GRACE_ERGONOMIC:-720}" != 15 ] || [ "${STAGEF_CC_GRACE_SAFETY:-17280}" != 15 ]; then
    echo "[SKIP] STAGEF_CC_GRACE_ERGONOMIC=${STAGEF_CC_GRACE_ERGONOMIC:-720}" \
         "STAGEF_CC_GRACE_SAFETY=${STAGEF_CC_GRACE_SAFETY:-17280} — needs the short-grace"
    echo "       build (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15"
    echo "       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15) and both variables = 15"
    exit 99
fi
for t in sqlite3 xxd openssl ss; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the storage checks need it"
        exit 99
    fi
done
if [ "$(printf 'abc' | openssl dgst -sha3-512 2>/dev/null | awk '{print $NF}')" != \
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" ]; then
    # SHA3-512("abc") — the known-answer probe test_cmt_evm.sh uses
    echo "[SKIP] this openssl has no working SHA3-512 (the segment root re-derivation needs it)"
    exit 99
fi
[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active Stage F run (bring one up with stagef_up_v2.sh)"
ref_db0=$(stagef_node_chain_db 1)
[ -n "$ref_db0" ] && [ -s "$ref_db0" ] || die "no chain DB for node1"
has_v2=$(sqlite3 "$ref_db0" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster — bring it up with stagef_up_v2.sh"
    exit 99
fi
if [ ! -f "$CONF" ]; then
    echo "[SKIP] no $CONF — this scenario needs a stagef_up_v2.sh bring-up"
    exit 99
fi
CONF_E=$(sed -n 's/^epoch_length *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
if [ "$CONF_E" != "$E_REQ" ]; then
    echo "[SKIP] the genesis document says epoch_length=${CONF_E:-?}, this scenario needs $E_REQ"
    exit 99
fi
INTERVAL=$(sed -n 's/^payout_interval_epochs *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
case "$INTERVAL" in ''|*[!0-9]*) die "no payout_interval_epochs in $CONF" ;; esac
if [ "$INTERVAL" -le 1 ]; then
    echo "[SKIP] payout_interval_epochs=$INTERVAL: every boundary is a payday, so the settlement"
    echo "       boundary can never be read without a payday emptying the accrual table — leave"
    echo "       STAGEF_PAYOUT_INTERVAL_EPOCHS unset (24)"
    exit 99
fi
POOL1_0=$(sqlite3 "$ref_db0" "SELECT balance FROM v2_treasury WHERE pool_id = 1;" 2>/dev/null || echo ERR)
case "$POOL1_0" in ''|*[!0-9]*) die "treasury pool 1 unreadable on node1 ('$POOL1_0')" ;; esac
if [ "$POOL1_0" -lt 131072 ]; then
    echo "[SKIP] treasury pool 1 holds $POOL1_0 raw — below 2^17 the budget (pool1 >> $DIV_LOG2) cannot"
    echo "       pay two members a non-zero share; export STAGEF_TREASURY_POOL1_RAW (suggested"
    echo "       1000000000000000) BEFORE stagef_up_v2.sh"
    exit 99
fi
[[ "$OWNER" =~ ^[0-9a-f]{128}$ ]] || die "STAGEF_HF6_OWNER_FP_HEX is not 128 hex characters ('$OWNER')"
[ -s "$BASE_DIR/v2_chain_id" ] || die "the bring-up recorded no $BASE_DIR/v2_chain_id (the consent files are checked against it)"
CHAIN_HEX=$(tr -d '\n' < "$BASE_DIR/v2_chain_id" | tr 'A-F' 'a-f')
[[ "$CHAIN_HEX" =~ ^[0-9a-f]{64}$ ]] || die "$BASE_DIR/v2_chain_id is not 64 hex characters ('$CHAIN_HEX')"
mkdir -p "$LOGD"

# ── 6b-3: the TEST-OWNER gate (FAIL when asked for and impossible) ───
# Set = the operator asked for the NO_EVIDENCE leg, so every missing piece
# FAILs here, before the ≈ 1.5-2 h of steps 1-11 (test_hf6_edge.sh's 6f-2
# gate, without its cand1 part). Unset = the leg is NOT RUN (PASS line).
if [ -n "$OWN_KEYS" ]; then
    [ -s "$OWN_KEYS/nodus.pk" ] && [ -s "$OWN_KEYS/nodus.sk" ] || die \
        "STAGEF_HF6_OWNER_KEYS=$OWN_KEYS holds no nodus.pk / nodus.sk — make it with stagef_hf6_owner.sh BEFORE the build"
    [ "$(stat -c %s "$OWN_KEYS/nodus.pk")" = 2592 ] || die "$OWN_KEYS/nodus.pk is not 2592 bytes"
    [ "$OWNER" != "$K8_OWNER" ] || die \
        "STAGEF_HF6_OWNER_KEYS is set but STAGEF_HF6_OWNER_FP_HEX is the K8 default — the NO_EVIDENCE leg needs the test owner compiled in (stagef_hf6_owner.sh prints the flag)"
    own_kfp=$(stagef_sha3_512_hex "$OWN_KEYS/nodus.pk")
    [ "$own_kfp" = "$OWNER" ] || die \
        "SHA3-512($OWN_KEYS/nodus.pk) = ${own_kfp:0:16}… is not STAGEF_HF6_OWNER_FP_HEX ${OWNER:0:16}… — the owner key and the compiled owner must be one identity"
    echo "[ok] TEST-OWNER MODE armed: owner keys $OWN_KEYS (SHA3-512 = STAGEF_HF6_OWNER_FP_HEX ${OWNER:0:16}…) — node $ST_B will be registered under the validators' owner"
else
    echo "[info] TEST-OWNER MODE not armed (STAGEF_HF6_OWNER_KEYS unset) — node $ST_B registers under its own key; NO_EVIDENCE will NOT be exercised"
fi

# ── CAPABILITY GATE (FAIL, not skip) ────────────────────────────────
bin_version() {            # BIN KIND ("Server" | "CLI") -> X.Y.Z, "" if no banner
    local out re="Nodus $2 v([0-9]+\.[0-9]+\.[0-9]+)"
    out=$("$1" -h 2>&1 || true)
    if [[ "$out" =~ $re ]]; then echo "${BASH_REMATCH[1]}"; fi
}
SRV_VER=$(bin_version "$SRV" Server); CLI_VER=$(bin_version "$CLI" CLI)
[ -n "$SRV_VER" ] && [ -n "$CLI_VER" ] || die "a binary printed no version banner on -h (server '$SRV_VER', cli '$CLI_VER')"
[ "$SRV_VER" = "$CLI_VER" ] || die "the server ($SRV_VER) and the CLI ($CLI_VER) are not one build"
listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}
PROBE_PORT=""
for p in 14991 14992 14993 14994 14995 14996 14997 14998 14999; do
    if ! listening "$p"; then PROBE_PORT="$p"; break; fi
done
[ -n "$PROBE_PORT" ] || die "no free port in 14991..14999 for the usage probe"
# the compiled vote literals, from the CLI's own usage text (nodus-cli.c
# cmd_chain_config_propose: "  EVM_ACTIVE             exactly %llu",
# "  RULESET_GEN_ROLES      exactly %llu", printed before any connect)
usage_out=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
D_DEC=$(sed -n 's/^  EVM_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D_DEC="${D_DEC%%$'\n'*}"
D4_DEC=$(sed -n 's/^  RULESET_GEN_ROLES  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D4_DEC="${D4_DEC%%$'\n'*}"
[ -n "$D_DEC" ] && [ -n "$D4_DEC" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's chain-config usage does not name both 'EVM_ACTIVE exactly <D>' and 'RULESET_GEN_ROLES exactly <D4>'"; }
[ "$D_DEC" -gt 0 ] 2>/dev/null && [ "$D4_DEC" -gt 0 ] 2>/dev/null || die "a vote literal is not a positive int64 (D '$D_DEC', D4 '$D4_DEC')"
D_HEX=$(printf '%016x' "$D_DEC"); D4_HEX=$(printf '%016x' "$D4_DEC")
st_usage=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" storage 2>&1 || true)
# prefix match: HF-6 7a appended " | --owner <hex128>" inside the brackets
[[ "$st_usage" == *"storage status [--fp <hex128>"* ]] || {
    printf '%s\n' "$st_usage" >&2; die "the CLI has no 'storage' command (B2b-CLI)"; }
# 6b-3: the owner-side commands (nodus-cli.c cli_storage_usage). The
# consent's owner form is matched as a regex: since the kind-3 owner the
# usage reads "storage consent (--owner <owner_fp hex128> | --msig ...",
# the bracket is optional so either form of the line passes.
consent_re='storage consent \(?--owner'
[[ "$st_usage" =~ $consent_re && "$st_usage" == *"storage register --keys"* && \
   "$st_usage" == *"storage exit --keys"* ]] || {
    printf '%s\n' "$st_usage" >&2; die "the CLI has no owner-side 'storage consent | register --keys | exit --keys' (HF-6 6b-3)"; }
echo "[ok] capability gate: one build v$SRV_VER; EVM D = $D_DEC (0x$D_HEX), HF-6 D4 = $D4_DEC (0x$D4_HEX); 'storage' with the owner-side commands present"

# ── script-local helpers (test_cmt_evm.sh's, unless "storage:") ─────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_of()  { cat "$1/nodus.fp"; }                 # $1 = identity dir
fp_lc()  { tr 'A-F' 'a-f' < "$1/nodus.fp"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }

node_runs_srv() {          # storage: the one build (no OLD/NEW pair)
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$SRV")" ] && return 0
    done
    return 1
}

spend_intent() { awk -F= '/^  intent_id=/{print $2; exit}' "$1"; }

claim_leaf() {
    local keys="$1" node="$2" port db fp log h wrc
    port=$(stagef_tcp_port "$node"); db=$(db_of "$node"); fp=$(fp_of "$keys")
    log="$LOGD/claim_$(basename "$(dirname "$keys")").log"
    "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$db" \
        --keys "$keys" --submit "127.0.0.1:$port" > "$log" 2>&1 \
        || { cat "$log" >&2; die "v2-claim for $keys was refused (see $log)"; }
    h=$(stagef_cmt_wait_row "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$fp'
           AND token_id = zeroblob(64) AND amount > $STAGEF_PUMP_FEE_RAW;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "the claimed coin for $keys never appeared (wait rc=$wrc, tip $h)"
    echo "[ok] claimed the genesis leaf of $keys (tip $h)"
}

wait_applied() {
    local h wrc
    h=$(stagef_cmt_wait_row "$(db_of "$1")" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$2';") && wrc=0 || wrc=$?
    case "$wrc" in
        0) printf '%s\n' "$h" ;;
        1) die "chain STALLED waiting for spend ${2:0:16}... on node$1 (tip $h)" ;;
        *) die "spend ${2:0:16}... not included within 20 heights on node$1 (tip $h) — dropped, not delayed" ;;
    esac
}

PUMP_KEYS=$(node_keys 3)
PUMP_SEQ=0
pump_to() {
    local node="$1" target="$2" log intent port
    port=$(stagef_tcp_port "$node")
    while [ "$(tip_of "$node")" -lt "$target" ]; do
        PUMP_SEQ=$(( PUMP_SEQ + 1 ))
        log="$LOGD/pump_$PUMP_SEQ.log"
        "$CLI" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$PUMP_KEYS" \
            --to "$(fp_of "$PUMP_KEYS")" --amount all --count 1 \
            --submit "127.0.0.1:$port" > "$log" 2>&1 \
            || { cat "$log" >&2; die "pump spend $PUMP_SEQ was refused/failed on node$node (see $log)"; }
        intent=$(spend_intent "$log")
        [ "${#intent}" = 128 ] || { cat "$log" >&2; die "pump spend $PUMP_SEQ printed no intent_id"; }
        wait_applied "$node" "$intent" >/dev/null
    done
    echo "[ok] node$node tip $(tip_of "$node") >= $target (pumped)"
}

wait_all() {
    local n
    for n in $(seq 1 "$N"); do
        stagef_cmt_wait_height "$(db_of "$n")" "$1" 3 >/dev/null \
            || die "node$n never reached height $1"
    done
}

diff_at() {
    bash "$S_DIR/stagef_diff.sh" --at-height "$1" "$2" || exit 2
}

cc_row() {
    sqlite3 "$(db_of "$1")" \
        "SELECT new_value || '|' || commit_block || '|' || hex(tx_hash) FROM chain_config_history
          WHERE param_id = $2 AND effective_block = $3;" 2>/dev/null || echo ERR
}

wait_cc_row() {
    local param="$1" eff="$2" val="$3" maxh="$4"
    local h wrc first="" r n rows=""
    h=$(stagef_cmt_wait_row "$(db_of 1)" \
        "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $param
           AND effective_block = $eff AND new_value = $val;" 3 "$maxh") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "chain STALLED waiting for the param-$param row (effective $eff) on node1 (tip $h)" ;;
        *) die "the param-$param row (effective $eff) did not land on node1 within $maxh heights (tip $h)" ;;
    esac
    for n in $(seq 1 "$N"); do
        stagef_cmt_wait_height "$(db_of "$n")" "$h" 3 >/dev/null \
            || die "node$n never reached height $h (the param-$param row's detection height)"
        r=$(cc_row "$n" "$param" "$eff")
        rows="$rows node$n=$r"
        if [ -z "$first" ]; then first="$r"
        elif [ "$r" != "$first" ]; then die "the param-$param row (effective $eff) DIFFERS across nodes:$rows"; fi
    done
    case "$first" in ""|ERR) die "no param-$param row (effective $eff) readable";; esac
    [ "${first%%|*}" = "$val" ] || die "the param-$param row carries value ${first%%|*}, expected $val"
    CC_CB="${first#*|}"; CC_CB="${CC_CB%%|*}"
    echo "[ok] param-$param row (value $val, effective $eff, commit_block $CC_CB) identical on 7/7"
}

# cc_guard NODE — the EVM template's epoch-boundary guard (the CLI takes
# the committee of tip + 1 but the epoch of tip — nodus/BUGS.md): the
# proposer's tip t must be off a boundary and >= CC_GUARD_GAP before the
# next one, else pump to the next boundary + 1. Sets CCG_TIP / CCG_NB.
cc_guard() {
    local n="$1" t nb try
    for try in 1 2; do
        t=$(tip_of "$n")
        nb=$(( (t / E + 1) * E ))
        if [ $(( t % E )) != 0 ] && [ $(( nb - t )) -ge "$CC_GUARD_GAP" ]; then
            CCG_TIP="$t"; CCG_NB="$nb"
            return 0
        fi
        echo "[info] node$n's tip $t is on or within $CC_GUARD_GAP heights of the epoch boundary $nb — pumping to $(( nb + 1 )) before the proposal (attempt $try)"
        pump_to 1 $(( nb + 1 ))
        wait_all $(( nb + 1 ))
    done
    die "node$n's tip $(tip_of "$n") is still next to an epoch boundary after two guard pumps"
}

cc_guard_after() {
    local t
    t=$(tip_of "$1")
    [ $(( t + 1 )) -lt "$CCG_NB" ] || die \
        "the proposal from node$1 crossed into the epoch boundary $CCG_NB (tip $CCG_TIP -> $t): its approvals may straddle two epochs (the CLI committee/epoch edge, nodus/BUGS.md) — the layout broke, not the chain"
}

# propose NAME VALUE EFFECTIVE LOG — node 1's seat; FAIL unless round 1
# is 7/7 and the CLI reports acceptance.
propose() {
    local name="$1" val="$2" eff="$3" log="$4" prc=0
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$(node_keys 1)" \
        chain-config propose --param "$name" --value "$val" --effective "$eff" > "$log" 2>&1 || prc=$?
    cat "$log"
    cc_guard_after 1
    [ "$prc" = 0 ] || die "chain-config propose $name exited $prc (see $log)"
    grep -q "Round 1: $N/$N approved" "$log" || die "propose $name: round 1 was not $N/$N (see $log)"
    grep -q "proposal accepted" "$log" || die "propose $name did not report acceptance (see $log)"
}

# ruleset_info NODE — nodus-cli.c cmd_ruleset_info's lines (the EVM
# template's parser).
ruleset_info() {
    local n="$1" log rrc=0
    log="$LOGD/ruleset_info_node${n}_$(tip_of "$n").log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" ruleset-info > "$log" 2>&1 || rrc=$?
    RI_RC="$rrc"
    RI_OUT=$(cat "$log")
    RI_TIP=$(sed -n 's/^tip=\([0-9]*\) generation=.*/\1/p' "$log")
    RI_GEN=$(sed -n 's/^tip=[0-9]* generation=\([0-9]*\) .*/\1/p' "$log")
    RI_H=$(sed -n 's/^  RULESET_GEN2 height H=\([0-9]*\).*/\1/p' "$log")
    RI_D2=$(sed -n 's/^  node D2=0x\([0-9a-f]*\) .*/\1/p' "$log")
    RI_CLI_D2=$(sed -n 's/^  node D2=0x[0-9a-f]*  this CLI D2=0x\([0-9a-f]*\).*/\1/p' "$log")
}

# require_gen NODE GEN H — generation + the param-9 H + carried by this
# CLI as that compiled generation.
require_gen() {
    local n="$1" g="$2" hh="$3"
    ruleset_info "$n"
    [ "$RI_RC" = 0 ] || { printf '%s\n' "$RI_OUT" >&2; die "ruleset-info on node$n exited $RI_RC"; }
    [ "$RI_GEN" = "$g" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports generation '$RI_GEN' at tip $RI_TIP, expected $g"; }
    [ "$RI_H" = "$hh" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports RULESET_GEN2 H=$RI_H, expected $hh"; }
    [[ "$RI_OUT" != *MISMATCH* ]] || { printf '%s\n' "$RI_OUT" >&2; die "node$n's D2 differs from the CLI's"; }
    [[ "$RI_OUT" == *"this CLI carries it as compiled generation $g"* ]] || {
        printf '%s\n' "$RI_OUT" >&2; die "the CLI does not carry node$n's tuple as compiled generation $g"; }
}

# cross_edge LABEL H — pumped to H - PUMP_STOP_GAP (a generation-N
# envelope still pending past the switch would read as "dropped": false
# RED only), then idle across H - 1 / H / H + 1, compared 7/7 AT each.
cross_edge() {
    local label="$1" hh="$2" x
    pump_to 1 $(( hh - PUMP_STOP_GAP ))
    wait_all $(( hh + 1 ))
    for x in $(( hh - 1 )) "$hh" $(( hh + 1 )); do diff_at "$x" "$label-at-height-$x"; done
}

# ── storage: helpers ────────────────────────────────────────────────
is_payday() { [ $(( ($1 / E) % INTERVAL )) -eq 0 ]; }

# registry_dump NODE — the whole storage registry, canonical
registry_dump() {
    sqlite3 "$(db_of "$1")" \
        "SELECT lower(hex(node_fp)) || '|' || lower(hex(payee_fp)) || '|' || bond || '|' || status || '|' ||
                registered_height || '|' || exit_height || '|' || fail_streak || '|' || grace_until
           FROM v2_storage_nodes ORDER BY node_fp;" 2>/dev/null || echo ERR
}

# require_registry WHAT [B_STATUS B_EXIT_HEIGHT] — the registry identical
# on 7/7, exactly the two storage nodes, bond 10^14, the owner column
# (SQL name payee_fp — the HF-6 meaning is the owner, design rev 6 §11.2)
# = owner_k. Default (no B_STATUS): both ACTIVE (1), exit_height 0,
# fail_streak 0, grace_until 0. After node 5's exit (B_STATUS 3): node 4
# ACTIVE / exit_height 0, node 5 RELEASED with exit_height B_EXIT_HEIGHT,
# and fail_streak / grace_until NOT judged (the boundaries crossed to the
# release settle unasserted verdicts — header, HOW IT CAN LIE).
require_registry() {
    local what="$1" b_status="${2:-1}" b_xh="${3:-0}"
    local n ref d fp owner bond status rh xh fs gu nrow=0 want_owner want_st want_xh
    ref=$(registry_dump 1)
    [ "$ref" != ERR ] && [ -n "$ref" ] || die "$what: node1's storage registry is unreadable or empty"
    for n in $(seq 2 "$N"); do
        d=$(registry_dump "$n")
        [ "$d" = "$ref" ] || { printf 'node1:\n%s\nnode%s:\n%s\n' "$ref" "$n" "$d" >&2
            die "$what: node$n's storage registry differs from node1's"; }
    done
    while IFS='|' read -r fp owner bond status rh xh fs gu; do
        nrow=$(( nrow + 1 ))
        if [ "$fp" = "$FP_A" ]; then want_owner="$OWNER_A"; want_st=1; want_xh=0
        elif [ "$fp" = "$FP_B" ]; then want_owner="$OWNER_B"; want_st="$b_status"; want_xh="$b_xh"
        else die "$what: a registry row for an unexpected node ${fp:0:16}..."; fi
        [ "$owner" = "$want_owner" ] || die "$what: ${fp:0:16}...'s owner is ${owner:0:16}..., expected ${want_owner:0:16}..."
        [ "$bond" = "$BOND" ] || die "$what: ${fp:0:16}...'s bond is $bond, expected $BOND"
        [ "$status" = "$want_st" ] || die "$what: ${fp:0:16}... is status $status, expected $want_st (1 ACTIVE, 3 RELEASED)"
        [ "$xh" = "$want_xh" ] || die "$what: ${fp:0:16}... has exit_height $xh, expected $want_xh"
        if [ "$b_status" = 1 ]; then
            [ "$fs" = 0 ] || die "$what: ${fp:0:16}...'s fail_streak is $fs, expected 0 (OK resets it, NO_EVIDENCE leaves it; NOT OK would write 1)"
            [ "$gu" = 0 ] || die "$what: ${fp:0:16}...'s grace_until is $gu, expected 0 (K9a: no take-over)"
        fi
    done <<< "$ref"
    [ "$nrow" = 2 ] || die "$what: the registry holds $nrow rows, expected 2"
    if [ "$b_status" = 1 ]; then
        echo "[ok] $what: the storage registry is identical on 7/7 — nodes $ST_A and $ST_B ACTIVE, bond $BOND, owners ${OWNER_A:0:16}... / ${OWNER_B:0:16}..., fail_streak 0, grace_until 0"
    else
        echo "[ok] $what: the storage registry is identical on 7/7 — node $ST_A ACTIVE, node $ST_B status $b_status (exit at $b_xh), bond $BOND, owners ${OWNER_A:0:16}... / ${OWNER_B:0:16}..."
    fi
}

# consent_make NODE OWNER OUT LOG — `-i <node> storage consent` (6b-3):
# the storage NODE's key consents to registration under OWNER, expiry =
# its tip + CONSENT_AHEAD. Sets CS_EXP. FAIL unless the file is written.
consent_make() {
    local n="$1" own="$2" out="$3" log="$4" crc=0
    CS_EXP=$(( $(tip_of "$n") + CONSENT_AHEAD ))
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" -i "$(node_keys "$n")" \
        storage consent --owner "$own" --expiry "$CS_EXP" --out "$out" > "$log" 2>&1 || crc=$?
    cat "$log"
    [ "$crc" = 0 ] && [ -s "$out" ] || die "node$n's storage consent (owner ${own:0:16}...) was refused (rc $crc, see $log)"
}

# consent_file_ok FILE NODE OWNER EXPIRY — the consent container
# (nodus_v2_stake.h NODUS_V2_CONSENT_MAGIC: exactly these eight lines)
# carries what the node was asked to sign: op 3, this chain, a zero
# subject, OWNER, the node's own nodus.pk bytes, EXPIRY, a 4627-byte sig.
consent_file_ok() {
    local f="$1" n="$2" own="$3" exp="$4" pkhex zero
    local -a L=()
    pkhex=$(xxd -p "$(node_keys "$n")/nodus.pk" | tr -d '\n')
    zero=$(printf '%0128d' 0)
    mapfile -t L < "$f"
    [ "${#L[@]}" = 8 ] || die "consent $f has ${#L[@]} lines, expected 8"
    [ "${L[0]}" = "nodus-valbind-consent v1" ] || die "consent $f: bad magic line '${L[0]}'"
    [ "${L[1]}" = "op 3" ] || die "consent $f: '${L[1]}', expected 'op 3' (STORAGE_REGISTER)"
    [ "${L[2]}" = "chain_id $CHAIN_HEX" ] || die "consent $f names chain '${L[2]#chain_id }', the bring-up's is $CHAIN_HEX"
    [ "${L[3]}" = "subject $zero" ] || die "consent $f: the subject is not 64 zero bytes"
    [ "${L[4]}" = "owner $own" ] || die "consent $f names owner '${L[4]#owner }', expected $own"
    [ "${L[5]}" = "consensus_pk $pkhex" ] || die "consent $f: consensus_pk is not node$n's nodus.pk"
    [ "${L[6]}" = "expiry $exp" ] || die "consent $f: '${L[6]}', expected 'expiry $exp'"
    [[ "${L[7]}" =~ ^sig\ [0-9a-f]{9254}$ ]] || die "consent $f: the sig line is not 4627 bytes of hex"
    echo "[ok] consent file $f: op 3, this chain, zero subject, owner ${own:0:16}..., node$n's key, expiry $exp"
}

# st_register NODE KEYS CONSENT MODE LOG — `storage register` (6b-3) on
# NODE's port, MODE dry-run | submit. Sets RG_RC, RG_OUT.
st_register() {
    local n="$1" keys="$2" cf="$3" mode="$4" log="$5" port
    port=$(stagef_tcp_port "$n"); RG_RC=0
    if [ "$mode" = submit ]; then
        "$CLI" -s 127.0.0.1 -p "$port" storage register --keys "$keys" --consent "$cf" \
            --submit "127.0.0.1:$port" > "$log" 2>&1 || RG_RC=$?
    else
        "$CLI" -s 127.0.0.1 -p "$port" storage register --keys "$keys" --consent "$cf" \
            --dry-run > "$log" 2>&1 || RG_RC=$?
    fi
    RG_OUT=$(cat "$log")
    printf '%s\n' "$RG_OUT"
}

# status_of NODE KEYS_NODE [--fp FP] — `storage status` on NODE's own port
status_of() {
    local n="$1" kn="$2" log src=0
    shift 2
    log="$LOGD/status_node${kn}_on_node${n}_$(tip_of "$n").log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" -i "$(node_keys "$kn")" \
        storage status "$@" > "$log" 2>&1 || src=$?
    ST_RC="$src"
    ST_OUT=$(cat "$log")
}

# ── 0. preconditions: fresh cluster on this build ───────────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
# HF-6 8c: every node's newest start printed the CLI's D4 in its startup
# banner (nodus_witness.c — the runbook's 7/7 pre-vote comparison)
for n in $(seq 1 "$N"); do
    bl=$(grep -o 'HF-6 rule-set generation 4 vote D4 0x[0-9a-f]* (param 18 RULESET_GEN_ROLES, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-6 rule-set generation 4 vote D4 0x$D4_HEX (param 18 RULESET_GEN_ROLES, switch spec v1)" ] || die \
        "node$n's startup banner D4 line is '${bl:-none}', not the CLI's D4 0x$D4_HEX (param 18, switch spec v1)"
done
echo "[ok] 7/7 startup banners name param 18 and the CLI's D4 0x$D4_HEX"
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM" "$PARAM_RET16" "$PARAM_HF6"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
[ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM v2_storage_nodes;" 2>/dev/null || echo ERR)" = 0 ] \
    || die "node1's storage registry is not empty — this scenario needs a fresh bring-up"
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
FP_A=$(fp_lc "$(node_keys "$ST_A")"); FP_B=$(fp_lc "$(node_keys "$ST_B")")
FP_1=$(fp_lc "$(node_keys 1)")
for f in "$FP_A" "$FP_B" "$FP_1"; do [ "${#f}" = 128 ] || die "a node fingerprint is not 128 hex"; done
# 6b-3: the owners. Node 4 is owned by its own key; node 5 by the test
# owner (TEST-OWNER MODE) or by its own key.
OWNER_A="$FP_A"; KEYS_A=$(node_keys "$ST_A")
if [ -n "$OWN_KEYS" ]; then
    OWNER_B="$OWNER"; KEYS_B="$OWN_KEYS"
    for n in $(seq 1 "$N"); do
        [ "$(fp_lc "$(node_keys "$n")")" != "$OWNER" ] || die \
            "the test owner ${OWNER:0:16}... is node$n's own key — it must be a separate identity (stagef_hf6_owner.sh)"
    done
else
    OWNER_B="$FP_B"; KEYS_B=$(node_keys "$ST_B")
fi
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run $(readlink -f "$SRV"); pool 1 = $POOL1_0 raw; payday every $INTERVAL epochs; P = $P"

# ── 1. the chain commits; fund the pump + the storage nodes ─────────
stagef_cmt_diff_at_floor "pre-storage" || exit 2
claim_leaf "$PUMP_KEYS" 1
claim_leaf "$(node_keys "$ST_A")" "$ST_A"
claim_leaf "$(node_keys "$ST_B")" "$ST_B"
# 6b-3, TEST-OWNER MODE: the owner holds nothing on a fresh chain — node 5
# pays it the bond + two fees; the coin is found by the spend's intent_id
# (utxo_set.tx_hash), never by "the owner has a coin".
if [ -n "$OWN_KEYS" ]; then
    flog="$LOGD/fund_owner.log"; frc=0
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$ST_B")" v2-envelope spend \
        --keys "$(node_keys "$ST_B")" --to "$OWNER" --amount "$OWNER_FUND" \
        --submit "127.0.0.1:$(stagef_tcp_port "$ST_B")" > "$flog" 2>&1 || frc=$?
    cat "$flog"
    [ "$frc" = 0 ] || die "node$ST_B's funding spend to the test owner was refused (rc $frc, see $flog)"
    f_intent=$(spend_intent "$flog")
    [ "${#f_intent}" = 128 ] || die "the funding spend printed no intent_id (see $flog)"
    fh=$(stagef_cmt_wait_row "$(db_of "$ST_B")" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$f_intent'
           AND lower(owner) = '$OWNER' AND amount = $OWNER_FUND;") && fwrc=0 || fwrc=$?
    case "$fwrc" in
        0) ;;
        1) die "chain STALLED waiting for the test owner's funding coin (tip $fh)" ;;
        *) die "the test owner's funding coin was not included within 20 heights (tip $fh) — dropped, not delayed" ;;
    esac
    echo "[ok] the test owner holds a $OWNER_FUND-raw coin from node$ST_B (tip $fh)"
fi
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
stagef_cmt_diff_at_floor "storage-chain-committing" || exit 2

# ── 2. the prerequisites: HF-2, HF-3, generation 2, the EVM generation ─
cc_guard 1
H2=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF2_ACTIVE=1 effective H2=$H2"
propose HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
[ "$CC_CB" -lt "$H2" ] || die "the HF2 row committed at $CC_CB, not before its effective height $H2"
pump_to 1 $(( H2 + 1 ))
wait_all $(( H2 + 1 ))
stagef_cmt_diff_at_floor "past-HF2" || exit 2

cc_guard 1
H3=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF3_ACTIVE=1 effective H3=$H3"
propose HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
[ "$CC_CB" -lt "$H3" ] || die "the HF3 row committed at $CC_CB, not before its effective height $H3"
pump_to 1 $(( H3 + 1 ))
wait_all $(( H3 + 1 ))
stagef_cmt_diff_at_floor "past-HF3" || exit 2

require_gen 1 1 0
D2_HEX="$RI_D2"
[ "${#D2_HEX}" = 16 ] && [ "$D2_HEX" = "$RI_CLI_D2" ] || die "the node's D2 '$D2_HEX' and the CLI's '$RI_CLI_D2' are not one 16-hex literal"
D2_DEC=$(( 16#$D2_HEX ))
cc_guard 1
H4=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( (H4 - 1) % E )) = 0 ]; do H4=$(( H4 + 1 )); done   # param 9 rule (c)
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN2=$D2_DEC effective H4=$H4"
propose RULESET_GEN2 "$D2_DEC" "$H4" "$LOGD/propose_gen2.log"
wait_cc_row "$PARAM_GEN2" "$H4" "$D2_DEC" 20
[ "$CC_CB" -lt "$H4" ] || die "the RULESET_GEN2 row committed at $CC_CB, not before its effective height $H4"
cross_edge gen2 "$H4"
for n in $(seq 1 "$N"); do
    grep -q "rule-set generation 1 -> 2 at the end of height $(( H4 - 1 )) " "$(node_log "$n")" \
        || die "node$n logged no 'rule-set generation 1 -> 2 at the end of height $(( H4 - 1 ))' line"
    require_gen "$n" "$GEN_2" "$H4"
done
echo "[ok] rule-set generation 2 on 7/7 from H4=$H4"

cc_guard 1
HE=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_SAFETY + GRACE_MARGIN ))    # param 14: SAFETY grace
H_WIN=$(( INIT_H + 256 + WINDOW_MARGIN ))                        # EVM rule (g), red-team F5
[ "$HE" -ge "$H_WIN" ] || HE="$H_WIN"
while [ $(( (HE - 1) % E )) = 0 ]; do HE=$(( HE + 1 )); done     # EVM rule (f)
echo "[ok] tip $CCG_TIP — node1 proposes EVM_ACTIVE=$D_DEC effective HE=$HE (window floor $H_WIN)"
propose EVM_ACTIVE "$D_DEC" "$HE" "$LOGD/propose_evm.log"
wait_cc_row "$PARAM_EVM" "$HE" "$D_DEC" 20
[ "$CC_CB" -lt "$HE" ] || die "the EVM_ACTIVE row committed at $CC_CB, not before its effective height $HE"
cross_edge evm "$HE"
EVM_LINE="Nodus EVM: rule-set generation $GEN_2 -> $GEN_EVM and the EVM domain registered ACTIVE at the end of height $(( HE - 1 )) (D 0x$D_HEX)"
for n in $(seq 1 "$N"); do
    grep -qF "$EVM_LINE" "$(node_log "$n")" || die "node$n logged no '$EVM_LINE' line"
    require_gen "$n" "$GEN_EVM" "$H4"
done
echo "[ok] the EVM generation $GEN_EVM on 7/7 from HE=$HE"

# ── 3. storage: before the vote — the CLI's generation gate refuses ──
# 6b-3: the request is otherwise VALID (node 4's key consents to its own
# key as owner, inside the window), so the generation is the only reason
# left to refuse it: the gate runs before the consent re-check
# (nodus-cli.c cmd_v2_stake). Until 6b-3 this step called the 6b-1 stub
# (cmd_storage_tx_refused), which refused at every generation and never
# printed the gate's sentence — the step had lost its subject.
c_pre="$LOGD/consent_pre_vote_node$ST_A.txt"
consent_make "$ST_A" "$OWNER_A" "$c_pre" "$LOGD/consent_pre_vote_node$ST_A.log"
consent_file_ok "$c_pre" "$ST_A" "$OWNER_A" "$CS_EXP"
st_register "$ST_A" "$KEYS_A" "$c_pre" dry-run "$LOGD/register_pre_vote.log"
[ "$RG_RC" != 0 ] && [[ "$RG_OUT" == *"storage registration exists only from generation $GEN_STOR"* ]] \
    || die "storage register before the vote was not refused by the CLI's generation gate (rc $RG_RC, see $LOGD/register_pre_vote.log)"
[ -z "$(spend_intent "$LOGD/register_pre_vote.log")" ] || die "storage register before the vote built an envelope"
status_of "$ST_A" "$ST_A"
[ "$ST_RC" = 0 ] && [[ "$ST_OUT" == *"registry: not registered"* ]] || {
    printf '%s\n' "$ST_OUT" >&2; die "storage status before the vote did not say 'not registered' (rc $ST_RC)"; }
echo "[ok] before the storage vote: a valid owner registration REFUSED by the generation gate; status 'not registered'"

# ── 4. storage: the RULESET_GEN_ROLES vote, H_s % E == 2 ────────────
cc_guard 1
HS=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( HS % E )) != 2 ]; do HS=$(( HS + 1 )); done          # rules (d)(e) + E-2 blocks to the boundary
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROLES=$D4_DEC effective H_s=$HS (first storage boundary $(( HS - 2 + E )))"
propose RULESET_GEN_ROLES "$D4_DEC" "$HS" "$LOGD/propose_storage.log"
wait_cc_row "$PARAM_HF6" "$HS" "$D4_DEC" 20
[ "$CC_CB" -lt "$HS" ] || die "the RULESET_GEN_ROLES row committed at $CC_CB, not before its effective height $HS"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_EVM" "$H4"; done
cross_edge storage "$HS"
# HF-6: the generation-4 edge (switch + validator migration) logs its own
# "HF-6:" line (nodus_witness_v2_apply.c phase_6b_gen4_edge); the storage
# boundary gate reads the same param 18 (nodus_witness_v2_storage.c).
STOR_LINE="HF-6: rule-set generation $GEN_EVM -> $GEN_STOR and the validator migration at the end of height $(( HS - 1 )) (param $PARAM_HF6 RULESET_GEN_ROLES, D4 0x$D4_HEX); height $HS is judged under generation $GEN_STOR"
for n in $(seq 1 "$N"); do
    grep -qF "$STOR_LINE" "$(node_log "$n")" || die "node$n logged no '$STOR_LINE' line"
    require_gen "$n" "$GEN_STOR" "$H4"
done
stagef_cmt_diff_at_floor "past-storage-edge" || exit 2
echo "[ok] the storage generation $GEN_STOR on 7/7 from H_s=$HS (D4 0x$D4_HEX)"
# 6b-3: whom the migration made the validators' owner (D2 (a): every
# genesis validator -> the compiled Foundation owner) — item 9's premise,
# read from the chain, never taken from the environment
VOWN_REF=""
for n in $(seq 1 "$N"); do
    v=$(sqlite3 -separator '|' "$(db_of "$n")" \
        "SELECT COUNT(*), COUNT(DISTINCT owner_fp), COALESCE(MIN(lower(hex(owner_fp))), '-')
           FROM v2_validator_roles;" 2>/dev/null || echo ERR)
    if [ -z "$VOWN_REF" ]; then VOWN_REF="$v"
    elif [ "$v" != "$VOWN_REF" ]; then die "node$n's validator owners '$v' differ from node1's '$VOWN_REF'"; fi
done
[ "$VOWN_REF" = "$N|1|$OWNER" ] || die \
    "the validator owners after the edge are '$VOWN_REF', expected '$N|1|${OWNER:0:16}...' — the build's DNAC_HF6_FOUNDATION_OWNER is not $([ -n "${STAGEF_HF6_OWNER_FP_HEX:-}" ] && echo 'STAGEF_HF6_OWNER_FP_HEX' || echo 'the K8 default')"
if [ "$OWNER" = "$K8_OWNER" ]; then BUILD_OWNER="the default build (Foundation owner = the K8 2-of-3 address)"
else BUILD_OWNER="a test-owner build (Foundation owner ${OWNER:0:16}...)"; fi
echo "[ok] all $N validators owned by ${OWNER:0:16}... on 7/7 — $BUILD_OWNER"

# ── 5. storage: the OWNERS register nodes 4 and 5 (6b-3) ─────────────
# 5a. node 4 — its key consents to its OWN key as owner; the file
# round-trips; a dry run names the node and the owner
c_a="$LOGD/consent_node$ST_A.txt"
consent_make "$ST_A" "$OWNER_A" "$c_a" "$LOGD/consent_node$ST_A.log"
consent_file_ok "$c_a" "$ST_A" "$OWNER_A" "$CS_EXP"
st_register "$ST_A" "$KEYS_A" "$c_a" dry-run "$LOGD/register_dry_node$ST_A.log"
[ "$RG_RC" = 0 ] || die "storage register --dry-run for node$ST_A exited $RG_RC"
[[ "$RG_OUT" == *"storage register: node $FP_A"* && "$RG_OUT" == *"  owner $OWNER_A"* ]] \
    || die "the node$ST_A dry run does not name node ${FP_A:0:16}... and owner ${OWNER_A:0:16}..."
[[ "$RG_OUT" == *"PREFLIGHT SELF-CHECK: OK (2 legs SYSTEM STORAGE_REGISTER + CORE SYSFUND)"* ]] \
    || die "the node$ST_A dry run did not pass its self-check"
# 5b. node 5 — its key consents to owner_5. The CLI's own owner check: a
# consent naming another owner than the --keys identity is refused before
# anything is built — with node 5's NODE identity as --keys (TEST-OWNER
# MODE: its real consent; default: a consent naming node 1, the only way
# to make the node identity a non-owner when it owns itself)
c_b="$LOGD/consent_node$ST_B.txt"
consent_make "$ST_B" "$OWNER_B" "$c_b" "$LOGD/consent_node$ST_B.log"
consent_file_ok "$c_b" "$ST_B" "$OWNER_B" "$CS_EXP"
if [ -n "$OWN_KEYS" ]; then
    c_x="$c_b"
else
    c_x="$LOGD/consent_node${ST_B}_owner_node1.txt"
    consent_make "$ST_B" "$FP_1" "$c_x" "$LOGD/consent_node${ST_B}_owner_node1.log"
    consent_file_ok "$c_x" "$ST_B" "$FP_1" "$CS_EXP"
fi
st_register "$ST_B" "$(node_keys "$ST_B")" "$c_x" dry-run "$LOGD/register_node${ST_B}_as_node.log"
[ "$RG_RC" != 0 ] && [[ "$RG_OUT" == *"the consent names another owner than the --keys identity"* ]] \
    || die "storage register with node$ST_B's own identity as --keys was not refused by the CLI's owner check (rc $RG_RC)"
[ -z "$(spend_intent "$LOGD/register_node${ST_B}_as_node.log")" ] || die "the refused registration built an envelope"
echo "[ok] the CLI refused node$ST_B's identity as --keys for a consent naming another owner — nothing built"
# 5c. submit both, each on its own node's port
for k in "$ST_A" "$ST_B"; do
    if [ "$k" = "$ST_A" ]; then keys="$KEYS_A"; cf="$c_a"; else keys="$KEYS_B"; cf="$c_b"; fi
    log="$LOGD/register_node$k.log"
    st_register "$k" "$keys" "$cf" submit "$log"
    [ "$RG_RC" = 0 ] || die "storage register for node$k exited $RG_RC (see $log)"
    grep -q '^accepted: mempool CheckTx approved' "$log" || die "storage register for node$k: no CheckTx approval line (see $log)"
    intent=$(spend_intent "$log")
    [ "${#intent}" = 128 ] || die "storage register for node$k printed no intent_id (see $log)"
done
REG_H=0
for k in "$ST_A" "$ST_B"; do
    if [ "$k" = "$ST_A" ]; then fp="$FP_A"; else fp="$FP_B"; fi
    h=$(stagef_cmt_wait_row "$(db_of "$k")" \
        "SELECT COUNT(*) FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '$fp' AND status = 1;") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "chain STALLED waiting for node$k's registry row (tip $h)" ;;
        *) die "node$k's registration did not land within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
    echo "[ok] node$k registered (row visible at tip $h)"
    [ "$h" -le "$REG_H" ] || REG_H="$h"
done
wait_all "$REG_H"          # every node holds both rows at or below this tip
require_registry "post-register"

# both in a frozen set: the first set that holds both is B_in. Pumped to
# the next boundary + 1 (twice at most); its set must name them both.
B_IN=""
for try in 1 2; do
    t=$(tip_of 1)
    nb=$(( (t / E + 1) * E ))
    pump_to 1 $(( nb + 1 ))
    wait_all $(( nb + 1 ))
    B_IN=$(sqlite3 "$(db_of 1)" \
        "SELECT COALESCE(MIN(epoch_start), '') FROM (SELECT epoch_start FROM v2_storage_set_members
           WHERE lower(hex(node_fp)) IN ('$FP_A', '$FP_B') GROUP BY epoch_start HAVING COUNT(*) = 2);" 2>/dev/null || echo ERR)
    [ "$B_IN" != ERR ] || die "v2_storage_set_members unreadable on node1"
    [ -n "$B_IN" ] && break
done
[ -n "$B_IN" ] || die "nodes $ST_A and $ST_B are not both in any frozen storage set after two boundaries"
B_FIRST=$(sqlite3 "$(db_of 1)" "SELECT MIN(epoch_start) FROM v2_storage_sets;" 2>/dev/null || echo ERR)
case "$B_FIRST" in ''|*[!0-9]*) die "v2_storage_sets unreadable on node1 ('$B_FIRST')" ;; esac
for n in $(seq 1 "$N"); do
    m=$(sqlite3 "$(db_of "$n")" \
        "SELECT group_concat(lower(hex(node_fp)) || ':' || fail_streak || ':' || grace_until, ',')
           FROM (SELECT node_fp, fail_streak, grace_until FROM v2_storage_set_members
                  WHERE epoch_start = $B_IN ORDER BY node_fp);" 2>/dev/null || echo ERR)
    case "$m" in
        *"$FP_A:0:0"*"$FP_B:0:0"*|*"$FP_B:0:0"*"$FP_A:0:0"*) ;;
        *) die "node$n's frozen set S($B_IN) is not {node$ST_A, node$ST_B} with fail_streak 0 / grace_until 0: '$m'" ;;
    esac
    c=$(sqlite3 "$(db_of "$n")" "SELECT member_count FROM v2_storage_sets WHERE epoch_start = $B_IN;" 2>/dev/null || echo ERR)
    [ "$c" = 2 ] || die "node$n's v2_storage_sets row at $B_IN counts '$c' members, expected 2"
done
echo "[ok] both storage nodes are members of S($B_IN) on 7/7 (first storage boundary $B_FIRST)"

# ── 6. storage: segment 1 published at the first boundary >= P + 2E ──
H_PUB_X=$(( P + DELAY ))
[ "$B_FIRST" -le "$H_PUB_X" ] || H_PUB_X="$B_FIRST"
[ $(( H_PUB_X % E )) = 0 ] || die "the expected publication height $H_PUB_X is not a boundary (P + 2E, E = $E)"
[ "$B_IN" -le "$H_PUB_X" ] || die \
    "the layout broke: the storage nodes joined at $B_IN, after the publication boundary $H_PUB_X — K9a would give them grace (not this scenario's path)"
pump_to 1 $(( H_PUB_X - 2 ))
echo "[info] idle production from tip $(tip_of 1) — no pump spend in flight across the probing epoch, the report window and the settlement"
wait_all "$H_PUB_X"
h=$(stagef_cmt_wait_row "$(db_of 1)" "SELECT COUNT(*) FROM v2_storage_segments WHERE k = 1;" 3 5) && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "segment 1 was not published on node1 by tip $h (expected at $H_PUB_X; wait rc $wrc)"
stagef_sentinel TARGET_REACHED
SEG_REF=""
for n in $(seq 1 "$N"); do
    s=$(sqlite3 "$(db_of "$n")" \
        "SELECT group_concat(k || '|' || lower(hex(root)) || '|' || published_height, ',')
           FROM (SELECT k, root, published_height FROM v2_storage_segments ORDER BY k);" 2>/dev/null || echo ERR)
    if [ -z "$SEG_REF" ]; then SEG_REF="$s"
    elif [ "$s" != "$SEG_REF" ]; then die "node$n's published segment list differs: '$s' vs node1 '$SEG_REF'"; fi
done
IFS='|' read -r seg_k SEG_ROOT H_PUB <<< "$SEG_REF"
[ "$seg_k" = 1 ] && [ "${#SEG_ROOT}" = 128 ] || die "the segment list is not exactly segment 1: '$SEG_REF'"
[[ "$H_PUB" =~ ^[0-9]+$ ]] || die "the segment list is not exactly segment 1: '$SEG_REF'"
[ "$H_PUB" = "$H_PUB_X" ] || die "segment 1 was published at $H_PUB, expected the first storage boundary >= P + 2E = $H_PUB_X"
# bytes item 1 at P = 24E: re-derived from node 1's v2_blocks
nblk=$(sqlite3 "$(db_of 1)" "SELECT COUNT(*) FROM v2_blocks WHERE global_height BETWEEN 1 AND $P AND length(block_id) = 64;")
[ "$nblk" = "$P" ] || die "node1 holds $nblk 64-byte block ids in 1..$P, expected $P"
seg_re=$( { printf 'NDS.STSEG.v1\0\0\0\0'
            printf '%016x%08x' 1 "$P" | xxd -r -p
            sqlite3 "$(db_of 1)" "SELECT hex(block_id) FROM v2_blocks WHERE global_height BETWEEN 1 AND $P
                                    ORDER BY global_height;" | tr -d '\n' | xxd -r -p
          } | openssl dgst -sha3-512 | awk '{print $NF}')
[ "$seg_re" = "$SEG_ROOT" ] || die "segment 1's root ${SEG_ROOT:0:16}... is not SHA3-512(NDS.STSEG.v1 ‖ k ‖ count=$P ‖ block_id[1..$P]) = ${seg_re:0:16}..."
diff_at "$H_PUB" "segment-published-at-$H_PUB"
echo "[ok] segment 1 (heights 1..$P) published at $H_PUB on 7/7; root ${SEG_ROOT:0:16}... = bytes item 1 recomputed at count $P"

# ── 7. storage: `storage status` in the epoch after the publication ──
for k in "$ST_A" "$ST_B"; do
    if [ "$k" = "$ST_A" ]; then fp="$FP_A"; own="$OWNER_A"; else fp="$FP_B"; own="$OWNER_B"; fi
    status_of "$k" "$k"
    printf '%s\n' "$ST_OUT"
    [ "$ST_RC" = 0 ] || die "storage status on node$k exited $ST_RC"
    [[ "$ST_OUT" == *"storage node $fp"* ]] || die "node$k's status names another node"
    [[ "$ST_OUT" == *"registry: ACTIVE, bond $BOND raw, fail_streak 0, registered at "* ]] \
        || die "node$k's status is not 'ACTIVE, bond $BOND raw, fail_streak 0'"
    [[ "$ST_OUT" == *"  owner: $own"* ]] || die "node$k's status does not name its owner ${own:0:16}... ('owner:' line, 6b-3)"
    [[ "$ST_OUT" == *"grace_until: 0 (never in grace)"* ]] || die "node$k's status is not 'grace_until: 0' (K9a)"
    [[ "$ST_OUT" != *"IN GRACE"* ]] || die "node$k's status says it is IN GRACE"
    re='frozen storage set for epoch [(]([0-9]+), [0-9]+[]]: 2 member[(]s[)], this node IS a member'
    [[ "$ST_OUT" =~ $re ]] || die "node$k's status does not show a 2-member set it is a member of"
    [ "${BASH_REMATCH[1]}" -ge "$H_PUB" ] || die "node$k's status is for epoch ${BASH_REMATCH[1]}, before the publication $H_PUB"
    [[ "$ST_OUT" == *"eligible segments this epoch: 1 ($P blocks): 1"* ]] \
        || die "node$k's status does not list segment 1 ($P blocks) as eligible"
done
status_of 1 1
[ "$ST_RC" = 0 ] && [[ "$ST_OUT" == *"registry: not registered"* && "$ST_OUT" == *"this node is NOT a member"* ]] || {
    printf '%s\n' "$ST_OUT" >&2; die "node1's status (not registered) did not read 'not registered' / 'NOT a member'"; }
echo "[ok] storage status: nodes $ST_A/$ST_B ACTIVE members, grace_until 0, segment 1 eligible ($P blocks); node1 not registered"

# ── 8. storage: the reports of the probing epoch Hx ─────────────────
HX="$H_PUB"
while is_payday $(( HX + DELAY )); do HX=$(( HX + E )); done
B_SET=$(( HX + DELAY ))
[ "$HX" = "$H_PUB" ] || echo "[info] $(( H_PUB + DELAY )) is a payday — the settled epoch is $HX instead (segment 1 stays eligible)"
W_CLOSED=$(( HX + E + REPORT_CLOSE ))
wait_all "$W_CLOSED"
SET_HASH=$(sqlite3 "$(db_of 1)" "SELECT lower(hex(set_hash)) FROM v2_storage_sets WHERE epoch_start = $HX;" 2>/dev/null || echo ERR)
[ "${#SET_HASH}" = 128 ] || die "no frozen S($HX) on node1 ('$SET_HASH')"
REP_REF=""
for n in $(seq 1 "$N"); do
    out=$(sqlite3 -separator ' ' "$(db_of "$n")" \
        "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
                (SELECT COUNT(*) FROM v2_storage_reports WHERE epoch_start = $HX),
                (SELECT COUNT(*) FROM v2_storage_reports WHERE epoch_start = $HX AND lower(hex(set_hash)) <> '$SET_HASH'),
                (SELECT COALESCE(group_concat(r, ','), '-') FROM
                   (SELECT seat || ':' || hex(bitmap) AS r FROM v2_storage_reports
                     WHERE epoch_start = $HX ORDER BY seat));" 2>/dev/null || echo ERR)
    read -r rt rc rbad rlist <<< "$out"
    [[ "$rt" =~ ^[0-9]+$ ]] && [[ "$rc" =~ ^[0-9]+$ ]] || die "node$n's report read failed: '$out'"
    [ "$rt" -lt "$B_SET" ] || die "node$n reached the settlement boundary $B_SET while its reports were read (tip $rt) — they are pruned there"
    [ "$rbad" = 0 ] || die "node$n holds $rbad report(s) for H=$HX against another set hash"
    if [ -z "$REP_REF" ]; then REP_REF="$rc $rlist"
    elif [ "$rc $rlist" != "$REP_REF" ]; then die "node$n's committed reports for H=$HX differ: '$rc $rlist' vs node1 '$REP_REF'"; fi
done
N_REP="${REP_REF%% *}"
[ $(( N_REP * 2 )) -gt "$N" ] || die "only $N_REP of $N seats committed a report for H=$HX — F1 (more than half the power) cannot hold"
# 6b-2: node 4's own seat is excluded for node 4 (key clause), so its
# independent power is N_REP − 1 seats when that seat reported; only
# 2·(N_REP − 1) > N makes "node 4 is OK" decidable without decoding which
# seat is node 4's (a NO_EVIDENCE node 4 would read as a broken pay)
[ $(( (N_REP - 1) * 2 )) -gt "$N" ] || die \
    "only $N_REP of $N seats reported for H=$HX — with node $ST_A's own seat among them its independent power can be <= half (the three-state verdict, design §11.6): the expected debit is not decidable here (layout broke — false RED)"
echo "[ok] $N_REP/$N seats committed a STORAGE_REPORT for H=$HX against S($HX), identical on 7/7 (seat:bitmap ${REP_REF#* })"
n_logged=0
for n in $(seq 1 "$N"); do
    if grep -q "report for H=$HX committed" "$(node_log "$n")"; then n_logged=$(( n_logged + 1 )); fi
done
echo "[info] REPORTED: $n_logged/$N node logs say 'report for H=$HX committed'"
# the reporter's "probe of <peer id, 16 hex>.. OK" line (W_STPROBE; the
# peer id is hex(fp[0..31]), nodus_witness_storage_reporter.c take_answer)
for k in "$ST_A" "$ST_B"; do
    if [ "$k" = "$ST_A" ]; then fp="$FP_A"; else fp="$FP_B"; fi
    n_ok=0
    for n in $(seq 1 "$N"); do
        if grep -q "probe of ${fp:0:16}\.\. OK" "$(node_log "$n")"; then n_ok=$(( n_ok + 1 )); fi
    done
    if [ -f "$(stagef_node_dir "$k")/data/segments/seg-1.ok" ]; then f=present; else f=absent; fi
    echo "[info] REPORTED: node$k — $n_ok/$N node logs hold a 'probe of ${fp:0:16}.. OK' line; segment file marker seg-1.ok $f"
done

# ── 9. storage: the settlement at B = Hx + 2E pays the storage OWNERS ─
# snap — ONE statement (the test_v2_rewards.sh lesson: every value from
# one read snapshot): "tip reward_pool pool1 Σaccrual acc(owner_A)
# acc(owner_B)" — owner_B is the Foundation owner in TEST-OWNER MODE.
# Prints the line and returns 0, or prints the raw answer and returns 1
# (the caller dies — a die inside $(...) would only end the subshell).
snap() {
    local out
    out=$(sqlite3 -separator ' ' "$(db_of 1)" \
      "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
              (SELECT reward_pool FROM supply_tracking WHERE id = 1),
              (SELECT balance FROM v2_treasury WHERE pool_id = 1),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual WHERE lower(hex(owner_fp)) = '$OWNER_A'),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual WHERE lower(hex(owner_fp)) = '$OWNER_B');" \
          2>&1) || { printf '%s\n' "$out"; return 1; }
    [[ "$out" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]] || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
}
s=$(snap) || die "the pre-settlement snapshot on node1 failed: '$s'"
read -r t_pre rp_pre p1_pre acc_pre a_pre b_pre <<< "$s"
[ "$t_pre" -lt "$B_SET" ] || die "node1 passed the settlement boundary $B_SET before the pre read (tip $t_pre)"
[ "$t_pre" -ge "$W_CLOSED" ] || die "pre read at tip $t_pre, before the report window closed ($W_CLOSED)"
[ "$p1_pre" = "$POOL1_0" ] || die "pool 1 moved before the first paying settlement: $POOL1_0 -> $p1_pre"
echo "[ok] pre  B=$B_SET: tip $t_pre reward_pool $rp_pre pool1 $p1_pre Σaccrual $acc_pre node$ST_A $a_pre node$ST_B $b_pre"
stagef_cmt_wait_height "$(db_of 1)" "$B_SET" 3 >/dev/null || die "the chain stalled short of the settlement boundary $B_SET"
s=$(snap) || die "the post-settlement snapshot on node1 failed: '$s'"
read -r t_post rp_post p1_post acc_post a_post b_post <<< "$s"
[ "$t_post" -ge "$B_SET" ] && [ "$t_post" -lt $(( B_SET + E )) ] \
    || die "post read at tip $t_post, outside [$B_SET, $(( B_SET + E )))"
echo "[ok] post B=$B_SET: tip $t_post reward_pool $rp_post pool1 $p1_post Σaccrual $acc_post node$ST_A $a_post node$ST_B $b_post"
BUDGET=$(( p1_pre >> DIV_LOG2 ))
SHARE=$(( BUDGET / 2 ))     # ⌊budget × P / 2P⌋: W counts both members (design §11.6)
[ "$SHARE" -gt 0 ] || die "the budget $BUDGET cannot pay two shares (pool 1 $p1_pre)"
DEBIT=$(( p1_pre - p1_post ))
d_acc=$(( acc_post - acc_pre )); d_rp=$(( rp_pre - rp_post ))
d_a=$(( a_post - a_pre )); d_b=$(( b_post - b_pre ))
[ "$d_acc" = $(( d_rp + DEBIT )) ] || die \
    "Σaccrual rose by $d_acc, expected reward-pool debit $d_rp + pool 1 debit $DEBIT = $(( d_rp + DEBIT ))"
# node 4's owner is its own key: after the generation-4 edge a node key
# earns no validator reward (the owner — the Foundation — does), so its
# accrual step is the storage share alone
[ "$d_a" = "$SHARE" ] || die \
    "node$ST_A's owner (its own key) rose by $d_a, expected exactly its storage share $SHARE (OK, equal weight $P)"
if [ -n "$OWN_KEYS" ]; then
    # NO_EVIDENCE (design §11.6): node 5 is owned by the validators' owner —
    # every report about it is owner-excluded, I = 0, 2·I <= P_total
    [ "$DEBIT" = "$SHARE" ] || die \
        "pool 1 fell by $DEBIT, expected ONE share $SHARE (node $ST_A OK, node $ST_B NO_EVIDENCE — its share stays in pool 1) — $([ "$DEBIT" = $(( 2 * SHARE )) ] && echo "node $ST_B was PAID: its validators' reports counted for it (owner exclusion not applied)" || echo 'not this settlement')"
    [ "$d_b" = "$d_rp" ] || die \
        "node$ST_B's owner (the Foundation owner) rose by $d_b, expected exactly the reward-pool debit $d_rp (the validator reward, no storage share)"
    echo "[ok] settlement at $B_SET: pool 1 -$DEBIT = ONE share — node$ST_A's owner +$SHARE; node$ST_B (owned by the validators' owner) NO_EVIDENCE, its owner +$d_b = the validator reward only; Σaccrual +$d_acc = reward pool -$d_rp + pool 1 -$DEBIT"
else
    [ "$DEBIT" = $(( 2 * SHARE )) ] || die \
        "pool 1 fell by $DEBIT, expected 2 x floor(($p1_pre >> $DIV_LOG2) / 2) = $(( 2 * SHARE )) (both members OK, equal weight $P) — $([ "$DEBIT" = "$SHARE" ] && echo 'ONE member was paid' || echo 'not a two-member settlement')"
    [ "$d_b" = "$SHARE" ] || die \
        "node$ST_B's owner (its own key) rose by $d_b, expected exactly its storage share $SHARE"
    echo "[ok] settlement at $B_SET paid both owners: pool 1 -$DEBIT (2 x $SHARE), each node-key owner +$SHARE, Σaccrual +$d_acc = reward pool -$d_rp + pool 1 -$DEBIT"
fi

# ── 10. storage: fail_streak 0 on both after the settlement; 7/7 ────
# OK resets it (K5a), NO_EVIDENCE leaves it untouched, NOT OK writes 1 —
# with the debit above this separates the three verdicts
wait_all "$B_SET"
require_registry "post-settlement"
for n in $(seq 1 "$N"); do
    p1=$(sqlite3 "$(db_of "$n")" "SELECT balance FROM v2_treasury WHERE pool_id = 1;" 2>/dev/null || echo ERR)
    [ "$p1" = "$p1_post" ] || die "node$n's pool 1 reads '$p1', node1's $p1_post"
done
diff_at "$B_SET" "storage-settlement-at-$B_SET"

# ── 11. storage: the OWNER takes node 5 out; the bond comes back (6b-3) ─
# 11a. the CLI's owner check on exit: node 4's keys do not own node 5
xlog="$LOGD/exit_node${ST_B}_by_node$ST_A.log"; xrc=0
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$ST_B")" storage exit --keys "$KEYS_A" \
    --node-fp "$FP_B" --dry-run > "$xlog" 2>&1 || xrc=$?
cat "$xlog"
[ "$xrc" != 0 ] && grep -q "only its owner can take it out" "$xlog" \
    || die "storage exit of node$ST_B with node$ST_A's keys was not refused by the CLI's owner check (rc $xrc, see $xlog)"
[ -z "$(spend_intent "$xlog")" ] || die "the refused exit built an envelope"
echo "[ok] the CLI refused an exit of node$ST_B by a non-owner — nothing built"
# 11b. the owner's exit
xlog="$LOGD/exit_node$ST_B.log"; xrc=0
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$ST_B")" storage exit --keys "$KEYS_B" \
    --node-fp "$FP_B" --submit "127.0.0.1:$(stagef_tcp_port "$ST_B")" > "$xlog" 2>&1 || xrc=$?
cat "$xlog"
[ "$xrc" = 0 ] || die "storage exit of node$ST_B by its owner exited $xrc (see $xlog)"
grep -q '^accepted: mempool CheckTx approved' "$xlog" || die "storage exit: no CheckTx approval line (see $xlog)"
x_intent=$(spend_intent "$xlog")
[ "${#x_intent}" = 128 ] || die "storage exit printed no intent_id (see $xlog)"
# the exec's effect: EXITING (2) with exit_height x — or already RELEASED
# (3) when x itself is a boundary (the EXIT is applied before that
# block's boundary step, which releases it in the same block)
h=$(stagef_cmt_wait_row "$(db_of "$ST_B")" \
    "SELECT COUNT(*) FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '$FP_B'
       AND status IN (2, 3) AND exit_height > 0;") && wrc=0 || wrc=$?
case "$wrc" in
    0) ;;
    1) die "chain STALLED waiting for node$ST_B's EXITING row (tip $h)" ;;
    *) die "node$ST_B's exit did not land within 20 heights (tip $h) — dropped, or refused by its exec (a refused item writes no row)" ;;
esac
XH=$(sqlite3 "$(db_of "$ST_B")" "SELECT exit_height FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '$FP_B';" 2>/dev/null || echo ERR)
[[ "$XH" =~ ^[0-9]+$ ]] && [ "$XH" -gt 0 ] || die "node$ST_B's exit_height is '$XH'"
B_REL=$(( (XH + E - 1) / E * E ))      # the first boundary >= x (st_release runs at it)
UNLOCK=$(( B_REL + EXIT_LOCK_EPOCHS * E ))
echo "[ok] node$ST_B EXITING at x=$XH (tip $h) — release boundary B_rel=$B_REL, unlock $UNLOCK"
# 11c. at B_rel: RELEASED + ONE release coin to the owner, 7/7
pump_to 1 $(( B_REL + 1 ))
wait_all "$B_REL"
require_registry "post-release" 3 "$XH"
REL_REF=""
for n in $(seq 1 "$N"); do
    r=$(sqlite3 -separator '|' "$(db_of "$n")" \
        "SELECT COUNT(*), COALESCE(MIN(lower(owner)), '-'), COALESCE(MIN(amount), -1),
                COALESCE(MIN(block_height), -1), COALESCE(MIN(unlock_block), -1)
           FROM utxo_set WHERE output_index = $EXIT_OUT_IDX;" 2>/dev/null || echo ERR)
    if [ -z "$REL_REF" ]; then REL_REF="$r"
    elif [ "$r" != "$REL_REF" ]; then die "node$n's storage release coins '$r' differ from node1's '$REL_REF'"; fi
done
[ "$REL_REF" = "1|$OWNER_B|$BOND|$B_REL|$UNLOCK" ] || die \
    "the storage release coins are '$REL_REF', expected exactly one: '1|${OWNER_B:0:16}...|$BOND|$B_REL|$UNLOCK' (owner_5, the bond, created at B_rel, locked $EXIT_LOCK_EPOCHS epochs)"
diff_at "$B_REL" "storage-release-at-$B_REL"
echo "[ok] at B_rel=$B_REL on 7/7: node$ST_B RELEASED (exit at $XH), node$ST_A ACTIVE, ONE release coin of $BOND raw to its owner ${OWNER_B:0:16}..., unlock_block $UNLOCK"

stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-storage" || exit 2
stagef_sentinel PASS
if [ -n "$OWN_KEYS" ]; then
    NE_LINE="NO_EVIDENCE: PROVEN on 7/7 — node $ST_B owned by the validators' owner: one share paid, its fail_streak 0"
else
    NE_LINE="NO_EVIDENCE: not run (STAGEF_HF6_OWNER_KEYS unset — coverage that did not happen; both nodes settled OK)"
fi
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | storage H_s $HS | first storage set $B_FIRST"
echo "       | both members from $B_IN | segment 1 published $H_PUB | probed epoch $HX | settled $B_SET"
echo "       | node $ST_B exit $XH | released $B_REL"
echo "[PASS] archive storage reward on $BUILD_OWNER: generation $GEN_STOR voted on top of the EVM"
echo "       generation, nodes $ST_A/$ST_B registered by their OWNERS (node consent op 3, file round-trip,"
echo "       the CLI's generation and owner checks), segment 1 (P = $P) published and re-derived,"
echo "       $N_REP/$N reports, the settlement debited pool 1 by $DEBIT (SHARE $SHARE), node $ST_B"
echo "       taken out by its owner and its bond released as one locked coin — 7/7 identical."
echo "       $NE_LINE."
echo "       E=15 / grace 15 / P=360 — the LOGIC only; the NOT OK / grace / handoff paths are NOT exercised (header)."
