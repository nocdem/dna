#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_hf6_edge.sh — HF-6 sub-slice 3f: the generation-4 edge on a 7-node
# chain — the validator migration at the end of H−1 (keys re-valued to
# validator_id, 10M bond -> 2M bond + 8M Foundation-owned self-delegation,
# the Foundation accrual merge), then the validator earnings landing on the
# Foundation owner across the epoch boundaries after H, 7/7 identical;
# HF-6 slice 5d: the validator-set snapshot switching to ruleset 2 at the
# first boundary after H and the power cap reaching cometbft's set one
# epoch later, over a 50M pre-edge delegation; HF-6 slice 6f-2 (only with
# STAGEF_HF6_OWNER_KEYS): a real consensus-key rotation of node 2 onto an
# 8th node, end to end (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: design docs/plans/2026-10-03-hf5-validator-owner-
# stake-design.md rev 6 §7 (migration steps 1-6, 10), §1.6 (base +
# commission to owner_fp), §8 (one generation, H−1 and H off a boundary),
# §10 item 2 (the development trigger: param 16 + the storage literal until
# slice 8); decisions docs/plans/decisions/2026-10-08-kurultay-14-hf6-
# summary.md (K4 accrual merge, K8 Foundation address) and docs/plans/
# decisions/2026-10-09-kurultay-16-hf6-storage-summary.md (D2 (a): owner =
# Foundation for every row with active_since_block <= 1); plan
# tasks/hf6-slice3-plan.md §2 "3f"; nodus/docs/ARCHITECTURE.md "HF-6
# sub-slice 3a/3b/3c/3d". TEMPLATE: test_storage_archive.sh — its vote
# helpers are copied (cc_guard / propose / wait_cc_row / ruleset_info /
# require_gen); the pump is stagef_env.sh's stagef_cmt_pump_to (1-in/1-out,
# --no-dust-sweep); every new part is marked "hf6:".
#
# WHY FIVE VOTES, NOT TWO: the generation-4 edge is triggered (on this
# development branch) by the param-16 row with DNAC_CFG_RULESET_GEN_STORAGE_D
# (nodus_witness_v2_apply.c phase_6b_gen4_edge). Param 16 is votable only
# while generation 3 (the EVM generation) judges the vote
# (nodus_witness_chain_config.c CC_PARAM_RULESET_GEN_STORAGE rule (d)), and
# the EVM vote needs HF-2, HF-3 and generation 2 — so HF2_ACTIVE (7),
# HF3_ACTIVE (8), RULESET_GEN2 (9), EVM_ACTIVE (14) and RULESET_GEN_STORAGE
# (16) are all voted, in that order, exactly as test_storage_archive.sh does.
#
# WHY H % E == 8: rule (c) forbids H−1 on a boundary; design §8 keeps H off
# a boundary too. With H % E == 8 the last boundary before H is H − 8 and
# the first after it is B1 = H + 7, so the pre-edge read (tip in
# [H − 8, H − 2]) and the post-edge read (tip in [H, H + 6]) each sit in a
# window no boundary writes into. H − 8 is also stepped off a payday, so the
# pre-edge accrual table holds the node-key rows K4 must merge.
#
# HF-6 SLICE 5d — THE SWITCH (plan tasks/hf6-slice5-plan.md §1; design rev 6
# §7.7, §7.8 item 8, §5; ORCHESTRATOR D4, D7). B1 is the plan's B₀: the
# first boundary reading generation 4. It stores snapshot(B1 + E) as the
# FIRST ruleset-2 blob (validator_id tiebreak, ids from the roles rows);
# every snapshot <= B1 stays ruleset 1. snapshot(B1 + E) takes effect at
# B1 + E, where FinalizeBlock's validator diff compares it (counted power,
# nodus_witness_vset_powers) with snapshot(B1) (ruleset 1, raw power).
# WHY THE DELEGATION IS PRE-EDGE: snapshot(B1 + E) is ranked by copy(B1 −
# E) = copy(H − 8), so only a delegation committed at or before H − 8 can
# shape it — a post-edge one lands one epoch later. And for the OLD side
# snapshot(B1) (built from copy(H − 8 − E)) to hold the same raw 60M, the
# delegation must sit in that copy too: H is therefore chosen >= C_D + E +
# 8, C_D = the first boundary >= the delegation's height. Then node 2 is
# [60M, 10M × 6] raw on BOTH sides and the cap alone decides the diff:
# counted 25714285 (design §5 at 3000 bps: k = 0 S = 120M c = 36M < 60M;
# k = 1 S = 60M c = ⌊3000·60M / 7000⌋ = 25714285 >= 10M, stop) — exactly
# ONE power change; raw on the new side would be ZERO changes.
#
# HF-6 SLICE 6f-2 — THE ROTATION (phase 10; plan tasks/hf6-slice6-plan.md
# §1, §2 "6f"; design rev 6 §3 and the khan decisions written under it,
# 2026-10-12: A1 the exec writes F, the freeze writes nothing; A2 the old
# key's reservation and the old voter's attendance row released at U + E;
# A3 a candidate that does not fit is skipped and the walk continues; A4
# ROTATE pays the fee only; A5 ACTIVE / ELIGIBLE rows only). Runs ONLY when
# STAGEF_HF6_OWNER_KEYS names the identity whose SHA3-512 the build
# compiled in as DNAC_HF6_FOUNDATION_OWNER (stagef_hf6_owner.sh prints the
# flag) — with the K8 default the owner of node 2 is a 2-of-3 the harness
# holds no key of, and nodus-cli's `v2-envelope rotate` builds a kind-1
# owner only (6f-1). Heights: the ROTATE applied at h_r; F = the first
# boundary >= h_r (rtn_rotate2_first_boundary, nodus_witness_rt_native.c);
# U = F + E. Comet: S(U) is frozen at F carrying the NEW key, FinalizeBlock
# (U) announces old-key removal + new-key addition, the new key signs from
# U + 2, U and U + 1 with the old (design §3).
# THE BUDGET, from the source (nodus_witness_vset.c vset_rotation_pass /
# vset_rot_fits: accept iff P − (R + p) > P * 2 / 3 in BOTH S(F) and S(U),
# each with its counted powers from nodus_witness_vset_powers — ruleset 2
# ⇒ the water-fill cap, shared/dnac/power_cap.c, ratio
# DNAC_HF6_POWER_CAP_BPS_DEFAULT 3000, r′ = max(3000, ⌈10000/7⌉) = 3000):
# phase 10 runs after step 8, so F >= B1 + 4E and S(F), S(U) are both
# ruleset 2; their raw whole-coin powers are node 2 = 2M bond + 8M
# self-delegation + 50M v2user = 60M and six × 10M (the step-7 rows,
# unchanged — phase 10 checks the decoded totals of both snapshots
# before it relies on them). Water-fill: k = 0 S_0 = 120M, c_0 = ⌊3000 ·
# 120M / 10000⌋ = 36M < 60M; k = 1 S_1 = 60M, c_1 = ⌊3000 · 60M / 7000⌋ =
# 25714285 >= 10M, stop. Counted: node 2 = 25714285, six × 10M. P =
# 85714285, P * 2 / 3 = ⌊171428570 / 3⌋ = 57142856, R = p(node 2) =
# 25714285: P − R = 60000000 > 57142856 — ADMITTED in both sets (S(F) and
# S(U) hold the same powers), so the node's own line is exactly
# "snapshot(U): 1 rotation(s) accepted, 0 waiting (P_U 85714285 R_U
# 25714285, P_F 85714285 R_F 25714285)". (Under the RAW power of a
# ruleset-1 S(F) it would NOT be: 120M − 60M = 60M ≤ 80M.)
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): the server and the CLI print one version
#      banner; the CLI's chain-config usage names "EVM_ACTIVE exactly <D>"
#      and "RULESET_GEN_STORAGE exactly <DS>" (compiled literals, never a
#      script literal); node 1's database has v2_validator_roles (schema
#      S18 — an HF-6 build).
#   1. Preconditions on a fresh chain: 7 validator rows, one per harness
#      node (matched by the raw nodus.pk bytes), each ACTIVE/ELIGIBLE,
#      active_since_block <= 1 (the D2 (a) predicate that makes them
#      Foundation-owned), self_stake 10M, no delegations, no roles rows.
#   2. HF2_ACTIVE, HF3_ACTIVE, RULESET_GEN2 (1 -> 2), EVM_ACTIVE (2 -> 3)
#      voted and crossed, each row identical 7/7, committed below its
#      effective height (the archive scenario's step 2, unchanged).
#   2b. (5d) The non-validator v2user claims its genesis leaf and
#      DELEGATEs 50M NODUS to node 2 under generation 3 (`v2-envelope
#      delegate --validator <node 2's pubkey>`, the path
#      test_cmt_self_delegate.sh uses); applied (its v2_intent_index row at
#      height h_d); 7/7: the delegation row holds 50M, node 2's
#      total_delegated = external_delegated = 50M. C_D = the first boundary
#      >= h_d (the copy that first holds it).
#   3. RULESET_GEN_STORAGE = DS voted at H (H % E == 8, H − 8 not a
#      payday, H >= C_D + E + 8 — header "THE SWITCH"): round 1 7/7, row
#      identical 7/7, committed < H; generation 3 on 7/7 before the edge.
#   4. Pre-edge snapshot on EACH node, one SQL statement each, tip in
#      [H − 8, H − 2] (block H − 1 not yet applied): Σself = 7 × 10M,
#      Σtotal_delegated = 50M, 1 delegation, 0 roles rows, Σaccrual > 0
#      held ONLY by the seven node-key fingerprints and (when it was
#      already paid) v2user's, no Foundation row; identical on 7/7 (tip
#      aside).
#   5. Crossing H (pumped to H − 7, idle after): 7/7 identical blocks AT
#      H − 1, H, H + 1; every node logged "HF-6: rule-set generation 3 -> 4
#      and the validator migration at the end of height H−1 (dev trigger:
#      storage vote literal 0x<DS>)" and "HF-6 migration: 7 validators
#      re-keyed (7 Foundation-owned), 7 consensus keys reserved, 8
#      delegations (1 before)"; `ruleset-info` 7/7 = generation 4.
#   6. Post-edge snapshot on EACH node, tip in [H, B1 − 1]:
#      Σself + Σtotal_delegated UNCHANGED versus step 4 (§7.10), Σself =
#      7 × 2M, Σtotal_delegated = 7 × 8M + 50M; Σaccrual unchanged, held by
#      the Foundation owner (= step 4's Σaccrual minus v2user's) and, when
#      it had one, v2user's row unchanged (K4 merges only the Foundation
#      nodes' rows); identical on 7/7.
#   7. The migrated rows, dumped canonically and identical on 7/7:
#      every validators row has a v2_validator_roles row (validator_id =
#      pubkey_hash, a NEW key — not its pre-edge tagged hash), owner_fp =
#      the Foundation owner, pending consensus key all zero, effective
#      epoch 0, self_stake 2M, total_delegated = external_delegated = 8M
#      (node 2: 8M + 50M), status and active_since_block as before; the
#      seven node pubkeys each exactly once; exactly 8 delegations: 7 of
#      (delegator = the Foundation owner, validator = one validator_id,
#      8M, delegated_at_block = H), one per validator, and v2user's
#      re-keyed to (SHA3-512(its key), node 2's validator_id), 50M, its
#      pre-edge delegated_at_block.
#   8. Epoch boundaries after H, B1 = H + 7, B1 + E, … — crossed until at
#      least THREE non-payday boundaries were checked AND one of them is
#      ≥ B1 + 3E (the first boundary whose source copy, B − 3E, was written
#      AFTER the edge — the 2M kind-0 + 8M kind-1 split governs its inner
#      split; nodus_witness_v2_econ.c v2ec_source_copy). Each boundary B:
#      pumped to B − 3, ONE-statement read at tip < B, idle to B, ONE-
#      statement read at tip in [B, B + E), NO envelope in between
#      (Σ v2_blocks.tx_count == 0); 7/7 identical global_root + block_id AT
#      B and 7/7 identical accrual table. Non-payday B: the accrual table
#      holds the Foundation owner's row and at most v2user's — NO node-key
#      row — and
#        Δ(Foundation row) + Δ(v2user row) == ΔΣaccrual
#          == reward_pool debit, Δ(Foundation row) > 0
#      (every validator's base + commission AND the self-delegations' x_d
#      land on the owner, §1.6; node 2's external delegator is paid its
#      own share), and Δ(v2user) > 0 once B − 3E >= C_D (its delegation in
#      the source copy). Payday B (not counted toward the three): the
#      accrual table is empty after it and the payday coins
#      (output_index >= 400) at height B are owned by the Foundation owner
#      and at most v2user (v2user's present once B − 3E >= C_D), summing
#      to the prior accrual + the reward_pool debit.
#   8a. (5d) at B1: on EACH node the stored selection_ruleset
#      (substr(snapshot_blob, 11, 4)) of EVERY snapshot row with
#      epoch_start <= B1 is 00000001 and of snapshot(B1 + E) is 00000002,
#      the list identical 7/7; node 2's entry holds 60M raw in both
#      snapshot(B1) (v1 layout) and snapshot(B1 + E) (v2 layout).
#   8b. (5d) at B1 + E: every node logged "epoch boundary height <B1+E> —
#      validator_updates n_added=0 n_power_changed=1 n_removed=0"
#      (nodus_witness_cmt_app.c FinalizeBlock) — node 2 at raw 60M on the
#      old side, so only the cap on the new side can produce the one
#      change; snapshot(B1 + 2E) is ruleset 2 on 7/7.
#   8c. (5d) B1 + 2E is the first distribution governed by a ruleset-2
#      snapshot: it pays (8's checks) with v2user's share > 0.
#   9. After the last boundary: the step-7 dumps unchanged on 7/7 (four+
#      boundaries do not disturb the migrated rows), and 7/7 identical
#      global_root + block_id at the final floor.
#  10. (6f-2, ONLY with STAGEF_HF6_OWNER_KEYS — otherwise the script says
#      "rotation phase: NOT RUN" and the PASS line says "rotation: not
#      run": coverage that did not happen, never a rotation pass.) Node 2's
#      consensus key rotates onto a FRESH 8th node, cand1, on the same
#      cluster; every check reads chain state, never CLI stdout:
#      (a) v2user pays the owner 10 NODUS (`v2-envelope spend`), applied:
#          the owner's coin with tx_hash = that envelope's intent_id;
#      (b) cand1 derives the fleet's genesis locally (chain id CHECKED
#          against $BASE_DIR/v2_chain_id), starts as a non-validator node
#          (the grow scenario's start line, its own data dir and so its own
#          priv_validator_state.json), runs STAGEF_NODUS_BIN, logs role /
#          startup table / LIVE, and block-syncs to the fleet tip;
#      (c) node 2's validator_id = its validators.pubkey_hash, the same on
#          7/7 and = step 7's (nodus_witness_validator.h: pubkey_hash IS the
#          validator_id from the generation-4 edge on), joined to its roles
#          row; no pending key yet; cand1's key reserved by nobody;
#      (d) cand1's key signs `validator consent --op rotate --owner <owner>
#          --subject <node 2's validator_id> --expiry <tip + 150>`;
#      (e) the owner submits `v2-envelope rotate`; APPLIED = its
#          v2_intent_index row at h_r (a refused item leaves none —
#          nodus_witness_v2_apply.c cmt_item_index);
#      (f) 8/8 (7 + cand1), tip in [h_r, U − 1]: node 2's roles row holds
#          pending = cand1's pubkey and consensus_key_effective_epoch = F;
#          the reservation SHA3-512(cand1 pk) → node 2's id, role 2; the
#          old key still role 1; the validators row still the old key;
#      (g) crossing F, 8/8: snapshot(F) and snapshot(U) are ruleset 2 with
#          raw totals [60M, 10M × 6] (the budget premise); snapshot(U)'s
#          entry for node 2's validator_id carries cand1's pubkey and voter
#          id, 60M, and no entry carries the old key; snapshot(F)'s entry
#          still the old key; snapshot(U)'s hash identical 8/8; every node
#          logged "snapshot(U): 1 rotation(s) accepted, 0 waiting (P_U
#          85714285 R_U 25714285, P_F 85714285 R_F 25714285)" — the
#          acceptance asserted EXPLICITLY, both as bytes and as the node's
#          own budget numbers (header "THE BUDGET");
#      (h) crossing U: blocks U − 1 / U / U + 1 identical 7/7; 8/8 logged
#          "epoch boundary height U — validator_updates n_added=1
#          n_power_changed=0 n_removed=1" (nodus_witness_cmt_app.c
#          FinalizeBlock: the diff is by pubkey, the six others' powers do
#          not move) and "boundary U: 1 consensus key(s) switched to the key
#          S(U) seats" (v2_epoch.c v2ep_rotate_swap); 8/8 at tip in
#          [U, U + E − 1]: the validators row holds cand1's pubkey, pending
#          zero, epoch 0; cand1's reservation role 1 AND the old key's still
#          role 1 (khan A2: kept until U + E); snapshot(U + E), frozen at U,
#          carries cand1's key for node 2's id (Comet does not fall back);
#      (i) attendance, 8/8, two reads >= 3 heights apart inside (U + 3,
#          U + E): cand1's voter (stagef_voter_id) has last_signed_height
#          >= U + 2, signed_count <= tip − U − 2 (it signed nothing before
#          U + 2), and its last_signed_height ADVANCES between the reads;
#          node 2's OLD voter has last_signed_height <= U + 1, signed_count
#          <= 2, both unchanged between the reads; node 2's process is
#          still running (A8: the old node is never stopped here);
#      (j) crossing U + E: 8/8 the old key's reservation and the old
#          voter's attendance row are GONE, cand1's reservation is the one
#          row naming node 2's id (role 1); every node logged "boundary
#          U+E: 1 previous consensus key(s) released with their attendance
#          rows" (v2ep_rotate_sweep); block U + E identical 7/7; node 2
#          and cand1 still running;
#      (k) the final floor comparison 7/7 (stagef_cmt_diff_at_floor) AND
#          cand1 at a floor over all eight (the helper loops 1..7 — the 8th
#          compare is explicit).
#
# WHAT IT REQUIRES
#   Compile flags — ONE short-epoch + short-grace build of THIS tree (an
#   HF-6 branch carrying sub-slices 3a-3d), nodus-server AND nodus-cli from
#   the SAME build, with NODUS_EVM_ENABLED (the default of the standalone
#   non-Windows nodus build — the generation-4 edge FAULTs without it):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9, 16 are ERGONOMIC; param 14 is SAFETY.)
#   THE FOUNDATION OWNER: the default build compiles the K8 address
#   (dnac/include/dnac/dnac.h DNAC_HF6_FOUNDATION_OWNER) and this script
#   expects it by default. The harness's own 2-of-3 multisig
#   ($BASE_DIR/msig_genesis_2of3.desc over nodes 2/3/4, stagef_up_v2.sh)
#   CANNOT be compiled in: its keys are generated at bring-up, after the
#   build. So with the default the owner is an address whose keys the
#   harness does not hold, and NO owner-side operation (UNSTAKE,
#   VALIDATOR_UPDATE, the owner's UNDELEGATE, ROTATE) of a genesis
#   validator can be signed (sub-slice 3c's unit test test_hf6_calls is
#   their proof). (6f-2) The ONE way to sign one here: a single test key
#   generated BEFORE the build (stagef_hf6_owner.sh) and compiled in — the
#   rotation phase, below.
#   A build with -DDNAC_HF6_FOUNDATION_OWNER="{0x..,…}" (exactly 64 bytes,
#   no spaces inside the -D; dnac.h's own form, checked by the 6f-2 author
#   against flags.make and the compiled object — stagef_hf6_owner.sh
#   header) must export the same 64 bytes as hex in STAGEF_HF6_OWNER_FP_HEX
#   (read by this script only); a mismatch FAILs at step 7 with the two
#   values.
#   Environment, ALL exported BEFORE stagef_up_v2.sh unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15  (read by this
#         script only)
#     STAGEF_HF6_OWNER_FP_HEX   (optional, read by this script only — the
#         default is the K8 hex 8eff7f41…9f7b89)
#     STAGEF_HF6_OWNER_KEYS     (6f-2, optional, read by this script only —
#         the owner identity directory; set = run the rotation phase)
#     STAGEF_V2_CANDIDATES=1    (6f-2, with the rotation phase only)
#   Leave STAGEF_PAYOUT_INTERVAL_EPOCHS unset (24): the script steps H − 8
#   off a payday and handles a payday among the post-H boundaries; 1
#   (every boundary a payday) is a SKIP. STAGEF_TREASURY_POOL1_RAW is not
#   needed (no storage node is registered).
#   (5d) The bring-up's non-validator identity $BASE_DIR/v2user with its
#   UNCLAIMED genesis leaf (100M NODUS, stagef_up_v2.sh) — the 50M
#   delegator; a bring-up without it SKIPs, an already-claimed leaf FAILs.
#   The tree must carry HF-6 slice 5d (the ruleset-2 switch, the
#   validator_id tiebreak, the phase-0a `_ex` hash); an older HF-6 tree
#   FAILs at step 8a (snapshot(B1 + E) still ruleset 1).
#   Tools: sqlite3, xxd, ss; with the rotation phase also openssl.
#   (6f-2) THE ROTATION PHASE needs, ALL together (any one missing while
#   STAGEF_HF6_OWNER_KEYS is set FAILs at the gate, before step 1 — the
#   operator asked for the rotation; unset = phase NOT RUN, reported):
#     - a PRE-BUILD owner identity: `bash stagef_hf6_owner.sh <DIR>` (it
#       spawns a short-lived nodus-server exactly like the bring-up's
#       identity spawns, checks nodus.fp == SHA3-512(nodus.pk), and prints
#       the flag and the exports below);
#     - the build ALSO compiled with that identity as the owner:
#       -DDNAC_HF6_FOUNDATION_OWNER="{0x..,…}" inside CMAKE_C_FLAGS (64
#       bytes, no spaces — the helper prints it; dnac.h's override);
#     - STAGEF_HF6_OWNER_FP_HEX = SHA3-512 of that nodus.pk (checked here)
#       and != the K8 address;
#     - STAGEF_HF6_OWNER_KEYS = that identity directory (nodus.pk + .sk);
#     - STAGEF_V2_CANDIDATES=1 exported BEFORE stagef_up_v2.sh (mints
#       $BASE_DIR/cand1 with its own funded leaf, port block C + 3 + 1 =
#       11 → 14100-14104, stagef_up_v2.sh section 1c; a different chain id,
#       nothing else in steps 0-9 reads it) — cand1 must not have run yet
#       (no witness_*.db under cand1/data).
#   Exact command sequence WITH the rotation phase (ORCHESTRATOR):
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_hf6_owner.sh /tmp/hf6-owner    # prints O=… and the FP
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     O='-DDNAC_HF6_FOUNDATION_OWNER="{0x..,…}"'    # the helper's exact line
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-hf6rot -DCMAKE_C_FLAGS="$F $O"
#     make -C <TREE>/nodus/build-hf6rot -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-hf6rot/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-hf6rot/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     export STAGEF_V2_CANDIDATES=1
#     export STAGEF_HF6_OWNER_FP_HEX=<the helper's 128 hex>
#     export STAGEF_HF6_OWNER_KEYS=/tmp/hf6-owner/identity
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_hf6_edge.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   Exact command sequence WITHOUT it (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-shortepoch -DCMAKE_C_FLAGS="$F"
#     make -C <TREE>/nodus/build-shortepoch -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-shortepoch/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-shortepoch/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_hf6_edge.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, STAGEF_EPOCH_LENGTH
#   or the genesis epoch_length != 15, a grace variable != 15, not a Comet
#   cluster, no $BASE_DIR/v2_genesis.conf, payout_interval_epochs <= 1, a
#   tool missing, any split STAGEF_MODE (ruleset-info and the CLI vote path
#   were not checked through a split core). A skip is not a pass.
#   FAIL (rc 1) on the capability gate, on a chain that already holds a
#   param 7 / 8 / 9 / 14 / 16 row, a delegation or a roles row (single-use
#   — needs a fresh bring-up), and on STAGEF_HF6_OWNER_FP_HEX malformed.
#   (6f-2) FAIL (rc 1) at the gate when STAGEF_HF6_OWNER_KEYS is set but:
#   it holds no nodus.pk (2592 B) / nodus.sk, SHA3-512(nodus.pk) differs
#   from STAGEF_HF6_OWNER_FP_HEX (or the latter is the K8 default), openssl
#   is missing, $BASE_DIR/cand1/identity is missing (STAGEF_V2_CANDIDATES
#   not exported before bring-up), cand1 already has a chain database, or
#   cand1 / the owner shares a fingerprint with a harness node or v2user.
#
# WHAT IT LEAVES BEHIND
#   HF-2 ACTIVE, HF-3 ACTIVE, rule-set generation 2, the EVM generation 3 +
#   EVM domain and generation 4 (HF-6) — all one-way; five
#   chain_config_history rows (params 7, 8, 9, 14, 16). The validator rows
#   re-keyed to validator_id with 2M bonds, seven 8M self-delegations owned
#   by the Foundation owner, seven v2_validator_roles rows, every node-key
#   accrual merged into the Foundation row (then grown by every boundary; a
#   payday crossed pays it as ONE coin to the Foundation address, which the
#   harness cannot spend). (5d) v2user's leaf claimed and 50M NODUS of it
#   delegated to node 2 for good (node 2 raw 60M — capped to 25714285
#   counted power in every ruleset-2 snapshot from B1 + E; a payday crossed
#   pays v2user a coin too); every snapshot from B1 + E on is ruleset 2.
#   Node 3's genesis leaf claimed by the pump and every pump fee (and
#   v2user's two fees) in the reward pool. $BASE_DIR/hf6/ (CLI logs).
#   Nothing killed or restarted. Tear down with stagef_down.sh before
#   re-running (params 9 / 14 / 16 and the v2user leaf are single-use).
#   (6f-2, rotation phase only) An EIGHTH running process: cand1
#   (nodus-server, $BASE_DIR/cand1/{data,nodus.log,derive.log}, ports
#   14100-14104, its pid appended to pids.txt so stagef_down.sh stops it);
#   node 2's validator ROTATED for good — its validators row carries
#   cand1's key, cand1 signs for it from U + 2 (it holds 25714285 of
#   85714285 counted power; node 2's process keeps running as a
#   non-validator full node); the owner holds 10 NODUS minus the ROTATE
#   fee; v2user's funding fee in the reward pool; $BASE_DIR/hf6/rot_*.log
#   and the consent file $BASE_DIR/hf6/rot_consent.txt. Single-use: a
#   second run needs a fresh bring-up (cand1's chain DB exists — refused).
#
# HOW IT CAN LIE
#   - **E = 15, grace 15/15, BPY 20 prove the LOGIC**, nothing about the
#     production 720 / 720 / 6 307 200 (README "WHAT A GREEN HARNESS RUN
#     DOES NOT PROVE").
#   - **The trigger is the development one** (param 16 + the storage
#     literal, design §10 item 2). Slice 8 moves it to param 18 / D4; this
#     scenario does not exercise that vote, its stateful rule or the mixed
#     fleet refusing param 16.
#   - **Every node runs the same binary**: a gen-4 reader forgotten
#     UNIFORMLY computes the same wrong value on all seven, and 7/7 identity
#     cannot see it. What this scenario does see: a forgotten reader that
#     FAULTS (the chain stalls -> FAIL), accrual landing anywhere but the
#     owner (step 8), and the exact pool -> accrual conservation. The
#     reader inventory is test_hf6_readers' subject.
#   - **Owner operations are NOT exercised** except ONE: the rotation
#     phase's ROTATE, and only with STAGEF_HF6_OWNER_KEYS (a kind-1 test
#     owner compiled in — the production Foundation owner is the kind-3
#     K8 2-of-3, whose ROTATE the 6f-1 CLI cannot build: NOT exercised).
#     Without the variable the phase does not run and the PASS line says
#     "rotation: not run" — that is coverage that did not happen. Never
#     exercised here: UNSTAKE / VALIDATOR_UPDATE / the owner's UNDELEGATE,
#     STAKE (a generation-4 STAKE — test_hf6_stake), a non-genesis
#     (own-owner) validator, a pre-H SELF-delegation (plan D5), a RETIRING
#     row graduating to the owner: the harness genesis has only seven
#     ACTIVE genesis rows, and the one pre-H delegation is an EXTERNAL one
#     (v2user). Those are the unit tests' (test_hf6_migrate, test_hf6_calls,
#     test_hf6_readers, test_hf6_rotate).
#   - **(6f-2) A rotation the budget never accepts would look like "no
#     switch"**, not like a failure, if only the row were read. So the
#     acceptance is asserted EXPLICITLY at F, before U: snapshot(U)'s bytes
#     carry the new key for node 2's id on 8/8 AND every node logged "1
#     rotation(s) accepted, 0 waiting" with the budget numbers of the
#     header's arithmetic; a "0 accepted, 1 waiting" line or old-key bytes
#     FAIL at (g), never pass at (h).
#   - **(6f-2) ONE rotation, of the validator with the largest counted
#     power (30 %)**; the budget's refusal path (a party that would breach
#     floor(2P/3)), a deferred rotation re-evaluated a boundary later, two
#     rotations in one freeze, a candidate absent from S(F) (khan A3) and a
#     rotating validator that graduates are NOT exercised — test_hf6_rotate
#     and the 6d unit fixtures are their proof.
#   - **(6f-2) The old node is NEVER stopped**, so a rotation that silently
#     still needed node 2's old process after U + 1 cannot show here; the
#     run proves only that the old key stops being credited after U + 1
#     and the new one is credited from U + 2. What an operator must keep
#     running, and until when, is the runbook's (A8). With the old node
#     up, even a cand1 that never signs would NOT halt the chain (the other
#     six hold 60000000 > 57142856 of 85714285) — which is why (i) asserts
#     cand1's attendance directly instead of relying on liveness.
#   - **(6f-2) Attendance credits come from each block's LastCommit**: a
#     precommit that arrives after the proposer's commit is ABSENT there.
#     (i) therefore asserts upper bounds for the old key (<= U + 1) and
#     "credited at least once from U + 2 and advancing" for the new one —
#     never an exact count; a cand1 whose precommits were never included
#     at all FAILs (i).
#   - **(6f-2) cand1's catch-up from genesis (≈ 450 blocks through five
#     generation edges) is NOT measured** — waited with the grow
#     scenario's wide 8-interval progress bound; a stall FAILs with that
#     reason. That it replays every edge byte-identically is shown only by
#     (k)'s 8th compare and its own log lines.
#   - **(5d) The counted power value is NOT read from cometbft.** Comet's
#     validator set lives in opaque protobuf blobs this harness cannot
#     decode, and no RPC reports the counted power (slice 5e). What is
#     asserted: node 2's RAW 60M in both stored blobs (decoded at fixed
#     offsets, shared/dnac/vset_wire.h) and the node's own log line
#     n_power_changed=1 at B1 + E — raw on both sides would log 0, so the
#     one change is the cap's; that it is exactly 25714285 is the unit
#     tests' (test_hf6_readers F4, test_cmt_app). A build that capped to
#     some OTHER value < 60M would log the same line.
#   - **(5d) The validator_id tiebreak order is NOT decoded here**: node 2
#     is alone at the top and the six equal seats' order is not compared
#     with the tiebreak (test_hf6_readers F2 / test_committee_election
#     (7)); 7/7 identical blocks and snapshot hashes are what this scenario
#     sees of it.
#   - **The committee after H is not decoded** beyond node 2's entry.
#     Continued 7/7 commits and the "every boundary pays the owner" checks
#     are indirect evidence the same seven sign; test_hf6_readers asserts
#     the re-selection directly.
#   - (5d) node 2 holds 50 % of the RAW power from the first v1 snapshot
#     holding the delegation until B1 + E: every commit in that window
#     needs node 2's precommit (+2/3 of 120M = 80M; the other six hold
#     60M) — a node-2 stall there halts the chain (FAIL, never a pass).
#   - **The validator_id VALUE is not re-derived** (crypto — slice 1's
#     codec and oracle): only that it is a 64-byte key differing from the
#     row's pre-edge tagged hash, joined to its roles row, identical 7/7.
#   - **Only the boundary ≥ B1 + 3E pays from a post-edge copy.** Earlier
#     ones read the pre-edge copies (10M bonds; node 2's 50M external
#     delegation from C_D on) through the v1-snapshot bridge (§7.5) up to
#     B1 + E and, from B1 + 2E, through a ruleset-2 snapshot by
#     validator_id. The per-member split (base 20 %, x_d 80 %) is not
#     separable for the Foundation: one owner receives both; v2user's
#     share is asserted > 0 and the owner + v2user total == the pool debit,
#     not each amount (their exact values are the unit tests').
#   - **A payday among the post-H boundaries is checked differently**
#     (one coin, exact amount) and not counted toward the three; it is not
#     required to occur.
#   - **The two windows are wall-clock-adjacent** (idle production ≈ 60 s
#     per block): a read that lands outside its window FAILs with "layout
#     broke" — a false RED, never a false PASS. An envelope (anyone's)
#     inside a boundary window FAILs the same way (attribution would be
#     impossible).
#   - **Every proposal is kept away from an epoch boundary** (cc_guard,
#     copied — the CLI's committee/epoch edge, BUGS.md); a tip crossing one
#     while the CLI runs FAILs (false RED).
#   - The log lines are asserted, but they are the node's own words —
#     the table checks are the proof.
#   - Every wait is progress- and height-bounded (stagef_cmt_wait_height /
#     _wait_row / stagef_cmt_pump_to), never a bare sleep. rc 99 = SKIP,
#     coverage that did not happen.
#   - Duration: ≈ 350 blocks (JUDGMENT, not measured): pumped to the EVM
#     edge's window floor (≈ 262) and on to H (≈ 300), idle across the
#     GEN2, EVM and HF-6 edges (≈ 8 blocks each) and ≈ 4 blocks before
#     each of four or five boundaries — on the order of 1-1.5 h. (6f-2)
#     The rotation phase adds cand1's catch-up (unmeasured) and ≈ 2E + 15
#     pumped blocks (F, U, U + E) — JUDGMENT ≈ 20-30 min more.
#   - Run results: none yet — written against the source, NOT run by its
#     author (sub-slice 3f, the slice-5d extension: 2b, 8a-8c, and the
#     slice-6f-2 rotation phase 10).
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# hf6: ruleset-info and the vote path were not checked through a split
# core — SKIP (99) in every split mode (the archive scenario's rule).
stagef_split_skip_if --reason "HF-6 edge scenario not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE (dnac.h), value exactly D
PARAM_STOR=16              # DNAC_CFG_RULESET_GEN_STORAGE — hf6: the dev trigger
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM (= NODUS_RT_GEN_STORAGE_BASE)
GEN_4=4                    # NODUS_RT_GEN_STORAGE — hf6: THE HF-6 generation
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
H_MOD=8                    # hf6: H % E (see the header, "WHY H % E == 8")
PRE_B_GAP=3                # hf6: idle blocks before each checked boundary
MAX_BOUNDARIES=6           # hf6: at most one payday fits in six boundaries
E_REQ=15
E="$E_REQ"
SELF_OLD=1000000000000000  # hf6: DNAC_SELF_STAKE_AMOUNT = 10M x 10^8
BOND_NEW=200000000000000   # hf6: DNAC_HF6_STAKE_MIN_DEFAULT = 2M x 10^8
SELFDEL=800000000000000    # hf6: SELF_OLD - BOND_NEW = 8M x 10^8
# 5d: the external delegation that makes node 2 [60M, 10M × 6] raw
DELEG_NODE=2
DELEG_AMT=5000000000000000 # 5d: 50M x 10^8 (node 2: 10M + 50M = 60M)
USER_DIR="$BASE_DIR/v2user"
RS_V1=00000001             # 5d: DNA_VSET_RULESET_TOPN_V1, u32 big-endian
RS_V2=00000002             # 5d: DNA_VSET_RULESET_TOPN_V2
# 5d: shared/dnac/vset_wire.h layout — header 78 B (epoch u64, count u16,
# ruleset u32, seed 64); v1 entry 2642 B (voter 32, pubkey 2592, total u64,
# self u64, commission u16); v2 entry 2770 B (voter 32, validator_id 64,
# owner 64, pubkey 2592, total, self, commission)
VSET_HDR=78
VSET_E1=2642; VSET_PK_OFF1=32
VSET_E2=2770; VSET_PK_OFF2=160
# hf6: the K8 Foundation address (dnac/include/dnac/dnac.h
# DNAC_HF6_FOUNDATION_OWNER, the hex in its own comment) — the default
# build's compiled owner. A test build with another owner exports its hex.
K8_OWNER=8eff7f418ab7a4432118ff99e21f2c3d1baf186200c148a3bba7d274499386ac970e267a9c9b3bbc05bfff1c62a72d63f72a555db780feeaaad4fb49ba9f7b89
OWNER="${STAGEF_HF6_OWNER_FP_HEX:-$K8_OWNER}"
OWNER=$(printf '%s' "$OWNER" | tr 'A-F' 'a-f')
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf6"
N="$STAGEF_COMMITTEE_SIZE"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN=$SRV" "STAGEF_NODUSCLI_BIN=$CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs the short-epoch"
        echo "       build of an HF-6 tree; see the header"
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
for t in sqlite3 xxd ss; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the HF-6 checks need it"
        exit 99
    fi
done
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
if [ ! -s "$USER_DIR/identity/nodus.pk" ] || [ ! -s "$USER_DIR/identity/nodus.fp" ]; then
    echo "[SKIP] no non-validator identity under $USER_DIR — the 5d delegator; a"
    echo "       stagef_up_v2.sh bring-up creates it with its own genesis leaf"
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
    echo "[SKIP] payout_interval_epochs=$INTERVAL: every boundary is a payday, so neither the"
    echo "       pre-edge accrual (K4's input) nor a non-payday owner credit can be observed —"
    echo "       leave STAGEF_PAYOUT_INTERVAL_EPOCHS unset (24)"
    exit 99
fi
[[ "$OWNER" =~ ^[0-9a-f]{128}$ ]] || die "STAGEF_HF6_OWNER_FP_HEX is not 128 hex characters ('$OWNER')"
mkdir -p "$LOGD"

# ── 6f-2: the rotation phase's gate (FAIL when asked for and impossible) ─
# Set = the operator asked for the rotation, so every missing piece FAILs
# here, before the ≈ 1-1.5 h of steps 1-9 (header "WHAT IT REQUIRES",
# 6f-2). Unset = the phase is NOT RUN and says so (step 10, PASS line).
ROT_KEYS="${STAGEF_HF6_OWNER_KEYS:-}"
CAND_DIR="$BASE_DIR/cand1"
CAND_PIDX=$(( N + 3 + 1 ))   # stagef_up_v2.sh section 1c: candidate i at C + 3 + i
if [ -n "$ROT_KEYS" ]; then
    command -v openssl >/dev/null 2>&1 || die "STAGEF_HF6_OWNER_KEYS is set but openssl is not installed (SHA3-512 checks)"
    [ -s "$ROT_KEYS/nodus.pk" ] && [ -s "$ROT_KEYS/nodus.sk" ] || die \
        "STAGEF_HF6_OWNER_KEYS=$ROT_KEYS holds no nodus.pk / nodus.sk — make it with stagef_hf6_owner.sh BEFORE the build"
    [ "$(stat -c %s "$ROT_KEYS/nodus.pk")" = 2592 ] || die "$ROT_KEYS/nodus.pk is not 2592 bytes"
    [ "$OWNER" != "$K8_OWNER" ] || die \
        "STAGEF_HF6_OWNER_KEYS is set but STAGEF_HF6_OWNER_FP_HEX is the K8 default — a rotation needs the test owner compiled in (stagef_hf6_owner.sh prints the flag)"
    rot_kfp=$(stagef_sha3_512_hex "$ROT_KEYS/nodus.pk")
    [ "$rot_kfp" = "$OWNER" ] || die \
        "SHA3-512($ROT_KEYS/nodus.pk) = ${rot_kfp:0:16}… is not STAGEF_HF6_OWNER_FP_HEX ${OWNER:0:16}… — the owner key and the compiled owner must be one identity"
    [ -s "$CAND_DIR/identity/nodus.pk" ] && [ -s "$CAND_DIR/identity/nodus.fp" ] && \
        [ -s "$CAND_DIR/identity/nodus.mlkem_sk" ] || die \
        "no rotation target identity under $CAND_DIR — export STAGEF_V2_CANDIDATES=1 BEFORE stagef_up_v2.sh"
    for f in "$CAND_DIR/data/"witness_*.db; do
        if [ -e "$f" ]; then
            die "cand1 already has a chain database ($f) — this bring-up already ran the rotation phase; bring up fresh"
        fi
    done
    [ -s "$BASE_DIR/v2_chain_id" ] || die "the bring-up recorded no $BASE_DIR/v2_chain_id (cand1's derived genesis is checked against it)"
    echo "[ok] 6f-2 rotation phase armed: owner keys $ROT_KEYS (SHA3-512 = the compiled owner), target cand1 (port block $CAND_PIDX)"
else
    echo "[info] 6f-2 rotation phase: NOT armed (STAGEF_HF6_OWNER_KEYS unset) — step 10 will not run"
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
# cmd_chain_config_propose, printed before any connect)
usage_out=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
D_DEC=$(sed -n 's/^  EVM_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D_DEC="${D_DEC%%$'\n'*}"
DS_DEC=$(sed -n 's/^  RULESET_GEN_STORAGE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
DS_DEC="${DS_DEC%%$'\n'*}"
[ -n "$D_DEC" ] && [ -n "$DS_DEC" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's chain-config usage does not name both 'EVM_ACTIVE exactly <D>' and 'RULESET_GEN_STORAGE exactly <DS>'"; }
[ "$D_DEC" -gt 0 ] 2>/dev/null && [ "$DS_DEC" -gt 0 ] 2>/dev/null || die "a vote literal is not a positive int64 (D '$D_DEC', DS '$DS_DEC')"
D_HEX=$(printf '%016x' "$D_DEC"); DS_HEX=$(printf '%016x' "$DS_DEC")
# hf6: schema S18 — the roles table exists only in an HF-6 build's database
has_roles=$(sqlite3 "$ref_db0" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_validator_roles';" 2>/dev/null || echo ERR)
[ "$has_roles" = 1 ] || die "node1's database has no v2_validator_roles table (schema S18) — not an HF-6 build"
echo "[ok] capability gate: one build v$SRV_VER; EVM D = $D_DEC (0x$D_HEX), dev trigger DS = $DS_DEC (0x$DS_HEX); schema S18"

# ── script-local helpers (test_storage_archive.sh's, unless "hf6:") ─
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_lc()  { tr 'A-F' 'a-f' < "$1/nodus.fp"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }

node_runs_srv() {
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$SRV")" ] && return 0
    done
    return 1
}

# hf6: the pump is stagef_env.sh's (funder node 3, submitted to node 1,
# one input / one output at the fixed fee, --no-dust-sweep, each step
# confirmed by its created utxo_set row) — reference DB node 1.
pump_to() {
    local target="$1" h prc
    h=$(stagef_cmt_pump_to "$(db_of 1)" "$target") && prc=0 || prc=$?
    case "$prc" in
        0) echo "[ok] node1 tip $h >= $target (pumped)" ;;
        1) die "chain STALLED while pumping to $target (tip $h)" ;;
        2) die "a pump spend was not included within 20 heights while pumping to $target (tip $h) — dropped, not delayed" ;;
        *) die "the pump faulted (rc $prc) while pumping to $target (tip $h) — its output is above" ;;
    esac
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
# the committee of tip + 1 but the epoch of tip — BUGS.md): the proposer's
# tip t must be off a boundary and >= CC_GUARD_GAP before the next one,
# else pump to the next boundary + 1. Sets CCG_TIP / CCG_NB.
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
        pump_to $(( nb + 1 ))
        wait_all $(( nb + 1 ))
    done
    die "node$n's tip $(tip_of "$n") is still next to an epoch boundary after two guard pumps"
}

cc_guard_after() {
    local t
    t=$(tip_of "$1")
    [ $(( t + 1 )) -lt "$CCG_NB" ] || die \
        "the proposal from node$1 crossed into the epoch boundary $CCG_NB (tip $CCG_TIP -> $t): its approvals may straddle two epochs (the CLI committee/epoch edge, BUGS.md) — the layout broke, not the chain"
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

# ruleset_info NODE — nodus-cli.c cmd_ruleset_info's lines
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

# cross_edge LABEL H — pumped to H - PUMP_STOP_GAP, then idle across
# H - 1 / H / H + 1, compared 7/7 AT each.
cross_edge() {
    local label="$1" hh="$2" x
    pump_to $(( hh - PUMP_STOP_GAP ))
    wait_all $(( hh + 1 ))
    for x in $(( hh - 1 )) "$hh" $(( hh + 1 )); do diff_at "$x" "$label-at-height-$x"; done
}

# ── hf6: helpers ─────────────────────────────────────────────────────
is_payday() { [ $(( ($1 / E) % INTERVAL )) -eq 0 ]; }

# hf6: the node-key fingerprints and raw pubkeys (hex, lowercase) of the
# seven harness nodes — the rows are tied to nodes by the pubkey bytes.
declare -A NODE_OF_PK=() NODE_FP=() IS_NODE_FP=()
for n in $(seq 1 "$N"); do
    k="$(node_keys "$n")"
    [ -s "$k/nodus.pk" ] && [ -s "$k/nodus.fp" ] || die "node$n has no nodus.pk / nodus.fp under $k"
    pk=$(xxd -p "$k/nodus.pk" | tr -d '\n')
    [ "${#pk}" = 5184 ] || die "node$n's nodus.pk is not 2592 bytes (${#pk} hex)"
    fp=$(fp_lc "$k")
    [ "${#fp}" = 128 ] || die "node$n's fingerprint is not 128 hex"
    [ "$fp" != "$OWNER" ] || die "node$n's fingerprint equals the Foundation owner — the owner checks would be vacuous"
    NODE_OF_PK["$pk"]="$n"; NODE_FP["$n"]="$fp"; IS_NODE_FP["$fp"]=1
done
# 5d: the delegator (v2user) and the delegated validator (node 2)
USER_PK=$(xxd -p "$USER_DIR/identity/nodus.pk" | tr -d '\n')
[ "${#USER_PK}" = 5184 ] || die "v2user's nodus.pk is not 2592 bytes (${#USER_PK} hex)"
USER_FP=$(fp_lc "$USER_DIR/identity")
[ "${#USER_FP}" = 128 ] || die "v2user's fingerprint is not 128 hex"
[ -z "${IS_NODE_FP[$USER_FP]:-}" ] && [ "$USER_FP" != "$OWNER" ] \
    || die "v2user's fingerprint equals a node key or the Foundation owner — the payee checks would be vacuous"
DELEG_PK=$(xxd -p "$(node_keys "$DELEG_NODE")/nodus.pk" | tr -d '\n')
# accrual owners a step-8 table may hold: the owner and v2user
acc_owner_ok() { [ "$1" = "$OWNER" ] || [ "$1" = "$USER_FP" ]; }
# 6f-2: the rotation's three identities must be distinct from every
# harness payee, or a check below could pass on the wrong key
if [ -n "$ROT_KEYS" ]; then
    CAND_FP=$(fp_lc "$CAND_DIR/identity")
    [ "${#CAND_FP}" = 128 ] || die "cand1's fingerprint is not 128 hex"
    [ -z "${IS_NODE_FP[$CAND_FP]:-}" ] && [ "$CAND_FP" != "$OWNER" ] && [ "$CAND_FP" != "$USER_FP" ] \
        || die "cand1's fingerprint equals a node key, the owner or v2user — the rotation checks would be vacuous"
    [ "$OWNER" != "$USER_FP" ] || die "the owner equals v2user — the funding check would be vacuous"
fi

# hf6: stake_snap NODE — ONE statement: "tip Σself Σtotal_delegated
# n_validators n_delegations n_roles Σaccrual n_accrual accrual_list"
# (accrual_list = owner:amount,… in owner order, '-' when empty).
stake_snap() {
    local out
    out=$(sqlite3 -separator ' ' "$(db_of "$1")" \
      "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
              (SELECT COALESCE(SUM(self_stake),0) FROM validators),
              (SELECT COALESCE(SUM(total_delegated),0) FROM validators),
              (SELECT COUNT(*) FROM validators),
              (SELECT COUNT(*) FROM delegations),
              (SELECT COUNT(*) FROM v2_validator_roles),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual),
              (SELECT COUNT(*) FROM v2_reward_accrual),
              (SELECT COALESCE(group_concat(r, ','), '-') FROM
                 (SELECT lower(hex(owner_fp)) || ':' || amount AS r FROM v2_reward_accrual
                   ORDER BY owner_fp));" 2>&1) || { printf '%s\n' "$out"; return 1; }
    [[ "$out" =~ ^-?[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [-0-9a-f:,]+$ ]] \
        || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
}

# hf6: acc_snap NODE — ONE statement: "tip reward_pool Σaccrual n_accrual
# owner_row user_row accrual_list" (owner_row = the Foundation owner's
# amount, user_row = v2user's (5d), each 0 when absent).
acc_snap() {
    local out
    out=$(sqlite3 -separator ' ' "$(db_of "$1")" \
      "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
              (SELECT reward_pool FROM supply_tracking WHERE id = 1),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual),
              (SELECT COUNT(*) FROM v2_reward_accrual),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual WHERE lower(hex(owner_fp)) = '$OWNER'),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual WHERE lower(hex(owner_fp)) = '$USER_FP'),
              (SELECT COALESCE(group_concat(r, ','), '-') FROM
                 (SELECT lower(hex(owner_fp)) || ':' || amount AS r FROM v2_reward_accrual
                   ORDER BY owner_fp));" 2>&1) || { printf '%s\n' "$out"; return 1; }
    [[ "$out" =~ ^-?[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [-0-9a-f:,]+$ ]] \
        || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
}

# 5d: rs_dump NODE — every stored snapshot's epoch and selection_ruleset
# (blob bytes 10..13, 1-based substr 11..14), epoch order:
# "epoch:RRRRRRRR,…".
rs_dump() {
    sqlite3 "$(db_of "$1")" \
        "SELECT COALESCE(group_concat(r, ','), '-') FROM
           (SELECT epoch_start || ':' || lower(hex(substr(snapshot_blob, 11, 4))) AS r
              FROM validator_set_snapshots ORDER BY epoch_start);" 2>/dev/null || echo ERR
}

# 5d: snap_total NODE EPOCH PUBKEYHEX — the raw total_stake of the entry
# holding PUBKEYHEX in the stored snapshot(EPOCH), decoded at the fixed
# offsets of its own ruleset's layout (header constants above); "ERR"
# when the row, the ruleset or the key is not found.
snap_total() {
    local db n_hex rs cnt elen pko i st row pkh toth
    db=$(db_of "$1")
    row=$(sqlite3 -separator ' ' "$db" \
        "SELECT lower(hex(substr(snapshot_blob, 9, 2))), lower(hex(substr(snapshot_blob, 11, 4)))
           FROM validator_set_snapshots WHERE epoch_start = $2;" 2>/dev/null || true)
    read -r n_hex rs <<< "$row"
    case "$rs" in
        "$RS_V1") elen="$VSET_E1"; pko="$VSET_PK_OFF1" ;;
        "$RS_V2") elen="$VSET_E2"; pko="$VSET_PK_OFF2" ;;
        *) echo ERR; return 0 ;;
    esac
    [[ "$n_hex" =~ ^[0-9a-f]{4}$ ]] || { echo ERR; return 0; }
    cnt=$(( 16#$n_hex ))
    for (( i = 0; i < cnt; i++ )); do
        st=$(( VSET_HDR + i * elen + pko + 1 ))       # 1-based substr
        row=$(sqlite3 -separator ' ' "$db" \
            "SELECT lower(hex(substr(snapshot_blob, $st, 2592))),
                    lower(hex(substr(snapshot_blob, $(( st + 2592 )), 8)))
               FROM validator_set_snapshots WHERE epoch_start = $2;" 2>/dev/null || true)
        read -r pkh toth <<< "$row"
        if [ "$pkh" = "$3" ]; then
            [[ "$toth" =~ ^[0-9a-f]{16}$ ]] || { echo ERR; return 0; }
            echo $(( 16#$toth ))
            return 0
        fi
    done
    echo ERR
}

# hf6: val_dump NODE — the validator rows joined to their roles rows,
# canonical (pubkey_hash order): vid|pubkey|self|td|ed|status|active_since|
# owner|pending_is_zero|key_epoch — a missing roles row reads an empty
# owner and fails the per-row checks.
val_dump() {
    sqlite3 "$(db_of "$1")" \
        "SELECT lower(hex(v.pubkey_hash)), lower(hex(v.pubkey)), v.self_stake, v.total_delegated,
                v.external_delegated, v.status, v.active_since_block, lower(hex(r.owner_fp)),
                (r.pending_consensus_pubkey = zeroblob(2592)), r.consensus_key_effective_epoch
           FROM validators v LEFT JOIN v2_validator_roles r ON r.validator_id = v.pubkey_hash
          ORDER BY v.pubkey_hash;" 2>/dev/null || echo ERR
}

# hf6: del_dump NODE — delegator|validator|amount|delegated_at, PK order
del_dump() {
    sqlite3 "$(db_of "$1")" \
        "SELECT lower(hex(delegator_hash)), lower(hex(validator_hash)), amount, delegated_at_block
           FROM delegations ORDER BY validator_hash, delegator_hash;" 2>/dev/null || echo ERR
}

# hf6: same_on_all WHAT FN — FN's output on node 1 equals every node's;
# prints node 1's.
same_on_all() {
    local what="$1" fn="$2" ref d n
    ref=$("$fn" 1)
    [ "$ref" != ERR ] && [ -n "$ref" ] || die "$what: node1's read failed or is empty"
    for n in $(seq 2 "$N"); do
        d=$("$fn" "$n")
        [ "$d" = "$ref" ] || { printf 'node1:\n%s\nnode%s:\n%s\n' "$ref" "$n" "$d" >&2
            die "$what: node$n differs from node1"; }
    done
    printf '%s\n' "$ref"
}

# ── 0. preconditions: a fresh cluster on this build ─────────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM" "$PARAM_STOR"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
for tb in delegations v2_validator_roles; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM $tb;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1's $tb is not empty — this scenario needs a fresh bring-up"
done
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
# hf6: the seven genesis rows, one per harness node, each the D2 (a) shape
declare -A PRE_KEY=() SEEN=()
nrow=0
while IFS='|' read -r vh vpk vs vtd ved vst vas; do
    nrow=$(( nrow + 1 ))
    n="${NODE_OF_PK[$vpk]:-}"
    [ -n "$n" ] || die "a validators row's pubkey belongs to no harness node (${vpk:0:16}...)"
    [ -z "${SEEN[$n]:-}" ] || die "node$n's pubkey has two validators rows"
    SEEN["$n"]=1; PRE_KEY["$vpk"]="$vh"
    [ "$vs" = "$SELF_OLD" ] || die "node$n's row holds self_stake $vs, expected $SELF_OLD (10M)"
    [ "$vtd" = 0 ] && [ "$ved" = 0 ] || die "node$n's row holds delegations already ($vtd / $ved)"
    [ "$vst" = 0 ] || [ "$vst" = 4 ] || die "node$n's row is status $vst, not ACTIVE (0) / ELIGIBLE (4)"
    [ "$vas" -le 1 ] || die "node$n's row has active_since_block $vas > 1 — not a genesis row, D2 (a) would not make it Foundation-owned"
done < <(sqlite3 "$ref_db0" \
    "SELECT lower(hex(pubkey_hash)), lower(hex(pubkey)), self_stake, total_delegated, external_delegated,
            status, active_since_block FROM validators ORDER BY pubkey_hash;" 2>/dev/null || echo ERR)
[ "$nrow" = "$N" ] || die "node1 holds $nrow validators rows, expected $N"
stagef_cmt_pump_ready "$(db_of 1)" || die "the CLI-SPEND pump is not usable on this bring-up (reason above)"
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run $(readlink -f "$SRV"); $N genesis rows (10M, active_since <= 1); payday every $INTERVAL epochs"
echo "[ok] expected Foundation owner ${OWNER:0:16}... ($([ "$OWNER" = "$K8_OWNER" ] && echo 'the K8 default' || echo 'STAGEF_HF6_OWNER_FP_HEX'))"

# ── 1. the chain commits ────────────────────────────────────────────
stagef_cmt_diff_at_floor "pre-hf6" || exit 2

# ── 2. the prerequisites: HF-2, HF-3, generation 2, the EVM generation ─
cc_guard 1
H2=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF2_ACTIVE=1 effective H2=$H2"
propose HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
[ "$CC_CB" -lt "$H2" ] || die "the HF2 row committed at $CC_CB, not before its effective height $H2"
pump_to $(( H2 + 1 ))
wait_all $(( H2 + 1 ))
stagef_cmt_diff_at_floor "past-HF2" || exit 2

cc_guard 1
H3=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF3_ACTIVE=1 effective H3=$H3"
propose HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
[ "$CC_CB" -lt "$H3" ] || die "the HF3 row committed at $CC_CB, not before its effective height $H3"
pump_to $(( H3 + 1 ))
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

# ── 2b. 5d: v2user claims its leaf and delegates 50M to node 2 (gen 3) ─
# (test_v2_stake.sh's funding claim, test_cmt_self_delegate.sh's
# delegate — both waited on their ledger effect, never on a height)
UPORT=$(stagef_tcp_port 1)
UKEYS="$USER_DIR/identity"
udry="$LOGD/v2user_claim_dry.log"
"$CLI" -s 127.0.0.1 -p "$UPORT" v2-claim --config "$CONF" --db "$(db_of 1)" \
    --keys "$UKEYS" --dry-run > "$udry" 2>&1 \
    || { cat "$udry" >&2; die "v2user's funding claim could not be BUILT (local self-check failed)"; }
u_null=$(awk '/^ *nullifier=/{sub(/^ *nullifier=/,""); print}' "$udry")
[ "${#u_null}" = 128 ] || die "could not read a 64-byte nullifier from v2user's claim dry run"
ulog="$LOGD/v2user_claim.log"
"$CLI" -s 127.0.0.1 -p "$UPORT" v2-claim --config "$CONF" --db "$(db_of 1)" \
    --keys "$UKEYS" --submit "127.0.0.1:$UPORT" > "$ulog" 2>&1 \
    || { cat "$ulog" >&2; die "v2user's funding claim was REJECTED (CheckTx) — its leaf already claimed? (needs a fresh bring-up)"; }
uh=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$u_null';" 4) && uwrc=0 || uwrc=$?
[ "$uwrc" = 1 ] && die "v2user's funding claim never appeared and the chain STALLED at $uh"
[ "$uwrc" = 2 ] && die "v2user's funding claim was not included within 20 heights (tip $uh) — dropped, not delayed"
echo "[ok] v2user funded by its own genesis leaf (tip $uh)"
ddry="$LOGD/v2user_delegate_dry.log"
"$CLI" -s 127.0.0.1 -p "$UPORT" v2-envelope delegate --keys "$UKEYS" \
    --validator "$DELEG_PK" --amount "$DELEG_AMT" --dry-run > "$ddry" 2>&1 \
    || { cat "$ddry" >&2; die "v2user's DELEGATE could not be BUILT (self-check against node 1 failed)"; }
grep -q 'PREFLIGHT SELF-CHECK: OK' "$ddry" \
    || { cat "$ddry" >&2; die "v2user's delegate dry run printed no self-check verdict"; }
dlog="$LOGD/v2user_delegate.log"
"$CLI" -s 127.0.0.1 -p "$UPORT" v2-envelope delegate --keys "$UKEYS" \
    --validator "$DELEG_PK" --amount "$DELEG_AMT" --submit "127.0.0.1:$UPORT" > "$dlog" 2>&1 \
    || { cat "$dlog" >&2; die "v2user's DELEGATE was REJECTED (CheckTx) — read the log above"; }
d_intent=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print}' "$dlog")
[ "${#d_intent}" = 128 ] || die "could not read a 64-byte intent_id from v2user's DELEGATE submit output"
dh=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$d_intent';" 4) && dwrc=0 || dwrc=$?
[ "$dwrc" = 1 ] && die "v2user's delegation never appeared and the chain STALLED at $dh"
[ "$dwrc" = 2 ] && die "v2user's delegation was not included within 20 heights (tip $dh) — dropped, not delayed"
H_D=$(sqlite3 "$(db_of 1)" \
    "SELECT global_height FROM v2_intent_index WHERE lower(hex(intent_id)) = '$d_intent' LIMIT 1;" 2>/dev/null || true)
case "$H_D" in ''|*[!0-9]*) die "v2user's delegation landed but its height could not be read ('$H_D')" ;; esac
C_D=$(( (H_D + E - 1) / E * E ))   # the first boundary >= H_D: copy(C_D) first holds it
wait_all "$H_D"
for n in $(seq 1 "$N"); do
    r=$(sqlite3 -separator '|' "$(db_of "$n")" \
        "SELECT (SELECT COALESCE(SUM(amount),0) FROM delegations
                  WHERE lower(hex(delegator_pubkey)) = '$USER_PK' AND lower(hex(validator_pubkey)) = '$DELEG_PK'),
                (SELECT total_delegated FROM validators WHERE lower(hex(pubkey)) = '$DELEG_PK'),
                (SELECT external_delegated FROM validators WHERE lower(hex(pubkey)) = '$DELEG_PK');" \
        2>/dev/null || echo ERR)
    [ "$r" = "$DELEG_AMT|$DELEG_AMT|$DELEG_AMT" ] || die \
        "node$n: v2user -> node$DELEG_NODE delegation|total|external = '$r', want $DELEG_AMT each"
done
U_AT=$(sqlite3 "$(db_of 1)" \
    "SELECT delegated_at_block FROM delegations
      WHERE lower(hex(delegator_pubkey)) = '$USER_PK' AND lower(hex(validator_pubkey)) = '$DELEG_PK';" 2>/dev/null || true)
case "$U_AT" in ''|*[!0-9]*) die "could not read the delegation's delegated_at_block ('$U_AT')" ;; esac
echo "[ok] 7/7: v2user delegated $DELEG_AMT raw (50M) to node$DELEG_NODE at height $H_D (dated $U_AT); first in copy($C_D)"

# ── 3. hf6: the generation-4 vote (the dev trigger), H % E == 8 ─────
# 5d: H >= C_D + E + H_MOD so the delegation is in copy(H − 8 − E), the
# copy snapshot(B1) is built from (header "THE SWITCH")
cc_guard 1
H=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
[ "$H" -ge $(( C_D + E + H_MOD )) ] || H=$(( C_D + E + H_MOD ))
while :; do
    if [ $(( H % E )) = "$H_MOD" ] && ! is_payday $(( H - H_MOD )); then break; fi
    H=$(( H + 1 ))
done
B0=$(( H - H_MOD ))        # the last boundary before H (not a payday)
B1=$(( B0 + E ))           # the first boundary after H
[ $(( (H - 1) % E )) != 0 ] && [ $(( H % E )) != 0 ] || die "internal: H=$H or H-1 is a boundary"
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_STORAGE=$DS_DEC effective H=$H (last boundary before $B0, first after $B1)"
propose RULESET_GEN_STORAGE "$DS_DEC" "$H" "$LOGD/propose_hf6.log"
wait_cc_row "$PARAM_STOR" "$H" "$DS_DEC" 20
[ "$CC_CB" -lt "$H" ] || die "the RULESET_GEN_STORAGE row committed at $CC_CB, not before its effective height $H"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_EVM" "$H4"; done
echo "[ok] generation $GEN_EVM on 7/7 before the edge"

# ── 4. hf6: the pre-edge snapshot, tip in [H − 8, H − 2] ────────────
pump_to $(( H - PUMP_STOP_GAP ))
echo "[info] idle production from tip $(tip_of 1) — no pump spend in flight across H"
wait_all $(( H - PUMP_STOP_GAP ))
PRE_REF=""
for n in $(seq 1 "$N"); do
    s=$(stake_snap "$n") || die "node$n's pre-edge snapshot failed: '$s'"
    read -r t rest <<< "$s"
    [ "$t" -ge "$B0" ] && [ "$t" -le $(( H - 2 )) ] || die \
        "node$n's pre-edge read is at tip $t, outside [$B0, $(( H - 2 ))] — the layout broke (false RED), re-run on a fresh bring-up"
    if [ -z "$PRE_REF" ]; then PRE_REF="$rest"
    elif [ "$rest" != "$PRE_REF" ]; then die "node$n's pre-edge snapshot '$rest' differs from node1's '$PRE_REF'"; fi
done
read -r pre_self pre_td pre_nv pre_nd pre_nr pre_acc pre_nacc pre_list <<< "$PRE_REF"
[ "$pre_nv" = "$N" ] && [ "$pre_self" = $(( N * SELF_OLD )) ] && [ "$pre_td" = "$DELEG_AMT" ] \
    || die "pre-edge: $pre_nv validators, Σself $pre_self, Σtotal_delegated $pre_td — expected $N, $(( N * SELF_OLD )), $DELEG_AMT"
[ "$pre_nd" = 1 ] && [ "$pre_nr" = 0 ] || die "pre-edge: $pre_nd delegations / $pre_nr roles rows, expected 1 (v2user's) / 0"
[ "$pre_acc" -gt 0 ] && [ "$pre_nacc" -gt 0 ] || die \
    "pre-edge: Σaccrual $pre_acc in $pre_nacc rows — the boundary $B0 paid nothing, K4's merge would be vacuous"
IFS=',' read -r -a pre_rows <<< "$pre_list"
pre_user=0
for r in "${pre_rows[@]}"; do
    o="${r%%:*}"
    if [ "$o" = "$USER_FP" ]; then pre_user="${r#*:}"; continue; fi   # 5d: the delegator
    [ -n "${IS_NODE_FP[$o]:-}" ] || die "pre-edge: an accrual row is owned by ${o:0:16}..., not a harness node key nor v2user"
done
[ "$pre_acc" -gt "$pre_user" ] || die "pre-edge: only v2user holds accrual — K4's merge would be vacuous"
echo "[ok] pre-edge 7/7: Σself $pre_self (7 x 10M), v2user's one delegation, no roles, Σaccrual $pre_acc in $pre_nacc row(s) (v2user $pre_user)"

# ── 5. hf6: crossing H — the edge, the logs, generation 4 ───────────
wait_all $(( H + 1 ))
POST_REF=""
for n in $(seq 1 "$N"); do
    s=$(stake_snap "$n") || die "node$n's post-edge snapshot failed: '$s'"
    read -r t rest <<< "$s"
    [ "$t" -ge "$H" ] && [ "$t" -lt "$B1" ] || die \
        "node$n's post-edge read is at tip $t, outside [$H, $(( B1 - 1 ))] — the layout broke (false RED)"
    if [ -z "$POST_REF" ]; then POST_REF="$rest"
    elif [ "$rest" != "$POST_REF" ]; then die "node$n's post-edge snapshot '$rest' differs from node1's '$POST_REF'"; fi
done
stagef_sentinel TARGET_REACHED
for x in $(( H - 1 )) "$H" $(( H + 1 )); do diff_at "$x" "hf6-at-height-$x"; done
HF6_LINE="HF-6: rule-set generation $GEN_EVM -> $GEN_4 and the validator migration at the end of height $(( H - 1 )) (dev trigger: storage vote literal 0x$DS_HEX)"
# 5d: the line's current text (nodus_witness_v2_migrate.c — slice 4 added
# the consensus-key count; the delegation count now includes v2user's)
MIG_LINE="HF-6 migration: $N validators re-keyed ($N Foundation-owned), $N consensus keys reserved, $(( N + 1 )) delegations (1 before)"
for n in $(seq 1 "$N"); do
    grep -qF "$HF6_LINE" "$(node_log "$n")" || die "node$n logged no '$HF6_LINE' line"
    grep -qF "$MIG_LINE" "$(node_log "$n")" || die "node$n logged no '$MIG_LINE' line"
    require_gen "$n" "$GEN_4" "$H4"
done
echo "[ok] generation $GEN_4 on 7/7 from H=$H; blocks H-1 / H / H+1 identical 7/7; both HF-6 log lines on 7/7"

# ── 6. hf6: conservation across the edge + K4 ───────────────────────
read -r post_self post_td post_nv post_nd post_nr post_acc post_nacc post_list <<< "$POST_REF"
[ $(( post_self + post_td )) = $(( pre_self + pre_td )) ] || die \
    "Σself + Σtotal_delegated moved across the edge: $(( pre_self + pre_td )) -> $(( post_self + post_td ))"
[ "$post_self" = $(( N * BOND_NEW )) ] && [ "$post_td" = $(( N * SELFDEL + DELEG_AMT )) ] || die \
    "post-edge Σself $post_self / Σtotal_delegated $post_td, expected $(( N * BOND_NEW )) / $(( N * SELFDEL + DELEG_AMT ))"
[ "$post_nv" = "$N" ] && [ "$post_nd" = $(( N + 1 )) ] && [ "$post_nr" = "$N" ] || die \
    "post-edge: $post_nv validators / $post_nd delegations / $post_nr roles rows, expected $N / $(( N + 1 )) / $N"
[ "$post_acc" = "$pre_acc" ] || die "Σaccrual moved across the edge: $pre_acc -> $post_acc (K4 is a merge)"
# K4 merges the Foundation nodes' rows only; v2user's row (if any) stays.
# The list is in owner_fp order — the hex order of the two fps.
want_list="$OWNER:$(( pre_acc - pre_user ))"
if [ "$pre_user" -gt 0 ]; then
    first_fp=$(printf '%s\n%s\n' "$OWNER" "$USER_FP" | LC_ALL=C sort | sed -n 1p)
    if [ "$first_fp" = "$OWNER" ]; then want_list="$want_list,$USER_FP:$pre_user"
    else want_list="$USER_FP:$pre_user,$want_list"; fi
fi
[ "$post_list" = "$want_list" ] || die \
    "post-edge accrual is '$post_list' ($post_nacc rows), expected '$want_list' (K4: every node-key row merged into the Foundation owner, v2user's untouched)"
echo "[ok] across the edge 7/7: Σself + Σdelegated $(( post_self + post_td )) unchanged (7 x 2M + 7 x 8M + 50M); Σaccrual $pre_acc = Foundation $(( pre_acc - pre_user )) + v2user $pre_user"

# ── 7. hf6: the migrated rows, identical 7/7 ────────────────────────
VAL_REF=$(same_on_all "validators + roles" val_dump)
DEL_REF=$(same_on_all "delegations" del_dump)
declare -A VID_SEEN=() SEEN2=()
DELEG_VID=""
nrow=0
while IFS='|' read -r vid vpk vs vtd ved vst vas vown vpz vke; do
    nrow=$(( nrow + 1 ))
    n="${NODE_OF_PK[$vpk]:-}"
    [ -n "$n" ] || die "post-edge: a validators row's consensus pubkey belongs to no harness node"
    [ -z "${SEEN2[$n]:-}" ] || die "post-edge: node$n's pubkey has two rows"
    SEEN2["$n"]=1; VID_SEEN["$vid"]=0
    [ "${#vid}" = 128 ] || die "node$n's validator_id is not 64 bytes"
    [ "$vid" != "${PRE_KEY[$vpk]}" ] || die "node$n's row kept its pre-edge key ${vid:0:16}... — not re-keyed"
    [ "$vown" = "$OWNER" ] || die \
        "node$n's owner_fp is '${vown:0:16}...', expected the Foundation owner ${OWNER:0:16}... (missing roles row, or the build's DNAC_HF6_FOUNDATION_OWNER differs from STAGEF_HF6_OWNER_FP_HEX)"
    [ "$vpz" = 1 ] && [ "$vke" = 0 ] || die "node$n's roles row carries a pending consensus key (zero $vpz, epoch $vke)"
    [ "$vs" = "$BOND_NEW" ] || die "node$n's self_stake is $vs, expected $BOND_NEW (2M)"
    want_d="$SELFDEL"
    if [ "$n" = "$DELEG_NODE" ]; then want_d=$(( SELFDEL + DELEG_AMT )); DELEG_VID="$vid"; fi
    [ "$vtd" = "$want_d" ] && [ "$ved" = "$want_d" ] || die "node$n's total/external_delegated are $vtd/$ved, expected $want_d each"
    [ "$vst" = 0 ] || [ "$vst" = 4 ] || die "node$n's row is status $vst after the edge"
    [ "$vas" -le 1 ] || die "node$n's active_since_block changed to $vas"
done <<< "$VAL_REF"
[ "$nrow" = "$N" ] || die "post-edge: $nrow validators rows, expected $N"
[ -n "$DELEG_VID" ] || die "post-edge: no row for node$DELEG_NODE"
nrow=0; user_rows=0
while IFS='|' read -r dfp dvid damt dat; do
    nrow=$(( nrow + 1 ))
    if [ "$dfp" = "$USER_FP" ]; then
        # 5d: v2user's delegation, re-keyed (design §7.3), amount and date kept
        user_rows=$(( user_rows + 1 ))
        [ "$dvid" = "$DELEG_VID" ] && [ "$damt" = "$DELEG_AMT" ] && [ "$dat" = "$U_AT" ] || die \
            "v2user's delegation is ${dvid:0:16}... / $damt / dated $dat, expected node$DELEG_NODE's validator_id / $DELEG_AMT / $U_AT"
        continue
    fi
    [ "$dfp" = "$OWNER" ] || die "a post-edge delegation's delegator is ${dfp:0:16}..., not the Foundation owner nor v2user"
    [ "${VID_SEEN[$dvid]:-x}" = 0 ] || die "a post-edge delegation targets ${dvid:0:16}..., not a validator_id (or targets one twice)"
    VID_SEEN["$dvid"]=1
    [ "$damt" = "$SELFDEL" ] || die "the self-delegation to ${dvid:0:16}... holds $damt, expected $SELFDEL (8M)"
    [ "$dat" = "$H" ] || die "the self-delegation to ${dvid:0:16}... is dated $dat, expected H=$H (§7.2: a new row)"
done <<< "$DEL_REF"
[ "$nrow" = $(( N + 1 )) ] && [ "$user_rows" = 1 ] || die "post-edge: $nrow delegations ($user_rows v2user's), expected $(( N + 1 )) (1)"
echo "[ok] the migrated rows 7/7: $N validator_ids (new keys, roles rows, owner = Foundation, 2M bond, 8M delegated;"
echo "     node$DELEG_NODE + 50M), $N self-delegations (Foundation -> each validator_id, 8M, dated H=$H),"
echo "     v2user's 50M re-keyed to node$DELEG_NODE's validator_id"

# ── 8. hf6: the boundaries after H — earnings land on the owner ─────
B="$B1"; checked=0; late=0; crossed=0; paydays=0
B_LATE=$(( B1 + 3 * E ))   # src(B) = B − 3E >= B1: the first post-edge copy governs
while [ "$checked" -lt 3 ] || [ "$late" = 0 ]; do
    crossed=$(( crossed + 1 ))
    [ "$crossed" -le "$MAX_BOUNDARIES" ] || die "internal: $MAX_BOUNDARIES boundaries crossed without three non-payday checks"
    pump_to $(( B - PRE_B_GAP ))
    s=$(acc_snap 1) || die "node1's pre-$B read failed: '$s'"
    read -r t_pre rp_pre acc_pre nacc_pre own_pre usr_pre list_pre <<< "$s"
    [ "$t_pre" -lt "$B" ] || die "node1 passed the boundary $B before the pre read (tip $t_pre) — false RED"
    [ "$nacc_pre" -le 2 ] || die "pre-$B: accrual holds $nacc_pre rows: '$list_pre'"
    if [ "$list_pre" != - ]; then
        IFS=',' read -r -a rows_pre <<< "$list_pre"
        for r in "${rows_pre[@]}"; do
            acc_owner_ok "${r%%:*}" || die "pre-$B: an accrual row is neither the Foundation owner's nor v2user's: '$list_pre'"
        done
    fi
    wait_all "$B"
    s=$(acc_snap 1) || die "node1's post-$B read failed: '$s'"
    read -r t_post rp_post acc_post nacc_post own_post usr_post list_post <<< "$s"
    [ "$t_post" -ge "$B" ] && [ "$t_post" -lt $(( B + E )) ] || die "node1's post-$B read at tip $t_post, outside [$B, $(( B + E )))"
    ntx=$(sqlite3 "$(db_of 1)" \
        "SELECT COALESCE(SUM(tx_count),0) FROM v2_blocks WHERE global_height > $t_pre AND global_height <= $t_post;" 2>/dev/null || echo ERR)
    [ "$ntx" = 0 ] || die "$ntx transaction(s) landed between the reads around $B (heights $t_pre..$t_post) — attribution impossible (false RED)"
    ACC_REF=""
    for n in $(seq 1 "$N"); do
        s=$(acc_snap "$n") || die "node$n's post-$B read failed: '$s'"
        read -r t rest <<< "$s"
        [ "$t" -ge "$B" ] && [ "$t" -lt $(( B + E )) ] || die "node$n's post-$B read at tip $t, outside [$B, $(( B + E )))"
        rest="${rest#* }"          # the reward pool moves with fees; compare the accrual columns
        if [ -z "$ACC_REF" ]; then ACC_REF="$rest"
        elif [ "$rest" != "$ACC_REF" ]; then die "node$n's accrual table after $B '$rest' differs from node1's '$ACC_REF'"; fi
    done
    diff_at "$B" "hf6-boundary-$B"
    d_rp=$(( rp_pre - rp_post ))
    # 5d: v2user is paid once its delegation is in the source copy B − 3E
    user_due=0
    if [ $(( B - 3 * E )) -ge "$C_D" ]; then user_due=1; fi
    if is_payday "$B"; then
        paydays=$(( paydays + 1 ))
        [ "$nacc_post" = 0 ] || die "payday $B: the accrual table still holds $nacc_post rows: '$list_post'"
        pc=$(sqlite3 -separator ' ' "$(db_of 1)" \
            "SELECT COUNT(*), COALESCE(SUM(amount),0),
                    COALESCE(SUM(CASE WHEN lower(owner) = '$OWNER' THEN 1 ELSE 0 END),0),
                    COALESCE(SUM(CASE WHEN lower(owner) = '$USER_FP' THEN 1 ELSE 0 END),0)
               FROM utxo_set WHERE block_height = $B AND output_index >= 400;" 2>/dev/null || echo ERR)
        read -r pcn pcsum pco pcu <<< "$pc"
        [ "$pco" = 1 ] && [ "$pcn" = $(( pco + pcu )) ] && [ "$pcu" -le 1 ] || die \
            "payday $B: $pcn payday coin(s) ($pco to the Foundation owner, $pcu to v2user) — expected ONE to the owner, at most one to v2user, no other"
        [ "$user_due" = 0 ] || [ "$pcu" = 1 ] || die "payday $B: v2user (its delegation in copy(B − 3E)) received no coin"
        [ "$pcsum" = $(( acc_pre + d_rp )) ] || die \
            "payday $B: the coins hold $pcsum, expected the prior accrual $acc_pre + the pool debit $d_rp"
        echo "[ok] payday $B 7/7: $pcn coin(s) of $pcsum in all — the Foundation owner's and v2user's $pcu (accrual $acc_pre + this boundary's $d_rp); not counted"
    else
        [ "$nacc_post" -ge 1 ] && [ "$nacc_post" -le 2 ] || die "boundary $B: the accrual table holds $nacc_post rows, expected the owner's and at most v2user's: '$list_post'"
        IFS=',' read -r -a rows_post <<< "$list_post"
        for r in "${rows_post[@]}"; do
            acc_owner_ok "${r%%:*}" || die "boundary $B: an accrual row is neither the Foundation owner's nor v2user's: '$list_post'"
        done
        d_own=$(( own_post - own_pre )); d_usr=$(( usr_post - usr_pre )); d_acc=$(( acc_post - acc_pre ))
        [ "$d_own" -gt 0 ] || die "boundary $B paid the Foundation owner nothing (Δ $d_own)"
        [ $(( d_own + d_usr )) = "$d_acc" ] && [ "$d_acc" = "$d_rp" ] || die \
            "boundary $B: Δowner $d_own + Δv2user $d_usr, ΔΣaccrual $d_acc, reward-pool debit $d_rp — expected all equal"
        [ "$user_due" = 0 ] || [ "$d_usr" -gt 0 ] || die \
            "boundary $B: v2user's delegation is in copy(B − 3E) (C_D $C_D) but it was paid nothing"
        checked=$(( checked + 1 ))
        if [ "$B" -ge "$B_LATE" ]; then late=1; fi
        echo "[ok] boundary $B 7/7: the reward pool paid $d_rp — $d_own to the Foundation owner, $d_usr to v2user (no node-key row)$([ "$B" -ge "$B_LATE" ] && echo ' — source copy written after the edge')"
    fi

    # ── 5d: the switch, at B1 / B1 + E / B1 + 2E ──────────────────────
    if [ "$B" = "$B1" ]; then
        # 8a: every stored snapshot <= B1 is ruleset 1, snapshot(B1 + E)
        # ruleset 2 — the same list on 7/7
        RS_REF=$(same_on_all "the stored selection_rulesets after $B1" rs_dump)
        IFS=',' read -r -a rs_rows <<< "$RS_REF"
        seen_next=0
        for r in "${rs_rows[@]}"; do
            ep="${r%%:*}"; rs="${r#*:}"
            if [ "$ep" -le "$B1" ]; then
                [ "$rs" = "$RS_V1" ] || die "snapshot($ep) <= B1=$B1 is stored with ruleset $rs, expected $RS_V1 (every row <= the first generation-4 boundary stays v1)"
            elif [ "$ep" = $(( B1 + E )) ]; then
                [ "$rs" = "$RS_V2" ] || die "snapshot($ep), stored by the first generation-4 boundary $B1, is ruleset $rs — expected $RS_V2 (the 5d switch)"
                seen_next=1
            else
                die "a snapshot row for epoch $ep exists after boundary $B1 — expected none above $(( B1 + E ))"
            fi
        done
        [ "$seen_next" = 1 ] || die "no snapshot($(( B1 + E ))) stored by boundary $B1"
        for n in $(seq 1 "$N"); do
            t_old=$(snap_total "$n" "$B1" "$DELEG_PK")
            t_new=$(snap_total "$n" $(( B1 + E )) "$DELEG_PK")
            [ "$t_old" = $(( SELF_OLD + DELEG_AMT )) ] && [ "$t_new" = $(( SELF_OLD + DELEG_AMT )) ] || die \
                "node$n: node$DELEG_NODE's raw total is '$t_old' in snapshot($B1) (v1) and '$t_new' in snapshot($(( B1 + E ))) (v2), expected $(( SELF_OLD + DELEG_AMT )) (60M) in both"
        done
        echo "[ok] 8a 7/7: snapshots <= $B1 ruleset 1, snapshot($(( B1 + E ))) ruleset 2 (the first v2 blob); node$DELEG_NODE raw 60M on both sides"
    elif [ "$B" = $(( B1 + E )) ]; then
        # 8b: cometbft's update at the first ruleset-2 set — ONE power change
        for n in $(seq 1 "$N"); do
            # no `grep | grep -q` under pipefail (README, test_v2_rewards.sh:
            # the early exit SIGPIPEs the writer) — read, then match in bash
            vu_lines=$(grep -F "epoch boundary height $B " "$(node_log "$n")" || true)
            [[ "$vu_lines" == *"validator_updates n_added=0 n_power_changed=1 n_removed=0"* ]] || {
                printf '%s\n' "$vu_lines" >&2
                die "node$n did not log 'n_added=0 n_power_changed=1 n_removed=0' at boundary $B (raw 60M -> the counted cap)"; }
        done
        [ "$(same_on_all "the stored selection_rulesets after $B" rs_dump | tr ',' '\n' | sed -n "s/^$(( B + E )):\(.*\)$/\1/p")" = "$RS_V2" ] \
            || die "snapshot($(( B + E ))) is not ruleset 2 on 7/7"
        echo "[ok] 8b 7/7: boundary $B (snapshot(B1 + E) takes effect) logged exactly one power change; snapshot($(( B + E ))) ruleset 2"
    elif [ "$B" = $(( B1 + 2 * E )) ]; then
        # 8c: the first distribution governed by a ruleset-2 snapshot
        is_payday "$B" || [ "$d_usr" -gt 0 ] || die "8c: the first v2-governed distribution at $B paid v2user nothing"
        echo "[ok] 8c 7/7: boundary $B — the first distribution governed by a ruleset-2 snapshot — paid by validator_id"
    fi
    B=$(( B + E ))
done
LAST_B=$(( B - E ))

# ── 9. hf6: the migrated rows untouched by the boundaries; 7/7 ──────
VAL_END=$(same_on_all "validators + roles (end)" val_dump)
DEL_END=$(same_on_all "delegations (end)" del_dump)
[ "$VAL_END" = "$VAL_REF" ] || die "the validator / roles rows changed between H and $LAST_B"
[ "$DEL_END" = "$DEL_REF" ] || die "the delegation rows changed between H and $LAST_B"
echo "[ok] the migrated rows are unchanged on 7/7 after $crossed boundaries"

# ── 10. 6f-2: a real validator key rotation, node 2 → cand1 ─────────
# Header "HF-6 SLICE 6f-2 — THE ROTATION" and WHAT IT PROVES item 10.
# Every check reads chain state (or the node's own log line beside it);
# no CLI stdout is ever the evidence. Node "c" below = cand1.
ROT_RAN=0
ROT_LINE="rotation: not run (STAGEF_HF6_OWNER_KEYS unset — coverage that did not happen)"
ROT_FUND=1000000000           # 10 NODUS: ROTATE pays the fee only (khan
                              # A4) = max(floor, NODUS_V2_STAKE_UNITS 400000
                              # × gas price) — 48 400 000 raw at the harness
                              # genesis price 121 (nodus_v2_stake.h; README
                              # "W-C"); the CLI reads the price itself
ROT_CONSENT_AHEAD=150         # > the envelope's own tip + 90
                              # (nodus-cli.c CLI_ENV_EXPIRY_AHEAD), well
                              # inside the fixed 720 (valbind_wire.h
                              # DNA_VALBIND_MAX_EXPIRY_BLOCKS)
ROT_P=85714285                # header "THE BUDGET": Σ counted powers
ROT_R=25714285                # node 2's counted power (the party)
ROT_DELEG_RAW=$(( SELF_OLD + DELEG_AMT ))   # node 2's raw total, 60M

# cand_db — cand1's chain DB: the largest non-empty witness_*.db under its
# data dir (stagef_node_chain_db's rule; a loop, never an early-exit pipe)
cand_db() {
    local f best="" bs=-1 s
    for f in "$CAND_DIR/data/"witness_*.db; do
        [ -s "$f" ] || continue
        s=$(stat -c %s "$f")
        if [ "$s" -gt "$bs" ]; then best="$f"; bs="$s"; fi
    done
    if [ -n "$best" ]; then echo "$best"; fi
    return 0
}
rot_db()   { if [ "$1" = c ]; then cand_db; else db_of "$1"; fi; }
rot_log()  { if [ "$1" = c ]; then echo "$CAND_DIR/nodus.log"; else node_log "$1"; fi; }
rot_name() { if [ "$1" = c ]; then echo cand1; else echo "node$1"; fi; }
ROT_ALL="$(seq -s ' ' 1 "$N") c"

# cand_runs — 0 iff a process with cand1's data dir runs STAGEF_NODUS_BIN
cand_runs() {
    local pid
    for pid in $(pgrep -f -- "-d $CAND_DIR/data" || true); do
        [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$SRV")" ] && return 0
    done
    return 1
}

# wait_rot H — every node AND cand1 reach H (progress-bounded)
wait_rot() {
    local n db
    for n in $ROT_ALL; do
        db=$(rot_db "$n")
        [ -n "$db" ] || die "$(rot_name "$n") has no chain database"
        stagef_cmt_wait_height "$db" "$1" 3 >/dev/null \
            || die "$(rot_name "$n") never reached height $1 (stuck at $(stagef_cmt_tip "$db"))"
    done
}

# rot_state DB — ONE statement: "tip|ROW|CANDRES|OLDRES|NRES" where ROW =
# "<validators.pubkey: old|cand|other>:<pending: zero|cand|other>:<epoch>"
# for node 2's validator_id ('none' without the joined row), CANDRES /
# OLDRES = "<validator_id>:<role>" of the reservation of SHA3-512(cand1 pk)
# / SHA3-512(node 2's old pk) ('-' when absent), NRES = the reservation
# rows naming node 2's id (v2_consensus_keys, nodus_witness_v2_schema.h
# S18 note).
rot_state() {
    sqlite3 -separator '|' "$1" \
      "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
              COALESCE((SELECT CASE WHEN lower(hex(v.pubkey)) = '$DELEG_PK' THEN 'old'
                                    WHEN lower(hex(v.pubkey)) = '$CAND_PK' THEN 'cand'
                                    ELSE 'other' END || ':' ||
                               CASE WHEN r.pending_consensus_pubkey = zeroblob(2592) THEN 'zero'
                                    WHEN lower(hex(r.pending_consensus_pubkey)) = '$CAND_PK' THEN 'cand'
                                    ELSE 'other' END || ':' ||
                               r.consensus_key_effective_epoch
                          FROM validators v JOIN v2_validator_roles r ON r.validator_id = v.pubkey_hash
                         WHERE lower(hex(v.pubkey_hash)) = '$VID'), 'none'),
              COALESCE((SELECT lower(hex(validator_id)) || ':' || role FROM v2_consensus_keys
                         WHERE lower(hex(consensus_pk_hash)) = '$CAND_PKH'), '-'),
              COALESCE((SELECT lower(hex(validator_id)) || ':' || role FROM v2_consensus_keys
                         WHERE lower(hex(consensus_pk_hash)) = '$OLD_PKH'), '-'),
              (SELECT COUNT(*) FROM v2_consensus_keys WHERE lower(hex(validator_id)) = '$VID');" \
        2>/dev/null || echo ERR
}

# check_rot_state LABEL LO HI WANT — on 8/8 the rot_state tip is in
# [LO, HI] and the rest equals WANT ("layout broke" outside the window —
# a false RED, never a false PASS)
check_rot_state() {
    local label="$1" lo="$2" hi="$3" want="$4" n s t rest
    for n in $ROT_ALL; do
        s=$(rot_state "$(rot_db "$n")")
        t="${s%%|*}"; rest="${s#*|}"
        case "$t" in ''|*[!0-9]*) die "$label: $(rot_name "$n")'s read failed ('$s')" ;; esac
        [ "$t" -ge "$lo" ] && [ "$t" -le "$hi" ] || die \
            "$label: $(rot_name "$n")'s read is at tip $t, outside [$lo, $hi] — the layout broke (false RED), re-run on a fresh bring-up"
        [ "$rest" = "$want" ] || die "$label: $(rot_name "$n") reads '$rest', expected '$want'"
    done
}

# att_state DB — ONE statement: "tip|NEW|OLD", each "signed_count:
# last_signed_height" of the v2_attendance row of cand1's / node 2's OLD
# voter_id ('-' when absent; schema S15 note, nodus_witness_v2_schema.h)
att_state() {
    sqlite3 -separator '|' "$1" \
      "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
              COALESCE((SELECT signed_count || ':' || last_signed_height FROM v2_attendance
                         WHERE lower(hex(voter_id)) = '$CAND_VOTER'), '-'),
              COALESCE((SELECT signed_count || ':' || last_signed_height FROM v2_attendance
                         WHERE lower(hex(voter_id)) = '$OLD_VOTER'), '-');" 2>/dev/null || echo ERR
}

# snap_v2_entries DB EPOCH — the ruleset-2 snapshot(EPOCH)'s entries at
# the fixed vset_wire.h offsets (header 78 B; entry 2770 B: voter 0..31,
# validator_id 32..95, owner 96..159, consensus_pk 160..2751, total_stake
# 2752..2759 u64 BE), one line "voter|validator_id|pubkey|total" each, in
# stored order; prints "ERR" when the row is absent or not ruleset 2.
snap_v2_entries() {
    local db="$1" ep="$2" row n_hex rs cnt i st out=""
    row=$(sqlite3 -separator ' ' "$db" \
        "SELECT lower(hex(substr(snapshot_blob, 9, 2))), lower(hex(substr(snapshot_blob, 11, 4)))
           FROM validator_set_snapshots WHERE epoch_start = $ep;" 2>/dev/null || true)
    read -r n_hex rs <<< "$row"
    [ "$rs" = "$RS_V2" ] && [[ "$n_hex" =~ ^[0-9a-f]{4}$ ]] || { echo ERR; return 0; }
    cnt=$(( 16#$n_hex ))
    for (( i = 0; i < cnt; i++ )); do
        st=$(( VSET_HDR + i * VSET_E2 + 1 ))        # 1-based substr
        row=$(sqlite3 -separator '|' "$db" \
            "SELECT lower(hex(substr(snapshot_blob, $st, 32))),
                    lower(hex(substr(snapshot_blob, $(( st + 32 )), 64))),
                    lower(hex(substr(snapshot_blob, $(( st + VSET_PK_OFF2 )), 2592))),
                    lower(hex(substr(snapshot_blob, $(( st + VSET_PK_OFF2 + 2592 )), 8)))
               FROM validator_set_snapshots WHERE epoch_start = $ep;" 2>/dev/null || true)
        [[ "$row" =~ ^[0-9a-f]{64}\|[0-9a-f]{128}\|[0-9a-f]{5184}\|[0-9a-f]{16}$ ]] || { echo ERR; return 0; }
        out="$out${row%|*}|$(( 16#${row##*|} ))"$'\n'
    done
    printf '%s' "$out"
}

# snap_hash_8 EPOCH — snapshot(EPOCH)'s stored hash, identical on 8/8
snap_hash_8() {
    local n h ref=""
    for n in $ROT_ALL; do
        h=$(sqlite3 "$(rot_db "$n")" \
            "SELECT lower(hex(snapshot_hash)) FROM validator_set_snapshots WHERE epoch_start = $1;" 2>/dev/null || true)
        [[ "$h" =~ ^[0-9a-f]{128}$ ]] || die "snapshot($1): $(rot_name "$n") holds no readable hash ('$h')"
        if [ -z "$ref" ]; then ref="$h"
        elif [ "$h" != "$ref" ]; then die "snapshot($1)'s hash differs: $(rot_name "$n") ${h:0:16}… vs node1 ${ref:0:16}…"; fi
    done
    echo "$ref"
}

# log_has_8 TEXT — every node's AND cand1's log carries TEXT (read whole,
# then matched — no early-exit pipe reader under pipefail)
log_has_8() {
    local n
    for n in $ROT_ALL; do
        grep -qF -- "$1" "$(rot_log "$n")" || die "$(rot_name "$n") logged no '$1' line"
    done
}

if [ -z "$ROT_KEYS" ]; then
    echo "[info] (10) rotation phase: NOT RUN — STAGEF_HF6_OWNER_KEYS is unset. Coverage that did not"
    echo "       happen, not a pass (header, 6f-2: it needs the pre-build owner identity and its build)."
else
    echo "══ (10) 6f-2: rotating node$DELEG_NODE's consensus key onto cand1 ══"
    CAND_PK=$(xxd -p "$CAND_DIR/identity/nodus.pk" | tr -d '\n')
    [ "${#CAND_PK}" = 5184 ] || die "cand1's nodus.pk is not 2592 bytes"
    CAND_PKH=$(stagef_sha3_512_hex "$CAND_DIR/identity/nodus.pk")
    OLD_PKH=$(stagef_sha3_512_hex "$(node_keys "$DELEG_NODE")/nodus.pk")
    CAND_VOTER=$(stagef_voter_id "$CAND_DIR/identity/nodus.pk")
    OLD_VOTER=$(stagef_voter_id "$(node_keys "$DELEG_NODE")/nodus.pk")
    [[ "$CAND_PKH" =~ ^[0-9a-f]{128}$ ]] && [[ "$OLD_PKH" =~ ^[0-9a-f]{128}$ ]] \
        && [[ "$CAND_VOTER" =~ ^[0-9a-f]{64}$ ]] && [[ "$OLD_VOTER" =~ ^[0-9a-f]{64}$ ]] \
        || die "a SHA3-512 of cand1's / node$DELEG_NODE's pubkey could not be computed"
    PORT1=$(stagef_tcp_port 1)

    # ── (a) the owner is funded — by its coin's identity, not its count
    # (a payday may already have paid the owner a coin at step 8)
    flog="$LOGD/rot_fund.log"
    "$CLI" -s 127.0.0.1 -p "$UPORT" v2-envelope spend --keys "$UKEYS" --to "$OWNER" \
        --amount "$ROT_FUND" --submit "127.0.0.1:$UPORT" > "$flog" 2>&1 \
        || { cat "$flog" >&2; die "(10a) v2user's funding spend to the owner was REJECTED — read the log above"; }
    f_intent=$(awk -F= '/^  intent_id=/{print $2; exit}' "$flog")
    [ "${#f_intent}" = 128 ] || { cat "$flog" >&2; die "(10a) no intent_id in the funding spend's output"; }
    fh=$(stagef_cmt_wait_row "$(db_of 1)" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$f_intent'
           AND lower(owner) = '$OWNER' AND amount = $ROT_FUND;" 4) && fwrc=0 || fwrc=$?
    [ "$fwrc" = 1 ] && die "(10a) the owner's funding coin never appeared and the chain STALLED at $fh"
    [ "$fwrc" = 2 ] && die "(10a) the owner's funding coin was not included within 20 heights (tip $fh) — dropped, not delayed"
    echo "[ok] (10a) the owner holds a $ROT_FUND-raw coin from v2user (tip $fh)"

    # ── (b) cand1: derive the fleet's genesis, start, catch up ───────
    # test_v2_grow_7_20.sh STEP 1c: the genesis is a pure function of the
    # config, derived locally and CHECKED against the fleet's chain id;
    # then the grow scenario's start line (nodus.json → the network file,
    # so cand1 dials the seven; the seven's DHT seeds). Its own data dir =
    # its own priv_validator_state.json (nodus_witness.c, the privval
    # path is <data>/priv_validator_state.json).
    CHAIN_ID=$(cat "$BASE_DIR/v2_chain_id")
    if ! "$SRV" --derive-v2-genesis "$CONF" -d "$CAND_DIR/data" \
            > "$CAND_DIR/derive.log" 2> "$CAND_DIR/derive.err"; then
        cat "$CAND_DIR/derive.log" "$CAND_DIR/derive.err" >&2
        die "(10b) cand1's genesis derivation was refused"
    fi
    cid=$(awk '/^chain-id/{print $2}' "$CAND_DIR/derive.log")
    [ "$cid" = "$CHAIN_ID" ] || die "(10b) cand1 derived chain '$cid', the fleet is $CHAIN_ID"
    # shellcheck disable=SC2046
    "$SRV" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$CAND_PIDX")" -t "$(stagef_tcp_port "$CAND_PIDX")" \
        -p "$(stagef_peer_port "$CAND_PIDX")" -C "$(stagef_chan_port "$CAND_PIDX")" \
        -W "$(stagef_witness_port "$CAND_PIDX")" \
        -i "$CAND_DIR/identity" -d "$CAND_DIR/data" $(stagef_seed_args) \
        >> "$CAND_DIR/nodus.log" 2>&1 &
    CAND_PID=$!
    echo "$CAND_PID" >> "$BASE_DIR/pids.txt"
    # listening (the bring-up's 60 x 0.5 s), then role / startup table /
    # LIVE in this boot's log (the grow scenario's wait_role_live, 90 x 1 s)
    ctcp=$(stagef_tcp_port "$CAND_PIDX"); up=0
    for _ in $(seq 1 60); do
        lst=$(ss -lt 2>/dev/null || true)
        if grep -Eq "[:.]${ctcp}\\b" <<< "$lst"; then up=1; break; fi
        sleep 0.5
    done
    [ "$up" = 1 ] || { tail -20 "$CAND_DIR/nodus.log" >&2; die "(10b) cand1 (pid $CAND_PID) never listened on $ctcp"; }
    flags=000
    for _ in $(seq 1 90); do
        flags=$(awk '/chain role: COMETBFT/ {r=1} /cometbft startup table built/ {s=1} /cometbft lane LIVE/ {l=1}
                     END { printf "%d%d%d", r, s, l }' "$CAND_DIR/nodus.log" 2>/dev/null || echo 000)
        [ "$flags" = 111 ] && break
        sleep 1
    done
    [ "$flags" = 111 ] || { tail -20 "$CAND_DIR/nodus.log" >&2; die "(10b) cand1 incomplete after start: role/startup-table/lane-live = $flags"; }
    [ "$(readlink -f "/proc/$CAND_PID/exe" 2>/dev/null || true)" = "$(readlink -f "$SRV")" ] \
        || die "(10b) cand1 (pid $CAND_PID) is not running STAGEF_NODUS_BIN"
    fleet=$(tip_of 1)
    cdb=$(cand_db)
    [ -n "$cdb" ] || die "(10b) cand1 has no chain database after its start"
    ct=$(stagef_cmt_wait_height "$cdb" "$fleet" 8) \
        || die "(10b) cand1 did not catch up to the fleet tip $fleet (stuck at $ct) — its from-genesis catch-up is unmeasured (header)"
    r1=$(sqlite3 "$(db_of 1)" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height = $fleet;" 2>/dev/null || true)
    rc1=$(sqlite3 "$cdb" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height = $fleet;" 2>/dev/null || true)
    [ -n "$r1" ] && [ "$r1" = "$rc1" ] || die "(10b) cand1's block $fleet ('${rc1:0:32}') is not node1's ('${r1:0:32}')"
    echo "[ok] (10b) cand1 derived chain $CHAIN_ID, is LIVE as a non-validator and caught up to $fleet (block identical to node1's)"

    # ── (c) node 2's validator_id, the same on 8/8 ───────────────────
    # validators.pubkey_hash IS the validator_id from the generation-4
    # edge on (nodus_witness_validator.h "validators.pubkey_hash =
    # validator_id (re-keyed at the edge)"; nodus_witness_v2_migrate.c
    # UPDATE validators SET pubkey_hash = …); step 7 joined it to its roles
    # row and found it as DELEG_VID.
    VID="$DELEG_VID"
    for n in $ROT_ALL; do
        v=$(sqlite3 "$(rot_db "$n")" \
            "SELECT lower(hex(pubkey_hash)) || '|' || status FROM validators WHERE lower(hex(pubkey)) = '$DELEG_PK';" \
            2>/dev/null || echo ERR)
        [ "${v%%|*}" = "$VID" ] || die "(10c) $(rot_name "$n"): node$DELEG_NODE's validator_id is '${v:0:16}…', step 7 read ${VID:0:16}…"
        case "${v#*|}" in 0|4) ;; *) die "(10c) $(rot_name "$n"): node$DELEG_NODE's row is status ${v#*|} — ROTATE needs ACTIVE / ELIGIBLE (khan A5)" ;; esac
    done
    # (window: every node, cand1 included, is at or past `fleet`; the
    # state cannot move before the ROTATE, so no upper bound)
    check_rot_state "(10c) before the ROTATE" "$fleet" 999999999999 "old:zero:0|-|$VID:1|1"
    echo "[ok] (10c) node$DELEG_NODE's validator_id ${VID:0:16}… on 8/8: old key, no pending key, cand1's key reserved by nobody"

    # ── (d) cand1's key consents to the ROTATE onto it ───────────────
    CONSENT="$LOGD/rot_consent.txt"
    C_EXP=$(( $(tip_of 1) + ROT_CONSENT_AHEAD ))
    clog="$LOGD/rot_consent.log"
    "$CLI" -s 127.0.0.1 -p "$PORT1" -i "$CAND_DIR/identity" validator consent --op rotate \
        --owner "$OWNER" --subject "$VID" --expiry "$C_EXP" --out "$CONSENT" > "$clog" 2>&1 \
        || { cat "$clog" >&2; die "(10d) cand1's consent was refused by the CLI — read the log above"; }
    [ -s "$CONSENT" ] || die "(10d) no consent file at $CONSENT"
    echo "[ok] (10d) cand1 consented (expiry $C_EXP) — $CONSENT"

    # ── (e) the owner submits the ROTATE; applied = its intent row ────
    rlog="$LOGD/rot_rotate.log"
    "$CLI" -s 127.0.0.1 -p "$PORT1" v2-envelope rotate --keys "$ROT_KEYS" --validator "$VID" \
        --consent "$CONSENT" --submit "127.0.0.1:$PORT1" > "$rlog" 2>&1 \
        || { cat "$rlog" >&2; die "(10e) the owner's ROTATE was REJECTED (CheckTx or the CLI's own checks) — read the log above"; }
    r_intent=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$rlog")
    [ "${#r_intent}" = 128 ] || { cat "$rlog" >&2; die "(10e) no intent_id in the ROTATE's output"; }
    rh=$(stagef_cmt_wait_row "$(db_of 1)" \
        "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$r_intent';" 4) && rwrc=0 || rwrc=$?
    [ "$rwrc" = 1 ] && die "(10e) the ROTATE never applied and the chain STALLED at $rh"
    [ "$rwrc" = 2 ] && die "(10e) the ROTATE was not applied within 20 heights (tip $rh) — dropped or refused by its exec (a refused item leaves no intent row)"
    H_R=$(sqlite3 "$(db_of 1)" \
        "SELECT global_height FROM v2_intent_index WHERE lower(hex(intent_id)) = '$r_intent' LIMIT 1;" 2>/dev/null || true)
    case "$H_R" in ''|*[!0-9]*) die "(10e) the ROTATE applied but its height could not be read ('$H_R')" ;; esac
    F=$(( (H_R + E - 1) / E * E ))     # rtn_rotate2_first_boundary: the first boundary >= h_r
    U=$(( F + E ))
    UE=$(( U + E ))
    echo "[ok] (10e) the ROTATE applied at h_r=$H_R: F=$F (freeze), U=$U (switch), U+E=$UE (release)"

    # ── (f) the pending rotation, 8/8, before U ──────────────────────
    wait_rot "$H_R"
    check_rot_state "(10f) pending" "$H_R" $(( U - 1 )) "old:cand:$F|$VID:2|$VID:1|2"
    echo "[ok] (10f) 8/8: pending key = cand1's, consensus_key_effective_epoch = F=$F; cand1's key reserved role 2, the old key role 1"

    # ── (g) crossing F: the freeze ACCEPTS the rotation ──────────────
    pump_to $(( F + 1 ))
    wait_rot $(( F + 1 ))
    HS_F=$(snap_hash_8 "$F"); HS_U=$(snap_hash_8 "$U")
    # the budget premise (header "THE BUDGET"), decoded on node 1 — the
    # identical hashes make it every node's bytes
    for ep in "$F" "$U"; do
        ents=$(snap_v2_entries "$(db_of 1)" "$ep")
        [ "$ents" != ERR ] && [ -n "$ents" ] || die "(10g) snapshot($ep) is absent or not ruleset 2 on node1"
        ne=0; nvid=0; nold=0; ncand=0
        while IFS='|' read -r evoter evid epk etot; do
            ne=$(( ne + 1 ))
            [ "$epk" = "$DELEG_PK" ] && nold=$(( nold + 1 ))
            [ "$epk" = "$CAND_PK" ] && ncand=$(( ncand + 1 ))
            if [ "$evid" = "$VID" ]; then
                nvid=$(( nvid + 1 ))
                [ "$etot" = "$ROT_DELEG_RAW" ] || die "(10g) snapshot($ep): node$DELEG_NODE's entry holds raw $etot, expected $ROT_DELEG_RAW (60M) — the budget premise"
                if [ "$ep" = "$F" ]; then
                    [ "$epk" = "$DELEG_PK" ] || die "(10g) snapshot(F=$F): node$DELEG_NODE's entry does not carry its OLD key"
                else
                    [ "$epk" = "$CAND_PK" ] && [ "$evoter" = "$CAND_VOTER" ] || die \
                        "(10g) snapshot(U=$U): node$DELEG_NODE's entry does not carry cand1's key and voter id — the freeze at F did NOT accept the rotation"
                fi
            else
                [ "$etot" = "$SELF_OLD" ] || die "(10g) snapshot($ep): an entry holds raw $etot, expected $SELF_OLD (10M) — the budget premise [60M, 10M x 6] does not hold"
            fi
        done <<< "$ents"
        [ "$ne" = "$N" ] && [ "$nvid" = 1 ] || die "(10g) snapshot($ep): $ne entries, $nvid for node$DELEG_NODE's id — expected $N / 1"
        if [ "$ep" = "$F" ]; then
            [ "$nold" = 1 ] && [ "$ncand" = 0 ] || die "(10g) snapshot(F=$F): old key $nold x, cand1 $ncand x — expected 1 / 0"
        else
            [ "$nold" = 0 ] && [ "$ncand" = 1 ] || die "(10g) snapshot(U=$U): old key $nold x, cand1 $ncand x — expected 0 / 1"
        fi
    done
    ACC_LINE="snapshot($U): 1 rotation(s) accepted, 0 waiting (P_U $ROT_P R_U $ROT_R, P_F $ROT_P R_F $ROT_R)"
    for n in $ROT_ALL; do
        al=$(grep -F "snapshot($U): " "$(rot_log "$n")" || true)
        [[ "$al" == *"$ACC_LINE"* ]] || { printf '%s\n' "$al" >&2; die "(10g) $(rot_name "$n") did not log '$ACC_LINE'"; }
        while IFS= read -r l; do
            [[ "$l" != *"rotation(s) accepted"* ]] || [[ "$l" == *"$ACC_LINE"* ]] \
                || die "(10g) $(rot_name "$n") logged a different budget verdict for snapshot($U): '$l'"
        done <<< "$al"
    done
    echo "[ok] (10g) the freeze at F=$F ACCEPTED it, 8/8: snapshot($U) (hash ${HS_U:0:16}…) seats cand1's key for"
    echo "     node$DELEG_NODE's id, snapshot($F) (${HS_F:0:16}…) the old key; raw [60M, 10M x 6] both; '$ACC_LINE'"

    # ── (h) crossing U: the switch ───────────────────────────────────
    pump_to $(( U + 1 ))
    wait_rot $(( U + 1 ))
    for x in $(( U - 1 )) "$U" $(( U + 1 )); do diff_at "$x" "rotate-at-height-$x"; done
    for n in $ROT_ALL; do
        vu=$(grep -F "epoch boundary height $U " "$(rot_log "$n")" || true)
        [[ "$vu" == *"validator_updates n_added=1 n_power_changed=0 n_removed=1"* ]] || {
            printf '%s\n' "$vu" >&2
            die "(10h) $(rot_name "$n") did not log 'n_added=1 n_power_changed=0 n_removed=1' at U=$U (old key out, cand1 in)"; }
    done
    log_has_8 "boundary $U: 1 consensus key(s) switched to the key S(U) seats"
    check_rot_state "(10h) switched" "$U" $(( UE - 1 )) "cand:zero:0|$VID:1|$VID:1|2"
    snap_hash_8 "$UE" >/dev/null
    ents=$(snap_v2_entries "$(db_of 1)" "$UE")
    [ "$ents" != ERR ] && [ -n "$ents" ] || die "(10h) snapshot(U+E=$UE) is absent or not ruleset 2 on node1"
    ok_ue=0
    while IFS='|' read -r evoter evid epk etot; do
        if [ "$evid" = "$VID" ] && [ "$epk" = "$CAND_PK" ]; then ok_ue=1; fi
        [ "$epk" != "$DELEG_PK" ] || die "(10h) snapshot(U+E=$UE), frozen at U, carries node$DELEG_NODE's OLD key — Comet would fall back to it"
    done <<< "$ents"
    [ "$ok_ue" = 1 ] || die "(10h) snapshot(U+E=$UE) does not seat cand1's key for node$DELEG_NODE's id"
    echo "[ok] (10h) at U=$U, 8/8: Comet told 1 removal + 1 addition; the row carries cand1's key, pending cleared;"
    echo "     both keys reserved role 1 (khan A2); snapshot($UE) keeps cand1's key; blocks U-1/U/U+1 identical 7/7"

    # ── (i) cand1 signs from U + 2, node 2's old key stops after U + 1 ─
    ATT1=$(( U + 6 )); ATT2=$(( U + E - 5 ))
    [ "$ATT2" -ge $(( ATT1 + 3 )) ] && [ "$ATT2" -lt "$UE" ] || die "internal: attendance reads $ATT1 / $ATT2 do not fit (U=$U, E=$E)"
    pump_to "$ATT1"
    wait_rot "$ATT1"
    declare -A ATT_NEW_LAST=() ATT_OLD=()
    for n in $ROT_ALL; do
        IFS='|' read -r t anew aold <<< "$(att_state "$(rot_db "$n")")"
        case "$t" in ''|*[!0-9]*) die "(10i) $(rot_name "$n")'s attendance read failed" ;; esac
        [ "$t" -ge "$ATT1" ] && [ "$t" -lt "$UE" ] || die "(10i) $(rot_name "$n")'s first read at tip $t, outside [$ATT1, $(( UE - 1 ))] — false RED"
        [ "$anew" != - ] || die "(10i) $(rot_name "$n"): cand1's voter has NO attendance row at tip $t — it never signed a committed block"
        [ "$aold" != - ] || die "(10i) $(rot_name "$n"): node$DELEG_NODE's old voter has no attendance row before U+E"
        nc="${anew%%:*}"; nl="${anew#*:}"; oc="${aold%%:*}"; ol="${aold#*:}"
        [ "$nl" -ge $(( U + 2 )) ] && [ "$nl" -le $(( t - 1 )) ] || die \
            "(10i) $(rot_name "$n"): cand1's last_signed_height $nl, expected in [U+2=$(( U + 2 )), $(( t - 1 ))]"
        [ "$nc" -ge 1 ] && [ "$nc" -le $(( t - U - 2 )) ] || die \
            "(10i) $(rot_name "$n"): cand1's signed_count $nc at tip $t — more than the $(( t - U - 2 )) commits from U+2 on (it signed before U+2?)"
        [ "$ol" -le $(( U + 1 )) ] && [ "$oc" -le 2 ] || die \
            "(10i) $(rot_name "$n"): the OLD key's last_signed_height $ol / signed_count $oc after U — it signed past U+1=$(( U + 1 ))"
        ATT_NEW_LAST["$n"]="$nl"; ATT_OLD["$n"]="$aold"
    done
    pump_to "$ATT2"
    wait_rot "$ATT2"
    for n in $ROT_ALL; do
        IFS='|' read -r t anew aold <<< "$(att_state "$(rot_db "$n")")"
        case "$t" in ''|*[!0-9]*) die "(10i) $(rot_name "$n")'s second attendance read failed" ;; esac
        [ "$t" -ge "$ATT2" ] && [ "$t" -lt "$UE" ] || die "(10i) $(rot_name "$n")'s second read at tip $t, outside [$ATT2, $(( UE - 1 ))] — false RED"
        nl="${anew#*:}"
        [ "$anew" != - ] && [ "$nl" -gt "${ATT_NEW_LAST[$n]}" ] || die \
            "(10i) $(rot_name "$n"): cand1's last_signed_height did not advance (${ATT_NEW_LAST[$n]} -> ${nl:-none})"
        [ "$aold" = "${ATT_OLD[$n]}" ] || die \
            "(10i) $(rot_name "$n"): the OLD key's attendance moved after U+1 ('${ATT_OLD[$n]}' -> '$aold')"
    done
    node_runs_srv "$DELEG_NODE" || die "(10i) node$DELEG_NODE's (old) process is not running — this scenario never stops it (A8)"
    cand_runs || die "(10i) cand1's process is not running"
    echo "[ok] (10i) 8/8: cand1 credited from U+2 and advancing; node$DELEG_NODE's old key last credited <= U+1"
    echo "     and frozen since; node$DELEG_NODE's old process still up (A8)"

    # ── (j) crossing U + E: the old key and its attendance released ───
    pump_to $(( UE + 1 ))
    wait_rot $(( UE + 1 ))
    diff_at "$UE" "rotate-release-at-height-$UE"
    check_rot_state "(10j) released" "$UE" 999999999999 "cand:zero:0|$VID:1|-|1"
    for n in $ROT_ALL; do
        IFS='|' read -r t anew aold <<< "$(att_state "$(rot_db "$n")")"
        [ "$aold" = - ] || die "(10j) $(rot_name "$n"): node$DELEG_NODE's OLD voter still has an attendance row ('$aold') at tip $t"
        [ "$anew" != - ] || die "(10j) $(rot_name "$n"): cand1's attendance row is gone at tip $t"
    done
    log_has_8 "boundary $UE: 1 previous consensus key(s) released with their attendance rows"
    node_runs_srv "$DELEG_NODE" || die "(10j) node$DELEG_NODE's (old) process is not running"
    cand_runs || die "(10j) cand1's process is not running"
    echo "[ok] (10j) at U+E=$UE, 8/8: the old key's reservation and the old voter's attendance row are gone;"
    echo "     cand1's key is node$DELEG_NODE's only reservation (role 1); block $UE identical 7/7"
    ROT_RAN=1
    ROT_LINE="rotation: node$DELEG_NODE → cand1 — ROTATE at $H_R, accepted at F=$F, switched at U=$U, old key released at U+E=$UE (8/8)"
fi

stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-hf6" || exit 2
if [ "$ROT_RAN" = 1 ]; then
    # (k) the 8th compare: stagef_cmt_diff_at_floor loops 1..7 — a floor
    # over all eight, 7/7 there by stagef_diff.sh, and cand1's row equal
    # to node 1's
    floor8=""
    for n in $ROT_ALL; do
        h=$(stagef_cmt_tip "$(rot_db "$n")")
        if [ -z "$floor8" ] || [ "$h" -lt "$floor8" ]; then floor8="$h"; fi
    done
    [ "$floor8" -ge 1 ] || die "(10k) some node has no block (floor $floor8)"
    diff_at "$floor8" "post-rotate-8"
    r1=$(sqlite3 "$(db_of 1)" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height = $floor8;" 2>/dev/null || true)
    rc1=$(sqlite3 "$(cand_db)" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height = $floor8;" 2>/dev/null || true)
    [ -n "$r1" ] && [ "$r1" = "$rc1" ] || die "(10k) cand1's block $floor8 ('${rc1:0:32}') is not node1's ('${r1:0:32}')"
    echo "[ok] (10k) cand1 agrees with the seven at the 8-node floor $floor8"
fi
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | v2user delegation $H_D (copy $C_D) | HF-6 H $H | boundaries $B1..$LAST_B ($checked checked, $paydays payday)"
echo "[PASS] HF-6 generation-4 edge: the migration re-keyed $N genesis validators to Foundation-owned"
echo "       2M bonds + 8M self-delegations (Σ unchanged, accrual merged), and $checked boundaries after H"
echo "       paid the validator reward to the owner and v2user's delegation share to v2user — 7/7 identical."
echo "       5d: snapshot($(( B1 + E ))) is the first ruleset-2 blob (all <= $B1 ruleset 1), and at $(( B1 + E ))"
echo "       node$DELEG_NODE's raw 60M became ONE capped power change on 7/7 (the counted value itself: unit tests)."
echo "       6f-2 $ROT_LINE."
echo "       E=15 / grace 15 / BPY 20 — the LOGIC only; owner operations other than this one ROTATE"
echo "       (kind-1 test owner) are NOT exercised (header)."
