#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_evm.sh — Nodus EVM, the EVM domain on the Nodus chain: a WIPELESS
# rolling upgrade from the live line to the Nodus EVM build, the EVM_ACTIVE
# vote (param 14), the generation switch 2 -> 3 at the end of block H-1,
# the bridge (deposit / withdraw / contract ticket + redeem), a contract
# deployed and called, and restart / wipe + pin replay across H
# (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
# rev 3 (+ rev 4/5 notes): §2 envelope shapes, §4 the two-savepoint
# failure model, §5 bridge / reserve / tickets, §7 receipts, §8 mempool +
# gas, §9 activation ("Oy ön koşulları"), §10 block environment, §18 RPC;
# docs/plans/decisions/2026-10-04-nodus-evm-domain.md,
# 2026-10-04-nodus-evm-kurultay-k1.md, 2026-10-04-nodus-evm-kurultay-k2-summary.md;
# nodus/docs/DEPLOY_RUNBOOK.md §2.2 (every node on the new binary BEFORE
# the vote). TEMPLATE: test_cmt_hf4_names.sh — its helpers are copied,
# every change is marked "Nodus EVM:".
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL, not skip — the Nodus EVM tree's NODUS_VERSION may
#      EQUAL the live line's, so nothing here orders versions): OLD's CLI
#      knows HF2_ACTIVE / HF3_ACTIVE / RULESET_GEN2 and prints "Unknown
#      param name: EVM_ACTIVE"; NEW's CLI passes EVM_ACTIVE to the connect
#      step; NEW's CLI knows `evm` (`evm address --keys` prints a 32-byte
#      address offline) and OLD's does not; each pair's server and CLI
#      banners agree (printed, not ordered); OLD and NEW servers differ
#      byte-wise (SKIP otherwise, as in the HF-4 scenario).
#   1. A chain started on OLD commits and 7/7 agree; the pump (node 3) and
#      the two EVM users (nodes 1 and 2) claim their leaves on OLD.
#   2. The live testnet's state is reached FIRST, on the OLD fleet with the
#      OLD CLI: HF2_ACTIVE, HF3_ACTIVE and RULESET_GEN2 (D2 read from
#      `ruleset-info`) are voted and crossed, each row identical 7/7 and
#      committed below its effective height; after the third, 7/7 report
#      rule-set generation 2 — EVM_ACTIVE's stateful rules require HF-2,
#      HF-3, a non-zero gas price (the harness genesis has 121) and the
#      registry at the EVM generation's BASE generation 2
#      (nodus_witness_chain_config.c nodus_chain_config_stateful_rules_ex,
#      case CC_PARAM_EVM_ACTIVE (a)-(f); NODUS_RT_GEN_EVM_BASE =
#      NODUS_RT_GEN_2, NODUS_RT_GEN_EVM = 3, nodus_witness_runtime.h).
#   3. Rolling upgrade OLD -> NEW one node at a time (SIGTERM, same data
#      dir / identity / ports): each back in its COMETBFT role with a NEW
#      completed handshake on the SAME chain file, real spends carried by
#      the mixed fleet, 7/7 after every step; all 7 then log one
#      generation-2 D2 + git-commit line.
#   4. Before the EVM vote: `ruleset-info` 7/7 = generation 2; `evm
#      balance` is refused (evm_account rc 2 — the node's "EVM domain is
#      not active" error, nodus_witness_handlers.c evm_gate) and `evm
#      deploy` is refused by the CLI ("smart contracts open with the EVM
#      generation"); evm_meta empty and v2_evm_reserve = 0 on 7/7 (the
#      S16 -> S17 migration on NEW's open).
#   5. The EVM_ACTIVE vote: value D = the decimal NEW's CLI prints as
#      "EVM_ACTIVE exactly <D>" (its compiled DNAC_CFG_EVM_ACTIVE_D, never
#      a literal of this script) at H = vote tip + 1 + SAFETY grace +
#      H_MARGIN, raised to at least initial_height + 256 + WINDOW_MARGIN
#      (red-team 1 F5 rule (g): the first EVM block's BLOCKHASH window
#      must lie on the chain; initial_height from $CONF), moved up until
#      H-1 is not an epoch boundary; round 1 is
#      7/7 — every seat's scalar rule compares the value with ITS OWN
#      compiled D (chain_config.c CC_PARAM_EVM_ACTIVE scalar case), so 7
#      approvals are the nodes' agreement on D; the row is byte-identical
#      on 7/7 and committed < H. A SECOND EVM_ACTIVE proposal (node 2's
#      seat, its own valid effective) is refused by all 6 other seats with
#      "stateful rules rejected" (rule (a), single use — each seat reads
#      "any param-14 row" as param 14 at INT64_MAX, so a row whose
#      effective H is still ahead counts: nodus_witness_chain_config.c,
#      the r14 read and facts.evm_active_voted before the "stateful rules
#      rejected" answer; "Quorum not reached"), and param 14 keeps ONE row
#      on 7/7 three heights later.
#      Between the vote and H: 7/7 still generation 2, evm still refused.
#   6. Cross H (pumped to H-7, then idle): 7/7 identical global_root +
#      block_id AT H-1, H, H+1; every node logged "Nodus EVM: rule-set
#      generation 2 -> 3 and the EVM domain registered ACTIVE at the end
#      of height H-1 (D 0x<D>)" with the SAME D as the vote; the SYSTEM /
#      CORE v2_root_history rows at H-1 are identical on 7/7, name versions
#      above generation 2's and the hashes `ruleset-info` reports for
#      generation 3, the rows below H-1 still name generation 2;
#      `ruleset-info` 7/7 = generation 3 carried by the NEW CLI; evm_meta
#      holds one zero row and v2_evm_reserve = 0 on 7/7.
#   7. Bridge in: node 1 `evm deposit D_RAW` applies (its evm_receipts row
#      by intent_id, status 1, op DEPOSIT); node 1's EVM balance is
#      D_RAW x 10^10 wei through EVERY node's evm_account RPC; the whole
#      EVM state (evm_accounts, evm_meta, v2_evm_reserve, evm_tickets,
#      evm_code_refs, the EVM root-history rows, evm_receipts, evm_logs) is
#      identical on 7/7; v2_evm_reserve = D_RAW; supply invariant
#      wei_live + wei_tickets + wei_lost == 10^10 x reserve_raw on 7/7
#      (design §5) with the exact expected wei_live / wei_tickets /
#      wei_lost.
#   8. Deploy + call: node 1 deploys Counter (fixtures/evm/Counter.hex):
#      receipt status 1, op CREATE, the created address (receipt bytes
#      27..58) identical on 7/7 and non-zero, its code in evm_code on
#      7/7; `evm send increment()` twice; `evm call get()` returns 2 on
#      every node's RPC; the second increment's log is returned by `evm
#      logs` on every node (topic0 = the compiler's Incremented topic,
#      topic1 = node 1's EVM address, tx = the intent); `evm receipt`
#      succeeds (the client SDK re-checks the digest) and prints the
#      digest the DB holds, which the harness RECOMPUTES as SHA3-512 of
#      the stored receipt bytes (design §7) on every node. A reverting
#      call (`boom()`, --force) is APPLIED: receipt status 0 with
#      evm_gas_used == its gas_limit (design §4 "tüm gas"), node 1's EVM
#      nonce +1, node 1's native coins down by exactly the fee the CLI
#      built, get() still 2 on 7/7; the simulation printed the revert
#      reason ("boom"). `gasLimitNow()` (the block GASLIMIT) is identical
#      on 7/7 and > 0 (printed, not hard-coded).
#   9. Two senders together: nodes 1 and 2 each submit an increment
#      back-to-back (both CheckTx-approved before either is waited on);
#      both apply; get() = 4 on 7/7; per carrying height the declared gas
#      of these legs and the receipts' evm_gas_used both stay <= the block
#      GASLIMIT read in step 8. A send with --gas above the per-tx cap is
#      refused before any envelope exists (see HOW IT CAN LIE): CLI rc != 0,
#      no intent built, node 2's nonce and the receipt count unchanged
#      three heights later.
#  10. Bridge out: `evm withdraw W_RAW --to <node 2 fp>` -> a native UTXO
#      (output_index 101, amount W_RAW) for node 2 on 7/7, reserve
#      D_RAW - W_RAW; Ticketer (fixtures/evm/Ticketer.hex) deployed;
#      `openTicket(sys, node2_fp)` with value T_RAW x 10^10 opens a TICKET
#      (evm_tickets row on 7/7: amount T_RAW, dest node 2, the id the
#      receipt names); `evm redeem <ticket>` -> a native UTXO (index 101,
#      amount T_RAW) for node 2 on 7/7, the ticket row gone, reserve
#      D_RAW - W_RAW - T_RAW; supply invariant (exact values) on 7/7 after
#      each of the three.
#  11. Restart across H: node 4 kill -9'd, restarted on NEW on its own
#      chain file (role + NEW completed handshake), catches up, 7/7 at a
#      later floor, and its whole EVM state equals the fleet's.
#  12. Pinned rejoin across H: node 6 wiped as test_v2_join.sh does
#      (identity kept), restarted on NEW with --v2-genesis-pin; it adopts
#      the fleet's chain file, re-executes genesis -> tip THROUGH the
#      generation-2 switch AND the EVM activation and every EVM block (its
#      truncated log carries both switch lines again); its EVM state
#      (receipt / log index included — rebuilt by the replay) and its
#      blocks AT H-1 / H / H+1 equal the fleet's; 7/7 at the end.
#
# WHAT IT REQUIRES
#   Compile flags — TWO short-epoch + short-grace builds, nodus-server AND
#   nodus-cli from the SAME tree each (the HF-2..HF-4 scenarios' flag set;
#   the two builds must agree or NEW's open of OLD's chain fails for an
#   unrelated reason):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9 are ERGONOMIC; param 14 is SAFETY — dnac.h.) OLD = a
#   PRE-EVM build (written when that was main's; the recorded PASS used
#   main f3b79523, 0.23.18 — main is an EVM build since the Nodus EVM merge,
#   and an EVM OLD FAILS this mode's gate: use the "MODE voted-before"
#   pair below for that); NEW = the Nodus EVM tree, built with
#   NODUS_EVM_ENABLED (the default of the standalone non-Windows nodus
#   build, nodus/CMakeLists.txt; a NEW CLI without it fails gate 0, a NEW
#   server without it would FAULT at the edge — phase 6b''). NEW's
#   NODUS_VERSION may equal OLD's: the gate is capability-based.
#   Environment:
#     exported BEFORE stagef_up_v2.sh (hashed into the genesis document):
#       STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     read by THIS script only:
#       STAGEF_NODUS_BIN_OLD / STAGEF_NODUSCLI_BIN_OLD   the OLD pair
#       STAGEF_NODUS_BIN_NEW / STAGEF_NODUSCLI_BIN_NEW   the NEW pair
#       STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     and the bring-up must run the OLD server + OLD CLI as
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN (checked through every node's
#     /proc/<pid>/exe). Leave STAGEF_PAYOUT_INTERVAL_EPOCHS,
#     STAGEF_ADDR_HISTORY_INDEX and the evidence-window knobs unset.
#   Tools on the machine: sqlite3, bc, xxd, openssl with SHA3-512
#   (`openssl dgst -sha3-512`), ss. NO solc: the fixtures are committed
#   bytecode (fixtures/evm/README.md says how they were compiled).
#   Exact command sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     git -C /opt/dna worktree add <OLD_TREE> <a pre-EVM commit, e.g. f3b79523>
#     cmake -S <OLD_TREE>/nodus -B <OLD_TREE>/nodus/build-evm -DCMAKE_C_FLAGS="$F"
#     make -C <OLD_TREE>/nodus/build-evm -j"$(nproc)" nodus-server nodus-cli
#     cmake -S <NEW_TREE>/nodus -B <NEW_TREE>/nodus/build-evm -DCMAKE_C_FLAGS="$F"
#     make -C <NEW_TREE>/nodus/build-evm -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN_OLD=<OLD_TREE>/nodus/build-evm/nodus-server
#     export STAGEF_NODUSCLI_BIN_OLD=<OLD_TREE>/nodus/build-evm/nodus-cli
#     export STAGEF_NODUS_BIN_NEW=<NEW_TREE>/nodus/build-evm/nodus-server
#     export STAGEF_NODUSCLI_BIN_NEW=<NEW_TREE>/nodus/build-evm/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=/opt/dna/nodus/tests/integration/stagef
#     STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD \
#         bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_evm.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, OLD and NEW servers
#   byte-identical, STAGEF_EPOCH_LENGTH != 15, a grace variable != 15, not
#   a Comet cluster, no $BASE_DIR/v2_genesis_pin, a fixture missing, a
#   needed tool missing, any split STAGEF_MODE. A skip is not a pass.
#
#   CAPABILITY GATE (iii): name-table probes against a port nothing
#   listens on — OLD's CLI must reach "client_connect failed" with
#   HF2_ACTIVE, HF3_ACTIVE and RULESET_GEN2 and print "Unknown param name:
#   EVM_ACTIVE"; NEW's must reach "client_connect failed" with EVM_ACTIVE.
#   NEW's `evm address --keys <node 1 identity>` (offline, nodus-cli.c
#   main: the `evm address` branch before "All other commands need a
#   server") must print one 0x + 64-hex line with rc 0; OLD's must exit
#   non-zero without one. Banners are PRINTED; only each pair's
#   server == CLI is asserted.
#
# WHAT IT LEAVES BEHIND
#   All 7 nodes on NEW under new pids (appended to pids.txt). Every
#   nodus.log appended EXCEPT node 6's (TRUNCATED by step 12); node 4
#   restarted twice (upgrade + kill -9). HF-2 ACTIVE from H2, HF-3 from
#   H3, rule-set generation 2 from H4 and the EVM generation 3 + EVM
#   domain from H — all one-way. Four chain_config_history rows (params
#   7, 8, 9, 14). In the EVM domain: node 1's and node 2's accounts, the
#   Counter (count = 4) and Ticketer contracts, no pending ticket;
#   v2_evm_reserve = D_RAW - W_RAW - T_RAW; node 2 holds two index-101
#   release coins (W_RAW, T_RAW); every EVM fee + pump fee in the reward
#   pool. The leaves of nodes 1, 2, 3 claimed. Node 6's data dir rebuilt by
#   adoption (identity kept). $BASE_DIR/evm/ (every CLI log). Tear down
#   with stagef_down.sh before re-running (leaves and params 9 / 14 are
#   single-use).
#
# HOW IT CAN LIE
#   - **E = 15, grace 15/15, BPY 20 prove the LOGIC, not 720 / 17 280.**
#     Param 14's live grace is SAFETY (17 280 blocks).
#   - **The window rule, not the grace, decides H here.** Red-team 1 F5
#     (rule (g)) refuses an EVM_ACTIVE effective below initial_height +
#     256, so at grace 15 H is moved past 257 (initial_height 1) and the
#     chain is PUMPED there — about 250 more pump spends than before. A
#     vote below the floor (the refusal itself) is NOT exercised here;
#     the unit tests (test_v2_evm section 3) are its proof. At the
#     production SAFETY grace (17 280) the floor never binds.
#   - **The gas numbers are placeholders, not measurements.** The block
#     GASLIMIT this chain runs at is whatever param 15 / the compiled
#     default says (printed: DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT = 30 000 000
#     = NODUS_RT_EVM_TX_GAS_CAP in this tree, design §8 "ölçüm kapısı");
#     nothing here measures the cost of a gas unit, and no block comes
#     near the limit.
#   - **The CheckTx block-gas refusal is NOT exercised.** CheckTx refuses
#     an envelope whose EVM gas exceeds EVM_BLOCK_GAS_LIMIT at tip + 1
#     (nodus_witness_cmt_app.c, the PostCheckMaxGas analogue), but with
#     no param-15 row the limit equals the per-tx cap, and the CLI cannot
#     build an envelope above the cap: it asks evm_estimate first, and the
#     node refuses g > cap before simulating (nodus_witness_handlers.c
#     handle_evm_call, "g must be between 1 and the per-transaction gas
#     cap"). Step 9 therefore proves only that such a request builds and
#     lands NOTHING. Voting param 15 below the cap would not help either:
#     the CLI's estimate then runs at the default gas = the cap
#     (handlers.c `gas = x.has_g ? x.g : NODUS_RT_EVM_TX_GAS_CAP`) inside a
#     block environment whose GASLIMIT is the voted value
#     (nodus_witness_rt_evm.c `benv->gas_limit`), which the engine refuses
#     (shared/evm/evm_tx.c check_transaction, GAS_ALLOWANCE) — and an
#     explicit --gas above the limit fails the same estimate. The unit
#     tests are the CheckTx refusal's proof.
#   - **The RPC work budget is not exercised.** The per-height §18 work
#     budget is in this tree (nodus_witness_handlers.c); this scenario
#     passes explicit, modest --gas values so its reads stay far below it,
#     and never asserts a RATE_LIMITED answer. A read refused by the
#     budget reads as a FAIL with the CLI's rc, never a pass.
#   - **"Not active" is a NODE error string the CLI never prints:** `evm
#     balance` shows only "evm_account failed (rc=2)" (nodus-cli.c cmd_evm
#     balance). rc 2 (NODUS_ERR_NOT_FOUND) is also "no version-3 chain";
#     it is narrowed by ruleset-info succeeding on the same node and by
#     the CLI's own generation refusal of `evm deploy`.
#   - **Two senders "together" is a wall-clock race:** both are
#     CheckTx-approved before either is awaited, but whether they share a
#     block depends on PrepareProposal timing (the env_flood precedent).
#     Both applying is asserted; the carrying heights are PRINTED.
#   - **A pump spend still pending at the EVM edge would read as
#     "dropped"** (a generation-2 envelope after H): the NEW CLI caps
#     expiry at H-1 only for the generation-1 -> 2 switch
#     (cli_env_expiry), so pumping stops at H - PUMP_STOP_GAP and H-1 / H /
#     H+1 are crossed on idle production. This can only produce a false
#     RED, never a false GREEN; `tx_count` there is REPORTED.
#   - **Every chain-config proposal is kept away from an epoch boundary**
#     (cc_guard; ORCH run 1 failed the HF3 vote at tip 29 with every
#     other seat answering "MISMATCH (peer's set_hash/epoch differ …)").
#     The CLI takes the committee of tip + 1 (dnac_committee_query) but
#     the epoch of tip — at tip = kE − 1 they straddle the boundary (a
#     pre-existing CLI edge, nodus/BUGS.md). Before each proposal the
#     proposer node's tip must be off a boundary and >= CC_GUARD_GAP (4)
#     heights before the next one, else the chain is pumped to the next
#     epoch start + 1; every effective height is computed from the tip
#     read AFTER the guard; right after the CLI returns, tip + 1 must still
#     be below that boundary, else FAIL (a false RED, never a false PASS).
#     So this scenario NEVER exercises a proposal near a boundary — the
#     edge itself stays open in the CLI. H_MARGIN for the EVM vote is 40
#     (the HF-4 template's 20 + one guard pump).
#   - **Only one machine;** seven nodes and every CLI share it.
#   - **The fixtures exercise a small opcode set** (SSTORE / SLOAD /
#     LOG2 / REVERT / CALL with value / GASLIMIT / CREATE). The engine's
#     opcode proof is the Prague state-test suite, not this scenario.
#     SELFDESTRUCT (wei_lost), BUDGET, OOG, precompiles, CREATE2, a heavy
#     block and a double redeem are NOT exercised (design §11 harness
#     list) — wei_lost is only asserted to stay 0.
#   - **Every refusal here is pre-envelope or a seat's answer:** the
#     second EVM_ACTIVE proposal is refused by the approval responders
#     (rule (a)), never by CheckTx or the SYSTEM exec; `evm deploy` before
#     the switch is refused by the CLI's own generation check. The
#     node-side refusals (exec of an EVM leg at generation 2, a wrong D,
#     rules (b)-(f) as refusals) are unit-tested only.
#   - **The receipt digest check is self-consistency of the stored bytes**
#     (SHA3-512 of evm_receipts.receipt == evm_receipts.digest == what the
#     RPC prints); the binding of that digest to the NEXT block's
#     LastResultsHash is not decoded by this bash harness — the 7/7
#     block_id / global_root agreement is the chain-side check.
#   - **The ticket system address is derived HERE** (SHA3-512 of the 18
#     ASCII bytes "NDS.EVMWITHDRAW.v1", first 32 bytes — design §5,
#     nodus_witness_rt_evm.c TICKET_ADDR_PREIMAGE / nodus_rt_evm_ticket_addr);
#     the evm_tickets row appearing is what proves the derivation matches
#     the engine's.
#   - **"Same D2 and git commit on 7/7" reads log lines** — one build
#     reported, not identical bytes.
#   - Heights other than the H-1/H/H+1 window are driven by real spends
#     (node 3's leaf) or by the EVM transactions themselves; every wait is
#     progress- and height-bounded (stagef_cmt_wait_height / _wait_row),
#     never a bare sleep (the 0.5 s / 1 s attempt-bounded polls for a
#     process exit, a port and a log line are the HF-4 scenario's).
#   - rc 99 = SKIP, coverage that did not happen.
#   - Wall time NOT measured (JUDGMENT: three rolling-vote crossings and a
#     rolling upgrade on pumped blocks, ~8 idle 60 s blocks across each
#     edge, a from-genesis rejoin — on the order of an hour).
#   - Written against the source; NOT yet run (the first run is the
#     ORCHESTRATOR's).
#
# ── MODE voted-before (STAGEF_EVM_UPGRADE_MODE=voted-before) ────────────
# Everything above describes the DEFAULT mode, voted-after (unset or
# `voted-after`): roll first, vote on NEW. Any other value of the variable
# FAILS at once (never silently the default). The scenario prints the mode
# it runs ("[info] STAGEF_EVM_UPGRADE_MODE=…") before its SKIP gates (after
# the split-mode SKIP); the voted-before [PASS] block names it again. The live situation this mode reproduces
# (decision docs/plans/decisions/2026-10-06-hf5-evm-activation.md; runbook
# §2.2 "Live hard forks" HF-5 row): the fleet ran nodus 0.24.1 — an EVM
# build — and voted EVM_ACTIVE with it; before the effective height every
# node is rolled to a LATER build carrying the same D (0.25.0: generation 4
# code, inert until its own vote), and the chain crosses H on that build.
#
# WHAT IT PROVES (voted-before) — steps 0-2 and 6-12 as above, except:
#   0'. Capability gate: OLD and NEW servers differ byte-wise (SKIP
#       otherwise, unchanged); OLD's CLI knows HF2_ACTIVE / HF3_ACTIVE /
#       RULESET_GEN2 (unchanged) AND passes EVM_ACTIVE to the connect step
#       exactly as NEW's does; both CLIs' usage texts name `EVM_ACTIVE
#       exactly <D>` and the two D values are EQUAL (FAIL naming both if
#       not); OLD's `evm address --keys <node 1>` prints exactly one address,
#       equal to NEW's for the same keys.
#   2b. After generation 2 on OLD: the EVM_ACTIVE vote, cast by node 1's seat
#       on the 7/7 OLD fleet with the OLD CLI — the same function as step 5
#       (cc_guard, SAFETY grace + H_MARGIN, the F5 floor, rule (f), round 1
#       7/7 = the seven OLD servers' agreement on D, the row byte-identical
#       7/7 and committed < H, a second proposal from node 2's seat refused
#       by the 6 others, ONE param-14 row three heights later) — with H
#       raised by ROLL_MARGIN = 7 x ROLL_STEP_BLOCKS (4) blocks. Then, on
#       7/7: the row is the voted one, one row, generation 2 (OLD CLI).
#   3'. The roll OLD -> NEW (upgrade_node, unchanged: role, handshake, same
#       chain file, real spends, 7/7 after every step). Before each step
#       the remaining steps x max(ROLL_STEP_BLOCKS, the largest step
#       MEASURED so far, in blocks) must end below H-1 on the highest node,
#       else FAIL ("cannot finish before H-1"); after each step the highest
#       tip + 1 < H (else FAIL: H-1 reached mid-roll), the step's block
#       count is printed, the param-14 row is the voted one on 7/7 (one
#       row) and 7/7 report generation 2 — each node asked with the CLI of
#       the binary it runs.
#   4'. Step 4's checks on the NEW fleet, labelled "between the vote and H
#       (rolled)": generation 2 with generation 2's hashes, evm_meta empty
#       and reserve 0 (OLD already migrated to S17), `evm balance` and
#       `evm deploy` refused; step 5 does NOT vote again — it re-reads the
#       row / one row / generation 2 on the 7/7 NEW fleet; the between-vote
#       -and-H checks (tip + 1 < H before and after) run unchanged.
#   6-12 unchanged: the crossing is made by NEW only (7/7 run NEW before
#       H-1), the switch line names the D both CLIs carry, and step 12's
#       pinned rejoin replays the vote block an OLD fleet committed on NEW.
# WHAT IT REQUIRES (voted-before) — the compile flags and every variable
#   above, plus STAGEF_EVM_UPGRADE_MODE=voted-before (read by THIS script
#   only — the bring-up does not read it), and a DIFFERENT pair: OLD = the
#   build that votes HF-5 (the live nodus 0.24.1, f7aa7984), NEW = the
#   build rolled onto before H (nodus 0.25.0, main) — BOTH Nodus EVM builds
#   (NODUS_EVM_ENABLED), both carrying the SAME DNAC_CFG_EVM_ACTIVE_D
#   (0x029f47596864d407 in both trees today; the gate compares what the
#   CLIs print, never this literal) and the same witness schema (NEW must
#   open OLD's S17 database — a refusal shows as REFUSING START / a
#   different chain file in upgrade_node). Exact sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     git -C /opt/dna worktree add <OLD_TREE> f7aa7984          # 0.24.1
#     git -C /opt/dna worktree add <NEW_TREE> main              # 0.25.0
#     cmake -S <OLD_TREE>/nodus -B <OLD_TREE>/nodus/build-se -DCMAKE_C_FLAGS="$F"
#     make -C <OLD_TREE>/nodus/build-se -j"$(nproc)" nodus-server nodus-cli
#     cmake -S <NEW_TREE>/nodus -B <NEW_TREE>/nodus/build-se -DCMAKE_C_FLAGS="$F"
#     make -C <NEW_TREE>/nodus/build-se -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN_OLD=<OLD_TREE>/nodus/build-se/nodus-server
#     export STAGEF_NODUSCLI_BIN_OLD=<OLD_TREE>/nodus/build-se/nodus-cli
#     export STAGEF_NODUS_BIN_NEW=<NEW_TREE>/nodus/build-se/nodus-server
#     export STAGEF_NODUSCLI_BIN_NEW=<NEW_TREE>/nodus/build-se/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=/opt/dna/nodus/tests/integration/stagef
#     STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD \
#         bash $S/stagef_up_v2.sh
#     STAGEF_EVM_UPGRADE_MODE=voted-before bash $S/tests/test_cmt_evm.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   The default-mode pair (OLD = a pre-EVM build) FAILS this mode's gate,
#   and this mode's pair FAILS the default gate — export the pair of the
#   mode you run. SKIPs (99) as above.
# WHAT IT LEAVES BEHIND (voted-before) — as above (same rows, accounts,
#   coins, restarts, node 6 rebuilt); the param-14 row was committed by
#   the OLD fleet; $BASE_DIR/evm/ holds both CLIs' logs.
# HOW IT CAN LIE (voted-before) — everything above, plus:
#   - **The gate compares the two CLIs' compiled D, not the servers'.**
#     The OLD servers' D is proven by the 7/7 round-1 approvals (each seat
#     compares the value with its own compiled D); the NEW servers' D only
#     at H, by the switch line naming D 0x<D> on every node and the 7/7
#     identical blocks — a NEW server with another D FAILS at step 6, not
#     at the gate. What a NEW build with a DIFFERENT D does at H is not
#     exercised (the gate FAILs first, by design).
#   - **The schema is not compared directly** — only NEW opening OLD's
#     chain file (same file, handshake completed, no REFUSING START).
#   - **At E = 15 the F5 window floor, not the roll margin, likely decides
#     H** (JUDGMENT, not measured: with the vote tip a few heights past H4,
#     tip + 1 + 15 + 40 + 28 stays below the floor 262, so H = 262 and the
#     roll guard has a wide slack and is not expected to bite — H is printed
#     either way); at the production SAFETY grace the slack is 17 280 blocks. The guard is a projection — it can FAIL a roll
#     that would still have fit (false RED), never pass one that did not:
#     the hard check (highest tip + 1 < H after every step) is separate.
#   - **The live roll's wall-clock spacing is not reproduced** (minutes
#     here; the live window between vote and H was ~24 h) — nothing here
#     depends on it, the margin is counted in blocks.
#   - **Mixed OLD/NEW blocks between the vote and H carry only idle blocks
#     and 1-in/1-out pump SPENDs** — no EVM envelope can exist before H.
#   - **The second EVM_ACTIVE proposal is refused by OLD seats** (rule (a)
#     on 0.24.1), not by NEW's; NEW's rule (a) refusal is exercised only in
#     the default mode.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# Split S3/S6: restarts every node as one nodus-server process (OLD/NEW
# pair) — SKIP (99) in every split mode (decision
# 2026-10-01-nodus-component-split.md item 23).
stagef_split_skip_if $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FIX_DIR="$S_DIR/fixtures/evm"          # Nodus EVM: committed bytecode
OLD_SRV="${STAGEF_NODUS_BIN_OLD:-}"
OLD_CLI="${STAGEF_NODUSCLI_BIN_OLD:-}"
NEW_SRV="${STAGEF_NODUS_BIN_NEW:-}"
NEW_CLI="${STAGEF_NODUSCLI_BIN_NEW:-}"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_EVM=14               # Nodus EVM: DNAC_CFG_EVM_ACTIVE (dnac.h), value exactly D
GEN_BASE=2                 # Nodus EVM: NODUS_RT_GEN_EVM_BASE (nodus_witness_runtime.h)
GEN_EVM=3                  # Nodus EVM: NODUS_RT_GEN_EVM (nodus_witness_runtime.h)
DOM_SYSTEM=0               # DNA_DOMAIN_SYSTEM (shared/dnac/ledger_ids.h)
DOM_CORE=1                 # DNA_DOMAIN_CORE
DOM_EVM=2                  # Nodus EVM: DNA_DOMAIN_EVM
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
# Nodus EVM: the HF-4 template's 20 + room for one epoch-boundary guard pump
# (cc_guard: at most E + 1 heights) before the second proposal — a layout
# choice, not a timeout; a fleet that still gets to H-1 first FAILS.
H_MARGIN=40
# Nodus EVM red-team 1 F5: the heights kept above the first-window floor
# initial_height + 256 (rule (g)) — a layout choice, not a timeout
WINDOW_MARGIN=5
# Nodus EVM (ORCH run 1, FAIL at the HF3 vote): a chain-config proposal is made
# only when the proposer node's tip t is not an epoch boundary and the next
# boundary is >= CC_GUARD_GAP heights away (cc_guard below)
CC_GUARD_GAP=4
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
E_REQ=15
# Nodus EVM upgrade mode (header "MODE voted-before"): voted-after = the
# default path (roll, then vote); voted-before = vote on OLD, roll, cross H
UPG_MODE="${STAGEF_EVM_UPGRADE_MODE:-voted-after}"
case "$UPG_MODE" in
    voted-after|voted-before) ;;
    *) die "STAGEF_EVM_UPGRADE_MODE='$UPG_MODE' — the accepted values are voted-after (the default) and voted-before" ;;
esac
# voted-before: the blocks ONE rolling step may consume (upgrade_node pumps
# fleet tip + 2; a restart may let an idle block land) — a layout choice,
# not a timeout. H gets N x this on top of H_MARGIN; before every step the
# roll is projected with max(this, the largest step MEASURED so far), and a
# roll that would reach H-1 FAILS (never a pass).
ROLL_STEP_BLOCKS=4
ROLL_MARGIN=0
if [ "$UPG_MODE" = voted-before ]; then
    ROLL_MARGIN=$(( STAGEF_COMMITTEE_SIZE * ROLL_STEP_BLOCKS ))
    echo "[info] STAGEF_EVM_UPGRADE_MODE=voted-before — EVM_ACTIVE voted on OLD, rolled OLD -> NEW before H-1, H crossed on NEW"
else
    echo "[info] STAGEF_EVM_UPGRADE_MODE=voted-after (default) — rolled OLD -> NEW first, EVM_ACTIVE voted on NEW"
fi
# Nodus EVM: the bridge amounts (raw units; q = 10^10 wei per raw unit, design §5)
Q=10000000000
D_RAW=100000000000         # 1 000 NODUS deposited
W_RAW=10000000000          # 100 NODUS withdrawn to node 2
T_RAW=5000000000           # 50 NODUS through a contract ticket
GAS_DEPLOY=1000000         # Nodus EVM: explicit, modest gas (HOW IT CAN LIE: the
GAS_SEND=200000            #   RPC simulation budget); a creation of either
GAS_TICKET=300000          #   fixture and a CALL of each function fit
GAS_CALL=100000
GAS_OVER_CAP=30000001      # NODUS_RT_EVM_TX_GAS_CAP + 1 (30 000 000, dnac.h comment
                           #   at DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT)
# receipt layout (design §7, nodus_witness_rt_evm.c rcpt encoder): a 16-byte
# tag, then status u8 (byte 17, 1-based), op u8 (18), evm_gas_used u64 BE
# (19..26), created[32] (27..58)
OP_CALL=01; OP_CREATE=02; OP_DEPOSIT=03; OP_WITHDRAW=04; OP_REDEEM=05
REL_INDEX=101              # RTN_EVMFUND_REL_INDEX (nodus_witness_rt_native.c)
CONF="$BASE_DIR/v2_genesis.conf"
PINFILE="$BASE_DIR/v2_genesis_pin"
LOGD="$BASE_DIR/evm"
N="$STAGEF_COMMITTEE_SIZE"
RESTART_VICTIM=4
JOIN_VICTIM=6

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN_OLD=$OLD_SRV" "STAGEF_NODUSCLI_BIN_OLD=$OLD_CLI" \
            "STAGEF_NODUS_BIN_NEW=$NEW_SRV" "STAGEF_NODUSCLI_BIN_NEW=$NEW_CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs"
        echo "       an OLD (the live line) and a NEW (Nodus EVM) short-epoch build; see the header"
        exit 99
    fi
done
if cmp -s "$OLD_SRV" "$NEW_SRV"; then
    echo "[SKIP] STAGEF_NODUS_BIN_OLD and STAGEF_NODUS_BIN_NEW are byte-identical —"
    echo "       an upgrade to the same binary proves nothing"
    exit 99
fi
if [ "${STAGEF_EPOCH_LENGTH:-720}" != "$E_REQ" ]; then
    echo "[SKIP] STAGEF_EPOCH_LENGTH=${STAGEF_EPOCH_LENGTH:-720} — this scenario is laid out for"
    echo "       E=$E_REQ (-DDNAC_EPOCH_LENGTH=$E_REQ + STAGEF_EPOCH_LENGTH=$E_REQ before bring-up)"
    exit 99
fi
if [ "${STAGEF_CC_GRACE_ERGONOMIC:-720}" != 15 ] || [ "${STAGEF_CC_GRACE_SAFETY:-17280}" != 15 ]; then
    echo "[SKIP] STAGEF_CC_GRACE_ERGONOMIC=${STAGEF_CC_GRACE_ERGONOMIC:-720}" \
         "STAGEF_CC_GRACE_SAFETY=${STAGEF_CC_GRACE_SAFETY:-17280} — needs the short-grace"
    echo "       builds (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15"
    echo "       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15) and both variables = 15"
    exit 99
fi
# Nodus EVM: the committed fixtures and the tools the EVM checks use
for f in Counter.hex Ticketer.hex abi.sigs; do
    if [ ! -s "$FIX_DIR/$f" ]; then
        echo "[SKIP] fixture $FIX_DIR/$f is missing"
        exit 99
    fi
done
for t in sqlite3 bc xxd openssl ss; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the EVM checks need it"
        exit 99
    fi
done
if [ "$(printf 'abc' | openssl dgst -sha3-512 2>/dev/null | awk '{print $NF}')" != \
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" ]; then
    # SHA3-512("abc") — the value openssl and python3 hashlib.sha3_512 both
    # printed when this script was written (a known-answer probe)
    echo "[SKIP] this openssl has no working SHA3-512 (the receipt digest and ticket address need it)"
    exit 99
fi

# ── CAPABILITY GATE (FAIL, not skip — see the header) ───────────────
bin_version() {            # BIN KIND ("Server" | "CLI") -> X.Y.Z, "" if no banner
    local out re="Nodus $2 v([0-9]+\.[0-9]+\.[0-9]+)"
    out=$("$1" -h 2>&1 || true)
    if [[ "$out" =~ $re ]]; then echo "${BASH_REMATCH[1]}"; fi
}
OLD_VER=$(bin_version "$OLD_SRV" Server); NEW_VER=$(bin_version "$NEW_SRV" Server)
OLD_CLI_VER=$(bin_version "$OLD_CLI" CLI); NEW_CLI_VER=$(bin_version "$NEW_CLI" CLI)
echo "[info] versions (printed, NOT ordered): OLD server ${OLD_VER:-?} / cli ${OLD_CLI_VER:-?}; NEW server ${NEW_VER:-?} / cli ${NEW_CLI_VER:-?}"
for pair in "OLD server=$OLD_VER" "OLD cli=$OLD_CLI_VER" "NEW server=$NEW_VER" "NEW cli=$NEW_CLI_VER"; do
    [ -n "${pair#*=}" ] || die "the ${pair%%=*} binary printed no version banner on -h"
done
[ "$OLD_VER" = "$OLD_CLI_VER" ] || die "the OLD server ($OLD_VER) and OLD CLI ($OLD_CLI_VER) are not one build"
[ "$NEW_VER" = "$NEW_CLI_VER" ] || die "the NEW server ($NEW_VER) and NEW CLI ($NEW_CLI_VER) are not one build"
# Nodus EVM: NO "NEW != OLD" check — the Nodus EVM tree's NODUS_VERSION may equal the
# live line's (version bumps happen at merge); capability decides below.

listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}
PROBE_PORT=""
for p in 14991 14992 14993 14994 14995 14996 14997 14998 14999; do
    if ! listening "$p"; then PROBE_PORT="$p"; break; fi
done
[ -n "$PROBE_PORT" ] || die "no free port in 14991..14999 for the name-table probes"
probe() {                  # CLI PARAM VALUE -> the CLI's combined output (rc ignored: 1 either way)
    timeout 60 "$1" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose \
        --param "$2" --value "$3" --effective 1 2>&1 || true
}
for nm in HF2_ACTIVE HF3_ACTIVE RULESET_GEN2; do
    o=$(probe "$OLD_CLI" "$nm" 1)
    [[ "$o" != *"Unknown param name"* && "$o" == *"client_connect failed"* ]] || {
        printf '%s\n' "$o" >&2
        die "the OLD CLI does not know $nm — OLD is not the post-HF-4 live line (step 2 votes it)"; }
done
old_evm=$(probe "$OLD_CLI" EVM_ACTIVE 1)
new_evm=$(probe "$NEW_CLI" EVM_ACTIVE 1)
if [ "$UPG_MODE" = voted-before ]; then
# voted-before: OLD is the build that VOTES HF-5 (the live 0.24.1) — its name
# table must pass EVM_ACTIVE to the connect step exactly as NEW's does
[[ "$old_evm" != *"Unknown param name"* && "$old_evm" == *"client_connect failed"* ]] || {
    printf '%s\n' "$old_evm" >&2
    die "voted-before: the OLD CLI did not pass EVM_ACTIVE through its name table to the connect step — OLD is not a Nodus EVM build"; }
else
[[ "$old_evm" == *"Unknown param name: EVM_ACTIVE"* ]] || {
    printf '%s\n' "$old_evm" >&2
    die "the OLD CLI's name table ACCEPTED EVM_ACTIVE — OLD is not a pre-Nodus-EVM build"; }
fi
[[ "$new_evm" != *"Unknown param name"* && "$new_evm" == *"client_connect failed"* ]] || {
    printf '%s\n' "$new_evm" >&2
    die "the NEW CLI did not pass EVM_ACTIVE through its name table to the connect step — NEW is not a Nodus EVM build"; }
# Nodus EVM: D — the EVM_ACTIVE literal the NEW CLI was compiled with, read from
# its own usage text ("  EVM_ACTIVE             exactly %llu", nodus-cli.c
# cmd_chain_config_propose's usage block, printed before any connect).
usage_out=$(timeout 60 "$NEW_CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
D_DEC=$(sed -n 's/^  EVM_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D_DEC="${D_DEC%%$'\n'*}"
[ -n "$D_DEC" ] || { printf '%s\n' "$usage_out" >&2; die "the NEW CLI's chain-config usage names no 'EVM_ACTIVE exactly <D>'"; }
[ "$D_DEC" -gt 0 ] 2>/dev/null || die "the NEW CLI's EVM_ACTIVE literal '$D_DEC' is not a positive int64"
D_HEX=$(printf '%016x' "$D_DEC")
if [ "$UPG_MODE" = voted-before ]; then
# voted-before: the OLD CLI's own literal, read the same way — the vote is cast
# by OLD and judged at H by NEW, so the two builds must carry ONE D (a binary
# with another D refuses the param-14 value, runbook §2.2 HF-5 item 3)
usage_old=$(timeout 60 "$OLD_CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
D_DEC_OLD=$(sed -n 's/^  EVM_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_old")
D_DEC_OLD="${D_DEC_OLD%%$'\n'*}"
[[ "$D_DEC_OLD" =~ ^[0-9]+$ ]] || { printf '%s\n' "$usage_old" >&2; die "voted-before: the OLD CLI's chain-config usage names no 'EVM_ACTIVE exactly <D>'"; }
[ "$D_DEC_OLD" = "$D_DEC" ] || die \
    "voted-before: the OLD CLI's EVM_ACTIVE literal $D_DEC_OLD (0x$(printf '%016x' "$D_DEC_OLD")) differs from the NEW CLI's $D_DEC (0x$D_HEX) — a fleet rolled onto NEW after an OLD vote would not carry the voted D"
echo "[ok] capability gate (voted-before): OLD knows HF2/HF3/RULESET_GEN2 AND EVM_ACTIVE; NEW knows EVM_ACTIVE (probe port $PROBE_PORT, nothing reached); OLD's D = NEW's D = $D_DEC = 0x$D_HEX"
else
echo "[ok] capability gate: OLD knows HF2/HF3/RULESET_GEN2 and refuses EVM_ACTIVE by name; NEW knows EVM_ACTIVE (probe port $PROBE_PORT, nothing reached); NEW's D = $D_DEC = 0x$D_HEX"
fi

# ── cluster preconditions ───────────────────────────────────────────
[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active Stage F run (bring one up with stagef_up_v2.sh)"
ref_db0=$(stagef_node_chain_db 1)
[ -n "$ref_db0" ] && [ -s "$ref_db0" ] || die "no chain DB for node1"
has_v2=$(sqlite3 "$ref_db0" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster — bring it up with stagef_up_v2.sh"
    exit 99
fi
if [ ! -s "$PINFILE" ]; then
    echo "[SKIP] no $PINFILE — step 12's pinned rejoin needs a stagef_up_v2.sh bring-up that recorded the pin"
    exit 99
fi
PIN=$(cat "$PINFILE")
[ "${#PIN}" = 64 ] || die "recorded pin is not 64 hex chars (32-byte chain id, D-24 rev 4)"
[ -f "$CONF" ] || die "no $CONF — this scenario needs a stagef_up_v2.sh bring-up"
mkdir -p "$LOGD"

# ── script-local helpers (test_cmt_hf4_names.sh's, unless "Nodus EVM:") ──
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_of()  { cat "$1/nodus.fp"; }                 # $1 = identity dir
fp_lc()  { tr 'A-F' 'a-f' < "$1/nodus.fp"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }

node_pid() {
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        case "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" in
            "$(readlink -f "$OLD_SRV")"|"$(readlink -f "$NEW_SRV")") echo "$pid"; return 0 ;;
        esac
    done
    return 0
}

node_runs() {
    local pid
    pid=$(node_pid "$1")
    [ -n "$pid" ] || return 1
    [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$2")" ]
}

# the CLI that may talk to node $1 (the HF-4 rule: a NEW CLI asks
# `dnac_ruleset_info`; the OLD CLI is kept for OLD nodes)
cli_for() {
    if node_runs "$1" "$NEW_SRV"; then echo "$NEW_CLI"; else echo "$OLD_CLI"; fi
}

floor_of() {               # NODE... -> the minimum tip
    local floor=-1 first=1 n h
    for n in "$@"; do
        h=$(tip_of "$n"); [ -n "$h" ] || h=-1
        if [ "$first" = 1 ]; then floor="$h"; first=0
        elif [ "$h" -lt "$floor" ]; then floor="$h"; fi
    done
    echo "$floor"
}

# "  intent_id=<128 hex>" — every v2-envelope builder and the evm builder
# (nodus-cli.c evm_tx_run: printf("  intent_id=") + evm_print_hex)
spend_intent() { awk -F= '/^  intent_id=/{print $2; exit}' "$1"; }

claim_leaf() {
    local cli="$1" keys="$2" node="$3" port db fp log h wrc
    port=$(stagef_tcp_port "$node"); db=$(db_of "$node"); fp=$(fp_of "$keys")
    log="$LOGD/claim_$(basename "$(dirname "$keys")").log"
    "$cli" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$db" \
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
    local node="$1" target="$2" log intent port cli
    port=$(stagef_tcp_port "$node")
    while [ "$(tip_of "$node")" -lt "$target" ]; do
        PUMP_SEQ=$(( PUMP_SEQ + 1 ))
        log="$LOGD/pump_$PUMP_SEQ.log"
        cli=$(cli_for "$node")
        "$cli" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$PUMP_KEYS" \
            --to "$(fp_of "$PUMP_KEYS")" --amount all --count 1 \
            --submit "127.0.0.1:$port" > "$log" 2>&1 \
            || { cat "$log" >&2; die "pump spend $PUMP_SEQ ($cli) was refused/failed on node$node (see $log)"; }
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

stop_node() {
    local k="$1" sig="${2:-TERM}" pid tcp i
    pid=$(node_pid "$k"); tcp=$(stagef_tcp_port "$k")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "-$sig" "$pid"
        for i in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
        ! kill -0 "$pid" 2>/dev/null || die "node$k (pid $pid) did not exit within 60 s of SIG$sig"
        echo "[ok] node$k stopped (SIG$sig, pid $pid)"
    else
        echo "[info] node$k had no running server process to stop"
    fi
    for i in $(seq 1 60); do listening "$tcp" || break; sleep 0.5; done
    ! listening "$tcp" || die "node$k's client port $tcp is still bound after the stop"
}

start_node() {
    local k="$1" bin="$2" nd seeds="" n tcp i ok=0 pid
    shift 2
    nd=$(stagef_node_dir "$k"); tcp=$(stagef_tcp_port "$k")
    for n in $(seq 1 "$N"); do seeds="$seeds -s 127.0.0.1:$(stagef_udp_port "$n")"; done
    # shellcheck disable=SC2086
    "$bin" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$k")" -t "$tcp" \
        -p "$(stagef_peer_port "$k")" -C "$(stagef_chan_port "$k")" \
        -W "$(stagef_witness_port "$k")" \
        "$@" \
        -i "$nd/identity" -d "$nd/data" $seeds \
        >> "$nd/nodus.log" 2>&1 &
    pid=$!
    echo "$pid" >> "$BASE_DIR/pids.txt"
    for i in $(seq 1 60); do if listening "$tcp"; then ok=1; break; fi; sleep 0.5; done
    [ "$ok" = 1 ] || die "node$k never listened again on $tcp after the restart"
    echo "[ok] node$k restarted on $(readlink -f "$bin") (pid $pid)"
}

wait_log_delta() {
    local log="$1" pat="$2" before="$3" what="$4" i
    for i in $(seq 1 30); do
        [ "$(grep -c -- "$pat" "$log" || true)" -gt "$before" ] && return 0
        sleep 1
    done
    die "$what"
}

d2_line_of() {
    grep -o 'generation-2 vote D2 0x[0-9a-f]* (switch spec v[0-9]*), built from git commit [^ ]*' \
        "$(stagef_node_dir "$1")/nodus.log" | tail -1 || true
}

upgrade_node() {
    local k="$1" ref vlog nd chain_before role0 hs0 hsdone0 refuse0 newver0 d2c0 base fleet target
    ref=$(( k == 1 ? 2 : 1 ))
    nd=$(stagef_node_dir "$k"); vlog="$nd/nodus.log"
    node_runs "$k" "$OLD_SRV" || die "node$k is not running the OLD binary before its upgrade step"
    stagef_cmt_diff_at_floor "pre-upgrade-node$k" || exit 2
    base=$(floor_of $(seq 1 "$N"))
    chain_before=$(basename "$(db_of "$k")")
    role0=$(grep -c 'chain role: COMETBFT' "$vlog" || true)
    hs0=$(grep -c 'ABCI replay blocks:' "$vlog" || true)
    hsdone0=$(grep -c 'completed ABCI handshake' "$vlog" || true)
    refuse0=$(grep -c 'REFUSING START' "$vlog" || true)
    # Nodus EVM: OLD and NEW may print the SAME version, so the banner line is
    # counted as a delta (one more "Nodus v<NEW> running" than before)
    newver0=$(grep -c "Nodus v$NEW_VER running" "$vlog" || true)
    d2c0=$(grep -c 'generation-2 vote D2 0x' "$vlog" || true)

    stop_node "$k"
    start_node "$k" "$NEW_SRV"
    node_runs "$k" "$NEW_SRV" || die "node$k's process is not the NEW binary after the restart"

    wait_log_delta "$vlog" 'chain role: COMETBFT' "$role0" \
        "node$k did not re-establish the COMETBFT role on the NEW binary"
    wait_log_delta "$vlog" "Nodus v$NEW_VER running" "$newver0" \
        "node$k's log has no NEW 'Nodus v$NEW_VER running' line after the restart"
    wait_log_delta "$vlog" 'completed ABCI handshake' "$hsdone0" \
        "node$k did not complete a NEW ABCI handshake on the NEW binary"
    wait_log_delta "$vlog" 'generation-2 vote D2 0x' "$d2c0" \
        "node$k's NEW start logged no 'generation-2 vote D2 …, built from git commit …' line"
    [ "$(grep -c 'ABCI replay blocks:' "$vlog" || true)" -gt "$hs0" ] \
        || die "node$k shows no NEW 'ABCI replay blocks:' line after the restart"
    [ "$(grep -c 'REFUSING START' "$vlog" || true)" = "$refuse0" ] \
        || die "node$k logged REFUSING START on the NEW binary"
    [ "$(basename "$(db_of "$k")")" = "$chain_before" ] \
        || die "node$k came back on a DIFFERENT chain file ($chain_before -> $(basename "$(db_of "$k")"))"
    echo "[ok] node$k on NEW: COMETBFT role, handshake completed, same chain file ($chain_before)"

    fleet=$(tip_of "$ref")
    stagef_cmt_wait_height "$(db_of "$k")" "$fleet" 3 >/dev/null \
        || die "node$k did not catch up to the fleet tip $fleet after its upgrade"
    target=$(( fleet + 2 ))
    pump_to "$ref" "$target"
    wait_all "$target"
    [ "$(floor_of $(seq 1 "$N"))" -gt "$base" ] || die "the floor did not move past $base in node$k's step"
    stagef_cmt_diff_at_floor "post-upgrade-node$k" || exit 2
    echo "[ok] rolling step node$k: OLD -> NEW, chain advanced $base -> >= $target, 7/7 agree"
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

# cc_guard NODE — Nodus EVM (ORCH run 1: `chain-config propose HF3_ACTIVE` at tip
# 29, next block 30 an epoch boundary, every other seat answered "MISMATCH
# (peer's set_hash/epoch differ …)"). The CLI takes the committee from
# dnac_committee_query, which answers the committee of tip + 1
# (nodus_witness_handlers.c), but derives the epoch from tip (nodus-cli.c
# cmd_chain_config_propose) — at tip = kE − 1 the two straddle the
# boundary (pre-existing CLI edge, nodus/BUGS.md). The guard: the proposer
# node's tip t must not be a boundary (t % E != 0) and the next boundary
# nb must be >= CC_GUARD_GAP heights away; otherwise pump to nb + 1 and
# re-check (twice at most). The test_cmt_hf2_gov_power.sh precedent
# ("every CC submission is kept >= 3 heights before an epoch boundary").
# Sets CCG_TIP (the guarded tip — every effective height is computed from
# it) and CCG_NB (the next boundary, for cc_guard_after).
cc_guard() {
    local n="$1" t nb try
    for try in 1 2; do
        t=$(tip_of "$n")
        nb=$(( (t / E_REQ + 1) * E_REQ ))
        if [ $(( t % E_REQ )) != 0 ] && [ $(( nb - t )) -ge "$CC_GUARD_GAP" ]; then
            CCG_TIP="$t"; CCG_NB="$nb"
            return 0
        fi
        echo "[info] node$n's tip $t is on or within $CC_GUARD_GAP heights of the epoch boundary $nb — pumping to $(( nb + 1 )) before the proposal (attempt $try)"
        pump_to 1 $(( nb + 1 ))
        wait_all $(( nb + 1 ))
    done
    die "node$n's tip $(tip_of "$n") is still next to an epoch boundary after two guard pumps"
}

# cc_guard_after NODE — right after the CLI returned: the proposer's tip + 1
# must still be below the boundary cc_guard saw, so every tip the CLI could
# have read kept tip and tip + 1 in ONE epoch. Otherwise FAIL with that
# reason — a false RED, never a false PASS.
cc_guard_after() {
    local t
    t=$(tip_of "$1")
    [ $(( t + 1 )) -lt "$CCG_NB" ] || die \
        "the proposal from node$1 crossed into the epoch boundary $CCG_NB (tip $CCG_TIP -> $t): its approvals may straddle two epochs (the CLI committee/epoch edge, nodus/BUGS.md) — the layout broke, not the chain"
}

# propose CLI NAME VALUE EFFECTIVE LOG — node 1's seat; FAIL unless round 1
# is 7/7 and the CLI reports acceptance. Nodus EVM: the 7/7 round-1 check is the
# seats' agreement on the value (each one's scalar rule).
propose() {
    local cli="$1" name="$2" val="$3" eff="$4" log="$5" prc=0
    "$cli" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$(node_keys 1)" \
        chain-config propose --param "$name" --value "$val" --effective "$eff" > "$log" 2>&1 || prc=$?
    cat "$log"
    cc_guard_after 1
    [ "$prc" = 0 ] || die "chain-config propose $name exited $prc (see $log)"
    grep -q "Round 1: $N/$N approved" "$log" || die "propose $name: round 1 was not $N/$N (see $log)"
    grep -q "proposal accepted" "$log" || die "propose $name did not report acceptance (see $log)"
}

# second_proposal CLI NAME VALUE EFFECTIVE LOG — node 2's seat (no
# per-proposer cooldown record); every OTHER seat must refuse with the
# stateful rule's own text (the HF-4 scenario's single-use check).
second_proposal() {
    local cli="$1" name="$2" val="$3" eff="$4" log="$5" prc=0 nref
    "$cli" -s 127.0.0.1 -p "$(stagef_tcp_port 2)" -i "$(node_keys 2)" \
        chain-config propose --param "$name" --value "$val" --effective "$eff" > "$log" 2>&1 || prc=$?
    cat "$log"
    cc_guard_after 2
    [ "$prc" != 0 ] || die "a SECOND $name proposal (effective $eff) exited 0 — single use did not refuse it"
    ! grep -q "proposal accepted" "$log" || die "the second $name proposal reported acceptance"
    grep -q "Round 1: 1/$N approved" "$log" \
        || die "the second $name proposal did not end round 1 at 1/$N (only its own seat) — see $log"
    nref=$(grep -c "REFUSED: stateful rules rejected" "$log" || true)
    [ "$nref" = $(( N - 1 )) ] || die \
        "$nref of $(( N - 1 )) other seats refused the second $name proposal with 'stateful rules rejected' — see $log"
    grep -q "Quorum not reached" "$log" || die "the second $name proposal did not abort on quorum (see $log)"
}

# ruleset_info CLI NODE — Nodus EVM: the CLI is an argument (OLD on the OLD
# fleet, NEW after the roll). Output lines parsed (nodus-cli.c
# cmd_ruleset_info): "tip=%llu generation=%u (governs tip+1)",
# "  SYSTEM v%u hash=<128>", "  CORE   v%u hash=<128>",
# "  RULESET_GEN2 height H=%llu…", "  node D2=0x%016llx  this CLI D2=0x%016llx…",
# "  this CLI carries it as compiled generation %u".
ruleset_info() {
    local cli="$1" n="$2" log rrc=0
    log="$LOGD/ruleset_info_node${n}_$(tip_of "$n")_$(basename "$cli").log"
    "$cli" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" ruleset-info > "$log" 2>&1 || rrc=$?
    RI_RC="$rrc"
    RI_OUT=$(cat "$log")
    RI_TIP=$(sed -n 's/^tip=\([0-9]*\) generation=.*/\1/p' "$log")
    RI_GEN=$(sed -n 's/^tip=[0-9]* generation=\([0-9]*\) .*/\1/p' "$log")
    RI_SYS_V=$(awk '$1 == "SYSTEM" { print substr($2, 2); exit }' "$log")
    RI_SYS_H=$(awk '$1 == "SYSTEM" { print substr($3, 6); exit }' "$log")
    RI_CORE_V=$(awk '$1 == "CORE" { print substr($2, 2); exit }' "$log")
    RI_CORE_H=$(awk '$1 == "CORE" { print substr($3, 6); exit }' "$log")
    RI_H=$(sed -n 's/^  RULESET_GEN2 height H=\([0-9]*\).*/\1/p' "$log")
    RI_D2=$(sed -n 's/^  node D2=0x\([0-9a-f]*\) .*/\1/p' "$log")
    RI_CLI_D2=$(sed -n 's/^  node D2=0x[0-9a-f]*  this CLI D2=0x\([0-9a-f]*\).*/\1/p' "$log")
}

# require_gen CLI NODE GEN H — Nodus EVM: generation + the param-9 H + carried
# by CLI as that compiled generation; versions are read, never assumed.
require_gen() {
    local cli="$1" n="$2" g="$3" hh="$4"
    ruleset_info "$cli" "$n"
    [ "$RI_RC" = 0 ] || { printf '%s\n' "$RI_OUT" >&2; die "ruleset-info on node$n exited $RI_RC"; }
    [ "$RI_GEN" = "$g" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports generation '$RI_GEN' at tip $RI_TIP, expected $g"; }
    [ "${#RI_SYS_H}" = 128 ] && [ "${#RI_CORE_H}" = 128 ] || {
        printf '%s\n' "$RI_OUT" >&2; die "node$n's ruleset-info hashes did not parse"; }
    [ "$RI_H" = "$hh" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports RULESET_GEN2 H=$RI_H, expected $hh"; }
    [[ "$RI_OUT" != *MISMATCH* ]] || { printf '%s\n' "$RI_OUT" >&2; die "node$n's D2 differs from the CLI's"; }
    [[ "$RI_OUT" == *"this CLI carries it as compiled generation $g"* ]] || {
        printf '%s\n' "$RI_OUT" >&2; die "the CLI does not carry node$n's tuple as compiled generation $g"; }
}

rh_row() {
    sqlite3 "$(db_of "$1")" \
        "SELECT ruleset_version || '|' || lower(hex(ruleset_hash)) || '|' || lower(hex(state_root))
           FROM v2_root_history WHERE domain_id = $2 AND global_height = $3;" 2>/dev/null || echo ERR
}
rh_below() {
    sqlite3 "$(db_of "$1")" \
        "SELECT ruleset_version || '|' || lower(hex(ruleset_hash)) FROM v2_root_history
          WHERE domain_id = $2 AND global_height < $3
          ORDER BY global_height DESC LIMIT 1;" 2>/dev/null || echo ERR
}

# ── Nodus EVM: EVM helpers ───────────────────────────────────────────────
BC() { BC_LINE_LENGTH=0 bc; }
hexdec() {                 # 64 UPPERCASE hex (sqlite hex()) -> decimal
    [ "${#1}" = 64 ] || { echo ERR; return 0; }
    printf 'ibase=16; %s\n' "$1" | BC
}

# evm_addr_of KEYS -> the 32-byte address `evm address` prints (offline;
# nodus-cli.c cmd_evm "address": printf("0x") + 64 hex)
evm_addr_of() {
    local out line hit="" n=0
    out=$("$NEW_CLI" evm address --keys "$1" 2>&1) || die "evm address --keys $1 failed: $out"
    while IFS= read -r line; do
        if [[ "$line" =~ ^0x([0-9a-f]{64})$ ]]; then hit="${BASH_REMATCH[1]}"; n=$(( n + 1 )); fi
    done <<< "$out"
    [ "$n" = 1 ] || die "evm address --keys $1 printed $n address lines: '$out'"
    echo "$hit"
}

# evm_tx NODE KEYS_NODE LOG SUBCOMMAND ARGS... — a transaction with the NEW
# CLI as KEYS_NODE's identity, submitted to NODE's own port, --no-wait
# (inclusion is read from the ledger, never from the CLI). Sets EV_RC,
# EV_INTENT and the build line's fields EV_NONCE / EV_GAS / EV_FEE, parsed
# from nodus-cli.c evm_tx_run's
#   "evm %s: sender 0x<64> nonce=%llu gas=%llu units=%llu fee=%llu
#    inputs=%d change=%llu expiry=%llu generation=%u"
# and "accepted: mempool CheckTx approved …" (t6_submit_on).
evm_tx() {
    local node="$1" kn="$2" log="$3" port
    shift 3
    port=$(stagef_tcp_port "$node")
    EV_RC=0
    "$NEW_CLI" -s 127.0.0.1 -p "$port" evm "$@" --keys "$(node_keys "$kn")" \
        --submit "127.0.0.1:$port" --no-wait > "$log" 2>&1 || EV_RC=$?
    cat "$log"
    EV_INTENT=$(spend_intent "$log")
    EV_NONCE=$(sed -n 's/^evm [A-Z]*: sender 0x[0-9a-f]* nonce=\([0-9]*\) .*/\1/p' "$log")
    EV_GAS=$(sed -n 's/^evm [A-Z]*: sender 0x[0-9a-f]* nonce=[0-9]* gas=\([0-9]*\) .*/\1/p' "$log")
    EV_FEE=$(sed -n 's/^evm [A-Z]*: .* fee=\([0-9]*\) inputs=.*/\1/p' "$log")
}

# evm_tx_ok — the last evm_tx was built AND CheckTx-approved
evm_tx_ok() {
    [ "$EV_RC" = 0 ] || die "$1: the CLI exited $EV_RC"
    [ "${#EV_INTENT}" = 128 ] || die "$1: no intent_id printed"
    [ -n "$EV_GAS" ] && [ -n "$EV_FEE" ] && [ -n "$EV_NONCE" ] || die "$1: the build line did not parse"
    grep -q '^accepted: mempool CheckTx approved' "$2" || die "$1: no CheckTx approval line"
}

# wait_receipt NODE INTENT WHAT — the evm_receipts row (design §7, written
# in the item's savepoint) is the inclusion; sets RC_H = its global_height.
wait_receipt() {
    local db h wrc
    db=$(db_of "$1")
    h=$(stagef_cmt_wait_row "$db" \
        "SELECT COUNT(*) FROM evm_receipts WHERE lower(hex(intent_id)) = '$2';") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "$3: chain STALLED waiting for its receipt on node$1 (tip $h)" ;;
        *) die "$3: no receipt within 20 heights on node$1 (tip $h) — dropped, not delayed" ;;
    esac
    RC_H=$(sqlite3 "$db" "SELECT global_height FROM evm_receipts WHERE lower(hex(intent_id)) = '$2';")
    wait_all "$RC_H"
}

# rcpt NODE INTENT -> "status|op|gas_used_hex|created_hex" from the stored
# canonical receipt bytes (layout: header comment)
rcpt() {
    sqlite3 "$(db_of "$1")" \
        "SELECT hex(substr(receipt,17,1)) || '|' || hex(substr(receipt,18,1)) || '|' ||
                hex(substr(receipt,19,8)) || '|' || lower(hex(substr(receipt,27,32)))
           FROM evm_receipts WHERE lower(hex(intent_id)) = '$2';" 2>/dev/null || echo ERR
}

# require_rcpt INTENT STATUS OP WHAT — the receipt fields identical on 7/7,
# status / op as expected, and the digest re-derived from the stored bytes
# on every node; sets RCPT (the shared field string).
require_rcpt() {
    local i="$1" st="$2" op="$3" what="$4" n r dg re
    RCPT=""
    for n in $(seq 1 "$N"); do
        r=$(rcpt "$n" "$i")
        [ -n "$r" ] && [ "$r" != ERR ] || die "$what: node$n has no receipt row for ${i:0:16}..."
        if [ -z "$RCPT" ]; then RCPT="$r"
        elif [ "$r" != "$RCPT" ]; then die "$what: node$n's receipt '$r' differs from node1's '$RCPT'"; fi
        dg=$(sqlite3 "$(db_of "$n")" "SELECT lower(hex(digest)) FROM evm_receipts WHERE lower(hex(intent_id)) = '$i';")
        re=$(sqlite3 "$(db_of "$n")" "SELECT hex(receipt) FROM evm_receipts WHERE lower(hex(intent_id)) = '$i';" \
             | xxd -r -p | openssl dgst -sha3-512 | awk '{print $NF}')
        [ "${#dg}" = 128 ] && [ "$dg" = "$re" ] || die "$what: node$n's stored digest is not SHA3-512 of its stored receipt"
    done
    [ "${RCPT%%|*}" = "$st" ] || die "$what: receipt status ${RCPT%%|*}, expected $st"
    r="${RCPT#*|}"
    [ "${r%%|*}" = "$op" ] || die "$what: receipt op ${r%%|*}, expected $op"
}

# evm_q NODE ARGS... — a read with the NEW CLI against NODE (EQ_RC, EQ_OUT)
evm_q() {
    local n="$1"
    shift
    EQ_RC=0
    EQ_OUT=$("$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" evm "$@" 2>&1) || EQ_RC=$?
}

# evm_balance_of NODE ADDR -> the wei decimal (nodus-cli.c cmd_evm balance:
# "  balance %s wei (%s NODUS)")
evm_balance_of() {
    evm_q "$1" balance "$2"
    [ "$EQ_RC" = 0 ] || { printf '%s\n' "$EQ_OUT" >&2; die "evm balance on node$1 exited $EQ_RC"; }
    awk '$1 == "balance" && !f { print $2; f = 1 }' <<< "$EQ_OUT"
}

# evm_call_u256 NODE ADDR SIG -> the first decoded return word (nodus-cli.c
# cmd_evm call: "ok at height …" then evm_abi_print's "  [0] <decimal>")
evm_call_u256() {
    evm_q "$1" call "$2" "$3" --gas "$GAS_CALL"
    [ "$EQ_RC" = 0 ] || { printf '%s\n' "$EQ_OUT" >&2; die "evm call $3 on node$1 exited $EQ_RC"; }
    # a LINE starting "ok at height" — the CLI's "Using random identity"
    # (nodus-cli.c:8138, stderr) precedes it in EQ_OUT (harness run 3)
    grep -q '^ok at height' <<< "$EQ_OUT" || { printf '%s\n' "$EQ_OUT" >&2; die "evm call $3 on node$1 did not succeed"; }
    awk '$1 == "[0]" && !f { print $2; f = 1 }' <<< "$EQ_OUT"
}

require_call_all() {       # ADDR SIG EXPECTED
    local n v
    for n in $(seq 1 "$N"); do
        v=$(evm_call_u256 "$n" "$1" "$2")
        [ "$v" = "$3" ] || die "evm call $2 on node$n returned '$v', expected $3"
    done
}

nonce_of() {               # NODE ADDR -> the committed EVM nonce ("" = no account)
    sqlite3 "$(db_of "$1")" "SELECT nonce FROM evm_accounts WHERE lower(hex(addr)) = '$2';" 2>/dev/null || echo ERR
}

# native_sum NODE FP — node-owned native coins below the graduation (200)
# and payday (>= 400) bands: only the owner's own spends move them
native_sum() {
    sqlite3 "$(db_of "$1")" \
        "SELECT COALESCE(SUM(amount), 0) FROM utxo_set WHERE lower(owner) = '$2'
           AND token_id = zeroblob(64) AND output_index < 200;" 2>/dev/null || echo ERR
}

rel_count() {              # NODE FP AMOUNT -> index-101 release coins of that amount
    sqlite3 "$(db_of "$1")" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(owner) = '$2' AND amount = $3
           AND output_index = $REL_INDEX AND token_id = zeroblob(64);" 2>/dev/null || echo ERR
}

# evm_dump NODE FLOOR — the whole EVM state + the node-local receipt / log
# index, one canonical text (ORDER BY every key). The EVM domain's
# v2_root_history rows are bounded to global_height <= FLOOR (a height
# every compared node holds): whether that table gains a row on blocks
# without an EVM item was not read, so nodes one idle block apart must not
# be compared past the floor.
evm_dump() {
    local floor="$2"
    sqlite3 "$(db_of "$1")" "
      SELECT 'A|' || lower(hex(addr)) || '|' || nonce || '|' || hex(balance) || '|' || hex(code_hash) || '|' ||
             code_size || '|' || hex(code_digest) || '|' || storage_count || '|' || hex(storage_root)
        FROM evm_accounts ORDER BY addr;
      SELECT 'S|' || hex(addr) || '|' || hex(slot) || '|' || hex(value) FROM evm_slots ORDER BY addr, slot;
      SELECT 'C|' || hex(digest) || '|' || refs || '|' || code_size FROM evm_code_refs ORDER BY digest;
      SELECT 'K|' || hex(digest) || '|' || chunk || '|' || length(bytes) || '|' || hex(bytes) FROM evm_code ORDER BY digest, chunk;
      SELECT 'T|' || hex(ticket_id) || '|' || amount_raw || '|' || hex(dest_fp) FROM evm_tickets ORDER BY ticket_id;
      SELECT 'M|' || hex(wei_live) || '|' || hex(wei_tickets) || '|' || hex(wei_lost) || '|' ||
             hex(account_trie_root) || '|' || hex(tickets_root) FROM evm_meta ORDER BY id;
      SELECT 'R|' || reserve_raw FROM v2_evm_reserve ORDER BY id;
      SELECT 'H|' || global_height || '|' || ruleset_version || '|' || hex(ruleset_hash) || '|' || hex(state_root)
        FROM v2_root_history WHERE domain_id = $DOM_EVM AND global_height <= $floor ORDER BY global_height;
      SELECT 'X|' || hex(intent_id) || '|' || global_height || '|' || item_index || '|' || hex(digest)
        FROM evm_receipts ORDER BY intent_id;
      SELECT 'L|' || hex(intent_id) || '|' || log_index || '|' || global_height || '|' || hex(addr) || '|' ||
             hex(topics) || '|' || hex(data) FROM evm_logs ORDER BY intent_id, log_index;" 2>/dev/null || echo ERR
}

# require_evm_same WHAT [NODES...] — the EVM dump identical on the nodes
# (default 1..7); the caller has waited every node past the last EVM effect
require_evm_same() {
    local what="$1" n ref d fl
    shift
    local nodes="${*:-$(seq 1 "$N")}"
    fl=$(floor_of $(seq 1 "$N"))
    [ "$fl" -ge 0 ] || die "$what: no floor height"
    ref=$(evm_dump 1 "$fl")
    [ "$ref" != ERR ] || die "$what: node1's EVM tables are unreadable"
    for n in $nodes; do
        d=$(evm_dump "$n" "$fl")
        [ "$d" = "$ref" ] || {
            printf 'node1:\n%s\nnode%s:\n%s\n' "$ref" "$n" "$d" >&2
            die "$what: node$n's EVM state differs from node1's"; }
    done
    EVM_DUMP="$ref"
}

# require_supply WHAT RESERVE LIVE TICKETS — exact values + the design §5
# invariant wei_live + wei_tickets + wei_lost == 10^10 x reserve_raw, 7/7
require_supply() {
    local what="$1" rsv_x="$2" live_x="$3" tk_x="$4" n meta L T X rsv live tk lost lhs rhs
    for n in $(seq 1 "$N"); do
        meta=$(sqlite3 "$(db_of "$n")" \
            "SELECT hex(wei_live) || ' ' || hex(wei_tickets) || ' ' || hex(wei_lost) FROM evm_meta WHERE id = 1;" 2>/dev/null || true)
        read -r L T X <<< "$meta" || true
        rsv=$(sqlite3 "$(db_of "$n")" "SELECT reserve_raw FROM v2_evm_reserve WHERE id = 1;" 2>/dev/null || echo ERR)
        live=$(hexdec "${L:-}"); tk=$(hexdec "${T:-}"); lost=$(hexdec "${X:-}")
        for v in "$live" "$tk" "$lost" "$rsv"; do
            [[ "$v" =~ ^[0-9]+$ ]] || die "$what: node$n's evm_meta / v2_evm_reserve did not read ('$meta' / '$rsv')"
        done
        lhs=$(printf '%s+%s+%s\n' "$live" "$tk" "$lost" | BC)
        rhs=$(printf '%s*%s\n' "$rsv" "$Q" | BC)
        [ "$lhs" = "$rhs" ] || die "$what: node$n BREAKS the supply invariant: $live + $tk + $lost != $Q x $rsv"
        [ "$rsv" = "$rsv_x" ] || die "$what: node$n's reserve is $rsv, expected $rsv_x"
        [ "$live" = "$live_x" ] || die "$what: node$n's wei_live is $live, expected $live_x"
        [ "$tk" = "$tk_x" ] || die "$what: node$n's wei_tickets is $tk, expected $tk_x"
        [ "$lost" = 0 ] || die "$what: node$n's wei_lost is $lost, expected 0 (nothing here destroys value)"
    done
    echo "[ok] $what: 7/7 reserve $rsv_x raw, wei_live $live_x, wei_tickets $tk_x, wei_lost 0 — invariant holds"
}

# ── 0. preconditions: fresh cluster, every node on the OLD binary ───
for n in $(seq 1 "$N"); do
    node_runs "$n" "$OLD_SRV" || die \
        "node$n is not running STAGEF_NODUS_BIN_OLD ($(readlink -f "$OLD_SRV")) — bring the cluster up with STAGEF_NODUS_BIN=\$STAGEF_NODUS_BIN_OLD (header)"
    grep -q "Nodus v$OLD_VER running" "$(stagef_node_dir "$n")/nodus.log" \
        || die "node$n's log has no 'Nodus v$OLD_VER running' line — it was not started from the OLD build"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
# Nodus EVM: the `evm` capability (offline — no server reached)
ADDR1=$(evm_addr_of "$(node_keys 1)")
ADDR2=$(evm_addr_of "$(node_keys 2)")
[ "$ADDR1" != "$ADDR2" ] || die "nodes 1 and 2 map to the same EVM address"
old_ea_rc=0
old_ea=$(timeout 60 "$OLD_CLI" -s 127.0.0.1 -p "$PROBE_PORT" evm address --keys "$(node_keys 1)" 2>&1) || old_ea_rc=$?
# (pure bash match — `printf | grep -q` under pipefail can SIGPIPE, README
# "test_v2_rewards.sh … Membership is matched in PURE BASH")
old_ea_addr=0
while IFS= read -r line; do
    [[ "$line" =~ ^0x[0-9a-f]{64}$ ]] && old_ea_addr=1
done <<< "$old_ea"
if [ "$UPG_MODE" = voted-before ]; then
# voted-before: OLD is an EVM build too — it must answer with exactly one
# address line, and the SAME 32-byte address NEW derived for node 1
old_ea_hits=0; old_ea_hex=""
while IFS= read -r line; do
    if [[ "$line" =~ ^0x([0-9a-f]{64})$ ]]; then old_ea_hex="${BASH_REMATCH[1]}"; old_ea_hits=$(( old_ea_hits + 1 )); fi
done <<< "$old_ea"
[ "$old_ea_rc" = 0 ] && [ "$old_ea_hits" = 1 ] && [ "$old_ea_hex" = "$ADDR1" ] || {
    printf '%s\n' "$old_ea" >&2
    die "voted-before: the OLD CLI's 'evm address' (rc $old_ea_rc, $old_ea_hits address line(s), '0x$old_ea_hex') is not node1's 0x$ADDR1 as NEW derives it"; }
echo "[ok] both CLIs know 'evm' and derive the same address (node1 0x$ADDR1, node2 0x$ADDR2, offline)"
else
[ "$old_ea_rc" != 0 ] && [ "$old_ea_addr" = 0 ] || {
    printf '%s\n' "$old_ea" >&2
    die "the OLD CLI answered 'evm address' (rc $old_ea_rc) — OLD is not a pre-Nodus-EVM build"; }
echo "[ok] NEW CLI knows 'evm' (node1 0x$ADDR1, node2 0x$ADDR2, offline); OLD CLI does not (rc $old_ea_rc)"
fi
# Nodus EVM: the ticket system address (design §5; nodus_witness_rt_evm.c
# TICKET_ADDR_PREIMAGE "NDS.EVMWITHDRAW.v1", nodus_rt_evm_ticket_addr:
# SHA3-512 of the 18 bytes, first 32)
SYS_ADDR=$(printf 'NDS.EVMWITHDRAW.v1' | openssl dgst -sha3-512 | awk '{print substr($NF, 1, 64)}')
[ "${#SYS_ADDR}" = 64 ] || die "could not derive the ticket system address"
COUNTER_HEX=$(tr -d '\n' < "$FIX_DIR/Counter.hex")
TICKETER_HEX=$(tr -d '\n' < "$FIX_DIR/Ticketer.hex")
INCR_TOPIC=$(sed -n 's/^event \([0-9a-f]\{64\}\): Incremented(address,uint256)$/\1/p' "$FIX_DIR/abi.sigs")
[ "${#INCR_TOPIC}" = 64 ] || die "abi.sigs names no Incremented topic"
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run the OLD binary $(readlink -f "$OLD_SRV")"
echo "     NEW binary: $(readlink -f "$NEW_SRV")"

# ── 1. the OLD chain commits; fund the pump + the EVM users ─────────
stagef_cmt_diff_at_floor "on-OLD" || exit 2
claim_leaf "$OLD_CLI" "$PUMP_KEYS" 1
claim_leaf "$OLD_CLI" "$(node_keys 1)" 1
claim_leaf "$OLD_CLI" "$(node_keys 2)" 1
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
stagef_cmt_diff_at_floor "OLD-chain-committing" || exit 2

# ── 2. the live testnet's state on the OLD fleet: HF-2, HF-3, gen 2 ─
cc_guard 1
T_V2="$CCG_TIP"
H2=$(( T_V2 + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $T_V2 — node1 proposes HF2_ACTIVE=1 effective H2=$H2 with the OLD CLI"
propose "$OLD_CLI" HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
R_V2="$CC_CB"
[ "$R_V2" -lt "$H2" ] || die "the HF2 row committed at $R_V2, not before its effective height $H2"
pump_to 1 $(( H2 + 1 ))
wait_all $(( H2 + 1 ))
stagef_cmt_diff_at_floor "OLD-past-HF2" || exit 2
echo "[ok] HF-2 ACTIVE on the OLD fleet from H2=$H2 (row committed at $R_V2)"

cc_guard 1
T_V3="$CCG_TIP"
H3=$(( T_V3 + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $T_V3 — node1 proposes HF3_ACTIVE=1 effective H3=$H3 with the OLD CLI"
propose "$OLD_CLI" HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
R_V3="$CC_CB"
[ "$R_V3" -lt "$H3" ] || die "the HF3 row committed at $R_V3, not before its effective height $H3"
pump_to 1 $(( H3 + 1 ))
wait_all $(( H3 + 1 ))
stagef_cmt_diff_at_floor "OLD-past-HF3" || exit 2
echo "[ok] HF-3 ACTIVE on the OLD fleet from H3=$H3 (row committed at $R_V3)"

# Nodus EVM: RULESET_GEN2 on the OLD fleet with the OLD CLI (the HF-4
# scenario's step 5 and 7 shape) — the registry must be at generation 2
# (rule (e) of EVM_ACTIVE) before the EVM vote.
require_gen "$OLD_CLI" 1 1 0
D2_HEX="$RI_D2"
[ "${#D2_HEX}" = 16 ] && [ "$D2_HEX" = "$RI_CLI_D2" ] || die "the node's D2 '$D2_HEX' and the OLD CLI's '$RI_CLI_D2' are not one 16-hex literal"
D2_DEC=$(( 16#$D2_HEX ))
[ "$D2_DEC" -gt 0 ] || die "D2 0x$D2_HEX is not a positive int64"
cc_guard 1
T_V4="$CCG_TIP"
H4=$(( T_V4 + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( (H4 - 1) % E_REQ )) = 0 ]; do H4=$(( H4 + 1 )); done   # param 9 rule (c)
echo "[ok] tip $T_V4 — node1 proposes RULESET_GEN2=$D2_DEC effective H4=$H4 with the OLD CLI"
propose "$OLD_CLI" RULESET_GEN2 "$D2_DEC" "$H4" "$LOGD/propose_gen2.log"
wait_cc_row "$PARAM_GEN2" "$H4" "$D2_DEC" 20
R_V4="$CC_CB"
[ "$R_V4" -lt "$H4" ] || die "the RULESET_GEN2 row committed at $R_V4, not before its effective height $H4"
pump_to 1 $(( H4 - PUMP_STOP_GAP ))      # the OLD CLI caps a gen-1 expiry at H4-1
wait_all $(( H4 + 1 ))
for hh in $(( H4 - 1 )) "$H4" $(( H4 + 1 )); do diff_at "$hh" "gen2-at-height-$hh"; done
for n in $(seq 1 "$N"); do
    grep -q "rule-set generation 1 -> 2 at the end of height $(( H4 - 1 )) " "$(stagef_node_dir "$n")/nodus.log" \
        || die "node$n logged no 'rule-set generation 1 -> 2 at the end of height $(( H4 - 1 ))' line"
    require_gen "$OLD_CLI" "$n" "$GEN_BASE" "$H4"
done
GEN2_SYS_V="$RI_SYS_V"; GEN2_CORE_V="$RI_CORE_V"; GEN2_SYS_H="$RI_SYS_H"; GEN2_CORE_H="$RI_CORE_H"
stagef_cmt_diff_at_floor "OLD-past-gen2" || exit 2
echo "[ok] rule-set generation 2 on the OLD fleet from H4=$H4 (row committed at $R_V4): SYSTEM v$GEN2_SYS_V / CORE v$GEN2_CORE_V"

# evm_vote CLI — step 5's vote, unchanged but for the CLI it votes with
# (NEW at step 5 in voted-after; OLD right below in voted-before) and
# ROLL_MARGIN in H (0 in voted-after). Sets T_VOTE, H, R_VOTE, T_2ND, H_2ND.
evm_vote() {
    local cli="$1"
    cc_guard 1
    T_VOTE="$CCG_TIP"
    H=$(( T_VOTE + 1 + STAGEF_CC_GRACE_SAFETY + H_MARGIN + ROLL_MARGIN ))    # param 14: SAFETY grace
    # Nodus EVM red-team 1 F5, rule (g): the first EVM block's BLOCKHASH window
    # [H-256, H-1] must lie on the chain — H >= initial_height + 256, the
    # initial height read from the ceremony's genesis config (completed 0 -> 1
    # as the node completes it, nodus_witness_v2_chain_initial_height). Every
    # seat refuses an earlier H ("stateful rules rejected"), so H moves up to
    # that floor + WINDOW_MARGIN; the pumping below carries the chain there.
    INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
    [ -n "$INIT_H" ] || die "no initial_height in $CONF"
    [ "$INIT_H" = 0 ] && INIT_H=1
    H_WIN=$(( INIT_H + 256 + WINDOW_MARGIN ))
    [ "$H" -ge "$H_WIN" ] || H="$H_WIN"
    while [ $(( (H - 1) % E_REQ )) = 0 ]; do H=$(( H + 1 )); done   # rule (f)
    echo "[ok] F5 window floor: initial_height $INIT_H -> H >= $(( INIT_H + 256 )) (H $H)"
    echo "[ok] tip $T_VOTE — node1 proposes EVM_ACTIVE=$D_DEC effective H=$H (H-1=$(( H - 1 )), $(( (H - 1) % E_REQ )) past a boundary of E=$E_REQ)"
    propose "$cli" EVM_ACTIVE "$D_DEC" "$H" "$LOGD/propose_evm.log"
    wait_cc_row "$PARAM_EVM" "$H" "$D_DEC" 20
    R_VOTE="$CC_CB"
    [ "$R_VOTE" -lt "$H" ] || die "the EVM_ACTIVE row committed at $R_VOTE, not before its effective height $H"
    stagef_cmt_diff_at_floor "post-evm-vote" || exit 2

    cc_guard 2                 # node 2's seat proposes, on node 2's own port
    T_2ND="$CCG_TIP"
    [ $(( T_2ND + 1 )) -lt "$H" ] || die "node2's tip $T_2ND reached H-1 before the second proposal (widen H_MARGIN)"
    H_2ND=$(( H + 2 ))
    [ "$H_2ND" -ge $(( T_2ND + 1 + STAGEF_CC_GRACE_SAFETY )) ] || H_2ND=$(( T_2ND + 1 + STAGEF_CC_GRACE_SAFETY ))
    while [ $(( (H_2ND - 1) % E_REQ )) = 0 ]; do H_2ND=$(( H_2ND + 1 )); done
    [ "$H_2ND" -ge $(( T_2ND + 1 + STAGEF_CC_GRACE_SAFETY )) ] \
        || die "the second proposal's effective $H_2ND is below its grace floor at tip $T_2ND — the layout broke (widen H_MARGIN)"
    second_proposal "$cli" EVM_ACTIVE "$D_DEC" "$H_2ND" "$LOGD/propose_evm_second.log"
    t=$(tip_of 1)
    pump_to 1 $(( t + 3 ))
    wait_all $(( t + 3 ))
    for n in $(seq 1 "$N"); do
        c=$(sqlite3 "$(db_of "$n")" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $PARAM_EVM;" 2>/dev/null || echo ERR)
        [ "$c" = 1 ] || die "node$n holds $c param-14 rows at tip >= $(( t + 3 )) — expected exactly the one effective at $H"
    done
    echo "[ok] the second EVM_ACTIVE proposal (effective $H_2ND) was REFUSED by the seats; param 14 has ONE row on 7/7"
}

# ── voted-before helpers (defined in every mode, called only in voted-before) ──
ceil_of() {                # NODE... -> the maximum tip (no node past it)
    local top=-1 n h
    for n in "$@"; do
        h=$(tip_of "$n"); [ -n "$h" ] || h=-1
        [ "$h" -le "$top" ] || top="$h"
    done
    echo "$top"
}

# vb_state WHAT — the param-14 row is still EVM_ROW on 7/7, still ONE row,
# and 7/7 still report generation 2 (each node asked with the CLI of the
# binary it runs, cli_for — the mixed window's rule)
vb_state() {
    local what="$1" n r c
    for n in $(seq 1 "$N"); do
        r=$(cc_row "$n" "$PARAM_EVM" "$H")
        [ "$r" = "$EVM_ROW" ] || die "$what: node$n's param-14 row is '$r', not the voted '$EVM_ROW'"
        c=$(sqlite3 "$(db_of "$n")" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $PARAM_EVM;" 2>/dev/null || echo ERR)
        [ "$c" = 1 ] || die "$what: node$n holds $c param-14 rows, expected exactly one"
        require_gen "$(cli_for "$n")" "$n" "$GEN_BASE" "$H4"
    done
    echo "[ok] $what: the param-14 row (value $D_DEC, effective $H) identical on 7/7, ONE row; 7/7 still generation $GEN_BASE"
}

# vb_roll_guard K — before node K's rolling step: the steps left, each
# charged max(ROLL_STEP_BLOCKS, the largest step measured so far), must
# still end with H-1 uncommitted on every node; else FAIL with that reason.
VB_STEP_MAX=0; VB_STEP_BASE=0
vb_roll_guard() {
    local k="$1" top left per
    top=$(ceil_of $(seq 1 "$N"))
    left=$(( N - k + 1 ))
    per="$ROLL_STEP_BLOCKS"
    [ "$VB_STEP_MAX" -le "$per" ] || per="$VB_STEP_MAX"
    [ $(( top + left * per + 1 )) -lt "$H" ] || die \
        "voted-before: the rolling upgrade cannot finish before H-1=$(( H - 1 )): highest tip $top, $left step(s) left x $per blocks (max of ROLL_STEP_BLOCKS=$ROLL_STEP_BLOCKS and the largest step measured, $VB_STEP_MAX) reaches $(( top + left * per )) — widen ROLL_STEP_BLOCKS"
    VB_STEP_BASE="$top"
}

# vb_after_step K — node K's step measured in blocks; H-1 still uncommitted
# on every node; the row and generation 2 unchanged on 7/7
vb_after_step() {
    local k="$1" top used
    top=$(ceil_of $(seq 1 "$N"))
    used=$(( top - VB_STEP_BASE ))
    [ "$used" -le "$VB_STEP_MAX" ] || VB_STEP_MAX="$used"
    [ $(( top + 1 )) -lt "$H" ] || die \
        "voted-before: a node committed H-1=$(( H - 1 )) during the rolling upgrade (after node$k's step, highest tip $top) — the roll did not finish before H-1"
    echo "[ok] node$k's rolling step consumed $used block(s) (largest so far $VB_STEP_MAX); highest tip $top, H-1=$(( H - 1 )) still ahead"
    vb_state "after node$k's rolling step"
}

# ── 2b. voted-before: EVM_ACTIVE voted on the 7/7 OLD fleet, BEFORE the roll ──
# (the live order: nodus 0.24.1 voted HF-5, the fleet then rolls to a later
# build of the same D before H — decision 2026-10-06-hf5-evm-activation.md)
WHEN_LBL="before the vote"
if [ "$UPG_MODE" = voted-before ]; then
    evm_vote "$OLD_CLI"
    EVM_ROW=$(cc_row 1 "$PARAM_EVM" "$H")
    [ $(( $(ceil_of $(seq 1 "$N")) + 1 )) -lt "$H" ] || die "voted-before: H-1 was reached before the roll began (widen H_MARGIN)"
    vb_state "voted-before, OLD fleet after the vote"
    echo "[ok] voted-before: EVM_ACTIVE=$D_DEC voted by the OLD fleet with the OLD CLI at tip $T_VOTE, row committed at $R_VOTE, H=$H"
    WHEN_LBL="between the vote and H (rolled)"
fi

# ── 3. rolling upgrade, 7/7 after every step ────────────────────────
for k in $(seq 1 "$N"); do
    if [ "$UPG_MODE" = voted-before ]; then vb_roll_guard "$k"; fi
    upgrade_node "$k"
    if [ "$UPG_MODE" = voted-before ]; then vb_after_step "$k"; fi
done
for n in $(seq 1 "$N"); do node_runs "$n" "$NEW_SRV" || die "node$n is not on NEW after the rolling upgrade"; done
D2_LINE=$(d2_line_of 1)
[ -n "$D2_LINE" ] || die "node1 logged no D2 / git-commit line"
for n in $(seq 2 "$N"); do
    [ "$(d2_line_of "$n")" = "$D2_LINE" ] || die \
        "node$n's D2 / git-commit line differs from node1's: '$(d2_line_of "$n")' vs '$D2_LINE'"
done
H_UPGRADED=$(tip_of 1)
echo "[ok] all 7 nodes upgraded one at a time with no wipe; 7/7 agreed after every step (tip $H_UPGRADED)"
echo "[ok] 7/7 logged: $D2_LINE"

# ── 4. before the EVM vote: generation 2, the EVM closed ────────────
# (voted-before: the same checks, run after the roll and before H —
# WHEN_LBL names the phase; the S17 migration ran on OLD's first open)
for n in $(seq 1 "$N"); do
    require_gen "$NEW_CLI" "$n" "$GEN_BASE" "$H4"
    [ "$RI_SYS_H" = "$GEN2_SYS_H" ] && [ "$RI_CORE_H" = "$GEN2_CORE_H" ] \
        || die "node$n's generation-2 hashes on NEW differ from the OLD fleet's"
    m=$(sqlite3 "$(db_of "$n")" "SELECT COUNT(*) FROM evm_meta;" 2>/dev/null || echo ERR)
    r=$(sqlite3 "$(db_of "$n")" "SELECT reserve_raw FROM v2_evm_reserve WHERE id = 1;" 2>/dev/null || echo ERR)
    [ "$m" = 0 ] && [ "$r" = 0 ] || die "node$n $WHEN_LBL: evm_meta rows '$m', reserve '$r' (expected 0 / 0 — the S17 migration's empty state)"
done
evm_q 1 balance "$ADDR1"
[ "$EQ_RC" != 0 ] && [[ "$EQ_OUT" == *"evm_account failed (rc=2)"* ]] || {
    printf '%s\n' "$EQ_OUT" >&2; die "evm balance $WHEN_LBL was not refused with evm_account rc 2 (rc $EQ_RC)"; }
echo "[ok] REFUSED $WHEN_LBL: $EQ_OUT"
evm_tx 1 1 "$LOGD/deploy_pre_vote.log" deploy "$COUNTER_HEX" --gas "$GAS_DEPLOY"
[ "$EV_RC" != 0 ] && grep -q "smart contracts open with the EVM generation" "$LOGD/deploy_pre_vote.log" \
    || die "evm deploy $WHEN_LBL was not refused by the generation check (see $LOGD/deploy_pre_vote.log)"
[ -z "$EV_INTENT" ] || die "evm deploy $WHEN_LBL built an envelope"
echo "[ok] REFUSED $WHEN_LBL (CLI generation check): $(grep 'smart contracts open' "$LOGD/deploy_pre_vote.log")"
stagef_cmt_diff_at_floor "pre-evm-vote" || exit 2

# ── 5. the EVM_ACTIVE vote on 7/7 NEW (voted-after; voted-before voted at 2b) ──
if [ "$UPG_MODE" = voted-after ]; then
    evm_vote "$NEW_CLI"
else
    vb_state "voted-before, 7/7 NEW before H"
fi

[ $(( $(tip_of 1) + 1 )) -lt "$H" ] || die "node1's tip reached H-1 before the between-vote-and-H checks (widen H_MARGIN)"
for n in $(seq 1 "$N"); do require_gen "$NEW_CLI" "$n" "$GEN_BASE" "$H4"; done
evm_q 1 balance "$ADDR1"
[ "$EQ_RC" != 0 ] && [[ "$EQ_OUT" == *"evm_account failed (rc=2)"* ]] || {
    printf '%s\n' "$EQ_OUT" >&2; die "evm balance between the vote and H was not refused (rc $EQ_RC)"; }
[ $(( $(tip_of 1) + 1 )) -lt "$H" ] || die "node1's tip reached H-1 while the between-vote-and-H checks ran (widen H_MARGIN)"
echo "[ok] between the vote and H (tip $(tip_of 1)): 7/7 generation 2; evm_account still refused"

# ── 6. cross H: pumped to H-PUMP_STOP_GAP, then idle production ─────
pump_to 1 $(( H - PUMP_STOP_GAP ))
wait_all $(( H + 1 ))
stagef_sentinel TARGET_REACHED
for hh in $(( H - 1 )) "$H" $(( H + 1 )); do diff_at "$hh" "evm-at-height-$hh"; done
echo "[info] REPORTED: v2_blocks.tx_count at H-1/H/H+1 on node1 = $(sqlite3 "$(db_of 1)" \
    "SELECT group_concat(global_height || ':' || tx_count, ' ') FROM v2_blocks
      WHERE global_height BETWEEN $(( H - 1 )) AND $(( H + 1 ));" 2>/dev/null || echo '?')"
SWITCH_LINE="Nodus EVM: rule-set generation $GEN_BASE -> $GEN_EVM and the EVM domain registered ACTIVE at the end of height $(( H - 1 )) (D 0x$D_HEX)"
RH_SYS=""; RH_CORE=""
for n in $(seq 1 "$N"); do
    grep -qF "$SWITCH_LINE" "$(stagef_node_dir "$n")/nodus.log" \
        || die "node$n logged no '$SWITCH_LINE' line"
    s=$(rh_row "$n" "$DOM_SYSTEM" $(( H - 1 ))); c=$(rh_row "$n" "$DOM_CORE" $(( H - 1 )))
    [ -n "$s" ] && [ "$s" != ERR ] || die "node$n has no SYSTEM v2_root_history row at H-1=$(( H - 1 ))"
    [ -n "$c" ] && [ "$c" != ERR ] || die "node$n has no CORE v2_root_history row at H-1=$(( H - 1 ))"
    if [ -z "$RH_SYS" ]; then RH_SYS="$s"; RH_CORE="$c"
    else
        [ "$s" = "$RH_SYS" ] || die "node$n's SYSTEM root-history row at H-1 differs: $s vs $RH_SYS"
        [ "$c" = "$RH_CORE" ] || die "node$n's CORE root-history row at H-1 differs: $c vs $RH_CORE"
    fi
    sb=$(rh_below "$n" "$DOM_SYSTEM" $(( H - 1 ))); cb=$(rh_below "$n" "$DOM_CORE" $(( H - 1 )))
    [ "$sb" = "$GEN2_SYS_V|$GEN2_SYS_H" ] || die "node$n's last SYSTEM row below H-1 is '$sb', expected generation 2"
    [ "$cb" = "$GEN2_CORE_V|$GEN2_CORE_H" ] || die "node$n's last CORE row below H-1 is '$cb', expected generation 2"
done
[ "${RH_SYS%%|*}" -gt "$GEN2_SYS_V" ] || die "the SYSTEM row at H-1 names v${RH_SYS%%|*}, not above generation 2's v$GEN2_SYS_V"
[ "${RH_CORE%%|*}" -gt "$GEN2_CORE_V" ] || die "the CORE row at H-1 names v${RH_CORE%%|*}, not above generation 2's v$GEN2_CORE_V"
for n in $(seq 1 "$N"); do
    require_gen "$NEW_CLI" "$n" "$GEN_EVM" "$H4"
    s="${RH_SYS#*|}"; c="${RH_CORE#*|}"
    [ "$RI_SYS_V|$RI_SYS_H" = "${RH_SYS%%|*}|${s%%|*}" ] || die "node$n's ruleset-info SYSTEM differs from the H-1 root-history row"
    [ "$RI_CORE_V|$RI_CORE_H" = "${RH_CORE%%|*}|${c%%|*}" ] || die "node$n's ruleset-info CORE differs from the H-1 root-history row"
done
require_evm_same "post-activation"
require_supply "post-activation" 0 0 0
echo "[ok] 7/7 switched to generation $GEN_EVM at the end of H-1=$(( H - 1 )) (D 0x$D_HEX = the vote's value):"
echo "     SYSTEM v${RH_SYS%%|*} / CORE v${RH_CORE%%|*}; blocks AT H-1/H/H+1 identical; EVM domain empty and identical"

# ── 7. bridge in: deposit ───────────────────────────────────────────
NFP1=$(fp_lc "$(node_keys 1)"); NFP2=$(fp_lc "$(node_keys 2)")
evm_tx 1 1 "$LOGD/deposit.log" deposit "$D_RAW"
evm_tx_ok "evm deposit" "$LOGD/deposit.log"
I_DEP="$EV_INTENT"
wait_receipt 1 "$I_DEP" "evm deposit"
require_rcpt "$I_DEP" 01 "$OP_DEPOSIT" "evm deposit"
WEI_DEP=$(printf '%s*%s\n' "$D_RAW" "$Q" | BC)
for n in $(seq 1 "$N"); do
    b=$(evm_balance_of "$n" "$ADDR1")
    [ "$b" = "$WEI_DEP" ] || die "node$n's evm_account says node1 holds '$b' wei, expected $WEI_DEP"
done
require_evm_same "post-deposit"
require_supply "post-deposit" "$D_RAW" "$WEI_DEP" 0
stagef_cmt_diff_at_floor "post-deposit" || exit 2
echo "[ok] deposit of $D_RAW raw applied at $RC_H: node1 holds $WEI_DEP wei on every node's RPC"

# ── 8. deploy + call ────────────────────────────────────────────────
evm_tx 1 1 "$LOGD/deploy_counter.log" deploy "$COUNTER_HEX" --gas "$GAS_DEPLOY"
evm_tx_ok "evm deploy Counter" "$LOGD/deploy_counter.log"
I_DEPLOY="$EV_INTENT"
wait_receipt 1 "$I_DEPLOY" "evm deploy Counter"
require_rcpt "$I_DEPLOY" 01 "$OP_CREATE" "evm deploy Counter"
COUNTER="${RCPT##*|}"
[ "${#COUNTER}" = 64 ] && [ "$COUNTER" != "$(printf '%064d' 0)" ] || die "the Counter receipt names no created address ('$COUNTER')"
for n in $(seq 1 "$N"); do
    c=$(sqlite3 "$(db_of "$n")" "SELECT COUNT(*) FROM evm_code k JOIN evm_accounts a ON a.code_digest = k.digest
                                  WHERE lower(hex(a.addr)) = '$COUNTER' AND a.code_size > 0;" 2>/dev/null || echo ERR)
    [ "$c" != ERR ] && [ "$c" -ge 1 ] || die "node$n holds no evm_code row for the Counter at 0x$COUNTER"
done
echo "[ok] Counter deployed at 0x$COUNTER (height $RC_H), code stored on 7/7"

for i in 1 2; do
    evm_tx 1 1 "$LOGD/increment_$i.log" send "$COUNTER" "increment()" --gas "$GAS_SEND"
    evm_tx_ok "increment $i" "$LOGD/increment_$i.log"
    eval "I_INC$i=\$EV_INTENT"
    wait_receipt 1 "$EV_INTENT" "increment $i"
    require_rcpt "$EV_INTENT" 01 "$OP_CALL" "increment $i"
    eval "R_INC$i=\$RC_H"
done
require_call_all "$COUNTER" "get()(uint256)" 2
# the second increment's log, through every node's evm_logs RPC
# (nodus-cli.c cmd_evm logs: "h=%llu x=%u li=%u address=0x<64> tx=<128>",
#  "  topic%u 0x<64>", "%zu log(s)…")
for n in $(seq 1 "$N"); do
    evm_q "$n" logs --from-height "$R_INC2" --to-height "$R_INC2" --address "$COUNTER"
    [ "$EQ_RC" = 0 ] || { printf '%s\n' "$EQ_OUT" >&2; die "evm logs on node$n exited $EQ_RC"; }
    [[ "$EQ_OUT" == *"h=$R_INC2 "*" address=0x$COUNTER tx=$I_INC2"* ]] || {
        printf '%s\n' "$EQ_OUT" >&2; die "evm logs on node$n does not return the increment's log at $R_INC2"; }
    [[ "$EQ_OUT" == *"  topic0 0x$INCR_TOPIC"* && "$EQ_OUT" == *"  topic1 0x$ADDR1"* ]] || {
        printf '%s\n' "$EQ_OUT" >&2; die "node$n's increment log carries other topics than Incremented(node1)"; }
    [[ "$EQ_OUT" == *"1 log(s)"* ]] || { printf '%s\n' "$EQ_OUT" >&2; die "node$n returns more than one log at $R_INC2"; }
done
# `evm receipt` (the client SDK re-checks the digest; nodus-cli.c
# evm_print_receipt, labelled since red-team 1 F11: "receipt (as reported by
# the connected node; not proven against the chain): CALL SUCCEEDED,
# included at height … item …", "  receipt digest (Data, matches the fields
# above — not checked against the chain): <128>")
evm_q 1 receipt "$I_INC2"
[ "$EQ_RC" = 0 ] || { printf '%s\n' "$EQ_OUT" >&2; die "evm receipt of increment 2 exited $EQ_RC"; }
dg=$(sqlite3 "$(db_of 1)" "SELECT lower(hex(digest)) FROM evm_receipts WHERE lower(hex(intent_id)) = '$I_INC2';")
[[ "$EQ_OUT" == *"): CALL SUCCEEDED, included at height $R_INC2 "* && "$EQ_OUT" == *"against the chain): $dg"* ]] || {
    printf '%s\n' "$EQ_OUT" >&2; die "evm receipt does not report the stored receipt (height $R_INC2, digest ${dg:0:16}...)"; }
echo "[ok] increment x2 applied ($R_INC1, $R_INC2); get() = 2 on 7/7; the log and the receipt (digest re-derived) agree"

# the BLOCK GASLIMIT the environment carries (design §10) — printed, not assumed
GASLIMIT=""
for n in $(seq 1 "$N"); do
    g=$(evm_call_u256 "$n" "$COUNTER" "gasLimitNow()(uint256)")
    [[ "$g" =~ ^[0-9]+$ ]] && [ "$g" -gt 0 ] || die "gasLimitNow() on node$n returned '$g'"
    if [ -z "$GASLIMIT" ]; then GASLIMIT="$g"
    elif [ "$g" != "$GASLIMIT" ]; then die "gasLimitNow() differs: node$n $g vs $GASLIMIT"; fi
done
echo "[info] block GASLIMIT (EVM_BLOCK_GAS_LIMIT in force) = $GASLIMIT on 7/7"

# a REVERTING call is APPLIED (design §4): nonce + 1, fee paid, state unchanged
NONCE_B=$(nonce_of 1 "$ADDR1"); SUM_B=$(native_sum 1 "$NFP1")
evm_tx 1 1 "$LOGD/boom.log" send "$COUNTER" "boom()" --gas "$GAS_SEND" --force
evm_tx_ok "boom() --force" "$LOGD/boom.log"
grep -q "the call FAILS" "$LOGD/boom.log" && grep -q '"boom"' "$LOGD/boom.log" \
    || die "the simulation did not show the revert reason \"boom\" (see $LOGD/boom.log)"
I_BOOM="$EV_INTENT"; FEE_BOOM="$EV_FEE"
wait_receipt 1 "$I_BOOM" "boom()"
require_rcpt "$I_BOOM" 00 "$OP_CALL" "boom()"
r="${RCPT#*|}"; r="${r#*|}"
[ "${r%%|*}" = "$(printf '%016X' "$GAS_SEND")" ] || die "the failed receipt's evm_gas_used is 0x${r%%|*}, expected the whole gas_limit $GAS_SEND (design §4)"
wait_all $(( RC_H + 1 ))
for n in $(seq 1 "$N"); do
    [ "$(nonce_of "$n" "$ADDR1")" = $(( NONCE_B + 1 )) ] || die "node$n: node1's EVM nonce is $(nonce_of "$n" "$ADDR1"), expected $(( NONCE_B + 1 )) after the failed call"
done
SUM_A=$(native_sum 1 "$NFP1")
[ $(( SUM_B - SUM_A )) = "$FEE_BOOM" ] || die "node1's native coins moved by $(( SUM_B - SUM_A )), expected exactly the fee $FEE_BOOM"
require_call_all "$COUNTER" "get()(uint256)" 2
require_evm_same "post-revert"
stagef_cmt_diff_at_floor "post-revert" || exit 2
echo "[ok] boom() FAILED and was APPLIED at $RC_H: nonce $NONCE_B -> $(( NONCE_B + 1 )), fee $FEE_BOOM paid, gas_used = gas_limit, count still 2"
echo "     revert reason shown: $(grep -A1 'revert: Error(string)' "$LOGD/boom.log" | tail -1)"

# ── 9. two senders in flight together; an over-cap request ──────────
evm_tx 1 1 "$LOGD/pair_node1.log" send "$COUNTER" "increment()" --gas "$GAS_SEND"
evm_tx_ok "pair: node1 increment" "$LOGD/pair_node1.log"
I_PA="$EV_INTENT"; G_PA="$EV_GAS"
evm_tx 2 2 "$LOGD/pair_node2.log" send "$COUNTER" "increment()" --gas "$GAS_SEND"
evm_tx_ok "pair: node2 increment" "$LOGD/pair_node2.log"
I_PB="$EV_INTENT"; G_PB="$EV_GAS"
wait_receipt 1 "$I_PA" "pair: node1 increment"; R_PA="$RC_H"
wait_receipt 1 "$I_PB" "pair: node2 increment"; R_PB="$RC_H"
require_rcpt "$I_PA" 01 "$OP_CALL" "pair: node1 increment"
require_rcpt "$I_PB" 01 "$OP_CALL" "pair: node2 increment"
echo "[info] REPORTED: node1's increment at $R_PA, node2's at $R_PB (same block only if PrepareProposal saw both)"
for hh in $(printf '%s\n%s\n' "$R_PA" "$R_PB" | sort -u); do
    decl=0
    [ "$R_PA" = "$hh" ] && decl=$(( decl + G_PA ))
    [ "$R_PB" = "$hh" ] && decl=$(( decl + G_PB ))
    used=$(sqlite3 "$(db_of 1)" "SELECT hex(substr(receipt,19,8)) FROM evm_receipts WHERE global_height = $hh;" \
           | while read -r x; do printf '%d\n' "$(( 16#$x ))"; done | awk '{s += $1} END {print s + 0}')
    [ "$decl" -le "$GASLIMIT" ] && [ "$used" -le "$GASLIMIT" ] \
        || die "height $hh: declared gas $decl / used $used exceed the block GASLIMIT $GASLIMIT"
    echo "[ok] height $hh: these legs' declared gas $decl, receipts' evm_gas_used $used <= GASLIMIT $GASLIMIT"
done
require_call_all "$COUNTER" "get()(uint256)" 4
NONCE2_B=$(nonce_of 1 "$ADDR2")
NRCPT_B=$(sqlite3 "$(db_of 1)" "SELECT COUNT(*) FROM evm_receipts;")
evm_tx 2 2 "$LOGD/over_cap.log" send "$COUNTER" "increment()" --gas "$GAS_OVER_CAP"
[ "$EV_RC" != 0 ] || die "a send with --gas $GAS_OVER_CAP exited 0"
[ -z "$EV_INTENT" ] && ! grep -q '^accepted:' "$LOGD/over_cap.log" \
    || die "a send with --gas $GAS_OVER_CAP built or submitted an envelope (see $LOGD/over_cap.log)"
t=$(tip_of 1)
pump_to 1 $(( t + 3 ))
wait_all $(( t + 3 ))
[ "$(nonce_of 1 "$ADDR2")" = "$NONCE2_B" ] || die "node2's EVM nonce moved after the refused over-cap request"
[ "$(sqlite3 "$(db_of 1)" "SELECT COUNT(*) FROM evm_receipts;")" = "$NRCPT_B" ] || die "a receipt appeared after the refused over-cap request"
require_evm_same "post-pair"
stagef_cmt_diff_at_floor "post-pair" || exit 2
echo "[ok] both senders applied; get() = 4 on 7/7; --gas $GAS_OVER_CAP REFUSED before any envelope ($(grep -m1 'failed' "$LOGD/over_cap.log" || true)) — nothing landed"

# ── 10. bridge out: withdraw, a contract ticket, redeem ─────────────
REL_W_B=$(rel_count 1 "$NFP2" "$W_RAW")
evm_tx 1 1 "$LOGD/withdraw.log" withdraw "$W_RAW" --to "$(fp_of "$(node_keys 2)")"
evm_tx_ok "evm withdraw" "$LOGD/withdraw.log"
I_WD="$EV_INTENT"
wait_receipt 1 "$I_WD" "evm withdraw"
require_rcpt "$I_WD" 01 "$OP_WITHDRAW" "evm withdraw"
for n in $(seq 1 "$N"); do
    [ "$(rel_count "$n" "$NFP2" "$W_RAW")" = $(( REL_W_B + 1 )) ] \
        || die "node$n holds no new index-$REL_INDEX release coin of $W_RAW raw for node2"
done
WEI_LIVE=$(printf '(%s-%s)*%s\n' "$D_RAW" "$W_RAW" "$Q" | BC)
require_supply "post-withdraw" $(( D_RAW - W_RAW )) "$WEI_LIVE" 0
require_evm_same "post-withdraw"
echo "[ok] withdraw of $W_RAW raw applied at $RC_H: node2's release coin on 7/7, reserve $(( D_RAW - W_RAW ))"

evm_tx 1 1 "$LOGD/deploy_ticketer.log" deploy "$TICKETER_HEX" --gas "$GAS_DEPLOY"
evm_tx_ok "evm deploy Ticketer" "$LOGD/deploy_ticketer.log"
wait_receipt 1 "$EV_INTENT" "evm deploy Ticketer"
require_rcpt "$EV_INTENT" 01 "$OP_CREATE" "evm deploy Ticketer"
TICKETER="${RCPT##*|}"
[ "${#TICKETER}" = 64 ] && [ "$TICKETER" != "$(printf '%064d' 0)" ] || die "the Ticketer receipt names no created address"
T_WEI=$(printf '%s*%s\n' "$T_RAW" "$Q" | BC)
evm_tx 1 1 "$LOGD/open_ticket.log" send "$TICKETER" "openTicket(address,bytes)" "$SYS_ADDR" "$NFP2" \
    --value "$T_WEI" --gas "$GAS_TICKET"
evm_tx_ok "openTicket" "$LOGD/open_ticket.log"
I_TK="$EV_INTENT"
wait_receipt 1 "$I_TK" "openTicket"
require_rcpt "$I_TK" 01 "$OP_CALL" "openTicket"
TICKET=$(sqlite3 "$(db_of 1)" "SELECT lower(hex(ticket_id)) FROM evm_tickets;")
[ "${#TICKET}" = 128 ] || die "node1 holds no single evm_tickets row after openTicket ('$TICKET')"
for n in $(seq 1 "$N"); do
    row=$(sqlite3 "$(db_of "$n")" "SELECT lower(hex(ticket_id)) || '|' || amount_raw || '|' || lower(hex(dest_fp)) FROM evm_tickets;")
    [ "$row" = "$TICKET|$T_RAW|$NFP2" ] || die "node$n's ticket row is '$row', expected '$TICKET|$T_RAW|$NFP2'"
done
evm_q 1 receipt "$I_TK"
[ "$EQ_RC" = 0 ] && [[ "$EQ_OUT" == *"  withdrawal ticket: $TICKET"* ]] || {
    printf '%s\n' "$EQ_OUT" >&2; die "the openTicket receipt does not name the ticket $TICKET"; }
WEI_LIVE=$(printf '(%s-%s-%s)*%s\n' "$D_RAW" "$W_RAW" "$T_RAW" "$Q" | BC)
require_supply "post-ticket" $(( D_RAW - W_RAW )) "$WEI_LIVE" "$T_WEI"
require_evm_same "post-ticket"
echo "[ok] Ticketer at 0x$TICKETER opened ticket ${TICKET:0:16}... ($T_RAW raw -> node2) at $RC_H, identical on 7/7"

REL_T_B=$(rel_count 1 "$NFP2" "$T_RAW")
evm_tx 1 1 "$LOGD/redeem.log" redeem "$TICKET"
evm_tx_ok "evm redeem" "$LOGD/redeem.log"
I_RD="$EV_INTENT"
wait_receipt 1 "$I_RD" "evm redeem"
require_rcpt "$I_RD" 01 "$OP_REDEEM" "evm redeem"
for n in $(seq 1 "$N"); do
    [ "$(rel_count "$n" "$NFP2" "$T_RAW")" = $(( REL_T_B + 1 )) ] \
        || die "node$n holds no new index-$REL_INDEX release coin of $T_RAW raw for node2 after the redeem"
    [ "$(sqlite3 "$(db_of "$n")" "SELECT COUNT(*) FROM evm_tickets;")" = 0 ] || die "node$n still holds the redeemed ticket"
done
require_supply "post-redeem" $(( D_RAW - W_RAW - T_RAW )) "$WEI_LIVE" 0
for n in $(seq 1 "$N"); do
    b=$(evm_balance_of "$n" "$ADDR1")
    [ "$b" = "$WEI_LIVE" ] || die "node$n's evm_account says node1 holds '$b' wei, expected $WEI_LIVE"
done
require_evm_same "post-redeem"
stagef_cmt_diff_at_floor "post-redeem" || exit 2
echo "[ok] redeem applied at $RC_H: node2's second release coin ($T_RAW raw) on 7/7, ticket gone, reserve $(( D_RAW - W_RAW - T_RAW ))"

# ── 11. restart across H (kill -9) ──────────────────────────────────
k="$RESTART_VICTIM"; vlog="$(stagef_node_dir "$k")/nodus.log"
chain_before=$(basename "$(db_of "$k")")
role0=$(grep -c 'chain role: COMETBFT' "$vlog" || true)
hsdone0=$(grep -c 'completed ABCI handshake' "$vlog" || true)
stagef_cmt_diff_at_floor "pre-kill-node$k" || exit 2
base=$(floor_of $(seq 1 "$N"))
stop_node "$k" KILL
start_node "$k" "$NEW_SRV"
node_runs "$k" "$NEW_SRV" || die "node$k's process is not the NEW binary after the kill -9 restart"
wait_log_delta "$vlog" 'chain role: COMETBFT' "$role0" "node$k did not re-establish the COMETBFT role after kill -9"
wait_log_delta "$vlog" 'completed ABCI handshake' "$hsdone0" "node$k did not complete a NEW ABCI handshake after kill -9"
[ "$(basename "$(db_of "$k")")" = "$chain_before" ] || die "node$k came back on a DIFFERENT chain file after kill -9"
fleet=$(tip_of 1)
stagef_cmt_wait_height "$(db_of "$k")" "$fleet" 3 >/dev/null \
    || die "node$k did not catch up to the fleet tip $fleet after kill -9"
pump_to 1 $(( fleet + 2 ))
wait_all $(( fleet + 2 ))
[ "$(floor_of $(seq 1 "$N"))" -gt "$base" ] || die "the floor did not move past $base after node$k's restart"
stagef_cmt_diff_at_floor "post-kill-node$k" || exit 2
require_evm_same "post-kill-node$k"
require_gen "$NEW_CLI" "$k" "$GEN_EVM" "$H4"
echo "[ok] node$k kill -9'd after H, restarted on its own chain file, caught up; 7/7 agree and its EVM state equals the fleet's"

# ── 12. pinned rejoin across H (wipe + pin, test_v2_join.sh's wipe) ──
k="$JOIN_VICTIM"; nd=$(stagef_node_dir "$k")
fleet_gid=$(basename "$(db_of 1)")
stagef_cmt_diff_at_floor "pre-wipe-node$k" || exit 2
stop_node "$k" KILL
rm -f "$nd/data/"*.db "$nd/data/"*.db-wal "$nd/data/"*.db-shm \
      "$nd/data/.witness_db_seen" "$nd/data/.bootstrap_in_progress" \
      "$nd/data/.recovery_in_progress"
rm -rf "$nd/data/archive"
: > "$nd/nodus.log"
if ls "$nd/data/"witness_*.db >/dev/null 2>&1; then die "the wipe did not remove node$k's chain DB"; fi
echo "[ok] node$k wiped (identity kept, databases gone, log truncated)"
start_node "$k" "$NEW_SRV" --v2-genesis-pin "$PIN"
adopted=0; gid=""
for _ in $(seq 1 120); do
    if ls "$nd/data/"witness_*.db >/dev/null 2>&1; then
        gid=$(basename "$(db_of "$k")" 2>/dev/null || true)
        [ -n "$gid" ] && { adopted=1; break; }
    fi
    sleep 1
done
[ "$adopted" = 1 ] || die "node$k never adopted a chain after the pinned restart"
[ "$gid" = "$fleet_gid" ] || die "node$k adopted a DIFFERENT chain: $gid vs the fleet's $fleet_gid"
role_ok=0; live_ok=0
for _ in $(seq 1 30); do
    grep -q 'chain role: COMETBFT' "$nd/nodus.log" && role_ok=1
    grep -q 'cometbft lane LIVE' "$nd/nodus.log" && live_ok=1
    [ "$role_ok" = 1 ] && [ "$live_ok" = 1 ] && break
    sleep 1
done
[ "$role_ok" = 1 ] && [ "$live_ok" = 1 ] || die \
    "node$k has the chain but never reported COMETBFT role + lane LIVE (role=$role_ok live=$live_ok)"
fleet=$(tip_of 1)
stagef_cmt_wait_height "$(db_of "$k")" "$fleet" 3 >/dev/null \
    || die "node$k adopted but did not catch up to the fleet tip $fleet (replaying across H4=$H4 and H=$H)"
grep -q "rule-set generation 1 -> 2 at the end of height $(( H4 - 1 )) " "$nd/nodus.log" \
    || die "node$k's replay logged no 'rule-set generation 1 -> 2 at the end of height $(( H4 - 1 ))' line"
grep -qF "$SWITCH_LINE" "$nd/nodus.log" || die "node$k's replay logged no '$SWITCH_LINE' line"
[ "$(rh_row "$k" "$DOM_SYSTEM" $(( H - 1 )))" = "$RH_SYS" ] || die "node$k's replayed SYSTEM root-history row at H-1 differs"
[ "$(rh_row "$k" "$DOM_CORE" $(( H - 1 )))" = "$RH_CORE" ] || die "node$k's replayed CORE root-history row at H-1 differs"
require_gen "$NEW_CLI" "$k" "$GEN_EVM" "$H4"
for hh in $(( H - 1 )) "$H" $(( H + 1 )); do diff_at "$hh" "rejoined-at-height-$hh"; done
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
wait_all $(( t + 2 ))
require_evm_same "rejoined-node$k"
require_call_all "$COUNTER" "get()(uint256)" 4
echo "[ok] node$k rejoined by pin, replayed genesis -> tip $(tip_of "$k") through both switches and every EVM block; its EVM state and receipt index equal the fleet's"

for n in $(seq 1 "$N"); do node_runs "$n" "$NEW_SRV" || die "node$n is not running NEW at the end"; done
require_supply "end" $(( D_RAW - W_RAW - T_RAW )) "$WEI_LIVE" 0

stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-evm" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 H2=$H2 (row $R_V2) | HF3 H3=$H3 (row $R_V3) | GEN2 H4=$H4 (row $R_V4) | upgraded-by $H_UPGRADED"
echo "       | EVM vote tip $T_VOTE, row commit $R_VOTE, H=$H (second proposal effective $H_2ND refused) | D 0x$D_HEX"
echo "       | Counter 0x$COUNTER, Ticketer 0x$TICKETER, GASLIMIT $GASLIMIT"
if [ "$UPG_MODE" = voted-before ]; then
echo "       | mode voted-before: roll steps measured <= $VB_STEP_MAX block(s) each (charged >= $ROLL_STEP_BLOCKS)"
echo "[PASS] Nodus EVM (STAGEF_EVM_UPGRADE_MODE=voted-before): HF-2 + HF-3 + generation 2 on OLD ($OLD_VER);"
echo "       EVM_ACTIVE (D 0x$D_HEX, the same literal in both CLIs) voted by the OLD fleet at H=$H (a second"
echo "       vote refused); 7 nodes rolled OLD -> NEW ($NEW_VER) one at a time BEFORE H-1 with the row identical"
echo "       and generation $GEN_BASE on 7/7 after every step; the NEW fleet switched to generation $GEN_EVM at the"
echo "       end of H-1 with 7/7 identical blocks AT H-1/H/H+1; deposit, deploy, calls, an applied revert, two"
echo "       senders, withdraw, a contract ticket and its redeem identical on 7/7 with the supply invariant;"
echo "       kill -9 and wipe + pin replay (through the OLD-voted block) converge."
echo "       E=15 / grace 15 — the LOGIC only; the CheckTx block-gas refusal is NOT exercised (header)."
else
echo "[PASS] Nodus EVM: HF-2 + HF-3 + generation 2 on OLD ($OLD_VER), 7 nodes rolled OLD -> NEW ($NEW_VER)"
echo "       one at a time; EVM_ACTIVE voted at H=$H (a second vote refused), the fleet switched to"
echo "       generation $GEN_EVM at the end of H-1 with 7/7 identical blocks AT H-1/H/H+1; deposit, deploy,"
echo "       calls, an applied revert, two senders, withdraw, a contract ticket and its redeem identical"
echo "       on 7/7 with the supply invariant; kill -9 and wipe + pin replay converge."
echo "       E=15 / grace 15 — the LOGIC only; the CheckTx block-gas refusal is NOT exercised (header)."
fi
