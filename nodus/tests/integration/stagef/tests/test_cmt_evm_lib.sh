#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_evm_lib.sh — the Nodus security contract library v0.1 ON A
# CHAIN: a MultisigVault paying a Nodus account through a withdrawal
# ticket (redeemed to a native coin), a Timelock whose delay is judged in
# BLOCK time, and a MilestoneEscrow settled milestone by milestone — all
# deployed from the COMMITTED bytecode of nodus/tools/evm/contracts/out/
# default/, on a fresh 7-node chain climbed to the EVM generation
# (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/2026-10-21-nodus-contract-library-design.md
# rev 3 (§0 Nodus facts — the ticket exit, q = 10^10 wei, block.timestamp
# = committed block seconds; §5 "Not covered here … REDEEM of a ticket,
# the chain fee path" — the gap this scenario covers);
# docs/plans/decisions/2026-10-21-kurultay-30-summary.md (choices 1-5; the
# ticket exit is "the biggest correction"); the library's own README
# (nodus/tools/evm/contracts/README.md, "Getting value out of a
# contract"). TEMPLATES: test_cmt_hf8_gen5.sh — its gate, its vote helpers
# (cc_guard / propose / wait_cc_row / ruleset_info / require_gen /
# cross_edge) and its generation 1 -> 2 -> 3 climb on ONE build of the
# tree, stopped at the EVM edge; test_cmt_evm.sh — its EVM helpers
# (evm_tx / wait_receipt / require_rcpt / evm_dump / require_supply) and
# its Ticketer fixture. Every new part is marked "lib:".
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): one version banner for the server and the
#      CLI; the CLI's chain-config usage names "EVM_ACTIVE exactly <D>";
#      its `evm address --keys` prints one 32-byte address offline. The
#      three library creation files and the Ticketer fixture are tracked
#      by git and UNMODIFIED against HEAD (`git diff --quiet HEAD`): the
#      bytes deployed below are the committed ones (no solc at test time).
#   1. Fresh chain (no param 7 / 8 / 9 / 14 row); nodes 1, 2, 3 claim
#      their leaves (the pump runs on node 5's leaf).
#   2. HF2_ACTIVE, HF3_ACTIVE, RULESET_GEN2 and EVM_ACTIVE voted and
#      crossed (test_cmt_hf8_gen5.sh's path, stopped at generation 3):
#      each row identical 7/7 and committed below its effective height;
#      stagef_cmt_diff_at_floor 7/7 after HF-2 and HF-3; blocks AT H−1 / H
#      / H+1 identical 7/7 at the generation-2 and the EVM edge; every
#      node logged the EVM switch line with the CLI's D; ruleset-info 7/7
#      = generation 3.
#   3. `evm deposit DEP_RAW` by nodes 1, 2 and 3: receipts status 1 op
#      DEPOSIT; each EVM balance DEP_RAW x 10^10 wei on 7/7; the supply
#      invariant with exact values on 7/7.
#   4. lib: the Ticketer fixture is deployed (status 1, op CREATE) and
#      ends with balance 0. It USED to be the value forwarder; the vault
#      and the timelock are now funded with the CLI's plain value transfer
#      (`evm send <address> --value <wei>`, empty calldata = receive()).
#      Kept only so every earlier assertion stays (HOW IT CAN LIE).
#   5. lib: MultisigVault — `evm encode --ctor "(address[],uint256)"`
#      equals this script's independently hand-built constructor words (see
#      "CONSTRUCTOR ENCODING"); then deployed by node 1 with `evm deploy
#      <creation hex> --args "(address[],uint256)" "[a1,a2,a3]" 2` (owners =
#      the EVM addresses of nodes 1, 2, 3, threshold 2); the decoding is
#      proven on chain: isOwner(node 1/2/3) = true, isOwner(node 4) =
#      false, threshold() = 2, proposalCount() = 0; its code on 7/7 = the
#      committed out/default/MultisigVault.runtime.hex byte for byte.
#      Funded with VAULT_FUND by node 1's plain value transfer (`evm send
#      <vault> --value`): the vault holds exactly that, node 1 lost exactly
#      that (7/7).
#      Node 1 submits proposal 0 = (ticket address, PAY_RAW x 10^10 wei,
#      calldata = node 4's 64-byte fingerprint): getProposal(0) reads back
#      exactly that with 1 approval, not executed.
#      NEGATIVE: node 1's execute(0) with one approval, sent with --force,
#      is APPLIED with receipt status 0 (the simulation's revert data ends
#      with the words (0, 1, 2) = VaultBelowThreshold's arguments — the
#      selector itself is not checked, HOW IT CAN LIE); the vault's
#      balance, the evm_tickets table and getProposal(0) (1 approval, not
#      executed) are unchanged.
#      Node 2 approves (2 approvals); node 3 — the third owner; execute is
#      owner-only — executes: status 1; ONE evm_tickets row on 7/7 =
#      (amount PAY_RAW, dest node 4), named by the receipt's "withdrawal
#      ticket:" line; the vault's balance fell by exactly PAY_RAW x 10^10;
#      proposal 0 executed; the supply invariant moves PAY_RAW x 10^10
#      from wei_live to wei_tickets (7/7). `evm redeem <ticket>` (node 1
#      pays the fee): status 1 op REDEEM; node 4 holds one NEW index-101
#      native coin of exactly PAY_RAW on 7/7; the ticket row is gone; the
#      reserve fell by PAY_RAW.
#   6. lib: Timelock, part 1 — `evm encode --ctor` = the hand-built words;
#      deployed by node 1 with `--args "(uint256,address[],address[],
#      address[])"` minDelay TL_DELAY, proposers = executors = [node 1],
#      cancellers = [] (the empty array "[]"): getMinDelay() = TL_DELAY,
#      hasRole(PROPOSER / EXECUTOR, node 1) = true, hasRole(CANCELLER,
#      node 1) = false; code = the committed runtime on 7/7; funded with
#      TL_FUND by node 1's plain value transfer. Node 1 schedules
#      (node 2's EVM address, TL_PAY_RAW x 10^10 wei, empty data, SALT,
#      TL_DELAY); hashOperation(...) gives the id; getOperationState(id) =
#      1 (Pending); READY = getReadyTime(id) and T_CHAIN = READY −
#      TL_DELAY is the schedule block's block.timestamp — the ONLY chain
#      clock this script reads (no CLI verb prints a block time).
#      NEGATIVE: an execute before READY, sent with --force, is APPLIED
#      with status 0 (its simulation's revert data ends with (id, READY) =
#      TimelockNotReady's arguments); node 2's and the timelock's balances
#      and the state (Pending) are unchanged.
#   7. lib: MilestoneEscrow — `evm encode --ctor` = the hand-built words;
#      deployed with `--args "(address,address,address,uint256[],uint256)"`
#      payer node 1, payee node 2, arbiter node 3,
#      milestones (M0_RAW, M1_RAW) x 10^10 wei, deadline = T_CHAIN +
#      ESCROW_WINDOW_S (block time, never the wall clock); on chain:
#      parties() = (1, 2, 3), total() = the sum, milestoneCount() = 2,
#      milestone(i) = (amount, 0), deadline() = the deadline, funded() =
#      false; code = the committed runtime on 7/7. Node 1 fund()s the exact
#      sum: funded() true, the escrow holds the sum, node 1 lost it.
#      NEGATIVE: node 2's fund() with the same value, --force: status 0
#      (revert data ends with node 2's address = EscrowUnauthorized's
#      argument), balances and funded() unchanged.
#      Node 1 release(0): milestone(0) = (M0, Released=1), creditOf(node 2)
#      = M0. NEGATIVE: node 1's second release(0), --force: status 0
#      (revert data ends with (0, 1) = EscrowAlreadySettled's arguments),
#      the milestone and the credit unchanged.
#      Node 2 withdraw(): node 2's EVM balance rises by exactly M0, the
#      escrow's falls by M0, creditOf(node 2) = 0. Node 3 resolve(1,
#      false): milestone(1) = (M1, Refunded=2), creditOf(node 1) = M1;
#      node 1 withdraw(): node 1 rises by exactly M1; the escrow holds 0;
#      accounting() = (0, 0, sum).
#      Node 2 `evm withdraw W_RAW` (to itself): status 1 op WITHDRAW; one
#      NEW index-101 native coin of W_RAW for node 2 on 7/7; node 2's EVM
#      balance fell by W_RAW x 10^10; the reserve fell by W_RAW.
#   8. lib: Timelock, part 2 — the chain is advanced ONE BLOCK AT A TIME
#      (idle production, stagef_cmt_wait_height) until a simulated
#      execute at the tip succeeds (the node simulates at the TIP's block
#      time, nodus_witness_handlers.c handle_evm_call
#      nodus_witness_v2_tip_block_time; every refusal on the way must be
#      TimelockNotReady's (id, READY)); then node 1's execute: status 1,
#      node 2's balance rises by exactly TL_PAY, the timelock's falls by
#      it, getOperationState(id) = 2 (Done).
#   9. The whole EVM state (+ receipt / log index) identical on 7/7; the
#      supply invariant wei_live + wei_tickets + wei_lost == 10^10 x
#      reserve_raw with the exact values on 7/7 after every bridge step
#      and at the end; stagef_cmt_diff_at_floor 7/7 at the end.
#
# CONSTRUCTOR ENCODING (lib:) — the contracts are deployed with the CLI's
#   own encoder: `evm deploy <creation hex> --args "(T…)" v…`, an array
#   given as ONE argument "[v1,v2,...]" ("[]" = empty; nodus-cli.c
#   evm_abi_type / evm_abi_array). As an independent cross-check, this
#   script ALSO hand-builds each constructor's words (Solidity ABI spec,
#   "Formal Specification of the Encoding": a head of one word per
#   argument — a static value, or for an array the byte offset of its tail
#   from the start of the arguments — then each array's tail = its length
#   word and its elements) and requires `evm encode --ctor "(T…)" v…`
#   (offline, no selector) to print exactly those words:
#     MultisigVault(address[] owners, uint256 threshold)
#       [0x40][2][3][addr1][addr2][addr3]
#     MilestoneEscrow(address payer, address payee, address arbiter,
#                     uint256[] amounts, uint256 deadline)
#       [addr1][addr2][addr3][0xa0][deadline][2][m0][m1]
#     Timelock(uint256 minDelay, address[] proposers, address[] executors,
#              address[] cancellers)
#       [TL_DELAY][0x80][0xc0][0x100][1][addr1][1][addr1][0]
#   Every word is 32 bytes; a Nodus address fills all 32. The views in
#   steps 5-7 are the on-chain proof that each contract decoded them.
#
# WHAT IT REQUIRES
#   Compile flags — ONE short-epoch + short-grace build of THIS tree,
#   nodus-server AND nodus-cli from the SAME build dir, with
#   NODUS_EVM_ENABLED (the standalone non-Windows default,
#   nodus/CMakeLists.txt):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9 ERGONOMIC, param 14 SAFETY — dnac.h). No TEST-OWNER
#   flags: the climb stops before HF-6.
#   Environment, exported BEFORE stagef_up_v2.sh unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     read by THIS script only:
#       STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#   The script SETS STAGEF_PUMP_FUNDER_NODE=5 before sourcing stagef_env.sh
#   (the default funder, node 3, is an EVM user here; an exported value is
#   overridden). Leave STAGEF_PAYOUT_INTERVAL_EPOCHS and STAGEF_MODE unset.
#   Tools: sqlite3, bc, xxd, openssl with SHA3-512, ss, git (the
#   committed-bytes check). NO solc: the library's out/default/ and the
#   stagef fixture fixtures/evm/Ticketer.hex are committed bytecode.
#   Exact command sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-evmlib -DCMAKE_C_FLAGS="$F"
#     make -C <TREE>/nodus/build-evmlib -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-evmlib/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-evmlib/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_evm_lib.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, STAGEF_EPOCH_LENGTH
#   or the genesis epoch_length != 15, a grace variable != 15, not a Comet
#   cluster, no $BASE_DIR/v2_genesis.conf, a tool missing, a library
#   creation / runtime file or the Ticketer fixture missing, the tree not a
#   git checkout, any split STAGEF_MODE. A skip is not a pass.
#   FAIL (rc 1) on the capability gate, on a bytecode file that is
#   untracked or modified against HEAD, on a chain that already holds a
#   param 7 / 8 / 9 / 14 row (every switch is one-way, the leaves
#   single-use — it needs a fresh bring-up), and on any assertion.
#
# WHAT IT LEAVES BEHIND
#   HF-2, HF-3, rule-set generation 2 and the EVM generation 3 + EVM
#   domain — all one-way; four chain_config_history rows (params 7, 8, 9,
#   14). The leaves of nodes 1, 2, 3 and 5 (the pump) claimed. In the EVM
#   domain: the EVM accounts of nodes 1, 2, 3; the Ticketer (balance 0),
#   the MultisigVault (VAULT_FUND − PAY, proposal 0 executed), the
#   Timelock (TL_FUND − TL_PAY, one Done operation) and the
#   MilestoneEscrow (funded, both milestones settled, balance 0); no
#   pending ticket; v2_evm_reserve = 3 x DEP_RAW − PAY_RAW − W_RAW. Node 4
#   holds one index-101 release coin (PAY_RAW, its leaf unclaimed), node 2
#   one (W_RAW). Every fee (four status-0 transactions included) in the
#   reward pool. $BASE_DIR/evmlib/ (every CLI log). Nothing killed or
#   restarted. Tear down with stagef_down.sh before re-running.
#
# HOW IT CAN LIE
#   - **Generation 3, not 5.** The live testnet runs generation 5 (HF-6,
#     HF-7); this chain stops at the EVM generation. The EVM runtime and
#     the bridge are the generation-3 ones; nothing here exercises the
#     library under generation 4 / 5 rules.
#   - **E = 15, grace 15/15, BPY 20 prove the LOGIC**, nothing about 720 /
#     17 280 / 6 307 200. The EVM vote's H is decided by the F5 window
#     floor (initial_height + 256 + 5), so ~250 pump spends carry the
#     chain there.
#   - **The custom-error SELECTORS are not checked.** No keccak-256 tool
#     is on the machine (openssl 3.0 has none, python's hashlib has none),
#     so each negative control asserts a status-0 receipt, unchanged state
#     and that the SIMULATION's revert data ENDS with the error's encoded
#     arguments — never which error's selector precedes them. The
#     simulation runs at the tip before the transaction; the on-chain
#     status-0 is the chain's own verdict, its reason is inferred from the
#     simulation + the unchanged state + the same call succeeding once the
#     missing condition holds.
#   - **The Ticketer fixture is deployed but no longer used** (step 4):
#     the vault / timelock are funded by the CLI's plain value transfer.
#     Its deploy and its balance-0 checks are kept so no earlier assertion
#     was dropped; they prove nothing about the library.
#   - **The constructor cross-check compares two encoders written from
#     the same ABI spec** (the CLI's and this script's w_uint / w_addr) —
#     agreement proves they agree, not that the spec was read right; the
#     on-chain views (isOwner, threshold, parties, milestone, hasRole, …)
#     are the proof that each contract decoded them. A wrong encoding
#     FAILs (cross-check, reverted deployment or wrong views), never
#     passes. `evm encode` runs offline and is not the deploy path itself;
#     the deploy uses `--args`, which calls the same evm_abi_encode.
#   - **The plain value transfer is exercised only into receive()**
#     (vault, timelock) with a non-zero value; `--value 0` with no data and
#     a send to an account without code are not exercised here.
#   - **Deployed code = committed runtime** compares the evm_code chunks
#     of the account's code_digest, concatenated in chunk order
#     (nodus_witness_rt_evm.c NODUS_RT_EVM_OP_CODE: key[64] = chunk
#     index, value = raw bytes) — a storage-layout change would FAIL here,
#     not pass.
#   - **The Timelock's ready wait counts BLOCKS, bounded at TL_WAIT_BLOCKS
#     = TL_DELAY / (STAGEF_CMT_TIMEOUT_COMMIT_MS / 1000) + 5 heights**, each
#     height waited for with stagef_cmt_wait_height's stall bound. That
#     a height advances block time by at least timeout_commit is a
#     JUDGMENT (not read in the BFT-time code); if it is wrong the run
#     FAILs (false RED), never passes.
#   - **The early execute must land before READY**: TL_DELAY = 300 s of
#     block time against the handful of blocks between the schedule and
#     the early execute. If a stall pushed it past READY it would succeed
#     and the run FAILs (false RED).
#   - **The escrow deadline is never reached** (T_CHAIN + 1 day):
#     refund(), the post-deadline paths and fund() at the deadline are the
#     library's unit tests (shared/evm/tests/test_contract_lib.c), not
#     this scenario's.
#   - Gas: explicit --gas on every transaction (GAS_DEPLOY 5 000 000,
#     GAS_SEND 1 000 000, GAS_CALL 300 000 for reads) — placeholders sized
#     from the code (7 KB runtime x 200 gas/byte deposit), not measured;
#     a too-small value FAILs (OOG status 0), never passes. The per-height
#     RPC simulation budget (60 000 000 gas) is not approached on purpose
#     and never asserted.
#   - Fees: every transaction passes --yes (the CLI otherwise asks on
#     stdin above 50 NODUS, nodus-cli.c EVM_FEE_CONFIRM_RAW); native fee
#     amounts are not asserted (test_cmt_evm.sh asserts the fee path).
#   - Balances are read from every node's evm_accounts row (7/7) and
#     cross-checked through node 1's `evm balance` RPC; views (isOwner,
#     getProposal, …) are read on node 1 only — their 7/7 agreement is
#     the whole-state dump comparison.
#   - The ticket address is derived HERE (SHA3-512("NDS.EVMWITHDRAW.v1")
#     [0..32], openssl); the evm_tickets row appearing proves it matches
#     the engine's (nodus_witness_rt_evm.c TICKET_ADDR_PREIMAGE).
#   - Removing an owner / changing the threshold (configVersion), cancel,
#     updateDelay, refund, re-entry and the other negative controls of the
#     design's §5 are NOT exercised here — the unit tests are their proof.
#   - Every proposal is kept away from an epoch boundary (cc_guard); a tip
#     crossing one while the CLI runs FAILs (false RED, never a PASS).
#   - One machine; rc 99 = SKIP, coverage that did not happen.
#   - Duration ≈ 300 blocks (JUDGMENT, not measured: the EVM window floor
#     ≈ 262 pumped heights plus ~40 transactions and the ~5 idle blocks of
#     the timelock wait).
#   - Run results: none — written against the source, NOT run by its
#     author.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
# lib: node 3 is an EVM user (deposit, execute, resolve) — the pump runs on
# node 5's leaf instead (stagef_env.sh STAGEF_PUMP_FUNDER_NODE, read by
# stagef_pump_keys at call time)
STAGEF_PUMP_FUNDER_NODE=5
export STAGEF_PUMP_FUNDER_NODE
. "$(dirname "$0")/../stagef_env.sh"
# lib: the vote path and the EVM checks were not checked through a split
# core — SKIP (99) in every split mode (the HF-8 gen-5 rule)
stagef_split_skip_if --reason "EVM library scenario not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
LIB_DIR="$STAGEF_REPO_ROOT/nodus/tools/evm/contracts"     # lib: the library
LIB_OUT="$LIB_DIR/out/default"   # what `evm deploy --solc` compiles (library README)
FIX_DIR="$S_DIR/fixtures/evm"    # the Ticketer fixture (test_cmt_evm.sh)
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE (dnac.h), value exactly D
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM (nodus_witness_runtime.h)
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
E_REQ=15
E="$E_REQ"
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/evmlib"
N="$STAGEF_COMMITTEE_SIZE"
# lib: amounts in RAW units (1 NODUS = 10^8 raw; q = 10^10 wei per raw unit,
# library README "What is different on Nodus"); every wei value is raw x Q
# computed with bc (10^21 does not fit a bash integer)
Q=10000000000
DEP_RAW=100000000000       # 1 000 NODUS deposited by each of nodes 1, 2, 3
VAULT_FUND_RAW=10000000000 # 100 NODUS into the vault
PAY_RAW=4000000000         # 40 NODUS: the vault's ticket payout to node 4
TL_FUND_RAW=1000000000     # 10 NODUS into the timelock
TL_PAY_RAW=300000000       # 3 NODUS: the timelock's payout to node 2
M0_RAW=2000000000          # 20 NODUS: escrow milestone 0 (released to node 2)
M1_RAW=3000000000          # 30 NODUS: escrow milestone 1 (resolved back to node 1)
W_RAW=1000000000           # 10 NODUS: node 2's WITHDRAW to native
THRESHOLD=2                # the vault's 2-of-3
TL_DELAY=300               # seconds of BLOCK time (HOW IT CAN LIE)
ESCROW_WINDOW_S=86400      # the escrow deadline = T_CHAIN + 1 day (never reached)
SALT=0000000000000000000000000000000000000000000000000000000000000001
GAS_DEPLOY=5000000         # explicit gas (HOW IT CAN LIE: placeholders)
GAS_SEND=1000000
GAS_CALL=300000
# receipt layout (design §7, test_cmt_evm.sh header): status byte 17, op 18,
# evm_gas_used 19..26, created 27..58
OP_CALL=01; OP_CREATE=02; OP_DEPOSIT=03; OP_WITHDRAW=04; OP_REDEEM=05
REL_INDEX=101              # RTN_EVMFUND_REL_INDEX (nodus_witness_rt_native.c)
ZERO64=0000000000000000000000000000000000000000000000000000000000000000

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN=$SRV" "STAGEF_NODUSCLI_BIN=$CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs the short-epoch"
        echo "       short-grace build of this tree; see the header"
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
for t in sqlite3 bc xxd openssl ss git; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the EVM library checks need it"
        exit 99
    fi
done
if [ "$(printf 'abc' | openssl dgst -sha3-512 2>/dev/null | awk '{print $NF}')" != \
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" ]; then
    # SHA3-512("abc") — test_cmt_evm.sh's known-answer probe
    echo "[SKIP] this openssl has no working SHA3-512 (the receipt digest and the ticket address need it)"
    exit 99
fi
# lib: the committed bytecode (library out/default + the Ticketer fixture)
LIB_FILES=""
for c in MultisigVault MilestoneEscrow Timelock; do
    for k in creation runtime; do LIB_FILES="$LIB_FILES $LIB_OUT/$c.$k.hex"; done
done
for f in $LIB_FILES "$FIX_DIR/Ticketer.hex"; do
    if [ ! -s "$f" ]; then
        echo "[SKIP] committed bytecode $f is missing"
        exit 99
    fi
done
if ! git -C "$STAGEF_REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "[SKIP] $STAGEF_REPO_ROOT is not a git checkout — the committed-bytes check needs git"
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
mkdir -p "$LOGD"

# ── CAPABILITY GATE (FAIL, not skip) — test_cmt_hf8_gen5.sh's, cut to D ──
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
usage_out=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
D_DEC=$(sed -n 's/^  EVM_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D_DEC="${D_DEC%%$'\n'*}"
[ -n "$D_DEC" ] || { printf '%s\n' "$usage_out" >&2; die "the CLI's chain-config usage names no 'EVM_ACTIVE exactly <D>'"; }
[ "$D_DEC" -gt 0 ] 2>/dev/null || die "the CLI's EVM_ACTIVE literal '$D_DEC' is not a positive int64"
D_HEX=$(printf '%016x' "$D_DEC")

# lib: the tested bytes are the COMMITTED ones — tracked and unmodified
# against HEAD (an edited out/ would test code nobody committed)
LIB_HEAD=$(git -C "$STAGEF_REPO_ROOT" rev-parse HEAD)
for f in $LIB_FILES "$FIX_DIR/Ticketer.hex"; do
    git -C "$STAGEF_REPO_ROOT" ls-files --error-unmatch -- "$f" >/dev/null 2>&1 \
        || die "$f is not tracked by git — the scenario deploys COMMITTED bytecode only"
    git -C "$STAGEF_REPO_ROOT" diff --quiet HEAD -- "$f" \
        || die "$f differs from HEAD $LIB_HEAD — the scenario deploys COMMITTED bytecode only"
done
echo "[ok] capability gate: one build v$SRV_VER; D = 0x$D_HEX; library out/default + Ticketer.hex = HEAD $LIB_HEAD"

# ── script-local helpers (test_cmt_hf8_gen5.sh's, unless "lib:") ────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }
fp_of()  { tr 'A-F' 'a-f' < "$1/nodus.fp" | tr -d '[:space:]'; }   # $1 = identity dir

node_runs_srv() {
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$SRV")" ] && return 0
    done
    return 1
}

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

cross_edge() {
    local label="$1" hh="$2" x
    pump_to $(( hh - PUMP_STOP_GAP ))
    wait_all $(( hh + 1 ))
    for x in $(( hh - 1 )) "$hh" $(( hh + 1 )); do diff_at "$x" "$label-at-height-$x"; done
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

# ── EVM helpers (test_cmt_evm.sh's, unless "lib:") ───────────────────
BC() { BC_LINE_LENGTH=0 bc; }
hexdec() {                 # 64 hex (either case) -> decimal
    [ "${#1}" = 64 ] || { echo ERR; return 0; }
    printf 'ibase=16; %s\n' "$(tr 'a-f' 'A-F' <<< "$1")" | BC
}
wei_of() { printf '%s*%s\n' "$1" "$Q" | BC; }     # lib: raw -> wei

# lib: w_uint DEC -> one 32-byte ABI word, 64 lowercase hex (bc: no overflow)
w_uint() {
    local h
    h=$(printf 'obase=16; %s\n' "$1" | BC | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]{1,64}$ ]] || die "w_uint: '$1' is not a uint256"
    printf '%64s' "$h" | tr ' ' 0
}
# lib: w_addr ADDR -> the address word (a Nodus address fills all 32 bytes)
w_addr() {
    [[ "$1" =~ ^[0-9a-f]{64}$ ]] || die "w_addr: '$1' is not a 64-hex lowercase address"
    printf '%s' "$1"
}

# evm_addr_of KEYS -> the 32-byte address `evm address` prints (offline)
evm_addr_of() {
    local out line hit="" n=0
    out=$("$CLI" evm address --keys "$1" 2>&1) || die "evm address --keys $1 failed: $out"
    while IFS= read -r line; do
        if [[ "$line" =~ ^0x([0-9a-f]{64})$ ]]; then hit="${BASH_REMATCH[1]}"; n=$(( n + 1 )); fi
    done <<< "$out"
    [ "$n" = 1 ] || die "evm address --keys $1 printed $n address lines: '$out'"
    echo "$hit"
}

# evm_tx NODE KEYS_NODE LOG SUBCOMMAND ARGS... — a transaction as KEYS_NODE's
# identity, submitted to NODE's own port, --no-wait (inclusion is read from
# the ledger) and lib: --yes (no fee question on stdin; stdin is /dev/null
# besides). Sets EV_RC, EV_INTENT, EV_NONCE / EV_GAS / EV_FEE.
evm_tx() {
    local node="$1" kn="$2" log="$3" port
    shift 3
    port=$(stagef_tcp_port "$node")
    EV_RC=0
    "$CLI" -s 127.0.0.1 -p "$port" evm "$@" --keys "$(node_keys "$kn")" \
        --submit "127.0.0.1:$port" --no-wait --yes < /dev/null > "$log" 2>&1 || EV_RC=$?
    cat "$log"
    EV_INTENT=$(spend_intent "$log")
    EV_NONCE=$(sed -n 's/^evm [A-Z]*: sender 0x[0-9a-f]* nonce=\([0-9]*\) .*/\1/p' "$log")
    EV_GAS=$(sed -n 's/^evm [A-Z]*: sender 0x[0-9a-f]* nonce=[0-9]* gas=\([0-9]*\) .*/\1/p' "$log")
    EV_FEE=$(sed -n 's/^evm [A-Z]*: .* fee=\([0-9]*\) inputs=.*/\1/p' "$log")
}

evm_tx_ok() {
    [ "$EV_RC" = 0 ] || die "$1: the CLI exited $EV_RC"
    [ "${#EV_INTENT}" = 128 ] || die "$1: no intent_id printed"
    [ -n "$EV_GAS" ] && [ -n "$EV_FEE" ] && [ -n "$EV_NONCE" ] || die "$1: the build line did not parse"
    grep -q '^accepted: mempool CheckTx approved' "$2" || die "$1: no CheckTx approval line"
}

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

rcpt() {
    sqlite3 "$(db_of "$1")" \
        "SELECT hex(substr(receipt,17,1)) || '|' || hex(substr(receipt,18,1)) || '|' ||
                hex(substr(receipt,19,8)) || '|' || lower(hex(substr(receipt,27,32)))
           FROM evm_receipts WHERE lower(hex(intent_id)) = '$2';" 2>/dev/null || echo ERR
}

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

# lib: tx_ok NODE KEYS_NODE LABEL STATUS OP SUBCOMMAND ARGS... — evm_tx +
# CheckTx approval + the receipt on 7/7 with STATUS / OP; sets TX_INTENT,
# TX_LOG and RC_H / RCPT. The log name is derived from LABEL.
TX_SEQ=0
tx_ok() {
    local node="$1" kn="$2" label="$3" st="$4" op="$5"
    shift 5
    TX_SEQ=$(( TX_SEQ + 1 ))
    TX_LOG="$LOGD/tx_$(printf '%02d' "$TX_SEQ")_${label// /_}.log"
    evm_tx "$node" "$kn" "$TX_LOG" "$@"
    evm_tx_ok "$label" "$TX_LOG"
    TX_INTENT="$EV_INTENT"
    wait_receipt 1 "$TX_INTENT" "$label"
    require_rcpt "$TX_INTENT" "$st" "$op" "$label"
    echo "[ok] $label: receipt status $st op $op at height $RC_H (7/7)"
}

# lib: revert_tail TEXT -> the revert data after its 4-byte selector, from the
# FIRST "  revert data: 0x…" line (nodus-cli.c evm_print_revert; a custom
# error is neither Error(string) nor Panic(uint256), so it prints raw)
revert_tail() {
    awk '/^  revert data: 0x[0-9a-f]*$/ && !f { sub(/^  revert data: 0x/, ""); print substr($0, 9); f = 1 }' <<< "$1"
}

# lib: tx_reverted NODE KEYS_NODE LABEL TAIL SUBCOMMAND ARGS... — a call the
# simulation says FAILS, sent with --force: the simulation's revert data
# must END with TAIL (the error's encoded arguments; the selector is not
# derivable here — header), and the transaction is APPLIED with status 0.
tx_reverted() {
    local node="$1" kn="$2" label="$3" tail_x="$4" got
    shift 4
    TX_SEQ=$(( TX_SEQ + 1 ))
    TX_LOG="$LOGD/tx_$(printf '%02d' "$TX_SEQ")_${label// /_}.log"
    evm_tx "$node" "$kn" "$TX_LOG" "$@" --force
    grep -q 'the call FAILS' "$TX_LOG" || die "$label: the simulation did not report a failing call (see $TX_LOG)"
    got=$(revert_tail "$(cat "$TX_LOG")")
    [ "$got" = "$tail_x" ] || die "$label: the simulation's revert arguments are '$got', expected '$tail_x' (see $TX_LOG)"
    evm_tx_ok "$label" "$TX_LOG"
    TX_INTENT="$EV_INTENT"
    wait_receipt 1 "$TX_INTENT" "$label"
    require_rcpt "$TX_INTENT" 00 "$OP_CALL" "$label"
    echo "[ok] $label: REFUSED by the contract — applied with receipt status 0 at height $RC_H (7/7)"
}

evm_q() {
    local n="$1"
    shift
    EQ_RC=0
    EQ_OUT=$("$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" evm "$@" 2>&1) || EQ_RC=$?
}

# lib: view ADDR SIG ARGS... — a read on node 1 (`evm call`, --from node 1);
# sets CW[0..] to the decoded return words ("  [i] <value>", evm_abi_print)
view() {
    local a="$1" sig="$2" line
    shift 2
    evm_q 1 call "$a" "$sig" "$@" --from "$ADDR1" --gas "$GAS_CALL"
    [ "$EQ_RC" = 0 ] && grep -q '^ok at height' <<< "$EQ_OUT" || {
        printf '%s\n' "$EQ_OUT" >&2; die "evm call $sig on 0x${a:0:16}… did not succeed (rc $EQ_RC)"; }
    CW=()
    while IFS= read -r line; do
        if [[ "$line" =~ ^\ \ \[([0-9]+)\]\ (.*)$ ]]; then CW[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"; fi
    done <<< "$EQ_OUT"
}
# lib: view_is ADDR SIG ARGS... -- EXPECTED... — every return word as expected
view_is() {
    local a="$1" sig="$2" args=() i=0 x
    shift 2
    while [ "$#" -gt 0 ] && [ "$1" != -- ]; do args+=("$1"); shift; done
    [ "${1:-}" = -- ] || die "view_is: no -- separator"
    shift
    view "$a" "$sig" "${args[@]}"
    for x in "$@"; do
        [ "${CW[$i]:-}" = "$x" ] || die "$sig on 0x${a:0:16}… returned [$i] '${CW[$i]:-}', expected '$x'"
        i=$(( i + 1 ))
    done
}

nonce_of() {
    sqlite3 "$(db_of "$1")" "SELECT nonce FROM evm_accounts WHERE lower(hex(addr)) = '$2';" 2>/dev/null || echo ERR
}

# lib: wei_db NODE ADDR -> the account's balance in wei from evm_accounts
# (32-byte big-endian, nodus_witness_rt_evm.c account row store); 0 when the
# account has no row
wei_db() {
    local h
    h=$(sqlite3 "$(db_of "$1")" "SELECT hex(balance) FROM evm_accounts WHERE lower(hex(addr)) = '$2';" 2>/dev/null || echo ERR)
    if [ -z "$h" ]; then echo 0; else hexdec "$h"; fi
}

# lib: require_wei WHAT ADDR EXPECTED — 7/7 rows + node 1's evm_account RPC
require_wei() {
    local what="$1" a="$2" x="$3" n b
    for n in $(seq 1 "$N"); do
        b=$(wei_db "$n" "$a")
        [ "$b" = "$x" ] || die "$what: node$n's evm_accounts says 0x${a:0:16}… holds '$b' wei, expected $x"
    done
    evm_q 1 balance "$a"
    [ "$EQ_RC" = 0 ] || { printf '%s\n' "$EQ_OUT" >&2; die "$what: evm balance on node1 exited $EQ_RC"; }
    b=$(awk '$1 == "balance" && !f { print $2; f = 1 }' <<< "$EQ_OUT")
    [ "$b" = "$x" ] || die "$what: node1's evm_account RPC says 0x${a:0:16}… holds '$b' wei, expected $x"
}

# lib: require_code WHAT ADDR RUNTIME_HEX — the deployed code on 7/7 is the
# committed runtime, byte for byte (evm_code chunks in chunk order)
require_code() {
    local what="$1" a="$2" rt="$3" n row dg sz code
    for n in $(seq 1 "$N"); do
        row=$(sqlite3 "$(db_of "$n")" \
            "SELECT lower(hex(code_digest)) || '|' || code_size FROM evm_accounts WHERE lower(hex(addr)) = '$a';" 2>/dev/null || echo ERR)
        dg="${row%%|*}"; sz="${row##*|}"
        [ "${#dg}" = 128 ] || die "$what: node$n has no code row for 0x${a:0:16}… ('$row')"
        [ "$sz" = $(( ${#rt} / 2 )) ] || die "$what: node$n's code_size is $sz, the committed runtime is $(( ${#rt} / 2 )) bytes"
        code=$(sqlite3 "$(db_of "$n")" \
            "SELECT lower(hex(bytes)) FROM evm_code WHERE lower(hex(digest)) = '$dg' ORDER BY chunk;" 2>/dev/null | tr -d '\n')
        [ "$code" = "$rt" ] || die "$what: node$n's deployed code differs from the committed runtime"
    done
    echo "[ok] $what: deployed code on 7/7 = the committed runtime ($(( ${#rt} / 2 )) bytes)"
}

rel_count() {              # NODE FP AMOUNT -> index-101 release coins of that amount
    sqlite3 "$(db_of "$1")" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(owner) = '$2' AND amount = $3
           AND output_index = $REL_INDEX AND token_id = zeroblob(64);" 2>/dev/null || echo ERR
}

ticket_count() { sqlite3 "$(db_of "$1")" "SELECT COUNT(*) FROM evm_tickets;" 2>/dev/null || echo ERR; }

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
        FROM v2_root_history WHERE domain_id = 2 AND global_height <= $floor ORDER BY global_height;
      SELECT 'X|' || hex(intent_id) || '|' || global_height || '|' || item_index || '|' || hex(digest)
        FROM evm_receipts ORDER BY intent_id;
      SELECT 'L|' || hex(intent_id) || '|' || log_index || '|' || global_height || '|' || hex(addr) || '|' ||
             hex(topics) || '|' || hex(data) FROM evm_logs ORDER BY intent_id, log_index;" 2>/dev/null || echo ERR
}

require_evm_same() {
    local what="$1" n ref d fl
    fl=$(stagef_cmt_tip "$(db_of 1)")
    for n in $(seq 2 "$N"); do
        d=$(tip_of "$n"); [ "$d" -ge "$fl" ] || fl="$d"
    done
    [ "$fl" -ge 0 ] || die "$what: no floor height"
    ref=$(evm_dump 1 "$fl")
    [ "$ref" != ERR ] || die "$what: node1's EVM tables are unreadable"
    for n in $(seq 2 "$N"); do
        d=$(evm_dump "$n" "$fl")
        [ "$d" = "$ref" ] || {
            printf 'node1:\n%s\nnode%s:\n%s\n' "$ref" "$n" "$d" >&2
            die "$what: node$n's EVM state differs from node1's"; }
    done
    echo "[ok] $what: the whole EVM state + receipt / log index identical on 7/7"
}

# require_supply WHAT RESERVE TICKETS_WEI — exact values + the design §5
# invariant on 7/7; lib: wei_live is DERIVED as 10^10 x reserve − tickets
# (wei_lost must stay 0: nothing here destroys value)
require_supply() {
    local what="$1" rsv_x="$2" tk_x="$3" live_x n meta L T X rsv live tk lost lhs rhs v
    live_x=$(printf '%s*%s-%s\n' "$rsv_x" "$Q" "$tk_x" | BC)
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
        [ "$lost" = 0 ] || die "$what: node$n's wei_lost is $lost, expected 0"
    done
    echo "[ok] $what: 7/7 reserve $rsv_x raw, wei_live $live_x, wei_tickets $tk_x, wei_lost 0 — invariant holds"
}

# lib: created_of LABEL — CREATED = the created address of the last
# require_rcpt (receipt bytes 27..58); called directly, never in $(...),
# so a die() ends the scenario
created_of() {
    CREATED="${RCPT##*|}"
    [ "${#CREATED}" = 64 ] && [ "$CREATED" != "$ZERO64" ] || die "$1: the receipt names no created address ('$CREATED')"
}

# lib: args_ok LABEL HEX WORDS — a constructor encoding is exactly WORDS
# 32-byte words of hex (w_uint / w_addr run in $(...): a refusal there
# shows as a short encoding here)
args_ok() {
    [[ "$2" =~ ^[0-9a-f]+$ ]] && [ "${#2}" = $(( $3 * 64 )) ] \
        || die "$1: the constructor encoding is ${#2} hex characters, expected $3 words"
}

# lib: ctor_enc_is LABEL HAND_HEX "(T…)" VALUES... — the CLI's offline
# `evm encode --ctor` prints exactly 0x + the script's hand-built words
ctor_enc_is() {
    local label="$1" hand="$2" out erc=0
    shift 2
    out=$("$CLI" evm encode --ctor "$@" 2>&1) || erc=$?
    [ "$erc" = 0 ] || die "$label: evm encode --ctor exited $erc: $out"
    [ "$out" = "0x$hand" ] || die "$label: evm encode --ctor printed '$out', the script's hand-built encoding is '0x$hand'"
    echo "[ok] $label: evm encode --ctor = the hand-built constructor words ($(( ${#hand} / 64 )) words)"
}

# ── 0/1. preconditions: a fresh cluster on this build ───────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
ADDR1=$(evm_addr_of "$(node_keys 1)")
ADDR2=$(evm_addr_of "$(node_keys 2)")
ADDR3=$(evm_addr_of "$(node_keys 3)")
ADDR4=$(evm_addr_of "$(node_keys 4)")
[ "$ADDR1" != "$ADDR2" ] && [ "$ADDR1" != "$ADDR3" ] && [ "$ADDR2" != "$ADDR3" ] \
    || die "nodes 1, 2, 3 do not map to three distinct EVM addresses"
NFP2=$(fp_of "$(node_keys 2)"); NFP4=$(fp_of "$(node_keys 4)")
[[ "$NFP4" =~ ^[0-9a-f]{128}$ ]] || die "node4's fingerprint is not 128 hex ('$NFP4')"
# the ticket system address (library README "Getting value out of a
# contract"; nodus_witness_rt_evm.c TICKET_ADDR_PREIMAGE)
SYS_ADDR=$(printf 'NDS.EVMWITHDRAW.v1' | openssl dgst -sha3-512 | awk '{print substr($NF, 1, 64)}')
[ "${#SYS_ADDR}" = 64 ] || die "could not derive the ticket system address"
hexfile() { tr -d '[:space:]' < "$1" | tr 'A-F' 'a-f'; }
VAULT_INIT=$(hexfile "$LIB_OUT/MultisigVault.creation.hex")
VAULT_RT=$(hexfile "$LIB_OUT/MultisigVault.runtime.hex")
ESC_INIT=$(hexfile "$LIB_OUT/MilestoneEscrow.creation.hex")
ESC_RT=$(hexfile "$LIB_OUT/MilestoneEscrow.runtime.hex")
TL_INIT=$(hexfile "$LIB_OUT/Timelock.creation.hex")
TL_RT=$(hexfile "$LIB_OUT/Timelock.runtime.hex")
TICKETER_HEX=$(hexfile "$FIX_DIR/Ticketer.hex")
stagef_cmt_pump_ready "$(db_of 1)" || die "the CLI-SPEND pump is not usable on this bring-up (reason above)"
stagef_sentinel SETUP_OK
stagef_cmt_diff_at_floor "pre-evmlib" || exit 2
echo "[ok] fresh chain; EVM addresses: node1 0x$ADDR1, node2 0x$ADDR2, node3 0x$ADDR3, node4 0x$ADDR4"
echo "     ticket address 0x$SYS_ADDR (SHA3-512(\"NDS.EVMWITHDRAW.v1\")[0..32])"

# ── 1. leaves ───────────────────────────────────────────────────────
for k in 1 2 3; do claim_leaf "$(node_keys "$k")" 1; done

# ── 2. the four votes to the EVM generation (test_cmt_hf8_gen5.sh's) ─
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
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_2" "$H4"; done
echo "[ok] rule-set generation 2 on 7/7 from H4=$H4"

cc_guard 1
HE=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_SAFETY + GRACE_MARGIN ))    # param 14: SAFETY grace
H_WIN=$(( INIT_H + 256 + WINDOW_MARGIN ))                        # EVM rule (g)
[ "$HE" -ge "$H_WIN" ] || HE="$H_WIN"
while [ $(( (HE - 1) % E )) = 0 ]; do HE=$(( HE + 1 )); done     # EVM rule (f)
echo "[ok] tip $CCG_TIP — node1 proposes EVM_ACTIVE=$D_DEC effective HE=$HE (window floor $H_WIN)"
propose EVM_ACTIVE "$D_DEC" "$HE" "$LOGD/propose_evm.log"
wait_cc_row "$PARAM_EVM" "$HE" "$D_DEC" 20
[ "$CC_CB" -lt "$HE" ] || die "the EVM_ACTIVE row committed at $CC_CB, not before its effective height $HE"
cross_edge evm "$HE"
SWITCH_LINE="Nodus EVM: rule-set generation $GEN_2 -> $GEN_EVM and the EVM domain registered ACTIVE at the end of height $(( HE - 1 )) (D 0x$D_HEX)"
for n in $(seq 1 "$N"); do
    grep -qF "$SWITCH_LINE" "$(node_log "$n")" || die "node$n logged no '$SWITCH_LINE' line"
    require_gen "$n" "$GEN_EVM" "$H4"
done
echo "[ok] the EVM generation $GEN_EVM on 7/7 from HE=$HE"

# ── 3. bridge in: nodes 1, 2, 3 deposit ─────────────────────────────
DEP_WEI=$(wei_of "$DEP_RAW")
B1="$DEP_WEI"; B2="$DEP_WEI"; B3="$DEP_WEI"     # lib: the expected EVM balances (wei)
RSV=0; TK=0                                     # lib: expected reserve (raw), tickets (wei)
for k in 1 2 3; do
    tx_ok "$k" "$k" "deposit node$k" 01 "$OP_DEPOSIT" deposit "$DEP_RAW"
    RSV=$(( RSV + DEP_RAW ))
done
require_wei "deposit node1" "$ADDR1" "$B1"
require_wei "deposit node2" "$ADDR2" "$B2"
require_wei "deposit node3" "$ADDR3" "$B3"
require_supply "post-deposits" "$RSV" "$TK"
stagef_cmt_diff_at_floor "post-deposits" || exit 2

# ── 4. lib: the stagef fixture (no longer the value path, header) ───
tx_ok 1 1 "deploy Ticketer" 01 "$OP_CREATE" deploy "$TICKETER_HEX" --gas "$GAS_DEPLOY"
created_of "deploy Ticketer"; TICKETER="$CREATED"
echo "[ok] Ticketer (kept fixture, not the value path) at 0x$TICKETER"

# ── 5. lib: MultisigVault, 2-of-3, paying node 4 through a ticket ───
# the hand-built words: the independent cross-check of the CLI's encoder
VAULT_ARGS="$(w_uint 64)$(w_uint "$THRESHOLD")$(w_uint 3)$(w_addr "$ADDR1")$(w_addr "$ADDR2")$(w_addr "$ADDR3")"
args_ok "MultisigVault" "$VAULT_ARGS" 6
VAULT_SIG="(address[],uint256)"
ctor_enc_is "MultisigVault" "$VAULT_ARGS" "$VAULT_SIG" "[$ADDR1,$ADDR2,$ADDR3]" "$THRESHOLD"
tx_ok 1 1 "deploy MultisigVault" 01 "$OP_CREATE" deploy "$VAULT_INIT" \
    --args "$VAULT_SIG" "[$ADDR1,$ADDR2,$ADDR3]" "$THRESHOLD" --gas "$GAS_DEPLOY"
created_of "deploy MultisigVault"; VAULT="$CREATED"
require_code "MultisigVault" "$VAULT" "$VAULT_RT"
for a in "$ADDR1" "$ADDR2" "$ADDR3"; do view_is "$VAULT" "isOwner(address)(bool)" "$a" -- true; done
view_is "$VAULT" "isOwner(address)(bool)" "$ADDR4" -- false
view_is "$VAULT" "threshold()(uint256)" -- "$THRESHOLD"
view_is "$VAULT" "proposalCount()(uint256)" -- 0
echo "[ok] MultisigVault at 0x$VAULT: owners nodes 1, 2, 3 (node 4 not), threshold $THRESHOLD — the constructor encoding decoded on chain"

VF_WEI=$(wei_of "$VAULT_FUND_RAW")
tx_ok 1 1 "fund vault" 01 "$OP_CALL" send "$VAULT" --value "$VF_WEI" --gas "$GAS_SEND"
B1=$(printf '%s-%s\n' "$B1" "$VF_WEI" | BC); BV="$VF_WEI"
require_wei "vault funded" "$VAULT" "$BV"
require_wei "vault funded (node1)" "$ADDR1" "$B1"
require_wei "vault funded (Ticketer keeps nothing)" "$TICKETER" 0

PAY_WEI=$(wei_of "$PAY_RAW")
tx_ok 1 1 "vault submit" 01 "$OP_CALL" send "$VAULT" "submit(address,uint256,bytes)" "$SYS_ADDR" "$PAY_WEI" "$NFP4" \
    --gas "$GAS_SEND"
PROP=0
view_is "$VAULT" "proposalCount()(uint256)" -- 1
view_is "$VAULT" "getProposal(uint256)(address,uint256,bytes,uint256,uint256,bool)" "$PROP" -- \
    "0x$SYS_ADDR" "$PAY_WEI" "0x$NFP4" 0 1 false
echo "[ok] proposal $PROP = (ticket address, $PAY_WEI wei, node4's fingerprint), 1 approval"

# NEGATIVE: execute with ONE approval (VaultBelowThreshold(id 0, 1, 2))
[ "$(ticket_count 1)" = 0 ] || die "node1 holds an evm_tickets row before the vault's execute"
tx_reverted 1 1 "vault execute below threshold" "$(w_uint "$PROP")$(w_uint 1)$(w_uint "$THRESHOLD")" \
    send "$VAULT" "execute(uint256)" "$PROP" --gas "$GAS_SEND"
require_wei "after the refused execute" "$VAULT" "$BV"
for n in $(seq 1 "$N"); do
    [ "$(ticket_count "$n")" = 0 ] || die "node$n holds an evm_tickets row after the REFUSED execute"
done
view_is "$VAULT" "getProposal(uint256)(address,uint256,bytes,uint256,uint256,bool)" "$PROP" -- \
    "0x$SYS_ADDR" "$PAY_WEI" "0x$NFP4" 0 1 false
echo "[ok] below threshold: nothing moved (vault balance, no ticket, proposal not executed)"

tx_ok 2 2 "vault approve node2" 01 "$OP_CALL" send "$VAULT" "approve(uint256)" "$PROP" --gas "$GAS_SEND"
view_is "$VAULT" "isApproved(uint256,address)(bool)" "$PROP" "$ADDR2" -- true
tx_ok 3 3 "vault execute node3" 01 "$OP_CALL" send "$VAULT" "execute(uint256)" "$PROP" --gas "$GAS_SEND"
I_VEXEC="$TX_INTENT"
TICKET=$(sqlite3 "$(db_of 1)" "SELECT lower(hex(ticket_id)) FROM evm_tickets;")
[ "${#TICKET}" = 128 ] || die "node1 holds no single evm_tickets row after the vault's execute ('$TICKET')"
for n in $(seq 1 "$N"); do
    row=$(sqlite3 "$(db_of "$n")" "SELECT lower(hex(ticket_id)) || '|' || amount_raw || '|' || lower(hex(dest_fp)) FROM evm_tickets;")
    [ "$row" = "$TICKET|$PAY_RAW|$NFP4" ] || die "node$n's ticket row is '$row', expected '$TICKET|$PAY_RAW|$NFP4'"
done
evm_q 1 receipt "$I_VEXEC"
[ "$EQ_RC" = 0 ] && [[ "$EQ_OUT" == *"  withdrawal ticket: $TICKET"* ]] || {
    printf '%s\n' "$EQ_OUT" >&2; die "the vault execute's receipt does not name the ticket $TICKET"; }
BV=$(printf '%s-%s\n' "$BV" "$PAY_WEI" | BC); TK="$PAY_WEI"
require_wei "vault paid the ticket" "$VAULT" "$BV"
view_is "$VAULT" "getProposal(uint256)(address,uint256,bytes,uint256,uint256,bool)" "$PROP" -- \
    "0x$SYS_ADDR" "$PAY_WEI" "0x$NFP4" 0 2 true
require_supply "post-vault-ticket" "$RSV" "$TK"
require_evm_same "post-vault-ticket"
stagef_sentinel TARGET_REACHED
echo "[ok] 2-of-3 executed by node3: ticket ${TICKET:0:16}… ($PAY_RAW raw -> node4) on 7/7, vault $BV wei"

REL4_B=$(rel_count 1 "$NFP4" "$PAY_RAW")
tx_ok 1 1 "redeem vault ticket" 01 "$OP_REDEEM" redeem "$TICKET"
for n in $(seq 1 "$N"); do
    [ "$(rel_count "$n" "$NFP4" "$PAY_RAW")" = $(( REL4_B + 1 )) ] \
        || die "node$n holds no new index-$REL_INDEX release coin of $PAY_RAW raw for node4"
    [ "$(ticket_count "$n")" = 0 ] || die "node$n still holds the redeemed ticket"
done
RSV=$(( RSV - PAY_RAW )); TK=0
require_supply "post-redeem" "$RSV" "$TK"
stagef_cmt_diff_at_floor "post-redeem" || exit 2
echo "[ok] redeemed: node4 holds a native coin of exactly $PAY_RAW raw on 7/7, reserve $RSV raw"

# ── 6. lib: Timelock, part 1 — deploy, fund, schedule, refused early ─
TL_ARGS="$(w_uint "$TL_DELAY")$(w_uint 128)$(w_uint 192)$(w_uint 256)"
TL_ARGS="$TL_ARGS$(w_uint 1)$(w_addr "$ADDR1")$(w_uint 1)$(w_addr "$ADDR1")$(w_uint 0)"
args_ok "Timelock" "$TL_ARGS" 9
TL_SIG="(uint256,address[],address[],address[])"
ctor_enc_is "Timelock" "$TL_ARGS" "$TL_SIG" "$TL_DELAY" "[$ADDR1]" "[$ADDR1]" "[]"
tx_ok 1 1 "deploy Timelock" 01 "$OP_CREATE" deploy "$TL_INIT" \
    --args "$TL_SIG" "$TL_DELAY" "[$ADDR1]" "[$ADDR1]" "[]" --gas "$GAS_DEPLOY"
created_of "deploy Timelock"; TL="$CREATED"
require_code "Timelock" "$TL" "$TL_RT"
view_is "$TL" "getMinDelay()(uint256)" -- "$TL_DELAY"
view "$TL" "PROPOSER_ROLE()(bytes32)"; R_PROP="${CW[0]:-}"
view "$TL" "EXECUTOR_ROLE()(bytes32)"; R_EXEC="${CW[0]:-}"
view "$TL" "CANCELLER_ROLE()(bytes32)"; R_CANC="${CW[0]:-}"
for r in "$R_PROP" "$R_EXEC" "$R_CANC"; do
    [[ "$r" =~ ^0x[0-9a-f]{64}$ ]] || die "a Timelock role constant did not read ('$r')"
done
view_is "$TL" "hasRole(bytes32,address)(bool)" "$R_PROP" "$ADDR1" -- true
view_is "$TL" "hasRole(bytes32,address)(bool)" "$R_EXEC" "$ADDR1" -- true
view_is "$TL" "hasRole(bytes32,address)(bool)" "$R_CANC" "$ADDR1" -- false
echo "[ok] Timelock at 0x$TL: minDelay $TL_DELAY s, proposer = executor = node1, no canceller"

TLF_WEI=$(wei_of "$TL_FUND_RAW")
tx_ok 1 1 "fund timelock" 01 "$OP_CALL" send "$TL" --value "$TLF_WEI" --gas "$GAS_SEND"
B1=$(printf '%s-%s\n' "$B1" "$TLF_WEI" | BC); BT="$TLF_WEI"
require_wei "timelock funded" "$TL" "$BT"
require_wei "timelock funded (node1)" "$ADDR1" "$B1"

TLP_WEI=$(wei_of "$TL_PAY_RAW")
tx_ok 1 1 "timelock schedule" 01 "$OP_CALL" send "$TL" "schedule(address,uint256,bytes,bytes32,uint256)" \
    "$ADDR2" "$TLP_WEI" 0x "0x$SALT" "$TL_DELAY" --gas "$GAS_SEND"
view "$TL" "hashOperation(address,uint256,bytes,bytes32)(bytes32)" "$ADDR2" "$TLP_WEI" 0x "0x$SALT"
TL_ID="${CW[0]:-}"; TL_ID="${TL_ID#0x}"
[[ "$TL_ID" =~ ^[0-9a-f]{64}$ ]] || die "hashOperation did not return an id ('$TL_ID')"
view_is "$TL" "getOperationState(bytes32)(uint8)" "0x$TL_ID" -- 1
view "$TL" "getReadyTime(bytes32)(uint256)" "0x$TL_ID"
READY="${CW[0]:-}"
[[ "$READY" =~ ^[0-9]+$ ]] && [ "$READY" -gt "$TL_DELAY" ] || die "getReadyTime returned '$READY'"
T_CHAIN=$(( READY - TL_DELAY ))
echo "[ok] scheduled op ${TL_ID:0:16}…: ready at block time $READY; the schedule block's block.timestamp = $T_CHAIN (the chain clock)"

# NEGATIVE: execute before READY (TimelockNotReady(id, READY))
tx_reverted 1 1 "timelock execute early" "$TL_ID$(w_uint "$READY")" \
    send "$TL" "execute(address,uint256,bytes,bytes32)" "$ADDR2" "$TLP_WEI" 0x "0x$SALT" --gas "$GAS_SEND"
require_wei "after the early execute (node2)" "$ADDR2" "$B2"
require_wei "after the early execute (timelock)" "$TL" "$BT"
view_is "$TL" "getOperationState(bytes32)(uint8)" "0x$TL_ID" -- 1
echo "[ok] before ready: nothing moved, the operation is still Pending"

# ── 7. lib: MilestoneEscrow ─────────────────────────────────────────
M0_WEI=$(wei_of "$M0_RAW"); M1_WEI=$(wei_of "$M1_RAW")
SUM_WEI=$(printf '%s+%s\n' "$M0_WEI" "$M1_WEI" | BC)
DEADLINE=$(( T_CHAIN + ESCROW_WINDOW_S ))
ESC_ARGS="$(w_addr "$ADDR1")$(w_addr "$ADDR2")$(w_addr "$ADDR3")$(w_uint 160)$(w_uint "$DEADLINE")"
ESC_ARGS="$ESC_ARGS$(w_uint 2)$(w_uint "$M0_WEI")$(w_uint "$M1_WEI")"
args_ok "MilestoneEscrow" "$ESC_ARGS" 8
ESC_SIG="(address,address,address,uint256[],uint256)"
ctor_enc_is "MilestoneEscrow" "$ESC_ARGS" "$ESC_SIG" "$ADDR1" "$ADDR2" "$ADDR3" "[$M0_WEI,$M1_WEI]" "$DEADLINE"
tx_ok 1 1 "deploy MilestoneEscrow" 01 "$OP_CREATE" deploy "$ESC_INIT" \
    --args "$ESC_SIG" "$ADDR1" "$ADDR2" "$ADDR3" "[$M0_WEI,$M1_WEI]" "$DEADLINE" --gas "$GAS_DEPLOY"
created_of "deploy MilestoneEscrow"; ESC="$CREATED"
require_code "MilestoneEscrow" "$ESC" "$ESC_RT"
view_is "$ESC" "parties()(address,address,address)" -- "0x$ADDR1" "0x$ADDR2" "0x$ADDR3"
view_is "$ESC" "total()(uint256)" -- "$SUM_WEI"
view_is "$ESC" "milestoneCount()(uint256)" -- 2
view_is "$ESC" "milestone(uint256)(uint256,uint8)" 0 -- "$M0_WEI" 0
view_is "$ESC" "milestone(uint256)(uint256,uint8)" 1 -- "$M1_WEI" 0
view_is "$ESC" "deadline()(uint256)" -- "$DEADLINE"
view_is "$ESC" "funded()(bool)" -- false
echo "[ok] MilestoneEscrow at 0x$ESC: payer node1, payee node2, arbiter node3, milestones $M0_WEI + $M1_WEI wei, deadline $DEADLINE (block time)"

tx_ok 1 1 "escrow fund" 01 "$OP_CALL" send "$ESC" "fund()" --value "$SUM_WEI" --gas "$GAS_SEND"
B1=$(printf '%s-%s\n' "$B1" "$SUM_WEI" | BC); BE="$SUM_WEI"
view_is "$ESC" "funded()(bool)" -- true
require_wei "escrow funded" "$ESC" "$BE"
require_wei "escrow funded (node1)" "$ADDR1" "$B1"

# NEGATIVE: fund() by node 2 (EscrowUnauthorized(node2))
tx_reverted 2 2 "escrow fund by payee" "$(w_addr "$ADDR2")" \
    send "$ESC" "fund()" --value "$SUM_WEI" --gas "$GAS_SEND"
require_wei "after the refused fund (escrow)" "$ESC" "$BE"
require_wei "after the refused fund (node2)" "$ADDR2" "$B2"

tx_ok 1 1 "escrow release 0" 01 "$OP_CALL" send "$ESC" "release(uint256)" 0 --gas "$GAS_SEND"
view_is "$ESC" "milestone(uint256)(uint256,uint8)" 0 -- "$M0_WEI" 1
view_is "$ESC" "creditOf(address)(uint256)" "$ADDR2" -- "$M0_WEI"

# NEGATIVE: release(0) again (EscrowAlreadySettled(0, Released=1))
tx_reverted 1 1 "escrow release 0 again" "$(w_uint 0)$(w_uint 1)" \
    send "$ESC" "release(uint256)" 0 --gas "$GAS_SEND"
view_is "$ESC" "milestone(uint256)(uint256,uint8)" 0 -- "$M0_WEI" 1
view_is "$ESC" "creditOf(address)(uint256)" "$ADDR2" -- "$M0_WEI"

tx_ok 2 2 "escrow withdraw node2" 01 "$OP_CALL" send "$ESC" "withdraw()" --gas "$GAS_SEND"
B2=$(printf '%s+%s\n' "$B2" "$M0_WEI" | BC); BE=$(printf '%s-%s\n' "$BE" "$M0_WEI" | BC)
require_wei "payee withdrew milestone 0" "$ADDR2" "$B2"
require_wei "payee withdrew milestone 0 (escrow)" "$ESC" "$BE"
view_is "$ESC" "creditOf(address)(uint256)" "$ADDR2" -- 0

tx_ok 3 3 "escrow resolve 1 to payer" 01 "$OP_CALL" send "$ESC" "resolve(uint256,bool)" 1 false --gas "$GAS_SEND"
view_is "$ESC" "milestone(uint256)(uint256,uint8)" 1 -- "$M1_WEI" 2
view_is "$ESC" "creditOf(address)(uint256)" "$ADDR1" -- "$M1_WEI"

tx_ok 1 1 "escrow withdraw node1" 01 "$OP_CALL" send "$ESC" "withdraw()" --gas "$GAS_SEND"
B1=$(printf '%s+%s\n' "$B1" "$M1_WEI" | BC); BE=$(printf '%s-%s\n' "$BE" "$M1_WEI" | BC)
[ "$BE" = 0 ] || die "the escrow's expected balance is $BE after both milestones (arithmetic)"
require_wei "payer withdrew milestone 1" "$ADDR1" "$B1"
require_wei "escrow emptied" "$ESC" 0
view_is "$ESC" "accounting()(uint256,uint256,uint256)" -- 0 0 "$SUM_WEI"
require_evm_same "post-escrow"
echo "[ok] escrow: milestone 0 released to node2 (+$M0_WEI wei), milestone 1 resolved back to node1 (+$M1_WEI wei), escrow empty, accounting (0, 0, $SUM_WEI)"

# node 2 takes part of its EVM balance back to native
REL2_B=$(rel_count 1 "$NFP2" "$W_RAW")
tx_ok 2 2 "evm withdraw node2" 01 "$OP_WITHDRAW" withdraw "$W_RAW"
for n in $(seq 1 "$N"); do
    [ "$(rel_count "$n" "$NFP2" "$W_RAW")" = $(( REL2_B + 1 )) ] \
        || die "node$n holds no new index-$REL_INDEX release coin of $W_RAW raw for node2"
done
B2=$(printf '%s-%s\n' "$B2" "$(wei_of "$W_RAW")" | BC)
RSV=$(( RSV - W_RAW ))
require_wei "node2 withdrew to native" "$ADDR2" "$B2"
require_supply "post-withdraw" "$RSV" "$TK"
stagef_cmt_diff_at_floor "post-withdraw" || exit 2
echo "[ok] node2 withdrew $W_RAW raw: a native coin on 7/7, reserve $RSV raw"

# ── 8. lib: Timelock, part 2 — block time passes READY, then execute ─
TL_WAIT_BLOCKS=$(( TL_DELAY / (STAGEF_CMT_TIMEOUT_COMMIT_MS / 1000) + 5 ))
waited=0
while :; do
    evm_q 1 call "$TL" "execute(address,uint256,bytes,bytes32)" "$ADDR2" "$TLP_WEI" 0x "0x$SALT" \
        --from "$ADDR1" --gas "$GAS_CALL"
    if [ "$EQ_RC" = 0 ] && grep -q '^ok at height' <<< "$EQ_OUT"; then break; fi
    [ "$EQ_RC" = 3 ] || { printf '%s\n' "$EQ_OUT" >&2; die "the ready probe failed (rc $EQ_RC)"; }
    got=$(revert_tail "$EQ_OUT")
    [ "$got" = "$TL_ID$(w_uint "$READY")" ] || {
        printf '%s\n' "$EQ_OUT" >&2; die "the ready probe reverts with other arguments than (id, READY): '$got'"; }
    waited=$(( waited + 1 ))
    [ "$waited" -le "$TL_WAIT_BLOCKS" ] || die \
        "block time did not reach READY=$READY within $TL_WAIT_BLOCKS heights (header: the per-height JUDGMENT)"
    t=$(tip_of 1)
    stagef_cmt_wait_height "$(db_of 1)" $(( t + 1 )) 3 >/dev/null \
        || die "chain STALLED at $(tip_of 1) while waiting for the timelock's ready time"
done
echo "[ok] block time reached READY=$READY after $waited more height(s) (node1 tip $(tip_of 1))"
tx_ok 1 1 "timelock execute" 01 "$OP_CALL" send "$TL" "execute(address,uint256,bytes,bytes32)" \
    "$ADDR2" "$TLP_WEI" 0x "0x$SALT" --gas "$GAS_SEND"
B2=$(printf '%s+%s\n' "$B2" "$TLP_WEI" | BC); BT=$(printf '%s-%s\n' "$BT" "$TLP_WEI" | BC)
require_wei "timelock paid node2" "$ADDR2" "$B2"
require_wei "timelock paid node2 (timelock)" "$TL" "$BT"
view_is "$TL" "getOperationState(bytes32)(uint8)" "0x$TL_ID" -- 2
echo "[ok] timelock executed after its delay: node2 +$TLP_WEI wei, operation Done"

# ── 9. final ────────────────────────────────────────────────────────
require_wei "end (node1)" "$ADDR1" "$B1"
require_wei "end (node2)" "$ADDR2" "$B2"
require_wei "end (node3)" "$ADDR3" "$B3"
require_wei "end (vault)" "$VAULT" "$BV"
require_wei "end (timelock)" "$TL" "$BT"
require_wei "end (escrow)" "$ESC" 0
require_wei "end (Ticketer)" "$TICKETER" 0
require_supply "end" "$RSV" "$TK"
require_evm_same "end"
stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-evmlib" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | library deployed from HEAD $LIB_HEAD (out/default)"
echo "       | vault 0x$VAULT | timelock 0x$TL (ready $READY) | escrow 0x$ESC (deadline $DEADLINE) | Ticketer 0x$TICKETER"
echo "[PASS] Nodus contract library on a chain (generation $GEN_EVM): a 2-of-3 MultisigVault refused one"
echo "       approval and paid node4 $PAY_RAW raw through a ticket that redeemed to a native coin; a"
echo "       Timelock refused before its block-time delay and paid after it; a MilestoneEscrow refused"
echo "       a wrong funder and a double release and paid both milestones; node2 withdrew to native;"
echo "       EVM state, supply invariant and blocks identical on 7/7."
echo "       E=15 / grace 15 — the LOGIC only; custom-error selectors NOT checked (header)."
