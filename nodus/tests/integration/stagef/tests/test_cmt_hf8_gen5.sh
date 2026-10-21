#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf8_gen5.sh — HF-8, "delegation requires an on-chain name",
# on a GENERATION-5 chain (the rule the testnet would run): the six-vote
# path of test_cmt_hf7.sh to generation 5, then the param-17 vote; a
# nameless non-owner DELEGATE lands before the vote and between the vote
# and H, and after H the SYSTEM DELEGATE leg refuses a nameless non-owner
# (new and top-up) and a validator's NODE key, while a named delegator
# and the validator's OWNER land; dnac_fee_info reports the rule 0 / 1;
# rev 3: after H a 2-of-3 VAULT registers a name, and a nameless STAKE is
# refused while a named one lands (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: decision docs/plans/decisions/2026-10-21-hf8-
# activation.md (the operator's "Tamam": the dnac_fee_info field + this
# scenario before the vote); docs/plans/2026-10-07-delegate-name-required-
# design.md rev 2 §1 (the rule; its §1 predates D3); decision D3 in
# docs/plans/decisions/2026-10-09-kurultay-16-hf6-storage-summary.md
# :105-108 (from generation 4 the rule is on the SYSTEM DELEGATE leg,
# exempt = delegator_fp == the validator row's owner_fp). TEMPLATES:
# test_cmt_hf7.sh — its capability gate, its vote helpers (cc_guard /
# propose / wait_cc_row / ruleset_info / require_gen / cross_edge) and its
# generation 1 -> 2 -> 3 -> 4 -> 5 path, WITHOUT its multisig / replay
# steps; test_cmt_hf8_delegate_name.sh — the claim, name-register,
# param-17 and delegate steps; test_storage_archive.sh — the TEST-OWNER
# gate and the owner funding spend. Every new part is marked "g5:".
#
# THE RULE UNDER TEST (nodus_witness_rt_native.c rtn_deleg2_name_gate /
# rtn_delegate2_exec, op 16 NAMEOWN2; the CORE SYSFUND leg is NOT gated at
# generation >= 4, rtn_sysfund_name_gate): from param 17's height a
# generation-4/5 DELEGATE whose delegator_fp differs from the target
# row's owner_fp must own a v2_names row; the refusal is the generic exec
# verdict of leg 0 — "env 0 leg 0 domain 0 op 2: runtime exec refused (rc
# -1)" (nodus_witness_v2_apply.c exec_one_env; DNA_DOMAIN_SYSTEM = 0,
# shared/dnac/ledger_ids.h:52; DNA_SYSRULE_DELEGATE = 2,
# nodus_witness_runtime.h:89) behind CheckTx's "dry run item code 7"
# (NODUS_V2_TX_ERR_EXEC, nodus_witness_cmt_app.c app_refuse_log).
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): one version banner for the server and the
#      CLI; the CLI's chain-config usage names EVM_ACTIVE / RULESET_GEN_
#      ROLES / RULESET_GEN_ROOTS "exactly <D…>" and passes
#      DELEGATE_NAME_REQUIRED to the connect step; node 1's database is
#      schema S19; every node's newest start logged the CLI's D4 and D5.
#      TEST-OWNER gate: STAGEF_HF6_OWNER_KEYS holds nodus.pk / nodus.sk,
#      SHA3-512(nodus.pk) == STAGEF_HF6_OWNER_FP_HEX != the K8 default,
#      and the owner is no node's key.
#   1. Fresh chain: no param 7 / 8 / 9 / 14 / 16 / 17 / 18 / 22 row, no
#      roles row, no delegation; nodes 2, 4, 5, 6, 7 claim their leaves;
#      node 4 pays the test owner AMOUNT + 2 NODUS (its funding coin).
#   2. HF2_ACTIVE, HF3_ACTIVE, RULESET_GEN2, EVM_ACTIVE, RULESET_GEN_ROLES
#      and RULESET_GEN_ROOTS voted and crossed (test_cmt_hf7.sh's path),
#      each row identical 7/7 and committed below its effective height,
#      blocks AT each edge's H−1 / H / H+1 identical 7/7, each edge's log
#      line on 7/7; ruleset-info 7/7 = generation 5; every validator row's
#      owner_fp = the test owner (the build carries it).
#   3. g5: dnac_fee_info's "delegate_name_required" reads 0 before any
#      param-17 row (the CLI's `v2-envelope delegate --dry-run` state line
#      for node 2, which submits nothing).
#   4. g5: before any param-17 row node 4 — nameless, NOT the owner —
#      delegates AMOUNT to node 1's validator_id and it LANDS (its
#      v2_intent_index row; the delegations row (SHA3-512(node 4's key),
#      node 1's validator_id) holds AMOUNT).
#   5. g5: node 2 registers NAME_B (`name register`); the v2_names row
#      lands.
#   6. g5: `chain-config propose --param DELEGATE_NAME_REQUIRED --value 1`
#      at H = tip + 1 + grace + H_MARGIN: round 1 7/7, the row identical
#      7/7, committed < H.
#   7. g5: between the vote and H (tip + 1 < H, checked before and after):
#      the state line still reads 0, and node 5 — nameless — delegates and
#      it LANDS below H.
#   8. g5: the chain crosses H: 7/7 identical global_root + block_id AT
#      H−1, H and H+1; the state line then reads 1.
#   9. g5: after H, all submitted to node 1:
#      a. node 7 (nameless, a NEW delegation) WITHOUT --no-name-precheck:
#         the CLI refuses before signing, with its plain text ("This
#         identity has no chain name."), and submits nothing;
#      b. node 7 again WITH --no-name-precheck: REFUSED at CheckTx with
#         "dry run item code 7" and "domain 0 op 2: runtime exec refused
#         (rc -1)";
#      c. node 4 (nameless, a TOP-UP of its step-4 row) with
#         --no-name-precheck: REFUSED with the same text;
#      d. node 6's NODE key delegating to node 6's OWN validator_id with
#         --no-name-precheck: REFUSED with the same text — a node key is
#         not its validator's owner (D3);
#      e. node 2 (named) delegates and it LANDS;
#      f. the test OWNER (nameless) delegates to node 1's validator_id —
#         its own validator — WITHOUT --no-name-precheck: the CLI's
#         pre-check lets it through (exempt) and it LANDS, a top-up of
#         the Foundation-owned self-delegation the HF-6 migration wrote;
#      g. two heights later, on 7/7: node 2's row = AMOUNT, the owner's
#         row = its pre-H amount + AMOUNT, no node 7 row, no node 6 → node
#         6 row, node 4's row still exactly AMOUNT.
#   7b. rev3 (decision 2026-10-21-hf8-activation.md amendment, "ekle."):
#      between the vote and H, `name register NAME_V --msig` of the genesis
#      2-of-3 vault (nodes 2, 3, 4 — stagef_up_v2.sh) is refused by the CLI
#      ("a multisig vault can register a name only once HF-8 …") and
#      writes no export.
#  10. rev3, after H — a vault's name (rule 3):
#      a. a registration funded by the vault's genesis coin AND node 2's
#         own coin: `msig sign` by node 2 on its pinned node REFUSES ("is
#         not an unspent coin of this vault") and writes no signature
#         (operator "Yalnız kasanın parası");
#      b. funded by the vault's coin only: nodes 2 and 3 sign (the
#         NAME_REGISTER read-back is shown), `msig combine` submits, the
#         v2_names row (NAME_V, the vault address) lands at >= H, `name
#         lookup NAME_V` returns the vault address on 7/7, the genesis coin
#         is spent.
#  11. rev3, after H — the STAKER's name (rule 2), a fresh consensus key KS
#      (stagef_hf6_owner.sh, the harness's identity maker) consenting to
#      each owner, the same bond (STAKE_MIN 2M NODUS) and commission:
#      a. node 7 (nameless) `v2-envelope stake2`: the CLI refuses before
#         signing ("This identity has no chain name. Staking needs one"),
#         nothing submitted, the state line reads 1;
#      b. again with --no-name-precheck: REFUSED at CheckTx with "dry run
#         item code 7" and "domain 0 op 1: runtime exec refused (rc -1)";
#      c. node 2 (named) stakes KS: it LANDS at >= H; on 7/7 one validator
#         row with key KS whose roles row's owner_fp = node 2, and no
#         validator owned by node 7.
#  12. stagef_cmt_diff_at_floor 7/7 at the start and at the end.
#
# WHAT IT REQUIRES
#   Compile flags — ONE short-epoch + short-grace TEST-OWNER build of THIS
#   tree (nodus-server AND nodus-cli from the SAME build dir, with
#   NODUS_EVM_ENABLED — the standalone non-Windows default; the
#   generation-4 and generation-5 edges FAULT without it):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   PLUS the three owner flags stagef_hf6_owner.sh prints (all or none —
#   a partial set refuses to start on every node):
#     -DDNAC_HF6_FOUNDATION_OWNER="{0x..,…}"   (the test owner)
#     -DDNAC_CFG_RULESET_GEN_ROLES_D=<its D4>  -DDNAC_CFG_RULESET_GEN_ROOTS_D=<its D5>
#   (params 7, 8, 9, 17, 18, 22 are ERGONOMIC; param 14 is SAFETY.)
#   Environment, exported BEFORE stagef_up_v2.sh unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     read by THIS script only:
#       STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#       STAGEF_HF6_OWNER_FP_HEX=<the owner's 128 hex>
#       STAGEF_HF6_OWNER_KEYS=<DIR>/identity      (the owner signs step 9f)
#   Leave STAGEF_PAYOUT_INTERVAL_EPOCHS and STAGEF_MODE unset.
#   The bring-up's genesis 2-of-3 coin ($BASE_DIR/msig_genesis_2of3.desc,
#   msig_genesis.addr — written by stagef_up_v2.sh when its nodus-cli has
#   `msig address`, i.e. a CLI of this tree): absent -> SKIP.
#   Tools: sqlite3, xxd, ss, openssl (SHA3-512), python3 (step 11 runs
#   stagef_hf6_owner.sh for its fresh consensus key; that script checks
#   its oracles).
#   Exact command sequence (ORCHESTRATOR):
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_hf6_owner.sh /tmp/hf8-owner <TREE>/nodus/build/nodus-server
#       (prints the owner fp and the three flags O / D / D5F)
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-hf8g5 -DCMAKE_C_FLAGS="$F $O $D $D5F"
#     make -C <TREE>/nodus/build-hf8g5 -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-hf8g5/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-hf8g5/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     export STAGEF_HF6_OWNER_FP_HEX=<fp> STAGEF_HF6_OWNER_KEYS=/tmp/hf8-owner/identity
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf8_gen5.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, STAGEF_EPOCH_LENGTH
#   or the genesis epoch_length != 15, a grace variable != 15, not a Comet
#   cluster, no $BASE_DIR/v2_genesis.conf, a tool missing,
#   STAGEF_HF6_OWNER_KEYS unset (the owner exemption — step 9f — cannot be
#   signed with the K8 default: its keys are not the harness's), no genesis
#   2-of-3 coin files, python3 missing, any split STAGEF_MODE. A skip is
#   not a pass.
#   FAIL (rc 1) on the capability / TEST-OWNER gates, on a chain that
#   already holds a param 7 / 8 / 9 / 14 / 16 / 17 / 18 / 22 row, a roles
#   row or a delegation, whose genesis 2-of-3 coin is spent or whose vault
#   already holds a name (every switch is one-way, the leaves and the coin
#   single-use — it needs a fresh bring-up), and on a CLI that prints no
#   "delegate_name_required at tip + 1:" line (not a build of this
#   package).
#
# WHAT IT LEAVES BEHIND
#   HF-2, HF-3, rule-set generations 2, 3 (+ the EVM domain), 4 and 5 and
#   HF-8 — all one-way; seven chain_config_history rows (params 7, 8, 9,
#   14, 18, 22, 17). The HF-6 migration's rows (validators re-keyed to
#   validator_id, 2M bonds + 8M owner self-delegations, seven roles /
#   consensus-key rows), the HF-7 seed. ONE v2_names row (NAME_B -> node
#   2, permanent) with its price + fee in the reward pool. The genesis
#   leaves of nodes 2, 3 (the pump), 4, 5, 6, 7 claimed; the owner's
#   funding coin spent. Delegations that stay: node 4 -> node 1, node 5 ->
#   node 1, node 2 -> node 1 (AMOUNT each) and the owner's node-1 row grown
#   by AMOUNT (node 1's power and reward share grow from the next
#   snapshots). rev3: a SECOND v2_names row (NAME_V -> the 2-of-3 vault,
#   permanent) and the vault's genesis coin spent (its change back to the
#   vault); an EIGHTH validator (key KS, owner node 2, bond 2M NODUS,
#   ACTIVE) whose consensus key runs on NO node — the scenario ends within
#   a few blocks, before its Rule-R tenure (2E) could seat it; a cluster
#   left running past that may seat an offline validator (its power is
#   2M of the committee's, liveness unaffected while the seven hold >2/3 —
#   JUDGMENT, not run). $BASE_DIR/hf8g5/stakekey/ (KS's identity, made by
#   stagef_hf6_owner.sh on port block 90 and killed), $BASE_DIR/hf8g5/
#   (every CLI log, the exports and signature files). Nothing killed or
#   restarted. Tear down with stagef_down.sh before re-running.
#
# HOW IT CAN LIE
#   - **ONE build, no rolling upgrade.** Every node runs this binary from
#     bring-up on; the live order (roll the release carrying the
#     dnac_fee_info field 7/7, then vote — runbook §2.2 HF-8) and a mixed
#     fleet are NOT exercised. The rule itself is not new code here: it is
#     the generation-4 arm every generation-5 runtime shares
#     (rtn_gen_roles, generation >= 4).
#   - **rev3's chain-side refusals are partly the tools'.** The vault's
#     mixed-funding registration (10a) is refused by the CO-SIGNER's input
#     check (msig_inputs_verify), before any envelope exists — the chain's
#     own refusal of a member's coin (rtn_name_exec, every input owned by
#     the vault) is test_hf8_msig_name.c's (engine) and test_hf4_names.c's
#     (hook), not this scenario's. Likewise the vault's pre-H refusal (7b)
#     is the CLI's; the chain's (a kind-3 owner refused while param 17 is
#     off) is the unit tests'. The STAKE refusal (11b) is the engine's
#     GENERIC exec verdict of leg 0 op 1; what ties it to the name rule:
#     the same key, bond, commission and builder LAND for named node 2.
#   - The vault and both stakers are single scenarios each: a kind-3
#     STAKE owner (the vault address needing its own name), the in-block
#     NAME_REGISTER-then-STAKE ordering, the vault's change output read by
#     an explorer, and the one-extra-w_read unit cost of a STAKE after H
#     are NOT exercised here.
#   - **The refusals are CheckTx's** (tip + 1 over committed state, node 1
#     only). A refused envelope never enters a block, so the in-block
#     refusal with its SYSTEM leg's writes rolled back is the unit tests'
#     (test_hf6_calls A4 / A7 / B5, test_v2_native §20).
#   - **The reason text is the engine's GENERIC exec verdict** of the
#     SYSTEM DELEGATE leg — "domain 0 op 2: runtime exec refused (rc -1)"
#     — which another DELEGATE refusal (an unknown or unbonded target, a
#     malformed row, a full validator, a new row below 100 NODUS) would
#     print too. What ties it to the name rule: the SAME builder and shape
#     LAND for node 5 between the vote and H, for named node 2 and for the
#     owner after H, the targets are ACTIVE genesis validators, and AMOUNT
#     is far above the 100-NODUS minimum.
#   - **The dnac_fee_info field is read through the CLI's state line**
#     ("delegate_name_required at tip + 1: 0|1"), a print of the decoder
#     nodus_dnac_delegate_name_rule_decode; the RPC's raw bytes and an
#     older node's "unknown" answer are the unit test's (test_hf4_names
#     client_decoders). The 0 / 1 reads are each one node (node 1) at one
#     tip; the H boundary is shown by "0 at tip + 1 < H" and "1 at tip >=
#     H", not at tip = H − 1 exactly.
#   - **The CLI's own refusal (9a) is asserted by its text and by the
#     absence of any submission line**, and only for a nameless non-owner;
#     the exemption path of the pre-check is exercised by 9f. The
#     pre-check's "unknown" (older node) and "validator row unreadable"
#     arms are not.
#   - **The owner is a single TEST key** compiled in by stagef_hf6_owner.sh
#     — production's owner is the K8 2-of-3 multisig (kind 3); a kind-3
#     owner's exemption (delegator_fp = the multisig address) is the unit
#     tests', not this scenario's.
#   - Same-block NAME_REGISTER / DELEGATE ordering, the 15-input funding
#     ceiling, the extra w_read and the fault classes are NOT exercised.
#   - Every proposal is kept away from an epoch boundary (cc_guard); a tip
#     crossing one while the CLI runs FAILs (false RED, never a false
#     PASS). Each generation edge is pumped to H − 7 and crossed idle;
#     param 17's H is crossed on pumped production.
#   - E = 15, grace 15, BPY 20: the LOGIC at those constants, nothing
#     about the production 720 / 720 / 6 307 200.
#   - rc 99 = SKIP, coverage that did not happen.
#   - Duration ≈ 400 blocks (JUDGMENT, not measured: test_cmt_hf7.sh's
#     path to generation 5 without its prune tail, plus param 17's grace).
#   - Run results: none — written against the source, NOT run by its
#     author.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# g5: ruleset-info, the vote path and the delegate flow were not checked
# through a split core — SKIP (99) in every split mode (the HF-6 rule).
stagef_split_skip_if --reason "HF-8 generation-5 scenario not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE (dnac.h), value exactly D
PARAM_RET16=16             # DNAC_CFG_RULESET_GEN_STORAGE — RETIRED
PARAM_DNR=17               # g5: DNAC_CFG_DELEGATE_NAME_REQUIRED (dnac.h), value 1
PARAM_HF6=18               # DNAC_CFG_RULESET_GEN_ROLES (dnac.h), value exactly D4
PARAM_HF7=22               # DNAC_CFG_RULESET_GEN_ROOTS (dnac.h), value exactly D5
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM
GEN_4=4                    # NODUS_RT_GEN_STORAGE
GEN_5=5                    # NODUS_RT_GEN_ROOTS (nodus_witness_runtime.h)
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
EDGE_MOD=8                 # H % E and A % E of params 18 / 22 (test_cmt_hf7.sh header)
# g5: param 17's vote carries room for the checks between the vote and H
# (a layout choice, not a timeout — a fleet that gets there first FAILS)
H_MARGIN=20
E_REQ=15
E="$E_REQ"
AMOUNT=100000000000        # g5: 1 000 NODUS (>= DNAC_MIN_DELEGATION, 100 NODUS)
OWNER_FUND=$(( AMOUNT + 200000000 ))   # g5: AMOUNT + 2 NODUS for the fee
NAME_B=hf8gfivetwo         # g5: node 2's name (11 characters: the 6+ price tier)
TARGET=1                   # g5: the delegations' target validator (node 1)
FUNDER=4                   # g5: pays the owner its funding coin
K8_OWNER=8eff7f418ab7a4432118ff99e21f2c3d1baf186200c148a3bba7d274499386ac970e267a9c9b3bbc05bfff1c62a72d63f72a555db780feeaaad4fb49ba9f7b89
OWNER=$(printf '%s' "${STAGEF_HF6_OWNER_FP_HEX:-$K8_OWNER}" | tr 'A-F' 'a-f')
OWN_KEYS="${STAGEF_HF6_OWNER_KEYS:-}"
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf8g5"
N="$STAGEF_COMMITTEE_SIZE"
# g5: the refusal a nameless non-owner DELEGATE must meet at CheckTx
# (header "THE RULE UNDER TEST")
REFUSE_CODE="dry run item code 7"
REFUSE_TEXT="domain 0 op 2: runtime exec refused (rc -1)"
CLI_NONAME="This identity has no chain name."
STATE_LINE="delegate_name_required at tip + 1:"
# rev3 (decision 2026-10-21-hf8-activation.md amendment): the STAKE and the
# vault-name rules switched on by the same param 17
REFUSE_TEXT_STAKE="domain 0 op 1: runtime exec refused (rc -1)"   # DNA_SYSRULE_STAKE = 1
CLI_NONAME_STAKE="This identity has no chain name. Staking needs one"
CLI_VAULT_PREH="a multisig vault can register a name only once HF-8"
BOND=200000000000000       # rev3: DNAC_HF6_STAKE_MIN_DEFAULT (2M NODUS), no param-19 row
NAME_V=hf8gfivevault       # rev3: the 2-of-3 vault's name (6+ tier)
NAME_M=hf8gfivemixed       # rev3: the mixed-funding attempt's name (never lands)
MSIG_DESC="$BASE_DIR/msig_genesis_2of3.desc"     # rev3: stagef_up_v2.sh's vault
MSIG_ADDR_FILE="$BASE_DIR/msig_genesis.addr"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN=$SRV" "STAGEF_NODUSCLI_BIN=$CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs the short-epoch"
        echo "       TEST-OWNER build of this tree; see the header"
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
for t in sqlite3 xxd ss openssl; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the HF-8 generation-5 checks need it"
        exit 99
    fi
done
if [ -z "$OWN_KEYS" ]; then
    echo "[SKIP] STAGEF_HF6_OWNER_KEYS is unset — the owner exemption (step 9f) needs a"
    echo "       TEST-OWNER build (stagef_hf6_owner.sh, header); with the K8 default no owner"
    echo "       delegation can be signed in the harness"
    exit 99
fi
if [ ! -s "$MSIG_DESC" ] || [ ! -s "$MSIG_ADDR_FILE" ]; then
    echo "[SKIP] no genesis 2-of-3 coin files ($MSIG_DESC, $MSIG_ADDR_FILE) — the vault-name"
    echo "       steps need them; the bring-up writes them only with a nodus-cli that has"
    echo "       \`msig address\` (stagef_up_v2.sh [warn])"
    exit 99
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "[SKIP] python3 is not installed — stagef_hf6_owner.sh (the fresh consensus key of"
    echo "       step 11) needs it"
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

# ── CAPABILITY GATE (FAIL, not skip) — test_cmt_hf7.sh's ─────────────
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
D4_DEC=$(sed -n 's/^  RULESET_GEN_ROLES  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D4_DEC="${D4_DEC%%$'\n'*}"
D5_DEC=$(sed -n 's/^  RULESET_GEN_ROOTS  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D5_DEC="${D5_DEC%%$'\n'*}"
[ -n "$D_DEC" ] && [ -n "$D4_DEC" ] && [ -n "$D5_DEC" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's chain-config usage does not name 'EVM_ACTIVE exactly <D>', 'RULESET_GEN_ROLES exactly <D4>' and 'RULESET_GEN_ROOTS exactly <D5>'"; }
[ "$D_DEC" -gt 0 ] 2>/dev/null && [ "$D4_DEC" -gt 0 ] 2>/dev/null && [ "$D5_DEC" -gt 0 ] 2>/dev/null \
    || die "a vote literal is not a positive int64 (D '$D_DEC', D4 '$D4_DEC', D5 '$D5_DEC')"
D_HEX=$(printf '%016x' "$D_DEC"); D4_HEX=$(printf '%016x' "$D4_DEC"); D5_HEX=$(printf '%016x' "$D5_DEC")
# test_cmt_hf8_delegate_name.sh's name-table probe: param 17 by name
probe=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose \
            --param DELEGATE_NAME_REQUIRED --value 1 --effective 1 2>&1 || true)
[[ "$probe" != *"Unknown param name"* && "$probe" == *"client_connect failed"* ]] || {
    printf '%s\n' "$probe" >&2
    die "the CLI did not pass DELEGATE_NAME_REQUIRED through its name table to the connect step — not an HF-8 build"; }
s19=$(sqlite3 -separator '|' "$ref_db0" \
    "SELECT (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_replay'),
            (SELECT COUNT(*) FROM pragma_table_info('v2_domain_heads') WHERE name='last_upd_hash'),
            (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_validator_roles');" \
    2>/dev/null || echo ERR)
[ "$s19" = "1|1|1" ] || die "node1's database is not schema S19 (v2_replay|last_upd_hash|v2_validator_roles = '$s19') — not an HF-7 build"
echo "[ok] capability gate: one build v$SRV_VER; D = 0x$D_HEX, D4 = 0x$D4_HEX, D5 = 0x$D5_HEX; schema S19; DELEGATE_NAME_REQUIRED by name"

# ── script-local helpers (test_cmt_hf7.sh's, unless "g5:") ──────────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }
fp_of()  { tr 'A-F' 'a-f' < "$1/nodus.fp" | tr -d '[:space:]'; }   # $1 = identity dir
pk_of()  { xxd -p -c 99999 "$(node_keys "$1")/nodus.pk"; }

# ── TEST-OWNER gate (FAIL — the operator asked for it by setting the keys) ─
[[ "$OWNER" =~ ^[0-9a-f]{128}$ ]] || die "STAGEF_HF6_OWNER_FP_HEX is not 128 hex characters ('$OWNER')"
[ -s "$OWN_KEYS/nodus.pk" ] && [ -s "$OWN_KEYS/nodus.sk" ] || die \
    "STAGEF_HF6_OWNER_KEYS=$OWN_KEYS holds no nodus.pk / nodus.sk — make it with stagef_hf6_owner.sh BEFORE the build"
[ "$(stat -c %s "$OWN_KEYS/nodus.pk")" = 2592 ] || die "$OWN_KEYS/nodus.pk is not 2592 bytes"
[ "$OWNER" != "$K8_OWNER" ] || die \
    "STAGEF_HF6_OWNER_KEYS is set but STAGEF_HF6_OWNER_FP_HEX is the K8 default — the build must compile the test owner (stagef_hf6_owner.sh prints the flags)"
own_kfp=$(stagef_sha3_512_hex "$OWN_KEYS/nodus.pk")
[ "$own_kfp" = "$OWNER" ] || die \
    "SHA3-512($OWN_KEYS/nodus.pk) = ${own_kfp:0:16}… is not STAGEF_HF6_OWNER_FP_HEX ${OWNER:0:16}… — the owner key and the compiled owner must be one identity"
for n in $(seq 1 "$N"); do
    [ "$(fp_of "$(node_keys "$n")")" != "$OWNER" ] || die "the test owner is node$n's own key — it must be a separate identity"
done
echo "[ok] TEST-OWNER gate: owner keys $OWN_KEYS, SHA3-512 = ${OWNER:0:16}…"

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

# test_cmt_hf8_delegate_name.sh's claim (v2-claim of a node's leaf)
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

# g5: a node's validator_id after the HF-6 edge (the validators row's
# pubkey_hash, joined to its roles row — test_hf6_edge.sh val_dump)
vid_of() {
    sqlite3 "$(db_of 1)" \
        "SELECT lower(hex(v.pubkey_hash)) FROM validators v
           JOIN v2_validator_roles r ON r.validator_id = v.pubkey_hash
          WHERE lower(hex(v.pubkey)) = '$(pk_of "$1")';" 2>/dev/null || echo ERR
}

# g5: one `v2-envelope delegate` from identity dir $1 to validator_id $2,
# submitted to node 1 (or --dry-run when $4 = dry). $3 = log, $5 = extra
# flag (--no-name-precheck or ""). Sets DG_RC, DG_INTENT, DG_STATE (the
# state line's value).
delegate() {
    local keys="$1" vid="$2" log="$3" mode="$4" extra="${5:-}" port args=()
    port=$(stagef_tcp_port 1)
    args=(v2-envelope delegate --keys "$keys" --validator "$vid" --amount "$AMOUNT")
    [ -n "$extra" ] && args+=("$extra")
    if [ "$mode" = dry ]; then args+=(--dry-run); else args+=(--submit "127.0.0.1:$port"); fi
    DG_RC=0
    "$CLI" -s 127.0.0.1 -p "$port" "${args[@]}" > "$log" 2>&1 || DG_RC=$?
    cat "$log"
    DG_INTENT=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$log")
    DG_STATE=$(sed -n "s/^$STATE_LINE \\([^ ]*\\).*/\\1/p" "$log" | head -1)
}

# g5: the rule's state at node 1's tip + 1, through a --dry-run of node 2
# (named or not — the state line is printed before any pre-check refusal)
rule_state() {
    local want="$1" label="$2" log="$LOGD/state_$2.log"
    delegate "$(node_keys 2)" "$VID_T" "$log" dry
    [ -n "$DG_STATE" ] || die "$label: the CLI printed no '$STATE_LINE' line (see $log) — not a build of this package"
    [ "$DG_STATE" = "$want" ] || die "$label: dnac_fee_info reports delegate_name_required '$DG_STATE', expected $want (see $log)"
    echo "[ok] $label: dnac_fee_info delegate_name_required = $DG_STATE at node1 tip + 1"
}

wait_intent() {
    local h wrc
    h=$(stagef_cmt_wait_row "$(db_of 1)" \
        "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$1';" 4) \
        && wrc=0 || wrc=$?
    [ "$wrc" = 1 ] && die "$2: the v2_intent_index row never appeared and the chain STALLED at $h"
    [ "$wrc" = 2 ] && die "$2: not included within 20 heights (tip $h) — dropped, not delayed"
    sqlite3 "$(db_of 1)" \
        "SELECT global_height FROM v2_intent_index WHERE lower(hex(intent_id)) = '$1' LIMIT 1;"
}

# g5: a generation-4 delegations row (delegator_fp $2, validator_id $3) on
# node $1 — its amount, "" when absent
deleg_amount() {
    sqlite3 "$(db_of "$1")" \
        "SELECT amount FROM delegations
          WHERE lower(hex(delegator_hash)) = '$2' AND lower(hex(validator_hash)) = '$3';" 2>/dev/null || echo ERR
}

pin_of() { fp_of "$(node_keys "$1")"; }

# rev3: vname_build LABEL EXPORT NAME --in NUL:AMT ... — `name register
# --msig` of the genesis 2-of-3 vault (session node 5, signs nothing).
# Sets VB_RC / VB_LOG.
vname_build() {
    local label="$1" exp="$2" nm="$3" port
    shift 3
    port=$(stagef_tcp_port 5)
    VB_LOG="$LOGD/vault_name_build_$label.log"; VB_RC=0
    "$CLI" -s 127.0.0.1 -p "$port" name register "$nm" --msig "$MSIG_DESC" \
        --keys "$(node_keys 5)" "$@" --export "$exp" --submit "127.0.0.1:$port" \
        > "$VB_LOG" 2>&1 || VB_RC=$?
    cat "$VB_LOG"
}

# rev3: consent_for OWNER_FP OUT — the fresh key KS consents to OWNER's
# STAKE (`validator consent`, expiry tip + 300 — within the 720 window)
consent_for() {
    local owner="$1" out="$2" log="$LOGD/consent_$(basename "$2").log" t
    t=$(tip_of 1)
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$KS_ID" validator consent --op stake \
        --owner "$owner" --expiry $(( t + 300 )) --out "$out" > "$log" 2>&1 \
        || { cat "$log" >&2; die "the consent of KS for ${owner:0:16}… was refused (see $log)"; }
    [ -s "$out" ] || die "the consent file $out is empty"
}

# rev3: stake2 KEYS CONSENT LOG [EXTRA] — `v2-envelope stake2` of BOND,
# submitted to node 1. Sets SK_RC, SK_INTENT, SK_STATE.
stake2() {
    local keys="$1" consent="$2" log="$3" extra="${4:-}" port args=()
    port=$(stagef_tcp_port 1)
    args=(v2-envelope stake2 --keys "$keys" --consent "$consent" --bond "$BOND" --commission 500)
    [ -n "$extra" ] && args+=("$extra")
    args+=(--submit "127.0.0.1:$port")
    SK_RC=0
    "$CLI" -s 127.0.0.1 -p "$port" "${args[@]}" > "$log" 2>&1 || SK_RC=$?
    cat "$log"
    SK_INTENT=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$log")
    SK_STATE=$(sed -n "s/^$STATE_LINE \\([^ ]*\\).*/\\1/p" "$log" | head -1)
}

require_name_refusal() {
    local what="$1" log="$2"
    [ "$DG_RC" != 0 ] || die "$what was ADMITTED after H (see $log)"
    grep -qF "$REFUSE_CODE" "$log" && grep -qF "$REFUSE_TEXT" "$log" \
        || die "$what was refused for ANOTHER reason (see $log) — expected '$REFUSE_CODE' and '$REFUSE_TEXT' (the SYSTEM DELEGATE exec verdict)"
    echo "[ok] $what REFUSED at CheckTx: $(grep -o 'CheckTx code [^"]*' "$log" | head -1)"
}

# ── 0/1. preconditions: a fresh cluster on this build ───────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
for n in $(seq 1 "$N"); do
    bl=$(grep -o 'HF-6 rule-set generation 4 vote D4 0x[0-9a-f]* (param 18 RULESET_GEN_ROLES, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-6 rule-set generation 4 vote D4 0x$D4_HEX (param 18 RULESET_GEN_ROLES, switch spec v1)" ] || die \
        "node$n's startup banner D4 line is '${bl:-none}', not the CLI's D4 0x$D4_HEX (param 18, switch spec v1)"
    bl=$(grep -o 'HF-7 rule-set generation 5 vote D5 0x[0-9a-f]* (param 22 RULESET_GEN_ROOTS, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-7 rule-set generation 5 vote D5 0x$D5_HEX (param 22 RULESET_GEN_ROOTS, switch spec v1)" ] || die \
        "node$n's startup banner D5 line is '${bl:-none}', not the CLI's D5 0x$D5_HEX (param 22, switch spec v1)"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM" "$PARAM_RET16" "$PARAM_DNR" "$PARAM_HF6" "$PARAM_HF7"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
for tb in v2_validator_roles delegations; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM $tb;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1's $tb is not empty — this scenario needs a fresh bring-up"
done
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
# rev3: the genesis 2-of-3 vault (nodes 2, 3, 4) and its one coin
# (test_cmt_hf7.sh's identity: height 0, output_index 0, tx_hash =
# nullifier) — single-use, so a spent coin needs a fresh bring-up
MSIG_ADDR=$(tr -d '[:space:]' < "$MSIG_ADDR_FILE")
[ "${#MSIG_ADDR}" = 128 ] || die "$MSIG_ADDR_FILE does not hold a 128-hex address"
gcoin=$(sqlite3 "$ref_db0" \
    "SELECT lower(hex(nullifier)) || ':' || amount FROM utxo_set
      WHERE owner = '$MSIG_ADDR' AND block_height = 0 AND output_index = 0
        AND tx_hash = nullifier LIMIT 1;" 2>/dev/null || true)
[ -n "$gcoin" ] || die "no genesis coin owned by the 2-of-3 address (already spent? — needs a fresh bring-up)"
GNUL="${gcoin%%:*}"; GAMT="${gcoin##*:}"
[ "${#GNUL}" = 128 ] || die "the genesis 2-of-3 coin '$gcoin' is malformed"
[ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM v2_names WHERE lower(hex(owner)) = '$MSIG_ADDR';" 2>/dev/null || echo ERR)" = 0 ] \
    || die "the vault already holds a name — this scenario needs a fresh bring-up"
stagef_cmt_pump_ready "$(db_of 1)" || die "the CLI-SPEND pump is not usable on this bring-up (reason above)"
stagef_sentinel SETUP_OK
stagef_cmt_diff_at_floor "pre-hf8g5" || exit 2

# ── 1. leaves; the owner's funding coin ─────────────────────────────
for k in 2 4 5 6 7; do claim_leaf "$(node_keys "$k")" 1; done
flog="$LOGD/fund_owner.log"; frc=0
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" v2-envelope spend \
    --keys "$(node_keys "$FUNDER")" --to "$OWNER" --amount "$OWNER_FUND" \
    --submit "127.0.0.1:$(stagef_tcp_port 1)" > "$flog" 2>&1 || frc=$?
cat "$flog"
[ "$frc" = 0 ] || die "node$FUNDER's funding spend to the test owner was refused (rc $frc, see $flog)"
f_intent=$(spend_intent "$flog")
[ "${#f_intent}" = 128 ] || die "the funding spend printed no intent_id (see $flog)"
fh=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$f_intent'
       AND lower(owner) = '$OWNER' AND amount = $OWNER_FUND;") && fwrc=0 || fwrc=$?
case "$fwrc" in
    0) ;;
    1) die "chain STALLED waiting for the test owner's funding coin (tip $fh)" ;;
    *) die "the test owner's funding coin was not included within 20 heights (tip $fh) — dropped, not delayed" ;;
esac
echo "[ok] the test owner holds a $OWNER_FUND-raw coin from node$FUNDER (tip $fh)"

# ── 2. the six votes to generation 5 (test_cmt_hf7.sh steps 2-3, 7) ──
cc_guard 1
H2=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF2_ACTIVE=1 effective H2=$H2"
propose HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
[ "$CC_CB" -lt "$H2" ] || die "the HF2 row committed at $CC_CB, not before its effective height $H2"
pump_to $(( H2 + 1 ))
wait_all $(( H2 + 1 ))

cc_guard 1
H3=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF3_ACTIVE=1 effective H3=$H3"
propose HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
[ "$CC_CB" -lt "$H3" ] || die "the HF3 row committed at $CC_CB, not before its effective height $H3"
pump_to $(( H3 + 1 ))
wait_all $(( H3 + 1 ))

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
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_EVM" "$H4"; done
echo "[ok] the EVM generation $GEN_EVM on 7/7 from HE=$HE"

cc_guard 1
H6=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( H6 % E )) != "$EDGE_MOD" ]; do H6=$(( H6 + 1 )); done   # rules (d), (e)
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROLES=$D4_DEC effective H6=$H6"
propose RULESET_GEN_ROLES "$D4_DEC" "$H6" "$LOGD/propose_hf6.log"
wait_cc_row "$PARAM_HF6" "$H6" "$D4_DEC" 20
[ "$CC_CB" -lt "$H6" ] || die "the RULESET_GEN_ROLES row committed at $CC_CB, not before its effective height $H6"
cross_edge hf6 "$H6"
HF6_LINE="HF-6: rule-set generation $GEN_EVM -> $GEN_4 and the validator migration at the end of height $(( H6 - 1 )) (param $PARAM_HF6 RULESET_GEN_ROLES, D4 0x$D4_HEX); height $H6 is judged under generation $GEN_4"
for n in $(seq 1 "$N"); do
    grep -qF "$HF6_LINE" "$(node_log "$n")" || die "node$n logged no '$HF6_LINE' line"
    require_gen "$n" "$GEN_4" "$H4"
done
echo "[ok] generation $GEN_4 on 7/7 from H6=$H6 (HF-6)"

cc_guard 1
A=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( A % E )) != "$EDGE_MOD" ]; do A=$(( A + 1 )); done     # rules (d), (e)
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROOTS=$D5_DEC effective A=$A"
propose RULESET_GEN_ROOTS "$D5_DEC" "$A" "$LOGD/propose_hf7.log"
wait_cc_row "$PARAM_HF7" "$A" "$D5_DEC" 20
[ "$CC_CB" -lt "$A" ] || die "the RULESET_GEN_ROOTS row committed at $CC_CB, not before its effective height $A"
cross_edge hf7 "$A"
HF7_LINE="HF-7: rule-set generation $GEN_4 -> $GEN_5 and the head last_upd_hash seed at the end of height $(( A - 1 )) (param $PARAM_HF7 RULESET_GEN_ROOTS, D5 0x$D5_HEX); height $A is judged under generation $GEN_5"
for n in $(seq 1 "$N"); do
    grep -qF "$HF7_LINE" "$(node_log "$n")" || die "node$n logged no '$HF7_LINE' line"
    require_gen "$n" "$GEN_5" "$H4"
done
echo "[ok] generation $GEN_5 on 7/7 from A=$A (HF-7)"

# g5: the build carries the test owner — every validator row's owner_fp
own_cnt=$(sqlite3 "$(db_of 1)" \
    "SELECT COUNT(*) || '|' || SUM(lower(hex(r.owner_fp)) = '$OWNER')
       FROM validators v JOIN v2_validator_roles r ON r.validator_id = v.pubkey_hash;" 2>/dev/null || echo ERR)
[ "$own_cnt" = "$N|$N" ] || die \
    "validator rows / rows owned by the test owner = '$own_cnt', expected '$N|$N' — the build's DNAC_HF6_FOUNDATION_OWNER is not STAGEF_HF6_OWNER_FP_HEX"
VID_T=$(vid_of "$TARGET"); VID_6=$(vid_of 6)
[ "${#VID_T}" = 128 ] && [ "${#VID_6}" = 128 ] || die "could not read node$TARGET's / node6's validator_id ('$VID_T' / '$VID_6')"
stagef_cmt_diff_at_floor "gen5" || exit 2
echo "[ok] 7/7 validators owned by the test owner; node$TARGET validator_id ${VID_T:0:16}…, node6 ${VID_6:0:16}…"

FP2=$(fp_of "$(node_keys 2)"); FP4=$(fp_of "$(node_keys 4)"); FP5=$(fp_of "$(node_keys 5)")
FP6=$(fp_of "$(node_keys 6)"); FP7=$(fp_of "$(node_keys 7)")

# ── 3. g5: the field before any param-17 row ────────────────────────
rule_state 0 "before-vote"

# ── 4. g5: a nameless non-owner DELEGATE lands before any param-17 row ─
delegate "$(node_keys 4)" "$VID_T" "$LOGD/delegate_node4_preH.log" submit
[ "$DG_RC" = 0 ] || die "node4's nameless DELEGATE was refused before any param-17 row (see $LOGD/delegate_node4_preH.log)"
[ "${#DG_INTENT}" = 128 ] || die "node4's delegate SUBMIT printed no intent_id"
h4=$(wait_intent "$DG_INTENT" "node4's pre-vote DELEGATE")
A4=$(deleg_amount 1 "$FP4" "$VID_T")
[ "$A4" = "$AMOUNT" ] || die "node4 -> node$TARGET delegation reads '$A4', want $AMOUNT"
echo "[ok] before any param-17 row: node4 (no name, not the owner) delegated $AMOUNT at height $h4"

# ── 5. g5: node 2 registers a name ──────────────────────────────────
nlog="$LOGD/register_${NAME_B}.log"
port1=$(stagef_tcp_port 1)
"$CLI" -s 127.0.0.1 -p "$port1" name register "$NAME_B" --keys "$(node_keys 2)" \
    --submit "127.0.0.1:$port1" > "$nlog" 2>&1 \
    || { cat "$nlog" >&2; die "name register $NAME_B from node2 failed (see $nlog)"; }
hn=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_names WHERE name = CAST('$NAME_B' AS BLOB)
       AND lower(hex(owner)) = '$FP2';") && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "the v2_names row '$NAME_B' -> node2 did not land (wait rc=$wrc, tip $hn)"
echo "[ok] '$NAME_B' registered to node2 (tip $hn)"

# ── 6. g5: the param-17 vote ────────────────────────────────────────
cc_guard 1
T_V17="$CCG_TIP"
H=$(( T_V17 + 1 + STAGEF_CC_GRACE_ERGONOMIC + H_MARGIN ))
echo "[ok] tip $T_V17 — node1 proposes DELEGATE_NAME_REQUIRED=1 effective H=$H"
propose DELEGATE_NAME_REQUIRED 1 "$H" "$LOGD/propose_dnr.log"
wait_cc_row "$PARAM_DNR" "$H" 1 20
R_V17="$CC_CB"
[ "$R_V17" -lt "$H" ] || die "the param-17 row committed at $R_V17, not before its effective height $H"
stagef_cmt_diff_at_floor "post-dnr-vote" || exit 2

# ── 7. g5: between the vote and H ───────────────────────────────────
[ $(( $(tip_of 1) + 1 )) -lt "$H" ] || die "node1's tip reached H-1 before the between-vote-and-H checks (widen H_MARGIN)"
rule_state 0 "vote-to-H"
delegate "$(node_keys 5)" "$VID_T" "$LOGD/delegate_node5_vote_to_H.log" submit
[ "$DG_RC" = 0 ] || die "node5's nameless DELEGATE was refused between the vote and H (see $LOGD/delegate_node5_vote_to_H.log)"
[ "${#DG_INTENT}" = 128 ] || die "node5's delegate SUBMIT printed no intent_id"
h5=$(wait_intent "$DG_INTENT" "node5's between-vote-and-H DELEGATE")
[ "$h5" -lt "$H" ] || die "node5's delegation applied at $h5 >= H=$H — the between-vote check did not run below H (widen H_MARGIN)"
echo "[ok] vote committed, below H: node5 (no name) delegated at height $h5 < H=$H"
# rev3: below H the vault's name registration is refused by the CLI (the
# chain admits a multisig registration only from H — rtn_name_owner)
vname_build preH "$LOGD/vault_name_preH.export" "$NAME_V" --in "$GNUL:$GAMT"
[ "$VB_RC" != 0 ] || die "the vault's name registration was BUILT below H (see $VB_LOG)"
grep -qF "$CLI_VAULT_PREH" "$VB_LOG" \
    || die "the pre-H vault registration failed, but not with '$CLI_VAULT_PREH' (see $VB_LOG)"
[ ! -s "$LOGD/vault_name_preH.export" ] || die "an export was written below H"
[ $(( $(tip_of 1) + 1 )) -lt "$H" ] || die "node1's tip reached H-1 during the between-vote-and-H checks (widen H_MARGIN)"
echo "[ok] below H: the CLI refused the vault's name registration (delegate_name_required 0)"

# ── 8. g5: cross H ──────────────────────────────────────────────────
pump_to $(( H + 1 ))
wait_all $(( H + 1 ))
stagef_sentinel TARGET_REACHED
for hh in $(( H - 1 )) "$H" $(( H + 1 )); do diff_at "$hh" "hf8g5-at-height-$hh"; done
echo "[ok] 7/7 identical blocks AT H-1/H/H+1 (H=$H)"
rule_state 1 "after-H"
A_OWN_PRE=$(deleg_amount 1 "$OWNER" "$VID_T")
case "$A_OWN_PRE" in ''|ERR|*[!0-9]*) die "the owner's node$TARGET delegation row is unreadable ('$A_OWN_PRE') — the HF-6 migration writes one" ;; esac

# ── 9. g5: after H ──────────────────────────────────────────────────
# a. the CLI's own refusal (no flag): nothing submitted
delegate "$(node_keys 7)" "$VID_T" "$LOGD/delegate_node7_cli.log" submit
[ "$DG_RC" != 0 ] || die "node7's nameless DELEGATE passed the CLI pre-check after H (see $LOGD/delegate_node7_cli.log)"
grep -qF "$CLI_NONAME" "$LOGD/delegate_node7_cli.log" \
    || die "node7's DELEGATE failed, but not with the CLI's '$CLI_NONAME' (see $LOGD/delegate_node7_cli.log)"
! grep -q "dnac_spend\|CheckTx" "$LOGD/delegate_node7_cli.log" \
    || die "node7's pre-check refusal still reached the node (a submission line in $LOGD/delegate_node7_cli.log)"
echo "[ok] node7 (nameless, not the owner): the CLI refused before signing — '$CLI_NONAME'"
# b. the same at CheckTx
delegate "$(node_keys 7)" "$VID_T" "$LOGD/delegate_node7_postH.log" submit --no-name-precheck
require_name_refusal "node7's nameless NEW DELEGATE" "$LOGD/delegate_node7_postH.log"
# c. node 4's TOP-UP
delegate "$(node_keys 4)" "$VID_T" "$LOGD/delegate_node4_topup_postH.log" submit --no-name-precheck
require_name_refusal "node4's nameless TOP-UP" "$LOGD/delegate_node4_topup_postH.log"
# d. node 6's NODE key to its own validator — not the owner
delegate "$(node_keys 6)" "$VID_6" "$LOGD/delegate_node6_nodekey.log" submit --no-name-precheck
require_name_refusal "node6's NODE-key delegation to its own validator" "$LOGD/delegate_node6_nodekey.log"
# e. node 2 (named)
delegate "$(node_keys 2)" "$VID_T" "$LOGD/delegate_node2_named.log" submit
[ "$DG_RC" = 0 ] || die "node2's NAMED DELEGATE was refused after H (see $LOGD/delegate_node2_named.log)"
h2=$(wait_intent "$DG_INTENT" "node2's named DELEGATE")
[ "$h2" -ge "$H" ] || die "node2's delegation applied at $h2 < H=$H"
# f. the OWNER (nameless) to its own validator — exempt, pre-check on
delegate "$OWN_KEYS" "$VID_T" "$LOGD/delegate_owner.log" submit
[ "$DG_RC" = 0 ] || die "the OWNER's nameless delegation to its own validator was refused after H (see $LOGD/delegate_owner.log)"
h_own=$(wait_intent "$DG_INTENT" "the owner's DELEGATE")
[ "$h_own" -ge "$H" ] || die "the owner's delegation applied at $h_own < H=$H"
echo "[ok] after H: node2 (named) delegated at $h2, the owner (nameless, exempt) at $h_own"

# g. 7/7, two heights on
stagef_sentinel ASSERT_RUN
t=$(tip_of 1)
hmax=$h2; [ "$h_own" -gt "$hmax" ] && hmax=$h_own
[ "$t" -gt "$hmax" ] || t=$hmax
pump_to $(( t + 2 ))
wait_all $(( t + 2 ))
A_OWN_WANT=$(( A_OWN_PRE + AMOUNT ))
for n in $(seq 1 "$N"); do
    a2=$(deleg_amount "$n" "$FP2" "$VID_T"); ao=$(deleg_amount "$n" "$OWNER" "$VID_T")
    a4=$(deleg_amount "$n" "$FP4" "$VID_T"); a5=$(deleg_amount "$n" "$FP5" "$VID_T")
    a6=$(deleg_amount "$n" "$FP6" "$VID_6"); a7=$(deleg_amount "$n" "$FP7" "$VID_T")
    [ "$a2" = "$AMOUNT" ] || die "node$n: node2 -> node$TARGET reads '$a2', want $AMOUNT"
    [ "$ao" = "$A_OWN_WANT" ] || die "node$n: owner -> node$TARGET reads '$ao', want $A_OWN_PRE + $AMOUNT = $A_OWN_WANT"
    [ "$a4" = "$AMOUNT" ] || die "node$n: node4 -> node$TARGET reads '$a4', want its pre-H $AMOUNT (the refused top-up must not land)"
    [ "$a5" = "$AMOUNT" ] || die "node$n: node5 -> node$TARGET reads '$a5', want $AMOUNT"
    [ -z "$a6" ] || die "node$n holds a node6-key -> node6 delegation ('$a6') — the refused envelope landed"
    [ -z "$a7" ] || die "node$n holds a node7 -> node$TARGET delegation ('$a7') — the refused envelope landed"
done
echo "[ok] 7/7: node2 and the owner delegated; node4's row unchanged; no node6-key or node7 row"

# ── 10. rev3: a VAULT registers a name after H (rule 3) ─────────────
# a. a member's coin among the inputs: the co-signer's own input check
#    (`msig sign`, msig_inputs_verify on its pinned node) refuses to sign
mixed_coin=$(sqlite3 "$(db_of 2)" \
    "SELECT lower(hex(nullifier)) || ':' || amount FROM utxo_set
      WHERE owner = '$FP2' AND token_id = zeroblob(64) AND amount > 0
        AND unlock_block <= $(tip_of 2)
      ORDER BY amount DESC, nullifier LIMIT 1;" 2>/dev/null || true)
[ -n "$mixed_coin" ] || die "node2 holds no spendable native coin for the mixed-funding case"
EXPM="$LOGD/vault_name_mixed.export"
vname_build mixed "$EXPM" "$NAME_M" --in "$GNUL:$GAMT" --in "$mixed_coin"
[ "$VB_RC" = 0 ] || die "the mixed-funding vault registration could not be BUILT (see $VB_LOG)"
mslog="$LOGD/msig_sign_vault_mixed_node2.log"; msrc=0
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 2)" msig sign --pin "$(pin_of 2)" \
    --keys "$(node_keys 2)" --in "$EXPM" --out "$LOGD/sig_vault_mixed_node2" > "$mslog" 2>&1 || msrc=$?
cat "$mslog"
[ "$msrc" != 0 ] || die "node2 SIGNED a vault name registration funded by its own coin (see $mslog)"
grep -qF "is not an unspent coin of this vault" "$mslog" \
    || die "node2 refused to sign the mixed-funding export, but not for the member's coin (see $mslog)"
[ ! -s "$LOGD/sig_vault_mixed_node2" ] || die "node2 wrote a signature file for the mixed-funding export"
echo "[ok] a member's coin among a vault name registration's inputs: the co-signer refused to sign"
# b. the vault's own coin only: nodes 2 and 3 sign, combine, it LANDS
EXPV="$LOGD/vault_name.export"
vname_build vault "$EXPV" "$NAME_V" --in "$GNUL:$GAMT"
[ "$VB_RC" = 0 ] || die "the vault name registration could not be BUILT after H (see $VB_LOG)"
for n in 2 3; do
    vslog="$LOGD/msig_sign_vault_node$n.log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" msig sign --pin "$(pin_of "$n")" \
        --keys "$(node_keys "$n")" --in "$EXPV" --out "$LOGD/sig_vault_node$n" > "$vslog" 2>&1 \
        || { cat "$vslog" >&2; die "node$n could not sign the vault name registration (see $vslog)"; }
    grep -qF "signing a NAME REGISTRATION by 2-of-3 vault $MSIG_ADDR" "$vslog" \
        || die "node$n's msig sign did not show the vault NAME_REGISTER read-back (see $vslog)"
done
vclog="$LOGD/msig_combine_vault.log"; vcrc=0
"$CLI" msig combine --in "$EXPV" --sig "$LOGD/sig_vault_node2" --sig "$LOGD/sig_vault_node3" \
    --keys "$(node_keys 5)" --submit "127.0.0.1:$(stagef_tcp_port 1)" > "$vclog" 2>&1 || vcrc=$?
cat "$vclog"
[ "$vcrc" = 0 ] || die "the vault's name registration was refused after H (see $vclog)"
hv=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_names WHERE name = CAST('$NAME_V' AS BLOB)
       AND lower(hex(owner)) = '$MSIG_ADDR';") && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "the v2_names row '$NAME_V' -> the vault did not land (wait rc=$wrc, tip $hv)"
[ "$hv" -ge "$H" ] || die "the vault's name landed at $hv < H=$H"
wait_all "$hv"
for n in $(seq 1 "$N"); do
    lklog="$LOGD/lookup_${NAME_V}_node$n.log"; lkrc=0
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" name lookup "$NAME_V" > "$lklog" 2>&1 || lkrc=$?
    [ "$lkrc" = 0 ] || { cat "$lklog" >&2; die "node$n: name lookup $NAME_V exited $lkrc"; }
    lo=$(sed -n 's/^owner=\([0-9a-f]*\) .*/\1/p' "$lklog")
    [ "$lo" = "$MSIG_ADDR" ] || { cat "$lklog" >&2; die "node$n: '$NAME_V' resolves to '${lo:0:16}…', not the vault ${MSIG_ADDR:0:16}…"; }
done
[ "$(sqlite3 "$(db_of 1)" "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(nullifier)) = '$GNUL';" 2>/dev/null || echo ERR)" = 0 ] \
    || die "the vault's genesis coin is still unspent after its name registration landed"
echo "[ok] after H: the 2-of-3 vault registered '$NAME_V' at height $hv; name lookup returns the vault address on 7/7"

# ── 11. rev3: STAKE needs the STAKER's name after H (rule 2) ────────
# a fresh consensus key KS (the harness's own identity maker), consenting
# to each owner; the same key, bond and shape for both stakers
kslog="$LOGD/stakekey_gen.log"
bash "$S_DIR/stagef_hf6_owner.sh" "$LOGD/stakekey" "$SRV" > "$kslog" 2>&1 \
    || { cat "$kslog" >&2; die "could not generate the fresh consensus key for the STAKE steps (see $kslog)"; }
KS_ID="$LOGD/stakekey/identity"
[ -s "$KS_ID/nodus.pk" ] && [ -s "$KS_ID/nodus.sk" ] || die "the fresh consensus key has no nodus.pk / nodus.sk"
KS_FP=$(fp_of "$KS_ID")
for n in $(seq 1 "$N"); do
    [ "$(fp_of "$(node_keys "$n")")" != "$KS_FP" ] || die "the fresh consensus key is node$n's key"
done
# a. node 7 (nameless) WITHOUT --no-name-precheck: the CLI refuses
consent_for "$FP7" "$LOGD/consent_node7"
stake2 "$(node_keys 7)" "$LOGD/consent_node7" "$LOGD/stake2_node7_cli.log"
[ "$SK_RC" != 0 ] || die "node7's nameless STAKE passed the CLI pre-check after H (see $LOGD/stake2_node7_cli.log)"
grep -qF "$CLI_NONAME_STAKE" "$LOGD/stake2_node7_cli.log" \
    || die "node7's STAKE failed, but not with the CLI's '$CLI_NONAME_STAKE' (see $LOGD/stake2_node7_cli.log)"
! grep -q "dnac_spend\|CheckTx" "$LOGD/stake2_node7_cli.log" \
    || die "node7's STAKE pre-check refusal still reached the node (see $LOGD/stake2_node7_cli.log)"
[ "$SK_STATE" = 1 ] || die "the stake2 state line reads '$SK_STATE' after H, expected 1"
echo "[ok] node7 (nameless staker): the CLI refused before signing"
# b. the same at CheckTx
stake2 "$(node_keys 7)" "$LOGD/consent_node7" "$LOGD/stake2_node7_postH.log" --no-name-precheck
[ "$SK_RC" != 0 ] || die "node7's nameless STAKE was ADMITTED after H (see $LOGD/stake2_node7_postH.log)"
grep -qF "$REFUSE_CODE" "$LOGD/stake2_node7_postH.log" && grep -qF "$REFUSE_TEXT_STAKE" "$LOGD/stake2_node7_postH.log" \
    || die "node7's nameless STAKE was refused for ANOTHER reason (see $LOGD/stake2_node7_postH.log) — expected '$REFUSE_CODE' and '$REFUSE_TEXT_STAKE'"
echo "[ok] node7's nameless STAKE REFUSED at CheckTx (the SYSTEM STAKE exec verdict)"
# c. node 2 (named) with the same key and bond: it LANDS
consent_for "$FP2" "$LOGD/consent_node2"
stake2 "$(node_keys 2)" "$LOGD/consent_node2" "$LOGD/stake2_node2_named.log"
[ "$SK_RC" = 0 ] || die "node2's NAMED STAKE was refused after H (see $LOGD/stake2_node2_named.log)"
[ "${#SK_INTENT}" = 128 ] || die "node2's stake2 SUBMIT printed no intent_id"
hs=$(wait_intent "$SK_INTENT" "node2's named STAKE")
[ "$hs" -ge "$H" ] || die "node2's STAKE applied at $hs < H=$H"
wait_all "$hs"
KS_PK=$(xxd -p -c 99999 "$KS_ID/nodus.pk")
for n in $(seq 1 "$N"); do
    so=$(sqlite3 "$(db_of "$n")" \
        "SELECT COUNT(*) FROM validators v JOIN v2_validator_roles r ON r.validator_id = v.pubkey_hash
          WHERE lower(hex(r.owner_fp)) = '$FP2' AND lower(hex(v.pubkey)) = '$KS_PK';" 2>/dev/null || echo ERR)
    [ "$so" = 1 ] || die "node$n: the new validator (owner node2, key KS) reads '$so' rows, want 1"
    s7=$(sqlite3 "$(db_of "$n")" \
        "SELECT COUNT(*) FROM v2_validator_roles WHERE lower(hex(owner_fp)) = '$FP7';" 2>/dev/null || echo ERR)
    [ "$s7" = 0 ] || die "node$n holds a validator owned by node7 ('$s7') — the refused STAKE landed"
done
echo "[ok] after H: node2 (named) staked KS at height $hs, on 7/7; no node7-owned validator"

stagef_cmt_diff_at_floor "post-hf8g5" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | HF-6 $H6 | HF-7 A $A | node4 pre-vote at $h4 | '$NAME_B' at $hn"
echo "       | param-17 vote tip $T_V17, row commit $R_V17, H=$H | node5 at $h5 | node2 at $h2 | owner at $h_own"
echo "       | vault '$NAME_V' at $hv | node2's STAKE at $hs"
echo "[PASS] HF-8 on generation 5: DELEGATE_NAME_REQUIRED voted at H=$H; dnac_fee_info reported 0 before H and 1"
echo "       after it; nameless non-owner delegations landed before H and were REFUSED after it at CheckTx"
echo "       (new, top-up, a node key to its own validator) and by the CLI's pre-check; a named delegator and"
echo "       the validator's owner landed 7/7; a 2-of-3 vault registered a name after H (lookup = the vault"
echo "       on 7/7) and a member's coin was refused by the co-signer; a nameless STAKE was refused (CLI and"
echo "       CheckTx) and a named one landed 7/7; blocks AT H-1/H/H+1 identical on 7/7."
echo "       ONE build, E=15 / grace 15 / BPY 20 — the LOGIC only (header)."
