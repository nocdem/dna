#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_mldsa.sh — the ML-DSA-87 verification precompile's ACTIVATION
# on a chain: chain-config param 23 MLDSA_ACTIVE voted on a fresh 7-node
# chain climbed to the EVM generation; the precompile's address behaves as
# an ordinary account below the activation height H and verifies from H
# on — in the node's simulation AND in executed transactions — with one
# node DOWN across H that catches up afterwards (standalone — NOT in the
# sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/decisions/2026-10-21-mldsa87-evm-
# precompile.md (items 1-8, "Measurement", "Activation route and grace":
# Route B — an engine fact from param 23, the EVM rule-set tuple
# unchanged; grace ERGONOMIC; conditions "H−1/H, restart and replay
# tests"; "Vote literal tag and preimage" — DECIDED by the operator
# 2026-10-22); design docs/plans/2026-10-21-mldsa87-evm-precompile-
# design.md rev 2. TEMPLATE: test_cmt_evm_lib.sh — its gate, its vote
# helpers (cc_guard / propose / wait_cc_row / ruleset_info / require_gen /
# cross_edge), its generation 1 -> 2 -> 3 climb and its EVM helpers;
# test_cmt_evm.sh — second_proposal (the single-use check);
# test_v2_restart_convergence.sh — stagef_stop_node / stagef_spawn_node.
# Every new part is marked "ml:".
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): one version banner for the server and the
#      CLI; the CLI's chain-config usage names "MLDSA_ACTIVE exactly <D>"
#      and "EVM_ACTIVE exactly <D>"; D (param 23) equals the literal this
#      script re-derives with openssl from the DECIDED 115-byte preimage
#      (TAG16("NDS.MLDSAACT.v1") ‖ SHA3-512("NDS.EVMMLDSA87.v1")[0..32] ‖
#      u32 19 ‖ "nodus.evm.attest.v1" ‖ u32 5 ‖ u64 25000, 12, 65536, 2592,
#      4627; first 8 digest bytes big-endian, top bit cleared) AND the
#      oracle's (shared/dnac/tests/nodus_mldsa_activation_oracle.py); every
#      node logged "ML-DSA-87 precompile vote D 0x<D> (param 23
#      MLDSA_ACTIVE)" at start-up (its own re-derivation passed). The probe
#      fixture fixtures/evm/MldsaProbe.hex and the precompile source the
#      test vectors are read from are tracked by git and UNMODIFIED against
#      HEAD. The test vectors (shared/evm/evm_precompile.c MLDSA_KAT_PK /
#      _SIG / _SIG_EMPTYCTX / _MSG / _ADDR) have their declared widths and
#      MLDSA_KAT_ADDR = SHA3-512(pk)[0..32] computed here with openssl.
#   1. Fresh chain (no param 7 / 8 / 9 / 14 / 23 row); node 1 claims its
#      leaf (the pump runs on node 5's leaf).
#   2. HF2_ACTIVE, HF3_ACTIVE, RULESET_GEN2 voted and crossed (the library
#      scenario's path). ml: NEGATIVE — under generation 2 an MLDSA_ACTIVE
#      proposal from node 2's seat (a valid effective height) is refused by
#      the 6 other seats with "stateful rules rejected" (rule (b): the EVM
#      generation must be in force) and no param-23 row exists on 7/7.
#      EVM_ACTIVE voted and crossed: generation 3 on 7/7.
#   3. Node 1 deposits; ml: MldsaProbe deployed (status 1, op CREATE).
#   4. ml: BEFORE THE VOTE (generation 3, no param-23 row): the simulation
#      of probe(precompile, valid input) answers (true, 0, 0x00…00) — the
#      address is an ordinary account; record(precompile, valid input) is
#      executed with status 1 and the contract stores (calls 1, lastOk
#      true, lastLen 0, lastWord 0).
#   5. ml: node 1 proposes MLDSA_ACTIVE = D effective HM (ERGONOMIC grace;
#      HM − 1 not an epoch boundary): the row is identical on 7/7 and
#      committed below HM. NEGATIVE — a SECOND MLDSA_ACTIVE proposal from
#      node 3's seat is refused by the 6 other seats with "stateful rules
#      rejected" (rule (a), single use).
#   6. ml: between the vote and HM: record(valid) executed at a height
#      < HM − 2 stores (calls 2, true, 0, 0) — a committed row whose height
#      is not reached does not switch the precompile on.
#   7. ml: node 7 is STOPPED (SIGKILL) below HM − 2 and stays down until
#      step 10. The chain crosses HM on 6/7. The simulation is read at two
#      EXACT tips on node 1 (the node simulates at tip + 1,
#      nodus_witness_handlers.c handle_evm_call): at tip HM − 2 (simulated
#      height HM − 1) probe(valid) = (true, 0, 0x00…00); at tip HM − 1
#      (simulated height HM) probe(valid) = (true, 32, the signer's
#      address). The answer flips between two consecutive heights.
#   8. ml: FROM HM, executed (each receipt at a height >= HM): record(valid)
#      stores (calls 3, true, 32, the signer's address);
#      record(empty-context signature over the same message) stores
#      (calls 4, true, 0, 0) — the precompile verifies under
#      "nodus.evm.attest.v1" only; record(7218 bytes, one short of pk ‖
#      sig) stores (calls 5, true, 0, 0) — malformed input is "invalid",
#      the call still succeeds. probe(empty-context) simulated = (true, 0,
#      0x00…00).
#   9. ml: node 7 is restarted (stagef_spawn_node), logs its D line again,
#      reaches the tip of the others, and then: blocks AT HM − 1 / HM /
#      HM + 1 identical 7/7 (stagef_diff.sh --at-height); the param-23 row
#      identical 7/7; the whole EVM state (accounts, slots — the probe's
#      four stored values included —, code, receipts, logs, per-height
#      EVM roots) identical 7/7; the supply invariant with exact values on
#      7/7; stagef_cmt_diff_at_floor 7/7. Node 7 did not run the blocks
#      HM − 2 … tip while they were made; it holds them now with the same
#      results (the harness has no state sync: grep -i 'statesync'
#      stagef_env.sh stagef_up_v2.sh finds nothing).
#
# WHAT IT REQUIRES
#   Compile flags — ONE short-epoch + short-grace build of THIS tree,
#   nodus-server AND nodus-cli from the SAME build dir, with
#   NODUS_EVM_ENABLED (the standalone non-Windows default,
#   nodus/CMakeLists.txt):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9, 23 ERGONOMIC, param 14 SAFETY — dnac.h).
#   Environment, exported BEFORE stagef_up_v2.sh unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     read by THIS script only:
#       STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#   The script SETS STAGEF_PUMP_FUNDER_NODE=5 before sourcing stagef_env.sh
#   (an exported value is overridden). Leave STAGEF_PAYOUT_INTERVAL_EPOCHS
#   and STAGEF_MODE unset (combined mode; every split mode SKIPs).
#   Tools: sqlite3, bc, xxd, openssl with SHA3-512, ss, git, python3. NO
#   solc: fixtures/evm/MldsaProbe.hex is committed bytecode.
#   Exact command sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-mldsa-e15 -DCMAKE_C_FLAGS="$F"
#     make -C <TREE>/nodus/build-mldsa-e15 -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-mldsa-e15/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-mldsa-e15/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_mldsa.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, STAGEF_EPOCH_LENGTH
#   or the genesis epoch_length != 15, a grace variable != 15, not a Comet
#   cluster, no $BASE_DIR/v2_genesis.conf, a tool missing, the probe
#   fixture or the precompile source missing, the tree not a git checkout,
#   any split STAGEF_MODE. A skip is not a pass.
#   FAIL (rc 1) on the capability gate, on a fixture / source that is
#   untracked or modified against HEAD, on a chain that already holds a
#   param 7 / 8 / 9 / 14 / 23 row (every switch is one-way — it needs a
#   fresh bring-up), and on any assertion.
#
# WHAT IT LEAVES BEHIND
#   HF-2, HF-3, rule-set generation 2, the EVM generation 3 + EVM domain
#   and the ML-DSA precompile — all one-way; five chain_config_history
#   rows (params 7, 8, 9, 14, 23). The leaves of nodes 1 and 5 (the pump)
#   claimed. In the EVM domain: node 1's account and the MldsaProbe
#   (calls 5). Node 7 was SIGKILLed once and restarted with
#   stagef_spawn_node (its new pid appended to pids.txt; its log carries
#   two start-ups). $BASE_DIR/mldsa/ (every CLI log). Tear down with
#   stagef_down.sh before re-running.
#
# HOW IT CAN LIE
#   - **Generation 3, not 5.** The live testnet runs generation 5 (HF-6,
#     HF-7, HF-8); this chain stops at the EVM generation. Rule (b) admits
#     generations 3, 4 and 5 alike (nodus_witness_chain_config.c,
#     CC_PARAM_MLDSA_ACTIVE stateful case); only 3 is exercised here.
#   - **E = 15, grace 15/15, BPY 20 prove the LOGIC**, nothing about 720 /
#     17 280 / 6 307 200. The EVM vote's H is decided by the F5 window
#     floor (initial_height + 256 + 5), so ~250 pump spends carry the
#     chain there.
#   - **The test vectors are the tree's own** (evm_precompile.c PC_KATS32's
#     arrays, made by the tree's signer — self-consistent, not external;
#     the external layer is the NIST ACVP fixture in shared/evm make
#     test). Read here with awk from the C source; a changed layout of
#     those arrays FAILs the width checks (false RED), never passes.
#   - **The D cross-check compares three derivations by ONE author** (this
#     script's openssl, the oracle, the C start-up check): agreement proves
#     they agree on the DECIDED layout, not an independent pin. The
#     decision file requires a re-derivation by someone who has not read
#     the C before any vote on the live chain.
#   - **The exact-tip reads race block production.** Each is taken right
#     after node 1 reaches the tip; the reply names the tip it simulated
#     on ("ok at height T"), and a T other than the one asked for FAILs
#     (false RED, never a PASS). On an idle chain the window is the
#     60-second empty-block interval (nodus_witness_cmt_node.c).
#   - **The executed calls do not land AT HM − 1 and HM exactly**: the
#     pre-activation record lands at some height < HM − 2, the post-
#     activation ones at heights >= HM (asserted from each receipt). The
#     exact-height flip is shown by the simulation (step 7) and by the
#     block identity at HM − 1 / HM / HM + 1 on 7/7 — the simulation and
#     the block path read the SAME reader (nodus_rt_evm_mldsa_active_at,
#     nodus_witness_rt_evm.c simulate and nodus_witness_v2_apply.c
#     env_evm_facts), which is a code fact, not something this run shows.
#   - **Gas is not asserted, and it CANNOT show the precompile here.**
#     Every record() carries ~7.3 KB of calldata, so its gas used is the
#     EIP-7623 calldata floor (shared/evm/evm_tx.c: used = max(execution,
#     21 000 + 10 x tokens)), not the execution: record(valid) used 311 960
#     both before the vote and from HM (the floor of its 7 364-byte
#     calldata, 120 zero + 7 244 non-zero bytes = 29 096 tokens, computed
#     2026-10-22). The precompile's 25 000 + 12 per word is the unit test's
#     (shared/evm tests/test_mldsa_precompile.c); here only the stored
#     results show what ran.
#   - **Node 7's catch-up path is not asserted** (block sync vs consensus
#     catch-up): what is asserted is that, once back, it holds the same
#     blocks and the same EVM state. A node that rejoined with a wrong
#     state FAILs the 7/7 comparisons.
#   - **A restart with the precompile already active on disk** is node 7's
#     restart (step 9); a restart of every node at once and an OLD binary
#     refusing param 23 are not exercised (the latter: test_cc_unknown_
#     param in ctest).
#   - **One machine; rc 99 = SKIP, coverage that did not happen.**
#   - Duration ≈ 320 blocks (JUDGMENT, not measured: the EVM window floor
#     ≈ 262 pumped heights, the param-23 grace ≈ 30 heights, ~10 idle
#     blocks around HM at the 60-second empty-block interval).
#   - Run results: 2026-10-22, session "evm" — PASS (rc 0) at 1ca261d91
#     (local main a87ef9de3 + the ML-DSA precompile + param 23 + this
#     scenario), short-epoch build E = 15 / BPY 20 / grace 15/15, combined
#     mode, fresh bring-up: EVM HE 262; vote committed 272 -> HM 304; node 7
#     stopped at 275; simulation inactive on tip 302, the signer on tip
#     303; records executed at 268 / 274 (empty) and 306 (signer), 308 /
#     310 (empty); node 7 back and caught up to 311; final floor 311
#     identical 7/7. The LOGIC only.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
STAGEF_PUMP_FUNDER_NODE=5
export STAGEF_PUMP_FUNDER_NODE
. "$(dirname "$0")/../stagef_env.sh"
stagef_split_skip_if --reason "ML-DSA activation scenario not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
FIX_DIR="$S_DIR/fixtures/evm"
PC_SRC="$STAGEF_REPO_ROOT/shared/evm/evm_precompile.c"     # ml: the test vectors
ORACLE="$STAGEF_REPO_ROOT/shared/dnac/tests/nodus_mldsa_activation_oracle.py"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE (dnac.h), value exactly D
PARAM_MLDSA=23             # ml: DNAC_CFG_MLDSA_ACTIVE (dnac.h), value exactly DM
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM (nodus_witness_runtime.h)
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
MLDSA_MARGIN=12            # ml: room for steps 5-7 between the vote and HM − 7
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
E_REQ=15
E="$E_REQ"
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/mldsa"
N="$STAGEF_COMMITTEE_SIZE"
VICTIM="$N"                # ml: the node kept down across HM
DOWN=""                    # ml: the node currently down ("" = none)
DEP_RAW=100000000000       # 1 000 NODUS deposited by node 1
Q=10000000000              # wei per raw unit
GAS_DEPLOY=5000000
GAS_SEND=1000000
GAS_CALL=1000000
OP_CALL=01; OP_CREATE=02; OP_DEPOSIT=03
ZERO64=0000000000000000000000000000000000000000000000000000000000000000
# ml: the precompile's widths (shared/evm/evm.h EVM_MLDSA87_PK_BYTES /
# _SIG_BYTES; the decision's item 1 layout pk ‖ sig ‖ msg)
PK_LEN=2592; SIG_LEN=4627

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
for t in sqlite3 bc xxd openssl ss git python3; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the ML-DSA activation checks need it"
        exit 99
    fi
done
if [ "$(printf 'abc' | openssl dgst -sha3-512 2>/dev/null | awk '{print $NF}')" != \
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" ]; then
    echo "[SKIP] this openssl has no working SHA3-512 (D, the addresses and the receipt digest need it)"
    exit 99
fi
for f in "$FIX_DIR/MldsaProbe.hex" "$PC_SRC" "$ORACLE"; do
    if [ ! -s "$f" ]; then
        echo "[SKIP] $f is missing"
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
usage_out=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
D_DEC=$(sed -n 's/^  EVM_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D_DEC="${D_DEC%%$'\n'*}"
[ -n "$D_DEC" ] || { printf '%s\n' "$usage_out" >&2; die "the CLI's chain-config usage names no 'EVM_ACTIVE exactly <D>'"; }
D_HEX=$(printf '%016x' "$D_DEC")
DM_DEC=$(sed -n 's/^  MLDSA_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
DM_DEC="${DM_DEC%%$'\n'*}"
[ -n "$DM_DEC" ] || { printf '%s\n' "$usage_out" >&2; die "the CLI's chain-config usage names no 'MLDSA_ACTIVE exactly <D>'"; }
[ "$DM_DEC" -gt 0 ] 2>/dev/null || die "the CLI's MLDSA_ACTIVE literal '$DM_DEC' is not a positive int64"
DM_HEX=$(printf '%016x' "$DM_DEC")

# ml: the precompile address and D, re-derived here from the DECIDED layout
# (decision "Vote literal tag and preimage", operator 2026-10-22)
PC_ADDR=$(printf 'NDS.EVMMLDSA87.v1' | openssl dgst -sha3-512 | awk '{print substr($NF, 1, 64)}')
[ "${#PC_ADDR}" = 64 ] || die "could not derive the precompile address"
be_u64() { printf '%016x' "$1"; }
DM_PRE="$(printf 'NDS.MLDSAACT.v1' | xxd -p -c 256)00${PC_ADDR}00000013$(printf 'nodus.evm.attest.v1' | xxd -p -c 256)00000005$(be_u64 25000)$(be_u64 12)$(be_u64 65536)$(be_u64 "$PK_LEN")$(be_u64 "$SIG_LEN")"
[ "${#DM_PRE}" = 230 ] || die "the re-derived preimage is $(( ${#DM_PRE} / 2 )) bytes, the decided layout is 115"
dm_top=$(printf '%s' "$DM_PRE" | xxd -r -p | openssl dgst -sha3-512 | awk '{print substr($NF, 1, 16)}')
DM_MINE=$(printf '%016x' $(( 16#$dm_top & 0x7fffffffffffffff )))
[ "$DM_MINE" = "$DM_HEX" ] || die "the CLI's MLDSA_ACTIVE literal 0x$DM_HEX differs from the one re-derived from the decided preimage, 0x$DM_MINE"
oracle_out=$(python3 "$ORACLE" 2>&1) || { printf '%s\n' "$oracle_out" >&2; die "the oracle $ORACLE failed"; }
grep -qx "#define DNAC_CFG_MLDSA_ACTIVE_D 0x${DM_HEX}ULL" <<< "$oracle_out" \
    || { printf '%s\n' "$oracle_out" >&2; die "the oracle does not print 0x$DM_HEX"; }
for n in $(seq 1 "$N"); do
    grep -qF "ML-DSA-87 precompile vote D 0x$DM_HEX (param $PARAM_MLDSA MLDSA_ACTIVE)" "$(stagef_node_log "$n")" \
        || die "node$n logged no 'ML-DSA-87 precompile vote D 0x$DM_HEX' start-up line"
done

# ml: committed bytes only — the probe fixture and the vectors' source
SRC_HEAD=$(git -C "$STAGEF_REPO_ROOT" rev-parse HEAD)
for f in "$FIX_DIR/MldsaProbe.hex" "$PC_SRC"; do
    git -C "$STAGEF_REPO_ROOT" ls-files --error-unmatch -- "$f" >/dev/null 2>&1 \
        || die "$f is not tracked by git — the scenario uses COMMITTED bytes only"
    git -C "$STAGEF_REPO_ROOT" diff --quiet HEAD -- "$f" \
        || die "$f differs from HEAD $SRC_HEAD — the scenario uses COMMITTED bytes only"
done

# ml: c_array NAME -> the bytes of `static const uint8_t NAME[..] = { .. };`
# in evm_precompile.c as lowercase hex (read-only)
c_array() {
    awk -v pat="^static const uint8_t $1\\\\[" '
        $0 ~ pat { f = 1; next }
        f && /^};/ { exit }
        f { print }' "$PC_SRC" | grep -o '0x[0-9a-fA-F][0-9a-fA-F]' | cut -c3- | tr -d '\n' | tr 'A-F' 'a-f'
}
KAT_PK=$(c_array MLDSA_KAT_PK)
KAT_SIG=$(c_array MLDSA_KAT_SIG)
KAT_SIG0=$(c_array MLDSA_KAT_SIG_EMPTYCTX)
KAT_MSG=$(c_array MLDSA_KAT_MSG)
KAT_ADDR=$(c_array MLDSA_KAT_ADDR)
[ "${#KAT_PK}" = $(( PK_LEN * 2 )) ] || die "MLDSA_KAT_PK read as $(( ${#KAT_PK} / 2 )) bytes, expected $PK_LEN"
[ "${#KAT_SIG}" = $(( SIG_LEN * 2 )) ] || die "MLDSA_KAT_SIG read as $(( ${#KAT_SIG} / 2 )) bytes, expected $SIG_LEN"
[ "${#KAT_SIG0}" = $(( SIG_LEN * 2 )) ] || die "MLDSA_KAT_SIG_EMPTYCTX read as $(( ${#KAT_SIG0} / 2 )) bytes, expected $SIG_LEN"
[ "${#KAT_MSG}" = 64 ] || die "MLDSA_KAT_MSG read as $(( ${#KAT_MSG} / 2 )) bytes, expected 32"
[ "${#KAT_ADDR}" = 64 ] || die "MLDSA_KAT_ADDR read as $(( ${#KAT_ADDR} / 2 )) bytes, expected 32"
[ "$KAT_SIG" != "$KAT_SIG0" ] || die "the two test signatures are identical"
SIGNER=$(printf '%s' "$KAT_PK" | xxd -r -p | openssl dgst -sha3-512 | awk '{print substr($NF, 1, 64)}')
[ "$SIGNER" = "$KAT_ADDR" ] || die "MLDSA_KAT_ADDR 0x$KAT_ADDR is not SHA3-512(pk)[0..32] = 0x$SIGNER"
IN_VALID="${KAT_PK}${KAT_SIG}${KAT_MSG}"
IN_EMPTYCTX="${KAT_PK}${KAT_SIG0}${KAT_MSG}"
IN_SHORT=$(printf '%0*d' $(( (PK_LEN + SIG_LEN - 1) * 2 )) 0)   # 7218 zero bytes
echo "[ok] capability gate: one build v$SRV_VER; EVM D = 0x$D_HEX; MLDSA D = 0x$DM_HEX (CLI = openssl re-derivation"
echo "     of the decided 115-byte preimage = oracle = every node's start-up line); precompile 0x$PC_ADDR;"
echo "     probe fixture + vectors = HEAD $SRC_HEAD; signer 0x$SIGNER = SHA3-512(pk)[0..32]"

# ── script-local helpers (test_cmt_evm_lib.sh's, unless "ml:") ──────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }
fp_of()  { tr 'A-F' 'a-f' < "$1/nodus.fp" | tr -d '[:space:]'; }
# ml: the nodes that are up (every node but $DOWN)
live_nodes() {
    local n
    for n in $(seq 1 "$N"); do [ "$n" = "$DOWN" ] || echo "$n"; done
}

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

wait_all() {               # ml: the live nodes
    local n
    for n in $(live_nodes); do
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

cc_count() {               # ml: NODE PARAM -> rows of that param
    sqlite3 "$(db_of "$1")" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $2;" 2>/dev/null || echo ERR
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
    for n in $(live_nodes); do
        stagef_cmt_wait_height "$(db_of "$n")" "$h" 3 >/dev/null \
            || die "node$n never reached height $h (the param-$param row's detection height)"
        r=$(cc_row "$n" "$param" "$eff")
        rows="$rows node$n=$r"
        if [ -z "$first" ]; then first="$r"
        elif [ "$r" != "$first" ]; then die "the param-$param row (effective $eff) DIFFERS across nodes:$rows"; fi
    done
    case "$first" in ""|ERR) die "no param-$param row (effective $eff) readable";; esac
    [ "${first%%|*}" = "$val" ] || die "the param-$param row carries value ${first%%|*}, expected $val"
    CC_ROW="$first"
    CC_CB="${first#*|}"; CC_CB="${CC_CB%%|*}"
    echo "[ok] param-$param row (value $val, effective $eff, commit_block $CC_CB) identical on the live nodes"
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

# ml: refused_proposal NODE NAME VALUE EFFECTIVE LOG WHY — test_cmt_evm.sh's
# second_proposal from NODE's seat: every OTHER seat refuses with the
# stateful rule's own text; WHY names the rule for the message
refused_proposal() {
    local pn="$1" name="$2" val="$3" eff="$4" log="$5" why="$6" prc=0 nref
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$pn")" -i "$(node_keys "$pn")" \
        chain-config propose --param "$name" --value "$val" --effective "$eff" > "$log" 2>&1 || prc=$?
    cat "$log"
    cc_guard_after "$pn"
    [ "$prc" != 0 ] || die "the $name proposal from node$pn ($why) exited 0 — it was not refused"
    ! grep -q "proposal accepted" "$log" || die "the $name proposal from node$pn ($why) reported acceptance"
    grep -q "Round 1: 1/$N approved" "$log" \
        || die "the $name proposal from node$pn ($why) did not end round 1 at 1/$N (only its own seat) — see $log"
    nref=$(grep -c "REFUSED: stateful rules rejected" "$log" || true)
    [ "$nref" = $(( N - 1 )) ] || die \
        "$nref of $(( N - 1 )) other seats refused the $name proposal ($why) with 'stateful rules rejected' — see $log"
    grep -q "Quorum not reached" "$log" || die "the $name proposal ($why) did not abort on quorum (see $log)"
    echo "[ok] $name from node$pn REFUSED by the $(( N - 1 )) other seats ($why)"
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

# ── EVM helpers (test_cmt_evm_lib.sh's, unless "ml:") ────────────────
BC() { BC_LINE_LENGTH=0 bc; }
hexdec() {
    [ "${#1}" = 64 ] || { echo ERR; return 0; }
    printf 'ibase=16; %s\n' "$(tr 'a-f' 'A-F' <<< "$1")" | BC
}

evm_addr_of() {
    local out line hit="" n=0
    out=$("$CLI" evm address --keys "$1" 2>&1) || die "evm address --keys $1 failed: $out"
    while IFS= read -r line; do
        if [[ "$line" =~ ^0x([0-9a-f]{64})$ ]]; then hit="${BASH_REMATCH[1]}"; n=$(( n + 1 )); fi
    done <<< "$out"
    [ "$n" = 1 ] || die "evm address --keys $1 printed $n address lines: '$out'"
    echo "$hit"
}

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

require_rcpt() {           # ml: over the live nodes
    local i="$1" st="$2" op="$3" what="$4" n r dg re
    RCPT=""
    for n in $(live_nodes); do
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
    RC_GAS=$(( 16#$(r="${RCPT#*|}"; r="${r#*|}"; echo "${r%%|*}") ))
    echo "[ok] $label: receipt status $st op $op at height $RC_H, evm gas used $RC_GAS (live nodes)"
}

evm_q() {
    local n="$1"
    shift
    EQ_RC=0
    EQ_OUT=$("$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" evm "$@" 2>&1) || EQ_RC=$?
}

# view ADDR SIG ARGS... — a read on node 1; sets CW[0..] to the decoded
# return words and ml: VIEW_T to the tip the node simulated on (the call
# itself ran at VIEW_T + 1 — nodus_witness_handlers.c handle_evm_call)
view() {
    local a="$1" sig="$2" line
    shift 2
    evm_q 1 call "$a" "$sig" "$@" --from "$ADDR1" --gas "$GAS_CALL"
    [ "$EQ_RC" = 0 ] && grep -q '^ok at height' <<< "$EQ_OUT" || {
        printf '%s\n' "$EQ_OUT" >&2; die "evm call $sig on 0x${a:0:16}… did not succeed (rc $EQ_RC)"; }
    VIEW_T=$(sed -n 's/^ok at height \([0-9]*\), gas .*/\1/p' <<< "$EQ_OUT")
    [ -n "$VIEW_T" ] || { printf '%s\n' "$EQ_OUT" >&2; die "evm call $sig printed no 'ok at height' tip"; }
    CW=()
    while IFS= read -r line; do
        if [[ "$line" =~ ^\ \ \[([0-9]+)\]\ (.*)$ ]]; then CW[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"; fi
    done <<< "$EQ_OUT"
}
view_is() {
    local a="$1" sig="$2" args=() i=0 x
    shift 2
    while [ "$#" -gt 0 ] && [ "$1" != -- ]; do args+=("$1"); shift; done
    [ "${1:-}" = -- ] || die "view_is: no -- separator"
    shift
    view "$a" "$sig" "${args[@]}"
    for x in "$@"; do
        [ "${CW[$i]:-}" = "$x" ] || die "$sig on 0x${a:0:16}… returned [$i] '${CW[$i]:-}', expected '$x' (simulated on tip $VIEW_T)"
        i=$(( i + 1 ))
    done
}

# ml: probe_is INPUT_HEX EXPECTED_OK EXPECTED_LEN EXPECTED_WORD — the probe's
# view through the node's simulation
probe_is() {
    view_is "$PROBE" "probe(address,bytes)(bool,uint256,bytes32)" "$PC_ADDR" "0x$1" -- "$2" "$3" "0x$4"
}
# ml: stored_is CALLS OK LEN WORD — the probe's four stored values (node 1)
stored_is() {
    view_is "$PROBE" "calls()(uint256)" -- "$1"
    view_is "$PROBE" "lastOk()(bool)" -- "$2"
    view_is "$PROBE" "lastLen()(uint256)" -- "$3"
    view_is "$PROBE" "lastWord()(bytes32)" -- "0x$4"
}

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

require_supply() {
    local what="$1" rsv_x="$2" live_x n meta L T X rsv live tk lost lhs rhs v
    live_x=$(printf '%s*%s\n' "$rsv_x" "$Q" | BC)
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
        [ "$tk" = 0 ] || die "$what: node$n's wei_tickets is $tk, expected 0"
        [ "$lost" = 0 ] || die "$what: node$n's wei_lost is $lost, expected 0"
    done
    echo "[ok] $what: 7/7 reserve $rsv_x raw, wei_live $live_x, no tickets, wei_lost 0 — invariant holds"
}

created_of() {
    CREATED="${RCPT##*|}"
    [ "${#CREATED}" = 64 ] && [ "$CREATED" != "$ZERO64" ] || die "$1: the receipt names no created address ('$CREATED')"
}

# ml: wait_tip_exact T — node 1's tip reaches T; FAIL if it is already past
# T (the exact-tip read would be on another height — HOW IT CAN LIE)
wait_tip_exact() {
    local t
    stagef_cmt_wait_height "$(db_of 1)" "$1" 3 >/dev/null || die "node1 never reached height $1"
    t=$(tip_of 1)
    [ "$t" = "$1" ] || die "node1's tip is $t, past $1, before the exact-tip read — the layout broke, not the chain"
}

# ── 0/1. preconditions: a fresh cluster on this build ───────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM" "$PARAM_MLDSA"; do
    [ "$(cc_count 1 "$p")" = 0 ] || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
ADDR1=$(evm_addr_of "$(node_keys 1)")
hexfile() { tr -d '[:space:]' < "$1" | tr 'A-F' 'a-f'; }
PROBE_INIT=$(hexfile "$FIX_DIR/MldsaProbe.hex")
stagef_cmt_pump_ready "$(db_of 1)" || die "the CLI-SPEND pump is not usable on this bring-up (reason above)"
stagef_sentinel SETUP_OK
stagef_cmt_diff_at_floor "pre-mldsa" || exit 2
echo "[ok] fresh chain; node1's EVM address 0x$ADDR1; victim node$VICTIM"

# ── 1. leaf ─────────────────────────────────────────────────────────
claim_leaf "$(node_keys 1)" 1

# ── 2. the votes to the EVM generation (test_cmt_evm_lib.sh's) ─────
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

# ml: NEGATIVE — param 23 under generation 2 (rule (b))
cc_guard 2
HX=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( (HX - 1) % E )) = 0 ]; do HX=$(( HX + 1 )); done
echo "[ok] tip $CCG_TIP — node2 proposes MLDSA_ACTIVE=$DM_DEC effective $HX under generation $GEN_2 (must be refused)"
refused_proposal 2 MLDSA_ACTIVE "$DM_DEC" "$HX" "$LOGD/propose_mldsa_gen2.log" "generation 2: the EVM generation is not in force"
for n in $(seq 1 "$N"); do
    [ "$(cc_count "$n" "$PARAM_MLDSA")" = 0 ] || die "node$n holds a param-23 row after the refused generation-2 proposal"
done

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

# ── 3. deposit + the probe ──────────────────────────────────────────
tx_ok 1 1 "deposit node1" 01 "$OP_DEPOSIT" deposit "$DEP_RAW"
RSV="$DEP_RAW"
require_supply "post-deposit" "$RSV"
tx_ok 1 1 "deploy MldsaProbe" 01 "$OP_CREATE" deploy "$PROBE_INIT" --gas "$GAS_DEPLOY"
created_of "deploy MldsaProbe"; PROBE="$CREATED"
stored_is 0 false 0 "$ZERO64"
echo "[ok] MldsaProbe at 0x$PROBE"

# ── 4. before the vote: an ordinary account ─────────────────────────
probe_is "$IN_VALID" true 0 "$ZERO64"
echo "[ok] before the vote (simulated at $(( VIEW_T + 1 ))): probe(valid) = (true, 0, 0) — no precompile at 0x${PC_ADDR:0:16}…"
tx_ok 1 1 "record valid before the vote" 01 "$OP_CALL" send "$PROBE" "record(address,bytes)" "$PC_ADDR" "0x$IN_VALID" --gas "$GAS_SEND"
GAS_PRE_VOTE="$RC_GAS"
stored_is 1 true 0 "$ZERO64"
echo "[ok] before the vote, executed at $RC_H: the probe stored (1, true, 0, 0)"

# ── 5. the vote + single use ────────────────────────────────────────
cc_guard 1
HM=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN + MLDSA_MARGIN ))
while [ $(( (HM - 1) % E )) = 0 ]; do HM=$(( HM + 1 )); done     # param 23 rule (c)
echo "[ok] tip $CCG_TIP — node1 proposes MLDSA_ACTIVE=$DM_DEC effective HM=$HM"
propose MLDSA_ACTIVE "$DM_DEC" "$HM" "$LOGD/propose_mldsa.log"
wait_cc_row "$PARAM_MLDSA" "$HM" "$DM_DEC" 20
MLDSA_ROW="$CC_ROW"
[ "$CC_CB" -lt "$HM" ] || die "the MLDSA_ACTIVE row committed at $CC_CB, not before its effective height $HM"

cc_guard 3
H2ND=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( (H2ND - 1) % E )) = 0 ] || [ "$H2ND" = "$HM" ]; do H2ND=$(( H2ND + 1 )); done
refused_proposal 3 MLDSA_ACTIVE "$DM_DEC" "$H2ND" "$LOGD/propose_mldsa_second.log" "single use: a param-23 row exists"
for n in $(seq 1 "$N"); do
    [ "$(cc_count "$n" "$PARAM_MLDSA")" = 1 ] || die "node$n holds $(cc_count "$n" "$PARAM_MLDSA") param-23 rows after the refused second proposal, expected 1"
done

# ── 6. voted, not reached ───────────────────────────────────────────
tx_ok 1 1 "record valid after the vote below HM" 01 "$OP_CALL" send "$PROBE" "record(address,bytes)" "$PC_ADDR" "0x$IN_VALID" --gas "$GAS_SEND"
[ "$RC_H" -lt $(( HM - 2 )) ] || die "the pre-activation record landed at $RC_H, not below HM − 2 = $(( HM - 2 )) — the layout broke (MLDSA_MARGIN), not the chain"
stored_is 2 true 0 "$ZERO64"
echo "[ok] voted (effective $HM), executed at $RC_H: the probe stored (2, true, 0, 0) — not active yet"

# ── 7. node 7 down; the exact flip in the simulation ────────────────
[ "$(tip_of 1)" -lt $(( HM - 2 )) ] || die "node1's tip $(tip_of 1) is not below HM − 2 before node$VICTIM is stopped — the layout broke"
VICTIM_TIP=$(tip_of "$VICTIM")
VICTIM_DLINES=$(grep -c "ML-DSA-87 precompile vote D 0x$DM_HEX" "$(node_log "$VICTIM")" || true)
src=0; stagef_stop_node "$VICTIM" KILL || src=$?
[ "$src" != 1 ] || die "node$VICTIM is not running"
[ "$src" = 0 ] || die "stopping node$VICTIM failed (stagef_stop_node rc=$src — the [FAIL] line above)"
DOWN="$VICTIM"
echo "[ok] node$VICTIM stopped at its tip $VICTIM_TIP (pids $STAGEF_STOPPED_PIDS); the chain continues on $(( N - 1 ))/$N"
T_STOP=$(( HM - PUMP_STOP_GAP ))
if [ "$(tip_of 1)" -lt "$T_STOP" ]; then pump_to "$T_STOP"; fi
wait_tip_exact $(( HM - 2 ))
probe_is "$IN_VALID" true 0 "$ZERO64"
[ "$VIEW_T" = $(( HM - 2 )) ] || die "the probe simulated on tip $VIEW_T, not HM − 2 = $(( HM - 2 )) (HOW IT CAN LIE: the exact-tip read raced a block)"
echo "[ok] simulated at height $(( HM - 1 )) (tip $VIEW_T): probe(valid) = (true, 0, 0) — inactive"
wait_tip_exact $(( HM - 1 ))
probe_is "$IN_VALID" true 32 "$SIGNER"
[ "$VIEW_T" = $(( HM - 1 )) ] || die "the probe simulated on tip $VIEW_T, not HM − 1 = $(( HM - 1 )) (HOW IT CAN LIE: the exact-tip read raced a block)"
echo "[ok] simulated at height $HM (tip $VIEW_T): probe(valid) = (true, 32, 0x${SIGNER:0:16}…) — the precompile verifies"
wait_all $(( HM + 1 ))

# ── 8. executed from HM ─────────────────────────────────────────────
tx_ok 1 1 "record valid from HM" 01 "$OP_CALL" send "$PROBE" "record(address,bytes)" "$PC_ADDR" "0x$IN_VALID" --gas "$GAS_SEND"
[ "$RC_H" -ge "$HM" ] || die "the post-activation record landed at $RC_H < HM $HM"
GAS_ACTIVE="$RC_GAS"
stored_is 3 true 32 "$SIGNER"
echo "[ok] executed at $RC_H: the probe stored (3, true, 32, the signer 0x${SIGNER:0:16}…)"
tx_ok 1 1 "record empty-context signature" 01 "$OP_CALL" send "$PROBE" "record(address,bytes)" "$PC_ADDR" "0x$IN_EMPTYCTX" --gas "$GAS_SEND"
[ "$RC_H" -ge "$HM" ] || die "the empty-context record landed at $RC_H < HM $HM"
stored_is 4 true 0 "$ZERO64"
echo "[ok] executed at $RC_H: an empty-context signature over the same message stored (4, true, 0, 0)"
tx_ok 1 1 "record malformed input" 01 "$OP_CALL" send "$PROBE" "record(address,bytes)" "$PC_ADDR" "0x$IN_SHORT" --gas "$GAS_SEND"
[ "$RC_H" -ge "$HM" ] || die "the malformed record landed at $RC_H < HM $HM"
stored_is 5 true 0 "$ZERO64"
echo "[ok] executed at $RC_H: 7218 bytes (one short of pk ‖ sig) stored (5, true, 0, 0)"
probe_is "$IN_EMPTYCTX" true 0 "$ZERO64"
echo "[ok] simulated at $(( VIEW_T + 1 )): probe(empty context) = (true, 0, 0)"
echo "[info] evm gas used by record(valid): $GAS_PRE_VOTE before the vote, $GAS_ACTIVE from HM (not asserted)"

# ── 9. node 7 back; everything 7/7 ──────────────────────────────────
stagef_spawn_node "$VICTIM" \
    || die "node$VICTIM did not come back after the restart (the [FAIL] line above names the process)"
DOWN=""
echo "[ok] node$VICTIM restarted (pids $STAGEF_NODE_PIDS)"
d_ok=0
for _ in $(seq 1 30); do
    [ "$(grep -c "ML-DSA-87 precompile vote D 0x$DM_HEX" "$(node_log "$VICTIM")" || true)" -gt "$VICTIM_DLINES" ] && { d_ok=1; break; }
    sleep 1
done
[ "$d_ok" = 1 ] || die "node$VICTIM logged no new 'ML-DSA-87 precompile vote D 0x$DM_HEX' line after its restart"
T_END=$(tip_of 1)
wait_all "$T_END"
echo "[ok] node$VICTIM caught up to height $T_END (it was stopped at $VICTIM_TIP, below HM − 2)"
for x in $(( HM - 1 )) "$HM" $(( HM + 1 )); do diff_at "$x" "mldsa-at-height-$x"; done
for n in $(seq 1 "$N"); do
    r=$(cc_row "$n" "$PARAM_MLDSA" "$HM")
    [ "$r" = "$MLDSA_ROW" ] || die "node$n's param-23 row '$r' differs from '$MLDSA_ROW'"
done
echo "[ok] the param-23 row identical on 7/7 (node$VICTIM included)"
require_supply "end" "$RSV"
require_evm_same "end"
stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-mldsa" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | MLDSA vote $CC_CB -> HM $HM | probe 0x$PROBE | node$VICTIM down $VICTIM_TIP..restart"
echo "[PASS] ML-DSA-87 precompile activation (param 23, D 0x$DM_HEX): refused under generation 2 and a second"
echo "       time; below HM the address is an ordinary account (simulated and executed), from HM a valid"
echo "       signature returns the signer's address while an empty-context signature and a short input"
echo "       return empty; node$VICTIM, down across HM, caught up with identical blocks and EVM state (7/7)."
echo "       E=15 / grace 15 — the LOGIC only (header)."
