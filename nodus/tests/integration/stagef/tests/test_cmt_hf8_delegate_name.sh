#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf8_delegate_name.sh — HF-8, "delegation requires an on-chain
# name": the param-17 vote, a nameless DELEGATE landing before the
# activation height H, refused at CheckTx after it (the node's own reason
# text), a named one and a nameless self-delegation landing 7/7, and
# block identity 7/7 at H-1 / H / H+1 (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/2026-10-07-delegate-name-required-design.md
# rev 2 §1 (Kurultay #11, docs/plans/kurultay/2026-10-07-11-delegate-
# name/summary.md); HF number: docs/plans/decisions/2026-10-05-hf-
# numbering-evm-hf5.md "Ek 2026-10-07"; names: docs/plans/decisions/
# 2026-10-02-onchain-names.md. Helpers copied from test_cmt_hf4_names.sh
# (pump, claim, propose, wait_cc_row, ruleset-info parse) and
# test_cmt_self_delegate.sh (the delegate submit and its intent wait),
# changed only where noted "HF-8:".
#
# WHAT IT PROVES — each item would be false if it failed
#   0. The CLI is an HF-8 build: its name table passes
#      DELEGATE_NAME_REQUIRED to the connect step (probe against a port
#      nothing listens on — FAIL, not skip, if it prints "Unknown param
#      name").
#   1. Prerequisites on the fresh chain: the pump (node 3) and the
#      delegators (nodes 2, 4, 5, 6, 7) claim their genesis leaves; HF-2
#      (param 7) is voted and passed (param 9's rule (b)); rule-set
#      generation 2 (param 9 = D2) is voted and the fleet crosses its H9
#      (names exist only from generation 2 — and param 17 is votable only
#      while generation >= 2 judges the vote).
#   2. Before any param-17 row: node 4 — a validator WITHOUT a name —
#      delegates to node 1 and it LANDS (its v2_intent_index row).
#   3. Node 2 registers an on-chain name (`name register`); the v2_names
#      row lands.
#   4. `chain-config propose --param DELEGATE_NAME_REQUIRED --value 1` at
#      H = vote tip + 1 + grace + H_MARGIN lands byte-identical on 7/7,
#      committed below H.
#   5. Between the vote and H (tip + 1 < H, checked before and after):
#      node 5 — nameless — delegates to node 1 and it LANDS below H (the
#      rule is inert until H, even with the vote committed).
#   6. The chain crosses H: 7/7 identical global_root + block_id AT H-1,
#      AT H and AT H+1.
#   7. After H:
#      a. node 7 (nameless, a NEW delegation to node 1) is REFUSED at
#         CheckTx: the CLI exits non-zero and the node's reason names the
#         dry run's EXEC item code and the CORE SYSFUND leg's exec verdict
#         ("dry run item code 7", "domain 1 op 7: runtime exec refused
#         (rc -1)");
#      b. node 4 (nameless, a TOP-UP of its pre-H delegation) is REFUSED
#         with the same text — top-ups are covered;
#      c. node 2 (named) delegates to node 1 and it LANDS; the delegation
#         row is identical on 7/7;
#      d. node 6 (nameless) delegates to ITSELF and it LANDS (exempt); the
#         row is identical on 7/7;
#      e. two heights later, on 7/7: no node7 -> node1 row, node 4's row
#         still holds exactly its pre-H amount.
#   8. stagef_cmt_diff_at_floor 7/7 at the end.
#
# WHAT IT REQUIRES
#   Compile flags — ONE short-epoch + short-grace build of THIS tree,
#   nodus-server AND nodus-cli (the HF-4 scenario's flag set):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 9 and 17 are all ERGONOMIC; param 9's rule (c) reads the
#   epoch length.)
#   Environment:
#     exported BEFORE stagef_up_v2.sh (hashed into the genesis document):
#       STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     read by THIS script:
#       STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#       STAGEF_NODUSCLI_BIN (default $STAGEF_REPO_ROOT/nodus/build/
#       nodus-cli) — the CLI of the SAME build
#     and the bring-up must run that build's server as STAGEF_NODUS_BIN.
#   Exact command sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-hf8 -DCMAKE_C_FLAGS="$F"
#     make -C <TREE>/nodus/build-hf8 -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-hf8/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-hf8/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf8_delegate_name.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): the CLI missing / not executable, STAGEF_EPOCH_LENGTH !=
#   15, a grace variable != 15, not a Comet cluster, no $BASE_DIR/
#   v2_genesis.conf, a split mode (stagef_split_skip_if — `ruleset-info`
#   and `name register` are not verified through a split core). A skip is
#   not a pass. FAIL (1) if the chain already holds a param 7, 9 or 17
#   row — it needs a fresh bring-up (every switch is one-way and the
#   leaves are single-use).
#
# WHAT IT LEAVES BEHIND
#   HF-2 ACTIVE from H2, rule-set generation 2 from H9 and HF-8 from H —
#   all one-way; rows param 7 = 1 at H2, param 9 = D2 at H9, param 17 = 1
#   at H. ONE v2_names row (NAME -> node 2, permanent) with its price + fee
#   in the reward pool. The genesis leaves of nodes 2, 3, 4, 5, 6 and 7
#   claimed. Four delegations that stay: node 4 -> node 1, node 5 ->
#   node 1, node 2 -> node 1 and node 6 -> node 6 (AMOUNT each; node 1's
#   and node 6's power and reward shares grow from the next snapshots).
#   $BASE_DIR/hf8/ (every CLI log). Nothing killed or restarted. The chain
#   several epochs further on. Tear down with stagef_down.sh before
#   re-running.
#
# HOW IT CAN LIE
#   - **The refusals are judged at CheckTx, not inside a block.** The CLI
#     submits to node 1 only; CheckTx's dry run judges committed state at
#     tip + 1 (the design's UX note), which is how a client meets the
#     rule. A refused envelope never enters a block here, so the in-block
#     refusal (the item rolled back with its SYSTEM leg's writes) is the
#     unit test test_v2_native §20 E5, not this scenario.
#   - **The reason text is the engine's GENERIC exec verdict** — "runtime
#     exec refused (rc -1)" on the CORE SYSFUND leg (domain 1, op 7);
#     hooks have no per-rule reason channel. Another SYSFUND refusal of
#     the same envelope (a spent coin, a conservation mismatch) would read
#     the same. What ties it to the name rule: the SAME build, the SAME
#     shape (the CLI's builder, one coin, one change) LANDS for node 5
#     between the vote and H and for node 2 (named) after H, and the
#     refused envelopes are funded by freshly claimed leaves.
#   - **Same-block NAME_REGISTER / DELEGATE ordering, the 14/15 input
#     ceiling, the extra w_read and fault classes are NOT exercised** —
#     the CLI builder caps a non-self DELEGATE at 14 inputs and each
#     delegator here holds one coin; their proofs are test_v2_native §20.
#   - **Node 4's refused top-up** proves "top-ups are covered" only
#     because its row exists from step 2 (checked: its v2_intent_index row
#     and its delegation row before H).
#   - **The CLI's own refusal path is not exercised** — nodus-cli has no
#     name pre-check for `v2-envelope delegate`; every refusal here is the
#     NODE's CheckTx answer (the text comes back in the error frame,
#     commit 4039bcc6).
#   - Param 17's stateful rule (generation >= 2) is only SATISFIED here,
#     never driven as a refusal; the vote's scalar / grace / stateful
#     matrix is test_hf4_params.c.
#   - **Every proposal is kept away from an epoch boundary** (cc_guard,
#     copied from test_cmt_evm.sh: the CLI takes the committee of tip + 1
#     but the epoch of tip — a pre-existing CLI edge, nodus/BUGS.md); a
#     proposal next to a boundary is never exercised, and if the tip
#     crosses one while the CLI runs the scenario FAILS (false RED, never
#     a false PASS).
#   - H-1 / H / H+1 are crossed on PUMPED production (node 3's leaf) —
#     unlike HF-4 there is no CLI expiry cap around param 17's H.
#   - E = 15, grace 15, BPY 20: the LOGIC of the switch at those
#     constants, nothing about the production 720 / 720 / 6 307 200.
#   - rc 99 = SKIP, coverage that did not happen.
#   - First run: ORCHESTRATOR 2026-10-07, PASS (rc 0) at E = 15 / BPY 20 /
#     grace 15/15, H = 112 — proves the logic at those constants only.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# HF-8: `ruleset-info`, `name register` and the CheckTx reason text are
# read through each node's client port only; not verified through a
# split core — SKIP (99) in every split mode.
stagef_split_skip_if --reason "HF-8 CLI paths not verified through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_DNR=17               # DNAC_CFG_DELEGATE_NAME_REQUIRED (dnac.h), value 1
GRACE_MARGIN=5             # the HF-2 vote: test_cmt_hf4_names.sh's +5
# the param-9 and param-17 votes carry room for the checks between the
# vote and H (a layout choice, not a timeout — a fleet that gets there
# first FAILS with that reason)
H_MARGIN=20
PUMP_STOP_GAP=7            # param 9 only: the CLI's expiry cap (HF-4 header)
E_REQ=15
AMOUNT=100000000000        # 1 000 NODUS (>= DNAC_MIN_DELEGATION, 100 NODUS)
NAME_B=hf8nodetwo          # node 2's name (10 characters: the 6+ price tier)
TARGET=1                   # every delegation's target validator (node 1)
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf8"
N="$STAGEF_COMMITTEE_SIZE"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
if [ ! -x "$CLI" ]; then
    echo "[SKIP] nodus-cli '$CLI' is missing or not executable — set STAGEF_NODUSCLI_BIN (header)"
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
    echo "       build (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15"
    echo "       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15) and both variables = 15"
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
    echo "[SKIP] no $CONF — the leaf claims need a stagef_up_v2.sh bring-up"
    exit 99
fi
mkdir -p "$LOGD"

# ── 0. the CLI gate (FAIL, not skip) ────────────────────────────────
listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}
PROBE_PORT=""
for p in 14991 14992 14993 14994 14995 14996 14997 14998 14999; do
    if ! listening "$p"; then PROBE_PORT="$p"; break; fi
done
[ -n "$PROBE_PORT" ] || die "no free port in 14991..14999 for the name-table probe"
probe=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose \
            --param DELEGATE_NAME_REQUIRED --value 1 --effective 1 2>&1 || true)
[[ "$probe" != *"Unknown param name"* && "$probe" == *"client_connect failed"* ]] || {
    printf '%s\n' "$probe" >&2
    die "the CLI did not pass DELEGATE_NAME_REQUIRED through its name table to the connect step — not an HF-8 build"; }
echo "[ok] CLI gate: $(readlink -f "$CLI") knows DELEGATE_NAME_REQUIRED (probe port $PROBE_PORT, nothing reached)"

# ── script-local helpers (test_cmt_hf4_names.sh's, unless "HF-8:") ─
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_of()  { cat "$1/nodus.fp"; }                 # $1 = identity dir
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
# HF-8: a node's 2592-byte public key as 5184 lowercase hex (the
# self-delegate scenario's read) and the delegations-row key form
pk_of()  { xxd -p -c 99999 "$(node_keys "$1")/nodus.pk"; }

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

PUMP_KEYS=$(node_keys 3)          # node 3's leaf drives height (stagef_env.sh's funder)
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

# cc_guard NODE / cc_guard_after NODE — copied from test_cmt_evm.sh (its
# ORCH run 1: a proposal at tip = kE − 1 met "MISMATCH (peer's set_hash/
# epoch differ …)" on every other seat — the CLI takes the committee of
# tip + 1 but the epoch of tip, a pre-existing CLI edge, nodus/BUGS.md).
# The proposer's tip must be off a boundary and >= CC_GUARD_GAP heights
# before the next one, else pump to the next epoch start + 1 (twice at
# most). Sets CCG_TIP (every effective height is computed from it) and
# CCG_NB. After the CLI returns, tip + 1 must still be below CCG_NB, else
# FAIL — a false RED, never a false PASS.
CC_GUARD_GAP=4
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
cc_guard_after() {
    local t
    t=$(tip_of "$1")
    [ $(( t + 1 )) -lt "$CCG_NB" ] || die \
        "the proposal from node$1 crossed into the epoch boundary $CCG_NB (tip $CCG_TIP -> $t): its approvals may straddle two epochs (the CLI committee/epoch edge, nodus/BUGS.md) — the layout broke, not the chain"
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

# `ruleset-info` against node $1; the parsed fields land in RI_*
ruleset_info() {
    local n="$1" log rrc=0
    log="$LOGD/ruleset_info_node${n}_$(tip_of "$n").log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" ruleset-info > "$log" 2>&1 || rrc=$?
    RI_RC="$rrc"
    RI_OUT=$(cat "$log")
    RI_GEN=$(sed -n 's/^tip=[0-9]* generation=\([0-9]*\) .*/\1/p' "$log")
    RI_D2=$(sed -n 's/^  node D2=0x\([0-9a-f]*\) .*/\1/p' "$log")
    RI_CLI_D2=$(sed -n 's/^  node D2=0x[0-9a-f]*  this CLI D2=0x\([0-9a-f]*\).*/\1/p' "$log")
}

# HF-8: one `v2-envelope delegate` from node $1's identity to node $2's
# key, submitted to node 1. Sets DG_RC and DG_INTENT; output in $3.
delegate() {
    local from="$1" to="$2" log="$3" port
    port=$(stagef_tcp_port 1)
    DG_RC=0
    "$CLI" -s 127.0.0.1 -p "$port" v2-envelope delegate \
        --keys "$(node_keys "$from")" --validator "$(pk_of "$to")" \
        --amount "$AMOUNT" --submit "127.0.0.1:$port" > "$log" 2>&1 || DG_RC=$?
    cat "$log"
    DG_INTENT=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$log")
}

# HF-8: wait for an admitted delegation's v2_intent_index row on node 1;
# prints its height
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

# HF-8: the delegation amount (from $2 to $3) on node $1, "" when absent
deleg_amount() {
    sqlite3 "$(db_of "$1")" \
        "SELECT amount FROM delegations
          WHERE lower(hex(delegator_pubkey)) = '$(pk_of "$2")'
            AND lower(hex(validator_pubkey)) = '$(pk_of "$3")';" 2>/dev/null || echo ERR
}

# HF-8: the refusal a nameless DELEGATE must meet at CheckTx — the dry
# run's EXEC item code and the CORE SYSFUND (domain 1, op 7) exec verdict
# (nodus_witness_cmt_app.c app_refuse_log, nodus_witness_v2_apply.c
# exec_one_env's "runtime exec refused" line)
require_name_refusal() {
    local what="$1" log="$2"
    [ "$DG_RC" != 0 ] || die "$what was ADMITTED after H (see $log)"
    grep -q "dry run item code 7" "$log" \
        && grep -q "domain 1 op 7: runtime exec refused (rc -1)" "$log" \
        || die "$what was refused for ANOTHER reason (see $log) — expected the CORE SYSFUND exec verdict"
    echo "[ok] $what REFUSED at CheckTx: $(grep -o 'CheckTx code [^"]*' "$log" | head -1)"
}

# ── preconditions: a fresh chain ────────────────────────────────────
for p in "$PARAM_HF2" "$PARAM_GEN2" "$PARAM_DNR"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
stagef_sentinel SETUP_OK
stagef_cmt_diff_at_floor "pre-hf8" || exit 2

# ── 1. prerequisites: leaves, HF-2, generation 2 ────────────────────
claim_leaf "$PUMP_KEYS" 1
for k in 2 4 5 6 7; do claim_leaf "$(node_keys "$k")" 1; done
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))

cc_guard 1
T_V2="$CCG_TIP"
H2=$(( T_V2 + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $T_V2 — node1 proposes HF2_ACTIVE=1 effective H2=$H2"
propose HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
pump_to 1 $(( H2 + 1 ))
wait_all $(( H2 + 1 ))
echo "[ok] HF-2 ACTIVE from H2=$H2"

ruleset_info 1
[ "$RI_RC" = 0 ] && [ "$RI_GEN" = 1 ] || { printf '%s\n' "$RI_OUT" >&2; die "node1 does not report generation 1 before the param-9 vote"; }
D2_HEX="$RI_D2"
[ "${#D2_HEX}" = 16 ] && [ "$D2_HEX" = "$RI_CLI_D2" ] || die "the node's D2 '$D2_HEX' and the CLI's '$RI_CLI_D2' are not one 16-hex literal"
D2_DEC=$(( 16#$D2_HEX ))
[ "$D2_DEC" -gt 0 ] || die "D2 0x$D2_HEX is not a positive int64"
cc_guard 1
T_V9="$CCG_TIP"
H9=$(( T_V9 + 1 + STAGEF_CC_GRACE_ERGONOMIC + H_MARGIN ))
while [ $(( (H9 - 1) % E_REQ )) = 0 ]; do H9=$(( H9 + 1 )); done   # param 9 rule (c)
echo "[ok] tip $T_V9 — node1 proposes RULESET_GEN2=$D2_DEC effective H9=$H9"
propose RULESET_GEN2 "$D2_DEC" "$H9" "$LOGD/propose_gen2.log"
wait_cc_row "$PARAM_GEN2" "$H9" "$D2_DEC" 20
# param 9: the CLI caps an envelope's expiry at H9-1 before H9
# (test_cmt_hf4_names.sh HOW IT CAN LIE) — pump to H9 - gap, then idle
pump_to 1 $(( H9 - PUMP_STOP_GAP ))
wait_all $(( H9 + 1 ))
for n in $(seq 1 "$N"); do
    ruleset_info "$n"
    [ "$RI_RC" = 0 ] && [ "$RI_GEN" = 2 ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n does not report generation 2 past H9=$H9"; }
done
stagef_cmt_diff_at_floor "post-gen2" || exit 2
echo "[ok] 7/7 on rule-set generation 2 from H9=$H9"

# ── 2. before any param-17 row: a nameless DELEGATE lands ───────────
delegate 4 "$TARGET" "$LOGD/delegate_node4_preH.log"
[ "$DG_RC" = 0 ] || die "node4's nameless DELEGATE was refused before any param-17 row (see $LOGD/delegate_node4_preH.log)"
[ "${#DG_INTENT}" = 128 ] || die "node4's delegate SUBMIT printed no intent_id"
h4=$(wait_intent "$DG_INTENT" "node4's pre-vote DELEGATE")
A4=$(deleg_amount 1 4 "$TARGET")
[ "$A4" = "$AMOUNT" ] || die "node4 -> node$TARGET delegation reads '$A4', want $AMOUNT"
echo "[ok] before any param-17 row: node4 (no name) delegated $AMOUNT to node$TARGET at height $h4"

# ── 3. node 2 registers a name ──────────────────────────────────────
nlog="$LOGD/register_${NAME_B}.log"
port1=$(stagef_tcp_port 1)
"$CLI" -s 127.0.0.1 -p "$port1" name register "$NAME_B" --keys "$(node_keys 2)" \
    --submit "127.0.0.1:$port1" > "$nlog" 2>&1 \
    || { cat "$nlog" >&2; die "name register $NAME_B from node2 failed (see $nlog)"; }
hn=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_names WHERE name = CAST('$NAME_B' AS BLOB)
       AND lower(hex(owner)) = lower('$(fp_of "$(node_keys 2)")');") && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "the v2_names row '$NAME_B' -> node2 did not land (wait rc=$wrc, tip $hn)"
echo "[ok] '$NAME_B' registered to node2 (tip $hn)"

# ── 4. the param-17 vote ────────────────────────────────────────────
cc_guard 1
T_V17="$CCG_TIP"
H=$(( T_V17 + 1 + STAGEF_CC_GRACE_ERGONOMIC + H_MARGIN ))
echo "[ok] tip $T_V17 — node1 proposes DELEGATE_NAME_REQUIRED=1 effective H=$H"
propose DELEGATE_NAME_REQUIRED 1 "$H" "$LOGD/propose_dnr.log"
wait_cc_row "$PARAM_DNR" "$H" 1 20
R_V17="$CC_CB"
[ "$R_V17" -lt "$H" ] || die "the param-17 row committed at $R_V17, not before its effective height $H"
stagef_cmt_diff_at_floor "post-dnr-vote" || exit 2

# ── 5. between the vote and H: a nameless DELEGATE still lands ──────
[ $(( $(tip_of 1) + 1 )) -lt "$H" ] || die "node1's tip reached H-1 before the between-vote-and-H check (widen H_MARGIN)"
delegate 5 "$TARGET" "$LOGD/delegate_node5_vote_to_H.log"
[ "$DG_RC" = 0 ] || die "node5's nameless DELEGATE was refused between the vote and H (see $LOGD/delegate_node5_vote_to_H.log)"
[ "${#DG_INTENT}" = 128 ] || die "node5's delegate SUBMIT printed no intent_id"
h5=$(wait_intent "$DG_INTENT" "node5's between-vote-and-H DELEGATE")
[ "$h5" -lt "$H" ] || die "node5's delegation applied at $h5 >= H=$H — the between-vote check did not run below H (widen H_MARGIN)"
echo "[ok] vote committed, below H: node5 (no name) delegated at height $h5 < H=$H"

# ── 6. cross H ──────────────────────────────────────────────────────
pump_to 1 $(( H + 1 ))
wait_all $(( H + 1 ))
stagef_sentinel TARGET_REACHED
for hh in $(( H - 1 )) "$H" $(( H + 1 )); do
    diff_at "$hh" "hf8-at-height-$hh"
done
echo "[ok] 7/7 identical blocks AT H-1/H/H+1 (H=$H)"

# ── 7. after H ──────────────────────────────────────────────────────
delegate 7 "$TARGET" "$LOGD/delegate_node7_postH.log"
require_name_refusal "node7's nameless NEW DELEGATE" "$LOGD/delegate_node7_postH.log"
delegate 4 "$TARGET" "$LOGD/delegate_node4_topup_postH.log"
require_name_refusal "node4's nameless TOP-UP" "$LOGD/delegate_node4_topup_postH.log"

delegate 2 "$TARGET" "$LOGD/delegate_node2_named.log"
[ "$DG_RC" = 0 ] || die "node2's NAMED DELEGATE was refused after H (see $LOGD/delegate_node2_named.log)"
h2=$(wait_intent "$DG_INTENT" "node2's named DELEGATE")
[ "$h2" -ge "$H" ] || die "node2's delegation applied at $h2 < H=$H"

delegate 6 6 "$LOGD/delegate_node6_self.log"
[ "$DG_RC" = 0 ] || die "node6's nameless SELF-delegation was refused after H (see $LOGD/delegate_node6_self.log)"
h6=$(wait_intent "$DG_INTENT" "node6's self-delegation")
[ "$h6" -ge "$H" ] || die "node6's self-delegation applied at $h6 < H=$H"

stagef_sentinel ASSERT_RUN
t=$(tip_of 1)
hmax=$h2; [ "$h6" -gt "$hmax" ] && hmax=$h6
[ "$t" -gt "$hmax" ] || t=$hmax
pump_to 1 $(( t + 2 ))
wait_all $(( t + 2 ))
for n in $(seq 1 "$N"); do
    a2=$(deleg_amount "$n" 2 "$TARGET"); a6=$(deleg_amount "$n" 6 6)
    a7=$(deleg_amount "$n" 7 "$TARGET"); a4=$(deleg_amount "$n" 4 "$TARGET")
    [ "$a2" = "$AMOUNT" ] || die "node$n: node2 -> node$TARGET reads '$a2', want $AMOUNT"
    [ "$a6" = "$AMOUNT" ] || die "node$n: node6 -> node6 reads '$a6', want $AMOUNT"
    [ -z "$a7" ] || die "node$n holds a node7 -> node$TARGET delegation ('$a7') — the refused envelope landed"
    [ "$a4" = "$AMOUNT" ] || die "node$n: node4 -> node$TARGET reads '$a4', want its pre-H $AMOUNT (the refused top-up must not land)"
done
echo "[ok] 7/7: node2 (named) and node6 (self) delegated at $h2 / $h6; no node7 row; node4's row unchanged"

stagef_cmt_diff_at_floor "post-hf8" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: H2=$H2 | H9=$H9 (D2 0x$D2_HEX) | node4 pre-vote at $h4 | '$NAME_B' at $hn"
echo "       | param-17 vote tip $T_V17, row commit $R_V17, H=$H | node5 at $h5 | node2 at $h2 | node6 at $h6"
echo "[PASS] HF-8: DELEGATE_NAME_REQUIRED voted at H=$H; nameless delegations landed before H (vote"
echo "       committed or not), were REFUSED at CheckTx after it (a new one and a top-up); a named one"
echo "       and a nameless self-delegation landed 7/7; blocks AT H-1/H/H+1 identical on 7/7."
echo "       E=15 / grace 15 — the LOGIC only (header)."
