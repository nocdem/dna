#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_chain_config.sh — a validator proposes a chain_config change
# over the network, on the Comet lane (D-16 rev 7, W4-CC)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That `nodus-cli chain-config propose`, run from a validator's OWN
#   identity against ITS OWN node, collects committee approvals over
#   the network and lands a `chain_config_history` row that is
#   BYTE-IDENTICAL on all 7 nodes. Since decision
#   docs/plans/decisions/2026-09-26-cc-approval-via-own-node.md the CLI
#   never dials 4004: it hands the envelope to its own node on 4001
#   (`dnac_cc_collect`), and that node asks every other seat on channel
#   0x71 (the former verbs 40-41) over its EXISTING 4004 connections,
#   then answers the CLI with one result per seat. The property that
#   would be false if it failed: *a governance proposal collected over
#   the network reaches the same committed row everywhere* — the same
#   determinism guarantee every other Comet-lane scenario checks for a
#   transfer or a stake, now for a governance change.
#
#   This is the only networked exercise of the whole path — CLI →
#   own node (4001) → seats (0x71 on 4004) → responders → back — against
#   REAL validator processes. test_cc_appr.c drives the responder's
#   verdict directly (no network), test_cc_collect.c the node-side
#   collection with injected answers, test_witness_p2p.c (2d) one 0x71
#   round trip between two in-process hosts, test_tier3.c the codec.
#
#   THE PARAMETER (0.20.3): TARGET_ACTIVE_COUNT (param id 4) = 32.
#   Until 0.20.3 this scenario voted BLOCK_INTERVAL_SEC (id 2), which the
#   Comet lane never reads — and since 0.20.3 CHAIN_CONFIG refuses every
#   parameter the running consensus does not read (dnac.h
#   dnac_cfg_param_read_by_consensus = {4, 5}; decision file
#   docs/plans/decisions/2026-09-23-height-activated-upgrades-before-
#   testnet.md item 1, which also names this move). Why 32: it is the
#   value the chain already uses when NO row exists
#   (DNAC_TARGET_ACTIVE_DEFAULT = NODUS_V2_ACTIVE_SET_MAX = 32, read by
#   nodus_witness_committee.c committee_target_for_epoch and
#   nodus_witness_vset.c vset_target_for_epoch), and the version-3 lane's
#   governed range is [7, 32]. So when the chain later passes the
#   effective height, every seat count a later scenario in the same sweep
#   sees is byte-identical to a sweep without this row — including the
#   8th validator test_v2_stake.sh bonds, which any target below 8 would
#   rotate out. The cost is honesty about what the value proves: see HOW
#   IT CAN LIE.
#
# WHAT IT REQUIRES
#   ⚠ **A SHORT-GRACE BINARY. Both halves, or it skips.**
#     compile: -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#              -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#              (README.md's own short-grace build line)
#     env:     STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15,
#              exported BEFORE stagef_up_v2.sh — the bring-up writes
#              these into the genesis config, and a build compiled with
#              a DIFFERENT grace than the config declares fails the
#              config/binary agreement check at bring-up, not here.
#   At the shipped grace (17280 blocks — about 19 h at the 4 s commit
#   timeout under constant load, far longer on an idle chain that makes
#   an empty block every 60 s) TARGET_ACTIVE_COUNT's own effective height
#   (a SAFETY-class parameter) would need to be that far past the
#   proposal — this scenario SKIPS (rc=99) rather than wait for that.
#   A cluster from stagef_up_v2.sh. No pump / funded user needed — this
#   scenario never spends a UTXO, it only proposes a governance change.
#
# WHAT IT LEAVES BEHIND
#   One committed `chain_config_history` row (TARGET_ACTIVE_COUNT ->
#   32, param_id 4, effective at the height this run picked, ~21 blocks
#   ahead at grace 15) on every node. Nothing waits for it here, but the
#   chain WILL pass that height if later scenarios run on the same
#   cluster: from the first epoch boundary at or after it, the committee
#   and snapshot builders read the row's 32 where they read the no-row
#   default 32 before — the same number, so no seat count changes. A scenario that asserts
#   "no TARGET_ACTIVE_COUNT row exists" (test_v2_grow_7_32.sh) must not
#   share this cluster; the README already runs it standalone on its
#   own fresh bring-up. Nothing is killed or restarted.
#
# HOW IT CAN LIE
#   - **The CLI's exit code is the RPC round's own verdict, not
#     inclusion.** `chain-config propose` prints "proposal accepted:
#     mempool CheckTx approved" on success — that is CheckTx admission,
#     the SAME "admitted, not committed" distinction every other
#     Comet-lane scenario's header already makes for `dnac_spend`. The
#     row is asserted from the CHAIN, via `stagef_cmt_wait_row`, never
#     from the CLI's own stdout.
#   - **A CheckTx-approved proposal is not guaranteed in the very next
#     block** (`stagef_cmt_wait_row`'s own doc comment, DELTA 2) — the
#     wait is for the row itself, bounded by both a stall detector and
#     a height budget, never a bare "tip+1" read.
#   - **Round 2 is rarely exercised here.** This scenario asks all 7
#     seats in round 1, so it only reaches round 2 if a seat refuses,
#     is not connected to the proposer's node, or misses the node's
#     5000 ms collection deadline. The CLI then waits out the seats'
#     per-proposer cooldown (`NODUS_CC_RATE_LIMIT_WINDOW_MS` = 5000 ms)
#     before re-asking (decision (6)), so a round-2 "rate-limited"
#     refusal would be a defect, not the old design tension. A green
#     run with "Round 1: 7/7 approved" says nothing about round 2.
#   - **A seat not connected to the proposer's node is reported
#     "SKIP (this node has no connection to the seat)"** — on a healthy
#     7-node cluster every seat is connected; a SKIP line means the 4004
#     mesh was incomplete when the proposal ran, not a governance defect.
#   - **rc=99 means the short-grace build is absent** — the coverage
#     did not happen, never a pass.
#   - **This scenario does NOT prove the effective-height CUTOVER** —
#     nothing here waits for the chain to reach the proposal's
#     effective height and read back the new target; it proves only
#     that the proposal round-trips and commits identically everywhere.
#     And because the value (32) equals the no-row default, even a run
#     that DID wait could not tell "the row was applied" from "the row
#     was ignored" by counting seats — deliberately, so this row stays
#     harmless to the rest of a sweep. Observing the cutover needs a
#     value that differs from the default (the decision's item 2, a
#     separate scenario).
#   - **It does NOT prove the refusal of an unread parameter** (id 2)
#     over the network — that is pinned in the unit tests
#     (test_chain_config_verify.c, test_v2_econ_params.c, test_cc_appr.c
#     block_interval_unread_refused, test_v2_native.c), not here.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Ledger V2 cluster — use stagef_up_v2.sh"
    exit 99
fi
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

# ⚠ SHORT-GRACE GATE — see the header. Both halves must agree: the
# BINARY was compiled with a short grace (checked indirectly — a
# proposal at a near effective height only lands if the running node's
# OWN compiled grace floor admits it, which the responder itself
# enforces) and the ENVIRONMENT told bring-up to write a matching
# config. STAGEF_CC_GRACE_SAFETY defaults to 17280 (stagef_env.sh) —
# this scenario needs the operator to have exported the short value
# BEFORE stagef_up_v2.sh ran; there is no way to ask a running cluster
# what grace its binary was compiled with, so this checks the
# ENVIRONMENT variable as the best available signal and lets the
# proposal's own outcome be the final proof.
if [ "${STAGEF_CC_GRACE_SAFETY:-17280}" -gt 100 ]; then
    echo "[SKIP] STAGEF_CC_GRACE_SAFETY=${STAGEF_CC_GRACE_SAFETY:-17280} —"
    echo "       needs a short-grace build: -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15"
    echo "       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15, with"
    echo "       STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15 exported"
    echo "       BEFORE stagef_up_v2.sh (README.md's short-grace build line)"
    exit 99
fi

tip0=$(stagef_cmt_tip "$ref_db")
[ "$tip0" -ge 0 ] || die "no Comet block on node$REF yet"
# TARGET_ACTIVE_COUNT is a SAFETY-CRITICAL param
# (nodus_chain_config_grace_for_param) — the grace floor is
# STAGEF_CC_GRACE_SAFETY blocks past the candidate height. Generous
# margin (+5) over the exact floor so a few blocks of collection-round
# latency cannot itself invalidate the proposal.
effective=$(( tip0 + 1 + STAGEF_CC_GRACE_SAFETY + 5 ))
# 32 = the no-row default and the version-3 ceiling — see the header
# ("THE PARAMETER") for why this value and what it cannot prove.
CC_PARAM_NAME=TARGET_ACTIVE_COUNT
CC_PARAM_ID=4
CC_VALUE=32

echo "[ok] node$REF at tip $tip0, proposing $CC_PARAM_NAME=$CC_VALUE effective=$effective"

stagef_cmt_diff_at_floor "pre-cc-propose" || exit 2

log="$BASE_DIR/cc_propose_node${REF}.log"
# ORCHESTRATOR correction (W4-CC ORC-9): under `set -e` a non-zero CLI
# exit aborted the script on the line above the `cat`, so a failed
# proposal left NO diagnostics in the runner's output. `|| rc=$?` keeps
# the verdict AND prints the log.
propose_rc=0
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" \
    -i "$(stagef_node_dir "$REF")/identity" \
    chain-config propose --param "$CC_PARAM_NAME" --value "$CC_VALUE" \
    --effective "$effective" > "$log" 2>&1 || propose_rc=$?
cat "$log"
[ "$propose_rc" -eq 0 ] || die "chain-config propose exited $propose_rc (see $log)"
grep -q "proposal accepted" "$log" || die "propose did not report acceptance (see $log)"

echo "[ok] proposal round-trip accepted — waiting for the committed row"

# The row's PRIMARY KEY is (param_id, effective_block) — param_id 4 is
# TARGET_ACTIVE_COUNT (dnac.h dnac_chain_config_param_id_t). Wait for the
# row itself, never a bare tip+1 (stagef_cmt_wait_row's own DELTA 2
# rationale).
row_h=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM chain_config_history WHERE param_id=$CC_PARAM_ID AND effective_block=$effective AND new_value=$CC_VALUE;") \
    || { rc=$?; [ "$rc" -eq 1 ] && die "stalled waiting for the chain_config_history row"; \
         die "chain advanced past its height budget without the row appearing (dropped, not delayed)"; }
echo "[ok] chain_config_history row committed by height $row_h"

# Every node must show the SAME row. Wait for each to reach row_h first
# (a follower behind row_h has "no row yet" = lag, never divergence).
first=""; rows=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$row_h" 3 >/dev/null \
        || die "node$n never reached height $row_h (mesh replication stalled)"
    r=$(sqlite3 "$(stagef_node_chain_db "$n")" \
        "SELECT new_value || ':' || hex(tx_hash) FROM chain_config_history \
         WHERE param_id=$CC_PARAM_ID AND effective_block=$effective;" 2>/dev/null || echo ERR)
    rows="$rows node$n=$r"
    if [ -z "$first" ]; then first="$r"
    elif [ "$r" != "$first" ]; then
        echo "[FAIL] the chain_config_history row DIFFERS across nodes:$rows" >&2
        exit 1
    fi
done
case "$first" in ""|ERR) die "no chain_config_history row on any node";; esac
echo "[ok] the committed row ($first) is byte-identical on all $STAGEF_COMMITTEE_SIZE nodes"

stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-cc-propose" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] chain-config propose collected committee approvals over the"
echo "       network (verbs 40-41, D-16 rev 7) and committed a"
echo "       byte-identical chain_config_history row on all"
echo "       $STAGEF_COMMITTEE_SIZE nodes. Grace floor STAGEF_CC_GRACE_SAFETY=$STAGEF_CC_GRACE_SAFETY —"
echo "       NOT the shipped 17280, so this proves the LOGIC and nothing"
echo "       about the production grace's magnitude."
