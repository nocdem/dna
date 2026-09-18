#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_chain_config.sh — a validator proposes a chain_config change
# over the network, on the Comet lane (D-16 rev 7, W4-CC)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That `nodus-cli chain-config propose`, run from a validator's OWN
#   identity against ITS OWN node, collects committee approvals over
#   the network (verbs 40-41, the SYSTEM-governance approval-collection
#   RPC this package rebuilds the retired vote-collect pair, 14-15,
#   into) and lands a `chain_config_history` row that is BYTE-IDENTICAL
#   on all 7 nodes. The property that would be false if it failed: *a
#   governance proposal collected over the network reaches the same
#   committed row everywhere* — the same determinism guarantee every
#   other Comet-lane scenario checks for a transfer or a stake, now for
#   a governance change.
#
#   This is the FIRST networked exercise of verbs 40-41 anywhere in the
#   tree — test_cc_appr.c drives the responder directly (no network,
#   no CLI), and test_tier3.c is wire-codec-only. This scenario is what
#   proves the CLI's round-1/round-2 collection flow (nodus-cli.c) and
#   the responder (nodus_witness_handle_cc_appr_req) actually agree
#   over a REAL TCP connection, against REAL validator processes.
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
#   At the shipped grace (17280 blocks, ~29 h at 6 s/block) BLOCK_INTERVAL
#   _SEC's own effective height would need to be tens of thousands of
#   blocks past the proposal — this scenario SKIPS (rc=99) rather than
#   wait for that.
#   A cluster from stagef_up_v2.sh. No pump / funded user needed — this
#   scenario never spends a UTXO, it only proposes a governance change.
#
# WHAT IT LEAVES BEHIND
#   One committed `chain_config_history` row (BLOCK_INTERVAL_SEC ->
#   6, effective at the height this run picked) on every node. The
#   chain's block interval itself does not change — chain_config_get_u64
#   readers evaluate the override only once the chain reaches the
#   effective height, and nothing in this scenario waits that far.
#   Nothing is killed or restarted.
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
#   - **The per-proposer rate limit is real and can make round 2 refuse
#     a seat that accepted round 1** (nodus_chain_config.h:382,
#     `NODUS_CC_RATE_LIMIT_WINDOW_MS` = 5000 ms; register
#     R3-W4-CC-writer's own BLOCKED ON). This scenario asks all 7 seats
#     in round 1, so it only reaches round 2 if a real network hiccup
#     refuses one — if it fails here with "Round 2: a previously-
#     accepting seat refused", that is this design tension surfacing
#     live, not a defect in the harness.
#   - **rc=99 means the short-grace build is absent** — the coverage
#     did not happen, never a pass.
#   - **This scenario does NOT prove the effective-height CUTOVER** —
#     nothing here waits for the chain to reach the proposal's
#     effective height and read back the NEW block interval; it proves
#     only that the proposal round-trips and commits identically
#     everywhere. That is test_v2_epoch_boundary.sh-adjacent territory,
#     not this scenario's.
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
# BLOCK_INTERVAL_SEC is a SAFETY-CRITICAL param (same grace tier as
# INFLATION_START_BLOCK / TARGET_ACTIVE_COUNT) — the grace floor is
# STAGEF_CC_GRACE_SAFETY blocks past the candidate height. Generous
# margin (+5) over the exact floor so a few blocks of collection-round
# latency cannot itself invalidate the proposal.
effective=$(( tip0 + 1 + STAGEF_CC_GRACE_SAFETY + 5 ))

echo "[ok] node$REF at tip $tip0, proposing BLOCK_INTERVAL_SEC=6 effective=$effective"

stagef_cmt_diff_at_floor "pre-cc-propose" || exit 2

log="$BASE_DIR/cc_propose_node${REF}.log"
# ORCHESTRATOR correction (W4-CC ORC-9): under `set -e` a non-zero CLI
# exit aborted the script on the line above the `cat`, so a failed
# proposal left NO diagnostics in the runner's output. `|| rc=$?` keeps
# the verdict AND prints the log.
propose_rc=0
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" \
    -i "$(stagef_node_dir "$REF")/identity" \
    chain-config propose --param BLOCK_INTERVAL_SEC --value 6 \
    --effective "$effective" > "$log" 2>&1 || propose_rc=$?
cat "$log"
[ "$propose_rc" -eq 0 ] || die "chain-config propose exited $propose_rc (see $log)"
grep -q "proposal accepted" "$log" || die "propose did not report acceptance (see $log)"

echo "[ok] proposal round-trip accepted — waiting for the committed row"

# The row's PRIMARY KEY is (param_id, effective_block) — param_id 2 is
# BLOCK_INTERVAL_SEC (nodus_chain_config.h). Wait for the row itself,
# never a bare tip+1 (stagef_cmt_wait_row's own DELTA 2 rationale).
row_h=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM chain_config_history WHERE param_id=2 AND effective_block=$effective;") \
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
         WHERE param_id=2 AND effective_block=$effective;" 2>/dev/null || echo ERR)
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
