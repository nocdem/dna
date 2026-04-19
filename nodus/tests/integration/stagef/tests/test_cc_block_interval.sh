#!/usr/bin/env bash
#
# Stage F test — chain-config BLOCK_INTERVAL_SEC proposal (hard-fork v1).
#
# Committee operator (node 1) proposes a BLOCK_INTERVAL_SEC change via
# `nodus-cli chain-config propose`. The flow fans out to all 7 peers,
# collects w_cc_vote_rsp, builds a DNAC_TX_CHAIN_CONFIG, and submits.
# Verifies:
#   1. 7/7 votes collected (min quorum = 5).
#   2. chain_config_history row lands with identical (param_id, value,
#      effective_block) on all 7 nodes.
#   3. state_root stays identical 7/7 after commit.
#
# The finalize_block consumer (§ Stage D) picks up the new value once
# chain_head reaches effective_block — not tested here (would need
# another 20+ blocks = 100 s wall clock).
#
# Requires an active Stage F harness.

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

NODUS_CLI="$STAGEF_REPO_ROOT/nodus/build/nodus-cli"
V0_FP=$(awk -F= '/^validator_0_fp=/ {print $2}' "$BASE_DIR/chain_def.conf")
if [ -z "$V0_FP" ]; then
    echo "[FAIL] validator_0_fp missing from chain_def.conf" >&2
    exit 1
fi

bash "$(dirname "$0")/../stagef_diff.sh" "baseline"

# Short settle period: the CLI's first send after harness bring-up can
# beat the BFT committee into steady state if the roster is still
# converging; give the cluster an extra 3 s before the first TX.
sleep 3

# Fund node 1's validator identity so it can pay the TX fee (base 0.01 DNAC).
# Send 1 DNAC = 100_000_000 raw units.
echo ""
echo "== fund validator_0 identity with 1 DNAC for chain-config fee =="
stagef_dna -q dna send "$V0_FP" 100000000 "cc-fund" \
    > "$BASE_DIR/test_cc_fund.log" 2>&1 || {
    echo "[FAIL] fund tx failed" >&2
    tail -10 "$BASE_DIR/test_cc_fund.log" >&2
    exit 2
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-fund"

# BLOCK_INTERVAL_SEC is a safety-critical param: grace tier is
# 12 × EPOCH_LENGTH = 1440 blocks. The apply rule is
# `effective_block >= commit_block + grace`, so we must choose an
# effective block at least (head + 1 + 1440) blocks in the future.
# Activation at that height is intentionally unreachable in a 60-second
# harness — we test only the propose → 7/7 vote → TX commit flow,
# not the finalize_block consumer picking up the new value.
head_block=$(sqlite3 "$(stagef_node_chain_db 1)" \
    "SELECT MAX(height) FROM blocks;")
EFFECTIVE=$(( head_block + 1500 ))
NEW_INTERVAL=7   # seconds; range [1,15] per hard-fork v1 allowlist

echo ""
echo "== chain-config propose BLOCK_INTERVAL_SEC=$NEW_INTERVAL effective=$EFFECTIVE =="
"$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
    -i "$(stagef_node_dir 1)/identity" \
    chain-config propose \
        --param BLOCK_INTERVAL_SEC \
        --value "$NEW_INTERVAL" \
        --effective "$EFFECTIVE" \
    > "$BASE_DIR/test_cc_block_interval.log" 2>&1 || {
    echo "[FAIL] chain-config propose failed" >&2
    tail -30 "$BASE_DIR/test_cc_block_interval.log" >&2
    exit 3
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-CC-BLOCK_INTERVAL"

# Verify chain_config_history row identical on all 7 nodes.
# Param IDs per dnac hard-fork v1: 1=MAX_TXS_PER_BLOCK, 2=BLOCK_INTERVAL_SEC, 3=INFLATION_START_BLOCK.
PARAM_ID=2
first_row=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    row=$(sqlite3 "$db" \
      "SELECT param_id || '|' || new_value || '|' || effective_block \
       FROM chain_config_history \
       WHERE param_id = $PARAM_ID AND new_value = $NEW_INTERVAL \
         AND effective_block = $EFFECTIVE;")
    if [ -z "$row" ]; then
        echo "[FAIL] node$n: chain_config_history row missing" >&2
        exit 4
    fi
    if [ -z "$first_row" ]; then
        first_row="$row"
    elif [ "$row" != "$first_row" ]; then
        echo "[FAIL] node$n chain_config_history row=$row differs from node1=$first_row" >&2
        exit 5
    fi
done

echo ""
echo "[PASS] chain-config BLOCK_INTERVAL_SEC=$NEW_INTERVAL @ block $EFFECTIVE committed identically on $STAGEF_COMMITTEE_SIZE nodes"
