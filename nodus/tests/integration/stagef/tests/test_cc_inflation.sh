#!/usr/bin/env bash
#
# Stage F test — chain-config INFLATION_START_BLOCK proposal (hard-fork v1).
#
# Same shape as test_cc_block_interval.sh but for the inflation-start
# parameter. Verifies that the 7-node cluster commits the same
# chain_config_history row and state_root 7/7 stays identical.
#
# Grace tier for INFLATION_START_BLOCK is STAGEF_CC_GRACE_SAFETY blocks
# (safety-critical per CC-GOV-001 monotonicity rule). Activation at
# that height is not testable in the 60 s budget; only the commit
# path is verified here.
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
sleep 3

# Fund validator_0 identity (reused if already funded — send is idempotent
# in the sense that it burns one UTXO per call regardless).
echo ""
echo "== fund validator_0 identity with 1 DNAC =="
stagef_dna -q dna send "$V0_FP" 100000000 "cc-fund-inflation" \
    > "$BASE_DIR/test_cc_infl_fund.log" 2>&1 || {
    echo "[FAIL] fund tx failed" >&2
    tail -10 "$BASE_DIR/test_cc_infl_fund.log" >&2
    exit 2
}
sleep 8

head_block=$(sqlite3 "$(stagef_node_chain_db 1)" \
    "SELECT MAX(height) FROM blocks;")
EFFECTIVE=$(( head_block + STAGEF_CC_GRACE_SAFETY + 60 ))
NEW_INFL_START=1000000      # Rule CC-GOV-001: INFLATION_START_BLOCK must be
                            # non-zero. Range on v1 is [0, 2^48].

echo ""
echo "== chain-config propose INFLATION_START_BLOCK=$NEW_INFL_START effective=$EFFECTIVE =="
"$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
    -i "$(stagef_node_dir 1)/identity" \
    chain-config propose \
        --param INFLATION_START_BLOCK \
        --value "$NEW_INFL_START" \
        --effective "$EFFECTIVE" \
    > "$BASE_DIR/test_cc_inflation.log" 2>&1 || {
    echo "[FAIL] chain-config propose failed" >&2
    tail -30 "$BASE_DIR/test_cc_inflation.log" >&2
    exit 3
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-CC-INFLATION_START_BLOCK"

# Verify chain_config_history row identical on all 7 nodes.
# param_id: 3 = INFLATION_START_BLOCK.
PARAM_ID=3
first_row=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    row=$(sqlite3 "$db" \
      "SELECT param_id || '|' || new_value || '|' || effective_block \
       FROM chain_config_history \
       WHERE param_id = $PARAM_ID AND new_value = $NEW_INFL_START \
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
echo "[PASS] chain-config INFLATION_START_BLOCK=$NEW_INFL_START @ block $EFFECTIVE committed identically on $STAGEF_COMMITTEE_SIZE nodes"
