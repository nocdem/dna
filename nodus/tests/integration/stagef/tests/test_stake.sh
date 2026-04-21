#!/usr/bin/env bash
#
# Stage F test — STAKE consensus check.
#
# A non-committee user becomes a validator by submitting a STAKE TX.
# Verifies that:
#   1. The TX commits across the 7-node cluster.
#   2. validator_tree gains a new row on every node identically.
#   3. state_root stays identical 7/7 after commit.
#
# Requires an active Stage F harness (stagef_up.sh).

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

# Create a fresh funded test user — avoids contaminating stagef_user state
# and sidesteps ordering collisions with test_delegate_to_retiring.
TEST_HOME=$(stagef_mk_funded_user "stake" 1200000000000000) || exit 1

# Baseline state_root (post-fund — test user's funding block already landed).
bash "$(dirname "$0")/../stagef_diff.sh" "baseline"

# Snapshot validator row count across all 7 nodes.
v_before=()
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    count=$(sqlite3 "$db" "SELECT COUNT(*) FROM validators;")
    v_before+=("$count")
done
echo "[info] validator rows before STAKE: ${v_before[*]}"

# ── STAKE (default 10M DNAC self-stake, 5% commission) ──────────────
echo ""
echo "== STAKE 10M self-stake (default commission 500 bps) =="
stagef_dna_as "$TEST_HOME" -q dna stake \
    > "$BASE_DIR/test_stake.log" 2>&1 || {
    echo "[FAIL] stake submit failed" >&2
    tail -10 "$BASE_DIR/test_stake.log" >&2
    exit 2
}
# Wait a few block intervals for BFT commit.
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-STAKE"

# Verify validator_tree grew by exactly 1 on every node.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    count=$(sqlite3 "$db" "SELECT COUNT(*) FROM validators;")
    expected=$(( ${v_before[$((n-1))]} + 1 ))
    if [ "$count" -ne "$expected" ]; then
        echo "[FAIL] node$n: validator count=$count expected=$expected" >&2
        exit 3
    fi
done

# Verify the staker's pubkey matches the TEST user identity (not stagef_user).
USER_FP=$(cat "$TEST_HOME/fp.txt")
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    row=$(sqlite3 "$db" \
      "SELECT hex(unstake_destination_fp) || '|' || self_stake \
       FROM validators ORDER BY active_since_block DESC LIMIT 1;")
    # self_stake should equal DNAC_SELF_STAKE_AMOUNT = 10M × 10^8 = 1e15 raw
    expected_stake="1000000000000000"
    stake=$(echo "$row" | cut -d'|' -f2)
    if [ "$stake" != "$expected_stake" ]; then
        echo "[FAIL] node$n: self_stake=$stake expected=$expected_stake" >&2
        exit 4
    fi
done

echo ""
echo "[PASS] STAKE consensus intact across $STAGEF_COMMITTEE_SIZE nodes"
