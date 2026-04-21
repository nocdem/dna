#!/usr/bin/env bash
#
# Stage F test — UNSTAKE consensus check (phase 1: RETIRING transition).
#
# Validator submits UNSTAKE TX. Verifies that:
#   1. TX commits and validator status transitions to RETIRING.
#   2. unstake_commit_block is set identically on all 7 nodes.
#   3. state_root stays identical 7/7 after commit.
#
# The phase-2 unlock (self-stake returns as UTXO after
# DNAC_UNSTAKE_COOLDOWN_BLOCKS = 17280 blocks ≈ 24 h at 5 s block
# interval) is NOT testable in < 60 s and is left for a production
# deploy check.
#
# Depends on test_stake.sh: the user must be a validator before
# UNSTAKE can apply. If run standalone, stake first.
#
# Requires an active Stage F harness.

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

# Create a fresh funded test user, stake them, then test UNSTAKE.
# Self-contained — avoids ordering collisions with test_delegate_to_retiring
# (which already retires stagef_user) or test_stake (which stakes stagef_user).
TEST_HOME=$(stagef_mk_funded_user "unstake" 1200000000000000) || exit 1
USER_FP=$(cat "$TEST_HOME/fp.txt")

# Stake the test user — test UNSTAKE always starts from fresh ACTIVE state.
echo "[info] staking test user before UNSTAKE"
stagef_dna_as "$TEST_HOME" -q dna stake > "$BASE_DIR/test_unstake_prestake.log" 2>&1 || {
    echo "[FAIL] pre-stake failed" >&2
    tail -10 "$BASE_DIR/test_unstake_prestake.log" >&2
    exit 2
}
sleep 8

bash "$(dirname "$0")/../stagef_diff.sh" "pre-UNSTAKE"

# ── UNSTAKE ─────────────────────────────────────────────────────────
echo ""
echo "== UNSTAKE (trigger RETIRING + cooldown) =="
stagef_dna_as "$TEST_HOME" -q dna unstake \
    > "$BASE_DIR/test_unstake.log" 2>&1 || {
    echo "[FAIL] unstake submit failed" >&2
    tail -10 "$BASE_DIR/test_unstake.log" >&2
    exit 3
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-UNSTAKE"

# Verify validator status = RETIRING (1) on every node and
# unstake_commit_block is non-zero + identical across nodes.
first_ucb=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    row=$(sqlite3 "$db" \
      "SELECT status || '|' || unstake_commit_block \
       FROM validators \
       WHERE unstake_destination_fp = '$USER_FP';")
    status=$(echo "$row" | cut -d'|' -f1)
    ucb=$(echo "$row" | cut -d'|' -f2)
    if [ "$status" != "1" ]; then
        echo "[FAIL] node$n: status=$status expected=1 (RETIRING)" >&2
        exit 4
    fi
    if [ "$ucb" = "0" ] || [ -z "$ucb" ]; then
        echo "[FAIL] node$n: unstake_commit_block not set" >&2
        exit 5
    fi
    if [ -z "$first_ucb" ]; then
        first_ucb="$ucb"
    elif [ "$ucb" != "$first_ucb" ]; then
        echo "[FAIL] node$n unstake_commit_block=$ucb differs from node1=$first_ucb" >&2
        exit 6
    fi
done

echo ""
echo "[PASS] UNSTAKE consensus intact — validator RETIRING at block $first_ucb across $STAGEF_COMMITTEE_SIZE nodes"
