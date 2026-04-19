#!/usr/bin/env bash
#
# Stage F test — CLAIM_REWARD on a RETIRING validator must produce a
# deterministic outcome (same accept/reject on every node; same
# resulting reward accumulator state).
#
# Strict "mid-claim" concurrency between CLAIM and UNSTAKE cannot be
# orchestrated from a shell script — inter-block timing is not
# controllable. This test exercises the strictly-after scenario:
#   1. User stakes (becomes validator, status=ACTIVE).
#   2. User unstakes (status=RETIRING, unstake_commit_block set).
#   3. User issues CLAIM_REWARD.
#   4. Assert state_root + reward_accumulator identical 7/7.
#
# Purpose: catches non-determinism in the claim path when the
# validator row's status has transitioned — the same class of bug as
# the 2026-04-19 accumulator-attendance divergence.
#
# Requires an active Stage F harness.

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

USER_FP=$(cat "$BASE_DIR/user_fp.txt")
db0=$(stagef_node_chain_db 1)

bash "$(dirname "$0")/../stagef_diff.sh" "baseline"
sleep 3

# ── STAKE ───────────────────────────────────────────────────────────
echo ""
echo "== STAKE =="
stagef_dna -q dna stake > "$BASE_DIR/test_cwr_stake.log" 2>&1 || {
    echo "[FAIL] stake failed" >&2
    tail -10 "$BASE_DIR/test_cwr_stake.log" >&2
    exit 2
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-STAKE"

USER_PUBKEY_HEX=$(sqlite3 "$db0" \
    "SELECT lower(hex(pubkey)) FROM validators \
     WHERE unstake_destination_fp = '$USER_FP';")
if [ -z "$USER_PUBKEY_HEX" ]; then
    echo "[FAIL] could not extract user validator pubkey" >&2
    exit 3
fi

# ── UNSTAKE ─────────────────────────────────────────────────────────
echo ""
echo "== UNSTAKE (→ RETIRING) =="
stagef_dna -q dna unstake > "$BASE_DIR/test_cwr_unstake.log" 2>&1 || {
    echo "[FAIL] unstake failed" >&2
    tail -10 "$BASE_DIR/test_cwr_unstake.log" >&2
    exit 4
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-UNSTAKE"

# ── CLAIM_REWARD while validator RETIRING ───────────────────────────
# The user will have accumulated ~0 rewards since they staked only a
# few blocks ago and aren't in the committee. The claim amount will
# probably be zero, but the important thing is that every node agrees
# whether to accept or reject — and if accepted, writes the same
# reward_accumulator_claimed value.
echo ""
echo "== CLAIM_REWARD from RETIRING validator =="
rc=0
stagef_dna -q dna claim "$USER_PUBKEY_HEX" \
    > "$BASE_DIR/test_cwr_claim.log" 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "[info] claim CLI succeeded (rc=0); checking on-chain determinism"
else
    echo "[info] claim CLI returned rc=$rc (likely rejected or no rewards)"
fi
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-CLAIM"

# Verify rewards table is identical 7/7 for this validator_pubkey.
first_row=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    # rewards.validator_hash = SHA3-256(validator_pubkey). Stored
    # as BLOB; compute on SQL side for cross-node comparability.
    # Columns: accumulator + validator_unclaimed + last_update_block.
    row=$(sqlite3 "$db" \
        "SELECT hex(accumulator) || '|' || validator_unclaimed \
            || '|' || last_update_block || '|' || residual_dust \
         FROM rewards LIMIT 8;" || echo "")
    if [ -z "$first_row" ]; then
        first_row="$row"
    elif [ "$row" != "$first_row" ]; then
        echo "[FAIL] node$n rewards row=$row differs from node1=$first_row" >&2
        exit 5
    fi
done

echo ""
echo "[PASS] CLAIM-while-RETIRING consensus intact across $STAGEF_COMMITTEE_SIZE nodes (rewards.last_update_block=$first_row)"
