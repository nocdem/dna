#!/usr/bin/env bash
#
# Stage F test — VALIDATOR_UPDATE consensus check.
#
# An active validator updates its commission rate. Verifies:
#   1. TX commits on all 7 nodes.
#   2. pending_commission_bps + pending_effective_block are set
#      identically on every node (deterministic across the cluster).
#   3. state_root stays identical 7/7 after commit.
#
# Phase-2 check (commission actually takes effect after grace) is NOT
# tested here — the epoch-boundary wait would exceed the < 60 s budget.
#
# Requires an active Stage F harness + the user must be a validator.
# If the user is not a validator yet, stakes first (re-usable block).

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

USER_FP=$(cat "$BASE_DIR/user_fp.txt")

# Ensure the user is an ACTIVE validator. If not, stake first.
db0=$(stagef_node_chain_db 1)
user_status=$(sqlite3 "$db0" \
  "SELECT status FROM validators \
   WHERE unstake_destination_fp = '$USER_FP';" 2>/dev/null || echo "")
if [ -z "$user_status" ]; then
    echo "[info] user not yet a validator — staking first"
    stagef_dna -q dna stake > "$BASE_DIR/test_vu_prestake.log" 2>&1 || {
        echo "[FAIL] pre-stake failed" >&2
        tail -10 "$BASE_DIR/test_vu_prestake.log" >&2
        exit 2
    }
    sleep 8
elif [ "$user_status" != "0" ]; then
    echo "[FAIL] user validator status=$user_status; needs to be ACTIVE(0)." \
         "Run on a fresh harness or after stake only." >&2
    exit 2
fi

bash "$(dirname "$0")/../stagef_diff.sh" "pre-VALIDATOR_UPDATE"

# Snapshot current commission + pending fields.
row_before=$(sqlite3 "$db0" \
  "SELECT commission_bps || '|' || pending_commission_bps || '|' || pending_effective_block \
   FROM validators WHERE unstake_destination_fp = '$USER_FP';")
echo "[info] before: commission|pending|effective = $row_before"

# ── VALIDATOR_UPDATE — change commission 500 → 777 bps ──────────────
NEW_BPS=777
echo ""
echo "== VALIDATOR_UPDATE commission → $NEW_BPS bps (7.77%) =="
stagef_dna -q dna validator-update --commission-bps "$NEW_BPS" \
    > "$BASE_DIR/test_validator_update.log" 2>&1 || {
    echo "[FAIL] validator-update submit failed" >&2
    tail -10 "$BASE_DIR/test_validator_update.log" >&2
    exit 3
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-VALIDATOR_UPDATE"

# Verify pending_commission_bps = $NEW_BPS and pending_effective_block
# is non-zero + identical across all 7 nodes.
first_row=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    row=$(sqlite3 "$db" \
      "SELECT pending_commission_bps || '|' || pending_effective_block \
       FROM validators WHERE unstake_destination_fp = '$USER_FP';")
    pend_bps=$(echo "$row" | cut -d'|' -f1)
    pend_eb=$(echo "$row"  | cut -d'|' -f2)
    if [ "$pend_bps" != "$NEW_BPS" ]; then
        echo "[FAIL] node$n: pending_commission_bps=$pend_bps expected=$NEW_BPS" >&2
        exit 4
    fi
    if [ "$pend_eb" = "0" ] || [ -z "$pend_eb" ]; then
        echo "[FAIL] node$n: pending_effective_block not set" >&2
        exit 5
    fi
    if [ -z "$first_row" ]; then
        first_row="$row"
    elif [ "$row" != "$first_row" ]; then
        echo "[FAIL] node$n pending fields=$row differ from node1=$first_row" >&2
        exit 6
    fi
done

echo ""
echo "[PASS] VALIDATOR_UPDATE consensus intact — pending $NEW_BPS bps at block $(echo "$first_row" | cut -d'|' -f2) across $STAGEF_COMMITTEE_SIZE nodes"
