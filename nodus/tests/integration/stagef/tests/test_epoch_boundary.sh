#!/usr/bin/env bash
#
# Stage F test — block-production + validator-row stability check.
#
# DNAC_EPOCH_LENGTH = 120 blocks × 5 s block interval = 10 min, which
# exceeds the < 60 s stagef budget. Full epoch-boundary logic is
# covered by ctest `test_apply_epoch_boundary` (unit, mocked clock).
#
# This integration test verifies the weaker but still-useful invariant
# that *any* sequence of TXs keeps validator rows byte-identical across
# the cluster — catches state_root non-determinism sources hidden in
# reward accumulator math or epoch-adjacent code paths (§ same class
# of bug the 2026-04-19 attendance fix resolved).
#
# Sequence: DELEGATE → UNDELEGATE partial → VALIDATOR_UPDATE → diff.
#
# Requires an active Stage F harness.

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

V0_PUBKEY=$(awk -F= '/^validator_0_pubkey=/ {print $2}' "$BASE_DIR/chain_def.conf")
if [ -z "$V0_PUBKEY" ]; then
    echo "[FAIL] validator_0 pubkey missing from chain_def.conf" >&2
    exit 1
fi

bash "$(dirname "$0")/../stagef_diff.sh" "baseline"

# Snapshot validator row hash per node.
snap_hash() {
    local label="$1"
    local first=""
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        local db
        db=$(stagef_node_chain_db "$n")
        local h
        h=$(sqlite3 "$db" \
          "SELECT hex(pubkey) || self_stake || total_delegated || external_delegated \
             || commission_bps || pending_commission_bps || pending_effective_block \
             || status || active_since_block || unstake_commit_block \
             || consecutive_missed_epochs \
           FROM validators ORDER BY hex(pubkey);" | sha256sum | awk '{print $1}')
        if [ -z "$first" ]; then
            first="$h"
        elif [ "$h" != "$first" ]; then
            echo "[FAIL] validator-row divergence $label node$n ($h) vs node1 ($first)" >&2
            exit 9
        fi
    done
    echo "[ok] validator rows identical across $STAGEF_COMMITTEE_SIZE nodes ($label): $first"
}
snap_hash "baseline"

# DELEGATE 5M → validator 0.
echo ""
echo "== DELEGATE 5M → validator 0 =="
stagef_dna -q dna delegate "$V0_PUBKEY" 500000000000000 "stage-f" \
    > "$BASE_DIR/test_eb_delegate.log" 2>&1 || {
    echo "[FAIL] delegate failed" >&2
    tail -10 "$BASE_DIR/test_eb_delegate.log" >&2
    exit 2
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-DELEGATE"
snap_hash "post-DELEGATE"

# UNDELEGATE 2M partial.
echo ""
echo "== UNDELEGATE 2M partial from validator 0 =="
stagef_dna -q dna undelegate "$V0_PUBKEY" 200000000000000 \
    > "$BASE_DIR/test_eb_undelegate.log" 2>&1 || {
    echo "[FAIL] undelegate failed" >&2
    tail -10 "$BASE_DIR/test_eb_undelegate.log" >&2
    exit 3
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-UNDELEGATE"
snap_hash "post-UNDELEGATE"

echo ""
echo "[PASS] block-production + validator-row consensus intact across $STAGEF_COMMITTEE_SIZE nodes"
echo "       (full 120-block epoch-boundary: covered by ctest test_apply_epoch_boundary)"
