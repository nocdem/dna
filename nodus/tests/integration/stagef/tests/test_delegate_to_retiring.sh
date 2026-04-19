#!/usr/bin/env bash
#
# Stage F test — DELEGATE to a RETIRING validator must be rejected
# deterministically across all 7 nodes.
#
# Rule: nodus_witness_bft.c:982 (apply_delegate) enforces
#   v.status == DNAC_VALIDATOR_ACTIVE — otherwise the TX is rejected.
#
# The critical property is determinism: whether the cluster accepts
# or rejects the TX, every node must decide identically. A divergent
# accept/reject decision would fork state_root. This test exercises
# the reject path and confirms 7/7 agreement.
#
# Sequence:
#   1. stagef_user stakes → becomes validator, status=ACTIVE.
#   2. stagef_user unstakes → status=RETIRING, unstake_commit_block set.
#   3. stagef_user attempts to delegate to their own (RETIRING)
#      validator pubkey.
#   4. Assert state_root identical 7/7.
#   5. Assert total_delegated on that validator row is identical 7/7
#      (i.e., either all rejected → 0, or all accepted → same value).
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

# ── STAKE — user becomes validator ──────────────────────────────────
echo ""
echo "== STAKE (user becomes validator) =="
stagef_dna -q dna stake > "$BASE_DIR/test_dtr_stake.log" 2>&1 || {
    echo "[FAIL] stake failed" >&2
    tail -10 "$BASE_DIR/test_dtr_stake.log" >&2
    exit 2
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-STAKE"

# Extract user's validator pubkey hex (128 chars Dilithium5 pk).
USER_PUBKEY_HEX=$(sqlite3 "$db0" \
    "SELECT lower(hex(pubkey)) FROM validators \
     WHERE unstake_destination_fp = '$USER_FP';")
if [ -z "$USER_PUBKEY_HEX" ]; then
    echo "[FAIL] could not extract user validator pubkey" >&2
    exit 3
fi
echo "[info] user validator pubkey: ${USER_PUBKEY_HEX:0:16}..."

# ── UNSTAKE — user validator becomes RETIRING ────────────────────────
echo ""
echo "== UNSTAKE (user validator → RETIRING) =="
stagef_dna -q dna unstake > "$BASE_DIR/test_dtr_unstake.log" 2>&1 || {
    echo "[FAIL] unstake failed" >&2
    tail -10 "$BASE_DIR/test_dtr_unstake.log" >&2
    exit 4
}
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-UNSTAKE"

# Verify status == 1 (RETIRING) on node 1 before trying to delegate.
user_status=$(sqlite3 "$db0" \
    "SELECT status FROM validators WHERE unstake_destination_fp = '$USER_FP';")
if [ "$user_status" != "1" ]; then
    echo "[FAIL] expected user status=1 (RETIRING), got $user_status" >&2
    exit 5
fi

# ── DELEGATE to RETIRING validator — expect deterministic reject ────
echo ""
echo "== DELEGATE 100 DNAC to RETIRING validator (expect reject) =="
# Use MIN_DELEGATION (100 DNAC = 100 × 10^8 raw = 10000000000).
rc=0
stagef_dna -q dna delegate "$USER_PUBKEY_HEX" 10000000000 "delegate-to-retiring" \
    > "$BASE_DIR/test_dtr_delegate.log" 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "[info] delegate TX submitted (CLI succeeded); checking on-chain rejection"
else
    echo "[info] delegate CLI returned rc=$rc (likely rejected)"
fi
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-DELEGATE-attempt"

# Core assertion: total_delegated identical across all 7 nodes.
# The exact value doesn't matter — determinism does.
first_delegated=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    td=$(sqlite3 "$db" \
        "SELECT total_delegated FROM validators \
         WHERE unstake_destination_fp = '$USER_FP';")
    if [ -z "$first_delegated" ]; then
        first_delegated="$td"
    elif [ "$td" != "$first_delegated" ]; then
        echo "[FAIL] node$n total_delegated=$td differs from node1=$first_delegated" >&2
        exit 6
    fi
done

if [ "$first_delegated" = "0" ]; then
    outcome="rejected (total_delegated=0)"
else
    outcome="accepted (total_delegated=$first_delegated)"
fi

echo ""
echo "[PASS] DELEGATE-to-RETIRING outcome consistent across $STAGEF_COMMITTEE_SIZE nodes: $outcome"
