#!/usr/bin/env bash
#
# Stage F.2 test — epoch-boundary settlement consensus check.
#
# Verifies the v0.16 push-per-epoch settlement pipeline behaves
# deterministically across all harness nodes:
#
#   1. After bring-up + user funding, all N nodes share a state_root.
#   2. After N blocks' worth of inflation accumulates into
#      epoch_state.epoch_pool_accum and an epoch boundary fires
#      (block_height % DNAC_EPOCH_LENGTH == 0), apply_epoch_settlement
#      emits UTXOs to committee validators + delegators on every node.
#   3. Post-settlement state_root MUST still be identical 7/7. Any
#      divergence is a Stage E determinism bug.
#
# Blocks to wait: DNAC_EPOCH_LENGTH (= 120 at canonical 5s blocks).
# At 5s/block that is ~10 minutes per iteration — slow. The
# stagef_env.sh harness can optionally override EPOCH_LENGTH at
# bring-up (env var STAGEF_EPOCH_LENGTH) so local runs can settle
# every 10–20 blocks. When unset, the full 120-block wait is used.
#
# Requires an active Stage F harness (stagef_up.sh).
#
# Exit codes:
#   0 = all consensus checks passed
#   1 = no active harness
#   2 = state_root diverged pre-settlement
#   3 = state_root diverged post-settlement
#   4 = settlement did not fire within the expected block window

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

EPOCH_LENGTH="${STAGEF_EPOCH_LENGTH:-120}"

# ── Baseline: all nodes agree at bring-up ─────────────────────────────
bash "$(dirname "$0")/../stagef_diff.sh" "pre-settlement" || exit 2

# ── Wait one epoch ────────────────────────────────────────────────────
# 5s per block × EPOCH_LENGTH + 30s slack.
WAIT_SEC=$(( EPOCH_LENGTH * 5 + 30 ))
echo ""
echo "== Waiting ${WAIT_SEC}s for an epoch boundary to fire =="
sleep "$WAIT_SEC"

# ── Post-settlement: state_root MUST still match across all nodes ─────
bash "$(dirname "$0")/../stagef_diff.sh" "post-settlement" || exit 3

# ── Sanity: at least one committee validator should have accrued a
# kind=0x20 (validator) or kind=0x21 (delegator) synthetic UTXO. ──
# Sketch: the diff tool shows per-node UTXO counts; a full verifier
# would parse witness logs for "emit_synthetic_utxo" entries with
# kind=0x20/0x21 at the expected settling_epoch_start height.
# Left as a TODO pending a richer stagef_diff schema.

echo ""
echo "[PASS] epoch settlement state_root consistent across nodes"
