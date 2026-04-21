#!/usr/bin/env bash
#
# Stage F.4 test — halving-boundary emission determinism.
#
# The unit test nodus/tests/test_emission_boundaries.c covers the
# pure function at every one of the 5 halving boundaries
# (Y1→Y2 ... Y5→floor). This script is the consensus counterpart:
# once a harness run crosses a boundary, every node must agree on
# (a) emission_per_block output at the boundary height, and
# (b) the state_root that flows from total_minted += emission.
#
# Normally the first halving boundary is block 6,307,200 — years
# into the future at 5s blocks. For a local run to reach a boundary
# in useful time, the harness can optionally override
# DNAC_BLOCKS_PER_YEAR via a test-only env flag (STAGEF_BLOCKS_PER_YEAR,
# e.g. = 20). With BY=20 the halving fires at block 20 → ~100s wait
# on a 5s-block cluster.
#
# Requires an active Stage F harness (stagef_up.sh) started with a
# test-only BLOCKS_PER_YEAR override.
#
# Exit:
#   0  = boundary crossed, state_root still 7/7 consistent
#   1  = no active harness
#   2  = pre-boundary state_root diverged
#   3  = post-boundary state_root diverged
#   99 = BLOCKS_PER_YEAR override not set (test refuses to wait
#        through the production-scale 6.3M block window)

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

BY="${STAGEF_BLOCKS_PER_YEAR:-0}"
if [ "$BY" = "0" ]; then
    echo "[SKIP] STAGEF_BLOCKS_PER_YEAR not set — refusing to wait"
    echo "       through the production 6,307,200-block halving cycle."
    echo "       Export STAGEF_BLOCKS_PER_YEAR=20 (or similar) at"
    echo "       stagef_up.sh invocation to exercise this test."
    exit 99
fi

echo "== Baseline (pre-boundary) consensus check =="
bash "$(dirname "$0")/../stagef_diff.sh" "pre-boundary" || exit 2

# Wait through the boundary. 5s per block × BY + slack.
WAIT_SEC=$(( BY * 5 + 30 ))
echo ""
echo "== Waiting ${WAIT_SEC}s for block ${BY} (halving boundary) to fire =="
sleep "$WAIT_SEC"

echo ""
echo "== Post-boundary consensus check =="
bash "$(dirname "$0")/../stagef_diff.sh" "post-boundary" || exit 3

echo ""
echo "[PASS] halving boundary crossed, state_root consistent across nodes"
