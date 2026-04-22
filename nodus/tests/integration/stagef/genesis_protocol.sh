#!/usr/bin/env bash
#
# Genesis Protocol — deterministic Stage F consensus-shakedown runner.
#
# Single assertion method: EXIT CODE. No stdout filtering of any kind.
#   rc=0  → PASS
#   rc=99 → SKIP (reserved TODO sentinel, test_supply_invariant_halt)
#   else  → FAIL (full stdout echoed, unbounded)
#
# Usage:
#   bash genesis_protocol.sh              # full run (ctest + stagef)
#   bash genesis_protocol.sh --scenarios  # only scenario tests (assumes
#                                         # stagef already up)
#
# Exit: 0 if all PASS (SKIPs allowed), 1 if any FAIL.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NODUS_BUILD="$(cd "$HERE/../../../build" && pwd)"
STAGEF_EPOCH_LENGTH="${STAGEF_EPOCH_LENGTH:-15}"
export STAGEF_EPOCH_LENGTH

SCENARIOS_ONLY=0
if [ "${1:-}" = "--scenarios" ]; then
    SCENARIOS_ONLY=1
fi

PASS=0
FAIL=0
SKIP=0
FAILED_TESTS=()

banner() { printf '\n=== %s ===\n' "$*"; }

run_one() {
    local path="$1"
    local name
    name="$(basename "$path" .sh)"
    local out
    out="$(bash "$path" 2>&1)"
    local rc=$?

    if [ $rc -eq 0 ]; then
        printf '  [PASS] %s\n' "$name"
        PASS=$((PASS + 1))
    elif [ $rc -eq 99 ]; then
        printf '  [SKIP] %s (rc=99)\n' "$name"
        SKIP=$((SKIP + 1))
    else
        printf '  [FAIL] %s (rc=%d)\n' "$name" "$rc"
        printf -- '--- begin full output ---\n'
        printf '%s\n' "$out"
        printf -- '--- end full output ---\n'
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$name")
    fi
}

if [ $SCENARIOS_ONLY -eq 0 ]; then
    banner "Phase 1: nodus ctest (unit suite)"
    if ! (cd "$NODUS_BUILD" && ctest --output-on-failure); then
        echo "[FAIL] nodus ctest failed — aborting Genesis Protocol"
        exit 1
    fi
    echo "[OK] nodus ctest complete"

    banner "Phase 2: stagef_up.sh — 7-node consensus cluster"
    bash "$HERE/stagef_down.sh"
    if ! bash "$HERE/stagef_up.sh"; then
        echo "[FAIL] stagef_up.sh failed — aborting Genesis Protocol"
        exit 1
    fi
fi

banner "Phase 3: scenario tests (alphabetical, exit-code only)"
for t in "$HERE"/tests/*.sh; do
    run_one "$t"
done

banner "Phase 4: stagef_down.sh"
if [ $SCENARIOS_ONLY -eq 0 ]; then
    bash "$HERE/stagef_down.sh"
    echo "[OK] stagef torn down"
else
    echo "[SKIP] teardown (--scenarios mode)"
fi

banner "Genesis Protocol result: $PASS PASS / $FAIL FAIL / $SKIP SKIP"
if [ $FAIL -gt 0 ]; then
    printf 'Failed tests:\n'
    for name in "${FAILED_TESTS[@]}"; do
        printf '  - %s\n' "$name"
    done
    exit 1
fi
exit 0
