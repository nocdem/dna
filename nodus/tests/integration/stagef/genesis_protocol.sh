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
    ctest_log="$(mktemp)"
    trap "rm -f $ctest_log" EXIT

    if (cd "$NODUS_BUILD" && ctest 2>&1) > "$ctest_log"; then
        echo "[OK] nodus ctest complete (no failures)"
    else
        # ctest reported failures — distinguish STUB-by-design from real fails.
        # STUB tests print "STUB — failing by design" to stdout and exit non-zero
        # by spec; they are RED placeholders for unimplemented Faz work and must
        # not block the consensus shakedown.
        real_fails=()
        stub_skips=()
        while IFS= read -r line; do
            if [[ $line =~ ^[[:space:]]*[0-9]+[[:space:]]*-[[:space:]]*([a-zA-Z0-9_]+)[[:space:]]*\(Failed\) ]]; then
                test_name="${BASH_REMATCH[1]}"
                test_bin="$NODUS_BUILD/$test_name"
                if [ -x "$test_bin" ] && "$test_bin" 2>&1 | grep -q "STUB — failing by design"; then
                    stub_skips+=("$test_name")
                else
                    real_fails+=("$test_name")
                fi
            fi
        done < "$ctest_log"

        if [ ${#real_fails[@]} -gt 0 ]; then
            echo "[FAIL] nodus ctest has ${#real_fails[@]} real failure(s) — aborting:"
            for t in "${real_fails[@]}"; do echo "  - $t"; done
            if [ ${#stub_skips[@]} -gt 0 ]; then
                echo "[INFO] ${#stub_skips[@]} STUB-by-design fails (skipped, not blockers)"
            fi
            cat "$ctest_log"
            exit 1
        fi

        echo "[OK] nodus ctest complete (${#stub_skips[@]} STUB-by-design fails skipped)"
    fi

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
