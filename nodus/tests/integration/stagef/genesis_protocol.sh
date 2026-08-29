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

# O15B §7 — REACHABILITY, REPORTED PER SCENARIO.
#
# An exit code alone cannot distinguish "setup failed" from "the consensus
# assertion ran and disagreed", and it cannot detect the worse case: a
# scenario that returns 0 without ever reaching the thing it exists to
# check. Both were live before this season — five scenarios failed for one
# shared setup reason and were reported as five independent consensus
# failures.
#
# Scenarios record marks via stagef_sentinel (stagef_env.sh). This reads
# them back and classifies the run. A PASS that never recorded ASSERT_RUN
# is converted to a FAILURE: a green scenario that skipped its terminal
# assertion is not coverage, and calling it a pass is how coverage silently
# evaporates.
#
# A scenario that records NOTHING is reported as UNINSTRUMENTED rather than
# failed — the sentinels are being adopted, and a scenario that predates
# them still runs its real assertions. That distinction is stated here so a
# reader is not misled into thinking every green run is proven.
STAGEF_ENV="$HERE/stagef_env.sh"
# shellcheck source=/dev/null
. "$STAGEF_ENV" 2>/dev/null || true

UNINSTRUMENTED=0

run_one() {
    local path="$1"
    local name
    name="$(basename "$path" .sh)"
    local out
    out="$(bash "$path" 2>&1)"
    local rc=$?

    local marks
    marks="$(stagef_sentinel_summary "$name" 2>/dev/null || printf 'NONE')"
    local reached_assert=0 instrumented=1
    case "$marks" in
        NONE|'') instrumented=0 ;;
    esac
    if stagef_sentinel_has "$name" ASSERT_RUN 2>/dev/null; then
        reached_assert=1
    fi

    if [ $rc -eq 0 ]; then
        if [ $instrumented -eq 1 ] && [ $reached_assert -eq 0 ]; then
            printf '  [FAIL] %s (rc=0 but NEVER REACHED ITS TERMINAL ASSERTION; marks: %s)\n' \
                   "$name" "$marks"
            printf -- '--- begin full output ---\n'
            printf '%s\n' "$out"
            printf -- '--- end full output ---\n'
            FAIL=$((FAIL + 1))
            FAILED_TESTS+=("$name (vacuous pass)")
            return
        fi
        if [ $instrumented -eq 0 ]; then
            printf '  [PASS] %s (UNINSTRUMENTED — no reachability sentinels)\n' "$name"
            UNINSTRUMENTED=$((UNINSTRUMENTED + 1))
        else
            printf '  [PASS] %s (marks: %s)\n' "$name" "$marks"
        fi
        PASS=$((PASS + 1))
    elif [ $rc -eq 99 ]; then
        printf '  [SKIP] %s (rc=99)\n' "$name"
        SKIP=$((SKIP + 1))
    else
        # The marks are the diagnosis: they say WHERE it stopped, which is
        # the difference between "the fixture broke" and "consensus
        # disagreed" — a distinction the exit code cannot carry.
        printf '  [FAIL] %s (rc=%d; reached: %s)\n' "$name" "$rc" "$marks"
        printf -- '--- begin full output ---\n'
        printf '%s\n' "$out"
        printf -- '--- end full output ---\n'
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$name")
    fi
}

if [ $SCENARIOS_ONLY -eq 0 ]; then
    # Defensive teardown — leftover stagef nodes from a previous run
    # (incomplete Phase 4 cleanup, Ctrl+C, etc.) hold ports 14001-34004
    # and would cause test_server to fail in Phase 1 with "Failed to
    # listen on TCP 127.0.0.1:14001". Idempotent — no-op if no run.
    bash "$HERE/stagef_down.sh" >/dev/null 2>&1 || true

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
                # Capture stdout via command substitution + `|| true` —
                # STUB binaries exit 1 by design, which would trip
                # `set -o pipefail` if we piped directly into grep.
                if [ -x "$test_bin" ]; then
                    test_out="$("$test_bin" 2>&1 || true)"
                    if [[ "$test_out" == *"STUB — failing by design"* ]]; then
                        stub_skips+=("$test_name")
                        continue
                    fi
                fi
                real_fails+=("$test_name")
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

# ── Scripts that MUST NOT be in an automated sweep ───────────────────
#
# Running the whole directory blindly is NOT a clean sweep, and the
# README says so at its "Phase 3" bullet. Two scripts here exit non-zero
# BY DESIGN, and including them made this runner's own red meaningless:
# a reader who sees `SCENARIOS_RC=1` without opening the per-scenario
# output concludes the tree is broken when it is not. That cost a full
# misattribution round on 2026-08-28 — three scenarios that never ran
# (missing NODUS_FAULT_*) plus these two were reported as eight code
# failures; exactly one was real, and it was in a test's assertion.
#
# To ADD an entry: it must be a script whose non-zero exit is the
# CORRECT result on a healthy tree, and the reason must already be
# written in the README's scenario tables. Anything else is a failure
# and belongs in the count.
#
#   test_med28_negative.sh — a NEGATIVE CONTROL. It runs the MED-28
#     injection against a build with the retention call REMOVED, and is
#     driven manually against a throwaway neutralized build in /tmp.
#     Against a healthy build it fails with "a node retained a batch —
#     this build is NOT neutralized", and that failure is the CORRECT
#     result. The README: "Never add it to an automated run."
#   test_v2_grow_7_20.sh — marked "BROKEN — do not run" in the README.
#     It wants -DNODUS_V2_ACTIVATION=ON, an option deleted with the
#     activation ceremony (O15J Faz 3). Rewriting it is Faz 4's job.
#
# Excluded scripts are ANNOUNCED, never silently skipped — a reader must
# be able to see that the sweep did not cover them.
GENESIS_EXCLUDE=(
    "test_med28_negative"
    "test_v2_grow_7_20"
)

is_excluded() {
    local base="$1" e
    for e in "${GENESIS_EXCLUDE[@]}"; do
        [ "$base" = "$e" ] && return 0
    done
    return 1
}

banner "Phase 3: scenario tests (alphabetical, exit-code only)"
for t in "$HERE"/tests/*.sh; do
    base=$(basename "$t" .sh)
    if is_excluded "$base"; then
        echo "  [EXCLUDED] $base — non-zero exit is the CORRECT result here;"
        echo "             see GENESIS_EXCLUDE in this script. NOT swept."
        continue
    fi
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
if [ "$UNINSTRUMENTED" -gt 0 ]; then
    printf '%s scenario(s) carry NO reachability sentinels — their PASS is\n' \
           "$UNINSTRUMENTED"
    printf 'an exit code, not a proof that a terminal assertion ran.\n'
fi
if [ $FAIL -gt 0 ]; then
    printf 'Failed tests:\n'
    for name in "${FAILED_TESTS[@]}"; do
        printf '  - %s\n' "$name"
    done
    exit 1
fi
exit 0
