#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# genesis_protocol_v2.sh — the Ledger V2 half of the Genesis Protocol
# ════════════════════════════════════════════════════════════════════
#
# The legacy runner (genesis_protocol.sh) brings up a chain born from a
# GENESIS TRANSACTION and sweeps the scenarios that exercise it. This one
# brings up a chain born from an operator CONFIG — no transaction, no
# consensus round — and runs the scenarios that exercise the V2 lane.
#
# Both are needed and neither replaces the other. The consensus code is
# ONE implementation threaded with `v2_successor` branches: a legacy
# cluster never takes them, and a V2 cluster never takes the other side.
# The v0.19.37 startup defect lived in such a branch, in a file that
# season had been editing, and no legacy run could have seen it.
#
# ── ASSERTION METHOD: EXIT CODE ONLY ────────────────────────────────
#   0   PASS
#   99  SKIP — a prerequisite was absent. NOT a pass: that coverage did
#       not happen, and it is counted and reported separately.
#   else FAIL — the scenario's full stdout is echoed unbounded (no tail,
#       no grep) and the runner returns 1.
#
# ── WHAT IT DELIBERATELY DOES NOT DO ────────────────────────────────
#   It does not glob tests/*.sh. The legacy runner does, and its own
#   README then has to explain that the sweep includes a negative control
#   whose failure is CORRECT and a script marked BROKEN — which makes its
#   rc=1 not evidence on its own. The V2 list here is explicit, so a red
#   run means a red scenario.
#
# ── ORDER, AND WHY IT IS NOT ALPHABETICAL BY ACCIDENT ───────────────
#   The scenarios are order-independent BY CONSTRUCTION: stagef_up_v2.sh
#   gives every node, plus one non-validator identity, its own genesis
#   allocation, so no two compete for the same single-use leaf. That is
#   the property the legacy suite most conspicuously lacks — see the
#   residue list in README.md. The order below is alphabetical because
#   nothing requires otherwise, and if that ever stops being true the
#   scenario that broke it is the one with the bug.
#
# ── LEAF BUDGET ─────────────────────────────────────────────────────
#   A genesis leaf can be claimed exactly ONCE. Three scenarios consume
#   one each (claim, stake, view_change); the bring-up mints eight. A
#   second full run against the SAME cluster will fail on the claiming
#   scenarios, correctly — bring the cluster up fresh, which is what this
#   runner does by default.
#
# Usage:
#   bash genesis_protocol_v2.sh              # bring up + run + tear down
#   bash genesis_protocol_v2.sh --scenarios  # run only; cluster must be up
#
# ════════════════════════════════════════════════════════════════════
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCENARIOS_ONLY=0
[ "${1:-}" = "--scenarios" ] && SCENARIOS_ONLY=1

V2_TESTS="
test_v2_claim.sh
test_v2_join.sh
test_v2_partial_wipe.sh
test_v2_restart_convergence.sh
test_v2_stake.sh
test_v2_view_change.sh
"

if [ "$SCENARIOS_ONLY" = 0 ]; then
    echo "════ Phase 1 — teardown any previous run ════"
    bash "$HERE/stagef_down.sh" >/dev/null 2>&1 || true

    echo "════ Phase 2 — bring up a pure Ledger V2 cluster ════"
    if ! bash "$HERE/stagef_up_v2.sh"; then
        echo "[FAIL] V2 bring-up failed — nothing was run" >&2
        exit 1
    fi
fi

pass=0; fail=0; skip=0
failed_names=""
skipped_names=""

echo ""
echo "════ Phase 3 — V2 scenarios ════"
for t in $V2_TESTS; do
    script="$HERE/tests/$t"
    if [ ! -x "$script" ]; then
        echo "[FAIL] $t is missing or not executable" >&2
        fail=$(( fail + 1 )); failed_names="$failed_names $t"
        continue
    fi
    out=$(mktemp)
    bash "$script" > "$out" 2>&1
    rc=$?
    case "$rc" in
      0)  echo "  PASS  $t"; pass=$(( pass + 1 )) ;;
      99) echo "  SKIP  $t   (coverage did NOT happen)"
          skip=$(( skip + 1 )); skipped_names="$skipped_names $t"
          # A skip's reason is short and worth seeing without digging.
          grep -E '^\[SKIP\]' "$out" | sed 's/^/        /' ;;
      *)  echo "  FAIL  $t   (rc=$rc)"
          fail=$(( fail + 1 )); failed_names="$failed_names $t"
          echo "        --- begin full output ---"
          cat "$out"
          echo "        --- end full output ---" ;;
    esac
    rm -f "$out"
done

if [ "$SCENARIOS_ONLY" = 0 ]; then
    echo ""
    echo "════ Phase 4 — teardown ════"
    bash "$HERE/stagef_down.sh" >/dev/null 2>&1 || true
fi

echo ""
echo "════ V2 Genesis Protocol — result ════"
echo "  passed:  $pass"
echo "  skipped: $skip${skipped_names:+ —$skipped_names}"
echo "  failed:  $fail${failed_names:+ —$failed_names}"
if [ "$skip" -gt 0 ]; then
    echo ""
    echo "  ⚠ A SKIP IS NOT A PASS. The scenarios above declined to run and"
    echo "    their coverage is ABSENT from this result."
fi
[ "$fail" -eq 0 ] || exit 1
exit 0
