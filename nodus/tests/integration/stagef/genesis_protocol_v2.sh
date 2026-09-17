#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# genesis_protocol_v2.sh — the Comet lane half of the Genesis Protocol
# ════════════════════════════════════════════════════════════════════
#
# R3 W3 package C2d (D-17 rev 10 item 9, D-23 rev 7/8, D-24 rev 4, all
# atlas APPROVED): THE LEGACY RUNNER (genesis_protocol.sh) IS CLOSED —
# it prints the closure banner and exits 99, unconditionally. This is
# now the harness's ONLY live lane: nodus-server never starts the
# legacy BFT or the pre-Comet V2 lane on any chain any more (the
# witness's post-open gate refuses a database that is not a version-3
# chain, fail closed). "The V2 lane" in the scenario names below means
# what it always meant — the Ledger V2 domain/state model — but the
# CONSENSUS underneath it is now cometbft @709fd12b, literally ported,
# not the legacy PBFT. Historical framing kept below for the sections
# that are still accurate about it (no genesis transaction, no
# consensus round at bring-up); the three rules that flipped are
# called out in README.md's Comet-lane section, not repeated here.
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
# ── ORDER, AND WHY IT IS NOT ALPHABETICAL ANY MORE (R3 W3 C2d) ──────
#   The scenarios are still order-independent of EACH OTHER'S leaves BY
#   CONSTRUCTION: stagef_up_v2.sh gives every node, plus the non-validator
#   user, its own genesis allocation, so no two compete for the same
#   single-use leaf. That is the property the legacy suite most
#   conspicuously lacks — see the residue list in README.md. But the
#   Comet lane adds a TIME-ORDER constraint the pre-Comet lane never had:
#   test_cmt_empty_blocks.sh must observe an interval with no transaction
#   in flight, which only the FIRST scenario in a sweep can guarantee, so
#   the list above is an explicit ORDER, not an alphabetical accident.
#
#   TWO EXCEPTIONS, stated rather than discovered:
#   test_v2_epoch_boundary.sh runs near the end because it SPENDS THE
#   REMAINING PUMP LEAVES to help drive the chain across a boundary.
#   Anything that needs a transaction after it would find none. It is
#   also the only scenario that needs a short-epoch binary, and it SKIPS
#   (99) rather than pretending on a default build.
#   test_cmt_arena_runway.sh runs absolute LAST because its subject is
#   the CUMULATIVE receive-arena usage every other node in this sweep
#   has already produced — reading it any earlier would read a partial
#   history.
#
# ── LEAF BUDGET ─────────────────────────────────────────────────────
#   A genesis leaf can be claimed exactly ONCE. The bring-up mints one per
#   node, one for the non-validator user, and a batch of small PUMP leaves
#   (STAGEF_V2_PUMP_LEAVES, default 40) for driving the chain to a height.
#   DELTA 1 correction (verifier CLAIM 5): test_cmt_mempool_flood.sh does
#   NOT touch the PUMP batch — it spends node 4's, node 5's, node 6's and
#   node 7's own genesis leaves (test_cmt_mempool_flood.sh:89,112 — its
#   own header and the README say the same). test_v2_epoch_boundary.sh is
#   the ONLY scenario that reaches
#   for the PUMP batch. The two scenarios therefore do not compete for
#   anything; they are placed in this order because
#   test_cmt_mempool_flood.sh is a quick, cheap scenario and
#   test_v2_epoch_boundary.sh is the slow, leaf-spending one that should
#   run near the end regardless. A second full run against the SAME
#   cluster fails on the leaf-spending scenarios, correctly — the default
#   mode brings the cluster up fresh for exactly that reason.
#
# ── R3 W3 (C2d) — CLAIMS DO NOT BATCH ONE-PER-BLOCK ANY MORE ────────
#   The pre-Comet lane's "N claims submitted -> N blocks" (measured:
#   40 leaves -> 40 blocks) does NOT hold under cometbft. `dnac_spend`
#   answers CheckTx immediately (D-23 rev 7 item 22,
#   nodus_witness_handlers.c:2047-2063) — it no longer blocks the client
#   until a block commits — so a tight loop of submissions (what
#   `v2-claim` over a leaf batch does) lands many transactions in the
#   mempool before the NEXT PrepareProposal fires, and PrepareProposal
#   fills one block up to its claim bound (~2 972 claims,
#   D-23 rev 8 item 24) before starting another. A batch of 40 pump
#   claims should therefore be expected to land in ONE block (or a small
#   handful), not forty. Reaching a height target is now bounded by the
#   CreateEmptyBlocksInterval cadence (60 000 ms, idle production),
#   not by leaf count — see test_v2_epoch_boundary.sh's own header for
#   the wait this implies.
#
# Usage:
#   bash genesis_protocol_v2.sh              # bring up + run + tear down
#   bash genesis_protocol_v2.sh --scenarios  # run only; cluster must be up
#
# ════════════════════════════════════════════════════════════════════
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$HERE/stagef_env.sh"

SCENARIOS_ONLY=0
[ "${1:-}" = "--scenarios" ] && SCENARIOS_ONLY=1

# R3 W3 (C2d) — ORDER IS EXPLICIT AND NO LONGER ALPHABETICAL.
#
#   test_cmt_empty_blocks.sh   FIRST: it must observe an interval with NO
#     transaction of ITS OWN or anyone else's in flight, which is only
#     guaranteed right after bring-up, before any scenario below has
#     touched the mempool.
#   test_v2_claim.sh / test_v2_join.sh / test_v2_partial_wipe.sh /
#   test_v2_restart_convergence.sh / test_v2_stake.sh — order-independent
#     of each other and of the two above/below, exactly as before: each
#     spends only its own genesis leaf (claim, stake) or none at all
#     (join, partial_wipe, restart_convergence).
#   test_cmt_dead_proposer.sh — needs no leaf (CreateEmptyBlocks means
#     demand is not required to observe a rotation); still placed after
#     the leaf-spending scenarios so a stalled proposer never blocks
#     something else's claim from committing.
#   test_cmt_mempool_flood.sh — DELTA 1 correction (verifier CLAIM 5):
#     spends node 4/5/6/7's OWN genesis leaves, NOT the PUMP batch — it
#     does not compete with test_v2_epoch_boundary.sh for anything.
#     Placed here because it is quick and cheap; the slow, leaf-spending
#     scenario belongs near the end regardless of what it shares with.
#   test_v2_epoch_boundary.sh — the ONLY scenario that spends the PUMP
#     batch, to help reach the boundary; SKIPS (99) at the shipped epoch
#     length.
#   test_cmt_arena_runway.sh   LAST, unconditionally: it reads the
#     receive-arena usage every OTHER node has accumulated across the
#     whole sweep and asserts no latch fired ACROSS ALL OF IT.
V2_TESTS="
test_cmt_empty_blocks.sh
test_v2_claim.sh
test_v2_join.sh
test_v2_partial_wipe.sh
test_v2_restart_convergence.sh
test_v2_stake.sh
test_cmt_dead_proposer.sh
test_cmt_mempool_flood.sh
test_v2_epoch_boundary.sh
test_cmt_arena_runway.sh
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

# DELTA 1 item 2 — a failed run's evidence must survive Phase 4.
#
# `stagef_down.sh` does TWO things in one step, unconditionally
# (read, verbatim, `stagef_down.sh:18-39`): it kills every pid in
# `pids.txt` (graceful, then -9 after a 2s grace) AND `rm -rf`s the
# whole `$BASE_DIR` (guarded only to paths under `/tmp/stagef-*`). It
# takes no flag to do only the first half. `stagef_down.sh` is not in
# this package's whitelist, so rather than add one there, a FAILED run
# replicates ONLY the kill half here, inline, and deliberately skips the
# `rm -rf` — every node's `nodus.log`, every witness DB, the genesis
# config and the pin file all survive at `$BASE_DIR` for inspection. A
# fully GREEN run tears down exactly as before.
BASE_DIR="$(cat "$STAGEF_POINTER" 2>/dev/null || true)"
if [ "$SCENARIOS_ONLY" = 0 ]; then
    echo ""
    if [ "$fail" -eq 0 ]; then
        echo "════ Phase 4 — teardown (all green) ════"
        bash "$HERE/stagef_down.sh" >/dev/null 2>&1 || true
    else
        echo "════ Phase 4 — stop processes, KEEP evidence (a scenario FAILED) ════"
        if [ -n "$BASE_DIR" ] && [ -f "$BASE_DIR/pids.txt" ]; then
            while read -r pid; do
                [ -z "$pid" ] && continue
                kill "$pid" 2>/dev/null || true
            done < "$BASE_DIR/pids.txt"
            sleep 2
            while read -r pid; do
                [ -z "$pid" ] && continue
                kill -9 "$pid" 2>/dev/null || true
            done < "$BASE_DIR/pids.txt"
            echo "  processes stopped"
        fi
        rm -f "$STAGEF_POINTER"
        echo "  logs kept at ${BASE_DIR:-<unknown BASE_DIR>} — teardown skipped because $fail scenario(s) failed"
    fi
fi

echo ""
echo "════ V2 Genesis Protocol — result ════"
echo "  passed:  $pass"
echo "  skipped: $skip${skipped_names:+ —$skipped_names}"
echo "  failed:  $fail${failed_names:+ —$failed_names}"
if [ "$fail" -gt 0 ] && [ "$SCENARIOS_ONLY" = 0 ]; then
    echo "  logs kept at: ${BASE_DIR:-<unknown BASE_DIR>}"
fi
if [ "$skip" -gt 0 ]; then
    echo ""
    echo "  ⚠ A SKIP IS NOT A PASS. The scenarios above declined to run and"
    echo "    their coverage is ABSENT from this result."
fi
[ "$fail" -eq 0 ] || exit 1
exit 0
