#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# genesis_protocol_v2.sh — the Comet lane half of the Genesis Protocol
# ════════════════════════════════════════════════════════════════════
#
# R3 W3 package C2d (D-17 rev 10 item 9, D-23 rev 7/8, D-24 rev 4, all
# atlas APPROVED); R3 W4-D deletes what W3 only closed: THE LEGACY
# RUNNER (genesis_protocol.sh, which used to print a closure banner and
# exit 99 unconditionally) is gone from the tree, along with its 23
# legacy scenarios and stagef_up.sh. This is now the harness's ONLY live
# lane: nodus-server never starts the
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
#   test_cmt_claim_flood.sh (R3 W4 package C) and, right after it,
#   test_v2_epoch_boundary.sh run near the end because the FIRST of the
#   two SPENDS THE WHOLE PUMP BATCH in one call, and the second wants to
#   run AFTER that spend (whatever it opportunistically finds left,
#   ordinarily nothing — see its own header). Anything that needs a
#   transaction after either would find none. test_v2_epoch_boundary.sh
#   needs a short-epoch binary, and it SKIPS (99) rather than pretending
#   on a default build — so do test_cmt_rule_n_retire.sh and
#   test_v2_rewards.sh (the latter ALSO needs STAGEF_PAYOUT_INTERVAL_
#   EPOCHS=2 exported before bring-up); this sentence read "the only
#   scenario" until tokenomics-v3 P2 corrected it. (The CLI-SPEND pump
#   those three use claims node 3's own leaf, never the PUMP batch.)
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
#   own header and the README say the same). R3 W4 package C:
#   test_cmt_claim_flood.sh is now the ONLY scenario that reaches for the
#   PUMP batch — it submits the WHOLE thing in one call and proves a
#   single block can carry more than the retired 16-item cap
#   (NODUS_V2_APPLY_MAX_CLAIMS, 14 162, replaces the earlier ~2 972
#   estimate this file used to cite — see that scenario's own header for
#   the derivation). test_v2_epoch_boundary.sh's own pump submission is
#   opportunistic leftovers only, ordinarily nothing. None of the three
#   scenarios therefore compete for anything; they are placed in THIS
#   order (mempool_flood, claim_flood, epoch_boundary) because
#   test_cmt_mempool_flood.sh is quick and cheap, test_cmt_claim_flood.sh
#   is the one that must run before the pump batch is touched by
#   anything else, and test_v2_epoch_boundary.sh is the slow scenario
#   that should run last regardless of what it shares with the other two.
#   A second full run against the SAME cluster fails on the leaf-spending
#   scenarios, correctly — the default mode brings the cluster up fresh
#   for exactly that reason.
#
# ── R3 W3/W4 — CLAIMS DO NOT BATCH ONE-PER-BLOCK ANY MORE ───────────
#   The pre-Comet lane's "N claims submitted -> N blocks" (measured:
#   40 leaves -> 40 blocks) does NOT hold under cometbft. `dnac_spend`
#   answers CheckTx immediately (D-23 rev 7 item 22,
#   nodus_witness_handlers.c:2047-2063) — it no longer blocks the client
#   until a block commits — so a tight loop of submissions (what
#   `v2-claim` over a leaf batch does) lands many transactions in the
#   mempool before the NEXT PrepareProposal fires, and PrepareProposal
#   fills one block up to its claim bound before starting another. R3 W3
#   (C2a-19) temporarily flattened that bound to 16 items REGARDLESS OF
#   CLASS (the fix for a live defect where a 40-claim decided block
#   FAULTED every node's FinalizeBlock); R3 W4 package C replaced the
#   flat cap with a per-class one, so claims are bounded again by
#   cometbft's own block-byte ceiling (`NODUS_V2_APPLY_MAX_CLAIMS`,
#   14 162, nodus_witness_v2_apply.h) rather than by a flat item count.
#   A batch of 40 pump claims should therefore be expected to land in ONE
#   block, not forty — test_cmt_claim_flood.sh proves exactly that.
#   Reaching a height target by idle production alone is bounded by the
#   CreateEmptyBlocksInterval cadence (60 000 ms) — see test_v2_epoch_
#   boundary.sh's own header for the wait this implies once the pump
#   batch is (ordinarily) already spent.
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
#   test_cmt_chain_config.sh (D-16 rev 7, W4-CC) — needs no leaf either
#     (a governance proposal, not a spend); SKIPS (99) unless the short
#     grace convention (STAGEF_CC_GRACE_SAFETY=15, matching a
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 build) was exported
#     before bring-up.
#   test_cmt_mempool_flood.sh — DELTA 1 correction (verifier CLAIM 5):
#     spends node 4/5/6/7's OWN genesis leaves, NOT the PUMP batch — it
#     does not compete with test_cmt_claim_flood.sh or test_v2_epoch_
#     boundary.sh for anything. Placed here because it is quick and
#     cheap; the slow, leaf-spending scenarios belong near the end
#     regardless of what they share with.
#   test_cmt_claim_flood.sh (R3 W4 package C) — the ONLY scenario that
#     spends the PUMP batch: one v2-claim call over the WHOLE thing,
#     proving a single block can carry more claims than the retired
#     16-item cap. MUST run before test_v2_epoch_boundary.sh, whose own
#     header describes what it finds left (ordinarily nothing).
#   test_cmt_env_flood.sh (R3 W4-C delta 2) — INTENDED to prove a block
#     beyond 10 ENVELOPES (not claims) applies with 7/7 agreement;
#     currently a SKIP (99) — nodus-cli has no generic CORE spend/
#     transfer envelope command to drive it (see the script's own
#     header). Placed here, after claim_flood and before epoch_boundary,
#     because it does not touch the pump batch at all while skipping
#     (nothing to leave behind either way).
#   test_v2_epoch_boundary.sh — opportunistically submits whatever
#     remains of the PUMP batch (ordinarily nothing, since the scenario
#     above already spent it) to help reach the boundary; SKIPS (99) at
#     the shipped epoch length.
#   test_v2_rewards.sh (tokenomics-v3 P2) — drives the chain through
#     paying boundaries up to a payday with the CLI-SPEND pump; SKIPS
#     (99) unless the bring-up ran with a short epoch AND
#     STAGEF_PAYOUT_INTERVAL_EPOCHS=2 exported (the interval is part of
#     the genesis document). MUST run BEFORE test_cmt_rule_n_retire.sh:
#     it asserts all SEVEN committee validators are paid, and that
#     scenario permanently retires node 7.
#   test_cmt_rule_n_retire.sh (round 2, tokenomics-v3 P1 §A/D-3/D-11) —
#     SKIPS (99) at the shipped epoch length (needs THREE boundaries'
#     worth of idle-only wall time, its own header explains why three,
#     not two). Placed AFTER every leaf-spending and epoch-boundary
#     scenario and BEFORE arena_runway: it PERMANENTLY AUTO_RETIREs node
#     7 (its own "WHAT IT LEAVES BEHIND" — not reversible within this
#     bring-up), so nothing after it may assume 7 ACTIVE validators.
#     arena_runway only READS accumulated counters, unaffected by which
#     validators are still ACTIVE.
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
test_cmt_chain_config.sh
test_cmt_mempool_flood.sh
test_cmt_claim_flood.sh
test_cmt_env_flood.sh
test_v2_epoch_boundary.sh
test_v2_rewards.sh
test_cmt_rule_n_retire.sh
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
    # R3 W4 package H — the reachability sentinels are BACK on this lane.
    # Every scenario in V2_TESTS records SETUP_OK once its preconditions
    # hold, ASSERT_RUN immediately before its terminal assertion and PASS
    # at its end (stagef_env.sh `stagef_sentinel`, marks under
    # $BASE_DIR/sentinels). A scenario that exits 0 WITHOUT having reached
    # its terminal assertion — an early `return`, a skipped branch, a
    # helper that silently succeeded on nothing — is not coverage, and the
    # deleted legacy runner turned exactly that into a FAILURE. So does
    # this one, in both shapes: rc 0 with SETUP_OK but no ASSERT_RUN is a
    # VACUOUS pass; rc 0 with no marks at all is an UNINSTRUMENTED
    # scenario (a new script must carry the three marks before it counts).
    sname="${t%.sh}"
    if [ "$rc" -eq 0 ] && ! stagef_sentinel_has "$sname" ASSERT_RUN; then
        if stagef_sentinel_has "$sname" SETUP_OK; then
            echo "  FAIL  $t   (rc=0 but ASSERT_RUN was never recorded — a VACUOUS pass; marks: $(stagef_sentinel_summary "$sname"))"
        else
            echo "  FAIL  $t   (rc=0 but no reachability mark at all — UNINSTRUMENTED; add stagef_sentinel SETUP_OK/ASSERT_RUN/PASS)"
        fi
        fail=$(( fail + 1 )); failed_names="$failed_names $t"
        echo "        --- begin full output ---"
        cat "$out"
        echo "        --- end full output ---"
        rm -f "$out"
        continue
    fi
    case "$rc" in
      0)  echo "  PASS  $t   [$(stagef_sentinel_summary "$sname")]"; pass=$(( pass + 1 ))
          # R3 W4-C (ORCHESTRATOR, ORC-6): a PASSING scenario's output was
          # discarded, which threw away the MEASUREMENTS the claim-flood
          # scenario exists to print (CLI wall-clock, claims per carrying
          # block, harness-observed block gaps). Keep every `[info]` line
          # and the indented measurement rows that follow one; nothing
          # else of a green run is echoed. A run that asserts on none of
          # these numbers still has to SHOW them, or the measurement never
          # happened as far as the reader can tell.
          grep -E '^\[info\]|^ {8,}(height [0-9]+ observed_at|[0-9]+:[0-9]+$)|wall-clock' "$out" \
              | sed 's/^/        /' ;;
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
