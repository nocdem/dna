#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_arena_runway.sh — the receive arena never approached its wall
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That across the WHOLE sweep — every scenario that ran before this
#   one, on every node — the Comet transport glue's fixed receive-arena
#   runway (64 MiB, `NODUS_CMT_NET_RECV_ARENA_BYTES`,
#   nodus_witness_cmt_net.h) never got anywhere near full. The property
#   that would be false if it failed: *this build's per-tick arena reset
#   policy keeps the runway's steady-state usage far below its ceiling
#   under ordinary harness traffic* — delta 2, register row R3-A-5, is a
#   KNOWN, ACCEPTED design point (a fixed arena, not a growable one; the
#   full policy question is deferred to R3-C2), and this scenario is
#   this package's only measurement of whether that fixed size holds up
#   in practice, even at harness scale.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none. Submits nothing itself.
#   ⚠ MUST run LAST (genesis_protocol_v2.sh's explicit order does this):
#   its subject is the CUMULATIVE usage every earlier scenario in the
#   sweep has already produced. Running it earlier reads a partial
#   history and understates whatever the full sweep would have shown.
#
# WHAT IT LEAVES BEHIND
#   Nothing. Read-only: greps every node's already-written nodus.log.
#
# HOW IT CAN LIE
#   - **There is no per-block (or any periodic) USAGE NUMBER to read.**
#     `nodus_cmt_net_recv_arena_used()` (nodus_witness_cmt_net.c:799-802)
#     exists and returns the live byte count, but it has NO CALLER
#     anywhere in nodus/src or nodus/tools — confirmed by search. Nothing
#     in this build ever logs it, at any cadence. So this scenario
#     cannot report "peak usage was N% of the runway" the way its own
#     name might suggest; it can only report whether either LATCH
#     (nodus_witness_cmt_net.c:770-789) fired. This is a real gap in
#     what this build can be asked, not a gap in this script — recorded
#     here rather than inventing a number nothing prints.
#   - **A latch is a ONE-SHOT, PER-PROCESS-LIFETIME flag.** Once fired it
#     never fires again for the SAME lifetime of that node
#     (`recv_arena_warned_50`/`_90`, set once, never cleared), so this
#     scenario would miss a SECOND approach to the wall on a node that
#     already crossed 50% once earlier and drained back down — the log
#     line would not repeat. Reported as a known limitation: this
#     scenario proves "the wall was never approached", not "the wall
#     was approached at most once".
#   - **A node restarted DURING the sweep resets its latches.** node4
#     (test_v2_restart_convergence.sh), node5 (test_v2_partial_wipe.sh)
#     and node6 (test_v2_join.sh) all restart earlier in the order this
#     package places them; each restart is a FRESH process with fresh
#     `recv_arena_warned_50/_90` flags, so this scenario's history for
#     those three nodes is not the WHOLE sweep's — only what happened
#     since their last restart. Disclosed, not hidden: their nodus.log
#     files are APPENDED across restarts (never truncated by this
#     package's scenarios), so the grep below still covers every
#     process lifetime that node had, just not as one continuous latch
#     state.
#   - **A latch firing does not by itself prove data was lost.** The 50%
#     line is a WARN (headroom remains); only the 90% line is an ERROR
#     ("close to refusing every part-carrying message"). Both are
#     reported as failures here, on the theory that seeing either at
#     harness scale is worth investigating before it ships, not that
#     the 50% line alone is catastrophic.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster — use stagef_up_v2.sh"
    exit 99
fi
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

# DELTA 1 (verifier CLAIM 17, REFUTED as originally worded) — "no
# caller" over-claimed: nodus_cmt_net_recv_arena_used() DOES have callers
# — seven sites across this build's own test binaries (nodus/tests/
# test_cmt_net.c:824,871 and test_cmt_live.c:763,873,1015,1055,1187).
# What is true, and load-bearing here, is narrower: no caller exists in
# nodus/src or nodus/tools — nothing in the SERVER prints a usage number
# at any cadence, in production or under this harness. This scenario
# still asserts only the two one-shot latches, for exactly that reason.
echo "[info] no per-block recv_arena usage is logged by nodus-server —"
echo "       nodus_cmt_net_recv_arena_used() has no caller in nodus/src or"
echo "       nodus/tools (it is called from this build's own test binaries"
echo "       only). Asserting the two one-shot latches only (50% WARN, 90% ERROR)."

bad=0
stagef_sentinel ASSERT_RUN   # the terminal assertion (the latch scan) is next
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    log="$(stagef_node_dir "$n")/nodus.log"
    [ -f "$log" ] || { echo "[FAIL] node$n has no nodus.log" >&2; bad=1; continue; }
    w50=$(grep -c 'recv_arena at 50%' "$log" || true)
    w90=$(grep -c 'recv_arena at 90%' "$log" || true)
    if [ "${w50:-0}" != "0" ] || [ "${w90:-0}" != "0" ]; then
        echo "[FAIL] node$n: recv_arena latch fired (50%%: $w50, 90%%: $w90)" >&2
        grep -E 'recv_arena at (50|90)%' "$log" >&2
        bad=1
    else
        echo "[ok] node$n: neither recv_arena latch fired"
    fi
done
[ "$bad" = 0 ] || die "at least one node's receive-arena latch fired during this sweep"

stagef_sentinel PASS
echo ""
echo "[PASS] no node's Comet receive-arena runway latch (50% or 90% of"
echo "       its 64 MiB fixed size) fired at any point across the sweep."
