#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_p2p_seam_faults.sh — the reactor seam never hit a node-local fault
# ════════════════════════════════════════════════════════════════════
#
# REPLACES test_cmt_arena_runway.sh (P2P-PORT F6). That scenario grepped
# for the old Comet transport glue's receive-arena latches ("recv_arena at
# 50%/90%", nodus_witness_cmt_net.c) — the glue is DELETED with the 4004
# p2p port (docs/plans/2026-09-26-p2p-port-design.md §2 "replaces
# nodus_witness_cmt_net.c"), nothing emits those lines any more, and the
# grep passed vacuously. This one reads what the NEW seam really emits.
#
# WHAT IT PROVES
#   That across the WHOLE sweep, on every node, the 4004 host never handed
#   the consensus or mempool reactor a message that made it report a
#   NODE-LOCAL fault: no "conr receive: CMT_FAULT" and no "memr receive:
#   CMT_FAULT" line (nodus_witness_p2p.c cons_receive / mem_receive). The
#   property that would be false if it failed: *the seam that replaced the
#   deleted glue (cmt_conr_host_t / the mempool host rows) keeps the
#   reactors' own invariants*. CMT_FAULT from cmt_conr_receive /
#   cmt_memr_receive is the reference's panic class — a peer index the
#   host wired wrongly, a peer state that does not exist, a type the
#   reactor refuses (cmt_conr.h "NODE-LOCAL → CMT_FAULT") — never a
#   property of what a remote peer sent (that is CMT_REJECT, a WARN, which
#   this scenario does NOT count). R-P2P-53 made it log-and-continue
#   instead of halting, so this scan is the only thing that turns it into
#   a verdict.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary built from a tree
#   with the 4004 p2p port (P2P-PORT F5+).
#   Environment: none. Submits nothing itself.
#   ⚠ MUST run LAST (genesis_protocol_v2.sh's explicit order does this):
#   its subject is every earlier scenario's traffic — the kills, stops,
#   restarts and floods included. Run earlier, it reads a partial history.
#
# WHAT IT LEAVES BEHIND
#   Nothing. Read-only: greps every node's already-written nodus.log.
#
# HOW IT CAN LIE
#   - **A green scan on a build without the seam is vacuous.** Before
#     requiring the absence of the fault lines it requires every node's
#     log to carry the 4004 host's start line ("p2p on … persistent
#     peer(s)", nodus_witness_p2p.c) — a node that never started the new
#     host could never print a seam fault. A missing start line FAILS.
#   - **Which CMT_FAULTs a stopped / killed / re-added peer could reach
#     (read, shared/dnac/cmt_conr.c cmt_conr_receive; cmt_memr.c
#     cmt_memr_receive).** The one PEER-STATE fault — "Peer %d has no
#     state" (no slot, or not in_set) — is gated by the host: a message
#     from a peer the lane does not know (lane_find < 0) or before / after
#     its reactor membership (!conr_added / !memr_added) is DROPPED at
#     DEBUG in nodus_witness_p2p.c cons_receive / mem_receive, never
#     handed to the reactor. The rest are decode / allocation / invariant
#     faults (NULL arguments, arena, clock read, peer-state apply rows) —
#     node-local by construction. ONE is less clear-cut: memr's
#     CMT_FAULT from cmt_mem_check_tx is the app's CheckTx faulting (e.g.
#     a database error in the dry run) — still node-local, but a busy or
#     failing disk could produce it; a RED naming "memr receive" needs the
#     node log read before it is called a seam defect.
#   - **It proves absence of a FAULT LINE, not correct delivery.** A
#     message dropped before the reactor knew the peer (R-P2P-47, a DEBUG
#     line) or a REJECT from a misbehaving peer is not counted — the
#     sweep's 7/7 agreement checks are what cover delivery.
#   - **Not every restart keeps its log.** test_v2_restart_convergence.sh
#     appends to node 4's nodus.log, but test_v2_partial_wipe.sh (node 5)
#     and test_v2_join.sh (node 6) TRUNCATE theirs (their own headers and
#     README rows say so) — for those two nodes this scan covers only the
#     process lifetime since that scenario. Disclosed, not hidden.
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
stagef_sentinel SETUP_OK   # the runner turns PASS-without-ASSERT_RUN into FAIL

bad=0
stagef_sentinel ASSERT_RUN   # the terminal assertion (the fault scan) is next
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    log="$(stagef_node_dir "$n")/nodus.log"
    [ -f "$log" ] || { echo "[FAIL] node$n has no nodus.log" >&2; bad=1; continue; }
    # anti-vacuity: the seam this scenario is about must have existed
    if ! grep -q 'p2p on .* persistent peer(s)' "$log"; then
        echo "[FAIL] node$n: no 4004 p2p host start line — this binary has no seam to check (pre-F5?)" >&2
        bad=1
        continue
    fi
    fc=$(grep -c 'conr receive: CMT_FAULT' "$log" || true)
    fm=$(grep -c 'memr receive: CMT_FAULT' "$log" || true)
    if [ "${fc:-0}" != "0" ] || [ "${fm:-0}" != "0" ]; then
        echo "[FAIL] node$n: node-local reactor fault(s) at the seam (conr: $fc, memr: $fm)" >&2
        grep -E '(conr|memr) receive: CMT_FAULT' "$log" >&2
        bad=1
    else
        echo "[ok] node$n: 4004 host started; no conr/memr CMT_FAULT"
    fi
done
[ "$bad" = 0 ] || die "at least one node hit a node-local fault at the 4004 reactor seam, or never started it"

stagef_sentinel PASS
echo ""
echo "[PASS] no node's consensus or mempool reactor reported a node-local"
echo "       fault (CMT_FAULT) at the 4004 seam at any point across the sweep."
