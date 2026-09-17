#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_epoch_boundary.sh — a V2 chain crosses an epoch boundary
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a Ledger V2 fleet driven ACROSS an epoch boundary freezes the
#   next epoch's validator-set snapshot identically on every node, and
#   still agrees on state_root afterwards. The property that would be
#   false if it failed: *the V2 epoch machinery is deterministic across
#   nodes* — the boundary is where a chain writes state nobody asked it
#   to write, from a rule rather than from a transaction, and it is the
#   classic place for two nodes to disagree.
#
#   DELTA 1 (verifier CLAIM 16, REFUTED as this scenario originally read
#   it) — crossing height H = k*E_LEN writes the snapshot for
#   `epoch_start = H + E_LEN`, not for `epoch_start = H`
#   (nodus_witness_vset.c:658-659). The cross-node comparison below reads
#   `epoch_start = next_boundary + E_LEN`, the row THIS crossing actually
#   produced — comparing at `next_boundary` itself would have compared a
#   row genesis already seeded identically on every node, which can never
#   differ and would have proved nothing about the crossing this scenario
#   exists to exercise.
#
# WHAT IT REQUIRES
#   ⚠ **A SHORT-EPOCH BINARY. Both halves, or it skips.**
#     compile: -DDNAC_EPOCH_LENGTH=<E> with E small (15 is the harness
#              convention)
#     env:     STAGEF_EPOCH_LENGTH=<E> matching it, exported BEFORE
#              stagef_up_v2.sh — the bring-up writes E into the genesis
#              config, and the builder REFUSES a config that disagrees
#              with the binary.
#   At the shipped 720 this scenario skips — see R3 W3 below for why the
#   reachability test is no longer a leaf count.
#   A cluster from stagef_up_v2.sh. Pump leaves help but are no longer
#   required to reach the boundary at all (see below).
#
# R3 W3 (C2d) — WHERE THE BLOCKS COME FROM CHANGED COMPLETELY
#   The pre-Comet measurement this scenario was built on — "40 leaves ->
#   40 blocks, height 0 -> 40" — does NOT hold under cometbft, and
#   reproducing it would be reporting a fact that stopped being true.
#   `dnac_spend` answers CheckTx immediately now (D-23 rev 7 item 22),
#   so a `v2-claim` call over the whole pump batch queues every leaf in
#   the mempool before the client's own loop finishes submitting them,
#   and the NEXT PrepareProposal drains as many as fit under its claim
#   bound (~2 972, D-23 rev 8 item 24) into ONE block — 40 pump leaves
#   should be expected to land in ONE block, not forty (see
#   test_cmt_mempool_flood.sh, which proves this batching directly).
#   Reaching a height target is therefore bounded by TIME
#   (CreateEmptyBlocksInterval, 60 000 ms of idle production per block,
#   nodus_witness_cmt_node.c:1700), not by how many leaves exist. The
#   pump batch still helps — it can turn what would otherwise be several
#   idle intervals into one quick block — but it can no longer be relied
#   on to multiply blocks 1:1, so the SKIP threshold below is expressed
#   in WALL-CLOCK FEASIBILITY (blocks needed x the interval, against a
#   fixed harness patience budget), not in leaves-on-hand. At E=15 that
#   budget check passes exactly as the old leaf-count check did (both
#   converge on "15 is fine, 720 is not"); the reasoning underneath
#   is now honest about why.
#
# WHAT IT LEAVES BEHIND
#   Whatever remains of the PUMP identity's leaves gets submitted once,
#   opportunistically — spent if it lands, unclaimed if the earlier
#   test_cmt_mempool_flood.sh already used them (that scenario
#   deliberately does NOT touch the pump batch, so ordinarily there is
#   still a full batch here; if run standalone after something else that
#   drained it, this scenario still reaches the boundary on idle
#   production alone, just more slowly). The chain is at least E blocks
#   further on, past at least one epoch boundary. Nothing is killed or
#   restarted. This is the last leaf-spending scenario in the sweep —
#   genesis_protocol_v2.sh's explicit order places it after
#   test_cmt_mempool_flood.sh for exactly that reason.
#
# HOW IT CAN LIE
#   - **Advancing is not crossing.** A height delta proves the chain
#     moved; it says nothing about a boundary. The assertion is that the
#     height crossed a multiple of E, computed from the before/after
#     heights, and that a snapshot row for the NEW epoch appeared.
#   - **A snapshot that was already there proves nothing.** The bring-up
#     seeds epochs 0 and E at genesis, so the row for the FIRST boundary
#     exists before this scenario runs. The assertion is on a row that
#     was ABSENT before and PRESENT after, and the before-set is captured
#     first.
#   - **Identical-across-nodes is the point, not existence.** One node
#     writing a snapshot proves nothing about agreement; the row's hash
#     is compared across all seven.
#   - **NEVER parse `committed:` on this lane.** The pump submission's
#     own exit code is CheckTx admission, not inclusion; the boundary
#     crossing is read from the chain, not the CLI's stdout.
#   - **This is now one of the SLOWEST scenarios in the sweep.** At
#     E=15 the pump batch can shorten the wait, but the worst case (an
#     empty or already-spent pump batch) is bounded purely by
#     CreateEmptyBlocksInterval — up to `need * 60s` wall-clock. Budget
#     minutes, not seconds, for this scenario even at the short-epoch
#     harness convention.
#   - **rc=99 means the boundary was out of the harness's wall-clock
#     patience**, i.e. the coverage did not happen. Never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
CONF="$BASE_DIR/v2_genesis.conf"
PUMP="$BASE_DIR/v2pump/identity"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
E_LEN="${STAGEF_EPOCH_LENGTH:-720}"

die() { echo "[FAIL] $*" >&2; exit 1; }
tip() { sqlite3 "$(stagef_node_chain_db "$REF")" \
        "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;"; }
snapshots() { sqlite3 "$(stagef_node_chain_db "$1")" \
        "SELECT group_concat(epoch_start,',') FROM \
         (SELECT epoch_start FROM validator_set_snapshots ORDER BY epoch_start);"; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ] || [ ! -s "$PUMP/nodus.pk" ]; then
    echo "[SKIP] not a Ledger V2 cluster with a pump identity — use stagef_up_v2.sh"
    exit 99
fi

# R3 W3 (C2d) — REACHABILITY IS NOW A WALL-CLOCK BUDGET, NOT A LEAF
# COUNT. See this script's header: submitted claims no longer land one
# per block, so counting leaves cannot say whether the boundary is
# reachable. The worst case is purely idle production — every one of
# the $need blocks takes a full CreateEmptyBlocksInterval — and this
# harness's patience for that worst case is bounded, exactly the way
# the old check was bounded by leaves on hand: same two conventional
# values (15 -> proceeds, 720 -> skips), honest reasoning underneath.
STAGEF_EPOCH_BOUNDARY_BUDGET_S="${STAGEF_EPOCH_BOUNDARY_BUDGET_S:-1800}"
head0=$(tip)
next_boundary=$(( (head0 / E_LEN + 1) * E_LEN ))
need=$(( next_boundary - head0 ))
worst_case_s=$(( need * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))
if [ "$worst_case_s" -gt "$STAGEF_EPOCH_BOUNDARY_BUDGET_S" ]; then
    echo "[SKIP] the next boundary is $need blocks away (epoch length $E_LEN);"
    echo "       the worst-case idle-only wait is ${worst_case_s}s, over this"
    echo "       harness's ${STAGEF_EPOCH_BOUNDARY_BUDGET_S}s patience budget —"
    echo "       needs a SHORT-EPOCH build: -DDNAC_EPOCH_LENGTH=15 + STAGEF_EPOCH_LENGTH=15"
    exit 99
fi
echo "[ok] epoch length $E_LEN, head $head0, next boundary at $next_boundary ($need blocks, worst case ${worst_case_s}s)"

before_set=$(snapshots "$REF")
echo "[ok] snapshots before: $before_set"

stagef_cmt_diff_at_floor "pre-v2-epoch" || exit 2

# ── Drive the chain across, opportunistically ───────────────────────
# Best-effort: whatever the PUMP identity still holds is submitted in
# one call (it may be everything, if test_cmt_mempool_flood.sh has not
# run or did not touch it; it may be nothing, if it is already fully
# spent — v2-claim SKIPS already-claimed leaves rather than failing).
# Either way this is not the reachability assertion: the wait below is
# bounded by the wall-clock budget already checked above, not by
# whether this submission produced anything.
log="$BASE_DIR/v2epoch_pump.log"
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" v2-claim --config "$CONF" \
    --db "$ref_db" --keys "$PUMP" \
    --submit "127.0.0.1:$(stagef_tcp_port "$REF")" > "$log" 2>&1 || true
echo "[ok] pump batch submission attempted (best-effort; see $log)"

# A STALL here means literally zero progress for 4 consecutive
# intervals — a real failure signal regardless of how many intervals
# $need itself implies, since idle production alone should tick every
# single interval. The wall-clock feasibility question was already
# answered above; this bound is for detecting a genuine halt quickly,
# not for capping how long a HEALTHY wait may legitimately take.
head1=$(stagef_cmt_wait_height "$ref_db" "$next_boundary" 4) \
    || die "height stalled at $head1 for 4 consecutive intervals, short of the boundary at $next_boundary"
echo "[ok] the chain CROSSED the boundary: $head0 -> $head1 (boundary $next_boundary)"

# ── A snapshot for a NEW epoch must have appeared ────────────────────
after_set=$(snapshots "$REF")
[ "$after_set" != "$before_set" ] || die \
  "the snapshot set is unchanged ($after_set) — the chain crossed a boundary and froze nothing, which is the defect this scenario exists to catch"
echo "[ok] snapshots after: $after_set"

# ── And every node must have frozen the SAME one ────────────────────
# DELTA 1 (verifier CLAIM 16, REFUTED as originally described) — crossing
# height H = k*E_LEN writes the snapshot for epoch_start = H + E_LEN, NOT
# for epoch_start = H itself (nodus_witness_vset.c:658-659,
# `next_start = boundary_height + DNAC_EPOCH_LENGTH`, bound as the row's
# `epoch_start`). Genesis seeds epoch_start 0 and E_LEN; crossing the
# FIRST boundary ($next_boundary = E_LEN) therefore produces the row at
# epoch_start = 2*E_LEN, not at $next_boundary. Comparing at
# $next_boundary was comparing a row genesis already seeded on every
# node, which can never differ and proves nothing about THIS crossing.
frozen_epoch_start=$(( next_boundary + E_LEN ))

# Every follower must reach $next_boundary FIRST — reading its snapshot
# row before it exists there is "no row yet" (lag), never divergence.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$next_boundary" 3 >/dev/null \
        || die "node$n never reached height $next_boundary (mesh replication stalled)"
done
first=""; rows=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    h=$(sqlite3 "$(stagef_node_chain_db "$n")" \
        "SELECT COUNT(*) || ':' || COALESCE(hex(snapshot_hash),'-') \
         FROM validator_set_snapshots WHERE epoch_start = $frozen_epoch_start;" 2>/dev/null || echo ERR)
    rows="$rows node$n=$h"
    if [ -z "$first" ]; then first="$h"
    elif [ "$h" != "$first" ]; then
        echo "[FAIL] the epoch-$frozen_epoch_start snapshot DIFFERS across nodes:$rows" >&2
        exit 1
    fi
done
case "$first" in 0:*|ERR) die "no epoch-$frozen_epoch_start snapshot row on any node";; esac
echo "[ok] the epoch-$frozen_epoch_start snapshot is byte-identical on all $STAGEF_COMMITTEE_SIZE nodes"

stagef_cmt_diff_at_floor "post-v2-epoch" || exit 2

echo ""
echo "[PASS] a Ledger V2 chain crossed the epoch boundary at $next_boundary, froze the"
echo "       next validator-set snapshot (epoch_start=$frozen_epoch_start) byte-identically"
echo "       on all $STAGEF_COMMITTEE_SIZE nodes, and every"
echo "       node still agrees on state_root. Epoch length $E_LEN — NOT the shipped 720,"
echo "       so this proves the LOGIC of the boundary and nothing about its magnitude."
