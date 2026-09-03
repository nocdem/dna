#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_view_change.sh — the epoch leader is paused, on the V2 lane
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a Ledger V2 fleet whose DERIVED epoch leader stops responding
#   rotates the view past it, commits work without it, and re-converges
#   when it comes back. The property that would be false if it failed:
#   *V2 inherits the shared BFT liveness machinery intact* — a chain can
#   make progress while its designated leader is unresponsive.
#
#   The legacy twin, test_view_change_fork.sh, proves the same property
#   on the legacy lane. Running BOTH is the point: the consensus code is
#   one implementation, but it is threaded with `v2_successor` branches,
#   and a legacy cluster never takes them. Today's v0.19.37 startup
#   defect lived in exactly such a branch, inside a file the season had
#   been editing, and no legacy run could see it. This is the scenario
#   that would.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: STAGEF_EPOCH_LENGTH must match the binary's
#   DNAC_EPOCH_LENGTH — the leader rank is derived from the epoch
#   ordinal. At the defaults (both 720) that is automatic.
#   ⚠ A cluster from **stagef_up_v2.sh**, and at least one UNCLAIMED
#   genesis leaf, because demand is what arms the deadman (below).
#
# WHAT IT LEAVES BEHIND
#   One committee node SIGSTOPped and then SIGCONTed — a DIFFERENT one on
#   every run, so it is printed. It keeps its pid. An EXIT trap resumes
#   it on every early exit, or a failed run would leave the fleet a node
#   short for everything after it. The cluster is left at a HIGHER view,
#   and one genesis leaf is spent.
#
# HOW IT CAN LIE
#   - **A dead leader on an IDLE chain rotates nothing, by design.** The
#     deadman that starts a round when the leader is silent is gated on
#     pending work; an idle node arms no timeout. On a V2 chain there is
#     no idle block production at all, so "no rotation in N seconds"
#     measured before any demand exists is the PREDICTED behaviour and
#     evidence of nothing. Demand is created deliberately, and the
#     assertion is taken after it.
#   - **Stale log lines.** Every line this looks for may already exist —
#     other V2 scenarios run first in an alphabetical sweep. Every count
#     is a BEFORE/AFTER delta; only an INCREASE is evidence. A `grep -q`
#     here would be vacuously true.
#   - **A pass means the REAL leader was paused.** That rests entirely on
#     the derivation and on the pubkey cross-check that maps it to a
#     node. Remove the cross-check and a wrong read would pause an
#     innocent follower, the real leader would keep producing, and the
#     scenario would fail — loudly, not silently, which is the right
#     direction for that particular mistake.
#   - **The claim is submitted to a node that is NOT the victim.** A
#     SIGSTOPped process still holds its listening socket, so a client
#     connecting to it completes the TCP handshake and then times out at
#     the HELLO — demand would never reach the cluster and the failure
#     would look like a consensus fault.
#   - **rc=99 means the cluster was not V2, or had no unclaimed leaf.**
#     Coverage that did not happen.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF_NODE=1
CONF="$BASE_DIR/v2_genesis.conf"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
E_LEN="${STAGEF_EPOCH_LENGTH:-720}"

VICTIM=""
resume() { [ -n "$VICTIM" ] && kill -CONT "$VPID" 2>/dev/null || true; }
trap resume EXIT

die() { echo "[FAIL] $*" >&2; exit 1; }
v2tip() { sqlite3 "$(ref_db)" "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;"; }

ref=$(ref_db)
[ -n "$ref" ] && [ -s "$ref" ] || die "no chain DB for the reference node"
has_v2=$(sqlite3 "$ref" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ]; then
    echo "[SKIP] not a Ledger V2 cluster with a genesis config — use stagef_up_v2.sh"
    exit 99
fi

# ── Find a node whose leaf is still unclaimed ───────────────────────
# Demand has to come from somewhere, and on a V2 chain the only thing a
# fresh identity can submit is its claim. Pick a donor now, so a "no
# unclaimed leaf" cluster SKIPS instead of failing later for a reason
# that has nothing to do with view changes.
DONOR=""
for n in $(running_nodes); do
    d="$BASE_DIR/vc_probe_$n.log"
    if "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF_NODE")" \
        v2-claim --config "$CONF" --db "$ref" \
        --keys "$(stagef_node_dir "$n")/identity" --dry-run > "$d" 2>&1 \
       && grep -q 'LOCAL ADMIT: OK' "$d"; then
        DONOR="$n"; break
    fi
done
[ -n "$DONOR" ] || { echo "[SKIP] no unclaimed genesis leaf left — bring the cluster up fresh"; exit 99; }
echo "[ok] node$DONOR still holds an unclaimed leaf (the demand source)"

bash "$(dirname "$0")/../stagef_diff.sh" "pre-v2-vc" || exit 2

# ── Derive the leader of the epoch the NEXT block lands in ──────────
head=$(v2tip)
[ "$head" -ge 0 ] || die "no V2 block to read a head from"
next=$(( head + 1 ))
EPOCH_START=$(( next / E_LEN * E_LEN ))
view_before=$(node_view "$REF_NODE")
echo "[ok] head=$head next=$next epoch_start=$EPOCH_START view=$view_before"

LEADER_LINE=$(stagef_leader_entry "$ref" "$EPOCH_START" "$E_LEN" "$view_before") || exit 5
read -r LEADER_IDX ACTIVE_COUNT LEADER_PK LEADER_WID <<< "$LEADER_LINE"

for n in $(running_nodes); do
    if [ "$(node_pubkey_hex "$n")" = "$LEADER_PK" ]; then VICTIM="$n"; break; fi
done
[ -n "$VICTIM" ] || die "the derived leader (entry $LEADER_IDX of $ACTIVE_COUNT) is none of this harness's nodes"
[ "$VICTIM" != "$DONOR" ] || {
    # The donor must stay reachable: a SIGSTOPped node still accepts TCP
    # and then times out at HELLO, so the claim would be lost client-side
    # and the cluster would never see demand.
    for n in $(running_nodes); do
        [ "$n" = "$VICTIM" ] && continue
        d="$BASE_DIR/vc_probe2_$n.log"
        if "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF_NODE")" \
            v2-claim --config "$CONF" --db "$ref" \
            --keys "$(stagef_node_dir "$n")/identity" --dry-run > "$d" 2>&1 \
           && grep -q 'LOCAL ADMIT: OK' "$d"; then DONOR="$n"; break; fi
    done
    [ "$VICTIM" != "$DONOR" ] || die "the only unclaimed leaf belongs to the derived leader"
}
VPID=$(pgrep -f "nodus-server.*node$VICTIM/data" | head -1 || true)
[ -n "$VPID" ] || die "node$VICTIM is not running"
echo "[ok] derived epoch leader = node$VICTIM (entry $LEADER_IDX of $ACTIVE_COUNT, pid $VPID)"

# Every single-node read from here on must avoid the victim.
[ "$REF_NODE" != "$VICTIM" ] || { REF_NODE=$(( VICTIM % STAGEF_COMMITTEE_SIZE + 1 )); echo "[ok] reference node re-pointed to node$REF_NODE"; }
SUBMIT_PORT=$(stagef_tcp_port "$REF_NODE")

vc_before=$(log_count "view change quorum")
p3_before=$(log_count "P3 committed tip frozen")

# ── Pause it ────────────────────────────────────────────────────────
kill -STOP "$VPID"
echo "[ok] node$VICTIM (the leader) paused"

# ── Create demand — this is what arms anything at all ───────────────
sub="$BASE_DIR/vc_demand.log"
"$CLI" -s 127.0.0.1 -p "$SUBMIT_PORT" v2-claim --config "$CONF" --db "$ref" \
    --keys "$(stagef_node_dir "$DONOR")/identity" \
    --submit "127.0.0.1:$SUBMIT_PORT" > "$sub" 2>&1 || true
echo "[ok] demand submitted from node$DONOR (claim)"

# ── Two independent facts, both required ────────────────────────────
committed=0
for _ in $(seq 1 120); do
    [ "$(v2tip)" -gt "$head" ] && { committed=1; break; }
    sleep 1
done
view_after=$(cluster_view_max "$VICTIM")
vc_after=$(log_count "view change quorum")
p3_after=$(log_count "P3 committed tip frozen")

echo "[info] with node$VICTIM paused: view $view_before -> $view_after, " \
     "head $head -> $(v2tip), vc quorums +$(( vc_after - vc_before )), P3 +$(( p3_after - p3_before )), committed=$committed"

rotated=0
[ "$view_after" -gt "$view_before" ] && rotated=1
[ "$vc_after" -gt "$vc_before" ] && rotated=1

if [ "$rotated" = 1 ] && [ "$committed" = 1 ]; then
    echo "[ok] the fleet rotated past its paused leader AND committed without it"
elif [ "$rotated" = 1 ]; then
    die "the view rotated but nothing committed — the survivors moved and then could not make a block"
elif [ "$committed" = 1 ]; then
    die "work committed with no view change — the paused node was not the leader, or the derivation is wrong"
else
    die "neither a rotation nor a commit — the cluster saw no demand (check $sub) or is stalled"
fi

# ── Resume and re-converge ──────────────────────────────────────────
resumed_node="$VICTIM"
kill -CONT "$VPID"
VICTIM=""          # disarms the EXIT trap; it has already been resumed
echo "[ok] node$resumed_node resumed"
sleep 15
bash "$(dirname "$0")/../stagef_diff.sh" "post-v2-vc" || exit 2

echo ""
echo "[PASS] a Ledger V2 fleet rotated the view past its DERIVED epoch leader,"
echo "       committed new work without it, and re-converged to one state_root"
echo "       across all $STAGEF_COMMITTEE_SIZE nodes after it resumed. Epoch length $E_LEN."
