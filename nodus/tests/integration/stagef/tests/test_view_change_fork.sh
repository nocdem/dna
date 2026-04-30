#!/usr/bin/env bash
#
# Stage F test — C5 view-change + partial-participation safety.
#
# Verifies the C5 (PBFT prepared-certificate view-change discipline)
# path does not introduce state_root divergence:
#
#   Phase A — C5 prepared-cert capture fires on all 7 nodes after
#             genesis commit (Phase 3 regression guard).
#   Phase B — Stop one node mid-workload, verify the surviving 6
#             nodes keep consensus and commit a new TX (2f+1=5 of 7
#             is reachable with 1 node down; no view-change fires but
#             the prepared-cert capture path must stay healthy).
#   Phase C — Resume the stopped node, verify it syncs back to the
#             same state_root via the sync handler.
#   Phase D — Final assertion: all 7 nodes at identical state_root.
#
# Full Byzantine view-change-fork triggering (leader isolated mid-
# proposal so 3+ nodes carry conflicting prepared certs) requires
# network partition tooling (tc/iptables) or Byzantine injection —
# future work. This test catches regressions in the C5 capture / sync /
# convergence paths using just process-level signals.
#
# Requires an active Stage F harness (stagef_up.sh).

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

# ── Phase A — C5 prepared-cert capture on all nodes ─────────────────
# Genesis BFT round fires shortly after stagef_up returns. On slow
# machines or when peer-mesh establishment lags into the warn-window
# ("[warn] not all nodes reached full roster within 30 s"), a node
# may still be wiring up its committee at the moment we sample the
# log. Poll for up to 30 s with 1 s granularity instead of one-shot —
# if all 7 captures never arrive within that window the node really
# did miss the round.
echo "== Phase A — C5 prepared-cert capture post-genesis =="
deadline=$(( SECONDS + 60 ))
captured=0
while [ $SECONDS -lt $deadline ]; do
    captured=0
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        log="$BASE_DIR/node$n/nodus.log"
        if [ -f "$log" ] && grep -q "C5 prepared cert captured" "$log"; then
            captured=$((captured + 1))
        fi
    done
    [ "$captured" -ge "$STAGEF_COMMITTEE_SIZE" ] && break
    sleep 1
done
if [ "$captured" -lt "$STAGEF_COMMITTEE_SIZE" ]; then
    echo "[FAIL] only $captured of $STAGEF_COMMITTEE_SIZE nodes logged C5 prepared-cert capture (after 60s wait)" >&2
    exit 2
fi
echo "[info] all $captured nodes logged C5 prepared-cert capture"

bash "$(dirname "$0")/../stagef_diff.sh" "baseline"

# ── Phase B — stop one node, verify 6-of-7 consensus ────────────────
echo ""
echo "== Phase B — partial participation (stop 1 node) =="

# Target node 1. With 2f+1=5 quorum and 6 live nodes, consensus still
# forms even if node 1 was the leader (next leader takes over on
# round-timeout path, or leader stays node 1 but never reaches quorum
# so round eventually times out and view-changes — either way the
# remaining cluster either commits or falls back; we verify
# convergence, not the exact path).
TARGET_NODE=1
TARGET_PID=$(pgrep -f "$BASE_DIR/node${TARGET_NODE}/" | head -1 || true)
if [ -z "$TARGET_PID" ]; then
    echo "[FAIL] could not find pid for node$TARGET_NODE" >&2
    exit 3
fi
echo "[info] stopping node$TARGET_NODE (pid=$TARGET_PID)"

# Set trap to resume the node even on early exit (so we don't leave
# the harness in a stopped state for the next test).
kill -STOP "$TARGET_PID"
trap "kill -CONT $TARGET_PID 2>/dev/null || true" EXIT

# When node 1 was the BFT leader, the surviving 6 nodes need to
# complete a view change before any new TX can commit:
#   - 16s round_timeout (NODUS_T3_ROUND_TIMEOUT_MS)
#   - 16s view_change_timeout (NODUS_T3_VIEWCHG_TIMEOUT_MS)
#   - new leader broadcasts new_view + first proposal
# CLI `dna send` waits ~30s for commit. If we issue the spend BEFORE
# the view change completes, the leader is still node 1 (paused) and
# the spend times out even though consensus is healthy.
#
# Wait for the surviving nodes to either record a "view change quorum"
# or move on to a round under a new leader before issuing the spend.
# Polling cap: 90 s (covers worst-case round + view-change + slack).
echo "[info] waiting for view change quorum on surviving nodes (max 90s)..."
deadline=$(( SECONDS + 90 ))
vc_quorum=0
while [ $SECONDS -lt $deadline ]; do
    vc_quorum=0
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        [ "$n" = "$TARGET_NODE" ] && continue
        log="$BASE_DIR/node$n/nodus.log"
        if [ -f "$log" ] && grep -q "view change quorum" "$log"; then
            vc_quorum=$((vc_quorum + 1))
        fi
    done
    # Need 2f+1 = 5 (out of 6 surviving) to have logged VC quorum.
    [ "$vc_quorum" -ge 5 ] && break
    sleep 2
done
if [ "$vc_quorum" -lt 5 ]; then
    echo "[info] only $vc_quorum/6 surviving nodes reached view change quorum (90s)"
    echo "[info] proceeding anyway — the original leader may still be node 1's slot, in which case no VC is required and the spend will simply commit"
else
    echo "[info] view change quorum reached on $vc_quorum surviving nodes"
fi

# Create a fresh funded user while node 1 is paused. 6 live witnesses
# must carry the funding TX to commit. New leader (post-VC) handles it.
TEST_HOME=$(stagef_mk_funded_user "vcfork" 120000000000000) || {
    echo "[FAIL] could not fund test user (6-of-7 consensus broken?)" >&2
    exit 4
}
echo "[info] funded user created with node$TARGET_NODE paused"

# ── Phase C — resume node, verify sync catch-up ─────────────────────
echo ""
echo "== Phase C — resume + sync =="
kill -CONT "$TARGET_PID"
trap - EXIT
echo "[info] node$TARGET_NODE resumed"

# Give sync 30s to catch node 1 up. Sync interval is typically fast but
# Dilithium verify on replayed blocks is slow.
sleep 30

# ── Phase D — final state_root convergence ──────────────────────────
echo ""
echo "== Phase D — final state_root convergence =="
bash "$(dirname "$0")/../stagef_diff.sh" "post-vcfork"

# Bonus: report any view-change or reproposal evidence we observed.
# This is informational; the PASS is defined by state_root convergence.
vc_evidence=0
repr_evidence=0
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    log="$BASE_DIR/node$n/nodus.log"
    [ -f "$log" ] || continue
    if grep -q "view change quorum\|initiated view change" "$log"; then
        vc_evidence=$((vc_evidence + 1))
    fi
    if grep -q "C5 NEW_VIEW\|C5 PROPOSE matches\|C5 accepted prepared" "$log"; then
        repr_evidence=$((repr_evidence + 1))
    fi
done
echo "[info] view-change activity on $vc_evidence nodes"
echo "[info] C5 reproposal activity on $repr_evidence nodes"

echo ""
echo "[PASS] C5 view-change-fork smoke: $captured/$STAGEF_COMMITTEE_SIZE nodes captured prepared cert, state_root converged after partial participation + resume"
