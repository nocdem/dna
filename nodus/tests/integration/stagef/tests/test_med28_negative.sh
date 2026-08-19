#!/usr/bin/env bash
#
# Stage F — MED-28 NEGATIVE case (O15C-D.1).
#
# Proves the e2e scenario actually depends on the MED-28 repair: run the
# SAME injection against a build whose retention call has been removed,
# and the cluster must wedge instead of recovering.
#
# This script EXPECTS FAILURE of the chain and exits 0 when it observes
# it. It is not part of ctest; it is driven manually against a throwaway
# neutralized build in /tmp (never the worktree, never git history).
#
# Why not `git archive HEAD^`: the parent commit also lacks the MED-27
# repair, the arrival-order leader fix and this season's fault-injection
# scaffolding, so a failure there would not be attributable to MED-28.
# The neutralized copy differs from the tested tree by exactly ONE call.
#
# Expected mechanism without the repair:
#   round timeout → batch FREED on every node → view change completes →
#   the C5 selection still binds the prepared digest (self-bind) → but
#   NO node holds the bytes, so the bound height can never be proposed.
#   A second spend submitted afterwards is rejected by every follower
#   with "C5 PROPOSE does not match NEW_VIEW reproposal", which is the
#   wedge made observable.

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || \
    fail "no active Stage F harness. Run stagef_up.sh first."
ARM="${NODUS_FAULT_ARM_FILE:-}"
[ -n "$ARM" ] || fail "NODUS_FAULT_ARM_FILE not set"

N=7
node1_db() { stagef_node_chain_db 1; }
head_height() {
    sqlite3 -readonly "$(node1_db)" "SELECT COALESCE(MAX(height),0) FROM blocks;"
}

# The neutralized build must NOT be able to retain a batch.
inst=0
for n in $(seq 1 $N); do
    grep -q "drop predicate installed" "$(stagef_node_dir "$n")/nodus.log" && inst=$((inst+1))
done
[ "$inst" -eq "$N" ] || fail "predicate installed on only $inst/$N — wrong binary?"
ok "fault predicate installed on $N/$N (neutralized build)"

H0=$(head_height)
info "head before injection: $H0"

DEST=$(cat "$BASE_DIR/node2/identity/nodus.fp")
: > "$ARM"
ok "armed"

set +e
stagef_dna -q dna send "$DEST" 100000000 "med28_neg_1" \
    > "$BASE_DIR/med28_neg1.log" 2>&1
set -e
info "spend #1 submitted (the round that will be made to fail)"

# Give the round timeout (15 s) + view change (10 s) room to complete.
sleep_deadline=$(( SECONDS + 60 ))
while [ $SECONDS -lt $sleep_deadline ]; do
    if grep -qh "view change quorum!" "$BASE_DIR"/node*/nodus.log 2>/dev/null; then break; fi
    sleep 2
done
grep -qh "view change quorum!" "$BASE_DIR"/node*/nodus.log || \
    fail "no view change completed — the injection did not bite, nothing is being proven"
ok "view change completed (the wedge precondition)"

# Second spend: this is what turns "nothing happened" into an OBSERVED
# rejection against the binding.
set +e
stagef_dna -q dna send "$DEST" 100000000 "med28_neg_2" \
    > "$BASE_DIR/med28_neg2.log" 2>&1
set -e
info "spend #2 submitted (must be rejected against the C5 binding)"

deadline=$(( SECONDS + 150 ))
H1=$H0
while [ $SECONDS -lt $deadline ]; do
    H1=$(head_height)
    [ "${H1:-0}" -gt "$H0" ] && break
    sleep 3
done

# ── The proof ─────────────────────────────────────────────────────────
ret_n=0; rej_n=0; sb_n=0; nohold_n=0
for n in $(seq 1 $N); do
    lg="$(stagef_node_dir "$n")/nodus.log"
    grep -q "MED-28 retained"                            "$lg" && ret_n=$((ret_n+1))
    grep -q "C5 PROPOSE does not match NEW_VIEW"         "$lg" && rej_n=$((rej_n+1))
    grep -q "C5 self-bound to reproposal"                "$lg" && sb_n=$((sb_n+1))
    grep -q "MED-28 bound to a reproposal we do not hold" "$lg" && nohold_n=$((nohold_n+1))
done

[ "$ret_n" -eq 0 ] || fail "a node retained a batch — this build is NOT neutralized"
ok "no node retained a batch (repair confirmed absent)"

[ "$sb_n" -ge 1 ] || fail "C5 never armed — the wedge cannot be attributed to MED-28"
ok "C5 binding armed on $sb_n/$N (so the binding IS enforced here)"

[ "$nohold_n" -ge 1 ] || info "no node reported 'bound to a reproposal we do not hold'"
[ "$nohold_n" -eq 0 ] || ok "$nohold_n node(s) were bound to bytes NOBODY holds — the MED-28 wedge"

if [ "${H1:-0}" -gt "$H0" ]; then
    fail "chain advanced $H0 → $H1 WITHOUT the repair — the scenario does not depend on MED-28, so the positive run proved nothing"
fi
ok "chain did NOT advance past $H0 — wedged, as the removed repair predicts"

[ "$rej_n" -ge 1 ] || info "no follower logged a C5 mismatch (the leader may never have proposed at all — also a wedge)"
[ "$rej_n" -eq 0 ] || ok "$rej_n follower(s) rejected a proposal against the binding"

echo
echo "=== MED-28 NEGATIVE CASE CONFIRMED ==="
echo "    Removing exactly one call (retained_batch_take) wedges the"
echo "    cluster on the same scenario the repaired build recovers from."
