#!/usr/bin/env bash
#
# Stage F — O15C-D.3 — live seven-node NEW_VIEW convergence under
# GENUINELY DIFFERENT VIEW_CHANGE subsets.
#
# The record: honest validators may obtain different valid first-2f+1
# VIEW_CHANGE collections for the same target view. `view_changes[]`
# freezes at quorum (handle_viewchg drops any later VIEW_CHANGE for the
# accepted view), so the divergence is permanent. Before the repair a
# follower verified the leader's reproposal against its OWN frozen
# subset, so two honest nodes could reach different verdicts on the very
# same valid NEW_VIEW — and, worse, a node whose own prepared value was
# missing from its subset would vote a conflicting value at a height it
# had itself prepared.
#
# How the state is manufactured deterministically (not by timing):
#
#   * view-0 PRECOMMITs are dropped cluster-wide, so the round fails and
#     a view change starts with a prepared certificate in play;
#   * each node ALSO drops VIEW_CHANGE from its own list of senders
#     (NODUS_FAULT_DROP_VC_ROTATE=<k>, k >= 1), so the nodes legitimately
#     collect DIFFERENT — but individually valid — first-2f+1 subsets.
#     (This comment named NODUS_FAULT_DROP_VC_FROM until 2026-08-27. No
#     such variable has ever existed: nodus_witness_fault.c:164 reads
#     NODUS_FAULT_DROP_VC_ROTATE. Exporting the name written here does
#     nothing, every node comes up with vc_drop_senders=0, and the
#     scenario aborts as vacuous — which is exactly how the wrong name
#     was found.)
#
# What must hold after the repair:
#
#   1. the cluster still converges and commits;
#   2. every node agrees on height, state_root and tx_root;
#   3. the target spend is not lost;
#   4. NEW_VIEW carried a certificate (not a bare digest), and followers
#      verified it rather than consulting their own subsets.
#
# Requires nodus-server built -DQGP_FAULT_INJECT=ON, and ALL of these
# exported BEFORE stagef_up.sh (the server installs the predicate once,
# at witness init — exporting them later has no effect):
#
#   NODUS_FAULT_ARM_FILE=<path>        # armed by TOUCHING this file;
#                                      # must NOT exist at scenario start
#   NODUS_FAULT_DROP_TYPE=precommit    # view-0 PRECOMMITs, cluster-wide
#   NODUS_FAULT_DROP_VIEW=0
#   NODUS_FAULT_DROP_VC_ROTATE=2       # per-node VIEW_CHANGE drop width

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || \
    fail "no active Stage F harness. Run stagef_up.sh first."
ARM="${NODUS_FAULT_ARM_FILE:-}"
[ -n "$ARM" ] || fail "NODUS_FAULT_ARM_FILE not set"
command -v sqlite3 >/dev/null || fail "sqlite3 CLI required"

N=7
node1_db() { stagef_node_chain_db 1; }
head_height() {
    sqlite3 -readonly "$(node1_db)" "SELECT COALESCE(MAX(height),0) FROM blocks;"
}

# The predicate must be installed on all seven, and the per-node
# VIEW_CHANGE drop lists must actually be in force — otherwise the
# subsets would be identical and this scenario would prove nothing.
inst=0; vcd=0
for n in $(seq 1 $N); do
    lg="$(stagef_node_dir "$n")/nodus.log"
    grep -q "drop predicate installed" "$lg" && inst=$((inst+1))
    grep -q "vc_drop_senders=[1-9]" "$lg" && vcd=$((vcd+1))
done
[ "$inst" -eq "$N" ] || fail "predicate installed on only $inst/$N nodes"
ok "fault predicate installed on $N/$N"
[ "$vcd" -ge 2 ] || fail "sender-scoped VIEW_CHANGE drops active on only $vcd nodes — subsets would not differ, the scenario would be vacuous"
ok "per-node VIEW_CHANGE drop lists active on $vcd/$N nodes (subsets WILL differ)"

H0=$(head_height)
info "head before injection: $H0"
[ "${H0:-0}" -ge 1 ] || fail "cluster has no committed blocks"

DEST=$(cat "$BASE_DIR/node2/identity/nodus.fp")
: > "$ARM"
ok "armed: view-0 PRECOMMITs dropped cluster-wide; per-node VIEW_CHANGE drops live"

set +e
stagef_dna -q dna send "$DEST" 100000000 "d3_conv" \
    > "$BASE_DIR/d3_send.log" 2>&1
rc=$?
set -e
info "client submit rc=$rc (not authoritative)"

deadline=$(( SECONDS + 240 ))
H1=$H0
while [ $SECONDS -lt $deadline ]; do
    H1=$(head_height)
    [ "${H1:-0}" -gt "$H0" ] && break
    sleep 3
done

if [ "${H1:-0}" -le "$H0" ]; then
    echo "[FAIL] chain did not advance past $H0 within 240 s" >&2
    for n in $(seq 1 $N); do
        echo "--- node$n ---" >&2
        tail -20 "$(stagef_node_dir "$n")/nodus.log" >&2
    done
    exit 1
fi
ok "chain advanced $H0 → $H1 despite differing VIEW_CHANGE subsets"

# ── the repaired mechanism actually executed ──────────────────────────
vc_n=0; cert_n=0; adopt_n=0; keep_n=0; verifyfail_n=0
for n in $(seq 1 $N); do
    lg="$(stagef_node_dir "$n")/nodus.log"
    grep -q "view change quorum!"                    "$lg" && vc_n=$((vc_n+1))
    grep -q "carrying .* sigs"                       "$lg" && cert_n=$((cert_n+1))
    grep -q "C5 ADOPTED the NEW_VIEW's verified cert" "$lg" && adopt_n=$((adopt_n+1))
    grep -q "C5 kept our own binding"                 "$lg" && keep_n=$((keep_n+1))
    grep -q "UNVERIFIABLE prepared cert"              "$lg" && verifyfail_n=$((verifyfail_n+1))
done
[ "$vc_n" -ge 1 ] || fail "no view change completed — the injection did not bite"
ok "view change completed on $vc_n/$N"
[ "$cert_n" -ge 1 ] || fail "no NEW_VIEW carried a certificate — the wire repair did not execute"
ok "NEW_VIEW carried a prepared CERTIFICATE on $cert_n node(s) (not a bare digest)"
info "adoption: $adopt_n adopted the carried cert, $keep_n kept a strictly-outranking local binding"
[ "$verifyfail_n" -eq 0 ] || fail "$verifyfail_n node(s) rejected the cert as unverifiable — honest leader's proof must verify everywhere"
ok "no honest node found the carried certificate unverifiable"

# ── committed-state agreement ─────────────────────────────────────────
ref=""
for n in $(seq 1 $N); do
    row=$(sqlite3 -readonly "$(stagef_node_chain_db "$n")" \
        "SELECT MAX(height) || '|' || hex(state_root) || '|' || hex(tx_root) \
           FROM blocks WHERE height = (SELECT MAX(height) FROM blocks);" \
        2>/dev/null || true)
    [ -n "$row" ] || fail "node$n has no committed blocks"
    if [ -z "$ref" ]; then ref="$row"
    elif [ "$row" != "$ref" ]; then
        fail "node$n DIVERGED: $row != $ref"
    fi
done
ok "height/state_root/tx_root identical $N/$N"

found=0
for n in $(seq 1 $N); do
    cnt=$(sqlite3 -readonly "$(stagef_node_chain_db "$n")" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$DEST';" 2>/dev/null || echo 0)
    [ "${cnt:-0}" -ge 1 ] && found=$((found+1))
done
[ "$found" -eq "$N" ] || fail "target spend visible on only $found/$N nodes"
ok "the target spend survived and committed on $N/$N"

echo
echo "=== NEW_VIEW CONVERGENCE UNDER DIFFERING SUBSETS PASSED ==="
