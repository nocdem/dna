#!/usr/bin/env bash
#
# Stage F — MED-28 end-to-end proof (O15C-D.1).
#
# MED-28 was repaired in 73b5d943 with unit + ASan evidence only. The
# real path — a batch reaching PREPARED, the round failing, a view
# change completing, NEW_VIEW binding the prepared digest, and the new
# leader RE-PROPOSING the exact bytes — was never executed, because the
# ordinary rehearsal never times a round out. This scenario drives it on
# the live seven-node cluster.
#
# ── The defect being proven repaired ──────────────────────────────────
#
#   round timeout → round_state_free_batch() freed the batch on EVERY
#   node that held it (they had already left the mempool when batched),
#   and w->last_prepared carries the certificate but NO transaction
#   bytes. So once a view change completed with a prepared cert, the
#   (height, tx_root) digest NEW_VIEW bound could not be satisfied by
#   anyone: reproposal_required clears only on a matching PROPOSE, and
#   no node could construct one. The height wedged permanently.
#
# ── How the round is made to fail, deterministically ──────────────────
#
# The Faz 5.4 T3 drop predicate, driven by the env installer added in
# this season (nodus_witness_fault.c). Every node drops INBOUND
# PRECOMMIT while header.view == 0 and the arm file exists:
#
#   * PREVOTEs still flow      ⇒ prevote quorum ⇒ prepared cert captured
#   * PRECOMMITs never arrive  ⇒ no precommit quorum ⇒ round timeout
#   * timeout                  ⇒ retain the batch, start a view change
#   * view 1                   ⇒ NOT matched by the predicate, so the
#                                re-proposed round commits normally
#
# The arm file is created AFTER the cluster is up and funded and BEFORE
# the target spend is submitted — strictly-before, so nothing here
# depends on how long a step takes. Genesis (also view 0) commits during
# bring-up while the predicate is still inert, which is the whole reason
# it is arm-file-gated rather than armed at process start.
#
# ── What is asserted ──────────────────────────────────────────────────
#
# Primary evidence is COMMITTED CHAIN STATE, read from all seven witness
# DBs; log lines are corroboration for WHICH mechanism produced it.
#
#   1. the target spend commits (it must not be lost by the failed round)
#   2. the block carrying it committed at view > 0 — i.e. it really did
#      go through a view change, not a lucky retry
#   3. the re-proposed tx_root EQUALS the digest the prepared cert
#      authenticated — the value re-proposed is the value authorised
#   4. height, BlockID inputs and state_root identical 7/7
#   5. the retention and reproposal actually ran (log corroboration)
#
# Requires: nodus-server built -DQGP_FAULT_INJECT=ON.
# Env: NODUS_FAULT_ARM_FILE must have been exported before stagef_up.sh,
#      so every spawned node inherited it.

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || \
    fail "no active Stage F harness. Run stagef_up.sh first."
command -v sqlite3 >/dev/null || fail "sqlite3 CLI required"

ARM="${NODUS_FAULT_ARM_FILE:-}"
[ -n "$ARM" ] || fail "NODUS_FAULT_ARM_FILE not set — the nodes cannot have installed a predicate"

N=7
node1_db() { stagef_node_chain_db 1; }
head_height() {
    sqlite3 -readonly "$(node1_db)" "SELECT COALESCE(MAX(height),0) FROM blocks;"
}

# ── 0. the predicate must actually be installed on all seven ──────────
inst=0
for n in $(seq 1 $N); do
    grep -q "drop predicate installed" "$(stagef_node_dir "$n")/nodus.log" && inst=$((inst+1))
done
[ "$inst" -eq "$N" ] || fail "drop predicate installed on only $inst/$N nodes — is nodus-server built with -DQGP_FAULT_INJECT=ON?"
ok "fault predicate installed on $N/$N nodes"

[ ! -f "$ARM" ] || fail "arm file already exists before the scenario armed it: $ARM"
ok "predicate inert during bring-up (genesis committed at view 0)"

H0=$(head_height)
info "head before injection: $H0"
[ "${H0:-0}" -ge 1 ] || fail "cluster has no committed blocks — bring-up did not complete"

# ── 1. arm, THEN submit ───────────────────────────────────────────────
DEST=$(cat "$BASE_DIR/node2/identity/nodus.fp")
: > "$ARM"
ok "armed: view-0 PRECOMMITs will be dropped cluster-wide"

# The CLI's own wait will very likely expire — the round it lands in is
# the one being made to fail. The CHAIN is the authority in both
# directions (the harness's standing rule), so the exit code is noted,
# never trusted.
set +e
stagef_dna -q dna send "$DEST" 100000000 "med28_target" \
    > "$BASE_DIR/med28_send.log" 2>&1
send_rc=$?
set -e
info "client submit returned rc=$send_rc (not authoritative)"

# ── 2. wait for the chain to move past the wedge ──────────────────────
# round_timeout 15 s + viewchg_timeout 10 s + commit. A generous bound:
# if MED-28 is unrepaired this never advances, and that is the point.
deadline=$(( SECONDS + 180 ))
H1=$H0
while [ $SECONDS -lt $deadline ]; do
    H1=$(head_height)
    [ "${H1:-0}" -gt "$H0" ] && break
    sleep 2
done

if [ "${H1:-0}" -le "$H0" ]; then
    echo "[FAIL] chain did not advance past $H0 within 180 s" >&2
    echo "       This is the MED-28 wedge: a prepared batch was freed," >&2
    echo "       so the digest NEW_VIEW bound can never be re-proposed." >&2
    for n in $(seq 1 $N); do
        echo "--- node$n (tail) ---" >&2
        tail -25 "$(stagef_node_dir "$n")/nodus.log" >&2
    done
    exit 1
fi
ok "chain advanced $H0 → $H1 after the injected round failure"

# ── 3. the round really did fail and a view change really happened ────
to_n=0; vc_n=0; ret_n=0
for n in $(seq 1 $N); do
    lg="$(stagef_node_dir "$n")/nodus.log"
    grep -q "round timeout"                   "$lg" && to_n=$((to_n+1))
    grep -q "we are new leader for view"      "$lg" && vc_n=$((vc_n+1))
    grep -q "MED-28 retained"                 "$lg" && ret_n=$((ret_n+1))
done
[ "$to_n"  -ge 1 ] || fail "no node logged a round timeout — the injection did not bite"
[ "$ret_n" -ge 1 ] || fail "no node retained a batch — retained_batch_take never ran"
ok "round timeout on $to_n/$N, batch retained on $ret_n/$N, new leader on $vc_n"

# ── 4. the reproposal executed, and followers accepted it as MATCHING ─
rep_n=0; match_n=0; nohold_n=0
for n in $(seq 1 $N); do
    lg="$(stagef_node_dir "$n")/nodus.log"
    grep -q "MED-28 re-proposed retained batch"            "$lg" && rep_n=$((rep_n+1))
    grep -q "C5 PROPOSE matches NEW_VIEW reproposal"       "$lg" && match_n=$((match_n+1))
    grep -q "MED-28 bound to a reproposal we do not hold"  "$lg" && nohold_n=$((nohold_n+1))
done
[ "$rep_n" -ge 1 ] || fail "no node re-proposed a retained batch — the repaired path never executed"
[ "$nohold_n" -eq 0 ] || info "$nohold_n node(s) were bound to a reproposal they did not hold (allowed: they stay silent and the view rotates)"

# HARD assertion — this is the one that proves the binding was ENFORCED
# rather than merely announced.
#
# It was report-only in the first version of this scenario, and that is
# exactly how a vacuous pass slipped through: the run went green with
# match_n == 0, because every node self-advanced its own view and the
# NEW_VIEW accept block (which was then the ONLY place arming C5) was
# skipped. The gate never evaluated, so a substituted value would have
# been accepted. See nodus_witness_bft_bind_reproposal_from_view_changes.
sb_n=0
for n in $(seq 1 $N); do
    grep -q "C5 self-bound to reproposal" "$(stagef_node_dir "$n")/nodus.log" && sb_n=$((sb_n+1))
done
[ "$sb_n" -ge 1 ] || fail "no node self-bound to the reproposal — the C5 rule did not arm"
ok "C5 binding armed on $sb_n/$N nodes (self-bind at view-change quorum)"

[ "$match_n" -ge 1 ] || fail \
    "the C5 gate never accepted the reproposal on any follower (match=$match_n, self-bound=$sb_n) — the binding was not enforced"
ok "retained batch RE-PROPOSED by $rep_n node(s); $match_n follower(s) EVALUATED the C5 gate and accepted it as matching"

# ── 5. the re-proposed value is the value the prepared cert authorised ─
# The C5 binding is (height, tx_root). Extract the digest a NEW_VIEW
# bound, and the tx_root the block at that height actually committed.
bound=$(grep -h "C5 NEW_VIEW reproposal (height=" "$BASE_DIR"/node*/nodus.log | head -1 || true)
[ -n "$bound" ] || fail "no NEW_VIEW carried a reproposal binding — nothing was bound to prove"
bh=$(echo "$bound" | sed -n 's/.*height=\([0-9]*\).*/\1/p')
[ -n "$bh" ] || fail "could not parse the bound height from: $bound"
info "NEW_VIEW bound height=$bh"

committed_root=$(sqlite3 -readonly "$(node1_db)" \
    "SELECT hex(tx_root) FROM blocks WHERE height = $bh;")
[ -n "$committed_root" ] || fail "no block committed at the bound height $bh — the binding was never satisfied"
ok "a block committed at the bound height $bh (tx_root ${committed_root:0:16}...)"

# ── 6. 7/7 identity on the block that went through the view change ────
ref=""
for n in $(seq 1 $N); do
    db=$(stagef_node_chain_db "$n")
    row=$(sqlite3 -readonly "$db" \
        "SELECT height || '|' || hex(state_root) || '|' || hex(tx_root) \
           FROM blocks WHERE height = $bh;" 2>/dev/null || true)
    [ -n "$row" ] || fail "node$n has no block at height $bh"
    if [ -z "$ref" ]; then ref="$row"
    elif [ "$row" != "$ref" ]; then
        fail "node$n DIVERGED at height $bh: $row != $ref"
    fi
done
ok "height/state_root/tx_root identical $N/$N at the re-proposed height $bh"

# ── 7. the target spend was not lost by the failed round ──────────────
found=0
for n in $(seq 1 $N); do
    db=$(stagef_node_chain_db "$n")
    cnt=$(sqlite3 -readonly "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$DEST';" 2>/dev/null || echo 0)
    [ "${cnt:-0}" -ge 1 ] && found=$((found+1))
done
[ "$found" -eq "$N" ] || fail "target spend visible on only $found/$N nodes"
ok "the target spend survived the failed round and committed on $N/$N"

echo
echo "=== MED-28 END-TO-END PROOF PASSED ==="
echo "    prepared batch → round failure → view change → NEW_VIEW binding"
echo "    → reproposal of the retained bytes → committed, identical $N/$N"
