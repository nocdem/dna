#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_restart_convergence.sh — a V2 node dies and comes back
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a node holding a pure Ledger V2 chain, killed and restarted,
#   comes back ON THE SAME CHAIN, in its witness role, and still agrees
#   with the six that never stopped. The property that would be false if
#   it failed: *a V2 node's chain identity and its right to vote survive
#   a restart, and are re-derived from disk rather than from peers.*
#
#   That is not a formality on this lane. A V2 node establishes its role
#   at open by probing its own database (nodus_witness.c: the pure-V2
#   role gate), and until v0.19.37 a restarted node with a V2 chain
#   answered "I have no chain" — because the presence test read the
#   LEGACY blocks table, which a V2 chain never writes — and walked into
#   the legacy DISCOVER state machine, which ends in exit(2). This
#   scenario is the multi-node witness for that fix; ctest covers the
#   branch, nothing covered the node.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none of its own.
#   ⚠ A cluster brought up by **stagef_up_v2.sh**, not stagef_up.sh. On a
#   legacy cluster it exits 99 rather than pretending to have tested a
#   V2 property — a skip is not a pass, and a silent legacy run here
#   would be exactly the vacuous green this suite keeps finding.
#
# WHAT IT LEAVES BEHIND
#   One node killed and restarted under a NEW pid, appended to
#   pids.txt so stagef_down.sh still reaps it. Its nodus.log is appended
#   to, not truncated, so it holds two runs. The victim is node 4 —
#   FIXED, not derived, and the reason is written at the kill site.
#   Nothing else changes: no transaction is submitted, so the chain does
#   not advance.
#
# HOW IT CAN LIE
#   - **It cannot observe block production, and does not claim to.** A
#     pure V2 chain today has no way to receive a transaction — the only
#     genesis-claim builder derives its leaves from a LEGACY utxo_set
#     (nodus-cli.c claim_derive_legacy_leaves) and a hard cutover leaves
#     no legacy database, so nothing can be submitted and the chain sits
#     at height 0. Every assertion here is therefore about IDENTITY and
#     ROLE across a restart, never about consensus making progress.
#     When that blocker is closed, this scenario should NOT be extended
#     to cover progress — write the one that pumps, and leave this one
#     measuring what it measures.
#   - **"Still 7/7" is weak while the chain is frozen.** With no new
#     blocks, the post-restart state_root comparison is over the same
#     genesis row it read before. It would catch a node that came back on
#     a DIFFERENT chain or with a corrupted root — which is the point —
#     but it cannot catch a node that fails to APPLY anything, because
#     nothing is being applied. Read the role and chain-id assertions as
#     the load-bearing ones.
#   - **A restarted node still LISTENS even when its witness role fails.**
#     nodus keeps serving DHT traffic when the witness module refuses to
#     init, so a port check would pass on a node that votes on nothing.
#     The role line is read from the log for exactly that reason, and the
#     count is a BEFORE/AFTER delta — the line from the FIRST boot is
#     already in that file, so `grep -q` would be vacuously true.
#   - **rc=99 means the cluster was not V2**, not that the property
#     holds. The runner treats 99 as SKIP; that is coverage that did not
#     happen.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

VICTIM=4          # FIXED, deliberately: leadership plays no part here —
                  # nothing is proposed, so there is no leader to derive
                  # and no reason to pretend otherwise. A derived victim
                  # would imply this scenario is about rotation. It is not.
REF=1

die() { echo "[FAIL] $*" >&2; exit 1; }

db_of() { stagef_node_chain_db "$1"; }

# ── Precondition: this MUST be a V2 cluster ─────────────────────────
ref_db=$(db_of "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"

has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Ledger V2 cluster — bring it up with stagef_up_v2.sh"
    exit 99
fi
n_v2=$(sqlite3 "$ref_db" "SELECT COUNT(*) FROM v2_blocks;" 2>/dev/null || echo 0)
[ "${n_v2:-0}" != "0" ] || { echo "[SKIP] V2 schema present but no V2 block"; exit 99; }
echo "[ok] cluster is on the Ledger V2 lane ($n_v2 block(s))"

# ── Baseline ────────────────────────────────────────────────────────
bash "$(dirname "$0")/../stagef_diff.sh" "pre-v2-restart" || exit 2

chain_before=$(sqlite3 "$(db_of "$VICTIM")" \
    "SELECT hex(block_id) FROM v2_blocks WHERE global_height=0;")
[ -n "$chain_before" ] || die "node$VICTIM has no V2 genesis row"

vlog="$(stagef_node_dir "$VICTIM")/nodus.log"
role_before=$(grep -c 'chain role: LEDGER V2' "$vlog" || true)
[ "$role_before" -ge 1 ] || die "node$VICTIM never reported the V2 role before the kill"
echo "[ok] node$VICTIM baseline: genesis=${chain_before:0:32} role_lines=$role_before"

# ── Kill ────────────────────────────────────────────────────────────
# The victim's own spawn line is reconstructed from stagef_env, not
# scraped from ps: a scraped command line would carry whatever the
# previous restart used and quietly drift.
vpid=$(pgrep -f "node$VICTIM/data" | head -1 || true)
[ -n "$vpid" ] || die "node$VICTIM is not running"
kill -9 "$vpid"
echo "[ok] node$VICTIM killed (pid $vpid)"
sleep 3

# The six survivors must still agree while it is down. If they do not,
# the restart has nothing to do with it.
bash "$(dirname "$0")/../stagef_diff.sh" "victim-down" >/dev/null 2>&1 || {
    echo "[info] state_root read failed with the victim down — expected:" >&2
    echo "       stagef_diff reads ALL committee nodes and node$VICTIM has no process." >&2
}

# ── Restart ─────────────────────────────────────────────────────────
nd=$(stagef_node_dir "$VICTIM")
SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done
# shellcheck disable=SC2086
"$STAGEF_NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
    -u "$(stagef_udp_port "$VICTIM")" -t "$(stagef_tcp_port "$VICTIM")" \
    -p "$(stagef_peer_port "$VICTIM")" -C "$(stagef_chan_port "$VICTIM")" \
    -W "$(stagef_witness_port "$VICTIM")" \
    -i "$nd/identity" -d "$nd/data" $SEEDS \
    >> "$nd/nodus.log" 2>&1 &
newpid=$!
echo "$newpid" >> "$BASE_DIR/pids.txt"
echo "[ok] node$VICTIM restarted (pid $newpid)"

tcp=$(stagef_tcp_port "$VICTIM")
up=0
for _ in $(seq 1 60); do
    if ss -lt 2>/dev/null | grep -Eq "[:.]${tcp}\\b"; then up=1; break; fi
    sleep 0.5
done
[ "$up" = 1 ] || die "node$VICTIM never listened again on $tcp"
sleep 5

# ── THE ASSERTIONS ──────────────────────────────────────────────────
# 1. It came back IN ITS WITNESS ROLE. A delta, not a presence check:
#    the line from the first boot is already in this file.
role_after=$(grep -c 'chain role: LEDGER V2' "$vlog" || true)
[ "$role_after" -gt "$role_before" ] || die \
  "node$VICTIM did NOT report the V2 role after restart (before=$role_before after=$role_after) — \
this is the shape the pre-v0.19.37 defect had: the node comes up, listens, serves DHT, and holds no witness role"
echo "[ok] node$VICTIM re-established the LEDGER V2 role ($role_before -> $role_after)"

# 2. It refused nothing on the way up.
if grep -q 'REFUSING START' "$vlog"; then
    tail -20 "$vlog" >&2
    die "node$VICTIM logged REFUSING START"
fi

# 3. It is on the SAME chain — the identity survived the restart and was
#    re-derived from disk, not adopted from a peer.
chain_after=$(sqlite3 "$(db_of "$VICTIM")" \
    "SELECT hex(block_id) FROM v2_blocks WHERE global_height=0;")
[ "$chain_after" = "$chain_before" ] || die \
  "node$VICTIM came back on a DIFFERENT chain: ${chain_before:0:32} -> ${chain_after:0:32}"
echo "[ok] node$VICTIM is on the same chain (${chain_after:0:32})"

# 4. The partial-wipe marker is present. On a V2 chain nothing else can
#    have written it: the derivation's own write lands in a scratch
#    directory that is discarded, and there is no genesis transaction to
#    trigger the legacy path. So this is the v0.19.37 server-side write,
#    exercised by a real restart.
[ -f "$nd/data/.witness_db_seen" ] || die \
  "node$VICTIM has no .witness_db_seen after a successful start — the partial-wipe gate is disarmed on this node"
echo "[ok] partial-wipe marker present after restart"

# 5. Everyone still agrees.
bash "$(dirname "$0")/../stagef_diff.sh" "post-v2-restart" || exit 2

echo ""
echo "[PASS] a Ledger V2 node was killed and restarted: it re-established its"
echo "       witness role, re-derived the SAME chain identity from disk, kept"
echo "       the partial-wipe marker, and all $STAGEF_COMMITTEE_SIZE nodes still agree."
echo "       NOT proven here: block production — a pure V2 chain cannot yet"
echo "       receive a transaction (see the genesis-claim blocker), so the"
echo "       chain is frozen at its genesis height throughout."
