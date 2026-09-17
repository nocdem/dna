#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_restart_convergence.sh — a V2 node dies and comes back
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a node holding a version-3 (cometbft) chain, killed and
#   restarted, comes back ON THE SAME CHAIN, in its witness role, resumes
#   production, and still agrees with the six that never stopped. The
#   property that would be false if it failed: *a Comet node's chain
#   identity and its right to vote survive a restart, are re-derived from
#   disk rather than from peers, and its ledger and its consensus state
#   are reconciled by the reference's own Handshaker before it rejoins.*
#
#   That is not a formality on this lane. A version-3 node establishes
#   its role at open by probing its own database
#   (nodus_witness.c:861-962, `witness_post_open_gate`), and on a
#   restart it additionally runs the ABCI Handshake
#   (`nodus_cmt_node_start` -> `hs_replay_blocks_with_context`,
#   nodus_witness_cmt_node.c:854-1130) — reconciling the ledger's own
#   height against the Comet block store and the Comet state store
#   before consensus is allowed to resume. Until v0.19.37 (the pre-Comet
#   fix this scenario is descended from) a restarted V2 node answered "I
#   have no chain" and walked into the legacy DISCOVER machine, which
#   ends in exit(2).
#
#   DELTA 1 (verifier CLAIM 12, REFUTED on the point below — CORRECTED,
#   not removed): the bootstrap machine is NOT unreachable on a
#   version-3 chain. `nodus_witness_bootstrap_start` runs unconditionally
#   (nodus_witness.c:1951), seven lines before the `v2_successor` gate,
#   and `nodus_witness_bootstrap.c:457,480-482` deliberately ROUTES a
#   version-3 chain into the HAVE_CHAIN branch (`v2_chain || tip >= 1`) —
#   the O16A/D8 fix this scenario was always meant to witness. It logs
#   `"WITNESS-BOOTSTRAP: state=DONE branch=HAVE_CHAIN tip=%lld ..."`
#   (`:519-523`, `fprintf(stderr, ...)`, confirmed reaching `nodus.log`
#   live). This scenario therefore keeps BOTH deltas, not one instead of
#   the other: the HAVE_CHAIN branch line (the original, still-accurate
#   assertion) AND the ABCI Handshake lines (D-23 rev 7/8's own
#   contribution, additional evidence the Handshaker specifically ran).
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
#   to, not truncated, so it holds two runs — every count below is a
#   BEFORE/AFTER delta for exactly that reason. The victim is node 4 —
#   FIXED, not derived: there is no leader and no epoch-rank concept on
#   this lane to derive one from, and this scenario is about identity and
#   replay across a restart, not about who happens to be proposing.
#
# R3 W3 (C2d) — WHAT FLIPPED, AND WHAT STAYED (DELTA 1 correction)
#   The chain is NOT frozen at genesis on this lane. CreateEmptyBlocks
#   means idle production continues on its own (60 000 ms interval,
#   nodus_witness_cmt_node.c:1700), so unlike the pre-Comet scenario this
#   replaces, THIS run can and does observe real block production
#   resuming after the restart — that is now a load-bearing assertion,
#   not an acknowledged gap. The legacy V2 role line
#   ("chain role: LEDGER V2") is gone; the version-3 line is
#   "chain role: COMETBFT" (nodus_witness.c:892-893).
#
#   The HAVE_CHAIN / DISCOVER bootstrap-branch check STAYS — it was
#   wrongly removed in the first cut of this package on the mistaken
#   premise that the bootstrap machine never runs on a version-3 chain.
#   It does run, and is deliberately routed into HAVE_CHAIN (see the
#   header above); the delta (`hc_after > hc_before`) is exactly as
#   satisfiable as it was on the pre-Comet lane. ADDED alongside it, not
#   instead of it: the ABCI Handshake's own lines, which name all three
#   heights it reconciled and are D-23's own contribution beyond what the
#   pre-Comet scenario could ever check.
#
# HOW IT CAN LIE
#   - **A restarted node still LISTENS even when its witness role fails.**
#     nodus keeps serving DHT traffic when the witness module refuses to
#     init, so a port check would pass on a node that votes on nothing.
#     The role line is read from the log for exactly that reason, and
#     every count is a BEFORE/AFTER delta — the line from the FIRST boot
#     is already in that file, so `grep -q` would be vacuously true.
#   - **The Handshaker log line proves reconciliation, not agreement.**
#     "ABCI replay blocks: app H, store H, state H" fires on EVERY start
#     including the very first one, so the assertion is a delta (a SECOND
#     occurrence after the restart), never presence. It says the node's
#     own three trackers agree with each other; it does not by itself say
#     the resulting height matches the fleet — the tip-advance and
#     stagef_diff checks below are what say that.
#   - **A missed handshake FAULT would abort the process, not print a
#     lie.** Every branch inside `hs_replay_blocks_with_context` that is
#     not a clean reconciliation returns CMT_FAULT and the node does not
#     start (nodus_cmt_node_start refuses); this scenario would then fail
#     on the "node never listened again" check, not silently pass.
#   - **DELTA 1 (item 4, CONFIRMED live and fixed) — "caught up and
#     producing again" used to require ZERO progress.** The catch-up wait
#     targeted a `fleet_tip` snapshot taken once; if the victim had
#     already reached or passed it by the time the wait started (routine
#     on a live cluster — mesh catch-up is fast), the wait returned
#     immediately and the stage passed having observed NOTHING new
#     (measured: "tip 29 -> 29, fleet was at 29"). Fixed with an explicit
#     SECOND wait for a height strictly past that snapshot, plus a
#     floor-strictly-greater-than-baseline check before the final diff —
#     a restart on a chain that has genuinely stopped producing is now
#     RED here.
#   - **DELTA 1 (verifier CLAIM 20 note) — the "never listened again"
#     wait (60 x 0.5 s) and the role-delta wait (30 x 1 s) are
#     ATTEMPT-bounded, not a single fixed timer deciding the verdict**:
#     each polls for a socket or a log line and dies if it never appears
#     within the bound, the same shape bring-up's own anti-vacuity loop
#     uses — not the `test_v2_partial_wipe.sh` `sleep 8` shape (fixed in
#     that script, DELTA 1 item 5) where one fixed sleep decided the
#     whole outcome.
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
stagef_cmt_diff_at_floor "pre-v2-restart" || exit 2

# R3 W3 (C2d) — a version-3 chain never writes a global_height=0 row
# (initial_height starts the real block sequence, and genesis is a
# STATE, not a stored block — nodus_v2_gen_config.c's own required-key
# message: "0 and 1 both start the chain at height 1 but are DIFFERENT
# chain ids"). Chain identity is read from the witness DB's own
# FILENAME instead: it embeds the first 16 bytes of the derived 32-byte
# chain id, in the SAME hex the join path writes
# (nodus_witness_v2_join.c's join_adopt: `witness_%s.db` over
# `chain32[0..15]`), so an unchanged filename after the restart is an
# unchanged chain identity — and nothing here can delete or rename that
# file (no wipe in this scenario), so this also catches an operator
# accident that touched the wrong node's directory.
chain_before=$(basename "$(db_of "$VICTIM")")
[ -n "$chain_before" ] || die "node$VICTIM has no chain DB before the kill"

vlog="$(stagef_node_dir "$VICTIM")/nodus.log"
role_before=$(grep -c 'chain role: COMETBFT' "$vlog" || true)
[ "$role_before" -ge 1 ] || die "node$VICTIM never reported the COMETBFT role before the kill"
hs_before=$(grep -c 'ABCI replay blocks:' "$vlog" || true)
[ "$hs_before" -ge 1 ] || die "node$VICTIM has no ABCI handshake line from its first boot — cannot take a delta"
# DELTA 1 (verifier CLAIM 12, restored) — the bootstrap machine DOES run
# on a version-3 chain and IS routed into HAVE_CHAIN
# (nodus_witness_bootstrap.c:457,480-482); this delta is exactly as
# satisfiable here as it always was on the pre-Comet lane.
hc_before=$(grep -c 'branch=HAVE_CHAIN' "$vlog" || true)
[ "$hc_before" -ge 1 ] || die "node$VICTIM never logged branch=HAVE_CHAIN on its first boot — cannot take a delta"
tip_before=$(stagef_cmt_tip "$(db_of "$VICTIM")")
echo "[ok] node$VICTIM baseline: chain_db=$chain_before role_lines=$role_before handshake_lines=$hs_before have_chain_lines=$hc_before tip=$tip_before"

# ── Kill ────────────────────────────────────────────────────────────
# The victim's own spawn line is reconstructed from stagef_env, not
# scraped from ps: a scraped command line would carry whatever the
# previous restart used and quietly drift.
vpid=$(pgrep -f "node$VICTIM/data" | head -1 || true)
[ -n "$vpid" ] || die "node$VICTIM is not running"
kill -9 "$vpid"
echo "[ok] node$VICTIM killed (pid $vpid)"
sleep 3

# The six survivors must still agree while it is down. Non-fatal by
# design: node$VICTIM's SQLite file was not closed cleanly (kill -9), so
# a stale WAL/SHM sidecar can make ITS OWN read racy even though this is
# a floor comparison — that residual is disclosed, not asserted away.
stagef_cmt_diff_at_floor "victim-down" >/dev/null 2>&1 || {
    echo "[info] state_root read failed with the victim down — a kill -9'd" >&2
    echo "       node's uncleanly-closed SQLite file can be transiently racy" >&2
    echo "       to open; this call is informational, not the assertion." >&2
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

# ── THE ASSERTIONS ──────────────────────────────────────────────────
# 1. It came back IN ITS WITNESS ROLE. A delta, not a presence check:
#    the line from the first boot is already in this file.
role_ok=0
for _ in $(seq 1 30); do
    role_after=$(grep -c 'chain role: COMETBFT' "$vlog" || true)
    [ "$role_after" -gt "$role_before" ] && { role_ok=1; break; }
    sleep 1
done
[ "$role_ok" = 1 ] || die \
  "node$VICTIM did NOT report the COMETBFT role after restart (before=$role_before after=$role_after)"
echo "[ok] node$VICTIM re-established the COMETBFT role ($role_before -> $role_after)"

# 2. AND IT TOOK THE HAVE_CHAIN BRANCH — DELTA 1 (verifier CLAIM 12):
#    restored, not removed. The bootstrap machine runs on a version-3
#    chain and is deliberately routed here (nodus_witness_bootstrap.c
#    :457,480-482). A BEFORE/AFTER delta, because the first boot already
#    logged one.
hc_after=$(grep -c 'branch=HAVE_CHAIN' "$vlog" || true)
[ "$hc_after" -gt "$hc_before" ] || die \
  "node$VICTIM did not take the HAVE_CHAIN branch after restart (before=$hc_before after=$hc_after)"
echo "[ok] node$VICTIM took the HAVE_CHAIN branch ($hc_before -> $hc_after)"

# 3. AND THE ABCI HANDSHAKE RAN AND RECONCILED — D-23's own contribution
#    beyond the HAVE_CHAIN check above: the reference's own Handshaker
#    (node.go:242-280, ported at nodus_witness_cmt_node.c:1090-1130) is
#    what proves the restarted node read its OWN ledger height correctly
#    rather than assuming a fresh chain. A BEFORE/AFTER delta, because
#    the first boot already logged one.
hs_after=$(grep -c 'ABCI replay blocks:' "$vlog" || true)
[ "$hs_after" -gt "$hs_before" ] || die \
  "node$VICTIM shows no NEW 'ABCI replay blocks:' line after restart (before=$hs_before after=$hs_after) — the Handshaker did not run, or the log capture missed it"
completed=$(grep -c 'completed ABCI handshake' "$vlog" || true)
[ "$completed" -ge 1 ] || die "node$VICTIM never logged 'completed ABCI handshake' — the reconciliation did not finish"
echo "[ok] node$VICTIM ran and completed the ABCI Handshake on restart ($hs_before -> $hs_after)"
echo "     $(grep 'ABCI replay blocks:' "$vlog" | tail -1)"

# 4. It refused nothing on the way up.
if grep -q 'REFUSING START' "$vlog"; then
    tail -20 "$vlog" >&2
    die "node$VICTIM logged REFUSING START"
fi

# 5. It is on the SAME chain — the same witness DB file was reopened,
#    never a different one adopted from a peer (this scenario never
#    passes --v2-genesis-pin, so the joiner path is not even armed; this
#    check is what proves that rather than assumes it).
chain_after=$(basename "$(db_of "$VICTIM")")
[ "$chain_after" = "$chain_before" ] || die \
  "node$VICTIM came back on a DIFFERENT chain file: $chain_before -> $chain_after"
echo "[ok] node$VICTIM reopened the same chain file ($chain_after)"

# 6. The partial-wipe marker is present. Nothing but a successful
#    nodus_server_init write could have put it there (nodus_server.c
#    :6233-6252), armed unconditionally on this restart the same as on
#    the first boot.
[ -f "$nd/data/.witness_db_seen" ] || die \
  "node$VICTIM has no .witness_db_seen after a successful start — the partial-wipe gate is disarmed on this node"
echo "[ok] partial-wipe marker present after restart"

# 7. PRODUCTION RESUMED — load-bearing on this lane, unlike the
#    pre-Comet scenario this replaces: CreateEmptyBlocks means the tip
#    keeps advancing on its own, so the restarted node must catch up to
#    the fleet AND KEEP PRODUCING AFTERWARDS, not merely sit at the
#    height it had when killed or at whatever the fleet happened to be
#    at the instant this check started.
#
#    DELTA 1 (item 4, CONFIRMED live) — the FIRST cut of this stage
#    waited only for the victim to reach a `fleet_tip` snapshot taken
#    once; on a live cluster the victim had often ALREADY reached or
#    passed that snapshot by the time the wait started (mesh catch-up is
#    fast), so the wait returned IMMEDIATELY and "producing again" was
#    asserted with ZERO required progress (measured: "tip 29 -> 29,
#    fleet was at 29" — a vacuous pass). Fixed with an EXPLICIT second
#    wait for a height STRICTLY PAST that snapshot, so this stage cannot
#    pass without observing the victim actually commit something NEW
#    after rejoining — a restart on a chain that has stopped producing
#    is now RED here, not merely unproven.
fleet_tip=$(stagef_cmt_tip "$ref_db")
vt=$(stagef_cmt_wait_height "$(db_of "$VICTIM")" "$fleet_tip" 3) \
    || die "node$VICTIM did not catch up to the fleet tip $fleet_tip (stuck at $vt) — it came back on the right chain but stopped voting on it"
[ "$vt" -ge "$tip_before" ] || die "node$VICTIM's tip REGRESSED after restart ($tip_before -> $vt)"
echo "[ok] node$VICTIM caught up to the fleet's snapshot tip (tip $tip_before -> $vt, fleet was at $fleet_tip)"

vt2=$(stagef_cmt_wait_height "$(db_of "$VICTIM")" "$(( fleet_tip + 1 ))" 3) \
    || die "node$VICTIM caught up to $vt but then produced NOTHING further (stuck at $vt2) — catching up once is not the same as still producing"
echo "[ok] node$VICTIM is STILL producing past the catch-up point (tip -> $vt2)"

# 8. Everyone still agrees, AND the agreed floor is STRICTLY PAST the
#    pre-kill baseline — the post-diff must not silently compare the
#    same pre-kill height back to itself.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$vt2" 2 >/dev/null \
        || die "node$n never reached height $vt2 (mesh replication stalled)"
done
post_floor=-1 first=1
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    h=$(stagef_cmt_tip "$(stagef_node_chain_db "$n")")
    [ -z "$h" ] && h=-1
    if [ "$first" = 1 ]; then post_floor="$h"; first=0
    elif [ "$h" -lt "$post_floor" ]; then post_floor="$h"; fi
done
[ "$post_floor" -gt "$tip_before" ] || die \
  "the post-restart floor ($post_floor) is not strictly greater than the pre-kill baseline ($tip_before) — the chain did not demonstrably advance"
stagef_cmt_diff_at_floor "post-v2-restart" || exit 2
echo "[ok] post-restart floor $post_floor is strictly past the pre-kill baseline $tip_before"

echo ""
echo "[PASS] a Comet node was killed and restarted: it re-established its"
echo "       COMETBFT role, took the HAVE_CHAIN branch, ran the ABCI Handshake,"
echo "       reopened the SAME chain file, kept the partial-wipe marker, caught"
echo "       up to tip $vt2 and KEPT PRODUCING past it, and all $STAGEF_COMMITTEE_SIZE nodes agree"
echo "       on block identity at a height strictly past the pre-kill baseline."
