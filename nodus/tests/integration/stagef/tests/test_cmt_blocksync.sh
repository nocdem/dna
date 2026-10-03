#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_blocksync.sh — a node that fell BEHIND catches up through the
# block sync reactor (channel 0x40), then joins consensus
# ════════════════════════════════════════════════════════════════════
#
# Decision: docs/plans/decisions/2026-09-29-blocksync-before-testnet.md
# (blocksync before testnet; wait_sync = blockSync, node.go:375).
# Port: shared/dnac/cmt_bsync_{msgs,pool,reactor}.c (blocksync/*.go @
# cometbft 709fd12b), wired in nodus_witness.c / nodus_witness_p2p.c.
#
# WHAT IT PROVES
#   That a validator stopped while the chain moves on by a DISTANCE of
#   STAGEF_BLOCKSYNC_DISTANCE blocks (default 20), then restarted on its
#   own data directory, catches up THROUGH BLOCK SYNC — its log shows the
#   node deciding blockSync = ON (it is not the only validator,
#   node.go:375) and then "block sync done at height H (N block(s)
#   synced) — consensus started" with N >= 1 and H >= the fleet target −
#   2 (IsCaughtUp stops at maxPeerHeight − 1, pool.go:220, and a block is
#   applied only once its successor's commit arrived, reactor.go:456-461)
#   — and only THEN joins consensus: it keeps producing past the fleet
#   tip it came back to, and all 7 agree on block identity and global
#   root at a floor strictly past its pre-stop tip. The property that
#   would be false if it failed: *a lagging node is brought to the chain
#   head by verified block transfer (VerifyCommitLight, reactor.go:496),
#   applied through the same executor consensus uses, and the state it
#   reaches is the fleet's state.*
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary WITH the blocksync
#   port (0x40); nodus-cli from the same tree when the pump is used.
#   Environment: STAGEF_BLOCKSYNC_DISTANCE (default 20, blocks) — how far
#   the fleet moves while the victim is down, CAPPED at
#   STAGEF_EPOCH_LENGTH/2 − 2 (5 at the short-epoch 15; see "THE RULE N
#   CAP" below) so the victim can miss Rule N's bar in at most one epoch
#   and is never retired. In the sweep (genesis_protocol_v2.sh) it runs
#   after test_v2_rewards.sh (a missed epoch could cost the victim its
#   accrual row there) and before test_cmt_rule_n_retire.sh (after it,
#   stopping node 4 could halt a set that has lost node 7). Optional
#   CLI-SPEND pump
#   (stagef_cmt_pump_ready: funder STAGEF_PUMP_FUNDER_NODE = 3, submitter
#   STAGEF_PUMP_SUBMIT_NODE = 1 — both must differ from the victim, node
#   4); without it the distance is covered by idle production at the
#   60 s CreateEmptyBlocksInterval, i.e. ~20 minutes at the default.
#   A cluster brought up by stagef_up_v2.sh (a version-3 chain); on
#   anything else it exits 99.
#
# SPLIT S6 — RUNS IN EVERY MODE
#   The victim is stopped with stagef_stop_node TERM (every process of
#   node 4 — core, and nodus-witness / nodus-storage where the mode splits
#   them — each found by its executable; SIGKILL after 15 s for any that
#   has not exited) and restarted with stagef_spawn_node. The block-sync
#   lines are read from stagef_node_log (witness.log when its witness is
#   split); `REFUSING START` from the core's nodus.log AND that log. It
#   used to SKIP (99) on a split victim.
#
# WHAT IT LEAVES BEHIND
#   Node 4 stopped (SIGTERM, SIGKILL after 15 s) and restarted under a NEW
#   pid (every process of it, in a split mode), appended to pids.txt; its
#   nodus.log (and witness.log where split) is APPENDED (every count is
#   a before/after delta). The chain >= STAGEF_BLOCKSYNC_DISTANCE blocks
#   further on. When pumped: node 3's genesis leaf claimed by the first
#   pump step (unless an earlier pump already did) and one fee per pump
#   step gone from node 3's single coin. Nothing wiped.
#
# HOW IT CAN LIE
#   - The blocksync evidence is two LOG LINES of this build
#     (nodus_witness.c: "block sync ON" at construction,
#     "block sync done at height" from the switch row). A build without
#     the port prints neither and this FAILS — never a false pass.
#     The synced COUNT N comes from the reactor's own counter; N >= 1
#     proves at least one block was applied by block sync, not that
#     every missing block was (the last one or two can arrive through
#     consensus after the switch — the reference's own shape).
#   - "State equal" is the harness's usual 7/7 block-id + global-root
#     comparison at a floor (stagef_cmt_diff_at_floor) — it covers the
#     victim like every other node.
#   - The DISTANCE is modest (20 by default): a long outage (thousands
#     of blocks) is not exercised; it is the same code path, but its
#     memory/time profile is not measured here.
#   - Only ONE node is behind, and it syncs from six up-to-date peers;
#     the bad-peer paths (a bad commit → stop + ban + redo) are unit-
#     tested only (test_cmt_bsync_reactor.c).
#   - The victim is restarted, never SIGSTOPped: block sync runs only at
#     start (reactor.go:132-146); a SIGSTOPped node resumes through
#     consensus gossip, which is test_cmt_dead_proposer.sh's subject.
#   - rc=99 means the cluster was not version-3 — coverage that did not
#     happen, not a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

VICTIM=4          # FIXED: neither the pump funder (3) nor its submit node (1)
REF=1
DIST="${STAGEF_BLOCKSYNC_DISTANCE:-20}"

die() { echo "[FAIL] $*" >&2; exit 1; }

db_of() { stagef_node_chain_db "$1"; }

case "$DIST" in ''|*[!0-9]*) die "STAGEF_BLOCKSYNC_DISTANCE must be a positive integer (got '$DIST')";; esac
# THE RULE N CAP (sweep safety). The victim signs nothing while it is
# down, and Rule N AUTO_RETIREs a validator below the 50 % bar for TWO
# consecutive epochs (README, test_cmt_rule_n_retire.sh). A contiguous
# gap of at most E/2 − 2 blocks (plus the one or two the restart and the
# sync themselves cost) can put at most ONE epoch below the bar, so the
# victim is never retired and the later sweep scenarios still see seven
# ACTIVE validators. At the shipped E = 720 the cap is 358 (the default
# 20 stands); at the short-epoch E = 15 it is 5.
DIST_CAP=$(( STAGEF_EPOCH_LENGTH / 2 - 2 ))
if [ "$DIST" -gt "$DIST_CAP" ]; then
    echo "[info] distance $DIST capped to $DIST_CAP (epoch length $STAGEF_EPOCH_LENGTH — Rule N cap)"
    DIST="$DIST_CAP"
fi
[ "$DIST" -ge 3 ] || die "the block-sync distance must be >= 3 (got $DIST; epoch length $STAGEF_EPOCH_LENGTH)"
[ "$VICTIM" != "$STAGEF_PUMP_FUNDER_NODE" ] && [ "$VICTIM" != "$STAGEF_PUMP_SUBMIT_NODE" ] \
    || die "the victim (node $VICTIM) is the pump's funder or submit node — change STAGEF_PUMP_*"

# ── Precondition: a version-3 cluster ───────────────────────────────
ref_db=$(db_of "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a version-3 cluster — bring it up with stagef_up_v2.sh"
    exit 99
fi
stagef_sentinel SETUP_OK

# ── Baseline ────────────────────────────────────────────────────────
stagef_cmt_diff_at_floor "pre-blocksync" || exit 2

vdb=$(db_of "$VICTIM")
[ -n "$vdb" ] || die "node$VICTIM has no chain DB"
chain_before=$(basename "$vdb")
vlog=$(stagef_node_log "$VICTIM")   # the WITNESS lines: witness.log when split
clog="$(stagef_node_dir "$VICTIM")/nodus.log"   # the core's (the partial-wipe gate)
on_before=$(grep -c 'block sync ON' "$vlog" || true)
done_before=$(grep -c 'block sync done at height' "$vlog" || true)
tip_before=$(stagef_cmt_tip "$vdb")
[ -n "$tip_before" ] || die "node$VICTIM has no tip"
echo "[ok] node$VICTIM baseline: tip=$tip_before blocksync_on_lines=$on_before blocksync_done_lines=$done_before"

# ── Stop the victim ─────────────────────────────────────────────────
# SIGTERM to every process of the node, waited for (30 x 0.5 s); any still
# alive is SIGKILLed (stagef_stop_node says so) and waited for again.
src=0; stagef_stop_node "$VICTIM" TERM || src=$?
[ "$src" != 1 ] || die "node$VICTIM is not running"
[ "$src" = 0 ] || die "node$VICTIM did not exit even after SIGKILL"
echo "[ok] node$VICTIM stopped (pids $STAGEF_STOPPED_PIDS)"

# ── Let the fleet move on by a DISTANCE in blocks ───────────────────
pace="idle production (CreateEmptyBlocksInterval)"
if stagef_cmt_pump_ready "$ref_db"; then
    pace="CLI-SPEND pump (node$STAGEF_PUMP_FUNDER_NODE funds, node$STAGEF_PUMP_SUBMIT_NODE submits)"
fi
echo "[ok] block driving: $pace"
target=$(( tip_before + DIST ))
reached=$(stagef_cmt_advance_to "$ref_db" "$target" 3) && arc=0 || arc=$?
[ "$arc" = 0 ] || die "the fleet did not reach height $target with node$VICTIM down (rc=$arc, tip $reached)"
echo "[ok] the fleet moved from $tip_before to $reached while node$VICTIM was down"

# ── Restart the victim on its own data directory ────────────────────
# Every process of the node in this mode, every pid appended to pids.txt;
# returns once the core's client port listens (60 x 0.5 s).
stagef_spawn_node "$VICTIM" \
    || die "node$VICTIM never listened again on $(stagef_tcp_port "$VICTIM")"
echo "[ok] node$VICTIM restarted (pids $STAGEF_NODE_PIDS)"
for lg in "$clog" "$vlog"; do
    if grep -q 'REFUSING START' "$lg"; then
        tail -20 "$lg" >&2
        die "node$VICTIM logged REFUSING START ($lg)"
    fi
done

# ── THE ASSERTIONS ──────────────────────────────────────────────────
# 1. blockSync was decided ON at construction (node.go:375). A delta.
on_ok=0
for _ in $(seq 1 30); do
    on_after=$(grep -c 'block sync ON' "$vlog" || true)
    [ "$on_after" -gt "$on_before" ] && { on_ok=1; break; }
    sleep 1
done
[ "$on_ok" = 1 ] || die "node$VICTIM never logged 'block sync ON' after the restart (before=$on_before) — blockSync was not decided, or the binary has no blocksync port"
echo "[ok] node$VICTIM decided blockSync = ON"

# 2. Block sync caught it up and switched to consensus. Progress-bounded:
#    the victim's own tip must keep moving while it has not switched —
#    a stall of 3 CreateEmptyBlocks intervals with no new done-line and no
#    tip movement FAILS (never a raised wall-clock budget).
last_tip=-1 since=0 poll_s=5
stall_polls=$(( (3 * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) + poll_s - 1) / poll_s ))
while :; do
    done_after=$(grep -c 'block sync done at height' "$vlog" || true)
    [ "$done_after" -gt "$done_before" ] && break
    t=$(stagef_cmt_tip "$(db_of "$VICTIM")")
    [ -n "$t" ] || t=-1
    if [ "$t" -gt "$last_tip" ]; then last_tip="$t"; since=0
    else since=$(( since + 1 )); fi
    [ "$since" -lt "$stall_polls" ] || die "node$VICTIM made no block-sync progress (tip $t) across 3 empty-block intervals and never switched to consensus"
    sleep "$poll_s"
done
line=$(grep 'block sync done at height' "$vlog" | tail -1)
echo "     $line"
synced_h=$(printf '%s\n' "$line" | sed -n 's/.*block sync done at height \([0-9]*\) (\([0-9]*\) block.*/\1/p')
synced_n=$(printf '%s\n' "$line" | sed -n 's/.*block sync done at height \([0-9]*\) (\([0-9]*\) block.*/\2/p')
[ -n "$synced_h" ] && [ -n "$synced_n" ] || die "could not parse the block-sync line: $line"
[ "$synced_n" -ge 1 ] || die "block sync switched with 0 blocks synced — the node was not caught up BY block sync"
[ "$synced_h" -ge $(( target - 2 )) ] || die "block sync switched at height $synced_h, below the fleet target $target − 2 (IsCaughtUp: maxPeerHeight − 1)"
echo "[ok] node$VICTIM block-synced $synced_n block(s) to height $synced_h (fleet target $target), then started consensus"

# 3. Same chain file (no adoption from a peer).
chain_after=$(basename "$(db_of "$VICTIM")")
[ "$chain_after" = "$chain_before" ] || die "node$VICTIM came back on a DIFFERENT chain file: $chain_before -> $chain_after"

# 4. It keeps producing past the fleet tip it came back to.
fleet_tip=$(stagef_cmt_tip "$ref_db")
vt=$(stagef_cmt_wait_height "$(db_of "$VICTIM")" "$(( fleet_tip + 1 ))" 3) \
    || die "node$VICTIM switched to consensus but produced nothing past the fleet tip $fleet_tip (stuck at $vt)"
echo "[ok] node$VICTIM is producing past the fleet tip it rejoined at ($fleet_tip -> $vt)"

# 5. 7/7 at a floor strictly past the pre-stop tip.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$vt" 2 >/dev/null \
        || die "node$n never reached height $vt"
done
post_floor=-1 first=1
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    h=$(stagef_cmt_tip "$(stagef_node_chain_db "$n")")
    [ -z "$h" ] && h=-1
    if [ "$first" = 1 ]; then post_floor="$h"; first=0
    elif [ "$h" -lt "$post_floor" ]; then post_floor="$h"; fi
done
[ "$post_floor" -ge "$target" ] || die "the post-sync floor ($post_floor) is below the distance target ($target)"
stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-blocksync" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] node$VICTIM, stopped at $tip_before while the fleet moved $DIST blocks,"
echo "       caught up by BLOCK SYNC ($synced_n block(s), to height $synced_h),"
echo "       switched to consensus, kept producing, and all $STAGEF_COMMITTEE_SIZE nodes"
echo "       agree at floor $post_floor (>= target $target)."
