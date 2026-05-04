#!/usr/bin/env bash
#
# Stage F test — PR 3 / F2: witness bootstrap join-live + orphan recovery.
#
# Two phases on a single 7-node cluster:
#
# Phase A (anti-EU-4 invariant):
#   1. Pick node 7, kill its PID, wipe its 3 SQLite DBs (keep identity).
#   2. Restart with the same nodus-server args.
#   3. Wait for bootstrap to complete (DISCOVER -> FETCH_GENESIS -> DONE)
#      and the existing sync_check + replay path to catch up.
#   4. Assert state_root identical 7/7 at the chain tip — proves the
#      bootstrap-rejoined node converged on the same chain history as
#      the 6 HAVE_CHAIN peers.
#
# Phase B (H-7 atomic-recovery + E0 startup orphan-sentinel cleanup):
#   1. Same node 7, kill again + wipe.
#   2. BEFORE restart: pre-create <data>/.bootstrap_in_progress and a
#      stub witness_<hex>.db (simulating a prior FETCH_GENESIS crash
#      after sentinel write but before atomic chain-DB commit).
#   3. Restart. The E0 orphan-sentinel boot gate MUST detect the
#      marker, archive the stub DB, clear the sentinel, and let
#      DISCOVER restart cleanly.
#   4. Verify the orphan-cleanup log line appears in nodus.log.
#   5. Wait for bootstrap, assert state_root identical 7/7 again.
#
# Requires an active Stage F harness (stagef_up.sh).
#
# Exit:
#   0  PASS — both phases converge with identical state_root 7/7
#   2  Phase A failure (regular rejoin)
#   3  Phase B failure (orphan-sentinel recovery)
#   1  setup error (no harness, missing files)

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

# Pick the last node — least likely to be the current leader and so
# least disruptive to in-flight rounds.
TARGET=$STAGEF_COMMITTEE_SIZE
TARGET_DIR=$(stagef_node_dir "$TARGET")
TARGET_LOG="$TARGET_DIR/nodus.log"

# Build the same SEEDS string stagef_up.sh used so the restarted
# node finds its peers via Kademlia.
SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done

# Spawn helper: starts node $TARGET with the original stagef_up.sh args.
# Returns the new PID via stdout; writes log to $TARGET_LOG.append-mode
# so we keep the prior crash trail for triage.
respawn_target() {
    # shellcheck disable=SC2086
    "$STAGEF_NODUS_BIN" \
        -c "$BASE_DIR/nodus.json" \
        -b 127.0.0.1 \
        -u "$(stagef_udp_port "$TARGET")" \
        -t "$(stagef_tcp_port "$TARGET")" \
        -p "$(stagef_peer_port "$TARGET")" \
        -C "$(stagef_chan_port "$TARGET")" \
        -W "$(stagef_witness_port "$TARGET")" \
        -i "$TARGET_DIR/identity" \
        -d "$TARGET_DIR/data" \
        $SEEDS \
        >> "$TARGET_LOG" 2>&1 &
    echo $!
}

# Read the leader's chain tip height; baseline for "node N caught up".
peer_tip_height() {
    local n=$1
    local db
    db=$(stagef_node_chain_db "$n")
    [ -z "$db" ] && { echo 0; return; }
    sqlite3 "$db" \
      "SELECT COALESCE(MAX(height), 0) FROM blocks;" 2>/dev/null || echo 0
}

# Wait for target node to catch up to expected_height (with timeout).
wait_target_caught_up() {
    local expected=$1
    local deadline=$(( SECONDS + 60 ))
    while [ $SECONDS -lt $deadline ]; do
        local h
        h=$(peer_tip_height "$TARGET")
        if [ "$h" -ge "$expected" ]; then
            echo "[ok] node$TARGET caught up: tip=$h (expected >= $expected)"
            return 0
        fi
        sleep 1
    done
    local last
    last=$(peer_tip_height "$TARGET")
    echo "[FAIL] node$TARGET did not catch up within 60 s "\
"(tip=$last expected >= $expected)" >&2
    echo "  last 30 log lines from $TARGET_LOG:" >&2
    tail -30 "$TARGET_LOG" >&2 || true
    return 1
}

# Kill target node by reading its current PID from a tracked file.
# We track separately from pids.txt because the node will be restarted
# multiple times in this test and pids.txt is owned by stagef_up.sh.
kill_target() {
    local pid=$1
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        # Wait up to 5 s for graceful exit, then SIGKILL.
        for _ in 1 2 3 4 5; do
            if ! kill -0 "$pid" 2>/dev/null; then
                return 0
            fi
            sleep 1
        done
        kill -9 "$pid" 2>/dev/null || true
        sleep 1
    fi
}

# Wipe the 3 DB files but keep identity intact.
wipe_target_data() {
    rm -f "$TARGET_DIR/data/witness_"*.db \
          "$TARGET_DIR/data/witness_"*.db-wal \
          "$TARGET_DIR/data/witness_"*.db-shm \
          "$TARGET_DIR/data/nodus.db" \
          "$TARGET_DIR/data/nodus.db-wal" \
          "$TARGET_DIR/data/nodus.db-shm" \
          "$TARGET_DIR/data/channels.db" \
          "$TARGET_DIR/data/channels.db-wal" \
          "$TARGET_DIR/data/channels.db-shm" \
          "$TARGET_DIR/data/.bootstrap_in_progress" \
          "$TARGET_DIR/data/.recovery_in_progress" 2>/dev/null || true
    # Leave identity/, archive/ alone. Identity must persist or peer
    # auth will reject the rejoiner; archive/ is forensic snapshot.
}

# Find the original PID for $TARGET in pids.txt (line $TARGET).
ORIG_PID=$(sed -n "${TARGET}p" "$BASE_DIR/pids.txt")
echo "[info] target node=$TARGET orig_pid=$ORIG_PID data=$TARGET_DIR/data"

# ─── Baseline: state_root must be identical before we touch anything ──
bash "$(dirname "$0")/../stagef_diff.sh" "baseline-pre-bootstrap-test"

# ============================================================
# Phase A — regular wipe + rejoin (anti-EU-4 invariant)
# ============================================================
echo ""
echo "== Phase A: wipe node$TARGET, restart, verify chain DB converges =="

PRE_TIP=$(peer_tip_height 1)
echo "[info] cluster tip (node1) before wipe: $PRE_TIP"

kill_target "$ORIG_PID"
wipe_target_data
echo "[ok] node$TARGET killed + data wiped (identity preserved)"

A_PID=$(respawn_target)
echo "[ok] node$TARGET respawned pid=$A_PID"

# After restart, target must:
#   1. detect no chain DB -> enter DISCOVER
#   2. send w_chain_q -> reach quorum -> FETCH_GENESIS
#   3. write chain DB -> sync_check + replay catches up to PRE_TIP+
# 60 s deadline covers DISCOVER round (5 s) + sync replay (~1 s/block
# at the small chain heights this harness produces).
if ! wait_target_caught_up "$PRE_TIP"; then
    kill_target "$A_PID"
    exit 2
fi

# State_root must be identical at the new tip.
if ! bash "$(dirname "$0")/../stagef_diff.sh" "phase-A-post-rejoin"; then
    kill_target "$A_PID"
    exit 2
fi

# Pick up some new blocks while node $TARGET participates so we
# reproduce the "bootstrapped node not just caught up but actively
# voting" path. Fund a throwaway user — the resulting send TX is
# committed by leader and replicated; if node$TARGET's chain is
# divergent the diff at the next stagef_diff will catch it.
sleep 6
bash "$(dirname "$0")/../stagef_diff.sh" "phase-A-after-new-blocks"

# ============================================================
# Phase B — H-7 atomic recovery via E0 orphan-sentinel cleanup
# ============================================================
echo ""
echo "== Phase B: simulate prior crashed FETCH_GENESIS, verify recovery =="

POST_A_TIP=$(peer_tip_height 1)
echo "[info] cluster tip before phase B: $POST_A_TIP"

kill_target "$A_PID"
wipe_target_data

# Simulate a prior crashed FETCH_GENESIS:
#   - sentinel file present (write side ran)
#   - stub witness_<hex>.db file exists (create_chain_db ran but
#     either the INSERT or the unlink never landed)
# E0 must detect both, archive the stub, clear the sentinel.
SENTINEL="$TARGET_DIR/data/.bootstrap_in_progress"
STUB_DB="$TARGET_DIR/data/witness_deadbeef00112233445566778899aabb.db"
touch "$SENTINEL"
echo "stub" > "$STUB_DB"
echo "[ok] simulated prior crash: sentinel + stub DB present"

# Snapshot log size BEFORE respawn so the grep below only inspects log
# content emitted by this Phase-B attempt — Phase A may have produced
# unrelated output, and a stale "orphan-sentinel cleanup complete"
# string from an earlier test run on this same node would otherwise
# false-positive.
PRE_B_LOG_SIZE=$(stat -c%s "$TARGET_LOG" 2>/dev/null || echo 0)

B_PID=$(respawn_target)
echo "[ok] node$TARGET respawned pid=$B_PID (post-crash recovery)"

# Verify the E0 cleanup log line appears within a few seconds.
for _ in $(seq 1 20); do
    if tail -c +"$((PRE_B_LOG_SIZE + 1))" "$TARGET_LOG" \
            | grep -q "ORPHAN BOOTSTRAP SENTINEL detected"; then
        break
    fi
    sleep 0.5
done
if ! tail -c +"$((PRE_B_LOG_SIZE + 1))" "$TARGET_LOG" \
        | grep -q "ORPHAN BOOTSTRAP SENTINEL detected"; then
    echo "[FAIL] orphan-sentinel cleanup log line never appeared" >&2
    tail -30 "$TARGET_LOG" >&2 || true
    kill_target "$B_PID"
    exit 3
fi
if ! tail -c +"$((PRE_B_LOG_SIZE + 1))" "$TARGET_LOG" \
        | grep -q "orphan-sentinel cleanup complete"; then
    echo "[FAIL] orphan-sentinel cleanup did not complete" >&2
    tail -30 "$TARGET_LOG" >&2 || true
    kill_target "$B_PID"
    exit 3
fi
# Sentinel must be cleared on disk; stub must be in archive/.
if [ -e "$SENTINEL" ]; then
    echo "[FAIL] sentinel still present at $SENTINEL after cleanup" >&2
    kill_target "$B_PID"
    exit 3
fi
if [ -e "$STUB_DB" ]; then
    echo "[FAIL] stub DB not archived at $STUB_DB" >&2
    kill_target "$B_PID"
    exit 3
fi
if ! ls "$TARGET_DIR/data/archive/"*"witness_deadbeef"* >/dev/null 2>&1; then
    echo "[FAIL] no archived stub DB found under $TARGET_DIR/data/archive/" >&2
    kill_target "$B_PID"
    exit 3
fi
echo "[ok] E0 orphan-sentinel cleanup verified (sentinel cleared, stub archived)"

# After cleanup, bootstrap must restart cleanly and catch up.
if ! wait_target_caught_up "$POST_A_TIP"; then
    kill_target "$B_PID"
    exit 3
fi

if ! bash "$(dirname "$0")/../stagef_diff.sh" "phase-B-post-recovery"; then
    kill_target "$B_PID"
    exit 3
fi

# Leave node$TARGET running so subsequent tests in genesis_protocol.sh
# see a healthy 7-node cluster. Update pids.txt so stagef_down.sh
# kills the new PID rather than the original (already dead).
sed -i "${TARGET}s/.*/$B_PID/" "$BASE_DIR/pids.txt"

echo ""
echo "[PASS] PR 3 / F2 bootstrap join-live + orphan recovery — both phases converged"
