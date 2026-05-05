#!/usr/bin/env bash
#
# Stage F test — PR 3 / F5: H-10 partial-wipe XOR boot gate (E5).
#
# Verifies that nodus_server_init refuses to start when the operator
# wipes exactly one of the 3 SQLite DBs (nodus.db, channels.db, the
# active witness_<hex>.db). End-to-end exercise of the
# nodus_server_check_partial_wipe() boot gate that runs BEFORE
# nodus_storage_open / nodus_channel_store_open auto-create the
# missing files and silently mask the wipe.
#
# Strategy:
#   For each of the 3 DBs, kill node $TARGET, wipe ONLY that file,
#   restart, expect the process to exit non-zero within a few seconds
#   AND emit the "PARTIAL WIPE DETECTED" log line. Restore by
#   wiping ALL 3 + re-running the bootstrap to a healthy state, so
#   subsequent harness tests see a 7-node cluster.
#
# Non-destructive to the other 6 nodes; node $TARGET ends in the same
# bootstrapped state F2 left it in.
#
# Exit:
#   0  PASS — all 3 single-file wipes correctly refused start
#   2  any partial-wipe scenario started successfully (boot gate FAIL)
#   3  cluster-restore failed (test ended in degraded state)
#   1  setup error

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

TARGET=$STAGEF_COMMITTEE_SIZE
TARGET_DIR=$(stagef_node_dir "$TARGET")
TARGET_LOG="$TARGET_DIR/nodus.log"
TARGET_DATA="$TARGET_DIR/data"

SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done

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

kill_pid() {
    local pid=$1
    # Defensive: kill 0 means "every process in the calling process
    # group", NOT "kill PID zero". Scenarios 2+3 pass "0" as the
    # placeholder for "no prior PID to kill" — that previously
    # SIGTERM'd the test runner. Reject 0 / empty / non-positive.
    if [ -z "$pid" ] || [ "$pid" -le 0 ] 2>/dev/null; then
        return 0
    fi
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "$pid" 2>/dev/null || return 0
            sleep 1
        done
        kill -9 "$pid" 2>/dev/null || true
        sleep 1
    fi
}

# Wipe ALL 3 DBs (resets to clean fresh state).
wipe_all_dbs() {
    rm -f "$TARGET_DATA/witness_"*.db \
          "$TARGET_DATA/witness_"*.db-wal \
          "$TARGET_DATA/witness_"*.db-shm \
          "$TARGET_DATA/nodus.db" \
          "$TARGET_DATA/nodus.db-wal" \
          "$TARGET_DATA/nodus.db-shm" \
          "$TARGET_DATA/channels.db" \
          "$TARGET_DATA/channels.db-wal" \
          "$TARGET_DATA/channels.db-shm" \
          "$TARGET_DATA/.bootstrap_in_progress" 2>/dev/null || true
}

# Read pids.txt[$TARGET] (post-F2 if it ran, original otherwise).
ORIG_PID=$(sed -n "${TARGET}p" "$BASE_DIR/pids.txt")
echo "[info] target node=$TARGET orig_pid=$ORIG_PID"

# Each scenario: keep 2 of 3 DBs, wipe one, restart, expect exit
# non-zero AND the H-10 log line. We drive 3 scenarios:
#   1. wipe nodus.db only       (keep channels + witness)
#   2. wipe channels.db only    (keep nodus + witness)
#   3. wipe witness_*.db only   (keep nodus + channels)
test_partial_wipe_one_db() {
    local label="$1"     # "nodus" / "channels" / "witness"
    local pre_pid=$2

    echo ""
    echo "== Scenario: wipe only $label.db, expect refuse-start =="

    # Bring node down + wipe everything to start from a known state.
    kill_pid "$pre_pid"
    wipe_all_dbs

    # Bring it up briefly so all 3 DBs get created via normal init,
    # then bring it down again — that gives us a healthy on-disk
    # snapshot of all 3 SQLite files to selectively wipe from.
    #
    # The seed wait must be at least as long as F2's 60 s budget: a
    # freshly-respawned node has to peer-auth all 6 partners, run
    # DISCOVER → quorum → FETCH_GENESIS, then sync block 1 from a
    # peer (witness_*.db only lands after the sync replay, since
    # the bootstrap path no longer writes a placeholder row). 30 s
    # was the original budget but is too tight when peer auth
    # contention is high; 60 s mirrors F2 and leaves comfortable
    # headroom on a developer laptop.
    local seed_pid
    seed_pid=$(respawn_target)
    # Wait for all 3 DB files to exist on disk.
    local all_present=0
    for _ in $(seq 1 60); do
        if [ -e "$TARGET_DATA/nodus.db" ] && \
           [ -e "$TARGET_DATA/channels.db" ] && \
           ls "$TARGET_DATA"/witness_*.db >/dev/null 2>&1; then
            all_present=1
            break
        fi
        sleep 1
    done
    if [ "$all_present" -ne 1 ]; then
        echo "[FAIL] could not seed all 3 DBs on node$TARGET" >&2
        kill_pid "$seed_pid"
        echo "$seed_pid"
        return 2
    fi
    kill_pid "$seed_pid"

    # Now wipe only the file under test (and its sidecars).
    case "$label" in
        nodus)
            rm -f "$TARGET_DATA/nodus.db" \
                  "$TARGET_DATA/nodus.db-wal" \
                  "$TARGET_DATA/nodus.db-shm" ;;
        channels)
            rm -f "$TARGET_DATA/channels.db" \
                  "$TARGET_DATA/channels.db-wal" \
                  "$TARGET_DATA/channels.db-shm" ;;
        witness)
            rm -f "$TARGET_DATA/witness_"*.db \
                  "$TARGET_DATA/witness_"*.db-wal \
                  "$TARGET_DATA/witness_"*.db-shm ;;
        *) echo "[FAIL] unknown label $label" >&2; return 1 ;;
    esac

    # Snapshot log size BEFORE the partial-wipe respawn so the grep
    # below only inspects log content emitted by the new attempt.
    local pre_log_size
    pre_log_size=$(stat -c%s "$TARGET_LOG" 2>/dev/null || echo 0)

    # Restart and expect immediate non-zero exit.
    local pid
    pid=$(respawn_target)
    # Boot-gate refusal happens in the early init path (before storage
    # opens). 5 s window is generous; in practice the process exits
    # within ~50 ms.
    local exited=0
    for _ in $(seq 1 20); do
        if ! kill -0 "$pid" 2>/dev/null; then
            exited=1
            break
        fi
        sleep 0.25
    done

    if [ "$exited" -ne 1 ]; then
        echo "[FAIL] node$TARGET stayed running after $label-only wipe; "\
"H-10 boot gate did not fire" >&2
        kill_pid "$pid"
        echo "$pid"
        return 2
    fi

    # The H-10 log line must appear in the new tail of the log.
    if ! tail -c +"$((pre_log_size + 1))" "$TARGET_LOG" \
            | grep -q "PARTIAL WIPE DETECTED"; then
        echo "[FAIL] $label-only wipe: process exited but no" \
             "PARTIAL WIPE DETECTED log line" >&2
        echo "  log tail since respawn:" >&2
        tail -c +"$((pre_log_size + 1))" "$TARGET_LOG" | head -20 >&2 || true
        echo "0"
        return 2
    fi

    echo "[ok] $label-only wipe correctly refused start (exit detected, "\
"log line present)" >&2
    echo "0"
    return 0
}

# Scenario 1: wipe nodus.db
result=$(test_partial_wipe_one_db "nodus" "$ORIG_PID") || {
    echo "$result" > /dev/null  # discard pid; failure already logged
    exit 2
}

# Scenarios 2 + 3 each start from a cleanly seeded state (handled
# inside test_partial_wipe_one_db) so the previous run's leftover
# does not contaminate.
result=$(test_partial_wipe_one_db "channels" "0") || exit 2
result=$(test_partial_wipe_one_db "witness" "0") || exit 2

# ── Restore: wipe ALL + bootstrap node$TARGET back into the cluster ──
echo ""
echo "== Restore node$TARGET to healthy bootstrapped state =="
wipe_all_dbs
RESTORE_PID=$(respawn_target)

# Wait for the bootstrap state machine to converge to the cluster tip.
PRE_TIP=$(sqlite3 "$(stagef_node_chain_db 1)" \
    "SELECT COALESCE(MAX(height), 0) FROM blocks;" 2>/dev/null || echo 0)
echo "[info] cluster tip (node1): $PRE_TIP — waiting node$TARGET to catch up"

deadline=$(( SECONDS + 60 ))
caught_up=0
while [ $SECONDS -lt $deadline ]; do
    db=$(stagef_node_chain_db "$TARGET")
    if [ -n "$db" ]; then
        h=$(sqlite3 "$db" \
            "SELECT COALESCE(MAX(height), 0) FROM blocks;" 2>/dev/null || echo 0)
        if [ "$h" -ge "$PRE_TIP" ]; then
            caught_up=1
            break
        fi
    fi
    sleep 1
done

if [ "$caught_up" -ne 1 ]; then
    echo "[FAIL] node$TARGET could not be restored to healthy state" >&2
    tail -30 "$TARGET_LOG" >&2 || true
    exit 3
fi

if ! bash "$(dirname "$0")/../stagef_diff.sh" "post-restore"; then
    exit 3
fi

# Update pids.txt so stagef_down.sh kills the new PID.
sed -i "${TARGET}s/.*/$RESTORE_PID/" "$BASE_DIR/pids.txt"

echo ""
echo "[PASS] H-10 partial-wipe XOR boot gate refused all 3 single-file" \
"wipes; cluster restored 7/7 identical state_root"
