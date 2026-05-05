#!/usr/bin/env bash
#
# Stage F test — PR 3 / F4: H-9 mixed-version cluster fail-fast.
#
# Verifies that a fresh node entering DISCOVER detects any peer
# reporting an older nodus_version and exits with code 3 ("MIXED
# VERSION CLUSTER DETECTED"), forcing the operator to finish the
# rolling deploy before bringing fresh nodes online.
#
# Implementation: the dev-only --mock-nodus-version=N CLI flag
# (shipped in this PR alongside this test) lets one node advertise
# a forged older version in its w_ident. We:
#   1. Stop node 1 from the live cluster.
#   2. Restart node 1 with --mock-nodus-version=0x000100 (= 0.1.0,
#      definitely older than any real shipped version).
#   3. Wait for node 1 to re-join the mesh and exchange ident with
#      surviving peers — they store its forged remote_nodus_version.
#   4. Wipe node 7's data directory (forces fresh-bootstrap path).
#   5. Restart node 7 normally.
#   6. Expect node 7 to enter DISCOVER, detect node 1's "older"
#      version on the next bootstrap_tick, log "MIXED VERSION
#      CLUSTER DETECTED", and exit(3).
#   7. Restore: restart node 1 without the mock flag and
#      re-bootstrap node 7 cleanly.
#
# Exit:
#   0  PASS — node 7 exited 3 with the expected log line
#   2  Phase failure (node 7 didn't exit 3, or wrong log)
#   3  cluster restore failed
#   1  setup error

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

TARGET=$STAGEF_COMMITTEE_SIZE   # node 7 — the fresh bootstrapper
FAKE_OLD=1                      # node 1 — pretends to be old version
TARGET_DIR=$(stagef_node_dir "$TARGET")
TARGET_LOG="$TARGET_DIR/nodus.log"
TARGET_DATA="$TARGET_DIR/data"
FAKE_OLD_DIR=$(stagef_node_dir "$FAKE_OLD")
FAKE_OLD_LOG="$FAKE_OLD_DIR/nodus.log"

SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done

respawn() {
    local n=$1
    local node_dir=$(stagef_node_dir "$n")
    local extra_arg="${2:-}"
    # shellcheck disable=SC2086
    "$STAGEF_NODUS_BIN" \
        -c "$BASE_DIR/nodus.json" \
        -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" \
        -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" \
        -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$node_dir/identity" \
        -d "$node_dir/data" \
        $extra_arg \
        $SEEDS \
        >> "$node_dir/nodus.log" 2>&1 &
    echo $!
}

kill_pid() {
    local pid=$1
    if [ -z "$pid" ] || [ "$pid" -le 0 ] 2>/dev/null; then return 0; fi
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

ORIG_TARGET_PID=$(sed -n "${TARGET}p" "$BASE_DIR/pids.txt")
ORIG_FAKEOLD_PID=$(sed -n "${FAKE_OLD}p" "$BASE_DIR/pids.txt")

# ── 1. Stop node 1, restart with mock-version=0x000100 ──
echo "== Phase A: restart node$FAKE_OLD with --mock-nodus-version=0x000100 =="
kill_pid "$ORIG_FAKEOLD_PID"
FAKE_PID=$(respawn "$FAKE_OLD" "--mock-nodus-version=0x000100")
echo "[ok] node$FAKE_OLD respawned pid=$FAKE_PID with mock version 0.1.0"

# Wait for fake-old to log its mock-version banner.
for _ in $(seq 1 20); do
    if grep -q "mock nodus_version active" "$FAKE_OLD_LOG"; then break; fi
    sleep 0.5
done
if ! grep -q "mock nodus_version active" "$FAKE_OLD_LOG"; then
    echo "[FAIL] node$FAKE_OLD did not log mock-version banner" >&2
    kill_pid "$FAKE_PID"; respawn "$FAKE_OLD" >/dev/null
    exit 2
fi

# Allow ident exchange to propagate to other nodes.
sleep 5

# ── 2. Wipe node 7, restart fresh ──
echo "== Phase B: wipe node$TARGET, restart, expect H-9 exit(3) =="
kill_pid "$ORIG_TARGET_PID"
rm -f "$TARGET_DATA/witness_"*.db* \
      "$TARGET_DATA/nodus.db" "$TARGET_DATA/nodus.db-wal" "$TARGET_DATA/nodus.db-shm" \
      "$TARGET_DATA/channels.db" "$TARGET_DATA/channels.db-wal" "$TARGET_DATA/channels.db-shm" \
      "$TARGET_DATA/.bootstrap_in_progress" "$TARGET_DATA/.witness_db_seen" 2>/dev/null || true

# Snapshot pre-respawn log size for grep scoping.
PRE_LOG_SIZE=$(stat -c%s "$TARGET_LOG" 2>/dev/null || echo 0)

T_PID=$(respawn "$TARGET")

# H-9 exits with code 3 on the first DISCOVER tick that sees an
# older peer. The process self-terminates via exit(3); we observe
# the side-effects: (a) process gone, (b) log line emitted with
# "Exiting with code 3 (H-9)" verbatim. Trying to read the exit
# code through `wait` is racy: the shell may have already reaped
# the child by the time we get here, returning 127 ("not a child").
# Log + process-gone is sufficient and unambiguous.
exited=0
for _ in $(seq 1 60); do
    if ! kill -0 "$T_PID" 2>/dev/null; then
        exited=1
        break
    fi
    sleep 0.5
done

if [ "$exited" -ne 1 ]; then
    echo "[FAIL] node$TARGET still running after 30s — H-9 did not fire" >&2
    kill_pid "$T_PID"
    kill_pid "$FAKE_PID"; respawn "$FAKE_OLD" >/dev/null
    exit 2
fi

# Log line must mention MIXED VERSION CLUSTER and "code 3 (H-9)".
NEW_LOG=$(tail -c +"$((PRE_LOG_SIZE + 1))" "$TARGET_LOG")
if ! echo "$NEW_LOG" | grep -q "MIXED VERSION CLUSTER DETECTED"; then
    echo "[FAIL] node$TARGET exited but no MIXED VERSION log line" >&2
    echo "$NEW_LOG" | head -20 >&2 || true
    kill_pid "$FAKE_PID"; respawn "$FAKE_OLD" >/dev/null
    exit 2
fi
if ! echo "$NEW_LOG" | grep -q "Exiting with code 3 (H-9)"; then
    echo "[FAIL] MIXED VERSION line found but no 'Exiting with code 3' tag" >&2
    kill_pid "$FAKE_PID"; respawn "$FAKE_OLD" >/dev/null
    exit 2
fi

echo "[ok] node$TARGET correctly exited via H-9 with MIXED VERSION log"

# ── 3. Restore: kill fake-old, restart without mock; bootstrap node 7 ──
echo "== Restore: revert node$FAKE_OLD to real version, rebuild node$TARGET =="
kill_pid "$FAKE_PID"
RESTORE_FAKEOLD_PID=$(respawn "$FAKE_OLD")

# Wait for node 1 to be reachable again.
for _ in $(seq 1 30); do
    if ss -lt 2>/dev/null \
            | grep -Eq ":$(stagef_tcp_port "$FAKE_OLD")\\b"; then
        break
    fi
    sleep 0.5
done

# Re-bootstrap node 7 (data still wiped from above).
RESTORE_TARGET_PID=$(respawn "$TARGET")

# Wait for node 7 to catch up to cluster tip.
PRE_TIP=$(sqlite3 "$(stagef_node_chain_db 2)" \
    "SELECT COALESCE(MAX(height), 0) FROM blocks;" 2>/dev/null || echo 0)
deadline=$(( SECONDS + 60 ))
caught_up=0
while [ $SECONDS -lt $deadline ]; do
    db=$(stagef_node_chain_db "$TARGET")
    if [ -n "$db" ]; then
        h=$(sqlite3 "$db" \
            "SELECT COALESCE(MAX(height), 0) FROM blocks;" 2>/dev/null || echo 0)
        if [ "$h" -ge "$PRE_TIP" ]; then caught_up=1; break; fi
    fi
    sleep 1
done

if [ "$caught_up" -ne 1 ]; then
    echo "[FAIL] node$TARGET could not re-join cluster after restore" >&2
    exit 3
fi

if ! bash "$(dirname "$0")/../stagef_diff.sh" "post-mixed-version-restore"; then
    exit 3
fi

# Update pids.txt so stagef_down.sh kills the right PIDs.
sed -i "${FAKE_OLD}s/.*/$RESTORE_FAKEOLD_PID/" "$BASE_DIR/pids.txt"
sed -i "${TARGET}s/.*/$RESTORE_TARGET_PID/" "$BASE_DIR/pids.txt"

echo ""
echo "[PASS] H-9 mixed-version cluster fail-fast — fresh node correctly " \
     "detected an older peer and exited 3; cluster restored 7/7 identical."
