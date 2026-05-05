#!/usr/bin/env bash
#
# Stage F test — PR 3 / F3: C4 --cold-bootstrap operator escape.
#
# Verifies the C-2 cabal-bypass behavior of the --cold-bootstrap
# CLI flag. The flag's only direct observable effect is at
# handle_chain_q: a node that is in DISCOVER/FETCH_GENESIS state
# normally drops incoming w_chain_q (C-2 protection — two fresh
# nodes must not agree on a fictitious chain_id without operator
# intervention). With --cold-bootstrap, the node bypasses C-2 and
# logs "answered via --cold-bootstrap operator escape (C4); cabal
# protection bypassed". This is the operator-facing forensic log
# line that distinguishes a cold-DR seed from accidental cabal.
#
# Scenario:
#   1. Start with an active 7-node cluster (genesis already
#      committed via stagef_up.sh).
#   2. Kill nodes 1 and 7. Wipe both their data dirs.
#   3. Restart node 1 with --cold-bootstrap. It enters DISCOVER
#      (no chain).
#   4. Restart node 7 normally. It also enters DISCOVER (fresh,
#      no chain). Node 7 starts broadcasting w_chain_q.
#   5. Node 1 receives node 7's w_chain_q; is_cold=true triggers
#      the C-2 bypass log line.
#   6. Verify node 1's log contains the cabal-bypass message.
#   7. Restore: kill both, restart node 1 normally (no flag),
#      let both re-bootstrap to cluster tip.
#
# Coverage scope: this test verifies the LOG SIDE of cold-bootstrap
# — the bypass fires and is auditable. The downstream "cold node
# serves a synthetic chain_def" path is not implemented in this PR
# (the chain_tip_height < 1 short-circuit at line ~657 of
# nodus_witness_bootstrap.c returns before any response is sent
# even with bypass enabled). When that synthetic-cdb path lands,
# extend this test to also assert that fresh joiners receive a
# cdh agreed via the cold seed.
#
# Exit:
#   0  PASS — cabal-bypass log line observed
#   2  Phase failure (bypass log absent, or cluster restore failed)
#   1  setup error

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

COLD=1                    # node 1 — cold-bootstrap seed
JOINER=$STAGEF_COMMITTEE_SIZE   # node 7 — regular fresh joiner

COLD_DIR=$(stagef_node_dir "$COLD")
COLD_LOG="$COLD_DIR/nodus.log"
COLD_DATA="$COLD_DIR/data"
JOINER_DIR=$(stagef_node_dir "$JOINER")
JOINER_DATA="$JOINER_DIR/data"

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

wipe_data() {
    local data_path=$1
    rm -f "$data_path/witness_"*.db* \
          "$data_path/nodus.db" "$data_path/nodus.db-wal" "$data_path/nodus.db-shm" \
          "$data_path/channels.db" "$data_path/channels.db-wal" "$data_path/channels.db-shm" \
          "$data_path/.bootstrap_in_progress" "$data_path/.witness_db_seen" 2>/dev/null || true
}

ORIG_COLD_PID=$(sed -n "${COLD}p" "$BASE_DIR/pids.txt")
ORIG_JOINER_PID=$(sed -n "${JOINER}p" "$BASE_DIR/pids.txt")

# ── Phase A: kill + wipe both, restart node 1 with cold flag ──
echo "== Phase A: prep cold seed (node$COLD) and fresh joiner (node$JOINER) =="
kill_pid "$ORIG_COLD_PID"
kill_pid "$ORIG_JOINER_PID"
wipe_data "$COLD_DATA"
wipe_data "$JOINER_DATA"

# Snapshot cold log size so the bypass-line grep is scoped.
PRE_COLD_LOG_SIZE=$(stat -c%s "$COLD_LOG" 2>/dev/null || echo 0)

COLD_PID=$(respawn "$COLD" "--cold-bootstrap")
echo "[ok] node$COLD respawned pid=$COLD_PID with --cold-bootstrap"

JOINER_PID=$(respawn "$JOINER")
echo "[ok] node$JOINER respawned pid=$JOINER_PID (fresh, no flag)"

# ── Phase B: wait for cabal-bypass log on node 1 ──
echo "== Phase B: wait for cabal-bypass log on node$COLD =="
# Node $JOINER must come up, auth to peers, broadcast w_chain_q.
# Node $COLD must receive it and log the bypass message. Allow up
# to 60 s for the full handshake + first bootstrap_tick.
bypass_seen=0
for _ in $(seq 1 120); do
    if tail -c +"$((PRE_COLD_LOG_SIZE + 1))" "$COLD_LOG" 2>/dev/null \
            | grep -q "answered via --cold-bootstrap operator escape"; then
        bypass_seen=1
        break
    fi
    sleep 0.5
done

if [ "$bypass_seen" -ne 1 ]; then
    echo "[FAIL] cabal-bypass log line never appeared on node$COLD" >&2
    echo "  last 30 lines of $COLD_LOG (since respawn):" >&2
    tail -c +"$((PRE_COLD_LOG_SIZE + 1))" "$COLD_LOG" | tail -30 >&2 || true
    kill_pid "$COLD_PID"
    kill_pid "$JOINER_PID"
    exit 2
fi
echo "[ok] cabal-bypass log line observed on node$COLD"

# ── Phase C: restore — kill both, restart without cold flag ──
echo "== Phase C: restore both nodes to healthy bootstrapped state =="
kill_pid "$COLD_PID"
kill_pid "$JOINER_PID"
wipe_data "$COLD_DATA"
wipe_data "$JOINER_DATA"

RESTORE_COLD_PID=$(respawn "$COLD")
RESTORE_JOINER_PID=$(respawn "$JOINER")

# Wait for both to catch up to cluster tip.
PRE_TIP=$(sqlite3 "$(stagef_node_chain_db 2)" \
    "SELECT COALESCE(MAX(height), 0) FROM blocks;" 2>/dev/null || echo 0)
deadline=$(( SECONDS + 90 ))
for n in $COLD $JOINER; do
    caught=0
    while [ $SECONDS -lt $deadline ]; do
        db=$(stagef_node_chain_db "$n")
        if [ -n "$db" ]; then
            h=$(sqlite3 "$db" \
                "SELECT COALESCE(MAX(height), 0) FROM blocks;" 2>/dev/null || echo 0)
            if [ "$h" -ge "$PRE_TIP" ]; then caught=1; break; fi
        fi
        sleep 1
    done
    if [ "$caught" -ne 1 ]; then
        echo "[FAIL] node$n could not re-join cluster after restore" >&2
        exit 2
    fi
done

if ! bash "$(dirname "$0")/../stagef_diff.sh" "post-cold-dr-restore"; then
    exit 2
fi

# Update pids.txt so stagef_down.sh kills the right PIDs.
sed -i "${COLD}s/.*/$RESTORE_COLD_PID/" "$BASE_DIR/pids.txt"
sed -i "${JOINER}s/.*/$RESTORE_JOINER_PID/" "$BASE_DIR/pids.txt"

echo ""
echo "[PASS] C4 --cold-bootstrap cabal-bypass — operator escape log " \
     "observed on cold seed when fresh joiner sent w_chain_q; cluster " \
     "restored 7/7 identical."
