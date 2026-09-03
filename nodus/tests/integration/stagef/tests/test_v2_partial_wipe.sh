#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_partial_wipe.sh — the H-10 boot gate, armed on a V2 chain
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a Ledger V2 node which has lost exactly ONE of its three SQLite
#   databases REFUSES TO START, instead of booting half-wiped. The
#   property that would be false if it failed: *an operator who deletes
#   one file by accident is stopped, not silently degraded.*
#
#   And, inseparably, that the marker which ARMS that gate is present on
#   a V2 node at all. It is not obvious that it would be: the marker is
#   written by nodus_server_init on a successful boot with a chain
#   (v0.19.37), and on a V2 chain nothing else can write it — the
#   derivation's own write lands in a scratch directory that is
#   discarded, and there is no genesis transaction to trigger the legacy
#   path. Before v0.19.37 a derived V2 node had NO marker, this gate was
#   disarmed on every one of them, and a half-wiped node booted happily
#   into the bootstrap state machine.
#
# WHY THIS IS NOT test_bootstrap_partial_wipe.sh WITH A DIFFERENT NAME
#   That scenario RESTORES the victim by letting it re-bootstrap from
#   peers, which is the legacy recovery path and does not exist on V2 —
#   it fails at its restore step on a V2 cluster, which is what sent this
#   work here in the first place. Recovery here is the V2 one: wipe
#   everything and rejoin on the genesis pin.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none. Needs $BASE_DIR/v2_genesis_pin for the restore,
#   which stagef_up_v2.sh writes.
#
# WHAT IT LEAVES BEHIND
#   Node 5 with a rebuilt data directory (wiped and re-adopted) under a
#   NEW pid, and a truncated nodus.log. Nothing else.
#
# HOW IT CAN LIE
#   - **"It did not come up" is not "the gate refused it".** A node can
#     fail to start for a dozen reasons. The assertion is the gate's own
#     line, `PARTIAL WIPE DETECTED`, in that boot's log — and the log is
#     truncated before each attempt so a line from an earlier attempt
#     cannot be counted.
#   - **All three files must be tried.** Removing only one of them would
#     leave two thirds of the gate unmeasured, and the three are found by
#     different code (two by name, the witness DB by a directory scan).
#   - **The marker's absence must be tried too, or the gate could be
#     passing for the wrong reason.** The scenario removes the marker and
#     asserts the SAME half-wiped directory now BOOTS — which is what
#     proves the refusals above came from the marker being armed rather
#     than from the missing file alone. Without that half, a node that
#     refused to start for any reason at all would read as a pass.
#   - **rc=99 means the cluster was not V2.** Coverage that did not
#     happen.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

VICTIM=5
REF=1
PINFILE="$BASE_DIR/v2_genesis_pin"

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -s "$PINFILE" ]; then
    echo "[SKIP] not a Ledger V2 cluster with a recorded genesis pin — use stagef_up_v2.sh"
    exit 99
fi

nd=$(stagef_node_dir "$VICTIM")
data="$nd/data"

# The marker is the precondition for everything below. On a V2 chain its
# presence IS the v0.19.37 server-side write — nothing else could have
# put it there.
[ -f "$data/.witness_db_seen" ] || die \
  "node$VICTIM has no .witness_db_seen, so the H-10 gate is DISARMED on it — this is the pre-v0.19.37 state and every refusal below would be untestable"
echo "[ok] the partial-wipe marker is present (the gate is armed)"

SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done

stop_victim() {
    local p; p=$(pgrep -f "nodus-server.*node$VICTIM/data" | head -1 || true)
    [ -n "$p" ] && { kill -9 "$p"; sleep 2; }
    return 0
}

# Start the victim and report whether the gate refused it. The log is
# TRUNCATED first: a `PARTIAL WIPE DETECTED` line from a previous attempt
# would otherwise make every later attempt look like a refusal.
try_boot() {
    : > "$nd/boot.log"
    # shellcheck disable=SC2086
    "$STAGEF_NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$VICTIM")" -t "$(stagef_tcp_port "$VICTIM")" \
        -p "$(stagef_peer_port "$VICTIM")" -C "$(stagef_chan_port "$VICTIM")" \
        -W "$(stagef_witness_port "$VICTIM")" \
        -i "$nd/identity" -d "$data" $SEEDS \
        > "$nd/boot.log" 2>&1 &
    local bp=$!
    sleep 8
    if grep -q 'PARTIAL WIPE DETECTED' "$nd/boot.log"; then
        kill -9 "$bp" 2>/dev/null || true
        wait "$bp" 2>/dev/null || true
        echo "refused"; return 0
    fi
    # Not refused: is it actually up?
    if kill -0 "$bp" 2>/dev/null; then
        kill -9 "$bp" 2>/dev/null || true; wait "$bp" 2>/dev/null || true
        echo "booted"; return 0
    fi
    echo "died-other"; return 0
}

bash "$(dirname "$0")/../stagef_diff.sh" "pre-v2-partial-wipe" || exit 2
stop_victim

# ── Each of the three, one at a time ────────────────────────────────
# Found by different code: nodus.db and channels.db by name, the witness
# database by a directory scan for witness_*.db. Removing only one would
# leave two thirds of the gate unmeasured.
for target in nodus.db channels.db witness; do
    bak="$BASE_DIR/pw_backup_$target"
    rm -rf "$bak"; mkdir -p "$bak"
    if [ "$target" = "witness" ]; then
        mv "$data"/witness_*.db* "$bak"/ 2>/dev/null || die "no witness DB to move"
    else
        mv "$data/$target" "$bak"/ || die "no $target to move"
        mv "$data/$target"-wal "$bak"/ 2>/dev/null || true
        mv "$data/$target"-shm "$bak"/ 2>/dev/null || true
    fi

    r=$(try_boot)
    [ "$r" = "refused" ] || die \
      "with $target missing the node reported '$r', not a refusal — the H-10 gate did not fire and a half-wiped node would have booted"
    echo "[ok] $target missing -> REFUSING START"

    mv "$bak"/* "$data"/ 2>/dev/null || true
    rmdir "$bak" 2>/dev/null || true
done

# ── The other half: without the marker the SAME state must boot ─────
# This is what proves the three refusals came from an ARMED gate and not
# from the missing file on its own.
mv "$data/nodus.db" "$BASE_DIR/pw_probe_nodus.db"
mv "$data/.witness_db_seen" "$BASE_DIR/pw_probe_marker"
r=$(try_boot)
mv "$BASE_DIR/pw_probe_nodus.db" "$data/nodus.db"
mv "$BASE_DIR/pw_probe_marker" "$data/.witness_db_seen"
[ "$r" != "refused" ] || die \
  "the node refused even with NO marker — the gate is firing for some other reason and the three results above prove nothing about it"
echo "[ok] same half-wiped directory with NO marker -> boots ($r): the refusals above were the ARMED gate"

# ── Restore, the V2 way ─────────────────────────────────────────────
# Not by re-bootstrapping from peers — that is the legacy path and does
# not exist here. Wipe and rejoin on the pin.
stop_victim
rm -f "$data"/*.db "$data"/*.db-wal "$data"/*.db-shm \
      "$data/.witness_db_seen" "$data/.bootstrap_in_progress"
rm -rf "$data/archive"
: > "$nd/nodus.log"
PIN=$(cat "$PINFILE")
# shellcheck disable=SC2086
"$STAGEF_NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
    -u "$(stagef_udp_port "$VICTIM")" -t "$(stagef_tcp_port "$VICTIM")" \
    -p "$(stagef_peer_port "$VICTIM")" -C "$(stagef_chan_port "$VICTIM")" \
    -W "$(stagef_witness_port "$VICTIM")" --v2-genesis-pin "$PIN" \
    -i "$nd/identity" -d "$data" $SEEDS \
    >> "$nd/nodus.log" 2>&1 &
echo "$!" >> "$BASE_DIR/pids.txt"

fleet_tip=$(sqlite3 "$ref_db" "SELECT MAX(global_height) FROM v2_blocks;")
back=0
for _ in $(seq 1 180); do
    vt=$(sqlite3 "$(stagef_node_chain_db "$VICTIM")" \
         "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;" 2>/dev/null || echo -1)
    [ "$vt" -ge "$fleet_tip" ] && { back=1; break; }
    sleep 1
done
[ "$back" = 1 ] || die "node$VICTIM did not rejoin after the restore (tip $vt < fleet $fleet_tip)"
echo "[ok] node$VICTIM restored by rejoining on its pin (tip $vt)"

sleep 3
bash "$(dirname "$0")/../stagef_diff.sh" "post-v2-partial-wipe" || exit 2

echo ""
echo "[PASS] the H-10 boot gate is ARMED on a Ledger V2 node and refused all"
echo "       three single-file wipes; with the marker removed the same directory"
echo "       booted, which is what makes those three refusals mean something."
