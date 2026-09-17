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
#   (that legacy scenario was deleted with the legacy lane in R3 W4)
#   That scenario RESTORED the victim by letting it re-bootstrap from
#   peers, which is the legacy recovery path and does not exist on V2 —
#   it fails at its restore step on a V2 cluster, which is what sent this
#   work here in the first place. Recovery here is the V2 one: wipe
#   everything and rejoin on the genesis pin.
#
# R3 W3 (C2d) — THE GATE ITSELF DID NOT MOVE
#   `nodus_server_check_partial_wipe` (nodus_server.c:5700-5796) and the
#   marker write after a successful open
#   (nodus_server.c:6233-6252, gated only on `srv->witness &&
#   srv->witness->db`) are lane-agnostic: file presence and an open chain
#   handle, nothing about which consensus runs on it. Read for this
#   package and confirmed unchanged — this scenario's core mechanism
#   needed NO rewrite. What changed is the RESTORE step below: it is
#   still the pin-based join, but the joined node now comes up as a
#   COMETBFT witness, not a Ledger V2 one, and the anti-vacuity check
#   added below reads for that role.
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
#     asserts the SAME half-wiped directory now demonstrably BOOTS (the
#     TCP port actually accepts a connection, not merely "the process
#     did not exit") — which is what proves the refusals above came from
#     the marker being armed rather than from the missing file alone.
#   - **DELTA 1 (verifier UNCOVERED FINDING 5, fixed).** `try_boot` used
#     to decide the whole verdict off one fixed `sleep 8` — a gate that
#     refused correctly but later than 8 s read as "booted", and the
#     negative control's `!= "refused"` check would then misread that
#     late refusal as proof the gate was disarmed. Replaced with a
#     bounded 30 s POLL for either real outcome (the refusal line, or the
#     TCP port actually listening); the negative control now requires the
#     POSITIVE "booted" result specifically, not merely "anything but
#     refused".
#   - **The attempt-loop bounds elsewhere in this script (the restore's
#     rejoin wait) are LOG-LINE / height bounds, the same shape as
#     bring-up's own anti-vacuity loop — bounded by ATTEMPTS, not by a
#     single fixed sleep deciding a verdict. `try_boot`'s old `sleep 8`
#     was the one exception, and DELTA 1 above is what removed it.**
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
#
# DELTA 1 (verifier UNCOVERED FINDING 5, CONFIRMED) — a bare `sleep 8`
# used to decide the ENTIRE verdict: a gate that refuses correctly but
# takes longer than 8 s to print its line would read as "booted", and
# the negative control's `[ "$r" != "refused" ]` check would then read
# that late refusal as proof the gate was disarmed — a false GREEN in
# BOTH directions. Replaced with a bounded POLL (up to 30 s) for either
# real outcome: the refusal line appearing, or the TCP port actually
# accepting connections (not merely "the process is still alive", which
# a hung boot could satisfy without ever becoming a witness).
try_boot() {
    : > "$nd/boot.log"
    # shellcheck disable=SC2086
    "$STAGEF_NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$VICTIM")" -t "$(stagef_tcp_port "$VICTIM")" \
        -p "$(stagef_peer_port "$VICTIM")" -C "$(stagef_chan_port "$VICTIM")" \
        -W "$(stagef_witness_port "$VICTIM")" \
        -i "$nd/identity" -d "$data" $SEEDS \
        > "$nd/boot.log" 2>&1 &
    local bp=$! tcp result=""
    tcp=$(stagef_tcp_port "$VICTIM")
    for _ in $(seq 1 60); do
        if grep -q 'PARTIAL WIPE DETECTED' "$nd/boot.log"; then
            result="refused"; break
        fi
        if ss -lt 2>/dev/null | grep -Eq "[:.]${tcp}\\b"; then
            result="booted"; break
        fi
        if ! kill -0 "$bp" 2>/dev/null; then
            # ORCHESTRATOR (sweep 5): the refusal prints its line and exits
            # within the same half-second, so a poll that grepped BEFORE
            # the write and tested liveness AFTER the exit misclassified a
            # correct refusal as "died-other" (measured: boot.log held
            # "PARTIAL WIPE DETECTED … REFUSING START", verdict died-other).
            # Once the process is gone its log is final — read it once more
            # before deciding.
            if grep -q 'PARTIAL WIPE DETECTED' "$nd/boot.log"; then
                result="refused"; break
            fi
            result="died-other"; break
        fi
        sleep 0.5
    done
    kill -9 "$bp" 2>/dev/null || true
    wait "$bp" 2>/dev/null || true
    echo "${result:-timeout}"
    return 0
}

stagef_cmt_diff_at_floor "pre-v2-partial-wipe" || exit 2
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
# DELTA 1 (finding 5) — requires the POSITIVE outcome "booted", not
# merely "not refused". A "timeout" or "died-other" result is NEITHER a
# refusal NOR proof the same directory boots — `!= "refused"` let either
# one through as if it were.
[ "$r" = "booted" ] || die \
  "the node did not demonstrably BOOT with no marker (result: '$r') — either it refused (the gate is firing for some other reason and the three results above prove nothing about it) or it neither refused nor came up listening within the bound"
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
# stagef_cmt_wait_height takes a fixed DB PATH; the victim has none until
# it adopts (stagef_node_chain_db globs for whatever witness_*.db exists
# right now, which is nothing before adoption), so this loop re-resolves
# the path on every poll instead of calling the helper once.
vt=-1
for _ in $(seq 1 180); do
    vdb=$(stagef_node_chain_db "$VICTIM")
    if [ -n "$vdb" ]; then
        vt=$(sqlite3 "$vdb" "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;" 2>/dev/null || echo -1)
        [ "$vt" -ge "$fleet_tip" ] && break
    fi
    sleep 1
done
[ "$vt" -ge "$fleet_tip" ] || die "node$VICTIM did not rejoin after the restore (tip $vt < fleet $fleet_tip)"
echo "[ok] node$VICTIM restored by rejoining on its pin (tip $vt)"

# ANTI-VACUITY: it must have come back as a COMETBFT witness, not merely
# a DHT-only process with a chain file on disk (nodus keeps serving DHT
# when the witness module never armed — stagef_up_v2.sh's own bring-up
# gate exists for exactly that reason; this restore path deserves no less).
role_ok=0 live_ok=0
for _ in $(seq 1 30); do
    if grep -q 'chain role: COMETBFT' "$nd/nodus.log"; then role_ok=1; fi
    if grep -q 'cometbft lane LIVE' "$nd/nodus.log"; then live_ok=1; fi
    if [ "$role_ok" = 1 ] && [ "$live_ok" = 1 ]; then break; fi
    sleep 1
done
[ "$role_ok" = 1 ] && [ "$live_ok" = 1 ] || die \
  "node$VICTIM adopted a chain but never reported COMETBFT role + lane LIVE (role=$role_ok live=$live_ok) — it may be up as a DHT-only process"
echo "[ok] node$VICTIM re-established the COMETBFT role and went LIVE"

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$vt" 2 >/dev/null \
        || die "node$n never reached height $vt (mesh replication stalled)"
done
stagef_cmt_diff_at_floor "post-v2-partial-wipe" || exit 2

echo ""
echo "[PASS] the H-10 boot gate is ARMED on a Ledger V2 node and refused all"
echo "       three single-file wipes; with the marker removed the same directory"
echo "       booted, which is what makes those three refusals mean something."
