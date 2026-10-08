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
#   `nodus_server_check_partial_wipe` (nodus_server.c) and the
#   marker write after a successful open (nodus_server.c, gated only on
#   `srv->chain && srv->chain->ops->chain_open(srv->chain)` since split
#   S1 — the in-process backend's chain_open is `w->db != NULL`,
#   nodus_chain_backend_inproc.c) are lane-agnostic: file presence and an open chain
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
#   which stagef_up_v2.sh writes. On a witness-split victim the
#   nodus-witness binary (STAGEF_NODUSWITNESS_BIN, the one the bring-up
#   used) must carry the witness gate (nodus-witness.c, 2026-10-08); an
#   older nodus-witness FAILS the witness refusal assertion, by design.
#
# SPLIT S6 — RUNS IN EVERY MODE
#   The gate's owner is the CORE (nodus_server_init_ex runs
#   nodus_server_check_partial_wipe first, in nodus-server and nodus-core
#   alike; decision 2026-10-01-nodus-component-split.md item 9), so
#   `try_boot` starts the victim's core ONLY — its core binary with the
#   mode's `--*-external` flags (stagef_core_cmd), never a bare
#   nodus-server, which on a split node's data directory would be a
#   combined server. Every other start / stop of the victim — the first
#   stop, the EXIT trap's restore, the final pin rejoin — uses
#   stagef_stop_node / stagef_spawn_node, i.e. ALL of the node's
#   processes: a nodus-witness or nodus-storage left running would hold
#   the very database files this scenario moves. It used to SKIP (99) on a
#   split victim.
#
# THE WITNESS GATE (operator ruling 2026-10-08, decision 2026-10-01-
# nodus-component-split.md "Canlıya alma öncesi iki OPEN maddenin kararı")
#   nodus-witness runs the SAME gate itself (tools/nodus-witness.c main,
#   right after its data-directory lock, before the network-file pin
#   check and before the chain database opens) and exits 1 on a half-wiped
#   directory — fail closed, instead of opening the surviving chain
#   database while core and nodus-storage refuse. On a WITNESS-SPLIT
#   victim (stagef_node_is_split: splitw, split) `try_boot_witness` starts
#   the victim's nodus-witness ALONE (stagef_spawn_witness — the bring-up's
#   argv; no core, no storage) on the same half-wiped directory:
#     - each of the three single-file wipes: the core refuses (try_boot,
#       as before) AND the witness refuses — its own new witness.log bytes
#       carry `PARTIAL WIPE DETECTED` (the gate's line; nodus-witness adds
#       its own `NODUS_WITNESS: PARTIAL WIPE DETECTED …` line after it);
#     - the negative control (nodus.db missing, marker removed): the
#       witness must demonstrably BOOT — a NEW `Nodus witness v… running`
#       line, printed only after witness init and its IPC listen — and it
#       runs BEFORE the core's control, because a booting core can
#       recreate nodus.db (nodus-server --witness-external opens it) and
#       arm the marker, after which the directory is no longer half-wiped.
#       After the witness attempt the scenario asserts nodus.db and the
#       marker are STILL absent (the witness creates neither: it does not
#       open nodus.db, and it writes the marker only when nodus.db and
#       channels.db exist — nodus-witness.c core_dbs_present).
#   Combined mode has no nodus-witness: the gate there is the combined
#   server's (try_boot). splits has no witness process either. In mixedw /
#   mixed node 5 is NOT a split node (STAGEF_MIX*_SPLIT_NODES=3), so those
#   modes run no witness attempt — see HOW IT CAN LIE.
#
# WHAT IT LEAVES BEHIND
#   Node 5 with a rebuilt data directory (wiped and re-adopted) under a
#   NEW pid (every process of it, in a split mode), and a truncated
#   nodus.log (and witness.log where its witness is split). On a
#   witness-split victim the try_boot_witness attempts append to its
#   witness.log, which the restore then truncates like the rest; their
#   SIGKILL leaves `nodus-witness.lock` and possibly a stale
#   `witness.sock` in the data directory (the restart re-locks the one and
#   re-creates the other; neither is a database the gate counts).
#   Node 5's boot.log (core attempts). Nothing else.
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
#   - **The witness gate is exercised ONLY on a witness-split victim
#     (splitw, split).** combined, splits, mixedw, mixeds and mixed (node 5
#     is combined or storage-only there) print `[info] … no nodus-witness
#     attempt` and PASS on the core path alone — the witness gate's
#     coverage did not happen in those runs.
#   - **The witness's "booted" is its running line, not a port.** A
#     nodus-witness alone opens no client TCP port; the positive outcome
#     is a NEW `Nodus witness v… running` line in the bytes witness.log
#     gained after that spawn (the bring-up's own signal and its 90 x 1 s
#     bound, stagef_spawn_node), never "the process is still alive". As in
#     try_boot, a process that died is judged on its final log, read once
#     more; and the attempt does not return until the SIGKILLed witness has
#     exited, so its data-directory lock cannot make the NEXT attempt die
#     as "held by another nodus-witness".
#   - **A witness attempt after a core attempt is meaningful only if the
#     core created nothing.** Before every witness refusal attempt the
#     scenario asserts the removed file is still absent (a refusing core
#     opens nothing); the negative control runs the witness FIRST and
#     asserts afterwards that nodus.db and the marker are still absent.
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
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

nd=$(stagef_node_dir "$VICTIM")
data="$nd/data"

# The marker is the precondition for everything below. On a V2 chain its
# presence IS the v0.19.37 server-side write — nothing else could have
# put it there.
[ -f "$data/.witness_db_seen" ] || die \
  "node$VICTIM has no .witness_db_seen, so the H-10 gate is DISARMED on it — this is the pre-v0.19.37 state and every refusal below would be untestable"
echo "[ok] the partial-wipe marker is present (the gate is armed)"

vlog=$(stagef_node_log "$VICTIM")   # the WITNESS lines: witness.log when split

# Every process of the victim (core, and nodus-witness / nodus-storage
# where the mode splits them), each found by its executable, waited for
# until all have exited. "Not running" (rc 1) is fine here: try_boot kills
# its own core-only process, and the trap may run after the victim is
# already down. A process that survives SIGKILL (rc 2) is not, and neither
# is a node that was not whole (rc 3: fewer or more processes than its
# mode runs — stagef_stop_node has still stopped every one it found, so
# the trap's restore never moves files under a live process).
# The 2 s pause after the exit is the pre-S6 script's post-kill sleep,
# kept so the timing relative to the peers is unchanged; it decides no
# verdict.
stop_victim() {
    local rc=0
    stagef_stop_node "$VICTIM" KILL || rc=$?
    [ "$rc" = 2 ] && return 1
    [ "$rc" = 3 ] && return 1
    [ "$rc" = 0 ] && sleep 2
    return 0
}

# ── R3 W4 package H: the victim is restored on EVERY exit ────────────
# Sweep 5 (2026-09-17) aborted this scenario mid-way with node5 stopped
# and one of its database files moved into a backup directory; the five
# scenarios after it then ran on SIX nodes and reported that as their
# own failure. Under `set -e` a `die` (or any failing command) leaves the
# victim exactly like that. This trap runs on a NON-ZERO exit only: it
# puts back whatever this scenario moved out of the victim's data
# directory (the per-target backups and the two marker-probe files) and
# restarts the victim from its now-intact directory — the ordinary
# restart `test_v2_restart_convergence.sh` performs, not the pin
# rejoin (nothing was wiped). It does NOT wait for the victim to catch
# up: the next scenario's own height waits do that. On a clean exit the
# scenario has already restored the victim itself (below) and this trap
# does nothing. `PW_DOWN` is raised at the first stop and cleared once
# the pin rejoin has been asserted.
PW_DOWN=0
pw_cleanup() {
    local rc=$?
    [ "$rc" -ne 0 ] || return 0
    [ "$PW_DOWN" -eq 1 ] || return 0
    echo "[cleanup] rc=$rc with node$VICTIM down — restoring its files and restarting it" >&2
    stop_victim || echo "[cleanup] stopping node$VICTIM failed (the [FAIL] line above) — restoring anyway" >&2
    for b in "$BASE_DIR"/pw_backup_*; do
        [ -d "$b" ] || continue
        mv "$b"/* "$data"/ 2>/dev/null || true
        rmdir "$b" 2>/dev/null || true
    done
    [ -f "$BASE_DIR/pw_probe_nodus.db" ] && mv "$BASE_DIR/pw_probe_nodus.db" "$data/nodus.db"
    [ -f "$BASE_DIR/pw_probe_marker" ]   && mv "$BASE_DIR/pw_probe_marker" "$data/.witness_db_seen"
    # The pin is passed on EVERY restart here: with a chain database
    # present it is inert (nodus_witness_v2_join_arm returns before
    # arming when `w->db` is open), and if the failure happened AFTER the
    # wipe below (the rejoin never completed) the directory is empty and
    # the pin is exactly what lets the victim adopt again. Every process
    # of the node (stagef_spawn_node; the pin goes to the witness's
    # process); every pid appended to pids.txt.
    if stagef_spawn_node "$VICTIM" --v2-genesis-pin "$(cat "$PINFILE")"; then
        echo "[cleanup] node$VICTIM restarted (pids $STAGEF_NODE_PIDS); the next scenario's height wait covers its catch-up" >&2
    else
        echo "[cleanup] node$VICTIM restarted (pids $STAGEF_NODE_PIDS) but did not come up (the [FAIL] line above)" >&2
    fi
}
trap pw_cleanup EXIT

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
#
# Split S6: the CORE only — the gate's owner (header). stagef_core_cmd
# gives the victim's core binary with the mode's flags; no nodus-witness or
# nodus-storage is started, so "booted" means the core passed the gate and
# listens.
try_boot() {
    : > "$nd/boot.log"
    stagef_core_cmd "$VICTIM" "$BASE_DIR/nodus.json"
    # shellcheck disable=SC2046
    "${STAGEF_CMD[@]}" $(stagef_seed_args) > "$nd/boot.log" 2>&1 &
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

# try_boot_witness — witness-split victim only (header, THE WITNESS GATE):
# start the victim's nodus-witness ALONE (stagef_spawn_witness: the
# bring-up's argv, appending to witness.log) and report whether the gate
# refused it. Only the bytes witness.log gains after this spawn are read
# (the _stagef_wait_up pattern: the file is appended to, and an earlier
# attempt's lines are still in it; process substitution, not a pipe into
# `grep -q`, because of pipefail). Outcomes, polled up to 90 x 1 s — the
# bring-up's own bound for the witness's running line (stagef_spawn_node):
#   refused    — `PARTIAL WIPE DETECTED` in the new bytes;
#   booted     — a new `Nodus witness v… running` line (printed after
#                witness init and the IPC listen, nodus-witness.c);
#   died-other — the process exited with neither line (its final log is
#                read once more first, as in try_boot);
#   timeout    — neither within the bound.
# The witness is then SIGKILLed and the function waits (30 x 0.5 s,
# stagef_stop_node's bound) until it has exited: its exclusive lock on
# nodus-witness.lock lives as long as the process, and a next attempt
# started under it would die as "held by another nodus-witness".
# "survived-kill" when it does not exit.
try_boot_witness() {
    local wlog off wp result="" gone=0
    wlog="$(stagef_node_witness_log "$VICTIM")"
    off=$(stat -c %s "$wlog" 2>/dev/null || echo 0)
    wp=$(stagef_spawn_witness "$VICTIM")
    for _ in $(seq 1 90); do
        if grep -q -- 'PARTIAL WIPE DETECTED' < <(tail -c +"$(( off + 1 ))" "$wlog" 2>/dev/null); then
            result="refused"; break
        fi
        if grep -q -- 'Nodus witness v.* running' < <(tail -c +"$(( off + 1 ))" "$wlog" 2>/dev/null); then
            result="booted"; break
        fi
        if _stagef_pid_gone "$wp"; then
            if grep -q -- 'PARTIAL WIPE DETECTED' < <(tail -c +"$(( off + 1 ))" "$wlog" 2>/dev/null); then
                result="refused"; break
            fi
            result="died-other"; break
        fi
        sleep 1
    done
    kill -9 "$wp" 2>/dev/null || true
    for _ in $(seq 1 30); do
        if _stagef_pid_gone "$wp"; then gone=1; break; fi
        sleep 0.5
    done
    [ "$gone" = 1 ] || result="survived-kill"
    echo "${result:-timeout}"
    return 0
}

# The removed file is still absent — a witness attempt after a core attempt
# is on the half-wiped directory only if the core created nothing.
target_absent() {
    if [ "$1" = "witness" ]; then
        ! compgen -G "$data/witness_*.db" >/dev/null
    else
        [ ! -e "$data/$1" ]
    fi
}

if stagef_node_is_split "$VICTIM"; then
    echo "[info] $(stagef_mode): node$VICTIM's witness is split — the gate is also asserted on its nodus-witness started alone"
else
    echo "[info] $(stagef_mode): node$VICTIM has no nodus-witness — no nodus-witness attempt; the witness gate is NOT covered by this run"
fi

stagef_cmt_diff_at_floor "pre-v2-partial-wipe" || exit 2
PW_DOWN=1   # from here on, an abnormal exit must put node$VICTIM back
stop_victim || die "stopping node$VICTIM failed (a process survived SIGKILL, or the node was not whole — the [FAIL] line above)"

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

    if stagef_node_is_split "$VICTIM"; then
        target_absent "$target" || die \
          "$target reappeared after the core's refused boot — the directory is no longer half-wiped, so a witness attempt now would prove nothing"
        r=$(try_boot_witness)
        [ "$r" = "refused" ] || die \
          "with $target missing node$VICTIM's nodus-witness (started alone) reported '$r', not a refusal — the witness runs no partial-wipe gate and would open the surviving chain database"
        echo "[ok] $target missing -> nodus-witness REFUSING START"
    fi

    mv "$bak"/* "$data"/ 2>/dev/null || true
    rmdir "$bak" 2>/dev/null || true
done

# ── The other half: without the marker the SAME state must boot ─────
# This is what proves the three refusals came from an ARMED gate and not
# from the missing file on its own.
mv "$data/nodus.db" "$BASE_DIR/pw_probe_nodus.db"
mv "$data/.witness_db_seen" "$BASE_DIR/pw_probe_marker"
# The witness's control FIRST (header): a booting core may recreate
# nodus.db and arm the marker, after which this is no longer the
# half-wiped, unarmed directory.
if stagef_node_is_split "$VICTIM"; then
    r=$(try_boot_witness)
    [ "$r" = "booted" ] || die \
      "node$VICTIM's nodus-witness did not demonstrably BOOT with no marker (result: '$r') — either it refused (its gate fires for some other reason and the witness refusals above prove nothing about it) or it printed no running line within the bound"
    [ ! -e "$data/nodus.db" ] && [ ! -e "$data/.witness_db_seen" ] || die \
      "nodus.db or the marker exists after the witness's control boot — the witness created one, so the core's control below would not run on the half-wiped, unarmed directory"
    echo "[ok] same half-wiped directory with NO marker -> nodus-witness boots ($r): its refusals above were the ARMED gate"
fi
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
stop_victim || die "stopping node$VICTIM failed (a process survived SIGKILL, or the node was not whole — the [FAIL] line above)"
rm -f "$data"/*.db "$data"/*.db-wal "$data"/*.db-shm \
      "$data/.witness_db_seen" "$data/.bootstrap_in_progress"
rm -rf "$data/archive"
: > "$nd/nodus.log"
[ "$vlog" = "$nd/nodus.log" ] || : > "$vlog"
PIN=$(cat "$PINFILE")
# Every process of the node; the pin goes to the witness's process.
stagef_spawn_node "$VICTIM" --v2-genesis-pin "$PIN" \
    || die "node$VICTIM did not come up after the restore (the [FAIL] line above names the process: core client port, nodus-witness or nodus-storage)"
echo "[ok] node$VICTIM restarted for the pin rejoin (pids $STAGEF_NODE_PIDS)"

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
PW_DOWN=0   # the victim is back on its own; the EXIT trap has nothing to do

# ANTI-VACUITY: it must have come back as a COMETBFT witness, not merely
# a DHT-only process with a chain file on disk (nodus keeps serving DHT
# when the witness module never armed — stagef_up_v2.sh's own bring-up
# gate exists for exactly that reason; this restore path deserves no less).
role_ok=0 live_ok=0
for _ in $(seq 1 30); do
    if grep -q 'chain role: COMETBFT' "$vlog"; then role_ok=1; fi
    if grep -q 'cometbft lane LIVE' "$vlog"; then live_ok=1; fi
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
stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-v2-partial-wipe" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] the H-10 boot gate is ARMED on a Ledger V2 node and refused all"
echo "       three single-file wipes; with the marker removed the same directory"
echo "       booted, which is what makes those three refusals mean something."
