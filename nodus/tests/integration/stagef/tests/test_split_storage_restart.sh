#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_split_storage_restart.sh — nodus-storage dies and comes back
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES (split S5b; decision docs/plans/decisions/2026-10-01-
# nodus-component-split.md items 5, 17, 27, 31, 32, 34)
#   On a storage-split node (core = nodus-server --storage-external with
#   its witness in-process, DHT = nodus-storage):
#   1. Through the core, a DHT put + get works (the storage IPC carries a
#      client request and its reply).
#   2. kill -9 of nodus-storage leaves the core — and so its in-process
#      witness — running: the process stays alive and the node's chain
#      keeps committing (its own Comet tip passes the height it had).
#   3. While storage is down a client DHT request is answered AT ONCE with
#      the decision-31 error ("PUT error: [21] storage module not
#      available") — not a timeout (nodus-cli waits 5 s and then prints
#      "No response to PUT"; that output FAILS this scenario).
#   4. Restarted, nodus-storage is found again by the core: the control
#      connection comes back (a new "control connection to nodus-storage
#      up" line) and the routing snapshot is re-pushed on it (a new
#      "routing snapshot from nodus-storage" line — logged on the first
#      snapshot of every control connection), and a new put + get through
#      the core work again.
#   The property that would be false if it failed: *storage is a separate
#   failure domain — its death costs DHT service only, is reported to
#   clients at once, and its return needs no core restart.*
#
# WHAT IT REQUIRES
#   Compile flags: NONE (a default nodus/build: nodus-server, nodus-storage,
#   nodus-cli from ONE build).
#   Environment: a cluster brought up by stagef_up_v2.sh in STAGEF_MODE
#   `splits` or `mixeds` (README "Harness modes"); in any other mode no
#   node is storage-split and it exits 99 (SKIP — coverage that did not
#   happen). STAGEF_NODUSCLI_BIN executable (put / get).
#   ⚠ Not runnable until tools/nodus_node_config.c parses
#   `--storage-external` (S5b report): before that a storage-split mode
#   cannot even come up.
#
# WHAT IT LEAVES BEHIND
#   The victim node's nodus-storage killed and restarted under a NEW pid,
#   appended to pids.txt so stagef_down.sh reaps it; its storage.log is
#   appended to (two runs), so every log assertion here is a BEFORE/AFTER
#   count delta. Two short-lived DHT values (random keys, 7-day TTL) on
#   the victim's storage and their replicas. Client sessions of the victim
#   node that had done a DHT request were closed when storage died
#   (decision 32) — clients reconnect; nodus-cli is per-call anyway.
#
# HOW IT CAN LIE
#   - **"At once" is read from the CLI's output, not a clock.** nodus-cli
#     prints "No response to PUT" after its 5 s wait when nothing answers;
#     the decision-31 text can only come from the core's immediate answer.
#     It does NOT prove the answer took no network round trip — only that
#     the core answered instead of storage.
#   - **The error is checked only once the core has SEEN storage go**
#     (a new "control connection to nodus-storage lost" line,
#     attempt-bounded). A request racing the kill could reach a storage
#     that is still half-alive; this scenario does not test that window.
#   - **"Chain keeps committing" is the victim's OWN tip passing its
#     pre-kill height** (stagef_cmt_wait_height, progress-bounded). In
#     `splits` / `mixeds` the witness runs inside the core process, so a
#     live core is the witness; that is what this shows, nothing about a
#     three-process node (S6).
#   - **The put after the restart proves storage serves again, not that
#     its pre-kill state survived** — the first value is read back too
#     (it is in nodus.db), but a value the dead process had only in memory
#     would not be.
#   - **rc=99 is a SKIP** (no storage-split node in this mode), never a
#     pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

die() { echo "[FAIL] $*" >&2; exit 1; }

VICTIM=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    if stagef_node_is_storage_split "$n"; then VICTIM="$n"; break; fi
done
if [ -z "$VICTIM" ]; then
    echo "[SKIP] $(stagef_mode): no storage-split node — this scenario needs STAGEF_MODE=splits or mixeds"
    exit 99
fi
[ -x "$STAGEF_NODUSCLI_BIN" ] || { echo "[SKIP] no nodus-cli at $STAGEF_NODUSCLI_BIN"; exit 99; }

nd=$(stagef_node_dir "$VICTIM")
clog="$nd/nodus.log"
port=$(stagef_tcp_port "$VICTIM")
db=$(stagef_node_chain_db "$VICTIM")
[ -n "$db" ] || die "node$VICTIM has no chain database"

cli() { "$STAGEF_NODUSCLI_BIN" -s 127.0.0.1 -p "$port" "$@" 2>&1 || true; }

# The core: the process naming node$VICTIM/data whose executable is
# STAGEF_NODUS_BIN (never the storage process, same data directory).
core_pid() {
    local want pid
    want="$(readlink -f "$STAGEF_NODUS_BIN" 2>/dev/null || echo "$STAGEF_NODUS_BIN")"
    for pid in $(pgrep -f -- "node$VICTIM/data( |\$)" || true); do
        if [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$want" ]; then
            echo "$pid"; return 0
        fi
    done
    return 1
}

stagef_sentinel SETUP_OK

cpid=$(core_pid) || die "node$VICTIM's nodus-server is not running"
spid=$(stagef_node_storage_pid "$VICTIM") || die "node$VICTIM's nodus-storage is not running"
echo "[ok] node$VICTIM: core pid=$cpid storage pid=$spid"

# ── 1. DHT through the core ─────────────────────────────────────────
k1="s5b-before-$$-$RANDOM"
out=$(cli put "$k1" "v-before")
echo "$out" | grep -q 'PUT ok' || die "put before the kill failed: $out"
out=$(cli get "$k1")
echo "$out" | grep -q 'Value: v-before' || die "get before the kill failed: $out"
echo "[ok] put + get through the core before the kill"

lost0=$(grep -c 'control connection to nodus-storage lost' "$clog" || true)
up0=$(grep -c 'control connection to nodus-storage up' "$clog" || true)
rt0=$(grep -c 'routing snapshot from nodus-storage' "$clog" || true)
tip0=$(stagef_cmt_tip "$db")

# ── 2. kill storage ─────────────────────────────────────────────────
kill -9 "$spid"
echo "[ok] node$VICTIM's nodus-storage killed (pid $spid)"
seen=0
for _ in $(seq 1 40); do
    lost=$(grep -c 'control connection to nodus-storage lost' "$clog" || true)
    [ "$lost" -gt "$lost0" ] && { seen=1; break; }
    sleep 0.25
done
[ "$seen" = 1 ] || die "the core never noticed nodus-storage was gone"
kill -0 "$cpid" 2>/dev/null || die "the core died with its storage"

# ── 3. decision 31: the error, at once ──────────────────────────────
out=$(cli put "s5b-down-$$" "v-down")
echo "$out" | grep -q 'PUT error: \[21\] storage module not available' || \
    die "a put with storage down did not get the decision-31 error: $out"
echo "[ok] put with storage down: decision-31 error from the core"

# The witness (in the core) keeps committing.
h=$(stagef_cmt_wait_height "$db" $(( tip0 + 1 )) 3) || \
    die "node$VICTIM's chain stopped with storage down (stuck at $h, was $tip0)"
echo "[ok] node$VICTIM kept committing with storage down (tip $tip0 -> $h)"
kill -0 "$cpid" 2>/dev/null || die "the core died while storage was down"

# ── 4. restart storage ──────────────────────────────────────────────
nspid=$(stagef_spawn_storage "$VICTIM")
echo "$nspid" >> "$BASE_DIR/pids.txt"
echo "[ok] node$VICTIM's nodus-storage restarted (pid $nspid)"

back=0
for _ in $(seq 1 60); do
    up=$(grep -c 'control connection to nodus-storage up' "$clog" || true)
    rt=$(grep -c 'routing snapshot from nodus-storage' "$clog" || true)
    if [ "$up" -gt "$up0" ] && [ "$rt" -gt "$rt0" ]; then back=1; break; fi
    sleep 0.5
done
[ "$back" = 1 ] || die "the core did not reconnect / get a re-pushed routing snapshot (up $up0 -> ${up:-?}, routing $rt0 -> ${rt:-?})"
echo "[ok] control connection back and routing snapshot re-pushed"

stagef_sentinel ASSERT_RUN
k2="s5b-after-$$-$RANDOM"
out=$(cli put "$k2" "v-after")
echo "$out" | grep -q 'PUT ok' || die "put after the restart failed: $out"
out=$(cli get "$k2")
echo "$out" | grep -q 'Value: v-after' || die "get after the restart failed: $out"
out=$(cli get "$k1")
echo "$out" | grep -q 'Value: v-before' || die "the value stored before the kill is gone: $out"
kill -0 "$cpid" 2>/dev/null || die "the core is not the one that was running before"
echo "[ok] put + get through the core after the restart; the earlier value survived"

stagef_sentinel PASS
echo "[PASS] storage stop/start on node$VICTIM"
