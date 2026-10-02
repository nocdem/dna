#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_p2p_stopall_nowipe.sh — the 4004 p2p port ships as STOP-ALL,
# NO WIPE: a chain started on the old transport continues on the new
# one, and an old node cannot join the new mesh (standalone — NOT in the
# sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/decisions/2026-09-26-witness-port-
# session.md ("Deploy: zincir SİLİNMEZ" — block format unchanged, stop-all
# + protocol 7→8; "Ağ config dosyası (pin + seed'ler)"); design
# docs/plans/2026-09-26-p2p-port-design.md §6 test plan ("a stop-all
# no-wipe two-binary scenario"). Shape and helpers follow
# test_cmt_hf1_gas_upgrade.sh (two binaries, /proc/<pid>/exe checks,
# "Nodus v<X> running" lines, attempt-bounded role waits).
#
# WHAT IT PROVES — each item would be false if it failed
#   0. OLD is really old and NEW really new: OLD's -h does NOT list
#      --network-file, NEW's does; the -h banners' versions satisfy
#      OLD < NEW (sort -V). Printed, and a mismatch FAILs.
#   1. A chain started on the OLD binary (the 4004 T3 transport) commits,
#      7/7 agree, and it advances >= 2 heights before the stop.
#   1b. THE DANGEROUS PRECONDITION EXISTS AT THE STOP (P2P-FIX-1 E2;
#      decision 2026-09-26-cmt-wal-file-group.md DÜZELTME + item 6
#      AMENDED; red-team R5 F1). Right after a fresh commit at tip H is
#      seen, 3 of the 7 are SIGSTOPped (the idle chain's next proposal
#      waits create_empty_blocks_interval = 60 s, so the freeze lands
#      inside a window where nobody has signed at H+1 — and that is
#      CHECKED, not hoped: each frozen node's priv_validator_state.json
#      height <= H and its chain DB holds 0 `cmt_wal` MsgInfo (kind 2)
#      rows at H+1, else the attempt is discarded). The other 4 (4/7,
#      below cometbft's > 2/3) enter H+1 and sign; the script waits until
#      each of the 4 shows height H+1, step >= 2 (prevote) in its privval
#      file, prints height/round/step and whether the signed vote is for
#      a BLOCK or NIL (decoded from `signbytes`: the CanonicalVote's
#      field 4 present = block), and requires >= 1 kind-2 row at H+1 in
#      each signer's `cmt_wal`. THE DANGEROUS FORM is >= 3 BLOCK signers
#      (3 of 7 >= 1/3: the other four hold 4 of 7 < the 5 needed for
#      +2/3, so without them nothing can pass round 0). Which form an
#      attempt gets depends on whether the round-0 proposer of H+1 is
#      among the 4 — not readable from anywhere (cmt_cs.c logs no
#      proposer, v2_blocks has no proposer column) — so an attempt with
#      fewer than 3 block signers is resumed (SIGCONT, the chain commits
#      H+1) and repeated with the frozen trio rotated, at most 7
#      attempts. Then the stop: the 3 frozen are SIGKILLed and the 4
#      SIGTERMed in one loop (a stopped process cannot receive SIGTERM),
#      and every node's chain tip is asserted <= H — no commit at H+1
#      happened during the stop.
#   2. STOP-ALL: every node is stopped at once (item 1b's KILL/TERM
#      loop), every process exits and every client port is released — no
#      node keeps running the old transport while another starts the new
#      one.
#   3. NO WIPE: all 7 restart on NEW over the SAME data dirs, identities
#      and ports, with the network file (pin = the chain id bring-up
#      recorded, the seven "id@127.0.0.1:<witness port>" peers) through
#      nodus.json. Per node: the process IS the NEW binary
#      (/proc/<pid>/exe); a NEW "Nodus v<NEW> running" line; a NEW
#      "chain role: COMETBFT" and a NEW "completed ABCI handshake"; the
#      "p2p on … 7 persistent peer(s)" start line; no "REFUSING START"
#      (the network file's pin-at-start check passed against the chain
#      it holds); the SAME chain database file; and its tip, read right
#      after the restart, is >= its own pre-stop tip — no node started
#      over from genesis.
#   3b. THE CARRY-OVER RAN: each of the 4 signers logs a NEW
#      "consensus WAL carry-over:" line (nodus_cmt_wal_carry_sqlite —
#      its SQLite-era `cmt_wal` tail re-framed into <data>/cs.wal/wal
#      before NewWAL); the frozen 3's lines are printed (they carry too).
#      Item 4 then requires the chain to commit H+1 and move on — which
#      under item 1b's dangerous form it cannot do unless the 4 replay
#      their own signed messages.
#   4. THE 4004 MESH FORMS ON THE NEW STACK: EVERY node's own tip passes
#      the highest pre-stop tip + 3 (the only carrier of blocks between
#      nodes is 4004 — there is no blocksync and 4002 carries none), and
#      7/7 agree on global_root + block_id at a floor strictly past the
#      pre-stop maximum.
#   5. NEGATIVE CONTROL — an OLD node cannot join the NEW mesh: node 7 is
#      restarted on OLD (same data dir; its -s seeds make it dial the
#      others' witness ports with the old handshake). It comes up — NEW
#      role + LIVE lines, the process alive at the end of the window — and
#      its tip stays FROZEN while the six NEW nodes advance >= 5 heights
#      (6 of 7 is above cometbft's 2/3, so they must keep committing).
#   6. Recovery: node 7 restarted on NEW catches up to the fleet, the
#      chain advances >= 2 more, and 7/7 agree.
#   N. NEGATIVE CONTROL OF THE CARRY (opt-in, STAGEF_STOPALL_NEGATIVE=1;
#      NOT part of the default run; items 4-6 are not run): the same
#      precondition, but before NEW starts the `cmt_wal` rows of the 4
#      signers are deleted with the sqlite3 CLI (the carry then finds an
#      empty table and does nothing — what NEW without the carry would
#      do). Required form: >= 3 BLOCK signers, else SKIP 99. Expected,
#      and derived from the recorded privval state: the block signers
#      cannot sign anything at (H+1, 0) but that block (privval refuses a
#      step regression and conflicting data, cmt_privval.c; the block is
#      lost — none of the 4 has its WAL and the frozen 3 provably never
#      received it), the rest hold <= 4 of 7 < 5 (quorum = total*2/3 + 1,
#      shared/dnac/cmt_vote_set.c:509; `sum > total*2/3` :967 — equal
#      power assumed, as every stagef genesis), no +2/3-any ever forms,
#      no round timeout arms: every block signer logs a NEW "failed
#      signing vote: height H+1 round 0" line and the tip does not pass H
#      across 3 CreateEmptyBlocks intervals (stagef_cmt_wait_height's own
#      stall rule). A commit at H+1 FAILS the control. Deterministic in
#      that form; the NIL form (fewer than 3 block signers) is NOT
#      deterministic — whether a nil signer re-signs nil or refuses a new
#      proposal depends on whether that proposal reaches it before its
#      propose timeout — and is never asserted.
#
# WHAT IT REQUIRES
#   Compile flags: NONE beyond default builds, both halves of each pair:
#     OLD = a 0.19.80 build (the operator's main tree, pre-P2P-PORT),
#     NEW = this worktree's build (nodus 0.20.0+, the 4004 p2p port).
#     Both at the SAME epoch/grace constants (defaults are fine).
#   Environment (read by THIS script):
#     STAGEF_NODUS_BIN_OLD   the OLD nodus-server
#     STAGEF_NODUS_BIN_NEW   the NEW nodus-server
#     STAGEF_NODUSCLI_BIN    a NEW nodus-cli (its `whoami` prints
#                            "P2P ID:" — the network file's IDs come from
#                            it; the height pump uses it against NEW nodes
#                            only). Default: this tree's nodus/build.
#     STAGEF_STOPALL_NEGATIVE  unset/0 = the default run; 1 = item N
#                            instead of items 4-6.
#   Tools: sqlite3 (already required), sed (reads the privval files).
#   OLD must be the SQLite-WAL build (0.19.80: consensus WAL rows in the
#   chain DB's `cmt_wal` table) — item 1b reads those rows.
#   The cluster must be brought up on OLD (checked: every node's
#   /proc/<pid>/exe must be the OLD binary, else FAIL):
#     S=<this tree>/nodus/tests/integration/stagef
#     export STAGEF_NODUS_BIN_OLD=/opt/dna/nodus/build/nodus-server
#     export STAGEF_NODUS_BIN_NEW=<this tree>/nodus/build/nodus-server
#     STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD bash $S/stagef_up_v2.sh
#     bash $S/tests/test_p2p_stopall_nowipe.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   (stagef_up_v2.sh sees an OLD server — no --network-file in its -h —
#   and writes NO network file; the old nodes mesh through their -s seeds
#   as they always did. This script writes the file at the stop.)
#   SKIP (rc 99): a binary missing / not executable, OLD and NEW
#   byte-identical, or not a Comet cluster. A skip is not a pass.
#   FAIL (rc 1), not skip: the capability / version gate of item 0.
#   The script RUNS each server once with -h to read that banner.
#
# WHAT IT LEAVES BEHIND
#   All 7 nodes running NEW under new pids (appended to pids.txt; every
#   nodus.log appended — it holds the OLD run and the NEW one; node 7's
#   holds OLD, NEW, OLD again and NEW again). $BASE_DIR/network.json
#   written (pin = the chain id, the seven peers). Each node's data dir
#   additionally holds the NEW binary's p2p files (address book, own ADDR
#   sequence). When the height pump was usable: node 3's genesis leaf
#   claimed and one fee per pump step gone from it (stagef_env.sh
#   CLI-SPEND). Nothing is wiped. On a FAIL the nodes are left as they
#   were at the failure (node 7 possibly on OLD) — tear down. Item 1b:
#   up to 7 heights committed through a freeze/resume cycle each; an EXIT
#   trap SIGCONTs any node still frozen. Every node's data dir gains
#   `cs.wal/wal` (the carried tail); the SQLite `cmt_wal` rows stay.
#   NEGATIVE mode: the 4 signers' `cmt_wal` rows are DELETED, and the
#   chain is left HALTED at H on NEW (by design) — tear down; a SKIP 99
#   there (form not reached) leaves the cluster resumed on OLD.
#
# HOW IT CAN LIE
#   - **Heights before the stop are idle production** (60 s per block,
#     README "What flips" rule 1): the OLD phase submits nothing — the
#     NEW nodus-cli is never pointed at an OLD server. After the restart
#     stagef_cmt_advance_to pumps when the CLI-SPEND pump is usable
#     (printed by its "[ok] block driving:" line), idles otherwise.
#   - **"The mesh formed" is inferred from every node's OWN progress.**
#     The new stack logs no per-peer "added" line; the "persistent
#     peer(s)" line is config, not connection. A node's tip moving past
#     its pre-stop value is the evidence that it received blocks — over
#     4004, the only path. A node that caught up and then lost its peers
#     after the final floor read would not be seen.
#   - **"No genesis restart" = same chain file + tip never behind its own
#     pre-stop tip.** The tip is read from the chain database the restart
#     opens (v2_blocks), which a node starting over would not have.
#   - **The negative control uses ONE old node for >= 5 heights.** It
#     proves that node did not advance; the "connection rejected" lines
#     on the six are printed as evidence only, never asserted (which
#     check refuses the old handshake first is not pinned here). An old
#     node that could not even start would make "frozen" vacuous — hence
#     the NEW role + LIVE lines and the live process are REQUIRED.
#   - **One machine, 127.0.0.1**: allow_duplicate_ip / addr_book_strict
#     = false are HARNESS-ONLY settings (nodus.json) a production node
#     never carries.
#   - **Both binaries at the same compiled constants.** A pair built at
#     different epoch lengths would fail at open for a reason unrelated
#     to the transport.
#   - **Item 1b's dangerous form is searched for, not constructed.** Up to
#     7 freeze attempts, the trio rotated; if none produced >= 3 BLOCK
#     signers, the default run CONTINUES on the last attempt's (weaker,
#     NIL-majority) precondition and says so on a "[WARN] PRECONDITION"
#     line and in the final PASS line ("precondition: NIL form") — such a
#     PASS proves the carry on a restart after signing, NOT that the
#     carry prevented a halt. The negative mode SKIPs (99) instead.
#   - **Block vs nil is decoded from the privval `signbytes`** by the
#     CanonicalVote field layout (cmt_pb.c canonical_vote_wr: 1 type, 2
#     height, 3 round omitted at 0, 4 block_id only when not zero, 5
#     timestamp) — a layout change would print "unknown" and the attempt
#     counts no block signer.
#   - **The freeze proof is per attempt**: privval height <= H and no
#     kind-2 `cmt_wal` row at H+1 on each frozen node. A proposal that
#     reached a frozen node's socket buffer but was never read is not in
#     its WAL and dies with the SIGKILL — the negative control depends on
#     exactly that.
#   - **The idle freeze window replaces "keep the chain loaded"** (the
#     E2 dispatch asked for a pump during the freeze): a pumped chain
#     proposes H+1 ~4 s after committing H, which races the freeze; the
#     NEW nodus-cli is not pointed at OLD servers anyway. The 4 sign H+1
#     at the 60 s empty-block interval.
#   - **Item 3b reads a log line**; that the replay then carried the 4's
#     own votes is inferred from item 4 (H+1 committed), not observed.
#   - rc 99 = SKIP, coverage that did not happen.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# Split S3: stops, freezes and restarts EVERY node as one nodus-server
# process — SKIP (99) in any split mode (splitw, mixedw).
stagef_split_skip_if $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

OLD_SRV="${STAGEF_NODUS_BIN_OLD:-}"
NEW_SRV="${STAGEF_NODUS_BIN_NEW:-}"
CLI="$STAGEF_NODUSCLI_BIN"
N="$STAGEF_COMMITTEE_SIZE"
NEG="${STAGEF_STOPALL_NEGATIVE:-0}"
case "$NEG" in 0|1) ;; *) die "STAGEF_STOPALL_NEGATIVE must be 0 or 1 (got '$NEG')" ;; esac
[ "$N" = 7 ] || die "item 1b's arithmetic (3 frozen, 4 signing, >= 3 block signers) is written for 7 validators, got $N"
PRECOND_ATTEMPTS=7          # one per rotation of the frozen trio over the 7 nodes

# ── 0. binaries: present, different, OLD without / NEW with the p2p port ─
for b in "$OLD_SRV" "$NEW_SRV" "$CLI"; do
    if [ -z "$b" ] || [ ! -x "$b" ]; then
        echo "[SKIP] a binary is missing — set STAGEF_NODUS_BIN_OLD / STAGEF_NODUS_BIN_NEW (and STAGEF_NODUSCLI_BIN); got '$b'"
        exit 99
    fi
done
if cmp -s "$OLD_SRV" "$NEW_SRV"; then
    echo "[SKIP] OLD and NEW nodus-server are byte-identical — a stop-all onto the same binary proves nothing"
    exit 99
fi
banner_ver() { "$1" -h 2>&1 | awk '/^Nodus Server v/{sub(/^Nodus Server v/, ""); print; exit}'; }
OLD_VER=$(banner_ver "$OLD_SRV")
NEW_VER=$(banner_ver "$NEW_SRV")
[ -n "$OLD_VER" ] && [ -n "$NEW_VER" ] || die "could not read a 'Nodus Server v…' banner from both servers (OLD '$OLD_VER', NEW '$NEW_VER')"
if stagef_server_has_network_file "$OLD_SRV"; then
    die "OLD ($OLD_SRV, v$OLD_VER) already understands --network-file — it is not a pre-p2p-port build"
fi
stagef_server_has_network_file "$NEW_SRV" || die "NEW ($NEW_SRV, v$NEW_VER) has no --network-file — it is not a p2p-port build"
lowest=$(printf '%s\n%s\n' "$OLD_VER" "$NEW_VER" | sort -V | head -n 1)
[ "$lowest" = "$OLD_VER" ] && [ "$OLD_VER" != "$NEW_VER" ] || die "version order: OLD v$OLD_VER is not below NEW v$NEW_VER"
echo "[ok] OLD $OLD_SRV v$OLD_VER (no network file) → NEW $NEW_SRV v$NEW_VER (network file)"
stagef_p2p_id "$(stagef_node_dir 1)/identity" > /dev/null || die "the CLI $CLI prints no P2P ID — set STAGEF_NODUSCLI_BIN to a NEW nodus-cli"

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active Stage F run (bring one up with stagef_up_v2.sh on OLD)"
ref_db0=$(stagef_node_chain_db 1)
[ -n "$ref_db0" ] && [ -s "$ref_db0" ] || die "no chain DB for node1"
has_v2=$(sqlite3 "$ref_db0" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster — bring it up with stagef_up_v2.sh"
    exit 99
fi
[ -s "$BASE_DIR/v2_chain_id" ] || die "bring-up recorded no chain id ($BASE_DIR/v2_chain_id)"
CHAIN_ID=$(cat "$BASE_DIR/v2_chain_id")

# ── helpers (test_cmt_hf1_gas_upgrade.sh shapes) ────────────────────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { local t; t=$(stagef_cmt_tip "$(db_of "$1")"); echo "${t:--1}"; }
log_of() { echo "$(stagef_node_dir "$1")/nodus.log"; }
cnt()    { grep -c -- "$2" "$(log_of "$1")" 2>/dev/null || true; }

node_pid() {
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        case "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" in
            "$(readlink -f "$OLD_SRV")"|"$(readlink -f "$NEW_SRV")") echo "$pid"; return 0 ;;
        esac
    done
    return 0
}
node_runs() {
    local pid
    pid=$(node_pid "$1")
    [ -n "$pid" ] || return 1
    [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$2")" ]
}
listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}

# stop_nodes K... — SIGTERM to every listed node FIRST, then an
# attempt-bounded wait for each process and client port to go.
stop_nodes() {
    local k pid i
    local -a pids=()
    for k in "$@"; do
        pid=$(node_pid "$k")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid"; pids+=("$k:$pid")
        fi
    done
    for kp in "${pids[@]+"${pids[@]}"}"; do
        k=${kp%%:*}; pid=${kp#*:}
        for i in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
        ! kill -0 "$pid" 2>/dev/null || die "node$k (pid $pid) did not exit within 60 s of SIGTERM"
    done
    for k in "$@"; do
        for i in $(seq 1 60); do listening "$(stagef_tcp_port "$k")" || break; sleep 0.5; done
        ! listening "$(stagef_tcp_port "$k")" || die "node$k's client port is still bound after the stop"
    done
    echo "[ok] stopped (SIGTERM, all at once): nodes $*"
}

# start_node K BIN — stagef_up_v2.sh's spawn line (same identity, data,
# ports, -c nodus.json, -s seeds). The log is APPENDED.
start_node() {
    local k="$1" bin="$2" nd seeds="" n pid
    nd=$(stagef_node_dir "$k")
    for n in $(seq 1 "$N"); do seeds="$seeds -s 127.0.0.1:$(stagef_udp_port "$n")"; done
    # shellcheck disable=SC2086
    "$bin" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$k")" -t "$(stagef_tcp_port "$k")" \
        -p "$(stagef_peer_port "$k")" -C "$(stagef_chan_port "$k")" \
        -W "$(stagef_witness_port "$k")" \
        -i "$nd/identity" -d "$nd/data" $seeds \
        >> "$nd/nodus.log" 2>&1 &
    pid=$!
    echo "$pid" >> "$BASE_DIR/pids.txt"
}
wait_listening() {
    local i ok=0
    for i in $(seq 1 60); do if listening "$(stagef_tcp_port "$1")"; then ok=1; break; fi; sleep 0.5; done
    [ "$ok" = 1 ] || die "node$1 never listened on $(stagef_tcp_port "$1") after its start"
}
# wait_more K PATTERN BEFORE — attempt-bounded: node K's log gains a
# PATTERN line beyond the BEFORE count.
wait_more() {
    local i
    for i in $(seq 1 90); do
        [ "$(cnt "$1" "$2")" -gt "$3" ] && return 0
        sleep 1
    done
    return 1
}

# ── item 1b helpers: the privval file, the freeze ───────────────────
# The witness's data_path is <node>/data (the chain DB lives there,
# stagef_node_chain_db); nodus_witness.c writes
# <data_path>/priv_validator_state.json — the reference FilePVLastSignState
# as indented JSON: "height": "<n>" (quoted), "round": <n>, "step": <n>,
# "signbytes": "<UPPER HEX>" (nodus_witness_cmt_privval.c
# lss_encode_compact). Steps: 1 propose, 2 prevote, 3 precommit
# (cmt_privval.h CMT_STEP_*).
pv_path() { echo "$(stagef_node_dir "$1")/data/priv_validator_state.json"; }
pv_get() {
    local f v=""
    f=$(pv_path "$1")
    if [ -s "$f" ]; then
        case "$2" in
            height)    v=$(sed -n 's/.*"height": *"\(-\{0,1\}[0-9]*\)".*/\1/p' "$f" | head -n 1) ;;
            round)     v=$(sed -n 's/.*"round": *\(-\{0,1\}[0-9]*\).*/\1/p' "$f" | head -n 1) ;;
            step)      v=$(sed -n 's/.*"step": *\(-\{0,1\}[0-9]*\).*/\1/p' "$f" | head -n 1) ;;
            signbytes) v=$(sed -n 's/.*"signbytes": *"\([0-9A-Fa-f]*\)".*/\1/p' "$f" | head -n 1) ;;
        esac
    fi
    case "$2" in
        signbytes) echo "$v" ;;
        *) echo "${v:--1}" ;;
    esac
}
# pv_target HEX — block | nil | unknown, from a vote's sign bytes: the
# varint length prefix (cmt_pb_marshal_delimited), then CanonicalVote in
# field order (cmt_pb.c canonical_vote_wr): 08 <type>, 11 <8 B height>,
# 19 <8 B round> — omitted at round 0 (wf_sfixed64 skips 0) —, then 22
# = field 4 block_id (present only for a non-zero block id,
# cmt_canonical.c cmt_canonicalize_block_id) or 2A = field 5 timestamp
# (nil vote).
pv_target() {
    local h="$1" i=0 b n=0
    [ -n "$h" ] || { echo unknown; return 0; }
    while :; do
        [ -n "${h:i:2}" ] || { echo unknown; return 0; }
        b=$(( 16#${h:i:2} )); i=$(( i + 2 )); n=$(( n + 1 ))
        [ "$b" -lt 128 ] && break
        [ "$n" -lt 5 ] || { echo unknown; return 0; }
    done
    [ "${h:i:2}" = "08" ] || { echo unknown; return 0; }
    i=$(( i + 4 ))
    [ "${h:i:2}" = "11" ] && i=$(( i + 18 ))
    [ "${h:i:2}" = "19" ] && i=$(( i + 18 ))
    case "${h:i:2}" in
        22) echo block ;;
        2A|2a) echo nil ;;
        *) echo unknown ;;
    esac
}
pv_line() {
    local s t
    s=$(pv_get "$1" step)
    if [ "$s" = 1 ]; then t=proposal; else t=$(pv_target "$(pv_get "$1" signbytes)"); fi
    echo "height=$(pv_get "$1" height) round=$(pv_get "$1" round) step=$s vote=$t signbytes=$(pv_get "$1" signbytes | cut -c1-48)..."
}
# SQLite-era WAL rows (nodus 0.19.80: protocol_id 1; kind 2 = MsgInfo —
# a proposal, a block part or a vote, received or our own) at height H.
wal_msginfo_rows() {
    sqlite3 "$(db_of "$1")" \
        "SELECT COUNT(*) FROM cmt_wal WHERE protocol_id = 1 AND kind = 2 AND height = $2;" \
        2>/dev/null || echo -1
}

FROZEN=()                   # SIGSTOPped now — the EXIT trap resumes them
resume_frozen() {
    local k pid
    for k in "${FROZEN[@]+"${FROZEN[@]}"}"; do
        pid=$(node_pid "$k")
        [ -z "$pid" ] || kill -CONT "$pid" 2>/dev/null || true
    done
    FROZEN=()
}
trap resume_frozen EXIT

# wait_fresh_commit DB — prints DB's tip as soon as it moves past its
# value at the call (0.5 s polls, so the freeze lands well inside the
# 60 s idle window). Progress-bounded with stagef_cmt_wait_height's own
# rule: 3 CreateEmptyBlocks intervals with no increase = stall (rc 1).
wait_fresh_commit() {
    local db="$1" t0 t i polls
    polls=$(( 3 * STAGEF_CMT_EMPTY_INTERVAL_MS / 500 ))
    t0=$(stagef_cmt_tip "$db"); t=$t0
    for i in $(seq 1 "$polls"); do
        t=$(stagef_cmt_tip "$db")
        if [ "$t" -gt "$t0" ]; then echo "$t"; return 0; fi
        sleep 0.5
    done
    echo "$t"
    return 1
}

# wait_signed H K... — until every listed node's privval shows height
# H+1 and step >= 2. Progress-bounded: the joint privval state of the
# listed nodes not changing for 3 CreateEmptyBlocks intervals = stall
# (rc 1). Dies if any listed node's chain passes H (4 of 7 must not
# commit).
wait_signed() {
    local H="$1"; shift
    local k st last="" since=0 polls done_all
    polls=$(( 3 * STAGEF_CMT_EMPTY_INTERVAL_MS / 1000 ))
    while :; do
        st=""; done_all=1
        for k in "$@"; do
            st="$st $(pv_get "$k" height)/$(pv_get "$k" round)/$(pv_get "$k" step)"
            if [ "$(pv_get "$k" height)" != "$(( H + 1 ))" ] || [ "$(pv_get "$k" step)" -lt 2 ]; then
                done_all=0
            fi
            [ "$(tip_of "$k")" -le "$H" ] || die "node$k committed past $H with 3 of 7 frozen — 4 of 7 must not reach +2/3"
        done
        [ "$done_all" = 1 ] && return 0
        if [ "$st" != "$last" ]; then last=$st; since=0; else since=$(( since + 1 )); fi
        [ "$since" -lt "$polls" ] || { echo "[..] privval states:$st" >&2; return 1; }
        sleep 1
    done
}

# ── 1. the cluster is on OLD and commits ────────────────────────────
for n in $(seq 1 "$N"); do
    node_runs "$n" "$OLD_SRV" || die "node$n is not running the OLD binary — bring the cluster up with STAGEF_NODUS_BIN=\$STAGEF_NODUS_BIN_OLD"
done
[ ! -e "$(stagef_network_file)" ] || die "a network file already exists — the bring-up was not on an OLD server"
stagef_sentinel SETUP_OK
echo "[ok] all $N nodes run OLD v$OLD_VER"

h0=$(tip_of 1)
h=$(stagef_cmt_wait_height "$ref_db0" $(( h0 + 2 )) 3) || die "the OLD chain did not advance 2 heights ($h0 -> $h)"
stagef_cmt_diff_at_floor "pre-stop (OLD)" || exit 2

# ── 1b. the dangerous precondition: 3 frozen, 4 signed at tip+1 ─────
has_wal=$(sqlite3 "$ref_db0" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cmt_wal';" 2>/dev/null || echo 0)
[ "$has_wal" = 1 ] && [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM cmt_wal WHERE protocol_id = 1;")" -gt 0 ] \
    || die "node1's chain DB holds no SQLite-era consensus WAL rows — OLD is not the SQLite-WAL build item 1b needs"
FORM=""; H=-1; BLOCK_SIGNERS=0
declare -a FZ SG
for attempt in $(seq 1 "$PRECOND_ATTEMPTS"); do
    FZ=(); SG=()
    for j in 0 1 2; do FZ+=( $(( ( attempt + 4 + j - 1 ) % N + 1 )) ); done   # 1: 5 6 7, 2: 6 7 1, …
    for n in $(seq 1 "$N"); do
        case " ${FZ[*]} " in *" $n "*) ;; *) SG+=( "$n" ) ;; esac
    done
    watch=${SG[0]}
    h=$(wait_fresh_commit "$(db_of "$watch")") || die "attempt $attempt: no fresh commit on node$watch (stuck at $h)"
    fpids=()
    for k in "${FZ[@]}"; do
        pid=$(node_pid "$k"); [ -n "$pid" ] || die "node$k has no process to freeze"
        fpids+=( "$pid" )
    done
    kill -STOP "${fpids[@]}"
    FROZEN=( "${FZ[@]}" )
    H=$(tip_of "$watch")
    echo "[..] attempt $attempt: commit $h seen on node$watch; SIGSTOPped nodes ${FZ[*]} at tip $H; signers ${SG[*]}"

    # the freeze was in time: no frozen node signed or received anything at H+1
    late=""
    for k in "${FZ[@]}"; do
        pvh=$(pv_get "$k" height); rows=$(wal_msginfo_rows "$k" $(( H + 1 ))); t=$(tip_of "$k")
        [ "$rows" != -1 ] || die "cannot read node$k's cmt_wal (sqlite3 error) — not a late freeze"
        echo "     frozen node$k: tip $t, privval $(pv_line "$k"), cmt_wal MsgInfo rows at $(( H + 1 )): $rows"
        if [ "$pvh" -gt "$H" ] || [ "$rows" != 0 ] || [ "$t" -gt "$H" ]; then late="$late node$k"; fi
    done
    if [ -n "$late" ]; then
        echo "[..] attempt $attempt discarded: the freeze was late on$late"
        resume_frozen
        stagef_cmt_wait_height "$(db_of "$watch")" $(( H + 1 )) 3 > /dev/null || die "the chain did not recover after resuming$late"
        continue
    fi

    wait_signed "$H" "${SG[@]}" || die "attempt $attempt: the 4 signers never all signed at $(( H + 1 )) (privval unchanged for 3 CreateEmptyBlocks intervals)"
    BLOCK_SIGNERS=0
    for k in "${SG[@]}"; do
        rows=$(wal_msginfo_rows "$k" $(( H + 1 )))
        [ "$rows" != -1 ] || die "cannot read node$k's cmt_wal (sqlite3 error)"
        tgt=$(pv_target "$(pv_get "$k" signbytes)")
        [ "$tgt" = block ] && BLOCK_SIGNERS=$(( BLOCK_SIGNERS + 1 ))
        echo "     signer node$k: tip $(tip_of "$k"), privval $(pv_line "$k"), cmt_wal MsgInfo rows at $(( H + 1 )): $rows"
        # ≥ 1 MsgInfo row is NECESSARY for its own vote to be in the WAL,
        # not sufficient: kind 2 also counts RECEIVED messages (verifier
        # note) — the privval line above is the proof that it signed.
        [ "$rows" -ge 1 ] || die "node$k signed at $(( H + 1 )) but its cmt_wal holds no MsgInfo row there — its own signed message cannot be in the WAL"
    done
    if [ "$BLOCK_SIGNERS" -ge 3 ]; then FORM=block; break; fi
    if [ "$attempt" = "$PRECOND_ATTEMPTS" ]; then FORM=nil; break; fi
    echo "[..] attempt $attempt: $BLOCK_SIGNERS block signer(s) < 3 (the round-0 proposer of $(( H + 1 )) was frozen) — resume and retry"
    resume_frozen
    stagef_cmt_wait_height "$(db_of "$watch")" $(( H + 1 )) 3 > /dev/null || die "the chain did not commit $(( H + 1 )) after resuming"
done
[ -n "$FORM" ] || die "no freeze attempt was in time in $PRECOND_ATTEMPTS attempts"
if [ "$FORM" = block ]; then
    echo "[ok] PRECONDITION (dangerous form): $BLOCK_SIGNERS of 7 validators signed a BLOCK vote at (H+1=$(( H + 1 )), round 0) — >= 1/3 of the power holds a last-sign state a fresh round 0 cannot reproduce; the other 4 hold 4 of 7 < 5 (+2/3)"
elif [ "$NEG" = 1 ]; then
    resume_frozen
    echo "[SKIP] negative control: $PRECOND_ATTEMPTS attempts produced at most $BLOCK_SIGNERS block signer(s) — the NIL form's outcome is timing-dependent and is never asserted; the cluster is resumed on OLD. A skip is not a pass."
    exit 99
else
    echo "[WARN] PRECONDITION: NIL form only ($BLOCK_SIGNERS block signer(s) after $PRECOND_ATTEMPTS attempts) — this run proves the carry on a restart after signing at $(( H + 1 )), NOT that the carry prevented a halt"
fi

# ── 2. STOP ALL — the 3 frozen KILLed, the 4 TERMed, one loop ───────
declare -a PRE_TIP PRE_DB ROLE0 HS0 VER0 REF0 P2P0 CARRY0 REFUSE0
declare -a spids=()
for k in "${FZ[@]}"; do pid=$(node_pid "$k"); kill -KILL "$pid"; spids+=( "$k:$pid" ); done
for k in "${SG[@]}"; do pid=$(node_pid "$k"); kill -TERM "$pid"; spids+=( "$k:$pid" ); done
FROZEN=()
for kp in "${spids[@]}"; do
    k=${kp%%:*}; pid=${kp#*:}
    for i in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    ! kill -0 "$pid" 2>/dev/null || die "node$k (pid $pid) did not exit within 60 s of its signal"
done
for n in $(seq 1 "$N"); do
    for i in $(seq 1 60); do listening "$(stagef_tcp_port "$n")" || break; sleep 0.5; done
    ! listening "$(stagef_tcp_port "$n")" || die "node$n's client port is still bound after the stop"
done
echo "[ok] stopped: nodes ${FZ[*]} SIGKILLed (frozen), nodes ${SG[*]} SIGTERMed, in one loop"
for n in $(seq 1 "$N"); do
    t=$(tip_of "$n")
    [ "$t" -le "$H" ] || die "node$n's chain tip $t passed $H — a commit at $(( H + 1 )) happened during the stop, the precondition is gone"
done
for k in "${SG[@]}"; do echo "     after the stop, signer node$k: privval $(pv_line "$k")"; done
echo "[ok] no chain tip passed $H during the stop"
PRE_MAX=-1
for n in $(seq 1 "$N"); do
    PRE_TIP[$n]=$(tip_of "$n")
    PRE_DB[$n]=$(basename "$(db_of "$n")")
    [ "${PRE_TIP[$n]}" -ge 1 ] || die "node$n has no committed block before the stop"
    [ "${PRE_TIP[$n]}" -gt "$PRE_MAX" ] && PRE_MAX=${PRE_TIP[$n]}
    ROLE0[$n]=$(cnt "$n" 'chain role: COMETBFT')
    HS0[$n]=$(cnt "$n" 'completed ABCI handshake')
    VER0[$n]=$(cnt "$n" "Nodus v$NEW_VER running")
    REF0[$n]=$(cnt "$n" 'REFUSING START')
    P2P0[$n]=$(cnt "$n" "p2p on .* $N persistent peer(s)")
    CARRY0[$n]=$(cnt "$n" 'consensus WAL carry-over:')
    REFUSE0[$n]=$(cnt "$n" "failed signing vote: height $(( H + 1 )) round 0")
done
echo "[ok] pre-stop tips: $(for n in $(seq 1 "$N"); do printf 'node%s=%s ' "$n" "${PRE_TIP[$n]}"; done)(max $PRE_MAX)"

# ── N (opt-in). the carry disabled on the 4 signers ─────────────────
if [ "$NEG" = 1 ]; then
    for k in "${SG[@]}"; do
        sqlite3 "$(db_of "$k")" "DELETE FROM cmt_wal;" || die "could not delete node$k's cmt_wal rows"
        [ "$(sqlite3 "$(db_of "$k")" "SELECT COUNT(*) FROM cmt_wal;")" = 0 ] || die "node$k's cmt_wal still holds rows"
    done
    echo "[ok] NEGATIVE: the SQLite-era WAL rows of the signers ${SG[*]} deleted — their NEW start finds nothing to carry"
fi

# ── 3. the network file, then ALL on NEW, no wipe ───────────────────
stagef_write_network_file "$CHAIN_ID" || die "could not write the network file"
[ "$(stagef_network_file_pin)" = "$CHAIN_ID" ] || die "the network file does not pin $CHAIN_ID"
echo "[ok] network file written: pin $CHAIN_ID, $N persistent peers ($(stagef_network_file))"
for n in $(seq 1 "$N"); do start_node "$n" "$NEW_SRV"; done
for n in $(seq 1 "$N"); do wait_listening "$n"; done
for n in $(seq 1 "$N"); do
    node_runs "$n" "$NEW_SRV" || die "node$n's process is not the NEW binary"
    wait_more "$n" 'chain role: COMETBFT' "${ROLE0[$n]}" || die "node$n: no NEW COMETBFT role line on NEW"
    wait_more "$n" "Nodus v$NEW_VER running" "${VER0[$n]}" || die "node$n: no 'Nodus v$NEW_VER running' line"
    wait_more "$n" 'completed ABCI handshake' "${HS0[$n]}" || die "node$n: no NEW completed ABCI handshake on NEW"
    [ "$(cnt "$n" "p2p on .* $N persistent peer(s)")" -gt "${P2P0[$n]}" ] || die "node$n did not start its 4004 host with the network file's $N peers"
    [ "$(cnt "$n" 'REFUSING START')" = "${REF0[$n]}" ] || die "node$n logged REFUSING START on NEW (the pin-at-start check?)"
    [ "$(basename "$(db_of "$n")")" = "${PRE_DB[$n]}" ] || die "node$n came back on a DIFFERENT chain file (${PRE_DB[$n]} -> $(basename "$(db_of "$n")"))"
    t=$(tip_of "$n")
    [ "$t" -ge "${PRE_TIP[$n]}" ] || die "node$n's tip $t is BELOW its pre-stop tip ${PRE_TIP[$n]} — it did not resume its chain"
    echo "[ok] node$n on NEW: role, handshake, $N peers, same chain file, tip $t >= ${PRE_TIP[$n]}"
done
stagef_sentinel TARGET_REACHED

# ── 3b. the carry-over ran (or, negative, found nothing) ────────────
for k in "${SG[@]}"; do
    c=$(cnt "$k" 'consensus WAL carry-over:')
    if [ "$NEG" = 1 ]; then
        [ "$c" = "${CARRY0[$k]}" ] || die "NEGATIVE: node$k logged a carry-over although its rows were deleted"
    else
        [ "$c" -gt "${CARRY0[$k]}" ] || die "signer node$k logged no 'consensus WAL carry-over:' line on NEW — its signed messages at $(( H + 1 )) were not carried"
        echo "[ok] signer node$k: $(grep -- 'consensus WAL carry-over:' "$(log_of "$k")" | tail -n 1)"
    fi
done
for k in "${FZ[@]}"; do
    echo "     frozen node$k: carry-over lines $(cnt "$k" 'consensus WAL carry-over:') (before: ${CARRY0[$k]}) — evidence only"
done

# ── N (opt-in). the expected halt without the carry ─────────────────
if [ "$NEG" = 1 ]; then
    echo "[..] NEGATIVE expectation, derived from the privval states recorded above: $BLOCK_SIGNERS signer(s) signed a BLOCK vote at ($(( H + 1 )), 0);"
    echo "     none of them can sign a new proposal (step regression) or a nil/other vote (conflicting data) at round 0; the block is lost"
    echo "     (their WAL deleted; the frozen 3 held no MsgInfo row at $(( H + 1 ))); the rest hold <= $(( N - BLOCK_SIGNERS )) of $N < 5 (+2/3),"
    echo "     so no +2/3-any forms, no round timeout arms, and the tip must stay at $H"
    for k in "${SG[@]}"; do
        [ "$(pv_target "$(pv_get "$k" signbytes)")" = block ] || continue
        polls=$(( 3 * STAGEF_CMT_EMPTY_INTERVAL_MS / 1000 )); seen=0
        for i in $(seq 1 "$polls"); do
            if [ "$(cnt "$k" "failed signing vote: height $(( H + 1 )) round 0")" -gt "${REFUSE0[$k]}" ]; then seen=1; break; fi
            [ "$(tip_of 1)" -le "$H" ] || die "NEGATIVE control FAILED: the chain committed past $H without the carry"
            sleep 1
        done
        [ "$seen" = 1 ] || die "NEGATIVE: block signer node$k logged no refused vote at $(( H + 1 )) round 0 within 3 CreateEmptyBlocks intervals"
        echo "[ok] NEGATIVE: node$k: $(grep -- "failed signing vote: height $(( H + 1 )) round 0" "$(log_of "$k")" | tail -n 1)"
    done
    if h=$(stagef_cmt_wait_height "$(db_of 1)" $(( H + 1 )) 3); then
        die "NEGATIVE control FAILED: the chain committed $(( H + 1 )) (tip $h) without the carry — the precondition did not bind"
    fi
    stagef_sentinel ASSERT_RUN
    stagef_sentinel PASS
    echo ""
    echo "[PASS] NEGATIVE control: without the carry-over the chain HALTS at $H —"
    echo "       $BLOCK_SIGNERS block signers refused to re-sign at ($(( H + 1 )), 0) and no height"
    echo "       across 3 CreateEmptyBlocks intervals (stuck at $h). The cluster is left"
    echo "       HALTED on NEW by design — tear it down."
    exit 0
fi

# ── 4. the mesh: every node's OWN tip moves past the pre-stop max ───
target=$(( PRE_MAX + 3 ))
h=$(stagef_cmt_advance_to "$(db_of 1)" "$target" 4) || die "the NEW chain did not reach $target (stuck at $h)"
for n in $(seq 1 "$N"); do
    t=$(stagef_cmt_wait_height "$(db_of "$n")" "$target" 4) \
        || die "node$n never reached $target on NEW (stuck at $t) — it is not receiving blocks over 4004"
done
floor=-1
for n in $(seq 1 "$N"); do t=$(tip_of "$n"); if [ "$floor" = -1 ] || [ "$t" -lt "$floor" ]; then floor=$t; fi; done
[ "$floor" -gt "$PRE_MAX" ] || die "the floor $floor did not pass the pre-stop max $PRE_MAX"
stagef_cmt_diff_at_floor "post-stopall (NEW)" || exit 2
echo "[ok] the 4004 mesh formed on NEW: every node past $target, 7/7 agree past $PRE_MAX"
echo "[ok] the height the 4 had signed before the stop, $(( H + 1 )), committed on NEW (precondition: $FORM form, $BLOCK_SIGNERS block signer(s))"

# ── 5. negative control: node 7 on OLD cannot join ──────────────────
V=7
others=$(seq 1 $(( V - 1 )))
rej0=0
for n in $others; do rej0=$(( rej0 + $(cnt "$n" 'connection rejected') )); done
stop_nodes "$V"
vrole0=$(cnt "$V" 'chain role: COMETBFT'); vlive0=$(cnt "$V" 'cometbft lane LIVE')
start_node "$V" "$OLD_SRV"
wait_listening "$V"
node_runs "$V" "$OLD_SRV" || die "node$V's process is not the OLD binary"
wait_more "$V" 'chain role: COMETBFT' "$vrole0" || die "node$V on OLD never re-established its role — 'cannot join' would be vacuous"
wait_more "$V" 'cometbft lane LIVE' "$vlive0" || die "node$V on OLD never went LIVE — 'cannot join' would be vacuous"
v_tip=$(tip_of "$V")
target=$(( $(tip_of 1) + 5 ))
h=$(stagef_cmt_advance_to "$(db_of 1)" "$target" 4) || die "the six NEW nodes did not advance to $target with node$V on OLD (stuck at $h)"
for n in $others; do
    stagef_cmt_wait_height "$(db_of "$n")" "$target" 4 > /dev/null || die "node$n did not reach $target"
done
node_runs "$V" "$OLD_SRV" || die "node$V (OLD) died during the window — its frozen tip would prove nothing"
v_now=$(tip_of "$V")
[ "$v_now" = "$v_tip" ] || die "node$V on OLD advanced $v_tip -> $v_now — an OLD node JOINED the NEW mesh"
rej1=0
for n in $others; do rej1=$(( rej1 + $(cnt "$n" 'connection rejected') )); done
echo "[ok] node$V on OLD stayed at $v_tip while the six reached $target ('connection rejected' lines on the six: $rej0 -> $rej1, evidence only)"

# ── 6. recovery: node 7 back on NEW ─────────────────────────────────
vhs0=$(cnt "$V" 'completed ABCI handshake')
stop_nodes "$V"
start_node "$V" "$NEW_SRV"
wait_listening "$V"
node_runs "$V" "$NEW_SRV" || die "node$V's process is not the NEW binary after recovery"
wait_more "$V" 'completed ABCI handshake' "$vhs0" || die "node$V: no NEW ABCI handshake on NEW"
fleet=$(tip_of 1)
t=$(stagef_cmt_wait_height "$(db_of "$V")" "$fleet" 4) || die "node$V did not catch up to $fleet on NEW (stuck at $t)"
target=$(( fleet + 2 ))
h=$(stagef_cmt_advance_to "$(db_of 1)" "$target" 4) || die "the chain did not advance to $target after recovery (stuck at $h)"
for n in $(seq 1 "$N"); do
    stagef_cmt_wait_height "$(db_of "$n")" "$target" 4 > /dev/null || die "node$n did not reach $target"
done
stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-recovery (all NEW)" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] stop-all no-wipe: OLD v$OLD_VER -> NEW v$NEW_VER over the same data"
echo "       dirs, the chain continued past $PRE_MAX on the new 4004 mesh, 7/7"
echo "       agree, and an OLD node could not join the NEW mesh. Precondition at"
echo "       the stop: $FORM form ($BLOCK_SIGNERS of 7 had signed a BLOCK vote at $(( H + 1 ))),"
echo "       carried over from the SQLite WAL and committed on NEW."
