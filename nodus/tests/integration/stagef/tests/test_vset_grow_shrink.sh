#!/usr/bin/env bash
#
# Stage F test — Ledger V2 S3: dynamic validator set, 7 → 9 → 7.
#
# REQUIRES a SHORT-EPOCH nodus build. The harness binaries must be
# compiled with:
#     -DDNAC_EPOCH_LENGTH=15
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
# (dnac.h S3 #ifndef guards) and STAGEF_EPOCH_LENGTH=15 exported before
# stagef_up.sh. The script self-checks the binary's epoch length against
# the genesis validator-set snapshots and aborts on mismatch.
#
# Scenario:
#   A. genesis snapshots (epochs 0, E) byte-identical across 7 nodes
#   B. bring up nodes 8 and 9 (join live, sync)
#   C. fund node8/node9 witness identities
#   D. nodus-cli stake from both node identities → 9 bonded validators
#   E. chain-config propose TARGET_ACTIVE_COUNT=9 → at the governed
#      boundary the snapshot holds 9, statuses all ACTIVE, state_root
#      identical across ALL RUNNING nodes
#   F. propose TARGET_ACTIVE_COUNT=7 → set shrinks; exactly 2 validators
#      are ELIGIBLE (status 4) with their 10M bond PRESERVED
#   G. crash injection: kill -9 one committee node across a boundary,
#      restart, assert identical snapshots + state_root after resync
#
# Exit 0 PASS / non-zero FAIL.

set -uo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

E_LEN="${STAGEF_EPOCH_LENGTH:-15}"
NODUS_CLI="$STAGEF_REPO_ROOT/nodus/build/nodus-cli"
NODUS_BIN="$STAGEF_NODUS_BIN"
BOND_RAW=1000000000000000            # 10M DNAC
FUND_RAW=1000100000000000            # 10,001,000 DNAC (bond + fees + buffer)

fail() { echo "[FAIL] $*" >&2; exit 1; }
info() { echo "[info] $*"; }

# ── helpers ─────────────────────────────────────────────────────────

# All node indices that currently have a data dir (1..7 always, 8/9 later).
running_nodes() {
    for d in "$BASE_DIR"/node*/; do
        basename "$d" | sed 's/node//'
    done | sort -n
}

node1_db() { stagef_node_chain_db 1; }

head_height() {
    local db; db=$(node1_db)
    sqlite3 "$db" "SELECT COALESCE(MAX(height),0) FROM blocks;"
}

# Wait until node1's head >= $1 (timeout $2 seconds).
wait_height() {
    local target="$1" timeout="${2:-300}" t=0 h=0
    while [ $t -lt "$timeout" ]; do
        h=$(head_height)
        [ "$h" -ge "$target" ] && return 0
        sleep 3; t=$((t + 3))
    done
    fail "timeout waiting for height >= $target (at $h)"
}

# Assert every RUNNING node agrees on (epoch_start|hash) for ALL snapshot
# rows, and print them. $1 = label.
assert_snapshots_identical() {
    local label="$1" ref="" cur=""
    for n in $(running_nodes); do
        local db; db=$(stagef_node_chain_db "$n")
        [ -n "$db" ] || fail "$label: node$n has no chain DB"
        cur=$(sqlite3 "$db" "SELECT epoch_start || '|' || active_count \
              || '|' || hex(snapshot_hash) FROM validator_set_snapshots \
              ORDER BY epoch_start;") || fail "$label: node$n snapshot query"
        if [ -z "$ref" ]; then ref="$cur";
        elif [ "$cur" != "$ref" ]; then
            echo "--- node reference:"; echo "$ref"
            echo "--- node$n:"; echo "$cur"
            fail "$label: snapshot divergence on node$n"
        fi
    done
    info "$label: snapshots identical across $(running_nodes | wc -l) nodes"
    echo "$ref" | sed 's/^/       /' | cut -c1-100
}

# Assert state_root identical across ALL running nodes at same height.
assert_state_root_identical() {
    local label="$1" ref="" first_h=""
    # Let heights settle: two probes 1s apart until stable.
    sleep 2
    for n in $(running_nodes); do
        local db; db=$(stagef_node_chain_db "$n")
        local row; row=$(sqlite3 "$db" "SELECT height || '|' || \
            hex(state_root) FROM blocks ORDER BY height DESC LIMIT 1;")
        local h=${row%%|*} r=${row#*|}
        if [ -z "$ref" ]; then ref="$r"; first_h="$h"
        else
            # nodes may be ±1 block apart transiently; compare the root of
            # the REFERENCE height on this node instead
            local rr; rr=$(sqlite3 "$db" "SELECT hex(state_root) FROM \
                blocks WHERE height = $first_h;")
            [ -n "$rr" ] || fail "$label: node$n missing block $first_h"
            [ "$rr" == "$ref" ] || fail "$label: state_root divergence at h=$first_h on node$n"
        fi
    done
    info "$label: state_root identical at h=$first_h across $(running_nodes | wc -l) nodes"
}

# validator statuses (status -> count) on a node.
status_counts() {
    sqlite3 "$(stagef_node_chain_db "$1")" \
      "SELECT status || ':' || COUNT(*) FROM validators GROUP BY status ORDER BY status;" \
      | tr '\n' ' '
}

# ── A. self-check + genesis snapshots ───────────────────────────────

info "epoch length: $E_LEN (harness) — verifying against binary"
rows=$(sqlite3 "$(node1_db)" \
  "SELECT epoch_start FROM validator_set_snapshots ORDER BY epoch_start;")
exp_rows=$(printf '0\n%s' "$E_LEN")
if [ "$rows" != "$exp_rows" ]; then
    echo "  stored snapshot epochs: $(echo $rows | tr '\n' ' ')" >&2
    fail "genesis snapshots do not match STAGEF_EPOCH_LENGTH=$E_LEN — \
short-epoch binary not in use? (expected epochs 0 and $E_LEN)"
fi
assert_snapshots_identical "A/genesis"
assert_state_root_identical "A/genesis"

# ── B. nodes 8 and 9 join live ──────────────────────────────────────

SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done

# Nodes join SEQUENTIALLY: two simultaneous DISCOVER nodes pollute each
# other's peer counts, and the committee nodes only learn a joiner's
# identity via the periodic (60 s) DHT roster refresh — so each join
# gets its own settle window.
for n in 8 9; do
    node_dir="$BASE_DIR/node$n"
    mkdir -p "$node_dir/identity" "$node_dir/data"
    # identity generation via short-lived spawn (same as stagef_up)
    "$NODUS_BIN" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$node_dir/identity" -d "$node_dir/data" \
        > "$node_dir/identity_gen.log" 2>&1 &
    ig_pid=$!
    for _ in $(seq 1 40); do
        [ -s "$node_dir/identity/nodus.fp" ] && break
        sleep 0.25
    done
    kill "$ig_pid" 2>/dev/null || true; wait "$ig_pid" 2>/dev/null || true
    [ -s "$node_dir/identity/nodus.fp" ] || fail "node$n identity generation"
    # wipe the data dir the identity-gen spawn may have touched, then start
    rm -rf "$node_dir/data"; mkdir -p "$node_dir/data"
    # shellcheck disable=SC2086
    "$NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$node_dir/identity" -d "$node_dir/data" \
        $SEEDS > "$node_dir/nodus.log" 2>&1 &
    echo $! >> "$BASE_DIR/pids.txt"
    info "node$n spawned pid=$!"

    # Wait for THIS node to bootstrap + sync before starting the next.
    info "waiting for node$n to sync the chain (roster refresh is 60 s)"
    t=0; h=0
    # The joiner's DISCOVER backoff schedule is 0/30/60/120/240/300…s
    # (nodus_witness_bootstrap.c BOOTSTRAP_WAIT_SCHEDULE_SEC), and the
    # committee side only learns the joiner via the 60 s roster refresh,
    # so attempt 5 — the first one that typically lands after inclusion —
    # fires at ~450 s. 900 s covers attempt 6 as well.
    while [ $t -lt 900 ]; do
        db=$(stagef_node_chain_db "$n")
        if [ -n "$db" ] && [ -s "$db" ]; then
            h=$(sqlite3 "$db" "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null || echo 0)
            [ "${h:-0}" -ge 1 ] && break
        fi
        sleep 5; t=$((t + 5))
    done
    [ "${h:-0}" -ge 1 ] || fail "node$n did not sync genesis in 900s"
    info "node$n synced to h=$h"
done

# ── C. fund the two node identities ─────────────────────────────────

for n in 8 9; do
    fp=$(cat "$BASE_DIR/node$n/identity/nodus.fp")
    info "funding node$n identity ${fp:0:16}… with $FUND_RAW raw"
    ok=0
    for attempt in 1 2 3; do
        if stagef_dna -q dna send "$fp" "$FUND_RAW" "bond$n" \
             > "$BASE_DIR/fund_node$n.log" 2>&1; then ok=1; break; fi
        sleep 6
    done
    # CLI exit code is not the commit truth — verify on-chain (utxo_set
    # schema: owner TEXT, spent rows are deleted).
    committed=0
    for _ in $(seq 1 15); do
        sleep 4
        bal=$(sqlite3 "$(node1_db)" "SELECT COALESCE(SUM(amount),0) FROM \
            utxo_set WHERE owner = '$fp';" 2>/dev/null || echo 0)
        if [ "${bal:-0}" -ge "$BOND_RAW" ]; then committed=1; break; fi
    done
    [ "$committed" -eq 1 ] || fail "node$n funding not committed (bal=${bal:-0}, send ok=$ok)"
done
assert_state_root_identical "C/funding"

# ── D. stake both node identities ───────────────────────────────────

for n in 8 9; do
    info "staking node$n identity"
    "$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
        -i "$BASE_DIR/node$n/identity" stake --commission $((500 + n)) \
        > "$BASE_DIR/stake_node$n.log" 2>&1 \
        || fail "nodus-cli stake for node$n (see stake_node$n.log)"
    sleep 8
done

vcount=$(sqlite3 "$(node1_db)" "SELECT COUNT(*) FROM validators;")
[ "$vcount" -eq 9 ] || fail "expected 9 validator rows, got $vcount"
for n in $(running_nodes); do
    c=$(sqlite3 "$(stagef_node_chain_db "$n")" "SELECT COUNT(*) FROM validators;")
    [ "$c" -eq 9 ] || fail "node$n validator count $c != 9"
done
info "9 bonded validators on every node"
assert_state_root_identical "D/staked"

# ── E. grow: TARGET_ACTIVE_COUNT = 9 ────────────────────────────────

H=$(head_height)
# effective: a boundary far enough out to clear grace(15) + one full epoch
EFF=$(( ((H + 2 * E_LEN) / E_LEN + 1) * E_LEN ))
info "proposing TARGET_ACTIVE_COUNT=9 effective=$EFF (head=$H)"
"$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
    -i "$BASE_DIR/node1/identity" chain-config propose \
    --param TARGET_ACTIVE_COUNT --value 9 --effective "$EFF" \
    > "$BASE_DIR/cc_grow.log" 2>&1 || fail "propose grow (see cc_grow.log)"

# The first epoch whose SNAPSHOT can hold 9: built at a boundary B with
# B+E_LEN >= EFF AND tenure cleared: staked block S needs S + 2E <= lookback.
# Just poll: wait until some snapshot row has active_count 9.
info "waiting for a 9-member snapshot"
t=0; grown_epoch=""
while [ $t -lt 600 ]; do
    grown_epoch=$(sqlite3 "$(node1_db)" "SELECT epoch_start FROM \
        validator_set_snapshots WHERE active_count = 9 \
        ORDER BY epoch_start LIMIT 1;")
    [ -n "$grown_epoch" ] && break
    sleep 5; t=$((t + 5))
done
[ -n "$grown_epoch" ] || fail "no 9-member snapshot appeared in 600s"
info "9-member snapshot for epoch $grown_epoch"

# Wait until that epoch is fully underway (boundary applied + a few blocks).
wait_height $((grown_epoch + 3)) 600
assert_snapshots_identical "E/grown"
assert_state_root_identical "E/grown"
sc=$(status_counts 1)
info "statuses after grow: $sc"
a9=$(sqlite3 "$(node1_db)" "SELECT COUNT(*) FROM validators WHERE status = 0;")
[ "$a9" -eq 9 ] || fail "expected 9 ACTIVE after grow, got: $sc"

# ── F. shrink: TARGET_ACTIVE_COUNT = 7 ──────────────────────────────

H=$(head_height)
EFF2=$(( ((H + 2 * E_LEN) / E_LEN + 1) * E_LEN ))
info "proposing TARGET_ACTIVE_COUNT=7 effective=$EFF2 (head=$H)"
"$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
    -i "$BASE_DIR/node1/identity" chain-config propose \
    --param TARGET_ACTIVE_COUNT --value 7 --effective "$EFF2" \
    > "$BASE_DIR/cc_shrink.log" 2>&1 || fail "propose shrink (see cc_shrink.log)"

info "waiting for a 7-member snapshot AFTER epoch $grown_epoch"
t=0; shrunk_epoch=""
while [ $t -lt 600 ]; do
    shrunk_epoch=$(sqlite3 "$(node1_db)" "SELECT epoch_start FROM \
        validator_set_snapshots WHERE active_count = 7 \
        AND epoch_start > $grown_epoch ORDER BY epoch_start LIMIT 1;")
    [ -n "$shrunk_epoch" ] && break
    sleep 5; t=$((t + 5))
done
[ -n "$shrunk_epoch" ] || fail "no post-grow 7-member snapshot in 600s"
info "7-member snapshot for epoch $shrunk_epoch"

wait_height $((shrunk_epoch + 3)) 600
assert_snapshots_identical "F/shrunk"
assert_state_root_identical "F/shrunk"
sc=$(status_counts 1)
info "statuses after shrink: $sc"
el=$(sqlite3 "$(node1_db)" "SELECT COUNT(*) FROM validators WHERE status = 4;")
ac=$(sqlite3 "$(node1_db)" "SELECT COUNT(*) FROM validators WHERE status = 0;")
[ "$el" -eq 2 ] || fail "expected 2 ELIGIBLE after shrink, got: $sc"
[ "$ac" -eq 7 ] || fail "expected 7 ACTIVE after shrink, got: $sc"
# Bond preserved on the ELIGIBLE pair — never destroyed or unlocked.
badbond=$(sqlite3 "$(node1_db)" "SELECT COUNT(*) FROM validators \
    WHERE status = 4 AND self_stake < $BOND_RAW;")
[ "$badbond" -eq 0 ] || fail "an ELIGIBLE validator lost its bond"
info "ELIGIBLE pair keeps its bond"

# ── G. crash injection across a boundary ────────────────────────────

H=$(head_height)
NEXT_B=$(( (H / E_LEN + 1) * E_LEN ))
victim=4
victim_pid=$(pgrep -f "node$victim/identity" | head -1)
[ -n "$victim_pid" ] || fail "cannot find node$victim pid"
info "killing node$victim (pid $victim_pid) before boundary $NEXT_B (head=$H)"
kill -9 "$victim_pid"
wait_height $((NEXT_B + 2)) 600
info "boundary $NEXT_B passed without node$victim — restarting it"
node_dir="$BASE_DIR/node$victim"
# shellcheck disable=SC2086
"$NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
    -u "$(stagef_udp_port "$victim")" -t "$(stagef_tcp_port "$victim")" \
    -p "$(stagef_peer_port "$victim")" -C "$(stagef_chan_port "$victim")" \
    -W "$(stagef_witness_port "$victim")" \
    -i "$node_dir/identity" -d "$node_dir/data" \
    $SEEDS >> "$node_dir/nodus.log" 2>&1 &
echo $! >> "$BASE_DIR/pids.txt"

info "waiting for node$victim to catch up"
t=0
while [ $t -lt 300 ]; do
    ref_h=$(head_height)
    vh=$(sqlite3 "$(stagef_node_chain_db "$victim")" \
        "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null || echo 0)
    [ "${vh:-0}" -ge "$ref_h" ] && break
    sleep 5; t=$((t + 5))
done
[ "${vh:-0}" -ge "$ref_h" ] || fail "node$victim did not catch up ($vh < $ref_h)"
assert_snapshots_identical "G/crash-recovery"
assert_state_root_identical "G/crash-recovery"

echo ""
echo "[PASS] 7→9→7 dynamic validator set: snapshots, flips, bonds, "
echo "       state_root and crash recovery all identical across nodes"
