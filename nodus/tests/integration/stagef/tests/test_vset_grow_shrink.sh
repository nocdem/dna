#!/usr/bin/env bash
#
# Stage F test — Ledger V2 S3: dynamic validator set, 7 → 9 → 7.
#
# REQUIRES a SHORT-EPOCH nodus build. The harness binaries must be
# compiled with:
#     -DDNAC_EPOCH_LENGTH=<E>
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=<E>
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=<E>
# (dnac.h S3 #ifndef guards) and STAGEF_EPOCH_LENGTH=<E> exported before
# stagef_up.sh. Section A self-checks the binary's epoch length against
# the genesis validator-set snapshots and aborts on mismatch.
#
# Scenario:
#   A. genesis snapshots (epochs 0, E) byte-identical across 7 nodes
#   B. bring up nodes 8 and 9 (join live, leave DISCOVER, sync)
#   C. fund node8/node9 witness identities
#   D. nodus-cli stake from both node identities → 9 bonded validators
#   E. chain-config propose TARGET_ACTIVE_COUNT=9 → at the governed
#      epoch boundary the snapshot holds 9 (and contains node8 + node9),
#      statuses all ACTIVE, dynamic quorum moves to 7, state_root and
#      block identity identical across ALL RUNNING nodes
#   F. propose TARGET_ACTIVE_COUNT=7 → set shrinks; exactly 2 validators
#      are ELIGIBLE (status 4) with their 10M bond PRESERVED, the
#      demoted pair is absent from the new authoritative snapshot, and
#      every historical snapshot is byte-unchanged
#   G. crash injection: kill -9 one committee node across a boundary,
#      restart, assert identical snapshots + state_root + block identity
#      after resync
#
# BLOCK PRODUCTION IS TX-DRIVEN. nodus_witness_tick only opens a round
# when the mempool is non-empty (nodus_witness.c, block-timer branch),
# so an idle cluster never reaches the next epoch boundary. Every wait
# for a height in this scenario therefore PUMPS the chain instead of
# sleeping — a bounded stream of 1-raw sends, one per block.
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
ok()   { echo "[ok] $*"; }

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

# Raw Dilithium5 public key of a harness node, uppercase hex — the exact
# byte string the validator row and the snapshot blob carry.
node_pubkey_hex() {
    xxd -p -u -c 99999 "$BASE_DIR/node$1/identity/nodus.pk"
}

# Drive the chain to >= $1 by submitting one minimal TX per block.
#
# A blind sleep cannot do this: with no TXs there are no blocks, so the
# original wait_height could only ever time out once the scenario had
# stopped generating traffic of its own.
# FAIL ON NO PROGRESS, NOT ON A CLOCK.
#
# This used to fail when a wall-clock budget expired, and every call site
# carried a hand-picked number. Those numbers encoded an assumption about
# SPEED, and the assumption was wrong in every direction: a pump
# iteration is `dna sync` (measured 14 s on its own) + `dna send` + a 6 s
# settle, so ~37 s/block on a healthy localhost cluster and ~63 s/block in
# section G, where a committee member is dead BY DESIGN and every round
# waits out its missing vote. The scenario kept failing with the chain
# healthy and still advancing — `height 15 < 22`, `height 104 < 107` —
# and each failure invited another number bump. That is the wrong shape:
# tuning a timeout until a test goes green hides real stalls, and a
# number calibrated on this machine says nothing about the next one.
#
# The property this function actually needs is not "finish within T
# seconds" but "the chain is still producing blocks". So the failure
# condition is now STALL: PUMP_STALL_ROUNDS consecutive iterations with
# NO height change. A slow machine, a slow round, a deliberately degraded
# cluster — none of them trip it, because each still advances. A wedged
# chain trips it immediately and reports the height it died at.
#
# `timeout` is kept as an ABSOLUTE ceiling so a pathologically slow but
# technically-advancing chain cannot run forever; it is deliberately
# generous and is NOT the thing being asserted.
PUMP_STALL_ROUNDS=8

pump_to_height() {
    local target="$1" timeout="${2:-7200}"
    local h; h=$(head_height)
    local last_h="${h:-0}" stalled=0

    local deadline=$(( SECONDS + timeout ))
    local sink; sink=$(cat "$BASE_DIR/node1/identity/nodus.fp")
    while [ "${h:-0}" -lt "$target" ] && [ $SECONDS -lt $deadline ]; do
        # SYNC BEFORE EVERY SEND — not only after a failure.
        #
        # The wallet spends one coin and books its change locally. If a
        # submit times out (which happens whenever a BFT round has to be
        # retried, and the grow/shrink boundaries do retry), the wallet is
        # left believing its only coin is in flight: every later send then
        # reports "Insufficient funds" against a wallet that holds the
        # genesis supply on-chain. Without new transactions the chain
        # produces no blocks, so the change can never confirm — a deadlock
        # the pump cannot escape on its own.
        #
        # Only `dna sync` re-reads the committed UTXO set and clears that
        # belief, so it runs unconditionally. A sync-on-failure-only
        # variant was measurably faster and deadlocked at exactly the
        # boundary this scenario exists to cross. Slower and deterministic
        # beats faster and stuck (feedback_dnac_sync_between_sends).
        stagef_dna -q dna sync >> "$BASE_DIR/vset_pump.log" 2>&1 || true
        if ! stagef_dna -q dna send "$sink" 1 "pump" \
               >> "$BASE_DIR/vset_pump.log" 2>&1; then
            stagef_dna -q dna sync >> "$BASE_DIR/vset_pump.log" 2>&1 || true
            stagef_dna -q dna send "$sink" 1 "pump" \
                >> "$BASE_DIR/vset_pump.log" 2>&1 || true
        fi
        sleep 6
        h=$(head_height)

        # Progress, not speed, is the assertion.
        if [ "${h:-0}" -gt "$last_h" ]; then
            last_h="${h:-0}"
            stalled=0
        else
            stalled=$(( stalled + 1 ))
            if [ "$stalled" -ge "$PUMP_STALL_ROUNDS" ]; then
                fail "pump STALLED at height $h (target $target): no block \
in $PUMP_STALL_ROUNDS consecutive send rounds — the chain has stopped \
producing, which is a real failure, not a slow machine"
            fi
        fi
    done
    [ "${h:-0}" -ge "$target" ] || \
        fail "pump: height $h < $target — hit the absolute ${timeout}s \
ceiling while still advancing (last progress at $last_h). This is NOT a \
stall; if it is legitimate, the ceiling is too low for this cluster."
    info "pumped to height $h (target $target)"
}

# Block until every running node holds the SAME head height.
#
# Every cross-node assertion below is an equality over committed state.
# Comparing while one node is a block behind would report a divergence
# that is really lag — a flaky consensus assertion, which this tree
# forbids outright. So converge FIRST, on an explicit condition, and keep
# the deadline only as failure protection.
converge_heads() {
    local label="$1" timeout="${2:-300}"
    local deadline=$(( SECONDS + timeout ))
    local lo hi
    while [ $SECONDS -lt $deadline ]; do
        lo=""; hi=""
        for n in $(running_nodes); do
            local db; db=$(stagef_node_chain_db "$n")
            [ -n "$db" ] || { lo=""; break; }
            local h; h=$(sqlite3 "$db" \
                "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null || echo "")
            [ -n "$h" ] || { lo=""; break; }
            [ -z "$lo" ] && { lo="$h"; hi="$h"; continue; }
            [ "$h" -lt "$lo" ] && lo="$h"
            [ "$h" -gt "$hi" ] && hi="$h"
        done
        if [ -n "$lo" ] && [ "$lo" = "$hi" ]; then
            CONVERGED_H="$lo"
            info "$label: all $(running_nodes | wc -l) nodes at height $lo"
            return 0
        fi
        sleep 3
    done
    fail "$label: nodes did not converge (lo=${lo:-?} hi=${hi:-?}) in ${timeout}s"
}
CONVERGED_H=0

# Assert every RUNNING node agrees on (epoch_start|active_count|hash) for
# ALL snapshot rows, and print them. $1 = label.
assert_snapshots_identical() {
    local label="$1" ref="" cur=""
    converge_heads "$label"
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
    ok "$label: snapshots identical across $(running_nodes | wc -l) nodes"
    echo "$ref" | sed 's/^/       /' | cut -c1-100
}

# Assert state_root identical across ALL running nodes at same height.
assert_state_root_identical() {
    local label="$1" ref=""
    converge_heads "$label"
    local first_h="$CONVERGED_H"
    for n in $(running_nodes); do
        local db; db=$(stagef_node_chain_db "$n")
        local rr; rr=$(sqlite3 "$db" "SELECT hex(state_root) FROM \
            blocks WHERE height = $first_h;")
        [ -n "$rr" ] || fail "$label: node$n missing block $first_h"
        if [ -z "$ref" ]; then ref="$rr"
        else
            [ "$rr" == "$ref" ] || fail "$label: state_root divergence at h=$first_h on node$n"
        fi
    done
    ok "$label: state_root identical at h=$first_h across $(running_nodes | wc -l) nodes"
}

# Assert the committed BLOCK IDENTITY — not just the state_root — is the
# same on every running node. state_root alone would still agree if two
# nodes disagreed on the transaction set or the parent link.
assert_block_identity_identical() {
    local label="$1"
    converge_heads "$label"
    local ref="" ref_h="$CONVERGED_H"
    for n in $(running_nodes); do
        local db; db=$(stagef_node_chain_db "$n")
        local row
        row=$(sqlite3 "$db" "SELECT height || '|' || hex(tx_root) || '|' || \
              tx_count || '|' || timestamp || '|' || hex(prev_hash) || '|' || \
              hex(state_root) || '|' || hex(COALESCE(proposer_id, x'')) \
              FROM blocks WHERE height = $ref_h;")
        [ -n "$row" ] || fail "$label: node$n missing block $ref_h"
        if [ -z "$ref" ]; then ref="$row"
        elif [ "$row" != "$ref" ]; then
            echo "--- reference: $ref"
            echo "--- node$n:    $row"
            fail "$label: block identity divergence at h=$ref_h on node$n"
        fi
    done
    ok "$label: block identity identical at h=$ref_h across $(running_nodes | wc -l) nodes"
}

# validator statuses (status -> count) on a node.
status_counts() {
    sqlite3 "$(stagef_node_chain_db "$1")" \
      "SELECT status || ':' || COUNT(*) FROM validators GROUP BY status ORDER BY status;" \
      | tr '\n' ' '
}

# Snapshot membership: is this raw pubkey inside the authoritative blob
# committed for epoch $1?
snapshot_contains() {
    local epoch="$1" pk="$2"
    sqlite3 "$(node1_db)" "SELECT CASE WHEN instr(hex(snapshot_blob), \
        '$pk') > 0 THEN 1 ELSE 0 END FROM validator_set_snapshots \
        WHERE epoch_start = $epoch;"
}

# The authoritative snapshot for the epoch the head is IN must hold
# exactly the validators whose status byte says ACTIVE, and none of the
# demoted ones.
#
# WHICH snapshot matters. nodus_witness_vset.c flips EVERY bonded row to
# ELIGIBLE at each boundary and then flips exactly that epoch's snapshot
# members back to ACTIVE, so the status bytes always describe the epoch
# containing the head — never an earlier one. With nine bonded validators
# at an identical 10M bond and seven seats, the seven legitimately ROTATE
# from epoch to epoch, so an earlier 7-member snapshot names a different
# seven and comparing against it reports a divergence that does not exist.
assert_status_matches_epoch_snapshot() {
    local label="$1" tries=0
    while [ $tries -lt 5 ]; do
        local h0 e have a_missing e_present h1
        h0=$(head_height)
        e=$(( (h0 / E_LEN) * E_LEN ))
        have=$(sqlite3 "$(node1_db)" "SELECT COUNT(*) FROM \
            validator_set_snapshots WHERE epoch_start = $e;")
        if [ "$have" != "1" ]; then tries=$((tries + 1)); sleep 3; continue; fi

        a_missing=0; e_present=0
        while read -r pk; do
            [ -z "$pk" ] && continue
            [ "$(snapshot_contains "$e" "$pk")" = "1" ] || a_missing=$((a_missing + 1))
        done <<EOF
$(sqlite3 "$(node1_db)" "SELECT hex(pubkey) FROM validators WHERE status = 0;")
EOF
        while read -r pk; do
            [ -z "$pk" ] && continue
            [ "$(snapshot_contains "$e" "$pk")" = "0" ] || e_present=$((e_present + 1))
        done <<EOF
$(sqlite3 "$(node1_db)" "SELECT hex(pubkey) FROM validators WHERE status = 4;")
EOF
        # If the head crossed a boundary mid-read the two sides came from
        # different epochs; retry instead of reporting a race as a
        # divergence.
        h1=$(head_height)
        if [ $(( (h1 / E_LEN) * E_LEN )) -ne "$e" ]; then
            tries=$((tries + 1)); continue
        fi

        [ "$a_missing" -eq 0 ] || \
            fail "$label: $a_missing ACTIVE validator(s) absent from the epoch-$e snapshot"
        [ "$e_present" -eq 0 ] || \
            fail "$label: $e_present demoted validator(s) still in the epoch-$e snapshot"
        ok "$label: epoch-$e snapshot holds exactly the ACTIVE set — no demoted member stays authoritative"
        return 0
    done
    fail "$label: statuses and snapshot could not be read inside one epoch"
}

# Every stored snapshot epoch is a boundary multiple, and the series has
# no gap and no duplicate — a validator set may only ever change by ONE
# governed epoch transition at a time.
assert_snapshot_series_sane() {
    local label="$1"
    local rows; rows=$(sqlite3 "$(node1_db)" \
        "SELECT epoch_start FROM validator_set_snapshots ORDER BY epoch_start;")
    local prev=""
    for e in $rows; do
        [ $(( e % E_LEN )) -eq 0 ] || \
            fail "$label: snapshot epoch_start=$e is not a multiple of $E_LEN"
        if [ -n "$prev" ] && [ "$prev" -ne 0 ]; then
            [ $(( e - prev )) -eq "$E_LEN" ] || \
                fail "$label: snapshot series jumps $prev -> $e (expected +$E_LEN)"
        fi
        prev="$e"
    done
    ok "$label: snapshot series is boundary-aligned, gapless and unique"
}

# ── A. self-check + genesis snapshots ───────────────────────────────

info "epoch length: $E_LEN (harness) — verifying against binary"
rows=$(sqlite3 "$(node1_db)" \
  "SELECT epoch_start FROM validator_set_snapshots ORDER BY epoch_start;")

# O15B §7 / §16 — THE CHECK WAS ORDER-DEPENDENT, AND THE ORDER CHANGED.
#
# It required the snapshot table to hold EXACTLY {0, E_LEN}, the two epochs
# genesis seeds (nodus_witness_vset_commit_genesis). That is only true on a
# freshly created chain. Every epoch boundary since then has committed
# another snapshot (nodus_witness_vset_commit_next), and this scenario runs
# LAST in the alphabetical order genesis_protocol.sh uses — so by the time
# it runs, on a short-epoch harness, the table holds dozens of rows and the
# equality can never hold.
#
# The PROPERTY it actually wanted is that the binary's epoch length matches
# the harness's. That is checked directly and order-independently: genesis
# seeds epoch 0 and epoch E_LEN, so BOTH must be present whatever else has
# accumulated, and no snapshot may sit at a non-multiple of E_LEN.
have_0=$(printf '%s\n' "$rows" | grep -cx '0' || true)
have_e=$(printf '%s\n' "$rows" | grep -cx "$E_LEN" || true)
if [ "${have_0:-0}" -lt 1 ] || [ "${have_e:-0}" -lt 1 ]; then
    echo "  stored snapshot epochs: $(echo $rows | tr '\n' ' ')" >&2
    fail "genesis snapshots missing epoch 0 and/or $E_LEN — \
short-epoch binary not in use? (STAGEF_EPOCH_LENGTH=$E_LEN)"
fi
assert_snapshot_series_sane "A/genesis"
info "snapshot epochs present: $(echo $rows | tr '\n' ' ')"
stagef_sentinel SETUP_OK
assert_snapshots_identical "A/genesis"
assert_state_root_identical "A/genesis"
assert_block_identity_identical "A/genesis"

# ── B. nodes 8 and 9 join live ──────────────────────────────────────

SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done

# Nodes join SEQUENTIALLY: two simultaneous DISCOVER nodes pollute each
# other's peer counts, and the committee side learns a joiner from the
# DHT nodus:pk registry on its next roster rebuild — so each join gets
# its own settle window.
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

    # ASSERTION 1 — the joiner must LEAVE DISCOVER. A joiner that never
    # reaches bootstrap quorum sits in DISCOVER forever and every later
    # symptom ("did not sync") is downstream of that one fact, so it is
    # asserted on its own, by the state machine's own terminal log line
    # (nodus_witness_bootstrap.c: "state=DONE branch=DISCOVER").
    #
    # The committee learns a joiner from the DHT nodus:pk registry
    # (nodus_witness_peer.c rebuild_roster_from_peers) on its 60 s roster
    # tick, and the joiner's DISCOVER backoff schedule is
    # 0/30/90/210/450/750 s (BOOTSTRAP_WAIT_SCHEDULE_SEC cumulative), so
    # a healthy join lands on attempt 3-4. 600 s covers attempt 5.
    info "waiting for node$n to leave DISCOVER"
    t=0; left=0
    while [ $t -lt 600 ]; do
        if grep -q "state=DONE branch=DISCOVER" "$node_dir/nodus.log" 2>/dev/null; then
            left=1; break
        fi
        sleep 5; t=$((t + 5))
    done
    if [ $left -ne 1 ]; then
        echo "--- node$n bootstrap trace ---" >&2
        grep "WITNESS-BOOTSTRAP" "$node_dir/nodus.log" | tail -20 >&2
        for c in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
            echo "  node$c roster: $(grep -c 'roster swap' "$BASE_DIR/node$c/nodus.log") swaps, \
$(grep -c 'unknown sender' "$BASE_DIR/node$c/nodus.log") unknown-sender drops" >&2
        done
        fail "node$n never left DISCOVER (bootstrap quorum not reached in ${t}s)"
    fi
    ok "node$n left DISCOVER after ${t}s"

    # ASSERTION 2 — and then reached the synchronisation target.
    t=0; h=0
    while [ $t -lt 300 ]; do
        db=$(stagef_node_chain_db "$n")
        if [ -n "$db" ] && [ -s "$db" ]; then
            h=$(sqlite3 "$db" "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null || echo 0)
            [ "${h:-0}" -ge 1 ] && break
        fi
        sleep 5; t=$((t + 5))
    done
    [ "${h:-0}" -ge 1 ] || fail "node$n left DISCOVER but did not sync genesis in ${t}s"
    ok "node$n synced to h=$h"
done

# ── C. fund the two node identities ─────────────────────────────────

for n in 8 9; do
    fp=$(cat "$BASE_DIR/node$n/identity/nodus.fp")
    info "funding node$n identity ${fp:0:16}… with $FUND_RAW raw"
    ok_send=0
    : > "$BASE_DIR/fund_node$n.log"
    for attempt in 1 2 3; do
        # SYNC FIRST, every time. The second funding TX spends the change
        # output of the first, and the wallet cannot select a coin it has
        # not seen: without this, node9's send failed with
        # "Error: Insufficient funds" against a wallet holding the entire
        # genesis supply. (feedback_dnac_sync_between_sends; this section
        # of the scenario had never executed before O15B.1.)
        stagef_dna -q dna sync >> "$BASE_DIR/fund_node$n.log" 2>&1 || true
        if stagef_dna -q dna send "$fp" "$FUND_RAW" "bond$n" \
             >> "$BASE_DIR/fund_node$n.log" 2>&1; then ok_send=1; break; fi
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
    [ "$committed" -eq 1 ] || fail "node$n funding not committed (bal=${bal:-0}, send ok=$ok_send)"
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

# The count alone would be satisfied by ANY nine rows. Name the two the
# scenario actually brought in.
PK8=$(node_pubkey_hex 8)
PK9=$(node_pubkey_hex 9)
for pk_label in "8:$PK8" "9:$PK9"; do
    lbl=${pk_label%%:*}; pk=${pk_label#*:}
    got=$(sqlite3 "$(node1_db)" \
        "SELECT COUNT(*) FROM validators WHERE hex(pubkey) = '$pk';")
    [ "$got" -eq 1 ] || fail "node$lbl identity is not a bonded validator"
done
ok "9 bonded validators on every node, including node8 and node9"
assert_state_root_identical "D/staked"

# ── E. grow: TARGET_ACTIVE_COUNT = 9 ────────────────────────────────
# O15B §7 — the operation under test begins here.
stagef_sentinel TARGET_REACHED

# Record the pre-grow authoritative snapshots so section F can prove the
# historical rows never move.
PRE_GROW_SERIES=$(sqlite3 "$(node1_db)" "SELECT epoch_start || '|' || \
    active_count || '|' || hex(snapshot_hash) FROM validator_set_snapshots \
    ORDER BY epoch_start;")

# A chain-config proposal is a fee-paying TX like any other
# (nodus_witness_verify.c: committed_fee >= DNAC_MIN_FEE_RAW), and the
# proposer here is node1's WITNESS identity, not the harness user. Fund
# it from this scenario rather than inheriting a balance an earlier
# alphabetically-ordered scenario happened to leave behind — this
# scenario has to stand on its own when run in isolation.
V0_FP=$(cat "$BASE_DIR/node1/identity/nodus.fp")
info "funding node1 witness identity ${V0_FP:0:16}… for the propose fees"
stagef_dna -q dna sync > "$BASE_DIR/vset_cc_fund.log" 2>&1 || true
stagef_dna -q dna send "$V0_FP" 100000000 "cc-fee" \
    >> "$BASE_DIR/vset_cc_fund.log" 2>&1 || true
cc_funded=0
for _ in $(seq 1 15); do
    sleep 4
    bal=$(sqlite3 "$(node1_db)" "SELECT COALESCE(SUM(amount),0) FROM \
        utxo_set WHERE owner = '$V0_FP';" 2>/dev/null || echo 0)
    if [ "${bal:-0}" -ge 100000000 ]; then cc_funded=1; break; fi
done
[ "$cc_funded" -eq 1 ] || fail "node1 witness identity not funded (bal=${bal:-0})"
ok "node1 witness identity funded (${bal} raw)"

H=$(head_height)
# effective: a boundary far enough out to clear grace + one full epoch
EFF=$(( ((H + 2 * E_LEN) / E_LEN + 1) * E_LEN ))
info "proposing TARGET_ACTIVE_COUNT=9 effective=$EFF (head=$H)"
"$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
    -i "$BASE_DIR/node1/identity" chain-config propose \
    --param TARGET_ACTIVE_COUNT --value 9 --effective "$EFF" \
    > "$BASE_DIR/cc_grow.log" 2>&1 || fail "propose grow (see cc_grow.log)"

# The first epoch whose SNAPSHOT can hold 9: built at a boundary B with
# B+E_LEN >= EFF AND tenure cleared (staked block S needs S + 2E <=
# lookback). Drive the chain there — nothing else will.
info "pumping past the governed boundary and waiting for a 9-member snapshot"
grown_epoch=""
# BUDGET FROM THE DISTANCE, NOT A FLAT WALL CLOCK.
#
# WAIT ON THE HEIGHT THE CHAIN MUST REACH, NOT ON A CLOCK.
#
# The first snapshot that can hold 9 is built at a boundary at or after
# EFF, so the chain has to travel to about EFF + E_LEN. This used to be a
# flat wall-clock deadline, which encoded a guess about block rate and
# gave up at height 37 with EFF=45 while the chain was healthy and still
# advancing. The honest condition is the DISTANCE: pump until the target
# height is reached (pump_to_height fails on a real stall), re-checking
# for the snapshot each round. If the height arrives and the snapshot
# still has not, THAT is a genuine consensus failure and is reported as
# one — no timing involved.
grow_target=$(( EFF + E_LEN ))
while [ "$(head_height)" -lt "$grow_target" ]; do
    grown_epoch=$(sqlite3 "$(node1_db)" "SELECT epoch_start FROM \
        validator_set_snapshots WHERE active_count = 9 \
        ORDER BY epoch_start LIMIT 1;")
    [ -n "$grown_epoch" ] && break
    pump_to_height $(( $(head_height) + E_LEN ))
done
[ -n "$grown_epoch" ] || grown_epoch=$(sqlite3 "$(node1_db)" \
    "SELECT epoch_start FROM validator_set_snapshots WHERE active_count = 9 \
     ORDER BY epoch_start LIMIT 1;")
[ -n "$grown_epoch" ] || fail "no 9-member snapshot appeared even though \
the chain reached height $(head_height) (>= $grow_target, the first \
boundary that could carry the governed set) — the grow did not happen"
info "9-member snapshot for epoch $grown_epoch"

# GOVERNANCE: the set may only grow at a boundary at or after the height
# the chain-config proposal made effective. A 9-member snapshot BEFORE
# that height would mean the active set moved outside the epoch-boundary
# mechanism.
[ $(( grown_epoch % E_LEN )) -eq 0 ] || \
    fail "grow landed at epoch_start=$grown_epoch, not an epoch boundary"
[ "$grown_epoch" -ge "$EFF" ] || \
    fail "set grew at epoch $grown_epoch, BEFORE the governed effective height $EFF"
ok "grow happened at boundary $grown_epoch >= effective $EFF"

# Let the grown epoch actually come into force.
pump_to_height $(( grown_epoch + 3 ))
assert_snapshot_series_sane "E/grown"
assert_snapshots_identical "E/grown"
assert_state_root_identical "E/grown"
assert_block_identity_identical "E/grown"

sc=$(status_counts 1)
info "statuses after grow: $sc"
a9=$(sqlite3 "$(node1_db)" "SELECT COUNT(*) FROM validators WHERE status = 0;")
[ "$a9" -eq 9 ] || fail "expected 9 ACTIVE after grow, got: $sc"

# MEMBERSHIP: the authoritative snapshot must actually carry the nine
# ACTIVE keys — including the two this scenario introduced.
for pk_label in "8:$PK8" "9:$PK9"; do
    lbl=${pk_label%%:*}; pk=${pk_label#*:}
    [ "$(snapshot_contains "$grown_epoch" "$pk")" = "1" ] || \
        fail "node$lbl is ACTIVE but absent from the epoch-$grown_epoch snapshot"
done
missing=0
while read -r pk; do
    [ -z "$pk" ] && continue
    [ "$(snapshot_contains "$grown_epoch" "$pk")" = "1" ] || missing=$((missing + 1))
done <<EOF
$(sqlite3 "$(node1_db)" "SELECT hex(pubkey) FROM validators WHERE status = 0;")
EOF
[ "$missing" -eq 0 ] || fail "$missing ACTIVE validators missing from the epoch-$grown_epoch snapshot"
ok "epoch-$grown_epoch snapshot carries all 9 ACTIVE members incl. node8 + node9"
assert_status_matches_epoch_snapshot "E/grown"

# DYNAMIC QUORUM: 9 validators ⇒ (2*9)/3 + 1 = 7. The BFT round logs the
# quorum it is actually enforcing; it must have moved with the snapshot.
EXPECT_Q=$(( (2 * 9) / 3 + 1 ))
# Bounded by BLOCKS, not seconds: the quorum is re-derived once per
# round, so a fixed number of committed blocks is the honest budget and
# it holds on any machine at any speed. pump_to_height fails on a real
# stall, so a chain that has stopped is caught there, not here.
q_seen=0
q_rounds=0
while [ "$q_rounds" -lt $(( 2 * E_LEN )) ]; do
    if grep -q "quorum=$EXPECT_Q)" "$BASE_DIR/node1/nodus.log" 2>/dev/null; then
        q_seen=1; break
    fi
    pump_to_height $(( $(head_height) + 1 ))
    q_rounds=$(( q_rounds + 1 ))
done
[ "$q_seen" -eq 1 ] || fail "dynamic quorum never reached $EXPECT_Q after grow \
(last seen: $(grep -o 'quorum=[0-9]*' "$BASE_DIR/node1/nodus.log" | tail -1))"
ok "dynamic quorum is $EXPECT_Q, matching the 9-member snapshot"

GROWN_SNAP_HASH=$(sqlite3 "$(node1_db)" "SELECT hex(snapshot_hash) FROM \
    validator_set_snapshots WHERE epoch_start = $grown_epoch;")

# ── F. shrink: TARGET_ACTIVE_COUNT = 7 ──────────────────────────────

H=$(head_height)
EFF2=$(( ((H + 2 * E_LEN) / E_LEN + 1) * E_LEN ))
info "proposing TARGET_ACTIVE_COUNT=7 effective=$EFF2 (head=$H)"
"$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
    -i "$BASE_DIR/node1/identity" chain-config propose \
    --param TARGET_ACTIVE_COUNT --value 7 --effective "$EFF2" \
    > "$BASE_DIR/cc_shrink.log" 2>&1 || fail "propose shrink (see cc_shrink.log)"

info "pumping past the governed boundary and waiting for a 7-member snapshot"
shrunk_epoch=""
# Same derivation as the grow wait above — a flat wall clock under-budgets
# the distance at the harness's real pump rate.
# Same distance-based wait as the grow above — no wall clock.
shrink_target=$(( EFF2 + E_LEN ))
while [ "$(head_height)" -lt "$shrink_target" ]; do
    shrunk_epoch=$(sqlite3 "$(node1_db)" "SELECT epoch_start FROM \
        validator_set_snapshots WHERE active_count = 7 \
        AND epoch_start > $grown_epoch ORDER BY epoch_start LIMIT 1;")
    [ -n "$shrunk_epoch" ] && break
    pump_to_height $(( $(head_height) + E_LEN ))
done
[ -n "$shrunk_epoch" ] || shrunk_epoch=$(sqlite3 "$(node1_db)" \
    "SELECT epoch_start FROM validator_set_snapshots WHERE active_count = 7 \
     AND epoch_start > $grown_epoch ORDER BY epoch_start LIMIT 1;")
[ -n "$shrunk_epoch" ] || fail "no post-grow 7-member snapshot appeared even \
though the chain reached height $(head_height) (>= $shrink_target) — the \
governed shrink did not happen"
info "7-member snapshot for epoch $shrunk_epoch"
[ $(( shrunk_epoch % E_LEN )) -eq 0 ] || \
    fail "shrink landed at epoch_start=$shrunk_epoch, not an epoch boundary"
[ "$shrunk_epoch" -ge "$EFF2" ] || \
    fail "set shrank at epoch $shrunk_epoch, BEFORE the governed effective height $EFF2"

pump_to_height $(( shrunk_epoch + 3 ))
assert_snapshot_series_sane "F/shrunk"
assert_snapshots_identical "F/shrunk"
assert_state_root_identical "F/shrunk"
assert_block_identity_identical "F/shrunk"

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
ok "ELIGIBLE pair keeps its bond"

# AUTHORITY: a demoted validator must not remain in the authoritative
# set, and an ACTIVE one must be in it. The snapshot — not the row
# status — is what the QC is verified against.
assert_status_matches_epoch_snapshot "F/shrunk"

# And the shrink itself must have dropped exactly two seats: the epoch
# that first held 7 after the grow carries seven members, no more.
sc7=$(sqlite3 "$(node1_db)" "SELECT active_count FROM \
    validator_set_snapshots WHERE epoch_start = $shrunk_epoch;")
[ "$sc7" -eq 7 ] || fail "epoch-$shrunk_epoch snapshot has active_count=$sc7, expected 7"
ok "the governed shrink dropped exactly 2 seats at epoch $shrunk_epoch"

# HISTORY: every snapshot committed before the shrink must still read
# back byte-identically. A later committed set may never rewrite an
# earlier one.
NOW_SERIES=$(sqlite3 "$(node1_db)" "SELECT epoch_start || '|' || \
    active_count || '|' || hex(snapshot_hash) FROM validator_set_snapshots \
    WHERE epoch_start <= $(echo "$PRE_GROW_SERIES" | tail -1 | cut -d'|' -f1) \
    ORDER BY epoch_start;")
[ "$NOW_SERIES" = "$PRE_GROW_SERIES" ] || {
    echo "--- before grow:"; echo "$PRE_GROW_SERIES"
    echo "--- now:";         echo "$NOW_SERIES"
    fail "a historical validator-set snapshot changed"
}
STILL_GROWN=$(sqlite3 "$(node1_db)" "SELECT hex(snapshot_hash) FROM \
    validator_set_snapshots WHERE epoch_start = $grown_epoch;")
[ "$STILL_GROWN" = "$GROWN_SNAP_HASH" ] || \
    fail "the 9-member snapshot for epoch $grown_epoch changed after the shrink"
ok "historical snapshots (incl. the 9-member epoch $grown_epoch) are unchanged"

# ── G. crash injection across a boundary ────────────────────────────

H=$(head_height)
NEXT_B=$(( (H / E_LEN + 1) * E_LEN ))
victim=4
victim_pid=$(pgrep -f "node$victim/identity" | head -1)
[ -n "$victim_pid" ] || fail "cannot find node$victim pid"
info "killing node$victim (pid $victim_pid) before boundary $NEXT_B (head=$H)"
kill -9 "$victim_pid"
# A committee member is deliberately dead across this stretch, so each
# round waits out its missing vote and blocks come roughly half as fast
# (measured ~63 s vs ~37 s). No special budget is needed: pump_to_height
# asserts PROGRESS, not speed, so a degraded-but-advancing cluster passes
# unchanged and only a genuine stall fails.
pump_to_height $(( NEXT_B + 2 ))
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
stagef_sentinel ASSERT_RUN
assert_snapshot_series_sane "G/crash-recovery"
assert_snapshots_identical "G/crash-recovery"
assert_state_root_identical "G/crash-recovery"
assert_block_identity_identical "G/crash-recovery"
assert_status_matches_epoch_snapshot "G/crash-recovery"

stagef_sentinel PASS
echo ""
echo "[PASS] 7→9→7 dynamic validator set: joins left DISCOVER, snapshots,"
echo "       governed boundary flips, membership, dynamic quorum, bonds,"
echo "       historical immutability, state_root, block identity and crash"
echo "       recovery all identical across nodes"
