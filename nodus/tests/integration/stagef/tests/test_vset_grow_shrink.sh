#!/usr/bin/env bash
#
# Stage F test — Ledger V2 S3: dynamic validator set, 7 → 9 → 7.
#
# REQUIRES a SHORT-EPOCH nodus build. The harness binaries must be
# compiled with:
#     -DDNAC_EPOCH_LENGTH=<E>
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=<G>
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=<any>
# with STAGEF_CC_GRACE_SAFETY=<G> exported to match the SAFETY define.
#
# O15P — <G> NO LONGER HAS TO EQUAL <E>. It used to, because the
# effective-height arithmetic below ignored the grace and only worked
# while grace <= 2 * epoch; it now reads STAGEF_CC_GRACE_SAFETY. Pick <G>
# for RUNTIME, not for correctness: the scenario has to drive the chain
# past the governed boundary twice, so a grace of 24 * <E> (production's
# ratio) means a very long run. The ERGONOMIC grace is not used by this
# scenario at all — TARGET_ACTIVE_COUNT is a SAFETY parameter.
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
#   G. dead EPOCH LEADER: derive the validator that leads the next
#      boundary epoch from the frozen snapshot, kill -9 exactly that
#      node, and require the chain to ROTATE THE VIEW past it — proven
#      by the P3 deadman firing, by a completed view change, and by no
#      block in that epoch carrying the dead node as proposer — then
#      restart it and assert identical snapshots + state_root + block
#      identity after resync
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

# THE REFERENCE NODE — the node every single-node read goes through.
#
# Sections A-F read the chain through node1 because nothing is dead yet.
# Section G kills a node that it DERIVES, and that node can be node1. A
# single-node read against a corpse is not a failure that announces
# itself: `head_height` would return the dead node's frozen tip, the pump
# would report a stall on a chain that is advancing fine, and — worst —
# G's catch-up loop compares the victim's height against `head_height`,
# so with victim == node1 both sides would read the SAME database and the
# comparison would be trivially true the instant it ran.
#
# So every such read goes through $REF_NODE, which G re-points to a node
# it has proven is alive and is not the victim BEFORE the kill. It stays
# 1 for the whole of A-F, so those sections behave exactly as before.
REF_NODE=1

# The validator-set snapshot wire geometry (VSET_HDR_LEN, VSET_ENTRY_LEN,
# VSET_VOTER_ID_LEN, VSET_PUBKEY_LEN) and the leader derivation that reads
# entry k positionally now live in stagef_env.sh, because
# test_view_change_fork.sh derives its victim with the SAME rule and a
# second copy of a consensus rule in shell is how these two scenarios
# drifted apart. Behaviour here is unchanged; see stagef_leader_entry.

fail() { echo "[FAIL] $*" >&2; exit 1; }
info() { echo "[info] $*"; }
ok()   { echo "[ok] $*"; }

# ── helpers ─────────────────────────────────────────────────────────
#
# running_nodes, ref_db, node_view, cluster_view_max, log_count and
# node_pubkey_hex were MOVED to stagef_env.sh (2026-09-02) so
# test_view_change_fork.sh derives its victim through the same code
# instead of a copy. Same names, same arguments, same return contracts —
# nothing in this scenario calls them differently.

head_height() {
    local db; db=$(ref_db)
    sqlite3 "$db" "SELECT COALESCE(MAX(height),0) FROM blocks;"
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
    # The sink is a DESTINATION ADDRESS read from a file, so it stays
    # valid whether or not that node is running — but it is re-pointed
    # with everything else so no node1 dependency is left to reason about.
    local sink; sink=$(cat "$BASE_DIR/node$REF_NODE/identity/nodus.fp")
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
    sqlite3 "$(ref_db)" "SELECT CASE WHEN instr(hex(snapshot_blob), \
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
        have=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM \
            validator_set_snapshots WHERE epoch_start = $e;")
        if [ "$have" != "1" ]; then tries=$((tries + 1)); sleep 3; continue; fi

        a_missing=0; e_present=0
        while read -r pk; do
            [ -z "$pk" ] && continue
            [ "$(snapshot_contains "$e" "$pk")" = "1" ] || a_missing=$((a_missing + 1))
        done <<EOF
$(sqlite3 "$(ref_db)" "SELECT hex(pubkey) FROM validators WHERE status = 0;")
EOF
        while read -r pk; do
            [ -z "$pk" ] && continue
            [ "$(snapshot_contains "$e" "$pk")" = "0" ] || e_present=$((e_present + 1))
        done <<EOF
$(sqlite3 "$(ref_db)" "SELECT hex(pubkey) FROM validators WHERE status = 4;")
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
    local rows; rows=$(sqlite3 "$(ref_db)" \
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
rows=$(sqlite3 "$(ref_db)" \
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
        bal=$(sqlite3 "$(ref_db)" "SELECT COALESCE(SUM(amount),0) FROM \
            utxo_set WHERE owner = '$fp';" 2>/dev/null || echo 0)
        if [ "${bal:-0}" -ge "$BOND_RAW" ]; then committed=1; break; fi
    done
    [ "$committed" -eq 1 ] || fail "node$n funding not committed (bal=${bal:-0}, send ok=$ok_send)"
done
assert_state_root_identical "C/funding"

# ── D. stake both node identities ───────────────────────────────────

for n in 8 9; do
    info "staking node$n identity"
    "$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF_NODE")" \
        -i "$BASE_DIR/node$n/identity" stake --commission $((500 + n)) \
        > "$BASE_DIR/stake_node$n.log" 2>&1 \
        || fail "nodus-cli stake for node$n (see stake_node$n.log)"
    sleep 8
done

vcount=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM validators;")
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
    got=$(sqlite3 "$(ref_db)" \
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
PRE_GROW_SERIES=$(sqlite3 "$(ref_db)" "SELECT epoch_start || '|' || \
    active_count || '|' || hex(snapshot_hash) FROM validator_set_snapshots \
    ORDER BY epoch_start;")

# A chain-config proposal is a fee-paying TX like any other
# (nodus_witness_verify.c: committed_fee >= DNAC_MIN_FEE_RAW), and the
# proposer here is node1's WITNESS identity, not the harness user. Fund
# it from this scenario rather than inheriting a balance an earlier
# alphabetically-ordered scenario happened to leave behind — this
# scenario has to stand on its own when run in isolation.
#
# The proposer identity stays node1's DELIBERATELY: it is the identity
# this block funds, and E/F both run before section G kills anything, so
# REF_NODE is still 1 here. Only the CONNECTION target is routed through
# $REF_NODE, for consistency with every other CLI call.
V0_FP=$(cat "$BASE_DIR/node1/identity/nodus.fp")
info "funding node1 witness identity ${V0_FP:0:16}… for the propose fees"
stagef_dna -q dna sync > "$BASE_DIR/vset_cc_fund.log" 2>&1 || true
stagef_dna -q dna send "$V0_FP" 100000000 "cc-fee" \
    >> "$BASE_DIR/vset_cc_fund.log" 2>&1 || true
cc_funded=0
for _ in $(seq 1 15); do
    sleep 4
    bal=$(sqlite3 "$(ref_db)" "SELECT COALESCE(SUM(amount),0) FROM \
        utxo_set WHERE owner = '$V0_FP';" 2>/dev/null || echo 0)
    if [ "${bal:-0}" -ge 100000000 ]; then cc_funded=1; break; fi
done
[ "$cc_funded" -eq 1 ] || fail "node1 witness identity not funded (bal=${bal:-0})"
ok "node1 witness identity funded (${bal} raw)"

H=$(head_height)
# ── effective: a boundary far enough out to clear THE GRACE plus one
# full epoch. O15P — this now READS the grace.
#
# WHAT WAS WRONG. The comment here always claimed the formula cleared the
# grace; the formula was `((H + 2*E_LEN) / E_LEN + 1) * E_LEN` and never
# mentioned it. It happened to be right only while grace <= 2 * epoch,
# which is why the header above demanded GRACE_SAFETY_BLOCKS == E_LEN.
# The moment the two differ the arithmetic breaks, and the chain — which
# is correct — refuses the proposal: measured at epoch 7 / safety 21,
# this proposed effective=21 from head=6 against a requirement of
# commit + grace = 28.
#
# WHY THAT MATTERED BEYOND ONE RED SCENARIO. Production is epoch 720 with
# SAFETY grace 17280, i.e. 24x the epoch — a relationship this scenario
# could not express at all, so the governed path had only ever been
# exercised at grace == epoch, a shape production does not have.
#
# TARGET_ACTIVE_COUNT is a SAFETY parameter — verified, not assumed:
# nodus_chain_config_grace_for_param maps CC_PARAM_TARGET_ACTIVE to
# DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS. So SAFETY is the grace to clear,
# and STAGEF_CC_GRACE_SAFETY is the variable that mirrors it
# (stagef_env.sh already exports it; this file simply never read it).
#
# The chain's rule is `effective >= commit_block + grace`, and the commit
# lands a block or two after H, so clear the grace from H and then round
# UP to the next boundary — the extra epoch is the margin that keeps the
# boundary strictly after the effective height.
G_SAFETY="${STAGEF_CC_GRACE_SAFETY:?STAGEF_CC_GRACE_SAFETY unset — the effective height cannot clear a grace it cannot read}"
EFF=$(( ((H + G_SAFETY + E_LEN) / E_LEN + 1) * E_LEN ))
info "proposing TARGET_ACTIVE_COUNT=9 effective=$EFF (head=$H, safety grace=$G_SAFETY, epoch=$E_LEN)"
"$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF_NODE")" \
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
    grown_epoch=$(sqlite3 "$(ref_db)" "SELECT epoch_start FROM \
        validator_set_snapshots WHERE active_count = 9 \
        ORDER BY epoch_start LIMIT 1;")
    [ -n "$grown_epoch" ] && break
    pump_to_height $(( $(head_height) + E_LEN ))
done
[ -n "$grown_epoch" ] || grown_epoch=$(sqlite3 "$(ref_db)" \
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

sc=$(status_counts "$REF_NODE")
info "statuses after grow: $sc"
a9=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM validators WHERE status = 0;")
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
$(sqlite3 "$(ref_db)" "SELECT hex(pubkey) FROM validators WHERE status = 0;")
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
    if grep -q "quorum=$EXPECT_Q)" "$BASE_DIR/node$REF_NODE/nodus.log" 2>/dev/null; then
        q_seen=1; break
    fi
    pump_to_height $(( $(head_height) + 1 ))
    q_rounds=$(( q_rounds + 1 ))
done
[ "$q_seen" -eq 1 ] || fail "dynamic quorum never reached $EXPECT_Q after grow \
(last seen: $(grep -o 'quorum=[0-9]*' "$BASE_DIR/node$REF_NODE/nodus.log" | tail -1))"
ok "dynamic quorum is $EXPECT_Q, matching the 9-member snapshot"

GROWN_SNAP_HASH=$(sqlite3 "$(ref_db)" "SELECT hex(snapshot_hash) FROM \
    validator_set_snapshots WHERE epoch_start = $grown_epoch;")

# ── F. shrink: TARGET_ACTIVE_COUNT = 7 ──────────────────────────────

H=$(head_height)
# Same rule as the grow proposal above — see the reasoning there. Also a
# SAFETY parameter, so also the SAFETY grace.
EFF2=$(( ((H + G_SAFETY + E_LEN) / E_LEN + 1) * E_LEN ))
info "proposing TARGET_ACTIVE_COUNT=7 effective=$EFF2 (head=$H, safety grace=$G_SAFETY, epoch=$E_LEN)"
"$NODUS_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF_NODE")" \
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
    shrunk_epoch=$(sqlite3 "$(ref_db)" "SELECT epoch_start FROM \
        validator_set_snapshots WHERE active_count = 7 \
        AND epoch_start > $grown_epoch ORDER BY epoch_start LIMIT 1;")
    [ -n "$shrunk_epoch" ] && break
    pump_to_height $(( $(head_height) + E_LEN ))
done
[ -n "$shrunk_epoch" ] || shrunk_epoch=$(sqlite3 "$(ref_db)" \
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

sc=$(status_counts "$REF_NODE")
info "statuses after shrink: $sc"
el=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM validators WHERE status = 4;")
ac=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM validators WHERE status = 0;")
[ "$el" -eq 2 ] || fail "expected 2 ELIGIBLE after shrink, got: $sc"
[ "$ac" -eq 7 ] || fail "expected 7 ACTIVE after shrink, got: $sc"
# Bond preserved on the ELIGIBLE pair — never destroyed or unlocked.
badbond=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM validators \
    WHERE status = 4 AND self_stake < $BOND_RAW;")
[ "$badbond" -eq 0 ] || fail "an ELIGIBLE validator lost its bond"
ok "ELIGIBLE pair keeps its bond"

# AUTHORITY: a demoted validator must not remain in the authoritative
# set, and an ACTIVE one must be in it. The snapshot — not the row
# status — is what the QC is verified against.
assert_status_matches_epoch_snapshot "F/shrunk"

# And the shrink itself must have dropped exactly two seats: the epoch
# that first held 7 after the grow carries seven members, no more.
sc7=$(sqlite3 "$(ref_db)" "SELECT active_count FROM \
    validator_set_snapshots WHERE epoch_start = $shrunk_epoch;")
[ "$sc7" -eq 7 ] || fail "epoch-$shrunk_epoch snapshot has active_count=$sc7, expected 7"
ok "the governed shrink dropped exactly 2 seats at epoch $shrunk_epoch"

# HISTORY: every snapshot committed before the shrink must still read
# back byte-identically. A later committed set may never rewrite an
# earlier one.
NOW_SERIES=$(sqlite3 "$(ref_db)" "SELECT epoch_start || '|' || \
    active_count || '|' || hex(snapshot_hash) FROM validator_set_snapshots \
    WHERE epoch_start <= $(echo "$PRE_GROW_SERIES" | tail -1 | cut -d'|' -f1) \
    ORDER BY epoch_start;")
[ "$NOW_SERIES" = "$PRE_GROW_SERIES" ] || {
    echo "--- before grow:"; echo "$PRE_GROW_SERIES"
    echo "--- now:";         echo "$NOW_SERIES"
    fail "a historical validator-set snapshot changed"
}
STILL_GROWN=$(sqlite3 "$(ref_db)" "SELECT hex(snapshot_hash) FROM \
    validator_set_snapshots WHERE epoch_start = $grown_epoch;")
[ "$STILL_GROWN" = "$GROWN_SNAP_HASH" ] || \
    fail "the 9-member snapshot for epoch $grown_epoch changed after the shrink"
ok "historical snapshots (incl. the 9-member epoch $grown_epoch) are unchanged"

# ── G. the epoch leader dies and the chain must ROTATE PAST IT ──────
#
# WHAT IT PROVES
#   That a chain whose EPOCH LEADER is killed recovers by rotating the
#   view. If this section failed, the false property would be: "a BFT
#   chain can make progress across an epoch boundary whose designated
#   leader is dead." Concretely it pins three things that are each
#   independently sufficient to expose the halt this scenario exists for:
#     1. some follower's demand-armed deadman (P3) actually FIRED;
#     2. a view change actually COMPLETED — the persisted, quorum-gated
#        current_view moved, and the cluster logged the completion;
#     3. no block in the dead leader's epoch carries it as proposer,
#        i.e. leadership genuinely moved to somebody else.
#   And then, as before, that the restarted node re-converges to
#   byte-identical snapshots / state_root / block identity.
#
#   ⚠ WHAT IT NO LONGER DOES: pass merely because the chain crossed the
#   boundary. It used to kill a HARDCODED node 4 and then assert only
#   that blocks kept coming. The leader for a block is
#   `(epoch + view) % n` over a committee ordered by stake DESC and then
#   by SHA3-512(0x02 ‖ pubkey ‖ state_seed) ASC within tied stake groups
#   (nodus_witness_committee.c:47-64,300-330). Every harness validator
#   posts the same 10M bond, so the whole committee is ONE tied group and
#   the rank is entirely state_seed-derived — over identities that are
#   generated fresh on every run. Node 4 was therefore the leader only by
#   luck, and "the chain crossed NEXT_B" is fully compatible with "the
#   victim was never the leader". The victim is now DERIVED.
#
#   ⚠ AND THE DERIVATION IS NO LONGER G's ALONE. Since 2026-09-02 the
#   geometry checks and the positional slice live in stagef_env.sh as
#   stagef_leader_entry, because test_view_change_fork.sh had the SAME
#   defect (hardcoded node 1) and fixing it by copying these eighty lines
#   would have re-created the drift that produced the defect. G still owns
#   everything around the call — the bounded snapshot re-read, the
#   two-attempt view pin, the REF_NODE re-point, the fingerprint
#   cross-check and every `fail` — so a change to the shared function can
#   only ever make the derivation refuse, never make G assert less.
#
# WHAT IT REQUIRES
#   Compile flags (the binary): the same short-epoch build the whole
#     scenario needs — -DDNAC_EPOCH_LENGTH=<E>,
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=<E>,
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=<E>. G adds NO compile
#     flag of its own: it needs no fault-injection build, and
#     -DQGP_FAULT_INJECT is NOT required.
#   Environment (the scripts): STAGEF_EPOCH_LENGTH=<E> exported BEFORE
#     stagef_up.sh, matching the binary. G adds no NODUS_FAULT_* or
#     STAGEF_* variable of its own.
#   State: sections A-F must have run in this process — G consumes the
#     9-bonded/7-active cluster they build and the head they leave.
#
# WHAT IT LEAVES BEHIND
#   A node that was kill -9'd and then restarted under a NEW pid (appended
#   to $BASE_DIR/pids.txt; its nodus.log is appended to, not truncated, so
#   it holds two runs). Which node that is VARIES PER RUN — it is derived,
#   so it is printed, and it may be node1. The chain is left a few blocks
#   past the boundary $NEXT_B, at a HIGHER current_view than it started
#   at (current_view never resets and is persisted per chain DB), and the
#   validator set is the post-shrink 7-active/2-eligible set from F.
#   Nothing is cleaned up: G is the last section of the last scenario.
#
# HOW IT CAN LIE
#   1. THE PUMP CANNOT SEE THIS HALT. pump_to_height fails on
#      PUMP_STALL_ROUNDS=8 consecutive no-progress rounds (~5 min at the
#      measured ~37 s/round), while the deadman fires at 15 s and a
#      rotation converges well inside a minute. So pump success is NOT
#      evidence and is not asserted as such — the three positive checks
#      below are. If they are ever deleted, G silently returns to being a
#      liveness test that cannot observe the thing it is named for.
#   2. STALE LOG LINES. Every log line G looks for also appears earlier in
#      a full run — test_view_change_fork deliberately forces view changes
#      and sorts BEFORE this scenario. Presence proves nothing; G compares
#      BEFORE/AFTER counts and requires an INCREASE. A rewrite that
#      "simplifies" these to `grep -q` makes all of them vacuously true.
#   3. VIEW DRIFT REDIRECTS LEADERSHIP. The derivation is only as good as
#      the view it used. The kill degrades every round to ~63 s, so a
#      round timeout between the read and the boundary rotates the view
#      and hands leadership to a DIFFERENT node — the victim is then
#      merely a dead follower, P3 never fires, and G FAILS ON A HEALTHY
#      CHAIN. That residual is NOT closed here: it cannot be, from outside
#      the node. It is made DIAGNOSABLE instead — the pre-kill and
#      post-boundary views are printed in the failure text, so a redirect
#      is visible at a glance rather than looking like a consensus bug.
#      The window before the kill IS closed, by re-reading and re-deriving.
#   4. A SKIP WOULD HIDE ALL OF IT. rc=99 is BANNED in this section.
#      genesis_protocol.sh treats 99 as SKIP and exits 0 with SKIPs
#      allowed (:7,:15,:97-99), and a SKIP needs no ASSERT_RUN sentinel —
#      so encoding "snapshot row missing" / "view moved twice" / "victim
#      not derivable" as a skip would make this coverage silently absent
#      while the suite reported green. Every precondition here FAILS.
#   5. A DEAD REFERENCE NODE. Every single-node read goes through
#      $REF_NODE, which is re-pointed off the victim before the kill. If a
#      future edit reintroduces a raw node1 read into this section, it can
#      read a frozen database and report a stall — or, in the catch-up
#      loop, compare the victim against itself and pass instantly.
#
# A NOTED FALSE-*FAIL* RESIDUAL (not a lie-path — it cannot produce a
# green): the pump submits through dna-connect-cli, and the victim is one
# of the nodes that CLI may connect to. stagef_up.sh writes ALL
# $STAGEF_COMMITTEE_SIZE nodes into bootstrap_nodes (:75-79,86), not just
# node1, and stagef_dna scrubs known_nodes/preferred_node before every
# call (stagef_env.sh:100-107) so the list is rebuilt from the config each
# time — so the CLI has failover candidates rather than one pinned target.
# The pre-existing section killed node 4, which was equally in that list,
# and the pump kept working; that is the evidence this is tolerated. What
# is NOT verifiable from this script is the CLI's failover ORDER, so if
# the pump ever stalls immediately after the kill with the cluster
# otherwise healthy, suspect this before suspecting consensus.
#
# NEVER TUNE A TIMEOUT TO MAKE THIS PASS. If G fails while the chain is
# healthy and still advancing, the wait is mis-expressed, not too short —
# see lie-path 3 first. This bug was very nearly buried by a raised pump
# budget.

H=$(head_height)
NEXT_B=$(( (H / E_LEN + 1) * E_LEN ))

# ── G.1 the frozen snapshot that governs the boundary epoch ─────────
#
# The set for epoch NEXT_B was frozen at the PREVIOUS boundary by
# nodus_witness_vset_commit_next, so by now it is already committed and
# G must NOT pump to produce it — pumping is exactly what would carry the
# head past the boundary this section needs to arrive at with a dead
# leader. A bounded re-read covers a read racing the writer on one node;
# an absent row after that is a real fault and FAILS.
snap_have=0
for _ in $(seq 1 10); do
    snap_have=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM \
        validator_set_snapshots WHERE epoch_start = $NEXT_B;" 2>/dev/null || echo 0)
    [ "${snap_have:-0}" = "1" ] && break
    sleep 2
done
[ "${snap_have:-0}" = "1" ] || fail "no committed validator-set snapshot for \
the boundary epoch $NEXT_B (head=$H) — the leader for that epoch cannot be \
derived, and guessing one would make this whole section meaningless"

# ── G.2 derive the victim: the validator that LEADS epoch NEXT_B ─────
#
# Leader rank = (epoch + view) % n, with epoch the epoch ORDINAL and n the
# committee size (nodus_witness_bft.c:1195-1198, called at :1284). NEXT_B
# is a boundary multiple, so its epoch ordinal is NEXT_B / E_LEN and that
# one rank leads EVERY block of [NEXT_B, NEXT_B + E_LEN).
#
# The arithmetic, the snapshot geometry checks and the positional slice
# are stagef_leader_entry's (stagef_env.sh) — the SAME code
# test_view_change_fork.sh derives its victim with. It prints
# "<rank> <active_count> <pubkey_hex> <voter_id_hex>" and returns 1 with a
# precise [FAIL] on stderr for every fault it can see, which is why the
# `|| exit 1` below adds no message of its own: the diagnosis is already
# printed and a second line would only bury it.
#
# The view is re-read and the whole derivation re-run below if it moved.
derive_view=""
victim=""
DERIVED_OK=0
for attempt in 1 2; do
    # Read the view from node1, which is alive for the whole of this
    # derivation — nothing has been killed yet.
    derive_view=$(node_view 1) || \
        fail "cannot read current_view from node1's pbft_state — the leader \
rank is (epoch + view) % n and is underivable without it"

    LEADER_LINE=$(stagef_leader_entry "$(ref_db)" "$NEXT_B" "$E_LEN" \
        "$derive_view") || exit 1
    read -r LEADER_IDX ACTIVE_COUNT LEADER_PK LEADER_WID <<< "$LEADER_LINE"

    # Which of our nodes is that? Matched on the RAW PUBKEY, the same
    # byte string node_pubkey_hex reads out of the node's own identity.
    victim=""
    for n in $(running_nodes); do
        [ "$(node_pubkey_hex "$n")" = "$LEADER_PK" ] && { victim="$n"; break; }
    done
    [ -n "$victim" ] || fail "the epoch-$NEXT_B leader (rank $LEADER_IDX of \
$ACTIVE_COUNT, view $derive_view) is not any of this harness's nodes — the \
snapshot names a validator this scenario did not create"

    # The reference node: alive, and NOT the corpse. Lowest running index
    # that is not the victim, so it is deterministic rather than whichever
    # one the shell happened to list first.
    REF_NODE=""
    for n in $(running_nodes); do
        [ "$n" = "$victim" ] || { REF_NODE="$n"; break; }
    done
    [ -n "$REF_NODE" ] || fail "no running node other than the victim"

    # RE-READ THE VIEW IMMEDIATELY BEFORE THE KILL. A round timeout in the
    # window between deriving and killing rotates the view and silently
    # hands leadership to somebody else, which would make the kill land on
    # an innocent follower and the whole section prove nothing.
    view_now=$(node_view 1) || fail "cannot re-read current_view before the kill"
    if [ "$view_now" = "$derive_view" ]; then DERIVED_OK=1; break; fi
    info "view moved $derive_view -> $view_now during derivation (attempt \
$attempt) — re-deriving the leader"
done
[ "$DERIVED_OK" -eq 1 ] || fail "current_view moved on both derivation \
attempts (last seen $derive_view -> $view_now) — the epoch leader cannot be \
pinned down long enough to kill it. This is a FAILURE, never a skip: a \
skipped G is coverage that did not happen."

info "epoch $NEXT_B leader = rank $LEADER_IDX of $ACTIVE_COUNT at view \
$derive_view -> node$victim (witness id ${LEADER_WID:0:16}…)"
info "reference node for every single-node read is now node$REF_NODE"

# Cross-check the two independent derivations of the same 32 bytes: the
# snapshot's voter_id field (sliced positionally out of the blob) and the
# first half of the node's own fingerprint file. Both are
# SHA3-512(pubkey)[0..31] — nodus_chain_config_derive_witness_id vs
# nodus_fingerprint (nodus_sign.c:241-245) — and it is also exactly what
# the node writes into blocks.proposer_id (nodus_witness.c:856-858,
# NODUS_T3_WITNESS_ID_LEN=32). If these disagree, the byte offsets above
# are wrong and every conclusion drawn from them is worthless.
VICTIM_FP_WID=$(cut -c1-$(( VSET_VOTER_ID_LEN * 2 )) \
    < "$BASE_DIR/node$victim/identity/nodus.fp" | tr '[:lower:]' '[:upper:]')
[ "$VICTIM_FP_WID" = "$LEADER_WID" ] || \
    fail "snapshot entry $LEADER_IDX voter_id ($LEADER_WID) does not match \
node$victim's own fingerprint prefix ($VICTIM_FP_WID) — the positional read \
of the snapshot blob is addressing the wrong bytes"

# ── G.3 baselines, then kill the leader ─────────────────────────────
#
# Counted BEFORE the kill because all three log lines already exist in a
# full run (test_view_change_fork rotates the view and sorts earlier), so
# only a DELTA is evidence. See lie-path 2.
P3_BEFORE=$(log_count "P3 committed tip frozen")
VCQ_BEFORE=$(log_count "view change quorum! new view:")
VCI_BEFORE=$(log_count "initiated view change to view")
VIEW_BEFORE=$(cluster_view_max "$victim") || \
    fail "cannot read current_view from any surviving node"

# THE DERIVATION NODE MUST NOT BE BEHIND THE CLUSTER.
#
# The loop above pinned the view by re-reading node1. That closes the
# window on node1 — but this baseline reads the MAX across the survivors,
# and if a survivor already holds a HIGHER view then a rotation has
# completed that node1 has not adopted yet, so the rank derived from
# node1's view is stale and the kill would land on a follower rather than
# on the leader. That is lie-path 3, except this instance happens BEFORE
# the kill and is therefore closable — so it is closed, not documented.
# Same class as "the view moved on both attempts": a FAILURE, never a
# skip.
[ "$VIEW_BEFORE" -eq "$derive_view" ] || \
    fail "the leader was derived from node1's view ($derive_view) but a \
surviving node already holds view $VIEW_BEFORE — a rotation has completed \
that node1 has not adopted, so rank $LEADER_IDX no longer identifies the \
epoch-$NEXT_B leader and killing node$victim would prove nothing"

victim_pid=$(pgrep -f "node$victim/identity" | head -1)
[ -n "$victim_pid" ] || fail "cannot find node$victim pid"
info "killing the epoch leader node$victim (pid $victim_pid) before boundary \
$NEXT_B (head=$H, view=$VIEW_BEFORE, P3 fires so far=$P3_BEFORE)"
kill -9 "$victim_pid"

# The DESIGNATED LEADER is deliberately dead across this stretch, so the
# chain cannot make a single block until the view rotates away from it,
# and every round after that still waits out the missing vote (measured
# ~63 s vs ~37 s). No special budget is needed and none may be added:
# pump_to_height asserts PROGRESS, not speed, so a degraded-but-advancing
# cluster passes unchanged and only a genuine stall fails. Crossing the
# boundary is a PRECONDITION for the assertions below, NOT the assertion.
pump_to_height $(( NEXT_B + 2 ))
info "boundary $NEXT_B crossed without its designated leader node$victim"

# The scenario has reached the thing it exists to check. Recorded before
# the assertions run so that a failure below is reported as a consensus
# failure rather than a broken fixture.
stagef_sentinel ASSERT_RUN

# ── G.4 POSITIVE ROTATION EVIDENCE ──────────────────────────────────
#
# Captured before the restart, so it can only describe the window in
# which the leader was actually dead.
VIEW_AFTER=$(cluster_view_max "$victim") || \
    fail "cannot read current_view from any surviving node after the boundary"
P3_AFTER=$(log_count "P3 committed tip frozen")
VCQ_AFTER=$(log_count "view change quorum! new view:")
VCI_AFTER=$(log_count "initiated view change to view")

# (a) A follower's demand-armed deadman FIRED. Nothing else in the system
#     can start a round when the leader is dead: only the leader leaves
#     IDLE unprompted, so without P3 the chain has no event at all and
#     sits frozen for the whole epoch (nodus_witness_bft.c:8834-8853,
#     stderr, captured into node$n/nodus.log by the harness).
[ "$P3_AFTER" -gt "$P3_BEFORE" ] || \
    fail "the P3 demand-armed deadman never fired while the epoch leader \
node$victim was dead ($P3_BEFORE -> $P3_AFTER across all node logs). The \
chain reached $(head_height), but no follower ever noticed a frozen tip with \
live demand — which is the halt this section exists to catch. Views: \
$VIEW_BEFORE -> $VIEW_AFTER."

# (b) A view change actually COMPLETED. current_view has exactly three
#     message-driven writers — the view-change quorum
#     (nodus_witness_bft.c:7703), adopting a NEW_VIEW (:8196) and
#     adopting a PROPOSE's view (:5040). ONLY the first is backed by
#     a proven majority; the other two raise it on the sender's word,
#     so the LOG LINE below, not the number, is the real evidence.
#     Persisted per chain DB (nodus_witness_db_save_pbft_state,
#     :2122-2153), which is why it is read rather than assumed.
#
#     The quorum LOG LINE is required alongside the number, because the
#     number alone cannot say WHERE the rotation came from: only :7694
#     prints, and the node that printed it is by definition the one whose
#     quorum caused every other node's adoption. Requiring both means a
#     view inherited from an earlier scenario cannot stand in for one
#     this section caused.
[ "$VIEW_AFTER" -gt "$VIEW_BEFORE" ] || \
    fail "current_view did not advance while the epoch leader was dead \
($VIEW_BEFORE -> $VIEW_AFTER, max across the surviving nodes) — the chain \
crossed $NEXT_B without ever rotating away from node$victim, which means \
node$victim was not really leading it (see lie-path 3: a view drift after the \
kill redirects leadership). P3 fires: $P3_BEFORE -> $P3_AFTER."
[ "$VCQ_AFTER" -gt "$VCQ_BEFORE" ] || \
    fail "current_view moved ($VIEW_BEFORE -> $VIEW_AFTER) but no node \
logged a view-change QUORUM in this window (initiations: $VCI_BEFORE -> \
$VCI_AFTER) — a rotation that no quorum completed is not a recovery"
ok "view rotated $VIEW_BEFORE -> $VIEW_AFTER past the dead leader \
(P3 fires +$(( P3_AFTER - P3_BEFORE )), initiations \
+$(( VCI_AFTER - VCI_BEFORE )), quorums +$(( VCQ_AFTER - VCQ_BEFORE )))"

# (c) LEADERSHIP GENUINELY MOVED. Every block of [NEXT_B, NEXT_B+E_LEN)
#     has the same leader rank, so if the rotation had not happened the
#     dead node would be the proposer of record for all of them.
#     proposer_id is the 32-byte witness id (nodus_witness_db.c:606), the
#     same bytes as the snapshot voter_id matched above.
PROP_TOTAL=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM blocks \
    WHERE height >= $NEXT_B AND height < $(( NEXT_B + E_LEN ));")
PROP_VICTIM=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM blocks \
    WHERE height >= $NEXT_B AND height < $(( NEXT_B + E_LEN )) \
      AND hex(COALESCE(proposer_id, x'')) = '$LEADER_WID';")
# Non-vacuity FIRST: "no block names the victim" is trivially true of an
# empty range, and an empty range here would mean the boundary was never
# really crossed.
[ "${PROP_TOTAL:-0}" -ge 1 ] || \
    fail "no block at all in [$NEXT_B, $(( NEXT_B + E_LEN ))) on node$REF_NODE \
— the proposer check would have passed vacuously"
[ "${PROP_VICTIM:-0}" -eq 0 ] || \
    fail "$PROP_VICTIM of $PROP_TOTAL blocks in the dead leader's epoch still \
name node$victim as proposer — leadership never moved"
ok "all $PROP_TOTAL blocks in epoch $NEXT_B were proposed by somebody other \
than the dead leader node$victim"

# ── G.5 the corpse rejoins and re-converges ─────────────────────────

info "restarting node$victim"
node_dir="$BASE_DIR/node$victim"
# shellcheck disable=SC2086
"$NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
    -u "$(stagef_udp_port "$victim")" -t "$(stagef_tcp_port "$victim")" \
    -p "$(stagef_peer_port "$victim")" -C "$(stagef_chan_port "$victim")" \
    -W "$(stagef_witness_port "$victim")" \
    -i "$node_dir/identity" -d "$node_dir/data" \
    $SEEDS >> "$node_dir/nodus.log" 2>&1 &
echo $! >> "$BASE_DIR/pids.txt"

# ref_h comes from node$REF_NODE, which is NOT the victim — so this is a
# real comparison between two different databases.
#
# This guard is NEW because the hazard is new: the old section killed a
# hardcoded node 4, so head_height (node1) was always a different file.
# Now that the victim is DERIVED it can be node1, and without the
# re-pointing both sides of `vh >= ref_h` would read the SAME database
# and the loop would exit on its first iteration having proven nothing.
info "waiting for node$victim to catch up to node$REF_NODE"
t=0
while [ $t -lt 300 ]; do
    ref_h=$(head_height)
    vh=$(sqlite3 "$(stagef_node_chain_db "$victim")" \
        "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null || echo 0)
    [ "${vh:-0}" -ge "$ref_h" ] && break
    sleep 5; t=$((t + 5))
done
[ "${vh:-0}" -ge "$ref_h" ] || fail "node$victim did not catch up ($vh < $ref_h)"
assert_snapshot_series_sane "G/leader-recovery"
assert_snapshots_identical "G/leader-recovery"
assert_state_root_identical "G/leader-recovery"
assert_block_identity_identical "G/leader-recovery"
assert_status_matches_epoch_snapshot "G/leader-recovery"

stagef_sentinel PASS
echo ""
echo "[PASS] 7→9→7 dynamic validator set: joins left DISCOVER, snapshots,"
echo "       governed boundary flips, membership, dynamic quorum, bonds,"
echo "       historical immutability, state_root and block identity all"
echo "       identical across nodes — and the chain rotated the view past"
echo "       a DERIVED, deliberately killed epoch leader (node$victim,"
echo "       view $VIEW_BEFORE -> $VIEW_AFTER) and re-converged after it"
echo "       rejoined"
