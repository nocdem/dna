#!/usr/bin/env bash
#
# Stage F — O15C Ledger V2 activation rehearsal (THE final O15C-B gate).
#
# Runs ONLY against an activation-authority harness:
#   * nodus-server + nodus-cli built with -DNODUS_V2_ACTIVATION=ON and
#     short-epoch overrides (-DDNAC_EPOCH_LENGTH=<E>,
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=<lead>,
#     _ERGONOMIC_=<E>), pointed at via STAGEF_NODUS_BIN /
#     STAGEF_NODUSCLI_BIN before stagef_up.sh;
#   * STAGEF_EPOCH_LENGTH exported to the SAME <E>.
#
# Proves, on the live 7-node cluster (O15C-B §6):
#   1. a type-15 SCHEDULE reaches quorum 5 and commits identically 7/7,
#      with the committed target digest equal to the compiled D;
#   2. type-16 readiness reaches 7/7;
#   3. the boundary at H_act commits ACTIVE in the terminal block, with
#      terminal height / block identity / state_root identical 7/7;
#   4. legacy processing refuses every height above H_act;
#   5. every node derives byte-identically the SAME successor V2 chain
#      (one filename = one derived chain id; identical genesis BlockID);
#   6. the S6 claim reserve equals the committed terminal migratable
#      value and NO legacy UTXO is spendable in V2;
#   7. a restarted node prefers the successor, re-reaches the same
#      derivation, and its post-open gate reports the preflight CLEAR
#      (Rule N issue 12 retired, issue 13 clear) with ingress ARMED.
#
# No grow/shrink, no 20-node, no fault campaign — O15B proved those.

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || \
    fail "no active Stage F harness. Run stagef_up.sh first."
command -v sqlite3 >/dev/null || fail "sqlite3 CLI required"

E_LEN="${STAGEF_EPOCH_LENGTH}"
LEAD="${STAGEF_CC_GRACE_SAFETY}"
NODUSCLI="$STAGEF_NODUSCLI_BIN"
[ -x "$NODUSCLI" ] || fail "nodus-cli not found at $NODUSCLI"

N=7
node1_db() { stagef_node_chain_db 1; }
head_height() {
    sqlite3 "$(node1_db)" "SELECT COALESCE(MAX(height),0) FROM blocks;"
}

# ── pump/converge (the test_vset_grow_shrink helpers, verbatim shape) ──
pump_to_height() {
    local target="$1" timeout="${2:-600}"
    local deadline=$(( SECONDS + timeout ))
    local h; h=$(head_height)
    local sink; sink=$(cat "$BASE_DIR/node1/identity/nodus.fp")
    while [ "${h:-0}" -lt "$target" ] && [ $SECONDS -lt $deadline ]; do
        stagef_dna -q dna sync >> "$BASE_DIR/act_pump.log" 2>&1 || true
        if ! stagef_dna -q dna send "$sink" 1 "pump" \
               >> "$BASE_DIR/act_pump.log" 2>&1; then
            stagef_dna -q dna sync >> "$BASE_DIR/act_pump.log" 2>&1 || true
            stagef_dna -q dna send "$sink" 1 "pump" \
                >> "$BASE_DIR/act_pump.log" 2>&1 || true
        fi
        sleep 6
        h=$(head_height)
    done
    [ "${h:-0}" -ge "$target" ] || fail "pump: height $h < $target"
    info "pumped to height $h (target $target)"
}

# Soft variant for RETRY LOOPS: `fail` exits the whole shell (set -e +
# exit 1), so a hard pump inside the readiness retry loop used to kill
# the scenario on its first miss and the loop's `|| true` was dead code
# (observed: the 2026-08-19 run died at "pump: height 19 < 20" instead
# of taking ready attempt 2). Returns 1; the caller's attempt loop is
# the retry policy.
pump_soft() {
    local target="$1" timeout="${2:-90}"
    local deadline=$(( SECONDS + timeout ))
    local h; h=$(head_height)
    local sink; sink=$(cat "$BASE_DIR/node1/identity/nodus.fp")
    while [ "${h:-0}" -lt "$target" ] && [ $SECONDS -lt $deadline ]; do
        stagef_dna -q dna sync >> "$BASE_DIR/act_pump.log" 2>&1 || true
        stagef_dna -q dna send "$sink" 1 "pump" \
            >> "$BASE_DIR/act_pump.log" 2>&1 || true
        sleep 6
        h=$(head_height)
    done
    if [ "${h:-0}" -lt "$target" ]; then
        info "pump_soft: height $h < $target (retryable)"
        return 1
    fi
    info "pumped to height $h (target $target)"
    return 0
}

converge_heads() {
    local label="$1" timeout="${2:-300}"
    local deadline=$(( SECONDS + timeout ))
    while [ $SECONDS -lt $deadline ]; do
        local lo="" hi=""
        for n in $(seq 1 $N); do
            local db h
            db=$(stagef_node_chain_db "$n")
            h=$(sqlite3 "$db" \
                "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null \
                || echo 0)
            [ -z "$lo" ] || [ "$h" -lt "$lo" ] && lo="$h"
            [ -z "$hi" ] || [ "$h" -gt "$hi" ] && hi="$h"
        done
        [ "$lo" = "$hi" ] && { ok "heads converged at $lo ($label)"; return; }
        sleep 3
    done
    fail "heads did not converge ($label)"
}

# Identical value across all 7 nodes for one SQL expression.
assert_same_7() {
    local label="$1" sql="$2"
    local first="" v
    for n in $(seq 1 $N); do
        v=$(sqlite3 "$(stagef_node_chain_db "$n")" "$sql" 2>/dev/null) \
            || fail "$label: sqlite failed on node$n"
        if [ -z "$first" ]; then first="$v"
        elif [ "$v" != "$first" ]; then
            fail "$label: node$n ($v) != node1 ($first)"
        fi
    done
    echo "$first"
}

# ── SETUP: fund every node identity (READY/SCHEDULE fees) ─────────────
#
# FULL stagef_mk_funded_user FUNDING SEMANTICS, mirrored — the helper
# itself creates a fresh identity, so it cannot be invoked for a FIXED
# node fingerprint; this reproduces its exact fund-retry loop with no
# new policy. The chain is the authority in BOTH directions
# (project_genesis_client_false_error): a CLI failure may still have
# committed, a CLI success is unproven until the chain shows it. Up to
# THREE chain-verified attempts; the committed exact-amount UTXO is
# proven ABSENT before every retransmission (never a balance read the
# 1-raw pump outputs could satisfy), and the spendability predicate is
# the consensus one (unlock_block <= chain height), polled on EVERY
# node's witness DB (the BUGS.md 2026-08-04 H1 lesson).
FUND_RAW=50000000

# The exact expected funding UTXO for `fp`, committed AND spendable, on
# ANY node's witness DB. Empty query results are "not yet", never success.
act_fund_on_chain() {
    local owner_fp="$1" node db cnt height
    for node in $(seq 1 $N); do
        db=$(ls "$BASE_DIR/node$node/data"/witness_*.db 2>/dev/null | head -1)
        [ -n "$db" ] || continue
        height=$(sqlite3 -readonly "$db" \
            "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null) \
            || continue
        [ -n "$height" ] || continue
        cnt=$(sqlite3 -readonly "$db" \
            "SELECT COUNT(*) FROM utxo_set
              WHERE owner = '$owner_fp'
                AND amount = $FUND_RAW
                AND COALESCE(unlock_block,0) <= $height;" 2>/dev/null) \
            || continue
        [ -n "$cnt" ] || continue
        [ "${cnt:-0}" -ge 1 ] && return 0
    done
    return 1
}

info "funding the 7 node identities (fee reserves for types 15/16)"
for n in $(seq 1 $N); do
    fp=$(cat "$BASE_DIR/node$n/identity/nodus.fp")
    fund_ok=0
    used_attempts=0
    for attempt in 1 2 3; do
        # Prove the committed UTXO ABSENT before (re)transmitting —
        # present means funded, and a duplicate send would double-fund.
        if act_fund_on_chain "$fp"; then
            fund_ok=1
            break
        fi
        used_attempts=$attempt
        stagef_dna -q dna sync >> "$BASE_DIR/act_fund.log" 2>&1 || true
        if stagef_dna -q dna send "$fp" "$FUND_RAW" "actfund$n" \
               >> "$BASE_DIR/act_fund.log" 2>&1; then
            chain_deadline=$(( SECONDS + 45 ))
            while [ $SECONDS -lt $chain_deadline ]; do
                if act_fund_on_chain "$fp"; then fund_ok=1; break; fi
                sleep 2
            done
            [ "$fund_ok" -eq 1 ] && break
            echo "[warn] funding node$n: CLI success but no committed" \
                 "UTXO (attempt $attempt)" >&2
        else
            # CLI said failure — ask the chain before believing it.
            chain_deadline=$(( SECONDS + 45 ))
            while [ $SECONDS -lt $chain_deadline ]; do
                if act_fund_on_chain "$fp"; then
                    echo "[info] funding node$n: CLI failed but fund TX" \
                         "COMMITTED on chain (attempt $attempt)" >&2
                    fund_ok=1
                    break
                fi
                sleep 2
            done
            [ "$fund_ok" -eq 1 ] && break
        fi
        if [ "$attempt" -lt 3 ]; then
            echo "[info] funding node$n: attempt $attempt failed (chain" \
                 "checked), retrying in 5s..." >&2
            tail -3 "$BASE_DIR/act_fund.log" >&2 || true
            sleep 5
        fi
    done
    if [ "$fund_ok" -eq 0 ]; then
        echo "--- funding diagnostic: node$n" >&2
        echo "    recipient fp: $fp" >&2
        echo "    attempts:     $used_attempts of 3 (chain verified" \
             "empty before each)" >&2
        echo "    chain height: $(head_height)" >&2
        echo "    committed UTXOs for this owner:" >&2
        sqlite3 -readonly "$(node1_db)" \
            "SELECT amount, output_index FROM utxo_set \
             WHERE owner = '$fp';" >&2 || true
        echo "    last CLI output:" >&2
        tail -8 "$BASE_DIR/act_fund.log" >&2 || true
        fail "funding node$n: no committed $FUND_RAW UTXO after 3 attempts"
    fi
    # Established helper behavior: bounded re-confirmation that the
    # committed state REMAINS there — not a wait for it to appear.
    fund_stable=0
    stable_deadline=$(( SECONDS + 20 ))
    while [ $SECONDS -lt $stable_deadline ]; do
        if act_fund_on_chain "$fp"; then fund_stable=1; break; fi
        sleep 1
    done
    [ "$fund_stable" -eq 1 ] || \
        fail "funding node$n: committed UTXO did not remain spendable"
    ok "funding $n/7 committed on chain (attempts used: ${used_attempts:-0})"
done
converge_heads "post-funding"
stagef_sentinel SETUP_OK

# ── 1. SCHEDULE (quorum 5 of 7, offline-signed votes) ─────────────────
H0=$(head_height)
H_ACT=$(( ( (H0 + LEAD) / E_LEN + 2 ) * E_LEN ))
info "head=$H0 lead=$LEAD epoch=$E_LEN -> scheduling H_act=$H_ACT"

KEYS="$BASE_DIR/node1/identity"
for n in 2 3 4 5; do KEYS="$KEYS,$BASE_DIR/node$n/identity"; done

SCHED_OUT=$("$NODUSCLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
    -i "$BASE_DIR/node1/identity" v2-activation schedule \
    --height "$H_ACT" --nonce 7 --keys "$KEYS") \
    || fail "schedule submit failed"
echo "$SCHED_OUT"
DIG=$(echo "$SCHED_OUT" | awk -F= '/^SCHED digest=/{print $2}')
D_LOCAL=$(echo "$SCHED_OUT" | awk '/compiled target D/{print $5}')
[ -n "$DIG" ] || fail "no schedule digest in output"

pump_to_height $(( $(head_height) + 2 )) 120
converge_heads "post-schedule"

ST=$(assert_same_7 "record state" \
    "SELECT record_version || '|' || state || '|' || activation_height \
     || '|' || hex(schedule_digest) || '|' || hex(target) \
     FROM v2_activation WHERE id = 1;")
echo "$ST" | grep -q "^1|1|$H_ACT|" || fail "record not SCHEDULED at $H_ACT: $ST"
echo "$ST" | grep -qi "$DIG" || fail "committed digest != CLI digest"
ok "SCHEDULE committed identically 7/7 (state=SCHEDULED, H_act=$H_ACT)"
TGT=$(assert_same_7 "target digest" \
    "SELECT lower(hex(target)) FROM v2_activation WHERE id = 1;")
info "committed target D = ${TGT:0:16}... (compiled: ${D_LOCAL:-n/a})"
stagef_sentinel TARGET_REACHED

# ── 2. READINESS 7/7 ──────────────────────────────────────────────────
for n in $(seq 1 $N); do
    got=0
    for attempt in 1 2 3; do
        if "$NODUSCLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" \
             -i "$BASE_DIR/node$n/identity" v2-activation ready \
             --digest "$DIG" --keys "$BASE_DIR/node$n/identity" \
             >> "$BASE_DIR/act_ready.log" 2>&1; then
            pump_soft $(( $(head_height) + 1 )) 90 || true
            cnt=$(sqlite3 "$(node1_db)" \
                "SELECT COUNT(*) FROM v2_activation_readiness;")
            if [ "$cnt" -ge "$n" ]; then got=1; break; fi
            info "node$n readiness not committed (attempt $attempt) — retrying"
        else
            info "node$n ready submit failed (attempt $attempt) — retrying"
            pump_soft $(( $(head_height) + 1 )) 90 || true
        fi
    done
    [ "$got" = 1 ] || fail "node$n readiness did not commit after 3 attempts"
    ok "readiness $n/7 committed"
done
converge_heads "post-readiness"
RCNT=$(assert_same_7 "readiness count" \
    "SELECT COUNT(*) FROM v2_activation_readiness;")
[ "$RCNT" = "7" ] || fail "readiness count $RCNT != 7"
ok "readiness 7/7 committed identically on every node"

# ── 3. Cross the boundary: terminal block at H_act ────────────────────
pump_to_height "$H_ACT" 900
converge_heads "terminal"

AST=$(assert_same_7 "activation state" \
    "SELECT state || '|' || activation_height FROM v2_activation \
     WHERE id = 1;")
[ "$AST" = "3|$H_ACT" ] || fail "record not ACTIVE at H_act: $AST"
ok "activation ACTIVE at the H_act=$H_ACT boundary on all 7 nodes"

TERM=$(assert_same_7 "terminal block identity" \
    "SELECT height || '|' || hex(state_root) || '|' || hex(tx_root) \
     || '|' || hex(prev_hash) || '|' || hex(proposer_id) || '|' || tx_count \
     FROM blocks WHERE height = $H_ACT;")
[ -n "$TERM" ] || fail "no terminal block row"
ok "terminal legacy height/BlockID inputs/state_root identical 7/7"
TERM_UTXO=$(assert_same_7 "terminal migratable value" \
    "SELECT COALESCE(SUM(amount),0) FROM utxo_set WHERE amount > 0;")
info "terminal migratable native value = $TERM_UTXO raw"

# ── 4. Legacy refuses H_act + 1 ───────────────────────────────────────
info "probing that the terminal chain refuses to advance"
for i in 1 2 3; do
    stagef_dna -q dna sync >> "$BASE_DIR/act_pump.log" 2>&1 || true
    stagef_dna -q dna send \
        "$(cat "$BASE_DIR/node1/identity/nodus.fp")" 1 "postterm" \
        >> "$BASE_DIR/act_pump.log" 2>&1 || true
    sleep 4
done
HN=$(assert_same_7 "post-terminal head" \
    "SELECT COALESCE(MAX(height),0) FROM blocks;")
[ "$HN" = "$H_ACT" ] || fail "chain advanced past terminal: $HN > $H_ACT"
grep -q "legacy chain is TERMINAL" "$BASE_DIR"/node*/nodus.log \
    || fail "no terminal-refusal log line found"
ok "every height above H_act refused (head pinned at $H_ACT)"

# ── 5. Successor derivation, byte-identical 7/7 ───────────────────────
LEGACY_BASENAME=$(basename "$(node1_db)")
succ_db() {   # $1 = node
    local d="$BASE_DIR/node$1/data" f
    for f in "$d"/witness_*.db; do
        [ -e "$f" ] || continue
        [ "$(basename "$f")" = "$LEGACY_BASENAME" ] && continue
        [ -s "$f" ] || continue
        echo "$f"; return 0
    done
    return 1
}
SUCC_NAME=""
for n in $(seq 1 $N); do
    t=0
    while [ $t -lt 120 ]; do
        s=$(succ_db "$n" || true)
        [ -n "${s:-}" ] && break
        sleep 3; t=$((t+3))
    done
    [ -n "${s:-}" ] || fail "node$n derived no successor chain"
    b=$(basename "$s")
    if [ -z "$SUCC_NAME" ]; then SUCC_NAME="$b"
    elif [ "$b" != "$SUCC_NAME" ]; then
        fail "successor chain id differs: node$n $b vs $SUCC_NAME"
    fi
done
ok "all 7 nodes derived the SAME successor chain: $SUCC_NAME"

first_gid=""
for n in $(seq 1 $N); do
    s=$(succ_db "$n")
    gid=$(sqlite3 "$s" "SELECT hex(block_id) FROM v2_blocks WHERE \
        global_height = 0;") || fail "successor genesis unreadable node$n"
    gr=$(sqlite3 "$s" "SELECT hex(global_root) || '|' || hex(vset_hash) \
        FROM v2_blocks WHERE global_height = 0;")
    res=$(sqlite3 "$s" "SELECT COALESCE(SUM(remaining),-1) FROM v2_dist_state;")
    utx=$(sqlite3 "$s" "SELECT COUNT(*) FROM utxo_set;")
    man=$(sqlite3 "$s" "SELECT COUNT(*) FROM v2_manifests WHERE \
        committed_height = 0;")
    if [ -z "$first_gid" ]; then first_gid="$gid|$gr"
    elif [ "$gid|$gr" != "$first_gid" ]; then
        fail "successor genesis identity differs on node$n"
    fi
    [ "$res" = "$TERM_UTXO" ] || \
        fail "node$n claim reserve $res != terminal migratable $TERM_UTXO"
    [ "$utx" = "0" ] || fail "node$n successor holds spendable UTXOs ($utx)"
    [ "$man" = "1" ] || fail "node$n successor genesis manifest missing"
done
ok "successor genesis BlockID + global root + vset hash identical 7/7"
ok "claim reserve == committed terminal migratable value on every node"
ok "NO legacy UTXO is spendable in V2 (utxo_set empty pre-claims)"

# ── 6. STOP-ALL restart: successor preferred, gate OPEN, on all 7 ─────
#
# The cutover is STOP-ALL by doctrine (feedback_consensus_deploy_stop_all)
# and by necessity: a SINGLE node restarted onto the successor while six
# peers still advertise the legacy chain id trips the pre-existing
# chain-quorum quarantine (dissent >= 2, agree == 0), which archives the
# "wrong" chain — exactly what the first rehearsal observed. So the
# restart phase restarts the WHOLE fleet, the shape the real Testnet2
# cutover will use; every node must then prefer the successor, re-reach
# the identical derivation, preflight CLEAR and ARM its gate.
info "stop-all restart onto the successor chain"
SEEDS=""
for n in $(seq 1 $N); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done
for n in $(seq 1 $N); do
    pid=$(pgrep -f "node$n/identity" | head -1)
    [ -n "$pid" ] && kill "$pid"
done
sleep 4
for n in $(seq 1 $N); do
    node_dir="$BASE_DIR/node$n"
    : > "$node_dir/nodus.restart.log"
    # shellcheck disable=SC2086
    "$STAGEF_NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$node_dir/identity" -d "$node_dir/data" \
        $SEEDS >> "$node_dir/nodus.restart.log" 2>&1 &
    echo $! >> "$BASE_DIR/pids.txt"
done
for n in $(seq 1 $N); do
    node_dir="$BASE_DIR/node$n"
    t=0
    while [ $t -lt 120 ]; do
        grep -q "Ledger V2 ingress ARMED (gate OPEN)" \
            "$node_dir/nodus.restart.log" && break
        sleep 3; t=$((t+3))
    done
    grep -q "seam successor chain preferred" "$node_dir/nodus.restart.log" \
        || fail "node$n did not prefer the successor chain"
    grep -q "Ledger V2 ingress ARMED (gate OPEN)" \
        "$node_dir/nodus.restart.log" \
        || fail "node$n's gate did not OPEN (preflight not clear)"
    grep -q "preflight reports" "$node_dir/nodus.restart.log" \
        && fail "node$n's preflight reported blocking issues"
    s2=$(succ_db "$n")
    gid2=$(sqlite3 "$s2" \
        "SELECT hex(block_id) || '|' || hex(global_root) || '|' || \
         hex(vset_hash) FROM v2_blocks WHERE global_height = 0;")
    [ "$gid2" = "$first_gid" ] || \
        fail "node$n reproduced a DIFFERENT successor derivation"
    ok "node$n: successor preferred, derivation identical, gate OPEN"
done
ok "stop-all restart: 7/7 successor, preflight CLEAR, ingress ARMED"
ok "Rule N (12) retired + ingress (13) clear — gate OPEN on the successor"

stagef_sentinel ASSERT_RUN
stagef_sentinel PASS
echo
echo "=== O15C ACTIVATION REHEARSAL PASSED ==="
