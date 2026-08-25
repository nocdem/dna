#!/usr/bin/env bash
#
# Stage F — O15F Ledger V2 successor validator-set GROWTH 7 → 20 (Task 7).
#
# The O15E season shipped the successor lane but left the 20-validator
# rehearsal UNRUN — "the season result is INCOMPLETE" — because the
# successor `utxo_set` is EMPTY by the seam's post-condition, so no
# CORE-funded transaction was submittable and 13 fresh validators could
# never self-bond. O15F closes exactly that gap: the 13 candidates are
# funded on the LEGACY chain BEFORE activation (so each becomes a
# distribution leaf), then on the successor each CLAIMS its leaf into a
# CORE UTXO (`v2-claim`) and STAKES that UTXO (`v2-envelope stake`). The
# committee grows to 20 by governance (`v2-envelope chain-config`
# TARGET_ACTIVE_COUNT=20) at an epoch boundary e*, and this scenario
# proves the whole path end to end on the live cluster.
#
# Runs ONLY against an activation-authority harness, exactly like
# test_v2_activation_rehearsal.sh:
#   * nodus-server + nodus-cli built with -DNODUS_V2_ACTIVATION=ON and
#     SHORT epoch / grace overrides (-DDNAC_EPOCH_LENGTH=<E>,
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=<lead>,
#     _ERGONOMIC_=<E>), pointed at via STAGEF_NODUS_BIN /
#     STAGEF_NODUSCLI_BIN before stagef_up.sh;
#   * STAGEF_EPOCH_LENGTH exported to the SAME <E> (use 15 — small enough
#     that the e* boundary is reachable by TX-pumping, large enough that
#     the 13 candidates' tenure (S + 2E) clears inside the run).
#   * SAFETY grace SMALL (<= 2E), so governance can take effect inside
#     the pumped window. This scenario reads STAGEF_CC_GRACE_SAFETY and
#     computes the effective height to respect it; the -D grace define
#     MUST match.
#
# THE O15B.1 PUMP DISCIPLINE: block production is TX-driven
# (nodus_witness_tick opens a round only for a non-empty mempool), so an
# idle cluster never reaches the next boundary. Every height wait PUMPS
# one minimal TX per block and polls a condition — NO blind sleeps for a
# consensus outcome. The successor pump vehicle is a single-leg SYSTEM
# CHAIN_CONFIG envelope with an INERT value (TARGET_ACTIVE_COUNT=7) at an
# effective height FAR beyond every epoch this scenario tests, so a pump
# can never move the governed target at e*.
#
# Reachability sentinels: SETUP_OK / TARGET_REACHED / ASSERT_RUN / PASS.
#
# Exit 0 PASS / non-zero FAIL.

set -uo pipefail

. "$(dirname "$0")/../stagef_env.sh"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || \
    fail "no active Stage F harness. Run stagef_up.sh first."
command -v sqlite3 >/dev/null || fail "sqlite3 CLI required"

E_LEN="${STAGEF_EPOCH_LENGTH:-15}"
GRACE="${STAGEF_CC_GRACE_SAFETY:-15}"
NODUSCLI="$STAGEF_NODUSCLI_BIN"
NODUS_BIN="$STAGEF_NODUS_BIN"
[ -x "$NODUSCLI" ]  || fail "nodus-cli not found at $NODUSCLI"
[ -x "$NODUS_BIN" ] || fail "nodus-server not found at $NODUS_BIN"

ORIG=7                 # genesis committee (nodes 1..7)
CAND_LO=8              # first candidate node index
CAND_HI=20            # last candidate node index (13 candidates: 8..20)
TOTAL=20              # target validator-set size

# Funding amounts (RAW base units, 10^8 per DNAC).
NODE_FUND=50000000                  # 0.5 DNAC — SCHEDULE/READY fee reserve
CAND_FUND=1000000100000000          # 10,000,001 DNAC — bond + 1 DNAC margin
BOND_RAW=1000000000000000           # 10,000,000 DNAC — the exact self-bond
STAKE_FEE=1000000                   # max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE)

# ── cleanup: tear down ALL nodes on exit (BASE_DIR is unique per run) ──
cleanup() {
    echo "[cleanup] tearing down every node under $BASE_DIR" >&2
    pkill -f "$BASE_DIR/node" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── log tracking: each (re)start writes a fresh per-node log; CUR_LOG[n]
# is the log to grep for THAT node's most recent lifecycle. The genesis
# 7 were started by stagef_up into nodus.log. ────────────────────────
declare -A CUR_LOG
for n in $(seq 1 $ORIG); do CUR_LOG[$n]="$BASE_DIR/node$n/nodus.log"; done
LOG_SEQ=0

# All seed endpoints (1..20). Unreachable/not-yet-started seeds are
# harmless to Kademlia; seeding every endpoint maximises mesh formation
# and, with the O15B.1 per-endpoint placeholder ids, a node skips its own
# address. Restarts and joiner boots all use this list.
SEEDS_ALL=""
for n in $(seq 1 $TOTAL); do
    SEEDS_ALL="$SEEDS_ALL -s 127.0.0.1:$(stagef_udp_port "$n")"
done

# Spawn node $1 with optional extra args ($2..). Writes a fresh log and
# records CUR_LOG[$1]. Does NOT wait for readiness (caller polls).
start_node() {
    local n="$1"; shift
    local node_dir="$BASE_DIR/node$n"
    LOG_SEQ=$(( LOG_SEQ + 1 ))
    local log="$node_dir/run_${LOG_SEQ}.log"
    CUR_LOG[$n]="$log"
    : > "$log"
    # shellcheck disable=SC2086
    "$NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$node_dir/identity" -d "$node_dir/data" \
        "$@" $SEEDS_ALL >> "$log" 2>&1 &
    echo $! >> "$BASE_DIR/pids.txt"
}

stop_node() {
    local n="$1"
    local pid
    pid=$(pgrep -f "$BASE_DIR/node$n/identity" | head -1)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
}

# Wait until node $1's CURRENT log shows the successor gate OPEN.
wait_armed() {
    local n="$1" timeout="${2:-150}" t=0
    while [ $t -lt "$timeout" ]; do
        grep -q "Ledger V2 ingress ARMED (gate OPEN)" "${CUR_LOG[$n]}" \
            2>/dev/null && return 0
        sleep 3; t=$(( t + 3 ))
    done
    return 1
}

# ── legacy-chain helpers (pre-activation phase) ──────────────────────
node1_db() { stagef_node_chain_db 1; }
head_height() {
    sqlite3 "$(node1_db)" "SELECT COALESCE(MAX(height),0) FROM blocks;" \
        2>/dev/null || echo 0
}

# The exact-amount funding UTXO for `fp`, committed AND spendable, on ANY
# node's witness DB. Empty results are "not yet", never success. Mirrors
# test_v2_activation_rehearsal.sh::act_fund_on_chain, generalised to an
# arbitrary amount so a fixed-fingerprint fund is proven ABSENT before
# every (re)transmission — no double-fund can inflate a candidate's leaf
# count.
fund_on_chain() {
    local owner_fp="$1" amount="$2" node db cnt height
    for node in $(seq 1 $ORIG); do
        db=$(ls "$BASE_DIR/node$node/data"/witness_*.db 2>/dev/null | head -1)
        [ -n "$db" ] || continue
        height=$(sqlite3 -readonly "$db" \
            "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null) \
            || continue
        [ -n "$height" ] || continue
        cnt=$(sqlite3 -readonly "$db" \
            "SELECT COUNT(*) FROM utxo_set
              WHERE owner = '$owner_fp' AND amount = $amount
                AND COALESCE(unlock_block,0) <= $height;" 2>/dev/null) \
            || continue
        [ -n "$cnt" ] || continue
        [ "${cnt:-0}" -ge 1 ] && return 0
    done
    return 1
}

# Fund a FIXED fingerprint with an EXACT amount on the legacy chain, the
# chain-verified way (a CLI exit code is not a commit in either
# direction — project_genesis_client_false_error). Up to 3 attempts, the
# committed exact-amount UTXO proven ABSENT before each retransmission.
fund_legacy() {
    local fp="$1" amount="$2" label="$3"
    local ok_fund=0 used=0
    for attempt in 1 2 3; do
        if fund_on_chain "$fp" "$amount"; then ok_fund=1; break; fi
        used=$attempt
        stagef_dna -q dna sync >> "$BASE_DIR/grow_fund.log" 2>&1 || true
        if stagef_dna -q dna send "$fp" "$amount" "$label" \
               >> "$BASE_DIR/grow_fund.log" 2>&1; then
            local dl=$(( SECONDS + 60 ))
            while [ $SECONDS -lt $dl ]; do
                if fund_on_chain "$fp" "$amount"; then ok_fund=1; break; fi
                sleep 2
            done
            [ "$ok_fund" -eq 1 ] && break
        else
            local dl=$(( SECONDS + 60 ))
            while [ $SECONDS -lt $dl ]; do
                if fund_on_chain "$fp" "$amount"; then ok_fund=1; break; fi
                sleep 2
            done
            [ "$ok_fund" -eq 1 ] && break
        fi
        [ "$attempt" -lt 3 ] && sleep 5
    done
    if [ "$ok_fund" -eq 0 ]; then
        tail -6 "$BASE_DIR/grow_fund.log" >&2 || true
        fail "$label: no committed $amount UTXO for ${fp:0:16}… after 3 tries"
    fi
    # Bounded re-confirmation that the committed state REMAINS.
    local sd=$(( SECONDS + 20 ))
    while [ $SECONDS -lt $sd ]; do
        fund_on_chain "$fp" "$amount" && return 0
        sleep 1
    done
    fail "$label: committed UTXO did not remain spendable"
}

# Legacy pump — one minimal 1-raw self-send per block until head >= $1.
pump_legacy() {
    local target="$1" timeout="${2:-600}"
    local deadline=$(( SECONDS + timeout ))
    local h; h=$(head_height)
    local sink; sink=$(cat "$BASE_DIR/node1/identity/nodus.fp")
    while [ "${h:-0}" -lt "$target" ] && [ $SECONDS -lt $deadline ]; do
        stagef_dna -q dna sync >> "$BASE_DIR/grow_pump.log" 2>&1 || true
        if ! stagef_dna -q dna send "$sink" 1 "pump" \
               >> "$BASE_DIR/grow_pump.log" 2>&1; then
            stagef_dna -q dna sync >> "$BASE_DIR/grow_pump.log" 2>&1 || true
            stagef_dna -q dna send "$sink" 1 "pump" \
                >> "$BASE_DIR/grow_pump.log" 2>&1 || true
        fi
        sleep 6
        h=$(head_height)
    done
    [ "${h:-0}" -ge "$target" ] || fail "legacy pump: height $h < $target"
    info "legacy pumped to height $h (target $target)"
}

# Identical value across ALL nodes in $NODES for one legacy SQL expr.
assert_same_legacy() {
    local label="$1" sql="$2" first="" v
    for n in $NODES; do
        v=$(sqlite3 "$(stagef_node_chain_db "$n")" "$sql" 2>/dev/null) \
            || fail "$label: sqlite failed on node$n"
        if [ -z "$first" ]; then first="$v"
        elif [ "$v" != "$first" ]; then
            fail "$label: node$n ($v) != node(first) ($first)"
        fi
    done
    echo "$first"
}

converge_legacy() {
    local label="$1" timeout="${2:-300}"
    local deadline=$(( SECONDS + timeout ))
    while [ $SECONDS -lt $deadline ]; do
        local lo="" hi="" h
        for n in $NODES; do
            h=$(sqlite3 "$(stagef_node_chain_db "$n")" \
                "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null \
                || echo 0)
            [ -z "$lo" ] && { lo="$h"; hi="$h"; continue; }
            [ "$h" -lt "$lo" ] && lo="$h"
            [ "$h" -gt "$hi" ] && hi="$h"
        done
        [ -n "$lo" ] && [ "$lo" = "$hi" ] && \
            { ok "legacy heads converged at $lo ($label)"; return 0; }
        sleep 3
    done
    fail "legacy heads did not converge ($label)"
}

# ── successor-chain helpers ──────────────────────────────────────────
LEGACY_BASENAME=""
succ_db() {   # $1 = node — the witness_*.db that is NOT the terminal legacy DB
    local d="$BASE_DIR/node$1/data" f
    for f in "$d"/witness_*.db; do
        [ -e "$f" ] || continue
        [ "$(basename "$f")" = "$LEGACY_BASENAME" ] && continue
        [ -s "$f" ] || continue
        echo "$f"; return 0
    done
    return 1
}
succ_height() {   # $1 = node
    local s; s=$(succ_db "$1" 2>/dev/null) || { echo 0; return; }
    sqlite3 -readonly "$s" \
        "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks;" 2>/dev/null \
        || echo 0
}

# Identical successor value across every node in $NODES.
assert_same_succ() {
    local label="$1" sql="$2" first="" v
    for n in $NODES; do
        v=$(sqlite3 -readonly "$(succ_db "$n")" "$sql" 2>/dev/null) \
            || fail "$label: sqlite failed on node$n"
        if [ -z "$first" ]; then first="$v"
        elif [ "$v" != "$first" ]; then
            fail "$label: node$n ($v) != node(first) ($first)"
        fi
    done
    echo "$first"
}

# Block until every node in $NODES holds the SAME successor tip.
converge_succ() {
    local label="$1" timeout="${2:-300}"
    local deadline=$(( SECONDS + timeout ))
    while [ $SECONDS -lt $deadline ]; do
        local lo="" hi="" h
        for n in $NODES; do
            h=$(succ_height "$n")
            [ -z "$lo" ] && { lo="$h"; hi="$h"; continue; }
            [ "$h" -lt "$lo" ] && lo="$h"
            [ "$h" -gt "$hi" ] && hi="$h"
        done
        [ -n "$lo" ] && [ "$lo" = "$hi" ] && \
            { ok "successor heads converged at $lo ($label)"; return 0; }
        sleep 3
    done
    fail "successor heads did not converge ($label)"
}

wait_succ_height() {   # $1 = target, $2 = timeout — MIN over $NODES
    local target="$1" timeout="${2:-150}" deadline=$(( SECONDS + ${2:-150} ))
    while [ $SECONDS -lt $deadline ]; do
        local lo=999999999 h
        for n in $NODES; do
            h=$(succ_height "$n")
            [ "${h:-0}" -lt "$lo" ] && lo="$h"
        done
        [ "$lo" -ge "$target" ] && return 0
        sleep 2
    done
    return 1
}

wait_qc() {   # $1 = height, $2 = timeout — qc attached on every node in $NODES
    local h="$1" deadline=$(( SECONDS + ${2:-90} ))
    while [ $SECONDS -lt $deadline ]; do
        local miss=0 q
        for n in $NODES; do
            q=$(sqlite3 -readonly "$(succ_db "$n")" \
                "SELECT COUNT(*) FROM v2_blocks WHERE global_height=$h \
                 AND qc IS NOT NULL;" 2>/dev/null || echo 0)
            [ "${q:-0}" = "1" ] || { miss=1; break; }
        done
        [ "$miss" = "0" ] && return 0
        sleep 2
    done
    return 1
}

# Raw Dilithium pubkey of node $1 in UPPER hex — the exact string the
# validator row and the snapshot blob carry (snapshot_contains matches it).
node_pubkey_hex() { xxd -p -u -c 99999 "$BASE_DIR/node$1/identity/nodus.pk"; }

# Is raw pubkey $2 inside the authoritative snapshot for epoch $1?
snapshot_contains() {
    sqlite3 -readonly "$(succ_db 1)" \
        "SELECT CASE WHEN instr(hex(snapshot_blob), '$2') > 0 THEN 1 ELSE 0 \
         END FROM validator_set_snapshots WHERE epoch_start = $1;" \
        2>/dev/null || echo 0
}

# The proposal-nonce stream. Every submitted CHAIN_CONFIG envelope gets a
# UNIQUE nonce AND a UNIQUE effective height (PUMP_EFF_BASE + NONCE, parked
# far beyond e* so the inert pump CC can never govern a tested epoch). BOTH
# feed the envelope's intent_id: the 41-byte CHAIN_CONFIG proposal (param,
# value, effective, nonce, signed_at, valid_before) enters call_commit ->
# intent_leg_commit -> intent_id (shared/dnac/env_wire.c), so a unique
# (nonce,effective) yields a unique intent and the committed-intent replay
# guard admits every pump. EMPIRICALLY CONFIRMED against a committed
# successor DB: two CCs differing only in nonce+effective produce DISTINCT
# intent_ids; reusing the same nonce reproduces ONE identical intent.
#
# CRITICAL: bump the global as a BARE STATEMENT (`bump_nonce`), NEVER via
# `$(bump_nonce)`. A command substitution runs in a SUBSHELL whose
# increment does not persist, so every caller would read NONCE=1000 and
# emit nonce=1001/effective=901001 EVERY time -> one identical intent_id ->
# the 2nd+ pump refused 'intent already committed on this chain' -> the
# STEP 9 pump stall. That subshell bug (not any CLI/intent property) was
# the observed collision.
NONCE=1000
bump_nonce() { NONCE=$(( NONCE + 1 )); }
PUMP_EFF_BASE=900000

ESTAR=""   # set once the 20-member snapshot is observed (used by steps 9/10)

# Approver keys for a successor CHAIN_CONFIG. The CLI matches each key to a
# committee SEAT and signs exactly quorum keys, so the keys MUST be current
# committee members. A CC landing at H = tip+1 resolves its committee at
# H-1 = tip, i.e. snapshot(epoch(tip)). This is DERIVED FROM THAT SNAPSHOT
# rather than a static node list, because with every validator at an
# identical 10M bond the seven-seat committee ROTATES among the tenured set
# each epoch (the tiebreak is seeded from the epoch's BlockID): once the
# candidates tenure (anchor = e_start, committee.c) but before the target
# rises to 20, more than seven validators are tenured and a fixed "nodes
# 1..5" can silently drop out of the committee. Reading the governing
# snapshot is correct at every epoch AND at the boundary.
succ_pump_keys() {
    local t e need count=0 keys="" n pk n_active
    t=$(succ_height 1)
    e=$(( t / E_LEN * E_LEN ))
    n_active=$(sqlite3 -readonly "$(succ_db 1)" \
        "SELECT active_count FROM validator_set_snapshots WHERE epoch_start = $e;" \
        2>/dev/null)
    [ -n "$n_active" ] || n_active=7
    need=$(( (2 * n_active) / 3 + 1 ))
    for n in $(seq 1 $TOTAL); do
        pk=$(node_pubkey_hex "$n")
        if [ "$(snapshot_contains "$e" "$pk")" = "1" ]; then
            keys="${keys:+$keys,}$BASE_DIR/node$n/identity"
            count=$(( count + 1 ))
            [ "$count" -ge "$need" ] && break
        fi
    done
    echo "$keys"
}

# Submit one successor envelope. Returns the CLI exit code.
#   submit_cc <param> <value> <effective> <nonce> <keys>
submit_cc() {
    "$NODUSCLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
        -i "$BASE_DIR/node1/identity" v2-envelope chain-config \
        --db "$(succ_db 1)" --keys "$5" \
        --param "$1" --value "$2" --effective "$3" --nonce "$4" \
        >> "$BASE_DIR/grow_succ_submit.log" 2>&1
}

# One inert pump CC (TARGET_ACTIVE_COUNT=7, effective ≫ e*).
submit_pump() {
    bump_nonce   # bare statement — the increment persists in the caller's shell
    submit_cc 4 7 $(( PUMP_EFF_BASE + NONCE )) "$NONCE" "$(succ_pump_keys)"
}

# Pump the successor to tip >= $1 by one inert CC per block.
pump_succ() {
    local target="$1" timeout="${2:-600}"
    local deadline=$(( SECONDS + timeout ))
    local h; h=$(succ_height 1)
    while [ "${h:-0}" -lt "$target" ] && [ $SECONDS -lt $deadline ]; do
        submit_pump || true
        sleep 6
        h=$(succ_height 1)
    done
    [ "${h:-0}" -ge "$target" ] || fail "successor pump: tip $h < $target"
    info "successor pumped to tip $h (target $target)"
}

# Assert successor block identity is identical across $NODES at height $1.
assert_succ_block_identity() {
    assert_same_succ "successor block $1 identity" \
        "SELECT global_height || '|' || hex(block_id) || '|' || \
         hex(prev_block_id) || '|' || hex(global_root) || '|' || \
         hex(vset_hash) || '|' || tx_count \
         FROM v2_blocks WHERE global_height = $1;" > /dev/null
    ok "successor block $1 identical across $(echo $NODES | wc -w) nodes"
}

# ══════════════════════════════════════════════════════════════════════
# STEP 1 — generate 13 candidate identities OFFLINE (nodes 8..20).
#
# Only the identity files (nodus.pk/sk/fp) are needed now: the candidates
# CLAIM and STAKE as offline identities submitted through node1, and only
# BOOT as nodes at step 8. A short-lived spawn generates each identity,
# then the data dir is wiped so a fresh pinned-genesis join is clean.
# ══════════════════════════════════════════════════════════════════════
NODES="$(seq 1 $ORIG | tr '\n' ' ')"
info "STEP 1 — generating 13 candidate identities (nodes $CAND_LO..$CAND_HI)"
for n in $(seq $CAND_LO $CAND_HI); do
    node_dir="$BASE_DIR/node$n"
    mkdir -p "$node_dir/identity" "$node_dir/data"
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
    rm -rf "$node_dir/data"; mkdir -p "$node_dir/data"
done
ok "13 candidate identities generated"

# ══════════════════════════════════════════════════════════════════════
# STEP 2 — legacy chain up (via stagef_up); fund the 7 node identities
# (activation fees) AND the 13 candidate fps (10,000,001 DNAC each) so
# every candidate becomes a terminal-legacy distribution leaf.
# ══════════════════════════════════════════════════════════════════════
info "STEP 2 — funding the $ORIG node identities (SCHEDULE/READY fees)"
for n in $(seq 1 $ORIG); do
    fp=$(cat "$BASE_DIR/node$n/identity/nodus.fp")
    fund_legacy "$fp" "$NODE_FUND" "nodefund$n"
    ok "node$n activation fee funded"
done
info "STEP 2 — funding the 13 candidate fingerprints ($CAND_FUND raw each)"
for n in $(seq $CAND_LO $CAND_HI); do
    fp=$(cat "$BASE_DIR/node$n/identity/nodus.fp")
    fund_legacy "$fp" "$CAND_FUND" "candfund$n"
    ok "candidate node$n funded + spendable on the legacy chain"
done
converge_legacy "post-funding"
stagef_sentinel SETUP_OK

# ══════════════════════════════════════════════════════════════════════
# STEP 3 — activation: SCHEDULE -> READY 7/7 -> terminal H_act -> 7/7
# identical successor derivation; record the terminal V1 DB sha256.
# ══════════════════════════════════════════════════════════════════════
info "STEP 3 — SCHEDULE / READY / terminal / successor derivation"
H0=$(head_height)
# Schedule lead in BLOCKS. The activation machine transitions state->READY
# ONLY at an epoch boundary STRICTLY BEFORE H_act, and activates at H_act
# ONLY if state==READY by then; readiness that becomes all-active only
# AFTER the H_act-E boundary legitimately POSTPONES activation +1 epoch
# (nodus_witness_v2_activation.c convergence). Readiness here consumes a
# dozen-plus blocks (7 signals + pumps), so H_act is placed generously
# beyond the protocol floor max(2E, SAFETY grace) — enough that readiness
# completes before H_act-E in the common case. The ACTIVE poll below is the
# robust backstop that captures the REAL activation height if a postpone
# happens anyway.
READY_MARGIN=25
LEAD=$(( 2 * E_LEN ))
[ "$GRACE" -gt "$LEAD" ] && LEAD="$GRACE"
[ "$READY_MARGIN" -gt "$LEAD" ] && LEAD="$READY_MARGIN"
# A full extra epoch of slack: H_act-E >= H0+LEAD (the readiness window).
H_ACT=$(( ( (H0 + LEAD) / E_LEN + 2 ) * E_LEN ))
info "legacy head=$H0 lead=$LEAD epoch=$E_LEN -> scheduling H_act=$H_ACT (H_act-E=$(( H_ACT - E_LEN )))"

SCHED_KEYS="$BASE_DIR/node1/identity"
for n in 2 3 4 5; do SCHED_KEYS="$SCHED_KEYS,$BASE_DIR/node$n/identity"; done
SCHED_OUT=$("$NODUSCLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" \
    -i "$BASE_DIR/node1/identity" v2-activation schedule \
    --height "$H_ACT" --nonce 7 --keys "$SCHED_KEYS") \
    || fail "schedule submit failed"
echo "$SCHED_OUT"
DIG=$(echo "$SCHED_OUT" | awk -F= '/^SCHED digest=/{print $2}')
[ -n "$DIG" ] || fail "no schedule digest in output"
pump_legacy $(( $(head_height) + 2 )) 180
converge_legacy "post-schedule"

ST=$(assert_same_legacy "record state" \
    "SELECT state || '|' || activation_height FROM v2_activation WHERE id=1;")
[ "$ST" = "1|$H_ACT" ] || fail "record not SCHEDULED at $H_ACT: $ST"
ok "SCHEDULE committed identically 7/7 (H_act=$H_ACT)"

for n in $(seq 1 $ORIG); do
    got=0
    for attempt in 1 2 3; do
        if "$NODUSCLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" \
             -i "$BASE_DIR/node$n/identity" v2-activation ready \
             --digest "$DIG" --keys "$BASE_DIR/node$n/identity" \
             >> "$BASE_DIR/grow_ready.log" 2>&1; then
            pump_legacy $(( $(head_height) + 1 )) 90 || true
            cnt=$(sqlite3 "$(node1_db)" \
                "SELECT COUNT(*) FROM v2_activation_readiness;" 2>/dev/null \
                || echo 0)
            [ "${cnt:-0}" -ge "$n" ] && { got=1; break; }
        else
            pump_legacy $(( $(head_height) + 1 )) 90 || true
        fi
    done
    [ "$got" = 1 ] || fail "node$n readiness did not commit"
    ok "readiness $n/7 committed"
done
converge_legacy "post-readiness"
RCNT=$(assert_same_legacy "readiness count" \
    "SELECT COUNT(*) FROM v2_activation_readiness;")
[ "$RCNT" = "7" ] || fail "readiness count $RCNT != 7"
# Readiness 7/7 is confirmed committed HERE — strictly before pumping across
# the H_act-E boundary (the machine reads readiness AT that boundary). If
# readiness overran the lead the ACTIVE poll below still converges.
H_READY=$(head_height)
if [ "$H_READY" -lt "$(( H_ACT - E_LEN ))" ]; then
    ok "readiness 7/7 committed at height $H_READY (< H_act-E=$(( H_ACT - E_LEN )))"
else
    info "readiness 7/7 committed at $H_READY (>= H_act-E) — a +1-epoch postpone is expected; the poll handles it"
fi

# Cross the boundary and POLL for ACTIVE, capturing the ACTUAL terminal
# height. Do NOT assert at exactly H_act: if readiness landed after the
# H_act-E boundary the machine postpones +1 epoch (state stays SCHEDULED,
# activation_height advances) and would activate at the NEXT boundary. Pump
# to the current target, re-read, repeat — bounded to a few postpones.
H_ACT_REAL=""
target="$H_ACT"
for _ in 1 2 3 4 5; do
    pump_legacy "$target" 900
    converge_legacy "activation poll (target $target)"
    AST=$(assert_same_legacy "activation state" \
        "SELECT state || '|' || activation_height FROM v2_activation WHERE id=1;")
    astate="${AST%%|*}"; aheight="${AST#*|}"
    if [ "$astate" = "3" ]; then H_ACT_REAL="$aheight"; break; fi
    info "activation not ACTIVE yet (state=$astate, target now $aheight) — postpone, continuing"
    target="$aheight"
    [ "$target" -gt "$(head_height)" ] || target=$(( $(head_height) + E_LEN ))
done
[ -n "$H_ACT_REAL" ] || fail "activation never reached ACTIVE within 5 postpones (scheduled $H_ACT)"
ok "activation ACTIVE at H_act_real=$H_ACT_REAL (scheduled $H_ACT) on all 7 nodes"

TERM_UTXO=$(assert_same_legacy "terminal migratable value" \
    "SELECT COALESCE(SUM(amount),0) FROM utxo_set WHERE amount > 0;")
info "terminal migratable native value = $TERM_UTXO raw"

# Successor derivation, byte-identical 7/7.
LEGACY_BASENAME=$(basename "$(node1_db)")
SUCC_NAME=""
for n in $(seq 1 $ORIG); do
    t=0; s=""
    while [ $t -lt 150 ]; do
        s=$(succ_db "$n" || true); [ -n "${s:-}" ] && break
        sleep 3; t=$(( t + 3 ))
    done
    [ -n "${s:-}" ] || fail "node$n derived no successor chain"
    b=$(basename "$s")
    if [ -z "$SUCC_NAME" ]; then SUCC_NAME="$b"
    elif [ "$b" != "$SUCC_NAME" ]; then
        fail "successor chain id differs: node$n $b vs $SUCC_NAME"
    fi
done
ok "all 7 nodes derived the SAME successor chain: $SUCC_NAME"

FIRST_GID=""
for n in $(seq 1 $ORIG); do
    s=$(succ_db "$n")
    gid=$(sqlite3 -readonly "$s" "SELECT hex(block_id) || '|' || \
        hex(global_root) || '|' || hex(vset_hash) FROM v2_blocks \
        WHERE global_height = 0;")
    res=$(sqlite3 -readonly "$s" \
        "SELECT COALESCE(SUM(remaining),-1) FROM v2_dist_state;")
    utx=$(sqlite3 -readonly "$s" "SELECT COUNT(*) FROM utxo_set;")
    if [ -z "$FIRST_GID" ]; then FIRST_GID="$gid"
    elif [ "$gid" != "$FIRST_GID" ]; then
        fail "successor genesis identity differs on node$n"
    fi
    [ "$res" = "$TERM_UTXO" ] || \
        fail "node$n claim reserve $res != terminal migratable $TERM_UTXO"
    [ "$utx" = "0" ] || fail "node$n successor holds UTXOs pre-claims ($utx)"
done
ok "successor genesis identity identical 7/7; reserve == terminal value; utxo_set empty"

# The genesis BlockID (128 hex) — the operator pin the step-8 joiners use.
GENESIS_PIN=$(sqlite3 -readonly "$(succ_db 1)" \
    "SELECT hex(block_id) FROM v2_blocks WHERE global_height = 0;")
[ ${#GENESIS_PIN} -eq 128 ] || fail "genesis pin is not 128 hex: ${#GENESIS_PIN}"

# Terminal V1 database bytes, per node — must be byte-frozen end-to-end.
declare -A TERM_SHA
for n in $(seq 1 $ORIG); do
    TERM_SHA[$n]=$(sha256sum "$BASE_DIR/node$n/data/$LEGACY_BASENAME" \
        | awk '{print $1}')
done
info "terminal V1 db sha256 (node1) = ${TERM_SHA[1]:0:16}..."

# STOP-ALL restart onto the successor (STOP-ALL by doctrine — a single
# node restarted into a legacy-advertising fleet trips the chain-quorum
# quarantine). Every node must prefer the successor and ARM its gate.
info "STEP 3 — stop-all restart onto the successor (arming the gate)"
for n in $(seq 1 $ORIG); do stop_node "$n"; done
sleep 4
for n in $(seq 1 $ORIG); do start_node "$n"; done
for n in $(seq 1 $ORIG); do
    wait_armed "$n" 150 || fail "node$n gate did not OPEN after cutover restart"
    grep -q "seam successor chain preferred" "${CUR_LOG[$n]}" \
        || fail "node$n did not prefer the successor chain"
    g=$(sqlite3 -readonly "$(succ_db "$n")" "SELECT hex(block_id) || '|' || \
        hex(global_root) || '|' || hex(vset_hash) FROM v2_blocks \
        WHERE global_height = 0;")
    [ "$g" = "$FIRST_GID" ] || fail "node$n reproduced a different successor"
done
ok "stop-all restart: 7/7 successor preferred, gate OPEN, derivation identical"
sleep 5   # peer mesh re-establishment before the first successor round

# ══════════════════════════════════════════════════════════════════════
# STEP 4 — each candidate CLAIMS its distribution leaf into a CORE UTXO.
# 13 claims commit across >=2 blocks on all 7; reserve decreases by the
# claimed sum and exactly 13 CORE utxo rows appear.
# ══════════════════════════════════════════════════════════════════════
info "STEP 4 — submitting 13 GENESIS_CLAIMs (v2-claim)"
RESERVE_BEFORE=$(sqlite3 -readonly "$(succ_db 1)" \
    "SELECT COALESCE(SUM(remaining),0) FROM v2_dist_state;")
CLAIM_TIP0=$(succ_height 1)
LEGACY_DB1="$BASE_DIR/node1/data/$LEGACY_BASENAME"
for n in $(seq $CAND_LO $CAND_HI); do
    idr="$BASE_DIR/node$n/identity"
    got=0
    for attempt in 1 2 3; do
        if "$NODUSCLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$idr" \
             v2-claim --legacy-db "$LEGACY_DB1" --db "$(succ_db 1)" \
             --keys "$idr" --submit "127.0.0.1:$(stagef_tcp_port 1)" \
             >> "$BASE_DIR/grow_claim.log" 2>&1; then got=1; break; fi
        info "claim node$n attempt $attempt failed — retrying"
        sleep 5
    done
    [ "$got" = 1 ] || { tail -6 "$BASE_DIR/grow_claim.log" >&2
                        fail "candidate node$n claim submit failed"; }
done
# 13 CORE UTXOs must commit; that needs the chain to make blocks — pump.
CLAIM_TARGET=$(( CLAIM_TIP0 + 2 ))
deadline=$(( SECONDS + 300 ))
while [ $SECONDS -lt $deadline ]; do
    u=$(sqlite3 -readonly "$(succ_db 1)" \
        "SELECT COUNT(*) FROM utxo_set WHERE domain_id = 1;" 2>/dev/null \
        || echo 0)
    [ "${u:-0}" -ge 13 ] && break
    pump_succ $(( $(succ_height 1) + 1 )) 60
done
NODES="$(seq 1 $ORIG | tr '\n' ' ')"
converge_succ "post-claims"
UROWS=$(assert_same_succ "CORE utxo rows" \
    "SELECT COUNT(*) FROM utxo_set WHERE domain_id = 1;")
[ "$UROWS" = "13" ] || fail "expected 13 CORE utxo rows, got $UROWS"
RESERVE_AFTER=$(assert_same_succ "reserve after claims" \
    "SELECT COALESCE(SUM(remaining),0) FROM v2_dist_state;")
EXPECT_DROP=$(( 13 * CAND_FUND ))
[ $(( RESERVE_BEFORE - RESERVE_AFTER )) -eq "$EXPECT_DROP" ] || \
    fail "reserve dropped $(( RESERVE_BEFORE - RESERVE_AFTER )) != $EXPECT_DROP"
CLAIM_TIP1=$(succ_height 1)
[ $(( CLAIM_TIP1 - CLAIM_TIP0 )) -ge 2 ] || \
    fail "13 claims did not span >=2 blocks (tip $CLAIM_TIP0 -> $CLAIM_TIP1)"
ok "13 claims committed across >=2 blocks; reserve -= claimed sum; 13 CORE utxos (7/7)"

# ══════════════════════════════════════════════════════════════════════
# STEP 5 — each candidate STAKES its claimed UTXO (successor height s>=2).
# 13 new validator rows, active_count 7 -> 20, roots identical 7/7.
# The R7 tenure wart: never stake at s=1; the claim phase already put the
# tip well past 2, so every stake lands at s>=3.
# ══════════════════════════════════════════════════════════════════════
info "STEP 5 — submitting 13 STAKE envelopes (v2-envelope stake)"
[ "$(succ_height 1)" -ge 2 ] || pump_succ 2 120
for n in $(seq $CAND_LO $CAND_HI); do
    idr="$BASE_DIR/node$n/identity"
    fp=$(cat "$idr/nodus.fp")
    got=0
    for attempt in 1 2 3; do
        if "$NODUSCLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$idr" \
             v2-envelope stake --db "$(succ_db 1)" --keys "$idr" \
             --bond "$BOND_RAW" --commission $(( 500 + n )) --dest-fp "$fp" \
             --submit "127.0.0.1:$(stagef_tcp_port 1)" \
             >> "$BASE_DIR/grow_stake.log" 2>&1; then got=1; break; fi
        info "stake node$n attempt $attempt failed — pumping + retrying"
        pump_succ $(( $(succ_height 1) + 1 )) 60
    done
    [ "$got" = 1 ] || { tail -6 "$BASE_DIR/grow_stake.log" >&2
                        fail "candidate node$n stake submit failed"; }
done
deadline=$(( SECONDS + 300 ))
while [ $SECONDS -lt $deadline ]; do
    v=$(sqlite3 -readonly "$(succ_db 1)" \
        "SELECT COUNT(*) FROM validators;" 2>/dev/null || echo 0)
    [ "${v:-0}" -ge 20 ] && break
    pump_succ $(( $(succ_height 1) + 1 )) 60
done
converge_succ "post-stakes"
VROWS=$(assert_same_succ "validator rows" "SELECT COUNT(*) FROM validators;")
[ "$VROWS" = "20" ] || fail "expected 20 validator rows, got $VROWS"
ACOUNT=$(assert_same_succ "active_count counter" \
    "SELECT value FROM validator_stats WHERE key='active_count';")
[ "$ACOUNT" = "20" ] || fail "active_count $ACOUNT != 20"
# Name the 13 the scenario introduced — a bare count of 20 is not proof.
for n in $(seq $CAND_LO $CAND_HI); do
    pk=$(node_pubkey_hex "$n")
    got=$(sqlite3 -readonly "$(succ_db 1)" \
        "SELECT COUNT(*) FROM validators WHERE hex(pubkey) = '$pk';")
    [ "$got" = 1 ] || fail "candidate node$n is not a bonded validator"
done
assert_same_succ "successor root after stakes" \
    "SELECT hex(global_root) FROM v2_blocks \
     WHERE global_height = (SELECT MAX(global_height) FROM v2_blocks);" \
    > /dev/null
ok "20 validators, active_count 7->20, roots identical 7/7 (incl. all 13 candidates)"
stagef_sentinel TARGET_REACHED

# ══════════════════════════════════════════════════════════════════════
# STEP 5b — launch the 13 pinned-genesis joiners NOW, DECOUPLED from the
# growth boundary. At E=6 an epoch is ~30-60s wall-clock — SHORTER than
# the ~2-3 min a joiner needs to become DHT-visible (nodus:pk registry)
# and be dialed by the committee on the witness port (4004). 13
# SIMULTANEOUS joiners overwhelm the 7-node committee's registry
# replication + connection establishment, so a joiner can send zero
# gbundle requests inside a short window (the observed STEP 8 failure).
# Launching them HERE — before governance, before any pump toward e* —
# gives them UNLIMITED wall-clock: they bootstrap through steps 6/7 and
# the STEP 8 barrier while the head stays far below e*, then follow the
# chain to e* and vote as the 20-set (quorum 14). STAGGERED to spread the
# 7x13 committee->joiner dial + registry-publish load (O15B.1 visibility
# is ~60s identity refresh + ~60s roster tick).
# ══════════════════════════════════════════════════════════════════════
info "STEP 5b — launching 13 pinned-genesis joiners (staggered)"
for n in $(seq $CAND_LO $CAND_HI); do
    start_node "$n" --v2-genesis-pin "$GENESIS_PIN"
    sleep 8   # stagger: spread registry publish + committee dial load
done
ok "13 joiners launched (staggered); they bootstrap while steps 6-7 run"

# ══════════════════════════════════════════════════════════════════════
# STEP 6 — governance: chain-config TARGET_ACTIVE_COUNT=20, effective at a
# boundary that clears SAFETY grace AND the candidates' tenure (S + 2E).
# ══════════════════════════════════════════════════════════════════════
HG=$(succ_height 1)
# EFF = smallest multiple of E that is >= max(HG + 2E, HG + grace + 1).
EFF_A=$(( HG + 2 * E_LEN ))
EFF_B=$(( HG + GRACE + 1 ))
EFF_MIN=$(( EFF_A > EFF_B ? EFF_A : EFF_B ))
EFF=$(( ( (EFF_MIN + E_LEN - 1) / E_LEN ) * E_LEN ))
info "STEP 6 — governance TARGET_ACTIVE_COUNT=20 effective=$EFF (head=$HG)"
bump_nonce; GNONCE=$NONCE
for attempt in 1 2 3; do
    if submit_cc 4 20 "$EFF" "$GNONCE" "$(succ_pump_keys)"; then break; fi
    info "governance submit attempt $attempt failed — retrying"
    [ "$attempt" = 3 ] && { tail -6 "$BASE_DIR/grow_succ_submit.log" >&2
                            fail "governance submit failed"; }
    sleep 5
done
wait_succ_height $(( HG + 1 )) 120 || fail "governance block did not commit"
converge_succ "post-governance"
ok "governance CC committed (TARGET_ACTIVE_COUNT=20 effective=$EFF)"

# ══════════════════════════════════════════════════════════════════════
# STEP 7 — negative pin: a 31-target CC is a deterministic exec VERDICT
# reject (NODUS_V2_ACTIVE_SET_MAX = 30, rt_native.c). It is admitted and
# preflighted (structurally valid) then rejected at apply, so the block
# rolls back and the offending envelope is FREED (bft.c BATCH COMMIT
# FAILED path) — the chain self-heals. Asserted from a node log.
# ══════════════════════════════════════════════════════════════════════
info "STEP 7 — negative pin: submitting a 31-target CC (must be rejected)"
# Record each node's CURRENT log length BEFORE the 31-CC, so the reject
# grep reads ONLY lines produced AFTER this submission — an earlier
# transient batch failure (claim/stake retry noise) must not satisfy the
# pin vacuously (O15B §7 sentinel discipline).
declare -A NEG_OFF
for n in $NODES; do
    NEG_OFF[$n]=$(wc -l < "${CUR_LOG[$n]}" 2>/dev/null || echo 0)
done
bump_nonce; NNONCE=$NONCE
# The submit may itself return non-zero (client told ERROR); that is the
# EXPECTED negative outcome, not a script failure.
submit_cc 4 31 "$EFF" "$NNONCE" "$(succ_pump_keys)" || true
neg_seen=0
neg_deadline=$(( SECONDS + 120 ))
while [ $SECONDS -lt $neg_deadline ]; do
    for n in $NODES; do
        if tail -n +$(( ${NEG_OFF[$n]} + 1 )) "${CUR_LOG[$n]}" 2>/dev/null \
             | grep -qE "REJECTED by the engine|BATCH COMMIT FAILED"; then
            neg_seen=1; break
        fi
    done
    [ "$neg_seen" = 1 ] && break
    submit_pump || true    # keep the chain live so a leader runs the reject
    sleep 4
done
[ "$neg_seen" = 1 ] || fail "31-target CC was not visibly rejected in any node log"
# And the target must NOT have moved to 31 anywhere.
BADSNAP=$(assert_same_succ "no 31-member snapshot" \
    "SELECT COUNT(*) FROM validator_set_snapshots WHERE active_count > 30;")
[ "$BADSNAP" = "0" ] || fail "a snapshot with active_count > 30 was committed"
ok "31-target CC rejected (engine verdict); no >30 snapshot ever committed"

# ══════════════════════════════════════════════════════════════════════
# STEP 8 — BARRIER: every joiner (launched at STEP 5b) must ADOPT the
# pinned genesis AND catch up to head BEFORE the chain crosses e*. If it
# crossed with unsynced joiners, the 20-validator committee (quorum 14)
# could not reach quorum from the 7 old nodes alone and the chain would
# halt. We WAIT concurrently (all 13 bootstrap in parallel), gently
# pumping so the Faz B sync driver keeps broadcasting head hints — but
# NEVER above CEIL, which is strictly below e* (e* >= EFF, so EFF-E is
# below every height whose committee is the 20-set).
# ══════════════════════════════════════════════════════════════════════
info "STEP 8 — barrier: waiting for all 13 joiners to adopt + catch up"
CEIL=$(( EFF - E_LEN ))   # gentle-pump ceiling: strictly below e*
barrier_pump() {   # one inert pump ONLY while the head is safely below e*
    [ "$(succ_height 1)" -lt "$CEIL" ] && { submit_pump || true; }
    return 0
}

# Phase 1 — ALL 13 adopt (shared, generous deadline; O15E allowed 420s
# for ONE joiner, 13 simultaneous need far more).
#
# STRAGGLER RESTART (orchestrator fix): the committee's transport-layer
# identification of 13 SIMULTANEOUS joiners is wall-clock variable — most
# get an identified 4004 peer (and send their gbundle request) within a
# couple of minutes, but a straggler or two can miss the window entirely
# (armed, roster formed, but no identified peer to pull from). This is a
# localhost-scale timing artifact of the DHT registry + committee dial,
# NOT a consensus issue (state_root stays deterministic). A restart
# re-publishes the joiner's nodus:pk and re-arms the join, forcing a
# fresh visibility + dial cycle (the O15B.1 republish mechanism). We
# restart any un-adopted joiner every RESTART_EVERY seconds.
# O15G — adoption is STICKY across restarts. A joiner writes a FRESH run
# log on every (re)start (start_node bumps CUR_LOG[$n]), and once it already
# holds the successor chain it does NOT re-emit the "adopted from a peer
# bundle (pin matched)" line. Grepping only CUR_LOG[$n] (the latest log)
# therefore FALSE-NEGATIVES an already-adopted joiner and restarts it
# forever, dropping it back into DISCOVER (the barrier thrash observed
# 2026-08-25). Check ALL of the node's logs — adoption in ANY of them is
# permanent.
joiner_adopted() {   # $1 = node
    grep -qs "adopted from a peer bundle (pin matched)" \
        "$BASE_DIR/node$1/"run_*.log "$BASE_DIR/node$1/nodus.log" 2>/dev/null
}
adopt_deadline=$(( SECONDS + 2400 ))
RESTART_EVERY=300
next_restart=$(( SECONDS + RESTART_EVERY ))
all_adopted=0
while [ $SECONDS -lt $adopt_deadline ]; do
    all_adopted=1
    for n in $(seq $CAND_LO $CAND_HI); do
        joiner_adopted "$n" || { all_adopted=0; break; }
    done
    [ "$all_adopted" = 1 ] && break
    if [ $SECONDS -ge $next_restart ]; then
        for n in $(seq $CAND_LO $CAND_HI); do
            joiner_adopted "$n" && continue
            info "barrier: restarting straggler joiner node$n (re-publish + re-arm)"
            stop_node "$n"; sleep 2
            start_node "$n" --v2-genesis-pin "$GENESIS_PIN"
        done
        next_restart=$(( SECONDS + RESTART_EVERY ))
    fi
    barrier_pump
    sleep 8
done
if [ "$all_adopted" != 1 ]; then
    for n in $(seq $CAND_LO $CAND_HI); do
        joiner_adopted "$n" || echo "  node$n: NOT adopted" >&2
    done
    fail "not all joiners adopted the successor genesis within the barrier"
fi
ok "all 13 joiners adopted the successor genesis on a pin match"

# Phase 2 — ALL 13 catch up to a FROZEN head.
#
# TWO discipline changes vs the naive version (which crashed a committee
# node under load):
#  1. THE HEAD IS HELD STILL — no barrier_pump here. A moving head makes
#     every joiner perpetually ~1 behind, which never satisfies all_caught
#     AND (with a restart-if-behind rule) restarts ~all joiners every cycle,
#     flooding the 7-node committee with reconnect/w_ident storms until a
#     committee node exits ("bootstrap max attempts exhausted"). A static
#     target lets the joiners converge and stay converged. The head is
#     already < CEIL < e*, so the committee is still the 7 originals here.
#  2. SURGICAL RESTART — a joiner is restarted ONLY when it is TRULY STUCK
#     (its height has not advanced since the previous check), never merely
#     because it is behind. A joiner that is actively syncing is left
#     alone. At most 3 restarts per check, so a bad round can never become
#     a flood. A restart re-publishes the joiner's nodus:pk so a committee
#     node that did not yet have it in its transport roster (and was
#     dropping its range requests as "unknown sender") picks it up.
catchup_deadline=$(( SECONDS + 2400 ))
declare -A CU_LAST
for n in $(seq $CAND_LO $CAND_HI); do CU_LAST[$n]=-1; done
next_cu_check=$(( SECONDS + 150 ))
head=$(succ_height 1)   # FROZEN catch-up target
info "barrier: catch-up target frozen at head=$head (no pumping until all synced)"
all_caught=0
while [ $SECONDS -lt $catchup_deadline ]; do
    all_caught=1
    for n in $(seq $CAND_LO $CAND_HI); do
        [ "$(succ_height "$n")" -ge "$head" ] || { all_caught=0; break; }
    done
    [ "$all_caught" = 1 ] && break
    if [ $SECONDS -ge $next_cu_check ]; then
        restarted=0
        for n in $(seq $CAND_LO $CAND_HI); do
            h=$(succ_height "$n"); h=${h:-0}
            [ "$h" -ge "$head" ] && { CU_LAST[$n]=$h; continue; }
            if [ "$h" -le "${CU_LAST[$n]}" ] && [ $restarted -lt 3 ]; then
                info "barrier: restarting STUCK catch-up joiner node$n (h=$h, no progress since last check)"
                stop_node "$n"; sleep 2
                start_node "$n" --v2-genesis-pin "$GENESIS_PIN"
                restarted=$(( restarted + 1 ))
            fi
            CU_LAST[$n]=$h
        done
        next_cu_check=$(( SECONDS + 150 ))
    fi
    sleep 8
done
[ "$all_caught" = 1 ] || \
    fail "not all joiners caught up to head within the barrier"
NODES="$(seq 1 $TOTAL | tr '\n' ' ')"
converge_succ "joiners caught up (20 nodes)" 600
ok "13 joiners adopted + caught up; cluster is 20 nodes, head below e*"
# Brief settle so the 20-way transport rosters fully converge before the
# boundary; the step-9 pump to e* (many blocks) also covers this, so this
# is insurance, not a timing bet — the barrier above is the real gate.
sleep 30

# ══════════════════════════════════════════════════════════════════════
# STEP 9 — pump to e*-1: governing snapshot N=7, Q=5; snapshot(e*)
# (committed at boundary e*-E) contains all 20, hash identical on all 20.
#
# e* is DISCOVERED, not assumed: pump and poll for the first 20-member
# snapshot (grow/shrink discipline — the tenure interaction picks the
# exact boundary). Its epoch_start IS e*, and it must be boundary-aligned
# and at/after the governed effective height.
# ══════════════════════════════════════════════════════════════════════
info "STEP 9 — pumping to the governed boundary; discovering e*"
grow_deadline=$(( SECONDS + 1200 ))
while [ $SECONDS -lt $grow_deadline ]; do
    ESTAR=$(sqlite3 -readonly "$(succ_db 1)" \
        "SELECT epoch_start FROM validator_set_snapshots \
         WHERE active_count = 20 ORDER BY epoch_start LIMIT 1;" 2>/dev/null)
    [ -n "$ESTAR" ] && break
    pump_succ $(( $(succ_height 1) + E_LEN )) 300
done
[ -n "$ESTAR" ] || fail "no 20-member snapshot ever appeared"
[ $(( ESTAR % E_LEN )) -eq 0 ] || fail "e*=$ESTAR is not an epoch boundary"
[ "$ESTAR" -ge "$EFF" ] || fail "e*=$ESTAR is before the effective height $EFF"
info "discovered e* = $ESTAR (snapshot(e*) committed at boundary $(( ESTAR - E_LEN )))"

# snapshot(e*) contains all 20 and is hash-identical on all 20 nodes.
pump_succ $(( ESTAR - E_LEN )) 600   # ensure the boundary that commits it passed
converge_succ "snapshot(e*) committed" 600
assert_same_succ "snapshot(e*) hash" \
    "SELECT active_count || '|' || hex(snapshot_hash) \
     FROM validator_set_snapshots WHERE epoch_start = $ESTAR;" > /dev/null
for n in $(seq 1 $TOTAL); do
    pk=$(node_pubkey_hex "$n")
    [ "$(snapshot_contains "$ESTAR" "$pk")" = "1" ] || \
        fail "node$n absent from the snapshot(e*=$ESTAR)"
done
ok "snapshot(e*=$ESTAR) contains all 20, hash identical across 20 nodes"

# Pump to e*-1 and assert the GOVERNING committee there is still 7 (Q=5).
pump_succ $(( ESTAR - 1 )) 600
converge_succ "e*-1"
GOV_PREV=$(sqlite3 -readonly "$(succ_db 1)" \
    "SELECT active_count FROM validator_set_snapshots \
     WHERE epoch_start = $(( ESTAR - E_LEN ));")
[ "$GOV_PREV" = "7" ] || fail "governing snapshot at e*-1 is $GOV_PREV, expected 7"
EXPECT_Q5=$(( (2 * 7) / 3 + 1 ))
# The 7-committee has run every round since successor genesis, so its
# quorum line is already in node1's (cumulative) current log.
grep -q "quorum=$EXPECT_Q5)" "${CUR_LOG[1]}" 2>/dev/null || \
    fail "no quorum=$EXPECT_Q5 round observed before e* (N=7 not enforced)"
ok "at e*-1 the governing set is N=7 (Q=5)"

# ══════════════════════════════════════════════════════════════════════
# STEP 10 — height e* onward: N=20, Q=14 (resolver + header vset_hash).
# ══════════════════════════════════════════════════════════════════════
info "STEP 10 — crossing e*=$ESTAR: N=20, Q=14"
VSET_PRE=$(sqlite3 -readonly "$(succ_db 1)" \
    "SELECT hex(vset_hash) FROM v2_blocks WHERE global_height = $(( ESTAR - 1 ));")
pump_succ "$ESTAR" 600
converge_succ "at e*"
assert_succ_block_identity "$ESTAR"
wait_qc "$ESTAR" 120 || fail "e* boundary block QC not attached on all 20"
GOV_NOW=$(sqlite3 -readonly "$(succ_db 1)" \
    "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$ESTAR;")
[ "$GOV_NOW" = "20" ] || fail "governing snapshot at e* is $GOV_NOW, expected 20"
VSET_AT=$(sqlite3 -readonly "$(succ_db 1)" \
    "SELECT hex(vset_hash) FROM v2_blocks WHERE global_height = $ESTAR;")
[ "$VSET_AT" != "$VSET_PRE" ] || fail "header vset_hash did not change at e*"
EXPECT_Q14=$(( (2 * 20) / 3 + 1 ))
q14_seen=0; q_deadline=$(( SECONDS + 300 ))
while [ $SECONDS -lt $q_deadline ]; do
    grep -q "quorum=$EXPECT_Q14)" "${CUR_LOG[1]}" 2>/dev/null && { q14_seen=1; break; }
    pump_succ $(( $(succ_height 1) + 1 )) 90
done
[ "$q14_seen" = 1 ] || fail "dynamic quorum never reached $EXPECT_Q14 after e*"
ok "at e* the committee is N=20, Q=14, header vset_hash changed (identity 20/20)"
stagef_sentinel ASSERT_RUN

# ══════════════════════════════════════════════════════════════════════
# STEP 11 — liveness matrix at N=20 / Q=14.
#   (a) stop 6 (14 alive) -> advances
#   (b) stop 1 more (13 alive) -> NO progress for >=3 round timeouts
#   (c) restart 1 (14 alive) -> resumes
#   (d) old-set-alone: stop all 13 new (7 old < Q14) -> no progress; restart
# node1 stays UP throughout (the pump submission target).
# ══════════════════════════════════════════════════════════════════════
info "STEP 11 — liveness matrix"
RTO_MS=5000                              # view_change_timeout_ms (chain_def)
NO_PROGRESS_WINDOW=$(( 3 * RTO_MS / 1000 + 10 ))

# (a) stop 6 of 20 (nodes 15..20) -> 14 alive -> advances.
for n in $(seq 15 20); do stop_node "$n"; done
sleep 4
NODES="$(seq 1 14 | tr '\n' ' ')"
H_A=$(succ_height 1)
pump_succ $(( H_A + 2 )) 300
ok "(a) 14/20 alive -> chain advanced to $(succ_height 1)"

# (b) stop 1 more (node14) -> 13 alive -> NO progress.
stop_node 14
# Let any round that already reached quorum before the stop commit and the
# chain quiesce (> one round timeout) BEFORE the baseline read, so lag can
# never masquerade as progress.
sleep $(( RTO_MS / 1000 + 3 ))
NODES="$(seq 1 13 | tr '\n' ' ')"
H_B=$(succ_height 1)
submit_pump || true          # a pending TX that CANNOT commit (13 < Q14)
sleep "$NO_PROGRESS_WINDOW"
H_B2=$(succ_height 1)
[ "$H_B2" = "$H_B" ] || fail "(b) chain advanced with only 13/20 alive ($H_B -> $H_B2)"
ok "(b) 13/20 alive (< Q14) -> no progress across >=3 round timeouts (tip $H_B)"

# (c) restart node14 -> 14 alive -> resumes.
start_node 14 --v2-genesis-pin "$GENESIS_PIN"
wait_armed 14 200 || info "node14 arm-line not seen yet (may arm post-catchup)"
NODES="$(seq 1 14 | tr '\n' ' ')"
H_C=$(succ_height 1)
pump_succ $(( H_C + 2 )) 300
ok "(c) restarted node14 -> 14/20 alive -> chain resumed to $(succ_height 1)"

# Bring 15..20 back so the full 20 are available for the old-set probe.
for n in $(seq 15 20); do start_node "$n" --v2-genesis-pin "$GENESIS_PIN"; done
for n in $(seq 15 20); do wait_armed "$n" 200 || true; done
NODES="$(seq 1 $TOTAL | tr '\n' ' ')"
converge_succ "all 20 back" 600

# (d) old-set-alone: stop all 13 new validators (nodes 8..20) -> only the
# 7 originals alive -> 7 < Q14 -> no progress; then restart them.
for n in $(seq $CAND_LO $CAND_HI); do stop_node "$n"; done
# Quiesce past one round timeout before the baseline read (see (b)).
sleep $(( RTO_MS / 1000 + 3 ))
NODES="$(seq 1 $ORIG | tr '\n' ' ')"
H_D=$(succ_height 1)
submit_pump || true          # a pending TX that CANNOT commit (7 < Q14)
sleep "$NO_PROGRESS_WINDOW"
H_D2=$(succ_height 1)
[ "$H_D2" = "$H_D" ] || fail "(d) old 7 alone advanced the chain ($H_D -> $H_D2)"
ok "(d) old 7 alone (< Q14) -> no progress; the new set is required"
for n in $(seq $CAND_LO $CAND_HI); do
    start_node "$n" --v2-genesis-pin "$GENESIS_PIN"
done
for n in $(seq $CAND_LO $CAND_HI); do wait_armed "$n" 200 || true; done
NODES="$(seq 1 $TOTAL | tr '\n' ' ')"
converge_succ "old-set probe recovered" 600
H_DR=$(succ_height 1)
pump_succ $(( H_DR + 1 )) 300
ok "(d) new set restarted -> chain resumed"

# ══════════════════════════════════════════════════════════════════════
# STEP 12 — stop-all restart once more (already done once before the
# boundary at step 3); do it now AFTER the boundary. Production resumes
# from the committed tip both times.
# ══════════════════════════════════════════════════════════════════════
info "STEP 12 — stop-all restart AFTER the boundary"
TIP_BEFORE=$(succ_height 1)
for n in $(seq 1 $TOTAL); do stop_node "$n"; done
sleep 5
for n in $(seq 1 $TOTAL); do
    if [ "$n" -le "$ORIG" ]; then start_node "$n"
    else start_node "$n" --v2-genesis-pin "$GENESIS_PIN"; fi
done
for n in $(seq 1 $TOTAL); do
    wait_armed "$n" 200 || fail "node$n did not re-arm after the stop-all restart"
done
converge_succ "post stop-all restart" 600
TIP_RESUME=$(succ_height 1)
[ "$TIP_RESUME" -ge "$TIP_BEFORE" ] || \
    fail "stop-all restart lost successor blocks ($TIP_RESUME < $TIP_BEFORE)"
sleep 5
pump_succ $(( TIP_RESUME + 1 )) 300
ok "stop-all restart after the boundary resumed from tip $TIP_RESUME"

# ══════════════════════════════════════════════════════════════════════
# STEP 13 — catch-up: keep ONE original-7 node (node2) down ACROSS the
# NEXT boundary, then restart it — it must sync through the 7->20
# transition (historical N7 QCs verified with historical snapshots) to
# head.
# ══════════════════════════════════════════════════════════════════════
info "STEP 13 — original node2 down across the next boundary, then catch up"
H_NOW=$(succ_height 1)
NEXT_B=$(( (H_NOW / E_LEN + 1) * E_LEN ))
stop_node 2
sleep 3
NODES="1 $(seq 3 $TOTAL | tr '\n' ' ')"
pump_succ $(( NEXT_B + 1 )) 900
ok "boundary $NEXT_B crossed without node2"
start_node 2
wait_armed 2 200 || fail "node2 did not re-arm"
t=0
while [ $t -lt 600 ]; do
    ref=$(succ_height 1); vh=$(succ_height 2)
    [ "${vh:-0}" -ge "$ref" ] && break
    sleep 5; t=$(( t + 5 ))
done
[ "$(succ_height 2)" -ge "$(succ_height 1)" ] || \
    fail "node2 did not catch up through the transition"
NODES="$(seq 1 $TOTAL | tr '\n' ' ')"
converge_succ "node2 caught up through 7->20" 600
ok "node2 synced through the 7->20 transition to head (historical QCs verified)"

# ══════════════════════════════════════════════════════════════════════
# STEP 14 — fresh joiner AFTER the boundary: full replay genesis->head
# across the transition. Reuse node20's slot with a wiped data dir.
# ══════════════════════════════════════════════════════════════════════
info "STEP 14 — fresh joiner (node20) full replay genesis->head after e*"
stop_node 20
sleep 3
rm -rf "$BASE_DIR/node20/data"; mkdir -p "$BASE_DIR/node20/data"
NODES="$(seq 1 19 | tr '\n' ' ')"
HEAD_F=$(succ_height 1)
start_node 20 --v2-genesis-pin "$GENESIS_PIN"
t=0; adopted=0
while [ $t -lt 400 ]; do
    grep -q "adopted from a peer bundle (pin matched)" "${CUR_LOG[20]}" \
        2>/dev/null && { adopted=1; break; }
    sleep 3; t=$(( t + 3 ))
done
[ "$adopted" = 1 ] || fail "fresh node20 did not adopt genesis from the bundle"
t=0
while [ $t -lt 600 ]; do
    [ "$(succ_height 20)" -ge "$HEAD_F" ] && break
    sleep 5; t=$(( t + 5 ))
done
[ "$(succ_height 20)" -ge "$HEAD_F" ] || \
    fail "fresh node20 did not replay to head $HEAD_F"
NODES="$(seq 1 $TOTAL | tr '\n' ' ')"
converge_succ "fresh joiner replayed" 600
ok "fresh joiner replayed genesis->head across the 7->20 transition"

# ══════════════════════════════════════════════════════════════════════
# STEP 15 — QC audit: every committed height (>=1) has a stored, verified
# QC on every node (the attach path runs nodus_witness_v2_qc_verify
# against committed authority before writing). Missing-QC recovery
# (O15E Faz C) is allowed to heal any lag first.
# ══════════════════════════════════════════════════════════════════════
info "STEP 15 — QC audit across all 20 nodes"
qc_ok=0; qc_deadline=$(( SECONDS + 240 ))
while [ $SECONDS -lt $qc_deadline ]; do
    miss=0
    for n in $NODES; do
        m=$(sqlite3 -readonly "$(succ_db "$n")" \
            "SELECT COUNT(*) FROM v2_blocks \
             WHERE global_height >= 1 AND qc IS NULL;" 2>/dev/null || echo 1)
        [ "${m:-1}" = "0" ] || { miss=1; break; }
    done
    [ "$miss" = 0 ] && { qc_ok=1; break; }
    sleep 5
done
[ "$qc_ok" = 1 ] || fail "some committed height still has a NULL QC on a node"
ok "QC audit: every committed height >=1 carries a verified QC on all 20 nodes"

# ══════════════════════════════════════════════════════════════════════
# STEP 16 — continue >= one further epoch (e*+E); terminal identity: all
# 20 byte-identical BlockID/global root/vset hash/committee/head; terminal
# V1 DBs byte-identical to step-3 hashes; no legacy block on the successor.
# ══════════════════════════════════════════════════════════════════════
E_PLUS=$(( ESTAR + E_LEN ))
info "STEP 16 — continuing past e*+E = $E_PLUS"
pump_succ "$E_PLUS" 900
wait_qc "$E_PLUS" 120 || fail "block $E_PLUS QC not attached on all 20"
converge_succ "terminal" 600

TERM_HEAD=$(succ_height 1)
assert_same_succ "terminal head" \
    "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks;" > /dev/null
assert_succ_block_identity "$TERM_HEAD"
assert_same_succ "terminal governing snapshot" \
    "SELECT epoch_start || '|' || active_count || '|' || hex(snapshot_hash) \
     FROM validator_set_snapshots WHERE epoch_start = $ESTAR;" > /dev/null
# committee identity: the full snapshot series read back byte-identical.
# A plain ORDER BY yields deterministic row order (compared as one
# multi-line string) — no group_concat, whose ordering is unspecified.
assert_same_succ "full snapshot series" \
    "SELECT epoch_start || ':' || active_count || ':' || hex(snapshot_hash) \
     FROM validator_set_snapshots ORDER BY epoch_start;" > /dev/null
LB=$(assert_same_succ "legacy blocks on successor" \
    "SELECT COALESCE(MAX(height),0) FROM blocks;")
[ "$LB" = "0" ] || fail "a legacy block appeared on the successor: $LB"
ok "terminal identity byte-identical across all 20 nodes; no legacy block on successor"

# Terminal V1 databases untouched end-to-end (only the 7 originals hold one).
for n in $(seq 1 $ORIG); do
    now=$(sha256sum "$BASE_DIR/node$n/data/$LEGACY_BASENAME" | awk '{print $1}')
    [ "$now" = "${TERM_SHA[$n]}" ] || \
        fail "node$n terminal V1 database bytes changed during the run"
    hl=$(sqlite3 -readonly "$BASE_DIR/node$n/data/$LEGACY_BASENAME" \
        "SELECT COALESCE(MAX(height),0) FROM blocks;")
    [ "$hl" = "$H_ACT_REAL" ] || fail "node$n terminal V1 advanced past $H_ACT_REAL: $hl"
done
ok "terminal V1 databases byte-identical to step-3 hashes (frozen at H_act_real=$H_ACT_REAL)"

# ══════════════════════════════════════════════════════════════════════
# STEP 17 — sentinels + PASS.
# ══════════════════════════════════════════════════════════════════════
stagef_sentinel PASS
echo
echo "=== O15F SUCCESSOR VALIDATOR-SET GROWTH 7->20 REHEARSAL PASSED ==="
echo "    e* = $ESTAR, terminal head = $TERM_HEAD, 20 nodes byte-identical"
