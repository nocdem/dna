#!/usr/bin/env bash
#
# Stage F harness — bring up a 3-node localhost cluster and submit
# genesis. On success, emits the BASE_DIR path for later tests to
# use.
#
# See stagef/README.md for layout and isolation guarantees.

set -euo pipefail

# Resolve env (binaries, ports).
. "$(dirname "${BASH_SOURCE[0]}")/stagef_env.sh"

# ── Preflight ───────────────────────────────────────────────────────

if [ ! -x "$STAGEF_NODUS_BIN" ]; then
    echo "[FAIL] missing: $STAGEF_NODUS_BIN" >&2
    echo "       build: cd $STAGEF_REPO_ROOT/nodus/build && make -j\$(nproc)" >&2
    exit 1
fi
if [ ! -x "$STAGEF_DNACLI_BIN" ]; then
    echo "[FAIL] missing: $STAGEF_DNACLI_BIN" >&2
    echo "       build: cd $STAGEF_REPO_ROOT/messenger/build && make -j\$(nproc)" >&2
    exit 1
fi

# Refuse to run if a prior harness is still up.
if [ -f "$STAGEF_POINTER" ]; then
    prev="$(cat "$STAGEF_POINTER")"
    echo "[FAIL] existing Stage F run detected at $prev" >&2
    echo "       run stagef_down.sh first" >&2
    exit 2
fi

port_in_use() {
    ss -ltun 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${1}\$"
}

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    for port in "$(stagef_udp_port "$n")" \
                "$(stagef_tcp_port "$n")" \
                "$(stagef_peer_port "$n")" \
                "$(stagef_chan_port "$n")" \
                "$(stagef_witness_port "$n")"; do
        if port_in_use "$port"; then
            echo "[FAIL] node $n port $port already in use" >&2
            exit 3
        fi
    done
done
echo "[ok] binaries present, ports 14000-34004 free"

# ── Create BASE_DIR ─────────────────────────────────────────────────

TS=$(date +%Y%m%dT%H%M%SZ)
BASE_DIR="/tmp/stagef-$TS"
mkdir -p "$BASE_DIR"
echo "$BASE_DIR" > "$STAGEF_POINTER"
echo "[ok] BASE_DIR=$BASE_DIR"

# Export + re-source so helpers pick it up.
export BASE_DIR
. "$(dirname "${BASH_SOURCE[0]}")/stagef_env.sh"

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    mkdir -p "$BASE_DIR/node$n/identity" "$BASE_DIR/node$n/data"
done
mkdir -p "$(stagef_user_home)/.dna"
echo "[ok] dir layout created"

# ── Seed user dna.conf with node1 as bootstrap ──────────────────────
# qgp_platform_app_data_dir uses $HOME/.dna on Linux, so writing
# $BASE/user/.dna/dna.conf isolates the test user from punk.

bootstrap_csv=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    [ -n "$bootstrap_csv" ] && bootstrap_csv="$bootstrap_csv,"
    bootstrap_csv="${bootstrap_csv}127.0.0.1:$(stagef_tcp_port "$n")"
done
# NOTE: config file is named "config" (not "dna.conf") — see
# messenger/dna_config.c CONFIG_FILE_NAME. Writing the wrong name
# silently makes the CLI fall back to production defaults.
cat > "$(stagef_user_home)/.dna/config" <<EOF
log_level=INFO
log_file_enabled=0
bootstrap_nodes=$bootstrap_csv
EOF
echo "[ok] user config written ($STAGEF_COMMITTEE_SIZE bootstrap entries)"

# ── Pre-generate identities by one-shot boot per node ───────────────
# nodus-server auto-generates identity on first boot if files missing.
# We spawn each briefly to create the .pk/.sk/.kyber_* files, then
# stop. Identity binding to the port layout happens now.

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    node_dir=$(stagef_node_dir "$n")
    # Short-lived spawn that just generates identity then we kill it.
    "$STAGEF_NODUS_BIN" \
        -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" \
        -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" \
        -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$node_dir/identity" \
        -d "$node_dir/data" \
        > "$node_dir/identity_gen.log" 2>&1 &
    ig_pid=$!
    # Wait for identity files to appear.
    for _ in $(seq 1 40); do
        if [ -s "$node_dir/identity/nodus.pk" ] && \
           [ -s "$node_dir/identity/nodus.sk" ] && \
           [ -s "$node_dir/identity/nodus.fp" ]; then
            break
        fi
        sleep 0.25
    done
    kill "$ig_pid" 2>/dev/null || true
    wait "$ig_pid" 2>/dev/null || true
    if [ ! -s "$node_dir/identity/nodus.pk" ]; then
        echo "[FAIL] node $n identity generation failed (see $node_dir/identity_gen.log)" >&2
        exit 4
    fi
    echo "[ok] node $n identity generated ($(stat -c%s "$node_dir/identity/nodus.pk") bytes pk)"
done

# ── Build chain_def.conf ────────────────────────────────────────────
# genesis-prepare expects a KEY=VALUE file with validator_N_pubkey=hex
# entries. Committee size is 3 for this harness.

CD_CONF="$BASE_DIR/chain_def.conf"
{
    echo "chain_name=stagef"
    echo "protocol_version=1"
    echo "witness_count=0"
    echo "max_active_witnesses=21"
    echo "block_interval_sec=5"
    echo "max_txs_per_block=10"
    echo "view_change_timeout_ms=5000"
    echo "token_symbol=DNAC"
    echo "token_decimals=8"
    echo "initial_supply_raw=100000000000000000"
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        idx=$(( n - 1 ))
        node_dir=$(stagef_node_dir "$n")
        pk_hex=$(xxd -p -c 99999 "$node_dir/identity/nodus.pk")
        fp_hex=$(cat "$node_dir/identity/nodus.fp")
        echo "validator_${idx}_pubkey=$pk_hex"
        echo "validator_${idx}_fp=$fp_hex"
        echo "validator_${idx}_commission_bps=500"
        echo "validator_${idx}_endpoint=127.0.0.1:$(stagef_witness_port "$n")"
    done
} > "$CD_CONF"
echo "[ok] chain_def.conf built ($STAGEF_COMMITTEE_SIZE validators)"

# ── Spawn nodus-server instances BEFORE any CLI connect ─────────────
# CRITICAL ORDER: the CLI's singleton init does a DHT connect on
# first run and the FIRST server it reaches gets saved to
# ~/.dna/known_nodes via TOFU. If we create the user identity before
# the harness nodes are listening, the CLI falls through to the
# hardcoded production fallback, caches production IPs, and every
# subsequent CLI call (including genesis-create) ignores the config
# file's stagef bootstrap list.
# Pass all nodes as seed to each other (UDP Kademlia bootstrap).

SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done

# Shared JSON config: enable require_peer_auth so the Dilithium5 handshake
# runs on the witness TCP port (4004/+stride). Without this, on_witness_frame
# ignores hello messages and on_witness_connect never sends hello — the
# witness mesh cannot form on a fresh cluster. Production sets this via
# /etc/nodus.conf; stagef needs the same knob. CLI args override JSON.
cat > "$BASE_DIR/nodus.json" <<EOF
{ "require_peer_auth": true }
EOF

: > "$BASE_DIR/pids.txt"
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    node_dir=$(stagef_node_dir "$n")
    # shellcheck disable=SC2086
    "$STAGEF_NODUS_BIN" \
        -c "$BASE_DIR/nodus.json" \
        -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" \
        -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" \
        -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$node_dir/identity" \
        -d "$node_dir/data" \
        $SEEDS \
        > "$node_dir/nodus.log" 2>&1 &
    echo $! >> "$BASE_DIR/pids.txt"
    echo "[ok] node $n spawned pid=$!"
done

# Wait for all TCP client ports to accept.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    tcp=$(stagef_tcp_port "$n")
    for _ in $(seq 1 60); do
        if ss -lt 2>/dev/null | grep -Eq "[:.]${tcp}\\b"; then
            break
        fi
        sleep 0.25
    done
    if ! ss -lt 2>/dev/null | grep -Eq "[:.]${tcp}\\b"; then
        echo "[FAIL] node $n TCP $tcp never opened" >&2
        exit 8
    fi
done
echo "[ok] all $STAGEF_COMMITTEE_SIZE nodes listening"

# Wait for BFT peer mesh + tier-2 accept loop to be fully responsive.
# Too-short wait leads to auth timeouts on first CLI connect, which
# trigger fallback to hardcoded production IPs (see known_nodes TOFU
# upsert in nodus_init.c — that's how production leaks into what
# should be a fully isolated HOME).
#
# Also: leader election + roster convergence are multi-stage. 10 s was
# not enough: the genesis TX could reach a node whose roster/leader
# view was still settling, triggering w_fwd_req to a non-leader and a
# 30 s pending-forward timeout. Poll the committee on each node until
# each reports the full 7-member roster with non-zero quorum, or 30 s
# elapses. Cheap loop; no impact on stable clusters.
deadline=$(( SECONDS + 30 ))
while [ $SECONDS -lt $deadline ]; do
    ready=1
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        log="$(stagef_node_dir "$n")/nodus.log"
        if ! grep -q "epoch roster swap: $STAGEF_COMMITTEE_SIZE witnesses, quorum=5" "$log" 2>/dev/null; then
            ready=0
            break
        fi
    done
    [ $ready -eq 1 ] && break
    sleep 1
done
if [ $ready -eq 1 ]; then
    echo "[ok] all $STAGEF_COMMITTEE_SIZE nodes reached roster=$STAGEF_COMMITTEE_SIZE"
else
    echo "[warn] not all nodes reached full roster within 30 s; continuing anyway"
fi

# Pre-populate known_nodes cache with stagef entries so Source 1 of
# nodus_init's bootstrap order is already stagef-biased. Format:
# ip:port|dil_fp|kyber_hash|last_seen|rtt  (TOFU fills fp/kyber).
{
    ts=$(date +%s)
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        fp=$(cat "$(stagef_node_dir "$n")/identity/nodus.fp" | head -c 32)
        echo "127.0.0.1:$(stagef_tcp_port "$n")|$fp|$(printf '%.32s' "$fp")|$ts|1"
    done
} > "$(stagef_user_home)/.dna/known_nodes"
echo "[ok] known_nodes pre-seeded with $STAGEF_COMMITTEE_SIZE stagef entries"

# Also pre-set preferred_node so CLI's prioritize_server picks a
# stagef node for the first connect attempt.
echo "127.0.0.1:$(stagef_tcp_port 1)|1" > "$(stagef_user_home)/.dna/preferred_node"

# ── Create user identity (now that stagef nodes are reachable) ──────
# Any CLI call triggers singleton init + bootstrap connect. We want
# the first connect to hit a stagef node, NOT a hardcoded production
# fallback — else known_nodes caches production.

USER_FP_FILE="$BASE_DIR/user_fp.txt"
USER_NAME="stagef_user"
USER_PW="stagef"
(
    # Scrub cache so CLI rebuilds bootstrap list from config only
    # (belt & suspenders alongside DNA_NO_FALLBACK=1 — see stagef_env.sh).
    rm -f "$(stagef_user_home)/.dna/known_nodes" \
          "$(stagef_user_home)/.dna/preferred_node"
    export HOME="$(stagef_user_home)"
    export DNA_NO_FALLBACK=1
    "$STAGEF_DNACLI_BIN" -q identity create "$USER_NAME" "$USER_PW" \
        > "$BASE_DIR/user_create.log" 2>&1 || true
)
rm -f "$(stagef_user_home)/.dna/known_nodes" \
      "$(stagef_user_home)/.dna/preferred_node"
USER_FP=$(HOME="$(stagef_user_home)" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" -q identity whoami 2>&1 \
    | awk '/^Current identity:/ {print $3; exit}')
if [ -z "$USER_FP" ] || [ ${#USER_FP} -lt 64 ]; then
    echo "[FAIL] could not resolve test user fingerprint" >&2
    exit 5
fi
echo "$USER_FP" > "$USER_FP_FILE"
echo "[ok] user identity fp: $(echo "$USER_FP" | head -c 16)..."

# Sanity: assert no production IPs leaked into known_nodes.
if [ -f "$(stagef_user_home)/.dna/known_nodes" ]; then
    if grep -Eq '(154\.38|156\.67|161\.97|164\.68|75\.119)' \
        "$(stagef_user_home)/.dna/known_nodes"; then
        echo "[FAIL] production IP leaked into user known_nodes cache" >&2
        cat "$(stagef_user_home)/.dna/known_nodes" >&2
        exit 5
    fi
fi
echo "[ok] known_nodes clean (no production IPs)"

# ── Run genesis-prepare + submit ────────────────────────────────────

CD_BIN="$BASE_DIR/chain_def.bin"
(
    # Scrub cache so CLI rebuilds bootstrap list from config only
    # (belt & suspenders alongside DNA_NO_FALLBACK=1 — see stagef_env.sh).
    rm -f "$(stagef_user_home)/.dna/known_nodes" \
          "$(stagef_user_home)/.dna/preferred_node"
    export HOME="$(stagef_user_home)"
    export DNA_NO_FALLBACK=1
    "$STAGEF_DNACLI_BIN" -q dna genesis-prepare "$CD_CONF" \
        > "$BASE_DIR/genesis_prepare.stdout" \
        2> "$BASE_DIR/genesis_prepare.stderr" || {
        echo "[FAIL] genesis-prepare failed" >&2
        cat "$BASE_DIR/genesis_prepare.stderr" >&2
        exit 6
    }
)
# genesis-prepare stdout contains CLI boilerplate ("Loading
# identity...") above the raw hex. Strip to pure-hex lines before
# decoding. A valid hex line is >=64 chars of [0-9a-f] with no
# colons/spaces.
grep -E '^[0-9a-f]{64,}$' "$BASE_DIR/genesis_prepare.stdout" \
    | tr -d '\n' \
    | xxd -r -p > "$CD_BIN"
if [ ! -s "$CD_BIN" ]; then
    echo "[FAIL] chain_def.bin empty — stdout may have new format" >&2
    head -20 "$BASE_DIR/genesis_prepare.stdout" >&2
    exit 7
fi
echo "[ok] chain_def.bin built ($(stat -c%s "$CD_BIN") bytes)"

(
    # Scrub cache so CLI rebuilds bootstrap list from config only
    # (belt & suspenders alongside DNA_NO_FALLBACK=1 — see stagef_env.sh).
    rm -f "$(stagef_user_home)/.dna/known_nodes" \
          "$(stagef_user_home)/.dna/preferred_node"
    export HOME="$(stagef_user_home)"
    export DNA_NO_FALLBACK=1
    USER_FP="$(cat "$USER_FP_FILE")"
    "$STAGEF_DNACLI_BIN" -q dna genesis-create "$USER_FP" 0 \
        --chain-def-file "$CD_BIN" \
        > "$BASE_DIR/genesis_create.log" 2>&1 || {
        echo "[FAIL] genesis-create failed — see $BASE_DIR/genesis_create.log" >&2
        tail -20 "$BASE_DIR/genesis_create.log" >&2
        exit 9
    }
    "$STAGEF_DNACLI_BIN" -q dna genesis-submit \
        > "$BASE_DIR/genesis_submit.log" 2>&1 || true
) || true

# Wait for genesis block to actually commit on all nodes.
# DB file existence is not sufficient — the witness subsystem creates
# the file as soon as genesis TX is received, regardless of whether it
# commits. Poll blocks-table row count to confirm the genesis block
# (height=0) was actually written. Catches supply-invariant rejections
# and other post-receive / pre-commit failures that would otherwise
# silently advance the harness into tests against an empty chain.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    # First wait for the DB file to appear (witness init).
    for _ in $(seq 1 30); do
        if [ -n "$(stagef_node_chain_db "$n")" ]; then break; fi
        sleep 0.5
    done
    db=$(stagef_node_chain_db "$n")
    if [ -z "$db" ]; then
        echo "[FAIL] node $n never got witness DB" >&2
        echo "       check $(stagef_node_dir "$n")/nodus.log" >&2
        exit 10
    fi
    # Then poll for at least one block row.
    cnt=0
    for _ in $(seq 1 60); do
        cnt=$(sqlite3 "$db" "SELECT COUNT(*) FROM blocks;" 2>/dev/null || echo 0)
        if [ "$cnt" -ge 1 ]; then break; fi
        sleep 0.5
    done
    if [ "$cnt" -lt 1 ]; then
        echo "[FAIL] node $n witness DB exists but no blocks committed" >&2
        echo "       likely a supply-invariant or finalize_block rejection —" >&2
        echo "       relevant lines from $(stagef_node_dir "$n")/nodus.log:" >&2
        grep -iE "SUPPLY INVARIANT|REJECTED|invariant|BATCH COMMIT FAILED" \
            "$(stagef_node_dir "$n")/nodus.log" 2>/dev/null | tail -5 >&2 || true
        exit 10
    fi
done
echo "[ok] genesis committed on all $STAGEF_COMMITTEE_SIZE nodes"

echo ""
echo "=== Stage F harness UP ==="
echo "  BASE_DIR:     $BASE_DIR"
echo "  USER_FP:      $(cat "$USER_FP_FILE" | head -c 16)..."
echo "  node1 log:    $BASE_DIR/node1/nodus.log"
echo "  chain DB:     $(stagef_node_chain_db 1)"
echo ""
echo "Run tests: bash $STAGEF_REPO_ROOT/nodus/tests/integration/stagef/tests/*.sh"
echo "Teardown:  bash $STAGEF_REPO_ROOT/nodus/tests/integration/stagef/stagef_down.sh"
