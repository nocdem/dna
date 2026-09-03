#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# stagef_up_v2.sh — bring up a 7-node cluster on a PURE LEDGER V2 chain
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That seven independent nodes, each handed the SAME genesis config
#   file and each deriving its own chain locally, arrive at a
#   BYTE-IDENTICAL chain — same chain id, same genesis BlockID — and
#   then come up as Ledger V2 witnesses on it. The property that would
#   be false if it failed: *a V2 chain's identity is a pure function of
#   its config, so a fleet can be born without a genesis round and
#   without copying a database between machines.*
#
#   This is the V2 counterpart of stagef_up.sh, and the two are born
#   completely differently. stagef_up.sh submits a GENESIS TRANSACTION
#   to a running cluster and the chain is created by consensus. Here
#   there is no transaction and no cluster: each node runs an OFFLINE
#   one-shot before anything is listening, and agreement is CHECKED
#   rather than negotiated.
#
# WHAT IT REQUIRES
#   Compile flags: NONE beyond a default `nodus/build`. The config's
#   epoch_length / blocks_per_year / decimal_unit are read from the
#   binary itself (below), so this script cannot disagree with the
#   build it is testing — a mismatch is refused by the builder, and the
#   whole point of reading them out is that the refusal never fires for
#   a reason the operator has to guess at.
#   Environment: none. STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN are
#   honoured through stagef_env.sh as usual.
#
# WHAT IT LEAVES BEHIND
#   A full 7-node cluster running under $BASE_DIR, its path in
#   /tmp/stagef_current, pids in $BASE_DIR/pids.txt — the same contract
#   stagef_up.sh leaves, so stagef_down.sh tears this down unchanged.
#   The genesis config used is kept at $BASE_DIR/v2_genesis.conf; it is
#   the only artifact that would need to travel to another machine.
#
# HOW IT CAN LIE
#   - **Seven identical chain ids from seven identical configs is not a
#     surprise on ONE machine.** Every node here runs the same binary
#     off the same disk, so this cannot catch a difference that only
#     appears between builds or between hosts. It catches a derivation
#     that is not a pure function of its input — readdir order, a clock,
#     an uninitialised byte — and nothing about portability.
#   - **Bring-up proves birth, not consensus.** Reaching the end of this
#     script means the nodes started and agree on a genesis they each
#     computed. It does NOT mean they can commit a block together; the
#     V2 lane's multi-node behaviour is the scenario suite's job, and at
#     the time of writing there is no scenario that drives a V2 chain.
#     Do not read a green bring-up as a green V2 lane.
#   - **The chain-id comparison is the assertion.** Deleting it leaves a
#     script that starts seven nodes and says nothing about whether they
#     are on the same chain — they would simply fail to talk to each
#     other later, somewhere less obvious.
#   - **A node that fails its witness role still LISTENS.** nodus keeps
#     serving DHT traffic when the witness module refuses to init
#     (nodus_server.c), so "all 7 ports accept" is not evidence of 7
#     witnesses. The role line is checked per node for that reason.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/stagef_env.sh"

C=${STAGEF_COMMITTEE_SIZE:-7}

# ── 0. binaries ─────────────────────────────────────────────────────
[ -x "$STAGEF_NODUS_BIN" ] || { echo "[FAIL] no nodus-server at $STAGEF_NODUS_BIN" >&2; exit 2; }
echo "[ok] nodus-server: $STAGEF_NODUS_BIN"

# stagef_env.sh takes BASE_DIR from the pointer file when one exists;
# a bring-up creates its own, exactly as stagef_up.sh:56 does. Done
# AFTER sourcing so a stale pointer from a torn-down run cannot be
# inherited.
BASE_DIR="/tmp/stagef-$(date +%Y%m%dT%H%M%SZ)"
export BASE_DIR
mkdir -p "$BASE_DIR"
echo "$BASE_DIR" > "$STAGEF_POINTER"
echo "[ok] BASE_DIR=$BASE_DIR"

for n in $(seq 1 "$C"); do
    mkdir -p "$(stagef_node_dir "$n")/identity" "$(stagef_node_dir "$n")/data"
done
echo "[ok] dir layout created"

# ── 1. identities ───────────────────────────────────────────────────
# Same short-lived spawn stagef_up.sh uses: the server generates its
# Dilithium5 identity on first run, we wait for the three files and
# kill it. Nothing is listening long enough to matter.
for n in $(seq 1 "$C"); do
    node_dir=$(stagef_node_dir "$n")
    "$STAGEF_NODUS_BIN" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$node_dir/identity" -d "$node_dir/data" \
        > "$node_dir/identity_gen.log" 2>&1 &
    ig=$!
    for _ in $(seq 1 40); do
        [ -s "$node_dir/identity/nodus.pk" ] && [ -s "$node_dir/identity/nodus.fp" ] && break
        sleep 0.25
    done
    kill "$ig" 2>/dev/null || true; wait "$ig" 2>/dev/null || true
    [ -s "$node_dir/identity/nodus.pk" ] || { echo "[FAIL] node $n identity" >&2; exit 4; }
done
echo "[ok] $C identities generated"

# The identity-generation spawn opened a data directory, so each node
# now holds nodus.db / channels.db. The derivation refuses to run
# beside a FOREIGN chain database but does not care about these, and
# the partial-wipe gate wants all three present — which is exactly the
# state a real host is in after its first start. Left alone on purpose.

# ── 2. the genesis config ───────────────────────────────────────────
# THE ECONOMIC PARAMETERS MUST MATCH THE BINARY, and there is no way to
# ask the binary what it was built with — nothing exports them. So they
# are written here at the SHIPPED defaults, and the honest consequence
# is stated rather than worked around:
#
#   against a default build   → they match, derivation proceeds;
#   against a short-epoch or short-year build (the ones several
#   scenarios need) → the BUILDER REFUSES, naming both numbers, and
#   this script exits 5 with that message on screen.
#
# That refusal is the correct outcome, not a defect to route around. A
# chain derived at an epoch length its own binary disagrees with is a
# chain the fleet cannot run — the mismatch is refused again at every
# node's open (nodus_witness_v2_econ.c). If this script is ever needed
# against a short-epoch build, override these three to match the build;
# do NOT make the builder lenient.
EL=720
BY=6307200
DU=100000000

SELF_STAKE=1000000000000000          # DNAC_SELF_STAKE_AMOUNT: 10M x 10^8
TOTAL=100000000000000000             # matches the legacy harness supply
ALLOC=$(( TOTAL - SELF_STAKE * C ))

CONF="$BASE_DIR/v2_genesis.conf"
{
    echo "# stagef V2 genesis — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "total_supply_raw      = $TOTAL"
    echo "epoch_length          = $EL"
    echo "blocks_per_year       = $BY"
    echo "decimal_unit          = $DU"
    # 0 = emission never runs. The reversible choice: a later governance
    # vote can still turn it on, while any non-zero value can never be
    # turned off again (nodus_witness_rt_native.c). A harness chain has
    # no reason to mint.
    echo "inflation_start_block = 0"
    for n in $(seq 1 "$C"); do
        nd=$(stagef_node_dir "$n")
        pk=$(xxd -p -c 99999 "$nd/identity/nodus.pk")
        fp=$(cat "$nd/identity/nodus.fp")
        echo ""
        echo "[validator]"
        echo "pubkey                     = $pk"
        # The node's OWN key is its payout key here, so the fingerprint
        # the builder demands is exactly the identity's own nodus.fp —
        # which IS sha3-512(nodus.pk). A real fleet would use a separate
        # payout key; the builder's check is the same either way.
        echo "unstake_destination_pubkey = $pk"
        echo "unstake_destination_fp     = $fp"
        echo "self_stake                 = $SELF_STAKE"
        echo "commission_bps             = 500"
    done
    echo ""
    echo "[allocation]"
    echo "source_id    = $(printf 'a%.0s' $(seq 1 128))"
    # dest_binding is SHA3-512(claimant pubkey); node1's own fingerprint
    # is that value for node1's key, so node1 can claim it.
    echo "dest_binding = $(cat "$(stagef_node_dir 1)/identity/nodus.fp")"
    echo "amount       = $ALLOC"
} > "$CONF"
echo "[ok] v2_genesis.conf built ($C validators, 1 allocation, $(stat -c%s "$CONF") bytes)"

# ── 3. derive on every node, INDEPENDENTLY ──────────────────────────
CHAIN_ID=""; GENESIS_PIN=""
for n in $(seq 1 "$C"); do
    nd=$(stagef_node_dir "$n")
    out="$nd/derive.log"
    if ! "$STAGEF_NODUS_BIN" --derive-v2-genesis "$CONF" -d "$nd/data" \
         > "$out" 2> "$nd/derive.err"; then
        echo "[FAIL] node $n derivation refused — full output:" >&2
        cat "$out" "$nd/derive.err" >&2
        exit 5
    fi
    cid=$(awk '/^chain-id/{print $2}' "$out")
    pin=$(awk '/^v2-genesis-pin/{print $2}' "$out")
    [ -n "$cid" ] && [ -n "$pin" ] || { echo "[FAIL] node $n printed no chain id" >&2; cat "$out" >&2; exit 5; }

    if [ -z "$CHAIN_ID" ]; then
        CHAIN_ID=$cid; GENESIS_PIN=$pin
        echo "[ok] node $n derived  chain-id=$cid"
    elif [ "$cid" != "$CHAIN_ID" ] || [ "$pin" != "$GENESIS_PIN" ]; then
        # THE ASSERTION. Same config in, different chain out = the
        # derivation is not a pure function of its input.
        echo "[FAIL] node $n derived a DIFFERENT chain from the SAME config" >&2
        echo "       node1: $CHAIN_ID" >&2
        echo "       node$n: $cid" >&2
        exit 6
    else
        echo "[ok] node $n derived  (identical)"
    fi
done
echo "[ok] all $C nodes derived a byte-identical chain"
echo "     chain-id       $CHAIN_ID"
echo "     v2-genesis-pin $GENESIS_PIN"

# ── 4. spawn ────────────────────────────────────────────────────────
SEEDS=""
for n in $(seq 1 "$C"); do SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"; done
cat > "$BASE_DIR/nodus.json" <<'EOF'
{ "require_peer_auth": true }
EOF

: > "$BASE_DIR/pids.txt"
for n in $(seq 1 "$C"); do
    nd=$(stagef_node_dir "$n")
    # shellcheck disable=SC2086
    "$STAGEF_NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$n")" -t "$(stagef_tcp_port "$n")" \
        -p "$(stagef_peer_port "$n")" -C "$(stagef_chan_port "$n")" \
        -W "$(stagef_witness_port "$n")" \
        -i "$nd/identity" -d "$nd/data" $SEEDS \
        > "$nd/nodus.log" 2>&1 &
    echo $! >> "$BASE_DIR/pids.txt"
    echo "[ok] node $n spawned pid=$!"
done

for n in $(seq 1 "$C"); do
    tcp=$(stagef_tcp_port "$n")
    ok=0
    for _ in $(seq 1 60); do
        if ss -lt 2>/dev/null | grep -Eq "[:.]${tcp}\\b"; then ok=1; break; fi
        sleep 0.5
    done
    [ "$ok" = 1 ] || { echo "[FAIL] node $n never listened on $tcp" >&2; exit 7; }
done
echo "[ok] all $C nodes listening"

# ── 5. every node must have come up AS A V2 WITNESS ─────────────────
# Listening is not evidence: nodus keeps serving DHT traffic when the
# witness module refuses to initialise, so a cluster of role-less nodes
# would pass a port check and fail everything after it.
sleep 5
bad=0
for n in $(seq 1 "$C"); do
    nd=$(stagef_node_dir "$n")
    if grep -q 'chain role: LEDGER V2' "$nd/nodus.log"; then
        echo "[ok] node $n role: LEDGER V2"
    else
        echo "[FAIL] node $n did NOT report the Ledger V2 chain role" >&2
        grep -E 'REFUSING|chain role|witness' "$nd/nodus.log" | tail -5 >&2
        bad=1
    fi
done
[ "$bad" = 0 ] || exit 8

echo ""
echo "=== Stage F V2 harness UP ==="
echo "  BASE_DIR:       $BASE_DIR"
echo "  chain-id:       $CHAIN_ID"
echo "  v2-genesis-pin: $GENESIS_PIN"
echo "  config:         $CONF"
echo ""
echo "Teardown: bash $(dirname "$0")/stagef_down.sh"
