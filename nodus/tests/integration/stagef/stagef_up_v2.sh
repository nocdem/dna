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
#   Compile flags: NONE beyond a default `nodus/build`.
#   Environment: STAGEF_EPOCH_LENGTH / STAGEF_BLOCKS_PER_YEAR /
#   STAGEF_DECIMAL_UNIT default to the SHIPPED values and are written
#   into the genesis config. The harness's standing rule applies: they
#   only tell this SCRIPT what the binary was built with, so setting one
#   without the matching -D produces a config the builder REFUSES (loudly,
#   naming both numbers). That refusal is correct — a chain derived at an
#   epoch length its own binary disagrees with is a chain the fleet
#   cannot run.
#   STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN honoured as usual.
#
# WHAT IT LEAVES BEHIND
#   A full 7-node cluster running under $BASE_DIR, its path in
#   /tmp/stagef_current, pids in $BASE_DIR/pids.txt — the same contract
#   stagef_up.sh leaves, so stagef_down.sh tears this down unchanged.
#   The genesis config used is kept at $BASE_DIR/v2_genesis.conf; it is
#   the only artifact that would need to travel to another machine. The
#   chain id and genesis pin are written to $BASE_DIR/v2_chain_id and
#   $BASE_DIR/v2_genesis_pin so a scenario can READ the fleet's identity
#   rather than form a second opinion by re-deriving it.
#
#   THREE IDENTITIES BESIDE THE SEVEN NODES, each with its own genesis
#   leaves, because on a V2 chain who can be funded is decided BEFORE the
#   chain exists:
#     - every node          one leaf   (so claiming scenarios never
#                                       compete for the same single-use
#                                       leaf and stay order-independent)
#     - $BASE_DIR/v2user    one leaf   NOT a validator, so it can STAKE
#     - $BASE_DIR/v2pump    many small leaves — a supply of transactions,
#                                       because a V2 chain makes one block
#                                       per transaction and a scenario
#                                       that needs to reach a height has
#                                       no other way to get there
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
#     computed. It does NOT mean they can commit a block together — that
#     is the scenario suite's job (genesis_protocol_v2.sh). Do not read a
#     green bring-up as a green V2 lane.
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

# ── 1b. one NON-VALIDATOR identity ──────────────────────────────────
# The seven node identities are all genesis validators with a bonded
# self-stake, so any scenario that tries to STAKE as one of them is
# correctly refused — the engine says
#   "env 0 leg 0 domain 0 op 1: runtime exec refused"
# and it is right. A scenario needs an identity that is NOT already a
# validator, and on a V2 chain the only way to give it spendable value
# is a genesis allocation, decided before the chain exists.
#
# This is a real difference from the legacy harness, where a user is
# funded by a transaction after bring-up. Here, who can be funded is a
# GENESIS decision.
USER_DIR="$BASE_DIR/v2user"
mkdir -p "$USER_DIR/identity" "$USER_DIR/data"
"$STAGEF_NODUS_BIN" -b 127.0.0.1 \
    -u "$(stagef_udp_port $(( C + 1 )))" -t "$(stagef_tcp_port $(( C + 1 )))" \
    -p "$(stagef_peer_port $(( C + 1 )))" -C "$(stagef_chan_port $(( C + 1 )))" \
    -W "$(stagef_witness_port $(( C + 1 )))" \
    -i "$USER_DIR/identity" -d "$USER_DIR/data" \
    > "$USER_DIR/identity_gen.log" 2>&1 &
ug=$!
for _ in $(seq 1 40); do
    [ -s "$USER_DIR/identity/nodus.pk" ] && [ -s "$USER_DIR/identity/nodus.fp" ] && break
    sleep 0.25
done
kill "$ug" 2>/dev/null || true; wait "$ug" 2>/dev/null || true
[ -s "$USER_DIR/identity/nodus.pk" ] || { echo "[FAIL] user identity" >&2; exit 4; }
echo "[ok] non-validator user identity generated ($USER_DIR/identity)"

# A SECOND non-validator identity, which owns the pump leaves. Kept
# separate from the user so a scenario that drives the chain hard cannot
# spend the leaf another scenario is relying on.
PUMP_DIR="$BASE_DIR/v2pump"
mkdir -p "$PUMP_DIR/identity" "$PUMP_DIR/data"
"$STAGEF_NODUS_BIN" -b 127.0.0.1 \
    -u "$(stagef_udp_port $(( C + 2 )))" -t "$(stagef_tcp_port $(( C + 2 )))" \
    -p "$(stagef_peer_port $(( C + 2 )))" -C "$(stagef_chan_port $(( C + 2 )))" \
    -W "$(stagef_witness_port $(( C + 2 )))" \
    -i "$PUMP_DIR/identity" -d "$PUMP_DIR/data" \
    > "$PUMP_DIR/identity_gen.log" 2>&1 &
pg=$!
for _ in $(seq 1 40); do
    [ -s "$PUMP_DIR/identity/nodus.pk" ] && [ -s "$PUMP_DIR/identity/nodus.fp" ] && break
    sleep 0.25
done
kill "$pg" 2>/dev/null || true; wait "$pg" 2>/dev/null || true
[ -s "$PUMP_DIR/identity/nodus.pk" ] || { echo "[FAIL] pump identity" >&2; exit 4; }
echo "[ok] pump identity generated ($PUMP_DIR/identity)"

# ── 1c. CANDIDATE identities, for the growth scenario ───────────────
# Off by default. STAGEF_V2_CANDIDATES=<N> generates N more identities,
# each with a genesis leaf big enough to SELF-BOND, so a scenario can
# grow the committee by having them stake.
#
# They are NOT validators at genesis — that is the whole point. They are
# funded strangers who become validators on a running chain, which is the
# only way to test that the committee can grow at all.
#
# They live under $BASE_DIR/cand<N>/, NOT under node<N>/, deliberately:
# running_nodes() enumerates node* DIRECTORIES, so materialising them as
# nodes here would make every other scenario count 20 participants that
# hold no chain. The growth scenario starts them itself when it wants
# them. (That directory-counting trap is exactly what the legacy suite's
# residue list records about test_bootstrap_join_live.sh's node8.)
CANDIDATES="${STAGEF_V2_CANDIDATES:-0}"
if [ "$CANDIDATES" -gt 0 ]; then
    for i in $(seq 1 "$CANDIDATES"); do
        cd_dir="$BASE_DIR/cand$i"
        mkdir -p "$cd_dir/identity" "$cd_dir/data"
        # Port block past the pump identity's, so an identity-generation
        # spawn can never collide with a live node.
        pn=$(( C + 2 + i ))
        "$STAGEF_NODUS_BIN" -b 127.0.0.1 \
            -u "$(stagef_udp_port "$pn")" -t "$(stagef_tcp_port "$pn")" \
            -p "$(stagef_peer_port "$pn")" -C "$(stagef_chan_port "$pn")" \
            -W "$(stagef_witness_port "$pn")" \
            -i "$cd_dir/identity" -d "$cd_dir/data" \
            > "$cd_dir/identity_gen.log" 2>&1 &
        cg=$!
        for _ in $(seq 1 40); do
            [ -s "$cd_dir/identity/nodus.pk" ] && [ -s "$cd_dir/identity/nodus.fp" ] && break
            sleep 0.25
        done
        kill "$cg" 2>/dev/null || true; wait "$cg" 2>/dev/null || true
        [ -s "$cd_dir/identity/nodus.pk" ] || { echo "[FAIL] candidate $i identity" >&2; exit 4; }
    done
    echo "[ok] $CANDIDATES candidate identities generated (\$BASE_DIR/cand1..$CANDIDATES)"
fi

# The identity-generation spawn opened a data directory, so each node
# now holds nodus.db / channels.db. The derivation refuses to run
# beside a FOREIGN chain database but does not care about these, and
# the partial-wipe gate wants all three present — which is exactly the
# state a real host is in after its first start. Left alone on purpose.

# ── 2. the genesis config ───────────────────────────────────────────
# THE ECONOMIC PARAMETERS MUST MATCH THE BINARY, and there is no way to
# ask the binary what it was built with — nothing exports them. So they
# are taken from the environment, defaulting to the SHIPPED values, and
# the harness's existing convention applies unchanged: STAGEF_* tells the
# SCRIPTS what the binary was built with, and setting one without the
# matching -D is the mistake the README warns about at the top.
#
#   default build            → the defaults below match, derivation runs;
#   short-epoch build without STAGEF_EPOCH_LENGTH → the BUILDER REFUSES,
#     naming both numbers, and this script exits 5 with that on screen.
#
# That refusal is the correct outcome, never something to route around: a
# chain derived at an epoch length its own binary disagrees with is a
# chain the fleet cannot run, and the mismatch is refused again at every
# node's open (nodus_witness_v2_econ.c). Do NOT make the builder lenient.
EL="${STAGEF_EPOCH_LENGTH:-720}"
BY="${STAGEF_BLOCKS_PER_YEAR:-6307200}"
DU="${STAGEF_DECIMAL_UNIT:-100000000}"
echo "[ok] econ parameters: epoch_length=$EL blocks_per_year=$BY decimal_unit=$DU"

SELF_STAKE=1000000000000000          # DNAC_SELF_STAKE_AMOUNT: 10M x 10^8
# ONE ALLOCATION PER NODE, not one for the whole chain.
#
# A distribution leaf can be claimed exactly once — the claim nullifier
# makes sure of it — so a single shared allocation would let the FIRST
# scenario that claims it succeed and every later one fail for a reason
# that has nothing to do with what it tests. Giving each node its own
# leaf makes the scenarios independent of each other and of run order,
# which is the property the legacy suite most conspicuously lacks (see
# the residue list in README.md).
ALLOC=10000000000000000              # 100M DNAC per leaf, a round number
# Pump leaves: small, many, and owned by one identity — see the comment
# at their generation. 40 is enough to cross a short epoch with room to
# spare; at the shipped 720 nothing can cross a boundary here anyway.
PUMP_LEAVES="${STAGEF_V2_PUMP_LEAVES:-40}"
PUMP_ALLOC=1000000000                # 10 DNAC each, deliberately tiny
# A candidate must be able to SELF-BOND, so its leaf carries the exact
# bond plus a margin for fees. Anything less and the stake is refused for
# a reason that has nothing to do with what a growth scenario tests.
CAND_ALLOC=$(( SELF_STAKE + 100000000000 ))
TOTAL=$(( SELF_STAKE * C + ALLOC * (C + 1) + PUMP_ALLOC * PUMP_LEAVES \
          + CAND_ALLOC * CANDIDATES ))

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
    # One leaf per node. source_id is operator-chosen and only has to be
    # unique; a zero-padded ordinal keeps the file readable and the
    # canonical source_id-ASC order equal to node order, which makes a
    # scenario's "my leaf" trivially predictable.
    for n in $(seq 1 "$C"); do
        echo ""
        echo "[allocation]"
        printf 'source_id    = %0128d\n' "$n"
        # dest_binding is SHA3-512(claimant pubkey), and a node's own
        # nodus.fp IS that value for its own key — so node N, and only
        # node N, can claim leaf N.
        echo "dest_binding = $(cat "$(stagef_node_dir "$n")/identity/nodus.fp")"
        echo "amount       = $ALLOC"
    done
    # The non-validator user's leaf, numbered past the nodes.
    echo ""
    echo "[allocation]"
    printf 'source_id    = %0128d\n' "$(( C + 1 ))"
    echo "dest_binding = $(cat "$USER_DIR/identity/nodus.fp")"
    echo "amount       = $ALLOC"

    # ── CANDIDATE LEAVES ────────────────────────────────────────────
    # Each candidate gets ONE leaf worth a self-bond plus a margin, so it
    # can claim and then stake without a second funding step. Numbered in
    # their own band so the source_id order stays readable.
    for i in $(seq 1 "$CANDIDATES"); do
        echo ""
        echo "[allocation]"
        printf 'source_id    = %0128d\n' "$(( 2000 + i ))"
        echo "dest_binding = $(cat "$BASE_DIR/cand$i/identity/nodus.fp")"
        echo "amount       = $CAND_ALLOC"
    done

    # ── PUMP LEAVES ─────────────────────────────────────────────────
    # A V2 chain produces a block only when a transaction arrives, and on
    # a fresh one the ONLY thing a fresh identity can submit is a claim.
    # So the number of blocks a scenario can drive is bounded by the
    # number of unclaimed leaves it can reach — which made an epoch
    # boundary (E blocks away) unreachable with one leaf per identity.
    #
    # dest_binding is per-LEAF, not per-identity, so one identity can own
    # many leaves and each is a separate claim with its own nullifier.
    # These belong to the pump identity and exist for exactly that: to
    # give a scenario a supply of transactions.
    #
    # They are the LAST leaves in source_id order, so a scenario that
    # wants "the next unclaimed pump leaf" can walk forward.
    for i in $(seq 1 "$PUMP_LEAVES"); do
        echo ""
        echo "[allocation]"
        printf 'source_id    = %0128d\n' "$(( 1000 + i ))"
        echo "dest_binding = $(cat "$PUMP_DIR/identity/nodus.fp")"
        echo "amount       = $PUMP_ALLOC"
    done
} > "$CONF"
echo "[ok] v2_genesis.conf built ($C validators, $(( C + 1 + PUMP_LEAVES + CANDIDATES )) allocations incl. $PUMP_LEAVES pump + $CANDIDATES candidate leaves, $(stat -c%s "$CONF") bytes)"

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

# Persist both, because a scenario that needs the pin must not re-derive
# it: re-derivation would be a SECOND opinion about the chain's identity,
# and a scenario is supposed to check the fleet's, not form its own.
printf '%s\n' "$CHAIN_ID"    > "$BASE_DIR/v2_chain_id"
printf '%s\n' "$GENESIS_PIN" > "$BASE_DIR/v2_genesis_pin"

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
echo "  user identity:  $USER_DIR/identity  (NOT a validator; owns leaf $(( C + 1 )))"
echo ""
echo "Teardown: bash $(dirname "$0")/stagef_down.sh"
