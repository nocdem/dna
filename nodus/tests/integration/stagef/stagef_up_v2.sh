#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# stagef_up_v2.sh — bring up a 7-node cluster on a PURE LEDGER V2 chain
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That seven independent nodes, each handed the SAME genesis config
#   file and each deriving its own chain locally, arrive at a
#   BYTE-IDENTICAL chain — same chain id, same genesis document — and
#   then come up as COMETBFT witnesses on it (D-17 rev 10 item 9,
#   atlas-dec-9d96e2ec31ad4840cf258df21732b67f, APPROVED: nodus-server
#   never starts the legacy BFT or the pre-Comet V2 lane on ANY chain
#   any more — the witness's post-open gate refuses a database that is
#   not a version-3 chain, fail closed, logged). The property that would
#   be false if it failed: *a version-3 chain's identity is a pure
#   function of its config, so a fleet can be born without a genesis
#   round and without copying a database between machines.*
#
#   R3 W4-D deleted stagef_up.sh (the legacy runner's bring-up script,
#   along with genesis_protocol.sh and its 23 scenarios) — this script
#   is this harness's only bring-up path now. Historical contrast, kept
#   for the reasoning it explains: stagef_up.sh used to submit a GENESIS
#   TRANSACTION to a running cluster and the chain was created by
#   consensus. Here there is no transaction and no cluster: each node
#   runs an OFFLINE one-shot before anything is listening, and agreement
#   is CHECKED rather than negotiated.
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
#   STAGEF_PAYOUT_INTERVAL_EPOCHS (default 24, the production value;
#   tokenomics-v3 P2-7) is written into the genesis config as
#   payout_interval_epochs — the payday cadence. It is part of the
#   hashed genesis document, so it must be exported BEFORE bring-up; a
#   different value is a different chain id. The genesis config also
#   reserves reward_pool_initial = 200M x 10^8 (P2-1), added to
#   total_supply_raw.
#   STAGEF_V2_PUMP_IDENTITIES=K (default 1; block capacity trial B,
#   operator 2026-09-24) generates K-1 EXTRA pump identities under
#   $BASE_DIR/v2pump2 .. v2pumpK, each owning its OWN STAGEF_V2_PUMP_LEAVES
#   leaves of the same PUMP_ALLOC, in its own source_id band
#   j x 10^9 + 1 .. j x 10^9 + PUMP_LEAVES (j = 2..K), added to
#   total_supply_raw (Rule P.2). Only bench_tps_v2.sh uses them (one
#   coin listing is capped at 100 rows PER IDENTITY). **K = 1 emits no
#   extra line and adds 0 to the total: the config is byte-for-byte what
#   this script wrote before the knob existed** (same inputs, same
#   timestamps), so every sweep scenario's chain is unchanged. K > 1 is
#   a DIFFERENT chain id (more leaves in the hashed document).
#
# WHAT IT LEAVES BEHIND
#   A full 7-node cluster running under $BASE_DIR, its path in
#   /tmp/stagef_current, pids in $BASE_DIR/pids.txt — the same contract
#   the now-deleted stagef_up.sh left, so stagef_down.sh tears this down
#   unchanged.
#   The genesis config used is kept at $BASE_DIR/v2_genesis.conf; it is
#   the only artifact that would need to travel to another machine. The
#   chain id and genesis pin are written to $BASE_DIR/v2_chain_id and
#   $BASE_DIR/v2_genesis_pin so a scenario can READ the fleet's identity
#   rather than form a second opinion by re-deriving it.
#
#   FOUR IDENTITIES BESIDE THE SEVEN NODES, each with its own genesis
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
#     - $BASE_DIR/v2probe   one small leaf — tokenomics-v3 P1:
#                                       test_cmt_empty_blocks.sh's OWN
#                                       claim, kept separate from the pump
#                                       leaves so its submission-to-
#                                       inclusion latency measurement
#                                       never changes what any pump-leaf-
#                                       counting scenario sees
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
# a bring-up creates its own, the same way the now-deleted stagef_up.sh
# did. Done AFTER sourcing so a stale pointer from a torn-down run cannot
# be inherited.
BASE_DIR="/tmp/stagef-$(date -u +%Y%m%dT%H%M%SZ)"
export BASE_DIR
mkdir -p "$BASE_DIR"
echo "$BASE_DIR" > "$STAGEF_POINTER"
echo "[ok] BASE_DIR=$BASE_DIR"

for n in $(seq 1 "$C"); do
    mkdir -p "$(stagef_node_dir "$n")/identity" "$(stagef_node_dir "$n")/data"
done
echo "[ok] dir layout created"

# ── 1. identities ───────────────────────────────────────────────────
# The same short-lived spawn the now-deleted stagef_up.sh used: the
# server generates its Dilithium5 identity on first run, we wait for the
# three files and kill it. Nothing is listening long enough to matter.
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

# A THIRD non-validator identity, tokenomics-v3 P1: `test_cmt_empty_blocks.sh`
# needs to submit exactly ONE claim, from an identity NO OTHER scenario ever
# touches, to measure how fast a real transaction reaches inclusion on an
# otherwise-idle chain (D-5's txsAvailable wiring). Reusing a pump leaf
# would work for that ONE measurement but would silently subtract a leaf
# every other pump-leaf-counting scenario (test_cmt_claim_flood.sh,
# test_v2_epoch_boundary.sh, test_v2_grow_7_20.sh — grep confirms all three
# read the pump identity/leaf count) assumes is untouched — exactly the
# cross-scenario coupling the pump/user split above already exists to
# avoid. Kept separate for the same reason.
PROBE_DIR="$BASE_DIR/v2probe"
mkdir -p "$PROBE_DIR/identity" "$PROBE_DIR/data"
"$STAGEF_NODUS_BIN" -b 127.0.0.1 \
    -u "$(stagef_udp_port $(( C + 3 )))" -t "$(stagef_tcp_port $(( C + 3 )))" \
    -p "$(stagef_peer_port $(( C + 3 )))" -C "$(stagef_chan_port $(( C + 3 )))" \
    -W "$(stagef_witness_port $(( C + 3 )))" \
    -i "$PROBE_DIR/identity" -d "$PROBE_DIR/data" \
    > "$PROBE_DIR/identity_gen.log" 2>&1 &
prg=$!
for _ in $(seq 1 40); do
    [ -s "$PROBE_DIR/identity/nodus.pk" ] && [ -s "$PROBE_DIR/identity/nodus.fp" ] && break
    sleep 0.25
done
kill "$prg" 2>/dev/null || true; wait "$prg" 2>/dev/null || true
[ -s "$PROBE_DIR/identity/nodus.pk" ] || { echo "[FAIL] probe identity" >&2; exit 4; }
echo "[ok] probe identity generated ($PROBE_DIR/identity)"

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
# every Comet-lane script that counts participants iterates a FIXED
# range (`seq 1 "$STAGEF_COMMITTEE_SIZE"`), never a `node*` directory
# glob, so this naming choice no longer guards against the specific
# mechanism it used to (R3 W4-D deleted running_nodes(), the legacy
# stagef_env.sh function that DID enumerate `node*` directories — it had
# no surviving caller). The separation is kept anyway as the same
# discipline: the growth scenario starts these candidates itself when it
# wants them, and nothing else should ever count them as active
# committee members by accident of naming.
CANDIDATES="${STAGEF_V2_CANDIDATES:-0}"
if [ "$CANDIDATES" -gt 0 ]; then
    for i in $(seq 1 "$CANDIDATES"); do
        cd_dir="$BASE_DIR/cand$i"
        mkdir -p "$cd_dir/identity" "$cd_dir/data"
        # Port block past the pump AND probe identities' (tokenomics-v3
        # P1 added the probe identity at C+3), so an identity-generation
        # spawn can never collide with a live node or either of them.
        pn=$(( C + 3 + i ))
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

# ── 1d. EXTRA PUMP identities, for the TPS bench (trial B) ──────────
# Off by default (K = 1: nothing below runs and nothing is written into
# the genesis config). STAGEF_V2_PUMP_IDENTITIES=K generates K-1 more
# pump identities, $BASE_DIR/v2pump2 .. v2pumpK, generated EXACTLY like
# $BASE_DIR/v2pump above (a short-lived nodus-server spawn that writes
# identity/nodus.pk + nodus.fp). Why several: the dnac_utxo listing
# returns at most NODUS_DNAC_MAX_UTXO_RESULTS = 100 coins per identity,
# so one pump identity can never keep more than ~100 spends in flight —
# below trial B's 255-per-block unit cap. K identities lift that bound to
# ~100 x K. Port blocks: past the probe (C+3) AND every candidate
# (C+3+1 .. C+3+CANDIDATES), so no spawn collides with a node, the pump,
# the probe or a candidate.
PUMP_IDS="${STAGEF_V2_PUMP_IDENTITIES:-1}"
case "$PUMP_IDS" in
    ''|*[!0-9]*) echo "[FAIL] STAGEF_V2_PUMP_IDENTITIES='$PUMP_IDS' — must be an integer 1..100" >&2; exit 2 ;;
esac
if [ "$PUMP_IDS" -lt 1 ] || [ "$PUMP_IDS" -gt 100 ]; then
    echo "[FAIL] STAGEF_V2_PUMP_IDENTITIES=$PUMP_IDS — must be 1..100" >&2; exit 2
fi
if [ "$PUMP_IDS" -gt 1 ]; then
    for j in $(seq 2 "$PUMP_IDS"); do
        xp_dir="$BASE_DIR/v2pump$j"
        mkdir -p "$xp_dir/identity" "$xp_dir/data"
        pn=$(( C + 3 + CANDIDATES + j - 1 ))
        "$STAGEF_NODUS_BIN" -b 127.0.0.1 \
            -u "$(stagef_udp_port "$pn")" -t "$(stagef_tcp_port "$pn")" \
            -p "$(stagef_peer_port "$pn")" -C "$(stagef_chan_port "$pn")" \
            -W "$(stagef_witness_port "$pn")" \
            -i "$xp_dir/identity" -d "$xp_dir/data" \
            > "$xp_dir/identity_gen.log" 2>&1 &
        xg=$!
        for _ in $(seq 1 40); do
            [ -s "$xp_dir/identity/nodus.pk" ] && [ -s "$xp_dir/identity/nodus.fp" ] && break
            sleep 0.25
        done
        kill "$xg" 2>/dev/null || true; wait "$xg" 2>/dev/null || true
        [ -s "$xp_dir/identity/nodus.pk" ] || { echo "[FAIL] pump identity $j" >&2; exit 4; }
    done
    echo "[ok] $(( PUMP_IDS - 1 )) extra pump identities generated (\$BASE_DIR/v2pump2..v2pump$PUMP_IDS)"
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

# ── R3 W3 (C2d) — THE VERSION-3 KEYS ────────────────────────────────
# config_version = 3 is REQUIRED: since tokenomics-v3 P4 the config
# parser refuses a file without it and accepts no other value
# (nodus_v2_gen_config.c), gen_plan_build refuses anything but 3
# (nodus_witness_v2_gen.c), and run_derive_v2_genesis (nodus-server.c)
# calls only the version-3 derivation — the version-2 derivation is
# deleted. Without this key stagef_up_v2.sh cannot derive at all.
#
# genesis_time_ms is MANDATORY for a version-3 document
# (nodus_v2_gen_config.c ~:1030-1045: "a version-3 document must name
# BOTH genesis_time_ms ... and initial_height") and MUST be identical
# bytes in every node's copy of the config — the chain id hashes the
# whole document, so seven independently-derived genesis documents are
# byte-identical only if they were built from byte-identical input.
# Computed ONCE, here, before the loop that writes the file: the value
# is fixed the moment this script decides it, not re-read at derive
# time, so however long identity generation and the 7 derivations take,
# every node hashes the SAME millisecond. A genesis time already in the
# past is fine and expected: node.go:518-524 (ported at
# witness_cmt_tick, nodus_witness.c:1655-1697) only ever WAITS for a
# future genesis_time — a past one is satisfied on the very first tick.
GENESIS_TIME_MS=$(($(date -u +%s%N) / 1000000))
# initial_height: the reference treats 0 and 1 identically at the
# ledger (both start the chain at height 1), but the RAW FIELD VALUE is
# part of the hashed document, so 0 and 1 are two DIFFERENT chain ids
# for the same effective start (nodus_v2_gen_config.c's own required-key
# message says so explicitly). 1 is written down as the operator's
# choice, not derived from anything.
INITIAL_HEIGHT=1
echo "[ok] version-3 keys: config_version=3 genesis_time_ms=$GENESIS_TIME_MS initial_height=$INITIAL_HEIGHT"

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
# tokenomics-v3 P1: the probe identity's ONE leaf — small, like a pump
# leaf (it exists to be claimed once, not to fund anything), but its own
# allocation so no pump-leaf-counting scenario sees its count change.
PROBE_ALLOC=1000000000               # 10 DNAC, deliberately tiny
# A candidate must be able to SELF-BOND, so its leaf carries the exact
# bond plus a margin for fees. Anything less and the stake is refused for
# a reason that has nothing to do with what a growth scenario tests.
CAND_ALLOC=$(( SELF_STAKE + 100000000000 ))
# tokenomics-v3 P2-1 — THE REWARD RESERVE. Rule P.2 is now
#   Σ allocations + Σ self_stake + reward_pool_initial == total_supply_raw
# (nodus_witness_v2_gen.c gen_plan_build), and supply_tracking.reward_pool
# is seeded with it at genesis. Written EXPLICITLY at the decision's own
# number (200M NODUS; decision 2026-09-22 §1 "Ödüller ve ücretler",
# v2_gen.c GEN_V3_REWARD_POOL_INITIAL) rather than left to the builder's
# default, so the config file says what the chain holds. The leaves above
# keep their sizes: the reserve is ADDED to the total, so no scenario that
# counts a leaf's value sees it change.
#
# DELIBERATE DIFFERENCE FROM PRODUCTION (operator, 2026-09-24): on the
# production chain the total supply is FIXED and the reserve is carved
# out of the treasury allocation (genesis_v3_oracle.py; the builder
# checks only the equation above). This harness has no treasury leaf —
# its largest leaf is 100M, smaller than the 200M reserve — and its
# total is not a production number, so the reserve is added on top
# instead of shrinking a leaf a scenario relies on. Rule P.2 holds
# either way; nothing here tests the production total.
REWARD_POOL=20000000000000000        # 200M x 10^8
# The payday cadence (design §7 P2-7): every payout_interval_epochs-th
# boundary turns the accrual table into UTXOs. The production value is
# 24; a scenario that must SEE a payday in a short-epoch run exports a
# smaller one BEFORE bring-up (test_v2_rewards.sh documents its own).
# The value is part of the hashed genesis document — every node reads
# the same config file, so all seven agree by construction.
PAYOUT_INTERVAL="${STAGEF_PAYOUT_INTERVAL_EPOCHS:-24}"
case "$PAYOUT_INTERVAL" in
    ''|*[!0-9]*|0) echo "[FAIL] STAGEF_PAYOUT_INTERVAL_EPOCHS='$PAYOUT_INTERVAL' — must be a positive integer" >&2; exit 2 ;;
esac
TOTAL=$(( SELF_STAKE * C + ALLOC * (C + 1) + PUMP_ALLOC * PUMP_LEAVES \
          + PROBE_ALLOC + CAND_ALLOC * CANDIDATES + REWARD_POOL ))
# Trial B: the extra pump identities' leaves (section 1d). K = 1 adds
# exactly 0, so the total — and the line that writes it — is unchanged.
TOTAL=$(( TOTAL + PUMP_ALLOC * PUMP_LEAVES * (PUMP_IDS - 1) ))
echo "[ok] reward reserve: reward_pool_initial=$REWARD_POOL payout_interval_epochs=$PAYOUT_INTERVAL"

CONF="$BASE_DIR/v2_genesis.conf"
{
    echo "# stagef V2 genesis — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # R3 W3 (C2d) — the version-3 keys, ONE VALUE, WRITTEN ONCE, and used
    # by every node: the chain id hashes this document byte-for-byte, so
    # a config assembled here and read seven times (never re-generated
    # per node) is what makes seven independent derivations agree at
    # all. The Comet consensus params (block size, evidence window,
    # timeouts) are NOT written here — they come from the BUILDER
    # (nodus_witness_v2_gen_v3_defaults, which installs
    # cmt_default_consensus_params — nodus_witness_v2_gen.c:2327-2340),
    # never from a value typed in this file.
    echo "config_version        = 3"
    echo "genesis_time_ms       = $GENESIS_TIME_MS"
    echo "initial_height        = $INITIAL_HEIGHT"
    echo "total_supply_raw      = $TOTAL"
    echo "epoch_length          = $EL"
    echo "blocks_per_year       = $BY"
    echo "decimal_unit          = $DU"
    # MUST be 0: tokenomics-v3 P2-4 deleted the per-block mint and
    # retired its governance parameter (id 3); the builder refuses any
    # other value. The key stays because it is a field of the canonical
    # genesis encoding.
    echo "inflation_start_block = 0"
    echo "reward_pool_initial   = $REWARD_POOL"
    echo "payout_interval_epochs = $PAYOUT_INTERVAL"
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

    # ── PROBE LEAF (tokenomics-v3 P1) ───────────────────────────────
    # Exactly ONE leaf, in its own source_id band (3000) so it can never
    # collide with the node/user (1..C+1), pump (1001..) or candidate
    # (2001..) bands. test_cmt_empty_blocks.sh claims it to measure
    # submission-to-inclusion latency on an otherwise idle chain.
    echo ""
    echo "[allocation]"
    printf 'source_id    = %0128d\n' 3000
    echo "dest_binding = $(cat "$PROBE_DIR/identity/nodus.fp")"
    echo "amount       = $PROBE_ALLOC"

    # ── EXTRA PUMP LEAVES (trial B, section 1d) ─────────────────────
    # Written ONLY when K > 1 — with the default K = 1 this block emits
    # nothing, so the file above is byte-for-byte the pre-knob config.
    # Identity j (2..K) owns PUMP_LEAVES leaves of PUMP_ALLOC (the same
    # leaf size as v2pump) in its own band j x 10^9 + i. No band can
    # collide: node/user 1..C+1, pump 1001..1000+PUMP_LEAVES, candidates
    # 2001.., probe 3000 all sit below 2 x 10^9 for any derivable config
    # (the builder takes at most NODUS_V2_GEN_MAX_ALLOCS = 65 536 leaves,
    # nodus_witness_v2_gen.h:284, so PUMP_LEAVES < 10^9), and band j ends
    # at j x 10^9 + PUMP_LEAVES < (j + 1) x 10^9. The builder sorts the
    # leaves by source_id itself (nodus_witness_v2_gen.c:793-796, qsort,
    # duplicates rejected), so appending here is order-safe.
    if [ "$PUMP_IDS" -gt 1 ]; then
        for j in $(seq 2 "$PUMP_IDS"); do
            xp_fp=$(cat "$BASE_DIR/v2pump$j/identity/nodus.fp")
            for i in $(seq 1 "$PUMP_LEAVES"); do
                echo ""
                echo "[allocation]"
                printf 'source_id    = %0128d\n' "$(( j * 1000000000 + i ))"
                echo "dest_binding = $xp_fp"
                echo "amount       = $PUMP_ALLOC"
            done
        done
    fi
} > "$CONF"
echo "[ok] v2_genesis.conf built ($C validators, $(( C + 1 + PUMP_LEAVES * PUMP_IDS + 1 + CANDIDATES )) allocations incl. $PUMP_LEAVES pump x $PUMP_IDS identit(y/ies) + 1 probe + $CANDIDATES candidate leaves, $(stat -c%s "$CONF") bytes)"

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

# ── 5. every node must have come up AS A COMETBFT WITNESS, AND GONE LIVE
# Listening is not evidence: nodus keeps serving DHT traffic when the
# witness module refuses to initialise, so a cluster of role-less nodes
# would pass a port check and fail everything after it.
#
# R3 W3 (C2d), DELTA 1 — ANTI-VACUITY, FOUR LINES PER NODE, NOT THREE.
# The role line alone proves the post-open gate accepted a version-3
# chain (nodus_witness.c witness_post_open_gate, D-17 rev 10/11 outcome
# (a)); it does NOT prove the node ever tried to run consensus on it. A
# node whose `witness_cmt_live_init` failed (nodus_witness.c:1502-1612)
# would still print the role line and then never print either line
# below — and a role+startup+live-only check would call that a green
# bring-up even though the chain never produced anything. So every node
# must ALSO show:
#   "cometbft startup table built at height ..."   (witness_cmt_live_init,
#       nodus_witness.c:1600-1603 — the startup table was built)
#   "cometbft lane LIVE — genesis time reached"     (witness_cmt_tick,
#       nodus_witness.c:1695-1696 — the reactors actually started)
# AND, FOURTH — the chain PRODUCES: every node's own Comet tip reaches
# height 1. The first sweep against this exact bring-up (DELTA 1) showed
# why the first three are not enough on their own: every scenario failed
# inside a second at its own PRE-action `stagef_cmt_diff_at_floor` with
# "no node has a Comet block yet" — the floor stays -1 until the first
# block commits, and nothing in bring-up had ever waited for that first
# commit. A node that shows role+startup+live and STILL never reaches
# height 1 is exactly the failure this fourth check exists to catch
# (measured live: a real server-side defect — every node stopping after
# height 1 on a SQLite snapshot lock, since fixed upstream — would have
# produced this same silence, and the three-line check alone could not
# have told "never started producing" apart from "still forming the
# mesh"). A node that shows the role but never goes live, or never
# produces, is a FAIL, not a slow pass: every wait below is bounded by
# ATTEMPTS or by `stagef_cmt_wait_height`'s progress bound, never a bare
# sleep — the CLAUDE.md "never tune a timeout" rule applies to bring-up
# exactly as it does to a scenario.
bad=0
for n in $(seq 1 "$C"); do
    nd=$(stagef_node_dir "$n")
    role_ok=0 startup_ok=0 live_ok=0
    for _ in $(seq 1 90); do
        if grep -q 'chain role: COMETBFT' "$nd/nodus.log"; then role_ok=1; fi
        if grep -q 'cometbft startup table built' "$nd/nodus.log"; then startup_ok=1; fi
        if grep -q 'cometbft lane LIVE' "$nd/nodus.log"; then live_ok=1; fi
        if [ "$role_ok" = 1 ] && [ "$startup_ok" = 1 ] && [ "$live_ok" = 1 ]; then break; fi
        sleep 1
    done
    if [ "$role_ok" = 1 ] && [ "$startup_ok" = 1 ] && [ "$live_ok" = 1 ]; then
        echo "[ok] node $n role=COMETBFT startup-table=built lane=LIVE"
    else
        echo "[FAIL] node $n incomplete: role=$role_ok startup-table=$startup_ok lane-live=$live_ok" >&2
        grep -E 'REFUSING|chain role|cometbft|CMT_FAULT' "$nd/nodus.log" | tail -10 >&2
        bad=1
    fi
done
[ "$bad" = 0 ] || exit 8

# ── 6. FOURTH anti-vacuity line: the chain actually PRODUCES ────────
# DELTA 1. Role + startup-table + lane-LIVE prove the reactors started;
# they do not prove a single block ever committed. Bounded by
# stagef_cmt_wait_height's progress detection (stall = 3 consecutive
# 60s-equivalent intervals with no height increase) — the mesh that lets
# the first proposal actually reach quorum forms from the seed list in
# seconds (measured), so 3 intervals of headroom is generous, not tight.
for n in $(seq 1 "$C"); do
    nd=$(stagef_node_dir "$n")
    db=$(stagef_node_chain_db "$n")
    if [ -z "$db" ]; then
        echo "[FAIL] node $n has no chain database file to read a tip from" >&2
        bad=1
        continue
    fi
    h=$(stagef_cmt_wait_height "$db" 1 3) || {
        echo "[FAIL] node $n never reached height 1 (stuck at $h) — role/startup/LIVE all passed but the chain never produced" >&2
        grep -E 'ERR|CMT|cometbft' "$nd/nodus.log" | tail -10 >&2
        bad=1
        continue
    }
    echo "[ok] node $n first block committed (height $h)"
done
[ "$bad" = 0 ] || exit 9

# And the seven first blocks must be the SAME block — proven before any
# scenario runs, not left for the first scenario's own pre-check to
# discover (or, worse, to silently race).
stagef_cmt_diff_at_floor "bring-up" || exit 10

echo ""
echo "=== Stage F V2 harness UP ==="
echo "  BASE_DIR:       $BASE_DIR"
echo "  chain-id:       $CHAIN_ID"
echo "  v2-genesis-pin: $GENESIS_PIN"
echo "  config:         $CONF"
echo "  user identity:  $USER_DIR/identity  (NOT a validator; owns leaf $(( C + 1 )))"
echo ""
echo "Teardown: bash $(dirname "$0")/stagef_down.sh"
