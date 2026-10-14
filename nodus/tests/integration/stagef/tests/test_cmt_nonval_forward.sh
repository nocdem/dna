#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_nonval_forward.sh — a NON-VALIDATOR node takes a client's
# transactions on its own client port and they commit on the validators
# ════════════════════════════════════════════════════════════════════
#
# Why: Kurultay #22, khan decision 3 (docs/plans/decisions/2026-10-14-
# kurultay-22-summary.md): a storage node — which may run the witness
# OUTSIDE the validator set and block-sync (khan decision 2; nodus/docs/
# DEPLOY_RUNBOOK.md:603 "Joining a node to an existing V2 chain") — serves
# clients, including transaction submission forwarded over 4004 (the
# mempool reactor, channel 0x30). The record says: "transaction
# forwarding from a NON-validator node has not been exercised" — test it
# before relying on it. Every other scenario submits to a VALIDATOR's
# client port (e.g. test_v2_grow_7_32.sh STEP 1b submits to node 1).
# NOT in genesis_protocol_v2.sh's sweep list.
#
# WHAT IT PROVES
#   The property that would be false if it failed: *a client transaction
#   submitted ONLY to a non-validator node's client port reaches the
#   validators' mempools over the 4004 mempool channel (0x30) and commits
#   — identically on the 7 validators and on the non-validator itself.*
#
#   Steps, each asserted separately:
#     1. cand1 (a funded identity the bring-up minted, NOT a validator)
#        starts as an 8th node with an EMPTY data directory and joins by
#        the 64-hex genesis pin (`--v2-genesis-pin`, the grow scenario's
#        STEP 9 / test_v2_join.sh shape): it adopts the fleet's chain,
#        comes up COMETBFT + LIVE, block-syncs (the "block sync done …
#        consensus started" line), and catches up to the fleet tip. It has
#        NO `validators` row (node 1's DB and its own) — so it can neither
#        propose nor vote, and a block carrying its transaction can only
#        have been proposed by a validator that received the bytes from
#        somewhere else.
#     2. Through cand1's OWN client port (port block C+3+1 — printed, and
#        checked to be (a) none of the 7 validators' client ports and (b)
#        served by the very process this script started): cand1 claims
#        its genesis leaf (`v2-claim`), and the claimed coin is waited for
#        as a LEDGER EFFECT on node 1's DB AND on cand1's DB.
#     3. Again only through cand1's port: one SPEND self-send of that coin
#        minus the fee (`v2-envelope spend --no-dust-sweep`, the pump's
#        shape); its created utxo_set row (tx_hash = the intent_id) is
#        waited for on node 1 AND on cand1 (progress- and height-bounded;
#        "dropped" rc 2 reported distinctly from a stall rc 1).
#     4. Every node 1..7 and cand1 reach the spend's height;
#        stagef_cmt_diff_at_floor agrees across the 7 validators; cand1's
#        v2_blocks row at the spend's height (global_root + block_id)
#        equals node 1's.
#     5. TERMINAL anti-vacuity: cand1 still has no `validators` row on
#        node 1 or on itself, and NO v2_attendance row carries its
#        voter_id (stagef_voter_id) on node 1 — it signed no commit.
#
# WHY "COMMITTED" HERE MEANS "FORWARDED" (the inference, and its basis)
#   - On a version-3 chain the client RPC's whole answer is the local
#     Comet mempool's CheckTx: "no leader/follower branch, no forward-to-
#     leader (there is no leader; the mempool reactor floods)"
#     (nodus/src/witness/nodus_witness_handlers.c handle_dnac_spend, the
#     FLEET-TM-R3 W3 block, :3180-3210). The only path out of cand1's
#     mempool to another node is the mempool shim reactor on channel 0x30
#     (nodus_witness_p2p.c:2290, cmt_memr_get_channels).
#   - The client bytes go to cand1's port ONLY (both -s/-p and --submit
#     name it). No validator received them from the client. cand1 is not
#     a validator (step 1/5), so it never proposes. A block containing
#     the transaction therefore proves a validator's mempool got it from
#     the mesh — i.e. cand1 forwarded it (directly, or via another node
#     that had it from cand1). WHICH hop carried it is not observed.
#
# WHAT IT REQUIRES
#   compile — NOTHING beyond a default build: nodus-server and nodus-cli
#     from the SAME tree, a tree with the 4004 p2p port (the bring-up's
#     network file). Any epoch length works; it crosses no boundary on
#     purpose and asserts none.
#   env — exported BEFORE stagef_up_v2.sh:
#     STAGEF_V2_CANDIDATES >= 1 — mints cand1 (identity + a genesis leaf
#       of a self-bond plus a margin, stagef_up_v2.sh section 1c and the
#       CAND_ALLOC leaf). Absent → SKIP 99. Port block C+3+1 (11): ports
#       14100-14104.
#   SKIPS (rc 99) — coverage that did not happen, never a pass — when:
#     any split mode (splitw / mixedw / splits / mixeds / split / mixed:
#     this script starts cand1 as ONE combined nodus-server, its own
#     spawn line — a non-validator in a split fleet would be a split node
#     and is not adapted); not a version-3 cluster / no genesis config /
#     no recorded pin; no network file (pre-p2p server); no cand1
#     identity.
#   FAILS (not skips) when the cluster is not fresh for cand1: cand1
#     already has a chain DB, a validators row, or a coin (its leaf is
#     single-use — README "A genesis leaf can be claimed exactly once").
#   Its own fresh bring-up is the clean case; it touches no validator's
#   process, so it may run after the sweep on the same cluster as long as
#   nothing else used cand1 (the grow scenarios do).
#
# WHAT IT LEAVES BEHIND
#   - cand1 STOPPED: an EXIT trap SIGTERMs it on ANY exit (pass, fail,
#     skip after spawn, ^C) and waits for it to exit (60 × 1 s, then
#     SIGKILL said out loud), so later scenarios run on the 7. Its pid is
#     also in pids.txt (stagef_down.sh's safety net).
#   - cand1's genesis leaf CLAIMED and its coin SPENT once to itself (one
#     fee into the reward pool): the leaf is gone for any later scenario
#     (the grow scenarios then FAIL on cand1 — bring up fresh for them).
#   - $BASE_DIR/cand1/data (the adopted chain DB), $BASE_DIR/cand1/
#     nodus.log, $BASE_DIR/nonval_claim.log, $BASE_DIR/nonval_spend.log.
#   - a few chain heights.
#
# HOW IT CAN LIE
#   - **If cand1 were a validator**, its own proposal could include the
#     transaction with no forwarding at all. Guarded twice: no
#     `validators` row for its key on node 1 and on cand1 (before and
#     after), and no v2_attendance row for its voter_id on node 1 (it
#     signed no commit). Seats come only from `validators` rows
#     (snapshot ranking), so no row = no seat.
#   - **If the claim/spend went to node 1 by mistake** forwarding would be
#     untested. The script prints the port it submits to, asserts it is
#     none of the 7 validators' client ports, and asserts (ss -ltnp) that
#     the listener on it is the cand1 process THIS script started. Both
#     -s/-p and --submit carry that port (the spend's coin listing and
#     chain-id read run on that ONE session — nodus-cli usage text).
#   - **`v2-claim --db` is a LOCAL read-only open**, not a network path:
#     it reads cand1's own adopted DB (manifest, tip). That does not route
#     any bytes to a node.
#   - **Inclusion ≠ which hop.** A commit proves the bytes left cand1 over
#     the mesh (the 0x30 channel is the only exit — above); it does not
#     show whether a validator heard it from cand1 directly or second-hand
#     from another validator. Not asserted.
#   - **CheckTx APPROVED is admission, not inclusion.** Both transactions
#     are followed to their LEDGER EFFECT through stagef_cmt_wait_row on
#     node 1 AND cand1.
#   - **"block sync done" ≠ caught up to the tip.** It means consensus
#     started on cand1 (nodus_witness.c wb_switch_to_consensus); the tip
#     wait after it is separate (8 intervals of no progress fails — the
#     grow scenarios' catch-up bound; do NOT tune it down).
#   - **A wait that never ends is impossible by construction**: every wait
#     is attempt-bounded (spawn, adoption, role lines) or progress-bounded
#     (stagef_cmt_wait_height / stagef_cmt_wait_row: no tip increase for N
#     CreateEmptyBlocks intervals → stall; the row absent 20 heights past
#     submission → dropped). No bare sleep decides an outcome.
#   - **One machine, loopback.** allow_duplicate_ip / addr_book_strict=
#     false are harness-only (README "P2P-PORT F6"); the non-validator is
#     admitted under the inbound cap because the fleet has 8 nodes, far
#     below max_num_inbound_peers — the cap-crowding risk khan decision 3
#     names (and its storage-registry exemption) is NOT exercised.
#   - **Run once, PASS (2026-10-14, main 0bdbac29e):** standalone on a
#     fresh combined bring-up, default build, production constants
#     (epoch 720), STAGEF_V2_CANDIDATES=1, one machine — claim at height 2,
#     spend at height 4, 7/7 state_root identical and cand1's block 4
#     equal to node 1's. Not run in any split mode (it SKIPs there).
#   - **rc=99 is not a pass.**
#
# EXIT: 0 pass (every step asserted), 99 skip, anything else fail.
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# This script starts cand1 as ONE combined nodus-server process (its own
# spawn line below). SKIP (99) in every split mode — before SETUP_OK and
# before the EXIT trap, as stagef_split_skip_if requires.
stagef_split_skip_if --reason "the non-validator is spawned as one combined nodus-server, not adapted to split nodes" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die()  { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }
skip() { echo "[SKIP] $*"; exit 99; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active harness — run stagef_up_v2.sh first"
command -v sqlite3 >/dev/null || die "sqlite3 required"
command -v openssl >/dev/null || die "openssl required (stagef_voter_id)"
command -v ss >/dev/null      || die "ss required (listener checks)"

CLI="$STAGEF_NODUSCLI_BIN"
NODUS="$STAGEF_NODUS_BIN"
[ -x "$CLI" ]   || die "nodus-cli not found at $CLI"
[ -x "$NODUS" ] || die "nodus-server not found at $NODUS"

C="$STAGEF_COMMITTEE_SIZE"          # 7 genesis validators (stagef_env.sh)
CONF="$BASE_DIR/v2_genesis.conf"
CAND_DIR="$BASE_DIR/cand1"
# cand1's port block: C+3+1 — the one stagef_up_v2.sh section 1c gave its
# identity spawn, past the v2user (C+1), pump (C+2) and probe (C+3)
# blocks (the grow scenarios' node_pidx rule).
CAND_PIDX=$(( C + 3 + 1 ))
CAND_PORT=$(stagef_tcp_port "$CAND_PIDX")
CAND_LOG="$CAND_DIR/nodus.log"
FEE="$STAGEF_PUMP_FEE_RAW"

# ── requirements, checked not assumed ───────────────────────────────
SDB=$(stagef_node_chain_db 1)
[ -n "$SDB" ] && [ -s "$SDB" ] || skip "no chain DB for node1 — not a stagef_up_v2.sh cluster"
has_v2=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
[ "${has_v2:-0}" != "0" ] && [ -f "$CONF" ] || skip "not a version-3 cluster with a genesis config — use stagef_up_v2.sh"
[ -s "$BASE_DIR/v2_genesis_pin" ] && [ -s "$BASE_DIR/v2_chain_id" ] || skip "bring-up recorded no genesis pin / chain id"
[ -s "$(stagef_network_file)" ] || skip "no network file at $(stagef_network_file) — bring up on a nodus-server with the 4004 p2p port (its -h lists --network-file)"
[ -s "$CAND_DIR/identity/nodus.pk" ] && [ -s "$CAND_DIR/identity/nodus.fp" ] || \
    skip "no cand1 identity — export STAGEF_V2_CANDIDATES=1 (or more) BEFORE stagef_up_v2.sh"
PIN=$(cat "$BASE_DIR/v2_genesis_pin")
[ "${#PIN}" = 64 ] || die "recorded pin is not 64 hex characters (${#PIN})"

CAND_FP=$(cat "$CAND_DIR/identity/nodus.fp")
[ "${#CAND_FP}" = 128 ] || die "cand1's fingerprint is not 128 hex characters"
CAND_PKHEX=$(xxd -p -c 999999 "$CAND_DIR/identity/nodus.pk")
CAND_VID=$(stagef_voter_id "$CAND_DIR/identity/nodus.pk")
[ "${#CAND_VID}" = 64 ] || die "could not derive cand1's voter_id"
grep -q "^dest_binding = ${CAND_FP}\$" "$CONF" || die "$CONF binds no genesis leaf to cand1 ($CAND_FP)"

# Fresh for cand1: its leaf is single-use.
if ls "$CAND_DIR/data/"witness_*.db >/dev/null 2>&1; then
    die "cand1 already has a chain database — another scenario (a grow scenario, or this one) already ran cand1 on this bring-up; bring up fresh"
fi
isval=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$CAND_PKHEX';")
[ "$isval" = 0 ] || die "cand1 is a validator on node 1 ($isval row) — this scenario needs a NON-validator; bring up fresh"
coins=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM utxo_set WHERE owner='$CAND_FP';")
[ "$coins" = 0 ] || die "cand1 already owns $coins coin(s) on node 1 — its leaf was claimed; bring up fresh"

# The submit port is none of the validators' client ports.
for n in $(seq 1 "$C"); do
    [ "$CAND_PORT" != "$(stagef_tcp_port "$n")" ] || \
        die "harness arithmetic: cand1's client port $CAND_PORT is node $n's"
done
lst=$(ss -lt 2>/dev/null || true)
if grep -Eq "[:.]${CAND_PORT}\\b" <<< "$lst"; then
    die "something already listens on cand1's client port $CAND_PORT — a leftover process"
fi
stagef_sentinel SETUP_OK
ok "requirements met (cand1 fp ${CAND_FP:0:16}…, client port $CAND_PORT, no validator row, no coin)"

# ── small helpers ───────────────────────────────────────────────────
# largest_db DIR — the largest non-empty witness_*.db in DIR, without a
# `ls | head` pipe (under pipefail an early-exiting reader can SIGPIPE
# the writer — README, test_v2_rewards.sh row).
largest_db() {
    local f best="" bs=-1 s
    for f in "$1/"witness_*.db; do
        [ -s "$f" ] || continue
        s=$(stat -c%s "$f")
        if [ "$s" -gt "$bs" ]; then best="$f"; bs="$s"; fi
    done
    if [ -n "$best" ]; then echo "$best"; fi
    return 0
}
tip() { stagef_cmt_tip "$SDB"; }

# cand_largest DB — cand1's largest SPENDABLE native coin on DB
# (stagef_pump_largest's predicate, unlock_block <= DB's tip, with cand1's
# fingerprint — that helper is bound to the pump funder's keys).
cand_largest() {
    local amt
    amt=$(sqlite3 "$1" \
        "SELECT COALESCE(MAX(amount),0) FROM utxo_set
          WHERE owner = '$CAND_FP' AND token_id = zeroblob(64)
            AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks);" \
        2>/dev/null || echo 0)
    case "$amt" in ''|*[!0-9]*) amt=0 ;; esac
    echo "$amt"
}

# wait_effect LABEL DB SQL — stagef_cmt_wait_row with its two exits told
# apart (rc 1 = the chain stalled, rc 2 = dropped: the chain kept going
# without the row). Prints the tip at success.
wait_effect() {
    local label="$1" db="$2" sql="$3" h wrc
    h=$(stagef_cmt_wait_row "$db" "$sql" 3) && wrc=0 || wrc=$?
    case "$wrc" in
        0) printf '%s\n' "$h" ;;
        1) die "$label: never appeared and the chain STALLED at $h ($db)" ;;
        *) die "$label: not included within 20 heights (tip $h) — dropped, not delayed ($db)" ;;
    esac
}

# ── cand1 is stopped on ANY exit ─────────────────────────────────────
CAND_PID=""
stop_cand() {
    local pid="$CAND_PID" st gone=0
    [ -n "$pid" ] || return 0
    CAND_PID=""
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 60); do
        st=$(ps -o stat= -p "$pid" 2>/dev/null || true)
        case "$st" in
            ''|Z*) gone=1; break ;;
        esac
        sleep 1
    done
    if [ "$gone" != 1 ]; then
        echo "[info] cand1 (pid $pid) did not exit within 60 s of SIGTERM — SIGKILLed" >&2
        kill -9 "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
    echo "[info] cand1 (pid $pid) stopped — later scenarios run on the $C validators"
    return 0
}
trap stop_cand EXIT

echo "══ a NON-validator (cand1) takes a claim and a spend on its own client port $CAND_PORT; the validators commit them ══"
stagef_cmt_diff_at_floor "pre-nonval-forward" || exit 2

# ════════════════════════════════════════════════════════════════════
# STEP 1 — cand1 joins by the pin, block-syncs, catches up; not a validator
# ════════════════════════════════════════════════════════════════════
mkdir -p "$CAND_DIR/data"
SEEDS=()
for s in $(seq 1 "$C"); do SEEDS+=(-s "127.0.0.1:$(stagef_udp_port "$s")"); done
# The pin joiner's spawn line: test_v2_grow_7_20.sh STEP 9 (-c nodus.json
# gives the network file's persistent peers; --v2-genesis-pin on an EMPTY
# data directory makes it pull the genesis bundle and adopt it).
"$NODUS" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
    -u "$(stagef_udp_port "$CAND_PIDX")" -t "$CAND_PORT" \
    -p "$(stagef_peer_port "$CAND_PIDX")" -C "$(stagef_chan_port "$CAND_PIDX")" \
    -W "$(stagef_witness_port "$CAND_PIDX")" \
    --v2-genesis-pin "$PIN" -i "$CAND_DIR/identity" -d "$CAND_DIR/data" "${SEEDS[@]}" \
    >> "$CAND_LOG" 2>&1 &
CAND_PID=$!
echo "$CAND_PID" >> "$BASE_DIR/pids.txt"
info "cand1 started (pid $CAND_PID, port block $CAND_PIDX, client port $CAND_PORT)"

# 1a. client port listening — attempt-bounded (60 x 0.5 s, the bring-up's
#     own bound), and the listener is THIS process.
up=0
for _ in $(seq 1 60); do
    lst=$(ss -lt 2>/dev/null || true)
    if grep -Eq "[:.]${CAND_PORT}\\b" <<< "$lst"; then up=1; break; fi
    kill -0 "$CAND_PID" 2>/dev/null || break
    sleep 0.5
done
[ "$up" = 1 ] || { tail -30 "$CAND_LOG" >&2; die "cand1 never listened on its client port $CAND_PORT"; }
# ss -p names the owning process ("users:((\"nodus-server\",pid=N,fd=M))");
# read into a variable first — no early-exit reader on a pipe (pipefail).
lstp=$(ss -ltnp 2>/dev/null || true)
plin=$(grep -E "[:.]${CAND_PORT}\\b" <<< "$lstp" || true)
grep -q "pid=${CAND_PID}," <<< "$plin" || {
    printf '%s\n' "$plin" >&2
    die "the listener on $CAND_PORT is not cand1's process (pid $CAND_PID) — the submissions below would not go to cand1"
}
ok "STEP 1 — cand1's client port $CAND_PORT is served by pid $CAND_PID"

# 1b. adoption by pin — attempt-bounded (120 x 1 s, test_cmt_prune.sh's
#     pin-joiner bound); the adopted file is the fleet's chain.
CDB=""
for _ in $(seq 1 120); do
    CDB=$(largest_db "$CAND_DIR/data")
    [ -n "$CDB" ] && break
    kill -0 "$CAND_PID" 2>/dev/null || break
    sleep 1
done
[ -n "$CDB" ] || { tail -30 "$CAND_LOG" >&2; die "cand1 never adopted a chain by its pin"; }
[ "$(basename "$CDB")" = "$(basename "$SDB")" ] || die "cand1 adopted $(basename "$CDB"), the fleet is $(basename "$SDB")"
ok "STEP 1 — cand1 adopted the fleet's chain by its pin ($(basename "$CDB"))"

# 1c. role + startup table + LIVE — attempt-bounded (90 x 1 s, the
#     bring-up's anti-vacuity shape; one awk pass, no early-exit pipe).
flags=000
for _ in $(seq 1 90); do
    flags=$(awk '/chain role: COMETBFT/        {r=1}
                 /cometbft startup table built/ {s=1}
                 /cometbft lane LIVE/          {l=1}
                 END { printf "%d%d%d", r, s, l }' "$CAND_LOG" 2>/dev/null || echo 000)
    [ "$flags" = 111 ] && break
    kill -0 "$CAND_PID" 2>/dev/null || break
    sleep 1
done
[ "$flags" = 111 ] || die "cand1 incomplete after start: role/startup-table/lane-live = $flags (see $CAND_LOG)"
# The p2p host's start line names how many persistent peers it was given
# (the network file lists the $C genesis nodes) — config evidence; that
# the mesh FORMED is the block sync below.
if ! grep -q "p2p on .* $C persistent peer(s)" "$CAND_LOG"; then
    grep -E 'p2p on|network file' "$CAND_LOG" >&2 || true
    die "cand1 did not start its 4004 host with the network file's $C persistent peers"
fi
ok "STEP 1 — cand1 is COMETBFT + LIVE with the network file's $C persistent peers"

# 1d. block sync → consensus started (nodus_witness.c wb_switch_to_consensus).
#     Progress-bounded like test_cmt_blocksync.sh / test_cmt_prune.sh: 3
#     empty-block intervals with neither the done line nor tip movement
#     fail it.
last_tip=-1 since=0 poll_s=5
stall_polls=$(( (3 * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) + poll_s - 1) / poll_s ))
while ! grep -q 'block sync done at height' "$CAND_LOG"; do
    kill -0 "$CAND_PID" 2>/dev/null || { tail -30 "$CAND_LOG" >&2; die "cand1 exited during block sync"; }
    t=$(stagef_cmt_tip "$CDB")
    [ -n "$t" ] || t=-1
    if [ "$t" -gt "$last_tip" ]; then last_tip="$t"; since=0
    else since=$(( since + 1 )); fi
    [ "$since" -lt "$stall_polls" ] || die "cand1 made no block-sync progress (tip $t) across 3 empty-block intervals and never started consensus"
    sleep "$poll_s"
done
line=$(grep 'block sync done at height' "$CAND_LOG" || true)
line=${line##*$'\n'}
ok "STEP 1 — cand1 switched to consensus: $line"

# 1e. caught up to the fleet tip (8-interval progress bound — the grow
#     scenarios' catch-up bound; do NOT tune it down).
fleet=$(tip)
ct=$(stagef_cmt_wait_height "$CDB" "$fleet" 8) || die "cand1 did not catch up to the fleet tip $fleet (stuck at $ct)"
ok "STEP 1 — cand1 caught up to the fleet tip $fleet (its tip $ct)"

# 1f. NOT a validator — on node 1 and on its own copy.
for db in "$SDB" "$CDB"; do
    v=$(sqlite3 "$db" "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$CAND_PKHEX';")
    [ "$v" = 0 ] || die "cand1 has a validators row on $db — it is not a non-validator; the scenario would prove nothing"
done
ok "STEP 1 — cand1 has NO validators row (node 1 and its own DB): it can neither propose nor vote"

# ════════════════════════════════════════════════════════════════════
# STEP 2 — the claim, submitted ONLY to cand1's client port
# ════════════════════════════════════════════════════════════════════
stagef_sentinel TARGET_REACHED
info "submitting the claim to 127.0.0.1:$CAND_PORT (cand1) — not to any validator"
crc=0
"$CLI" -s 127.0.0.1 -p "$CAND_PORT" v2-claim --config "$CONF" --db "$CDB" \
    --keys "$CAND_DIR/identity" --submit "127.0.0.1:$CAND_PORT" \
    > "$BASE_DIR/nonval_claim.log" 2>&1 || crc=$?
[ "$crc" = 0 ] || { cat "$BASE_DIR/nonval_claim.log" >&2; die "cand1's claim was not admitted by cand1's CheckTx (v2-claim rc=$crc)"; }
grep -q 'accepted: mempool CheckTx approved' "$BASE_DIR/nonval_claim.log" || {
    cat "$BASE_DIR/nonval_claim.log" >&2; die "v2-claim exited 0 but printed no CheckTx approval"
}
ok "STEP 2 — cand1's CheckTx approved the claim (admission only — inclusion next)"
CLAIM_SQL="SELECT COUNT(*) FROM utxo_set WHERE owner='$CAND_FP' AND token_id=zeroblob(64) AND amount > 0;"
h1=$(wait_effect "cand1's claimed coin on node 1" "$SDB" "$CLAIM_SQL")
hc=$(wait_effect "cand1's claimed coin on cand1" "$CDB" "$CLAIM_SQL")
ok "STEP 2 — the claimed coin is on node 1 (tip $h1) and on cand1 (tip $hc)"

# ════════════════════════════════════════════════════════════════════
# STEP 3 — one SPEND self-send, submitted ONLY to cand1's client port
# ════════════════════════════════════════════════════════════════════
# The spend lists coins over its session to cand1, so cand1 must see a
# spendable coin first (unlock_block <= its tip) — progress-bounded.
amt=$(cand_largest "$CDB")
if [ "$amt" -le "$FEE" ]; then
    cl=$(stagef_cmt_wait_row "$CDB" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner='$CAND_FP' AND token_id=zeroblob(64)
           AND amount > $FEE AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks);" 3) \
        || die "cand1's claimed coin never became spendable on cand1 (tip $cl)"
    amt=$(cand_largest "$CDB")
fi
[ "$amt" -gt "$FEE" ] || die "cand1 holds no spendable native coin above the fee $FEE (largest $amt)"
info "submitting a spend of $(( amt - FEE )) (+ fee $FEE) to 127.0.0.1:$CAND_PORT (cand1) — not to any validator"
out=$("$CLI" -s 127.0.0.1 -p "$CAND_PORT" v2-envelope spend --keys "$CAND_DIR/identity" --to "$CAND_FP" \
        --amount "$(( amt - FEE ))" --fee "$FEE" --no-dust-sweep \
        --submit "127.0.0.1:$CAND_PORT" 2>&1) || {
    printf '%s\n' "$out" > "$BASE_DIR/nonval_spend.log"
    printf '%s\n' "$out" >&2
    die "cand1's spend was not admitted by cand1's CheckTx"
}
printf '%s\n' "$out" > "$BASE_DIR/nonval_spend.log"
intent=$(awk -F= '/^  intent_id=/ && !d {print $2; d=1}' <<< "$out")
[ "${#intent}" = 128 ] || { printf '%s\n' "$out" >&2; die "the spend printed no intent_id"; }
ok "STEP 3 — cand1's CheckTx approved the spend ${intent:0:16}… (admission only — inclusion next)"
SPEND_SQL="SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash))='$intent';"
h1=$(wait_effect "the spend's created coin on node 1" "$SDB" "$SPEND_SQL")
hc=$(wait_effect "the spend's created coin on cand1" "$CDB" "$SPEND_SQL")
SPEND_H=$(sqlite3 "$SDB" "SELECT block_height FROM utxo_set WHERE lower(hex(tx_hash))='$intent' LIMIT 1;")
case "$SPEND_H" in ''|*[!0-9]*) die "cannot read the spend's block height on node 1 ('$SPEND_H')" ;; esac
SPEND_HC=$(sqlite3 "$CDB" "SELECT block_height FROM utxo_set WHERE lower(hex(tx_hash))='$intent' LIMIT 1;")
[ "$SPEND_HC" = "$SPEND_H" ] || die "the spend landed at height $SPEND_H on node 1 but $SPEND_HC on cand1"
ok "STEP 3 — the spend's coin is on node 1 (tip $h1) and on cand1 (tip $hc), both at height $SPEND_H"

# ════════════════════════════════════════════════════════════════════
# STEP 4 — the 7 validators agree, and cand1 holds the same block
# ════════════════════════════════════════════════════════════════════
for n in $(seq 1 "$C"); do
    db=$(stagef_node_chain_db "$n")
    [ -n "$db" ] || die "node $n has no chain database"
    stagef_cmt_wait_height "$db" "$SPEND_H" 4 >/dev/null \
        || die "node $n never reached the spend's height $SPEND_H (stuck at $(stagef_cmt_tip "$db"))"
done
stagef_cmt_wait_height "$CDB" "$SPEND_H" 4 >/dev/null \
    || die "cand1 never reached the spend's height $SPEND_H (stuck at $(stagef_cmt_tip "$CDB"))"
stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-nonval-forward (7 validators)" || exit 2
r1=$(sqlite3 "$SDB" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height=$SPEND_H;")
rc_=$(sqlite3 "$CDB" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height=$SPEND_H;")
[ -n "$r1" ] && [ -n "$rc_" ] || die "block $SPEND_H missing on node 1 or on cand1 — an empty read is a failure, not agreement"
[ "$r1" = "$rc_" ] || die "cand1's block $SPEND_H (${rc_:0:32}…) differs from node 1's (${r1:0:32}…)"
ok "STEP 4 — the 7 validators agree at their floor; cand1's block $SPEND_H equals node 1's (root|block_id ${r1:0:16}…)"

# ════════════════════════════════════════════════════════════════════
# TERMINAL — cand1 is still not a validator and signed no commit
# ════════════════════════════════════════════════════════════════════
for db in "$SDB" "$CDB"; do
    v=$(sqlite3 "$db" "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$CAND_PKHEX';")
    [ "$v" = 0 ] || die "cand1 has a validators row on $db at the end — the commit could have been its own proposal"
done
att=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM v2_attendance WHERE lower(hex(voter_id))='$CAND_VID';")
[ "$att" = 0 ] || die "cand1's voter_id has $att v2_attendance row(s) on node 1 — it signed commits, so it is in cometbft's voting set"
ok "TERMINAL — cand1: no validators row, no attendance (it signed no commit)"

stagef_sentinel PASS
echo
echo "[PASS] a claim and a spend submitted ONLY to the non-validator cand1 (client port $CAND_PORT)"
echo "       were committed by the $C validators (spend at height $SPEND_H) and agree on all"
echo "       $C and on cand1: the 0x30 mempool channel carried them off a node that cannot propose."
echo "       Parameters: whatever this bring-up used (epoch length ${STAGEF_EPOCH_LENGTH}); no boundary"
echo "       is asserted. Which hop carried the bytes is not observed."
exit 0
