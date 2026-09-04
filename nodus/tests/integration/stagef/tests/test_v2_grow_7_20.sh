#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_grow_7_20.sh — a V2 committee grows 7 → 14 → 20 by governance
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a running Ledger V2 chain can enlarge its own validator set:
#   funded strangers become validators by bonding, the network votes its
#   committee size up, the change lands on an epoch boundary, and the
#   BFT quorum moves with the committee — up AND down. The property that
#   would be false if it failed: *a V2 chain's committee is governable
#   while the chain is live*, which is the difference between a fleet you
#   can grow and a fleet frozen at its genesis seven.
#
#   Nine claims, each asserted separately (STEP numbers below):
#     1. a non-validator with funds can bond and become a validator on a
#        live chain — 13 of them
#     2. the committee size is decided by a governance vote, not by a
#        constant
#     3. a target above this release's ceiling is refused, identically,
#        by every node
#     4. the growth happens AT the boundary and nowhere else, proven four
#        ways: the committed snapshot's count, its hash agreeing across
#        nodes, the block header's validator-set digest changing, and the
#        block carrying certificates
#     5. tenure (Rule R) gates it: at the boundary BEFORE the candidates
#        are tenured the snapshot is still the genesis seven
#     6. quorum tracks the committee — 2N/3+1 alive commits, one fewer
#        stalls, restoring it resumes, and the original seven ALONE stall
#     7. the enlarged set survives a full stop/start of every node
#     8. a node that misses an entire epoch boundary catches up
#     9. a node with no chain replays the whole history, growth boundary
#        included, from genesis to head
#
# WHAT IT REQUIRES
#   ⚠ **A SHORT-EPOCH BINARY AND A CANDIDATE-BEARING BRING-UP.**
#     compile: -DDNAC_EPOCH_LENGTH=15
#              -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#              (nodus/build-shortepoch is built exactly this way)
#     env, ALL exported BEFORE stagef_up_v2.sh:
#              STAGEF_EPOCH_LENGTH=15      — must match the -D
#              STAGEF_V2_CANDIDATES=13     — mints the 13 funded
#                                            identities this needs; with
#                                            0 (the default) it SKIPS
#              STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN → build-shortepoch
#   At the shipped epoch length of 720 the arithmetic below is
#   unreachable and this scenario skips. rc=99 means the coverage did not
#   happen; it is never a pass.
#
# WHY THE CANDIDATES ARE A GENESIS DECISION
#   On a pure V2 chain who can be funded is fixed BEFORE the chain
#   exists: value enters only through a genesis allocation leaf. So the
#   13 future validators must already own leaves in v2_genesis.conf,
#   which is why they come from the bring-up and not from this file.
#   They are NOT validators at genesis — that is the whole point.
#
# THE ARITHMETIC, at E=15, because every wait below depends on it
#   epoch start of height h = (h / E) * E → boundaries at 15, 30, 45, 60
#   Rule R (nodus_witness_validator.c): a validator may be SELECTED for
#   epoch e only if active_since_block + 2E <= e. Genesis-seeded
#   validators (active_since <= 1) are carved out and always tenured.
#   Snapshots are built ONE EPOCH AHEAD: the row for epoch e is written
#   at the boundary that starts epoch e-E.
#
#   13 claims + 13 bonds land serially at heights 1..26, so the
#   candidates' active_since values are 2,4,6,…,26.
#     epoch 30  → needs active_since <= 0 → genesis seven only     → 7
#     epoch 45  → needs active_since <= 15 → candidates 1..7 too   → 14
#     epoch 60  → needs active_since <= 30 → all thirteen          → 20
#   The vote is submitted at ~27 with effective=45; SAFETY grace is 15,
#   so 45 >= 27+15 holds, and the row is committed well before height 30
#   when the epoch-45 snapshot is built.
#
#   That 7 → 14 → 20 ramp is not a compromise, it is the honest shape:
#   tenure and governance are independent gates and the chain crosses
#   them at different boundaries.
#
# WHAT IT LEAVES BEHIND
#   ⚠ THE HEAVIEST RESIDUE IN THE SUITE. Run it LAST or standalone.
#     - 13 extra nodes running under $BASE_DIR/cand1..13, their pids
#       appended to pids.txt so stagef_down.sh reaps them
#     - a committee of 20, permanently — no scenario after this one sees
#       a 7-node chain
#     - every candidate's genesis leaf SPENT
#     - the chain tens of blocks on, past three epoch boundaries
#     - pump leaves partly consumed
#   It restores quorum before exiting. If it dies mid-matrix the chain is
#   left below quorum and stopped; tear down rather than diagnose.
#
# HOW IT CAN LIE — every one of these was a live defect in an earlier cut
#   - **"20 validator rows exist" is NOT "the committee is 20."** A fresh
#     bond writes status ACTIVE directly (nodus_witness_rt_native.c:3107)
#     and the boundary flip corrects it later, so the status byte is not
#     evidence. The committed validator_set_snapshots row is the only
#     authority and every count below reads it.
#   - **A stall is only a stall if the chain was ASKED to move.** A V2
#     chain makes no block without a transaction, so "no block while 13
#     are down" is vacuously true if nobody submits. Every stopped-phase
#     check SUBMITS a pump claim first, then requires no block across
#     N consecutive rounds — progress, never a sleep budget.
#   - **A resumed chain must commit, not merely be up.** After quorum is
#     restored the check is a BLOCK, not a process count.
#   - **Snapshot existence is not agreement.** Counts and hashes are
#     compared across all 20 nodes, not read from node1.
#   - **The 31-refusal must be a REFUSAL, not a submission failure.** A
#     CLI that dies for an unrelated reason looks identical. The check is
#     that no chain_config row for the illegal value exists on any node
#     AFTER the attempt, plus that a LEGAL vote from the same path in the
#     same run succeeded — otherwise the refusal proves only that the
#     path is broken.
#   - **Joining takes MINUTES.** Measured on this harness: 12 of 13
#     joiners adopt by ~180 s and the thirteenth by ~360 s, gated by DHT
#     visibility latency, not by anything this scenario does. The waits
#     are long on purpose and must not be "tuned down" when they fail —
#     see feedback_no_timeout_tuning.
#   - **A green here is green at E=15.** It proves the LOGIC — governance
#     lands on a boundary, tenure gates selection, quorum tracks the set.
#     It proves NOTHING about production magnitudes (E=720, grace 17280).
#
# WHAT IT DOES NOT PROVE
#   - Recovery. STEP 6 proves the chain STOPS below quorum; it says
#     nothing about getting it back if those validators never return.
#     That is the permanent-quorum-loss item, and it is out of scope here.
#   - Anything about a real network. 20 processes on one host: no
#     partition, no latency, no clock skew.
#
# EXIT: 0 pass, 99 skip (requirements unmet), non-zero fail.
# ════════════════════════════════════════════════════════════════════
set -uo pipefail

. "$(dirname "$0")/../stagef_env.sh"

die()  { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }
skip() { echo "[SKIP] $*"; exit 99; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active harness — run stagef_up_v2.sh first"
command -v sqlite3 >/dev/null || die "sqlite3 required"

CLI="$STAGEF_NODUSCLI_BIN"
NODUS="$STAGEF_NODUS_BIN"
[ -x "$CLI" ]   || die "nodus-cli not found at $CLI"
[ -x "$NODUS" ] || die "nodus-server not found at $NODUS"

E=${STAGEF_EPOCH_LENGTH:-720}
ORIG=${STAGEF_COMMITTEE_SIZE:-7}
NCAND=13
TOTAL=$(( ORIG + NCAND ))          # 20
CONF="$BASE_DIR/v2_genesis.conf"
PUMP="$BASE_DIR/v2pump/identity"
BOND=1000000000000000              # DNAC_SELF_STAKE_AMOUNT
COMMISSION=500
V2_SET_MAX=30                      # NODUS_V2_ACTIVE_SET_MAX (nodus_witness.h:162)
ILLEGAL=$(( V2_SET_MAX + 1 ))      # 31

# ── requirements, checked not assumed ───────────────────────────────
[ -f "$CONF" ] || skip "not a Ledger V2 cluster (no v2_genesis.conf) — use stagef_up_v2.sh"
[ -s "$PUMP/nodus.pk" ] || skip "no pump identity — this needs stagef_up_v2.sh"
[ "$E" -le 20 ] || skip "epoch length $E: the tenure arithmetic needs 3 boundaries within a pumpable height; rebuild with -DDNAC_EPOCH_LENGTH=15"
for i in $(seq 1 $NCAND); do
    [ -s "$BASE_DIR/cand$i/identity/nodus.pk" ] || \
        skip "candidate $i missing — export STAGEF_V2_CANDIDATES=$NCAND before stagef_up_v2.sh"
done
# ── THE PUMP BUDGET, CHECKED UP FRONT ───────────────────────────────
#
# A V2 chain makes a block only when a transaction arrives, so every
# height this scenario reaches costs one pump leaf. Running out halfway
# is not a soft failure: it stops the run at whatever step happened to be
# next and, before the fix in pump_to, reported it as "chain stopped
# advancing" — the harness accusing the chain of its own empty tank.
#
# WHERE THE NUMBER COMES FROM. 26 blocks go to the 13 claims and 13
# bonds. The rest is height: the growth boundaries alone need 4E+2, and
# STEPS 6c/6e/7/8 each drive the tip further — STEP 8 by a full epoch
# past wherever STEP 7 left it. A measured run reached 227 and wanted
# 242. So the requirement is stated as a formula with real margin rather
# than a number someone once found sufficient:
#
#     16 x E + 80     (=320 at E=15)
#
# Checked HERE, before anything is spent, so the failure is one line at
# the start naming the number to raise — not a death at STEP 8 forty
# minutes in.
PUMP_HAVE=$(grep -c "^amount       = 1000000000$" "$CONF" 2>/dev/null || echo 0)
PUMP_NEED=$(( 16 * E + 80 ))
[ "$PUMP_HAVE" -ge "$PUMP_NEED" ] || \
    skip "pump budget too small: the config has $PUMP_HAVE pump leaves, this
       scenario needs $PUMP_NEED at E=$E (16*E+80). Every height costs one
       leaf and running dry mid-run cannot be distinguished from a stalled
       chain without lying about one of them. Re-run the bring-up with
       STAGEF_V2_PUMP_LEAVES=$PUMP_NEED."

ok "requirements met (E=$E, $NCAND candidates, $PUMP_HAVE pump leaves >= $PUMP_NEED needed)"

PORT1=$(stagef_tcp_port 1)
SDB=$(stagef_node_chain_db 1)

# Candidate i runs at port index ORIG+2+i — the same block the bring-up
# used to generate its identity, so it can never collide with a live node.
cand_pidx() { echo $(( ORIG + 2 + $1 )); }
cand_dir()  { echo "$BASE_DIR/cand$1"; }
cand_db()   { ls "$BASE_DIR/cand$1/data/"witness_*.db 2>/dev/null | head -1; }

node_db() {   # $1 = 1..TOTAL  (1..ORIG genesis, ORIG+1..TOTAL candidates)
    if [ "$1" -le "$ORIG" ]; then stagef_node_chain_db "$1"
    else cand_db $(( $1 - ORIG )); fi
}
node_port() {
    if [ "$1" -le "$ORIG" ]; then stagef_tcp_port "$1"
    else stagef_tcp_port "$(cand_pidx $(( $1 - ORIG )))"; fi
}

tip() { sqlite3 -readonly "$SDB" "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks;" 2>/dev/null || echo 0; }

# Quorum the code uses: dna_bft_quorum(n) = 2n/3 + 1.
quorum_of() { echo $(( (2 * $1) / 3 + 1 )); }

# The committed snapshot for an epoch, on one node. Empty = absent.
snap_count() { sqlite3 -readonly "$1" "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$2;" 2>/dev/null; }
snap_hash()  { sqlite3 -readonly "$1" "SELECT hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$2;" 2>/dev/null; }

# ── pump: one claim per unclaimed pump leaf, each its own block ─────
#
# ⚠ IT MUST BE ABLE TO SAY "I SUBMITTED NOTHING", and the first cut could
# not. v2-claim over an identity whose leaves are ALL spent still connects
# and still returns non-zero, which is indistinguishable from "the chain
# would not commit". That confound cost a full diagnosis: STEP 6a reported
# a stall while the pump had been handing the node an already-claimed leaf,
# which the node REJECTED at admission and forwarded anyway
# (`not pooled locally (admission: claim admission rejected)`), so the
# scenario was measuring a transaction that could never commit under any
# quorum. The stall turned out to be real — a fresh leaf failed too — but
# only re-running by hand established that, which is exactly the work a
# scenario is supposed to have already done.
#
# So: return 0 only when a claim COMMITTED, 2 when there was nothing left
# to submit, 1 when something was submitted and did not commit. The
# liveness matrix reads the difference, because "no block" only means
# anything after "something was submitted".
pump_once() {
    local log="$BASE_DIR/grow_pump_one.log" crc
    : > "$log"
    "$CLI" -s 127.0.0.1 -p "$PORT1" v2-claim --config "$CONF" --db "$SDB" \
        --keys "$PUMP" --submit "127.0.0.1:$PORT1" > "$log" 2>&1
    crc=$?
    cat "$log" >> "$BASE_DIR/grow_pump.log"
    grep -q '^committed: height=' "$log" && return 0
    # v2-claim returns 2, and says so, when every leaf bound to this key is
    # already claimed. Before v0.19.46 it re-submitted spent leaves instead,
    # which is what made "no block" ambiguous here.
    [ "$crc" = 2 ] && return 2
    grep -q 'nothing to submit' "$log" && return 2
    return 1
}

# How many pump leaves remain. Guards every phase that needs to submit.
pump_remaining() {
    local total spent
    total=$(grep -c "^amount       = 1000000000$" "$CONF" 2>/dev/null || echo 0)
    spent=$(sqlite3 -readonly "$SDB" "SELECT COUNT(*) FROM v2_claims_spent;" 2>/dev/null || echo 0)
    echo $(( total - spent + NCAND + 1 ))   # candidates+user claims are not pump leaves
}

# Advance to tip >= $1. Pumps, then polls. Fails on no PROGRESS rather
# than on a clock: if the chain is moving at all the budget renews.
pump_to() {
    local target="$1" last stuck=0 prc
    last=$(tip)
    while [ "$(tip)" -lt "$target" ]; do
        pump_once; prc=$?
        # ⚠ AN EMPTY PUMP IS NOT A STOPPED CHAIN, AND SAYING SO IS A LIE
        # ABOUT THE SUBJECT. This loop used to discard pump_once's verdict
        # and report `chain stopped advancing` whenever the tip did not
        # move — including when there was nothing left to submit. It did
        # exactly that on a run where the chain was demonstrably healthy:
        # node1's own log showed block 227 committed with its QC attached
        # (14 certs) and `evicted 5/5 decided mempool entries (0 still
        # pending)`, while v2-claim was answering `all 200 leaf/leaves
        # bound to this key are already claimed — nothing to submit`.
        # The scenario had run out of fuel and blamed the chain for it.
        #
        # This is the same vacuity this file's header warns about, applied
        # to the other direction: there, a stall check that submits nothing
        # passes for the wrong reason; here, a progress check that submits
        # nothing FAILS for the wrong reason. Both are the harness lying
        # about what it measured.
        if [ "$prc" = 2 ]; then
            die "the pump is DRY at tip $(tip), target $target — every leaf
       bound to the pump identity is already claimed. The chain is NOT
       stopped; this scenario ran out of transactions to send. Raise
       STAGEF_V2_PUMP_LEAVES (see the budget check at startup) and re-run.
       Do NOT read this as a consensus failure."
        fi
        local waited=0
        while [ "$waited" -lt 40 ]; do
            sleep 2; waited=$(( waited + 2 ))
            [ "$(tip)" -gt "$last" ] && break
        done
        if [ "$(tip)" -le "$last" ]; then
            stuck=$(( stuck + 1 ))
            [ "$stuck" -ge 3 ] && die "chain stopped advancing at tip $(tip), target $target (the pump still had leaves — this one IS the chain)"
        else
            stuck=0
        fi
        last=$(tip)
    done
    info "tip $(tip) (target $target)"
}

# ── assert a value is identical across a set of node DBs ────────────
# $1 label, $2 sql, $3.. node indices
assert_same() {
    local label="$1" sql="$2"; shift 2
    local first="" n v
    for n in "$@"; do
        local db; db=$(node_db "$n")
        [ -n "$db" ] || die "$label: node $n has no chain DB"
        v=$(sqlite3 -readonly "$db" "$sql" 2>/dev/null)
        [ -n "$v" ] || die "$label: node $n returned EMPTY — an empty read is a failure, not agreement"
        if [ -z "$first" ]; then first="$v"
        elif [ "$v" != "$first" ]; then
            die "$label: node $n disagrees ($v != $first)"
        fi
    done
    echo "$first"
}

# ── how many nodes of $@ are up ─────────────────────────────────────
alive_count() {
    local n c=0
    for n in "$@"; do
        local pat
        if [ "$n" -le "$ORIG" ]; then pat="node$n/data"
        else pat="cand$(( n - ORIG ))/data"; fi
        ps -eo pid,comm,args --no-headers 2>/dev/null | \
            awk -v p="$pat" '$2=="nodus-server" && index($0,p)>0 {found=1} END{exit !found}' \
            && c=$(( c + 1 ))
    done
    echo "$c"
}

stop_node() {
    local n="$1" pat
    if [ "$n" -le "$ORIG" ]; then pat="node$n/data"; else pat="cand$(( n - ORIG ))/data"; fi
    local pid
    pid=$(ps -eo pid,comm,args --no-headers | \
          awk -v p="$pat" '$2=="nodus-server" && index($0,p)>0 {print $1; exit}')
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
}

start_node() {
    local n="$1" pidx dir extra="${2:-}"
    if [ "$n" -le "$ORIG" ]; then pidx="$n"; dir="$(stagef_node_dir "$n")"
    else pidx=$(cand_pidx $(( n - ORIG ))); dir="$(cand_dir $(( n - ORIG )))"; fi
    local seeds=""
    local s; for s in $(seq 1 "$ORIG"); do seeds="$seeds -s 127.0.0.1:$(stagef_udp_port "$s")"; done
    # shellcheck disable=SC2086
    "$NODUS" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$pidx")" -t "$(stagef_tcp_port "$pidx")" \
        -p "$(stagef_peer_port "$pidx")" -C "$(stagef_chan_port "$pidx")" \
        -W "$(stagef_witness_port "$pidx")" \
        $extra -i "$dir/identity" -d "$dir/data" $seeds \
        >> "$dir/nodus.log" 2>&1 &
    echo "$!" >> "$BASE_DIR/pids.txt"
}

# Wait for the chain to commit at least one block, pumping. Returns 0 if
# it moved, 1 if it did not. Used for BOTH directions of the matrix, so
# the "stalled" and "resumed" checks are the same measurement.
# Returns 0 = the chain committed, 1 = it did not, 2 = NOTHING COULD BE
# SUBMITTED (the pump is dry — the caller must NOT read that as a stall).
chain_moves() {
    local rounds="${1:-3}" before after r prc submitted=0
    before=$(tip)
    for r in $(seq 1 "$rounds"); do
        pump_once; prc=$?
        [ "$prc" = 2 ] && continue          # nothing to submit this round
        submitted=1
        [ "$prc" = 0 ] && { echo "$before -> $(tip)"; return 0; }
        local waited=0
        while [ "$waited" -lt 30 ]; do
            sleep 2; waited=$(( waited + 2 ))
            after=$(tip)
            [ "$after" -gt "$before" ] && { echo "$before -> $after"; return 0; }
        done
    done
    if [ "$submitted" = 0 ]; then
        echo "NOTHING SUBMITTED (pump dry, $(pump_remaining) leaves by count)"
        return 2
    fi
    echo "$before -> $(tip)"
    return 1
}

# A stall assertion that cannot pass vacuously: it FAILS if nothing could
# be submitted, because then no claim about liveness was tested at all.
assert_stalled() {
    local label="$1" rounds="${2:-3}" r rc
    r=$(chain_moves "$rounds"); rc=$?
    case "$rc" in
      0) die "$label — the chain COMMITTED while it should not have ($r)" ;;
      2) die "$label — nothing could be submitted ($r); a stall was never tested, and a skipped measurement is not a pass" ;;
      *) echo "$r" ;;
    esac
}

echo "══ V2 committee growth $ORIG → $TOTAL ══"
bash "$(dirname "$0")/../stagef_diff.sh" "pre-v2-grow" || exit 2

# ════════════════════════════════════════════════════════════════════
# STEP 1 — 13 funded strangers bond and become validators
# ════════════════════════════════════════════════════════════════════
t0=$(tip)
pre_vals=$(sqlite3 -readonly "$SDB" "SELECT COUNT(*) FROM validators;")
[ "$pre_vals" = "$ORIG" ] || die "expected $ORIG validators before growth, found $pre_vals — this cluster is not fresh"

for i in $(seq 1 $NCAND); do
    k="$(cand_dir "$i")/identity"
    pk=$(xxd -p -c 99999 "$k/nodus.pk")
    isval=$(sqlite3 -readonly "$SDB" "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$pk';" 2>/dev/null || echo 0)
    [ "${isval:-0}" = "0" ] || die "candidate $i is ALREADY a validator — it cannot demonstrate becoming one"

    # ⚠ THE CLIENT'S PATIENCE IS NOT THE CHAIN'S VERDICT.
    #
    # `committed: height=` is printed only when the submitting CLI is still
    # waiting when the reply arrives. It gives up after 60 s, and ONE leader
    # rotation costs more than that: round timeout (15 s) + view change
    # (10 s) + the new leader's round. So a transaction that commits
    # perfectly well can leave the client with nothing but
    # `dnac_spend RPC failed (rc=6)` and `Pending txn abandoned:
    # reason=timeout after 60000ms`.
    #
    # This scenario read that as a failure and killed a run in which the
    # chain was demonstrably fine: node1 had committed the block, attached
    # its QC (5 certs, quorum 5 of 7) and evicted the entry as decided,
    # while `v2_claims_spent` showed the claim SETTLED — and the harness
    # reported "candidate 8 could not claim its genesis leaf". Same class as
    # the empty-pump lie fixed in pump_to: the harness blaming the chain for
    # something that is not the chain's.
    #
    # So: the CLI's word is taken when it says yes; when it says no, the
    # CHAIN is asked. A claim is settled when its nullifier is in
    # v2_claims_spent, and a bond when the validator row exists — both are
    # committed state, which is the only authority here.
    claims_before=$(sqlite3 -readonly "$SDB" "SELECT COUNT(*) FROM v2_claims_spent;" 2>/dev/null || echo 0)
    "$CLI" -s 127.0.0.1 -p "$PORT1" v2-claim --config "$CONF" --db "$SDB" \
        --keys "$k" --submit "127.0.0.1:$PORT1" > "$BASE_DIR/grow_claim_$i.log" 2>&1 || true
    if ! grep -q '^committed: height=' "$BASE_DIR/grow_claim_$i.log"; then
        settled=0
        for _ in $(seq 1 30); do
            now=$(sqlite3 -readonly "$SDB" "SELECT COUNT(*) FROM v2_claims_spent;" 2>/dev/null || echo 0)
            [ "${now:-0}" -gt "${claims_before:-0}" ] && { settled=1; break; }
            sleep 2
        done
        [ "$settled" = 1 ] || {
            tail -5 "$BASE_DIR/grow_claim_$i.log" >&2
            die "candidate $i's claim did NOT settle — the client gave up AND
       v2_claims_spent did not grow, so this one really is the chain"
        }
        info "candidate $i's claim SETTLED after the client gave up (a leader
       rotation outlasts the 60 s wait) — reading the chain, not the client"
    fi
    sleep 2

    "$CLI" -s 127.0.0.1 -p "$PORT1" v2-envelope stake --db "$SDB" --keys "$k" \
        --bond "$BOND" --commission "$COMMISSION" --dest-fp "$(cat "$k/nodus.fp")" \
        --submit "127.0.0.1:$PORT1" > "$BASE_DIR/grow_stake_$i.log" 2>&1 || true
    if ! grep -q '^committed: height=' "$BASE_DIR/grow_stake_$i.log"; then
        bonded=0
        for _ in $(seq 1 30); do
            n=$(sqlite3 -readonly "$SDB" "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$pk';" 2>/dev/null || echo 0)
            [ "${n:-0}" -ge 1 ] && { bonded=1; break; }
            sleep 2
        done
        [ "$bonded" = 1 ] || {
            tail -5 "$BASE_DIR/grow_stake_$i.log" >&2
            die "candidate $i's bond did NOT settle — the client gave up AND no
       validator row appeared, so this one really is the chain"
        }
        info "candidate $i's bond SETTLED after the client gave up"
    fi
    sleep 2
done

post_vals=$(sqlite3 -readonly "$SDB" "SELECT COUNT(*) FROM validators;")
[ "$post_vals" = "$TOTAL" ] || die "expected $TOTAL validator rows after bonding, found $post_vals"
ok "STEP 1 — $NCAND non-validators bonded and became validators (tip $t0 -> $(tip))"

# The committee has NOT changed yet, and asserting that is the point:
# bonding is not membership.
e_now=$(( $(tip) / E * E ))
c_now=$(snap_count "$SDB" "$e_now")
[ "$c_now" = "$ORIG" ] || die "the live epoch's committee changed on bonding alone (epoch $e_now count=$c_now) — membership must come from a boundary, not from a stake"
ok "STEP 1b — the live committee is still $ORIG: bonding is not membership"

# ════════════════════════════════════════════════════════════════════
# STEP 2/3 — governance: an illegal target is refused, a legal one lands
# ════════════════════════════════════════════════════════════════════
KEYS=""
q=$(quorum_of "$ORIG")
for n in $(seq 1 "$q"); do KEYS="${KEYS:+$KEYS,}$BASE_DIR/node$n/identity"; done

EFFECTIVE=$(( 3 * E ))          # 45 at E=15 — see the arithmetic block
GROWTH_EPOCH=$(( 4 * E ))       # 60 — where ALL thirteen are tenured
MID_EPOCH=$EFFECTIVE            # 45 — where the first seven are

# 3 — above this release's V2 ceiling.
"$CLI" -s 127.0.0.1 -p "$PORT1" -i "$BASE_DIR/node1/identity" v2-envelope chain-config \
    --db "$SDB" --keys "$KEYS" --param 4 --value "$ILLEGAL" --effective "$EFFECTIVE" \
    --nonce 77001 > "$BASE_DIR/grow_cc_illegal.log" 2>&1 || true
sleep 8
for n in $(seq 1 "$ORIG"); do
    bad=$(sqlite3 -readonly "$(node_db "$n")" \
        "SELECT COUNT(*) FROM chain_config_history WHERE param_id=4 AND new_value=$ILLEGAL;" 2>/dev/null || echo 0)
    [ "${bad:-0}" = "0" ] || die "node $n COMMITTED the illegal target $ILLEGAL (ceiling is $V2_SET_MAX)"
done
ok "STEP 3 — target $ILLEGAL (> $V2_SET_MAX) is on no node's chain"

# 2 — the legal vote. This also retires the "the CLI was simply broken"
# reading of the refusal above: same binary, same path, same run.
"$CLI" -s 127.0.0.1 -p "$PORT1" -i "$BASE_DIR/node1/identity" v2-envelope chain-config \
    --db "$SDB" --keys "$KEYS" --param 4 --value "$TOTAL" --effective "$EFFECTIVE" \
    --nonce 77002 > "$BASE_DIR/grow_cc_legal.log" 2>&1 || true
landed=0
for _ in $(seq 1 30); do
    v=$(sqlite3 -readonly "$SDB" "SELECT new_value FROM chain_config_history WHERE param_id=4 AND effective_block=$EFFECTIVE;" 2>/dev/null)
    [ "$v" = "$TOTAL" ] && { landed=1; break; }
    sleep 2
done
[ "$landed" = 1 ] || { tail -5 "$BASE_DIR/grow_cc_legal.log" >&2; die "the legal vote (target $TOTAL) never committed — so the $ILLEGAL refusal above proves nothing about governance, only that this path is broken"; }
val=$(assert_same "chain_config row" \
      "SELECT new_value || '|' || effective_block FROM chain_config_history WHERE param_id=4 AND effective_block=$EFFECTIVE;" \
      $(seq 1 "$ORIG"))
ok "STEP 2 — committee target voted to $TOTAL, effective at $EFFECTIVE, identical on $ORIG nodes ($val)"

# ⚠ do NOT re-submit this vote. A second identical vote is a transaction
# the engine deterministically rejects at apply — see the POISON BATCH
# entry in nodus/BUGS.md. Survivable since v0.19.42, still a wasted round.

# ════════════════════════════════════════════════════════════════════
# STEP 1c — the candidates come up as nodes, BEFORE any boundary that
# could select them. A committee member that is not running is a seat
# that cannot vote.
# ════════════════════════════════════════════════════════════════════
PIN=$(cat "$BASE_DIR/v2_genesis_pin")
for i in $(seq 1 $NCAND); do
    rm -rf "$(cand_dir "$i")/data"; mkdir -p "$(cand_dir "$i")/data"
    start_node $(( ORIG + i )) "--v2-genesis-pin $PIN"
done
info "$NCAND candidate nodes started as pinned joiners — adoption is DHT-gated and takes minutes"

adopted=0
for t in $(seq 1 40); do          # 10 minutes; measured need ~6
    adopted=0
    for i in $(seq 1 $NCAND); do [ -n "$(cand_db "$i")" ] && adopted=$(( adopted + 1 )); done
    [ "$adopted" -ge "$NCAND" ] && break
    [ $(( t % 8 )) -eq 0 ] && info "  adopted $adopted/$NCAND (${_t:-$(( t * 15 ))}s)"
    sleep 15
done
[ "$adopted" -ge "$NCAND" ] || die "only $adopted/$NCAND candidates adopted the chain — a committee of $TOTAL cannot be reached with $(( NCAND - adopted )) seats held by nodes that have no chain"
ok "STEP 1c — all $NCAND candidates adopted the chain and are running"

# ════════════════════════════════════════════════════════════════════
# STEP 5 — Rule R: at the boundary BEFORE the candidates are tenured the
# committee is still the genesis seven, even though the target says $TOTAL
# ════════════════════════════════════════════════════════════════════
pump_to $(( 2 * E + 2 ))
c=$(assert_same "epoch $(( 2 * E )) snapshot" \
    "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$(( 2 * E ));" \
    $(seq 1 "$ORIG"))
[ "$c" = "$ORIG" ] || die "epoch $(( 2*E )) already has $c seats — Rule R did not gate the untenured candidates, and every growth assertion after this would be meaningless"
ok "STEP 5 — epoch $(( 2*E )) is still $ORIG seats: tenure gates selection independently of the target"

# ════════════════════════════════════════════════════════════════════
# STEP 4 — the growth lands AT the boundaries, four ways
# ════════════════════════════════════════════════════════════════════
pump_to $(( MID_EPOCH + 2 ))
ALL=$(seq 1 "$TOTAL")
mid=$(assert_same "epoch $MID_EPOCH snapshot count" \
      "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$MID_EPOCH;" $ALL)
info "epoch $MID_EPOCH committee: $mid seats"
[ "$mid" -gt "$ORIG" ] || die "epoch $MID_EPOCH is still $mid seats — the first tenured candidates were not selected"
assert_same "epoch $MID_EPOCH snapshot hash" \
    "SELECT hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$MID_EPOCH;" $ALL > /dev/null
ok "STEP 4a — epoch $MID_EPOCH grew to $mid seats, byte-identical on all $TOTAL nodes"

pump_to $(( GROWTH_EPOCH + 2 ))
grown=$(assert_same "epoch $GROWTH_EPOCH snapshot count" \
        "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$GROWTH_EPOCH;" $ALL)
[ "$grown" = "$TOTAL" ] || die "epoch $GROWTH_EPOCH has $grown seats, expected $TOTAL"
assert_same "epoch $GROWTH_EPOCH snapshot hash" \
    "SELECT hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$GROWTH_EPOCH;" $ALL > /dev/null
ok "STEP 4b — epoch $GROWTH_EPOCH committee is $TOTAL, byte-identical on all $TOTAL nodes"

# the header's validator-set digest actually changed at the boundary
pre_v=$(sqlite3 -readonly "$SDB" "SELECT hex(vset_hash) FROM v2_blocks WHERE global_height=$(( GROWTH_EPOCH - 1 ));")
post_v=$(sqlite3 -readonly "$SDB" "SELECT hex(vset_hash) FROM v2_blocks WHERE global_height=$(( GROWTH_EPOCH + 1 ));")
[ -n "$pre_v" ] && [ -n "$post_v" ] || die "missing blocks around the boundary — cannot compare the header digest"
[ "$pre_v" != "$post_v" ] || die "the block header's validator-set digest is UNCHANGED across the growth boundary — the snapshot row moved but the chain does not commit to it"
ok "STEP 4c — the block header's validator-set digest changed at the boundary"

# and the boundary block carries certificates
qc=$(sqlite3 -readonly "$SDB" "SELECT LENGTH(COALESCE(qc,'')) FROM v2_blocks WHERE global_height=$GROWTH_EPOCH;")
[ "${qc:-0}" -gt 0 ] || die "the boundary block at $GROWTH_EPOCH carries no certificate"
ok "STEP 4d — the boundary block carries a certificate ($qc bytes)"

assert_same "post-growth global_root" \
    "SELECT hex(global_root) FROM v2_blocks WHERE global_height=$(( GROWTH_EPOCH + 1 ));" $ALL > /dev/null
ok "STEP 4e — all $TOTAL nodes agree on state after the growth boundary"

# ════════════════════════════════════════════════════════════════════
# STEP 6 — quorum tracks the committee
# ════════════════════════════════════════════════════════════════════
Q=$(quorum_of "$TOTAL")           # 14 at N=20
info "committee $TOTAL → quorum $Q"

# 6a — Q alive commits.
for n in $(seq $(( Q + 1 )) "$TOTAL"); do stop_node "$n"; done
sleep 10
a=$(alive_count $(seq 1 "$TOTAL"))
[ "$a" = "$Q" ] || die "wanted exactly $Q alive, have $a"
r=$(chain_moves 3); rc=$?
[ "$rc" = 2 ] && die "STEP 6a — the pump is dry ($r); this step tested nothing"
[ "$rc" = 0 ] || die "STEP 6a — $Q of $TOTAL alive is EXACT QUORUM and the chain did NOT commit ($r).
       This is the view-change scatter recorded in nodus/BUGS.md: with the
       live view's leader among the stopped six, only nodes holding client
       work arm a view change, each escalates on its own clock, the tally
       is per-target, and the targets never converge. Measured at N=20:
       one block in an hour, a lone node climbing target 2 -> 318 at 1/14.
       DO NOT raise a timeout here — the chain is not slow, it cannot rotate."
ok "STEP 6a — $Q alive: chain commits ($r)"

# 6b — one fewer stalls. Submitted, not idle.
stop_node "$Q"
sleep 10
a=$(alive_count $(seq 1 "$TOTAL"))
[ "$a" = "$(( Q - 1 ))" ] || die "wanted exactly $(( Q - 1 )) alive, have $a"
r=$(assert_stalled "STEP 6b — $(( Q - 1 )) of $TOTAL is BELOW quorum $Q" 3)
ok "STEP 6b — $(( Q - 1 )) alive: no block across 3 pumped rounds ($r)"

# 6c — restoring quorum resumes it.
start_node "$Q"
sleep 20
r=$(chain_moves 5) || die "STEP 6c — quorum restored but the chain did not resume ($r)"
ok "STEP 6c — quorum restored: chain resumes ($r)"

# 6d — the original seven ALONE are now a minority.
for n in $(seq $(( ORIG + 1 )) "$TOTAL"); do stop_node "$n"; done
sleep 10
a=$(alive_count $(seq 1 "$TOTAL"))
[ "$a" = "$ORIG" ] || die "wanted exactly $ORIG alive, have $a"
r=$(assert_stalled "STEP 6d — the original $ORIG while the committee is $TOTAL (quorum $Q)" 3)
ok "STEP 6d — the genesis $ORIG alone are a minority and cannot commit ($r)"

# restore everyone — the residue contract says we leave a live chain
for n in $(seq $(( ORIG + 1 )) "$TOTAL"); do start_node "$n"; done
sleep 30
r=$(chain_moves 5) || die "could not restore the chain after the liveness matrix ($r)"
ok "STEP 6e — full set restored, chain live again ($r)"

# ════════════════════════════════════════════════════════════════════
# STEP 7 — the enlarged committee survives a full stop/start
# ════════════════════════════════════════════════════════════════════
before=$(tip)
for n in $(seq 1 "$TOTAL"); do stop_node "$n"; done
sleep 15
[ "$(alive_count $(seq 1 "$TOTAL"))" = "0" ] || die "not every node stopped"
for n in $(seq 1 "$TOTAL"); do start_node "$n"; done
sleep 40
r=$(chain_moves 6) || die "STEP 7 — the chain did not resume after a full restart at committee $TOTAL ($r)"
c=$(assert_same "post-restart committee" \
    "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$GROWTH_EPOCH;" $(seq 1 "$TOTAL"))
[ "$c" = "$TOTAL" ] || die "committee is $c after restart, expected $TOTAL"
ok "STEP 7 — full restart at committee $TOTAL: chain resumed and the set held ($r)"

# ════════════════════════════════════════════════════════════════════
# STEP 8 — a node misses an entire epoch and catches up
# ════════════════════════════════════════════════════════════════════
VICTIM=$TOTAL
stop_node "$VICTIM"
sleep 5
h_down=$(tip)
pump_to $(( h_down + E + 2 ))     # more than a whole epoch, boundary included
start_node "$VICTIM"
caught=0
for _ in $(seq 1 60); do
    vh=$(sqlite3 -readonly "$(node_db "$VICTIM")" "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;" 2>/dev/null)
    [ "${vh:--1}" -ge "$(tip)" ] && { caught=1; break; }
    sleep 5
done
[ "$caught" = 1 ] || die "STEP 8 — node $VICTIM did not catch up after missing an epoch boundary"
assert_same "post-catchup root" \
    "SELECT hex(global_root) FROM v2_blocks WHERE global_height=$(tip);" $(seq 1 "$TOTAL") > /dev/null
ok "STEP 8 — a node that missed a whole epoch caught up and agrees"

# ════════════════════════════════════════════════════════════════════
# STEP 9 — history is verifiable by someone who was never there
# ════════════════════════════════════════════════════════════════════
FRESH_IDX=$(( ORIG + 2 + NCAND + 1 ))
FRESH="$BASE_DIR/grow_replay"
rm -rf "$FRESH"; mkdir -p "$FRESH/identity" "$FRESH/data"
seeds=""; for s in $(seq 1 "$ORIG"); do seeds="$seeds -s 127.0.0.1:$(stagef_udp_port "$s")"; done
# shellcheck disable=SC2086
"$NODUS" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
    -u "$(stagef_udp_port $FRESH_IDX)" -t "$(stagef_tcp_port $FRESH_IDX)" \
    -p "$(stagef_peer_port $FRESH_IDX)" -C "$(stagef_chan_port $FRESH_IDX)" \
    -W "$(stagef_witness_port $FRESH_IDX)" \
    --v2-genesis-pin "$PIN" -i "$FRESH/identity" -d "$FRESH/data" $seeds \
    >> "$FRESH/nodus.log" 2>&1 &
echo "$!" >> "$BASE_DIR/pids.txt"

head=$(tip)
replayed=0
for _ in $(seq 1 60); do
    fdb=$(ls "$FRESH/data/"witness_*.db 2>/dev/null | head -1)
    if [ -n "$fdb" ]; then
        fh=$(sqlite3 -readonly "$fdb" "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;" 2>/dev/null)
        [ "${fh:--1}" -ge "$head" ] && { replayed=1; break; }
    fi
    sleep 10
done
[ "$replayed" = 1 ] || die "STEP 9 — a fresh node could not replay the chain to head $head"
fdb=$(ls "$FRESH/data/"witness_*.db | head -1)
for h in $GROWTH_EPOCH $(( GROWTH_EPOCH + 1 )) "$head"; do
    a=$(sqlite3 -readonly "$SDB"  "SELECT hex(global_root) FROM v2_blocks WHERE global_height=$h;")
    b=$(sqlite3 -readonly "$fdb"  "SELECT hex(global_root) FROM v2_blocks WHERE global_height=$h;")
    [ -n "$a" ] && [ -n "$b" ] || die "STEP 9 — missing block $h on one side"
    [ "$a" = "$b" ] || die "STEP 9 — replayed block $h differs from the fleet's"
done
gc=$(sqlite3 -readonly "$fdb" "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$GROWTH_EPOCH;")
[ "$gc" = "$TOTAL" ] || die "STEP 9 — the replaying node derived a committee of $gc at the growth epoch, not $TOTAL"
ok "STEP 9 — a node that was never there replayed genesis→head, growth boundary included"

echo
echo "[PASS] a V2 committee grew $ORIG → $mid → $TOTAL by governance, on the boundary,"
echo "       with quorum tracking it in both directions, surviving a full restart,"
echo "       a missed epoch, and a cold replay by a node that was never present."
# ⚠ REPORT THE PARAMETERS THE BINARY WAS BUILT WITH, NOT THE ONES THE
# SHELL HAPPENS TO HOLD. STAGEF_CC_GRACE_SAFETY defaults to the PRODUCTION
# 17280 in stagef_env.sh:60, so printing it made a run on a grace-15 binary
# claim it had been made at production grace — the exact dishonest-parameter
# report this file's header forbids. The environment variable only tells the
# SCRIPT what to write into a config; it cannot say what the binary carries.
# Read the grace out of the build's own cache when that is knowable, and say
# so plainly when it is not.
_grace="unknown (set -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS is compiled in; \
this script cannot read it)"
_cache="$(dirname "$STAGEF_NODUS_BIN")/CMakeCache.txt"
if [ -f "$_cache" ]; then
    _g=$(grep -o 'DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=[0-9]*' "$_cache" \
         | head -1 | cut -d= -f2)
    [ -n "$_g" ] && _grace="$_g (from the binary's CMakeCache)"
fi
echo "       Parameters: DNAC_EPOCH_LENGTH=$E, SAFETY grace $_grace."
echo "       This proves the LOGIC at those constants and nothing about production"
echo "       magnitudes (720 / 17280)."
exit 0
