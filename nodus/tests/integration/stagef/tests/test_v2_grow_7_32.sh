#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_grow_7_32.sh — a Comet committee grows 7 → 32 WITHOUT a vote,
# commits with 22 of 32 alive, halts with 21, and comes back at 22
# ════════════════════════════════════════════════════════════════════
#
# The operator's FINAL p2p-port scenario (docs/plans/2026-09-26-p2p-port-
# design.md §10): 7 → 32 → 22 → 21 (halt) → 22 (live). Written against
# the source in P2P-PORT F6; NOT RUN YET — its first run is its first
# measurement. Modelled on test_v2_grow_7_20.sh (STEP 1 claim + bond,
# STEP 4 snapshot / ValidatorUpdates / vset_hash checks, STEP 6 the
# stop / halt / resume shape); read that header for the shared reasoning.
#
# WHAT IT PROVES
#   The property that would be false if it failed: *on the 4004 p2p
#   port, a running version-3 chain seats 25 strangers who bond on it —
#   32 validators, the full active-set ceiling, with no governance vote —
#   cometbft's OWN voting set follows, and at N = 32 with equal stake the
#   chain commits with exactly 22 validators alive, stops with 21, and a
#   transaction left pending across the stop lands as soon as the 22nd
#   comes back.*
#
#   Steps, each asserted separately:
#     1. 25 candidate nodes start from the network file alone (persistent
#        peers = the 7 genesis nodes, PEX for the rest), derive the
#        fleet's chain, go LIVE and catch up; each claims its genesis leaf
#        and bonds (`v2-envelope stake`, no --db) — every step waited on
#        its LEDGER EFFECT; 32 equal bonds, no delegation (read, not
#        assumed); bonding alone is not membership.
#     2. growth, derived from the bond heights that landed: E_ALL = the
#        first boundary at which ALL 25 are tenured AND in the frozen
#        copy. There: every candidate's bond is in copy(E_ALL − 2E) and
#        that copy holds 32 equal totals; snapshot(E_ALL − E) seats exactly
#        7 + (the candidates already eligible one epoch earlier — 0 unless
#        the bonds straddled a boundary); snapshot(E_ALL) seats EXACTLY 32,
#        count and hash identical on all 32 nodes; cometbft's
#        ValidatorUpdates line at E_ALL is identical on all 32 and adds
#        exactly 32 − that previous count, removing 0; and the committed
#        header's NEXT-validators hash shows cometbft's two-height lag
#        (equal at E_ALL − 1 / E_ALL, changed at E_ALL + 1, equal again at
#        E_ALL + 2), identical on all 32.
#     3. 22 LIVE (positive control): aligned to a fresh epoch start b, ten
#        validators are SIGSTOPped — genesis nodes 2..7 and cand22..25 —
#        and the chain commits WINDOW = 23 heights (pigeonhole, below);
#        the ten sign nothing (v2_attendance frozen), every one of the 22
#        running signs.
#     4. 21 → HALT: cand21 stopped too; a spend CheckTx-approved by node 1
#        is pending, and NO height lands across 3 consecutive
#        CreateEmptyBlocks intervals (≤ 2 in-flight heights allowed).
#     5. 22 → LIVE: cand21 alone is SIGCONTed; the SAME pending spend
#        lands; the chain advances 3 more heights with the other ten still
#        stopped (their attendance still frozen); then the ten resume
#        and all 32 agree at a floor (this script's own 32-node
#        comparison — stagef_cmt_diff_at_floor loops nodes 1..7 only,
#        stagef_env.sh stagef_cmt_diff_at_floor).
#     6. END: the chain is driven past the boundary at which Rule N would
#        retire a validator that missed two epochs (b + 2E); no validator
#        is AUTO_RETIRED and the latest snapshot still seats 32.
#
# GROUNDING (read in the source, not assumed)
#   - Default seat target 32 — dnac/include/dnac/dnac.h:253
#     DNAC_TARGET_ACTIVE_DEFAULT, equal by _Static_assert to the active-set
#     ceiling NODUS_V2_ACTIVE_SET_MAX 32 (nodus/src/witness/
#     nodus_witness.h:151-155). vset_target_for_epoch uses it whenever no
#     TARGET_ACTIVE_COUNT row applies (nodus_witness_vset.c:485-507), and
#     the genesis config stagef_up_v2.sh writes carries no such row — so
#     reaching 32 needs NO governance vote.
#   - Tenure: status IN (ACTIVE, ELIGIBLE) AND active_since_block + 2E <=
#     e_start, genesis rows (active_since <= 1) exempt
#     (nodus_witness_validator.c nodus_validator_bonded_tenured, :357-395;
#     DNAC_MIN_TENURE_BLOCKS = 2E, dnac.h:224).
#   - Frozen copy: epoch e is ranked by copy(e − 2E)
#     (nodus_witness_committee.c:390 copy_epoch, the "okuma B" comment
#     above it), and a STAKE executed IN boundary block B is inside
#     copy(B) — "its own transactions run before boundary B − E writes
#     copy(B − E)" (the same comment; the copy is written LAST at a
#     boundary, nodus_witness_v2_epoch.c:1651-1660). A candidate with a
#     frozen total of 0 is not seated (committee.c, the frozen_total == 0
#     branch).
#     ⇒ first-eligible(a) = ceil(a / E)·E + 2E for a bond landing at
#       height a; E_ALL = the maximum over the 25. The script CHECKS both
#       halves on the chain (every bond in copy(E_ALL − 2E), the counts
#       one epoch before and at E_ALL) — a wrong derivation is a RED with
#       "arithmetic" in its message, never a silent change of subject.
#   - Quorum: a vote set has a majority when `sum > total * 2 / 3`
#     (integer — shared/dnac/cmt_vote_set.c:967). Power per validator =
#     total_stake / DNAC_DECIMAL_UNIT (nodus_witness_cmt_app.c, the §A
#     diff); every validator bonds DNAC_SELF_STAKE_AMOUNT = 10^15 raw
#     (dnac.h:137) and nobody delegates, so every power is 10^7. The
#     script READS that premise (validators.self_stake all equal,
#     delegations 0, the frozen copy's totals all equal) and computes:
#       N = 32: total 3.2e8, total*2/3 = 213 333 333 → need power
#               > 213 333 333 → 22 signers. 21 signers = 2.1e8 → stall.
#   - Rule N: attendance meets the bar when signed_count·10000 >=
#     E·DNAC_LIVENESS_THRESHOLD_BPS (5000) AND the last signature is
#     within DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS of the boundary
#     (nodus_witness_v2_epoch.c:907-930); DNAC_AUTO_RETIRE_EPOCHS = 2
#     consecutive misses retire (dnac.h:315, :321). The round-6 weight
#     floor would NOT save the stopped ten (22 remaining at equal power
#     satisfy (P − max) > P·2/3).
#
# WHY 23 HEIGHTS IN STEP 3 (pigeonhole), AND WHY E MUST BE >= 30
#   Under equal voting power cometbft's weighted round-robin degenerates
#   to exact round-robin (test_cmt_dead_proposer.sh's header, read from
#   shared/dnac/cmt_validator_set.c:849-977 — GROUNDED INFERENCE from the
#   ported code's structure, not observed here). 23 consecutive heights
#   have 23 distinct round-0 proposers out of 32; only 22 are running, so
#   at least one of those heights had a STOPPED round-0 proposer and had
#   to time out and move on. WINDOW = running + 1 = 23.
#   Rule N: the ten are stopped RIGHT AT a fresh epoch start b. They miss
#   epoch [b, b+E) and must still sign >= E/2 of [b+E, b+2E), or the
#   second miss retires them at b + 2E. Their stop lasts WINDOW (23) + at
#   most 2 in-flight heights (STEP 4) + the landing of the pending spend
#   (≈ 2, JUDGMENT) + 3 heights of STEP 5 = WINDOW + 7 = 30 heights, then
#   their catch-up lag. With E >= 30 that whole stop fits in the aligned
#   epoch and the next one only has to absorb the catch-up lag (< E/2).
#   At the harness's usual E = 15 the ten would miss 15 of [b, b+15) AND
#   ≈ 13 of [b+15, b+30) — retired at b+30 BY CONSTRUCTION, so this
#   scenario SKIPs below 30 instead of going RED for a reason that is not
#   a defect. The terminal "no AUTO_RETIRED" check makes a wrong premise
#   a visible RED.
#
# WHAT IT REQUIRES
#   ⚠ ITS OWN BUILD, ITS OWN FRESH CLUSTER, RUN STANDALONE AND LAST.
#     compile — an EPOCH LENGTH OF 30 (not the Quick-start 15; see above).
#       Either the Quick-start four-flag line with 30 in place of 15:
#         -DDNAC_EPOCH_LENGTH=30 -DDNAC_BLOCKS_PER_YEAR=20
#         -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#         -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#       or -DDNAC_EPOCH_LENGTH=30 alone (this scenario proposes no
#       governance change and reaches no halving, so the grace and year
#       constants are irrelevant to it — but STAGEF_BLOCKS_PER_YEAR must
#       then stay at its default, matching the binary). nodus-server AND
#       nodus-cli from the SAME build, from a tree with the 4004 p2p port.
#     env, ALL exported BEFORE stagef_up_v2.sh:
#       STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN → that build
#       STAGEF_EPOCH_LENGTH=30 (and STAGEF_BLOCKS_PER_YEAR=20 with the
#         four-flag build; unset with the one-flag build)
#       STAGEF_V2_CANDIDATES=25   — mints cand1..25 (fewer → SKIP)
#     Kept at their defaults: STAGEF_PUMP_FUNDER_NODE=3 (keys only — node
#     3 is stopped in STEP 3) and STAGEF_PUMP_SUBMIT_NODE=1 (REQUIRED:
#     node 1 is the reference DB and is never stopped; other → SKIP).
#     Bring-up with STAGEF_V2_CANDIDATES=25 changes nothing in
#     stagef_up_v2.sh: candidate i uses source_id 2000 + i (2001..2025,
#     below the probe's 3000) and port block C+3+i (up to index 35, ports
#     14340-14344); 25 × CAND_ALLOC keeps total_supply_raw far below
#     INT64_MAX (nodus_witness_v2_gen.c:834).
#   SKIPS (rc 99) — coverage that did not happen, never a pass — when:
#     not a version-3 cluster / no genesis config; no network file (a
#     bring-up on a pre-p2p server); a candidate identity missing;
#     STAGEF_EPOCH_LENGTH outside [30, 40] (below 30 see above; above 40
#     the ≈ 7 epochs walked are out of a reasonable wall clock); the
#     CLI-SPEND pump unavailable; the pump submit node not node 1.
#   ⏱ JUDGMENT, not measured: ≈ 45-90 min on one 4-CPU machine —
#     ≈ 7 epochs of 30 pumped blocks, a 25-node catch-up from genesis over
#     the 4004 stack, one 3-interval (180 s) expected halt.
#
# WHAT IT LEAVES BEHIND
#   Run it on its own fresh bring-up and tear down after (stagef_down.sh
#   reaps every pid this script appends to pids.txt).
#     - 25 candidate nodes running under $BASE_DIR/cand1..25 (derived
#       locally from v2_genesis.conf, ports C+3+i), in pids.txt
#     - a PERMANENT 32-seat committee; every candidate leaf claimed and
#       bonded; node 3's leaf claimed by the pump and one fee per pump step
#       gone from it (into the reward pool)
#     - nodes 2..7 and cand21..25 SIGSTOPped and resumed (an EXIT trap
#       SIGCONTs every node this script stopped, on ANY exit)
#     - $BASE_DIR/grow32_claim_<i>.log / grow32_stake_<i>.log
#     - the chain ≈ 7 epochs on
#
# HOW IT CAN LIE
#   - **CheckTx APPROVED is admission, not inclusion.** Every claim, bond
#     and pump spend is followed to its LEDGER EFFECT through
#     stagef_cmt_wait_row (progress- AND height-bounded). The CLI's stdout
#     is read for its verdict and the spend's intent_id only.
#   - **A halt is only a quorum halt if the same chain was just shown to
#     commit, and comes back.** 33 processes share 4 CPUs. STEP 3 (22
#     running commit WINDOW heights) is the positive control right before
#     the halt, and STEP 5 (the SAME pending spend lands the moment ONE
#     validator returns) is the recovery right after — together they tell
#     a 21-of-32 quorum halt from CPU starvation. Every failure message in
#     STEPs 3-5 names its step and prints each node's state, tip and CPU
#     share over one second (/proc), so a starved machine is visible in
#     the output. A RED at STEP 3 is NOT evidence of a quorum bug until the
#     node logs have been read for round timeouts.
#   - **STEP 3 runs at EXACT majority.** 22 running, 22 needed: every
#     running validator's precommit is required for every block; one node
#     lagging a round costs that round a timeout.
#   - **An in-flight height may commit just after the 11th stop.** STEP 4
#     allows the tip to move by at most 2 before freezing (JUDGMENT, the
#     test_cmt_dead_proposer.sh settle shape); more is RED.
#   - **STEP 5 resumes the LAST node stopped (cand21)**, ≤ 2 heights
#     behind, so it tests quorum restoration, not a long catch-up; a
#     resumed genesis node (stopped ≥ 23 heights) would add catch-up over
#     the consensus reactor's stored-part gossip (no blocksync — README
#     "What a green COMET run does not prove" item 4) to the subject.
#   - **The pigeonhole in STEP 3 is an INFERENCE** from the ported
#     proposer selection, not an observed timeout (cmt_cs.c logs no
#     "round advanced" line). The load-bearing STEP 3 assertions are the
#     attendance rows.
#   - **The K2 inbound-cap exemption for bonded identities is NOT
#     exercised.** A genesis node's inbound peers are at most the 25
#     candidates plus 6 genesis peers = 31, below the default
#     max_num_inbound_peers 40 (shared/dnac/cmt_p2p_switch.h:138), so no
#     peer is ever refused for the cap; the exemption is covered by unit
#     tests only. allow_duplicate_ip / addr_book_strict=false are
#     harness-only (README "P2P-PORT F6").
#   - **A 25-node catch-up from genesis on the new 4004 stack is not
#     measured yet.** STEP 1 waits for it with a wide 8-interval progress
#     bound (the GROW-7-20 value) and FAILS with that reason; do NOT tune
#     it down.
#   - **"32 validator rows" is not "a committee of 32".** Seats come only
#     from a boundary's snapshot; counts are read from
#     validator_set_snapshots and cometbft's own ValidatorUpdates line, on
#     all 32 nodes. Which members the snapshot holds is not decoded — 32
#     seats out of exactly 32 eligible rows implies all of them.
#   - **Rule N safety is arithmetic, then checked.** The terminal check
#     runs only after the chain passed b + 2E + 1, the first boundary
#     that could retire a validator stopped in STEP 3, so it is not
#     vacuous; a RED there points at resume/catch-up lag first.
#   - **One machine.** No partition, no latency, SIGSTOP is not a crash,
#     and green at E = 30 proves the LOGIC only — nothing about production
#     magnitudes (E = 720).
#   - **NOT RUN YET.** Written against the source; no line has run on a
#     cluster.
#   - **rc=99 is not a pass.**
#
# EXIT: 0 pass (every step asserted), 99 skip, anything else fail.
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

die()  { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }
skip() { echo "[SKIP] $*"; exit 99; }

# ── every node this script SIGSTOPs is SIGCONTed on ANY exit ─────────
STOPPED_PIDS=()
resume_stopped() {
    local p
    for p in "${STOPPED_PIDS[@]+"${STOPPED_PIDS[@]}"}"; do
        kill -CONT "$p" 2>/dev/null || true
    done
    STOPPED_PIDS=()
}
trap resume_stopped EXIT

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active harness — run stagef_up_v2.sh first"
command -v sqlite3 >/dev/null || die "sqlite3 required"
command -v openssl >/dev/null || die "openssl required (stagef_voter_id)"

CLI="$STAGEF_NODUSCLI_BIN"
NODUS="$STAGEF_NODUS_BIN"
[ -x "$CLI" ]   || die "nodus-cli not found at $CLI"
[ -x "$NODUS" ] || die "nodus-server not found at $NODUS"

C="$STAGEF_COMMITTEE_SIZE"          # 7 genesis validators (stagef_env.sh)
NCAND=25
TOTAL=$(( C + NCAND ))              # 32
E="${STAGEF_EPOCH_LENGTH:-720}"
CONF="$BASE_DIR/v2_genesis.conf"
BOND=1000000000000000               # DNAC_SELF_STAKE_AMOUNT (dnac.h:137)
COMMISSION=500
V2_SET_MAX=32                       # NODUS_V2_ACTIVE_SET_MAX (nodus_witness.h:151)
E_MIN=30                            # see "WHY E MUST BE >= 30" above
E_MAX=40

# ── requirements, checked not assumed ───────────────────────────────
SDB=$(stagef_node_chain_db 1)
[ -n "$SDB" ] && [ -s "$SDB" ] || skip "no chain DB for node1 — not a stagef_up_v2.sh cluster"
has_v2=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
[ "${has_v2:-0}" != "0" ] && [ -f "$CONF" ] || skip "not a version-3 cluster with a genesis config — use stagef_up_v2.sh"
[ -s "$BASE_DIR/v2_genesis_pin" ] && [ -s "$BASE_DIR/v2_chain_id" ] || skip "bring-up recorded no genesis pin / chain id"
[ -s "$(stagef_network_file)" ] || skip "no network file at $(stagef_network_file) — bring up on a nodus-server with the 4004 p2p port (its -h lists --network-file)"
[ "$TOTAL" = "$V2_SET_MAX" ] || die "harness arithmetic: $C + $NCAND is not the active-set ceiling $V2_SET_MAX"
for i in $(seq 1 "$NCAND"); do
    [ -s "$BASE_DIR/cand$i/identity/nodus.pk" ] && [ -s "$BASE_DIR/cand$i/identity/nodus.fp" ] || \
        skip "candidate $i missing — export STAGEF_V2_CANDIDATES=$NCAND before stagef_up_v2.sh"
done
if [ "$E" -lt "$E_MIN" ] || [ "$E" -gt "$E_MAX" ]; then
    skip "epoch length $E: needs a build with $E_MIN <= E <= $E_MAX
       (-DDNAC_EPOCH_LENGTH=30 + STAGEF_EPOCH_LENGTH=30, exported before
       stagef_up_v2.sh). Below $E_MIN the ten validators STEP 3 stops for a
       23-height pigeonhole window plus the halt and the recovery miss two
       consecutive epochs and Rule N retires them BY CONSTRUCTION (see the
       header); above $E_MAX the ~7 epochs walked are out of a reasonable
       wall clock."
fi
[ "$STAGEF_PUMP_SUBMIT_NODE" = 1 ] || \
    skip "STAGEF_PUMP_SUBMIT_NODE=$STAGEF_PUMP_SUBMIT_NODE — node 1 is the only node never stopped; the pump must submit to it"
if ! stagef_cmt_pump_ready "$SDB"; then
    skip "the CLI-SPEND pump is unavailable (see [pump] above) — ~7 epochs of
       idle production at 60 s per block is out of reach"
fi
DU=$(awk -F'= *' '/^decimal_unit/{print $2; exit}' "$CONF")
case "$DU" in ''|*[!0-9]*|0) die "cannot read decimal_unit from $CONF" ;; esac

pre_vals=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM validators;")
[ "$pre_vals" = "$C" ] || die "expected $C validators before growth, found $pre_vals — this cluster is not fresh (run standalone)"
for i in $(seq 1 "$NCAND"); do
    if ls "$BASE_DIR/cand$i/data/"witness_*.db >/dev/null 2>&1; then
        die "cand$i already has a chain database — this bring-up already ran a growth scenario; bring up fresh"
    fi
done
stagef_sentinel SETUP_OK
ok "requirements met (E=$E, $NCAND candidates, pump ready, decimal_unit $DU)"

# ── node addressing: 1..C genesis, C+1..TOTAL candidates ─────────────
PORT1=$(stagef_tcp_port 1)
node_dir()  { if [ "$1" -le "$C" ]; then echo "$BASE_DIR/node$1"; else echo "$BASE_DIR/cand$(( $1 - C ))"; fi; }
# Candidate i uses port block C+3+i — the one stagef_up_v2.sh (section 1c)
# gave its identity spawn, past the v2user (C+1), pump (C+2) and probe
# (C+3) blocks.
node_pidx() { if [ "$1" -le "$C" ]; then echo "$1"; else echo $(( C + 3 + $1 - C )); fi; }
# largest_db DIR — the largest non-empty witness_*.db in DIR, without a
# `ls | head` pipe (under pipefail an early-exiting reader can SIGPIPE the
# writer — README, test_v2_rewards.sh row).
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
node_db()  { largest_db "$(node_dir "$1")/data"; }
node_log() { echo "$(node_dir "$1")/nodus.log"; }
node_pk()  { echo "$(node_dir "$1")/identity/nodus.pk"; }
node_fp()  { cat "$(node_dir "$1")/identity/nodus.fp"; }
node_pkhex() { xxd -p -c 999999 "$(node_pk "$1")"; }
# The node's own process: its data dir as the -d argument (one per dir).
node_pid() { pgrep -o -f -- "-d $(node_dir "$1")/data( |\$)" || true; }
tip() { stagef_cmt_tip "$SDB"; }

SEEDS=()
for s in $(seq 1 "$C"); do SEEDS+=(-s "127.0.0.1:$(stagef_udp_port "$s")"); done

# start_node N — the bring-up's spawn line, with -c nodus.json (its
# "network_file" key gives the node its persistent peers), log APPENDED,
# pid appended to pids.txt.
start_node() {
    local n="$1" dir pidx
    dir=$(node_dir "$n"); pidx=$(node_pidx "$n")
    "$NODUS" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$pidx")" -t "$(stagef_tcp_port "$pidx")" \
        -p "$(stagef_peer_port "$pidx")" -C "$(stagef_chan_port "$pidx")" \
        -W "$(stagef_witness_port "$pidx")" \
        -i "$dir/identity" -d "$dir/data" "${SEEDS[@]}" \
        >> "$dir/nodus.log" 2>&1 &
    echo "$!" >> "$BASE_DIR/pids.txt"
}

# wait_listening N — attempt-bounded, the bring-up's own check.
wait_listening() {
    local tcp ok_=0 lst
    tcp=$(stagef_tcp_port "$(node_pidx "$1")")
    for _ in $(seq 1 60); do
        lst=$(ss -lt 2>/dev/null || true)
        if grep -Eq "[:.]${tcp}\\b" <<< "$lst"; then ok_=1; break; fi
        sleep 0.5
    done
    [ "$ok_" = 1 ] || die "node $1 never listened on $tcp"
}

# wait_role_live N — role + startup table + LIVE in the node's log
# (nodus_witness.c:935 / :1704 / :1825), attempt-bounded, the bring-up's
# anti-vacuity shape. One awk pass — no early-exit pipe reader.
wait_role_live() {
    local log flags=000
    log=$(node_log "$1")
    for _ in $(seq 1 90); do
        flags=$(awk '/chain role: COMETBFT/        {r=1}
                     /cometbft startup table built/ {s=1}
                     /cometbft lane LIVE/          {l=1}
                     END { printf "%d%d%d", r, s, l }' "$log" 2>/dev/null || echo 000)
        [ "$flags" = 111 ] && return 0
        sleep 1
    done
    die "node $1 incomplete after start: role/startup-table/lane-live = $flags (see $log)"
}

# sigstop_node N — SIGSTOP, recorded for the EXIT trap.
sigstop_node() {
    local pid; pid=$(node_pid "$1")
    [ -n "$pid" ] || die "node $1 is not running"
    kill -STOP "$pid"
    STOPPED_PIDS+=("$pid")
}
# resume_one N — SIGCONT exactly node N and forget it in the trap list.
resume_one() {
    local pid p keep=()
    pid=$(node_pid "$1")
    [ -n "$pid" ] || die "node $1 is not running"
    kill -CONT "$pid"
    for p in "${STOPPED_PIDS[@]+"${STOPPED_PIDS[@]}"}"; do
        [ "$p" = "$pid" ] || keep+=("$p")
    done
    STOPPED_PIDS=("${keep[@]+"${keep[@]}"}")
}

# dump_fleet — diagnostic for the reader of a STEP 3-5 failure: per node
# its process state (T = stopped), its OWN tip and its CPU share over ONE
# second (utime+stime delta from /proc/<pid>/stat, in % of one core), plus
# the load average. Printed only; nothing is asserted on it. It is what
# separates "a quorum halt" from "33 processes starving on 4 CPUs".
dump_fleet() {
    local n pid st db t hz f1 f2 ticks
    declare -A T0
    hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
    for n in $(seq 1 "$TOTAL"); do
        pid=$(node_pid "$n")
        if [ -n "$pid" ] && [ -r "/proc/$pid/stat" ]; then
            f1=$(awk '{print $14 + $15}' "/proc/$pid/stat" 2>/dev/null || echo 0)
            T0[$n]="$f1"
        fi
    done
    sleep 1
    echo "── fleet state (CPU = % of one core over the last second; $(nproc 2>/dev/null || echo '?') CPUs; load $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo '?')) ──" >&2
    for n in $(seq 1 "$TOTAL"); do
        pid=$(node_pid "$n")
        db=$(node_db "$n")
        if [ -n "$db" ]; then t=$(stagef_cmt_tip "$db"); else t="-"; fi
        if [ -z "$pid" ]; then
            printf '   node %2d  (%s)  NOT RUNNING  tip %s\n' "$n" "$(basename "$(node_dir "$n")")" "$t" >&2
            continue
        fi
        st=$(ps -o stat= -p "$pid" 2>/dev/null || echo "?")
        f2=$(awk '{print $14 + $15}' "/proc/$pid/stat" 2>/dev/null || echo 0)
        ticks=$(( f2 - ${T0[$n]:-$f2} ))
        printf '   node %2d  (%-6s)  pid %-7s state %-4s tip %-6s cpu %3d%%\n' \
            "$n" "$(basename "$(node_dir "$n")")" "$pid" "$st" "$t" $(( ticks * 100 / hz )) >&2
    done
}
step_fail() {   # STEP MESSAGE — the fleet dump, then die naming the step
    local s="$1"; shift
    dump_fleet || true
    die "$s — $*"
}

# wait_all_reach H STALL [N...] — every listed node's own tip reaches H,
# progress-bounded (stagef_cmt_wait_height). Default: all TOTAL nodes.
wait_all_reach() {
    local h="$1" stall="$2" n db; shift 2
    local nodes=("$@")
    [ "${#nodes[@]}" -gt 0 ] || nodes=($(seq 1 "$TOTAL"))
    for n in "${nodes[@]}"; do
        db=$(node_db "$n")
        [ -n "$db" ] || die "node $n has no chain database"
        stagef_cmt_wait_height "$db" "$h" "$stall" >/dev/null \
            || die "node $n never reached height $h (stuck at $(stagef_cmt_tip "$db"))"
    done
}

# assert_same LABEL SQL N... — identical and NON-EMPTY on every listed
# node (an empty read is a failure, never agreement).
assert_same() {
    local label="$1" sql="$2"; shift 2
    local first="" n db v
    for n in "$@"; do
        db=$(node_db "$n")
        [ -n "$db" ] || die "$label: node $n has no chain DB"
        v=$(sqlite3 "$db" "$sql" 2>/dev/null || true)
        [ -n "$v" ] || die "$label: node $n returned EMPTY — an empty read is a failure, not agreement"
        if [ -z "$first" ]; then first="$v"
        elif [ "$v" != "$first" ]; then die "$label: node $n disagrees ($v != $first)"; fi
    done
    echo "$first"
}

# agree_at_floor LABEL — stagef_cmt_diff_at_floor's shape over ALL 32
# nodes (that helper and stagef_diff.sh loop 1..7 only): the floor is the
# minimum tip, a height every node has provably reached; global_root AND
# block_id must be identical there.
agree_at_floor() {
    local label="$1" dbs=() db n h floor="" ref="" row
    for n in $(seq 1 "$TOTAL"); do
        db=$(node_db "$n"); [ -n "$db" ] || die "$label: node $n has no chain DB"
        dbs+=("$db")
    done
    for db in "${dbs[@]}"; do
        h=$(stagef_cmt_tip "$db"); [ -n "$h" ] || h=-1
        if [ -z "$floor" ] || [ "$h" -lt "$floor" ]; then floor="$h"; fi
    done
    [ "$floor" -ge 1 ] || die "$label: some node has no block (floor $floor)"
    for db in "${dbs[@]}"; do
        row=$(sqlite3 "$db" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height=$floor;" 2>/dev/null || true)
        [ -n "$row" ] || die "$label: $(dirname "$(dirname "$db")") has no row at the floor $floor"
        if [ -z "$ref" ]; then ref="$row"
        elif [ "$row" != "$ref" ]; then
            die "$label: DIVERGENCE at height $floor — $(dirname "$(dirname "$db")") has ${row:0:32}..., the first node ${ref:0:32}..."
        fi
    done
    ok "$label: ${#dbs[@]} nodes identical at height $floor (root|block_id ${ref:0:16}...)"
}

# need_signers N P — the smallest k with k·P > (N·P)·2/3 (integer), i.e.
# cometbft's majority rule (cmt_vote_set.c:967) at N equal powers P.
need_signers() {
    local n="$1" p="$2" k=0 thr
    thr=$(( n * p * 2 / 3 ))
    while [ $(( k * p )) -le "$thr" ]; do k=$(( k + 1 )); done
    echo "$k"
}

# vu_line N H — "n_added n_power_changed n_removed" from node N's
# cometbft ValidatorUpdates INFO line for boundary H
# (nodus_witness_cmt_app.c:2655-2658), empty when absent.
vu_line() {
    local line
    line=$(grep -m1 "epoch boundary height $2 .*validator_updates n_added=" "$(node_log "$1")" 2>/dev/null || true)
    if [[ $line =~ n_added=([0-9]+)\ n_power_changed=([0-9]+)\ n_removed=([0-9]+) ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
    fi
}

# vset_switch H — v2_blocks.vset_hash is the Comet header's NEXT-
# validators hash (nodus_witness_cmt_app.c:2356-2364): block h commits to
# the set validating h+1. With cometbft's two-height lag: vset(H−1) =
# vset(H) = old, vset(H+1) = vset(H+2) = new. Asserted exactly, and the
# H+1 value identical on all TOTAL nodes. Callers have waited for every
# node to reach H+2.
vset_at() { sqlite3 "$SDB" "SELECT hex(vset_hash) FROM v2_blocks WHERE global_height=$1;"; }
vset_switch() {
    local h="$1" vm v0 v1 v2
    vm=$(vset_at $(( h - 1 ))); v0=$(vset_at "$h")
    v1=$(vset_at $(( h + 1 ))); v2=$(vset_at $(( h + 2 )))
    [ -n "$vm" ] && [ -n "$v0" ] && [ -n "$v1" ] && [ -n "$v2" ] || die "vset_hash missing around boundary $h"
    [ "$vm" = "$v0" ] || die "the header next-validators hash changed already at $h — cometbft's two-height lag says H+1 is still validated by the previous set"
    [ "$v0" != "$v1" ] || die "the header next-validators hash is UNCHANGED at $(( h + 1 )) — the snapshot moved but cometbft's voting set for $(( h + 2 )) did not"
    [ "$v1" = "$v2" ] || die "the header next-validators hash moved again at $(( h + 2 )) — expected one change per boundary"
    assert_same "header next-validators hash at $(( h + 1 ))" \
        "SELECT hex(vset_hash) FROM v2_blocks WHERE global_height=$(( h + 1 ));" $(seq 1 "$TOTAL") >/dev/null
}

# frozen_copy_check EPOCH — per-validator totals in copy(EPOCH)
# (v2_balance_copy, nodus_witness_v2_econ.c:415) as "count|distinct|min".
frozen_copy_check() {
    sqlite3 "$SDB" "SELECT COUNT(*)||'|'||COUNT(DISTINCT s)||'|'||COALESCE(MIN(s),0) FROM
        (SELECT validator_fp, SUM(amount) AS s FROM v2_balance_copy WHERE epoch_start=$1 GROUP BY validator_fp);"
}
in_copy() {   # N EPOCH → the node's frozen total in copy(EPOCH), 0 absent
    sqlite3 "$SDB" "SELECT COALESCE(SUM(amount),0) FROM v2_balance_copy WHERE epoch_start=$2
        AND lower(hex(validator_fp))=lower('$(node_fp "$1")');"
}
snap_count() { sqlite3 "$SDB" "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$1;"; }

echo "══ Comet committee growth $C → $TOTAL without a vote; 22 live / 21 halt / 22 live at N=$TOTAL ══"
stagef_cmt_diff_at_floor "pre-v2-grow32" || exit 2

# ════════════════════════════════════════════════════════════════════
# STEP 1a — the 25 candidates come up as nodes from the network file
# ════════════════════════════════════════════════════════════════════
CHAIN_ID=$(cat "$BASE_DIR/v2_chain_id")
for i in $(seq 1 "$NCAND"); do
    n=$(( C + i )); d=$(node_dir "$n")
    # The genesis is a pure function of the config (stagef_up_v2.sh step 3):
    # derive it locally, exactly as the seven did, and CHECK it is the fleet's.
    if ! "$NODUS" --derive-v2-genesis "$CONF" -d "$d/data" > "$d/derive.log" 2> "$d/derive.err"; then
        cat "$d/derive.log" "$d/derive.err" >&2; die "cand$i's genesis derivation was refused"
    fi
    cid=$(awk '/^chain-id/{print $2}' "$d/derive.log")
    [ "$cid" = "$CHAIN_ID" ] || die "cand$i derived chain $cid, the fleet is $CHAIN_ID"
    start_node "$n"
done
for i in $(seq 1 "$NCAND"); do
    wait_listening $(( C + i )); wait_role_live $(( C + i ))
    # The p2p host's start line names how many persistent peers it was
    # given (nodus_witness_p2p.c:2582) — the network file lists the $C
    # genesis nodes. Config evidence (the stagef_up_v2.sh check); that
    # the mesh FORMED is the catch-up below.
    if ! grep -q "p2p on .* $C persistent peer(s)" "$(node_log $(( C + i )))"; then
        grep -E 'p2p on|network file' "$(node_log $(( C + i )))" >&2 || true
        die "cand$i did not start its 4004 host with the network file's $C persistent peers"
    fi
done
ok "STEP 1a — $NCAND candidates derived the fleet's chain ($CHAIN_ID), are LIVE and started with the network file's $C persistent peers"
fleet=$(tip)
wait_all_reach "$fleet" 8 $(seq $(( C + 1 )) "$TOTAL")
ok "STEP 1a — all $NCAND candidates caught up to the fleet tip $fleet over the 4004 p2p port"

# ════════════════════════════════════════════════════════════════════
# STEP 1b — each candidate claims its leaf and bonds
# ════════════════════════════════════════════════════════════════════
t0=$(tip)
for i in $(seq 1 "$NCAND"); do
    n=$(( C + i ))
    isval=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$(node_pkhex "$n")';")
    [ "$isval" = 0 ] || die "cand$i is ALREADY a validator — it cannot demonstrate becoming one"
    crc=0
    "$CLI" -s 127.0.0.1 -p "$PORT1" v2-claim --config "$CONF" --db "$SDB" \
        --keys "$(node_dir "$n")/identity" --submit "127.0.0.1:$PORT1" \
        > "$BASE_DIR/grow32_claim_$i.log" 2>&1 || crc=$?
    [ "$crc" = 0 ] || { cat "$BASE_DIR/grow32_claim_$i.log" >&2; die "cand$i's claim was not admitted (v2-claim rc=$crc)"; }
done
ok "$NCAND candidate claims CheckTx-approved (admission only — inclusion next)"
for i in $(seq 1 "$NCAND"); do
    n=$(( C + i )); fp=$(node_fp "$n")
    h=$(stagef_cmt_wait_row "$SDB" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner='$fp' AND token_id=zeroblob(64) AND amount > 0;" 3) \
        && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "cand$i's claimed coin never appeared and the chain STALLED at $h" ;;
        *) die "cand$i's claim was not included within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
done
ok "all $NCAND claimed coins are on the chain (tip $t0 -> $(tip))"

for i in $(seq 1 "$NCAND"); do
    n=$(( C + i )); k="$(node_dir "$n")/identity"
    src=0
    # P2P-PORT F6 (K3): no --db — the stake builder reads chain id, coins,
    # tip and gas price from node 1 over the candidate's own session.
    "$CLI" -s 127.0.0.1 -p "$PORT1" v2-envelope stake --keys "$k" \
        --bond "$BOND" --commission "$COMMISSION" --dest-fp "$(node_fp "$n")" \
        --submit "127.0.0.1:$PORT1" > "$BASE_DIR/grow32_stake_$i.log" 2>&1 || src=$?
    [ "$src" = 0 ] || { cat "$BASE_DIR/grow32_stake_$i.log" >&2; die "cand$i's stake was not admitted (rc=$src)"; }
done
ok "$NCAND stake envelopes CheckTx-approved (admission only — inclusion next)"
for i in $(seq 1 "$NCAND"); do
    n=$(( C + i ))
    h=$(stagef_cmt_wait_row "$SDB" \
        "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$(node_pkhex "$n")';" 3) \
        && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "cand$i's validator row never appeared and the chain STALLED at $h" ;;
        *) die "cand$i's bond was not included within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
done
vrow=$(sqlite3 "$SDB" "SELECT COUNT(*)||'|'||COUNT(DISTINCT self_stake)||'|'||MIN(self_stake)||'|'||
        (SUM(total_delegated)+SUM(external_delegated)) FROM validators;")
[ "$vrow" = "$TOTAL|1|$BOND|0" ] || die "validators table is not $TOTAL equal bonds with no delegation: count|distinct|min|delegated = $vrow"
POWER=$(( BOND / DU ))
ok "STEP 1b — $NCAND strangers bonded: $TOTAL validator rows, every self_stake $BOND, no delegation (power $POWER each)"

e_now=$(( $(tip) / E * E ))
c_now=$(snap_count "$e_now")
[ "$c_now" = "$C" ] || die "the live epoch's committee changed on bonding alone (epoch $e_now count=$c_now)"
ok "STEP 1b — the live committee (epoch $e_now) is still $C: bonding is not membership"

# ── the growth epoch, from what actually landed ─────────────────────
# first-eligible(a) = ceil(a/E)·E + 2E (header, GROUNDING); E_ALL = max.
declare -A FE
A_MIN=""; A_MAX=""; E_ALL=0
for i in $(seq 1 "$NCAND"); do
    as=$(sqlite3 "$SDB" "SELECT active_since_block FROM validators WHERE lower(hex(pubkey))='$(node_pkhex $(( C + i )))';")
    case "$as" in ''|*[!0-9]*|0) die "cannot read cand$i's active_since_block ('$as')" ;; esac
    if [ -z "$A_MIN" ] || [ "$as" -lt "$A_MIN" ]; then A_MIN="$as"; fi
    if [ -z "$A_MAX" ] || [ "$as" -gt "$A_MAX" ]; then A_MAX="$as"; fi
    FE[$i]=$(( ((as + E - 1) / E) * E + 2 * E ))
    if [ "${FE[$i]}" -gt "$E_ALL" ]; then E_ALL="${FE[$i]}"; fi
done
E_PREV=$(( E_ALL - E ))
COPY_ALL=$(( E_ALL - 2 * E ))
early=0
for i in $(seq 1 "$NCAND"); do
    if [ "${FE[$i]}" -le "$E_PREV" ]; then early=$(( early + 1 )); fi
done
PREV_EXPECT=$(( C + early ))
ok "bonds landed at heights $A_MIN..$A_MAX → all $NCAND first eligible at epoch $E_ALL (copy($COPY_ALL)); $early already at $E_PREV, so snapshot($E_PREV) must seat $PREV_EXPECT"

N_NEED=$(need_signers "$TOTAL" "$POWER")
STOP_A=$(( TOTAL - N_NEED ))
WINDOW=$(( N_NEED + 1 ))
[ "$N_NEED" = 22 ] && [ "$STOP_A" = 10 ] || \
    die "at N=$TOTAL power $POWER cometbft needs $N_NEED signers ($STOP_A may stop) — this scenario is written for 22 / 10 (harness arithmetic)"
[ $(( WINDOW + 7 )) -le "$E" ] || die "pigeonhole window $WINDOW + 7 > E=$E (see the Rule N note in the header)"
info "quorum: N=$TOTAL needs $N_NEED signers ($STOP_A may stop, $(( STOP_A + 1 )) halt); pigeonhole window $WINDOW"

# ════════════════════════════════════════════════════════════════════
# STEP 2 — growth to 32 at E_ALL, in the snapshot AND in cometbft's set
# ════════════════════════════════════════════════════════════════════
# 2a — at E_PREV + 1 boundary E_PREV has run. E_ALL is ranked by
# copy(COPY_ALL), written at boundary COPY_ALL and still retained (a
# boundary B prunes only below B − 2E, nodus_witness_v2_econ.c step 4);
# snapshot(E_PREV) was stored at boundary COPY_ALL, snapshot(E_ALL) at
# boundary E_PREV (commit_next, nodus_witness_vset.c:696-708).
h=$(stagef_cmt_advance_to "$SDB" $(( E_PREV + 1 )) 4) || die "could not reach $(( E_PREV + 1 )) (stuck at $h)"
wait_all_reach $(( E_PREV + 1 )) 4
for i in $(seq 1 "$NCAND"); do
    [ "$(in_copy $(( C + i )) "$COPY_ALL")" = "$BOND" ] || \
        die "cand$i's bond is not in the frozen copy($COPY_ALL) — the first-eligible arithmetic above is wrong (harness arithmetic, read the grounding)"
done
cp=$(frozen_copy_check "$COPY_ALL")
[ "$cp" = "$TOTAL|1|$BOND" ] || die "copy($COPY_ALL) is not $TOTAL equal totals of $BOND: count|distinct|min = $cp"
prev=$(assert_same "epoch $E_PREV snapshot count" \
    "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$E_PREV;" $(seq 1 "$TOTAL"))
[ "$prev" = "$PREV_EXPECT" ] || die "epoch $E_PREV seats $prev, the derivation says $PREV_EXPECT — tenure/copy did not gate the way the header reads the source"
[ "$prev" -lt "$TOTAL" ] || die "epoch $E_PREV already seats $TOTAL — E_ALL=$E_ALL is not the growth boundary (harness arithmetic)"
ok "STEP 2a — copy($COPY_ALL) holds $TOTAL equal totals of $BOND; epoch $E_PREV seats $prev on all $TOTAL nodes (not yet $TOTAL)"

h=$(stagef_cmt_advance_to "$SDB" $(( E_ALL + 2 )) 6) || die "the chain did not reach $(( E_ALL + 2 )) after the $TOTAL-set took over (stuck at $h)"
wait_all_reach $(( E_ALL + 2 )) 4
grown=$(assert_same "epoch $E_ALL snapshot count" \
    "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$E_ALL;" $(seq 1 "$TOTAL"))
[ "$grown" = "$TOTAL" ] || die "epoch $E_ALL seats $grown, expected EXACTLY $TOTAL (default target $V2_SET_MAX, $TOTAL eligible, no vote)"
assert_same "epoch $E_ALL snapshot hash" \
    "SELECT hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$E_ALL;" $(seq 1 "$TOTAL") >/dev/null
ccrows=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM chain_config_history WHERE param_id=4;")
[ "$ccrows" = 0 ] || die "a TARGET_ACTIVE_COUNT row exists ($ccrows) — the growth would not be the default's"
vu=$(vu_line 1 "$E_ALL")
[ -n "$vu" ] || die "node1 logged no cometbft ValidatorUpdates line for boundary $E_ALL"
for n in $(seq 2 "$TOTAL"); do
    [ "$(vu_line "$n" "$E_ALL")" = "$vu" ] || die "node $n's ValidatorUpdates line at $E_ALL ($(vu_line "$n" "$E_ALL")) differs from node1's ($vu)"
done
read -r addA pcA remA <<< "$vu"
[ "$addA" = $(( TOTAL - prev )) ] && [ "$remA" = 0 ] || \
    die "cometbft's update at $E_ALL (added $addA, removed $remA) does not take $prev to $TOTAL"
vset_switch "$E_ALL"
stagef_sentinel TARGET_REACHED
ok "STEP 2 — epoch $E_ALL: $TOTAL seats (no vote — default target), count + hash identical on $TOTAL nodes; cometbft added $addA, removed 0 (power changes $pcA) identically on $TOTAL; next-validators hash switched at $(( E_ALL + 1 ))"
agree_at_floor "STEP 2 — after growth"

# ════════════════════════════════════════════════════════════════════
# STEP 3 — 22 of 32 running: the chain commits (positive control)
# ════════════════════════════════════════════════════════════════════
declare -A VID
for n in $(seq 1 "$TOTAL"); do
    VID[$n]=$(stagef_voter_id "$(node_pk "$n")")
    [ "${#VID[$n]}" = 64 ] || die "could not derive node $n's voter_id"
done
last_signed() {
    sqlite3 "$SDB" "SELECT COALESCE(MAX(last_signed_height),-1) FROM v2_attendance WHERE lower(hex(voter_id))='${VID[$1]}';"
}
# The ten: genesis 2..C (if cometbft's set were still the genesis 7, the
# chain could not commit without them) + the LAST (STOP_A − (C−1))
# candidates. Node 1 (reference DB, pump submit node) never stops.
STOP_SET=($(seq 2 "$C"))
for n in $(seq $(( TOTAL - (STOP_A - (C - 1)) + 1 )) "$TOTAL"); do STOP_SET+=("$n"); done
[ "${#STOP_SET[@]}" = "$STOP_A" ] || die "harness arithmetic: stop set has ${#STOP_SET[@]} nodes, not $STOP_A"
V11=$(( TOTAL - (STOP_A - (C - 1)) ))      # cand21: the 11th
RUNNING=(1)
for n in $(seq $(( C + 1 )) $(( V11 ))); do RUNNING+=("$n"); done
[ "${#RUNNING[@]}" = "$N_NEED" ] || die "harness arithmetic: ${#RUNNING[@]} running, not $N_NEED"

# Align to a fresh epoch start (Rule N — see the header), then stop the ten.
b=$(( ($(tip) / E + 1) * E ))
h=$(stagef_cmt_advance_to "$SDB" "$b" 4) || die "could not reach the aligned boundary $b (stuck at $h)"
for n in "${STOP_SET[@]}"; do sigstop_node "$n"; done
tip_stop=$(tip)
ok "STEP 3 — nodes ${STOP_SET[*]} SIGSTOPped at tip $tip_stop (boundary $b): $N_NEED of $TOTAL running, cometbft needs $N_NEED"

settle=$(( tip_stop + 3 ))   # one-block credit lag (test_cmt_dead_proposer.sh SETTLE)
h=$(stagef_cmt_advance_to "$SDB" "$settle" 6) || \
    step_fail "STEP 3 (22 live, positive control)" "with $STOP_A of $TOTAL stopped the chain did NOT reach $settle (stuck at $h) — $N_NEED is exactly cometbft's majority and it must commit; read the node logs for round timeouts and the CPU column above before calling this a quorum defect"
declare -A FROZEN
for n in "${STOP_SET[@]}"; do FROZEN[$n]=$(last_signed "$n"); done
target=$(( tip_stop + WINDOW ))
h=$(stagef_cmt_advance_to "$SDB" "$target" 6) || \
    step_fail "STEP 3 (22 live, positive control)" "the chain did not reach $target with $STOP_A stopped (stuck at $h)"
for n in "${STOP_SET[@]}"; do
    [ "$(last_signed "$n")" = "${FROZEN[$n]}" ] || \
        step_fail "STEP 3 (22 live)" "stopped node $n's attendance MOVED after the settle point (${FROZEN[$n]} -> $(last_signed "$n"))"
done
for n in "${RUNNING[@]}"; do
    ls_n=$(last_signed "$n")
    [ "$ls_n" -gt "$settle" ] || \
        step_fail "STEP 3 (22 live)" "running node $n's attendance did not move past $settle ($ls_n) — at exact majority every running validator's precommit is required, so its absence means the voting set is not what this scenario thinks"
done
ok "STEP 3 — $STOP_A of $TOTAL stopped: tip $tip_stop -> $h (>= $WINDOW heights, a stopped round-0 proposer by pigeonhole); the $STOP_A signed nothing, all $N_NEED running signed"

# ════════════════════════════════════════════════════════════════════
# STEP 4 — 21 of 32: NO height with a spend pending (the expected halt)
# ════════════════════════════════════════════════════════════════════
sigstop_node "$V11"
tip_b=$(tip)
keys=$(stagef_pump_keys); pfp=$(cat "$keys/nodus.fp")
amt=$(stagef_pump_largest "$SDB")
[ "$amt" -gt "$STAGEF_PUMP_FEE_RAW" ] || step_fail "STEP 4 (21 halt)" "the pump funder holds no coin above the fee; nothing could be submitted, a halt would be untested"
# One pump step's spend (the same CLI line as stagef_env.sh
# stagef_cmt_pump_to), submitted WITHOUT waiting — its inclusion is the
# subject.
out=$("$CLI" -s 127.0.0.1 -p "$PORT1" v2-envelope spend --keys "$keys" --to "$pfp" \
        --amount "$(( amt - STAGEF_PUMP_FEE_RAW ))" --fee "$STAGEF_PUMP_FEE_RAW" \
        --submit "127.0.0.1:$PORT1" 2>&1) || { printf '%s\n' "$out" >&2; step_fail "STEP 4 (21 halt)" "the probe spend was not admitted by node 1's CheckTx; a halt would be untested"; }
intent=$(awk -F= '/^  intent_id=/ && !d {print $2; d=1}' <<< "$out")
[ "${#intent}" = 128 ] || { printf '%s\n' "$out" >&2; step_fail "STEP 4 (21 halt)" "the probe spend printed no intent_id"; }
stall_at=$(stagef_cmt_wait_row "$SDB" "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash))='$intent';" 3) \
    && src=0 || src=$?
case "$src" in
    1) ;;
    0) step_fail "STEP 4 (21 halt)" "with $(( STOP_A + 1 )) of $TOTAL stopped the chain COMMITTED the probe spend (tip $stall_at) — $(( N_NEED - 1 )) signers are below cometbft's majority $N_NEED" ;;
    *) step_fail "STEP 4 (21 halt)" "the chain kept committing (tip $tip_b -> $stall_at) with $(( STOP_A + 1 )) of $TOTAL stopped" ;;
esac
[ "$stall_at" -le $(( tip_b + 2 )) ] || \
    step_fail "STEP 4 (21 halt)" "the tip moved $tip_b -> $stall_at after the 11th stop: more than the 2-height in-flight allowance"
ok "STEP 4 — $(( STOP_A + 1 )) of $TOTAL stopped: NO height for 3 consecutive intervals with a CheckTx-approved spend pending (tip $tip_b -> $stall_at) — the expected safety halt"

# ════════════════════════════════════════════════════════════════════
# STEP 5 — back to 22: the SAME spend lands, the chain goes on
# ════════════════════════════════════════════════════════════════════
resume_one "$V11"
h=$(stagef_cmt_wait_row "$SDB" "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash))='$intent';" 6) \
    && rrc=0 || rrc=$?
[ "$rrc" = 0 ] || step_fail "STEP 5 (22 live again)" "after resuming node $V11 alone the pending spend did not land (wait rc=$rrc, tip $h) — the chain did not recover at $N_NEED of $TOTAL"
rec_h=$(sqlite3 "$SDB" "SELECT block_height FROM utxo_set WHERE lower(hex(tx_hash))='$intent' LIMIT 1;")
adv=$(( $(tip) + 3 ))
h=$(stagef_cmt_advance_to "$SDB" "$adv" 6) || \
    step_fail "STEP 5 (22 live again)" "the chain did not keep committing at $N_NEED of $TOTAL after the spend landed (stuck at $h, wanted $adv)"
for n in "${STOP_SET[@]}"; do
    [ "$(last_signed "$n")" = "${FROZEN[$n]}" ] || \
        step_fail "STEP 5 (22 live again)" "still-stopped node $n's attendance MOVED (${FROZEN[$n]} -> $(last_signed "$n")) — the recovery was not at $N_NEED"
done
ok "STEP 5 — node $V11 alone resumed: the pending spend landed at $rec_h and the chain reached $h with the other $STOP_A still stopped"
resume_stopped
h=$(tip)
wait_all_reach "$h" 4
stagef_cmt_diff_at_floor "post-liveness (genesis 7)" || exit 2
agree_at_floor "STEP 5 — all resumed"
ok "STEP 5 — the other $STOP_A resumed: all $TOTAL nodes agree"

# ════════════════════════════════════════════════════════════════════
# TERMINAL — past the boundary that could retire a STEP-3 validator,
# nobody is AUTO_RETIRED, the set is still 32, all agree
# ════════════════════════════════════════════════════════════════════
rn=$(( b + 2 * E + 1 ))
h=$(stagef_cmt_advance_to "$SDB" "$rn" 4) || die "could not reach $rn, past the second Rule N boundary after the stop (stuck at $h)"
wait_all_reach "$rn" 4
retired=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM validators WHERE status=3;")
if [ "$retired" != 0 ]; then
    sqlite3 "$SDB" "SELECT lower(hex(substr(pubkey,1,8)))||' status='||status||' missed='||consecutive_missed_epochs FROM validators WHERE status=3;" >&2 || true
    die "$retired validator(s) AUTO_RETIRED by boundary $(( b + 2 * E )) — the Rule N alignment premise of STEP 3 failed (resume/catch-up lag first)"
fi
missed=$(sqlite3 "$SDB" "SELECT COALESCE(MAX(consecutive_missed_epochs),0) FROM validators;")
last_c=$(assert_same "latest snapshot count" \
    "SELECT active_count FROM validator_set_snapshots ORDER BY epoch_start DESC LIMIT 1;" $(seq 1 "$TOTAL"))
[ "$last_c" = "$TOTAL" ] || die "the latest snapshot seats $last_c, not $TOTAL"
ok "TERMINAL — past boundary $(( b + 2 * E )): no validator AUTO_RETIRED (max consecutive_missed_epochs now $missed), latest snapshot seats $last_c on all $TOTAL nodes"
h=$(tip)
wait_all_reach "$h" 4
stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-v2-grow32 (genesis 7)" || exit 2
agree_at_floor "post-v2-grow32 (all $TOTAL)"

stagef_sentinel PASS
echo
echo "[PASS] a Comet committee grew $C → $TOTAL with no vote (boundary $E_ALL, bonds at $A_MIN..$A_MAX),"
echo "       cometbft's own set followed, and at N=$TOTAL with equal power the chain committed"
echo "       with $N_NEED running, halted with $(( N_NEED - 1 )) and a spend pending, and landed that SAME"
echo "       spend (height $rec_h) once the ${N_NEED}nd validator came back; all $TOTAL agree."
echo "       Parameters: DNAC_EPOCH_LENGTH=$E (the ceremony refuses a config whose epoch"
echo "       length disagrees with the binary). This proves the LOGIC at that constant and"
echo "       nothing about the production 720."
exit 0
