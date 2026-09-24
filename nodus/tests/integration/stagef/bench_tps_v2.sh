#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# bench_tps_v2.sh — sustained CORE SPEND throughput on the version-3
# (cometbft) chain, at TODAY's consensus constants
# ════════════════════════════════════════════════════════════════════
#
# A STANDALONE BENCH, NOT A SWEEP SCENARIO. It is not in
# genesis_protocol_v2.sh and must never be: it asserts no property, it
# MEASURES one. Its only pass/fail verdicts are "the load ran without a
# worker fault" and the closing 7/7 agreement check.
#
# WHAT IT MEASURES
#   How many real CORE SPEND envelopes per second the 7-node localhost
#   cluster commits while M parallel client sessions keep its mempool fed
#   for D seconds. The load is `nodus-cli v2-envelope spend --amount all
#   --count all --shard I/M`: worker I (0 <= I < M) owns the PUMP
#   identity's coins whose nullifier falls in shard I, self-sends every
#   one it can see (each coin's whole value minus the fee — 1 input, 1
#   output, no change), waits until every accepted spend's created
#   `utxo_set` row (tx_hash = the envelope's intent_id,
#   nodus_witness_rt_native.c rtn_utxo_create_eff :1505) exists on the
#   node it submits to, then repeats. The shard is a property of the COIN
#   (first 8 nullifier bytes mod M) and the CLI re-draws every output
#   seed until the new coin lands in the same shard, so the M sessions
#   can never select the same coin (nodus-cli.c cmd_v2_spend's header).
#   Worker I submits to, lists on and confirms on node (I mod 7) + 1 —
#   ONE replica per worker, so its next listing always reflects the spends
#   it just confirmed (the STAGEF_PUMP_SUBMIT_NODE README row: a lagging
#   submit node re-spends an already-spent coin).
#   While the load runs, the parent polls node 1's `v2_blocks` about once
#   a second and records, per new height, its first-seen wall time and
#   `tx_count` (applied envelopes); it reads every node's nodus-server
#   CPU time (utime+stime, /proc/<pid>/stat) at load start and load end.
#   Reported (stdout and $BASE_DIR/bench/summary.txt, per-block rows in
#   $BASE_DIR/bench/blocks.csv): committed envelopes in the window,
#   window seconds (first to last block observed inside the load window),
#   TPS, blocks, mean / max / p50 envelopes per block, mean / max
#   harness-observed block interval, CPU% per node, per-worker submitted
#   / accepted / refused / dropped / applied / idle rounds, and the
#   theoretical per-block cap floor(NODUS_V2_GLOBAL_UNIT_BUDGET / the
#   res_max_total_units the CLI declared) next to the measured max.
#   Ends with stagef_cmt_diff_at_floor "post-bench-tps".
#
# WHAT IT REQUIRES
#   Compile flags: none beyond a default build — nodus-server AND
#   nodus-cli from the SAME tree (the CLI takes the CORE ruleset from its
#   own compiled table, and the bench reads NODUS_V2_GLOBAL_UNIT_BUDGET
#   from this tree's nodus_witness_v2_apply.h — a binary built from
#   another tree makes the printed cap wrong).
#   Environment:
#     STAGEF_V2_PUMP_LEAVES=<N>  exported BEFORE stagef_up_v2.sh (it is
#                                part of the genesis document). Suggested
#                                400; the script default is 40. See "HOW
#                                IT CAN LIE" on the 100-row listing cap.
#     STAGEF_BENCH_WORKERS       M, default 7 = one per node, max 7: a
#                                node evicts an older session of the
#                                same identity (SESSION_EVICT), so two
#                                workers on one node kill each other.
#     STAGEF_BENCH_DURATION_S    D, default 600 — how long workers START
#                                new rounds. A load length, never a
#                                correctness bound: every wait inside is
#                                progress-bounded (below).
#   A fresh cluster from stagef_up_v2.sh (not a Comet cluster, or no pump
#   identity → rc 99). The PUMP batch is claimed here in ONE v2-claim call
#   if it is not claimed yet (v2-claim rc 2 "all already claimed" is
#   accepted, e.g. after test_cmt_claim_flood.sh).
#
# WHAT IT LEAVES BEHIND
#   The PUMP identity's whole batch claimed; every coin it spent replaced
#   by one coin STAGEF_PUMP_FEE_RAW smaller (coin count unchanged, fees
#   in the reward pool). The chain many blocks further on. Nothing is
#   killed or restarted. $BASE_DIR/bench/ holds blocks.csv, summary.txt
#   and one worker_<I>.log / worker_<I>.stats per worker. A worker still
#   running when the bench aborts is killed; a nodus-cli it had started
#   finishes on its own.
#
# HOW IT CAN LIE
#   - **1 s timing granularity.** Block times are the harness's FIRST
#     SIGHTING of each height on node 1, polled once a second — not the
#     header's BFT time (v2_blocks carries no timestamp column; the
#     header lives in opaque cmt_blockstore blobs). Two heights seen in
#     one poll get a 0 s interval. TPS over a 600 s window is good to
#     about ±1 s / window; single intervals are not.
#   - **One machine, seven nodes, plus the clients.** Every nodus-server
#     and every nodus-cli share this machine's cores; CPU% per node is
#     printed so contention is visible, but the TPS is this machine's,
#     not a network's.
#   - **Localhost: no network latency, no bandwidth limit.** Gossip and
#     consensus messages cross loopback. A real deployment is slower.
#   - **CLIENT PACING.** If the measured max envelopes per block is BELOW
#     the unit cap, no block was full and the CLIENTS were the
#     bottleneck — the TPS is then a floor on the chain's capacity, not
#     its ceiling, and the summary says so in as many words. Causes: each
#     round pays a fresh session (Kyber1024 handshake + auth) plus a 1 s
#     confirmation poll, and a worker never has more than its share of
#     the listing in flight.
#   - **The 100-row listing cap bounds what is in flight.** dnac_utxo
#     returns at most NODUS_DNAC_MAX_UTXO_RESULTS = 100 rows with no
#     ORDER BY before its LIMIT (nodus_witness_db.c
#     nodus_witness_utxo_by_owner). Every worker lists the SAME identity,
#     so ALL workers together see at most 100 coins per listing, and a
#     worker sees only the part of those 100 that falls in its shard.
#     Leaves beyond 100 are a reserve that rotates into view as spent
#     coins are replaced; they do not raise the in-flight bound.
#     (Which 100 rows come back is SQLite's plan choice, not a documented
#     order — JUDGMENT, not verified with EXPLAIN on a live DB.) A worker
#     whose shard has nothing visible does an IDLE round — it waits for
#     one new height and lists again; idle rounds are counted per worker.
#   - **Today's unit budget only.** The per-block cap is
#     NODUS_V2_GLOBAL_UNIT_BUDGET (1 000 000, nodus_witness_v2_apply.h:292)
#     / the CLI's right-sized ceiling (t6_spend_ceiling). A different
#     budget, metering weight, auth size or ceiling rule is a different
#     cap and a different result. Other block bounds (Block.MaxBytes,
#     NODUS_V2_ENV_BATCH_MAX) are far above this load and are not
#     reported; if one ever bound first, the "cap" line would be wrong.
#   - **The fencepost.** TPS = envelopes in window blocks 2..n / (first-
#     seen(n) − first-seen(1)): block 1's envelopes accumulated BEFORE the
#     window opened, so they are excluded from the rate (printed in the
#     envelope total). Ramp-up (the first round's session setup) is
#     inside the window; blocks first seen after D (the last rounds'
#     tail) are in blocks.csv with in_window=0 and outside the rate.
#   - **Refused and dropped spends are COUNTED, never retried silently.**
#     A refused spend's coin (CheckTx said no) and a dropped spend's coin
#     (CheckTx said yes, not applied within 20 heights) stay unspent in
#     the worker's shard and are listed again in its next round — each
#     occurrence is counted again. A round whose FIRST spend is refused
#     (nothing in flight) waits for one new height before listing again,
#     counted as an idle round, so a refusal cannot spin the worker.
#     A drop is not distinguished from a
#     spend that lands after the 20-height budget (the stagef_cmt_wait_row
#     residual every Comet scenario discloses); a late landing makes the
#     worker's next spend of that coin a refusal or a drop, also counted.
#   - **The inclusion wait is an INLINE copy of stagef_cmt_wait_row's
#     rules** (stall = 3 × 60 s with the node's tip not moving → the
#     worker FAILS and the bench aborts; budget = 20 heights past the
#     submission tip → the missing spends are counted as dropped), polled
#     every second so a worker does not idle 5 s per round. If the
#     helper's rules change, this loop must change with it.
#   - **tx_count counts applied ENVELOPES of anyone.** On a fresh bench
#     cluster the pump identity is the only submitter; a claim or a
#     payday coin is never an envelope. The summary prints the workers'
#     own applied total next to Σ tx_count so a stray submitter shows.
#   - rc 99 = not a Comet cluster / no pump identity: nothing measured.
#
# Exit: 0 load ran + 7/7 agree · 1 setup or worker fault · 2 divergence
#       · 99 skip.
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/stagef_env.sh"

REF=1
C="$STAGEF_COMMITTEE_SIZE"
CONF="$BASE_DIR/v2_genesis.conf"
PUMP="$BASE_DIR/v2pump/identity"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
M="${STAGEF_BENCH_WORKERS:-$STAGEF_COMMITTEE_SIZE}"
D="${STAGEF_BENCH_DURATION_S:-600}"
FEE="$STAGEF_PUMP_FEE_RAW"
MAX_HEIGHTS=20                                   # stagef_cmt_wait_row's default
STALL_POLLS=$(( 3 * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))   # 3 intervals @ 1 s
APPLY_H="$STAGEF_REPO_ROOT/nodus/src/witness/nodus_witness_v2_apply.h"

die() { echo "[FAIL] $*" >&2; exit 1; }

case "$M" in ''|*[!0-9]*) die "STAGEF_BENCH_WORKERS must be an integer 1..100 (got '$M')" ;; esac
case "$D" in ''|*[!0-9]*) die "STAGEF_BENCH_DURATION_S must be a positive integer (got '$D')" ;; esac
[ "$M" -ge 1 ] && [ "$M" -le 100 ] || die "STAGEF_BENCH_WORKERS must be 1..100 (the CLI's --shard bound)"
# ONE worker per node, at most: a node keeps ONE client session per
# (IP, identity) and EVICTS the older one when the same identity
# connects again (node log "SESSION_EVICT: old slot=… replaced by new
# slot=…"). Two workers of the PUMP identity on one node kill each
# other's handshake (MEASURED, first run at 0.19.69 with M=8: worker 0
# and worker 7 both on node1 -> "no response to KEY_INIT", ECONNRESET).
[ "$M" -le "$STAGEF_COMMITTEE_SIZE" ] || die "STAGEF_BENCH_WORKERS=$M > $STAGEF_COMMITTEE_SIZE nodes: two workers of one identity on one node evict each other's session (SESSION_EVICT) — use <= $STAGEF_COMMITTEE_SIZE"
[ "$D" -ge 1 ] || die "STAGEF_BENCH_DURATION_S must be >= 1"

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF (is a cluster up? BASE_DIR='$BASE_DIR')"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ] || [ ! -s "$PUMP/nodus.pk" ]; then
    echo "[SKIP] not a Comet cluster with a pump identity — use stagef_up_v2.sh"
    exit 99
fi
[ -x "$CLI" ] || die "no nodus-cli at $CLI"
[ -s "$BASE_DIR/pids.txt" ] || die "no $BASE_DIR/pids.txt"
BUDGET=$(awk '$1 == "#define" && $2 == "NODUS_V2_GLOBAL_UNIT_BUDGET" { v = $3; sub(/u$/, "", v); print v; exit }' "$APPLY_H" 2>/dev/null || true)
case "$BUDGET" in ''|*[!0-9]*) die "could not read NODUS_V2_GLOBAL_UNIT_BUDGET from $APPLY_H" ;; esac

BENCH_DIR="$BASE_DIR/bench"
mkdir -p "$BENCH_DIR"
rm -f "$BENCH_DIR"/worker_*.log "$BENCH_DIR"/worker_*.stats \
      "$BENCH_DIR"/blocks.csv "$BENCH_DIR"/summary.txt

pump_fp=$(cat "$PUMP/nodus.fp")
n_leaves=$(grep -c "^dest_binding = ${pump_fp}\$" "$CONF" || true)
[ "${n_leaves:-0}" -gt 0 ] || die "no pump leaves for $pump_fp in $CONF"
echo "[ok] pump identity: $n_leaves genesis leaves (STAGEF_V2_PUMP_LEAVES at bring-up)"
[ "$n_leaves" -ge "$M" ] || echo "[warn] fewer pump leaves ($n_leaves) than workers ($M) — some shards start empty"
[ "$n_leaves" -le 100 ] || echo "[info] $n_leaves leaves > the 100-row listing cap: at most 100 coins are visible to all workers together at a time (see HOW IT CAN LIE)"

stagef_cmt_diff_at_floor "pre-bench-tps" || exit 2

# ── (i) claim the whole batch in ONE call, wait for every coin ───────
claim_log="$BENCH_DIR/claim.log"
port=$(stagef_tcp_port "$REF")
crc=0
"$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$ref_db" \
    --keys "$PUMP" --submit "127.0.0.1:$port" > "$claim_log" 2>&1 || crc=$?
if [ "$crc" = 2 ]; then
    echo "[ok] the pump batch was already claimed (v2-claim rc 2) — using it as it stands"
elif [ "$crc" != 0 ]; then
    cat "$claim_log" >&2
    die "the pump batch claim failed (v2-claim rc $crc)"
else
    echo "[ok] pump batch submitted in one v2-claim call"
fi
h=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT (SELECT COUNT(*) FROM utxo_set WHERE owner = '$pump_fp'
               AND token_id = zeroblob(64) AND amount > $FEE
               AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks))
            >= $n_leaves;") && wrc=0 || wrc=$?
case "$wrc" in
    0) ;;
    1) die "the claimed pump coins never all appeared and the chain STALLED (tip $h)" ;;
    *) die "fewer than $n_leaves spendable pump coins above the fee on node$REF within $MAX_HEIGHTS heights (tip $h) — a claim was refused or dropped, or earlier use left coins at or below the fee" ;;
esac
echo "[ok] $n_leaves spendable pump coins on node$REF (tip $h)"
# every node a worker will list on must hold the same coins first
for n in $(seq 1 "$C"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$h" 3 >/dev/null \
        || die "node$n never reached height $h (replication stalled)"
done

# ── (ii) the workers ─────────────────────────────────────────────────
# wait_new_height DB START_H — progress-bounded wait for DB's tip to pass
# START_H (the stall rule of stagef_cmt_wait_row, 1 s poll). rc 0 / 1
# stalled. Used before re-listing after a round that put NOTHING in
# flight, so a worker never spins on the same listing.
wait_new_height() {
    local db="$1" start_h="$2" since=0 h
    while :; do
        h=$(stagef_cmt_tip "$db")
        [ "$h" -gt "$start_h" ] && return 0
        since=$(( since + 1 ))
        [ "$since" -lt "$STALL_POLLS" ] || return 1
        sleep 1
    done
}

# worker I: loop until LOAD_END; every round = one CLI session.
worker() {
    local I="$1" node port db log stats
    node=$(( I % C + 1 ))
    port=$(stagef_tcp_port "$node")
    db=$(stagef_node_chain_db "$node")
    log="$BENCH_DIR/worker_$I.log"
    stats="$BENCH_DIR/worker_$I.stats"
    local rounds=0 idle=0 submitted=0 accepted=0 refused=0 unsent=0
    local dropped=0 applied=0
    local out rc planned acc ref intents in_list start_h h last since n_app
    while [ "$(date +%s)" -lt "$LOAD_END" ]; do
        rounds=$(( rounds + 1 ))
        start_h=$(stagef_cmt_tip "$db")
        rc=0
        out=$("$CLI" -s 127.0.0.1 -p "$port" v2-envelope spend \
                --keys "$PUMP" --to "$pump_fp" --amount all --count all \
                --shard "$I/$M" --fee "$FEE" \
                --submit "127.0.0.1:$port" 2>&1) || rc=$?
        printf '── round %d (tip %s, rc %d)\n%s\n' "$rounds" "$start_h" "$rc" "$out" >> "$log"
        planned=$(printf '%s\n' "$out" | grep -c '^v2-envelope spend [0-9]*/[0-9]*:' || true)
        acc=$(printf '%s\n' "$out" | grep -c '^accepted: mempool CheckTx approved' || true)
        ref=$(printf '%s\n' "$out" | grep -c '^dnac_spend refused (status=' || true)
        if [ "$rc" != 0 ] && [ "$ref" != 1 ]; then
            echo "[FAIL] worker $I (node$node) round $rounds: nodus-cli rc $rc and no CheckTx refusal — a client/session fault:" >&2
            printf '%s\n' "$out" >&2
            exit 1
        fi
        if [ "$planned" = 0 ]; then
            # pure-bash match: `printf | grep -q` under pipefail can SIGPIPE
            # the writer on an early match (rc 141 — test_v2_rewards.sh's
            # measured trap, README)
            case "$out" in
                *"v2-envelope spend: 0 eligible coin"*) ;;
                *)
                    echo "[FAIL] worker $I round $rounds: no spend planned and no 'nothing to submit' line:" >&2
                    printf '%s\n' "$out" >&2
                    exit 1 ;;
            esac
            # IDLE round: nothing of this shard visible — wait for ONE new
            # height (progress-bounded) and list again.
            idle=$(( idle + 1 ))
            wait_new_height "$db" "$start_h" || {
                echo "[FAIL] worker $I: node$node's tip did not pass $start_h for $STALL_POLLS s during an idle round — chain STALLED" >&2
                exit 1
            }
            continue
        fi
        submitted=$(( submitted + acc + ref ))
        accepted=$(( accepted + acc ))
        refused=$(( refused + ref ))
        unsent=$(( unsent + planned - acc - ref ))
        if [ "$acc" = 0 ]; then
            # the FIRST spend was refused, nothing is in flight: counted
            # above; wait for one new height before listing again instead
            # of re-submitting the same coin in a tight loop
            idle=$(( idle + 1 ))
            wait_new_height "$db" "$start_h" || {
                echo "[FAIL] worker $I: node$node's tip did not pass $start_h for $STALL_POLLS s after a refused round — chain STALLED" >&2
                exit 1
            }
            continue
        fi
        # the accepted spends are the FIRST $acc printed (the CLI stops at
        # the first refusal) — awk reads everything, no SIGPIPE under pipefail
        intents=$(printf '%s\n' "$out" | awk -F= -v n="$acc" \
                  '/^  intent_id=/ { c++; if (c <= n) print $2 }')
        [ "$(printf '%s\n' "$intents" | grep -c '^[0-9a-f]\{128\}$' || true)" = "$acc" ] || {
            echo "[FAIL] worker $I round $rounds: $acc accepted but not $acc intent ids:" >&2
            printf '%s\n' "$out" >&2
            exit 1
        }
        # shellcheck disable=SC2086
        in_list=$(printf "'%s'," $intents)
        in_list="${in_list%,}"
        # INLINE stagef_cmt_wait_row rules, 1 s poll, on THIS worker's node
        last="$start_h"; since=0
        while :; do
            n_app=$(sqlite3 "$db" \
                "SELECT COUNT(DISTINCT tx_hash) FROM utxo_set WHERE lower(hex(tx_hash)) IN ($in_list);" \
                2>/dev/null || echo 0)
            case "$n_app" in ''|*[!0-9]*) n_app=0 ;; esac
            [ "$n_app" -ge "$acc" ] && break
            h=$(stagef_cmt_tip "$db")
            if [ "$h" -gt "$last" ]; then last="$h"; since=0
            else since=$(( since + 1 )); fi
            if [ "$since" -ge "$STALL_POLLS" ]; then
                echo "[FAIL] worker $I: $n_app of $acc spends applied and node$node's tip STALLED at $h" >&2
                exit 1
            fi
            if [ $(( h - start_h )) -gt "$MAX_HEIGHTS" ]; then
                echo "[warn] worker $I: $(( acc - n_app )) of $acc spends not applied within $MAX_HEIGHTS heights (tip $start_h -> $h) — counted as DROPPED" >&2
                dropped=$(( dropped + acc - n_app ))
                break
            fi
            sleep 1
        done
        applied=$(( applied + n_app ))
    done
    {
        echo "worker=$I"; echo "node=$node"; echo "rounds=$rounds"
        echo "idle_rounds=$idle"; echo "submitted=$submitted"
        echo "accepted=$accepted"; echo "refused=$refused"
        echo "unsent=$unsent"; echo "dropped=$dropped"; echo "applied=$applied"
    } > "$stats"
    exit 0
}

# CPU: utime+stime (fields 14+15) of every node, in clock ticks. The
# comm field may contain spaces, so parse after the LAST ')'.
node_pid() { sed -n "${1}p" "$BASE_DIR/pids.txt"; }
cpu_ticks() {
    local pid="$1" rest
    [ -r "/proc/$pid/stat" ] || { echo -1; return 0; }
    rest=$(cat "/proc/$pid/stat" 2>/dev/null) || { echo -1; return 0; }
    rest="${rest##*) }"
    # rest starts at field 3 (state): utime = its 12th word, stime 13th
    # shellcheck disable=SC2086
    set -- $rest
    echo $(( ${12} + ${13} ))
}
CLK_TCK=$(getconf CLK_TCK)

# ── (iii) start the load, sample while it runs ───────────────────────
csv="$BENCH_DIR/blocks.csv"
echo "height,first_seen_s,tx_count,in_window" > "$csv"
last_h=$(stagef_cmt_tip "$ref_db")
base_h="$last_h"
declare -a cpu0 wpids
for n in $(seq 1 "$C"); do cpu0[$n]=$(cpu_ticks "$(node_pid "$n")"); done
LOAD_START=$(date +%s)
LOAD_END=$(( LOAD_START + D ))
export LOAD_END
for I in $(seq 0 $(( M - 1 ))); do
    worker "$I" &
    wpids[$I]=$!
done
kill_workers() {
    local p
    for p in "${wpids[@]}"; do kill "$p" 2>/dev/null || true; done
}
trap kill_workers EXIT
echo "[ok] $M workers started at $LOAD_START for ${D}s (nodes: worker I -> node I mod $C + 1); base tip $base_h"

sample() {
    local now rows row bh tc inwin
    now=$(date +%s)
    rows=$(sqlite3 -readonly "$ref_db" \
        "SELECT global_height || ',' || tx_count FROM v2_blocks
          WHERE global_height > $last_h ORDER BY global_height;" 2>/dev/null || true)
    [ -n "$rows" ] || return 0
    while IFS=, read -r bh tc; do
        [ -n "$bh" ] || continue
        inwin=0; [ "$now" -le "$LOAD_END" ] && inwin=1
        echo "$bh,$now,$tc,$inwin" >> "$csv"
        last_h="$bh"
    done <<< "$rows"
}

cpu1_taken=0
declare -a cpu1
running="$M"
while [ "$running" -gt 0 ]; do
    sample
    if [ "$cpu1_taken" = 0 ] && [ "$(date +%s)" -ge "$LOAD_END" ]; then
        for n in $(seq 1 "$C"); do cpu1[$n]=$(cpu_ticks "$(node_pid "$n")"); done
        cpu1_taken=1
    fi
    running=0
    for I in $(seq 0 $(( M - 1 ))); do
        p="${wpids[$I]}"
        [ -n "$p" ] || continue
        if kill -0 "$p" 2>/dev/null; then running=$(( running + 1 )); continue; fi
        wrc=0; wait "$p" || wrc=$?
        wpids[$I]=""
        if [ "$wrc" != 0 ]; then
            kill_workers
            die "worker $I exited rc $wrc — the bench is ABORTED (see its message above and $BENCH_DIR/worker_$I.log); no partial result is reported"
        fi
    done
    [ "$running" -gt 0 ] && sleep 1
done
sample
if [ "$cpu1_taken" = 0 ]; then
    for n in $(seq 1 "$C"); do cpu1[$n]=$(cpu_ticks "$(node_pid "$n")"); done
fi
trap - EXIT
LOAD_DONE=$(date +%s)
CPU_WALL=$(( (cpu1_taken == 1 ? LOAD_END : LOAD_DONE) - LOAD_START ))
[ "$CPU_WALL" -ge 1 ] || CPU_WALL=1

# ── (iv) report ──────────────────────────────────────────────────────
sum_w() { awk -F= -v k="$1" '$1 == k { s += $2 } END { print s + 0 }' "$BENCH_DIR"/worker_*.stats; }
w_sub=$(sum_w submitted); w_acc=$(sum_w accepted); w_ref=$(sum_w refused)
w_uns=$(sum_w unsent);    w_drop=$(sum_w dropped); w_app=$(sum_w applied)
w_idle=$(sum_w idle_rounds); w_rounds=$(sum_w rounds)

units=$(cat "$BENCH_DIR"/worker_*.log 2>/dev/null | grep -o ' units=[0-9]*' | sort -u | awk -F= '{ print $2 }' | sort -n | tail -1 || true)
n_units=$(cat "$BENCH_DIR"/worker_*.log 2>/dev/null | grep -o ' units=[0-9]*' | sort -u | wc -l || true)
cap="n/a"
if [ -n "$units" ] && [ "$units" -gt 0 ]; then cap=$(( BUDGET / units )); fi

# window statistics over in_window rows (awk over the CSV — read only)
read -r w_blocks w_env w_env_rate w_first w_last w_max w_p50 w_ivmax w_tail_b w_tail_e < <(
    awk -F, 'NR > 1 {
        if ($4 == 1) {
            n++; h[n] = $1; t[n] = $2; c[n] = $3; env += $3
            if (n > 1) { rate += $3; iv = $2 - t[n-1]; if (iv > ivmax) ivmax = iv }
            if ($3 > max) max = $3
        } else { tb++; te += $3 }
    }
    END {
        if (n == 0) { print 0, 0, 0, 0, 0, 0, 0, 0, tb + 0, te + 0; exit }
        for (i = 1; i <= n; i++) s[i] = c[i]
        for (i = 2; i <= n; i++) { v = s[i]; j = i - 1; while (j >= 1 && s[j] > v) { s[j+1] = s[j]; j-- } s[j+1] = v }
        p50 = s[int((n + 1) / 2)]
        print n, env, rate, t[1], t[n], max + 0, p50, ivmax + 0, tb + 0, te + 0
    }' "$csv")

win_s=$(( w_last - w_first ))
tps="n/a"; mean_env="n/a"; mean_iv="n/a"
if [ "$w_blocks" -gt 0 ]; then
    mean_env=$(awk -v e="$w_env" -v b="$w_blocks" 'BEGIN { printf "%.2f", e / b }')
fi
if [ "$win_s" -gt 0 ]; then
    tps=$(awk -v e="$w_env_rate" -v s="$win_s" 'BEGIN { printf "%.2f", e / s }')
    mean_iv=$(awk -v s="$win_s" -v b="$w_blocks" 'BEGIN { printf "%.2f", s / (b - 1) }')
fi

summary="$BENCH_DIR/summary.txt"
{
    echo "bench_tps_v2 — $(date -u +%Y-%m-%dT%H:%M:%SZ), BASE_DIR $BASE_DIR"
    echo "parameters: workers M=$M, load D=${D}s, --count all, --amount all, fee $FEE raw,"
    echo "            pump leaves $n_leaves, nodes $C on one machine ($(nproc) CPUs), reference node$REF"
    echo "load: started $LOAD_START, stopped starting rounds at $LOAD_END, last worker done $LOAD_DONE"
    echo ""
    echo "window (blocks first seen on node$REF between load start and load end):"
    echo "  blocks                      $w_blocks (heights > $base_h)"
    echo "  committed envelopes         $w_env (Σ tx_count; $w_env_rate after the first window block)"
    echo "  window seconds              $win_s (first-seen of first -> last window block)"
    echo "  TPS                         $tps  (= $w_env_rate / $win_s — fencepost: the first block's envelopes excluded)"
    echo "  envelopes/block mean        $mean_env"
    echo "  envelopes/block max         $w_max"
    echo "  envelopes/block p50         $w_p50"
    echo "  block interval mean         $mean_iv s (harness-observed, 1 s granularity)"
    echo "  block interval max          $w_ivmax s"
    echo "  tail after the window       $w_tail_b block(s), $w_tail_e envelope(s) (not in the rate)"
    echo ""
    echo "per-block cap (theory):       $cap = floor($BUDGET NODUS_V2_GLOBAL_UNIT_BUDGET / ${units:-?} declared units)"
    [ "${n_units:-0}" -le 1 ] || echo "  WARNING: the CLI declared $n_units different unit ceilings; the cap uses the LARGEST"
    echo "measured max per block:       $w_max"
    if [ "$cap" = "n/a" ]; then
        echo "  VERDICT: no spend was built, no cap to compare against"
    elif [ "$w_max" -lt "$cap" ]; then
        echo "  VERDICT: NO block reached the unit cap — the CLIENTS were the bottleneck,"
        echo "           this TPS is a FLOOR on the chain's capacity, not its ceiling."
    else
        n_full=$(awk -F, -v cap="$cap" 'NR > 1 && $4 == 1 && $3 >= cap { n++ } END { print n + 0 }' "$csv")
        echo "  VERDICT: $n_full window block(s) reached the unit cap — the chain's unit budget bound at least those blocks."
    fi
    echo ""
    echo "clients (sum over workers):"
    echo "  rounds $w_rounds (idle — nothing of the shard visible, or its first spend refused — then one height waited: $w_idle)"
    echo "  submitted $w_sub = accepted $w_acc + refused $w_ref; planned but unsent after a refusal $w_uns"
    echo "  applied (created row seen on the worker's node) $w_app; DROPPED (not applied within $MAX_HEIGHTS heights) $w_drop"
    echo "  cross-check: workers' applied $w_app vs Σ tx_count over window+tail $(( w_env + w_tail_e ))"
    for f in "$BENCH_DIR"/worker_*.stats; do
        echo "  $(tr '\n' ' ' < "$f")"
    done
    echo ""
    echo "nodus-server CPU over ${CPU_WALL}s of load (utime+stime / wall; > 100% = more than one core):"
    for n in $(seq 1 "$C"); do
        a="${cpu0[$n]}"; b="${cpu1[$n]}"
        if [ "$a" -lt 0 ] || [ "$b" -lt 0 ] || [ "$b" -lt "$a" ]; then
            echo "  node$n  n/a (pid $(node_pid "$n") not readable at start or end, or restarted)"
        else
            echo "  node$n  $(awk -v d="$(( b - a ))" -v hz="$CLK_TCK" -v w="$CPU_WALL" 'BEGIN { printf "%.1f%%", 100 * d / hz / w }')"
        fi
    done
} > "$summary"
cat "$summary"
echo "[ok] per-block rows: $csv; summary: $summary"

stagef_cmt_diff_at_floor "post-bench-tps" || { echo "[FAIL] 7/7 disagreement after the bench" | tee -a "$summary" >&2; exit 2; }
echo "7/7 agreement at the floor after the bench: OK" >> "$summary"
if [ "$w_ref" -gt 0 ] || [ "$w_drop" -gt 0 ]; then
    echo "[warn] $w_ref refused and $w_drop dropped spend(s) — counted above, never retried silently"
fi
echo "[DONE] bench_tps_v2: $tps TPS over ${win_s}s, max $w_max/block (cap $cap), 7/7 agree"
