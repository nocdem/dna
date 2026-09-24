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
#   --count all --shard R/W`. PUMP IDENTITIES (trial B): the bring-up may
#   have made K pump identities (STAGEF_V2_PUMP_IDENTITIES; identity 1 =
#   $BASE_DIR/v2pump, j = $BASE_DIR/v2pump<j>, counted on disk); worker I
#   (0 <= I < M) spends identity (I mod K) + 1. The W workers sharing an
#   identity (I, I+K, I+2K, ...) shard ITS coins among themselves, worker
#   I taking shard R = I div K of W; workers on different identities need
#   no sharding (different owners — they can never list the same coin).
#   With K = M every worker owns one identity and runs --shard 0/1 (no
#   sharding); with K = 1 this is exactly the old --shard I/M. Each worker
#   self-sends every coin of its shard it can see (each coin's whole value
#   minus the fee — 1 input, 1 output, no change), waits until every
#   accepted spend's created
#   `utxo_set` row (tx_hash = the envelope's intent_id,
#   nodus_witness_rt_native.c rtn_utxo_create_eff :1505) exists on the
#   node it submits to, then repeats. The shard is a property of the COIN
#   (first 8 nullifier bytes mod W) and the CLI re-draws every output
#   seed until the new coin lands in the same shard, so the sessions of
#   one identity can never select the same coin (nodus-cli.c
#   cmd_v2_spend's header).
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
#   BANDWIDTH (operator requirement, trial B 2026-09-24): during the load
#   window the parent also samples, about once a second, every
#   nodus-server pid's TCP sockets with `ss -tinpH` (bytes_sent — or
#   bytes_acked where bytes_sent is absent — and bytes_received per
#   socket, keyed by pid + local port + peer port), keeps the LAST (=
#   MAX, the counters only grow) value seen per socket so a socket that
#   closes mid-run still counts what it carried until its last sample,
#   and subtracts a baseline taken at window start for sockets that
#   already existed. Per node it reports bytes sent / received in the
#   window and bytes/s, split by the node's own listening-port class for
#   INCOMING connections (in_client 14xx1, in_internode 14xx2,
#   in_channel 14xx3, in_witness 14xx4 — README "Port map",
#   stagef_env.sh stagef_*_port) and by the PEER's port class for its
#   OUTGOING ones (out_client / out_internode / out_channel / out_witness,
#   out_other for anything outside the cluster's range), plus bytes per
#   committed envelope per node and for the cluster; one CSV per node,
#   $BASE_DIR/bench/bandwidth_node<N>.csv, and the raw samples in
#   $BASE_DIR/bench/bw_samples.raw.
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
#                                part of the genesis document), PER pump
#                                identity. The script default is 40.
#     STAGEF_V2_PUMP_IDENTITIES=<K>  exported BEFORE stagef_up_v2.sh
#                                (default 1). The bench counts the
#                                identities on disk; if this variable is
#                                also exported at bench time it must
#                                match, or the bench refuses.
#                                SUGGESTED for the trial-B cap of 255:
#                                K = 7, N = 150 (in-flight bound
#                                7 x min(100, 150) = 700; see "HOW IT CAN
#                                LIE" on the 100-row listing cap).
#     STAGEF_BENCH_WORKERS       M, default 7 = one per node, max 7: a
#                                node evicts an older session of the
#                                same identity (SESSION_EVICT), so two
#                                workers on one node kill each other.
#     STAGEF_BENCH_DURATION_S    D, default 600 — how long workers START
#                                new rounds. A load length, never a
#                                correctness bound: every wait inside is
#                                progress-bounded (below).
#   A fresh cluster from stagef_up_v2.sh (not a Comet cluster, or no pump
#   identity → rc 99). Every pump identity's batch is claimed here, ONE
#   v2-claim call per identity, if it is not claimed yet (v2-claim rc 2
#   "all already claimed" is accepted, e.g. after
#   test_cmt_claim_flood.sh), and the load starts only once EVERY
#   identity's coins are all spendable on node 1 and every node has
#   reached that height.
#   Optional: `ss` (iproute2) with TCP byte counters (`-i` printing
#   bytes_received / bytes_acked) for the bandwidth section. Without it
#   that section is SKIPPED with a message; the bench itself still runs
#   and still exits 0 on a clean load.
#
# WHAT IT LEAVES BEHIND
#   Every pump identity's whole batch claimed; every coin spent replaced
#   by one coin STAGEF_PUMP_FEE_RAW smaller (coin count unchanged, fees
#   in the reward pool). The chain many blocks further on. Nothing is
#   killed or restarted. $BASE_DIR/bench/ holds blocks.csv, summary.txt,
#   one worker_<I>.log / worker_<I>.stats per worker and — when ss
#   qualified — bw_samples.raw and bandwidth_node<N>.csv. A worker still
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
#     nodus_witness_utxo_by_owner) — PER IDENTITY. The workers of one
#     identity together see at most 100 of its coins per listing, and a
#     worker sees only the part of those 100 that falls in its shard.
#     Leaves beyond 100 per identity are a reserve that rotates into view
#     as spent coins are replaced; they do not raise the bound. The
#     in-flight bound is therefore ≈ Σ over the identities that have a
#     worker of min(100, leaves) — 100 × K with ≥ 100 leaves each (K = 7:
#     700 ≥ 255) — and the summary prints K and this bound; when the
#     bound is below the cap it says the block CANNOT fill.
#     (Which 100 rows come back is SQLite's plan choice, not a documented
#     order — JUDGMENT, not verified with EXPLAIN on a live DB.) A worker
#     whose shard has nothing visible does an IDLE round — it waits for
#     one new height and lists again; idle rounds are counted per worker.
#   - **Today's unit budget only.** The per-block cap is
#     NODUS_V2_GLOBAL_UNIT_BUDGET (read from nodus_witness_v2_apply.h:298
#     at run time — 2 097 152 since block capacity trial B, operator
#     2026-09-24; it was 1 000 000) / the CLI's right-sized ceiling
#     (t6_spend_ceiling over the EXACT effect declaration,
#     t6_spend_effect_decl). ARITHMETIC, NOT MEASURED: a 1-in/1-out spend
#     declares 8 221 units (all weights 1: base 1 + op 1 + call 298 +
#     auth 7 220 + 3 effects + 696 effect bytes + 2 reads), so the cap is
#     floor(2 097 152 / 8 221) = 255. A different budget, metering
#     weight, auth size or ceiling rule is a different cap and a
#     different result. The policy's envelope BYTE bound
#     (max_block_env_bytes 2 MiB) is now close: a 1-in/1-out envelope is
#     43 + 30 + 298 + 7 220 = 7 591 bytes (env_wire.h fixed head + leg
#     header + call + auth), floor(2 097 152 / 7 591) = 276 per block,
#     so the UNIT cap still binds first by that arithmetic; the bench
#     prints only the unit cap. Block.MaxBytes and NODUS_V2_ENV_BATCH_MAX
#     are far above this load and are not reported; if one ever bound
#     first, the "cap" line would be wrong.
#   - **With ONE pump identity the CLIENTS cannot fill a 255 block.** The
#     100-row listing cap (above) then bounds all workers together to
#     ~100 coins in flight, below the trial-B cap of 255 — the summary
#     prints "STRUCTURAL" under the verdict. Bring the cluster up with
#     STAGEF_V2_PUMP_IDENTITIES=7 (bound 700). A bound above the cap is
#     NECESSARY, not sufficient: each worker also pays a session setup and
#     a ~1 s confirmation poll per round, so a block may still fall short
#     of the cap — the verdict line then still says CLIENTS, honestly.
#   - **Bandwidth is localhost TCP payload, and sampled.** The counters
#     are the kernel's per-socket TCP payload bytes (bytes_sent /
#     bytes_acked, bytes_received): they INCLUDE everything nodus writes
#     to the socket — its wire framing, CBOR, and whatever session
#     encryption / authentication overhead that link carries — and
#     EXCLUDE IP/TCP headers; on loopback there is no
#     real network, no loss and no bandwidth limit, so the numbers say
#     how much a node SENDS, not how fast a real link could carry it.
#     A socket opened AND closed between two ~1 s samples is missed
#     entirely; a socket's bytes after its last sample are missed;
#     `ss -p` attributes a socket to a pid only for the caller's own
#     processes (or as root), so nodes run by another user are invisible
#     and the section reports "no nodus-server TCP socket was seen"; a
#     (pid, local port, peer port) tuple re-used by a new socket is
#     detected only when a counter goes DOWN (counted as a re-use and
#     summed as two sockets). The report prints how many sockets were
#     seen, how many were open at start, opened during and gone before
#     the end. Node-to-node bytes appear twice across the cluster (sent
#     by one node, received by the other); client (nodus-cli) sessions
#     are measured on the server side only (their pids are not
#     sampled). Bytes per envelope divide the window's bytes by the
#     committed envelopes in the window blocks — the byte window
#     (wall-clock load start → load end) and the block window (blocks
#     first seen inside it) are not the same interval at their edges.
#     Consensus traffic flows with or without envelopes (idle blocks,
#     votes), so bytes per envelope is an upper bound on what an
#     envelope costs, not its marginal cost.
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

# ── the pump identities (trial B: STAGEF_V2_PUMP_IDENTITIES at bring-up)
# Identity 1 is $BASE_DIR/v2pump; identities 2..K are v2pump2..v2pumpK,
# counted ON DISK (consecutive, each with a nodus.pk) because the bench
# runs against a cluster that already exists. If STAGEF_V2_PUMP_IDENTITIES
# is exported it must agree with what the bring-up actually made.
K=1
while [ -s "$BASE_DIR/v2pump$(( K + 1 ))/identity/nodus.pk" ]; do K=$(( K + 1 )); done
if [ -n "${STAGEF_V2_PUMP_IDENTITIES:-}" ] && [ "$STAGEF_V2_PUMP_IDENTITIES" != "$K" ]; then
    die "STAGEF_V2_PUMP_IDENTITIES=$STAGEF_V2_PUMP_IDENTITIES but this bring-up has $K pump identit(y/ies) under $BASE_DIR — export the value used at bring-up, or unset it"
fi
declare -a PK_DIR PK_FP PK_LEAVES PK_WORKERS
n_leaves=0
for j in $(seq 1 "$K"); do
    if [ "$j" = 1 ]; then PK_DIR[$j]="$PUMP"; else PK_DIR[$j]="$BASE_DIR/v2pump$j/identity"; fi
    PK_FP[$j]=$(cat "${PK_DIR[$j]}/nodus.fp")
    PK_LEAVES[$j]=$(grep -c "^dest_binding = ${PK_FP[$j]}\$" "$CONF" || true)
    [ "${PK_LEAVES[$j]:-0}" -gt 0 ] || die "no pump leaves for identity $j (${PK_FP[$j]}) in $CONF"
    # workers I with I mod K == j-1 use identity j
    if [ "$(( j - 1 ))" -lt "$M" ]; then
        PK_WORKERS[$j]=$(( (M - 1 - (j - 1)) / K + 1 ))
    else
        PK_WORKERS[$j]=0
    fi
    n_leaves=$(( n_leaves + PK_LEAVES[j] ))
done
# In-flight bound: one dnac_utxo listing returns at most
# NODUS_DNAC_MAX_UTXO_RESULTS = 100 coins of ONE identity, and every
# worker of an identity lists that same identity — so the coins the
# workers can see at once are Σ over USED identities of min(100, leaves).
INFLIGHT_BOUND=0
for j in $(seq 1 "$K"); do
    [ "${PK_WORKERS[$j]}" -gt 0 ] || continue
    l="${PK_LEAVES[$j]}"; [ "$l" -le 100 ] || l=100
    INFLIGHT_BOUND=$(( INFLIGHT_BOUND + l ))
done
echo "[ok] pump identities K=$K, $n_leaves genesis leaves in total (STAGEF_V2_PUMP_LEAVES per identity at bring-up); in-flight bound ≈ $INFLIGHT_BOUND coins (100-row listing cap per identity)"
for j in $(seq 1 "$K"); do
    if [ "${PK_WORKERS[$j]}" = 0 ]; then
        echo "[warn] pump identity $j has no worker (K=$K > M=$M) — its batch is claimed but never spent"
    elif [ "${PK_LEAVES[$j]}" -lt "${PK_WORKERS[$j]}" ]; then
        echo "[warn] pump identity $j: fewer leaves (${PK_LEAVES[$j]}) than its workers (${PK_WORKERS[$j]}) — some shards start empty"
    fi
done

stagef_cmt_diff_at_floor "pre-bench-tps" || exit 2

# ── (i) claim every identity's batch (ONE v2-claim call per identity),
#        then wait until EVERY identity's coins are all spendable ──────
port=$(stagef_tcp_port "$REF")
for j in $(seq 1 "$K"); do
    claim_log="$BENCH_DIR/claim_$j.log"
    crc=0
    "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$ref_db" \
        --keys "${PK_DIR[$j]}" --submit "127.0.0.1:$port" > "$claim_log" 2>&1 || crc=$?
    if [ "$crc" = 2 ]; then
        echo "[ok] pump identity $j: batch already claimed (v2-claim rc 2) — using it as it stands"
    elif [ "$crc" != 0 ]; then
        cat "$claim_log" >&2
        die "pump identity $j: batch claim failed (v2-claim rc $crc)"
    else
        echo "[ok] pump identity $j: ${PK_LEAVES[$j]} leaves submitted in one v2-claim call"
    fi
done
for j in $(seq 1 "$K"); do
    h=$(stagef_cmt_wait_row "$ref_db" \
        "SELECT (SELECT COUNT(*) FROM utxo_set WHERE owner = '${PK_FP[$j]}'
                   AND token_id = zeroblob(64) AND amount > $FEE
                   AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks))
                >= ${PK_LEAVES[$j]};") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "pump identity $j: the claimed coins never all appeared and the chain STALLED (tip $h)" ;;
        *) die "pump identity $j: fewer than ${PK_LEAVES[$j]} spendable coins above the fee on node$REF within $MAX_HEIGHTS heights (tip $h) — a claim was refused or dropped, or earlier use left coins at or below the fee" ;;
    esac
    echo "[ok] pump identity $j: ${PK_LEAVES[$j]} spendable coins on node$REF (tip $h)"
done
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
    local I="$1" node port db log stats pj keys fp shard
    node=$(( I % C + 1 ))
    # pump identity (I mod K) + 1; among the workers sharing it (I, I+K,
    # I+2K, ...) this one is rank I div K of PK_WORKERS[pj], and shards
    # that identity's coins by rank — workers on DIFFERENT identities can
    # never select the same coin (different owners), so sharding is only
    # needed within an identity. K = M gives every worker its own identity
    # and --shard 0/1 (= no sharding, the CLI's shard_m 1).
    pj=$(( I % K + 1 ))
    keys="${PK_DIR[$pj]}"
    fp="${PK_FP[$pj]}"
    shard="$(( I / K ))/${PK_WORKERS[$pj]}"
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
                --keys "$keys" --to "$fp" --amount all --count all \
                --shard "$shard" --fee "$FEE" \
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
        echo "worker=$I"; echo "node=$node"; echo "pump_identity=$pj"
        echo "shard=$shard"; echo "rounds=$rounds"
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

# BANDWIDTH: per-socket TCP byte counters of every nodus-server pid,
# via `ss -tinpH` (iproute2). Each sample appends one line per nodus
# socket to $BW_RAW:  phase,time,pid,node,local_port,peer_port,sent,recv
# (phase 0 = the baseline at load start, 1 = inside the window). `ss`
# prints each socket on a line starting at column 0 and its `-i`
# counters on the NEXT, indented line; sent = bytes_sent (bytes_acked
# when bytes_sent is absent), recv = bytes_received, 0 when not printed.
# Missing `ss` or missing byte counters SKIP this section only.
BW_OK=0
BW_WHY=""
BW_RAW="$BENCH_DIR/bw_samples.raw"
BW_SAMPLES=0
BW_TEND=0
rm -f "$BW_RAW" "$BENCH_DIR"/bandwidth_node*.csv
if ! command -v ss >/dev/null 2>&1; then
    BW_WHY="ss (iproute2) is not installed"
else
    bw_probe=$(ss -tinpH 2>/dev/null || true)
    case "$bw_probe" in
        *bytes_received:*|*bytes_acked:*) BW_OK=1 ;;
        *) BW_WHY="ss -tinpH printed no bytes_received / bytes_acked counters (ss or kernel too old for -i byte counters)" ;;
    esac
    unset bw_probe
fi
BW_PIDMAP=""
for n in $(seq 1 "$C"); do BW_PIDMAP="$BW_PIDMAP $(node_pid "$n"):$n"; done
if [ "$BW_OK" = 1 ]; then
    echo "[ok] bandwidth: sampling nodus-server TCP sockets with ss -tinpH (~1 s)"
else
    echo "[info] bandwidth section SKIPPED: $BW_WHY"
fi

# bw_sample PHASE TIME — one ss snapshot of the nodus sockets. Never
# fails the bench: an ss error just loses that sample.
bw_sample() {
    [ "$BW_OK" = 1 ] || return 0
    BW_SAMPLES=$(( BW_SAMPLES + 1 ))
    { ss -tinpH 2>/dev/null || true; } | awk -v ph="$1" -v t="$2" -v map="$BW_PIDMAP" '
        BEGIN {
            n = split(map, a, " ")
            for (i = 1; i <= n; i++) { split(a[i], kv, ":"); node[kv[1]] = kv[2] }
            key = ""
        }
        /^[^ \t]/ {
            key = ""
            if (match($0, /pid=[0-9]+/)) {
                pid = substr($0, RSTART + 4, RLENGTH - 4)
                if (pid in node) {
                    lp = $4; sub(/.*:/, "", lp)
                    pp = $5; sub(/.*:/, "", pp)
                    key = pid "," node[pid] "," lp "," pp
                }
            }
            next
        }
        key != "" {
            s = 0; r = 0
            if (match($0, /bytes_sent:[0-9]+/))
                s = substr($0, RSTART + 11, RLENGTH - 11)
            else if (match($0, /bytes_acked:[0-9]+/))
                s = substr($0, RSTART + 12, RLENGTH - 12)
            if (match($0, /bytes_received:[0-9]+/))
                r = substr($0, RSTART + 15, RLENGTH - 15)
            print ph "," t "," key "," s "," r
            key = ""
        }' >> "$BW_RAW" || true
}

# bw_report — the window's bytes per node and port class (stdout) and
# one CSV per node. Reads $BW_RAW in append (= time) order: per socket
# key the LAST value is its MAX (the kernel counters only grow); a
# counter going DOWN means a new socket re-used the key — the old one's
# last value is banked and counting restarts. Window bytes = banked +
# last − baseline (baseline = the phase-0 value, 0 for a socket first
# seen inside the window). Output order is fixed (nodes 1..C, a fixed
# class list), never awk's hash order.
bw_report() {
    if [ "$BW_OK" != 1 ]; then
        echo "bandwidth: SKIPPED — $BW_WHY (nothing else in this bench depends on it)"
        return 0
    fi
    if [ ! -s "$BW_RAW" ]; then
        echo "bandwidth: SKIPPED — no nodus-server TCP socket was seen in any of $BW_SAMPLES ss sample(s) (ss -p names a socket's pid only for the caller's own processes unless run as root — are the nodes another user's?)"
        return 0
    fi
    awk -F, -v C="$C" -v dir="$BENCH_DIR" -v wall="$BW_WALL" -v env="$w_env" \
        -v tend="$BW_TEND" -v nsamp="$BW_SAMPLES" '
    function cls(nd, l, p,    d) {
        d = l - (14000 + (nd - 1) * 10)
        if (d >= 1 && d <= 4) return "in_" nm[d]
        if (p >= 14000 && p < 14000 + 10 * C) {
            d = (p - 14000) % 10
            if (d >= 1 && d <= 4) return "out_" nm[d]
        }
        return "out_other"
    }
    function B(x) { return sprintf("%.0f", x) }
    function R(x) { return sprintf("%.1f", x / wall) }
    function E(x) { return env > 0 ? sprintf("%.0f", x / env) : "n/a" }
    BEGIN {
        nm[1] = "client"; nm[2] = "internode"; nm[3] = "channel"; nm[4] = "witness"
        ncl = split("in_client in_internode in_channel in_witness out_client out_internode out_channel out_witness out_other", cl, " ")
    }
    {
        k = $3 "," $5 "," $6
        s = $7 + 0; r = $8 + 0
        if (!(k in kn)) {
            kn[k] = $4; kl[k] = $5 + 0; kp[k] = $6 + 0
            if ($1 == 0) { bs[k] = s; br[k] = r; n_start++ }
            else         { bs[k] = 0; br[k] = 0; n_new++ }
            ls[k] = s; lr[k] = r; as[k] = 0; ar[k] = 0
        } else if (s < ls[k] || r < lr[k]) {
            as[k] += ls[k]; ar[k] += lr[k]; n_reuse++
            ls[k] = s; lr[k] = r
        } else {
            ls[k] = s; lr[k] = r
        }
        lt[k] = $2 + 0
    }
    END {
        for (k in kn) {
            nd = kn[k]; c = cls(nd, kl[k], kp[k])
            ws = as[k] + ls[k] - bs[k]; wr = ar[k] + lr[k] - br[k]
            if (ws < 0) ws = 0
            if (wr < 0) wr = 0
            S[nd, c] += ws; RV[nd, c] += wr; K[nd, c]++
            TS[nd] += ws; TR[nd] += wr; TK[nd]++
            if (lt[k] < tend) n_gone++
            nk++
        }
        printf "bandwidth over %d s of load (ss -tinpH, %d sample(s) ~1 s apart; %d socket(s) seen: %d open at start, %d opened during the window, %d gone before the end, %d key re-use(s)):\n", wall, nsamp, nk, n_start + 0, n_new + 0, n_gone + 0, n_reuse + 0
        printf "  bytes per envelope = window bytes / %s committed envelopes (window blocks)\n", env
        for (nd = 1; nd <= C; nd++) {
            f = dir "/bandwidth_node" nd ".csv"
            print "class,sockets,bytes_sent,bytes_received,sent_Bps,recv_Bps,sent_per_env,recv_per_env" > f
            printf "  node%d  sent %s B (%s B/s)  recv %s B (%s B/s)  per envelope: sent %s B, recv %s B  [%d socket(s)]\n", nd, B(TS[nd]), R(TS[nd]), B(TR[nd]), R(TR[nd]), E(TS[nd]), E(TR[nd]), TK[nd]
            for (i = 1; i <= ncl; i++) {
                c = cl[i]
                if (!((nd, c) in K)) continue
                printf "         %-14s sent %s B (%s B/s)  recv %s B (%s B/s)  [%d]\n", c, B(S[nd, c]), R(S[nd, c]), B(RV[nd, c]), R(RV[nd, c]), K[nd, c]
                print c "," K[nd, c] "," B(S[nd, c]) "," B(RV[nd, c]) "," R(S[nd, c]) "," R(RV[nd, c]) "," E(S[nd, c]) "," E(RV[nd, c]) > f
            }
            print "total," (TK[nd] + 0) "," B(TS[nd]) "," B(TR[nd]) "," R(TS[nd]) "," R(TR[nd]) "," E(TS[nd]) "," E(TR[nd]) > f
            close(f)
            CS += TS[nd]; CR += TR[nd]
        }
        printf "  cluster sent %s B (%s B/s)  recv %s B (%s B/s)  per envelope: sent %s B, recv %s B\n", B(CS), R(CS), B(CR), R(CR), E(CS), E(CR)
        printf "  (node-to-node bytes count once as sent and once as received; client sessions only on the server side)\n"
    }' "$BW_RAW" || echo "bandwidth: report FAILED to aggregate $BW_RAW (awk error) — raw samples kept"
}

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
bw_sample 0 "$LOAD_START"                        # the bandwidth baseline
for I in $(seq 0 $(( M - 1 ))); do
    worker "$I" &
    wpids[$I]=$!
done
kill_workers() {
    local p
    for p in "${wpids[@]}"; do kill "$p" 2>/dev/null || true; done
}
trap kill_workers EXIT
echo "[ok] $M workers started at $LOAD_START for ${D}s (nodes: worker I -> node I mod $C + 1; pump identity I mod $K + 1); base tip $base_h"

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
    now_s=$(date +%s)
    if [ "$cpu1_taken" = 0 ] && [ "$now_s" -ge "$LOAD_END" ]; then
        for n in $(seq 1 "$C"); do cpu1[$n]=$(cpu_ticks "$(node_pid "$n")"); done
        BW_TEND="$now_s"
        bw_sample 1 "$BW_TEND"                   # the window's last sample
        cpu1_taken=1
    elif [ "$cpu1_taken" = 0 ]; then
        bw_sample 1 "$now_s"
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
    BW_TEND=$(date +%s)
    bw_sample 1 "$BW_TEND"
fi
trap - EXIT
LOAD_DONE=$(date +%s)
CPU_WALL=$(( (cpu1_taken == 1 ? LOAD_END : LOAD_DONE) - LOAD_START ))
[ "$CPU_WALL" -ge 1 ] || CPU_WALL=1
BW_WALL=$(( BW_TEND - LOAD_START ))
[ "$BW_WALL" -ge 1 ] || BW_WALL=1

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
    echo "            pump leaves $n_leaves over K=$K pump identit(y/ies) (worker I -> identity I mod K + 1),"
    echo "            nodes $C on one machine ($(nproc) CPUs), reference node$REF"
    echo "in-flight bound: ≈ $INFLIGHT_BOUND coins = Σ over the identities with a worker of min(100, leaves)"
    echo "            (the dnac_utxo listing returns at most 100 coins per identity)"
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
        if [ "$INFLIGHT_BOUND" -lt "$cap" ]; then
            echo "           STRUCTURAL: the in-flight bound ($INFLIGHT_BOUND) is below the cap ($cap) —"
            echo "           no block CAN fill; raise STAGEF_V2_PUMP_IDENTITIES / STAGEF_V2_PUMP_LEAVES at bring-up."
        fi
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
    echo ""
    bw_report
} > "$summary"
cat "$summary"
echo "[ok] per-block rows: $csv; summary: $summary"
[ "$BW_OK" != 1 ] || echo "[ok] bandwidth: per-node CSVs $BENCH_DIR/bandwidth_node<N>.csv; raw samples $BW_RAW"

stagef_cmt_diff_at_floor "post-bench-tps" || { echo "[FAIL] 7/7 disagreement after the bench" | tee -a "$summary" >&2; exit 2; }
echo "7/7 agreement at the floor after the bench: OK" >> "$summary"
if [ "$w_ref" -gt 0 ] || [ "$w_drop" -gt 0 ]; then
    echo "[warn] $w_ref refused and $w_drop dropped spend(s) — counted above, never retried silently"
fi
echo "[DONE] bench_tps_v2: $tps TPS over ${win_s}s, max $w_max/block (cap $cap), 7/7 agree"
