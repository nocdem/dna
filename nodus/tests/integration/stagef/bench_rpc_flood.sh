#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# bench_rpc_flood.sh — does a high volume of ordinary client chain
# requests to ONE node delay that node's own consensus participation?
# A defensive MEASUREMENT of our own node on localhost.
# ════════════════════════════════════════════════════════════════════
#
# A MEASUREMENT, NOT A SCENARIO. It is not in genesis_protocol_v2.sh and
# must never be: it asserts NO performance threshold, it MEASURES one node
# under two conditions and prints both side by side. Its only verdicts are
# "it ran" (exit 0), "this is not a Comet cluster" (exit 99 SKIP) and "a
# setup fault" (non-zero). The operator reads the two windows and judges.
#
# WHAT IT MEASURES
#   Against an already-up localhost cluster (stagef_up_v2.sh, any
#   STAGEF_MODE — production is split, so STAGEF_MODE=split is the honest
#   shape; see below), it runs TWO windows of the SAME length, each
#   STAGEF_FLOOD_HEIGHTS committed heights long (boundaries read from a
#   NON-victim node's DB, never wall-clock):
#     Phase A (baseline) — no flood.
#     Phase B (flood)    — stagef_rpc_flood pointed at ONE node's client
#                          port only (STAGEF_FLOOD_VICTIM), STAGEF_FLOOD_
#                          SESSIONS sessions x STAGEF_FLOOD_THREADS threads
#                          of STAGEF_FLOOD_MODE requests.
#   In BOTH windows the chain is driven at the timeout_commit pace (not the
#   60 s idle interval) by the existing CLI-SPEND pump (stagef_cmt_pump_to)
#   run from a node that is NOT the victim. Per window it records, from a
#   non-victim reference node's witness DB, once a second: the committed
#   tip, each validator's v2_attendance.signed_count, and the victim's own
#   tip lag behind the reference (max). From that it reports: heights
#   committed, harness-observed seconds per height (mean / max, 1 s poll),
#   per-validator signed_count delta across the window (voter id via
#   stagef_voter_id), the victim's max tip lag, and — if readable — the
#   victim witness process CPU% (utime+stime from /proc, as bench_tps_v2).
#   The flood tool's own stats (sent / answered / refused / errors /
#   timeouts, requests/s) are copied into the summary.
#   The comparison IS the output; no pass/fail is derived from it.
#
# WHAT IT REQUIRES
#   Compile flags: none beyond a default build — nodus-server AND nodus-cli
#   AND stagef_rpc_flood from the SAME tree (the CLI pump and the flood
#   tool take the CORE ruleset from their own compiled table; a binary
#   from another tree would build an envelope for a different ruleset and
#   be refused EARLY, not at the input-existence check the spend-invalid
#   mode exercises). A short-epoch build (DNAC_EPOCH_LENGTH=15) only
#   changes how often signed_count resets (see HOW IT CAN LIE).
#   Environment (all optional, with defaults):
#     STAGEF_FLOOD_VICTIM    node flooded + measured (default 2). MUST
#                            differ from STAGEF_PUMP_FUNDER_NODE (3) and
#                            STAGEF_PUMP_SUBMIT_NODE (1) — the pump drives
#                            the chain from those; this bench refuses at
#                            once otherwise.
#     STAGEF_FLOOD_MODE      spend-invalid (default) | v3-block | balance.
#     STAGEF_FLOOD_SESSIONS  S, 1..19 (default 19 — 20 connections per IP
#                            is the server cap, nodus_tcp.c:1069).
#     STAGEF_FLOOD_THREADS   T per session, 1..64 (default 32 — 64 is
#                            NODUS_MAX_PENDING per client).
#     STAGEF_FLOOD_HEIGHTS   window length in committed heights (default
#                            30). A LENGTH, never a correctness bound:
#                            every wait inside is progress-bounded.
#     STAGEF_FLOOD_BIN       default nodus/build/stagef_rpc_flood.
#   A Comet cluster from stagef_up_v2.sh (v2_blocks table + a pump-ready
#   funder leaf), else exit 99. Nothing is exported before bring-up; this
#   bench runs against the cluster as it stands.
#
# WHAT IT LEAVES BEHIND
#   The pump's fees spent (node 3's genesis leaf claimed if no earlier pump
#   did; each pump spend replaces one coin STAGEF_PUMP_FEE_RAW smaller).
#   The chain many blocks further on (two windows of driven heights).
#   The flood tool's refused / read requests committed NOTHING. NOTHING is
#   killed or restarted — no node is stopped, no identity file is touched
#   (the flood tool's identities are ephemeral, in memory only). Outputs
#   under $BASE_DIR/rpcflood/.
#
# HOW IT CAN LIE
#   - **SDK-shaped load only.** Every tool thread waits for its answer
#     (<= 64 in flight per session, NODUS_MAX_PENDING), so the victim never
#     holds more than S x T queued requests; a client that never waits can
#     queue 256 frames per session per poll pass, and several IPs multiply
#     the 19-session cap — neither is measured here.
#   - **One machine, 7 nodes, plus the clients.** Every nodus process and
#     the flood tool share this machine's cores. A delay seen under flood
#     may be CPU contention on the shared host, not a protocol effect —
#     the victim CPU% is printed so that is visible. A real deployment's
#     victim is alone on its host.
#   - **Localhost: no network.** The flood's packets cross loopback; a real
#     attacker's would cross a NIC and a link with their own limits. This
#     measures the node's CPU/lock response to request volume, not a
#     network-saturation attack.
#   - **Harness-observed block times, 1 s granularity.** Seconds per height
#     are the reference node's FIRST SIGHTING of each height, polled once a
#     second (v2_blocks carries no timestamp column) — NOT the header's BFT
#     time. Two heights seen in one poll read as a 0 s interval. A per-
#     height number is noisy; the mean over the window is what to compare.
#   - **signed_count RESETS to 0 at every epoch boundary** (v2ep_attendance_
#     reset, nodus_witness_v2_epoch.c:1881 — UPDATE v2_attendance SET
#     signed_count = 0). A window that crosses a boundary would compute a
#     NEGATIVE delta; this bench detects end < start and reports the window
#     as "crossed an epoch boundary" for that validator rather than a
#     bogus number. Under the short-epoch build (E=15) a 30-height window
#     ALWAYS crosses at least one boundary; at production E=720 it rarely
#     does. The attendance delta is only a clean "did this validator keep
#     voting" signal inside ONE epoch.
#   - **Tip lag is a proxy, not a vote.** The victim's witness DB tip
#     trailing the reference's is replication/commit lag; a validator can
#     lag in its DB write yet still have PREVOTED/PRECOMMITTED on time.
#     Lag rising under flood is a hint to investigate, not proof the victim
#     missed consensus. The signed_count delta (same-epoch) is the direct
#     participation signal; tip lag complements it.
#   - **The flood is CLIENT-paced too.** sent/s is bounded by the session
#     setup, the SDK's 64-in-flight-per-client cap and each request's round
#     trip, not only by the node. A low sent/s with no commit delay means
#     the node shrugged off the load at THIS request rate — not that no
#     rate could delay it. Raise S, T or run several copies to push harder.
#   - **spend-invalid proves CheckTx work only if the proof line printed.**
#     The tool submits one fabricated-input envelope first and refuses to
#     run unless the node answered with a CheckTx refusal ("CheckTx code
#     N"); if that proof fails the tool exits non-zero and this bench fails
#     the phase. v3-block / balance do read work regardless.
#   - **A skip is not a pass.** rc 99 = not a Comet cluster / no pump leaf:
#     nothing was measured.
#   - **Pump drift.** If the funder's leaf was already spent down to the
#     fee by other work, the pump faults and this bench fails as a setup
#     fault — it never silently falls back to 60 s idle production, which
#     would measure a different (idle) chain.
#
# Exit: 0 ran (both windows measured, 7/7 agree at the floor) · 1 setup or
#       pump fault · 2 7/7 divergence · 99 SKIP (not a Comet cluster).
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/stagef_env.sh"

VICTIM="${STAGEF_FLOOD_VICTIM:-2}"
MODE="${STAGEF_FLOOD_MODE:-spend-invalid}"
SESSIONS="${STAGEF_FLOOD_SESSIONS:-19}"
THREADS="${STAGEF_FLOOD_THREADS:-32}"
HEIGHTS="${STAGEF_FLOOD_HEIGHTS:-30}"
BIN="${STAGEF_FLOOD_BIN:-$STAGEF_REPO_ROOT/nodus/build/stagef_rpc_flood}"
C="$STAGEF_COMMITTEE_SIZE"
FEE="$STAGEF_PUMP_FEE_RAW"
# stall guard for the sampler: 3 idle-block intervals with the tip not
# advancing at all is a genuine stall (a healthy Comet chain commits at
# least once per interval). Same discipline as stagef_cmt_wait_height.
STALL_POLLS=$(( 3 * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))

die()  { echo "[FAIL] $*" >&2; exit 1; }

# ── argument / environment verdicts ──────────────────────────────────
case "$VICTIM"   in ''|*[!0-9]*) die "STAGEF_FLOOD_VICTIM must be an integer (got '$VICTIM')" ;; esac
case "$SESSIONS" in ''|*[!0-9]*) die "STAGEF_FLOOD_SESSIONS must be an integer (got '$SESSIONS')" ;; esac
case "$THREADS"  in ''|*[!0-9]*) die "STAGEF_FLOOD_THREADS must be an integer (got '$THREADS')" ;; esac
case "$HEIGHTS"  in ''|*[!0-9]*) die "STAGEF_FLOOD_HEIGHTS must be an integer (got '$HEIGHTS')" ;; esac
[ "$VICTIM" -ge 1 ] && [ "$VICTIM" -le "$C" ] || die "STAGEF_FLOOD_VICTIM must be 1..$C"
[ "$SESSIONS" -ge 1 ] && [ "$SESSIONS" -le 19 ] || die "STAGEF_FLOOD_SESSIONS must be 1..19"
[ "$THREADS"  -ge 1 ] && [ "$THREADS"  -le 64 ] || die "STAGEF_FLOOD_THREADS must be 1..64"
[ "$HEIGHTS"  -ge 2 ] || die "STAGEF_FLOOD_HEIGHTS must be >= 2 (a window needs an interval)"
case "$MODE" in spend-invalid|v3-block|balance) ;; *) die "STAGEF_FLOOD_MODE must be spend-invalid | v3-block | balance" ;; esac
[ -x "$BIN" ] || die "no stagef_rpc_flood at $BIN (build it: cd nodus/build && make stagef_rpc_flood)"

# the pump drives the chain from the funder + submit nodes; they must not
# be the node we flood and measure (fail at once otherwise)
if [ "$VICTIM" = "$STAGEF_PUMP_FUNDER_NODE" ] || [ "$VICTIM" = "$STAGEF_PUMP_SUBMIT_NODE" ]; then
    die "STAGEF_FLOOD_VICTIM=$VICTIM collides with the pump funder (node $STAGEF_PUMP_FUNDER_NODE) or submit node (node $STAGEF_PUMP_SUBMIT_NODE) — the pump must drive the chain from a node other than the victim; set STAGEF_FLOOD_VICTIM to a node that is neither"
fi

# reference (reads + window boundaries): a NON-victim node. The submit
# node is non-victim by the check above, so use it.
REF="$STAGEF_PUMP_SUBMIT_NODE"
REF_DB=$(stagef_node_chain_db "$REF")
VICTIM_DB=$(stagef_node_chain_db "$VICTIM")
[ -n "$REF_DB" ] && [ -s "$REF_DB" ] || die "no chain DB for reference node$REF (is a cluster up? BASE_DIR='$BASE_DIR')"
[ -n "$VICTIM_DB" ] && [ -s "$VICTIM_DB" ] || die "no chain DB for victim node$VICTIM"

has_v2=$(sqlite3 "$REF_DB" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster (no v2_blocks on node$REF) — use stagef_up_v2.sh"
    exit 99
fi
[ -s "$BASE_DIR/pids.txt" ] || die "no $BASE_DIR/pids.txt"

VICTIM_PORT=$(stagef_tcp_port "$VICTIM")
FLOOD_DIR="$BASE_DIR/rpcflood"
mkdir -p "$FLOOD_DIR"
rm -f "$FLOOD_DIR"/*.csv "$FLOOD_DIR"/flood_*.txt "$FLOOD_DIR/summary.txt"

# ── the pump: feasibility now, so a phase that cannot drive the chain
#    fails as a setup fault rather than measuring an idle chain ─────────
stagef_cmt_pump_ready "$REF_DB" || die "the CLI-SPEND pump is not available (needs nodus-cli, $BASE_DIR/v2_genesis.conf and node$STAGEF_PUMP_FUNDER_NODE's funder identity with a spendable leaf) — this bench must drive the chain at commit pace, not measure idle production"

# ── per-validator voter ids (SHA3-512(pubkey)[0..31], 64 hex) for the
#    one-shot attendance read ───────────────────────────────────────────
declare -a VOTER
for n in $(seq 1 "$C"); do
    vid=$(stagef_voter_id "$BASE_DIR/node$n/identity/nodus.pk")
    [ "${#vid}" = 64 ] || die "could not derive voter id for node$n (openssl / nodus.pk?)"
    VOTER[$n]="$vid"
done

# the one REF read per sample: tip, then every validator's signed_count.
# Built once (the voter ids are fixed), reused each poll — ONE sqlite
# statement per sample.
build_ref_sql() {
    local sql="SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks)"
    local n
    for n in $(seq 1 "$C"); do
        # COALESCE OUTSIDE the subquery: with no attendance row yet (a
        # fresh chain) the subquery itself is NULL, and an empty field
        # would vanish from the bash array below
        sql="$sql, COALESCE((SELECT signed_count FROM v2_attendance WHERE voter_id = X'${VOTER[$n]}'),0)"
    done
    echo "$sql;"
}
REF_SQL=$(build_ref_sql)

now_ms() { date +%s%3N; }

# victim witness process CPU ticks (utime+stime, /proc), as bench_tps_v2.
# In a split node the witness is its own nodus-witness; otherwise it is the
# core (nodus-server runs the witness in-process). -1 when not readable.
victim_witness_pid() {
    if stagef_node_is_split "$VICTIM"; then
        stagef_node_witness_pid "$VICTIM" 2>/dev/null || echo ""
    else
        stagef_node_core_pid "$VICTIM" 2>/dev/null || echo ""
    fi
}
cpu_ticks() {
    local pid="$1" rest
    [ -n "$pid" ] && [ -r "/proc/$pid/stat" ] || { echo -1; return 0; }
    rest=$(cat "/proc/$pid/stat" 2>/dev/null) || { echo -1; return 0; }
    rest="${rest##*) }"
    # shellcheck disable=SC2086
    set -- $rest
    echo $(( ${12} + ${13} ))
}
CLK_TCK=$(getconf CLK_TCK)

# ── run ONE phase: drive HEIGHTS heights (background pump) while sampling
#    the reference node once a second; with_flood=1 also runs the flood
#    tool against the victim for the whole window. Sets, by phase prefix:
#      <P>_blocks <P>_wall_s <P>_iv_mean <P>_iv_max <P>_lag_max
#      <P>_cpu <P>_att (a "node:delta|..." string, or "boundary")
#    and copies the flood stats file. ───────────────────────────────────
run_phase() {
    local P="$1" with_flood="$2"
    local start_h target end_target csv heights_f sidx last since
    csv="$FLOOD_DIR/${P}_poll.csv"
    heights_f="$FLOOD_DIR/${P}_heights.txt"
    : > "$heights_f"
    echo "phase,poll,wall_ms,ref_tip,victim_tip,tip_lag,$(for n in $(seq 1 "$C"); do printf 'sc_%d,' "$n"; done | sed 's/,$//')" > "$csv"

    start_h=$(stagef_cmt_tip "$REF_DB")
    [ "$start_h" -ge 0 ] || die "$P: reference node$REF has no Comet block yet"
    target=$(( start_h + HEIGHTS ))
    # drive a little past the window so a spend is in flight THROUGHOUT it
    end_target=$(( target + 5 ))

    # attendance snapshot at the window start (one sqlite statement:
    # field 0 = tip, fields 1..C = each validator's signed_count)
    declare -a sc_start
    local row
    row=$(sqlite3 -readonly "$REF_DB" "$REF_SQL" 2>/dev/null) || die "$P: reference read failed"
    local -a F
    IFS='|' read -ra F <<< "$row"
    for n in $(seq 1 "$C"); do sc_start[$n]="${F[$n]}"; done

    # background pump toward end_target (keeps the chain at commit pace)
    local pump_log="$FLOOD_DIR/${P}_pump.log"
    stagef_cmt_pump_to "$REF_DB" "$end_target" > "$pump_log" 2>&1 &
    local pump_pid=$!

    # flood (phase B only): a generous --seconds upper bound; we SIGTERM it
    # at the window boundary and it then writes its stats and exits 0.
    local flood_pid="" flood_log="" flood_stats="" flood_secs
    if [ "$with_flood" = 1 ]; then
        flood_log="$FLOOD_DIR/flood.log"
        flood_stats="$FLOOD_DIR/flood_stats.txt"
        flood_secs=$(( HEIGHTS * STAGEF_CMT_PUMP_BLOCK_S * 4 + 120 ))
        local extra=()
        if [ "$MODE" = v3-block ]; then
            extra=(--height "$start_h")
        elif [ "$MODE" = balance ]; then
            local funder_fp
            funder_fp=$(cat "$BASE_DIR/node$STAGEF_PUMP_FUNDER_NODE/identity/nodus.fp" 2>/dev/null || true)
            [ "${#funder_fp}" = 128 ] || die "$P: could not read funder fp for balance mode"
            extra=(--owner "$funder_fp")
        fi
        "$BIN" --host 127.0.0.1 --port "$VICTIM_PORT" --mode "$MODE" \
               --sessions "$SESSIONS" --threads "$THREADS" \
               --seconds "$flood_secs" --stats-file "$flood_stats" \
               "${extra[@]}" > "$flood_log" 2>&1 &
        flood_pid=$!
        # readiness: the tool prints a proof/info line once connected and
        # built; wait (bounded, 120 x 0.5 s) for that OR an early exit.
        local ready=0 k
        for k in $(seq 1 120); do
            if grep -q -E '^\[proof\]|^\[info\]' "$flood_log" 2>/dev/null; then ready=1; break; fi
            if ! kill -0 "$flood_pid" 2>/dev/null; then break; fi
            sleep 0.5
        done
        if [ "$ready" != 1 ]; then
            kill "$flood_pid" 2>/dev/null || true
            wait "$flood_pid" 2>/dev/null || true
            kill "$pump_pid" 2>/dev/null || true
            wait "$pump_pid" 2>/dev/null || true
            echo "[FAIL] $P: the flood tool did not reach its request loop (connect / CheckTx-proof failed):" >&2
            tail -20 "$flood_log" >&2
            exit 1
        fi
    fi

    local cpu_pid cpu0 cpu1 wall0 wall1
    cpu_pid=$(victim_witness_pid)
    cpu0=$(cpu_ticks "$cpu_pid")
    wall0=$(now_ms)

    # ── sampler: 1 s poll of the reference, progress-bounded ──────────
    sidx=0; last="$start_h"; since=0
    local lag_max=0 ref_tip victim_tip lag
    declare -a sc_last
    for n in $(seq 1 "$C"); do sc_last[$n]="${sc_start[$n]}"; done
    while :; do
        row=$(sqlite3 -readonly "$REF_DB" "$REF_SQL" 2>/dev/null || true)
        [ -n "$row" ] || { sleep 1; continue; }
        IFS='|' read -ra F <<< "$row"
        ref_tip="${F[0]}"
        for n in $(seq 1 "$C"); do sc_last[$n]="${F[$n]}"; done
        victim_tip=$(stagef_cmt_tip "$VICTIM_DB"); [ -n "$victim_tip" ] || victim_tip=-1
        lag=$(( ref_tip - victim_tip )); [ "$lag" -lt 0 ] && lag=0
        [ "$lag" -gt "$lag_max" ] && lag_max="$lag"
        sidx=$(( sidx + 1 ))
        {
            printf '%s,%d,%s,%s,%s,%s' "$P" "$sidx" "$(now_ms)" "$ref_tip" "$victim_tip" "$lag"
            for n in $(seq 1 "$C"); do printf ',%s' "${F[$n]}"; done
            printf '\n'
        } >> "$csv"
        # record first-seen wall of each newly committed height
        if [ "$ref_tip" -gt "$last" ]; then
            local h
            for h in $(seq $(( last + 1 )) "$ref_tip"); do
                [ "$h" -gt "$start_h" ] && [ "$h" -le "$target" ] && echo "$h $(now_ms)" >> "$heights_f"
            done
            last="$ref_tip"; since=0
        else
            since=$(( since + 1 ))
        fi
        [ "$ref_tip" -ge "$target" ] && break
        # stall guard (no bare timeout: progress-bounded)
        if [ "$since" -ge "$STALL_POLLS" ]; then
            [ -n "$flood_pid" ] && { kill "$flood_pid" 2>/dev/null || true; wait "$flood_pid" 2>/dev/null || true; }
            kill "$pump_pid" 2>/dev/null || true; wait "$pump_pid" 2>/dev/null || true
            die "$P: reference tip STALLED at $ref_tip for ${STALL_POLLS}s (pump dead? see $pump_log)"
        fi
        # the background pump finishing early without reaching the window
        # is a setup fault, not a reason to idle on
        if ! kill -0 "$pump_pid" 2>/dev/null && [ "$ref_tip" -lt "$target" ]; then
            local prc=0
            wait "$pump_pid" 2>/dev/null || prc=$?
            if [ "$prc" != 0 ]; then
                [ -n "$flood_pid" ] && { kill "$flood_pid" 2>/dev/null || true; wait "$flood_pid" 2>/dev/null || true; }
                die "$P: the pump exited rc $prc before the window completed (tip $ref_tip < $target) — see $pump_log"
            fi
            pump_pid=""   # finished cleanly past its own target; keep sampling
        fi
        sleep 1
    done
    wall1=$(now_ms)
    cpu1=$(cpu_ticks "$cpu_pid")

    # stop the flood (writes its stats), then the pump
    if [ -n "$flood_pid" ]; then
        kill "$flood_pid" 2>/dev/null || true
        wait "$flood_pid" 2>/dev/null || true
    fi
    if [ -n "$pump_pid" ]; then
        kill "$pump_pid" 2>/dev/null || true
        wait "$pump_pid" 2>/dev/null || true
    fi

    # ── window statistics ─────────────────────────────────────────────
    local wall_s iv_mean iv_max blocks
    wall_s=$(awk -v a="$wall0" -v b="$wall1" 'BEGIN { printf "%.1f", (b - a) / 1000.0 }')
    blocks=$(wc -l < "$heights_f" | tr -d ' ')
    read -r iv_mean iv_max < <(awk '{ t[NR] = $2 }
        END {
            if (NR < 2) { print "n/a", "n/a"; exit }
            mx = 0; sum = 0
            for (i = 2; i <= NR; i++) { d = (t[i] - t[i-1]) / 1000.0; sum += d; if (d > mx) mx = d }
            printf "%.2f %.2f\n", sum / (NR - 1), mx
        }' "$heights_f")   # the newline matters: read returns 1 at EOF without one (set -e)

    # attendance delta across the window, per validator; a decrease means
    # the window crossed an epoch boundary (signed_count was reset to 0)
    local att="" boundary=0 n d
    for n in $(seq 1 "$C"); do
        local s0="${sc_start[$n]}" s1="${sc_last[$n]}"
        if [ "$s1" -lt "$s0" ]; then boundary=1; att="$att node$n:reset|"; else d=$(( s1 - s0 )); att="$att node$n:+$d|"; fi
    done
    att="${att%|}"
    [ "$boundary" = 1 ] && att="$att (epoch boundary crossed — a reset is not a negative delta)"

    # victim witness CPU% over the window
    local cpu
    if [ "$cpu0" -lt 0 ] || [ "$cpu1" -lt 0 ] || [ "$cpu1" -lt "$cpu0" ]; then
        cpu="n/a (victim witness pid not readable at both ends, or restarted)"
    else
        cpu=$(awk -v d="$(( cpu1 - cpu0 ))" -v hz="$CLK_TCK" -v w="$wall_s" \
              'BEGIN { if (w <= 0) w = 0.001; printf "%.1f%%", 100 * d / hz / w }')
    fi

    # value-safe assignment to the phase-prefixed result vars (att / cpu
    # carry spaces — printf -v, never eval with an unquoted RHS)
    printf -v "${P}_blocks" '%s' "$blocks"
    printf -v "${P}_wall_s" '%s' "$wall_s"
    printf -v "${P}_iv_mean" '%s' "$iv_mean"
    printf -v "${P}_iv_max" '%s' "$iv_max"
    printf -v "${P}_lag_max" '%s' "$lag_max"
    printf -v "${P}_cpu" '%s' "$cpu"
    printf -v "${P}_att" '%s' "$att"
    echo "[ok] $P: $blocks height(s) over ${wall_s}s, mean ${iv_mean}s/height (max ${iv_max}s), victim max tip lag ${lag_max}, CPU $cpu"
}

# ── 7/7 agreement before, both phases, 7/7 agreement after ────────────
stagef_cmt_diff_at_floor "pre-rpc-flood" || exit 2

echo "[ok] phase A (baseline, no flood): driving $HEIGHTS heights"
run_phase A 0
echo "[ok] phase B (flood: $MODE, ${SESSIONS}x${THREADS} on node$VICTIM:$VICTIM_PORT): driving $HEIGHTS heights"
run_phase B 1

# wait for the victim to catch up (progress-bounded), then 7/7 at the floor
echo "[ok] waiting for victim node$VICTIM to catch up to the reference tip"
ref_now=$(stagef_cmt_tip "$REF_DB")
stagef_cmt_wait_height "$VICTIM_DB" "$ref_now" 3 >/dev/null \
    || die "victim node$VICTIM did not reach height $ref_now after the flood (replication STALLED)"

# ── summary (both phases side by side + the flood tool's stats) ───────
summary="$FLOOD_DIR/summary.txt"
{
    echo "bench_rpc_flood — $(date -u +%Y-%m-%dT%H:%M:%SZ), BASE_DIR $BASE_DIR"
    echo "parameters: victim node$VICTIM (client port $VICTIM_PORT), reference node$REF,"
    echo "            mode $MODE, sessions $SESSIONS x threads $THREADS,"
    echo "            window $HEIGHTS committed heights, STAGEF_MODE $(stagef_mode),"
    echo "            epoch length $STAGEF_EPOCH_LENGTH, pump funder node$STAGEF_PUMP_FUNDER_NODE / submit node$STAGEF_PUMP_SUBMIT_NODE, fee $FEE raw"
    echo ""
    printf '%-26s %-22s %-22s\n' "" "PHASE A (baseline)" "PHASE B (flood)"
    printf '%-26s %-22s %-22s\n' "heights committed"      "$A_blocks"  "$B_blocks"
    printf '%-26s %-22s %-22s\n' "window seconds"         "$A_wall_s"  "$B_wall_s"
    printf '%-26s %-22s %-22s\n' "sec/height mean"        "$A_iv_mean" "$B_iv_mean"
    printf '%-26s %-22s %-22s\n' "sec/height max"         "$A_iv_max"  "$B_iv_max"
    printf '%-26s %-22s %-22s\n' "victim max tip lag"     "$A_lag_max" "$B_lag_max"
    printf '%-26s %-22s %-22s\n' "victim witness CPU"     "$A_cpu"     "$B_cpu"
    echo ""
    echo "per-validator signed_count delta across the window (voter id = SHA3-512(pubkey)[0..31]):"
    echo "  phase A: $A_att"
    echo "  phase B: $B_att"
    echo ""
    echo "NO THRESHOLD IS ASSERTED. Compare the two columns; a delay under"
    echo "flood is a signal to investigate (read HOW IT CAN LIE in the header)."
    echo ""
    if [ -s "$FLOOD_DIR/flood_stats.txt" ]; then
        echo "flood tool stats (phase B):"
        sed 's/^/  /' "$FLOOD_DIR/flood_stats.txt"
    else
        echo "flood tool stats: (none written — check $FLOOD_DIR/flood.log)"
    fi
    echo ""
    echo "per-poll CSVs: $FLOOD_DIR/A_poll.csv, $FLOOD_DIR/B_poll.csv"
} > "$summary"
cat "$summary"
echo "[ok] summary: $summary"

stagef_cmt_diff_at_floor "post-rpc-flood" || { echo "[FAIL] 7/7 disagreement after the flood" | tee -a "$summary" >&2; exit 2; }
echo "7/7 agreement at the floor after the flood: OK" >> "$summary"
echo "[DONE] bench_rpc_flood: phase A vs phase B measured, 7/7 agree"
