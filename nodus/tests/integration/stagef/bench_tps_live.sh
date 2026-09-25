#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# bench_tps_live.sh — sustained CORE SPEND throughput on the LIVE 7-node
# devnet, loaded from several client machines at once
# ════════════════════════════════════════════════════════════════════
#
# THE LIVE COUNTERPART OF bench_tps_v2.sh. A STANDALONE MEASUREMENT, NOT
# A SCENARIO: it is not in genesis_protocol_v2.sh and must never be. It
# asserts no property; its only verdicts are "the load ran without a
# worker fault" and the closing agreement check over all nodes (7 on the
# live devnet). It reuses the local
# bench's worker loop, measurement queries, output shapes and honesty
# rules; what differs is (a) the chain is the live devnet reached over
# the network (every node read goes through ssh, READ-ONLY), and (b) the
# nodus-cli sessions run on SEVERAL client hosts.
#
# WHAT IT MEASURES
#   How many real CORE SPEND envelopes per second the live 7-node chain
#   commits while M parallel client sessions, spread over the client
#   hosts in BENCH_HOSTS, keep its mempool fed for D seconds. The load is
#   `nodus-cli v2-envelope spend --amount all --count all --shard R/W`,
#   exactly as in bench_tps_v2.sh. PUMP IDENTITIES: the first K of the
#   test identities in BENCH_IDENTITIES (default the 9 test_* key dirs of
#   the 2026-09-25 devnet baseline genesis under /home/nocdem/testkeys).
#   Worker I (0 <= I < M) spends identity (I mod K) + 1 with shard
#   R = I div K of W (W = that identity's worker count), runs its
#   nodus-cli on client host (I mod H) + 1, and submits to, lists on and
#   confirms on ONE node, chosen so that no two workers of one identity
#   ever share a node (a node EVICTS an older session of the same
#   identity whatever the client IP — nodus_auth.c:99-117 compares the
#   client fingerprint only, SESSION_EVICT). Each round self-sends every
#   coin of the shard it can see, then waits until every accepted spend's
#   created `utxo_set` row (tx_hash = the envelope's intent_id) exists on
#   its node, then repeats; the worker LOOP runs on the controller (this
#   machine), only the nodus-cli call runs on the client host, and the
#   confirmation is a read-only sqlite query to the node over ssh.
#   PREPARATION (before the load, resumable): every pump identity must
#   own N spendable coins (BENCH_COINS, default 150). An identity holding
#   fewer is split by HALVING rounds with the existing CLI: per round the
#   script reads ALL the identity's spendable native coins from the node
#   DB (uncapped sqlite, not the CLI's 100-row listing), sets
#   amount = (min coin - fee) / 2 and count = min(coins, N - coins, 100),
#   and runs `v2-envelope spend --to <own fp> --amount <amount> --count
#   <count>`. The CLI picks each spend's inputs largest-first until they
#   cover amount + fee (nodus-cli.c t6_spend_pick :3180-3193); every coin
#   is >= 2 x amount + fee, so every spend takes ONE coin and returns two
#   (the amount to self + the native change, :3683-3695) — the coin count
#   doubles per round: 1 -> 2 -> 4 -> ... -> 128 -> 150 = 8 rounds for
#   N = 150, the K identities in parallel. (A FIXED --amount does not
#   double: after one split the small output cannot cover amount + fee,
#   and the whole planned batch is refused before anything is sent,
#   :3589-3649.) Identities already holding >= N coins are skipped.
#   While the load runs, the controller streams ONE node's (BENCH_REF_NODE)
#   `v2_blocks` rows over a single ssh session (a read-only shell loop on
#   the node polling about once a second) and stamps every new height
#   with the CONTROLLER's clock on arrival; every node streams its own
#   nodus-server /proc/<pid>/stat and `ss -tinpH` sockets about once a
#   second over one ssh session per node (CPU and bandwidth).
#   Reported (stdout and $BENCH_OUT/summary.txt, per-block rows in
#   $BENCH_OUT/blocks.csv): parameters (hosts, K, N, M, D), committed
#   envelopes in the window, window seconds, TPS, blocks, mean / max / p50
#   envelopes per block, mean / max observed block interval, the
#   theoretical per-block cap floor(NODUS_V2_GLOBAL_UNIT_BUDGET / the
#   declared units) next to the measured max, per-node CPU%, per-node
#   bandwidth by port class (bandwidth_node<N>.csv), NETSTATS deltas per
#   node / direction / channel / kind (netstats.csv, read from journald),
#   per-worker counts, the measured controller->node ssh round trip, the
#   node clock offsets, and the closing agreement of all nodes (7 on the
#   live devnet) at a common height.
#
# WHAT IT REQUIRES
#   Compile flags: none beyond a default build. The per-block cap is read
#   from THIS tree's nodus/src/witness/nodus_witness_v2_apply.h
#   (NODUS_V2_GLOBAL_UNIT_BUDGET) and NODUS_CMT_NET_STATS_PERIOD_S from
#   nodus_witness_cmt_net.h: the live nodes must run a binary built from
#   the same source, and every client host's nodus-cli should too (the CLI
#   takes the CORE ruleset from its own compiled table; the summary warns
#   when the CLIs declared different unit ceilings).
#   Controller (this machine): bash >= 4.4 (checked at start: empty-array
#   expansion under `set -u`, `printf %(...)T`), ssh (OpenSSH,
#   ControlMaster), awk, sort, pgrep / pkill (procps), a nodus-cli (BENCH_CTRL_CLI, default this
#   tree's nodus/build/nodus-cli) for the preparation and cluster-status,
#   and read access to the test key dirs (BENCH_KEYS_SRC).
#   Nodes: `ssh -o BatchMode=yes root@<ip>` from the controller (key auth,
#   no prompt); on each node: sqlite3, ss (iproute2; a node whose
#   `ss -tinpH` prints no bytes_received / bytes_acked counters at start
#   has its bandwidth SKIPPED, the rest still runs), journalctl,
#   systemctl, getconf, nproc, awk; the systemd
#   unit BENCH_NODE_UNIT (default `nodus`) running nodus-server; exactly
#   ONE chain DB matching BENCH_NODE_DATA_DIR/witness_*.db. Every one of
#   these is checked at start on every node and the script refuses with
#   the reason if one is missing.
#   Client hosts (BENCH_HOSTS entries other than `local`): `ssh -o
#   BatchMode=yes <alias>` from the controller, an executable nodus-cli at
#   the given path, a writable key directory path (the script copies the
#   test key dirs there), chmod and GNU `stat -c` (the key modes are set
#   and read back), pkill (only used on abort). The script installs
#   nothing and clones nothing.
#   Chain: the live version-3 chain with every pump identity's genesis
#   allocation CLAIMED (at least one spendable native coin each). The
#   script never claims.
#   Environment (all optional):
#     BENCH_HOSTS        space-separated client host specs
#                        `<host>:<nodus-cli path>:<key dir>`; <host> is
#                        `local` (this machine; key dir `-` = read the
#                        keys straight from BENCH_KEYS_SRC) or an ssh
#                        destination/alias. Default
#                        `local:<tree>/nodus/build/nodus-cli:-`.
#     BENCH_KEYS_SRC     /home/nocdem/testkeys
#     BENCH_IDENTITIES   the 9 test_* dir names (order = identity 1..9)
#     BENCH_K            pump identities used, default all listed
#     BENCH_COINS        N, coins per identity, default 150
#     BENCH_WORKERS      M, default K (one worker per identity)
#     BENCH_DURATION_S   D, default 600 — how long workers START rounds
#     BENCH_OUT          output dir, default /tmp/bench_tps_live.<UTC>
#     BENCH_NODES        the 7 node IPs (default the live devnet)
#     BENCH_NODE_NAMES   their labels (default EU-1..EU-6 US-1)
#     BENCH_NODE_USER    root · BENCH_NODE_UNIT nodus
#     BENCH_NODE_DATA_DIR  /var/lib/nodus/data
#     BENCH_REF_NODE     1 (the node whose v2_blocks is polled)
#     BENCH_CLIENT_IPS   optional: the public IPs the client hosts reach
#                        the nodes from; client-port sockets from these
#                        IPs are reported as in_client_bench
#     BENCH_FEE_RAW      1000000 = the CLI default max(DNAC_MIN_FEE_RAW,
#                        NODUS_W_BASE_TX_FEE) (dnac.h:143,
#                        nodus_types.h:266)
#     BENCH_MAX_SSH_SESSIONS  10 = sshd's default MaxSessions; the bench
#                        keeps concurrent sessions per target <= this - 1
#                        (see HOW IT CAN LIE)
#
# WHAT IT LEAVES BEHIND
#   ON THE LIVE CHAIN: the pump identities' coins SPLIT into N coins each
#   (preparation; each split spend pays one fee), then churned: every
#   coin a worker spent replaced by one coin BENCH_FEE_RAW smaller (coin
#   count unchanged). Every fee (preparation and load) goes to the reward
#   pool (docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md
#   §1; the chain credits it there, nodus-cli.c cmd_v2_spend header). The
#   chain many blocks further on. Nothing is stopped, restarted or
#   written on any node: every node command is read-only (sqlite3
#   -readonly, journalctl, ss, /proc, systemctl show). NOTE: SQLite
#   readers of a WAL database update the read marks in its -shm shared
#   memory index — that is how any WAL reader works; no file is created.
#   ON EACH REMOTE CLIENT HOST: a copy of every test identity dir that
#   host's workers use (nodus.pk, .sk, .fp, .kyber_pk/_sk, .mlkem_pk/_sk;
#   the whole dir, because nodus_identity_load GENERATES and WRITES the
#   KEM files when they are missing, nodus_identity.c:430-470) under its
#   <key dir>/<identity name>, mode 0700 / 0600. Not removed at the end —
#   they are test keys; remove them by hand when the host is done.
#   ON THIS MACHINE: $BENCH_OUT (summary.txt, blocks.csv, blocks.raw,
#   prep_<identity>.log, worker_<I>.log / .stats, node_<N>.stream,
#   bw_samples.raw, bandwidth_node<N>.csv, netstats_node<N>.start / .end,
#   netstats_node<N>.jstart / .jend (the journald slices), netstats_delta.raw,
#   netstats.csv, nodes.txt, agreement.txt, cluster_status.txt) and a
#   short-lived ssh ControlMaster socket dir /tmp/btl.XXXXXX (removed at
#   exit; a master left by a killed run exits after 600 s idle).
#   On EVERY exit path (normal end, a fault, Ctrl-C / TERM) the cleanup
#   kills what this script started, and it always runs to its end: its
#   first act is to re-route INT, TERM and HUP to a one-line log, so a
#   second Ctrl-C / TERM during the cleanup cannot skip the KILL pass,
#   the survivor check, the remote pkill or the ssh master close.
#   Every preparation job and every
#   worker is started in its OWN process group (`set -m` around the `&`),
#   so the cleanup signals the whole group — the job's subshells, its
#   command-substitution subshell and the nodus-cli / ssh it is running —
#   with TERM, then KILL for whatever is left after 1 s. (nodus-cli
#   ignores SIGINT during `v2-envelope spend`: nodus-cli.c:116-119 only
#   clears a flag that cmd_v2_spend never reads — so it must be KILLED,
#   and a Ctrl-C at the terminal reaches only this script, whose trap
#   then kills the groups.) Afterwards it runs `pgrep -af 'v2-envelope
#   spend --keys <dir>/'` on THIS machine for every key dir it used and
#   prints a [warn] naming every survivor. When a worker had started, it
#   also runs `pkill -f` with the same pattern on every remote client
#   host and prints the hosts where that failed. A spend a killed
#   nodus-cli had ALREADY submitted may still commit — a kill stops
#   further submissions, it cannot recall one. The remote read-only shell
#   loops on the nodes end at their next write after their ssh session is
#   gone (<= 1 s for the samplers; the block poller writes only when a
#   block arrives, so <= one block interval); if the controller dies
#   without closing them they also stop by themselves after D + 1800
#   iterations.
#
# HOW IT CAN LIE
#   - **Real network, but not the network's clients.** Node-to-node
#     latency and bandwidth are real now. The client hosts are the
#     operator's machines, not a population of wallets: their location,
#     their link to each node and their CPU (every spend is an ML-DSA-87
#     signature plus a session handshake) shape the offered load. The
#     summary prints the hosts; a TPS measured from one host is that
#     host's.
#   - **1 s polling granularity, plus one-way ssh latency.** Block times
#     are the controller's FIRST SIGHTING of each height of ONE node
#     (BENCH_REF_NODE), polled about once a second on the node and stamped
#     here when the line arrives (+ roughly half the printed ssh round
#     trip) — not the header's BFT time (v2_blocks has no timestamp
#     column). Two heights in one poll get a 0 s interval. TPS over 600 s
#     is good to about ±1-2 s / window; single intervals are not.
#   - **One polling node.** Other nodes may commit a height earlier or
#     later than the reference node applies it; the window is that node's.
#   - **CLIENT PACING.** If the measured max per block is BELOW the unit
#     cap, no block was full and the CLIENTS were the bottleneck — the TPS
#     is a floor on the chain's capacity, and the summary says so. On the
#     live chain every worker round pays a fresh session (Kyber/ML-KEM
#     handshake + auth) across a real link, and a confirmation poll that
#     is an ssh round trip from the controller to the node per second.
#   - **The 100-row listing cap bounds what is in flight.** dnac_utxo
#     returns at most NODUS_DNAC_MAX_UTXO_RESULTS = 100 rows per identity
#     with no ORDER BY before its LIMIT; the in-flight bound is
#     ≈ Σ over identities with a worker of min(100, N) (K = 9, N = 150:
#     900) and the summary prints it, with a STRUCTURAL line when it is
#     below the cap. The preparation reads coin counts from the node DB
#     directly, so it is not bounded by that cap.
#   - **Today's unit budget only.** The cap is arithmetic (budget / the
#     CLI's declared units), exactly as in bench_tps_v2.sh's header; a
#     different budget, weight, auth size or ceiling rule is a different
#     cap. The byte bound and Block.MaxBytes are not reported.
#   - **The live DHT shares the nodes.** nodus-server also serves real
#     Connect clients and DHT replication while the bench runs. CPU% is
#     the whole process. Bandwidth is split by port class: in_witness /
#     out_witness (4004) carry consensus only; in_internode / out_internode
#     (4002) are DHT replication, NOT consensus; in_client (4001) mixes
#     real users with the bench's own sessions — separated ONLY when
#     BENCH_CLIENT_IPS names the client hosts' public IPs (then
#     in_client_bench), otherwise NOT separated and the summary says so.
#     UDP 4000 (Kademlia) is never seen (`ss -t`). NETSTATS counts the
#     witness port only, so it is not polluted by the DHT.
#   - **Bandwidth is TCP payload, sampled ~1 s.** Same rules as the local
#     bench (bytes_sent / bytes_acked, bytes_received; last value per
#     socket; baseline = the node's first sample; a socket opened and
#     closed between samples is missed; a counter going down = key
#     re-use). Each node's window is its OWN first-to-last sample span on
#     its own clock (printed), not the controller's load window; the
#     sampler's own ssh session (port 22) is outside every class.
#   - **NETSTATS come from journald.** The start / end values are the
#     newest COMPLETE snapshot (end line present, data-line count =
#     lines=) in `journalctl -u <unit> --since @<edge - 2 periods - 10 s>
#     --until @<edge>` — journald's receive time decides the slice, the
#     snapshot's own t= is the node's clock (offsets are printed against
#     the controller's edge together with the measured clock offset). A
#     restart between the edges is detected by the unit's MainPID changing
#     or a counter going down; journald rate limiting or a cut slice fails
#     the line count and the previous snapshot is used. `--since @<epoch>`
#     is assumed to be supported by the nodes' journalctl (systemd.time
#     epoch syntax) — a node whose query fails is SKIPPED, never zeroed.
#   - **Refused and dropped spends are COUNTED, never retried silently**,
#     with the local bench's inline stagef_cmt_wait_row rules: stall =
#     180 s (3 x the 60 s idle interval, stagef_env.sh:466) of WALL CLOCK
#     with the node's tip not moving -> the worker FAILS and the bench
#     aborts; budget = 20 heights past the submission tip -> the missing
#     spends are counted as DROPPED. Wall clock, not a poll count, because
#     a poll here costs an ssh round trip.
#   - **tx_count counts applied envelopes of ANYONE.** The live chain may
#     carry other users' envelopes; the summary prints the workers' own
#     applied total next to Σ tx_count so a stray submitter shows.
#   - **The fencepost** is the local bench's: TPS = envelopes in window
#     blocks 2..n / (first-seen(n) - first-seen(1)).
#   - **The preparation is part of the chain's history, not of the
#     window.** Its blocks precede LOAD_START and are not counted.
#   - **An unreadable node is not a height.** A failed tip read (ssh or
#     sqlite error) is re-read once a second; if no valid tip comes back
#     for STALL_S (180 s) the node is declared UNREACHABLE and the worker
#     (or the preparation) FAILS with that status — never counted as a
#     stall, and never folded into DROPPED spends. The two clocks are
#     independent: the time a node was unreadable is kept off the stall
#     clock, which counts readable time without progress only.
#   - **ssh session limit per target.** Every node and client host is
#     reached through ONE ssh ControlMaster connection, and sshd allows at
#     most MaxSessions sessions per connection (sshd_config default 10;
#     the nodes' / hosts' actual setting is NOT read by this script). The
#     bench refuses a placement whose concurrent sessions on one target —
#     node: its workers' confirmation polls + its sampler (+ the block
#     poller on the reference node), or its preparation jobs; client
#     host: its workers — exceed BENCH_MAX_SSH_SESSIONS - 1 (default
#     10 - 1 = 9: the default MaxSessions, minus one kept free for the
#     controller's own one-off commands). If a target's sshd is set lower,
#     a session is refused, ssh exits 255 and the worker FAILS loudly.
#
# Exit: 0 load ran + every node agrees · 1 setup or worker fault ·
#       2 divergence (two readable nodes differ at the floor height) ·
#       3 incomplete: the READABLE nodes agree at the floor of their tips,
#         but at least one node (tip or row) could not be checked, or
#         fewer than 2 nodes were readable — a divergence on an unchecked
#         node is NOT excluded (a divergence among readable nodes is 2) ·
#       129 hang-up (HUP) · 130 interrupted (INT / TERM) — in both cases
#         the cleanup still ran to its end.
# ════════════════════════════════════════════════════════════════════
set -uo pipefail

if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    echo "[FAIL] bash >= 4.4 required (this is $BASH_VERSION): empty-array expansion under set -u" >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd) || { echo "[FAIL] cannot resolve the script dir" >&2; exit 1; }
REPO_ROOT=$(cd "$SCRIPT_DIR/../../../.." && pwd) || { echo "[FAIL] cannot resolve the repo root" >&2; exit 1; }
APPLY_H="$REPO_ROOT/nodus/src/witness/nodus_witness_v2_apply.h"
NS_H="$REPO_ROOT/nodus/src/witness/nodus_witness_cmt_net.h"

die() { echo "[FAIL] $*" >&2; exit 1; }

# ── parameters ───────────────────────────────────────────────────────
BENCH_KEYS_SRC="${BENCH_KEYS_SRC:-/home/nocdem/testkeys}"
BENCH_IDENTITIES="${BENCH_IDENTITIES:-test_pool_storage test_pool_compute test_pool_vpn_bandwidth test_pool_future_services test_pool_security_bug_bounty test_pool_liquidity test_pool_ecosystem_grants test_pool_community_airdrop test_foundation}"
BENCH_CTRL_CLI="${BENCH_CTRL_CLI:-$REPO_ROOT/nodus/build/nodus-cli}"
BENCH_HOSTS="${BENCH_HOSTS:-local:$REPO_ROOT/nodus/build/nodus-cli:-}"
BENCH_NODES="${BENCH_NODES:-161.97.85.25 156.67.24.125 156.67.25.251 164.68.105.227 164.68.116.180 75.119.141.51 154.38.182.161}"
BENCH_NODE_NAMES="${BENCH_NODE_NAMES:-EU-1 EU-2 EU-3 EU-4 EU-5 EU-6 US-1}"
NODE_USER="${BENCH_NODE_USER:-root}"
NODE_UNIT="${BENCH_NODE_UNIT:-nodus}"
NODE_DATA_DIR="${BENCH_NODE_DATA_DIR:-/var/lib/nodus/data}"
REF="${BENCH_REF_NODE:-1}"
N_COINS="${BENCH_COINS:-150}"
D="${BENCH_DURATION_S:-600}"
FEE="${BENCH_FEE_RAW:-1000000}"
BENCH_CLIENT_IPS="${BENCH_CLIENT_IPS:-}"
MAX_SESS="${BENCH_MAX_SSH_SESSIONS:-10}"
BENCH_OUT="${BENCH_OUT:-/tmp/bench_tps_live.$(date -u +%Y%m%dT%H%M%SZ)}"
# The live port map (nodus_types.h:94 NODUS_DEFAULT_TCP_PORT 4001; root
# CLAUDE.md "Ports"): base + 1 client, + 2 inter-node, + 3 channel,
# + 4 witness.
PORT_BASE=4000
CPORT=$(( PORT_BASE + 1 ))
MAX_HEIGHTS=20                      # stagef_cmt_wait_row's default budget
STALL_S=180                         # 3 x STAGEF_CMT_EMPTY_INTERVAL_MS (60 s)
LOOP_EXTRA=1800                     # remote loops stop by themselves after D + this

safe_word() {   # refuse anything that would need shell quoting remotely
    case "$1" in ''|*[!A-Za-z0-9_.@/+=-]*) return 1 ;; esac
    return 0
}
is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; return 0; }

is_uint "$N_COINS" && [ "$N_COINS" -ge 1 ] || die "BENCH_COINS must be a positive integer (got '$N_COINS')"
is_uint "$D" && [ "$D" -ge 1 ] || die "BENCH_DURATION_S must be a positive integer (got '$D')"
is_uint "$FEE" && [ "$FEE" -ge 1000000 ] || die "BENCH_FEE_RAW must be an integer >= 1000000, the chain's fee floor (got '$FEE')"
is_uint "$REF" || die "BENCH_REF_NODE must be an integer (got '$REF')"
is_uint "$MAX_SESS" && [ "$MAX_SESS" -ge 2 ] || die "BENCH_MAX_SSH_SESSIONS must be an integer >= 2 (got '$MAX_SESS')"
SESS_BOUND=$(( MAX_SESS - 1 ))     # one session kept free for the controller's own commands
# every file of an identity dir: nodus_identity_load GENERATES and WRITES
# the kyber / mlkem files when they are missing (nodus_identity.c:446-452
# and the ML-KEM branch after it) — a partial dir would be modified
KEY_FILES="nodus.pk nodus.sk nodus.fp nodus.kyber_pk nodus.kyber_sk nodus.mlkem_pk nodus.mlkem_sk"

# nodes
read -r -a NODE_IP_LIST <<< "$BENCH_NODES"
read -r -a NODE_NAME_LIST <<< "$BENCH_NODE_NAMES"
NN=${#NODE_IP_LIST[@]}
[ "$NN" -ge 1 ] || die "BENCH_NODES is empty"
[ "${#NODE_NAME_LIST[@]}" = "$NN" ] || die "BENCH_NODE_NAMES has ${#NODE_NAME_LIST[@]} names for $NN nodes"
[ "$REF" -ge 1 ] && [ "$REF" -le "$NN" ] || die "BENCH_REF_NODE must be 1..$NN"
declare -a NODE_IP NODE_NAME
for n in $(seq 1 "$NN"); do
    NODE_IP[n]="${NODE_IP_LIST[$(( n - 1 ))]}"
    NODE_NAME[n]="${NODE_NAME_LIST[$(( n - 1 ))]}"
    safe_word "${NODE_IP[n]}" || die "node address '${NODE_IP[n]}' has characters this script will not pass to ssh"
done
safe_word "$NODE_USER" && safe_word "$NODE_UNIT" && safe_word "$NODE_DATA_DIR" \
    || die "BENCH_NODE_USER / BENCH_NODE_UNIT / BENCH_NODE_DATA_DIR contain characters this script will not pass to ssh"

# identities
read -r -a ID_LIST <<< "$BENCH_IDENTITIES"
K="${BENCH_K:-${#ID_LIST[@]}}"
is_uint "$K" && [ "$K" -ge 1 ] && [ "$K" -le "${#ID_LIST[@]}" ] || die "BENCH_K must be 1..${#ID_LIST[@]} (got '$K')"
M="${BENCH_WORKERS:-$K}"
is_uint "$M" && [ "$M" -ge 1 ] || die "BENCH_WORKERS must be a positive integer (got '$M')"
# a node evicts an older session of the same identity (SESSION_EVICT,
# nodus_auth.c:99-117), so one identity can have at most NN concurrent
# workers (one per node); --shard caps W at NODUS_DNAC_MAX_UTXO_RESULTS
# (nodus-cli.c:3386, 100)
[ "$M" -le $(( NN * K )) ] || die "BENCH_WORKERS=$M > $NN nodes x $K identities: two workers of one identity would share a node and evict each other's session (SESSION_EVICT)"
declare -a PK_NAME PK_DIR PK_FP PK_WORKERS
for j in $(seq 1 "$K"); do
    PK_NAME[j]="${ID_LIST[$(( j - 1 ))]}"
    safe_word "${PK_NAME[j]}" || die "identity name '${PK_NAME[j]}' has unsafe characters"
    PK_DIR[j]="$BENCH_KEYS_SRC/${PK_NAME[j]}"
    for f in $KEY_FILES; do
        [ -s "${PK_DIR[j]}/$f" ] || die "identity ${PK_NAME[j]}: ${PK_DIR[j]}/$f missing or empty — all 7 identity files are required (nodus-cli would generate and WRITE missing KEM files into the key dir)"
    done
    PK_FP[j]=$(tr -d '\n' < "${PK_DIR[j]}/nodus.fp")
    case "${PK_FP[j]}" in *[!0-9a-f]*) die "identity ${PK_NAME[j]}: nodus.fp is not lowercase hex" ;; esac
    [ "${#PK_FP[j]}" = 128 ] || die "identity ${PK_NAME[j]}: nodus.fp is not 128 hex chars"
    if [ $(( j - 1 )) -lt "$M" ]; then PK_WORKERS[j]=$(( (M - 1 - (j - 1)) / K + 1 )); else PK_WORKERS[j]=0; fi
done

# client hosts
read -r -a HOST_SPECS <<< "$BENCH_HOSTS"
H=${#HOST_SPECS[@]}
[ "$H" -ge 1 ] || die "BENCH_HOSTS is empty"
declare -a HOST_NAME HOST_CLI HOST_KEYS
for i in $(seq 0 $(( H - 1 ))); do
    IFS=: read -r h_name h_cli h_keys h_rest <<< "${HOST_SPECS[$i]}"
    [ -z "${h_rest:-}" ] || die "host spec '${HOST_SPECS[$i]}' has more than 3 ':' fields"
    [ -n "${h_name:-}" ] && [ -n "${h_cli:-}" ] && [ -n "${h_keys:-}" ] \
        || die "host spec '${HOST_SPECS[$i]}' must be <host>:<nodus-cli path>:<key dir>"
    safe_word "$h_name" && safe_word "$h_cli" && safe_word "$h_keys" \
        || die "host spec '${HOST_SPECS[$i]}' has characters this script will not pass to ssh"
    HOST_NAME[i]="$h_name"; HOST_CLI[i]="$h_cli"
    if [ "$h_name" = local ]; then
        [ "$h_keys" = - ] || [ "$h_keys" = "$BENCH_KEYS_SRC" ] \
            || die "host 'local' reads the keys from BENCH_KEYS_SRC; its key dir must be '-' (got '$h_keys')"
        HOST_KEYS[i]="$BENCH_KEYS_SRC"
        [ -x "$h_cli" ] || die "host local: no executable nodus-cli at $h_cli"
    else
        [ "$h_keys" != - ] || die "host '$h_name': a remote host needs a key dir path, not '-'"
        HOST_KEYS[i]="$h_keys"
    fi
done
[ -x "$BENCH_CTRL_CLI" ] || die "no controller nodus-cli at $BENCH_CTRL_CLI (BENCH_CTRL_CLI)"

BUDGET=$(awk '$1 == "#define" && $2 == "NODUS_V2_GLOBAL_UNIT_BUDGET" { v = $3; sub(/u$/, "", v); print v; exit }' "$APPLY_H" 2>/dev/null || true)
is_uint "$BUDGET" || die "could not read NODUS_V2_GLOBAL_UNIT_BUDGET from $APPLY_H"
NS_PERIOD=$(awk '$1 == "#define" && $2 == "NODUS_CMT_NET_STATS_PERIOD_S" { print $3; exit }' "$NS_H" 2>/dev/null || true)
is_uint "$NS_PERIOD" || die "could not read NODUS_CMT_NET_STATS_PERIOD_S from $NS_H"

mkdir -p "$BENCH_OUT" || die "cannot create $BENCH_OUT"
rm -f "$BENCH_OUT"/worker_*.log "$BENCH_OUT"/worker_*.stats "$BENCH_OUT"/prep_*.log \
      "$BENCH_OUT"/blocks.csv "$BENCH_OUT"/blocks.raw "$BENCH_OUT"/summary.txt \
      "$BENCH_OUT"/node_*.stream "$BENCH_OUT"/bw_samples.raw "$BENCH_OUT"/bandwidth_node*.csv \
      "$BENCH_OUT"/netstats* "$BENCH_OUT"/agreement.txt "$BENCH_OUT"/cluster_status.txt \
      "$BENCH_OUT"/nodes.txt

# ── ssh plumbing: one ControlMaster per target, closed at exit ───────
CTL_DIR=$(mktemp -d /tmp/btl.XXXXXX) || die "mktemp for the ssh control dir failed"
SSH_BASE=(-o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=15
          -o ServerAliveCountMax=4 -o ControlMaster=auto
          -o "ControlPath=$CTL_DIR/%C" -o ControlPersist=600)
declare -A CTL_TARGETS=()
node_target() { echo "$NODE_USER@${NODE_IP[$1]}"; }
# node_ssh N CMD — a read-only command on node N (stdin not read)
node_ssh() {
    CTL_TARGETS["$(node_target "$1")"]=1
    ssh -n "${SSH_BASE[@]}" "$(node_target "$1")" "$2"
}
# node_sql N SQL — read-only sqlite3 on node N's chain DB; the SQL goes
# over stdin, so it is never re-parsed by the remote shell
declare -a NODE_DB
node_sql() {
    CTL_TARGETS["$(node_target "$1")"]=1
    printf '.timeout 5000\n%s\n' "$2" | \
        ssh "${SSH_BASE[@]}" "$(node_target "$1")" "sqlite3 -readonly '${NODE_DB[$1]}'"
}
node_tip() {   # ONE read; -1 = unreadable — NEVER use it as a height
    local t
    t=$(node_sql "$1" "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;" 2>/dev/null) || t=-1
    is_uint "$t" || t=-1
    echo "$t"
}
# node_tip_valid N — a VALID tip of node N: re-reads once a second until
# one comes back; rc 1 (prints -1) when none did for STALL_S seconds —
# the node is UNREACHABLE, a status of its own (never a height, never a
# stall, never DROPPED spends)
node_tip_valid() {
    local t first
    first=$(date +%s)
    while :; do
        t=$(node_tip "$1")
        if [ "$t" -ge 0 ]; then echo "$t"; return 0; fi
        if [ $(( $(date +%s) - first )) -ge "$STALL_S" ]; then echo -1; return 1; fi
        sleep 1
    done
}
# run_cli HOSTIDX ARGS... — nodus-cli on client host HOSTIDX (args are
# safe_word-checked or digits; nothing needs quoting)
run_cli() {
    local hi="$1"; shift
    if [ "${HOST_NAME[$hi]}" = local ]; then
        "${HOST_CLI[$hi]}" "$@"
    else
        CTL_TARGETS["${HOST_NAME[$hi]}"]=1
        ssh -n "${SSH_BASE[@]}" "${HOST_NAME[$hi]}" "${HOST_CLI[$hi]} $*"
    fi
}
now_ms() { date +%s%3N; }

# ── cleanup: kill what this script started; say what it could not ────
# WPIDS = the preparation jobs and the workers. Each is started with
# `set -m` on, so it is the LEADER of its own process group (pgid = its
# pid) and everything it forks — the command-substitution subshell, the
# nodus-cli, the ssh — stays in that group; killing the group reaches the
# grandchildren a plain `kill <pid>` / `pkill -P <pid>` would orphan.
declare -a WPIDS=() STREAM_PIDS=()
ABORTING=1
WORKERS_STARTED=0
# start_job VAR FUNC ARGS... — run FUNC ARGS in the background in its own
# process group; its pid (= pgid) is stored in VAR (a name[index] string)
start_job() {
    local var="$1"; shift
    set -m
    "$@" &
    printf -v "$var" '%s' "$!"
    set +m
}
# kill_groups PGID... — TERM each whole group, then KILL what is left
# after 1 s (nodus-cli does not stop on SIGINT, nodus-cli.c:116-119)
kill_groups() {
    local p left=0
    for p in "$@"; do
        [ -n "$p" ] || continue
        kill -TERM -- "-$p" 2>/dev/null && left=1
    done
    [ "$left" = 1 ] || return 0
    sleep 1
    for p in "$@"; do
        [ -n "$p" ] || continue
        kill -0 -- "-$p" 2>/dev/null && kill -KILL -- "-$p" 2>/dev/null
    done
}
# local_survivors — every nodus-cli spend of this bench's key dirs still
# alive on THIS machine (the pattern the remote pkill uses), one [warn]
# line per survivor; covers local-host workers, the preparation's spends
# and the ssh processes that carry remote-host spends
local_survivors() {
    local kd seen=" " line
    for kd in "$BENCH_KEYS_SRC" "${HOST_KEYS[@]}"; do
        case "$seen" in *" $kd "*) continue ;; esac
        seen="$seen$kd "
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            echo "[warn] still running on this machine after the cleanup (kill it by hand): $line" >&2
        done < <(pgrep -af -- "v2-envelope spend --keys $kd/" 2>/dev/null)
    done
}
cleanup() {
    local p rc hi
    # a second INT / TERM / HUP must not cut the cleanup short (it would
    # skip the KILL pass, the survivor check, the remote pkill and the
    # master close): from here on those signals only log a line, and the
    # cleanup always runs to its end
    trap 'echo "[info] signal received during cleanup — ignored, the cleanup finishes first" >&2' INT TERM HUP
    kill_groups "${WPIDS[@]}"
    for p in "${STREAM_PIDS[@]}"; do
        [ -n "$p" ] || continue
        kill "$p" 2>/dev/null
    done
    sleep 1
    for p in "${STREAM_PIDS[@]}"; do
        [ -n "$p" ] || continue
        if kill -0 "$p" 2>/dev/null; then
            echo "[warn] could not kill local stream process $p" >&2
        fi
    done
    for p in "${WPIDS[@]}"; do
        [ -n "$p" ] || continue
        if kill -0 -- "-$p" 2>/dev/null; then
            echo "[warn] process group $p (a preparation job or worker) still has live members after TERM + KILL" >&2
        fi
    done
    local_survivors
    if [ "$ABORTING" = 1 ] && [ "$WORKERS_STARTED" = 1 ]; then
        for hi in $(seq 0 $(( H - 1 ))); do
            [ "${HOST_NAME[$hi]}" != local ] || continue
            rc=0
            ssh -n "${SSH_BASE[@]}" "${HOST_NAME[$hi]}" \
                "pkill -f -- 'v2-envelope spend --keys ${HOST_KEYS[$hi]}/'" 2>/dev/null || rc=$?
            case "$rc" in
                0) echo "[info] host ${HOST_NAME[$hi]}: killed its running nodus-cli spend(s)" >&2 ;;
                1) ;;   # nothing was running
                *) echo "[warn] host ${HOST_NAME[$hi]}: could not run pkill (rc $rc) — a nodus-cli spend there may still finish its batch on its own" >&2 ;;
            esac
        done
    fi
    for p in "${!CTL_TARGETS[@]}"; do
        ssh "${SSH_BASE[@]}" -O exit "$p" >/dev/null 2>&1
    done
    rm -rf "$CTL_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
# HUP (terminal gone): trapped explicitly so the EXIT-trap cleanup is
# guaranteed to run; 129 = 128 + SIGHUP keeps it distinguishable from an
# interrupt
trap 'exit 129' HUP

# ── (0) every node: tools, the chain DB, the process, clock, latency ─
NODE_CHECK_SH='
set -u
d="$1"; u="$2"
for t in sqlite3 ss journalctl systemctl getconf nproc awk; do
    command -v "$t" >/dev/null 2>&1 || { echo "ERR missing tool: $t"; exit 3; }
done
set -- "$d"/witness_*.db
if [ "$#" != 1 ] || [ ! -f "$1" ]; then echo "ERR expected exactly one $d/witness_*.db, found: $*"; exit 3; fi
echo "DB $1"
pid=$(systemctl show -p MainPID --value "$u" 2>/dev/null)
case "$pid" in ""|0|*[!0-9]*) echo "ERR unit $u has no MainPID (not running?)"; exit 3 ;; esac
echo "PID $pid"
echo "COMM $(cat /proc/$pid/comm 2>/dev/null)"
echo "HZ $(getconf CLK_TCK)"
echo "NPROC $(nproc)"
echo "NOW $(date +%s)"
echo "BW $(ss -tinpH 2>/dev/null | grep -c -e bytes_received: -e bytes_acked:)"
'
declare -a NODE_PID0 NODE_HZ NODE_NPROC NODE_SKEW NODE_RTT_MS NODE_BW
{
    echo "node,name,ip,db,pid,hz,nproc,clock_offset_s,ssh_sql_rtt_ms"
} > "$BENCH_OUT/nodes.txt"
for n in $(seq 1 "$NN"); do
    CTL_TARGETS["$(node_target "$n")"]=1
    out=$(ssh "${SSH_BASE[@]}" "$(node_target "$n")" "sh -s -- '$NODE_DATA_DIR' '$NODE_UNIT'" <<< "$NODE_CHECK_SH" 2>&1) \
        || die "node$n ${NODE_NAME[n]} (${NODE_IP[n]}): check failed: $out"
    t_here=$(date +%s)
    NODE_DB[n]=$(printf '%s\n' "$out" | awk '$1 == "DB" { print $2 }')
    NODE_PID0[n]=$(printf '%s\n' "$out" | awk '$1 == "PID" { print $2 }')
    comm=$(printf '%s\n' "$out" | awk '$1 == "COMM" { print $2 }')
    NODE_HZ[n]=$(printf '%s\n' "$out" | awk '$1 == "HZ" { print $2 }')
    NODE_NPROC[n]=$(printf '%s\n' "$out" | awk '$1 == "NPROC" { print $2 }')
    t_node=$(printf '%s\n' "$out" | awk '$1 == "NOW" { print $2 }')
    # ss byte counters present? (bench_tps_v2.sh's probe: without them the
    # bandwidth section is SKIPPED for this node, never reported as zero)
    NODE_BW[n]=$(printf '%s\n' "$out" | awk '$1 == "BW" { print ($2 + 0 > 0) ? 1 : 0 }')
    [ "${NODE_BW[n]}" = 1 ] || echo "[info] node$n: ss -tinpH printed no bytes_received / bytes_acked counters — its bandwidth will be SKIPPED"
    safe_word "${NODE_DB[n]}" || die "node$n: chain DB path '${NODE_DB[n]}' has unsafe characters"
    [ "$comm" = nodus-server ] || die "node$n: unit $NODE_UNIT's MainPID ${NODE_PID0[n]} is '$comm', not nodus-server"
    is_uint "${NODE_HZ[n]}" && is_uint "${NODE_NPROC[n]}" && is_uint "$t_node" || die "node$n: unreadable check output: $out"
    NODE_SKEW[n]=$(( t_node - t_here ))
    has_v2=$(node_sql "$n" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>&1) \
        || die "node$n: read-only sqlite3 on ${NODE_DB[n]} failed: $has_v2"
    [ "$has_v2" = 1 ] || die "node$n: ${NODE_DB[n]} has no v2_blocks table — not a version-3 chain"
    t0=$(now_ms); node_sql "$n" "SELECT 1;" >/dev/null 2>&1 || die "node$n: sqlite round trip failed"; t1=$(now_ms)
    NODE_RTT_MS[n]=$(( t1 - t0 ))
    echo "[ok] node$n ${NODE_NAME[n]} ${NODE_IP[n]}: ${NODE_DB[n]}, nodus-server pid ${NODE_PID0[n]}, ${NODE_NPROC[n]} CPUs, clock offset ${NODE_SKEW[n]} s (1 s resolution), ssh+sqlite round trip ${NODE_RTT_MS[n]} ms"
    echo "$n,${NODE_NAME[n]},${NODE_IP[n]},${NODE_DB[n]},${NODE_PID0[n]},${NODE_HZ[n]},${NODE_NPROC[n]},${NODE_SKEW[n]},${NODE_RTT_MS[n]}" >> "$BENCH_OUT/nodes.txt"
done

# ── (0b) worker placement: identity, shard, node, host ───────────────
declare -a W_ID W_SHARD W_NODE W_HOST
declare -A TAKEN=()
for I in $(seq 0 $(( M - 1 ))); do
    pj=$(( I % K + 1 ))
    W_ID[I]=$pj
    W_SHARD[I]="$(( I / K ))/${PK_WORKERS[$pj]}"
    [ "${PK_WORKERS[$pj]}" -le 100 ] || die "identity $pj would get ${PK_WORKERS[$pj]} workers; --shard allows at most 100"
    cand=$(( I % NN )); tries=0
    while [ -n "${TAKEN[$pj:$cand]:-}" ]; do
        cand=$(( (cand + 1) % NN )); tries=$(( tries + 1 ))
        [ "$tries" -lt "$NN" ] || die "no free node for worker $I of identity $pj (every node already has one of its sessions)"
    done
    TAKEN[$pj:$cand]=1
    W_NODE[I]=$(( cand + 1 ))
    W_HOST[I]=$(( I % H ))
done
# assert: no two workers of one identity on one node
for a in $(seq 0 $(( M - 1 ))); do
    for b in $(seq $(( a + 1 )) $(( M - 1 ))); do
        if [ "${W_ID[a]}" = "${W_ID[b]}" ] && [ "${W_NODE[a]}" = "${W_NODE[b]}" ]; then
            die "placement bug: workers $a and $b share identity ${W_ID[a]} and node ${W_NODE[a]}"
        fi
    done
done
# ssh sessions per ControlMaster connection (sshd MaxSessions, default
# 10). Concurrent sessions per target, each worker holding at most ONE
# session at a time to its node and ONE to its client host:
#   node n during the load  = its workers + its sampler (+ the block
#                             poller on the reference node)
#   node n during the prep  = the identities prepared on it
#   client host             = its workers
# Refused above SESS_BOUND = BENCH_MAX_SSH_SESSIONS - 1.
for n in $(seq 1 "$NN"); do
    s=1; [ "$n" != "$REF" ] || s=2
    for I in $(seq 0 $(( M - 1 ))); do [ "${W_NODE[I]}" != "$n" ] || s=$(( s + 1 )); done
    [ "$s" -le "$SESS_BOUND" ] || die "node$n ${NODE_NAME[n]} would carry $s concurrent ssh sessions during the load (> $SESS_BOUND = BENCH_MAX_SSH_SESSIONS - 1; sshd MaxSessions default 10) — lower BENCH_WORKERS or raise BENCH_MAX_SSH_SESSIONS only if that node's sshd allows it"
    s=0
    for j in $(seq 1 "$K"); do [ $(( (j - 1) % NN + 1 )) != "$n" ] || s=$(( s + 1 )); done
    [ "$s" -le "$SESS_BOUND" ] || die "node$n would carry $s concurrent preparation ssh sessions (> $SESS_BOUND)"
done
for hi in $(seq 0 $(( H - 1 ))); do
    [ "${HOST_NAME[$hi]}" != local ] || continue
    s=0
    for I in $(seq 0 $(( M - 1 ))); do [ "${W_HOST[I]}" != "$hi" ] || s=$(( s + 1 )); done
    [ "$s" -le "$SESS_BOUND" ] || die "client host ${HOST_NAME[$hi]} would carry $s concurrent ssh sessions (> $SESS_BOUND = BENCH_MAX_SSH_SESSIONS - 1) — add hosts, lower BENCH_WORKERS, or raise BENCH_MAX_SSH_SESSIONS only if that host's sshd allows it"
done

# ── (0c) client hosts: the CLI exists, the keys each host needs ──────
for hi in $(seq 0 $(( H - 1 ))); do
    [ "${HOST_NAME[$hi]}" != local ] || continue
    hn="${HOST_NAME[$hi]}"; kd="${HOST_KEYS[$hi]}"
    CTL_TARGETS[$hn]=1
    ssh -n "${SSH_BASE[@]}" "$hn" "test -x '${HOST_CLI[$hi]}'" \
        || die "host $hn: no executable nodus-cli at ${HOST_CLI[$hi]} (or ssh failed)"
    for j in $(seq 1 "$K"); do
        used=0
        for I in $(seq 0 $(( M - 1 ))); do
            [ "${W_HOST[I]}" = "$hi" ] && [ "${W_ID[I]}" = "$j" ] && used=1
        done
        [ "$used" = 1 ] || continue
        ssh -n "${SSH_BASE[@]}" "$hn" "umask 077 && mkdir -p '$kd/${PK_NAME[j]}' && chmod 700 '$kd/${PK_NAME[j]}'" \
            || die "host $hn: cannot create / chmod $kd/${PK_NAME[j]}"
        for f in $KEY_FILES; do
            [ -s "${PK_DIR[j]}/$f" ] || die "identity ${PK_NAME[j]}: ${PK_DIR[j]}/$f missing — copying a partial identity would let nodus-cli generate and write new KEM files on $hn"
            # umask does not change an EXISTING file's mode: chmod explicitly
            ssh "${SSH_BASE[@]}" "$hn" "umask 077 && cat > '$kd/${PK_NAME[j]}/$f' && chmod 600 '$kd/${PK_NAME[j]}/$f'" < "${PK_DIR[j]}/$f" \
                || die "host $hn: copying / chmod of ${PK_NAME[j]}/$f failed"
        done
        rfp=$(ssh -n "${SSH_BASE[@]}" "$hn" "tr -d '\n' < '$kd/${PK_NAME[j]}/nodus.fp'") || rfp=""
        [ "$rfp" = "${PK_FP[j]}" ] || die "host $hn: the copied ${PK_NAME[j]}/nodus.fp does not match the source"
        modes=$(ssh -n "${SSH_BASE[@]}" "$hn" "cd '$kd/${PK_NAME[j]}' && stat -c '%a' . $KEY_FILES | tr '\n' ' '") || modes="unreadable"
        echo "[ok] host $hn: identity ${PK_NAME[j]} copied to $kd/${PK_NAME[j]} (modes dir + files as read back: $modes; left there)"
        [ "$modes" = "700 600 600 600 600 600 600 600 " ] \
            || echo "[warn] host $hn: $kd/${PK_NAME[j]} modes are not 700 / 600 after chmod — check the host by hand" >&2
    done
done

# ── (i) preparation: every pump identity owns >= N spendable coins ───
# coin_state N FP — "count min tip" of FP's spendable native coins above
# the fee on node N (the same predicate as bench_tps_v2.sh's readiness
# wait; uncapped — this is not the CLI's 100-row listing)
coin_state() {
    node_sql "$1" "SELECT COUNT(*) || ' ' || COALESCE(MIN(amount),0) || ' ' ||
                          (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks)
                     FROM utxo_set WHERE owner = '$2' AND token_id = zeroblob(64)
                      AND amount > $FEE
                      AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks);"
}

# wait_new_height NODE START_H — progress-bounded: the node's tip passes
# START_H (a VALID height, never -1); rc 1 when it did not move for
# STALL_S seconds of wall clock, rc 3 when the node was UNREACHABLE (no
# valid tip for STALL_S seconds, node_tip_valid)
wait_new_height() {
    # last starts at -1 so the FIRST read seeds it: a node catching up
    # from below START_H is progress, not a stall
    # Two independent clocks: `bad_since` bounds an UNREADABLE spell
    # (STALL_S -> rc 3); `moved` bounds READABLE time without progress
    # (STALL_S -> rc 1). The length of an unreadable spell is added to
    # `moved` when a valid read returns, so time the node could not be
    # read never counts as stall time — and the wait stays bounded: every
    # readable iteration still advances the stall clock by >= 1 s.
    local node="$1" start_h="$2" last=-1 moved h bad_since=""
    [ "$start_h" -ge 0 ] || return 3
    moved=$(date +%s)
    while :; do
        h=$(node_tip "$node")
        if [ "$h" -lt 0 ]; then
            [ -n "$bad_since" ] || bad_since=$(date +%s)
            [ $(( $(date +%s) - bad_since )) -lt "$STALL_S" ] || return 3
            sleep 1
            continue
        fi
        if [ -n "$bad_since" ]; then moved=$(( moved + $(date +%s) - bad_since )); bad_since=""; fi
        [ "$h" -gt "$start_h" ] && return 0
        if [ "$h" -gt "$last" ]; then last="$h"; moved=$(date +%s); fi
        [ $(( $(date +%s) - moved )) -lt "$STALL_S" ] || return 1
        sleep 1
    done
}

# wait_applied NODE START_H ACC IN_LIST — the inline stagef_cmt_wait_row
# rules on NODE: prints "<applied> <tip>"; rc 0 all applied, 2 height
# budget exceeded (the rest = DROPPED), 1 STALL, 3 UNREACHABLE (no valid
# answer for STALL_S seconds). START_H must be a valid height. A failed
# read is NEVER a height and never a count: it is retried, and only a
# node that stayed unreadable for STALL_S becomes rc 3 — so an ssh or
# sqlite error can never turn into DROPPED spends.
wait_applied() {
    local node="$1" start_h="$2" acc="$3" in_list="$4" last="$2" moved r n_app h bad_since=""
    [ "$start_h" -ge 0 ] || { echo "0 -1"; return 3; }
    moved=$(date +%s)
    while :; do
        r=$(node_sql "$node" "SELECT (SELECT COUNT(DISTINCT tx_hash) FROM utxo_set WHERE lower(hex(tx_hash)) IN ($in_list))
                               || ' ' || (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks);" 2>/dev/null) || r=""
        n_app=""; h=""
        read -r n_app h <<< "$r"
        if ! is_uint "${n_app:-}" || ! is_uint "${h:-}"; then
            # unreadable: not a height, not a count — retry, bounded
            [ -n "$bad_since" ] || bad_since=$(date +%s)
            if [ $(( $(date +%s) - bad_since )) -ge "$STALL_S" ]; then echo "0 $last"; return 3; fi
            sleep 1
            continue
        fi
        # unreadable time is not stall time: shift the stall clock by the
        # spell's length (same two-clock rule as wait_new_height)
        if [ -n "$bad_since" ]; then moved=$(( moved + $(date +%s) - bad_since )); bad_since=""; fi
        if [ "$n_app" -ge "$acc" ]; then echo "$n_app $h"; return 0; fi
        if [ "$h" -gt "$last" ]; then last="$h"; moved=$(date +%s); fi
        if [ $(( $(date +%s) - moved )) -ge "$STALL_S" ]; then echo "$n_app $h"; return 1; fi
        if [ $(( h - start_h )) -gt "$MAX_HEIGHTS" ]; then echo "$n_app $h"; return 2; fi
        sleep 1
    done
}

# parse_round OUT — sets P_PLANNED P_ACC P_REF P_INTENTS P_INLIST from a
# `v2-envelope spend` output (the lines printed at nodus-cli.c :3775,
# :3790 and by t6_submit_on :2094 / :2106)
parse_round() {
    local out="$1"
    P_PLANNED=$(printf '%s\n' "$out" | grep -c '^v2-envelope spend [0-9]*/[0-9]*:' || true)
    P_ACC=$(printf '%s\n' "$out" | grep -c '^accepted: mempool CheckTx approved' || true)
    P_REF=$(printf '%s\n' "$out" | grep -c '^dnac_spend refused (status=' || true)
    P_INTENTS=$(printf '%s\n' "$out" | awk -F= -v n="$P_ACC" '/^  intent_id=/ { c++; if (c <= n) print $2 }')
    P_INLIST=""
    local x
    for x in $P_INTENTS; do P_INLIST="$P_INLIST'$x',"; done
    P_INLIST="${P_INLIST%,}"
}

# prep_identity J — halving rounds until identity J holds >= N coins on
# its prep node. Every CLI call runs on THIS machine (BENCH_CTRL_CLI).
prep_identity() {
    local j="$1" node log st cnt mn tip count amount out rc r n_app h rounds=0 max_rounds bits=0 v
    node=$(( (j - 1) % NN + 1 ))
    log="$BENCH_OUT/prep_${PK_NAME[$j]}.log"
    v=1; while [ "$v" -lt "$N_COINS" ]; do v=$(( v * 2 )); bits=$(( bits + 1 )); done
    max_rounds=$(( bits + 4 ))   # doubling needs <= ceil(log2 N); +4 for refused / dropped rounds
    local bad_since
    while :; do
        # a failed read is retried once a second; UNREACHABLE after STALL_S
        bad_since=$(date +%s)
        while :; do
            st=$(coin_state "$node" "${PK_FP[$j]}" 2>&1) || st="read failed: $st"
            cnt=""; mn=""; tip=""
            read -r cnt mn tip <<< "$st"
            is_uint "${cnt:-}" && is_uint "${mn:-}" && is_uint "${tip:-}" && break
            if [ $(( $(date +%s) - bad_since )) -ge "$STALL_S" ]; then
                echo "[FAIL] prep ${PK_NAME[$j]}: node$node UNREACHABLE — no valid coin state for ${STALL_S}s (last answer: $st)" >&2
                exit 1
            fi
            sleep 1
        done
        printf '── state: %s coins > fee, min %s raw, tip %s\n' "$cnt" "$mn" "$tip" >> "$log"
        if [ "$cnt" -ge "$N_COINS" ]; then
            echo "[ok] prep ${PK_NAME[$j]}: $cnt spendable coins on node$node (tip $tip) after $rounds split round(s)"
            exit 0
        fi
        [ "$cnt" -ge 1 ] || { echo "[FAIL] prep ${PK_NAME[$j]}: no spendable native coin above the fee on node$node — is its genesis allocation claimed?" >&2; exit 1; }
        rounds=$(( rounds + 1 ))
        [ "$rounds" -le "$max_rounds" ] || { echo "[FAIL] prep ${PK_NAME[$j]}: still $cnt < $N_COINS coins after $max_rounds split rounds (see $log)" >&2; exit 1; }
        count=$(( N_COINS - cnt )); [ "$count" -le "$cnt" ] || count="$cnt"; [ "$count" -le 100 ] || count=100
        amount=$(( (mn - FEE) / 2 ))
        [ "$amount" -ge 1 ] || { echo "[FAIL] prep ${PK_NAME[$j]}: smallest coin $mn raw is too small to split around the fee $FEE" >&2; exit 1; }
        rc=0
        out=$("$BENCH_CTRL_CLI" -s "${NODE_IP[$node]}" v2-envelope spend \
                --keys "${PK_DIR[$j]}" --to "${PK_FP[$j]}" --amount "$amount" \
                --count "$count" --fee "$FEE" --submit "${NODE_IP[$node]}:$CPORT" 2>&1) || rc=$?
        printf '── split round %d: --amount %s --count %s (rc %d)\n%s\n' "$rounds" "$amount" "$count" "$rc" "$out" >> "$log"
        parse_round "$out"
        if [ "$rc" != 0 ] && [ "$P_REF" != 1 ]; then
            echo "[FAIL] prep ${PK_NAME[$j]} round $rounds: nodus-cli rc $rc and no CheckTx refusal:" >&2
            printf '%s\n' "$out" >&2
            exit 1
        fi
        if [ "$P_ACC" = 0 ]; then
            echo "[warn] prep ${PK_NAME[$j]} round $rounds: first split refused — waiting one height" >&2
            rc=0; wait_new_height "$node" "$tip" || rc=$?
            case "$rc" in
                0) ;;
                3) echo "[FAIL] prep ${PK_NAME[$j]}: node$node UNREACHABLE (no valid tip for ${STALL_S}s)" >&2; exit 1 ;;
                *) echo "[FAIL] prep ${PK_NAME[$j]}: node$node's tip STALLED at $tip" >&2; exit 1 ;;
            esac
            continue
        fi
        [ "$(printf '%s\n' "$P_INTENTS" | grep -c '^[0-9a-f]\{128\}$' || true)" = "$P_ACC" ] \
            || { echo "[FAIL] prep ${PK_NAME[$j]} round $rounds: $P_ACC accepted but not $P_ACC intent ids" >&2; exit 1; }
        r=$(wait_applied "$node" "$tip" "$P_ACC" "$P_INLIST"); rc=$?
        read -r n_app h <<< "$r"
        case "$rc" in
            0) ;;
            2) echo "[warn] prep ${PK_NAME[$j]} round $rounds: $(( P_ACC - n_app )) of $P_ACC splits not applied within $MAX_HEIGHTS heights — DROPPED; the next round recounts from the DB" >&2 ;;
            3) echo "[FAIL] prep ${PK_NAME[$j]}: node$node UNREACHABLE while confirming round $rounds (no valid answer for ${STALL_S}s)" >&2; exit 1 ;;
            *) echo "[FAIL] prep ${PK_NAME[$j]}: $n_app of $P_ACC splits applied and node$node's tip STALLED at $h" >&2; exit 1 ;;
        esac
    done
}

echo "[..] preparation: $K identit(y/ies) to >= $N_COINS spendable coins each (halving splits; skipped where already met)"
declare -a PREP_PIDS
for j in $(seq 1 "$K"); do
    start_job "PREP_PIDS[$j]" prep_identity "$j"     # own process group
    WPIDS+=("${PREP_PIDS[j]}")
done
# wait for all; on the FIRST failure stop: die -> the EXIT trap kills the
# process group of every preparation job still splitting coins on the
# live chain (kill_groups), then reports survivors
prep_left="$K"
while [ "$prep_left" -gt 0 ]; do
    prep_left=0
    for j in $(seq 1 "$K"); do
        p="${PREP_PIDS[j]}"
        [ -n "$p" ] || continue
        if kill -0 "$p" 2>/dev/null; then prep_left=$(( prep_left + 1 )); continue; fi
        prc=0; wait "$p" || prc=$?
        PREP_PIDS[j]=""
        [ "$prc" = 0 ] || die "preparation of ${PK_NAME[j]} failed (rc $prc; message above, log $BENCH_OUT/prep_${PK_NAME[j]}.log) — stopping the other preparations; nothing measured"
    done
    [ "$prep_left" -gt 0 ] && sleep 1
done
WPIDS=()

# every node a worker lists on must hold the same coins first
prep_h=-1
for j in $(seq 1 "$K"); do
    pn=$(( (j - 1) % NN + 1 ))
    h=$(node_tip_valid "$pn") || die "node$pn ${NODE_NAME[pn]} UNREACHABLE after the preparation (no valid tip for ${STALL_S}s)"
    [ "$h" -le "$prep_h" ] || prep_h="$h"
done
for n in $(seq 1 "$NN"); do
    h=$(node_tip_valid "$n") || die "node$n ${NODE_NAME[n]} UNREACHABLE (no valid tip for ${STALL_S}s)"
    if [ "$h" -lt "$prep_h" ]; then
        wrc=0; wait_new_height "$n" $(( prep_h - 1 )) || wrc=$?
        case "$wrc" in
            0) ;;
            3) die "node$n ${NODE_NAME[n]} UNREACHABLE while catching up to height $prep_h (no valid tip for ${STALL_S}s)" ;;
            *) die "node$n ${NODE_NAME[n]} never reached height $prep_h (its tip did not move for ${STALL_S}s)" ;;
        esac
    fi
done
echo "[ok] every node has reached height $prep_h (the preparation's highest tip)"

INFLIGHT_BOUND=0
for j in $(seq 1 "$K"); do
    [ "${PK_WORKERS[j]}" -gt 0 ] || { echo "[warn] identity ${PK_NAME[j]} has no worker (K=$K > M=$M)"; continue; }
    l="$N_COINS"; [ "$l" -le 100 ] || l=100
    INFLIGHT_BOUND=$(( INFLIGHT_BOUND + l ))
done

# ── (ii) the workers (the loop is bench_tps_v2.sh worker(), made remote) ─
worker() {
    local I="$1" node hi pj keys fp shard ip log stats
    node="${W_NODE[$I]}"; hi="${W_HOST[$I]}"; pj="${W_ID[$I]}"
    ip="${NODE_IP[$node]}"; fp="${PK_FP[$pj]}"; shard="${W_SHARD[$I]}"
    keys="${HOST_KEYS[$hi]}/${PK_NAME[$pj]}"
    log="$BENCH_OUT/worker_$I.log"
    stats="$BENCH_OUT/worker_$I.stats"
    local rounds=0 idle=0 submitted=0 accepted=0 refused=0
    local dropped=0 applied=0
    local out rc start_h r n_app h
    while [ "$(date +%s)" -lt "$LOAD_END" ]; do
        rounds=$(( rounds + 1 ))
        # a VALID tip or an UNREACHABLE failure — never -1 as a height
        start_h=$(node_tip_valid "$node") || {
            echo "[FAIL] worker $I: node$node ${NODE_NAME[$node]} UNREACHABLE — no valid tip for ${STALL_S}s before round $rounds" >&2
            exit 1
        }
        rc=0
        out=$(run_cli "$hi" -s "$ip" v2-envelope spend \
                --keys "$keys" --to "$fp" --amount all --count all \
                --shard "$shard" --fee "$FEE" --submit "$ip:$CPORT" 2>&1) || rc=$?
        printf '── round %d (tip %s, rc %d)\n%s\n' "$rounds" "$start_h" "$rc" "$out" >> "$log"
        parse_round "$out"
        if [ "$rc" != 0 ] && [ "$P_REF" != 1 ]; then
            echo "[FAIL] worker $I (host ${HOST_NAME[$hi]}, node$node) round $rounds: nodus-cli rc $rc and no CheckTx refusal — a client/session/ssh fault:" >&2
            printf '%s\n' "$out" >&2
            exit 1
        fi
        if [ "$P_PLANNED" = 0 ]; then
            case "$out" in
                *"v2-envelope spend: 0 eligible coin"*) ;;
                *)
                    echo "[FAIL] worker $I round $rounds: no spend planned and no 'nothing to submit' line:" >&2
                    printf '%s\n' "$out" >&2
                    exit 1 ;;
            esac
            idle=$(( idle + 1 ))
            rc=0; wait_new_height "$node" "$start_h" || rc=$?
            case "$rc" in
                0) ;;
                3) echo "[FAIL] worker $I: node$node UNREACHABLE (no valid tip for ${STALL_S}s) during an idle round" >&2; exit 1 ;;
                *) echo "[FAIL] worker $I: node$node's tip did not pass $start_h for ${STALL_S}s during an idle round — chain STALLED" >&2; exit 1 ;;
            esac
            continue
        fi
        # P_PLANNED always equals P_ACC + P_REF here: the CLI prints each
        # plan line right before submitting that envelope and stops at the
        # first refusal (nodus-cli.c :3775, :3806-3809), so there is no
        # "planned but unsent" count to report
        submitted=$(( submitted + P_ACC + P_REF ))
        accepted=$(( accepted + P_ACC ))
        refused=$(( refused + P_REF ))
        if [ "$P_ACC" = 0 ]; then
            idle=$(( idle + 1 ))
            rc=0; wait_new_height "$node" "$start_h" || rc=$?
            case "$rc" in
                0) ;;
                3) echo "[FAIL] worker $I: node$node UNREACHABLE (no valid tip for ${STALL_S}s) after a refused round" >&2; exit 1 ;;
                *) echo "[FAIL] worker $I: node$node's tip did not pass $start_h for ${STALL_S}s after a refused round — chain STALLED" >&2; exit 1 ;;
            esac
            continue
        fi
        [ "$(printf '%s\n' "$P_INTENTS" | grep -c '^[0-9a-f]\{128\}$' || true)" = "$P_ACC" ] || {
            echo "[FAIL] worker $I round $rounds: $P_ACC accepted but not $P_ACC intent ids:" >&2
            printf '%s\n' "$out" >&2
            exit 1
        }
        r=$(wait_applied "$node" "$start_h" "$P_ACC" "$P_INLIST"); rc=$?
        read -r n_app h <<< "$r"
        case "$rc" in
            0) ;;
            2)
                echo "[warn] worker $I: $(( P_ACC - n_app )) of $P_ACC spends not applied within $MAX_HEIGHTS heights (tip $start_h -> $h) — counted as DROPPED" >&2
                dropped=$(( dropped + P_ACC - n_app )) ;;
            3)
                echo "[FAIL] worker $I: node$node UNREACHABLE while confirming round $rounds (no valid answer for ${STALL_S}s) — its $P_ACC accepted spend(s) are neither applied nor dropped as far as this bench can tell" >&2
                exit 1 ;;
            *)
                echo "[FAIL] worker $I: $n_app of $P_ACC spends applied and node$node's tip STALLED at $h" >&2
                exit 1 ;;
        esac
        applied=$(( applied + n_app ))
    done
    {
        echo "worker=$I"; echo "host=${HOST_NAME[$hi]}"; echo "node=$node"
        echo "node_name=${NODE_NAME[$node]}"; echo "pump_identity=${PK_NAME[$pj]}"
        echo "shard=$shard"; echo "rounds=$rounds"
        echo "idle_rounds=$idle"; echo "submitted=$submitted"
        echo "accepted=$accepted"; echo "refused=$refused"
        echo "dropped=$dropped"; echo "applied=$applied"
    } > "$stats"
    exit 0
}

# ── the node streams (read-only shell loops on the nodes) ────────────
# SAMPLER: once a second, "S <node time>", "C <the /proc/<pid>/stat
# fields after the comm>" and one "T <local addr:port> <peer addr:port>
# <sent> <recv>" line per nodus-server TCP socket (sent = bytes_sent, or
# bytes_acked when bytes_sent is absent; 0 when not printed) — filtered
# on the node, so only nodus-server's sockets cross the link.
SAMPLER_SH='
pid="$1"; n="$2"; i=0
while [ "$i" -lt "$n" ]; do
    echo "S $(date +%s)"
    st=$(cat /proc/"$pid"/stat 2>/dev/null) || st=""
    echo "C ${st##*) }"
    ss -tinpH 2>/dev/null | awk -v p="pid=$pid," "
        /^[^ \t]/ { key = \"\"; if (index(\$0, p)) key = \$4 \" \" \$5; next }
        key != \"\" {
            s = 0; r = 0
            if (match(\$0, /bytes_sent:[0-9]+/)) s = substr(\$0, RSTART + 11, RLENGTH - 11)
            else if (match(\$0, /bytes_acked:[0-9]+/)) s = substr(\$0, RSTART + 12, RLENGTH - 12)
            if (match(\$0, /bytes_received:[0-9]+/)) r = substr(\$0, RSTART + 15, RLENGTH - 15)
            print \"T \" key \" \" s \" \" r
            key = \"\"
        }"
    i=$((i + 1))
    sleep 1
done
'
# POLLER: once a second, every v2_blocks row above the last one printed,
# as "<height>,<tx_count>".
POLLER_SH='
db="$1"; last="$2"; n="$3"; i=0
while [ "$i" -lt "$n" ]; do
    rows=$(sqlite3 -readonly -separator , -cmd ".timeout 2000" "$db" "SELECT global_height, tx_count FROM v2_blocks WHERE global_height > $last ORDER BY global_height;" 2>/dev/null)
    for r in $rows; do echo "$r"; last=${r%%,*}; done
    i=$((i + 1))
    sleep 1
done
'
stamp() { local l; while IFS= read -r l; do printf '%s,%(%s)T\n' "$l" -1; done; }

# ── (iii) start the load, stream while it runs ───────────────────────
base_h=$(node_tip_valid "$REF") || die "node$REF ${NODE_NAME[$REF]} UNREACHABLE (no valid tip for ${STALL_S}s) — load not started"
NLOOP=$(( D + LOOP_EXTRA ))
declare -a SAMPLER_PID
for n in $(seq 1 "$NN"); do
    ssh "${SSH_BASE[@]}" "$(node_target "$n")" "sh -s -- '${NODE_PID0[n]}' '$NLOOP'" \
        <<< "$SAMPLER_SH" > "$BENCH_OUT/node_$n.stream" 2>/dev/null &
    SAMPLER_PID[n]=$!
    STREAM_PIDS+=("${SAMPLER_PID[n]}")
done
: > "$BENCH_OUT/blocks.raw"
ssh "${SSH_BASE[@]}" "$(node_target "$REF")" "sh -s -- '${NODE_DB[$REF]}' '$base_h' '$NLOOP'" \
    <<< "$POLLER_SH" 2>/dev/null > >(stamp >> "$BENCH_OUT/blocks.raw") &
POLLER_PID=$!
STREAM_PIDS+=("$POLLER_PID")

LOAD_START=$(date +%s)
LOAD_END=$(( LOAD_START + D ))
WORKERS_STARTED=1
for I in $(seq 0 $(( M - 1 ))); do
    start_job "WPIDS[$I]" worker "$I"       # own process group
done
echo "[ok] $M workers started at $LOAD_START for ${D}s over $H client host(s); base tip $base_h on node$REF ${NODE_NAME[$REF]}"
for I in $(seq 0 $(( M - 1 ))); do
    echo "     worker $I: host ${HOST_NAME[${W_HOST[I]}]}, identity ${PK_NAME[${W_ID[I]}]}, shard ${W_SHARD[I]}, node${W_NODE[I]} ${NODE_NAME[${W_NODE[I]}]}"
done

samplers_stopped=0
BW_TEND=0
running="$M"
while [ "$running" -gt 0 ]; do
    now_s=$(date +%s)
    if [ "$samplers_stopped" = 0 ] && [ "$now_s" -ge "$LOAD_END" ]; then
        for n in $(seq 1 "$NN"); do kill "${SAMPLER_PID[n]}" 2>/dev/null; done
        BW_TEND="$now_s"
        samplers_stopped=1
    fi
    running=0
    for I in $(seq 0 $(( M - 1 ))); do
        p="${WPIDS[I]}"
        [ -n "$p" ] || continue
        if kill -0 "$p" 2>/dev/null; then running=$(( running + 1 )); continue; fi
        wrc=0; wait "$p" || wrc=$?
        WPIDS[I]=""
        if [ "$wrc" != 0 ]; then
            die "worker $I exited rc $wrc — the bench is ABORTED (see its message above and $BENCH_OUT/worker_$I.log); no partial result is reported"
        fi
    done
    [ "$running" -gt 0 ] && sleep 1
done
WPIDS=()
if [ "$samplers_stopped" = 0 ]; then
    for n in $(seq 1 "$NN"); do kill "${SAMPLER_PID[n]}" 2>/dev/null; done
    BW_TEND=$(date +%s)
fi
LOAD_DONE=$(date +%s)
# the last rows: stop the stream, then one direct read above what it saw
kill "$POLLER_PID" 2>/dev/null
sleep 1
last_seen=$(awk -F, 'BEGIN { m = -1 } $1 + 0 > m { m = $1 + 0 } END { print m }' "$BENCH_OUT/blocks.raw")
[ "$last_seen" -ge "$base_h" ] || last_seen="$base_h"
node_sql "$REF" "SELECT global_height || ',' || tx_count FROM v2_blocks WHERE global_height > $last_seen ORDER BY global_height;" \
    2>/dev/null | stamp >> "$BENCH_OUT/blocks.raw"
NODE_PID1=()
for n in $(seq 1 "$NN"); do
    NODE_PID1[n]=$(node_ssh "$n" "systemctl show -p MainPID --value '$NODE_UNIT'" 2>/dev/null || echo "?")
done

# ── (iv) report ──────────────────────────────────────────────────────
csv="$BENCH_OUT/blocks.csv"
echo "height,first_seen_s,tx_count,in_window" > "$csv"
LC_ALL=C sort -t, -k1,1n "$BENCH_OUT/blocks.raw" | \
    awk -F, -v le="$LOAD_END" '$1 ~ /^[0-9]+$/ && !($1 in seen) { seen[$1] = 1; print $1 "," $3 "," $2 "," ($3 <= le ? 1 : 0) }' >> "$csv"

sum_w() { awk -F= -v k="$1" '$1 == k { s += $2 } END { print s + 0 }' "$BENCH_OUT"/worker_*.stats; }
w_sub=$(sum_w submitted); w_acc=$(sum_w accepted); w_ref=$(sum_w refused)
w_drop=$(sum_w dropped); w_app=$(sum_w applied)
w_idle=$(sum_w idle_rounds); w_rounds=$(sum_w rounds)

# declared units: the LOAD's spends only (worker logs; the preparation's
# 1-in/2-out splits declare more and are not in the window)
units=$(cat "$BENCH_OUT"/worker_*.log 2>/dev/null | grep -o ' units=[0-9]*' | sort -u | awk -F= '{ print $2 }' | sort -n | awk 'END { print $1 }')
n_units=$(cat "$BENCH_OUT"/worker_*.log 2>/dev/null | grep -o ' units=[0-9]*' | sort -u | wc -l)
cap="n/a"
if is_uint "${units:-}" && [ "$units" -gt 0 ]; then cap=$(( BUDGET / units )); fi

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

# per-node stream -> CPU and the bandwidth raw rows
# bw_samples.raw: phase,time,node,local_port,peer_ip,peer_port,sent,recv
# (phase 0 = the node's FIRST sample = its baseline; time = node clock)
BW_RAW="$BENCH_OUT/bw_samples.raw"
: > "$BW_RAW"
BW_SKIP=""
declare -a CPU_LINE BW_SPAN BW_NSAMP
for n in $(seq 1 "$NN"); do
    f="$BENCH_OUT/node_$n.stream"
    # CPU: utime + stime are words 12 and 13 after the comm (fields 14/15
    # of /proc/<pid>/stat) = $13 + $14 on a "C ..." line
    CPU_LINE[n]=$(awk -v hz="${NODE_HZ[n]}" -v np="${NODE_NPROC[n]}" '
        $1 == "S" { t = $2 + 0; ns++ }
        $1 == "C" {
            if (NF < 14) { bad = 1; next }
            c = $13 + $14
            if (!have) { t0 = t; c0 = c; have = 1 }
            if (c < last) bad = 1
            t1 = t; c1 = c; last = c
        }
        END {
            if (!have || bad || t1 <= t0) { print "n/a (fewer than two readable samples, or the process went away / restarted)"; exit }
            w = t1 - t0; d = (c1 - c0) / hz
            printf "%.1f%% of one core (%.1f%% of its %d CPUs) over %d s, %d sample(s)", 100 * d / w, 100 * d / w / np, np, w, ns
        }' "$f" 2>/dev/null)
    [ -n "${CPU_LINE[n]}" ] || CPU_LINE[n]="n/a (no stream)"
    read -r BW_SPAN[n] BW_NSAMP[n] < <(awk '$1 == "S" { if (!f) { f = $2 } l = $2; c++ } END { print (l - f) + 0, c + 0 }' "$f" 2>/dev/null || echo "0 0")
    if [ "${NODE_BW[n]}" != 1 ]; then BW_SKIP="$BW_SKIP $n"; continue; fi
    awk -v node="$n" '
        function hp(s,    i, p, a) {           # split "addr:port" at the LAST colon
            i = 0; p = s
            while ((a = index(p, ":")) > 0) { i += a; p = substr(p, a + 1) }
            H = substr(s, 1, i - 1); P = p
            gsub(/^\[|\]$/, "", H); sub(/^::ffff:/, "", H); sub(/%.*/, "", H)
        }
        $1 == "S" { t = $2; ph = (ns == 0) ? 0 : 1; ns++; next }
        $1 == "T" && NF >= 5 {
            hp($2); lp = P
            hp($3); pip = H; pp = P
            print ph "," t "," node "," lp "," pip "," pp "," $4 "," $5
        }' "$f" >> "$BW_RAW" 2>/dev/null
done

CLUSTER_IPS=""
for n in $(seq 1 "$NN"); do CLUSTER_IPS="$CLUSTER_IPS ${NODE_IP[n]}"; done
SPANS=""
for n in $(seq 1 "$NN"); do SPANS="$SPANS ${BW_SPAN[n]:-0}"; done
bw_report() {
    local n
    for n in $BW_SKIP; do
        echo "bandwidth node$n: SKIPPED — its ss -tinpH printed no bytes_received / bytes_acked counters at start (ss or kernel too old for -i byte counters); absent from the cluster sum, not zero"
    done
    if [ ! -s "$BW_RAW" ]; then
        echo "bandwidth: SKIPPED — no nodus-server TCP socket was seen in any node's stream (ss missing byte counters, or the samplers produced nothing — see $BENCH_OUT/node_<N>.stream)"
        return 0
    fi
    awk -F, -v NN="$NN" -v base="$PORT_BASE" -v dir="$BENCH_OUT" -v env="$w_env" \
        -v cluster="$CLUSTER_IPS" -v bench="$BENCH_CLIENT_IPS" -v spans="$SPANS" -v skip="$BW_SKIP" '
    function cls(l, pip, p,    d, c) {
        d = l - base
        if (d >= 1 && d <= 4) {
            c = "in_" nm[d]
            if (d == 1 && (pip in B)) c = "in_client_bench"
            return c
        }
        d = p - base
        if ((pip in CL) && d >= 1 && d <= 4) return "out_" nm[d]
        return "out_other"
    }
    function Bf(x) { return sprintf("%.0f", x) }
    function R(x, w) { return w > 0 ? sprintf("%.1f", x / w) : "n/a" }
    function E(x) { return env > 0 ? sprintf("%.0f", x / env) : "n/a" }
    BEGIN {
        nm[1] = "client"; nm[2] = "internode"; nm[3] = "channel"; nm[4] = "witness"
        ncl = split("in_client in_client_bench in_internode in_channel in_witness out_client out_internode out_channel out_witness out_other", cl, " ")
        n = split(cluster, a, " "); for (i = 1; i <= n; i++) CL[a[i]] = 1
        n = split(bench, a, " ");   for (i = 1; i <= n; i++) B[a[i]] = 1
        split(spans, SP, " ")
        n = split(skip, a, " "); for (i = 1; i <= n; i++) SK[a[i] + 0] = 1
    }
    {
        k = $3 "," $4 "," $5 "," $6
        s = $7 + 0; r = $8 + 0
        if (!(k in kn)) {
            kn[k] = $3; kl[k] = $4 + 0; ki[k] = $5; kp[k] = $6 + 0
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
        if ($2 + 0 > tend[$3]) tend[$3] = $2 + 0
    }
    END {
        for (k in kn) {
            nd = kn[k]; c = cls(kl[k], ki[k], kp[k])
            ws = as[k] + ls[k] - bs[k]; wr = ar[k] + lr[k] - br[k]
            if (ws < 0) ws = 0
            if (wr < 0) wr = 0
            S[nd, c] += ws; RV[nd, c] += wr; K[nd, c]++
            TS[nd] += ws; TR[nd] += wr; TK[nd]++
            if (lt[k] < tend[nd]) n_gone++
            nk++
        }
        printf "bandwidth during the load (ss -tinpH on each node, ~1 s; %d socket key(s): %d open at the first sample, %d opened later, %d gone before the node'"'"'s last sample, %d key re-use(s)):\n", nk, n_start + 0, n_new + 0, n_gone + 0, n_reuse + 0
        printf "  B/s = bytes / that node'"'"'s own sampled span; per envelope = bytes / %s committed envelopes (window blocks)\n", env
        for (nd = 1; nd <= NN; nd++) {
            if (nd in SK) continue
            w = SP[nd] + 0
            f = dir "/bandwidth_node" nd ".csv"
            print "class,sockets,bytes_sent,bytes_received,sent_Bps,recv_Bps,sent_per_env,recv_per_env" > f
            printf "  node%d  span %d s  sent %s B (%s B/s)  recv %s B (%s B/s)  per envelope: sent %s B, recv %s B  [%d socket(s)]\n", nd, w, Bf(TS[nd]), R(TS[nd], w), Bf(TR[nd]), R(TR[nd], w), E(TS[nd]), E(TR[nd]), TK[nd]
            for (i = 1; i <= ncl; i++) {
                c = cl[i]
                if (!((nd, c) in K)) continue
                printf "         %-16s sent %s B (%s B/s)  recv %s B (%s B/s)  [%d]\n", c, Bf(S[nd, c]), R(S[nd, c], w), Bf(RV[nd, c]), R(RV[nd, c], w), K[nd, c]
                print c "," K[nd, c] "," Bf(S[nd, c]) "," Bf(RV[nd, c]) "," R(S[nd, c], w) "," R(RV[nd, c], w) "," E(S[nd, c]) "," E(RV[nd, c]) > f
            }
            print "total," (TK[nd] + 0) "," Bf(TS[nd]) "," Bf(TR[nd]) "," R(TS[nd], w) "," R(TR[nd], w) "," E(TS[nd]) "," E(TR[nd]) > f
            close(f)
            CS += TS[nd]; CR += TR[nd]
        }
        printf "  cluster sent %s B  recv %s B  per envelope: sent %s B, recv %s B\n", Bf(CS), Bf(CR), E(CS), E(CR)
        printf "  (node-to-node bytes count once as sent and once as received. in/out_witness (4004) = consensus only; in/out_internode (4002) = DHT replication, NOT consensus; in_client (4001) = real Connect clients%s)\n", (bench == "" ? " AND the bench'"'"'s own sessions — NOT separated (BENCH_CLIENT_IPS unset)" : "; in_client_bench = sessions from BENCH_CLIENT_IPS")
    }' "$BW_RAW" || echo "bandwidth: report FAILED to aggregate $BW_RAW (awk error) — raw samples kept"
}

# NETSTATS: the newest COMPLETE snapshot in a journald slice (the local
# bench's ns_snap, reading a file instead of a log prefix)
NS_CSV="$BENCH_OUT/netstats.csv"
NS_DELTA="$BENCH_OUT/netstats_delta.raw"
ns_snap() {
    awk '
    function reset() { split("", cnt); split("", endk); split("", tt); split("", rows) }
    BEGIN { reset(); last = -1; restarts = 0 }
    {
        i = index($0, "NETSTATS seq=")
        if (i == 0) next
        n = split(substr($0, i + 9), f, " ")
        split("", kv)
        for (j = 1; j <= n; j++) {
            p = index(f[j], "=")
            if (p > 1) kv[substr(f[j], 1, p - 1)] = substr(f[j], p + 1)
            else kv[f[j]] = ""
        }
        if (kv["seq"] !~ /^[0-9]+$/) next
        sq = kv["seq"] + 0
        if (sq < last || (sq in endk)) { reset(); restarts++ }
        last = sq
        if ("end" in kv) {
            if (kv["lines"] ~ /^[0-9]+$/ && kv["t"] ~ /^-?[0-9]+$/) { endk[sq] = kv["lines"] + 0; tt[sq] = kv["t"] }
            next
        }
        cr = ("sign" in kv) ? kv["sign"] : kv["verify"]
        if (kv["dir"] !~ /^(tx|rx)$/ || kv["ch"] == "" || kv["kind"] == "") next
        if (kv["msgs"] !~ /^[0-9]+$/ || kv["payload"] !~ /^[0-9]+$/ || kv["frame"] !~ /^[0-9]+$/ ||
            cr !~ /^[0-9]+$/ || kv["fail"] !~ /^[0-9]+$/) next
        cnt[sq]++
        rows[sq, cnt[sq]] = kv["dir"] " " kv["ch"] " " kv["kind"] " " kv["msgs"] " " kv["payload"] " " kv["frame"] " " cr " " kv["fail"]
    }
    END {
        best = -1
        for (s in endk) if ((cnt[s] + 0) == endk[s] && s + 0 > best) best = s + 0
        if (best < 0) { print "NONE -1 -1 " restarts; exit }
        print "SNAP " best " " tt[best] " " restarts
        for (j = 1; j <= cnt[best]; j++) print rows[best, j]
    }' "$1" > "$2" 2>/dev/null || echo "NONE -1 -1 0" > "$2"
}
# ns_fetch NODE EDGE OUT — journald slice [EDGE - 2 periods - 10 s, EDGE]
ns_fetch() {
    node_ssh "$1" "journalctl -q -u '$NODE_UNIT' -o cat --no-pager --since @$(( $2 - 2 * NS_PERIOD - 10 )) --until @$2" > "$3" 2>/dev/null
}

ns_report() {
    local n s0 s1 j0 j1 h0 h1 k0 q0 t0 r0 k1 q1 t1 r1 used="" drc
    echo "inter-node traffic — NETSTATS counters from journald (witness port, cumulative snapshots every ${NS_PERIOD} s; window = end snapshot − start snapshot):"
    : > "$NS_DELTA"
    for n in $(seq 1 "$NN"); do
        s0="$BENCH_OUT/netstats_node$n.start"; s1="$BENCH_OUT/netstats_node$n.end"
        j0="$BENCH_OUT/netstats_node$n.jstart"; j1="$BENCH_OUT/netstats_node$n.jend"
        if ! ns_fetch "$n" "$LOAD_START" "$j0" || ! ns_fetch "$n" "$BW_TEND" "$j1"; then
            echo "  node$n: SKIPPED — journalctl -u $NODE_UNIT --since/--until @<epoch> failed on the node"
            continue
        fi
        if [ "${NODE_PID1[n]}" != "${NODE_PID0[n]}" ]; then
            echo "  node$n: SKIPPED — its nodus-server MainPID is unreadable or changed (${NODE_PID0[n]} -> ${NODE_PID1[n]}): a restart would have started the counters over"
            continue
        fi
        ns_snap "$j0" "$s0"
        ns_snap "$j1" "$s1"
        h0=$(head -n 1 "$s0"); h1=$(head -n 1 "$s1")
        read -r k0 q0 t0 r0 <<< "$h0" || true
        read -r k1 q1 t1 r1 <<< "$h1" || true
        if [ "$k0" != SNAP ]; then
            echo "  node$n: SKIPPED — no complete NETSTATS snapshot in journald in the $(( 2 * NS_PERIOD + 10 )) s before load start (older than nodus 0.19.76, rate-limited, or not live long enough)"
            continue
        fi
        if [ "$k1" != SNAP ]; then
            echo "  node$n: SKIPPED — no complete NETSTATS snapshot in journald in the $(( 2 * NS_PERIOD + 10 )) s before load end"
            continue
        fi
        if [ "$q0" = "$q1" ]; then
            echo "  node$n: SKIPPED — the same snapshot (seq $q0) is the newest at both edges: the window is shorter than the ${NS_PERIOD} s cadence"
            continue
        fi
        drc=0
        awk -v node="$n" '
        BEGIN {
            nc = split("0x20 0x21 0x22 0x23 0x30 t3", c, " ")
            for (i = 1; i <= nc; i++) co[c[i]] = i
            nk = split("unknown new_round_step new_valid_block proposal proposal_pol block_part vote has_vote vote_set_maj23 vote_set_bits txs other", k, " ")
            for (i = 1; i <= nk; i++) ko[k[i]] = i
        }
        FNR == 1 { next }
        FILENAME == ARGV[1] {
            key = $1 " " $2 " " $3
            b4[key] = $4; b5[key] = $5; b6[key] = $6; b7[key] = $7; b8[key] = $8
            next
        }
        {
            key = $1 " " $2 " " $3; seen[key] = 1
            d4 = $4 - b4[key]; d5 = $5 - b5[key]; d6 = $6 - b6[key]; d7 = $7 - b7[key]; d8 = $8 - b8[key]
            if (d4 < 0 || d5 < 0 || d6 < 0 || d7 < 0 || d8 < 0) bad = 1
            ord = ($1 == "tx" ? 0 : 1) * 10000 + (($2 in co) ? co[$2] : 99) * 100 + (($3 in ko) ? ko[$3] : 99)
            printf "%d,%d,%s,%s,%s,%.0f,%.0f,%.0f,%.0f,%.0f\n", ord, node, $1, $2, $3, d4, d5, d6, d7, d8
        }
        END {
            for (key in b4) if (!(key in seen) && (b4[key] + b5[key] + b6[key] + b7[key] + b8[key]) > 0) bad = 1
            if (bad) exit 3
        }' "$s0" "$s1" > "$NS_DELTA.node" || drc=$?
        if [ "$drc" != 0 ]; then
            echo "  node$n: SKIPPED — a counter went DOWN between the snapshots (an undetected restart, or awk rc $drc)"
            continue
        fi
        cat "$NS_DELTA.node" >> "$NS_DELTA"
        used="$used $n"
        echo "  node$n: start snapshot seq $q0 t=$t0 ($(( t0 - NODE_SKEW[n] - LOAD_START )) s from load start after removing the node's ${NODE_SKEW[n]} s clock offset), end snapshot seq $q1 t=$t1 ($(( t1 - NODE_SKEW[n] - BW_TEND )) s from load end) — counted span $(( t1 - t0 )) s"
    done
    rm -f "$NS_DELTA.node"
    if [ -z "$used" ]; then
        echo "  no node had a usable pair of snapshots — the NETSTATS table is ABSENT for this run (not zero)"
        return 0
    fi
    echo "node,dir,ch,kind,msgs,payload_bytes,frame_bytes,sign_or_verify,fail,frame_bytes_per_env,sign_or_verify_per_env" > "$NS_CSV"
    LC_ALL=C sort -t, -k2,2n -k1,1n "$NS_DELTA" | awk -F, -v env="$w_env" -v csv="$NS_CSV" '
    function E(x, d) { return env > 0 ? sprintf("%." d "f", x / env) : "n/a" }
    function flush(   d) {
        if (cur == "") return
        for (d = 0; d < 2; d++) {
            dn = d == 0 ? "tx" : "rx"
            if (!(dn in TM)) continue
            printf "    %-2s %-4s %-15s %10.0f %14.0f %12.0f %8.0f %14s %10s\n", dn, "all", "ALL", TM[dn], TF[dn], TC[dn], TL[dn], E(TF[dn], 0), E(TC[dn], 2)
            print "node" cur "," dn ",all,ALL," sprintf("%.0f,%.0f,%.0f,%.0f,%.0f", TM[dn], TP[dn], TF[dn], TC[dn], TL[dn]) "," E(TF[dn], 0) "," E(TC[dn], 2) >> csv
        }
        split("", TM); split("", TP); split("", TF); split("", TC); split("", TL)
    }
    {
        if ($2 != cur) {
            flush(); cur = $2
            printf "  node%s  (%s committed envelopes in the window blocks; sign = tx, verify = rx)\n", cur, env
            printf "    %-2s %-4s %-15s %10s %14s %12s %8s %14s %10s\n", "dir", "ch", "kind", "msgs", "frame_B", "sign/verify", "fail", "frame_B/env", "crypto/env"
        }
        printf "    %-2s %-4s %-15s %10.0f %14.0f %12.0f %8.0f %14s %10s\n", $3, $4, $5, $6, $8, $9, $10, E($8, 0), E($9, 2)
        print "node" $2 "," $3 "," $4 "," $5 "," $6 "," $7 "," $8 "," $9 "," $10 "," E($8, 0) "," E($9, 2) >> csv
        TM[$3] += $6; TP[$3] += $7; TF[$3] += $8; TC[$3] += $9; TL[$3] += $10
    }
    END { flush() }' || echo "  netstats: per-node table FAILED to aggregate $NS_DELTA (sort/awk error) — raw differences kept"
    LC_ALL=C sort -t, -k1,1n -k2,2n "$NS_DELTA" | awk -F, -v env="$w_env" -v csv="$NS_CSV" -v used="$used" '
    function E(x, d) { return env > 0 ? sprintf("%." d "f", x / env) : "n/a" }
    function row() {
        if (ord == "") return
        printf "    %-2s %-4s %-15s %10.0f %14.0f %12.0f %8.0f %14s %10s\n", dr, ch, kd, m, f, c, l, E(f, 0), E(c, 2)
        print "cluster," dr "," ch "," kd "," sprintf("%.0f,%.0f,%.0f,%.0f,%.0f", m, p, f, c, l) "," E(f, 0) "," E(c, 2) >> csv
        TM[dr] += m; TP[dr] += p; TF[dr] += f; TC[dr] += c; TL[dr] += l
    }
    BEGIN {
        printf "  cluster total over node(s)%s  (node-to-node traffic counts once as tx on the sender and once as rx on the receiver)\n", used
        printf "    %-2s %-4s %-15s %10s %14s %12s %8s %14s %10s\n", "dir", "ch", "kind", "msgs", "frame_B", "sign/verify", "fail", "frame_B/env", "crypto/env"
    }
    {
        if ($1 != ord) { row(); ord = $1; dr = $3; ch = $4; kd = $5; m = 0; p = 0; f = 0; c = 0; l = 0 }
        m += $6; p += $7; f += $8; c += $9; l += $10
    }
    END {
        row()
        for (d = 0; d < 2; d++) {
            dn = d == 0 ? "tx" : "rx"
            if (!(dn in TM)) continue
            printf "    %-2s %-4s %-15s %10.0f %14.0f %12.0f %8.0f %14s %10s\n", dn, "all", "ALL", TM[dn], TF[dn], TC[dn], TL[dn], E(TF[dn], 0), E(TC[dn], 2)
            print "cluster," dn ",all,ALL," sprintf("%.0f,%.0f,%.0f,%.0f,%.0f", TM[dn], TP[dn], TF[dn], TC[dn], TL[dn]) "," E(TF[dn], 0) "," E(TC[dn], 2) >> csv
        }
    }' || echo "  netstats: cluster table FAILED to aggregate $NS_DELTA (sort/awk error) — raw differences kept"
    echo "  frame_B = the signed tier-3 message handed to / taken from the transport (no frame header, no channel encryption — the ss bandwidth above includes both); per envelope = window delta / the $w_env committed envelopes of the window blocks (snapshot edges and block window differ)"
}

# closing agreement: every READABLE node's tip first, the minimum of those
# as a floor, then the full global_root and block_id AT that height on
# every readable node (the stagef_cmt_diff_at_floor / stagef_diff.sh
# --at-height shape, read-only). An unreachable node is recorded, never
# used as a height, and never hides a divergence between the others.
agreement() {
    # rc 0 = every node read and all rows agree
    # rc 2 = DIVERGENCE: two readable rows differ (wins over everything)
    # rc 3 = the readable rows agree, but at least one node (tip or row)
    #        could not be checked — or fewer than 2 nodes were readable
    local n h floor=-1 row ref_row="" div=0 unread=0 n_tip=0 n_row=0
    local -a ok_tip=()
    : > "$BENCH_OUT/agreement.txt"
    for n in $(seq 1 "$NN"); do
        if h=$(node_tip_valid "$n"); then
            ok_tip[n]=1; n_tip=$(( n_tip + 1 ))
            if [ "$floor" -lt 0 ] || [ "$h" -lt "$floor" ]; then floor="$h"; fi
        else
            echo "node$n ${NODE_NAME[n]} UNREACHABLE (no valid tip for ${STALL_S}s) — NOT CHECKED" >> "$BENCH_OUT/agreement.txt"
            unread=1
        fi
    done
    if [ "$n_tip" -lt 2 ]; then
        echo "agreement: NOT CHECKED — only $n_tip of $NN node(s) returned a valid tip; at least 2 are needed to compare anything" | tee -a "$BENCH_OUT/agreement.txt"
        return 3
    fi
    for n in $(seq 1 "$NN"); do
        [ -n "${ok_tip[n]:-}" ] || continue
        row=$(node_sql "$n" "SELECT global_height || '|root:' || lower(hex(global_root)) || '|bid:' || lower(hex(block_id)) FROM v2_blocks WHERE global_height = $floor;" 2>/dev/null) || row=""
        echo "node$n ${NODE_NAME[n]} ${row:-UNREADABLE row at height $floor — NOT CHECKED}" >> "$BENCH_OUT/agreement.txt"
        if [ -z "$row" ]; then unread=1; continue; fi
        n_row=$(( n_row + 1 ))
        if [ -z "$ref_row" ]; then ref_row="$row"
        elif [ "$row" != "$ref_row" ]; then div=1; fi
    done
    if [ "$div" = 1 ]; then
        echo "DIVERGENCE at the floor height $floor between readable nodes — rows:"
        cat "$BENCH_OUT/agreement.txt"
        return 2
    fi
    if [ "$n_row" -lt 2 ]; then
        echo "agreement: NOT CHECKED at the floor height $floor — only $n_row readable row(s); rows:"
        cat "$BENCH_OUT/agreement.txt"
        return 3
    fi
    if [ "$unread" = 1 ]; then
        echo "agreement: INCOMPLETE at the floor height $floor (floor of the readable nodes) — the $n_row readable node(s) agree, $(( NN - n_row )) node(s) NOT CHECKED (listed below); a divergence on an unchecked node cannot be excluded:"
        cat "$BENCH_OUT/agreement.txt"
        return 3
    fi
    echo "$NN/$NN agreement at the floor height $floor (global_root + block_id, every node): OK"
    return 0
}

summary="$BENCH_OUT/summary.txt"
agree_out=$(agreement); agree_rc=$?
{
    echo "bench_tps_live — $(date -u +%Y-%m-%dT%H:%M:%SZ), output $BENCH_OUT"
    echo "parameters: workers M=$M, load D=${D}s, --count all, --amount all, fee $FEE raw,"
    echo "            K=$K pump identit(y/ies) x N=$N_COINS coins (worker I -> identity I mod K + 1),"
    echo "            client hosts H=$H: $BENCH_HOSTS"
    echo "            nodes $NN (reference node$REF ${NODE_NAME[$REF]} ${NODE_IP[$REF]})"
    echo "in-flight bound: ≈ $INFLIGHT_BOUND coins = Σ over the identities with a worker of min(100, N)"
    echo "load: started $LOAD_START, stopped starting rounds at $LOAD_END, last worker done $LOAD_DONE (controller clock)"
    echo "controller -> node ssh + sqlite round trip (ms, measured once at start): $(for n in $(seq 1 "$NN"); do printf 'node%d %s  ' "$n" "${NODE_RTT_MS[n]}"; done)"
    echo "node clock offsets vs controller (s, 1 s resolution): $(for n in $(seq 1 "$NN"); do printf 'node%d %s  ' "$n" "${NODE_SKEW[n]}"; done)"
    echo ""
    echo "window (blocks first seen on node$REF between load start and load end):"
    echo "  blocks                      $w_blocks (heights > $base_h)"
    echo "  committed envelopes         $w_env (Σ tx_count; $w_env_rate after the first window block)"
    echo "  window seconds              $win_s (first-seen of first -> last window block)"
    echo "  TPS                         $tps  (= $w_env_rate / $win_s — fencepost: the first block's envelopes excluded)"
    echo "  envelopes/block mean        $mean_env"
    echo "  envelopes/block max         $w_max"
    echo "  envelopes/block p50         $w_p50"
    echo "  block interval mean         $mean_iv s (controller-observed via ssh, ~1 s granularity)"
    echo "  block interval max          $w_ivmax s"
    echo "  tail after the window       $w_tail_b block(s), $w_tail_e envelope(s) (not in the rate)"
    echo ""
    echo "per-block cap (theory):       $cap = floor($BUDGET NODUS_V2_GLOBAL_UNIT_BUDGET / ${units:-?} declared units)"
    [ "${n_units:-0}" -le 1 ] || echo "  WARNING: the CLIs declared $n_units different unit ceilings; the cap uses the LARGEST"
    echo "measured max per block:       $w_max"
    if [ "$cap" = "n/a" ]; then
        echo "  VERDICT: no spend was built, no cap to compare against"
    elif [ "$w_max" -lt "$cap" ]; then
        echo "  VERDICT: NO block reached the unit cap — the CLIENTS were the bottleneck,"
        echo "           this TPS is a FLOOR on the chain's capacity, not its ceiling."
        if [ "$INFLIGHT_BOUND" -lt "$cap" ]; then
            echo "           STRUCTURAL: the in-flight bound ($INFLIGHT_BOUND) is below the cap ($cap) —"
            echo "           no block CAN fill; raise BENCH_K / BENCH_COINS."
        fi
    else
        n_full=$(awk -F, -v cap="$cap" 'NR > 1 && $4 == 1 && $3 >= cap { n++ } END { print n + 0 }' "$csv")
        echo "  VERDICT: $n_full window block(s) reached the unit cap — the chain's unit budget bound at least those blocks."
    fi
    echo ""
    echo "clients (sum over workers):"
    echo "  rounds $w_rounds (idle — nothing of the shard visible, or its first spend refused — then one height waited: $w_idle)"
    echo "  submitted $w_sub = accepted $w_acc + refused $w_ref (a refusal ends that round's batch)"
    echo "  applied (created row seen on the worker's node) $w_app; DROPPED (not applied within $MAX_HEIGHTS heights) $w_drop"
    echo "  cross-check: workers' applied $w_app vs Σ tx_count over window+tail $(( w_env + w_tail_e )) (a live chain may carry other submitters' envelopes)"
    for f in "$BENCH_OUT"/worker_*.stats; do
        [ -f "$f" ] && echo "  $(tr '\n' ' ' < "$f")"
    done
    echo ""
    echo "nodus-server CPU during the load (utime+stime / the node's own sampled span; the WHOLE process — DHT serving included):"
    for n in $(seq 1 "$NN"); do
        echo "  node$n ${NODE_NAME[n]}  ${CPU_LINE[n]}"
    done
    echo ""
    bw_report
    echo ""
    ns_report
    echo ""
    echo "$agree_out"
} > "$summary"
cat "$summary"
echo "[ok] per-block rows: $csv; summary: $summary; node streams: $BENCH_OUT/node_<N>.stream"
[ ! -s "$NS_CSV" ] || echo "[ok] inter-node counters: $NS_CSV; the snapshots used: $BENCH_OUT/netstats_node<N>.start / .end"

# informational only: each node's CURRENT height and 8 root bytes, read
# at different moments (it races ongoing production — the verdict is the
# floor comparison above)
cs_targets=()
for n in $(seq 1 "$NN"); do cs_targets+=("${NODE_IP[n]}:$CPORT"); done
"$BENCH_CTRL_CLI" cluster-status "${cs_targets[@]}" > "$BENCH_OUT/cluster_status.txt" 2>&1
echo "cluster-status (informational — current heights, not a common height):"
cat "$BENCH_OUT/cluster_status.txt"

ABORTING=0
case "$agree_rc" in
    0) ;;
    2)
        echo "[FAIL] DIVERGENCE between nodes after the bench — see $BENCH_OUT/agreement.txt" >&2
        exit 2 ;;
    *)
        echo "[FAIL] agreement INCOMPLETE: the readable nodes agree, but at least one node (or its row) could not be checked — a divergence there is not excluded; see $BENCH_OUT/agreement.txt" >&2
        exit 3 ;;
esac
if [ "$w_ref" -gt 0 ] || [ "$w_drop" -gt 0 ]; then
    echo "[warn] $w_ref refused and $w_drop dropped spend(s) — counted above, never retried silently"
fi
echo "[DONE] bench_tps_live: $tps TPS over ${win_s}s, max $w_max/block (cap $cap), $NN/$NN agree"
