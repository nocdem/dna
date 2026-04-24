#!/usr/bin/env bash
#
# Master bench orchestrator.
#
#   1. Stage F cluster bring-up (reuses stagef_up.sh)
#   2. Create N funded wallets for parallel spend (stagef_mk_funded_user)
#   3. Run bench_cluster_tps — concurrent SPEND workload
#   4. Signal each node to dump QGP_BENCH counters to /tmp
#   5. Copy outputs to results/ + aggregate layer breakdown
#   6. Stage F teardown
#   7. Optional regression diff vs last baseline
#
# Usage:
#     bash nodus/tests/bench_run.sh \
#         --concurrency 4 --duration 30 --output results/
#
# Requires a build with -DQGP_BENCH=ON for layer attribution to
# produce non-zero counters. Without bench build, the TPS numbers are
# still valid but per-layer dump will be all zeros.
#
# See nodus/docs/plans/2026-04-24-perf-harness-design.md section 5/Phase 5.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CLI_BIN="$REPO_ROOT/messenger/build/cli/dna-connect-cli"
NODUS_BIN="$REPO_ROOT/nodus/build/nodus-server"
BENCH_BIN="$REPO_ROOT/nodus/build/tests/bench/bench_cluster_tps"
STAGEF_UP="$REPO_ROOT/nodus/tests/integration/stagef/stagef_up.sh"
STAGEF_DOWN="$REPO_ROOT/nodus/tests/integration/stagef/stagef_down.sh"
STAGEF_ENV="$REPO_ROOT/nodus/tests/integration/stagef/stagef_env.sh"

CONCURRENCY=4
DURATION=30
OUTPUT_DIR="results_$(date -u +%Y%m%d_%H%M%S)"
SKIP_CLUSTER=0
BASELINE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --duration)    DURATION="$2"; shift 2 ;;
        --output)      OUTPUT_DIR="$2"; shift 2 ;;
        --skip-cluster) SKIP_CLUSTER=1; shift ;;
        --baseline)    BASELINE="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,25p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# ── Preflight ────────────────────────────────────────────────────

for bin in "$CLI_BIN" "$NODUS_BIN" "$BENCH_BIN" "$STAGEF_UP" "$STAGEF_DOWN"; do
    if [ ! -x "$bin" ]; then
        echo "[FAIL] missing: $bin" >&2
        echo "       build: cd <project>/build && make" >&2
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
echo "[bench_run] output dir: $OUTPUT_DIR"
echo "[bench_run] concurrency=$CONCURRENCY duration=${DURATION}s"

NODUS_VERSION=$(grep -oP 'NODUS_VERSION_STRING\s+"\K[^"]+' \
    "$REPO_ROOT/nodus/include/nodus/nodus_types.h" 2>/dev/null || echo unknown)
echo "[bench_run] nodus version: $NODUS_VERSION"

# ── Cluster bring-up ────────────────────────────────────────────

if [ "$SKIP_CLUSTER" -eq 0 ]; then
    echo "[bench_run] bringing up Stage F cluster..."
    bash "$STAGEF_UP" > "$OUTPUT_DIR/stagef_up.log" 2>&1 || {
        echo "[FAIL] stagef_up failed. Log tail:" >&2
        tail -30 "$OUTPUT_DIR/stagef_up.log" >&2
        exit 1
    }
fi

# shellcheck disable=SC1090
. "$STAGEF_ENV"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] Stage F BASE_DIR not set after bring-up" >&2
    exit 1
fi

cleanup() {
    if [ "$SKIP_CLUSTER" -eq 0 ]; then
        echo "[bench_run] tearing down cluster..."
        bash "$STAGEF_DOWN" > "$OUTPUT_DIR/stagef_down.log" 2>&1 || true
    fi
}
trap cleanup EXIT

# ── Create funded bench wallets ─────────────────────────────────

echo "[bench_run] creating $CONCURRENCY funded wallets..."
WALLETS_FILE="$OUTPUT_DIR/wallets.txt"
: > "$WALLETS_FILE"
for i in $(seq 1 "$CONCURRENCY"); do
    wallet_home=$(stagef_mk_funded_user "bench_${i}" 1000000000) || {
        echo "[FAIL] could not create funded wallet $i" >&2
        exit 1
    }
    echo "$wallet_home" >> "$WALLETS_FILE"
done
echo "[bench_run] wallets:"
cat "$WALLETS_FILE"

# Destination: reuse stagef master user's fp as the recipient. stagef_up.sh
# writes this to $BASE_DIR/user_fp.txt (see stagef_up.sh:283 +  tests/test_*.sh).
RECIPIENT_FP=""
if [ -f "$BASE_DIR/user_fp.txt" ]; then
    RECIPIENT_FP=$(cat "$BASE_DIR/user_fp.txt")
fi
if [ -z "$RECIPIENT_FP" ]; then
    echo "[FAIL] could not locate recipient fingerprint at $BASE_DIR/user_fp.txt" >&2
    exit 1
fi
echo "[bench_run] recipient: ${RECIPIENT_FP:0:16}..."

# ── Reset counters on each node (optional; QGP_BENCH build only) ──

# (Skipped in this MVP. Counters accumulate across runs — stagef
# brings up fresh data dirs so the process-local state is fresh.)

# ── Run the load generator ──────────────────────────────────────

echo "[bench_run] running bench_cluster_tps..."
"$BENCH_BIN" \
    --cli "$CLI_BIN" \
    --wallets "$WALLETS_FILE" \
    --recipient "$RECIPIENT_FP" \
    --concurrency "$CONCURRENCY" \
    --duration "$DURATION" \
    --version "$NODUS_VERSION" \
    --output "$OUTPUT_DIR/throughput.json"

echo "[bench_run] throughput result:"
cat "$OUTPUT_DIR/throughput.json"
echo

# ── Dump per-node QGP_BENCH counters (best-effort) ──────────────

# Each node in Stage F has a pid file. Signal SIGUSR1 after adding a
# handler to nodus-server (future work). For now, write whatever
# /tmp/nodus_bench_<pid>.json files already exist (if the server is
# a bench build + has a periodic dump mechanism).
LAYER_FILE="$OUTPUT_DIR/layer_breakdown.json"
echo '{"nodes":[' > "$LAYER_FILE"
first=1
for i in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    pid_file="$(stagef_node_dir "$i")/nodus.pid"
    pid=""
    [ -f "$pid_file" ] && pid=$(cat "$pid_file")
    dump="/tmp/nodus_bench_${pid}.json"
    if [ -n "$pid" ] && [ -f "$dump" ]; then
        [ "$first" -eq 1 ] || echo ',' >> "$LAYER_FILE"
        first=0
        printf '{"node":%d,"pid":%s,"counters":' "$i" "$pid" >> "$LAYER_FILE"
        cat "$dump" >> "$LAYER_FILE"
        echo '}' >> "$LAYER_FILE"
    fi
done
echo ']}' >> "$LAYER_FILE"

# ── Optional regression diff ────────────────────────────────────

if [ -n "$BASELINE" ]; then
    DIFF_TOOL="$SCRIPT_DIR/bench_diff.py"
    if [ -x "$DIFF_TOOL" ]; then
        echo "[bench_run] diff against $BASELINE..."
        python3 "$DIFF_TOOL" \
            --baseline "$BASELINE" \
            --current "$OUTPUT_DIR/throughput.json" \
            || exit 1
    else
        echo "[warn] bench_diff.py not executable; skipping diff" >&2
    fi
fi

echo "[bench_run] done. Results in: $OUTPUT_DIR"
