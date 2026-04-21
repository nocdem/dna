# shellcheck shell=bash
#
# Shared env for Stage F harness scripts. Source from other scripts.
#
# Reads /tmp/stagef_current to find the active BASE_DIR. stagef_up.sh
# writes that file when it spawns the cluster; stagef_down.sh removes
# it.

# Script repo root (resolve regardless of where we're called from).
STAGEF_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
export STAGEF_REPO_ROOT

STAGEF_NODUS_BIN="$STAGEF_REPO_ROOT/nodus/build/nodus-server"
STAGEF_DNACLI_BIN="$STAGEF_REPO_ROOT/messenger/build/cli/dna-connect-cli"
export STAGEF_NODUS_BIN STAGEF_DNACLI_BIN

# Pointer file — stagef_up.sh writes, stagef_down.sh reads+removes.
STAGEF_POINTER=/tmp/stagef_current
export STAGEF_POINTER

# BASE_DIR is either passed in as env (when stagef_up.sh creates it)
# or read from the pointer file (when a later script is invoked).
if [ -z "${BASE_DIR:-}" ]; then
    if [ -f "$STAGEF_POINTER" ]; then
        BASE_DIR="$(cat "$STAGEF_POINTER")"
    fi
fi
export BASE_DIR

# Per-node port layout. 10-stride starting at 14000, caps under
# 65535 even with committee_size=21 (worst case port 14204).
# node 1: 14000-14004, node 2: 14010-14014, ..., node 7: 14060-14064.
stagef_udp_port()      { echo "$(( 14000 + ( $1 - 1 ) * 10 + 0 ))"; }
stagef_tcp_port()      { echo "$(( 14000 + ( $1 - 1 ) * 10 + 1 ))"; }
stagef_peer_port()     { echo "$(( 14000 + ( $1 - 1 ) * 10 + 2 ))"; }
stagef_chan_port()     { echo "$(( 14000 + ( $1 - 1 ) * 10 + 3 ))"; }
stagef_witness_port()  { echo "$(( 14000 + ( $1 - 1 ) * 10 + 4 ))"; }

# Committee size. DNAC_COMMITTEE_SIZE is hardcoded to 7 in
# dnac/src/ledger/genesis_prepare.c; genesis-prepare rejects any
# other value. Keeping parity with production makes the harness
# catch bugs that only show up at 7-node quorum geometry (5-of-7).
STAGEF_COMMITTEE_SIZE=7
export STAGEF_COMMITTEE_SIZE

stagef_node_dir() {
    # $1 = node index 1..STAGEF_COMMITTEE_SIZE
    echo "$BASE_DIR/node$1"
}

stagef_node_chain_db() {
    # Returns path to witness_*.db if exactly one exists; empty otherwise.
    local node_data="$BASE_DIR/node$1/data"
    local found
    found=$(ls "$node_data"/witness_*.db 2>/dev/null | head -1 || true)
    echo "$found"
}

stagef_user_home() { echo "$BASE_DIR/user"; }

# Wrapper: run dna-connect-cli as the test user, fully isolated.
# HOME → test-only .dna directory (no pollution of the real ~/.dna).
# DNA_NO_FALLBACK=1 → CLI skips its hardcoded production bootstrap
# list and uses ONLY the test config (stagef/README.md explains why
# this is required for consensus testing).
#
# BELT & SUSPENDERS: scrub known_nodes + preferred_node BEFORE every
# call. Some CLI code paths still add production IPs even with
# DNA_NO_FALLBACK set (auto-reconnect, RTT probe, etc.). Forcing
# Source 1 (known_nodes cache) to be empty at each call entry makes
# the CLI rebuild it from the config file alone.
stagef_dna() {
    local udna
    udna="$(stagef_user_home)/.dna"
    if [ -d "$udna" ]; then
        rm -f "$udna/known_nodes" "$udna/preferred_node"
    fi
    HOME="$(stagef_user_home)" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" "$@"
}

# ──────────────────────────────────────────────────────────────────────
# Test-user helpers — for tests that need their own validator state
# without contaminating or depending on stagef_user.
# ──────────────────────────────────────────────────────────────────────

# stagef_mk_funded_user LABEL [FUND_RAW]
#   Creates a fresh identity in an isolated HOME under $BASE_DIR/tusers/,
#   funds it FUND_RAW raw DNAC from stagef_user, waits 8s for block commit.
#   Prints HOME path to stdout on success. Caller reads fp from $HOME/fp.txt.
#   Default FUND_RAW = 12M DNAC (enough for 10M STAKE + fee + buffer).
stagef_mk_funded_user() {
    local label="$1"
    local fund_raw="${2:-1200000000000000}"
    local test_home="$BASE_DIR/tusers/${label}_$$"
    mkdir -p "$test_home/.dna"
    cp "$(stagef_user_home)/.dna/config" "$test_home/.dna/config"
    # Retry identity create — back-to-back test runs sometimes hit
    # contention on keyserver publish or local KV init.
    local fp=""
    for _ in 1 2 3; do
        HOME="$test_home" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" \
            -q identity create "$label" "stagefpw" > "$test_home/create.log" 2>&1 || true
        fp=$(HOME="$test_home" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" \
            -q identity whoami 2>&1 | awk '/^Current identity:/ {print $3; exit}')
        if [ -n "$fp" ] && [ ${#fp} -ge 64 ]; then
            break
        fi
        sleep 2
    done
    if [ -z "$fp" ] || [ ${#fp} -lt 64 ]; then
        echo "[FAIL] stagef_mk_funded_user: could not create $label after retries" >&2
        tail -10 "$test_home/create.log" >&2
        return 1
    fi
    echo "$fp" > "$test_home/fp.txt"
    stagef_dna -q dna send "$fp" "$fund_raw" "stagef_fund_$label" \
        > "$test_home/fund.log" 2>&1 || {
        echo "[FAIL] stagef_mk_funded_user: fund failed for $label" >&2
        tail -10 "$test_home/fund.log" >&2
        return 1
    }
    sleep 8
    # Sync the new user's wallet so subsequent CLI calls see the incoming
    # UTXO. Without this, the next `dna stake` fails with "Insufficient
    # funds" even though the chain has the fund TX committed.
    HOME="$test_home" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" \
        -q dna sync > "$test_home/sync.log" 2>&1 || {
        echo "[FAIL] stagef_mk_funded_user: sync failed for $label" >&2
        tail -10 "$test_home/sync.log" >&2
        return 1
    }
    echo "$test_home"
}

# stagef_dna_as TEST_HOME <CLI args>
#   Runs dna-connect-cli with HOME pointing at a test user's isolated home,
#   scrubbing the known_nodes/preferred_node cache first (same belt & braces
#   as stagef_dna).
stagef_dna_as() {
    local test_home="$1"
    shift
    rm -f "$test_home/.dna/known_nodes" "$test_home/.dna/preferred_node"
    HOME="$test_home" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" "$@"
}
