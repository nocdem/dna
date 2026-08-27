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

# Overridable so special-build campaigns (e.g. a run against binaries
# built with non-default tokenomic constants, such as the halving test's
# -DDNAC_BLOCKS_PER_YEAR build) can point the harness at their binaries
# without touching the default build tree.
STAGEF_NODUS_BIN="${STAGEF_NODUS_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-server}"
STAGEF_DNACLI_BIN="${STAGEF_DNACLI_BIN:-$STAGEF_REPO_ROOT/messenger/build/cli/dna-connect-cli}"
STAGEF_NODUSCLI_BIN="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
export STAGEF_NODUS_BIN STAGEF_DNACLI_BIN STAGEF_NODUSCLI_BIN

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

# Timing constants — mirror dnac.h so tests can compute expected
# boundaries parametrically instead of hardcoding literals. When tuning
# the production constants these defaults MUST be updated in lockstep.
#   EPOCH_LENGTH             — committee rotation + settlement cadence
#   CC_GRACE_SAFETY          — chain_config_tx grace for safety params
#   CC_GRACE_ERGONOMIC       — chain_config_tx grace for ergonomic params
# STAGEF_EPOCH_LENGTH can be overridden at bring-up for local smoke
# runs that need faster epoch boundaries (e.g. 10–20 blocks).
STAGEF_EPOCH_LENGTH="${STAGEF_EPOCH_LENGTH:-720}"
STAGEF_CC_GRACE_SAFETY="${STAGEF_CC_GRACE_SAFETY:-17280}"
STAGEF_CC_GRACE_ERGONOMIC="${STAGEF_CC_GRACE_ERGONOMIC:-720}"
export STAGEF_EPOCH_LENGTH STAGEF_CC_GRACE_SAFETY STAGEF_CC_GRACE_ERGONOMIC

stagef_node_dir() {
    # $1 = node index 1..STAGEF_COMMITTEE_SIZE
    echo "$BASE_DIR/node$1"
}

stagef_node_chain_db() {
    # Returns path to the active witness_*.db (largest non-empty file).
    #
    # Stub files of size 0 may appear alongside the real chain DB —
    # observed 2026-05-03 when a chain_id never seen in nodus.log was
    # touched on all 7 nodes within 36 ms (likely halt-recovery / orphan
    # chain_id sqlite3_open path). When sorted alphabetically those
    # stubs can shadow the real chain and surface as "no such table"
    # SQL errors in tests. Filter them out and pick the live DB.
    local node_data="$BASE_DIR/node$1/data"
    local found
    found=$(ls -S "$node_data"/witness_*.db 2>/dev/null | head -1 || true)
    if [ -n "$found" ] && [ ! -s "$found" ]; then
        found=""
    fi
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
# O15B §7 — REACHABILITY SENTINELS
#
# A scenario that dies in setup and a scenario that ran its real consensus
# assertion both exit non-zero, and before this they were indistinguishable
# in the summary. That is how five scenarios could fail for one shared
# setup reason while the suite reported five independent consensus test
# failures — and, worse, how a scenario whose setup silently degraded could
# report PASS without ever reaching the thing it exists to check.
#
# Every scenario now records how far it got. Four ordered marks:
#
#   SETUP_OK        fixtures exist: funded users, validators, whatever the
#                   scenario needs before it can do its real work.
#   TARGET_REACHED  the operation under test was actually performed.
#   ASSERT_RUN      the terminal assertion executed (it may still fail).
#   PASS            the scenario succeeded.
#
# The marks are files, so they survive the subshell each scenario runs in
# and can be read by the runner after the fact. `genesis_protocol.sh`
# reports them per scenario and treats a PASS with no ASSERT_RUN as a
# FAILURE — a green scenario that never reached its assertion is not
# coverage, and saying so is the whole point.
# ──────────────────────────────────────────────────────────────────────

# Directory holding this run's sentinel marks.
#
# RESOLVED FRESH ON EVERY CALL, from the pointer file first.
#
# The first version read `${BASE_DIR:-/tmp}`, captured when the caller
# sourced this file — and that made the whole gate INERT in a full run.
# genesis_protocol.sh sources this at script top, BEFORE Phase 2 brings the
# cluster up, and at that moment /tmp/stagef_current does not exist (the
# defensive stagef_down.sh removed it). So the runner's BASE_DIR stayed
# unset, stagef_up.sh set its own in a CHILD process, and the runner went on
# looking in /tmp/sentinels while every scenario wrote to
# $NEW_BASE/sentinels. Every scenario read back NONE, was classified
# UNINSTRUMENTED, and the "PASS without ASSERT_RUN is a FAILURE" conversion
# could never fire. It worked only in --scenarios mode, where the pointer
# already existed at source time — which is exactly how it was tested.
# Review R3 found this.
stagef_sentinel_dir() {
    local base="${BASE_DIR:-}"
    if [ -f "$STAGEF_POINTER" ]; then
        base="$(cat "$STAGEF_POINTER" 2>/dev/null || true)"
    fi
    echo "${base:-/tmp}/sentinels"
}

# stagef_sentinel MARK  — record that this scenario reached MARK.
# The scenario name is derived from $0 so no scenario has to repeat it.
#
# The FIRST mark of a scenario TRUNCATES its file. Appending unconditionally
# meant marks accumulated across repeated `--scenarios` runs against one live
# harness: a scenario that recorded ASSERT_RUN on run 1 and skipped it on
# run 2 still showed the mark, masking precisely the regression the gate
# exists to catch (review R3). SETUP_OK is every instrumented scenario's
# first mark, so truncating on it starts each run clean.
stagef_sentinel() {
    local mark="$1"
    local name
    name="$(basename "${0:-unknown}" .sh)"
    local dir
    dir="$(stagef_sentinel_dir)"
    mkdir -p "$dir" 2>/dev/null || return 0
    if [ "$mark" = "SETUP_OK" ]; then
        printf '%s\n' "$mark" > "$dir/$name"
    else
        printf '%s\n' "$mark" >> "$dir/$name"
    fi
    return 0
}

# stagef_sentinel_has NAME MARK — 0 if scenario NAME recorded MARK.
stagef_sentinel_has() {
    local dir
    dir="$(stagef_sentinel_dir)"
    [ -f "$dir/$1" ] || return 1
    grep -qx "$2" "$dir/$1"
}

# stagef_sentinel_summary NAME — the marks NAME recorded, space separated.
stagef_sentinel_summary() {
    local dir
    dir="$(stagef_sentinel_dir)"
    if [ -f "$dir/$1" ]; then
        tr '\n' ' ' < "$dir/$1"
    else
        printf 'NONE'
    fi
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
    # Fund TX retry — CLI's commit-wait can race with cluster timing
    # in the moments after stagef_up returns (peer mesh + leader
    # election still settling, view-change rotations under load).
    #
    # ⚠ The CLI exit code is NOT the source of truth for commit: the
    # cluster can commit the spend AFTER the CLI's ~30 s wait expires
    # (known pattern, memory project_genesis_client_false_error — seen
    # live 2026-07-22 in test_view_change_fork: leader paused → view
    # change latency → CLI timeout, yet the TX committed at the next
    # height with 7/7 state_root identity). So after ANY failed CLI
    # attempt, poll the CHAIN (node1 witness DB, read-only) for the
    # funded UTXO before declaring failure or re-sending — this both
    # kills the false negative and avoids duplicate fund spends.
    stagef_fund_on_chain() {
        # Poll EVERY node's witness DB and succeed on the first hit —
        # a witness DB only advances via consensus commit, so any copy
        # showing the UTXO proves the chain committed it. Polling a
        # single fixed node is wrong whenever a test has PAUSED that
        # node (test_view_change_fork SIGSTOPs node1): the frozen
        # replica can never show a late commit, and the old node1-only
        # check reported "chain verified empty" against a stale file
        # (BUGS.md 2026-08-04, H1).
        #
        # O15B §7 — the UTXO must be SPENDABLE, not merely present.
        # Counting rows was not enough: consensus rejects a spend whose
        # input is still inside its post-UNSTAKE cooldown (Rule D,
        # nodus_witness_verify.c:730), so a funded user holding only
        # locked coins would pass this check and then fail every
        # subsequent operation with an unexplained timeout. That is
        # exactly the failure this season root-caused. The predicate is
        # now the same one consensus applies: unlock_block <= the
        # chain's current height.
        # The chain head column is `blocks.height` (see the witness schema:
        # `CREATE TABLE blocks (height INTEGER PRIMARY KEY AUTOINCREMENT, ...)`).
        # An empty result from either query is treated as "not yet", never as
        # success — a query that cannot run must not read as a confirmation.
        local owner_fp="$1" node db cnt height
        for node in 1 2 3 4 5 6 7; do
            db=$(ls "$BASE_DIR/node$node/data"/witness_*.db 2>/dev/null | head -1)
            [ -n "$db" ] || continue
            height=$(sqlite3 -readonly "$db" \
                "SELECT COALESCE(MAX(height),0) FROM blocks;" \
                2>/dev/null) || continue
            [ -n "$height" ] || continue
            cnt=$(sqlite3 -readonly "$db" \
                "SELECT COUNT(*) FROM utxo_set
                  WHERE owner = '$owner_fp'
                    AND COALESCE(unlock_block,0) <= $height;" \
                2>/dev/null) || continue
            [ -n "$cnt" ] || continue
            [ "${cnt:-0}" -ge 1 ] && return 0
        done
        return 1
    }
    fund_ok=0
    for attempt in 1 2 3; do
        if stagef_dna -q dna send "$fp" "$fund_raw" "stagef_fund_$label" \
                > "$test_home/fund.log" 2>&1; then
            # O15B §7 — A CLI SUCCESS IS NOT A COMMIT.
            #
            # This branch used to set fund_ok=1 on the exit code alone, so
            # the helper's guarantee depended on the CLI's opinion. The
            # chain is the authority in BOTH directions: a CLI failure may
            # still have committed (the pre-existing false negative this
            # code already handled), and a CLI success must still be
            # confirmed before anything is built on top of it. Confirming
            # only failures left the success path unproven.
            chain_deadline=$(( SECONDS + 45 ))
            while [ $SECONDS -lt $chain_deadline ]; do
                if stagef_fund_on_chain "$fp"; then
                    fund_ok=1
                    break
                fi
                sleep 2
            done
            [ "$fund_ok" -eq 1 ] && break
            echo "[warn] stagef_mk_funded_user: CLI reported success but no SPENDABLE UTXO appeared on chain for $label (attempt $attempt)" >&2
        fi
        # CLI said failure — ask the chain before believing it. Poll up
        # to 45 s (covers round timeout + view change + commit lag).
        chain_deadline=$(( SECONDS + 45 ))
        while [ $SECONDS -lt $chain_deadline ]; do
            if stagef_fund_on_chain "$fp"; then
                echo "[info] stagef_mk_funded_user: CLI timed out but fund TX COMMITTED on chain for $label (attempt $attempt)" >&2
                fund_ok=1
                break
            fi
            sleep 2
        done
        [ "$fund_ok" -eq 1 ] && break
        if [ "$attempt" -lt 3 ]; then
            echo "[info] stagef_mk_funded_user: fund attempt $attempt failed for $label (chain checked), retrying in 5s..." >&2
            tail -3 "$test_home/fund.log" >&2
            sleep 5
        fi
    done
    if [ "$fund_ok" -eq 0 ]; then
        echo "[FAIL] stagef_mk_funded_user: fund failed for $label after 3 attempts (chain verified empty)" >&2
        tail -10 "$test_home/fund.log" >&2
        return 1
    fi
    # O15B §7 — EXPLICIT CONFIRMATION, NOT A GUESS.
    #
    # This was `sleep 8`. A fixed sleep is a bet that the cluster is done
    # in eight seconds; it is too long when things are healthy and silently
    # wrong when they are not, and §7 forbids replacing a readiness
    # condition with a timing guess. The condition is the one that
    # actually matters — the funded UTXO is committed AND spendable — and
    # it has already been established above by stagef_fund_on_chain, so
    # this is a short bounded re-confirmation that the state is still
    # there rather than a wait for it to appear.
    fund_stable=0
    stable_deadline=$(( SECONDS + 20 ))
    while [ $SECONDS -lt $stable_deadline ]; do
        if stagef_fund_on_chain "$fp"; then fund_stable=1; break; fi
        sleep 1
    done
    if [ "$fund_stable" -eq 0 ]; then
        echo "[FAIL] stagef_mk_funded_user: funded UTXO for $label did not remain spendable on chain" >&2
        return 1
    fi

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
