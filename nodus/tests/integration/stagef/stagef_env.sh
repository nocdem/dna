# shellcheck shell=bash
#
# Shared env for Stage F harness scripts. Source from other scripts.
#
# Reads /tmp/stagef_current to find the active BASE_DIR. stagef_up_v2.sh
# (R3 W4-D deleted the legacy stagef_up.sh, which used to be the other
# writer) writes that file when it spawns the cluster; stagef_down.sh
# removes it.

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

# Pointer file — stagef_up_v2.sh writes, stagef_down.sh reads+removes.
STAGEF_POINTER=/tmp/stagef_current
export STAGEF_POINTER

# BASE_DIR is either passed in as env (when stagef_up_v2.sh creates it)
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
# and can be read by the runner after the fact. The now-deleted legacy
# runner, `genesis_protocol.sh`, reported them per scenario and treated a
# PASS with no ASSERT_RUN as a FAILURE — a green scenario that never
# reached its assertion is not coverage, and saying so was the whole
# point. R3 W4-D FINDING, NOT FIXED HERE (out of this delta's scope,
# comments-only): `genesis_protocol_v2.sh`, the surviving Comet runner,
# reads no sentinel mark at all — the PASS-without-ASSERT_RUN conversion
# this mechanism exists for has no replacement on the Comet lane.
# ──────────────────────────────────────────────────────────────────────

# Directory holding this run's sentinel marks.
#
# RESOLVED FRESH ON EVERY CALL, from the pointer file first.
#
# The first version read `${BASE_DIR:-/tmp}`, captured when the caller
# sourced this file — and that made the whole gate INERT in a full run.
# The now-deleted legacy runner, genesis_protocol.sh, sourced this at
# script top, BEFORE Phase 2 brought the cluster up, and at that moment
# /tmp/stagef_current did not exist (the defensive stagef_down.sh removed
# it). So the runner's BASE_DIR stayed unset, the (also now-deleted)
# stagef_up.sh set its own in a CHILD process, and the runner went on
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
    # in the moments after stagef_up_v2.sh returns (peer mesh still
    # settling, the round-robin proposer's round timeouts under load).
    #
    # ⚠ The CLI exit code is NOT the source of truth for commit: the
    # cluster can commit the spend AFTER the CLI's ~30 s wait expires
    # (known pattern, memory project_genesis_client_false_error — seen
    # live 2026-07-22 on the legacy lane's test_view_change_fork,
    # deleted in R3 W4: leader paused → view-change latency → CLI
    # timeout, yet the TX committed at the next height with 7/7
    # state_root identity). So after ANY failed CLI
    # attempt, poll the CHAIN (node1 witness DB, read-only) for the
    # funded UTXO before declaring failure or re-sending — this both
    # kills the false negative and avoids duplicate fund spends.
    stagef_fund_on_chain() {
        # Poll EVERY node's witness DB and succeed on the first hit —
        # a witness DB only advances via consensus commit, so any copy
        # showing the UTXO proves the chain committed it. Polling a
        # single fixed node is wrong whenever a test has PAUSED that
        # node (test_cmt_dead_proposer.sh SIGSTOPs node 2; the deleted
        # legacy test_view_change_fork paused the DERIVED epoch leader,
        # a different node on every run): the frozen replica can
        # never show a late commit, and the old node1-only check
        # reported "chain verified empty" against a stale file
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

# ──────────────────────────────────────────────────────────────────────
# R3 W4-D — the LEGACY / pre-Comet PBFT lane's committee/epoch-leader
# derivation (running_nodes, ref_db, node_view, cluster_view_max,
# log_count, node_pubkey_hex, the VSET_* wire-geometry constants,
# stagef_leader_entry) is DELETED with the closed consensus lane: its
# only readers were the legacy runner (genesis_protocol.sh, deleted) and
# test_vset_grow_shrink.sh / test_view_change_fork.sh (both deleted).
# Grepped every surviving scenario (the 11 test_cmt_*/test_v2_* scripts)
# and the other harness scripts for every one of these names — zero
# calls anywhere, only one historical comment reference
# (tests/test_cmt_dead_proposer.sh:8, outside this package's whitelist,
# not fixed — its citation of "stagef_env.sh:512" is now a stale line
# number, reported not corrected).
# ──────────────────────────────────────────────────────────────────────
# R3 W3 package C2d — COMET LANE HELPERS
#
# R3 W4-D deleted the LEGACY / pre-Comet PBFT lane's derivation that used
# to stand above this line ($pbft_state, current_view, `blocks`,
# `stagef_leader_entry`'s committee-snapshot derivation, running_nodes,
# ref_db — see the deletion note above). NONE of it applied on a
# version-3 (cometbft) chain: `pbft_state` and `current_view` are never
# written there (nodus_witness.c's `witness_post_open_gate` routes a
# version-3 chain straight into `witness_cmt_tick`, which never touches
# the legacy BFT state), and there is no per-node view or leader RANK to
# derive — cometbft's proposer is a weighted round-robin over
# accumulated priority, carried in the `cmt_state` KV blob, not a SQL
# column this harness can read.
#
# Every SURVIVING scenario must still never call stagef_fund_on_chain /
# stagef_mk_funded_user: both read the legacy `blocks.height` column to
# find the chain head (stagef_fund_on_chain, above), and a version-3
# chain never writes `blocks` — the read returns empty and the height
# gate silently never opens. Comet scenarios fund themselves from their
# OWN genesis allocation (stagef_up_v2.sh's per-node / v2user / v2pump
# leaves) instead, exactly as the existing V2 scenarios already do.
#
# ⚠ THIS FILE IS SOURCED BY EVERY SURVIVING SCENARIO.
# Nothing below runs at source time except constant assignments (the two
# Comet timing constants just below and CLI-SPEND's pump constants).
# ──────────────────────────────────────────────────────────────────────

# The two Comet timing constants this build overrides away from the
# library defaults, read directly from the node's own construction so a
# scenario's wait budget is derived from the SAME numbers the node runs
# on, never a second, hand-copied guess:
#   create_empty_blocks_interval — nodus_witness_cmt_node.c:1761
#     (`n->config.create_empty_blocks_interval = 60000 * CMT_MILLISECOND`)
#   timeout_commit                — nodus_witness_cmt_node.c:1760
#     (`n->config.timeout_commit = 4000 * CMT_MILLISECOND` — tokenomics-v3
#     P1 round 5, operator decision S-7: 5000 -> 4000, decision file §1
#     line 57's 2026-09-23 note)
# `create_empty_blocks` itself stays the library default `true`
# (shared/dnac/cmt_config.h:121) — this build does not turn it off.
#
# DELTA 1 (HISTORICAL — SUPERSEDED BY tokenomics-v3 P1, see below).
# Before P1: MEASURED FACT — STAGEF_CMT_EMPTY_INTERVAL_MS was NOT the
# observed pace, only an upper bound. Rule N attendance wrote the
# proposer's `last_signed_block` on every single block, so the global
# root changed at every height and cometbft's `needProofBlock`
# (state.go:1106-1129, ported at cmt_cs.c:1872) was TRUE at every height
# in that build — every block was a proof block, produced at the
# `timeout_commit` pace (5 000 ms at the time this was measured, now
# 4 000 ms — round 5, S-7), not the `create_empty_blocks_interval` pace:
# measured live, seven nodes committed at roughly one block per 6 s, not
# one per 60 s.
#
# tokenomics-v3 P1 (D-4): attendance is now out-of-root — a
# decided_last_commit vote credits `v2_attendance`, which is not a leg of
# any root, so an EMPTY block no longer moves `system_state_root` and
# `needProofBlock` is FALSE on an idle chain. STAGEF_CMT_EMPTY_INTERVAL_MS
# is therefore now the OBSERVED pace again, as D-4 rev 3 always specified
# — this is exactly the property `test_cmt_empty_blocks.sh` measures
# directly (>= 45 s between consecutive idle commits) rather than assumes
# from this comment. Still used below as the stall detector's budget; on
# THIS build that budget and the expected pace are the same number, which
# they were not before P1.
STAGEF_CMT_EMPTY_INTERVAL_MS=60000
STAGEF_CMT_TIMEOUT_COMMIT_MS=4000
export STAGEF_CMT_EMPTY_INTERVAL_MS STAGEF_CMT_TIMEOUT_COMMIT_MS

# stagef_cmt_tip DB — the Comet lane's tip, read from v2_blocks (the
# SAME table the pre-Comet V2 lane wrote; the Comet apply lane's block
# metadata insert is a 10-column variant of the same statement —
# nodus_witness_v2_apply.c:4805-4816). -1 on an empty or unreadable
# table, never a silent 0 that a caller could mistake for genesis.
stagef_cmt_tip() {
    local db="$1"
    sqlite3 "$db" "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;" \
        2>/dev/null || echo -1
}

# stagef_cmt_wait_height DB TARGET [STALL_INTERVALS]
#
# Poll DB's Comet tip until it reaches TARGET. THE WAIT IS PROGRESS-
# BOUNDED, never a bare wall-clock cap on the whole call: a stall is
# declared only after STALL_INTERVALS consecutive
# create_empty_blocks_interval-lengths (60 000 ms each, by default) have
# elapsed with the height NOT increasing at all. On an idle chain a
# healthy Comet lane commits at least once per interval by construction
# (CreateEmptyBlocks=true), so "no increase for STALL_INTERVALS
# intervals" is a real stall, not an unlucky poll — the same discipline
# `pump_to_height`'s PUMP_STALL_ROUNDS applies on the legacy lane
# (README.md "never tune a timeout to make a scenario pass").
#
# Prints the final height read and returns 0 on reaching TARGET, 1 on a
# declared stall (still prints the height it stalled at, for the
# caller's diagnosis).
stagef_cmt_wait_height() {
    local db="$1" target="$2" stall_intervals="${3:-3}"
    local poll_s=5
    local stall_budget_s=$(( stall_intervals * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))
    local stall_polls=$(( (stall_budget_s + poll_s - 1) / poll_s ))
    local last=-1 since=0 h
    while :; do
        h=$(stagef_cmt_tip "$db")
        [ -n "$h" ] || h=-1
        if [ "$h" -ge "$target" ]; then printf '%s\n' "$h"; return 0; fi
        if [ "$h" -gt "$last" ]; then last="$h"; since=0
        else since=$(( since + 1 )); fi
        if [ "$since" -ge "$stall_polls" ]; then printf '%s\n' "$h"; return 1; fi
        sleep "$poll_s"
    done
}

# stagef_cmt_wait_row DB SQL [STALL_INTERVALS] [MAX_HEIGHTS]
#
# DELTA 2 — WHY THIS EXISTS, MEASURED. "Wait for tip+1, then assert a
# ledger-effect row exists" is UNSOUND: a CheckTx-APPROVED transaction is
# NOT guaranteed to land in the very next block. Measured live
# (`/tmp/stagef-20260917T021735Z`, `test_v2_stake.sh` on the fixed
# server): a stake envelope was APPROVED at tip 2; its `v2_tx_index` row
# did not exist at tip 3 and was absent until tip 4 (`tx_count` per
# height: 0,0,0,1,0,0). The reference makes no promise that an admitted
# transaction is in the very next proposal — one that arrives while a
# round is already in flight (PrepareProposal for the next height
# already building, or the eventual proposer's own mempool receiving the
# gossip a tick late) lands in a LATER one. Every wait for a ledger
# effect must therefore wait for the EFFECT ITSELF, never for "one height
# past submission" — that shape (`stagef_cmt_wait_height DB $((t+1))`
# followed by a bare row read) is exactly the defect this helper
# replaces at every call site that used it.
#
# SQL is an expression whose result is a COUNT (`SELECT COUNT(*) FROM
# ...`); this polls it every 5 s until it reads > 0. The STALL bound
# reuses `stagef_cmt_tip`, the SAME stall detection
# `stagef_cmt_wait_height` uses (STALL_INTERVALS consecutive
# create_empty_blocks_interval-lengths with the CHAIN'S TIP not
# increasing at all — not the row's own count, which by definition
# cannot "increase" usefully past 1 for a single-row check). This is
# deliberate: the chain can keep committing perfectly healthy EMPTY
# blocks while the one transaction a caller is waiting on is still
# somewhere between CheckTx and inclusion, and that must not be read as
# a stall.
#
# DELTA 3 — A SECOND, INDEPENDENT BOUND WAS MISSING, MEASURED. The stall
# bound alone lets this loop wait FOREVER on a chain that keeps
# committing perfectly healthily while the specific row it is waiting
# for never appears (a dropped or mis-keyed query) — measured: the stake
# scenario sat 34 minutes at tip 347, still polling, until killed by
# hand (rc 143). MAX_HEIGHTS (default 20 — a judgment: three full
# proposer cycles at this build's 7-validator committee, not a measured
# constant) is a SECOND, independent exit: if the chain's tip has
# advanced more than MAX_HEIGHTS past the height this call STARTED at
# while the row is still absent, this returns 2 — a chain that keeps
# producing dozens of blocks without ever including the awaited
# transaction is not "still delayed", it is DROPPED, and no stall bound
# tuned for a healthy chain's own cadence can ever catch that on its
# own.
#
# Prints the CURRENT TIP on every exit (0, 1 or 2) — never the row's own
# count — so the caller can read the row's actual height on success, or
# diagnose on failure. Returns 0 on success, 1 on a declared STALL (the
# chain's tip stopped advancing), 2 on a declared HEIGHT BUDGET EXCEEDED
# (the chain kept advancing, but not with this row in it). Callers
# should give these two distinct die() messages — "chain stalled" is a
# different diagnosis from "chain healthy, transaction dropped".
#
# ⚠ NEITHER EXIT DISTINGUISHES A GENUINE DROP FROM A QUERY THAT WILL
# NEVER MATCH (e.g. a mis-keyed column — see DEFECT 1, R3 W3 delta 3,
# which is exactly how this was found: `test_v2_stake.sh` waited on a
# value that could never appear, and this budget is what turns "wait
# forever" into a bounded, diagnosable failure rather than a fix for the
# underlying mis-keying). A STALL (return 1) and a budget exceeded
# (return 2) ARE distinguished from each other; neither is distinguished
# from "the reference genuinely, silently dropped this transaction" —
# that residual is disclosed in each caller's own "how it can lie"
# section.
stagef_cmt_wait_row() {
    local db="$1" sql="$2" stall_intervals="${3:-3}" max_heights="${4:-20}"
    local poll_s=5
    local stall_budget_s=$(( stall_intervals * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))
    local stall_polls=$(( (stall_budget_s + poll_s - 1) / poll_s ))
    local start_h last=-1 since=0 h cnt
    start_h=$(stagef_cmt_tip "$db")
    [ -n "$start_h" ] || start_h=-1
    while :; do
        cnt=$(sqlite3 "$db" "$sql" 2>/dev/null || echo 0)
        case "$cnt" in ''|*[!0-9]*) cnt=0 ;; esac
        if [ "$cnt" -gt 0 ]; then
            h=$(stagef_cmt_tip "$db")
            printf '%s\n' "$h"
            return 0
        fi
        h=$(stagef_cmt_tip "$db")
        [ -n "$h" ] || h=-1
        if [ "$h" -gt "$last" ]; then last="$h"; since=0
        else since=$(( since + 1 )); fi
        if [ "$since" -ge "$stall_polls" ]; then printf '%s\n' "$h"; return 1; fi
        if [ "$(( h - start_h ))" -gt "$max_heights" ]; then printf '%s\n' "$h"; return 2; fi
        sleep "$poll_s"
    done
}

# ──────────────────────────────────────────────────────────────────────
# CLI-SPEND — TRANSACTION-DRIVEN HEIGHT (the "pump")
#
# WHY. After tokenomics-v3 P1 an idle chain commits one block per
# create_empty_blocks_interval (60 s, above), so a scenario that must
# cross several epoch boundaries waited on idle production alone — the
# nodus/BUGS.md top entry records the cost (test_cmt_rule_n_retire.sh
# ≈ 40-45 min of a ≈ 64 min short-epoch sweep). `nodus-cli v2-envelope
# spend` now exists, so a scenario can drive height with REAL CORE SPEND
# transactions instead.
#
# THE FUNDER. Node STAGEF_PUMP_FUNDER_NODE's own genesis leaf (default
# node 3). stagef_up_v2.sh gives every node one leaf (100M DNAC) and no
# scenario in genesis_protocol_v2.sh's list claims node 1's or node 3's
# (grep of every `v2-claim` call: test_v2_claim.sh = node 2,
# test_cmt_mempool_flood.sh = nodes 4-7, test_v2_stake.sh = v2user,
# test_cmt_claim_flood.sh / test_v2_epoch_boundary.sh = the PUMP batch,
# test_cmt_empty_blocks.sh = v2probe). The PUMP identity's batch is
# deliberately NOT the funder: test_cmt_claim_flood.sh must be the one to
# claim it, in one call, or its assertion breaks.
#
# THE SPEND. Each step sends the funder's LARGEST spendable native coin
# back to itself minus the fee: exactly one input, exactly one output, no
# change, no dust. The funder's coin count therefore never grows, which
# matters because dnac_utxo lists at most 100 coins with no ORDER BY
# before its LIMIT (nodus_witness_db.c nodus_witness_utxo_by_owner) — a
# pump that minted a dust output per step would, after ~100 steps, hide
# its own change coin from the CLI's selection.
#
# ONE SPEND IN FLIGHT, EACH CONFIRMED BY ITS LEDGER EFFECT. The next spend
# is built only after the previous one's created UTXO row (utxo_set
# tx_hash = the envelope's intent_id, nodus_witness_rt_native.c
# rtn_utxo_create_eff :1463) is visible on the reference node, via
# stagef_cmt_wait_row. Chosen over "one spend per observed height"
# because (a) dnac_utxo lists COMMITTED coins only, so a second spend
# built before the first commits would select the same coin and be a
# double spend; (b) every step is proven applied, not merely admitted —
# a CheckTx-approved spend that never lands is reported (rc 2), never
# papered over by the next one.
#
# PROGRESS-BOUNDED, NEVER A BIGGER TIMEOUT. Every wait inside is
# stagef_cmt_wait_row's own two bounds (STALL_INTERVALS × 60 s with the
# tip not moving → rc 1; the awaited row absent 20 heights past its
# submission → rc 2). There is no wall-clock cap on the whole call.
# ──────────────────────────────────────────────────────────────────────

# The funder / submission nodes, and the fee each pump step pays: the
# CLI's own default, max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE) — both
# 1 000 000 raw (dnac/include/dnac/dnac.h:143,
# nodus/include/nodus/nodus_types.h:266) — passed explicitly so the
# helper's "amount = coin − fee" arithmetic and the CLI can never disagree.
STAGEF_PUMP_FUNDER_NODE="${STAGEF_PUMP_FUNDER_NODE:-3}"
STAGEF_PUMP_SUBMIT_NODE="${STAGEF_PUMP_SUBMIT_NODE:-1}"
STAGEF_PUMP_FEE_RAW=1000000
# PUMPED PACE, for a scenario's SKIP feasibility budget only (never a
# wait bound). JUDGMENT, NOT MEASURED on this build: one pump step costs
# at most one block interval to inclusion — measured ≈ 6 s per proof
# block at timeout_commit 5 s before P1 (the DELTA 1 note above; 4 s
# now) — plus stagef_cmt_wait_row's 5 s poll plus one CLI session
# (≈ 1 s per Kyber1024 handshake + T2 auth, test_cmt_claim_flood.sh's
# measured per-leaf reconnect pace). ≈ 12 s, rounded up to 15. At the
# harness conventions it changes no verdict: E=15 proceeds, E=720 still
# skips.
STAGEF_CMT_PUMP_BLOCK_S=15
export STAGEF_PUMP_FUNDER_NODE STAGEF_PUMP_SUBMIT_NODE STAGEF_PUMP_FEE_RAW \
       STAGEF_CMT_PUMP_BLOCK_S

stagef_pump_keys() { echo "$(stagef_node_dir "$STAGEF_PUMP_FUNDER_NODE")/identity"; }

# stagef_pump_largest DB — the funder's largest SPENDABLE native coin on
# DB (unlock_block <= DB's tip, the stake builder's and the CLI's own
# lock predicate), 0 when it holds none or the read fails.
stagef_pump_largest() {
    local db="$1" fp amt
    fp=$(cat "$(stagef_pump_keys)/nodus.fp" 2>/dev/null || true)
    [ "${#fp}" = 128 ] || { echo 0; return 0; }
    amt=$(sqlite3 "$db" \
        "SELECT COALESCE(MAX(amount),0) FROM utxo_set
          WHERE owner = '$fp' AND token_id = zeroblob(64)
            AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks);" \
        2>/dev/null || echo 0)
    case "$amt" in ''|*[!0-9]*) amt=0 ;; esac
    echo "$amt"
}

# stagef_cmt_pump_ready DB
#
# A PURE FEASIBILITY CHECK — submits nothing, changes no chain state, so
# a scenario that decides its pace with it and then SKIPs leaves nothing
# behind. Records the answer in STAGEF_PUMP_READY (1 / 0) for
# stagef_cmt_advance_to. CALL IT DIRECTLY, never inside $(...): the
# variable must land in the calling shell.
#   rc 0 / READY=1 — nodus-cli, the genesis config and the funder
#                    identity exist, AND the funder either already holds
#                    a spendable native coin above the fee on DB, or the
#                    config binds a genesis leaf to it (claimed by
#                    stagef_cmt_pump_to's first step, not here);
#   rc 1 / READY=0 — otherwise (reason on stderr).
# It cannot see whether that leaf was already claimed AND spent down by
# someone else — nothing in the sweep does that; if it ever happens the
# first pump step's claim is refused and the pump FAULTS (rc 3) loudly.
stagef_cmt_pump_ready() {
    local db="$1" keys conf fp
    STAGEF_PUMP_READY=0
    keys=$(stagef_pump_keys)
    conf="$BASE_DIR/v2_genesis.conf"
    if [ ! -x "$STAGEF_NODUSCLI_BIN" ] || [ ! -f "$conf" ] || \
       [ ! -s "$keys/nodus.pk" ] || [ ! -s "$keys/nodus.fp" ]; then
        echo "[pump] unavailable: needs $STAGEF_NODUSCLI_BIN, $conf and $keys" >&2
        return 1
    fi
    fp=$(cat "$keys/nodus.fp")
    if [ "$(stagef_pump_largest "$db")" -le "$STAGEF_PUMP_FEE_RAW" ] && \
       ! grep -q "^dest_binding = ${fp}\$" "$conf"; then
        echo "[pump] unavailable: node$STAGEF_PUMP_FUNDER_NODE holds no coin above the fee and $conf binds no leaf to it" >&2
        return 1
    fi
    STAGEF_PUMP_READY=1
    return 0
}

# stagef_pump_claim DB — claim the funder's genesis leaf (`v2-claim`,
# submitted to the submit node) and wait for the claimed coin as a
# LEDGER EFFECT: an unlocked native coin above the fee owned by the
# funder — ordinarily the 100M DNAC leaf itself. The predicate is only
# "above the fee": a tokenomics-v3 P2 PAYDAY coin (a validator's payout,
# output_index >= 400) landing in the same wait would satisfy it too;
# harmless for the pump, which spends whichever coin is largest
# (stagef_pump_largest). Prints the tip; rc 0 /
# 1 stall / 2 not included within 20 heights / 3 the claim was refused.
stagef_pump_claim() {
    local db="$1" keys conf fp port log h wrc
    keys=$(stagef_pump_keys)
    conf="$BASE_DIR/v2_genesis.conf"
    fp=$(cat "$keys/nodus.fp")
    port=$(stagef_tcp_port "$STAGEF_PUMP_SUBMIT_NODE")
    log="$BASE_DIR/pump_claim_node${STAGEF_PUMP_FUNDER_NODE}.log"
    if ! "$STAGEF_NODUSCLI_BIN" -s 127.0.0.1 -p "$port" v2-claim \
           --config "$conf" --db "$db" --keys "$keys" \
           --submit "127.0.0.1:$port" > "$log" 2>&1; then
        echo "[pump] node$STAGEF_PUMP_FUNDER_NODE's genesis-leaf claim was refused:" >&2
        cat "$log" >&2
        stagef_cmt_tip "$db"
        return 3
    fi
    h=$(stagef_cmt_wait_row "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$fp'
           AND token_id = zeroblob(64) AND amount > $STAGEF_PUMP_FEE_RAW;") \
        && wrc=0 || wrc=$?
    if [ "$wrc" != 0 ]; then
        echo "[pump] node$STAGEF_PUMP_FUNDER_NODE's claimed coin never appeared (wait rc=$wrc, tip $h)" >&2
    else
        echo "[pump] node$STAGEF_PUMP_FUNDER_NODE's genesis leaf claimed (tip $h)" >&2
    fi
    printf '%s\n' "$h"
    return "$wrc"
}

# stagef_cmt_pump_to DB TARGET [STALL_INTERVALS]
#
# Drive DB's Comet tip to TARGET with pump spends (see the section note).
# Requires a successful stagef_cmt_pump_ready. Prints the final tip read.
#   rc 0  reached TARGET
#   rc 1  STALL — a spend's inclusion wait saw the tip stop advancing
#   rc 2  DROPPED — a CheckTx-approved spend was not included within 20
#         heights while the chain kept advancing
#   rc 3  PUMP FAULT — the funder's leaf claim was refused, no spendable
#         funder coin above the fee even after claiming, the CLI
#         refused/failed, or its output carried no intent_id (the CLI's
#         own output is echoed to stderr)
# FIRST STEP, when the funder holds no coin above the fee: claim its
# genesis leaf (stagef_pump_claim) — ONCE per call; a second shortfall
# is a fault, not another claim.
# A fault is RETURNED, never retried: the caller decides; nothing here
# falls back to idle production silently.
stagef_cmt_pump_to() {
    local db="$1" target="$2" stall="${3:-3}"
    local keys fp port h amt out intent wrc steps=0 claimed=0
    keys=$(stagef_pump_keys)
    fp=$(cat "$keys/nodus.fp" 2>/dev/null || true)
    port=$(stagef_tcp_port "$STAGEF_PUMP_SUBMIT_NODE")
    while :; do
        h=$(stagef_cmt_tip "$db")
        [ -n "$h" ] || h=-1
        if [ "$h" -ge "$target" ]; then
            echo "[pump] tip $h >= $target after $steps spend(s)" >&2
            printf '%s\n' "$h"
            return 0
        fi
        amt=$(stagef_pump_largest "$db")
        if [ "$amt" -le "$STAGEF_PUMP_FEE_RAW" ]; then
            if [ "$claimed" = 1 ]; then
                echo "[pump] node$STAGEF_PUMP_FUNDER_NODE holds no spendable native coin above the fee even after claiming its leaf" >&2
                printf '%s\n' "$h"
                return 3
            fi
            claimed=1
            h=$(stagef_pump_claim "$db") && wrc=0 || wrc=$?
            if [ "$wrc" != 0 ]; then
                printf '%s\n' "$h"
                return "$wrc"
            fi
            continue                # the claim itself may have reached TARGET
        fi
        if ! out=$("$STAGEF_NODUSCLI_BIN" -s 127.0.0.1 -p "$port" \
                   v2-envelope spend --keys "$keys" --to "$fp" \
                   --amount "$(( amt - STAGEF_PUMP_FEE_RAW ))" \
                   --fee "$STAGEF_PUMP_FEE_RAW" \
                   --submit "127.0.0.1:$port" 2>&1); then
            echo "[pump] v2-envelope spend failed at tip $h:" >&2
            printf '%s\n' "$out" >&2
            printf '%s\n' "$h"
            return 3
        fi
        intent=$(printf '%s\n' "$out" | awk -F= '/^  intent_id=/{print $2; exit}')
        if [ "${#intent}" != 128 ]; then
            echo "[pump] the spend's output carried no intent_id:" >&2
            printf '%s\n' "$out" >&2
            printf '%s\n' "$h"
            return 3
        fi
        h=$(stagef_cmt_wait_row "$db" \
            "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$intent';" \
            "$stall") && wrc=0 || wrc=$?
        if [ "$wrc" != 0 ]; then
            echo "[pump] spend ${intent:0:16}... not applied (wait rc=$wrc, tip $h)" >&2
            printf '%s\n' "$h"
            return "$wrc"
        fi
        steps=$(( steps + 1 ))
    done
}

# stagef_cmt_advance_to DB TARGET [STALL_INTERVALS]
#
# The one call a scenario uses for a multi-block wait: stagef_cmt_pump_to
# when STAGEF_PUMP_READY=1, stagef_cmt_wait_height (idle production)
# otherwise. Same stdout (the final tip) and rc 0 = reached; any other rc
# is the underlying helper's own (pump: 1/2/3, idle: 1).
stagef_cmt_advance_to() {
    if [ "${STAGEF_PUMP_READY:-0}" = 1 ]; then
        stagef_cmt_pump_to "$@"
    else
        stagef_cmt_wait_height "$@"
    fi
}

# stagef_voter_id PUBKEY_FILE
#
# tokenomics-v3 P1 (D-2, §C) — `v2_attendance.voter_id` is
# SHA3-512(pubkey)[0..31] (vset_wire.h:121, `nodus_chain_config_derive_
# witness_id`, nodus_witness_chain_config.c:637-652), the SAME 32-byte
# value cometbft's own address is. Hashes the RAW pubkey file bytes
# directly (never the hex text of it) with the openssl CLI, matching the
# C's one EVP SHA3-512 call over the 2592-byte key, and prints the first
# 64 hex characters (32 bytes) lowercase. No caller of this function may
# read `validators.last_signed_block` / `signed_blocks_this_epoch` —
# those columns are RETIRED (tokenomics-v3 P1, Q2 clean path); attendance
# is read from `v2_attendance` keyed by this value.
stagef_voter_id() {
    local pkfile="$1"
    openssl dgst -sha3-512 "$pkfile" 2>/dev/null | awk '{print substr($NF,1,64)}'
}

# stagef_cmt_diff_at_floor [LABEL]
#
# R3 W3 (C2d) — THE RACE-FREE WAY TO CALL stagef_diff.sh ON THIS LANE.
#
# CreateEmptyBlocks means a Comet-lane chain keeps committing on its own
# (README.md's flipped rule #1), so comparing "each node's CURRENT
# latest block" (stagef_diff.sh's plain mode) races that ongoing
# production: seven sequential SQLite reads spanning even a fraction of
# a second can catch one node one idle block ahead of another through
# nothing but scheduling, and misreport that as divergence. This reads
# every node's tip FIRST (a value each of them has, by construction,
# ALREADY reached at read time), takes the MINIMUM as a floor, and asks
# stagef_diff.sh to compare the row AT that exact height — a target
# fixed in the past the instant it is read, immune to anything the
# chain commits afterward. Use this for EVERY Comet-lane stagef_diff.sh
# call, pre- and post-action alike; a bare call races exactly as
# described above regardless of where in a scenario it sits.
stagef_cmt_diff_at_floor() {
    local label="${1:-}"
    # DELTA 1 (verifier CLAIM 7 NOTE, CONFIRMED as a narrow false-RED-only
    # flaw) — the FIRST cut used `if [ "$floor" -lt 0 ]` to seed floor,
    # which does not distinguish "not yet seeded" from "genuinely -1": a
    # node with NO block set floor=-1, and the NEXT node's real tip then
    # OVERWROTE it unconditionally (the `elif` never fires once floor is
    # negative, since nothing there re-enters the -1 branch). Tips
    # `10, -1, 20, 30` yielded floor=20, silently forgetting the true
    # minimum of 10. An explicit `first` flag removes the ambiguity: the
    # very first tip read seeds floor unconditionally, every later one
    # only lowers it.
    local floor=-1 first=1 n h
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        h=$(stagef_cmt_tip "$(stagef_node_chain_db "$n")")
        [ -z "$h" ] && h=-1
        if [ "$first" = 1 ]; then
            floor="$h"; first=0
        elif [ "$h" -lt "$floor" ]; then
            floor="$h"
        fi
    done
    if [ "$floor" -lt 0 ]; then
        echo "[FAIL] stagef_cmt_diff_at_floor: no node has a Comet block yet" >&2
        return 1
    fi
    bash "$(dirname "${BASH_SOURCE[0]}")/stagef_diff.sh" --at-height "$floor" "$label"
}
