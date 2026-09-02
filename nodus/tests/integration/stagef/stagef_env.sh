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
        # node (test_view_change_fork SIGSTOPs the validator it DERIVES
        # as the current epoch leader, which is a different node on
        # every run and may be any of them): the frozen replica can
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
# COMMITTEE / EPOCH-LEADER DERIVATION — ONE IMPLEMENTATION, TWO USERS
#
# Everything below lived only inside test_vset_grow_shrink.sh until
# 2026-09-02, when test_view_change_fork.sh needed the same derivation to
# stop being a coin flip. Copying ~80 lines into a second scenario is
# exactly how the two drifted apart in the first place: vset section G was
# taught to kill a DERIVED leader while the fork test went on killing a
# hardcoded node 1 and calling whatever happened next a pass.
#
# MOVED, NOT REWRITTEN. Every function here is the body that was deleted
# from test_vset_grow_shrink.sh, under the same name, with the same
# arguments and the same return contract, so that scenario behaves exactly
# as before. Section G is the suite's only proof that the chain rotates
# past a dead leader; breaking it silently would be worse than the defect
# this move exists to fix.
#
# ⚠ THIS FILE IS SOURCED BY EVERY SCENARIO. A fault here breaks all of
# them, not one. Nothing below runs at source time except four integer
# constant assignments — the rest are function definitions.
#
# ⚠ ref_db() reads the CALLER'S $REF_NODE, and that global contract is
# KEPT DELIBERATELY: test_vset_grow_shrink.sh calls `ref_db` with no
# arguments at ~30 sites, and re-signaturing it would mean rewriting the
# section whose behaviour must not change. No default REF_NODE is set
# here on purpose — a scenario that calls ref_db without setting REF_NODE
# must fail loudly under `set -u`, not quietly read node1.
# ──────────────────────────────────────────────────────────────────────

# All node indices that currently have a data dir (1..7 always, 8/9 later).
running_nodes() {
    for d in "$BASE_DIR"/node*/; do
        basename "$d" | sed 's/node//'
    done | sort -n
}

# The chain DB of the reference node. Was node1_db; it is now named for
# what it is, because in the sections that kill or pause a DERIVED node it
# is deliberately NOT node1.
ref_db() { stagef_node_chain_db "$REF_NODE"; }

# The BFT view a node currently holds, from its own persisted singleton
# row (pbft_state, nodus_witness_db.c:2122-2196).
#
# current_view NEVER resets (nothing sets it to 0) and it survives
# restarts — so it must be READ, never assumed to be 0. NOT monotonic.
# Scenarios that rotate the view sort earlier in a sweep, so by the time a
# later one runs the cluster is routinely at a non-zero view.
#
# A missing row is the documented fresh-DB state and means view 0 (the
# loader leaves the default in place, :2155-2160). A FAILED query is not
# a value: it returns 1 and prints nothing, so no caller can read an
# error as a view.
node_view() {
    local db out
    db=$(stagef_node_chain_db "$1")
    [ -n "$db" ] || return 1
    out=$(sqlite3 "$db" \
        "SELECT COALESCE(current_view, 0) FROM pbft_state WHERE id = 1;" \
        2>/dev/null) || return 1
    [ -z "$out" ] && out=0
    echo "$out"
}

# The highest view held by any node EXCEPT $1, which is the node the
# caller is about to kill or pause (or has already).
#
# Why the max over a set rather than one node's value: current_view is
# per-node runtime state with three writers — the view-change quorum
# itself (nodus_witness_bft.c:7703), adopting a NEW_VIEW (:8196) and
# adopting a PROPOSE's view (:5040) — so a node that sits out a round can
# lag, and the lowest-numbered surviving node is not guaranteed to be one
# of the ACTIVE set. The property being asserted is "the cluster rotated",
# i.e. SOME surviving node advanced, and the max expresses exactly that.
# NOT monotonic per node: :5040 copies the proposal's view UNCONDITIONALLY
# and can LOWER it.
#
# The victim is excluded from BOTH the before and after readings, so the
# two are taken over the SAME set and stay comparable — and so that a
# kill -9'd database with a hot journal is never opened by this script.
cluster_view_max() {
    local skip="$1" best=-1 n v
    for n in $(running_nodes); do
        [ "$n" = "$skip" ] && continue
        v=$(node_view "$n") || continue
        [ "$v" -gt "$best" ] && best="$v"
    done
    [ "$best" -ge 0 ] || return 1
    echo "$best"
}

# How many times PATTERN appears across EVERY running node's log.
#
# Always used as a BEFORE/AFTER delta, never as a bare presence test.
# The logs are cumulative across the whole harness run and every earlier
# scenario in it — several deliberately force view changes — so "a
# VIEW_CHANGE line exists" is already true when a later scenario starts
# and proves nothing about it. Only an INCREASE is evidence.
log_count() {
    local pat="$1" total=0 n c
    for n in $(running_nodes); do
        c=$(grep -c -- "$pat" "$BASE_DIR/node$n/nodus.log" 2>/dev/null || true)
        total=$(( total + ${c:-0} ))
    done
    echo "$total"
}

# Raw Dilithium5 public key of a harness node, uppercase hex — the exact
# byte string the validator row and the snapshot blob carry.
node_pubkey_hex() {
    xxd -p -u -c 99999 "$BASE_DIR/node$1/identity/nodus.pk"
}

# Canonical validator-set snapshot wire geometry (shared/dnac/vset_wire.h:
# DNA_VSET_HDR_LEN=78, DNA_VSET_ENTRY_LEN=2642, voter_id 32 B at entry
# offset 0, pubkey DNA_VSET_PUBKEY_LEN=2592 at entry offset 32).
#
# These are used to read entry k POSITIONALLY. That is the whole point:
# the snapshot stores its entries in COMMITTEE ORDER by construction
# (nodus_witness_vset.c:360-378 builds them straight out of
# nodus_committee_compute_for_epoch), so slicing by offset READS the
# committee rank instead of recomputing it. An `instr()`-style search —
# the pattern snapshot_contains uses — answers MEMBERSHIP, not ORDER, and
# would happily identify the wrong validator as the leader.
VSET_HDR_LEN=78
VSET_ENTRY_LEN=2642
VSET_VOTER_ID_LEN=32
VSET_PUBKEY_LEN=2592

# stagef_leader_entry DB EPOCH_START E_LEN VIEW
#
# THE ONE IMPLEMENTATION of "which validator leads epoch EPOCH_START".
#
#   prints on success:  "<rank> <active_count> <pubkey_hex> <voter_id_hex>"
#   on any fault:       the precise [FAIL] diagnosis on stderr, return 1
#
# It never exits and never touches a global, so each caller keeps its own
# exit code, its own trap and its own resume-the-victim obligation.
#
# THE RULE IT ENCODES. Leader rank = (epoch + view) % n, where epoch is
# the epoch ORDINAL (EPOCH_START / E_LEN) and n is the committee size
# (nodus_witness_bft_leader_index, nodus_witness_bft.c:1195-1198, called
# at :1284 with `epoch = next_bh / DNAC_EPOCH_LENGTH`). Note :1229 —
# `next_bh` is the tip PLUS ONE, so a caller deriving the CURRENT leader
# from a committed head H must use the epoch of H+1, not of H.
#
# WHY IT READS THE SNAPSHOT INSTEAD OF RE-DERIVING THE ORDER. Rank is
# turned into an identity POSITIONALLY: nodus_witness_vset.c:360-378 fills
# snapshot entry i straight from nodus_committee_compute_for_epoch's
# member i, and nodus_committee_get_for_block serves that persisted
# snapshot as the committee authority for the epoch
# (nodus_witness_committee.c:548-568). So entry order IS committee order.
# Re-deriving the stake-DESC / SHA3-512(0x02 ‖ pubkey ‖ state_seed)-ASC
# tiebreak in shell would be a second implementation of a consensus rule,
# which is precisely what must not exist.
#
# EVERY sqlite3 result is guarded with `|| var=""` so this behaves the
# same under `set -e` (test_view_change_fork.sh) and without it
# (test_vset_grow_shrink.sh): a failed query yields an empty value the
# numeric checks below reject — never an abort, and never a silent 0.
stagef_leader_entry() {
    local db="$1" epoch="$2" e_len="$3" view="$4"
    local active_count blob_len blob_entries rank pk_off vid_off pk wid

    # Guard the inputs before any arithmetic touches them. $(( )) coerces
    # an empty string to 0, which would turn an unreadable height or view
    # into a plausible-looking rank.
    case "$epoch" in ''|*[!0-9]*)
        echo "[FAIL] stagef_leader_entry: epoch_start '$epoch' is not a number" >&2
        return 1;;
    esac
    case "$e_len" in ''|*[!0-9]*)
        echo "[FAIL] stagef_leader_entry: epoch length '$e_len' is not a number" >&2
        return 1;;
    esac
    case "$view" in ''|*[!0-9]*)
        echo "[FAIL] stagef_leader_entry: view '$view' is not a number" >&2
        return 1;;
    esac
    if [ "$e_len" -lt 1 ]; then
        echo "[FAIL] stagef_leader_entry: epoch length $e_len < 1" >&2
        return 1
    fi

    active_count=$(sqlite3 "$db" "SELECT active_count FROM \
        validator_set_snapshots WHERE epoch_start = $epoch;") || active_count=""
    blob_len=$(sqlite3 "$db" "SELECT length(snapshot_blob) FROM \
        validator_set_snapshots WHERE epoch_start = $epoch;") || blob_len=""
    # Both must be non-empty NUMBERS before any arithmetic touches them: an
    # empty cell would otherwise be coerced to 0 inside $(( )) and quietly
    # produce a plausible-looking entry count.
    case "$active_count" in ''|*[!0-9]*)
        echo "[FAIL] epoch-$epoch snapshot has no usable active_count ('$active_count')" >&2
        return 1;;
    esac
    case "$blob_len" in ''|*[!0-9]*)
        echo "[FAIL] epoch-$epoch snapshot blob has no readable length ('$blob_len')" >&2
        return 1;;
    esac
    if [ "$active_count" -lt 1 ]; then
        echo "[FAIL] epoch-$epoch snapshot has active_count=$active_count" >&2
        return 1
    fi

    # The column and the blob must agree about how many entries there are.
    # active_count is what the leader formula takes its modulus from, and
    # the blob is what the entry is sliced out of; if they disagree, one of
    # the two is wrong and the derived index would address the wrong bytes.
    blob_entries=$(( (blob_len - VSET_HDR_LEN) / VSET_ENTRY_LEN ))
    if [ $(( VSET_HDR_LEN + blob_entries * VSET_ENTRY_LEN )) -ne "$blob_len" ]; then
        echo "[FAIL] epoch-$epoch snapshot blob is $blob_len bytes, not a whole \
number of $VSET_ENTRY_LEN-byte entries after the $VSET_HDR_LEN-byte header" >&2
        return 1
    fi
    if [ "$blob_entries" -ne "$active_count" ]; then
        echo "[FAIL] epoch-$epoch snapshot says active_count=$active_count but \
its blob carries $blob_entries entries" >&2
        return 1
    fi

    rank=$(( (epoch / e_len + view) % active_count ))
    # SQLite substr() is 1-indexed and byte-addressed on a BLOB.
    pk_off=$(( VSET_ENTRY_LEN * rank + VSET_HDR_LEN + VSET_VOTER_ID_LEN + 1 ))
    vid_off=$(( VSET_ENTRY_LEN * rank + VSET_HDR_LEN + 1 ))
    pk=$(sqlite3 "$db" "SELECT hex(substr(snapshot_blob, \
        $pk_off, $VSET_PUBKEY_LEN)) FROM validator_set_snapshots \
        WHERE epoch_start = $epoch;") || pk=""
    wid=$(sqlite3 "$db" "SELECT hex(substr(snapshot_blob, \
        $vid_off, $VSET_VOTER_ID_LEN)) FROM validator_set_snapshots \
        WHERE epoch_start = $epoch;") || wid=""
    if [ ${#pk} -ne $(( VSET_PUBKEY_LEN * 2 )) ]; then
        echo "[FAIL] entry $rank pubkey slice is ${#pk} hex chars, \
expected $(( VSET_PUBKEY_LEN * 2 )) — the snapshot layout moved" >&2
        return 1
    fi
    if [ ${#wid} -ne $(( VSET_VOTER_ID_LEN * 2 )) ]; then
        echo "[FAIL] entry $rank voter_id slice is ${#wid} hex chars, \
expected $(( VSET_VOTER_ID_LEN * 2 )) — the snapshot layout moved" >&2
        return 1
    fi

    printf '%s %s %s %s\n' "$rank" "$active_count" "$pk" "$wid"
}
