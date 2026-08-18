#!/usr/bin/env bash
#
# Stage F.4 test — halving-boundary emission determinism.
#
# The unit test nodus/tests/test_emission_boundaries.c covers the pure
# function at every one of the 5 halving boundaries (Y1→Y2 ... Y5→floor).
# This script is the CONSENSUS counterpart: once a harness run crosses a
# boundary, every node must agree on
#   (a) the emission actually credited at heights either side of it, and
#   (b) the state_root that flows from total_minted += emission.
#
# O15B.1 — WHY THIS SCRIPT CHANGED.
#
# The old version skipped on `STAGEF_BLOCKS_PER_YEAR` being unset and its
# header said the harness "can optionally override DNAC_BLOCKS_PER_YEAR
# via a test-only env flag". No such override existed: the constant was an
# unguarded `#define DNAC_BLOCKS_PER_YEAR 6307200ULL`
# (nodus_witness_emission.h) and NOTHING in the tree read
# STAGEF_BLOCKS_PER_YEAR. The predicate was therefore permanently true for
# a reason that had nothing to do with the environment — and had an
# operator exported the variable, the script would have slept
# `BY*5 + 30` WALL-CLOCK seconds and diffed two state_roots without
# crossing anything, because block production here is TX-driven, not
# clock-driven. A vacuous pass behind a false skip.
#
# O15B.1 guards the constant with `#ifndef` (same idiom the file already
# uses for DNAC_DECIMAL_UNIT), so the harness can compile a short
# tokenomic year, and this script now:
#   - measures the emission the CHAIN actually credited per block,
#   - checks it against the schedule the declared BY implies, which is
#     what proves the binary and the harness agree (a mismatch is a
#     FAILURE, never a skip),
#   - PUMPS the chain across the next boundary instead of sleeping,
#   - and asserts the halving happened and 7/7 state_root held.
#
# Requires an active Stage F harness (stagef_up.sh) started from a build
# carrying -DDNAC_BLOCKS_PER_YEAR=<BY>, with STAGEF_BLOCKS_PER_YEAR=<BY>
# exported to declare it.
#
# Exit:
#   0  = boundary crossed, emission halved as scheduled, state_root 7/7
#   1  = no active harness
#   2  = pre-boundary state_root diverged
#   3  = post-boundary state_root diverged
#   4  = emission schedule mismatch (binary/harness disagreement, or a
#        boundary that did not halve)
#   99 = short tokenomic year not declared for this run

set -uo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

BY="${STAGEF_BLOCKS_PER_YEAR:-0}"
if [ "$BY" = "0" ]; then
    echo "[SKIP] STAGEF_BLOCKS_PER_YEAR not set — this run's nodus binary"
    echo "       was not built with -DDNAC_BLOCKS_PER_YEAR=<small>, so the"
    echo "       first halving sits at block 6,307,200 and no boundary is"
    echo "       reachable. Rebuild with the override and export the same"
    echo "       value to exercise this test."
    exit 99
fi

DECIMAL_UNIT=100000000        # nodus_witness_emission.h DNAC_DECIMAL_UNIT
EMISSION_BASE=32              # DNAC_EMISSION_BASE / DNAC_DECIMAL_UNIT
HALVING_YEARS=5               # DNAC_HALVING_YEARS
EMISSION_FLOOR=1              # DNAC_EMISSION_FLOOR / DNAC_DECIMAL_UNIT

fail() { echo "[FAIL] $*" >&2; exit "${2:-4}"; }
info() { echo "[info] $*"; }
ok()   { echo "[ok] $*"; }

node1_db() { stagef_node_chain_db 1; }

head_height() {
    sqlite3 "$(node1_db)" "SELECT COALESCE(MAX(height),0) FROM blocks;"
}

# (height, total_minted) read in ONE statement so the pair is a single
# consistent SQLite snapshot rather than two racing reads.
sample() {
    sqlite3 "$(node1_db)" "SELECT (SELECT COALESCE(MAX(height),0) FROM blocks) \
        || '|' || (SELECT total_minted FROM supply_tracking WHERE id = 1);"
}

# Expected per-block emission, in RAW units, at an absolute height —
# the same schedule nodus_emission_per_block implements.
expected_emission() {
    local h="$1"
    local yi=$(( h / BY ))
    if [ "$yi" -ge "$HALVING_YEARS" ]; then
        echo $(( EMISSION_FLOOR * DECIMAL_UNIT ))
    else
        echo $(( (EMISSION_BASE >> yi) * DECIMAL_UNIT ))
    fi
}

# Drive the chain to >= $1, one TX per block. Block production is
# TX-driven (nodus_witness_tick opens a round only for a non-empty
# mempool), so a sleep would never cross a boundary.
pump_to_height() {
    local target="$1" timeout="${2:-600}"
    local deadline=$(( SECONDS + timeout ))
    local h; h=$(head_height)
    local sink; sink=$(cat "$BASE_DIR/node1/identity/nodus.fp")
    while [ "${h:-0}" -lt "$target" ] && [ $SECONDS -lt $deadline ]; do
        stagef_dna -q dna sync  > "$BASE_DIR/test_halving_pump.log" 2>&1 || true
        stagef_dna -q dna send "$sink" 1 "halving-pump" \
            >> "$BASE_DIR/test_halving_pump.log" 2>&1 || true
        sleep 6
        h=$(head_height)
    done
    [ "${h:-0}" -ge "$target" ] || fail "pump: height $h < $target (timeout ${timeout}s)"
    info "pumped to height $h (target $target)"
}

# Observed per-block emission between two samples, asserted against the
# schedule for the year both samples sit in. $1 = label, $2 = span.
#
# The result lands in the global RATE rather than on stdout: a command
# substitution would run this in a SUBSHELL, where `fail`'s exit would
# only kill the subshell and the scenario would sail past a failed
# assertion.
RATE=0
measure_rate() {
    local label="$1" span="${2:-4}"
    local a b h1 m1 h2 m2
    a=$(sample); h1=${a%%|*}; m1=${a#*|}
    pump_to_height $(( h1 + span )) 300
    b=$(sample); h2=${b%%|*}; m2=${b#*|}

    [ "$h2" -gt "$h1" ] || fail "$label: chain did not advance ($h1 -> $h2)"
    local dh=$(( h2 - h1 ))
    local dm=$(( m2 - m1 ))
    [ $(( dm % dh )) -eq 0 ] || \
        fail "$label: minted delta $dm is not a whole multiple of $dh blocks"
    local rate=$(( dm / dh ))

    # Both samples must sit in the SAME tokenomic year or the average is
    # not a single schedule value.
    [ $(( h1 / BY )) -eq $(( h2 / BY )) ] || \
        fail "$label: sample window $h1..$h2 straddles a boundary"

    local want; want=$(expected_emission "$h2")
    [ "$rate" -eq "$want" ] || \
        fail "$label: emission $rate raw/block at h=$h1..$h2 (year $(( h1 / BY ))), \
schedule says $want — the binary's DNAC_BLOCKS_PER_YEAR and the harness's \
STAGEF_BLOCKS_PER_YEAR=$BY disagree"
    ok "$label: $rate raw/block over h=$h1..$h2 matches the year-$(( h1 / BY )) schedule"
    RATE="$rate"
}

info "short tokenomic year declared: STAGEF_BLOCKS_PER_YEAR=$BY"

H0=$(head_height)
YI=$(( H0 / BY ))
if [ "$YI" -ge "$HALVING_YEARS" ]; then
    fail "chain is already at year $YI >= $HALVING_YEARS (perpetual floor); \
no halving boundary remains to cross with BY=$BY" 4
fi
NB=$(( (H0 / BY + 1) * BY ))
# The pre-boundary rate needs a sample window that sits strictly BELOW the
# boundary. If the chain is already sitting on top of one, take the next.
if [ $(( NB - H0 - 1 )) -lt 3 ]; then
    NB=$(( NB + BY ))
    info "head=$H0 is too close to the previous boundary — targeting $NB"
fi
[ $(( NB / BY )) -le "$HALVING_YEARS" ] || \
    fail "target boundary $NB is past the perpetual floor with BY=$BY" 4
info "head=$H0 (year $YI); halving boundary under test: block $NB"

echo ""
echo "== Baseline (pre-boundary) consensus check =="
bash "$(dirname "$0")/../stagef_diff.sh" "pre-boundary" || exit 2

echo ""
echo "== Pre-boundary emission rate =="
# Keep the whole sample window strictly below the boundary.
ROOM=$(( NB - $(head_height) - 1 ))
SPAN=4
[ "$ROOM" -lt "$SPAN" ] && SPAN="$ROOM"
[ "$SPAN" -ge 2 ] || fail "not enough room below boundary $NB to measure a rate" 4
measure_rate "pre-boundary" "$SPAN"
RATE_PRE="$RATE"

echo ""
echo "== Crossing the halving boundary at block $NB =="
pump_to_height $(( NB + 2 )) 900
ok "crossed boundary $NB (head=$(head_height))"

echo ""
echo "== Post-boundary emission rate =="
measure_rate "post-boundary" 4
RATE_POST="$RATE"

WANT_POST=$(expected_emission "$NB")
[ "$RATE_POST" -eq "$WANT_POST" ] || \
    fail "post-boundary emission $RATE_POST != scheduled $WANT_POST" 4
[ "$RATE_POST" -lt "$RATE_PRE" ] || \
    fail "emission did not drop across boundary $NB ($RATE_PRE -> $RATE_POST)" 4
if [ $(( NB / BY )) -lt "$HALVING_YEARS" ]; then
    [ $(( RATE_PRE / 2 )) -eq "$RATE_POST" ] || \
        fail "emission did not HALVE across boundary $NB ($RATE_PRE -> $RATE_POST)" 4
    ok "emission halved exactly: $RATE_PRE -> $RATE_POST raw/block"
else
    ok "emission dropped to the perpetual floor: $RATE_PRE -> $RATE_POST raw/block"
fi

echo ""
echo "== Post-boundary consensus check =="
bash "$(dirname "$0")/../stagef_diff.sh" "post-boundary" || exit 3

echo ""
echo "[PASS] halving boundary $NB crossed, emission followed the schedule"
echo "       ($RATE_PRE -> $RATE_POST raw/block), state_root identical"
echo "       across all $STAGEF_COMMITTEE_SIZE nodes either side"
