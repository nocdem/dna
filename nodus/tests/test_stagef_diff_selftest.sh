#!/usr/bin/env bash
#
# Self-test of the Stage F state-root comparison helper
# (nodus/tests/integration/stagef/stagef_diff.sh), B-08.
#
# The helper used to compare only the first 8 bytes of global_root and of
# block_id unless `--full` was given, and printed "state_root identical"
# regardless: two roots that differ in the other 56 bytes passed.
#
# PROVES (seven scratch chain databases, one v2_blocks row each, no node, no
# network, no port):
#   S1  seven identical rows            -> exit 0, default AND --full; the
#                                          default [ok] line prints the first
#                                          16 hex characters of each hash.
#   S2  node 4's global_root differs in byte 9 only (bytes 1-8 equal)
#                                       -> exit non-zero, default AND --full.
#   S3  node 4's block_id differs in byte 64 only
#                                       -> exit non-zero, default AND --full.
#   S4  every node's block_id is 32 bytes (identical on all seven)
#                                       -> exit non-zero (not two 128-hex
#                                          fields), default AND --full.
#   S5  --at-height with identical rows -> exit 0 (a flag combination the
#                                          scenarios use).
# Today (before the fix) S2, S3 and S4 exit 0 in the default mode.
#
# REQUIRES: bash, sqlite3 on PATH. Environment: none (BASE_DIR is set to the
# scratch directory for the helper's own process only). Leaves behind:
# nothing (the scratch directory is removed on exit).
#
# HOW IT CAN LIE: it tests the helper against synthetic rows, not against a
# chain; it does not prove the engine stores 64-byte values, only that the
# helper refuses anything else.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
diff_sh="$here/integration/stagef/stagef_diff.sh"
[ -f "$diff_sh" ] || { echo "FAIL: $diff_sh missing" >&2; exit 1; }
command -v sqlite3 >/dev/null || { echo "FAIL: sqlite3 not on PATH" >&2; exit 1; }

tmp=$(mktemp -d /tmp/test_stagef_diff_selftest_XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# N hex pairs of one byte value
rep() { local b="$1" n="$2" out="" i; for ((i = 0; i < n; i++)); do out+="$b"; done; printf '%s' "$out"; }

ROOT_BASE=$(rep AA 64)
BID_BASE=$(rep BB 64)

# mk_node N ROOT_HEX BID_HEX — node N's chain database with one block at 5
mk_node() {
    local n="$1" root="$2" bid="$3" dir="$tmp/node$1/data"
    mkdir -p "$dir"
    rm -f "$dir/witness_a.db"
    sqlite3 "$dir/witness_a.db" \
        "CREATE TABLE v2_blocks (global_height INTEGER PRIMARY KEY, global_root BLOB, block_id BLOB);
         INSERT INTO v2_blocks VALUES (5, x'$root', x'$bid');"
}

fill_all() { local n; for n in 1 2 3 4 5 6 7; do mk_node "$n" "$1" "$2"; done; }

# run_diff ARGS... — prints nothing; sets RC and OUT
run_diff() {
    RC=0
    OUT=$(BASE_DIR="$tmp" bash "$diff_sh" "$@" 2>&1) || RC=$?
}

failed=0
check() {                      # DESCRIPTION CONDITION-EXIT-STATUS
    if [ "$2" = 0 ]; then echo "[ok] $1"; else echo "[FAIL] $1" >&2; failed=1; fi
}

# S1 — identical
fill_all "$ROOT_BASE" "$BID_BASE"
run_diff "s1 default"
check "S1 identical rows pass (default)" "$RC"
case "$OUT" in
    *"7/7 state_root identical (5|v2:AAAAAAAAAAAAAAAA|bid:BBBBBBBBBBBBBBBB)"*) s=0 ;;
    *) s=1; echo "$OUT" >&2 ;;
esac
check "S1 the default line prints 8 bytes of each hash" "$s"
run_diff --full "s1 full"
check "S1 identical rows pass (--full)" "$RC"

# S2 — global_root differs in byte 9 only
bad_root="$(rep AA 8)FF$(rep AA 55)"
fill_all "$ROOT_BASE" "$BID_BASE"
mk_node 4 "$bad_root" "$BID_BASE"
run_diff "s2 default"
[ "$RC" != 0 ] && s=0 || s=1
check "S2 a global_root differing in byte 9 FAILS (default)" "$s"
run_diff --full "s2 full"
[ "$RC" != 0 ] && s=0 || s=1
check "S2 a global_root differing in byte 9 FAILS (--full)" "$s"

# S3 — block_id differs in byte 64 only
bad_bid="$(rep BB 63)FF"
fill_all "$ROOT_BASE" "$BID_BASE"
mk_node 4 "$ROOT_BASE" "$bad_bid"
run_diff "s3 default"
[ "$RC" != 0 ] && s=0 || s=1
check "S3 a block_id differing in byte 64 FAILS (default)" "$s"
run_diff --full "s3 full"
[ "$RC" != 0 ] && s=0 || s=1
check "S3 a block_id differing in byte 64 FAILS (--full)" "$s"

# S4 — a 32-byte block_id everywhere
fill_all "$ROOT_BASE" "$(rep BB 32)"
run_diff "s4 default"
[ "$RC" != 0 ] && s=0 || s=1
check "S4 a 32-byte block_id on every node FAILS (default)" "$s"
run_diff --full "s4 full"
[ "$RC" != 0 ] && s=0 || s=1
check "S4 a 32-byte block_id on every node FAILS (--full)" "$s"

# S5 — flag combination
fill_all "$ROOT_BASE" "$BID_BASE"
run_diff --at-height 5 "s5"
check "S5 --at-height with identical rows passes" "$RC"

if [ "$failed" = 0 ]; then echo "PASS test_stagef_diff_selftest"; fi
exit "$failed"
