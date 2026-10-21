#!/usr/bin/env bash
# verify.sh — the source/artifact drift check of the Nodus security contract library.
#
# What it does: re-compiles src/ and test/mocks/ with build.sh (same compiler pin, same
#   flags, same source list) into a temporary directory and compares it with the COMMITTED
#   out/ (diff -r). Exit 0 = no drift; exit 1 = out/ does not match the sources (the diff is
#   printed) or the build failed; exit 2 = no / wrong compiler.
#   This is a MANDATORY gate before any commit or publication of the library: the tests run
#   the committed out/, and nothing else compares the .sol files with the .hex files.
# What it requires: SOLC=<path to the Nodus solc> (or the first argument), the pinned
#   version line (build.sh refuses any other).
# What it leaves behind: nothing (the temporary directory is removed).
set -euo pipefail

SOLC="${1:-${SOLC:-}}"
if [ -z "$SOLC" ] || [ ! -x "$SOLC" ]; then
	echo "usage: SOLC=/path/to/solc $0   (or: $0 /path/to/solc)" >&2
	exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -d "$HERE/out" ]; then
	echo "no committed out/ to verify against" >&2
	exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

rc=0
OUT_DIR="$TMP/out" SOLC="$SOLC" "$HERE/build.sh" > "$TMP/build.log" 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
	cat "$TMP/build.log" >&2
	echo "verify: build failed (exit $rc)" >&2
	[ "$rc" -eq 2 ] && exit 2
	exit 1
fi

if diff -r "$HERE/out" "$TMP/out"; then
	echo "verify: out/ matches the sources ($(find "$HERE/out" -type f | wc -l) files)"
	exit 0
fi
echo "verify: DRIFT — out/ does not match the sources; re-run build.sh and review the diff" >&2
exit 1
