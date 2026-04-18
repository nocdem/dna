#!/usr/bin/env bash
# check_u128_determinism.sh — Phase 2 Task 7 of witness stake v1
#
# Ensures the vendored u128 library (shared/crypto/utils/qgp_u128.{c,h})
# produces bit-identical results when compiled with gcc vs clang.
# Divergence = potential Merkle state_root fork across the 7-node
# witness cluster (design spec §3.4, F-CRYPTO-08 mitigation).
#
# Usage: scripts/check_u128_determinism.sh
#
# Exit codes:
#   0 — compilers agree, OR at least one compiler not installed (skip)
#   1 — compilers disagree, or build/run failure on an installed compiler
#
# Self-contained: only standard tools (gcc, clang, cmp, diff, bash).
# Not wired into CI yet — a separate task will add this to .gitlab-ci.yml.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
U128_SRC="$REPO_ROOT/shared/crypto/utils/qgp_u128.c"
KAT_SRC="$REPO_ROOT/messenger/tests/test_u128_kat.c"
SHARED_INCLUDE="$REPO_ROOT/shared"

if [ ! -f "$U128_SRC" ]; then
    echo "[fail] missing source: $U128_SRC"
    exit 1
fi
if [ ! -f "$KAT_SRC" ]; then
    echo "[fail] missing source: $KAT_SRC"
    exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Compile + run; echoes status to stderr via return code
#   0 = ok (binary built and ran clean)
#   1 = compile or runtime failure
#   2 = compiler not installed (skip)
compile_and_run() {
    local cc="$1"
    local bin="$TMPDIR/kat_$cc"
    local out="$TMPDIR/out_$cc.txt"

    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "[skip] $cc not installed"
        return 2
    fi

    if ! "$cc" -std=c11 -O2 -Wall -Wextra -Werror \
            -I"$SHARED_INCLUDE" \
            -o "$bin" "$U128_SRC" "$KAT_SRC" 2> "$TMPDIR/build_$cc.err"; then
        echo "[fail] $cc compile error:"
        cat "$TMPDIR/build_$cc.err" >&2
        return 1
    fi

    if ! "$bin" > "$out" 2>&1; then
        local rc=$?
        echo "[fail] $cc binary exit $rc"
        cat "$out" >&2
        return 1
    fi

    return 0
}

echo "== Compiling u128 KAT with gcc =="
set +e
compile_and_run gcc
gcc_rc=$?
set -e

echo "== Compiling u128 KAT with clang =="
set +e
compile_and_run clang
clang_rc=$?
set -e

if [ "$gcc_rc" -eq 2 ] || [ "$clang_rc" -eq 2 ]; then
    echo "[warn] one or both compilers missing — skipping determinism check"
    exit 0
fi

if [ "$gcc_rc" -ne 0 ] || [ "$clang_rc" -ne 0 ]; then
    echo "[fail] one or both compilers failed; cannot compare"
    exit 1
fi

if cmp -s "$TMPDIR/out_gcc.txt" "$TMPDIR/out_clang.txt"; then
    echo "[ok] gcc and clang produce bit-identical output"
    echo "---- shared output ----"
    cat "$TMPDIR/out_gcc.txt"
    exit 0
else
    echo "[fail] gcc vs clang output DIVERGES"
    diff -u "$TMPDIR/out_gcc.txt" "$TMPDIR/out_clang.txt" || true
    exit 1
fi
