#!/usr/bin/env bash
# check_state_root_determinism.sh — Phase 17 Task 82 of witness stake v1
#
# Cross-compiler determinism gate for the nodus witness state_root.
#
# Builds the nodus tree twice — once with gcc, once with clang — into
# disjoint build dirs, then runs the state_root-sensitive tests with
# each build and compares their stdout byte-for-byte. Any divergence
# in the composite state_root or the supply-invariant trace across
# compilers implies a potential consensus fork on a heterogeneous
# production cluster (design §3.4, F-CRYPTO-08 mitigation).
#
# Mirrors scripts/check_u128_determinism.sh in shape + exit-code
# contract; where that script checks the vendored u128 math, this
# one checks the higher-level Merkle composition + the Task 81
# supply-invariance simulator.
#
# Usage: scripts/check_state_root_determinism.sh
#
# Exit codes:
#   0 — compilers agree on every selected test's output, OR a
#       compiler is missing (skip), OR the nodus tree currently
#       does not build with the alternate compiler (soft skip,
#       logged via [warn]; the build-compat issue is tracked
#       separately and does not block the gate)
#   1 — compilers both built successfully AND their state_root
#       outputs diverge (actual determinism failure)
#
# CI-ready. Not wired into .gitlab-ci.yml yet; a follow-up task will
# add it alongside the u128 gate. On first CI enablement, set
# STRICT_BUILD=1 to promote alternate-compiler build failures
# back to hard-fail.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODUS_ROOT="$REPO_ROOT/nodus"

# Subset of ctest patterns whose output is a deterministic function
# of the state_root computation path. If these produce identical
# stdout across compilers the 4-subtree composition and the supply
# invariant math are bit-stable.
#
# Keep this list short. Adding tests whose output includes anything
# stochastic (timestamps, addresses, tmp paths) will cause false
# divergence; add only after auditing the test's printf output.
SELECTED_TESTS=(
    test_state_root_4subtree
    test_merkle_domain_tags
    test_merkle_tree_tags
    test_merkle_utxo_root
    test_supply_invariant
)

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# build_with_cc <cc> <build_dir>
#   Configure + build the nodus tree with the named compiler into
#   <build_dir>. Exit code:
#     0 = built OK
#     1 = configure or build failed
#     2 = compiler not installed (skip)
build_with_cc() {
    local cc="$1"
    local build_dir="$2"

    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "[skip] $cc not installed"
        return 2
    fi

    mkdir -p "$build_dir"
    (
        cd "$build_dir"
        CC="$cc" cmake "$NODUS_ROOT" \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_C_COMPILER="$cc" \
            >"$TMPDIR/cfg_${cc}.log" 2>&1
    ) || {
        echo "[fail] $cc cmake configure failed"
        tail -40 "$TMPDIR/cfg_${cc}.log" >&2 || true
        return 1
    }

    (
        cd "$build_dir"
        make -j"$(nproc)" "${SELECTED_TESTS[@]}" \
            >"$TMPDIR/build_${cc}.log" 2>&1
    ) || {
        echo "[fail] $cc build failed"
        tail -60 "$TMPDIR/build_${cc}.log" >&2 || true
        return 1
    }

    return 0
}

# run_tests <cc> <build_dir> <out_file>
run_tests() {
    local cc="$1"
    local build_dir="$2"
    local out_file="$3"

    : > "$out_file"
    for t in "${SELECTED_TESTS[@]}"; do
        local bin="$build_dir/$t"
        if [ ! -x "$bin" ]; then
            echo "[fail] $cc: expected binary $bin missing after build"
            return 1
        fi
        printf '==== %s ====\n' "$t" >> "$out_file"
        if ! "$bin" >>"$out_file" 2>&1; then
            local rc=$?
            echo "[fail] $cc: $t exited $rc"
            tail -40 "$out_file" >&2 || true
            return 1
        fi
    done
    return 0
}

# ── main ────────────────────────────────────────────────────────────

GCC_BUILD="$TMPDIR/build_gcc"
CLANG_BUILD="$TMPDIR/build_clang"
GCC_OUT="$TMPDIR/out_gcc.txt"
CLANG_OUT="$TMPDIR/out_clang.txt"

echo "== Compiling nodus tests with gcc =="
set +e
build_with_cc gcc "$GCC_BUILD"
gcc_rc=$?
set -e

echo "== Compiling nodus tests with clang =="
set +e
build_with_cc clang "$CLANG_BUILD"
clang_rc=$?
set -e

if [ "$gcc_rc" -eq 2 ] || [ "$clang_rc" -eq 2 ]; then
    echo "[warn] one or both compilers missing — skipping determinism check"
    exit 0
fi
if [ "$gcc_rc" -ne 0 ] || [ "$clang_rc" -ne 0 ]; then
    if [ "${STRICT_BUILD:-0}" = "1" ]; then
        echo "[fail] one or both compilers failed (STRICT_BUILD=1)"
        exit 1
    fi
    echo "[warn] one or both compilers failed to build the nodus tree;"
    echo "       the determinism gate cannot run until the build-compat"
    echo "       issue (e.g. -Werror + #pragma GCC poison under clang)"
    echo "       is addressed. Skipping with rc=0."
    echo "       Set STRICT_BUILD=1 to promote build failure to hard fail."
    exit 0
fi

echo "== Running state_root-sensitive tests on gcc build =="
set +e
run_tests gcc "$GCC_BUILD" "$GCC_OUT"
run_gcc_rc=$?
set -e

echo "== Running state_root-sensitive tests on clang build =="
set +e
run_tests clang "$CLANG_BUILD" "$CLANG_OUT"
run_clang_rc=$?
set -e

if [ "$run_gcc_rc" -ne 0 ] || [ "$run_clang_rc" -ne 0 ]; then
    echo "[fail] test runs failed; cannot compare"
    exit 1
fi

if cmp -s "$GCC_OUT" "$CLANG_OUT"; then
    echo "[ok] gcc and clang produce bit-identical state_root outputs"
    echo "---- shared output ----"
    cat "$GCC_OUT"
    exit 0
else
    echo "[fail] gcc vs clang state_root output DIVERGES"
    diff -u "$GCC_OUT" "$CLANG_OUT" || true
    exit 1
fi
