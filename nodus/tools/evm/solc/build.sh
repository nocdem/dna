#!/usr/bin/env bash
# build.sh — build the Nodus EVM Solidity compiler (32-byte addresses).
#
# Clones upstream solidity at tag v0.8.30, verifies the commit hash, applies
# 0001-nodus-address-256.patch and builds the `solc` target only (no test binaries).
#
# Usage:  ./build.sh [WORK_DIR]
#   WORK_DIR   where the clone and the build tree go (default: ${TMPDIR:-/tmp}/solc-nodus-addr256).
#              It must not exist yet, or be an earlier WORK_DIR of this script.
# Environment:
#   JOBS        parallel compile jobs (default: nproc). solc TUs are large; ~1.5 GB RAM per job.
#   BOOST_ROOT  prefix of a Boost >= 1.67 install with filesystem, program_options, system and
#               unit_test_framework libraries (static by default, upstream
#               cmake/EthDependencies.cmake:27,32). Leave unset to use the system Boost.
#
# Output: $WORK_DIR/solidity/build/solc/solc, and its `--version` printed at the end.
set -euo pipefail

SOLC_REPO="https://github.com/ethereum/solidity.git"
SOLC_TAG="v0.8.30"
SOLC_COMMIT="73712a01b2de56d9ad91e3b6936f85c90cb7de36"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$HERE/0001-nodus-address-256.patch"
WORK="${1:-${TMPDIR:-/tmp}/solc-nodus-addr256}"
JOBS="${JOBS:-$(nproc)}"
SRC="$WORK/solidity"

[ -f "$PATCH" ] || { echo "missing $PATCH" >&2; exit 1; }
mkdir -p "$WORK"

if [ ! -d "$SRC/.git" ]; then
	git clone --depth 1 --branch "$SOLC_TAG" "$SOLC_REPO" "$SRC"
fi

head="$(git -C "$SRC" rev-parse HEAD)"
if [ "$head" != "$SOLC_COMMIT" ]; then
	echo "commit mismatch: $SOLC_TAG resolved to $head, expected $SOLC_COMMIT" >&2
	exit 1
fi

# Apply the patch once (idempotent re-runs: skip if it is already applied).
if git -C "$SRC" apply --check "$PATCH" 2>/dev/null; then
	git -C "$SRC" apply "$PATCH"
elif git -C "$SRC" apply --reverse --check "$PATCH" 2>/dev/null; then
	echo "patch already applied"
else
	echo "patch does not apply to $SOLC_COMMIT" >&2
	exit 1
fi

# Release-style, reproducible version string (cmake/scripts/buildinfo.cmake):
#  - an empty prerelease.txt marks a release (otherwise a "develop.<today>" suffix is generated);
#  - commit_hash.txt pins the commit part to the upstream base (otherwise the dirty tree adds ".mod").
# Result: 0.8.30+nodus.addr256.commit.73712a01.<platform>
: > "$SRC/prerelease.txt"
echo "$SOLC_COMMIT" > "$SRC/commit_hash.txt"

cmake_args=(
	-DCMAKE_BUILD_TYPE=Release
	-DTESTS=OFF
	-DTOOLS=OFF
	-DSTRICT_Z3_VERSION=OFF
)
# v0.8.30 has no USE_Z3 / USE_CVC4 options: Z3 is only looked up for emscripten builds
# (CMakeLists.txt:99-123); native builds call SMT solvers as external processes.
if [ -n "${BOOST_ROOT:-}" ]; then
	cmake_args+=(-DBOOST_ROOT="$BOOST_ROOT" -DCMAKE_PREFIX_PATH="$BOOST_ROOT" -DBoost_NO_SYSTEM_PATHS=ON)
fi

cmake -S "$SRC" -B "$SRC/build" "${cmake_args[@]}"
cmake --build "$SRC/build" -j"$JOBS" --target solc

"$SRC/build/solc/solc" --version
