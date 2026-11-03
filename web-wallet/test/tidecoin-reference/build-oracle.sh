#!/usr/bin/env bash
# Offline, isolated build. TIDECOIN_SRC must be a clean checkout of the pinned
# upstream commit; BOOST_ROOT must be the 1.88.0 header install from its pinned
# dependency recipe. No network, node, wallet or transaction submission.
set -euo pipefail
: "${TIDECOIN_SRC:?set pinned Tidecoin source path}"
: "${BOOST_ROOT:?set isolated Boost 1.88.0 install prefix}"
: "${BUILD_ROOT:?set isolated output directory}"
CMAKE_BIN=${CMAKE_BIN:-cmake}
here=$(cd "$(dirname "$0")" && pwd)
test "$(git -C "$TIDECOIN_SRC" rev-parse HEAD)" = 7d653be5d24e73b49d101578afb33d8d7a889c1d
test -z "$(git -C "$TIDECOIN_SRC" status --porcelain)"
"$CMAKE_BIN" -S "$TIDECOIN_SRC" -B "$BUILD_ROOT" -DBUILD_TIDECOIN_BIN=OFF -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF -DBUILD_TESTS=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF -DENABLE_WALLET=OFF -DBUILD_GUI=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DWITH_MINIUPNPC=OFF -DWITH_NATPMP=OFF -DCMAKE_BUILD_TYPE=Release -DBoost_ROOT="$BOOST_ROOT"
"$CMAKE_BIN" --build "$BUILD_ROOT" --target tidecoin_consensus tidecoin_quantum tidecoin_crypto tidecoin_util tidecoin_clientversion -j 2
for file in policy/policy.cpp policy/feerate.cpp script/solver.cpp; do
  "${CXX:-g++}" -std=c++20 -O2 -ffunction-sections -fdata-sections -I"$TIDECOIN_SRC/src" -I"$BUILD_ROOT/src" -I"$BOOST_ROOT/include" -c "$TIDECOIN_SRC/src/$file" -o "$BUILD_ROOT/$(basename "$file" .cpp)-oracle.o"
done
"${CXX:-g++}" -std=c++20 -O2 -ffunction-sections -fdata-sections -I"$TIDECOIN_SRC/src" -I"$BUILD_ROOT/src" -I"$BOOST_ROOT/include" "$here/verify.cpp" "$BUILD_ROOT/policy-oracle.o" "$BUILD_ROOT/feerate-oracle.o" "$BUILD_ROOT/solver-oracle.o" -Wl,--gc-sections -Wl,--start-group "$BUILD_ROOT/lib/libtidecoin_consensus.a" "$BUILD_ROOT/lib/libtidecoin_quantum.a" "$BUILD_ROOT/lib/libtidecoin_crypto.a" "$BUILD_ROOT/lib/libtidecoin_util.a" "$BUILD_ROOT/lib/libtidecoin_clientversion.a" -Wl,--end-group -pthread -o "$BUILD_ROOT/tidecoin-script-oracle"
