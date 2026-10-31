#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
wallet_dir="$(cd -- "$script_dir/.." && pwd)"
build_dir="${PQ_RECEIVE_BUILD_DIR:-${TMPDIR:-/tmp}/dna-pq-receive-wasm-build}"
emcmake_bin="${EMCMAKE_BIN:-emcmake}"
cmake_bin="${CMAKE_BIN:-cmake}"

"$emcmake_bin" "$cmake_bin" -S "$wallet_dir/crypto/pq-receive" \
    -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
"$cmake_bin" --build "$build_dir" --target pq_receive_keygen --parallel 2
install -d "$wallet_dir/src/pq"
install -m 0644 "$build_dir/receive-keygen.wasm" "$wallet_dir/src/pq/receive-keygen.wasm"
