#!/usr/bin/env bash
set -euo pipefail
wallet_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${ALGORAND_SIGN_BUILD_DIR:-${TMPDIR:-/tmp}/dna-algorand-sign-build}"
"${EMCMAKE_BIN:-emcmake}" "${CMAKE_BIN:-cmake}" -S "$wallet_dir/crypto/algorand-sign" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
"${CMAKE_BIN:-cmake}" --build "$build_dir" --target algorand_sign --parallel 2
install -m 0644 "$build_dir/algorand-sign.wasm" "$wallet_dir/src/pq/algorand-sign.wasm"
