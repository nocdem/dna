#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build="${TIDECOIN_BUILD_DIR:-${TMPDIR:-/tmp}/dna-tidecoin-sign-wasm-build}"
"${EMCMAKE_BIN:-emcmake}" "${CMAKE_BIN:-cmake}" -S "$root/crypto/tidecoin-sign" -B "$build" -DCMAKE_BUILD_TYPE=Release
"${CMAKE_BIN:-cmake}" --build "$build" --target tidecoin_sign --parallel 2
install -m 0644 "$build/tidecoin-sign.wasm" "$root/src/pq/tidecoin-sign.wasm"
