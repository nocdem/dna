#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build="${MLDSA65_BUILD_DIR:-${TMPDIR:-/tmp}/dna-mldsa65-sign-wasm-build}"
"${EMCMAKE_BIN:-emcmake}" "${CMAKE_BIN:-cmake}" -S "$root/crypto/mldsa65-sign" -B "$build" -DCMAKE_BUILD_TYPE=Release
"${CMAKE_BIN:-cmake}" --build "$build" --target mldsa65_sign --parallel 2
install -m 0644 "$build/mldsa65-sign.wasm" "$root/src/pq/mldsa65-sign.wasm"
