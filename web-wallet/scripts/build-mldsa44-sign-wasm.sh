#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build="${MLDSA44_BUILD_DIR:-${TMPDIR:-/tmp}/dna-mldsa44-sign-wasm-build}"
"${EMCMAKE_BIN:-emcmake}" "${CMAKE_BIN:-cmake}" -S "$root/crypto/mldsa44-sign" -B "$build" -DCMAKE_BUILD_TYPE=Release
"${CMAKE_BIN:-cmake}" --build "$build" --target mldsa44_sign --parallel 2
install -m 0644 "$build/mldsa44-sign.wasm" "$root/src/pq/mldsa44-sign.wasm"
