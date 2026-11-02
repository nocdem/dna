#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build="${QTC_MLDSA44_BUILD_DIR:-${TMPDIR:-/tmp}/dna-qtc-mldsa44-sign-wasm-build}"
"${EMCMAKE_BIN:-emcmake}" "${CMAKE_BIN:-cmake}" -S "$root/crypto/qtc-mldsa44-sign" -B "$build" -DCMAKE_BUILD_TYPE=Release
"${CMAKE_BIN:-cmake}" --build "$build" --target qtc_mldsa44_sign --parallel 2
install -m 0644 "$build/qtc-mldsa44-sign.wasm" "$root/src/pq/qtc-mldsa44-sign.wasm"
