#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build="${CKB_SLH_BUILD_DIR:-${TMPDIR:-/tmp}/dna-ckb-slh-sign-wasm-build}"
"${EMCMAKE_BIN:-emcmake}" "${CMAKE_BIN:-cmake}" -S "$root/crypto/ckb-slh-sign" -B "$build" -DCMAKE_BUILD_TYPE=Release
"${CMAKE_BIN:-cmake}" --build "$build" --target ckb_slh_sign --parallel 2
install -m 0644 "$build/ckb-slh-sign.wasm" "$root/src/pq/ckb-slh-sign.wasm"
