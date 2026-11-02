#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
"${CMAKE_BIN:-cmake}" -S "$root/../shared/crypto/sign/mldsa" -B "$tmp/build" -DCMAKE_BUILD_TYPE=Release
"${CMAKE_BIN:-cmake}" --build "$tmp/build" --parallel 2
"${CC:-cc}" -O2 -Wall -Wextra -Werror -I"$root/../shared" "$root/test/mldsa65-reference/native-harness.c" "$root/crypto/mldsa65-sign.c" "$tmp/build/libqgp_mldsa.a" -o "$tmp/harness"
node "$root/test/mldsa65-reference/verify-native.mjs" "$tmp/harness"
