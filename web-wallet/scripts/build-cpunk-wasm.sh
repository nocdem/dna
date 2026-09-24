#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Zig 0.13.0, installed separately (e.g. isolated pip ziglang==0.13.0).
ZIG_BIN="${ZIG_BIN:-zig}"
src=../shared/crypto/sign/cellframe_dilithium
"$ZIG_BIN" cc --target=wasm32-wasi -mexec-model=reactor -O2 -DNDEBUG -I"$src" \
 crypto/cpunk-wasm.c "$src"/{dilithium_params,dilithium_packing,dilithium_poly,dilithium_polyvec,dilithium_rounding_reduce,dilithium_sign,fips202}.c \
 -Wl,--export=cpunk_input -Wl,--export=cpunk_output -Wl,--export=cpunk_derive \
 -Wl,--strip-all -Wl,-z,stack-size=262144 -o src/cpunk/legacy-dilithium.wasm
