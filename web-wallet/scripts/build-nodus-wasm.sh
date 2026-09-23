#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Reproducible with Emscripten 4.0.16. No changes to shared native crypto sources.
EMCC_BIN="${EMCC_BIN:-emcc}"
src=../shared/crypto/sign/dsa
"$EMCC_BIN" -O2 -I../shared -ffunction-sections -fdata-sections \
  crypto/nodus-wasm.c ../shared/crypto/sign/qgp_dilithium.c \
  "$src"/{packing,polyvec,poly,ntt,rounding,reduce,fips202,symmetric-shake}.c \
  --no-entry -s STANDALONE_WASM=1 -s STACK_SIZE=262144 -s INITIAL_MEMORY=2097152 \
  -s EXPORTED_FUNCTIONS='["_nodus_input","_nodus_output","_nodus_derive"]' \
  -Wl,--strip-all -o src/nodus/mldsa87.wasm
chmod 644 src/nodus/mldsa87.wasm
