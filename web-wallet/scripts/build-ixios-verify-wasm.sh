#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
src=../shared/crypto/sign/dsa
"${EMCC_BIN:-emcc}" -O2 -I../shared -ffunction-sections -fdata-sections crypto/ixios-mldsa87-verify.c ../shared/crypto/sign/qgp_dilithium.c "$src"/{sign,packing,polyvec,poly,ntt,rounding,reduce,fips202,symmetric-shake}.c --no-entry -s STANDALONE_WASM=1 -s STACK_SIZE=524288 -s INITIAL_MEMORY=4194304 -s EXPORTED_FUNCTIONS='["_ixios_message","_ixios_public_key","_ixios_signature","_ixios_verify","_ixios_clear"]' -Wl,--strip-all -o src/ixios/mldsa87-verify.wasm
