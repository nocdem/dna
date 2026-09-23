#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Reproducible with Emscripten 4.0.16. No changes to shared native crypto sources.
# Stack sized for crypto_sign_signature_internal's own frame (mat[K=8] polyvecl
# 8*7*1024=57344B + s1/y/z polyvecl 3*7168B + t0/s2/w1/w0/h polyveck 5*8192B +
# cp poly 1024B + seedbuf/state ~500B =~ 121KB peak, sign.c:146-250) plus the
# qgp_dsa87_keypair_derand frame it also calls (not nested, ~97KB, same shape);
# 512KB / 4MB give >2x headroom over the larger (signing) frame.
EMCC_BIN="${EMCC_BIN:-emcc}"
src=../shared/crypto/sign/dsa
mkdir -p src/pq
"$EMCC_BIN" -O2 -I../shared -ffunction-sections -fdata-sections \
  crypto/mldsa87-sign-wasm.c ../shared/crypto/sign/qgp_dilithium.c \
  "$src"/{sign,packing,polyvec,poly,ntt,rounding,reduce,fips202,symmetric-shake}.c \
  --no-entry -s STANDALONE_WASM=1 -s STACK_SIZE=524288 -s INITIAL_MEMORY=4194304 \
  -s EXPORTED_FUNCTIONS='["_mldsa_seed","_mldsa_hash","_mldsa_rnd","_mldsa_pk","_mldsa_sig","_mldsa_sign"]' \
  -Wl,--strip-all -o src/pq/mldsa87-sign.wasm
chmod 644 src/pq/mldsa87-sign.wasm
