#!/usr/bin/env bash
# Downloadable site SDK verifier; builds only, never executes the output.
# Same toolchain/flags style as build-nodus-send-wasm.sh. No send artifacts.
# Uses unchanged project SHA3-512 and ML-DSA-87 implementations.
set -euo pipefail
cd "$(dirname "$0")/.."
root=..
EMCC_REQUIRED_VERSION="6.0.10"
EMSDK="${EMSDK:-$HOME/emsdk}"
EMCC_BIN="${EMCC_BIN:-$EMSDK/upstream/emscripten/emcc}"
OPENSSL_WASM_PREFIX="${OPENSSL_WASM_PREFIX:-$HOME/wasm-deps/openssl-3.0.15-wasm}"
if [ ! -x "$EMCC_BIN" ]; then
  echo "build-nodus-site-verify-wasm: $EMCC_BIN not found (set EMSDK or EMCC_BIN)" >&2
  exit 2
fi
emcc_line="$("$EMCC_BIN" --version | head -1)"
echo "$emcc_line"
case "$emcc_line" in
  *" ${EMCC_REQUIRED_VERSION} "*) ;;
  *) echo "build-nodus-site-verify-wasm: emcc ${EMCC_REQUIRED_VERSION} required, found: $emcc_line" >&2; exit 2 ;;
esac
if [ ! -f "$OPENSSL_WASM_PREFIX/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_WASM_PREFIX/include/openssl/evp.h" ]; then
  echo "build-nodus-site-verify-wasm: OpenSSL wasm build missing under $OPENSSL_WASM_PREFIX" >&2
  exit 2
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
dsa=$root/shared/crypto/sign/dsa
sources=(crypto/nodus-site-verify-wasm.c "$root/nodus/src/crypto/nodus_sign.c"
  "$root/shared/crypto/hash/qgp_sha3.c" "$root/shared/crypto/sign/qgp_dilithium.c"
  "$dsa"/{sign,packing,polyvec,poly,ntt,rounding,reduce,fips202,symmetric-shake}.c)
objects=()
for src in "${sources[@]}"; do
  obj="$work/$(echo "$src" | tr '/.' '__').o"
  "$EMCC_BIN" -c -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Werror \
    -ffunction-sections -fdata-sections \
    -I$root/nodus/include -I$root/nodus/src -I$root/shared \
    -I"$OPENSSL_WASM_PREFIX/include" "$src" -o "$obj"
  objects+=("$obj")
done
mkdir -p extension/site-sdk
"$EMCC_BIN" -O2 -Werror "${objects[@]}" "$OPENSSL_WASM_PREFIX/lib/libcrypto.a" \
  --no-entry -Wl,--gc-sections \
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createNodusSiteVerifyWasm \
  -sENVIRONMENT=web,node \
  -sSTACK_SIZE=1048576 -sINITIAL_MEMORY=67108864 \
  -sALLOW_MEMORY_GROWTH=1 -sMAXIMUM_MEMORY=268435456 \
  -sEXPORTED_FUNCTIONS='["_nsv_verify","_nsv_address_of","_malloc","_free"]' \
  -sEXPORTED_RUNTIME_METHODS='["HEAPU8"]' \
  -o extension/site-sdk/nodus-site-verify.mjs
chmod 644 extension/site-sdk/nodus-site-verify.{mjs,wasm}
sha256sum extension/site-sdk/nodus-site-verify.{mjs,wasm}
