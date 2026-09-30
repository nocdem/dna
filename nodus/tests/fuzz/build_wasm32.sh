#!/usr/bin/env bash
# Build the nodus fuzz targets for wasm32 (32-bit size_t — the width the
# browser build of the tier-2 client runs with; web Connect design rev 5,
# §5 A2, package NC-5).
#
# Emscripten has no libFuzzer runtime: each harness is linked with
# fuzz_driver.c (replay + deterministic mutation, see its header) and with
# AddressSanitizer. The result is a node.js program per target:
#
#   node <out>/fuzz_t2_decode.js [-mutate=N] [-seed=S] <file-or-dir>...
#
# NODERAWFS=1 gives the program the host filesystem, so the corpus
# directories and libFuzzer crash files are passed by path.
#
# Compile set = the files web-wallet/scripts/build-nodus-send-wasm.sh links
# for the same decoders (nodus_tier2 / nodus_cbor / nodus_wire / nodus_value
# / nodus_sign + shared SHA3 + ML-DSA-87), plus fuzz_driver.c,
# fuzz_wasm_platform.c (randomness / memzero) and fuzz_wasm_log.c (QGP log
# back end). OpenSSL's libcrypto (SHA3 through EVP) comes from the same
# prebuilt wasm archive the web wallet uses.
#
# Environment:
#   EMCC_BIN             default ~/emsdk/upstream/emscripten/emcc
#   OPENSSL_WASM_PREFIX  default ~/wasm-deps/openssl-3.0.15-wasm
#                        (web-wallet/scripts/build-openssl-wasm.sh builds it)
#   OUT_DIR              default <nodus>/build-fuzz-wasm32
#   SQLITE3_H            default /usr/include/sqlite3.h (declarations only)
#
# Toolchain pin: Emscripten 6.0.10, the version the OpenSSL archive is built
# with (build-openssl-wasm.sh EMCC_REQUIRED_VERSION) — one toolchain for
# every object in the link.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
nodus="$(cd "$here/../.." && pwd)"
root="$(cd "$nodus/.." && pwd)"

EMCC_REQUIRED_VERSION="6.0.10"
EMCC_BIN="${EMCC_BIN:-$HOME/emsdk/upstream/emscripten/emcc}"
OPENSSL_WASM_PREFIX="${OPENSSL_WASM_PREFIX:-$HOME/wasm-deps/openssl-3.0.15-wasm}"
OUT_DIR="${OUT_DIR:-$nodus/build-fuzz-wasm32}"
SQLITE3_H="${SQLITE3_H:-/usr/include/sqlite3.h}"

if [ ! -x "$EMCC_BIN" ]; then
  echo "build_wasm32: $EMCC_BIN not found (set EMCC_BIN)" >&2
  exit 2
fi
emcc_line="$("$EMCC_BIN" --version | head -1)"
echo "$emcc_line"
case "$emcc_line" in
  *" ${EMCC_REQUIRED_VERSION} "*) ;;
  *) echo "build_wasm32: emcc ${EMCC_REQUIRED_VERSION} required, found: $emcc_line" >&2
     exit 2 ;;
esac
if [ ! -f "$OPENSSL_WASM_PREFIX/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_WASM_PREFIX/include/openssl/evp.h" ]; then
  echo "build_wasm32: OpenSSL wasm build missing under $OPENSSL_WASM_PREFIX (run web-wallet/scripts/build-openssl-wasm.sh)" >&2
  exit 2
fi

if [ ! -f "$SQLITE3_H" ]; then
  echo "build_wasm32: $SQLITE3_H not found (set SQLITE3_H)" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

# nodus_tier2.h pulls in nodus_media_storage.h, which includes <sqlite3.h>
# for declarations only; no sqlite code is compiled or linked. Same trick as
# web-wallet/scripts/build-nodus-send-wasm.sh (SQLITE3_H).
inc="$(mktemp -d)"
trap 'rm -rf "$inc"' EXIT
cp "$SQLITE3_H" "$inc/sqlite3.h"

common_sources=(
  "$here/fuzz_driver.c"
  "$here/fuzz_wasm_platform.c"
  "$here/fuzz_wasm_log.c"
  "$nodus/src/protocol/nodus_tier2.c"
  "$nodus/src/protocol/nodus_cbor.c"
  "$nodus/src/protocol/nodus_wire.c"
  "$nodus/src/core/nodus_value.c"
  "$nodus/src/crypto/nodus_sign.c"
  "$root/shared/crypto/hash/qgp_sha3.c"
  "$root/shared/crypto/sign/qgp_dilithium.c"
  "$root/shared/crypto/sign/dsa/sign.c"
  "$root/shared/crypto/sign/dsa/packing.c"
  "$root/shared/crypto/sign/dsa/polyvec.c"
  "$root/shared/crypto/sign/dsa/poly.c"
  "$root/shared/crypto/sign/dsa/ntt.c"
  "$root/shared/crypto/sign/dsa/rounding.c"
  "$root/shared/crypto/sign/dsa/reduce.c"
  "$root/shared/crypto/sign/dsa/fips202.c"
  "$root/shared/crypto/sign/dsa/symmetric-shake.c"
)

cflags=(
  -O1 -g -fsanitize=address -Wall -Wextra -Wno-unused-parameter
  -DNODUS_CHANNELS_DISABLED
  -I"$nodus/include" -I"$nodus/src"
  -I"$root/shared" -I"$root/shared/crypto" -I"$root/shared/crypto/sign/dsa"
  -I"$OPENSSL_WASM_PREFIX/include" -I"$inc"
)
ldflags=(
  -fsanitize=address
  -sENVIRONMENT=node -sNODERAWFS=1 -sALLOW_MEMORY_GROWTH=1
  -sSTACK_SIZE=1048576 -sEXIT_RUNTIME=1
  "$OPENSSL_WASM_PREFIX/lib/libcrypto.a"
)

for target in fuzz_t2_decode fuzz_cbor fuzz_value; do
  echo "== $target (wasm32)"
  "$EMCC_BIN" "${cflags[@]}" "$here/$target.c" "${common_sources[@]}" \
    "${ldflags[@]}" -o "$OUT_DIR/$target.js"
done
echo "build_wasm32: outputs in $OUT_DIR"
