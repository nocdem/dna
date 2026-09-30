#!/usr/bin/env bash
# Build messenger fuzz targets for wasm32 (32-bit size_t — the width the web
# Connect thin core runs with in the browser; design rev 5 §5 A2, NC-5).
#
# Emscripten has no libFuzzer runtime: each harness is linked with the
# replay + deterministic-mutation driver nodus/tests/fuzz/fuzz_driver.c and
# AddressSanitizer. Output: one node.js program per target,
#
#   node <out>/fuzz_seal_decode.js [-mutate=N] [-seed=S] <file-or-dir>...
#
# with NODERAWFS=1 (host filesystem), so corpus directories and libFuzzer
# crash files from the native build are passed by path.
#
# Targets and what they compile (the parser sources unchanged):
#   fuzz_seal_decode      dna_api.c + shared crypto
#   fuzz_message_decrypt  dna_api.c + shared crypto
#   fuzz_offline_queue    dht_offline_queue.c + codec/offline_queue_codec.c
#   fuzz_contact_request  dht_contact_request.c + codec/contact_request_codec.c
#   fuzz_contactlist      dht_contactlist.c + codec/contactlist_codec.c + dna_api.c,
#                         both modes (raw blob, and sealed JSON reaching the
#                         JSON parser), with the real wasm32 json-c
#   fuzz_anchor_json      dht/client/dna_profile.c, with the real wasm32 json-c
#   NC-1 moved the parsers of offline_queue / contact_request / contactlist
#   into messenger/codec/; the I/O files call them there, so each of those
#   targets compiles its codec unit too.
# Not built for wasm32 (gap, see messenger/docs/FUZZING.md):
#   fuzz_salt_packet (gek.c pulls the group database; available once NC-1
#   extracts the KEM-wrap codec), fuzz_profile_json / fuzz_base58 (not on
#   the web core's input path).
#
# json-c: the wasm32 archive from web-wallet/scripts/build-jsonc-wasm.sh,
# tag json-c-0.17-20230812 — the tag the frozen app's Android and Windows
# builds fetch (web Connect design §1.2: same json-c version as the frozen
# app). Its headers (with the wasm32-generated json_config.h) are the ones
# compiled against; the host /usr/include/json-c is not used.
#
# fuzz_dht_stub.c (the nodus_ops read/write test doubles) is linked into
# every target. I/O and keyring functions the compiled files reference but
# the parsers never call are defined in fuzz_wasm_abort_stubs.c as abort():
# reaching one is a harness bug, reported loudly instead of silently
# returning.
#
# Environment:
#   EMCC_BIN             default ~/emsdk/upstream/emscripten/emcc
#   OPENSSL_WASM_PREFIX  default ~/wasm-deps/openssl-3.0.15-wasm
#                        (web-wallet/scripts/build-openssl-wasm.sh builds it)
#   JSONC_WASM_PREFIX    default ~/wasm-deps/json-c-0.17-wasm
#                        (web-wallet/scripts/build-jsonc-wasm.sh builds it)
#   SQLITE3_H            default /usr/include/sqlite3.h (declarations only)
#   OUT_DIR              default <messenger>/tests/fuzz/build-wasm32
#
# Toolchain pin: Emscripten 6.0.10 (same as the OpenSSL and json-c archives).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
messenger="$(cd "$here/../.." && pwd)"
root="$(cd "$messenger/.." && pwd)"
nodus_fuzz="$root/nodus/tests/fuzz"

EMCC_REQUIRED_VERSION="6.0.10"
EMCC_BIN="${EMCC_BIN:-$HOME/emsdk/upstream/emscripten/emcc}"
OPENSSL_WASM_PREFIX="${OPENSSL_WASM_PREFIX:-$HOME/wasm-deps/openssl-3.0.15-wasm}"
JSONC_WASM_PREFIX="${JSONC_WASM_PREFIX:-$HOME/wasm-deps/json-c-0.17-wasm}"
SQLITE3_H="${SQLITE3_H:-/usr/include/sqlite3.h}"
OUT_DIR="${OUT_DIR:-$here/build-wasm32}"

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
if [ ! -f "$JSONC_WASM_PREFIX/lib/libjson-c.a" ] || [ ! -f "$JSONC_WASM_PREFIX/include/json-c/json.h" ]; then
  echo "build_wasm32: json-c wasm build missing under $JSONC_WASM_PREFIX (run web-wallet/scripts/build-jsonc-wasm.sh)" >&2
  exit 2
fi
if [ ! -f "$SQLITE3_H" ]; then
  echo "build_wasm32: $SQLITE3_H not found (set SQLITE3_H)" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

# Declaration-only header the compiled sources include transitively
# (nodus media storage -> sqlite3.h). No sqlite code is compiled or linked.
inc="$(mktemp -d)"
trap 'rm -rf "$inc"' EXIT
cp "$SQLITE3_H" "$inc/sqlite3.h"

crypto_sources=(
  "$root/shared/crypto/hash/qgp_sha3.c"
  "$root/shared/crypto/utils/qgp_random.c"
  "$root/shared/crypto/sign/qgp_signature.c"
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
  "$root/shared/crypto/enc/qgp_aes.c"
  "$root/shared/crypto/enc/aes_keywrap.c"
  "$root/shared/crypto/enc/qgp_kyber.c"
  "$root/shared/crypto/enc/kyber_r3_legacy.c"
  "$root/shared/crypto/enc/qgp_mlkem.c"
  "$root/shared/crypto/enc/kem/cbd.c"
  "$root/shared/crypto/enc/kem/fips202.c"
  "$root/shared/crypto/enc/kem/indcpa.c"
  "$root/shared/crypto/enc/kem/kem.c"
  "$root/shared/crypto/enc/kem/ntt.c"
  "$root/shared/crypto/enc/kem/poly.c"
  "$root/shared/crypto/enc/kem/polyvec.c"
  "$root/shared/crypto/enc/kem/reduce.c"
  "$root/shared/crypto/enc/kem/symmetric-shake.c"
  "$root/shared/crypto/enc/kem/verify.c"
)
support_sources=(
  "$nodus_fuzz/fuzz_driver.c"
  "$nodus_fuzz/fuzz_wasm_platform.c"
  "$nodus_fuzz/fuzz_wasm_log.c"
  "$here/fuzz_dht_stub.c"
  "$here/fuzz_wasm_abort_stubs.c"
)

cflags=(
  -O1 -g -fsanitize=address -Wall -Wextra -Wno-unused-parameter
  -DNODUS_CHANNELS_DISABLED
  -I"$here" -I"$messenger" -I"$messenger/include" -I"$messenger/dht"
  -I"$messenger/dht/client" -I"$messenger/dht/shared"
  -I"$root/nodus/include" -I"$root/nodus/src"
  -I"$root/shared" -I"$root/shared/crypto"
  -I"$root/shared/crypto/sign/dsa" -I"$root/shared/crypto/enc/kem"
  -I"$root/dnac/include"
  -I"$OPENSSL_WASM_PREFIX/include" -I"$JSONC_WASM_PREFIX/include" -I"$inc"
)
ldflags=(
  -fsanitize=address
  -sENVIRONMENT=node -sNODERAWFS=1 -sALLOW_MEMORY_GROWTH=1
  -sSTACK_SIZE=1048576 -sEXIT_RUNTIME=1
  "$OPENSSL_WASM_PREFIX/lib/libcrypto.a"
  "$JSONC_WASM_PREFIX/lib/libjson-c.a"
)

build() {
  local target="$1"; shift
  echo "== $target (wasm32)"
  "$EMCC_BIN" "${cflags[@]}" "$@" "${support_sources[@]}" "${crypto_sources[@]}" \
    "${ldflags[@]}" -o "$OUT_DIR/$target.js"
}

build fuzz_seal_decode "$here/fuzz_seal_decode.c" "$here/fuzz_keys.c" "$messenger/dna_api.c"
build fuzz_message_decrypt "$here/fuzz_message_decrypt.c" "$here/fuzz_common.c" "$messenger/dna_api.c"
build fuzz_offline_queue "$here/fuzz_offline_queue.c" "$messenger/dht/shared/dht_offline_queue.c" \
  "$messenger/codec/offline_queue_codec.c"
build fuzz_contact_request "$here/fuzz_contact_request.c" "$messenger/dht/shared/dht_contact_request.c" \
  "$messenger/codec/contact_request_codec.c"
build fuzz_contactlist "$here/fuzz_contactlist.c" "$here/fuzz_keys.c" \
  "$messenger/dht/client/dht_contactlist.c" "$messenger/codec/contactlist_codec.c" "$messenger/dna_api.c"
build fuzz_anchor_json "$here/fuzz_anchor_json.c" "$messenger/dht/client/dna_profile.c"
echo "build_wasm32: outputs in $OUT_DIR"
