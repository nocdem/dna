#!/usr/bin/env bash
# Nodus Connect thin core: C -> WebAssembly (package NC-2 of
# docs/plans/2026-09-24-web-connect-design.md rev 5, §1; governing decision
# docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md).
#
# One module = the thin core library (web-wallet/connect/nc_*.c), its
# standalone entry (connect/nc_wasm.c), the nodus tier-2 client with the
# browser branches of package (c1), the message codecs compiled VERBATIM
# from messenger/codec/ (NC-1, decision Q2 = a), the Seal / authorship code
# (messenger/dna_api.c), the Anchor profile codec
# (messenger/dht/client/dna_profile.c), the BIP39 seed derivation and the
# shared crypto. Same toolchain and link model as the wallet's send module
# (scripts/build-nodus-send-wasm.sh): Emscripten 6.0.10, one thread,
# Asyncify, -Werror.
#
# THE OUTPUT IS A TEST ARTIFACT. It opens its own tier-2 session; shipped
# next to src/nodus/send.wasm the two sessions of one identity would evict
# each other on a node (nodus_auth.c:95-116, design §1.1). Linking the
# library into the one shared module is package NC-4. Nothing under src/ is
# written by default.
#
# Usage:
#   build-connect-wasm.sh              -> $NC_WASM_OUT (default
#                                         /tmp/nodus-connect-wasm):
#                                         connect-web.js/.wasm  (ENVIRONMENT web)
#                                         connect-node.mjs/.wasm (ENVIRONMENT node,
#                                         for a node-side harness)
#
# Toolchain / inputs:
#   EMSDK (default ~/emsdk) or EMCC_BIN; emcc 6.0.10 exactly (checked).
#   OPENSSL_WASM_PREFIX (default ~/wasm-deps/openssl-3.0.15-wasm,
#     scripts/build-openssl-wasm.sh): libcrypto.a — bip39 PBKDF2/SHA-512
#     (shared/crypto/key/bip39) and the tier-2 channel AES-GCM.
#   JSONC_WASM_PREFIX (default ~/wasm-deps/json-c-0.17-wasm,
#     scripts/build-jsonc-wasm.sh): libjson-c.a — the Anchor record codec
#     and this module's results. The Anchor signature is over json-c's
#     re-serialisation (design §1.2): the json-c version must match the one
#     the frozen app was built with; that version is NOT established (the
#     host's is printed below for the record).
#   SQLITE3_H (default /usr/include/sqlite3.h): declarations-only header
#     nodus/include/nodus/nodus.h pulls in (same trick as the send module);
#     no sqlite code is compiled or linked.
#
# Asyncify stack: the deepest wait chain is an export -> nc_* -> nodus
# client -> wait_response -> emscripten_sleep, with every large object
# (identity, record, values) on the heap or in static storage. The bound of
# the send module (16384, measured there for its chains) is reused;
# for THIS module it is NOT re-measured from a --profiling-funcs
# disassembly — expected to hold, not measured.
set -euo pipefail
cd "$(dirname "$0")/.."            # web-wallet/
root=..

EMCC_REQUIRED_VERSION="6.0.10"
EMSDK="${EMSDK:-$HOME/emsdk}"
EMCC_BIN="${EMCC_BIN:-$EMSDK/upstream/emscripten/emcc}"
OPENSSL_WASM_PREFIX="${OPENSSL_WASM_PREFIX:-$HOME/wasm-deps/openssl-3.0.15-wasm}"
JSONC_WASM_PREFIX="${JSONC_WASM_PREFIX:-$HOME/wasm-deps/json-c-0.17-wasm}"
SQLITE3_H="${SQLITE3_H:-/usr/include/sqlite3.h}"
out="${NC_WASM_OUT:-/tmp/nodus-connect-wasm}"
ASYNCIFY_STACK=16384

if [ ! -x "$EMCC_BIN" ]; then
  echo "build-connect-wasm: $EMCC_BIN not found (set EMSDK or EMCC_BIN)" >&2
  exit 2
fi
emcc_line="$("$EMCC_BIN" --version | head -1)"
echo "$emcc_line"
case "$emcc_line" in
  *" ${EMCC_REQUIRED_VERSION} "*) ;;
  *) echo "build-connect-wasm: emcc ${EMCC_REQUIRED_VERSION} required (pinned toolchain), found: $emcc_line" >&2
     exit 2 ;;
esac
if [ ! -f "$OPENSSL_WASM_PREFIX/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_WASM_PREFIX/include/openssl/evp.h" ]; then
  echo "build-connect-wasm: OpenSSL wasm build missing under $OPENSSL_WASM_PREFIX (run scripts/build-openssl-wasm.sh)" >&2
  exit 2
fi
if [ ! -f "$JSONC_WASM_PREFIX/lib/libjson-c.a" ] || [ ! -f "$JSONC_WASM_PREFIX/include/json-c/json.h" ]; then
  echo "build-connect-wasm: json-c wasm build missing under $JSONC_WASM_PREFIX (run scripts/build-jsonc-wasm.sh)" >&2
  exit 2
fi
if [ ! -f "$SQLITE3_H" ]; then
  echo "build-connect-wasm: $SQLITE3_H not found (set SQLITE3_H)" >&2
  exit 2
fi
echo "json-c (wasm): $(sed -n 's/^Version: //p' "$JSONC_WASM_PREFIX/lib/pkgconfig/json-c.pc" 2>/dev/null || echo unknown)"
echo "json-c (host, informational): $(pkg-config --modversion json-c 2>/dev/null || echo unknown)"
case "$(cd "$out" 2>/dev/null && pwd -P || echo "$out")" in
  "$(pwd -P)"/*) echo "build-connect-wasm: output must be outside web-wallet/ ($out)" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/inc"
cp "$SQLITE3_H" "$work/inc/sqlite3.h"

sources=(
  # the thin core
  connect/nc_wasm.c
  connect/nc_keys.c
  connect/nc_read.c
  connect/nc_servers.c
  connect/nc_profile.c
  connect/nc_requests.c
  connect/nc_salt.c
  connect/nc_outbox.c
  # message codecs, verbatim (NC-1)
  $root/messenger/codec/contact_request_codec.c
  $root/messenger/codec/dm_outbox_codec.c
  $root/messenger/codec/offline_queue_codec.c
  $root/messenger/codec/salt_agreement_codec.c
  $root/messenger/codec/seal_multi_codec.c
  $root/messenger/codec/gek_wrap_codec.c
  # Seal decode / authorship, Anchor record codec (compiled as-is)
  $root/messenger/dna_api.c
  $root/messenger/dht/client/dna_profile.c
  # nodus client (package (c1) compile set)
  $root/nodus/src/client/nodus_client.c
  $root/nodus/src/transport/nodus_tcp.c
  $root/nodus/src/protocol/nodus_tier2.c
  $root/nodus/src/protocol/nodus_cbor.c
  $root/nodus/src/protocol/nodus_wire.c
  $root/nodus/src/core/nodus_value.c
  $root/nodus/src/crypto/nodus_sign.c
  $root/nodus/src/crypto/nodus_identity.c
  $root/nodus/src/crypto/nodus_channel_crypto.c
  $root/nodus/src/nodus_log_shim.c
  # shared crypto (qgp_platform_<os>.c is NOT linked: nc_wasm.c defines
  # qgp_platform_random and qgp_secure_memzero)
  $root/shared/crypto/key/bip39/bip39.c
  $root/shared/crypto/key/bip39/bip39_pbkdf2.c
  $root/shared/crypto/key/bip39/seed_derivation.c
  $root/shared/crypto/hash/qgp_sha3.c
  $root/shared/crypto/hash/hkdf_sha3.c
  $root/shared/crypto/utils/qgp_random.c
  $root/shared/crypto/utils/qgp_fingerprint.c
  $root/shared/crypto/sign/qgp_signature.c
  $root/shared/crypto/sign/qgp_dilithium.c
  $root/shared/crypto/sign/dsa/sign.c
  $root/shared/crypto/sign/dsa/packing.c
  $root/shared/crypto/sign/dsa/polyvec.c
  $root/shared/crypto/sign/dsa/poly.c
  $root/shared/crypto/sign/dsa/ntt.c
  $root/shared/crypto/sign/dsa/rounding.c
  $root/shared/crypto/sign/dsa/reduce.c
  $root/shared/crypto/sign/dsa/fips202.c
  $root/shared/crypto/sign/dsa/symmetric-shake.c
  $root/shared/crypto/enc/qgp_aes.c
  $root/shared/crypto/enc/aes_keywrap.c
  $root/shared/crypto/enc/qgp_kyber.c
  $root/shared/crypto/enc/kyber_r3_legacy.c
  $root/shared/crypto/enc/qgp_mlkem.c
  $root/shared/crypto/enc/kem/cbd.c
  $root/shared/crypto/enc/kem/fips202.c
  $root/shared/crypto/enc/kem/indcpa.c
  $root/shared/crypto/enc/kem/kem.c
  $root/shared/crypto/enc/kem/ntt.c
  $root/shared/crypto/enc/kem/poly.c
  $root/shared/crypto/enc/kem/polyvec.c
  $root/shared/crypto/enc/kem/reduce.c
  $root/shared/crypto/enc/kem/symmetric-shake.c
  $root/shared/crypto/enc/kem/verify.c
)

exports=(
  nc_error nc_result nc_net_load nc_words_alloc nc_unlock nc_tick
  nc_profile_get nc_profile_update
  nc_requests_get nc_request_new nc_request_approve nc_request_withdraw
  nc_salt_get nc_salt_pick
  nc_day_today nc_outbox_send nc_outbox_get nc_ack_send nc_ack_get
  nc_cancel nc_lock
)

join_exports() {
  local s="" name
  for name in "$@"; do s="${s:+$s,}\"_$name\""; done
  printf '[%s]' "$s"
}

objdir="$work/obj"
mkdir -p "$objdir"
objects=()
for src in "${sources[@]}"; do
  obj="$objdir/$(echo "$src" | tr '/.' '__').o"
  extra=()
  # shared/crypto/utils/qgp_fingerprint.c:15 sizes a 16-char digit table
  # without its NUL on purpose; silenced for that one file only, as in
  # scripts/build-nodus-send-wasm.sh.
  case "$src" in */qgp_fingerprint.c) extra=(-Wno-unterminated-string-initialization) ;; esac
  "$EMCC_BIN" -c -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Werror \
    "${extra[@]}" \
    -I$root/nodus/include -I$root/nodus/src -I$root/shared -I$root/messenger \
    -I$root/messenger/include -Iconnect -I"$work/inc" -I"$OPENSSL_WASM_PREFIX/include" \
    -I"$JSONC_WASM_PREFIX/include" \
    "$src" -o "$obj"
  objects+=("$obj")
done

mkdir -p "$out"
for env in web node; do
  case "$env" in web) target="$out/connect-web.js" ;; node) target="$out/connect-node.mjs" ;; esac
  "$EMCC_BIN" -O2 -Werror "${objects[@]}" \
    "$JSONC_WASM_PREFIX/lib/libjson-c.a" "$OPENSSL_WASM_PREFIX/lib/libcrypto.a" \
    --no-entry \
    -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createNodusConnectWasm \
    -sENVIRONMENT="$env" \
    -sASYNCIFY=1 -sASYNCIFY_STACK_SIZE=$ASYNCIFY_STACK \
    -sSTACK_SIZE=1048576 -sINITIAL_MEMORY=67108864 \
    -sALLOW_MEMORY_GROWTH=1 -sMAXIMUM_MEMORY=268435456 \
    -sWEBSOCKET_URL=wss:// -sWEBSOCKET_SUBPROTOCOL=binary \
    -sEXPORTED_FUNCTIONS="$(join_exports "${exports[@]}")" \
    -sEXPORTED_RUNTIME_METHODS='["ccall","UTF8ToString","HEAPU8","abort"]' \
    -o "$target"
done
ls -l "$out"
sha256sum "$out"/*.wasm
