#!/usr/bin/env bash
# Compile check (no link) of the nodus client SDK for the browser build.
#
# Design: docs/plans/2026-09-25-web-wallet-nodus-send-design.md rev 2,
# package (c1). Proves that the __EMSCRIPTEN__ branches of
# nodus/src/transport/nodus_tcp.c (poll() event loop, no listen/accept/WS
# server) and nodus/src/client/nodus_client.c (no read thread,
# emscripten_sleep yields, nodus_client_tick) plus the nodus sources the
# client calls directly compile with emcc — with -Werror, so a warning is a
# failure. It does NOT link, does not produce a .wasm, and runs nothing.
#
# Requires: emcc on PATH (`source ~/emsdk/emsdk_env.sh`) or EMCC_BIN; the
# host's sqlite3.h (SQLITE3_H, default /usr/include/sqlite3.h); the wasm
# OpenSSL 3.0.15 headers built by web-wallet/scripts/build-openssl-wasm.sh
# (OPENSSL_WASM_PREFIX, default ~/wasm-deps/openssl-3.0.15-wasm).
#
# Why OpenSSL: nodus/src/crypto/nodus_channel_crypto.c does the tier-2
# channel AES-256-GCM through OpenSSL EVP (<openssl/evp.h>). It is compiled
# against the wasm build's headers (-I, not -isystem: the headers compile
# clean under the same -Werror flags). Nothing is linked, so libcrypto.a is
# not used here.
#
# Why sqlite3.h: nodus/include/nodus/nodus.h includes the media / channel
# store headers, which #include <sqlite3.h> for their struct types. Only
# that ONE declarations-only header (its sole include is <stdarg.h>) is
# copied into a private include dir; no sqlite code is compiled or linked,
# and nothing the client calls touches sqlite.
#
# NOT compiled here (reported, not skipped silently):
#   Shared crypto (shared/crypto: SHA3, ML-DSA, ML-KEM, Kyber) — its wasm
#   link set is package (c3).
set -euo pipefail
cd "$(dirname "$0")/../.."          # monorepo root

EMCC_BIN="${EMCC_BIN:-emcc}"
SQLITE3_H="${SQLITE3_H:-/usr/include/sqlite3.h}"
OPENSSL_WASM_PREFIX="${OPENSSL_WASM_PREFIX:-$HOME/wasm-deps/openssl-3.0.15-wasm}"

if ! command -v "$EMCC_BIN" >/dev/null 2>&1; then
  echo "check-nodus-client-wasm: '$EMCC_BIN' not found (source ~/emsdk/emsdk_env.sh or set EMCC_BIN)" >&2
  exit 2
fi
if [ ! -f "$SQLITE3_H" ]; then
  echo "check-nodus-client-wasm: $SQLITE3_H not found (set SQLITE3_H)" >&2
  exit 2
fi
if [ ! -f "$OPENSSL_WASM_PREFIX/include/openssl/evp.h" ]; then
  echo "check-nodus-client-wasm: $OPENSSL_WASM_PREFIX/include/openssl/evp.h not found (run web-wallet/scripts/build-openssl-wasm.sh or set OPENSSL_WASM_PREFIX)" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/inc" "$work/obj"
cp "$SQLITE3_H" "$work/inc/sqlite3.h"

sources=(
  nodus/src/client/nodus_client.c
  nodus/src/transport/nodus_tcp.c
  nodus/src/protocol/nodus_tier2.c
  nodus/src/protocol/nodus_cbor.c
  nodus/src/protocol/nodus_wire.c
  nodus/src/core/nodus_value.c
  nodus/src/crypto/nodus_sign.c
  nodus/src/crypto/nodus_identity.c
  nodus/src/crypto/nodus_channel_crypto.c
)

"$EMCC_BIN" --version | head -1
fail=0
for src in "${sources[@]}"; do
  obj="$work/obj/$(basename "${src%.c}").o"
  if "$EMCC_BIN" -c -O2 -Wall -Wextra -Wno-unused-parameter -Werror \
       -Inodus/include -Inodus/src -Ishared -I"$work/inc" \
       -I"$OPENSSL_WASM_PREFIX/include" \
       "$src" -o "$obj"; then
    echo "OK    $src"
  else
    echo "FAIL  $src"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "check-nodus-client-wasm: FAILED" >&2
  exit 1
fi
echo "check-nodus-client-wasm: ${#sources[@]} files compiled clean (no link)"
