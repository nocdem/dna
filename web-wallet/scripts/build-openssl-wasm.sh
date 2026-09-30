#!/usr/bin/env bash
# Build a static OpenSSL 3.0.15 libcrypto for WebAssembly (Emscripten).
#
# Design: docs/plans/2026-09-25-web-wallet-nodus-send-design.md rev 2
# ("OpenSSL: SHA3, AES-256-GCM, HMAC -> OpenSSL WASM derlemesi"). The
# browser build of the nodus client links these through OpenSSL EVP:
#   nodus/src/crypto/nodus_channel_crypto.c  EVP_aes_256_gcm (tier-2 channel)
#   shared/crypto/hash/qgp_sha3.c            EVP_sha3_256 / EVP_sha3_512
#   shared/crypto/hash/hkdf_sha3.c           EVP_MAC_fetch(NULL, "HMAC", ...)
# Only libcrypto is built. libssl is not needed: no nodus or shared source
# includes <openssl/ssl.h> or calls SSL_*, and TLS for the browser is the
# browser's own wss:// terminated by Caddy on each node (decision record
# docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md, "TLS").
#
# Output: $OPENSSL_WASM_PREFIX (default ~/wasm-deps/openssl-3.0.15-wasm)
#   include/openssl/*.h   public headers (source + generated)
#   lib/libcrypto.a       wasm32 object archive
#
# Idempotent: if the prefix already holds lib/libcrypto.a and
# include/openssl/evp.h the script prints the path and exits 0 (FORCE=1
# rebuilds). A rebuild always starts from a freshly extracted tree; it never
# re-Configures a dirty one. One download attempt, no retries.
#
# Reproducibility: the tarball is pinned by SHA-256, the toolchain by
# emcc version, and the build date string by SOURCE_DATE_EPOCH. The
# configured OPENSSLDIR/ENGINESDIR/MODULESDIR strings contain the install
# prefix, so the archive is byte-identical only when built at the same path.
#
# Requires: curl, sha256sum, tar, perl, make; Emscripten 6.0.10 (emcc, emar,
# emranlib, emnm on PATH, or EMSDK_ENV pointing at emsdk_env.sh, default
# ~/emsdk/emsdk_env.sh).
set -euo pipefail

OPENSSL_VERSION="3.0.15"
# SHA-256 of openssl-3.0.15.tar.gz, copied from the published checksum files
#   https://www.openssl.org/source/openssl-3.0.15.tar.gz.sha256
#   https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz.sha256
# (both fetched 2026-09-29; the two files carry the same value).
OPENSSL_SHA256="23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
EMCC_REQUIRED_VERSION="6.0.10"
# Date of the 3.0.15 release tarball's files (2024-09-03 UTC); read by
# util/mkbuildinf.pl so the embedded "built on:" string is fixed.
export SOURCE_DATE_EPOCH=1725321600

DEPS_DIR="${WASM_DEPS_DIR:-$HOME/wasm-deps}"
SRC_DIR="$DEPS_DIR/src"
PREFIX="${OPENSSL_WASM_PREFIX:-$DEPS_DIR/openssl-${OPENSSL_VERSION}-wasm}"
TARBALL="$SRC_DIR/openssl-${OPENSSL_VERSION}.tar.gz"
TREE="$SRC_DIR/openssl-${OPENSSL_VERSION}"

if [ -z "${FORCE:-}" ] && [ -f "$PREFIX/lib/libcrypto.a" ] \
     && [ -f "$PREFIX/include/openssl/evp.h" ]; then
  echo "build-openssl-wasm: already built (FORCE=1 to rebuild)"
  echo "$PREFIX"
  exit 0
fi

if ! command -v emcc >/dev/null 2>&1; then
  EMSDK_ENV="${EMSDK_ENV:-$HOME/emsdk/emsdk_env.sh}"
  if [ ! -f "$EMSDK_ENV" ]; then
    echo "build-openssl-wasm: emcc not on PATH and $EMSDK_ENV not found (set EMSDK_ENV)" >&2
    exit 2
  fi
  # shellcheck disable=SC1090
  source "$EMSDK_ENV" >/dev/null 2>&1
fi
emcc_line="$(emcc --version | head -1)"
echo "$emcc_line"
case "$emcc_line" in
  *" ${EMCC_REQUIRED_VERSION} "*) ;;
  *)
    echo "build-openssl-wasm: emcc ${EMCC_REQUIRED_VERSION} required (pinned toolchain), found: $emcc_line" >&2
    exit 2
    ;;
esac

verify_tarball() {
  echo "${OPENSSL_SHA256}  $TARBALL" | sha256sum -c --status
}

mkdir -p "$SRC_DIR"
if [ -f "$TARBALL" ] && ! verify_tarball; then
  echo "build-openssl-wasm: cached $TARBALL does not match the pinned SHA-256; removing it" >&2
  rm -f "$TARBALL"
fi
if [ ! -f "$TARBALL" ]; then
  curl -fsSL -o "$TARBALL.part" "$OPENSSL_URL"
  mv "$TARBALL.part" "$TARBALL"
fi
if ! verify_tarball; then
  echo "build-openssl-wasm: SHA-256 mismatch for $TARBALL (expected $OPENSSL_SHA256); refusing to build" >&2
  sha256sum "$TARBALL" >&2
  rm -f "$TARBALL"
  exit 1
fi
echo "build-openssl-wasm: $TARBALL sha256 OK ($OPENSSL_SHA256)"

rm -rf "$TREE"
tar -xzf "$TARBALL" -C "$SRC_DIR"
cd "$TREE"

# Configure flags (INSTALL.md of the 3.0.15 tarball, section "Enable and
# Disable Features"):
#   linux-generic32  plain-C unix target with 32-bit bn_ops; wasm32 is ILP32.
#   CC/AR/RANLIB     the Emscripten tools, passed to Configure explicitly.
#                    emconfigure is NOT used: it exports CROSS_COMPILE=
#                    <emscripten>/em (tools/building.py) alongside CC=<full
#                    path>/emcc, and OpenSSL's Makefile prepends
#                    CROSS_COMPILE to CC, producing a nonexistent
#                    ".../em/.../emcc". CROSS_COMPILE is unset here.
#   --libdir=lib     fixed layout (lib/, not lib64/) for the check script.
#   no-asm           no assembler exists for wasm; C implementations only.
#   no-threads       the browser module is single-threaded (decision record
#                    "Çalışma modeli", operator 2026-09-25); no -pthread.
#   no-shared        static archive only; the wasm link takes .a inputs.
#   no-dso           no dlopen in the browser module.
#   no-module        no dynamically loaded providers; the default provider
#                    stays built into libcrypto, which EVP_MAC_fetch(NULL,
#                    "HMAC", NULL) in shared/crypto/hash/hkdf_sha3.c needs.
#   no-engine        ENGINE API unused by nodus/shared (EVP only).
#   no-afalgeng      Linux kernel AF_ALG sockets do not exist in wasm.
#   no-ui-console    termios console prompts; no terminal in the browser.
#   no-sock          socket BIOs unused; the client owns its sockets.
#   no-async         async jobs need ucontext/makecontext, absent in wasm.
#   no-legacy        legacy provider (MD4, DES, Blowfish, ...) unused: the
#                    client's algorithms are AES-GCM, SHA-1, SHA-2/3, HMAC.
#   no-tests         test programs are not built or run.
# Kept (default provider): AES incl. GCM, SHA-1, SHA-2, SHA-3/SHAKE, HMAC
# (EVP_MAC), EVP, base64 (EVP_EncodeBlock).
unset CROSS_COMPILE
./Configure linux-generic32 CC=emcc AR=emar RANLIB=emranlib \
  --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib \
  no-asm no-threads no-shared no-dso no-module no-engine no-afalgeng \
  no-ui-console no-sock no-async no-legacy no-tests

# Build only the generated headers and libcrypto.a (no libssl, no apps).
make -j"$(nproc)" build_generated
make -j"$(nproc)" libcrypto.a

rm -rf "$PREFIX"
mkdir -p "$PREFIX/include/openssl" "$PREFIX/lib"
cp include/openssl/*.h "$PREFIX/include/openssl/"
cp libcrypto.a "$PREFIX/lib/libcrypto.a"
cp LICENSE.txt "$PREFIX/LICENSE.txt"

# Defined-symbol check: the EVP entry points the nodus client calls, and the
# default-provider implementation tables behind them (AES-256-GCM, SHA-1,
# SHA-256, SHA3-256/512, HMAC). The symbol table goes to a file first: piping
# emnm into `grep -q` under pipefail would fail on SIGPIPE, not on absence.
syms="$(mktemp)"
trap 'rm -f "$syms"' EXIT
emnm "$PREFIX/lib/libcrypto.a" > "$syms" 2>/dev/null
for sym in EVP_aes_256_gcm EVP_sha1 EVP_sha256 EVP_sha3_256 EVP_sha3_512 \
           EVP_MAC_fetch EVP_EncodeBlock EVP_Digest EVP_CIPHER_CTX_new \
           ossl_default_provider_init ossl_aes256gcm_functions \
           ossl_sha1_functions ossl_sha256_functions ossl_sha3_256_functions \
           ossl_sha3_512_functions ossl_hmac_functions; do
  if ! grep -qE " [TDR] ${sym}\$" "$syms"; then
    echo "build-openssl-wasm: expected symbol $sym not defined in libcrypto.a" >&2
    exit 1
  fi
done
echo "build-openssl-wasm: required EVP symbols and provider tables present"
sha256sum "$PREFIX/lib/libcrypto.a"
ls -l "$PREFIX/lib/libcrypto.a"
echo "$PREFIX"
