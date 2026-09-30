#!/usr/bin/env bash
# Build a static json-c 0.17 (tag json-c-0.17-20230812) for WebAssembly
# (Emscripten).
#
# Design: docs/plans/2026-09-24-web-connect-design.md §1.2 — the web Connect
# core must compile the SAME json-c version as the frozen app, because the
# Anchor record signature is over json-c's re-serialisation
# (dna_identity_to_json_unsigned, messenger/dht/client/dna_profile.c). The
# frozen app's Android build fetches tag json-c-0.17-20230812
# (messenger/scripts/build-android-docker.sh:218-219) and its Windows build
# the same tag (messenger/setup-windows-build.sh:454-459); this script pins
# that tag and that download URL.
# Consumers today: messenger/tests/fuzz/build_wasm32.sh (fuzz_contactlist,
# fuzz_anchor_json).
#
# Output: $JSONC_WASM_PREFIX (default ~/wasm-deps/json-c-0.17-wasm)
#   include/json-c/*.h    public headers (source + generated json_config.h)
#   lib/libjson-c.a       wasm32 object archive
#   COPYING               upstream license
#
# Idempotent: if the prefix already holds lib/libjson-c.a and
# include/json-c/json.h the script prints the path and exits 0 (FORCE=1
# rebuilds). A rebuild always starts from a freshly extracted tree and an
# empty build directory. One download attempt, no retries.
#
# Reproducibility: the tarball is pinned by SHA-256 and the toolchain by emcc
# version. json-c is built without sanitizers, like the OpenSSL archive: it
# is the product-like dependency, not instrumented fuzz code.
#
# Requires: curl, sha256sum, tar, cmake, make; Emscripten 6.0.10 (emcmake,
# emcc, emnm on PATH, or EMSDK_ENV pointing at emsdk_env.sh, default
# ~/emsdk/emsdk_env.sh).
set -euo pipefail

JSONC_TAG="json-c-0.17-20230812"
# SHA-256 of the GitHub tag archive below. json-c publishes no checksum for
# it (no GitHub release object for the tag; no .sha256 next to the S3
# release tarball). The value was computed with sha256sum from the file
# downloaded 2026-09-30, and its CONTENT was checked against the official
# release tarball https://s3.amazonaws.com/json-c_releases/releases/json-c-0.17.tar.gz
# (sha256 7550914d58fb63b2c3546f3ccfbe11f1c094147bd31a69dcd23714d7956159e6,
# same day): `diff -rq` of the two extracted trees differs only by a stray
# editor swap file .CMakeLists.txt.swp present in the S3 tarball.
# GitHub tag archives are not promised to be byte-stable; on a mismatch,
# re-verify the content against the S3 release tarball before re-pinning.
JSONC_SHA256="024d302a3aadcbf9f78735320a6d5aedf8b77876c8ac8bbb95081ca55054c7eb"
JSONC_URL="https://github.com/json-c/json-c/archive/refs/tags/${JSONC_TAG}.tar.gz"
EMCC_REQUIRED_VERSION="6.0.10"

DEPS_DIR="${WASM_DEPS_DIR:-$HOME/wasm-deps}"
SRC_DIR="$DEPS_DIR/src"
PREFIX="${JSONC_WASM_PREFIX:-$DEPS_DIR/json-c-0.17-wasm}"
TARBALL="$SRC_DIR/${JSONC_TAG}.tar.gz"
TREE="$SRC_DIR/json-c-${JSONC_TAG}"
BUILD="$TREE/build-wasm"

if [ -z "${FORCE:-}" ] && [ -f "$PREFIX/lib/libjson-c.a" ] \
     && [ -f "$PREFIX/include/json-c/json.h" ]; then
  echo "build-jsonc-wasm: already built (FORCE=1 to rebuild)"
  echo "$PREFIX"
  exit 0
fi

if ! command -v emcc >/dev/null 2>&1; then
  EMSDK_ENV="${EMSDK_ENV:-$HOME/emsdk/emsdk_env.sh}"
  if [ ! -f "$EMSDK_ENV" ]; then
    echo "build-jsonc-wasm: emcc not on PATH and $EMSDK_ENV not found (set EMSDK_ENV)" >&2
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
    echo "build-jsonc-wasm: emcc ${EMCC_REQUIRED_VERSION} required (pinned toolchain), found: $emcc_line" >&2
    exit 2
    ;;
esac

verify_tarball() {
  echo "${JSONC_SHA256}  $TARBALL" | sha256sum -c --status
}

mkdir -p "$SRC_DIR"
if [ -f "$TARBALL" ] && ! verify_tarball; then
  echo "build-jsonc-wasm: cached $TARBALL does not match the pinned SHA-256; removing it" >&2
  rm -f "$TARBALL"
fi
if [ ! -f "$TARBALL" ]; then
  curl -fsSL -o "$TARBALL.part" "$JSONC_URL"
  mv "$TARBALL.part" "$TARBALL"
fi
if ! verify_tarball; then
  echo "build-jsonc-wasm: SHA-256 mismatch for $TARBALL (expected $JSONC_SHA256); refusing to build" >&2
  sha256sum "$TARBALL" >&2
  rm -f "$TARBALL"
  exit 1
fi
echo "build-jsonc-wasm: $TARBALL sha256 OK ($JSONC_SHA256)"

rm -rf "$TREE"
tar -xzf "$TARBALL" -C "$SRC_DIR"
mkdir -p "$BUILD"
cd "$BUILD"

# CMake options (json-c 0.17 CMakeLists.txt option() list):
#   BUILD_SHARED_LIBS=OFF, BUILD_STATIC_LIBS=ON
#                    as the frozen app's Android build
#                    (build-android-docker.sh:223); static archive only.
#   BUILD_APPS=OFF, BUILD_TESTING=OFF
#                    as the frozen app's Windows build
#                    (setup-windows-build.sh:468-469); the apps and tests are
#                    host programs and are not wanted in the archive.
#   CMAKE_BUILD_TYPE=Release
#                    optimised library, no debug asserts beyond json-c's own.
#   CMAKE_INSTALL_PREFIX / CMAKE_INSTALL_LIBDIR=lib
#                    fixed layout (lib/, not lib64/) for the consumers.
# Everything else stays at json-c's default (thread-local storage on,
# threading off, RDRAND off, -Werror on).
emcmake cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_STATIC_LIBS=ON \
  -DBUILD_APPS=OFF \
  -DBUILD_TESTING=OFF

make -j"$(nproc)"

rm -rf "$PREFIX"
make install
cp "$TREE/COPYING" "$PREFIX/COPYING"

# Defined-symbol check: every json-c function the wasm32 consumers call
# (messenger/codec/contactlist_codec.c, messenger/dht/client/dna_profile.c).
# A `T` entry from emnm also shows the archive holds wasm objects. The symbol
# table goes to a file first: piping emnm into `grep -q` under pipefail would
# fail on SIGPIPE, not on absence.
syms="$(mktemp)"
trap 'rm -f "$syms"' EXIT
emnm "$PREFIX/lib/libjson-c.a" > "$syms" 2>/dev/null
for sym in json_tokener_parse json_object_put json_object_is_type \
           json_object_to_json_string_ext json_object_new_object \
           json_object_object_add json_object_object_get_ex \
           json_object_new_array json_object_array_length \
           json_object_array_add json_object_array_get_idx \
           json_object_new_int json_object_new_int64 json_object_get_int \
           json_object_get_int64 json_object_new_string \
           json_object_get_string json_object_new_boolean \
           json_object_get_boolean; do
  if ! grep -qE " T ${sym}\$" "$syms"; then
    echo "build-jsonc-wasm: expected symbol $sym not defined in libjson-c.a" >&2
    exit 1
  fi
done
echo "build-jsonc-wasm: required json-c symbols present"
sha256sum "$PREFIX/lib/libjson-c.a"
ls -l "$PREFIX/lib/libjson-c.a"
echo "$PREFIX"
