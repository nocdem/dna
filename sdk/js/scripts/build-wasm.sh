#!/usr/bin/env bash
# Builds the node-environment send module the SDK loads, by running the web
# wallet's own build script in its `parity` mode — the SAME C sources, the
# SAME link settings, the SAME pinned toolchain (Emscripten 6.0.10). Nothing
# is forked: every source list, flag and toolchain check lives in
# web-wallet/scripts/build-nodus-send-wasm.sh.
#
# Output (gitignored): sdk/js/wasm/
#   send-node.mjs + send-node.wasm            release C flags (-DNODUS_SEND_RELEASE)
#                                             — the ONLY build the SDK loads
#   send-test-node.mjs + send-test-node.wasm  -DNODUS_SEND_TEST_FIXED_RANDOM;
#                                             written by the same parity mode,
#                                             never loaded by the SDK
#
# Requirements: those of the wallet script (its header): EMSDK (default
# ~/emsdk), OPENSSL_WASM_PREFIX (default ~/wasm-deps/openssl-3.0.15-wasm),
# JSONC_WASM_PREFIX (default ~/wasm-deps/json-c-0.17-wasm), SQLITE3_H
# (default /usr/include/sqlite3.h).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd -P)"      # sdk/js/
repo="$(cd "$here/../.." && pwd -P)"
mkdir -p "$here/wasm"
NODUS_SEND_PARITY_OUT="$here/wasm" bash "$repo/web-wallet/scripts/build-nodus-send-wasm.sh" parity
for f in send-node.mjs send-node.wasm; do
  if [ ! -f "$here/wasm/$f" ]; then
    echo "build-wasm: $here/wasm/$f was not produced" >&2
    exit 1
  fi
done
sha256sum "$here/wasm/send-node.wasm" "$here/wasm/send-node.mjs"
