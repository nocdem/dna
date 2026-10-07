#!/usr/bin/env bash
# Native parity vector for the NODUS send module (web wallet package (c3);
# design docs/plans/2026-09-25-web-wallet-nodus-send-design.md §2, test plan
# item 2). Compiles crypto/nodus-send-native-vector.c with the SAME
# crypto/nodus-send-wasm.c the browser module is built from, in its
# offline-only TEST form:
#   -DNODUS_SEND_OFFLINE_ONLY        no network code (no nodus client, no
#                                    OpenSSL channel crypto, no sockets)
#   -DNODUS_SEND_TEST_FIXED_RANDOM   every random byte is caller-supplied
#                                    (--out-seeds, --sign-random)
# The offline EVM build (0.1.64, `evm` mode) links the shared EVM builder
# nodus/src/client/nodus_v2_evm.c with its call codec
# shared/dnac/evm_call_wire.c and Keccak-256 (the CREATE address).
# A test tool: it is never shipped and never run by this script.
#
# Requires: cc, the host OpenSSL (-lcrypto: shared/crypto/hash/qgp_sha3.c
# hashes through EVP). Output: $NODUS_SEND_VECTOR_BIN
# (default /tmp/nodus-send-native-vector).
set -euo pipefail
cd "$(dirname "$0")/.."
root=..
dsa=$root/shared/crypto/sign/dsa
out="${NODUS_SEND_VECTOR_BIN:-/tmp/nodus-send-native-vector}"

"${CC:-cc}" -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Werror \
  -ffunction-sections -fdata-sections \
  -DNODUS_SEND_OFFLINE_ONLY -DNODUS_SEND_TEST_FIXED_RANDOM \
  -I$root/nodus/include -I$root/nodus/src -I$root/shared -I$root/dnac/include \
  crypto/nodus-send-native-vector.c crypto/nodus-send-wasm.c \
  $root/nodus/src/client/nodus_v2_spend.c \
  $root/nodus/src/client/nodus_v2_stake.c \
  $root/nodus/src/client/nodus_v2_evm.c \
  $root/nodus/src/nodus_log_shim.c \
  $root/shared/dnac/{env_wire,env_preflight,res_meter,effect_wire,manifest_wire,ledger_roots_v2,evm_call_wire}.c \
  $root/shared/crypto/hash/{qgp_sha3,keccak256}.c \
  $root/shared/crypto/utils/{qgp_fingerprint,qgp_random}.c \
  $root/shared/crypto/sign/qgp_dilithium.c \
  "$dsa"/{sign,packing,polyvec,poly,ntt,rounding,reduce,fips202,symmetric-shake}.c \
  -Wl,--gc-sections -lcrypto -o "$out"
echo "$out"
