#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
src=../shared/crypto/sign/dsa
cc -O2 -ffunction-sections -fdata-sections -I../shared \
  crypto/nodus-native-vector.c ../shared/crypto/key/bip39/{bip39,bip39_pbkdf2,seed_derivation}.c \
  ../shared/crypto/enc/kem/fips202_kyber.c ../shared/crypto/hash/qgp_sha3.c \
  ../shared/crypto/sign/qgp_dilithium.c \
  "$src"/{packing,polyvec,poly,ntt,rounding,reduce,fips202,symmetric-shake}.c \
  -Wl,--gc-sections -lcrypto -o "${NODUS_VECTOR_BIN:-/tmp/nodus-wallet-native-vector}"
