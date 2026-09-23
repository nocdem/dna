#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
src=../shared/crypto/sign/cellframe_dilithium
cc -O2 -ffunction-sections -fdata-sections -I../shared -I../messenger/blockchain/cellframe \
 crypto/native-vector.c ../messenger/blockchain/cellframe/{cellframe_wallet_create,cellframe_addr}.c \
 ../shared/crypto/utils/base58.c "$src"/{dilithium_params,dilithium_packing,dilithium_poly,dilithium_polyvec,dilithium_rounding_reduce,dilithium_sign,fips202,dna_compat}.c \
 -Wl,--gc-sections -lcrypto -o "${CPUNK_VECTOR_BIN:-/tmp/nodus-cpunk-native-vector}"
