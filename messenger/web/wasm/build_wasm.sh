#!/bin/bash
set -e

echo "🔨 Building DNA Messenger WebAssembly Module..."

# Source Emscripten environment
source /opt/emsdk/emsdk_env.sh > /dev/null 2>&1

# Output directory
OUTPUT_DIR="."
SRC_DIR="../.."

# Compile flags
EMCC_FLAGS="-O3 \
  -s WASM=1 \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_FUNCTIONS='[\"_malloc\",\"_free\",\"_dna_encrypt_message_raw\",\"_dna_decrypt_message_raw\"]' \
  -s EXPORTED_RUNTIME_METHODS='[\"ccall\",\"cwrap\",\"getValue\",\"setValue\",\"HEAPU8\"]' \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='DNAModule' \
  -fno-unroll-loops \
  -fno-vectorize \
  -Wno-unused-command-line-argument"

# Include paths
INCLUDES="-I${SRC_DIR} \
  -I${SRC_DIR}/crypto/kyber512 \
  -I${SRC_DIR}/crypto/dilithium"

# Core source files
CORE_SOURCES="${SRC_DIR}/dna_api.c \
  ${SRC_DIR}/qgp_aes.c \
  ${SRC_DIR}/qgp_kyber.c \
  ${SRC_DIR}/qgp_dilithium.c \
  ${SRC_DIR}/qgp_random.c \
  ${SRC_DIR}/qgp_key.c \
  ${SRC_DIR}/aes_keywrap.c \
  ${SRC_DIR}/armor.c"

# Kyber512 sources (exclude test files)
KYBER_SOURCES="${SRC_DIR}/crypto/kyber512/cbd.c \
  ${SRC_DIR}/crypto/kyber512/indcpa.c \
  ${SRC_DIR}/crypto/kyber512/kem.c \
  ${SRC_DIR}/crypto/kyber512/ntt_kyber.c \
  ${SRC_DIR}/crypto/kyber512/poly_kyber.c \
  ${SRC_DIR}/crypto/kyber512/polyvec.c \
  ${SRC_DIR}/crypto/kyber512/reduce_kyber.c \
  ${SRC_DIR}/crypto/kyber512/verify.c \
  ${SRC_DIR}/crypto/kyber512/fips202_kyber.c \
  ${SRC_DIR}/crypto/kyber512/symmetric-shake.c"

# Dilithium sources (exclude test files)
DILITHIUM_SOURCES="${SRC_DIR}/crypto/dilithium/sign.c \
  ${SRC_DIR}/crypto/dilithium/packing.c \
  ${SRC_DIR}/crypto/dilithium/polyvec.c \
  ${SRC_DIR}/crypto/dilithium/poly.c \
  ${SRC_DIR}/crypto/dilithium/ntt.c \
  ${SRC_DIR}/crypto/dilithium/rounding.c \
  ${SRC_DIR}/crypto/dilithium/reduce.c \
  ${SRC_DIR}/crypto/dilithium/fips202.c \
  ${SRC_DIR}/crypto/dilithium/symmetric-shake.c"

# Combine all sources
ALL_SOURCES="$CORE_SOURCES $KYBER_SOURCES $DILITHIUM_SOURCES"

# Compile
echo "📦 Compiling C sources to WebAssembly..."
emcc $EMCC_FLAGS $INCLUDES $ALL_SOURCES -o ${OUTPUT_DIR}/dna_wasm.js

# Check output
if [ -f "${OUTPUT_DIR}/dna_wasm.js" ] && [ -f "${OUTPUT_DIR}/dna_wasm.wasm" ]; then
    echo "✅ Build successful!"
    echo ""
    echo "📄 Output files:"
    ls -lh ${OUTPUT_DIR}/dna_wasm.js ${OUTPUT_DIR}/dna_wasm.wasm
    echo ""

    WASM_SIZE=$(stat -c%s "${OUTPUT_DIR}/dna_wasm.wasm" 2>/dev/null || stat -f%z "${OUTPUT_DIR}/dna_wasm.wasm" 2>/dev/null)
    WASM_SIZE_MB=$(echo "scale=2; $WASM_SIZE / 1048576" | bc)
    echo "📊 WASM module size: ${WASM_SIZE} bytes (${WASM_SIZE_MB} MB)"

    if (( $(echo "$WASM_SIZE_MB > 2.0" | bc -l) )); then
        echo "⚠️  Warning: WASM module is larger than 2MB"
    else
        echo "✅ WASM module size is acceptable"
    fi
else
    echo "❌ Build failed!"
    exit 1
fi
