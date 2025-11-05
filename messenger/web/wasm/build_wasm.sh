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
  -I${SRC_DIR}/crypto/kem \
  -I${SRC_DIR}/crypto/dsa"

# Core source files
CORE_SOURCES="${SRC_DIR}/dna_api.c \
  ${SRC_DIR}/qgp_aes.c \
  ${SRC_DIR}/qgp_kyber.c \
  ${SRC_DIR}/qgp_dilithium.c \
  ${SRC_DIR}/qgp_random.c \
  ${SRC_DIR}/qgp_key.c \
  ${SRC_DIR}/aes_keywrap.c \
  ${SRC_DIR}/armor.c"

# KEM sources (ML-KEM-1024) - exclude test files
KYBER_SOURCES="${SRC_DIR}/crypto/kem/cbd.c \
  ${SRC_DIR}/crypto/kem/indcpa.c \
  ${SRC_DIR}/crypto/kem/kem.c \
  ${SRC_DIR}/crypto/kem/ntt_kyber.c \
  ${SRC_DIR}/crypto/kem/poly_kyber.c \
  ${SRC_DIR}/crypto/kem/polyvec.c \
  ${SRC_DIR}/crypto/kem/reduce_kyber.c \
  ${SRC_DIR}/crypto/kem/verify.c \
  ${SRC_DIR}/crypto/kem/fips202_kyber.c \
  ${SRC_DIR}/crypto/kem/symmetric-shake.c"

# DSA sources (ML-DSA-87) - exclude test files
DILITHIUM_SOURCES="${SRC_DIR}/crypto/dsa/sign.c \
  ${SRC_DIR}/crypto/dsa/packing.c \
  ${SRC_DIR}/crypto/dsa/polyvec.c \
  ${SRC_DIR}/crypto/dsa/poly.c \
  ${SRC_DIR}/crypto/dsa/ntt.c \
  ${SRC_DIR}/crypto/dsa/rounding.c \
  ${SRC_DIR}/crypto/dsa/reduce.c \
  ${SRC_DIR}/crypto/dsa/fips202.c \
  ${SRC_DIR}/crypto/dsa/symmetric-shake.c"

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
