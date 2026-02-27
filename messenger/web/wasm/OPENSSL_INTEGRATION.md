# OpenSSL Integration for WebAssembly

**Issue:** DNA Messenger's C library requires OpenSSL (specifically libcrypto) for AES-256-GCM encryption, but Emscripten doesn't include OpenSSL by default.

**Status:** Requires additional configuration

**Note:** This document was last reviewed October 2025. WASM/Web Messenger is Phase 8 (planned, not in active development).

---

## Problem

The `qgp_aes.c` file uses OpenSSL EVP API:
- `EVP_CIPHER_CTX_new()` - AES-256-GCM context
- `EVP_EncryptInit_ex()` - Initialize encryption
- `EVP_EncryptUpdate()` - Encrypt data with AAD
- `EVP_CIPHER_CTX_ctrl()` - Get/set GCM tag

Build error:
```
qgp_aes.c:11:10: fatal error: 'openssl/evp.h' file not found
```

---

## Solution Options

### Option 1: Use Emscripten Ports (OpenSSL) ⭐ RECOMMENDED

Emscripten has a port system that can compile OpenSSL for WebAssembly.

**Update build_wasm.sh:**
```bash
EMCC_FLAGS="-O3 \
  -s WASM=1 \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s USE_ZLIB=1 \
  -I/opt/emsdk/upstream/emscripten/cache/sysroot/include \
  ..."

# Link with OpenSSL
emcc $EMCC_FLAGS $INCLUDES $ALL_SOURCES \
  -lssl -lcrypto \
  -o ${OUTPUT_DIR}/dna_wasm.js
```

**Test:**
```bash
cd /opt/dna-messenger/web/wasm
./build_wasm.sh
```

---

### Option 2: Compile OpenSSL Manually for WASM

More control but significantly more complex.

**Steps:**
1. Download OpenSSL source
2. Configure for wasm32-unknown-emscripten target
3. Compile with emcc
4. Link static libraries

**Not recommended** due to complexity and maintenance burden.

---

### Option 3: Replace OpenSSL with WebCrypto API

Rewrite `qgp_aes.c` to use browser's WebCrypto API instead of OpenSSL.

**Pros:**
- No external dependencies
- Native browser crypto (potentially faster)
- Smaller WASM bundle

**Cons:**
- Requires rewriting C code
- Async API (WebCrypto is promise-based)
- Breaking change to existing code

**Not recommended** - would require significant refactoring of the entire codebase.

---

### Option 4: Use BoringSSL (Google's OpenSSL fork)

BoringSSL is designed to be more embeddable and may work better with Emscripten.

**Status:** Experimental, needs testing

---

## Implementation Plan (Option 1)

### Step 1: Update Build Script

```bash
# In build_wasm.sh, update EMCC_FLAGS:

EMCC_FLAGS="-O3 \
  -s WASM=1 \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_FUNCTIONS='[\"_malloc\",\"_free\",\"_dna_encrypt_message_raw\",\"_dna_decrypt_message_raw\"]' \
  -s EXPORTED_RUNTIME_METHODS='[\"ccall\",\"cwrap\",\"getValue\",\"setValue\",\"HEAPU8\"]' \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='DNAModule' \
  -s USE_ZLIB=1 \
  -fno-unroll-loops \
  -fno-vectorize \
  -Wno-unused-command-line-argument"

# Link command:
emcc $EMCC_FLAGS $INCLUDES $ALL_SOURCES \
  -lcrypto \
  -o ${OUTPUT_DIR}/dna_wasm.js
```

### Step 2: Test Build

```bash
cd /opt/dna-messenger/web/wasm
source /opt/emsdk/emsdk_env.sh
./build_wasm.sh
```

Expected output:
```
✅ Build successful!
📄 Output files:
-rw-rw-r-- 1 nocdem nocdem 1.5M dna_wasm.wasm
-rw-rw-r-- 1 nocdem nocdem 89K dna_wasm.js
```

### Step 3: Verify OpenSSL Symbols

```bash
# Check if OpenSSL symbols are present
wasm-objdump -x dna_wasm.wasm | grep EVP_
```

Should show:
```
EVP_CIPHER_CTX_new
EVP_EncryptInit_ex
EVP_EncryptUpdate
EVP_DecryptInit_ex
...
```

---

## Current Status

**Completed:**
- ✅ Emscripten SDK installed (v4.0.16)
- ✅ Build script created
- ✅ Source files identified
- ✅ Build process tested (failed due to OpenSSL)

**Next Steps:**
1. Update `build_wasm.sh` with OpenSSL linking flags
2. Run build script
3. Verify WASM module size (target: < 2MB)
4. Create JavaScript wrapper API
5. Test encryption/decryption in Node.js

---

## Alternative: Minimal WASM Build (No OpenSSL)

If OpenSSL proves too difficult, we can build a minimal WASM module with only PQ crypto (Kyber + Dilithium) and handle AES on the server-side.

**Trade-off:** Reduced security (server sees unencrypted data temporarily)

**Not recommended** - defeats purpose of end-to-end encryption.

---

## Resources

- Emscripten Ports: https://emscripten.org/docs/compiling/Building-Projects.html#emscripten-ports
- OpenSSL WASM: https://github.com/emscripten-core/emscripten/tree/main/test/third_party
- WebCrypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

---

**Last Updated:** 2025-10-15
**Status:** OpenSSL integration required for WASM build
**Next Action:** Update build script with `-lcrypto` flag and test
