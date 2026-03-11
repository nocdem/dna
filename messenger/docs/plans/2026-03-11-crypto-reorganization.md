# Crypto Directory Reorganization Plan

**Date:** 2026-03-11
**Status:** APPROVED — Ready for execution
**Goal:** Reorganize `shared/crypto/` into 4 semantic categories: `sign/`, `enc/`, `hash/`, `key/`
**Also:** Extract secp256k1 and Ed25519 signing into shared utilities (eliminate duplicate code)

---

## Current Structure

```
shared/crypto/
├── bip32/                 ← key derivation (standalone)
├── bip39/                 ← mnemonic seed (standalone)
├── cellframe_dilithium/   ← Cellframe Dilithium fork (signing)
├── dsa/                   ← Dilithium5 NIST reference impl (signing)
├── kem/                   ← Kyber1024 NIST reference impl (encryption)
└── utils/                 ← EVERYTHING ELSE (35 files mixed together)
    ├── qgp_dilithium.c/h     (signing wrapper)
    ├── qgp_signature.c       (signing utility)
    ├── qgp_kyber.c/h         (encryption wrapper)
    ├── qgp_aes.c/h           (encryption)
    ├── aes_keywrap.c/h       (encryption)
    ├── key_encryption.c/h    (key management)
    ├── seed_storage.c/h      (key management)
    ├── qgp_key.c             (key management)
    ├── qgp_sha3.c/h          (hashing)
    ├── keccak256.c/h          (hashing)
    ├── kyber_deterministic.c/h (encryption helper)
    ├── qgp_log.c/h            (infra)
    ├── qgp_random.c/h         (infra)
    ├── qgp_platform*.c/h      (infra)
    ├── qgp_types.h            (infra)
    ├── qgp_compiler.h         (infra)
    ├── base58.c/h             (encoding)
    ├── armor.c                (encoding)
    ├── threadpool.c/h         (infra)
    └── qgp_utils_standalone.c (infra)
```

## Target Structure

```
shared/crypto/
│
├── sign/                              ← ALL SIGNING
│   ├── dsa/                           ← Dilithium5 reference impl (MOVED from crypto/dsa/)
│   ├── cellframe_dilithium/           ← Cellframe fork (MOVED from crypto/cellframe_dilithium/)
│   ├── qgp_dilithium.c/h             ← Dilithium5 wrapper (MOVED from utils/)
│   ├── qgp_signature.c               ← Signature utilities (MOVED from utils/)
│   ├── secp256k1_sign.c/h            ← NEW — secp256k1 ECDSA (ETH/TRON/EIP-712)
│   └── ed25519_sign.c/h              ← NEW — Ed25519 (Solana)
│
├── enc/                               ← ALL ENCRYPTION
│   ├── kem/                           ← Kyber1024 reference impl (MOVED from crypto/kem/)
│   ├── qgp_kyber.c/h                 ← Kyber wrapper (MOVED from utils/)
│   ├── qgp_aes.c/h                   ← AES-256-GCM (MOVED from utils/)
│   ├── aes_keywrap.c/h               ← AES Key Wrap (MOVED from utils/)
│   └── kyber_deterministic.c/h        ← Deterministic KEM helper (MOVED from utils/)
│
├── hash/                              ← ALL HASHING
│   ├── qgp_sha3.c/h                  ← SHA3-512 (MOVED from utils/)
│   └── keccak256.c/h                  ← Keccak-256 Ethereum hash (MOVED from utils/)
│
├── key/                               ← KEY MANAGEMENT
│   ├── bip32/                         ← HD key derivation (MOVED from crypto/bip32/)
│   ├── bip39/                         ← Mnemonic seed (MOVED from crypto/bip39/)
│   ├── qgp_key.c                     ← Key load/save (MOVED from utils/)
│   ├── key_encryption.c/h            ← PBKDF2 + AES key encryption (MOVED from utils/)
│   └── seed_storage.c/h              ← Kyber KEM seed storage (MOVED from utils/)
│
└── utils/                             ← INFRA / PLATFORM / ENCODING (stays)
    ├── qgp_log.c/h
    ├── qgp_random.c/h
    ├── qgp_platform.h
    ├── qgp_platform_linux.c
    ├── qgp_platform_windows.c
    ├── qgp_platform_android.c
    ├── qgp_types.h
    ├── qgp_compiler.h
    ├── base58.c/h
    ├── armor.c
    ├── threadpool.c/h
    └── qgp_utils_standalone.c
```

---

## Execution Phases

Execute in 4 phases. **Build ALL 3 projects after each phase** to catch errors immediately.

Build commands:
```bash
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
cd /opt/dna/dnac/build && cmake .. && make -j$(nproc)
```

### Phase 1: hash/ (lowest risk, fewest dependencies)

**Create directory:** `shared/crypto/hash/`

**Move files:**
| File | From | To |
|------|------|----|
| `qgp_sha3.c` | `crypto/utils/` | `crypto/hash/` |
| `qgp_sha3.h` | `crypto/utils/` | `crypto/hash/` |
| `keccak256.c` | `crypto/utils/` | `crypto/hash/` |
| `keccak256.h` | `crypto/utils/` | `crypto/hash/` |

**Include path changes:**
| Old | New | File count |
|-----|-----|-----------|
| `crypto/utils/qgp_sha3.h` | `crypto/hash/qgp_sha3.h` | 41 files |
| `crypto/utils/keccak256.h` | `crypto/hash/keccak256.h` | 5 files |

**CMakeLists.txt changes:**
- messenger/CMakeLists.txt: Update `qgp_sha3.c` and `keccak256.c` paths (3 occurrences)
- nodus/CMakeLists.txt: Update `qgp_sha3.c` path (1 occurrence)
- dnac/CMakeLists.txt: No direct reference (uses include dir)

**Internal includes to update:**
- `qgp_sha3.c` includes itself via `crypto/utils/qgp_sha3.h` → `crypto/hash/qgp_sha3.h`
- `qgp_aes.c` (still in utils/) includes `qgp_sha3.h` — NO, it doesn't. Check needed.
- Many files across messenger/nodus/dnac include `qgp_sha3.h`

**BUILD & VERIFY after Phase 1**

---

### Phase 2: sign/ (medium risk, new files + moves)

**Create directory:** `shared/crypto/sign/`

**Move files:**
| File | From | To |
|------|------|----|
| `qgp_dilithium.c` | `crypto/utils/` | `crypto/sign/` |
| `qgp_dilithium.h` | `crypto/utils/` | `crypto/sign/` |
| `qgp_signature.c` | `crypto/utils/` | `crypto/sign/` |
| `dsa/` (entire dir) | `crypto/dsa/` | `crypto/sign/dsa/` |
| `cellframe_dilithium/` (entire dir) | `crypto/cellframe_dilithium/` | `crypto/sign/cellframe_dilithium/` |

**Create NEW files:**
| File | Description |
|------|-------------|
| `crypto/sign/secp256k1_sign.c` | secp256k1 ECDSA recoverable signing utility |
| `crypto/sign/secp256k1_sign.h` | Header for above |
| `crypto/sign/ed25519_sign.c` | Ed25519 signing utility (extracted from sol_wallet.c) |
| `crypto/sign/ed25519_sign.h` | Header for above |

**secp256k1_sign.h API:**
```c
#ifndef SECP256K1_SIGN_H
#define SECP256K1_SIGN_H
#include <stdint.h>

/**
 * Sign a 32-byte hash with secp256k1 ECDSA (recoverable).
 *
 * Output: sig_out = r(32) + s(32) + v(1) where v = 27 + recovery_id
 * For EIP-155 (ETH TX): caller uses recovery_id_out to compute v = recovery_id + chainId*2 + 35
 * For TRON/EIP-712: sig_out[65] is ready to use directly (v = 27 + recovery_id)
 *
 * @param private_key      32-byte private key
 * @param hash             32-byte hash to sign
 * @param sig_out          Output: 65 bytes (r + s + v)
 * @param recovery_id_out  Output: raw recovery_id (0 or 1). Pass NULL if not needed.
 * @return                 0 on success, -1 on error
 */
int secp256k1_sign_hash(
    const uint8_t private_key[32],
    const uint8_t hash[32],
    uint8_t sig_out[65],
    int *recovery_id_out
);

#endif
```

**ed25519_sign.h API:**
```c
#ifndef ED25519_SIGN_H
#define ED25519_SIGN_H
#include <stdint.h>
#include <stddef.h>

/**
 * Sign message with Ed25519 (OpenSSL EVP).
 *
 * @param private_key  32-byte Ed25519 private key (seed)
 * @param message      Message bytes to sign
 * @param message_len  Message length
 * @param sig_out      Output: 64-byte Ed25519 signature
 * @return             0 on success, -1 on error
 */
int ed25519_sign(
    const uint8_t private_key[32],
    const uint8_t *message,
    size_t message_len,
    uint8_t sig_out[64]
);

/**
 * Derive Ed25519 public key from private key.
 *
 * @param private_key  32-byte Ed25519 private key
 * @param pubkey_out   Output: 32-byte public key
 * @return             0 on success, -1 on error
 */
int ed25519_pubkey_from_private(
    const uint8_t private_key[32],
    uint8_t pubkey_out[32]
);

#endif
```

**Include path changes:**
| Old | New | File count |
|-----|-----|-----------|
| `crypto/utils/qgp_dilithium.h` | `crypto/sign/qgp_dilithium.h` | 27 files |
| `crypto/cellframe_dilithium/cellframe_dilithium_api.h` | `crypto/sign/cellframe_dilithium/cellframe_dilithium_api.h` | 2 files |
| `crypto/cellframe_dilithium/dilithium_params.h` | `crypto/sign/cellframe_dilithium/dilithium_params.h` | 1 file |
| `crypto/dsa/api.h` (internal) | `crypto/sign/dsa/api.h` | 2 files (qgp_dilithium.c + 1 other) |
| `crypto/dsa/*` (internal) | `crypto/sign/dsa/*` | 2 files total |
| `crypto/kem/*` → NO, that's enc phase | — | — |

**Internal includes to update within moved files:**
- `qgp_dilithium.c`: includes `crypto/utils/qgp_dilithium.h` → `crypto/sign/qgp_dilithium.h`
- `qgp_dilithium.c`: includes `crypto/dsa/api.h` etc → `crypto/sign/dsa/api.h` etc (6 includes)
- `qgp_signature.c`: includes `crypto/utils/qgp_types.h` → stays (utils/ not moving)
- `qgp_signature.c`: includes `crypto/utils/qgp_log.h` → stays (utils/ not moving)

**Refactor callers to use new sign utilities:**
- `eth_tx.c`: Replace inline secp256k1 block (~20 lines) with `secp256k1_sign_hash()` call. Use `recovery_id_out` for EIP-155 v. Remove `#include <secp256k1.h>` and `<secp256k1_recovery.h>`.
- `trx_tx.c`: Replace inline secp256k1 block (~20 lines) with `secp256k1_sign_hash()` call. sig_out ready to use. Remove secp256k1 includes.
- `eth_eip712.c`: Replace inline secp256k1 block (~15 lines) with `secp256k1_sign_hash()` call. Remove secp256k1 includes.
- `sol_wallet.c`: Replace `sol_sign_message()` body with `ed25519_sign()` call. Replace `ed25519_pubkey_from_private()` static with shared version. Remove OpenSSL EVP includes if no longer needed (check: SLIP-10 derivation still uses HMAC).

**CMakeLists.txt changes:**
- messenger: Update `qgp_dilithium.c`, `qgp_signature.c` paths. Add `secp256k1_sign.c`, `ed25519_sign.c`. Update `add_subdirectory` for dsa and cellframe_dilithium.
- nodus: Update `qgp_dilithium.c` path. Update `add_subdirectory` for dsa.
- dnac: Uses include dir, but check if any direct source refs exist.

**BUILD & VERIFY after Phase 2**

---

### Phase 3: enc/ (medium risk)

**Create directory:** `shared/crypto/enc/`

**Move files:**
| File | From | To |
|------|------|----|
| `qgp_kyber.c` | `crypto/utils/` | `crypto/enc/` |
| `qgp_kyber.h` | `crypto/utils/` | `crypto/enc/` |
| `qgp_aes.c` | `crypto/utils/` | `crypto/enc/` |
| `qgp_aes.h` | `crypto/utils/` | `crypto/enc/` |
| `aes_keywrap.c` | `crypto/utils/` | `crypto/enc/` |
| `aes_keywrap.h` | `crypto/utils/` | `crypto/enc/` |
| `kyber_deterministic.c` | `crypto/utils/` | `crypto/enc/` |
| `kyber_deterministic.h` | `crypto/utils/` | `crypto/enc/` |
| `kem/` (entire dir) | `crypto/kem/` | `crypto/enc/kem/` |

**Include path changes:**
| Old | New | File count |
|-----|-----|-----------|
| `crypto/utils/qgp_kyber.h` | `crypto/enc/qgp_kyber.h` | 13 files |
| `crypto/utils/qgp_aes.h` | `crypto/enc/qgp_aes.h` | 7 files |
| `crypto/utils/aes_keywrap.h` | `crypto/enc/aes_keywrap.h` | 4 files |
| `crypto/utils/kyber_deterministic.h` | `crypto/enc/kyber_deterministic.h` | 2 files |
| `crypto/kem/kem.h` (internal) | `crypto/enc/kem/kem.h` | 3 files |
| `crypto/kem/*` (internal) | `crypto/enc/kem/*` | 3 files |

**Internal includes to update within moved files:**
- `qgp_kyber.c`: includes `crypto/utils/qgp_kyber.h` → `crypto/enc/qgp_kyber.h`
- `qgp_kyber.c`: includes `crypto/kem/kem.h` → `crypto/enc/kem/kem.h`
- `qgp_aes.c`: includes `crypto/utils/qgp_aes.h` → `crypto/enc/qgp_aes.h`
- `qgp_aes.c`: includes `crypto/utils/qgp_random.h` → stays (utils/)
- `qgp_aes.c`: includes `crypto/utils/qgp_log.h` → stays (utils/)
- `kyber_deterministic.c`: includes `crypto/kem/*` → `crypto/enc/kem/*` (7 includes)
- `seed_storage.c` (moving in Phase 4): includes `qgp_kyber.h` and `qgp_aes.h` — use relative or new paths

**CMakeLists.txt changes:**
- messenger: Update `qgp_kyber.c`, `qgp_aes.c`, `aes_keywrap.c`, `kyber_deterministic.c` paths. Update `add_subdirectory` for kem.
- nodus: Update `add_subdirectory` for kem (if standalone).
- dnac: Check.

**BUILD & VERIFY after Phase 3**

---

### Phase 4: key/ (low risk, few files)

**Create directory:** `shared/crypto/key/`

**Move files:**
| File | From | To |
|------|------|----|
| `qgp_key.c` | `crypto/utils/` | `crypto/key/` |
| `key_encryption.c` | `crypto/utils/` | `crypto/key/` |
| `key_encryption.h` | `crypto/utils/` | `crypto/key/` |
| `seed_storage.c` | `crypto/utils/` | `crypto/key/` |
| `seed_storage.h` | `crypto/utils/` | `crypto/key/` |
| `bip32/` (entire dir) | `crypto/bip32/` | `crypto/key/bip32/` |
| `bip39/` (entire dir) | `crypto/bip39/` | `crypto/key/bip39/` |

**Include path changes:**
| Old | New | File count |
|-----|-----|-----------|
| `crypto/utils/key_encryption.h` | `crypto/key/key_encryption.h` | 5 files |
| `crypto/utils/seed_storage.h` | `crypto/key/seed_storage.h` | 4 files |
| `crypto/bip32/bip32.h` | `crypto/key/bip32/bip32.h` | 3 files |
| `crypto/bip39/bip39.h` | `crypto/key/bip39/bip39.h` | 6 files |

**Internal includes to update:**
- `qgp_key.c`: includes `crypto/utils/key_encryption.h` → `crypto/key/key_encryption.h`
- `qgp_key.c`: includes `crypto/utils/qgp_types.h` → stays (utils/)
- `seed_storage.c`: includes `qgp_kyber.h` → needs `crypto/enc/qgp_kyber.h` (moved in Phase 3)
- `seed_storage.c`: includes `qgp_aes.h` → needs `crypto/enc/qgp_aes.h` (moved in Phase 3)
- `bip39/bip39.c` and `bip39/bip39_pbkdf2.c`: check internal includes

**CMakeLists.txt changes:**
- messenger: Update `qgp_key.c`, `key_encryption.c`, `seed_storage.c`, bip32, bip39 paths.
- nodus: Likely no changes (doesn't use key/ files).
- dnac: Check.

**BUILD & VERIFY after Phase 4**

---

## Post-Completion

### Version Bump
- C Library: version.h PATCH bump (v0.9.42 → v0.9.43)
- Nodus: nodus_types.h PATCH bump IF nodus CMakeLists changed
- No Flutter bump (no Dart changes)

### Documentation Updates
- `messenger/docs/ARCHITECTURE_DETAILED.md` — Update crypto directory layout
- `messenger/docs/functions/blockchain.md` — Add secp256k1_sign_hash, ed25519_sign entries
- `messenger/docs/functions/crypto.md` — Update file locations
- `CLAUDE.md` (both root and messenger) — Update shared crypto section

### Commit
Single commit with all changes:
```
refactor: reorganize shared/crypto/ into sign/enc/hash/key (v0.9.43)
```

---

## Risk Mitigation

1. **Build after each phase** — catch errors immediately
2. **Use Edit tool only** — no sed/find-replace, each include updated individually
3. **Internal includes first** — update moved files' own includes before updating callers
4. **Don't rename files** — only move them. File names stay the same.
5. **git mv** — use git mv for moves so git tracks the rename history

## File Count Summary

| Action | Count |
|--------|-------|
| New files created | 4 (secp256k1_sign.c/h, ed25519_sign.c/h) |
| Files moved | ~30 (includes entire dsa/, kem/, cellframe_dilithium/, bip32/, bip39/ dirs) |
| Include updates | ~125 (across messenger, nodus, dnac) |
| CMakeLists.txt updates | 3 (messenger, nodus, dnac) |
| Callers refactored | 4 (eth_tx.c, trx_tx.c, eth_eip712.c, sol_wallet.c) |

## Notes

- `qgp_types.h` stays in `utils/` — it defines types used everywhere
- `qgp_log.h` stays in `utils/` — logging infrastructure
- `qgp_random.h` stays in `utils/` — CSPRNG used by both sign and enc
- `qgp_platform*.c` stays in `utils/` — platform abstraction
- `base58.c/h` stays in `utils/` — encoding utility
- Files that include from BOTH old and new paths (e.g., `seed_storage.c` includes both `qgp_kyber.h` from enc/ and `qgp_platform.h` from utils/) — this is fine, cross-directory includes work because `-I shared/` is set
- `sol_wallet.c` still needs OpenSSL for SLIP-10 HMAC derivation even after Ed25519 extraction — don't remove all OpenSSL includes, only remove EVP signing imports if they become unused
