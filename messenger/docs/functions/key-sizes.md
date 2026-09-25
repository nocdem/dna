# Key Sizes Reference

**Last verified:** 2026-04-24 against `shared/crypto/` headers. Values are cryptographic-spec constants; verify during any crypto upgrade.

Quick reference for cryptographic algorithm key and component sizes.

---

## Post-Quantum Algorithms

| Algorithm | Component | Size (bytes) | Notes |
|-----------|-----------|--------------|-------|
| **Kyber1024 (round-3, legacy)** | Public Key | 1568 | `qgp_kyber.h` — same bytes as ML-KEM-1024; the two are NOT interoperable |
| **Kyber1024 (round-3, legacy)** | Private Key | 3168 | `qgp_kyber.h` |
| **Kyber1024 (round-3, legacy)** | Ciphertext | 1568 | KEM encapsulation |
| **Kyber1024 (round-3, legacy)** | Shared Secret | 32 | 256-bit symmetric key |
| **ML-KEM-1024 (FIPS 203)** | Encapsulation Key (ek) | 1568 | `qgp_mlkem.h` — **CHANGED (KEM Faz 1, M1, grep-verified 2026-09-23):** now has direct callers of `qgp_mlkem1024_*` in `dna_profile.c` (ek_check at record intake, D9), `dna_api.c` (encrypt/decrypt raw_alg), `messenger/gek.c` (IKP v3, GEK rotation), `messenger/keygen.c` (dual-key creation/migration), `messenger/messages.c` (multi-recipient Seal gate), `src/api/engine/dna_engine_calls.c` (call ephemeral/static KEM), `src/api/engine/dna_engine_identity.c` (migration keypair derivation), `shared/crypto/key/seed_storage.c` (`mnemonic_storage_save_v2`/`_load_v2` encapsulate/decapsulate), `nodus/src/crypto/nodus_identity.c` + `nodus/src/server/nodus_auth.c` + `nodus/src/client/nodus_client.c` (nodus package N1: identity keypair, KEY_INIT decapsulation, client encapsulation) |
| **ML-KEM-1024 (FIPS 203)** | Decapsulation Key (dk) | 3168 | `qgp_mlkem.h` |
| **ML-KEM-1024 (FIPS 203)** | Ciphertext | 1568 | |
| **ML-KEM-1024 (FIPS 203)** | Shared Secret | 32 | |
| **ML-KEM-1024 (FIPS 203)** | KeyGen coins (d ‖ z) | 64 | `QGP_MLKEM1024_COINS_BYTES` |
| **Dilithium5** | Public Key | 2592 | ML-DSA-87 |
| **Dilithium5** | Private Key | 4896 | ML-DSA-87 |
| **Dilithium5** | Signature | 4627 | Variable (max 4627) |

## Symmetric Cryptography

| Algorithm | Component | Size (bytes) | Notes |
|-----------|-----------|--------------|-------|
| **AES-256-GCM** | Key | 32 | 256-bit |
| **AES-256-GCM** | Nonce | 12 | 96-bit |
| **AES-256-GCM** | Tag | 16 | 128-bit auth tag |

## Hash Functions

| Algorithm | Component | Size (bytes) | Notes |
|-----------|-----------|--------------|-------|
| **SHA3-512** | Hash | 64 | Fingerprint |
| **SHA3-256** | Hash | 32 | General hashing |

## Key Derivation

| Algorithm | Component | Size (bytes) | Notes |
|-----------|-----------|--------------|-------|
| **BIP39** | Master Seed | 64 | 512-bit |
| **BIP39** | Entropy | 32 | 256-bit (24 words) |

## Classical Algorithms (Blockchain)

| Algorithm | Component | Size (bytes) | Notes |
|-----------|-----------|--------------|-------|
| **Ed25519** | Private Key | 32 | Solana |
| **Ed25519** | Public Key | 32 | Solana |
| **Ed25519** | Signature | 64 | Solana |
| **secp256k1** | Private Key | 32 | ETH/TRON |
| **secp256k1** | Public Key | 65 | Uncompressed |
| **secp256k1** | Signature | 65 | Recoverable (r,s,v) |
