# Key Sizes Reference

Quick reference for cryptographic algorithm key and component sizes.

---

## Post-Quantum Algorithms

| Algorithm | Component | Size (bytes) | Notes |
|-----------|-----------|--------------|-------|
| **Kyber1024** | Public Key | 1568 | ML-KEM-1024 |
| **Kyber1024** | Private Key | 3168 | ML-KEM-1024 |
| **Kyber1024** | Ciphertext | 1568 | KEM encapsulation |
| **Kyber1024** | Shared Secret | 32 | 256-bit symmetric key |
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
