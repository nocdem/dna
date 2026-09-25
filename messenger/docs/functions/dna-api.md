# DNA API Functions

**File:** `messenger/dna_api.h` (legacy standalone API; primary UI/FFI path is `include/dna/dna_engine.h` — see [public-api.md](public-api.md))

Low-level cryptographic API for message encryption/decryption with post-quantum algorithms. Kept for direct-library consumers (CLI, tests, DB integration). New features should be added to the engine modular handler pattern, not here.

---

## 2.1 Version & Error Handling

| Function | Description |
|----------|-------------|
| `const char* dna_version(void)` | Get library version string |
| `const char* dna_error_string(dna_error_t error)` | Get human-readable error message |

## 2.2 Context Management

| Function | Description |
|----------|-------------|
| `dna_context_t* dna_context_new(void)` | Create new DNA context |
| `void dna_context_free(dna_context_t *ctx)` | Free DNA context and all resources |

## 2.3 Buffer Management

| Function | Description |
|----------|-------------|
| `dna_buffer_t dna_buffer_new(size_t size)` | Allocate new buffer |
| `void dna_buffer_free(dna_buffer_t *buffer)` | Free buffer data (secure wipe) |

## 2.4 Message Encryption

| Function | Description |
|----------|-------------|
| `dna_error_t dna_encrypt_message_raw(...)` | Encrypt message with raw keys (for DB integration). Thin wrapper over `dna_encrypt_message_raw_alg(..., NULL, ...)` — always round-3 (KEM Faz 1, R7) |
| `dna_error_t dna_encrypt_message_raw_alg(dna_context_t*, const uint8_t*, size_t, const uint8_t *recipient_enc_pubkey, const uint8_t *sender_sign_pubkey, const uint8_t *sender_sign_privkey, uint64_t, uint8_t enc_key_type, uint8_t**, size_t*)` | **NEW (KEM Faz 1, R7).** `enc_key_type` selects the algorithm and is written into the header: `QGP_KEY_TYPE_KEM1024` (2, round-3) or `QGP_KEY_TYPE_MLKEM1024` (3, ML-KEM-1024) — `recipient_enc_pubkey` must match that algorithm's key |

<!-- NOTE: dna_encrypt_message() removed in v0.3.150 - used broken keyring stubs -->

## 2.5 Message Decryption

| Function | Description |
|----------|-------------|
| `dna_error_t dna_decrypt_message_raw(...)` | Decrypt message with raw keys (v0.08: returns sender timestamp). Thin wrapper over `dna_decrypt_message_raw_alg(..., NULL, ...)`. **CHANGED (D14, M1 delta 1):** restores the pre-KEM-Faz-1 `DNA_ERROR_INVALID_ARG` when `recipient_enc_privkey` is NULL — checked in THIS wrapper before delegating, so this specific caller contract is unaffected by `_alg`'s own (different, and correct for ITS callers) `DNA_ERROR_DECRYPT`-on-NULL behavior below |
| `dna_error_t dna_decrypt_message_raw_alg(dna_context_t*, const uint8_t*, size_t, const uint8_t *recipient_enc_privkey, const uint8_t *recipient_mlkem_privkey, uint8_t**, size_t*, uint8_t**, size_t*, uint8_t**, size_t*, uint64_t*)` | **NEW (KEM Faz 1, R7).** Validates `header.enc_key_type` (round-3 or ML-KEM-1024 only, else `DNA_ERROR_DECRYPT`) and requires the matching key parameter be non-NULL for that type (round-3 needs `recipient_enc_privkey`; ML-KEM needs `recipient_mlkem_privkey`) — else `DNA_ERROR_DECRYPT` (this function's own NULL-key case is a decrypt-time fact, not a caller error, unlike the `dna_decrypt_message_raw` wrapper above) |

<!-- NOTE: dna_decrypt_message() removed in v0.3.150 - used broken keyring stubs -->

## 2.6 Signature Operations

| Function | Description |
|----------|-------------|
| `dna_error_t dna_sign_message(...)` | Sign message with Dilithium5 |
| `dna_error_t dna_verify_message(...)` | Verify message signature |

## 2.7 Key Management

<!-- NOTE: dna_load_key() and dna_load_pubkey() removed in v0.3.150 - used broken keyring stubs -->
<!-- Keys are now managed through dna_engine identity system -->

## 2.8 Utility Functions

| Function | Description |
|----------|-------------|
| `dna_error_t dna_key_fingerprint(...)` | Get key fingerprint (SHA256) |
| `dna_error_t dna_fingerprint_to_hex(...)` | Convert fingerprint to hex string |

## 2.9 Group Messaging (GEK)

| Function | Description |
|----------|-------------|
| `dna_error_t dna_encrypt_message_gek(...)` | Encrypt message with Group Symmetric Key |
| `dna_error_t dna_decrypt_message_gek(...)` | Decrypt GEK-encrypted message |
