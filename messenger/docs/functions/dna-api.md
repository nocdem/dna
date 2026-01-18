# DNA API Functions

**File:** `dna_api.h`

Low-level cryptographic API for message encryption/decryption with post-quantum algorithms.

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
| `dna_error_t dna_encrypt_message_raw(...)` | Encrypt message with raw keys (for DB integration) |

<!-- NOTE: dna_encrypt_message() removed in v0.3.150 - used broken keyring stubs -->

## 2.5 Message Decryption

| Function | Description |
|----------|-------------|
| `dna_error_t dna_decrypt_message_raw(...)` | Decrypt message with raw keys (v0.08: returns sender timestamp) |

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
