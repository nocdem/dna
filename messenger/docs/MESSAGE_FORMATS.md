# DNA Messenger Message Format Specification

**Version:** 0.08
**Date:** 2025-11-18
**Status:** Production

## Overview

DNA Messenger uses a custom message format with **Category 5 post-quantum cryptography** (Kyber1024 + Dilithium5) for end-to-end encrypted messaging. This document specifies the binary message format for all versions.

---

## Version History

| Version | Date | Changes | Breaking |
|---------|------|---------|----------|
| **0x08** | 2025-11-18 | Encrypted sender timestamp in payload | ✅ Yes |
| **0x07** | 2025-11-18 | Fingerprint privacy: sender FP encrypted, pubkey removed from signature | ✅ Yes |
| **0x06** | 2025-11-04 | Category 5 upgrade: Kyber1024, Dilithium5, SHA3-512 | ✅ Yes |
| **0x05** | 2025-10-23 | Multi-recipient support | No |
| **0x04** | 2025-10-15 | Initial release | N/A |

---

## Message Format v0.08 (Current)

### Binary Structure

```
┌──────────────────────────────────────────────────────────┐
│ Header (20 bytes)                                        │
│  - magic[8]:         "PQSIGENC"                          │
│  - version:          0x08                                │
│  - enc_key_type:     23 (Kyber1024)                      │
│  - recipient_count:  1-255                               │
│  - reserved:         0x00                                │
│  - encrypted_size:   uint32 (network byte order)         │
│  - signature_size:   uint32 (network byte order)         │
├──────────────────────────────────────────────────────────┤
│ Recipients (1608 bytes × N)                              │
│  Per recipient:                                          │
│    - kyber_ciphertext[1568]:  Kyber1024 encapsulation    │
│    - wrapped_dek[40]:         AES-256 key wrap of DEK    │
├──────────────────────────────────────────────────────────┤
│ Nonce (12 bytes)                                         │
│  - Random AES-256-GCM initialization vector              │
├──────────────────────────────────────────────────────────┤
│ Ciphertext (variable = 64 + 8 + plaintext_len)           │
│  AES-256-GCM encrypted:                                  │
│    - sender_fingerprint[64]:  SHA3-512(sender pubkey)    │
│    - timestamp[8]:            uint64 Unix epoch (big-endian) │
│    - plaintext:               Actual message content     │
├──────────────────────────────────────────────────────────┤
│ Tag (16 bytes)                                           │
│  - AES-256-GCM authentication tag                        │
├──────────────────────────────────────────────────────────┤
│ Signature (3 + sig_len bytes, ~4598 bytes total)         │
│  - type (1 byte):      0x01 (Dilithium5)                 │
│  - sig_size (2 bytes): ~4595 (network byte order)        │
│  - signature (var):    Dilithium5 signature bytes        │
└──────────────────────────────────────────────────────────┘
```

### Size Calculation

For a **100-byte plaintext message**:

```
Header:             20 bytes
Recipients (1):   1608 bytes
Nonce:              12 bytes
Ciphertext:        172 bytes  (64 fingerprint + 8 timestamp + 100 plaintext)
Tag:                16 bytes
Signature:        4598 bytes  (type + size + ~4595 sig)
──────────────────────────────
Total:            6426 bytes

Overhead: 6326 bytes (63x)
```

### Comparison with Previous Versions

| Component | v0.06 | v0.07 | v0.08 |
|-----------|-------|-------|-------|
| Header | 20 B | 20 B | 20 B |
| Recipients | 1608 B | 1608 B | 1608 B |
| Nonce | 12 B | 12 B | 12 B |
| Ciphertext | 100 B | 164 B | **172 B** |
| Tag | 16 B | 16 B | 16 B |
| Signature | 7195 B | 4598 B | 4598 B |
| **Total** | **8951 B** | **6418 B** | **6426 B** |

**Key improvements (v0.08 vs v0.06):**
- ✅ Sender fingerprint encrypted (64 bytes inside ciphertext)
- ✅ Sender timestamp encrypted (8 bytes inside ciphertext)
- ✅ Public key removed from signature (2592 bytes saved)
- ✅ Net reduction: 2525 bytes per message (28.2%)

---

## Field Specifications

### Header (20 bytes)

```c
typedef struct {
    char magic[8];          // "PQSIGENC" (0x50 0x51 0x53 0x49 0x47 0x45 0x4E 0x43)
    uint8_t version;        // 0x08
    uint8_t enc_key_type;   // 23 = Kyber1024
    uint8_t recipient_count;// 1-255
    uint8_t reserved;       // 0x00
    uint32_t encrypted_size;// Ciphertext length (big-endian)
    uint32_t signature_size;// Signature block length (big-endian)
} __attribute__((packed)) dna_enc_header_t;
```

**Validation:**
- `magic` must be "PQSIGENC"
- `version` must be `0x08` for v0.08 clients
- `enc_key_type` must be `23` (Kyber1024)
- `recipient_count` must be ≥ 1

### Recipients (1608 bytes per recipient)

```c
typedef struct {
    uint8_t kyber_ciphertext[1568];  // Kyber1024 encapsulation
    uint8_t wrapped_dek[40];         // AES-256 key wrap (RFC 3394)
} __attribute__((packed)) dna_recipient_entry_t;
```

**Kyber1024 Parameters:**
- Public key size: 1568 bytes
- Ciphertext size: 1568 bytes
- Shared secret size: 32 bytes (used as KEK)

**Key Wrapping:**
- DEK (32 bytes) wrapped with Kyber1024-derived KEK
- Uses AES-256 key wrap (RFC 3394)
- Wrapped output: 40 bytes

### Nonce (12 bytes)

- Random initialization vector for AES-256-GCM
- Generated using `qgp_randombytes()`
- Must be unique per message (never reused with same DEK)

### Ciphertext (64 + 8 + plaintext_len bytes)

**Structure (v0.08):**
```
[sender_fingerprint(64)] || [timestamp(8)] || [plaintext]
```

**Encryption:**
- Algorithm: AES-256-GCM
- Key: 32-byte random DEK
- AAD: Header (20 bytes)
- Nonce: 12-byte random IV
- Tag: 16 bytes (appended separately)

**sender_fingerprint:**
- SHA3-512 hash of sender's Dilithium5 public key
- Binary format (64 bytes, not hex)
- Used for keyserver lookup during verification

**timestamp:**
- Unix epoch timestamp (uint64_t, 8 bytes)
- Big-endian byte order (network byte order)
- Sender's time when message was created
- Encrypted inside payload (privacy-preserving)
- Used for correct message ordering

**plaintext:**
- Actual message content (UTF-8 text or binary data)
- No length prefix (derived from `encrypted_size - 64 - 8`)

### Tag (16 bytes)

- AES-256-GCM authentication tag
- Authenticates header (AAD) + ciphertext
- Verified during decryption

### Signature (3 + ~4595 bytes)

**v0.08 Format:**
```
[type(1)] [sig_size(2)] [signature_bytes]
```

**Changes from v0.06:**
- ❌ Removed: `pkey_size` (2 bytes)
- ❌ Removed: `public_key` (2592 bytes for Dilithium5)
- ✅ Sender public key now inside encrypted payload (as fingerprint)
- ✅ Timestamp added to encrypted payload (v0.08)

**Dilithium5 Parameters:**
- Public key size: 2592 bytes (no longer in signature)
- Signature size: ~4595 bytes
- Security level: NIST Category 5 (256-bit quantum security)

---

## Encryption Flow

### Sender (Encryption)

```
1. Generate random DEK (32 bytes)
2. Compute sender_fingerprint = SHA3-512(sender_dilithium_pubkey)
3. Get current timestamp = time(NULL) (Unix epoch, uint64_t)
4. Build payload = fingerprint(64) || timestamp(8, big-endian) || plaintext
5. Create signature = Dilithium5.sign(plaintext, sender_sign_privkey)
6. Encrypt payload:
   ciphertext, tag = AES-256-GCM.encrypt(
       key=DEK,
       plaintext=payload,
       aad=header,
       nonce=random(12)
   )
7. For each recipient:
   a. kek, kyber_ct = Kyber1024.encapsulate(recipient_enc_pubkey)
   b. wrapped_dek = AES_KeyWrap(DEK, kek)
8. Serialize signature (no public key in v0.08)
9. Assemble message:
   [header][recipients][nonce][ciphertext][tag][signature]
```

### Recipient (Decryption)

```
1. Parse header, validate magic + version
2. Try each recipient entry:
   a. kek = Kyber1024.decapsulate(kyber_ct, recipient_enc_privkey)
   b. DEK = AES_KeyUnwrap(wrapped_dek, kek)
   c. If successful, break
3. Decrypt ciphertext:
   payload = AES-256-GCM.decrypt(
       key=DEK,
       ciphertext=ciphertext,
       aad=header,
       nonce=nonce,
       tag=tag
   )
4. Extract sender_fingerprint = payload[0:64]
5. Extract timestamp = be64toh(payload[64:72])  // Big-endian to host
6. Extract plaintext = payload[72:]
7. Query keyserver for pubkey:
   dilithium_pubkey = keyserver_lookup(sender_fingerprint)
   (Cache-first, then DHT, 7-day TTL)
8. Verify signature:
   verified = Dilithium5.verify(signature, plaintext, dilithium_pubkey)
9. If verified, return plaintext + timestamp
```

---

## Security Properties

### Cryptographic Guarantees

| Property | Algorithm | Parameters | Security Level |
|----------|-----------|------------|----------------|
| **Confidentiality** | AES-256-GCM | 256-bit key | Classical: 256-bit / Quantum: 128-bit |
| **Key Exchange** | Kyber1024 (ML-KEM-1024) | 1568-byte keys | Quantum: 256-bit (Category 5) |
| **Authentication** | Dilithium5 (ML-DSA-87) | 2592-byte keys | Quantum: 256-bit (Category 5) |
| **Integrity** | AES-GCM tag + Dilithium | 16-byte tag | 128-bit |
| **Hashing** | SHA3-512 | 512-bit output | Quantum: 256-bit |

**Post-Quantum Security:**
- Resistant to Grover's algorithm (quantum search)
- Resistant to Shor's algorithm (quantum factoring)
- NIST FIPS 203/204 compliant (standardized 2024)
- Secure beyond 2050+ against known quantum attacks

### Privacy Analysis

**What's Encrypted:**
- ✅ Message plaintext (AES-256-GCM)
- ✅ Sender fingerprint (inside ciphertext)
- ✅ Sender timestamp (inside ciphertext, v0.08)
- ✅ DEK (Kyber1024 + AES key wrap)

**What's Plaintext:**
- ⚠️ Message size (encrypted_size field)
- ⚠️ Recipient count
- ⚠️ Signature (but no sender pubkey in v0.08)
- ⚠️ Queue timestamp (in DHT offline queue metadata, separate from message timestamp)

**Network Observer Can See:**
- IP addresses (source, destination)
- Packet sizes
- Connection timing
- Protocol fingerprint ("PQSIGENC" magic)

**Network Observer CANNOT See:**
- Sender identity (fingerprint encrypted in v0.08)
- Sender timestamp (encrypted in v0.08)
- Message content
- Full sender public key

**Privacy Improvement vs v0.06:**
- v0.06: Sender's 2592-byte Dilithium5 pubkey in plaintext → linkable
- v0.07: Only 64-byte fingerprint, encrypted → not linkable from network traffic
- v0.08: Timestamp also encrypted → no timing metadata leak

---

## DHT Offline Queue Format

When recipient is offline, messages are stored in DHT using sender outbox model (Model E).

### Queue Entry Structure

```
┌─────────────────────────────────────────────────┐
│ Entry Metadata                                  │
│  - count (4 bytes):      Number of messages     │
│  - magic (4 bytes):      "DNA "                 │
│  - version (1 byte):     0x01                   │
│  - timestamp (8 bytes):  When queued            │
│  - expiry (8 bytes):     TTL (7 days)           │
│  - sender_len (2 bytes): 64 (fingerprint)       │
│  - recipient_len (2):    64 (fingerprint)       │
│  - ciphertext_len (4):   Message size           │
├─────────────────────────────────────────────────┤
│ Sender Fingerprint (64 bytes)                   │
│  - SHA3-512(sender pubkey) - plaintext          │
├─────────────────────────────────────────────────┤
│ Recipient Fingerprint (64 bytes)                │
│  - SHA3-512(recipient pubkey) - plaintext       │
├─────────────────────────────────────────────────┤
│ Encrypted Message (variable)                    │
│  - Complete v0.07 message format                │
│  - Already encrypted, no double encryption      │
└─────────────────────────────────────────────────┘
```

**DHT Storage Key:**
```
SHA3-512(sender_fingerprint + ":outbox:" + recipient_fingerprint)
```

**Example:**
```
Key: a3f5e2d1...c8b4:outbox:d7e9f1a2...b3c8
Value: [queue entry with v0.07 message inside]
TTL: 7 days
```

**Privacy Note:**
- Fingerprints in queue metadata are **plaintext** (DHT sees them)
- Fingerprint inside v0.08 message is **encrypted** (better privacy for P2P)
- Timestamp in queue metadata is **plaintext** (when message was queued)
- Timestamp inside v0.08 message is **encrypted** (when message was sent)
- DHT queue privacy same as v0.06
- Direct P2P privacy improved in v0.08

---

## Compatibility & Migration

### Version Detection

```c
uint8_t version = ciphertext[9];  // Byte offset after magic[8]

if (version == 0x06) {
    // v0.06: pubkey in signature, no fingerprint in ciphertext
    return decrypt_v06(ciphertext);
}
else if (version == 0x07) {
    // v0.07: fingerprint in ciphertext, no timestamp
    return decrypt_v07(ciphertext);
}
else if (version == 0x08) {
    // v0.08: fingerprint + timestamp in ciphertext
    return decrypt_v08(ciphertext);
}
else {
    return ERROR_UNSUPPORTED_VERSION;
}
```

### Breaking Changes

**v0.07 → v0.08:**
| Change | Impact | Mitigation |
|--------|--------|------------|
| **Timestamp in ciphertext** | Decryption must extract timestamp | Update decrypt function |
| **Ciphertext +8 bytes** | Slightly larger payload | Minimal overhead |
| **Message ordering** | Now uses sender time, not receive time | UI must use extracted timestamp |

**v0.06 → v0.07:**
| Change | Impact | Mitigation |
|--------|--------|------------|
| **Fingerprint inside ciphertext** | Decryption must extract FP first | Update decrypt function |
| **Pubkey removed from signature** | Cannot verify without keyserver | Query by fingerprint |
| **Ciphertext +64 bytes** | Larger encrypted payload | Accept size increase |
| **Signature -2597 bytes** | Smaller signature block | Net savings overall |

**Migration Strategy:**
- No backward compatibility (clean break)
- All clients must upgrade simultaneously
- Set mandatory upgrade deadline
- Old messages become unreadable after upgrade

### Upgrade Checklist

**v0.07 → v0.08:**
- [ ] Update encryption: Add timestamp to payload (fingerprint + timestamp + plaintext)
- [ ] Update decryption: Extract timestamp from payload (bytes 64-71)
- [ ] Update version constant: DNA_ENC_VERSION = 0x08
- [ ] Update all callers: Pass/receive timestamp parameter
- [ ] Update UI: Display sender timestamp, not receive time
- [ ] Test roundtrip: Verify timestamp survives encryption/decryption
- [ ] Update documentation

**v0.06 → v0.07:**
- [ ] Update encryption: Prepend fingerprint to plaintext
- [ ] Update decryption: Extract fingerprint from payload
- [ ] Update signature serialization: Remove pubkey
- [ ] Add keyserver lookup by fingerprint
- [ ] Update database schema: Add `sender_fingerprint` column
- [ ] Test roundtrip: Encrypt → Decrypt → Verify
- [ ] Update documentation
- [ ] Announce breaking change

---

## Implementation Notes

### Memory Management

**Encryption (v0.08):**
```c
// Allocate payload buffer
size_t payload_len = 64 + 8 + plaintext_len;  // fingerprint + timestamp + plaintext
uint8_t *payload = malloc(payload_len);

// Build payload
memcpy(payload, fingerprint, 64);

// Add timestamp (big-endian)
uint64_t timestamp_be = htobe64(timestamp);
memcpy(payload + 64, &timestamp_be, 8);

memcpy(payload + 64 + 8, plaintext, plaintext_len);

// Encrypt
aes256_gcm_encrypt(dek, payload, payload_len, ...);

// IMPORTANT: Zero and free
memset(payload, 0, payload_len);
free(payload);
```

**Decryption (v0.08):**
```c
// Decrypt
uint8_t *decrypted = malloc(encrypted_size);
aes256_gcm_decrypt(dek, ciphertext, encrypted_size, decrypted, ...);

// Extract fingerprint
uint8_t *fingerprint = malloc(64);
memcpy(fingerprint, decrypted, 64);

// Extract timestamp (big-endian to host)
uint64_t timestamp_be;
memcpy(&timestamp_be, decrypted + 64, 8);
uint64_t timestamp = be64toh(timestamp_be);

// Extract plaintext
size_t plaintext_len = encrypted_size - 72;  // 64 + 8
uint8_t *plaintext = malloc(plaintext_len);
memcpy(plaintext, decrypted + 72, plaintext_len);

// Clean up decrypted buffer
memset(decrypted, 0, encrypted_size);
free(decrypted);
```

### Error Handling

**Common Errors:**

| Error | Cause | Mitigation |
|-------|-------|------------|
| `DNA_ERROR_DECRYPT` | Wrong DEK, corrupted data | Try all recipient entries |
| `DNA_ERROR_VERIFY` | Invalid signature | Check pubkey lookup |
| `DNA_ERROR_VERSION` | Unsupported version | Upgrade client |
| `DNA_ERROR_MEMORY` | malloc() failed | Check system resources |

**Verification in v0.08:**
```c
// After decryption
uint8_t *fingerprint = extract_fingerprint(decrypted);
uint64_t timestamp = extract_timestamp(decrypted);

// Query keyserver (cache-first)
uint8_t *pubkey = NULL;
if (keyserver_cache_get(fingerprint, &pubkey) != 0) {
    // Cache miss - query DHT
    if (dht_keyserver_lookup(fingerprint, &pubkey) != 0) {
        // DHT failed - queue for retry
        return DNA_ERROR_VERIFICATION_DEFERRED;
    }
    keyserver_cache_set(fingerprint, pubkey);
}

// Verify signature
if (dilithium5_verify(signature, plaintext, pubkey) != 0) {
    return DNA_ERROR_VERIFY;
}

// Return plaintext + timestamp
*plaintext_out = plaintext;
*timestamp_out = timestamp;
```

### Performance Considerations

**Bottlenecks:**
- Kyber1024 encapsulation: ~50,000 CPU cycles (~25 μs)
- Dilithium5 signature: ~2,000,000 CPU cycles (~1 ms)
- AES-256-GCM: ~10,000 cycles per 100 bytes (~5 μs)

**Optimization:**
- Cache keyserver lookups (7-day TTL)
- Batch DHT queries when possible
- Parallelize multi-recipient encryption

---

## Test Vectors

### Example Message (100-byte plaintext)

**Input:**
```
Plaintext: "Hello, this is a test message for DNA Messenger v0.07! Post-quantum security rocks! 🚀"
Length: 100 bytes
Sender: nocdem (fingerprint: a3f5e2d1...c8b4)
Recipient: alice (Kyber1024 pubkey: 1568 bytes)
```

**Encryption:**
```
1. sender_fingerprint = SHA3-512(nocdem_dilithium_pubkey)
   = a3f5e2d1c8b4... (64 bytes)

2. timestamp = time(NULL)
   = 1763472712 (Unix epoch)
   = 0x00000000691A0CC8 (64-bit big-endian)

3. payload = fingerprint || timestamp || plaintext
   = [a3f5...c8b4][00 00 00 00 69 1A 0C C8][48656c6c6f2c207468697320697320...]
   = 64 + 8 + 100 = 172 bytes

4. DEK = random(32)
   = 7a3f2e1d9c8b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f

5. signature = Dilithium5.sign(plaintext, nocdem_privkey)
   = [type:01][size:11F3][sig_bytes:4595 bytes]

6. kyber_ct, kek = Kyber1024.encapsulate(alice_pubkey)
7. wrapped_dek = AES_KeyWrap(DEK, kek)

8. ciphertext, tag = AES-256-GCM.encrypt(
       payload,
       dek,
       header_aad,
       random_nonce
   )
```

**Output Message (v0.08):**
```
Offset  | Field               | Size    | Value (hex)
--------|---------------------|---------|-------------
0       | magic               | 8       | 50 51 53 49 47 45 4E 43
8       | version             | 1       | 08
9       | enc_key_type        | 1       | 17
10      | recipient_count     | 1       | 01
11      | reserved            | 1       | 00
12      | encrypted_size      | 4       | 00 00 00 AC (172)
16      | signature_size      | 4       | 00 00 11 F6 (4598)
20      | kyber_ct[0]         | 1568    | ...
1588    | wrapped_dek[0]      | 40      | ...
1628    | nonce               | 12      | ...
1640    | ciphertext          | 172     | ... (fingerprint + timestamp + plaintext encrypted)
1812    | tag                 | 16      | ...
1828    | signature           | 4598    | [01][11F3][sig_bytes]
--------|---------------------|---------|-------------
        | TOTAL               | 6426    |
```

---

## References

### Standards

- **NIST FIPS 203** - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
- **NIST FIPS 204** - Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium)
- **RFC 5116** - An Interface and Algorithms for Authenticated Encryption (AES-GCM)
- **RFC 3394** - Advanced Encryption Standard (AES) Key Wrap Algorithm
- **FIPS 202** - SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions

### Implementations

- **pq-crystals** - Reference implementation of Kyber and Dilithium
  - https://github.com/pq-crystals/kyber
  - https://github.com/pq-crystals/dilithium

### Related Documents

- `CLAUDE.md` - Development guidelines
- `ROADMAP.md` - Feature timeline
- `docs/DHT_REFACTORING_PROGRESS.md` - DHT architecture
- `docs/MODEL_E_MIGRATION.md` - Offline queue design
- `docs/GROUP_INVITATIONS_GUIDE.md` - Group messaging

---

## Changelog

### v0.08 (2025-11-18)
- **Added:** Encrypted sender timestamp inside payload (8 bytes, big-endian uint64)
- **Changed:** Payload format: `fingerprint(64) || plaintext` → `fingerprint(64) || timestamp(8) || plaintext`
- **Result:** 8-byte increase per message (minimal overhead)
- **Privacy:** Sender timestamp no longer exposed in network traffic
- **Benefit:** Correct message ordering using sender's time, not receive time
- **Breaking:** v0.07 clients cannot decrypt v0.08 messages

### v0.07 (2025-11-18)
- **Added:** Sender fingerprint inside encrypted payload (64 bytes)
- **Removed:** Sender public key from signature block (2592 bytes)
- **Changed:** Signature format: `[type|pkey_size|sig_size|pubkey|sig]` → `[type|sig_size|sig]`
- **Result:** 2533-byte reduction per message (28.5%)
- **Privacy:** Sender identity no longer exposed in network traffic

### v0.06 (2025-11-04)
- **Upgraded:** Kyber 512 → 1024 (Category 3 → 5)
- **Upgraded:** Dilithium 3 → 5 (Category 3 → 5)
- **Upgraded:** SHA-256 → SHA3-512
- **Breaking:** All keys must regenerate

### v0.05 (2025-10-23)
- **Added:** Multi-recipient support
- **Added:** Recipient entry array

### v0.04 (2025-10-15)
- Initial release

---

**Document Version:** 1.0
**Last Updated:** 2025-11-18
**Maintained By:** DNA Messenger Team
**License:** MIT
