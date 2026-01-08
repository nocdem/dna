# DNA Messenger - Message System Documentation

**Version:** v0.08 (Phase 14 - DHT-Only Messaging)
**Last Updated:** 2025-12-24
**Security Level:** NIST Category 5 (256-bit quantum)

This document describes how the DNA Messenger message system works, with all facts verified directly from source code.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Message Lifecycle](#2-message-lifecycle)
3. [Message Format v0.08](#3-message-format-v008)
4. [Encryption Process](#4-encryption-process)
5. [Decryption Process](#5-decryption-process)
6. [Transport Layer](#6-transport-layer)
7. [GSK System](#7-gsk-system-group-symmetric-key)
8. [Key Management](#8-key-management)
9. [Database Schema](#9-database-schema)
10. [Security Properties](#10-security-properties)
11. [Source Code Reference](#11-source-code-reference)

---

## 1. Overview

### 1.1 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DNA MESSENGER MESSAGE FLOW                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐                                        ┌─────────────┐    │
│  │   SENDER    │                                        │  RECIPIENT  │    │
│  └──────┬──────┘                                        └──────┬──────┘    │
│         │                                                      │           │
│         ▼                                                      ▼           │
│  ┌─────────────┐         ENCRYPTION LAYER           ┌─────────────────┐   │
│  │ GUI Input   │                                    │   GUI Display   │   │
│  │ (ImGui)     │                                    │   (ImGui)       │   │
│  └──────┬──────┘                                    └────────┬────────┘   │
│         │                                                    ▲            │
│         ▼                                                    │            │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                    MESSENGER CORE (messenger/messages.c)         │     │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │     │
│  │  │ Dilithium5│  │ Kyber1024 │  │AES-256-GCM│  │  SHA3-512 │    │     │
│  │  │  (sign)   │  │  (KEM)    │  │ (encrypt) │  │(fingerprint│    │     │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘    │     │
│  └──────┬──────────────────────────────────────────────┬──────────┘     │
│         │                                              │                 │
│         ▼                                              ▼                 │
│  ┌─────────────┐                                ┌─────────────┐         │
│  │   SQLite    │◄───────────────────────────────│   SQLite    │         │
│  │ (messages.db│                                │ (messages.db│         │
│  └──────┬──────┘                                └──────┬──────┘         │
│         │                                              ▲                 │
│         ▼                                              │                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    TRANSPORT LAYER (Phase 14)                    │   │
│  │                                                                  │   │
│  │           ┌────────────────────────────────────┐                 │   │
│  │           │    DHT Queue (Spillway Protocol)   │                 │   │
│  │           │   All messages → DHT directly      │                 │   │
│  │           │   7-day TTL, sender-based outbox   │                 │   │
│  │           └───────────────┬────────────────────┘                 │   │
│  │                           │                                      │   │
│  │                           ▼                                      │   │
│  │               ┌────────────────┐                                 │   │
│  │               │   DHT Network  │                                 │   │
│  │               │   (UDP:4000)   │                                 │   │
│  │               │  OpenDHT-PQ    │                                 │   │
│  │               └────────────────┘                                 │   │
│  │                                                                  │   │
│  │   Note: P2P infrastructure preserved for future audio/video     │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Cryptographic Stack

| Algorithm | Standard | Purpose | Key/Output Size |
|-----------|----------|---------|-----------------|
| **Kyber1024** | ML-KEM-1024 (FIPS 203) | Key Encapsulation | Pub: 1568, Priv: 3168, CT: 1568, SS: 32 |
| **Dilithium5** | ML-DSA-87 (FIPS 204) | Digital Signatures | Pub: 2592, Priv: 4896, Sig: ~4627 |
| **AES-256-GCM** | FIPS 197 + SP 800-38D | Symmetric Encryption | Key: 32, Nonce: 12, Tag: 16 |
| **SHA3-512** | FIPS 202 | Fingerprints/Hashing | Output: 64 bytes |
| **AES Key Wrap** | RFC 3394 | DEK Protection | KEK: 32, Wrapped: 40 |

**Source:** `crypto/utils/qgp_types.h`, `crypto/utils/qgp_aes.h`, `crypto/utils/qgp_kyber.h`, `crypto/utils/qgp_dilithium.h`

---

## 2. Message Lifecycle

### 2.1 Send Flow

```
USER INPUT                     ENCRYPTION                      STORAGE                       TRANSPORT
    │                              │                              │                              │
    ▼                              │                              │                              │
┌─────────┐                        │                              │                              │
│ Type    │                        │                              │                              │
│ Message │                        │                              │                              │
└────┬────┘                        │                              │                              │
     │                             │                              │                              │
     ▼                             │                              │                              │
┌─────────────┐                    │                              │                              │
│ Optimistic  │ STATUS_PENDING     │                              │                              │
│ UI Update   │ (clock icon)       │                              │                              │
└──────┬──────┘                    │                              │                              │
       │                           │                              │                              │
       │ Async Queue               │                              │                              │
       ▼                           ▼                              │                              │
    ┌──────────────────────────────────────┐                      │                              │
    │ messenger_send_message()             │                      │                              │
    │   ├─ Load sender Dilithium5 key      │                      │                              │
    │   ├─ Load recipient Kyber1024 pubkey │                      │                              │
    │   └─ Add sender as recipient[0]      │                      │                              │
    └──────────────────┬───────────────────┘                      │                              │
                       │                                          │                              │
                       ▼                                          │                              │
    ┌──────────────────────────────────────┐                      │                              │
    │ messenger_encrypt_multi_recipient()  │                      │                              │
    │   1. Generate random 32-byte DEK     │                      │                              │
    │   2. Sign plaintext (Dilithium5)     │                      │                              │
    │   3. Compute fingerprint (SHA3-512)  │                      │                              │
    │   4. Build payload: fp+ts+plaintext  │                      │                              │
    │   5. Encrypt with AES-256-GCM        │                      │                              │
    │   6. For each recipient:             │                      │                              │
    │      - Kyber1024 encapsulate → KEK   │                      │                              │
    │      - AES-wrap DEK with KEK         │                      │                              │
    │   7. Assemble final ciphertext       │                      │                              │
    └──────────────────┬───────────────────┘                      │                              │
                       │                                          │                              │
                       │                                          ▼                              │
                       │                           ┌───────────────────────────┐                 │
                       │                           │ message_backup_save()     │                 │
                       │                           │   Store encrypted blob    │                 │
                       │                           │   in SQLite               │                 │
                       │                           └─────────────┬─────────────┘                 │
                       │                                         │                               │
                       │                                         │                               ▼
                       │                                         │              ┌────────────────────────────┐
                       │                                         │              │ Phase 14: DHT-Only Path    │
                       │                                         │              │ messenger_queue_to_dht()   │
                       │                                         │              └───────────┬────────────────┘
                       │                                         │                          │
                       │                                         │                          ▼
                       │                                         │              ┌──────────────────────────┐
                       │                                         │              │ DHT Queue (Spillway)     │
                       │                                         │              │ All messages → DHT       │
                       │                                         │              │ 7-day TTL                │
                       │                                         │              └────────────┬─────────────┘
                       │                                         │                           │
                       └─────────────────────────────────────────┼───────────────────────────┘
                                                                 │
                                                                 ▼
                                                        STATUS_SENT (checkmark)
                                                        or STATUS_FAILED (error)
```

**Source:** `messenger/messages.c:309-499`, `dna_messenger_flutter/lib/screens/chat/`

### 2.2 Receive Flow

```
TRANSPORT                         STORAGE                        DECRYPTION                    DISPLAY
    │                                │                               │                             │
    │                                │                               │                             │
    ▼                                │                               │                             │
┌───────────────────┐                │                               │                             │
│ P2P Callback      │                │                               │                             │
│ (if sender online)│                │                               │                             │
└────────┬──────────┘                │                               │                             │
         │                           │                               │                             │
         │    OR                     │                               │                             │
         │                           │                               │                             │
         ▼                           │                               │                             │
┌───────────────────┐                │                               │                             │
│ DHT Listen        │                │                               │                             │
│ (push notify)     │                │                               │                             │
│ Query contacts'   │                │                               │                             │
│ outboxes          │                │                               │                             │
└────────┬──────────┘                │                               │                             │
         │                           │                               │                             │
         │                           ▼                               │                             │
         │          ┌─────────────────────────────┐                  │                             │
         └─────────►│ message_backup_save()       │                  │                             │
                    │   Store encrypted blob      │                  │                             │
                    │   is_outgoing = false       │                  │                             │
                    │   Check duplicate (hash)    │                  │                             │
                    └───────────────┬─────────────┘                  │                             │
                                    │                                │                             │
                                    │ User opens chat                │                             │
                                    ▼                                ▼                             │
                    ┌─────────────────────────────────────────────────────┐                        │
                    │ messenger_decrypt_message()                         │                        │
                    │   1. Load my Kyber1024 private key                  │                        │
                    │   2. Parse header, find my recipient entry          │                        │
                    │   3. Kyber1024 decapsulate → KEK                    │                        │
                    │   4. AES-unwrap → DEK                               │                        │
                    │   5. AES-256-GCM decrypt → payload                  │                        │
                    │   6. Extract fingerprint, timestamp, plaintext      │                        │
                    │   7. Query keyserver for sender's Dilithium5 pubkey │                        │
                    │   8. Verify signature                               │                        │
                    └────────────────────────────────┬────────────────────┘                        │
                                                     │                                             │
                                                     ▼                                             ▼
                                            ┌──────────────────┐                        ┌───────────────────┐
                                            │ Plaintext +      │ ─────────────────────► │ Display in GUI    │
                                            │ Signature Status │                        │ with status icons │
                                            └──────────────────┘                        └───────────────────┘
```

**Source:** `messenger/messages.c:592-747`, `p2p/transport/transport_offline.c:64-170`

### 2.3 Message Status States

| Status | Value | Icon | Description |
|--------|-------|------|-------------|
| `STATUS_PENDING` | 0 | Clock | Sending in progress |
| `STATUS_SENT` | 1 | Checkmark | Successfully sent (P2P or DHT queued) |
| `STATUS_FAILED` | 2 | Error | Send failed (retry available) |

**Source:** `messenger.h` (message_info_t), `dna_messenger_flutter/lib/models/`

---

## 3. Message Format v0.08

### 3.1 Complete Message Layout

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         MESSAGE FORMAT v0.08                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  OFFSET   SIZE    FIELD                                                      │
│  ───────────────────────────────────────────────────────────────────────     │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ HEADER (22 bytes)                                                    │    │
│  ├──────┬─────────┬────────────────────────────────────────────────────┤    │
│  │  0   │    8    │ magic[8] = "PQSIGENC"                              │    │
│  │  8   │    1    │ version = 0x08                                     │    │
│  │  9   │    1    │ enc_key_type = 2 (QGP_KEY_TYPE_KEM1024)            │    │
│  │  10  │    1    │ recipient_count (1-255)                            │    │
│  │  11  │    1    │ message_type (0=direct, 1=group)                   │    │
│  │  12  │    4    │ encrypted_size (uint32_t, little-endian)           │    │
│  │  16  │    4    │ signature_size (uint32_t, little-endian)           │    │
│  └──────┴─────────┴────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ RECIPIENT ENTRIES (1608 bytes × recipient_count)                     │    │
│  ├──────┬─────────┬────────────────────────────────────────────────────┤    │
│  │  0   │  1568   │ kyber_ciphertext[1568] (Kyber1024 encapsulation)   │    │
│  │ 1568 │   40    │ wrapped_dek[40] (AES-wrapped DEK: 32+8 bytes)      │    │
│  └──────┴─────────┴────────────────────────────────────────────────────┘    │
│  (Repeated for each recipient)                                              │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ NONCE (12 bytes)                                                     │    │
│  ├──────┬─────────┬────────────────────────────────────────────────────┤    │
│  │  0   │   12    │ nonce[12] (random, per-message)                    │    │
│  └──────┴─────────┴────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ ENCRYPTED PAYLOAD (encrypted_size bytes)                             │    │
│  │ AES-256-GCM encrypted content:                                       │    │
│  ├──────┬─────────┬────────────────────────────────────────────────────┤    │
│  │  0   │   64    │ fingerprint[64] (SHA3-512 of sender's Dilithium5)  │    │
│  │  64  │    8    │ timestamp (uint64_t, big-endian, Unix epoch)       │    │
│  │  72  │   var   │ plaintext (UTF-8 message content)                  │    │
│  └──────┴─────────┴────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ AUTH TAG (16 bytes)                                                  │    │
│  ├──────┬─────────┬────────────────────────────────────────────────────┤    │
│  │  0   │   16    │ tag[16] (AES-GCM authentication tag)               │    │
│  └──────┴─────────┴────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ SIGNATURE (signature_size bytes, ~4627)                              │    │
│  │ Dilithium5 signature over plaintext                                  │    │
│  ├──────┬─────────┬────────────────────────────────────────────────────┤    │
│  │  0   │  var    │ signature (~4595-4627 bytes)                       │    │
│  └──────┴─────────┴────────────────────────────────────────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Header Structure (C Definition)

```c
// Source: messenger/messages.c:47-55
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x08 (Category 5 + encrypted timestamp)
    uint8_t enc_key_type;       // QGP_KEY_TYPE_KEM1024 (2)
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t message_type;       // MSG_TYPE_DIRECT_PQC or MSG_TYPE_GROUP_GSK
    uint32_t encrypted_size;    // Size of encrypted data
    uint32_t signature_size;    // Size of signature
} messenger_enc_header_t;
```

### 3.3 Recipient Entry Structure (C Definition)

```c
// Source: messenger/messages.c:57-60
typedef struct {
    uint8_t kyber_ciphertext[1568];   // Kyber1024 ciphertext
    uint8_t wrapped_dek[40];          // AES-wrapped DEK (32-byte + 8-byte IV)
} messenger_recipient_entry_t;
```

### 3.4 Size Calculation

For a message with N recipients:

```
Total Size = Header(22) + Recipients(1608×N) + Nonce(12) + Encrypted(var) + Tag(16) + Signature(~4627)

Example for 1 recipient, 100-byte plaintext:
  Header:      22 bytes
  Recipients:  1608 bytes (1 × 1608)
  Nonce:       12 bytes
  Encrypted:   172 bytes (64 + 8 + 100)
  Tag:         16 bytes
  Signature:   ~4627 bytes
  ─────────────────────
  Total:       ~6457 bytes
```

### 3.5 Version History

| Version | Changes | Source |
|---------|---------|--------|
| v0.07 | Added fingerprint (64 bytes) inside encrypted payload for identity privacy | `messages.c:155-160` |
| v0.08 | Added encrypted timestamp (8 bytes) for replay protection | `messages.c:162-178` |

---

## 4. Encryption Process

### 4.1 Function: `messenger_encrypt_multi_recipient()`

**Source:** `messenger/messages.c:74-307`

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ENCRYPTION PROCESS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  INPUT: plaintext, recipients[], sender_sign_key                            │
│                                                                             │
│  STEP 1: Generate DEK (Data Encryption Key)                                 │
│  ─────────────────────────────────────────                                  │
│  ┌────────────────────────────────────────┐                                 │
│  │ qgp_randombytes(dek, 32)               │  → 32-byte random DEK           │
│  └────────────────────────────────────────┘                                 │
│  Source: messages.c:96-106                                                  │
│                                                                             │
│  STEP 2: Sign Plaintext                                                     │
│  ───────────────────────                                                    │
│  ┌────────────────────────────────────────┐                                 │
│  │ qgp_dsa87_sign(plaintext,              │  → ~4627-byte signature         │
│  │                sender_privkey)          │                                 │
│  └────────────────────────────────────────┘                                 │
│  Source: messages.c:108-153                                                 │
│                                                                             │
│  STEP 3: Compute Sender Fingerprint                                         │
│  ──────────────────────────────────                                         │
│  ┌────────────────────────────────────────┐                                 │
│  │ qgp_sha3_512(sender_pubkey, 2592,      │  → 64-byte fingerprint          │
│  │              fingerprint)               │                                 │
│  └────────────────────────────────────────┘                                 │
│  Source: messages.c:155-160                                                 │
│                                                                             │
│  STEP 4: Build Payload                                                      │
│  ─────────────────────                                                      │
│  ┌────────────────────────────────────────────────────────────────┐        │
│  │ payload = [fingerprint(64)] || [timestamp_be(8)] || [plaintext] │        │
│  └────────────────────────────────────────────────────────────────┘        │
│  Source: messages.c:162-178                                                 │
│                                                                             │
│  STEP 5: Encrypt Payload with AES-256-GCM                                   │
│  ────────────────────────────────────────                                   │
│  ┌────────────────────────────────────────┐                                 │
│  │ qgp_aes256_encrypt(                    │                                 │
│  │   key = dek,                           │                                 │
│  │   plaintext = payload,                 │                                 │
│  │   aad = header_for_aad,                │  Header as Additional           │
│  │   → ciphertext, nonce, tag             │  Authenticated Data             │
│  │ )                                      │                                 │
│  └────────────────────────────────────────┘                                 │
│  Source: messages.c:196-202                                                 │
│                                                                             │
│  STEP 6: Wrap DEK for Each Recipient                                        │
│  ───────────────────────────────────                                        │
│  FOR each recipient:                                                        │
│  ┌────────────────────────────────────────┐                                 │
│  │ qgp_kem1024_encapsulate(               │  Kyber1024 → KEK (32 bytes)     │
│  │   kyber_ct, kek, recipient_pubkey      │  + ciphertext (1568 bytes)      │
│  │ )                                      │                                 │
│  │                                        │                                 │
│  │ aes256_wrap_key(                       │  AES Key Wrap → wrapped_dek     │
│  │   dek, 32, kek, wrapped_dek            │  (40 bytes = 32 + 8 IV)         │
│  │ )                                      │                                 │
│  └────────────────────────────────────────┘                                 │
│  Source: messages.c:215-240                                                 │
│                                                                             │
│  STEP 7: Assemble Output                                                    │
│  ───────────────────────                                                    │
│  ┌────────────────────────────────────────────────────────────────┐        │
│  │ output = [header] || [recipient_entries×N] || [nonce] ||       │        │
│  │          [ciphertext] || [tag] || [signature]                  │        │
│  └────────────────────────────────────────────────────────────────┘        │
│  Source: messages.c:242-292                                                 │
│                                                                             │
│  OUTPUT: Complete encrypted message blob                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Key Points

1. **Sender as Recipient[0]:** Sender is always added as the first recipient so they can decrypt their own sent messages (Source: `messages.c:350`)

2. **Per-Message DEK:** A fresh random 32-byte DEK is generated for each message, providing forward secrecy

3. **Header as AAD:** The message header is used as Additional Authenticated Data in AES-GCM, ensuring header integrity without encrypting it

4. **Independent Per-Recipient Wrapping:** Each recipient gets their own Kyber1024 encapsulation, so compromising one recipient's key doesn't affect others

---

## 5. Decryption Process

### 5.1 Function: `messenger_read_message()` / `dna_decrypt_message_raw()`

**Source:** `messenger/messages.c:592-747`

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DECRYPTION PROCESS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  INPUT: ciphertext, my_kyber_privkey                                        │
│                                                                             │
│  STEP 1: Parse Header                                                       │
│  ────────────────────                                                       │
│  ┌────────────────────────────────────────┐                                 │
│  │ Verify magic == "PQSIGENC"             │                                 │
│  │ Verify version == 0x08                 │                                 │
│  │ Extract recipient_count, encrypted_size│                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                             │
│  STEP 2: Find My Recipient Entry                                            │
│  ───────────────────────────────                                            │
│  ┌────────────────────────────────────────┐                                 │
│  │ FOR i = 0 to recipient_count:          │                                 │
│  │   Try decapsulate with my privkey      │                                 │
│  │   If success → found my entry          │                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                             │
│  STEP 3: Kyber1024 Decapsulation                                            │
│  ───────────────────────────────                                            │
│  ┌────────────────────────────────────────┐                                 │
│  │ qgp_kem1024_decapsulate(               │  Kyber1024 → KEK (32 bytes)     │
│  │   kek, kyber_ct, my_privkey            │                                 │
│  │ )                                      │                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                             │
│  STEP 4: Unwrap DEK                                                         │
│  ──────────────────                                                         │
│  ┌────────────────────────────────────────┐                                 │
│  │ aes256_unwrap_key(                     │  AES Key Unwrap → DEK           │
│  │   wrapped_dek, 40, kek, dek            │  (32 bytes)                     │
│  │ )                                      │                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                             │
│  STEP 5: AES-256-GCM Decryption                                             │
│  ──────────────────────────────                                             │
│  ┌────────────────────────────────────────┐                                 │
│  │ qgp_aes256_decrypt(                    │  If tag verification fails →    │
│  │   key = dek,                           │  REJECT (tampering detected)    │
│  │   ciphertext, nonce, tag, aad          │                                 │
│  │   → payload                            │                                 │
│  │ )                                      │                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                             │
│  STEP 6: Extract Payload Components                                         │
│  ──────────────────────────────────                                         │
│  ┌────────────────────────────────────────────────────────────────┐        │
│  │ fingerprint = payload[0:64]   (64 bytes)                       │        │
│  │ timestamp   = be64toh(payload[64:72])  (8 bytes → uint64)      │        │
│  │ plaintext   = payload[72:]    (remaining bytes)                │        │
│  └────────────────────────────────────────────────────────────────┘        │
│                                                                             │
│  STEP 7: Verify Signature                                                   │
│  ────────────────────────                                                   │
│  ┌────────────────────────────────────────┐                                 │
│  │ Load sender pubkey from keyserver      │  Using fingerprint to lookup    │
│  │ (fingerprint → Dilithium5 pubkey)      │                                 │
│  │                                        │                                 │
│  │ qgp_dsa87_verify(                      │  Returns 0 if valid             │
│  │   signature, plaintext, sender_pubkey  │  Returns -1 if invalid/forged   │
│  │ )                                      │                                 │
│  └────────────────────────────────────────┘                                 │
│  Source: messages.c:697-718                                                 │
│                                                                             │
│  OUTPUT: plaintext, sender_timestamp, signature_verified                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Error Conditions

| Error | Cause | Source |
|-------|-------|--------|
| Magic mismatch | Not a DNA message | Header parsing |
| Version mismatch | Unsupported format | Header parsing |
| Entry not found | Not a recipient | Step 2 |
| Decapsulation failure | Wrong private key | Step 3 |
| Unwrap failure | KEK mismatch | Step 4 |
| Tag verification failure | Tampered message | Step 5 |
| Signature invalid | Forged message | Step 7 |

---

## 6. Transport Layer

### 6.1 Architecture (Phase 14: DHT-Only Messaging)

**As of Phase 14**, all messaging goes directly to DHT (Spillway protocol). P2P direct delivery
is **disabled for messaging** to improve reliability on mobile platforms where background
execution restrictions make P2P connections unreliable.

**P2P infrastructure is preserved** for future audio/video calls.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TRANSPORT LAYER (Phase 14 - DHT-Only)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                      ┌─────────────────────────┐                            │
│                      │ messenger_send_message()│                            │
│                      └───────────┬─────────────┘                            │
│                                  │                                          │
│                                  ▼                                          │
│                      ┌─────────────────────────┐                            │
│                      │ messenger_queue_to_dht()│                            │
│                      │ (Phase 14: DHT-only)    │                            │
│                      └───────────┬─────────────┘                            │
│                                  │                                          │
│                                  ▼                                          │
│                      ┌─────────────────────────────────┐                    │
│                      │    DHT Queue (Spillway)         │                    │
│                      │    Key: sender:outbox:recipient │                    │
│                      │    TTL: 7 days                  │                    │
│                      │    Signed put (value_id=1)      │                    │
│                      └─────────────────────────────────┘                    │
│                                                                             │
│  DEPRECATED (kept for future audio/video):                                  │
│  ─────────────────────────────────────────                                  │
│  • messenger_send_p2p() - No longer called for messaging                    │
│  • p2p_lookup_peer() - Used for presence only                               │
│  • TCP direct delivery - Bypassed for messages                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Source:** `messenger/messages.c:463-491`, `messenger_p2p.c:780-838`

### 6.2 Port Configuration

| Port | Protocol | Purpose |
|------|----------|---------|
| 4000 | UDP | DHT Network (OpenDHT-PQ) |
| 4001 | TCP | P2P Messaging |

**Source:** `p2p/p2p_transport.h:20-25`

### 6.3 DHT Offline Queue (Spillway Protocol)

**Spillway Protocol** = Sender-Based Outbox Architecture with Watermark Pruning

**Source:** `dht/shared/dht_offline_queue.h:14-37`

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 SPILLWAY PROTOCOL: SENDER-BASED OUTBOX                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  STORAGE KEY GENERATION:                                                    │
│  ───────────────────────                                                    │
│  key = SHA3-512(sender_fingerprint + ":outbox:" + recipient_fingerprint)    │
│                                                                             │
│  Example:                                                                   │
│    sender    = "a3f9e2d1c5b8..."  (128 hex chars)                          │
│    recipient = "b4a7f89012e3..."  (128 hex chars)                          │
│    input     = "a3f9e2d1c5b8...:outbox:b4a7f89012e3..."                    │
│    key       = SHA3-512(input) → 64 bytes                                  │
│                                                                             │
│  STORAGE:                                                                   │
│  ────────                                                                   │
│  ┌────────────────────────────────────────────────────┐                    │
│  │ dht_put_signed(key, messages, value_id=1)          │                    │
│  │                                                    │                    │
│  │ - Uses Dilithium5 signature for authentication    │                    │
│  │ - value_id=1 enables REPLACEMENT (not append)     │                    │
│  │ - TTL: 7 days (604,800 seconds)                   │                    │
│  └────────────────────────────────────────────────────┘                    │
│                                                                             │
│  RETRIEVAL:                                                                 │
│  ──────────                                                                 │
│  ┌────────────────────────────────────────────────────┐                    │
│  │ FOR each contact in my_contacts:                   │                    │
│  │   key = SHA3-512(contact + ":outbox:" + me)        │                    │
│  │   messages = dht_get(key)                          │                    │
│  │   deliver_to_callback(messages)                    │                    │
│  └────────────────────────────────────────────────────┘                    │
│                                                                             │
│  Delivery: Real-time via DHT listen (push notifications)                   │
│                                                                             │
│  WATERMARK PRUNING:                                                         │
│  ──────────────────                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ 1. Alice sends msgs to Bob with seq_num (1, 2, 3...)               │    │
│  │ 2. Bob receives, publishes watermark: seq=3                        │    │
│  │ 3. Alice sends new msg (seq=4), fetches Bob's watermark            │    │
│  │ 4. Alice prunes outbox: removes msgs where seq <= 3                │    │
│  │ 5. Result: Bounded outbox, only undelivered messages remain        │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  Watermark Key: SHA3-512(recipient + ":watermark:" + sender)                │
│  Watermark TTL: 30 days                                                     │
│  Watermark Value: 8-byte big-endian seq_num                                 │
│                                                                             │
│  BENEFITS:                                                                  │
│  ─────────                                                                  │
│  ✓ Bounded storage (watermark pruning prevents unbounded growth)           │
│  ✓ Clock-skew immune (uses monotonic seq_num, not timestamps)              │
│  ✓ Spam prevention (recipients only query known contacts)                  │
│  ✓ Sender control (can edit/delete within TTL)                             │
│  ✓ Parallel retrieval (10-100× speedup)                                    │
│  ✓ Async watermarks (fire-and-forget, self-healing on retry)               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.4 Offline Message Format (v2)

```c
// Source: dht/shared/dht_offline_queue.h:32-34

Message Format v2 (Spillway Protocol):
[4-byte magic "DNA "][1-byte version=2][8-byte seq_num][8-byte timestamp][8-byte expiry]
[2-byte sender_len][2-byte recipient_len][4-byte ciphertext_len]
[sender string][recipient string][ciphertext bytes]

Header size: 37 bytes (was 29 bytes in v1)

Fields:
- seq_num:   Monotonic per sender-recipient pair (for watermark pruning)
- timestamp: Unix timestamp when queued (for display only)
- expiry:    Unix timestamp when message expires
```

---

## 7. GSK System (Group Symmetric Key)

### 7.1 Purpose

GSK provides **200× faster** group message encryption compared to per-recipient Kyber1024.

Instead of:
- N members × Kyber1024 encapsulation = N × 1608 bytes per message

GSK uses:
- 1 AES-256-GCM encryption with shared key = same ciphertext for all members

**Source:** `messenger/gsk.h:1-165`

### 7.2 GSK Entry Structure

```c
// Source: messenger/gsk.h:36-42

typedef struct {
    char group_uuid[37];       // UUID v4 (36 + null terminator)
    uint32_t gsk_version;      // Rotation counter (0, 1, 2, ...)
    uint8_t gsk[GSK_KEY_SIZE]; // AES-256 key (32 bytes)
    uint64_t created_at;       // Unix timestamp (seconds)
    uint64_t expires_at;       // created_at + GSK_DEFAULT_EXPIRY
} gsk_entry_t;

#define GSK_KEY_SIZE 32                    // AES-256
#define GSK_DEFAULT_EXPIRY (7 * 24 * 3600) // 7 days
```

### 7.3 Initial Key Packet Format

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      INITIAL KEY PACKET (GSK Distribution)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  HEADER (42 bytes)                                                          │
│  ┌───────┬──────────┬──────────────────────────────────────────────────┐   │
│  │  0    │   37     │ group_uuid[37] (UUID v4 + null)                  │   │
│  │  37   │    4     │ version (uint32_t, GSK version number)           │   │
│  │  41   │    1     │ member_count (uint8_t, 1-255)                    │   │
│  └───────┴──────────┴──────────────────────────────────────────────────┘   │
│                                                                             │
│  MEMBER ENTRIES (1672 bytes × member_count)                                 │
│  ┌───────┬──────────┬──────────────────────────────────────────────────┐   │
│  │  0    │   64     │ fingerprint[64] (SHA3-512 of member's pubkey)    │   │
│  │  64   │  1568    │ kyber_ciphertext[1568] (Kyber1024 encapsulation) │   │
│  │ 1632  │   40     │ wrapped_gsk[40] (AES-wrapped GSK)                │   │
│  └───────┴──────────┴──────────────────────────────────────────────────┘   │
│  (Repeated for each member)                                                 │
│                                                                             │
│  SIGNATURE BLOCK (~4630 bytes)                                              │
│  ┌───────┬──────────┬──────────────────────────────────────────────────┐   │
│  │  0    │    1     │ signature_type (1 = Dilithium5)                  │   │
│  │  1    │    2     │ sig_size (uint16_t, ~4627)                       │   │
│  │  3    │  ~4627   │ signature (Dilithium5 over header+entries)       │   │
│  └───────┴──────────┴──────────────────────────────────────────────────┘   │
│                                                                             │
│  TOTAL SIZE: 42 + (1672 × N) + 4630 bytes                                  │
│                                                                             │
│  Example for 10 members: 42 + 16720 + 4630 = 21,392 bytes                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Source:** `messenger/gsk_packet.h:8-17`

### 7.4 GSK Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GSK LIFECYCLE                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. GROUP CREATION                                                          │
│     ─────────────────                                                       │
│     ┌─────────────────────────────────────────────────┐                    │
│     │ gsk_generate(group_uuid, version=0, gsk)        │                    │
│     │ gsk_store(group_uuid, 0, gsk)                   │                    │
│     │ gsk_packet_build(...) → Initial Key Packet      │                    │
│     │ DHT publish packet to all members               │                    │
│     └─────────────────────────────────────────────────┘                    │
│                                                                             │
│  2. MEMBER ADDED                                                            │
│     ────────────────                                                        │
│     ┌─────────────────────────────────────────────────┐                    │
│     │ gsk_rotate_on_member_add()                      │                    │
│     │   - Generate new GSK (version++)                │                    │
│     │   - Build new Initial Key Packet (all members)  │                    │
│     │   - Publish to DHT                              │                    │
│     └─────────────────────────────────────────────────┘                    │
│                                                                             │
│  3. MEMBER REMOVED                                                          │
│     ───────────────                                                         │
│     ┌─────────────────────────────────────────────────┐                    │
│     │ gsk_rotate_on_member_remove()                   │                    │
│     │   - Generate new GSK (version++)                │  CRITICAL:         │
│     │   - Build new Initial Key Packet (WITHOUT       │  Removed member    │
│     │     removed member)                             │  cannot decrypt    │
│     │   - Publish to DHT                              │  future messages   │
│     └─────────────────────────────────────────────────┘                    │
│                                                                             │
│  4. GSK EXPIRATION (7 days)                                                 │
│     ───────────────────────                                                 │
│     ┌─────────────────────────────────────────────────┐                    │
│     │ gsk_cleanup_expired() - removes old GSKs        │                    │
│     │ Auto-rotate if needed for continued messaging   │                    │
│     └─────────────────────────────────────────────────┘                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Source:** `messenger/gsk.h:132-159`

---

## 8. Key Management

### 8.1 Key File Locations

```
~/.dna/
├── <fingerprint>.dsa     # Dilithium5 private key (4896 bytes)
├── <fingerprint>.kem     # Kyber1024 private key (3168 bytes)
├── messages.db           # SQLite message database
└── keyserver_cache.db    # Public key cache (7-day TTL)
```

**Source:** `messenger.h:1-12`, `messenger/messages.c:358-367`

### 8.2 Key Sizes

| Key Type | Public | Private | Source |
|----------|--------|---------|--------|
| Dilithium5 (signing) | 2592 bytes | 4896 bytes | `p2p_transport.h:54` |
| Kyber1024 (encryption) | 1568 bytes | 3168 bytes | `messages.c:642-648` |

### 8.3 Fingerprint Computation

```c
// Source: messenger/messages.c:155-160

uint8_t sender_fingerprint[64];
if (qgp_sha3_512(sender_sign_key->public_key,
                 QGP_DSA87_PUBLICKEYBYTES,  // 2592
                 sender_fingerprint) != 0) {
    // Error
}

// Fingerprint = SHA3-512(Dilithium5_pubkey) = 64 bytes = 128 hex chars
```

### 8.4 Keyserver Architecture

- **Primary:** DHT-based (decentralized, permanent)
- **Cache:** Local SQLite with 7-day TTL
- **Lookup:** Cache-first, then DHT query

**Source:** `messenger.h:274-321`

---

## 9. Database Schema

### 9.1 Messages Table

```sql
-- Source: message_backup.c:40-56

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  sender_fingerprint BLOB,          -- SHA3-512 fingerprint (64 bytes, v0.07)
  encrypted_message BLOB NOT NULL,  -- Encrypted ciphertext
  encrypted_len INTEGER NOT NULL,   -- Ciphertext length
  timestamp INTEGER NOT NULL,
  delivered INTEGER DEFAULT 1,
  read INTEGER DEFAULT 0,
  is_outgoing INTEGER DEFAULT 0,
  status INTEGER DEFAULT 1,         -- 0=PENDING, 1=SENT, 2=FAILED
  group_id INTEGER DEFAULT 0,       -- 0=direct message, >0=group ID
  message_type INTEGER DEFAULT 0,   -- 0=chat, 1=group_invitation
  invitation_status INTEGER DEFAULT 0  -- 0=pending, 1=accepted, 2=declined
);
```

### 9.2 Indexes

```sql
-- Source: message_backup.c:58-61

CREATE INDEX IF NOT EXISTS idx_sender ON messages(sender);
CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient);
CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sender_fingerprint ON messages(sender_fingerprint);
```

### 9.3 Message Types

| Type | Value | Description |
|------|-------|-------------|
| `MESSAGE_TYPE_CHAT` | 0 | Regular chat message |
| `MESSAGE_TYPE_GROUP_INVITATION` | 1 | Group invitation |

**Source:** `message_backup.h:32-34`

### 9.4 Invitation Status

| Status | Value | Description |
|--------|-------|-------------|
| `MESSAGE_INVITATION_STATUS_PENDING` | 0 | Awaiting response |
| `MESSAGE_INVITATION_STATUS_ACCEPTED` | 1 | Invitation accepted |
| `MESSAGE_INVITATION_STATUS_REJECTED` | 2 | Invitation declined |

**Source:** `message_backup.h:40-42`

---

## 10. Security Properties

### 10.1 Summary Table

| Property | Implementation | Source |
|----------|----------------|--------|
| **Confidentiality** | AES-256-GCM (256-bit key) | `crypto/utils/qgp_aes.h` |
| **Integrity** | AES-GCM 128-bit auth tag | `crypto/utils/qgp_aes.h:9-11` |
| **Authentication** | Dilithium5 signature (~4627 bytes) | `messages.c:121-127` |
| **Forward Secrecy** | Per-message random DEK | `messages.c:96-106` |
| **Replay Protection** | Encrypted timestamp (v0.08) | `messages.c:174-175` |
| **Identity Privacy** | Fingerprint (not pubkey) in payload | `messages.c:155-160` |
| **Post-Quantum** | NIST Level 5 (256-bit quantum) | All crypto |
| **Data Sovereignty** | Local SQLite storage | `message_backup.c` |

### 10.2 What is Protected

1. **Message Content:** AES-256-GCM encrypted, only recipients can decrypt
2. **Sender Identity:** SHA3-512 fingerprint encrypted in payload (not visible in headers)
3. **Timestamp:** Encrypted in payload (v0.08), prevents replay attacks
4. **Header Integrity:** Used as AAD, authenticated but not encrypted

### 10.3 What is NOT Protected

1. **Recipient Count:** Visible in header (recipient_count field)
2. **Message Size:** Approximate plaintext length can be inferred
3. **Traffic Analysis:** Timing and frequency of messages
4. **Metadata:** Message exists in database (even if encrypted)

### 10.4 Threat Model

| Threat | Mitigation |
|--------|------------|
| Eavesdropping | AES-256-GCM encryption |
| Man-in-the-Middle | Dilithium5 signature verification |
| Quantum Computer | Kyber1024 + Dilithium5 (NIST Level 5) |
| Message Tampering | AES-GCM authentication tag |
| Replay Attack | Encrypted timestamp (v0.08) |
| Sender Impersonation | Signature + fingerprint verification |
| Key Compromise (future) | Per-message DEK (forward secrecy) |

---

## 11. Source Code Reference

### 11.1 Core Message Files

| File | Lines | Purpose |
|------|-------|---------|
| `messenger/messages.c` | 74-307 | Multi-recipient encryption |
| `messenger/messages.c` | 309-499 | Send message flow |
| `messenger/messages.c` | 592-747 | Read/decrypt message |
| `messenger/messages.h` | 34-90 | Message API definitions |

### 11.2 Data Structures

| File | Lines | Structure |
|------|-------|-----------|
| `messenger/messages.c` | 47-55 | `messenger_enc_header_t` |
| `messenger/messages.c` | 57-60 | `messenger_recipient_entry_t` |
| `messenger.h` | 66-76 | `message_info_t` |
| `message_backup.h` | 48-61 | `backup_message_t` |
| `dna_messenger_flutter/lib/models/` | - | Flutter message models |

### 11.3 Cryptographic Functions

| File | Function | Purpose |
|------|----------|---------|
| `crypto/utils/qgp_aes.c` | `qgp_aes256_encrypt()` | AES-256-GCM encryption |
| `crypto/utils/qgp_aes.c` | `qgp_aes256_decrypt()` | AES-256-GCM decryption |
| `crypto/utils/qgp_kyber.c` | `qgp_kem1024_encapsulate()` | Kyber1024 encapsulation |
| `crypto/utils/qgp_kyber.c` | `qgp_kem1024_decapsulate()` | Kyber1024 decapsulation |
| `crypto/utils/qgp_dilithium.c` | `qgp_dsa87_sign()` | Dilithium5 signing |
| `crypto/utils/qgp_dilithium.c` | `qgp_dsa87_verify()` | Dilithium5 verification |
| `crypto/utils/qgp_sha3.c` | `qgp_sha3_512()` | SHA3-512 hashing |
| `crypto/utils/aes_keywrap.c` | `aes256_wrap_key()` | RFC 3394 key wrapping |

### 11.4 Transport Layer

| File | Lines | Purpose |
|------|-------|---------|
| `p2p/p2p_transport.h` | 1-320 | P2P transport API |
| `p2p/p2p_transport.c` | - | P2P implementation |
| `dht/shared/dht_offline_queue.h` | 1-237 | Offline queue API |
| `p2p/transport/transport_offline.c` | 64-170 | Offline message polling |

### 11.5 GSK System

| File | Lines | Purpose |
|------|-------|---------|
| `messenger/gsk.h` | 1-165 | GSK management API |
| `messenger/gsk.c` | - | GSK implementation |
| `messenger/gsk_packet.h` | 1-131 | Initial Key Packet API |
| `messenger/gsk_packet.c` | - | Packet building/extraction |

### 11.6 Database

| File | Lines | Purpose |
|------|-------|---------|
| `message_backup.h` | 1-271 | Backup API |
| `message_backup.c` | 40-68 | Schema definition |

---

## Appendix A: Example Message Sizes

| Scenario | Calculation | Total Size |
|----------|-------------|------------|
| 1 recipient, 100-char message | 22 + 1608 + 12 + 172 + 16 + 4627 | ~6,457 bytes |
| 5 recipients, 100-char message | 22 + 8040 + 12 + 172 + 16 + 4627 | ~12,889 bytes |
| 1 recipient, 1000-char message | 22 + 1608 + 12 + 1072 + 16 + 4627 | ~7,357 bytes |

## Appendix B: Version History

| Date | Version | Changes |
|------|---------|---------|
| 2025-12-24 | v0.08 | Phase 14: DHT-only messaging (P2P deprecated for messages, kept for future audio/video) |
| 2025-11-26 | v0.08 | Initial documentation from source code audit |

---

*Document generated from DNA Messenger source code analysis. All line numbers and code references verified against codebase.*
