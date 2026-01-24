# DNA Messenger - Message System Documentation

**Version:** v0.09 (Phase 14 - DHT-Only Messaging, Spillway v2)
**Last Updated:** 2026-01-16
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
7. [GEK System](#7-gek-system-group-encryption-key)
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

**Source:** `messenger/messages.c:592-747`, `transport/internal/transport_offline.c:64-170`

### 2.3 Message Status States (v15: Simplified 4-State Model)

| Status | Value | Icon | Description |
|--------|-------|------|-------------|
| `STATUS_PENDING` | 0 | Clock | Queued locally, not yet published to DHT |
| `STATUS_SENT` | 1 | Single ✓ | Successfully published to DHT |
| `STATUS_RECEIVED` | 2 | Double ✓✓ | Recipient ACK'd (fetched messages) |
| `STATUS_FAILED` | 3 | ✗ Error | Failed to publish (will auto-retry) |

**Status Flow (v15+):**
```
User sends → PENDING(0) → DHT PUT
                          ├── success → SENT(1) → [recipient fetches] → RECEIVED(2)
                          └── failure → FAILED(3) → auto-retry → PENDING(0)
```

**v15 Changes (Simple ACK System):**
- Replaced complex watermark seq_num tracking with simple ACK timestamps
- Reduced from 6 states to 4 states (removed DELIVERED, READ, STALE)
- ACK = simple timestamp per sender-recipient pair
- When recipient syncs messages, they publish an ACK timestamp
- Sender marks ALL sent messages as RECEIVED when ACK updates

**ACK System:**
- Key format: `SHA3-512(recipient + ":ack:" + sender)`
- Value: 8-byte Unix timestamp
- TTL: 30 days

**Source:** `message_backup.h` (backup_message_t), `dna_messenger_flutter/lib/ffi/dna_engine.dart`

### 2.4 Bulletproof Message Delivery (Auto-Retry)

Messages are automatically retried when send fails. This ensures messages are never lost due to transient network issues.

```
SEND ATTEMPT                     FAILURE                          RETRY TRIGGERS
    │                               │                                  │
    ▼                               │                                  │
┌─────────────────┐                 │                                  │
│ messenger_send  │                 │                                  │
│   _message()    │                 │                                  │
└────────┬────────┘                 │                                  │
         │                          │                                  │
         ▼                          │                                  │
    DHT Queue ──────► FAILED ───────┼──────────────────────────────────┤
         │                          │                                  │
         │                          ▼                                  │
         │               ┌───────────────────┐                         │
         │               │ status = FAILED   │                         │
         │               │ retry_count++     │                         │
         │               └─────────┬─────────┘                         │
         │                         │                                   │
         │                         │    ┌───────────────────────────┐  │
         │                         │    │ RETRY TRIGGERS:           │  │
         │                         │    │ • Identity load (app start)│  │
         │                         │    │ • DHT reconnect           │  │
         │                         │    │ • Network change          │  │
         │                         │    └─────────────┬─────────────┘  │
         │                         │                  │                │
         │                         │                  ▼                │
         │                         │    ┌───────────────────────────┐  │
         │                         └───►│ dna_engine_retry_pending  │  │
         │                              │   _messages()             │  │
         │                              │ Query: status IN (0,2)    │  │
         │                              │        AND retry_count<10 │  │
         │                              └─────────────┬─────────────┘  │
         │                                            │                │
         │                                            ▼                │
         │                              ┌───────────────────────────┐  │
         │                              │ For each pending message: │  │
         │                              │   Re-queue to DHT (async) │  │
         │                              │   Success → stays PENDING │  │
         │                              │   Fail → retry_count++    │  │
         │                              └───────────────────────────┘  │
         │                                                             │
         ▼                                                             │
    SUCCESS (queued to DHT) ───────────────────────────────────────────┘
    status = PENDING (until watermark confirms DELIVERED)
```

**Retry Logic:**
- **Max retries:** 10 attempts (`retry_count` column in messages table)
- **Retry triggers:** Identity load, DHT reconnect, network state change
- **Thread safety:** Mutex-protected to prevent concurrent retry calls
- **Query:** `SELECT * FROM messages WHERE is_outgoing=1 AND (status=0 OR status=2) AND retry_count < 10`
- **On success:** Status stays PENDING (0), awaiting watermark confirmation → DELIVERED (3)
- **On failure:** `retry_count` incremented, status remains FAILED (2)

**Database Schema (v10):**
```sql
ALTER TABLE messages ADD COLUMN retry_count INTEGER DEFAULT 0;
```

Note: v9 added GEK group tables (groups, group_members, group_geks, pending_invitations, group_messages).

**Source:** `message_backup.c:644-721`, `src/api/dna_engine.c:4862-4920`

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
    uint8_t message_type;       // MSG_TYPE_DIRECT_PQC or MSG_TYPE_GROUP_GEK
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
│  • transport_register_presence() - Used for presence only                               │
│  • TCP direct delivery - Bypassed for messages                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Source:** `messenger/messages.c:463-491`, `messenger_transport.c:780-838`

### 6.2 Port Configuration

| Port | Protocol | Purpose |
|------|----------|---------|
| 4000 | UDP | DHT Network (OpenDHT-PQ) |
| 4001 | TCP | P2P Messaging |

**Source:** `transport/transport.h:20-25`

### 6.3 DHT Offline Queue (Spillway Protocol v2 - Daily Buckets)

**Spillway Protocol v2** = Sender-Based Outbox with Daily Buckets (v0.5.0+)

**Source:** `dht/shared/dht_dm_outbox.h`, `dht/shared/dht_dm_outbox.c`

```
┌─────────────────────────────────────────────────────────────────────────────┐
│             SPILLWAY PROTOCOL v2: DAILY BUCKET OUTBOX (v0.5.0+)             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  KEY FORMAT:                                                                │
│  ───────────                                                                │
│  key = sender_fp:outbox:recipient_fp:DAY_BUCKET                             │
│                                                                             │
│  where DAY_BUCKET = unix_timestamp / 86400 (days since epoch)               │
│                                                                             │
│  Example (2026-01-16, day 20470):                                           │
│    alice_fp:outbox:bob_fp:20470  (today's messages)                         │
│    alice_fp:outbox:bob_fp:20469  (yesterday's messages)                     │
│                                                                             │
│  STORAGE:                                                                   │
│  ────────                                                                   │
│  ┌────────────────────────────────────────────────────────────┐             │
│  │ dht_chunked_publish(key, messages)                         │             │
│  │                                                             │             │
│  │ - Uses Dilithium5 signature for authentication             │             │
│  │ - Chunked storage (supports large message lists)           │             │
│  │ - TTL: 7 days (auto-expire, no pruning needed)             │             │
│  │ - Max 500 messages per day bucket (DoS prevention)         │             │
│  └────────────────────────────────────────────────────────────┘             │
│                                                                             │
│  SYNC STRATEGY (3-day parallel):                                            │
│  ───────────────────────────────                                            │
│  ┌────────────────────────────────────────────────────────────┐             │
│  │ Recent sync: yesterday + today + tomorrow (clock skew)     │             │
│  │ Full sync:   last 8 days (today-6 to today+1)              │             │
│  │                                                             │             │
│  │ FOR each contact:                                           │             │
│  │   parallel_fetch(day-1, day, day+1)  // 3 days in parallel │             │
│  │   merge_and_deduplicate(messages)                          │             │
│  └────────────────────────────────────────────────────────────┘             │
│                                                                             │
│  LISTEN & DAY ROTATION:                                                     │
│  ───────────────────────                                                    │
│  ┌────────────────────────────────────────────────────────────┐             │
│  │ 1. Subscribe to contact's today bucket                     │             │
│  │ 2. Heartbeat checks day rotation every 4 minutes           │             │
│  │ 3. At midnight UTC: rotate to new day's bucket             │             │
│  │ 4. Sync yesterday one more time (catch late messages)      │             │
│  └────────────────────────────────────────────────────────────┘             │
│                                                                             │
│  ACK SYSTEM (v15: replaces watermarks):                                     │
│  ───────────────────────────────────────                                    │
│  - ACK Key: SHA3-512(recipient + ":ack:" + sender)                          │
│  - ACK TTL: 30 days                                                         │
│  - Used for: RECEIVED status notifications (per-contact, not per-message)   │
│  - Simplified: single timestamp instead of per-message seq_num tracking     │
│                                                                             │
│  BENEFITS vs v1:                                                            │
│  ───────────────                                                            │
│  ✓ No watermark pruning needed (TTL auto-expire)                            │
│  ✓ Bounded storage (max 500 msgs/day × 7 days = 3500 max)                   │
│  ✓ Parallel sync (3 days fetched simultaneously)                            │
│  ✓ Clock-skew tolerant (+/- 1 day buffer)                                   │
│  ✓ Consistent with group outbox architecture                                │
│  ✓ Simpler implementation (no read-modify-write for pruning)                │
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
- seq_num:   Monotonic per sender-recipient pair (for ordering and delivery confirmation)
- timestamp: Unix timestamp when queued (for display only)
- expiry:    Unix timestamp when message expires
```

---

## 7. GEK System (Group Encryption Key)

### 7.1 Purpose

GEK provides **200× faster** group message encryption compared to per-recipient Kyber1024.

Instead of:
- N members × Kyber1024 encapsulation = N × 1608 bytes per message

GEK uses:
- 1 AES-256-GCM encryption with shared key = same ciphertext for all members

**Source:** `messenger/gek.h`

### 7.2 GEK Entry Structure

```c
// Source: messenger/gek.h

typedef struct {
    char group_uuid[37];       // UUID v4 (36 + null terminator)
    uint32_t gek_version;      // Unix timestamp (v0.6.39+), was incremental counter (0,1,2...)
    uint8_t gek[GEK_KEY_SIZE]; // AES-256 key (32 bytes)
    uint64_t created_at;       // Unix timestamp (seconds)
    uint64_t expires_at;       // created_at + GEK_DEFAULT_EXPIRY
} gek_entry_t;

#define GEK_KEY_SIZE 32                    // AES-256
#define GEK_DEFAULT_EXPIRY (7 * 24 * 3600) // 7 days
```

### 7.3 Initial Key Packet Format

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      INITIAL KEY PACKET (GEK Distribution)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  HEADER (45 bytes)                                                          │
│  ┌───────┬──────────┬──────────────────────────────────────────────────┐   │
│  │  0    │    4     │ magic (0x47454B20 = "GEK ")                      │   │
│  │  4    │   36     │ group_uuid[36] (UUID v4)                         │   │
│  │  40   │    4     │ version (uint32_t, GEK version number)           │   │
│  │  44   │    1     │ member_count (uint8_t, 1-16)                     │   │
│  └───────┴──────────┴──────────────────────────────────────────────────┘   │
│                                                                             │
│  MEMBER ENTRIES (1672 bytes × member_count)                                 │
│  ┌───────┬──────────┬──────────────────────────────────────────────────┐   │
│  │  0    │   64     │ fingerprint[64] (SHA3-512 of member's pubkey)    │   │
│  │  64   │  1568    │ kyber_ciphertext[1568] (Kyber1024 encapsulation) │   │
│  │ 1632  │   40     │ wrapped_gek[40] (AES-wrapped GEK)                │   │
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
│  TOTAL SIZE: 45 + (1672 × N) + 4630 bytes                                  │
│                                                                             │
│  Example for 10 members: 45 + 16720 + 4630 = 21,395 bytes                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Source:** `messenger/gek.h` (IKP constants)

### 7.4 GEK Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GEK LIFECYCLE                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. GROUP CREATION                                                          │
│     ─────────────────                                                       │
│     ┌─────────────────────────────────────────────────┐                    │
│     │ gek_generate(group_uuid, version=0, gek)        │                    │
│     │ gek_store(group_uuid, 0, gek)                   │                    │
│     │ ikp_build(...) → Initial Key Packet             │                    │
│     │ DHT publish packet to all members               │                    │
│     └─────────────────────────────────────────────────┘                    │
│                                                                             │
│  2. MEMBER ADDED                                                            │
│     ────────────────                                                        │
│     ┌─────────────────────────────────────────────────┐                    │
│     │ gek_rotate_on_member_add()                      │                    │
│     │   - Generate new GEK (version++)                │                    │
│     │   - Build new Initial Key Packet (all members)  │                    │
│     │   - Publish to DHT                              │                    │
│     └─────────────────────────────────────────────────┘                    │
│                                                                             │
│  3. MEMBER REMOVED                                                          │
│     ───────────────                                                         │
│     ┌─────────────────────────────────────────────────┐                    │
│     │ gek_rotate_on_member_remove()                   │                    │
│     │   - Generate new GEK (version++)                │  CRITICAL:         │
│     │   - Build new Initial Key Packet (WITHOUT       │  Removed member    │
│     │     removed member)                             │  cannot decrypt    │
│     │   - Publish to DHT                              │  future messages   │
│     └─────────────────────────────────────────────────┘                    │
│                                                                             │
│  4. GEK EXPIRATION (7 days)                                                 │
│     ───────────────────────                                                 │
│     ┌─────────────────────────────────────────────────┐                    │
│     │ gek_cleanup_expired() - removes old GEKs        │                    │
│     │ Auto-rotate if needed for continued messaging   │                    │
│     └─────────────────────────────────────────────────┘                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Source:** `messenger/gek.h`

#### GEK Fetching (Invitee/Recovery)

When a user accepts a group invitation or needs to recover GEK after reinstall:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  GEK FETCH FLOW (v0.4.64+)                                                  │
│                                                                             │
│  1. Fetch group metadata from DHT: hash(group_uuid)                         │
│     → Metadata contains gek_version field                                   │
│                                                                             │
│  2. Fetch IKP (Initial Key Packet) for that specific version:               │
│     → dht_gek_fetch(group_uuid, gek_version)                                │
│                                                                             │
│  3. Extract GEK using user's Kyber private key:                             │
│     → ikp_extract(ikp, kyber_sk, gek_out)                                   │
│                                                                             │
│  4. Store GEK locally for message encryption/decryption                     │
│                                                                             │
│  NOTE: Prior to v0.4.64, the code tried versions 0-9 sequentially,          │
│        which could fail if the correct version was > 9 or if an earlier     │
│        version was found first.                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Flutter API:** `syncGroup(uuid)` triggers this flow for GEK recovery.

**Source:** `messenger_groups.c:messenger_sync_group_gek()`

### 7.5 Group Outbox DHT Storage (Single-Key Multi-Writer)

Group messages use a single-key multi-writer architecture where ALL members write to the SAME DHT key with different `value_id`s.

#### Key Format

```
dna:group:<uuid>:out:<day>

Where:
  <uuid>       = Group UUID (36 chars)
  <day>        = Day bucket (Unix timestamp / 86400)

Example:
  dna:group:550e8400-e29b-41d4-a716-446655440000:out:20089
```

#### Architecture Benefits

| Aspect | Single-Key Multi-Writer |
|--------|-------------------------|
| Listeners per group | 1 (not N per member) |
| Max groups (1024 limit) | 1024 (vs ~50 with per-sender) |
| Writer isolation | `value_id` per sender |
| Storage | Chunked ZSTD (unlimited size) |
| Real-time | Single `dht_listen()` per group |
| Member changes | Automatic (no resubscription) |

#### Multi-Writer DHT Model

```
All members write to same key with unique value_id:

Key: dna:group:<uuid>:out:<day>
  ├── Writer A (value_id=A) → [A's messages JSON]
  ├── Writer B (value_id=B) → [B's messages JSON]
  └── Writer C (value_id=C) → [C's messages JSON]

dht_get_all_with_ids() returns:
  [(data_A, id_A), (data_B, id_B), (data_C, id_C)]
```

#### Send Flow

```
User sends message
       │
       ▼
┌─────────────────────────────────────┐
│ 1. Load GEK (auto-sync from DHT)    │
│ 2. day = time() / 86400             │
│ 3. Generate message_id              │
│ 4. Encrypt with GEK (AES-256-GCM)   │
│ 5. Sign with Dilithium5             │
└─────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│ 6. group_key = dna:group:<uuid>     │
│         :out:<day>                  │
│ 7. dht_chunked_fetch_mine(key)      │
│    → Filter by MY value_id          │
│ 8. Append new message to my bucket  │
│ 9. dht_chunked_publish(key, bucket) │
│    → Uses MY value_id (replaces)    │
└─────────────────────────────────────┘
       │
       ▼
   Store locally
```

#### Listen Flow

```
Group loaded
    │
    ▼
┌─────────────────────────────────────┐
│ group_key = dna:group:<uuid>        │
│         :out:<day>                  │
│ chunk0_key = SHA3(key+":chunk:0")   │
│ dht_listen(chunk0_key, callback)    │
│                                     │
│ → SINGLE listener for ALL members   │
│ → Fires when ANY member publishes   │
└─────────────────────────────────────┘
    │
    ▼
[Callback fires]
    │
    ▼
┌─────────────────────────────────────┐
│ 1. dht_chunked_fetch_all(group_key) │
│    → Gets ALL senders' buckets      │
│ 2. Merge messages from all senders  │
│ 3. Dedupe by message_id             │
│ 4. Decrypt and store new messages   │
│ 5. Fire UI callback                 │
└─────────────────────────────────────┘
```

#### Day Rotation (Midnight UTC)

```
Every 4 minutes (heartbeat timer)
         │
         ▼
┌─────────────────────────────────────┐
│ new_day = time() / 86400            │
│ if new_day != current_day:          │
│   Cancel 1 listener (old day)       │
│   Subscribe 1 listener (new day)    │
└─────────────────────────────────────┘
```

#### Sync (Catch-up)

On group load, syncs last 7 days of messages:

```c
for (day = last_sync_day + 1; day <= current_day; day++) {
    dht_chunked_fetch_all(group_key_for_day)
    // → Gets ALL senders' messages at once
    decrypt and store new messages
}
```

#### Multi-Chunk Multi-Writer Handling

When a sender's data exceeds 45KB, `dht_chunked_fetch_all()` uses `value_id` to group chunks:

```
Key: chunk0 of group_key
  ├── Writer A chunk0 (value_id=A, total_chunks=3)
  └── Writer B chunk0 (value_id=B, total_chunks=1)

For Writer A (multi-chunk):
  1. Fetch chunk1 key → get all values with ids
  2. Filter by value_id=A
  3. Repeat for chunk2
  4. Assemble and decompress
```

**Source:** `dht/client/dna_group_outbox.c`, `src/api/dna_engine.c`

---

## 8. Key Management

### 8.1 Key File Locations

```
~/.dna/
├── keys/
│   └── identity.dsa      # Dilithium5 private key (4896 bytes)
│   └── identity.kem      # Kyber1024 private key (3168 bytes)
├── db/
│   ├── messages.db       # SQLite - Direct messages only (v0.4.63+)
│   ├── groups.db         # SQLite - All group data (v0.4.63+)
│   └── keyserver_cache.db    # Public key cache (7-day TTL)
└── ...
```

**Database Separation (v0.4.63):**
- **messages.db**: Direct user-to-user messages only
- **groups.db**: Groups, members, GEKs, invitations, group messages

**Source:** `messenger.h:1-12`, `messenger/messages.c:358-367`

### 8.2 Key Sizes

| Key Type | Public | Private | Source |
|----------|--------|---------|--------|
| Dilithium5 (signing) | 2592 bytes | 4896 bytes | `transport/transport.h` |
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

**v0.4.63+ Architecture:** Two separate databases for clean separation:
- **messages.db**: Direct user-to-user messages (`message_backup.c`)
- **groups.db**: All group data (`messenger/group_database.c`)

### 9.1 Messages Table (messages.db)

```sql
-- Source: message_backup.c - Schema v14
-- NOTE: v14 stores plaintext directly (no per-message encryption)
--       Database encryption handled by SQLCipher in future update

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  sender_fingerprint TEXT,          -- SHA3-512 fingerprint (128 hex chars, v14)
  plaintext TEXT NOT NULL,          -- Decrypted message content (v14)
  timestamp INTEGER NOT NULL,
  delivered INTEGER DEFAULT 1,
  read INTEGER DEFAULT 0,
  is_outgoing INTEGER DEFAULT 0,
  status INTEGER DEFAULT 1,         -- 0=PENDING, 1=SENT(legacy), 2=FAILED, 3=DELIVERED, 4=READ, 5=STALE
  group_id INTEGER DEFAULT 0,       -- 0=direct message, >0=group ID
  message_type INTEGER DEFAULT 0,   -- 0=chat, 1=group_invitation
  invitation_status INTEGER DEFAULT 0,  -- 0=pending, 1=accepted, 2=declined
  retry_count INTEGER DEFAULT 0,    -- Retry attempts for failed messages
  offline_seq INTEGER DEFAULT 0     -- DHT offline queue sequence number
);
```

**Breaking Change (v14):** Schema v14 is incompatible with v13 and earlier.
- Old `encrypted_message BLOB` replaced with `plaintext TEXT`
- Migration: Old messages table dropped, fresh start required
- Transport encryption (DHT) remains unchanged - only storage changed

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

### 9.5 Groups Database Schema (groups.db)

**Added in v0.4.63** - All group data moved to separate database.

```sql
-- Source: messenger/group_database.c:48-96

-- Core group metadata
CREATE TABLE IF NOT EXISTS groups (
  uuid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  is_owner INTEGER DEFAULT 0,
  owner_fp TEXT NOT NULL
);

-- Group members
CREATE TABLE IF NOT EXISTS group_members (
  group_uuid TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  added_at INTEGER NOT NULL,
  PRIMARY KEY (group_uuid, fingerprint)
);

-- Group Encryption Keys (GEK) per version
CREATE TABLE IF NOT EXISTS group_geks (
  group_uuid TEXT NOT NULL,
  version INTEGER NOT NULL,
  encrypted_key BLOB NOT NULL,   -- Kyber1024-encrypted (1628 bytes)
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (group_uuid, version)
);

-- Pending group invitations
CREATE TABLE IF NOT EXISTS pending_invitations (
  group_uuid TEXT PRIMARY KEY,
  group_name TEXT NOT NULL,
  owner_fp TEXT NOT NULL,
  received_at INTEGER NOT NULL
);

-- Decrypted group message cache
CREATE TABLE IF NOT EXISTS group_messages (
  id INTEGER PRIMARY KEY,
  group_uuid TEXT NOT NULL,
  message_id INTEGER NOT NULL,
  sender_fp TEXT NOT NULL,
  timestamp_ms INTEGER NOT NULL,
  gek_version INTEGER NOT NULL,
  plaintext TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  UNIQUE (group_uuid, sender_fp, message_id)
);
```

**Source:** `messenger/group_database.c`

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
| `transport/transport.h` | 1-320 | P2P transport API |
| `transport/transport.c` | - | P2P implementation |
| `dht/shared/dht_offline_queue.h` | 1-237 | Offline queue API |
| `transport/internal/transport_offline.c` | 64-170 | Offline message polling |

### 11.5 GEK System

| File | Lines | Purpose |
|------|-------|---------|
| `messenger/gek.h` | 1-399 | GEK management + IKP API |
| `messenger/gek.c` | - | GEK implementation |
| `messenger/groups.h` | 1-266 | Group management API |
| `messenger/groups.c` | - | Group implementation |

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
