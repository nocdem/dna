# DNA Messenger - Protocol Specifications

**Version:** 1.0
**Last Updated:** 2025-12-12
**Security Level:** NIST Category 5 (256-bit quantum)

This document specifies all wire formats and protocols used by DNA Messenger.

---

## Protocol Summary

| Protocol | Version | Purpose |
|----------|---------|---------|
| **Seal Protocol** | v0.08 | E2E encrypted message envelope |
| **Spillway Protocol** | v2 | Offline delivery with watermark pruning |
| **Anchor Protocol** | v1 | Unified identity in DHT |
| **Atlas Protocol** | v1 | DHT key derivation scheme |
| **Nexus Protocol** | v1 | Group symmetric key encryption |

---

## Table of Contents

1. [Cryptographic Primitives](#1-cryptographic-primitives)
2. [Seal Protocol](#2-seal-protocol) - Message Encryption
3. [Spillway Protocol](#3-spillway-protocol) - Offline Delivery
4. [Anchor Protocol](#4-anchor-protocol) - Unified Identity
5. [Atlas Protocol](#5-atlas-protocol) - DHT Key Derivation
6. [Nexus Protocol](#6-nexus-protocol) - Group Encryption
7. [Signature Format](#7-signature-format)
8. [Key File Formats](#8-key-file-formats)

---

## 1. Cryptographic Primitives

All protocols use NIST Category 5 post-quantum cryptography.

| Algorithm | Standard | Purpose | Sizes |
|-----------|----------|---------|-------|
| **ML-KEM-1024** | FIPS 203 (Kyber1024) | Key Encapsulation | Pub: 1568, Priv: 3168, CT: 1568, SS: 32 |
| **ML-DSA-87** | FIPS 204 (Dilithium5) | Digital Signatures | Pub: 2592, Priv: 4896, Sig: ~4627 |
| **AES-256-GCM** | FIPS 197 + SP 800-38D | Symmetric Encryption | Key: 32, Nonce: 12, Tag: 16 |
| **SHA3-512** | FIPS 202 | Fingerprints/Hashing | Output: 64 bytes |
| **AES Key Wrap** | RFC 3394 | DEK Protection | KEK: 32, Wrapped: 40 |

**Source:** `crypto/utils/qgp_types.h`

---

## 2. Seal Protocol

*Sealed envelope for E2E encrypted messages*

### 2.1 Overview

The Seal Protocol defines the wire format for encrypted messages. Each message is a "sealed envelope" containing:
- Encrypted payload (fingerprint + timestamp + plaintext)
- Per-recipient key encapsulation (Kyber1024)
- Digital signature (Dilithium5)

### 2.2 Wire Format (v0.08)

```
+-----------------------------------------------------------------------------+
|                         SEAL PROTOCOL v0.08                                  |
+-----------------------------------------------------------------------------+

  HEADER (20 bytes, unencrypted)
  +--------+--------+-----------------------------------------------------+
  | Offset |  Size  | Field                                               |
  +--------+--------+-----------------------------------------------------+
  |   0    |    8   | magic[8] = "PQSIGENC"                               |
  |   8    |    1   | version = 0x08                                      |
  |   9    |    1   | enc_key_type = 2 (KEM1024)                          |
  |  10    |    1   | recipient_count (1-255)                             |
  |  11    |    1   | message_type (0=direct, 1=nexus)                    |
  |  12    |    4   | encrypted_size (uint32_t LE)                        |
  |  16    |    4   | signature_size (uint32_t LE)                        |
  +--------+--------+-----------------------------------------------------+

  RECIPIENT ENTRIES (1608 bytes x recipient_count)
  +--------+--------+-----------------------------------------------------+
  |   0    |  1568  | kyber_ciphertext[1568] (ML-KEM-1024)                |
  | 1568   |   40   | wrapped_dek[40] (AES-wrapped DEK)                   |
  +--------+--------+-----------------------------------------------------+

  NONCE (12 bytes)
  +--------+--------+-----------------------------------------------------+
  |   0    |   12   | nonce[12] (random per-message)                      |
  +--------+--------+-----------------------------------------------------+

  ENCRYPTED PAYLOAD (encrypted_size bytes, AES-256-GCM)
  Decrypted content:
  +--------+--------+-----------------------------------------------------+
  |   0    |   64   | sender_fingerprint[64] (SHA3-512)                   |
  |  64    |    8   | timestamp (uint64_t BE, Unix epoch)                 |
  |  72    |  var   | plaintext (UTF-8 message)                           |
  +--------+--------+-----------------------------------------------------+

  AUTH TAG (16 bytes)
  +--------+--------+-----------------------------------------------------+
  |   0    |   16   | tag[16] (AES-GCM authentication tag)                |
  +--------+--------+-----------------------------------------------------+

  SIGNATURE (signature_size bytes, ~4627)
  +--------+--------+-----------------------------------------------------+
  |   0    |  var   | dilithium_signature (~4595-4627 bytes)              |
  +--------+--------+-----------------------------------------------------+
```

### 2.3 C Structures

```c
// Header (20 bytes)
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x08
    uint8_t enc_key_type;       // 2 (KEM1024)
    uint8_t recipient_count;    // 1-255
    uint8_t message_type;       // 0=direct (Seal), 1=group (Nexus)
    uint32_t encrypted_size;    // Little-endian
    uint32_t signature_size;    // Little-endian
} messenger_enc_header_t;

// Recipient entry (1608 bytes)
typedef struct {
    uint8_t kyber_ciphertext[1568];  // ML-KEM-1024 ciphertext
    uint8_t wrapped_dek[40];         // AES-wrapped DEK (32+8)
} messenger_recipient_entry_t;

// Message types
typedef enum {
    MSG_TYPE_SEAL  = 0x00,  // Per-recipient Kyber1024 (Seal Protocol)
    MSG_TYPE_NEXUS = 0x01   // Group symmetric key (Nexus Protocol)
} message_type_t;
```

### 2.4 Size Calculation

```
Total = 20 + (1608 x N) + 12 + encrypted_size + 16 + signature_size

Example (1 recipient, 100-byte plaintext):
  Header:      20 bytes
  Recipients:  1608 bytes
  Nonce:       12 bytes
  Encrypted:   172 bytes (64 + 8 + 100)
  Tag:         16 bytes
  Signature:   ~4627 bytes
  -----------------------
  Total:       ~6455 bytes
```

### 2.5 Encryption Process

1. Generate random 32-byte DEK (Data Encryption Key)
2. Sign plaintext with sender's Dilithium5 key
3. Compute sender fingerprint: `SHA3-512(dilithium_pubkey)`
4. Build payload: `fingerprint || timestamp_be || plaintext`
5. Encrypt payload with AES-256-GCM (header as AAD)
6. For each recipient:
   - ML-KEM-1024 encapsulate -> KEK + ciphertext
   - AES Key Wrap DEK with KEK -> wrapped_dek
7. Assemble: `header || recipients || nonce || ciphertext || tag || signature`

### 2.6 Version History

| Version | Changes |
|---------|---------|
| v0.07 | Added fingerprint inside encrypted payload (identity privacy) |
| v0.08 | Added encrypted timestamp (replay protection) |

**Source:** `messenger/messages.c`

---

## 3. Spillway Protocol

*Offline message delivery with watermark-based pruning*

### 3.1 Overview

The Spillway Protocol manages offline message delivery using a sender-based outbox model with watermark pruning. Like a dam spillway that controls water level, the watermark tells senders which messages have been received so they can prune delivered messages.

### 3.2 Architecture

```
+-----------------------------------------------------------------------------+
|                         SPILLWAY PROTOCOL                                    |
+-----------------------------------------------------------------------------+

  SENDER OUTBOX MODEL:
  Each sender maintains ONE outbox per recipient in DHT

  Outbox Key: SHA3-512(sender_fp + ":outbox:" + recipient_fp)
  Value:      Serialized message array
  TTL:        7 days
  Put Type:   Signed (value_id=1, enables replacement)

  WATERMARK PRUNING:
  Recipients publish highest seq_num received per sender

  Watermark Key: SHA3-512(recipient_fp + ":watermark:" + sender_fp)
  Value:         8-byte seq_num (big-endian)
  TTL:           30 days

  FLOW:
  +-------------------------------------------------------------------+
  | 1. Alice sends msg to Bob (seq=3)                                  |
  |    -> Alice fetches Bob's watermark (seq=2)                        |
  |    -> Alice prunes seq<=2 from outbox                              |
  |    -> Alice appends seq=3, publishes to DHT                        |
  |                                                                    |
  | 2. Bob comes online                                                |
  |    -> Bob queries Alice's outbox (finds seq=3)                     |
  |    -> Bob publishes watermark: seq=3                               |
  |                                                                    |
  | 3. Alice sends next msg (seq=4)                                    |
  |    -> Alice fetches watermark (seq=3)                              |
  |    -> Alice prunes seq<=3 (removes seq=3)                          |
  |    -> Outbox now contains only seq=4                               |
  +-------------------------------------------------------------------+
```

### 3.3 Message Wire Format (v2)

```
+-----------------------------------------------------------------------------+
|                    SPILLWAY MESSAGE FORMAT v2                                |
+-----------------------------------------------------------------------------+

  +--------+--------+-----------------------------------------------------+
  | Offset |  Size  | Field                                               |
  +--------+--------+-----------------------------------------------------+
  |   0    |    4   | magic = "DNA " (0x444E4120)                         |
  |   4    |    1   | version = 2                                         |
  |   5    |    8   | seq_num (uint64_t BE) - monotonic per pair          |
  |  13    |    8   | timestamp (uint64_t BE) - Unix epoch                |
  |  21    |    8   | expiry (uint64_t BE) - Unix epoch                   |
  |  29    |    2   | sender_len (uint16_t BE)                            |
  |  31    |    2   | recipient_len (uint16_t BE)                         |
  |  33    |    4   | ciphertext_len (uint32_t BE)                        |
  |  37    |  var   | sender (fingerprint string, 128 chars)              |
  |  var   |  var   | recipient (fingerprint string, 128 chars)           |
  |  var   |  var   | ciphertext (Seal Protocol encrypted message)        |
  +--------+--------+-----------------------------------------------------+

  Header size: 37 bytes (fixed)
  Total size: 37 + sender_len + recipient_len + ciphertext_len
```

### 3.4 C Structure

```c
typedef struct {
    uint64_t seq_num;         // Monotonic per sender-recipient pair
    uint64_t timestamp;       // Unix timestamp (for display)
    uint64_t expiry;          // Unix timestamp (when expires)
    char *sender;             // Sender fingerprint (128 hex chars)
    char *recipient;          // Recipient fingerprint (128 hex chars)
    uint8_t *ciphertext;      // Seal Protocol encrypted message
    size_t ciphertext_len;    // Ciphertext length
} dht_offline_message_t;
```

### 3.5 Constants

```c
#define DHT_SPILLWAY_MAGIC         0x444E4120  // "DNA "
#define DHT_SPILLWAY_VERSION       2
#define DHT_SPILLWAY_DEFAULT_TTL   604800      // 7 days
#define DHT_SPILLWAY_WATERMARK_TTL (30 * 24 * 3600)  // 30 days
```

### 3.6 Version History

| Version | Changes |
|---------|---------|
| v1 | Initial: timestamp, expiry, sender, recipient, ciphertext |
| v2 | Added seq_num for watermark pruning (clock-skew immune) |

**Source:** `dht/shared/dht_offline_queue.h`, `dht/shared/dht_offline_queue.c`

---

## 4. Anchor Protocol

*Unified identity anchored in DHT*

### 4.1 Overview

The Anchor Protocol defines the format for user identities stored in DHT. Each identity is an "anchor" - a stable reference point containing cryptographic keys, profile data, and metadata.

### 4.2 Structure

```c
typedef struct {
    // ===== MESSENGER KEYS =====
    char fingerprint[129];           // SHA3-512 hex (128 chars + null)
    uint8_t dilithium_pubkey[2592];  // ML-DSA-87 public key
    uint8_t kyber_pubkey[1568];      // ML-KEM-1024 public key

    // ===== DNA NAME REGISTRATION =====
    bool has_registered_name;        // true if name registered
    char registered_name[256];       // DNA name (e.g., "alice")
    uint64_t name_registered_at;     // Registration timestamp
    uint64_t name_expires_at;        // Expiration (+365 days)
    uint32_t name_version;           // Version (increment on renewal)

    // ===== PROFILE DATA =====
    char display_name[128];          // Display name
    char bio[512];                   // User bio
    char avatar_hash[128];           // SHA3-512 of avatar
    char avatar_base64[20484];       // Base64 avatar (64x64 PNG)
    char location[128];              // Geographic location
    char website[256];               // Personal website

    dna_wallets_t wallets;           // Wallet addresses
    dna_socials_t socials;           // Social profiles

    // ===== METADATA =====
    uint64_t created_at;             // Profile creation
    uint64_t updated_at;             // Last update
    uint64_t timestamp;              // Entry timestamp
    uint32_t version;                // Entry version

    // ===== SIGNATURE =====
    uint8_t signature[4627];         // Dilithium5 signature
} dna_unified_identity_t;
```

### 4.3 Wallet Addresses

```c
typedef struct {
    // Cellframe networks
    char backbone[120];     // Backbone address
    char alvin[120];        // Alvin testnet

    // External blockchains
    char btc[128];          // Bitcoin
    char eth[128];          // Ethereum (also BSC, Polygon)
    char sol[128];          // Solana
    char trx[128];          // TRON
} dna_wallets_t;
```

### 4.4 Social Profiles

```c
typedef struct {
    char telegram[128];
    char x[128];            // Twitter/X
    char github[128];
    char facebook[128];
    char instagram[128];
    char linkedin[128];
    char google[128];
} dna_socials_t;
```

### 4.5 Serialization

- **Format:** JSON
- **Size:** ~25-30 KB serialized
- **Signature:** Computed over JSON without signature field
- **TTL:** 365 days

### 4.6 Fingerprint Derivation

```
fingerprint = hex(SHA3-512(dilithium_pubkey))
            = 128 hex characters (64 bytes binary)
```

**Source:** `dht/client/dna_profile.h`, `dht/client/dna_profile.c`

---

## 5. Atlas Protocol

*DHT key derivation - mapping data to locations*

### 5.1 Overview

The Atlas Protocol defines how DHT keys are derived from identities and data types. Like an atlas maps coordinates to locations, this protocol maps fingerprints and identifiers to 64-byte DHT keys.

### 5.2 Key Derivation Formula

All keys are 64-byte SHA3-512 hashes:

```
key = SHA3-512(base_string)
```

### 5.3 Key Formats

| Data Type | Base String | TTL |
|-----------|-------------|-----|
| **Presence** | `{fingerprint}` | 7 days |
| **Outbox** | `{sender}:outbox:{recipient}` | 7 days |
| **Watermark** | `{recipient}:watermark:{sender}` | 30 days |
| **Profile** | `{fingerprint}:profile` | 365 days |
| **Name Lookup** | `{name}:lookup` | 365 days |
| **Contact Requests** | `{fingerprint}:requests` | 7 days |
| **Contact List** | `{fingerprint}:contactlist` | 7 days |

### 5.4 Examples

```c
// Presence key for user with fingerprint "abc123..."
key = SHA3-512("abc123...")

// Outbox key for Alice sending to Bob
key = SHA3-512("alice_fp:outbox:bob_fp")

// Watermark key (Bob's watermark for Alice's messages)
key = SHA3-512("bob_fp:watermark:alice_fp")

// Profile lookup by fingerprint
key = SHA3-512("abc123...:profile")

// Name lookup (case-insensitive, lowercase)
key = SHA3-512("alice:lookup")
```

### 5.5 C Functions

```c
// Generate outbox key (Spillway Protocol)
void dht_generate_outbox_key(
    const char *sender,      // 128-char fingerprint
    const char *recipient,   // 128-char fingerprint
    uint8_t *key_out         // 64-byte output
);

// Generate watermark key (Spillway Protocol)
void dht_generate_watermark_key(
    const char *recipient,   // Watermark owner
    const char *sender,      // Message sender
    uint8_t *key_out         // 64-byte output
);
```

**Source:** `dht/shared/dht_offline_queue.c`, `dht/keyserver/keyserver_core.h`

---

## 6. Nexus Protocol

*Group symmetric key - connection point for groups*

### 6.1 Overview

The Nexus Protocol provides efficient group encryption using a shared symmetric key. Like a nexus (connection point), all group members connect through a shared secret that enables ~200x faster encryption than per-recipient Kyber.

### 6.2 GSK (Group Symmetric Key)

- **Key Size:** 32 bytes (AES-256)
- **Generation:** Random on group creation
- **Distribution:** Kyber1024 encrypted per-member on join
- **Storage:** Encrypted in local SQLite

### 6.3 Message Format

Uses Seal Protocol with `message_type = 0x01`:

```
Header:
  message_type = MSG_TYPE_NEXUS (0x01)
  recipient_count = 1

Recipient Entry:
  kyber_ciphertext = zeros (not used)
  wrapped_dek = AES-wrap(DEK, GSK)  // GSK as KEK
```

### 6.4 Key Rotation

| Event | Action |
|-------|--------|
| Member joins | Encrypt current GSK with new member's Kyber pubkey |
| Member leaves | Generate new GSK, distribute to remaining members |
| Key compromise | Generate new GSK, distribute to all members |

### 6.5 Forward Secrecy

- New GSK on member removal
- Old members cannot decrypt new messages
- Per-message DEK provides forward secrecy within sessions

### 6.6 Performance

| Method | Encryption Time | Size Overhead |
|--------|-----------------|---------------|
| Seal (per-recipient) | ~50ms/recipient | 1608 bytes/recipient |
| Nexus (GSK) | ~0.25ms total | 40 bytes fixed |

**Source:** `messenger/gsk.c`, `messenger/gsk.h`

---

## 7. Signature Format

### 7.1 Wire Format (v0.07+)

```
+-----------------------------------------------------------------------------+
|                         SIGNATURE BLOCK                                      |
+-----------------------------------------------------------------------------+

  +--------+--------+-----------------------------------------------------+
  | Offset |  Size  | Field                                               |
  +--------+--------+-----------------------------------------------------+
  |   0    |    1   | type = 1 (DILITHIUM)                                |
  |   1    |    2   | signature_size (uint16_t, ~4627)                    |
  |   3    |  var   | signature bytes                                     |
  +--------+--------+-----------------------------------------------------+

  Total size: 3 + signature_size

  Note: v0.07+ removed embedded public key (lookup via fingerprint)
```

### 7.2 C Structure

```c
typedef enum {
    QGP_SIG_TYPE_INVALID   = 0,
    QGP_SIG_TYPE_DILITHIUM = 1
} qgp_sig_type_t;

typedef struct {
    qgp_sig_type_t type;      // QGP_SIG_TYPE_DILITHIUM (1)
    uint16_t public_key_size; // 0 in v0.07+ (pubkey not embedded)
    uint16_t signature_size;  // ~4627 for Dilithium5
    uint8_t *data;            // Signature bytes
} qgp_signature_t;
```

**Source:** `crypto/utils/qgp_types.h`

---

## 8. Key File Formats

### 8.1 Private Key File

```
+-----------------------------------------------------------------------------+
|                      PRIVATE KEY FILE FORMAT                                 |
+-----------------------------------------------------------------------------+

  +--------+--------+-----------------------------------------------------+
  | Offset |  Size  | Field                                               |
  +--------+--------+-----------------------------------------------------+
  |   0    |    8   | magic = "PQSIGNUM"                                  |
  |   8    |    1   | version = 1                                         |
  |   9    |    1   | key_type (1=DSA87, 2=KEM1024)                       |
  |  10    |    1   | purpose (1=signing, 2=encryption)                   |
  |  11    |    1   | reserved = 0                                        |
  |  12    |    4   | public_key_size (uint32_t)                          |
  |  16    |    4   | private_key_size (uint32_t)                         |
  |  20    |  256   | name[256]                                           |
  | 276    |  var   | public_key                                          |
  |  var   |  var   | private_key                                         |
  +--------+--------+-----------------------------------------------------+

  Header size: 276 bytes

  DSA87:   276 + 2592 + 4896 = 7764 bytes
  KEM1024: 276 + 1568 + 3168 = 5012 bytes
```

### 8.2 Public Key File

```
+-----------------------------------------------------------------------------+
|                      PUBLIC KEY FILE FORMAT                                  |
+-----------------------------------------------------------------------------+

  +--------+--------+-----------------------------------------------------+
  | Offset |  Size  | Field                                               |
  +--------+--------+-----------------------------------------------------+
  |   0    |    8   | magic = "QGPPUBKY"                                  |
  |   8    |    1   | version = 1                                         |
  |   9    |    1   | key_type (1=DSA87, 2=KEM1024)                       |
  |  10    |    1   | purpose (1=signing, 2=encryption)                   |
  |  11    |    1   | reserved = 0                                        |
  |  12    |    4   | public_key_size (uint32_t)                          |
  |  16    |  256   | name[256]                                           |
  | 272    |  var   | public_key                                          |
  +--------+--------+-----------------------------------------------------+

  Header size: 272 bytes

  DSA87:   272 + 2592 = 2864 bytes
  KEM1024: 272 + 1568 = 1840 bytes
```

### 8.3 Constants

```c
#define QGP_PRIVKEY_MAGIC   "PQSIGNUM"
#define QGP_PUBKEY_MAGIC    "QGPPUBKY"
#define QGP_PRIVKEY_VERSION 1
#define QGP_PUBKEY_VERSION  1

typedef enum {
    QGP_KEY_TYPE_INVALID = 0,
    QGP_KEY_TYPE_DSA87   = 1,  // ML-DSA-87 (Dilithium5)
    QGP_KEY_TYPE_KEM1024 = 2   // ML-KEM-1024 (Kyber1024)
} qgp_key_type_t;

typedef enum {
    QGP_KEY_PURPOSE_UNKNOWN    = 0,
    QGP_KEY_PURPOSE_SIGNING    = 1,
    QGP_KEY_PURPOSE_ENCRYPTION = 2
} qgp_key_purpose_t;
```

**Source:** `crypto/utils/qgp_types.h`

---

## Appendix A: Protocol Cross-Reference

| Protocol | Depends On | Used By |
|----------|------------|---------|
| **Seal** | ML-KEM-1024, ML-DSA-87, AES-256-GCM | Spillway, Nexus |
| **Spillway** | Seal, Atlas | P2P Transport |
| **Anchor** | ML-DSA-87, Atlas | DHT Keyserver |
| **Atlas** | SHA3-512 | All DHT operations |
| **Nexus** | Seal, AES-256 | Group Messaging |

## Appendix B: Security Properties

| Protocol | Confidentiality | Integrity | Authentication | Forward Secrecy |
|----------|-----------------|-----------|----------------|-----------------|
| **Seal** | AES-256-GCM | GCM tag + signature | Dilithium5 | Per-message DEK |
| **Spillway** | Inherits Seal | Signed DHT puts | DHT signatures | Per-message |
| **Anchor** | Public data | Dilithium5 signature | Self-signed | N/A |
| **Nexus** | AES-256-GCM | GCM tag | Group membership | Key rotation |

---

**Maintained by:** DNA Messenger Team
**Repository:** https://gitlab.cpunk.io/cpunk/dna-messenger
