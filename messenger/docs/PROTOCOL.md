# DNA Connect - Protocol Specifications

**Version:** 1.3
**Last Updated:** 2026-09-23
**Library:** v0.11.20 | **Nodus:** v0.19.64
**Security Level:** NIST Category 5 (256-bit quantum)

This document specifies all wire formats and protocols used by DNA Connect.

---

## Protocol Summary

| Protocol | Version | Purpose |
|----------|---------|---------|
| **Seal Protocol** | v0.08 | E2E encrypted message envelope |
| **Spillway Protocol** | v2 | Offline delivery with daily buckets + TTL auto-expire |
| **Anchor Protocol** | v1 | Unified identity in DHT |
| **Atlas Protocol** | v1 | DHT key derivation scheme |
| **Nexus Protocol** | v1 | Group symmetric key encryption |
| **Circuit Relay** | v1 | NAT traversal via relay nodes |
| **Media Storage** | v1 | Encrypted media attachments in DHT |
| **Call Signaling** | v1 | PQ VoIP call control over Seal (Faz A) |

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
9. [Call Signaling Protocol](#9-call-signaling-protocol)

---

## 1. Cryptographic Primitives

All protocols use NIST Category 5 post-quantum cryptography.

| Algorithm | Standard | Purpose | Sizes |
|-----------|----------|---------|-------|
| **Kyber1024 round-3** | pre-FIPS-203 — LEGACY (read always; send during Faz 1-2) ⚠ | Key Encapsulation | Pub: 1568, Priv: 3168, CT: 1568, SS: 32 |
| **ML-KEM-1024** | FIPS 203 input-output conformant (pq-crystals `standard`@d5b791c, NIST ACVP-Server @975de31 + CCTV KAT) — *not* FIPS 140-3 validated | Key Encapsulation | Pub: 1568, Priv: 3168, CT: 1568, SS: 32 |
| **ML-DSA-87** | FIPS 204 (Dilithium5) | Digital Signatures | Pub: 2592, Priv: 4896, Sig: ~4627 |
| **AES-256-GCM** | FIPS 197 + SP 800-38D | Symmetric Encryption | Key: 32, Nonce: 12, Tag: 16 |
| **SHA3-512** | FIPS 202 | Fingerprints/Hashing | Output: 64 bytes |
| **AES Key Wrap** | RFC 3394 | DEK Protection | KEK: 32, Wrapped: 40 |

**Source:** `crypto/utils/qgp_types.h`

> ⚠ **Migration status (Faz 1 dual-key rollout, 2026-09-23).** `shared/crypto/enc/kem/`
> is the pq-crystals/kyber `standard`@d5b791c reference (ML-KEM-1024, FIPS 203
> input-output conformant); the pre-existing round-3 implementation moved to
> `shared/crypto/enc/kyber_r3_legacy.c` (`shared/crypto/enc/qgp_kyber.h`) and is kept
> for backward compatibility (decrypt always; ENCRYPT only while a peer has not
> published an ML-KEM key). Every identity now holds TWO KEM keypairs
> (`keys/identity.kem` type 2 round-3, `keys/identity.mlkem` type 3 ML-KEM-1024,
> `shared/crypto/enc/qgp_mlkem.h`). Wire sizes are identical between the two
> (1568/3168/1568/32) — algorithms cannot be told apart by size, only by the
> explicit `alg`/`enc_key_type` tag each format below carries. **Sender rule
> (all formats, all-or-nothing):** if EVERY recipient has published an ML-KEM key
> (checked via the local keyserver cache), use alg/enc_key_type 3 with ML-KEM keys;
> otherwise use alg/enc_key_type 2 with round-3 keys. See
> `docs/plans/decisions/2026-09-23-kem-mlkem-migration.md` (K1-K6) and
> `docs/plans/2026-09-23-mlkem-fips203-migration-design.md` for the phased rollout
> (Faz 1 = this dual-key period, `release`; Faz 2 = `release enforced`, round-3
> ENCAPSULATION removed; Faz 3 = round-3 DECAPSULATION removed). Faz 2/3 have not
> shipped — round-3 remains fully readable and remains the fallback for any peer
> who has not migrated.

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
  |   9    |    1   | enc_key_type = 2 (round-3, legacy) or 3 (ML-KEM-1024, KEM Faz 1) |
  |  10    |    1   | recipient_count (1-255)                             |
  |  11    |    1   | message_type (0=direct, 1=nexus)                    |
  |  12    |    4   | encrypted_size (uint32_t LE)                        |
  |  16    |    4   | signature_size (uint32_t LE)                        |
  +--------+--------+-----------------------------------------------------+

  RECIPIENT ENTRIES (1608 bytes x recipient_count)
  All entries in a message use the SAME algorithm (header enc_key_type is
  recipient-general — the header byte, not the entry, carries the tag).
  +--------+--------+-----------------------------------------------------+
  |   0    |  1568  | kyber_ciphertext[1568] (round-3 or ML-KEM-1024, per header enc_key_type) |
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
    uint8_t enc_key_type;       // 2 (round-3, legacy) or 3 (ML-KEM-1024, KEM Faz 1) — validated on decrypt since KEM Faz 1; any other value -> DNA_ERROR_DECRYPT
    uint8_t recipient_count;    // 1-255
    uint8_t message_type;       // 0=direct (Seal), 1=group (Nexus)
    uint32_t encrypted_size;    // Little-endian
    uint32_t signature_size;    // Little-endian
} messenger_enc_header_t;

// Recipient entry (1608 bytes)
typedef struct {
    uint8_t kyber_ciphertext[1568];  // round-3 or ML-KEM-1024 ciphertext, per header.enc_key_type
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
   - KEM encapsulate -> KEK + ciphertext (ML-KEM-1024 when every recipient has a published ML-KEM key, otherwise Kyber1024 round-3 — §1 sender rule; recorded in `enc_key_type`)
   - AES Key Wrap DEK with KEK -> wrapped_dek
7. Assemble: `header || recipients || nonce || ciphertext || tag || signature`

### 2.6 Version History

| Version | Changes |
|---------|---------|
| v0.07 | Added fingerprint inside encrypted payload (identity privacy) |
| v0.08 | Added encrypted timestamp (replay protection) |
| — (KEM Faz 1, 2026-09-23) | Header byte stays 0x08; `enc_key_type` gains value 3 (ML-KEM-1024) alongside 2 (round-3, legacy) and is now VALIDATED on decrypt (previously parsed but never checked). No header version bump — v0x09 (per-recipient alg byte) is deferred to Faz 3. |

**Source:** `messenger/messages.c`, `messenger/dna_api.c` (`dna_encrypt_message_raw_alg`/`dna_decrypt_message_raw_alg`)

---

## 3. Spillway Protocol

*Offline message delivery with daily buckets and TTL auto-expire*

### 3.1 Overview

The Spillway Protocol manages offline message delivery using a sender-based outbox model with **daily buckets**. Messages are organized by day and automatically expire after 7 days via DHT TTL - no manual pruning required.

**Watermarks** are used solely for **delivery confirmation** (updating message status to DELIVERED), not for pruning.

### 3.2 Architecture (v0.4.81+ Daily Buckets)

```
+-----------------------------------------------------------------------------+
|                    SPILLWAY PROTOCOL v2 (Daily Buckets)                      |
+-----------------------------------------------------------------------------+

  DAILY BUCKET MODEL:
  Each sender maintains daily outboxes per recipient in DHT

  Outbox Key (unsalted): sender_fp:outbox:recipient_fp:DAY_BUCKET
  Outbox Key (salted):   sender_fp:outbox:recipient_fp:DAY_BUCKET:SALT_HEX
              where DAY_BUCKET = unix_timestamp / 86400
              SALT_HEX = 64-char hex of 32-byte per-contact salt

  Example (2026-01-23, day 20477, salted):
    alice_fp:outbox:bob_fp:20477:a1b2c3...  (today's messages)
    alice_fp:outbox:bob_fp:20476:a1b2c3...  (yesterday's messages)

  TTL:        7 days (auto-expire, no pruning needed)
  Put Type:   Signed (value_id=1)
  Max:        50 messages per day bucket (DNA_DM_OUTBOX_MAX_MESSAGES_PER_BUCKET, DoS prevention)

  ACK (v15, delivery confirmation):
  Recipients publish ACK timestamp per sender

  ACK Key (unsalted): SHA3-512(recipient_fp + ":ack:" + sender_fp)
  ACK Key (salted):   SHA3-512(recipient_fp + ":ack:" + sender_fp + ":" + SALT_HEX)
  Value:         8-byte Unix timestamp (big-endian)
  TTL:           30 days
  Purpose:       RECEIVED status notifications

  SEND FLOW:
  +-------------------------------------------------------------------+
  | 1. Alice sends msg to Bob (seq=3)                                  |
  |    -> Look up per-contact salt from contacts DB                    |
  |    -> Generate today's bucket key: alice:outbox:bob:20477:SALT     |
  |    -> Fetch existing bucket from cache/DHT                         |
  |    -> Append new message (seq=3)                                   |
  |    -> Publish updated bucket to DHT                                |
  |    -> NO watermark fetch, NO pruning                               |
  +-------------------------------------------------------------------+

  RECEIVE FLOW:
  +-------------------------------------------------------------------+
  | 1. Bob comes online                                                |
  |    -> Sync last 3-8 days of Alice's buckets (parallel)             |
  |    -> Deduplicate by message hash                                  |
  |    -> Store new messages locally                                   |
  |    -> Publish ACK timestamp (async, for delivery confirmation)     |
  |                                                                    |
  | 2. Alice's ACK listener fires                                      |
  |    -> Update message status: SENT → RECEIVED                      |
  |    -> Fire UI event (double checkmark)                             |
  +-------------------------------------------------------------------+

  CLEANUP:
  +-------------------------------------------------------------------+
  | Messages auto-expire after 7 days via DHT TTL.                     |
  | No manual pruning needed. Bounded storage guaranteed.              |
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
/* Actual constant names in code (dht/shared/dht_offline_queue.h) —
 * "Spillway" is the protocol name, not the identifier prefix: */
#define DHT_OFFLINE_QUEUE_MAGIC    0x444E4120  // "DNA "
#define DHT_ACK_TTL                (30 * 24 * 3600)  // 30 days
/* Message version = 2; default TTL = 7 days (NODUS_DEFAULT_TTL) */
```

### 3.6 Version History

| Version | Changes |
|---------|---------|
| v1 | Initial: timestamp, expiry, sender, recipient, ciphertext; static outbox key |
| v2 | Added seq_num for ordering; daily bucket keys; TTL auto-expire (no pruning) |

**Architecture Change (v0.4.81):**
- **Old (v1):** Static key `sender:outbox:recipient` + watermark pruning
- **New (v2):** Daily bucket key `sender:outbox:recipient:DAY` + TTL auto-expire
- Watermarks now only used for delivery confirmation (DELIVERED status)

**Source:** `dht/shared/dht_dm_outbox.h`, `dht/shared/dht_dm_outbox.c`, `dht/shared/dht_offline_queue.h`

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
    uint8_t kyber_pubkey[1568];      // round-3 Kyber1024 public key (legacy)

    // ===== ML-KEM-1024 (KEM Faz 1, 2026-09-23) =====
    uint8_t mlkem_pubkey[1568];      // ML-KEM-1024 public key, valid only if has_mlkem_pubkey
    bool has_mlkem_pubkey;           // true once the identity has migrated (identity.mlkem exists)

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

**`mlkem_pubkey` (hex) is deliberately OUTSIDE the signature preimage (KEM Faz 1).**
It is present in the stored/transmitted JSON (`dna_identity_to_json`) but NEVER in
the JSON the signature is computed/verified over (`dna_identity_to_json_unsigned`).
This lets a client that has never heard of the field drop it, re-serialize, and
still verify the UNCHANGED main signature — required because verifiers
re-serialize from the parsed struct rather than checking the raw received bytes
(`keyserver_lookup.c:112-121`). There is intentionally NO separate binding
signature over `mlkem_pubkey` (operator decision K4,
`docs/plans/decisions/2026-09-23-kem-mlkem-migration.md` §5.2) — integrity comes
from server-side write ownership on the DHT value (authenticated session
identity + value signature + EXCLUSIVE key), not from a second signature.
Accepted risk: a malicious/compromised nodus node could serve a reader a
tampered `mlkem_pubkey`; the deterrent is witness slashing, not a wire-level
check. A reader who never sees a `mlkem_pubkey` field for a peer sends that
peer round-3 (§1 sender rule).

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
| **Outbox** | `{sender}:outbox:{recipient}:{day}` or `{sender}:outbox:{recipient}:{day}:{salt}` | 7 days |
| **ACK** | `{recipient}:ack:{sender}` or `{recipient}:ack:{sender}:{salt}` | 30 days |
| **Profile** | `{fingerprint}:profile` | 365 days |
| **Name Lookup** | `{name}:lookup` | 365 days |
| **Contact Requests** | `{fingerprint}:requests` | 7 days |
| **Contact List** | `{fingerprint}:contactlist` | 7 days |

### 5.4 Examples

```c
// Presence key for user with fingerprint "abc123..."
key = SHA3-512("abc123...")

// Outbox key for Alice sending to Bob (salted, v0.8.5+)
key = "alice_fp:outbox:bob_fp:20477:SALT_HEX"

// ACK key (Bob's ACK for Alice's messages, salted)
key = SHA3-512("bob_fp:ack:alice_fp:SALT_HEX")

// Profile lookup by fingerprint
key = SHA3-512("abc123...:profile")

// Name lookup (case-insensitive, lowercase)
key = SHA3-512("alice:lookup")
```

### 5.5 C Functions

```c
// Generate ACK key (Spillway Protocol, v15+)
void dht_generate_ack_key(
    const char *recipient,   // ACK owner
    const char *sender,      // Message sender
    const uint8_t *salt,     // 32-byte per-contact salt (NULL = unsalted)
    uint8_t *key_out         // 64-byte output
);
```

**Source:** `dht/shared/dht_offline_queue.c`, `dht/keyserver/keyserver_core.h`

---

## 6. Nexus Protocol

*Group symmetric key - connection point for groups*

### 6.1 Overview

The Nexus Protocol provides efficient group encryption using a shared symmetric key. Like a nexus (connection point), all group members connect through a shared secret that enables ~200x faster encryption than per-recipient Kyber.

### 6.2 GEK (Group Symmetric Key)

- **Key Size:** 32 bytes (AES-256)
- **Generation:** Random on group creation
- **Distribution:** Per-member Initial Key Packet (IKP, §6.2a) on join/rotation
- **Storage:** Encrypted in local SQLite (`gek_encrypt`/`gek_decrypt`, round-3 alg 2)

### 6.2a Initial Key Packet (IKP) — GEK distribution

Distributes a group's GEK to every member. Built by `ikp_build()`, read by
`ikp_extract()`/`ikp_extract_alg()` (`messenger/gek.c`, `messenger/gek.h`).

```
+-----------------------------------------------------------------------------+
|                  IKP HEADER (77 bytes, identical in v2 and v3)              |
+--------+--------+-----------------------------------------------------+
| Offset |  Size  | Field                                               |
+--------+--------+-----------------------------------------------------+
|   0    |    4   | magic = 0x47454B32 "GEK2" (v2) or 0x47454B33 "GEK3" (v3, KEM Faz 1) |
|   4    |   36   | group_uuid (36 bytes, no null terminator)           |
|  40    |    4   | version (uint32_t, network byte order)             |
|  44    |    1   | member_count (1-16, IKP_MAX_MEMBERS)                |
|  45    |   32   | dht_salt (per-group DHT privacy salt, CORE-04)      |
+--------+--------+-----------------------------------------------------+

  PER-MEMBER ENTRY, v2 (1672 bytes x member_count) — unchanged, alg implicitly 2
  +--------+--------+-----------------------------------------------------+
  |   0    |   64   | fingerprint (SHA3-512 of member's Dilithium5 pubkey) |
  |  64    | 1568   | kyber_ciphertext (round-3 Kyber1024 encapsulation of KEK) |
  | 1632   |   40   | wrapped_gek (GEK AES-key-wrapped with KEK)          |
  +--------+--------+-----------------------------------------------------+

  PER-MEMBER ENTRY, v3 (1673 bytes x member_count, KEM Faz 1)
  +--------+--------+-----------------------------------------------------+
  |   0    |   64   | fingerprint                                        |
  |  64    |    1   | alg (2 = round-3, 3 = ML-KEM-1024)                  |
  |  65    | 1568   | kem_ciphertext (encapsulation of KEK, per alg)      |
  | 1633   |   40   | wrapped_gek                                        |
  +--------+--------+-----------------------------------------------------+

  SIGNATURE (variable, ~4630 bytes, identical in v2 and v3)
  +--------+--------+-----------------------------------------------------+
  |   0    |    1   | sig_type = 23 (Dilithium5 / ML-DSA-87)              |
  |   1    |    2   | sig_size (uint16_t, network byte order)             |
  |   3    |  var   | dilithium5_signature over everything before this block |
  +--------+--------+-----------------------------------------------------+
```

**v3 all-or-nothing gate:** `ikp_build()` emits v3 ONLY when EVERY member entry
carries a non-NULL ML-KEM pubkey (checked from the keyserver cache/DHT record);
one member without one keeps the WHOLE packet on v2 (a v2 reader cannot parse
the longer v3 entry). Readers (`ikp_extract_alg()`, `ikp_verify()`,
`ikp_get_version()`, `ikp_get_member_count()`) accept both magics; the OLD
`ikp_extract()` (v2-only signature, kept unchanged for existing callers) still
parses a v3 packet's header but can only decapsulate entries whose alg is 2.

### 6.3 Message Format

Uses Seal Protocol with `message_type = 0x01`:

```
Header:
  message_type = MSG_TYPE_NEXUS (0x01)
  recipient_count = 1

Recipient Entry:
  kyber_ciphertext = zeros (not used)
  wrapped_dek = AES-wrap(DEK, GEK)  // GEK as KEK
```

### 6.4 Key Rotation

| Event | Action |
|-------|--------|
| Member joins | Encrypt current GEK with new member's Kyber pubkey |
| Member leaves | Generate new GEK, distribute to remaining members |
| Key compromise | Generate new GEK, distribute to all members |

### 6.5 Forward Secrecy

- New GEK on member removal
- Old members cannot decrypt new messages
- Per-message DEK provides forward secrecy within sessions

### 6.6 Performance

| Method | Encryption Time | Size Overhead |
|--------|-----------------|---------------|
| Seal (per-recipient) | ~50ms/recipient | 1608 bytes/recipient |
| Nexus (GEK) | ~0.25ms total | 40 bytes fixed |

**Source:** `messenger/gek.c`, `messenger/gek.h`

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
  |   9    |    1   | key_type (1=DSA87, 2=KEM1024 round-3 legacy, 3=MLKEM1024) |
  |  10    |    1   | purpose (1=signing, 2=encryption)                   |
  |  11    |    1   | reserved = 0                                        |
  |  12    |    4   | public_key_size (uint32_t)                          |
  |  16    |    4   | private_key_size (uint32_t)                         |
  |  20    |  256   | name[256]                                           |
  | 276    |  var   | public_key                                          |
  |  var   |  var   | private_key                                         |
  +--------+--------+-----------------------------------------------------+

  Header size: 276 bytes

  DSA87:     276 + 2592 + 4896 = 7764 bytes
  KEM1024:   276 + 1568 + 3168 = 5012 bytes (round-3, legacy — keys/identity.kem)
  MLKEM1024: 276 + 1568 + 3168 = 5012 bytes (FIPS 203, same sizes — keys/identity.mlkem, KEM Faz 1)
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
  |   9    |    1   | key_type (1=DSA87, 2=KEM1024 round-3 legacy, 3=MLKEM1024) |
  |  10    |    1   | purpose (1=signing, 2=encryption)                   |
  |  11    |    1   | reserved = 0                                        |
  |  12    |    4   | public_key_size (uint32_t)                          |
  |  16    |  256   | name[256]                                           |
  | 272    |  var   | public_key                                          |
  +--------+--------+-----------------------------------------------------+

  Header size: 272 bytes

  DSA87:     272 + 2592 = 2864 bytes
  KEM1024:   272 + 1568 = 1840 bytes (round-3, legacy)
  MLKEM1024: 272 + 1568 = 1840 bytes (FIPS 203, same size, KEM Faz 1)
```

### 8.3 Constants

```c
#define QGP_PRIVKEY_MAGIC   "PQSIGNUM"
#define QGP_PUBKEY_MAGIC    "QGPPUBKY"
#define QGP_PRIVKEY_VERSION 1
#define QGP_PUBKEY_VERSION  1

typedef enum {
    QGP_KEY_TYPE_INVALID   = 0,
    QGP_KEY_TYPE_DSA87     = 1,  // ML-DSA-87 (Dilithium5)
    QGP_KEY_TYPE_KEM1024   = 2,  // Kyber1024 round-3 (legacy) — NOT ML-KEM/FIPS 203
    QGP_KEY_TYPE_MLKEM1024 = 3   // ML-KEM-1024, FIPS 203 (KEM Faz 1, 2026-09-23)
} qgp_key_type_t;

typedef enum {
    QGP_KEY_PURPOSE_UNKNOWN    = 0,
    QGP_KEY_PURPOSE_SIGNING    = 1,
    QGP_KEY_PURPOSE_ENCRYPTION = 2
} qgp_key_purpose_t;
```

**Source:** `crypto/utils/qgp_types.h`

---

## Appendix A: Additional Protocols

### Circuit Relay Protocol (Nodus VPN Mesh)

Peer-to-peer circuit relay through the Nodus cluster for peers that cannot establish direct connections. Two authenticated clients are bridged over the existing TCP 4001 (client) and TCP 4002 (inter-node) transports. Circuits opened with `nodus_circuit_open_e2e()` are end-to-end encrypted (Kyber1024 KEM → HKDF-SHA3-256 → AES-256-GCM) — relay servers forward only opaque ciphertext. The messenger does not use circuits yet; the SDK is the foundation for future file transfer and voice/video calls.

**Spec:** `nodus/docs/CIRCUIT_PROTOCOL.md`
**Source:** `nodus/src/circuit/`, `nodus/src/client/nodus_client.c` (`nodus_circuit_*`)

### Media Storage Protocol

Media attachments (voice messages, video clips, images) are stored in DHT using chunked uploads (512 KB chunks client-side, 64 MB max per media object). The media payload is encrypted with AES-256-GCM before upload. Recipients receive a media reference (DHT key + decryption key) inside the Seal-encrypted message, then fetch and decrypt the media independently.

**Supported types:** Voice messages, video, images

**Source:** `dht/shared/nodus_ops.c` (`nodus_ops_media_put/get/exists`), server side `nodus/src/core/nodus_media_storage.c`

### Salt Agreement Protocol (per-contact DHT outbox privacy)

Agrees and stores a per-contact-pair 32-byte salt (used to derive the DM outbox
DHT key, keeping it unlinkable without knowing both parties) at a deterministic
DHT key `SHA3-512(min(fp_a,fp_b) + ":" + max(fp_a,fp_b) + ":salt_agreement")`.
Dual-encrypted (once per party) with a Dilithium5 signature over the data
portion. `dht/shared/dht_salt_agreement.c`, `dht/shared/dht_salt_agreement.h`.

```
+-----------------------------------------------------------------------------+
|                    SALT AGREEMENT PACKET, v1                                |
+--------+--------+-----------------------------------------------------+
| Offset |  Size  | Field                                               |
+--------+--------+-----------------------------------------------------+
|   0    |    2   | version = 1 (uint16_t, network byte order)          |
|   2    |   64   | entry[0].fingerprint (lower of the two, binary)     |
|  66    | 1628   | entry[0].gek_enc (round-3 KEM ct[1568] || nonce[12] || tag[16] || enc_salt[32]) |
| 1694   |   64   | entry[1].fingerprint (higher of the two, binary)    |
| 1758   | 1628   | entry[1].gek_enc                                    |
| 3386   |  var   | dilithium5_signature over bytes [0, 3386)           |
+--------+--------+-----------------------------------------------------+

  SALT AGREEMENT PACKET, v2 (KEM Faz 1, 2026-09-23)
  Same layout, each entry gains a 1-byte alg field between fingerprint and
  the encrypted blob:
+--------+--------+-----------------------------------------------------+
|   0    |    2   | version = 2                                         |
|   2    |   64   | entry[0].fingerprint                                |
|  66    |    1   | entry[0].alg (2 = round-3, 3 = ML-KEM-1024)         |
|  67    | 1628   | entry[0].gek_enc                                    |
| 1695   |   64   | entry[1].fingerprint                                |
| 1759   |    1   | entry[1].alg                                        |
| 1760   | 1628   | entry[1].gek_enc                                    |
| 3388   |  var   | dilithium5_signature over bytes [0, 3388)           |
+--------+--------+-----------------------------------------------------+
```

**Faz 1 status (D7, M1 delta 1 — ORCHESTRATOR decision): v2 is DEFINED but
NOT EMITTED.** The v2 packet layout above, `salt_agreement_publish_v2()` and
`salt_agreement_fetch_v2()` exist and are unit-tested, but neither is called
from any production code path — the two real callers
(`dna_engine_contacts.c`, `dna_engine_listeners.c`) still call the v1-only
`salt_agreement_publish()`/`salt_agreement_fetch()` exclusively. Reason: the
tiebreak picks the lowest SHA3 hash over the salts each party could decrypt;
a Faz-0 device of the SAME identity (an accepted mixed-device state, K1)
cannot decrypt any v2 value and discards them all, so the two parties would
compute the tiebreak over different candidate sets and could pick DIFFERENT
salts — the only Faz-1 surface where a mixed read set changes a
deterministic AGREEMENT (not just a decode failure on one blob). The `_v2`
entry points are the Faz-2 hook, wired only once every device of an
identity is expected to have an ML-KEM key.
<!-- was, until M1 delta 1 (D7): "v2 gate: published ONLY when BOTH parties
have a published ML-KEM key (own file + the contact's cache entry);
otherwise the unchanged v1 packet is published." That description matches
the *_v2 functions' own internal logic but was never wired to any caller —
see above. -->
The signature covers the data portion exactly as in v1 — only its length
changes when v2 IS used. `salt_agreement_publish()`/`salt_agreement_fetch()`
keep their original signatures (v1-only, unchanged); `salt_agreement_publish_v2()`/
`salt_agreement_fetch_v2()` add the ML-KEM pubkey/privkey parameters.

---

## Appendix B: Protocol Cross-Reference

| Protocol | Depends On | Used By |
|----------|------------|---------|
| **Seal** | ML-KEM-1024 (Kyber1024 round-3 legacy fallback), ML-DSA-87, AES-256-GCM | Spillway, Nexus |
| **Spillway** | Seal, Atlas | P2P Transport |
| **Anchor** | ML-DSA-87, Atlas | DHT Keyserver |
| **Atlas** | SHA3-512 | All DHT operations |
| **Nexus** | Seal, AES-256 | Group Messaging |

## Appendix C: Security Properties

| Protocol | Confidentiality | Integrity | Authentication | Forward Secrecy |
|----------|-----------------|-----------|----------------|-----------------|
| **Seal** | AES-256-GCM | GCM tag + signature | Dilithium5 | Per-message DEK |
| **Spillway** | Inherits Seal | Signed DHT puts | DHT signatures | Per-message |
| **Anchor** | Public data | Dilithium5 signature | Self-signed | N/A |
| **Nexus** | AES-256-GCM | GCM tag | Group membership | Key rotation |

---

## 9. Call Signaling Protocol

*Post-quantum 1:1 call control (Faz A). Media (audio) is Faz B.*

### 9.1 Overview

Call control is a typed-JSON message carried inside a normal **Seal** envelope (§2), so it
inherits PQ E2E encryption, Dilithium5 identity, and Spillway offline queueing for free. A call
is negotiated as a small state machine and never touches consensus (`state_root`).

The Seal plaintext body is the UTF-8 JSON below (the same "typed JSON in message body" pattern
as media references). On updated clients the receive-path router intercepts
`"type":"call_signal"` bodies and never renders them as chat text.

### 9.2 Signal body (canonical, fixed field order)

```
{"type":"call_signal","v":1,"call":"<32 hex = 16B call_id>","sig":"<base64 Dilithium5>",
 "seq":<u32>,"kind":"INVITE|RINGING|ACCEPT|REJECT|BUSY|END"<,per-kind fields>}
```

| Kind | Extra fields |
|------|--------------|
| `INVITE` | `"caller":"<128 hex fp>"`, `"eph_pk":"<base64 1568B pk, of alg>"`, `"alg":1` (KEM Faz 1, OMITTED when 0/round-3), `"cap":{...}` |
| `ACCEPT` | `"eph_ct":"<base64 1568B>"`, `"static_ct":"<base64 1568B>"` |
| `REJECT` / `BUSY` / `END` | `"reason":<int>` |
| `RINGING` | (base fields only) |

**`alg` (KEM Faz 1, 2026-09-23).** The caller emits `"alg":1` in the INVITE
ONLY when the callee has a published ML-KEM-1024 key (checked via the
keyserver cache); when absent, an old parser defaults to 0 (round-3) —
byte-identical wire output to before this field existed, so this is not a
breaking change. The caller mints its ephemeral keypair with that same alg;
ACCEPT encapsulates BOTH the ephemeral and the callee's static key with the
INVITE's alg (ACCEPT carries no `alg` field of its own — both sides already
agree on it from the INVITE).

**Signature (`sig`).** Computed by Dilithium5 over the body bytes with an **empty** `"sig":""`
slot, then base64-spliced into that slot. Verification runs over the exact received bytes
(blank the sig value, verify) — never re-serializing — so it is immune to JSON-encoder
differences. Both INVITE and ACCEPT are signed. This inner signature is load-bearing: the
direct-message receive path does not verify Seal's own signature, so `sig` is what binds
`eph_pk` and the ACCEPT ciphertexts to the caller/callee identity. Verified against the pubkey
fetched for the dialed fingerprint, asserting `fp == SHA3-512(pk)`.

### 9.3 Per-call key agreement (K_call)

The caller mints a per-call **ephemeral** keypair (in the signed INVITE) — round-3 Kyber1024 by
default, or ML-KEM-1024 when the callee has published one (`"alg":1`, KEM Faz 1, §9.2). The callee
encapsulates to both the ephemeral pk and the caller's static pk (from the DHT profile), with
THAT SAME alg, returning `eph_ct` + `static_ct` in the signed ACCEPT. Both sides derive:

```
K_call = HKDF-SHA3-256(
    salt = caller_fp[0:32] || callee_fp[0:32],
    ikm  = ss_eph || ss_static,
    info = "dna-call-v1" || call_id || SHA3-512(eph_pk)[0:32])   -> 32 bytes
```

Forward secrecy comes from destroying `ss_eph` (and the ephemeral secret key) at teardown; the
static secret adds identity depth without weakening it. No new primitive — HKDF-SHA3-256 is the
audited `hkdf_sha3_256` (RFC 5869). `K_call` keys the media circuit in Faz B.

### 9.4 State machine

`INVITE → RINGING → ACCEPT | REJECT | TIMEOUT | BUSY → (ACTIVE) → END`. The media circuit is
opened only after a verified ACCEPT; the callee accepts the inbound circuit only via a one-shot,
windowed consent gate keyed on the caller's fingerprint (no nodus wire change). Non-contacts
cannot ring (contacts-only by default). Glare (simultaneous mutual INVITE) resolves to the lower
raw 16-byte `call_id`.

**Source:** `src/api/engine/dna_call_crypto.{c,h}`, `dna_call_fsm.{c,h}`, `dna_call_orch.{c,h}`.
See `docs/functions/calls.md`.

---

**Maintained by:** DNA Connect Team
**Repository:** https://gitlab.cpunk.io/cpunk/dna
