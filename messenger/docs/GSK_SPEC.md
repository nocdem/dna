# GSK (Group Symmetric Key) Implementation Specification

## Document Info
- **Version:** 1.0
- **Date:** 2026-01-09
- **Status:** PLANNED (Not Yet Implemented)
- **Scope:** Complete GSK system for group messaging encryption

---

## ⚠️ IMPLEMENTATION STATUS

**THIS FEATURE IS NOT YET IMPLEMENTED.**

This document is a detailed design specification for future implementation.
The current codebase contains a partial/legacy GSK implementation that will be
replaced by this new design.

**Current Status:**
- [ ] Database Schema (Phase 1)
- [ ] GSK Core Functions (Phase 2)
- [ ] IKP Functions (Phase 3)
- [ ] Group Management (Phase 4)
- [ ] DHT Integration (Phase 5)
- [ ] Invitations (Phase 6)
- [ ] CLI Commands (Phase 7)
- [ ] FFI Bindings (Phase 8)
- [ ] Flutter UI (Phase 9)
- [ ] Cleanup Old Code (Phase 10)

---

## 1. Overview

### 1.1 Purpose
GSK (Group Symmetric Key) enables efficient encrypted group messaging by using a shared AES-256 symmetric key instead of per-recipient Kyber encryption.

### 1.2 Design Goals
1. **Simplicity** - Minimal files, clear data flow
2. **Security** - Post-quantum (NIST Category 5), forward secrecy on rotation
3. **Efficiency** - Single encryption per message regardless of group size
4. **Reliability** - Works with DHT-only transport (no P2P required)

### 1.3 Architecture Summary
```
┌─────────────────────────────────────────────────────────────────┐
│                      GROUP MESSAGING                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  LOCAL STORAGE              DHT STORAGE                         │
│  ┌─────────────────┐       ┌─────────────────────────────────┐ │
│  │ groups          │       │ dna:group:<uuid>:gsk            │ │
│  │ group_members   │       │   └─ Initial Key Packet (IKP)   │ │
│  │ group_gsks      │       │                                 │ │
│  │ pending_invites │       │ dna:group:<uuid>:msg            │ │
│  │ group_messages  │       │   └─ Encrypted messages         │ │
│  └─────────────────┘       └─────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Structures

### 2.1 GSK Entry (In-Memory)

**Purpose:** Represents a single GSK for a group version.

**Fields:**
| Field | Type | Size | Description |
|-------|------|------|-------------|
| group_uuid | char[37] | 37 bytes | UUID v4 string (36 chars + null) |
| version | uint32_t | 4 bytes | GSK version (0, 1, 2...) |
| key | uint8_t[32] | 32 bytes | AES-256 key material |
| created_at | uint64_t | 8 bytes | Unix timestamp (seconds) |
| expires_at | uint64_t | 8 bytes | created_at + 7 days |

**Total in-memory:** 97 bytes

### 2.2 GSK Encrypted Blob (Database Storage)

**Purpose:** GSK encrypted with user's Kyber1024 key for secure storage.

**Format:**
```
Offset  Size    Field
──────────────────────────────────────────
0       1568    kem_ciphertext    (Kyber1024 encapsulation)
1568    12      aes_nonce         (Random nonce)
1580    16      aes_tag           (GCM authentication tag)
1596    32      encrypted_gsk     (AES-256-GCM ciphertext)
──────────────────────────────────────────
Total:  1628 bytes
```

**Security Properties:**
- Fresh KEM encapsulation per storage (forward secrecy)
- AES-256-GCM provides authenticated encryption
- Database compromise doesn't expose GSK without Kyber private key

### 2.3 Initial Key Packet (IKP) - DHT Format

**Purpose:** Distributes GSK to all group members via DHT.

**Format:**
```
Offset  Size        Field
──────────────────────────────────────────────────────────────────
HEADER (19 bytes):
0       4           magic             "GSK " (0x47534B20)
4       1           format_version    1
5       4           gsk_version       uint32_t big-endian
9       2           member_count      uint16_t big-endian (max 256)
11      8           created_at        uint64_t big-endian (unix timestamp)

MEMBER ENTRIES (1672 bytes each):
19      64          fingerprint[0]    SHA3-512 hash (binary)
83      1568        kyber_ct[0]       Kyber1024 ciphertext
1651    40          wrapped_gsk[0]    AES-256-GCM(KEK, GSK) + nonce + tag
...     ...         (repeat for each member)

SIGNATURE BLOCK (4691 bytes):
N       64          owner_fingerprint SHA3-512 of owner's Dilithium pubkey
N+64    4627        dilithium_sig     Dilithium5 signature over all above
──────────────────────────────────────────────────────────────────
Total: 19 + (1672 × member_count) + 4691 bytes

Example sizes:
  1 member:   19 + 1672 + 4691 =  6,382 bytes
  5 members:  19 + 8360 + 4691 = 13,070 bytes
 10 members:  19 + 16720 + 4691 = 21,430 bytes
```

**Wrapped GSK Format (40 bytes per member):**
```
Offset  Size    Field
──────────────────────────────────────────
0       12      nonce         (Random)
12      16      tag           (GCM authentication)
28      32      ciphertext    (AES-256-GCM encrypted GSK)
──────────────────────────────────────────
Total: 60 bytes (nonce + tag stored separately for clarity)

Note: KEK (Key Encryption Key) derived from Kyber1024 decapsulation
```

### 2.4 Group Message Format - DHT Format

**Purpose:** Single encrypted message stored on group's message DHT key.

**Format:**
```
Offset  Size        Field
──────────────────────────────────────────────────────────────────
HEADER (88 bytes):
0       4           magic             "GMSG" (0x474D5347)
4       4           gsk_version       uint32_t big-endian
8       8           timestamp_ms      uint64_t big-endian (milliseconds)
16      8           message_id        uint64_t big-endian (unique per sender)
24      64          sender_fp         SHA3-512 fingerprint (binary)

ENCRYPTED PAYLOAD (variable):
88      12          nonce             AES-256-GCM nonce
100     16          tag               AES-256-GCM tag
116     4           ciphertext_len    uint32_t big-endian
120     N           ciphertext        AES-256-GCM encrypted plaintext

SIGNATURE:
120+N   4627        dilithium_sig     Sender's signature over all above
──────────────────────────────────────────────────────────────────
Total: 88 + 12 + 16 + 4 + N + 4627 = 4747 + N bytes

Example: 100-char message ≈ 4847 bytes
```

**Message ID Generation:**
- Format: `(timestamp_ms << 16) | (random_16bit)`
- Ensures uniqueness even for simultaneous messages
- Used for deduplication on receive

### 2.5 Group Invitation Message - Spillway Format

**Purpose:** Notify user of group invitation (sent via 1:1 Spillway).

**JSON Payload:**
```
{
  "type": "group_invite",
  "group_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "group_name": "My Group",
  "owner_fingerprint": "a3f9e2d1c5b8...(128 hex chars)",
  "member_count": 5,
  "created_at": 1704825600
}
```

**Message Type:** MESSAGE_TYPE_GROUP_INVITATION (value: 1)

---

## 3. Database Schema

### 3.1 Groups Table

**Purpose:** Store group metadata locally.

**Schema:**
```
TABLE: groups
──────────────────────────────────────────────────────────────────
Column          Type        Constraints         Description
──────────────────────────────────────────────────────────────────
uuid            TEXT        PRIMARY KEY         UUID v4 (36 chars)
name            TEXT        NOT NULL            Group display name
created_at      INTEGER     NOT NULL            Unix timestamp
is_owner        INTEGER     DEFAULT 0           1 if local user created
owner_fp        TEXT        NOT NULL            Owner's fingerprint
──────────────────────────────────────────────────────────────────

Indexes:
  - PRIMARY KEY on uuid
```

### 3.2 Group Members Table

**Purpose:** Track members of each group.

**Schema:**
```
TABLE: group_members
──────────────────────────────────────────────────────────────────
Column          Type        Constraints         Description
──────────────────────────────────────────────────────────────────
group_uuid      TEXT        NOT NULL            FK to groups.uuid
fingerprint     TEXT        NOT NULL            Member's 128-char hex fingerprint
added_at        INTEGER     NOT NULL            Unix timestamp
──────────────────────────────────────────────────────────────────
PRIMARY KEY (group_uuid, fingerprint)

Indexes:
  - PRIMARY KEY on (group_uuid, fingerprint)
  - INDEX on fingerprint (for "my groups" queries)
```

### 3.3 Group GSKs Table

**Purpose:** Store encrypted GSKs for each group version.

**Schema:**
```
TABLE: group_gsks
──────────────────────────────────────────────────────────────────
Column          Type        Constraints         Description
──────────────────────────────────────────────────────────────────
group_uuid      TEXT        NOT NULL            FK to groups.uuid
version         INTEGER     NOT NULL            GSK version (0, 1, 2...)
encrypted_key   BLOB        NOT NULL            1628-byte encrypted GSK
created_at      INTEGER     NOT NULL            Unix timestamp
expires_at      INTEGER     NOT NULL            created_at + 7 days
──────────────────────────────────────────────────────────────────
PRIMARY KEY (group_uuid, version)

Indexes:
  - PRIMARY KEY on (group_uuid, version)
  - INDEX on (group_uuid, expires_at DESC) for active GSK lookup
```

### 3.4 Pending Invitations Table

**Purpose:** Store received invitations awaiting user action.

**Schema:**
```
TABLE: pending_invitations
──────────────────────────────────────────────────────────────────
Column          Type        Constraints         Description
──────────────────────────────────────────────────────────────────
group_uuid      TEXT        PRIMARY KEY         Group UUID
group_name      TEXT        NOT NULL            Group display name
owner_fp        TEXT        NOT NULL            Owner's fingerprint
received_at     INTEGER     NOT NULL            Unix timestamp
──────────────────────────────────────────────────────────────────

Indexes:
  - PRIMARY KEY on group_uuid
  - INDEX on received_at DESC (for sorted display)
```

### 3.5 Group Messages Table

**Purpose:** Store decrypted group messages locally.

**Schema:**
```
TABLE: group_messages
──────────────────────────────────────────────────────────────────
Column          Type        Constraints         Description
──────────────────────────────────────────────────────────────────
id              INTEGER     PRIMARY KEY AUTO    Local ID
group_uuid      TEXT        NOT NULL            FK to groups.uuid
message_id      INTEGER     NOT NULL            Unique ID from sender
sender_fp       TEXT        NOT NULL            Sender's fingerprint
timestamp_ms    INTEGER     NOT NULL            Message timestamp (ms)
gsk_version     INTEGER     NOT NULL            GSK version used
plaintext       TEXT        NOT NULL            Decrypted message text
received_at     INTEGER     NOT NULL            When we received it
──────────────────────────────────────────────────────────────────
UNIQUE (group_uuid, sender_fp, message_id)

Indexes:
  - PRIMARY KEY on id
  - UNIQUE INDEX on (group_uuid, sender_fp, message_id) for deduplication
  - INDEX on (group_uuid, timestamp_ms) for conversation display
```

---

## 4. DHT Key Structure

### 4.1 GSK Key

**Key Format:**
```
String:  "dna:group:<uuid>:gsk"
Example: "dna:group:550e8400-e29b-41d4-a716-446655440000:gsk"

DHT Hash: SHA3-512(key_string) → 64-byte binary key
```

**Value:** Initial Key Packet (IKP) binary blob

**DHT Properties:**
- TTL: 30 days (longer than message TTL to ensure members can always get GSK)
- Signed: Yes (owner's value_id)
- Replacement: Each publish replaces previous (same value_id)

### 4.2 Messages Key

**Key Format:**
```
String:  "dna:group:<uuid>:msg"
Example: "dna:group:550e8400-e29b-41d4-a716-446655440000:msg"

DHT Hash: SHA3-512(key_string) → 64-byte binary key
```

**Value:** Multiple values (one per sender), each containing array of messages

**DHT Properties:**
- TTL: 7 days
- Signed: Yes (each sender uses their own value_id)
- Multi-value: dht_get_all() returns all senders' messages

**Per-Sender Value Format:**
```
Offset  Size        Field
──────────────────────────────────────────────────────────────────
0       4           magic             "GMSV" (Group Message Sender Value)
4       4           message_count     uint32_t big-endian
8       N           messages[]        Array of Group Message Format entries
──────────────────────────────────────────────────────────────────
```

---

## 5. Algorithms

### 5.1 GSK Generation

**Input:** group_uuid (string)
**Output:** gsk (32-byte key), version (uint32_t)

**Algorithm:**
```
FUNCTION gsk_generate(group_uuid):
    1. Query database for current highest version:
       SELECT MAX(version) FROM group_gsks WHERE group_uuid = ?

    2. IF no result THEN new_version = 0
       ELSE new_version = result + 1

    3. Generate random key:
       gsk = random_bytes(32)  // Cryptographically secure

    4. Set timestamps:
       created_at = current_unix_timestamp()
       expires_at = created_at + (7 * 24 * 3600)  // 7 days

    5. RETURN (gsk, new_version, created_at, expires_at)
```

### 5.2 GSK Storage (Encrypt and Store)

**Input:** group_uuid, version, gsk (32 bytes), my_kyber_pubkey (1568 bytes)
**Output:** success/failure

**Algorithm:**
```
FUNCTION gsk_store(group_uuid, version, gsk, kyber_pubkey):
    1. Generate fresh KEM encapsulation:
       (shared_secret, kem_ciphertext) = kyber1024_encapsulate(kyber_pubkey)
       // shared_secret: 32 bytes
       // kem_ciphertext: 1568 bytes

    2. Generate random nonce:
       nonce = random_bytes(12)

    3. Encrypt GSK with shared secret:
       (ciphertext, tag) = aes256_gcm_encrypt(
           key = shared_secret,
           nonce = nonce,
           plaintext = gsk,
           aad = group_uuid || version  // Additional authenticated data
       )
       // ciphertext: 32 bytes (same as plaintext)
       // tag: 16 bytes

    4. Build encrypted blob:
       blob = kem_ciphertext || nonce || tag || ciphertext
       // Total: 1568 + 12 + 16 + 32 = 1628 bytes

    5. Store in database:
       INSERT INTO group_gsks (group_uuid, version, encrypted_key, created_at, expires_at)
       VALUES (?, ?, blob, ?, ?)

    6. Securely wipe shared_secret from memory

    7. RETURN success
```

### 5.3 GSK Load (Decrypt from Storage)

**Input:** group_uuid, version, my_kyber_privkey (3168 bytes)
**Output:** gsk (32 bytes) or error

**Algorithm:**
```
FUNCTION gsk_load(group_uuid, version, kyber_privkey):
    1. Query database:
       SELECT encrypted_key FROM group_gsks
       WHERE group_uuid = ? AND version = ? AND expires_at > current_time()

    2. IF no result THEN RETURN error("GSK not found or expired")

    3. Parse encrypted blob (1628 bytes):
       kem_ciphertext = blob[0:1568]
       nonce = blob[1568:1580]
       tag = blob[1580:1596]
       ciphertext = blob[1596:1628]

    4. Decapsulate to get shared secret:
       shared_secret = kyber1024_decapsulate(kyber_privkey, kem_ciphertext)
       // 32 bytes

    5. Decrypt GSK:
       gsk = aes256_gcm_decrypt(
           key = shared_secret,
           nonce = nonce,
           ciphertext = ciphertext,
           tag = tag,
           aad = group_uuid || version
       )

    6. IF decryption fails THEN RETURN error("Decryption failed")

    7. Securely wipe shared_secret from memory

    8. RETURN gsk
```

### 5.4 GSK Load Active (Latest Non-Expired)

**Input:** group_uuid, my_kyber_privkey
**Output:** (gsk, version) or error

**Algorithm:**
```
FUNCTION gsk_load_active(group_uuid, kyber_privkey):
    1. Query database for latest non-expired version:
       SELECT version, encrypted_key FROM group_gsks
       WHERE group_uuid = ? AND expires_at > current_time()
       ORDER BY version DESC
       LIMIT 1

    2. IF no result THEN RETURN error("No active GSK")

    3. Decrypt using gsk_load algorithm (steps 3-8)

    4. RETURN (gsk, version)
```

### 5.5 Initial Key Packet Build

**Input:**
- group_uuid
- gsk (32 bytes)
- gsk_version
- members[] (array of fingerprint + kyber_pubkey pairs)
- owner_dilithium_privkey (4896 bytes)

**Output:** ikp_blob (binary), ikp_size

**Algorithm:**
```
FUNCTION ikp_build(group_uuid, gsk, gsk_version, members, owner_privkey):
    1. Validate inputs:
       IF member_count > 256 THEN RETURN error("Too many members")
       IF member_count == 0 THEN RETURN error("No members")

    2. Allocate buffer:
       header_size = 19
       entries_size = 1672 * member_count
       sig_size = 4691
       total_size = header_size + entries_size + sig_size
       buffer = allocate(total_size)

    3. Write header:
       buffer[0:4] = "GSK " (magic)
       buffer[4] = 1 (format version)
       buffer[5:9] = gsk_version (big-endian uint32)
       buffer[9:11] = member_count (big-endian uint16)
       buffer[11:19] = current_timestamp (big-endian uint64)

    4. For each member (i = 0 to member_count-1):
       offset = 19 + (i * 1672)

       a. Write fingerprint:
          buffer[offset:offset+64] = members[i].fingerprint

       b. Encapsulate with member's Kyber pubkey:
          (kek, kyber_ct) = kyber1024_encapsulate(members[i].kyber_pubkey)
          buffer[offset+64:offset+1632] = kyber_ct

       c. Wrap GSK with KEK:
          nonce = random_bytes(12)
          (ct, tag) = aes256_gcm_encrypt(key=kek, nonce=nonce, plaintext=gsk)
          buffer[offset+1632:offset+1644] = nonce
          buffer[offset+1644:offset+1660] = tag
          buffer[offset+1660:offset+1672] = ct

       d. Securely wipe kek from memory

    5. Write owner fingerprint:
       sig_offset = 19 + entries_size
       owner_fp = sha3_512(owner_dilithium_pubkey)
       buffer[sig_offset:sig_offset+64] = owner_fp

    6. Sign everything before signature:
       message_to_sign = buffer[0:sig_offset+64]
       signature = dilithium5_sign(owner_privkey, message_to_sign)
       buffer[sig_offset+64:sig_offset+4691] = signature

    7. RETURN (buffer, total_size)
```

### 5.6 Initial Key Packet Extract

**Input:**
- ikp_blob (binary)
- ikp_size
- my_fingerprint (64 bytes)
- my_kyber_privkey (3168 bytes)

**Output:** (gsk, gsk_version) or error

**Algorithm:**
```
FUNCTION ikp_extract(ikp_blob, ikp_size, my_fp, kyber_privkey):
    1. Validate magic:
       IF ikp_blob[0:4] != "GSK " THEN RETURN error("Invalid magic")

    2. Parse header:
       format_version = ikp_blob[4]
       IF format_version != 1 THEN RETURN error("Unknown format")
       gsk_version = parse_uint32_be(ikp_blob[5:9])
       member_count = parse_uint16_be(ikp_blob[9:11])
       created_at = parse_uint64_be(ikp_blob[11:19])

    3. Validate size:
       expected_size = 19 + (1672 * member_count) + 4691
       IF ikp_size != expected_size THEN RETURN error("Invalid size")

    4. Find my entry:
       FOR i = 0 to member_count-1:
           offset = 19 + (i * 1672)
           entry_fp = ikp_blob[offset:offset+64]
           IF entry_fp == my_fp THEN
               my_offset = offset
               BREAK
       IF my_offset not found THEN RETURN error("Not a member")

    5. Extract my wrapped GSK:
       kyber_ct = ikp_blob[my_offset+64:my_offset+1632]
       nonce = ikp_blob[my_offset+1632:my_offset+1644]
       tag = ikp_blob[my_offset+1644:my_offset+1660]
       wrapped_gsk = ikp_blob[my_offset+1660:my_offset+1672]

    6. Decapsulate to get KEK:
       kek = kyber1024_decapsulate(kyber_privkey, kyber_ct)

    7. Unwrap GSK:
       gsk = aes256_gcm_decrypt(key=kek, nonce=nonce, ciphertext=wrapped_gsk, tag=tag)
       IF decryption fails THEN RETURN error("Unwrap failed")

    8. Securely wipe kek from memory

    9. RETURN (gsk, gsk_version)
```

### 5.7 Initial Key Packet Verify

**Input:**
- ikp_blob (binary)
- ikp_size
- owner_dilithium_pubkey (2592 bytes)

**Output:** valid (bool)

**Algorithm:**
```
FUNCTION ikp_verify(ikp_blob, ikp_size, owner_pubkey):
    1. Parse header to get member_count:
       member_count = parse_uint16_be(ikp_blob[9:11])

    2. Calculate signature offset:
       sig_offset = 19 + (1672 * member_count)

    3. Verify owner fingerprint matches pubkey:
       stored_owner_fp = ikp_blob[sig_offset:sig_offset+64]
       expected_owner_fp = sha3_512(owner_pubkey)
       IF stored_owner_fp != expected_owner_fp THEN RETURN false

    4. Extract signature:
       signature = ikp_blob[sig_offset+64:sig_offset+4691]

    5. Verify signature:
       message = ikp_blob[0:sig_offset+64]
       valid = dilithium5_verify(owner_pubkey, message, signature)

    6. RETURN valid
```

### 5.8 Group Message Encrypt

**Input:**
- plaintext (string)
- gsk (32 bytes)
- gsk_version (uint32)
- sender_fingerprint (64 bytes)
- sender_dilithium_privkey (4896 bytes)

**Output:** encrypted_message (binary), size

**Algorithm:**
```
FUNCTION group_message_encrypt(plaintext, gsk, gsk_version, sender_fp, sender_privkey):
    1. Generate message metadata:
       timestamp_ms = current_time_milliseconds()
       message_id = (timestamp_ms << 16) | random_uint16()

    2. Encrypt plaintext:
       nonce = random_bytes(12)
       (ciphertext, tag) = aes256_gcm_encrypt(
           key = gsk,
           nonce = nonce,
           plaintext = utf8_encode(plaintext),
           aad = gsk_version || timestamp_ms  // Bind to metadata
       )

    3. Build message buffer:
       header_size = 88
       payload_size = 12 + 16 + 4 + len(ciphertext)
       sig_size = 4627
       total_size = header_size + payload_size + sig_size
       buffer = allocate(total_size)

    4. Write header:
       buffer[0:4] = "GMSG"
       buffer[4:8] = gsk_version (big-endian uint32)
       buffer[8:16] = timestamp_ms (big-endian uint64)
       buffer[16:24] = message_id (big-endian uint64)
       buffer[24:88] = sender_fp

    5. Write encrypted payload:
       buffer[88:100] = nonce
       buffer[100:116] = tag
       buffer[116:120] = len(ciphertext) (big-endian uint32)
       buffer[120:120+len(ciphertext)] = ciphertext

    6. Sign message:
       sig_offset = 120 + len(ciphertext)
       message_to_sign = buffer[0:sig_offset]
       signature = dilithium5_sign(sender_privkey, message_to_sign)
       buffer[sig_offset:sig_offset+4627] = signature

    7. RETURN (buffer, total_size)
```

### 5.9 Group Message Decrypt

**Input:**
- encrypted_message (binary)
- message_size
- group_uuid (for GSK lookup)
- sender_dilithium_pubkey (2592 bytes, for verification)
- my_kyber_privkey (for GSK decryption if needed)

**Output:** (plaintext, sender_fp, timestamp_ms, message_id) or error

**Algorithm:**
```
FUNCTION group_message_decrypt(encrypted, size, group_uuid, sender_pubkey, kyber_privkey):
    1. Validate magic:
       IF encrypted[0:4] != "GMSG" THEN RETURN error("Invalid magic")

    2. Parse header:
       gsk_version = parse_uint32_be(encrypted[4:8])
       timestamp_ms = parse_uint64_be(encrypted[8:16])
       message_id = parse_uint64_be(encrypted[16:24])
       sender_fp = encrypted[24:88]

    3. Parse payload:
       nonce = encrypted[88:100]
       tag = encrypted[100:116]
       ciphertext_len = parse_uint32_be(encrypted[116:120])
       ciphertext = encrypted[120:120+ciphertext_len]

    4. Verify signature:
       sig_offset = 120 + ciphertext_len
       signature = encrypted[sig_offset:sig_offset+4627]
       message_to_verify = encrypted[0:sig_offset]

       expected_sender_fp = sha3_512(sender_pubkey)
       IF sender_fp != expected_sender_fp THEN RETURN error("Fingerprint mismatch")

       valid = dilithium5_verify(sender_pubkey, message_to_verify, signature)
       IF NOT valid THEN RETURN error("Invalid signature")

    5. Load GSK for this version:
       gsk = gsk_load(group_uuid, gsk_version, kyber_privkey)
       IF error THEN RETURN error("GSK not found for version")

    6. Decrypt message:
       plaintext_bytes = aes256_gcm_decrypt(
           key = gsk,
           nonce = nonce,
           ciphertext = ciphertext,
           tag = tag,
           aad = gsk_version || timestamp_ms
       )
       IF decryption fails THEN RETURN error("Decryption failed")

    7. Decode plaintext:
       plaintext = utf8_decode(plaintext_bytes)

    8. RETURN (plaintext, sender_fp, timestamp_ms, message_id)
```

### 5.10 GSK Rotation (On Member Change)

**Input:**
- group_uuid
- members[] (current member list after add/remove)
- owner credentials

**Output:** success/failure, new_gsk_version

**Algorithm:**
```
FUNCTION gsk_rotate(group_uuid, members, owner_kyber_pub, owner_kyber_priv, owner_dilithium_priv):
    1. Generate new GSK:
       (gsk, new_version, created_at, expires_at) = gsk_generate(group_uuid)

    2. Store GSK locally (encrypted):
       gsk_store(group_uuid, new_version, gsk, owner_kyber_pub)

    3. Fetch Kyber pubkeys for all members:
       FOR each member in members:
           member_identity = dht_keyserver_lookup(member.fingerprint)
           IF error THEN
               log_warning("Could not get pubkey for member, skipping")
               CONTINUE
           member.kyber_pubkey = member_identity.kyber_pubkey

    4. Build Initial Key Packet:
       (ikp_blob, ikp_size) = ikp_build(
           group_uuid, gsk, new_version, members, owner_dilithium_priv
       )

    5. Publish to DHT:
       dht_key = "dna:group:" + group_uuid + ":gsk"
       dht_put_signed(dht_key, ikp_blob, ttl=30_days)

    6. Securely wipe gsk from memory

    7. RETURN (success, new_version)
```

### 5.11 Group Message Send

**Input:**
- group_uuid
- plaintext
- sender credentials

**Output:** success/failure, message_id

**Algorithm:**
```
FUNCTION group_send_message(group_uuid, plaintext, sender_fp, sender_kyber_priv, sender_dilithium_priv):
    1. Load active GSK:
       (gsk, gsk_version) = gsk_load_active(group_uuid, sender_kyber_priv)
       IF error THEN RETURN error("No active GSK - sync from DHT first")

    2. Encrypt message:
       (encrypted, size) = group_message_encrypt(
           plaintext, gsk, gsk_version, sender_fp, sender_dilithium_priv
       )

    3. Fetch my existing messages from DHT:
       dht_key = "dna:group:" + group_uuid + ":msg"
       my_value = dht_get_my_value(dht_key)  // Uses my value_id

    4. Append new message:
       IF my_value exists THEN
           messages = deserialize_sender_value(my_value)
           messages.append(encrypted)
       ELSE
           messages = [encrypted]

    5. Prune old messages (older than 7 days):
       current_time = current_time_milliseconds()
       messages = filter(messages, msg => msg.timestamp_ms > current_time - 7_days_ms)

    6. Serialize and publish:
       new_value = serialize_sender_value(messages)
       dht_put_signed(dht_key, new_value, ttl=7_days)

    7. Store locally:
       INSERT INTO group_messages (group_uuid, message_id, sender_fp, timestamp_ms, gsk_version, plaintext, received_at)
       VALUES (?, ?, ?, ?, ?, ?, current_time())

    8. Securely wipe gsk from memory

    9. RETURN (success, message_id)
```

### 5.12 Group Message Sync

**Input:**
- group_uuid
- my credentials

**Output:** new_message_count

**Algorithm:**
```
FUNCTION group_sync_messages(group_uuid, my_fp, my_kyber_priv):
    1. First, sync GSK if needed:
       current_gsk_version = gsk_get_current_version(group_uuid)

       dht_gsk_key = "dna:group:" + group_uuid + ":gsk"
       ikp_blob = dht_get(dht_gsk_key)

       IF ikp_blob exists THEN
           dht_gsk_version = parse_gsk_version_from_ikp(ikp_blob)
           IF dht_gsk_version > current_gsk_version THEN
               // Need to extract new GSK
               owner_pubkey = get_group_owner_pubkey(group_uuid)
               IF ikp_verify(ikp_blob, owner_pubkey) THEN
                   (gsk, version) = ikp_extract(ikp_blob, my_fp, my_kyber_priv)
                   gsk_store(group_uuid, version, gsk, my_kyber_pub)

    2. Fetch all messages from DHT:
       dht_msg_key = "dna:group:" + group_uuid + ":msg"
       all_values = dht_get_all(dht_msg_key)  // Returns all senders' values

    3. Process each sender's messages:
       new_count = 0
       FOR each value in all_values:
           messages = deserialize_sender_value(value)

           FOR each msg in messages:
               // Check if already have this message
               exists = SELECT 1 FROM group_messages
                        WHERE group_uuid = ? AND sender_fp = ? AND message_id = ?
               IF exists THEN CONTINUE

               // Get sender's pubkey for verification
               sender_pubkey = dht_keyserver_lookup(msg.sender_fp).dilithium_pubkey

               // Decrypt and verify
               result = group_message_decrypt(msg, group_uuid, sender_pubkey, my_kyber_priv)
               IF error THEN
                   log_warning("Could not decrypt message, skipping")
                   CONTINUE

               // Store locally
               INSERT INTO group_messages
               (group_uuid, message_id, sender_fp, timestamp_ms, gsk_version, plaintext, received_at)
               VALUES (?, result.message_id, result.sender_fp, result.timestamp_ms, msg.gsk_version, result.plaintext, current_time())

               new_count++

    4. RETURN new_count
```

---

## 6. Function Reference

### 6.1 GSK Core Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `gsk_init` | backup_ctx | int (0=success) | Initialize GSK subsystem, create tables |
| `gsk_set_kem_keys` | kem_pubkey, kem_privkey | int | Set user's Kyber keys for GSK encryption |
| `gsk_clear_kem_keys` | (none) | void | Securely wipe KEM keys from memory |
| `gsk_generate` | group_uuid | gsk_entry_t* | Generate new GSK with incremented version |
| `gsk_store` | group_uuid, version, gsk | int | Encrypt and store GSK in database |
| `gsk_load` | group_uuid, version | gsk (32 bytes) | Load and decrypt specific GSK version |
| `gsk_load_active` | group_uuid | (gsk, version) | Load latest non-expired GSK |
| `gsk_get_current_version` | group_uuid | uint32_t | Get highest stored version number |
| `gsk_cleanup_expired` | (none) | int (count) | Delete expired GSKs from database |

### 6.2 IKP Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `ikp_build` | group_uuid, gsk, version, members[], owner_privkey | (blob, size) | Build Initial Key Packet |
| `ikp_extract` | blob, size, my_fp, my_kyber_priv | (gsk, version) | Extract GSK from IKP |
| `ikp_verify` | blob, size, owner_pubkey | bool | Verify IKP signature |
| `ikp_get_version` | blob | uint32_t | Parse GSK version from IKP header |
| `ikp_get_member_count` | blob | uint16_t | Parse member count from IKP header |

### 6.3 Group Management Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `groups_create` | name | uuid | Create new group, generate GSK v0 |
| `groups_delete` | uuid | int | Delete group locally |
| `groups_list` | (none) | group_info_t[] | List all groups user is member of |
| `groups_get_info` | uuid | group_info_t | Get single group info |
| `groups_get_members` | uuid | fingerprint[] | Get group member list |
| `groups_add_member` | uuid, fingerprint | int | Add member, rotate GSK, send invitation |
| `groups_remove_member` | uuid, fingerprint | int | Remove member, rotate GSK |
| `groups_is_owner` | uuid | bool | Check if local user owns group |

### 6.4 Group Messaging Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `groups_send_message` | uuid, plaintext | message_id | Encrypt and send message to group |
| `groups_sync_messages` | uuid | int (new_count) | Fetch new messages from DHT |
| `groups_get_conversation` | uuid, limit, offset | message_t[] | Get local message history |
| `groups_gsk_sync` | uuid | int | Sync GSK from DHT |
| `groups_gsk_rotate` | uuid | int | Manually rotate GSK |

### 6.5 Invitation Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `groups_send_invitation` | uuid, fingerprint | int | Send invitation via Spillway |
| `groups_accept_invitation` | uuid | int | Accept invitation, fetch GSK, join group |
| `groups_decline_invitation` | uuid | int | Decline invitation, delete locally |
| `groups_get_pending` | (none) | invitation_t[] | Get pending invitations |

---

## 7. Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | GSK_OK | Success |
| -1 | GSK_ERR_NULL_PARAM | Null parameter passed |
| -2 | GSK_ERR_NOT_FOUND | GSK or group not found |
| -3 | GSK_ERR_EXPIRED | GSK has expired |
| -4 | GSK_ERR_DB | Database error |
| -5 | GSK_ERR_ENCRYPT | Encryption failed |
| -6 | GSK_ERR_DECRYPT | Decryption failed |
| -7 | GSK_ERR_VERIFY | Signature verification failed |
| -8 | GSK_ERR_DHT | DHT operation failed |
| -9 | GSK_ERR_NOT_MEMBER | User is not a group member |
| -10 | GSK_ERR_NOT_OWNER | User is not group owner |
| -11 | GSK_ERR_INVALID_FORMAT | Invalid data format |
| -12 | GSK_ERR_TOO_MANY_MEMBERS | Exceeds max member limit (256) |

---

## 8. Security Considerations

### 8.1 Forward Secrecy
- Each GSK rotation creates a new key
- Removed members cannot decrypt future messages
- New members cannot decrypt past messages

### 8.2 Key Protection
- GSKs encrypted at rest with Kyber1024 KEM
- Fresh encapsulation per store (no key reuse)
- Private keys wiped from memory after use

### 8.3 Authentication
- IKP signed by group owner (Dilithium5)
- Each message signed by sender (Dilithium5)
- Fingerprints verified against Dilithium pubkeys

### 8.4 Replay Protection
- Message ID includes timestamp + random component
- Deduplication by (group_uuid, sender_fp, message_id)
- GSK version binding in encryption AAD

### 8.5 Denial of Service Mitigation
- Max 256 members per group
- 7-day message TTL (automatic cleanup)
- 30-day GSK TTL (automatic cleanup)

---

## 9. File Structure

### 9.1 After Implementation

```
messenger/
├── gsk.h           (~150 LOC)  GSK + IKP API declarations
├── gsk.c           (~800 LOC)  GSK + IKP implementations (consolidated)
├── groups.h        (~100 LOC)  Group management API
└── groups.c        (~400 LOC)  Group management + messaging

message_backup.c    (modify)    Add 5 group tables
messenger.h         (modify)    Add group API exports
cli/cli.c           (modify)    Add group CLI commands
src/dna_engine.c    (modify)    Add FFI bindings
```

### 9.2 Files to Delete

```
messenger/gsk_packet.c          (merged into gsk.c)
messenger/gsk_packet.h          (merged into gsk.h)
messenger/gsk_encryption.c      (merged into gsk.c)
messenger/gsk_encryption.h      (merged into gsk.h)
messenger_groups.c              (replaced by messenger/groups.c)
dht/shared/dht_groups.c         (not needed - local only)
dht/shared/dht_groups.h         (not needed)
dht/shared/dht_gsk_storage.c    (not needed - direct DHT put)
dht/shared/dht_gsk_storage.h    (not needed)
dht/client/dna_group_outbox.c   (replaced by messenger/groups.c)
dht/client/dna_group_outbox.h   (replaced)
database/group_invitations.c    (merged into groups.c)
database/group_invitations.h    (merged)
```

---

## 10. Implementation Phases

### Phase 1: Database Schema
- Add 5 tables to message_backup.c
- Drop existing group tables (fresh start)
- Test table creation

### Phase 2: GSK Core
- Consolidate gsk.c (merge packet + encryption)
- Implement all gsk_* functions
- Unit test GSK generate/store/load

### Phase 3: IKP Functions
- Implement ikp_build, ikp_extract, ikp_verify
- Unit test with mock data

### Phase 4: Group Management
- Create messenger/groups.c
- Implement local CRUD (groups, members)
- Implement GSK rotation on member change

### Phase 5: DHT Integration
- Implement IKP publish to DHT
- Implement message publish to DHT
- Implement sync from DHT

### Phase 6: Invitations
- Implement invitation send via Spillway
- Implement accept/decline flow

### Phase 7: CLI Commands
- Add group-create, group-add, group-send, etc.
- Test end-to-end via CLI

### Phase 8: FFI Bindings
- Update dna_engine.c with group functions
- Update dna_engine.dart FFI bindings

### Phase 9: Flutter UI
- Update groups_provider.dart
- Implement group chat screen
- Test end-to-end in app

### Phase 10: Cleanup
- Delete old files
- Update CMakeLists.txt
- Final testing

---

## 11. Appendix: Constants

```
// Cryptographic sizes
KYBER1024_PUBKEY_SIZE    = 1568
KYBER1024_PRIVKEY_SIZE   = 3168
KYBER1024_CIPHERTEXT_SIZE = 1568
KYBER1024_SHARED_SECRET  = 32

DILITHIUM5_PUBKEY_SIZE   = 2592
DILITHIUM5_PRIVKEY_SIZE  = 4896
DILITHIUM5_SIGNATURE_SIZE = 4627

AES256_KEY_SIZE          = 32
AES256_GCM_NONCE_SIZE    = 12
AES256_GCM_TAG_SIZE      = 16

SHA3_512_SIZE            = 64

// GSK sizes
GSK_KEY_SIZE             = 32
GSK_ENCRYPTED_SIZE       = 1628  // KEM_CT + nonce + tag + encrypted
GSK_WRAPPED_SIZE         = 60    // nonce + tag + encrypted (in IKP)

// Limits
GSK_MAX_MEMBERS          = 256
GSK_DEFAULT_TTL_DAYS     = 7
GSK_IKP_TTL_DAYS         = 30
GSK_MESSAGE_TTL_DAYS     = 7

// Fingerprint
FINGERPRINT_SIZE         = 64    // SHA3-512 binary
FINGERPRINT_HEX_SIZE     = 128   // Hex string

// UUID
UUID_SIZE                = 36    // UUID v4 string (no null)
UUID_SIZE_WITH_NULL      = 37
```
