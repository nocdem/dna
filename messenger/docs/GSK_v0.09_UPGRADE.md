# DNA Messenger v0.09 - GSK (Group Symmetric Key) Upgrade

**Status:** Planned
**Date:** 2025-11-20
**Breaking Change:** No (backward compatible with v0.08)
**Security Level:** NIST Category 5 (256-bit quantum security maintained)

---

## Executive Summary

v0.09 introduces **Group Symmetric Key (GSK)** encryption for group messages, reducing message overhead from **1,608 bytes × N recipients** to a fixed **~20 bytes** regardless of group size.

### Key Metrics:

| Group Size | Current (v0.08) | GSK (v0.09) | Size Reduction |
|------------|-----------------|-------------|----------------|
| 5 members | 12,890 bytes | 4,870 bytes | **62%** |
| 20 members | 37,010 bytes | 4,870 bytes | **87%** |
| 50 members | 85,250 bytes | 4,870 bytes | **94%** |
| 100 members | 165,650 bytes | 4,870 bytes | **97%** |

**One-time setup cost:** ~168 KB for 100-member group (stored in DHT, fetched once)

---

## Architecture Overview

### Current System (v0.08 - Per-Recipient Kyber1024)

```
Every message:
┌────────────────────────────────────────────────────────┐
│ For each recipient:                                    │
│   1. Kyber1024 encapsulation of DEK → 1,568 bytes     │
│   2. AES key wrap of DEK → 40 bytes                   │
│   Total per recipient: 1,608 bytes                    │
└────────────────────────────────────────────────────────┘

Message size = 20 + (1,608 × N) + 72 + plaintext + 4,630
```

**Problem:** Unsustainable for large groups (exceeds DHT 56 KB limit at 35 members)

### GSK System (v0.09)

```
One-time setup (per group):
┌────────────────────────────────────────────────────────┐
│ 1. Generate random 32-byte GSK                        │
│ 2. Wrap GSK with Kyber1024 for each member           │
│ 3. Store Initial Key Packet in DHT (chunked)         │
│ 4. Members fetch once and cache locally               │
└────────────────────────────────────────────────────────┘

Every message:
┌────────────────────────────────────────────────────────┐
│ 1. Load GSK from local cache                          │
│ 2. Encrypt with AES-256-GCM using GSK                 │
│ 3. Add group_uuid + gsk_version (20 bytes)            │
└────────────────────────────────────────────────────────┘

Message size = 20 + 20 + 72 + plaintext + 4,630 = ~4,870 bytes
```

---

## Message Format v0.09

### MSG_TYPE_GROUP_GSK (0x01) Format:

```
┌────────────────────────────────────────────────────────────────┐
│                    HEADER (20 bytes)                            │
├───────────┬─────┬───────────────────────────────────────────────┤
│ Offset    │ Len │ Field                                         │
├───────────┼─────┼───────────────────────────────────────────────┤
│ 0-7       │  8  │ magic = "PQSIGENC"                            │
│ 8         │  1  │ version = 0x08                                │
│ 9         │  1  │ enc_key_type = 23 (not used in GSK mode)      │
│ 10        │  1  │ recipient_count = 0 (not used in GSK mode)    │
│ 11        │  1  │ message_type = 0x01 (MSG_TYPE_GROUP_GSK)      │
│ 12-15     │  4  │ encrypted_size                                │
│ 16-19     │  4  │ signature_size                                │
└───────────┴─────┴───────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│                 GSK_METADATA (20 bytes)                         │
├───────────┬─────┬───────────────────────────────────────────────┤
│ 20-35     │ 16  │ group_uuid (128-bit binary UUID)              │
│ 36-39     │  4  │ gsk_version (uint32_t, network byte order)    │
└───────────┴─────┴───────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│              AES-256-GCM ENCRYPTED DATA                         │
├───────────┬─────┬───────────────────────────────────────────────┤
│ 40-51     │ 12  │ nonce (random, 96-bit)                        │
│ 52-115    │ 64  │ ciphertext: sender_fingerprint (SHA3-512)     │
│ 116-123   │  8  │ ciphertext: timestamp (uint64_t)              │
│ 124-N     │ var │ ciphertext: plaintext message                 │
│ N+1       │ 16  │ tag (GCM authentication tag)                  │
└───────────┴─────┴───────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│            DILITHIUM5 SIGNATURE (~4,630 bytes)                  │
├───────────┬─────┬───────────────────────────────────────────────┤
│           │  1  │ type = 23 (Dilithium5 / ML-DSA-87)            │
│           │  2  │ sig_size (uint16_t, big-endian)               │
│           │~4627│ signature (Dilithium5 signature bytes)        │
└───────────┴─────┴───────────────────────────────────────────────┘
```

**Total for 100-byte message:** 4,870 bytes (vs 165,650 bytes in v0.08!)

---

## Data Structures

### GSK Entry (Local Storage)

```c
// Stored in SQLite: ~/.dna/messages.db
typedef struct {
    char group_uuid[37];       // UUID v4 (36 + null)
    uint32_t gsk_version;      // Rotation counter (0, 1, 2, ...)
    uint8_t gsk[32];           // AES-256 key
    uint64_t created_at;       // Unix timestamp
    uint64_t expires_at;       // created_at + 7 days
} gsk_entry_t;
```

**Database Schema v7:**

```sql
CREATE TABLE IF NOT EXISTS dht_group_gsks (
    group_uuid TEXT NOT NULL,
    gsk_version INTEGER NOT NULL,
    gsk_key BLOB NOT NULL,        -- 32-byte AES-256 key
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (group_uuid, gsk_version)
);
```

### Initial Key Packet (DHT Distribution)

```c
typedef struct {
    char group_uuid[37];           // Which group
    uint32_t gsk_version;          // GSK version (0 for initial)
    uint8_t member_count;          // Number of recipients

    // Per-member entry (repeated member_count times)
    struct {
        uint8_t fingerprint[64];   // SHA3-512 recipient fingerprint
        uint8_t kyber_ct[1568];    // Kyber1024 encapsulation of GSK
        uint8_t wrapped_gsk[40];   // AES-wrap(GSK, KEK from Kyber)
    } members[];

    // Dilithium5 signature by group owner
    uint8_t signature_type;        // 23 (Dilithium5)
    uint16_t signature_size;       // ~4627
    uint8_t signature[];           // Actual signature
} initial_key_packet_t;
```

**Size Calculation:**
```
Header: 37 + 4 + 1 = 42 bytes
Per member: 64 + 1568 + 40 = 1,672 bytes
Signature: 1 + 2 + 4627 = 4,630 bytes

Total = 42 + (1,672 × member_count) + 4,630 bytes

Examples:
- 5 members: 13,030 bytes (~13 KB)
- 20 members: 38,110 bytes (~37 KB)
- 50 members: 88,230 bytes (~86 KB)
- 100 members: 171,870 bytes (~168 KB)
```

### Group Metadata Extension

```c
// Extended from v0.08
typedef struct {
    char group_uuid[37];
    char name[128];
    char description[512];
    char creator[129];
    uint64_t created_at;
    uint32_t version;
    uint32_t member_count;
    char **members;
    uint32_t gsk_version;  // NEW: Current GSK version
} dht_group_metadata_t;
```

**JSON Serialization:**
```json
{
  "group_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Team Chat",
  "description": "Work discussions",
  "creator": "a3f5e2d1c8b4...",
  "created_at": 1732012800,
  "version": 1,
  "member_count": 5,
  "members": ["fingerprint1", "fingerprint2", ...],
  "gsk_version": 0
}
```

---

## DHT Storage Strategy

### DHT Keys

```
Initial Key Packet (chunked if >50 KB):
├─ Metadata: SHA3-512(group_uuid + ":gsk:v" + version + ":meta")
│  Value: {"chunks": 4, "total_size": 171870}
│
├─ Chunk 0: SHA3-512(group_uuid + ":gsk:v" + version + ":chunk0")
│  Value: First 50,000 bytes of packet
│
├─ Chunk 1: SHA3-512(group_uuid + ":gsk:v" + version + ":chunk1")
│  Value: Next 50,000 bytes
│
└─ ...

Group Metadata (existing):
└─ Key: SHA3-512(group_uuid)
   Value: JSON metadata (includes gsk_version field)
   TTL: 7 days
```

### Chunking Strategy

```c
#define MAX_CHUNK_SIZE 50000  // 50 KB (safe under DHT 56 KB limit)

int num_chunks = (total_size + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;

for (int i = 0; i < num_chunks; i++) {
    char chunk_key[129];
    sprintf(chunk_key, "%s:gsk:v%u:chunk%d",
            group_uuid_hash, version, i);

    int offset = i * MAX_CHUNK_SIZE;
    int chunk_size = min(MAX_CHUNK_SIZE, total_size - offset);

    dht_put_signed(ctx, chunk_key, 128,
                   packet + offset, chunk_size,
                   version, 7*24*3600);  // 7-day TTL
}
```

### Fetching from DHT

```c
// 1. Fetch metadata to determine chunk count
char meta_key[129];
sprintf(meta_key, "%s:gsk:v%u:meta", group_uuid_hash, version);
char *meta_json = dht_get(ctx, meta_key, 128);
int num_chunks = parse_json_int(meta_json, "chunks");

// 2. Fetch all chunks
uint8_t *full_packet = malloc(total_size);
for (int i = 0; i < num_chunks; i++) {
    char chunk_key[129];
    sprintf(chunk_key, "%s:gsk:v%u:chunk%d", group_uuid_hash, version, i);
    uint8_t *chunk_data;
    size_t chunk_size;
    dht_get(ctx, chunk_key, 128, &chunk_data, &chunk_size);
    memcpy(full_packet + (i * MAX_CHUNK_SIZE), chunk_data, chunk_size);
}

// 3. Parse packet and extract our GSK
```

---

## Implementation Flow

### 1. Group Creation with GSK

```
User creates group → messenger_create_group()
│
├─ 1. Generate UUID v4
│
├─ 2. Generate GSK (random 32 bytes)
│      gsk_generate(group_uuid, 0, gsk)
│
├─ 3. Fetch member Kyber1024 public keys from DHT keyserver
│      (cache-first, 7-day TTL)
│
├─ 4. Build Initial Key Packet
│      For each member:
│        - Kyber1024 encapsulation: kyber_ct = Enc(gsk, member_pubkey)
│        - AES key wrap: wrapped_gsk = AES_Wrap(gsk, kek)
│        - Store entry: fingerprint | kyber_ct | wrapped_gsk
│      Sign entire packet with owner's Dilithium5 key
│
├─ 5. Store in DHT (chunked if large)
│      dht_gsk_store(ctx, group_uuid, 0, packet, packet_size)
│      - Chunk into 50 KB pieces if needed
│      - Store metadata with chunk count
│      - Use SHA3-512 keys with 7-day TTL
│
├─ 6. Store locally (encrypted)
│      gsk_store(group_uuid, 0, gsk)
│      - Insert into dht_group_gsks table
│      - Set expires_at = created_at + 7 days
│
└─ 7. Update group metadata
       metadata.gsk_version = 0
       dht_groups_update(ctx, metadata)
```

### 2. Sending Group Message with GSK

```
User sends message → messenger_send_group_message()
│
├─ 1. Load GSK from local database
│      SELECT gsk_key, gsk_version FROM dht_group_gsks
│      WHERE group_uuid = ? AND expires_at > ?
│      ORDER BY gsk_version DESC LIMIT 1
│
├─ 2. If not found: Fetch from DHT
│      - Get current version from group metadata
│      - Fetch Initial Key Packet (reassemble chunks)
│      - Extract our entry (match fingerprint)
│      - Decapsulate: kek = Kyber1024_Dec(kyber_ct, my_privkey)
│      - Unwrap: gsk = AES_Unwrap(wrapped_gsk, kek)
│      - Store locally
│      - Retry send
│
├─ 3. Build message with GSK
│      Header: message_type = MSG_TYPE_GROUP_GSK (0x01)
│      GSK_Metadata: group_uuid (16 bytes) | gsk_version (4 bytes)
│      Nonce: random 12 bytes
│      Payload: fingerprint(64) | timestamp(8) | plaintext
│      Encrypt: AES-256-GCM(payload, gsk, nonce)
│      Sign: Dilithium5(entire message, my_sign_key)
│
├─ 4. Store in local database (single copy)
│      INSERT INTO messages (encrypted_message, group_id, ...)
│      - NOT per-recipient (saves database space too!)
│
└─ 5. Send via P2P to group members
       - Try direct TCP connection to each online member
       - Fall back to DHT offline queue for offline members
       - Message size: ~4,870 bytes (vs 165,650 for 100 members!)
```

### 3. Receiving and Decrypting GSK Message

```
Message received → dna_decrypt_message_raw()
│
├─ 1. Parse header
│      if (header.message_type == MSG_TYPE_GROUP_GSK) {
│          // GSK decryption path
│      }
│
├─ 2. Extract GSK metadata
│      group_uuid = bytes 20-35 (16-byte binary UUID)
│      gsk_version = bytes 36-39 (uint32_t)
│
├─ 3. Load GSK from local database
│      SELECT gsk_key FROM dht_group_gsks
│      WHERE group_uuid = ? AND gsk_version = ?
│
├─ 4. If not found: Fetch from DHT
│      gsk_fetch_on_demand(group_uuid, gsk_version)
│      - Fetch chunked packet from DHT
│      - Extract our GSK
│      - Store locally
│
├─ 5. Decrypt payload
│      plaintext = AES-256-GCM_Dec(ciphertext, gsk, nonce, tag)
│      - Extract sender_fingerprint (64 bytes)
│      - Extract timestamp (8 bytes)
│      - Extract message text
│
├─ 6. Verify signature
│      - Fetch sender's Dilithium5 pubkey from keyserver (by fingerprint)
│      - Verify: Dilithium5_Verify(signature, message, sender_pubkey)
│
└─ 7. Display message
```

### 4. GSK Discovery (Periodic Check)

```
Background task (every 2 minutes):
│
├─ For each group in local cache:
│   │
│   ├─ Fetch group metadata from DHT
│   │
│   ├─ Compare gsk_version:
│   │   local_version = get_local_gsk_version(group_uuid)
│   │   dht_version = metadata.gsk_version
│   │
│   └─ If dht_version > local_version:
│       - New version available!
│       - Fetch Initial Key Packet for new version
│       - Extract our GSK
│       - Store locally
│       - Log: "GSK updated from v{old} to v{new} for {group_name}"
│
└─ Continue polling
```

---

## GSK Rotation

### Rotation Triggers

1. **Time-based:** Every 7 days (automatic)
2. **Event-based:** Member removed from group
3. **Manual:** Group owner explicitly rotates

### Rotation Flow

```
Owner triggers rotation → gsk_rotate(group_uuid)
│
├─ 1. Get current version
│      current_version = get_current_gsk_version(group_uuid)
│      new_version = current_version + 1
│
├─ 2. Generate new GSK
│      gsk_generate(group_uuid, new_version, new_gsk)
│
├─ 3. Get updated member list
│      members = get_group_members(group_uuid)
│      // Excludes removed members, includes new members
│
├─ 4. Build new Initial Key Packet
│      gsk_packet_build(group_uuid, new_version, new_gsk,
│                       members, member_count, &packet, &packet_size)
│
├─ 5. Store in DHT (chunked)
│      dht_gsk_store(ctx, group_uuid, new_version, packet, packet_size)
│
├─ 6. Store locally
│      gsk_store(group_uuid, new_version, new_gsk)
│      - Old version remains in database for decrypting old messages
│
└─ 7. Update group metadata
       metadata.gsk_version = new_version
       dht_groups_update(ctx, metadata)
       - Members will discover new version on next poll (2 min max)
```

### Old Message Decryption

```
Messages include gsk_version in GSK_Metadata (bytes 36-39)

Decryption flow:
├─ Extract gsk_version from message
├─ Load that specific version from database:
│   SELECT gsk_key FROM dht_group_gsks
│   WHERE group_uuid = ? AND gsk_version = ?
│
└─ If not found:
    - Fetch from DHT (old versions stay for 7 days)
    - If DHT expired: Cannot decrypt (expected after 7 days)

Recommendation: Keep last 30 days of GSK versions locally
```

---

## Security Analysis

### Threat Model

**Attack:** Compromise any single member's Kyber private key

**Impact (both v0.08 and v0.09):**
- Attacker decrypts **all group messages** (member is recipient of all)
- **Blast radius: IDENTICAL** in both systems

**Why GSK doesn't reduce security:**
- v0.08: Compromise member key → Decapsulate all per-recipient entries → All DEKs → All messages
- v0.09: Compromise member key → Decrypt local GSK storage → GSK → All messages
- **Result:** Same impact in group context

### GSK-Specific Risks

| Risk | Mitigation |
|------|-----------|
| **Long-lived shared secret** | 7-day automatic rotation |
| **GSK database theft** | GSK stored encrypted (not implemented in this spec, future) |
| **Post-compromise security** | Rotation provides forward secrecy after 7 days |
| **Member removal** | Immediate rotation on member removal |

### Security Properties Maintained

✅ **Post-quantum security:** Kyber1024 + Dilithium5 (NIST Category 5)
✅ **End-to-end encryption:** Messages encrypted client-side
✅ **Message authentication:** Dilithium5 signatures
✅ **Sender authentication:** Fingerprint in encrypted payload
✅ **Replay protection:** Timestamp in encrypted payload

### Security Properties Changed

⚠️ **Forward secrecy:** Limited to 7-day rotation period (was per-message DEK)
⚠️ **Group-wide compromise:** GSK is shared (vs individual per-recipient keys)
✅ **Mitigated by:** Rotation, encrypted local storage, DHT access control

---

## Performance Analysis

### Message Size Comparison

| Metric | v0.08 (100 members) | v0.09 GSK | Reduction |
|--------|---------------------|-----------|-----------|
| Header | 20 bytes | 20 bytes | 0% |
| Recipients/Metadata | 160,800 bytes | 20 bytes | **99.99%** |
| Encrypted payload | 172 bytes | 172 bytes | 0% |
| Signature | 4,630 bytes | 4,630 bytes | 0% |
| **Total** | **165,622 bytes** | **4,842 bytes** | **97.1%** |

### DHT Impact

| Operation | v0.08 | v0.09 GSK |
|-----------|-------|-----------|
| **Per message (100 members)** | 165 KB write | 4.8 KB write |
| **Setup cost** | 0 KB | 168 KB (one-time) |
| **After 35 messages** | 5.8 MB total | 336 KB total |
| **After 100 messages** | 16.6 MB total | 650 KB total |

**Break-even point:** ~1 message (immediate savings)

### Database Storage

| Aspect | v0.08 | v0.09 GSK |
|--------|-------|-----------|
| **Message storage** | Per-recipient (100 copies) | Single copy |
| **Database size** | 100 × message size | 1 × message size |
| **Queries** | `recipient = ?` | `group_id = ?` |

### Network Bandwidth

| Scenario | v0.08 | v0.09 GSK |
|----------|-------|-----------|
| **Send to 100 online** | 16.6 MB | 480 KB |
| **Send to 50 online, 50 offline** | 8.3 MB + 8.3 MB DHT | 240 KB + 240 KB DHT |
| **Fetch on join** | 0 KB | 168 KB (one-time) |

---

## Migration Path

### Backward Compatibility

**v0.09 clients can:**
- ✅ Send/receive v0.08 messages (MSG_TYPE_DIRECT_PQC)
- ✅ Send/receive v0.09 messages (MSG_TYPE_GROUP_GSK)
- ✅ Participate in v0.08 groups (per-recipient encryption)
- ✅ Participate in v0.09 groups (GSK encryption)

**v0.08 clients:**
- ✅ Send/receive v0.08 messages
- ❌ Cannot decrypt v0.09 messages (unknown message_type = 0x01)
- ⚠️ Will see "Unsupported message type" error

### Gradual Rollout Strategy

**Phase 1: Foundation**
- Deploy v0.09 clients with GSK support
- All messages still use v0.08 format (MSG_TYPE_DIRECT_PQC)
- No breaking changes

**Phase 2: Opt-in GSK**
- Group owners can enable GSK for their groups
- Mixed groups supported (some members v0.08, some v0.09)
- v0.08 members receive "Upgrade required" notification

**Phase 3: Default GSK**
- New groups default to GSK (MSG_TYPE_GROUP_GSK)
- Old groups remain v0.08 until owner migrates
- Smooth transition

**Phase 4: Deprecate v0.08**
- After 90% adoption, deprecate per-recipient encryption
- Archive v0.08 code for reference
- Full GSK rollout

---

## API Reference

### GSK Manager (`messenger/gsk.h`)

```c
// Generate random 32-byte GSK
int gsk_generate(const char *group_uuid, uint32_t version,
                 uint8_t gsk_out[32]);

// Store GSK in local database
int gsk_store(const char *group_uuid, uint32_t version,
              const uint8_t gsk[32]);

// Load GSK from database
int gsk_load(const char *group_uuid, uint32_t version,
             uint8_t gsk_out[32]);

// Load active GSK (latest non-expired)
int gsk_load_active(const char *group_uuid,
                    uint8_t gsk_out[32],
                    uint32_t *version_out);

// Rotate GSK (increment version, generate new)
int gsk_rotate(const char *group_uuid,
               uint32_t *new_version_out,
               uint8_t new_gsk_out[32]);

// Fetch GSK from DHT on demand
int gsk_fetch_on_demand(const char *group_uuid, uint32_t version);
```

### GSK Packet Builder (`messenger/gsk_packet.h`)

```c
// Build Initial Key Packet for distribution
int gsk_packet_build(const char *group_uuid,
                     uint32_t version,
                     const uint8_t gsk[32],
                     const char **member_fingerprints,
                     size_t member_count,
                     uint8_t **packet_out,
                     size_t *packet_size_out);

// Extract GSK from received packet
int gsk_packet_extract(const uint8_t *packet,
                       size_t packet_size,
                       const char *my_fingerprint,
                       uint8_t gsk_out[32],
                       uint32_t *version_out);

// Verify packet signature
int gsk_packet_verify(const uint8_t *packet,
                      size_t packet_size,
                      const uint8_t *owner_dilithium_pubkey);
```

### DHT GSK Storage (`dht/gsk_storage.h`)

```c
// Store GSK packet in DHT (chunked if >50KB)
int dht_gsk_store(dht_context_t *ctx,
                  const char *group_uuid,
                  uint32_t version,
                  const uint8_t *packet,
                  size_t packet_size);

// Fetch GSK packet from DHT (reassemble chunks)
int dht_gsk_fetch(dht_context_t *ctx,
                  const char *group_uuid,
                  uint32_t version,
                  uint8_t **packet_out,
                  size_t *packet_size_out);

// Get current GSK version from group metadata
int dht_gsk_get_current_version(dht_context_t *ctx,
                                 const char *group_uuid,
                                 uint32_t *version_out);
```

---

## Testing Plan

### Unit Tests

```c
// tests/test_gsk.c

void test_gsk_generation() {
    uint8_t gsk[32];
    assert(gsk_generate("test-uuid", 0, gsk) == 0);
    // Verify randomness (all zeros = failure)
    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (gsk[i] != 0) all_zero = 0;
    assert(!all_zero);
}

void test_gsk_packet_build_extract() {
    // Build packet
    uint8_t gsk[32] = {/* test key */};
    const char *members[] = {"fingerprint1", "fingerprint2"};
    uint8_t *packet;
    size_t packet_size;
    assert(gsk_packet_build("uuid", 0, gsk, members, 2,
                            &packet, &packet_size) == 0);

    // Extract
    uint8_t extracted_gsk[32];
    uint32_t version;
    assert(gsk_packet_extract(packet, packet_size, "fingerprint1",
                              extracted_gsk, &version) == 0);

    // Verify
    assert(memcmp(gsk, extracted_gsk, 32) == 0);
    assert(version == 0);
}

void test_dht_chunking() {
    // Create 200 KB packet (requires 4 chunks)
    uint8_t large_packet[200000];
    memset(large_packet, 0xAA, sizeof(large_packet));

    // Store
    assert(dht_gsk_store(ctx, "uuid", 0, large_packet, 200000) == 0);

    // Fetch and verify
    uint8_t *fetched;
    size_t fetched_size;
    assert(dht_gsk_fetch(ctx, "uuid", 0, &fetched, &fetched_size) == 0);
    assert(fetched_size == 200000);
    assert(memcmp(large_packet, fetched, 200000) == 0);
}

void test_gsk_rotation() {
    // Initial GSK
    uint8_t gsk_v0[32];
    gsk_generate("uuid", 0, gsk_v0);
    gsk_store("uuid", 0, gsk_v0);

    // Rotate
    uint32_t new_version;
    uint8_t gsk_v1[32];
    assert(gsk_rotate("uuid", &new_version, gsk_v1) == 0);
    assert(new_version == 1);

    // Verify both versions exist
    uint8_t loaded_v0[32], loaded_v1[32];
    assert(gsk_load("uuid", 0, loaded_v0) == 0);
    assert(gsk_load("uuid", 1, loaded_v1) == 0);
    assert(memcmp(gsk_v0, loaded_v0, 32) == 0);
    assert(memcmp(gsk_v1, loaded_v1, 32) == 0);
}
```

### Integration Tests

```bash
# Test 1: Create 5-member group with GSK
./dna_messenger_imgui --test-mode
> create_group "Test Group" alice bob carol dave eve
> verify_gsk_generated "Test Group"
> send_message "Test Group" "Hello from GSK!"
> verify_message_size < 5000  # Should be ~4.8 KB, not ~13 KB

# Test 2: Member joins and fetches GSK
> add_member "Test Group" frank
> switch_user frank
> fetch_gsk "Test Group"
> decrypt_messages "Test Group"
> verify_decryption_success

# Test 3: Rotation
> rotate_gsk "Test Group"
> send_message "Test Group" "After rotation"
> verify_gsk_version 1
> verify_old_messages_decrypt  # Should still work with v0

# Test 4: Large group (100 members)
> create_large_group "Big Group" 100
> verify_packet_chunked "Big Group"
> send_message "Big Group" "Scalability test"
> verify_message_size < 5000  # Should be ~4.8 KB, not ~166 KB!
```

---

## Deployment Checklist

### Pre-Deployment

- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Database migration tested (v6 → v7)
- [ ] DHT chunking tested with large packets
- [ ] Rotation logic tested
- [ ] Windows cross-compile successful
- [ ] Documentation complete

### Deployment

- [ ] Tag release: v0.09.0
- [ ] Build Linux binary
- [ ] Build Windows binary (MXE)
- [ ] Update CHANGELOG.md
- [ ] Update CLAUDE.md (add Phase 13)
- [ ] Push to GitLab (primary)
- [ ] Push to GitHub (mirror)

### Post-Deployment

- [ ] Monitor DHT usage (should decrease)
- [ ] Monitor message sizes (should be ~4.8 KB for groups)
- [ ] Monitor GSK fetch success rate
- [ ] Monitor rotation success rate
- [ ] Collect user feedback
- [ ] Address any bugs in patch releases

---

## Future Enhancements

### v0.10: Enhanced Security

- Encrypt GSK in local database (currently plaintext)
- Add GSK derivation from BIP39 seed (multi-device sync)
- Implement perfect forward secrecy (Double Ratchet)

### v0.11: Performance Optimizations

- Cache GSK in memory (avoid repeated DB reads)
- Batch DHT chunk fetches
- Parallel packet extraction for multiple groups

### v0.12: Advanced Features

- Sub-group GSK (nested groups with separate keys)
- GSK announcement messages (0x02 type - optional fast notification)
- GSK export/import for group migration

---

## References

### Related Documents

- [CLAUDE.md](/opt/dna-messenger/CLAUDE.md) - Development guidelines
- [MESSAGE_FORMATS.md](/opt/dna-messenger/docs/MESSAGE_FORMATS.md) - Message format specs
- [DHT_REFACTORING_PROGRESS.md](/opt/dna-messenger/docs/DHT_REFACTORING_PROGRESS.md) - DHT architecture

### Code References

- Message encryption: `messenger/messages.c:63-296`
- Message decryption: `dna_api.c:750-975`
- Group creation: `messenger_groups.c:243-342`
- Group messaging: `messenger_groups.c:801-918`
- DHT storage: `dht/core/dht_context.h:101-195`

### External References

- [Kyber (ML-KEM-1024)](https://pq-crystals.org/kyber/) - NIST FIPS 203
- [Dilithium (ML-DSA-87)](https://pq-crystals.org/dilithium/) - NIST FIPS 204
- [OpenDHT](https://github.com/savoirfairelinux/opendht) - DHT implementation

---

**Document Version:** 1.0
**Last Updated:** 2025-11-20
**Status:** Planning Phase
**Next Review:** After Phase 1 implementation

---

**Questions or feedback?** Contact: [cpunk.io](https://cpunk.io) | [Telegram @chippunk_official](https://t.me/chippunk_official)
