# DHT Keyserver Design (Decentralized Public Key Distribution)

**Component:** Decentralized Public Key Infrastructure
**Status:** Research & Planning Phase
**Dependencies:** P2P Transport Layer (DHT)

---

## OVERVIEW

Replace the centralized HTTP keyserver (PostgreSQL-backed) with a fully decentralized DHT-based public key distribution system. Public keys are stored in the Kademlia DHT network with self-signed certificates, enabling peer discovery and key verification without trusted third parties.

**Current System (v0.1.x):**
```
Client → HTTP Keyserver (PostgreSQL) → Public Keys
         └── Single point of failure, centralized trust
```

**Future System (v2.0):**
```
Peer → DHT Network → Public Keys (replicated, self-signed)
       └── No central server, TOFU (Trust On First Use)
```

---

## ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                 DHT Keyserver Architecture                   │
│                                                               │
│   User "alice" wants bob's public key                        │
│         │                                                     │
│         ▼                                                     │
│   ┌──────────────────────────────────────────────────────┐  │
│   │  Query DHT: "pubkey:bob"                             │  │
│   │  Key = SHA256("pubkey:" + "bob")                     │  │
│   └──────────────────────────────────────────────────────┘  │
│         │                                                     │
│         ▼                                                     │
│   ┌──────────────────────────────────────────────────────┐  │
│   │  Kademlia DHT Lookup                                  │  │
│   │  Finds nodes responsible for SHA256("pubkey:bob")    │  │
│   └──────────────────────────────────────────────────────┘  │
│         │                                                     │
│         ▼                                                     │
│   ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐           │
│   │Node C  │  │Node D  │  │Node E  │  │Node F  │           │
│   │(copy 1)│  │(copy 2)│  │(copy 3)│  │(copy 4)│           │
│   └────────┘  └────────┘  └────────┘  └────────┘           │
│         │                                                     │
│         ▼                                                     │
│   ┌──────────────────────────────────────────────────────┐  │
│   │  Returns: {                                           │  │
│   │    identity: "bob",                                   │  │
│   │    dilithium_pubkey: <1952 bytes>,                   │  │
│   │    kyber_pubkey: <800 bytes>,                        │  │
│   │    self_signature: <signed by bob's private key>,    │  │
│   │    timestamp: creation_time                           │  │
│   │  }                                                    │  │
│   └──────────────────────────────────────────────────────┘  │
│         │                                                     │
│         ▼                                                     │
│   ┌──────────────────────────────────────────────────────┐  │
│   │  Verify self-signature (TOFU on first use)            │  │
│   │  Cache locally for future use                         │  │
│   └──────────────────────────────────────────────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## KEY ENTRY FORMAT

### Public Key Bundle Structure

```c
typedef struct {
    char identity[256];                  // Username (e.g., "bob")
    uint8_t dilithium_pubkey[1952];      // Signing public key (Dilithium3)
    uint8_t kyber_pubkey[800];           // Encryption public key (Kyber512)
    uint64_t timestamp;                  // Key creation time (Unix timestamp)
    uint32_t version;                    // Key version (1, 2, 3... for rotation)
    char fingerprint[65];                // SHA256(dilithium_pubkey), hex string
    uint8_t self_signature[3309];        // Dilithium3 signature (self-signed)
} dht_pubkey_entry_t;
```

**Self-Signature:** Signs entire structure with identity's own Dilithium3 private key
- Proves ownership of identity
- Prevents impersonation attacks
- Enables TOFU (Trust On First Use) verification

---

## DHT STORAGE KEY

### Key Generation

**Purpose:** Map identity to DHT keyspace

**Formula:**
```c
storage_key = SHA256("pubkey:" + identity)
```

**Example:**
```c
identity = "bob"
key_input = "pubkey:bob"
storage_key = SHA256("pubkey:bob")
            = 0x7d9e3f2a... (32 bytes / 256 bits)
```

**Why prefix "pubkey:"?**
- Namespace separation (messages vs keys)
- Prevents collision with message storage keys
- Enables filtering (query all pubkeys)

---

## DHT OPERATIONS

### 1. PUBLISH (Store Public Key)

**Scenario:** Bob generates new key pair, publishes to DHT

**Process:**

```c
int dht_publish_pubkey(
    dht_context_t *ctx,
    const char *identity,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey  // For self-signing
);
```

**Steps:**

1. **Create key entry:**
   ```c
   dht_pubkey_entry_t entry = {
       .identity = "bob",
       .timestamp = time(NULL),
       .version = 1,
   };
   memcpy(entry.dilithium_pubkey, dilithium_pubkey, 1952);
   memcpy(entry.kyber_pubkey, kyber_pubkey, 800);
   ```

2. **Generate fingerprint:**
   ```c
   uint8_t fingerprint_hash[32];
   SHA256(dilithium_pubkey, 1952, fingerprint_hash);
   bytes_to_hex(fingerprint_hash, 32, entry.fingerprint);
   // Result: "9d4f7e2a..." (64-char hex string)
   ```

3. **Self-sign the entry:**
   ```c
   // Sign: identity + dilithium_pubkey + kyber_pubkey + timestamp + version
   uint8_t sign_input[4096];
   size_t offset = 0;
   memcpy(sign_input + offset, entry.identity, strlen(entry.identity));
   offset += strlen(entry.identity);
   memcpy(sign_input + offset, entry.dilithium_pubkey, 1952);
   offset += 1952;
   memcpy(sign_input + offset, entry.kyber_pubkey, 800);
   offset += 800;
   memcpy(sign_input + offset, &entry.timestamp, sizeof(entry.timestamp));
   offset += sizeof(entry.timestamp);
   memcpy(sign_input + offset, &entry.version, sizeof(entry.version));
   offset += sizeof(entry.version);

   size_t sig_len;
   dilithium_sign(entry.self_signature, &sig_len,
                  sign_input, offset, dilithium_privkey);
   ```

4. **Serialize entry:**
   ```c
   uint8_t *serialized;
   size_t serialized_len;
   serialize_pubkey_entry(&entry, &serialized, &serialized_len);
   ```

5. **Generate DHT storage key:**
   ```c
   char key_input[512];
   snprintf(key_input, sizeof(key_input), "pubkey:%s", identity);

   uint8_t storage_key[32];
   SHA256(key_input, strlen(key_input), storage_key);
   ```

6. **Store in DHT with replication k=5:**
   ```c
   dht_put(ctx, storage_key, 32, serialized, serialized_len, 5);
   ```

7. **Verify stored successfully:**
   ```c
   printf("✓ Published public key for '%s'\n", identity);
   printf("  Fingerprint: %s\n", entry.fingerprint);
   printf("  Replicated to k=5 DHT nodes\n");
   ```

---

### 2. LOOKUP (Retrieve Public Key)

**Scenario:** Alice wants to send message to Bob, needs Bob's public key

**Process:**

```c
int dht_lookup_pubkey(
    dht_context_t *ctx,
    const char *identity,
    uint8_t *dilithium_pubkey_out,  // 1952 bytes
    uint8_t *kyber_pubkey_out       // 800 bytes
);
```

**Steps:**

1. **Check local cache first:**
   ```c
   if (cache_get_pubkey(ctx->cache, identity,
                        dilithium_pubkey_out, kyber_pubkey_out) == 0) {
       return 0; // Cache hit, no DHT query needed
   }
   ```

2. **Generate DHT lookup key:**
   ```c
   char key_input[512];
   snprintf(key_input, sizeof(key_input), "pubkey:%s", identity);

   uint8_t lookup_key[32];
   SHA256(key_input, strlen(key_input), lookup_key);
   ```

3. **Query DHT:**
   ```c
   uint8_t *value;
   size_t value_len;
   int result = dht_get(ctx, lookup_key, 32, &value, &value_len);

   if (result != 0) {
       fprintf(stderr, "Error: Public key not found for '%s'\n", identity);
       return -1;
   }
   ```

4. **Deserialize entry:**
   ```c
   dht_pubkey_entry_t entry;
   deserialize_pubkey_entry(value, value_len, &entry);
   free(value);
   ```

5. **Verify self-signature:**
   ```c
   uint8_t sign_input[4096];
   size_t offset = 0;
   // (Same sign_input construction as publish step)
   ...

   if (dilithium_verify(entry.self_signature, sign_input, offset,
                        entry.dilithium_pubkey) != 0) {
       fprintf(stderr, "Error: Invalid self-signature for '%s'\n", identity);
       return -1;
   }
   ```

6. **TOFU (Trust On First Use) check:**
   ```c
   if (is_first_time_seeing_identity(ctx, identity)) {
       // First encounter with this identity
       printf("⚠ Trust On First Use (TOFU): '%s'\n", identity);
       printf("  Fingerprint: %s\n", entry.fingerprint);
       printf("  Do you trust this key? (y/n): ");

       char response;
       scanf(" %c", &response);

       if (response != 'y' && response != 'Y') {
           fprintf(stderr, "User rejected key for '%s'\n", identity);
           return -1;
       }

       // Mark as trusted
       cache_mark_trusted(ctx->cache, identity, entry.fingerprint);
   } else {
       // Subsequent encounter, verify fingerprint matches
       char cached_fingerprint[65];
       cache_get_fingerprint(ctx->cache, identity, cached_fingerprint);

       if (strcmp(cached_fingerprint, entry.fingerprint) != 0) {
           fprintf(stderr, "⚠ WARNING: Key changed for '%s'!\n", identity);
           fprintf(stderr, "  Cached:  %s\n", cached_fingerprint);
           fprintf(stderr, "  New:     %s\n", entry.fingerprint);
           fprintf(stderr, "  This could indicate a MitM attack!\n");
           return -1;
       }
   }
   ```

7. **Cache locally:**
   ```c
   cache_put_pubkey(ctx->cache, identity,
                    entry.dilithium_pubkey, entry.kyber_pubkey,
                    entry.fingerprint);
   ```

8. **Return public keys:**
   ```c
   memcpy(dilithium_pubkey_out, entry.dilithium_pubkey, 1952);
   memcpy(kyber_pubkey_out, entry.kyber_pubkey, 800);
   return 0;
   ```

---

### 3. UPDATE (Key Rotation)

**Scenario:** Bob rotates keys (old keys compromised or periodic rotation)

**Process:**

```c
int dht_update_pubkey(
    dht_context_t *ctx,
    const char *identity,
    const uint8_t *new_dilithium_pubkey,
    const uint8_t *new_kyber_pubkey,
    const uint8_t *old_dilithium_privkey  // Prove ownership of old key
);
```

**Steps:**

1. **Fetch existing key entry:**
   ```c
   dht_pubkey_entry_t old_entry;
   dht_lookup_pubkey_full(ctx, identity, &old_entry);
   ```

2. **Create new entry with incremented version:**
   ```c
   dht_pubkey_entry_t new_entry = {
       .identity = identity,
       .timestamp = time(NULL),
       .version = old_entry.version + 1,  // Increment version
   };
   memcpy(new_entry.dilithium_pubkey, new_dilithium_pubkey, 1952);
   memcpy(new_entry.kyber_pubkey, new_kyber_pubkey, 800);
   ```

3. **Sign with OLD private key (proves continuity):**
   ```c
   // Sign new entry with OLD key to prove you own the identity
   uint8_t transition_signature[3309];
   dilithium_sign(transition_signature, &sig_len,
                  &new_entry, sizeof(new_entry), old_dilithium_privkey);
   ```

4. **Self-sign with NEW private key:**
   ```c
   dilithium_sign(new_entry.self_signature, &sig_len,
                  &new_entry, sizeof(new_entry), new_dilithium_privkey);
   ```

5. **Store updated entry in DHT:**
   ```c
   dht_publish_pubkey_with_transition(ctx, &new_entry, transition_signature);
   ```

6. **Notify contacts (optional):**
   ```c
   // Send key rotation notification to all contacts
   send_key_rotation_notice(ctx, identity, old_entry.fingerprint,
                            new_entry.fingerprint);
   ```

**Result:** Seamless key rotation with cryptographic proof of ownership

---

## TRUST MODEL

### TOFU (Trust On First Use)

**Concept:** Similar to SSH key verification

**First Encounter:**
```
User: alice sends message to bob
System: Fetching bob's public key from DHT...
        Fingerprint: 9d4f7e2a...

⚠ Trust On First Use (TOFU):
  This is the first time you've communicated with 'bob'.
  Please verify the fingerprint out-of-band (Signal, phone call, etc.)

  Fingerprint: 9d4f7e2a3c1b5d7f...

Do you trust this key? (y/n): y

✓ Key for 'bob' marked as trusted
```

**Subsequent Encounters:**
```
System: bob's public key verified (matches cached fingerprint)
        ✓ Trusted
```

### Key Change Detection

**If fingerprint changes:**
```
⚠ WARNING: Key changed for 'bob'!

  Previous fingerprint: 9d4f7e2a3c1b5d7f...
  New fingerprint:      7a1f8c3e2b9d4f6a...

  This could indicate:
  - Key rotation (normal)
  - Man-in-the-Middle attack (DANGER!)

  Please verify the new fingerprint with bob out-of-band.

Accept new key? (y/n):
```

**User must manually approve** key changes (security vs usability tradeoff)

---

## SECURITY ENHANCEMENTS

### 1. Web of Trust (Future)

**Concept:** Friends vouch for each other's keys

```c
typedef struct {
    char identity[256];
    char voucher[256];               // Who vouched for this key
    uint8_t vouch_signature[3309];   // Voucher's signature
    uint64_t vouch_timestamp;
} pubkey_vouch_t;
```

**Example:**
```
alice trusts carol (verified in person)
carol vouches for bob's key
alice accepts bob's key based on carol's vouch
```

**Storage:** Store vouches in DHT alongside public keys

---

### 2. Blockchain Anchoring (Future)

**Concept:** Publish key fingerprints to Cellframe cpunk blockchain

**Benefits:**
- Immutable record (tamper-proof)
- Timestamped (proves key existed at time T)
- Publicly auditable

**Implementation:**
```c
// Publish to blockchain when registering key
int blockchain_anchor_pubkey(
    const char *identity,
    const char *fingerprint
) {
    // Create blockchain transaction:
    // identity → fingerprint mapping
    cellframe_publish_data("dna-keyserver", identity, fingerprint);

    // Store transaction ID in DHT entry
    return 0;
}
```

**Verification:**
```c
// Verify fingerprint matches blockchain record
int blockchain_verify_pubkey(
    const char *identity,
    const char *fingerprint
) {
    char *blockchain_fingerprint = cellframe_query_data("dna-keyserver", identity);

    if (strcmp(fingerprint, blockchain_fingerprint) != 0) {
        fprintf(stderr, "Fingerprint mismatch with blockchain!\n");
        return -1;
    }

    return 0; // Verified
}
```

**Tradeoff:** Blockchain writes are slower/costlier, but provide highest security

---

### 3. Keybase-Style Proofs (Future)

**Concept:** Link identity to other online accounts

**Example Proof:**
```
bob (DNA Messenger)
├── Twitter: @bobsmith (verified tweet)
├── GitHub: bobsmith (verified gist)
└── Website: bobsmith.com (verified DNS TXT record)
```

**Storage:** Store proofs in DHT entry

**Verification:** Automatic cross-platform verification increases trust

---

## CACHING STRATEGY

### Local Key Cache (SQLite)

**Purpose:**
- Reduce DHT queries (performance)
- Offline key verification
- Key history tracking

**Schema:**
```sql
CREATE TABLE pubkey_cache (
    identity TEXT PRIMARY KEY,
    dilithium_pubkey BLOB NOT NULL,  -- 1952 bytes
    kyber_pubkey BLOB NOT NULL,      -- 800 bytes
    fingerprint TEXT NOT NULL,       -- SHA256(dilithium_pubkey)
    version INTEGER DEFAULT 1,
    trusted BOOLEAN DEFAULT 0,       -- TOFU approved
    first_seen INTEGER NOT NULL,     -- Unix timestamp
    last_verified INTEGER NOT NULL,  -- Last DHT verification
    blockchain_anchored BOOLEAN DEFAULT 0
);

CREATE TABLE pubkey_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    version INTEGER NOT NULL,
    change_timestamp INTEGER NOT NULL,
    change_type TEXT NOT NULL  -- 'initial', 'rotation', 'suspicious'
);
```

**Cache Policy:**
- **Cache hit:** Use cached key (no DHT query)
- **Cache miss:** Query DHT, verify, cache
- **Refresh:** Re-verify from DHT every 24 hours (detect key rotations)

---

## API DESIGN

```c
// DHT Keyserver Context
typedef struct dht_keyserver_context_t dht_keyserver_context_t;

// Initialize DHT keyserver
dht_keyserver_context_t* dht_keyserver_init(
    dht_context_t *dht_ctx,
    sqlite3 *cache_db
);

// Publish public key
int dht_keyserver_publish(
    dht_keyserver_context_t *ctx,
    const char *identity,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey  // For self-signing
);

// Lookup public key
int dht_keyserver_lookup(
    dht_keyserver_context_t *ctx,
    const char *identity,
    uint8_t *dilithium_pubkey_out,
    uint8_t *kyber_pubkey_out
);

// Update public key (key rotation)
int dht_keyserver_update(
    dht_keyserver_context_t *ctx,
    const char *identity,
    const uint8_t *new_dilithium_pubkey,
    const uint8_t *new_kyber_pubkey,
    const uint8_t *old_dilithium_privkey  // Prove ownership
);

// Verify fingerprint (manual TOFU)
int dht_keyserver_verify_fingerprint(
    dht_keyserver_context_t *ctx,
    const char *identity,
    const char *expected_fingerprint
);

// Mark key as trusted (TOFU approved)
int dht_keyserver_mark_trusted(
    dht_keyserver_context_t *ctx,
    const char *identity
);

// Get key fingerprint
int dht_keyserver_get_fingerprint(
    dht_keyserver_context_t *ctx,
    const char *identity,
    char *fingerprint_out  // 65 bytes (64 hex + null)
);

// List all cached keys
int dht_keyserver_list_cached(
    dht_keyserver_context_t *ctx,
    char ***identities_out,
    size_t *count_out
);

// Cleanup
void dht_keyserver_free(dht_keyserver_context_t *ctx);
```

---

## MIGRATION FROM HTTP KEYSERVER

### Transition Plan

**Phase 1: Dual Mode (HTTP + DHT)**
```c
// Try DHT first, fallback to HTTP
int lookup_pubkey_hybrid(const char *identity, ...) {
    if (dht_keyserver_lookup(ctx, identity, ...) == 0) {
        return 0; // DHT success
    }

    // Fallback to HTTP keyserver
    return http_keyserver_lookup(identity, ...);
}
```

**Phase 2: DHT Primary, HTTP Backup**
```c
// Log warning when using HTTP fallback
if (http_fallback_used) {
    fprintf(stderr, "Warning: Using legacy HTTP keyserver\n");
}
```

**Phase 3: DHT Only**
```c
// Remove HTTP keyserver code entirely
```

### Data Migration

**Export from PostgreSQL:**
```sql
SELECT identity, dilithium_pubkey, kyber_pubkey
FROM keyserver;
```

**Import to DHT:**
```c
// For each identity:
dht_keyserver_publish(ctx, identity, dilithium_pubkey, kyber_pubkey, privkey);
```

**Timeline:** 1-2 months of dual mode before deprecating HTTP keyserver

---

## IMPLEMENTATION FILES

```c
dht_keyserver.h          // Public API
dht_keyserver.c          // Core implementation
dht_keyserver_cache.c    // Local SQLite cache
dht_keyserver_tofu.c     // TOFU verification logic
```

---

## TESTING PLAN

### Unit Tests
- Key serialization/deserialization
- Self-signature generation/verification
- Fingerprint calculation
- TOFU logic

### Integration Tests
- Publish and lookup key
- Key rotation
- Key change detection
- Cache hit/miss

### Security Tests
- Invalid self-signature rejection
- Man-in-the-middle detection
- Key impersonation attempts

---

## COMPARISON WITH EXISTING SYSTEMS

| System | Key Distribution | Trust Model | Decentralized |
|--------|------------------|-------------|---------------|
| **Signal** | Central server | TOFU + Safety Numbers | No |
| **PGP** | Keyservers | Web of Trust | Partial |
| **SSH** | Manual exchange | TOFU | N/A |
| **Keybase** | Central server | Proofs + Social | No |
| **DNA (v2.0)** | DHT (replicated) | TOFU + Blockchain | Yes |

**Advantages:**
- No central server (censorship-resistant)
- Automatic key distribution (no manual exchange)
- Self-signed (no CA required)

**Disadvantages:**
- TOFU requires out-of-band verification (same as SSH)
- Key rotation more complex (multi-step process)

---

## FUTURE ENHANCEMENTS

1. **Automatic key rotation** - Every 90 days
2. **Web of Trust integration** - Friend vouches
3. **Keybase-style proofs** - Social account linking
4. **Blockchain anchoring** - Cellframe cpunk integration
5. **Quantum-safe upgrades** - NIST PQC final standards

---

**Document Version:** 1.0
**Last Updated:** 2025-10-16
**Status:** Research & Planning Phase
