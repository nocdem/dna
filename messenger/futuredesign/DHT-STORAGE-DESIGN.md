# DHT Distributed Storage Design

**Component:** Distributed Message Storage
**Status:** Research & Planning Phase
**Dependencies:** P2P Transport Layer (DHT for routing)

---

## OVERVIEW

The DHT storage layer provides decentralized, replicated storage for encrypted messages. When a recipient is offline, messages are stored across multiple DHT nodes and retrieved when the recipient comes online.

**Key Properties:**
- **Zero-knowledge storage** - Nodes store encrypted blobs they cannot decrypt
- **Replication** - k=5 copies across different nodes (fault tolerance)
- **Auto-expiry** - Messages deleted after 30 days (configurable)
- **Content-addressed** - Messages identified by cryptographic hash
- **No central database** - Fully distributed across P2P network

---

## ARCHITECTURE

```
┌──────────────────────────────────────────────────────────────┐
│                    DHT Storage Network                        │
│                                                                │
│   Sender (alice)                      Recipient (bob)         │
│        │                                    ▲                  │
│        │ Store message                     │ Retrieve         │
│        ▼                                    │                  │
│   ┌────────────────────────────────────────────┐              │
│   │          Kademlia DHT (160-bit space)      │              │
│   │                                             │              │
│   │   Key: SHA256("bob:msg:" + timestamp)     │              │
│   │   Value: <encrypted_message_blob>          │              │
│   └────────────────────────────────────────────┘              │
│         │          │          │          │                     │
│         ▼          ▼          ▼          ▼                     │
│   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐     │
│   │Node C  │ │Node D  │ │Node E  │ │Node F  │ │Node G  │     │
│   │(copy 1)│ │(copy 2)│ │(copy 3)│ │(copy 4)│ │(copy 5)│     │
│   └────────┘ └────────┘ └────────┘ └────────┘ └────────┘     │
│                                                                │
│   Replication factor k=5: Message survives 4/5 nodes offline  │
└──────────────────────────────────────────────────────────────┘
```

---

## STORAGE MODEL

### Message Storage Entry

```c
typedef struct {
    uint8_t key[32];              // SHA256 hash (storage key)
    char sender[256];             // Sender identity
    char recipient[256];          // Recipient identity
    uint64_t timestamp;           // Unix timestamp (creation time)
    uint64_t expiry;              // Unix timestamp (auto-delete after)
    size_t ciphertext_len;        // Encrypted message size
    uint8_t *ciphertext;          // Encrypted DNA message blob
    uint8_t signature[3309];      // Dilithium3 signature (sender proves authorship)
} dht_message_t;
```

### Storage Key Generation

**Purpose:** Generate unique, content-addressed key for DHT storage

**Formula:**
```c
storage_key = SHA256(recipient + ":" + timestamp + ":" + nonce)
```

**Example:**
```c
recipient = "bob"
timestamp = 1697465432 (Unix time)
nonce = random_bytes(16) // Prevent collision

storage_key = SHA256("bob:msg:1697465432:7a3f2c1b...")
            = 0x9d4f7e2a... (32 bytes / 256 bits)
```

**Why this format:**
- **Recipient prefix** - Enables efficient queries ("All messages for bob")
- **Timestamp** - Natural ordering, enables time-based queries
- **Nonce** - Prevents collisions, adds entropy

### Value Serialization

**Format:** Binary-encoded message structure

```
┌──────────────────────────────────────────────────────────┐
│                   DHT Storage Value                       │
├──────────────────────────────────────────────────────────┤
│  Header (32 bytes)                                        │
│  ├─ Magic (4 bytes): 0x444E4153 ("DNAS")                │
│  ├─ Version (2 bytes): 0x0100                            │
│  ├─ Sender Length (2 bytes): strlen(sender)              │
│  ├─ Recipient Length (2 bytes): strlen(recipient)        │
│  ├─ Timestamp (8 bytes): Unix time                       │
│  ├─ Expiry (8 bytes): Unix time                          │
│  └─ Ciphertext Length (4 bytes): Size of payload         │
├──────────────────────────────────────────────────────────┤
│  Sender Identity (variable, 1-256 bytes)                  │
├──────────────────────────────────────────────────────────┤
│  Recipient Identity (variable, 1-256 bytes)               │
├──────────────────────────────────────────────────────────┤
│  Ciphertext (variable, encrypted DNA message blob)        │
├──────────────────────────────────────────────────────────┤
│  Signature (3309 bytes, Dilithium3)                       │
│  - Signs: sender + recipient + timestamp + ciphertext     │
└──────────────────────────────────────────────────────────┘
```

---

## DHT OPERATIONS

### 1. STORE (Send Message to Offline Recipient)

**Scenario:** Alice sends message to Bob, but Bob is offline

**Process:**

```c
int dht_store_message(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint32_t ttl_days
);
```

**Steps:**

1. **Generate storage key:**
   ```c
   uint8_t nonce[16];
   qgp_randombytes(nonce, 16);
   uint64_t timestamp = time(NULL);

   char key_input[512];
   snprintf(key_input, sizeof(key_input), "%s:msg:%lu:%s",
            recipient, timestamp, hex(nonce, 16));

   uint8_t storage_key[32];
   SHA256(key_input, strlen(key_input), storage_key);
   ```

2. **Create message entry:**
   ```c
   dht_message_t msg = {
       .sender = "alice",
       .recipient = "bob",
       .timestamp = time(NULL),
       .expiry = time(NULL) + (ttl_days * 86400),
       .ciphertext = ciphertext,
       .ciphertext_len = ciphertext_len
   };
   ```

3. **Sign message:**
   ```c
   // Load sender's Dilithium3 private key
   uint8_t dilithium_sk[4032];
   load_private_key("alice", dilithium_sk);

   // Sign: sender + recipient + timestamp + ciphertext
   dilithium_sign(msg.signature, &sig_len,
                  &msg, sizeof(msg), dilithium_sk);
   ```

4. **Serialize value:**
   ```c
   uint8_t *value;
   size_t value_len;
   serialize_dht_message(&msg, &value, &value_len);
   ```

5. **Store in DHT with replication k=5:**
   ```c
   dht_put(ctx, storage_key, 32, value, value_len, 5); // k=5 replicas
   ```

6. **DHT routes to k=5 successor nodes:**
   - Node responsible for storage_key
   - k-1 successor nodes in Kademlia ring

**Result:** Message replicated on 5 different DHT nodes

---

### 2. RETRIEVE (Fetch Messages for Online Recipient)

**Scenario:** Bob comes online, wants to fetch pending messages

**Process:**

```c
int dht_retrieve_messages(
    dht_context_t *ctx,
    const char *recipient,
    dht_message_t **messages_out,
    size_t *count_out
);
```

**Steps:**

1. **Query DHT for all keys matching recipient:**
   ```c
   // Find all keys starting with "bob:msg:"
   char query_prefix[256];
   snprintf(query_prefix, sizeof(query_prefix), "%s:msg:", recipient);

   uint8_t **keys;
   size_t key_count;
   dht_find_keys_by_prefix(ctx, query_prefix, &keys, &key_count);
   ```

2. **Retrieve each message:**
   ```c
   dht_message_t *messages = calloc(key_count, sizeof(dht_message_t));

   for (size_t i = 0; i < key_count; i++) {
       uint8_t *value;
       size_t value_len;
       dht_get(ctx, keys[i], 32, &value, &value_len);

       deserialize_dht_message(value, value_len, &messages[i]);
   }
   ```

3. **Verify signatures:**
   ```c
   for (size_t i = 0; i < key_count; i++) {
       // Load sender's public key from DHT keyserver
       uint8_t sender_pubkey[1952];
       dht_get_pubkey(ctx, messages[i].sender, sender_pubkey);

       // Verify Dilithium3 signature
       if (dilithium_verify(messages[i].signature, &messages[i],
                            sizeof(messages[i]), sender_pubkey) != 0) {
           fprintf(stderr, "Invalid signature from %s\n", messages[i].sender);
           continue; // Skip invalid message
       }
   }
   ```

4. **Sort by timestamp:**
   ```c
   qsort(messages, key_count, sizeof(dht_message_t), compare_timestamp);
   ```

5. **Return messages:**
   ```c
   *messages_out = messages;
   *count_out = key_count;
   ```

**Result:** Bob receives all pending messages in chronological order

---

### 3. DELETE (Clean Up After Reading)

**Scenario:** Bob read message, delete from DHT to save space

**Process:**

```c
int dht_delete_message(
    dht_context_t *ctx,
    const uint8_t *storage_key
);
```

**Steps:**

1. **Send DELETE request to DHT:**
   ```c
   dht_delete(ctx, storage_key, 32);
   ```

2. **DHT removes from all k=5 replicas:**
   - Primary node deletes
   - Replication nodes notified to delete

3. **Verify deletion:**
   ```c
   // Optional: Query to confirm gone
   uint8_t *value;
   size_t value_len;
   int result = dht_get(ctx, storage_key, 32, &value, &value_len);
   assert(result == DHT_NOT_FOUND);
   ```

**Who can delete:**
- **Recipient** (bob) - After reading message
- **Sender** (alice) - Before recipient reads (optional)
- **DHT auto-expiry** - After TTL expires (30 days)

---

## REPLICATION STRATEGY

### DHash-Style Replication (Chord/Kademlia)

**Concept:** Store on k successive nodes in DHT ring

**Kademlia Ring:**
```
Node IDs (sorted):
0x0123... → 0x1a2b... → 0x3f7c... → 0x7d9e... → 0xabcd... → 0xef12...
   ↑           ↑           ↑           ↑           ↑           ↑
 Node A      Node B      Node C      Node D      Node E      Node F
```

**Storage Key:** `0x3f9a...` (falls between Node C and Node D)

**Replication (k=5):**
1. **Primary:** Node D (first successor of key)
2. **Replica 1:** Node E (next successor)
3. **Replica 2:** Node F (next successor)
4. **Replica 3:** Node A (wraps around ring)
5. **Replica 4:** Node B (next successor)

**Fault Tolerance:**
- Message survives if ANY of the 5 nodes remain online
- If Node D goes offline, Node E promotes to primary
- Remaining nodes re-replicate to maintain k=5

### Replication Management

**On Node Join:**
```c
// New node joins DHT
void on_node_join(dht_context_t *ctx, uint8_t *new_node_id) {
    // Transfer keys that now belong to new node
    dht_transfer_keys(ctx, new_node_id);
}
```

**On Node Leave:**
```c
// Node gracefully leaves
void on_node_leave(dht_context_t *ctx, uint8_t *leaving_node_id) {
    // Successor nodes re-replicate to maintain k=5
    dht_re_replicate(ctx, leaving_node_id);
}
```

**On Node Failure (No Goodbye):**
```c
// Periodic health check detects dead node
void on_node_failure_detected(dht_context_t *ctx, uint8_t *failed_node_id) {
    // Surviving replicas re-replicate
    dht_re_replicate(ctx, failed_node_id);
}
```

---

## MESSAGE EXPIRY & GARBAGE COLLECTION

### Auto-Expiry

**Default TTL:** 30 days

**Rationale:**
- Messages should be temporary (offline queue, not archive)
- Prevent DHT storage exhaustion
- Privacy: Old messages auto-delete

**Implementation:**

```c
// Each DHT node runs periodic cleanup (every 1 hour)
void dht_garbage_collect(dht_context_t *ctx) {
    uint64_t now = time(NULL);

    // Iterate all stored messages
    for (size_t i = 0; i < ctx->message_count; i++) {
        if (ctx->messages[i].expiry < now) {
            // Message expired, delete
            dht_delete_local(ctx, ctx->messages[i].key);
            printf("Deleted expired message: %s\n", hex(ctx->messages[i].key, 32));
        }
    }
}
```

**User-Configurable:**
```c
// Store with custom TTL
dht_store_message(ctx, "alice", "bob", ciphertext, len, 7); // 7 days
```

### Manual Deletion

**Recipient deletes after reading:**
```c
// Bob reads message
dht_message_t *messages;
size_t count;
dht_retrieve_messages(ctx, "bob", &messages, &count);

for (size_t i = 0; i < count; i++) {
    // Decrypt and display
    dna_decrypt_message_raw(...);

    // Delete from DHT
    dht_delete_message(ctx, messages[i].key);
}
```

**Sender revokes unread message:**
```c
// Alice deletes message she sent (before Bob reads it)
dht_delete_message(ctx, storage_key);
```

---

## STORAGE CAPACITY PLANNING

### Per-Message Storage Cost

**Typical message:**
- Sender identity: 20 bytes
- Recipient identity: 20 bytes
- Timestamp: 8 bytes
- Expiry: 8 bytes
- Ciphertext: 6,000 bytes (average DNA encrypted message)
- Signature: 3,309 bytes
- **Total: ~9.4 KB per message**

### Network-Wide Storage

**Assumptions:**
- 10,000 active users
- Average 100 messages/day/user
- Replication factor k=5
- 30-day retention

**Calculation:**
```
Messages per day: 10,000 users × 100 msg = 1,000,000 messages/day
Messages in 30 days: 1,000,000 × 30 = 30,000,000 messages
Storage per message (replicated): 9.4 KB × 5 = 47 KB
Total network storage: 30M × 47 KB = 1.41 TB

Distributed across nodes:
- 1,000 nodes → 1.41 GB per node
- 10,000 nodes → 141 MB per node
```

**Conclusion:** Storage requirements are reasonable for distributed network

### Storage Limits Per Node

**Recommended:**
- Default: 10 GB storage allocation per node
- User-configurable: 1 GB - 100 GB

**Eviction Policy (if node reaches limit):**
1. Delete expired messages first
2. Delete oldest messages next (FIFO)
3. Notify network to re-replicate on other nodes

---

## SECURITY & PRIVACY

### Zero-Knowledge Storage

**DHT nodes can see:**
- Storage key (SHA256 hash)
- Sender identity ("alice")
- Recipient identity ("bob")
- Message size (~9 KB)
- Timestamp

**DHT nodes CANNOT see:**
- Plaintext message content (encrypted end-to-end)
- Message metadata (encrypted inside ciphertext)
- Conversation patterns (if using local cache, see SYNC-PROTOCOL-DESIGN.md)

### Threat Model

**Protected Against:**
- **Malicious storage node reading messages** - End-to-end encryption
- **Node tampering with messages** - Dilithium3 signatures prevent forgery
- **Node deleting messages** - k=5 replication provides redundancy
- **Network eavesdropper** - Messages encrypted (TLS for DHT protocol)

**NOT Protected Against:**
- **Traffic analysis** - Observer sees alice↔bob communication (metadata)
  - **Mitigation:** Tor integration (future)
- **Malicious node refusing to store** - k=5 replication mitigates (4/5 success sufficient)
- **Sybil attack** - Attacker controls many nodes, targets specific recipient
  - **Mitigation:** Reputation system, proof-of-work (future)

### Signature Verification

**Why sign stored messages:**
- Prevents impersonation attacks (attacker claiming to be alice)
- Recipient verifies message authenticity before decrypting
- Storage nodes can verify signature (prevents spam/DoS)

**Verification at storage time:**
```c
int dht_store_message(...) {
    // 1. Load sender's public key from DHT keyserver
    uint8_t sender_pubkey[1952];
    if (dht_get_pubkey(ctx, sender, sender_pubkey) != 0) {
        return DHT_ERROR_SENDER_NOT_FOUND;
    }

    // 2. Verify Dilithium3 signature
    if (dilithium_verify(signature, &msg, sizeof(msg), sender_pubkey) != 0) {
        return DHT_ERROR_INVALID_SIGNATURE;
    }

    // 3. Store if valid
    return dht_put(ctx, key, 32, value, value_len, 5);
}
```

---

## TECHNOLOGY OPTIONS

### DHT Implementation

| Library | Language | Storage API | Replication | Used By |
|---------|----------|-------------|-------------|---------|
| **OpenDHT** | C++ | Yes (put/get) | Yes (k replicas) | Jami messenger |
| **libp2p Kad-DHT** | C++ | Yes (content routing) | Yes | IPFS, Filecoin |
| **BitTorrent DHT** | C | Limited (mutable data) | Yes | BitTorrent |
| **Custom** | C | Full control | Manual | - |

**Recommendation:** OpenDHT (designed for messaging, proven in production)

### OpenDHT Features (Perfect for DNA Messenger)

**Encrypted values:**
```c
// OpenDHT supports encrypted storage natively
dht.putEncrypted(key, value, recipient_pubkey);
```

**Signed values:**
```c
// OpenDHT verifies signatures automatically
dht.putSigned(key, value, sender_privkey);
```

**Listening for new values:**
```c
// Bob can subscribe to new messages
dht.listen(key, [](shared_ptr<Value> value) {
    // New message arrived!
});
```

**Perfect fit** for DNA Messenger requirements

---

## API DESIGN

```c
// DHT Storage Context
typedef struct dht_storage_context_t dht_storage_context_t;

// Initialize DHT storage
dht_storage_context_t* dht_storage_init(dht_context_t *dht_ctx);

// Store message (offline recipient)
int dht_storage_put_message(
    dht_storage_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint32_t ttl_days,
    uint8_t *storage_key_out  // Output: Storage key for deletion
);

// Retrieve all messages for recipient
int dht_storage_get_messages(
    dht_storage_context_t *ctx,
    const char *recipient,
    dht_message_t **messages_out,
    size_t *count_out
);

// Delete message (after reading or revoke)
int dht_storage_delete_message(
    dht_storage_context_t *ctx,
    const uint8_t *storage_key
);

// Garbage collection (periodic cleanup)
int dht_storage_garbage_collect(dht_storage_context_t *ctx);

// Statistics
typedef struct {
    size_t messages_stored;
    size_t total_bytes;
    size_t expired_messages;
} dht_storage_stats_t;

int dht_storage_get_stats(dht_storage_context_t *ctx,
                          dht_storage_stats_t *stats_out);

// Cleanup
void dht_storage_free(dht_storage_context_t *ctx);
```

---

## IMPLEMENTATION FILES

```c
dht_storage.h           // Public API
dht_storage.c           // Core implementation
dht_replication.c       // Replication management
dht_expiry.c            // Garbage collection
```

---

## TESTING PLAN

### Unit Tests
- Message serialization/deserialization
- Storage key generation
- Signature verification
- Expiry calculation

### Integration Tests
- Store and retrieve message
- Replication (k=5 nodes)
- Node failure recovery
- Expiry and garbage collection
- Large message support (>1 MB)

### Stress Tests
- 10,000 messages stored
- Node churn (nodes joining/leaving rapidly)
- Network partition recovery

---

## FUTURE ENHANCEMENTS

1. **Erasure coding** - Store k/n fragments (more efficient than full replication)
2. **Bloom filters** - Fast "any messages for me?" query
3. **Message prioritization** - Important messages replicated more (k=10)
4. **Incentive system** - CF20 tokens for storage nodes (Phase 8+)
5. **Archive nodes** - Long-term storage (>30 days) for premium users

---

**Document Version:** 1.0
**Last Updated:** 2025-10-16
**Status:** Research & Planning Phase
