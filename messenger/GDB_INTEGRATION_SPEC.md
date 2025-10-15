# DNA Messenger - Cellframe GDB Integration Specification

**Version:** 1.0
**Date:** 2025-10-15
**Status:** Proposed Implementation
**Author:** DNA Messenger Development Team

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [GDB Key Structure](#gdb-key-structure)
3. [Encryption Scheme](#encryption-scheme)
4. [Message Send Flow](#message-send-flow)
5. [Message Receive Flow](#message-receive-flow)
6. [Push Notification System](#push-notification-system)
7. [Device Management](#device-management)
8. [Security Analysis](#security-analysis)
9. [Implementation Plan](#implementation-plan)
10. [Migration from PostgreSQL](#migration-from-postgresql)
11. [Testing & Validation](#testing-validation)

---

## Executive Summary

### Overview

DNA Messenger will integrate with Cellframe's Global Database (GDB) to provide:
- **Distributed keyserver** - Public keys replicated across Cellframe network
- **Decentralized message storage** - Messages stored in GDB instead of centralized PostgreSQL
- **Push notifications** - Real-time message delivery via GDB watches
- **Multi-device support** - Device registration and synchronization
- **Privacy-preserving metadata** - Encrypted metadata to prevent traffic analysis

### Key Design Decisions

1. **No Protocol Changes** - Current encryption protocol (v0.05) remains unchanged
2. **Application-Layer Metadata Encryption** - Metadata encrypted with same DEK as message content
3. **Reuse Existing Kyber KEM** - No new cryptographic primitives needed
4. **Dual Storage Model** - Separate GDB groups for message content and encrypted metadata
5. **Backward Compatible** - Existing encrypted messages work unchanged

### Architecture

```
Current (PostgreSQL):
  Client → PostgreSQL → [keyserver, messages] tables

Proposed (GDB):
  Client → GDB → [dna.keys.*, dna.inbox.*, dna.meta.*, dna.notify.*] groups
```

---

## GDB Key Structure

### Group Naming Convention

```
dna.<category>[.<scope>]/<key>

Where:
  category = keys | inbox | meta | notify | unread | devices | receipt | presence | typing
  scope    = identity (for per-user namespacing)
  key      = unique identifier within group
```

### Complete Key Structure

#### 1. Public Keys (Distributed Keyserver)

**Signing Keys:**
```
Group: dna.keys.signing
Key:   <identity>
Value: <base64_dilithium3_pubkey>

Example:
  dna.keys.signing/alice = "YWxpY2Utc2lnbmluZy1wdWJrZXk..."

Size: ~2600 bytes (1952 bytes Dilithium3 pubkey + base64 overhead)
```

**Encryption Keys:**
```
Group: dna.keys.encryption
Key:   <identity>
Value: <base64_kyber512_pubkey>

Example:
  dna.keys.encryption/alice = "YWxpY2UtZW5jcnlwdGlvbi1wdWJrZXk..."

Size: ~1067 bytes (800 bytes Kyber512 pubkey + base64 overhead)
```

**Key Metadata:**
```
Group: dna.keys.metadata
Key:   <identity>
Value: <created_timestamp>|<key_version>

Example:
  dna.keys.metadata/alice = "1728950400|1"

Size: ~20 bytes
```

---

#### 2. Message Storage (Encrypted Blobs)

**Message Content:**
```
Group: dna.inbox.<recipient>
Key:   <message_id>
Value: <base64_encrypted_message>

Message ID Format: msg_<unix_timestamp>_<random_hex_8>
Example: msg_1728950400_a3f2b8c1

Example:
  dna.inbox.alice/msg_1728950400_a3f2b8c1 = "UFBTSUdFTkMF..."

Content Format (encrypted):
  [header(20) | recipient_entries(808×N) | nonce(12) | ciphertext | tag(16) | signature]

Size: Variable
  - Header: 20 bytes
  - Per recipient: 808 bytes
  - Nonce: 12 bytes
  - Ciphertext: message length (no padding)
  - Tag: 16 bytes
  - Signature: ~3366 bytes (Dilithium3)

  Example for single recipient, 256-byte message:
    20 + 808 + 12 + 256 + 16 + 3366 = 4,478 bytes
    Base64: ~5,971 bytes
```

---

#### 3. Encrypted Metadata (Per-Recipient)

**Message Metadata:**
```
Group: dna.meta.<recipient>
Key:   <message_id>
Value: <base64_encrypted_metadata>

Encrypted Metadata Format:
  [nonce(12) | encrypted_metadata | tag(16)]

Plaintext Metadata Format (before encryption):
  <sender>|<timestamp>|<type>|<size>|<reply_to>|<ttl>|<flags>

Fields:
  - sender: Identity string (e.g., "bob")
  - timestamp: Unix timestamp (e.g., "1728950400")
  - type: text|image|file|voice|video|location|contact|sticker
  - size: Ciphertext size in bytes (e.g., "4478")
  - reply_to: Message ID being replied to, or "none"
  - ttl: Time-to-live in seconds (0 = permanent)
  - flags: Comma-separated flags (encrypted,urgent,forwarded,edited,deleted)

Example:
  dna.meta.alice/msg_1728950400_a3f2b8c1 = "cmFuZG9tX25vbmNl..."

  Decrypts to: "bob|1728950400|text|4478|none|0|encrypted"

Size: ~100-200 bytes (base64)
  - Nonce: 12 bytes
  - Encrypted metadata: ~50-120 bytes (depends on field lengths)
  - Tag: 16 bytes
  - Base64 overhead: ~33%
```

**Encryption:**
```
DEK (Data Encryption Key) = same 32-byte key used for message content
Nonce = 12 random bytes (generated per metadata encryption)
Algorithm = AES-256-GCM

Encryption:
  encrypted_metadata = AES-256-GCM(DEK, metadata_plaintext, nonce)

Output:
  [nonce | encrypted_metadata | tag]
```

---

#### 4. Push Notifications (Ephemeral Queue)

**Notification Queue:**
```
Group: dna.notify.<recipient>
Key:   <timestamp>_<random_hex_8>
Value: <base64_encrypted_notification>

Encrypted Notification Format:
  [nonce(12) | encrypted_notification | tag(16)]

Plaintext Notification Format (before encryption):
  <sender>|<message_id>|<type>

Example:
  dna.notify.alice/1728950400_xyz789ab = "bm90aWZfbm9uY2U..."

  Decrypts to: "bob|msg_1728950400_a3f2b8c1|text"

Size: ~80 bytes (base64)

Encryption:
  Same DEK as message/metadata
  New random nonce per notification
```

**Client Workflow:**
```
1. Watch dna.notify.<identity> for new keys
2. Fetch new notification keys
3. Decrypt notification (fast - just 50 bytes)
4. Display: "Bob sent you a message"
5. When user opens app:
   - Fetch encrypted metadata from dna.meta.<identity>/<msg_id>
   - Decrypt metadata (fast - just 100 bytes)
   - Display conversation UI with sender/timestamp
6. When user opens conversation:
   - Fetch full encrypted message from dna.inbox.<identity>/<msg_id>
   - Decrypt message (slower - full message size)
7. Delete notification key (cleanup)
```

---

#### 5. Unread Counters (Badge Counts)

**Unread Count:**
```
Group: dna.unread
Key:   <recipient>
Value: <count>

Example:
  dna.unread/alice = "5"

Size: 1-4 bytes

Operations:
  - Increment when message received
  - Decrement when message read
  - Reset to 0 when conversation opened
```

**Note:** This leaks message count metadata, but is necessary for badge functionality.

---

#### 6. Device Registration (Multi-Device Support)

**Device Info:**
```
Group: dna.devices.<identity>
Key:   <device_id>
Value: <base64_encrypted_device_info>

Device ID Format: <platform>_<random_hex_16>
Example: android_a3f2b8c1d4e5f6a7

Encrypted Device Info Format:
  [nonce(12) | encrypted_device_info | tag(16)]

Plaintext Device Info (before encryption):
  <device_type>|<push_token>|<registered_ts>|<last_seen_ts>

Device Types: android|ios|desktop|web

Example:
  dna.devices.alice/android_a3f2b8c1d4e5f6a7 = "ZGV2aWNlX25vbmNl..."

  Decrypts to: "android|fcm_token_xyz...|1728950000|1728951000"

Size: ~150-250 bytes (base64)

Encryption:
  Use device-specific key derived from user's master key
```

---

#### 7. Delivery & Read Receipts (Optional)

**Receipt Info:**
```
Group: dna.receipt.<message_id>
Key:   <recipient>
Value: <base64_encrypted_receipt>

Encrypted Receipt Format:
  [nonce(12) | encrypted_receipt | tag(16)]

Plaintext Receipt Format:
  <delivered_ts>|<read_ts>|<device_id>

Example:
  dna.receipt.msg_1728950400_a3f2b8c1/alice = "cmVjZWlwdF9ub25jZQ..."

  Decrypts to: "1728950401|1728950450|android_a3f2b8c1d4e5f6a7"

Size: ~90 bytes (base64)

Encryption:
  DEK from original message (sender can decrypt with their copy)
```

**Privacy Note:** Receipts reveal communication patterns. Make optional/disabled by default.

---

#### 8. Presence & Status (User-Controlled)

**Presence:**
```
Group: dna.presence
Key:   <identity>
Value: <status>|<last_seen_ts>|<status_message>

Status Values: online|away|busy|offline|invisible

Example:
  dna.presence/alice = "online|1728951000|At work"

Size: ~30-100 bytes

Note: User explicitly shares presence. Not encrypted (public status).
```

**Typing Indicators:**
```
Group: dna.typing
Key:   <identity>.<conversation_with>
Value: <timestamp>

Example:
  dna.typing/alice.bob = "1728951005"

Note: Ephemeral. If timestamp > 5 seconds old, clear indicator.

Size: ~10 bytes
```

---

## Encryption Scheme

### Overview

**Strategy:** Reuse existing DEK (Data Encryption Key) for both message content and metadata encryption.

**Rationale:**
- No protocol changes needed
- Uses existing Kyber512 KEM infrastructure
- Same security guarantees for content and metadata
- Simple implementation
- Efficient (no extra key wrapping overhead)

---

### Current Message Encryption (Unchanged)

```
Protocol Version: 0x05 (AES-256-GCM)

1. Generate random 32-byte DEK
2. Sign message plaintext with Dilithium3
3. Encrypt message with AES-256-GCM using DEK
4. For each recipient:
   a. Kyber512.Encaps(recipient_pubkey) → (kyber_ct, shared_secret)
   b. AES_KeyWrap(DEK, shared_secret) → wrapped_dek
5. Build message: [header | recipient_entries | nonce | ciphertext | tag | signature]
```

**Message Format:**
```
struct messenger_enc_header_t {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x05
    uint8_t enc_key_type;       // Kyber512
    uint8_t recipient_count;    // 1-255
    uint8_t reserved;
    uint32_t encrypted_size;
    uint32_t signature_size;
};

struct messenger_recipient_entry_t {
    uint8_t kyber_ciphertext[768];    // Kyber512 KEM ciphertext
    uint8_t wrapped_dek[40];          // AES-wrapped DEK
};

Message Structure:
[header(20) | recipient_entry_1(808) | ... | recipient_entry_N(808) |
 nonce(12) | encrypted_data | tag(16) | signature]
```

---

### Metadata Encryption (NEW)

**Using Same DEK:**

```
1. Generate random 32-byte DEK (done for message)
2. Build metadata plaintext:
   "<sender>|<timestamp>|<type>|<size>|<reply_to>|<ttl>|<flags>"
3. Generate random 12-byte nonce (separate from message nonce)
4. Encrypt metadata with AES-256-GCM:
   encrypted_meta = AES-256-GCM(DEK, metadata_plaintext, meta_nonce)
5. Build metadata blob: [meta_nonce | encrypted_meta | meta_tag]
```

**Metadata Blob Format:**
```
[nonce(12) | encrypted_metadata(variable) | tag(16)]

Total size: 28 + len(encrypted_metadata)
Typical size: 28 + 50-120 = 78-148 bytes
Base64: ~100-200 bytes
```

---

### Notification Encryption (NEW)

**Using Same DEK:**

```
1. Build notification plaintext:
   "<sender>|<message_id>|<type>"
2. Generate random 12-byte nonce
3. Encrypt notification with AES-256-GCM:
   encrypted_notif = AES-256-GCM(DEK, notif_plaintext, notif_nonce)
4. Build notification blob: [notif_nonce | encrypted_notif | notif_tag]
```

**Notification Blob Format:**
```
[nonce(12) | encrypted_notification(variable) | tag(16)]

Total size: 28 + len(encrypted_notification)
Typical size: 28 + 40-60 = 68-88 bytes
Base64: ~90-120 bytes
```

---

### Decryption Process

**Steps:**
```
1. Recipient fetches message from dna.inbox.<identity>/<msg_id>
2. Parse message header to get recipient_count
3. Try each recipient_entry:
   a. Kyber512.Decaps(kyber_ciphertext, recipient_privkey) → shared_secret
   b. AES_KeyUnwrap(wrapped_dek, shared_secret) → DEK
4. If unwrap succeeds, use DEK to:
   a. Decrypt message: AES-256-GCM(DEK, message_ciphertext, message_nonce)
   b. Verify signature with sender's pubkey (embedded in message)
5. Separately, decrypt metadata:
   a. Fetch from dna.meta.<identity>/<msg_id>
   b. Parse: [meta_nonce | encrypted_meta | meta_tag]
   c. AES-256-GCM(DEK, encrypted_meta, meta_nonce) → metadata_plaintext
   d. Parse: "sender|timestamp|type|..."
6. Separately, decrypt notification (if present):
   a. Fetch from dna.notify.<identity>/<key>
   b. Parse: [notif_nonce | encrypted_notif | notif_tag]
   c. AES-256-GCM(DEK, encrypted_notif, notif_nonce) → notif_plaintext
```

**Key Insight:** Same DEK is used for message, metadata, and notification. Each has independent nonce for GCM.

---

### Security Properties

**Forward Secrecy:**
- ✅ New random DEK generated for every message
- ✅ Compromise of one message's DEK doesn't affect others
- ✅ Kyber512 KEM provides quantum-resistant key exchange

**Authenticated Encryption:**
- ✅ AES-256-GCM provides AEAD (Authenticated Encryption with Associated Data)
- ✅ Authentication tag prevents tampering
- ✅ Dilithium3 signature provides sender authentication

**Metadata Privacy:**
- ✅ Sender identity encrypted (not visible in GDB)
- ✅ Timestamp encrypted
- ✅ Message type encrypted
- ✅ Only recipient can decrypt metadata

**Traffic Analysis Resistance:**
- ⚠️ Partial - GDB keys reveal recipient identity (dna.inbox.<recipient>)
- ⚠️ Message count leaked via unread counter
- ✅ Sender identity hidden
- ✅ Conversation patterns hidden (reply_to encrypted)

---

## Message Send Flow

### Complete Send Operation

**Bob sends message to Alice:**

```
Function: messenger_send_message(ctx, recipients=["alice"], message="Hello")

Step 1: Generate Keys
  - DEK = random_bytes(32)
  - message_nonce = random_bytes(12)
  - meta_nonce = random_bytes(12)
  - notif_nonce = random_bytes(12)

Step 2: Load Keys
  - Load bob's signing private key: ~/.dna/bob-dilithium.pqkey
  - Load alice's public keys from GDB:
    * signing_pk = gdb_read("dna.keys.signing/alice")
    * encryption_pk = gdb_read("dna.keys.encryption/alice")

Step 3: Sign Message
  - signature = Dilithium3.Sign(bob_signing_privkey, "Hello")
  - Verify: Dilithium3.Verify(signature, "Hello", bob_signing_pubkey) ✓

Step 4: Encrypt Message Content
  - encrypted_msg = AES-256-GCM(DEK, "Hello", message_nonce)
  - Produces: ciphertext + tag

Step 5: Encrypt Metadata
  - meta_plaintext = "bob|1728950400|text|256|none|0|encrypted"
  - encrypted_meta = AES-256-GCM(DEK, meta_plaintext, meta_nonce)
  - meta_blob = [meta_nonce | encrypted_meta | meta_tag]

Step 6: Encrypt Notification
  - notif_plaintext = "bob|msg_1728950400_a3f2b8c1|text"
  - encrypted_notif = AES-256-GCM(DEK, notif_plaintext, notif_nonce)
  - notif_blob = [notif_nonce | encrypted_notif | notif_tag]

Step 7: Wrap DEK for Alice
  - (kyber_ct, shared_secret) = Kyber512.Encaps(alice_encryption_pk)
  - wrapped_dek = AES_KeyWrap(DEK, shared_secret)
  - recipient_entry = [kyber_ct | wrapped_dek]  // 768 + 40 = 808 bytes

Step 8: Build Message Blob
  - header = {magic, version, enc_key_type, recipient_count=1, ...}
  - message_blob = [header | recipient_entry | message_nonce | encrypted_msg | msg_tag | signature]

Step 9: Store in GDB
  - msg_id = "msg_" + timestamp + "_" + random_hex(8)

  # Store encrypted message
  gdb_write("dna.inbox.alice/" + msg_id, base64(message_blob))

  # Store encrypted metadata
  gdb_write("dna.meta.alice/" + msg_id, base64(meta_blob))

  # Store encrypted notification
  notif_key = timestamp + "_" + random_hex(8)
  gdb_write("dna.notify.alice/" + notif_key, base64(notif_blob))

  # Increment unread counter
  count = gdb_read("dna.unread/alice") || 0
  gdb_write("dna.unread/alice", count + 1)

Step 10: Cleanup
  - Securely wipe DEK: memset(DEK, 0, 32)
  - Securely wipe shared_secret
  - Free all allocated memory

Result:
  ✓ Message encrypted and stored in Alice's inbox
  ✓ Metadata encrypted and stored separately
  ✓ Notification queued for Alice
  ✓ Unread badge updated
```

---

### GDB Commands (CLI Example)

```bash
#!/bin/bash

# Send message from Bob to Alice

MSG_ID="msg_$(date +%s)_$(openssl rand -hex 4)"
TIMESTAMP=$(date +%s)

# 1. Encrypt message (calls messenger library)
MESSAGE_BLOB=$(./dna_messenger encrypt \
  --sender bob \
  --recipients alice \
  --message "Hello" \
  --output-format base64)

# 2. Build and encrypt metadata
META_PLAINTEXT="bob|${TIMESTAMP}|text|$(echo $MESSAGE_BLOB | wc -c)|none|0|encrypted"
ENCRYPTED_META=$(encrypt_metadata "$META_PLAINTEXT" "$DEK")

# 3. Build and encrypt notification
NOTIF_PLAINTEXT="bob|${MSG_ID}|text"
ENCRYPTED_NOTIF=$(encrypt_notification "$NOTIF_PLAINTEXT" "$DEK")

# 4. Store message blob
cellframe-node-cli global_db write \
  -group dna.inbox.alice \
  -key "$MSG_ID" \
  -value "$MESSAGE_BLOB"

# 5. Store encrypted metadata
cellframe-node-cli global_db write \
  -group dna.meta.alice \
  -key "$MSG_ID" \
  -value "$ENCRYPTED_META"

# 6. Store encrypted notification
NOTIF_KEY="${TIMESTAMP}_$(openssl rand -hex 4)"
cellframe-node-cli global_db write \
  -group dna.notify.alice \
  -key "$NOTIF_KEY" \
  -value "$ENCRYPTED_NOTIF"

# 7. Update unread counter
CURRENT_COUNT=$(cellframe-node-cli global_db read -group dna.unread -key alice 2>/dev/null || echo "0")
NEW_COUNT=$((CURRENT_COUNT + 1))
cellframe-node-cli global_db write \
  -group dna.unread \
  -key alice \
  -value "$NEW_COUNT"

echo "✓ Message sent to Alice (ID: $MSG_ID)"
```

---

## Message Receive Flow

### Complete Receive Operation

**Alice receives message from Bob:**

```
Step 1: Watch for Notifications
  - Poll/watch: gdb_get_keys("dna.notify.alice")
  - New keys found: ["1728950400_xyz789ab"]

Step 2: Fetch Encrypted Notification
  - notif_blob = gdb_read("dna.notify.alice/1728950400_xyz789ab")
  - Parse: [notif_nonce | encrypted_notif | notif_tag]

Step 3: Fetch Message to Get DEK
  - Need DEK to decrypt notification
  - msg_id = (extracted from notification key or predefined mapping)
  - message_blob = gdb_read("dna.inbox.alice/" + msg_id)

Step 4: Unwrap DEK
  - Parse message header → recipient_count
  - Load alice_kyber_privkey from ~/.dna/alice-kyber512.pqkey
  - For each recipient_entry:
    * shared_secret = Kyber512.Decaps(kyber_ct, alice_kyber_privkey)
    * DEK = AES_KeyUnwrap(wrapped_dek, shared_secret)
    * If unwrap succeeds, break

Step 5: Decrypt Notification
  - notif_plaintext = AES-256-GCM(DEK, encrypted_notif, notif_nonce, notif_tag)
  - Parse: "bob|msg_1728950400_a3f2b8c1|text"
  - Extract: sender="bob", msg_id="msg_1728950400_a3f2b8c1", type="text"

Step 6: Show Push Notification
  - Display: "Bob sent you a message"
  - Badge: Update with unread count from gdb_read("dna.unread/alice")

Step 7: User Opens App → Fetch Metadata
  - meta_blob = gdb_read("dna.meta.alice/msg_1728950400_a3f2b8c1")
  - Parse: [meta_nonce | encrypted_meta | meta_tag]
  - meta_plaintext = AES-256-GCM(DEK, encrypted_meta, meta_nonce, meta_tag)
  - Parse: "bob|1728950400|text|4478|none|0|encrypted"
  - Display in conversation list:
    * Sender: Bob
    * Time: 2:00 PM
    * Type: Text message
    * Size: 4478 bytes

Step 8: User Opens Conversation → Decrypt Message
  - message_blob already fetched (Step 3)
  - Parse: [header | recipient_entries | msg_nonce | encrypted_msg | msg_tag | signature]
  - message_plaintext = AES-256-GCM(DEK, encrypted_msg, msg_nonce, msg_tag)
  - Result: "Hello"

Step 9: Verify Signature
  - Extract sender_signing_pubkey from signature data
  - Verify: Dilithium3.Verify(signature, "Hello", sender_signing_pubkey)
  - Cross-check sender_pubkey against keyserver:
    * keyserver_pubkey = gdb_read("dna.keys.signing/bob")
    * Assert: sender_signing_pubkey == keyserver_pubkey ✓

Step 10: Send Read Receipt (Optional)
  - receipt_plaintext = timestamp_delivered + "|" + timestamp_read + "|" + device_id
  - encrypted_receipt = AES-256-GCM(DEK, receipt_plaintext, receipt_nonce)
  - receipt_blob = [receipt_nonce | encrypted_receipt | receipt_tag]
  - gdb_write("dna.receipt.msg_1728950400_a3f2b8c1/alice", base64(receipt_blob))

Step 11: Update Unread Counter
  - count = gdb_read("dna.unread/alice")
  - gdb_write("dna.unread/alice", count - 1)

Step 12: Cleanup Notification
  - gdb_delete("dna.notify.alice/1728950400_xyz789ab")

Step 13: Display Message
  - Show in UI: "Bob (2:00 PM): Hello"
  - Mark as read

Step 14: Cleanup
  - Securely wipe DEK: memset(DEK, 0, 32)
  - Free all allocated memory
```

---

### Optimized Receive Flow (Caching)

**Performance Optimization:**

```
Problem: Fetching message blob just to get DEK for notification is slow

Solution: Cache DEK locally after first message fetch

Step 1: Watch for notifications
Step 2: Fetch encrypted notification
Step 3: Check local cache for DEK:
  - cache_key = hash(msg_id)
  - DEK = local_cache.get(cache_key)
  - If not cached:
    * Fetch message blob
    * Unwrap DEK
    * Cache DEK: local_cache.set(cache_key, DEK, ttl=3600)
Step 4: Decrypt notification with cached DEK
Step 5: Show push notification (fast!)

Result: Subsequent notifications decrypt instantly without fetching full message
```

---

## Push Notification System

### Architecture

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Bob's App  │         │  GDB Node   │         │ Alice's App │
└─────────────┘         └─────────────┘         └─────────────┘
       │                       │                       │
       │  1. Send message      │                       │
       ├──────────────────────>│                       │
       │                       │                       │
       │  2. Write to          │                       │
       │     dna.notify.alice  │                       │
       │                       │                       │
       │                       │  3. Watch triggered   │
       │                       │<──────────────────────┤
       │                       │                       │
       │                       │  4. Fetch notification│
       │                       ├──────────────────────>│
       │                       │                       │
       │                       │  5. Decrypt           │
       │                       │     (sender=bob)      │
       │                       │                       │
       │                       │  6. Show notification │
       │                       │    "Bob: New message" │
```

### Implementation Options

#### Option 1: Polling

```c
// Client polls notification queue every N seconds

void *notification_thread(void *arg) {
    char *identity = (char*)arg;
    char group[256];
    snprintf(group, sizeof(group), "dna.notify.%s", identity);

    while (running) {
        // Get all notification keys
        char **keys = gdb_get_keys(group);

        for (int i = 0; keys[i]; i++) {
            // Process notification
            process_notification(identity, keys[i]);

            // Delete after processing
            gdb_delete(group, keys[i]);
        }

        // Poll every 5 seconds
        sleep(5);
    }
}
```

**Pros:**
- ✅ Simple implementation
- ✅ Works with any GDB backend

**Cons:**
- ❌ High latency (5-10 second delay)
- ❌ Wastes bandwidth polling empty queue

---

#### Option 2: GDB Watch (If Supported)

```c
// Client registers watch callback

void notification_callback(const char *group, const char *key, const char *value) {
    // Called when new key appears in watched group
    printf("New notification: %s/%s\n", group, key);

    // Process immediately
    process_notification_immediate(key, value);
}

// Register watch
gdb_watch("dna.notify.alice", notification_callback);
```

**Pros:**
- ✅ Real-time (instant notification)
- ✅ Efficient (no polling)

**Cons:**
- ❌ Requires GDB watch support
- ❌ Persistent connection needed

---

#### Option 3: WebSocket Relay (Recommended)

```
Client → WebSocket → Relay Server → GDB

Relay server watches GDB and pushes to clients via WebSocket
```

**Relay Server:**
```python
# dna_notification_relay.py

from flask_socketio import SocketIO, emit
import subprocess

socketio = SocketIO(app)
connected_users = {}  # {identity: [socket_ids]}

# Watch GDB for notifications
def watch_gdb_notifications():
    while True:
        # Poll all active users
        for identity in connected_users:
            keys = gdb_get_keys(f"dna.notify.{identity}")
            for key in keys:
                value = gdb_read(f"dna.notify.{identity}/{key}")

                # Push to all connected devices for this user
                for socket_id in connected_users[identity]:
                    socketio.emit('notification', {
                        'key': key,
                        'value': value
                    }, room=socket_id)

        time.sleep(1)

@socketio.on('register')
def handle_register(data):
    identity = data['identity']
    if identity not in connected_users:
        connected_users[identity] = []
    connected_users[identity].append(request.sid)
```

**Client:**
```c
// Connect to relay server
WebSocket *ws = websocket_connect("wss://relay.dna-messenger.io");

// Register for notifications
websocket_send(ws, "{\"event\":\"register\",\"identity\":\"alice\"}");

// Receive notifications
void on_notification(const char *data) {
    // Immediate notification received
    process_notification(data);
}

websocket_on_message(ws, on_notification);
```

**Pros:**
- ✅ Real-time (instant)
- ✅ Scales well (relay server handles GDB polling)
- ✅ Works on mobile (iOS/Android support WebSockets)

**Cons:**
- ❌ Requires relay server infrastructure
- ❌ Centralization (but relay can't decrypt messages)

---

## Device Management

### Device Registration

```c
/**
 * Register device for push notifications
 */
int register_device(
    const char *identity,
    const char *device_id,      // "android_a3f2b8c1d4e5f6a7"
    const char *device_type,    // "android|ios|desktop|web"
    const char *push_token      // FCM/APNS token or WebSocket session
) {
    // 1. Build device info
    char device_info[512];
    snprintf(device_info, sizeof(device_info),
             "%s|%s|%ld|%ld",
             device_type, push_token, time(NULL), time(NULL));

    // 2. Derive device encryption key from user's master key
    uint8_t device_key[32];
    derive_device_key(identity, device_key);

    // 3. Encrypt device info
    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;
    encrypt_device_info(device_info, device_key, &encrypted, &encrypted_len);

    // 4. Store in GDB
    char group[256];
    snprintf(group, sizeof(group), "dna.devices.%s", identity);
    gdb_write(group, device_id, base64(encrypted));

    // 5. Cleanup
    memset(device_key, 0, 32);
    free(encrypted);

    return 0;
}
```

### Device List

```c
/**
 * Get all registered devices for user
 */
char **get_devices(const char *identity) {
    char group[256];
    snprintf(group, sizeof(group), "dna.devices.%s", identity);

    // Get all device IDs
    char **device_ids = gdb_get_keys(group);

    return device_ids;
}
```

### Update Last Seen

```c
/**
 * Update device last_seen timestamp
 */
int update_device_last_seen(const char *identity, const char *device_id) {
    // 1. Fetch current device info
    char group[256];
    snprintf(group, sizeof(group), "dna.devices.%s", identity);
    char *encrypted = gdb_read(group, device_id);

    // 2. Decrypt
    char *device_info = decrypt_device_info(encrypted, identity);

    // 3. Parse and update last_seen
    char type[32], token[256];
    long registered_ts, last_seen_ts;
    sscanf(device_info, "%[^|]|%[^|]|%ld|%ld", type, token, &registered_ts, &last_seen_ts);

    // 4. Build updated info
    snprintf(device_info, 512, "%s|%s|%ld|%ld", type, token, registered_ts, time(NULL));

    // 5. Re-encrypt and store
    uint8_t *new_encrypted = NULL;
    size_t new_encrypted_len = 0;
    encrypt_device_info(device_info, identity_key, &new_encrypted, &new_encrypted_len);
    gdb_write(group, device_id, base64(new_encrypted));

    free(encrypted);
    free(device_info);
    free(new_encrypted);

    return 0;
}
```

---

## Security Analysis

### Threat Model

**Assumptions:**
1. GDB is distributed and replicated across Cellframe network nodes
2. Node operators can read all GDB data
3. Network traffic can be observed (passive adversary)
4. Cryptographic primitives (Kyber512, Dilithium3, AES-256-GCM) are secure

**Adversaries:**
- **Passive Observer:** Can read GDB, observe network traffic
- **GDB Node Operator:** Can read all data stored in GDB
- **Network Attacker:** Can intercept/analyze network packets

---

### Security Properties

#### ✅ Confidentiality (Message Content)

**Protected:**
- Message plaintext encrypted with AES-256-GCM
- DEK wrapped with Kyber512 KEM (quantum-resistant)
- Signature prevents tampering

**Attack Resistance:**
- ✅ Resistant to quantum computer attacks (Kyber512)
- ✅ Authenticated encryption prevents tampering (GCM)
- ✅ Forward secrecy (new DEK per message)

---

#### ✅ Confidentiality (Metadata)

**Protected:**
- Sender identity encrypted
- Timestamp encrypted
- Message type encrypted
- Reply threading encrypted

**Attack Resistance:**
- ✅ GDB node operators cannot see who sent message
- ✅ Passive observers cannot see conversation structure

---

#### ⚠️ Partial: Traffic Analysis

**Leaked:**
- ❌ Recipient identity visible in GDB keys: `dna.inbox.alice/<msg_id>`
- ❌ Message count visible: `dna.unread/alice`
- ❌ Timing: When messages sent (key creation timestamp)

**Attack Possibilities:**
- 🔴 Build social graph: Track which users receive messages
- 🔴 Identify busy users: High message count
- 🔴 Timing analysis: Daily patterns

**Mitigation:**
- Use pseudonymous identities (alice_device1, alice_device2)
- Pad unread counts to nearest power of 2
- Add dummy traffic (cover traffic)

---

#### ✅ Authenticity

**Protected:**
- Dilithium3 signature proves sender identity
- Sender pubkey verified against keyserver
- GCM tag prevents ciphertext modification

**Attack Resistance:**
- ✅ Cannot spoof sender
- ✅ Cannot modify message without detection
- ✅ Replay attacks prevented (unique nonces)

---

#### ✅ Forward Secrecy

**Properties:**
- New DEK generated per message
- Past messages remain secure if current DEK compromised
- Kyber512 KEM provides ephemeral key exchange

**Attack Resistance:**
- ✅ Compromise of one message doesn't affect others
- ✅ Quantum resistance maintained

---

### Comparison with Other Messengers

| Feature | DNA Messenger (GDB) | Signal | WhatsApp | Telegram |
|---------|---------------------|--------|----------|----------|
| **E2E Encryption** | ✅ Kyber512+AES-256 | ✅ Signal Protocol | ✅ Signal Protocol | ⚠️ Optional |
| **Metadata Encryption** | ✅ Yes | ⚠️ Partial (sealed sender) | ❌ No | ❌ No |
| **Quantum Resistance** | ✅ Yes (Kyber512) | ❌ No | ❌ No | ❌ No |
| **Forward Secrecy** | ✅ Yes | ✅ Yes | ✅ Yes | ⚠️ Optional |
| **Decentralized Storage** | ✅ Yes (GDB) | ❌ No (AWS) | ❌ No (Meta) | ❌ No (Telegram servers) |
| **Traffic Analysis Resistance** | ⚠️ Partial | ⚠️ Partial | ❌ Poor | ❌ Poor |
| **Sender Anonymity** | ✅ Yes (encrypted) | ⚠️ Partial | ❌ No | ❌ No |

---

## Implementation Plan

### Phase 1: Core GDB Interface (Week 1-2)

**Files to Create:**
```
dna_gdb.h           - GDB interface header
dna_gdb.c           - GDB CLI command wrapper
dna_gdb_crypto.c    - Metadata/notification encryption
dna_gdb_crypto.h    - Crypto function declarations
```

**Functions:**
```c
// GDB basic operations
int gdb_write(const char *group, const char *key, const char *value);
char* gdb_read(const char *group, const char *key);
int gdb_delete(const char *group, const char *key);
char** gdb_get_keys(const char *group);

// Keyserver operations
int gdb_store_pubkey(const char *identity, const uint8_t *sign_pk, const uint8_t *enc_pk);
int gdb_load_pubkey(const char *identity, uint8_t **sign_pk, uint8_t **enc_pk);

// Message operations (with encryption)
int gdb_send_message(const char *sender, const char **recipients, size_t count, const char *msg);
int gdb_receive_messages(const char *recipient, message_info_t **messages, int *count);

// Metadata encryption
int encrypt_metadata(const uint8_t *dek, const char *metadata, uint8_t **encrypted, size_t *len);
int decrypt_metadata(const uint8_t *dek, const uint8_t *encrypted, size_t len, char **metadata);

// Notification encryption
int encrypt_notification(const uint8_t *dek, const char *notif, uint8_t **encrypted, size_t *len);
int decrypt_notification(const uint8_t *dek, const uint8_t *encrypted, size_t len, char **notif);
```

---

### Phase 2: Modify Messenger (Week 3-4)

**Files to Modify:**
```
messenger.c         - Add GDB calls
messenger.h         - Update function signatures
CMakeLists.txt      - Add dna_gdb sources
```

**Changes:**

```c
// In messenger_send_message():

// BEFORE (PostgreSQL):
PQexecParams(ctx->pg_conn, "INSERT INTO messages ...", ...);

// AFTER (GDB):
// 1. Encrypt message (existing code)
uint8_t *ciphertext = NULL;
size_t ciphertext_len = 0;
messenger_encrypt_multi_recipient(message, ..., &ciphertext, &ciphertext_len);

// 2. Encrypt metadata (NEW)
uint8_t *encrypted_meta = NULL;
size_t encrypted_meta_len = 0;
encrypt_metadata(dek, metadata_plaintext, &encrypted_meta, &encrypted_meta_len);

// 3. Encrypt notification (NEW)
uint8_t *encrypted_notif = NULL;
size_t encrypted_notif_len = 0;
encrypt_notification(dek, notif_plaintext, &encrypted_notif, &encrypted_notif_len);

// 4. Store in GDB
gdb_write(sprintf("dna.inbox.%s", recipient), msg_id, base64(ciphertext));
gdb_write(sprintf("dna.meta.%s", recipient), msg_id, base64(encrypted_meta));
gdb_write(sprintf("dna.notify.%s", recipient), notif_key, base64(encrypted_notif));
```

---

### Phase 3: Testing (Week 5)

**Test Cases:**

```c
// Test 1: Public key storage and retrieval
void test_keyserver() {
    // Store keys
    gdb_store_pubkey("alice", alice_sign_pk, alice_enc_pk);

    // Retrieve keys
    uint8_t *sign_pk = NULL, *enc_pk = NULL;
    gdb_load_pubkey("alice", &sign_pk, &enc_pk);

    // Verify
    assert(memcmp(sign_pk, alice_sign_pk, 1952) == 0);
    assert(memcmp(enc_pk, alice_enc_pk, 800) == 0);
}

// Test 2: Message send/receive
void test_messaging() {
    // Bob sends to Alice
    gdb_send_message("bob", (const char*[]){"alice"}, 1, "Hello");

    // Alice receives
    message_info_t *messages = NULL;
    int count = 0;
    gdb_receive_messages("alice", &messages, &count);

    // Verify
    assert(count == 1);
    assert(strcmp(messages[0].sender, "bob") == 0);
    assert(strcmp(messages[0].plaintext, "Hello") == 0);
}

// Test 3: Metadata encryption
void test_metadata_encryption() {
    uint8_t dek[32];
    qgp_randombytes(dek, 32);

    const char *metadata = "bob|1728950400|text|256|none|0|encrypted";

    // Encrypt
    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;
    encrypt_metadata(dek, metadata, &encrypted, &encrypted_len);

    // Decrypt
    char *decrypted = NULL;
    decrypt_metadata(dek, encrypted, encrypted_len, &decrypted);

    // Verify
    assert(strcmp(metadata, decrypted) == 0);
}

// Test 4: Notification system
void test_notifications() {
    // Send message
    gdb_send_message("bob", (const char*[]){"alice"}, 1, "Hello");

    // Check notification queue
    char **notif_keys = gdb_get_keys("dna.notify.alice");
    assert(notif_keys[0] != NULL);

    // Fetch and decrypt notification
    char *encrypted_notif = gdb_read("dna.notify.alice", notif_keys[0]);
    char *notif_plaintext = NULL;
    decrypt_notification(dek, encrypted_notif, strlen(encrypted_notif), &notif_plaintext);

    // Verify format: "bob|msg_...|text"
    assert(strncmp(notif_plaintext, "bob|", 4) == 0);
}

// Test 5: Multi-recipient
void test_multi_recipient() {
    // Bob sends to Alice and Carol
    gdb_send_message("bob", (const char*[]){"alice", "carol"}, 2, "Hello all");

    // Alice receives
    message_info_t *alice_messages = NULL;
    int alice_count = 0;
    gdb_receive_messages("alice", &alice_messages, &alice_count);
    assert(alice_count == 1);

    // Carol receives
    message_info_t *carol_messages = NULL;
    int carol_count = 0;
    gdb_receive_messages("carol", &carol_messages, &carol_count);
    assert(carol_count == 1);

    // Both decrypt same message
    assert(strcmp(alice_messages[0].plaintext, carol_messages[0].plaintext) == 0);
}
```

---

### Phase 4: Migration Tools (Week 6)

**PostgreSQL → GDB Migration Script:**

```python
#!/usr/bin/env python3
"""
Migrate DNA Messenger data from PostgreSQL to Cellframe GDB
"""

import psycopg2
import subprocess
import base64

def migrate_keyserver():
    """Migrate public keys from keyserver table to GDB"""
    conn = psycopg2.connect("dbname=dna_messenger user=dna password=dna_password")
    cur = conn.cursor()

    # Fetch all keys from PostgreSQL
    cur.execute("SELECT identity, signing_pubkey, encryption_pubkey, created_at FROM keyserver")
    rows = cur.fetchall()

    for identity, sign_pk, enc_pk, created_at in rows:
        # Store signing key
        subprocess.run([
            'cellframe-node-cli', 'global_db', 'write',
            '-group', 'dna.keys.signing',
            '-key', identity,
            '-value', base64.b64encode(sign_pk).decode()
        ])

        # Store encryption key
        subprocess.run([
            'cellframe-node-cli', 'global_db', 'write',
            '-group', 'dna.keys.encryption',
            '-key', identity,
            '-value', base64.b64encode(enc_pk).decode()
        ])

        # Store metadata
        timestamp = int(created_at.timestamp())
        subprocess.run([
            'cellframe-node-cli', 'global_db', 'write',
            '-group', 'dna.keys.metadata',
            '-key', identity,
            '-value', f"{timestamp}|1"
        ])

        print(f"✓ Migrated keys for {identity}")

    cur.close()
    conn.close()

def migrate_messages():
    """Migrate messages from messages table to GDB"""
    conn = psycopg2.connect("dbname=dna_messenger user=dna password=dna_password")
    cur = conn.cursor()

    # Fetch all messages
    cur.execute("""
        SELECT id, sender, recipient, ciphertext, created_at
        FROM messages
        ORDER BY created_at ASC
    """)
    rows = cur.fetchall()

    for msg_id, sender, recipient, ciphertext, created_at in rows:
        # Generate message ID
        timestamp = int(created_at.timestamp())
        gdb_msg_id = f"msg_{timestamp}_{msg_id:08x}"

        # Store encrypted message blob
        subprocess.run([
            'cellframe-node-cli', 'global_db', 'write',
            '-group', f'dna.inbox.{recipient}',
            '-key', gdb_msg_id,
            '-value', base64.b64encode(ciphertext).decode()
        ])

        # Note: Cannot migrate metadata as it wasn't stored in PostgreSQL
        # Metadata will be generated on-the-fly or left empty

        print(f"✓ Migrated message {gdb_msg_id} ({sender} → {recipient})")

    cur.close()
    conn.close()

if __name__ == '__main__':
    print("Starting PostgreSQL → GDB migration...")
    migrate_keyserver()
    migrate_messages()
    print("\n✓ Migration complete!")
```

---

## Migration from PostgreSQL

### Current PostgreSQL Schema

```sql
-- Public keys
CREATE TABLE keyserver (
    id SERIAL PRIMARY KEY,
    identity TEXT UNIQUE NOT NULL,
    signing_pubkey BYTEA NOT NULL,           -- Dilithium3 (1952 bytes)
    signing_pubkey_len INTEGER NOT NULL,
    encryption_pubkey BYTEA NOT NULL,        -- Kyber512 (800 bytes)
    encryption_pubkey_len INTEGER NOT NULL,
    fingerprint TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    ciphertext_len INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_messages_recipient ON messages(recipient);
CREATE INDEX idx_messages_sender ON messages(sender);
```

---

### GDB Equivalent Structure

```
PostgreSQL Table: keyserver
  → dna.keys.signing/<identity> = base64(signing_pubkey)
  → dna.keys.encryption/<identity> = base64(encryption_pubkey)
  → dna.keys.metadata/<identity> = created_at|1

PostgreSQL Table: messages
  → dna.inbox.<recipient>/<msg_id> = base64(ciphertext)
  → dna.meta.<recipient>/<msg_id> = base64(encrypted_metadata)  [NEW]
```

---

### Migration Strategy

**Phase 1: Dual Write (Weeks 1-2)**
```
Write to both PostgreSQL and GDB
Read from PostgreSQL (primary)
```

**Phase 2: Dual Read (Weeks 3-4)**
```
Write to both PostgreSQL and GDB
Read from GDB (primary), fallback to PostgreSQL
```

**Phase 3: GDB Only (Week 5+)**
```
Write to GDB only
Read from GDB only
Keep PostgreSQL as backup (read-only)
```

**Phase 4: Deprecate PostgreSQL (Month 2+)**
```
Archive PostgreSQL data
Remove PostgreSQL dependency
GDB is source of truth
```

---

### Code Changes for Dual Write

```c
// In messenger_send_message():

#ifdef DUAL_WRITE_MODE
    // Write to PostgreSQL (existing code)
    PQexecParams(ctx->pg_conn, "INSERT INTO messages ...", ...);

    // Also write to GDB (new code)
    gdb_write(sprintf("dna.inbox.%s", recipient), msg_id, base64(ciphertext));
    gdb_write(sprintf("dna.meta.%s", recipient), msg_id, base64(encrypted_meta));
#else
    // GDB only (production mode)
    gdb_write(sprintf("dna.inbox.%s", recipient), msg_id, base64(ciphertext));
    gdb_write(sprintf("dna.meta.%s", recipient), msg_id, base64(encrypted_meta));
#endif
```

---

## Testing & Validation

### Unit Tests

```c
// test_gdb_interface.c

void test_gdb_write_read() {
    // Write
    int ret = gdb_write("test.group", "key1", "value1");
    assert(ret == 0);

    // Read
    char *value = gdb_read("test.group", "key1");
    assert(strcmp(value, "value1") == 0);
    free(value);
}

void test_gdb_delete() {
    gdb_write("test.group", "key1", "value1");
    gdb_delete("test.group", "key1");

    char *value = gdb_read("test.group", "key1");
    assert(value == NULL);
}

void test_gdb_get_keys() {
    gdb_write("test.group", "key1", "value1");
    gdb_write("test.group", "key2", "value2");

    char **keys = gdb_get_keys("test.group");
    assert(keys[0] != NULL);
    assert(keys[1] != NULL);
    assert(keys[2] == NULL);
}
```

---

### Integration Tests

```bash
#!/bin/bash
# test_end_to_end.sh

# Setup: Generate keys for Alice and Bob
./dna_messenger --generate-keys alice
./dna_messenger --generate-keys bob

# Test 1: Alice sends to Bob
./dna_messenger --sender alice --recipient bob --message "Hello Bob"

# Verify Bob receives
OUTPUT=$(./dna_messenger --identity bob --list-messages)
echo "$OUTPUT" | grep "Hello Bob" || exit 1

# Test 2: Bob replies to Alice
./dna_messenger --sender bob --recipient alice --message "Hi Alice"

# Verify Alice receives
OUTPUT=$(./dna_messenger --identity alice --list-messages)
echo "$OUTPUT" | grep "Hi Alice" || exit 1

# Test 3: Multi-recipient
./dna_messenger --sender alice --recipients bob,carol --message "Hello all"

# Verify both receive
OUTPUT_BOB=$(./dna_messenger --identity bob --list-messages)
OUTPUT_CAROL=$(./dna_messenger --identity carol --list-messages)
echo "$OUTPUT_BOB" | grep "Hello all" || exit 1
echo "$OUTPUT_CAROL" | grep "Hello all" || exit 1

echo "✓ All integration tests passed"
```

---

### Performance Tests

```c
// test_performance.c

void benchmark_metadata_encryption() {
    uint8_t dek[32];
    qgp_randombytes(dek, 32);

    const char *metadata = "bob|1728950400|text|4478|none|0|encrypted";

    clock_t start = clock();
    for (int i = 0; i < 10000; i++) {
        uint8_t *encrypted = NULL;
        size_t encrypted_len = 0;
        encrypt_metadata(dek, metadata, &encrypted, &encrypted_len);
        free(encrypted);
    }
    clock_t end = clock();

    double time_per_op = ((double)(end - start)) / CLOCKS_PER_SEC / 10000.0;
    printf("Metadata encryption: %.6f sec per op\n", time_per_op);
    // Expected: < 0.0001 sec (< 100 microseconds)
}

void benchmark_notification_decryption() {
    uint8_t dek[32];
    qgp_randombytes(dek, 32);

    const char *notification = "bob|msg_1728950400_a3f2b8c1|text";
    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;
    encrypt_notification(dek, notification, &encrypted, &encrypted_len);

    clock_t start = clock();
    for (int i = 0; i < 10000; i++) {
        char *decrypted = NULL;
        decrypt_notification(dek, encrypted, encrypted_len, &decrypted);
        free(decrypted);
    }
    clock_t end = clock();

    double time_per_op = ((double)(end - start)) / CLOCKS_PER_SEC / 10000.0;
    printf("Notification decryption: %.6f sec per op\n", time_per_op);
    // Expected: < 0.0001 sec (< 100 microseconds)
}
```

---

## Appendix A: GDB Command Reference

### Write Operation

```bash
cellframe-node-cli global_db write \
  -group <group_name> \
  -key <key> \
  -value <value>

Example:
cellframe-node-cli global_db write \
  -group dna.keys.signing \
  -key alice \
  -value "YWxpY2Utc2lnbmluZy1wdWJrZXk..."
```

### Read Operation

```bash
cellframe-node-cli global_db read \
  -group <group_name> \
  -key <key>

Example:
cellframe-node-cli global_db read \
  -group dna.keys.signing \
  -key alice

Output: YWxpY2Utc2lnbmluZy1wdWJrZXk...
```

### Delete Operation

```bash
cellframe-node-cli global_db delete \
  -group <group_name> \
  -key <key>

Example:
cellframe-node-cli global_db delete \
  -group dna.notify.alice \
  -key 1728950400_xyz789ab
```

### List Keys Operation

```bash
cellframe-node-cli global_db get_keys \
  -group <group_name>

Example:
cellframe-node-cli global_db get_keys \
  -group dna.inbox.alice

Output:
msg_1728950400_a3f2b8c1
msg_1728950401_b4c3d2e1
msg_1728950402_c5d4e3f2
```

---

## Appendix B: Error Codes

```c
// dna_gdb.h

typedef enum {
    GDB_OK = 0,                    // Success
    GDB_ERROR_CONNECT = -1,        // Cannot connect to GDB node
    GDB_ERROR_NOT_FOUND = -2,      // Key not found
    GDB_ERROR_PERMISSION = -3,     // Permission denied
    GDB_ERROR_INVALID_ARG = -4,    // Invalid argument
    GDB_ERROR_NETWORK = -5,        // Network error
    GDB_ERROR_TIMEOUT = -6,        // Operation timeout
    GDB_ERROR_CRYPTO = -7,         // Encryption/decryption failed
    GDB_ERROR_MEMORY = -8,         // Memory allocation failed
    GDB_ERROR_PARSE = -9,          // Failed to parse response
    GDB_ERROR_INTERNAL = -99       // Internal error
} gdb_error_t;
```

---

## Appendix C: Configuration

```ini
# ~/.dna/config.ini

[gdb]
# GDB connection method: cli|rest|websocket
method = cli

# CLI command path
cli_path = /usr/bin/cellframe-node-cli

# REST API endpoint (if method=rest)
rest_url = http://localhost:8089

# WebSocket endpoint (if method=websocket)
ws_url = ws://localhost:8089/ws

# Timeout in seconds
timeout = 5

# Retry attempts
retry = 3

[notification]
# Notification method: poll|watch|websocket
method = poll

# Poll interval in seconds (if method=poll)
poll_interval = 5

# WebSocket relay server (if method=websocket)
relay_url = wss://relay.dna-messenger.io

[security]
# Enable metadata encryption
encrypt_metadata = true

# Enable read receipts (reduces privacy)
read_receipts = false

# Enable typing indicators (reduces privacy)
typing_indicators = false

# Enable presence (reduces privacy)
presence = false
```

---

## Appendix D: FAQ

**Q: Why not embed metadata in the message protocol?**
A: Keeps protocol simple and allows metadata format changes without protocol version bump. Separation of concerns: crypto protocol vs application metadata.

**Q: Why reuse DEK instead of separate MEK?**
A: Simplicity, no protocol changes, same security level. Metadata needs same protection as content.

**Q: What if GDB node operators collude?**
A: They can only see recipient identities (GDB keys), not content, sender, or metadata. Use pseudonymous identities for additional privacy.

**Q: How to handle message deletion?**
A: Delete key from GDB. Tombstone: Write encrypted "deleted" flag to metadata. Cannot guarantee deletion from all replicated nodes (distributed system property).

**Q: Backward compatibility with existing messages?**
A: Yes. Existing encrypted messages work unchanged. Metadata is optional enhancement - if missing, UI shows generic placeholder.

**Q: How to scale notification polling?**
A: Use WebSocket relay server. Relay polls GDB once and pushes to many clients via WebSocket. Reduces GDB load.

**Q: Can relay server decrypt messages?**
A: No. Relay only handles encrypted blobs. DEK never leaves client. Relay is transport layer only.

**Q: What about offline messages?**
A: Messages stored in GDB persist until recipient fetches. No TTL by default (ttl=0). Can set expiring messages with ttl>0.

**Q: Multi-device synchronization?**
A: Same DEK unwrapped on each device. Metadata fetched independently per device. Device registration tracks active devices.

---

## Appendix E: Glossary

**AAD** - Additional Authenticated Data
**AEAD** - Authenticated Encryption with Associated Data
**DEK** - Data Encryption Key (32-byte AES-256 key)
**GCM** - Galois/Counter Mode (AES encryption mode)
**GDB** - Global Database (Cellframe's distributed key-value store)
**KEM** - Key Encapsulation Mechanism
**KEK** - Key Encryption Key (derived from Kyber shared secret)
**MEK** - Metadata Encryption Key
**PFS** - Perfect Forward Secrecy
**TTL** - Time To Live (message expiration)

---

**Document Version:** 1.0
**Last Updated:** 2025-10-15
**Status:** Ready for Implementation Review
**Next Steps:** Review → Approve → Implement Phase 1

---

END OF SPECIFICATION
