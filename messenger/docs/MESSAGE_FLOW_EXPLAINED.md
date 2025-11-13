# DNA Messenger - How Messages Are Sent (Step-by-Step)

**For YouTube Video: "Inside DNA Messenger - Post-Quantum Message Encryption Explained"**

---

## Overview: 3-Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    1. USER INTERFACE LAYER                  │
│              (Qt GUI - User types message)                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  2. ENCRYPTION LAYER                        │
│   (Kyber512 + AES-256-GCM + Dilithium3 Signature)         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  3. TRANSPORT LAYER                         │
│     (P2P → DHT Offline Queue → PostgreSQL Fallback)        │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎬 Scene 1: User Types Message (GUI Layer)

**Location:** `gui/MainWindow.cpp`

### What Happens:
1. User types: `"Hey Bob, dinner at 7?"`
2. User clicks "Send" button
3. GUI collects:
   - Message text (plaintext)
   - Recipient identity (`"bob"`)
   - Sender identity (`"alice"`)

**Visual:** Screen recording of typing in chat interface

---

## 🔐 Scene 2: Encryption Begins (The Magic Starts!)

**Location:** `dna_api.h` → `dna_encrypt_message_raw()`

### Step 2.1: Load Cryptographic Keys

**Keys Loaded from Disk (`~/.dna/` directory):**

| Key Type | File | Size | Purpose |
|----------|------|------|---------|
| **Sender's Dilithium3 Private Key** | `alice-dilithium.pqkey` | 4016 bytes | Sign message (proof it's from Alice) |
| **Sender's Dilithium3 Public Key** | Keyserver DB | 1952 bytes | Signature verification |
| **Recipient's Kyber512 Public Key** | Keyserver DB | 800 bytes | Encrypt message for Bob |

**Visual Suggestion:** Show file icons + key sizes on screen

---

### Step 2.2: Sign the Plaintext Message (Dilithium3)

**What:** Post-quantum digital signature proves the message is from Alice

**Algorithm:** CRYSTALS-Dilithium3 (NIST PQC Standard)

**Process:**
```
Plaintext: "Hey Bob, dinner at 7?" (19 bytes)
         ↓
     [Dilithium3 Signature Algorithm]
         ↓ (using Alice's 4016-byte private key)
Signature: 3309 bytes of quantum-safe proof
```

**Why?** Bob needs cryptographic proof the message is from Alice (not an imposter)

**Security Level:** ~128-bit quantum security (resistant to Shor's algorithm)

**Visual:** Animation of signature being "stamped" onto message

---

### Step 2.3: Generate Random Encryption Key (DEK)

**What:** Data Encryption Key - a one-time random key for this message only

**Algorithm:** OpenSSL `RAND_bytes()`

**Key Generated:**
- **Size:** 32 bytes (256 bits)
- **Purpose:** Symmetric encryption of message content
- **Lifetime:** Single-use only (destroyed after encryption)

**Example DEK (hex):**
```
7a3f9c2e8d1b5a4f6e3d9c2b8a1f5e4d3c9b8a7f6e5d4c3b2a1f9e8d7c6b5a4f
```

**Visual:** Random bytes appearing on screen with dice/randomness animation

---

### Step 2.4: Encrypt Message with AES-256-GCM

**What:** Symmetric encryption of the plaintext message

**Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Block Cipher:** AES-256
- **Mode:** GCM (provides encryption + authentication)
- **Key:** 32-byte DEK (from Step 2.3)
- **Nonce:** 12 bytes (random, unique per message)

**Encryption Process:**
```
Plaintext:  "Hey Bob, dinner at 7?" (19 bytes)
DEK:        32 bytes (random)
Nonce:      12 bytes (random)
         ↓
   [AES-256-GCM Encryption]
         ↓
Ciphertext: 19 bytes (encrypted message)
Auth Tag:   16 bytes (tamper detection)
```

**Output:**
- **Ciphertext:** `9f7e3d2c1b5a4f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f` (19 bytes)
- **Authentication Tag:** `2a1f3e5d7c9b8a4f6e3d2c1b5a4f8e7d` (16 bytes)

**Why GCM?**
- ✅ Authenticated encryption (detects tampering)
- ✅ Fast (hardware-accelerated)
- ✅ Industry standard (TLS 1.3, etc.)

**Visual:** Plaintext transforming into garbled ciphertext with lock icon

---

### Step 2.5: Wrap DEK with Kyber512 (Post-Quantum!)

**What:** Encrypt the DEK using Bob's Kyber512 public key

**Algorithm:** CRYSTALS-Kyber512 (NIST PQC Standard)

**Why?** Even if quantum computers break RSA, Kyber512 remains secure

**Process:**
```
DEK: 32 bytes (from Step 2.3)
Bob's Kyber512 Public Key: 800 bytes
         ↓
  [Kyber512 Encapsulation]
         ↓
Encapsulated Key (KEK): 768 bytes
Ciphertext: 32 bytes (encrypted DEK)
```

**Kyber512 Output:**
1. **KEK (Key Encapsulation Key):** 768 bytes
   - This is sent to Bob
   - Only Bob can decapsulate it (using his private key)

2. **Encrypted DEK:** 32 bytes
   - Wrapped inside the KEK
   - Bob will extract the DEK to decrypt the message

**Security Level:** ~128-bit quantum security (lattice-based cryptography)

**Visual:** DEK being "wrapped" in a quantum-safe envelope addressed to Bob

---

### Step 2.6: Construct Final Encrypted Message

**Format:** Binary structure with multiple components

**Message Structure (Total Size: ~4,200 bytes):**

```
┌────────────────────────────────────────────────────────────────┐
│  HEADER (Fixed Size)                                           │
│  - Magic bytes: 0x444E4120 ("DNA ")                           │
│  - Version: 1                                                  │
│  - Recipient count: 1                                          │
│  - Message flags                                               │
├────────────────────────────────────────────────────────────────┤
│  RECIPIENT ENTRY (Per recipient)                               │
│  - Recipient ID                                                │
│  - KEK (Encapsulated Kyber512 key): 768 bytes                 │
│  - Encrypted DEK: 32 bytes                                     │
├────────────────────────────────────────────────────────────────┤
│  ENCRYPTED MESSAGE                                             │
│  - Nonce: 12 bytes                                             │
│  - Ciphertext: 19 bytes (encrypted "Hey Bob, dinner at 7?")   │
│  - Auth Tag: 16 bytes (GCM tag)                                │
├────────────────────────────────────────────────────────────────┤
│  SIGNATURE (Dilithium3)                                        │
│  - Sender's public key: 1952 bytes                             │
│  - Signature: 3309 bytes                                       │
└────────────────────────────────────────────────────────────────┘

TOTAL SIZE: ~4,200 bytes (for 19-byte message!)
```

**Why So Large?** Post-quantum signatures (3309 bytes) are much bigger than ECDSA (64 bytes)

**File Reference:** `messenger_p2p.c:420-488` (encryption flow)

**Visual:** Stack animation showing layers being added one by one

---

## 🚀 Scene 3: Transport Layer (3-Tier Delivery System)

**Location:** `messenger_p2p.c` + `p2p/p2p_transport.c`

### Transport Decision Tree:

```
Encrypted Message Ready (4200 bytes)
         ↓
    Try Tier 1: Direct P2P
         ↓
  Is recipient online?
    /            \
  YES              NO
   ↓                ↓
Send via TCP    Try Tier 2: DHT Offline Queue
Port 4001            ↓
   ↓            Queue in DHT (7-day storage)
✅ SUCCESS           ↓
                Is DHT available?
                  /         \
                YES          NO
                 ↓            ↓
            ✅ QUEUED    Try Tier 3: PostgreSQL
                         ↓
                    Store in database
                         ↓
                    ✅ FALLBACK SUCCESS
```

---

### Step 3.1: Tier 1 - Direct P2P Connection (Preferred)

**Location:** `p2p/p2p_transport.c:678-777` (`p2p_send_message()`)

**Process:**

**3.1.1: Lookup Recipient in DHT**
```
Bob's Dilithium3 Public Key (1952 bytes)
         ↓
    SHA256 Hash
         ↓
DHT Key: 2c7f9a3e1d8b4f6a... (32 bytes)
         ↓
    Query OpenDHT
         ↓
Bob's Presence Info:
  - IP: 203.0.113.42
  - Port: 4001
  - Last Seen: 30 seconds ago
  - Status: ONLINE ✅
```

**DHT Bootstrap Nodes (3 global nodes):**
- `154.38.182.161:4000` (US - Virginia)
- `164.68.105.227:4000` (EU - France)
- `164.68.116.180:4000` (EU - Germany)

**Visual:** Map showing DHT lookup bouncing between bootstrap nodes

---

**3.1.2: Establish TCP Connection**
```
Alice's Computer              Bob's Computer
  (Sender)                    (Recipient)
     |                             |
     |  TCP SYN → 203.0.113.42:4001
     |─────────────────────────────>|
     |                             |
     |  <─────────────────────────  |
     |         TCP SYN-ACK          |
     |                             |
     |  TCP ACK ───────────────────>|
     |                             |
     | ✅ Connection Established    |
```

**Timeout:** 3 seconds (if no response, fallback to Tier 2)

**Visual:** Network cable connecting two computers

---

**3.1.3: Send Encrypted Message**

**Protocol:** Simple length-prefixed binary protocol

```
Message Format Over TCP:
┌──────────────────────────────────────┐
│  Length Header (4 bytes, network order) │
│  Value: 0x00001068 (4200 in hex)    │
├──────────────────────────────────────┤
│  Encrypted Message (4200 bytes)      │
│  [Full encrypted blob from Step 2.6] │
└──────────────────────────────────────┘
```

**Send Process:**
```c
// 1. Send length header (4 bytes)
uint32_t msg_len = htonl(4200);  // Convert to network byte order
send(socket, &msg_len, 4, 0);

// 2. Send message data (4200 bytes)
send(socket, encrypted_message, 4200, 0);

// 3. Wait for ACK (1 byte)
uint8_t ack;
recv(socket, &ack, 1, 0);  // Waits for 0x01 (success)
```

**File Reference:** `p2p/p2p_transport.c:738-776`

**Visual:** Progress bar showing bytes being transmitted

---

**3.1.4: Bob Receives and Acknowledges**

**Bob's Side (Listener Thread):**
```
Bob's Computer (Port 4001)
         ↓
  Receive 4 bytes (length)
         ↓
  Length = 4200 bytes
         ↓
  Receive 4200 bytes (message)
         ↓
  Store in PostgreSQL
         ↓
  Send ACK (1 byte: 0x01)
         ↓
  ✅ Alice receives ACK
         ↓
  Message Delivered Successfully!
```

**File Reference:** `p2p/p2p_transport.c:315-375` (listener thread)

**Visual:** Green checkmark appearing with "Delivered" status

---

### Step 3.2: Tier 2 - DHT Offline Queue (If Bob Offline)

**Location:** `dht/dht_offline_queue.c` + `p2p/p2p_transport.c:866-901`

**When?** Bob is offline or unreachable via TCP

**Process:**

**3.2.1: Generate DHT Queue Key**
```
Recipient: "bob"
         ↓
String: "bob:offline_queue"
         ↓
    SHA256 Hash
         ↓
Queue Key: 8f3a9d2e1c5b4a7f... (32 bytes)
```

**File Reference:** `dht/dht_offline_queue.c:32-36`

---

**3.2.2: Retrieve Existing Queue (if any)**

**DHT Query:**
```
Query OpenDHT with Key: 8f3a9d2e...
         ↓
    DHT Returns:
    - Existing queue: 2 messages (8400 bytes)
    - OR empty (no previous messages)
```

---

**3.2.3: Append New Message to Queue**

**Queue Serialization Format:**

```
┌─────────────────────────────────────────────────────────────┐
│  Message Count: 3 (4 bytes, network order)                  │
├─────────────────────────────────────────────────────────────┤
│  Message #1:                                                │
│    - Magic: 0x444E4120 ("DNA ")                            │
│    - Version: 1                                             │
│    - Timestamp: 1730800000 (8 bytes)                        │
│    - Expiry: 1731404800 (8 bytes, +7 days)                 │
│    - Sender: "alice" (2 bytes length + 5 bytes string)      │
│    - Recipient: "bob" (2 bytes length + 3 bytes string)     │
│    - Ciphertext: 4200 bytes                                 │
├─────────────────────────────────────────────────────────────┤
│  Message #2: [same format]                                  │
├─────────────────────────────────────────────────────────────┤
│  Message #3: [NEW - Alice's message]                        │
└─────────────────────────────────────────────────────────────┘

TOTAL SIZE: ~12,600 bytes (3 messages in queue)
```

**File Reference:** `dht/dht_offline_queue.c:87-184` (serialization)

**Visual:** Message being added to a queue/stack

---

**3.2.4: Store Queue Back to DHT**

```
DHT Put Operation:
  Key: 8f3a9d2e... (Bob's queue key)
  Value: 12,600 bytes (serialized queue)
  TTL: 7 days (604,800 seconds)
         ↓
  Replicated across 8+ DHT nodes
         ↓
  ✅ Message Queued Successfully!
```

**Replication:** OpenDHT stores each value on ~8 nodes for redundancy

**File Reference:** `dht/dht_offline_queue.c:323-435` (`dht_queue_message()`)

**Visual:** Message spreading across multiple server nodes

---

**3.2.5: Bob Retrieves Messages When He Comes Online**

**Automatic Polling (GUI):**
```
Bob's Messenger App
         ↓
  Every 2 minutes:
    Check DHT for queue
         ↓
  Query DHT with Key: 8f3a9d2e...
         ↓
  DHT Returns: 3 messages (12,600 bytes)
         ↓
  Download all 3 messages
         ↓
  Deliver to PostgreSQL
         ↓
  Clear queue in DHT
         ↓
  ✅ Messages appear in Bob's chat!
```

**File Reference:** `gui/MainWindow.cpp` (2-minute timer) + `p2p/p2p_transport.c:779-864`

**Visual:** Timer ticking, then messages "popping" into inbox

---

### Step 3.3: Tier 3 - PostgreSQL Fallback (Ultimate Reliability)

**Location:** `messenger_p2p.c:420-488`

**When?**
- P2P connection fails (network issues)
- DHT storage fails (node unavailable)
- Last resort fallback

**Process:**

**3.3.1: Store in PostgreSQL Database**

**Database Schema:**
```sql
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender TEXT NOT NULL,          -- "alice"
    recipient TEXT NOT NULL,       -- "bob"
    ciphertext BYTEA NOT NULL,     -- 4200 bytes (encrypted message)
    ciphertext_len INTEGER,        -- 4200
    timestamp TIMESTAMP DEFAULT NOW(),
    message_group_id TEXT          -- For group chats
);
```

**Insert Operation:**
```sql
INSERT INTO messages
  (sender, recipient, ciphertext, ciphertext_len)
VALUES
  ('alice', 'bob', <4200 bytes>, 4200);
```

**Database Location:** `ai.cpunk.io:5432` (PostgreSQL server)

**File Reference:** `messenger_p2p.c:549-584` (receive callback)

**Visual:** Database icon with "Backup Storage" label

---

**3.3.2: Bob Polls PostgreSQL**

**Query (Bob checks for new messages):**
```sql
SELECT sender, ciphertext, ciphertext_len
FROM messages
WHERE recipient = 'bob'
  AND id > <last_seen_id>
ORDER BY timestamp ASC;
```

**Polling Frequency:** Every 5 seconds (configurable)

**Visual:** Database query results appearing in inbox

---

## 🔓 Scene 4: Bob Decrypts the Message

**Location:** `dna_api.h` → `dna_decrypt_message_raw()`

### Step 4.1: Load Bob's Private Keys

**Keys Loaded:**
- **Kyber512 Private Key:** `bob-kyber512.pqkey` (2400 bytes)
- **Dilithium3 Public Key (Alice):** From keyserver (1952 bytes)

---

### Step 4.2: Parse Encrypted Message

**Extract Components:**
```
Encrypted Message (4200 bytes)
         ↓
    Parse Header
         ↓
Extract:
  - Recipient Entry → KEK (768 bytes)
  - Nonce (12 bytes)
  - Ciphertext (19 bytes)
  - Auth Tag (16 bytes)
  - Signature (3309 bytes)
  - Alice's Public Key (1952 bytes)
```

---

### Step 4.3: Unwrap DEK with Kyber512

**Decapsulation:**
```
KEK: 768 bytes (from message)
Bob's Kyber512 Private Key: 2400 bytes
         ↓
  [Kyber512 Decapsulation]
         ↓
DEK: 32 bytes (recovered!)
```

**This is the same DEK Alice generated in Step 2.3!**

---

### Step 4.4: Decrypt with AES-256-GCM

**Decryption:**
```
Ciphertext: 19 bytes
DEK: 32 bytes (from Step 4.3)
Nonce: 12 bytes
Auth Tag: 16 bytes
         ↓
   [AES-256-GCM Decryption]
         ↓
Plaintext: "Hey Bob, dinner at 7?" ✅
```

**Authentication Check:** GCM verifies auth tag (detects tampering)

---

### Step 4.5: Verify Dilithium3 Signature

**Verification:**
```
Plaintext: "Hey Bob, dinner at 7?"
Signature: 3309 bytes
Alice's Public Key: 1952 bytes
         ↓
  [Dilithium3 Verification]
         ↓
Result: ✅ VALID (message is from Alice)
```

**If signature invalid:** Message rejected (imposter detected)

---

### Step 4.6: Display Message in GUI

**Bob's Screen:**
```
┌─────────────────────────────────────┐
│  Chat with Alice                    │
├─────────────────────────────────────┤
│  Alice                  10:45 AM    │
│  Hey Bob, dinner at 7? ✅           │
│                                     │
│  [Type a message...]                │
└─────────────────────────────────────┘
```

**Mission Accomplished!** 🎉

---

## 📊 Summary Table: Message Journey

| Step | Layer | What Happens | Size | Time |
|------|-------|--------------|------|------|
| 1 | GUI | User types message | 19 bytes | Instant |
| 2.1 | Crypto | Load keys | 6768 bytes | <1ms |
| 2.2 | Crypto | Sign (Dilithium3) | +3309 bytes | ~2ms |
| 2.3 | Crypto | Generate DEK | +32 bytes | <1ms |
| 2.4 | Crypto | Encrypt (AES-256-GCM) | +47 bytes | <1ms |
| 2.5 | Crypto | Wrap DEK (Kyber512) | +800 bytes | ~1ms |
| 2.6 | Crypto | Construct message | 4200 bytes total | <1ms |
| 3.1 | P2P | DHT lookup | - | 50-200ms |
| 3.2 | P2P | TCP send | 4204 bytes | 10-50ms |
| 3.3 | P2P | ACK received | 1 byte | 10-50ms |
| 4 | Decrypt | Bob decrypts | 19 bytes | ~5ms |

**Total Time (P2P):** ~100-300ms (sub-second delivery!)

**Total Time (DHT Queue):** 0-2 minutes (polling interval)

**Total Time (PostgreSQL):** 0-5 seconds (polling interval)

---

## 🔐 Security Properties

### Post-Quantum Security:
✅ **Kyber512:** Lattice-based KEM (NIST PQC standard)
✅ **Dilithium3:** Module-LWE signatures (NIST PQC standard)
✅ **AES-256-GCM:** Quantum-resistant symmetric encryption

### End-to-End Encryption:
✅ Message encrypted on Alice's device
✅ Only Bob can decrypt (with his private key)
✅ Server/DHT/PostgreSQL cannot read message content

### Authentication:
✅ Dilithium3 signature proves message from Alice
✅ GCM auth tag prevents tampering
✅ No man-in-the-middle attacks

### Forward Secrecy:
⚠️ **Not yet implemented** (Phase 7 - planned)
⚠️ Current: If private key compromised, past messages readable

---

## 🎥 Video Script Outline

### Act 1: The Problem (0:00-1:00)
- "What happens when you send a message?"
- Most apps: encrypt, send to server, server reads it
- Show WhatsApp/Signal server architecture
- "But what if quantum computers break encryption?"

### Act 2: DNA Messenger Architecture (1:00-2:00)
- Show 3-layer architecture
- Explain post-quantum cryptography
- Compare key sizes (ECDSA vs Dilithium3)

### Act 3: Encryption Deep Dive (2:00-6:00)
- Walk through Steps 2.1-2.6
- Visualize each crypto operation
- Show actual byte sizes

### Act 4: Transport Layer (6:00-9:00)
- Explain P2P → DHT → PostgreSQL tiers
- Show network visualization
- Demo offline message queueing

### Act 5: Decryption (9:00-11:00)
- Bob's side of the story
- Show reverse crypto operations
- Message appears in chat

### Act 6: Security Analysis (11:00-13:00)
- Explain quantum resistance
- Show threat model
- Compare to other messengers

### Outro (13:00-14:00)
- Open source, try it yourself
- Link to GitLab repo
- Call to action

---

## 📚 File References

| Component | File | Lines |
|-----------|------|-------|
| GUI Send | `gui/MainWindow.cpp` | 200-250 |
| Encryption API | `dna_api.h` | 137-170 |
| P2P Send | `messenger_p2p.c` | 420-488 |
| P2P Transport | `p2p/p2p_transport.c` | 678-777 |
| DHT Queue | `dht/dht_offline_queue.c` | 323-435 |
| Decryption API | `dna_api.h` | 198-231 |

---

## 🔗 External Resources

- **CRYSTALS-Kyber:** https://pq-crystals.org/kyber/
- **CRYSTALS-Dilithium:** https://pq-crystals.org/dilithium/
- **NIST PQC Standards:** https://csrc.nist.gov/projects/post-quantum-cryptography
- **OpenDHT:** https://github.com/savoirfairelinux/opendht
- **DNA Messenger Repo:** https://gitlab.cpunk.io/cpunk/dna-messenger

---

**Document Version:** 1.0
**Last Updated:** 2025-11-03
**Author:** Claude AI (with DNA Messenger codebase analysis)

