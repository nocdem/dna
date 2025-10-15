# Phase 4: Network Layer - Hypercore Protocol Architecture

**Status:** 📋 Planned
**Timeline:** 4-6 weeks
**Version:** 0.4.0

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Technology Stack](#technology-stack)
4. [Data Model](#data-model)
5. [Implementation Plan](#implementation-plan)
6. [API Specification](#api-specification)
7. [Migration Strategy](#migration-strategy)
8. [Security Considerations](#security-considerations)
9. [Deployment](#deployment)

---

## Overview

Phase 4 transforms DNA Messenger from a **centralized PostgreSQL architecture** to a **fully peer-to-peer (P2P) system** using the Hypercore Protocol stack. This eliminates the need for centralized servers while maintaining post-quantum end-to-end encryption.

### Goals

- ✅ **True P2P**: Direct peer-to-peer messaging without relay servers
- ✅ **Offline-First**: Messages sync automatically when peers reconnect
- ✅ **Distributed Keyserver**: No central authority for public keys
- ✅ **NAT Traversal**: Works behind firewalls and home routers
- ✅ **Immutable Message Log**: Append-only, cryptographically signed
- ✅ **Efficient Replication**: Sparse sync, only download what you need

### What Changes

| Component | Before (Phase 3) | After (Phase 4) |
|-----------|------------------|-----------------|
| **Message Storage** | Centralized PostgreSQL | Hyperbee (distributed B-tree) |
| **Keyserver** | PostgreSQL table at ai.cpunk.io | Distributed Hyperbee replicas |
| **Networking** | None (manual message insertion) | Hyperswarm P2P with NAT traversal |
| **Replication** | N/A | Hypercore append-only log |
| **Discovery** | DNS/IP addresses | DHT-based topic discovery |
| **Message Delivery** | Pull from server | Real-time push via replication |

---

## Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    DNA Messenger (C/C++)                     │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │
│  │    GUI     │  │    CLI     │  │  Post-Quantum Crypto │  │
│  │  (Qt5)     │  │            │  │  (Kyber + Dilithium) │  │
│  └─────┬──────┘  └─────┬──────┘  └──────────┬───────────┘  │
│        │               │                     │               │
│        └───────────────┴─────────────────────┘               │
│                        │                                     │
│                 ┌──────▼───────┐                             │
│                 │  messenger.c │                             │
│                 │  (IPC Client)│                             │
│                 └──────┬───────┘                             │
└────────────────────────┼─────────────────────────────────────┘
                         │ Unix Socket / Named Pipe
                         │ (JSON IPC Protocol)
┌────────────────────────▼─────────────────────────────────────┐
│              Node.js P2P Bridge Daemon                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Hyperswarm  │  │  Corestore   │  │   Hyperbee      │  │
│  │  (P2P DHT)   │  │  (Core Mgmt) │  │   (K/V Store)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────────┘  │
│         │                 │                  │               │
│         └─────────────────┴──────────────────┘               │
│                           │                                  │
│                    ┌──────▼───────┐                          │
│                    │   Hypercore  │                          │
│                    │ (Append-only │                          │
│                    │  signed log) │                          │
│                    └──────────────┘                          │
└──────────────────────────────────────────────────────────────┘
                           │
                           │ Hypercore Replication Protocol
                           │ (Noise encrypted, Merkle verified)
                           │
            ┌──────────────┴──────────────┐
            │                             │
    ┌───────▼────────┐            ┌──────▼───────┐
    │  Peer A Device │            │ Peer B Device│
    │  (Alice)       │◄──────────►│ (Bob)        │
    └────────────────┘            └──────────────┘
         P2P Network (Hyperswarm DHT)
```

### Core Concepts

#### 1. OUTBOX/INBOX Replication Pattern

Every user maintains their own **Hyperbee** (append-only B-tree database) as their OUTBOX. Contacts replicate this Hyperbee to read incoming messages.

**Example: Alice → Bob messaging**

```
Alice's Device:
├── Alice's Hyperbee (OUTBOX)      ← Alice writes here (single writer)
│   └── Messages Alice sent to: Bob, Charlie, etc.
├── Bob's Hyperbee (replicated)     ← Alice reads Bob's messages (INBOX from Bob)
└── Charlie's Hyperbee (replicated) ← Alice reads Charlie's messages (INBOX from Charlie)

Bob's Device:
├── Bob's Hyperbee (OUTBOX)        ← Bob writes here (single writer)
│   └── Messages Bob sent to: Alice, Charlie, etc.
├── Alice's Hyperbee (replicated)   ← Bob reads Alice's messages (INBOX from Alice)
└── Charlie's Hyperbee (replicated) ← Bob reads Charlie's messages (INBOX from Charlie)
```

**Key Properties:**
- ✅ Each user is the **single writer** of their own Hyperbee (owns private key)
- ✅ Contacts are **multi-readers** who replicate the user's Hyperbee
- ✅ Append-only: Messages cannot be deleted or modified (immutable)
- ✅ Cryptographically signed: Hypercore signs all blocks with user's Hypercore key
- ✅ Efficient: Sparse replication downloads only new messages

#### 2. Distributed Keyserver

The keyserver (public key directory) is also a Hyperbee replicated by all users.

**Keyserver Hyperbee:**
- Managed by trusted maintainer(s) initially (single writer)
- Contains: `{identity → {dilithium_pubkey, kyber_pubkey, hypercore_key}}`
- All users replicate the keyserver Hyperbee to discover contacts
- Future: Multi-writer keyserver using CRDTs (multi-hyperbee)

#### 3. Peer Discovery with Hyperswarm

**Hyperswarm** is a DHT (Distributed Hash Table) for peer discovery:

- Users join "topics" (derived from Hypercore discovery keys)
- Topics are derived from public keys (safe to share publicly)
- Hyperswarm finds peers interested in the same topics
- Built-in NAT traversal (UDP hole-punching)
- Noise protocol encrypts transport layer

**Discovery Flow:**
1. Alice wants to message Bob
2. Alice fetches Bob's `hypercore_key` from keyserver Hyperbee
3. Alice derives Bob's `discovery_key` from `hypercore_key`
4. Alice joins Hyperswarm topic: `swarm.join(bob_discovery_key)`
5. Hyperswarm connects Alice to Bob's device
6. Alice replicates Bob's Hyperbee to read messages

---

## Technology Stack

### Core Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **P2P Networking** | Hyperswarm | Peer discovery, NAT traversal, DHT |
| **Append-Only Log** | Hypercore | Signed, immutable message log |
| **Database** | Hyperbee | B-tree key-value store on Hypercore |
| **Core Management** | Corestore | Manages multiple Hypercores per user |
| **Bridge Runtime** | Node.js v18+ | Runs Hypercore Protocol stack |
| **IPC** | Unix Socket / Named Pipes | C/C++ ↔ Node.js communication |
| **Encryption** | Noise Protocol | Transport layer (Hypercore native) |
| **Post-Quantum E2E** | Kyber512 + Dilithium3 | Message encryption (DNA Messenger) |

### Why Node.js?

Hypercore Protocol is **JavaScript-native** with no official C/C++ bindings. Options:

1. ✅ **Node.js Bridge** (chosen): Run Node.js daemon, IPC to C/C++
2. ❌ **N-API Bindings**: Create C++ wrappers (massive maintenance burden)
3. ❌ **Rewrite in Rust/Go**: Start from scratch (no Hypercore ecosystem)

**Node.js Bridge Benefits:**
- Leverage mature Hypercore Protocol ecosystem
- Clean separation: C/C++ for crypto/GUI, Node.js for networking
- Easy updates (npm package updates)
- Can embed Node.js runtime in installers (like Electron apps)

---

## Data Model

### Hyperbee Schema

#### User's OUTBOX Hyperbee

```
Key Format: "msg/{timestamp}_{messageId}"
Value: {
  "id": "uuid-v4",
  "recipients": ["bob", "charlie"],
  "encrypted_payload": "base64(...)",  // Post-quantum encrypted message
  "signature": "base64(...)",          // Dilithium3 signature
  "created_at": "2025-10-15T12:34:56Z",
  "nonce": "random_bytes"
}

Example:
msg/1729000000000_a1b2c3d4-... → { id: ..., recipients: ["bob"], ... }
```

**Key Design:**
- `timestamp` ensures chronological ordering
- `messageId` ensures uniqueness
- Hyperbee automatically sorts keys lexicographically
- Range queries: `db.createReadStream({ gt: 'msg/1729000000000' })`

#### Keyserver Hyperbee (Distributed)

```
Key Format: "user/{identity}"
Value: {
  "identity": "alice",
  "dilithium_pubkey": "base64(...)",
  "kyber_pubkey": "base64(...)",
  "hypercore_key": "hex(...)",         // 64-char hex public key
  "discovery_key": "hex(...)",         // Derived from hypercore_key
  "created_at": "2025-10-15T12:34:56Z",
  "updated_at": "2025-10-15T12:34:56Z"
}

Example:
user/alice → { identity: "alice", dilithium_pubkey: "...", hypercore_key: "abc123...", ... }
```

**Access Pattern:**
- Read: `db.get('user/alice')` → Get Alice's public keys
- List: `db.createReadStream({ gte: 'user/', lt: 'user/~' })` → All users
- Write: Only keyserver maintainer can write (single writer)

---

## Implementation Plan

### Week 1-2: Node.js P2P Bridge

**Goal:** Build Node.js daemon that manages Hypercore Protocol

#### Tasks:
1. **Setup Project**
   ```bash
   mkdir dna-p2p-bridge
   cd dna-p2p-bridge
   npm init -y
   npm install hyperswarm hypercore hyperbee corestore
   ```

2. **Implement Core Features**
   - Initialize Corestore (manages multiple Hypercores)
   - Create user's OUTBOX Hyperbee
   - Replicate contact Hyperbees (INBOX)
   - Join Hyperswarm topics for peer discovery

3. **IPC Server**
   - Unix socket server (Linux): `/tmp/dna-bridge.sock`
   - Named pipe server (Windows): `\\.\pipe\dna-bridge`
   - JSON protocol for commands:
     - `INIT`: Initialize user's Hypercore
     - `SEND_MESSAGE`: Write to OUTBOX
     - `GET_MESSAGES`: Read from contact's INBOX
     - `SUBSCRIBE_CONTACT`: Start replicating contact
     - `GET_KEYSERVER`: Fetch from keyserver Hyperbee

4. **Message Handling**
   ```javascript
   // Write to OUTBOX
   await userBee.put(`msg/${Date.now()}_${msgId}`, {
     id: msgId,
     recipients: ['bob', 'charlie'],
     encrypted_payload: base64_msg,
     signature: base64_sig,
     created_at: new Date().toISOString()
   })

   // Read from contact's INBOX
   const entries = await contactBee.createReadStream({
     gte: 'msg/1729000000000',
     limit: 50
   })
   ```

### Week 2: C/C++ IPC Client

**Goal:** Connect DNA Messenger to P2P bridge

#### Files to Create:
- `network/hypercore_bridge.h` - API header
- `network/hypercore_bridge.c` - IPC implementation
- `network/json_utils.c` - JSON encoding/decoding

#### API:
```c
// Initialize bridge connection
int hypercore_bridge_init(const char *socket_path);

// Send message (writes to OUTBOX)
int hypercore_bridge_send_message(
    const char **recipients,
    size_t recipient_count,
    const uint8_t *encrypted_msg,
    size_t msg_len,
    const uint8_t *signature,
    size_t sig_len
);

// Subscribe to contact's Hypercore
int hypercore_bridge_subscribe_contact(
    const char *contact_identity,
    const char *hypercore_key
);

// Poll for new messages
int hypercore_bridge_poll_messages(
    const char *contact_identity,
    message_callback_t callback,
    void *user_data
);

// Get contact info from keyserver
int hypercore_bridge_get_contact(
    const char *identity,
    contact_info_t *out
);
```

### Week 3: Keyserver Migration

**Goal:** Move keyserver to distributed Hyperbee

#### Approach:
1. **Create Keyserver Hyperbee**
   - Maintained by DNA Messenger project initially
   - Contains all user public keys
   - Replicated by all users

2. **Migration Tool**
   ```bash
   ./migrate_keyserver_to_hyperbee.js
   ```
   - Reads from PostgreSQL `keyserver` table
   - Generates Hypercore keys for each user (deterministically)
   - Writes to keyserver Hyperbee

3. **Client Integration**
   - Users replicate keyserver Hyperbee on first run
   - Lookup contacts: `keyserverBee.get('user/alice')`
   - Periodic sync: Pull latest keyserver updates

### Week 4: Integration & Testing

**Goal:** Replace PostgreSQL message queries with Hyperbee

#### Updates to `messenger.c`:
```c
// OLD (PostgreSQL):
int messenger_send_message(messenger_context_t *ctx,
                           const char **recipients,
                           size_t recipient_count,
                           const char *message) {
    // Encrypt message
    // INSERT INTO messages (sender, recipient, ciphertext) VALUES (...)
}

// NEW (Hyperbee via bridge):
int messenger_send_message(messenger_context_t *ctx,
                           const char **recipients,
                           size_t recipient_count,
                           const char *message) {
    // Encrypt message
    // hypercore_bridge_send_message(recipients, encrypted_msg, signature)
}
```

#### Background Sync Thread:
```c
void* hypercore_sync_thread(void *arg) {
    while (running) {
        // Poll all subscribed contacts for new messages
        for (contact in contacts) {
            hypercore_bridge_poll_messages(contact->identity, on_new_message, ctx);
        }
        sleep(1); // Check every second
    }
}
```

---

## API Specification

### IPC Protocol (JSON over Unix Socket)

#### Request Format:
```json
{
  "id": "request-uuid",
  "command": "SEND_MESSAGE",
  "params": {
    "recipients": ["bob", "charlie"],
    "encrypted_payload": "base64...",
    "signature": "base64..."
  }
}
```

#### Response Format:
```json
{
  "id": "request-uuid",
  "status": "success",
  "result": {
    "message_id": "uuid",
    "timestamp": 1729000000000
  }
}
```

### Commands

#### 1. INIT
Initialize user's Hypercore and keyserver replication.

**Request:**
```json
{
  "command": "INIT",
  "params": {
    "identity": "alice",
    "hypercore_key": "optional-existing-key"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "result": {
    "hypercore_key": "abc123...",
    "discovery_key": "def456..."
  }
}
```

#### 2. SEND_MESSAGE
Write message to user's OUTBOX Hyperbee.

**Request:**
```json
{
  "command": "SEND_MESSAGE",
  "params": {
    "recipients": ["bob"],
    "encrypted_payload": "base64...",
    "signature": "base64..."
  }
}
```

**Response:**
```json
{
  "status": "success",
  "result": {
    "message_id": "uuid",
    "timestamp": 1729000000000
  }
}
```

#### 3. SUBSCRIBE_CONTACT
Start replicating a contact's Hyperbee.

**Request:**
```json
{
  "command": "SUBSCRIBE_CONTACT",
  "params": {
    "identity": "bob",
    "hypercore_key": "bob_hypercore_key_hex"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "result": {
    "syncing": true,
    "peer_count": 2
  }
}
```

#### 4. GET_MESSAGES
Fetch messages from contact's replicated Hyperbee.

**Request:**
```json
{
  "command": "GET_MESSAGES",
  "params": {
    "contact": "bob",
    "since_timestamp": 1729000000000,
    "limit": 50
  }
}
```

**Response:**
```json
{
  "status": "success",
  "result": {
    "messages": [
      {
        "id": "uuid",
        "recipients": ["alice"],
        "encrypted_payload": "base64...",
        "signature": "base64...",
        "created_at": "2025-10-15T12:34:56Z"
      }
    ]
  }
}
```

#### 5. GET_CONTACT
Fetch contact info from keyserver Hyperbee.

**Request:**
```json
{
  "command": "GET_CONTACT",
  "params": {
    "identity": "bob"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "result": {
    "identity": "bob",
    "dilithium_pubkey": "base64...",
    "kyber_pubkey": "base64...",
    "hypercore_key": "hex..."
  }
}
```

---

## Migration Strategy

### Option 1: Parallel Operation (Recommended)

**Timeline:** Gradual migration over 2-3 releases

1. **v0.4.0**: Ship with both PostgreSQL and Hypercore
   - Users opt-in to Hypercore via Settings
   - PostgreSQL remains default
   - Bridge daemon optional

2. **v0.5.0**: Switch default to Hypercore
   - PostgreSQL used as local cache/index
   - Migration tool: Export PostgreSQL → Hyperbee

3. **v0.6.0**: PostgreSQL optional/deprecated
   - Full Hypercore by default
   - PostgreSQL support removed in future versions

### Option 2: Clean Break (Faster but disruptive)

1. **v0.4.0**: Hypercore-only release
2. Provide migration tool
3. No backward compatibility

### Migration Tool

```bash
./tools/migrate_to_hypercore.sh

# Steps:
1. Export messages from PostgreSQL to JSON
2. Generate user's Hypercore if not exists
3. Bulk insert messages to Hyperbee OUTBOX
4. Replicate contacts' Hypercores
5. Verify message integrity
```

---

## Security Considerations

### Threat Model

#### What Hypercore Protocol Provides:
- ✅ **Transport Encryption**: Noise protocol (ephemeral keys)
- ✅ **Data Integrity**: Merkle tree verification
- ✅ **Authenticity**: Hypercore signs all blocks
- ✅ **Immutability**: Append-only, tamper-evident

#### What DNA Messenger Provides (On Top):
- ✅ **End-to-End Encryption**: Kyber512 + Dilithium3 (post-quantum)
- ✅ **Message Signatures**: Dilithium3 signatures in payload
- ✅ **Forward Secrecy**: Ephemeral session keys (future)

#### Attack Scenarios:

**1. MITM Attack on Hypercore Replication**
- **Risk**: Attacker intercepts Hypercore replication
- **Mitigation**: Noise protocol encrypts transport
- **Additional**: Verify Hypercore public key matches keyserver

**2. Malicious Peer Serves Fake Messages**
- **Risk**: Attacker creates fake Hyperbee claiming to be Alice
- **Mitigation**: Hypercore public key verified via keyserver
- **Additional**: Messages signed with Dilithium3 (checked at application layer)

**3. Sybil Attack on DHT**
- **Risk**: Attacker floods DHT with fake peers
- **Mitigation**: Hyperswarm's DHT is resilient to Sybil attacks
- **Additional**: Verify peer's Hypercore key before accepting data

**4. Replay Attack**
- **Risk**: Attacker replays old messages
- **Mitigation**: Timestamps checked, nonces prevent duplicates
- **Additional**: Client tracks latest seen message ID

**5. Keyserver Compromise**
- **Risk**: Attacker controls keyserver, serves fake public keys
- **Mitigation**: Multi-signature keyserver (future)
- **Additional**: Key fingerprint verification (QR codes)

### Best Practices

1. **Verify Hypercore Keys**: Always cross-reference with keyserver
2. **Check Signatures**: Verify Dilithium3 signatures on decryption
3. **Audit Logs**: Hypercore's append-only log is auditable
4. **Pin Keys**: Store trusted contact keys locally (TOFU - Trust On First Use)
5. **Monitor Replication**: Alert if Hypercore changes unexpectedly

---

## Deployment

### Requirements

**Server Side:**
- None! (Fully P2P)

**Client Side:**
- Node.js v18+ runtime (bundled with installer)
- ~50MB disk space for Node.js + dependencies
- ~10-100MB per contact for replicated Hyperbees (depends on message history)

### Installation

#### Linux:
```bash
# Install DNA Messenger
wget https://github.com/nocdem/dna-messenger/releases/latest/dna-messenger-linux.tar.gz
tar -xzf dna-messenger-linux.tar.gz
cd dna-messenger

# Node.js runtime bundled, no separate install needed
./dna_messenger_gui
```

#### Windows:
```bash
# Download installer
dna-messenger-setup.exe

# Installer includes:
- DNA Messenger GUI/CLI
- Node.js runtime (embedded)
- P2P bridge auto-starts with app
```

### Service Management

#### Linux (systemd):
```bash
# Auto-start P2P bridge on boot
sudo systemctl enable dna-p2p-bridge
sudo systemctl start dna-p2p-bridge
```

#### Windows:
```bash
# Bridge runs as background process
# Managed by DNA Messenger GUI
```

### Firewall Configuration

**Required Ports:**
- None! Hyperswarm uses UDP hole-punching
- Works behind NAT/firewalls without port forwarding

**Optional (for better connectivity):**
- UDP port range 49152-65535 (ephemeral ports)
- Allow in firewall for faster peer discovery

---

## FAQ

### Q: Why not just use libp2p?
**A:** Hypercore Protocol is more mature for append-only data structures. Hyperbee is specifically designed for key-value replication. libp2p would require building equivalent abstractions.

### Q: What if Node.js is not installed?
**A:** We bundle Node.js runtime with the installer (like Electron apps). Users don't need to install separately.

### Q: How much bandwidth does replication use?
**A:** Sparse replication is very efficient. Only new messages are downloaded. Typical: <1KB per message. Bulk sync: ~1MB per 1000 messages.

### Q: Can messages be deleted?
**A:** No. Hyperbee is append-only. Messages cannot be deleted from the log. Clients can hide messages locally, but they remain in the Hypercore.

### Q: What about groups?
**A:** Groups are supported via the creator's Hyperbee. All members replicate the creator's Hyperbee. For collaborative groups, we'll use multi-hyperbee with CRDTs (Phase 7).

### Q: How do I backup messages?
**A:** Export Hypercore storage directory (~/.hypercore). Contains all your messages and replicated contacts. Restore by copying back.

### Q: What if a peer is offline?
**A:** Messages queue locally. When the peer comes online, Hyperswarm reconnects and Hyperbee syncs automatically.

---

## Next Steps

1. ✅ Update ROADMAP.md with Hypercore Protocol tasks
2. ✅ Create `dna-p2p-bridge/` directory
3. ✅ Initialize Node.js project
4. Implement basic Hyperbee CRUD operations
5. Build Unix socket IPC server
6. Test C → Node.js → Hyperbee → back to C
7. Migrate keyserver to Hyperbee
8. Integration testing with GUI

---

**Document Version:** 1.0
**Last Updated:** 2025-10-15
**Author:** DNA Messenger Development Team
**License:** GNU GPL v3.0
