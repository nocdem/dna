# P2P Transport Layer Design

**Component:** Network Transport & Peer Discovery
**Status:** Research & Planning Phase
**Dependencies:** None (new subsystem)

---

## OVERVIEW

The P2P transport layer enables direct peer-to-peer communication without central relay servers. It consists of three main components:

1. **Peer Discovery** - Find peers by identity (DHT)
2. **NAT Traversal** - Connect through firewalls/NAT (ICE/STUN)
3. **Message Transport** - Send encrypted messages directly

---

## ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                    P2P Transport Stack                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │         Application Layer (DNA Messenger)             │  │
│  └─────────────────┬─────────────────────────────────────┘  │
│                    │                                          │
│  ┌─────────────────▼─────────────────────────────────────┐  │
│  │         Message Transport (P2P Protocol)              │  │
│  │  - Send/Receive encrypted messages                    │  │
│  │  - Connection management                              │  │
│  │  - Multiplexing (multiple streams)                    │  │
│  └─────────────────┬─────────────────────────────────────┘  │
│                    │                                          │
│  ┌─────────────────▼─────────────────────────────────────┐  │
│  │         NAT Traversal (ICE/STUN/TURN)                 │  │
│  │  - UDP hole punching                                  │  │
│  │  - STUN server queries                                │  │
│  │  - TURN relay fallback                                │  │
│  └─────────────────┬─────────────────────────────────────┘  │
│                    │                                          │
│  ┌─────────────────▼─────────────────────────────────────┐  │
│  │         Peer Discovery (Kademlia DHT)                 │  │
│  │  - Find peer IP:port by identity                      │  │
│  │  - Bootstrap node discovery                           │  │
│  │  - Periodic peer refresh                              │  │
│  └─────────────────┬─────────────────────────────────────┘  │
│                    │                                          │
│  ┌─────────────────▼─────────────────────────────────────┐  │
│  │         Network Layer (UDP/TCP Sockets)               │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## COMPONENT 1: PEER DISCOVERY (KADEMLIA DHT)

### Purpose

Find a peer's current IP address and port by their identity (username).

### How It Works

```
Query: "WHERE IS bob?"
         ↓
DHT Lookup: SHA256("bob") → 0x7a3f... (160-bit key)
         ↓
Kademlia Routing: Find node responsible for 0x7a3f...
         ↓
Response: bob is at 192.168.1.100:4567 (last seen 5 seconds ago)
```

### Kademlia DHT Overview

**Key Properties:**
- 160-bit keyspace (SHA-1 or SHA-256)
- XOR distance metric
- k-buckets for routing (k=20 typical)
- O(log N) lookup complexity

**Node ID:** Each peer gets a random 160-bit ID
**Key:** Identity mapped to keyspace via hash: SHA256("bob") → DHT key

### DHT Entry Format

```c
typedef struct {
    char identity[256];        // "bob"
    uint8_t node_id[20];       // 160-bit Kademlia node ID
    char ip_address[46];       // IPv4 or IPv6
    uint16_t port;             // UDP/TCP port
    uint64_t last_seen;        // Unix timestamp
    uint8_t pubkey[1952];      // Dilithium3 public key (for verification)
    uint8_t signature[3309];   // Self-signed (proves ownership of identity)
} dht_peer_entry_t;
```

### DHT Operations

**STORE (Announce Presence):**
```c
// Called when peer comes online
int dht_announce(dht_context_t *ctx, const char *identity,
                 const char *ip, uint16_t port);

// Example:
dht_announce(ctx, "bob", "192.168.1.100", 4567);
// Stores bob → 192.168.1.100:4567 in DHT
```

**FIND (Locate Peer):**
```c
// Query DHT for peer's location
int dht_find_peer(dht_context_t *ctx, const char *identity,
                  char *ip_out, uint16_t *port_out);

// Example:
char ip[46];
uint16_t port;
if (dht_find_peer(ctx, "bob", ip, &port) == 0) {
    // Found: bob is at ip:port
} else {
    // Not found: bob is offline
}
```

**REFRESH (Periodic Update):**
```c
// Called every 5 minutes to keep DHT entry alive
int dht_refresh(dht_context_t *ctx);
```

### Technology Options

| Library | Language | Pros | Cons |
|---------|----------|------|------|
| **libp2p Kad-DHT** | C++ | Complete P2P stack, battle-tested | C++ dependency |
| **OpenDHT** | C++ | Used by Jami messenger, proven | C++ dependency |
| **BitTorrent DHT** | C | Lightweight, millions of nodes | Limited features |
| **Custom Implementation** | C | Full control, minimal deps | Development effort |

**Recommendation:** OpenDHT (production-ready for messaging) or libp2p (if using full stack)

### Bootstrap Nodes

**Purpose:** How to join DHT network when starting with zero peers?

**Solution:** Hardcoded list of well-known bootstrap nodes

```c
const char *BOOTSTRAP_NODES[] = {
    "bootstrap1.dna-messenger.io:4567",
    "bootstrap2.dna-messenger.io:4567",
    "bootstrap3.dna-messenger.io:4567",
    NULL
};

// On startup:
dht_bootstrap(ctx, BOOTSTRAP_NODES);
```

**Bootstrap Node Requirements:**
- Always online (99%+ uptime)
- Public IP address
- Standard DHT node (participates in routing)
- Does NOT store messages (only helps with discovery)

---

## COMPONENT 2: NAT TRAVERSAL

### Problem

Most users are behind NAT (Network Address Translation) or firewalls:
- Home routers use NAT
- Corporate firewalls block incoming connections
- Mobile networks use carrier-grade NAT

**Result:** Direct connection often impossible without NAT traversal

### Solution: ICE (Interactive Connectivity Establishment)

ICE combines multiple techniques:
1. **Direct connection** (if both have public IPs)
2. **STUN** (Session Traversal Utilities for NAT) - UDP hole punching
3. **TURN** (Traversal Using Relays around NAT) - Relay fallback

### NAT Traversal Process

```
Step 1: Gather Candidates
Peer A queries STUN server:
  - Local IP: 192.168.1.100:5000
  - Public IP: 203.0.113.5:60001 (reflexive address)

Peer B queries STUN server:
  - Local IP: 10.0.0.50:5001
  - Public IP: 198.51.100.10:60002

Step 2: Exchange Candidates (via DHT)
A sends to DHT: "My candidates: 192.168.1.100:5000, 203.0.113.5:60001"
B retrieves from DHT

Step 3: Connectivity Checks
A tries to connect to B's candidates:
  - 10.0.0.50:5001 (fails - not on same LAN)
  - 198.51.100.10:60002 (succeeds - UDP hole punching works!)

Step 4: Establish Connection
A ↔ 198.51.100.10:60002 ↔ NAT ↔ B
```

### STUN Server Role

**Purpose:** Discover your public IP:port as seen by the internet

**Protocol:**
```
Client → STUN Server: "What's my public IP?"
STUN Server → Client: "You appear as 203.0.113.5:60001"
```

**Public STUN Servers (Free):**
- `stun.l.google.com:19302`
- `stun.cloudflare.com:3478`
- `stun.ekiga.net:3478`

**Important:** STUN servers do NOT relay messages, only help with discovery

### TURN Server (Fallback)

**When Needed:** Symmetric NAT or restrictive firewalls (5-10% of cases)

**How It Works:** TURN server relays all traffic
```
Peer A ↔ TURN Server ↔ Peer B
```

**Tradeoff:** Requires bandwidth, costs money, less private
**Recommendation:** Use only as last resort when direct/STUN fails

### Technology Options

| Library | Language | Pros | Cons |
|---------|----------|------|------|
| **libnice** | C | GStreamer project, stable | Complex API |
| **pjnath** | C | PJSIP library, lightweight | Less documented |
| **libjingle** | C++ | Google, used by Valve/Steam | C++ dependency |
| **libdatachannel** | C++ | WebRTC data channels, modern | C++ dependency |

**Recommendation:** libnice (C, mature) or libdatachannel (if using WebRTC)

### API Design

```c
// NAT Traversal Context
typedef struct nat_traversal_context_t nat_traversal_context_t;

// Initialize NAT traversal
nat_traversal_context_t* nat_traversal_init(const char *stun_server);

// Gather local and reflexive candidates
typedef struct {
    char ip[46];
    uint16_t port;
    enum { CANDIDATE_LOCAL, CANDIDATE_REFLEXIVE, CANDIDATE_RELAY } type;
} ice_candidate_t;

int nat_gather_candidates(nat_traversal_context_t *ctx,
                          ice_candidate_t *candidates,
                          size_t *count);

// Add remote candidates (received from peer)
int nat_add_remote_candidate(nat_traversal_context_t *ctx,
                             const ice_candidate_t *candidate);

// Perform connectivity checks
int nat_establish_connection(nat_traversal_context_t *ctx,
                              int *socket_fd_out);

// Cleanup
void nat_traversal_free(nat_traversal_context_t *ctx);
```

---

## COMPONENT 3: MESSAGE TRANSPORT

### Protocol Design

Once P2P connection established, use custom protocol for message exchange.

### Message Frame Format

```
┌────────────────────────────────────────────────────────┐
│                    DNA P2P Message                      │
├────────────────────────────────────────────────────────┤
│  Header (32 bytes)                                      │
│  ├─ Magic (4 bytes): 0x444E4120 ("DNA ")              │
│  ├─ Version (2 bytes): 0x0100 (v1.0)                  │
│  ├─ Message Type (2 bytes): MSG/ACK/PING/PONG         │
│  ├─ Sequence Number (4 bytes): Incremental counter    │
│  ├─ Payload Length (4 bytes): Ciphertext size         │
│  ├─ Checksum (4 bytes): CRC32 of payload              │
│  └─ Reserved (12 bytes): Future use                   │
├────────────────────────────────────────────────────────┤
│  Payload (variable)                                     │
│  └─ Encrypted message blob (DNA format)               │
└────────────────────────────────────────────────────────┘
```

### Message Types

```c
typedef enum {
    DNA_MSG_DATA      = 0x0001,  // Encrypted message
    DNA_MSG_ACK       = 0x0002,  // Acknowledgment
    DNA_MSG_PING      = 0x0003,  // Keepalive ping
    DNA_MSG_PONG      = 0x0004,  // Keepalive pong
    DNA_MSG_PRESENCE  = 0x0005,  // Online status update
} dna_message_type_t;
```

### Transport API

```c
// Transport Context
typedef struct transport_context_t transport_context_t;

// Initialize transport
transport_context_t* transport_init(const char *identity);

// Connect to peer
int transport_connect(transport_context_t *ctx,
                      const char *peer_identity,
                      int *connection_id_out);

// Send encrypted message
int transport_send(transport_context_t *ctx,
                   int connection_id,
                   const uint8_t *ciphertext,
                   size_t ciphertext_len);

// Receive message (blocking or with timeout)
int transport_receive(transport_context_t *ctx,
                      int connection_id,
                      uint8_t **ciphertext_out,
                      size_t *ciphertext_len_out,
                      int timeout_ms);

// Disconnect
int transport_disconnect(transport_context_t *ctx, int connection_id);

// Cleanup
void transport_free(transport_context_t *ctx);
```

### Connection Establishment Flow

```
1. Alice wants to send message to Bob

2. Query DHT:
   dht_find_peer(ctx, "bob", &bob_ip, &bob_port)
   → bob_ip = "198.51.100.10", bob_port = 60002

3. If bob_ip != NULL (Bob is online):
   a. Gather ICE candidates (NAT traversal)
   b. Exchange candidates via DHT
   c. Perform connectivity checks
   d. Establish UDP/TCP connection

4. If bob_ip == NULL (Bob is offline):
   → Fall back to DHT storage (see DHT-STORAGE-DESIGN.md)

5. Send message over P2P connection:
   transport_send(ctx, connection_id, ciphertext, ciphertext_len)

6. Bob receives and decrypts:
   transport_receive(ctx, connection_id, &ciphertext, &ciphertext_len)
   dna_decrypt_message_raw(...)
```

---

## TECHNOLOGY RECOMMENDATION

### Option A: libp2p (Full Stack)

**Pros:**
- Complete P2P networking stack
- Includes DHT (Kademlia), NAT traversal, multiplexing
- Battle-tested (IPFS, Filecoin, Polkadot)
- Active development

**Cons:**
- C++ (not pure C)
- Heavy dependency
- Complex API

**Use Case:** If building production-ready system quickly

### Option B: Custom Stack (Modular)

**Components:**
- DHT: OpenDHT or BitTorrent DHT (C)
- NAT: libnice (C)
- Transport: Raw UDP/TCP sockets

**Pros:**
- Full control
- Lightweight (only what we need)
- Pure C possible

**Cons:**
- More integration work
- Need to handle edge cases

**Use Case:** If minimizing dependencies and binary size

### Option C: Hybrid (libdatachannel + OpenDHT)

**Components:**
- WebRTC: libdatachannel (C++, lightweight)
- DHT: OpenDHT (C++)

**Pros:**
- Modern WebRTC (used by browsers)
- Built-in NAT traversal
- Simpler than libp2p

**Cons:**
- C++ dependency
- Still requires signaling (use DHT)

**Use Case:** If prioritizing WebRTC compatibility (browser interop)

---

## RECOMMENDED APPROACH

**For DNA Messenger:**

**Phase 1:** Prototype with libp2p (fastest to working P2P)
**Phase 2:** Evaluate performance, binary size, complexity
**Phase 3:** Consider custom stack if needed (optimize later)

**Rationale:** libp2p gives working P2P quickly, can optimize later if needed

---

## IMPLEMENTATION FILES

```c
// Header files
network_transport.h    // Public API for P2P messaging
dht_discovery.h        // Peer discovery via DHT
nat_traversal.h        // ICE/STUN/TURN handling
p2p_protocol.h         // Message framing/serialization

// Implementation files
network_transport.c    // Transport layer implementation
dht_discovery.c        // DHT integration (libp2p or OpenDHT)
nat_traversal.c        // NAT traversal (libnice or libdatachannel)
p2p_protocol.c         // Protocol encoding/decoding
```

---

## TESTING PLAN

### Unit Tests
- DHT store/retrieve
- NAT candidate gathering
- Message framing/parsing

### Integration Tests
- Two peers on same LAN (direct connection)
- Two peers behind NAT (STUN)
- Two peers behind symmetric NAT (TURN fallback)
- Peer goes offline mid-conversation
- DHT network partition/recovery

### Performance Tests
- Connection establishment time
- Message latency (direct vs TURN)
- Throughput (messages/second)
- DHT lookup time

---

## FUTURE ENHANCEMENTS

1. **Multiple transports:** UDP for messages, TCP for file transfers
2. **Onion routing:** Tor integration for metadata privacy
3. **Multicast:** Group messaging optimization
4. **Compression:** Reduce bandwidth usage
5. **Forward error correction:** Unreliable network resilience

---

**Document Version:** 1.0
**Last Updated:** 2025-10-16
**Status:** Research & Planning Phase
