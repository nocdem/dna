# DNA Messenger - Future Decentralized Architecture

**Version:** 2.0 (Future Design)
**Status:** Research & Planning Phase
**Goal:** Fully decentralized P2P messaging with distributed storage

---

## VISION

Transform DNA Messenger from current hybrid architecture (local PostgreSQL + filesystem) to a fully decentralized peer-to-peer system with NO central servers and NO local-only storage.

**Current Architecture (v0.1.x):**
```
Client → PostgreSQL (messages + keyserver) + Filesystem (private keys)
         └── Centralized, single point of failure
```

**Future Architecture (v2.0):**
```
Peer A ←→ DHT Network ←→ Peer B
   ↕                        ↕
Storage Nodes (distributed, replicated, encrypted)
```

---

## CORE PRINCIPLES

### 1. Full Decentralization
- **No central servers** for messages, keys, or coordination
- **No single point of failure** - network survives peer churn
- **No trust required** in infrastructure providers

### 2. Distributed Storage
- Messages stored across multiple peers (not just sender/recipient)
- **Replication factor k=5** - survives 4 out of 5 nodes going offline
- **Zero-knowledge storage** - storage nodes cannot decrypt messages
- **Auto-expiry** - messages deleted after 30 days (configurable)

### 3. Multi-Device Synchronization
- Same identity works on multiple devices
- Messages synchronized via DHT network
- Local cache for performance (SQLite encrypted)

### 4. Privacy & Security
- End-to-end encryption (post-quantum)
- DHT stores only encrypted blobs
- NAT traversal without compromising privacy
- Optional: Tor integration for metadata protection

---

## HIGH-LEVEL ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────┐
│                    DNA Messenger P2P Network                     │
│                                                                   │
│  ┌──────────────┐         DHT Network         ┌──────────────┐  │
│  │   Peer A     │◄──────────────────────────►│   Peer B     │  │
│  │   (alice)    │     (Kademlia DHT)          │   (bob)      │  │
│  │              │                              │              │  │
│  │ ┌──────────┐ │                              │ ┌──────────┐ │  │
│  │ │  SQLite  │ │                              │ │  SQLite  │ │  │
│  │ │  Cache   │ │                              │ │  Cache   │ │  │
│  │ └──────────┘ │                              │ └──────────┘ │  │
│  └──────────────┘                              └──────────────┘  │
│         ▲                                              ▲         │
│         │        ┌──────────┐    ┌──────────┐         │         │
│         └───────►│ Storage  │◄──►│ Storage  │◄────────┘         │
│                  │  Node C  │    │  Node D  │                   │
│                  └──────────┘    └──────────┘                   │
│                        (Stores encrypted message chunks)         │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │         Public Key Distribution (DHT Keyserver)          │   │
│  │  identity "bob" → {dilithium_pubkey, kyber_pubkey}      │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## KEY COMPONENTS

### 1. P2P Transport Layer
- **Technology:** libp2p (C++) or libdatachannel (C)
- **Peer Discovery:** Kademlia DHT
- **NAT Traversal:** ICE/STUN/TURN (libnice or pjnath)
- **Direct messaging** when both peers online
- **Bootstrap nodes** for initial DHT join

**Design Document:** `P2P-TRANSPORT-DESIGN.md`

### 2. Distributed Storage Layer
- **Technology:** OpenDHT or BitTorrent DHT
- **Replication:** k=5 successor nodes (DHash-style)
- **Encrypted blobs** stored at SHA256(recipient + timestamp + nonce)
- **Automatic cleanup** after 30 days
- **Store-and-forward** for offline message delivery

**Design Document:** `DHT-STORAGE-DESIGN.md`

### 3. Local Cache Layer
- **Technology:** SQLite + SQLCipher (encrypted)
- **Purpose:** Fast queries, offline access, search/filter
- **Synchronization:** Background sync with DHT network
- **Schema:** Same as current (messages, conversations, contacts, groups)

**Design Document:** `SYNC-PROTOCOL-DESIGN.md`

### 4. Decentralized Keyserver
- **Technology:** DHT-based key-value store
- **Storage:** Public keys replicated across DHT
- **Verification:** Self-signed keys (TOFU model)
- **Optional:** Blockchain anchoring for tamper-proof registry

**Design Document:** `DHT-KEYSERVER-DESIGN.md`

---

## MESSAGE FLOW

### Scenario 1: Both Peers Online (Direct Messaging)

```
1. Alice queries DHT: "WHERE IS bob?"
2. DHT responds: "bob is at 192.168.1.100:4567"
3. Alice establishes direct P2P connection (NAT traversal)
4. Alice encrypts message (end-to-end)
5. Alice sends directly to Bob
6. Bob receives and decrypts
7. Both store in local SQLite cache
8. Both replicate to DHT (background) for multi-device sync
```

### Scenario 2: Recipient Offline (Store-and-Forward)

```
1. Alice queries DHT: "WHERE IS bob?"
2. DHT responds: "bob is OFFLINE"
3. Alice encrypts message (end-to-end)
4. Alice stores in DHT:
   Key = SHA256("bob" + timestamp + nonce)
   Value = <encrypted_message_blob>
5. DHT replicates to k=5 storage nodes
6. Bob comes online later
7. Bob queries DHT: "ANY MESSAGES FOR bob?"
8. DHT returns list of encrypted messages
9. Bob downloads and decrypts messages
10. Bob stores in local SQLite cache
11. Bob sends DELETE request to DHT (cleanup)
```

### Scenario 3: Multi-Device Sync

```
1. Alice sends message from Desktop
2. Message stored in DHT
3. Alice's Phone queries DHT: "SYNC MESSAGES FOR alice"
4. DHT returns new messages
5. Alice's Phone downloads and caches locally
6. Result: Both devices have same conversation history
```

---

## TECHNOLOGY STACK

### C/C++ Libraries

| Component | Technology Options | Recommendation |
|-----------|-------------------|----------------|
| **P2P Networking** | libp2p (C++), libdatachannel (C) | libp2p (most complete) |
| **DHT** | OpenDHT (C++), BitTorrent DHT (C), libp2p Kad-DHT | OpenDHT (proven for messaging) |
| **NAT Traversal** | libnice (C), pjnath (C), libjingle (C++) | libnice (GStreamer, stable) |
| **Local Storage** | SQLite + SQLCipher | SQLite (existing, familiar) |
| **Crypto** | Existing (Dilithium3, Kyber512, AES-256-GCM) | Keep current implementation |

### Bootstrap Infrastructure

**Required (minimal):**
- 3-5 public bootstrap DHT nodes (for initial network join)
- 2-3 public STUN servers (for NAT discovery)

**Optional:**
- TURN servers (relay fallback for difficult NATs)

**Note:** Bootstrap/STUN servers do NOT see message content, only used for discovery

---

## MIGRATION PATH

### Phase 4.1: P2P Transport (6-8 weeks)
- Integrate libp2p or libdatachannel
- Implement Kademlia DHT peer discovery
- Add NAT traversal (ICE/STUN)
- Direct peer-to-peer messaging
- Bootstrap node infrastructure

### Phase 4.2: Distributed Storage (6-8 weeks)
- Integrate OpenDHT for message storage
- Encrypted message storage in DHT
- Replication management (k=5)
- Message retrieval and deletion
- Garbage collection (30-day expiry)

### Phase 4.3: Local Cache + Sync (4 weeks)
- Keep SQLite as encrypted cache
- Implement sync protocol (local ↔ DHT)
- Multi-device synchronization
- Offline mode support

### Phase 4.4: DHT Keyserver (4 weeks)
- Store public keys in DHT
- Replace HTTP keyserver
- Self-signed key verification
- Key rotation protocol

### Phase 4.5: Integration & Testing (4 weeks)
- End-to-end testing (multi-peer)
- Performance optimization
- Network resilience testing
- Security audit

**Total Timeline:** ~6 months for complete transition

---

## ADVANTAGES

### vs. Current Architecture (PostgreSQL)

| Aspect | Current (v0.1.x) | Future (v2.0) |
|--------|------------------|---------------|
| **Servers** | PostgreSQL required | Zero servers |
| **Single Point of Failure** | Yes (database) | No (distributed) |
| **Scalability** | Limited by database | Unlimited (P2P) |
| **Privacy** | Server sees metadata | Zero-knowledge storage |
| **Multi-Device** | Database sync | DHT sync |
| **Offline Delivery** | Database queue | DHT store-and-forward |
| **Censorship Resistance** | Vulnerable | Highly resistant |

### vs. Other Messengers

**Signal:** Centralized servers, excellent encryption
**Matrix:** Federated servers, complex protocol
**Session:** P2P (similar), uses Oxen blockchain
**Briar:** P2P, Tor-only (slow), no multi-device
**DNA Messenger (v2.0):** P2P, post-quantum, multi-device, fast

---

## CHALLENGES & SOLUTIONS

### Challenge 1: NAT Traversal
**Problem:** Most peers behind NAT/firewalls
**Solution:** ICE/STUN for hole punching, TURN as fallback

### Challenge 2: DHT Network Bootstrap
**Problem:** How to join DHT network initially?
**Solution:** Public bootstrap nodes (like BitTorrent trackers)

### Challenge 3: Message Persistence
**Problem:** Messages might be lost if all storage nodes go offline
**Solution:** k=5 replication + incentivize storage nodes (CF20 tokens, future)

### Challenge 4: Spam/DoS Attacks
**Problem:** Malicious peers flood DHT with messages
**Solution:** Rate limiting, proof-of-work, reputation system (future)

### Challenge 5: Large Message History
**Problem:** Syncing years of messages from DHT is slow
**Solution:** Local cache + incremental sync, optional archive nodes

---

## SECURITY CONSIDERATIONS

### Threat Model

**Protected Against:**
- Network eavesdropping (end-to-end encryption)
- Quantum attacks (post-quantum algorithms)
- Message tampering (authenticated encryption)
- Censorship (no central servers to block)
- Single point of failure (distributed replication)

**NOT Protected Against:**
- Compromised devices (end-to-end can't protect endpoints)
- Traffic analysis (metadata visible to network observers)
  - **Future:** Tor integration for metadata protection
- Malicious storage nodes (they can delete messages, but not read them)
  - **Mitigation:** k=5 replication makes deletion difficult

### Privacy Considerations

**What DHT Nodes Can See:**
- Encrypted message blobs (unreadable)
- Sender/recipient identities (metadata)
- Timestamps
- Message sizes

**What DHT Nodes CANNOT See:**
- Plaintext message content
- Contact lists
- Conversation patterns (with local cache)

**Future Enhancement:** Onion routing for metadata protection

---

## FUTURE ENHANCEMENTS (Phase 5+)

### Voice/Video Calls
- WebRTC P2P audio/video
- Same NAT traversal infrastructure

### Group Messaging (Advanced)
- Multi-recipient encryption (already implemented)
- Group membership via DHT
- Consensus for admin operations

### Blockchain Integration
- Public key anchoring on Cellframe cpunk network
- CF20 token incentives for storage nodes
- Tamper-proof identity registry

### Mobile Optimization
- Lightweight DHT for battery efficiency
- Push notification bridge (optional relay)
- Offline-first architecture

---

## COMPARISON WITH EXISTING SYSTEMS

### IPFS (InterPlanetary File System)
**Similarities:** DHT-based storage, content addressing
**Differences:** DNA Messenger designed for real-time messaging, not file storage

### BitTorrent DHT
**Similarities:** Kademlia DHT, proven at massive scale
**Differences:** DNA uses DHT for message storage, not just peer discovery

### Jami (formerly Ring)
**Similarities:** P2P messaging, OpenDHT
**Differences:** DNA has post-quantum crypto, blockchain-ready

### Session Messenger
**Similarities:** P2P, decentralized
**Differences:** Session uses Oxen blockchain, DNA uses pure DHT + optional blockchain

---

## CONCLUSION

The future architecture transforms DNA Messenger into a fully decentralized, serverless messaging platform. By leveraging proven P2P technologies (Kademlia DHT, libp2p, ICE/STUN) and combining them with post-quantum cryptography, DNA Messenger will offer:

- **No servers** - truly peer-to-peer
- **No single point of failure** - distributed replication
- **Privacy** - zero-knowledge storage
- **Scalability** - unlimited peer growth
- **Censorship resistance** - no central authority
- **Multi-device** - synchronized via DHT

This design document serves as the foundation for Phase 4+ development, guiding the transition from the current hybrid architecture to a fully decentralized system.

---

**Next Steps:**
1. Review detailed component designs in `futuredesign/` folder
2. Prototype DHT storage with OpenDHT
3. Test P2P transport with libp2p/libdatachannel
4. Build proof-of-concept with 5-10 peers
5. Iterate based on performance/security findings

---

**Document Version:** 1.0
**Last Updated:** 2025-10-16
**Author:** DNA Messenger Development Team
**Status:** Research & Planning Phase
