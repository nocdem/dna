# DNA Messenger Premium Mode - Future Implementation

**Status:** Planning
**Target Phase:** TBD
**Last Updated:** 2025-11-28

---

## Overview

Implement a **fully decentralized, cryptographically enforced** premium subscription system for DNA Messenger. Premium status is verified through blockchain payments and enforced via signed certificates - impossible to bypass without valid cryptographic proof.

---

## Design Goals

1. **Fully Decentralized** - No central premium server required
2. **Cryptographically Enforced** - Features impossible to access without valid proof
3. **Subscription Model** - 30-day stackable subscriptions (buy multiple = more days)
4. **Simple Expiry** - When time runs out, premium features stop working
5. **No Smart Contracts** - Works with existing Cellframe RPC capabilities

---

## Architecture

### Core Concept: Premium Certificates

Premium status is proven via digitally signed certificates issued by bootstrap nodes after verifying blockchain payments.

```
┌─────────────┐    TX + memo     ┌──────────────────┐
│   User      │ ───────────────> │ Cellframe Chain  │
│  (Client)   │                  │  PREMIUM_ADDRESS │
└─────────────┘                  └────────┬─────────┘
       │                                  │
       │ fetch cert                       │ monitor TXs
       ▼                                  ▼
┌─────────────┐                  ┌──────────────────┐
│    DHT      │ <─────────────── │  Bootstrap Nodes │
│  (Storage)  │   publish cert   │   (dna-nodus)    │
└─────────────┘                  └──────────────────┘
```

### Certificate Properties

- **Signed** by bootstrap node's Dilithium5 key
- **Stored** in DHT with 365-day TTL
- **Verified** cryptographically by all peers
- **Impossible to forge** without bootstrap private keys

---

## Premium Features

### Tier Comparison

| Feature | Free | Premium |
|---------|------|---------|
| Offline message outbox | 10 messages | 100 messages |
| Group creation | Cannot create | Unlimited |
| Join groups | Yes | Yes |
| Profile badge | None | Premium badge |
| Future: Voice/video calls | No | Yes |
| Future: Custom themes | No | Yes |
| Future: Large file transfers | Limited | Unlimited |

### Additional Premium Ideas

- **Read receipts** - See when messages are read
- **Message scheduling** - Send messages at future time
- **Extended message history** - Longer local retention
- **Custom notification sounds** - Premium-only sounds
- **Priority message delivery** - Premium messages processed first
- **Larger avatars/media** - Higher resolution allowed
- **Multiple identities** - More than N identities
- **Group size limits** - Free: 50 members, Premium: unlimited
- **Message wall posts** - Free: 5/day, Premium: unlimited

---

## Payment Flow

### Step 1: User Purchases Premium

```
Transaction:
  To:     PREMIUM_ADDRESS (configured wallet)
  Amount: PREMIUM_PRICE CPUNK (configurable)
  Memo:   "PREMIUM:<fingerprint>"
```

Example memo: `PREMIUM:a1b2c3d4e5f6...` (128 hex character fingerprint)

### Step 2: Bootstrap Node Detects Payment

1. dna-nodus polls Cellframe RPC for TXs to `PREMIUM_ADDRESS`
2. Parses memo to extract fingerprint
3. Verifies TX is confirmed (status: ACCEPTED)
4. Calculates new expiry: `max(current_expiry, now) + 30 days`

### Step 3: Certificate Issuance

Bootstrap node creates and signs a Premium Certificate:

```c
struct PremiumCertificate {
    uint8_t  version;           // 1
    char     fingerprint[129];  // User's Dilithium5 fingerprint
    int64_t  expires_at;        // Unix timestamp
    int64_t  issued_at;         // When certificate was created
    uint32_t total_days;        // Cumulative days purchased
    char     tx_hashes[MAX_TXS][65];  // All premium TX hashes
    char     issuer_fp[129];    // Bootstrap node fingerprint
    uint8_t  signature[4627];   // Dilithium5 signature
};
```

### Step 4: DHT Publication

```
Key:   SHA3-512(fingerprint + ":premium:v1")
Value: Serialized PremiumCertificate
TTL:   365 days
```

### Step 5: Renewal (Stacking)

User can purchase multiple times:
- Each purchase adds 30 days
- Expiry extends from current expiry (not from purchase date)
- Example: Buy 3x = 90 days of premium

---

## Cryptographic Enforcement

### Group Creation (Premium Only)

**How it works:**
1. When creating a group, user attaches their premium certificate
2. Group metadata in DHT includes creator's certificate
3. Peers joining the group verify:
   - Certificate signature valid (signed by known bootstrap)
   - Certificate not expired (`expires_at > now`)
   - Certificate fingerprint matches group creator
4. Invalid certificate = reject group entirely

**Implementation:**
- Group metadata struct gains `creator_premium_cert` field
- `group_create()` requires valid local premium status
- `group_join()` validates creator's embedded certificate

### Outbox Limits

**How it works:**
1. When receiving offline messages, check sender's certificate
2. Free users: Accept max 10 queued messages from any sender
3. Premium users: Accept up to 100 queued messages
4. Certificate verified before accepting queued message

**Implementation:**
- Outbox acceptance checks sender's DHT certificate
- Counter per sender fingerprint
- Reject with error if limit exceeded

### Profile Badge

**How it works:**
1. User profile includes embedded certificate
2. Viewers verify certificate cryptographically
3. Display badge only if certificate valid and not expired

**Implementation:**
- Profile struct gains `premium_cert` field
- UI verifies before displaying badge
- Not client-side trust - cryptographic verification

---

## Verification Flow

### Client Checking Own Premium Status

```c
bool is_premium(const char* my_fingerprint) {
    // 1. Check local cache first
    PremiumCert* cached = cache_get_premium(my_fingerprint);
    if (cached && cached->expires_at > time(NULL)) {
        return true;
    }

    // 2. Fetch from DHT
    char key[129];
    compute_premium_key(my_fingerprint, key);
    PremiumCert* cert = dht_get(key);
    if (!cert) return false;

    // 3. Verify signature against known bootstrap keys
    if (!verify_premium_cert(cert)) {
        return false;
    }

    // 4. Check expiry
    if (cert->expires_at <= time(NULL)) {
        return false;
    }

    // 5. Cache and return
    cache_set_premium(my_fingerprint, cert);
    return true;
}
```

### Verifying Another User's Premium

Same flow - fetch from DHT, verify signature, check expiry. Used when:
- Joining groups (verify creator)
- Accepting queued messages (verify sender)
- Displaying profile badges (verify profile owner)

---

## Bootstrap Node Implementation

### New Components for dna-nodus

1. **Premium TX Monitor**
   - Poll Cellframe RPC every N seconds for TXs to PREMIUM_ADDRESS
   - Parse memo, extract fingerprint
   - Track processed TX hashes (avoid duplicates)

2. **Certificate Manager**
   - Maintain SQLite table of active subscriptions
   - Calculate expiry dates (stackable 30-day increments)
   - Generate and sign certificates with node's Dilithium5 key

3. **DHT Publisher**
   - Publish certificates to DHT
   - Re-publish before TTL expiry (every ~300 days)
   - Handle certificate updates on new purchases

### Configuration Extension (dna-nodus.conf)

```json
{
    "dht_port": 4000,
    "seed_nodes": ["154.38.182.161", "164.68.105.227"],
    "turn_port": 3478,
    "public_ip": "auto",
    "persistence_path": "/var/lib/dna-dht/bootstrap.state",

    "premium": {
        "enabled": true,
        "address": "CPUNK_PREMIUM_WALLET_ADDRESS",
        "price_cpunk": 1.0,
        "days_per_purchase": 30,
        "poll_interval_seconds": 60,
        "rpc_endpoint": "https://rpc.cellframe.net"
    }
}
```

---

## Database Schema

### Bootstrap Node SQLite

```sql
-- Premium subscription tracking
CREATE TABLE premium_subscriptions (
    fingerprint TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    total_days INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Transaction history (prevent replay)
CREATE TABLE premium_transactions (
    tx_hash TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    amount REAL NOT NULL,
    processed_at INTEGER NOT NULL,
    FOREIGN KEY (fingerprint) REFERENCES premium_subscriptions(fingerprint)
);

-- Indexes
CREATE INDEX idx_premium_expires ON premium_subscriptions(expires_at);
CREATE INDEX idx_tx_fingerprint ON premium_transactions(fingerprint);
```

### Client SQLite (per-identity)

```sql
-- Premium certificate cache
-- File: <fingerprint>_premium.db
CREATE TABLE premium_cache (
    fingerprint TEXT PRIMARY KEY,
    certificate BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    cached_at INTEGER NOT NULL
);

CREATE INDEX idx_cache_expires ON premium_cache(expires_at);
```

---

## Implementation Phases

### Phase 1: Core Infrastructure

1. Define `PremiumCertificate` structure in `premium/premium_cert.h`
2. Implement serialization/deserialization
3. Implement signature generation and verification
4. Create DHT key derivation: `SHA3-512(fp + ":premium:v1")`
5. Store known bootstrap public keys in client config

### Phase 2: Bootstrap Node Premium Service

1. Add premium config parsing to dna-nodus
2. Implement Cellframe RPC TX monitoring
3. Implement certificate generation and Dilithium5 signing
4. Implement DHT publishing
5. Add SQLite persistence for subscription tracking
6. Add TX deduplication logic

### Phase 3: Feature Gating

1. Gate group creation behind premium check
2. Implement outbox limits (free: 10, premium: 100)
3. Add premium certificate to profile structure
4. Update Flutter UI to show premium status and badges

### Phase 4: Integration & Testing

1. End-to-end test: purchase -> certificate -> feature unlock
2. Test certificate expiry behavior
3. Test renewal flow (stacking multiple purchases)
4. Cross-platform testing (Linux, Windows, Android)

---

## Files to Create/Modify

### New Files

```
premium/
├── premium_cert.h          # Certificate structures
├── premium_cert.c          # Serialization, verification
├── premium_client.h        # Client-side premium checks
├── premium_client.c        # DHT fetch, cache, verify
└── premium_keys.h          # Known bootstrap public keys
```

### Bootstrap Node (dna-nodus)

```
vendor/opendht-pq/tools/
├── dna-nodus.cpp           # Add premium service init
├── premium_monitor.h       # TX monitoring header
├── premium_monitor.cpp     # TX monitoring impl
├── premium_db.h            # SQLite persistence
├── premium_db.cpp          # SQLite persistence impl
└── dna-nodus.conf.example  # Add premium config section
```

### Client Integration

```
dht/groups/
└── group_create.c          # Require premium certificate

dht/offline_queue/
└── outbox.c                # Enforce message limits

dht/profiles/
└── profile.c               # Embed certificate for badge

flutter_ui/lib/
├── services/premium_service.dart
├── widgets/premium_badge.dart
└── screens/premium_screen.dart
```

### Configuration

```
include/
└── config.h                # PREMIUM_ADDRESS, default price

blockchain/
└── blockchain_rpc.h        # Add TX monitoring helpers
```

---

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| Certificate forgery | Impossible without bootstrap private keys (Dilithium5) |
| Replay attacks | TX hashes tracked, duplicates rejected |
| Time manipulation | Expiry checked against network time |
| DHT tampering | Certificates are signed, tampering detectable |
| Bootstrap compromise | Single node can issue certs (acceptable - trusted infrastructure) |

### Trust Model

- Bootstrap nodes are already trusted infrastructure (DHT entry points)
- Clients maintain hardcoded list of known bootstrap public keys
- Any valid signature from a known node = valid certificate
- Same trust model as DHT itself

---

## Configuration Summary

| Setting | Value |
|---------|-------|
| Premium price | Configurable (TBD) |
| Days per purchase | 30 days |
| Free outbox limit | 10 messages |
| Premium outbox limit | 100 messages |
| Free group access | Can JOIN only |
| Premium group access | Can CREATE unlimited |
| Certificate TTL | 365 days |
| Verification | Single bootstrap signature |

---

## User Experience Flow

### Purchasing Premium

1. User opens Premium screen in app
2. App displays premium wallet address and required amount
3. User sends CPUNK from their wallet with fingerprint memo
4. App shows "Waiting for confirmation..."
5. Bootstrap detects TX, issues certificate
6. App fetches certificate from DHT
7. Premium features unlock immediately

### Checking Status

1. App checks local cache first (instant)
2. If cache expired/missing, fetch from DHT
3. Verify signature and expiry
4. Display remaining days and premium badge

### Renewal

1. User sees "X days remaining" in Premium screen
2. User sends another TX to premium address
3. Days are added to existing subscription
4. Certificate updated in DHT

---

## Future Enhancements

### Potential Improvements

1. **Grace period** - Allow 7-day grace after expiry before feature lockout
2. **Referral system** - Get bonus days for referring new premium users
3. **Bulk discounts** - Lower per-day price for longer subscriptions
4. **Gift premium** - Send premium to another user's fingerprint
5. **Token staking** - Alternative model: stake tokens instead of spending
6. **Multi-tier** - Basic, Pro, Enterprise tiers with different features

### Threshold Signatures (Optional Enhancement)

If stronger security is needed later:
- Require 2/3 bootstrap nodes to sign
- Prevents single compromised node from issuing fake certs
- More complex implementation

---

## Related Documentation

- [Architecture](ARCHITECTURE.md) - System architecture
- [DNA Nodus](DNA_NODUS.md) - Bootstrap server details
- [API Reference](API.md) - Blockchain RPC integration
- [Development Guidelines](DEVELOPMENT.md) - Code patterns

---

## Summary

This design implements decentralized premium subscriptions by:

1. **Payment**: User sends CPUNK to premium address with fingerprint in memo
2. **Verification**: Bootstrap node (dna-nodus) verifies TX and issues signed certificate
3. **Storage**: Certificate stored in DHT with 365-day TTL
4. **Enforcement**: Peers verify Dilithium5 signature before allowing premium features
5. **Expiry**: 30-day stackable subscriptions, time-based expiry

**Cryptographic Guarantees:**
- Certificate forgery impossible without bootstrap private keys
- Features enforced at protocol level, not client-side checks
- Fully decentralized - no central premium server
