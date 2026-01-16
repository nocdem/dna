# DNA Plus - Premium Subscription System

**Status:** Documentation Phase
**Target Phase:** TBD
**Last Updated:** 2026-01-10

---

## Overview

DNA Plus is a premium subscription tier for DNA Messenger that unlocks additional features through a fully decentralized, cryptographically-enforced subscription system. Premium status is verified through CPUNK blockchain payments and enforced via Dilithium5-signed certificates.

---

## Design Goals

1. **Fully Decentralized** - No central premium server required
2. **Cryptographically Enforced** - Features impossible to access without valid proof
3. **Subscription Model** - 30-day stackable subscriptions (buy multiple = more days)
4. **Simple Expiry** - When time runs out, premium features stop working
5. **No Smart Contracts** - Works with existing Cellframe RPC capabilities

---

## Feature Comparison

| Feature | Free | DNA Plus |
|---------|------|----------|
| **Messaging** | | |
| Offline message outbox | 10 messages | 100 messages |
| Read receipts | No | Yes |
| Message scheduling | No | Yes |
| **Groups** | | |
| Join groups | Yes | Yes |
| Create groups | No | Unlimited |
| Group size limit | N/A | Unlimited |
| **Profile** | | |
| Profile badge | None | Premium badge |
| Avatar size | Standard | High-res |
| **Storage** | | |
| Message history | 30 days | Unlimited local |
| **Future Features** | | |
| Voice/Video calls | No | Yes |
| Custom themes | No | Yes |
| Large file transfers | 10MB | 100MB |

---

## Architecture

### Certificate-Based Subscription

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

### Certificate Structure

```c
struct PremiumCertificate {
    uint8_t  version;           // 1
    uint8_t  tier;              // 0=Free, 1=Plus
    char     fingerprint[129];  // User's Dilithium5 fingerprint
    int64_t  expires_at;        // Unix timestamp
    int64_t  issued_at;         // When certificate was created
    uint32_t total_days;        // Cumulative days purchased
    char     tx_hashes[MAX_TXS][65];  // All premium TX hashes
    char     issuer_fp[129];    // Bootstrap node fingerprint
    uint8_t  signature[4627];   // Dilithium5 signature
};
```

### DHT Storage

```
Key:   SHA3-512(fingerprint + ":premium:v1")
Value: Serialized PremiumCertificate
TTL:   365 days
```

---

## User Flows

### 1. New User Purchase Flow

**Entry Point:** Settings > DNA Plus

```
┌─────────────────────────────────────────────────────────────────┐
│  DNA Plus Screen - Not Subscribed                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ╔═══════════════════════════════════════════════════════════╗  │
│  ║  DNA Plus                                                  ║  │
│  ║  Unlock premium features                                   ║  │
│  ╚═══════════════════════════════════════════════════════════╝  │
│                                                                 │
│  Status: Not Subscribed                                         │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  What you get with DNA Plus:                              │  │
│  │                                                           │  │
│  │  ✓ Create unlimited groups                                │  │
│  │  ✓ 100 offline messages (vs 10)                           │  │
│  │  ✓ Read receipts                                          │  │
│  │  ✓ Premium profile badge                                  │  │
│  │  ✓ Priority support                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Price: X CPUNK / 30 days                                       │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    [ Subscribe Now ]                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Step-by-Step Flow:**

1. User opens **Settings > DNA Plus**
2. Views pricing and benefits comparison table
3. Sees "Not Subscribed" status
4. Taps "Subscribe Now"
5. App displays payment screen:

```
┌─────────────────────────────────────────────────────────────────┐
│  Subscribe to DNA Plus                                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Send X CPUNK to:                                               │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  CPUNK_PREMIUM_WALLET_ADDRESS                    [Copy]   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─────────────────────┐                                        │
│  │                     │                                        │
│  │     [QR CODE]       │                                        │
│  │                     │                                        │
│  └─────────────────────┘                                        │
│                                                                 │
│  IMPORTANT: Include this memo in your transaction:              │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  PREMIUM:a1b2c3d4e5f6...                         [Copy]   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Your fingerprint is auto-filled above.                         │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  [ Pay with In-App Wallet ]                               │  │
│  │  [ I'll Pay from External Wallet ]                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

6. User sends CPUNK:
   - **In-App Wallet:** Pre-filled transaction, user confirms
   - **External Wallet:** User copies address and memo, pays externally

7. App shows "Waiting for confirmation...":

```
┌─────────────────────────────────────────────────────────────────┐
│  Waiting for Payment                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                    [Spinning Indicator]                         │
│                                                                 │
│  Looking for your payment on the blockchain...                  │
│                                                                 │
│  This usually takes 1-5 minutes.                                │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      [ Cancel ]                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

   - App polls DHT every 30 seconds for certificate
   - Bootstrap node detects TX, verifies, issues certificate

8. Success screen:

```
┌─────────────────────────────────────────────────────────────────┐
│  DNA Plus Activated!                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                         ✓                                       │
│                                                                 │
│  Welcome to DNA Plus!                                           │
│                                                                 │
│  Your subscription is active until:                             │
│  February 10, 2026                                              │
│                                                                 │
│  Premium features are now unlocked.                             │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      [ Done ]                             │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### 2. Subscription Status Check Flow

**When:** On app startup and when viewing DNA Plus screen

```
┌─────────────────────────────────────────────────────────────────┐
│                    Status Check Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  App Startup                                                    │
│       │                                                         │
│       ▼                                                         │
│  ┌─────────────────────────────────────┐                        │
│  │ 1. Check local SQLite cache         │                        │
│  │    for PremiumCertificate           │                        │
│  └────────────────┬────────────────────┘                        │
│                   │                                             │
│         ┌─────────┴─────────┐                                   │
│         │                   │                                   │
│    Cache Hit            Cache Miss                              │
│    & Not Expired        or Expired                              │
│         │                   │                                   │
│         ▼                   ▼                                   │
│  ┌──────────────┐   ┌─────────────────────┐                     │
│  │ Enable       │   │ 2. Fetch from DHT   │                     │
│  │ Premium      │   │    (async, non-     │                     │
│  │ Features     │   │    blocking)        │                     │
│  └──────────────┘   └──────────┬──────────┘                     │
│                                │                                │
│                      ┌─────────┴─────────┐                      │
│                      │                   │                      │
│                   Found              Not Found                  │
│                      │                   │                      │
│                      ▼                   ▼                      │
│              ┌───────────────┐   ┌───────────────┐              │
│              │ 3. Verify     │   │ Disable       │              │
│              │ Dilithium5    │   │ Premium       │              │
│              │ Signature     │   │ Features      │              │
│              └───────┬───────┘   └───────────────┘              │
│                      │                                          │
│            ┌─────────┴─────────┐                                │
│            │                   │                                │
│         Valid              Invalid                              │
│         & Not Expired      or Expired                           │
│            │                   │                                │
│            ▼                   ▼                                │
│     ┌──────────────┐   ┌───────────────┐                        │
│     │ Cache locally │   │ Disable       │                        │
│     │ Enable premium│   │ Premium       │                        │
│     └──────────────┘   └───────────────┘                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Verification Steps:**

1. **Local Cache Check:**
   ```sql
   SELECT * FROM premium_cache
   WHERE fingerprint = ? AND expires_at > ?
   ```

2. **DHT Fetch:**
   ```
   Key: SHA3-512(fingerprint + ":premium:v1")
   ```

3. **Signature Verification:**
   - Verify Dilithium5 signature against known bootstrap public keys
   - Known keys stored in `premium_keys.h`

4. **Display Status:**
   - Settings drawer: Premium badge next to username
   - DNA Plus screen: "Subscribed until [date]" or "Not Subscribed"

---

### 3. Renewal Flow

**When:** User has active subscription nearing expiry

```
┌─────────────────────────────────────────────────────────────────┐
│  DNA Plus Screen - Active Subscription                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Status: Subscribed                                             │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  ⚠️  Your DNA Plus expires in 7 days                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Expires: January 17, 2026                                      │
│  Total days purchased: 30                                       │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  [ Extend Subscription ]                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Stacking Logic:**

1. User sends another X CPUNK payment
2. Bootstrap node detects TX
3. New expiry calculated: `max(current_expiry, now) + 30 days`
4. Certificate updated with new expiry
5. DHT updated with new certificate

**Example:**
- Current expiry: January 17, 2026
- User pays on January 10, 2026
- New expiry: February 16, 2026 (adds 30 days to January 17)

---

### 4. Expiry Flow

**When:** Subscription expires

```
┌─────────────────────────────────────────────────────────────────┐
│  DNA Plus Screen - Expired                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Status: Expired                                                │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Your DNA Plus subscription has expired.                  │  │
│  │                                                           │  │
│  │  Premium features are now disabled:                       │  │
│  │  • Group creation locked                                  │  │
│  │  • Offline outbox reduced to 10 messages                  │  │
│  │  • Read receipts disabled                                 │  │
│  │  • Premium badge removed                                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    [ Renew Now ]                          │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**What Happens:**

1. Certificate `expires_at` < current time
2. Premium features disabled:
   - Cannot create new groups (existing groups still work)
   - Outbox limit reduced to 10 messages
   - Read receipts disabled
   - Premium badge removed from profile
3. User can renew at any time
4. No grace period in v1 (can add later)

---

## Business Logic

### Payment Verification

| Rule | Value |
|------|-------|
| Payment address | Configured in dna-nodus.conf |
| Required amount | Configurable (TBD CPUNK) |
| Memo format | `PREMIUM:<fingerprint>` |
| TX confirmations required | 1 (ACCEPTED status) |
| Poll interval | 60 seconds |

### Certificate Issuance

| Rule | Value |
|------|-------|
| Issuer | Bootstrap node (dna-nodus) |
| Signature algorithm | Dilithium5 (ML-DSA-87) |
| Days per purchase | 30 |
| TTL in DHT | 365 days |

### Expiry Calculation (Stacking)

```
new_expiry = max(current_expiry, now) + 30 days
```

- If not subscribed: expiry = now + 30 days
- If subscribed: expiry = current_expiry + 30 days
- Multiple purchases stack (buy 3x = 90 days)

### Feature Gating Rules

| Feature | Check Method |
|---------|--------------|
| Group creation | `is_premium()` before `group_create()` |
| Outbox limit | Check limit in `dht_queue_message()` |
| Read receipts | Check before sending receipt |
| Profile badge | Verify certificate before displaying |

### Cache Invalidation

| Event | Action |
|-------|--------|
| App startup | Refresh if cache > 1 hour old |
| Certificate expiry | Remove from cache |
| DHT sync | Update cache if certificate changed |
| Manual refresh | User pulls to refresh in DNA Plus screen |

### Offline Behavior

| Scenario | Behavior |
|----------|----------|
| No network at startup | Use cached certificate |
| Cache valid, offline | Premium features work |
| Cache expired, offline | Premium features disabled until online |
| New purchase, offline | Cannot complete (requires network) |

---

## Error Handling

### Payment Not Detected

**Cause:** TX not yet confirmed or memo incorrect

```
┌─────────────────────────────────────────────────────────────────┐
│  Payment Not Found                                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  We couldn't find your payment yet.                             │
│                                                                 │
│  This could mean:                                               │
│  • The transaction is still confirming                          │
│  • The memo format was incorrect                                │
│  • The amount was insufficient                                  │
│                                                                 │
│  Expected memo: PREMIUM:a1b2c3d4...                             │
│  Expected amount: X CPUNK                                       │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  [ Check Again ]     [ Contact Support ]                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Handling:**
1. Display helpful error message
2. Show expected memo and amount
3. Allow user to retry
4. Provide support contact

### Invalid Memo Format

**Cause:** User typed memo incorrectly

**Prevention:**
- Auto-fill memo with user's fingerprint
- Copy button copies exact format
- Clear instructions on payment screen

**Recovery:**
- Payment goes to address but certificate not issued
- User must contact support with TX hash
- Manual certificate issuance possible (admin tool)

### Network Errors

**Cause:** DHT unreachable

```
┌─────────────────────────────────────────────────────────────────┐
│  Connection Error                                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Couldn't connect to the network.                               │
│                                                                 │
│  Please check your internet connection and try again.           │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      [ Retry ]                            │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Handling:**
1. Use cached certificate if available
2. Show offline indicator
3. Retry when network available
4. Don't lock out user if they have valid cache

### Certificate Verification Failures

**Cause:** Tampered or corrupted certificate

**Handling:**
1. Reject certificate
2. Fetch fresh from DHT
3. If still fails, disable premium features
4. Log for debugging

### Expired Certificates

**Cause:** Subscription period ended

**Handling:**
1. Disable premium features gracefully
2. Show clear expiry message
3. Prominent "Renew Now" button
4. Keep existing data (groups, messages) intact

---

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| Certificate forgery | Impossible without bootstrap Dilithium5 keys |
| Replay attacks | TX hashes tracked, duplicates rejected |
| Time manipulation | Expiry checked against network time |
| DHT tampering | Certificates are signed, tampering detectable |
| Client bypass | Features enforced at protocol level, not UI |
| Bootstrap compromise | Single node can issue certs (trusted infrastructure) |

### Trust Model

- Bootstrap nodes are already trusted infrastructure (DHT entry points)
- Clients maintain hardcoded list of known bootstrap public keys
- Any valid signature from a known node = valid certificate
- Same trust model as DHT itself

---

## Configuration

### dna-nodus.conf

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

### Client Configuration

```c
// include/config.h
#define PREMIUM_FREE_OUTBOX_LIMIT 10
#define PREMIUM_PLUS_OUTBOX_LIMIT 100
#define PREMIUM_FREE_GROUP_CREATE false
#define PREMIUM_PLUS_GROUP_CREATE true
#define PREMIUM_CACHE_REFRESH_HOURS 1
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

### Phase 1: Core Infrastructure (C Library)

**New Files:**
```
premium/
├── premium_cert.h          # Certificate structures
├── premium_cert.c          # Serialization, verification
├── premium_client.h        # Client-side premium checks
├── premium_client.c        # DHT fetch, cache, verify
└── premium_keys.h          # Known bootstrap public keys
```

**Tasks:**
1. Define `PremiumCertificate` structure
2. Implement serialization/deserialization
3. Implement Dilithium5 signature verification
4. Create DHT key derivation: `SHA3-512(fp + ":premium:v1")`
5. Add local SQLite cache for certificates
6. Add `dna_engine_is_premium()` API function

### Phase 2: Bootstrap Node (dna-nodus)

**New Files:**
```
vendor/opendht-pq/tools/
├── premium_monitor.h/.cpp  # TX monitoring
├── premium_db.h/.cpp       # SQLite persistence
└── dna-nodus.conf.example  # Premium config section
```

**Tasks:**
1. Add premium config parsing
2. Implement Cellframe RPC TX monitoring
3. Implement certificate generation
4. Implement DHT publishing
5. Add SQLite persistence for subscription tracking

### Phase 3: Feature Gating

**Modify:**
- `dht/groups/messenger_groups.c` - Require premium for creation
- `dht/shared/dht_offline_queue.c` - Enforce outbox limits
- `dht/profiles/dht_profile.c` - Embed premium badge

### Phase 4: Flutter UI

**New Files:**
```
dna_messenger_flutter/lib/
├── screens/premium/
│   ├── premium_screen.dart       # Main subscription screen
│   └── premium_purchase.dart     # Purchase flow
├── widgets/
│   └── premium_badge.dart        # Badge component
└── providers/
    └── premium_provider.dart     # Subscription state
```

### Phase 5: Testing

1. End-to-end: purchase -> certificate -> feature unlock
2. Certificate expiry behavior
3. Renewal flow (stacking purchases)
4. Cross-platform testing (Linux, Windows, Android)

---

## Future Enhancements

- **Grace period** - Allow X days after expiry before feature lockout
- **Gift premium** - Purchase premium for another user's fingerprint
- **Trial period** - Free trial for new users
- **Multi-tier** - Basic, Pro, Enterprise tiers
- **Referral system** - Bonus days for referrals
- **Bulk discounts** - Lower per-day price for longer subscriptions
- **Token staking** - Alternative: stake tokens instead of spending
- **Threshold signatures** - Require 2/3 bootstrap nodes to sign

---

## Related Documentation

- [Architecture](ARCHITECTURE_DETAILED.md) - System architecture
- [DNA Nodus](DNA_NODUS.md) - Bootstrap server details
- [DHT System](DHT_SYSTEM.md) - DHT operations
- [Blockchain Integration](BLOCKCHAIN_INTEGRATION.md) - Wallet and RPC

---

## Summary

DNA Plus implements decentralized premium subscriptions by:

1. **Payment**: User sends CPUNK to premium address with fingerprint in memo
2. **Verification**: Bootstrap node (dna-nodus) verifies TX and issues signed certificate
3. **Storage**: Certificate stored in DHT with 365-day TTL
4. **Enforcement**: Peers verify Dilithium5 signature before allowing premium features
5. **Expiry**: 30-day stackable subscriptions, time-based expiry

**Cryptographic Guarantees:**
- Certificate forgery impossible without bootstrap private keys
- Features enforced at protocol level, not client-side checks
- Fully decentralized - no central premium server
