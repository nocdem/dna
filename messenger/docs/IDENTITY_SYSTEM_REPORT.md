# DNA Messenger Identity System Technical Report

**Date:** 2026-01-29
**Status:** Research Complete - Requires Separate Implementation Session
**Impact:** Critical for future voting/reputation features at scale

---

## Executive Summary

DNA Messenger has **two separate Dilithium5 identity systems** that both derive from the same BIP39 mnemonic but use different keypairs. This results in **double-signing** for all DHT content, causing significant bandwidth overhead (~12KB per vote instead of ~5KB).

**Key Finding:** Every DHT `putSigned()` operation adds a ~7.2KB DHT-level signature ON TOP OF any content-level Messenger signature. This makes the current architecture unsuitable for high-volume reputation voting without modification.

---

## 1. The Two Identity Systems

### 1.1 Messenger Identity

**Purpose:** User-facing identity for signing messages, profiles, votes, contacts

**Storage:** `~/.dna/keys/identity.dsa`

**Derivation:**
```
BIP39 Mnemonic
    ↓
bip39_mnemonic_to_seed()
    ↓
signing_seed (derived from master_seed)
    ↓
qgp_dsa87_keypair_derand(dilithium_pk, dilithium_sk, signing_seed)
    ↓
Dilithium5 Keypair (identity.dsa)
    ↓
fingerprint = SHA3-512(dilithium_pubkey) → 128 hex chars
```

**Key Sizes:**
- Public key: 2,592 bytes
- Private key: 4,896 bytes
- Signature: 4,627 bytes
- Fingerprint: 128 hex characters (64 bytes binary)

**File:** `/opt/dna-messenger/messenger/keygen.c`

### 1.2 DHT Identity

**Purpose:** DHT node identity for routing and signed DHT operations

**Storage:** `~/.dna/dht_identity.bin` (cached)

**Derivation:**
```
BIP39 Mnemonic
    ↓
bip39_mnemonic_to_seed() → master_seed (64 bytes)
    ↓
seed_input = master_seed + "dht_identity" (76 bytes)
    ↓
qgp_sha3_512(seed_input) → full_hash (64 bytes)
    ↓
dht_seed = full_hash[0:32] (truncated to 32 bytes)
    ↓
dht_identity_generate_from_seed(dht_seed)
    ↓
SEPARATE Dilithium5 Keypair (dht_identity.bin)
```

**Key Sizes:** Same as Messenger (Dilithium5)

**File:** `/opt/dna-messenger/messenger/init.c` lines 374-509

### 1.3 Critical Difference

| Aspect | Messenger Identity | DHT Identity |
|--------|-------------------|--------------|
| Derivation path | `signing_seed` | `SHA3-512(master_seed + "dht_identity")[0:32]` |
| Storage | `keys/identity.dsa` | `dht_identity.bin` |
| Fingerprint | User-visible, 128 hex | Internal node_id |
| Signs | Content (votes, messages, profiles) | DHT values (transport layer) |
| Persistence | Always persistent | Cached, deterministic |

**Same mnemonic → Different keypairs → Different signatures**

---

## 2. The Double-Signing Problem

### 2.1 Code Path Trace

When publishing ANY content to DHT:

```
Application Layer (e.g., vote casting)
    ↓
dna_feed_vote_cast()                    // dht/client/dna_feed_votes.c
    ↓
Creates vote record with MESSENGER signature (4,627 bytes)
    ↓
dht_chunked_publish()                   // dht/shared/dht_chunked.c:504
    ↓
dht_put_signed_sync()                   // dht/shared/dht_chunked.c:624
    ↓
dht_put_signed()                        // dht/core/dht_context.cpp:964
    ↓
ctx->runner.putSigned()                 // dht/core/dht_context.cpp:1032
    ↓
SecureDht::putSigned()                  // vendor/opendht-pq/src/securedht.cpp:471
    ↓
sign(*val)                              // securedht.cpp:508
    ↓
Value::sign(*key_)                      // securedht.cpp:593
    ↓
v.sign(*key_)                           // vendor/opendht-pq/src/value.cpp:258
    ↓
owner = key.getSharedPublicKey()        // Sets DHT pubkey (2,592 bytes)
signature = key.sign(getToSign())       // Adds DHT signature (4,627 bytes)
```

### 2.2 Value::sign() Implementation

**File:** `/opt/dna-messenger/vendor/opendht-pq/src/value.cpp` lines 258-264

```cpp
Value::sign(const crypto::PrivateKey& key)
{
    if (isEncrypted())
        throw DhtException("Can't sign encrypted data.");
    owner = key.getSharedPublicKey();  // 2,592 bytes - DHT node's pubkey
    signature = key.sign(getToSign()); // 4,627 bytes - DHT Dilithium5 sig
}
```

### 2.3 Proof of Double-Signing

**SecureDht::putSigned()** at `/opt/dna-messenger/vendor/opendht-pq/src/securedht.cpp:507-509`:

```cpp
[hash,val,this,callback,permanent] (bool /* ok */) {
    sign(*val);  // <-- ADDS DHT SIGNATURE HERE
    dht_->put(hash, val, callback, time_point::max(), permanent);
}
```

This is called for EVERY `dht_put_signed()` operation, regardless of whether the content already has a Messenger signature.

---

## 3. Bandwidth Impact Analysis

### 3.1 Per-Vote Size Breakdown

| Component | Size | Source |
|-----------|------|--------|
| Vote data (target_fp, value, timestamp) | ~150 bytes | Content |
| Messenger signature | 4,627 bytes | Content signing |
| Chunk header + compression overhead | ~100 bytes | dht_chunked |
| **Subtotal (content)** | **~4,877 bytes** | |
| DHT owner public key | 2,592 bytes | Value::sign() |
| DHT signature | 4,627 bytes | Value::sign() |
| **DHT overhead** | **~7,219 bytes** | |
| **TOTAL PER VOTE** | **~12,096 bytes (~12 KB)** | |

### 3.2 Scalability Impact

| Votes | Without DHT Overhead | With DHT Overhead | Difference |
|-------|---------------------|-------------------|------------|
| 100 | 488 KB | 1.2 MB | +146% |
| 1,000 | 4.9 MB | 12 MB | +146% |
| 10,000 | 49 MB | 120 MB | +146% |
| 100,000 | 490 MB | 1.2 GB | +146% |

**For reputation voting at scale, this is UNACCEPTABLE.**

---

## 4. Current Architecture Details

### 4.1 Identity Initialization Flow

**File:** `/opt/dna-messenger/src/api/engine/dna_engine_identity.c`

```
dna_handle_load_identity()
    ↓
1. Load session password
2. Free old messenger context
3. Validate & decrypt keys
4. messenger_init(fingerprint)           // Initialize Messenger
5. Copy fingerprint to engine
6. messenger_load_dht_identity_for_engine()  // Load DHT identity
    ↓
    a. Try cached dht_identity.bin
    b. If not found: derive from mnemonic
    c. Cache for future loads
    d. dht_singleton_init_with_identity()
    ↓
7. Load KEM keys
8. Initialize databases
9. Initialize P2P transport
10. Start presence heartbeat
11. Mark identity loaded
```

### 4.2 DHT Identity Loading

**File:** `/opt/dna-messenger/messenger/init.c` lines 374-509

```c
int messenger_load_dht_identity(const char *fingerprint) {
    // Method 1: Try cached dht_identity.bin (fast path)
    FILE *f = fopen(dht_id_path, "rb");
    if (f) {
        // Load from cache
        dht_identity_import_from_buffer(buffer, file_size, &dht_identity);
    }

    // Method 2: Derive from mnemonic if not cached
    if (!dht_identity) {
        // Load mnemonic
        mnemonic_storage_load(mnemonic, ...);

        // Convert to master seed
        bip39_mnemonic_to_seed(mnemonic, "", master_seed);

        // Derive DHT seed: SHA3-512(master_seed + "dht_identity")[0:32]
        memcpy(seed_input, master_seed, 64);
        memcpy(seed_input + 64, "dht_identity", 12);
        qgp_sha3_512(seed_input, sizeof(seed_input), full_hash);
        memcpy(dht_seed, full_hash, 32);

        // Generate DHT identity
        dht_identity_generate_from_seed(dht_seed, &dht_identity);

        // Cache for next time
        dht_identity_export_to_buffer(dht_identity, &buffer, &size);
        fwrite(buffer, 1, size, cache_f);
    }

    // Initialize DHT with permanent identity
    dht_singleton_init_with_identity(dht_identity);
}
```

### 4.3 Fingerprint-to-Value-ID Mapping

**File:** `/opt/dna-messenger/dht/shared/dht_contact_request.c`

```c
uint64_t dht_fingerprint_to_value_id(const char *fingerprint) {
    // Uses first 16 hex chars (8 bytes) as value_id
    uint64_t value_id = 0;
    for (int i = 0; i < 16; i++) {
        char c = fingerprint[i];
        uint64_t digit = (c >= '0' && c <= '9') ? (c - '0') : (c - 'a' + 10);
        value_id = (value_id << 4) | digit;
    }
    return value_id;
}
```

This links DHT multi-owner tracking to Messenger fingerprint, but the SIGNATURES are still separate.

---

## 5. Solution Options

### 5.1 Option A: Identity Unification (Recommended Long-Term)

**Approach:** Make DHT use the Messenger keypair directly

**Changes Required:**

| File | Change |
|------|--------|
| `messenger/init.c` | Pass Messenger keypair to DHT init instead of deriving separate DHT identity |
| `dht/core/dht_context.cpp` | Accept external Dilithium5 keypair |
| `dht/client/dht_singleton.c` | Initialize with Messenger identity |
| `vendor/opendht-pq/` | May need modifications to accept external identity |

**Benefits:**
- Single signature per value (~5KB instead of ~12KB)
- Single keypair to backup
- Cleaner architecture
- Fingerprint = DHT node_id

**Risks:**
- Significant refactoring
- Migration of existing DHT data
- Potential OpenDHT compatibility issues

### 5.2 Option B: Skip Content Signature (Medium-Term)

**Approach:** Don't sign content with Messenger identity; rely only on DHT signature

**How it works:**
- Content published unsigned (no Messenger signature)
- DHT `putSigned()` adds DHT signature
- DHT owner identity serves as proof of authorship
- Need mapping: DHT node_id → Messenger fingerprint

**Benefits:**
- ~7KB per value (DHT overhead only)
- No code changes to OpenDHT
- Simpler content structures

**Risks:**
- Requires trusted DHT identity → fingerprint mapping
- Less cryptographic independence

### 5.3 Option C: Aggregated Scores (Required Either Way)

**Approach:** Don't fetch individual votes; publish aggregated scores

**Implementation:**
```
User reputation key: SHA256("dna:feeds:reputation:" + fingerprint)
Value: {
    "score": 142,
    "upvotes": 150,
    "downvotes": 8,
    "last_updated": 1706540800,
    "signature": "<Messenger Dilithium5 signature>"
}
Size: ~5KB (constant, regardless of vote count)
```

**Benefits:**
- Constant size regardless of votes
- Fast reputation lookups
- Works with current architecture

**Risks:**
- Users self-report their own score
- Need verification mechanism (day-bucketed vote audit)

---

## 6. Files Reference

### 6.1 Identity System Files

| File | Purpose |
|------|---------|
| `messenger/init.c:374-509` | DHT identity loading and derivation |
| `messenger/keygen.c` | Messenger identity generation |
| `dht/core/dht_context.cpp` | DHT context and putSigned implementation |
| `dht/client/dht_identity.cpp` | DHT identity generation and serialization |
| `dht/client/dht_singleton.c` | Global DHT instance management |
| `src/api/engine/dna_engine_identity.c` | Engine identity loading |

### 6.2 OpenDHT Files

| File | Purpose |
|------|---------|
| `vendor/opendht-pq/src/securedht.cpp:471-514` | putSigned() implementation |
| `vendor/opendht-pq/src/value.cpp:258-264` | Value::sign() - adds DHT signature |
| `vendor/opendht-pq/include/opendht/securedht.h` | SecureDht class definition |

### 6.3 Content Signing Files

| File | Purpose |
|------|---------|
| `dht/client/dna_feed_votes.c` | Vote signing with Messenger identity |
| `dht/keyserver/keyserver_profiles.c` | Profile signing |
| `messenger/messages.c` | Message signing |
| `dht/shared/dht_chunked.c:504-627` | Chunked publish → putSigned |

---

## 7. Recommendations

### 7.1 For Feeds v2 (Immediate)

1. **Use Aggregated Scores** (Option C) - Required regardless of identity unification
2. **Accept current overhead** for initial implementation
3. **Design data structures** to minimize signed content size

### 7.2 For Future Session (Identity Unification)

1. **Research OpenDHT identity injection** - Can we pass external keypair?
2. **Design migration path** - How to handle existing DHT data
3. **Implement Option A** - Unified identity with single Dilithium5 keypair
4. **Measure bandwidth improvement** - Should see ~58% reduction per vote

### 7.3 Priority Order

1. **Phase 1:** Feeds v2 with aggregated scores (works with current architecture)
2. **Phase 2:** Identity unification (separate project)
3. **Phase 3:** Optimize Feeds v2 with unified identity

---

## 8. Verification Commands

To verify the findings in this report:

```bash
# Check DHT identity derivation
grep -n "dht_identity" /opt/dna-messenger/messenger/init.c

# Check putSigned implementation
grep -n "putSigned" /opt/dna-messenger/dht/core/dht_context.cpp

# Check Value::sign
grep -n "Value::sign" /opt/dna-messenger/vendor/opendht-pq/src/value.cpp

# Check SecureDht::putSigned
grep -n "sign\(\*val\)" /opt/dna-messenger/vendor/opendht-pq/src/securedht.cpp
```

---

## 9. Conclusion

The DNA Messenger identity system has a **fundamental architectural issue** where two separate Dilithium5 keypairs are derived from the same mnemonic, resulting in double-signing overhead of ~7KB per DHT value.

For Feeds v2 reputation voting to scale, we must either:
1. **Unify the identities** (long-term, significant work)
2. **Use aggregated scores** (immediate, works around the problem)

The recommended approach is to implement Feeds v2 with aggregated scores first, then tackle identity unification as a separate project.

---

**End of Identity System Technical Report**
