> **⚠️ DESIGN PROPOSAL — NOT IMPLEMENTED**
> The vulnerability described in Section 2 is real and accurately documented. However, the proposed fix (per-contact DHT salt, Sections 3+) has NOT been implemented. No salt exchange, database migrations, or API changes described below exist in code. Current DHT key derivation still uses deterministic SHA3-512.

---

# DHT Key Derivation Privacy Analysis

**Date:** 2026-01-11
**Status:** VULNERABILITY IDENTIFIED - Fix Planned
**Severity:** MEDIUM (Metadata Leak)
**Affects:** All versions through v0.4.28

---

## Executive Summary

The current DHT key derivation scheme for offline messaging uses **deterministic keys** derived from both parties' fingerprints. This allows any third party who knows both fingerprints to:

1. Calculate the exact DHT keys used for communication
2. Monitor those keys via `dht_listen()` to detect communication activity
3. Perform traffic analysis (timing, frequency, direction)

**Message content remains encrypted** (Kyber1024 + AES-256-GCM), but the **existence of communication** is leaked.

---

## Technical Details

### Current Key Derivation (Vulnerable)

#### Outbox Key
**File:** `dht/shared/dht_offline_queue.c:131-144`

```c
// Key format: sender + ":outbox:" + recipient
static void make_outbox_base_key(const char *sender, const char *recipient,
                                  char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "%s:outbox:%s", sender, recipient);
}

void dht_generate_outbox_key(const char *sender, const char *recipient, uint8_t *key_out) {
    char base_key[512];
    make_outbox_base_key(sender, recipient, base_key, sizeof(base_key));
    qgp_sha3_512((const uint8_t*)base_key, strlen(base_key), key_out);
}
```

**Result:** `SHA3-512(sender_fp + ":outbox:" + recipient_fp)`

#### Watermark Key
**File:** `dht/shared/dht_offline_queue.c:1007-1019`

```c
static void make_watermark_base_key(const char *recipient, const char *sender,
                                     char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "%s:watermark:%s", recipient, sender);
}

void dht_generate_watermark_key(const char *recipient, const char *sender, uint8_t *key_out) {
    char base_key[512];
    make_watermark_base_key(recipient, sender, base_key, sizeof(base_key));
    qgp_sha3_512((const uint8_t*)base_key, strlen(base_key), key_out);
}
```

**Result:** `SHA3-512(recipient_fp + ":watermark:" + sender_fp)`

### Other Affected Keys

| DHT Key Type | Derivation | Third-Party Calculable? |
|--------------|------------|------------------------|
| Outbox | `SHA3-512(sender:outbox:recipient)` | YES - if both fps known |
| Watermark | `SHA3-512(recipient:watermark:sender)` | YES - if both fps known |
| Presence | `SHA3-512(dilithium_pubkey)` = fingerprint | YES - fingerprint IS the key |
| Profile | `SHA3-512(fingerprint:profile)` | YES - single fp needed |
| Contact Requests | `SHA3-512(fingerprint:requests)` | YES - single fp needed |
| Contact List | `SHA3-512(fingerprint:contactlist)` | YES - but content encrypted |

---

## Attack Scenario

### Prerequisites
- Attacker knows Alice's fingerprint (public, in her profile)
- Attacker knows Bob's fingerprint (public, in his profile)

### Attack Steps

1. **Calculate DHT keys:**
   ```
   alice_to_bob_outbox = SHA3-512("alice_fp:outbox:bob_fp")
   bob_to_alice_outbox = SHA3-512("bob_fp:outbox:alice_fp")
   alice_watermark = SHA3-512("alice_fp:watermark:bob_fp")
   bob_watermark = SHA3-512("bob_fp:watermark:alice_fp")
   ```

2. **Subscribe to keys:**
   ```c
   dht_listen(ctx, alice_to_bob_outbox, 64, attacker_callback, NULL);
   dht_listen(ctx, bob_to_alice_outbox, 64, attacker_callback, NULL);
   ```

3. **Observe:**
   - Callback fires when Alice sends message to Bob
   - Callback fires when Bob sends message to Alice
   - Callback fires when watermarks update (delivery confirmations)

### Information Leaked

| Metadata | Leaked? | Notes |
|----------|---------|-------|
| Communication exists | YES | DHT key activity reveals relationship |
| Timing of messages | YES | Callback timestamps |
| Frequency | YES | Count callbacks over time |
| Direction | YES | Different keys for A→B vs B→A |
| Message content | NO | Encrypted with Kyber1024 + AES-256-GCM |
| Exact message count | PARTIAL | Chunked storage obscures somewhat |
| Message size | PARTIAL | Chunked storage obscures somewhat |

---

## Proposed Fix: Per-Contact DHT Salt

### Overview

Introduce a **random 32-byte salt** exchanged during contact establishment. DHT keys become unpredictable to third parties who don't possess the salt.

### New Key Derivation

```
OLD: SHA3-512(sender + ":outbox:" + recipient)
NEW: SHA3-512(salt + ":" + sender + ":outbox:" + recipient)
```

Where `salt` is a 32-byte random value known only to the two communicating parties.

### Salt Properties

| Property | Value |
|----------|-------|
| Size | 32 bytes (256 bits) |
| Generation | `qgp_random_bytes()` (cryptographically secure) |
| Storage | Local contacts database only |
| Exchange | Encrypted in contact request/acceptance |
| Lifetime | Permanent per contact pair |

### Implementation Plan

#### Phase 1: Database Schema

**File:** `messenger/contacts.c`

Add column to contacts table:
```sql
ALTER TABLE contacts ADD COLUMN dht_salt BLOB;
```

Add field to contact structure:
```c
typedef struct {
    // ... existing fields ...
    uint8_t dht_salt[32];      // Per-contact DHT key salt
    bool has_dht_salt;         // Salt validity flag
} contact_t;
```

#### Phase 2: Salt Exchange Protocol

**File:** `dht/shared/dht_contact_request.c`

1. **Sending contact request:**
   - Generate 32 random bytes as `my_salt`
   - Include in `dht_contact_request_t` structure
   - Salt encrypted along with rest of request

2. **Accepting contact request:**
   - Extract sender's salt from request
   - Store in contacts database
   - Generate own salt for reverse direction
   - Include own salt in reciprocal request

3. **Contact request structure update:**
   ```c
   typedef struct {
       // ... existing fields ...
       uint8_t dht_salt[32];           // Proposer's salt for key derivation
       bool has_dht_salt;              // v2 field indicator
   } dht_contact_request_t;
   ```

#### Phase 3: Key Derivation Update

**File:** `dht/shared/dht_offline_queue.c`

```c
// NEW: Salt-aware key derivation
static void make_outbox_base_key_v2(
    const uint8_t *salt,           // 32 bytes, may be NULL
    const char *sender,
    const char *recipient,
    char *key_out,
    size_t key_out_size
) {
    if (salt) {
        // New format with salt
        char salt_hex[65];
        bytes_to_hex(salt, 32, salt_hex);
        snprintf(key_out, key_out_size, "%s:%s:outbox:%s", salt_hex, sender, recipient);
    } else {
        // Legacy format (backward compatibility)
        snprintf(key_out, key_out_size, "%s:outbox:%s", sender, recipient);
    }
}
```

#### Phase 4: API Updates

**Files to modify:**
- `src/api/dna_engine.c` - Pass salt to queue functions
- `dht/shared/dht_offline_queue.c` - Accept salt parameter
- `dht/shared/dht_offline_queue.h` - Update function signatures

New API:
```c
int dht_queue_message_v2(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *salt,           // NEW: 32-byte salt or NULL
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint64_t seq_num,
    uint32_t ttl_seconds
);
```

#### Phase 5: Migration Strategy

**For existing contacts (no salt):**

1. Continue using legacy deterministic keys
2. Send salt exchange message on OLD key (one-time)
3. Once both parties have salt, switch to NEW keys
4. Grace period: check BOTH old and new keys for 30 days

**Salt exchange message format:**
```c
typedef struct {
    uint32_t magic;              // 0x53414C54 ("SALT")
    uint8_t version;             // 1
    uint8_t salt[32];            // My salt for this contact
    uint64_t timestamp;          // When generated
    uint8_t signature[4627];     // Dilithium5 signature
} salt_exchange_msg_t;
```

**Migration flow:**
```
1. App updates to new version
2. For each contact without salt:
   a. Generate random 32-byte salt
   b. Send SALT_EXCHANGE on OLD deterministic key (encrypted)
   c. Store salt locally, mark as "pending"
3. When receiving SALT_EXCHANGE:
   a. Store their salt
   b. Send own salt if not already sent
   c. Mark contact as "salt_complete"
4. Once salt_complete:
   a. Use NEW salted keys for sending
   b. Still check OLD keys during grace period
5. After 30-day grace period:
   a. Stop checking old keys
```

---

## Security Analysis

### Before Fix

| Threat | Mitigated? |
|--------|-----------|
| Third party calculates DHT keys | NO |
| Third party monitors communication | NO |
| Third party reads message content | YES (encrypted) |
| Third party performs traffic analysis | NO |

### After Fix

| Threat | Mitigated? |
|--------|-----------|
| Third party calculates DHT keys | YES (needs salt) |
| Third party monitors communication | YES (random keys) |
| Third party reads message content | YES (encrypted) |
| Third party performs traffic analysis | YES (can't find keys) |

### Residual Risks

1. **Salt compromise:** If attacker gains access to local database, salt is exposed
   - Mitigation: Database encryption (already implemented via H2 fix)

2. **First-contact visibility:** Contact request inbox key is still deterministic
   - Mitigation: Accept as acceptable risk (one-time event)

3. **Presence key:** Still fingerprint-based (by design - for discoverability)
   - Mitigation: Presence is intentionally public

---

## Breaking Changes

| Change | Impact | Mitigation |
|--------|--------|------------|
| New DHT keys | Messages on new keys invisible to old clients | Grace period with dual-key lookup |
| Contact request format | Old clients can't parse salt field | Version field + backward compat |
| Database schema | New column required | Migration adds column with NULL default |

---

## Files to Modify

| File | Changes |
|------|---------|
| `messenger/contacts.h` | Add `dht_salt[32]` field |
| `messenger/contacts.c` | Database migration, salt storage |
| `dht/shared/dht_contact_request.h` | Add salt to request structure |
| `dht/shared/dht_contact_request.c` | Salt generation/extraction |
| `dht/shared/dht_offline_queue.h` | Update function signatures |
| `dht/shared/dht_offline_queue.c` | Salt-aware key derivation |
| `src/api/dna_engine.c` | Pass salt through API calls |
| `docs/DHT_SYSTEM.md` | Document new key format |
| `docs/MESSAGE_SYSTEM.md` | Document salt exchange |

---

## Testing Plan

1. **Unit tests:**
   - Salt generation produces 32 random bytes
   - Key derivation with salt differs from without
   - Same salt + fps = same key (deterministic given salt)

2. **Integration tests:**
   - New contact: salt exchanged, new keys used
   - Existing contact: migration flow works
   - Mixed versions: old client can still receive (grace period)

3. **Security tests:**
   - Keys with salt are unpredictable
   - Third party cannot calculate keys without salt

---

## Timeline

| Phase | Description | Effort |
|-------|-------------|--------|
| 1 | Database schema + contact struct | Small |
| 2 | Salt exchange in contact request | Medium |
| 3 | Key derivation update | Small |
| 4 | API updates + callers | Medium |
| 5 | Migration + backward compat | Medium |
| 6 | Testing + documentation | Medium |

---

## References

- `dht/shared/dht_offline_queue.c` - Current key derivation
- `dht/shared/dht_contact_request.c` - Contact request flow
- `docs/DHT_SYSTEM.md` - DHT architecture
- `docs/SECURITY_AUDIT.md` - Security findings

---

## Appendix: Key Derivation Comparison

### Current (Vulnerable)
```
Alice→Bob outbox:  SHA3-512("alice_fp:outbox:bob_fp")
Bob→Alice outbox:  SHA3-512("bob_fp:outbox:alice_fp")
```

Third party who knows both fingerprints can calculate both keys.

### Proposed (Fixed)
```
salt = random 32 bytes (exchanged during contact setup)
Alice→Bob outbox:  SHA3-512(hex(salt) + ":alice_fp:outbox:bob_fp")
Bob→Alice outbox:  SHA3-512(hex(salt) + ":bob_fp:outbox:alice_fp")
```

Third party cannot calculate keys without knowing the salt.
