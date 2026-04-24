> **ARCHIVED 2026-04-24** — RESOLVED in v0.4.0. `dnac_spend_request_t` now carries the full serialized TX instead of a single nullifier; witnesses extract and verify ALL input nullifiers. See `dnac/include/dnac/nodus.h:105-106` ("v0.4.0: Now carries full serialized transaction...") and `dnac/src/transaction/builder.c:335-361` (loop over `tx->inputs[i].nullifier`). The "Status: CRITICAL" below is stale. Kept for history.

# Problem: Multi-Input Double-Spend Vulnerability

**Status:** CRITICAL
**Severity:** Critical (funds at risk)
**Date:** 2026-01-23

---

## Summary

The SpendRequest protocol only sends ONE nullifier to witness servers, regardless of how many inputs a transaction has. This allows double-spending of all inputs except the first one.

---

## Vulnerability Details

### The Bug

```c
// include/dnac/nodus.h:82-89
typedef struct {
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];  // ← SINGLE field, not array
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t signature[DNAC_SIGNATURE_SIZE];
    uint64_t timestamp;
    uint64_t fee_amount;
} dnac_spend_request_t;
```

```c
// src/transaction/builder.c:285-288
/* Use first input's nullifier for spend request */
if (tx->input_count > 0) {
    memcpy(request.nullifier, tx->inputs[0].nullifier, DNAC_NULLIFIER_SIZE);
}
// inputs[1], inputs[2], etc. are IGNORED
```

### Attack Scenario

```
Transaction TX1:
  inputs: [UTXO_A (nullifier_A), UTXO_B (nullifier_B)]
  outputs: [payment to victim]

What gets sent to witnesses:
  SpendRequest { nullifier: nullifier_A }  // nullifier_B missing!

Witness records:
  nullifier_A → spent

Later, attacker creates TX2:
  inputs: [UTXO_B (nullifier_B)]  // Same UTXO, never recorded!
  outputs: [payment to attacker]

Witness check:
  nullifier_B not in database → APPROVED ✓

Result: UTXO_B spent twice = DOUBLE SPEND
```

### Affected Code Paths

| File | Line | Issue |
|------|------|-------|
| `include/dnac/nodus.h` | 84 | Single nullifier field |
| `src/transaction/builder.c` | 287 | Only first nullifier copied |
| `src/bft/consensus.c` | 243-247 | Only one nullifier checked |
| `src/bft/consensus.c` | 268-269 | Only one nullifier stored |
| `src/witness/bft_main.c` | 376-451 | Single nullifier parameter |

### Transaction Limits

```c
// include/dnac/transaction.h:25
#define DNAC_TX_MAX_INPUTS  16
```

Up to 16 inputs supported, but only 1 nullifier verified = 15 potential double-spends per TX.

---

## Impact Assessment

| Severity | Impact |
|----------|--------|
| **Critical** | Complete bypass of double-spend protection |
| **Exploitable** | Yes, trivially |
| **Funds at Risk** | All multi-input transactions |
| **Detection** | None - witnesses have no record |

### Who Can Exploit

- Any wallet owner spending multiple UTXOs
- Requires no special access or tools
- Attack is invisible to current system

---

## Solution Options

### Option A: Array of Nullifiers in SpendRequest

**Change:** Expand SpendRequest to carry all nullifiers

```c
typedef struct {
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE];  // Array
    uint8_t nullifier_count;                                       // Count
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t signature[DNAC_SIGNATURE_SIZE];
    uint64_t timestamp;
    uint64_t fee_amount;
} dnac_spend_request_t;
```

**Pros:**
- Single request, all nullifiers included
- Atomic verification (all-or-nothing)
- Minimal protocol changes

**Cons:**
- Larger message size (up to 16 × 64 = 1024 bytes extra)
- Breaking change to wire protocol
- All witnesses must upgrade simultaneously

**Files to modify:**
- `include/dnac/nodus.h` - Structure definition
- `src/transaction/builder.c` - Copy all nullifiers
- `src/nodus/client.c` - Serialize all nullifiers
- `src/witness/bft_main.c` - Parse all nullifiers
- `src/bft/consensus.c` - Check and store all nullifiers
- `src/bft/serialize.c` - Wire format changes

---

### Option B: One SpendRequest Per Input

**Change:** Loop and send separate request for each input

```c
// In builder.c dnac_tx_broadcast():
for (int i = 0; i < tx->input_count; i++) {
    dnac_spend_request_t request = {0};
    memcpy(request.nullifier, tx->inputs[i].nullifier, ...);
    // ... fill rest ...
    rc = dnac_witness_request(ctx, &request, witnesses, &witness_count);
    if (rc != DNAC_SUCCESS) {
        // Rollback? How?
        return rc;
    }
}
```

**Pros:**
- No protocol changes needed
- Backward compatible
- Simple implementation

**Cons:**
- Multiple round-trips (slow)
- Atomicity problem: What if input 3 fails after 1,2 succeed?
- Rollback mechanism needed
- Race conditions between requests

**Files to modify:**
- `src/transaction/builder.c` - Add loop
- Need rollback/compensation logic

---

### Option C: Transaction-Level Witness Verification

**Change:** Witnesses verify the full transaction, not individual nullifiers

```c
typedef struct {
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t tx_data[MAX_TX_SIZE];    // Full serialized TX
    size_t tx_len;
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t signature[DNAC_SIGNATURE_SIZE];
    uint64_t timestamp;
    uint64_t fee_amount;
} dnac_spend_request_t;
```

Witness extracts all nullifiers from TX and verifies each.

**Pros:**
- Witnesses see complete transaction
- Can verify balance, signatures, everything
- Most thorough validation
- Future-proof for additional checks

**Cons:**
- Largest message size
- Witnesses must parse full TX
- More complex implementation
- Breaking protocol change

**Files to modify:**
- `include/dnac/nodus.h` - New structure
- `src/transaction/builder.c` - Send full TX
- `src/nodus/client.c` - Serialize TX
- `src/witness/bft_main.c` - Parse and verify TX
- `src/bft/consensus.c` - Extract and check all nullifiers

---

### Option D: Hash-Based Multi-Nullifier Commitment

**Change:** Send hash of all nullifiers, witnesses verify against known set

```c
typedef struct {
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t nullifier_root[64];           // SHA3-512(all nullifiers)
    uint8_t nullifiers[16][64];           // All nullifiers
    uint8_t nullifier_count;
    // ... rest same
} dnac_spend_request_t;
```

**Pros:**
- Commitment scheme prevents tampering
- Witnesses can verify completeness
- Moderate message size

**Cons:**
- More complex crypto
- Still need all nullifiers in message
- Overkill for current needs

---

## Recommended Solution

**Option A (Array of Nullifiers)** is recommended because:

1. **Atomic** - All nullifiers verified together
2. **Simple** - Straightforward array expansion
3. **Efficient** - Single round-trip
4. **Clean** - No rollback logic needed

### Migration Strategy

1. **Version the protocol** - Add version field to SpendRequest
2. **Witnesses accept both** - Old (v1) and new (v2) format during transition
3. **Clients upgrade first** - Start sending v2 format
4. **Deprecate v1** - After all clients upgraded

---

## Verification Test

After fix, this test should FAIL (double-spend rejected):

```bash
# 1. Create wallet with 2 UTXOs
mint <wallet> 100
mint <wallet> 100

# 2. Create TX spending both
send <recipient> 150  # Uses both UTXOs

# 3. Try to spend second UTXO again
# This should be REJECTED because nullifier_B was recorded

# Current behavior: APPROVED (bug)
# Expected after fix: REJECTED (secure)
```

---

## Timeline

| Phase | Task | Duration |
|-------|------|----------|
| 1 | Protocol design | 1 day |
| 2 | Implement SpendRequest changes | 1 day |
| 3 | Implement witness changes | 1 day |
| 4 | Testing | 1 day |
| 5 | Deployment | 1 day |

**Priority:** CRITICAL - Must fix before any real usage

---

## References

- SpendRequest: `include/dnac/nodus.h:82-89`
- Broadcast: `src/transaction/builder.c:257-423`
- BFT consensus: `src/bft/consensus.c:216-334`
- Nullifier storage: `src/witness/nullifier.c`
