# Phase 5: Profile System Unification - Design Document

**Date:** 2025-11-16
**Status:** Design Phase
**Goal:** Unify profile systems to eliminate redundancy and inconsistency

## Current State Analysis

### 1. dht_profile.h (Simple DHT Profiles)
**Location:** `dht/shared/dht_profile.{c,h}` (470 lines)
**Purpose:** Lightweight profile for UI display
**Fields:**
- display_name (128 chars)
- bio (512 chars)
- avatar_hash (128 chars)
- location (128 chars)
- website (256 chars)
- created_at, updated_at (timestamps)

**DHT Storage:**
- Key: `SHA3-512(fingerprint + ":profile")`
- TTL: PERMANENT
- Format: JSON, Dilithium5 signed
- value_id: 1 (replacement, not accumulation)

**Consumers:**
- `database/profile_cache.{c,h}` - Local SQLite cache (7d TTL)
- `database/profile_manager.{c,h}` - Smart fetch (cache-first + DHT fallback)
- `imgui_gui/core/app_state.h` - GUI state

**Functions:**
- `dht_profile_publish()` - Publish to DHT
- `dht_profile_fetch()` - Fetch from DHT
- `dht_profile_delete()` - Delete from DHT
- `dht_profile_validate()` - Validation
- `dht_profile_init_empty()` - Initialize empty

### 2. dna_profile.h (Unified Identity)
**Location:** `dht/client/dna_profile.{c,h}` (18,717 lines - massive!)
**Purpose:** Complete identity structure for keyserver
**Fields:**
- **Messenger keys:** fingerprint, dilithium_pubkey, kyber_pubkey
- **DNA name:** registered_name, timestamps, tx_hash, network, version
- **Wallets:** 7 Cellframe + 5 external chains (backbone, kelvpn, riemann, raiden, mileena, subzero, cpunk_testnet, btc, eth, sol, qevm, bnb)
- **Socials:** telegram, x, github, facebook, instagram, linkedin, google
- **Profile:** bio, profile_picture_ipfs
- **Metadata:** timestamp, version
- **Signature:** Dilithium5 signature over entire structure

**Structure:**
```c
typedef struct {
    // Messenger keys
    char fingerprint[129];
    uint8_t dilithium_pubkey[2592];
    uint8_t kyber_pubkey[1568];

    // DNA name registration
    bool has_registered_name;
    char registered_name[256];
    uint64_t name_registered_at;
    uint64_t name_expires_at;
    char registration_tx_hash[67];
    char registration_network[32];
    uint32_t name_version;

    // Wallets (unified)
    dna_wallets_t wallets;

    // Socials
    dna_socials_t socials;

    // Profile
    char bio[512];
    char profile_picture_ipfs[64];

    // Metadata
    uint64_t timestamp;
    uint32_t version;

    // Signature
    uint8_t signature[4627];
} dna_unified_identity_t;
```

**Consumers:**
- `dht/core/dht_keyserver.h` - Keyserver (includes dna_profile.h)
- `dht/keyserver/keyserver_core.h` - Keyserver modules
- `dht/quick_lookup.c`, `dht/test_lookup.c` - Lookup tools
- `legacy-tools/lookup_name.c` - Legacy CLI
- `imgui_gui/main.cpp` - GUI initialization
- `tests/test_dna_profile.c`, `tests/test_simple.c` - Tests
- `gui/MainWindow.cpp` - Qt GUI (deprecated)

**Functions:**
- `dna_profile_create()` / `dna_profile_free()`
- `dna_identity_create()` / `dna_identity_free()`
- `dna_profile_to_json()` / `dna_profile_from_json()`
- `dna_identity_to_json()` / `dna_identity_from_json()`
- `dna_profile_validate()` - Validation
- `dna_validate_wallet_address()` - Wallet validation
- `dna_validate_ipfs_cid()` - IPFS validation
- `dna_validate_name()` - Name validation
- Plus 100+ helper functions for wallet/network operations

## Problem Statement

**Redundancy:**
- `dht_profile_t` fields (display_name, bio, avatar_hash, location, website) overlap with `dna_unified_identity_t` (bio, profile_picture_ipfs)
- Two separate DHT publish/fetch paths
- Two separate cache systems could get out of sync
- Inconsistent TTL (dht_profile: PERMANENT, profile_cache: 7d)

**Missing Fields:**
- `dht_profile_t` lacks social links (Telegram, X, GitHub, etc.)
- `dht_profile_t` lacks wallet addresses for tipping/donations
- `dna_unified_identity_t` lacks display_name, location, website

**Architecture Confusion:**
- Should profile UI show data from `dht_profile_t` or `dna_unified_identity_t`?
- Which one is the "source of truth"?
- How do updates propagate between the two?

## Design Decision: Keep DNA Unified Identity as Source of Truth

**Rationale:**
1. `dna_unified_identity_t` is already used by keyserver (core identity system)
2. It's the most comprehensive structure (includes everything)
3. It's already signed and verified
4. Profile data is a **subset** of identity data
5. UI needs wallet addresses and social links anyway (DNA Board Phase 10.2)

**Approach:**
- **Deprecate** `dht_profile.{c,h}` in favor of `dna_unified_identity_t`
- **Extend** `dna_unified_identity_t` to include missing fields (display_name, location, website)
- **Update** profile cache to store full `dna_unified_identity_t`
- **Update** profile manager to fetch `dna_unified_identity_t`
- **Add** helper functions to extract display-only data from `dna_unified_identity_t`

## Unified Profile Schema

### Extended dna_unified_identity_t

Add missing fields to `dna_unified_identity_t`:

```c
typedef struct {
    // ===== MESSENGER KEYS =====
    char fingerprint[129];
    uint8_t dilithium_pubkey[2592];
    uint8_t kyber_pubkey[1568];

    // ===== DNA NAME REGISTRATION =====
    bool has_registered_name;
    char registered_name[256];
    uint64_t name_registered_at;
    uint64_t name_expires_at;
    char registration_tx_hash[67];
    char registration_network[32];
    uint32_t name_version;

    // ===== PROFILE DATA =====
    char display_name[128];          // NEW: Display name (optional, defaults to name or fingerprint)
    char bio[512];                   // EXISTING
    char avatar_hash[128];           // NEW: SHA3-512 hash of avatar (for lookup)
    char profile_picture_ipfs[64];   // EXISTING: IPFS CID for avatar
    char location[128];              // NEW: Location
    char website[256];               // NEW: Website URL

    dna_wallets_t wallets;           // EXISTING: Wallet addresses
    dna_socials_t socials;           // EXISTING: Social profiles

    // ===== METADATA =====
    uint64_t created_at;             // NEW: Profile creation timestamp
    uint64_t updated_at;             // NEW: Last update timestamp
    uint64_t timestamp;              // EXISTING: Entry timestamp
    uint32_t version;                // EXISTING: Entry version

    // ===== SIGNATURE =====
    uint8_t signature[4627];         // EXISTING: Dilithium5 signature
} dna_unified_identity_t;
```

**New fields:**
- `display_name[128]` - Human-readable name (e.g., "Alice Smith")
- `avatar_hash[128]` - SHA3-512 of avatar for quick comparisons
- `location[128]` - Geographic location
- `website[256]` - Personal website URL
- `created_at` - Profile creation timestamp
- `updated_at` - Last update timestamp

**Backward Compatibility:**
- Old identities without these fields will have empty strings / zero timestamps
- Validation allows empty fields (all profile fields are optional)

### Display-Only Helper Structure

For UI components that only need display data:

```c
/**
 * Display-only profile data (extracted from dna_unified_identity_t)
 * Used for UI rendering without exposing full identity
 */
typedef struct {
    char fingerprint[129];
    char display_name[128];
    char bio[512];
    char avatar_hash[128];
    char location[128];
    char website[256];

    // Selected social links
    char telegram[128];
    char x[128];
    char github[128];

    // Selected wallet addresses (for tipping)
    char backbone[120];
    char btc[128];
    char eth[128];

    uint64_t updated_at;
} dna_display_profile_t;
```

**Helper function:**
```c
/**
 * Extract display profile from unified identity
 * @param identity Full identity structure
 * @param display_out Output display profile (caller provides buffer)
 */
void dna_identity_to_display_profile(
    const dna_unified_identity_t *identity,
    dna_display_profile_t *display_out
);
```

## Migration Plan

### Step 1: Extend dna_unified_identity_t
**Files:** `dht/client/dna_profile.{c,h}`

1. Add new fields to `dna_unified_identity_t` struct
2. Update `dna_identity_to_json()` to serialize new fields
3. Update `dna_identity_from_json()` to parse new fields (with defaults)
4. Update `dna_profile_validate()` to validate new fields
5. Add `dna_identity_to_display_profile()` helper

**Estimated LOC:** +200 lines

### Step 2: Update Profile Cache
**Files:** `database/profile_cache.{c,h}`

1. Change cache DB schema from `dht_profile_t` to `dna_unified_identity_t`
2. Migration: Add new columns (or recreate table)
3. Update `profile_cache_get()` to return `dna_unified_identity_t*`
4. Update `profile_cache_set()` to accept `dna_unified_identity_t*`
5. Keep 7-day TTL for staleness detection

**SQL Migration:**
```sql
-- Option 1: Recreate table (lose old cache - acceptable)
DROP TABLE IF EXISTS profiles;
CREATE TABLE profiles (
    fingerprint TEXT PRIMARY KEY,
    identity_json TEXT NOT NULL,           -- Full dna_unified_identity_t
    cached_at INTEGER NOT NULL,
    UNIQUE(fingerprint)
);
CREATE INDEX idx_cached_at ON profiles(cached_at);

-- Option 2: Preserve old data (migration)
ALTER TABLE profiles ADD COLUMN identity_json TEXT;
-- Migrate old data to new format (requires conversion function)
```

**Estimated LOC:** ~150 lines modified

### Step 3: Update Profile Manager
**Files:** `database/profile_manager.{c,h}`

1. Change API signatures from `dht_profile_t*` to `dna_unified_identity_t*`
2. Update `profile_manager_get_profile()` to fetch unified identity
3. Update `profile_manager_refresh_profile()` to use keyserver lookup
4. Remove dependency on `dht/shared/dht_profile.h`
5. Add dependency on `dht/client/dna_profile.h`

**Key change:**
```c
// OLD
int profile_manager_get_profile(const char *user_fingerprint, dht_profile_t *profile_out);

// NEW
int profile_manager_get_profile(const char *user_fingerprint, dna_unified_identity_t **identity_out);
```

**Estimated LOC:** ~100 lines modified

### Step 4: Update GUI Consumers
**Files:** `imgui_gui/core/app_state.h`, `imgui_gui/screens/*`

1. Change `#include "../../dht/dht_profile.h"` to `#include "../../dht/client/dna_profile.h"`
2. Replace `dht_profile_t` with `dna_display_profile_t` in UI state
3. Use `dna_identity_to_display_profile()` to convert fetched identities
4. Update profile editor to edit full `dna_unified_identity_t`

**Estimated LOC:** ~50 lines modified across multiple screens

### Step 5: Deprecate dht_profile.{c,h}
**Files:** `dht/shared/dht_profile.{c,h}`

1. Add deprecation notice to header
2. Remove from CMakeLists.txt (or mark as deprecated)
3. Move to `legacy/` directory (preserve for reference)
4. Update CLAUDE.md to reflect new architecture

**Deprecation notice:**
```c
/**
 * DEPRECATED: Use dna_profile.h (dna_unified_identity_t) instead
 * This module is preserved for reference only.
 * @deprecated Since 2025-11-16
 */
```

### Step 6: Update DHT Keyserver Integration
**Files:** `dht/keyserver/*.c`

1. Verify keyserver already uses `dna_unified_identity_t`
2. Ensure profile fetch uses `dna_identity_from_json()`
3. Update any hardcoded field references to use new fields

**Estimated LOC:** ~20 lines verification

### Step 7: Testing
**Files:** `tests/test_dna_profile.c`, new test file

1. Test extended `dna_unified_identity_t` serialization/deserialization
2. Test profile cache migration
3. Test profile manager with unified identity
4. Test GUI display profile conversion
5. End-to-end test: publish → fetch → cache → display

**Estimated LOC:** +150 lines of tests

## DHT Storage Updates

### Keyserver Entry (No Change)
- Key: `SHA3-512(fingerprint + ":profile")`
- Value: JSON serialization of `dna_unified_identity_t`
- TTL: PERMANENT
- Signature: Dilithium5 over entire structure

### Profile Cache (Updated Schema)
- Database: `~/.dna/<identity>_profiles.db`
- Table: `profiles`
- Columns:
  - `fingerprint TEXT PRIMARY KEY`
  - `identity_json TEXT NOT NULL` (full `dna_unified_identity_t`)
  - `cached_at INTEGER NOT NULL`
- TTL: 7 days (stale detection, not deletion)

## API Changes Summary

### Deprecated APIs (dht_profile.h)
```c
// DEPRECATED
int dht_profile_publish(dht_context_t *dht_ctx, const char *user_fingerprint, const dht_profile_t *profile, const uint8_t *dilithium_privkey);
int dht_profile_fetch(dht_context_t *dht_ctx, const char *user_fingerprint, dht_profile_t *profile_out);
int dht_profile_delete(dht_context_t *dht_ctx, const char *user_fingerprint);
bool dht_profile_validate(const dht_profile_t *profile);
void dht_profile_init_empty(dht_profile_t *profile_out);
```

### New APIs (dna_profile.h extensions)
```c
// NEW helper for UI
void dna_identity_to_display_profile(const dna_unified_identity_t *identity, dna_display_profile_t *display_out);

// EXISTING (already in dna_profile.h)
dna_unified_identity_t* dna_identity_create(void);
void dna_identity_free(dna_unified_identity_t *identity);
char* dna_identity_to_json(const dna_unified_identity_t *identity);
int dna_identity_from_json(const char *json, dna_unified_identity_t **identity_out);
int dna_profile_validate(const dna_profile_data_t *profile); // Extend for unified identity
```

### Updated APIs (profile_manager.h)
```c
// OLD
int profile_manager_get_profile(const char *user_fingerprint, dht_profile_t *profile_out);
int profile_manager_refresh_profile(const char *user_fingerprint, dht_profile_t *profile_out);

// NEW
int profile_manager_get_profile(const char *user_fingerprint, dna_unified_identity_t **identity_out);
int profile_manager_refresh_profile(const char *user_fingerprint, dna_unified_identity_t **identity_out);
```

## Benefits

1. **Single Source of Truth:** `dna_unified_identity_t` is the canonical profile representation
2. **No Redundancy:** Eliminates duplicate profile storage and sync issues
3. **Feature Complete:** UI gets access to wallets, socials, and all profile fields
4. **Consistent Caching:** One cache system for all profile data
5. **DNA Board Ready:** Profile viewer can show tipping addresses and social links
6. **Keyserver Integration:** Profile data seamlessly integrates with identity system
7. **Backward Compatible:** Old keyserver entries continue to work (missing fields default to empty)

## Risks and Mitigation

**Risk 1: Cache Migration Failure**
- **Mitigation:** Accept cache clear (7d TTL means data refreshes anyway)
- **Fallback:** Recreate cache DB if migration fails

**Risk 2: Larger DHT Values**
- **Mitigation:** New fields add ~600 bytes (negligible vs. existing ~25KB identity)
- **Impact:** Minimal (identities already large due to keys + signature)

**Risk 3: Breaking GUI Code**
- **Mitigation:** Introduce `dna_display_profile_t` as intermediate step
- **Testing:** Comprehensive GUI testing before commit

**Risk 4: Performance (Larger Cache)**
- **Mitigation:** SQLite handles 25KB JSON efficiently
- **Optimization:** Only fetch/deserialize when needed (lazy loading)

## Timeline

- **Step 1 (Extend dna_profile.h):** 1-2 hours
- **Step 2 (Update cache):** 1 hour
- **Step 3 (Update manager):** 1 hour
- **Step 4 (Update GUI):** 1-2 hours
- **Step 5 (Deprecate old):** 30 min
- **Step 6 (Keyserver verify):** 30 min
- **Step 7 (Testing):** 2 hours

**Total Estimated Time:** 7-9 hours

## Success Criteria

- ✅ `dna_unified_identity_t` includes all profile fields
- ✅ Profile cache stores full unified identities
- ✅ Profile manager fetches from keyserver → cache works
- ✅ GUI displays profiles correctly (name, bio, avatar, wallets, socials)
- ✅ `dht_profile.{c,h}` deprecated and moved to legacy
- ✅ All tests passing
- ✅ No memory leaks
- ✅ Documentation updated

## Next Steps

1. Review and approve this design
2. Implement Step 1 (extend dna_profile.h)
3. Implement Steps 2-4 (cache + manager + GUI)
4. Deprecate old code (Step 5)
5. Test thoroughly (Step 7)
6. Commit and push Phase 5

---

**Last Updated:** 2025-11-16
**Status:** Ready for Implementation
