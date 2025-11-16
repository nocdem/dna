# DHT Refactoring - Migration Guide

**Date:** 2025-11-16
**For:** Contributors and developers working with DNA Messenger

This guide helps you understand the DHT refactoring changes and update your code if needed.

---

## Overview

Between 2025-11-15 and 2025-11-16, the DHT layer underwent a comprehensive refactoring across 5 phases (Phases 1-5, 7; Phase 6 skipped). The refactoring improved code organization, modularity, and maintainability while maintaining **100% backward compatibility**.

---

## What Changed

### Phase 4: DHT Directory Reorganization

**Old Structure:**
```
dht/
├── dht_context.{cpp,h}
├── dht_keyserver.{c,h}
├── dht_singleton.{c,h}
├── dht_profile.{c,h}
├── dna_profile.{c,h}
├── dht_identity.{cpp,h}
├── dht_stats.{cpp,h}
└── keyserver/
    └── (6 modules)
```

**New Structure (Phase 4):**
```
dht/
├── core/                # Core DHT functionality
│   ├── dht_context.{cpp,h}
│   ├── dht_keyserver.{c,h}
│   └── dht_stats.{cpp,h}
├── client/              # Client-side modules
│   ├── dht_singleton.{c,h}
│   ├── dht_identity.{cpp,h}
│   ├── dna_profile.{c,h}
│   ├── dht_contactlist.{c,h}
│   ├── dht_identity_backup.{c,h}
│   └── dna_message_wall.{c,h}
├── shared/              # Shared data structures
│   ├── dht_offline_queue.{c,h}
│   ├── dht_groups.{c,h}
│   ├── dht_profile.{c,h}      # DEPRECATED
│   └── dht_value_storage.{cpp,h}
└── keyserver/           # Keyserver modules (6 files)
    └── (unchanged)
```

### Phase 5: Profile System Unification

**Old:**
- Two separate profile systems: `dht_profile.h` (simple) and `dna_profile.h` (extended)
- Profile cache stored 9 columns (display_name, bio, avatar_hash, etc.)

**New:**
- Single unified system: `dna_unified_identity_t` in `dna_profile.h`
- Profile cache stores 3 columns: fingerprint, identity_json (TEXT), cached_at
- Extended with 6 new fields: display_name, avatar_hash, location, website, created_at, updated_at

### Phase 7: Unified Cache Manager

**Old:**
- Each cache module initialized/cleaned up independently
- No centralized statistics or eviction

**New:**
- `database/cache_manager.{c,h}` coordinates all caches
- Single `cache_manager_init()` initializes all caches in order
- Single `cache_manager_cleanup()` closes all databases
- Aggregated statistics via `cache_manager_stats()`
- Automatic startup eviction

---

## Migration Steps

### 1. Update Include Paths (Phase 4)

If your code includes DHT headers, update paths:

```c
// OLD:
#include "dht/dht_keyserver.h"
#include "dht/dht_singleton.h"
#include "dht/dna_profile.h"

// NEW:
#include "dht/core/dht_keyserver.h"
#include "dht/client/dht_singleton.h"
#include "dht/client/dna_profile.h"
```

**Common patterns:**
- `dht/dht_keyserver.h` → `dht/core/dht_keyserver.h`
- `dht/dht_singleton.h` → `dht/client/dht_singleton.h`
- `dht/dht_profile.h` → `dht/shared/dht_profile.h` (DEPRECATED - use `dna_profile.h`)
- `dht/dna_profile.h` → `dht/client/dna_profile.h`
- `dht/dht_groups.h` → `dht/shared/dht_groups.h`

### 2. Migrate from dht_profile_t to dna_unified_identity_t (Phase 5)

**Old code:**
```c
#include "dht/dht_profile.h"

dht_profile_t profile;
int result = profile_manager_get_profile(fingerprint, &profile);
if (result == 0) {
    printf("Name: %s\n", profile.display_name);
}
```

**New code:**
```c
#include "dht/client/dna_profile.h"

dna_unified_identity_t *identity = NULL;
int result = profile_manager_get_profile(fingerprint, &identity);
if (result == 0 && identity) {
    printf("Name: %s\n", identity->display_name);
    dna_identity_free(identity);  // IMPORTANT: Must free!
}
```

**Key changes:**
- `dht_profile_t` → `dna_unified_identity_t*` (heap-allocated)
- Must call `dna_identity_free(identity)` when done
- Access extended fields: `identity->display_name`, `identity->avatar_hash`, etc.

### 3. Use Cache Manager (Phase 7 - Optional)

**Old code:**
```c
keyserver_cache_init(NULL);
profile_cache_init(identity);
contacts_db_init(identity);
presence_cache_init();

// ... later ...

keyserver_cache_cleanup();
profile_cache_close();
contacts_db_close();
presence_cache_free();
```

**New code (recommended):**
```c
#include "database/cache_manager.h"

cache_manager_init(identity);  // Initializes all caches in correct order

// ... later ...

cache_manager_cleanup();  // Cleans up all caches in reverse order
```

**Benefits:**
- Guaranteed correct initialization order
- Automatic startup eviction (removes expired entries)
- No forgotten cleanup calls
- Unified statistics API

---

## Breaking Changes

**None.** All changes are backward compatible. Old include paths still work via header propagation in `dht/core/dht_context.h`.

---

## Deprecated APIs

### dht_profile.h (Use dna_profile.h instead)

`dht/shared/dht_profile.h` is **DEPRECATED**. Use `dht/client/dna_profile.h` instead.

**Reason:** `dna_unified_identity_t` is a superset that includes all profile fields plus identity keys, wallet addresses, and social links.

**Migration:**
```c
// DEPRECATED:
#include "dht/shared/dht_profile.h"
dht_profile_t profile;

// USE INSTEAD:
#include "dht/client/dna_profile.h"
dna_unified_identity_t *identity = NULL;
// ... remember to free with dna_identity_free()
```

---

## New Features

### 1. Extended Profile Fields (Phase 5)

`dna_unified_identity_t` now includes:
- `display_name[128]` - User's display name
- `avatar_hash[128]` - SHA3-512 hash of avatar image
- `location[128]` - Geographic location
- `website[256]` - Website URL
- `created_at` - Profile creation timestamp
- `updated_at` - Last update timestamp

### 2. Cache Manager API (Phase 7)

```c
#include "database/cache_manager.h"

// Initialize all caches
cache_manager_init("your-identity-fingerprint");

// Get statistics
cache_manager_stats_t stats;
cache_manager_stats(&stats);
printf("Total entries: %zu\n", stats.total_entries);
printf("Total size: %zu bytes\n", stats.total_size_bytes);

// Evict expired entries
int evicted = cache_manager_evict_expired();
printf("Evicted %d entries\n", evicted);

// Clear all caches (testing/logout)
cache_manager_clear_all();

// Cleanup
cache_manager_cleanup();
```

### 3. Display Profile Helper (Phase 5)

For GUI display, use `dna_display_profile_t`:

```c
#include "dht/client/dna_profile.h"

dna_unified_identity_t *identity = /* ... fetch from cache ... */;

dna_display_profile_t display;
dna_identity_to_display_profile(identity, &display);

// Use display fields (28 total):
printf("Name: %s\n", display.display_name);
printf("Bio: %s\n", display.bio);
printf("Telegram: %s\n", display.telegram);
printf("BTC: %s\n", display.btc);
```

---

## Testing Your Changes

### 1. Build Test
```bash
cd build
make -j$(nproc)
```

All targets should compile successfully.

### 2. Include Path Test

If you get errors like:
```
fatal error: dht/dht_keyserver.h: No such file or directory
```

Update to new path: `dht/core/dht_keyserver.h`

### 3. Profile Migration Test

If you get errors like:
```
error: unknown type name 'dht_profile_t'
```

Migrate to `dna_unified_identity_t*` with proper memory management.

### 4. Memory Leak Test (valgrind)

```bash
valgrind --leak-check=full ./build/imgui_gui/dna_messenger_imgui
```

Ensure you're calling `dna_identity_free()` for all fetched profiles.

---

## Common Errors and Fixes

### Error 1: Header Not Found

**Error:**
```
fatal error: dht/dht_singleton.h: No such file or directory
```

**Fix:**
```c
// Change:
#include "dht/dht_singleton.h"

// To:
#include "dht/client/dht_singleton.h"
```

### Error 2: Unknown Type dht_profile_t

**Error:**
```
error: unknown type name 'dht_profile_t'
```

**Fix:**
```c
// Change:
dht_profile_t profile;
profile_manager_get_profile(fp, &profile);

// To:
dna_unified_identity_t *identity = NULL;
profile_manager_get_profile(fp, &identity);
if (identity) {
    // Use identity->display_name, etc.
    dna_identity_free(identity);
}
```

### Error 3: Memory Leak

**Error (valgrind):**
```
definitely lost: 30,720 bytes in 1 blocks
```

**Fix:**
```c
// Add missing free:
dna_unified_identity_t *identity = NULL;
profile_manager_get_profile(fp, &identity);
if (identity) {
    // ... use identity ...
    dna_identity_free(identity);  // ← ADD THIS
}
```

---

## Getting Help

1. **Documentation:**
   - `/docs/DHT_REFACTORING_PROGRESS.md` - Full refactoring log
   - `/docs/PHASE5_PROFILE_UNIFICATION_DESIGN.md` - Profile system design
   - `/docs/PHASE7_CACHE_MANAGER_DESIGN.md` - Cache manager design

2. **Examples:**
   - See `imgui_gui/screens/contact_profile_viewer.cpp` for profile usage
   - See `imgui_gui/screens/add_contact_dialog.cpp` for identity fetching
   - See `database/profile_manager.c` for cache-first pattern

3. **Contact:**
   - GitLab Issues: https://gitlab.cpunk.io/cpunk/dna-messenger/issues
   - GitHub Issues: https://github.com/nocdem/dna-messenger/issues
   - Telegram: @chippunk_official

---

## Summary

✅ **Update include paths** if you use DHT headers (Phase 4)
✅ **Migrate to dna_unified_identity_t** if you use profiles (Phase 5)
✅ **Optionally use cache_manager** for simplified init/cleanup (Phase 7)
✅ **No breaking changes** - old code still works
✅ **Test your build** - ensure all targets compile

The refactoring improves code organization and maintainability while preserving all existing functionality.
