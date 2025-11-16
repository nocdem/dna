# Phase 7: Unified Cache Manager Design

**Date:** 2025-11-16
**Status:** Design Phase
**Goal:** Consolidate cache lifecycle management under single manager

## Problem Statement

Currently we have 4 separate cache implementations:
1. **Keyserver Cache** (`keyserver_cache.{c,h}`) - Public keys, 7d TTL, global
2. **Profile Cache** (`profile_cache.{c,h}`) - Profiles, 7d TTL, per-identity
3. **Presence Cache** (`presence_cache.{c,h}`) - Online status, 5min TTL, in-memory
4. **Contacts DB** (`contacts_db.{c,h}`) - Contact lists, permanent, per-identity

### Current Issues
- No centralized lifecycle management (each module manages own database)
- No unified cleanup on startup (expired entries left in DB)
- No shared statistics API (can't see total cache size/counts)
- Inconsistent init/cleanup patterns across modules

### NOT a Problem
- Different storage formats (BLOB vs JSON vs structured) - this is correct!
- Different TTL policies (7d vs 5min vs permanent) - this is intentional!
- Per-identity vs global databases - this is architectural!

## Design Philosophy

**NOT a "unified database"** - Keep separate SQLite files for modularity

**IS a "lifecycle coordinator"** - Single entry point for:
- Initialization (in correct order)
- Cleanup (in reverse order)
- Statistics aggregation
- Automatic eviction on startup

## Proposed API

### database/cache_manager.h

```c
typedef struct {
    size_t total_entries;           // Total cached entries across all caches
    size_t total_size_bytes;        // Approximate disk usage
    size_t keyserver_entries;       // Keyserver cache count
    size_t profile_entries;         // Profile cache count (all identities)
    size_t presence_entries;        // Presence cache count (in-memory)
    size_t expired_entries;         // Total expired but not yet evicted
} cache_manager_stats_t;

// Initialize ALL cache modules (in dependency order)
int cache_manager_init(const char *identity);  // NULL = global caches only

// Cleanup ALL cache modules (in reverse order)
void cache_manager_cleanup(void);

// Run eviction on ALL caches (remove expired entries)
int cache_manager_evict_expired(void);

// Get aggregated statistics across all caches
int cache_manager_stats(cache_manager_stats_t *stats_out);

// Clear ALL caches (for testing, logout, etc.)
void cache_manager_clear_all(void);
```

### Initialization Order

```c
int cache_manager_init(const char *identity) {
    // 1. Global caches first
    keyserver_cache_init(NULL);  // ~/.dna/keyserver_cache.db

    // 2. Per-identity caches (if identity provided)
    if (identity) {
        profile_cache_init(identity);  // ~/.dna/<identity>_profiles.db
        contacts_db_init(identity);    // ~/.dna/<identity>_contacts.db
    }

    // 3. In-memory caches last
    presence_cache_init();  // In-memory only

    // 4. Run startup eviction (clean expired entries from previous run)
    cache_manager_evict_expired();

    return 0;
}
```

### Cleanup Order (Reverse)

```c
void cache_manager_cleanup(void) {
    // Reverse order from init
    presence_cache_free();
    // contacts_db cleanup (if needed)
    profile_cache_cleanup();  // Will be added
    keyserver_cache_cleanup();
}
```

## Implementation Plan

### Step 1: Add Missing Cleanup Functions

Some cache modules are missing explicit cleanup:
- `profile_cache.c` - Add `profile_cache_cleanup()` (close SQLite connection)
- `contacts_db.c` - Add `contacts_db_cleanup()` (if needed)

### Step 2: Create cache_manager.{c,h}

New module in `database/cache_manager.{c,h}` (~200 lines):
- Wraps existing cache init/cleanup calls
- Aggregates statistics from each cache
- Implements eviction across all caches
- No new database - just coordination layer

### Step 3: Update Consumer Code

**messenger/init.c** (or wherever messenger context is created):
```c
// OLD:
keyserver_cache_init(NULL);
profile_cache_init(ctx->identity);
contacts_db_init(ctx->identity);
presence_cache_init();

// NEW:
cache_manager_init(ctx->identity);
```

**messenger cleanup**:
```c
// OLD:
keyserver_cache_cleanup();
presence_cache_free();

// NEW:
cache_manager_cleanup();
```

### Step 4: Add Statistics UI (Optional Enhancement)

In ImGui GUI, add "Cache Statistics" screen:
```cpp
void CacheStatsScreen::render(AppState& state) {
    cache_manager_stats_t stats;
    cache_manager_stats(&stats);

    ImGui::Text("Total Cached Entries: %zu", stats.total_entries);
    ImGui::Text("Disk Usage: %.2f MB", stats.total_size_bytes / 1024.0 / 1024.0);
    ImGui::Text("Expired Entries: %zu", stats.expired_entries);

    if (ImGui::Button("Clear All Caches")) {
        cache_manager_clear_all();
    }
}
```

## Benefits

✅ **Single initialization point** - Easier to maintain, correct order guaranteed
✅ **Automatic cleanup** - No forgotten cleanup calls
✅ **Unified statistics** - See total cache usage at a glance
✅ **Startup optimization** - Evict expired entries on launch (faster DHT queries)
✅ **Testing helper** - `cache_manager_clear_all()` for clean test state

## Non-Goals

❌ **NOT merging databases** - Keep separate SQLite files for modularity
❌ **NOT changing cache formats** - Each cache keeps its schema
❌ **NOT enforcing uniform TTL** - Different TTLs are intentional
❌ **NOT adding query interface** - Use module-specific APIs for queries

## Code Changes

### Files to Create
- `database/cache_manager.h` (100 lines)
- `database/cache_manager.c` (150 lines)

### Files to Modify
- `database/profile_cache.{c,h}` - Add `profile_cache_cleanup()` function
- `database/contacts_db.{c,h}` - Add `contacts_db_cleanup()` if missing
- `messenger/init.c` (or wherever init happens) - Replace individual calls with `cache_manager_init()`
- `CMakeLists.txt` - Add cache_manager.c to dna_lib sources

### Files to Update (Consumers)
- `imgui_gui/main.cpp` - Use cache_manager in initialization
- Any other places that call cache init functions directly

## Estimated LOC

- New code: ~250 lines (cache_manager.{c,h})
- Modified code: ~50 lines (add cleanup functions, update consumers)
- **Total:** ~300 lines affected

## Testing Plan

1. Build with cache manager
2. Run messenger - verify all caches initialize
3. Quit messenger - verify all caches cleanup
4. Restart messenger - verify expired entries are evicted
5. Check statistics - verify counts are accurate

## Migration Path

### Step 1: Non-Breaking Addition
- Add cache_manager.{c,h} alongside existing code
- Add cleanup functions to existing caches
- No consumer changes yet
- Build and test (everything still works)

### Step 2: Update Consumers
- Replace init/cleanup calls in messenger
- Replace init/cleanup calls in GUI
- Test again

### Step 3: Optional Enhancements
- Add cache statistics screen in GUI
- Add cache clear functionality
- Document in CLAUDE.md

---

**Conclusion:** Phase 7 provides real value by consolidating lifecycle management without breaking existing cache modularity. It's a thin coordination layer (~250 LOC) that simplifies initialization and adds useful statistics.
