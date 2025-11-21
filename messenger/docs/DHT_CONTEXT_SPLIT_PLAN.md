# dht_context.cpp Split Plan - Phase 3

**File:** `/opt/dna-messenger/dht/dht_context.cpp` (1,282 lines)
**Goal:** Split into 4 focused modules (~300 LOC each)
**Status:** Ready for execution

---

## Extraction Map

### 1. Identity Management → `dht/client/dht_identity.cpp` (202 lines)

**Lines to Extract:** 1085-1282 (198 lines actual code)

**Functions:**
```cpp
// Line 1092-1110
extern "C" int dht_identity_generate_random(dht_identity_t **identity_out);

// Line 1117-1192
extern "C" int dht_identity_export_to_buffer(
    dht_identity_t *identity,
    uint8_t **buffer_out,
    size_t *buffer_size_out);

// Line 1197-1273
extern "C" int dht_identity_import_from_buffer(
    const uint8_t *buffer,
    size_t buffer_size,
    dht_identity_t **identity_out);

// Line 1278-1282
extern "C" void dht_identity_free(dht_identity_t *identity);
```

**Dependencies:**
- `dht_identity` struct definition (line 28-31) - needs to stay in dht_context.cpp or move to shared header
- GNUTLS headers
- OpenDHT crypto headers
- Standard C++ headers (iostream, memory, string)

**New Files:**
- `dht/client/dht_identity.h` - Public API (4 functions)
- `dht/client/dht_identity.cpp` - Implementation

---

### 2. Statistics → `dht/core/dht_stats.cpp` (41 lines)

**Lines to Extract:** 1040-1080 (41 lines)

**Functions:**
```cpp
// Line 1043-1080
extern "C" int dht_get_stats(dht_context_t *ctx,
                             size_t *node_count,
                             size_t *stored_values);

// Line 1075-1083
extern "C" struct dht_value_storage* dht_get_storage(dht_context_t *ctx);
```

**Dependencies:**
- `dht_context_t` struct (needs access to ctx->runner, ctx->storage)
- OpenDHT NodeInfo structures

**New Files:**
- `dht/core/dht_stats.h` - Public API (2 functions)
- `dht/core/dht_stats.cpp` - Implementation

**Note:** `dht_get_storage()` is bootstrap-specific but logically groups with stats

---

### 3. Core Context → `dht/core/dht_context.cpp` (Remaining ~1,000 lines)

**Keep in dht_context.cpp:**
- Lines 1-95: Headers, imports, ValueType definitions, global storage
- Lines 98-231: Helper functions (save/load identity PEM)
- Lines 233-431: Lifecycle (dht_context_new, dht_context_start, dht_context_start_with_identity)
- Lines 433-467: Shutdown (dht_context_stop, dht_context_free)
- Lines 469-496: Status (dht_context_is_ready)
- Lines 498-688: Put operations (7 variants: put, put_ttl, put_permanent, put_signed, put_signed_permanent)
- Lines 690-993: Get operations (3 variants: get, get_async, get_all)
- Lines 995-1038: Delete operations

**Functions Staying:**
- Lifecycle: new, start, start_with_identity, stop, free
- Status: is_ready
- Put operations: 7 variants
- Get operations: 3 variants
- Delete: 1 function

---

## Implementation Steps

### Step 1: Create Header Files

**`dht/client/dht_identity.h`:**
```c
#ifndef DHT_IDENTITY_H
#define DHT_IDENTITY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer (defined in dht_context.cpp for now)
typedef struct dht_identity dht_identity_t;

int dht_identity_generate_random(dht_identity_t **identity_out);
int dht_identity_export_to_buffer(dht_identity_t *identity, uint8_t **buffer_out, size_t *buffer_size_out);
int dht_identity_import_from_buffer(const uint8_t *buffer, size_t buffer_size, dht_identity_t **identity_out);
void dht_identity_free(dht_identity_t *identity);

#ifdef __cplusplus
}
#endif

#endif // DHT_IDENTITY_H
```

**`dht/core/dht_stats.h`:**
```c
#ifndef DHT_STATS_H
#define DHT_STATS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dht_context dht_context_t;
struct dht_value_storage;

int dht_get_stats(dht_context_t *ctx, size_t *node_count, size_t *stored_values);
struct dht_value_storage* dht_get_storage(dht_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // DHT_STATS_H
```

### Step 2: Create Implementation Files

**`dht/client/dht_identity.cpp`:**
```cpp
#include "dht_identity.h"
#include "../dht_context.h"  // For dht_identity struct definition
#include <opendht/crypto.h>
#include <gnutls/x509.h>
#include <iostream>
#include <memory>
#include <cstring>
#include <arpa/inet.h>  // For htonl/ntohl

// Include dht_identity struct definition (needs to be accessible)
// Option 1: Keep in dht_context.h (current approach)
// Option 2: Move to dht_identity_internal.h

extern "C" int dht_identity_generate_random(dht_identity_t **identity_out) {
    // Copy lines 1093-1109 from dht_context.cpp
}

extern "C" int dht_identity_export_to_buffer(...) {
    // Copy lines 1118-1191 from dht_context.cpp
}

extern "C" int dht_identity_import_from_buffer(...) {
    // Copy lines 1198-1272 from dht_context.cpp
}

extern "C" void dht_identity_free(dht_identity_t *identity) {
    // Copy lines 1279-1281 from dht_context.cpp
}
```

**`dht/core/dht_stats.cpp`:**
```cpp
#include "dht_stats.h"
#include "../dht_context.h"  // For dht_context struct
#include "../services/value_storage/dht_value_storage.h"  // TODO: Fix path
#include <opendht/dhtrunner.h>
#include <iostream>

extern "C" int dht_get_stats(dht_context_t *ctx, size_t *node_count, size_t *stored_values) {
    // Copy lines 1044-1076 from dht_context.cpp
}

extern "C" struct dht_value_storage* dht_get_storage(dht_context_t *ctx) {
    // Copy lines 1076-1082 from dht_context.cpp
}
```

### Step 3: Update dht_context.h

Add includes for new modules:
```c
#include "core/dht_stats.h"
#include "client/dht_identity.h"
```

Remove function declarations that moved:
- Lines 287-322 (identity functions) → Now in dht_identity.h
- Lines 260-273 (stats/storage) → Now in dht_stats.h

### Step 4: Update dht_context.cpp

**Remove extracted sections:**
1. Delete lines 1085-1282 (identity functions)
2. Delete lines 1040-1083 (stats + storage functions)

**Add includes at top:**
```cpp
#include "core/dht_stats.h"
#include "client/dht_identity.h"
```

**Update line numbers in comments** (if any reference specific lines)

### Step 5: Update CMakeLists.txt

**`dht/CMakeLists.txt`:**
```cmake
# Add new source files to dht_lib
add_library(dht_lib STATIC
    dht_context.cpp
    core/dht_stats.cpp          # NEW
    client/dht_identity.cpp     # NEW
    # ... existing files ...
)

# Update include directories
target_include_directories(dht_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core      # NEW
    ${CMAKE_CURRENT_SOURCE_DIR}/client    # NEW
    ${CMAKE_CURRENT_SOURCE_DIR}/shared    # NEW (for future)
    # ... existing includes ...
)
```

### Step 6: Update Includes Across Codebase

**Files that use identity functions:**
- `dht/dht_identity_backup.c` - Add `#include "client/dht_identity.h"`
- `dht/dht_identity_backup.h` - Add forward declaration or include

**Files that use stats:**
- `bootstrap/core/bootstrap_main.c` - Add `#include "dht/core/dht_stats.h"`

**Grep for includes:**
```bash
grep -r "dht_identity_generate_random\|dht_identity_export\|dht_identity_import" --include="*.c" --include="*.h" --include="*.cpp"
grep -r "dht_get_stats\|dht_get_storage" --include="*.c" --include="*.h" --include="*.cpp"
```

### Step 7: Test Build

```bash
cd /opt/dna-messenger/build
rm -rf *  # Clean rebuild recommended
cmake ..
make -j4

# Verify binaries
ls -lh bootstrap/persistent_bootstrap
ls -lh imgui_gui/dna_messenger_imgui
```

### Step 8: Test Functionality

1. **Bootstrap server:**
   ```bash
   ./bootstrap/persistent_bootstrap
   # Should start without errors
   # Ctrl+C to stop
   ```

2. **Client messenger:**
   ```bash
   ./imgui_gui/dna_messenger_imgui
   # Should load identity correctly
   # Verify BIP39 recovery works
   ```

---

## Issues to Watch For

### 1. Circular Dependencies

**Problem:** `dht_identity` struct is defined in `dht_context.cpp` but needed by `dht_identity.cpp`

**Solution Options:**
- **Option A (Current):** Keep struct in `dht_context.h`, include from dht_identity.cpp
- **Option B:** Create `dht/core/dht_types.h` with shared types, include everywhere
- **Option C:** Create `dht/client/dht_identity_internal.h` with struct definition

**Recommended:** Option A for now (simplest), Option B for full refactoring

### 2. Include Path Changes

After extraction, some files will need updated includes:
```c
// Old:
#include "dht_context.h"

// New:
#include "dht_context.h"
#include "core/dht_stats.h"
#include "client/dht_identity.h"
```

### 3. Value Storage Include Path

`dht_stats.cpp` needs access to `dht_value_storage_t` type:
```cpp
// Current (will break):
#include "dht_value_storage.h"

// After bootstrap separation:
#include "../../bootstrap/services/value_storage/dht_value_storage.h"
```

**TODO:** This reveals value_storage should be in dht/, not bootstrap/ (it's used by both)

---

## Post-Split File Sizes

**Before:**
```
dht_context.cpp: 1,282 lines
```

**After:**
```
dht/core/dht_context.cpp:        ~1,000 lines (core put/get/lifecycle)
dht/client/dht_identity.cpp:       ~200 lines (identity management)
dht/core/dht_stats.cpp:             ~50 lines (stats + storage getter)
```

---

## Benefits After Split

1. **Clearer separation:** Identity functions only needed by client
2. **Easier testing:** Can test identity management independently
3. **Reduced coupling:** dht_context.cpp focuses on DHT operations
4. **Better organization:** Matches planned dht/client, dht/core, dht/shared structure
5. **Smaller files:** All modules <1,000 LOC (more maintainable)

---

## Alternative: Defer Full Split

Given token constraints (122K/200K used), consider:

**Minimal Approach:**
1. Create headers (`dht_identity.h`, `dht_stats.h`) with forward declarations
2. Keep implementations in `dht_context.cpp` for now
3. Add TODO comments marking extraction points
4. Execute full split in fresh session

**Benefit:** Preserves tokens for other high-value work (profile unification, cache manager)

---

## Execution Checklist

- [ ] Create `dht/client/dht_identity.h`
- [ ] Create `dht/client/dht_identity.cpp`
- [ ] Create `dht/core/dht_stats.h`
- [ ] Create `dht/core/dht_stats.cpp`
- [ ] Extract functions from `dht_context.cpp` (lines 1040-1282)
- [ ] Update `dht_context.h` (remove moved declarations)
- [ ] Update `dht/CMakeLists.txt` (add new source files)
- [ ] Update includes in `dht_identity_backup.{c,h}`
- [ ] Update includes in `bootstrap/core/bootstrap_main.c`
- [ ] Test build (cmake + make)
- [ ] Test bootstrap server starts
- [ ] Test client messenger starts
- [ ] Commit changes

**Estimated Time:** 4-6 hours
**Token Cost (if done now):** ~25,000-30,000 tokens
**Remaining Tokens:** 78,000 (may not be sufficient for subsequent phases)

**Recommendation:** Mark as "ready for execution" and continue with Phase 4-7 planning
