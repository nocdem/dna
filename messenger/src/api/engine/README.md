# DNA Engine Modular Structure

This directory contains the modular DNA Engine implementation.

## Current State

**Phase: Modular Extraction Complete** (v0.6.62, 2026-01-29)

The DNA Engine has been refactored from a 10,843-line monolith into modular components.

| Metric | Value |
|--------|-------|
| Original monolith | 10,843 lines |
| Current monolith | ~6,400 lines (41% reduction) |
| Modules extracted | 7 integrated |
| Modules blocked | 2 (compile issues) |

## Module Status

| Module | Lines | Status | Functions | Description |
|--------|-------|--------|-----------|-------------|
| `dna_engine_feed.c` | 644 | ✅ Integrated | 22 | Feed channels, posts, comments, voting |
| `dna_engine_p2p.c` | 395 | ✅ Integrated | 19 | Presence refresh, DHT sync, P2P coordination |
| `dna_engine_wallet.c` | 990 | ✅ Integrated | 9 | Multi-chain wallet, balances, transactions |
| `dna_engine_groups.c` | 485 | ✅ Integrated | 10 | Group CRUD, invitations, subscriptions |
| `dna_engine_messaging.c` | 324 | ✅ Integrated | 4 | Send/receive, conversations |
| `dna_engine_contacts.c` | 700 | ✅ Integrated | 11 | Contact requests, blocking, auto-approval |
| `dna_engine_identity.c` | 975 | ✅ Integrated | 11 | Identity create/load, profiles, display names |
| `dna_engine_utils.c` | 259 | ❌ Blocked | 29 | Missing dna_config_* symbols |
| `dna_engine_core.c` | 489 | ❌ Blocked | 20 | Missing stdatomic.h, circular deps |

## Architecture

```
src/api/
├── dna_engine.c              # Monolith (core + listeners + dispatchers)
├── dna_engine_internal.h     # Internal structures and types
└── engine/
    ├── README.md             # This file
    ├── engine_includes.h     # Shared includes for all modules
    ├── dna_engine_feed.c     # Feed handlers + API
    ├── dna_engine_p2p.c      # P2P handlers + API
    ├── dna_engine_wallet.c   # Wallet handlers + API
    ├── dna_engine_groups.c   # Group handlers + API
    ├── dna_engine_messaging.c # Messaging handlers + API
    ├── dna_engine_contacts.c # Contact handlers + API
    ├── dna_engine_identity.c # Identity handlers + API
    ├── dna_engine_utils.c    # (blocked) Utility functions
    └── dna_engine_core.c     # (blocked) Core infrastructure
```

## Module Pattern

Each module follows this structure:

```c
/*
 * DNA Engine - [Module] Module
 * Functions:
 *   - dna_handle_xxx()      // Task handlers (internal)
 *   - dna_engine_xxx()      // Public API wrappers
 */

#define DNA_ENGINE_XXX_IMPL
#include "engine_includes.h"

/* ============ TASK HANDLERS ============ */

void dna_handle_xxx(dna_engine_t *engine, dna_task_t *task) {
    // Handler implementation
}

/* ============ PUBLIC API ============ */

dna_request_id_t dna_engine_xxx(dna_engine_t *engine, ...) {
    // Submits task to engine queue
    return dna_submit_task(engine, TASK_XXX, &params, cb, user_data);
}
```

## Function Ownership

| Category | Location | Pattern |
|----------|----------|---------|
| Task handlers | Module files | `dna_handle_*()` |
| Public API | Module files | `dna_engine_*()` |
| Task dispatch | dna_engine.c | `dna_execute_task()` |
| Event system | dna_engine.c | `dna_dispatch_event()` |
| Lifecycle | dna_engine.c | `dna_engine_create/destroy()` |
| Listeners | dna_engine.c | `dna_engine_listen_*()` |

## Build Configuration

All module files are compiled by CMakeLists.txt:

```cmake
set(DNA_LIB_SOURCES
    ${DNA_ROOT}/src/api/dna_engine.c
    ${DNA_ROOT}/src/api/engine/dna_engine_feed.c
    ${DNA_ROOT}/src/api/engine/dna_engine_p2p.c
    ${DNA_ROOT}/src/api/engine/dna_engine_wallet.c
    ${DNA_ROOT}/src/api/engine/dna_engine_groups.c
    ${DNA_ROOT}/src/api/engine/dna_engine_messaging.c
    ${DNA_ROOT}/src/api/engine/dna_engine_contacts.c
    ${DNA_ROOT}/src/api/engine/dna_engine_identity.c
)
```

## Shared Header: engine_includes.h

Provides common includes and cross-platform utilities:

```c
#include "engine_includes.h"

// Available:
// - All standard headers (stdio, stdlib, string, time, etc.)
// - dna_engine_internal.h (engine types, task types)
// - LOG_TAG definition
// - safe_timegm() cross-platform UTC time conversion
// - dna_submit_task() declaration
```

## Adding a New Handler

1. **Add task type** to `dna_engine_internal.h`:
   ```c
   typedef enum {
       // ...
       TASK_NEW_OPERATION,
   } dna_task_type_t;
   ```

2. **Add params** (if needed) to `dna_task_params_t` union

3. **Implement handler** in appropriate module file:
   ```c
   void dna_handle_new_operation(dna_engine_t *engine, dna_task_t *task) {
       // Implementation
   }
   ```

4. **Add public API wrapper** in same module file:
   ```c
   dna_request_id_t dna_engine_new_operation(dna_engine_t *engine, ...) {
       dna_task_callback_t cb = { .completion = callback };
       return dna_submit_task(engine, TASK_NEW_OPERATION, &params, cb, user_data);
   }
   ```

5. **Add dispatch case** in `dna_execute_task()` (dna_engine.c):
   ```c
   case TASK_NEW_OPERATION:
       dna_handle_new_operation(engine, task);
       break;
   ```

6. **Declare in header** `include/dna/dna_engine.h`:
   ```c
   dna_request_id_t dna_engine_new_operation(dna_engine_t *engine, ...);
   ```

## Blocked Modules - How to Fix

### dna_engine_utils.c

Missing symbols: `dna_config_load()`, `dna_config_save()`

**Option A (Recommended):** Keep utils in monolith - these are tightly coupled with config system.

**Option B:** Export config functions in a separate header.

### dna_engine_core.c

Issues:
1. Missing `#include <stdatomic.h>` in engine_includes.h
2. Missing `dna_execute_task()` export in engine_includes.h
3. Circular dependency with globals

**Fix (if needed):**
```c
// Add to engine_includes.h:
#include <stdatomic.h>
void dna_execute_task(dna_engine_t *engine, dna_task_t *task);
```

**Recommendation:** Keep core in monolith - it's the foundation that other modules depend on.

## Testing

```bash
# Build
cd /opt/dna-messenger/build
cmake .. && make -j$(nproc)

# Verify CLI functions
./cli/dna-messenger-cli whoami
./cli/dna-messenger-cli contacts
./cli/dna-messenger-cli send nocdem "Test"

# Memory check (if valgrind available)
valgrind --leak-check=full ./cli/dna-messenger-cli whoami
```

## Version History

| Version | Changes |
|---------|---------|
| v0.6.62 | Moved public API wrappers to P2P and Wallet modules |
| v0.6.61 | Extracted identity module |
| v0.6.60 | Extracted contacts module |
| v0.6.59 | Extracted messaging module |
| v0.6.58 | Extracted groups module |
| v0.6.57 | Extracted wallet module |
| v0.6.56 | Security fixes (strdup NULL checks, buffer overflow, timezone) |
