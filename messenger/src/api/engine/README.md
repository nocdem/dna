# DNA Engine Modular Structure

This directory contains the modular DNA Engine implementation.

## Current State

**Phase: Modular Extraction Complete** (v0.6.70, 2026-01-29)

The DNA Engine has been refactored from a 10,843-line monolith into modular components.

| Metric | Value |
|--------|-------|
| Original monolith | 10,843 lines |
| Current monolith | 3,093 lines (71% reduction) |
| Modules extracted | 16 integrated |

## Module Status

| Module | Lines | Status | Functions | Description |
|--------|-------|--------|-----------|-------------|
| `dna_engine_feed.c` | 644 | ✅ Integrated | 22 | Feed channels, posts, comments, voting |
| `dna_engine_presence.c` | 356 | ✅ Integrated | 7 | Presence heartbeat, refresh/lookup, network change |
| `dna_engine_wallet.c` | 990 | ✅ Integrated | 9 | Multi-chain wallet, balances, transactions |
| `dna_engine_groups.c` | 485 | ✅ Integrated | 10 | Group CRUD, invitations, subscriptions |
| `dna_engine_messaging.c` | 578 | ✅ Integrated | 6 | Send/receive, conversations, message retry |
| `dna_engine_contacts.c` | 700 | ✅ Integrated | 11 | Contact requests, blocking, auto-approval |
| `dna_engine_identity.c` | 975 | ✅ Integrated | 11 | Identity create/load, profiles, display names |
| `dna_engine_listeners.c` | 1200 | ✅ Integrated | 14 | Outbox, presence, contact request, ACK listeners |
| `dna_engine_logging.c` | 212 | ✅ Integrated | 13 | Log level/tags config, debug log API |
| `dna_engine_addressbook.c` | 403 | ✅ Integrated | 10 | Wallet address book CRUD |
| `dna_engine_backup.c` | 852 | ✅ Integrated | 14 | Message/contacts/groups/addressbook DHT sync |
| `dna_engine_lifecycle.c` | 178 | ✅ Integrated | 5 | Engine pause/resume for mobile background |
| `dna_engine_helpers.c` | 106 | ✅ Integrated | 4 | DHT context, key loading, stabilization |
| `dna_engine_workers.c` | 113 | ✅ Integrated | 3 | Worker thread pool management |
| `dna_engine_version.c` | 243 | ✅ Integrated | 4 | Version string, DHT publish/check |
| `dna_engine_signing.c` | 115 | ✅ Integrated | 2 | Dilithium5 signing for QR Auth |

## Architecture

```
src/api/
├── dna_engine.c              # Monolith (core + dispatchers)
├── dna_engine_internal.h     # Internal structures and types
└── engine/
    ├── README.md             # This file
    ├── engine_includes.h     # Shared includes for all modules
    ├── dna_engine_feed.c     # Feed handlers + API
    ├── dna_engine_presence.c      # P2P handlers + API
    ├── dna_engine_wallet.c   # Wallet handlers + API
    ├── dna_engine_groups.c   # Group handlers + API
    ├── dna_engine_messaging.c # Messaging handlers + API
    ├── dna_engine_contacts.c # Contact handlers + API
    ├── dna_engine_identity.c # Identity handlers + API
    ├── dna_engine_listeners.c # DHT listeners (outbox, presence, ACK)
    ├── dna_engine_logging.c  # Log config + debug log API
    ├── dna_engine_addressbook.c # Wallet address book CRUD
    ├── dna_engine_backup.c   # All DHT sync (messages, contacts, groups, addressbook)
    ├── dna_engine_lifecycle.c # Engine pause/resume for mobile background
    ├── dna_engine_helpers.c  # DHT context, key loading, stabilization
    ├── dna_engine_workers.c  # Worker thread pool management
    ├── dna_engine_version.c  # DHT version publish/check
    └── dna_engine_signing.c  # Dilithium5 signing API
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
| Pause/Resume | dna_engine_lifecycle.c | `dna_engine_pause/resume()` |
| Listeners | dna_engine_listeners.c | `dna_engine_listen_*()`, `dna_engine_start_*_listener()` |

## Build Configuration

All module files are compiled by CMakeLists.txt:

```cmake
set(DNA_LIB_SOURCES
    ${DNA_ROOT}/src/api/dna_engine.c
    ${DNA_ROOT}/src/api/engine/dna_engine_feed.c
    ${DNA_ROOT}/src/api/engine/dna_engine_presence.c
    ${DNA_ROOT}/src/api/engine/dna_engine_wallet.c
    ${DNA_ROOT}/src/api/engine/dna_engine_groups.c
    ${DNA_ROOT}/src/api/engine/dna_engine_messaging.c
    ${DNA_ROOT}/src/api/engine/dna_engine_contacts.c
    ${DNA_ROOT}/src/api/engine/dna_engine_identity.c
    ${DNA_ROOT}/src/api/engine/dna_engine_listeners.c
    ${DNA_ROOT}/src/api/engine/dna_engine_logging.c
    ${DNA_ROOT}/src/api/engine/dna_engine_addressbook.c
    ${DNA_ROOT}/src/api/engine/dna_engine_backup.c
    ${DNA_ROOT}/src/api/engine/dna_engine_lifecycle.c
    ${DNA_ROOT}/src/api/engine/dna_engine_helpers.c
    ${DNA_ROOT}/src/api/engine/dna_engine_workers.c
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
| v0.6.70 | Extracted version + signing modules; moved presence heartbeat to presence |
| v0.6.69 | Moved message retry to messaging module (bulletproof delivery) |
| v0.6.68 | Extracted helpers + workers modules (DHT helpers, thread pool) |
| v0.6.67 | Extracted lifecycle module (pause/resume for mobile background) |
| v0.6.66 | Consolidated backup module (message backup, contacts/groups/addressbook sync) |
| v0.6.65 | Extracted address book module (CRUD, DHT sync) |
| v0.6.64 | Extracted logging module (log config, debug log API) |
| v0.6.63 | Extracted listeners module (outbox, presence, contact request, ACK) |
| v0.6.62 | Moved public API wrappers to P2P and Wallet modules |
| v0.6.61 | Extracted identity module |
| v0.6.60 | Extracted contacts module |
| v0.6.59 | Extracted messaging module |
| v0.6.58 | Extracted groups module |
| v0.6.57 | Extracted wallet module |
| v0.6.56 | Security fixes (strdup NULL checks, buffer overflow, timezone) |
