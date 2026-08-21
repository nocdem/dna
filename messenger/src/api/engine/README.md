# DNA Engine Modular Structure

This directory contains the modular DNA Engine implementation.
`src/api/dna_engine.c` is the core (async task queue, dispatch, events,
lifecycle); every feature domain lives in its own module file here.

## Modules (current)

23 `dna_engine_*` modules plus 4 support files. The authoritative list
is the `add_library(dna ...)` source list in `messenger/CMakeLists.txt`.

| Module | Domain |
|--------|--------|
| `dna_engine_addressbook.c` | Wallet address book CRUD |
| `dna_engine_backup.c` | DHT sync for messages, contacts, groups, addressbook |
| `dna_engine_calls.c` | PQ VoIP call control (Faz A): invite/accept/reject/hangup |
| `dna_engine_channels.c` | Channel CRUD, posts, subscriptions (**DISABLED** — `DNA_CHANNELS_ENABLED` guard) |
| `dna_engine_contacts.c` | Contact requests, blocking |
| `dna_engine_debug_log.c` | Encrypted debug-log send to developer |
| `dna_engine_dnac.c` | DNA Chain wallet (balance, send, sync, history, UTXOs) |
| `dna_engine_follow.c` | Follow/unfollow, list, DHT sync |
| `dna_engine_groups.c` | Group CRUD, GEK encryption, invitations |
| `dna_engine_helpers.c` | Shared utility functions |
| `dna_engine_identity.c` | Identity create/load, profiles |
| `dna_engine_lifecycle.c` | Engine pause/resume (mobile background) |
| `dna_engine_listeners.c` | DHT key subscriptions (outbox, presence, ACK) |
| `dna_engine_logging.c` | Log level/tags config, debug log API |
| `dna_engine_media.c` | Media upload/download, outbox queue |
| `dna_engine_messaging.c` | Send/receive, conversations, retry |
| `dna_engine_presence.c` | Heartbeat, presence lookup |
| `dna_engine_signing.c` | Dilithium5 data signing |
| `dna_engine_version.c` | Version info, DHT publish/check |
| `dna_engine_wall.c` | Personal wall posts |
| `dna_engine_wall_poll.c` | Periodic batch wall polling |
| `dna_engine_wallet.c` | Multi-chain wallet (Cellframe, ETH, BSC, SOL, TRON) |
| `dna_engine_workers.c` | Background thread pool |

Support files: `dna_call_crypto.c`, `dna_call_fsm.c`, `dna_call_orch.c`
(VoIP crypto/FSM/orchestrator used by `dna_engine_calls.c`) and
`dna_debug_log_wire.c` (debug-log wire format).

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

3. **Implement handler** in the appropriate module file:
   ```c
   void dna_handle_new_operation(dna_engine_t *engine, dna_task_t *task) {
       // Implementation
   }
   ```

4. **Add public API wrapper** in the same module file:
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

7. **Update docs** — the matching `messenger/docs/functions/*.md` entry
   lands in the same commit.

## Testing

```bash
# Build
cd /opt/dna/messenger/build
cmake .. && make -j$(nproc)

# Verify CLI functions
./cli/dna-connect-cli whoami
./cli/dna-connect-cli contacts
./cli/dna-connect-cli send nocdem "Test"

# Memory check (if valgrind available)
valgrind --leak-check=full ./cli/dna-connect-cli whoami
```
