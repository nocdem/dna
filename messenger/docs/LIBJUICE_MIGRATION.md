# libjuice Migration Plan
## Replacing libnice + glib with libjuice

**Branch:** `feature/libjuice-migration`
**Date:** 2025-11-19
**Status:** In Progress

---

## Executive Summary

This document tracks the migration from **libnice + glib** to **libjuice** for NAT traversal in DNA Messenger. The primary goal is to eliminate the glib dependency, which complicates cross-compilation for Windows and adds ~31 dependencies and ~50MB of static libraries.

**Benefits:**
- ✅ No glib dependency (simpler cross-compilation)
- ✅ Smaller binaries (~50MB → ~500KB for NAT traversal libs)
- ✅ Faster builds (no MXE glib compilation - saves 30+ minutes)
- ✅ Simpler code (~200 lines less, no event loop thread)
- ✅ Modern API (libjuice uses direct callbacks, not GObject signals)

**Risks:**
- ⚠️ Medium complexity (critical path for P2P messaging)
- ⚠️ Requires extensive testing across NAT types
- ⚠️ Potential DHT candidate format change (SDP → JSON)

---

## Current Architecture Analysis

### libnice Dependencies (Before Migration)

**Lines of Code:**
- `p2p/transport/transport_ice.c`: 945 lines
- `p2p/transport/transport_ice_persistent.c`: 314 lines
- **Total:** ~1,259 lines of ICE-related code

**libnice API Usage:**
- `nice_agent_new()` - Creates ICE agent with GMainContext
- `nice_agent_add_stream()` - Creates UDP stream
- `nice_agent_gather_candidates()` - STUN candidate gathering
- `nice_agent_send()` - Send data over ICE connection
- `nice_agent_attach_recv()` - Attach receive callback
- `nice_agent_set_remote_candidates()` - Add remote candidates
- `nice_agent_get_local_candidates()` - Retrieve gathered candidates
- `nice_agent_generate_local_candidate_sdp()` - Serialize to SDP
- `nice_agent_parse_remote_candidate_sdp()` - Parse SDP candidate
- `nice_agent_remove_stream()` - Cleanup

**glib Dependencies (45+ Functions):**

**Threading & Synchronization:**
- `GThread`, `g_thread_new()`, `g_thread_join()`
- `GMutex`, `g_mutex_init/lock/unlock/clear()`
- `GCond`, `g_cond_init/wait/signal/broadcast/clear()`
- `g_get_monotonic_time()` - Monotonic timestamps

**Event Loop (Required by libnice):**
- `GMainLoop`, `g_main_loop_new/run/quit/unref()`
- `GMainContext`, `g_main_loop_get_context()`
- Separate thread runs `g_main_loop_run()` continuously

**Data Structures:**
- `GQueue` - FIFO message queue (16 messages max)
- `GSList` - Candidate lists
- `g_queue_new/push_tail/pop_head/free()`
- `g_slist_append/free/free_full()`

**GObject System:**
- `g_object_set()` - Configure STUN server, port, controlling mode
- `g_object_unref()` - Reference counting
- `g_signal_connect()` - Connect to "candidate-gathering-done" and "component-state-changed" signals
- `g_signal_handler_disconnect()` - Cleanup

**Memory:**
- `g_free()` - Free glib-allocated memory

**Types:**
- `guint`, `gulong`, `gint64`, `gchar*`, `gpointer`, `gboolean`

### Key Architectural Patterns

#### 1. Event Loop Threading
**File:** `p2p/transport/transport_ice.c:262-286`

```c
// Separate thread for GMainLoop (required by libnice for async I/O)
static gpointer ice_main_loop_thread(gpointer data) {
    ice_context_t *ctx = (ice_context_t*)data;
    g_main_loop_run(ctx->loop);
    return NULL;
}
```

**Why needed:** libnice requires a GMainLoop for async I/O and callbacks.

**libjuice change:** Not needed - libjuice handles I/O in internal threads.

#### 2. Async Callback → Queue → Blocking Receive
**File:** `p2p/transport/transport_ice.c:88-156, 638-723`

```
libnice callback → GQueue (thread-safe) → ice_recv_timeout() (blocking with GCond)
```

Flow:
1. `on_ice_data_received()` pushes to GQueue (line 147)
2. `ice_recv_timeout()` pops from GQueue with timeout (line 690)
3. `GCond` used for efficient blocking instead of busy-wait polling

**libjuice change:** Replace GQueue + GCond with pthread-protected ring buffer + pthread_cond.

#### 3. Signal-Based State Management
**File:** `p2p/transport/transport_ice.c:59-60, 299-306`

```c
// Track signal handler IDs
gulong gathering_handler_id;
gulong state_handler_id;

// Connect signals
gathering_handler_id = g_signal_connect(G_OBJECT(ctx->agent),
    "candidate-gathering-done", G_CALLBACK(on_candidate_gathering_done), ctx);

// Disconnect before cleanup (prevents use-after-free)
g_signal_handler_disconnect(ctx->agent, gathering_handler_id);
```

**libjuice change:** Use direct callbacks with function pointers.

#### 4. Persistent ICE Context
**File:** `p2p/transport/transport_ice_persistent.c`

- One ICE agent per application lifetime (not per-message)
- Candidates gathered once at startup, published to DHT
- Connection caching - reuses ICE connections to same peer
- Context kept alive until shutdown

**libjuice change:** Same pattern - libjuice supports persistent agents.

#### 5. DHT-Based Candidate Exchange
**File:** `p2p/transport/transport_ice.c:423-527`

```c
// DHT key: SHA3-512(fingerprint + ":ice_candidates")
// DHT value: SDP-formatted candidates (newline-separated)
// TTL: 7 days
```

**libjuice change:** May need format conversion (SDP → JSON) or version field for backward compatibility.

### Security Fixes Applied (Must Preserve)

**Commits:** 1ee3929, 7b961d9, 34592c8

1. **Data Loss Prevention:** GQueue-based message queue (16 messages max) prevents single-buffer overwrite
2. **Use-After-Free Prevention:** Track handler IDs, disconnect signals before agent destruction
3. **Buffer Overflow Prevention:** Check remaining space before candidate string concatenation
4. **Partial Send Retry:** Loop until all bytes sent via `nice_agent_send()`
5. **Receive Buffer Validation:** Return -1 if buffer too small, return message to queue

---

## libjuice API Overview

**Repository:** https://github.com/paullouisageneau/libjuice
**License:** MPL 2.0 (compatible with GPL v3)
**Size:** ~500KB (compiled), 15 source files
**Dependencies:** None (uses OS sockets directly)

### Core API

```c
// Agent creation
juice_agent_t *juice_create(const juice_config_t *config);
void juice_destroy(juice_agent_t *agent);

// Callbacks
void juice_set_state_changed_callback(juice_agent_t *agent,
    juice_cb_state_changed_t cb, void *user_ptr);
void juice_set_candidate_callback(juice_agent_t *agent,
    juice_cb_candidate_t cb, void *user_ptr);
void juice_set_gathering_done_callback(juice_agent_t *agent,
    juice_cb_gathering_done_t cb, void *user_ptr);
void juice_set_recv_callback(juice_agent_t *agent,
    juice_cb_recv_t cb, void *user_ptr);

// Candidate gathering
int juice_gather_candidates(juice_agent_t *agent);

// Remote candidates
int juice_add_remote_candidate(juice_agent_t *agent, const char *sdp);
int juice_set_remote_description(juice_agent_t *agent, const char *sdp);

// Send/Receive
int juice_send(juice_agent_t *agent, const char *data, size_t size);
int juice_get_selected_candidates(juice_agent_t *agent,
    char *local, size_t local_size, char *remote, size_t remote_size);

// State
juice_state_t juice_get_state(juice_agent_t *agent);
```

### Configuration

```c
typedef struct juice_config {
    juice_concurrency_mode_t concurrency_mode; // JUICE_CONCURRENCY_MODE_POLL or MUX
    const char *stun_server_host;
    uint16_t stun_server_port;
    const char *turn_servers[JUICE_MAX_TURN_SERVERS]; // Optional
    juice_cb_state_changed_t cb_state_changed;
    juice_cb_candidate_t cb_candidate;
    juice_cb_gathering_done_t cb_gathering_done;
    juice_cb_recv_t cb_recv;
    void *user_ptr;
} juice_config_t;
```

### States

```c
typedef enum juice_state {
    JUICE_STATE_DISCONNECTED,
    JUICE_STATE_GATHERING,
    JUICE_STATE_CONNECTING,
    JUICE_STATE_CONNECTED,
    JUICE_STATE_COMPLETED,
    JUICE_STATE_FAILED
} juice_state_t;
```

---

## Migration Mapping

### API Mapping

| libnice API | libjuice Equivalent | Notes |
|-------------|---------------------|-------|
| `nice_agent_new()` | `juice_create()` | No GMainLoop needed |
| `nice_agent_add_stream()` | Implicit in `juice_create()` | Single stream only |
| `nice_agent_gather_candidates()` | `juice_gather_candidates()` | Async, callback-based |
| `nice_agent_send()` | `juice_send()` | Direct send, no loop |
| `nice_agent_attach_recv()` | `juice_set_recv_callback()` | Direct callback, no loop thread |
| `nice_agent_set_remote_candidates()` | `juice_add_remote_candidate()` | Call per candidate |
| `nice_agent_get_local_candidates()` | Callback in `cb_candidate` | Called for each candidate |
| `nice_agent_generate_local_candidate_sdp()` | Candidate already in SDP format | libjuice provides SDP directly |
| `nice_agent_parse_remote_candidate_sdp()` | `juice_add_remote_candidate()` | Accepts SDP directly |
| `nice_agent_remove_stream()` | `juice_destroy()` | Full cleanup |

### glib Replacement

| glib Component | Replacement | Platform |
|----------------|-------------|----------|
| `GMainLoop` | **Not needed** | libjuice handles I/O internally |
| `GThread` | **Remove loop thread** | libjuice has internal threads |
| `GMutex` | `pthread_mutex_t` | POSIX (Linux/Windows) |
| `GCond` | `pthread_cond_t` | POSIX (Linux/Windows) |
| `GQueue` | Ring buffer + pthread mutex | Custom implementation |
| `GSList` | Fixed array | Candidate count is small (<20) |
| `GObject signals` | Direct callbacks | Function pointers |
| `g_get_monotonic_time()` | `clock_gettime(CLOCK_MONOTONIC)` | Linux |
| `g_get_monotonic_time()` | `GetTickCount64()` | Windows |
| `guint`, `gchar*`, etc. | Standard C types | `unsigned int`, `char*`, etc. |

---

## Implementation Plan

### Phase 1: Vendor libjuice ✅

**Task 1.1:** Add libjuice as CMake external project

**File:** `CMakeLists.txt`

```cmake
# Download and build libjuice at configure time
include(ExternalProject)
ExternalProject_Add(libjuice_external
    GIT_REPOSITORY https://github.com/paullouisageneau/libjuice.git
    GIT_TAG v1.7.0  # Latest stable (2025-11-19)
    PREFIX ${CMAKE_BINARY_DIR}/vendor/libjuice
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/vendor/libjuice/install
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_SHARED_LIBS=OFF
        -DUSE_NETTLE=OFF  # Use OpenSSL for HMAC (already a dependency)
    BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/vendor/libjuice/install/lib/libjuice-static.a
)

# Create imported target
add_library(libjuice STATIC IMPORTED)
set_target_properties(libjuice PROPERTIES
    IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/vendor/libjuice/install/lib/libjuice-static.a
)
add_dependencies(libjuice libjuice_external)

set(JUICE_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/vendor/libjuice/install/include)
set(JUICE_LIBRARIES libjuice)
```

**Task 1.2:** Update `.gitignore`

```
build/vendor/libjuice/
```

**Status:** Pending

---

### Phase 2: Implement transport_juice.c ✅

**Task 2.1:** Create `p2p/transport/transport_juice.h`

```c
#ifndef TRANSPORT_JUICE_H
#define TRANSPORT_JUICE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

// Forward declaration
typedef struct juice_agent juice_agent_t;

// Message queue structure (replaces GQueue)
typedef struct {
    uint8_t *data;
    size_t size;
} juice_message_t;

typedef struct {
    juice_message_t messages[16];  // Fixed-size queue (max 16 messages)
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} juice_queue_t;

// ICE context (same interface as transport_ice.h)
typedef struct {
    juice_agent_t *agent;
    char stun_server[256];
    uint16_t stun_port;

    // Candidate gathering
    volatile bool gathering_done;
    pthread_mutex_t gathering_mutex;
    pthread_cond_t gathering_cond;

    // Connection state
    volatile bool connected;
    pthread_mutex_t state_mutex;
    pthread_cond_t state_cond;

    // Receive queue
    juice_queue_t *recv_queue;

    // Local candidates (for DHT publishing)
    char local_candidates[4096];
    pthread_mutex_t candidates_mutex;
} ice_context_t;

// Initialize ICE context
ice_context_t* ice_context_create(const char *stun_server, uint16_t stun_port);

// Gather local candidates
int ice_gather_candidates(ice_context_t *ctx, int timeout_ms);

// Get local candidates (SDP format)
const char* ice_get_local_candidates(ice_context_t *ctx);

// Set remote candidates (SDP format, newline-separated)
int ice_set_remote_candidates(ice_context_t *ctx, const char *remote_sdp);

// Connect to remote peer
int ice_connect(ice_context_t *ctx, int timeout_ms);

// Send data
int ice_send(ice_context_t *ctx, const uint8_t *data, size_t len);

// Receive data (blocking with timeout)
int ice_recv_timeout(ice_context_t *ctx, uint8_t *buffer, size_t buffer_size, int timeout_ms);

// Cleanup
void ice_context_free(ice_context_t *ctx);

#endif // TRANSPORT_JUICE_H
```

**Task 2.2:** Implement `p2p/transport/transport_juice.c`

Key sections:
1. Queue management (replace GQueue)
2. Callbacks (state, gathering, candidates, receive)
3. Candidate gathering with timeout
4. Connection establishment with timeout
5. Send/receive with retry logic
6. Cleanup with proper synchronization

**Status:** Pending

---

### Phase 3: Replace glib Primitives ✅

**Task 3.1:** Replace threading primitives

```c
// Before (glib)
GMutex mutex;
g_mutex_init(&mutex);
g_mutex_lock(&mutex);
g_mutex_unlock(&mutex);
g_mutex_clear(&mutex);

// After (pthread)
pthread_mutex_t mutex;
pthread_mutex_init(&mutex, NULL);
pthread_mutex_lock(&mutex);
pthread_mutex_unlock(&mutex);
pthread_mutex_destroy(&mutex);
```

**Task 3.2:** Replace condition variables

```c
// Before (glib)
GCond cond;
g_cond_init(&cond);
g_cond_wait(&cond, &mutex);
g_cond_signal(&cond);
g_cond_clear(&cond);

// After (pthread)
pthread_cond_t cond;
pthread_cond_init(&cond, NULL);
pthread_cond_wait(&cond, &mutex);
pthread_cond_signal(&cond);
pthread_cond_destroy(&cond);
```

**Task 3.3:** Replace monotonic time

```c
// Before (glib)
gint64 deadline = g_get_monotonic_time() + timeout_ms * 1000;

// After (Linux)
#include <time.h>
struct timespec ts;
clock_gettime(CLOCK_MONOTONIC, &ts);
ts.tv_sec += timeout_ms / 1000;
ts.tv_nsec += (timeout_ms % 1000) * 1000000;

// After (Windows)
#include <windows.h>
ULONGLONG deadline = GetTickCount64() + timeout_ms;
```

**Status:** Pending

---

### Phase 4: Update Build System ✅

**Task 4.1:** Remove libnice/glib from `CMakeLists.txt`

Remove lines 128-153 (libnice and glib detection).

**Task 4.2:** Update `p2p/CMakeLists.txt`

Replace:
```cmake
pkg_check_modules(OPENDHT REQUIRED opendht>=3.0)
pkg_check_modules(NICE REQUIRED nice)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
```

With:
```cmake
pkg_check_modules(OPENDHT REQUIRED opendht>=3.0)
# libjuice added via ExternalProject in main CMakeLists.txt
```

**Task 4.3:** Update `build-cross-compile.sh`

Remove MXE glib/libnice builds (saves 30+ minutes on first build).

**Task 4.4:** Update dependency documentation

- `README.md` - Remove libnice-dev, libglib2.0-dev
- `.gitlab-ci.yml` - Remove from apt install lists

**Status:** Pending

---

### Phase 5: Testing ✅

**Task 5.1:** Unit tests

- Test candidate gathering
- Test queue operations (enqueue/dequeue)
- Test timeout mechanisms
- Test cleanup (no leaks, no use-after-free)

**Task 5.2:** Integration tests

- Test LAN peer discovery (same subnet)
- Test NAT traversal (Symmetric NAT, Cone NAT)
- Test message send/receive over ICE
- Test connection reuse (persistent context)

**Task 5.3:** Cross-platform builds

- Build on Linux x64
- Build on Linux ARM64
- Cross-compile for Windows x64 with `build-cross-compile.sh`

**Task 5.4:** Performance benchmarks

- Compare connection establishment time vs libnice
- Compare message latency vs libnice
- Measure binary size reduction

**Status:** Pending

---

## Rollback Plan

If migration encounters critical issues:

1. **Keep both implementations:** `transport_ice.c` (libnice) and `transport_juice.c` (libjuice)
2. **Add compile-time flag:** `-DUSE_LIBJUICE=ON/OFF`
3. **Conditional compilation:** Test libjuice in beta, keep libnice as fallback
4. **Gradual rollout:** Enable libjuice for Linux first, keep libnice for Windows

---

## Timeline & Effort Estimate

| Phase | Tasks | Estimated Effort | Status |
|-------|-------|-----------------|--------|
| Phase 1: Vendor libjuice | 2 tasks | 2 hours | Pending |
| Phase 2: Implement transport_juice.c | 2 tasks | 8 hours | Pending |
| Phase 3: Replace glib primitives | 3 tasks | 4 hours | Pending |
| Phase 4: Update build system | 4 tasks | 3 hours | Pending |
| Phase 5: Testing | 4 tasks | 8 hours | Pending |
| **Total** | **15 tasks** | **25 hours** | **In Progress** |

---

## References

- **libjuice Repository:** https://github.com/paullouisageneau/libjuice
- **libjuice Documentation:** https://github.com/paullouisageneau/libjuice/wiki
- **ICE RFC 8445:** https://datatracker.ietf.org/doc/html/rfc8445
- **STUN RFC 5389:** https://datatracker.ietf.org/doc/html/rfc5389
- **Current Implementation:** `p2p/transport/transport_ice.c`, `p2p/transport/transport_ice_persistent.c`
- **Security Audit:** `docs/ICE_SECURITY_AUDIT.md`

---

## Change Log

- **2025-11-19:** Migration plan created, branch `feature/libjuice-migration` initiated
