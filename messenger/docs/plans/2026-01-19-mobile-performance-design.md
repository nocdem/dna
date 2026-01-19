# Mobile Performance Optimization: Parallel + Lazy Loading

**Date:** 2026-01-19
**Status:** Approved
**Author:** Claude + mika

---

## Problem

App startup takes 30-60 seconds on mobile due to two synchronous, sequential operations:

### Bottleneck 1: Listener Subscriptions (15-30s)

`dna_engine_listen_all_contacts()` loops through all contacts sequentially, calling 3 blocking DHT operations per contact:
- `dna_engine_listen_outbox()` - blocks up to 5s
- `dna_engine_start_presence_listener()` - blocks up to 5s
- `dna_engine_start_watermark_listener()` - blocks up to 5s

**Impact:** 20 contacts × 3 listeners × ~200ms = 12 seconds typical, up to 5 minutes worst case.

### Bottleneck 2: Full Message Sync (15-30s)

`messenger_transport_check_offline_messages()` fetches messages from last 8 days for ALL contacts:
- Each day bucket requires a DHT GET (~150-250ms)
- 8 days × 20 contacts = 160 DHT GETs
- **Impact:** 160 × 200ms = 32 seconds sequential

**Combined impact:** 45-60+ seconds before UI is usable.

---

## Solution

**Three-pronged approach:**

1. **Parallel subscription** - Use thread pool to subscribe multiple contacts concurrently
2. **Lazy listener loading** - Flutter only subscribes to visible contacts, loads others on-demand
3. **Lazy message sync** - Skip full sync on startup, sync per-contact when user opens chat

**Architecture change:**

| Current | New |
|---------|-----|
| Identity load → Sync ALL (32s) → Subscribe ALL (15s) → Show UI | Identity load → Show UI (<1s) → Lazy subscribe visible (500ms) |

**Key insight:** Listeners catch NEW messages in real-time. Old messages only need syncing when user actually opens that chat.

---

## Implementation

### 1. C Engine: Parallel `dna_engine_listen_all_contacts()`

**File:** `src/api/dna_engine.c`

Modify the existing function to use worker thread pool:

```c
// New internal structure for listener task
typedef struct {
    dna_engine_t *engine;
    char fingerprint[129];
    atomic_int completed;
} listener_task_ctx_t;

// Worker function for parallel subscription
static void *listener_task_worker(void *arg) {
    listener_task_ctx_t *ctx = (listener_task_ctx_t *)arg;

    dna_engine_listen_outbox(ctx->engine, ctx->fingerprint);
    dna_engine_start_presence_listener(ctx->engine, ctx->fingerprint);
    dna_engine_start_watermark_listener(ctx->engine, ctx->fingerprint);

    atomic_store(&ctx->completed, 1);
    return NULL;
}

int dna_engine_listen_all_contacts(dna_engine_t *engine) {
    // ... existing validation and contact list retrieval ...

    // Allocate task contexts
    size_t count = list->count;
    listener_task_ctx_t *tasks = calloc(count, sizeof(listener_task_ctx_t));
    pthread_t *threads = calloc(count, sizeof(pthread_t));

    // Spawn parallel threads (limited by practical concurrency)
    int max_parallel = 8;  // Reasonable limit for mobile
    size_t active = 0;
    size_t started = 0;

    for (size_t i = 0; i < count; i++) {
        tasks[i].engine = engine;
        strncpy(tasks[i].fingerprint, list->contacts[i].identity, 128);
        atomic_store(&tasks[i].completed, 0);

        pthread_create(&threads[i], NULL, listener_task_worker, &tasks[i]);
        started++;

        // Limit concurrent threads
        if (started - active >= max_parallel) {
            // Wait for oldest to complete
            pthread_join(threads[active], NULL);
            active++;
        }
    }

    // Wait for remaining threads
    for (size_t i = active; i < started; i++) {
        pthread_join(threads[i], NULL);
    }

    free(tasks);
    free(threads);
    contacts_db_free_list(list);

    // Start contact request listener (always needed)
    dna_engine_start_contact_request_listener(engine);

    return (int)count;
}
```

### 2. C Engine: Remove Automatic Listener Setup from Identity Load

**File:** `src/api/dna_engine.c` (in `dna_handle_load_identity()`)

```c
// REMOVE these lines from dna_handle_load_identity():
// QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: starting outbox listeners...");
// int listener_count = dna_engine_listen_all_contacts(engine);
// QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: started %d listeners", listener_count);

// KEEP: Contact request listener (lightweight, always needed)
dna_engine_start_contact_request_listener(engine);
```

### 3. C Engine: Skip Full Message Sync on Startup

**File:** `src/api/dna_engine.c` (in `dna_handle_load_identity()`, around line 1947-1957)

```c
// REMOVE: Full sync of all contacts on startup (SLOW - 30+ seconds)
// size_t offline_count = 0;
// if (messenger_transport_check_offline_messages(engine->messenger, NULL, &offline_count) == 0) {
//     if (offline_count > 0) {
//         QGP_LOG_INFO(LOG_TAG, "Received %zu offline messages\n", offline_count);
//     }
// }

// NEW: Skip sync - listeners will catch new messages, old messages sync on chat open
QGP_LOG_INFO(LOG_TAG, "Skipping offline sync on startup (lazy loading enabled)");
```

**Per-contact sync already exists** - called when user opens a chat:
- Function: `dna_engine_check_contact_offline(engine, fingerprint)`
- Location: `src/api/dna_engine.c` line ~5915
- Flutter binding: `engine.checkContactOffline(fingerprint)`

### 4. Android Service: Explicit Listener Setup (keeps full sync for notifications)

**File:** `dna_messenger_flutter/android/app/src/main/kotlin/io/cpunk/dna_messenger/DnaMessengerService.kt`

```kotlin
private fun ensureIdentityLoaded(): Boolean {
    // ... existing identity load code ...

    if (identityLoaded) {
        // Service needs ALL listeners for notifications when app is killed
        Log.i(TAG, "Setting up listeners for all contacts...")
        val listenerCount = nativeListenAllContacts()
        Log.i(TAG, "Started $listenerCount contact listeners")
    }

    return identityLoaded
}
```

**File:** `jni/dna_jni.c` - Add JNI binding if not exists:

```c
JNIEXPORT jint JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeListenAllContacts(
    JNIEnv *env, jobject thiz)
{
    if (!g_engine) return 0;
    return dna_engine_listen_all_contacts(g_engine);
}
```

### 5. Flutter: Lazy Loading for Visible Contacts

**File:** `dna_messenger_flutter/lib/providers/listener_state_provider.dart` (NEW)

```dart
import 'package:flutter_riverpod/flutter_riverpod.dart';

class ListenerStateNotifier extends StateNotifier<Set<String>> {
  ListenerStateNotifier() : super({});

  bool hasListener(String fingerprint) => state.contains(fingerprint);

  void markActive(String fingerprint) {
    state = {...state, fingerprint};
  }

  void clear() {
    state = {};
  }
}

final listenerStateProvider =
    StateNotifierProvider<ListenerStateNotifier, Set<String>>(
        (ref) => ListenerStateNotifier());
```

**File:** `dna_messenger_flutter/lib/screens/chat_list_screen.dart`

```dart
// When contact becomes visible in list
void _ensureContactListener(WidgetRef ref, String contactFp) {
  final listenerState = ref.read(listenerStateProvider.notifier);

  if (!listenerState.hasListener(contactFp)) {
    final engine = ref.read(dnaEngineProvider);
    engine.listenOutbox(contactFp);
    engine.startPresenceListener(contactFp);
    engine.startWatermarkListener(contactFp);
    listenerState.markActive(contactFp);
  }
}

// In ListView.builder for contacts:
itemBuilder: (context, index) {
  final contact = contacts[index];

  // Lazy load listener when item is built (becomes visible)
  WidgetsBinding.instance.addPostFrameCallback((_) {
    _ensureContactListener(ref, contact.fingerprint);
  });

  return ContactListTile(contact: contact);
}
```

**File:** `dna_messenger_flutter/lib/screens/chat_screen.dart`

```dart
@override
void initState() {
  super.initState();

  WidgetsBinding.instance.addPostFrameCallback((_) {
    // Ensure listener is active when opening chat
    _ensureContactListener(ref, widget.contactFingerprint);

    // Sync old messages for this contact (lazy sync)
    final engine = ref.read(dnaEngineProvider);
    engine.checkContactOffline(widget.contactFingerprint);
  });
}
```

---

## Expected Results

| Metric | Before | After |
|--------|--------|-------|
| App startup to UI | 45-60 seconds | <1 second |
| Service startup | 45-60 seconds | 2-5s (parallel listeners, keeps sync for notifications) |
| Time to receive NEW messages | Immediate | Immediate for visible contacts |
| Time to load OLD messages | Immediate (pre-synced) | 1-2s when opening chat (lazy sync) |

---

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Message arrives for non-visible contact | Service has all listeners, will show notification |
| User opens chat before listener ready | `listenOutbox()` is idempotent, will set up listener |
| Network loss during setup | Existing resubscribe mechanism handles reconnect |
| App killed mid-subscription | Service takes over with fresh listeners |
| User opens chat with old messages | `checkContactOffline()` syncs last 8 days (~1-2s) |
| User scrolls chat while sync in progress | Show cached messages first, new ones appear as synced |

---

## Testing Plan

1. **Startup time measurement:**
   - Measure time from app launch to chat list visible
   - Target: <1 second on mid-range Android device

2. **Notification test:**
   - Kill app, send message from another device
   - Verify notification appears (service has listeners)

3. **Lazy loading test:**
   - Open app with 50+ contacts
   - Scroll through list, verify no lag
   - Open chat for contact at bottom, verify messages load

4. **Parallel subscription test:**
   - Log listener setup times in service
   - Verify parallel execution (should see overlapping timestamps)

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/api/dna_engine.c` | Parallel `listen_all_contacts()`, remove listeners + sync from identity load |
| `jni/dna_jni.c` | Add `nativeListenAllContacts` JNI binding |
| `DnaMessengerService.kt` | Call `nativeListenAllContacts()` after identity load |
| `lib/providers/listener_state_provider.dart` | NEW: Track active listeners |
| `lib/screens/chat_list_screen.dart` | Lazy load listeners for visible contacts |
| `lib/screens/chat_screen.dart` | Ensure listener + call `checkContactOffline()` on chat open |

---

## Summary

| Optimization | Saves | Approach |
|--------------|-------|----------|
| Skip full message sync on startup | 30-40s | Sync per-contact when chat opened |
| Parallel listener subscriptions | 10-15s | Thread pool instead of sequential |
| Lazy listener loading | 5-10s | Only visible contacts on startup |
| **Total** | **45-65s** | **<1s to usable UI** |
