# Mobile Performance Optimization - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce app startup from 45-60 seconds to <1 second by implementing parallel + lazy loading.

**Architecture:** Skip full message sync and listener setup during identity load. Service calls parallel listener setup explicitly. Flutter uses lazy loading for visible contacts only, syncs messages when user opens chat.

**Tech Stack:** C (pthreads), Kotlin (JNI), Dart/Flutter (Riverpod)

**Design Doc:** `docs/plans/2026-01-19-mobile-performance-design.md`

---

## Task 1: Skip Full Message Sync on Startup (C Engine)

**Files:**
- Modify: `src/api/dna_engine.c:1950-1960`

**Step 1: Comment out the offline message sync in identity load**

In `dna_handle_load_identity()`, find and comment out the sync block:

```c
// Around line 1950-1960, REPLACE:
            /* 1. Check for offline messages (Spillway: query contacts' outboxes) */
            size_t offline_count = 0;
            if (messenger_transport_check_offline_messages(engine->messenger, NULL, &offline_count) == 0) {
                if (offline_count > 0) {
                    QGP_LOG_INFO(LOG_TAG, "Received %zu offline messages\n", offline_count);
                } else {
                    QGP_LOG_INFO(LOG_TAG, "No offline messages found\n");
                }
            } else {
                QGP_LOG_INFO(LOG_TAG, "Warning: Failed to check offline messages\n");
            }

// WITH:
            /* PERF: Skip full offline sync on startup - lazy sync when user opens chat.
             * Listeners will catch NEW messages. Old messages sync via checkContactOffline(). */
            QGP_LOG_INFO(LOG_TAG, "Skipping offline sync (lazy loading enabled)\n");
```

**Step 2: Build to verify no compile errors**

Run: `cd /home/mika/dev/dna-messenger/build && make -j$(nproc) 2>&1 | tail -20`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add src/api/dna_engine.c
git commit -m "perf: Skip full offline sync on startup for lazy loading"
```

---

## Task 2: Remove Automatic Listener Setup from Identity Load (C Engine)

**Files:**
- Modify: `src/api/dna_engine.c:1978-1988`

**Step 1: Comment out automatic listen_all_contacts in identity load**

In `dna_handle_load_identity()`, find and modify the listener setup:

```c
// Around line 1978-1988, REPLACE:
    if (engine->messenger) {
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: starting outbox listeners...");
        int listener_count = dna_engine_listen_all_contacts(engine);
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: started %d listeners", listener_count);

        /* Subscribe to group outboxes for real-time group messages.
         * This is critical: DHT usually connects before identity loads, so the
         * background thread (dna_engine_setup_listeners_thread) never runs.
         * We must subscribe to groups here after identity loads. */
        int group_count = dna_engine_subscribe_all_groups(engine);
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: subscribed to %d groups", group_count);

// WITH:
    if (engine->messenger) {
        /* PERF: Skip automatic listener setup - Flutter uses lazy loading,
         * Service calls listen_all_contacts explicitly after identity load.
         * Contact request listener is lightweight, always start it. */
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Identity load: skipping auto-listeners (lazy loading)");
        dna_engine_start_contact_request_listener(engine);

        /* Groups still need subscription for real-time messages */
        int group_count = dna_engine_subscribe_all_groups(engine);
        QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity load: subscribed to %d groups", group_count);
```

**Step 2: Build to verify**

Run: `cd /home/mika/dev/dna-messenger/build && make -j$(nproc) 2>&1 | tail -20`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add src/api/dna_engine.c
git commit -m "perf: Remove automatic listener setup from identity load"
```

---

## Task 3: Make listen_all_contacts Parallel (C Engine)

**Files:**
- Modify: `src/api/dna_engine.c:6890-7020` (the `dna_engine_listen_all_contacts` function)

**Step 1: Add parallel listener task structure at top of file (after includes)**

Find a good location near line 50-100 and add:

```c
/* Parallel listener setup context (for mobile performance) */
typedef struct {
    dna_engine_t *engine;
    char fingerprint[129];
} parallel_listener_ctx_t;

static void *parallel_listener_worker(void *arg) {
    parallel_listener_ctx_t *ctx = (parallel_listener_ctx_t *)arg;
    if (!ctx || !ctx->engine) return NULL;

    dna_engine_listen_outbox(ctx->engine, ctx->fingerprint);
    dna_engine_start_presence_listener(ctx->engine, ctx->fingerprint);
    dna_engine_start_watermark_listener(ctx->engine, ctx->fingerprint);

    return NULL;
}
```

**Step 2: Modify dna_engine_listen_all_contacts to use parallel threads**

Replace the sequential loop (around line 6966-6999) with parallel execution:

```c
// Find and REPLACE the sequential loop:
    /* Start listener for each contact (outbox + presence) */
    int started = 0;
    int presence_started = 0;
    size_t count = list->count;
    for (size_t i = 0; i < count; i++) {
        const char *contact_id = list->contacts[i].identity;
        // ... sequential calls ...
    }

// WITH parallel implementation:
    /* Start listeners in parallel for better mobile performance */
    size_t count = list->count;
    int max_parallel = 8;  /* Limit concurrent threads on mobile */

    if (count == 0) {
        contacts_db_free_list(list);
        dna_engine_start_contact_request_listener(engine);
        engine->listeners_starting = false;
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Starting parallel subscription for %zu contacts (max %d threads)",
                 count, max_parallel);

    parallel_listener_ctx_t *tasks = calloc(count, sizeof(parallel_listener_ctx_t));
    pthread_t *threads = calloc(count, sizeof(pthread_t));
    if (!tasks || !threads) {
        QGP_LOG_ERROR(LOG_TAG, "[LISTEN] Failed to allocate parallel task memory");
        free(tasks);
        free(threads);
        contacts_db_free_list(list);
        engine->listeners_starting = false;
        return 0;
    }

    /* Spawn threads with concurrency limit */
    size_t active_start = 0;
    for (size_t i = 0; i < count; i++) {
        tasks[i].engine = engine;
        strncpy(tasks[i].fingerprint, list->contacts[i].identity, 128);
        tasks[i].fingerprint[128] = '\0';

        if (pthread_create(&threads[i], NULL, parallel_listener_worker, &tasks[i]) != 0) {
            QGP_LOG_WARN(LOG_TAG, "[LISTEN] Failed to create thread for contact %zu", i);
            threads[i] = 0;
            continue;
        }

        /* Limit concurrent threads */
        if ((i - active_start + 1) >= (size_t)max_parallel) {
            pthread_join(threads[active_start], NULL);
            active_start++;
        }
    }

    /* Wait for remaining threads */
    for (size_t i = active_start; i < count; i++) {
        if (threads[i] != 0) {
            pthread_join(threads[i], NULL);
        }
    }

    free(tasks);
    free(threads);
    int started = (int)count;
    QGP_LOG_INFO(LOG_TAG, "[LISTEN] Parallel subscription complete: %d contacts", started);
```

**Step 3: Build to verify**

Run: `cd /home/mika/dev/dna-messenger/build && make -j$(nproc) 2>&1 | tail -20`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add src/api/dna_engine.c
git commit -m "perf: Parallel listener subscriptions in listen_all_contacts"
```

---

## Task 4: Add JNI Binding for nativeListenAllContacts

**Files:**
- Modify: `jni/dna_jni.c` (add near line 1370, after identity lock functions)

**Step 1: Add the JNI function**

```c
/* ============================================================================
 * PERFORMANCE: Parallel listener setup for ForegroundService
 * ============================================================================ */

/**
 * Start listeners for all contacts (parallel).
 * Called by ForegroundService after identity load to enable notifications.
 * Returns: number of contacts with listeners started, or -1 on error.
 */
JNIEXPORT jint JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeListenAllContacts(
    JNIEnv *env, jobject thiz)
{
    if (!g_engine) {
        LOGE("nativeListenAllContacts: engine is NULL");
        return -1;
    }

    LOGI("nativeListenAllContacts: Starting parallel listener setup...");
    int count = dna_engine_listen_all_contacts(g_engine);
    LOGI("nativeListenAllContacts: Started listeners for %d contacts", count);

    return count;
}
```

**Step 2: Build Android library to verify**

Run: `cd /home/mika/dev/dna-messenger && ./build-cross-compile.sh android-arm64 2>&1 | tail -30`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add jni/dna_jni.c
git commit -m "feat: Add nativeListenAllContacts JNI binding for service"
```

---

## Task 5: Call nativeListenAllContacts from Android Service

**Files:**
- Modify: `dna_messenger_flutter/android/app/src/main/kotlin/io/cpunk/dna_messenger/DnaMessengerService.kt`

**Step 1: Add native method declaration**

Find the native method declarations (around line 100-120) and add:

```kotlin
// Add with other native method declarations:
private external fun nativeListenAllContacts(): Int
```

**Step 2: Call it after identity load succeeds**

In `ensureIdentityLoaded()`, after the successful identity load (around line 345-350), add:

```kotlin
// Find the success log after nativeLoadIdentityMinimalSync, add after it:
            android.util.Log.i(TAG, "Identity loaded (minimal mode) - setting up listeners")

            // Start parallel listener setup for notifications
            val listenerCount = nativeListenAllContacts()
            if (listenerCount >= 0) {
                android.util.Log.i(TAG, "Started listeners for $listenerCount contacts")
            } else {
                android.util.Log.e(TAG, "Failed to start listeners")
            }
```

**Step 3: Commit**

```bash
git add dna_messenger_flutter/android/app/src/main/kotlin/io/cpunk/dna_messenger/DnaMessengerService.kt
git commit -m "feat: Service calls nativeListenAllContacts after identity load"
```

---

## Task 6: Add Listener State Provider (Flutter)

**Files:**
- Create: `dna_messenger_flutter/lib/providers/listener_state_provider.dart`

**Step 1: Create the provider file**

```dart
// Tracks which contacts have active DHT listeners
// Used for lazy loading - only subscribe when contact becomes visible
import 'package:flutter_riverpod/flutter_riverpod.dart';

class ListenerStateNotifier extends StateNotifier<Set<String>> {
  ListenerStateNotifier() : super({});

  bool hasListener(String fingerprint) => state.contains(fingerprint);

  void markActive(String fingerprint) {
    if (!state.contains(fingerprint)) {
      state = {...state, fingerprint};
    }
  }

  void markInactive(String fingerprint) {
    if (state.contains(fingerprint)) {
      state = state.where((fp) => fp != fingerprint).toSet();
    }
  }

  void clear() {
    state = {};
  }
}

final listenerStateProvider =
    StateNotifierProvider<ListenerStateNotifier, Set<String>>(
        (ref) => ListenerStateNotifier());
```

**Step 2: Export from providers.dart**

Add to `dna_messenger_flutter/lib/providers/providers.dart`:

```dart
export 'listener_state_provider.dart';
```

**Step 3: Commit**

```bash
git add dna_messenger_flutter/lib/providers/listener_state_provider.dart
git add dna_messenger_flutter/lib/providers/providers.dart
git commit -m "feat: Add listener state provider for lazy loading"
```

---

## Task 7: Lazy Load Listeners in Contacts Screen

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/contacts/contacts_screen.dart`

**Step 1: Add helper method to ensure listener**

Add inside the `ContactsScreen` class or as a top-level function:

```dart
void _ensureContactListener(WidgetRef ref, String fingerprint) {
  final listenerState = ref.read(listenerStateProvider.notifier);
  if (listenerState.hasListener(fingerprint)) return;

  // Start listeners for this contact
  ref.read(engineProvider).whenData((engine) {
    engine.listenOutbox(fingerprint);
    engine.startPresenceListener(fingerprint);
    engine.startWatermarkListener(fingerprint);
    listenerState.markActive(fingerprint);
  });
}
```

**Step 2: Call it when contact tile is built**

In `_buildContactList`, modify the ListView.builder itemBuilder to trigger lazy loading:

```dart
// In the itemBuilder, after getting the contact, add:
WidgetsBinding.instance.addPostFrameCallback((_) {
  _ensureContactListener(ref, contact.fingerprint);
});
```

**Step 3: Commit**

```bash
git add dna_messenger_flutter/lib/screens/contacts/contacts_screen.dart
git commit -m "feat: Lazy load listeners when contact becomes visible"
```

---

## Task 8: Sync Messages When Opening Chat

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/chat/chat_screen.dart`

**Step 1: Add offline check in initState**

In `_ChatScreenState.initState()`, add after `_markMessagesAsRead()`:

```dart
// Add after _markMessagesAsRead(); call:
_checkOfflineMessages();
```

**Step 2: Add the helper method**

```dart
Future<void> _checkOfflineMessages() async {
  final contact = ref.read(selectedContactProvider);
  if (contact == null) return;

  try {
    final engine = await ref.read(engineProvider.future);
    // Sync old messages for this contact (lazy sync)
    await engine.checkContactOffline(contact.fingerprint);
  } catch (e) {
    // Non-fatal - just log it
    DnaLogger.error('CHAT', 'Failed to check offline messages: $e');
  }
}
```

**Step 3: Ensure listener is active when opening chat**

In `initState()`, also ensure the listener:

```dart
// In initState, add:
WidgetsBinding.instance.addPostFrameCallback((_) {
  _markMessagesAsRead();
  _checkOfflineMessages();
  _ensureContactListener();
});
```

Add the helper:

```dart
void _ensureContactListener() {
  final contact = ref.read(selectedContactProvider);
  if (contact == null) return;

  final listenerState = ref.read(listenerStateProvider.notifier);
  if (listenerState.hasListener(contact.fingerprint)) return;

  ref.read(engineProvider).whenData((engine) {
    engine.listenOutbox(contact.fingerprint);
    engine.startPresenceListener(contact.fingerprint);
    engine.startWatermarkListener(contact.fingerprint);
    listenerState.markActive(contact.fingerprint);
  });
}
```

**Step 4: Commit**

```bash
git add dna_messenger_flutter/lib/screens/chat/chat_screen.dart
git commit -m "feat: Lazy sync messages and ensure listener when opening chat"
```

---

## Task 9: Bump Versions and Final Commit

**Files:**
- Modify: `include/dna/version.h` (v0.6.4 → v0.6.5)
- Modify: `dna_messenger_flutter/pubspec.yaml` (v0.100.8 → v0.100.9)
- Modify: `CLAUDE.md` (update version refs)

**Step 1: Bump C library version**

```c
#define DNA_VERSION_MAJOR 0
#define DNA_VERSION_MINOR 6
#define DNA_VERSION_PATCH 5

#define DNA_VERSION_STRING "0.6.5"
```

**Step 2: Bump Flutter version**

```yaml
version: 0.100.9+10109
```

**Step 3: Update CLAUDE.md version refs**

Update the header line and version table.

**Step 4: Final commit**

```bash
git add include/dna/version.h dna_messenger_flutter/pubspec.yaml CLAUDE.md
git commit -m "perf: Mobile startup optimization - parallel + lazy loading (v0.6.5/v0.100.9)

- Skip full offline sync on startup (lazy sync when chat opened)
- Remove automatic listener setup from identity load
- Parallel listener subscriptions (8 concurrent threads)
- Service calls listen_all_contacts explicitly
- Flutter lazy loads listeners for visible contacts only

Reduces startup from 45-60s to <1s on mobile."
```

---

## Testing Checklist

After implementation:

1. **Build Android APK:**
   ```bash
   cd /home/mika/dev/dna-messenger
   ./build-cross-compile.sh android-arm64
   cd dna_messenger_flutter && flutter build apk
   ```

2. **Test startup time:**
   - Install APK on device
   - Force stop app, clear from recents
   - Launch app and measure time to chat list

3. **Test notifications (service):**
   - Open app, then swipe away
   - Send message from another device
   - Verify notification appears

4. **Test lazy loading:**
   - Open app with 10+ contacts
   - Check logs for parallel listener setup NOT happening
   - Scroll through contacts, verify no lag
   - Open a chat, verify messages load

5. **Test offline sync:**
   - Send messages while app is closed
   - Open app, open that chat
   - Verify old messages appear (1-2s delay acceptable)
