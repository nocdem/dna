# Listener DHT Readiness Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ensure listeners start only when DHT is ready, and Android service only starts notification-relevant listeners.

**Architecture:** Wait for DHT peers before subscribing. Separate "minimal" listener function for service (no presence/watermark).

**Tech Stack:** C (dna_engine.c), Kotlin (DnaMessengerService.kt), Dart (identity_provider.dart)

---

## Problem Statement

1. **Listeners start before DHT ready** - Presence shows "never online" because lookup happens before routing table has peers
2. **Android service starts unnecessary listeners** - Presence and watermark listeners are useless for background notifications

## Solution

### 1. DHT Readiness Wait

Add wait loop before listener setup. DHT is "ready" when `dht_context_is_ready()` returns true (≥1 good node in routing table).

```c
// Wait up to 30 seconds for DHT to become ready
int wait_seconds = 0;
while (!dht_context_is_ready(dht_ctx) && wait_seconds < 30) {
    qgp_platform_sleep_ms(1000);
    wait_seconds++;
}
if (!dht_context_is_ready(dht_ctx)) {
    QGP_LOG_WARN(LOG_TAG, "DHT not ready after 30s, starting listeners anyway");
}
```

### 2. Minimal Listener Function for Service (JNI only)

New separate function for Android ForegroundService (called via JNI):

```c
// For JNI/service - notifications only
int dna_engine_listen_all_contacts_minimal(dna_engine_t *engine)

// For Flutter FFI - full UI (unchanged)
int dna_engine_listen_all_contacts(dna_engine_t *engine)
```

**Minimal version starts:**
- Outbox listeners (private message notifications)
- Contact request listener
- Group outbox listeners

**Minimal version skips:**
- Presence listeners (not needed for notifications)
- Watermark listeners (not needed for notifications)

**Full version (Flutter):** Starts ALL listeners including presence and watermark.

### 3. Flutter Background Listener Setup

After identity loads, trigger background listener setup:

```dart
// In identity_provider.dart after identity loaded
Future<void> _setupListenersInBackground(DnaEngine engine) async {
  // This runs in background, doesn't block UI
  await engine.listenAllContacts();  // Waits for DHT ready internally
}
```

## Changes Required

### C Layer (src/api/dna_engine.c)

1. Add `_wait_for_dht_ready()` helper function
2. Add `dna_engine_listen_all_contacts_minimal()` - skips presence/watermark
3. Update `dna_engine_listen_all_contacts()` to call wait helper first
4. Update listener setup background thread to wait for DHT ready

### JNI Layer (jni/dna_jni.c)

1. Update `nativeListenAllContacts()` to call `dna_engine_listen_all_contacts_minimal()`

### Flutter Layer

1. `identity_provider.dart`: After identity loads, call `listenAllContacts()` in background
2. Remove lazy loading from contacts_screen.dart and chat_screen.dart (listeners already active)

## Task Breakdown

### Task 1: Add DHT ready wait helper in C
- File: `src/api/dna_engine.c`
- Add `static void _wait_for_dht_ready(dna_engine_t *engine, int max_seconds)`

### Task 2: Add minimal listener function for JNI/service
- File: `src/api/dna_engine.c`
- Add `int dna_engine_listen_all_contacts_minimal(dna_engine_t *engine)`
- Starts: outbox, contact request, groups
- Skips: presence, watermark
- Calls DHT wait helper first

### Task 3: Update full listener function to wait for DHT
- File: `src/api/dna_engine.c`
- Update `dna_engine_listen_all_contacts()` to call wait helper first
- Keep ALL listeners (presence, watermark included) - used by Flutter

### Task 4: Update JNI to use minimal function
- File: `jni/dna_jni.c`
- Change `nativeListenAllContacts()` to call `dna_engine_listen_all_contacts_minimal()`

### Task 5: Add declaration to header
- File: `include/dna/dna_engine.h`
- Add `int dna_engine_listen_all_contacts_minimal(dna_engine_t *engine);`

### Task 6: Add Flutter background listener setup
- File: `dna_messenger_flutter/lib/providers/identity_provider.dart`
- After identity loaded event, trigger `listenAllContacts()` in background isolate/future

### Task 7: Remove lazy loading from Flutter screens
- Files: `contacts_screen.dart`, `chat_screen.dart`
- Remove `_ensureListenerStarted()` calls - listeners already active from startup

### Task 8: Test and verify
- Build and test on Android
- Verify presence shows correct "last seen" times
- Verify notifications work when app killed

## Version Bump

- C Library: v0.6.5 → v0.6.6 (listener changes)
- Flutter: v0.100.9 → v0.100.10 (background listener setup)
