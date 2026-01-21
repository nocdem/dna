# Battery Optimization Design - Foreground Service

**Date:** 2026-01-21
**Status:** Approved
**Target:** v0.100.20

## Problem

The foreground service uses continuous wakelock (30 min, auto-renewed) to keep DHT listeners active. This drains battery significantly - CPU is awake 100% of the time.

## Solution

Switch from push (listeners) to pull (polling) model:
- Remove continuous wakelock
- Remove DHT listeners
- Poll outboxes every 5 minutes using AlarmManager
- Acquire short wakelock only during check (~30 seconds)

**Battery improvement:** 100% duty cycle → 1% duty cycle

## Architecture

### New Flow

```
Every 5 min (AlarmManager):
  Wake → Acquire wakelock → Init DHT → Check outboxes → Release wakelock → Sleep

On network change:
  Wake → Acquire wakelock → Reinit DHT → Check outboxes → Release wakelock
```

### Constants

```kotlin
POLL_INTERVAL_MS = 5 * 60 * 1000L      // 5 minutes
WAKELOCK_TIMEOUT_MS = 30 * 1000L       // 30 seconds max per check
```

## Changes Required

### 1. JNI Layer (jni/dna_jni.c)

Add synchronous offline message check:

```c
JNIEXPORT jint JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeCheckOfflineMessages(
    JNIEnv *env, jobject thiz)
```

### 2. Service (DnaMessengerService.kt)

**Remove:**
- `LISTEN_RENEWAL_INTERVAL_MS`, `HEALTH_CHECK_*` constants
- `healthCheckHandler`, `wakeLockRenewalHandler`, `listenRenewalTimer`
- `startListenRenewalTimer()`, `stopListenRenewalTimer()`
- `startHealthCheckTimer()`, `stopHealthCheckTimer()`
- `startFastHealthCheck()`, `performHealthCheck()`
- `onDhtReconnected()`
- `nativeSetReconnectHelper()`, `nativeListenAllContacts()` calls
- `fastHealthCheckMode` logic

**Add:**
- `pollAlarmManager` with 5-min repeating alarm
- `performMessageCheck()` - acquire wakelock, init DHT, check messages, release
- `schedulePollAlarm()`, `cancelPollAlarm()`

**Keep:**
- Network callback (triggers immediate check on network change)
- Short-duration wakelock functions
- `ensureIdentityLoaded()` core logic (but remove listener setup)
- Notification helper integration

### 3. Files Unchanged

- AndroidManifest.xml (already has remoteMessaging)
- C library (use existing `dna_engine_check_offline_messages`)

## Trade-offs

- **Pro:** Massive battery savings (~99% reduction in CPU active time)
- **Pro:** Simpler architecture (no listeners, no renewal timers)
- **Con:** Message delivery delayed up to 5 minutes (acceptable per requirements)
- **Con:** Slightly more network overhead per check vs listeners

## Testing

1. Verify messages arrive within 5 minutes when app backgrounded
2. Verify network change triggers immediate check
3. Verify battery usage significantly reduced
4. Verify service survives overnight without being killed
