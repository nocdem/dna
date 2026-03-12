# Inbox Notification Pattern — Implementation Plan

## Context

DNA Connect currently uses 150+ DHT listeners per client (50 contacts × 3 key types: outbox, presence, ACK). As user count grows, this creates unsustainable load on the DHT network.

This plan adds a **client-side inbox notification** mechanism: when Alice sends Bob a message, she also writes a tiny notification to Bob's single inbox key. Bob only needs **1 listener** on his own inbox key instead of 50 separate outbox listeners.

**Phase 1 only:** Message notifications. Outbox listeners kept for backwards compatibility. Future phases can extend inbox to cover presence and ACK, reducing total listeners from 150+ to 2.

---

## Key Design

```
Inbox key: SHA3-512(recipient_fp + ":inbox")
```

One key per user. Multiple senders write to it using per-sender `value_id` (derived from `dht_fingerprint_to_value_id(sender_fp)`). Each sender replaces only their own previous notification — no accumulation.

**Notification payload (142 bytes):**
```
[4 bytes]  magic:      "DNIN" (0x444E494E)
[1 byte]   version:    1
[1 byte]   type:       0x01=message
[8 bytes]  timestamp:  uint64_t Unix timestamp
[128 bytes] sender_fp: full fingerprint (null-terminated)
```

---

## Implementation Steps

### Step 1: Create `dht/shared/dht_inbox_notify.h` and `dht/shared/dht_inbox_notify.c`

New module following `dht_contact_request.c` pattern exactly.

**Header (`dht_inbox_notify.h`):**
- `DHT_INBOX_MAGIC` (0x444E494E), `DHT_INBOX_VERSION` (1)
- `DHT_INBOX_TYPE_MESSAGE` (0x01), reserved types for future (0x02 ACK, 0x03 presence)
- `dht_inbox_notification_t` struct (magic, version, type, timestamp, sender_fingerprint)
- `void dht_generate_inbox_key(const char *fingerprint, uint8_t *key_out)` — SHA3-512(fp + ":inbox")
- `int dht_inbox_notify(dht_context_t *ctx, const char *sender_fp, const char *recipient_fp, uint8_t type)` — fire-and-forget notification publish
- `int dht_inbox_notify_parse(const uint8_t *data, size_t len, dht_inbox_notification_t *out)` — parse raw DHT value
- `int dht_inbox_notify_serialize(const dht_inbox_notification_t *notif, uint8_t *buf, size_t buf_size)` — serialize to binary

**Implementation (`dht_inbox_notify.c`):**
- `dht_generate_inbox_key()`: `snprintf(buf, "%s:inbox", fp)` → `qgp_sha3_512()` → 64-byte key. Pattern from `dht_contact_request.c:32-42`.
- `dht_inbox_notify()`:
  1. Build `dht_inbox_notification_t` with sender_fp, timestamp=time(NULL), type
  2. Serialize to 142-byte buffer
  3. Generate inbox key: `dht_generate_inbox_key(recipient_fp, key)`
  4. Generate value_id: `dht_fingerprint_to_value_id(sender_fp)` (reuse from `dht_contact_request.c:47`)
  5. Call `dht_put_signed(ctx, key, 64, payload, len, value_id, 604800, "inbox_notify")`
  6. Log warning on failure, return 0 regardless (fire-and-forget)
- `dht_inbox_notify_parse()`: Validate magic + version, extract fields, return -1 on corrupt data
- `dht_inbox_notify_serialize()`: Write magic (network byte order), version, type, timestamp (network byte order), sender_fp

### Step 2: Add to build system

**File:** `dht/CMakeLists.txt`

Add after line 31 (`shared/dht_contact_request.c`):
```
shared/dht_inbox_notify.c     # Inbox notification for message alerts
```

### Step 3: Add event type to public API

**File:** `include/dna/dna_engine.h`

Add to `dna_event_type_t` enum (after `DNA_EVENT_WALL_NEW_POST` at line 652):
```c
DNA_EVENT_INBOX_NOTIFICATION,        /* Inbox notification from contact (v0.7.x+) */
```

Add to `dna_event_t` union (after `wall_new_post` struct at line 726):
```c
struct {
    char sender_fingerprint[129];
    uint8_t notification_type;
    uint64_t timestamp;
} inbox_notification;
```

### Step 4: Add inbox listener struct to engine

**File:** `src/api/dna_engine_internal.h`

Add after `dna_contact_request_listener_t` (line 547):
```c
typedef struct {
    size_t dht_token;
    bool active;
} dna_inbox_listener_t;
```

Add to `struct dna_engine` (after `contact_request_listener_mutex` at line 617):
```c
dna_inbox_listener_t inbox_listener;
pthread_mutex_t inbox_listener_mutex;
```

**File:** `src/api/engine/dna_engine.c`

Add `pthread_mutex_init(&engine->inbox_listener_mutex, NULL)` in `dna_engine_create()`.
Add `pthread_mutex_destroy(&engine->inbox_listener_mutex)` in `dna_engine_destroy()`.

### Step 5: Implement inbox listener in engine

**File:** `src/api/engine/dna_engine_listeners.c`

Add new section after contact request listener section (~line 985). Follow `dna_engine_start_contact_request_listener()` pattern (lines 900-961):

**Callback function `inbox_listen_callback()`:**
1. Check `!expired && value && value_len > 0`
2. Parse with `dht_inbox_notify_parse()`
3. Validate sender is a known contact: `contacts_db_exists(sender_fp)`
4. Check sender not blocked: `contacts_db_is_blocked(sender_fp)`
5. Dispatch `DNA_EVENT_INBOX_NOTIFICATION` event with sender_fp, type, timestamp

**Setup function `dna_engine_start_inbox_listener()`:**
1. Lock `inbox_listener_mutex`
2. Check not already active (with stale check via `dht_is_listener_active()`)
3. Generate key: `dht_generate_inbox_key(engine->fingerprint, inbox_key)`
4. Allocate callback context
5. Call `dht_listen_ex(dht_ctx, inbox_key, 64, inbox_listen_callback, ctx, cleanup)`
6. Store token, set active=true
7. Unlock, return token

**Cancel function `dna_engine_cancel_inbox_listener()`:**
1. Lock mutex
2. If active: `dht_cancel_listen()`, set active=false
3. Unlock

### Step 6: Hook inbox listener into engine lifecycle

**File:** `src/api/engine/dna_engine_listeners.c`

In `dna_engine_listen_all_contacts()` (~line 485, after contact request listener start):
```c
dna_engine_start_inbox_listener(engine);
```

In `dna_engine_refresh_listeners()` (~line 800, with other cancel calls):
```c
dna_engine_cancel_inbox_listener(engine);
```

In the 0-contacts early return path (~line 403), also start inbox listener.

### Step 7: Hook notification send into message path

**File:** `messenger_transport.c`

Add `#include "dht/shared/dht_inbox_notify.h"` at top.

In `messenger_queue_to_dht()` at line 544 (after successful queue_result==0):
```c
/* Inbox notification: fire-and-forget signal to recipient */
dht_inbox_notify(dht_ctx, ctx->identity, recipient_fingerprint, DHT_INBOX_TYPE_MESSAGE);
```

### Step 8: Flutter event handling

**File:** `dna_messenger_flutter/lib/ffi/dna_engine.dart`

Add event class (after `WallNewPostEvent`):
```dart
class InboxNotificationEvent extends DnaEvent {
  final String senderFingerprint;
  final int notificationType;
  InboxNotificationEvent(this.senderFingerprint, this.notificationType);
}
```

Add parsing in event callback switch for `DNA_EVENT_INBOX_NOTIFICATION`. Extract `sender_fingerprint` from event data struct offset.

**File:** `dna_messenger_flutter/lib/providers/event_handler.dart`

Add case in `_handleEvent` (after `OutboxUpdatedEvent` case):
```dart
case InboxNotificationEvent(senderFingerprint: final senderFp):
  _scheduleOutboxCheck(senderFp);  // Reuse existing debounce
  break;
```

### Step 9: Update documentation

| File | Update |
|------|--------|
| `docs/DHT_SYSTEM.md` | Add inbox key to key derivation table |
| `docs/MESSAGE_SYSTEM.md` | Add inbox notification to message flow |
| `docs/functions/dht.md` | Add `dht_inbox_notify` functions |

### Step 10: Version bump

C library code changes → bump `include/dna/version.h`
Flutter code changes → bump `dna_messenger_flutter/pubspec.yaml`

---

## Critical Files

| File | Change |
|------|--------|
| `dht/shared/dht_inbox_notify.h` | **NEW** — notification module header |
| `dht/shared/dht_inbox_notify.c` | **NEW** — notification module impl |
| `dht/CMakeLists.txt:31` | Add source file |
| `include/dna/dna_engine.h:652,726` | Add event type + data struct |
| `src/api/dna_engine_internal.h:547,617` | Add listener struct + engine field |
| `src/api/engine/dna_engine.c` | Init/destroy mutex |
| `src/api/engine/dna_engine_listeners.c:485,800,985+` | Inbox listener impl + lifecycle hooks |
| `messenger_transport.c:544` | Send notification after message queue |
| `dna_messenger_flutter/lib/ffi/dna_engine.dart` | InboxNotificationEvent class + parsing |
| `dna_messenger_flutter/lib/providers/event_handler.dart:285` | Handle inbox event |

## Reuse Existing Code

| What | From |
|------|------|
| `dht_fingerprint_to_value_id()` | `dht/shared/dht_contact_request.c:47` |
| `dht_generate_*_key()` pattern | `dht/shared/dht_contact_request.c:32` |
| `qgp_sha3_512()` | `crypto/utils/qgp_sha3.h` |
| Singleton listener pattern | `dna_engine_listeners.c:900-985` (contact request) |
| Event dispatch pattern | `dna_engine_listeners.c:77-117` (outbox callback) |
| `_scheduleOutboxCheck()` debounce | `event_handler.dart:427-449` |
| Network byte order helpers | `dht_contact_request.c:22-27` |

## Backwards Compatibility

- Old clients (no inbox notification) continue working — they just don't send notifications
- New clients listen to inbox key AND existing outbox listeners run simultaneously
- No breaking changes to message format, DHT keys, or database schema
- Gradual rollout: as more clients update, inbox notifications become the primary path

## Verification

1. **Build:** `cd build && cmake .. && make -j$(nproc)` — zero warnings
2. **Flutter:** `cd dna_messenger_flutter && flutter build linux` — zero errors
3. **CLI test send:** `./cli/dna-messenger-cli send <contact> "test"` — verify notification published (check logs for "inbox_notify")
4. **CLI test receive:** On receiving side, check logs for "[INBOX] Notification from..."
5. **Flutter test:** Send message from one device, verify receiving device shows message via inbox notification path (check debug log for INBOX events)
