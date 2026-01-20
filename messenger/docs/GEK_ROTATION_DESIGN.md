# GEK Rotation Design Document

**Status:** PLANNED
**Author:** Claude (Executor)
**Date:** 2026-01-18
**Version:** 1.0

---

## Executive Summary

This document describes the design for two GEK (Group Encryption Key) rotation features:

1. **Remove Member API** - Public API to remove group members (triggers GEK rotation for forward secrecy)
2. **Daily GEK Rotation** - Automatic key rotation every 24 hours by group owners

Both features enhance the security posture of DNA Messenger's group messaging by ensuring cryptographic keys are rotated regularly.

---

## Table of Contents

1. [Background](#1-background)
2. [Current State Analysis](#2-current-state-analysis)
3. [Feature 1: Remove Member API](#3-feature-1-remove-member-api)
4. [Feature 2: Daily GEK Rotation](#4-feature-2-daily-gek-rotation)
5. [Security Considerations](#5-security-considerations)
6. [Implementation Checklist](#6-implementation-checklist)
7. [Testing Strategy](#7-testing-strategy)
8. [Future Enhancements](#8-future-enhancements)

---

## 1. Background

### 1.1 What is GEK?

GEK (Group Encryption Key) is an AES-256 symmetric key used for encrypting group messages. Instead of encrypting each message with every member's public key (expensive with Kyber1024), messages are encrypted once with the GEK, and only the GEK needs to be distributed to members.

### 1.2 GEK Distribution via IKP

Initial Key Packet (IKP) is the mechanism for distributing GEKs:

```
IKP Format:
┌─────────────────────────────────────────────────────────┐
│ Header (45 bytes)                                       │
│   magic(4) || group_uuid(36) || version(4) || count(1) │
├─────────────────────────────────────────────────────────┤
│ Per-Member Entry (1672 bytes each)                      │
│   fingerprint(64) || kyber_ct(1568) || wrapped_gek(40) │
│   [repeated for each member]                            │
├─────────────────────────────────────────────────────────┤
│ Signature Block (~4630 bytes)                           │
│   type(1) || size(2) || dilithium5_signature(~4627)    │
└─────────────────────────────────────────────────────────┘
```

Each member's entry contains the GEK encrypted with their Kyber1024 public key, so only they can decrypt it.

### 1.3 Why Rotate GEKs?

| Trigger | Reason |
|---------|--------|
| Member Added | New member shouldn't read old messages (optional policy) |
| Member Removed | **Critical**: Removed member must NOT decrypt future messages |
| Time-based | Limits exposure if GEK is compromised |

---

## 2. Current State Analysis

### 2.1 What Already Exists

| Component | Status | Location |
|-----------|--------|----------|
| `gek_rotate()` | ✅ Implemented | `messenger/gek.c:389` |
| `gek_rotate_on_member_add()` | ✅ Implemented | `messenger/gek.c:764` |
| `gek_rotate_on_member_remove()` | ✅ Implemented | `messenger/gek.c:769` |
| `gek_rotate_and_publish()` | ✅ Implemented | `messenger/gek.c:590` (internal) |
| `messenger_add_group_member()` | ✅ Implemented | `messenger_groups.c:285` |
| `messenger_remove_group_member()` | ✅ Implemented | `messenger_groups.c:356` |
| `dna_engine_add_group_member()` | ✅ Implemented | `src/api/dna_engine.c:6253` |
| `dna_engine_remove_group_member()` | ❌ **MISSING** | - |
| Daily rotation check | ❌ **MISSING** | - |

### 2.2 GEK Database Schema

```sql
-- Located in: messenger/group_database.c
CREATE TABLE IF NOT EXISTS group_geks (
    group_uuid TEXT NOT NULL,
    version INTEGER NOT NULL,
    encrypted_key BLOB NOT NULL,    -- Encrypted with Kyber1024 + AES-256-GCM
    created_at INTEGER NOT NULL,    -- Unix timestamp (seconds)
    expires_at INTEGER NOT NULL,    -- created_at + 7 days
    PRIMARY KEY (group_uuid, version)
);
```

**Key fields for rotation tracking:**
- `created_at`: When the GEK was created/rotated
- `version`: Monotonically increasing counter (0, 1, 2, ...)

### 2.3 Group Ownership

Groups track ownership in two places:

1. **DHT Metadata** (`dht_group_cache` table):
   ```sql
   creator TEXT NOT NULL  -- Owner's 128-char hex fingerprint
   ```

2. **Local Groups** (`groups` table):
   ```sql
   owner_fp TEXT NOT NULL
   is_owner INTEGER DEFAULT 0
   ```

**Ownership check:** `strcmp(group.creator, my_fingerprint) == 0`

---

## 3. Feature 1: Remove Member API

### 3.1 Goal

Expose `messenger_remove_group_member()` to the Flutter app via the public API.

### 3.2 Architecture

```
Flutter App
     │
     ▼
┌─────────────────────────────────────┐
│ dna_engine_remove_group_member()    │  ← NEW: Public API
│   - Validate inputs                 │
│   - Submit task to queue            │
└─────────────────────────────────────┘
     │
     ▼ (Worker Thread)
┌─────────────────────────────────────┐
│ dna_handle_remove_group_member()    │  ← NEW: Task handler
│   - Lookup group_id from UUID       │
│   - Call messenger API              │
│   - Invoke callback                 │
└─────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ messenger_remove_group_member()     │  ← EXISTS
│   - Remove from DHT                 │
│   - Sync local cache                │
│   - Rotate GEK                      │
└─────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ gek_rotate_on_member_remove()       │  ← EXISTS
│   - Generate new GEK                │
│   - Build IKP (excludes removed)    │
│   - Publish to DHT                  │
└─────────────────────────────────────┘
```

### 3.3 Implementation Details

#### 3.3.1 Add Task Type

**File:** `src/api/dna_engine_internal.h`

```c
typedef enum {
    // ... existing types ...
    TASK_ADD_GROUP_MEMBER,
    TASK_REMOVE_GROUP_MEMBER,    // ← ADD THIS
    TASK_GET_INVITATIONS,
    // ...
} dna_task_type_t;
```

The existing `add_group_member` params union can be reused:
```c
/* Add group member - reuse for remove */
struct {
    char group_uuid[37];
    char fingerprint[129];
} add_group_member;
```

#### 3.3.2 Add Public API Function

**File:** `src/api/dna_engine.c`

```c
dna_request_id_t dna_engine_remove_group_member(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !fingerprint || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.add_group_member.group_uuid, group_uuid, 36);
    strncpy(params.add_group_member.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REMOVE_GROUP_MEMBER, &params, cb, user_data);
}
```

#### 3.3.3 Add Task Handler

**File:** `src/api/dna_engine.c`

```c
void dna_handle_remove_group_member(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Look up group_id from UUID using local cache */
    dht_group_cache_entry_t *entries = NULL;
    int entry_count = 0;
    if (dht_groups_list_for_user(engine->fingerprint, &entries, &entry_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    int group_id = -1;
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].group_uuid, task->params.add_group_member.group_uuid) == 0) {
            group_id = entries[i].local_id;
            break;
        }
    }
    dht_groups_free_cache_entries(entries, entry_count);

    if (group_id < 0) {
        error = DNA_ENGINE_ERROR_NOT_FOUND;
        goto done;
    }

    /* Remove member using messenger API */
    int rc = messenger_remove_group_member(
        engine->messenger,
        group_id,
        task->params.add_group_member.fingerprint
    );

    if (rc == -2) {
        error = DNA_ENGINE_ERROR_PERMISSION;  // Not owner
    } else if (rc == -3) {
        error = DNA_ENGINE_ERROR_NOT_FOUND;   // Not a member
    } else if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}
```

#### 3.3.4 Add Header Declaration

**File:** `include/dna/dna_engine.h`

```c
/**
 * Remove member from group
 *
 * Removes member from group in DHT, rotates GEK (forward secrecy).
 * Only group owner can remove members.
 *
 * @param engine      Engine instance
 * @param group_uuid  Group UUID
 * @param fingerprint Member fingerprint to remove
 * @param callback    Called on completion
 * @param user_data   User data for callback
 * @return            Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_remove_group_member(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);
```

#### 3.3.5 Add Switch Case

**File:** `src/api/dna_engine.c` (in `dna_execute_task()`)

```c
case TASK_ADD_GROUP_MEMBER:
    dna_handle_add_group_member(engine, task);
    break;
case TASK_REMOVE_GROUP_MEMBER:    // ← ADD THIS
    dna_handle_remove_group_member(engine, task);
    break;
case TASK_GET_INVITATIONS:
    dna_handle_get_invitations(engine, task);
    break;
```

#### 3.3.6 Flutter FFI Binding

**File:** `dna_messenger_flutter/lib/ffi/dna_bindings.dart`

```dart
// Add typedef
typedef DnaEngineRemoveGroupMemberNative = Uint64 Function(
  Pointer<dna_engine_t> engine,
  Pointer<Utf8> groupUuid,
  Pointer<Utf8> fingerprint,
  Pointer<NativeFunction<DnaCompletionCbNative>> callback,
  Pointer<Void> userData,
);

typedef DnaEngineRemoveGroupMemberDart = int Function(
  Pointer<dna_engine_t> engine,
  Pointer<Utf8> groupUuid,
  Pointer<Utf8> fingerprint,
  Pointer<NativeFunction<DnaCompletionCbNative>> callback,
  Pointer<Void> userData,
);

// Add lookup in class
late final DnaEngineRemoveGroupMemberDart dna_engine_remove_group_member =
    _lib.lookupFunction<DnaEngineRemoveGroupMemberNative,
        DnaEngineRemoveGroupMemberDart>('dna_engine_remove_group_member');
```

**File:** `dna_messenger_flutter/lib/ffi/dna_engine.dart`

```dart
/// Remove member from group (owner only)
/// Triggers GEK rotation for forward secrecy
Future<void> removeGroupMember(String groupUuid, String fingerprint) async {
  final completer = Completer<void>();
  final localId = _nextLocalId++;

  final uuidPtr = groupUuid.toNativeUtf8();
  final fpPtr = fingerprint.toNativeUtf8();

  void onComplete(int requestId, int error, Pointer<Void> userData) {
    calloc.free(uuidPtr);
    calloc.free(fpPtr);

    if (error == 0) {
      completer.complete();
    } else {
      completer.completeError(DnaEngineException.fromCode(error, _bindings));
    }
    _cleanupRequest(localId);
  }

  final callback = NativeCallable<DnaCompletionCbNative>.listener(onComplete);
  _pendingRequests[localId] = _PendingRequest(callback: callback);

  final requestId = _bindings.dna_engine_remove_group_member(
    _engine,
    uuidPtr.cast(),
    fpPtr.cast(),
    callback.nativeFunction.cast(),
    nullptr,
  );

  if (requestId == 0) {
    calloc.free(uuidPtr);
    calloc.free(fpPtr);
    _cleanupRequest(localId);
    throw DnaEngineException(-1, 'Failed to submit request');
  }

  return completer.future;
}
```

---

## 4. Feature 2: Daily GEK Rotation

### 4.1 Goal

Group owners automatically rotate GEK every 24 hours when online, limiting cryptographic exposure windows.

### 4.2 Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Presence Heartbeat Thread (runs every 4 minutes)        │
│   src/api/dna_engine.c:presence_heartbeat_thread()      │
└─────────────────────────────────────────────────────────┘
     │
     ├──► messenger_transport_refresh_presence()  ← EXISTS
     ├──► dna_engine_check_group_day_rotation()   ← EXISTS
     ├──► dna_engine_check_outbox_day_rotation()  ← EXISTS
     └──► dna_engine_check_gek_daily_rotation()   ← NEW
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│ For each group owned by current user:                   │
│   1. Check: gek_needs_daily_rotation(group_uuid)        │
│   2. If yes: gek_rotate_on_member_add(...)              │
│   3. Log: [GEK] Daily rotation for group <name>         │
└─────────────────────────────────────────────────────────┘
```

### 4.3 Implementation Details

#### 4.3.1 Add Rotation Check Function

**File:** `messenger/gek.h`

```c
/**
 * Check if GEK needs daily rotation
 *
 * Checks if the most recent GEK for this group was created more than
 * 24 hours ago. Used for automatic daily key rotation.
 *
 * @param group_uuid Group UUID (36-char UUID v4 string)
 * @return 1 if needs rotation (>24h since last), 0 if not, -1 on error
 */
int gek_needs_daily_rotation(const char *group_uuid);

/**
 * Daily rotation threshold (24 hours in seconds)
 */
#define GEK_DAILY_ROTATION_THRESHOLD (24 * 3600)
```

**File:** `messenger/gek.c`

```c
int gek_needs_daily_rotation(const char *group_uuid) {
    if (!group_uuid || !msg_db) {
        return -1;
    }

    /* Query the most recent GEK creation time for this group */
    const char *sql = "SELECT MAX(created_at) FROM group_geks WHERE group_uuid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(msg_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare gek rotation check: %s\n",
                      sqlite3_errmsg(msg_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_STATIC);

    int result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            uint64_t created_at = (uint64_t)sqlite3_column_int64(stmt, 0);
            uint64_t now = (uint64_t)time(NULL);
            uint64_t age = now - created_at;

            /* Check if older than 24 hours */
            result = (age > GEK_DAILY_ROTATION_THRESHOLD) ? 1 : 0;

            QGP_LOG_DEBUG(LOG_TAG, "GEK for %s: age=%llu seconds (%s rotation)\n",
                          group_uuid, (unsigned long long)age,
                          result ? "needs" : "no");
        } else {
            /* No GEK exists - needs rotation */
            result = 1;
        }
    }

    sqlite3_finalize(stmt);
    return result;
}
```

#### 4.3.2 Add Engine Daily Rotation Check

**File:** `src/api/dna_engine_internal.h`

```c
/**
 * @brief Check and rotate GEKs for owned groups (daily rotation)
 *
 * Called from heartbeat thread every 4 minutes. Actual rotation only
 * happens if >24 hours since last rotation for that group.
 *
 * Only rotates GEKs for groups where the current user is the owner.
 *
 * @param engine Engine instance
 * @return Number of groups that were rotated
 */
int dna_engine_check_gek_daily_rotation(dna_engine_t *engine);
```

**File:** `src/api/dna_engine.c`

```c
int dna_engine_check_gek_daily_rotation(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return 0;
    }

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        return 0;
    }

    /* Get all groups user belongs to */
    dht_group_cache_entry_t *groups = NULL;
    int count = 0;
    if (dht_groups_list_for_user(engine->fingerprint, &groups, &count) != 0) {
        QGP_LOG_WARN(LOG_TAG, "[GEK] Failed to list groups for daily rotation check\n");
        return 0;
    }

    int rotated = 0;

    /* Check each group where we are the owner */
    for (int i = 0; i < count; i++) {
        /* Skip groups we don't own */
        if (strcmp(groups[i].creator, engine->fingerprint) != 0) {
            continue;
        }

        /* Check if this group needs daily rotation */
        int needs_rotation = gek_needs_daily_rotation(groups[i].group_uuid);
        if (needs_rotation != 1) {
            continue;  /* No rotation needed or error */
        }

        /* Perform rotation */
        QGP_LOG_INFO(LOG_TAG, "[GEK] Daily rotation for owned group: %s (%s)\n",
                     groups[i].name, groups[i].group_uuid);

        int rc = gek_rotate_on_member_add(dht_ctx, groups[i].group_uuid, engine->fingerprint);
        if (rc != 0) {
            QGP_LOG_WARN(LOG_TAG, "[GEK] Daily rotation failed for group %s (non-fatal)\n",
                         groups[i].group_uuid);
            /* Continue with other groups */
        } else {
            rotated++;
        }
    }

    dht_groups_free_cache_entries(groups, count);

    if (rotated > 0) {
        QGP_LOG_INFO(LOG_TAG, "[GEK] Daily rotation completed: %d group(s) rotated\n", rotated);
    }

    return rotated;
}
```

#### 4.3.3 Call from Heartbeat Thread

**File:** `src/api/dna_engine.c` (in `presence_heartbeat_thread()`)

```c
/* Only announce presence if active (foreground) */
if (atomic_load(&engine->presence_active) && engine->messenger) {
    QGP_LOG_DEBUG(LOG_TAG, "Heartbeat: refreshing presence");
    messenger_transport_refresh_presence(engine->messenger);
}

/* Check for day rotation on group listeners */
dna_engine_check_group_day_rotation(engine);

/* Check for day rotation on 1-1 DM outbox listeners (v0.4.81+) */
dna_engine_check_outbox_day_rotation(engine);

/* Check for GEK daily rotation (owner only, runs every 4 min,
 * actual rotation only happens if >24h since last rotation) */
dna_engine_check_gek_daily_rotation(engine);  // ← ADD THIS
```

### 4.4 Timing Analysis

| Event | Frequency | Actual Work |
|-------|-----------|-------------|
| Heartbeat tick | Every 4 minutes | Check timestamp |
| Rotation check | Every 4 minutes | ~1ms database query per group |
| Actual rotation | Once per 24 hours | ~500ms (crypto + DHT publish) |

**Impact:** Minimal. Most heartbeats will:
1. Query database for GEK creation time
2. Compare with 24-hour threshold
3. Skip rotation (no work)

---

## 5. Security Considerations

### 5.1 Forward Secrecy on Member Remove

When a member is removed:

1. **GEK is rotated immediately** - New random AES-256 key generated
2. **New IKP built** - Contains entries ONLY for remaining members
3. **Published to DHT** - All members get notified
4. **Removed member cannot decrypt** - Their fingerprint not in IKP

```
Before: IKP contains entries for [Alice, Bob, Eve]
Remove: Eve is removed
After:  IKP contains entries for [Alice, Bob] - Eve excluded
        Eve cannot decrypt future messages (no GEK entry for her)
```

### 5.2 Daily Rotation Benefits

| Threat | Mitigation |
|--------|------------|
| GEK compromise | Max exposure window: 24 hours |
| Long-lived groups | Keys still rotate even with stable membership |
| Passive attacker | Historical keys don't help with new messages |

### 5.3 IKP Signature Verification

All IKPs are signed with the owner's Dilithium5 key:

1. Owner generates IKP with new GEK
2. Owner signs IKP with Dilithium5 private key
3. Members verify signature against owner's public key
4. Only accept IKP if signature valid

**Attack prevention:** Malicious members cannot forge IKPs or inject fake GEKs.

### 5.4 Race Conditions

**Scenario:** Owner rotates GEK while member is sending message.

**Handling:**
- Messages include GEK version in encrypted header
- Recipients can decrypt with matching GEK version
- Old GEKs kept for 7 days (`GEK_DEFAULT_EXPIRY`)
- Recipients fetch missed IKPs on sync

---

## 6. Implementation Checklist

### Part 1: Remove Member API

- [ ] Add `TASK_REMOVE_GROUP_MEMBER` to `dna_engine_internal.h`
- [ ] Add `dna_handle_remove_group_member()` forward declaration
- [ ] Add switch case in `dna_execute_task()`
- [ ] Implement `dna_handle_remove_group_member()` handler
- [ ] Add `dna_engine_remove_group_member()` public API
- [ ] Add declaration to `include/dna/dna_engine.h`
- [ ] Add Flutter FFI binding in `dna_bindings.dart`
- [ ] Add `removeGroupMember()` method in `dna_engine.dart`
- [ ] Update `docs/functions/public-api.md`

### Part 2: Daily GEK Rotation

- [ ] Add `GEK_DAILY_ROTATION_THRESHOLD` constant to `gek.h`
- [ ] Add `gek_needs_daily_rotation()` declaration to `gek.h`
- [ ] Implement `gek_needs_daily_rotation()` in `gek.c`
- [ ] Add `dna_engine_check_gek_daily_rotation()` declaration to `dna_engine_internal.h`
- [ ] Implement `dna_engine_check_gek_daily_rotation()` in `dna_engine.c`
- [ ] Call from `presence_heartbeat_thread()`
- [ ] Update `docs/functions/messenger.md`

---

## 7. Testing Strategy

### 7.1 Unit Tests

```c
/* Test gek_needs_daily_rotation() */
void test_gek_needs_rotation_fresh(void) {
    // Create GEK with current timestamp
    // gek_needs_daily_rotation() should return 0
}

void test_gek_needs_rotation_old(void) {
    // Create GEK with timestamp > 24h ago
    // gek_needs_daily_rotation() should return 1
}

void test_gek_needs_rotation_no_gek(void) {
    // No GEK exists for group
    // gek_needs_daily_rotation() should return 1
}
```

### 7.2 Integration Tests

**Test: Remove Member Triggers GEK Rotation**
1. Create group with 3 members
2. Record GEK version
3. Remove one member
4. Verify GEK version incremented
5. Verify removed member cannot decrypt new messages

**Test: Daily Rotation**
1. Create group owned by test user
2. Manually set GEK `created_at` to 25 hours ago
3. Trigger heartbeat or call `dna_engine_check_gek_daily_rotation()`
4. Verify GEK version incremented
5. Verify new IKP published to DHT

### 7.3 CLI Testing

```bash
# Test remove member (if CLI command added)
./dna-messenger-cli group-remove-member <group-uuid> <member-fp>

# Check GEK version
./dna-messenger-cli group-info <group-uuid>
# Output should show: GEK Version: X

# Check logs for daily rotation
grep "\[GEK\] Daily rotation" /var/log/dna-messenger.log
```

---

## 8. Future Enhancements

### 8.1 Configurable Rotation Interval

Allow users to configure rotation frequency:
```c
#define GEK_ROTATION_INTERVAL_HOURS 24  // Default
// Could be 12, 24, 48, 168 (weekly)
```

### 8.2 Rotation Notification Event

Fire event to Flutter when GEK is rotated:
```c
DNA_EVENT_GEK_ROTATED
  - group_uuid
  - new_version
  - rotated_by (fingerprint)
```

### 8.3 Per-Message Key Ratcheting

Signal-style key ratcheting for maximum forward secrecy:
- New key derived for each message
- Significantly more complex
- Better security guarantees

### 8.4 Offline Owner Fallback

What if owner is offline for extended period?
- Option 1: Allow any admin to rotate
- Option 2: Automatic rotation by longest-online member
- Option 3: Accept stale GEK until owner returns

---

## Appendix A: Related Files

| File | Purpose |
|------|---------|
| `messenger/gek.h` | GEK API declarations |
| `messenger/gek.c` | GEK implementation |
| `messenger/group_database.c` | `group_geks` table schema |
| `messenger_groups.c` | Group member management |
| `dht/shared/dht_groups.c` | DHT group metadata |
| `src/api/dna_engine.c` | Public API + heartbeat thread |
| `src/api/dna_engine_internal.h` | Internal task types |
| `include/dna/dna_engine.h` | Public API declarations |

---

## Appendix B: Database Queries

```sql
-- Get last GEK rotation time for a group
SELECT MAX(created_at) FROM group_geks WHERE group_uuid = ?;

-- Get all groups owned by user
SELECT DISTINCT c.group_uuid, c.name, c.creator
FROM dht_group_cache c
INNER JOIN dht_group_members m ON c.group_uuid = m.group_uuid
WHERE m.member_identity = ? AND c.creator = ?;

-- Get current GEK version
SELECT MAX(version) FROM group_geks WHERE group_uuid = ?;

-- Check if GEK is expired
SELECT 1 FROM group_geks
WHERE group_uuid = ? AND expires_at > strftime('%s', 'now')
ORDER BY version DESC LIMIT 1;
```

---

*End of Design Document*
