# Feed Cache Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a global SQLite cache for feed topics and comments with stale-while-revalidate semantics, reducing feed screen load time from 5-15s to ~1ms.

**Architecture:** New `database/feed_cache.c` module following the established `profile_cache` pattern. Handlers in `dna_engine_feed.c` check cache before DHT, fire callback immediately with cached data, then submit background revalidation if stale. A new `DNA_EVENT_FEED_CACHE_UPDATED` event triggers Flutter UI refresh when background data arrives.

**Tech Stack:** C (SQLite3), Dart/Flutter (Riverpod providers)

**Design Doc:** `docs/plans/2026-02-22-feed-cache-design.md`

---

### Task 1: Create feed_cache.h header

**Files:**
- Create: `database/feed_cache.h`

**Step 1: Write the header file**

```c
#ifndef DNA_FEED_CACHE_H
#define DNA_FEED_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Forward declarations to avoid circular includes */
typedef struct dna_feed_topic_info dna_feed_topic_info_t;
typedef struct dna_feed_comment_info dna_feed_comment_info_t;

#define FEED_CACHE_TTL_SECONDS      300       /* 5 minutes staleness window */
#define FEED_CACHE_EVICT_SECONDS    2592000   /* 30 days max age */

/* Lifecycle */
int  feed_cache_init(void);
void feed_cache_close(void);
int  feed_cache_evict_expired(void);

/* Single topic */
int  feed_cache_put_topic_json(const char *uuid, const char *topic_json,
                               const char *category_id, uint64_t created_at,
                               int deleted);
int  feed_cache_get_topic_json(const char *uuid, char **topic_json_out);
int  feed_cache_delete_topic(const char *uuid);

/* Bulk topic listing (from index results) */
int  feed_cache_get_topics_by_category(const char *category_id, int days_back,
                                       char ***topic_jsons_out, int *count);
int  feed_cache_get_topics_all(int days_back,
                               char ***topic_jsons_out, int *count);
void feed_cache_free_json_list(char **jsons, int count);

/* Comments */
int  feed_cache_put_comments(const char *topic_uuid,
                             const char *comments_json, int comment_count);
int  feed_cache_get_comments(const char *topic_uuid,
                             char **comments_json_out, int *comment_count_out);
int  feed_cache_invalidate_comments(const char *topic_uuid);

/* Staleness check */
int  feed_cache_update_meta(const char *cache_key);
bool feed_cache_is_stale(const char *cache_key);

/* Stats */
int  feed_cache_stats(int *total_topics, int *total_comments, int *expired);

#endif /* DNA_FEED_CACHE_H */
```

**Notes:**
- Uses JSON strings rather than typed structs to avoid complex serialization in the cache layer. The engine handlers already have JSON to struct conversion.
- Forward-declares info structs to avoid pulling in the full `dna_engine.h` header.
- Check `include/dna/dna_engine.h:248-275` for `dna_feed_topic_info_t` and `dna_feed_comment_info_t` struct names. The forward declarations must match the actual typedef pattern used there.

**Step 2: Commit**

```bash
git add database/feed_cache.h
git commit -m "feat: Add feed_cache.h header for feed caching system"
```

---

### Task 2: Implement feed_cache.c - Lifecycle and Schema

**Files:**
- Create: `database/feed_cache.c`
- Reference: `database/profile_cache.c` (lines 54-138 for init pattern, 553-559 for close)

**Step 1: Write lifecycle functions (init, close, evict)**

Follow the exact pattern from `profile_cache.c`:
- `sqlite3_open_v2()` with `SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX`
- `sqlite3_busy_timeout(g_db, 5000)` for Android crash recovery
- WAL checkpoint: `sqlite3_wal_checkpoint(g_db, NULL)`
- CREATE TABLE IF NOT EXISTS for all 3 tables (see design doc schema)
- CREATE INDEX statements
- Global `static sqlite3 *g_cache_db = NULL` pointer
- `LOG_TAG` = `"FEED_CACHE"`
- Database path: construct from data dir using `qgp_get_data_dir()` same as profile_cache

Init function:
- Build path: `{data_dir}/db/feed_cache.db`
- Open with FULLMUTEX
- Set busy timeout 5000ms
- WAL checkpoint
- Execute schema (3 tables + indexes)
- Log success

Close function:
- sqlite3_close if non-NULL, set to NULL

Evict function:
- Delete from all 3 tables where cached_at/last_fetched < (now - 30 days)
- Return total evicted count

**Step 2: Commit**

```bash
git add database/feed_cache.c
git commit -m "feat: Add feed_cache.c lifecycle (init, close, evict)"
```

---

### Task 3: Implement feed_cache.c - Topic and Comment Operations

**Files:**
- Modify: `database/feed_cache.c`
- Reference: `database/profile_cache.c` (lines 143-249 for put/get SQL pattern)

**Step 1: Add topic operations**

- `feed_cache_put_topic_json()`: INSERT OR REPLACE with cached_at = now
- `feed_cache_get_topic_json()`: SELECT topic_json WHERE uuid = ?, return strdup'd string
- `feed_cache_delete_topic()`: DELETE WHERE uuid = ?
- `feed_cache_get_topics_all()`: SELECT topic_json WHERE created_at >= cutoff AND deleted = 0 ORDER BY created_at DESC. Return dynamically-grown array of strdup'd strings.
- `feed_cache_get_topics_by_category()`: Same but with category_id filter
- `feed_cache_free_json_list()`: Free array of strings

All follow the profile_cache pattern: prepare statement, bind params, step, finalize.
Return -2 for not found, -1 for error, -3 for uninitialized, 0 for success.

**Step 2: Add comment operations**

- `feed_cache_put_comments()`: INSERT OR REPLACE comments_json for topic_uuid
- `feed_cache_get_comments()`: SELECT comments_json, comment_count WHERE topic_uuid = ?
- `feed_cache_invalidate_comments()`: DELETE WHERE topic_uuid = ?

**Step 3: Add staleness and stats operations**

- `feed_cache_update_meta()`: INSERT OR REPLACE into feed_cache_meta with last_fetched = now
- `feed_cache_is_stale()`: SELECT last_fetched WHERE cache_key = ?. Return true if (now - last_fetched) >= 300 or not found
- `feed_cache_stats()`: COUNT queries on feed_topics and feed_comments tables

**Step 4: Commit**

```bash
git add database/feed_cache.c
git commit -m "feat: Add feed cache topic, comment, staleness, and stats operations"
```

---

### Task 4: Add feed_cache.c to Build System

**Files:**
- Modify: `CMakeLists.txt` (lines 210-218, database source files section)

**Step 1: Add feed_cache.c to the source list**

Find `database/feed_subscriptions_db.c` (line 215) and add after it:
```cmake
database/feed_cache.c
```

**IMPORTANT:** The file appears in TWO places in CMakeLists.txt: the SHARED library target (lines 172-248) and the STATIC library target (lines 250-299). Add to BOTH.

**Step 2: Build and verify compilation**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

Expected: Clean build with no errors. Check for any warnings in feed_cache.c.

**Step 3: Commit**

```bash
git add CMakeLists.txt
git commit -m "build: Add feed_cache.c to CMake build"
```

---

### Task 5: Register Feed Cache in Cache Manager

**Files:**
- Modify: `database/cache_manager.c`
  - Init section (around line 70, after `presence_cache_init()`)
  - Cleanup section (around line 108, before `presence_cache_free()`)
  - Eviction section (around line 136, after keyserver eviction)

**Step 1: Add include at top**

```c
#include "feed_cache.h"
```

**Step 2: Add init call in `cache_manager_init()`**

After `presence_cache_init()` (around line 70):
```c
    /* Feed cache (global - public DHT data) */
    if (feed_cache_init() != 0) {
        QGP_LOG_WARN(LOG_TAG, "Feed cache init failed (non-fatal)");
    }
```

**Step 3: Add cleanup call in `cache_manager_cleanup()`**

Before `presence_cache_free()` (around line 108):
```c
    feed_cache_close();
```

**Step 4: Add eviction in `cache_manager_evict_expired()`**

After keyserver eviction (around line 142):
```c
    int feed_evicted = feed_cache_evict_expired();
    if (feed_evicted > 0) {
        QGP_LOG_INFO(LOG_TAG, "Feed cache: evicted %d expired entries", feed_evicted);
        total_evicted += feed_evicted;
    }
```

**Step 5: Build and verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 6: Commit**

```bash
git add database/cache_manager.c
git commit -m "feat: Register feed cache in cache manager lifecycle"
```

---

### Task 6: Add Event and Task Types for Background Revalidation

**Files:**
- Modify: `include/dna/dna_engine.h` (event enum around line 626, event data union around line 685)
- Modify: `src/api/dna_engine_internal.h` (task enum at line 142, params union, handler declarations)
- Modify: `src/api/dna_engine.c` (dispatch switch around line 1155)

**Step 1: Add event type in dna_engine.h**

Find `DNA_EVENT_FEED_SUBSCRIPTIONS_SYNCED` (line 626) and add after it:
```c
    DNA_EVENT_FEED_CACHE_UPDATED,        /* Feed cache refreshed with new DHT data (v0.6.121+) */
```

Ensure `DNA_EVENT_ERROR` remains the last entry.

**Step 2: Add event data struct in dna_engine.h**

In the event data union (around line 685-692), add:
```c
    struct {
        char cache_key[64];
    } feed_cache_updated;
```

**Step 3: Add revalidation task types in dna_engine_internal.h**

Find `TASK_FEED_REINDEX_TOPIC` (line 142) and add before the closing brace:
```c
    /* Feed cache revalidation (v0.6.121+) */
    TASK_FEED_REVALIDATE_INDEX,
    TASK_FEED_REVALIDATE_TOPIC,
    TASK_FEED_REVALIDATE_COMMENTS
```

**Step 4: Add revalidation params structs in dna_engine_internal.h**

In the params union (around line 360), add:
```c
    struct {
        char category[65];
        int days_back;
        char cache_key[64];
    } feed_revalidate_index;

    struct {
        char uuid[37];
    } feed_revalidate_topic;

    struct {
        char topic_uuid[37];
    } feed_revalidate_comments;
```

**Step 5: Add handler declarations in dna_engine_internal.h**

In handler declarations section (around line 780):
```c
void dna_handle_feed_revalidate_index(dna_engine_t *engine, dna_task_t *task);
void dna_handle_feed_revalidate_topic(dna_engine_t *engine, dna_task_t *task);
void dna_handle_feed_revalidate_comments(dna_engine_t *engine, dna_task_t *task);
```

**Step 6: Add dispatch cases in dna_engine.c**

After `TASK_FEED_REINDEX_TOPIC` case (around line 1157):
```c
        case TASK_FEED_REVALIDATE_INDEX:
            dna_handle_feed_revalidate_index(engine, task);
            break;
        case TASK_FEED_REVALIDATE_TOPIC:
            dna_handle_feed_revalidate_topic(engine, task);
            break;
        case TASK_FEED_REVALIDATE_COMMENTS:
            dna_handle_feed_revalidate_comments(engine, task);
            break;
```

**Step 7: Build and verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

Note: Expect linker warnings about unresolved `dna_handle_feed_revalidate_*` until Task 7.

**Step 8: Commit**

```bash
git add include/dna/dna_engine.h src/api/dna_engine_internal.h src/api/dna_engine.c
git commit -m "feat: Add feed cache event type and revalidation task types"
```

---

### Task 7: Implement Background Revalidation Handlers

**Files:**
- Modify: `src/api/engine/dna_engine_feed.c` (add new handler functions at end of file)

**Pre-check:** Verify JSON serialization function names exist:
```bash
grep -n "topic_to_json\|topic_from_json\|comments_to_json\|comments_from_json" dht/client/dna_feed*.c
```
Adjust function names in code below if they differ.

**Step 1: Add include at top of dna_engine_feed.c**

```c
#include "database/feed_cache.h"
```

**Step 2: Add three revalidation handlers at end of file**

Each handler:
1. Fetches fresh data from DHT (reusing existing DHT calls)
2. Serializes to JSON and stores in cache
3. Updates cache meta timestamp
4. Fires `DNA_EVENT_FEED_CACHE_UPDATED` event

`dna_handle_feed_revalidate_index()`:
- Read category and days_back from params
- If category is empty string, call `dna_feed_index_get_all()`, else `dna_feed_index_get_category()`
- For each index entry, fetch full topic with `dna_feed_topic_get()`, serialize with topic_to_json, store with `feed_cache_put_topic_json()`
- Call `feed_cache_update_meta(cache_key)`
- Dispatch `DNA_EVENT_FEED_CACHE_UPDATED` event with cache_key

`dna_handle_feed_revalidate_topic()`:
- Fetch topic with `dna_feed_topic_get()`
- Serialize and cache
- Dispatch event

`dna_handle_feed_revalidate_comments()`:
- Fetch comments with `dna_feed_comments_get()`
- Serialize all comments to JSON array
- Cache with `feed_cache_put_comments()`
- Dispatch event

**Important:** These handlers have NO callback. They are fire-and-forget background tasks. The event is the notification mechanism. Use `dna_dispatch_event()` pattern from `dna_engine_messaging.c:60`.

**Step 3: Build and verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 4: Commit**

```bash
git add src/api/engine/dna_engine_feed.c
git commit -m "feat: Add background revalidation handlers for feed cache"
```

---

### Task 8: Add Cache Logic to Existing Feed Handlers

**Files:**
- Modify: `src/api/engine/dna_engine_feed.c`
  - `dna_handle_feed_get_all()` (line 534)
  - `dna_handle_feed_get_category()` (line 467)
  - `dna_handle_feed_get_topic()` (line 209)
  - `dna_handle_feed_get_comments()` (line 398)
  - `dna_handle_feed_create_topic()` (line 111) - add invalidation
  - `dna_handle_feed_delete_topic()` (line 274) - add invalidation
  - `dna_handle_feed_add_comment()` (line 317) - add invalidation

This is the core integration task. Each read handler gets the stale-while-revalidate pattern.

**Step 1: Modify `dna_handle_feed_get_all()`**

Insert cache check BEFORE the existing DHT fetch code. Structure:

```
1. Build cache_key = "index:all:{days_back}"
2. Try feed_cache_get_topics_all(days_back, &cached_jsons, &cached_count)
3. If cache HIT (return 0, count > 0):
   a. For each JSON string: parse with topic_from_json() -> convert to dna_feed_topic_info_t
      (same conversion logic as existing code at lines 564-593)
   b. Fire callback immediately with cached data
   c. Free the info structs and JSON list
   d. If feed_cache_is_stale(cache_key): submit TASK_FEED_REVALIDATE_INDEX
   e. Return early
4. If cache MISS: fall through to existing DHT code
5. After existing DHT fetch succeeds: cache each result with feed_cache_put_topic_json()
   and call feed_cache_update_meta(cache_key)
```

**Step 2: Modify `dna_handle_feed_get_category()`**

Same pattern as get_all but:
- cache_key = `"index:{category_id}:{days_back}"`
- Use `feed_cache_get_topics_by_category()`
- Background task sets `category` field in params

**Step 3: Modify `dna_handle_feed_get_topic()`**

- cache_key = `"topic:{uuid}"`
- Cache check: `feed_cache_get_topic_json(uuid, &json)`
- Parse JSON to topic struct, convert to info, fire callback
- If stale: submit `TASK_FEED_REVALIDATE_TOPIC`
- On cache miss: existing DHT fetch + cache the result

**Step 4: Modify `dna_handle_feed_get_comments()`**

- cache_key = `"comments:{topic_uuid}"`
- Cache check: `feed_cache_get_comments(topic_uuid, &json, &count)`
- Parse JSON to comment array, convert to info structs, fire callback
- If stale: submit `TASK_FEED_REVALIDATE_COMMENTS`
- On cache miss: existing DHT fetch + cache the result

**Step 5: Add cache invalidation to write handlers**

In `dna_handle_feed_create_topic()` after successful creation (around line 161):
```c
/* Invalidate all index meta so next fetch gets fresh data from DHT */
/* Simple approach: the new topic is already on DHT, just mark indexes as stale */
feed_cache_update_meta(""); /* Forces all index meta stale - will be refreshed */
```

In `dna_handle_feed_delete_topic()` after successful deletion (around line 290):
```c
feed_cache_delete_topic(uuid);
```

In `dna_handle_feed_add_comment()` after successful comment add (around line 355):
```c
feed_cache_invalidate_comments(topic_uuid);
```

**Step 6: Build and verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 7: Commit**

```bash
git add src/api/engine/dna_engine_feed.c
git commit -m "feat: Add stale-while-revalidate cache logic to feed handlers"
```

---

### Task 9: Update Flutter Event Handling

**Files:**
- Modify: `dna_messenger_flutter/lib/ffi/dna_bindings.dart` (line 544, event constants)
- Modify: `dna_messenger_flutter/lib/ffi/dna_engine.dart` (add event class and parsing, around line 1504)
- Modify: `dna_messenger_flutter/lib/providers/event_handler.dart` (handle event, around line 353)

**Step 1: Add event constant in dna_bindings.dart**

Find `DNA_EVENT_ERROR = 22` (line 544). Insert before it:
```dart
  static const int DNA_EVENT_FEED_CACHE_UPDATED = 22;  // Feed cache refreshed
```
Then bump ERROR:
```dart
  static const int DNA_EVENT_ERROR = 23;
```

**IMPORTANT:** Verify the C enum numbering matches. Count the enum values in `include/dna/dna_engine.h` to confirm the integer value.

**Step 2: Add Dart event class in dna_engine.dart**

After `FeedSubscriptionsSyncedEvent` class (around line 1148):
```dart
/// Feed cache updated with fresh DHT data (v0.6.121+)
class FeedCacheUpdatedEvent extends DnaEvent {
  final String cacheKey;
  FeedCacheUpdatedEvent(this.cacheKey);
}
```

**Step 3: Add event parsing in dna_engine.dart**

In the event parsing switch, after `DNA_EVENT_FEED_SUBSCRIPTIONS_SYNCED` case (around line 1510):
```dart
      case DnaEventType.DNA_EVENT_FEED_CACHE_UPDATED:
        final keyBytes = <int>[];
        for (int i = 0; i < 64; i++) {
          final byte = event.data[i];
          if (byte == 0) break;
          keyBytes.add(byte);
        }
        final cacheKey = String.fromCharCodes(keyBytes);
        dartEvent = FeedCacheUpdatedEvent(cacheKey);
        break;
```

**Step 4: Handle event in event_handler.dart**

Add import at top:
```dart
import 'feed_provider.dart';
```

In event switch, after `FeedSubscriptionsSyncedEvent` case (around line 357):
```dart
      case FeedCacheUpdatedEvent(cacheKey: final key):
        logPrint('[DART-HANDLER] FeedCacheUpdatedEvent: cache updated (key=$key)');
        _ref.invalidate(feedTopicsProvider);
        final selectedUuid = _ref.read(selectedTopicUuidProvider);
        if (selectedUuid != null && key.contains(selectedUuid)) {
          _ref.invalidate(selectedTopicProvider);
          _ref.invalidate(topicCommentsProvider(selectedUuid));
        }
        break;
```

**Step 5: Wire up existing TODO items in event_handler.dart**

The `FeedTopicCommentEvent` handler at line 347-350 has a TODO. Update to:
```dart
      case FeedTopicCommentEvent(...):
        // ... existing log ...
        _ref.invalidate(topicCommentsProvider(uuid));
        break;
```

The `FeedSubscriptionsSyncedEvent` handler at line 353-356 has a TODO. Update to:
```dart
      case FeedSubscriptionsSyncedEvent(...):
        // ... existing log ...
        _ref.invalidate(feedSubscriptionsProvider);
        break;
```

**Step 6: Build Flutter**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux
```

**Step 7: Commit**

```bash
git add dna_messenger_flutter/lib/ffi/dna_bindings.dart \
        dna_messenger_flutter/lib/ffi/dna_engine.dart \
        dna_messenger_flutter/lib/providers/event_handler.dart
git commit -m "feat: Handle feed cache updated event in Flutter UI"
```

---

### Task 10: Full Build Verification

**Files:** No new files

**Step 1: Build C library**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

Expected: Clean build, zero errors, zero warnings in feed_cache.c and dna_engine_feed.c.

**Step 2: Build Flutter app**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux
```

Expected: Clean build, zero errors.

**Step 3: Verify cache DB gets created**

After running the app once, check:
```bash
ls -la ~/.dna/db/feed_cache.db
```

---

### Task 11: Update Documentation and Version

**Files:**
- Modify: `docs/functions/database.md` - Add feed_cache functions
- Modify: `docs/ARCHITECTURE_DETAILED.md` - Mention feed cache in database section
- Modify: `include/dna/version.h` - Bump C library version (0.6.120 -> 0.6.121)
- Modify: `CLAUDE.md` - Update version in header

**Step 1: Add feed_cache to database function reference**

Add new section in `docs/functions/database.md`:

```markdown
## Feed Cache (`database/feed_cache.c`)

| Function | Description |
|----------|-------------|
| `int feed_cache_init(void)` | Initialize feed cache database (global) |
| `void feed_cache_close(void)` | Close feed cache database |
| `int feed_cache_evict_expired(void)` | Delete entries older than 30 days |
| `int feed_cache_put_topic_json(uuid, json, cat, ts, del)` | Cache topic as JSON |
| `int feed_cache_get_topic_json(uuid, json_out)` | Get cached topic JSON |
| `int feed_cache_delete_topic(uuid)` | Remove topic from cache |
| `int feed_cache_get_topics_all(days, jsons_out, count)` | Get cached topics |
| `int feed_cache_get_topics_by_category(cat, days, jsons_out, count)` | Get by category |
| `void feed_cache_free_json_list(jsons, count)` | Free JSON array |
| `int feed_cache_put_comments(uuid, json, count)` | Cache comments |
| `int feed_cache_get_comments(uuid, json_out, count_out)` | Get cached comments |
| `int feed_cache_invalidate_comments(uuid)` | Remove cached comments |
| `int feed_cache_update_meta(key)` | Update last-fetched timestamp |
| `bool feed_cache_is_stale(key)` | Check if older than 5 minutes |
| `int feed_cache_stats(topics, comments, expired)` | Get cache statistics |
```

**Step 2: Update architecture doc**

Add `database/feed_cache.c` to the database module listing in `docs/ARCHITECTURE_DETAILED.md`.

**Step 3: Bump version**

In `include/dna/version.h`: bump patch (0.6.120 -> 0.6.121)
In `CLAUDE.md` header: update version

**Step 4: Commit**

```bash
git add docs/ include/dna/version.h CLAUDE.md
git commit -m "docs: Add feed cache documentation, bump to v0.6.121"
```

---

## Implementation Notes

### JSON Serialization Pre-Check

Before Task 7, verify exact function names:
```bash
grep -rn "to_json\|from_json" dht/client/dna_feed*.c dht/client/dna_feed*.h | head -20
```

Plan assumes `dna_feed_topic_to_json()` and `dna_feed_topic_from_json()` exist. Adjust if named differently.

### Cache Key Convention

| Query | Cache Key |
|-------|-----------|
| All topics, 7 days | `index:all:7` |
| Category "general", 7 days | `index:general:7` |
| Single topic | `topic:{uuid}` |
| Comments for topic | `comments:{topic_uuid}` |

### Error Handling

Cache failures are NON-FATAL. If cache read fails, fall through to DHT. If cache write fails, log warning and continue. The feed system must never break because the cache is unavailable.

### Thread Safety

Uses SQLite FULLMUTEX mode (same as profile_cache). Engine handlers run on the task thread pool; concurrent access handled by SQLite internal locking.

### Memory Management

- `feed_cache_get_topic_json()` returns strdup'd string. Caller must free().
- `feed_cache_get_topics_all()` returns array of strdup'd strings. Caller must use `feed_cache_free_json_list()`.
- `feed_cache_get_comments()` returns strdup'd JSON. Caller must free().
