# Feed Cache Design

**Date:** 2026-02-22
**Status:** Approved
**Component:** C Library (database layer)

---

## Problem

The feed system has no local caching. Every feed screen open triggers 7+ sequential DHT lookups (one per day bucket), each taking 1-3 seconds. Result: 5-15 seconds of loading spinner before any content appears. All other major features (profiles, keys, contacts) have local caches — feeds are the only gap.

## Solution

Add a global SQLite cache (`feed_cache.db`) with stale-while-revalidate semantics. Cached data is served instantly (~1ms), and a background DHT fetch silently refreshes the cache if stale (>5 minutes).

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Cache approach | Single SQLite database | Follows profile_cache/keyserver_cache pattern |
| Refresh UX | Stale-while-revalidate | Show cached data instantly, refresh in background |
| Cache depth | Full (topics + comments) | Both list view and detail view are instant |
| Cache scope | Global | Feed data is public, identical across identities |
| Cache TTL | 5 minutes | Balance between freshness and DHT load reduction |
| Data eviction | 30 days | Match DHT TTL for feed data |

## Database Schema

**File:** `~/.dna/db/feed_cache.db`

```sql
CREATE TABLE feed_topics (
    topic_uuid   TEXT PRIMARY KEY,
    topic_json   TEXT NOT NULL,
    category_id  TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    deleted      INTEGER DEFAULT 0,
    cached_at    INTEGER NOT NULL
);
CREATE INDEX idx_feed_topics_category ON feed_topics(category_id, created_at DESC);
CREATE INDEX idx_feed_topics_created  ON feed_topics(created_at DESC);
CREATE INDEX idx_feed_topics_cached   ON feed_topics(cached_at);

CREATE TABLE feed_comments (
    topic_uuid    TEXT PRIMARY KEY,
    comments_json TEXT NOT NULL,
    comment_count INTEGER DEFAULT 0,
    cached_at     INTEGER NOT NULL
);
CREATE INDEX idx_feed_comments_cached ON feed_comments(cached_at);

CREATE TABLE feed_cache_meta (
    cache_key    TEXT PRIMARY KEY,
    last_fetched INTEGER NOT NULL
);
```

### Table Purposes

- **feed_topics**: Stores full topic data as JSON. Queried by category+date range or globally. Replaces the need to cache day-bucketed DHT indexes separately.
- **feed_comments**: Stores all comments for a topic as a JSON array. Keyed by topic_uuid.
- **feed_cache_meta**: Tracks when each query type (e.g., "index:all:7", "index:general:7") was last fetched from DHT. Used to determine staleness.

## C API

### Header: `database/feed_cache.h`

```c
#ifndef DNA_FEED_CACHE_H
#define DNA_FEED_CACHE_H

#include "dht/client/dna_feed.h"
#include "dna/dna_engine.h"

#define FEED_CACHE_TTL_SECONDS      300       // 5 minutes staleness window
#define FEED_CACHE_EVICT_SECONDS    2592000   // 30 days max age

// Lifecycle
int  feed_cache_init(void);
void feed_cache_close(void);
int  feed_cache_evict_expired(void);

// Topics
int  feed_cache_put_topic(const dna_feed_topic_t *topic);
int  feed_cache_get_topic(const char *uuid, dna_feed_topic_t **out);
int  feed_cache_delete_topic(const char *uuid);

// Bulk topic operations (index results)
int  feed_cache_put_topics(const dna_feed_topic_info_t *topics, int count,
                           const char *cache_key);
int  feed_cache_get_topics_by_category(const char *category, int days_back,
                                       dna_feed_topic_info_t **out, int *count);
int  feed_cache_get_topics_all(int days_back,
                               dna_feed_topic_info_t **out, int *count);

// Comments
int  feed_cache_put_comments(const char *topic_uuid,
                             const dna_feed_comment_info_t *comments, int count);
int  feed_cache_get_comments(const char *topic_uuid,
                             dna_feed_comment_info_t **out, int *count);
int  feed_cache_invalidate_comments(const char *topic_uuid);

// Staleness
bool feed_cache_is_stale(const char *cache_key);

// Stats
int  feed_cache_stats(int *total_topics, int *total_comments, int *expired);

#endif // DNA_FEED_CACHE_H
```

### Return Codes

Following existing convention:
- `0` = success
- `-1` = database error
- `-2` = not found (cache miss)
- `-3` = uninitialized

## Engine Integration

### Stale-While-Revalidate Flow

Each read handler in `dna_engine_feed.c` gets a two-phase flow:

```
dna_handle_feed_get_all(engine, task):
  1. cache_key = "index:all:{days_back}"
  2. Try feed_cache_get_topics_all(days_back, &topics, &count)
  3. If cache HIT:
     a. Fire callback immediately with cached data
     b. Check feed_cache_is_stale(cache_key)
     c. If stale → submit TASK_FEED_REVALIDATE_INDEX background task
     d. Return
  4. If cache MISS:
     a. Fetch from DHT (blocking, same as current code)
     b. Store: feed_cache_put_topics(topics, count, cache_key)
     c. Fire callback with fresh data
```

Same pattern for `get_category`, `get_topic`, and `get_comments`.

### Background Revalidation

New internal task type `TASK_FEED_REVALIDATE_INDEX` (not in public API):

```
dna_handle_feed_revalidate(engine, task):
  1. Fetch from DHT (reuses existing fetch logic)
  2. Store results in cache
  3. Fire DNA_EVENT_FEED_CACHE_UPDATED event
  4. Flutter provider listens → invalidates → rebuilds with fresh data
```

### Cache Invalidation on Writes

| User Action | Cache Invalidation |
|-------------|-------------------|
| Create topic | Delete feed_cache_meta rows for affected category + "all" |
| Delete topic | Remove from feed_topics + invalidate meta |
| Add comment | feed_cache_invalidate_comments(topic_uuid) |
| DHT listener (new comment) | feed_cache_invalidate_comments(topic_uuid) + fire event |

## Flutter Changes

Minimal — the engine API signatures stay identical:

1. Add `DNA_EVENT_FEED_CACHE_UPDATED` event type to FFI bindings
2. In `feed_provider.dart`: listen for the event and invalidate providers
3. No other Flutter changes needed — caching is transparent

## Files

| File | Change Type | Description |
|------|-------------|-------------|
| `database/feed_cache.h` | NEW | Cache public API |
| `database/feed_cache.c` | NEW | Cache implementation (~400 lines) |
| `database/cache_manager.c` | MODIFY | Register feed cache init/cleanup/eviction |
| `src/api/engine/dna_engine_feed.c` | MODIFY | Add cache checks + background revalidation |
| `src/api/engine/dna_engine_internal.h` | MODIFY | Add TASK_FEED_REVALIDATE task type |
| `include/dna/dna_engine.h` | MODIFY | Add DNA_EVENT_FEED_CACHE_UPDATED event |
| `dna_messenger_flutter/lib/providers/feed_provider.dart` | MODIFY | Listen for cache update event |
| `database/CMakeLists.txt` or build config | MODIFY | Add feed_cache.c to build |

## Performance Impact

```
Before:  Feed screen → 7 DHT calls → 5-15s → data appears
After:   Feed screen → 1 SQLite query → ~1ms → cached data appears
                     → background DHT fetch → event → UI refreshes silently
```

## Storage Impact

- ~5KB per topic (JSON + metadata)
- ~2KB per comment
- Estimated: 100 topics + 500 comments = ~1.5 MB
- Auto-evicted after 30 days
