# Wall Feature & Home Screen Redesign - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add personal Wall posts with a Home timeline, and restructure navigation to Home | Messages | Feeds | More.

**Architecture:** Per-user DHT key (`SHA3-512("dna:wall:<fingerprint>")`) for wall posts. Contacts auto-follow. New engine module (`dna_engine_wall.c`). Flutter navigation restructure with unified Messages tab.

**Tech Stack:** C (DHT client + Engine API), Dart/Flutter (Riverpod providers, FFI bindings), SQLite (local cache), Dilithium5 (post signatures)

**Design Document:** `docs/plans/2026-02-25-wall-and-home-redesign-design.md`

---

## Task 1: Remove Old Wall Code (C Library Cleanup)

**Files:**
- Delete: `dht/client/dna_message_wall.h`
- Delete: `dht/client/dna_message_wall.c`
- Delete: `dht/client/dna_wall_votes.h`
- Delete: `dht/client/dna_wall_votes.c`
- Modify: `dht/CMakeLists.txt:~40-41` (remove old wall source entries)
- Modify: `docs/functions/dht.md` (remove sections 11.7 and 11.8)

**Step 1: Delete old wall files**

```bash
rm dht/client/dna_message_wall.h dht/client/dna_message_wall.c
rm dht/client/dna_wall_votes.h dht/client/dna_wall_votes.c
```

**Step 2: Remove from CMakeLists**

In `dht/CMakeLists.txt`, remove these two lines:
```cmake
client/dna_message_wall.c       # Message wall support file
client/dna_wall_votes.c         # Wall voting support
```

**Step 3: Remove from documentation**

In `docs/functions/dht.md`, remove sections 11.7 (Message Wall) and 11.8 (Wall Votes) entirely.

**Step 4: Check for any remaining references**

```bash
grep -r "dna_message_wall\|dna_wall_votes\|dna_wall_message_t\|dna_message_wall_t" --include="*.c" --include="*.h" .
```

Remove any `#include` statements or references found. There should be none since the wall API was never wired into the Engine layer.

**Step 5: Verify C build**

```bash
cd build && cmake .. && make -j$(nproc)
```

Expected: Clean build with no errors.

**Step 6: Commit**

```bash
git add -A dht/client/ dht/CMakeLists.txt docs/functions/dht.md
git commit -m "refactor: Remove old wall code (preparing for new wall system)"
```

---

## Task 2: New Wall DHT Client (C Header)

**Files:**
- Create: `dht/client/dna_wall.h`

**Step 1: Create the wall header**

```c
/*
 * DNA Wall - Personal wall posts stored on DHT
 *
 * Each user's wall posts are stored under a per-user DHT key:
 *   SHA3-512("dna:wall:<fingerprint>")
 *
 * Posts are signed with Dilithium5 for authenticity.
 * Max 50 posts per user, 30-day TTL, text-only (MVP).
 */

#ifndef DNA_WALL_H
#define DNA_WALL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "dht/core/dht_core.h"
#include "messenger/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ── */
#define DNA_WALL_MAX_TEXT_LEN    2048
#define DNA_WALL_MAX_POSTS       50
#define DNA_WALL_TTL_DAYS        30
#define DNA_WALL_KEY_PREFIX      "dna:wall:"

/* ── Data Structures ── */

/**
 * Single wall post
 */
typedef struct {
    char uuid[37];                      /* UUID v4 */
    char author_fingerprint[129];       /* SHA3-512 hex */
    char text[DNA_WALL_MAX_TEXT_LEN];   /* Post content */
    uint64_t timestamp;                 /* Unix epoch seconds */
    uint8_t signature[4627];            /* Dilithium5 signature */
    size_t signature_len;
    bool verified;                      /* Signature verified flag */
} dna_wall_post_t;

/**
 * Collection of wall posts for a user
 */
typedef struct {
    char owner_fingerprint[129];        /* Wall owner's fingerprint */
    dna_wall_post_t *posts;             /* Array of posts */
    size_t post_count;                  /* Number of posts */
} dna_wall_t;

/* ── DHT Key Derivation ── */

/**
 * Derive DHT key for a user's wall
 * @param fingerprint  User's SHA3-512 fingerprint (128 hex chars)
 * @param out_key      Output buffer (64 bytes for SHA3-512 hash)
 */
void dna_wall_make_key(const char *fingerprint, uint8_t *out_key);

/* ── Wall Operations ── */

/**
 * Post a message to own wall
 * @param dht       DHT context
 * @param identity  Poster's identity (for signing)
 * @param text      Post text (max DNA_WALL_MAX_TEXT_LEN-1 chars)
 * @param out_post  If non-NULL, filled with the created post
 * @return 0 on success, negative on error
 */
int dna_wall_post(dht_context_t *dht, qgp_identity_t *identity,
                  const char *text, dna_wall_post_t *out_post);

/**
 * Delete a post from own wall
 * @param dht       DHT context
 * @param identity  Owner's identity
 * @param post_uuid UUID of post to delete
 * @return 0 on success, negative on error
 */
int dna_wall_delete(dht_context_t *dht, qgp_identity_t *identity,
                    const char *post_uuid);

/**
 * Load a user's wall posts from DHT
 * @param dht          DHT context
 * @param fingerprint  Wall owner's fingerprint
 * @param wall         Output wall structure (caller must free with dna_wall_free)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dna_wall_load(dht_context_t *dht, const char *fingerprint,
                  dna_wall_t *wall);

/* ── Memory Management ── */

/**
 * Free wall structure
 */
void dna_wall_free(dna_wall_t *wall);

/* ── Verification ── */

/**
 * Verify a wall post's Dilithium5 signature
 * @param post  Post to verify
 * @param dht   DHT context (for keyserver lookup)
 * @return true if signature is valid
 */
bool dna_wall_post_verify(const dna_wall_post_t *post, dht_context_t *dht);

/* ── Serialization ── */

/**
 * Serialize wall to JSON string
 * @param wall  Wall to serialize
 * @return JSON string (caller frees) or NULL on error
 */
char *dna_wall_to_json(const dna_wall_t *wall);

/**
 * Deserialize wall from JSON string
 * @param json  JSON string
 * @param wall  Output wall structure
 * @return 0 on success, -1 on error
 */
int dna_wall_from_json(const char *json, dna_wall_t *wall);

#ifdef __cplusplus
}
#endif

#endif /* DNA_WALL_H */
```

**Step 2: Commit**

```bash
git add dht/client/dna_wall.h
git commit -m "feat: Add new wall DHT client header (dna_wall.h)"
```

---

## Task 3: New Wall DHT Client (C Implementation)

**Files:**
- Create: `dht/client/dna_wall.c`
- Modify: `dht/CMakeLists.txt` (add new source file)

**Step 1: Implement dna_wall.c**

Reference these existing patterns:
- `dht/client/dna_feed_topic.c` for DHT chunked storage pattern
- `dht/shared/dht_chunked.h` for chunked put/get API
- `crypto/dilithium/dilithium.h` for Dilithium5 signing

The implementation must include:
- `dna_wall_make_key()` - SHA3-512 hash of `"dna:wall:<fingerprint>"`
- `dna_wall_post()` - Create UUID, sign with Dilithium5, load existing posts, append (rotating if >50), put to DHT via chunked storage
- `dna_wall_delete()` - Load posts, remove matching UUID, re-put to DHT
- `dna_wall_load()` - Get from DHT via chunked storage, parse JSON, verify signatures
- `dna_wall_free()` - Free posts array
- `dna_wall_post_verify()` - Lookup author's Dilithium5 public key from keyserver, verify signature
- `dna_wall_to_json()` / `dna_wall_from_json()` - JSON serialization using json-c

**Signature format:** Sign `uuid + text + timestamp` (timestamp in network byte order, 8 bytes big-endian).

**JSON format per post:**
```json
{
  "uuid": "...",
  "author": "...",
  "text": "...",
  "ts": 1740000000,
  "sig": "<base64-encoded-dilithium5-signature>"
}
```

**Wall JSON (array of posts):**
```json
[
  { "uuid": "...", "author": "...", "text": "...", "ts": ..., "sig": "..." },
  ...
]
```

**Step 2: Add to CMakeLists**

In `dht/CMakeLists.txt`, add after the feed entries:
```cmake
client/dna_wall.c               # Personal wall posts (v0.6.135+)
```

**Step 3: Verify C build**

```bash
cd build && cmake .. && make -j$(nproc)
```

Expected: Clean build with no errors or warnings.

**Step 4: Commit**

```bash
git add dht/client/dna_wall.c dht/CMakeLists.txt
git commit -m "feat: Implement wall DHT client (dna_wall.c)"
```

---

## Task 4: Wall SQLite Cache

**Files:**
- Check: `database/` directory for existing cache patterns (e.g., `database/feed_cache.h` / `feed_cache.c`)
- Create: `database/wall_cache.h`
- Create: `database/wall_cache.c`
- Modify: Root `CMakeLists.txt` if needed (check if database/ files are auto-included)

**Step 1: Create wall_cache.h**

Follow the pattern from `database/feed_cache.h`:

```c
#ifndef WALL_CACHE_H
#define WALL_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include "dht/client/dna_wall.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize wall cache database
 * @param data_dir  Path to data directory
 * @return 0 on success
 */
int wall_cache_init(const char *data_dir);

/**
 * Store wall posts in local cache
 * @param fingerprint  Wall owner's fingerprint
 * @param posts        Array of posts
 * @param count        Number of posts
 * @return 0 on success
 */
int wall_cache_store(const char *fingerprint,
                     const dna_wall_post_t *posts, size_t count);

/**
 * Load wall posts from local cache
 * @param fingerprint  Wall owner's fingerprint
 * @param posts        Output array (caller frees with wall_cache_free_posts)
 * @param count        Output count
 * @return 0 on success, -1 on error, -2 if not found
 */
int wall_cache_load(const char *fingerprint,
                    dna_wall_post_t **posts, size_t *count);

/**
 * Load timeline (all contacts' posts merged, sorted by timestamp desc)
 * @param fingerprints  Array of contact fingerprints
 * @param fp_count      Number of contacts
 * @param posts         Output array (caller frees)
 * @param count         Output count
 * @return 0 on success
 */
int wall_cache_load_timeline(const char **fingerprints, size_t fp_count,
                             dna_wall_post_t **posts, size_t *count);

/**
 * Delete posts by a specific author from cache
 */
int wall_cache_delete_by_author(const char *fingerprint);

/**
 * Delete a specific post from cache
 */
int wall_cache_delete_post(const char *post_uuid);

/**
 * Check if cache is stale for a fingerprint (older than 5 minutes)
 */
int wall_cache_is_stale(const char *fingerprint);

/**
 * Free posts array from cache
 */
void wall_cache_free_posts(dna_wall_post_t *posts, size_t count);

/**
 * Close and cleanup wall cache
 */
void wall_cache_close(void);

#ifdef __cplusplus
}
#endif

#endif /* WALL_CACHE_H */
```

**Step 2: Implement wall_cache.c**

SQLite table schema:
```sql
CREATE TABLE IF NOT EXISTS wall_posts (
    uuid TEXT PRIMARY KEY,
    author_fingerprint TEXT NOT NULL,
    text TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    signature BLOB,
    signature_len INTEGER DEFAULT 0,
    verified INTEGER DEFAULT 0,
    cached_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_wall_author ON wall_posts(author_fingerprint);
CREATE INDEX IF NOT EXISTS idx_wall_timestamp ON wall_posts(timestamp DESC);
```

Follow the pattern from `database/feed_cache.c` for SQLite operations (open, prepare, bind, step, finalize).

Timeline query:
```sql
SELECT * FROM wall_posts
WHERE author_fingerprint IN (?, ?, ...)
ORDER BY timestamp DESC
LIMIT 100
```

**Step 3: Add to build if needed**

Check if `database/wall_cache.c` needs to be added to `CMakeLists.txt`. Look at how `database/feed_cache.c` is included:
```bash
grep "feed_cache" CMakeLists.txt
```
Add `database/wall_cache.c` in the same pattern (both SHARED and STATIC sections).

**Step 4: Verify C build**

```bash
cd build && cmake .. && make -j$(nproc)
```

**Step 5: Commit**

```bash
git add database/wall_cache.h database/wall_cache.c CMakeLists.txt
git commit -m "feat: Add wall SQLite cache (wall_cache.h/.c)"
```

---

## Task 5: Engine Internal Types (Task Types, Params, Handlers)

**Files:**
- Modify: `src/api/dna_engine_internal.h`
  - Lines ~149: Add wall task types to enum (before closing `}`)
  - Lines ~399: Add wall params to union (before closing `}`)
  - Lines ~430: Add wall callback to callback union
  - Lines ~809: Add wall handler declarations

**Step 1: Add task types**

At line 149 (before `} dna_task_type_t;`), add:

```c
    /* Feed cache revalidation (v0.6.121+) */
    TASK_FEED_REVALIDATE_INDEX,
    TASK_FEED_REVALIDATE_TOPIC,
    TASK_FEED_REVALIDATE_COMMENTS,

    /* Wall (personal wall posts, v0.6.135+) */
    TASK_WALL_POST,
    TASK_WALL_DELETE,
    TASK_WALL_LOAD,
    TASK_WALL_TIMELINE
} dna_task_type_t;
```

Note: Remove the existing closing brace line and re-add it after wall tasks. The comma after `TASK_FEED_REVALIDATE_COMMENTS` needs to be added.

**Step 2: Add task params**

Before the closing `} dna_task_params_t;` (line ~400), add:

```c
    /* Wall: Post message */
    struct {
        char *text;                     /* Heap allocated, task owns (max 2048 chars) */
    } wall_post;

    /* Wall: Delete post */
    struct {
        char uuid[37];                  /* Post UUID to delete */
    } wall_delete;

    /* Wall: Load one user's wall */
    struct {
        char fingerprint[129];          /* Wall owner's fingerprint */
    } wall_load;

    /* Wall: Timeline has no params (uses engine->contacts list) */
```

**Step 3: Add callback type**

In the `dna_task_callback_t` union (around line 431), add:

```c
    dna_wall_post_cb wall_post;
    dna_wall_posts_cb wall_posts;
```

**Step 4: Add handler declarations**

After the feed handler declarations (around line 809), add:

```c
/* Wall (personal wall posts, v0.6.135+) */
void dna_handle_wall_post(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_delete(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_load(dna_engine_t *engine, dna_task_t *task);
void dna_handle_wall_timeline(dna_engine_t *engine, dna_task_t *task);
```

**Step 5: Verify C build**

```bash
cd build && cmake .. && make -j$(nproc)
```

Note: Build may fail because the callback types and handlers are declared but not yet defined. That's expected - they'll be added in Tasks 6 and 7.

**Step 6: Commit**

```bash
git add src/api/dna_engine_internal.h
git commit -m "feat: Add wall task types, params, and handler declarations"
```

---

## Task 6: Public API Types and Callbacks

**Files:**
- Modify: `include/dna/dna_engine.h`
  - After `dna_feed_topic_info_t` (line ~260): Add `dna_wall_post_info_t` struct
  - After feed callbacks (line ~577): Add wall callbacks
  - After `DNA_EVENT_FEED_CACHE_UPDATED` (line ~616): Add `DNA_EVENT_WALL_NEW_POST`
  - After feed_cache_updated event data (line ~686): Add wall event data
  - After feed API section: Add wall API section
  - After `dna_free_feed_comments` (line ~970): Add wall memory cleanup

**Step 1: Add wall_post_info_t struct**

After the `dna_feed_topic_info_t` definition (around line 260), add:

```c
/**
 * Wall: Post information (for async API callbacks)
 */
typedef struct {
    char uuid[37];                      /* UUID v4 */
    char author_fingerprint[129];       /* Author's SHA3-512 fingerprint */
    char author_name[65];               /* Resolved display name (empty if unknown) */
    char text[2048];                    /* Post content */
    uint64_t timestamp;                 /* Unix timestamp (seconds) */
    bool verified;                      /* Signature verified */
} dna_wall_post_info_t;
```

**Step 2: Add wall callback types**

After the feed callback section (around line 577), add:

```c
/**
 * Wall: Single post callback
 */
typedef void (*dna_wall_post_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wall_post_info_t *post,
    void *user_data
);

/**
 * Wall: Posts list callback (for wall load and timeline)
 */
typedef void (*dna_wall_posts_cb)(
    dna_request_id_t request_id,
    int error,
    dna_wall_post_info_t *posts,
    int count,
    void *user_data
);
```

**Step 3: Add wall event type**

In the `dna_event_type_t` enum (after `DNA_EVENT_FEED_CACHE_UPDATED`, line ~616):

```c
    DNA_EVENT_FEED_CACHE_UPDATED,        /* Feed cache refreshed with new DHT data (v0.6.121+) */
    DNA_EVENT_WALL_NEW_POST,             /* New wall post from a contact (v0.6.135+) */
    DNA_EVENT_ERROR
```

Note: `DNA_EVENT_ERROR` must remain last. Add the new event before it.

**Step 4: Add wall event data**

In the event data union (after `feed_cache_updated`, around line 686):

```c
        struct {
            char author_fingerprint[129];   /* Post author's fingerprint */
            char post_uuid[37];             /* New post UUID */
        } wall_new_post;
```

**Step 5: Add wall public API functions**

After the Feed API section (look for the next `/* ===` section divider after feed functions), add:

```c
/* ============================================================================
 * WALL (personal wall posts, v0.6.135+)
 * ============================================================================ */

/**
 * Post a message to own wall
 *
 * @param engine    Engine instance
 * @param text      Post text (max 2047 chars, will be truncated)
 * @param callback  Called with created post info
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_post(
    dna_engine_t *engine,
    const char *text,
    dna_wall_post_cb callback,
    void *user_data
);

/**
 * Delete own wall post
 *
 * @param engine     Engine instance
 * @param post_uuid  UUID of post to delete
 * @param callback   Called when complete
 * @param user_data  User data for callback
 * @return           Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_delete(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_status_cb callback,
    void *user_data
);

/**
 * Load a user's wall posts
 *
 * @param engine       Engine instance
 * @param fingerprint  Wall owner's fingerprint
 * @param callback     Called with posts array
 * @param user_data    User data for callback
 * @return             Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_load(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_wall_posts_cb callback,
    void *user_data
);

/**
 * Load timeline (all contacts' wall posts merged)
 *
 * Returns posts from all contacts sorted by timestamp descending.
 * Also includes own posts.
 *
 * @param engine    Engine instance
 * @param callback  Called with merged posts array
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_wall_timeline(
    dna_engine_t *engine,
    dna_wall_posts_cb callback,
    void *user_data
);

/**
 * Free single wall post returned by callbacks
 */
DNA_API void dna_free_wall_post(dna_wall_post_info_t *post);

/**
 * Free wall posts array returned by callbacks
 */
DNA_API void dna_free_wall_posts(dna_wall_post_info_t *posts, int count);
```

**Step 6: Commit**

```bash
git add include/dna/dna_engine.h
git commit -m "feat: Add wall public API types, callbacks, events, and functions"
```

---

## Task 7: Engine Wall Module

**Files:**
- Create: `src/api/engine/dna_engine_wall.c`
- Modify: `src/api/dna_engine.c` (add dispatch cases + cleanup cases)
- Modify: `CMakeLists.txt` (add source to both SHARED and STATIC sections)

**Step 1: Create dna_engine_wall.c**

Follow the exact pattern from `src/api/engine/dna_engine_feed.c`:

```c
/*
 * DNA Engine - Wall Module
 *
 * Personal wall posts with DHT storage and local cache.
 *
 * Contains handlers and public API:
 *   - dna_handle_wall_post()
 *   - dna_handle_wall_delete()
 *   - dna_handle_wall_load()
 *   - dna_handle_wall_timeline()
 *   - dna_engine_wall_post()
 *   - dna_engine_wall_delete()
 *   - dna_engine_wall_load()
 *   - dna_engine_wall_timeline()
 *   - dna_free_wall_post()
 *   - dna_free_wall_posts()
 */

#define DNA_ENGINE_WALL_IMPL

#include "engine_includes.h"
#include "dht/client/dna_wall.h"
#include "database/wall_cache.h"

#undef LOG_TAG
#define LOG_TAG "ENGINE_WALL"
```

Implement each handler:

**`dna_handle_wall_post()`:**
1. Get DHT context and identity from engine
2. Call `dna_wall_post(dht, identity, task->params.wall_post.text, &post)`
3. Convert `dna_wall_post_t` to `dna_wall_post_info_t` (resolve author name)
4. Store in wall cache: `wall_cache_store()`
5. Call `task->callback.wall_post(request_id, error, &info, user_data)`
6. Free task->params.wall_post.text

**`dna_handle_wall_delete()`:**
1. Get DHT context and identity from engine
2. Call `dna_wall_delete(dht, identity, task->params.wall_delete.uuid)`
3. Remove from cache: `wall_cache_delete_post(uuid)`
4. Call `task->callback.completion(request_id, error, user_data)`

**`dna_handle_wall_load()`:**
1. Check wall cache first: `wall_cache_load(fingerprint, &posts, &count)`
2. If cache hit and not stale, convert to `dna_wall_post_info_t` array and callback immediately
3. If stale or miss, call `dna_wall_load(dht, fingerprint, &wall)`
4. Store result in cache: `wall_cache_store()`
5. Convert to info array, resolve author names
6. Call `task->callback.wall_posts(request_id, error, info, count, user_data)`

**`dna_handle_wall_timeline()`:**
1. Get contacts list from engine (use `messenger_contacts_get_all()` or equivalent)
2. Include own fingerprint in the list
3. Try cache first: `wall_cache_load_timeline(fps, fp_count, &posts, &count)`
4. If cache hit, convert and callback
5. If stale/miss, iterate contacts and call `dna_wall_load()` for each, updating cache
6. Merge all posts, sort by timestamp DESC
7. Convert to info array, resolve author names
8. Call `task->callback.wall_posts(request_id, error, info, count, user_data)`

**Public API wrappers** (follow `dna_engine_feed_get_all` pattern):

```c
dna_request_id_t dna_engine_wall_post(
    dna_engine_t *engine, const char *text,
    dna_wall_post_cb callback, void *user_data
) {
    if (!engine || !callback || !text) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.wall_post.text = strdup(text);
    if (!params.wall_post.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.wall_post = callback;
    return dna_submit_task(engine, TASK_WALL_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_delete(
    dna_engine_t *engine, const char *post_uuid,
    dna_status_cb callback, void *user_data
) {
    if (!engine || !callback || !post_uuid) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_delete.uuid, post_uuid, 36);

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_WALL_DELETE, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_load(
    dna_engine_t *engine, const char *fingerprint,
    dna_wall_posts_cb callback, void *user_data
) {
    if (!engine || !callback || !fingerprint) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_load.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = {0};
    cb.wall_posts = callback;
    return dna_submit_task(engine, TASK_WALL_LOAD, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_timeline(
    dna_engine_t *engine,
    dna_wall_posts_cb callback, void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};

    dna_task_callback_t cb = {0};
    cb.wall_posts = callback;
    return dna_submit_task(engine, TASK_WALL_TIMELINE, &params, cb, user_data);
}
```

**Memory cleanup:**

```c
void dna_free_wall_post(dna_wall_post_info_t *post) {
    /* dna_wall_post_info_t has no heap members, just free the struct */
    if (post) free(post);
}

void dna_free_wall_posts(dna_wall_post_info_t *posts, int count) {
    /* dna_wall_post_info_t has no heap members, just free the array */
    if (posts) free(posts);
}
```

**Step 2: Add dispatch cases to dna_engine.c**

In `src/api/dna_engine.c`, find the task dispatch switch (around line 1142).

Add after the feed cases (after line ~1187):

```c
        /* Wall (v0.6.135+) */
        case TASK_WALL_POST:
            dna_handle_wall_post(engine, task);
            break;
        case TASK_WALL_DELETE:
            dna_handle_wall_delete(engine, task);
            break;
        case TASK_WALL_LOAD:
            dna_handle_wall_load(engine, task);
            break;
        case TASK_WALL_TIMELINE:
            dna_handle_wall_timeline(engine, task);
            break;
```

Also add cleanup case in the task cleanup switch (around line 754):

```c
        case TASK_WALL_POST:
            free(task->params.wall_post.text);
            break;
```

**Step 3: Add to CMakeLists.txt**

In `CMakeLists.txt`, add `src/api/engine/dna_engine_wall.c` in BOTH the SHARED (around line 178) and STATIC (around line 257) library sections, after `dna_engine_feed.c`:

```cmake
        src/api/engine/dna_engine_feed.c
        src/api/engine/dna_engine_wall.c
```

Also add to `libs/dna-engine/CMakeLists.txt` (line ~40) if that file references engine modules:
```cmake
    ${DNA_ROOT}/src/api/engine/dna_engine_wall.c
```

**Step 4: Initialize wall cache in engine create**

In `src/api/dna_engine.c`, find where `feed_cache_init()` is called during engine creation. Add `wall_cache_init(data_dir)` nearby.

Also add `wall_cache_close()` in the engine destroy function.

**Step 5: Verify C build**

```bash
cd build && cmake .. && make -j$(nproc)
```

Expected: Clean build with zero errors and zero warnings.

**Step 6: Commit**

```bash
git add src/api/engine/dna_engine_wall.c src/api/dna_engine.c CMakeLists.txt libs/dna-engine/CMakeLists.txt
git commit -m "feat: Implement wall engine module with DHT storage and cache"
```

---

## Task 8: Flutter FFI Bindings

**Files:**
- Modify: `dna_messenger_flutter/lib/ffi/dna_bindings.dart` (add native bindings)
- Modify: `dna_messenger_flutter/lib/ffi/dna_engine.dart` (add WallPost model, event class, FFI functions)

**Step 1: Add native bindings to dna_bindings.dart**

Add the native function lookups. Follow the pattern from feed functions:

```dart
// Wall API
late final dna_engine_wall_post = _lookup<NativeFunction<...>>('dna_engine_wall_post');
late final dna_engine_wall_delete = _lookup<NativeFunction<...>>('dna_engine_wall_delete');
late final dna_engine_wall_load = _lookup<NativeFunction<...>>('dna_engine_wall_load');
late final dna_engine_wall_timeline = _lookup<NativeFunction<...>>('dna_engine_wall_timeline');
late final dna_free_wall_post_ptr = _lookup<NativeFunction<...>>('dna_free_wall_post');
late final dna_free_wall_posts_ptr = _lookup<NativeFunction<...>>('dna_free_wall_posts');
```

Note: The exact native types must match the C signatures. Check how `dna_engine_feed_create_topic` is bound for the pattern.

Also add the event type constant:

```dart
static const int DNA_EVENT_WALL_NEW_POST = 23;  // Was: DNA_EVENT_ERROR = 23
static const int DNA_EVENT_ERROR = 24;           // Bumped by 1
```

**IMPORTANT:** Since `DNA_EVENT_WALL_NEW_POST` is inserted before `DNA_EVENT_ERROR`, the ERROR enum value changes. Update the number to match the C enum ordering.

**Step 2: Add WallPost model to dna_engine.dart**

After the `FeedTopic` class, add:

```dart
/// Wall post data model
class WallPost {
  final String uuid;
  final String authorFingerprint;
  final String authorName;
  final String text;
  final DateTime timestamp;
  final bool verified;

  WallPost({
    required this.uuid,
    required this.authorFingerprint,
    required this.authorName,
    required this.text,
    required this.timestamp,
    required this.verified,
  });

  bool isOwn(String myFingerprint) => authorFingerprint == myFingerprint;

  factory WallPost.fromNative(dna_wall_post_info_t native) {
    return WallPost(
      uuid: native.uuid.toDartString(37),
      authorFingerprint: native.author_fingerprint.toDartString(129),
      authorName: native.author_name.toDartString(65),
      text: native.text.toDartString(2048),
      timestamp: DateTime.fromMillisecondsSinceEpoch(native.timestamp * 1000),
      verified: native.verified,
    );
  }
}
```

**Step 3: Add WallNewPostEvent class**

After the `FeedCacheUpdatedEvent` class:

```dart
class WallNewPostEvent extends DnaEvent {
  final String authorFingerprint;
  final String postUuid;
  WallNewPostEvent(this.authorFingerprint, this.postUuid);
}
```

**Step 4: Add event parsing**

In the event parsing switch (where `DNA_EVENT_FEED_CACHE_UPDATED` is handled), add:

```dart
case DnaEventType.DNA_EVENT_WALL_NEW_POST:
  // Parse wall_new_post: author_fingerprint(129 bytes at 0) + post_uuid(37 bytes at 132 aligned)
  final authorBytes = <int>[];
  for (var i = 0; i < 129; i++) {
    final byte = event.data[i];
    if (byte == 0) break;
    authorBytes.add(byte);
  }
  final postUuidBytes = <int>[];
  // post_uuid starts at offset 132 (129 aligned to 4 = 132)
  for (var i = 0; i < 37; i++) {
    final byte = event.data[132 + i];
    if (byte == 0) break;
    postUuidBytes.add(byte);
  }
  dartEvent = WallNewPostEvent(
    String.fromCharCodes(authorBytes),
    String.fromCharCodes(postUuidBytes),
  );
  break;
```

**IMPORTANT:** Check the actual byte offset of `post_uuid` in the C struct `wall_new_post`. The `author_fingerprint` is `char[129]`, and struct alignment may pad this. Verify by checking sizeof or inspecting the struct layout. For char arrays in a union, the offset is typically just after the previous field without padding.

**Step 5: Add FFI functions**

Follow the `feedCreateTopic()` and `feedGetAll()` patterns:

```dart
/// Post to own wall
Future<WallPost> wallPost(String text) async {
  final completer = Completer<WallPost>();
  final localId = _nextLocalId++;
  final textPtr = text.toNativeUtf8();

  void onComplete(int requestId, int error,
                  Pointer<dna_wall_post_info_t> post, Pointer<Void> userData) {
    calloc.free(textPtr);
    if (error == 0 && post != nullptr) {
      final result = WallPost.fromNative(post.ref);
      _bindings.dna_free_wall_post(post);
      completer.complete(result);
    } else {
      if (post != nullptr) _bindings.dna_free_wall_post(post);
      completer.completeError(DnaEngineException.fromCode(error, _bindings));
    }
    _cleanupRequest(localId);
  }

  final callback = NativeCallable<...>.isolate(onComplete, exceptionalReturn: null);
  _pendingRequests[localId] = _PendingRequest(callback: callback);

  final requestId = _bindings.dna_engine_wall_post(
    _engine, textPtr.cast(), callback.nativeFunction.cast(), nullptr);

  if (requestId == 0) {
    calloc.free(textPtr);
    _cleanupRequest(localId);
    throw DnaEngineException(-1, 'Failed to submit wall post request');
  }
  return completer.future;
}

/// Delete own wall post
Future<void> wallDelete(String postUuid) async { /* similar pattern with completion cb */ }

/// Load a user's wall
Future<List<WallPost>> wallLoad(String fingerprint) async { /* similar to feedGetAll */ }

/// Load timeline (all contacts' walls merged)
Future<List<WallPost>> wallTimeline() async { /* similar to feedGetAll, no params */ }
```

**Step 6: Commit**

```bash
git add dna_messenger_flutter/lib/ffi/dna_bindings.dart dna_messenger_flutter/lib/ffi/dna_engine.dart
git commit -m "feat: Add wall FFI bindings and WallPost model"
```

---

## Task 9: Wall Provider

**Files:**
- Create: `dna_messenger_flutter/lib/providers/wall_provider.dart`
- Modify: `dna_messenger_flutter/lib/providers/providers.dart` (add export)

**Step 1: Create wall_provider.dart**

Follow the `feed_provider.dart` pattern:

```dart
// Wall Provider - Personal wall posts and timeline
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Wall timeline provider - all contacts' posts merged, sorted by timestamp desc
final wallTimelineProvider =
    AsyncNotifierProvider<WallTimelineNotifier, List<WallPost>>(
  WallTimelineNotifier.new,
);

class WallTimelineNotifier extends AsyncNotifier<List<WallPost>> {
  @override
  Future<List<WallPost>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.wallTimeline();
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.wallTimeline();
    });
  }

  Future<WallPost> createPost(String text) async {
    final engine = await ref.read(engineProvider.future);
    final post = await engine.wallPost(text);
    await refresh();
    return post;
  }

  Future<void> deletePost(String postUuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.wallDelete(postUuid);
    await refresh();
  }
}
```

**Step 2: Add export to providers.dart**

In `dna_messenger_flutter/lib/providers/providers.dart`, add:

```dart
export 'wall_provider.dart';  // v0.6.135: Personal wall posts
```

**Step 3: Commit**

```bash
git add dna_messenger_flutter/lib/providers/wall_provider.dart dna_messenger_flutter/lib/providers/providers.dart
git commit -m "feat: Add wall provider (Riverpod state management)"
```

---

## Task 10: Wall Event Handling

**Files:**
- Modify: `dna_messenger_flutter/lib/providers/event_handler.dart`

**Step 1: Add wall event handling**

In the `_handleEvent` switch (after the `FeedCacheUpdatedEvent` case), add:

```dart
    case WallNewPostEvent(authorFingerprint: final author, postUuid: final uuid):
      DnaLogger.log('DART-HANDLER', 'WallNewPostEvent: author=${author.substring(0, 16)}..., post=$uuid');
      _ref.invalidate(wallTimelineProvider);
      break;
```

Make sure to import `wall_provider.dart` if not already available through the providers barrel file.

**Step 2: Commit**

```bash
git add dna_messenger_flutter/lib/providers/event_handler.dart
git commit -m "feat: Handle wall new post events in Flutter"
```

---

## Task 11: Wall Post Tile Widget

**Files:**
- Create: `dna_messenger_flutter/lib/widgets/wall_post_tile.dart`

**Step 1: Create the widget**

```dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../ffi/dna_engine.dart';
import '../providers/providers.dart';
import '../utils/time_formatter.dart';

class WallPostTile extends ConsumerWidget {
  final WallPost post;
  final String myFingerprint;
  final VoidCallback? onDelete;
  final VoidCallback? onAuthorTap;

  const WallPostTile({
    super.key,
    required this.post,
    required this.myFingerprint,
    this.onDelete,
    this.onAuthorTap,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isOwn = post.isOwn(myFingerprint);
    final theme = Theme.of(context);

    return DnaCard(
      child: Padding(
        padding: const EdgeInsets.all(DnaSpacing.md),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Author row
            Row(
              children: [
                DnaAvatar(
                  name: post.authorName.isNotEmpty ? post.authorName : '?',
                  size: 36,
                ),
                const SizedBox(width: DnaSpacing.sm),
                Expanded(
                  child: GestureDetector(
                    onTap: onAuthorTap,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          post.authorName.isNotEmpty
                              ? post.authorName
                              : post.authorFingerprint.substring(0, 16),
                          style: theme.textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          formatTimeAgo(post.timestamp),
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                if (isOwn)
                  IconButton(
                    icon: const FaIcon(FontAwesomeIcons.trash, size: 14),
                    onPressed: onDelete,
                    tooltip: 'Delete post',
                    iconSize: 14,
                  ),
              ],
            ),
            const SizedBox(height: DnaSpacing.sm),
            // Post text
            Text(
              post.text,
              style: theme.textTheme.bodyMedium,
            ),
          ],
        ),
      ),
    );
  }
}
```

Note: Check if `formatTimeAgo` exists in the codebase (likely in `lib/utils/`). If not, create a simple helper. Also check `DnaCard` and `DnaAvatar` exist in `lib/design_system/`.

**Step 2: Commit**

```bash
git add dna_messenger_flutter/lib/widgets/wall_post_tile.dart
git commit -m "feat: Add WallPostTile widget"
```

---

## Task 12: WallTimelineScreen (Home Tab)

**Files:**
- Create: `dna_messenger_flutter/lib/screens/wall/wall_timeline_screen.dart`

**Step 1: Create the screen**

Follow the `ContactsScreen` and `FeedScreen` patterns:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../providers/providers.dart';
import '../../widgets/wall_post_tile.dart';

class WallTimelineScreen extends ConsumerWidget {
  const WallTimelineScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final timeline = ref.watch(wallTimelineProvider);
    final identity = ref.watch(identityProvider);
    final myFp = identity.valueOrNull?.fingerprint ?? '';

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Home',
        leading: const SizedBox.shrink(),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.read(wallTimelineProvider.notifier).refresh(),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: timeline.when(
        data: (posts) => posts.isEmpty
            ? _buildEmptyState(context)
            : RefreshIndicator(
                onRefresh: () => ref.read(wallTimelineProvider.notifier).refresh(),
                child: ListView.separated(
                  padding: const EdgeInsets.all(DnaSpacing.md),
                  itemCount: posts.length,
                  separatorBuilder: (_, __) => const SizedBox(height: DnaSpacing.sm),
                  itemBuilder: (context, index) {
                    final post = posts[index];
                    return WallPostTile(
                      post: post,
                      myFingerprint: myFp,
                      onDelete: post.isOwn(myFp)
                          ? () => _confirmDelete(context, ref, post.uuid)
                          : null,
                    );
                  },
                ),
              ),
        loading: () {
          final cached = timeline.valueOrNull;
          if (cached != null && cached.isNotEmpty) {
            return ListView.separated(
              padding: const EdgeInsets.all(DnaSpacing.md),
              itemCount: cached.length,
              separatorBuilder: (_, __) => const SizedBox(height: DnaSpacing.sm),
              itemBuilder: (context, index) => WallPostTile(
                post: cached[index],
                myFingerprint: myFp,
              ),
            );
          }
          return const Center(child: CircularProgressIndicator());
        },
        error: (error, stack) => Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const FaIcon(FontAwesomeIcons.triangleExclamation, size: 48),
              const SizedBox(height: DnaSpacing.md),
              Text('Failed to load timeline'),
              const SizedBox(height: DnaSpacing.sm),
              DnaButton(
                onPressed: () => ref.invalidate(wallTimelineProvider),
                child: const Text('Retry'),
              ),
            ],
          ),
        ),
      ),
      floatingActionButton: FloatingActionButton(
        heroTag: 'wall_fab',
        onPressed: () => _showCreatePostDialog(context, ref),
        tooltip: 'New Post',
        child: const FaIcon(FontAwesomeIcons.pen),
      ),
    );
  }

  Widget _buildEmptyState(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(DnaSpacing.xl),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            FaIcon(
              FontAwesomeIcons.houseChimney,
              size: 64,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            const SizedBox(height: DnaSpacing.lg),
            Text(
              'Welcome to your timeline!',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: DnaSpacing.sm),
            Text(
              'Post something to your wall or add contacts to see their posts here.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showCreatePostDialog(BuildContext context, WidgetRef ref) {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('New Post'),
        content: TextField(
          controller: controller,
          maxLines: 5,
          maxLength: 2000,
          decoration: const InputDecoration(
            hintText: 'What\'s on your mind?',
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () async {
              final text = controller.text.trim();
              if (text.isEmpty) return;
              Navigator.pop(context);
              try {
                await ref.read(wallTimelineProvider.notifier).createPost(text);
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to post: $e')),
                  );
                }
              }
            },
            child: const Text('Post'),
          ),
        ],
      ),
    );
  }

  void _confirmDelete(BuildContext context, WidgetRef ref, String postUuid) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Post'),
        content: const Text('Are you sure you want to delete this post?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () async {
              Navigator.pop(context);
              try {
                await ref.read(wallTimelineProvider.notifier).deletePost(postUuid);
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to delete: $e')),
                  );
                }
              }
            },
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }
}
```

**Step 2: Commit**

```bash
git add dna_messenger_flutter/lib/screens/wall/wall_timeline_screen.dart
git commit -m "feat: Add WallTimelineScreen (Home tab)"
```

---

## Task 13: MessagesScreen (Unified Messages Tab)

**Files:**
- Create: `dna_messenger_flutter/lib/screens/messages/messages_screen.dart`

**Step 1: Create the unified messages screen**

This screen combines contacts (P2P chats) and groups with [All] [Chats] [Groups] filter tabs:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../providers/providers.dart';
import '../contacts/contacts_screen.dart';  // Reuse existing widgets
import '../groups/groups_screen.dart';       // Reuse existing widgets

/// Filter state for messages tab
enum MessagesFilter { all, chats, groups }

final messagesFilterProvider = StateProvider<MessagesFilter>((ref) => MessagesFilter.all);

class MessagesScreen extends ConsumerWidget {
  const MessagesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final filter = ref.watch(messagesFilterProvider);
    final chatUnread = ref.watch(totalUnreadCountProvider);
    final groupUnread = ref.watch(totalGroupUnreadCountProvider);

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Messages',
        leading: const SizedBox.shrink(),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () {
              ref.read(contactsProvider.notifier).refresh();
              ref.invalidate(groupsProvider);
            },
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: Column(
        children: [
          // Filter chips
          Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: DnaSpacing.md,
              vertical: DnaSpacing.sm,
            ),
            child: Row(
              children: [
                _FilterChip(
                  label: 'All',
                  selected: filter == MessagesFilter.all,
                  onTap: () => ref.read(messagesFilterProvider.notifier).state =
                      MessagesFilter.all,
                ),
                const SizedBox(width: DnaSpacing.sm),
                _FilterChip(
                  label: 'Chats',
                  badgeCount: chatUnread,
                  selected: filter == MessagesFilter.chats,
                  onTap: () => ref.read(messagesFilterProvider.notifier).state =
                      MessagesFilter.chats,
                ),
                const SizedBox(width: DnaSpacing.sm),
                _FilterChip(
                  label: 'Groups',
                  badgeCount: groupUnread,
                  selected: filter == MessagesFilter.groups,
                  onTap: () => ref.read(messagesFilterProvider.notifier).state =
                      MessagesFilter.groups,
                ),
              ],
            ),
          ),
          // Content based on filter
          Expanded(
            child: switch (filter) {
              MessagesFilter.all => _AllMessagesView(),
              MessagesFilter.chats => const ContactsScreen(embedded: true),
              MessagesFilter.groups => const GroupsScreen(embedded: true),
            },
          ),
        ],
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  final String label;
  final bool selected;
  final VoidCallback onTap;
  final int badgeCount;

  const _FilterChip({
    required this.label,
    required this.selected,
    required this.onTap,
    this.badgeCount = 0,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.md,
          vertical: DnaSpacing.xs,
        ),
        decoration: BoxDecoration(
          color: selected
              ? theme.colorScheme.primary
              : theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(20),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: TextStyle(
                color: selected
                    ? theme.colorScheme.onPrimary
                    : theme.colorScheme.onSurface,
                fontWeight: selected ? FontWeight.bold : FontWeight.normal,
              ),
            ),
            if (badgeCount > 0) ...[
              const SizedBox(width: 4),
              DnaBadge(count: badgeCount),
            ],
          ],
        ),
      ),
    );
  }
}
```

**Step 2: Modify ContactsScreen and GroupsScreen for embedded mode**

Both `ContactsScreen` and `GroupsScreen` need an `embedded` parameter that, when true, hides their AppBar (since MessagesScreen provides its own). Add a constructor parameter:

In `lib/screens/contacts/contacts_screen.dart`:
```dart
class ContactsScreen extends ConsumerWidget {
  final bool embedded;
  const ContactsScreen({super.key, this.embedded = false});
  // When embedded == true, return body content without Scaffold/AppBar
```

Same pattern for `lib/screens/groups/groups_screen.dart`.

**Alternative approach:** Instead of modifying existing screens, extract the list widget content into separate widgets (`ContactsList`, `GroupsList`) and use those in both the standalone screens and the MessagesScreen. This is cleaner but more refactoring.

**Step 3: Implement _AllMessagesView**

The "All" filter shows both contacts and groups in a single list sorted by last message time. This requires a unified data model:

```dart
class _AllMessagesView extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contacts = ref.watch(contactsProvider);
    final groups = ref.watch(groupsProvider);

    return contacts.when(
      data: (contactList) => groups.when(
        data: (groupList) => _buildMergedList(context, ref, contactList, groupList),
        loading: () => _buildMergedList(context, ref, contactList, []),
        error: (e, s) => _buildMergedList(context, ref, contactList, []),
      ),
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (e, s) => Center(child: Text('Error: $e')),
    );
  }

  Widget _buildMergedList(BuildContext context, WidgetRef ref,
      List<Contact> contacts, List<Group> groups) {
    // Build unified list items, sort by last activity
    // Each item is either a contact or a group
    // Render with appropriate icon (user vs userGroup)
    // ...
  }
}
```

**Step 4: Commit**

```bash
git add dna_messenger_flutter/lib/screens/messages/messages_screen.dart
git add dna_messenger_flutter/lib/screens/contacts/contacts_screen.dart
git add dna_messenger_flutter/lib/screens/groups/groups_screen.dart
git commit -m "feat: Add MessagesScreen with unified Chats/Groups view"
```

---

## Task 14: Navigation Restructure

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/home_screen.dart`

**Step 1: Update home_screen.dart**

Replace the entire navigation structure:

```dart
// Home Screen - Main navigation with bottom tabs
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../providers/providers.dart';
import 'wall/wall_timeline_screen.dart';
import 'messages/messages_screen.dart';
import 'feed/feed_screen.dart';
import 'more/more_screen.dart';

/// Current tab index: 0=Home, 1=Messages, 2=Feeds, 3=More
final currentTabProvider = StateProvider<int>((ref) => 0);

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return const _MainNavigation();
  }
}

class _MainNavigation extends ConsumerWidget {
  const _MainNavigation();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final currentTab = ref.watch(currentTabProvider);

    // Combined unread count for Messages tab
    final chatUnreadCount = ref.watch(totalUnreadCountProvider);
    final groupUnreadCount = ref.watch(totalGroupUnreadCountProvider);
    final totalMsgUnread = chatUnreadCount + groupUnreadCount;

    return Scaffold(
      body: IndexedStack(
        index: currentTab,
        children: const [
          WallTimelineScreen(),   // 0: Home
          MessagesScreen(),       // 1: Messages
          FeedScreen(),           // 2: Feeds
          MoreScreen(),           // 3: More
        ],
      ),
      bottomNavigationBar: DnaBottomBar(
        currentIndex: currentTab,
        onTap: (index) => ref.read(currentTabProvider.notifier).state = index,
        items: [
          DnaBottomBarItem(
            icon: FontAwesomeIcons.house,
            activeIcon: FontAwesomeIcons.house,
            label: 'Home',
          ),
          DnaBottomBarItem(
            icon: FontAwesomeIcons.comment,
            activeIcon: FontAwesomeIcons.solidComment,
            label: 'Messages',
            badgeCount: totalMsgUnread,
          ),
          DnaBottomBarItem(
            icon: FontAwesomeIcons.newspaper,
            activeIcon: FontAwesomeIcons.solidNewspaper,
            label: 'Feeds',
          ),
          DnaBottomBarItem(
            icon: FontAwesomeIcons.ellipsis,
            activeIcon: FontAwesomeIcons.ellipsis,
            label: 'More',
          ),
        ],
      ),
    );
  }
}
```

**Step 2: Remove old imports**

Remove the now-unused imports of `ContactsScreen` and `GroupsScreen` from `home_screen.dart` (they're now imported by `messages_screen.dart`).

**Step 3: Verify Flutter build**

```bash
cd dna_messenger_flutter && flutter build linux
```

Expected: Clean build with no errors.

**Step 4: Commit**

```bash
git add dna_messenger_flutter/lib/screens/home_screen.dart
git commit -m "feat: Restructure navigation to Home | Messages | Feeds | More"
```

---

## Task 15: Documentation Updates

**Files:**
- Modify: `docs/functions/dht.md` (add new wall API docs)
- Modify: `docs/functions/public-api.md` (add wall engine API)
- Modify: `docs/functions/engine.md` (add wall module)
- Modify: `docs/FLUTTER_UI.md` (update navigation, add wall screens)

**Step 1: Update dht.md**

Add new section for Wall API (replacing removed 11.7/11.8):

```markdown
### 11.7 Wall (Personal Wall Posts)

| Function | Description |
|----------|-------------|
| `int dna_wall_post(dht, identity, text, out_post)` | Post to own wall |
| `int dna_wall_delete(dht, identity, post_uuid)` | Delete own wall post |
| `int dna_wall_load(dht, fingerprint, wall)` | Load user's wall from DHT |
| `void dna_wall_free(wall)` | Free wall structure |
| `bool dna_wall_post_verify(post, dht)` | Verify post signature |
| `char* dna_wall_to_json(wall)` | Serialize wall to JSON |
| `int dna_wall_from_json(json, wall)` | Deserialize wall from JSON |
| `void dna_wall_make_key(fingerprint, out_key)` | Derive DHT key for wall |
```

**Step 2: Update public-api.md**

Add wall section to public API docs.

**Step 3: Update engine.md**

Add `dna_engine_wall.c` module to the engine modules table.

**Step 4: Update FLUTTER_UI.md**

Update navigation section to reflect new 4-tab layout: Home | Messages | Feeds | More.

**Step 5: Commit**

```bash
git add docs/
git commit -m "docs: Update documentation for wall feature and navigation redesign"
```

---

## Task 16: Version Bump & Final Build Verification

**Files:**
- Modify: `include/dna/version.h` (bump C library version)
- Modify: `dna_messenger_flutter/pubspec.yaml` (bump Flutter app version)

**Step 1: Bump C library version**

In `include/dna/version.h`, bump from `0.6.134` to `0.6.135`.

**Step 2: Bump Flutter app version**

In `dna_messenger_flutter/pubspec.yaml`, bump the version. Check current value first and increment PATCH.

**Step 3: Verify C build**

```bash
cd build && cmake .. && make -j$(nproc)
```

**Step 4: Verify Flutter build**

```bash
cd dna_messenger_flutter && flutter build linux
```

**Step 5: Update CLAUDE.md header**

Update the version numbers in the CLAUDE.md header line.

**Step 6: Commit**

```bash
git add include/dna/version.h dna_messenger_flutter/pubspec.yaml CLAUDE.md
git commit -m "feat: Wall feature & Home redesign (v0.6.135 / v0.100.114)"
```

---

## Summary

| Task | Component | Description |
|------|-----------|-------------|
| 1 | C Library | Remove old wall code |
| 2 | C Library | New wall header (dna_wall.h) |
| 3 | C Library | New wall implementation (dna_wall.c) |
| 4 | C Library | Wall SQLite cache |
| 5 | C Library | Engine internal types |
| 6 | C Library | Public API types and functions |
| 7 | C Library | Engine wall module |
| 8 | Flutter | FFI bindings |
| 9 | Flutter | Wall provider |
| 10 | Flutter | Event handling |
| 11 | Flutter | WallPostTile widget |
| 12 | Flutter | WallTimelineScreen |
| 13 | Flutter | MessagesScreen |
| 14 | Flutter | Navigation restructure |
| 15 | Docs | Documentation updates |
| 16 | Build | Version bump & verification |

**Dependencies:** Tasks 1-7 (C library) must complete before Tasks 8-14 (Flutter). Within C tasks, order matters: 1 → 2 → 3 → 4 → 5 → 6 → 7. Flutter tasks 8-10 can be parallel, then 11-14 sequential.
