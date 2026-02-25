# RSS-Like Channel System — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the forum-style feed system with an RSS-like channel system where users subscribe to named channels containing flat text post streams.

**Architecture:** Clean rewrite with new `dna:channels:` DHT namespace. New C engine module (`dna_engine_channels.c`), new DHT client files, new database layer, new Flutter screens/providers. Old feed code is deleted. 7 default channels (General, Technology, Help, Announcements, Trading, Off Topic, Cpunk) auto-subscribed on identity creation.

**Tech Stack:** C (libdna engine), SQLite (local cache/subscriptions), OpenDHT-PQ (DHT storage with Dilithium5 signing), Flutter/Dart (Riverpod providers, FFI bindings)

**Design Document:** `docs/plans/2026-02-26-rss-channel-system-design.md`

---

## Task 1: Channel Subscriptions Database (`database/channel_subscriptions_db.*`)

Local SQLite storage for channel subscriptions, mirroring the pattern from `feed_subscriptions_db.*`.

**Files:**
- Create: `database/channel_subscriptions_db.h`
- Create: `database/channel_subscriptions_db.c`
- Modify: `CMakeLists.txt:216-217` (add to both SHARED and STATIC `dna_lib` targets)

**Reference pattern:** `database/feed_subscriptions_db.h` and `database/feed_subscriptions_db.c`

**Step 1: Create header `database/channel_subscriptions_db.h`**

```c
#ifndef CHANNEL_SUBSCRIPTIONS_DB_H
#define CHANNEL_SUBSCRIPTIONS_DB_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Channel subscription entry (local SQLite)
 */
typedef struct {
    char channel_uuid[37];      /* UUID v4 of subscribed channel */
    uint64_t subscribed_at;     /* Unix timestamp when subscribed */
    uint64_t last_synced;       /* Unix timestamp of last DHT sync */
    uint64_t last_read_at;      /* Unix timestamp of last read (unread tracking) */
} channel_subscription_t;

int  channel_subscriptions_db_init(void);
void channel_subscriptions_db_close(void);
int  channel_subscriptions_db_subscribe(const char *channel_uuid);
int  channel_subscriptions_db_unsubscribe(const char *channel_uuid);
bool channel_subscriptions_db_is_subscribed(const char *channel_uuid);
int  channel_subscriptions_db_get_all(channel_subscription_t **out_subscriptions, int *out_count);
void channel_subscriptions_db_free(channel_subscription_t *subscriptions, int count);
int  channel_subscriptions_db_update_synced(const char *channel_uuid);
int  channel_subscriptions_db_mark_read(const char *channel_uuid, uint64_t timestamp);
uint64_t channel_subscriptions_db_get_last_read(const char *channel_uuid);

#ifdef __cplusplus
}
#endif
#endif
```

**Step 2: Create implementation `database/channel_subscriptions_db.c`**

Follow `feed_subscriptions_db.c` pattern:
- SQLite database at `<data_dir>/channel_subscriptions.db`
- Table: `subscriptions (channel_uuid TEXT PRIMARY KEY, subscribed_at INTEGER, last_synced INTEGER, last_read_at INTEGER)`
- All functions follow the same error code pattern: 0=success, -1=error, -2=not found, -3=uninitialized
- `_init()` creates table if not exists, called from `dna_engine_identity.c`
- `_close()` called from engine shutdown
- `_mark_read()` updates `last_read_at` to given timestamp
- `_get_last_read()` returns `last_read_at` for unread calculation

**Step 3: Add to `CMakeLists.txt`**

Add `database/channel_subscriptions_db.c` after `database/feed_subscriptions_db.c` in BOTH the SHARED (line ~216) and STATIC (line ~297) `dna_lib` targets.

**Step 4: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 5: Commit**

```bash
git add database/channel_subscriptions_db.h database/channel_subscriptions_db.c CMakeLists.txt
git commit -m "feat(channels): add channel subscriptions database layer"
```

---

## Task 2: Channel Cache Database (`database/channel_cache.*`)

Local SQLite cache for channel metadata and posts to avoid constant DHT queries.

**Files:**
- Create: `database/channel_cache.h`
- Create: `database/channel_cache.c`
- Modify: `CMakeLists.txt` (add to both dna_lib targets)

**Reference pattern:** `database/feed_cache.h` and `database/feed_cache.c`

**Step 1: Create header `database/channel_cache.h`**

```c
#ifndef CHANNEL_CACHE_H
#define CHANNEL_CACHE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Cache staleness: 5 minutes */
#define CHANNEL_CACHE_TTL_SECONDS 300

/* Cache eviction: 30 days */
#define CHANNEL_CACHE_EVICT_SECONDS (30 * 24 * 60 * 60)

int  channel_cache_init(void);
void channel_cache_close(void);

/* Channel metadata cache */
int  channel_cache_put_channel_json(const char *uuid, const char *channel_json,
                                     uint64_t created_at, int deleted);
int  channel_cache_get_channel_json(const char *uuid, char **channel_json_out);

/* Channel posts cache */
int  channel_cache_put_posts(const char *channel_uuid, const char *posts_json,
                              int post_count);
int  channel_cache_get_posts(const char *channel_uuid, char **posts_json_out,
                              int *post_count_out);

/* Staleness tracking */
bool channel_cache_is_stale(const char *cache_key);
int  channel_cache_mark_fresh(const char *cache_key);

/* Eviction */
int  channel_cache_evict_old(void);

#ifdef __cplusplus
}
#endif
#endif
```

**Step 2: Create implementation `database/channel_cache.c`**

Follow `feed_cache.c` pattern:
- SQLite database at `<data_dir>/channel_cache.db` (global, shared across identities)
- Tables:
  - `channels (uuid TEXT PK, channel_json TEXT, created_at INTEGER, deleted INTEGER, last_cached INTEGER)`
  - `channel_posts (channel_uuid TEXT PK, posts_json TEXT, post_count INTEGER, last_cached INTEGER)`
  - `cache_meta (cache_key TEXT PK, last_fetched INTEGER)`
- Standard error codes: 0=success, -1=error, -2=not found, -3=uninitialized
- `_init()` called from `dna_engine.c` during engine init (alongside `feed_cache_init()`)
- `_close()` called from engine shutdown

**Step 3: Add to `CMakeLists.txt`**

Add `database/channel_cache.c` after `database/feed_cache.c` in both dna_lib targets.

**Step 4: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 5: Commit**

```bash
git add database/channel_cache.h database/channel_cache.c CMakeLists.txt
git commit -m "feat(channels): add channel cache database layer"
```

---

## Task 3: DHT Channel Operations (`dht/client/dna_channels.*`)

DHT client layer for channel metadata CRUD and post read/write.

**Files:**
- Create: `dht/client/dna_channels.h`
- Create: `dht/client/dna_channels.c`
- Modify: `dht/CMakeLists.txt:44-46` (add to DHT_COMMON_SOURCES)

**Reference pattern:** `dht/client/dna_feed.h`, `dht/client/dna_feed_topic.c`, `dht/client/dna_feed_comments.c`

**Step 1: Create header `dht/client/dna_channels.h`**

```c
#ifndef DNA_CHANNELS_H
#define DNA_CHANNELS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dht_context dht_context_t;

/* Limits */
#define DNA_CHANNEL_NAME_MAX    100
#define DNA_CHANNEL_DESC_MAX    500
#define DNA_CHANNEL_POST_MAX    4000
#define DNA_CHANNEL_TTL_SECONDS (30 * 24 * 60 * 60)

/* DHT key namespace */
#define DNA_CHANNEL_NS_META   "dna:channels:meta:"
#define DNA_CHANNEL_NS_POSTS  "dna:channels:posts:"
#define DNA_CHANNEL_NS_INDEX  "dna:channels:idx:"

/* Internal channel structure (DHT layer) */
typedef struct {
    char uuid[37];
    char name[DNA_CHANNEL_NAME_MAX + 1];
    char *description;          /* heap-allocated, caller frees */
    char creator_fingerprint[129];
    uint64_t created_at;
    bool is_public;
    bool deleted;
    uint64_t deleted_at;
    /* Signature data */
    uint8_t *signature;
    size_t signature_len;
} dna_channel_t;

/* Internal post structure (DHT layer) */
typedef struct {
    char post_uuid[37];
    char channel_uuid[37];
    char author_fingerprint[129];
    char *body;                 /* heap-allocated, caller frees */
    uint64_t created_at;
    /* Signature data */
    uint8_t *signature;
    size_t signature_len;
} dna_channel_post_internal_t;

/* Channel CRUD */
int dna_channel_create(dht_context_t *dht_ctx,
                       const char *name,
                       const char *description,
                       bool is_public,
                       const char *creator_fingerprint,
                       const uint8_t *private_key,
                       char *uuid_out);

int dna_channel_get(dht_context_t *dht_ctx,
                    const char *uuid,
                    dna_channel_t **channel_out);

int dna_channel_delete(dht_context_t *dht_ctx,
                       const char *uuid,
                       const char *creator_fingerprint,
                       const uint8_t *private_key);

void dna_channel_free(dna_channel_t *channel);
void dna_channels_free(dna_channel_t *channels, size_t count);

/* Posts */
int dna_channel_post_create(dht_context_t *dht_ctx,
                            const char *channel_uuid,
                            const char *body,
                            const char *author_fingerprint,
                            const uint8_t *private_key,
                            char *post_uuid_out);

int dna_channel_posts_get(dht_context_t *dht_ctx,
                          const char *channel_uuid,
                          dna_channel_post_internal_t **posts_out,
                          size_t *count_out);

void dna_channel_post_free(dna_channel_post_internal_t *post);
void dna_channel_posts_free(dna_channel_post_internal_t *posts, size_t count);

/* Public index */
int dna_channel_index_register(dht_context_t *dht_ctx,
                               const char *channel_uuid,
                               const char *name,
                               const char *description,
                               const char *creator_fingerprint,
                               const uint8_t *private_key);

int dna_channel_index_browse(dht_context_t *dht_ctx,
                             int days_back,
                             dna_channel_t **channels_out,
                             size_t *count_out);

/* DHT key derivation */
int dna_channel_make_meta_key(const char *uuid, uint8_t *key_out, size_t *key_len_out);
int dna_channel_make_posts_key(const char *uuid, uint8_t *key_out, size_t *key_len_out);
int dna_channel_make_index_key(const char *date_str, uint8_t *key_out, size_t *key_len_out);

#ifdef __cplusplus
}
#endif
#endif
```

**Step 2: Create implementation `dht/client/dna_channels.c`**

Follow the patterns from `dna_feed_topic.c` and `dna_feed_comments.c`:
- Key derivation: `SHA256(namespace_prefix + identifier)` → 32-byte DHT key
- Channel metadata: single-owner `dht_put_signed()` with Dilithium5
- Posts: multi-owner `dht_put()` — each post is a separate DHT value on the posts key
- Index: multi-owner `dht_put()` on day-bucket key `dna:channels:idx:YYYYMMDD`
- Serialization: `json-c` for channel/post data → binary (JSON string → UTF-8 bytes)
- UUID generation: `qgp_random_bytes()` formatted as UUID v4
- Signature: Sign serialized JSON with Dilithium5 private key, store signature alongside data

**Step 3: Add to `dht/CMakeLists.txt`**

Add `client/dna_channels.c` to `DHT_COMMON_SOURCES` after `client/dna_feed_index.c` (line ~46).

**Step 4: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 5: Commit**

```bash
git add dht/client/dna_channels.h dht/client/dna_channels.c dht/CMakeLists.txt
git commit -m "feat(channels): add DHT channel operations layer"
```

---

## Task 4: DHT Channel Subscription Sync (`dht/shared/dht_channel_subscriptions.*`)

Multi-device subscription sync via DHT, mirroring `dht_feed_subscriptions.*`.

**Files:**
- Create: `dht/shared/dht_channel_subscriptions.h`
- Create: `dht/shared/dht_channel_subscriptions.c`
- Modify: `dht/CMakeLists.txt:32` (add to DHT_COMMON_SOURCES)

**Reference pattern:** `dht/shared/dht_feed_subscriptions.h` and `dht/shared/dht_feed_subscriptions.c`

**Step 1: Create header `dht/shared/dht_channel_subscriptions.h`**

```c
#ifndef DHT_CHANNEL_SUBSCRIPTIONS_H
#define DHT_CHANNEL_SUBSCRIPTIONS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dht_context dht_context_t;

#define DHT_CHANNEL_SUBS_VERSION     1
#define DHT_CHANNEL_SUBS_TTL_SECONDS (30 * 24 * 60 * 60)
#define DHT_CHANNEL_SUBS_MAX_COUNT   300

/* DHT key namespace */
#define DHT_CHANNEL_SUBS_NS "dna:channels:subs:"

typedef struct {
    char channel_uuid[37];
    uint64_t subscribed_at;
    uint64_t last_synced;
    uint64_t last_read_at;
} dht_channel_subscription_entry_t;

int dht_channel_subscriptions_sync_to_dht(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const dht_channel_subscription_entry_t *subscriptions,
    size_t count);

int dht_channel_subscriptions_sync_from_dht(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dht_channel_subscription_entry_t **subscriptions_out,
    size_t *count_out);

void dht_channel_subscriptions_free(
    dht_channel_subscription_entry_t *subscriptions,
    size_t count);

int dht_channel_subscriptions_make_key(
    const char *fingerprint,
    uint8_t *key_out,
    size_t *key_len_out);

#ifdef __cplusplus
}
#endif
#endif
```

**Step 2: Create implementation `dht/shared/dht_channel_subscriptions.c`**

Follow `dht_feed_subscriptions.c` pattern:
- DHT key: `SHA3-512("dna:channels:subs:" + fingerprint)` → 64-byte key
- Binary serialization: version byte + count + entries (uuid + timestamps)
- `dht_put_signed()` for ownership
- `dht_get()` + deserialize for sync-from
- Max 300 subscriptions (~16KB)

**Step 3: Add to `dht/CMakeLists.txt`**

Add `shared/dht_channel_subscriptions.c` after `shared/dht_feed_subscriptions.c` (line ~32).

**Step 4: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 5: Commit**

```bash
git add dht/shared/dht_channel_subscriptions.h dht/shared/dht_channel_subscriptions.c dht/CMakeLists.txt
git commit -m "feat(channels): add DHT channel subscription sync"
```

---

## Task 5: Public API Declarations (`include/dna/dna_engine.h`)

Add channel data structures, callback types, event constants, and function declarations to the public header.

**Files:**
- Modify: `include/dna/dna_engine.h`

**Step 1: Add channel data structures**

Add after the existing feed structs (around line ~311):

```c
/* =====================================================
 * Channel System (RSS-like channels, replaces Feed v2)
 * ===================================================== */

/**
 * Channel information (simplified for async API)
 */
typedef struct {
    char channel_uuid[37];          /* UUID v4 */
    char name[101];                 /* Channel name (max 100 chars) */
    char *description;              /* Optional description (caller frees, max 500 chars) */
    char creator_fingerprint[129];  /* Creator's SHA3-512 fingerprint */
    uint64_t created_at;            /* Unix timestamp */
    bool is_public;                 /* Listed on public DHT index */
    bool deleted;                   /* Soft delete flag */
    uint64_t deleted_at;            /* When deleted (0 if not deleted) */
    bool verified;                  /* Dilithium5 signature verified */
} dna_channel_info_t;

/**
 * Channel post (flat text entry in a channel)
 */
typedef struct {
    char post_uuid[37];             /* UUID v4 */
    char channel_uuid[37];          /* Parent channel UUID */
    char author_fingerprint[129];   /* Author's SHA3-512 fingerprint */
    char *body;                     /* Post text content (caller frees, max 4000 chars) */
    uint64_t created_at;            /* Unix timestamp */
    bool verified;                  /* Dilithium5 signature verified */
} dna_channel_post_info_t;

/**
 * Channel subscription (local + DHT sync)
 */
typedef struct {
    char channel_uuid[37];          /* UUID v4 of subscribed channel */
    uint64_t subscribed_at;         /* Unix timestamp when subscribed */
    uint64_t last_synced;           /* Unix timestamp of last DHT sync */
    uint64_t last_read_at;          /* For unread tracking */
} dna_channel_subscription_info_t;

/* Default channel UUIDs (deterministic from SHA256 of well-known names) */
#define DNA_DEFAULT_CHANNEL_COUNT 7
extern const char *DNA_DEFAULT_CHANNEL_UUIDS[DNA_DEFAULT_CHANNEL_COUNT];
extern const char *DNA_DEFAULT_CHANNEL_NAMES[DNA_DEFAULT_CHANNEL_COUNT];
extern const char *DNA_DEFAULT_CHANNEL_DESCRIPTIONS[DNA_DEFAULT_CHANNEL_COUNT];
```

**Step 2: Add callback types**

Add after existing feed callback types:

```c
/* Channel callbacks */
typedef void (*dna_channel_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_info_t *channel, void *user_data);

typedef void (*dna_channels_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_info_t *channels, int count, void *user_data);

typedef void (*dna_channel_post_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_post_info_t *post, void *user_data);

typedef void (*dna_channel_posts_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_post_info_t *posts, int count, void *user_data);

typedef void (*dna_channel_subscriptions_cb)(
    dna_request_id_t request_id, int error,
    dna_channel_subscription_info_t *subscriptions, int count, void *user_data);
```

**Step 3: Add event constants**

Add to the event enum/defines:

```c
DNA_EVENT_CHANNEL_NEW_POST,         /* New post in subscribed channel */
DNA_EVENT_CHANNEL_SUBS_SYNCED,      /* Subscriptions synced from DHT */
```

And add event data struct:
```c
struct {
    char channel_uuid[37];
    char post_uuid[37];
    char author_fingerprint[129];
} channel_new_post;

struct {
    int subscriptions_synced;
} channel_subs_synced;
```

**Step 4: Add public API function declarations**

```c
/* =====================================================
 * Channel API
 * ===================================================== */

/* Channel CRUD */
dna_request_id_t dna_engine_channel_create(dna_engine_t *engine,
    const char *name, const char *description, bool is_public,
    dna_channel_cb callback, void *user_data);

dna_request_id_t dna_engine_channel_get(dna_engine_t *engine,
    const char *uuid, dna_channel_cb callback, void *user_data);

dna_request_id_t dna_engine_channel_delete(dna_engine_t *engine,
    const char *uuid, dna_completion_cb callback, void *user_data);

dna_request_id_t dna_engine_channel_discover(dna_engine_t *engine,
    int days_back, dna_channels_cb callback, void *user_data);

/* Posts */
dna_request_id_t dna_engine_channel_post(dna_engine_t *engine,
    const char *channel_uuid, const char *body,
    dna_channel_post_cb callback, void *user_data);

dna_request_id_t dna_engine_channel_get_posts(dna_engine_t *engine,
    const char *channel_uuid,
    dna_channel_posts_cb callback, void *user_data);

/* Subscriptions (synchronous) */
int  dna_engine_channel_subscribe(dna_engine_t *engine, const char *channel_uuid);
int  dna_engine_channel_unsubscribe(dna_engine_t *engine, const char *channel_uuid);
bool dna_engine_channel_is_subscribed(dna_engine_t *engine, const char *channel_uuid);
int  dna_engine_channel_mark_read(dna_engine_t *engine, const char *channel_uuid);

/* Subscriptions (async) */
dna_request_id_t dna_engine_channel_get_subscriptions(dna_engine_t *engine,
    dna_channel_subscriptions_cb callback, void *user_data);

dna_request_id_t dna_engine_channel_sync_subs_to_dht(dna_engine_t *engine,
    dna_completion_cb callback, void *user_data);

dna_request_id_t dna_engine_channel_sync_subs_from_dht(dna_engine_t *engine,
    dna_completion_cb callback, void *user_data);

/* Memory management */
void dna_free_channel_info(dna_channel_info_t *channel);
void dna_free_channel_infos(dna_channel_info_t *channels, int count);
void dna_free_channel_post(dna_channel_post_info_t *post);
void dna_free_channel_posts(dna_channel_post_info_t *posts, int count);
void dna_free_channel_subscriptions(dna_channel_subscription_info_t *subs, int count);
```

**Step 5: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 6: Commit**

```bash
git add include/dna/dna_engine.h
git commit -m "feat(channels): add public API declarations to dna_engine.h"
```

---

## Task 6: Engine Internal Types (`src/api/dna_engine_internal.h`)

Add channel task types, task parameters, and handler declarations to the internal header.

**Files:**
- Modify: `src/api/dna_engine_internal.h`

**Step 1: Add task type enum entries**

Add after feed task types (around line ~159):

```c
/* Channel system (replaces Feed v2) */
TASK_CHANNEL_CREATE,
TASK_CHANNEL_GET,
TASK_CHANNEL_DELETE,
TASK_CHANNEL_DISCOVER,
TASK_CHANNEL_POST,
TASK_CHANNEL_GET_POSTS,
TASK_CHANNEL_GET_SUBSCRIPTIONS,
TASK_CHANNEL_SYNC_SUBS_TO_DHT,
TASK_CHANNEL_SYNC_SUBS_FROM_DHT,
```

**Step 2: Add task parameters to union**

Add to `dna_task_params_t` union:

```c
/* Channel: create */
struct {
    char name[101];
    char *description;       /* Heap allocated, task owns */
    bool is_public;
} channel_create;

/* Channel: get / delete / get_posts */
struct {
    char uuid[37];
} channel_by_uuid;

/* Channel: discover */
struct {
    int days_back;
} channel_discover;

/* Channel: post */
struct {
    char channel_uuid[37];
    char *body;              /* Heap allocated, task owns */
} channel_post;
```

**Step 3: Add callback entries to union**

Add to `dna_task_callback_t` union:

```c
dna_channel_cb channel;
dna_channels_cb channels;
dna_channel_post_cb channel_post;
dna_channel_posts_cb channel_posts;
dna_channel_subscriptions_cb channel_subscriptions;
```

**Step 4: Declare handler functions**

```c
/* Channel handlers (dna_engine_channels.c) */
void dna_handle_channel_create(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_get(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_delete(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_discover(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_post(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_get_posts(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_get_subscriptions(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_sync_subs_to_dht(dna_engine_t *engine, dna_task_t *task);
void dna_handle_channel_sync_subs_from_dht(dna_engine_t *engine, dna_task_t *task);
```

**Step 5: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 6: Commit**

```bash
git add src/api/dna_engine_internal.h
git commit -m "feat(channels): add internal task types and handler declarations"
```

---

## Task 7: Engine Channel Module (`src/api/engine/dna_engine_channels.c`)

The main engine module implementing all channel handlers and public API wrappers.

**Files:**
- Create: `src/api/engine/dna_engine_channels.c`
- Modify: `CMakeLists.txt` (add to both dna_lib targets)

**Reference pattern:** `src/api/engine/dna_engine_feed.c`

**Step 1: Create module file with header, helpers, and handlers**

```c
/*
 * DNA Engine - Channels Module
 *
 * RSS-like channel system. Named channels with flat text post streams.
 * Replaces the forum-style feed system (topics + threaded comments).
 *
 * Contains handlers and public API for:
 *   - Channel CRUD (create, get, delete)
 *   - Posts (create, list)
 *   - Subscriptions (subscribe, unsubscribe, sync)
 *   - Discovery (browse public index)
 */

#define DNA_ENGINE_CHANNELS_IMPL

#include "engine_includes.h"
#include "dht/client/dna_channels.h"
#include "database/channel_cache.h"
#include "database/channel_subscriptions_db.h"
#include "dht/shared/dht_channel_subscriptions.h"
#include <json-c/json.h>

#undef LOG_TAG
#define LOG_TAG "ENGINE_CHANNELS"
```

Implement all 9 handlers following the pattern from `dna_engine_feed.c`:

**Each handler follows this pattern:**
1. Get DHT context + private key (null checks)
2. Parse task params
3. Call DHT client function (`dna_channel_*`)
4. Convert internal struct → public `_info_t` struct
5. Cache result
6. Call `task->callback.<type>()` with result

**Then implement all public API wrappers:**
- Each follows the pattern: validate params → build task params → `dna_submit_task()`
- Synchronous functions (`subscribe/unsubscribe/is_subscribed/mark_read`) call database directly

**Also implement:**
- `channel_info_to_json()` / `channel_info_from_json()` — static serialization helpers
- `post_info_to_json()` / `post_info_from_json()` — static serialization helpers
- `dna_free_channel_info()`, `dna_free_channel_infos()` — public memory management
- `dna_free_channel_post()`, `dna_free_channel_posts()` — public memory management
- `dna_free_channel_subscriptions()` — public memory management
- Default channel UUID generation and registration constants

**Default channel UUIDs:** Generate deterministic UUIDs from `SHA256("dna:default:<name>")` truncated to UUID v4 format. Define these as `const char*` arrays in this file, declared `extern` in `dna_engine.h`.

**Step 2: Add to `CMakeLists.txt`**

Add `src/api/engine/dna_engine_channels.c` after `src/api/engine/dna_engine_feed.c` in both dna_lib targets.

**Step 3: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 4: Commit**

```bash
git add src/api/engine/dna_engine_channels.c CMakeLists.txt
git commit -m "feat(channels): implement channel engine module with handlers and API"
```

---

## Task 8: Engine Dispatch and Cleanup (`src/api/dna_engine.c`)

Wire up the new channel task types in the engine's dispatch and cleanup functions.

**Files:**
- Modify: `src/api/dna_engine.c`

**Step 1: Add dispatch cases to `dna_execute_task()`**

Add after feed dispatch cases (around line ~1201):

```c
/* Channel system */
case TASK_CHANNEL_CREATE:
    dna_handle_channel_create(engine, task);
    break;
case TASK_CHANNEL_GET:
    dna_handle_channel_get(engine, task);
    break;
case TASK_CHANNEL_DELETE:
    dna_handle_channel_delete(engine, task);
    break;
case TASK_CHANNEL_DISCOVER:
    dna_handle_channel_discover(engine, task);
    break;
case TASK_CHANNEL_POST:
    dna_handle_channel_post(engine, task);
    break;
case TASK_CHANNEL_GET_POSTS:
    dna_handle_channel_get_posts(engine, task);
    break;
case TASK_CHANNEL_GET_SUBSCRIPTIONS:
    dna_handle_channel_get_subscriptions(engine, task);
    break;
case TASK_CHANNEL_SYNC_SUBS_TO_DHT:
    dna_handle_channel_sync_subs_to_dht(engine, task);
    break;
case TASK_CHANNEL_SYNC_SUBS_FROM_DHT:
    dna_handle_channel_sync_subs_from_dht(engine, task);
    break;
```

**Step 2: Add cleanup cases to `dna_free_task_params()`**

```c
case TASK_CHANNEL_CREATE:
    free(task->params.channel_create.description);
    break;
case TASK_CHANNEL_POST:
    free(task->params.channel_post.body);
    break;
```

**Step 3: Add `channel_cache_init()` call**

In engine initialization (around line ~1345, after `feed_cache_init()`):

```c
/* Initialize global channel cache */
channel_cache_init();
```

**Step 4: Add `channel_cache_close()` and `channel_subscriptions_db_close()` calls**

In engine shutdown, add alongside existing close calls.

**Step 5: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 6: Commit**

```bash
git add src/api/dna_engine.c
git commit -m "feat(channels): wire up channel dispatch and cleanup in engine"
```

---

## Task 9: Channel Listeners (`src/api/engine/dna_engine_listeners.c`)

Add DHT listeners for real-time channel post notifications.

**Files:**
- Modify: `src/api/engine/dna_engine_listeners.c`

**Step 1: Add channel post listener callback**

Follow the `outbox_listen_callback` pattern:

```c
typedef struct {
    dna_engine_t *engine;
    char channel_uuid[37];
} channel_listener_ctx_t;

static bool channel_post_listen_callback(
    const uint8_t *value, size_t value_len,
    bool expired, void *user_data)
{
    channel_listener_ctx_t *ctx = (channel_listener_ctx_t *)user_data;
    if (!ctx || !ctx->engine) return false;

    if (!expired && value && value_len > 0) {
        dna_event_t event = {0};
        event.type = DNA_EVENT_CHANNEL_NEW_POST;
        strncpy(event.data.channel_new_post.channel_uuid,
                ctx->channel_uuid,
                sizeof(event.data.channel_new_post.channel_uuid) - 1);
        dna_dispatch_event(ctx->engine, &event);
    }
    return true;
}
```

**Step 2: Add function to start listening on a channel's posts key**

```c
void dna_engine_start_channel_listener(dna_engine_t *engine, const char *channel_uuid);
```

**Step 3: Add function to start listeners for all subscribed channels**

```c
void dna_engine_listen_all_channels(dna_engine_t *engine);
```

This reads all subscriptions from local DB and starts a listener for each channel's posts DHT key.

**Step 4: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 5: Commit**

```bash
git add src/api/engine/dna_engine_listeners.c
git commit -m "feat(channels): add real-time channel post listeners"
```

---

## Task 10: Identity Integration (Auto-Subscribe Defaults)

On new identity creation, auto-subscribe to the 7 default channels.

**Files:**
- Modify: `src/api/engine/dna_engine_identity.c`

**Step 1: Add channel subscription initialization**

In `dna_handle_identity_load` (where `feed_subscriptions_db_init()` is called, line ~214):

```c
/* Initialize channel subscriptions database */
if (channel_subscriptions_db_init() != 0) {
    QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize channel subscriptions database");
}
```

**Step 2: Add auto-subscribe for new identity**

In identity creation handler (where DNA_UPDATES_TOPIC_UUID subscription happens, line ~1081):

```c
/* Auto-subscribe new identity to default channels */
if (channel_subscriptions_db_init() == 0) {
    for (int i = 0; i < DNA_DEFAULT_CHANNEL_COUNT; i++) {
        channel_subscriptions_db_subscribe(DNA_DEFAULT_CHANNEL_UUIDS[i]);
    }
    QGP_LOG_INFO(LOG_TAG, "Auto-subscribed to %d default channels", DNA_DEFAULT_CHANNEL_COUNT);
}
```

**Step 3: Build to verify**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 4: Commit**

```bash
git add src/api/engine/dna_engine_identity.c
git commit -m "feat(channels): auto-subscribe to default channels on identity creation"
```

---

## Task 11: Flutter Dart Models (`lib/models/channel.dart`)

Dart model classes for channels, posts, and subscriptions.

**Files:**
- Create: `dna_messenger_flutter/lib/models/channel.dart`

**Step 1: Create models file**

```dart
/// Channel data models for the RSS-like channel system.

class Channel {
  final String uuid;
  final String name;
  final String description;
  final String creatorFingerprint;
  final DateTime createdAt;
  final bool isPublic;
  final bool deleted;
  final DateTime? deletedAt;
  final bool verified;

  Channel({
    required this.uuid,
    required this.name,
    required this.description,
    required this.creatorFingerprint,
    required this.createdAt,
    required this.isPublic,
    required this.deleted,
    this.deletedAt,
    this.verified = false,
  });
}

class ChannelPost {
  final String uuid;
  final String channelUuid;
  final String authorFingerprint;
  final String body;
  final DateTime createdAt;
  final bool verified;

  ChannelPost({
    required this.uuid,
    required this.channelUuid,
    required this.authorFingerprint,
    required this.body,
    required this.createdAt,
    this.verified = false,
  });
}

class ChannelSubscription {
  final String channelUuid;
  final DateTime subscribedAt;
  final DateTime? lastSynced;
  final DateTime? lastReadAt;

  ChannelSubscription({
    required this.channelUuid,
    required this.subscribedAt,
    this.lastSynced,
    this.lastReadAt,
  });
}
```

**Step 2: Commit**

```bash
git add dna_messenger_flutter/lib/models/channel.dart
git commit -m "feat(channels): add Flutter channel data models"
```

---

## Task 12: Flutter FFI Bindings (`lib/ffi/dna_engine.dart`)

Add FFI method wrappers and `fromNative()` factories to bridge C API → Dart.

**Files:**
- Modify: `dna_messenger_flutter/lib/ffi/dna_engine.dart`

**Step 1: Add `fromNative()` factories to models**

Add static factory constructors to `Channel`, `ChannelPost`, `ChannelSubscription` that read from native structs. Follow the `FeedTopic.fromNative()` pattern:
- Fixed char arrays: `.toDartString(N)`
- Heap pointers: null check + `.toDartString()`
- Timestamps: `DateTime.fromMillisecondsSinceEpoch(native.field * 1000)`

**Step 2: Add FFI method wrappers**

Add these methods to the `DnaEngine` class, following existing patterns:

```dart
// Channel CRUD
Future<Channel> channelCreate(String name, String description, {bool isPublic = true});
Future<Channel> channelGet(String uuid);
Future<void> channelDelete(String uuid);
Future<List<Channel>> channelDiscover({int daysBack = 7});

// Posts
Future<ChannelPost> channelPost(String channelUuid, String body);
Future<List<ChannelPost>> channelGetPosts(String channelUuid);

// Subscriptions (sync via engine, but these wrap the C synchronous calls)
bool channelSubscribe(String channelUuid);
bool channelUnsubscribe(String channelUuid);
bool channelIsSubscribed(String channelUuid);
void channelMarkRead(String channelUuid);

// Subscriptions (async)
Future<List<ChannelSubscription>> channelGetSubscriptions();
Future<void> channelSyncSubsToDht();
Future<void> channelSyncSubsFromDht();
```

Each async method follows the `Completer + NativeCallable.listener + _pendingRequests` pattern from `feedCreateTopic`.

Each sync method calls the C function directly (no completer needed — the C function returns immediately).

**Step 3: Add native callback type definitions**

Add typedef aliases for the native callback signatures matching `dna_channel_cb`, `dna_channels_cb`, `dna_channel_post_cb`, `dna_channel_posts_cb`, `dna_channel_subscriptions_cb`.

**Step 4: Verify with flutter analyze**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter analyze
```

**Step 5: Commit**

```bash
git add dna_messenger_flutter/lib/ffi/dna_engine.dart dna_messenger_flutter/lib/models/channel.dart
git commit -m "feat(channels): add Flutter FFI bindings for channel API"
```

---

## Task 13: Flutter Channel Provider (`lib/providers/channel_provider.dart`)

Riverpod providers for channel state management.

**Files:**
- Create: `dna_messenger_flutter/lib/providers/channel_provider.dart`
- Modify: `dna_messenger_flutter/lib/providers/providers.dart` (barrel export)

**Reference pattern:** `lib/providers/feed_provider.dart`

**Step 1: Create channel provider**

```dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import '../models/channel.dart';
import 'providers.dart';

/// Currently selected channel UUID
final selectedChannelProvider = StateProvider<String?>((ref) => null);

/// Subscribed channels list
final channelListProvider =
    AsyncNotifierProvider<ChannelListNotifier, List<Channel>>(
  ChannelListNotifier.new,
);

class ChannelListNotifier extends AsyncNotifier<List<Channel>> {
  @override
  Future<List<Channel>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return state.valueOrNull ?? [];

    final engine = await ref.watch(engineProvider.future);
    final subs = await engine.channelGetSubscriptions();

    // Fetch metadata for each subscribed channel
    final channels = <Channel>[];
    for (final sub in subs) {
      try {
        final channel = await engine.channelGet(sub.channelUuid);
        channels.add(channel);
      } catch (_) {
        // Channel may have expired from DHT - skip
      }
    }
    return channels;
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() => build());
  }

  Future<Channel> createChannel(String name, String description,
      {bool isPublic = true}) async {
    final engine = await ref.read(engineProvider.future);
    final channel =
        await engine.channelCreate(name, description, isPublic: isPublic);
    await refresh();
    return channel;
  }
}

/// Posts for a specific channel (family by UUID)
final channelPostsProvider = AsyncNotifierProviderFamily<
    ChannelPostsNotifier, List<ChannelPost>, String>(
  ChannelPostsNotifier.new,
);

class ChannelPostsNotifier
    extends FamilyAsyncNotifier<List<ChannelPost>, String> {
  @override
  Future<List<ChannelPost>> build(String arg) async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return state.valueOrNull ?? [];

    final engine = await ref.watch(engineProvider.future);
    return engine.channelGetPosts(arg);
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.channelGetPosts(arg);
    });
  }

  Future<ChannelPost> addPost(String body) async {
    final engine = await ref.read(engineProvider.future);
    final post = await engine.channelPost(arg, body);
    await refresh();
    return post;
  }
}

/// Channel subscriptions
final channelSubscriptionsProvider = AsyncNotifierProvider<
    ChannelSubscriptionsNotifier, List<ChannelSubscription>>(
  ChannelSubscriptionsNotifier.new,
);

class ChannelSubscriptionsNotifier
    extends AsyncNotifier<List<ChannelSubscription>> {
  @override
  Future<List<ChannelSubscription>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return state.valueOrNull ?? [];

    final engine = await ref.watch(engineProvider.future);
    return engine.channelGetSubscriptions();
  }

  Future<void> subscribe(String channelUuid) async {
    final engine = await ref.read(engineProvider.future);
    engine.channelSubscribe(channelUuid);
    ref.invalidateSelf();
    ref.invalidate(channelListProvider);
  }

  Future<void> unsubscribe(String channelUuid) async {
    final engine = await ref.read(engineProvider.future);
    engine.channelUnsubscribe(channelUuid);
    ref.invalidateSelf();
    ref.invalidate(channelListProvider);
  }

  Future<void> syncToDht() async {
    final engine = await ref.read(engineProvider.future);
    await engine.channelSyncSubsToDht();
  }

  Future<void> syncFromDht() async {
    final engine = await ref.read(engineProvider.future);
    await engine.channelSyncSubsFromDht();
    ref.invalidateSelf();
    ref.invalidate(channelListProvider);
  }
}

/// Discover public channels
final discoverChannelsProvider =
    AsyncNotifierProvider<DiscoverChannelsNotifier, List<Channel>>(
  DiscoverChannelsNotifier.new,
);

class DiscoverChannelsNotifier extends AsyncNotifier<List<Channel>> {
  @override
  Future<List<Channel>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return [];

    final engine = await ref.watch(engineProvider.future);
    return engine.channelDiscover(daysBack: 30);
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() => build());
  }
}
```

**Step 2: Export from barrel file**

Add to `lib/providers/providers.dart`:
```dart
export 'channel_provider.dart';
```

**Step 3: Verify with flutter analyze**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter analyze
```

**Step 4: Commit**

```bash
git add dna_messenger_flutter/lib/providers/channel_provider.dart dna_messenger_flutter/lib/providers/providers.dart
git commit -m "feat(channels): add Riverpod providers for channel state"
```

---

## Task 14: Flutter Event Handler Integration

Wire channel events to provider refreshes.

**Files:**
- Modify: `dna_messenger_flutter/lib/providers/event_handler.dart` (or `lib/services/event_handler.dart`)

**Step 1: Add channel event cases**

Add alongside existing feed event handling:

```dart
case ChannelNewPostEvent(channelUuid: final uuid):
  logPrint('[DART-HANDLER] ChannelNewPostEvent: channel=$uuid');
  _ref.invalidate(channelPostsProvider(uuid));
  break;

case ChannelSubsSyncedEvent(count: final count):
  logPrint('[DART-HANDLER] ChannelSubsSyncedEvent: synced $count subscriptions');
  _ref.invalidate(channelSubscriptionsProvider);
  _ref.invalidate(channelListProvider);
  break;
```

**Step 2: Add event class definitions**

Add `ChannelNewPostEvent` and `ChannelSubsSyncedEvent` to the event class hierarchy, following the pattern of `FeedTopicCommentEvent`.

**Step 3: Verify with flutter analyze**

**Step 4: Commit**

```bash
git add dna_messenger_flutter/lib/providers/event_handler.dart
git commit -m "feat(channels): integrate channel events with provider refresh"
```

---

## Task 15: Flutter Channel List Screen

The landing screen showing subscribed channels with unread indicators.

**Files:**
- Create: `dna_messenger_flutter/lib/screens/channels/channel_list_screen.dart`

**Reference pattern:** `lib/screens/contacts/contacts_screen.dart` and `lib/screens/feed/feed_screen.dart`

**Key elements:**
- `ConsumerWidget` with `ref.watch(channelListProvider)`
- `DnaAppBar` with title "Channels"
- Actions: [+] create, [🔍] discover (FontAwesome icons)
- `ListView.builder` of channel tiles
- Each tile: channel name, description snippet, unread indicator
- Pull-to-refresh via `RefreshIndicator`
- Tap → navigate to `ChannelDetailScreen`
- Long-press → unsubscribe dialog
- Empty state with icon + "No channels yet"
- Loading/error states using `.when()` with `skipLoadingOnReload: true`

**Step 1: Create the screen file with full widget implementation**

**Step 2: Verify with flutter analyze**

**Step 3: Commit**

```bash
git add dna_messenger_flutter/lib/screens/channels/channel_list_screen.dart
git commit -m "feat(channels): add channel list screen"
```

---

## Task 16: Flutter Channel Detail Screen

Post stream view for a single channel.

**Files:**
- Create: `dna_messenger_flutter/lib/screens/channels/channel_detail_screen.dart`

**Key elements:**
- `ConsumerStatefulWidget` (needs TextEditingController for post input)
- `ref.watch(channelPostsProvider(channelUuid))` for posts
- `DnaAppBar` with channel name + unsubscribe action
- `ListView.builder` of post cards (newest first)
- Each post: author name (resolved via profile provider), relative time, body text
- Post input at bottom: `TextField` + send `IconButton`
- Auto-mark channel as read on open (`channelMarkRead`)
- Pull-to-refresh

**Step 1: Create the screen file**

**Step 2: Verify with flutter analyze**

**Step 3: Commit**

```bash
git add dna_messenger_flutter/lib/screens/channels/channel_detail_screen.dart
git commit -m "feat(channels): add channel detail screen with post stream"
```

---

## Task 17: Flutter Create Channel Screen

Simple form for creating a new channel.

**Files:**
- Create: `dna_messenger_flutter/lib/screens/channels/create_channel_screen.dart`

**Key elements:**
- `ConsumerStatefulWidget` with form controllers
- Name field (required, max 100 chars)
- Description field (optional, max 500 chars)
- "List publicly" checkbox (default: true)
- `DnaButton` with `label: 'Create Channel'`
- Loading state while creating
- Navigate back on success
- Error snackbar on failure

**Step 1: Create the screen file**

**Step 2: Verify with flutter analyze**

**Step 3: Commit**

```bash
git add dna_messenger_flutter/lib/screens/channels/create_channel_screen.dart
git commit -m "feat(channels): add create channel screen"
```

---

## Task 18: Flutter Discover Channels Screen

Browse public channels from DHT index.

**Files:**
- Create: `dna_messenger_flutter/lib/screens/channels/discover_channels_screen.dart`

**Key elements:**
- `ConsumerWidget` with `ref.watch(discoverChannelsProvider)`
- `DnaAppBar` with title "Discover Channels"
- Search field for client-side filtering by name
- `ListView.builder` of discoverable channels
- Each item: name, description, creator name, subscribe [+] button
- Subscribe button calls `channelSubscriptionsProvider.subscribe(uuid)`
- Already-subscribed channels show checkmark instead of [+]

**Step 1: Create the screen file**

**Step 2: Verify with flutter analyze**

**Step 3: Commit**

```bash
git add dna_messenger_flutter/lib/screens/channels/discover_channels_screen.dart
git commit -m "feat(channels): add discover channels screen"
```

---

## Task 19: Navigation Integration

Replace the "Feeds" tab with "Channels" in bottom navigation.

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/home_screen.dart`

**Step 1: Replace FeedScreen with ChannelListScreen**

In the `IndexedStack` children (around the navigation definition):

```dart
// Before:
FeedScreen(),           // 2: Feeds

// After:
ChannelListScreen(),    // 2: Channels
```

**Step 2: Update bottom bar label**

```dart
// Before:
DnaBottomBarItem(
  icon: FontAwesomeIcons.newspaper,
  activeIcon: FontAwesomeIcons.solidNewspaper,
  label: 'Feeds',
),

// After:
DnaBottomBarItem(
  icon: FontAwesomeIcons.hashtag,
  activeIcon: FontAwesomeIcons.hashtag,
  label: 'Channels',
),
```

**Step 3: Add imports**

Replace feed screen import with channel screen import.

**Step 4: Verify with flutter analyze**

**Step 5: Commit**

```bash
git add dna_messenger_flutter/lib/screens/home_screen.dart
git commit -m "feat(channels): replace Feeds tab with Channels in navigation"
```

---

## Task 20: Delete Old Feed Code

Remove all old feed system code (C library + Flutter).

**Files to delete (C):**
- `dht/client/dna_feed.h`
- `dht/client/dna_feed_topic.c`
- `dht/client/dna_feed_comments.c`
- `dht/client/dna_feed_index.c`
- `dht/shared/dht_feed_subscriptions.h`
- `dht/shared/dht_feed_subscriptions.c`
- `database/feed_cache.h`
- `database/feed_cache.c`
- `database/feed_subscriptions_db.h`
- `database/feed_subscriptions_db.c`
- `src/api/engine/dna_engine_feed.c`

**Files to delete (Flutter):**
- `dna_messenger_flutter/lib/screens/feed/feed_screen.dart`
- `dna_messenger_flutter/lib/providers/feed_provider.dart`

**Files to modify:**
- `CMakeLists.txt` — remove `dna_engine_feed.c`, `feed_cache.c`, `feed_subscriptions_db.c`
- `dht/CMakeLists.txt` — remove `dna_feed_topic.c`, `dna_feed_comments.c`, `dna_feed_index.c`, `dht_feed_subscriptions.c`
- `include/dna/dna_engine.h` — remove feed structs, callbacks, function declarations, events
- `src/api/dna_engine_internal.h` — remove feed task types, params, handler declarations
- `src/api/dna_engine.c` — remove feed dispatch cases, cleanup cases, `feed_cache_init()`
- `src/api/engine/dna_engine_identity.c` — remove feed subscription init and auto-subscribe
- `src/api/engine/dna_engine_listeners.c` — remove feed listener code
- `dna_messenger_flutter/lib/ffi/dna_engine.dart` — remove feed FFI methods, FeedTopic/FeedComment/FeedSubscription/FeedCategories classes
- `dna_messenger_flutter/lib/providers/providers.dart` — remove feed_provider export
- `dna_messenger_flutter/lib/providers/event_handler.dart` — remove feed event handling

**IMPORTANT:** Do this deletion carefully. Build + flutter analyze after each major deletion step.

**Step 1: Delete C feed files**

```bash
rm dht/client/dna_feed.h dht/client/dna_feed_topic.c dht/client/dna_feed_comments.c dht/client/dna_feed_index.c
rm dht/shared/dht_feed_subscriptions.h dht/shared/dht_feed_subscriptions.c
rm database/feed_cache.h database/feed_cache.c
rm database/feed_subscriptions_db.h database/feed_subscriptions_db.c
rm src/api/engine/dna_engine_feed.c
```

**Step 2: Remove from CMakeLists.txt and dht/CMakeLists.txt**

**Step 3: Remove feed references from dna_engine.h, dna_engine_internal.h, dna_engine.c**

Remove all feed structs, task types, dispatch cases, cleanup cases, callback types, events, and function declarations. Remove `feed_cache_init()` and `feed_cache_close()` calls.

**Step 4: Remove feed references from dna_engine_identity.c**

Remove `feed_subscriptions_db_init()`, `feed_subscriptions_db_subscribe(DNA_UPDATES_TOPIC_UUID)`.

**Step 5: Remove feed listener code from dna_engine_listeners.c**

**Step 6: Build C library**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```

**Step 7: Delete Flutter feed files**

```bash
rm dna_messenger_flutter/lib/screens/feed/feed_screen.dart
rm dna_messenger_flutter/lib/providers/feed_provider.dart
```

**Step 8: Remove feed references from Flutter files**

- `dna_engine.dart`: Remove FeedTopic, FeedComment, FeedSubscription, FeedCategories classes and all feed FFI methods
- `providers.dart`: Remove `export 'feed_provider.dart'`
- `event_handler.dart`: Remove FeedTopicCommentEvent, FeedSubscriptionsSyncedEvent, FeedCacheUpdatedEvent handling

**Step 9: Verify Flutter**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter analyze
```

**Step 10: Commit**

```bash
git add -A
git commit -m "refactor(channels): remove old feed system code (replaced by channels)"
```

---

## Task 21: Documentation Updates

Update documentation to reflect the feed → channels change.

**Files:**
- Modify: `docs/FLUTTER_UI.md`
- Modify: `docs/functions/public-api.md`
- Modify: `docs/functions/engine.md`
- Modify: `docs/functions/dht.md`
- Modify: `docs/functions/database.md`

**Step 1: Update each doc file**

- Remove feed API references, add channel API references
- Update screen descriptions (Feed Screen → Channel List Screen)
- Update function reference tables

**Step 2: Commit**

```bash
git add docs/
git commit -m "docs: update documentation for feed → channels migration"
```

---

## Task 22: Build Verification and Version Bump

Full build verification and version bump for both C library and Flutter.

**Step 1: Full C build**

```bash
cd /opt/dna-messenger/build && cmake .. && make -j$(nproc)
```
Fix any warnings/errors.

**Step 2: Flutter analyze**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter analyze
```
Fix any issues.

**Step 3: Flutter build**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux
```
Fix any build failures.

**Step 4: Bump versions**

Both C library and Flutter versions need bumping since both changed.

- `include/dna/version.h`: Bump C library PATCH version
- `dna_messenger_flutter/pubspec.yaml`: Bump Flutter PATCH version + versionCode

**Step 5: Final commit**

```bash
git add include/dna/version.h dna_messenger_flutter/pubspec.yaml
git commit -m "feat: RSS-like channel system (vX.Y.Z / vX.Y.Z)"
```

---

## Execution Order Summary

| Task | Component | Description | Dependencies |
|------|-----------|-------------|--------------|
| 1 | C/Database | Channel subscriptions DB | None |
| 2 | C/Database | Channel cache DB | None |
| 3 | C/DHT | DHT channel operations | None |
| 4 | C/DHT | DHT subscription sync | None |
| 5 | C/API | Public API declarations | None |
| 6 | C/Engine | Internal types & handlers | 5 |
| 7 | C/Engine | Channel module implementation | 1, 2, 3, 4, 5, 6 |
| 8 | C/Engine | Dispatch & cleanup wiring | 6, 7 |
| 9 | C/Engine | Channel listeners | 3, 8 |
| 10 | C/Engine | Identity auto-subscribe | 1, 7 |
| 11 | Flutter | Dart models | None (parallel with C work) |
| 12 | Flutter | FFI bindings | 5, 11 |
| 13 | Flutter | Riverpod providers | 12 |
| 14 | Flutter | Event handler | 13 |
| 15 | Flutter | Channel list screen | 13 |
| 16 | Flutter | Channel detail screen | 13 |
| 17 | Flutter | Create channel screen | 13 |
| 18 | Flutter | Discover channels screen | 13 |
| 19 | Flutter | Navigation integration | 15 |
| 20 | Cleanup | Delete old feed code | 1-19 |
| 21 | Docs | Documentation updates | 20 |
| 22 | Build | Verification & version bump | 21 |

**Parallelizable groups:**
- Tasks 1-4 (all C foundation layers) can run in parallel
- Tasks 11-12 can start as soon as Task 5 is done
- Tasks 15-18 (all Flutter screens) can run in parallel after Task 13
