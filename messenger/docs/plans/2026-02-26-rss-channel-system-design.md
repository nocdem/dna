# RSS-Like Channel System Design

**Date:** 2026-02-26
**Status:** Approved
**Approach:** Clean Rewrite (Approach B)

---

## Overview

Replace the current forum-style feed system (Topics + threaded Comments + Categories) with an RSS-like **Channel** system. Channels are named content streams that any user can create. Subscribers see a flat chronological post stream. Wall handles personal/social content; Channels handle topic-based content.

**Key Decisions:**
- Channel model (not user-as-feed)
- Text-only posts, flat stream (no comments/threading)
- Open posting — anyone can post to any channel
- 7 default channels replace 6 old categories + new "Cpunk" channel
- Public DHT index (opt-in) + direct link sharing for discovery
- Channel list as landing screen with unread indicators
- No moderation in v1
- No external RSS import (deferred)
- Clean break — old feed data expires via 30-day DHT TTL

---

## Data Model

### Channel (`dna_channel_info_t`)
```c
typedef struct {
    char uuid[37];                  // UUID v4, generated on creation
    char name[101];                 // Channel name (max 100 chars)
    char *description;              // Optional description (max 500 chars, heap-allocated)
    char creator_fingerprint[129];  // Creator's SHA3-512 fingerprint
    uint64_t created_at;            // Unix timestamp
    bool is_public;                 // Listed on public DHT index (default: true)
    bool deleted;                   // Soft delete flag
    uint64_t deleted_at;            // Deletion timestamp (0 if not deleted)
    bool verified;                  // Dilithium5 signature verified
} dna_channel_info_t;
```

### Post (`dna_channel_post_t`)
```c
typedef struct {
    char post_uuid[37];             // UUID v4
    char channel_uuid[37];          // Parent channel UUID
    char author_fingerprint[129];   // Author's SHA3-512 fingerprint
    char *body;                     // Text content (max 4000 chars, heap-allocated)
    uint64_t created_at;            // Unix timestamp
    bool verified;                  // Dilithium5 signature verified
} dna_channel_post_t;
```

### Subscription (`dna_channel_subscription_t`)
```c
typedef struct {
    char channel_uuid[37];          // Subscribed channel UUID
    uint64_t subscribed_at;         // When subscribed
    uint64_t last_synced;           // Last DHT sync timestamp
    uint64_t last_read_at;          // For unread tracking
} dna_channel_subscription_t;
```

---

## DHT Storage

**Namespace:** `dna:channels:` (completely separate from old `dna:feeds:`)

| Data | DHT Key | Owner Model | TTL |
|------|---------|-------------|-----|
| Channel metadata | `SHA256("dna:channels:meta:" + uuid)` | Single-owner (creator) | 30 days |
| Channel posts | `SHA256("dna:channels:posts:" + uuid)` | Multi-owner (anyone) | 30 days |
| Public index (daily) | `SHA256("dna:channels:idx:" + YYYYMMDD)` | Multi-owner (anyone) | 30 days |
| Subscriptions | `SHA3-512("dna:channels:subs:" + fingerprint)` | Single-owner | 30 days |

### Operations

1. **Create channel:** Publish metadata to `dna:channels:meta:<uuid>` (signed, single-owner)
2. **List on index:** If `is_public`, publish reference to `dna:channels:idx:YYYYMMDD`
3. **Post to channel:** Publish to `dna:channels:posts:<uuid>` (signed, multi-owner)
4. **Read channel:** Fetch all values from `dna:channels:posts:<uuid>`, sort by timestamp
5. **Subscribe:** Store in local SQLite + sync to DHT
6. **Discover:** Browse daily index buckets to find public channels

### Default Channels (7, hardcoded deterministic UUIDs)

| Channel | UUID Derivation |
|---------|----------------|
| General | `SHA256("dna:default:general")` → UUID format |
| Technology | `SHA256("dna:default:technology")` → UUID format |
| Help | `SHA256("dna:default:help")` → UUID format |
| Announcements | `SHA256("dna:default:announcements")` → UUID format |
| Trading | `SHA256("dna:default:trading")` → UUID format |
| Off Topic | `SHA256("dna:default:offtopic")` → UUID format |
| Cpunk | `SHA256("dna:default:cpunk")` → UUID format |

Auto-subscribed on first identity creation. Created on DHT by first user to post.

---

## C Library API

### New Module: `src/api/engine/dna_engine_channels.c`

#### Channel Operations
```c
dna_request_id_t dna_engine_channel_create(dna_engine_t *engine, const char *name,
    const char *description, bool is_public, dna_callback_t cb, void *user_data);

dna_request_id_t dna_engine_channel_get(dna_engine_t *engine, const char *uuid,
    dna_callback_t cb, void *user_data);

dna_request_id_t dna_engine_channel_delete(dna_engine_t *engine, const char *uuid,
    dna_callback_t cb, void *user_data);

dna_request_id_t dna_engine_channel_discover(dna_engine_t *engine, int days_back,
    dna_callback_t cb, void *user_data);
```

#### Post Operations
```c
dna_request_id_t dna_engine_channel_post(dna_engine_t *engine, const char *channel_uuid,
    const char *body, dna_callback_t cb, void *user_data);

dna_request_id_t dna_engine_channel_get_posts(dna_engine_t *engine, const char *channel_uuid,
    dna_callback_t cb, void *user_data);
```

#### Subscription Operations
```c
int  dna_engine_channel_subscribe(dna_engine_t *engine, const char *channel_uuid);
int  dna_engine_channel_unsubscribe(dna_engine_t *engine, const char *channel_uuid);
bool dna_engine_channel_is_subscribed(dna_engine_t *engine, const char *channel_uuid);
int  dna_engine_channel_mark_read(dna_engine_t *engine, const char *channel_uuid);

dna_request_id_t dna_engine_channel_get_subscriptions(dna_engine_t *engine,
    dna_callback_t cb, void *user_data);

dna_request_id_t dna_engine_channel_sync_subs_to_dht(dna_engine_t *engine,
    dna_callback_t cb, void *user_data);

dna_request_id_t dna_engine_channel_sync_subs_from_dht(dna_engine_t *engine,
    dna_callback_t cb, void *user_data);
```

#### Events
```c
DNA_EVENT_CHANNEL_NEW_POST       // Real-time: new post in subscribed channel
DNA_EVENT_CHANNEL_SUBS_SYNCED    // Subscriptions synced from DHT
```

---

## Flutter UI

### Screen Flow
```
Channel List Screen (landing)
  ├── [+] → Create Channel Screen
  ├── [🔍] → Discover Channels Screen
  ├── Tap channel → Channel Detail Screen (post stream)
  │     ├── Post input at bottom
  │     └── Scrollable post list (newest first)
  └── Long-press channel → Unsubscribe option
```

### Channel List Screen (Landing)
- Shows subscribed channels only
- Each item: channel name, description snippet, unread indicator (dot + count)
- Pull-to-refresh fetches updated post counts
- [+] button to create channel
- [🔍] button to discover channels

### Channel Detail Screen (Post Stream)
- Header: channel name + unsubscribe button
- Flat chronological post list (newest first)
- Each post: author name, relative timestamp, body text
- Post input at bottom with send button
- Auto-marks channel as read when opened

### Create Channel Screen
- Name input (required, max 100 chars)
- Description input (optional, max 500 chars)
- "List publicly" checkbox (default: on)
- Create button

### Discover Channels Screen
- Browses public DHT index (daily buckets)
- Search/filter by name (client-side)
- Each item: name, description, creator, post count, subscribe button

### Riverpod Providers
```dart
// Async notifiers
channelListProvider             // AsyncNotifier<List<Channel>>
channelPostsProvider(uuid)      // AsyncNotifier<List<ChannelPost>> (family)
channelSubscriptionsProvider    // AsyncNotifier<List<ChannelSubscription>>
discoverChannelsProvider        // AsyncNotifier<List<Channel>>

// Simple state
selectedChannelProvider         // StateProvider<String?> (uuid)
unreadCountProvider(uuid)       // Provider<int> (family)
```

### New Files
```
lib/screens/channels/channel_list_screen.dart
lib/screens/channels/channel_detail_screen.dart
lib/screens/channels/create_channel_screen.dart
lib/screens/channels/discover_channels_screen.dart
lib/providers/channel_provider.dart
lib/models/channel.dart
```

---

## Files Affected

### C Library — Delete
| File | Reason |
|------|--------|
| `dht/client/dna_feed.h` / `.c` | Old feed DHT operations |
| `database/feed_cache.h` / `.c` | Old feed cache |
| `database/feed_subscriptions_db.h` / `.c` | Old feed subscriptions DB |
| `dht/shared/dht_feed_subscriptions.h` / `.c` | Old DHT subscription sync |
| `src/api/engine/dna_engine_feed.c` | Old feed engine module |

### C Library — Modify
| File | Change |
|------|--------|
| `include/dna/dna_engine.h` | Remove feed structs/functions, add channel API |
| `src/api/engine/dna_engine.c` | Remove feed dispatch, add channel dispatch |
| `src/api/engine/dna_engine_internal.h` | Remove feed task types, add channel types |
| `src/api/engine/dna_engine_listeners.c` | Replace feed listeners with channel listeners |

### C Library — Create
| File | Purpose |
|------|---------|
| `src/api/engine/dna_engine_channels.c` | Channel engine module |
| `dht/client/dna_channels.h` / `.c` | Channel DHT operations |
| `database/channel_cache.h` / `.c` | Channel local cache |
| `database/channel_subscriptions_db.h` / `.c` | Channel subscriptions DB |
| `dht/shared/dht_channel_subscriptions.h` / `.c` | DHT subscription sync |

### Flutter — Delete
| File | Reason |
|------|--------|
| `lib/screens/feed/feed_screen.dart` | Old feed UI |
| `lib/providers/feed_provider.dart` | Old feed providers |

### Flutter — Modify
| File | Change |
|------|--------|
| `lib/ffi/dna_engine.dart` | Remove feed FFI, add channel FFI |
| `lib/services/event_handler.dart` | Replace feed events with channel events |
| Navigation widget | Rename "Feeds" → "Channels" |

### Flutter — Create
| File | Purpose |
|------|---------|
| `lib/screens/channels/channel_list_screen.dart` | Channel list landing |
| `lib/screens/channels/channel_detail_screen.dart` | Post stream |
| `lib/screens/channels/create_channel_screen.dart` | Channel creation |
| `lib/screens/channels/discover_channels_screen.dart` | Public browser |
| `lib/providers/channel_provider.dart` | Channel providers |
| `lib/models/channel.dart` | Dart models |

---

## Migration Strategy

**Clean break.** No data migration.

- Old feed DHT data expires naturally (30-day TTL)
- Old feed cache DB can be deleted on upgrade
- New channel system starts fresh
- 7 default channels auto-created and auto-subscribed
- DNA Updates feed (UUID `765ed03d...`) transitions to use the Announcements default channel

---

## Out of Scope (Future)

- External RSS/Atom feed import
- Channel moderation (owner delete posts, moderator roles)
- Rich posts (images, links, media)
- Channel avatars/icons
- Reactions/voting on posts
- Full-text search
- Post editing/deletion
