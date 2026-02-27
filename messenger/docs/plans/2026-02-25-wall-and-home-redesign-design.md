# Wall Feature & Home Screen Redesign - Design Document

**Date:** 2026-02-25
**Status:** Draft
**Scope:** C Library + Engine API + Flutter UI

---

## 1. Overview

Add a personal Wall (duvar) system where users post text to their own wall, and contacts see these posts in a unified Home timeline. Redesign the app navigation from the current 4-tab layout to a new structure with Home as the default screen.

### Goals
- Personal wall posts visible to contacts (auto-follow via contact list)
- Home timeline aggregating wall posts from all contacts
- Unified Messages tab combining P2P chats and group chats
- Clean 4-tab navigation: Home | Messages | Feeds | More

### Non-Goals (MVP)
- No likes/voting on wall posts
- No comments/replies on wall posts
- No image/media attachments
- No independent follow system (contacts = auto-follow)
- No wall post editing (only create + delete)

---

## 2. Architecture

### 2.1 DHT Storage Model

Each user's wall posts are stored under a per-user DHT key:

```
DHT Key = SHA3-512("dna:wall:<fingerprint>")
```

- **Storage:** Chunked DHT storage (existing `dht_chunked` layer)
- **TTL:** 30 days (standard DHT expiry)
- **Max posts:** 50 per user (oldest rotated out)
- **Signature:** Each post signed with Dilithium5 (NIST Category 5)
- **Verification:** Recipients verify signature against author's public key from keyserver

### 2.2 Data Flow

```
Posting:
  User writes post
    -> Flutter FFI -> Engine task queue -> DHT put(wall_key, posts_json)
    -> Post stored in local SQLite cache
    -> DHT distributes to network

Reading (Timeline):
  App startup / refresh
    -> For each contact: DHT get(SHA3("dna:wall:<contact_fp>"))
    -> Verify signatures
    -> Merge all posts, sort by timestamp desc
    -> Cache in local SQLite
    -> Display in Home timeline

Real-time updates:
  Engine starts DHT listen on each contact's wall key
    -> New post event -> DNA_EVENT_WALL_NEW_POST
    -> Flutter event handler -> Update timeline provider
```

### 2.3 Follow Mechanism

No separate follow system. Contact relationship = auto-follow:

```
Contact added (existing flow):
  A sends contact request -> B accepts
  -> Both are now contacts
  -> Engine automatically:
     1. Starts DHT listen on other's wall key
     2. Fetches initial wall posts
     3. Adds to timeline

Contact removed:
  -> Engine stops DHT listen on that wall key
  -> Removes their posts from local cache
```

---

## 3. C Library Changes

### 3.1 Remove Old Wall Code

**Delete these files:**
- `dht/client/dna_message_wall.h` (212 lines)
- `dht/client/dna_message_wall.c` (814 lines)
- `dht/client/dna_wall_votes.h` (137 lines)
- `dht/client/dna_wall_votes.c` (483 lines)

**Update:**
- `dht/CMakeLists.txt` - Remove old wall source files
- `docs/functions/dht.md` - Remove old wall function docs (sections 11.7-11.8)

### 3.2 New Wall Module (DHT Client Layer)

**New files:**
- `dht/client/dna_wall.h`
- `dht/client/dna_wall.c`

**Data Structure (simplified from old):**

```c
#define DNA_WALL_MAX_TEXT_LEN    2048
#define DNA_WALL_MAX_POSTS       50
#define DNA_WALL_TTL_DAYS        30

typedef struct {
    char uuid[37];                  // UUID v4
    char author_fingerprint[129];   // SHA3-512 hex
    char text[DNA_WALL_MAX_TEXT_LEN];
    uint64_t timestamp;             // Unix epoch seconds
    uint8_t signature[4627];        // Dilithium5 signature
    size_t signature_len;
} dna_wall_post_t;

typedef struct {
    char owner_fingerprint[129];
    dna_wall_post_t *posts;
    size_t post_count;
} dna_wall_t;
```

**Functions:**

| Function | Description |
|----------|-------------|
| `dna_wall_post(dht, identity, text)` | Create and publish a wall post |
| `dna_wall_delete(dht, identity, post_uuid)` | Delete own wall post |
| `dna_wall_load(dht, fingerprint)` | Load a user's wall from DHT |
| `dna_wall_free(wall)` | Free wall structure |
| `dna_wall_post_verify(post)` | Verify post signature |
| `dna_wall_to_json(wall) / from_json(json)` | Serialization |

**DHT Key derivation:**
```c
// Wall posts key
void dna_wall_make_key(const char *fingerprint, uint8_t *out_key) {
    char input[256];
    snprintf(input, sizeof(input), "dna:wall:%s", fingerprint);
    sha3_512((uint8_t *)input, strlen(input), out_key);
}
```

**Signature covers:** `uuid + text + timestamp` (network byte order for timestamp)

### 3.3 Engine Module

**New file:** `src/api/engine/dna_engine_wall.c`

**New task types** (add to `dna_engine_internal.h` enum):
```c
TASK_WALL_POST,          // Create a wall post
TASK_WALL_DELETE,         // Delete own wall post
TASK_WALL_LOAD,           // Load one user's wall
TASK_WALL_TIMELINE,       // Load all contacts' walls (merged timeline)
```

**New task params** (add to union in `dna_engine_internal.h`):
```c
struct {
    char *text;             // Heap allocated, task owns
} wall_post;

struct {
    char uuid[37];          // Post UUID to delete
} wall_delete;

struct {
    char fingerprint[129];  // Whose wall to load
} wall_load;

// wall_timeline has no params (uses engine->contacts)
```

### 3.4 Public API

**New in `include/dna/dna_engine.h`:**

```c
/* ── Wall ── */

typedef struct {
    char uuid[37];
    char author_fingerprint[129];
    char author_name[65];           // Resolved display name
    char text[2048];
    uint64_t timestamp;
} dna_wall_post_info_t;

/* Callbacks */
typedef void (*dna_wall_post_cb)(
    dna_request_id_t request_id, int error,
    dna_wall_post_info_t *post, void *user_data);

typedef void (*dna_wall_posts_cb)(
    dna_request_id_t request_id, int error,
    dna_wall_post_info_t *posts, int count, void *user_data);

/* API Functions */
dna_request_id_t dna_engine_wall_post(
    dna_engine_t *engine, const char *text,
    dna_wall_post_cb cb, void *user_data);

dna_request_id_t dna_engine_wall_delete(
    dna_engine_t *engine, const char *post_uuid,
    dna_status_cb cb, void *user_data);

dna_request_id_t dna_engine_wall_load(
    dna_engine_t *engine, const char *fingerprint,
    dna_wall_posts_cb cb, void *user_data);

dna_request_id_t dna_engine_wall_timeline(
    dna_engine_t *engine,
    dna_wall_posts_cb cb, void *user_data);

void dna_free_wall_posts(dna_wall_post_info_t *posts, int count);
```

**New event type:**
```c
DNA_EVENT_WALL_NEW_POST  // New wall post from a contact
```

**Event data (add to union):**
```c
struct {
    char author_fingerprint[129];
    char post_uuid[37];
} wall_new_post;
```

### 3.5 Local Cache (SQLite)

**New table** in contacts database (or separate wall.db):

```sql
CREATE TABLE IF NOT EXISTS wall_posts (
    uuid TEXT PRIMARY KEY,
    author_fingerprint TEXT NOT NULL,
    text TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    signature BLOB,
    cached_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX idx_wall_posts_author ON wall_posts(author_fingerprint);
CREATE INDEX idx_wall_posts_timestamp ON wall_posts(timestamp DESC);
```

**Cache behavior:**
- On wall load: store/update posts in SQLite
- Timeline query: SELECT from cache, sorted by timestamp DESC
- Stale check: re-fetch from DHT if cached_at > 5 minutes
- Cleanup: Remove posts older than 30 days

---

## 4. Flutter UI Changes

### 4.1 Navigation Restructure

**Old (4 tabs):**
```
Chats(0) | Groups(1) | Feed(2) | More(3)
```

**New (4 tabs):**
```
Home(0) | Messages(1) | Feeds(2) | More(3)
```

**Changes to `home_screen.dart`:**

```dart
// Old
final currentTabProvider = StateProvider<int>((ref) => 0);
// Index 0: ContactsScreen, 1: GroupsScreen, 2: FeedScreen, 3: MoreScreen

// New
final currentTabProvider = StateProvider<int>((ref) => 0);
// Index 0: WallTimelineScreen, 1: MessagesScreen, 2: FeedScreen, 3: MoreScreen
```

**Bottom bar items:**
```dart
DnaBottomBarItem(
  icon: FontAwesomeIcons.house,
  activeIcon: FontAwesomeIcons.house,
  label: 'Home',
),
DnaBottomBarItem(
  icon: FontAwesomeIcons.comment,
  activeIcon: FontAwesomeIcons.solidComment,
  label: 'Messages',
  badgeCount: totalUnreadCount,  // P2P + Group combined
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
```

### 4.2 New Screen: WallTimelineScreen (Home Tab)

**File:** `lib/screens/wall_timeline_screen.dart`

**Layout:**
```
┌──────────────────────────────┐
│  Home                    [+] │  <- AppBar with "New Post" button
│──────────────────────────────│
│  ┌────────────────────────┐  │
│  │ 👤 Nox · 5m ago        │  │  <- Author avatar + name + time
│  │ "Yeni özellik geldi!"  │  │  <- Post text
│  └────────────────────────┘  │
│  ┌────────────────────────┐  │
│  │ 👤 Mika · 2h ago       │  │
│  │ "Bug fix tamamlandı"   │  │
│  └────────────────────────┘  │
│  ┌────────────────────────┐  │
│  │ 👤 You · 1d ago        │  │  <- Own posts also visible
│  │ "Merhaba dünya!"    🗑  │  │  <- Delete button on own posts
│  └────────────────────────┘  │
└──────────────────────────────┘
```

**Features:**
- Pull-to-refresh (triggers DHT re-fetch)
- FAB or AppBar button to create new post
- Post creation: simple text dialog (like feed topic creation)
- Own posts show delete icon
- Tap on author name/avatar -> navigate to profile (future: personal wall view)
- Empty state: "No posts yet. Add contacts to see their wall posts!"

### 4.3 New Screen: MessagesScreen (Messages Tab)

**File:** `lib/screens/messages_screen.dart`

**Layout:**
```
┌──────────────────────────────┐
│  Messages              [🔍]  │  <- AppBar with search
│  ┌──────────────────────────┐│
│  │ [All] [Chats] [Groups]  ││  <- Filter chips/tabs
│  └──────────────────────────┘│
│──────────────────────────────│
│  👤 Nox         "hey!"  12:30│  <- P2P chat
│  👥 Dev Team   "merged" 12:15│  <- Group chat (different icon)
│  👤 Mika       "ok"     11:45│  <- P2P chat
│  👥 General    "hi all" 10:00│  <- Group chat
│  ─────────────────────────────│
│  + Add Contact  |  + New Group│  <- Quick actions at bottom
└──────────────────────────────┘
```

**Features:**
- [All] tab: P2P + Groups merged, sorted by last message time
- [Chats] tab: Only P2P conversations (existing ContactsScreen content)
- [Groups] tab: Only group conversations (existing GroupsScreen content)
- Unified unread badge count (P2P + Groups)
- Each item shows: avatar, name, last message preview, time, unread badge
- Group items distinguished by group icon (FontAwesomeIcons.userGroup)
- Tapping navigates to ChatScreen or GroupChatScreen respectively

### 4.4 New Provider: wall_provider.dart

**File:** `lib/providers/wall_provider.dart`

```dart
/// Wall timeline provider - all contacts' posts merged
final wallTimelineProvider = AsyncNotifierProvider<WallTimelineNotifier, List<WallPost>>(
  WallTimelineNotifier.new,
);

/// Single user's wall provider (for profile view, future)
final wallProvider = AsyncNotifierProvider.family<WallNotifier, List<WallPost>, String>(
  WallNotifier.new,
);
```

**WallPost model:**
```dart
class WallPost {
  final String uuid;
  final String authorFingerprint;
  final String authorName;
  final String text;
  final DateTime timestamp;
  final bool isOwn;  // Computed: authorFp == myFp
}
```

### 4.5 FFI Bindings

**Add to `lib/ffi/dna_engine.dart`:**

```dart
// Wall API
Future<WallPost> wallPost(String text) async { ... }
Future<void> wallDelete(String postUuid) async { ... }
Future<List<WallPost>> wallLoad(String fingerprint) async { ... }
Future<List<WallPost>> wallTimeline() async { ... }
```

**Pattern:** Follow existing `feedCreateTopic()` / `feedGetAll()` FFI pattern.

### 4.6 Event Handling

**Add to `lib/providers/event_handler.dart`:**

```dart
case DnaEventType.wallNewPost:
  // Invalidate wall timeline to trigger refresh
  ref.invalidate(wallTimelineProvider);
  break;
```

---

## 5. Migration & Compatibility

### 5.1 No Breaking Changes

- Old wall C code is removed but was never exposed to Flutter/users
- No database migration needed (new table, not modifying existing)
- Navigation change is purely UI - no data format changes
- Existing contacts, messages, groups, feeds are untouched

### 5.2 Empty State Handling

- First launch after update: Home timeline is empty
- Prompt: "Post something to your wall!" with create button
- Timeline populates as contacts post

---

## 6. Implementation Order

1. **Phase A: Remove old C wall code** (cleanup)
2. **Phase B: New C wall module** (`dht/client/dna_wall.h/.c`)
3. **Phase C: Engine module** (`src/api/engine/dna_engine_wall.c`)
4. **Phase D: Public API** (`include/dna/dna_engine.h` additions)
5. **Phase E: SQLite cache** (wall_posts table)
6. **Phase F: Build verification** (C library compiles clean)
7. **Phase G: Flutter FFI bindings** (wall functions in engine.dart)
8. **Phase H: Wall provider** (wall_provider.dart)
9. **Phase I: Navigation restructure** (Home | Messages | Feeds | More)
10. **Phase J: WallTimelineScreen** (Home tab)
11. **Phase K: MessagesScreen** (unified messages tab)
12. **Phase L: Flutter build verification**

---

## 7. File Change Summary

### New Files
| File | Purpose |
|------|---------|
| `dht/client/dna_wall.h` | Wall DHT client header |
| `dht/client/dna_wall.c` | Wall DHT client implementation |
| `src/api/engine/dna_engine_wall.c` | Engine wall module |
| `lib/screens/wall_timeline_screen.dart` | Home timeline screen |
| `lib/screens/messages_screen.dart` | Unified messages screen |
| `lib/providers/wall_provider.dart` | Wall state management |
| `lib/widgets/wall_post_tile.dart` | Wall post widget |

### Modified Files
| File | Changes |
|------|---------|
| `include/dna/dna_engine.h` | Add wall types, callbacks, API functions, event |
| `src/api/dna_engine_internal.h` | Add TASK_WALL_* types, params, handler declarations |
| `src/api/engine/dna_engine.c` | Add wall task dispatch cases |
| `dht/CMakeLists.txt` | Replace old wall files with new |
| `lib/screens/home_screen.dart` | New tab layout, IndexedStack changes |
| `lib/design_system/navigation/dna_bottom_bar.dart` | (if needed) |
| `lib/ffi/dna_engine.dart` | Add wall FFI bindings + WallPost model |
| `lib/providers/event_handler.dart` | Handle wall events |
| `lib/providers/providers.dart` | Export wall provider |

### Deleted Files
| File | Reason |
|------|--------|
| `dht/client/dna_message_wall.h` | Replaced by simpler dna_wall.h |
| `dht/client/dna_message_wall.c` | Replaced by simpler dna_wall.c |
| `dht/client/dna_wall_votes.h` | MVP has no voting |
| `dht/client/dna_wall_votes.c` | MVP has no voting |

### Documentation Updates
| File | Changes |
|------|---------|
| `docs/functions/dht.md` | Replace wall sections 11.7-11.8 |
| `docs/functions/public-api.md` | Add wall API functions |
| `docs/functions/engine.md` | Add wall engine module |
| `docs/FLUTTER_UI.md` | Update navigation, add wall screens |
