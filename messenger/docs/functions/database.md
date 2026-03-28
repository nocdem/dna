# Database Functions

**Directory:** `database/`

Local SQLite databases for contacts, caching, and profiles.

---

## 13.1 Contacts Database (`contacts_db.h`)

### Core Operations

| Function | Description |
|----------|-------------|
| `int contacts_db_init(const char*)` | Initialize contacts database for identity |
| `int contacts_db_add(const char*, const char*)` | Add contact to database |
| `int contacts_db_remove(const char*)` | Remove contact from database |
| `int contacts_db_update_notes(const char*, const char*)` | Update contact notes |
| `bool contacts_db_exists(const char*)` | Check if contact exists |
| `int contacts_db_list(contact_list_t**)` | Get all contacts |
| `int contacts_db_count(void)` | Get contact count |
| `int contacts_db_clear_all(void)` | Clear all contacts |
| `void contacts_db_free_list(contact_list_t*)` | Free contact list |
| `void contacts_db_close(void)` | Close database |
| `int contacts_db_migrate_from_global(const char*)` | Migrate from global database |

### Contact Requests

| Function | Description |
|----------|-------------|
| `int contacts_db_add_incoming_request(const char*, const char*, const char*, uint64_t)` | Add incoming contact request |
| `int contacts_db_get_incoming_requests(incoming_request_t**, int*)` | Get pending requests |
| `int contacts_db_pending_request_count(void)` | Get pending request count |
| `int contacts_db_approve_request(const char*)` | Approve contact request |
| `int contacts_db_deny_request(const char*)` | Deny contact request |
| `int contacts_db_remove_request(const char*)` | Remove contact request |
| `bool contacts_db_request_exists(const char*)` | Check if request exists |
| `void contacts_db_free_requests(incoming_request_t*, int)` | Free requests array |
| `int contacts_db_update_request_name(const char*, const char*)` | Update display name for request |
| `int contacts_db_cleanup_old_denied(void)` | Remove denied requests older than 7 days (returns count deleted) |
| `int contacts_db_update_last_seen(const char*, uint64_t)` | Update last_seen timestamp for contact |
| `int contacts_db_update_nickname(const char*, const char*)` | Update local nickname for contact |

### Blocked Users

| Function | Description |
|----------|-------------|
| `int contacts_db_block_user(const char*, const char*)` | Block a user |
| `int contacts_db_unblock_user(const char*)` | Unblock a user |
| `bool contacts_db_is_blocked(const char*)` | Check if user is blocked |
| `int contacts_db_get_blocked_users(blocked_user_t**, int*)` | Get blocked users |
| `int contacts_db_blocked_count(void)` | Get blocked count |
| `void contacts_db_free_blocked(blocked_user_t*, int)` | Free blocked array |

---

## 13.2 Profile Manager (`profile_manager.h`)

| Function | Description |
|----------|-------------|
| `int profile_manager_init(void)` | Initialize profile manager |
| `int profile_manager_get_profile(const char*, dna_unified_identity_t**)` | Get profile (cache + DHT) |
| `int profile_manager_refresh_profile(const char*, dna_unified_identity_t**)` | Force refresh from DHT |
| `int profile_manager_refresh_all_expired(void)` | Refresh expired profiles (async) |
| `bool profile_manager_is_cached_and_fresh(const char*)` | Check if cached and fresh |
| `int profile_manager_delete_cached(const char*)` | Delete from cache |
| `int profile_manager_get_stats(int*, int*)` | Get cache statistics |
| `int profile_manager_prefetch_local_identities(const char*)` | Prefetch local identity profiles |
| `int dna_get_display_name(dht_context_t*, const char*, char**)` | Get display name for fingerprint |
| `void profile_manager_close(void)` | Close profile manager |

---

## 13.3 Profile Cache (`profile_cache.h`)

| Function | Description |
|----------|-------------|
| `int profile_cache_init(void)` | Initialize global profile cache |
| `int profile_cache_add_or_update(const char*, const dna_unified_identity_t*)` | Add/update cached profile |
| `int profile_cache_get(const char*, dna_unified_identity_t**, uint64_t*)` | Get cached profile |
| `bool profile_cache_exists(const char*)` | Check if profile cached |
| `bool profile_cache_is_expired(const char*)` | Check if profile expired |
| `int profile_cache_delete(const char*)` | Delete cached profile |
| `int profile_cache_list_expired(char***, size_t*)` | List expired profiles |
| `int profile_cache_list_all(profile_cache_list_t**)` | List all cached profiles |
| `int profile_cache_count(void)` | Get cached profile count |
| `int profile_cache_clear_all(void)` | Clear all cached profiles |
| `void profile_cache_free_list(profile_cache_list_t*)` | Free profile list |
| `void profile_cache_close(void)` | Close profile cache |

---

## 13.4 Keyserver Cache (`keyserver_cache.h`)

| Function | Description |
|----------|-------------|
| `int keyserver_cache_init(const char*)` | Initialize keyserver cache |
| `void keyserver_cache_cleanup(void)` | Cleanup keyserver cache |
| `int keyserver_cache_get(const char*, keyserver_cache_entry_t**)` | Get cached public key |
| `int keyserver_cache_put(const char*, const uint8_t*, size_t, const uint8_t*, size_t, uint64_t)` | Store public key |
| `int keyserver_cache_delete(const char*)` | Delete cached entry |
| `int keyserver_cache_expire_old(void)` | Clear expired entries |
| `bool keyserver_cache_exists(const char*)` | Check if entry exists |
| `int keyserver_cache_stats(int*, int*)` | Get cache statistics |
| `void keyserver_cache_free_entry(keyserver_cache_entry_t*)` | Free cache entry |
| `int keyserver_cache_get_name(const char*, char*, size_t)` | Get cached display name |
| `int keyserver_cache_put_name(const char*, const char*, uint64_t)` | Store display name |
| `int keyserver_cache_get_avatar(const char*, char**)` | Get cached avatar |
| `int keyserver_cache_put_avatar(const char*, const char*)` | Store avatar |

---

## 13.5 Presence Cache (`presence_cache.h`)

| Function | Description |
|----------|-------------|
| `int presence_cache_init(void)` | Initialize presence cache |
| `void presence_cache_update(const char*, bool, time_t)` | Update presence status |
| `bool presence_cache_get(const char*)` | Get online status |
| `time_t presence_cache_last_seen(const char*)` | Get last seen time |
| `void presence_cache_clear(void)` | Clear all entries |
| `void presence_cache_free(void)` | Cleanup presence cache |

---

## 13.6 Cache Manager (`cache_manager.h`)

| Function | Description |
|----------|-------------|
| `int cache_manager_init(const char*)` | Initialize all cache modules |
| `void cache_manager_cleanup(void)` | Cleanup all cache modules |
| `int cache_manager_evict_expired(void)` | Evict expired entries |
| `int cache_manager_stats(cache_manager_stats_t*)` | Get aggregated statistics |
| `void cache_manager_clear_all(void)` | Clear all caches |

---

## 13.7 Group Database (`messenger/group_database.h`)

**Added in v0.4.63** - Separate SQLite database for all group data.

| Function | Description |
|----------|-------------|
| `group_database_context_t* group_database_init(void)` | Initialize group database (singleton) |
| `group_database_context_t* group_database_get_instance(void)` | Get global group database instance |
| `void* group_database_get_db(group_database_context_t*)` | Get raw SQLite handle |
| `void group_database_close(group_database_context_t*)` | Close group database |
| `int group_database_get_stats(group_database_context_t*, int*, int*, int*)` | Get stats (groups, members, messages) |

**Database:** `~/.dna/db/groups.db`

**Tables:** groups, group_members, group_geks, pending_invitations, group_messages

---

## 13.8 Group Invitations (legacy) (`group_invitations.h`)

| Function | Description |
|----------|-------------|
| `int group_invitations_init(const char*)` | Initialize invitations database |
| `int group_invitations_store(const group_invitation_t*)` | Store new invitation |
| `int group_invitations_get_pending(group_invitation_t**, int*)` | Get pending invitations |
| `int group_invitations_get(const char*, group_invitation_t**)` | Get invitation by UUID |
| `int group_invitations_update_status(const char*, invitation_status_t)` | Update invitation status |
| `int group_invitations_delete(const char*)` | Delete invitation |
| `void group_invitations_free(group_invitation_t*, int)` | Free invitation array |
| `void group_invitations_cleanup(void)` | Cleanup database |

---

## 13.8 Bootstrap Cache (`dht/client/bootstrap_cache.h`)

SQLite cache for discovered bootstrap nodes, enabling decentralization.
*Note: Located in `dht/client/` as it's specifically for DHT bootstrap caching.*

| Function | Description |
|----------|-------------|
| `int bootstrap_cache_init(const char*)` | Initialize bootstrap cache (NULL = default path) |
| `void bootstrap_cache_cleanup(void)` | Cleanup bootstrap cache |
| `int bootstrap_cache_put(const char*, uint16_t, const char*, const char*, uint64_t)` | Store discovered bootstrap node |
| `int bootstrap_cache_get_best(size_t, bootstrap_cache_entry_t**, size_t*)` | Get top N nodes by reliability |
| `int bootstrap_cache_get_all(bootstrap_cache_entry_t**, size_t*)` | Get all cached nodes |
| `int bootstrap_cache_mark_connected(const char*, uint16_t)` | Mark node as successfully connected |
| `int bootstrap_cache_mark_failed(const char*, uint16_t)` | Increment failure counter |
| `int bootstrap_cache_expire(uint64_t)` | Remove nodes older than X seconds |
| `int bootstrap_cache_count(void)` | Get count of cached nodes |
| `bool bootstrap_cache_exists(const char*, uint16_t)` | Check if node exists in cache |
| `void bootstrap_cache_free_entries(bootstrap_cache_entry_t*)` | Free entry array |

---

## 13.9 Channel Cache (`database/channel_cache.h`)

Global SQLite cache for channel metadata and posts.

**Database:** `~/.dna/db/channel_cache.db`

**Tables:** channels, channel_posts

### Lifecycle

| Function | Description |
|----------|-------------|
| `int channel_cache_init(void)` | Initialize channel cache database |
| `void channel_cache_close(void)` | Close channel cache database |
| `int channel_cache_evict_expired(void)` | Evict expired entries |

### Channel Operations

| Function | Description |
|----------|-------------|
| `int channel_cache_store(const dna_channel_info_t*)` | Store/update channel info |
| `int channel_cache_get(const char*, dna_channel_info_t*)` | Get channel info by UUID |
| `int channel_cache_delete(const char*)` | Delete channel from cache |

### Post Operations

| Function | Description |
|----------|-------------|
| `int channel_cache_store_post(const dna_channel_post_info_t*)` | Store/update channel post |
| `int channel_cache_get_posts(const char*, int, int, dna_channel_post_info_t**, size_t*)` | Get posts for channel (paginated) |

---

## 13.9a Channel Subscriptions (`database/channel_subscriptions_db.h`)

Per-identity SQLite database for channel subscriptions.

### Lifecycle

| Function | Description |
|----------|-------------|
| `int channel_subscriptions_db_init(void)` | Initialize channel subscriptions database |
| `void channel_subscriptions_db_close(void)` | Close channel subscriptions database |

### Subscription Operations

| Function | Description |
|----------|-------------|
| `int channel_subscriptions_db_subscribe(const char*)` | Subscribe to a channel by UUID |
| `int channel_subscriptions_db_unsubscribe(const char*)` | Unsubscribe from a channel |
| `bool channel_subscriptions_db_is_subscribed(const char*)` | Check if subscribed to a channel |
| `int channel_subscriptions_db_get_all(dna_channel_subscription_info_t**, size_t*)` | Get all subscriptions |
| `int channel_subscriptions_db_mark_read(const char*)` | Mark a channel as read |

---

## 13.10 Wall Cache (`database/wall_cache.h`)

**Added in v0.7.0** - Global SQLite cache for wall posts and comments with stale-while-revalidate semantics.

**Database:** `~/.dna/wall_cache.db`

**Tables:** wall_posts, wall_cache_meta, wall_comments, wall_likes

**Constants:** `WALL_CACHE_TTL_SECONDS` (300), `WALL_CACHE_EVICT_SECONDS` (2592000)

### Lifecycle

| Function | Description |
|----------|-------------|
| `int wall_cache_init(void)` | Initialize wall cache database |
| `void wall_cache_close(void)` | Close wall cache database |
| `int wall_cache_evict_expired(void)` | Evict entries older than 30 days |

### Post Operations

| Function | Description |
|----------|-------------|
| `int wall_cache_store(const char*, const dna_wall_post_t*, size_t)` | Store wall posts for an author; includes `image_json` column (v0.7.0+) |
| `int wall_cache_load(const char*, dna_wall_post_t**, size_t*)` | Load cached wall posts for one author; populates `image_json` field (v0.7.0+) |
| `int wall_cache_load_timeline(const char**, size_t, dna_wall_post_t**, size_t*)` | Load merged timeline for multiple authors sorted by timestamp DESC (limit 200) |
| `int wall_cache_delete_by_author(const char*)` | Delete all cached posts for a specific author |
| `int wall_cache_delete_post(const char*)` | Delete a specific post by UUID |
| `int wall_cache_insert_post(const dna_wall_post_t*)` | INSERT OR REPLACE single post by uuid (v0.7.3+) |
| `void wall_cache_free_posts(dna_wall_post_t*, size_t)` | Free posts array returned by load functions |

### Comment Cache (v0.7.0+)

| Function | Description |
|----------|-------------|
| `int wall_cache_store_comments(const char*, const char*, int)` | Cache wall post comments as JSON blob with comment count |
| `int wall_cache_load_comments(const char*, char**, int*)` | Load cached wall post comments; returns heap-allocated JSON (caller frees) |
| `int wall_cache_invalidate_comments(const char*)` | Invalidate comment cache for a post by UUID |
| `bool wall_cache_is_stale_comments(const char*)` | Check if comment cache is stale for a post (5-min TTL) |

### Likes Cache (v0.9.53+)

| Function | Description |
|----------|-------------|
| `int wall_cache_store_likes(const char*, const char*, int)` | Cache wall post likes as JSON blob with like count |
| `int wall_cache_load_likes(const char*, char**, int*)` | Load cached wall post likes; returns heap-allocated JSON (caller frees) |
| `int wall_cache_invalidate_likes(const char*)` | Invalidate likes cache for a post by UUID |
| `bool wall_cache_is_stale_likes(const char*)` | Check if likes cache is stale for a post (5-min TTL) |

### Meta / Staleness

| Function | Description |
|----------|-------------|
| `int wall_cache_update_meta(const char*)` | Update last-fetched timestamp for a fingerprint cache key |
| `int wall_cache_delete_meta(const char*)` | Delete staleness metadata to force DHT re-fetch (v0.7.3+) |
| `bool wall_cache_is_stale(const char*)` | Check if post cache is stale for a fingerprint (>5 min) |
| `bool wall_cache_is_stale_wall_meta(const char*)` | Check if wall meta is stale for a fingerprint (v0.9.141+) |
| `int wall_cache_update_wall_meta(const char*)` | Mark wall meta as fresh (v0.9.141+) |
| `bool wall_cache_is_stale_day(const char*, const char*)` | Check if day bucket is stale (fp + date_str) (v0.9.141+) |
| `int wall_cache_update_meta_day(const char*, const char*)` | Mark day bucket as fresh (v0.9.141+) |
| `int wall_cache_store_wall_meta(const char*, const char*)` | Store DHT meta JSON blob locally (v0.9.141+) |
| `int wall_cache_load_wall_meta(const char*, char**)` | Load cached DHT meta JSON blob (v0.9.141+) |
| `uint64_t wall_cache_get_post_timestamp(const char*)` | Get post timestamp by UUID (for delete bucket routing) (v0.9.141+) |

---

## 13.11 Wallet Cache (`database/wallet_cache.h`)

**Added in v0.9.30** - Global SQLite cache for wallet balances and transaction history with stale-while-revalidate semantics.

**Database:** `~/.dna/wallet_cache.db`

**Tables:** wallet_balances, wallet_transactions

### Lifecycle

| Function | Description |
|----------|-------------|
| `int wallet_cache_init(void)` | Initialize wallet cache database |
| `void wallet_cache_close(void)` | Close wallet cache database |

### Balance Operations

| Function | Description |
|----------|-------------|
| `int wallet_cache_save_balances(int, const dna_balance_t*, int)` | Save balances to cache (upsert) |
| `int wallet_cache_get_balances(int, dna_balance_t**, int*)` | Get cached balances (caller frees) |
| `int wallet_cache_get_oldest_cached_at(int, int64_t*)` | Get oldest cached_at timestamp for TTL freshness check |

### Transaction Operations

| Function | Description |
|----------|-------------|
| `int wallet_cache_save_transactions(int, const char*, const dna_transaction_t*, int)` | Save transactions to cache (upsert by tx_hash) |
| `int wallet_cache_get_transactions(int, const char*, dna_transaction_t**, int*)` | Get cached transactions (caller frees) |
| `int wallet_cache_clear(void)` | Clear all cached data (balances + transactions) |
