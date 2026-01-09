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

## 13.7 Group Invitations (`group_invitations.h`)

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
