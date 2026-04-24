# DHT Functions

**Directory:** `dht/`

Domain-layer DHT wrappers used by the messenger for offline messaging, groups, profiles, contact lists, keyserver lookups, wall posts, and media.

> **Architectural note:** raw DHT primitives (`dht_put`, `dht_get`, `dht_context_*`, `dht_singleton_*`, `dht_value_storage_*`, `dht_chunked_*`, `dht_publish_queue_*`, `dht_bootstrap_discovery_*`, `dht_identity_*`) **no longer live in messenger**. The DHT layer is provided by **Nodus**, a purpose-built post-quantum Kademlia DHT (repo root: `/opt/dna/nodus/`). Messenger talks to Nodus through `nodus_ops_*` (Section 12 below); the domain wrappers in this file sit on top of that.
>
> - Need PUT/GET on an arbitrary key? Use `nodus_ops_put()` / `nodus_ops_get()` from `dht/shared/nodus_ops.h`.
> - Need LISTEN on a key? Use `nodus_ops_listen()` / `nodus_ops_listen_v2()`.
> - Need chunked large values / media? Use `nodus_ops_media_put()` / `nodus_ops_media_get()` (replaces the removed `dht_chunked_*`).

---

## 9. DHT Core wrappers

**Directory:** `dht/core/`

### 9.1 DHT Listen Helpers (`dht_listen.h`)

Thin wrappers that register subscriptions with Nodus under a messenger-specific listener table.

| Function | Description |
|----------|-------------|
| `size_t dht_listen(dht_context_t*, const uint8_t*, size_t, dht_listen_callback_t, void*)` | Start listening (wrapper for `dht_listen_ex` with NULL cleanup) |
| `void dht_cancel_listen(dht_context_t*, size_t)` | Cancel a single listen subscription |
| `size_t dht_listen_ex(dht_context_t*, const uint8_t*, size_t, dht_listen_callback_t, void*, dht_listen_cleanup_t)` | Listen with cleanup callback |

### 9.2 DHT Keyserver (`dht_keyserver.h`)

| Function | Description |
|----------|-------------|
| `int dht_keyserver_publish(...)` | Publish identity to DHT |
| `int dht_keyserver_publish_alias(dht_context_t*, const char*, const char*)` | Publish name → fingerprint alias |
| `int dht_keyserver_lookup(dht_context_t*, const char*, dna_unified_identity_t**)` | Lookup identity by name or fingerprint |
| `int dht_keyserver_update(dht_context_t*, const char*, const uint8_t*, const uint8_t*, const uint8_t*)` | Update public keys |
| `int dht_keyserver_reverse_lookup(const char*, char**)` | Reverse lookup by fingerprint. Returns 0+name on success, -2 if no name, -3 if verification failed. `*identity_out` is NULL on any failure. |
| `void dht_keyserver_reverse_lookup_async(const char*, void(*)(char*, void*), void*)` | Async reverse lookup. Callback receives NULL identity on any failure. |
| `bool dht_keyserver_is_valid_registered_name(const char*)` | Rejects NULL/empty/overlong/fingerprint-format strings. Used as invariant check by reverse_lookup and as migration guard for stale caches. |

### 9.3 DNA Name System (`dht_keyserver.h`)

| Function | Description |
|----------|-------------|
| `void dna_compute_fingerprint(const uint8_t*, char*)` | Compute SHA3-512 fingerprint |
| `int dna_register_name(dht_context_t*, const char*, const char*, const char*, const char*, const uint8_t*)` | Register DNA name |
| `int dna_update_profile(dht_context_t*, const char*, const dna_profile_data_t*, const uint8_t*, const uint8_t*, const uint8_t*)` | Update profile data |
| `int dna_renew_name(dht_context_t*, const char*, const char*, const uint8_t*)` | Renew name registration |
| `int dna_load_identity(dht_context_t*, const char*, dna_unified_identity_t**)` | Load identity from DHT |
| `int dna_lookup_by_name(dht_context_t*, const char*, char**)` | Lookup fingerprint by name |
| `bool dna_is_name_expired(const dna_unified_identity_t*)` | Check if name expired |
| `int dna_resolve_address(dht_context_t*, const char*, const char*, char**)` | Resolve name to wallet address |

---

## 10. DHT Shared (domain wrappers)

**Directory:** `dht/shared/`

Shared DHT modules for offline messaging, groups, profiles, contact requests, and GEK storage.

### 10.1 DM Outbox Daily Buckets (`dht_dm_outbox.h`)

| Function | Description |
|----------|-------------|
| `uint64_t dht_dm_outbox_get_day_bucket(void)` | Get current day bucket (timestamp/86400) |
| `int dht_dm_outbox_make_key(..., const uint8_t *salt)` | Generate DHT key for day bucket (salt REQUIRED, returns -1 if NULL — v0.9.196+) |
| `int dht_dm_queue_message(..., const uint8_t *salt)` | Queue message to daily bucket (salt-aware) |
| `int dht_dm_outbox_sync_day(..., const uint8_t *salt)` | Sync messages from specific day (salt-aware) |
| `int dht_dm_outbox_sync_recent(..., const uint8_t *salt)` | Sync 3 days (salt-aware) |
| `int dht_dm_outbox_sync_full(..., const uint8_t *salt)` | Sync last 8 days (salt-aware) |
| `int dht_dm_outbox_sync_all_contacts_recent(..., const uint8_t **salt_list)` | Sync 3 days from all contacts (parallel, salt array) |
| `int dht_dm_outbox_sync_all_contacts_full(..., const uint8_t **salt_list)` | Sync 8 days from all contacts (salt array) |
| `int dht_dm_outbox_subscribe(..., const uint8_t *salt)` | Subscribe with day rotation (salt-aware) |
| `void dht_dm_outbox_unsubscribe(...)` | Unsubscribe from contact's outbox |
| `int dht_dm_outbox_check_day_rotation(...)` | Check/rotate listener at midnight |
| `void dht_dm_outbox_cache_clear(void)` | Clear local outbox cache |
| `int dht_dm_outbox_cache_sync_pending(...)` | Sync pending cached entries |

#### Offline Queue Legacy (`dht_offline_queue.h`)

**Note:** `dht_queue_message()` redirects to `dht_dm_queue_message()` (v0.5.0+)

| Function | Description |
|----------|-------------|
| `int dht_queue_message(..., const uint8_t *salt)` | Store message (redirects to daily bucket API, salt-aware) |
| `void dht_offline_message_free(dht_offline_message_t*)` | Free single message |
| `void dht_offline_messages_free(dht_offline_message_t*, size_t)` | Free message array |
| `int dht_serialize_messages(...)` | Serialize messages to binary |
| `int dht_deserialize_messages(...)` | Deserialize messages from binary |

**CORE-04 (v0.9.197+):** Removed `dht_retrieve_queued_messages_from_contacts`, `dht_retrieve_queued_messages_from_contacts_parallel`, and `dht_generate_outbox_key`. These produced deterministic unsalted `SHA3-512(sender:outbox:recipient)` keys leaking communication metadata, had zero callers, and were removed per the No Dead Code rule. The live salted DM retrieval path is `dht_dm_outbox_fetch_*` in `dht_dm_outbox.h`.

### 10.2 ACK API (`dht_offline_queue.h`) — v15 replaces watermarks

Simple per-contact ACK timestamps for delivery confirmation. When recipient syncs messages, they publish an ACK. Sender marks ALL sent messages as RECEIVED.

| Function | Description |
|----------|-------------|
| `int dht_generate_ack_key(const char*, const char*, const uint8_t *salt, uint8_t*)` | Generate ACK DHT key (salt REQUIRED, returns -1 if NULL — v0.9.196+) |
| `int dht_publish_ack(const char*, const char*, const uint8_t *salt)` | Publish ACK timestamp (salt-aware) |
| `size_t dht_listen_ack(const char*, const char*, const uint8_t *salt, dht_ack_callback_t, void*)` | Listen for ACK updates (salt-aware) |
| `void dht_cancel_ack_listener(dht_context_t*, size_t)` | Cancel ACK listener |

**v15 Changes:** Removed watermark seq_num tracking. ACK uses simple timestamp (8 bytes). Per-contact, not per-message.

### 10.3 DHT Groups (`dht_groups.h`)

| Function | Description |
|----------|-------------|
| `int dht_groups_init(const char*, const char*)` | Initialize groups subsystem (identity, db_key) |
| `void dht_groups_cleanup(void)` | Cleanup groups subsystem |
| `int dht_groups_create(...)` | Create new group in DHT |
| `int dht_groups_get(dht_context_t*, const char*, dht_group_metadata_t**)` | Get group metadata |
| `int dht_groups_update(...)` | Update group metadata |
| `int dht_groups_add_member(dht_context_t*, const char*, const char*, const char*)` | Add member to group |
| `int dht_groups_remove_member(dht_context_t*, const char*, const char*, const char*)` | Remove member from group |
| `int dht_groups_update_gek_version(dht_context_t*, const char*, uint32_t)` | Update GEK version in metadata |
| `int dht_groups_delete(dht_context_t*, const char*, const char*)` | Delete group |
| `int dht_groups_list_for_user(const char*, dht_group_cache_entry_t**, int*)` | List user's groups |
| `int dht_groups_get_uuid_by_local_id(const char*, int, char*)` | Get UUID from local ID |
| `int dht_groups_sync_from_dht(dht_context_t*, const char*)` | Sync group from DHT |
| `int dht_groups_get_member_count(const char*, int*)` | Get member count |
| `void dht_groups_free_metadata(dht_group_metadata_t*)` | Free metadata |
| `void dht_groups_free_cache_entries(dht_group_cache_entry_t*, int)` | Free cache entries |

### 10.4 Contact Requests (`dht_contact_request.h`)

| Function | Description |
|----------|-------------|
| `void dht_generate_requests_inbox_key(const char*, uint8_t*)` | Generate requests inbox key |
| `int dht_send_contact_request(..., const uint8_t *dht_salt)` | Send contact request (v2 with salt) |
| `int dht_fetch_contact_requests(dht_context_t*, const char*, dht_contact_request_t**, size_t*)` | Fetch pending requests |
| `int dht_verify_contact_request(const dht_contact_request_t*)` | Verify request signature |
| `int dht_cancel_contact_request(dht_context_t*, const char*, const char*)` | Cancel sent request |
| `int dht_serialize_contact_request(const dht_contact_request_t*, uint8_t**, size_t*)` | Serialize request |
| `int dht_deserialize_contact_request(const uint8_t*, size_t, dht_contact_request_t*)` | Deserialize request |
| `void dht_contact_requests_free(dht_contact_request_t*, size_t)` | Free requests array |
| `uint64_t dht_fingerprint_to_value_id(const char*)` | Convert fingerprint to value_id |

### 10.5 DHT Profile (`dht_profile.h`)

| Function | Description |
|----------|-------------|
| `int dht_profile_init(void)` | Initialize profile subsystem |
| `void dht_profile_cleanup(void)` | Cleanup profile subsystem |
| `int dht_profile_publish(dht_context_t*, const char*, const dht_profile_t*, const uint8_t*)` | Publish profile to DHT |
| `int dht_profile_fetch(dht_context_t*, const char*, dht_profile_t*)` | Fetch profile from DHT |
| `int dht_profile_delete(dht_context_t*, const char*)` | Delete profile (best-effort) |
| `bool dht_profile_validate(const dht_profile_t*)` | Validate profile data |
| `void dht_profile_init_empty(dht_profile_t*)` | Create empty profile |

### 10.6 GEK Storage (`dht_gek_storage.h`)

| Function | Description |
|----------|-------------|
| `int dht_gek_publish(dht_context_t*, const char*, uint32_t, const uint8_t*, size_t)` | Publish GEK packet |
| `int dht_gek_fetch(dht_context_t*, const char*, uint32_t, uint8_t**, size_t*)` | Fetch GEK packet |
| `int dht_gek_make_chunk_key(const char*, uint32_t, uint32_t, char[65])` | Generate chunk key |
| `int dht_gek_serialize_chunk(const dht_gek_chunk_t*, uint8_t**, size_t*)` | Serialize chunk |
| `int dht_gek_deserialize_chunk(const uint8_t*, size_t, dht_gek_chunk_t*)` | Deserialize chunk |
| `void dht_gek_free_chunk(dht_gek_chunk_t*)` | Free chunk |

---

## 11. DHT Client (`dht/client/`)

High-level DHT client operations including identity import/export, contact lists, group lists, GEK sync, profiles, wall, message backup, and group outbox.

### 11.1 Identity Backup — REMOVED (v0.3.0)

As of v0.3.0, DHT identity is derived deterministically from the BIP39 master seed. The backup system is no longer needed. Same mnemonic = same DHT identity.

Files removed:
- `dht/client/dht_identity_backup.c`
- `dht/client/dht_identity_backup.h`

### 11.2 Contact List (`dht_contactlist.h`)

| Function | Description |
|----------|-------------|
| `int dht_contactlist_init(void)` | Initialize contact list subsystem |
| `void dht_contactlist_cleanup(void)` | Cleanup contact list subsystem |
| `int dht_contactlist_publish(const char*, const char**, size_t, const uint8_t**, ...)` | Publish encrypted contact list (v2 with salts) |
| `int dht_contactlist_fetch(const char*, char***, size_t*, uint8_t***, ...)` | Fetch and decrypt contact list (v2 returns salts) |
| `void dht_contactlist_free_contacts(char**, size_t)` | Free contacts array |
| `void dht_contactlist_free_salts(uint8_t**, size_t)` | Free salts array from fetch |
| `void dht_contactlist_free(dht_contactlist_t*)` | Free contact list structure |
| `bool dht_contactlist_exists(dht_context_t*, const char*)` | Check if contact list exists |
| `int dht_contactlist_get_timestamp(dht_context_t*, const char*, uint64_t*)` | Get contact list timestamp |

### 11.3 Group List (`dht_grouplist.h`) — v0.5.26+

Per-identity encrypted group membership list storage in DHT.

| Function | Description |
|----------|-------------|
| `int dht_grouplist_init(void)` | Initialize group list subsystem |
| `void dht_grouplist_cleanup(void)` | Cleanup group list subsystem |
| `int dht_grouplist_publish(dht_context_t*, const char*, const char**, size_t, ...)` | Publish encrypted group list (Kyber1024 + Dilithium5) |
| `int dht_grouplist_fetch(dht_context_t*, const char*, char***, size_t*, ...)` | Fetch and decrypt group list |
| `void dht_grouplist_free_groups(char**, size_t)` | Free groups array |
| `void dht_grouplist_free(dht_grouplist_t*)` | Free group list structure |
| `bool dht_grouplist_exists(dht_context_t*, const char*)` | Check if group list exists in DHT |
| `int dht_grouplist_get_timestamp(dht_context_t*, const char*, uint64_t*)` | Get group list timestamp |

**DHT Key:** `SHA3-512(fingerprint + ":grouplist")`
**Magic:** `GLST` (0x474C5354)
**Security:** Self-encrypted with Kyber1024, signed with Dilithium5

### 11.4 GEK Sync (`dht_geks.h`) — v0.6.49+

Per-identity encrypted GEK (Group Encryption Key) storage in DHT for multi-device sync. GEKs are self-encrypted and synced across devices, eliminating the need for per-device IKP fetches.

| Function | Description |
|----------|-------------|
| `int dht_geks_init(void)` | Initialize GEK sync subsystem |
| `void dht_geks_cleanup(void)` | Cleanup GEK sync subsystem |
| `int dht_geks_publish(dht_context_t*, const char*, const dht_gek_entry_t*, size_t, ...)` | Publish encrypted GEK cache (Kyber1024 + Dilithium5) |
| `int dht_geks_fetch(dht_context_t*, const char*, dht_gek_entry_t**, size_t*, ...)` | Fetch and decrypt GEK cache |
| `void dht_geks_free_entries(dht_gek_entry_t*, size_t)` | Free entries array |
| `void dht_geks_free_cache(dht_geks_cache_t*)` | Free cache structure |
| `bool dht_geks_exists(dht_context_t*, const char*)` | Check if GEKs exist in DHT |
| `int dht_geks_get_timestamp(dht_context_t*, const char*, uint64_t*)` | Get GEK cache timestamp |

**DHT Key:** `SHA3-512(fingerprint + ":geks")`
**Magic:** `GEKS` (0x47454B53)
**Security:** Self-encrypted with Kyber1024, signed with Dilithium5
**Format:** JSON with base64-encoded GEKs, organized by group UUID

### 11.5 DNA Profile (`dna_profile.h`)

| Function | Description |
|----------|-------------|
| `dna_unified_identity_t* dna_identity_create(void)` | Create new unified identity |
| `void dna_identity_free(dna_unified_identity_t*)` | Free unified identity |
| `char* dna_identity_to_json(const dna_unified_identity_t*)` | Serialize identity to JSON |
| `char* dna_identity_to_json_unsigned(const dna_unified_identity_t*)` | Serialize identity without signature |
| `int dna_identity_from_json(const char*, dna_unified_identity_t**)` | Parse identity from JSON |
| `bool dna_validate_wallet_address(const char*, const char*)` | Validate wallet address format |
| `bool dna_validate_name(const char*)` | Validate DNA name format |
| `bool dna_network_is_cellframe(const char*)` | Check if Cellframe network |
| `bool dna_network_is_external(const char*)` | Check if external blockchain |
| `void dna_network_normalize(char*)` | Normalize network name to lowercase |
| `const char* dna_identity_get_wallet(const dna_unified_identity_t*, const char*)` | Get wallet for network |
| `int dna_identity_set_wallet(dna_unified_identity_t*, const char*, const char*)` | Set wallet for network |

### 11.6 Wall (Personal Wall Posts — Daily Bucket Storage v0.9.141+)

Wall posts use daily bucket storage: each day's posts stored under `dna:wall:<fp>:<YYYY-MM-DD>`, with a meta key `dna:wall:meta:<fp>` listing which days have posts. Buckets are written as `NODUS_VALUE_EXCLUSIVE` (since v0.9.160 / 2026-04-01) — never expire and only the original writer can update. Refresh only fetches today's bucket; older days loaded on scroll (lazy load). Note: buckets created before v0.9.160 were written as ephemeral with a 30-day TTL and may have expired naturally; `dna_wall_delete()` treats DHT NOT_FOUND as idempotent success.

| Function | Description |
|----------|-------------|
| `void dna_wall_make_key(const char *fingerprint, char *out_key)` | Derive DHT key SHA3-512("dna:wall:<fingerprint>") |
| `int dna_wall_post(const char *fingerprint, const uint8_t *private_key, const char *text, dna_wall_post_t *out_post)` | Post to own wall — writes to today's bucket + updates meta |
| `int dna_wall_post_with_image(const char *fingerprint, const uint8_t *private_key, const char *text, const char *image_json, dna_wall_post_t *out_post)` | Post with image to today's bucket + updates meta |
| `int dna_wall_delete(const char *fingerprint, const uint8_t *private_key, const char *post_uuid, uint64_t post_timestamp)` | Delete post from its day bucket (timestamp used to derive bucket day) |
| `int dna_wall_load(const char *fingerprint, dna_wall_t *wall)` | Load user's wall — reads meta then aggregates all day buckets |
| `int dna_wall_load_day(const char *fingerprint, const char *date_str, dna_wall_t *wall)` | Load a single day's bucket from DHT (v0.9.141+) |
| `int dna_wall_load_meta(const char *fingerprint, dna_wall_meta_t *meta)` | Load wall metadata from DHT (v0.9.141+) |
| `int dna_wall_update_meta(const char *fingerprint, const char *date_str, int delta)` | Update meta after post/delete (+1/-1) (v0.9.141+) |
| `char* dna_wall_meta_to_json(const dna_wall_meta_t *meta)` | Serialize meta to JSON (v0.9.141+) |
| `int dna_wall_meta_from_json(const char *json, dna_wall_meta_t *meta)` | Deserialize meta from JSON (v0.9.141+) |
| `void dna_wall_meta_free(dna_wall_meta_t *meta)` | Free meta structure (v0.9.141+) |
| `void dna_wall_free(dna_wall_t *wall)` | Free wall structure |
| `int dna_wall_post_verify(const dna_wall_post_t *post, const uint8_t *public_key)` | Verify post Dilithium5 signature (0=valid) |
| `char* dna_wall_to_json(const dna_wall_t *wall)` | Serialize wall to JSON string |
| `int dna_wall_from_json(const char *json, dna_wall_t *wall)` | Deserialize wall from JSON string |

### 11.6a Wall Comments (`dna_wall.h`) — v0.7.0+

Single-level threaded comment system for wall posts. Comments are stored as multi-owner chunked values under a per-post DHT key (`SHA3-512("dna:wall:comments:<post_uuid>")`). Each commenter stores their own value_id slot, allowing concurrent writers without conflict.

| Function | Description |
|----------|-------------|
| `int dna_wall_comment_add(dht_context_t *dht_ctx, const char *post_uuid, const char *parent_comment_uuid, const char *body, const char *author_fingerprint, const uint8_t *private_key, char *uuid_out)` | Add a comment to a wall post; parent_comment_uuid may be NULL for top-level comments |
| `int dna_wall_comments_get(dht_context_t *dht_ctx, const char *post_uuid, dna_wall_comment_t **comments_out, size_t *count_out)` | Fetch all comments for a wall post from DHT; returns 0 on success, -2 if none found |
| `int dna_wall_comment_verify(const dna_wall_comment_t *comment, const uint8_t *public_key)` | Verify comment Dilithium5 signature (0=valid) |
| `void dna_wall_comments_free(dna_wall_comment_t *comments, size_t count)` | Free comments array returned by dna_wall_comments_get |

#### Wall Likes (v0.9.52+) — `dna_wall.h`

| Function | Description |
|----------|-------------|
| `int dna_wall_like_add(const char *post_uuid, const char *author_fingerprint, const uint8_t *private_key)` | Add a like to a wall post; returns -3 if already liked, -4 if max (100) reached |
| `int dna_wall_likes_get(const char *post_uuid, dna_wall_like_t **likes_out, size_t *count_out)` | Fetch all likes for a wall post from DHT; returns 0 on success, -2 if none found |
| `int dna_wall_like_verify(const dna_wall_like_t *like, const char *post_uuid, const uint8_t *public_key)` | Verify like Dilithium5 signature (0=valid) |
| `void dna_wall_likes_free(dna_wall_like_t *likes, size_t count)` | Free likes array returned by dna_wall_likes_get |

### 11.7 Group Outbox (`dna_group_outbox.h`)

#### Send/Receive API

| Function | Description |
|----------|-------------|
| `int dna_group_outbox_send(dht_context_t*, const char*, const char*, const char*, const uint8_t*, char*)` | Send message to group outbox |
| `int dna_group_outbox_fetch(dht_context_t*, const char*, uint64_t, dna_group_message_t**, size_t*)` | Fetch messages from group outbox |
| `int dna_group_outbox_sync(dht_context_t*, const char*, size_t*)` | Sync all days since last sync |
| `int dna_group_outbox_sync_all(dht_context_t*, const char*, size_t*)` | Sync all groups with smart sync (v0.5.22+) |
| `int dna_group_outbox_sync_recent(dht_context_t*, const char*, size_t*)` | Sync 3 days: yesterday, today, tomorrow (v0.5.22+) |
| `int dna_group_outbox_sync_full(dht_context_t*, const char*, size_t*)` | Sync 8 days: today-6 to today+1 (v0.5.22+) |

#### Utility Functions

| Function | Description |
|----------|-------------|
| `uint64_t dna_group_outbox_get_day_bucket(void)` | Get current day bucket (timestamp/86400) |
| `int dna_group_outbox_make_key(const char*, uint64_t, const uint8_t*, char*, size_t)` | Generate salted DHT key for outbox (CORE-04: salt is MANDATORY, 32 bytes, NULL → -1) |
| `int dna_group_outbox_make_message_id(const char*, const char*, uint64_t, char*)` | Generate message ID |
| `const char* dna_group_outbox_strerror(int)` | Get error message |

#### Database Functions

| Function | Description |
|----------|-------------|
| `int dna_group_outbox_db_init(void)` | Initialize group outbox tables |
| `int dna_group_outbox_db_store_message(const dna_group_message_t*)` | Store message in database |
| `int dna_group_outbox_db_message_exists(const char*)` | Check if message exists |
| `int dna_group_outbox_db_get_messages(const char*, size_t, size_t, dna_group_message_t**, size_t*)` | Get messages for group |
| `int dna_group_outbox_db_get_last_sync_day(const char*, uint64_t*)` | Get last sync day bucket |
| `int dna_group_outbox_db_set_last_sync_day(const char*, uint64_t)` | Update last sync day bucket |
| `int dna_group_outbox_db_get_sync_timestamp(const char*, uint64_t*)` | Get smart sync timestamp (v0.5.22+) |
| `int dna_group_outbox_db_set_sync_timestamp(const char*, uint64_t)` | Set smart sync timestamp (v0.5.22+) |

#### Memory Management

| Function | Description |
|----------|-------------|
| `void dna_group_outbox_free_message(dna_group_message_t*)` | Free single message |
| `void dna_group_outbox_free_messages(dna_group_message_t*, size_t)` | Free message array |
| `void dna_group_outbox_free_bucket(dna_group_outbox_bucket_t*)` | Free bucket structure |
| `void dna_group_outbox_set_db(void*)` | Set database handle |

### 11.8 Message Backup (`dht_message_backup.h`)

| Function | Description |
|----------|-------------|
| `int dht_message_backup_init(void)` | Initialize message backup subsystem |
| `void dht_message_backup_cleanup(void)` | Cleanup message backup subsystem |
| `int dht_message_backup_publish(dht_context_t*, message_backup_context_t*, const char*, ...)` | Backup messages to DHT |
| `int dht_message_backup_restore(dht_context_t*, message_backup_context_t*, const char*, ...)` | Restore messages from DHT |
| `bool dht_message_backup_exists(dht_context_t*, const char*)` | Check if backup exists |
| `int dht_message_backup_get_info(dht_context_t*, const char*, uint64_t*, int*)` | Get backup info |

---

## 12. Nodus Ops (`dht/shared/nodus_ops.h`)

Convenience wrappers around the Nodus singleton for DHT operations, presence, and media. **This is the authoritative messenger→DHT interface. New code should reach for these, not the legacy `dht_*` primitives.**

### 12.1 Presence (v0.9.0+)

| Function | Description |
|----------|-------------|
| `int nodus_ops_presence_query(const char **fingerprints, size_t count, bool *results)` | Batch-query presence for multiple contacts via single TCP call to Nodus server. Returns online/offline status per fingerprint in `results` array. |

### 12.2 Batch Operations (v0.9.123+)

| Function | Description |
|----------|-------------|
| `int nodus_ops_get_batch_str(const char **str_keys, int key_count, nodus_ops_batch_result_t **results_out, int *count_out)` | Batch GET_ALL — retrieve full data for N string keys in one request. Max 32 keys. Caller frees with `nodus_ops_free_batch_result()`. |
| `int nodus_ops_count_batch_str(const char **str_keys, int key_count, nodus_ops_count_result_t **results_out, int *count_out)` | Batch COUNT — get value counts + has_mine for N string keys. No value data transferred. Caller frees with `nodus_ops_free_count_result()`. |
| `void nodus_ops_free_batch_result(nodus_ops_batch_result_t *results, int count)` | Free batch get results. |
| `void nodus_ops_free_count_result(nodus_ops_count_result_t *results, int count)` | Free batch count results. |

### 12.3 Per-call Timeout (v0.10.5+)

| Function | Description |
|----------|-------------|
| `int nodus_ops_put_with_timeout(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint32_t ttl, uint64_t vid, int timeout_ms)` | Same as `nodus_ops_put` but overrides the default 10s request timeout. Use for large payloads (debug logs, media) or mobile-link callers that need more time after reconnect bursts. `timeout_ms <= 0` falls back to client default. |

### 12.4 LISTEN timeout semantics (v0.10.6+)

`nodus_ops_listen()` / `nodus_ops_listen_v2()` treat `NODUS_ERR_TIMEOUT` from the underlying client as a **soft success**: the callback is still installed in the listener table and a valid token is returned. Rationale: when LISTEN times out, the server may already have registered the subscription (only the `listen_ok` response was lost). Discarding the callback would cause silent push-event loss. The nodus client also tracks the key in `listen_keys[]` so `resubscribe_all()` retries the LISTEN on the next reconnect.

Server-side error responses (`type == 'e'`) remain hard failures — no token is returned.

### 12.5 Media Operations (v0.9.147+)

Replaces the removed `dht_chunked_*` API. Hashes chunks, distributes them across the Nodus DHT, and reassembles on read.

| Function | Description |
|----------|-------------|
| `int nodus_ops_media_put(const uint8_t content_hash[64], const uint8_t *data, size_t data_len, uint8_t media_type, bool encrypted, uint32_t ttl)` | Upload media to DHT. Chunks data (4MB max per chunk, 16 chunks max = 64MB). media_type: 0=image, 1=video, 2=audio. Returns 0 on success. |
| `int nodus_ops_media_get(const uint8_t content_hash[64], uint8_t **data_out, size_t *data_len_out)` | Download media from DHT. Fetches metadata + all chunks, reassembles into contiguous buffer. Caller frees `*data_out`. Returns 0 on success. |
| `int nodus_ops_media_exists(const uint8_t content_hash[64], bool *exists)` | Check if media exists on DHT (deduplication). Returns 0 on success. |

---

## 13. Salt Agreement (`dht/shared/dht_salt_agreement.h`)

Per-contact salt agreement via DHT. Kyber1024 dual-encrypted, Dilithium5 signed.

| Function | Description |
|----------|-------------|
| `int salt_agreement_make_key(const char *fp_a, const char *fp_b, char *key_out, size_t key_out_size)` | Compute deterministic DHT key for contact pair. `SHA3-512(min(fp)+":"+max(fp)+":salt_agreement")`. Output: 128-char hex. |
| `int salt_agreement_publish(const char *my_fp, const char *contact_fp, const uint8_t salt[32], const uint8_t *my_kyber_pub, const uint8_t *contact_kyber_pub, const uint8_t *my_dilithium_priv)` | Publish salt dual-encrypted for both parties. GEK pattern (Kyber1024 KEM + AES-256-GCM). Dilithium5 signed. Returns 0 on success. |
| `int salt_agreement_fetch(const char *my_fp, const char *contact_fp, const uint8_t *my_kyber_priv, const uint8_t *my_sign_pub, const uint8_t *contact_sign_pub, uint8_t salt_out[32])` | Fetch authenticated salt from DHT. Uses `get_all`, verifies signatures against both parties, discards third-party values. Deterministic tiebreaker for diverged salts. Returns 0 on success, 2 on success with divergence (caller should re-publish winner), -1 on error, -2 if not found. |
| `int salt_agreement_verify(const char *my_fp, const char *contact_fp, const uint8_t *my_kyber_pub, const uint8_t *my_kyber_priv, const uint8_t *contact_kyber_pub, const uint8_t *my_sign_pub, const uint8_t *my_dilithium_priv, const uint8_t *contact_sign_pub)` | Verify and reconcile salt for a contact. Compares local vs DHT, applies tiebreaker if diverged, re-publishes winner to overwrite stale entries (including when local matches winner). Returns 0 on success, 1 if pre-salt contact. |
