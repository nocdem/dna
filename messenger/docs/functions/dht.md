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
| `int dht_keyserver_publish(const char *fingerprint, const char *name, const uint8_t *dilithium_pubkey, const uint8_t *kyber_pubkey, const uint8_t *dilithium_privkey, const char *wallet_address, const char *eth_address, const char *sol_address, const char *trx_address, const uint8_t *mlkem_pubkey)` | Publish identity to DHT. **CHANGED (KEM Faz 1):** gained trailing `mlkem_pubkey` (nullable — NULL if the identity has not migrated). Callers: `keygen.c:595` (passes local `identity.mlkem` ek when present), `keys.c:110` (passes NULL — predates ML-KEM, no local key available at that call site) |
| `int dht_keyserver_publish_alias(dht_context_t*, const char*, const char*)` | Publish name → fingerprint alias |
| `int dht_keyserver_lookup(dht_context_t*, const char*, dna_unified_identity_t**)` | Lookup identity by name or fingerprint |
| `int dht_keyserver_update(const char *identity, const uint8_t *new_dilithium_pubkey, const uint8_t *new_kyber_pubkey, const uint8_t *new_dilithium_privkey, const uint8_t *mlkem_pubkey)` | Update public keys (version-bump re-sign). **CHANGED (KEM Faz 1):** gained trailing `mlkem_pubkey` (nullable). Previously had ZERO callers in-tree; its first caller is the KEM Faz 1 migration path (`dna_engine_identity.c`, `dna_kem_f1_migrate_to_mlkem`) — passes the identity's OWN current Dilithium/Kyber pubkeys as "new" (no rotation, fingerprint unchanged) plus the freshly-derived `mlkem_pubkey`. Returns -2 if the identity has no published record yet (via its internal `dht_keyserver_lookup`) — the migration path treats that as non-fatal ("will attach on next normal publish") |
| `int dht_keyserver_reverse_lookup(const char*, char**)` | Reverse lookup by fingerprint. Returns 0+name on success, -2 if no name, -3 if verification failed. `*identity_out` is NULL on any failure. |
| `void dht_keyserver_reverse_lookup_async(const char*, void(*)(char*, void*), void*)` | Async reverse lookup. Callback receives NULL identity on any failure. |
| `bool dht_keyserver_is_valid_registered_name(const char*)` | Rejects NULL/empty/overlong/fingerprint-format strings. Used as invariant check by reverse_lookup and as migration guard for stale caches. |

### 9.3 DNA Name System (`dht_keyserver.h`)

| Function | Description |
|----------|-------------|
| `void dna_compute_fingerprint(const uint8_t*, char*)` | Compute SHA3-512 fingerprint |
| `int dna_register_name(dht_context_t*, const char*, const char*, const char*, const char*, const uint8_t*)` | Register DNA name |
| `int dna_update_profile(const char *fingerprint, const dna_profile_t *profile, const uint8_t *dilithium_privkey, const uint8_t *dilithium_pubkey, const uint8_t *kyber_pubkey, const uint8_t *mlkem_pubkey)` | Update profile data. **CHANGED (D6, M1 delta 1b-2):** gained trailing `mlkem_pubkey` (nullable — sets identity->mlkem_pubkey/has_mlkem_pubkey on every branch when non-NULL, leaves the loaded record's field untouched when NULL). Note: this row previously showed a leading `dht_context_t*` parameter that does not exist in the actual header (`dht/core/dht_keyserver.h`) — pre-existing drift, corrected here along with the D6 param. |
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
| `uint64_t dht_dm_outbox_get_day_bucket(void)` | Get current day bucket (timestamp/86400). Defined in `codec/dm_outbox_codec.c` (NC-1, §14) |
| `int dht_dm_outbox_make_key(..., const uint8_t *salt)` | Generate DHT key for day bucket (salt REQUIRED, returns -1 if NULL — v0.9.196+). Defined in `codec/dm_outbox_codec.c` (NC-1, §14) |
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
| `void dht_offline_message_free(dht_offline_message_t*)` | Free single message. Defined in `codec/offline_queue_codec.c` (NC-1, §14) |
| `void dht_offline_messages_free(dht_offline_message_t*, size_t)` | Free message array. Defined in `codec/offline_queue_codec.c` (NC-1, §14) |
| `int dht_serialize_messages(...)` | Serialize messages to binary. Defined in `codec/offline_queue_codec.c` (NC-1, §14) |
| `int dht_deserialize_messages(...)` | Deserialize messages from binary. Defined in `codec/offline_queue_codec.c` (NC-1, §14) |

**CORE-04 (v0.9.197+):** Removed `dht_retrieve_queued_messages_from_contacts`, `dht_retrieve_queued_messages_from_contacts_parallel`, and `dht_generate_outbox_key`. These produced deterministic unsalted `SHA3-512(sender:outbox:recipient)` keys leaking communication metadata, had zero callers, and were removed per the No Dead Code rule. The live salted DM retrieval path is `dht_dm_outbox_fetch_*` in `dht_dm_outbox.h`.

### 10.2 ACK API (`dht_offline_queue.h`) — v15 replaces watermarks

Simple per-contact ACK timestamps for delivery confirmation. When recipient syncs messages, they publish an ACK. Sender marks ALL sent messages as RECEIVED.

| Function | Description |
|----------|-------------|
| `int dht_generate_ack_key(const char*, const char*, const uint8_t *salt, uint8_t*)` | Generate ACK DHT key (salt REQUIRED, returns -1 if NULL — v0.9.196+). Defined in `codec/offline_queue_codec.c` (NC-1, §14) |
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
| `void dht_generate_requests_inbox_key(const char*, uint8_t*)` | Generate requests inbox key. Defined in `codec/contact_request_codec.c` together with `dht_verify_contact_request`, `dht_serialize_contact_request`, `dht_deserialize_contact_request`, `dht_fingerprint_to_value_id` (NC-1, §14) |
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
| `int dht_contactlist_fetch(const char*, char***, size_t*, uint8_t***, ...)` | Fetch and decrypt contact list (v2 returns salts). v0.11.12+: blobs past the embedded 7-day expiry are accepted (logged only) — DHT storage is permanent, expiry must not block seed restore |
| `char* dht_contactlist_serialize_to_json(...)` / `int dht_contactlist_deserialize_from_json(...)` | **NC-1:** the contact-list JSON codec (formerly `static serialize_to_json` / `deserialize_from_json` in this file), now in `codec/contactlist_codec.{c,h}` — see §14 |
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
| `int dht_geks_publish(dht_context_t*, const char*, const dht_gek_entry_t*, size_t, ...)` | Publish encrypted GEK cache (Kyber1024 + Dilithium5). **CHANGED (D12, M1 delta 1b-2):** gained trailing nullable `mlkem_pubkey` (session-loaded via `gek_get_mlkem_keys()` at the gek.c call site, D17) — self-encrypts alg 3 when non-NULL. No more by-path `identity.mlkem` load inside this file. |
| `int dht_geks_fetch(dht_context_t*, const char*, dht_gek_entry_t**, size_t*, ...)` | Fetch and decrypt GEK cache. **CHANGED (D12):** gained trailing nullable `mlkem_privkey`, same source/reason as `dht_geks_publish` above. |
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
| `char* dna_identity_to_json(const dna_unified_identity_t*)` | Serialize identity to JSON (signed). **Behavior CHANGED (KEM Faz 1):** now includes `"mlkem_pubkey"` (hex) when `identity->has_mlkem_pubkey` |
| `char* dna_identity_to_json_unsigned(const dna_unified_identity_t*)` | Serialize identity without signature (the signature preimage). **Does NOT and must never** include `mlkem_pubkey` (KEM Faz 1) — it stays outside the signed scope so old clients that drop the field still verify the unchanged main signature |
| `int dna_identity_from_json(const char*, dna_unified_identity_t**)` | Parse identity from JSON. **Behavior CHANGED (KEM Faz 1):** reads `"mlkem_pubkey"` when present, setting `has_mlkem_pubkey=true`; absent on old-format records (defaults false, struct is calloc'd) |
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
| `int dht_message_backup_publish(dht_context_t*, message_backup_context_t*, const char*, ...)` | Backup messages to DHT. **CHANGED (D12, M1 delta 1b-2):** gained trailing nullable `mlkem_pubkey` (session-loaded via `dna_load_mlkem_key(engine)` in `dna_engine_backup.c`) — self-encrypts alg 3 when non-NULL. No more by-path `identity.mlkem` load inside this file. |
| `int dht_message_backup_restore(dht_context_t*, message_backup_context_t*, const char*, ...)` | Restore messages from DHT. **CHANGED (D12):** gained trailing nullable `mlkem_privkey`, same source/reason as `dht_message_backup_publish` above. |
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

### 12.3b Singleton endpoint introspection (`dht/shared/nodus_init.h`, v0.11.18+)

| Function | Description |
|----------|-------------|
| `int nodus_messenger_get_connected_endpoint(char *ip_out, size_t ip_len, uint16_t *port_out)` | Endpoint the READY nodus singleton is currently connected to (live connection, not the possibly-stale config index). Returns 0 with `ip_out`/`port_out` filled, -1 when not connected. O15C-C D3: quorum fan-outs that open short-lived per-peer clients with the same identity MUST route this endpoint's query through the singleton — a rival same-fingerprint session would evict the singleton's session server-side (one session per fingerprint) and the next singleton RPC fails on a dead connection. |

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

### 12.6 Nodus client SDK — server-key pin, monotonic waits, browser build (`nodus/include/nodus/nodus.h`, `nodus/src/transport/nodus_tcp.h`)

Web wallet NODUS send design, package (c1). Messenger (`nodus_init.c`) zeroes its
`nodus_client_config_t`, so it runs unpinned and its handshake is unchanged.
Details: `nodus/docs/ARCHITECTURE.md` Client SDK → "Timeouts and the clock",
"Server key pin", "Browser build".

| Function / field | Description |
|----------|-------------|
| `const nodus_key_t *pinned_server_fps; int pinned_server_fp_count;` (fields of `nodus_client_config_t`) | **NEW (optional).** Fingerprints (SHA3-512 of the server's Dilithium5 pubkey, `nodus_fingerprint()`) the client accepts. NULL / 0 = no pin, handshake unchanged. Set: `do_auth` refuses unless AUTH_OK has `kpk` + `spk` + a verifying `kpk_sig`, fingerprint(`spk`) is in the list, and a verifying `mpk_sig` for `mpk` (ML-KEM-1024 only — no unsigned-kpk, cached-key, Kyber round-3 or unencrypted session). Caller-owned array, must outlive the client. `count < 0`, or `count > 0` with NULL → `nodus_client_init` returns -1. |
| `int nodus_client_tick(nodus_client_t *client)` | **NEW.** For a client with no read thread (browser build): sends the 60 s keepalive ping when due, then `nodus_client_poll(client, 0)` (delivers input, runs a due reconnect). No-op returning 0 when a read thread runs; -1 on NULL client / no transport. `EMSCRIPTEN_KEEPALIVE` in the browser build, where it must be an async (Asyncify/JSPI) export. |
| `uint64_t nodus_time_mono_ms(void)` | **NEW.** Monotonic milliseconds (`CLOCK_MONOTONIC`; Windows `GetTickCount64`). Intervals/deadlines only; never compared with `nodus_time_now*()`. |
| `int nodus_client_poll(nodus_client_t *client, int timeout_ms)` | **CHANGED (browser build only):** `nodus_tcp_poll` does not wait there, so the requested wait is an `emscripten_sleep`. Native behaviour and signature unchanged. |
| `static int pin_check_auth_ok(const nodus_client_t *client, const nodus_tier2_msg_t *resp)` (`nodus_client.c`) | **NEW (internal).** The pinned-client AUTH_OK gate: 0 = proceed, -1 = refuse (no kpk, no spk/kpk_sig, no mpk/mpk_sig, fingerprint not in list). |
| `static void keepalive_if_due(nodus_client_t *client)` (`nodus_client.c`) | **NEW (internal).** The 60 s ping, shared by the read thread and `nodus_client_tick`. Caller holds `poll_mutex`. |
| `static uint64_t elapsed_since(uint64_t start)`, `static bool deadline_passed(uint64_t start, int limit_ms)` (`nodus_client.c`) | **NEW (internal).** Monotonic deadline helpers for `wait_response`, `do_connect_one` and the channel-connection waits (was a count of loop turns). `limit_ms <= 0` has always passed. |
| `static void client_yield(void)` (`nodus_client.c`, `__EMSCRIPTEN__` only) | **NEW (internal).** `emscripten_sleep(10)` after each poll in the thread-less loops so SOCKFS can deliver bytes. |

---

## 13. Salt Agreement (`dht/shared/dht_salt_agreement.h`)

Per-contact salt agreement via DHT. Round-3 Kyber1024 dual-encrypted (v1) or,
since KEM Faz 1, ML-KEM-1024 (v2, all-or-nothing gate) — Dilithium5 signed.

| Function | Description |
|----------|-------------|
| `int salt_agreement_make_key(const char *fp_a, const char *fp_b, char *key_out, size_t key_out_size)` | Compute deterministic DHT key for contact pair. `SHA3-512(min(fp)+":"+max(fp)+":salt_agreement")`. Output: 128-char hex. Defined in `codec/salt_agreement_codec.c`, with the four packet-parse helpers `salt_agreement_fp_hex_to_bin` / `_packet_data_size_for_version` / `_packet_decrypt_salt` / `_packet_verify_signature` (NC-1, §14) |
| `int salt_agreement_publish(const char *my_fp, const char *contact_fp, const uint8_t salt[32], const uint8_t *my_kyber_pub, const uint8_t *contact_kyber_pub, const uint8_t *my_dilithium_priv)` | Publish salt dual-encrypted for both parties (v1 only). **Signature UNCHANGED (KEM Faz 1)** — thin wrapper: `salt_agreement_publish_internal(..., NULL, NULL, ...)`. Returns 0 on success. |
| `int salt_agreement_publish_v2(const char *my_fp, const char *contact_fp, const uint8_t salt[32], const uint8_t *my_kyber_pub, const uint8_t *contact_kyber_pub, const uint8_t *my_mlkem_pub, const uint8_t *contact_mlkem_pub, const uint8_t *my_dilithium_priv)` | **NEW (KEM Faz 1).** Publishes packet v2 (per-entry `alg` byte, ML-KEM-1024 for both parties) ONLY when BOTH `my_mlkem_pub` and `contact_mlkem_pub` are non-NULL; otherwise falls back to the unchanged v1 packet |
| `int salt_agreement_fetch(const char *my_fp, const char *contact_fp, const uint8_t *my_kyber_priv, const uint8_t *my_sign_pub, const uint8_t *contact_sign_pub, uint8_t salt_out[32])` | Fetch authenticated salt from DHT. **Signature UNCHANGED (KEM Faz 1)** — thin wrapper: `salt_agreement_fetch_internal(..., NULL, ...)`; can verify/read v2 values but not decrypt an alg=ML-KEM entry without the key. Returns 0 on success, -1 on error, -2 if not found. |
| `int salt_agreement_fetch_v2(const char *my_fp, const char *contact_fp, const uint8_t *my_kyber_priv, const uint8_t *my_mlkem_priv, const uint8_t *my_sign_pub, const uint8_t *contact_sign_pub, uint8_t salt_out[32])` | **NEW (KEM Faz 1).** Accepts both v1 and v2 values; `my_mlkem_priv` (nullable) decrypts a v2 entry whose alg is ML-KEM-1024 |
| `int salt_agreement_verify(const char *my_fp, const char *contact_fp, const uint8_t *my_kyber_pub, const uint8_t *my_kyber_priv, const uint8_t *contact_kyber_pub, const uint8_t *my_sign_pub, const uint8_t *my_dilithium_priv, const uint8_t *contact_sign_pub)` | Verify and reconcile salt for a contact. **UNCHANGED (not wired to v2 in this package — its two callers, `dna_engine_contacts.c`/`dna_engine_listeners.c`, are outside package M1's whitelist)**. Compares local vs DHT, applies tiebreaker if diverged, re-publishes winner. Returns 0 on success, 1 if pre-salt contact. |

**Constants (KEM Faz 1):** `SALT_AGREEMENT_VERSION_V2 = 2`, `SALT_AGREEMENT_ALG_KYBER_R3 = 2`, `SALT_AGREEMENT_ALG_MLKEM1024 = 3`.

---

## 14. Codec units (`codec/`, NC-1)

**Directory:** `codec/` (messenger root). Pure encode/decode/derive functions
moved **verbatim** out of the DHT I/O files (Web Connect design rev 5 §1.3,
operator decision 2026-09-30 Q2 = a) so the native library and the web thin
core compile the same source. No network I/O, no database. Behaviour and wire
bytes are unchanged (before/after vectors: `tests/test_codec_extract_vectors.c`).
The five units below are compiled into `dht_lib` (the library the functions
lived in before), added from `messenger/CMakeLists.txt` via `target_sources`.

Functions that were already public keep their name and their declaration in
the original header. Former `static` helpers became external and got a module
prefix (bodies unchanged) — marked **RENAMED** below.

| Function | Defined in | Declared in | Moved from |
|----------|-----------|-------------|------------|
| `void dht_offline_message_free(dht_offline_message_t*)` | `codec/offline_queue_codec.c` | `dht/shared/dht_offline_queue.h` | `dht/shared/dht_offline_queue.c` |
| `void dht_offline_messages_free(dht_offline_message_t*, size_t)` | `codec/offline_queue_codec.c` | `dht/shared/dht_offline_queue.h` | `dht/shared/dht_offline_queue.c` |
| `int dht_serialize_messages(const dht_offline_message_t*, size_t, uint8_t**, size_t*)` | `codec/offline_queue_codec.c` | `dht/shared/dht_offline_queue.h` | `dht/shared/dht_offline_queue.c` |
| `int dht_deserialize_messages(const uint8_t*, size_t, dht_offline_message_t**, size_t*)` | `codec/offline_queue_codec.c` | `dht/shared/dht_offline_queue.h` | `dht/shared/dht_offline_queue.c` |
| `static int make_ack_base_key(const char*, const char*, const uint8_t*, char*, size_t)` | `codec/offline_queue_codec.c` (still `static`) | — | `dht/shared/dht_offline_queue.c` |
| `int dht_generate_ack_key(const char*, const char*, const uint8_t *salt, uint8_t*)` | `codec/offline_queue_codec.c` | `dht/shared/dht_offline_queue.h` | `dht/shared/dht_offline_queue.c` |
| `uint64_t dht_dm_outbox_get_day_bucket(void)` | `codec/dm_outbox_codec.c` | `dht/shared/dht_dm_outbox.h` | `dht/shared/dht_dm_outbox.c` |
| `int dht_dm_outbox_make_key(const char*, const char*, uint64_t, const uint8_t *salt, char*, size_t)` | `codec/dm_outbox_codec.c` | `dht/shared/dht_dm_outbox.h` | `dht/shared/dht_dm_outbox.c` |
| `int salt_agreement_make_key(const char*, const char*, char*, size_t)` | `codec/salt_agreement_codec.c` | `dht/shared/dht_salt_agreement.h` | `dht/shared/dht_salt_agreement.c` |
| `int salt_agreement_fp_hex_to_bin(const char *hex, uint8_t bin[FP_BIN_SIZE])` | `codec/salt_agreement_codec.c` | `codec/salt_agreement_codec.h` | **RENAMED** from `static fp_hex_to_bin`, `dht_salt_agreement.c` |
| `size_t salt_agreement_packet_data_size_for_version(uint16_t)` | `codec/salt_agreement_codec.c` | `codec/salt_agreement_codec.h` | **RENAMED** from `static packet_data_size_for_version` |
| `int salt_agreement_packet_decrypt_salt(const uint8_t*, size_t, const uint8_t[FP_BIN_SIZE], const uint8_t *kyber_priv, const uint8_t *mlkem_priv, uint8_t salt_out[32])` | `codec/salt_agreement_codec.c` | `codec/salt_agreement_codec.h` | **RENAMED** from `static packet_decrypt_salt` |
| `int salt_agreement_packet_verify_signature(const uint8_t*, size_t, size_t data_size, const uint8_t *pub_a, const uint8_t *pub_b)` | `codec/salt_agreement_codec.c` | `codec/salt_agreement_codec.h` | **RENAMED** from `static packet_verify_signature` |
| `char* dht_contactlist_serialize_to_json(const char *identity, const char **contacts, const uint8_t **salts, size_t count, uint64_t timestamp)` | `codec/contactlist_codec.c` | `codec/contactlist_codec.h` | **RENAMED** from `static serialize_to_json`, `dht/client/dht_contactlist.c` |
| `int dht_contactlist_deserialize_from_json(const char*, char***, size_t*, uint8_t***, uint64_t*)` | `codec/contactlist_codec.c` | `codec/contactlist_codec.h` | **RENAMED** from `static deserialize_from_json` |
| `static int hex_to_bytes(const char*, uint8_t*, size_t)` | `codec/contactlist_codec.c` (still `static`) | — | `dht/client/dht_contactlist.c` |
| `void dht_generate_requests_inbox_key(const char*, uint8_t*)` | `codec/contact_request_codec.c` | `dht/shared/dht_contact_request.h` | `dht/shared/dht_contact_request.c` |
| `uint64_t dht_fingerprint_to_value_id(const char*)` | `codec/contact_request_codec.c` | `dht/shared/dht_contact_request.h` | `dht/shared/dht_contact_request.c` |
| `int dht_serialize_contact_request(const dht_contact_request_t*, uint8_t**, size_t*)` | `codec/contact_request_codec.c` | `dht/shared/dht_contact_request.h` | `dht/shared/dht_contact_request.c` |
| `int dht_deserialize_contact_request(const uint8_t*, size_t, dht_contact_request_t*)` | `codec/contact_request_codec.c` | `dht/shared/dht_contact_request.h` | `dht/shared/dht_contact_request.c` |
| `int dht_verify_contact_request(const dht_contact_request_t*)` | `codec/contact_request_codec.c` | `dht/shared/dht_contact_request.h` | `dht/shared/dht_contact_request.c` |

**Macros moved:** `FP_BIN_SIZE`, `PACKET_VERSION_SIZE`, `PACKET_ENTRY_SIZE[_V2]`,
`PACKET_DATA_SIZE[_V2]`, `PACKET_TOTAL_SIZE[_V2]` → `codec/salt_agreement_codec.h`;
`DHT_OFFLINE_MAX_MESSAGES_PER_OUTBOX` (1000) → `codec/offline_queue_codec.c`.

**Two value_id derivations — deliberately separate (design §6.4 F6):**
`dht_fingerprint_to_value_id` = first 16 hex chars of the fingerprint read
big-endian (contact requests); `nodus_identity_value_id` = first 8 bytes of
node_id little-endian (every other record). Not merged into one helper.

**NOT moved (still inline in an I/O function, no separate function exists):**
the salt-agreement packet BUILD (`salt_agreement_publish_internal`), the
contact-list `CLST` blob build/parse (`dht_contactlist_publish` /
`dht_contactlist_fetch`), and the 8-byte big-endian ACK value encode/decode
(`dht_publish_ack` / `ack_listen_callback`).

---

## 15. Nodus Connect thin core (`web-wallet/connect/`, NC-2) + strict nodus reads

**Not part of libdna.** The web thin core (Web Connect design rev 5 §1.4,
package NC-2) is a separate C library under `web-wallet/connect/`, compiled to
WebAssembly by `web-wallet/scripts/build-connect-wasm.sh` and natively by
`web-wallet/connect/tests/CMakeLists.txt`. It calls the §14 codec units,
`dna_api.c` and `dht/client/dna_profile.c` as-is. Full contracts: the header
`web-wallet/connect/nc_core.h`.

**Nodus client additions** (`nodus/src/client/nodus_client_strict.h`,
defined in `nodus/src/client/nodus_client.c`; `nodus_client_get` /
`nodus_client_get_all` unchanged):

| Function | Description |
|----------|-------------|
| `int nodus_client_reply_value_shape(const uint8_t *raw, size_t raw_len, nodus_reply_value_shape_t *out)` | Pure walk of a raw tier-2 reply: does `"r"` carry `"val"` / `"vals"`, how many items. 0 / -1 |
| `int nodus_client_get_strict(nodus_client_t*, const nodus_key_t*, nodus_value_t **val_out)` | GET; a `"val"` that did not decode → `NODUS_ERR_PROTOCOL_ERROR`, never `NODUS_ERR_NOT_FOUND` (design §6.4 F1) |
| `int nodus_client_get_all_strict(nodus_client_t*, const nodus_key_t*, nodus_value_t ***vals_out, size_t *count_out, size_t *undecodable_out)` | GET_ALL; decoded values + the count of items that did not decode |

**Thin core library** (`web-wallet/connect/nc_core.h`):

| Function | Description |
|----------|-------------|
| `int nc_keys_from_words(const char *words, nc_keys_t *out)` / `void nc_keys_wipe(nc_keys_t*)` | Words → ML-DSA-87 identity, round-3 Kyber, ML-KEM-1024 (the app's derivation) |
| `void nc_classify_one(int rc, nodus_value_t*, const nodus_key_t *key, const nodus_key_t *expect_owner, nc_read_t*)` | R0, pure: FOUND / EMPTY / UNREADABLE(why) |
| `void nc_read_one(const nc_ctx_t*, const nodus_key_t*, const nodus_key_t *expect_owner, nc_read_t*)` / `void nc_read_clear(nc_read_t*)` | strict GET + classify |
| `void nc_classify_all(int rc, nodus_value_t **vals, size_t count, size_t undecodable, const nodus_key_t *key, const nodus_key_t *owners, size_t n_owners, nc_read_all_t*)` | R0 for GET_ALL, pure; FOUND is always partial |
| `void nc_read_all(const nc_ctx_t*, const nodus_key_t*, const nodus_key_t *owners, size_t n_owners, nc_read_all_t*)` / `void nc_read_all_clear(nc_read_all_t*)` | strict GET_ALL + classify |
| `int nc_put(const nc_ctx_t*, const nodus_key_t*, const uint8_t*, size_t, nodus_value_type_t, uint32_t ttl, uint64_t value_id)` | one signed PUT (the `nodus_ops.c do_put` shape) |
| `void nc_key_str(const char*, nodus_key_t*)` / `void nc_key_bytes(const uint8_t*, size_t, nodus_key_t*)` / `int nc_fp_parse(const char*, nodus_key_t*)` | DHT key hashing (string / bytes), fingerprint parse |
| `const char *nc_why_str(nc_why_t)` / `const char *nc_outcome_str(nc_outcome_t)` | names |
| `void nc_profile_read(const nc_ctx_t*, const char *fp, nc_read_t*, dna_unified_identity_t**, nc_peer_t*)` | R1 read + the app's record checks |
| `int nc_profile_publish(const nc_ctx_t*, const char *patch_json, nc_profile_result_t*)` | R1 update / Q1-gated create, EXCLUSIVE |
| `int nc_request_build(const nc_keys_t*, const char *recipient_fp, const char *message, const uint8_t *salt, uint8_t **out, size_t *out_len)` | R2 request bytes, checked with the codec's verify |
| `int nc_request_send(...)` / `int nc_request_accept(...)` / `int nc_request_cancel(...)` | R2 PUTs (send, the app's ACCEPT, cancel) |
| `int nc_requests_fetch(const nc_ctx_t*, nc_requests_t*)` / `void nc_requests_clear(nc_requests_t*)` | R2 inbox |
| `int nc_salt_read(const nc_ctx_t*, const nc_peer_t*, nc_salt_read_t*)` / `void nc_salt_read_clear(nc_salt_read_t*)` | R3 read (no publish) |
| `nc_salt_choice_t nc_salt_choose(const uint8_t *local, const uint8_t *dht, uint8_t chosen[32], bool *republish_wanted)` | R3 reconcile rule, pure |
| `int nc_outbox_build(...)` / `int nc_outbox_publish(...)` | R5 day blob (2-recipient Seal, alg all-or-nothing) + PUT |
| `int nc_outbox_fetch_day(const nc_ctx_t*, const nc_peer_t*, const uint8_t salt[32], uint64_t day, nc_inbox_t*)` / `void nc_inbox_clear(nc_inbox_t*)` | R5 one bucket + authorship gate |
| `int nc_ack_publish(const nc_ctx_t*, const char *peer_fp, const uint8_t salt[32])` / `void nc_ack_read(..., nc_read_t*, uint64_t *ack_ts)` | R5 ACK |
| `int nc_servers_parse(const char *json, nc_servers_t*, char *why, size_t why_len)` | embedded server list (`nodus-connect-servers` v1, `kind`-tagged entries) |

The WebAssembly exports (`nc_unlock`, `nc_profile_get`, `nc_outbox_send`, …)
are listed in `build-connect-wasm.sh` and documented in `web-wallet/connect/nc_wasm.c`
and `web-wallet/src/connect/core.js`.
