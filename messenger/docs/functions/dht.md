# DHT Functions

Core DHT (Distributed Hash Table) operations for decentralized storage.

---

## 9. DHT Core

**Directory:** `dht/core/`

### 9.1 Context Management (`dht_context.h`)

| Function | Description |
|----------|-------------|
| `dht_context_t* dht_context_new(const dht_config_t*)` | Initialize DHT context |
| `int dht_context_start(dht_context_t*)` | Start DHT node |
| `int dht_context_start_with_identity(dht_context_t*, dht_identity_t*)` | Start with provided identity |
| `void dht_context_stop(dht_context_t*)` | Stop DHT node |
| `void dht_context_free(dht_context_t*)` | Free DHT context |
| `bool dht_context_is_ready(dht_context_t*)` | Check if DHT has peers |
| `bool dht_context_is_running(dht_context_t*)` | Check if DHT is running |
| `void dht_context_set_status_callback(dht_context_t*, dht_status_callback_t, void*)` | Set status change callback |
| `int dht_context_bootstrap_runtime(dht_context_t*, const char*, uint16_t)` | Bootstrap to additional node |

### 9.2 DHT Put Operations (`dht_context.h`)

| Function | Description |
|----------|-------------|
| `int dht_put(dht_context_t*, const uint8_t*, size_t, const uint8_t*, size_t)` | Put value (7-day TTL) |
| `int dht_put_ttl(dht_context_t*, const uint8_t*, size_t, const uint8_t*, size_t, unsigned int)` | Put value with custom TTL |
| `int dht_put_permanent(dht_context_t*, const uint8_t*, size_t, const uint8_t*, size_t)` | Put value (never expires) |
| `int dht_put_signed(dht_context_t*, const uint8_t*, size_t, const uint8_t*, size_t, uint64_t, unsigned int)` | Put signed value with fixed ID |
| `int dht_put_signed_permanent(dht_context_t*, const uint8_t*, size_t, const uint8_t*, size_t, uint64_t)` | Put signed value permanently |
| `int dht_republish_packed(dht_context_t*, const char*, const uint8_t*, size_t)` | Republish serialized Value |

### 9.3 DHT Get Operations (`dht_context.h`)

| Function | Description |
|----------|-------------|
| `int dht_get(dht_context_t*, const uint8_t*, size_t, uint8_t**, size_t*)` | Get first value (blocking) |
| `void dht_get_async(dht_context_t*, const uint8_t*, size_t, void(*)(uint8_t*, size_t, void*), void*)` | Get value (async) |
| `int dht_get_all(dht_context_t*, const uint8_t*, size_t, uint8_t***, size_t**, size_t*)` | Get all values |
| `int dht_get_all_with_ids(dht_context_t*, const uint8_t*, size_t, uint8_t***, size_t**, uint64_t**, size_t*)` | Get all values with value_ids (for multi-writer filtering) |
| `void dht_get_batch(dht_context_t*, const uint8_t**, const size_t*, size_t, dht_batch_callback_t, void*)` | Batch GET (parallel) |
| `int dht_get_batch_sync(dht_context_t*, const uint8_t**, const size_t*, size_t, dht_batch_result_t**)` | Batch GET (blocking) |
| `void dht_batch_results_free(dht_batch_result_t*, size_t)` | Free batch results |

### 9.4 DHT Node Info (`dht_context.h`)

| Function | Description |
|----------|-------------|
| `int dht_get_node_id(dht_context_t*, char*)` | Get node ID (SHA3-512 hex) |
| `int dht_get_owner_value_id(dht_context_t*, uint64_t*)` | Get unique value_id for node |

### 9.5 DHT Listen (`dht_listen.h`)

| Function | Description |
|----------|-------------|
| `size_t dht_listen(dht_context_t*, const uint8_t*, size_t, dht_listen_callback_t, void*)` | Start listening (wrapper for `dht_listen_ex` with NULL cleanup) |
| `void dht_cancel_listen(dht_context_t*, size_t)` | Cancel listen subscription |
| `size_t dht_get_active_listen_count(dht_context_t*)` | Get active subscription count |
| `size_t dht_listen_ex(dht_context_t*, const uint8_t*, size_t, dht_listen_callback_t, void*, dht_listen_cleanup_t)` | Listen with cleanup callback |
| `void dht_cancel_all_listeners(dht_context_t*)` | Cancel all listeners |
| `void dht_suspend_all_listeners(dht_context_t*)` | Suspend listeners for reinit |
| `size_t dht_resubscribe_all_listeners(dht_context_t*)` | Resubscribe after reconnect |

### 9.6 DHT Keyserver (`dht_keyserver.h`)

| Function | Description |
|----------|-------------|
| `int dht_keyserver_publish(...)` | Publish identity to DHT |
| `int dht_keyserver_publish_alias(dht_context_t*, const char*, const char*)` | Publish name → fingerprint alias |
| `int dht_keyserver_lookup(dht_context_t*, const char*, dna_unified_identity_t**)` | Lookup identity by name or fingerprint |
| `int dht_keyserver_update(dht_context_t*, const char*, const uint8_t*, const uint8_t*, const uint8_t*)` | Update public keys |
| `int dht_keyserver_reverse_lookup(dht_context_t*, const char*, char**)` | Reverse lookup by fingerprint |
| `void dht_keyserver_reverse_lookup_async(dht_context_t*, const char*, void(*)(char*, void*), void*)` | Async reverse lookup |

### 9.7 DNA Name System (`dht_keyserver.h`)

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

### 9.8 DHT Statistics (`dht_stats.h`)

| Function | Description |
|----------|-------------|
| `int dht_get_stats(dht_context_t*, size_t*, size_t*)` | Get node count and stored values |
| `struct dht_value_storage* dht_get_storage(dht_context_t*)` | Get storage pointer |

### 9.9 Bootstrap Registry (`dht_bootstrap_registry.h`)

| Function | Description |
|----------|-------------|
| `int dht_bootstrap_registry_register(dht_context_t*, const char*, uint16_t, const char*, const char*, uint64_t)` | Register bootstrap node |
| `int dht_bootstrap_registry_fetch(dht_context_t*, bootstrap_registry_t*)` | Fetch bootstrap registry |
| `void dht_bootstrap_registry_filter_active(bootstrap_registry_t*)` | Filter active nodes |
| `char* dht_bootstrap_registry_to_json(const bootstrap_registry_t*)` | Serialize to JSON |
| `int dht_bootstrap_registry_from_json(const char*, bootstrap_registry_t*)` | Deserialize from JSON |

---

## 10. DHT Shared

**Directory:** `dht/shared/`

Shared DHT modules for offline messaging, groups, profiles, and storage.

### 10.1 DM Outbox Daily Buckets (`dht_dm_outbox.h`) - v0.5.0+

| Function | Description |
|----------|-------------|
| `uint64_t dht_dm_outbox_get_day_bucket(void)` | Get current day bucket (timestamp/86400) |
| `int dht_dm_outbox_make_key(..., const uint8_t *salt)` | Generate DHT key for day bucket (salt-aware) |
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

### 10.1.1 Offline Queue Legacy (`dht_offline_queue.h`)

**Note:** `dht_queue_message()` now redirects to `dht_dm_queue_message()` (v0.5.0+)

| Function | Description |
|----------|-------------|
| `int dht_queue_message(..., const uint8_t *salt)` | Store message (redirects to daily bucket API, salt-aware) |
| `int dht_retrieve_queued_messages_from_contacts(...)` | Retrieve messages from contacts (sequential) |
| `int dht_retrieve_queued_messages_from_contacts_parallel(...)` | Retrieve messages (parallel, 10-100× faster) |
| `void dht_offline_message_free(dht_offline_message_t*)` | Free single message |
| `void dht_offline_messages_free(dht_offline_message_t*, size_t)` | Free message array |
| `int dht_serialize_messages(...)` | Serialize messages to binary |
| `int dht_deserialize_messages(...)` | Deserialize messages from binary |
| `void dht_generate_outbox_key(const char*, const char*, uint8_t*)` | Generate outbox DHT key |

### 10.2 ACK API (`dht_offline_queue.h`) - v15 Replaces Watermarks

Simple per-contact ACK timestamps for delivery confirmation. When recipient syncs messages, they publish an ACK. Sender marks ALL sent messages as RECEIVED.

| Function | Description |
|----------|-------------|
| `void dht_generate_ack_key(const char*, const char*, const uint8_t *salt, uint8_t*)` | Generate ACK DHT key (salt-aware) |
| `int dht_publish_ack(const char*, const char*, const uint8_t *salt)` | Publish ACK timestamp (salt-aware) |
| `size_t dht_listen_ack(const char*, const char*, const uint8_t *salt, dht_ack_callback_t, void*)` | Listen for ACK updates (salt-aware) |
| `void dht_cancel_ack_listener(dht_context_t*, size_t)` | Cancel ACK listener |

**v15 Changes:** Removed watermark seq_num tracking. ACK uses simple timestamp (8 bytes). Per-contact, not per-message.

### 10.3 DHT Groups (`dht_groups.h`)

| Function | Description |
|----------|-------------|
| `int dht_groups_init(const char*)` | Initialize groups subsystem |
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

### 10.6 Chunked Storage (`dht_chunked.h`)

Transparent chunking for large data storage in DHT with ZSTD compression.
Chunk format v2 (v0.5.25+) adds content hash to chunk 0 for smart sync optimization.

**Constants:**
| Constant | Value | Description |
|----------|-------|-------------|
| `DHT_CHUNK_MAX_CHUNKS` | 10000 | Security limit: max chunks per fetch (~450MB). Prevents DoS via malicious total_chunks. |
| `DHT_CHUNK_DATA_SIZE` | 44975 | Effective payload per chunk (45KB - 25B header) |
| `DHT_CHUNK_KEY_SIZE` | 32 | DHT key size (SHA3-512 truncated) |

| Function | Description |
|----------|-------------|
| `int dht_chunked_publish(dht_context_t*, const char*, const uint8_t*, size_t, uint32_t)` | Publish with chunking (v2: includes SHA3-256 content hash) |
| `int dht_chunked_fetch(dht_context_t*, const char*, uint8_t**, size_t*)` | Fetch chunked data |
| `int dht_chunked_fetch_metadata(dht_context_t*, const char*, uint8_t[32], uint32_t*, uint32_t*, bool*)` | Fetch chunk 0 metadata only (v0.5.25+) |
| `int dht_chunked_delete(dht_context_t*, const char*, uint32_t)` | Delete chunked data |
| `const char* dht_chunked_strerror(int)` | Get error message |
| `int dht_chunked_make_key(const char*, uint32_t, uint8_t[32])` | Generate chunk key |
| `uint32_t dht_chunked_estimate_chunks(size_t)` | Estimate chunk count |
| `int dht_chunked_fetch_batch(dht_context_t*, const char**, size_t, dht_chunked_batch_result_t**)` | Batch fetch |
| `void dht_chunked_batch_results_free(dht_chunked_batch_result_t*, size_t)` | Free batch results |

### 10.6a Publish Queue (`dht_publish_queue.h`) - v0.6.80+

Non-blocking async publish queue with automatic retry and per-key serialization.

**Constants:**
| Constant | Value | Description |
|----------|-------|-------------|
| `DHT_PUBLISH_QUEUE_MAX_ITEMS` | 256 | Maximum queue size |
| `DHT_PUBLISH_QUEUE_MAX_RETRIES` | 3 | Retry attempts per item |
| `DHT_PUBLISH_QUEUE_RETRY_DELAY_MS` | 1000 | Initial retry delay |

**Status Codes:**
| Code | Value | Description |
|------|-------|-------------|
| `DHT_PUBLISH_STATUS_OK` | 0 | Success |
| `DHT_PUBLISH_STATUS_FAILED` | -1 | Failed after retries |
| `DHT_PUBLISH_STATUS_CANCELLED` | -2 | Cancelled |
| `DHT_PUBLISH_STATUS_QUEUE_FULL` | -3 | Queue at capacity |

| Function | Description |
|----------|-------------|
| `dht_publish_queue_t* dht_publish_queue_create(void)` | Create queue and start worker thread |
| `void dht_publish_queue_destroy(dht_publish_queue_t*)` | Stop worker and destroy queue |
| `dht_publish_request_id_t dht_chunked_publish_async(dht_publish_queue_t*, dht_context_t*, const char*, const uint8_t*, size_t, uint32_t, dht_publish_callback_t, void*)` | Submit async publish (non-blocking) |
| `int dht_publish_queue_cancel(dht_publish_queue_t*, dht_publish_request_id_t)` | Cancel pending request |
| `size_t dht_publish_queue_pending_count(dht_publish_queue_t*)` | Get queue size |
| `bool dht_publish_queue_is_running(dht_publish_queue_t*)` | Check if worker is active |

### 10.7 Value Storage (`dht_value_storage.h`)

| Function | Description |
|----------|-------------|
| `dht_value_storage_t* dht_value_storage_new(const char*)` | Create value storage |
| `void dht_value_storage_free(dht_value_storage_t*)` | Free storage |
| `int dht_value_storage_put(dht_value_storage_t*, const dht_value_metadata_t*)` | Store value |
| `int dht_value_storage_get(...)` | Get values for key |
| `void dht_value_storage_free_results(dht_value_metadata_t*, size_t)` | Free results |
| `int dht_value_storage_restore_async(dht_value_storage_t*, struct dht_context*)` | Restore values (async) |
| `int dht_value_storage_cleanup(dht_value_storage_t*)` | Clean up expired values |
| `int dht_value_storage_get_stats(dht_value_storage_t*, dht_storage_stats_t*)` | Get storage stats |
| `bool dht_value_storage_should_persist(uint32_t, uint64_t)` | Check if should persist |

### 10.8 GEK Storage (`dht_gek_storage.h`)

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

High-level DHT client operations including singleton management, identity backup, contact lists, profiles, and channels.

### 11.1 DHT Singleton (`dht_singleton.h`)

**v0.6.0+:** Engine owns DHT context. Singleton uses "borrowed context" for backwards compatibility.

| Function | Description |
|----------|-------------|
| `int dht_singleton_init(void)` | DEPRECATED: Initialize global DHT singleton (ephemeral identity) |
| `int dht_singleton_init_with_identity(dht_identity_t*)` | DEPRECATED: Initialize DHT singleton with user identity |
| `dht_context_t* dht_singleton_get(void)` | Get DHT context (borrowed from engine, or NULL) |
| `bool dht_singleton_is_initialized(void)` | Check if singleton is initialized |
| `bool dht_singleton_is_ready(void)` | Check if DHT is connected and ready |
| `void dht_singleton_cleanup(void)` | Cleanup global DHT singleton |
| `int dht_singleton_reinit(void)` | Reinitialize DHT after network change (restarts with same identity) |
| `void dht_singleton_set_status_callback(dht_status_callback_t, void*)` | Set connection status callback |
| `dht_context_t* dht_create_context_with_identity(dht_identity_t*)` | v0.6.0+: Create engine-owned DHT context |
| `void dht_singleton_set_borrowed_context(dht_context_t*)` | v0.6.0+: Set borrowed context from engine |

**Bootstrap Discovery (`dht_bootstrap_discovery.h`):**

Client-side discovery of bootstrap nodes from DHT registry for decentralization.

| Function | Description |
|----------|-------------|
| `int dht_bootstrap_from_cache(dht_config_t*, size_t)` | Populate config with best cached nodes |
| `int dht_bootstrap_discovery_start(dht_context_t*)` | Start background discovery thread (non-blocking) |
| `void dht_bootstrap_discovery_stop(void)` | Stop discovery thread |
| `bool dht_bootstrap_discovery_is_running(void)` | Check if discovery is running |
| `void dht_bootstrap_discovery_set_callback(dht_discovery_callback_t, void*)` | Set discovery completion callback |
| `int dht_bootstrap_discovery_run_sync(dht_context_t*)` | Run discovery synchronously (blocking) |

### 11.2 DHT Identity (`dht_identity.h`)

| Function | Description |
|----------|-------------|
| `int dht_identity_generate_dilithium5(dht_identity_t**)` | Generate Dilithium5 DHT identity |
| `int dht_identity_generate_from_seed(const uint8_t* seed, dht_identity_t**)` | Generate DHT identity deterministically from 32-byte seed (v0.3.0+) |
| `int dht_identity_export_to_buffer(dht_identity_t*, uint8_t**, size_t*)` | Export identity to binary buffer |
| `int dht_identity_import_from_buffer(const uint8_t*, size_t, dht_identity_t**)` | Import identity from buffer |
| `void dht_identity_free(dht_identity_t*)` | Free DHT identity |

### 11.3 Identity Backup - REMOVED (v0.3.0)

**Note:** As of v0.3.0, DHT identity is derived deterministically from the BIP39 master seed.
The backup system is no longer needed. Same mnemonic = same DHT identity.

Files removed:
- `dht/client/dht_identity_backup.c`
- `dht/client/dht_identity_backup.h`

### 11.4 Contact List (`dht_contactlist.h`)

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

### 11.4a Group List (`dht_grouplist.h`) - v0.5.26+

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

### 11.4b GEK Sync (`dht_geks.h`) - v0.6.49+

Per-identity encrypted GEK (Group Encryption Key) storage in DHT for multi-device sync.
GEKs are self-encrypted and synced across devices, eliminating the need for per-device IKP fetches.

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
| `dna_profile_data_t* dna_profile_create(void)` | Create new profile data structure |
| `void dna_profile_free(dna_profile_data_t*)` | Free profile data |
| `dna_unified_identity_t* dna_identity_create(void)` | Create new unified identity |
| `void dna_identity_free(dna_unified_identity_t*)` | Free unified identity |
| `char* dna_profile_to_json(const dna_profile_data_t*)` | Serialize profile to JSON |
| `int dna_profile_from_json(const char*, dna_profile_data_t**)` | Parse profile from JSON |
| `char* dna_identity_to_json(const dna_unified_identity_t*)` | Serialize identity to JSON |
| `char* dna_identity_to_json_unsigned(const dna_unified_identity_t*)` | Serialize identity without signature |
| `int dna_identity_from_json(const char*, dna_unified_identity_t**)` | Parse identity from JSON |
| `int dna_profile_validate(const dna_profile_data_t*)` | Validate profile data |
| `bool dna_validate_wallet_address(const char*, const char*)` | Validate wallet address format |
| `bool dna_validate_name(const char*)` | Validate DNA name format |
| `bool dna_network_is_cellframe(const char*)` | Check if Cellframe network |
| `bool dna_network_is_external(const char*)` | Check if external blockchain |
| `void dna_network_normalize(char*)` | Normalize network name to lowercase |
| `const char* dna_identity_get_wallet(const dna_unified_identity_t*, const char*)` | Get wallet for network |
| `int dna_identity_set_wallet(dna_unified_identity_t*, const char*, const char*)` | Set wallet for network |

### 11.6 DNA Channels (`dna_channels.h`)

RSS-like public channels with flat text posts and day-bucket discovery.
Uses `dna:channels:` DHT namespace.

#### Channel Operations (`dna_channels.c`)

| Function | Description |
|----------|-------------|
| `int dna_channel_create(dht_context_t*, const char*, const char*, bool, const char*, const uint8_t*)` | Create channel with name, description, is_public flag |
| `int dna_channel_get(dht_context_t*, const char*)` | Get channel info by UUID |
| `int dna_channel_delete(dht_context_t*, const char*, const char*, const uint8_t*)` | Delete channel (creator only) |
| `int dna_channel_discover(dht_context_t*, int, dna_channel_t**, size_t*)` | Discover channels by scanning recent day-buckets |
| `int dna_channel_post(dht_context_t*, const char*, const char*, const char*, const uint8_t*)` | Post message to channel |
| `int dna_channel_get_posts(dht_context_t*, const char*, int days_back, int, int, dna_channel_post_t**, size_t*)` | Get posts from channel (paginated, iterates daily buckets) |

#### Internal DHT Functions (`dna_channels.h`)

| Function | Description |
|----------|-------------|
| `int dna_channel_posts_get(dht_context_t*, const char*, int days_back, dna_channel_post_internal_t**, size_t*)` | Fetch posts from daily buckets (newest first, iterates `days_back` days) |
| `int dna_channel_make_posts_key(const char *uuid, const char *date, uint8_t*, size_t*)` | Generate DHT key for posts; `date` = "YYYYMMDD" for daily bucket, NULL for legacy undated key |
| `void channel_get_today_date(char *date_out)` | Get today's date as "YYYYMMDD" string (UTC) |
| `void channel_get_date_offset(int days_ago, char *date_out)` | Get date N days ago as "YYYYMMDD" string (UTC) |
| `int dna_channel_make_meta_key(const char *uuid, uint8_t*, size_t*)` | Generate DHT key for channel metadata |
| `int dna_channel_make_index_key(const char *date_str, uint8_t*, size_t*)` | Generate DHT key for channel index day-bucket |

#### Subscription Sync (`dht_channel_subscriptions.c`)

| Function | Description |
|----------|-------------|
| `int dht_channel_subscriptions_sync_to_dht(dht_context_t*, const char*, const uint8_t*)` | Sync subscription list to DHT (multi-device backup) |
| `int dht_channel_subscriptions_sync_from_dht(dht_context_t*, const char*)` | Sync subscriptions from DHT (restore on new device) |

### 11.7 Wall (Personal Wall Posts)

| Function | Description |
|----------|-------------|
| `void dna_wall_make_key(const char *fingerprint, char *out_key)` | Derive DHT key SHA3-512("dna:wall:<fingerprint>") |
| `int dna_wall_post(dht_context_t *dht, const char *fingerprint, const uint8_t *private_key, const char *text, dna_wall_post_t *out_post)` | Post to own wall (sign + publish to DHT) |
| `int dna_wall_post_with_image(dht_context_t *dht, const char *fingerprint, const uint8_t *private_key, const char *text, const char *image_json, dna_wall_post_t *out_post)` | Post to own wall with image attachment; image_json is base64+metadata JSON (v0.7.0+) |
| `int dna_wall_delete(dht_context_t *dht, const char *fingerprint, const uint8_t *private_key, const char *post_uuid)` | Delete own wall post by UUID |
| `int dna_wall_load(dht_context_t *dht, const char *fingerprint, dna_wall_t *wall)` | Load user's wall from DHT |
| `void dna_wall_free(dna_wall_t *wall)` | Free wall structure |
| `int dna_wall_post_verify(const dna_wall_post_t *post, const uint8_t *public_key)` | Verify post Dilithium5 signature (0=valid) |
| `char* dna_wall_to_json(const dna_wall_t *wall)` | Serialize wall to JSON string |
| `int dna_wall_from_json(const char *json, dna_wall_t *wall)` | Deserialize wall from JSON string |

### 11.7a Wall Comments (`dna_wall.h`) - v0.7.0+

Single-level threaded comment system for wall posts. Comments are stored as multi-owner
chunked values under a per-post DHT key (`SHA3-512("dna:wall:comments:<post_uuid>")`).
Each commenter stores their own value_id slot, allowing concurrent writers without conflict.

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

### 11.8 Group Outbox (`dna_group_outbox.h`)

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
| `int dna_group_outbox_make_key(const char*, uint64_t, char*, size_t)` | Generate DHT key for outbox |
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

### 11.9 Message Backup (`dht_message_backup.h`)

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

Convenience wrappers around the Nodus singleton for DHT operations and presence.

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

---

## 13. Salt Agreement (`dht/shared/dht_salt_agreement.h`)

Per-contact salt agreement via DHT. Kyber1024 dual-encrypted, Dilithium5 signed.

| Function | Description |
|----------|-------------|
| `int salt_agreement_make_key(const char *fp_a, const char *fp_b, char *key_out, size_t key_out_size)` | Compute deterministic DHT key for contact pair. `SHA3-512(min(fp)+":"+max(fp)+":salt_agreement")`. Output: 128-char hex. |
| `int salt_agreement_publish(const char *my_fp, const char *contact_fp, const uint8_t salt[32], const uint8_t *my_kyber_pub, const uint8_t *contact_kyber_pub, const uint8_t *my_dilithium_priv)` | Publish salt dual-encrypted for both parties. GEK pattern (Kyber1024 KEM + AES-256-GCM). Dilithium5 signed. Returns 0 on success. |
| `int salt_agreement_fetch(const char *my_fp, const char *contact_fp, const uint8_t *my_kyber_priv, const uint8_t *my_sign_pub, const uint8_t *contact_sign_pub, uint8_t salt_out[32])` | Fetch authenticated salt from DHT. Uses `get_all`, verifies signatures against both parties, discards third-party values. Deterministic tiebreaker for diverged salts. Returns 0 on success, -2 if not found. |
| `int salt_agreement_verify(const char *my_fp, const char *contact_fp, const uint8_t *my_kyber_pub, const uint8_t *my_kyber_priv, const uint8_t *contact_kyber_pub, const uint8_t *my_sign_pub, const uint8_t *my_dilithium_priv, const uint8_t *contact_sign_pub)` | Verify and reconcile salt for a contact. Compares local vs DHT, applies tiebreaker if diverged, re-publishes winner. Returns 0 on success, 1 if pre-salt contact. |
