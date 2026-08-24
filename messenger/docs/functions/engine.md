# Engine Implementation Functions

**Directory:** `src/api/`

Internal DNA engine implementation with async task queue.

---

## Engine Internal (`dna_engine_internal.h`)

### Task Queue

| Function | Description |
|----------|-------------|
| `void dna_task_queue_init(dna_task_queue_t*)` | Initialize task queue |
| `bool dna_task_queue_push(dna_task_queue_t*, const dna_task_t*)` | Push task to queue |
| `bool dna_task_queue_pop(dna_task_queue_t*, dna_task_t*)` | Pop task from queue |
| `bool dna_task_queue_empty(dna_task_queue_t*)` | Check if queue empty |

### Threading

| Function | Description |
|----------|-------------|
| `int dna_start_workers(dna_engine_t*)` | Start worker threads |
| `void dna_stop_workers(dna_engine_t*)` | Stop worker threads |
| `void* dna_worker_thread(void*)` | Worker thread entry point |
| `void* dna_engine_setup_listeners_thread(void*)` | Background thread for DHT listener setup (avoids deadlock) |

### Task Execution

| Function | Description |
|----------|-------------|
| `void dna_execute_task(dna_engine_t*, dna_task_t*)` | Execute task |
| `dna_request_id_t dna_next_request_id(dna_engine_t*)` | Generate next request ID |
| `dna_request_id_t dna_submit_task(dna_engine_t*, dna_task_type_t, ...)` | Submit task to queue |
| `void dna_dispatch_event(dna_engine_t*, const dna_event_t*)` | Dispatch event to callback |

### Task Handlers - Identity

| Function | Description |
|----------|-------------|
| `void dna_handle_list_identities(dna_engine_t*, dna_task_t*)` | Handle list identities |
| `void dna_handle_create_identity(dna_engine_t*, dna_task_t*)` | Handle create identity |
| `void dna_handle_load_identity(dna_engine_t*, dna_task_t*)` | Handle load identity |
| `void dna_handle_register_name(dna_engine_t*, dna_task_t*)` | Handle register name |
| `void dna_handle_get_display_name(dna_engine_t*, dna_task_t*)` | Handle get display name |
| `void dna_handle_get_avatar(dna_engine_t*, dna_task_t*)` | Handle get avatar |
| `void dna_handle_lookup_name(dna_engine_t*, dna_task_t*)` | Handle lookup name |
| `void dna_handle_get_profile(dna_engine_t*, dna_task_t*)` | Handle get profile |
| `void dna_handle_lookup_profile(dna_engine_t*, dna_task_t*)` | Handle lookup profile |
| `void dna_handle_update_profile(dna_engine_t*, dna_task_t*)` | Handle update profile |

**CORE-05 (Phase 6, 2026-04-14):** On registration failure, `dna_engine_create_identity_sync` (the public sync create-with-name entry point, internally documented as `dna_engine_create_identity_with_name_sync`) now PRESERVES local key material (`keys/`, `db/`, `wallets/`, `mnemonic.enc`). Previously it called `qgp_platform_rmdir_recursive` on all four paths whenever `messenger_init` or `messenger_register_name` returned a non-zero code, which locked users out of their identity on transient DHT errors. Retry is handled by the Flutter resume-flow UI calling `dna_engine_register_name` once the network recovers. Function signature and return codes (`DNA_ERROR_INTERNAL`, `DNA_ENGINE_ERROR_NETWORK`) are unchanged.

### Task Handlers - Contacts

| Function | Description |
|----------|-------------|
| `void dna_handle_get_contacts(dna_engine_t*, dna_task_t*)` | Handle get contacts |
| `void dna_handle_add_contact(dna_engine_t*, dna_task_t*)` | Handle add contact |
| `void dna_handle_remove_contact(dna_engine_t*, dna_task_t*)` | Handle remove contact |
| `void dna_handle_send_contact_request(dna_engine_t*, dna_task_t*)` | Handle send request |
| `void dna_handle_get_contact_requests(dna_engine_t*, dna_task_t*)` | Handle get requests |
| `void dna_handle_approve_contact_request(dna_engine_t*, dna_task_t*)` | Handle approve request |
| `void dna_handle_deny_contact_request(dna_engine_t*, dna_task_t*)` | Handle deny request |
| `void dna_handle_block_user(dna_engine_t*, dna_task_t*)` | Handle block user |
| `void dna_handle_unblock_user(dna_engine_t*, dna_task_t*)` | Handle unblock user |
| `void dna_handle_get_blocked_users(dna_engine_t*, dna_task_t*)` | Handle get blocked |

### Task Handlers - Messaging

| Function | Description |
|----------|-------------|
| `void dna_handle_send_message(dna_engine_t*, dna_task_t*)` | Handle send message |
| `void dna_handle_get_conversation(dna_engine_t*, dna_task_t*)` | Handle get conversation |
| `void dna_handle_check_offline_messages(dna_engine_t*, dna_task_t*)` | Handle check offline |
| `void dna_handle_delete_message(dna_engine_t*, dna_task_t*)` | Handle single message deletion with DHT cleanup + notices |
| `void dna_handle_delete_conversation(dna_engine_t*, dna_task_t*)` | Handle conversation purge with DHT cleanup + notices |
| `void dna_handle_delete_all_messages(dna_engine_t*, dna_task_t*)` | Handle purge all messages |

### Task Handlers - Groups

| Function | Description |
|----------|-------------|
| `void dna_handle_get_groups(dna_engine_t*, dna_task_t*)` | Handle get groups |
| `void dna_handle_create_group(dna_engine_t*, dna_task_t*)` | Handle create group |
| `void dna_handle_send_group_message(dna_engine_t*, dna_task_t*)` | Handle group message |
| `void dna_handle_get_invitations(dna_engine_t*, dna_task_t*)` | Handle get invitations |
| `void dna_handle_accept_invitation(dna_engine_t*, dna_task_t*)` | Handle accept invite |
| `void dna_handle_reject_invitation(dna_engine_t*, dna_task_t*)` | Handle reject invite |

### Task Handlers - Wallet

| Function | Description |
|----------|-------------|
| `void dna_handle_list_wallets(dna_engine_t*, dna_task_t*)` | Handle list wallets |
| `void dna_handle_get_balances(dna_engine_t*, dna_task_t*)` | Handle get balances |
| `void dna_handle_send_tokens(dna_engine_t*, dna_task_t*)` | Handle send tokens (network param: "Cellframe" canonical, "Backbone" accepted via strcasecmp fallback) |
| `void dna_handle_get_transactions(dna_engine_t*, dna_task_t*)` | Handle get transactions |
| `void dna_handle_dex_quote(dna_engine_t*, dna_task_t*)` | Handle DEX quote request |
| `void dna_handle_dex_list_pairs(dna_engine_t*, dna_task_t*)` | Handle DEX list pairs |
| `void dna_handle_dex_swap(dna_engine_t*, dna_task_t*)` | Handle DEX swap execution |

### Task Handlers - P2P/Presence

| Function | Description |
|----------|-------------|
| `void dna_handle_refresh_presence(dna_engine_t*, dna_task_t*)` | Handle refresh presence (triggers batch TCP query via Nodus server, v0.9.0+) |
| `void dna_handle_lookup_presence(dna_engine_t*, dna_task_t*)` | Handle lookup presence (reads from local cache populated by batch query) |
| `void dna_presence_batch_query(dna_engine_t*)` | Internal: batch-query all contacts' presence via single TCP call to Nodus server, updates local presence cache |
| `void dna_handle_sync_contacts_to_dht(dna_engine_t*, dna_task_t*)` | Handle sync to DHT |
| `void dna_handle_sync_contacts_from_dht(dna_engine_t*, dna_task_t*)` | Handle sync from DHT |
| `void dna_handle_sync_groups(dna_engine_t*, dna_task_t*)` | Handle sync groups |
| `void dna_handle_get_registered_name(dna_engine_t*, dna_task_t*)` | Handle get name |

### Task Handlers - Channels

| Function | Description |
|----------|-------------|
| `void dna_handle_channel_create(dna_engine_t*, dna_task_t*)` | Handle create channel |
| `void dna_handle_channel_get(dna_engine_t*, dna_task_t*)` | Handle get channel |
| `void dna_handle_channel_delete(dna_engine_t*, dna_task_t*)` | Handle delete channel |
| `void dna_handle_channel_discover(dna_engine_t*, dna_task_t*)` | Handle discover channels |
| `void dna_handle_channel_post(dna_engine_t*, dna_task_t*)` | Handle post to channel |
| `void dna_handle_channel_get_posts(dna_engine_t*, dna_task_t*)` | Handle get channel posts (task params include `days_back` for daily bucket iteration) |
| `void dna_handle_channel_get_subscriptions(dna_engine_t*, dna_task_t*)` | Handle get channel subscriptions |
| `void dna_handle_channel_sync_subs_to_dht(dna_engine_t*, dna_task_t*)` | Handle sync subscriptions to DHT |
| `void dna_handle_channel_sync_subs_from_dht(dna_engine_t*, dna_task_t*)` | Handle sync subscriptions from DHT |

### Task Handlers - Wall

| Function | Description |
|----------|-------------|
| `void dna_handle_wall_post(dna_engine_t*, dna_task_t*)` | Handle wall post |
| `void dna_handle_wall_delete(dna_engine_t*, dna_task_t*)` | Handle wall delete |
| `void dna_handle_wall_load(dna_engine_t*, dna_task_t*)` | Handle wall load |
| `void dna_handle_wall_timeline(dna_engine_t*, dna_task_t*)` | Handle wall timeline |
| `void dna_handle_wall_load_day(dna_engine_t*, dna_task_t*)` | Handle single day bucket load (`TASK_WALL_LOAD_DAY`, v0.9.141+) |
| `void dna_handle_wall_add_comment(dna_engine_t*, dna_task_t*)` | Handle wall add comment task (`TASK_WALL_ADD_COMMENT`, v0.7.0+) |
| `void dna_handle_wall_get_comments(dna_engine_t*, dna_task_t*)` | Handle wall get comments task (`TASK_WALL_GET_COMMENTS`, v0.7.0+) |

### Task Handlers - Media (v0.9.147+)

| Function | Description |
|----------|-------------|
| `void dna_handle_media_upload(dna_engine_t*, dna_task_t*)` | Handle media upload (hash, chunk, store via Nodus m_put) |
| `void dna_handle_media_download(dna_engine_t*, dna_task_t*)` | Handle media download (fetch meta + chunks, reassemble) |
| `void dna_handle_media_exists(dna_engine_t*, dna_task_t*)` | Handle media existence check |

### Wall Poll (v0.9.142+ — replaces wall listeners)

| Function | Description |
|----------|-------------|
| `int wall_poll_refresh(dna_engine_t*)` | Batch-poll all contact meta keys, fetch missing day buckets |
| `int wall_poll_boosts(dna_engine_t*)` | Poll boost keys for last 2 days |
| `void dna_engine_start_wall_poll(dna_engine_t*)` | Start 5-minute poll timer thread |
| `void dna_engine_stop_wall_poll(dna_engine_t*)` | Stop poll timer thread |

### DNAC (DNA Chain) (`dna_engine_dnac.c`)

| Function | Description |
|----------|-------------|
| `void dna_handle_dnac_get_balance(dna_engine_t*, dna_task_t*)` | Get balance handler |
| `void dna_handle_dnac_send(dna_engine_t*, dna_task_t*)` | Send payment handler |
| `void dna_handle_dnac_sync(dna_engine_t*, dna_task_t*)` | Wallet sync handler |
| `void dna_handle_dnac_get_history(dna_engine_t*, dna_task_t*)` | Transaction history handler |
| `void dna_handle_dnac_get_utxos(dna_engine_t*, dna_task_t*)` | UTXO list handler |
| `void dna_handle_dnac_estimate_fee(dna_engine_t*, dna_task_t*)` | Fee estimate handler |
| `void dna_handle_dnac_token_list(dna_engine_t*, dna_task_t*)` | List custom tokens handler |
| `void dna_handle_dnac_token_create(dna_engine_t*, dna_task_t*)` | Create token handler |
| `void dna_handle_dnac_token_balance(dna_engine_t*, dna_task_t*)` | Token balance handler |

### Task Handlers - Follow (`dna_engine_follow.c`)

| Function | Description |
|----------|-------------|
| `void dna_handle_follow(dna_engine_t*, dna_task_t*)` | Handle follow user |
| `void dna_handle_unfollow(dna_engine_t*, dna_task_t*)` | Handle unfollow user |
| `void dna_handle_get_following(dna_engine_t*, dna_task_t*)` | Handle get following list |
| `void dna_handle_sync_following_to_dht(dna_engine_t*, dna_task_t*)` | Sync following list to DHT |
| `void dna_handle_sync_following_from_dht(dna_engine_t*, dna_task_t*)` | Restore following list from DHT |
| `bool dna_engine_is_following(dna_engine_t*, const char *fingerprint)` | Synchronous follow-state check |

### Debug Log Send (`dna_engine_debug_log.c`)

| Function | Description |
|----------|-------------|
| `void dna_handle_debug_log_send(dna_engine_t*, dna_task_t*)` | Encrypt (Kyber1024 + AES-256-GCM) and DHT-deliver the app debug log to the developer |

### Backup / Sync (`dna_engine_backup.c`)

The contact/group sync handlers also appear under P2P/Presence above; the backup module additionally provides:

| Function | Description |
|----------|-------------|
| `void dna_handle_sync_groups_to_dht(dna_engine_t*, dna_task_t*)` | Push all groups to DHT |
| `void dna_handle_restore_groups_from_dht(dna_engine_t*, dna_task_t*)` | Restore all groups from DHT |
| `void dna_handle_sync_group_by_uuid(dna_engine_t*, dna_task_t*)` | Sync a single group by UUID |

Backup/restore run on joinable worker threads joined in `dna_engine_destroy` (thread-safety fix, verified 2026-07-08 — see `messenger/BUGS.md`).

### Address Book (`dna_engine_addressbook.c`)

| Function | Description |
|----------|-------------|
| `int dna_engine_add_address(dna_engine_t*, const char *address, const char *label, const char *network, const char *notes)` | Add a saved address (synchronous) |
| `dna_request_id_t dna_engine_get_addressbook(dna_engine_t*, dna_addressbook_cb, void*)` | Get all saved addresses |
| `dna_request_id_t dna_engine_get_addressbook_by_network(dna_engine_t*, const char *network, dna_addressbook_cb, void*)` | Filter saved addresses by network |
| `int dna_engine_remove_address(dna_engine_t*, int id)` | Remove a saved address by id |
| `int dna_engine_increment_address_usage(dna_engine_t*, int id)` | Bump the usage counter for an address |
| `void dna_free_addressbook_entries(dna_addressbook_entry_t*, int count)` | Free an addressbook result array |

### Signing (`dna_engine_signing.c`)

| Function | Description |
|----------|-------------|
| `int dna_engine_sign_data(dna_engine_t*, const uint8_t *data, size_t data_len, uint8_t *signature_out, size_t *sig_len_out)` | Dilithium5-sign arbitrary data with the loaded identity key. **Note:** `signature_out` has no capacity parameter — callers must supply a ≥4627-byte buffer (ML-DSA-87 fixed size) |
| `int dna_engine_get_signing_public_key(dna_engine_t*, uint8_t *pubkey_out, size_t pubkey_out_len)` | Export the identity's Dilithium5 public key |
| `int dna_engine_pubkey_to_fingerprint(const uint8_t *pubkey, size_t pubkey_len, char *out_hex, size_t out_hex_size)` | Derive the hex fingerprint from a Dilithium5 pubkey (pubkey_len hard-bound to Dilithium5) |

### Version (`dna_engine_version.c`)

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_version(void)` | Return the compiled C library version string |
| `int dna_engine_check_version_dht(dna_engine_t*, dna_version_check_result_t *result_out)` | Read the published version record from DHT (uses the nodus singleton; the engine param is unused) |

### Logging (`dna_engine_logging.c`)

| Function | Description |
|----------|-------------|
| `int dna_engine_set_log_level(const char *level)` | Set the global log level |
| `int dna_engine_set_log_tags(const char *tags)` | Set the enabled log-tag filter |
| `void dna_engine_debug_log_enable(bool enabled)` | Enable/disable the in-memory debug-log ring |
| `bool dna_engine_debug_log_is_enabled(void)` | Query debug-log enabled state |
| `int dna_engine_debug_log_get_entries(dna_debug_log_entry_t*, int max_entries)` | Copy ring-buffer entries out |
| `int dna_engine_debug_log_count(void)` | Number of buffered log entries |
| `void dna_engine_debug_log_clear(void)` | Clear the log ring buffer |
| `void dna_engine_debug_log_message(const char *tag, const char *message)` | Append a log line |
| `void dna_engine_debug_log_message_level(const char *tag, const char *message, int level)` | Append a log line with an explicit level |
| `int dna_engine_debug_log_export(const char *filepath)` | Export the log to a file |

### Lifecycle (`dna_engine_lifecycle.c`)

| Function | Description |
|----------|-------------|
| `int dna_engine_pause(dna_engine_t*)` | Pause engine (mobile background) |
| `int dna_engine_resume(dna_engine_t*)` | Resume engine (mobile foreground) |
| `bool dna_engine_is_paused(dna_engine_t*)` | Query paused state |
| `void dna_engine_pause_presence(dna_engine_t*)` | Pause the presence heartbeat only |
| `void dna_engine_resume_presence(dna_engine_t*)` | Resume the presence heartbeat only |

### Listeners (`dna_engine_listeners.c`)

| Function | Description |
|----------|-------------|
| `int dna_engine_listen_all_contacts(dna_engine_t*)` | Start outbox listeners for all contacts |
| `int dna_engine_refresh_listeners(dna_engine_t*)` | Rebuild all DHT listeners (e.g. after a network change) |
| `void dna_engine_cancel_all_outbox_listeners(dna_engine_t*)` | Cancel all outbox listeners |
| `void dna_engine_cancel_contact_request_listener(dna_engine_t*)` | Cancel the contact-request listener |
| `void dna_engine_cancel_ack_listener(dna_engine_t*, const char *contact_fingerprint)` | Cancel one ack listener |
| `void dna_engine_cancel_all_ack_listeners(dna_engine_t*)` | Cancel all ack listeners |
| `int dna_engine_subscribe_all_groups(dna_engine_t*)` | Subscribe to all group keys |
| `void dna_engine_unsubscribe_all_groups(dna_engine_t*)` | Unsubscribe from all groups |
| `int dna_engine_listen_all_channels(dna_engine_t*)` | Start listeners for all subscribed channels (channels currently DISABLED) |
| `int dna_engine_start_channel_listener(dna_engine_t*, const char *channel_uuid)` | Start one channel listener |
| `void dna_engine_cancel_channel_listener(dna_engine_t*, const char *channel_uuid)` | Cancel one channel listener |
| `void dna_engine_cancel_all_channel_listeners(dna_engine_t*)` | Cancel all channel listeners |
| `int dna_engine_check_group_day_rotation(dna_engine_t*)` | Rotate group day-bucket listeners |
| `int dna_engine_check_outbox_day_rotation(dna_engine_t*)` | Rotate outbox day-bucket listeners |
| `int dna_engine_check_channel_day_rotation(dna_engine_t*)` | Rotate channel day-bucket listeners |
| `void dna_engine_log_active_listeners(dna_engine_t*)` | Debug: log the current active listeners |

### Helpers

| Function | Description |
|----------|-------------|
| `int dna_scan_identities(const char*, char***, int*)` | Scan for identity files |
| `void dna_free_task_params(dna_task_t*)` | Free task parameters |

---

*Module coverage: all 22 engine modules in `src/api/engine/` are represented above. Last reconciled against source 2026-07-08.*
