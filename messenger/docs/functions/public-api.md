# Public API Functions

**File:** `include/dna/dna_engine.h`

The main public API for DNA Messenger. All UI/FFI bindings use these functions.

---

## 1.1 Lifecycle

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_version(void)` | Get DNA Messenger version string |
| `const char* dna_engine_error_string(int error)` | Get human-readable error message |
| `dna_engine_t* dna_engine_create(const char *data_dir)` | Create engine instance and spawn worker threads (blocking) |
| `void dna_engine_create_async(const char *data_dir, dna_engine_created_cb cb, void *user_data, _Atomic bool *cancelled)` | Create engine asynchronously (non-blocking) |
| `void dna_engine_set_event_callback(dna_engine_t*, dna_event_cb, void*)` | Set event callback for pushed events |
| `void dna_engine_destroy(dna_engine_t *engine)` | Destroy engine and release all resources |
| `const char* dna_engine_get_fingerprint(dna_engine_t *engine)` | Get current identity fingerprint |
| `void dna_free_event(dna_event_t *event)` | Free event structure from async callbacks |

## 1.2 Identity Management

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_list_identities(...)` | List available identities from ~/.dna |
| `dna_request_id_t dna_engine_create_identity(...)` | Create new identity from BIP39 seeds |
| `int dna_engine_create_identity_sync(...)` | Create identity synchronously (blocking) |
| `int dna_engine_restore_identity_sync(...)` | Restore identity from BIP39 seeds without DHT name |
| `int dna_engine_delete_identity_sync(...)` | Delete identity and all local data |
| `bool dna_engine_has_identity(...)` | Check if identity exists (v0.3.0 single-user) |
| `dna_request_id_t dna_engine_load_identity(...)` | Load and activate identity, bootstrap DHT |
| `dna_request_id_t dna_engine_load_identity_minimal(...)` | Load identity with minimal init - DHT + polling only, no presence/listeners (v0.6.15+) |
| `bool dna_engine_is_identity_loaded(...)` | Check if identity is currently loaded (v0.5.24+) |
| `bool dna_engine_is_transport_ready(...)` | Check if transport layer is initialized (v0.5.26+) |
| `dna_request_id_t dna_engine_register_name(...)` | Register human-readable name in DHT |
| `dna_request_id_t dna_engine_get_display_name(...)` | Lookup display name for fingerprint |
| `dna_request_id_t dna_engine_get_avatar(...)` | Get avatar for fingerprint |
| `dna_request_id_t dna_engine_lookup_name(...)` | Lookup name availability (name -> fingerprint) |
| `dna_request_id_t dna_engine_get_profile(...)` | Get current identity's profile from DHT |
| `dna_request_id_t dna_engine_lookup_profile(...)` | Lookup any user's profile by fingerprint |
| `dna_request_id_t dna_engine_refresh_contact_profile(...)` | Force refresh contact's profile from DHT (bypass cache) |
| `dna_request_id_t dna_engine_update_profile(...)` | Update current identity's profile in DHT |
| `int dna_engine_get_mnemonic(...)` | Get encrypted mnemonic (recovery phrase) |
| `int dna_engine_change_password_sync(...)` | Change password for identity keys |
| `int dna_engine_prepare_dht_from_mnemonic(dna_engine_t*, const char *mnemonic)` | Prepare DHT keys from mnemonic before identity load |

## 1.3 Contacts

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_get_contacts(...)` | Get contact list from local database |
| `dna_request_id_t dna_engine_add_contact(...)` | Add contact by fingerprint or registered name |
| `dna_request_id_t dna_engine_remove_contact(...)` | Remove contact |
| `int dna_engine_set_contact_nickname_sync(engine, fingerprint, nickname)` | Set local nickname for contact (sync) |

## 1.4 Contact Requests (ICQ-Style)

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_send_contact_request(...)` | Send contact request to another user |
| `dna_request_id_t dna_engine_get_contact_requests(...)` | Get pending incoming contact requests |
| `int dna_engine_get_contact_request_count(dna_engine_t*)` | Get count of pending requests (sync) |
| `dna_request_id_t dna_engine_approve_contact_request(...)` | Approve a contact request |
| `dna_request_id_t dna_engine_deny_contact_request(...)` | Deny a contact request |
| `dna_request_id_t dna_engine_block_user(...)` | Block a user permanently |
| `dna_request_id_t dna_engine_unblock_user(...)` | Unblock a user |
| `dna_request_id_t dna_engine_get_blocked_users(...)` | Get list of blocked users |
| `bool dna_engine_is_user_blocked(dna_engine_t*, const char*)` | Check if a user is blocked (sync) |

## 1.5 Messaging

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_send_message(...)` | Send message to contact (P2P + DHT fallback) |
| `int dna_engine_queue_message(...)` | Queue message for async sending |
| `int dna_engine_get_message_queue_capacity(...)` | Get message queue capacity |
| `int dna_engine_get_message_queue_size(...)` | Get current message queue size |
| `int dna_engine_set_message_queue_capacity(...)` | Set message queue capacity |
| `dna_request_id_t dna_engine_get_conversation(...)` | Get conversation with contact |
| `dna_request_id_t dna_engine_get_conversation_page(...)` | Get conversation page (paginated, newest first) |
| `dna_request_id_t dna_engine_check_offline_messages(...)` | Force check for offline messages (publishes watermarks) |
| `dna_request_id_t dna_engine_check_offline_messages_cached(...)` | Check offline messages without publishing watermarks (v0.6.15+, for background service) |
| `dna_request_id_t dna_engine_check_offline_messages_from(...)` | Check offline messages from specific contact |
| `int dna_engine_delete_message_sync(...)` | Delete message from local database |
| `int dna_engine_retry_pending_messages(...)` | Retry all pending/failed messages |
| `int dna_engine_retry_message(...)` | Retry single failed message by ID |
| `int dna_engine_get_unread_count(...)` | Get unread message count (sync) |
| `dna_request_id_t dna_engine_mark_conversation_read(...)` | Mark all messages as read |

## 1.6 Groups

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_get_groups(...)` | Get groups current identity belongs to |
| `dna_request_id_t dna_engine_create_group(...)` | Create new group with GEK encryption |
| `dna_request_id_t dna_engine_send_group_message(...)` | Send message to group |
| `dna_request_id_t dna_engine_get_invitations(...)` | Get pending group invitations |
| `dna_request_id_t dna_engine_accept_invitation(...)` | Accept group invitation |
| `dna_request_id_t dna_engine_reject_invitation(...)` | Reject group invitation |
| `dna_request_id_t dna_engine_get_group_info(...)` | Get extended group info (name, GEK version, etc.) |
| `dna_request_id_t dna_engine_get_group_members(...)` | Get list of group members |
| `dna_request_id_t dna_engine_add_group_member(engine, group_uuid, fingerprint, cb, user_data)` | Add member to group (owner only, rotates GEK) |
| `dna_request_id_t dna_engine_remove_group_member(engine, group_uuid, fingerprint, cb, user_data)` | Remove member from group (owner only, rotates GEK) |
| `dna_request_id_t dna_engine_get_group_conversation(...)` | Get group conversation history |
| `void dna_free_group_info(dna_group_info_t*)` | Free group info struct |
| `void dna_free_group_members(dna_group_member_t*, int)` | Free group members array |

## 1.7 Wallet (Cellframe + Multi-Chain)

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_list_wallets(...)` | List Cellframe wallets |
| `dna_request_id_t dna_engine_get_balances(...)` | Get token balances for wallet |
| `int dna_engine_estimate_eth_gas(int, dna_gas_estimate_t*)` | Get gas fee estimate for ETH transaction |
| `dna_request_id_t dna_engine_send_tokens(...)` | Send tokens (build tx, sign, submit) |
| `dna_request_id_t dna_engine_get_transactions(...)` | Get transaction history |

## 1.8 P2P & Presence

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_refresh_presence(...)` | Refresh presence in DHT |
| `bool dna_engine_is_peer_online(dna_engine_t*, const char*)` | Check if peer is online |
| `dna_request_id_t dna_engine_lookup_presence(...)` | Lookup peer presence from DHT |
| `dna_request_id_t dna_engine_sync_contacts_to_dht(...)` | Sync contacts to DHT |
| `dna_request_id_t dna_engine_sync_contacts_from_dht(...)` | Sync contacts from DHT |
| `dna_request_id_t dna_engine_sync_groups(...)` | Sync groups from DHT |
| `dna_request_id_t dna_engine_sync_groups_to_dht(...)` | Sync groups to DHT (v0.5.26+) |
| `dna_request_id_t dna_engine_sync_group_by_uuid(...)` | Sync specific group by UUID from DHT |
| `dna_request_id_t dna_engine_restore_groups_from_dht(...)` | Restore groups from DHT backup |
| `dna_request_id_t dna_engine_get_registered_name(...)` | Get registered name for current identity |
| `void dna_engine_pause_presence(dna_engine_t*)` | Pause presence updates (app backgrounded) |
| `void dna_engine_resume_presence(dna_engine_t*)` | Resume presence updates (app foregrounded) |
| `int dna_engine_pause(dna_engine_t*)` | Pause engine for background mode - suspends listeners, keeps DHT alive (v0.6.50+) |
| `int dna_engine_resume(dna_engine_t*)` | Resume engine from background - resubscribes listeners (v0.6.50+) |
| `bool dna_engine_is_paused(dna_engine_t*)` | Check if engine is in paused state (v0.6.50+) |
| `int dna_engine_network_changed(dna_engine_t*)` | Reinitialize DHT after network change (WiFi↔Cellular) |

## 1.9 Outbox Listeners

| Function | Description |
|----------|-------------|
| `size_t dna_engine_listen_outbox(dna_engine_t*, const char*)` | Start listening for updates to contact's outbox |
| `void dna_engine_cancel_outbox_listener(dna_engine_t*, const char*)` | Cancel outbox listener |
| `int dna_engine_listen_all_contacts(dna_engine_t*)` | Start all listeners (outbox + presence + watermark), waits for DHT ready |
| `void dna_engine_cancel_all_outbox_listeners(dna_engine_t*)` | Cancel all outbox listeners |
| `int dna_engine_refresh_listeners(dna_engine_t*)` | Refresh all DHT listeners |

## 1.10 Watermark Listeners

| Function | Description |
|----------|-------------|
| `size_t dna_engine_start_watermark_listener(dna_engine_t*, const char*)` | Start persistent watermark listener for contact |
| `void dna_engine_cancel_all_watermark_listeners(dna_engine_t*)` | Cancel all watermark listeners |

## 1.11 Feed v2 (Topic-based Public Feeds)

Topic-based feeds with categories and tags. No voting (deferred).

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_feed_create_topic(engine, title, body, category, tags_json, cb, ud)` | Create topic with category/tags |
| `dna_request_id_t dna_engine_feed_get_topic(engine, uuid, cb, ud)` | Get topic by UUID |
| `dna_request_id_t dna_engine_feed_delete_topic(engine, uuid, cb, ud)` | Soft delete topic (author only) |
| `dna_request_id_t dna_engine_feed_add_comment(engine, topic_uuid, body, mentions_json, cb, ud)` | Add comment with @mentions |
| `dna_request_id_t dna_engine_feed_get_comments(engine, topic_uuid, cb, ud)` | Get comments for topic |
| `dna_request_id_t dna_engine_feed_get_category(engine, category, days_back, cb, ud)` | Get topics by category |
| `dna_request_id_t dna_engine_feed_get_all(engine, days_back, cb, ud)` | Get all topics (global feed) |

## 1.12 Backward Compatibility

| Function | Description |
|----------|-------------|
| `void* dna_engine_get_messenger_context(dna_engine_t*)` | Get underlying messenger context |
| `void* dna_engine_get_dht_context(dna_engine_t*)` | Get DHT context |
| `int dna_engine_is_dht_connected(dna_engine_t*)` | Check if DHT is connected |

## 1.13 Log Configuration

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_log_level(void)` | Get current log level |
| `int dna_engine_set_log_level(const char *level)` | Set log level |
| `const char* dna_engine_get_log_tags(void)` | Get log tags filter |
| `int dna_engine_set_log_tags(const char *tags)` | Set log tags filter |

## 1.14 Memory Management

| Function | Description |
|----------|-------------|
| `void dna_free_strings(char**, int)` | Free string array |
| `void dna_free_contacts(dna_contact_t*, int)` | Free contacts array |
| `void dna_free_messages(dna_message_t*, int)` | Free messages array |
| `void dna_free_groups(dna_group_t*, int)` | Free groups array |
| `void dna_free_invitations(dna_invitation_t*, int)` | Free invitations array |
| `void dna_free_contact_requests(dna_contact_request_t*, int)` | Free contact requests array |
| `void dna_free_blocked_users(dna_blocked_user_t*, int)` | Free blocked users array |
| `void dna_free_wallets(dna_wallet_t*, int)` | Free wallets array |
| `void dna_free_balances(dna_balance_t*, int)` | Free balances array |
| `void dna_free_transactions(dna_transaction_t*, int)` | Free transactions array |
| `void dna_free_feed_topic(dna_feed_topic_info_t*)` | Free single feed topic |
| `void dna_free_feed_topics(dna_feed_topic_info_t*, int)` | Free feed topics array |
| `void dna_free_feed_comment(dna_feed_comment_info_t*)` | Free single feed comment |
| `void dna_free_feed_comments(dna_feed_comment_info_t*, int)` | Free feed comments array |
| `void dna_free_profile(dna_profile_t*)` | Free profile |
| `void dna_free_addressbook_entries(dna_addressbook_entry_t*, int)` | Free address book entries array |

## 1.15 Global Engine Access

**v0.6.0+:** Global engine functions are deprecated. Each caller (Flutter/Service) owns its own engine.

| Function | Description |
|----------|-------------|
| `void dna_engine_set_global(dna_engine_t*)` | DEPRECATED: Set global engine instance |
| `dna_engine_t* dna_engine_get_global(void)` | DEPRECATED: Get global engine instance |
| `void dna_dispatch_event(dna_engine_t*, const dna_event_t*)` | Dispatch event to Flutter/GUI layer |

**Error Codes (v0.6.0+):**
| Code | Constant | Description |
|------|----------|-------------|
| -117 | `DNA_ENGINE_ERROR_IDENTITY_LOCKED` | Identity lock held by another process |

## 1.16 Debug Log API

| Function | Description |
|----------|-------------|
| `void dna_engine_debug_log_enable(bool enabled)` | Enable/disable debug log ring buffer |
| `bool dna_engine_debug_log_is_enabled(void)` | Check if debug logging is enabled |
| `int dna_engine_debug_log_get_entries(dna_debug_log_entry_t*, int)` | Get debug log entries |
| `int dna_engine_debug_log_count(void)` | Get number of log entries |
| `void dna_engine_debug_log_clear(void)` | Clear all debug log entries |
| `void dna_engine_debug_log_message(const char*, const char*)` | Add log message from external code |
| `void dna_engine_debug_log_message_level(const char*, const char*, int)` | Add log message with level (0=DEBUG,1=INFO,2=WARN,3=ERROR) |
| `int dna_engine_debug_log_export(const char *filepath)` | Export debug logs to file |

## 1.17 Message Backup/Restore

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_backup_messages(...)` | Backup all messages to DHT |
| `dna_request_id_t dna_engine_restore_messages(...)` | Restore messages from DHT |
| `dna_request_id_t dna_engine_check_backup_exists(...)` | Check if backup exists for identity |

## 1.18 Version Check API

| Function | Description |
|----------|-------------|
| `int dna_engine_publish_version(engine, lib_ver, lib_min, app_ver, app_min, nodus_ver, nodus_min)` | Publish version info to DHT (signed with loaded identity) |
| `int dna_engine_check_version_dht(engine, result_out)` | Check version info from DHT and compare with local |

**Structures:**
- `dna_version_info_t` - Version info from DHT (library/app/nodus current+minimum, publisher, timestamp)
- `dna_version_check_result_t` - Check result with update_available flags

## 1.19 Signing API (for QR Auth)

| Function | Description |
|----------|-------------|
| `int dna_engine_sign_data(engine, data, data_len, signature_out, sig_len_out)` | Sign arbitrary data with loaded identity's Dilithium5 key |
| `int dna_engine_get_signing_public_key(engine, pubkey_out, pubkey_out_len)` | Get the loaded identity's Dilithium5 signing public key |

**Notes:**
- `signature_out` must be at least 4627 bytes (Dilithium5 max signature size)
- `pubkey_out` must be at least 2592 bytes (Dilithium5 public key size)
- Used for QR-based authentication flows where app needs to prove identity to external services
- `sign_data` returns 0 on success, `DNA_ENGINE_ERROR_NO_IDENTITY` if no identity loaded
- `get_signing_public_key` returns bytes written (2592) on success, negative on error

**Protocol Documentation:** See [QR_AUTH.md](../QR_AUTH.md) for full QR authentication protocol specification (v1/v2/v3), payload formats, RP binding, and canonical signing.

## 1.20 Android Callbacks (v0.6.0+)

| Function | Description |
|----------|-------------|
| `void dna_engine_set_android_notification_callback(cb, user_data)` | Set callback for message notifications (when Flutter detached) |
| `void dna_engine_set_android_group_message_callback(cb, user_data)` | Set callback for group message notifications |
| `void dna_engine_set_android_contact_request_callback(cb, user_data)` | Set callback for contact request notifications |
| `void dna_engine_set_android_reconnect_callback(cb, user_data)` | Set DHT reconnection callback for foreground service (v0.6.8+) |

**Callback Types:**
- `dna_android_notification_cb(fingerprint, display_name, user_data)` - Message notification
- `dna_android_group_message_cb(group_uuid, group_name, count, user_data)` - Group message notification
- `dna_android_contact_request_cb(fingerprint, display_name, user_data)` - Contact request notification
- `dna_android_reconnect_cb(user_data)` - DHT reconnection (for MINIMAL listener recreation)

**Notes:**
- These callbacks are used by the Android foreground service for background notifications
- The reconnect callback (v0.6.8+) allows the service to recreate MINIMAL listeners after network changes
- When reconnect callback is set, the engine does NOT spawn its automatic FULL listener setup thread

## 1.21 Address Book (Wallet Addresses)

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_get_addressbook(...)` | Get all address book entries |
| `dna_request_id_t dna_engine_get_addressbook_by_network(...)` | Get entries filtered by network |
| `int dna_engine_add_address(engine, address, label, network, notes)` | Add address (returns -2 if exists) |
| `int dna_engine_update_address(engine, id, label, notes)` | Update address notes |
| `int dna_engine_remove_address(engine, id)` | Remove address by ID |
| `bool dna_engine_address_exists(engine, address, network)` | Check if address exists |
| `int dna_engine_lookup_address(engine, address, network, entry_out)` | Lookup address (returns 1 if not found) |
| `int dna_engine_increment_address_usage(engine, id)` | Increment usage counter |
| `dna_request_id_t dna_engine_get_recent_addresses(...)` | Get recently used addresses |
| `dna_request_id_t dna_engine_sync_addressbook_to_dht(...)` | Sync address book to DHT |
| `dna_request_id_t dna_engine_sync_addressbook_from_dht(...)` | Sync address book from DHT |

**Notes:**
- Address book stores wallet addresses for all supported networks (backbone, ethereum, solana, tron)
- Entries track usage count for "recently used" sorting
- DHT sync allows address book recovery across devices
