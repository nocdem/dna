# Public API Functions

**File:** `include/dna/dna_engine.h`

The main public API for DNA Messenger. All UI/FFI bindings use these functions.

---

## 1.1 Lifecycle

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_version(void)` | Get DNA Messenger version string |
| `const char* dna_engine_error_string(int error)` | Get human-readable error message |
| `dna_engine_t* dna_engine_create(const char *data_dir)` | Create engine instance and spawn worker threads |
| `void dna_engine_set_event_callback(dna_engine_t*, dna_event_cb, void*)` | Set event callback for pushed events |
| `void dna_engine_destroy(dna_engine_t *engine)` | Destroy engine and release all resources |
| `const char* dna_engine_get_fingerprint(dna_engine_t *engine)` | Get current identity fingerprint |

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
| `dna_request_id_t dna_engine_check_offline_messages(...)` | Force check for offline messages |
| `int dna_engine_delete_message_sync(...)` | Delete message from local database |
| `int dna_engine_retry_pending_messages(...)` | Retry all pending/failed messages |
| `int dna_engine_retry_message(...)` | Retry single failed message by ID |
| `int dna_engine_get_unread_count(...)` | Get unread message count (sync) |
| `dna_request_id_t dna_engine_mark_conversation_read(...)` | Mark all messages as read |

## 1.6 Groups

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_get_groups(...)` | Get groups current identity belongs to |
| `dna_request_id_t dna_engine_create_group(...)` | Create new group with GSK encryption |
| `dna_request_id_t dna_engine_send_group_message(...)` | Send message to group |
| `dna_request_id_t dna_engine_get_invitations(...)` | Get pending group invitations |
| `dna_request_id_t dna_engine_accept_invitation(...)` | Accept group invitation |
| `dna_request_id_t dna_engine_reject_invitation(...)` | Reject group invitation |

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
| `dna_request_id_t dna_engine_sync_group_by_uuid(...)` | Sync specific group by UUID from DHT |
| `int dna_engine_request_turn_credentials(dna_engine_t*, int)` | Request TURN relay credentials |
| `dna_request_id_t dna_engine_get_registered_name(...)` | Get registered name for current identity |
| `void dna_engine_pause_presence(dna_engine_t*)` | Pause presence updates (app backgrounded) |
| `void dna_engine_resume_presence(dna_engine_t*)` | Resume presence updates (app foregrounded) |
| `int dna_engine_network_changed(dna_engine_t*)` | Reinitialize DHT after network change (WiFi↔Cellular) |

## 1.9 Outbox Listeners

| Function | Description |
|----------|-------------|
| `size_t dna_engine_listen_outbox(dna_engine_t*, const char*)` | Start listening for updates to contact's outbox |
| `void dna_engine_cancel_outbox_listener(dna_engine_t*, const char*)` | Cancel outbox listener |
| `int dna_engine_listen_all_contacts(dna_engine_t*)` | Start listeners for all contacts (outbox + presence) |
| `void dna_engine_cancel_all_outbox_listeners(dna_engine_t*)` | Cancel all outbox listeners |

## 1.10 Presence Listeners

| Function | Description |
|----------|-------------|
| `size_t dna_engine_start_presence_listener(dna_engine_t*, const char*)` | Start listening for contact's presence updates |
| `void dna_engine_cancel_presence_listener(dna_engine_t*, const char*)` | Cancel presence listener for contact |
| `void dna_engine_cancel_all_presence_listeners(dna_engine_t*)` | Cancel all presence listeners |

## 1.11 Delivery Trackers

| Function | Description |
|----------|-------------|
| `int dna_engine_track_delivery(dna_engine_t*, const char*)` | Start tracking delivery for recipient |
| `void dna_engine_untrack_delivery(dna_engine_t*, const char*)` | Stop tracking delivery |
| `void dna_engine_cancel_all_delivery_trackers(dna_engine_t*)` | Cancel all delivery trackers |

## 1.12 Feed (DNA Board)

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_get_feed_channels(...)` | Get all feed channels from DHT |
| `dna_request_id_t dna_engine_create_feed_channel(...)` | Create a new feed channel |
| `dna_request_id_t dna_engine_init_default_channels(...)` | Initialize default channels |
| `dna_request_id_t dna_engine_get_feed_posts(...)` | Get posts for a channel |
| `dna_request_id_t dna_engine_create_feed_post(...)` | Create a new post |
| `dna_request_id_t dna_engine_add_feed_comment(...)` | Add comment to post |
| `dna_request_id_t dna_engine_get_feed_comments(...)` | Get comments for post |
| `dna_request_id_t dna_engine_cast_feed_vote(...)` | Vote on a post |
| `dna_request_id_t dna_engine_get_feed_votes(...)` | Get vote counts for post |
| `dna_request_id_t dna_engine_cast_comment_vote(...)` | Vote on a comment |
| `dna_request_id_t dna_engine_get_comment_votes(...)` | Get vote counts for comment |

## 1.13 Backward Compatibility

| Function | Description |
|----------|-------------|
| `void* dna_engine_get_messenger_context(dna_engine_t*)` | Get underlying messenger context |
| `void* dna_engine_get_dht_context(dna_engine_t*)` | Get DHT context |
| `int dna_engine_is_dht_connected(dna_engine_t*)` | Check if DHT is connected |

## 1.14 Log Configuration

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_log_level(void)` | Get current log level |
| `int dna_engine_set_log_level(const char *level)` | Set log level |
| `const char* dna_engine_get_log_tags(void)` | Get log tags filter |
| `int dna_engine_set_log_tags(const char *tags)` | Set log tags filter |

## 1.15 Memory Management

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
| `void dna_free_feed_channels(dna_channel_info_t*, int)` | Free feed channels array |
| `void dna_free_feed_posts(dna_post_info_t*, int)` | Free feed posts array |
| `void dna_free_feed_post(dna_post_info_t*)` | Free single feed post |
| `void dna_free_feed_comments(dna_comment_info_t*, int)` | Free feed comments array |
| `void dna_free_feed_comment(dna_comment_info_t*)` | Free single feed comment |
| `void dna_free_profile(dna_profile_t*)` | Free profile |

## 1.16 Global Engine Access

| Function | Description |
|----------|-------------|
| `void dna_engine_set_global(dna_engine_t*)` | Set global engine instance |
| `dna_engine_t* dna_engine_get_global(void)` | Get global engine instance |
| `void dna_dispatch_event(dna_engine_t*, const dna_event_t*)` | Dispatch event to Flutter/GUI layer |

## 1.17 Debug Log API

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

## 1.18 Message Backup/Restore

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_backup_messages(...)` | Backup all messages to DHT |
| `dna_request_id_t dna_engine_restore_messages(...)` | Restore messages from DHT |

## 1.19 Version Check API

| Function | Description |
|----------|-------------|
| `int dna_engine_publish_version(engine, lib_ver, lib_min, app_ver, app_min, nodus_ver, nodus_min)` | Publish version info to DHT (signed with loaded identity) |
| `int dna_engine_check_version_dht(engine, result_out)` | Check version info from DHT and compare with local |

**Structures:**
- `dna_version_info_t` - Version info from DHT (library/app/nodus current+minimum, publisher, timestamp)
- `dna_version_check_result_t` - Check result with update_available flags
