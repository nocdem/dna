# Public API Functions

**File:** `include/dna/dna_engine.h`

The main public API for DNA Connect. All UI/FFI bindings use these functions.

---

## 1.1 Lifecycle

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_version(void)` | Get DNA Connect version string |
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
| `dna_request_id_t dna_engine_delete_message(engine, message_id, contact_fp, cb, ud)` | Delete single message with DHT cleanup + cross-device sync |
| `dna_request_id_t dna_engine_delete_conversation(engine, contact_fp, cb, ud)` | Delete all messages with contact (conversation purge) |
| `dna_request_id_t dna_engine_delete_all_messages(engine, cb, ud)` | Delete all messages across all contacts (purge everything) |
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
| `int dna_engine_queue_group_message(engine, group_uuid, message)` | Queue group message (fire-and-forget, returns immediately) |
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
| `dna_request_id_t dna_engine_send_tokens(...)` | Send tokens (build tx, sign, submit). Network param: "Cellframe" is canonical (was "Backbone"); "Backbone" still accepted via strcasecmp fallback |
| `dna_request_id_t dna_engine_get_tx_status(engine, tx_hash, chain, cb, user_data)` | Get TX verification status from blockchain (cached) |
| `dna_request_id_t dna_engine_get_transactions(...)` | Get transaction history |
| `dna_request_id_t dna_engine_dex_quote(engine, from, to, amount, filter, cb, ud)` | Get DEX swap quotes (Jupiter/Uniswap/Cellframe) |
| `dna_request_id_t dna_engine_dex_list_pairs(engine, cb, ud)` | List available DEX swap pairs |
| `dna_request_id_t dna_engine_dex_swap(engine, wallet_idx, from, to, amount, cb, ud)` | Execute DEX swap (Solana via Jupiter) |

## 1.8 P2P & Presence

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_refresh_presence(...)` | Trigger batch presence query via Nodus server TCP (v0.9.0+, replaces DHT PUT) |
| `bool dna_engine_is_peer_online(dna_engine_t*, const char*)` | Check if peer is online (from presence cache) |
| `dna_request_id_t dna_engine_lookup_presence(...)` | Read peer presence from local cache (populated by batch TCP query, v0.9.0+) |
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
| `int dna_engine_listen_all_contacts(dna_engine_t*)` | Start all listeners (outbox + watermark), waits for DHT ready. Presence listeners removed (v0.9.0+, Nodus-native). |
| `void dna_engine_cancel_all_outbox_listeners(dna_engine_t*)` | Cancel all outbox listeners |
| `int dna_engine_refresh_listeners(dna_engine_t*)` | Refresh all DHT listeners |

## 1.10 Channels (RSS-like Public Channels)

> **Status:** Soft-disabled since 2026-03-28 (ifdef-guarded, `DNA_CHANNELS_ENABLED`). Declarations kept; runtime paths inert. Functions below are listed for API compatibility only; calling them is a no-op until the subsystem is re-enabled.

Named channels with flat text posts. Open posting, day-bucket discovery.

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_channel_create(engine, name, description, is_public, cb, user_data)` | Create a new channel |
| `dna_request_id_t dna_engine_channel_get(engine, uuid, cb, user_data)` | Get channel info by UUID |
| `dna_request_id_t dna_engine_channel_delete(engine, uuid, cb, user_data)` | Delete a channel (creator only) |
| `dna_request_id_t dna_engine_channel_discover(engine, days_back, cb, user_data)` | Discover channels by scanning recent day-buckets |
| `dna_request_id_t dna_engine_channel_post(engine, channel_uuid, body, cb, user_data)` | Post a message to a channel |
| `dna_request_id_t dna_engine_channel_get_posts(engine, channel_uuid, days_back, cb, user_data)` | Get posts from a channel (daily buckets, default 3 days, max 30) |
| `dna_request_id_t dna_engine_channel_get_subscriptions(engine, cb, user_data)` | Get all channel subscriptions from local DB |
| `dna_request_id_t dna_engine_channel_sync_subs_to_dht(engine, cb, user_data)` | Sync subscription list to DHT (multi-device backup) |
| `dna_request_id_t dna_engine_channel_sync_subs_from_dht(engine, cb, user_data)` | Sync subscriptions from DHT (restore on new device) |
| `int dna_engine_channel_subscribe(engine, uuid)` | Subscribe to a channel (sync) |
| `int dna_engine_channel_unsubscribe(engine, uuid)` | Unsubscribe from a channel (sync) |
| `bool dna_engine_channel_is_subscribed(engine, uuid)` | Check if subscribed to a channel (sync) |
| `int dna_engine_channel_mark_read(engine, uuid)` | Mark a channel as read (sync) |
| `void dna_free_channel_info(dna_channel_info_t*)` | Free single channel info |
| `void dna_free_channel_infos(dna_channel_info_t*, int)` | Free channel infos array |

**Structures and Types:**

| Type | Description |
|------|-------------|
| `dna_channel_info_t` | Channel info struct (uuid, name, description, creator fingerprint, created_at, is_public) |
| `dna_channel_post_info_t` | Channel post info struct (uuid, channel_uuid, author fingerprint, body, timestamp) |
| `dna_channel_subscription_info_t` | Channel subscription info struct (channel_uuid, channel_name, subscribed_at, last_read) |

**Events:**

| Constant | Description |
|----------|-------------|
| `DNA_EVENT_CHANNEL_NEW_POST` | New post received in a subscribed channel |
| `DNA_EVENT_CHANNEL_SUBS_SYNCED` | Channel subscriptions synced from DHT |

## 1.11 Wall API

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_wall_post(dna_engine_t *engine, const char *text, dna_wall_post_cb callback, void *user_data)` | Post to own wall |
| `dna_request_id_t dna_engine_wall_post_with_image(dna_engine_t *engine, const char *text, const char *image_path, dna_wall_post_cb callback, void *user_data)` | Post to own wall with an attached image |
| `dna_request_id_t dna_engine_wall_delete(dna_engine_t *engine, const char *post_uuid, dna_completion_cb callback, void *user_data)` | Delete own wall post |
| `dna_request_id_t dna_engine_wall_load(dna_engine_t *engine, const char *fingerprint, dna_wall_posts_cb callback, void *user_data)` | Load user's wall posts |
| `dna_request_id_t dna_engine_wall_timeline(dna_engine_t *engine, dna_wall_posts_cb callback, void *user_data)` | Load timeline (all contacts' walls merged) |
| `dna_request_id_t dna_engine_wall_timeline_cached(dna_engine_t *engine, const char *fingerprint, dna_wall_posts_cb callback, void *user_data)` | Load timeline from local cache only (no identity/DHT required) |
| `dna_request_id_t dna_engine_wall_add_comment(dna_engine_t *engine, const char *post_uuid, const char *parent_comment_uuid, const char *text, dna_wall_comment_cb callback, void *user_data)` | Add a comment or reply to a wall post (parent_comment_uuid = NULL for top-level, UUID for reply) |
| `dna_request_id_t dna_engine_wall_get_comments(dna_engine_t *engine, const char *post_uuid, dna_wall_comments_cb callback, void *user_data)` | Fetch all comments for a wall post |
| `dna_request_id_t dna_engine_wall_like(dna_engine_t *engine, const char *post_uuid, dna_wall_likes_cb callback, void *user_data)` | Like a wall post (signed with Dilithium5, max 100 per post) |
| `dna_request_id_t dna_engine_wall_get_likes(dna_engine_t *engine, const char *post_uuid, dna_wall_likes_cb callback, void *user_data)` | Fetch all likes for a wall post |
| `dna_request_id_t dna_engine_wall_get_engagement(dna_engine_t *engine, const char **post_uuids, int post_count, dna_wall_engagement_cb callback, void *user_data)` | Batch fetch engagement (comments + like count) for multiple posts. Uses get_batch + count_batch (2 requests instead of N*2). Max 32 posts. (v0.9.124+) |
| `dna_request_id_t dna_engine_wall_get_engagement_cached(dna_engine_t *engine, const char **post_uuids, int post_count, dna_wall_engagement_cb callback, void *user_data)` | Cache-only variant — returns SQLite-cached counts immediately, skips DHT phase. Use for first-paint enrichment. (v0.10.7+) |
| `dna_request_id_t dna_engine_wall_load_day(dna_engine_t *engine, const char *fingerprint, const char *date_str, dna_wall_posts_cb callback, void *user_data)` | Load a single day's wall bucket from DHT (v0.9.141+). Used for lazy-loading older days on scroll. |
| `void dna_free_wall_posts(dna_wall_post_info_t *posts, int count)` | Free wall posts array |
| `void dna_free_wall_comments(dna_wall_comment_info_t *comments, int count)` | Free wall comments array |
| `void dna_free_wall_likes(dna_wall_like_info_t *likes, int count)` | Free wall likes array |
| `void dna_free_wall_engagement(dna_wall_engagement_t *engagements, int count)` | Free engagement array (v0.9.124+) |

**Structures and Types:**

| Type | Description |
|------|-------------|
| `dna_wall_post_info_t` | Wall post info struct; includes `char *image_json` field for attached image metadata |
| `dna_wall_comment_info_t` | Wall comment info struct (uuid, post_uuid, parent_comment_uuid, author_fp, text, timestamp) |
| `dna_wall_like_info_t` | Wall like info struct (author_fingerprint, author_name, timestamp, verified) |
| `dna_wall_engagement_t` | Per-post engagement: comments array + comment_count + like_count + is_liked_by_me (v0.9.124+) |
| `dna_wall_comment_cb` | Callback for a single wall comment result: `void (*)(dna_wall_comment_info_t *comment, int error, void *user_data)` |
| `dna_wall_comments_cb` | Callback for a list of wall comments: `void (*)(dna_wall_comment_info_t *comments, int count, int error, void *user_data)` |
| `dna_wall_likes_cb` | Callback for a list of wall likes: `void (*)(dna_wall_like_info_t *likes, int count, int error, void *user_data)` |

## 1.12 Follow API (v0.9.126+)

One-directional follow system. No approval needed, private to owner.

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_follow(engine, fingerprint, cb, user_data)` | Follow a user (one-directional, no approval) |
| `dna_request_id_t dna_engine_unfollow(engine, fingerprint, cb, user_data)` | Unfollow a user |
| `dna_request_id_t dna_engine_get_following(engine, cb, user_data)` | Get list of followed users |
| `void dna_free_following(dna_following_t*, int)` | Free following list |
| `dna_request_id_t dna_engine_sync_following_to_dht(engine, cb, user_data)` | Push follow list to DHT (encrypted) |
| `dna_request_id_t dna_engine_sync_following_from_dht(engine, cb, user_data)` | Pull follow list from DHT (restore) |

**Data Types:**
| Type | Description |
|------|-------------|
| `dna_following_t` | Following entry: `fingerprint[129]`, `followed_at` (uint64_t) |
| `dna_following_cb` | Callback: `void (*)(req_id, error, dna_following_t *following, int count, void *user_data)` |

**Notes:**
- Follow list is private (encrypted with owner's Kyber1024 key in DHT)
- Followed users' wall posts appear in timeline alongside contacts
- DHT key: `SHA3-512(identity + ":followlist")`
- BIP39 seed recovery restores follow list from DHT

## 1.13 Media Storage (v0.9.147+)

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_media_upload(engine, data, data_len, content_hash, media_type, encrypted, ttl, callback, user_data)` | Upload media to DHT. Computes SHA3-512 content hash, chunks (4MB), stores via Nodus. Max 64MB. |
| `dna_request_id_t dna_engine_media_download(engine, content_hash, callback, user_data)` | Download media from DHT. Reassembles chunks into contiguous buffer. |
| `dna_request_id_t dna_engine_media_exists(engine, content_hash, callback, user_data)` | Check if media exists on DHT (deduplication check). |

**Callback Types:**

| Type | Signature |
|------|-----------|
| `dna_media_upload_cb` | `void (*)(dna_request_id_t req_id, int error, const uint8_t *content_hash, void *user_data)` |
| `dna_media_download_cb` | `void (*)(dna_request_id_t req_id, int error, const uint8_t *data, size_t data_len, void *user_data)` |
| `dna_media_exists_cb` | `void (*)(dna_request_id_t req_id, int error, bool exists, void *user_data)` |

**Error Codes:** All three media operations return `DNA_ENGINE_ERROR_NOT_CONNECTED (-104)` if DHT is not yet connected (e.g., during startup before bootstrap completes). Flutter retries failed media downloads automatically when DHT connects.

## 1.14 Backward Compatibility

| Function | Description |
|----------|-------------|
| `void* dna_engine_get_messenger_context(dna_engine_t*)` | Get underlying messenger context |
| `int dna_engine_is_dht_connected(dna_engine_t*)` | Check if DHT is connected |

## 1.15 Log Configuration

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_log_level(void)` | Get current log level |
| `int dna_engine_set_log_level(const char *level)` | Set log level |
| `const char* dna_engine_get_log_tags(void)` | Get log tags filter |
| `int dna_engine_set_log_tags(const char *tags)` | Set log tags filter |

## 1.16 Memory Management

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
| `void dna_free_channel_info(dna_channel_info_t*)` | Free single channel info |
| `void dna_free_channel_infos(dna_channel_info_t*, int)` | Free channel infos array |
| `void dna_free_wall_posts(dna_wall_post_info_t*, int)` | Free wall posts array |
| `void dna_free_wall_comments(dna_wall_comment_info_t*, int)` | Free wall comments array |
| `void dna_free_profile(dna_profile_t*)` | Free profile |
| `void dna_free_addressbook_entries(dna_addressbook_entry_t*, int)` | Free address book entries array |

## 1.17 Global Engine Access

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

## 1.18 Debug Log API

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

## 1.19 Message Backup/Restore

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_backup_messages(...)` | Backup all messages to DHT |
| `dna_request_id_t dna_engine_restore_messages(...)` | Restore messages from DHT |
| `dna_request_id_t dna_engine_check_backup_exists(...)` | Check if backup exists for identity |

## 1.20 Version Check API

| Function | Description |
|----------|-------------|
| `int dna_engine_publish_version(engine, lib_ver, lib_min, app_ver, app_min, nodus_ver, nodus_min)` | Publish version info to DHT (signed with loaded identity) |
| `int dna_engine_check_version_dht(engine, result_out)` | Check version info from DHT and compare with local |

**Structures:**
- `dna_version_info_t` - Version info from DHT (library/app/nodus current+minimum, publisher, timestamp)
- `dna_version_check_result_t` - Check result with update_available flags + below_minimum flags (`library_below_minimum`, `app_below_minimum` — blocks app when true)

## 1.21 Signing API (for QR Auth)

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

## 1.22 Address Book (Wallet Addresses)

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

---

### DNAC Digital Cash (v0.9.175+)

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_dnac_get_balance(dna_engine_t *engine, dna_dnac_balance_cb callback, void *user_data)` | Get DNAC wallet balance (confirmed/pending/locked) |
| `dna_request_id_t dna_engine_dnac_send(dna_engine_t *engine, const char *recipient_fingerprint, uint64_t amount, const char *memo, dna_completion_cb callback, void *user_data)` | Send DNAC payment |
| `dna_request_id_t dna_engine_dnac_sync(dna_engine_t *engine, dna_completion_cb callback, void *user_data)` | Sync wallet from witnesses |
| `dna_request_id_t dna_engine_dnac_get_history(dna_engine_t *engine, dna_dnac_history_cb callback, void *user_data)` | Get transaction history |
| `dna_request_id_t dna_engine_dnac_get_utxos(dna_engine_t *engine, dna_dnac_utxos_cb callback, void *user_data)` | Get UTXO list |
| `dna_request_id_t dna_engine_dnac_estimate_fee(dna_engine_t *engine, uint64_t amount, dna_dnac_fee_cb callback, void *user_data)` | Estimate transaction fee |
| `void dna_engine_dnac_free_history(dna_dnac_history_t *history, int count)` | Free history array from callback |
| `void dna_engine_dnac_free_utxos(dna_dnac_utxo_t *utxos, int count)` | Free UTXO array from callback |
| `dna_request_id_t dna_engine_dnac_token_list(...)` | List all custom tokens from witnesses |
| `dna_request_id_t dna_engine_dnac_token_create(...)` | Create new token (burns 1 DNAC) |
| `dna_request_id_t dna_engine_dnac_token_balance(...)` | Get balance for specific token |
| `void dna_engine_dnac_free_tokens(dna_dnac_token_t *tokens, int count)` | Free token array |

**Data types:**
- `dna_dnac_balance_t` — `{uint64_t confirmed, pending, locked; int utxo_count}`
- `dna_dnac_history_t` — `{tx_hash[64], int type, counterparty[129], int64_t amount_delta, uint64_t fee/timestamp, memo[256]}`
- `dna_dnac_utxo_t` — `{tx_hash[64], uint32_t output_index, uint64_t amount, int status, uint64_t received_at}`
- `dna_dnac_token_t` — `{token_id[64], name[33], symbol[9], uint8_t decimals, int64_t supply, creator_fp[129]}`

**Notes:**
- Amounts are in raw units (1 token = 100,000,000 raw, 8 decimal places)
- Custom tokens may have different decimal places (0-18)
- DNAC context is lazy-initialized on first API call (no startup cost)
- Wallet syncs from witness servers (no DHT dependency)
- Thread-safe init via mutex
