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
| `void dna_handle_wall_add_comment(dna_engine_t*, dna_task_t*)` | Handle wall add comment task (`TASK_WALL_ADD_COMMENT`, v0.7.0+) |
| `void dna_handle_wall_get_comments(dna_engine_t*, dna_task_t*)` | Handle wall get comments task (`TASK_WALL_GET_COMMENTS`, v0.7.0+) |

### Wall Listeners (v0.7.3+)

| Function | Description |
|----------|-------------|
| `size_t dna_engine_start_wall_listener(dna_engine_t*, const char*)` | Start DHT listener for contact's wall changes |
| `void dna_engine_cancel_wall_listener(dna_engine_t*, const char*)` | Cancel single wall listener |
| `void dna_engine_cancel_all_wall_listeners(dna_engine_t*)` | Cancel all wall listeners |

### Helpers

| Function | Description |
|----------|-------------|
| `int dna_scan_identities(const char*, char***, int*)` | Scan for identity files |
| `void dna_free_task_params(dna_task_t*)` | Free task parameters |
