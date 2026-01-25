# Messenger Functions

Core messenger functionality including identity management, key generation, messaging, groups, and message backup.

---

## 3. Messenger Core

**File:** `messenger.h`

### 3.1 Initialization

| Function | Description |
|----------|-------------|
| `messenger_context_t* messenger_init(const char *identity)` | Initialize messenger context |
| `void messenger_free(messenger_context_t *ctx)` | Free messenger context |
| `void messenger_set_session_password(...)` | Set session password for encrypted keys |
| `int messenger_load_dht_identity(const char *fingerprint)` | Load DHT identity and reinitialize |

### 3.2 Key Generation

| Function | Description |
|----------|-------------|
| `int messenger_generate_keys(messenger_context_t*, const char*)` | Generate new keypair for identity |
| `int messenger_generate_keys_from_seeds(...)` | Generate keys from BIP39 seeds (non-interactive) |
| `int messenger_register_name(...)` | Register human-readable name for fingerprint |
| `int messenger_restore_keys(messenger_context_t*, const char*)` | Restore keypair from BIP39 mnemonic |
| `int messenger_restore_keys_from_file(...)` | Restore keys from seed file |

### 3.3 Fingerprint Utilities

| Function | Description |
|----------|-------------|
| `int messenger_compute_identity_fingerprint(const char*, char*)` | Compute fingerprint from Dilithium5 key file |
| `bool messenger_is_fingerprint(const char *str)` | Check if string is valid fingerprint |
| `int messenger_get_display_name(...)` | Get display name for identity |
| `int messenger_find_key_path(const char*, const char*, const char*, char*)` | Find key file path (.dsa or .kem) |

### 3.4 Public Key Management

| Function | Description |
|----------|-------------|
| `int messenger_store_pubkey(...)` | Store public key in DHT keyserver |
| `int messenger_load_pubkey(...)` | Load public key from cache or DHT |
| `int messenger_get_contact_list(...)` | Get contact list |
| `int messenger_sync_contacts_to_dht(messenger_context_t*)` | Sync contacts to DHT |
| `int messenger_sync_contacts_from_dht(messenger_context_t*)` | Sync contacts from DHT |
| `int messenger_contacts_auto_sync(messenger_context_t*)` | Auto-sync contacts on first access |

### 3.5 Message Operations

| Function | Description |
|----------|-------------|
| `int messenger_send_message(...)` | Send message to recipients |
| `int messenger_list_messages(messenger_context_t*)` | List messages for current user |
| `int messenger_list_sent_messages(messenger_context_t*)` | List sent messages |
| `int messenger_read_message(messenger_context_t*, int)` | Read and decrypt message |
| `int messenger_decrypt_message(...)` | Decrypt message and return plaintext |
| `int messenger_delete_message(messenger_context_t*, int)` | Delete message |
| `int messenger_search_by_sender(...)` | Search messages by sender |
| `int messenger_show_conversation(...)` | Show conversation with user |
| `int messenger_get_conversation(...)` | Get conversation messages (pre-decrypted, key loaded once) |
| `void messenger_free_messages(message_info_t*, int)` | Free message array |
| `int messenger_search_by_date(...)` | Search messages by date range |

### 3.6 Message Status

| Function | Description |
|----------|-------------|
| `int messenger_mark_delivered(messenger_context_t*, int)` | Mark message as delivered |
| `int messenger_mark_conversation_read(...)` | Mark conversation as read |

### 3.7 Group Management

| Function | Description |
|----------|-------------|
| `int messenger_create_group(...)` | Create a new group |
| `int messenger_get_groups(...)` | Get list of groups |
| `int messenger_get_group_info(...)` | Get group info by ID |
| `int messenger_get_group_members(...)` | Get members of group |
| `int messenger_add_group_member(...)` | Add member to group |
| `int messenger_remove_group_member(...)` | Remove member from group |
| `int messenger_leave_group(messenger_context_t*, int)` | Leave a group |
| `int messenger_delete_group(messenger_context_t*, int)` | Delete group (creator only) |
| `int messenger_update_group_info(...)` | Update group info |
| `int messenger_send_group_invitation(...)` | Send group invitation |
| `int messenger_accept_group_invitation(...)` | Accept group invitation |
| `int messenger_reject_group_invitation(...)` | Reject group invitation |
| `int messenger_sync_groups(messenger_context_t*)` | Sync groups from DHT |
| `int messenger_sync_groups_to_dht(messenger_context_t*)` | Sync groups to DHT (v0.5.26+) |
| `int messenger_restore_groups_from_dht(messenger_context_t*)` | Restore groups from DHT to local cache (v0.6.8+) |
| `int messenger_send_group_message(...)` | Send message to group |
| `void messenger_free_groups(group_info_t*, int)` | Free group array |

### 3.8 Group Encryption Key (GEK)

**File:** `messenger/gek.h`, `messenger/gek.c`

GEK provides AES-256 symmetric encryption for group messaging (faster than per-recipient Kyber).
GEKs are encrypted at rest using Kyber1024 KEM + AES-256-GCM.

| Function | Description |
|----------|-------------|
| `int gek_init(void *backup_ctx)` | Initialize GEK subsystem |
| `int gek_set_kem_keys(const uint8_t*, const uint8_t*)` | Set KEM keys for GEK encryption |
| `void gek_clear_kem_keys(void)` | Clear KEM keys from memory |
| `int gek_generate(const char*, uint32_t, uint8_t[32])` | Generate new random GEK |
| `int gek_store(const char*, uint32_t, const uint8_t[32])` | Store GEK (encrypted with KEM) |
| `int gek_load(const char*, uint32_t, uint8_t[32])` | Load GEK by version (decrypted) |
| `int gek_load_active(const char*, uint8_t[32], uint32_t*)` | Load latest active GEK |
| `int gek_rotate(const char*, uint32_t*, uint8_t[32])` | Rotate GEK (generate new version) |
| `int gek_get_current_version(const char*, uint32_t*)` | Get current GEK version |
| `int gek_cleanup_expired(void)` | Delete expired GEKs |
| `int gek_rotate_on_member_add(...)` | Rotate GEK when member added |
| `int gek_rotate_on_member_remove(...)` | Rotate GEK when member removed |
| `int gek_encrypt(const uint8_t[32], const uint8_t*, uint8_t*)` | Encrypt GEK with KEM |
| `int gek_decrypt(const uint8_t*, size_t, const uint8_t*, uint8_t[32])` | Decrypt GEK with KEM |

### 3.9 Initial Key Packet (IKP)

**File:** `messenger/gek.h`

IKP functions for distributing GEK to group members via Kyber1024 encryption.

| Function | Description |
|----------|-------------|
| `int ikp_build(...)` | Build Initial Key Packet for GEK distribution |
| `int ikp_extract(...)` | Extract GEK from received IKP |
| `int ikp_verify(...)` | Verify IKP signature (Dilithium5) |
| `size_t ikp_calculate_size(size_t member_count)` | Calculate expected IKP size |
| `int ikp_get_version(...)` | Get GEK version from IKP header |
| `int ikp_get_member_count(...)` | Get member count from IKP header |

### 3.10 GEK DHT Sync (Multi-Device) - v0.6.49+

**File:** `messenger/gek.h`, `messenger/gek.c`

GEK sync functions for multi-device synchronization via DHT. GEKs are exported (decrypted),
self-encrypted with the user's own Kyber1024 key, and published to DHT. Other devices can
fetch and import, eliminating the need for per-device IKP extraction.

| Function | Description |
|----------|-------------|
| `int gek_sync_to_dht(dht_ctx, identity, kyber_pub, kyber_priv, dilithium_pub, dilithium_priv)` | Export all local GEKs to DHT (self-encrypted) |
| `int gek_sync_from_dht(dht_ctx, identity, kyber_priv, dilithium_pub, imported_out)` | Fetch GEKs from DHT and import missing entries |
| `int gek_auto_sync(dht_ctx, identity, kyber_pub, kyber_priv, dilithium_pub, dilithium_priv)` | Auto-sync: fetch from DHT, then publish local |

**DHT Key:** `SHA3-512(fingerprint + ":geks")`
**Security:** Self-encrypted with Kyber1024, signed with Dilithium5
**Format:** JSON with base64-encoded GEKs, organized by group UUID

---

## 4. Message Backup

**File:** `message_backup.h`

Local SQLite database for message backup. Stores **plaintext** messages per-identity at `~/.dna/db/messages.db` (v14).

**v14 Schema Change:** Messages stored as plaintext (previously encrypted BLOB).
Database-level encryption (SQLCipher) planned for future.

### 4.1 Initialization

| Function | Description |
|----------|-------------|
| `message_backup_context_t* message_backup_init(const char *identity)` | Initialize message backup system |
| `void message_backup_close(message_backup_context_t *ctx)` | Close backup context |
| `void* message_backup_get_db(message_backup_context_t *ctx)` | Get SQLite database handle |

### 4.2 Message Storage

| Function | Description |
|----------|-------------|
| `int message_backup_save(ctx, sender, recipient, plaintext, sender_fp, timestamp, is_outgoing, group_id, message_type, offline_seq)` | Save plaintext message to local backup (v14) |
| `bool message_backup_exists(ctx, sender_fp, recipient, timestamp)` | Check if message exists (v14: by sender_fp+recipient+timestamp) |
| `int message_backup_delete(message_backup_context_t*, int)` | Delete message by ID |
| `void message_backup_free_messages(backup_message_t*, int)` | Free message array |

### 4.3 Message Status

| Function | Description |
|----------|-------------|
| `int message_backup_mark_delivered(message_backup_context_t*, int)` | Mark message as delivered |
| `int message_backup_mark_read(message_backup_context_t*, int)` | Mark message as read |
| `int message_backup_update_status(message_backup_context_t*, int, int)` | Update message status |
| `int message_backup_update_status_by_key(...)` | Update status by sender/recipient/timestamp |
| `int message_backup_get_last_id(message_backup_context_t*)` | Get last inserted message ID |
| `int message_backup_get_unread_count(...)` | Get unread count for contact |
| `int message_backup_increment_retry_count(message_backup_context_t*, int)` | Increment retry count for failed message |

### 4.4 Message Retry (Bulletproof Delivery)

| Function | Description |
|----------|-------------|
| `int message_backup_get_pending_messages(...)` | Get all PENDING/FAILED messages for retry (retry_count < max) |

**Message Status Values (v15: Simplified 4-State):**
| Status | Value | Icon | Meaning | Auto-Retry? |
|--------|-------|------|---------|-------------|
| PENDING | 0 | Clock | Queued locally, not yet published to DHT | Yes |
| SENT | 1 | Single ✓ | Successfully published to DHT | No |
| RECEIVED | 2 | Double ✓✓ | Recipient ACK'd (fetched messages) | No |
| FAILED | 3 | ✗ Error | Failed to publish (will auto-retry) | Yes |

**Status Flow (v15):** `PENDING(0) → SENT(1) → RECEIVED(2)`. On failure: `PENDING(0) → FAILED(3) → auto-retry → PENDING(0)`.

**v15 ACK System:** Replaces watermarks with simple per-contact ACK timestamps. When recipient syncs, they publish an ACK. Sender marks ALL sent messages as RECEIVED.

**Schema (v15):** `retry_count INTEGER DEFAULT 0` column tracks send attempts. Messages with `retry_count >= 10` are excluded from auto-retry. Retry functions are mutex-protected.

### 4.5 Conversation Retrieval

| Function | Description |
|----------|-------------|
| `int message_backup_get_conversation(...)` | Get all conversation history with contact (ASC order) |
| `int message_backup_get_conversation_page(ctx, contact, limit, offset, msgs_out, count_out, total_out)` | Get paginated conversation (DESC order, newest first) |
| `int message_backup_get_group_conversation(...)` | Get group conversation history |
| `int message_backup_get_recent_contacts(...)` | Get list of recent contacts |
| `int message_backup_search_by_identity(...)` | Search messages by sender/recipient |

**Pagination:** Use `message_backup_get_conversation_page()` for efficient loading in chat UIs. Returns messages in DESC order (newest first) with `total_out` for calculating has_more. Default page size: 50 messages.

### 4.6 ACK System (v15: Replaces Watermarks)

| Function | Description |
|----------|-------------|
| `int message_backup_mark_received_for_contact(ctx, recipient_fp)` | Mark all SENT messages to contact as RECEIVED (v15 ACK callback) |

**Note:** v15 removed seq_num tracking functions (`get_next_seq`, `get_max_sent_seq`, `mark_delivered_up_to_seq`). The new ACK system uses simple per-contact timestamps instead of per-message sequence numbers.
