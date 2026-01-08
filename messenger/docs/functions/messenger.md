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
| `int messenger_get_conversation(...)` | Get conversation messages |
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
| `int messenger_send_group_message(...)` | Send message to group |
| `int messenger_load_group_messages(...)` | Load group conversation messages |
| `void messenger_free_groups(group_info_t*, int)` | Free group array |

### 3.8 Group Symmetric Key (GSK)

**File:** `messenger/gsk.h`, `messenger/gsk_encryption.h`

GSK provides AES-256 symmetric encryption for group messaging (faster than per-recipient Kyber).
GSKs are now encrypted at rest using Kyber1024 KEM (H3 security fix).

| Function | Description |
|----------|-------------|
| `int gsk_init(void *backup_ctx)` | Initialize GSK subsystem |
| `int gsk_set_kem_keys(const uint8_t*, const uint8_t*)` | Set KEM keys for GSK encryption |
| `void gsk_clear_kem_keys(void)` | Clear KEM keys from memory |
| `int gsk_generate(const char*, uint32_t, uint8_t[32])` | Generate new random GSK |
| `int gsk_store(const char*, uint32_t, const uint8_t[32])` | Store GSK (encrypted with KEM) |
| `int gsk_load(const char*, uint32_t, uint8_t[32])` | Load GSK by version (decrypted) |
| `int gsk_load_active(const char*, uint8_t[32], uint32_t*)` | Load latest active GSK |
| `int gsk_rotate(const char*, uint32_t*, uint8_t[32])` | Rotate GSK (generate new version) |
| `int gsk_get_current_version(const char*, uint32_t*)` | Get current GSK version |
| `int gsk_cleanup_expired(void)` | Delete expired GSKs |
| `int gsk_rotate_on_member_add(...)` | Rotate GSK when member added |
| `int gsk_rotate_on_member_remove(...)` | Rotate GSK when member removed |
| `int gsk_encrypt(const uint8_t[32], const uint8_t*, uint8_t*)` | Encrypt GSK with KEM |
| `int gsk_decrypt(const uint8_t*, size_t, const uint8_t*, uint8_t[32])` | Decrypt GSK with KEM |

---

## 4. Message Backup

**File:** `message_backup.h`

Local SQLite database for message backup. Stores encrypted messages per-identity at `~/.dna/<fingerprint>_messages.db`.

### 4.1 Initialization

| Function | Description |
|----------|-------------|
| `message_backup_context_t* message_backup_init(const char *identity)` | Initialize message backup system |
| `void message_backup_close(message_backup_context_t *ctx)` | Close backup context |
| `void* message_backup_get_db(message_backup_context_t *ctx)` | Get SQLite database handle |

### 4.2 Message Storage

| Function | Description |
|----------|-------------|
| `int message_backup_save(...)` | Save encrypted message to local backup |
| `bool message_backup_exists_ciphertext(...)` | Check if message exists by ciphertext hash |
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

### 4.4 Conversation Retrieval

| Function | Description |
|----------|-------------|
| `int message_backup_get_conversation(...)` | Get conversation history with contact |
| `int message_backup_get_group_conversation(...)` | Get group conversation history |
| `int message_backup_get_recent_contacts(...)` | Get list of recent contacts |
| `int message_backup_search_by_identity(...)` | Search messages by sender/recipient |

### 4.5 Sequence Numbers (Watermark Pruning)

| Function | Description |
|----------|-------------|
| `uint64_t message_backup_get_next_seq(...)` | Get and increment next sequence number |
| `int message_backup_mark_delivered_up_to_seq(...)` | Mark messages delivered up to seq_num |
