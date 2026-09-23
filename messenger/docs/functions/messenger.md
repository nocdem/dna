# Messenger Functions

Core messenger functionality including identity management, key generation, messaging, groups, and message backup.

---

## 3. Messenger Core

**File:** `messenger.h`

### 3.1 Initialization

| Function | Description |
|----------|-------------|
| `messenger_context_t* messenger_init(const char *identity, const char *db_key)` | Initialize messenger context (db_key for SQLCipher encryption) |
| `void messenger_free(messenger_context_t *ctx)` | Free messenger context |
| `void messenger_set_session_password(...)` | Set session password for encrypted keys |
| `int messenger_load_dht_identity(const char *fingerprint)` | Load DHT identity and reinitialize |

### 3.2 Key Generation

| Function | Description |
|----------|-------------|
| `int messenger_generate_keys(messenger_context_t*, const char*)` | Generate new keypair for identity |
| `int messenger_generate_keys_from_seeds(const char *name, const uint8_t *signing_seed, const uint8_t *encryption_seed, const uint8_t *master_seed, const char *mnemonic, const char *data_dir, const char *password, char *fingerprint_out)` | Generate keys from BIP39 seeds (non-interactive). **Signature UNCHANGED. Behavior CHANGED (KEM Faz 1):** if `master_seed` is non-NULL, ALSO generates `identity.mlkem` (own domain-separated coins, independent of `encryption_seed`) and writes `mnemonic.v2.enc`. If `master_seed` is NULL — the ONLY caller that does this is the async `dna_engine_create_identity` path (`dna_handle_create_identity`, never sets `master_seed`; reachable from Android JNI) — ML-KEM creation is skipped with a WARN; the KEM Faz 1 migration path derives `identity.mlkem` from the mnemonic on the next identity load instead. |
| `int messenger_register_name(...)` | Register human-readable name for fingerprint. **Behavior CHANGED (KEM Faz 1):** loads `identity.mlkem` beside `identity.kem` (absent -> NULL, no error) and passes its pubkey to `dht_keyserver_publish` and `keyserver_cache_put` |
| `int messenger_restore_keys(messenger_context_t*, const char*)` | Restore keypair from BIP39 mnemonic (prompts via stdin) — calls `cmd_restore_key_from_seed` below |
| `int cmd_restore_key_from_seed(const char *name, const char *algo, const char *output_dir)` | Restore `<name>.dsa`/`<name>.kem` from a BIP39 mnemonic entered via stdin. **Signature UNCHANGED. Behavior CHANGED (KEM Faz 1):** now uses `qgp_derive_seeds_with_master()` (was `qgp_derive_seeds_from_mnemonic()`) to also obtain `master_seed`, and ALSO generates + saves `<name>.mlkem` (ML-KEM-1024) alongside; non-fatal on ML-KEM failure |
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
| `int messenger_store_pubkey(...)` | Store public key in DHT keyserver, via `dht_keyserver_publish` (KEM Faz 1: passes `mlkem_pubkey=NULL` — this restore-from-`.pub`-bundle path predates ML-KEM, no local ML-KEM key available at this call site) |
| `int messenger_load_pubkey(messenger_context_t*, const char*, uint8_t**, size_t*, uint8_t**, size_t*, char*)` | Load Dilithium5 + Kyber1024 (round-3) public key from cache or DHT. **Signature UNCHANGED — does NOT return mlkem_pubkey.** Callers that need it read it separately from `keyserver_cache_get()` (the cache was just warmed by this call) — see `messenger_send_message`/`messenger_flush_recipient_outbox` in `messages.c` (KEM Faz 1 sender-side alg gating) |
| `int messenger_get_contact_list(...)` | Get contact list |
| `int messenger_sync_contacts_to_dht(messenger_context_t*)` | Sync contacts to DHT |
| `int messenger_sync_contacts_from_dht(messenger_context_t*)` | Sync contacts from DHT |
| `int messenger_contacts_auto_sync(messenger_context_t*)` | Auto-sync contacts on first access |

### 3.5 Message Operations

| Function | Description |
|----------|-------------|
| `int messenger_send_message(...)` | Send message to recipients. **Behavior CHANGED (KEM Faz 1):** after resolving pubkeys via `messenger_load_pubkey`, ALSO checks `keyserver_cache_get()` (just warmed) for each recipient's `mlkem_pubkey`; alg 3 (ML-KEM-1024) is used ONLY if EVERY recipient (including self) has one, else alg 2 (round-3), all-or-nothing |
| `int messenger_flush_recipient_outbox(messenger_context_t *ctx, const char *recipient)` | Re-encrypt pending messages for a recipient and PUT the outbox blob. **Behavior CHANGED (KEM Faz 1):** same all-or-nothing alg gate as `messenger_send_message`, applied to the (sender, recipient) pair |
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

**Internal (KEM Faz 1):** `messenger_encrypt_multi_recipient()` (`static`,
`messages.c`) gained a `uint8_t alg` parameter (`QGP_KEY_TYPE_KEM1024` or
`QGP_KEY_TYPE_MLKEM1024`) — writes it into the Seal header's `enc_key_type`
byte and selects `qgp_kem1024_encapsulate` vs `qgp_mlkem1024_encapsulate` per
recipient entry. Both callers above (`messenger_send_message`,
`messenger_flush_recipient_outbox`) compute `alg` from the keyserver cache
before calling it.

### 3.5a Message Deletion

**File:** `messenger/messages.h`, `messenger/messages.c`

| Function | Description |
|----------|-------------|
| `int messenger_delete_message_full(messenger_context_t*, const char *fp, const char *hash, bool is_outgoing)` | Delete single message: local delete + outbox rebuild (if sent) + DELETE notice |
| `int messenger_delete_conversation_full(messenger_context_t*, const char *fp)` | Delete all messages with contact: batch delete + outbox rebuild + DELETE_CONVERSATION notice |
| `int messenger_delete_all_messages(messenger_context_t*)` | Delete all messages across all contacts |
| `int messenger_send_delete_notice(messenger_context_t*, const char *recipient_fp, int action, const char **hashes, int hash_count)` | Send DELETE notice message via outbox (encrypted, signed) |

**Types:**
| Type | Description |
|------|-------------|
| `delete_action_t` | Enum: `DELETE_SINGLE=0`, `DELETE_CONVERSATION=1`, `DELETE_ALL=2` |

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
| `int gek_set_kem_keys(const uint8_t*, const uint8_t*)` | Set round-3 (legacy) KEM keys for GEK encryption |
| `int gek_set_mlkem_keys(const uint8_t *mlkem_pubkey, const uint8_t *mlkem_privkey)` | **NEW (KEM Faz 1).** Set ML-KEM-1024 keys for GEK encryption; independent of `gek_set_kem_keys` |
| `int gek_get_mlkem_keys(uint8_t pub[1568], uint8_t priv[3168])` | **NEW (D17, M1 delta 1b-2).** Copy out the session ML-KEM-1024 keys `gek_set_mlkem_keys` populated; 0 on success, -1 if unset. Used by `gek_sync_to_dht`/`gek_sync_from_dht` to forward the session key into `dht_geks_publish`/`_fetch` (D12) instead of those functions doing their own by-path load |
| `void gek_clear_kem_keys(void)` | **CHANGED (KEM Faz 1):** clears BOTH the round-3 keys AND the ML-KEM-1024 keys |
| `int gek_generate(const char*, uint32_t, uint8_t[32])` | Generate new random GEK |
| `int gek_store(const char*, uint32_t, const uint8_t[32])` | Store GEK (encrypted with round-3 KEM, via `gek_encrypt`) |
| `int gek_load(const char*, uint32_t, uint8_t[32])` | Load GEK by version (decrypted, round-3) |
| `int gek_load_active(const char*, uint8_t[32], uint32_t*)` | Load latest active GEK |
| `int gek_rotate(const char*, uint32_t*, uint8_t[32])` | Rotate GEK (generate new version) |
| `int gek_get_current_version(const char*, uint32_t*)` | Get current GEK version |
| `int gek_cleanup_expired(void)` | Delete expired GEKs |
| `int gek_rotate_on_member_add(void *ctx, const char*, const char*)` | Rotate GEK when member added (ctx for session_password key load); builds IKP v3 iff every member has published ML-KEM (KEM Faz 1) |
| `int gek_rotate_on_member_remove(void *ctx, const char*, const char*)` | Rotate GEK when member removed (ctx for session_password key load); same v3 gate |
| `int gek_encrypt(const uint8_t[32], const uint8_t*, uint8_t*)` | Encrypt GEK with round-3 KEM. **Now a thin wrapper:** `gek_encrypt_alg(IKP_ALG_KYBER_R3, ...)` |
| `int gek_decrypt(const uint8_t*, size_t, const uint8_t*, uint8_t[32])` | Decrypt GEK with round-3 KEM. **Now a thin wrapper:** `gek_decrypt_alg(IKP_ALG_KYBER_R3, ...)` |
| `int gek_encrypt_alg(uint8_t alg, const uint8_t gek[32], const uint8_t pubkey[1568], uint8_t encrypted_out[GEK_ENC_TOTAL_SIZE])` | **NEW (KEM Faz 1).** `alg` = `IKP_ALG_KYBER_R3` (2) or `IKP_ALG_MLKEM1024` (3); wire layout unchanged (ct‖nonce‖tag‖enc, sizes byte-identical between algs) |
| `int gek_decrypt_alg(uint8_t alg, const uint8_t *encrypted, size_t encrypted_len, const uint8_t privkey[3168], uint8_t gek_out[32])` | **NEW (KEM Faz 1).** Counterpart decrypt |

### 3.9 Initial Key Packet (IKP)

**File:** `messenger/gek.h`

IKP functions for distributing GEK to group members. **v2** (unchanged, magic
`0x47454B32` "GEK2") encrypts every member entry with round-3 Kyber1024.
**v3** (KEM Faz 1, magic `0x47454B33` "GEK3") adds a per-member `alg` byte
(entry = fp(64)‖alg(1)‖ct(1568)‖wrapped(40), `IKP_MEMBER_ENTRY_SIZE_V3` =
1673) and is emitted by `ikp_build()` ONLY when EVERY `gek_member_entry_t` in
the call has a non-NULL `mlkem_pubkey` (all-or-nothing; one member without
one keeps the whole packet on v2). `gek_member_entry_t` gained a
`const uint8_t *mlkem_pubkey` field (nullable) alongside `kyber_pubkey`.

| Function | Description |
|----------|-------------|
| `int ikp_build(const char *group_uuid, uint32_t version, const uint8_t gek[GEK_KEY_SIZE], const uint8_t dht_salt[IKP_DHT_SALT_SIZE], const gek_member_entry_t *members, size_t member_count, const uint8_t *owner_dilithium_privkey, uint8_t **packet_out, size_t *packet_size_out)` | Build IKP; **CHANGED (KEM Faz 1):** chooses v2 or v3 per the all-or-nothing gate above (signature unchanged) |
| `int ikp_extract(...)` | Extract GEK from a received IKP. **Signature UNCHANGED** (kept for existing callers) — now a thin wrapper: `ikp_extract_alg(..., NULL)`. Still parses v2 AND v3 headers, but can only decapsulate a v3 entry whose alg is round-3 (no ML-KEM key slot in this signature) |
| `int ikp_extract_alg(const uint8_t *packet, size_t packet_size, const uint8_t *my_fingerprint_bin, const uint8_t *my_kyber_privkey, const uint8_t *my_mlkem_privkey, uint8_t gek_out[GEK_KEY_SIZE], uint32_t *version_out, uint8_t dht_salt_out[IKP_DHT_SALT_SIZE])` | **NEW (KEM Faz 1).** Accepts v2 and v3; dispatches decapsulation by the found entry's alg byte (v2 entries are implicitly alg 2). `my_mlkem_privkey` nullable — an alg=3 entry without it fails with -1, same as a v2 entry would without `my_kyber_privkey` |
| `int ikp_verify(...)` | Verify IKP signature (Dilithium5). **CHANGED (KEM Faz 1):** accepts both magics, computes the signed-data length from the version-specific entry size |
| `size_t ikp_calculate_size(size_t member_count)` | Calculate expected IKP size — **v2 sizing only** (unchanged); v3 sizing is `IKP_HEADER_SIZE + IKP_MEMBER_ENTRY_SIZE_V3 * member_count + IKP_SIGNATURE_SIZE`, computed inline in `ikp_build` |
| `int ikp_get_version(...)` | Get GEK version from IKP header. **CHANGED:** accepts both magics (version is at the same offset in v2/v3) |
| `int ikp_get_member_count(...)` | Get member count from IKP header. **CHANGED:** accepts both magics |

**Constants (KEM Faz 1):** `IKP_MAGIC_V3 = 0x47454B33`, `IKP_MEMBER_ENTRY_SIZE_V3 = 1673`, `IKP_ALG_KYBER_R3 = 2`, `IKP_ALG_MLKEM1024 = 3`.

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
| `int messenger_gek_auto_sync(void *ctx)` | High-level wrapper: loads keys internally, calls gek_auto_sync (v0.6.53+) |

**Call Sites (v0.6.54+):**
- Post-stabilization thread: Called in background after DHT stabilizes (restores GEKs on new device)
- On group create: Called after storing initial GEK in `messenger_create_group`
- On group join: Called after accepting invitation in `messenger_accept_group_invitation`

**v0.6.54 Change:** GEK sync moved from blocking identity load to background stabilization thread for faster startup.

**DHT Key:** `SHA3-512(fingerprint + ":geks")`
**Security:** Self-encrypted with Kyber1024, signed with Dilithium5
**Format:** JSON with base64-encoded GEKs, organized by group UUID

---

## 4. Message Backup

**File:** `message_backup.h`

Local SQLite database for message backup. Stores **plaintext** messages per-identity at `~/.dna/db/messages.db` (v14).

**v14 Schema Change:** Messages stored as plaintext (previously encrypted BLOB).
Database-level encryption uses SQLCipher v4.6.1 (added in v0.9.160).

### 4.1 Initialization

| Function | Description |
|----------|-------------|
| `message_backup_context_t* message_backup_init(const char *identity, const char *db_key)` | Initialize message backup system (db_key for SQLCipher encryption) |
| `void message_backup_close(message_backup_context_t *ctx)` | Close backup context |
| `void* message_backup_get_db(message_backup_context_t *ctx)` | Get SQLite database handle |

### 4.2 Message Storage

| Function | Description |
|----------|-------------|
| `int message_backup_save(ctx, sender, recipient, plaintext, sender_fp, timestamp, is_outgoing, group_id, message_type, offline_seq)` | Save plaintext message to local backup (v14) |
| `bool message_backup_exists(ctx, content_hash)` | Check if message exists (v16: by SHA3-256 content hash) |
| `int message_backup_delete(message_backup_context_t*, int)` | Delete message by ID |
| `int message_backup_delete_conversation(ctx, fingerprint)` | Delete all messages with a specific contact |
| `int message_backup_delete_all(message_backup_context_t*)` | Delete all messages |
| `int message_backup_delete_by_content_hash(ctx, content_hash)` | Delete message by content hash |
| `int message_backup_mark_deleted_by_sender(ctx, content_hash)` | Set deleted_by_sender flag for a message |
| `char* message_backup_get_content_hash_by_id(ctx, message_id)` | Get content hash for a message by ID (caller frees) |
| `int message_backup_get_all_content_hashes(ctx, fingerprint, hashes_out, count_out)` | Get all content hashes for a contact's messages |
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
