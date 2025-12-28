# DNA Messenger Function Reference

**Version:** 0.2.105
**Generated:** 2025-12-28
**Scope:** All functions (public + static/internal)

This document provides a comprehensive reference for all functions in the DNA Messenger codebase, organized by module.

---

## Table of Contents

1. [Public API (dna_engine.h)](#1-public-api)
2. [DNA API (dna_api.h)](#2-dna-api)
3. [Messenger Core](#3-messenger-core)
4. [Message Backup](#4-message-backup)
5. [Cryptography](#5-cryptography)
   - [5.1 Utils](#51-crypto-utils)
   - [5.2 KEM (Kyber)](#52-crypto-kem)
   - [5.3 DSA (Dilithium)](#53-crypto-dsa)
   - [5.4 BIP39/BIP32](#54-bip39bip32)
6. [DHT System](#6-dht-system)
   - [6.1 Core](#61-dht-core)
   - [6.2 Shared](#62-dht-shared)
   - [6.3 Client](#63-dht-client)
7. [P2P Transport](#7-p2p-transport)
8. [Database](#8-database)
9. [Blockchain](#9-blockchain)
   - [9.1 Cellframe](#91-cellframe)
   - [9.2 Ethereum](#92-ethereum)
   - [9.3 Solana](#93-solana)
   - [9.4 Tron](#94-tron)
10. [Engine Implementation](#10-engine-implementation)
11. [Key Sizes Reference](#11-key-sizes-reference)

---

## 1. Public API

**File:** `include/dna/dna_engine.h`

The main public API for DNA Messenger. All UI/FFI bindings use these functions.

### 1.1 Lifecycle

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_version(void)` | Get DNA Messenger version string |
| `const char* dna_engine_error_string(int error)` | Get human-readable error message |
| `dna_engine_t* dna_engine_create(const char *data_dir)` | Create engine instance and spawn worker threads |
| `void dna_engine_set_event_callback(dna_engine_t*, dna_event_cb, void*)` | Set event callback for pushed events |
| `void dna_engine_destroy(dna_engine_t *engine)` | Destroy engine and release all resources |
| `const char* dna_engine_get_fingerprint(dna_engine_t *engine)` | Get current identity fingerprint |

### 1.2 Identity Management

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_list_identities(...)` | List available identities from ~/.dna |
| `dna_request_id_t dna_engine_create_identity(...)` | Create new identity from BIP39 seeds |
| `int dna_engine_create_identity_sync(...)` | Create identity synchronously (blocking) |
| `int dna_engine_restore_identity_sync(...)` | Restore identity from BIP39 seeds without DHT name |
| `int dna_engine_delete_identity_sync(...)` | Delete identity and all local data |
| `dna_request_id_t dna_engine_load_identity(...)` | Load and activate identity, bootstrap DHT |
| `dna_request_id_t dna_engine_register_name(...)` | Register human-readable name in DHT |
| `dna_request_id_t dna_engine_get_display_name(...)` | Lookup display name for fingerprint |
| `dna_request_id_t dna_engine_get_avatar(...)` | Get avatar for fingerprint |
| `dna_request_id_t dna_engine_lookup_name(...)` | Lookup name availability (name -> fingerprint) |
| `dna_request_id_t dna_engine_get_profile(...)` | Get current identity's profile from DHT |
| `dna_request_id_t dna_engine_lookup_profile(...)` | Lookup any user's profile by fingerprint |
| `dna_request_id_t dna_engine_update_profile(...)` | Update current identity's profile in DHT |
| `int dna_engine_get_mnemonic(...)` | Get encrypted mnemonic (recovery phrase) |
| `int dna_engine_change_password_sync(...)` | Change password for identity keys |

### 1.3 Contacts

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_get_contacts(...)` | Get contact list from local database |
| `dna_request_id_t dna_engine_add_contact(...)` | Add contact by fingerprint or registered name |
| `dna_request_id_t dna_engine_remove_contact(...)` | Remove contact |

### 1.4 Contact Requests (ICQ-Style)

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

### 1.5 Messaging

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_send_message(...)` | Send message to contact (P2P + DHT fallback) |
| `int dna_engine_queue_message(...)` | Queue message for async sending |
| `int dna_engine_get_message_queue_capacity(...)` | Get message queue capacity |
| `int dna_engine_get_message_queue_size(...)` | Get current message queue size |
| `int dna_engine_set_message_queue_capacity(...)` | Set message queue capacity |
| `dna_request_id_t dna_engine_get_conversation(...)` | Get conversation with contact |
| `dna_request_id_t dna_engine_check_offline_messages(...)` | Force check for offline messages |
| `int dna_engine_get_unread_count(...)` | Get unread message count (sync) |
| `dna_request_id_t dna_engine_mark_conversation_read(...)` | Mark all messages as read |

### 1.6 Groups

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_get_groups(...)` | Get groups current identity belongs to |
| `dna_request_id_t dna_engine_create_group(...)` | Create new group with GSK encryption |
| `dna_request_id_t dna_engine_send_group_message(...)` | Send message to group |
| `dna_request_id_t dna_engine_get_invitations(...)` | Get pending group invitations |
| `dna_request_id_t dna_engine_accept_invitation(...)` | Accept group invitation |
| `dna_request_id_t dna_engine_reject_invitation(...)` | Reject group invitation |

### 1.7 Wallet (Cellframe + Multi-Chain)

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_list_wallets(...)` | List Cellframe wallets |
| `dna_request_id_t dna_engine_get_balances(...)` | Get token balances for wallet |
| `int dna_engine_estimate_eth_gas(int, dna_gas_estimate_t*)` | Get gas fee estimate for ETH transaction |
| `dna_request_id_t dna_engine_send_tokens(...)` | Send tokens (build tx, sign, submit) |
| `dna_request_id_t dna_engine_get_transactions(...)` | Get transaction history |

### 1.8 P2P & Presence

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_refresh_presence(...)` | Refresh presence in DHT |
| `bool dna_engine_is_peer_online(dna_engine_t*, const char*)` | Check if peer is online |
| `dna_request_id_t dna_engine_lookup_presence(...)` | Lookup peer presence from DHT |
| `dna_request_id_t dna_engine_sync_contacts_to_dht(...)` | Sync contacts to DHT |
| `dna_request_id_t dna_engine_sync_contacts_from_dht(...)` | Sync contacts from DHT |
| `dna_request_id_t dna_engine_sync_groups(...)` | Sync groups from DHT |
| `dna_request_id_t dna_engine_subscribe_to_contacts(...)` | Subscribe to contacts for push |
| `int dna_engine_request_turn_credentials(dna_engine_t*, int)` | Request TURN relay credentials |
| `dna_request_id_t dna_engine_get_registered_name(...)` | Get registered name for current identity |

### 1.9 Outbox Listeners

| Function | Description |
|----------|-------------|
| `size_t dna_engine_listen_outbox(dna_engine_t*, const char*)` | Start listening for updates to contact's outbox |
| `void dna_engine_cancel_outbox_listener(dna_engine_t*, const char*)` | Cancel outbox listener |
| `int dna_engine_listen_all_contacts(dna_engine_t*)` | Start listeners for all contacts |
| `void dna_engine_cancel_all_outbox_listeners(dna_engine_t*)` | Cancel all outbox listeners |

### 1.10 Delivery Trackers

| Function | Description |
|----------|-------------|
| `int dna_engine_track_delivery(dna_engine_t*, const char*)` | Start tracking delivery for recipient |
| `void dna_engine_untrack_delivery(dna_engine_t*, const char*)` | Stop tracking delivery |
| `void dna_engine_cancel_all_delivery_trackers(dna_engine_t*)` | Cancel all delivery trackers |

### 1.11 Feed (DNA Board)

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

### 1.12 Backward Compatibility

| Function | Description |
|----------|-------------|
| `void* dna_engine_get_messenger_context(dna_engine_t*)` | Get underlying messenger context |
| `void* dna_engine_get_dht_context(dna_engine_t*)` | Get DHT context |
| `int dna_engine_is_dht_connected(dna_engine_t*)` | Check if DHT is connected |

### 1.13 Log Configuration

| Function | Description |
|----------|-------------|
| `const char* dna_engine_get_log_level(void)` | Get current log level |
| `int dna_engine_set_log_level(const char *level)` | Set log level |
| `const char* dna_engine_get_log_tags(void)` | Get log tags filter |
| `int dna_engine_set_log_tags(const char *tags)` | Set log tags filter |

### 1.14 Memory Management

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

### 1.15 Global Engine Access

| Function | Description |
|----------|-------------|
| `void dna_engine_set_global(dna_engine_t*)` | Set global engine instance |
| `dna_engine_t* dna_engine_get_global(void)` | Get global engine instance |
| `void dna_dispatch_event(dna_engine_t*, const dna_event_t*)` | Dispatch event to Flutter/GUI layer |

### 1.16 Debug Log API

| Function | Description |
|----------|-------------|
| `void dna_engine_debug_log_enable(bool enabled)` | Enable/disable debug log ring buffer |
| `bool dna_engine_debug_log_is_enabled(void)` | Check if debug logging is enabled |
| `int dna_engine_debug_log_get_entries(dna_debug_log_entry_t*, int)` | Get debug log entries |
| `int dna_engine_debug_log_count(void)` | Get number of log entries |
| `void dna_engine_debug_log_clear(void)` | Clear all debug log entries |
| `void dna_engine_debug_log_message(const char*, const char*)` | Add log message from external code |
| `int dna_engine_debug_log_export(const char *filepath)` | Export debug logs to file |

### 1.17 Message Backup/Restore

| Function | Description |
|----------|-------------|
| `dna_request_id_t dna_engine_backup_messages(...)` | Backup all messages to DHT |
| `dna_request_id_t dna_engine_restore_messages(...)` | Restore messages from DHT |

---

## 2. DNA API

**File:** `dna_api.h`

Low-level cryptographic API for message encryption/decryption with post-quantum algorithms.

### 2.1 Version & Error Handling

| Function | Description |
|----------|-------------|
| `const char* dna_version(void)` | Get library version string |
| `const char* dna_error_string(dna_error_t error)` | Get human-readable error message |

### 2.2 Context Management

| Function | Description |
|----------|-------------|
| `dna_context_t* dna_context_new(void)` | Create new DNA context |
| `void dna_context_free(dna_context_t *ctx)` | Free DNA context and all resources |

### 2.3 Buffer Management

| Function | Description |
|----------|-------------|
| `dna_buffer_t dna_buffer_new(size_t size)` | Allocate new buffer |
| `void dna_buffer_free(dna_buffer_t *buffer)` | Free buffer data (secure wipe) |

### 2.4 Message Encryption

| Function | Description |
|----------|-------------|
| `dna_error_t dna_encrypt_message(...)` | Encrypt message for recipient(s) by name |
| `dna_error_t dna_encrypt_message_raw(...)` | Encrypt message with raw keys (for DB integration) |

### 2.5 Message Decryption

| Function | Description |
|----------|-------------|
| `dna_error_t dna_decrypt_message(...)` | Decrypt message using keyring name |
| `dna_error_t dna_decrypt_message_raw(...)` | Decrypt message with raw keys |

### 2.6 Signature Operations

| Function | Description |
|----------|-------------|
| `dna_error_t dna_sign_message(...)` | Sign message with Dilithium5 |
| `dna_error_t dna_verify_message(...)` | Verify message signature |

### 2.7 Key Management

| Function | Description |
|----------|-------------|
| `dna_error_t dna_load_key(...)` | Load key from keyring by name |
| `dna_error_t dna_load_pubkey(...)` | Load public key from keyring |

### 2.8 Utility Functions

| Function | Description |
|----------|-------------|
| `dna_error_t dna_key_fingerprint(...)` | Get key fingerprint (SHA256) |
| `dna_error_t dna_fingerprint_to_hex(...)` | Convert fingerprint to hex string |

### 2.9 Group Messaging (GSK)

| Function | Description |
|----------|-------------|
| `dna_error_t dna_encrypt_message_gsk(...)` | Encrypt message with Group Symmetric Key |
| `dna_error_t dna_decrypt_message_gsk(...)` | Decrypt GSK-encrypted message |

---

## 3. Messenger Core

**File:** `messenger.h`

Core messenger functionality including identity management, key generation, messaging, and groups.

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

### 3.4 Public Key Management

| Function | Description |
|----------|-------------|
| `int messenger_store_pubkey(...)` | Store public key in DHT keyserver |
| `int messenger_load_pubkey(...)` | Load public key from cache or DHT |
| `int messenger_list_pubkeys(messenger_context_t*)` | List all public keys in keyserver |
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

---

## 5. Cryptography Utilities

**Directory:** `crypto/utils/`

Low-level cryptographic primitives and platform abstraction layer.

### 5.1 AES-256-GCM (`qgp_aes.h`)

| Function | Description |
|----------|-------------|
| `size_t qgp_aes256_encrypt_size(size_t plaintext_len)` | Calculate buffer size for encryption |
| `int qgp_aes256_encrypt(...)` | Encrypt data with AES-256-GCM (AEAD) |
| `int qgp_aes256_decrypt(...)` | Decrypt data with AES-256-GCM (AEAD) |

### 5.2 SHA3-512 Hashing (`qgp_sha3.h`)

| Function | Description |
|----------|-------------|
| `int qgp_sha3_512(const uint8_t*, size_t, uint8_t*)` | Compute SHA3-512 hash |
| `int qgp_sha3_512_hex(...)` | Compute SHA3-512 and return as hex string |
| `int qgp_sha3_512_fingerprint(...)` | Compute SHA3-512 fingerprint of public key |

### 5.3 Kyber1024 KEM (`qgp_kyber.h`)

| Function | Description |
|----------|-------------|
| `int qgp_kem1024_keypair(uint8_t *pk, uint8_t *sk)` | Generate KEM-1024 keypair |
| `int qgp_kem1024_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk)` | Generate shared secret and ciphertext |
| `int qgp_kem1024_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)` | Recover shared secret from ciphertext |

### 5.4 Dilithium5 DSA (`qgp_dilithium.h`)

| Function | Description |
|----------|-------------|
| `int qgp_dsa87_keypair(uint8_t *pk, uint8_t *sk)` | Generate DSA-87 keypair |
| `int qgp_dsa87_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)` | Generate keypair from seed |
| `int qgp_dsa87_sign(uint8_t *sig, size_t *siglen, ...)` | Sign message (detached signature) |
| `int qgp_dsa87_verify(const uint8_t *sig, size_t siglen, ...)` | Verify signature |

### 5.5 Key Encryption (`key_encryption.h`)

| Function | Description |
|----------|-------------|
| `int key_encrypt(...)` | Encrypt key data with password (PBKDF2+AES-GCM) |
| `int key_decrypt(...)` | Decrypt key data with password |
| `int key_save_encrypted(...)` | Save encrypted key to file |
| `int key_load_encrypted(...)` | Load and decrypt key from file |
| `bool key_file_is_encrypted(const char *file_path)` | Check if key file is password-protected |
| `int key_change_password(...)` | Change password on encrypted key file |
| `int key_verify_password(...)` | Verify password against key file |

### 5.6 AES Key Wrap (`aes_keywrap.h`)

| Function | Description |
|----------|-------------|
| `int aes256_wrap_key(...)` | AES-256 key wrap (RFC 3394) |
| `int aes256_unwrap_key(...)` | AES-256 key unwrap (RFC 3394) |

### 5.7 Deterministic Kyber (`kyber_deterministic.h`)

| Function | Description |
|----------|-------------|
| `int crypto_kem_keypair_derand(unsigned char *pk, unsigned char *sk, const uint8_t *seed)` | Deterministic keypair from seed |

### 5.8 Random Number Generation (`qgp_random.h`)

| Function | Description |
|----------|-------------|
| `int qgp_randombytes(uint8_t *buf, size_t len)` | Generate cryptographically secure random bytes |

### 5.9 Base58 Encoding (`base58.h`)

| Function | Description |
|----------|-------------|
| `size_t base58_encode(const void *a_in, size_t a_in_size, char *a_out)` | Encode binary data to base58 string |
| `size_t base58_decode(const char *a_in, void *a_out)` | Decode base58 string to binary data |

### 5.10 Keccak-256 / Ethereum (`keccak256.h`)

| Function | Description |
|----------|-------------|
| `int keccak256(const uint8_t *data, size_t len, uint8_t hash_out[32])` | Compute Keccak-256 hash (Ethereum variant) |
| `int keccak256_hex(const uint8_t *data, size_t len, char hex_out[65])` | Compute Keccak-256 as hex string |
| `int eth_address_from_pubkey(const uint8_t pubkey[65], uint8_t addr[20])` | Derive Ethereum address from public key |
| `int eth_address_from_pubkey_hex(...)` | Derive checksummed address as hex string |
| `int eth_address_checksum(const char*, char[41])` | Apply EIP-55 checksum |
| `int eth_address_verify_checksum(const char *address)` | Validate Ethereum address checksum |

### 5.11 Seed Storage (`seed_storage.h`)

| Function | Description |
|----------|-------------|
| `int seed_storage_save(...)` | Save master seed encrypted with Kyber1024 KEM |
| `int seed_storage_load(...)` | Load master seed decrypted with Kyber1024 KEM |
| `bool seed_storage_exists(const char *identity_dir)` | Check if encrypted seed file exists |
| `int seed_storage_delete(const char *identity_dir)` | Delete encrypted seed file |
| `int mnemonic_storage_save(...)` | Save mnemonic encrypted with Kyber1024 KEM |
| `int mnemonic_storage_load(...)` | Load mnemonic decrypted with Kyber1024 KEM |
| `bool mnemonic_storage_exists(const char *identity_dir)` | Check if encrypted mnemonic file exists |

### 5.12 Avatar Utils (`avatar_utils.h`)

| Function | Description |
|----------|-------------|
| `int avatar_load_and_encode(const char*, char*, size_t)` | Load image, resize to 64x64, encode to base64 |
| `unsigned char* avatar_decode_base64(const char*, int*, int*, int*)` | Decode base64 avatar to RGBA pixel data |

### 5.13 Platform Abstraction (`qgp_platform.h`)

| Function | Description |
|----------|-------------|
| `int qgp_platform_random(uint8_t *buf, size_t len)` | Generate cryptographically secure random bytes |
| `int qgp_platform_mkdir(const char *path)` | Create directory with secure permissions |
| `int qgp_platform_file_exists(const char *path)` | Check if file/directory exists |
| `int qgp_platform_is_directory(const char *path)` | Check if path is a directory |
| `int qgp_platform_rmdir_recursive(const char *path)` | Recursively delete directory |
| `const char* qgp_platform_home_dir(void)` | Get user's home directory |
| `char* qgp_platform_join_path(const char*, const char*)` | Join path components |
| `void qgp_secure_memzero(void *ptr, size_t len)` | Securely zero memory |
| `const char* qgp_platform_app_data_dir(void)` | Get application data directory |
| `const char* qgp_platform_cache_dir(void)` | Get application cache directory |
| `int qgp_platform_set_app_dirs(const char*, const char*)` | Set app directories (mobile) |
| `qgp_network_state_t qgp_platform_network_state(void)` | Get current network state |
| `void qgp_platform_set_network_callback(...)` | Set network state change callback |
| `const char* qgp_platform_ca_bundle_path(void)` | Get CA certificate bundle path |

### 5.14 QGP Types (`qgp_types.h`)

| Function | Description |
|----------|-------------|
| `qgp_key_t* qgp_key_new(qgp_key_type_t, qgp_key_purpose_t)` | Create new key structure |
| `void qgp_key_free(qgp_key_t *key)` | Free key structure |
| `qgp_signature_t* qgp_signature_new(...)` | Create new signature structure |
| `void qgp_signature_free(qgp_signature_t *sig)` | Free signature structure |
| `size_t qgp_signature_get_size(const qgp_signature_t*)` | Get signature size |
| `size_t qgp_signature_serialize(const qgp_signature_t*, uint8_t*)` | Serialize signature |
| `int qgp_signature_deserialize(...)` | Deserialize signature |
| `int qgp_key_save(const qgp_key_t*, const char*)` | Save key to file |
| `int qgp_key_load(const char*, qgp_key_t**)` | Load key from file |
| `int qgp_pubkey_save(const qgp_key_t*, const char*)` | Save public key to file |
| `int qgp_pubkey_load(const char*, qgp_key_t**)` | Load public key from file |
| `int qgp_key_save_encrypted(...)` | Save key with password encryption |
| `int qgp_key_load_encrypted(...)` | Load key with password decryption |
| `bool qgp_key_file_is_encrypted(const char*)` | Check if key file is encrypted |
| `void qgp_hash_from_bytes(qgp_hash_t*, const uint8_t*, size_t)` | Create hash from bytes |
| `void qgp_hash_to_hex(const qgp_hash_t*, char*, size_t)` | Convert hash to hex string |
| `char* qgp_base64_encode(const uint8_t*, size_t, size_t*)` | Encode to base64 |
| `uint8_t* qgp_base64_decode(const char*, size_t*)` | Decode from base64 |

### 5.15 Logging (`qgp_log.h`)

| Function | Description |
|----------|-------------|
| `void qgp_log_set_level(qgp_log_level_t level)` | Set minimum log level |
| `qgp_log_level_t qgp_log_get_level(void)` | Get current log level |
| `void qgp_log_set_filter_mode(qgp_log_filter_mode_t)` | Set filter mode (whitelist/blacklist) |
| `qgp_log_filter_mode_t qgp_log_get_filter_mode(void)` | Get current filter mode |
| `void qgp_log_enable_tag(const char *tag)` | Enable logging for tag |
| `void qgp_log_disable_tag(const char *tag)` | Disable logging for tag |
| `void qgp_log_clear_filters(void)` | Clear all tag filters |
| `bool qgp_log_should_log(qgp_log_level_t, const char*)` | Check if tag should be logged |
| `void qgp_log_print(qgp_log_level_t, const char*, const char*, ...)` | Print log message |
| `void qgp_log_ring_enable(bool enabled)` | Enable/disable ring buffer storage |
| `bool qgp_log_ring_is_enabled(void)` | Check if ring buffer is enabled |
| `int qgp_log_ring_get_entries(qgp_log_entry_t*, int)` | Get log entries from ring buffer |
| `int qgp_log_ring_count(void)` | Get entry count in ring buffer |
| `void qgp_log_ring_clear(void)` | Clear all ring buffer entries |
| `int qgp_log_export_to_file(const char *filepath)` | Export ring buffer to file |
| `void qgp_log_ring_add(qgp_log_level_t, const char*, const char*, ...)` | Add entry to ring buffer |

---

## 6. Cryptography KEM (Kyber Internals)

**Directory:** `crypto/kem/`

Internal Kyber1024 (ML-KEM-1024) implementation from pq-crystals reference.

### 6.1 KEM API (`kem.h`)

| Function | Description |
|----------|-------------|
| `int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)` | Generate KEM keypair |
| `int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)` | Encapsulate shared secret |
| `int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)` | Decapsulate shared secret |

### 6.2 IND-CPA (`indcpa.h`)

| Function | Description |
|----------|-------------|
| `void gen_matrix(polyvec*, const uint8_t seed[32], int)` | Generate matrix from seed |
| `void indcpa_keypair(uint8_t *pk, uint8_t *sk)` | IND-CPA keypair generation |
| `void indcpa_enc(uint8_t *c, const uint8_t *m, const uint8_t *pk, const uint8_t *coins)` | IND-CPA encryption |
| `void indcpa_dec(uint8_t *m, const uint8_t *c, const uint8_t *sk)` | IND-CPA decryption |

### 6.3 Polynomial Operations (`poly_kyber.h`)

| Function | Description |
|----------|-------------|
| `void poly_compress(uint8_t*, poly*)` | Compress polynomial |
| `void poly_decompress(poly*, const uint8_t*)` | Decompress polynomial |
| `void poly_tobytes(uint8_t*, poly*)` | Serialize polynomial to bytes |
| `void poly_frombytes(poly*, const uint8_t*)` | Deserialize polynomial from bytes |
| `void poly_frommsg(poly*, const uint8_t*)` | Convert message to polynomial |
| `void poly_tomsg(uint8_t*, poly*)` | Convert polynomial to message |
| `void poly_getnoise_eta1(poly*, const uint8_t*, uint8_t)` | Sample noise polynomial (eta1) |
| `void poly_getnoise_eta2(poly*, const uint8_t*, uint8_t)` | Sample noise polynomial (eta2) |
| `void poly_ntt(poly*)` | Forward NTT transform |
| `void poly_invntt_tomont(poly*)` | Inverse NTT to Montgomery domain |
| `void poly_basemul_montgomery(poly*, const poly*, const poly*)` | Pointwise multiplication |
| `void poly_tomont(poly*)` | Convert to Montgomery representation |
| `void poly_reduce(poly*)` | Apply Barrett reduction |
| `void poly_csubq(poly*)` | Conditional subtraction of q |
| `void poly_add(poly*, const poly*, const poly*)` | Add polynomials |
| `void poly_sub(poly*, const poly*, const poly*)` | Subtract polynomials |

### 6.4 Polynomial Vector (`polyvec.h`)

| Function | Description |
|----------|-------------|
| `void polyvec_compress(uint8_t*, polyvec*)` | Compress polynomial vector |
| `void polyvec_decompress(polyvec*, const uint8_t*)` | Decompress polynomial vector |
| `void polyvec_tobytes(uint8_t*, polyvec*)` | Serialize polynomial vector |
| `void polyvec_frombytes(polyvec*, const uint8_t*)` | Deserialize polynomial vector |
| `void polyvec_ntt(polyvec*)` | Forward NTT on vector |
| `void polyvec_invntt_tomont(polyvec*)` | Inverse NTT on vector |
| `void polyvec_pointwise_acc_montgomery(poly*, const polyvec*, const polyvec*)` | Inner product |
| `void polyvec_reduce(polyvec*)` | Reduce coefficients |
| `void polyvec_csubq(polyvec*)` | Conditional subtraction |
| `void polyvec_add(polyvec*, const polyvec*, const polyvec*)` | Add vectors |

### 6.5 NTT (`ntt_kyber.h`)

| Function | Description |
|----------|-------------|
| `void ntt(int16_t poly[256])` | Number Theoretic Transform |
| `void invntt(int16_t poly[256])` | Inverse NTT |
| `void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)` | Base multiplication |

### 6.6 CBD Sampling (`cbd.h`)

| Function | Description |
|----------|-------------|
| `void cbd_eta1(poly*, const uint8_t*)` | Centered binomial distribution (eta1) |
| `void cbd_eta2(poly*, const uint8_t*)` | Centered binomial distribution (eta2) |

### 6.7 Reduction (`reduce_kyber.h`)

| Function | Description |
|----------|-------------|
| `int16_t montgomery_reduce(int32_t a)` | Montgomery reduction |
| `int16_t barrett_reduce(int16_t a)` | Barrett reduction |
| `int16_t csubq(int16_t x)` | Conditional subtraction of q |

### 6.8 Verification (`verify.h`)

| Function | Description |
|----------|-------------|
| `int verify(const uint8_t *a, const uint8_t *b, size_t len)` | Constant-time comparison |
| `void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)` | Constant-time conditional move |

### 6.9 Symmetric Primitives (`symmetric.h`, `fips202_kyber.h`)

| Function | Description |
|----------|-------------|
| `void kyber_shake128_absorb(keccak_state*, const uint8_t*, uint8_t, uint8_t)` | SHAKE128 absorb for Kyber |
| `void kyber_shake256_prf(uint8_t*, size_t, const uint8_t*, uint8_t)` | SHAKE256 PRF for Kyber |
| `void shake128_absorb(keccak_state*, const uint8_t*, size_t)` | SHAKE128 absorb |
| `void shake128_squeezeblocks(uint8_t*, size_t, keccak_state*)` | SHAKE128 squeeze blocks |
| `void shake256_absorb(keccak_state*, const uint8_t*, size_t)` | SHAKE256 absorb |
| `void shake256_squeezeblocks(uint8_t*, size_t, keccak_state*)` | SHAKE256 squeeze blocks |
| `void shake128(uint8_t*, size_t, const uint8_t*, size_t)` | SHAKE128 hash |
| `void shake256(uint8_t*, size_t, const uint8_t*, size_t)` | SHAKE256 hash |
| `void sha3_256(uint8_t h[32], const uint8_t*, size_t)` | SHA3-256 hash |
| `void sha3_512(uint8_t h[64], const uint8_t*, size_t)` | SHA3-512 hash |

### 6.10 SHA2 (`sha2.h`)

| Function | Description |
|----------|-------------|
| `void sha256(uint8_t out[32], const uint8_t*, size_t)` | SHA-256 hash |
| `void sha512(uint8_t out[64], const uint8_t*, size_t)` | SHA-512 hash |

### 6.11 AES-256-CTR (`aes256ctr.h`)

| Function | Description |
|----------|-------------|
| `void aes256ctr_prf(uint8_t*, size_t, const uint8_t key[32], const uint8_t nonce[12])` | AES-256-CTR PRF |
| `void aes256ctr_init(aes256ctr_ctx*, const uint8_t key[32], const uint8_t nonce[12])` | Initialize AES-256-CTR |
| `void aes256ctr_squeezeblocks(uint8_t*, size_t, aes256ctr_ctx*)` | Squeeze blocks from AES-CTR |

---

## 7. Cryptography DSA (Dilithium Internals)

**Directory:** `crypto/dsa/`

Internal Dilithium5 (ML-DSA-87) implementation from pq-crystals reference.

### 7.1 Signature API (`sign.h`)

| Function | Description |
|----------|-------------|
| `int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)` | Generate signing keypair |
| `int crypto_sign_signature(uint8_t *sig, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*)` | Create detached signature |
| `int crypto_sign(uint8_t *sm, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*)` | Sign message (attached) |
| `int crypto_sign_verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*)` | Verify detached signature |
| `int crypto_sign_open(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*)` | Verify and open signed message |
| `int crypto_sign_signature_internal(...)` | Internal signature with randomness |
| `int crypto_sign_verify_internal(...)` | Internal verification |

### 7.2 Level-Specific API (`api.h`)

| Function | Description |
|----------|-------------|
| `int pqcrystals_dilithium2_ref_keypair(uint8_t*, uint8_t*)` | Dilithium2 keypair |
| `int pqcrystals_dilithium2_ref_signature(...)` | Dilithium2 signature |
| `int pqcrystals_dilithium2_ref_verify(...)` | Dilithium2 verify |
| `int pqcrystals_dilithium3_ref_keypair(uint8_t*, uint8_t*)` | Dilithium3 keypair |
| `int pqcrystals_dilithium3_ref_signature(...)` | Dilithium3 signature |
| `int pqcrystals_dilithium3_ref_verify(...)` | Dilithium3 verify |
| `int pqcrystals_dilithium5_ref_keypair(uint8_t*, uint8_t*)` | Dilithium5 keypair |
| `int pqcrystals_dilithium5_ref_signature(...)` | Dilithium5 signature |
| `int pqcrystals_dilithium5_ref_verify(...)` | Dilithium5 verify |

### 7.3 Polynomial Operations (`poly.h`)

| Function | Description |
|----------|-------------|
| `void poly_reduce(poly*)` | Reduce polynomial coefficients |
| `void poly_caddq(poly*)` | Conditional add q |
| `void poly_add(poly*, const poly*, const poly*)` | Add polynomials |
| `void poly_sub(poly*, const poly*, const poly*)` | Subtract polynomials |
| `void poly_shiftl(poly*)` | Left shift polynomial |
| `void poly_ntt(poly*)` | Forward NTT |
| `void poly_invntt_tomont(poly*)` | Inverse NTT to Montgomery |
| `void poly_pointwise_montgomery(poly*, const poly*, const poly*)` | Pointwise multiplication |
| `void poly_power2round(poly*, poly*, const poly*)` | Power of 2 rounding |
| `void poly_decompose(poly*, poly*, const poly*)` | Decompose polynomial |
| `unsigned int poly_make_hint(poly*, const poly*, const poly*)` | Make hint polynomial |
| `void poly_use_hint(poly*, const poly*, const poly*)` | Apply hint polynomial |
| `int poly_chknorm(const poly*, int32_t)` | Check coefficient norm |
| `void poly_uniform(poly*, const uint8_t*, uint16_t)` | Sample uniform polynomial |
| `void poly_uniform_eta(poly*, const uint8_t*, uint16_t)` | Sample eta-bounded polynomial |
| `void poly_uniform_gamma1(poly*, const uint8_t*, uint16_t)` | Sample gamma1-bounded polynomial |
| `void poly_challenge(poly*, const uint8_t*)` | Generate challenge polynomial |
| `void polyeta_pack(uint8_t*, const poly*)` | Pack eta polynomial |
| `void polyeta_unpack(poly*, const uint8_t*)` | Unpack eta polynomial |
| `void polyt1_pack(uint8_t*, const poly*)` | Pack t1 polynomial |
| `void polyt1_unpack(poly*, const uint8_t*)` | Unpack t1 polynomial |
| `void polyt0_pack(uint8_t*, const poly*)` | Pack t0 polynomial |
| `void polyt0_unpack(poly*, const uint8_t*)` | Unpack t0 polynomial |
| `void polyz_pack(uint8_t*, const poly*)` | Pack z polynomial |
| `void polyz_unpack(poly*, const uint8_t*)` | Unpack z polynomial |
| `void polyw1_pack(uint8_t*, const poly*)` | Pack w1 polynomial |

### 7.4 Polynomial Vector L (`polyvec.h`)

| Function | Description |
|----------|-------------|
| `void polyvecl_uniform_eta(polyvecl*, const uint8_t*, uint16_t)` | Sample uniform eta vector |
| `void polyvecl_uniform_gamma1(polyvecl*, const uint8_t*, uint16_t)` | Sample uniform gamma1 vector |
| `void polyvecl_reduce(polyvecl*)` | Reduce vector coefficients |
| `void polyvecl_add(polyvecl*, const polyvecl*, const polyvecl*)` | Add vectors |
| `void polyvecl_ntt(polyvecl*)` | Forward NTT on vector |
| `void polyvecl_invntt_tomont(polyvecl*)` | Inverse NTT on vector |
| `void polyvecl_pointwise_poly_montgomery(polyvecl*, const poly*, const polyvecl*)` | Pointwise multiply |
| `void polyvecl_pointwise_acc_montgomery(poly*, const polyvecl*, const polyvecl*)` | Inner product |
| `int polyvecl_chknorm(const polyvecl*, int32_t)` | Check vector norm |

### 7.5 Polynomial Vector K (`polyvec.h`)

| Function | Description |
|----------|-------------|
| `void polyveck_uniform_eta(polyveck*, const uint8_t*, uint16_t)` | Sample uniform eta vector |
| `void polyveck_reduce(polyveck*)` | Reduce vector coefficients |
| `void polyveck_caddq(polyveck*)` | Conditional add q |
| `void polyveck_add(polyveck*, const polyveck*, const polyveck*)` | Add vectors |
| `void polyveck_sub(polyveck*, const polyveck*, const polyveck*)` | Subtract vectors |
| `void polyveck_shiftl(polyveck*)` | Left shift vector |
| `void polyveck_ntt(polyveck*)` | Forward NTT on vector |
| `void polyveck_invntt_tomont(polyveck*)` | Inverse NTT on vector |
| `void polyveck_pointwise_poly_montgomery(polyveck*, const poly*, const polyveck*)` | Pointwise multiply |
| `int polyveck_chknorm(const polyveck*, int32_t)` | Check vector norm |
| `void polyveck_power2round(polyveck*, polyveck*, const polyveck*)` | Power of 2 rounding |
| `void polyveck_decompose(polyveck*, polyveck*, const polyveck*)` | Decompose vector |
| `unsigned int polyveck_make_hint(polyveck*, const polyveck*, const polyveck*)` | Make hint vector |
| `void polyveck_use_hint(polyveck*, const polyveck*, const polyveck*)` | Apply hint vector |
| `void polyveck_pack_w1(uint8_t*, const polyveck*)` | Pack w1 vector |

### 7.6 Matrix Operations (`polyvec.h`)

| Function | Description |
|----------|-------------|
| `void polyvec_matrix_expand(polyvecl mat[K], const uint8_t*)` | Expand matrix from seed |
| `void polyvec_matrix_pointwise_montgomery(polyveck*, const polyvecl mat[K], const polyvecl*)` | Matrix-vector multiply |

### 7.7 NTT (`ntt.h`)

| Function | Description |
|----------|-------------|
| `void ntt(int32_t a[N])` | Number Theoretic Transform |
| `void invntt_tomont(int32_t a[N])` | Inverse NTT to Montgomery |

### 7.8 Reduction (`reduce.h`)

| Function | Description |
|----------|-------------|
| `int32_t montgomery_reduce(int64_t a)` | Montgomery reduction |
| `int32_t reduce32(int32_t a)` | Reduce modulo q |
| `int32_t caddq(int32_t a)` | Conditional add q |
| `int32_t freeze(int32_t a)` | Freeze to positive representative |

### 7.9 Rounding (`rounding.h`)

| Function | Description |
|----------|-------------|
| `int32_t power2round(int32_t*, int32_t)` | Power of 2 rounding |
| `int32_t decompose(int32_t*, int32_t)` | Decompose for hint |
| `unsigned int make_hint(int32_t, int32_t)` | Make hint bit |
| `int32_t use_hint(int32_t, unsigned int)` | Apply hint bit |

### 7.10 Packing (`packing.h`)

| Function | Description |
|----------|-------------|
| `void pack_pk(uint8_t*, const uint8_t*, const polyveck*)` | Pack public key |
| `void pack_sk(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*, const polyveck*, const polyvecl*, const polyveck*)` | Pack secret key |
| `void pack_sig(uint8_t*, const uint8_t*, const polyvecl*, const polyveck*)` | Pack signature |
| `void unpack_pk(uint8_t*, polyveck*, const uint8_t*)` | Unpack public key |
| `void unpack_sk(uint8_t*, uint8_t*, uint8_t*, polyveck*, polyvecl*, polyveck*, const uint8_t*)` | Unpack secret key |
| `int unpack_sig(uint8_t*, polyvecl*, polyveck*, const uint8_t*)` | Unpack signature |

---

## 8. BIP39/BIP32 Key Derivation

**Directory:** `crypto/bip39/`, `crypto/bip32/`

BIP39 mnemonic generation and BIP32 hierarchical deterministic key derivation.

### 8.1 BIP39 Mnemonic (`bip39.h`)

| Function | Description |
|----------|-------------|
| `int bip39_mnemonic_from_entropy(...)` | Generate mnemonic from entropy bytes |
| `int bip39_generate_mnemonic(int word_count, char*, size_t)` | Generate random mnemonic (12-24 words) |
| `bool bip39_validate_mnemonic(const char *mnemonic)` | Validate mnemonic checksum and words |
| `int bip39_mnemonic_to_seed(const char*, const char*, uint8_t[64])` | Derive 512-bit seed from mnemonic |
| `const char** bip39_get_wordlist(void)` | Get BIP39 English wordlist (2048 words) |
| `int bip39_word_index(const char *word)` | Get word index in wordlist (0-2047) |
| `int bip39_pbkdf2_hmac_sha512(...)` | PBKDF2-HMAC-SHA512 for seed derivation |

### 8.2 QGP Seed Derivation (`bip39.h`)

| Function | Description |
|----------|-------------|
| `int qgp_derive_seeds_from_mnemonic(...)` | Derive signing, encryption, wallet seeds |
| `int qgp_derive_seeds_with_master(...)` | Derive seeds + 64-byte master seed |
| `void qgp_display_mnemonic(const char *mnemonic)` | Display mnemonic with word numbers |
| `void test_hmac_sha512(...)` | Test HMAC-SHA512 implementation |

### 8.3 BIP32 HD Derivation (`bip32.h`)

| Function | Description |
|----------|-------------|
| `int bip32_master_key_from_seed(const uint8_t*, size_t, bip32_extended_key_t*)` | Derive master key from BIP39 seed |
| `int bip32_derive_hardened(const bip32_extended_key_t*, uint32_t, bip32_extended_key_t*)` | Derive hardened child key |
| `int bip32_derive_normal(const bip32_extended_key_t*, uint32_t, bip32_extended_key_t*)` | Derive normal child key |
| `int bip32_derive_path(const uint8_t*, size_t, const char*, bip32_extended_key_t*)` | Derive key from path string |
| `int bip32_derive_ethereum(const uint8_t*, size_t, bip32_extended_key_t*)` | Derive Ethereum key (m/44'/60'/0'/0/0) |
| `int bip32_get_public_key(const bip32_extended_key_t*, uint8_t[65])` | Get uncompressed secp256k1 public key |
| `int bip32_get_public_key_compressed(const bip32_extended_key_t*, uint8_t[33])` | Get compressed public key |
| `void bip32_clear_key(bip32_extended_key_t*)` | Securely clear key from memory |

---

## 9. DHT Core

**Directory:** `dht/core/`

Core DHT (Distributed Hash Table) operations for decentralized storage.

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
| `void dht_get_batch(dht_context_t*, const uint8_t**, const size_t*, size_t, dht_batch_callback_t, void*)` | Batch GET (parallel) |
| `int dht_get_batch_sync(dht_context_t*, const uint8_t**, const size_t*, size_t, dht_batch_result_t**)` | Batch GET (blocking) |
| `void dht_batch_results_free(dht_batch_result_t*, size_t)` | Free batch results |
| `int dht_delete(dht_context_t*, const uint8_t*, size_t)` | Delete value (NO-OP) |

### 9.4 DHT Node Info (`dht_context.h`)

| Function | Description |
|----------|-------------|
| `int dht_get_node_id(dht_context_t*, char*)` | Get node ID (SHA3-512 hex) |
| `int dht_get_owner_value_id(dht_context_t*, uint64_t*)` | Get unique value_id for node |

### 9.5 DHT Listen (`dht_listen.h`)

| Function | Description |
|----------|-------------|
| `size_t dht_listen(dht_context_t*, const uint8_t*, size_t, dht_listen_callback_t, void*)` | Start listening for values |
| `void dht_cancel_listen(dht_context_t*, size_t)` | Cancel listen subscription |
| `size_t dht_get_active_listen_count(dht_context_t*)` | Get active subscription count |
| `size_t dht_listen_ex(dht_context_t*, const uint8_t*, size_t, dht_listen_callback_t, void*, dht_listen_cleanup_t)` | Listen with cleanup callback |
| `void dht_cancel_all_listeners(dht_context_t*)` | Cancel all listeners |
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
| `int dht_keyserver_delete(dht_context_t*, const char*)` | Delete keys (NO-OP) |

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

### 9.9 DHT Errors (`dht_errors.h`)

| Function | Description |
|----------|-------------|
| `const char* dht_strerror(int error_code)` | Get error message (inline) |

### 9.10 Bootstrap Registry (`dht_bootstrap_registry.h`)

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

### 10.1 Offline Queue (`dht_offline_queue.h`)

| Function | Description |
|----------|-------------|
| `int dht_queue_message(...)` | Store message in sender's outbox |
| `int dht_retrieve_queued_messages_from_contacts(...)` | Retrieve messages from contacts (sequential) |
| `int dht_retrieve_queued_messages_from_contacts_parallel(...)` | Retrieve messages (parallel, 10-100× faster) |
| `void dht_offline_message_free(dht_offline_message_t*)` | Free single message |
| `void dht_offline_messages_free(dht_offline_message_t*, size_t)` | Free message array |
| `int dht_serialize_messages(...)` | Serialize messages to binary |
| `int dht_deserialize_messages(...)` | Deserialize messages from binary |
| `void dht_generate_outbox_key(const char*, const char*, uint8_t*)` | Generate outbox DHT key |

### 10.2 Watermark API (`dht_offline_queue.h`)

| Function | Description |
|----------|-------------|
| `void dht_generate_watermark_key(const char*, const char*, uint8_t*)` | Generate watermark DHT key |
| `void dht_publish_watermark_async(dht_context_t*, const char*, const char*, uint64_t)` | Publish watermark (async) |
| `int dht_get_watermark(dht_context_t*, const char*, const char*, uint64_t*)` | Get watermark (blocking) |
| `size_t dht_listen_watermark(dht_context_t*, const char*, const char*, dht_watermark_callback_t, void*)` | Listen for watermark updates |
| `void dht_cancel_watermark_listener(dht_context_t*, size_t)` | Cancel watermark listener |

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
| `int dht_send_contact_request(...)` | Send contact request |
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

| Function | Description |
|----------|-------------|
| `int dht_chunked_publish(dht_context_t*, const char*, const uint8_t*, size_t, uint32_t)` | Publish with chunking |
| `int dht_chunked_fetch(dht_context_t*, const char*, uint8_t**, size_t*)` | Fetch chunked data |
| `int dht_chunked_delete(dht_context_t*, const char*, uint32_t)` | Delete chunked data |
| `const char* dht_chunked_strerror(int)` | Get error message |
| `int dht_chunked_make_key(const char*, uint32_t, uint8_t[32])` | Generate chunk key |
| `uint32_t dht_chunked_estimate_chunks(size_t)` | Estimate chunk count |
| `int dht_chunked_fetch_batch(dht_context_t*, const char**, size_t, dht_chunked_batch_result_t**)` | Batch fetch |
| `void dht_chunked_batch_results_free(dht_chunked_batch_result_t*, size_t)` | Free batch results |

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

### 10.8 GSK Storage (`dht_gsk_storage.h`)

| Function | Description |
|----------|-------------|
| `int dht_gsk_publish(dht_context_t*, const char*, uint32_t, const uint8_t*, size_t)` | Publish GSK packet |
| `int dht_gsk_fetch(dht_context_t*, const char*, uint32_t, uint8_t**, size_t*)` | Fetch GSK packet |
| `int dht_gsk_make_chunk_key(const char*, uint32_t, uint32_t, char[65])` | Generate chunk key |
| `int dht_gsk_serialize_chunk(const dht_gsk_chunk_t*, uint8_t**, size_t*)` | Serialize chunk |
| `int dht_gsk_deserialize_chunk(const uint8_t*, size_t, dht_gsk_chunk_t*)` | Deserialize chunk |
| `void dht_gsk_free_chunk(dht_gsk_chunk_t*)` | Free chunk |

---

## 11. DHT Client (`dht/client/`)

High-level DHT client operations including singleton management, identity backup, contact lists, profiles, feeds, and message walls.

### 11.1 DHT Singleton (`dht_singleton.h`)

| Function | Description |
|----------|-------------|
| `int dht_singleton_init(void)` | Initialize global DHT singleton (ephemeral identity) |
| `int dht_singleton_init_with_identity(dht_identity_t*)` | Initialize DHT singleton with user identity |
| `dht_context_t* dht_singleton_get(void)` | Get global DHT singleton instance |
| `bool dht_singleton_is_initialized(void)` | Check if singleton is initialized |
| `bool dht_singleton_is_ready(void)` | Check if DHT is connected and ready |
| `void dht_singleton_cleanup(void)` | Cleanup global DHT singleton |
| `void dht_singleton_set_status_callback(dht_status_callback_t, void*)` | Set connection status callback |

### 11.2 DHT Identity (`dht_identity.h`)

| Function | Description |
|----------|-------------|
| `int dht_identity_generate_dilithium5(dht_identity_t**)` | Generate Dilithium5 DHT identity |
| `int dht_identity_generate_random(dht_identity_t**)` | Generate random DHT identity (legacy) |
| `int dht_identity_export_to_buffer(dht_identity_t*, uint8_t**, size_t*)` | Export identity to binary buffer |
| `int dht_identity_import_from_buffer(const uint8_t*, size_t, dht_identity_t**)` | Import identity from buffer |
| `void dht_identity_free(dht_identity_t*)` | Free DHT identity |

### 11.3 Identity Backup (`dht_identity_backup.h`)

| Function | Description |
|----------|-------------|
| `int dht_identity_create_and_backup(const char*, const uint8_t*, dht_context_t*, dht_identity_t**)` | Create identity and save encrypted backup |
| `int dht_identity_load_from_local(const char*, const uint8_t*, dht_identity_t**)` | Load identity from local backup |
| `int dht_identity_fetch_from_dht(const char*, const uint8_t*, dht_context_t*, dht_identity_t**)` | Fetch identity from DHT (recovery) |
| `int dht_identity_publish_backup(const char*, const uint8_t*, size_t, dht_context_t*)` | Publish encrypted backup to DHT |
| `bool dht_identity_local_exists(const char*)` | Check if local backup exists |
| `bool dht_identity_dht_exists(const char*, dht_context_t*)` | Check if DHT backup exists |
| `void dht_identity_free(dht_identity_t*)` | Free DHT identity |
| `int dht_identity_get_local_path(const char*, char*)` | Get local backup file path |

### 11.4 Contact List (`dht_contactlist.h`)

| Function | Description |
|----------|-------------|
| `int dht_contactlist_init(void)` | Initialize contact list subsystem |
| `void dht_contactlist_cleanup(void)` | Cleanup contact list subsystem |
| `int dht_contactlist_publish(dht_context_t*, const char*, const char**, size_t, ...)` | Publish encrypted contact list |
| `int dht_contactlist_fetch(dht_context_t*, const char*, char***, size_t*, ...)` | Fetch and decrypt contact list |
| `int dht_contactlist_clear(dht_context_t*, const char*)` | Clear contact list (best-effort) |
| `void dht_contactlist_free_contacts(char**, size_t)` | Free contacts array |
| `void dht_contactlist_free(dht_contactlist_t*)` | Free contact list structure |
| `bool dht_contactlist_exists(dht_context_t*, const char*)` | Check if contact list exists |
| `int dht_contactlist_get_timestamp(dht_context_t*, const char*, uint64_t*)` | Get contact list timestamp |

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
| `bool dna_validate_ipfs_cid(const char*)` | Validate IPFS CID format |
| `bool dna_validate_name(const char*)` | Validate DNA name format |
| `bool dna_network_is_cellframe(const char*)` | Check if Cellframe network |
| `bool dna_network_is_external(const char*)` | Check if external blockchain |
| `void dna_network_normalize(char*)` | Normalize network name to lowercase |
| `const char* dna_identity_get_wallet(const dna_unified_identity_t*, const char*)` | Get wallet for network |
| `int dna_identity_set_wallet(dna_unified_identity_t*, const char*, const char*)` | Set wallet for network |

### 11.6 DNA Feed (`dna_feed.h`)

#### Channel Operations

| Function | Description |
|----------|-------------|
| `int dna_feed_channel_create(dht_context_t*, const char*, const char*, const char*, const uint8_t*, dna_feed_channel_t**)` | Create new feed channel |
| `int dna_feed_channel_get(dht_context_t*, const char*, dna_feed_channel_t**)` | Get channel metadata |
| `int dna_feed_registry_get(dht_context_t*, dna_feed_registry_t**)` | Get all channels from registry |
| `int dna_feed_init_default_channels(dht_context_t*, const char*, const uint8_t*)` | Initialize default channels |
| `int dna_feed_make_channel_id(const char*, char*)` | Generate channel_id from name |
| `void dna_feed_channel_free(dna_feed_channel_t*)` | Free channel structure |
| `void dna_feed_registry_free(dna_feed_registry_t*)` | Free registry structure |

#### Post Operations

| Function | Description |
|----------|-------------|
| `int dna_feed_post_create(dht_context_t*, const char*, const char*, const char*, const uint8_t*, dna_feed_post_t**)` | Create new post |
| `int dna_feed_post_get(dht_context_t*, const char*, dna_feed_post_t**)` | Get single post by ID |
| `int dna_feed_posts_get_by_channel(dht_context_t*, const char*, const char*, dna_feed_post_t**, size_t*)` | Get posts for channel |
| `int dna_feed_post_get_full(dht_context_t*, const char*, dna_feed_post_with_comments_t**)` | Get post with comments |
| `int dna_feed_make_post_id(const char*, char*)` | Generate post_id |
| `int dna_feed_verify_post_signature(const dna_feed_post_t*, const uint8_t*)` | Verify post signature |
| `void dna_feed_post_free(dna_feed_post_t*)` | Free post structure |
| `void dna_feed_bucket_free(dna_feed_bucket_t*)` | Free bucket structure |
| `void dna_feed_post_with_comments_free(dna_feed_post_with_comments_t*)` | Free post with comments |

#### Comment Operations

| Function | Description |
|----------|-------------|
| `int dna_feed_comment_add(dht_context_t*, const char*, const char*, const char*, const uint8_t*, dna_feed_comment_t**)` | Add comment to post |
| `int dna_feed_comments_get(dht_context_t*, const char*, dna_feed_comment_t**, size_t*)` | Get all comments for post |
| `int dna_feed_make_comment_id(const char*, char*)` | Generate comment_id |
| `int dna_feed_verify_comment_signature(const dna_feed_comment_t*, const uint8_t*)` | Verify comment signature |
| `void dna_feed_comment_free(dna_feed_comment_t*)` | Free comment structure |
| `void dna_feed_comments_free(dna_feed_comment_t*, size_t)` | Free comments array |

#### Vote Operations

| Function | Description |
|----------|-------------|
| `int dna_feed_vote_cast(dht_context_t*, const char*, const char*, int8_t, const uint8_t*)` | Cast vote on post |
| `int dna_feed_votes_get(dht_context_t*, const char*, dna_feed_votes_t**)` | Get votes for post |
| `int8_t dna_feed_get_user_vote(const dna_feed_votes_t*, const char*)` | Get user's vote on post |
| `int dna_feed_verify_vote_signature(const dna_feed_vote_t*, const char*, const uint8_t*)` | Verify vote signature |
| `void dna_feed_votes_free(dna_feed_votes_t*)` | Free votes structure |
| `int dna_feed_comment_vote_cast(dht_context_t*, const char*, const char*, int8_t, const uint8_t*)` | Cast vote on comment |
| `int dna_feed_comment_votes_get(dht_context_t*, const char*, dna_feed_votes_t**)` | Get votes for comment |

#### DHT Key Generation

| Function | Description |
|----------|-------------|
| `int dna_feed_get_registry_key(char*)` | Get DHT key for channel registry |
| `int dna_feed_get_channel_key(const char*, char*)` | Get DHT key for channel metadata |
| `int dna_feed_get_bucket_key(const char*, const char*, char*)` | Get DHT key for daily post bucket |
| `int dna_feed_get_post_key(const char*, char*)` | Get DHT key for individual post |
| `int dna_feed_get_votes_key(const char*, char*)` | Get DHT key for post votes |
| `int dna_feed_get_comments_key(const char*, char*)` | Get DHT key for post comments |
| `int dna_feed_get_comment_votes_key(const char*, char*)` | Get DHT key for comment votes |
| `void dna_feed_get_today_date(char*)` | Get today's date string |

### 11.7 Message Wall (`dna_message_wall.h`)

| Function | Description |
|----------|-------------|
| `int dna_post_to_wall(dht_context_t*, const char*, const char*, const char*, const uint8_t*, const char*)` | Post message to wall |
| `int dna_load_wall(dht_context_t*, const char*, dna_message_wall_t**)` | Load message wall from DHT |
| `void dna_message_wall_free(dna_message_wall_t*)` | Free message wall |
| `int dna_message_wall_verify_signature(const dna_wall_message_t*, const uint8_t*)` | Verify message signature |
| `int dna_message_wall_to_json(const dna_message_wall_t*, char**)` | Serialize wall to JSON |
| `int dna_message_wall_from_json(const char*, dna_message_wall_t**)` | Parse wall from JSON |
| `int dna_wall_get_replies(const dna_message_wall_t*, const char*, dna_wall_message_t***, size_t*)` | Get direct replies to post |
| `int dna_wall_get_thread(const dna_message_wall_t*, const char*, dna_wall_message_t***, size_t*)` | Get full conversation thread |
| `int dna_wall_make_post_id(const char*, uint64_t, char*)` | Generate post_id |
| `int dna_wall_update_reply_counts(dna_message_wall_t*)` | Update reply counts |

### 11.8 Wall Votes (`dna_wall_votes.h`)

| Function | Description |
|----------|-------------|
| `int dna_cast_vote(dht_context_t*, const char*, const char*, int8_t, const uint8_t*)` | Cast vote on wall post |
| `int dna_load_votes(dht_context_t*, const char*, dna_wall_votes_t**)` | Load votes from DHT |
| `int8_t dna_get_user_vote(const dna_wall_votes_t*, const char*)` | Get user's vote on post |
| `void dna_wall_votes_free(dna_wall_votes_t*)` | Free votes structure |
| `int dna_verify_vote_signature(const dna_wall_vote_t*, const char*, const uint8_t*)` | Verify vote signature |

### 11.9 Group Outbox (`dna_group_outbox.h`)

#### Send/Receive API

| Function | Description |
|----------|-------------|
| `int dna_group_outbox_send(dht_context_t*, const char*, const char*, const char*, const uint8_t*, char*)` | Send message to group outbox |
| `int dna_group_outbox_fetch(dht_context_t*, const char*, uint64_t, dna_group_message_t**, size_t*)` | Fetch messages from group outbox |
| `int dna_group_outbox_sync(dht_context_t*, const char*, size_t*)` | Sync all hours since last sync |
| `int dna_group_outbox_sync_all(dht_context_t*, const char*, size_t*)` | Sync all groups user is member of |

#### Utility Functions

| Function | Description |
|----------|-------------|
| `uint64_t dna_group_outbox_get_hour_bucket(void)` | Get current hour bucket |
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
| `int dna_group_outbox_db_get_last_sync_hour(const char*, uint64_t*)` | Get last sync hour |
| `int dna_group_outbox_db_set_last_sync_hour(const char*, uint64_t)` | Update last sync hour |

#### Memory Management

| Function | Description |
|----------|-------------|
| `void dna_group_outbox_free_message(dna_group_message_t*)` | Free single message |
| `void dna_group_outbox_free_messages(dna_group_message_t*, size_t)` | Free message array |
| `void dna_group_outbox_free_bucket(dna_group_outbox_bucket_t*)` | Free bucket structure |
| `void dna_group_outbox_set_db(void*)` | Set database handle |

### 11.10 Message Backup (`dht_message_backup.h`)

| Function | Description |
|----------|-------------|
| `int dht_message_backup_init(void)` | Initialize message backup subsystem |
| `void dht_message_backup_cleanup(void)` | Cleanup message backup subsystem |
| `int dht_message_backup_publish(dht_context_t*, message_backup_context_t*, const char*, ...)` | Backup messages to DHT |
| `int dht_message_backup_restore(dht_context_t*, message_backup_context_t*, const char*, ...)` | Restore messages from DHT |
| `bool dht_message_backup_exists(dht_context_t*, const char*)` | Check if backup exists |
| `int dht_message_backup_get_info(dht_context_t*, const char*, uint64_t*, int*)` | Get backup info |

---

## 12. P2P Transport (`p2p/`)

Peer-to-peer transport layer for direct TCP messaging with DHT-based peer discovery.

### 12.1 P2P Transport (`p2p_transport.h`)

#### Core API

| Function | Description |
|----------|-------------|
| `p2p_transport_t* p2p_transport_init(const p2p_config_t*, ...)` | Initialize P2P transport layer |
| `int p2p_transport_start(p2p_transport_t*)` | Start DHT bootstrap + TCP listener |
| `void p2p_transport_stop(p2p_transport_t*)` | Stop transport and close connections |
| `void p2p_transport_free(p2p_transport_t*)` | Free transport context |
| `struct dht_context* p2p_transport_get_dht_context(p2p_transport_t*)` | Get DHT context from transport |
| `int p2p_transport_deliver_message(p2p_transport_t*, const uint8_t*, const uint8_t*, size_t)` | Deliver message via callback |

#### Peer Discovery

| Function | Description |
|----------|-------------|
| `int p2p_register_presence(p2p_transport_t*)` | Register presence in DHT |
| `int p2p_lookup_peer(p2p_transport_t*, const uint8_t*, peer_info_t*)` | Look up peer in DHT |
| `int p2p_lookup_presence_by_fingerprint(p2p_transport_t*, const char*, uint64_t*)` | Look up presence by fingerprint |

#### Direct Messaging

| Function | Description |
|----------|-------------|
| `int p2p_send_message(p2p_transport_t*, const uint8_t*, const uint8_t*, size_t)` | Send encrypted message to peer |
| `int p2p_check_offline_messages(p2p_transport_t*, size_t*)` | Check for offline messages in DHT |
| `int p2p_queue_offline_message(p2p_transport_t*, const char*, const char*, const uint8_t*, size_t, uint64_t)` | Queue message for offline recipient |

#### Connection Management

| Function | Description |
|----------|-------------|
| `int p2p_get_connected_peers(p2p_transport_t*, uint8_t(*)[2592], size_t, size_t*)` | Get connected peers |
| `int p2p_disconnect_peer(p2p_transport_t*, const uint8_t*)` | Disconnect from peer |
| `int p2p_get_stats(p2p_transport_t*, size_t*, size_t*, size_t*, size_t*)` | Get transport statistics |

---

## 13. Database (`database/`)

Local SQLite databases for contacts, caching, and profiles.

### 13.1 Contacts Database (`contacts_db.h`)

#### Core Operations

| Function | Description |
|----------|-------------|
| `int contacts_db_init(const char*)` | Initialize contacts database for identity |
| `int contacts_db_add(const char*, const char*)` | Add contact to database |
| `int contacts_db_remove(const char*)` | Remove contact from database |
| `int contacts_db_update_notes(const char*, const char*)` | Update contact notes |
| `bool contacts_db_exists(const char*)` | Check if contact exists |
| `int contacts_db_list(contact_list_t**)` | Get all contacts |
| `int contacts_db_count(void)` | Get contact count |
| `int contacts_db_clear_all(void)` | Clear all contacts |
| `void contacts_db_free_list(contact_list_t*)` | Free contact list |
| `void contacts_db_close(void)` | Close database |
| `int contacts_db_migrate_from_global(const char*)` | Migrate from global database |

#### Contact Requests

| Function | Description |
|----------|-------------|
| `int contacts_db_add_incoming_request(const char*, const char*, const char*, uint64_t)` | Add incoming contact request |
| `int contacts_db_get_incoming_requests(incoming_request_t**, int*)` | Get pending requests |
| `int contacts_db_pending_request_count(void)` | Get pending request count |
| `int contacts_db_approve_request(const char*)` | Approve contact request |
| `int contacts_db_deny_request(const char*)` | Deny contact request |
| `int contacts_db_remove_request(const char*)` | Remove contact request |
| `bool contacts_db_request_exists(const char*)` | Check if request exists |
| `void contacts_db_free_requests(incoming_request_t*, int)` | Free requests array |

#### Blocked Users

| Function | Description |
|----------|-------------|
| `int contacts_db_block_user(const char*, const char*)` | Block a user |
| `int contacts_db_unblock_user(const char*)` | Unblock a user |
| `bool contacts_db_is_blocked(const char*)` | Check if user is blocked |
| `int contacts_db_get_blocked_users(blocked_user_t**, int*)` | Get blocked users |
| `int contacts_db_blocked_count(void)` | Get blocked count |
| `void contacts_db_free_blocked(blocked_user_t*, int)` | Free blocked array |

### 13.2 Profile Manager (`profile_manager.h`)

| Function | Description |
|----------|-------------|
| `int profile_manager_init(void)` | Initialize profile manager |
| `int profile_manager_get_profile(const char*, dna_unified_identity_t**)` | Get profile (cache + DHT) |
| `int profile_manager_refresh_profile(const char*, dna_unified_identity_t**)` | Force refresh from DHT |
| `int profile_manager_refresh_all_expired(void)` | Refresh expired profiles (async) |
| `bool profile_manager_is_cached_and_fresh(const char*)` | Check if cached and fresh |
| `int profile_manager_delete_cached(const char*)` | Delete from cache |
| `int profile_manager_get_stats(int*, int*)` | Get cache statistics |
| `int profile_manager_prefetch_local_identities(const char*)` | Prefetch local identity profiles |
| `int dna_get_display_name(dht_context_t*, const char*, char**)` | Get display name for fingerprint |
| `void profile_manager_close(void)` | Close profile manager |

### 13.3 Profile Cache (`profile_cache.h`)

| Function | Description |
|----------|-------------|
| `int profile_cache_init(void)` | Initialize global profile cache |
| `int profile_cache_add_or_update(const char*, const dna_unified_identity_t*)` | Add/update cached profile |
| `int profile_cache_get(const char*, dna_unified_identity_t**, uint64_t*)` | Get cached profile |
| `bool profile_cache_exists(const char*)` | Check if profile cached |
| `bool profile_cache_is_expired(const char*)` | Check if profile expired |
| `int profile_cache_delete(const char*)` | Delete cached profile |
| `int profile_cache_list_expired(char***, size_t*)` | List expired profiles |
| `int profile_cache_list_all(profile_cache_list_t**)` | List all cached profiles |
| `int profile_cache_count(void)` | Get cached profile count |
| `int profile_cache_clear_all(void)` | Clear all cached profiles |
| `void profile_cache_free_list(profile_cache_list_t*)` | Free profile list |
| `void profile_cache_close(void)` | Close profile cache |

### 13.4 Keyserver Cache (`keyserver_cache.h`)

| Function | Description |
|----------|-------------|
| `int keyserver_cache_init(const char*)` | Initialize keyserver cache |
| `void keyserver_cache_cleanup(void)` | Cleanup keyserver cache |
| `int keyserver_cache_get(const char*, keyserver_cache_entry_t**)` | Get cached public key |
| `int keyserver_cache_put(const char*, const uint8_t*, size_t, const uint8_t*, size_t, uint64_t)` | Store public key |
| `int keyserver_cache_delete(const char*)` | Delete cached entry |
| `int keyserver_cache_expire_old(void)` | Clear expired entries |
| `bool keyserver_cache_exists(const char*)` | Check if entry exists |
| `int keyserver_cache_stats(int*, int*)` | Get cache statistics |
| `void keyserver_cache_free_entry(keyserver_cache_entry_t*)` | Free cache entry |
| `int keyserver_cache_get_name(const char*, char*, size_t)` | Get cached display name |
| `int keyserver_cache_put_name(const char*, const char*, uint64_t)` | Store display name |
| `int keyserver_cache_get_avatar(const char*, char**)` | Get cached avatar |
| `int keyserver_cache_put_avatar(const char*, const char*)` | Store avatar |

### 13.5 Presence Cache (`presence_cache.h`)

| Function | Description |
|----------|-------------|
| `int presence_cache_init(void)` | Initialize presence cache |
| `void presence_cache_update(const char*, bool, time_t)` | Update presence status |
| `bool presence_cache_get(const char*)` | Get online status |
| `time_t presence_cache_last_seen(const char*)` | Get last seen time |
| `void presence_cache_clear(void)` | Clear all entries |
| `void presence_cache_free(void)` | Cleanup presence cache |

### 13.6 Cache Manager (`cache_manager.h`)

| Function | Description |
|----------|-------------|
| `int cache_manager_init(const char*)` | Initialize all cache modules |
| `void cache_manager_cleanup(void)` | Cleanup all cache modules |
| `int cache_manager_evict_expired(void)` | Evict expired entries |
| `int cache_manager_stats(cache_manager_stats_t*)` | Get aggregated statistics |
| `void cache_manager_clear_all(void)` | Clear all caches |

### 13.7 Group Invitations (`group_invitations.h`)

| Function | Description |
|----------|-------------|
| `int group_invitations_init(const char*)` | Initialize invitations database |
| `int group_invitations_store(const group_invitation_t*)` | Store new invitation |
| `int group_invitations_get_pending(group_invitation_t**, int*)` | Get pending invitations |
| `int group_invitations_get(const char*, group_invitation_t**)` | Get invitation by UUID |
| `int group_invitations_update_status(const char*, invitation_status_t)` | Update invitation status |
| `int group_invitations_delete(const char*)` | Delete invitation |
| `void group_invitations_free(group_invitation_t*, int)` | Free invitation array |
| `void group_invitations_cleanup(void)` | Cleanup database |

---

## 14. Blockchain - Common Interface (`blockchain/`)

Modular blockchain interface for multi-chain wallet operations.

### 14.1 Blockchain Interface (`blockchain.h`)

| Function | Description |
|----------|-------------|
| `int blockchain_register(const blockchain_ops_t*)` | Register blockchain implementation |
| `const blockchain_ops_t* blockchain_get(const char*)` | Get blockchain by name |
| `const blockchain_ops_t* blockchain_get_by_type(blockchain_type_t)` | Get blockchain by type |
| `int blockchain_get_all(const blockchain_ops_t**, int)` | Get all registered blockchains |
| `int blockchain_init_all(void)` | Initialize all blockchains |
| `void blockchain_cleanup_all(void)` | Cleanup all blockchains |

### 14.2 Blockchain Wallet (`blockchain_wallet.h`)

| Function | Description |
|----------|-------------|
| `const char* blockchain_type_name(blockchain_type_t)` | Get blockchain name string |
| `const char* blockchain_type_ticker(blockchain_type_t)` | Get blockchain ticker |
| `int blockchain_create_all_wallets(const uint8_t*, const char*, const char*, const char*)` | Create all wallets from seed |
| `int blockchain_create_missing_wallets(const char*, const uint8_t*, int*)` | Create missing wallets |
| `int blockchain_create_wallet(blockchain_type_t, const uint8_t*, const char*, const char*, char*)` | Create wallet for blockchain |
| `int blockchain_list_wallets(const char*, blockchain_wallet_list_t**)` | List wallets for identity |
| `void blockchain_wallet_list_free(blockchain_wallet_list_t*)` | Free wallet list |
| `int blockchain_get_balance(blockchain_type_t, const char*, blockchain_balance_t*)` | Get wallet balance |
| `bool blockchain_validate_address(blockchain_type_t, const char*)` | Validate address format |
| `int blockchain_get_address_from_file(blockchain_type_t, const char*, char*)` | Get address from wallet file |
| `int blockchain_estimate_eth_gas(int, blockchain_gas_estimate_t*)` | Estimate ETH gas fee |
| `int blockchain_send_tokens(blockchain_type_t, const char*, const char*, const char*, const char*, int, char*)` | Send tokens |
| `int blockchain_derive_wallets_from_seed(const uint8_t*, const char*, const char*, blockchain_wallet_list_t**)` | Derive wallets on-demand |
| `int blockchain_send_tokens_with_seed(blockchain_type_t, const uint8_t*, const char*, const char*, const char*, const char*, int, char*)` | Send using derived key |

---

## 15. Blockchain - Cellframe (`blockchain/cellframe/`)

Cellframe blockchain integration with Dilithium post-quantum signatures.

### 15.1 Cellframe Wallet (`cellframe_wallet.h`)

| Function | Description |
|----------|-------------|
| `int wallet_read_cellframe_path(const char*, cellframe_wallet_t**)` | Read wallet from full path |
| `int wallet_read_cellframe(const char*, cellframe_wallet_t**)` | Read wallet from standard dir |
| `int wallet_list_cellframe(wallet_list_t**)` | List all Cellframe wallets |
| `int wallet_list_from_dna_dir(wallet_list_t**)` | List wallets from ~/.dna/wallets |
| `int wallet_list_for_identity(const char*, wallet_list_t**)` | List wallets for identity |
| `int wallet_get_address(const cellframe_wallet_t*, const char*, char*)` | Get wallet address |
| `void wallet_free(cellframe_wallet_t*)` | Free wallet structure |
| `void wallet_list_free(wallet_list_t*)` | Free wallet list |
| `const char* wallet_sig_type_name(wallet_sig_type_t)` | Get signature type name |

### 15.2 Cellframe Address (`cellframe_addr.h`)

| Function | Description |
|----------|-------------|
| `int cellframe_addr_from_pubkey(const uint8_t*, size_t, uint64_t, char*)` | Generate address from pubkey |
| `int cellframe_addr_for_identity(const char*, uint64_t, char*)` | Get address for DNA identity |
| `int cellframe_addr_to_str(const void*, char*, size_t)` | Convert binary to base58 |
| `int cellframe_addr_from_str(const char*, void*)` | Parse base58 to binary |

### 15.3 Cellframe RPC (`cellframe_rpc.h`)

| Function | Description |
|----------|-------------|
| `int cellframe_rpc_call(const cellframe_rpc_request_t*, cellframe_rpc_response_t**)` | Make RPC call |
| `int cellframe_rpc_get_tx(const char*, const char*, cellframe_rpc_response_t**)` | Get transaction details |
| `int cellframe_rpc_get_block(const char*, uint64_t, cellframe_rpc_response_t**)` | Get block details |
| `int cellframe_rpc_get_balance(const char*, const char*, const char*, cellframe_rpc_response_t**)` | Get wallet balance |
| `int cellframe_rpc_get_utxo(const char*, const char*, const char*, cellframe_rpc_response_t**)` | Get UTXOs |
| `int cellframe_rpc_submit_tx(const char*, const char*, const char*, cellframe_rpc_response_t**)` | Submit transaction |
| `int cellframe_rpc_get_tx_history(const char*, const char*, cellframe_rpc_response_t**)` | Get transaction history |
| `void cellframe_rpc_response_free(cellframe_rpc_response_t*)` | Free RPC response |
| `int cellframe_verify_registration_tx(const char*, const char*, const char*)` | Verify DNA registration tx |

### 15.4 Cellframe Transaction Builder (`cellframe_tx_builder.h`)

| Function | Description |
|----------|-------------|
| `cellframe_tx_builder_t* cellframe_tx_builder_new(void)` | Create transaction builder |
| `void cellframe_tx_builder_free(cellframe_tx_builder_t*)` | Free transaction builder |
| `int cellframe_tx_set_timestamp(cellframe_tx_builder_t*, uint64_t)` | Set transaction timestamp |
| `int cellframe_tx_add_in(cellframe_tx_builder_t*, const cellframe_hash_t*, uint32_t)` | Add input |
| `int cellframe_tx_add_out(cellframe_tx_builder_t*, const cellframe_addr_t*, uint256_t)` | Add output (native) |
| `int cellframe_tx_add_out_ext(cellframe_tx_builder_t*, const cellframe_addr_t*, uint256_t, const char*)` | Add output (token) |
| `int cellframe_tx_add_fee(cellframe_tx_builder_t*, uint256_t)` | Add fee output |
| `int cellframe_tx_add_tsd(cellframe_tx_builder_t*, uint16_t, const uint8_t*, size_t)` | Add TSD data |
| `const uint8_t* cellframe_tx_get_signing_data(cellframe_tx_builder_t*, size_t*)` | Get data for signing |
| `const uint8_t* cellframe_tx_get_data(cellframe_tx_builder_t*, size_t*)` | Get complete tx data |
| `int cellframe_tx_add_signature(cellframe_tx_builder_t*, const uint8_t*, size_t)` | Add signature |
| `int cellframe_uint256_from_str(const char*, uint256_t*)` | Parse CELL to datoshi |
| `int cellframe_uint256_scan_uninteger(const char*, uint256_t*)` | Parse raw datoshi |
| `int cellframe_hex_to_bin(const char*, uint8_t*, size_t)` | Hex to binary |

---

## 16. Blockchain - Ethereum (`blockchain/ethereum/`)

Ethereum blockchain with secp256k1 ECDSA signatures.

### 16.1 Ethereum Wallet (`eth_wallet.h`)

| Function | Description |
|----------|-------------|
| `int eth_wallet_create_from_seed(const uint8_t*, size_t, const char*, const char*, char*)` | Create wallet from seed |
| `int eth_wallet_generate(const uint8_t*, size_t, eth_wallet_t*)` | Generate wallet in memory |
| `void eth_wallet_clear(eth_wallet_t*)` | Clear wallet securely |
| `int eth_wallet_save(const eth_wallet_t*, const char*, const char*)` | Save wallet to file |
| `int eth_wallet_load(const char*, eth_wallet_t*)` | Load wallet from file |
| `int eth_wallet_get_address(const char*, char*, size_t)` | Get address from file |
| `int eth_address_from_private_key(const uint8_t*, uint8_t*)` | Derive address from privkey |
| `int eth_address_to_hex(const uint8_t*, char*)` | Format checksummed hex |
| `bool eth_validate_address(const char*)` | Validate address format |
| `int eth_rpc_get_balance(const char*, char*, size_t)` | Get ETH balance |
| `int eth_rpc_set_endpoint(const char*)` | Set RPC endpoint |
| `const char* eth_rpc_get_endpoint(void)` | Get RPC endpoint |
| `int eth_rpc_get_transactions(const char*, eth_transaction_t**, int*)` | Get transaction history |
| `void eth_rpc_free_transactions(eth_transaction_t*, int)` | Free transactions |

### 16.2 Ethereum Transactions (`eth_tx.h`)

| Function | Description |
|----------|-------------|
| `int eth_tx_get_nonce(const char*, uint64_t*)` | Get transaction nonce |
| `int eth_tx_get_gas_price(uint64_t*)` | Get current gas price |
| `int eth_tx_estimate_gas(const char*, const char*, const char*, uint64_t*)` | Estimate gas |
| `void eth_tx_init_transfer(eth_tx_t*, uint64_t, uint64_t, const uint8_t*, const uint8_t*, uint64_t)` | Init transfer tx |
| `int eth_tx_sign(const eth_tx_t*, const uint8_t*, eth_signed_tx_t*)` | Sign transaction |
| `int eth_tx_send(const eth_signed_tx_t*, char*)` | Broadcast transaction |
| `int eth_send_eth(const uint8_t*, const char*, const char*, const char*, char*)` | Send ETH |
| `int eth_send_eth_with_gas(const uint8_t*, const char*, const char*, const char*, int, char*)` | Send with gas preset |
| `int eth_parse_amount(const char*, uint8_t*)` | Parse amount to wei |
| `int eth_parse_address(const char*, uint8_t*)` | Parse hex address |

---

## 17. Blockchain - Solana (`blockchain/solana/`)

Solana blockchain with Ed25519 signatures.

### 17.1 Solana Wallet (`sol_wallet.h`)

| Function | Description |
|----------|-------------|
| `int sol_wallet_generate(const uint8_t*, size_t, sol_wallet_t*)` | Generate wallet from seed |
| `int sol_wallet_create_from_seed(const uint8_t*, size_t, const char*, const char*, char*)` | Create and save wallet |
| `int sol_wallet_load(const char*, sol_wallet_t*)` | Load wallet from file |
| `int sol_wallet_save(const sol_wallet_t*, const char*, const char*)` | Save wallet to file |
| `void sol_wallet_clear(sol_wallet_t*)` | Clear wallet from memory |
| `int sol_pubkey_to_address(const uint8_t*, char*)` | Public key to base58 |
| `int sol_address_to_pubkey(const char*, uint8_t*)` | Base58 to public key |
| `bool sol_validate_address(const char*)` | Validate address format |
| `int sol_sign_message(const uint8_t*, size_t, const uint8_t*, const uint8_t*, uint8_t*)` | Sign message |
| `void sol_rpc_set_endpoint(const char*)` | Set RPC endpoint |
| `const char* sol_rpc_get_endpoint(void)` | Get RPC endpoint |

### 17.2 Solana Transactions (`sol_tx.h`)

| Function | Description |
|----------|-------------|
| `int sol_tx_build_transfer(const sol_wallet_t*, const uint8_t*, uint64_t, const uint8_t*, uint8_t*, size_t, size_t*)` | Build transfer tx |
| `int sol_tx_send_lamports(const sol_wallet_t*, const char*, uint64_t, char*, size_t)` | Send in lamports |
| `int sol_tx_send_sol(const sol_wallet_t*, const char*, double, char*, size_t)` | Send in SOL |

---

## 18. Blockchain - TRON (`blockchain/tron/`)

TRON blockchain with secp256k1 signatures.

### 18.1 TRON Wallet (`trx_wallet.h`)

| Function | Description |
|----------|-------------|
| `int trx_wallet_generate(const uint8_t*, size_t, trx_wallet_t*)` | Generate wallet from seed |
| `int trx_wallet_create_from_seed(const uint8_t*, size_t, const char*, const char*, char*)` | Create and save wallet |
| `void trx_wallet_clear(trx_wallet_t*)` | Clear wallet securely |
| `int trx_wallet_save(const trx_wallet_t*, const char*, const char*)` | Save wallet to file |
| `int trx_wallet_load(const char*, trx_wallet_t*)` | Load wallet from file |
| `int trx_wallet_get_address(const char*, char*, size_t)` | Get address from file |
| `int trx_address_from_pubkey(const uint8_t*, uint8_t*)` | Derive address from pubkey |
| `int trx_address_to_base58(const uint8_t*, char*, size_t)` | Encode address as base58 |
| `int trx_address_from_base58(const char*, uint8_t*)` | Decode base58 address |
| `bool trx_validate_address(const char*)` | Validate address format |
| `int trx_rpc_set_endpoint(const char*)` | Set RPC endpoint |
| `const char* trx_rpc_get_endpoint(void)` | Get RPC endpoint |

### 18.2 TRON Transactions (`trx_tx.h`)

| Function | Description |
|----------|-------------|
| `int trx_tx_create_transfer(const char*, const char*, uint64_t, trx_tx_t*)` | Create TRX transfer |
| `int trx_tx_create_trc20_transfer(const char*, const char*, const char*, const char*, trx_tx_t*)` | Create TRC-20 transfer |
| `int trx_tx_sign(const trx_tx_t*, const uint8_t*, trx_signed_tx_t*)` | Sign transaction |
| `int trx_tx_broadcast(const trx_signed_tx_t*, char*)` | Broadcast transaction |
| `int trx_send_trx(const uint8_t*, const char*, const char*, const char*, char*)` | Send TRX |
| `int trx_parse_amount(const char*, uint64_t*)` | Parse TRX to SUN |
| `int trx_hex_to_base58(const char*, char*, size_t)` | Hex to base58 |
| `int trx_base58_to_hex(const char*, char*, size_t)` | Base58 to hex |

---

## 19. Engine Implementation (`src/api/`)

Internal DNA engine implementation with async task queue.

### 19.1 Engine Internal (`dna_engine_internal.h`)

#### Task Queue

| Function | Description |
|----------|-------------|
| `void dna_task_queue_init(dna_task_queue_t*)` | Initialize task queue |
| `bool dna_task_queue_push(dna_task_queue_t*, const dna_task_t*)` | Push task to queue |
| `bool dna_task_queue_pop(dna_task_queue_t*, dna_task_t*)` | Pop task from queue |
| `bool dna_task_queue_empty(dna_task_queue_t*)` | Check if queue empty |

#### Threading

| Function | Description |
|----------|-------------|
| `int dna_start_workers(dna_engine_t*)` | Start worker threads |
| `void dna_stop_workers(dna_engine_t*)` | Stop worker threads |
| `void* dna_worker_thread(void*)` | Worker thread entry point |

#### Task Execution

| Function | Description |
|----------|-------------|
| `void dna_execute_task(dna_engine_t*, dna_task_t*)` | Execute task |
| `dna_request_id_t dna_next_request_id(dna_engine_t*)` | Generate next request ID |
| `dna_request_id_t dna_submit_task(dna_engine_t*, dna_task_type_t, ...)` | Submit task to queue |
| `void dna_dispatch_event(dna_engine_t*, const dna_event_t*)` | Dispatch event to callback |

#### Task Handlers - Identity

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

#### Task Handlers - Contacts

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

#### Task Handlers - Messaging

| Function | Description |
|----------|-------------|
| `void dna_handle_send_message(dna_engine_t*, dna_task_t*)` | Handle send message |
| `void dna_handle_get_conversation(dna_engine_t*, dna_task_t*)` | Handle get conversation |
| `void dna_handle_check_offline_messages(dna_engine_t*, dna_task_t*)` | Handle check offline |

#### Task Handlers - Groups

| Function | Description |
|----------|-------------|
| `void dna_handle_get_groups(dna_engine_t*, dna_task_t*)` | Handle get groups |
| `void dna_handle_create_group(dna_engine_t*, dna_task_t*)` | Handle create group |
| `void dna_handle_send_group_message(dna_engine_t*, dna_task_t*)` | Handle group message |
| `void dna_handle_get_invitations(dna_engine_t*, dna_task_t*)` | Handle get invitations |
| `void dna_handle_accept_invitation(dna_engine_t*, dna_task_t*)` | Handle accept invite |
| `void dna_handle_reject_invitation(dna_engine_t*, dna_task_t*)` | Handle reject invite |

#### Task Handlers - Wallet

| Function | Description |
|----------|-------------|
| `void dna_handle_list_wallets(dna_engine_t*, dna_task_t*)` | Handle list wallets |
| `void dna_handle_get_balances(dna_engine_t*, dna_task_t*)` | Handle get balances |
| `void dna_handle_send_tokens(dna_engine_t*, dna_task_t*)` | Handle send tokens |
| `void dna_handle_get_transactions(dna_engine_t*, dna_task_t*)` | Handle get transactions |

#### Task Handlers - P2P/Presence

| Function | Description |
|----------|-------------|
| `void dna_handle_refresh_presence(dna_engine_t*, dna_task_t*)` | Handle refresh presence |
| `void dna_handle_lookup_presence(dna_engine_t*, dna_task_t*)` | Handle lookup presence |
| `void dna_handle_sync_contacts_to_dht(dna_engine_t*, dna_task_t*)` | Handle sync to DHT |
| `void dna_handle_sync_contacts_from_dht(dna_engine_t*, dna_task_t*)` | Handle sync from DHT |
| `void dna_handle_sync_groups(dna_engine_t*, dna_task_t*)` | Handle sync groups |
| `void dna_handle_subscribe_to_contacts(dna_engine_t*, dna_task_t*)` | Handle subscribe |
| `void dna_handle_get_registered_name(dna_engine_t*, dna_task_t*)` | Handle get name |

#### Task Handlers - Feed

| Function | Description |
|----------|-------------|
| `void dna_handle_get_feed_channels(dna_engine_t*, dna_task_t*)` | Handle get channels |
| `void dna_handle_create_feed_channel(dna_engine_t*, dna_task_t*)` | Handle create channel |
| `void dna_handle_init_default_channels(dna_engine_t*, dna_task_t*)` | Handle init defaults |
| `void dna_handle_get_feed_posts(dna_engine_t*, dna_task_t*)` | Handle get posts |
| `void dna_handle_create_feed_post(dna_engine_t*, dna_task_t*)` | Handle create post |
| `void dna_handle_add_feed_comment(dna_engine_t*, dna_task_t*)` | Handle add comment |
| `void dna_handle_get_feed_comments(dna_engine_t*, dna_task_t*)` | Handle get comments |
| `void dna_handle_cast_feed_vote(dna_engine_t*, dna_task_t*)` | Handle cast vote |
| `void dna_handle_get_feed_votes(dna_engine_t*, dna_task_t*)` | Handle get votes |
| `void dna_handle_cast_comment_vote(dna_engine_t*, dna_task_t*)` | Handle comment vote |
| `void dna_handle_get_comment_votes(dna_engine_t*, dna_task_t*)` | Handle get comment votes |

#### Helpers

| Function | Description |
|----------|-------------|
| `int dna_scan_identities(const char*, char***, int*)` | Scan for identity files |
| `void dna_free_task_params(dna_task_t*)` | Free task parameters |

---

## Appendix: Key Sizes Reference

| Algorithm | Component | Size (bytes) | Notes |
|-----------|-----------|--------------|-------|
| **Kyber1024** | Public Key | 1568 | ML-KEM-1024 |
| **Kyber1024** | Private Key | 3168 | ML-KEM-1024 |
| **Kyber1024** | Ciphertext | 1568 | KEM encapsulation |
| **Kyber1024** | Shared Secret | 32 | 256-bit symmetric key |
| **Dilithium5** | Public Key | 2592 | ML-DSA-87 |
| **Dilithium5** | Private Key | 4896 | ML-DSA-87 |
| **Dilithium5** | Signature | 4627 | Variable (max 4627) |
| **AES-256-GCM** | Key | 32 | 256-bit |
| **AES-256-GCM** | Nonce | 12 | 96-bit |
| **AES-256-GCM** | Tag | 16 | 128-bit auth tag |
| **SHA3-512** | Hash | 64 | Fingerprint |
| **SHA3-256** | Hash | 32 | General hashing |
| **BIP39** | Master Seed | 64 | 512-bit |
| **BIP39** | Entropy | 32 | 256-bit (24 words) |
| **Ed25519** | Private Key | 32 | Solana |
| **Ed25519** | Public Key | 32 | Solana |
| **Ed25519** | Signature | 64 | Solana |
| **secp256k1** | Private Key | 32 | ETH/TRON |
| **secp256k1** | Public Key | 65 | Uncompressed |
| **secp256k1** | Signature | 65 | Recoverable (r,s,v) |

