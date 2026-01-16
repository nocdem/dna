/**
 * DHT Message Backup/Restore
 * Per-identity message backup storage with encryption and DHT sync
 *
 * Architecture:
 * - Each identity can backup their messages to DHT
 * - Messages are self-encrypted with user's own Kyber1024 pubkey
 * - Dilithium5 signature for authenticity (prevent tampering)
 * - 7-day TTL for temporary backup storage
 * - Restore skips duplicates using ciphertext hash check
 *
 * DHT Key Derivation:
 * SHA3-512(fingerprint + ":message_backup") -> 64-byte DHT storage key
 *
 * Data Format v2 (before encryption):
 * {
 *   "version": 2,
 *   "fingerprint": "abc123...",
 *   "timestamp": 1703894400,
 *   "message_count": 150,
 *   "messages": [...],
 *
 *   "gek_count": 3,
 *   "geks": [
 *     {
 *       "group_uuid": "uuid-v4-string",
 *       "gek_version": 5,
 *       "gek_base64": "encrypted-gek-bytes",
 *       "created_at": 1703890000,
 *       "expires_at": 1704494800
 *     }
 *   ],
 *
 *   "group_count": 2,
 *   "groups": [
 *     {
 *       "uuid": "uuid-v4-string",
 *       "name": "Group Name",
 *       "owner_fingerprint": "abc123...",
 *       "is_owner": true,
 *       "members": ["fp1", "fp2"],
 *       "created_at": 1703890000
 *     }
 *   ]
 * }
 *
 * Encrypted Format (stored in DHT):
 * [4-byte magic "MSGB"][1-byte version][8-byte timestamp]
 * [8-byte expiry][4-byte payload_len][encrypted_payload]
 * [4-byte sig_len][dilithium5_signature]
 *
 * Security:
 * - Kyber1024 self-encryption (only owner can decrypt)
 * - Dilithium5 signature over (json_data || timestamp)
 * - Fingerprint verification in signature validation
 *
 * @file dht_message_backup.h
 * @date 2025-12-28
 */

#ifndef DHT_MESSAGE_BACKUP_H
#define DHT_MESSAGE_BACKUP_H

#include "../core/dht_context.h"
#include "../../message_backup.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic bytes for message backup format validation
#define DHT_MSGBACKUP_MAGIC 0x4D534742  // "MSGB"
#define DHT_MSGBACKUP_VERSION 3

// Version 2 adds GEK and group data to backup
// Version 3 changes encrypted_message to plaintext (v14 schema)

// Default TTL: 7 days (604,800 seconds)
#define DHT_MSGBACKUP_DEFAULT_TTL 604800

// Key sizes (NIST Category 5)
#define DHT_MSGBACKUP_KYBER_PUBKEY_SIZE 1568
#define DHT_MSGBACKUP_KYBER_PRIVKEY_SIZE 3168
#define DHT_MSGBACKUP_DILITHIUM_PUBKEY_SIZE 2592
#define DHT_MSGBACKUP_DILITHIUM_PRIVKEY_SIZE 4896
#define DHT_MSGBACKUP_DILITHIUM_SIGNATURE_SIZE 4627

/**
 * Backup result structure
 */
typedef struct {
    int message_count;      // Number of messages processed
    int skipped_count;      // Number of duplicates skipped (restore only)
    uint64_t timestamp;     // Backup timestamp
} dht_message_backup_result_t;

/**
 * Initialize DHT message backup subsystem
 * Must be called before using any other functions
 *
 * @return 0 on success, -1 on error
 */
int dht_message_backup_init(void);

/**
 * Cleanup DHT message backup subsystem
 * Call on shutdown
 */
void dht_message_backup_cleanup(void);

/**
 * Backup all messages to DHT (encrypted with self-encryption)
 *
 * Workflow:
 * 1. Query all messages from SQLite
 * 2. Serialize messages to JSON (with base64-encoded ciphertext)
 * 3. Sign JSON with Dilithium5 private key
 * 4. Encrypt JSON with owner's Kyber1024 public key (self-encryption)
 * 5. Create binary blob: [header][encrypted_json][signature]
 * 6. Store in DHT at SHA3-512(fingerprint + ":message_backup")
 *
 * @param dht_ctx DHT context
 * @param msg_ctx Message backup context (SQLite database)
 * @param fingerprint Owner fingerprint (128-char hex string)
 * @param kyber_pubkey Owner's Kyber1024 public key (1568 bytes)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes) - for decryption test
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes) - for encryption
 * @param dilithium_privkey Owner's Dilithium5 private key (4896 bytes) - for signing
 * @param message_count_out Output: number of messages backed up (can be NULL)
 * @return 0 on success, -1 on error
 */
int dht_message_backup_publish(
    dht_context_t *dht_ctx,
    message_backup_context_t *msg_ctx,
    const char *fingerprint,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    int *message_count_out
);

/**
 * Restore messages from DHT (skip duplicates)
 *
 * Workflow:
 * 1. Query DHT at SHA3-512(fingerprint + ":message_backup")
 * 2. Parse binary blob header
 * 3. Decrypt encrypted JSON with Kyber1024 private key
 * 4. Verify Dilithium5 signature
 * 5. Parse JSON to message array
 * 6. For each message, check if exists (skip duplicates)
 * 7. Import non-duplicate messages to SQLite
 *
 * @param dht_ctx DHT context
 * @param msg_ctx Message backup context (SQLite database)
 * @param fingerprint Owner fingerprint (128-char hex string)
 * @param kyber_privkey Owner's Kyber1024 private key (for decryption)
 * @param dilithium_pubkey Owner's Dilithium5 public key (for signature verification)
 * @param restored_count_out Output: number of messages restored (can be NULL)
 * @param skipped_count_out Output: number of duplicates skipped (can be NULL)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_message_backup_restore(
    dht_context_t *dht_ctx,
    message_backup_context_t *msg_ctx,
    const char *fingerprint,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    int *restored_count_out,
    int *skipped_count_out
);

/**
 * Check if message backup exists in DHT
 *
 * @param dht_ctx DHT context
 * @param fingerprint Owner fingerprint
 * @return true if exists, false otherwise
 */
bool dht_message_backup_exists(
    dht_context_t *dht_ctx,
    const char *fingerprint
);

/**
 * Get message backup timestamp from DHT (without full fetch)
 * Useful for checking if backup exists and when it was created
 *
 * @param dht_ctx DHT context
 * @param fingerprint Owner fingerprint
 * @param timestamp_out Output timestamp
 * @param message_count_out Output message count (can be NULL)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_message_backup_get_info(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    uint64_t *timestamp_out,
    int *message_count_out
);

#ifdef __cplusplus
}
#endif

#endif // DHT_MESSAGE_BACKUP_H
