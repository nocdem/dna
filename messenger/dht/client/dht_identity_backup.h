/**
 * DHT Identity Backup System
 * Encrypted backup of random DHT signing identity for BIP39 recovery
 *
 * Architecture:
 * - Generate random DHT identity (RSA-2048 or EC via OpenDHT)
 * - Encrypt with user's Kyber1024 public key
 * - Store locally + in DHT for multi-device recovery
 *
 * @file dht_identity_backup.h
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#ifndef DHT_IDENTITY_BACKUP_H
#define DHT_IDENTITY_BACKUP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../dna_api.h"
#include "../core/dht_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DHT Identity Handle (opaque)
 * Wraps OpenDHT crypto::Identity (PrivateKey + Certificate pair)
 */
typedef struct dht_identity dht_identity_t;

/**
 * Create new random DHT identity and save encrypted backup
 *
 * Flow:
 * 1. Generate random DHT identity (RSA-2048 via OpenDHT)
 * 2. Export identity to PEM format (private key + certificate)
 * 3. Encrypt with Kyber1024 public key
 * 4. Save to local file: ~/.dna/<fingerprint>_dht_identity.enc
 * 5. Publish to DHT: SHA3-512(fingerprint + ":dht_identity")
 * 6. Return identity for immediate use
 *
 * @param user_fingerprint User's Dilithium5 fingerprint (128-char hex)
 * @param kyber_pubkey User's Kyber1024 public key (for encryption)
 * @param dht_ctx DHT context (for publishing backup)
 * @param identity_out Output identity handle (caller must free)
 * @return 0 on success, -1 on error
 */
int dht_identity_create_and_backup(
    const char *user_fingerprint,
    const uint8_t *kyber_pubkey,  // Kyber1024 public key (1568 bytes)
    dht_context_t *dht_ctx,
    dht_identity_t **identity_out);

/**
 * Load DHT identity from local encrypted backup
 *
 * Flow:
 * 1. Read encrypted backup from ~/.dna/<fingerprint>_dht_identity.enc
 * 2. Decrypt with Kyber1024 private key
 * 3. Import PEM data to OpenDHT identity
 * 4. Return identity for use
 *
 * @param user_fingerprint User's Dilithium5 fingerprint
 * @param kyber_privkey User's Kyber1024 private key (for decryption)
 * @param identity_out Output identity handle
 * @return 0 on success, -1 on error (file not found, decryption failed)
 */
int dht_identity_load_from_local(
    const char *user_fingerprint,
    const uint8_t *kyber_privkey,  // Kyber1024 private key (3168 bytes)
    dht_identity_t **identity_out);

/**
 * Fetch DHT identity from DHT and decrypt (recovery on new device)
 *
 * Flow:
 * 1. Compute DHT key: SHA3-512(fingerprint + ":dht_identity")
 * 2. Fetch encrypted backup from DHT
 * 3. Decrypt with Kyber1024 private key
 * 4. Save to local file (for next login)
 * 5. Import to OpenDHT identity
 * 6. Return identity for use
 *
 * @param user_fingerprint User's Dilithium5 fingerprint
 * @param kyber_privkey User's Kyber1024 private key
 * @param dht_ctx DHT context (for fetching)
 * @param identity_out Output identity handle
 * @return 0 on success, -1 on error (DHT fetch failed, decryption failed)
 */
int dht_identity_fetch_from_dht(
    const char *user_fingerprint,
    const uint8_t *kyber_privkey,  // Kyber1024 private key (3168 bytes)
    dht_context_t *dht_ctx,
    dht_identity_t **identity_out);

/**
 * Publish encrypted DHT identity backup to DHT
 *
 * Used to retry publish if initial attempt failed during create_and_backup().
 * Should be called on every login until DHT publish succeeds.
 *
 * @param user_fingerprint User's Dilithium5 fingerprint
 * @param encrypted_backup Encrypted identity blob
 * @param backup_size Size of encrypted blob
 * @param dht_ctx DHT context
 * @return 0 on success, -1 on error
 */
int dht_identity_publish_backup(
    const char *user_fingerprint,
    const uint8_t *encrypted_backup,
    size_t backup_size,
    dht_context_t *dht_ctx);

/**
 * Check if local backup file exists
 *
 * @param user_fingerprint User's Dilithium5 fingerprint
 * @return true if file exists, false otherwise
 */
bool dht_identity_local_exists(const char *user_fingerprint);

/**
 * Check if DHT backup exists
 *
 * @param user_fingerprint User's Dilithium5 fingerprint
 * @param dht_ctx DHT context
 * @return true if backup exists in DHT, false otherwise
 */
bool dht_identity_dht_exists(
    const char *user_fingerprint,
    dht_context_t *dht_ctx);

/**
 * Free DHT identity
 *
 * @param identity Identity handle
 */
void dht_identity_free(dht_identity_t *identity);

/**
 * Get local backup file path
 *
 * @param user_fingerprint User's Dilithium5 fingerprint
 * @param path_out Output buffer (min 512 bytes)
 * @return 0 on success, -1 on error
 */
int dht_identity_get_local_path(
    const char *user_fingerprint,
    char *path_out);

#ifdef __cplusplus
}
#endif

#endif // DHT_IDENTITY_BACKUP_H
