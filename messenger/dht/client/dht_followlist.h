/**
 * DHT Follow List Synchronization
 * Per-identity follow list storage with encryption and DHT sync
 *
 * Architecture:
 * - Each identity has their own follow list in DHT
 * - Follow lists are self-encrypted with user's own Kyber1024 pubkey
 * - Dilithium5 signature for authenticity (prevent tampering)
 * - 7-day TTL with auto-republish
 * - Private: only the owner can decrypt
 *
 * DHT Key Derivation:
 * SHA3-512(identity + ":followlist") -> 64-byte DHT storage key
 *
 * Data Format (before encryption):
 * { "identity": "alice", "version": 1, "timestamp": 1730742000,
 *   "following": ["fp1", "fp2", ...] }
 *
 * Encrypted Format (stored in DHT):
 * [4-byte magic "FLST"][1-byte version][8-byte timestamp]
 * [8-byte expiry][4-byte json_len][encrypted_json_data]
 * [4-byte sig_len][dilithium5_signature]
 *
 * Security:
 * - Kyber1024 self-encryption (only owner can decrypt)
 * - Dilithium5 signature over (json_data || timestamp)
 *
 * @file dht_followlist.h
 */

#ifndef DHT_FOLLOWLIST_H
#define DHT_FOLLOWLIST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic bytes for follow list format validation: "FLST" */
#define DHT_FOLLOWLIST_MAGIC   0x464C5354
#define DHT_FOLLOWLIST_VERSION 1

/* Default TTL: 7 days (604,800 seconds) */
#define DHT_FOLLOWLIST_DEFAULT_TTL 604800

/**
 * Publish follow list to DHT (encrypted with self-encryption)
 *
 * @param identity           Owner fingerprint (128 hex chars)
 * @param fingerprints       Array of followed user fingerprints
 * @param count              Number of followed users
 * @param kyber_pubkey       Owner's Kyber1024 public key (1568 bytes)
 * @param kyber_privkey      Owner's Kyber1024 private key (3168 bytes)
 * @param dilithium_pubkey   Owner's Dilithium5 public key (2592 bytes)
 * @param dilithium_privkey  Owner's Dilithium5 private key (4896 bytes)
 * @param ttl_seconds        Time-to-live (0 = default 7 days)
 * @return 0 on success, -1 on error
 */
int dht_followlist_publish(
    const char *identity,
    const char **fingerprints,
    size_t count,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds
);

/**
 * Fetch follow list from DHT (decrypt and verify)
 *
 * @param identity           Owner fingerprint
 * @param fingerprints_out   Output array of fingerprints (caller must free)
 * @param count_out          Output number of followed users
 * @param kyber_privkey      Owner's Kyber1024 private key (for decryption)
 * @param dilithium_pubkey   Owner's Dilithium5 public key (for verification)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_followlist_fetch(
    const char *identity,
    char ***fingerprints_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey
);

/**
 * Free fingerprints array returned by dht_followlist_fetch
 *
 * @param fingerprints Array of fingerprint strings
 * @param count        Number of entries
 */
void dht_followlist_free(char **fingerprints, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* DHT_FOLLOWLIST_H */
