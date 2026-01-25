/**
 * @file gek.h
 * @brief Group Encryption Key (GEK) Manager
 *
 * Manages AES-256 symmetric keys for group messaging encryption.
 * Provides generation, storage, rotation, and retrieval of GEKs.
 *
 * Part of DNA Messenger - GEK System
 *
 * @date 2026-01-10
 */

#ifndef GEK_H
#define GEK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

/**
 * GEK key size (AES-256)
 */
#define GEK_KEY_SIZE 32

/**
 * Default GEK expiration (7 days in seconds)
 */
#define GEK_DEFAULT_EXPIRY (7 * 24 * 3600)

/**
 * GEK encryption constants (Kyber1024 KEM + AES-256-GCM)
 */
#define GEK_ENC_KEM_CT_SIZE     1568    /* Kyber1024 ciphertext */
#define GEK_ENC_NONCE_SIZE      12      /* AES-256-GCM nonce */
#define GEK_ENC_TAG_SIZE        16      /* AES-256-GCM tag */
#define GEK_ENC_KEY_SIZE        32      /* GEK size (AES-256 key) */
#define GEK_ENC_TOTAL_SIZE      (GEK_ENC_KEM_CT_SIZE + \
                                 GEK_ENC_NONCE_SIZE + \
                                 GEK_ENC_TAG_SIZE + \
                                 GEK_ENC_KEY_SIZE)  /* 1628 bytes */

/* ============================================================================
 * TYPES
 * ============================================================================ */

/**
 * GEK entry structure (local storage)
 */
typedef struct {
    char group_uuid[37];       // UUID v4 (36 + null terminator)
    uint32_t gek_version;      // Rotation counter (0, 1, 2, ...)
    uint8_t gek[GEK_KEY_SIZE]; // AES-256 key
    uint64_t created_at;       // Unix timestamp (seconds)
    uint64_t expires_at;       // created_at + GEK_DEFAULT_EXPIRY
} gek_entry_t;

/**
 * Member entry for IKP building
 */
typedef struct {
    uint8_t fingerprint[64];        // SHA3-512 fingerprint (binary)
    const uint8_t *kyber_pubkey;    // Kyber1024 public key (1568 bytes)
} gek_member_entry_t;

/* ============================================================================
 * IKP (Initial Key Packet) CONSTANTS
 * ============================================================================ */

/**
 * Maximum number of members per group
 * Prevents memory exhaustion from malicious packets claiming large member counts
 */
#define IKP_MAX_MEMBERS 16

/**
 * Per-member entry size in Initial Key Packet
 * fingerprint(64) + kyber_ct(1568) + wrapped_gek(40) = 1672 bytes
 */
#define IKP_MEMBER_ENTRY_SIZE 1672

/**
 * Packet header size
 * magic(4) + group_uuid(36) + version(4) + member_count(1) = 45 bytes
 */
#define IKP_HEADER_SIZE 45

/**
 * Signature block size (approximate)
 * type(1) + size(2) + Dilithium5_sig(~4627) = 4630 bytes
 */
#define IKP_SIGNATURE_SIZE 4630

/**
 * IKP Magic bytes: "GEK " (0x47454B20)
 */
#define IKP_MAGIC 0x47454B20

/* ============================================================================
 * INITIALIZATION
 * ============================================================================ */

/**
 * Initialize GEK subsystem
 *
 * Creates group_geks table if it doesn't exist.
 * Should be called on messenger initialization.
 *
 * @param backup_ctx Message backup context (provides database access)
 * @return 0 on success, -1 on error
 */
int gek_init(void *backup_ctx);

/**
 * Set KEM keys for GEK encryption/decryption
 *
 * Must be called after identity is loaded and before any GEK store/load operations.
 * The GEK subsystem will use these keys to encrypt GEKs before storing in database
 * and decrypt them when loading.
 *
 * Keys are copied internally - caller may free original buffers.
 *
 * @param kem_pubkey    1568-byte Kyber1024 public key (for encryption)
 * @param kem_privkey   3168-byte Kyber1024 private key (for decryption)
 * @return 0 on success, -1 on error
 */
int gek_set_kem_keys(const uint8_t *kem_pubkey, const uint8_t *kem_privkey);

/**
 * Clear KEM keys from GEK subsystem
 *
 * Should be called when identity is unloaded or on shutdown.
 * Securely wipes the stored keys from memory.
 */
void gek_clear_kem_keys(void);

/* ============================================================================
 * KEY GENERATION AND MANAGEMENT
 * ============================================================================ */

/**
 * Generate a new random GEK for a group
 *
 * @param group_uuid Group UUID (36-char UUID v4 string)
 * @param version GEK version number (0 for initial, increment on rotation)
 * @param gek_out Output buffer for generated GEK (32 bytes)
 * @return 0 on success, -1 on error
 */
int gek_generate(const char *group_uuid, uint32_t version, uint8_t gek_out[GEK_KEY_SIZE]);

/**
 * Store GEK in local database
 *
 * Stores the GEK in the group_geks table with expiration timestamp.
 * GEK is encrypted with Kyber1024 KEM + AES-256-GCM before storage.
 *
 * @param group_uuid Group UUID
 * @param version GEK version number
 * @param gek GEK to store (32 bytes)
 * @return 0 on success, -1 on error
 */
int gek_store(const char *group_uuid, uint32_t version, const uint8_t gek[GEK_KEY_SIZE]);

/**
 * Load GEK from local database by version
 *
 * @param group_uuid Group UUID
 * @param version GEK version to load
 * @param gek_out Output buffer for loaded GEK (32 bytes)
 * @return 0 on success, -1 on error (not found or expired)
 */
int gek_load(const char *group_uuid, uint32_t version, uint8_t gek_out[GEK_KEY_SIZE]);

/**
 * Load active (latest non-expired) GEK from local database
 *
 * Fetches the most recent GEK that hasn't expired yet.
 *
 * @param group_uuid Group UUID
 * @param gek_out Output buffer for loaded GEK (32 bytes)
 * @param version_out Output for loaded GEK version number (optional, can be NULL)
 * @return 0 on success, -1 on error (no active GEK found)
 */
int gek_load_active(const char *group_uuid, uint8_t gek_out[GEK_KEY_SIZE], uint32_t *version_out);

/**
 * Rotate GEK (increment version, generate new key)
 *
 * Generates a new GEK with version = current_version + 1.
 * Does NOT publish to DHT (caller must handle distribution).
 *
 * @param group_uuid Group UUID
 * @param new_version_out Output for new version number
 * @param new_gek_out Output buffer for new GEK (32 bytes)
 * @return 0 on success, -1 on error
 */
int gek_rotate(const char *group_uuid, uint32_t *new_version_out, uint8_t new_gek_out[GEK_KEY_SIZE]);

/**
 * Get current GEK version from local database
 *
 * Returns the highest GEK version number stored locally for a group.
 *
 * @param group_uuid Group UUID
 * @param version_out Output for current version (0 if no GEK exists)
 * @return 0 on success, -1 on error
 */
int gek_get_current_version(const char *group_uuid, uint32_t *version_out);

/**
 * Delete expired GEKs from database
 *
 * Cleanup function to remove old GEKs that have expired.
 * Should be called periodically (e.g., on startup, daily background task).
 *
 * @return Number of deleted entries, -1 on error
 */
int gek_cleanup_expired(void);

/* ============================================================================
 * ENCRYPTION / DECRYPTION (for at-rest storage)
 * ============================================================================ */

/**
 * Encrypt GEK with Kyber1024 KEM + AES-256-GCM
 *
 * @param gek           32-byte GEK to encrypt
 * @param kem_pubkey    1568-byte Kyber1024 public key
 * @param encrypted_out Output buffer (must be GEK_ENC_TOTAL_SIZE = 1628 bytes)
 * @return              0 on success, -1 on error
 */
int gek_encrypt(
    const uint8_t gek[32],
    const uint8_t kem_pubkey[1568],
    uint8_t encrypted_out[GEK_ENC_TOTAL_SIZE]
);

/**
 * Decrypt GEK with Kyber1024 KEM + AES-256-GCM
 *
 * @param encrypted     1628-byte encrypted blob from database
 * @param encrypted_len Size of encrypted blob (must be GEK_ENC_TOTAL_SIZE)
 * @param kem_privkey   3168-byte Kyber1024 private key
 * @param gek_out       Output buffer for decrypted GEK (32 bytes)
 * @return              0 on success, -1 on error
 */
int gek_decrypt(
    const uint8_t *encrypted,
    size_t encrypted_len,
    const uint8_t kem_privkey[3168],
    uint8_t gek_out[32]
);

/* ============================================================================
 * MEMBER CHANGE HANDLERS
 * ============================================================================ */

/**
 * Rotate GEK when a member is added to the group
 *
 * Automatically called by groups_add_member().
 * Generates new GEK, builds Initial Key Packet, publishes to DHT,
 * and notifies all members.
 *
 * @param dht_ctx DHT context for publishing
 * @param group_uuid Group UUID
 * @param owner_identity Owner's identity (for signing)
 * @return 0 on success, -1 on error
 */
int gek_rotate_on_member_add(void *dht_ctx, const char *group_uuid, const char *owner_identity);

/**
 * Rotate GEK when a member is removed from the group
 *
 * Automatically called by groups_remove_member().
 * Generates new GEK, builds Initial Key Packet, publishes to DHT,
 * and notifies all members.
 *
 * @param dht_ctx DHT context for publishing
 * @param group_uuid Group UUID
 * @param owner_identity Owner's identity (for signing)
 * @return 0 on success, -1 on error
 */
int gek_rotate_on_member_remove(void *dht_ctx, const char *group_uuid, const char *owner_identity);

/* ============================================================================
 * IKP (Initial Key Packet) FUNCTIONS
 * ============================================================================ */

/**
 * Build Initial Key Packet for GEK distribution
 *
 * Creates a packet containing the GEK wrapped with Kyber1024 for each member.
 * The packet is signed with the owner's Dilithium5 key for authentication.
 *
 * Packet format:
 *   [magic(4) || group_uuid(36) || version(4) || member_count(1)]
 *   [For each member: fingerprint(64) || kyber_ct(1568) || wrapped_gek(40)]
 *   [signature_type(1) || sig_size(2) || signature(~4627)]
 *
 * @param group_uuid Group UUID (36-char UUID v4 string)
 * @param version GEK version number
 * @param gek GEK to distribute (32 bytes)
 * @param members Array of member entries (fingerprint + kyber pubkey)
 * @param member_count Number of members
 * @param owner_dilithium_privkey Owner's Dilithium5 private key (4896 bytes) for signing
 * @param packet_out Output buffer for packet (allocated by function, caller must free)
 * @param packet_size_out Output for packet size
 * @return 0 on success, -1 on error
 */
int ikp_build(const char *group_uuid,
              uint32_t version,
              const uint8_t gek[GEK_KEY_SIZE],
              const gek_member_entry_t *members,
              size_t member_count,
              const uint8_t *owner_dilithium_privkey,
              uint8_t **packet_out,
              size_t *packet_size_out);

/**
 * Extract GEK from received Initial Key Packet
 *
 * Finds the entry matching my_fingerprint, performs Kyber1024 decapsulation
 * to get KEK, then unwraps the GEK.
 *
 * @param packet Received packet buffer
 * @param packet_size Packet size in bytes
 * @param my_fingerprint_bin My fingerprint (64 bytes binary)
 * @param my_kyber_privkey My Kyber1024 private key (3168 bytes)
 * @param gek_out Output buffer for extracted GEK (32 bytes)
 * @param version_out Output for GEK version (optional, can be NULL)
 * @return 0 on success, -1 on error (entry not found or decryption failed)
 */
int ikp_extract(const uint8_t *packet,
                size_t packet_size,
                const uint8_t *my_fingerprint_bin,
                const uint8_t *my_kyber_privkey,
                uint8_t gek_out[GEK_KEY_SIZE],
                uint32_t *version_out);

/**
 * Verify Initial Key Packet signature
 *
 * Verifies the Dilithium5 signature on the packet using the owner's public key.
 *
 * @param packet Packet buffer
 * @param packet_size Packet size in bytes
 * @param owner_dilithium_pubkey Owner's Dilithium5 public key (2592 bytes)
 * @return 0 on success (signature valid), -1 on error or invalid signature
 */
int ikp_verify(const uint8_t *packet,
               size_t packet_size,
               const uint8_t *owner_dilithium_pubkey);

/**
 * Calculate expected IKP size for a given member count
 *
 * Useful for pre-allocating buffers or validating packet sizes.
 *
 * @param member_count Number of group members
 * @return Expected packet size in bytes
 */
size_t ikp_calculate_size(size_t member_count);

/**
 * Get GEK version from IKP header
 *
 * Parses the packet header to extract the GEK version without full extraction.
 *
 * @param packet Packet buffer
 * @param packet_size Packet size in bytes
 * @param version_out Output for GEK version
 * @return 0 on success, -1 on error
 */
int ikp_get_version(const uint8_t *packet, size_t packet_size, uint32_t *version_out);

/**
 * Get member count from IKP header
 *
 * Parses the packet header to extract the member count without full extraction.
 *
 * @param packet Packet buffer
 * @param packet_size Packet size in bytes
 * @param count_out Output for member count
 * @return 0 on success, -1 on error
 */
int ikp_get_member_count(const uint8_t *packet, size_t packet_size, uint8_t *count_out);

/* ============================================================================
 * DHT SYNC (Multi-Device Sync via DHT)
 * ============================================================================ */

/**
 * Sync all local GEKs to DHT
 *
 * Exports all non-expired GEKs from local database and publishes to DHT.
 * Uses self-encryption (Kyber1024 + Dilithium5) for security.
 * Other devices can sync from DHT to get the same GEKs.
 *
 * @param dht_ctx DHT context
 * @param identity Owner's identity fingerprint (128-char hex)
 * @param kyber_pubkey Owner's Kyber1024 public key (1568 bytes)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes)
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes)
 * @param dilithium_privkey Owner's Dilithium5 private key (4896 bytes)
 * @return 0 on success, -1 on error
 */
int gek_sync_to_dht(
    void *dht_ctx,
    const char *identity,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey
);

/**
 * Sync GEKs from DHT to local database
 *
 * Fetches GEKs from DHT and imports missing entries to local database.
 * Only imports GEKs that don't already exist locally.
 *
 * @param dht_ctx DHT context
 * @param identity Owner's identity fingerprint (128-char hex)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes)
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes)
 * @param imported_out Output for number of imported entries (optional, can be NULL)
 * @return 0 on success, -1 on error, -2 if not found in DHT
 */
int gek_sync_from_dht(
    void *dht_ctx,
    const char *identity,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    int *imported_out
);

/**
 * Auto-sync GEKs (sync from DHT, then sync to DHT if newer locally)
 *
 * Convenience function that:
 * 1. Checks DHT timestamp
 * 2. If DHT is newer, syncs from DHT
 * 3. If local is newer, syncs to DHT
 * 4. If neither exists, does nothing
 *
 * @param dht_ctx DHT context
 * @param identity Owner's identity fingerprint
 * @param kyber_pubkey Owner's Kyber1024 public key
 * @param kyber_privkey Owner's Kyber1024 private key
 * @param dilithium_pubkey Owner's Dilithium5 public key
 * @param dilithium_privkey Owner's Dilithium5 private key
 * @return 0 on success, -1 on error
 */
int gek_auto_sync(
    void *dht_ctx,
    const char *identity,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey
);

/**
 * High-level GEK auto-sync using messenger context
 *
 * Loads keys from disk internally and calls gek_auto_sync().
 * Use this from dna_engine.c or other places that have messenger context.
 *
 * @param ctx Opaque messenger context pointer (cast from messenger_context_t*)
 * @return 0 on success, -1 on error
 */
int messenger_gek_auto_sync(void *ctx);

/* ============================================================================
 * BACKUP / RESTORE (Legacy - for transition period)
 * ============================================================================ */

/**
 * GEK export entry for backup
 * Contains encrypted GEK data (safe to store in DHT backup)
 */
typedef struct {
    char group_uuid[37];              // UUID v4 (36 + null)
    uint32_t gek_version;             // GEK version number
    uint8_t encrypted_gek[GEK_ENC_TOTAL_SIZE];  // Encrypted GEK (1628 bytes)
    uint64_t created_at;              // Creation timestamp
    uint64_t expires_at;              // Expiration timestamp
} gek_export_entry_t;

/**
 * Export all GEKs for backup
 *
 * Retrieves all GEK entries from the database in encrypted form.
 * The GEKs remain encrypted (safe to include in DHT backup).
 *
 * @param entries_out Output array (allocated by function, caller must free)
 * @param count_out Output for number of entries
 * @return 0 on success, -1 on error
 */
int gek_export_all(gek_export_entry_t **entries_out, size_t *count_out);

/**
 * Import GEKs from backup
 *
 * Imports encrypted GEK entries into the database.
 * Skips entries that already exist (by group_uuid + version).
 *
 * @param entries Array of GEK entries to import
 * @param count Number of entries
 * @param imported_out Output for number of successfully imported entries (can be NULL)
 * @return 0 on success, -1 on error
 */
int gek_import_all(const gek_export_entry_t *entries, size_t count, int *imported_out);

/**
 * Free exported GEK entries array
 *
 * @param entries Array to free
 * @param count Number of entries
 */
void gek_free_export_entries(gek_export_entry_t *entries, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* GEK_H */
