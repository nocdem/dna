/**
 * @file gek.h
 * @brief Group Encryption Key (GEK) Manager
 *
 * Manages AES-256 symmetric keys for group messaging encryption.
 * Provides generation, storage, rotation, and retrieval of GEKs.
 *
 * Part of DNA Connect - GEK System
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
 * GEK format version for HKDF ratchet (v2)
 * v1 = pure random GEK generation
 * v2 = HKDF-SHA3-256 ratchet on member removal
 */
#define GEK_FORMAT_VERSION 2

/**
 * HKDF ratchet info string
 */
#define GEK_HKDF_INFO "gek-ratchet-v2"
#define GEK_HKDF_INFO_LEN 14

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
 *
 * KEM Faz 1 (R8): mlkem_pubkey is nullable — the caller populates it from
 * the member's cache/DHT record when present. ikp_build() emits IKP v3 (with
 * a per-member alg byte) ONLY when EVERY member entry has a non-NULL
 * mlkem_pubkey; otherwise it falls back to the unchanged v2 packet using
 * kyber_pubkey for all members (design §5.4, all-or-nothing).
 */
typedef struct {
    uint8_t fingerprint[64];        // SHA3-512 fingerprint (binary)
    const uint8_t *kyber_pubkey;    // Kyber1024 round-3 public key (1568 bytes, legacy)
    const uint8_t *mlkem_pubkey;    // ML-KEM-1024 public key (1568 bytes), or NULL
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
 * Packet header size (CORE-04 v2: +32 bytes dht_salt)
 * magic(4) + group_uuid(36) + version(4) + member_count(1) + dht_salt(32) = 77 bytes
 */
#define IKP_HEADER_SIZE 77

/**
 * Size of the per-group DHT privacy salt in the IKP header
 */
#define IKP_DHT_SALT_SIZE 32

/**
 * Signature block size (approximate)
 * type(1) + size(2) + Dilithium5_sig(~4627) = 4630 bytes
 */
#define IKP_SIGNATURE_SIZE 4630

/**
 * IKP Magic bytes: "GEK2" (0x47454B32)
 *
 * CORE-04 (Phase 6 plan 04): IKP format v2 adds a 32-byte dht_salt field
 * to the header for group outbox DHT key privacy. Hard cutover: old "GEK "
 * magic is no longer accepted. Pre-existing groups must redistribute via
 * GEK rotation before members can receive messages under the new salted
 * key layout.
 */
#define IKP_MAGIC 0x47454B32

/**
 * IKP v3 magic bytes: "GEK3" (0x47454B33) — KEM Faz 1, R8.
 *
 * Same header shape as v2 (magic || group_uuid(36) || version(4) ||
 * member_count(1) || dht_salt(32)); each member entry gains a 1-byte alg
 * field: fingerprint(64) || alg(1) || ct(1568) || wrapped_gek(40). Emitted
 * ONLY when every member has a published ML-KEM key (ikp_build's
 * all-or-nothing gate); readers accept BOTH IKP_MAGIC (v2, alg implicitly 2)
 * and IKP_MAGIC_V3.
 */
#define IKP_MAGIC_V3 0x47454B33

/**
 * Per-member entry size in a v3 Initial Key Packet
 * fingerprint(64) + alg(1) + ct(1568) + wrapped_gek(40) = 1673 bytes
 */
#define IKP_MEMBER_ENTRY_SIZE_V3 1673

/* Per-member alg byte values (v3 only; v2 members are implicitly alg 2). */
#define IKP_ALG_KYBER_R3   2   /* round-3 Kyber1024 (legacy) */
#define IKP_ALG_MLKEM1024  3   /* ML-KEM-1024 (FIPS 203) */

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
 * Cleanup GEK subsystem
 *
 * Nulls the borrowed database pointer. Does NOT close the database
 * (that's handled by group_database_close).
 * Must be called during messenger_free() to prevent stale pointer on reinit.
 */
void gek_cleanup(void);

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
 * Set ML-KEM-1024 keys for GEK encryption/decryption (KEM Faz 1, R7/R8).
 *
 * Same contract as gek_set_kem_keys(), for the FIPS-203 key pair
 * (identity.mlkem). Keys are copied internally - caller may free original
 * buffers. Independent of gek_set_kem_keys()/gek_clear_kem_keys() — an
 * identity that has not migrated yet simply never calls this, and every
 * gek_*_alg() call with alg=2 (round-3) is unaffected.
 *
 * @param mlkem_pubkey    1568-byte ML-KEM-1024 public key (for encryption)
 * @param mlkem_privkey   3168-byte ML-KEM-1024 private key (for decryption)
 * @return 0 on success, -1 on error
 */
int gek_set_mlkem_keys(const uint8_t *mlkem_pubkey, const uint8_t *mlkem_privkey);

/**
 * Copy out the session ML-KEM-1024 keys previously set by
 * gek_set_mlkem_keys() (D17, M1 delta 1b-2 — D12-approved branch).
 *
 * Used by gek_sync_to_dht()/gek_sync_from_dht() to forward the SAME
 * session-loaded key to dht_geks_publish()/dht_geks_fetch(), instead of
 * those DHT-layer functions doing their own by-path load (which bypassed
 * the session password on a protected identity — D12).
 *
 * @param pub   Output 1568-byte ML-KEM-1024 public key buffer
 * @param priv  Output 3168-byte ML-KEM-1024 private key buffer
 * @return 0 on success (both copied), -1 if NULL args or not yet set
 *         (pre-migration or K2 identity — outputs left untouched)
 */
int gek_get_mlkem_keys(uint8_t pub[1568], uint8_t priv[3168]);

/**
 * Clear KEM keys from GEK subsystem
 *
 * Should be called when identity is unloaded or on shutdown.
 * Securely wipes the stored keys from memory. Clears BOTH the legacy
 * round-3 keys AND the ML-KEM-1024 keys (KEM Faz 1, R8).
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

/**
 * Encrypt GEK with the given KEM algorithm + AES-256-GCM (KEM Faz 1, R8).
 *
 * Same wire layout as gek_encrypt() (kem_ciphertext(1568) || nonce(12) ||
 * tag(16) || encrypted_gek(32) = GEK_ENC_TOTAL_SIZE) — ML-KEM-1024 and
 * round-3 Kyber1024 ciphertext/pubkey/privkey sizes are byte-identical, so
 * the blob format does not change, only which KEM primitive is called.
 *
 * @param alg           IKP_ALG_KYBER_R3 (2) or IKP_ALG_MLKEM1024 (3)
 * @param gek           32-byte GEK to encrypt
 * @param pubkey        1568-byte public key of the given alg
 * @param encrypted_out Output buffer (must be GEK_ENC_TOTAL_SIZE bytes)
 * @return              0 on success, -1 on error (including unknown alg)
 */
int gek_encrypt_alg(
    uint8_t alg,
    const uint8_t gek[32],
    const uint8_t pubkey[1568],
    uint8_t encrypted_out[GEK_ENC_TOTAL_SIZE]
);

/**
 * Decrypt GEK with the given KEM algorithm + AES-256-GCM (KEM Faz 1, R8).
 * See gek_encrypt_alg() for the wire layout (unchanged from gek_decrypt()).
 *
 * @param alg           IKP_ALG_KYBER_R3 (2) or IKP_ALG_MLKEM1024 (3)
 * @param encrypted     GEK_ENC_TOTAL_SIZE-byte encrypted blob
 * @param encrypted_len Size of encrypted blob (must be GEK_ENC_TOTAL_SIZE)
 * @param privkey       Private key of the given alg (3168 bytes)
 * @param gek_out       Output buffer for decrypted GEK (32 bytes)
 * @return              0 on success, -1 on error (including unknown alg)
 */
int gek_decrypt_alg(
    uint8_t alg,
    const uint8_t *encrypted,
    size_t encrypted_len,
    const uint8_t privkey[3168],
    uint8_t gek_out[32]
);

/* ============================================================================
 * HKDF RATCHET (GEK v2)
 * ============================================================================ */

/**
 * HKDF-SHA3-256 Extract-then-Expand
 *
 * Derives a new 32-byte key using HKDF with SHA3-256 as the underlying hash.
 * Used for GEK ratchet on member removal to break the derivation chain.
 *
 * Extract: PRK = HMAC-SHA3-256(salt, IKM)
 * Expand:  OKM = HMAC-SHA3-256(PRK, info || 0x01)
 *
 * @param salt      Salt value (random entropy, 32 bytes)
 * @param salt_len  Salt length
 * @param ikm       Input keying material (old GEK, 32 bytes)
 * @param ikm_len   IKM length
 * @param info      Context/application-specific info string
 * @param info_len  Info length
 * @param okm       Output keying material (new GEK, 32 bytes)
 * @param okm_len   Desired output length (must be <= 32)
 * @return          0 on success, -1 on error
 */
/* HKDF-SHA3-256 moved to shared/crypto/hash/hkdf_sha3.h — use hkdf_sha3_256() */

/**
 * Generate a ratcheted GEK for member removal
 *
 * Uses HKDF-SHA3-256 to derive a new GEK from the old one plus fresh entropy.
 * The removed member cannot derive the new GEK without the random entropy.
 *
 * @param old_gek       Previous GEK (32 bytes)
 * @param new_gek_out   Output buffer for new GEK (32 bytes)
 * @return              0 on success, -1 on error
 */
int gek_generate_ratcheted(const uint8_t old_gek[GEK_KEY_SIZE],
                           uint8_t new_gek_out[GEK_KEY_SIZE]);

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
 * @param ctx messenger context (for session_password key loading)
 * @param group_uuid Group UUID
 * @param owner_identity Owner's identity (for signing)
 * @return 0 on success, -1 on error
 */
int gek_rotate_on_member_add(void *ctx, const char *group_uuid, const char *owner_identity);

/**
 * Rotate GEK when a member is removed from the group
 *
 * Automatically called by groups_remove_member().
 * Generates new GEK, builds Initial Key Packet, publishes to DHT,
 * and notifies all members.
 *
 * @param ctx messenger context (for session_password key loading)
 * @param group_uuid Group UUID
 * @param owner_identity Owner's identity (for signing)
 * @return 0 on success, -1 on error
 */
int gek_rotate_on_member_remove(void *ctx, const char *group_uuid, const char *owner_identity);

/* ============================================================================
 * IKP (Initial Key Packet) FUNCTIONS
 * ============================================================================ */

/**
 * Build Initial Key Packet for GEK distribution (CORE-04 v2)
 *
 * Creates a packet containing the GEK wrapped with Kyber1024 for each member.
 * The packet is signed with the owner's Dilithium5 key for authentication.
 *
 * Packet format (v2):
 *   [magic(4) || group_uuid(36) || version(4) || member_count(1) || dht_salt(32)]
 *   [For each member: fingerprint(64) || kyber_ct(1568) || wrapped_gek(40)]
 *   [signature_type(1) || sig_size(2) || signature(~4627)]
 *
 * @param group_uuid Group UUID (36-char UUID v4 string)
 * @param version GEK version number
 * @param gek GEK to distribute (32 bytes)
 * @param dht_salt Per-group 32-byte DHT privacy salt (CORE-04, MUST be non-NULL)
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
              const uint8_t dht_salt[IKP_DHT_SALT_SIZE],
              const gek_member_entry_t *members,
              size_t member_count,
              const uint8_t *owner_dilithium_privkey,
              uint8_t **packet_out,
              size_t *packet_size_out);

/**
 * Extract GEK from received Initial Key Packet (CORE-04 v2)
 *
 * Finds the entry matching my_fingerprint, performs Kyber1024 decapsulation
 * to get KEK, then unwraps the GEK. Also returns the per-group DHT privacy
 * salt from the v2 header so the receiver can persist it for outbox reads.
 *
 * @param packet Received packet buffer
 * @param packet_size Packet size in bytes
 * @param my_fingerprint_bin My fingerprint (64 bytes binary)
 * @param my_kyber_privkey My Kyber1024 private key (3168 bytes)
 * @param gek_out Output buffer for extracted GEK (32 bytes)
 * @param version_out Output for GEK version (optional, can be NULL)
 * @param dht_salt_out Output buffer for DHT privacy salt (32 bytes, optional, can be NULL)
 * @return 0 on success, -1 on error (entry not found or decryption failed)
 */
int ikp_extract(const uint8_t *packet,
                size_t packet_size,
                const uint8_t *my_fingerprint_bin,
                const uint8_t *my_kyber_privkey,
                uint8_t gek_out[GEK_KEY_SIZE],
                uint32_t *version_out,
                uint8_t dht_salt_out[IKP_DHT_SALT_SIZE]);

/**
 * Extract GEK from a received Initial Key Packet, v2 OR v3 (KEM Faz 1, R8).
 *
 * Accepts both IKP_MAGIC (v2 — my_kyber_privkey only) and IKP_MAGIC_V3 (v3 —
 * my entry's alg byte selects which of my_kyber_privkey / my_mlkem_privkey
 * is used). ikp_extract() is a thin wrapper: ikp_extract_alg(..., NULL) —
 * so a v3 packet whose entry for me is alg=2 still extracts fine through the
 * old entry point; only an alg=3 entry needs my_mlkem_privkey.
 *
 * @param my_mlkem_privkey  My ML-KEM-1024 private key (3168 bytes), or NULL
 *        if not available (identity has not migrated — an alg=3 entry for
 *        me then fails with -1, exactly like a missing my_kyber_privkey
 *        would for an alg=2 entry).
 */
int ikp_extract_alg(const uint8_t *packet,
                    size_t packet_size,
                    const uint8_t *my_fingerprint_bin,
                    const uint8_t *my_kyber_privkey,
                    const uint8_t *my_mlkem_privkey,
                    uint8_t gek_out[GEK_KEY_SIZE],
                    uint32_t *version_out,
                    uint8_t dht_salt_out[IKP_DHT_SALT_SIZE]);

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
 * @param identity Owner's identity fingerprint (128-char hex)
 * @param kyber_pubkey Owner's Kyber1024 public key (1568 bytes)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes)
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes)
 * @param dilithium_privkey Owner's Dilithium5 private key (4896 bytes)
 * @return 0 on success, -1 on error
 */
int gek_sync_to_dht(
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
 * @param identity Owner's identity fingerprint (128-char hex)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes)
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes)
 * @param imported_out Output for number of imported entries (optional, can be NULL)
 * @return 0 on success, -1 on error, -2 if not found in DHT
 */
int gek_sync_from_dht(
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
 * @param identity Owner's identity fingerprint
 * @param kyber_pubkey Owner's Kyber1024 public key
 * @param kyber_privkey Owner's Kyber1024 private key
 * @param dilithium_pubkey Owner's Dilithium5 public key
 * @param dilithium_privkey Owner's Dilithium5 private key
 * @return 0 on success, -1 on error
 */
int gek_auto_sync(
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
