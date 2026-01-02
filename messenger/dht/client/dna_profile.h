/**
 * @file dna_profile.h
 * @brief DNA profile data structures and management functions
 *
 * This module provides data structures and functions for managing DNA profiles
 * in the DHT-based name system. Profiles contain wallet addresses (Cellframe +
 * external chains), social profiles, bio, and other user metadata.
 *
 * @author DNA Messenger Team
 * @date 2025-11-05
 */

#ifndef DNA_PROFILE_H
#define DNA_PROFILE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Unified wallet addresses structure
 *
 * Contains addresses for all supported networks (Cellframe + external chains).
 * All fields are optional (empty string if not set).
 */
typedef struct {
    // Cellframe networks
    char backbone[120];         /**< Backbone network address */
    char alvin[120];            /**< Alvin testnet address (not active) */

    // External blockchains
    char eth[128];              /**< Ethereum address (also works for BSC, Polygon, etc.) */
    char sol[128];              /**< Solana address */
    char trx[128];              /**< TRON address (T...) */
} dna_wallets_t;

/**
 * @brief Social profiles structure
 *
 * Contains social media usernames/handles. All fields are optional.
 */
typedef struct {
    char telegram[128];         /**< Telegram username */
    char x[128];                /**< X (Twitter) handle */
    char github[128];           /**< GitHub username */
    char facebook[128];         /**< Facebook username */
    char instagram[128];        /**< Instagram handle */
    char linkedin[128];         /**< LinkedIn profile */
    char google[128];           /**< Google email */
} dna_socials_t;

/**
 * @brief Complete unified identity structure
 *
 * This structure represents a complete DNA identity in the DHT. It includes
 * messenger keys, optional DNA name registration, wallet addresses, social
 * profiles, and a Dilithium5 signature over the entire structure.
 *
 * Size: ~25-30 KB when JSON serialized
 */
typedef struct {
    // ===== MESSENGER KEYS =====
    char fingerprint[129];               /**< SHA3-512 hex (128 chars + null) */
    uint8_t dilithium_pubkey[2592];      /**< Dilithium5 public key (Category 5) */
    uint8_t kyber_pubkey[1568];          /**< Kyber1024 public key (Category 5) */

    // ===== DNA NAME REGISTRATION =====
    bool has_registered_name;            /**< true if name registered */
    char registered_name[256];           /**< DNA name (e.g., "nocdem") */
    uint64_t name_registered_at;         /**< Registration timestamp (Unix epoch) */
    uint64_t name_expires_at;            /**< Expiration timestamp (+365 days) */
    uint32_t name_version;               /**< Version (increment on renewal) */

    // ===== PROFILE DATA =====
    char display_name[128];              /**< Display name (optional, defaults to name or fingerprint) */
    char bio[512];                       /**< User bio */
    char avatar_hash[128];               /**< SHA3-512 hash of avatar (for quick comparisons) */
    char profile_picture_ipfs[64];       /**< IPFS CID for avatar (legacy/future) */
    char avatar_base64[20484];           /**< Base64-encoded avatar (64x64 PNG/JPEG, ~20KB max + padding) */
    char location[128];                  /**< Geographic location (optional) */
    char website[256];                   /**< Personal website URL (optional) */

    dna_wallets_t wallets;               /**< Wallet addresses (unified) */
    dna_socials_t socials;               /**< Social profiles */

    // ===== METADATA =====
    uint64_t created_at;                 /**< Profile creation timestamp */
    uint64_t updated_at;                 /**< Last update timestamp */
    uint64_t timestamp;                  /**< Entry timestamp */
    uint32_t version;                    /**< Entry version */

    // ===== SIGNATURE =====
    uint8_t signature[4627];             /**< Dilithium5 signature over entire structure */

} dna_unified_identity_t;

/**
 * @brief Create new unified identity structure
 *
 * Allocates and initializes a new unified identity with all fields
 * set to zero/empty.
 *
 * @return Pointer to new identity, or NULL on allocation failure
 */
dna_unified_identity_t* dna_identity_create(void);

/**
 * @brief Free unified identity structure
 *
 * @param identity Identity to free (can be NULL)
 */
void dna_identity_free(dna_unified_identity_t *identity);

/**
 * @brief Serialize unified identity to JSON string
 *
 * Converts complete identity structure to JSON. Caller must free returned string.
 *
 * @param identity Identity to serialize
 * @return JSON string, or NULL on error
 */
char* dna_identity_to_json(const dna_unified_identity_t *identity);

/**
 * @brief Serialize unified identity to JSON string WITHOUT signature
 *
 * Used for signing/verification. The signature is computed over this JSON string.
 * This ensures forward compatibility when struct fields change.
 * Caller must free returned string.
 *
 * @param identity Identity to serialize
 * @return JSON string (without signature field), or NULL on error
 */
char* dna_identity_to_json_unsigned(const dna_unified_identity_t *identity);

/**
 * @brief Parse unified identity from JSON string
 *
 * @param json JSON string to parse
 * @param identity_out Output parameter for parsed identity (allocated)
 * @return 0 on success, -1 on error
 */
int dna_identity_from_json(const char *json, dna_unified_identity_t **identity_out);

/**
 * @brief Validate wallet address format
 *
 * Validates address format based on network type. Supports:
 * - Cellframe networks (base58)
 * - Bitcoin (legacy, SegWit)
 * - Ethereum (0x + 40 hex)
 * - Solana (base58)
 * - TON (EQ.../UQ... base64 format)
 *
 * @param address Address to validate
 * @param network Network identifier (e.g., "backbone", "eth", "sol")
 * @return true if valid, false otherwise
 */
bool dna_validate_wallet_address(const char *address, const char *network);

/**
 * @brief Validate IPFS CID format
 *
 * Checks if string is a valid IPFS CIDv1.
 *
 * @param cid IPFS CID string to validate
 * @return true if valid, false otherwise
 */
bool dna_validate_ipfs_cid(const char *cid);

/**
 * @brief Validate DNA name format
 *
 * Checks if name meets requirements:
 * - Length: 3-36 characters
 * - Characters: alphanumeric + . _ -
 * - Not disallowed (admin, root, system, etc.)
 *
 * @param name DNA name to validate
 * @return true if valid, false otherwise
 */
bool dna_validate_name(const char *name);

/**
 * @brief Check if network is a Cellframe network
 *
 * @param network Network identifier
 * @return true if Cellframe network, false otherwise
 */
bool dna_network_is_cellframe(const char *network);

/**
 * @brief Check if network is an external blockchain
 *
 * @param network Network identifier
 * @return true if external (BTC, ETH, SOL, etc.), false otherwise
 */
bool dna_network_is_external(const char *network);

/**
 * @brief Normalize network name to lowercase
 *
 * Converts network name to lowercase (e.g., "Backbone" → "backbone").
 * Modifies string in place.
 *
 * @param network Network name to normalize (modified in place)
 */
void dna_network_normalize(char *network);

/**
 * @brief Get wallet address for specific network from identity
 *
 * @param identity Identity structure
 * @param network Network identifier (e.g., "backbone", "eth")
 * @return Pointer to address string within identity, or NULL if not set
 */
const char* dna_identity_get_wallet(const dna_unified_identity_t *identity,
                                     const char *network);

/**
 * @brief Set wallet address for specific network in identity
 *
 * @param identity Identity structure (modified)
 * @param network Network identifier
 * @param address Address string to set
 * @return 0 on success, -1 on error (invalid network or address too long)
 */
int dna_identity_set_wallet(dna_unified_identity_t *identity,
                             const char *network,
                             const char *address);

#ifdef __cplusplus
}
#endif

#endif /* DNA_PROFILE_H */
