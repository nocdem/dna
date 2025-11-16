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
    // Cellframe networks (7 total)
    char backbone[120];         /**< Backbone network address */
    char kelvpn[120];           /**< KelVPN network address */
    char riemann[120];          /**< Riemann network address */
    char raiden[120];           /**< Raiden network address */
    char mileena[120];          /**< Mileena network address */
    char subzero[120];          /**< Subzero network address */
    char cpunk_testnet[120];    /**< CPUNK testnet address */

    // External blockchains (5 total)
    char btc[128];              /**< Bitcoin address */
    char eth[128];              /**< Ethereum address */
    char sol[128];              /**< Solana address */
    char qevm[128];             /**< QEVM address */
    char bnb[128];              /**< BNB Chain address */

    // Reserved for future expansion
    // char alvin[128];         /**< Alvin network (not implemented) */
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
 * @brief Profile data helper structure
 *
 * Used for profile updates. Contains all user-editable fields.
 */
typedef struct {
    dna_wallets_t wallets;      /**< Wallet addresses */
    dna_socials_t socials;      /**< Social profiles */
    char bio[512];              /**< User bio (max 512 chars) */
    char profile_picture_ipfs[64]; /**< IPFS CID for profile picture */
    char avatar_base64[20480];  /**< Base64-encoded avatar (64x64 PNG, ~20KB max) */
} dna_profile_data_t;

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
    char registration_tx_hash[67];       /**< Blockchain tx hash (66 hex + null) */
    char registration_network[32];       /**< Network (e.g., "Backbone") */
    uint32_t name_version;               /**< Version (increment on renewal) */

    // ===== PROFILE DATA =====
    char display_name[128];              /**< Display name (optional, defaults to name or fingerprint) */
    char bio[512];                       /**< User bio */
    char avatar_hash[128];               /**< SHA3-512 hash of avatar (for quick comparisons) */
    char profile_picture_ipfs[64];       /**< IPFS CID for avatar (legacy/future) */
    char avatar_base64[20480];           /**< Base64-encoded avatar (64x64 PNG/JPEG, ~20KB max) */
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
 * @brief Create new profile data structure
 *
 * Allocates and initializes a new profile data structure with all fields
 * set to zero/empty.
 *
 * @return Pointer to new profile data, or NULL on allocation failure
 */
dna_profile_data_t* dna_profile_create(void);

/**
 * @brief Free profile data structure
 *
 * @param profile Profile data to free (can be NULL)
 */
void dna_profile_free(dna_profile_data_t *profile);

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
 * @brief Serialize profile data to JSON string
 *
 * Converts profile data structure to JSON representation. Caller must
 * free returned string.
 *
 * @param profile Profile data to serialize
 * @return JSON string, or NULL on error
 */
char* dna_profile_to_json(const dna_profile_data_t *profile);

/**
 * @brief Parse profile data from JSON string
 *
 * @param json JSON string to parse
 * @param profile_out Output parameter for parsed profile (allocated)
 * @return 0 on success, -1 on error
 */
int dna_profile_from_json(const char *json, dna_profile_data_t **profile_out);

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
 * @brief Parse unified identity from JSON string
 *
 * @param json JSON string to parse
 * @param identity_out Output parameter for parsed identity (allocated)
 * @return 0 on success, -1 on error
 */
int dna_identity_from_json(const char *json, dna_unified_identity_t **identity_out);

/**
 * @brief Validate profile data
 *
 * Checks that all fields are valid:
 * - Bio length <= 512 chars
 * - Wallet addresses have correct format
 * - IPFS CID has correct format (if set)
 *
 * @param profile Profile data to validate
 * @return 0 if valid, negative error code on validation failure
 */
int dna_profile_validate(const dna_profile_data_t *profile);

/**
 * @brief Validate wallet address format
 *
 * Validates address format based on network type. Supports:
 * - Cellframe networks (base58)
 * - Bitcoin (legacy, SegWit)
 * - Ethereum (0x + 40 hex)
 * - Solana (base58)
 * - BNB/QEVM (Ethereum format)
 *
 * @param address Address to validate
 * @param network Network identifier (e.g., "backbone", "eth", "btc")
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

/**
 * @brief Display-only profile data (extracted from dna_unified_identity_t)
 *
 * Used for UI rendering without exposing full identity.
 * Contains only the fields needed for profile display.
 */
typedef struct {
    char fingerprint[129];          /**< SHA3-512 fingerprint */
    char display_name[128];         /**< Display name */
    char bio[512];                  /**< Biography */
    char avatar_hash[128];          /**< Avatar hash (SHA3-512) */
    char location[128];             /**< Location */
    char website[256];              /**< Website URL */

    // Selected social links
    char telegram[128];             /**< Telegram username */
    char x[128];                    /**< X (Twitter) handle */
    char github[128];               /**< GitHub username */

    // Selected wallet addresses (for tipping)
    char backbone[120];             /**< Backbone address */
    char btc[128];                  /**< Bitcoin address */
    char eth[128];                  /**< Ethereum address */

    uint64_t updated_at;            /**< Last update timestamp */
} dna_display_profile_t;

/**
 * @brief Extract display profile from unified identity
 *
 * Converts a full identity structure into a display-only profile
 * suitable for UI rendering. Only includes publicly visible fields.
 *
 * @param identity Full identity structure
 * @param display_out Output display profile (caller provides buffer)
 */
void dna_identity_to_display_profile(
    const dna_unified_identity_t *identity,
    dna_display_profile_t *display_out
);

#ifdef __cplusplus
}
#endif

#endif /* DNA_PROFILE_H */
