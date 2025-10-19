/*
 * wallet.h - Cellframe Wallet Reader for DNA Messenger
 *
 * Reads Cellframe wallet files from standard locations:
 * - Linux: /opt/cellframe-node/var/lib/wallet/
 * - Windows: C:\Users\Public\Documents\cellframe-node\var\lib\wallet\
 *
 * Wallet files are binary format containing:
 * - Wallet name
 * - Cryptographic keys (Dilithium, etc.)
 * - Network addresses
 */

#ifndef DNA_WALLET_H
#define DNA_WALLET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CONSTANTS
// ============================================================================

#define WALLET_NAME_MAX 256
#define WALLET_ADDRESS_MAX 128

// Platform-specific wallet paths
#ifdef _WIN32
#define CELLFRAME_WALLET_PATH "C:\\Users\\Public\\Documents\\cellframe-node\\var\\lib\\wallet"
#else
#define CELLFRAME_WALLET_PATH "/opt/cellframe-node/var/lib/wallet"
#endif

// ============================================================================
// TYPES
// ============================================================================

/**
 * Wallet status
 */
typedef enum {
    WALLET_STATUS_UNPROTECTED,  // No password
    WALLET_STATUS_PROTECTED,    // Password protected
    WALLET_STATUS_DEPRECATED    // Old format
} wallet_status_t;

/**
 * Wallet signature type
 */
typedef enum {
    WALLET_SIG_DILITHIUM,       // sig_dil (Dilithium)
    WALLET_SIG_PICNIC,          // sig_picnic
    WALLET_SIG_BLISS,           // sig_bliss
    WALLET_SIG_TESLA,           // sig_tesla
    WALLET_SIG_UNKNOWN          // Unknown signature type
} wallet_sig_type_t;

/**
 * Cellframe wallet information
 */
typedef struct {
    char filename[WALLET_NAME_MAX];       // Wallet filename (e.g., "test.dwallet")
    char name[WALLET_NAME_MAX];           // Wallet name (without extension)
    wallet_status_t status;               // Protected/unprotected status
    wallet_sig_type_t sig_type;           // Signature algorithm
    bool deprecated;                      // Deprecated format flag

    // Wallet data (raw keys)
    uint8_t *public_key;                  // Public key data
    size_t public_key_size;               // Public key size
    uint8_t *private_key;                 // Private key data (if unprotected)
    size_t private_key_size;              // Private key size

    // Network addresses (to be filled by network-specific functions)
    char address[WALLET_ADDRESS_MAX];     // Wallet address (network-dependent)
} cellframe_wallet_t;

/**
 * Wallet list
 */
typedef struct {
    cellframe_wallet_t *wallets;          // Array of wallets
    size_t count;                         // Number of wallets
} wallet_list_t;

// ============================================================================
// FUNCTIONS
// ============================================================================

/**
 * List all Cellframe wallets in standard directory
 *
 * @param list_out: Output wallet list (caller must free with wallet_list_free())
 * @return: 0 on success, -1 on error
 */
int wallet_list_cellframe(wallet_list_t **list_out);

/**
 * Read a specific Cellframe wallet file
 *
 * @param filename: Wallet filename (e.g., "test_dilithium.dwallet")
 * @param wallet_out: Output wallet structure (caller must free with wallet_free())
 * @return: 0 on success, -1 on error
 */
int wallet_read_cellframe(const char *filename, cellframe_wallet_t **wallet_out);

/**
 * Read Cellframe wallet from full path
 *
 * @param path: Full path to wallet file
 * @param wallet_out: Output wallet structure (caller must free with wallet_free())
 * @return: 0 on success, -1 on error
 */
int wallet_read_cellframe_path(const char *path, cellframe_wallet_t **wallet_out);

/**
 * Get wallet address for specific network
 *
 * @param wallet: Wallet structure
 * @param network_name: Network name (e.g., "Backbone", "KelVPN", "cpunk")
 * @param address_out: Output address buffer (WALLET_ADDRESS_MAX bytes)
 * @return: 0 on success, -1 on error
 */
int wallet_get_address(const cellframe_wallet_t *wallet, const char *network_name, char *address_out);

/**
 * Free a single wallet structure
 *
 * @param wallet: Wallet to free (can be NULL)
 */
void wallet_free(cellframe_wallet_t *wallet);

/**
 * Free wallet list
 *
 * @param list: Wallet list to free (can be NULL)
 */
void wallet_list_free(wallet_list_t *list);

/**
 * Get signature type name as string
 *
 * @param sig_type: Signature type
 * @return: String representation
 */
const char* wallet_sig_type_name(wallet_sig_type_t sig_type);

#ifdef __cplusplus
}
#endif

#endif // DNA_WALLET_H
