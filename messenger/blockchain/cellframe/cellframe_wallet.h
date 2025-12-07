/*
 * wallet.h - Cellframe Wallet Reader for DNA Messenger
 *
 * Reads Cellframe wallet files (.dwallet format) from standard locations.
 * These wallets are used for CF20 token operations on Cellframe blockchain.
 */

#ifndef WALLET_H
#define WALLET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Platform-specific wallet paths
#ifdef _WIN32
#define CELLFRAME_WALLET_PATH "C:\\Users\\Public\\Documents\\cellframe-node\\var\\lib\\wallet"
#else
#define CELLFRAME_WALLET_PATH "/opt/cellframe-node/var/lib/wallet"
#endif

#define WALLET_NAME_MAX 256
#define WALLET_ADDRESS_MAX 120

// Wallet status
typedef enum {
    WALLET_STATUS_UNPROTECTED,
    WALLET_STATUS_PROTECTED
} wallet_status_t;

// Wallet signature type
typedef enum {
    WALLET_SIG_DILITHIUM,
    WALLET_SIG_PICNIC,
    WALLET_SIG_BLISS,
    WALLET_SIG_TESLA,
    WALLET_SIG_UNKNOWN
} wallet_sig_type_t;

// Cellframe wallet information
typedef struct {
    char filename[WALLET_NAME_MAX];
    char name[WALLET_NAME_MAX];
    wallet_status_t status;
    wallet_sig_type_t sig_type;
    bool deprecated;
    uint8_t *public_key;
    size_t public_key_size;
    uint8_t *private_key;
    size_t private_key_size;
    char address[WALLET_ADDRESS_MAX];
} cellframe_wallet_t;

// List of wallets
typedef struct {
    cellframe_wallet_t *wallets;
    size_t count;
} wallet_list_t;

/**
 * Read Cellframe wallet from full path
 */
int wallet_read_cellframe_path(const char *path, cellframe_wallet_t **wallet_out);

/**
 * Read Cellframe wallet from standard directory
 */
int wallet_read_cellframe(const char *filename, cellframe_wallet_t **wallet_out);

/**
 * List all Cellframe wallets
 */
int wallet_list_cellframe(wallet_list_t **list_out);

/**
 * List wallets from ~/.dna/wallets directory (all identities)
 */
int wallet_list_from_dna_dir(wallet_list_t **list_out);

/**
 * List wallets for a specific identity from ~/.dna/<fingerprint>/wallets/
 */
int wallet_list_for_identity(const char *fingerprint, wallet_list_t **list_out);

/**
 * Get wallet address (returns address from loaded wallet struct)
 */
int wallet_get_address(const cellframe_wallet_t *wallet, const char *network_name, char *address_out);

/**
 * Free wallet structure
 */
void wallet_free(cellframe_wallet_t *wallet);

/**
 * Free wallet list
 */
void wallet_list_free(wallet_list_t *list);

/**
 * Get signature type name as string
 */
const char* wallet_sig_type_name(wallet_sig_type_t sig_type);

#ifdef __cplusplus
}
#endif

#endif /* WALLET_H */
