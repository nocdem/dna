/*
 * cellframe_wallet.h - Cellframe Wallet Types
 *
 * Defines the cellframe_wallet_t struct used by seed-based derivation.
 */

#ifndef WALLET_H
#define WALLET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WALLET_NAME_MAX 256
#define WALLET_ADDRESS_MAX 120

/* Wallet status */
typedef enum {
    WALLET_STATUS_UNPROTECTED,
    WALLET_STATUS_PROTECTED
} wallet_status_t;

/* Wallet signature type */
typedef enum {
    WALLET_SIG_DILITHIUM,
    WALLET_SIG_PICNIC,
    WALLET_SIG_BLISS,
    WALLET_SIG_TESLA,
    WALLET_SIG_UNKNOWN
} wallet_sig_type_t;

/* Cellframe wallet information */
typedef struct {
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

#ifdef __cplusplus
}
#endif

#endif /* WALLET_H */
