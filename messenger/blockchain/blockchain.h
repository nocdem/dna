/**
 * @file blockchain.h
 * @brief Modular Blockchain Interface
 *
 * Common interface for all blockchain implementations.
 * Each chain registers its operations via blockchain_register().
 */

#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum registered chains */
#define BLOCKCHAIN_MAX_CHAINS 16

/* Chain types */
typedef enum {
    BLOCKCHAIN_TYPE_UNKNOWN = 0,
    BLOCKCHAIN_TYPE_ETHEREUM,
    BLOCKCHAIN_TYPE_CELLFRAME,
    BLOCKCHAIN_TYPE_BITCOIN,      /* Future */
    BLOCKCHAIN_TYPE_SOLANA,       /* Future */
} blockchain_type_t;

/* Transaction status */
typedef enum {
    BLOCKCHAIN_TX_PENDING = 0,
    BLOCKCHAIN_TX_SUCCESS,
    BLOCKCHAIN_TX_FAILED,
    BLOCKCHAIN_TX_NOT_FOUND,
} blockchain_tx_status_t;

/* Fee speed presets */
typedef enum {
    BLOCKCHAIN_FEE_SLOW = 0,
    BLOCKCHAIN_FEE_NORMAL = 1,
    BLOCKCHAIN_FEE_FAST = 2,
} blockchain_fee_speed_t;

/* Forward declarations */
typedef struct blockchain_ops blockchain_ops_t;

/**
 * Blockchain operations interface
 *
 * Each chain implements this interface.
 */
struct blockchain_ops {
    /* Chain identification */
    const char *name;                 /* "ethereum", "cellframe", etc. */
    blockchain_type_t type;

    /* Lifecycle */
    int (*init)(void);
    void (*cleanup)(void);

    /* Balance */
    int (*get_balance)(
        const char *address,
        const char *token,            /* NULL for native token */
        char *balance_out,            /* Decimal string */
        size_t balance_out_size
    );

    /* Fee estimation */
    int (*estimate_fee)(
        blockchain_fee_speed_t speed,
        uint64_t *fee_out,            /* In smallest unit (wei, datoshi) */
        uint64_t *gas_price_out       /* Optional, can be NULL */
    );

    /* Send transaction */
    int (*send)(
        const char *from_address,
        const char *to_address,
        const char *amount,           /* Decimal string */
        const char *token,            /* NULL for native token */
        const uint8_t *private_key,
        size_t private_key_len,
        blockchain_fee_speed_t fee_speed,
        char *txhash_out,
        size_t txhash_out_size
    );

    /* Transaction status */
    int (*get_tx_status)(
        const char *txhash,
        blockchain_tx_status_t *status_out
    );

    /* Address validation */
    bool (*validate_address)(const char *address);

    /* Chain-specific data (optional) */
    void *user_data;
};

/**
 * Register a blockchain implementation
 *
 * @param ops   Pointer to operations struct (must remain valid)
 * @return      0 on success, -1 on error
 */
int blockchain_register(const blockchain_ops_t *ops);

/**
 * Get blockchain by name
 *
 * @param name  Chain name ("ethereum", "cellframe")
 * @return      Pointer to ops or NULL if not found
 */
const blockchain_ops_t *blockchain_get(const char *name);

/**
 * Get blockchain by type
 *
 * @param type  Chain type enum
 * @return      Pointer to ops or NULL if not found
 */
const blockchain_ops_t *blockchain_get_by_type(blockchain_type_t type);

/**
 * Get all registered blockchains
 *
 * @param ops_out   Array to fill with pointers
 * @param max_count Maximum entries to return
 * @return          Number of chains returned
 */
int blockchain_get_all(const blockchain_ops_t **ops_out, int max_count);

/**
 * Initialize all registered blockchains
 *
 * @return  0 on success, -1 if any chain failed
 */
int blockchain_init_all(void);

/**
 * Cleanup all registered blockchains
 */
void blockchain_cleanup_all(void);

#ifdef __cplusplus
}
#endif

#endif /* BLOCKCHAIN_H */
