/**
 * @file blockchain_registry.c
 * @brief Blockchain Registry Implementation
 */

#include "blockchain.h"
#include <string.h>
#include <stdio.h>

#define LOG_TAG "BLOCKCHAIN"
#include "crypto/utils/qgp_log.h"

/* Registered chains */
static const blockchain_ops_t *g_chains[BLOCKCHAIN_MAX_CHAINS];
static int g_chain_count = 0;

int blockchain_register(const blockchain_ops_t *ops) {
    if (!ops || !ops->name) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid blockchain ops");
        return -1;
    }

    if (g_chain_count >= BLOCKCHAIN_MAX_CHAINS) {
        QGP_LOG_ERROR(LOG_TAG, "Max chains reached");
        return -1;
    }

    /* Check for duplicate */
    for (int i = 0; i < g_chain_count; i++) {
        if (strcmp(g_chains[i]->name, ops->name) == 0) {
            QGP_LOG_ERROR(LOG_TAG, "Chain already registered: %s", ops->name);
            return -1;
        }
    }

    g_chains[g_chain_count++] = ops;
    QGP_LOG_INFO(LOG_TAG, "Registered chain: %s", ops->name);
    return 0;
}

const blockchain_ops_t *blockchain_get(const char *name) {
    if (!name) return NULL;

    for (int i = 0; i < g_chain_count; i++) {
        if (strcmp(g_chains[i]->name, name) == 0) {
            return g_chains[i];
        }
    }
    return NULL;
}

const blockchain_ops_t *blockchain_get_by_type(blockchain_type_t type) {
    for (int i = 0; i < g_chain_count; i++) {
        if (g_chains[i]->type == type) {
            return g_chains[i];
        }
    }
    return NULL;
}

int blockchain_get_all(const blockchain_ops_t **ops_out, int max_count) {
    if (!ops_out || max_count <= 0) return 0;

    int count = (g_chain_count < max_count) ? g_chain_count : max_count;
    for (int i = 0; i < count; i++) {
        ops_out[i] = g_chains[i];
    }
    return count;
}

int blockchain_init_all(void) {
    int failed = 0;

    for (int i = 0; i < g_chain_count; i++) {
        if (g_chains[i]->init) {
            QGP_LOG_INFO(LOG_TAG, "Initializing chain: %s", g_chains[i]->name);
            if (g_chains[i]->init() != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to init chain: %s", g_chains[i]->name);
                failed++;
            }
        }
    }

    return (failed > 0) ? -1 : 0;
}

void blockchain_cleanup_all(void) {
    for (int i = 0; i < g_chain_count; i++) {
        if (g_chains[i]->cleanup) {
            QGP_LOG_INFO(LOG_TAG, "Cleaning up chain: %s", g_chains[i]->name);
            g_chains[i]->cleanup();
        }
    }
}

/* Wrapper function to call send_from_wallet via ops pointer */
int blockchain_ops_send_from_wallet(
    const blockchain_ops_t *ops,
    const char *wallet_path,
    const char *to_address,
    const char *amount,
    const char *token,
    const char *network,
    blockchain_fee_speed_t fee_speed,
    char *txhash_out,
    size_t txhash_out_size
) {
    if (!ops || !ops->send_from_wallet) {
        QGP_LOG_ERROR(LOG_TAG, "Chain does not support send_from_wallet");
        return -1;
    }
    return ops->send_from_wallet(wallet_path, to_address, amount, token,
                                  network, fee_speed, txhash_out, txhash_out_size);
}
