/**
 * @file cli.h
 * @brief DNAC CLI declarations
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_CLI_H
#define DNAC_CLI_H

#include "dnac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CLI Command Functions
 * ========================================================================== */

/**
 * @brief Show wallet balance
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_balance(dnac_context_t *ctx);

/**
 * @brief List UTXOs
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_utxos(dnac_context_t *ctx);

/**
 * @brief Send payment
 * @param ctx DNAC context
 * @param recipient Recipient fingerprint
 * @param amount Amount to send
 * @param memo Optional memo (can be NULL)
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_send(dnac_context_t *ctx, const char *recipient,
                  uint64_t amount, const char *memo);

/**
 * @brief Sync wallet from DHT
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_sync(dnac_context_t *ctx);

/**
 * @brief Show transaction history
 * @param ctx DNAC context
 * @param limit Maximum entries to show (0 = all)
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_history(dnac_context_t *ctx, int limit);

/**
 * @brief Show transaction details
 * @param ctx DNAC context
 * @param tx_hash_hex Transaction hash in hex
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_tx_details(dnac_context_t *ctx, const char *tx_hash_hex);

/**
 * @brief List Nodus servers
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_nodus_list(dnac_context_t *ctx);

/**
 * @brief Recover wallet from DHT
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_recover(dnac_context_t *ctx);

/**
 * @brief Print CLI help
 */
void dnac_cli_print_help(void);

/**
 * @brief Print CLI version
 */
void dnac_cli_print_version(void);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_CLI_H */
