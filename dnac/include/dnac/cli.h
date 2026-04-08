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
 * @brief Query balance of any fingerprint via witness UTXO query
 */
int dnac_cli_balance_of(dnac_context_t *ctx, const char *fingerprint);

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
 * @brief Show wallet info and status
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_info(dnac_context_t *ctx);

/**
 * @brief Show wallet address (fingerprint only)
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_address(dnac_context_t *ctx);

/**
 * @brief Lookup identity by name or fingerprint
 * @param ctx DNAC context
 * @param query Name or fingerprint to lookup
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_query(dnac_context_t *ctx, const char *query);

/**
 * @brief Create genesis TX locally (Phase 1 — no network)
 *
 * Builds genesis TX, derives chain_id, saves to file.
 *
 * @param ctx DNAC context
 * @param fingerprint Recipient identity fingerprint
 * @param amount Amount to allocate
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_genesis_create(dnac_context_t *ctx, const char *fingerprint,
                            uint64_t amount);

/**
 * @brief Submit genesis TX to network (Phase 2 — requires witnesses)
 *
 * Loads genesis TX from file, recomputes chain_id, submits to witnesses.
 *
 * @param ctx DNAC context
 * @param tx_file Path to genesis TX file (NULL for default ~/.dna/genesis_tx.bin)
 * @return 0 on success, non-zero on failure
 */
int dnac_cli_genesis_submit(dnac_context_t *ctx, const char *tx_file);

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
