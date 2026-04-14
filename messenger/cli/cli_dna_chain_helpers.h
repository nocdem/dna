/**
 * @file cli_dna_chain_helpers.h
 * @brief Declarations for the dna-connect-cli `dna` subcommand handlers.
 *
 * Originally dnac/include/dnac/cli.h. Moved into messenger/cli/ together
 * with cli_dna_chain_impl.c so the messenger build owns its CLI surface.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CLI_DNA_CHAIN_HELPERS_H
#define CLI_DNA_CHAIN_HELPERS_H

#include "dnac/dnac.h"

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
int dna_chain_cmd_balance(dnac_context_t *ctx);

/**
 * @brief Query balance of any fingerprint via witness UTXO query
 */
int dna_chain_cmd_balance_of(dnac_context_t *ctx, const char *fingerprint);

/**
 * @brief List UTXOs
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_utxos(dnac_context_t *ctx);

/**
 * @brief Send payment
 * @param ctx DNAC context
 * @param recipient Recipient fingerprint
 * @param amount Amount to send
 * @param memo Optional memo (can be NULL)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_send(dnac_context_t *ctx, const char *recipient,
                  uint64_t amount, const char *memo);

/**
 * @brief Sync wallet from DHT
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_sync(dnac_context_t *ctx);

/**
 * @brief Show transaction history
 * @param ctx DNAC context
 * @param limit Maximum entries to show (0 = all)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_history(dnac_context_t *ctx, int limit);

/**
 * @brief Show transaction details
 * @param ctx DNAC context
 * @param tx_hash_hex Transaction hash in hex
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_tx_details(dnac_context_t *ctx, const char *tx_hash_hex);

/**
 * @brief List Nodus servers
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_nodus_list(dnac_context_t *ctx);

/**
 * @brief Show wallet info and status
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_info(dnac_context_t *ctx);

/**
 * @brief Show wallet address (fingerprint only)
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_address(dnac_context_t *ctx);

/**
 * @brief Lookup identity by name or fingerprint
 * @param ctx DNAC context
 * @param query Name or fingerprint to lookup
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_query(dnac_context_t *ctx, const char *query);

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
int dna_chain_cmd_genesis_create(dnac_context_t *ctx, const char *fingerprint,
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
int dna_chain_cmd_genesis_submit(dnac_context_t *ctx, const char *tx_file);

/**
 * @brief Create a new token
 * @param ctx DNAC context
 * @param name Token name
 * @param symbol Token symbol
 * @param supply Total supply in smallest units
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_token_create(dnac_context_t *ctx, const char *name,
                          const char *symbol, uint64_t supply);

/**
 * @brief List all known tokens
 * @param ctx DNAC context
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_token_list(dnac_context_t *ctx);

/**
 * @brief Show token info by ID (hex) or symbol
 * @param ctx DNAC context
 * @param id_or_symbol Token ID hex string or symbol to look up
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_token_info(dnac_context_t *ctx, const char *id_or_symbol);

/**
 * @brief Show balance for a specific token
 * @param ctx DNAC context
 * @param token_id_hex Token ID as hex string
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_balance_token(dnac_context_t *ctx, const char *token_id_hex);

/**
 * @brief Send token payment
 * @param ctx DNAC context
 * @param recipient Recipient fingerprint
 * @param amount Amount to send
 * @param token_id_hex Token ID as hex string
 * @param memo Optional memo (can be NULL)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_send_token(dnac_context_t *ctx, const char *recipient,
                        uint64_t amount, const char *token_id_hex,
                        const char *memo);

/**
 * @brief Print CLI help
 */
void dna_chain_cmd_print_help(void);

/**
 * @brief Print CLI version
 */
void dna_chain_cmd_print_version(void);

/**
 * @brief Read-only TX file inspector
 *
 * Opens @p tx_file, deserializes it via dnac_tx_deserialize, and pretty-prints
 * tx_hash, tx_type, every input nullifier, and every output recipient
 * fingerprint with its amount. Used at deploy time to verify a pre-signed
 * genesis.tx matches the out-of-band agreed recipient list before submission.
 *
 * @param ctx DNAC context (currently unused, accepted for dispatcher symmetry)
 * @param tx_file Path to a serialized transaction file
 * @return 0 on success, non-zero on read or deserialize failure
 */
int dna_chain_cmd_parse_tx(dnac_context_t *ctx, const char *tx_file);

#ifdef __cplusplus
}
#endif

#endif /* CLI_DNA_CHAIN_HELPERS_H */
