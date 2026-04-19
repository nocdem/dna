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
/**
 * @param chain_def_file_path  Optional binary file (serialized
 *                             dnac_chain_definition_t) produced by the
 *                             pack_chain_def operator tool. NULL for a
 *                             legacy (non-anchored) genesis.
 */
int dna_chain_cmd_genesis_create(dnac_context_t *ctx, const char *fingerprint,
                            uint64_t amount,
                            const char *chain_def_file_path);

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
 * @brief Build a chain_def blob from an operator config file.
 *
 * Thin wrapper around dnac_cli_genesis_prepare_blob — reads the config,
 * encodes the canonical chain_def blob (including 7 initial_validators),
 * and hex-prints it to stdout. ctx is currently unused (accepted for
 * dispatcher symmetry).
 *
 * @param ctx          DNAC context (unused).
 * @param config_path  Path to key=value operator config.
 * @return 0 on success, non-zero on failure.
 */
int dna_chain_cmd_genesis_prepare(dnac_context_t *ctx, const char *config_path);

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
 * dna_chain_cmd_print_help / dna_chain_cmd_print_version removed
 * 2026-04-19 — dead code (never called, stale `dnac-cli` text).
 * Group help lives in cli_dna_chain.c dispatch.
 */

/* ============================================================================
 * Stake & Delegation CLI (Phase 15 / Tasks 65-69)
 *
 * Thin wrappers around the Phase 7 builder APIs + Phase 14 query RPCs.
 * Validator identifiers are accepted as hex-encoded Dilithium5 pubkeys
 * (2 * DNAC_PUBKEY_SIZE = 5184 chars). Name/fingerprint → pubkey
 * resolution is deferred to a later polish commit (no direct helper
 * currently exists; would require iterating the full validator table).
 * ========================================================================== */

/**
 * @brief `dna stake` verb — become a validator.
 *
 * Defaults:
 *   - commission_bps = 500 (5%)
 *   - unstake_destination_fp = caller's own fingerprint
 *
 * @param ctx             DNAC context
 * @param commission_bps  Commission in basis points (0..DNAC_COMMISSION_BPS_MAX)
 * @param unstake_to_fp   Optional 128-char hex fingerprint (NULL = use own fp)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_stake(dnac_context_t *ctx,
                        uint16_t commission_bps,
                        const char *unstake_to_fp);

/**
 * @brief `dna unstake` verb — trigger validator retirement.
 *
 * Fee-only TX. Caller must be an active validator. Actual self-stake
 * return happens at the next epoch boundary via a locked UTXO.
 *
 * @param ctx  DNAC context
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_unstake(dnac_context_t *ctx);

/**
 * @brief `dna delegate` verb — stake native DNAC with a validator.
 *
 * @param ctx                   DNAC context
 * @param validator_pubkey_hex  Hex-encoded Dilithium5 pubkey (5184 chars)
 * @param amount                Amount in raw units (>= DNAC_MIN_DELEGATION)
 * @param memo                  Optional memo (currently unused; reserved)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_delegate(dnac_context_t *ctx,
                           const char *validator_pubkey_hex,
                           uint64_t amount,
                           const char *memo);

/**
 * @brief `dna undelegate` verb — withdraw (part of) a delegation.
 *
 * @param ctx                   DNAC context
 * @param validator_pubkey_hex  Hex-encoded Dilithium5 pubkey (5184 chars)
 * @param amount                Principal to withdraw in raw units (> 0)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_undelegate(dnac_context_t *ctx,
                             const char *validator_pubkey_hex,
                             uint64_t amount);

/**
 * @brief `dna claim` verb — withdraw accrued staking rewards.
 *
 * Internally queries pending rewards via Phase 14 RPC, sets
 * max_pending_amount = pending, valid_before_block = current + freshness,
 * then submits a CLAIM_REWARD TX.
 *
 * @param ctx                   DNAC context
 * @param validator_pubkey_hex  Hex-encoded Dilithium5 pubkey (5184 chars)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_claim(dnac_context_t *ctx,
                        const char *validator_pubkey_hex);

/**
 * @brief `dna validator-update` verb — change commission rate.
 *
 * Queries witness for current block height internally to populate
 * signed_at_block (Rule K freshness).
 *
 * @param ctx             DNAC context
 * @param commission_bps  New commission in basis points (0..DNAC_COMMISSION_BPS_MAX)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_validator_update(dnac_context_t *ctx,
                                   uint16_t commission_bps);

/**
 * @brief `dna validator-list` verb — dump validator table.
 *
 * @param ctx            DNAC context
 * @param filter_status  -1 = all, 0..3 = filter by dnac_validator_status_t
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_validator_list(dnac_context_t *ctx, int filter_status);

/**
 * @brief `dna committee` verb — dump current epoch's top-7 committee.
 */
int dna_chain_cmd_committee(dnac_context_t *ctx);

/**
 * @brief `dna pending-rewards` verb — show accrued rewards for caller
 *        (or a specified claimant pubkey).
 *
 * @param ctx                 DNAC context
 * @param claimant_pubkey_hex Optional hex-encoded pubkey (NULL = caller)
 * @return 0 on success, non-zero on failure
 */
int dna_chain_cmd_pending_rewards(dnac_context_t *ctx,
                                  const char *claimant_pubkey_hex);

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
