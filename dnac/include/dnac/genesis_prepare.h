/**
 * @file genesis_prepare.h
 * @brief Phase 12 Task 58 — operator tool to build a chain_def blob
 *        containing 7 initial_validators from a simple config file.
 *
 * The full "signed genesis TX" ceremony (UTXO supply distribution list +
 * signer witness attestations) is out of scope for this helper — that is
 * a Phase 18+ task. Here we produce just the chain_def CBOR-equivalent
 * canonical byte blob suitable for feeding to `dna genesis-create
 * --chain-def-file`.
 *
 * Config file format (simple key=value, one per line, '#' for comments):
 *
 *   chain_name=mainnet
 *   protocol_version=1
 *   witness_count=0                  # no legacy witness_pubkeys needed
 *   max_active_witnesses=21
 *   block_interval_sec=5
 *   max_txs_per_block=10
 *   view_change_timeout_ms=5000
 *   token_symbol=DNAC
 *   token_decimals=8
 *   initial_supply_raw=100000000000000000
 *
 *   # 7 initial validators — indexed 0..6 (missing indices fail validation).
 *   validator_0_pubkey=<5184-char hex>            # 2592 bytes
 *   validator_0_fp=<128-char hex>                 # 64 bytes hex-encoded
 *   validator_0_commission_bps=500                # 5 %
 *   validator_0_endpoint=node0.dnac.example:4004
 *   ... (validator_1_* through validator_6_*)
 *
 * Parent chain_id and genesis_message default to empty/zeros; operators
 * can override via `parent_chain_id=<hex128>` and `genesis_message=...`.
 */

#ifndef DNAC_GENESIS_PREPARE_H
#define DNAC_GENESIS_PREPARE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build a canonical chain_def blob from the config at @p config_path.
 *
 * @param config_path  Path to the key=value config file.
 * @param blob_out     Caller-allocated output buffer.
 * @param blob_cap     Capacity of blob_out in bytes.
 * @param blob_len_out [out] Bytes written to blob_out on success.
 * @param err_out      Optional caller-allocated error-message buffer
 *                     (at least 256 bytes). Filled on failure when non-NULL.
 * @param err_cap      Capacity of err_out.
 *
 * @return 0 on success, -1 on error.
 *
 * Successful invariants (all checked):
 *   - 7 initial_validators populated (indices 0..6 all present)
 *   - All pubkey hex fields are 5184 chars (2592 bytes)
 *   - All fp fields are at most 128 chars
 *   - All endpoint fields are at most 127 chars (leave room for terminating NUL)
 *   - commission_bps in [0, 10000]
 *   - pairwise-distinct validator_N_pubkey (Rule P.3 canary; final authority
 *     is the genesis TX verify, but catching it here gives better errors)
 */
int dnac_cli_genesis_prepare_blob(const char *config_path,
                                    uint8_t *blob_out,
                                    size_t blob_cap,
                                    size_t *blob_len_out,
                                    char *err_out,
                                    size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_GENESIS_PREPARE_H */
