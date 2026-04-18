/**
 * Nodus — Witness Transaction Verification
 *
 * Full transaction verification for BFT consensus.
 * Checks: tx_hash integrity, sender signature, balance, fee,
 * duplicate nullifiers, double-spend.
 *
 * Called from both leader (start_round) and follower (handle_propose)
 * paths before casting PREVOTE.
 *
 * @file nodus_witness_verify.h
 */

#ifndef NODUS_WITNESS_VERIFY_H
#define NODUS_WITNESS_VERIFY_H

#include "witness/nodus_witness.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Recompute SHA3-512 hash from serialized tx_data.
 *
 * Matches dnac_tx_compute_hash() byte-for-byte (design §2.3, F-CRYPTO-10):
 *
 *   version(u8) || type(u8) || timestamp(u64 BE) || chain_id[32] ||
 *   inputs[0..input_count]  each: nullifier(64) || amount(u64 BE) || token_id(64) ||
 *   outputs[0..output_count] each: version(u8) || fp(129) || amount(u64 BE) ||
 *                                  token_id(64) || seed(32) || memo_len(u8) || memo(memo_len) ||
 *   signer_count(u8) || signer_pubkeys[0..signer_count] (each NODUS_PK_BYTES) ||
 *   type_specific_appended
 *
 * Count bytes for inputs/outputs are NOT hashed (derived from wire-format
 * prefixes). The embedded tx_hash inside tx_data (at offset 10, 64 bytes) is
 * skipped. Signer signatures are NOT hashed — only their pubkeys.
 *
 * Type-specific appended (for STAKE/DELEGATE/etc.) is parsed from tx_data
 * directly since the wire bytes for those fields already use BE u64 encoding
 * (see dnac/src/transaction/serialize.c).
 *
 * @param chain_id         32-byte chain_id (witness's own; bound into preimage)
 * @param tx_data          Serialized transaction bytes
 * @param tx_len           Length of tx_data
 * @param signer_pubkeys   Concatenated signer public keys (signer_count * NODUS_PK_BYTES)
 * @param signer_count     Number of signers (0 for genesis)
 * @param hash_out         Output 64-byte SHA3-512 hash
 * @return 0 on success, -1 on error (truncated data, etc.)
 */
int nodus_witness_recompute_tx_hash(const uint8_t *chain_id,
                                     const uint8_t *tx_data, uint32_t tx_len,
                                     const uint8_t *signer_pubkeys,
                                     uint8_t signer_count,
                                     uint8_t *hash_out);

/**
 * Full transaction verification for BFT consensus.
 *
 * Performs six checks (balance/fee/sig skipped for genesis):
 *   1. Duplicate nullifiers within TX
 *   2. TX hash integrity (recompute and compare)
 *   3. Sender Dilithium5 signature
 *   4. Balance (input amounts from UTXO DB >= output amounts)
 *   5. Fee (actual >= min fee, matches declared)
 *   6. Double-spend (nullifiers not already in DB)
 *
 * @param w                 Witness context (for DB lookups)
 * @param tx_data           Serialized transaction bytes
 * @param tx_len            Length of tx_data
 * @param tx_hash           Claimed transaction hash (64 bytes)
 * @param tx_type           Transaction type (GENESIS/SPEND/BURN)
 * @param nullifiers        Concatenated nullifiers (nullifier_count * 64 bytes)
 * @param nullifier_count   Number of input nullifiers
 * @param client_pubkey     Sender's Dilithium5 public key (2592 bytes)
 * @param client_signature  Sender's signature over tx_hash (4627 bytes)
 * @param declared_fee      Fee amount declared by client
 * @param reject_reason     Output: human-readable rejection reason
 * @param reason_size       Size of reject_reason buffer
 * @return 0 if valid, -1 if invalid (reject_reason filled), -2 if double-spend
 */
int nodus_witness_verify_transaction(nodus_witness_t *w,
                                      const uint8_t *tx_data, uint32_t tx_len,
                                      const uint8_t *tx_hash, uint8_t tx_type,
                                      const uint8_t *nullifiers, uint8_t nullifier_count,
                                      const uint8_t *client_pubkey,
                                      const uint8_t *client_signature,
                                      uint64_t declared_fee,
                                      char *reject_reason, size_t reason_size);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_VERIFY_H */
