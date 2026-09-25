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
 * Verification mode — separates DETERMINISTIC consensus validation from
 * per-node LOCAL ADMISSION policy.
 *
 * R3 W4 — the dynamic fee surge (Check 5) that used to scale the minimum
 * acceptable fee with w->mempool.count is DELETED with the closed
 * consensus lane: the field it read no longer exists, and neither mode
 * branches on `mode` anywhere in nodus_witness_verify.c any more (grep
 * confirms zero `mode ==` comparisons left in that file) — ADMISSION and
 * VALIDATION are behaviourally identical here now. The two-valued type
 * itself is kept: it is still a caller-visible contract other callers
 * (e.g. the cometbft application's check_tx in ADMISSION mode) pass
 * explicitly, and nothing about this file requires collapsing it to one
 * value.
 *
 * The deterministic fee floor is unaffected: Check 0 enforces
 * committed_fee >= DNAC_MIN_FEE_RAW in BOTH modes, and
 * DNAC_MIN_FEE_RAW == NODUS_W_BASE_TX_FEE, so both modes hold the full
 * base-fee bar identically.
 *
 * VALIDATION == 0 IS DELIBERATE AND MUST NOT BE REORDERED: a future call
 * site that leaves the field zero-initialised or forgets to pass a mode
 * falls into the DETERMINISTIC branch (fail-close for consensus), never
 * into the node-local one — even though this file no longer distinguishes
 * the two, a future check might, and the fail-closed direction must stay
 * the zero value.
 */
typedef enum {
    NODUS_WITNESS_VERIFY_VALIDATION = 0,  /* block validation — deterministic */
    NODUS_WITNESS_VERIFY_ADMISSION  = 1   /* mempool admission — local policy */
} nodus_witness_verify_mode_t;

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
 *   5. Fee (actual == declared; surge minimum in ADMISSION mode only)
 *   6. Double-spend (nullifiers not already in DB)
 *
 * Every check except the Check-5 surge minimum is deterministic: it reads
 * only the TX bytes and committed DB state. See nodus_witness_verify_mode_t.
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
 * @param mode              VALIDATION (deterministic; block verify paths) or
 *                          ADMISSION (adds the node-local mempool fee surge)
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
                                      nodus_witness_verify_mode_t mode,
                                      char *reject_reason, size_t reason_size);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_VERIFY_H */
