/**
 * Nodus — DNAC Client Handlers
 *
 * Handles post-auth "dnac_*" Tier 2 methods:
 *   dnac_spend        — Submit TX for BFT consensus
 *   dnac_nullifier    — Check nullifier spend status
 *   dnac_ledger       — Query ledger entry by tx_hash
 *   dnac_supply       — Query supply state
 *   dnac_utxo         — Query UTXOs by owner fingerprint
 *   dnac_ledger_range — Query range of ledger entries
 *   dnac_roster       — Return witness roster
 *
 * CBOR request:  {"t":N, "y":"q", "q":"dnac_*", "tok":bstr, "a":{...}}
 * CBOR response: {"t":N, "y":"r", "q":"dnac_*", "r":{...}}
 *
 * @file nodus_witness_handlers.h
 */

#ifndef NODUS_WITNESS_HANDLERS_H
#define NODUS_WITNESS_HANDLERS_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_mempool.h"

#include "dnac/dnac.h"       /* DNAC_PUBKEY_SIZE */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct nodus_tcp_conn;

/** Per-entry output for pending rewards RPC (Phase 14 / Task 61). */
typedef struct {
    uint8_t  validator_pubkey[DNAC_PUBKEY_SIZE];
    uint64_t amount;
} dnac_pending_entry_t;

/**
 * Compute pending rewards for `claimant_pubkey`. Mirrors the u128 math
 * in apply_claim_reward (commit 5d46d5c2). One entry per active
 * delegation with non-zero pending, plus a final entry for the
 * validator-self path if the claimant is itself a validator with
 * validator_unclaimed > 0.
 *
 * Used by dnac_pending_rewards_query handler. Exposed in the header for
 * unit-test direct invocation without a TCP conn.
 *
 * @param w              Witness context (DB open).
 * @param claimant_pubkey  DNAC_PUBKEY_SIZE bytes.
 * @param entries_out    Caller-allocated, >= 65 slots.
 * @param entry_count_out [out] Number populated.
 * @param total_out      [out] Sum of all entries.
 * @return 0 on success, -1 on DB error.
 */
int nodus_witness_compute_pending_rewards(nodus_witness_t *w,
                                            const uint8_t *claimant_pubkey,
                                            dnac_pending_entry_t *entries_out,
                                            int *entry_count_out,
                                            uint64_t *total_out);

/**
 * Dispatch a DNAC client query to the appropriate handler.
 *
 * @param w         Witness context
 * @param conn      Client TCP connection (for sending response)
 * @param payload   Raw CBOR payload (full T2 message)
 * @param len       Payload length
 * @param method    Decoded method name ("dnac_spend", etc.)
 * @param txn_id    Transaction ID for response correlation
 */
void nodus_witness_handle_dnac(nodus_witness_t *w,
                                struct nodus_tcp_conn *conn,
                                const uint8_t *payload, size_t len,
                                const char *method, uint32_t txn_id);

/**
 * Phase 12 / Task 12.5 — per-entry spend_result sender.
 *
 * Sends the witness attestation receipt for a single TX after the
 * commit path lands the block. The entry MUST have been populated by
 * commit_batch (committed_block_height + committed_tx_index set,
 * client_conn / client_txn_id from when the TX was admitted).
 *
 * The signed preimage carries an 8-byte 'spndrslt' domain tag,
 * tx_hash, witness_id, SHA3-512(witness_pubkey), chain_id, status,
 * timestamp, block_height, and tx_index — 221 bytes, fixed layout —
 * fixing the legacy TOCTOU bug where time(NULL) was called twice and
 * the wpk was wire-only (not bound by the signature).
 *
 * @param w         Witness context
 * @param entry     Mempool entry that just committed
 * @param status    0=approved, 1=rejected, 2=error
 * @param error_msg Optional error message (NULL if approved)
 */
void nodus_witness_send_spend_result(nodus_witness_t *w,
                                      nodus_witness_mempool_entry_t *entry,
                                      int status,
                                      const char *error_msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_HANDLERS_H */
