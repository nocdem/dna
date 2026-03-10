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

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct nodus_tcp_conn;

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
 * Send spend result to client after BFT COMMIT.
 * Called from nodus_witness_bft.c when PRECOMMIT quorum is reached.
 *
 * @param w         Witness context
 * @param status    0=approved, 1=rejected, 2=error
 * @param error_msg Optional error message (NULL if approved)
 */
void nodus_witness_send_spend_result(nodus_witness_t *w,
                                      int status,
                                      const char *error_msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_HANDLERS_H */
