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
 *   dnac_v3_block     — One committed version-3 block, paged (scan-v3)
 *   dnac_balance      — One owner's transparent balance per token (scan-v3)
 *
 * CBOR request:  {"t":N, "y":"q", "q":"dnac_*", "tok":bstr, "a":{...}}
 * CBOR response: {"t":N, "y":"r", "q":"dnac_*", "r":{...}}
 *
 * @file nodus_witness_handlers.h
 */

#ifndef NODUS_WITNESS_HANDLERS_H
#define NODUS_WITNESS_HANDLERS_H

#include "witness/nodus_witness.h"

#include "dnac/dnac.h"       /* DNAC_PUBKEY_SIZE */
#include "witness/nodus_witness_cmt_store.h"   /* nodus_cmt_store_t (scan-v3) */
#include "witness/nodus_witness_cmt_host.h"    /* nodus_cmt_host_limits_t     */

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
 * scan-v3 — the `dnac_v3_block` answer WITHOUT its send (the handler adds
 * only the argument decode, the store/limits lookup on w->cmt_node and
 * the send; tests call this directly, test_v3_block_query.c). Wire:
 * include/nodus/nodus.h, nodus_client_dnac_v3_block. Sources and
 * fail-closed rules: the block comment above handle_dnac_v3_block in
 * nodus_witness_handlers.c.
 *
 * Pure read: no write, no transaction, no clock, no cache.
 *
 * @param store   the node's cometbft store (block store + state store)
 *                over w->db — READ only.
 * @param limits  the node's executor limits: a block whose meta exceeds
 *                them is refused, and `max_evidence` sizes the decode.
 * @param budget  item-byte budget; 0 = NODUS_DNAC_V3_BLOCK_BUDGET_MAX,
 *                clamped to [NODUS_DNAC_V3_BLOCK_BUDGET_MIN, _MAX].
 * @param out     [out] the complete T2 response frame (malloc'd; the
 *                caller frees) on success.
 * @param err_code/err_msg [out] the NODUS_ERR_* code and text the handler
 *                answers with on a refusal.
 * @return 0 / -1 refused (err_code/err_msg set when non-NULL).
 */
int nodus_witness_v3_block_build(nodus_witness_t *w,
                                 nodus_cmt_store_t *store,
                                 const nodus_cmt_host_limits_t *limits,
                                 uint32_t txn_id, uint64_t height,
                                 uint32_t from_index, uint32_t budget,
                                 uint8_t **out, size_t *out_len,
                                 int *err_code, char *err_msg,
                                 size_t err_cap);

/**
 * scan-v3 — the `dnac_balance` answer WITHOUT its send (the handler adds
 * only the argument decode and the send; tests call this directly,
 * test_v3_block_query.c). Wire: include/nodus/nodus.h,
 * nodus_client_dnac_balance. Sources, the lock rule and the TRANSPARENT-
 * ONLY scope: the block comment above handle_dnac_balance in
 * nodus_witness_handlers.c (decision 2026-09-28-scan-v3-query.md 3a).
 *
 * Pure read: no write, no transaction, no clock, no cache.
 *
 * @param owner   NUL-terminated; must be exactly 128 lowercase hex
 *                characters (refused otherwise: NODUS_ERR_PROTOCOL_ERROR).
 * @param out     [out] the complete T2 response frame (malloc'd; the
 *                caller frees) on success.
 * @param err_code/err_msg [out] the NODUS_ERR_* code and text the handler
 *                answers with on a refusal: PROTOCOL_ERROR (owner),
 *                NOT_FOUND (no version-3 chain), TOO_LARGE (more than
 *                NODUS_DNAC_BALANCE_MAX_TOKENS tokens), INTERNAL_ERROR
 *                (a store fault, an overflow, a malformed row).
 * @return 0 / -1 refused (err_code/err_msg set when non-NULL).
 */
int nodus_witness_dnac_balance_build(nodus_witness_t *w, uint32_t txn_id,
                                     const char *owner,
                                     uint8_t **out, size_t *out_len,
                                     int *err_code, char *err_msg,
                                     size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_HANDLERS_H */
