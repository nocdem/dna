/* exp_extract — DNAC Explorer TX extraction module.
 *
 * Turns raw wire-format TX bytes (as returned by the witness / stored in
 * blocks) into the row shapes exp_db.h persists (exp_tx_row_t + N ×
 * exp_io_row_t). All parsing goes through dnac_tx_deserialize — this module
 * never re-implements or duplicates the wire codec.
 *
 * Attribution rule (binding, plan Task 3): ALL input rows are attributed to
 * signers[0]'s fingerprint (SHA3-512(pubkey), lowercase hex) regardless of
 * which signer actually owns a given input's UTXO — this module does not
 * attempt per-input ownership resolution. multi_signer = (signer_count > 1).
 *
 * Determinism (PRIMARY OBJECTIVE: DETERMINISM): tx_row.timestamp comes ONLY
 * from the deserialized tx->timestamp — never from any envelope or
 * wall-clock source (D4/F6).
 */
#ifndef EXP_EXTRACT_H
#define EXP_EXTRACT_H

#include <stdint.h>
#include <stddef.h>

#include "exp_db.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Raw TX bytes -> rows. Fills tx_row (hash from deserialized tx->tx_hash,
 * seq/height passed in by caller, timestamp from tx->timestamp, fee from
 * tx->committed_fee, multi_signer = tx->signer_count > 1) and io rows.
 *
 * Input rows (ios[0..input_count)): direction=0, address = fingerprint of
 * signers[0].pubkey, amount/token_id from tx->inputs[i].
 * Output rows (ios[input_count..input_count+output_count)): direction=1,
 * address = tx->outputs[i].owner_fingerprint, amount/token_id from the
 * output. io_index restarts at 0 within each direction.
 *
 * Fails (-1) on: deserialize failure, signer_count == 0 (defensive — a
 * malformed-but-deserializable TX has no signer to attribute inputs to),
 * a malformed output owner_fingerprint (must be exactly 128 lowercase-hex
 * chars terminated by NUL at index 128 — checked in a pre-pass over all
 * outputs before any tx_row/ios write, so the untouched-on-failure
 * guarantee below holds for this case too), or
 * input_count + output_count > max_ios.
 *
 * @param raw          serialized TX bytes (wire format)
 * @param raw_len      length of raw in bytes
 * @param seq          ledger sequence to stamp into tx_row (caller-supplied)
 * @param height       block height to stamp into tx_row (caller-supplied)
 * @param tx_row       [out] filled on success
 * @param ios          [out] caller-allocated array, capacity max_ios
 * @param max_ios       capacity of ios[]
 * @param io_count_out [out] number of io rows written (input_count + output_count)
 * @return 0 on success, -1 on failure (tx_row/ios/io_count_out left
 *         untouched on failure)
 */
int exp_extract_tx(const uint8_t *raw, size_t raw_len,
                   uint64_t seq, uint64_t height,
                   exp_tx_row_t *tx_row,
                   exp_io_row_t *ios, int max_ios, int *io_count_out);

/* signers[0].pubkey -> 128-hex lowercase fingerprint (SHA3-512).
 *
 * @param pubkey     signer public key bytes
 * @param pubkey_len length of pubkey in bytes
 * @param fp_out     [out] 129-byte buffer (128 hex chars + NUL)
 * @return 0 on success, -1 on failure (bad params or hash failure)
 */
int exp_signer_fingerprint(const uint8_t *pubkey, size_t pubkey_len, char fp_out[129]);

#ifdef __cplusplus
}
#endif

#endif /* EXP_EXTRACT_H */
