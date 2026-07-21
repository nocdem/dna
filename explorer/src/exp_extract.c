/* exp_extract — DNAC Explorer TX extraction module. See exp_extract.h. */

#include "exp_extract.h"

#include <string.h>

#include "dnac/transaction.h"
#include "crypto/hash/qgp_sha3.h"

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_EXTRACT"

int exp_signer_fingerprint(const uint8_t *pubkey, size_t pubkey_len, char fp_out[129]) {
    if (!pubkey || pubkey_len == 0 || !fp_out) return -1;
    return qgp_sha3_512_hex(pubkey, pubkey_len, fp_out, QGP_SHA3_512_HEX_LENGTH);
}

int exp_extract_tx(const uint8_t *raw, size_t raw_len,
                   uint64_t seq, uint64_t height,
                   exp_tx_row_t *tx_row,
                   exp_io_row_t *ios, int max_ios, int *io_count_out) {
    if (!raw || !tx_row || !ios || max_ios < 0 || !io_count_out) {
        QGP_LOG_ERROR(LOG_TAG, "invalid params");
        return -1;
    }

    dnac_transaction_t *tx = NULL;
    if (dnac_tx_deserialize(raw, raw_len, &tx) != DNAC_SUCCESS || !tx) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_tx_deserialize failed");
        return -1;
    }

    /* Defensive: a malformed-but-deserializable TX with no signer has no
     * pubkey to attribute inputs to — reject rather than crash. */
    if (tx->signer_count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "signer_count == 0");
        dnac_tx_free(tx);
        return -1;
    }

    char fp0[129];
    if (exp_signer_fingerprint(tx->signers[0].pubkey, DNAC_PUBKEY_SIZE, fp0) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "signer[0] fingerprint failed");
        dnac_tx_free(tx);
        return -1;
    }

    int total_ios = tx->input_count + tx->output_count;
    if (total_ios > max_ios) {
        QGP_LOG_ERROR(LOG_TAG, "io_count %d exceeds max_ios %d", total_ios, max_ios);
        dnac_tx_free(tx);
        return -1;
    }

    memset(tx_row, 0, sizeof(*tx_row));
    memcpy(tx_row->hash, tx->tx_hash, sizeof(tx_row->hash));
    tx_row->seq          = seq;
    tx_row->height       = height;
    tx_row->tx_type      = (int)tx->type;
    tx_row->fee          = tx->committed_fee;
    tx_row->size         = (uint32_t)raw_len;
    tx_row->timestamp    = tx->timestamp;              /* D4/F6: never wall-clock */
    tx_row->multi_signer = (tx->signer_count > 1) ? 1 : 0;

    int idx = 0;
    for (int i = 0; i < tx->input_count; i++, idx++) {
        exp_io_row_t *row = &ios[idx];
        memset(row, 0, sizeof(*row));
        memcpy(row->tx_hash, tx->tx_hash, sizeof(row->tx_hash));
        row->io_index  = i;
        row->direction = 0;
        memcpy(row->address, fp0, sizeof(row->address));
        memcpy(row->token_id, tx->inputs[i].token_id, sizeof(row->token_id));
        row->amount = tx->inputs[i].amount;
    }

    for (int i = 0; i < tx->output_count; i++, idx++) {
        exp_io_row_t *row = &ios[idx];
        memset(row, 0, sizeof(*row));
        memcpy(row->tx_hash, tx->tx_hash, sizeof(row->tx_hash));
        row->io_index  = i;
        row->direction = 1;
        memcpy(row->address, tx->outputs[i].owner_fingerprint, sizeof(row->address));
        memcpy(row->token_id, tx->outputs[i].token_id, sizeof(row->token_id));
        row->amount = tx->outputs[i].amount;
    }

    *io_count_out = idx;

    dnac_tx_free(tx);
    return 0;
}
