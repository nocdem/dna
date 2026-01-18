/**
 * @file transaction.c
 * @brief Transaction creation and management
 */

#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

dnac_transaction_t* dnac_tx_create(dnac_tx_type_t type) {
    dnac_transaction_t *tx = calloc(1, sizeof(dnac_transaction_t));
    if (!tx) return NULL;

    tx->version = DNAC_TX_VERSION;
    tx->type = type;
    tx->timestamp = (uint64_t)time(NULL);
    tx->input_count = 0;
    tx->output_count = 0;
    tx->anchor_count = 0;

    return tx;
}

int dnac_tx_add_input(dnac_transaction_t *tx, const dnac_utxo_t *utxo) {
    if (!tx || !utxo) return DNAC_ERROR_INVALID_PARAM;
    if (tx->input_count >= DNAC_TX_MAX_INPUTS) return DNAC_ERROR_INVALID_PARAM;

    dnac_tx_input_t *input = &tx->inputs[tx->input_count];
    memcpy(input->nullifier, utxo->nullifier, DNAC_NULLIFIER_SIZE);
    /* TODO: Compute key image */

    tx->input_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_add_output(dnac_transaction_t *tx,
                       const char *recipient_fingerprint,
                       const uint8_t *recipient_pubkey,
                       uint64_t amount,
                       uint8_t *blinding_out) {
    if (!tx || !recipient_fingerprint || !recipient_pubkey || amount == 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (tx->output_count >= DNAC_TX_MAX_OUTPUTS) return DNAC_ERROR_INVALID_PARAM;

    (void)blinding_out;
    /* TODO: Create Pedersen commitment */
    /* TODO: Create range proof */
    /* TODO: Encrypt amount/blinding for recipient */

    tx->output_count++;
    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_tx_finalize(dnac_transaction_t *tx, const uint8_t *sender_privkey) {
    if (!tx || !sender_privkey) return DNAC_ERROR_INVALID_PARAM;

    /* TODO: Compute balance proof */
    /* TODO: Compute transaction hash */
    /* TODO: Sign with sender's key */

    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_tx_add_anchor(dnac_transaction_t *tx, const dnac_anchor_t *anchor) {
    if (!tx || !anchor) return DNAC_ERROR_INVALID_PARAM;
    if (tx->anchor_count >= DNAC_TX_MAX_ANCHORS) return DNAC_ERROR_INVALID_PARAM;

    memcpy(&tx->anchors[tx->anchor_count], anchor, sizeof(dnac_anchor_t));
    tx->anchor_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_verify(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;

    /* TODO: Verify all range proofs */
    /* TODO: Verify balance proof */
    /* TODO: Verify anchor signatures (need 2+) */
    /* TODO: Verify sender signature */

    if (tx->anchor_count < DNAC_ANCHORS_REQUIRED) {
        return DNAC_ERROR_ANCHOR_FAILED;
    }

    return DNAC_ERROR_NOT_INITIALIZED;
}

void dnac_free_transaction(dnac_transaction_t *tx) {
    free(tx);
}
