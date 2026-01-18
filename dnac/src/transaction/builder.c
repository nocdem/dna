/**
 * @file builder.c
 * @brief Transaction builder pattern
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include <stdlib.h>

struct dnac_tx_builder {
    dnac_context_t *ctx;
    dnac_transaction_t *tx;
    dnac_tx_output_t outputs[DNAC_TX_MAX_OUTPUTS];
    int output_count;
};

dnac_tx_builder_t* dnac_tx_builder_create(dnac_context_t *ctx) {
    if (!ctx) return NULL;

    dnac_tx_builder_t *builder = calloc(1, sizeof(dnac_tx_builder_t));
    if (!builder) return NULL;

    builder->ctx = ctx;
    builder->tx = dnac_tx_create(DNAC_TX_SPEND);
    if (!builder->tx) {
        free(builder);
        return NULL;
    }

    return builder;
}

int dnac_tx_builder_add_output(dnac_tx_builder_t *builder,
                               const dnac_tx_output_t *output) {
    if (!builder || !output) return DNAC_ERROR_INVALID_PARAM;
    if (builder->output_count >= DNAC_TX_MAX_OUTPUTS) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    builder->outputs[builder->output_count++] = *output;
    return DNAC_SUCCESS;
}

int dnac_tx_builder_build(dnac_tx_builder_t *builder,
                          dnac_transaction_t **tx_out) {
    if (!builder || !tx_out) return DNAC_ERROR_INVALID_PARAM;

    /* TODO: Select UTXOs from wallet */
    /* TODO: Add inputs */
    /* TODO: Add outputs */
    /* TODO: Add change output if needed */
    /* TODO: Finalize transaction */

    *tx_out = NULL;
    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_tx_broadcast(dnac_context_t *ctx,
                      dnac_transaction_t *tx,
                      dnac_callback_t callback,
                      void *user_data) {
    if (!ctx || !tx) return DNAC_ERROR_INVALID_PARAM;
    (void)callback;
    (void)user_data;

    /* TODO: Request anchors from Nodus servers */
    /* TODO: Once 2+ anchors collected, send via DHT */

    return DNAC_ERROR_NOT_INITIALIZED;
}

void dnac_tx_builder_free(dnac_tx_builder_t *builder) {
    if (!builder) return;
    if (builder->tx) dnac_free_transaction(builder->tx);
    free(builder);
}
