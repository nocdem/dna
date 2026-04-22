/**
 * @file validator_update.c
 * @brief VALIDATOR_UPDATE transaction builder (Phase 7, Task 37).
 *
 * Public API (see dnac.h):
 *   - dnac_validator_update() — build + broadcast a DNAC_TX_VALIDATOR_UPDATE
 *
 * Design-doc references: §2.3 (validator_update_fields), §2.4 / Rule K
 * (signed_at_block freshness + commission-increase epoch notice).
 *
 * Plan-deviation note: the Phase 7 plan sketch specified
 *   dnac_validator_update(ctx, new_commission_bps)
 * and had the builder internally query the witness's current block
 * height to fill in `signed_at_block`. No client-side RPC exists yet
 * for that query (that lands in Phase 14). We therefore expose
 * `signed_at_block` as an explicit parameter so CLI + Flutter can build
 * the TX in advance of the Phase 14 RPC. A future thin wrapper
 *   dnac_validator_update_auto(ctx, new_commission_bps)
 * will query the witness and call this builder — the builder signature
 * below is stable for the life of the protocol.
 *
 * This TX is fee-only (no non-change outputs); the validator record is
 * mutated by the witness at state-apply time (Phase 8 Task 44) after
 * Rule K freshness + increase-notice checks pass. The signer pubkey
 * must match an existing validator record (witness-side check).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/safe_math.h"

#include <dna/dna_engine.h>

#include "crypto/utils/qgp_log.h"
#include "nodus_init.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "DNAC_VALIDATOR_UPDATE"

/* ============================================================================
 * dnac_validator_update — build and broadcast a DNAC_TX_VALIDATOR_UPDATE
 * ========================================================================== */

int dnac_validator_update(dnac_context_t *ctx,
                          uint16_t new_commission_bps,
                          uint64_t signed_at_block,
                          dnac_callback_t callback,
                          void *user_data) {
    if (!ctx)                    return DNAC_ERROR_INVALID_PARAM;
    if (signed_at_block == 0)    return DNAC_ERROR_INVALID_PARAM;
    if (new_commission_bps > DNAC_COMMISSION_BPS_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "new_commission_bps out of range: %u",
                      new_commission_bps);
        return DNAC_ERROR_INVALID_PARAM;
    }

    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!owner_fp || !engine) return DNAC_ERROR_NOT_INITIALIZED;

    if (!nodus_messenger_wait_for_ready(5000)) {
        return DNAC_ERROR_NETWORK;
    }

    int rc;

    /* 1. Current fee. */
    uint64_t fee = 0;
    rc = dnac_get_current_fee(ctx, &fee);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_get_current_fee failed: %d", rc);
        return rc;
    }

    /* 2. Select native UTXOs to cover the fee. */
    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos_token(ctx, fee, NULL,
                                        &selected, &selected_count,
                                        &change_amount);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "UTXO selection failed: %d", rc);
        return rc;
    }

    uint64_t total_input = 0;
    for (int i = 0; i < selected_count; i++) {
        if (safe_add_u64(total_input, selected[i].amount, &total_input) != 0) {
            free(selected);
            return DNAC_ERROR_OVERFLOW;
        }
    }
    if (total_input < fee) {
        free(selected);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }
    change_amount = total_input - fee;

    /* 3. Construct TX. */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_VALIDATOR_UPDATE);
    if (!tx) {
        free(selected);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    /* 4. Inputs. */
    for (int i = 0; i < selected_count; i++) {
        rc = dnac_tx_add_input(tx, &selected[i]);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            dnac_free_transaction(tx);
            return rc;
        }
    }
    free(selected);
    selected = NULL;

    /* 5. Change output (native DNAC, caller) if any. */
    if (change_amount > 0) {
        uint8_t change_seed[32];
        rc = dnac_tx_add_output(tx, owner_fp, change_amount, change_seed);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            return rc;
        }
        /* token_id stays zeros (native) from calloc */
    }

    /* 6. Appended fields (design §2.3). */
    tx->validator_update_fields.new_commission_bps = new_commission_bps;
    tx->validator_update_fields.signed_at_block    = signed_at_block;

    /* 7. Chain_id binding (Task 14 / F-CRYPTO-10). */
    {
        const uint8_t *cid = dnac_get_chain_id(ctx);
        if (cid) memcpy(tx->chain_id, cid, 32);
    }

    /* 8. Signer: caller's Dilithium5 pubkey.
     *    Witness-side check: signer must match an existing validator record. */
    rc = dna_engine_get_signing_public_key(engine, tx->signers[0].pubkey,
                                           DNAC_PUBKEY_SIZE);
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }
    tx->signer_count = 1;
    tx->committed_fee = fee;   /* v0.17.1 — fee-only TX */

    /* 9. Compute preimage hash (binds validator_update_fields via Phase 5). */
    rc = dnac_tx_compute_hash(tx, tx->tx_hash);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    /* 10. Sign with caller's Dilithium5 secret key. */
    size_t sig_len = 0;
    rc = dna_engine_sign_data(engine,
                              tx->tx_hash, DNAC_TX_HASH_SIZE,
                              tx->signers[0].signature, &sig_len);
    if (rc != 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }

    /* 11. Broadcast. */
    rc = dnac_tx_broadcast(ctx, tx, callback, user_data);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    QGP_LOG_INFO(LOG_TAG,
                 "VALIDATOR_UPDATE submitted "
                 "(new_commission_bps=%u, signed_at_block=%llu, change=%llu)",
                 new_commission_bps,
                 (unsigned long long)signed_at_block,
                 (unsigned long long)change_amount);

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}
