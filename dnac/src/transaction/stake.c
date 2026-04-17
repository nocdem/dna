/**
 * @file stake.c
 * @brief STAKE / UNSTAKE transaction builders (Phase 7, Task 34).
 *
 * Public API (see dnac.h):
 *   - dnac_stake()   — build + broadcast a DNAC_TX_STAKE
 *   - dnac_unstake() — build + broadcast a DNAC_TX_UNSTAKE
 *
 * Design-doc references: §2.3 (STAKE appended fields),
 * §2.4 / Rule I, Rule M (witness-side enforcement), Rule T (immutable
 * unstake_destination_fp), F-CRYPTO-05 (purpose-tag binding).
 *
 * Style note: these builders intentionally bypass `dnac_tx_builder_*`
 * because that path is SPEND-specific (output + 0.1% fee pattern, memo
 * flow, token-aware 2-pool UTXO selection). STAKE/UNSTAKE have fixed
 * token (native DNAC), flat fee, no memo, and per-type appended fields —
 * so we construct the TX directly, mirroring genesis.c / token_create.c.
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

#define LOG_TAG "DNAC_STAKE"

/**
 * @brief Convert a 128-char lowercase-hex fingerprint into its raw 64-byte hash.
 *
 * STAKE's wire field `unstake_destination_fp[64]` stores the raw digest
 * (not the hex string used elsewhere for UTXO ownership). Returns 0 on
 * success, -1 on malformed input.
 */
static int fp_hex_to_raw(const char *hex, uint8_t out[64]) {
    if (!hex || strlen(hex) != 128) return -1;
    for (int i = 0; i < 64; i++) {
        char h = hex[2 * i];
        char l = hex[2 * i + 1];
        int hi, lo;
        if      (h >= '0' && h <= '9') hi = h - '0';
        else if (h >= 'a' && h <= 'f') hi = h - 'a' + 10;
        else                           return -1;
        if      (l >= '0' && l <= '9') lo = l - '0';
        else if (l >= 'a' && l <= 'f') lo = l - 'a' + 10;
        else                           return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* ============================================================================
 * dnac_stake — build and broadcast a DNAC_TX_STAKE
 * ========================================================================== */

int dnac_stake(dnac_context_t *ctx,
               uint16_t commission_bps,
               const char *unstake_destination_fp,
               dnac_callback_t callback,
               void *user_data) {
    if (!ctx)                        return DNAC_ERROR_INVALID_PARAM;
    if (!unstake_destination_fp)     return DNAC_ERROR_INVALID_PARAM;
    if (commission_bps > DNAC_COMMISSION_BPS_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "commission_bps out of range: %u", commission_bps);
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Convert & validate destination fp up front. */
    uint8_t dest_fp_raw[DNAC_STAKE_UNSTAKE_DEST_FP_SIZE];
    if (fp_hex_to_raw(unstake_destination_fp, dest_fp_raw) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "invalid unstake_destination_fp (128-hex expected)");
        return DNAC_ERROR_INVALID_PARAM;
    }

    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!owner_fp || !engine) return DNAC_ERROR_NOT_INITIALIZED;

    if (!nodus_messenger_wait_for_ready(5000)) {
        return DNAC_ERROR_NETWORK;
    }

    int rc;

    /* 1. Query current dynamic fee from witness. */
    uint64_t fee = 0;
    rc = dnac_get_current_fee(ctx, &fee);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_get_current_fee failed: %d", rc);
        return rc;
    }

    /* 2. Select native DNAC UTXOs to cover 10M + fee. */
    uint64_t need = 0;
    if (safe_add_u64(DNAC_SELF_STAKE_AMOUNT, fee, &need) != 0) {
        return DNAC_ERROR_OVERFLOW;
    }

    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos_token(ctx, need, NULL,
                                        &selected, &selected_count, &change_amount);
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
    if (total_input < need) {
        free(selected);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }
    change_amount = total_input - need;

    /* 3. Construct TX. */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_STAKE);
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
    tx->stake_fields.commission_bps = commission_bps;
    memcpy(tx->stake_fields.unstake_destination_fp, dest_fp_raw,
           DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);

    /* 7. Bind chain_id into preimage (Task 14 / F-CRYPTO-10). */
    {
        const uint8_t *cid = dnac_get_chain_id(ctx);
        if (cid) memcpy(tx->chain_id, cid, 32);
    }

    /* 8. Signer: caller's Dilithium5 pubkey. */
    rc = dna_engine_get_signing_public_key(engine, tx->signers[0].pubkey,
                                           DNAC_PUBKEY_SIZE);
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }
    tx->signer_count = 1;

    /* 9. Compute preimage hash (now binds stake_fields + purpose tag). */
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

    /* 11. Broadcast via the shared witness path. */
    rc = dnac_tx_broadcast(ctx, tx, callback, user_data);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    QGP_LOG_INFO(LOG_TAG,
                 "STAKE submitted (commission_bps=%u, change=%llu)",
                 commission_bps,
                 (unsigned long long)change_amount);

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * dnac_unstake — build and broadcast a DNAC_TX_UNSTAKE
 * ========================================================================== */

int dnac_unstake(dnac_context_t *ctx,
                 dnac_callback_t callback,
                 void *user_data) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

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
    if (rc != DNAC_SUCCESS) return rc;

    /* 2. Select native UTXOs to cover just the fee. */
    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos_token(ctx, fee, NULL,
                                        &selected, &selected_count, &change_amount);
    if (rc != DNAC_SUCCESS) return rc;

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
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_UNSTAKE);
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

    /* 5. Change output (native DNAC) if any. */
    if (change_amount > 0) {
        uint8_t change_seed[32];
        rc = dnac_tx_add_output(tx, owner_fp, change_amount, change_seed);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            return rc;
        }
    }

    /* 6. UNSTAKE has no appended fields — skip. */

    /* 7. Chain_id binding. */
    {
        const uint8_t *cid = dnac_get_chain_id(ctx);
        if (cid) memcpy(tx->chain_id, cid, 32);
    }

    /* 8. Signer. */
    rc = dna_engine_get_signing_public_key(engine, tx->signers[0].pubkey,
                                           DNAC_PUBKEY_SIZE);
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }
    tx->signer_count = 1;

    /* 9. Hash. */
    rc = dnac_tx_compute_hash(tx, tx->tx_hash);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    /* 10. Sign. */
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

    QGP_LOG_INFO(LOG_TAG, "UNSTAKE submitted");

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}
