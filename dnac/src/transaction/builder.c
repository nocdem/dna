/**
 * @file builder.c
 * @brief Transaction builder (v1 transparent)
 *
 * Builds transactions by:
 * 1. Collecting output specifications
 * 2. Selecting UTXOs to cover amount + fee
 * 3. Adding inputs from selected UTXOs
 * 4. Adding outputs (including change)
 * 5. Signing with sender's Dilithium5 key
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include <dna/dna_engine.h>
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <openssl/evp.h>

#include "nodus_init.h"
#include "dnac/safe_math.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"
#include "dnac/crypto_helpers.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "DNAC_BUILDER"

/* Check if token_id is all zeros (native DNAC) */
static bool is_native_token(const uint8_t *token_id) {
    for (int i = 0; i < DNAC_TOKEN_ID_SIZE; i++) {
        if (token_id[i] != 0) return false;
    }
    return true;
}

struct dnac_tx_builder {
    dnac_context_t *ctx;
    dnac_transaction_t *tx;
    dnac_tx_output_t outputs[DNAC_TX_MAX_OUTPUTS];
    int output_count;
    uint64_t total_output_amount;
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];  /* Token to send (zeros = native DNAC) */
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

    builder->output_count = 0;
    builder->total_output_amount = 0;

    return builder;
}

int dnac_tx_builder_add_output(dnac_tx_builder_t *builder,
                               const dnac_tx_output_t *output) {
    if (!builder || !output) return DNAC_ERROR_INVALID_PARAM;
    if (builder->output_count >= DNAC_TX_MAX_OUTPUTS) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (output->amount == 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    builder->outputs[builder->output_count++] = *output;
    if (safe_add_u64(builder->total_output_amount, output->amount,
                     &builder->total_output_amount) != 0) {
        builder->output_count--;
        return DNAC_ERROR_OVERFLOW;
    }

    return DNAC_SUCCESS;
}

int dnac_tx_builder_set_token(dnac_tx_builder_t *builder,
                               const uint8_t *token_id) {
    if (!builder || !token_id) return DNAC_ERROR_INVALID_PARAM;
    memcpy(builder->token_id, token_id, DNAC_TOKEN_ID_SIZE);
    return DNAC_SUCCESS;
}

int dnac_tx_builder_build(dnac_tx_builder_t *builder,
                          dnac_transaction_t **tx_out) {
    if (!builder || !tx_out) return DNAC_ERROR_INVALID_PARAM;
    if (builder->output_count == 0) return DNAC_ERROR_INVALID_PARAM;

    int rc;
    *tx_out = NULL;

    /* Estimate fee for initial UTXO selection */
    uint64_t fee = 0;
    rc = dnac_estimate_fee(builder->ctx, builder->total_output_amount, &fee);
    if (rc != DNAC_SUCCESS) return rc;

    uint64_t total_needed = 0;
    if (safe_add_u64(builder->total_output_amount, fee, &total_needed) != 0) {
        return DNAC_ERROR_OVERFLOW;
    }

    /* Select UTXOs */
    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos_token(builder->ctx, total_needed,
                                        builder->token_id,
                                        &selected, &selected_count, &change_amount);
    if (rc != DNAC_SUCCESS) return rc;

    /* Calculate fee based on send amount (0.1% of transfer, not input).
     * H-17: Aligned with witness — both use send_amount / 1000 (0.1%), min 1.
     */
    uint64_t total_input = 0;
    for (int i = 0; i < selected_count; i++) {
        if (safe_add_u64(total_input, selected[i].amount, &total_input) != 0) {
            free(selected);
            return DNAC_ERROR_OVERFLOW;
        }
    }
    fee = builder->total_output_amount / 1000;
    if (fee < 1) fee = 1;

    uint64_t output_plus_fee;
    if (safe_add_u64(builder->total_output_amount, fee, &output_plus_fee) != 0) {
        free(selected);
        return DNAC_ERROR_OVERFLOW;
    }
    if (output_plus_fee > total_input) {
        free(selected);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }
    change_amount = total_input - builder->total_output_amount - fee;
    if (rc != DNAC_SUCCESS) return rc;

    /* Add inputs from selected UTXOs */
    for (int i = 0; i < selected_count; i++) {
        rc = dnac_tx_add_input(builder->tx, &selected[i]);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            return rc;
        }
    }

    /* Add outputs (Gap 25: v0.6.0 - includes memo) */
    for (int i = 0; i < builder->output_count; i++) {
        uint8_t nullifier_seed[32];
        uint8_t memo_len = (uint8_t)strnlen(builder->outputs[i].memo, DNAC_MEMO_MAX_SIZE);
        rc = dnac_tx_add_output_with_memo(builder->tx,
                                           builder->outputs[i].recipient_fingerprint,
                                           builder->outputs[i].amount,
                                           nullifier_seed,
                                           memo_len > 0 ? builder->outputs[i].memo : NULL,
                                           memo_len);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            return rc;
        }
        /* Set token_id on the just-added output */
        memcpy(builder->tx->outputs[builder->tx->output_count - 1].token_id,
               builder->token_id, DNAC_TOKEN_ID_SIZE);
    }

    /* Add change output if needed */
    if (change_amount > 0) {
        const char *owner_fp = dnac_get_owner_fingerprint(builder->ctx);
        if (!owner_fp) {
            free(selected);
            return DNAC_ERROR_NOT_INITIALIZED;
        }

        uint8_t change_seed[32];
        rc = dnac_tx_add_output(builder->tx, owner_fp, change_amount, change_seed);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            return rc;
        }
        /* Set token_id on change output */
        memcpy(builder->tx->outputs[builder->tx->output_count - 1].token_id,
               builder->token_id, DNAC_TOKEN_ID_SIZE);
    }

    /* v0.8.0: Fees are burned (removed from circulation).
     * sum(inputs) > sum(outputs), the difference is the fee.
     * Fee pool + staking distribution planned for future version. */

    free(selected);

    /* Get sender's public key */
    dna_engine_t *engine = dnac_get_engine(builder->ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    rc = dna_engine_get_signing_public_key(engine, sender_pubkey, sizeof(sender_pubkey));
    if (rc < 0) {  /* Returns size on success, negative on error */
        return DNAC_ERROR_CRYPTO;
    }

    /* Copy public key BEFORE hash (sender_pubkey is part of tx_hash) */
    memcpy(builder->tx->signers[0].pubkey, sender_pubkey, DNAC_PUBKEY_SIZE);
    builder->tx->signer_count = 1;

    /* Compute transaction hash (includes sender_pubkey) */
    rc = dnac_tx_compute_hash(builder->tx, builder->tx->tx_hash);
    if (rc != DNAC_SUCCESS) return rc;

    /* Sign transaction hash with Dilithium5 */
    size_t sig_len = 0;
    rc = dna_engine_sign_data(engine,
                               builder->tx->tx_hash,
                               DNAC_TX_HASH_SIZE,
                               builder->tx->signers[0].signature,
                               &sig_len);
    if (rc != 0) {
        return DNAC_ERROR_CRYPTO;
    }

    /* Transfer ownership */
    *tx_out = builder->tx;
    builder->tx = NULL;  /* Prevent double-free */

    return DNAC_SUCCESS;
}


int dnac_tx_broadcast(dnac_context_t *ctx,
                      dnac_transaction_t *tx,
                      dnac_callback_t callback,
                      void *user_data) {
    if (!ctx || !tx) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    int rc;
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    if (!owner_fp) return DNAC_ERROR_NOT_INITIALIZED;

    if (!nodus_messenger_wait_for_ready(5000)) {
        return DNAC_ERROR_NETWORK;
    }

    /* Step 1: Create SpendRequest with full serialized transaction
     * v0.4.0: Send full TX instead of single nullifier to enable
     * witnesses to extract and verify ALL input nullifiers.
     */
    dnac_spend_request_t request = {0};
    memcpy(request.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
    memcpy(request.sender_pubkey, tx->signers[0].pubkey, DNAC_PUBKEY_SIZE);
    memcpy(request.signature, tx->signers[0].signature, DNAC_SIGNATURE_SIZE);
    request.timestamp = (uint64_t)time(NULL);

    /* Serialize full transaction into request */
    size_t tx_serialized_len = 0;
    rc = dnac_tx_serialize(tx, request.tx_data, sizeof(request.tx_data), &tx_serialized_len);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }
    request.tx_len = (uint32_t)tx_serialized_len;

    /* Declare actual fee (inputs - outputs) to match witness verification */
    uint64_t total_output = dnac_tx_total_output(tx);
    uint64_t total_input_val = dnac_tx_total_input(tx);
    request.fee_amount = total_input_val - total_output;

    /* Step 2: Store pending spend in database */
    uint64_t expires_at = request.timestamp + 300;  /* 5 minute expiry */
    for (int i = 0; i < tx->input_count; i++) {
        rc = dnac_db_store_pending_spend(db, tx->tx_hash,
                                          tx->inputs[i].nullifier,
                                          DNAC_WITNESSES_REQUIRED, expires_at);
        if (rc != DNAC_SUCCESS) {
            /* Non-fatal, continue */
        }
    }

    /* Step 2b (Fix #4 B): persist serialized TX + send parameters so a
     * retry of dnac_send (e.g. after a witness request timeout) can
     * locate and re-broadcast the exact same tx_hash via
     * dnac_db_find_active_broadcast(), instead of rebuilding a fresh
     * TX with a new timestamp/nullifier_seed (which would collide on
     * committed nullifiers and hit DOUBLE_SPEND). */
    {
        /* Identify the primary (non-change) recipient + amount for the
         * lookup key. Change outputs to ourselves are skipped. */
        const char *send_recipient = NULL;
        uint64_t send_amount = 0;
        for (int i = 0; i < tx->output_count; i++) {
            if (strcmp(tx->outputs[i].owner_fingerprint, owner_fp) != 0) {
                send_recipient = tx->outputs[i].owner_fingerprint;
                send_amount = tx->outputs[i].amount;
                break;
            }
        }
        if (send_recipient) {
            /* request.tx_data already holds the canonical serialized TX
             * (populated in Step 1 above). Reuse it verbatim. */
            int prc = dnac_db_store_pending_broadcast(
                db, tx->tx_hash,
                request.tx_data, request.tx_len,
                send_recipient, send_amount,
                tx->outputs[0].token_id,
                expires_at);
            if (prc != DNAC_SUCCESS) {
                /* Non-fatal — we'll just miss the retry optimization. */
                QGP_LOG_WARN(LOG_TAG,
                             "Pending broadcast persist failed: %d", prc);
            }
        }
    }

    /* Step 3: Request witness signatures */
    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES];
    int witness_count = 0;

    rc = dnac_witness_request(ctx, &request, witnesses, &witness_count);

    /* Fix #4 B: on timeout, the TX may or may not have been committed
     * before the response was lost. Probe via dnac_witness_replay to
     * recover a fresh spndrslt receipt bound to the committed (block,
     * tx_index). If recovered, treat as success and fall through to
     * the witness-verify + local-state-update path. */
    if (rc == DNAC_ERROR_TIMEOUT) {
        struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
        nanosleep(&ts, NULL);

        dnac_witness_sig_t replayed;
        int replay_rc = dnac_witness_replay(ctx, tx->tx_hash, &replayed);
        if (replay_rc == DNAC_SUCCESS) {
            QGP_LOG_WARN(LOG_TAG,
                "dnac_spend timed out but replay recovered a committed "
                "receipt (block=%llu, tx_index=%u) — treating as success",
                (unsigned long long)replayed.block_height,
                replayed.tx_index);
            witnesses[0] = replayed;
            witness_count = 1;
            rc = DNAC_SUCCESS;
        }
        /* else: genuinely timed out, TX is not in ledger — fall through
         * to the error branch below. */
    }

    /* BFT mode: 1 attestation proves consensus (quorum agreement happened internally) */
    if (rc != DNAC_SUCCESS || witness_count < 1) {
        /* Fix #4 B: on DOUBLE_SPEND, the nullifiers are committed but we
         * don't know if OUR tx_hash is the committing one. Call
         * dnac_witness_replay with our tx_hash — if it matches a
         * committed TX, we are the committer (this is the "retry of
         * cached pending broadcast" path) and should recover the
         * receipt instead of reporting failure. Otherwise, it's a
         * genuine double-spend from a different TX. */
        if (rc == DNAC_ERROR_DOUBLE_SPEND) {
            dnac_witness_sig_t replayed;
            int replay_rc = dnac_witness_replay(ctx, tx->tx_hash, &replayed);
            if (replay_rc == DNAC_SUCCESS) {
                QGP_LOG_WARN(LOG_TAG,
                    "DOUBLE_SPEND on our tx_hash — recovered via replay "
                    "(block=%llu, tx_index=%u), treating as success",
                    (unsigned long long)replayed.block_height,
                    replayed.tx_index);
                witnesses[0] = replayed;
                witness_count = 1;
                rc = DNAC_SUCCESS;
                goto receipt_ok;  /* Fall into Step 4 below */
            }
        }

        /* Mark pending spends as failed */
        dnac_db_expire_pending_spends(db);

        /* Genuine double-spend: different TX already committed these
         * nullifiers. Mark input UTXOs as spent locally so wallet state
         * stays in sync (real committed tx_hash is unknown from here;
         * next sync will reconcile from the ledger). */
        if (rc == DNAC_ERROR_DOUBLE_SPEND) {
            for (int i = 0; i < tx->input_count; i++) {
                dnac_db_mark_utxo_spent(db, tx->inputs[i].nullifier,
                                         tx->tx_hash);
            }
        }

        /* Propagate the specific error (double-spend, timeout, etc.)
         * instead of masking it as generic witness failure. */
        return (rc != DNAC_SUCCESS) ? rc : DNAC_ERROR_WITNESS_FAILED;
    }
receipt_ok:;

    /* Step 4: Verify and add witnesses to transaction.
     *
     * Phase 12 / Task 12.2 — witness now signs the 221-byte spndrslt
     * preimage with all eight bound fields. Reconstruct the same
     * preimage on the client side for verification:
     *
     *   [0..7]      'spndrslt' tag
     *   [8..71]     tx_hash
     *   [72..103]   witness_id
     *   [104..167]  SHA3-512(witness_pubkey)
     *   [168..199]  chain_id (from receipt)
     *   [200..207]  timestamp (LE)
     *   [208..215]  block_height (LE)
     *   [216..219]  tx_index (LE)
     *   [220]       status (0 = APPROVED) */
    static const uint8_t spend_tag[8] = { 's','p','n','d','r','s','l','t' };
    for (int i = 0; i < witness_count; i++) {
        uint8_t preimage[221];
        memset(preimage, 0, sizeof(preimage));

        memcpy(preimage,        spend_tag, 8);
        memcpy(preimage + 8,    tx->tx_hash, DNAC_TX_HASH_SIZE);
        memcpy(preimage + 72,   witnesses[i].witness_id, 32);

        /* SHA3-512 over the wire-supplied server pubkey */
        uint8_t wpk_hash[64];
        qgp_sha3_512(witnesses[i].server_pubkey, DNAC_PUBKEY_SIZE, wpk_hash);
        memcpy(preimage + 104, wpk_hash, 64);

        memcpy(preimage + 168, witnesses[i].chain_id, 32);

        for (int j = 0; j < 8; j++)
            preimage[200 + j] = (uint8_t)((witnesses[i].timestamp >> (j * 8)) & 0xFF);
        for (int j = 0; j < 8; j++)
            preimage[208 + j] = (uint8_t)((witnesses[i].block_height >> (j * 8)) & 0xFF);
        for (int j = 0; j < 4; j++)
            preimage[216 + j] = (uint8_t)((witnesses[i].tx_index >> (j * 8)) & 0xFF);
        preimage[220] = 0;  /* APPROVED */

        if (qgp_dsa87_verify(witnesses[i].signature, DNAC_SIGNATURE_SIZE,
                              preimage, sizeof(preimage),
                              witnesses[i].server_pubkey) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Witness %d signature verification failed", i);
            return DNAC_ERROR_WITNESS_FAILED;
        }

        rc = dnac_tx_add_witness(tx, &witnesses[i]);
        if (rc != DNAC_SUCCESS) return rc;
    }

    /* Phase 13 / Task 13.4 — stash the receipt on the context so the
     * CLI / Flutter caller can display block_height + tx_index after
     * the send completes. Use the first witness (BFT mode = 1
     * attestation == quorum). */
    if (witness_count > 0) {
        dnac_set_last_receipt(ctx, witnesses[0].block_height,
                                witnesses[0].tx_index, tx->tx_hash);
    }

    /* Step 5: Serialize transaction */
    uint8_t *tx_buffer = malloc(65536);
    if (!tx_buffer) return DNAC_ERROR_OUT_OF_MEMORY;
    size_t tx_len = 0;
    rc = dnac_tx_serialize(tx, tx_buffer, 65536, &tx_len);
    if (rc != DNAC_SUCCESS) {
        free(tx_buffer);
        return rc;
    }

    /* Wrap local DB updates in a transaction for crash consistency */
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    /* Step 6: Store change outputs locally */
    for (int i = 0; i < tx->output_count; i++) {
        /* Only process change outputs (to ourselves) */
        if (strcmp(tx->outputs[i].owner_fingerprint, owner_fp) != 0) {
            continue;
        }

        dnac_utxo_t utxo = {0};
        utxo.version = tx->outputs[i].version;
        memcpy(utxo.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
        utxo.output_index = (uint32_t)i;
        utxo.amount = tx->outputs[i].amount;
        memcpy(utxo.token_id, tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE);
        strncpy(utxo.owner_fingerprint, owner_fp, sizeof(utxo.owner_fingerprint) - 1);
        utxo.status = DNAC_UTXO_UNSPENT;
        utxo.received_at = (uint64_t)time(NULL);

        /* Derive nullifier from owner fingerprint and seed */
        uint8_t nullifier_data[256];
        size_t fp_len = strlen(owner_fp);
        memcpy(nullifier_data, owner_fp, fp_len);
        memcpy(nullifier_data + fp_len, tx->outputs[i].nullifier_seed, 32);
        if (qgp_sha3_512(nullifier_data, fp_len + 32, utxo.nullifier) == 0) {
            rc = dnac_db_store_utxo(db, &utxo);
        }
    }

    /* Step 7: Mark input UTXOs as spent */
    for (int i = 0; i < tx->input_count; i++) {
        rc = dnac_db_mark_utxo_spent(db, tx->inputs[i].nullifier, tx->tx_hash);
        if (rc != DNAC_SUCCESS) {
            /* Non-fatal, UTXO will be marked spent on next sync */
        }
    }

    /* Step 8: Store transaction in history */
    uint64_t total_input = dnac_tx_total_input(tx);

    /* v0.8.0: Fees are burned. Fee = sum(inputs) - sum(outputs). */
    uint64_t fee = total_input - total_output;

    /* Find first non-change recipient for counterparty field */
    const char *counterparty = NULL;
    for (int i = 0; i < tx->output_count; i++) {
        if (strcmp(tx->outputs[i].owner_fingerprint, owner_fp) != 0) {
            counterparty = tx->outputs[i].owner_fingerprint;
            break;
        }
    }

    rc = dnac_db_store_transaction(db, tx->tx_hash, tx_buffer, tx_len,
                                    tx->type, counterparty,
                                    total_input, total_output, fee);
    if (rc != DNAC_SUCCESS) {
        /* Non-fatal */
    }

    /* Step 9: Mark pending spends as complete */
    rc = dnac_db_complete_pending_spend(db, tx->tx_hash);
    if (rc != DNAC_SUCCESS) {
        /* Non-fatal */
    }

    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

    /* Call completion callback if provided */
    if (callback) {
        callback(DNAC_SUCCESS, NULL, user_data);
    }

    free(tx_buffer);
    return DNAC_SUCCESS;
}

void dnac_tx_builder_free(dnac_tx_builder_t *builder) {
    if (!builder) return;
    if (builder->tx) dnac_free_transaction(builder->tx);
    free(builder);
}
