/**
 * @file wallet.c
 * @brief DNAC wallet implementation (v1 transparent)
 */

#include "dnac/dnac.h"
#include "dnac/wallet.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/db.h"
#include "dnac/ledger.h"
#include <dna/dna_engine.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>

#include "nodus_ops.h"

/* Default database filename */
#define DNAC_DB_FILENAME "dnac.db"

struct dnac_context {
    dna_engine_t *dna_engine;           /* libdna engine */
    sqlite3 *db;                         /* SQLite database */
    char owner_fingerprint[129];         /* Owner's fingerprint */
    dnac_payment_cb_t payment_cb;
    void *payment_cb_data;
    size_t inbox_listen_token;           /* DHT listener token for inbox */
    int initialized;
};

/* ============================================================================
 * Lifecycle Functions
 * ========================================================================== */

dnac_context_t* dnac_init(void *dna_engine) {
    if (!dna_engine) return NULL;

    dna_engine_t *engine = (dna_engine_t *)dna_engine;

    /* Check if identity is loaded */
    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        fprintf(stderr, "DNAC: No identity loaded in DNA engine\n");
        return NULL;
    }

    dnac_context_t *ctx = calloc(1, sizeof(dnac_context_t));
    if (!ctx) return NULL;

    ctx->dna_engine = engine;
    strncpy(ctx->owner_fingerprint, fp, sizeof(ctx->owner_fingerprint) - 1);

    /* Open database in ~/.dna/ directory */
    /* For now, use current directory - TODO: get data_dir from engine */
    char db_path[512];
    const char *home = getenv("HOME");
    if (home) {
        snprintf(db_path, sizeof(db_path), "%s/.dna/%s", home, DNAC_DB_FILENAME);
    } else {
        snprintf(db_path, sizeof(db_path), "./%s", DNAC_DB_FILENAME);
    }

    int rc = sqlite3_open(db_path, &ctx->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "DNAC: Failed to open database: %s\n", sqlite3_errmsg(ctx->db));
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    /* Initialize schema */
    rc = dnac_db_init(ctx->db);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "DNAC: Failed to initialize database schema\n");
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    ctx->initialized = 1;
    return ctx;
}

void dnac_shutdown(dnac_context_t *ctx) {
    if (!ctx) return;

    /* Cancel inbox listener if active */
    if (ctx->inbox_listen_token != 0) {
        nodus_ops_cancel_listen(ctx->inbox_listen_token);
        ctx->inbox_listen_token = 0;
    }

    if (ctx->db) {
        sqlite3_close(ctx->db);
        ctx->db = NULL;
    }

    ctx->initialized = 0;
    free(ctx);
}

void dnac_set_payment_callback(dnac_context_t *ctx,
                               dnac_payment_cb_t callback,
                               void *user_data) {
    if (!ctx) return;
    ctx->payment_cb = callback;
    ctx->payment_cb_data = user_data;
}

/* ============================================================================
 * Inbox Listener Functions
 * ========================================================================== */

/* Forward declarations for inbox listener */
static int compute_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out);
static int build_inbox_key(const char *owner_fp, const uint8_t *chain_id, uint8_t *key_out);
static int derive_nullifier(const char *owner_fp, const uint8_t *seed, uint8_t *nullifier_out);
static bool utxo_exists(sqlite3 *db, const uint8_t *tx_hash, uint32_t output_index);

/**
 * DHT inbox listener callback - invoked when payments arrive
 */
static bool inbox_listener_callback(const uint8_t *value, size_t value_len,
                                    bool expired, void *user_data) {
    dnac_context_t *ctx = (dnac_context_t *)user_data;
    if (!ctx || !ctx->initialized) return false;
    if (expired || !value || value_len == 0) return true;

    /* Deserialize transaction */
    dnac_transaction_t *tx = NULL;
    int rc = dnac_tx_deserialize(value, value_len, &tx);
    if (rc != DNAC_SUCCESS || !tx) {
        return true;  /* Continue listening */
    }

    /* Verify transaction */
    rc = dnac_tx_verify(tx);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return true;
    }

    /* Extract outputs addressed to us */
    for (int j = 0; j < tx->output_count; j++) {
        if (strcmp(tx->outputs[j].owner_fingerprint, ctx->owner_fingerprint) != 0) {
            continue;
        }

        /* Check if UTXO already exists */
        if (utxo_exists(ctx->db, tx->tx_hash, (uint32_t)j)) {
            continue;
        }

        /* Create UTXO from output */
        dnac_utxo_t utxo = {0};
        utxo.version = tx->outputs[j].version;
        memcpy(utxo.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
        utxo.output_index = (uint32_t)j;
        utxo.amount = tx->outputs[j].amount;
        snprintf(utxo.owner_fingerprint, sizeof(utxo.owner_fingerprint),
                 "%s", ctx->owner_fingerprint);
        utxo.status = DNAC_UTXO_UNSPENT;
        utxo.received_at = (uint64_t)time(NULL);

        /* Derive nullifier from seed */
        if (derive_nullifier(ctx->owner_fingerprint,
                             tx->outputs[j].nullifier_seed,
                             utxo.nullifier) != 0) {
            continue;
        }

        /* Store UTXO in database */
        rc = dnac_db_store_utxo(ctx->db, &utxo);
        if (rc != DNAC_SUCCESS) {
            continue;
        }

        /* Fire payment callback if set */
        if (ctx->payment_cb) {
            ctx->payment_cb(&utxo, NULL, ctx->payment_cb_data);
        }
    }

    dnac_free_transaction(tx);
    return true;  /* Continue listening */
}

int dnac_start_listening(dnac_context_t *ctx) {
    if (!ctx || !ctx->initialized) return DNAC_ERROR_INVALID_PARAM;

    /* Already listening? */
    if (ctx->inbox_listen_token != 0) {
        return DNAC_SUCCESS;
    }

    /* Build inbox key */
    uint8_t inbox_key[64];
    if (build_inbox_key(ctx->owner_fingerprint, NULL, inbox_key) != 0) {
        return DNAC_ERROR_CRYPTO;
    }

    /* Start listening */
    size_t token = nodus_ops_listen(inbox_key, 64, inbox_listener_callback, ctx, NULL);
    if (token == 0) {
        return DNAC_ERROR_NETWORK;
    }

    ctx->inbox_listen_token = token;
    return DNAC_SUCCESS;
}

int dnac_stop_listening(dnac_context_t *ctx) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    if (ctx->inbox_listen_token == 0) {
        return DNAC_SUCCESS;  /* Not listening */
    }

    nodus_ops_cancel_listen(ctx->inbox_listen_token);
    ctx->inbox_listen_token = 0;
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Balance Functions
 * ========================================================================== */

int dnac_get_balance(dnac_context_t *ctx, dnac_balance_t *balance) {
    if (!ctx || !balance || !ctx->initialized) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    return dnac_wallet_calculate_balance(ctx, balance);
}

/* ============================================================================
 * UTXO Functions
 * ========================================================================== */

int dnac_get_utxos(dnac_context_t *ctx, dnac_utxo_t **utxos, int *count) {
    if (!ctx || !utxos || !count || !ctx->initialized) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    return dnac_db_get_unspent_utxos(ctx->db, ctx->owner_fingerprint, utxos, count);
}

void dnac_free_utxos(dnac_utxo_t *utxos, int count) {
    (void)count;
    free(utxos);
}

/**
 * Compute SHA3-512 hash of data
 */
static int compute_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, len) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash_out, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

/**
 * Build DHT key for payment inbox
 * Key: SHA3-512("dnac:inbox:" + owner_fingerprint)
 */
static int build_inbox_key(const char *owner_fp, const uint8_t *chain_id,
                            uint8_t *key_out) {
    uint8_t key_data[384];
    size_t offset = 0;

    const char *prefix = "dnac:inbox:";
    memcpy(key_data, prefix, strlen(prefix));
    offset = strlen(prefix);

    /* v0.10.0: Include chain_id hex in key for zone scoping */
    if (chain_id) {
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            key_data[offset++] = hex[(chain_id[i] >> 4) & 0xF];
            key_data[offset++] = hex[chain_id[i] & 0xF];
        }
        key_data[offset++] = ':';
    }

    size_t fp_len = strlen(owner_fp);
    memcpy(key_data + offset, owner_fp, fp_len);
    offset += fp_len;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Derive nullifier from seed and owner secret
 * nullifier = SHA3-512(owner_fingerprint || nullifier_seed)
 */
static int derive_nullifier(const char *owner_fp, const uint8_t *seed,
                            uint8_t *nullifier_out) {
    uint8_t data[256];
    size_t offset = 0;

    size_t fp_len = strlen(owner_fp);
    memcpy(data, owner_fp, fp_len);
    offset = fp_len;

    memcpy(data + offset, seed, 32);
    offset += 32;

    return compute_sha3_512(data, offset, nullifier_out);
}

/**
 * Check if UTXO already exists in database (by tx_hash + output_index)
 */
static bool utxo_exists(sqlite3 *db, const uint8_t *tx_hash, uint32_t output_index) {
    const char *sql = "SELECT 1 FROM dnac_utxos WHERE tx_hash = ? AND output_index = ? LIMIT 1";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)output_index);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return exists;
}

int dnac_sync_wallet(dnac_context_t *ctx) {
    if (!ctx || !ctx->initialized) return DNAC_ERROR_INVALID_PARAM;

    /* Step 1: Build inbox key */
    uint8_t inbox_key[64];
    if (build_inbox_key(ctx->owner_fingerprint, NULL, inbox_key) != 0) {
        return DNAC_ERROR_CRYPTO;
    }

    /* Step 2: Query DHT for all payments in our inbox */
    uint8_t **values = NULL;
    size_t *values_len = NULL;
    size_t count = 0;

    int rc = nodus_ops_get_all(inbox_key, 64, &values, &values_len, &count);
    if (rc != 0 || count == 0) {
        /* No payments or error - not fatal */
        fprintf(stderr, "[SYNC] No payments found (rc=%d, count=%zu)\n", rc, count);
        return DNAC_SUCCESS;
    }

    int new_payments = 0;

    /* Step 3: Process each payment */
    for (size_t i = 0; i < count; i++) {
        fprintf(stderr, "[SYNC] Processing value %zu: %zu bytes\n", i, values_len[i]);
        if (!values[i] || values_len[i] == 0) {
            fprintf(stderr, "[SYNC]   Skipping empty value\n");
            continue;
        }

        /* Deserialize transaction */
        dnac_transaction_t *tx = NULL;
        rc = dnac_tx_deserialize(values[i], values_len[i], &tx);
        if (rc != DNAC_SUCCESS || !tx) {
            fprintf(stderr, "[SYNC]   Deserialize FAILED: rc=%d\n", rc);
            continue;
        }
        fprintf(stderr, "[SYNC]   Deserialized TX: %d inputs, %d outputs\n", tx->input_count, tx->output_count);

        /* Verify transaction (optional - trust witnessed transactions) */
        rc = dnac_tx_verify(tx);
        if (rc != DNAC_SUCCESS) {
            fprintf(stderr, "[SYNC]   Verify FAILED: rc=%d\n", rc);
            dnac_free_transaction(tx);
            continue;
        }
        fprintf(stderr, "[SYNC]   TX verified OK\n");

        /* v0.9.0: Validate TX exists on current witness ledger.
         * Prevents storing stale UTXOs from old DHT data (previous deployments). */
        dnac_ledger_entry_t ledger_entry;
        rc = dnac_ledger_query_tx(ctx, tx->tx_hash, &ledger_entry, NULL);
        if (rc == DNAC_ERROR_NOT_FOUND) {
            fprintf(stderr, "[SYNC]   TX not in witness ledger, skipping (stale)\n");
            dnac_free_transaction(tx);
            continue;
        }
        if (rc != DNAC_SUCCESS) {
            fprintf(stderr, "[SYNC]   Ledger check failed (rc=%d), skipping\n", rc);
            dnac_free_transaction(tx);
            continue;
        }
        fprintf(stderr, "[SYNC]   TX confirmed in witness ledger (seq=%llu)\n",
                (unsigned long long)ledger_entry.sequence_number);

        /* Track if we stored any outputs from this transaction */
        bool stored_from_this_tx = false;
        uint64_t received_amount = 0;
        const char *sender_fp = NULL;

        /* Step 4: Extract outputs addressed to us */
        for (int j = 0; j < tx->output_count; j++) {
            fprintf(stderr, "[SYNC]   Output %d: owner=%.16s... amount=%llu\n",
                    j, tx->outputs[j].owner_fingerprint, (unsigned long long)tx->outputs[j].amount);
            /* Check if output is for us */
            if (strcmp(tx->outputs[j].owner_fingerprint, ctx->owner_fingerprint) != 0) {
                fprintf(stderr, "[SYNC]     Not for us, skipping\n");
                continue;
            }

            /* Check if UTXO already exists */
            if (utxo_exists(ctx->db, tx->tx_hash, (uint32_t)j)) {
                fprintf(stderr, "[SYNC]     Already exists, skipping\n");
                continue;
            }
            fprintf(stderr, "[SYNC]     NEW UTXO! Storing...\n");

            /* Create UTXO from output */
            dnac_utxo_t utxo = {0};
            utxo.version = tx->outputs[j].version;
            memcpy(utxo.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
            utxo.output_index = (uint32_t)j;
            utxo.amount = tx->outputs[j].amount;
            snprintf(utxo.owner_fingerprint, sizeof(utxo.owner_fingerprint),
                     "%s", ctx->owner_fingerprint);
            utxo.status = DNAC_UTXO_UNSPENT;
            utxo.received_at = (uint64_t)time(NULL);

            /* Derive nullifier from seed */
            if (derive_nullifier(ctx->owner_fingerprint,
                                 tx->outputs[j].nullifier_seed,
                                 utxo.nullifier) != 0) {
                continue;
            }

            /* Step 5: Store UTXO in database */
            rc = dnac_db_store_utxo(ctx->db, &utxo);
            if (rc != DNAC_SUCCESS) {
                continue;
            }

            /* Track for transaction history */
            stored_from_this_tx = true;
            received_amount += utxo.amount;

            new_payments++;

            /* Step 6: Call payment callback if set */
            if (ctx->payment_cb) {
                ctx->payment_cb(&utxo, NULL, ctx->payment_cb_data);
            }
        }

        /* Step 7: Store transaction in history if we received from it */
        if (stored_from_this_tx) {
            /* Find sender fingerprint from an output not addressed to us */
            for (int j = 0; j < tx->output_count && !sender_fp; j++) {
                if (strcmp(tx->outputs[j].owner_fingerprint, ctx->owner_fingerprint) != 0) {
                    sender_fp = tx->outputs[j].owner_fingerprint;
                }
            }

            /* Serialize transaction for storage */
            uint8_t tx_buffer[65536];
            size_t tx_len = 0;
            rc = dnac_tx_serialize(tx, tx_buffer, sizeof(tx_buffer), &tx_len);
            if (rc == DNAC_SUCCESS) {
                /* For received transactions: amount_in = received_amount, amount_out = 0, fee = 0 */
                dnac_db_store_transaction(ctx->db, tx->tx_hash, tx_buffer, tx_len,
                                          tx->type, sender_fp,
                                          received_amount, 0, 0);
            }
        }

        dnac_free_transaction(tx);
    }

    /* Free DHT results */
    for (size_t i = 0; i < count; i++) {
        free(values[i]);
    }
    free(values);
    free(values_len);

    return DNAC_SUCCESS;
}

int dnac_wallet_recover(dnac_context_t *ctx, int *recovered_count) {
    if (!ctx || !ctx->initialized) return DNAC_ERROR_INVALID_PARAM;

    /* Step 1: Clear existing UTXOs (fresh start) */
    int rc = dnac_db_clear_utxos(ctx->db, ctx->owner_fingerprint);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }

    /* Step 2: Build inbox key */
    uint8_t inbox_key[64];
    if (build_inbox_key(ctx->owner_fingerprint, NULL, inbox_key) != 0) {
        return DNAC_ERROR_CRYPTO;
    }

    /* Step 3: Query DHT for all payments in our inbox */
    uint8_t **values = NULL;
    size_t *values_len = NULL;
    size_t count = 0;

    rc = nodus_ops_get_all(inbox_key, 64, &values, &values_len, &count);
    if (rc != 0 || count == 0) {
        /* No payments or error - wallet is empty */
        if (recovered_count) *recovered_count = 0;
        return DNAC_SUCCESS;
    }

    int total_recovered = 0;

    /* Step 4: Process each payment */
    for (size_t i = 0; i < count; i++) {
        if (!values[i] || values_len[i] == 0) continue;

        /* Deserialize transaction */
        dnac_transaction_t *tx = NULL;
        rc = dnac_tx_deserialize(values[i], values_len[i], &tx);
        if (rc != DNAC_SUCCESS || !tx) {
            continue;
        }

        /* Verify transaction (optional - trust witnessed transactions) */
        rc = dnac_tx_verify(tx);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            continue;
        }

        /* Step 5: Extract outputs addressed to us */
        for (int j = 0; j < tx->output_count; j++) {
            /* Check if output is for us */
            if (strcmp(tx->outputs[j].owner_fingerprint, ctx->owner_fingerprint) != 0) {
                continue;
            }

            /* Create UTXO from output */
            dnac_utxo_t utxo = {0};
            utxo.version = tx->outputs[j].version;
            memcpy(utxo.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
            utxo.output_index = (uint32_t)j;
            utxo.amount = tx->outputs[j].amount;
            snprintf(utxo.owner_fingerprint, sizeof(utxo.owner_fingerprint),
                     "%s", ctx->owner_fingerprint);
            utxo.status = DNAC_UTXO_UNSPENT;
            utxo.received_at = (uint64_t)time(NULL);

            /* Derive nullifier from seed */
            if (derive_nullifier(ctx->owner_fingerprint,
                                 tx->outputs[j].nullifier_seed,
                                 utxo.nullifier) != 0) {
                continue;
            }

            /* Step 6: Store UTXO in database */
            rc = dnac_db_store_utxo(ctx->db, &utxo);
            if (rc != DNAC_SUCCESS) {
                continue;
            }

            total_recovered++;
        }

        dnac_free_transaction(tx);
    }

    /* Free DHT results */
    for (size_t i = 0; i < count; i++) {
        free(values[i]);
    }
    free(values);
    free(values_len);

    if (recovered_count) *recovered_count = total_recovered;
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Send Functions
 * ========================================================================== */

int dnac_send(dnac_context_t *ctx,
              const char *recipient_fingerprint,
              uint64_t amount,
              const char *memo,
              dnac_callback_t callback,
              void *user_data) {
    if (!ctx || !recipient_fingerprint || amount == 0 || !ctx->initialized) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    (void)memo;  /* TODO: Add memo to payment message in Phase 9 */

    int rc;

    /* Step 1: Create transaction builder */
    dnac_tx_builder_t *builder = dnac_tx_builder_create(ctx);
    if (!builder) {
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    /* Step 2: Add output */
    dnac_tx_output_t output = {0};
    strncpy(output.recipient_fingerprint, recipient_fingerprint,
            sizeof(output.recipient_fingerprint) - 1);
    output.amount = amount;
    if (memo) {
        strncpy(output.memo, memo, sizeof(output.memo) - 1);
    }

    rc = dnac_tx_builder_add_output(builder, &output);
    if (rc != DNAC_SUCCESS) {
        dnac_tx_builder_free(builder);
        return rc;
    }

    /* Step 3: Build transaction (selects UTXOs, signs) */
    dnac_transaction_t *tx = NULL;
    rc = dnac_tx_builder_build(builder, &tx);
    dnac_tx_builder_free(builder);

    if (rc != DNAC_SUCCESS) {
        return rc;
    }

    /* Step 4: Broadcast (gets witness signatures, sends via DHT) */
    rc = dnac_tx_broadcast(ctx, tx, callback, user_data);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}

int dnac_estimate_fee(dnac_context_t *ctx, uint64_t amount, uint64_t *fee_out) {
    if (!ctx || !fee_out) return DNAC_ERROR_INVALID_PARAM;

    /* Fee: 0.1% (10 basis points) */
    *fee_out = (amount * 10) / 10000;
    if (*fee_out < 1) *fee_out = 1; /* Minimum fee */

    return DNAC_SUCCESS;
}

/* ============================================================================
 * Context Accessors (for internal use)
 * ========================================================================== */

sqlite3* dnac_get_db(dnac_context_t *ctx) {
    return ctx ? ctx->db : NULL;
}

const char* dnac_get_owner_fingerprint(dnac_context_t *ctx) {
    return ctx ? ctx->owner_fingerprint : NULL;
}

dna_engine_t* dnac_get_engine(dnac_context_t *ctx) {
    return ctx ? ctx->dna_engine : NULL;
}

/* ============================================================================
 * Error Handling
 * ========================================================================== */

const char* dnac_error_string(int error) {
    switch (error) {
        case DNAC_SUCCESS: return "Success";
        case DNAC_ERROR_INVALID_PARAM: return "Invalid parameter";
        case DNAC_ERROR_OUT_OF_MEMORY: return "Out of memory";
        case DNAC_ERROR_NOT_INITIALIZED: return "Not initialized";
        case DNAC_ERROR_ALREADY_INITIALIZED: return "Already initialized";
        case DNAC_ERROR_DATABASE: return "Database error";
        case DNAC_ERROR_CRYPTO: return "Cryptographic error";
        case DNAC_ERROR_NETWORK: return "Network error";
        case DNAC_ERROR_INSUFFICIENT_FUNDS: return "Insufficient funds";
        case DNAC_ERROR_DOUBLE_SPEND: return "Double spend detected";
        case DNAC_ERROR_INVALID_PROOF: return "Invalid proof";
        case DNAC_ERROR_WITNESS_FAILED: return "Witness collection failed";
        case DNAC_ERROR_TIMEOUT: return "Operation timed out";
        case DNAC_ERROR_NOT_FOUND: return "Not found";
        default: return "Unknown error";
    }
}
