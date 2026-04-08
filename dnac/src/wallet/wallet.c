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
#include "dnac/commitment.h"
#include <dna/dna_engine.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"
#include "dnac/crypto_helpers.h"

#define LOG_TAG "DNAC_WALLET"

/* Default database filename */
#define DNAC_DB_FILENAME "dnac.db"

struct dnac_context {
    dna_engine_t *dna_engine;           /* libdna engine */
    sqlite3 *db;                         /* SQLite database */
    char owner_fingerprint[129];         /* Owner's fingerprint */
    dnac_payment_cb_t payment_cb;
    void *payment_cb_data;
    uint8_t chain_id[32];               /* Chain ID from witness */
    bool chain_id_loaded;               /* Whether chain_id has been fetched */
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
        QGP_LOG_ERROR(LOG_TAG, "No identity loaded in DNA engine");
        return NULL;
    }

    dnac_context_t *ctx = calloc(1, sizeof(dnac_context_t));
    if (!ctx) return NULL;

    ctx->dna_engine = engine;
    strncpy(ctx->owner_fingerprint, fp, sizeof(ctx->owner_fingerprint) - 1);

    /* Open database in engine's data directory (works on all platforms) */
    char db_path[512];
    const char *data_dir = dna_engine_get_data_dir(engine);
    if (data_dir) {
        snprintf(db_path, sizeof(db_path), "%s/%s", data_dir, DNAC_DB_FILENAME);
    } else {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(db_path, sizeof(db_path), "%s/.dna/%s", home, DNAC_DB_FILENAME);
        } else {
            snprintf(db_path, sizeof(db_path), "./%s", DNAC_DB_FILENAME);
        }
    }

    int rc = sqlite3_open(db_path, &ctx->db);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s", sqlite3_errmsg(ctx->db));
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    /* Initialize schema */
    rc = dnac_db_init(ctx->db);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize database schema");
        sqlite3_close(ctx->db);
        free(ctx);
        return NULL;
    }

    ctx->initialized = 1;
    return ctx;
}

void dnac_shutdown(dnac_context_t *ctx) {
    if (!ctx) return;

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
 * Chain ID (fetched from witness on first use)
 * ========================================================================== */

void dnac_set_chain_id(dnac_context_t *ctx, const uint8_t *chain_id) {
    if (!ctx || !chain_id) return;
    memcpy(ctx->chain_id, chain_id, 32);
    ctx->chain_id_loaded = true;
}

const uint8_t *dnac_get_chain_id(dnac_context_t *ctx) {
    if (!ctx) return NULL;

    if (!ctx->chain_id_loaded) {
        /* Fetch chain_id from witness via dnac_supply */
        uint64_t genesis_supply = 0;
        int rc = dnac_ledger_get_supply(ctx, &genesis_supply, NULL, NULL);
        (void)rc;
    }

    /* Return NULL if chain_id is all-zero (pre-genesis) */
    static const uint8_t zero[32] = {0};
    if (memcmp(ctx->chain_id, zero, 32) == 0)
        return NULL;

    return ctx->chain_id;
}

/* ============================================================================
 * Listener Functions (no-op: witness-based polling replaces DHT listener)
 * ========================================================================== */

int dnac_start_listening(dnac_context_t *ctx) {
    (void)ctx;
    return DNAC_SUCCESS;
}

int dnac_stop_listening(dnac_context_t *ctx) {
    (void)ctx;
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

    return qgp_sha3_512(data, offset, nullifier_out);
}

int dnac_sync_wallet(dnac_context_t *ctx) {
    if (!ctx || !ctx->initialized) return DNAC_ERROR_INVALID_PARAM;

    /* Clear existing UTXOs (fresh start from authoritative source) */
    int rc = dnac_db_clear_utxos(ctx->db, ctx->owner_fingerprint);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "sync: failed to clear local UTXOs: %d", rc);
        return rc;
    }

    /* Recover UTXO state from witnesses (authoritative source) */
    int witness_recovered = 0;
    uint64_t witness_total = 0;
    rc = dnac_wallet_recover_from_witnesses(ctx, &witness_recovered, &witness_total);
    if (rc == DNAC_SUCCESS && witness_recovered > 0) {
        QGP_LOG_INFO(LOG_TAG, "sync: recovered %d UTXOs from witnesses (total: %llu)",
                     witness_recovered, (unsigned long long)witness_total);
    }

    return rc;
}

int dnac_wallet_recover(dnac_context_t *ctx, int *recovered_count) {
    if (!ctx || !ctx->initialized) return DNAC_ERROR_INVALID_PARAM;

    /* recover is now just sync (which clears + rebuilds from authoritative sources) */
    int rc = dnac_sync_wallet(ctx);
    if (recovered_count) *recovered_count = 0;
    return rc;
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

    /* Validate fingerprint: must be exactly 128 lowercase hex characters */
    size_t fp_len = strlen(recipient_fingerprint);
    if (fp_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "invalid recipient fingerprint length: %zu (expected 128)", fp_len);
        return DNAC_ERROR_INVALID_PARAM;
    }
    for (size_t i = 0; i < 128; i++) {
        char c = recipient_fingerprint[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            QGP_LOG_ERROR(LOG_TAG, "invalid character '%c' at position %zu in fingerprint", c, i);
            return DNAC_ERROR_INVALID_PARAM;
        }
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

    /* Fee: 0.1% (10 basis points)
     * Use amount/1000 instead of (amount*10)/10000 to avoid overflow.
     * For amounts < 1000, this gives 0, so min_fee=1 applies. */
    *fee_out = amount / 1000;
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
        case DNAC_ERROR_OVERFLOW: return "Integer overflow in amount";
        default: return "Unknown error";
    }
}
