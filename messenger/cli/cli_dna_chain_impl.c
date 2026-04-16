/**
 * @file cli_dna_chain_impl.c
 * @brief Implementations for the `dna-connect-cli dna ...` subcommand group.
 *
 * Originally lived at dnac/src/cli/commands.c, moved into messenger/cli/
 * so the messenger build no longer reaches across project boundaries to
 * pick up source from the dnac tree. Functions are still named
 * dna_chain_cmd_* for now; the dispatcher in cli_dna_chain.c calls them
 * directly.
 */

#include "cli_dna_chain_helpers.h"
#include "dnac/dnac.h"
#include "dnac/wallet.h"
#include "dnac/transaction.h"
#include "dnac/genesis.h"
#include "dnac/crypto_helpers.h"
#include "dnac/trusted_state.h"
#include "dnac/version.h"
#include <dna/dna_engine.h>
#include "nodus_ops.h"
#include <nodus/nodus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <errno.h>
#include <strings.h>
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * Format amount for display (with decimal point).
 *
 * Phase 11 refactor: decimals come from the current trusted state
 * (set by wallet init after dnac_genesis_verify). Falls back to 8
 * when trust is uninitialized so early-boot callers keep working.
 */
static void format_amount_decimals(uint64_t amount, uint8_t decimals,
                                    char *buf, size_t buf_len) {
    if (decimals == 0) {
        snprintf(buf, buf_len, "%" PRIu64, amount);
        return;
    }
    uint64_t divisor = 1;
    for (uint8_t i = 0; i < decimals; i++) divisor *= 10;
    uint64_t whole = amount / divisor;
    uint64_t frac = amount % divisor;
    if (frac == 0) {
        snprintf(buf, buf_len, "%" PRIu64, whole);
    } else {
        snprintf(buf, buf_len, "%" PRIu64 ".%0*" PRIu64, whole, decimals, frac);
        size_t len = strlen(buf);
        while (len > 0 && buf[len - 1] == '0') buf[--len] = '\0';
    }
}

/** Format a native-token amount using the chain's trusted decimals. */
static void format_amount(uint64_t amount, char *buf, size_t buf_len) {
    format_amount_decimals(amount, dnac_current_token_decimals(), buf, buf_len);
}

/**
 * Format timestamp for display
 */
static void format_timestamp(uint64_t ts, char *buf, size_t buf_len) {
    time_t t = (time_t)ts;
    struct tm *tm = localtime(&t);
    strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S", tm);
}

/**
 * Convert hex string to bytes
 */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;

    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/* ============================================================================
 * Command Implementations
 * ========================================================================== */

int dna_chain_cmd_balance(dnac_context_t *ctx) {
    dnac_balance_t balance;
    int rc = dnac_get_balance(ctx, &balance);

    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    char confirmed_str[64], pending_str[64], locked_str[64];
    format_amount(balance.confirmed, confirmed_str, sizeof(confirmed_str));
    format_amount(balance.pending, pending_str, sizeof(pending_str));
    format_amount(balance.locked, locked_str, sizeof(locked_str));

    printf("DNAC Wallet Balance\n");
    printf("-------------------\n");
    printf("Confirmed:  %s\n", confirmed_str);
    printf("Pending:    %s\n", pending_str);
    printf("Locked:     %s\n", locked_str);
    printf("UTXOs:      %d\n", balance.utxo_count);

    /* Show custom token balances */
    dnac_token_t tokens[64];
    int token_count = 0;
    dnac_sync_tokens(ctx);
    if (dnac_token_list(ctx, tokens, 64, &token_count) == DNAC_SUCCESS && token_count > 0) {
        printf("\nTokens (%d)\n", token_count);
        printf("%-10s %-20s %s\n", "SYMBOL", "CONFIRMED", "PENDING");
        printf("--------  ------------------  ------------------\n");
        for (int i = 0; i < token_count; i++) {
            dnac_balance_t tbal = {0};
            dnac_wallet_get_balance_token(ctx, tokens[i].token_id, &tbal);
            char tconf[64], tpend[64];
            format_amount_decimals(tbal.confirmed, tokens[i].decimals, tconf, sizeof(tconf));
            format_amount_decimals(tbal.pending, tokens[i].decimals, tpend, sizeof(tpend));
            printf("%-10s %-20s %s\n", tokens[i].symbol, tconf, tpend);
        }
    }

    return 0;
}

int dna_chain_cmd_balance_of(dnac_context_t *ctx, const char *fingerprint) {
    (void)ctx;  /* only need nodus singleton */
    if (!fingerprint || strlen(fingerprint) != 128) {
        fprintf(stderr, "Error: fingerprint must be exactly 128 hex chars\n");
        return 1;
    }

    extern nodus_client_t *nodus_singleton_get(void);
    extern void nodus_singleton_lock(void);
    extern void nodus_singleton_unlock(void);

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        fprintf(stderr, "Error: nodus not connected\n");
        return 1;
    }

    nodus_singleton_lock();
    nodus_dnac_utxo_result_t result;
    int rc = nodus_client_dnac_utxo(client, fingerprint, 100, &result);
    nodus_singleton_unlock();

    if (rc != 0) {
        fprintf(stderr, "Error: nodus_client_dnac_utxo failed: %d\n", rc);
        return 1;
    }

    uint64_t total = 0;
    for (int i = 0; i < result.count; i++) {
        total += result.entries[i].amount;
    }

    char total_str[64];
    format_amount(total, total_str, sizeof(total_str));

    printf("Balance of %.16s...\n", fingerprint);
    printf("-------------------\n");
    printf("Total:      %s\n", total_str);
    printf("UTXOs:      %d\n", result.count);
    for (int i = 0; i < result.count; i++) {
        char amt_str[64];
        format_amount(result.entries[i].amount, amt_str, sizeof(amt_str));
        printf("  UTXO[%d]: %s (idx=%u, block=%llu)\n",
               i, amt_str, result.entries[i].output_index,
               (unsigned long long)result.entries[i].block_height);
    }

    nodus_client_free_utxo_result(&result);
    return 0;
}

int dna_chain_cmd_utxos(dnac_context_t *ctx) {
    dnac_utxo_t *utxos = NULL;
    int count = 0;

    int rc = dnac_get_utxos(ctx, &utxos, &count);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    if (count == 0) {
        printf("No UTXOs found.\n");
        return 0;
    }

    printf("DNAC UTXOs (%d total)\n", count);
    printf("%-6s  %-16s  %-10s  %-20s\n", "INDEX", "AMOUNT", "STATUS", "RECEIVED");
    printf("------  ----------------  ----------  --------------------\n");

    for (int i = 0; i < count; i++) {
        char amount_str[64], time_str[32];
        format_amount(utxos[i].amount, amount_str, sizeof(amount_str));
        format_timestamp(utxos[i].received_at, time_str, sizeof(time_str));

        const char *status_str;
        switch (utxos[i].status) {
            case DNAC_UTXO_UNSPENT: status_str = "unspent"; break;
            case DNAC_UTXO_PENDING: status_str = "pending"; break;
            case DNAC_UTXO_SPENT:   status_str = "spent";   break;
            default:                status_str = "unknown"; break;
        }

        printf("%-6d  %-16s  %-10s  %-20s\n", i, amount_str, status_str, time_str);
    }

    dnac_free_utxos(utxos, count);
    return 0;
}

/* Callback context for name lookup */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool done;
    int result;
    char fingerprint[129];
} name_lookup_ctx_t;

static void on_name_lookup(uint64_t request_id, int error,
                           const char *fingerprint, void *user_data) {
    (void)request_id;
    name_lookup_ctx_t *lctx = (name_lookup_ctx_t *)user_data;
    pthread_mutex_lock(&lctx->mutex);
    lctx->result = error;
    if (fingerprint && error == 0) {
        strncpy(lctx->fingerprint, fingerprint, 128);
        lctx->fingerprint[128] = '\0';
    }
    lctx->done = true;
    pthread_cond_signal(&lctx->cond);
    pthread_mutex_unlock(&lctx->mutex);

    /* Free the strdup'd string from dna_handle_lookup_name */
    if (fingerprint) {
        free((void*)fingerprint);
    }
}

/**
 * Resolve recipient: if 128 hex chars → use as fingerprint,
 * otherwise treat as DNA name and resolve via DHT lookup.
 * Returns 0 on success (fp_out filled), 1 on failure.
 */
static int resolve_recipient(dnac_context_t *ctx, const char *recipient,
                             char *fp_out) {
    size_t len = strlen(recipient);

    /* Check if it's already a fingerprint (128 lowercase hex) */
    bool is_fp = (len == 128);
    if (is_fp) {
        for (size_t i = 0; i < 128; i++) {
            char c = recipient[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                is_fp = false;
                break;
            }
        }
    }

    if (is_fp) {
        memcpy(fp_out, recipient, 128);
        fp_out[128] = '\0';
        return 0;
    }

    /* Name lookup */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) {
        fprintf(stderr, "Error: Engine not initialized\n");
        return 1;
    }

    printf("Resolving name '%s'...\n", recipient);

    name_lookup_ctx_t lookup = {0};
    pthread_mutex_init(&lookup.mutex, NULL);
    pthread_cond_init(&lookup.cond, NULL);

    dna_engine_lookup_name(engine, recipient, on_name_lookup, &lookup);

    pthread_mutex_lock(&lookup.mutex);
    while (!lookup.done) {
        pthread_cond_wait(&lookup.cond, &lookup.mutex);
    }
    int result = lookup.result;
    pthread_mutex_unlock(&lookup.mutex);

    pthread_mutex_destroy(&lookup.mutex);
    pthread_cond_destroy(&lookup.cond);

    if (result != 0 || lookup.fingerprint[0] == '\0') {
        fprintf(stderr, "Error: Name '%s' not found\n", recipient);
        return 1;
    }

    memcpy(fp_out, lookup.fingerprint, 128);
    fp_out[128] = '\0';
    printf("Resolved: %s → %.16s...\n", recipient, fp_out);
    return 0;
}

int dna_chain_cmd_send(dnac_context_t *ctx, const char *recipient,
                  uint64_t amount, const char *memo) {
    char resolved_fp[129];
    if (resolve_recipient(ctx, recipient, resolved_fp) != 0) {
        return 1;
    }

    char amount_str[64];
    format_amount(amount, amount_str, sizeof(amount_str));

    printf("Sending %s to %s...\n", amount_str, resolved_fp);

    /* Estimate fee */
    uint64_t fee = 0;
    int rc = dnac_estimate_fee(ctx, amount, &fee);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error estimating fee: %s\n", dnac_error_string(rc));
        return 1;
    }

    char fee_str[64];
    format_amount(fee, fee_str, sizeof(fee_str));
    printf("Fee: %s\n", fee_str);

    /* Send payment */
    rc = dnac_send(ctx, resolved_fp, amount, memo, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    printf("Payment sent successfully!\n");

    /* Phase 13 / Task 13.4 — print the witness receipt if available. */
    {
        uint64_t bh = 0;
        uint32_t ti = 0;
        uint8_t  txh[64];
        if (dnac_last_send_receipt(ctx, &bh, &ti, txh) == DNAC_SUCCESS) {
            printf("Block:        %" PRIu64 "\n", bh);
            printf("Tx index:     %" PRIu32 "\n", ti);
            printf("Tx hash:      ");
            for (int i = 0; i < DNAC_TX_HASH_SIZE; i++)
                printf("%02x", txh[i]);
            printf("\n");
        }
    }

    /* Allow DHT time to replicate the published TX data */
    printf("Waiting for DHT propagation...\n");
    sleep(5);

    return 0;
}

int dna_chain_cmd_sync(dnac_context_t *ctx) {
    printf("Syncing wallet from DHT...\n");

    int rc = dnac_sync_wallet(ctx);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    printf("Sync complete.\n");
    return 0;
}

int dna_chain_cmd_history(dnac_context_t *ctx, int limit) {
    dnac_tx_history_t *history = NULL;
    int count = 0;

    /* Fetch from Nodus (authoritative source) */
    int rc = dnac_get_remote_history(ctx, &history, &count);
    if (rc != DNAC_SUCCESS) {
        /* Fallback to local cache if network fails */
        fprintf(stderr, "Note: Could not fetch from network (%s), using local cache\n",
                dnac_error_string(rc));
        rc = dnac_get_history(ctx, &history, &count);
        if (rc != DNAC_SUCCESS) {
            fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
            return 1;
        }
    }

    if (count == 0) {
        printf("No transaction history.\n");
        return 0;
    }

    int display_count = (limit > 0 && limit < count) ? limit : count;

    printf("DNAC Transaction History (%d entries)\n", display_count);
    printf("%-20s  %-8s  %-16s  %-12s  %s\n",
           "DATE", "TYPE", "AMOUNT", "COUNTERPARTY", "MEMO");
    printf("--------------------  --------  ----------------  ------------  ----\n");

    for (int i = 0; i < display_count; i++) {
        char time_str[32], amount_str[64];
        format_timestamp(history[i].timestamp, time_str, sizeof(time_str));

        /* Format amount with +/- sign */
        if (history[i].amount_delta >= 0) {
            format_amount((uint64_t)history[i].amount_delta, amount_str, sizeof(amount_str));
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "+%s", amount_str);
            strncpy(amount_str, tmp, sizeof(amount_str));
        } else {
            format_amount((uint64_t)(-history[i].amount_delta), amount_str, sizeof(amount_str));
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "-%s", amount_str);
            strncpy(amount_str, tmp, sizeof(amount_str));
        }

        const char *type_str;
        switch (history[i].type) {
            case DNAC_TX_GENESIS:  type_str = "genesis";  break;
            case DNAC_TX_SPEND: type_str = "spend"; break;
            case DNAC_TX_BURN:  type_str = "burn";  break;
            default:            type_str = "?";     break;
        }

        /* Truncate counterparty for display */
        char cp_short[13] = "";
        if (history[i].counterparty[0]) {
            memcpy(cp_short, history[i].counterparty, 8);
            cp_short[8] = '\0';
            strcat(cp_short, "...");
        }

        printf("%-20s  %-8s  %-16s  %-12s  %s\n",
               time_str, type_str, amount_str, cp_short, history[i].memo);
    }

    dnac_free_history(history, count);
    return 0;
}

int dna_chain_cmd_tx_details(dnac_context_t *ctx, const char *tx_hash_hex) {
    /* Validate and convert hex hash */
    if (strlen(tx_hash_hex) != DNAC_TX_HASH_SIZE * 2) {
        fprintf(stderr, "Error: Invalid transaction hash (expected %d hex chars)\n",
                DNAC_TX_HASH_SIZE * 2);
        return 1;
    }

    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    if (hex_to_bytes(tx_hash_hex, tx_hash, DNAC_TX_HASH_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid hex in transaction hash\n");
        return 1;
    }

    /* Get transaction history and find matching entry */
    dnac_tx_history_t *history = NULL;
    int count = 0;

    int rc = dnac_get_history(ctx, &history, &count);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    dnac_tx_history_t *found = NULL;
    for (int i = 0; i < count; i++) {
        if (memcmp(history[i].tx_hash, tx_hash, DNAC_TX_HASH_SIZE) == 0) {
            found = &history[i];
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "Transaction not found in history.\n");
        dnac_free_history(history, count);
        return 1;
    }

    char time_str[32], amount_str[64], fee_str[64];
    format_timestamp(found->timestamp, time_str, sizeof(time_str));

    if (found->amount_delta >= 0) {
        format_amount((uint64_t)found->amount_delta, amount_str, sizeof(amount_str));
    } else {
        format_amount((uint64_t)(-found->amount_delta), amount_str, sizeof(amount_str));
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "-%s", amount_str);
        strncpy(amount_str, tmp, sizeof(amount_str));
    }
    format_amount(found->fee, fee_str, sizeof(fee_str));

    const char *type_str;
    switch (found->type) {
        case DNAC_TX_GENESIS:  type_str = "GENESIS";  break;
        case DNAC_TX_SPEND: type_str = "SPEND"; break;
        case DNAC_TX_BURN:  type_str = "BURN";  break;
        default:            type_str = "UNKNOWN"; break;
    }

    printf("Transaction Details\n");
    printf("-------------------\n");
    printf("Hash:         %s\n", tx_hash_hex);
    printf("Type:         %s\n", type_str);
    printf("Amount:       %s\n", amount_str);
    printf("Fee:          %s\n", fee_str);
    printf("Date:         %s\n", time_str);
    if (found->counterparty[0]) {
        printf("Counterparty: %s\n", found->counterparty);
    }
    if (found->memo[0]) {
        printf("Memo:         %s\n", found->memo);
    }

    dnac_free_history(history, count);
    return 0;
}

int dna_chain_cmd_nodus_list(dnac_context_t *ctx) {
    dnac_witness_info_t *servers = NULL;
    int count = 0;

    int rc = dnac_get_witness_list(ctx, &servers, &count);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    if (count == 0) {
        printf("No Nodus servers found.\n");
        return 0;
    }

    printf("DNAC Nodus Servers (%d total)\n", count);
    printf("%-4s  %-30s  %-10s  %-12s\n", "#", "ADDRESS", "STATUS", "FINGERPRINT");
    printf("----  ------------------------------  ----------  ------------\n");

    for (int i = 0; i < count; i++) {
        const char *status = servers[i].is_available ? "available" : "offline";

        /* Truncate fingerprint for display */
        char fp_short[13] = "";
        if (servers[i].fingerprint[0]) {
            memcpy(fp_short, servers[i].fingerprint, 8);
            fp_short[8] = '\0';
            strcat(fp_short, "...");
        }

        printf("%-4d  %-30s  %-10s  %-12s\n", i + 1, servers[i].address, status, fp_short);
    }

    dnac_free_witness_list(servers, count);
    return 0;
}


int dna_chain_cmd_info(dnac_context_t *ctx) {
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) {
        fprintf(stderr, "Error: Engine not initialized\n");
        return 1;
    }

    printf("DNAC Wallet Info\n");
    printf("================\n");
    printf("Version:     %s\n", dnac_get_version());

    /* Fingerprint (wallet address) */
    const char *fp = dna_engine_get_fingerprint(engine);
    if (fp) {
        printf("Address:     %.32s...\n", fp);
        printf("Full:        %s\n", fp);
    } else {
        printf("Address:     (not loaded)\n");
    }

    /* DHT status */
    bool dht_connected = nodus_ops_is_ready();
    printf("DHT:         %s\n", dht_connected ? "Connected" : "Disconnected");

    /* Balance summary */
    dnac_balance_t balance;
    if (dnac_get_balance(ctx, &balance) == DNAC_SUCCESS) {
        char amt[32];
        format_amount(balance.confirmed, amt, sizeof(amt));
        printf("Balance:     %s\n", amt);
    }

    return 0;
}

int dna_chain_cmd_address(dnac_context_t *ctx) {
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) {
        fprintf(stderr, "Error: Engine not initialized\n");
        return 1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (fp) {
        printf("%s\n", fp);
    } else {
        fprintf(stderr, "Error: Identity not loaded\n");
        return 1;
    }
    return 0;
}


int dna_chain_cmd_query(dnac_context_t *ctx, const char *query) {
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) {
        fprintf(stderr, "Error: Engine not initialized\n");
        return 1;
    }

    /* Determine if query is fingerprint (128 hex) or name */
    size_t len = strlen(query);
    bool is_fingerprint = (len == 128);

    /* Validate fingerprint format */
    if (is_fingerprint) {
        for (size_t i = 0; i < 128; i++) {
            char c = query[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                is_fingerprint = false;
                break;
            }
        }
    }

    const char *fingerprint = NULL;
    char fp_buf[129] = {0};

    if (is_fingerprint) {
        fingerprint = query;
        printf("Looking up fingerprint: %.32s...\n", fingerprint);
    } else {
        /* Name lookup */
        printf("Looking up name: %s\n", query);

        name_lookup_ctx_t lookup = {0};
        pthread_mutex_init(&lookup.mutex, NULL);
        pthread_cond_init(&lookup.cond, NULL);

        dna_engine_lookup_name(engine, query, on_name_lookup, &lookup);

        /* Wait for callback */
        pthread_mutex_lock(&lookup.mutex);
        while (!lookup.done) {
            pthread_cond_wait(&lookup.cond, &lookup.mutex);
        }
        int result = lookup.result;
        pthread_mutex_unlock(&lookup.mutex);

        pthread_mutex_destroy(&lookup.mutex);
        pthread_cond_destroy(&lookup.cond);

        if (result != 0) {
            fprintf(stderr, "Lookup failed\n");
            return 1;
        }

        if (lookup.fingerprint[0] == '\0') {
            fprintf(stderr, "Name '%s' not registered\n", query);
            return 1;
        }

        snprintf(fp_buf, sizeof(fp_buf), "%s", lookup.fingerprint);
        fingerprint = fp_buf;
    }

    /* Display result */
    printf("\nIdentity Found:\n");
    printf("  Fingerprint: %s\n", fingerprint);

    return 0;
}

/* ============================================================================
 * Genesis TX File Format
 *
 * Magic:    "DNAC_GEN\0"  (9 bytes)
 * Version:  uint8_t = 1
 * TX len:   uint32_t (little-endian)
 * TX data:  raw serialized bytes
 * Chain ID: 32 bytes (for verification on load)
 * ========================================================================== */

#define GENESIS_FILE_MAGIC     "DNAC_GEN"
#define GENESIS_FILE_MAGIC_LEN 9   /* includes NUL terminator */
#define GENESIS_FILE_VERSION   1
#define DNAC_CHAIN_ID_SIZE     32

/**
 * @brief Get default genesis TX file path (~/.dna/genesis_tx.bin)
 */
static int genesis_default_path(char *buf, size_t buf_len) {
    const char *home = getenv("HOME");
    if (!home) home = ".";
    int n = snprintf(buf, buf_len, "%s/.dna/genesis_tx.bin", home);
    return (n > 0 && (size_t)n < buf_len) ? 0 : -1;
}

/**
 * @brief Save genesis TX + chain_id to file
 */
static int genesis_file_save(const char *path,
                             const dnac_transaction_t *tx,
                             const uint8_t *chain_id) {
    /* Serialize TX */
    uint8_t *tx_buf = malloc(65536);
    if (!tx_buf) return -1;
    size_t tx_len = 0;
    int rc = dnac_tx_serialize(tx, tx_buf, 65536, &tx_len);
    if (rc != DNAC_SUCCESS) {
        free(tx_buf);
        return -1;
    }

    /* Ensure parent directory exists */
    char dir[512];
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir, 0700);  /* best-effort */
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        free(tx_buf);
        return -1;
    }

    /* Write magic (9 bytes including NUL) */
    if (fwrite(GENESIS_FILE_MAGIC, 1, GENESIS_FILE_MAGIC_LEN, f) != GENESIS_FILE_MAGIC_LEN)
        goto fail;

    /* Write version */
    uint8_t ver = GENESIS_FILE_VERSION;
    if (fwrite(&ver, 1, 1, f) != 1) goto fail;

    /* Write TX length (little-endian u32) */
    uint32_t len_le = (uint32_t)tx_len;
    uint8_t len_bytes[4] = {
        (uint8_t)(len_le & 0xFF),
        (uint8_t)((len_le >> 8) & 0xFF),
        (uint8_t)((len_le >> 16) & 0xFF),
        (uint8_t)((len_le >> 24) & 0xFF)
    };
    if (fwrite(len_bytes, 1, 4, f) != 4) goto fail;

    /* Write TX data */
    if (fwrite(tx_buf, 1, tx_len, f) != tx_len) goto fail;

    /* Write chain_id (32 bytes) */
    if (fwrite(chain_id, 1, DNAC_CHAIN_ID_SIZE, f) != DNAC_CHAIN_ID_SIZE) goto fail;

    fclose(f);
    free(tx_buf);
    return 0;

fail:
    fclose(f);
    free(tx_buf);
    return -1;
}

/**
 * @brief Load genesis TX + chain_id from file
 *
 * Caller must free *tx_out with dnac_free_transaction().
 */
static int genesis_file_load(const char *path,
                             dnac_transaction_t **tx_out,
                             uint8_t *chain_id_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    /* Read + verify magic */
    char magic[GENESIS_FILE_MAGIC_LEN];
    if (fread(magic, 1, GENESIS_FILE_MAGIC_LEN, f) != GENESIS_FILE_MAGIC_LEN) goto fail;
    if (memcmp(magic, GENESIS_FILE_MAGIC, GENESIS_FILE_MAGIC_LEN) != 0) {
        fprintf(stderr, "Error: Invalid genesis file (bad magic)\n");
        goto fail;
    }

    /* Read version */
    uint8_t ver;
    if (fread(&ver, 1, 1, f) != 1) goto fail;
    if (ver != GENESIS_FILE_VERSION) {
        fprintf(stderr, "Error: Unsupported genesis file version %u\n", ver);
        goto fail;
    }

    /* Read TX length (little-endian u32) */
    uint8_t len_bytes[4];
    if (fread(len_bytes, 1, 4, f) != 4) goto fail;
    uint32_t tx_len = (uint32_t)len_bytes[0]
                    | ((uint32_t)len_bytes[1] << 8)
                    | ((uint32_t)len_bytes[2] << 16)
                    | ((uint32_t)len_bytes[3] << 24);

    if (tx_len == 0 || tx_len > 65536) {
        fprintf(stderr, "Error: Invalid TX length in genesis file: %u\n", tx_len);
        goto fail;
    }

    /* Read TX data */
    uint8_t *tx_buf = malloc(tx_len);
    if (!tx_buf) goto fail;
    if (fread(tx_buf, 1, tx_len, f) != tx_len) {
        free(tx_buf);
        goto fail;
    }

    /* Read chain_id */
    if (fread(chain_id_out, 1, DNAC_CHAIN_ID_SIZE, f) != DNAC_CHAIN_ID_SIZE) {
        free(tx_buf);
        goto fail;
    }

    /* Deserialize TX */
    int rc = dnac_tx_deserialize(tx_buf, tx_len, tx_out);
    free(tx_buf);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: Failed to deserialize genesis TX: %s\n",
                dnac_error_string(rc));
        goto fail;
    }

    fclose(f);
    return 0;

fail:
    fclose(f);
    return -1;
}

/* ============================================================================
 * Genesis CLI Commands
 * ========================================================================== */

int dna_chain_cmd_genesis_create(dnac_context_t *ctx, const char *fingerprint,
                            uint64_t amount) {
    /* Build recipient */
    dnac_genesis_recipient_t recipients[1];
    strncpy(recipients[0].fingerprint, fingerprint,
            sizeof(recipients[0].fingerprint) - 1);
    recipients[0].fingerprint[sizeof(recipients[0].fingerprint) - 1] = '\0';
    recipients[0].amount = amount;

    /* Phase 1: create TX + derive chain_id (no network) */
    dnac_transaction_t *tx = NULL;
    uint8_t chain_id[DNAC_CHAIN_ID_SIZE];

    int rc = dnac_genesis_phase1_create(ctx, recipients, 1, &tx, chain_id);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error creating genesis TX: %s\n", dnac_error_string(rc));
        return 1;
    }

    /* Save to file */
    char filepath[512];
    if (genesis_default_path(filepath, sizeof(filepath)) != 0) {
        fprintf(stderr, "Error: Could not determine genesis file path\n");
        dnac_free_transaction(tx);
        return 1;
    }

    if (genesis_file_save(filepath, tx, chain_id) != 0) {
        fprintf(stderr, "Error: Failed to save genesis TX to %s\n", filepath);
        dnac_free_transaction(tx);
        return 1;
    }

    /* Format amount using chain-defined decimals (trust state). */
    char amount_str[64];
    format_amount(amount, amount_str, sizeof(amount_str));

    /* Print results */
    printf("\nGenesis TX created (Phase 1 — local only)\n");
    printf("──────────────────────────────────────────\n");

    printf("TX Hash:   ");
    for (int i = 0; i < DNAC_TX_HASH_SIZE; i++) printf("%02x", tx->tx_hash[i]);
    printf("\n");

    printf("Chain ID:  ");
    for (int i = 0; i < DNAC_CHAIN_ID_SIZE; i++) printf("%02x", chain_id[i]);
    printf("\n");

    printf("Recipient: %s\n", fingerprint);
    printf("Amount:    %s\n", amount_str);

    printf("\nGenesis TX saved to: %s\n", filepath);

    printf("\nNext steps:\n");
    printf("  1. Configure witnesses with chain_id: ");
    for (int i = 0; i < DNAC_CHAIN_ID_SIZE; i++) printf("%02x", chain_id[i]);
    printf("\n");
    printf("  2. Run: dnac-cli genesis-submit\n");

    dnac_free_transaction(tx);
    return 0;
}

/* Verify the cluster has actually committed the expected genesis chain,
 * even if dnac_genesis_phase2_submit returned an error. BFT consensus is
 * asynchronous: the client's attestation collector may time out on round N
 * while the cluster converges on round N+k. Re-query the witnesses for the
 * authoritative UTXO state before declaring failure to the user.
 *
 * Returns 1 if the cluster has the expected chain committed with a non-empty
 * UTXO set matching expected_chain_id, 0 otherwise.
 */
static int verify_genesis_actually_committed(dnac_context_t *ctx,
                                              const uint8_t *expected_chain_id) {
    /* Give the cluster a beat to settle its last BFT round. */
    sleep(2);

    /* Sync UTXOs from witnesses — authoritative source. */
    int rc = dnac_sync_wallet(ctx);
    if (rc != DNAC_SUCCESS) return 0;

    /* Confirm our ctx still points at the expected chain. sync_wallet can
     * reset chain_id on divergence, so re-check before trusting the balance. */
    const uint8_t *current_chain = dnac_get_chain_id(ctx);
    if (!current_chain ||
        memcmp(current_chain, expected_chain_id, DNAC_CHAIN_ID_SIZE) != 0) {
        return 0;
    }

    /* Non-empty UTXO set on the expected chain = cluster committed a genesis
     * that owns us funds. Genesis is the only way UTXOs appear before any
     * spends, so seeing any UTXO here proves the submit actually landed. */
    dnac_balance_t balance = {0};
    rc = dnac_get_balance(ctx, &balance);
    if (rc != DNAC_SUCCESS) return 0;
    return balance.utxo_count > 0;
}

int dna_chain_cmd_genesis_submit(dnac_context_t *ctx, const char *tx_file) {
    /* Determine file path */
    char filepath[512];
    if (tx_file) {
        strncpy(filepath, tx_file, sizeof(filepath) - 1);
        filepath[sizeof(filepath) - 1] = '\0';
    } else {
        if (genesis_default_path(filepath, sizeof(filepath)) != 0) {
            fprintf(stderr, "Error: Could not determine genesis file path\n");
            return 1;
        }
    }

    /* Load genesis TX from file */
    dnac_transaction_t *tx = NULL;
    uint8_t stored_chain_id[DNAC_CHAIN_ID_SIZE];

    printf("Loading genesis TX from: %s\n", filepath);

    if (genesis_file_load(filepath, &tx, stored_chain_id) != 0) {
        fprintf(stderr, "Error: Failed to load genesis TX from %s\n", filepath);
        return 1;
    }

    /* Recompute chain_id from TX data for verification */
    if (tx->output_count < 1) {
        fprintf(stderr, "Error: Genesis TX has no outputs\n");
        dnac_free_transaction(tx);
        return 1;
    }

    uint8_t recomputed_chain_id[DNAC_CHAIN_ID_SIZE];
    int rc = dnac_derive_chain_id(tx->outputs[0].owner_fingerprint,
                                   tx->tx_hash, recomputed_chain_id);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to recompute chain_id\n");
        dnac_free_transaction(tx);
        return 1;
    }

    /* Verify chain_id matches what was stored */
    if (memcmp(stored_chain_id, recomputed_chain_id, DNAC_CHAIN_ID_SIZE) != 0) {
        fprintf(stderr, "Error: Chain ID mismatch — file may be corrupted\n");
        fprintf(stderr, "  Stored:     ");
        for (int i = 0; i < DNAC_CHAIN_ID_SIZE; i++)
            fprintf(stderr, "%02x", stored_chain_id[i]);
        fprintf(stderr, "\n  Recomputed: ");
        for (int i = 0; i < DNAC_CHAIN_ID_SIZE; i++)
            fprintf(stderr, "%02x", recomputed_chain_id[i]);
        fprintf(stderr, "\n");
        dnac_free_transaction(tx);
        return 1;
    }

    printf("Chain ID verified: ");
    for (int i = 0; i < DNAC_CHAIN_ID_SIZE; i++) printf("%02x", recomputed_chain_id[i]);
    printf("\n");

    /* Phase 2: submit to witnesses + broadcast */
    printf("Submitting genesis to witnesses...\n");

    rc = dnac_genesis_phase2_submit(ctx, tx, recomputed_chain_id);
    if (rc == DNAC_ERROR_GENESIS_EXISTS) {
        fprintf(stderr, "Error: Genesis already exists on this chain.\n");
        dnac_free_transaction(tx);
        return 1;
    }
    if (rc != DNAC_SUCCESS) {
        /* Submit reported failure — but BFT consensus is asynchronous, so
         * the cluster may have committed on a later round than our local
         * attestation collector waited for. Query the authoritative cluster
         * state before giving up to avoid telling the user "failed" after
         * a successful commit. */
        fprintf(stderr,
                "Warning: submit reported '%s', verifying cluster state...\n",
                dnac_error_string(rc));

        if (!verify_genesis_actually_committed(ctx, recomputed_chain_id)) {
            fprintf(stderr, "Error: Genesis submission failed: %s\n",
                    dnac_error_string(rc));
            dnac_free_transaction(tx);
            return 1;
        }

        fprintf(stderr,
                "Cluster has committed this chain despite the submit error — "
                "treating as success.\n");
        /* Fall through to the success print path. */
    }

    /* Success */
    printf("\nGENESIS SUBMITTED SUCCESSFULLY!\n");
    printf("───────────────────────────────\n");

    printf("TX Hash:    ");
    for (int i = 0; i < DNAC_TX_HASH_SIZE; i++) printf("%02x", tx->tx_hash[i]);
    printf("\n");

    printf("Chain ID:   ");
    for (int i = 0; i < DNAC_CHAIN_ID_SIZE; i++) printf("%02x", recomputed_chain_id[i]);
    printf("\n");

    printf("Witnesses:  %d\n", tx->witness_count);

    uint64_t total = 0;
    for (int i = 0; i < tx->output_count; i++)
        total += tx->outputs[i].amount;
    char total_str[64];
    format_amount(total, total_str, sizeof(total_str));
    printf("Supply:     %s %s\n", total_str, dnac_current_token_symbol());

    dnac_free_transaction(tx);
    return 0;
}

/* ============================================================================
 * Token CLI Commands
 * ========================================================================== */

int dna_chain_cmd_token_create(dnac_context_t *ctx, const char *name,
                          const char *symbol, uint64_t supply) {
    printf("Creating token '%s' (%s) with supply %" PRIu64 "...\n",
           name, symbol, supply);

    int rc = dnac_token_create(ctx, name, symbol, 8, supply);  /* default 8 decimals */
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: Failed to create token: %s\n", dnac_error_string(rc));
        return 1;
    }

    printf("Token created successfully!\n");
    printf("Run 'token-list' to see the token ID.\n");
    return 0;
}

int dna_chain_cmd_token_list(dnac_context_t *ctx) {
    dnac_token_t tokens[64];
    int count = 0;

    int rc = dnac_token_list(ctx, tokens, 64, &count);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    if (count == 0) {
        printf("No tokens found.\n");
        return 0;
    }

    printf("Tokens (%d total)\n", count);
    printf("%-8s  %-20s  %-16s  %s\n", "SYMBOL", "NAME", "SUPPLY", "TOKEN ID");
    printf("--------  --------------------  ----------------  ----------------\n");

    for (int i = 0; i < count; i++) {
        char id_short[17] = {0};
        for (int j = 0; j < 8 && j < DNAC_TOKEN_ID_SIZE; j++)
            snprintf(id_short + j * 2, 3, "%02x", tokens[i].token_id[j]);

        char supply_str[64];
        format_amount(tokens[i].initial_supply, supply_str, sizeof(supply_str));

        printf("%-8s  %-20s  %16s  %s...\n",
               tokens[i].symbol, tokens[i].name, supply_str, id_short);
    }

    return 0;
}

int dna_chain_cmd_token_info(dnac_context_t *ctx, const char *id_or_symbol) {
    size_t len = strlen(id_or_symbol);

    /* If it looks like a hex token_id (128 hex chars = 64 bytes) */
    if (len == DNAC_TOKEN_ID_SIZE * 2) {
        uint8_t token_id[DNAC_TOKEN_ID_SIZE];
        if (hex_to_bytes(id_or_symbol, token_id, DNAC_TOKEN_ID_SIZE) != 0) {
            fprintf(stderr, "Error: Invalid hex in token ID\n");
            return 1;
        }

        dnac_token_t token;
        int rc = dnac_token_info(ctx, token_id, &token);
        if (rc != DNAC_SUCCESS) {
            fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
            return 1;
        }

        printf("Token Info\n");
        printf("----------\n");
        printf("Name:      %s\n", token.name);
        printf("Symbol:    %s\n", token.symbol);
        printf("Decimals:  %u\n", token.decimals);

        char supply_str[64];
        format_amount(token.initial_supply, supply_str, sizeof(supply_str));
        printf("Supply:    %s\n", supply_str);

        printf("Creator:   %.16s...\n", token.creator_fp);
        printf("Token ID:  ");
        for (int i = 0; i < DNAC_TOKEN_ID_SIZE; i++)
            printf("%02x", token.token_id[i]);
        printf("\n");

        if (token.block_height > 0) {
            printf("Block:     %" PRIu64 "\n", token.block_height);
        }
        if (token.timestamp > 0) {
            char time_str[32];
            format_timestamp(token.timestamp, time_str, sizeof(time_str));
            printf("Created:   %s\n", time_str);
        }
        return 0;
    }

    /* Otherwise treat as symbol — list all tokens and find matching symbol */
    dnac_token_t tokens[64];
    int count = 0;
    int rc = dnac_token_list(ctx, tokens, 64, &count);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    for (int i = 0; i < count; i++) {
        if (strcasecmp(tokens[i].symbol, id_or_symbol) == 0) {
            /* Found — recurse with full token_id hex */
            char id_hex[DNAC_TOKEN_ID_SIZE * 2 + 1];
            for (int j = 0; j < DNAC_TOKEN_ID_SIZE; j++)
                snprintf(id_hex + j * 2, 3, "%02x", tokens[i].token_id[j]);
            return dna_chain_cmd_token_info(ctx, id_hex);
        }
    }

    fprintf(stderr, "Token '%s' not found.\n", id_or_symbol);
    return 1;
}

int dna_chain_cmd_balance_token(dnac_context_t *ctx, const char *token_id_hex) {
    if (strlen(token_id_hex) != DNAC_TOKEN_ID_SIZE * 2) {
        fprintf(stderr, "Error: Token ID must be %d hex chars\n",
                DNAC_TOKEN_ID_SIZE * 2);
        return 1;
    }

    uint8_t token_id[DNAC_TOKEN_ID_SIZE];
    if (hex_to_bytes(token_id_hex, token_id, DNAC_TOKEN_ID_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid hex in token ID\n");
        return 1;
    }

    dnac_balance_t balance;
    int rc = dnac_wallet_get_balance_token(ctx, token_id, &balance);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    char confirmed_str[64], pending_str[64], locked_str[64];
    format_amount(balance.confirmed, confirmed_str, sizeof(confirmed_str));
    format_amount(balance.pending, pending_str, sizeof(pending_str));
    format_amount(balance.locked, locked_str, sizeof(locked_str));

    printf("Token Balance (%.16s...)\n", token_id_hex);
    printf("-------------------\n");
    printf("Confirmed:  %s\n", confirmed_str);
    printf("Pending:    %s\n", pending_str);
    printf("Locked:     %s\n", locked_str);
    printf("UTXOs:      %d\n", balance.utxo_count);

    return 0;
}

int dna_chain_cmd_send_token(dnac_context_t *ctx, const char *recipient,
                        uint64_t amount, const char *token_id_hex,
                        const char *memo) {
    char resolved_fp[129];
    if (resolve_recipient(ctx, recipient, resolved_fp) != 0) {
        return 1;
    }

    /* Parse token_id */
    if (strlen(token_id_hex) != DNAC_TOKEN_ID_SIZE * 2) {
        fprintf(stderr, "Error: Token ID must be %d hex chars\n",
                DNAC_TOKEN_ID_SIZE * 2);
        return 1;
    }

    uint8_t token_id[DNAC_TOKEN_ID_SIZE];
    if (hex_to_bytes(token_id_hex, token_id, DNAC_TOKEN_ID_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid hex in token ID\n");
        return 1;
    }

    char amount_str[64];
    format_amount(amount, amount_str, sizeof(amount_str));
    printf("Sending %s (token %.16s...) to %.16s...\n",
           amount_str, token_id_hex, resolved_fp);

    /* Build transaction with token */
    dnac_tx_builder_t *builder = dnac_tx_builder_create(ctx);
    if (!builder) {
        fprintf(stderr, "Error: Failed to create transaction builder\n");
        return 1;
    }

    int rc = dnac_tx_builder_set_token(builder, token_id);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error setting token: %s\n", dnac_error_string(rc));
        dnac_tx_builder_free(builder);
        return 1;
    }

    dnac_tx_output_t output = {0};
    strncpy(output.recipient_fingerprint, resolved_fp,
            sizeof(output.recipient_fingerprint) - 1);
    output.amount = amount;
    if (memo) {
        strncpy(output.memo, memo, sizeof(output.memo) - 1);
    }

    rc = dnac_tx_builder_add_output(builder, &output);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error adding output: %s\n", dnac_error_string(rc));
        dnac_tx_builder_free(builder);
        return 1;
    }

    dnac_transaction_t *tx = NULL;
    rc = dnac_tx_builder_build(builder, &tx);
    dnac_tx_builder_free(builder);

    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error building transaction: %s\n", dnac_error_string(rc));
        return 1;
    }

    /* Broadcast to witnesses */
    rc = dnac_tx_broadcast(ctx, tx, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        dnac_free_transaction(tx);
        return 1;
    }

    printf("Token payment sent successfully!\n");
    printf("TX Hash: ");
    for (int i = 0; i < DNAC_TX_HASH_SIZE; i++)
        printf("%02x", tx->tx_hash[i]);
    printf("\n");

    dnac_free_transaction(tx);

    /* Allow DHT time to replicate */
    printf("Waiting for DHT propagation...\n");
    sleep(5);

    return 0;
}

void dna_chain_cmd_print_help(void) {
    printf("dnac-cli - DNAC Wallet Command Line Interface\n\n");
    printf("Usage: dnac-cli [options] <command> [arguments]\n\n");
    printf("Options:\n");
    printf("  -h, --help       Show this help message\n");
    printf("  -v, --version    Show version information\n");
    printf("  -d, --data-dir   Data directory (default: ~/.dna)\n\n");
    printf("Commands:\n");
    printf("  info             Show wallet info and status\n");
    printf("  address          Show wallet address (fingerprint)\n");
    printf("  query <name|fp>  Lookup identity by name or fingerprint\n");
    printf("  balance          Show wallet balance\n");
    printf("  utxos            List unspent transaction outputs\n");
    printf("  send <fp> <amt>  Send payment to fingerprint\n");
    printf("  sync             Sync wallet from network (clears + rebuilds)\n");
    printf("  history [n]      Show transaction history (last n entries)\n");
    printf("  tx <hash>        Show transaction details\n");
    printf("  nodus-list       List Nodus servers\n");
    printf("  genesis-create <fp> <amount>   Create genesis TX locally (Phase 1)\n");
    printf("  genesis-submit [tx_file]       Submit genesis TX to network (Phase 2)\n\n");
    printf("Token Commands:\n");
    printf("  token-create <name> <symbol> <supply>  Create a new token\n");
    printf("  token-list                             List all known tokens\n");
    printf("  token-info <id|symbol>                 Show token details\n");
    printf("  balance --token <id>                   Show balance for a specific token\n");
    printf("  send --token <id> <fp> <amt> [memo]    Send token payment\n\n");
    printf("Examples:\n");
    printf("  dnac-cli balance\n");
    printf("  dnac-cli send abc123...def 1000000\n");
    printf("  dnac-cli sync\n");
    printf("  dnac-cli history 10\n");
}

void dna_chain_cmd_print_version(void) {
    printf("dna-connect-cli dna group version %s\n", DNAC_VERSION_STRING);
    printf("DNAC - Post-Quantum Digital Cash over DHT\n");
    printf("Protocol version: v%d\n", DNAC_PROTOCOL_VERSION);
}

/* ============================================================================
 * parse-tx (Phase 0 / Task 0.7)
 * ========================================================================== */

static const char *tx_type_name(dnac_tx_type_t t) {
    switch (t) {
        case DNAC_TX_GENESIS:      return "GENESIS";
        case DNAC_TX_SPEND:        return "SPEND";
        case DNAC_TX_BURN:         return "BURN";
        case DNAC_TX_TOKEN_CREATE: return "TOKEN_CREATE";
        default:                   return "UNKNOWN";
    }
}

static void hex_dump(const uint8_t *bytes, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", bytes[i]);
}

int dna_chain_cmd_parse_tx(dnac_context_t *ctx, const char *tx_file) {
    (void)ctx;
    if (!tx_file) {
        fprintf(stderr, "Error: tx_file is required\n");
        return 1;
    }

    /* Read file into memory */
    FILE *f = fopen(tx_file, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open %s: %s\n", tx_file, strerror(errno));
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: fseek failed: %s\n", strerror(errno));
        fclose(f);
        return 1;
    }
    long size = ftell(f);
    if (size < 0) {
        fprintf(stderr, "Error: ftell failed: %s\n", strerror(errno));
        fclose(f);
        return 1;
    }
    rewind(f);

    /* Sanity bound: 16 inputs + 16 outputs + 3 witnesses + headers fits well
     * under 64 KB. Reject anything larger as malformed. */
    if (size > 65536) {
        fprintf(stderr, "Error: %s is %ld bytes, exceeds 64 KB sanity limit\n",
                tx_file, size);
        fclose(f);
        return 1;
    }

    uint8_t *buf = malloc((size_t)size);
    if (!buf) {
        fprintf(stderr, "Error: out of memory reading %s\n", tx_file);
        fclose(f);
        return 1;
    }
    size_t nread = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (nread != (size_t)size) {
        fprintf(stderr, "Error: short read on %s (%zu/%ld)\n", tx_file, nread, size);
        free(buf);
        return 1;
    }

    /* Deserialize */
    dnac_transaction_t *tx = NULL;
    int rc = dnac_tx_deserialize(buf, (size_t)size, &tx);
    free(buf);
    if (rc != DNAC_SUCCESS || !tx) {
        fprintf(stderr, "Error: dnac_tx_deserialize failed (rc=%d)\n", rc);
        return 1;
    }

    /* Pretty-print */
    printf("file:       %s (%ld bytes)\n", tx_file, size);
    printf("version:    %u\n", tx->version);
    printf("tx_type:    %s\n", tx_type_name(tx->type));
    printf("tx_hash:    "); hex_dump(tx->tx_hash, DNAC_TX_HASH_SIZE); printf("\n");
    printf("timestamp:  %" PRIu64 "\n", tx->timestamp);
    printf("inputs:     %d\n", tx->input_count);
    for (int i = 0; i < tx->input_count; i++) {
        printf("  [%d] nullifier=", i);
        hex_dump(tx->inputs[i].nullifier, 8);
        printf("...  amount=%" PRIu64 "\n", tx->inputs[i].amount);
    }
    printf("outputs:    %d\n", tx->output_count);
    for (int i = 0; i < tx->output_count; i++) {
        printf("  [%d] fp=%.32s...  amount=%" PRIu64 "\n",
               i, tx->outputs[i].owner_fingerprint, tx->outputs[i].amount);
        if (tx->outputs[i].memo_len > 0) {
            printf("       memo=\"%.*s\"\n",
                   (int)tx->outputs[i].memo_len, tx->outputs[i].memo);
        }
    }
    printf("witnesses:  %d\n", tx->witness_count);

    free(tx);
    return 0;
}
