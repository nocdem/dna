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
#include "dnac/chain_def_codec.h"
#include "dnac/genesis_prepare.h"
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

int dna_chain_cmd_delegations(dnac_context_t *ctx) {
    dnac_delegation_t *list = NULL;
    int count = 0;

    int rc = dnac_get_my_delegations(ctx, &list, &count);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    if (count == 0) {
        printf("No active delegations.\n");
        return 0;
    }

    printf("Your Delegations (%d %s)\n",
           count, count == 1 ? "delegation" : "delegations");
    printf("%-20s  %-16s  %s\n", "VALIDATOR", "AMOUNT", "BLOCK");
    printf("--------------------  ----------------  -----\n");

    uint64_t total = 0;
    for (int i = 0; i < count; i++) {
        char vshort[21];  /* "xxxxxxxx...yyyyyyyy" + NUL */
        /* Render as 8 leading + "..." + 8 trailing so both ends of the
         * 128-char fp are visible — helps when comparing with the
         * validator list or the DelegationScreen pubkey column. */
        const char *fp = list[i].validator_fp;
        size_t flen = strlen(fp);
        if (flen >= 16) {
            memcpy(vshort, fp, 8);
            memcpy(vshort + 8, "...", 3);
            memcpy(vshort + 11, fp + flen - 8, 8);
            vshort[19] = '\0';
        } else {
            strncpy(vshort, fp, sizeof(vshort) - 1);
            vshort[sizeof(vshort) - 1] = '\0';
        }

        char amt_str[64];
        format_amount(list[i].amount_raw, amt_str, sizeof(amt_str));

        printf("%-20s  %-16s  %llu\n",
               vshort, amt_str,
               (unsigned long long)list[i].delegated_at_block);

        total += list[i].amount_raw;
    }

    char total_str[64];
    format_amount(total, total_str, sizeof(total_str));
    printf("\nTotal locked: %s DNAC\n", total_str);

    dnac_free_delegations(list, count);
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
                            uint64_t amount,
                            const char *chain_def_file_path) {
    /* If --chain-def-file is provided, load + decode it FIRST so we can
     * auto-compute the correct recipient amount (initial_supply_raw minus
     * the validator self-stake lock). Without this pre-computation an
     * operator who passes the gross initial_supply_raw as `amount` produces
     * a TX that the witness will reject via Rule P.2 — AND, if the witness
     * path doesn't enforce Rule P.2, a ghost supply on chain.
     * See dnac/docs/plans/2026-04-19-genesis-ghost-stake-fix.md. */
    uint8_t *cdbuf = NULL;
    long cdlen = 0;
    dnac_chain_definition_t preloaded_cd;
    bool have_preloaded_cd = false;
    memset(&preloaded_cd, 0, sizeof(preloaded_cd));

    if (chain_def_file_path && chain_def_file_path[0]) {
        FILE *cdf = fopen(chain_def_file_path, "rb");
        if (!cdf) {
            fprintf(stderr, "Error: cannot open chain-def-file '%s'\n", chain_def_file_path);
            return 1;
        }
        fseek(cdf, 0, SEEK_END);
        cdlen = ftell(cdf);
        fseek(cdf, 0, SEEK_SET);
        if (cdlen <= 0 || (size_t)cdlen > dnac_chain_def_max_size()) {
            fprintf(stderr, "Error: chain-def-file size %ld out of range\n", cdlen);
            fclose(cdf);
            return 1;
        }
        cdbuf = malloc((size_t)cdlen);
        if (!cdbuf || fread(cdbuf, 1, (size_t)cdlen, cdf) != (size_t)cdlen) {
            fprintf(stderr, "Error: reading chain-def-file failed\n");
            free(cdbuf);
            fclose(cdf);
            return 1;
        }
        fclose(cdf);
        if (dnac_chain_def_decode(cdbuf, (size_t)cdlen, &preloaded_cd) != 0) {
            fprintf(stderr, "Error: chain_def decode failed\n");
            free(cdbuf);
            return 1;
        }
        have_preloaded_cd = true;

        /* Auto-compute / validate amount against Rule P.2. */
        if (preloaded_cd.initial_validator_count > 0) {
            uint64_t stake_locked =
                (uint64_t)preloaded_cd.initial_validator_count *
                DNAC_SELF_STAKE_AMOUNT;
            if (stake_locked > preloaded_cd.initial_supply_raw) {
                fprintf(stderr,
                    "Error: chain_def.initial_supply_raw=%llu < required "
                    "stake_lock=%llu (%u validators x %llu). Fix operator "
                    "config.\n",
                    (unsigned long long)preloaded_cd.initial_supply_raw,
                    (unsigned long long)stake_locked,
                    (unsigned)preloaded_cd.initial_validator_count,
                    (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
                free(cdbuf);
                return 1;
            }
            uint64_t expected_amount =
                preloaded_cd.initial_supply_raw - stake_locked;

            if (amount == 0) {
                fprintf(stderr,
                    "Auto-computed recipient amount = %llu "
                    "(initial_supply_raw %llu − %u × %llu stake = %llu)\n",
                    (unsigned long long)expected_amount,
                    (unsigned long long)preloaded_cd.initial_supply_raw,
                    (unsigned)preloaded_cd.initial_validator_count,
                    (unsigned long long)DNAC_SELF_STAKE_AMOUNT,
                    (unsigned long long)expected_amount);
                amount = expected_amount;
            } else if (amount != expected_amount) {
                fprintf(stderr,
                    "Error: amount=%llu != expected=%llu "
                    "(initial_supply_raw %llu − %u × %llu stake). "
                    "Pass amount=0 to auto-compute, or fix the operator "
                    "config before running.\n",
                    (unsigned long long)amount,
                    (unsigned long long)expected_amount,
                    (unsigned long long)preloaded_cd.initial_supply_raw,
                    (unsigned)preloaded_cd.initial_validator_count,
                    (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
                free(cdbuf);
                return 1;
            }
        }
    }

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
        free(cdbuf);
        return 1;
    }

    /* Attach pre-loaded chain_def (if any). */
    if (have_preloaded_cd) {
        tx->chain_def = preloaded_cd;
        tx->has_chain_def = true;
        printf("Anchored genesis: chain_def loaded from %s (%ld bytes)\n",
               chain_def_file_path, cdlen);
        free(cdbuf);
        cdbuf = NULL;
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
    printf("  2. Run: dna-connect-cli dna genesis-submit\n");

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

/* dna_chain_cmd_print_help / dna_chain_cmd_print_version removed
 * 2026-04-19 — dead code (never called, stale `dnac-cli` text).
 * The live help is in cli_dna_chain.c group-help handlers. */

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

/* ============================================================================
 * Phase 12 Task 58 — genesis-prepare (operator tool)
 * ========================================================================== */

int dna_chain_cmd_genesis_prepare(dnac_context_t *ctx, const char *config_path) {
    (void)ctx;
    if (!config_path) {
        fprintf(stderr, "Error: config_path is NULL\n");
        return 1;
    }

    /* Upper bound on chain_def blob size. chain_def_codec.c caps
     * witness_count at 21 and initial_validator_count at 7 — the
     * dnac_chain_def_max_size() helper computes the exact upper bound
     * but we just use a comfortable static buffer here. */
    uint8_t blob[65536];
    size_t  blob_len = 0;
    char    err[256];
    err[0] = '\0';

    int rc = dnac_cli_genesis_prepare_blob(config_path,
                                             blob, sizeof(blob),
                                             &blob_len,
                                             err, sizeof(err));
    if (rc != 0) {
        fprintf(stderr, "genesis-prepare: %s\n",
                err[0] ? err : "(no error message)");
        return 1;
    }

    /* Hex-print to stdout so the operator can redirect into a file
     * (`... > chain_def.hex`) or pipe into `xxd -r -p` to recover the
     * binary blob for `dna genesis-create --chain-def-file`. */
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < blob_len; i++) {
        putchar(hex_digits[blob[i] >> 4]);
        putchar(hex_digits[blob[i] & 0xf]);
    }
    putchar('\n');

    fprintf(stderr, "genesis-prepare: wrote %zu bytes (hex %zu chars)\n",
            blob_len, blob_len * 2);
    return 0;
}

/* ============================================================================
 * Phase 15 / Stake & Delegation CLI helpers
 * ========================================================================== */

#include "dnac/validator.h"

/**
 * Parse a lowercase-hex Dilithium5 pubkey (5184 chars = 2 * DNAC_PUBKEY_SIZE)
 * into a caller-supplied buffer (DNAC_PUBKEY_SIZE bytes).
 *
 * Returns 0 on success, -1 on length mismatch or invalid hex.
 */
static int parse_validator_pubkey_hex(const char *hex,
                                      uint8_t out[DNAC_PUBKEY_SIZE]) {
    if (!hex || !out) return -1;
    size_t expected = (size_t)DNAC_PUBKEY_SIZE * 2;
    if (strlen(hex) != expected) return -1;
    return hex_to_bytes(hex, out, DNAC_PUBKEY_SIZE);
}

/* ============================================================================
 * Task 65 — `dna stake` verb
 * ========================================================================== */

int dna_chain_cmd_stake(dnac_context_t *ctx,
                        uint16_t commission_bps,
                        const char *unstake_to_fp) {
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) {
        fprintf(stderr, "Error: Engine not initialized\n");
        return 1;
    }

    if (commission_bps > DNAC_COMMISSION_BPS_MAX) {
        fprintf(stderr,
                "Error: commission_bps %u out of range (0..%u)\n",
                (unsigned)commission_bps,
                (unsigned)DNAC_COMMISSION_BPS_MAX);
        return 1;
    }

    /* Default unstake destination: caller's own fingerprint. */
    char self_fp[129] = {0};
    if (!unstake_to_fp || !*unstake_to_fp) {
        const char *fp = dna_engine_get_fingerprint(engine);
        if (!fp) {
            fprintf(stderr, "Error: Identity not loaded\n");
            return 1;
        }
        strncpy(self_fp, fp, 128);
        self_fp[128] = '\0';
        unstake_to_fp = self_fp;
    } else {
        /* Validate user-supplied fingerprint format. */
        if (strlen(unstake_to_fp) != 128) {
            fprintf(stderr,
                    "Error: --unstake-to fingerprint must be 128 hex chars\n");
            return 1;
        }
        for (size_t i = 0; i < 128; i++) {
            char c = unstake_to_fp[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                fprintf(stderr,
                        "Error: --unstake-to must be lowercase hex\n");
                return 1;
            }
        }
    }

    char stake_str[64];
    format_amount(DNAC_SELF_STAKE_AMOUNT, stake_str, sizeof(stake_str));
    printf("Becoming a validator...\n");
    printf("  Self-stake:       %s DNAC\n", stake_str);
    printf("  Commission:       %u bps (%.2f%%)\n",
           (unsigned)commission_bps, (double)commission_bps / 100.0);
    printf("  Unstake dest:     %.16s...\n", unstake_to_fp);

    int rc = dnac_stake(ctx, commission_bps, unstake_to_fp, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    printf("STAKE TX submitted successfully.\n");
    return 0;
}

/* ============================================================================
 * Task 66 — `dna delegate` + `dna undelegate` verbs
 *
 * Validator identifier = hex-encoded Dilithium5 pubkey (5184 chars).
 * Name/fp → pubkey resolution deferred: no direct helper currently
 * exists, and adding one would require iterating the full validator
 * table. Callers can obtain the pubkey via `dna validator-list`.
 * ========================================================================== */

int dna_chain_cmd_delegate(dnac_context_t *ctx,
                           const char *validator_pubkey_hex,
                           uint64_t amount,
                           const char *memo) {
    (void)memo;  /* Reserved for future use (builder does not take a memo) */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    if (parse_validator_pubkey_hex(validator_pubkey_hex, pubkey) != 0) {
        fprintf(stderr,
                "Error: validator pubkey must be %u lowercase hex chars\n",
                (unsigned)(DNAC_PUBKEY_SIZE * 2));
        return 1;
    }
    if (amount < DNAC_MIN_DELEGATION) {
        char min_str[64];
        format_amount(DNAC_MIN_DELEGATION, min_str, sizeof(min_str));
        fprintf(stderr,
                "Error: amount %" PRIu64 " below DNAC_MIN_DELEGATION (%s)\n",
                amount, min_str);
        return 1;
    }

    char amount_str[64];
    format_amount(amount, amount_str, sizeof(amount_str));
    printf("Delegating %s DNAC to validator %.16s...\n",
           amount_str, validator_pubkey_hex);

    int rc = dnac_delegate(ctx, pubkey, amount, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }
    printf("DELEGATE TX submitted successfully.\n");
    return 0;
}

int dna_chain_cmd_undelegate(dnac_context_t *ctx,
                             const char *validator_pubkey_hex,
                             uint64_t amount) {
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    if (parse_validator_pubkey_hex(validator_pubkey_hex, pubkey) != 0) {
        fprintf(stderr,
                "Error: validator pubkey must be %u lowercase hex chars\n",
                (unsigned)(DNAC_PUBKEY_SIZE * 2));
        return 1;
    }
    if (amount == 0) {
        fprintf(stderr, "Error: undelegate amount must be > 0\n");
        return 1;
    }

    char amount_str[64];
    format_amount(amount, amount_str, sizeof(amount_str));
    printf("Undelegating %s DNAC from validator %.16s...\n",
           amount_str, validator_pubkey_hex);

    int rc = dnac_undelegate(ctx, pubkey, amount, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }
    printf("UNDELEGATE TX submitted successfully.\n");
    return 0;
}

extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

/**
 * Query the witness-side current block height via the committee RPC.
 * Writes *out_height on success; returns 0 on success, -1 on failure.
 */
static int query_current_block_height(uint64_t *out_height) {
    if (!out_height) return -1;
    *out_height = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        fprintf(stderr, "Error: nodus not connected\n");
        return -1;
    }

    nodus_dnac_committee_result_t res = {0};
    nodus_singleton_lock();
    int rc = nodus_client_dnac_committee(client, &res);
    nodus_singleton_unlock();
    if (rc != 0) {
        fprintf(stderr,
                "Error: nodus_client_dnac_committee failed (%d)\n", rc);
        return -1;
    }
    *out_height = res.block_height;
    return 0;
}

/* ============================================================================
 * Task 68 — `dna unstake` + `dna validator-update` verbs
 *
 * unstake: fee-only TX, no appended fields. Witness enforces the
 *          "delegator_count == 0" invariant authoritatively; the CLI
 *          relies on that return code rather than attempting a pre-
 *          flight pubkey→record lookup (which would require iterating
 *          the validator table for every unstake).
 *
 * validator-update: queries chain head via the committee RPC to
 *          populate signed_at_block (Rule K freshness anchor).
 * ========================================================================== */

int dna_chain_cmd_unstake(dnac_context_t *ctx) {
    printf("Submitting UNSTAKE TX...\n");
    printf("  (validator will transition ACTIVE -> RETIRING,\n"
           "   self-stake unlocks after DNAC_UNSTAKE_COOLDOWN_BLOCKS)\n");

    int rc = dnac_unstake(ctx, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }
    printf("UNSTAKE TX submitted successfully.\n");
    return 0;
}

int dna_chain_cmd_validator_update(dnac_context_t *ctx,
                                   uint16_t commission_bps) {
    if (commission_bps > DNAC_COMMISSION_BPS_MAX) {
        fprintf(stderr,
                "Error: commission_bps %u out of range (0..%u)\n",
                (unsigned)commission_bps,
                (unsigned)DNAC_COMMISSION_BPS_MAX);
        return 1;
    }

    uint64_t head_block = 0;
    if (query_current_block_height(&head_block) != 0) {
        return 1;
    }
    if (head_block == 0) {
        fprintf(stderr,
                "Error: witness returned zero block height — chain not ready\n");
        return 1;
    }

    printf("Updating commission to %u bps (%.2f%%)...\n",
           (unsigned)commission_bps, (double)commission_bps / 100.0);
    printf("  signed_at_block = %" PRIu64 "\n", head_block);

    int rc = dnac_validator_update(ctx, commission_bps,
                                    head_block, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }
    printf("VALIDATOR_UPDATE TX submitted successfully.\n");
    return 0;
}

/* ============================================================================
 * Task 69 — Read-only verbs:
 *   `dna validator-list`, `dna committee`
 *
 * Both query the witness directly via the nodus client Phase 14
 * RPCs (bypassing the dnac_*_list / dnac_get_committee wrappers so the
 * CLI can surface witness-side fields like block_height + epoch_start
 * that the slimmer dnac_validator_list_entry_t does not carry).
 * ========================================================================== */

static const char *validator_status_str(uint8_t status) {
    switch (status) {
        case DNAC_VALIDATOR_ACTIVE:       return "ACTIVE";
        case DNAC_VALIDATOR_RETIRING:     return "RETIRING";
        case DNAC_VALIDATOR_UNSTAKED:     return "UNSTAKED";
        case DNAC_VALIDATOR_AUTO_RETIRED: return "AUTO_RETIRED";
        default:                          return "?";
    }
}

/** Print the first 16 hex chars of a DNAC pubkey (short form). */
static void pubkey_short(const uint8_t *pubkey, char out[17]) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = hexd[pubkey[i] >> 4];
        out[i * 2 + 1] = hexd[pubkey[i] & 0xf];
    }
    out[16] = '\0';
}

int dna_chain_cmd_validator_list(dnac_context_t *ctx, int filter_status) {
    (void)ctx;  /* only need nodus singleton */
    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        fprintf(stderr, "Error: nodus not connected\n");
        return 1;
    }

    nodus_dnac_validator_list_result_t res = {0};
    nodus_singleton_lock();
    int rc = nodus_client_dnac_validator_list(
            client, filter_status, /*offset=*/0, /*limit=*/100, &res);
    nodus_singleton_unlock();
    if (rc != 0) {
        fprintf(stderr,
                "Error: nodus_client_dnac_validator_list failed (%d)\n",
                rc);
        return 1;
    }

    printf("DNAC Validators (%d of %d total", res.count, res.total);
    if (filter_status >= 0) {
        printf(", status=%s", validator_status_str((uint8_t)filter_status));
    }
    printf(")\n");
    printf("%-16s  %-14s  %-18s  %-18s  %-6s  %-12s  %s\n",
           "PUBKEY", "STATUS", "SELF_STAKE", "TOTAL_DELEGATED",
           "COMM%", "EXT_DELEG", "ACTIVE_SINCE");
    printf("----------------  --------------  ------------------"
           "  ------------------  ------  ------------  ------------\n");
    for (int i = 0; i < res.count; i++) {
        const nodus_dnac_validator_list_entry_t *e = &res.entries[i];
        char pk_short[17];
        pubkey_short(e->pubkey, pk_short);
        char self_str[32], total_str[32], ext_str[32];
        format_amount(e->self_stake, self_str, sizeof(self_str));
        format_amount(e->total_delegated, total_str, sizeof(total_str));
        format_amount(e->external_delegated, ext_str, sizeof(ext_str));
        printf("%-16s  %-14s  %-18s  %-18s  %5.2f  %-12s  %" PRIu64 "\n",
               pk_short,
               validator_status_str(e->status),
               self_str, total_str,
               (double)e->commission_bps / 100.0,
               ext_str,
               e->active_since_block);
    }
    nodus_client_free_validator_list_result(&res);
    return 0;
}

int dna_chain_cmd_committee(dnac_context_t *ctx) {
    (void)ctx;
    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        fprintf(stderr, "Error: nodus not connected\n");
        return 1;
    }

    nodus_dnac_committee_result_t res = {0};
    nodus_singleton_lock();
    int rc = nodus_client_dnac_committee(client, &res);
    nodus_singleton_unlock();
    if (rc != 0) {
        fprintf(stderr,
                "Error: nodus_client_dnac_committee failed (%d)\n", rc);
        return 1;
    }

    printf("DNAC Committee (epoch_start=%" PRIu64 ", head=%" PRIu64 ")\n",
           res.epoch_start, res.block_height);
    printf("%-4s  %-16s  %-14s  %-18s  %-6s  %s\n",
           "SLOT", "PUBKEY", "STATUS", "TOTAL_STAKE", "COMM%", "ADDRESS");
    printf("----  ----------------  --------------  ------------------"
           "  ------  ----------------------------------\n");
    for (int i = 0; i < res.count; i++) {
        const nodus_dnac_committee_entry_t *e = &res.entries[i];
        char pk_short[17];
        pubkey_short(e->pubkey, pk_short);
        char stake_str[32];
        format_amount(e->total_stake, stake_str, sizeof(stake_str));
        printf("%-4d  %-16s  %-14s  %-18s  %5.2f  %s\n",
               i, pk_short,
               validator_status_str(e->status),
               stake_str,
               (double)e->commission_bps / 100.0,
               e->address[0] ? e->address : "(unknown)");
    }
    return 0;
}

