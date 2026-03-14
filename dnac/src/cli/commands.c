/**
 * @file commands.c
 * @brief DNAC CLI command implementations
 */

#include "dnac/cli.h"
#include "dnac/dnac.h"
#include "dnac/wallet.h"
#include "dnac/transaction.h"
#include "dnac/version.h"
#include <dna/dna_engine.h>
#include "nodus_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * Format amount for display (with decimal point)
 * Assumes 8 decimal places like satoshis
 */
static void format_amount(uint64_t amount, char *buf, size_t buf_len) {
    uint64_t whole = amount / 100000000;
    uint64_t frac = amount % 100000000;

    if (frac == 0) {
        snprintf(buf, buf_len, "%" PRIu64, whole);
    } else {
        snprintf(buf, buf_len, "%" PRIu64 ".%08" PRIu64, whole, frac);
        /* Trim trailing zeros */
        size_t len = strlen(buf);
        while (len > 0 && buf[len - 1] == '0') {
            buf[--len] = '\0';
        }
    }
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

int dnac_cli_balance(dnac_context_t *ctx) {
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

    return 0;
}

int dnac_cli_utxos(dnac_context_t *ctx) {
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

int dnac_cli_send(dnac_context_t *ctx, const char *recipient,
                  uint64_t amount, const char *memo) {
    /* Validate fingerprint early */
    size_t fp_len = strlen(recipient);
    if (fp_len != 128) {
        fprintf(stderr, "Error: Invalid fingerprint length %zu (expected 128 hex chars)\n", fp_len);
        return 1;
    }
    for (size_t i = 0; i < 128; i++) {
        char c = recipient[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            fprintf(stderr, "Error: Invalid character '%c' at position %zu in fingerprint\n", c, i);
            return 1;
        }
    }

    char amount_str[64];
    format_amount(amount, amount_str, sizeof(amount_str));

    printf("Sending %s to %s...\n", amount_str, recipient);

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
    rc = dnac_send(ctx, recipient, amount, memo, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    printf("Payment sent successfully!\n");

    /* Allow DHT time to replicate the published TX data */
    printf("Waiting for DHT propagation...\n");
    sleep(5);

    return 0;
}

int dnac_cli_sync(dnac_context_t *ctx) {
    printf("Syncing wallet from DHT...\n");

    int rc = dnac_sync_wallet(ctx);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    printf("Sync complete.\n");
    return 0;
}

int dnac_cli_history(dnac_context_t *ctx, int limit) {
    dnac_tx_history_t *history = NULL;
    int count = 0;

    int rc = dnac_get_history(ctx, &history, &count);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    if (count == 0) {
        printf("No transaction history.\n");
        return 0;
    }

    int display_count = (limit > 0 && limit < count) ? limit : count;

    printf("DNAC Transaction History (%d entries)\n", display_count);
    printf("%-20s  %-8s  %-16s  %-12s\n", "DATE", "TYPE", "AMOUNT", "COUNTERPARTY");
    printf("--------------------  --------  ----------------  ------------\n");

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

        printf("%-20s  %-8s  %-16s  %-12s\n", time_str, type_str, amount_str, cp_short);
    }

    dnac_free_history(history, count);
    return 0;
}

int dnac_cli_tx_details(dnac_context_t *ctx, const char *tx_hash_hex) {
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

int dnac_cli_nodus_list(dnac_context_t *ctx) {
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


int dnac_cli_info(dnac_context_t *ctx) {
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

int dnac_cli_address(dnac_context_t *ctx) {
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

int dnac_cli_query(dnac_context_t *ctx, const char *query) {
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

void dnac_cli_print_help(void) {
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
    printf("  nodus-list       List Nodus servers\n\n");
    printf("Examples:\n");
    printf("  dnac-cli balance\n");
    printf("  dnac-cli send abc123...def 1000000\n");
    printf("  dnac-cli sync\n");
    printf("  dnac-cli history 10\n");
}

void dnac_cli_print_version(void) {
    printf("dnac-cli version %s\n", DNAC_VERSION_STRING);
    printf("DNAC - Post-Quantum Digital Cash over DHT\n");
    printf("Protocol version: v%d\n", DNAC_PROTOCOL_VERSION);
}
