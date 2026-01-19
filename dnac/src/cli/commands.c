/**
 * @file commands.c
 * @brief DNAC CLI command implementations
 */

#include "dnac/cli.h"
#include "dnac/dnac.h"
#include "dnac/version.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

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

/**
 * Convert bytes to hex string
 */
static void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", data[i]);
    }
    out[len * 2] = '\0';
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
            case DNAC_TX_MINT:  type_str = "mint";  break;
            case DNAC_TX_SPEND: type_str = "spend"; break;
            case DNAC_TX_BURN:  type_str = "burn";  break;
            default:            type_str = "?";     break;
        }

        /* Truncate counterparty for display */
        char cp_short[13] = "";
        if (history[i].counterparty[0]) {
            strncpy(cp_short, history[i].counterparty, 8);
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
        case DNAC_TX_MINT:  type_str = "MINT";  break;
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
    dnac_nodus_info_t *servers = NULL;
    int count = 0;

    int rc = dnac_get_nodus_list(ctx, &servers, &count);
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
            strncpy(fp_short, servers[i].fingerprint, 8);
            strcat(fp_short, "...");
        }

        printf("%-4d  %-30s  %-10s  %-12s\n", i + 1, servers[i].address, status, fp_short);
    }

    dnac_free_nodus_list(servers, count);
    return 0;
}

int dnac_cli_recover(dnac_context_t *ctx) {
    printf("Recovering wallet from DHT...\n");
    printf("WARNING: This will clear existing UTXOs and re-scan from network.\n");

    int recovered_count = 0;
    int rc = dnac_wallet_recover(ctx, &recovered_count);

    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error: %s\n", dnac_error_string(rc));
        return 1;
    }

    printf("Recovery complete. %d UTXO(s) recovered.\n", recovered_count);

    /* Show balance after recovery */
    dnac_balance_t balance;
    rc = dnac_get_balance(ctx, &balance);
    if (rc == DNAC_SUCCESS) {
        char confirmed_str[64];
        format_amount(balance.confirmed, confirmed_str, sizeof(confirmed_str));
        printf("Current balance: %s\n", confirmed_str);
    }

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
    printf("  balance          Show wallet balance\n");
    printf("  utxos            List unspent transaction outputs\n");
    printf("  send <fp> <amt>  Send payment to fingerprint\n");
    printf("  sync             Sync wallet from DHT network\n");
    printf("  recover          Recover wallet from seed (re-scan DHT)\n");
    printf("  history [n]      Show transaction history (last n entries)\n");
    printf("  tx <hash>        Show transaction details\n");
    printf("  nodus-list       List Nodus servers\n\n");
    printf("Examples:\n");
    printf("  dnac-cli balance\n");
    printf("  dnac-cli send abc123...def 1000000\n");
    printf("  dnac-cli recover\n");
    printf("  dnac-cli history 10\n");
}

void dnac_cli_print_version(void) {
    printf("dnac-cli version %s\n", DNAC_VERSION_STRING);
    printf("DNAC - Post-Quantum Digital Cash over DHT\n");
    printf("Protocol version: v%d\n", DNAC_PROTOCOL_VERSION);
}
