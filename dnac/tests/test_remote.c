/**
 * @file test_remote.c
 * @brief Remote send test - sends DNAC to a different machine
 *
 * This test sends coins to a REMOTE recipient (not self).
 * Unlike test_real.c which sends to itself, this tests actual
 * cross-machine payment delivery.
 *
 * Usage:
 *   ./test_remote <recipient_fingerprint> [amount]
 *
 * Example:
 *   ./test_remote c888ed5b8fcbb97c... 5000
 *
 * The recipient fingerprint is the target wallet's DNA identity
 * fingerprint (64 hex characters, full or truncated).
 *
 * Requirements:
 * - At least 2 witness servers running
 * - DHT connectivity
 * - Recipient must have a valid DNAC-compatible identity
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <ctype.h>

#include "dnac/dnac.h"
#include "dnac/wallet.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"

#include <dna/dna_engine.h>
#include "nodus_ops.h"

/* ============================================================================
 * Test State
 * ========================================================================== */

static dna_engine_t *g_engine = NULL;
static dnac_context_t *g_ctx = NULL;
static char g_test_dir[512];
static char g_our_fingerprint[DNAC_FINGERPRINT_SIZE];
static char g_recipient_fingerprint[DNAC_FINGERPRINT_SIZE];
static uint64_t g_send_amount = 1000;  /* Default: 1000 satoshis */

/* For sync operations */
static pthread_mutex_t g_sync_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_sync_cond = PTHREAD_COND_INITIALIZER;
static volatile int g_sync_done = 0;
static volatile int g_sync_result = 0;

/* ============================================================================
 * Helpers
 * ========================================================================== */

static void sync_callback(unsigned long request_id, int result, void *user_data) {
    (void)request_id;
    (void)user_data;
    pthread_mutex_lock(&g_sync_mutex);
    g_sync_result = result;
    g_sync_done = 1;
    pthread_cond_signal(&g_sync_cond);
    pthread_mutex_unlock(&g_sync_mutex);
}

static int wait_for_sync(int timeout_sec) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_sec;

    pthread_mutex_lock(&g_sync_mutex);
    while (!g_sync_done) {
        if (pthread_cond_timedwait(&g_sync_cond, &g_sync_mutex, &ts) != 0) {
            pthread_mutex_unlock(&g_sync_mutex);
            return -1;  /* Timeout */
        }
    }
    int result = g_sync_result;
    g_sync_done = 0;
    pthread_mutex_unlock(&g_sync_mutex);
    return result;
}

/**
 * Validate fingerprint format (hex string, reasonable length)
 */
static int validate_fingerprint(const char *fp) {
    if (!fp || !fp[0]) return 0;

    size_t len = strlen(fp);
    if (len < 16 || len > 128) return 0;  /* Must be at least 16 chars */

    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)fp[i])) return 0;
    }
    return 1;
}

static void print_usage(const char *prog) {
    printf("Usage: %s <recipient_fingerprint> [amount]\n", prog);
    printf("\n");
    printf("Arguments:\n");
    printf("  recipient_fingerprint  Target wallet's DNA identity fingerprint\n");
    printf("                         (64+ hex characters, e.g., c888ed5b8fcbb97c...)\n");
    printf("  amount                 Amount to send in satoshis (default: 1000)\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s c888ed5b8fcbb97c1234567890abcdef... 5000\n", prog);
    printf("\n");
    printf("To get a machine's fingerprint, run dnac-cli info on that machine.\n");
}

/* ============================================================================
 * Test Environment Setup/Teardown
 * ========================================================================== */

static int setup_test_env(void) {
    printf("=== SETUP: Initializing test environment ===\n");

    const char *home = getenv("HOME");
    if (!home) home = "/root";

    snprintf(g_test_dir, sizeof(g_test_dir), "%s/.dna", home);
    printf("  DNA directory: %s\n", g_test_dir);

    g_engine = dna_engine_create(g_test_dir);
    if (!g_engine) {
        fprintf(stderr, "FATAL: Failed to create DNA engine\n");
        return -1;
    }

    if (!dna_engine_has_identity(g_engine)) {
        fprintf(stderr, "FATAL: No DNA identity found. Run dna-messenger first.\n");
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        return -1;
    }

    dna_request_id_t req = dna_engine_load_identity(g_engine, "", NULL,
                                                     sync_callback, NULL);
    if (req == 0) {
        fprintf(stderr, "FATAL: Failed to start identity load\n");
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        return -1;
    }

    int rc = wait_for_sync(1800);  /* 30 minute timeout for DHT bootstrap */
    printf("  Identity load result: %d\n", rc);

    const char *loaded_fp = dna_engine_get_fingerprint(g_engine);
    if (!loaded_fp || !loaded_fp[0]) {
        fprintf(stderr, "FATAL: Identity not loaded: no fingerprint\n");
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        return -1;
    }
    strncpy(g_our_fingerprint, loaded_fp, sizeof(g_our_fingerprint) - 1);
    printf("  Our fingerprint: %.32s...\n", g_our_fingerprint);

    /* Check if trying to send to self */
    if (strncmp(g_our_fingerprint, g_recipient_fingerprint,
                strlen(g_recipient_fingerprint)) == 0) {
        fprintf(stderr, "\nWARNING: Recipient fingerprint matches our own!\n");
        fprintf(stderr, "This test is meant for sending to a DIFFERENT machine.\n");
        fprintf(stderr, "Use test_real for self-send tests.\n\n");
    }

    /* Wait for DHT */
    bool dht_ready = nodus_ops_is_ready();

    if (!dht_ready) {
        printf("  Waiting for DHT (30s)...\n");
        struct timespec ts = {0, 100000000};  /* 100ms */
        for (int i = 0; i < 300; i++) {
            nanosleep(&ts, NULL);
            if (nodus_ops_is_ready()) {
                printf("  DHT ready after %.1f seconds\n", (i+1) * 0.1);
                dht_ready = true;
                break;
            }
        }
    }

    if (!dht_ready) {
        fprintf(stderr, "FATAL: DHT not ready after 30s\n");
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        return -1;
    }

    g_ctx = dnac_init(g_engine);
    if (!g_ctx) {
        fprintf(stderr, "FATAL: Failed to initialize DNAC context\n");
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        return -1;
    }

    printf("  DNAC context initialized\n");
    printf("=== SETUP COMPLETE ===\n\n");
    return 0;
}

static void cleanup_test_env(void) {
    printf("\n=== CLEANUP ===\n");

    if (g_ctx) {
        dnac_shutdown(g_ctx);
        g_ctx = NULL;
        printf("  DNAC context shutdown\n");
    }

    if (g_engine) {
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        printf("  DNA engine destroyed\n");
    }

    printf("=== CLEANUP COMPLETE ===\n");
}

/* ============================================================================
 * Test Steps
 * ========================================================================== */

/**
 * STEP 1: Check current balance
 */
static int step_check_balance(uint64_t *balance_out) {
    printf("STEP 1: CHECK BALANCE - Verifying sufficient funds...\n");

    dnac_sync_wallet(g_ctx);

    dnac_balance_t balance;
    int rc = dnac_get_balance(g_ctx, &balance);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_get_balance returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }

    printf("  Balance: confirmed=%lu, pending=%lu, utxos=%d\n",
           (unsigned long)balance.confirmed,
           (unsigned long)balance.pending,
           balance.utxo_count);

    if (balance.confirmed < g_send_amount) {
        fprintf(stderr, "  FAIL: Insufficient balance. Have %lu, need %lu\n",
                (unsigned long)balance.confirmed,
                (unsigned long)g_send_amount);
        fprintf(stderr, "\n  TIP: Run './test_real' first to mint some coins.\n");
        return -1;
    }

    *balance_out = balance.confirmed;
    printf("  PASS: Sufficient balance (%lu >= %lu)\n",
           (unsigned long)balance.confirmed,
           (unsigned long)g_send_amount);
    return 0;
}

/**
 * STEP 2: Check witnesses
 */
static int step_check_witnesses(void) {
    printf("STEP 2: CHECK WITNESSES - Verifying witness availability...\n");

    dnac_witness_info_t *servers = NULL;
    int server_count = 0;
    int rc = dnac_witness_discover(g_ctx, &servers, &server_count);
    if (rc != DNAC_SUCCESS || server_count < DNAC_WITNESSES_REQUIRED) {
        fprintf(stderr, "  FAIL: Need %d+ witnesses, found %d\n",
                DNAC_WITNESSES_REQUIRED, server_count);
        if (servers) dnac_free_witness_list(servers, server_count);
        return -1;
    }

    printf("  Found %d witnesses:\n", server_count);
    for (int i = 0; i < server_count; i++) {
        printf("    [%d] %.16s... at %s\n",
               i,
               servers[i].id,
               servers[i].address);
    }

    dnac_free_witness_list(servers, server_count);
    printf("  PASS: %d witnesses available\n", server_count);
    return 0;
}

/**
 * STEP 3: Send to remote recipient
 */
static int step_send_remote(void) {
    printf("STEP 3: SEND REMOTE - Sending %lu to %.32s...\n",
           (unsigned long)g_send_amount, g_recipient_fingerprint);

    printf("  Sender:    %.32s...\n", g_our_fingerprint);
    printf("  Recipient: %.32s...\n", g_recipient_fingerprint);
    printf("  Amount:    %lu satoshis\n", (unsigned long)g_send_amount);

    char memo[128];
    snprintf(memo, sizeof(memo), "test_remote.c payment at %lu", (unsigned long)time(NULL));

    int rc = dnac_send(g_ctx, g_recipient_fingerprint, g_send_amount, memo, NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_send returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }

    printf("  PASS: Sent %lu coins to remote recipient\n", (unsigned long)g_send_amount);
    return 0;
}

/**
 * STEP 4: Verify balance changed
 */
static int step_verify_balance(uint64_t original_balance) {
    printf("STEP 4: VERIFY - Checking balance after send...\n");

    /* Brief delay for processing */
    struct timespec ts = {1, 0};
    nanosleep(&ts, NULL);

    dnac_sync_wallet(g_ctx);

    dnac_balance_t balance;
    int rc = dnac_get_balance(g_ctx, &balance);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_get_balance returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }

    printf("  Original balance: %lu\n", (unsigned long)original_balance);
    printf("  New balance:      %lu\n", (unsigned long)balance.confirmed);
    printf("  Difference:       %lu (includes fee)\n",
           (unsigned long)(original_balance - balance.confirmed));

    /* Balance should be reduced by at least send_amount */
    if (balance.confirmed >= original_balance) {
        fprintf(stderr, "  FAIL: Balance did not decrease!\n");
        return -1;
    }

    uint64_t diff = original_balance - balance.confirmed;
    if (diff < g_send_amount) {
        fprintf(stderr, "  FAIL: Balance decreased by less than send amount\n");
        return -1;
    }

    printf("  PASS: Balance correctly decreased\n");
    return 0;
}

/**
 * STEP 5: Print receipt
 */
static void step_print_receipt(uint64_t original_balance) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    TRANSACTION RECEIPT                        ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Sender:    %.32s...  ║\n", g_our_fingerprint);
    printf("║  Recipient: %.32s...  ║\n", g_recipient_fingerprint);
    printf("║  Amount:    %-10lu satoshis                             ║\n", (unsigned long)g_send_amount);
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  To verify receipt on remote machine, run:                    ║\n");
    printf("║    dnac-cli sync && dnac-cli balance                         ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    (void)original_balance;
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* Parse recipient fingerprint */
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (!validate_fingerprint(argv[1])) {
        fprintf(stderr, "ERROR: Invalid fingerprint format: %s\n", argv[1]);
        fprintf(stderr, "       Fingerprint must be 16+ hex characters.\n");
        return 1;
    }
    strncpy(g_recipient_fingerprint, argv[1], sizeof(g_recipient_fingerprint) - 1);

    /* Parse optional amount */
    if (argc >= 3) {
        g_send_amount = (uint64_t)atoll(argv[2]);
        if (g_send_amount == 0) {
            fprintf(stderr, "ERROR: Invalid amount: %s\n", argv[2]);
            return 1;
        }
    }

    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║          DNAC Remote Send Test (test_remote.c)               ║\n");
    printf("║                                                               ║\n");
    printf("║  Sends coins to a REMOTE recipient (different machine)       ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Recipient: %-48.48s...║\n", g_recipient_fingerprint);
    printf("║  Amount:    %-10lu satoshis                             ║\n", (unsigned long)g_send_amount);
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");

    /* Setup */
    if (setup_test_env() != 0) {
        fprintf(stderr, "\nFATAL: Failed to setup test environment\n");
        return 1;
    }

    int failed = 0;
    uint64_t original_balance = 0;

    /* STEP 1: Check balance */
    if (step_check_balance(&original_balance) != 0) {
        fprintf(stderr, "\nFAILED at STEP 1: CHECK BALANCE\n");
        failed++;
    }

    /* STEP 2: Check witnesses */
    if (!failed && step_check_witnesses() != 0) {
        fprintf(stderr, "\nFAILED at STEP 2: CHECK WITNESSES\n");
        failed++;
    }

    /* STEP 3: Send remote */
    if (!failed && step_send_remote() != 0) {
        fprintf(stderr, "\nFAILED at STEP 3: SEND REMOTE\n");
        failed++;
    }

    /* STEP 4: Verify balance */
    if (!failed && step_verify_balance(original_balance) != 0) {
        fprintf(stderr, "\nFAILED at STEP 4: VERIFY\n");
        failed++;
    }

    /* Print receipt */
    if (!failed) {
        step_print_receipt(original_balance);
    }

    /* Cleanup */
    cleanup_test_env();

    /* Results */
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    if (failed == 0) {
        printf("║              REMOTE SEND TEST PASSED                         ║\n");
    } else {
        printf("║              REMOTE SEND TEST FAILED                         ║\n");
    }
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    return failed > 0 ? 1 : 0;
}
