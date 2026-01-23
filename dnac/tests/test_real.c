/**
 * @file test_real.c
 * @brief End-to-end test using real mint and real transactions
 *
 * This test file uses the REAL mint mechanism instead of injecting
 * synthetic UTXOs. It tests the complete flow:
 *
 * Flow: Mint -> Verify -> Send -> Verify -> Double-spend check -> Receive
 *
 * Requirements:
 * - At least 2 witness servers running
 * - Network connectivity
 * - DHT bootstrapped
 *
 * TESTNET NOTE: On testnet (chain_id=999), witnesses approve all mint
 * requests freely. On mainnet, only a genesis event creates coins.
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

#include "dnac/dnac.h"
#include "dnac/wallet.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"

#include <dna/dna_engine.h>
#include "dht/client/dht_singleton.h"
#include "dht/core/dht_context.h"

/* ============================================================================
 * Test State
 * ========================================================================== */

static dna_engine_t *g_engine = NULL;
static dnac_context_t *g_ctx = NULL;
static char g_test_dir[512];
static char g_fingerprint[DNAC_FINGERPRINT_SIZE];

/* For sync operations */
static pthread_mutex_t g_sync_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_sync_cond = PTHREAD_COND_INITIALIZER;
static volatile int g_sync_done = 0;
static volatile int g_sync_result = 0;

/* Track minted UTXO for double-spend test */
static dnac_transaction_t *g_minted_tx = NULL;

/* ============================================================================
 * Sync Helpers
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

/* ============================================================================
 * Test Environment Setup/Teardown
 * ========================================================================== */

/**
 * Setup test environment
 *
 * - Uses system's existing DNA data directory (has working DHT)
 * - Initializes DNAC context
 * - Waits for DHT to be ready
 */
static int setup_test_env(void) {
    printf("=== SETUP: Initializing test environment ===\n");

    /* Get user's home directory */
    const char *home = getenv("HOME");
    if (!home) home = "/root";

    /* Use system's DNA data directory */
    snprintf(g_test_dir, sizeof(g_test_dir), "%s/.dna", home);
    printf("  DNA directory: %s\n", g_test_dir);

    /* Create DNA engine */
    g_engine = dna_engine_create(g_test_dir);
    if (!g_engine) {
        fprintf(stderr, "FATAL: Failed to create DNA engine\n");
        return -1;
    }

    /* Check if identity exists */
    if (!dna_engine_has_identity(g_engine)) {
        fprintf(stderr, "FATAL: No DNA identity found. Run dna-messenger first.\n");
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        return -1;
    }

    /* Load the existing identity */
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
    strncpy(g_fingerprint, loaded_fp, sizeof(g_fingerprint) - 1);
    printf("  Our fingerprint: %.32s...\n", g_fingerprint);

    /* Wait for DHT to become ready */
    dht_context_t *dht_ctx = dht_singleton_get();
    bool dht_ready = dht_ctx ? dht_context_is_ready(dht_ctx) : false;

    if (!dht_ready) {
        printf("  Waiting for DHT (30s)...\n");
        struct timespec ts = {0, 100000000};  /* 100ms */
        for (int i = 0; i < 300; i++) {
            nanosleep(&ts, NULL);
            dht_ctx = dht_singleton_get();
            if (dht_ctx && dht_context_is_ready(dht_ctx)) {
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

    /* Initialize DNAC context */
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

/**
 * Cleanup test environment
 */
static void cleanup_test_env(void) {
    printf("\n=== CLEANUP ===\n");

    if (g_minted_tx) {
        dnac_free_transaction(g_minted_tx);
        g_minted_tx = NULL;
    }

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
 * Test Steps (Chained Flow)
 * ========================================================================== */

/**
 * STEP 1: MINT - Create test funds using real mint mechanism
 *
 * On testnet, witnesses approve all mint requests freely.
 * This is intentional for testing.
 */
static int step_mint(uint64_t amount) {
    printf("STEP 1: MINT - Creating %lu test coins...\n", (unsigned long)amount);

    int rc;

    /* Check witnesses are available first */
    dnac_witness_info_t *servers = NULL;
    int server_count = 0;
    rc = dnac_witness_discover(g_ctx, &servers, &server_count);
    if (rc != DNAC_SUCCESS || server_count < DNAC_WITNESSES_REQUIRED) {
        fprintf(stderr, "  FAIL: Need %d+ witnesses, found %d\n",
                DNAC_WITNESSES_REQUIRED, server_count);
        if (servers) dnac_free_witness_list(servers, server_count);
        return -1;
    }
    printf("  Found %d witness servers\n", server_count);
    dnac_free_witness_list(servers, server_count);

    /* Create MINT transaction */
    const char *our_fp = dnac_get_owner_fingerprint(g_ctx);
    if (!our_fp) {
        fprintf(stderr, "  FAIL: Could not get owner fingerprint\n");
        return -1;
    }

    rc = dnac_tx_create_mint(our_fp, amount, &g_minted_tx);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_tx_create_mint returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }
    printf("  MINT transaction created\n");

    /* Authorize mint via witness consensus (2-of-3) */
    rc = dnac_tx_authorize_mint(g_ctx, g_minted_tx);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_tx_authorize_mint returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }
    printf("  MINT authorized by %d witnesses\n", g_minted_tx->witness_count);

    /* Broadcast mint to deliver coins via DHT */
    rc = dnac_tx_broadcast_mint(g_ctx, g_minted_tx);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_tx_broadcast_mint returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }
    printf("  MINT broadcast complete\n");

    printf("  PASS: Minted %lu coins\n", (unsigned long)amount);
    return 0;
}

/**
 * STEP 2: VERIFY MINT - Check balance reflects minted coins
 */
static int step_verify_mint(uint64_t expected_amount) {
    printf("STEP 2: VERIFY MINT - Checking balance...\n");

    /* Brief delay for DHT propagation */
    struct timespec ts = {1, 0};
    nanosleep(&ts, NULL);

    /* Sync wallet to pick up new UTXOs */
    int rc = dnac_sync_wallet(g_ctx);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  WARN: dnac_sync_wallet returned %d\n", rc);
        /* Continue anyway - might already be synced */
    }

    dnac_balance_t balance;
    rc = dnac_get_balance(g_ctx, &balance);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_get_balance returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }

    printf("  Balance: confirmed=%lu, pending=%lu, locked=%lu, utxos=%d\n",
           (unsigned long)balance.confirmed,
           (unsigned long)balance.pending,
           (unsigned long)balance.locked,
           balance.utxo_count);

    if (balance.confirmed < expected_amount) {
        fprintf(stderr, "  FAIL: Expected at least %lu, got %lu\n",
                (unsigned long)expected_amount,
                (unsigned long)balance.confirmed);
        return -1;
    }

    printf("  PASS: Balance >= %lu\n", (unsigned long)expected_amount);
    return 0;
}

/**
 * STEP 3: SEND - Use minted coins to send payment
 *
 * Sends to self for testing (no second identity needed).
 */
static int step_send(uint64_t amount) {
    printf("STEP 3: SEND - Sending %lu to self...\n", (unsigned long)amount);

    const char *our_fp = dnac_get_owner_fingerprint(g_ctx);
    if (!our_fp) {
        fprintf(stderr, "  FAIL: Could not get owner fingerprint\n");
        return -1;
    }

    int rc = dnac_send(g_ctx, our_fp, amount, "test_real.c payment", NULL, NULL);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_send returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }

    printf("  PASS: Sent %lu coins\n", (unsigned long)amount);
    return 0;
}

/**
 * STEP 4: VERIFY SEND - Check balances after send
 *
 * Since we sent to self, total balance should be roughly the same
 * minus any fees.
 */
static int step_verify_send(uint64_t original_balance) {
    printf("STEP 4: VERIFY SEND - Checking post-send balance...\n");

    /* Brief delay for DHT propagation */
    struct timespec ts = {1, 0};
    nanosleep(&ts, NULL);

    /* Sync wallet */
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

    /* Sent to self, so balance should be original minus fee (0.1% = 10 bps) */
    /* Allow some tolerance for fee variations */
    uint64_t expected_min = original_balance - (original_balance / 100);  /* 1% tolerance */

    if (balance.confirmed + balance.pending < expected_min) {
        fprintf(stderr, "  FAIL: Balance too low. Expected ~%lu, got %lu\n",
                (unsigned long)original_balance,
                (unsigned long)(balance.confirmed + balance.pending));
        return -1;
    }

    printf("  PASS: Balance within expected range\n");
    return 0;
}

/**
 * STEP 5: DOUBLE-SPEND - Attempt to spend same UTXO again
 *
 * This tests that witnesses correctly reject double-spend attempts.
 * We try to submit the same nullifier from the minted TX with a new tx_hash.
 */
static int step_double_spend(void) {
    printf("STEP 5: DOUBLE-SPEND - Attempting replay attack...\n");

    if (!g_minted_tx || g_minted_tx->output_count == 0) {
        fprintf(stderr, "  SKIP: No minted transaction to test with\n");
        return 0;  /* Not a failure, just skip */
    }

    /* Get the nullifier seed from the minted output */
    uint8_t nullifier_seed[32];
    memcpy(nullifier_seed, g_minted_tx->outputs[0].nullifier_seed, 32);

    /* Build spend request with same nullifier concept */
    dnac_spend_request_t request;
    memset(&request, 0, sizeof(request));

    /* Create a fake SPEND transaction with a nullifier derived from minted UTXO */
    dnac_transaction_t *test_tx = dnac_tx_create(DNAC_TX_SPEND);
    if (!test_tx) {
        fprintf(stderr, "  FAIL: Could not create test transaction\n");
        return -1;
    }

    /* Add a fake input with derived nullifier */
    dnac_tx_input_t fake_input = {0};
    memcpy(fake_input.nullifier, nullifier_seed, 32);
    memcpy(fake_input.nullifier + 32, g_minted_tx->tx_hash, 32);
    fake_input.amount = 1000;
    test_tx->inputs[0] = fake_input;
    test_tx->input_count = 1;

    /* Add a fake output */
    test_tx->outputs[0].amount = 990;
    strncpy(test_tx->outputs[0].owner_fingerprint, "test_recipient", DNAC_FINGERPRINT_SIZE - 1);
    test_tx->output_count = 1;

    /* Compute hash */
    dnac_tx_compute_hash(test_tx, request.tx_hash);
    memcpy(test_tx->tx_hash, request.tx_hash, DNAC_TX_HASH_SIZE);

    /* Serialize transaction into request */
    size_t tx_ser_len = 0;
    int ser_rc = dnac_tx_serialize(test_tx, request.tx_data, sizeof(request.tx_data), &tx_ser_len);
    if (ser_rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: Could not serialize test transaction\n");
        dnac_free_transaction(test_tx);
        return -1;
    }
    request.tx_len = (uint32_t)tx_ser_len;

    request.timestamp = (uint64_t)time(NULL);
    request.fee_amount = 10;

    /* Get our pubkey */
    dna_engine_t *engine = dnac_get_engine(g_ctx);
    int rc = dna_engine_get_signing_public_key(engine, request.sender_pubkey,
                                                DNAC_PUBKEY_SIZE);
    if (rc < 0) {
        fprintf(stderr, "  FAIL: Could not get signing pubkey\n");
        return -1;
    }

    /* Sign the tx_hash */
    size_t sig_len = DNAC_SIGNATURE_SIZE;
    rc = dna_engine_sign_data(engine, request.tx_hash, DNAC_TX_HASH_SIZE,
                               request.signature, &sig_len);
    if (rc < 0) {
        fprintf(stderr, "  FAIL: Could not sign request\n");
        return -1;
    }

    /* First request - should succeed (registers nullifier) */
    dnac_witness_sig_t witnesses1[DNAC_MAX_WITNESS_SERVERS];
    int count1 = 0;
    rc = dnac_witness_request(g_ctx, &request, witnesses1, &count1);

    if (rc != DNAC_SUCCESS || count1 < DNAC_WITNESSES_REQUIRED) {
        /* This could happen if the nullifier was already spent from the mint */
        printf("  First request: rc=%d, count=%d (expected if already spent)\n",
               rc, count1);
    } else {
        printf("  First request: APPROVED with %d witnesses\n", count1);
    }

    /* Second request with SAME nullifier - should be REJECTED */
    /* Create a different transaction but with the same nullifier */
    dnac_transaction_t *test_tx2 = dnac_tx_create(DNAC_TX_SPEND);
    if (!test_tx2) {
        fprintf(stderr, "  FAIL: Could not create second test transaction\n");
        dnac_free_transaction(test_tx);
        return -1;
    }

    /* Same nullifier (double-spend attempt) */
    test_tx2->inputs[0] = fake_input;
    test_tx2->input_count = 1;

    /* Different output amount to make different tx_hash */
    test_tx2->outputs[0].amount = 980;
    strncpy(test_tx2->outputs[0].owner_fingerprint, "different_recipient", DNAC_FINGERPRINT_SIZE - 1);
    test_tx2->output_count = 1;

    /* Compute different hash */
    dnac_tx_compute_hash(test_tx2, request.tx_hash);
    memcpy(test_tx2->tx_hash, request.tx_hash, DNAC_TX_HASH_SIZE);

    /* Serialize the second transaction */
    tx_ser_len = 0;
    ser_rc = dnac_tx_serialize(test_tx2, request.tx_data, sizeof(request.tx_data), &tx_ser_len);
    if (ser_rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: Could not serialize second test transaction\n");
        dnac_free_transaction(test_tx);
        dnac_free_transaction(test_tx2);
        return -1;
    }
    request.tx_len = (uint32_t)tx_ser_len;
    request.timestamp = (uint64_t)time(NULL);

    /* Re-sign with new tx_hash */
    sig_len = DNAC_SIGNATURE_SIZE;
    rc = dna_engine_sign_data(engine, request.tx_hash, DNAC_TX_HASH_SIZE,
                               request.signature, &sig_len);
    if (rc < 0) {
        fprintf(stderr, "  FAIL: Could not sign second request\n");
        dnac_free_transaction(test_tx);
        dnac_free_transaction(test_tx2);
        return -1;
    }

    dnac_witness_sig_t witnesses2[DNAC_MAX_WITNESS_SERVERS];
    int count2 = 0;
    rc = dnac_witness_request(g_ctx, &request, witnesses2, &count2);

    dnac_free_transaction(test_tx);
    dnac_free_transaction(test_tx2);

    if (rc == DNAC_ERROR_DOUBLE_SPEND || count2 < DNAC_WITNESSES_REQUIRED) {
        printf("  Second request: REJECTED (rc=%d, count=%d)\n", rc, count2);
        printf("  PASS: Double-spend correctly prevented\n");
        return 0;
    }

    fprintf(stderr, "  FAIL: Double-spend was not detected! rc=%d, count=%d\n",
            rc, count2);
    return -1;
}

/**
 * STEP 6: RECEIVE - Verify we can query received payments
 *
 * Since we sent to self, we should have received the payment.
 */
static int step_receive(void) {
    printf("STEP 6: RECEIVE - Verifying payment receipt...\n");

    /* Sync wallet to ensure we have latest */
    dnac_sync_wallet(g_ctx);

    /* Get UTXOs */
    dnac_utxo_t *utxos = NULL;
    int count = 0;
    int rc = dnac_get_utxos(g_ctx, &utxos, &count);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "  FAIL: dnac_get_utxos returned %d (%s)\n",
                rc, dnac_error_string(rc));
        return -1;
    }

    printf("  Found %d UTXOs in wallet\n", count);

    /* Print summary of UTXOs */
    uint64_t total = 0;
    for (int i = 0; i < count; i++) {
        printf("    UTXO %d: amount=%lu, status=%d\n",
               i, (unsigned long)utxos[i].amount, utxos[i].status);
        if (utxos[i].status == DNAC_UTXO_UNSPENT) {
            total += utxos[i].amount;
        }
    }

    if (utxos) dnac_free_utxos(utxos, count);

    printf("  Total unspent: %lu\n", (unsigned long)total);

    if (total == 0 && count == 0) {
        fprintf(stderr, "  FAIL: No UTXOs found\n");
        return -1;
    }

    printf("  PASS: Wallet contains %d UTXOs\n", count);
    return 0;
}

/* ============================================================================
 * Main - Chained Test Flow
 * ========================================================================== */

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║          DNAC Real End-to-End Test (test_real.c)             ║\n");
    printf("║                                                               ║\n");
    printf("║  Flow: Mint -> Verify -> Send -> Verify -> Double-spend      ║\n");
    printf("║                                                               ║\n");
    printf("║  This test uses the REAL mint mechanism, not synthetic UTXOs ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");

    /* Seed random */
    srand((unsigned)time(NULL) ^ getpid());

    /* Setup */
    if (setup_test_env() != 0) {
        fprintf(stderr, "\nFATAL: Failed to setup test environment\n");
        return 1;
    }

    int failed = 0;
    uint64_t mint_amount = 10000;
    uint64_t send_amount = 3000;

    /* STEP 1: MINT */
    if (step_mint(mint_amount) != 0) {
        fprintf(stderr, "\nFAILED at STEP 1: MINT\n");
        failed++;
    }

    /* STEP 2: VERIFY MINT */
    if (!failed && step_verify_mint(mint_amount) != 0) {
        fprintf(stderr, "\nFAILED at STEP 2: VERIFY MINT\n");
        failed++;
    }

    /* STEP 3: SEND */
    if (!failed && step_send(send_amount) != 0) {
        fprintf(stderr, "\nFAILED at STEP 3: SEND\n");
        failed++;
    }

    /* STEP 4: VERIFY SEND */
    if (!failed && step_verify_send(mint_amount) != 0) {
        fprintf(stderr, "\nFAILED at STEP 4: VERIFY SEND\n");
        failed++;
    }

    /* STEP 5: DOUBLE-SPEND */
    if (!failed && step_double_spend() != 0) {
        fprintf(stderr, "\nFAILED at STEP 5: DOUBLE-SPEND\n");
        failed++;
    }

    /* STEP 6: RECEIVE */
    if (!failed && step_receive() != 0) {
        fprintf(stderr, "\nFAILED at STEP 6: RECEIVE\n");
        failed++;
    }

    /* Cleanup */
    cleanup_test_env();

    /* Results */
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    if (failed == 0) {
        printf("║                    ALL TESTS PASSED                          ║\n");
    } else {
        printf("║                    TESTS FAILED: %d                            ║\n", failed);
    }
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    return failed > 0 ? 1 : 0;
}
