/**
 * @file genesis_main.c
 * @brief Standalone genesis tool for DNAC
 *
 * Creates the one-time genesis transaction that establishes
 * the total token supply. Requires unanimous witness approval.
 *
 * Usage: dnac-genesis [-d datadir] <fingerprint> <amount>
 */

#include "dnac/cli.h"
#include "dnac/dnac.h"
#include "dnac/genesis.h"
#include "dnac/transaction.h"
#include <dna/dna_engine.h>
#include "nodus_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>

/* ── Async wait helpers ──────────────────────────────────────────── */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool done;
    int result;
} genesis_wait_t;

static void wait_init(genesis_wait_t *w) {
    pthread_mutex_init(&w->mutex, NULL);
    pthread_cond_init(&w->cond, NULL);
    w->done = false;
    w->result = 0;
}

static void wait_destroy(genesis_wait_t *w) {
    pthread_mutex_destroy(&w->mutex);
    pthread_cond_destroy(&w->cond);
}

static int wait_for(genesis_wait_t *w) {
    pthread_mutex_lock(&w->mutex);
    while (!w->done)
        pthread_cond_wait(&w->cond, &w->mutex);
    int result = w->result;
    pthread_mutex_unlock(&w->mutex);
    return result;
}

static void on_completion(uint64_t request_id, int error, void *user_data) {
    (void)request_id;
    genesis_wait_t *w = (genesis_wait_t *)user_data;
    pthread_mutex_lock(&w->mutex);
    w->result = error;
    w->done = true;
    pthread_cond_signal(&w->cond);
    pthread_mutex_unlock(&w->mutex);
}

/* ── Usage ───────────────────────────────────────────────────────── */

static void print_usage(void) {
    printf("dnac-genesis — One-time token supply creation\n\n");
    printf("Usage: dnac-genesis [options] <fingerprint> <amount>\n\n");
    printf("Options:\n");
    printf("  -d, --data-dir <path>  Data directory (default: ~/.dna)\n");
    printf("  -h, --help             Show this help\n\n");
    printf("Amount is in raw units (1 token = 100000000 raw units).\n");
    printf("Example: dnac-genesis abc123...def 100000000000000000  # 1 billion tokens\n\n");
    printf("Genesis can only happen once. All witnesses must approve unanimously.\n");
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    char data_dir[512] = "";

    /* Parse options */
    static struct option long_options[] = {
        {"help",     no_argument,       0, 'h'},
        {"data-dir", required_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+hd:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage();
                return 0;
            case 'd':
                strncpy(data_dir, optarg, sizeof(data_dir) - 1);
                break;
            default:
                print_usage();
                return 1;
        }
    }

    /* Need fingerprint + amount */
    if (optind + 2 > argc) {
        fprintf(stderr, "Error: Missing fingerprint and/or amount.\n\n");
        print_usage();
        return 1;
    }

    const char *fingerprint = argv[optind];
    uint64_t amount = strtoull(argv[optind + 1], NULL, 10);

    if (amount == 0) {
        fprintf(stderr, "Error: Amount must be > 0\n");
        return 1;
    }

    /* Expand data directory */
    char expanded_dir[512];
    if (data_dir[0] == '\0') {
        const char *home = getenv("HOME");
        snprintf(expanded_dir, sizeof(expanded_dir), "%s/.dna",
                 home ? home : ".");
    } else if (data_dir[0] == '~') {
        const char *home = getenv("HOME");
        snprintf(expanded_dir, sizeof(expanded_dir), "%s%s",
                 home ? home : ".", data_dir + 1);
    } else {
        strncpy(expanded_dir, data_dir, sizeof(expanded_dir) - 1);
        expanded_dir[sizeof(expanded_dir) - 1] = '\0';
    }

    /* Init engine */
    dna_engine_t *engine = dna_engine_create(expanded_dir);
    if (!engine) {
        fprintf(stderr, "Error: Failed to create engine\n");
        return 1;
    }

    if (!dna_engine_has_identity(engine)) {
        fprintf(stderr, "Error: No identity found in %s\n", expanded_dir);
        dna_engine_destroy(engine);
        return 1;
    }

    genesis_wait_t wait;
    wait_init(&wait);
    dna_engine_load_identity(engine, "", NULL, on_completion, &wait);
    if (wait_for(&wait) != 0) {
        fprintf(stderr, "Error: Failed to load identity\n");
        wait_destroy(&wait);
        dna_engine_destroy(engine);
        return 1;
    }
    wait_destroy(&wait);

    /* Init DNAC */
    dnac_context_t *ctx = dnac_init(engine);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize DNAC\n");
        dna_engine_destroy(engine);
        return 1;
    }

    /* Wait for nodus connection */
    for (int i = 0; i < 100; i++) {
        if (nodus_ops_is_ready()) break;
        usleep(100000);
    }

    if (!nodus_ops_is_ready()) {
        fprintf(stderr, "Error: Could not connect to nodus network\n");
        dnac_shutdown(ctx);
        dna_engine_destroy(engine);
        return 1;
    }

    /* Format amount for display */
    uint64_t whole = amount / 100000000;
    uint64_t frac = amount % 100000000;
    if (frac == 0) {
        printf("Creating GENESIS: %" PRIu64 " tokens to %s\n", whole, fingerprint);
    } else {
        printf("Creating GENESIS: %" PRIu64 ".%08" PRIu64 " tokens to %s\n",
               whole, frac, fingerprint);
    }
    printf("This can only happen once. All witnesses must approve.\n\n");

    /* Create genesis TX */
    dnac_genesis_recipient_t recipients[1];
    strncpy(recipients[0].fingerprint, fingerprint,
            sizeof(recipients[0].fingerprint) - 1);
    recipients[0].fingerprint[sizeof(recipients[0].fingerprint) - 1] = '\0';
    recipients[0].amount = amount;

    dnac_transaction_t *tx = NULL;
    int rc = dnac_tx_create_genesis(recipients, 1, &tx);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Error creating genesis: %s\n", dnac_error_string(rc));
        dnac_shutdown(ctx);
        dna_engine_destroy(engine);
        return 1;
    }

    /* Authorize with witnesses */
    printf("Requesting witness authorization...\n");
    rc = dnac_tx_authorize_genesis(ctx, tx);
    if (rc == DNAC_ERROR_GENESIS_EXISTS) {
        fprintf(stderr, "Error: Genesis already exists.\n");
        dnac_free_transaction(tx);
        dnac_shutdown(ctx);
        dna_engine_destroy(engine);
        return 1;
    }
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Witnesses rejected genesis: %s\n", dnac_error_string(rc));
        dnac_free_transaction(tx);
        dnac_shutdown(ctx);
        dna_engine_destroy(engine);
        return 1;
    }

    /* Broadcast */
    printf("Broadcasting...\n");
    rc = dnac_tx_broadcast_genesis(ctx, tx);
    if (rc != DNAC_SUCCESS) {
        fprintf(stderr, "Broadcast failed: %s\n", dnac_error_string(rc));
        dnac_free_transaction(tx);
        dnac_shutdown(ctx);
        dna_engine_destroy(engine);
        return 1;
    }

    printf("\nGENESIS SUCCESS!\n");
    printf("TX hash: ");
    for (int i = 0; i < 64; i++) printf("%02x", tx->tx_hash[i]);
    printf("\n");

    if (frac == 0) {
        printf("Supply:  %" PRIu64 " tokens\n", whole);
    } else {
        printf("Supply:  %" PRIu64 ".%08" PRIu64 " tokens\n", whole, frac);
    }

    dnac_free_transaction(tx);
    dnac_shutdown(ctx);
    dna_engine_destroy(engine);

    return 0;
}
