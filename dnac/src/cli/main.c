/**
 * @file main.c
 * @brief DNAC CLI entry point
 *
 * Standalone CLI for DNAC wallet operations.
 * For alpha/beta testing. Will merge with dna-messenger-cli on release.
 */

#include "dnac/cli.h"
#include "dnac/dnac.h"
#include <dna/dna_engine.h>
#include "nodus_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

/* Global options */
static char g_data_dir[512] = "";

/* ============================================================================
 * Synchronization Helpers (for async DNA engine calls)
 * ========================================================================== */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool done;
    int result;
} cli_wait_t;

static void cli_wait_init(cli_wait_t *wait) {
    pthread_mutex_init(&wait->mutex, NULL);
    pthread_cond_init(&wait->cond, NULL);
    wait->done = false;
    wait->result = 0;
}

static void cli_wait_destroy(cli_wait_t *wait) {
    pthread_mutex_destroy(&wait->mutex);
    pthread_cond_destroy(&wait->cond);
}

static int cli_wait_for(cli_wait_t *wait) {
    pthread_mutex_lock(&wait->mutex);
    while (!wait->done) {
        pthread_cond_wait(&wait->cond, &wait->mutex);
    }
    int result = wait->result;
    pthread_mutex_unlock(&wait->mutex);
    return result;
}

static void on_completion(uint64_t request_id, int error, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;
    pthread_mutex_lock(&wait->mutex);
    wait->result = error;
    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

/* ============================================================================
 * Command Line Parsing
 * ========================================================================== */

static int parse_options(int argc, char **argv) {
    static struct option long_options[] = {
        {"help",     no_argument,       0, 'h'},
        {"version",  no_argument,       0, 'v'},
        {"data-dir", required_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+hvd:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                dnac_cli_print_help();
                exit(0);
            case 'v':
                dnac_cli_print_version();
                exit(0);
            case 'd':
                strncpy(g_data_dir, optarg, sizeof(g_data_dir) - 1);
                break;
            default:
                return -1;
        }
    }

    return optind;
}

/* ============================================================================
 * Engine Initialization
 * ========================================================================== */

static dna_engine_t* init_engine(void) {
    /* Expand ~ in data directory */
    char expanded_dir[512];
    if (g_data_dir[0] == '\0') {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(expanded_dir, sizeof(expanded_dir), "%s/.dna", home);
        } else {
            strncpy(expanded_dir, ".dna", sizeof(expanded_dir));
        }
    } else if (g_data_dir[0] == '~') {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(expanded_dir, sizeof(expanded_dir), "%s%s", home, g_data_dir + 1);
        } else {
            strncpy(expanded_dir, g_data_dir, sizeof(expanded_dir));
        }
    } else {
        strncpy(expanded_dir, g_data_dir, sizeof(expanded_dir));
    }

    /* Initialize DNA engine */
    dna_engine_t *engine = dna_engine_create(expanded_dir);
    if (!engine) {
        fprintf(stderr, "Error: Failed to create DNA engine\n");
        return NULL;
    }

    /* Check if identity exists */
    if (!dna_engine_has_identity(engine)) {
        fprintf(stderr, "Error: No identity found. Run 'dna-cli create <name>' first.\n");
        dna_engine_destroy(engine);
        return NULL;
    }

    /* Load identity (async with wait) */
    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_load_identity(engine, "", NULL, on_completion, &wait);
    int rc = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (rc != 0) {
        fprintf(stderr, "Error: Failed to load identity\n");
        dna_engine_destroy(engine);
        return NULL;
    }

    return engine;
}

/* ============================================================================
 * Main Entry Point
 * ========================================================================== */

int main(int argc, char **argv) {
    /* Parse options */
    int cmd_start = parse_options(argc, argv);
    if (cmd_start < 0) {
        dnac_cli_print_help();
        return 1;
    }

    /* Check for command */
    if (cmd_start >= argc) {
        fprintf(stderr, "Error: No command specified.\n\n");
        dnac_cli_print_help();
        return 1;
    }

    const char *command = argv[cmd_start];

    /* Initialize engine and DNAC context */
    dna_engine_t *engine = init_engine();
    if (!engine) {
        return 1;
    }

    dnac_context_t *ctx = dnac_init(engine);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize DNAC\n");
        dna_engine_destroy(engine);
        return 1;
    }

    /* Wait for DHT connection (needed for send/sync/recover) */
    for (int i = 0; i < 100; i++) {  /* up to 10 seconds */
        if (nodus_ops_is_ready()) break;
        usleep(100000);  /* 100ms */
    }

    int result = 0;

    /* Dispatch command */
    if (strcmp(command, "info") == 0) {
        result = dnac_cli_info(ctx);
    }
    else if (strcmp(command, "address") == 0) {
        result = dnac_cli_address(ctx);
    }
    else if (strcmp(command, "query") == 0) {
        if (cmd_start + 1 >= argc) {
            fprintf(stderr, "Usage: dnac-cli query <name|fingerprint>\n");
            result = 1;
        } else {
            result = dnac_cli_query(ctx, argv[cmd_start + 1]);
        }
    }
    else if (strcmp(command, "balance") == 0) {
        /* Check for --token flag */
        if (cmd_start + 2 < argc && strcmp(argv[cmd_start + 1], "--token") == 0) {
            result = dnac_cli_balance_token(ctx, argv[cmd_start + 2]);
        } else {
            result = dnac_cli_balance(ctx);
        }
    }
    else if (strcmp(command, "utxos") == 0) {
        result = dnac_cli_utxos(ctx);
    }
    else if (strcmp(command, "send") == 0) {
        /* Check for --token flag: send --token <id> <fp> <amount> [memo] */
        if (cmd_start + 1 < argc && strcmp(argv[cmd_start + 1], "--token") == 0) {
            if (cmd_start + 4 >= argc) {
                fprintf(stderr, "Usage: dnac-cli send --token <token_id> <fingerprint> <amount> [memo]\n");
                result = 1;
            } else {
                const char *token_id_hex = argv[cmd_start + 2];
                const char *recipient = argv[cmd_start + 3];
                char *endptr = NULL;
                errno = 0;
                uint64_t amount = strtoull(argv[cmd_start + 4], &endptr, 10);
                if (errno == ERANGE || !endptr || *endptr != '\0' || amount == 0) {
                    fprintf(stderr, "Error: Invalid amount '%s'\n", argv[cmd_start + 4]);
                    result = 1;
                } else {
                    const char *memo = (cmd_start + 5 < argc) ? argv[cmd_start + 5] : NULL;
                    result = dnac_cli_send_token(ctx, recipient, amount, token_id_hex, memo);
                }
            }
        } else {
            if (cmd_start + 2 >= argc) {
                fprintf(stderr, "Usage: dnac-cli send <fingerprint> <amount> [memo]\n");
                result = 1;
            } else {
                const char *recipient = argv[cmd_start + 1];
                char *endptr = NULL;
                errno = 0;
                uint64_t amount = strtoull(argv[cmd_start + 2], &endptr, 10);
                if (errno == ERANGE || !endptr || *endptr != '\0' || amount == 0) {
                    fprintf(stderr, "Error: Invalid amount '%s'\n", argv[cmd_start + 2]);
                    result = 1;
                } else {
                    const char *memo = (cmd_start + 3 < argc) ? argv[cmd_start + 3] : NULL;
                    result = dnac_cli_send(ctx, recipient, amount, memo);
                }
            }
        }
    }
    else if (strcmp(command, "sync") == 0) {
        result = dnac_cli_sync(ctx);
    }
    else if (strcmp(command, "history") == 0) {
        int limit = 0;
        if (cmd_start + 1 < argc) {
            limit = atoi(argv[cmd_start + 1]);
        }
        result = dnac_cli_history(ctx, limit);
    }
    else if (strcmp(command, "tx") == 0) {
        if (cmd_start + 1 >= argc) {
            fprintf(stderr, "Usage: dnac-cli tx <hash>\n");
            result = 1;
        } else {
            result = dnac_cli_tx_details(ctx, argv[cmd_start + 1]);
        }
    }
    else if (strcmp(command, "nodus-list") == 0) {
        result = dnac_cli_nodus_list(ctx);
    }
    else if (strcmp(command, "genesis-create") == 0) {
        if (cmd_start + 2 >= argc) {
            fprintf(stderr, "Usage: dnac-cli genesis-create <fingerprint> <amount>\n");
            result = 1;
        } else {
            const char *fingerprint = argv[cmd_start + 1];
            char *gc_endptr = NULL;
            errno = 0;
            uint64_t amount = strtoull(argv[cmd_start + 2], &gc_endptr, 10);
            if (errno == ERANGE || !gc_endptr || *gc_endptr != '\0' || amount == 0) {
                fprintf(stderr, "Error: Invalid amount '%s' (must be > 0)\n", argv[cmd_start + 2]);
                result = 1;
            } else {
                result = dnac_cli_genesis_create(ctx, fingerprint, amount);
            }
        }
    }
    else if (strcmp(command, "genesis-submit") == 0) {
        const char *tx_file = (cmd_start + 1 < argc) ? argv[cmd_start + 1] : NULL;
        result = dnac_cli_genesis_submit(ctx, tx_file);
    }
    else if (strcmp(command, "token-create") == 0) {
        if (cmd_start + 3 >= argc) {
            fprintf(stderr, "Usage: dnac-cli token-create <name> <symbol> <supply>\n");
            result = 1;
        } else {
            const char *name = argv[cmd_start + 1];
            const char *symbol = argv[cmd_start + 2];
            char *endptr = NULL;
            errno = 0;
            uint64_t supply = strtoull(argv[cmd_start + 3], &endptr, 10);
            if (errno == ERANGE || !endptr || *endptr != '\0' || supply == 0) {
                fprintf(stderr, "Error: Invalid supply '%s' (must be > 0)\n", argv[cmd_start + 3]);
                result = 1;
            } else {
                result = dnac_cli_token_create(ctx, name, symbol, supply);
            }
        }
    }
    else if (strcmp(command, "token-list") == 0) {
        result = dnac_cli_token_list(ctx);
    }
    else if (strcmp(command, "token-info") == 0) {
        if (cmd_start + 1 >= argc) {
            fprintf(stderr, "Usage: dnac-cli token-info <token_id_hex|symbol>\n");
            result = 1;
        } else {
            result = dnac_cli_token_info(ctx, argv[cmd_start + 1]);
        }
    }
    else {
        fprintf(stderr, "Error: Unknown command '%s'\n\n", command);
        dnac_cli_print_help();
        result = 1;
    }

    /* Cleanup */
    dnac_shutdown(ctx);
    dna_engine_destroy(engine);

    return result;
}
