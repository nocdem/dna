/*
 * DNA Chain CLI commands for dna-connect-cli
 *
 * Embeds DNAC (DNA Chain) wallet commands into the Connect CLI.
 * Command group: "dna"
 *
 * Usage: dna-connect-cli dna <subcommand> [args...]
 */

#include "cli_commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#ifdef DNA_CHAIN_ENABLED

#include "dnac/dnac.h"
#include "dnac/cli.h"

/* ============================================================================
 * Helper: create and destroy DNAC context
 * ========================================================================== */

static dnac_context_t* dna_chain_init(dna_engine_t *engine) {
    if (!engine) {
        fprintf(stderr, "Error: Engine not initialized\n");
        return NULL;
    }
    dnac_context_t *ctx = dnac_init(engine);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize DNA Chain\n");
    }
    return ctx;
}

/* ============================================================================
 * Help
 * ========================================================================== */

static void print_dna_chain_help(void) {
    printf("DNA Chain — Post-Quantum Blockchain\n\n");
    printf("Usage: dna-connect-cli dna <command> [arguments]\n\n");
    printf("Commands:\n");
    printf("  info                          Show chain wallet info and status\n");
    printf("  address                       Show wallet address (fingerprint)\n");
    printf("  query <name|fp>               Lookup identity by name or fingerprint\n");
    printf("  balance                       Show wallet balance\n");
    printf("  utxos                         List unspent transaction outputs\n");
    printf("  send <fp> <amount> [memo]     Send payment to fingerprint\n");
    printf("  sync                          Sync wallet from network\n");
    printf("  history [n]                   Show transaction history (last n entries)\n");
    printf("  tx <hash>                     Show transaction details\n");
    printf("  witnesses                     List witness servers\n");
    printf("  genesis-create <fp> <amount>  Create genesis TX locally (Phase 1)\n");
    printf("  genesis-submit [tx_file]      Submit genesis TX to network (Phase 2)\n\n");
    printf("Token Commands:\n");
    printf("  token-create <name> <sym> <supply>  Create a new token\n");
    printf("  token-list                          List all known tokens\n");
    printf("  token-info <id|symbol>              Show token details\n");
    printf("  balance --token <id>                Show balance for a specific token\n");
    printf("  send --token <id> <fp> <amt> [memo] Send token payment\n");
}

/* ============================================================================
 * Dispatcher (argv-based, for main.c)
 * ========================================================================== */

int dispatch_dna_chain(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc) {
        print_dna_chain_help();
        return 1;
    }

    const char *cmd = argv[sub];

    if (strcmp(cmd, "help") == 0) {
        print_dna_chain_help();
        return 0;
    }

    /* All commands need DNAC context */
    dnac_context_t *ctx = dna_chain_init(engine);
    if (!ctx) return 1;

    int result = 0;

    if (strcmp(cmd, "info") == 0) {
        result = dnac_cli_info(ctx);
    }
    else if (strcmp(cmd, "address") == 0) {
        result = dnac_cli_address(ctx);
    }
    else if (strcmp(cmd, "query") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna query <name|fingerprint>\n");
            result = 1;
        } else {
            result = dnac_cli_query(ctx, argv[sub + 1]);
        }
    }
    else if (strcmp(cmd, "balance") == 0) {
        /* Check for --token flag */
        if (sub + 2 < argc && strcmp(argv[sub + 1], "--token") == 0) {
            result = dnac_cli_balance_token(ctx, argv[sub + 2]);
        } else {
            result = dnac_cli_balance(ctx);
        }
    }
    else if (strcmp(cmd, "balance-of") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna balance-of <fingerprint>\n");
            result = 1;
        } else {
            result = dnac_cli_balance_of(ctx, argv[sub + 1]);
        }
    }
    else if (strcmp(cmd, "utxos") == 0) {
        result = dnac_cli_utxos(ctx);
    }
    else if (strcmp(cmd, "send") == 0) {
        /* Check for --token flag: send --token <id> <fp> <amount> [memo] */
        if (sub + 1 < argc && strcmp(argv[sub + 1], "--token") == 0) {
            if (sub + 4 >= argc) {
                fprintf(stderr, "Usage: dna-connect-cli dna send --token <token_id> <fingerprint> <amount> [memo]\n");
                result = 1;
            } else {
                const char *token_id_hex = argv[sub + 2];
                const char *recipient = argv[sub + 3];
                char *endptr = NULL;
                errno = 0;
                uint64_t amount = strtoull(argv[sub + 4], &endptr, 10);
                if (errno == ERANGE || !endptr || *endptr != '\0' || amount == 0) {
                    fprintf(stderr, "Error: Invalid amount '%s'\n", argv[sub + 4]);
                    result = 1;
                } else {
                    const char *memo = (sub + 5 < argc) ? argv[sub + 5] : NULL;
                    result = dnac_cli_send_token(ctx, recipient, amount, token_id_hex, memo);
                }
            }
        } else {
            if (sub + 2 >= argc) {
                fprintf(stderr, "Usage: dna-connect-cli dna send <fingerprint> <amount> [memo]\n");
                result = 1;
            } else {
                const char *recipient = argv[sub + 1];
                char *endptr = NULL;
                errno = 0;
                uint64_t amount = strtoull(argv[sub + 2], &endptr, 10);
                if (errno == ERANGE || !endptr || *endptr != '\0' || amount == 0) {
                    fprintf(stderr, "Error: Invalid amount '%s'\n", argv[sub + 2]);
                    result = 1;
                } else {
                    const char *memo = (sub + 3 < argc) ? argv[sub + 3] : NULL;
                    result = dnac_cli_send(ctx, recipient, amount, memo);
                }
            }
        }
    }
    else if (strcmp(cmd, "sync") == 0) {
        result = dnac_cli_sync(ctx);
    }
    else if (strcmp(cmd, "history") == 0) {
        int limit = 0;
        if (sub + 1 < argc) {
            limit = atoi(argv[sub + 1]);
        }
        result = dnac_cli_history(ctx, limit);
    }
    else if (strcmp(cmd, "tx") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna tx <hash>\n");
            result = 1;
        } else {
            result = dnac_cli_tx_details(ctx, argv[sub + 1]);
        }
    }
    else if (strcmp(cmd, "witnesses") == 0) {
        result = dnac_cli_nodus_list(ctx);
    }
    else if (strcmp(cmd, "genesis-create") == 0) {
        if (sub + 2 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna genesis-create <fingerprint> <amount>\n");
            result = 1;
        } else {
            const char *fingerprint = argv[sub + 1];
            char *gc_endptr = NULL;
            errno = 0;
            uint64_t amount = strtoull(argv[sub + 2], &gc_endptr, 10);
            if (errno == ERANGE || !gc_endptr || *gc_endptr != '\0' || amount == 0) {
                fprintf(stderr, "Error: Invalid amount '%s' (must be > 0)\n", argv[sub + 2]);
                result = 1;
            } else {
                result = dnac_cli_genesis_create(ctx, fingerprint, amount);
            }
        }
    }
    else if (strcmp(cmd, "genesis-submit") == 0) {
        const char *tx_file = (sub + 1 < argc) ? argv[sub + 1] : NULL;
        result = dnac_cli_genesis_submit(ctx, tx_file);
    }
    else if (strcmp(cmd, "token-create") == 0) {
        if (sub + 3 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna token-create <name> <symbol> <supply>\n");
            result = 1;
        } else {
            const char *name = argv[sub + 1];
            const char *symbol = argv[sub + 2];
            char *endptr = NULL;
            errno = 0;
            uint64_t supply = strtoull(argv[sub + 3], &endptr, 10);
            if (errno == ERANGE || !endptr || *endptr != '\0' || supply == 0) {
                fprintf(stderr, "Error: Invalid supply '%s' (must be > 0)\n", argv[sub + 3]);
                result = 1;
            } else {
                result = dnac_cli_token_create(ctx, name, symbol, supply);
            }
        }
    }
    else if (strcmp(cmd, "token-list") == 0) {
        result = dnac_cli_token_list(ctx);
    }
    else if (strcmp(cmd, "token-info") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna token-info <token_id_hex|symbol>\n");
            result = 1;
        } else {
            result = dnac_cli_token_info(ctx, argv[sub + 1]);
        }
    }
    else {
        fprintf(stderr, "Unknown dna command: '%s'\n", cmd);
        print_dna_chain_help();
        result = 1;
    }

    dnac_shutdown(ctx);
    return result;
}

/* ============================================================================
 * REPL Dispatcher
 * ========================================================================== */

int dispatch_dna_chain_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || !*subcmd) {
        print_dna_chain_help();
        return 1;
    }

    /* Tokenize subcmd into argv */
    char buf[1024];
    strncpy(buf, subcmd, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *tokens[16];
    int argc = 0;
    char *tok = strtok(buf, " \t");
    while (tok && argc < 16) {
        tokens[argc++] = tok;
        tok = strtok(NULL, " \t");
    }

    if (argc == 0) {
        print_dna_chain_help();
        return 1;
    }

    /* Reuse argv dispatcher with sub=0 */
    return dispatch_dna_chain(engine, argc, tokens, 0);
}

#else /* DNA_CHAIN_ENABLED not defined */

int dispatch_dna_chain(dna_engine_t *engine, int argc, char **argv, int sub) {
    (void)engine; (void)argc; (void)argv; (void)sub;
    fprintf(stderr, "DNA Chain not available (libdnac not linked).\n");
    fprintf(stderr, "Build DNAC first: cd /opt/dna/dnac/build && cmake .. && make -j$(nproc)\n");
    return 1;
}

int dispatch_dna_chain_repl(dna_engine_t *engine, const char *subcmd) {
    (void)engine; (void)subcmd;
    fprintf(stderr, "DNA Chain not available (libdnac not linked).\n");
    return 1;
}

#endif /* DNA_CHAIN_ENABLED */
