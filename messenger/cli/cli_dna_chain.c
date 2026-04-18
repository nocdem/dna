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
#include "cli_dna_chain_helpers.h"

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
    printf("  send <name|fp> <amount> [memo] Send payment to name or fingerprint\n");
    printf("  sync                          Sync wallet from network\n");
    printf("  history [n]                   Show transaction history (last n entries)\n");
    printf("  tx <hash>                     Show transaction details\n");
    printf("  witnesses                     List witness servers\n");
    printf("  genesis-create <fp> <amount>  Create genesis TX locally (Phase 1)\n");
    printf("  genesis-submit [tx_file]      Submit genesis TX to network (Phase 2)\n");
    printf("  genesis-prepare <config>      Build chain_def blob from operator config (hex stdout)\n");
    printf("  parse-tx <tx_file>            Inspect a serialized TX file (read-only)\n\n");
    printf("Stake & Delegation:\n");
    printf("  stake [--commission-bps N] [--unstake-to FP]\n");
    printf("                                Become a validator (self-stake 10M DNAC)\n");
    printf("  delegate <pubkey_hex> <amount_raw> [memo]\n");
    printf("                                Delegate DNAC to a validator\n");
    printf("  undelegate <pubkey_hex> <amount_raw>\n");
    printf("                                Withdraw (part of) a delegation\n");
    printf("  claim <validator_pubkey_hex> Claim accrued staking rewards\n");
    printf("  unstake                       Trigger validator retirement (fee-only)\n");
    printf("  validator-update --commission-bps N\n");
    printf("                                Change validator commission rate\n");
    printf("  validator-list [--status N]   List validators (N: 0=ACTIVE, 1=RETIRING, 2=UNSTAKED, 3=AUTO_RETIRED)\n");
    printf("  committee                     Show current epoch's top-7 committee\n");
    printf("  pending-rewards [pubkey_hex]  Show pending rewards (default: caller)\n\n");
    printf("Token Commands:\n");
    printf("  token-create <name> <sym> <supply>  Create a new token\n");
    printf("  token-list                          List all known tokens\n");
    printf("  token-info <id|symbol>              Show token details\n");
    printf("  balance --token <id>                Show balance for a specific token\n");
    printf("  send --token <id> <name|fp> <amt> [memo] Send token payment\n");
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
        result = dna_chain_cmd_info(ctx);
    }
    else if (strcmp(cmd, "address") == 0) {
        result = dna_chain_cmd_address(ctx);
    }
    else if (strcmp(cmd, "query") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna query <name|fingerprint>\n");
            result = 1;
        } else {
            result = dna_chain_cmd_query(ctx, argv[sub + 1]);
        }
    }
    else if (strcmp(cmd, "balance") == 0) {
        /* Check for --token flag */
        if (sub + 2 < argc && strcmp(argv[sub + 1], "--token") == 0) {
            result = dna_chain_cmd_balance_token(ctx, argv[sub + 2]);
        } else {
            result = dna_chain_cmd_balance(ctx);
        }
    }
    else if (strcmp(cmd, "balance-of") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna balance-of <fingerprint>\n");
            result = 1;
        } else {
            result = dna_chain_cmd_balance_of(ctx, argv[sub + 1]);
        }
    }
    else if (strcmp(cmd, "utxos") == 0) {
        result = dna_chain_cmd_utxos(ctx);
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
                    result = dna_chain_cmd_send_token(ctx, recipient, amount, token_id_hex, memo);
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
                    result = dna_chain_cmd_send(ctx, recipient, amount, memo);
                }
            }
        }
    }
    else if (strcmp(cmd, "sync") == 0) {
        result = dna_chain_cmd_sync(ctx);
    }
    else if (strcmp(cmd, "history") == 0) {
        int limit = 0;
        if (sub + 1 < argc) {
            limit = atoi(argv[sub + 1]);
        }
        result = dna_chain_cmd_history(ctx, limit);
    }
    else if (strcmp(cmd, "tx") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna tx <hash>\n");
            result = 1;
        } else {
            result = dna_chain_cmd_tx_details(ctx, argv[sub + 1]);
        }
    }
    else if (strcmp(cmd, "witnesses") == 0) {
        result = dna_chain_cmd_nodus_list(ctx);
    }
    else if (strcmp(cmd, "genesis-create") == 0) {
        if (sub + 2 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna genesis-create <fingerprint> <amount> [--chain-def-file <path>]\n");
            fprintf(stderr, "  --chain-def-file  Path to binary file containing a serialized\n");
            fprintf(stderr, "                    dnac_chain_definition_t (see pack_chain_def tool).\n");
            fprintf(stderr, "                    When provided, the TX carries an anchored-genesis\n");
            fprintf(stderr, "                    chain_def trailer and witnesses will embed it in\n");
            fprintf(stderr, "                    the genesis block hash preimage.\n");
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
                /* Optional --chain-def-file <path> flag */
                const char *chain_def_file = NULL;
                for (int i = sub + 3; i + 1 < argc; i++) {
                    if (strcmp(argv[i], "--chain-def-file") == 0) {
                        chain_def_file = argv[i + 1];
                        break;
                    }
                }
                result = dna_chain_cmd_genesis_create(ctx, fingerprint, amount, chain_def_file);
            }
        }
    }
    else if (strcmp(cmd, "genesis-submit") == 0) {
        const char *tx_file = (sub + 1 < argc) ? argv[sub + 1] : NULL;
        result = dna_chain_cmd_genesis_submit(ctx, tx_file);
    }
    else if (strcmp(cmd, "genesis-prepare") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna genesis-prepare <config_file>\n");
            fprintf(stderr, "  Reads key=value operator config and prints the hex-encoded\n");
            fprintf(stderr, "  chain_def blob (including 7 initial_validators) to stdout.\n");
            fprintf(stderr, "  See dnac/include/dnac/genesis_prepare.h for the config schema.\n");
            result = 1;
        } else {
            result = dna_chain_cmd_genesis_prepare(ctx, argv[sub + 1]);
        }
    }
    else if (strcmp(cmd, "parse-tx") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna parse-tx <tx_file>\n");
            result = 1;
        } else {
            result = dna_chain_cmd_parse_tx(ctx, argv[sub + 1]);
        }
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
                result = dna_chain_cmd_token_create(ctx, name, symbol, supply);
            }
        }
    }
    else if (strcmp(cmd, "token-list") == 0) {
        result = dna_chain_cmd_token_list(ctx);
    }
    else if (strcmp(cmd, "stake") == 0) {
        /* Syntax: dna stake [--commission-bps N] [--unstake-to FP] */
        uint16_t commission_bps = 500;  /* Default 5% */
        const char *unstake_to = NULL;
        int i = sub + 1;
        while (i < argc) {
            if (strcmp(argv[i], "--commission-bps") == 0 && i + 1 < argc) {
                char *endptr = NULL;
                errno = 0;
                unsigned long v = strtoul(argv[i + 1], &endptr, 10);
                if (errno != 0 || !endptr || *endptr != '\0' || v > 10000) {
                    fprintf(stderr,
                            "Error: invalid --commission-bps '%s' (0..10000)\n",
                            argv[i + 1]);
                    result = 1;
                    goto stake_done;
                }
                commission_bps = (uint16_t)v;
                i += 2;
            } else if (strcmp(argv[i], "--unstake-to") == 0 && i + 1 < argc) {
                unstake_to = argv[i + 1];
                i += 2;
            } else {
                fprintf(stderr,
                        "Usage: dna-connect-cli dna stake"
                        " [--commission-bps N] [--unstake-to FP]\n");
                result = 1;
                goto stake_done;
            }
        }
        result = dna_chain_cmd_stake(ctx, commission_bps, unstake_to);
    stake_done: ;
    }
    else if (strcmp(cmd, "validator-list") == 0) {
        /* Syntax: dna validator-list [--status N]   (N in 0..3, omit = all) */
        int filter_status = -1;
        if (sub + 2 < argc && strcmp(argv[sub + 1], "--status") == 0) {
            char *endptr = NULL;
            errno = 0;
            long v = strtol(argv[sub + 2], &endptr, 10);
            if (errno != 0 || !endptr || *endptr != '\0' || v < 0 || v > 3) {
                fprintf(stderr,
                        "Error: --status must be 0..3 (0=ACTIVE, 1=RETIRING,"
                        " 2=UNSTAKED, 3=AUTO_RETIRED)\n");
                result = 1;
            } else {
                filter_status = (int)v;
            }
        }
        if (result == 0) {
            result = dna_chain_cmd_validator_list(ctx, filter_status);
        }
    }
    else if (strcmp(cmd, "committee") == 0) {
        result = dna_chain_cmd_committee(ctx);
    }
    else if (strcmp(cmd, "pending-rewards") == 0) {
        /* Syntax: dna pending-rewards [<claimant_pubkey_hex>] */
        const char *claimant = (sub + 1 < argc) ? argv[sub + 1] : NULL;
        result = dna_chain_cmd_pending_rewards(ctx, claimant);
    }
    else if (strcmp(cmd, "unstake") == 0) {
        /* Syntax: dna unstake (no args) */
        result = dna_chain_cmd_unstake(ctx);
    }
    else if (strcmp(cmd, "validator-update") == 0) {
        /* Syntax: dna validator-update --commission-bps N */
        int commission_bps = -1;
        int i = sub + 1;
        while (i < argc) {
            if (strcmp(argv[i], "--commission-bps") == 0 && i + 1 < argc) {
                char *endptr = NULL;
                errno = 0;
                unsigned long v = strtoul(argv[i + 1], &endptr, 10);
                if (errno != 0 || !endptr || *endptr != '\0' || v > 10000) {
                    fprintf(stderr,
                            "Error: invalid --commission-bps '%s' (0..10000)\n",
                            argv[i + 1]);
                    result = 1;
                    goto validator_update_done;
                }
                commission_bps = (int)v;
                i += 2;
            } else {
                fprintf(stderr,
                        "Usage: dna-connect-cli dna validator-update"
                        " --commission-bps N\n");
                result = 1;
                goto validator_update_done;
            }
        }
        if (commission_bps < 0) {
            fprintf(stderr,
                    "Usage: dna-connect-cli dna validator-update"
                    " --commission-bps N\n");
            result = 1;
        } else {
            result = dna_chain_cmd_validator_update(
                    ctx, (uint16_t)commission_bps);
        }
    validator_update_done: ;
    }
    else if (strcmp(cmd, "claim") == 0) {
        /* Syntax: dna claim <validator_pubkey_hex> */
        if (sub + 1 >= argc) {
            fprintf(stderr,
                    "Usage: dna-connect-cli dna claim"
                    " <validator_pubkey_hex>\n");
            result = 1;
        } else {
            result = dna_chain_cmd_claim(ctx, argv[sub + 1]);
        }
    }
    else if (strcmp(cmd, "delegate") == 0 || strcmp(cmd, "undelegate") == 0) {
        /* Syntax: dna delegate   <validator_pubkey_hex> <amount> [memo]
         *         dna undelegate <validator_pubkey_hex> <amount>
         *
         * Note: validator identifier is the full hex-encoded Dilithium5
         * pubkey. Name/fp → pubkey resolution deferred (see commit body).
         */
        bool is_delegate = (strcmp(cmd, "delegate") == 0);
        if (sub + 2 >= argc) {
            if (is_delegate) {
                fprintf(stderr,
                        "Usage: dna-connect-cli dna delegate"
                        " <validator_pubkey_hex> <amount_raw> [memo]\n");
            } else {
                fprintf(stderr,
                        "Usage: dna-connect-cli dna undelegate"
                        " <validator_pubkey_hex> <amount_raw>\n");
            }
            result = 1;
        } else {
            const char *pubkey_hex = argv[sub + 1];
            char *endptr = NULL;
            errno = 0;
            uint64_t amount = strtoull(argv[sub + 2], &endptr, 10);
            if (errno == ERANGE || !endptr || *endptr != '\0' || amount == 0) {
                fprintf(stderr,
                        "Error: Invalid amount '%s'\n", argv[sub + 2]);
                result = 1;
            } else if (is_delegate) {
                const char *memo = (sub + 3 < argc) ? argv[sub + 3] : NULL;
                result = dna_chain_cmd_delegate(ctx, pubkey_hex, amount, memo);
            } else {
                result = dna_chain_cmd_undelegate(ctx, pubkey_hex, amount);
            }
        }
    }
    else if (strcmp(cmd, "token-info") == 0) {
        if (sub + 1 >= argc) {
            fprintf(stderr, "Usage: dna-connect-cli dna token-info <token_id_hex|symbol>\n");
            result = 1;
        } else {
            result = dna_chain_cmd_token_info(ctx, argv[sub + 1]);
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
