/*
 * DNA Messenger CLI - Main Entry Point
 *
 * Single-command CLI for testing DNA Messenger without GUI.
 * Designed for automated testing by Claude AI.
 *
 * Usage:
 *   dna-messenger-cli [OPTIONS] <command> [args...]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>

#include <dna/dna_engine.h>
#include <dna/version.h>
#include "cli_commands.h"
#include "crypto/utils/qgp_log.h"
#include "dht/core/dht_context.h"
#include "dht/client/dht_singleton.h"

#define LOG_TAG "CLI_MAIN"

/* Global engine pointer for signal handler */
static dna_engine_t *g_engine = NULL;

/* Forward declaration for auto-load */
static int auto_load_identity(dna_engine_t *engine, const char *identity_hint, int quiet);

/* ============================================================================
 * SIGNAL HANDLER
 * ============================================================================ */

static void signal_handler(int signum) {
    (void)signum;
    fprintf(stderr, "\nInterrupted.\n");
    if (g_engine) {
        dna_engine_destroy(g_engine);
        g_engine = NULL;
    }
    exit(130);
}

/* ============================================================================
 * COMMAND LINE OPTIONS
 * ============================================================================ */

static struct option long_options[] = {
    {"data-dir",  required_argument, 0, 'd'},
    {"identity",  required_argument, 0, 'i'},
    {"help",      no_argument,       0, 'h'},
    {"version",   no_argument,       0, 'v'},
    {"quiet",     no_argument,       0, 'q'},
    {0, 0, 0, 0}
};

static void print_usage(const char *prog_name) {
    printf("DNA Messenger CLI v%s\n\n", DNA_VERSION_STRING);
    printf("Usage: %s [OPTIONS] <command> [args...]\n\n", prog_name);
    printf("Options:\n");
    printf("  -d, --data-dir <path>   Data directory (default: ~/.dna)\n");
    printf("  -q, --quiet             Suppress banner/status messages\n");
    printf("  -h, --help              Show this help\n");
    printf("  -v, --version           Show version\n");
    printf("\n");
    printf("IDENTITY COMMANDS (v0.3.0 single-user model):\n");
    printf("  create <name>               Create new identity\n");
    printf("  restore <mnemonic...>       Restore identity from 24-word mnemonic\n");
    printf("  delete                      Delete identity and all data\n");
    printf("  load                        Load identity (auto-detected)\n");
    printf("  whoami                      Show current identity\n");
    printf("  register <name>             Register a name on DHT\n");
    printf("  name                        Show registered name\n");
    printf("  lookup <name>               Check if name is available\n");
    printf("  profile [field=value]       Show or update profile\n");
    printf("\n");
    printf("CONTACT COMMANDS:\n");
    printf("  contacts                    List all contacts\n");
    printf("  add-contact <name|fp>       Add contact\n");
    printf("  remove-contact <fp>         Remove contact\n");
    printf("  request <fp> [msg]          Send contact request\n");
    printf("  requests                    List pending requests\n");
    printf("  approve <fp>                Approve contact request\n");
    printf("\n");
    printf("MESSAGING COMMANDS:\n");
    printf("  send <fp> <message>         Send message\n");
    printf("  messages <fp>               Show conversation\n");
    printf("  check-offline               Check for offline messages\n");
    printf("  listen                      Subscribe to contacts and listen (stays running)\n");
    printf("\n");
    printf("WALLET COMMANDS:\n");
    printf("  wallets                     List wallets\n");
    printf("  balance <index>             Show wallet balances\n");
    printf("\n");
    printf("NETWORK COMMANDS:\n");
    printf("  online <fp>                 Check if peer is online\n");
    printf("\n");
    printf("NAT TRAVERSAL COMMANDS:\n");
    printf("  stun-test                   Test STUN and show public IP\n");
    printf("  ice-status                  Show ICE connection status\n");
    printf("  turn-creds [--force]        Show/request TURN credentials\n");
    printf("  turn-test                   Test TURN relay with all servers\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s create alice\n", prog_name);
    printf("  %s restore abandon ability able about ...\n", prog_name);
    printf("  %s whoami\n", prog_name);
    printf("  %s contacts\n", prog_name);
    printf("  %s send nox \"Hello!\"\n", prog_name);
    printf("  %s messages nox\n", prog_name);
    printf("  %s -q contacts\n", prog_name);
}

/* Helper to join remaining args into a single string */
static char* join_args(int argc, char *argv[], int start) {
    size_t total_len = 0;
    for (int i = start; i < argc; i++) {
        total_len += strlen(argv[i]) + 1;
    }
    if (total_len == 0) return NULL;

    char *result = malloc(total_len);
    if (!result) return NULL;

    result[0] = '\0';
    for (int i = start; i < argc; i++) {
        if (i > start) strcat(result, " ");
        strcat(result, argv[i]);
    }
    return result;
}

/* ============================================================================
 * WAIT FOR DHT
 * ============================================================================ */

/**
 * Wait for DHT to become ready (connected to network)
 * @param quiet Suppress status messages
 * @param timeout_sec Maximum time to wait
 * @return 0 if connected, -1 if timeout
 */
static int wait_for_dht(int quiet, int timeout_sec) {
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        if (!quiet) {
            fprintf(stderr, "Warning: DHT not initialized\n");
        }
        return -1;
    }

    if (!quiet) {
        fprintf(stderr, "Waiting for DHT connection...");
    }

    for (int i = 0; i < timeout_sec * 10; i++) {
        if (dht_context_is_ready(dht)) {
            if (!quiet) {
                fprintf(stderr, " connected!\n");
            }
            return 0;
        }
        struct timespec ts = {0, 100000000};  /* 100ms */
        nanosleep(&ts, NULL);
    }

    if (!quiet) {
        fprintf(stderr, " timeout!\n");
    }
    return -1;
}

/* ============================================================================
 * AUTO-LOAD IDENTITY
 * ============================================================================ */

/**
 * Auto-load identity (v0.3.0 single-user model)
 *
 * Checks if identity exists (keys/identity.dsa) and loads it.
 * The identity_hint parameter is kept for backward compatibility but ignored.
 */
static int auto_load_identity(dna_engine_t *engine, const char *identity_hint, int quiet) {
    (void)identity_hint;  /* v0.3.0: Ignored - only one identity per app */

    /* v0.3.0: Check if identity exists using flat structure */
    if (!dna_engine_has_identity(engine)) {
        fprintf(stderr, "Error: No identity found. Create one first with 'create <name>'\n");
        return -1;
    }

    /* Load the single identity (fingerprint computed internally) */
    if (!quiet) {
        fprintf(stderr, "Loading identity...\n");
    }
    return cmd_load(engine, NULL);  /* NULL = auto-compute fingerprint */
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char *argv[]) {
    const char *data_dir = NULL;
    const char *identity = NULL;
    int quiet = 0;
    int opt;

    /* Parse command line options ('+' prefix = stop at first non-option) */
    while ((opt = getopt_long(argc, argv, "+d:i:hqv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                data_dir = optarg;
                break;
            case 'i':
                identity = optarg;
                break;
            case 'q':
                quiet = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                printf("dna-messenger-cli v%s (build %s %s)\n",
                       DNA_VERSION_STRING, BUILD_HASH, BUILD_TS);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Check for command */
    if (optind >= argc) {
        fprintf(stderr, "Error: No command specified\n\n");
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[optind];

    /* Handle help command without engine init */
    if (strcmp(command, "help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* Install signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize engine */
    if (!quiet) {
        fprintf(stderr, "Initializing DNA engine...\n");
    }

    g_engine = dna_engine_create(data_dir);
    if (!g_engine) {
        fprintf(stderr, "Error: Failed to initialize DNA engine\n");
        return 1;
    }

    if (!quiet) {
        fprintf(stderr, "Engine initialized.\n");
    }

    /* Auto-load identity for commands that need it */
    /* Skip auto-load for: create, restore, delete, list, help, stun-test */
    int needs_identity = !(strcmp(command, "create") == 0 ||
                           strcmp(command, "restore") == 0 ||
                           strcmp(command, "delete") == 0 ||
                           strcmp(command, "list") == 0 ||
                           strcmp(command, "ls") == 0 ||
                           strcmp(command, "help") == 0 ||
                           strcmp(command, "stun-test") == 0);

    if (needs_identity) {
        if (auto_load_identity(g_engine, identity, quiet) != 0) {
            dna_engine_destroy(g_engine);
            return 1;
        }

        /* Wait for DHT to connect (needed for network operations) */
        wait_for_dht(quiet, 10);  /* 10 second timeout */
    }

    /* Execute command */
    int result = 0;

    /* ====== IDENTITY COMMANDS ====== */
    if (strcmp(command, "create") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'create' requires <name> argument\n");
            result = 1;
        } else {
            result = cmd_create(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "restore") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'restore' requires mnemonic words\n");
            result = 1;
        } else {
            char *mnemonic = join_args(argc, argv, optind + 1);
            if (mnemonic) {
                result = cmd_restore(g_engine, mnemonic);
                free(mnemonic);
            } else {
                result = 1;
            }
        }
    }
    else if (strcmp(command, "list") == 0 || strcmp(command, "ls") == 0) {
        result = cmd_list(g_engine);
    }
    else if (strcmp(command, "delete") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'delete' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_delete(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "load") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'load' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_load(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "whoami") == 0) {
        cmd_whoami(g_engine);
        result = 0;
    }
    else if (strcmp(command, "register") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'register' requires <name> argument\n");
            result = 1;
        } else {
            result = cmd_register(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "name") == 0) {
        result = cmd_name(g_engine);
    }
    else if (strcmp(command, "lookup") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'lookup' requires <name> argument\n");
            result = 1;
        } else {
            result = cmd_lookup(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "lookup-profile") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'lookup-profile' requires <name|fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_lookup_profile(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "profile") == 0) {
        if (optind + 1 >= argc) {
            result = cmd_profile(g_engine, NULL, NULL);
        } else {
            /* Parse field=value */
            char *arg = argv[optind + 1];
            char *eq = strchr(arg, '=');
            if (!eq) {
                fprintf(stderr, "Error: profile requires field=value format\n");
                result = 1;
            } else {
                *eq = '\0';
                result = cmd_profile(g_engine, arg, eq + 1);
            }
        }
    }

    /* ====== CONTACT COMMANDS ====== */
    else if (strcmp(command, "contacts") == 0) {
        result = cmd_contacts(g_engine);
    }
    else if (strcmp(command, "add-contact") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'add-contact' requires <name|fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_add_contact(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "remove-contact") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'remove-contact' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_remove_contact(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "request") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'request' requires <fingerprint> argument\n");
            result = 1;
        } else {
            const char *fp = argv[optind + 1];
            const char *msg = (optind + 2 < argc) ? argv[optind + 2] : NULL;
            result = cmd_request(g_engine, fp, msg);
        }
    }
    else if (strcmp(command, "requests") == 0) {
        result = cmd_requests(g_engine);
    }
    else if (strcmp(command, "approve") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'approve' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_approve(g_engine, argv[optind + 1]);
        }
    }

    /* ====== MESSAGING COMMANDS ====== */
    else if (strcmp(command, "send") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: 'send' requires <fingerprint> and <message> arguments\n");
            result = 1;
        } else {
            result = cmd_send(g_engine, argv[optind + 1], argv[optind + 2]);
        }
    }
    else if (strcmp(command, "messages") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'messages' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_messages(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "check-offline") == 0) {
        result = cmd_check_offline(g_engine);
    }
    else if (strcmp(command, "listen") == 0) {
        result = cmd_listen(g_engine);
    }

    /* ====== WALLET COMMANDS ====== */
    else if (strcmp(command, "wallets") == 0) {
        result = cmd_wallets(g_engine);
    }
    else if (strcmp(command, "balance") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'balance' requires <wallet_index> argument\n");
            result = 1;
        } else {
            result = cmd_balance(g_engine, atoi(argv[optind + 1]));
        }
    }

    /* ====== NETWORK COMMANDS ====== */
    else if (strcmp(command, "online") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'online' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_online(g_engine, argv[optind + 1]);
        }
    }

    /* ====== NAT TRAVERSAL COMMANDS ====== */
    else if (strcmp(command, "stun-test") == 0) {
        result = cmd_stun_test();
    }
    else if (strcmp(command, "ice-status") == 0) {
        result = cmd_ice_status(g_engine);
    }
    else if (strcmp(command, "turn-creds") == 0) {
        bool force = (optind + 1 < argc && strcmp(argv[optind + 1], "--force") == 0);
        result = cmd_turn_creds(g_engine, force);
    }
    else if (strcmp(command, "turn-test") == 0) {
        result = cmd_turn_test(g_engine);
    }

    /* ====== UNKNOWN COMMAND ====== */
    else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        fprintf(stderr, "Run '%s --help' for usage.\n", argv[0]);
        result = 1;
    }

    /* Cleanup */
    if (!quiet) {
        fprintf(stderr, "Shutting down...\n");
    }
    dna_engine_destroy(g_engine);
    g_engine = NULL;

    return result < 0 ? 1 : result;
}
