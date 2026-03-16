/*
 * DNA Connect CLI - Main Entry Point
 *
 * Single-command CLI for testing DNA Connect without GUI.
 * Designed for automated testing by Claude AI.
 *
 * Usage:
 *   dna-connect-cli [OPTIONS] <command> [args...]
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
#include "dht/shared/nodus_init.h"

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
    printf("DNA Connect CLI v%s\n\n", DNA_VERSION_STRING);
    printf("Usage: %s [OPTIONS] <group> <command> [args...]\n\n", prog_name);
    printf("Options:\n");
    printf("  -d, --data-dir <path>   Data directory (default: ~/.dna)\n");
    printf("  -i, --identity <fp>     Use specific identity\n");
    printf("  -q, --quiet             Suppress banner/status messages\n");
    printf("  -h, --help              Show this help\n");
    printf("  -v, --version           Show version\n");
    printf("\n");
    printf("Command Groups:\n");
    printf("  identity    Identity management (create, restore, load, profile, ...)\n");
    printf("  contact     Contact management (add, remove, request, block, ...)\n");
    printf("  message     Messaging (send, list, queue, backup, ...)\n");
    printf("  group       Group chat (create, invite, send, sync, ...)\n");
    printf("  channel     Channels (create, post, subscribe, ...)\n");
    printf("  wallet      Wallet operations (balance, send, transactions, ...)\n");
    printf("  dex         DEX trading (quote, pairs)\n");
    printf("  network     Network & presence (online, dht-status, ...)\n");
    printf("  version     Version management (publish, check)\n");
    printf("  sign        Signing (data, pubkey)\n");
    printf("  wall        Wall posts (post, list, timeline, comments, likes, ...)\n");
    printf("  debug       Debug & logging (log-level, entries, export, ...)\n");
    printf("\n");
    printf("Run '%s <group>' for subcommand details.\n", prog_name);
    printf("\n");
    printf("Examples:\n");
    printf("  %s identity create alice\n", prog_name);
    printf("  %s contact add bob\n", prog_name);
    printf("  %s message send nox \"Hello!\"\n", prog_name);
    printf("  %s wallet balance 0\n", prog_name);
    printf("  %s dex quote ETH USDC 1.0\n", prog_name);
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
    if (!nodus_messenger_is_initialized()) {
        if (!quiet) {
            fprintf(stderr, "Warning: Nodus not initialized\n");
        }
        return -1;
    }

    if (!quiet) {
        fprintf(stderr, "Waiting for DHT connection...");
    }

    if (nodus_messenger_wait_for_ready(timeout_sec * 1000)) {
        if (!quiet) {
            fprintf(stderr, " connected!\n");
        }
        return 0;
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

    /* Load the single identity (fingerprint computed internally).
     * cmd_load() already prints "Loading identity..." to stdout. */
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
                printf("dna-connect-cli v%s (build %s %s)\n",
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

    /* If a known group is called with no subcommand or "help", show group help without engine init.
     * Also catch unknown groups early to avoid unnecessary engine init. */
    int bare_group = (optind + 1 >= argc) ||
                     (optind + 1 < argc && strcmp(argv[optind + 1], "help") == 0);
    const char *known_groups[] = {"identity", "contact", "message", "group", "channel",
                                  "wallet", "dex", "network", "version", "sign", "debug", "wall", NULL};
    if (bare_group) {
        for (int i = 0; known_groups[i]; i++) {
            if (strcmp(command, known_groups[i]) == 0) {
                /* Dispatchers print usage when sub >= argc (no subcommand) */
                if (strcmp(command, "identity") == 0) dispatch_identity(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "contact") == 0) dispatch_contact(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "message") == 0) dispatch_message(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "group") == 0) dispatch_group(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "channel") == 0) dispatch_channel(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "wallet") == 0) dispatch_wallet(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "dex") == 0) dispatch_dex(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "network") == 0) dispatch_network(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "version") == 0) dispatch_version(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "sign") == 0) dispatch_sign(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "debug") == 0) dispatch_debug(NULL, argc, argv, optind + 1);
                else if (strcmp(command, "wall") == 0) dispatch_wall(NULL, argc, argv, optind + 1);
                return 1;
            }
        }
    }

    /* Check for unknown group early — no engine init needed */
    {
        int is_known = 0;
        for (int i = 0; known_groups[i]; i++) {
            if (strcmp(command, known_groups[i]) == 0) { is_known = 1; break; }
        }
        if (!is_known) {
            fprintf(stderr, "Unknown command group: '%s'\n", command);
            fprintf(stderr, "Run '%s help' for available groups.\n", argv[0]);
            return 1;
        }
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

    /* Groups/subcommands that do NOT need an identity loaded */
    int needs_identity = 1;

    /* Note: bare group (no subcommand) and "help" subcommand are caught
     * earlier by the bare_group check and never reach here. */
    if (strcmp(command, "identity") == 0 && optind + 1 < argc) {
        const char *sub = argv[optind + 1];
        if (strcmp(sub, "create") == 0 || strcmp(sub, "restore") == 0 ||
            strcmp(sub, "delete") == 0 || strcmp(sub, "list") == 0) {
            needs_identity = 0;
        }
    }
    else if (strcmp(command, "version") == 0 && optind + 1 < argc) {
        /* version check needs DHT, which needs identity — keep needs_identity = 1 */
        (void)0;
    }
    else if (strcmp(command, "debug") == 0) {
        needs_identity = 0;
    }

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

    /* ====== GROUP DISPATCH ====== */
    if (strcmp(command, "help") == 0) {
        print_usage(argv[0]);
        result = 0;
    }
    else if (strcmp(command, "identity") == 0) {
        result = dispatch_identity(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "contact") == 0) {
        result = dispatch_contact(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "message") == 0) {
        result = dispatch_message(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "group") == 0) {
        result = dispatch_group(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "channel") == 0) {
        result = dispatch_channel(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "wallet") == 0) {
        result = dispatch_wallet(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "dex") == 0) {
        result = dispatch_dex(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "network") == 0) {
        result = dispatch_network(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "version") == 0) {
        result = dispatch_version(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "sign") == 0) {
        result = dispatch_sign(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "debug") == 0) {
        result = dispatch_debug(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "wall") == 0) {
        result = dispatch_wall(g_engine, argc, argv, optind + 1);
    }
    else {
        fprintf(stderr, "Unknown command group: '%s'\n", command);
        fprintf(stderr, "Run '%s help' for available groups.\n", argv[0]);
        result = 1;
    }

    /* Cleanup — flush stdout before destroy so command output appears before any
     * stderr noise from engine teardown */
    fflush(stdout);
    dna_engine_destroy(g_engine);
    g_engine = NULL;

    return result < 0 ? 1 : result;
}
