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
    printf("VERSION COMMANDS:\n");
    printf("  publish-version             Publish version info to DHT\n");
    printf("    --lib <ver> --app <ver> --nodus <ver> [--lib-min <ver>] [--app-min <ver>] [--nodus-min <ver>]\n");
    printf("  check-version               Check latest version from DHT\n");
    printf("\n");
    printf("DHT DEBUG COMMANDS:\n");
    printf("  bootstrap-registry          Show DHT bootstrap node registry\n");
    printf("\n");
    printf("GROUP COMMANDS:\n");
    printf("  group-list                  List all groups\n");
    printf("  group-create <name>         Create a new group\n");
    printf("  group-send <name|uuid> <msg>  Send message to group\n");
    printf("  group-info <uuid>           Show group info and members\n");
    printf("  group-invite <uuid> <name|fp>  Invite member to group\n");
    printf("  group-sync <uuid>           Sync group from DHT to local cache\n");
    printf("  group-publish-gek <name|uuid>  Publish GEK to DHT (owner only)\n");
    printf("  gek-fetch <uuid>            Fetch GEK from DHT (debug)\n");
    printf("  group-messages <name|uuid>  Show group conversation\n");
    printf("  group-members <uuid>        List group members\n");
    printf("  invitations                 List pending group invitations\n");
    printf("  invite-accept <uuid>        Accept group invitation\n");
    printf("  invite-reject <uuid>        Reject group invitation\n");
    printf("\n");
    printf("BLOCKING COMMANDS:\n");
    printf("  block <name|fp>             Block a user\n");
    printf("  unblock <fp>                Unblock a user\n");
    printf("  blocked                     List blocked users\n");
    printf("  is-blocked <fp>             Check if user is blocked\n");
    printf("  deny <fp>                   Deny contact request\n");
    printf("  request-count               Count pending contact requests\n");
    printf("\n");
    printf("MESSAGE QUEUE COMMANDS:\n");
    printf("  queue-status                Show message queue status\n");
    printf("  queue-send <fp> <msg>       Queue message for async sending\n");
    printf("  set-queue-capacity <n>      Set message queue capacity\n");
    printf("  retry-pending               Retry all pending messages\n");
    printf("  retry-message <id>          Retry single message by ID\n");
    printf("\n");
    printf("MESSAGE MANAGEMENT COMMANDS:\n");
    printf("  delete-message <id>         Delete message by ID\n");
    printf("  mark-read <name|fp>         Mark conversation as read\n");
    printf("  unread <name|fp>            Get unread count for contact\n");
    printf("  messages-page <fp> [n] [off]  Paginated messages (limit, offset)\n");
    printf("\n");
    printf("DHT SYNC COMMANDS:\n");
    printf("  sync-contacts-up            Push contacts to DHT\n");
    printf("  sync-contacts-down          Pull contacts from DHT\n");
    printf("  sync-groups                 Sync all groups from DHT\n");
    printf("  sync-groups-up              Push groups to DHT\n");
    printf("  sync-groups-down            Pull groups from DHT (restore)\n");
    printf("  refresh-presence            Refresh presence in DHT\n");
    printf("  presence <name|fp>          Lookup peer presence\n");
    printf("  dht-status                  Check DHT connection status\n");
    printf("\n");
    printf("DEBUG COMMANDS:\n");
    printf("  log-level [level]           Get/set log level (DEBUG/INFO/WARN/ERROR)\n");
    printf("  log-tags [tags]             Get/set log tag filter\n");
    printf("  debug-log <on|off>          Enable/disable debug logging\n");
    printf("  debug-entries [n]           Get recent log entries (default 50)\n");
    printf("  debug-count                 Get log entry count\n");
    printf("  debug-clear                 Clear debug log\n");
    printf("  debug-export <file>         Export debug log to file\n");
    printf("\n");
    printf("PRESENCE CONTROL COMMANDS:\n");
    printf("  pause-presence              Pause presence updates\n");
    printf("  resume-presence             Resume presence updates\n");
    printf("  network-changed             Reinit DHT after network change\n");
    printf("\n");
    printf("IDENTITY EXTENSION COMMANDS:\n");
    printf("  set-nickname <fp> <nick>    Set local nickname for contact\n");
    printf("  get-avatar <fp>             Get contact avatar info\n");
    printf("  get-mnemonic                Show recovery phrase (24 words)\n");
    printf("  refresh-profile <fp>        Force refresh contact profile from DHT\n");
    printf("\n");
    printf("EXTENDED WALLET COMMANDS:\n");
    printf("  send-tokens <w> <net> <tok> <to> <amt>  Send tokens\n");
    printf("  transactions <wallet_idx>   Show transaction history\n");
    printf("  estimate-gas <network_id>   Estimate ETH gas fees\n");
    printf("\n");
    printf("DNA BOARD COMMANDS:\n");
    printf("  feed-channels               List feed channels\n");
    printf("  feed-init                   Initialize default channels\n");
    printf("  feed-create-channel <name> [desc]  Create channel\n");
    printf("  feed-posts <channel_id>     List posts in channel\n");
    printf("  feed-post <channel_id> <text>  Create post\n");
    printf("  feed-vote <post_id> <up|down>  Vote on post\n");
    printf("  feed-votes <post_id>        Get vote counts\n");
    printf("  feed-comments <post_id>     List comments on post\n");
    printf("  feed-comment <post_id> <text>  Add comment\n");
    printf("  feed-comment-vote <id> <up|down>  Vote on comment\n");
    printf("  feed-comment-votes <id>     Get comment votes\n");
    printf("\n");
    printf("BACKUP COMMANDS:\n");
    printf("  backup-messages             Backup messages to DHT\n");
    printf("  restore-messages            Restore messages from DHT\n");
    printf("\n");
    printf("SIGNING COMMANDS:\n");
    printf("  sign <data>                 Sign data with Dilithium5\n");
    printf("  signing-pubkey              Get signing public key\n");
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

    /* ====== VERSION COMMANDS ====== */
    else if (strcmp(command, "publish-version") == 0) {
        /* Parse --lib, --app, --nodus and their -min variants */
        char *lib_ver = NULL, *lib_min = NULL;
        char *app_ver = NULL, *app_min = NULL;
        char *nodus_ver = NULL, *nodus_min = NULL;

        for (int i = optind + 1; i < argc; i++) {
            if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) {
                lib_ver = argv[++i];
            } else if (strcmp(argv[i], "--lib-min") == 0 && i + 1 < argc) {
                lib_min = argv[++i];
            } else if (strcmp(argv[i], "--app") == 0 && i + 1 < argc) {
                app_ver = argv[++i];
            } else if (strcmp(argv[i], "--app-min") == 0 && i + 1 < argc) {
                app_min = argv[++i];
            } else if (strcmp(argv[i], "--nodus") == 0 && i + 1 < argc) {
                nodus_ver = argv[++i];
            } else if (strcmp(argv[i], "--nodus-min") == 0 && i + 1 < argc) {
                nodus_min = argv[++i];
            }
        }

        if (!lib_ver || !app_ver || !nodus_ver) {
            fprintf(stderr, "Usage: publish-version --lib <ver> --app <ver> --nodus <ver>\n");
            fprintf(stderr, "       [--lib-min <ver>] [--app-min <ver>] [--nodus-min <ver>]\n");
            result = 1;
        } else {
            result = cmd_publish_version(g_engine, lib_ver, lib_min, app_ver, app_min, nodus_ver, nodus_min);
        }
    }
    else if (strcmp(command, "check-version") == 0) {
        result = cmd_check_version(g_engine);
    }

    /* ====== DHT DEBUG COMMANDS ====== */
    else if (strcmp(command, "bootstrap-registry") == 0) {
        result = cmd_bootstrap_registry(g_engine);
    }

    /* ====== GROUP COMMANDS ====== */
    else if (strcmp(command, "group-list") == 0) {
        result = cmd_group_list(g_engine);
    }
    else if (strcmp(command, "group-create") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'group-create' requires <name> argument\n");
            result = 1;
        } else {
            result = cmd_group_create(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "group-send") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: 'group-send' requires <name|uuid> and <message> arguments\n");
            result = 1;
        } else {
            result = cmd_group_send(g_engine, argv[optind + 1], argv[optind + 2]);
        }
    }
    else if (strcmp(command, "group-info") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'group-info' requires <uuid> argument\n");
            result = 1;
        } else {
            result = cmd_group_info(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "group-invite") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: 'group-invite' requires <uuid> and <fingerprint> arguments\n");
            result = 1;
        } else {
            result = cmd_group_invite(g_engine, argv[optind + 1], argv[optind + 2]);
        }
    }
    else if (strcmp(command, "group-sync") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'group-sync' requires <uuid> argument\n");
            result = 1;
        } else {
            result = cmd_group_sync(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "group-publish-gek") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'group-publish-gek' requires <name|uuid> argument\n");
            result = 1;
        } else {
            result = cmd_group_publish_gek(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "gek-fetch") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'gek-fetch' requires <uuid> argument\n");
            result = 1;
        } else {
            result = cmd_gek_fetch(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "group-messages") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'group-messages' requires <name|uuid> argument\n");
            result = 1;
        } else {
            result = cmd_group_messages(g_engine, argv[optind + 1]);
        }
    }

    /* ====== PHASE 1: CONTACT BLOCKING & REQUESTS ====== */
    else if (strcmp(command, "block") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'block' requires <name|fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_block(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "unblock") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'unblock' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_unblock(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "blocked") == 0) {
        result = cmd_blocked(g_engine);
    }
    else if (strcmp(command, "is-blocked") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'is-blocked' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_is_blocked(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "deny") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'deny' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_deny(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "request-count") == 0) {
        result = cmd_request_count(g_engine);
    }

    /* ====== PHASE 2: MESSAGE QUEUE OPERATIONS ====== */
    else if (strcmp(command, "queue-status") == 0) {
        result = cmd_queue_status(g_engine);
    }
    else if (strcmp(command, "queue-send") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: 'queue-send' requires <fingerprint> and <message> arguments\n");
            result = 1;
        } else {
            result = cmd_queue_send(g_engine, argv[optind + 1], argv[optind + 2]);
        }
    }
    else if (strcmp(command, "set-queue-capacity") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'set-queue-capacity' requires <capacity> argument\n");
            result = 1;
        } else {
            result = cmd_set_queue_capacity(g_engine, atoi(argv[optind + 1]));
        }
    }
    else if (strcmp(command, "retry-pending") == 0) {
        result = cmd_retry_pending(g_engine);
    }
    else if (strcmp(command, "retry-message") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'retry-message' requires <message_id> argument\n");
            result = 1;
        } else {
            result = cmd_retry_message(g_engine, atoll(argv[optind + 1]));
        }
    }

    /* ====== PHASE 3: MESSAGE MANAGEMENT ====== */
    else if (strcmp(command, "delete-message") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'delete-message' requires <message_id> argument\n");
            result = 1;
        } else {
            result = cmd_delete_message(g_engine, atoll(argv[optind + 1]));
        }
    }
    else if (strcmp(command, "mark-read") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'mark-read' requires <name|fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_mark_read(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "unread") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'unread' requires <name|fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_unread(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "messages-page") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'messages-page' requires <name|fingerprint> [limit] [offset] arguments\n");
            result = 1;
        } else {
            int limit = (optind + 2 < argc) ? atoi(argv[optind + 2]) : 50;
            int offset = (optind + 3 < argc) ? atoi(argv[optind + 3]) : 0;
            result = cmd_messages_page(g_engine, argv[optind + 1], limit, offset);
        }
    }

    /* ====== PHASE 4: DHT SYNC OPERATIONS ====== */
    else if (strcmp(command, "sync-contacts-up") == 0) {
        result = cmd_sync_contacts_up(g_engine);
    }
    else if (strcmp(command, "sync-contacts-down") == 0) {
        result = cmd_sync_contacts_down(g_engine);
    }
    else if (strcmp(command, "sync-groups") == 0) {
        result = cmd_sync_groups(g_engine);
    }
    else if (strcmp(command, "sync-groups-up") == 0) {
        result = cmd_sync_groups_up(g_engine);
    }
    else if (strcmp(command, "sync-groups-down") == 0) {
        result = cmd_sync_groups_down(g_engine);
    }
    else if (strcmp(command, "refresh-presence") == 0) {
        result = cmd_refresh_presence(g_engine);
    }
    else if (strcmp(command, "presence") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'presence' requires <name|fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_presence(g_engine, argv[optind + 1]);
        }
    }

    /* ====== PHASE 5: DEBUG LOGGING ====== */
    else if (strcmp(command, "log-level") == 0) {
        const char *level = (optind + 1 < argc) ? argv[optind + 1] : NULL;
        result = cmd_log_level(g_engine, level);
    }
    else if (strcmp(command, "log-tags") == 0) {
        const char *tags = (optind + 1 < argc) ? argv[optind + 1] : NULL;
        result = cmd_log_tags(g_engine, tags);
    }
    else if (strcmp(command, "debug-log") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'debug-log' requires <on|off> argument\n");
            result = 1;
        } else {
            bool enable = (strcmp(argv[optind + 1], "on") == 0 ||
                          strcmp(argv[optind + 1], "true") == 0 ||
                          strcmp(argv[optind + 1], "1") == 0);
            result = cmd_debug_log(g_engine, enable);
        }
    }
    else if (strcmp(command, "debug-entries") == 0) {
        int count = (optind + 1 < argc) ? atoi(argv[optind + 1]) : 50;
        result = cmd_debug_entries(g_engine, count);
    }
    else if (strcmp(command, "debug-count") == 0) {
        result = cmd_debug_count(g_engine);
    }
    else if (strcmp(command, "debug-clear") == 0) {
        result = cmd_debug_clear(g_engine);
    }
    else if (strcmp(command, "debug-export") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'debug-export' requires <filepath> argument\n");
            result = 1;
        } else {
            result = cmd_debug_export(g_engine, argv[optind + 1]);
        }
    }

    /* ====== PHASE 6: GROUP EXTENSIONS ====== */
    else if (strcmp(command, "group-members") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'group-members' requires <uuid> argument\n");
            result = 1;
        } else {
            result = cmd_group_members(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "invitations") == 0) {
        result = cmd_invitations(g_engine);
    }
    else if (strcmp(command, "invite-accept") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'invite-accept' requires <uuid> argument\n");
            result = 1;
        } else {
            result = cmd_invite_accept(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "invite-reject") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'invite-reject' requires <uuid> argument\n");
            result = 1;
        } else {
            result = cmd_invite_reject(g_engine, argv[optind + 1]);
        }
    }

    /* ====== PHASE 7: PRESENCE CONTROL ====== */
    else if (strcmp(command, "pause-presence") == 0) {
        result = cmd_pause_presence(g_engine);
    }
    else if (strcmp(command, "resume-presence") == 0) {
        result = cmd_resume_presence(g_engine);
    }
    else if (strcmp(command, "network-changed") == 0) {
        result = cmd_network_changed(g_engine);
    }

    /* ====== PHASE 8: CONTACT & IDENTITY EXTENSIONS ====== */
    else if (strcmp(command, "set-nickname") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: 'set-nickname' requires <fingerprint> <nickname> arguments\n");
            result = 1;
        } else {
            result = cmd_set_nickname(g_engine, argv[optind + 1], argv[optind + 2]);
        }
    }
    else if (strcmp(command, "get-avatar") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'get-avatar' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_get_avatar(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "get-mnemonic") == 0) {
        result = cmd_get_mnemonic(g_engine);
    }
    else if (strcmp(command, "refresh-profile") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'refresh-profile' requires <fingerprint> argument\n");
            result = 1;
        } else {
            result = cmd_refresh_profile(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "dht-status") == 0) {
        result = cmd_dht_status(g_engine);
    }

    /* ====== PHASE 9: WALLET OPERATIONS ====== */
    else if (strcmp(command, "send-tokens") == 0) {
        if (optind + 5 >= argc) {
            fprintf(stderr, "Error: 'send-tokens' requires <wallet_idx> <network> <token> <to> <amount> arguments\n");
            result = 1;
        } else {
            result = cmd_send_tokens(g_engine, atoi(argv[optind + 1]),
                                     argv[optind + 2], argv[optind + 3],
                                     argv[optind + 4], argv[optind + 5]);
        }
    }
    else if (strcmp(command, "transactions") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'transactions' requires <wallet_index> argument\n");
            result = 1;
        } else {
            result = cmd_transactions(g_engine, atoi(argv[optind + 1]));
        }
    }
    else if (strcmp(command, "estimate-gas") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'estimate-gas' requires <network_id> argument\n");
            result = 1;
        } else {
            result = cmd_estimate_gas(g_engine, atoi(argv[optind + 1]));
        }
    }

    /* ====== PHASE 10: FEED v2 (Topic-based public feeds) ====== */
    else if (strcmp(command, "feeds") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'feeds' requires a subcommand\n");
            fprintf(stderr, "Usage:\n");
            fprintf(stderr, "  feeds create <title> <body> [--category CAT] [--tags \"tag1,tag2\"]\n");
            fprintf(stderr, "  feeds get <uuid>\n");
            fprintf(stderr, "  feeds delete <uuid>\n");
            fprintf(stderr, "  feeds list --category <category> [--days N]\n");
            fprintf(stderr, "  feeds list-all [--days N]\n");
            fprintf(stderr, "  feeds comment <topic-uuid> <body> [--mentions \"fp1,fp2\"]\n");
            fprintf(stderr, "  feeds comments <topic-uuid>\n");
            result = 1;
        } else {
            const char *subcmd = argv[optind + 1];

            if (strcmp(subcmd, "create") == 0) {
                if (optind + 3 >= argc) {
                    fprintf(stderr, "Error: 'feeds create' requires <title> <body>\n");
                    result = 1;
                } else {
                    const char *title = argv[optind + 2];
                    const char *body = argv[optind + 3];
                    const char *category = NULL;
                    const char *tags = NULL;

                    /* Parse optional args */
                    for (int i = optind + 4; i < argc; i++) {
                        if (strcmp(argv[i], "--category") == 0 && i + 1 < argc) {
                            category = argv[++i];
                        } else if (strcmp(argv[i], "--tags") == 0 && i + 1 < argc) {
                            tags = argv[++i];
                        }
                    }

                    result = cmd_feeds_create(g_engine, title, body, category, tags);
                }
            }
            else if (strcmp(subcmd, "get") == 0) {
                if (optind + 2 >= argc) {
                    fprintf(stderr, "Error: 'feeds get' requires <uuid>\n");
                    result = 1;
                } else {
                    result = cmd_feeds_get(g_engine, argv[optind + 2]);
                }
            }
            else if (strcmp(subcmd, "delete") == 0) {
                if (optind + 2 >= argc) {
                    fprintf(stderr, "Error: 'feeds delete' requires <uuid>\n");
                    result = 1;
                } else {
                    result = cmd_feeds_delete(g_engine, argv[optind + 2]);
                }
            }
            else if (strcmp(subcmd, "list") == 0) {
                const char *category = NULL;
                int days = 7;

                /* Parse required --category and optional --days */
                for (int i = optind + 2; i < argc; i++) {
                    if (strcmp(argv[i], "--category") == 0 && i + 1 < argc) {
                        category = argv[++i];
                    } else if (strcmp(argv[i], "--days") == 0 && i + 1 < argc) {
                        days = atoi(argv[++i]);
                    }
                }

                if (!category) {
                    fprintf(stderr, "Error: 'feeds list' requires --category <category>\n");
                    fprintf(stderr, "Use 'feeds list-all' to list all categories\n");
                    result = 1;
                } else {
                    result = cmd_feeds_list(g_engine, category, days);
                }
            }
            else if (strcmp(subcmd, "list-all") == 0) {
                int days = 7;

                /* Parse optional --days */
                for (int i = optind + 2; i < argc; i++) {
                    if (strcmp(argv[i], "--days") == 0 && i + 1 < argc) {
                        days = atoi(argv[++i]);
                    }
                }

                result = cmd_feeds_list_all(g_engine, days);
            }
            else if (strcmp(subcmd, "comment") == 0) {
                if (optind + 3 >= argc) {
                    fprintf(stderr, "Error: 'feeds comment' requires <topic-uuid> <body>\n");
                    result = 1;
                } else {
                    const char *topic_uuid = argv[optind + 2];
                    const char *body = argv[optind + 3];
                    const char *mentions = NULL;

                    /* Parse optional --mentions */
                    for (int i = optind + 4; i < argc; i++) {
                        if (strcmp(argv[i], "--mentions") == 0 && i + 1 < argc) {
                            mentions = argv[++i];
                        }
                    }

                    result = cmd_feeds_comment(g_engine, topic_uuid, body, mentions);
                }
            }
            else if (strcmp(subcmd, "comments") == 0) {
                if (optind + 2 >= argc) {
                    fprintf(stderr, "Error: 'feeds comments' requires <topic-uuid>\n");
                    result = 1;
                } else {
                    result = cmd_feeds_comments(g_engine, argv[optind + 2]);
                }
            }
            else {
                fprintf(stderr, "Error: Unknown feeds subcommand '%s'\n", subcmd);
                result = 1;
            }
        }
    }

    /* ====== PHASE 11: MESSAGE BACKUP ====== */
    else if (strcmp(command, "backup-messages") == 0) {
        result = cmd_backup_messages(g_engine);
    }
    else if (strcmp(command, "restore-messages") == 0) {
        result = cmd_restore_messages(g_engine);
    }

    /* ====== PHASE 12: SIGNING API ====== */
    else if (strcmp(command, "sign") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'sign' requires <data> argument\n");
            result = 1;
        } else {
            result = cmd_sign(g_engine, argv[optind + 1]);
        }
    }
    else if (strcmp(command, "signing-pubkey") == 0) {
        result = cmd_signing_pubkey(g_engine);
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
