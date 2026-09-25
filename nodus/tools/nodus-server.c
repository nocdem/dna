/**
 * Nodus — Server Entry Point
 *
 * Start a Nodus DHT server with optional config file.
 *
 * Usage:
 *   nodus-server [-c <config.json>] [-b <bind_ip>] [-u <udp_port>]
 *                [-t <tcp_port>] [-i <identity_dir>] [-d <data_dir>]
 *                [-s <seed_ip:port>] [-h]
 */

#include "server/nodus_server.h"
#include "witness/nodus_witness_peer.h"   /* PR 3 / F4 — mock_version setter */
#include "witness/nodus_witness_v2_gen.h" /* O16A / D1 — the genesis builder */
#include "nodus_v2_gen_config.h"          /* O16A / D2 — its text config     */
#include "nodus/nodus_types.h"

#include <dirent.h>
#include <sys/stat.h>                     /* O16A — derive-time sentinel check */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sqlite3.h>

#ifdef NODUS_HAS_JSONC
#include <json-c/json.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#endif

static nodus_server_t server;

static void sighandler(int sig) {
    (void)sig;
    nodus_server_stop(&server);
}

static void usage(const char *prog) {
    fprintf(stderr, "Nodus Server v%s\n", NODUS_VERSION_STRING);
    fprintf(stderr, "Usage: %s [options]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c <config.json>  Load config from JSON file\n");
    fprintf(stderr, "  -b <bind_ip>      Bind address (default: 0.0.0.0)\n");
    fprintf(stderr, "  -u <udp_port>     UDP port (default: %d)\n", NODUS_DEFAULT_UDP_PORT);
    fprintf(stderr, "  -t <tcp_port>     TCP port (default: %d)\n", NODUS_DEFAULT_TCP_PORT);
    fprintf(stderr, "  -p <peer_port>    Inter-node TCP port (default: %d)\n", NODUS_DEFAULT_PEER_PORT);
    fprintf(stderr, "  -C <ch_port>      Channel TCP port (default: %d)\n", NODUS_DEFAULT_CH_PORT);
    fprintf(stderr, "  -W <witness_port> Witness BFT TCP port (default: %d)\n", NODUS_DEFAULT_WITNESS_PORT);
    fprintf(stderr, "  -i <identity_dir> Identity directory\n");
    fprintf(stderr, "  -d <data_dir>     Data directory (default: /var/lib/nodus)\n");
    fprintf(stderr, "  -s <ip:port>      Add seed node (repeatable)\n");
    fprintf(stderr, "  --v2-genesis-pin <64hex>\n");
    fprintf(stderr, "                    JOIN an existing chain: the local trust\n");
    fprintf(stderr, "                    anchor (the 32-byte chain id) a pulled\n");
    fprintf(stderr, "                    genesis bundle must re-derive to.\n");
    fprintf(stderr, "  --derive-v2-genesis <config-file>\n");
    fprintf(stderr, "                    CREATE a chain in -d <data_dir> from an\n");
    fprintf(stderr, "                    operator genesis config, print the chain\n");
    fprintf(stderr, "                    id, and EXIT. Offline one-shot: no socket\n");
    fprintf(stderr, "                    is opened and no server is constructed.\n");
    fprintf(stderr, "                    Mutually exclusive with --v2-genesis-pin.\n");
    fprintf(stderr, "  -h                Show this help\n");
}

/* PR 3 / E1 — long-option IDs for getopt_long. Numeric > 255 to avoid
 * collision with single-char short options.
 * R3 W4 — LONGOPT_COLD_BOOTSTRAP (and the "cold-bootstrap" option it
 * named) is DELETED with the closed consensus lane: its one reader,
 * nodus_witness_bootstrap.c, is deleted. */
#define LONGOPT_MOCK_NODUS_VER    1001
#define LONGOPT_V2_GENESIS_PIN    1002
#define LONGOPT_DERIVE_V2_GENESIS 1003

static const struct option g_longopts[] = {
    {"mock-nodus-version", required_argument, NULL, LONGOPT_MOCK_NODUS_VER},
    {"v2-genesis-pin",     required_argument, NULL, LONGOPT_V2_GENESIS_PIN},
    {"derive-v2-genesis",  required_argument, NULL, LONGOPT_DERIVE_V2_GENESIS},
    {0, 0, 0, 0}
};

/* R3 W3 (D-24 rev 4 (1)) — parse a 64-hex-char successor chain-id pin.
 * Was 128 hex / 64 bytes (a genesis BlockID); a version-3 chain has no
 * genesis BLOCK to pin one to (D-19 rev 6), so the pin is the 32-byte
 * chain id instead. */
static int parse_v2_pin(const char *hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        char *end = NULL;
        v = (unsigned)strtoul(b, &end, 16);
        if (end != b + 2) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* ── O16A / D1 — the offline genesis derivation one-shot ─────────────
 *
 * Everything below runs INSTEAD OF starting a server, never beside one.
 * That shape is not a convenience; two properties of the ceremony fall
 * out of it rather than out of a check:
 *
 *  - The node is not on the network while the chain is being derived.
 *    nodus_witness_v2_gen_derive_v3 takes no witness and no server
 *    handle (nodus_witness_v2_gen.h), so nothing arriving from a peer can
 *    reach a derived byte; with an offline tool there is additionally no
 *    process a peer could talk to.
 *  - The two abort()ing migrations inside nodus_witness_create_chain_db
 *    (nodus_witness_db.c, migrate_v12's ALTER and DROP INDEX paths)
 *    cannot kill a live node. On a one-shot tool an abort is a failed
 *    ceremony step the operator sees on their terminal; inside a running
 *    node it is a process death.
 *
 * ⚠ The rejected alternative was "derive automatically when the data dir
 * is empty and a genesis config is present". A node that lost its
 * database would then silently re-derive a chain instead of refusing or
 * joining, and in a hard cutover there is no second chance: the operator
 * gets a node that looks healthy and is on its own chain.
 */

/* Print a byte string as lowercase hex on stdout. */
static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

/* Locate the single chain database in `dir`.
 *
 * The filename predicate is character-for-character the one
 * gen_chain_db_scan uses (nodus_witness_v2_gen.c). That agreement is
 * load-bearing rather than tidy: if this tool counted a file the builder
 * ignores — or missed one it counts — the operator would be shown a pin
 * for a database the builder does not consider part of the data path.
 *
 * @return 0 exactly one found (path written), -1 otherwise. */
static int find_single_chain_db(const char *dir, char *out, size_t out_len) {
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "cannot read data directory %s\n", dir);
        return -1;
    }
    struct dirent *e;
    int found = 0;
    int truncated = 0;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".db") != 0) continue;
        found++;
        if (found == 1) {
            int n = snprintf(out, out_len, "%s/%s", dir, e->d_name);
            if (n < 0 || (size_t)n >= out_len) truncated = 1;
        }
    }
    closedir(d);
    if (truncated) {
        fprintf(stderr,
                "the chain database path under %s is too long to express — "
                "refusing rather than reading a truncated path\n", dir);
        return -1;
    }
    if (found == 1) return 0;
    /* More than one is refused rather than reported: with two chain
     * databases present, "which chain did this ceremony produce" has no
     * answer, and printing whichever readdir handed over first would make
     * the operator's pin depend on filesystem order. */
    fprintf(stderr,
            "expected exactly one witness_<hex>.db in %s after a "
            "derivation, found %d\n", dir, found);
    return -1;
}

/* Read the committed chain id out of a landed version-3 chain database.
 *
 * R3 W3 (D-17 rev 10 (8) / D-18 rev 4): a version-3 chain writes no
 * height-0 `v2_blocks` row (D-19 rev 6 withdrew the genesis block) — its
 * identity is the hash of its stored genesis DOCUMENT, read through the
 * canonical-strict accessor `nodus_witness_v2_gen_stored_chain_id`
 * (nodus_witness_v2_gen.h), the same reader the preflight and the join
 * pipeline use. `nodus_witness_v2_gen_stored_chain_id`'s own doc comment
 * says only `w->db` is used, so a read-only handle with nothing else set
 * is enough — no full witness-open ceremony is needed for an offline
 * tool.
 *
 * @return 0 / -1. */
static int read_genesis_chain_id(const char *db_path,
                                 uint8_t out[NODUS_V2_GEN_CHAIN_ID_LEN]) {
    /* Heap-allocated, never on the stack — the project convention for
     * every nodus_witness_t instance (it is far larger than a fixture
     * needs to be to overflow a default thread stack). */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    if (sqlite3_open_v2(db_path, &w->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        fprintf(stderr, "cannot open the derived chain database %s\n",
                db_path);
        return -1;
    }
    int rc = nodus_witness_v2_gen_stored_chain_id(w, out);
    sqlite3_close(w->db);
    free(w);
    if (rc != 0)
        fprintf(stderr,
                "the derived chain database %s has no readable genesis "
                "document identity — the W_V2GEN lines above name the "
                "reason\n", db_path);
    return rc;
}

/* Parse the config, derive the chain into `data_path`, print the two
 * values the ceremony needs, and return the process exit code. */
/* Refuse to derive into a data directory that still carries unfinished
 * business from a previous life.
 *
 * ── WHAT WOULD HAVE TO HAPPEN, because a risk without a cause is a
 * guess ──────────────────────────────────────────────────────────────
 *
 * Two dotfiles live beside the chain, and BOTH SURVIVE THE CEREMONY'S
 * WIPE: the runbook removes `witness_*`, and a name beginning with a dot
 * does not match that glob.
 *
 *   .bootstrap_in_progress — written by the LEGACY FETCH_GENESIS handler,
 *     which used to create it before deriving a chain database and unlink
 *     it on success. R3 W4 deleted that handler (and the DISCOVER branch
 *     that reached it) with the closed consensus lane, so a binary built
 *     from this tree can no longer write this file; present at boot, it
 *     means an OLDER binary died mid-write before this delta.
 *
 *   .recovery_in_progress — armed by halt recovery between dropping the
 *     witness database and replaying the first block.
 *
 * For either to be sitting here when the ceremony runs, a node must have
 * died inside one of those windows AND never been restarted since —
 * because the very next start clears the first and refuses on the
 * second. A stop-all cutover is exactly the situation that supplies the
 * "never restarted": the node crashed, nobody brought it back, and the
 * operator moved straight to the ceremony.
 *
 * ── WHY THIS IS WORTH A CHECK, given how narrow that is ──────────────
 *
 * The two consequences are not equally survivable. `.recovery_in_progress`
 * REFUSES the start, loudly, printing its own remedy — annoying, not
 * dangerous. `.bootstrap_in_progress` is the dangerous one: witness init
 * hands it to nodus_witness_check_orphan_bootstrap_sentinel, which calls
 * witness_archive_stale_chain_dbs(data_path, NULL) — and NULL means
 * archive EVERY witness_<hex>.db in the directory, including the genesis
 * chain derived twenty minutes earlier. It then clears the sentinel and
 * the node comes up reporting "no chain DB found — pre-genesis state".
 * A correct ceremony, silently undone, with no error anywhere.
 *
 * ── WHY HERE AND NOT IN THE ARCHIVE PATH ─────────────────────────────
 *
 * The archive is not wrong about what it was written for: a partial
 * database from a crashed legacy bootstrap IS garbage. It is wrong only
 * about a pure-V2 chain, which that path never produced. Teaching it the
 * difference means touching witness init; refusing here costs one stat
 * per ceremony and puts the message in front of the operator at the one
 * moment they are present, with nothing derived yet to lose.
 *
 * And the window is now closed for every node, not just a pure-V2 one:
 * R3 W4 deleted the legacy DISCOVER/FETCH_GENESIS bootstrap path
 * (nodus_witness_bootstrap_start and the verbs it drove) outright, so
 * no binary built from this tree can write .bootstrap_in_progress
 * again. The reader side this precheck guards against —
 * nodus_witness_check_orphan_bootstrap_sentinel and
 * witness_archive_stale_chain_dbs, both still live in nodus_witness.c
 * — is unchanged, which is why a sentinel left by an older binary is
 * still worth refusing on here.
 *
 * @return 0 clean, -1 refuse. */
static int derive_precheck_sentinels(const char *data_path) {
    static const struct {
        const char *name;
        const char *what;
    } sentinels[] = {
        { ".bootstrap_in_progress",
          "a previous LEGACY bootstrap died mid-write. Left in place, the "
          "next start would ARCHIVE the chain this ceremony is about to "
          "derive and come up as if it had none" },
        { ".recovery_in_progress",
          "a previous halt recovery did not finish. Left in place, the "
          "next start refuses outright" },
    };

    int bad = 0;
    for (size_t i = 0; i < sizeof(sentinels) / sizeof(sentinels[0]); i++) {
        char p[640];
        int n = snprintf(p, sizeof(p), "%s/%s", data_path, sentinels[i].name);
        if (n < 0 || (size_t)n >= sizeof(p)) {
            fprintf(stderr, "data path too long to check for %s\n",
                    sentinels[i].name);
            return -1;
        }
        struct stat st;
        if (stat(p, &st) != 0) continue;          /* absent — the normal case */

        fprintf(stderr,
                "REFUSING TO DERIVE — %s is present in %s.\n"
                "  What it means: %s.\n"
                "  Note it survived the wipe: the runbook removes "
                "witness_*, and a dot-file does not match that glob.\n"
                "  Fix: establish why the node died, then `rm %s` and "
                "re-run this command.\n",
                sentinels[i].name, data_path, sentinels[i].what, p);
        bad = 1;
    }
    return bad ? -1 : 0;
}

static int run_derive_v2_genesis(const char *cfg_path, const char *data_path) {
    /* BEFORE the config is even parsed: nothing has been done yet, so a
     * refusal here costs the operator nothing but a message. */
    if (derive_precheck_sentinels(data_path) != 0)
        return 1;

    nodus_v2_gen_config_t *cfg = NULL;
    if (nodus_v2_gen_config_parse_file(cfg_path, &cfg) != 0) {
        fprintf(stderr, "genesis config %s was REFUSED — nothing derived.\n",
                cfg_path);
        return 1;
    }

    fprintf(stderr,
            "deriving a cometbft (version 3) chain from %s into %s\n"
            "(offline one-shot: no socket is opened, no server is started)\n",
            cfg_path, data_path);

    /* R3 W3 (D-17 rev 10 (9)): the ceremony derives version 3 only. The
     * version-2 entry (nodus_witness_v2_gen_derive), closed by W3, is
     * DELETED from the tree by tokenomics-v3 P4 (OBLIGATION
     * atlas-dec-71525f3b), and the config parser refuses a version-2 or
     * version-less file before this point. out_chain32 is still passed
     * as NULL on purpose, and the printed value comes from the committed
     * database instead: nodus_witness_v2_gen_derive_v3 is idempotent and
     * returns 0 WITHOUT writing out_chain32 when a chain built from this
     * same config is already present, so printing from that buffer would
     * print whatever it held on exactly the re-run an operator is most
     * likely to perform — and a WRONG pin handed to six other nodes is
     * the failure this whole change exists to make impossible. The
     * database is the one source that is correct on both paths. */
    int derived_ok = (nodus_witness_v2_gen_derive_v3(data_path, cfg,
                                                     NULL) == 0);
    nodus_v2_gen_config_free(cfg);
    cfg = NULL;

    if (!derived_ok) {
        fprintf(stderr,
                "derivation REFUSED — the W_V2GEN lines above name the "
                "reason. The data directory is unchanged.\n");
        return 1;
    }

    char db_path[600];
    if (find_single_chain_db(data_path, db_path, sizeof(db_path)) != 0)
        return 1;

    /* R3 W3 (D-18 rev 4 / D-24 rev 4 (1)): the chain id IS the pin — a
     * version-3 chain has no 64-byte genesis BlockID to derive one from
     * (D-19 rev 6). One identity, read once. */
    uint8_t chain_id[NODUS_V2_GEN_CHAIN_ID_LEN];
    if (read_genesis_chain_id(db_path, chain_id) != 0) return 1;

    printf("chain-id       ");
    print_hex(chain_id, sizeof(chain_id));
    printf("\n");
    printf("v2-genesis-pin ");
    print_hex(chain_id, sizeof(chain_id));
    printf("\n");

    fprintf(stderr,
            "\nThe chain-id above MUST be identical on every node of the "
            "fleet — compare them before starting anything. Hand the\n"
            "v2-genesis-pin value to a joining node as\n"
            "  nodus-server --v2-genesis-pin <that 64-hex string> ...\n"
            "It is that node's LOCAL trust anchor: it adopts a peer's "
            "genesis bundle only if the bundle re-derives to it.\n");
    return 0;
}

static int parse_seed(const char *str, char *ip, size_t ip_len, uint16_t *port) {
    const char *colon = strrchr(str, ':');
    if (!colon) {
        snprintf(ip, ip_len, "%s", str);
        *port = NODUS_DEFAULT_UDP_PORT;
        return 0;
    }
    size_t host_len = (size_t)(colon - str);
    if (host_len >= ip_len) return -1;
    memcpy(ip, str, host_len);
    ip[host_len] = '\0';
    *port = (uint16_t)atoi(colon + 1);
    return 0;
}

#ifdef NODUS_HAS_JSONC
static int load_config_json(const char *path, nodus_server_config_t *cfg) {
    struct json_object *root = json_object_from_file(path);
    if (!root) {
        fprintf(stderr, "Failed to parse config: %s\n", path);
        return -1;
    }

    struct json_object *val;
    if (json_object_object_get_ex(root, "bind_ip", &val))
        snprintf(cfg->bind_ip, sizeof(cfg->bind_ip), "%s",
                 json_object_get_string(val));
    if (json_object_object_get_ex(root, "external_ip", &val))
        snprintf(cfg->external_ip, sizeof(cfg->external_ip), "%s",
                 json_object_get_string(val));
    if (json_object_object_get_ex(root, "udp_port", &val))
        cfg->udp_port = (uint16_t)json_object_get_int(val);
    if (json_object_object_get_ex(root, "tcp_port", &val))
        cfg->tcp_port = (uint16_t)json_object_get_int(val);
    if (json_object_object_get_ex(root, "peer_port", &val))
        cfg->peer_port = (uint16_t)json_object_get_int(val);
    if (json_object_object_get_ex(root, "ch_port", &val))
        cfg->ch_port = (uint16_t)json_object_get_int(val);
    if (json_object_object_get_ex(root, "witness_port", &val))
        cfg->witness_port = (uint16_t)json_object_get_int(val);
    if (json_object_object_get_ex(root, "identity_path", &val))
        snprintf(cfg->identity_path, sizeof(cfg->identity_path), "%s",
                 json_object_get_string(val));
    if (json_object_object_get_ex(root, "data_path", &val))
        snprintf(cfg->data_path, sizeof(cfg->data_path), "%s",
                 json_object_get_string(val));

    /* R3 W4 — the "halt_auto_recover" witness-config key is DELETED with
     * the closed consensus lane: nodus_witness_config_t's halt_auto_recover
     * field is replaced by a reserved byte (nodus_witness.h), and its only
     * reader, the legacy safety_halt recovery check, is deleted. */

    if (json_object_object_get_ex(root, "seed_nodes", &val) &&
        json_object_is_type(val, json_type_array)) {
        int n = json_object_array_length(val);
        for (int i = 0; i < n && cfg->seed_count < NODUS_MAX_SEED_NODES; i++) {
            struct json_object *entry = json_object_array_get_idx(val, i);
            const char *s = json_object_get_string(entry);
            if (s) {
                parse_seed(s, cfg->seed_nodes[cfg->seed_count],
                           sizeof(cfg->seed_nodes[0]),
                           &cfg->seed_ports[cfg->seed_count]);
                cfg->seed_count++;
            }
        }
    }

    /* C-01/C-02: Optional peer authentication enforcement */
    if (json_object_object_get_ex(root, "require_peer_auth", &val))
        cfg->require_peer_auth = json_object_get_boolean(val);

    /* R3 W4 — the "cold_bootstrap" config key is DELETED with the closed
     * consensus lane: is_cold_bootstrap's one reader
     * (nodus_witness_bootstrap.c) is deleted (see nodus_server.h's own
     * deletion note at the field). */

    json_object_put(root);
    return 0;
}
#endif

int main(int argc, char **argv) {
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));

    /* Defaults */
    snprintf(config.bind_ip, sizeof(config.bind_ip), "0.0.0.0");
    config.udp_port = NODUS_DEFAULT_UDP_PORT;
    config.tcp_port = NODUS_DEFAULT_TCP_PORT;
    config.peer_port = NODUS_DEFAULT_PEER_PORT;
    config.ch_port = NODUS_DEFAULT_CH_PORT;
    config.witness_port = NODUS_DEFAULT_WITNESS_PORT;
    snprintf(config.data_path, sizeof(config.data_path), "/var/lib/nodus");

    const char *config_file = NULL;
    /* O16A / D1 — held as a LOCAL, exactly like config_file, and for the
     * same reason: `config = file_cfg` below overwrites the whole config
     * struct, so anything recorded in it during the first parse pass is
     * lost when -c is also given. */
    const char *derive_v2_genesis_cfg = NULL;
    int opt;

    while ((opt = getopt_long(argc, argv, "c:b:u:t:p:C:W:i:d:s:h",
                              g_longopts, NULL)) != -1) {
        switch (opt) {
        case 'c': config_file = optarg; break;
        case 'b': snprintf(config.bind_ip, sizeof(config.bind_ip), "%s", optarg); break;
        case 'u': config.udp_port = (uint16_t)atoi(optarg); break;
        case 't': config.tcp_port = (uint16_t)atoi(optarg); break;
        case 'p': config.peer_port = (uint16_t)atoi(optarg); break;
        case 'C': config.ch_port = (uint16_t)atoi(optarg); break;
        case 'W': config.witness_port = (uint16_t)atoi(optarg); break;
        case 'i': snprintf(config.identity_path, sizeof(config.identity_path), "%s", optarg); break;
        case 'd': snprintf(config.data_path, sizeof(config.data_path), "%s", optarg); break;
        case 's':
            if (config.seed_count < NODUS_MAX_SEED_NODES) {
                parse_seed(optarg,
                           config.seed_nodes[config.seed_count],
                           sizeof(config.seed_nodes[0]),
                           &config.seed_ports[config.seed_count]);
                config.seed_count++;
            }
            break;
        case LONGOPT_V2_GENESIS_PIN:
            if (parse_v2_pin(optarg, config.v2_genesis_pin) != 0) {
                fprintf(stderr, "invalid --v2-genesis-pin (need 64 hex "
                        "chars = the 32-byte successor chain id)\n");
                return 1;
            }
            config.has_v2_genesis_pin = true;
            fprintf(stderr, "O15E: pinned-genesis joiner armed "
                    "(local trust anchor set)\n");
            break;
        case LONGOPT_DERIVE_V2_GENESIS:
            derive_v2_genesis_cfg = optarg;
            break;
        case LONGOPT_MOCK_NODUS_VER: {
            uint32_t mock = (uint32_t)strtoul(optarg, NULL, 0);
            nodus_witness_peer_set_mock_version(mock);
            fprintf(stderr,
                "[dev] mock nodus_version active: 0x%06x — w_ident "
                "advertises this packed value instead of compiled "
                "version. Used by F4 mixed-version harness only.\n",
                (unsigned)mock);
            break;
        }
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    /* Load JSON config if specified (CLI args override) */
    if (config_file) {
#ifdef NODUS_HAS_JSONC
        nodus_server_config_t file_cfg;
        memset(&file_cfg, 0, sizeof(file_cfg));
        snprintf(file_cfg.bind_ip, sizeof(file_cfg.bind_ip), "0.0.0.0");
        file_cfg.udp_port = NODUS_DEFAULT_UDP_PORT;
        file_cfg.tcp_port = NODUS_DEFAULT_TCP_PORT;
        file_cfg.peer_port = NODUS_DEFAULT_PEER_PORT;
        file_cfg.ch_port = NODUS_DEFAULT_CH_PORT;
        file_cfg.witness_port = NODUS_DEFAULT_WITNESS_PORT;
        snprintf(file_cfg.data_path, sizeof(file_cfg.data_path), "/var/lib/nodus");

        if (load_config_json(config_file, &file_cfg) != 0)
            return 1;

        /* CLI args take precedence: only copy file values where CLI was default */
        /* For simplicity, just use file config as base and re-apply CLI overrides */
        config = file_cfg;

        /* Re-parse CLI args to override file config */
        optind = 1;
        while ((opt = getopt_long(argc, argv, "c:b:u:t:p:C:W:i:d:s:h",
                                  g_longopts, NULL)) != -1) {
            switch (opt) {
            case 'b': snprintf(config.bind_ip, sizeof(config.bind_ip), "%s", optarg); break;
            case 'u': config.udp_port = (uint16_t)atoi(optarg); break;
            case 't': config.tcp_port = (uint16_t)atoi(optarg); break;
            case 'p': config.peer_port = (uint16_t)atoi(optarg); break;
            case 'C': config.ch_port = (uint16_t)atoi(optarg); break;
            case 'W': config.witness_port = (uint16_t)atoi(optarg); break;
            case 'i': snprintf(config.identity_path, sizeof(config.identity_path), "%s", optarg); break;
            case 'd': snprintf(config.data_path, sizeof(config.data_path), "%s", optarg); break;
            case 's':
                if (config.seed_count < NODUS_MAX_SEED_NODES) {
                    parse_seed(optarg,
                               config.seed_nodes[config.seed_count],
                               sizeof(config.seed_nodes[0]),
                               &config.seed_ports[config.seed_count]);
                    config.seed_count++;
                }
                break;
            case LONGOPT_MOCK_NODUS_VER: {
                uint32_t mock = (uint32_t)strtoul(optarg, NULL, 0);
                nodus_witness_peer_set_mock_version(mock);
                break;
            }
            case LONGOPT_V2_GENESIS_PIN:
                /* O15E Faz D — the re-parse pass (after `config = file_cfg`
                 * clobbers the first pass) MUST re-apply the pin, or a node
                 * started with BOTH -c <json> and --v2-genesis-pin loses it
                 * and never arms the joiner. */
                if (parse_v2_pin(optarg, config.v2_genesis_pin) != 0) {
                    fprintf(stderr, "invalid --v2-genesis-pin\n");
                    return 1;
                }
                config.has_v2_genesis_pin = true;
                break;
            case LONGOPT_DERIVE_V2_GENESIS:
                /* Re-applied for symmetry with the pin above. It is held
                 * in a local rather than in `config`, so the clobber
                 * cannot lose it — but leaving the case out would mean
                 * the two flags were handled differently in the two
                 * passes, which is the shape the pin's own bug had. */
                derive_v2_genesis_cfg = optarg;
                break;
            default: break;
            }
        }
#else
        fprintf(stderr, "JSON config not supported (built without json-c)\n");
        return 1;
#endif
    }

    /* ── O16A / D1 — the derivation one-shot, and the LAST thing this
     * process does ───────────────────────────────────────────────────
     * Placed after BOTH option-parsing passes (so config.data_path and
     * config.has_v2_genesis_pin are final) and before the signal
     * handlers, the server memset and nodus_server_init. Nothing below
     * this block runs on this path: no socket, no thread, no server
     * struct. That is the property D1 rests on, and it is expressed as
     * an early return rather than as a flag some later branch consults,
     * because a flag is something a future edit can forget to check. */
    if (derive_v2_genesis_cfg) {
        if (config.has_v2_genesis_pin) {
            /* Deriving CREATES the first chain; pinning JOINS one that
             * already exists. They are opposite intents and the operator
             * has stated both, so this is not a case where one can be
             * silently preferred: whichever we picked, the node would end
             * up on a chain the operator did not ask for, and doing it
             * quietly is the hardest version of that mistake to see. */
            fprintf(stderr,
                    "--derive-v2-genesis and --v2-genesis-pin are mutually "
                    "exclusive: the first CREATES a chain, the second JOINS "
                    "one that already exists. Give exactly one.\n");
            return 1;
        }
        return run_derive_v2_genesis(derive_v2_genesis_cfg,
                                     config.data_path);
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    memset(&server, 0, sizeof(server));

    if (nodus_server_init(&server, &config) != 0) {
        fprintf(stderr, "Server init failed\n");
        nodus_server_close(&server);
        return 1;
    }

    int rc = nodus_server_run(&server);
    nodus_server_close(&server);
    return rc;
}
