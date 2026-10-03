/**
 * Nodus — node command line + config file (shared by nodus-server,
 * nodus-witness and nodus-storage)
 *
 * Component split S3 (decision docs/plans/decisions/2026-10-01-nodus-
 * component-split.md item 18: one config file, each service reads its own
 * keys): the option set and the JSON config keys that nodus-server's
 * main() always had, moved here unchanged so the nodus-witness binary
 * takes the SAME command line and the SAME config file. Each binary uses
 * the fields it needs.
 *
 * Split S5b: the witness-side parts — the 4004 p2p section, the network
 * file, the --derive-v2-genesis one-shot — live in
 * nodus_node_config_witness.c and reach this parse through
 * nodus_node_config_witness_t, so nodus-storage (nodus_node_config_load_
 * storage) links no witness object (tests/storage_linked.cmake).
 *
 * Usage:
 *   nodus-server / nodus-witness / nodus-storage
 *                [-c <config.json>] [-b <bind_ip>] [-u <udp_port>]
 *                [-t <tcp_port>] [-i <identity_dir>] [-d <data_dir>]
 *                [-s <seed_ip:port>] [-h]
 */

#include "nodus_node_config.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#ifdef NODUS_HAS_JSONC
#include <json-c/json.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#include "crypto/utils/qgp_log.h"

#define LOG_TAG_CFG "NODUS_CFG"
#endif

static void usage(const char *prog, const char *title) {
    fprintf(stderr, "%s v%s\n", title, NODUS_VERSION_STRING);
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
    fprintf(stderr, "  -s [id@]<ip:port> Add seed node (repeatable). With id@ (the\n");
    fprintf(stderr, "                    node's 64-hex p2p ID) the node is also a\n");
    fprintf(stderr, "                    witness-port persistent peer at port + 4.\n");
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
    fprintf(stderr, "  --network-file <path>\n");
    fprintf(stderr, "                    The published network file (JSON:\n");
    fprintf(stderr, "                    \"v2_genesis_pin\", \"persistent_peers\";\n");
    fprintf(stderr, "                    nodus.json key \"network_file\"). A pin\n");
    fprintf(stderr, "                    joins when there is no chain and must\n");
    fprintf(stderr, "                    equal the chain's id when there is one\n");
    fprintf(stderr, "                    (else the node does not start); peers\n");
    fprintf(stderr, "                    join the witness-port persistent peers.\n");
    fprintf(stderr, "                    With --derive-v2-genesis the derived\n");
    fprintf(stderr, "                    chain id is written into an EMPTY pin.\n");
    fprintf(stderr, "  --witness-external\n");
    fprintf(stderr, "                    nodus-server: the witness runs as\n");
    fprintf(stderr, "                    the separate nodus-witness process,\n");
    fprintf(stderr, "                    reached over <data_dir>/witness.sock\n");
    fprintf(stderr, "                    (nodus.json key \"witness_external\").\n");
    fprintf(stderr, "                    nodus-witness REQUIRES it (flag or\n");
    fprintf(stderr, "                    key) and refuses to start without it.\n");
    fprintf(stderr, "  --storage-external\n");
    fprintf(stderr, "                    nodus-server: the DHT runs as the\n");
    fprintf(stderr, "                    separate nodus-storage process,\n");
    fprintf(stderr, "                    reached over <data_dir>/storage.sock\n");
    fprintf(stderr, "                    (nodus.json key \"storage_external\").\n");
    fprintf(stderr, "                    nodus-storage REQUIRES it (flag or\n");
    fprintf(stderr, "                    key) and refuses to start without it.\n");
    fprintf(stderr, "  -h                Show this help\n");
}

/* PR 3 / E1 — long-option IDs for getopt_long. Numeric > 255 to avoid
 * collision with single-char short options.
 * R3 W4 — LONGOPT_COLD_BOOTSTRAP (and the "cold-bootstrap" option it
 * named) is DELETED with the closed consensus lane: its one reader,
 * nodus_witness_bootstrap.c, is deleted. */
/* P2P-PORT F5 — LONGOPT_MOCK_NODUS_VER ("--mock-nodus-version", 1001) is
 * DELETED: its only consumer was the w_ident packed-version field, deleted
 * with IDENT. 1001 is not reused. */
#define LONGOPT_V2_GENESIS_PIN    1002
#define LONGOPT_DERIVE_V2_GENESIS 1003
#define LONGOPT_NETWORK_FILE      1004   /* P2P-PORT F6 */
#define LONGOPT_WITNESS_EXTERNAL  1005   /* component split S3 */
#define LONGOPT_STORAGE_EXTERNAL  1006   /* component split S5b */

static const struct option g_longopts[] = {
    {"v2-genesis-pin",     required_argument, NULL, LONGOPT_V2_GENESIS_PIN},
    {"derive-v2-genesis",  required_argument, NULL, LONGOPT_DERIVE_V2_GENESIS},
    {"network-file",       required_argument, NULL, LONGOPT_NETWORK_FILE},
    {"witness-external",   no_argument,       NULL, LONGOPT_WITNESS_EXTERNAL},
    {"storage-external",   no_argument,       NULL, LONGOPT_STORAGE_EXTERNAL},
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

/* The O16A / D1 offline genesis derivation one-shot (run_derive_v2_genesis
 * and its helpers) lives in nodus_node_config_witness.c since split S5b —
 * reached through nodus_node_config_witness_t.derive. */

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

/* P2P-PORT F5 — one seed entry (`-s` / "seed_nodes"): "ip:udp_port" seeds
 * the DHT cluster, as before; "id@ip:udp_port" ALSO makes that node a
 * witness-port persistent peer "id@ip:(udp_port + 4)" — the same "+4"
 * witness-port derivation the deleted seed dial used
 * (nodus_witness_peer.c before F5). An entry without an ID cannot be a
 * persistent peer: the 4004 p2p layer never dials unpinned (R-P2P-33).
 * Split S5b: the persistent-peer half only with the witness-side parts
 * (`w`); without them (nodus-storage) an "id@" entry adds its DHT seed.
 * @return 0; -1 malformed / full. */
static int add_seed_entry(nodus_server_config_t *cfg, const char *s,
                          const nodus_node_config_witness_t *w) {
    const char *at = strchr(s, '@');
    const char *hostport = at ? at + 1 : s;

    if (cfg->seed_count >= NODUS_MAX_SEED_NODES) return -1;
    if (parse_seed(hostport, cfg->seed_nodes[cfg->seed_count],
                   sizeof(cfg->seed_nodes[0]),
                   &cfg->seed_ports[cfg->seed_count]) != 0)
        return -1;
    if (at && w) {
        char pp[CMT_P2P_NETADDR_STR_MAX];
        const char *ip = cfg->seed_nodes[cfg->seed_count];
        bool v6 = strchr(ip, ':') != NULL && ip[0] != '[';
        int n = snprintf(pp, sizeof(pp), "%.*s@%s%s%s:%u", (int)(at - s), s,
                         v6 ? "[" : "", ip, v6 ? "]" : "",
                         (unsigned)(cfg->seed_ports[cfg->seed_count] + 4));

        if (n < 0 || (size_t)n >= sizeof(pp) ||
            w->p2p_add_persistent(&cfg->p2p, pp) != 0) {
            fprintf(stderr, "seed %s: witness persistent peer list full or "
                    "entry too long\n", s);
            return -1;
        }
    }
    cfg->seed_count++;
    return 0;
}

#ifdef NODUS_HAS_JSONC
/* A config.go list key: a JSON array of strings, or one comma-separated
 * string (the reference's TOML form). */
static void load_list(struct json_object *val, nodus_p2p_config_t *c,
                      int (*add)(nodus_p2p_config_t *, const char *),
                      const char *key) {
    if (json_object_is_type(val, json_type_array)) {
        int n = json_object_array_length(val);
        for (int i = 0; i < n; i++) {
            const char *s = json_object_get_string(json_object_array_get_idx(val, i));
            if (s && s[0] && add(c, s) != 0)
                fprintf(stderr, "config %s: entry \"%s\" dropped (list full "
                        "or too long)\n", key, s);
        }
    } else if (json_object_is_type(val, json_type_string)) {
        char buf[NODUS_P2P_MAX_PEER_LIST * CMT_P2P_NETADDR_STR_MAX];
        char *save = NULL;
        snprintf(buf, sizeof(buf), "%s", json_object_get_string(val));
        for (char *tok = strtok_r(buf, ", ", &save); tok;
             tok = strtok_r(NULL, ", ", &save)) {
            if (add(c, tok) != 0)
                fprintf(stderr, "config %s: entry \"%s\" dropped (list full "
                        "or too long)\n", key, tok);
        }
    }
}

/* P2P-PORT F5 — the witness port's P2P section: reference config.go
 * P2P key names (p2p-port design §4), top-level nodus.json keys. The list
 * adders are the witness-side parts' (`w`, never NULL here). */
static void load_p2p_json(struct json_object *root, nodus_p2p_config_t *c,
                          const nodus_node_config_witness_t *w) {
    struct json_object *val;

    if (json_object_object_get_ex(root, "persistent_peers", &val))
        load_list(val, c, w->p2p_add_persistent, "persistent_peers");
    if (json_object_object_get_ex(root, "unconditional_peer_ids", &val))
        load_list(val, c, w->p2p_add_unconditional,
                  "unconditional_peer_ids");
    if (json_object_object_get_ex(root, "private_peer_ids", &val))
        load_list(val, c, w->p2p_add_private, "private_peer_ids");
    if (json_object_object_get_ex(root, "pex", &val))
        c->pex = json_object_get_boolean(val);
    if (json_object_object_get_ex(root, "addr_book_strict", &val))
        c->addr_book_strict = json_object_get_boolean(val);
    if (json_object_object_get_ex(root, "allow_duplicate_ip", &val))
        c->allow_duplicate_ip = json_object_get_boolean(val);
    if (json_object_object_get_ex(root, "max_num_inbound_peers", &val))
        c->max_num_inbound_peers = json_object_get_int(val);
    if (json_object_object_get_ex(root, "max_num_outbound_peers", &val))
        c->max_num_outbound_peers = json_object_get_int(val);
    if (json_object_object_get_ex(root, "flush_throttle_timeout", &val))
        c->flush_throttle_timeout_ms = json_object_get_int64(val);
    if (json_object_object_get_ex(root, "max_packet_msg_payload_size", &val))
        c->max_packet_msg_payload_size = json_object_get_int(val);
    if (json_object_object_get_ex(root, "send_rate", &val))
        c->send_rate = json_object_get_int64(val);
    if (json_object_object_get_ex(root, "recv_rate", &val))
        c->recv_rate = json_object_get_int64(val);
    if (json_object_object_get_ex(root, "handshake_timeout", &val))
        c->handshake_timeout_ms = json_object_get_int64(val);
    if (json_object_object_get_ex(root, "dial_timeout", &val))
        c->dial_timeout_ms = json_object_get_int64(val);
    if (json_object_object_get_ex(root, "moniker", &val))
        snprintf(c->moniker, sizeof(c->moniker), "%s", json_object_get_string(val));
}

static int load_config_json(const char *path, nodus_server_config_t *cfg,
                            const nodus_node_config_witness_t *w) {
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

    /* WebSocket entry (nodus_server.h ws_port / ws_origins). Off unless
     * ws_port is set; the listen address is always 127.0.0.1 and has no
     * key. A malformed value refuses the start rather than silently
     * opening (or not opening) a network entry the operator did not ask
     * for. */
    if (json_object_object_get_ex(root, "ws_port", &val)) {
        int p = json_object_get_int(val);
        if (!json_object_is_type(val, json_type_int) || p < 0 || p > 65535) {
            QGP_LOG_ERROR(LOG_TAG_CFG, "ws_port must be an integer 0..65535");
            json_object_put(root);
            return -1;
        }
        cfg->ws_port = (uint16_t)p;
    }
    if (json_object_object_get_ex(root, "ws_origins", &val)) {
        if (!json_object_is_type(val, json_type_array)) {
            QGP_LOG_ERROR(LOG_TAG_CFG, "ws_origins must be an array of strings");
            json_object_put(root);
            return -1;
        }
        memset(&cfg->ws_origins, 0, sizeof(cfg->ws_origins));
        int n = json_object_array_length(val);
        for (int i = 0; i < n; i++) {
            struct json_object *entry = json_object_array_get_idx(val, i);
            const char *s = json_object_is_type(entry, json_type_string)
                          ? json_object_get_string(entry) : NULL;
            if (!s || nodus_ws_origins_add(&cfg->ws_origins, s) != 0) {
                QGP_LOG_ERROR(LOG_TAG_CFG, "ws_origins[%d] rejected (not a string, empty, "
                              "contains spaces/control characters, over %d bytes, "
                              "or more than %d entries)",
                              i, NODUS_WS_ORIGIN_MAX - 1, NODUS_WS_MAX_ORIGINS);
                json_object_put(root);
                return -1;
            }
        }
    }

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

    /* P2P-PORT F5: the witness-port list keys first, so an "id@" seed
     * below appends to a persistent_peers list that is already loaded.
     * Split S5b: only with the witness-side parts (not nodus-storage). */
    if (w)
        load_p2p_json(root, &cfg->p2p, w);

    if (json_object_object_get_ex(root, "seed_nodes", &val) &&
        json_object_is_type(val, json_type_array)) {
        int n = json_object_array_length(val);
        for (int i = 0; i < n && cfg->seed_count < NODUS_MAX_SEED_NODES; i++) {
            struct json_object *entry = json_object_array_get_idx(val, i);
            const char *s = json_object_get_string(entry);
            if (s)
                (void)add_seed_entry(cfg, s, w);
        }
    }

    /* C-01: Optional peer authentication enforcement (port 4002 only
     * since P2P-PORT F5 — nodus_server.h). */
    if (json_object_object_get_ex(root, "require_peer_auth", &val))
        cfg->require_peer_auth = json_object_get_boolean(val);

    /* Node-local address history index (nodus_server.h
     * addr_history_index; decision 2026-10-01-node-address-history-
     * index.md). Default OFF; a non-boolean value refuses the start
     * rather than silently guessing what the operator meant. */
    if (json_object_object_get_ex(root, "addr_history_index", &val)) {
        if (!json_object_is_type(val, json_type_boolean)) {
            QGP_LOG_ERROR(LOG_TAG_CFG, "addr_history_index must be true or "
                          "false");
            json_object_put(root);
            return -1;
        }
        cfg->addr_history_index = json_object_get_boolean(val) ? true
                                                               : false;
    }

    /* Node-local block retention (nodus_witness.h nodus_witness_config_t
     * retain_blocks; decision 2026-10-03-block-pruning-7-paydays.md).
     * Default 0 = archive. A non-integer or negative value refuses the
     * start; the floor against the chain's evidence window is checked
     * where the chain's consensus params are loaded
     * (nodus_cmt_node_init, nodus_cmt_node_check_retain_blocks). */
    if (json_object_object_get_ex(root, "retain_blocks", &val)) {
        int64_t rb = json_object_get_int64(val);
        if (!json_object_is_type(val, json_type_int) || rb < 0) {
            QGP_LOG_ERROR(LOG_TAG_CFG, "retain_blocks must be an integer "
                          ">= 0 (0 = keep every block)");
            json_object_put(root);
            return -1;
        }
        cfg->witness.retain_blocks = rb;
    }

    /* Component split S3 (nodus_server.h witness_external). Default
     * false = the in-process witness; a non-boolean value refuses the
     * start, like addr_history_index. nodus-witness requires it to be
     * true and refuses to start otherwise (tools/nodus-witness.c). */
    if (json_object_object_get_ex(root, "witness_external", &val)) {
        if (!json_object_is_type(val, json_type_boolean)) {
            QGP_LOG_ERROR(LOG_TAG_CFG, "witness_external must be true or "
                          "false");
            json_object_put(root);
            return -1;
        }
        cfg->witness_external = json_object_get_boolean(val) ? true
                                                             : false;
    }

    /* Component split S5b (nodus_server.h storage_external). Default
     * false = the in-process DHT; a non-boolean value refuses the start,
     * like witness_external. nodus-storage requires it to be true and
     * refuses to start otherwise (tools/nodus-storage.c). */
    if (json_object_object_get_ex(root, "storage_external", &val)) {
        if (!json_object_is_type(val, json_type_boolean)) {
            QGP_LOG_ERROR(LOG_TAG_CFG, "storage_external must be true or "
                          "false");
            json_object_put(root);
            return -1;
        }
        cfg->storage_external = json_object_get_boolean(val) ? true
                                                             : false;
    }

    /* P2P-PORT F6 — the published network file's path (loaded in main,
     * after both option passes; `--network-file` overrides it). */
    if (json_object_object_get_ex(root, "network_file", &val))
        snprintf(cfg->network_file, sizeof(cfg->network_file), "%s",
                 json_object_get_string(val));

    /* R3 W4 — the "cold_bootstrap" config key is DELETED with the closed
     * consensus lane: is_cold_bootstrap's one reader
     * (nodus_witness_bootstrap.c) is deleted (see nodus_server.h's own
     * deletion note at the field). */

    json_object_put(root);
    return 0;
}
#endif

int nodus_node_config_parse(int argc, char **argv, const char *title,
                            const nodus_node_config_witness_t *w,
                            nodus_server_config_t *out) {
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
    if (w)
        w->p2p_default(&config.p2p);
    /* DHT Package A (rev 2 item 10): 4002 peer auth is ON unless the JSON
     * config sets "require_peer_auth": false explicitly. */
    config.require_peer_auth = true;

    const char *config_file = NULL;
    /* O16A / D1 — held as a LOCAL, exactly like config_file, and for the
     * same reason: `config = file_cfg` below overwrites the whole config
     * struct, so anything recorded in it during the first parse pass is
     * lost when -c is also given. */
    const char *derive_v2_genesis_cfg = NULL;
    /* P2P-PORT F6 — `--network-file`, a local for the same reason. */
    const char *network_file_opt = NULL;
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
            (void)add_seed_entry(&config, optarg, w);
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
        case LONGOPT_NETWORK_FILE:
            network_file_opt = optarg;
            break;
        case LONGOPT_WITNESS_EXTERNAL:
            config.witness_external = true;
            break;
        case LONGOPT_STORAGE_EXTERNAL:
            config.storage_external = true;
            break;
        case 'h':
        default:
            usage(argv[0], title);
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
        if (w)
            w->p2p_default(&file_cfg.p2p);
        file_cfg.require_peer_auth = true;   /* default; the JSON may set false */

        if (load_config_json(config_file, &file_cfg, w) != 0)
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
                (void)add_seed_entry(&config, optarg, w);
                break;
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
            case LONGOPT_NETWORK_FILE:
                network_file_opt = optarg;
                break;
            case LONGOPT_WITNESS_EXTERNAL:
                /* Re-applied after the clobber, like the pin above. */
                config.witness_external = true;
                break;
            case LONGOPT_STORAGE_EXTERNAL:
                /* Re-applied after the clobber, like witness_external. */
                config.storage_external = true;
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
    /* P2P-PORT F6 — the effective network file: `--network-file` over the
     * nodus.json "network_file" key. Final only here, after both passes. */
    if (network_file_opt)
        snprintf(config.network_file, sizeof(config.network_file), "%s",
                 network_file_opt);
    const char *network_file = config.network_file[0]
                             ? config.network_file : NULL;

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
        /* Split S5b: the one-shot is a witness-side part — nodus-storage
         * does not carry it. */
        if (!w) {
            fprintf(stderr, "--derive-v2-genesis is not served by %s — run "
                    "it with nodus-server or nodus-witness\n", title);
            return 1;
        }
        /* A network file's pin is NOT refused here, unlike the CLI pin
         * above: the ceremony is the one writer of that pin, and a node
         * deriving after another has already written it must find its
         * own id equal (nothing written) or different (stop) —
         * run_derive_v2_genesis. */
        return w->derive(derive_v2_genesis_cfg, config.data_path,
                         network_file);
    }

    /* P2P-PORT F6 — a running node READS the network file, never writes
     * it (nodus_node_config_witness.c network_file_apply). Split S5b:
     * nodus-storage reads none of what it carries (the pin, the 4004
     * peers) and does not load it. */
    if (network_file && w) {
        if (w->network_file_apply(network_file, &config) != 0)
            return 1;
    }

    *out = config;
    return -1;
}

int nodus_node_config_load_storage(int argc, char **argv, const char *title,
                                   nodus_server_config_t *out) {
    return nodus_node_config_parse(argc, argv, title, NULL, out);
}
