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
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#ifdef NODUS_HAS_JSONC
#include <json-c/json.h>
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
    fprintf(stderr, "  -i <identity_dir> Identity directory\n");
    fprintf(stderr, "  -d <data_dir>     Data directory (default: /var/lib/nodus)\n");
    fprintf(stderr, "  -s <ip:port>      Add seed node (repeatable)\n");
    fprintf(stderr, "  -h                Show this help\n");
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
    if (json_object_object_get_ex(root, "identity_path", &val))
        snprintf(cfg->identity_path, sizeof(cfg->identity_path), "%s",
                 json_object_get_string(val));
    if (json_object_object_get_ex(root, "data_path", &val))
        snprintf(cfg->data_path, sizeof(cfg->data_path), "%s",
                 json_object_get_string(val));

    /* Witness module — all nodes are automatic witnesses (no config needed) */

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
    snprintf(config.data_path, sizeof(config.data_path), "/var/lib/nodus");

    const char *config_file = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "c:b:u:t:p:C:i:d:s:h")) != -1) {
        switch (opt) {
        case 'c': config_file = optarg; break;
        case 'b': snprintf(config.bind_ip, sizeof(config.bind_ip), "%s", optarg); break;
        case 'u': config.udp_port = (uint16_t)atoi(optarg); break;
        case 't': config.tcp_port = (uint16_t)atoi(optarg); break;
        case 'p': config.peer_port = (uint16_t)atoi(optarg); break;
        case 'C': config.ch_port = (uint16_t)atoi(optarg); break;
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
        snprintf(file_cfg.data_path, sizeof(file_cfg.data_path), "/var/lib/nodus");

        if (load_config_json(config_file, &file_cfg) != 0)
            return 1;

        /* CLI args take precedence: only copy file values where CLI was default */
        /* For simplicity, just use file config as base and re-apply CLI overrides */
        config = file_cfg;

        /* Re-parse CLI args to override file config */
        optind = 1;
        while ((opt = getopt(argc, argv, "c:b:u:t:p:C:i:d:s:h")) != -1) {
            switch (opt) {
            case 'b': snprintf(config.bind_ip, sizeof(config.bind_ip), "%s", optarg); break;
            case 'u': config.udp_port = (uint16_t)atoi(optarg); break;
            case 't': config.tcp_port = (uint16_t)atoi(optarg); break;
            case 'p': config.peer_port = (uint16_t)atoi(optarg); break;
            case 'C': config.ch_port = (uint16_t)atoi(optarg); break;
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
            default: break;
            }
        }
#else
        fprintf(stderr, "JSON config not supported (built without json-c)\n");
        return 1;
#endif
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
