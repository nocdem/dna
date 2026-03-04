/**
 * Nodus v5 — CLI Tool
 *
 * Connect to a Nodus server, authenticate, perform DHT operations.
 *
 * Usage:
 *   nodus-cli -s <server_ip> [-p <port>] [-i <identity_dir>] <command> [args...]
 *
 * Commands:
 *   ping                       Ping the server
 *   put <key> <value>          Store a DHT value
 *   get <key>                  Retrieve a DHT value
 *   listen <key>               Subscribe to key changes
 *   whoami                     Show identity info
 */

#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* ── Globals ─────────────────────────────────────────────────────── */

static nodus_identity_t identity;
static nodus_tcp_t transport;
static nodus_tcp_conn_t *server_conn = NULL;
static uint8_t session_token[NODUS_SESSION_TOKEN_LEN];
static bool authenticated = false;
static uint32_t next_txn = 1;
static volatile bool running = true;

/* Response state */
static nodus_tier2_msg_t last_response;
static bool response_ready = false;

/* Protocol message buffer */
static uint8_t proto_buf[32768];

/* ── Callbacks ───────────────────────────────────────────────────── */

static void on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                      size_t len, void *ctx) {
    (void)conn; (void)ctx;
    nodus_t2_msg_free(&last_response);
    memset(&last_response, 0, sizeof(last_response));
    if (nodus_t2_decode(payload, len, &last_response) == 0)
        response_ready = true;
}

static void on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    fprintf(stderr, "Disconnected from server\n");
    server_conn = NULL;
    running = false;
}

static void on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
}

/* ── Helpers ─────────────────────────────────────────────────────── */

static void sighandler(int sig) {
    (void)sig;
    running = false;
}

static bool wait_response(int timeout_ms) {
    response_ready = false;
    int elapsed = 0;
    while (!response_ready && elapsed < timeout_ms && running) {
        nodus_tcp_poll(&transport, 50);
        elapsed += 50;
    }
    return response_ready;
}

static int do_auth(void) {
    /* Step 1: HELLO */
    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_hello(txn, &identity.pk, &identity.node_id,
                    proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to HELLO\n");
        return -1;
    }

    if (strcmp(last_response.method, "challenge") != 0) {
        fprintf(stderr, "Expected challenge, got: %s\n", last_response.method);
        return -1;
    }

    /* Step 2: Sign nonce and send AUTH */
    nodus_sig_t sig;
    nodus_sign(&sig, last_response.nonce, NODUS_NONCE_LEN, &identity.sk);

    txn = next_txn++;
    nodus_t2_auth(txn, &sig, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to AUTH\n");
        return -1;
    }

    if (strcmp(last_response.method, "auth_ok") != 0) {
        if (last_response.type == 'e')
            fprintf(stderr, "Auth failed: %s\n", last_response.error_msg);
        else
            fprintf(stderr, "Expected auth_ok, got: %s\n", last_response.method);
        return -1;
    }

    memcpy(session_token, last_response.token, NODUS_SESSION_TOKEN_LEN);
    authenticated = true;
    return 0;
}

/* ── Commands ────────────────────────────────────────────────────── */

static int cmd_ping(void) {
    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_ping(txn, session_token, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No pong\n");
        return 1;
    }
    printf("pong (txn=%u)\n", last_response.txn_id);
    return 0;
}

static int cmd_put(const char *key_str, const char *value_str) {
    /* Hash the key */
    nodus_key_t key;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key);

    /* Build sign payload: key + data + type + ttl + vid + seq */
    const uint8_t *data = (const uint8_t *)value_str;
    size_t data_len = strlen(value_str);

    /* Sign the value */
    nodus_value_t *val = NULL;
    nodus_value_create(&key, data, data_len,
                        NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                        1, 0, &identity.pk, &val);
    nodus_value_sign(val, &identity.sk);

    /* Send PUT */
    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_put(txn, session_token, &key, data, data_len,
                  NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                  1, 0, &val->signature,
                  proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);
    nodus_value_free(val);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to PUT\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "PUT error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    printf("PUT ok (key=%s)\n", key_str);
    return 0;
}

static int cmd_get(const char *key_str) {
    nodus_key_t key;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key);

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_get(txn, session_token, &key, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to GET\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "GET error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    if (last_response.value) {
        printf("Value: %.*s\n", (int)last_response.value->data_len,
               (char *)last_response.value->data);
        printf("  seq=%lu vid=%lu type=%d\n",
               (unsigned long)last_response.value->seq,
               (unsigned long)last_response.value->value_id,
               last_response.value->type);
    } else {
        printf("(empty result)\n");
    }
    return 0;
}

static int cmd_listen(const char *key_str) {
    nodus_key_t key;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key);

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_listen(txn, session_token, &key,
                     proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to LISTEN\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "LISTEN error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    printf("Listening on key '%s'. Press Ctrl+C to stop.\n", key_str);

    /* Wait for notifications */
    while (running) {
        response_ready = false;
        nodus_tcp_poll(&transport, 1000);

        if (response_ready) {
            if (strcmp(last_response.method, "value_changed") == 0 &&
                last_response.value) {
                printf("[notify] %.*s\n",
                       (int)last_response.value->data_len,
                       (char *)last_response.value->data);
            }
        }
    }

    return 0;
}

static int cmd_servers(void) {
    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_servers(txn, session_token, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to servers request\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "servers error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    printf("Cluster servers (%d):\n", last_response.server_count);
    for (int i = 0; i < last_response.server_count; i++) {
        printf("  %s:%u\n",
               last_response.servers[i].ip,
               last_response.servers[i].tcp_port);
    }
    return 0;
}

static int hex_to_key(const char *hex, nodus_key_t *key) {
    if (strlen(hex) != 128) return -1;
    for (int i = 0; i < NODUS_KEY_BYTES; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        key->bytes[i] = (uint8_t)byte;
    }
    return 0;
}

static int cmd_presence(int argc, char **argv, int optind_cmd) {
    /* Build query: always include self, plus any extra fps from args */
    nodus_key_t fps[128];
    int fp_count = 0;

    /* Self */
    memcpy(&fps[fp_count++], &identity.node_id, sizeof(nodus_key_t));

    /* Extra fingerprints from command line */
    for (int i = optind_cmd + 1; i < argc && fp_count < 128; i++) {
        if (hex_to_key(argv[i], &fps[fp_count]) == 0) {
            fp_count++;
        } else {
            fprintf(stderr, "Invalid fingerprint (need 128 hex chars): %s\n", argv[i]);
        }
    }

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_presence_query(txn, session_token, fps, fp_count,
                              proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to presence query\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "pq error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    printf("Queried %d fingerprints, %d online:\n", fp_count, last_response.pq_count);
    for (int i = 0; i < last_response.pq_count; i++) {
        char hex[NODUS_KEY_HEX_LEN];
        for (int j = 0; j < NODUS_KEY_BYTES; j++)
            snprintf(hex + j * 2, 3, "%02x", last_response.pq_fps[i].bytes[j]);
        printf("  ONLINE: %.32s... (peer=%d)\n", hex, last_response.pq_peers[i]);
    }

    /* Check which queried fps are online/offline */
    for (int q = 0; q < fp_count; q++) {
        char hex[NODUS_KEY_HEX_LEN];
        for (int j = 0; j < NODUS_KEY_BYTES; j++)
            snprintf(hex + j * 2, 3, "%02x", fps[q].bytes[j]);

        bool found = false;
        for (int i = 0; i < last_response.pq_count; i++) {
            if (nodus_key_cmp(&last_response.pq_fps[i], &fps[q]) == 0) {
                found = true;
                break;
            }
        }
        printf("  %s %.32s...\n", found ? "ONLINE " : "OFFLINE", hex);
    }

    return 0;
}

/* Keep connected and print fingerprint, wait for Ctrl+C */
static int cmd_presence_hold(void) {
    printf("Identity online: %s\n", identity.fingerprint);
    printf("Holding connection (Ctrl+C to stop)...\n");
    fflush(stdout);
    while (running && server_conn) {
        /* Send ping every 15s to keep alive */
        size_t len = 0;
        uint32_t txn = next_txn++;
        nodus_t2_ping(txn, session_token, proto_buf, sizeof(proto_buf), &len);
        nodus_tcp_send(server_conn, proto_buf, len);
        for (int i = 0; i < 150 && running; i++)
            nodus_tcp_poll(&transport, 100);
    }
    printf("Disconnected.\n");
    return 0;
}

static void cmd_whoami(void) {
    printf("Fingerprint: %s\n", identity.fingerprint);
    printf("Node ID:     ");
    for (int i = 0; i < 8; i++) printf("%02x", identity.node_id.bytes[i]);
    printf("...\n");
}

/* ── Usage ───────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr, "Nodus CLI v%s\n", NODUS_VERSION_STRING);
    fprintf(stderr, "Usage: %s -s <server> [-p <port>] [-i <identity_dir>] <command> [args]\n", prog);
    fprintf(stderr, "\nCommands:\n");
    fprintf(stderr, "  whoami           Show identity\n");
    fprintf(stderr, "  ping             Ping server\n");
    fprintf(stderr, "  put <key> <val>  Store DHT value\n");
    fprintf(stderr, "  get <key>        Retrieve DHT value\n");
    fprintf(stderr, "  listen <key>     Subscribe to key changes\n");
    fprintf(stderr, "  servers          List cluster servers\n");
    fprintf(stderr, "  presence [fp..]  Query presence (self + optional fps)\n");
    fprintf(stderr, "  hold             Stay connected (test presence visibility)\n");
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    const char *server_ip = NULL;
    uint16_t server_port = NODUS_DEFAULT_TCP_PORT;
    const char *identity_dir = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "s:p:i:h")) != -1) {
        switch (opt) {
        case 's': {
            /* Support host:port format */
            char *colon = strchr(optarg, ':');
            if (colon) {
                static char host_buf[256];
                size_t hlen = (size_t)(colon - optarg);
                if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
                memcpy(host_buf, optarg, hlen);
                host_buf[hlen] = '\0';
                server_ip = host_buf;
                server_port = (uint16_t)atoi(colon + 1);
            } else {
                server_ip = optarg;
            }
            break;
        }
        case 'p': server_port = (uint16_t)atoi(optarg); break;
        case 'i': identity_dir = optarg; break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    const char *command = argv[optind];

    /* Handle whoami without server */
    if (strcmp(command, "whoami") == 0) {
        if (identity_dir) {
            if (nodus_identity_load(identity_dir, &identity) != 0) {
                fprintf(stderr, "Failed to load identity from %s\n", identity_dir);
                return 1;
            }
        } else {
            fprintf(stderr, "No identity directory. Generating random.\n");
            nodus_identity_generate(&identity);
        }
        cmd_whoami();
        nodus_identity_clear(&identity);
        return 0;
    }

    /* All other commands need a server */
    if (!server_ip) {
        fprintf(stderr, "Server required (-s <ip>)\n");
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGPIPE, SIG_IGN);

    /* Load or generate identity */
    if (identity_dir) {
        if (nodus_identity_load(identity_dir, &identity) != 0) {
            fprintf(stderr, "Failed to load identity from %s\n", identity_dir);
            return 1;
        }
    } else {
        nodus_identity_generate(&identity);
        fprintf(stderr, "Using random identity: %s\n", identity.fingerprint);
    }

    int rc = 1;

    /* Connect */
    nodus_tcp_init(&transport, -1);
    transport.on_frame = on_frame;
    transport.on_disconnect = on_disconnect;
    transport.on_connect = on_connect;

    printf("Connecting to %s:%u...\n", server_ip, server_port);
    fflush(stdout);
    server_conn = nodus_tcp_connect(&transport, server_ip, server_port);
    if (!server_conn) {
        fprintf(stderr, "Failed to connect\n");
        goto cleanup;
    }

    /* Wait for connection */
    for (int i = 0; i < 100 && server_conn->state == NODUS_CONN_CONNECTING; i++)
        nodus_tcp_poll(&transport, 50);

    if (!server_conn || server_conn->state != NODUS_CONN_CONNECTED) {
        fprintf(stderr, "Connection failed\n");
        goto cleanup;
    }
    printf("Connected.\n");
    fflush(stdout);

    /* Authenticate */
    printf("Authenticating...\n");
    fflush(stdout);
    if (do_auth() != 0) {
        fprintf(stderr, "Authentication failed\n");
        goto cleanup;
    }
    printf("Authenticated.\n");
    fflush(stdout);

    /* Dispatch command */
    rc = 0;
    if (strcmp(command, "ping") == 0) {
        rc = cmd_ping();
    } else if (strcmp(command, "servers") == 0) {
        rc = cmd_servers();
    } else if (strcmp(command, "put") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Usage: put <key> <value>\n");
            rc = 1;
        } else {
            rc = cmd_put(argv[optind + 1], argv[optind + 2]);
        }
    } else if (strcmp(command, "get") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: get <key>\n");
            rc = 1;
        } else {
            rc = cmd_get(argv[optind + 1]);
        }
    } else if (strcmp(command, "presence") == 0) {
        rc = cmd_presence(argc, argv, optind);
    } else if (strcmp(command, "hold") == 0) {
        rc = cmd_presence_hold();
    } else if (strcmp(command, "listen") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: listen <key>\n");
            rc = 1;
        } else {
            rc = cmd_listen(argv[optind + 1]);
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        rc = 1;
    }

cleanup:
    nodus_t2_msg_free(&last_response);
    nodus_tcp_close(&transport);
    nodus_identity_clear(&identity);
    return rc;
}
