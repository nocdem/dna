/**
 * Nodus — CLI Tool
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
#include "nodus/nodus.h"                    /* Stage E.2 helper + dnac_committee */
#include "nodus/nodus_types.h"
#include "nodus/nodus_chain_config.h"       /* Stage C vote primitives */
#include "protocol/nodus_cbor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#ifdef NODUS_CLI_HAS_DNAC
/* Hard-Fork v1 Stage E.3 — chain-config propose verb.
 *
 * Depends on libdna for pure TX wire functions (dnac_tx_create / add_input /
 * add_output / compute_hash / serialize). No dna_engine / dnac_context
 * is initialized — nodus-cli uses tier-2 RPCs for UTXO query + dnac_spend
 * submit, and signs with the operator's nodus Dilithium5 sk directly.
 *
 * Tech debt (logged in memory): the libdna dependency is load-bearing only
 * for serialize + compute_hash. Moving those to shared/dnac/ retires the
 * dependency. See project_nodus_cli_libdna_decouple.md. */
#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"   /* DNAC_MAX_UTXO_QUERY_RESULTS, DNAC_MAX_TX_SIZE */
#endif

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

    /* Step 2: Sign nonce and send AUTH (C2: domain-tagged AUTH_CHALLENGE) */
    nodus_sig_t sig;
    nodus_sign_auth_challenge(&sig, last_response.nonce, &identity.sk);

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

static int cmd_witness(const char *connected_ip) {
    /* Get all entries from "nodus:pk" DHT key */
    nodus_key_t key;
    nodus_hash((const uint8_t *)"nodus:pk", 8, &key);

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_get_all(txn, session_token, &key,
                      proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to GET_ALL\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "GET_ALL error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    if (!last_response.values || last_response.value_count == 0) {
        printf("No witnesses registered in DHT.\n");
        return 0;
    }

    /* connected_ip is the server we're talking to */

    printf("Witness Roster (from DHT \"nodus:pk\")\n");
    printf("=====================================\n");
    printf("Total entries: %zu\n\n", last_response.value_count);

    int my_index = -1;
    int valid_count = 0;

    for (size_t i = 0; i < last_response.value_count; i++) {
        nodus_value_t *val = last_response.values[i];
        if (!val || !val->data || val->data_len == 0) continue;

        /* Verify signature */
        bool sig_ok = (nodus_value_verify(val) == 0);

        /* Check expiry */
        bool expired = nodus_value_is_expired(val, (uint64_t)time(NULL));

        /* Decode CBOR payload */
        cbor_decoder_t dec;
        cbor_decoder_init(&dec, val->data, val->data_len);
        cbor_item_t top = cbor_decode_next(&dec);
        if (top.type != CBOR_ITEM_MAP) continue;

        char node_id_hex[NODUS_KEY_BYTES * 2 + 1] = {0};
        char ip[64] = {0};
        uint16_t port = 0;
        bool has_id = false;

        for (size_t m = 0; m < top.count; m++) {
            cbor_item_t k = cbor_decode_next(&dec);
            if (k.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

            if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "id", 2) == 0) {
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_KEY_BYTES) {
                    for (int b = 0; b < NODUS_KEY_BYTES; b++)
                        snprintf(node_id_hex + b * 2, sizeof(node_id_hex) - b * 2, "%02x", v.bstr.ptr[b]);
                    has_id = true;
                }
            } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "ip", 2) == 0) {
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_TSTR && v.tstr.len < sizeof(ip)) {
                    memcpy(ip, v.tstr.ptr, v.tstr.len);
                    ip[v.tstr.len] = '\0';
                }
            } else if (k.tstr.len == 4 && memcmp(k.tstr.ptr, "port", 4) == 0) {
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_UINT)
                    port = (uint16_t)v.uint_val;
            } else {
                cbor_decode_skip(&dec);
            }
        }

        if (!has_id) continue;
        valid_count++;

        /* Check if this is the server we're connected to (match by IP) */
        bool is_connected = (connected_ip && ip[0] &&
                             strcmp(ip, connected_ip) == 0);
        if (is_connected) my_index = valid_count - 1;

        printf("[%d] %s%s\n", valid_count - 1,
               is_connected ? "(CONNECTED) " : "",
               expired ? "(EXPIRED) " : "");
        printf("    node_id:  %.32s...\n", node_id_hex);
        printf("    address:  %s:%u\n", ip, port);
        printf("    sig:      %s\n", sig_ok ? "VALID" : "INVALID");
        printf("    seq:      %lu\n", (unsigned long)val->seq);
        printf("    expires:  %lds from now\n",
               (long)(val->expires_at - (uint64_t)time(NULL)));
        printf("\n");
    }

    printf("─────────────────────────────────\n");
    printf("Valid witnesses: %d\n", valid_count);
    printf("Server index:    %d\n", my_index);

    /* BFT config */
    if (valid_count >= NODUS_T3_MIN_WITNESSES) {
        uint32_t f = (valid_count - 1) / 3;
        uint32_t quorum = 2 * f + 1;
        printf("Consensus:       ACTIVE\n");
        printf("f_tolerance:     %u\n", f);
        printf("Quorum:          %u\n", quorum);
    } else {
        printf("Consensus:       DISABLED (need %d, have %d)\n",
               NODUS_T3_MIN_WITNESSES, valid_count);
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

/* ── cluster-status (Phase 0 / Task 0.2) ─────────────────────────────
 *
 * Queries one or more nodes for their block_height, state_root,
 * chain_id, peer count, uptime and wall clock, then prints a side-by-
 * side table. Each target gets its own connect+auth+query+disconnect
 * cycle — there is no batch query because operators want explicit
 * per-node visibility (and we want one node failing to be a single row
 * rather than the entire query collapsing).
 */
typedef struct {
    char     target[280];   /* "host:port" — host up to 256, ":port" up to 6 */
    bool     reachable;
    uint64_t block_height;
    uint8_t  state_root[64];
    uint8_t  chain_id[32];
    uint32_t peer_count;
    uint64_t uptime_sec;
    uint64_t wall_clock;
    uint8_t  disk_free_pct;
} cluster_node_status_t;

static int cluster_status_query_one(const char *host, uint16_t port,
                                     cluster_node_status_t *out) {
    snprintf(out->target, sizeof(out->target), "%s:%u", host, port);
    out->reachable = false;

    nodus_tcp_init(&transport, -1);
    transport.on_frame = on_frame;
    transport.on_disconnect = on_disconnect;
    transport.on_connect = on_connect;

    server_conn = nodus_tcp_connect(&transport, host, port);
    if (!server_conn) goto done;

    for (int i = 0; i < 60 && server_conn->state == NODUS_CONN_CONNECTING; i++)
        nodus_tcp_poll(&transport, 50);
    if (!server_conn || server_conn->state != NODUS_CONN_CONNECTED) goto done;

    if (do_auth() != 0) goto done;

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_status(txn, session_token, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);
    if (!wait_response(5000)) goto done;
    if (last_response.type == 'e' || !last_response.has_status_info) goto done;

    out->reachable = true;
    out->block_height  = last_response.status_info.block_height;
    memcpy(out->state_root, last_response.status_info.state_root, 64);
    memcpy(out->chain_id,   last_response.status_info.chain_id,   32);
    out->peer_count    = last_response.status_info.peer_count;
    out->uptime_sec    = last_response.status_info.uptime_sec;
    out->wall_clock    = last_response.status_info.wall_clock;
    out->disk_free_pct = last_response.status_info.disk_free_pct;

done:
    nodus_t2_msg_free(&last_response);
    nodus_tcp_close(&transport);
    server_conn = NULL;
    authenticated = false;
    return out->reachable ? 0 : -1;
}

static void format_uptime(uint64_t sec, char *buf, size_t buf_len) {
    if (sec == 0)              { snprintf(buf, buf_len, "  -"); return; }
    if (sec < 60)              { snprintf(buf, buf_len, "%2us", (unsigned)sec); return; }
    if (sec < 3600)            { snprintf(buf, buf_len, "%2um", (unsigned)(sec/60)); return; }
    if (sec < 86400)           { snprintf(buf, buf_len, "%2uh", (unsigned)(sec/3600)); return; }
    snprintf(buf, buf_len, "%2ud", (unsigned)(sec/86400));
}

static int cmd_cluster_status(int argc, char **argv, int optind_cmd) {
    if (optind_cmd + 1 >= argc) {
        fprintf(stderr, "Usage: nodus-cli cluster-status <host[:port]> [host[:port] ...]\n");
        return 1;
    }

    int targets = argc - (optind_cmd + 1);
    cluster_node_status_t *rows = calloc((size_t)targets, sizeof(*rows));
    if (!rows) return 1;

    for (int i = 0; i < targets; i++) {
        const char *spec = argv[optind_cmd + 1 + i];
        char host[256];
        uint16_t port = NODUS_DEFAULT_TCP_PORT;
        const char *colon = strchr(spec, ':');
        if (colon) {
            size_t hl = (size_t)(colon - spec);
            if (hl >= sizeof(host)) hl = sizeof(host) - 1;
            memcpy(host, spec, hl);
            host[hl] = '\0';
            port = (uint16_t)atoi(colon + 1);
        } else {
            snprintf(host, sizeof(host), "%s", spec);
        }
        cluster_status_query_one(host, port, &rows[i]);
    }

    /* Print table */
    printf("%-24s  %-6s  %-12s  %-6s  %-8s  %-5s  %-12s  %s\n",
           "ADDR", "STATUS", "HEIGHT", "PEERS", "UPTIME", "DF%",
           "WALL_CLOCK", "STATE_ROOT");
    printf("%-24s  %-6s  %-12s  %-6s  %-8s  %-5s  %-12s  %s\n",
           "------------------------", "------", "------------",
           "------", "--------", "-----", "------------",
           "----------------");
    for (int i = 0; i < targets; i++) {
        if (!rows[i].reachable) {
            printf("%-24s  %-6s\n", rows[i].target, "DOWN");
            continue;
        }
        char up[16];
        format_uptime(rows[i].uptime_sec, up, sizeof(up));
        char df[8];
        if (rows[i].disk_free_pct == 255) snprintf(df, sizeof(df), " -");
        else                              snprintf(df, sizeof(df), "%3u%%", rows[i].disk_free_pct);
        char sr_short[17];
        for (int j = 0; j < 8; j++)
            snprintf(sr_short + j * 2, 3, "%02x", rows[i].state_root[j]);
        printf("%-24s  %-6s  %-12llu  %-6u  %-8s  %-5s  %-12llu  %s...\n",
               rows[i].target,
               "UP",
               (unsigned long long)rows[i].block_height,
               rows[i].peer_count,
               up,
               df,
               (unsigned long long)rows[i].wall_clock,
               sr_short);
    }

    int down = 0;
    for (int i = 0; i < targets; i++) if (!rows[i].reachable) down++;
    free(rows);
    return down == 0 ? 0 : 1;
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

/* ── Channel listen: connect TCP 4003, subscribe, log incoming posts ── */

static int parse_uuid(const char *str, uint8_t out[NODUS_UUID_BYTES]) {
    /* Accept 32 hex chars or hyphenated UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) */
    char clean[33];
    int ci = 0;
    for (int i = 0; str[i] && ci < 32; i++) {
        if (str[i] == '-') continue;
        clean[ci++] = str[i];
    }
    clean[ci] = '\0';
    if (ci != 32) return -1;
    for (int i = 0; i < NODUS_UUID_BYTES; i++) {
        unsigned int byte;
        if (sscanf(clean + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static void uuid_to_str(const uint8_t uuid[NODUS_UUID_BYTES], char out[37]) {
    snprintf(out, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11],
        uuid[12], uuid[13], uuid[14], uuid[15]);
}

static int cmd_ch_listen(const char *server_ip, uint16_t ch_port,
                          const char *uuid_str, const char *log_path) {
    uint8_t ch_uuid[NODUS_UUID_BYTES];
    if (parse_uuid(uuid_str, ch_uuid) != 0) {
        fprintf(stderr, "Invalid UUID: %s\n", uuid_str);
        return 1;
    }

    /* Open log file (append) */
    FILE *logf = NULL;
    if (log_path) {
        logf = fopen(log_path, "a");
        if (!logf) {
            fprintf(stderr, "Cannot open log file: %s\n", log_path);
            return 1;
        }
    }

    /* Connect to TCP 4003 using global transport */
    nodus_tcp_init(&transport, -1);
    transport.on_frame = on_frame;
    transport.on_disconnect = on_disconnect;
    transport.on_connect = on_connect;

    printf("Connecting to %s:%u (channel port)...\n", server_ip, ch_port);
    fflush(stdout);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&transport, server_ip, ch_port);
    if (!conn) {
        fprintf(stderr, "Failed to connect to channel port\n");
        if (logf) fclose(logf);
        return 1;
    }

    /* Wait for connection */
    for (int i = 0; i < 100 && conn->state == NODUS_CONN_CONNECTING; i++)
        nodus_tcp_poll(&transport, 50);
    if (conn->state != NODUS_CONN_CONNECTED) {
        fprintf(stderr, "Connection failed\n");
        nodus_tcp_close(&transport);
        if (logf) fclose(logf);
        return 1;
    }
    printf("Connected to channel port.\n");

    /* Auth: hello → challenge → auth → auth_ok */
    server_conn = conn;

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_hello(txn, &identity.pk, &identity.node_id,
                    proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(conn, proto_buf, len);

    if (!wait_response(5000) || strcmp(last_response.method, "challenge") != 0) {
        fprintf(stderr, "Auth failed: no challenge\n");
        nodus_tcp_close(&transport);
        if (logf) fclose(logf);
        return 1;
    }

    /* C2: domain-tagged AUTH_CHALLENGE */
    nodus_sig_t sig;
    nodus_sign_auth_challenge(&sig, last_response.nonce, &identity.sk);
    txn = next_txn++;
    nodus_t2_auth(txn, &sig, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(conn, proto_buf, len);

    if (!wait_response(5000) || strcmp(last_response.method, "auth_ok") != 0) {
        fprintf(stderr, "Auth failed: %s\n",
                last_response.type == 'e' ? last_response.error_msg : last_response.method);
        nodus_tcp_close(&transport);
        if (logf) fclose(logf);
        return 1;
    }
    uint8_t ch_token[NODUS_SESSION_TOKEN_LEN];
    memcpy(ch_token, last_response.token, NODUS_SESSION_TOKEN_LEN);
    printf("Authenticated on channel port.\n");

    /* Subscribe */
    txn = next_txn++;
    nodus_t2_ch_subscribe(txn, ch_token, ch_uuid,
                            proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to ch_sub\n");
        nodus_tcp_close(&transport);
        if (logf) fclose(logf);
        return 1;
    }

    char uuid_pretty[37];
    uuid_to_str(ch_uuid, uuid_pretty);
    printf("Subscribed to channel %s\n", uuid_pretty);
    printf("Listening for posts... (Ctrl+C to stop)\n");
    if (logf) {
        fprintf(logf, "--- ch_listen started: %s ---\n", uuid_pretty);
        fflush(logf);
    }
    fflush(stdout);

    /* Main loop: stay connected, print incoming ch_post_notify */
    while (running) {
        response_ready = false;
        nodus_tcp_poll(&transport, 500);

        if (response_ready) {
            if (strcmp(last_response.method, "ch_ntf") == 0) {
                char post_uuid[37], author_hex[NODUS_KEY_HEX_LEN];
                uuid_to_str(last_response.post_uuid_ch, post_uuid);
                for (int i = 0; i < NODUS_KEY_BYTES; i++)
                    snprintf(author_hex + i * 2, 3, "%02x", last_response.fp.bytes[i]);

                /* ch_timestamp is Unix seconds (not ms) */
                time_t ts = (time_t)last_response.ch_timestamp;
                struct tm tm_buf;
                struct tm *tm = localtime_r(&ts, &tm_buf);
                char timebuf[32];
                strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

                printf("[%s] %.16s...: %.*s\n",
                       timebuf, author_hex,
                       (int)last_response.data_len,
                       last_response.data ? (char *)last_response.data : "");
                fflush(stdout);

                if (logf) {
                    fprintf(logf, "[%s] post=%s author=%.16s... body=%.*s\n",
                            timebuf, post_uuid, author_hex,
                            (int)last_response.data_len,
                            last_response.data ? (char *)last_response.data : "");
                    fflush(logf);
                }
            }
        }
    }

    printf("Disconnected.\n");
    nodus_tcp_close(&transport);
    if (logf) {
        fprintf(logf, "--- ch_listen stopped ---\n");
        fclose(logf);
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

#ifdef NODUS_CLI_HAS_DNAC
/* ── Stage E.3 — chain-config propose ───────────────────────────── */

static int cc_param_name_to_id(const char *name, uint8_t *out_id) {
    static const struct { const char *n; uint8_t id; } map[] = {
        { "MAX_TXS_PER_BLOCK",    DNAC_CFG_MAX_TXS_PER_BLOCK },
        { "max_txs_per_block",    DNAC_CFG_MAX_TXS_PER_BLOCK },
        { "BLOCK_INTERVAL_SEC",   DNAC_CFG_BLOCK_INTERVAL_SEC },
        { "block_interval_sec",   DNAC_CFG_BLOCK_INTERVAL_SEC },
        { "INFLATION_START_BLOCK", DNAC_CFG_INFLATION_START_BLOCK },
        { "inflation_start_block", DNAC_CFG_INFLATION_START_BLOCK },
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
        if (strcmp(name, map[i].n) == 0) { *out_id = map[i].id; return 0; }
    }
    return -1;
}

static void cc_print_hex16(FILE *out, const uint8_t *b) {
    for (int i = 0; i < 8; i++) fprintf(out, "%02x", b[i]);
    fprintf(out, "...");
}

/* chain-config propose flow.
 *
 * Assumes the outer main() has already loaded `identity` from -i and has
 * the base transport/session open on server_ip:server_port (the short-lived
 * nodus_client_t created below is a separate connection scoped just to the
 * DNAC RPC calls this command needs). */
static int cmd_chain_config_propose(const char *server_ip, uint16_t server_port,
                                     int argc, char **argv, int cmd_start) {
    /* 1. Parse sub-flags --param / --value / --effective / [--nonce]. */
    const char *param_name = NULL;
    uint64_t new_value = 0, effective_block = 0, proposal_nonce = 0;
    int has_value = 0, has_effective = 0, has_nonce = 0;

    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--param") == 0 && i + 1 < argc) {
            param_name = argv[++i];
        } else if (strcmp(a, "--value") == 0 && i + 1 < argc) {
            new_value = strtoull(argv[++i], NULL, 10); has_value = 1;
        } else if (strcmp(a, "--effective") == 0 && i + 1 < argc) {
            effective_block = strtoull(argv[++i], NULL, 10); has_effective = 1;
        } else if (strcmp(a, "--nonce") == 0 && i + 1 < argc) {
            proposal_nonce = strtoull(argv[++i], NULL, 10); has_nonce = 1;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", a);
            return 1;
        }
    }
    if (!param_name || !has_value || !has_effective) {
        fprintf(stderr,
            "Usage: chain-config propose --param <NAME> --value <N> "
            "--effective <BLOCK> [--nonce <N>]\n"
            "Params: MAX_TXS_PER_BLOCK, BLOCK_INTERVAL_SEC, "
            "INFLATION_START_BLOCK\n");
        return 1;
    }
    uint8_t param_id = 0;
    if (cc_param_name_to_id(param_name, &param_id) != 0) {
        fprintf(stderr, "Unknown param name: %s\n", param_name);
        return 1;
    }
    if (!has_nonce) {
        nodus_random((uint8_t *)&proposal_nonce, sizeof(proposal_nonce));
    }

    /* 2. Open a short-lived nodus_client_t for DNAC queries + submit. */
    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", server_ip);
    cfg.servers[0].port = server_port;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;

    if (nodus_client_init(&client, &cfg, &identity) != 0) {
        fprintf(stderr, "client_init failed\n");
        return 1;
    }
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client_connect failed\n");
        nodus_client_close(&client);
        return 1;
    }

    int rc = 1;
    dnac_transaction_t *tx = NULL;
    nodus_dnac_utxo_result_t utxos;
    memset(&utxos, 0, sizeof(utxos));
    bool utxos_valid = false;

    /* 3. Committee query. */
    nodus_dnac_committee_result_t committee;
    memset(&committee, 0, sizeof(committee));
    if (nodus_client_dnac_committee(&client, &committee) != 0) {
        fprintf(stderr, "committee query failed\n");
        goto done;
    }
    if (committee.count < DNAC_CHAIN_CONFIG_MIN_SIGS) {
        fprintf(stderr, "Committee size %d < min_sigs %d — quorum impossible\n",
                committee.count, DNAC_CHAIN_CONFIG_MIN_SIGS);
        goto done;
    }

    /* 4. Caller witness_id + committee-membership check. */
    uint8_t caller_wid[32];
    if (nodus_chain_config_derive_witness_id(identity.pk.bytes,
                                               caller_wid) != 0) {
        fprintf(stderr, "derive caller witness_id failed\n");
        goto done;
    }
    int self_idx = -1;
    for (int i = 0; i < committee.count; i++) {
        uint8_t m_wid[32];
        if (nodus_chain_config_derive_witness_id(
                committee.entries[i].pubkey, m_wid) != 0) continue;
        if (memcmp(m_wid, caller_wid, 32) == 0) { self_idx = i; break; }
    }
    if (self_idx < 0) {
        fprintf(stderr, "Current identity is NOT in the committee.\n");
        fprintf(stderr, "  your witness_id: ");
        cc_print_hex16(stderr, caller_wid);
        fprintf(stderr, "\n  chain-config propose requires a committee "
                        "operator key. Aborting.\n");
        goto done;
    }
    printf("Committee member #%d (%.16s...).\n",
           self_idx + 1, identity.fingerprint);

    /* 5. Anchor timing. signed_at_block is the committee snapshot height;
     * valid_before gives plenty of slack for the collect+commit round
     * trip — use the safety grace period as the outer bound so even
     * safety-critical proposals can settle before valid_before lapses. */
    uint64_t signed_at_block = committee.block_height;
    uint64_t valid_before = committee.block_height +
                             (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
    if (effective_block <= signed_at_block) {
        fprintf(stderr, "--effective (%llu) must be > current block (%llu)\n",
                (unsigned long long)effective_block,
                (unsigned long long)signed_at_block);
        goto done;
    }
    if (valid_before <= effective_block) {
        /* Ensure Rule CC freshness math cannot trivially fail. */
        valid_before = effective_block +
                       (uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS;
    }

    /* 6. chain_id from supply query. */
    nodus_dnac_supply_result_t supply;
    memset(&supply, 0, sizeof(supply));
    if (nodus_client_dnac_supply(&client, &supply) != 0) {
        fprintf(stderr, "supply query (for chain_id) failed\n");
        goto done;
    }

    /* 7. Proposal digest. */
    uint8_t digest[NODUS_CC_DIGEST_SIZE];
    if (nodus_chain_config_compute_digest(supply.chain_id, param_id, new_value,
                                            effective_block, proposal_nonce,
                                            signed_at_block, valid_before,
                                            digest) != 0) {
        fprintf(stderr, "digest compute failed\n");
        goto done;
    }

    /* 8. Collect votes. Self-vote first, then fan out via Stage E.2 helper. */
    dnac_chain_config_collected_vote_t votes[DNAC_COMMITTEE_SIZE];
    int vote_count = 0;
    memset(votes, 0, sizeof(votes));

    if (nodus_chain_config_sign_vote(identity.pk.bytes, identity.sk.bytes,
                                       digest, votes[0].witness_id,
                                       votes[0].signature) != 0) {
        fprintf(stderr, "self-sign failed\n");
        goto done;
    }
    vote_count = 1;
    printf("Vote %d/%d: self (accepted)\n",
           vote_count, DNAC_CHAIN_CONFIG_MIN_SIGS);

    nodus_t3_cc_vote_req_t req;
    memset(&req, 0, sizeof(req));
    req.param_id               = param_id;
    req.new_value              = new_value;
    req.effective_block_height = effective_block;
    req.proposal_nonce         = proposal_nonce;
    req.signed_at_block        = signed_at_block;
    req.valid_before_block     = valid_before;

    for (int i = 0; i < committee.count; i++) {
        if (i == self_idx) continue;
        const nodus_dnac_committee_entry_t *peer = &committee.entries[i];
        printf("Requesting vote from peer #%d", i + 1);
        if (peer->address[0]) printf(" (%s)", peer->address);
        printf("... ");
        fflush(stdout);

        if (peer->address[0] == '\0') { printf("SKIP (address unknown)\n"); continue; }

        nodus_pubkey_t peer_pk;
        memcpy(peer_pk.bytes, peer->pubkey, NODUS_PK_BYTES);

        nodus_t3_cc_vote_rsp_t rsp;
        int vrc = nodus_client_cc_vote_send(peer->address,
                                              &identity.pk, &identity.sk,
                                              caller_wid, &peer_pk,
                                              supply.chain_id, &req,
                                              5000, &rsp);
        if (vrc == 0 && rsp.accepted) {
            if (vote_count >= DNAC_COMMITTEE_SIZE) { printf("DROP (full)\n"); continue; }
            memcpy(votes[vote_count].witness_id, rsp.witness_id, 32);
            memcpy(votes[vote_count].signature, rsp.signature,
                   DNAC_SIGNATURE_SIZE);
            vote_count++;
            printf("ACCEPTED\n");
        } else if (vrc == 0) {
            printf("REJECTED: %s\n", rsp.reject_reason[0]
                                      ? rsp.reject_reason
                                      : "(no reason given)");
        } else if (vrc == -2) {
            printf("TIMEOUT\n");
        } else if (vrc == -3) {
            printf("BAD WSIG\n");
        } else {
            printf("ERROR (rc=%d)\n", vrc);
        }
    }

    printf("\nCollected %d/%d votes (min=%d).\n",
           vote_count, DNAC_COMMITTEE_SIZE, DNAC_CHAIN_CONFIG_MIN_SIGS);
    if (vote_count < DNAC_CHAIN_CONFIG_MIN_SIGS) {
        fprintf(stderr, "Quorum not reached. Aborting without submitting TX.\n");
        goto done;
    }

    /* 9. Fee query + UTXO query (native DNAC only). */
    nodus_dnac_fee_info_t fee_info;
    memset(&fee_info, 0, sizeof(fee_info));
    if (nodus_client_dnac_fee_info(&client, &fee_info) != 0) {
        fprintf(stderr, "fee info query failed\n");
        goto done;
    }
    uint64_t fee = fee_info.min_fee;

    if (nodus_client_dnac_utxo(&client, identity.fingerprint, 100,
                                 &utxos) != 0) {
        fprintf(stderr, "utxo query failed\n");
        goto done;
    }
    utxos_valid = true;
    if (utxos.count == 0) {
        fprintf(stderr, "No UTXOs for this identity — cannot pay fee %llu.\n",
                (unsigned long long)fee);
        goto done;
    }

    /* 10. Greedy native-DNAC selection (token_id all-zero). */
    static const uint8_t zero_token[DNAC_TOKEN_ID_SIZE] = {0};
    dnac_utxo_t selected[DNAC_MAX_UTXO_QUERY_RESULTS];
    int selected_count = 0;
    uint64_t total_input = 0;

    for (int i = 0; i < utxos.count && total_input < fee; i++) {
        const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
        if (memcmp(e->token_id, zero_token, DNAC_TOKEN_ID_SIZE) != 0) continue;
        dnac_utxo_t *s = &selected[selected_count++];
        memset(s, 0, sizeof(*s));
        s->version = 1;
        memcpy(s->tx_hash,  e->tx_hash,   DNAC_TX_HASH_SIZE);
        s->output_index = e->output_index;
        s->amount       = e->amount;
        memcpy(s->nullifier, e->nullifier, DNAC_NULLIFIER_SIZE);
        snprintf(s->owner_fingerprint, DNAC_FINGERPRINT_SIZE, "%s",
                  identity.fingerprint);
        memcpy(s->token_id, zero_token, DNAC_TOKEN_ID_SIZE);
        total_input += e->amount;
    }
    if (total_input < fee) {
        fprintf(stderr, "Insufficient native DNAC: have %llu raw, need %llu\n",
                (unsigned long long)total_input, (unsigned long long)fee);
        goto done;
    }
    uint64_t change = total_input - fee;

    /* 11. Build TX. */
    tx = dnac_tx_create(DNAC_TX_CHAIN_CONFIG);
    if (!tx) { fprintf(stderr, "tx_create failed\n"); goto done; }

    for (int i = 0; i < selected_count; i++) {
        if (dnac_tx_add_input(tx, &selected[i]) != DNAC_SUCCESS) {
            fprintf(stderr, "tx_add_input failed\n");
            goto done;
        }
    }
    if (change > 0) {
        uint8_t seed_unused[32];
        if (dnac_tx_add_output(tx, identity.fingerprint, change,
                                seed_unused) != DNAC_SUCCESS) {
            fprintf(stderr, "tx_add_output(change) failed\n");
            goto done;
        }
    }

    dnac_tx_chain_config_fields_t *cc = &tx->chain_config_fields;
    cc->param_id               = param_id;
    cc->new_value              = new_value;
    cc->effective_block_height = effective_block;
    cc->proposal_nonce         = proposal_nonce;
    cc->signed_at_block        = signed_at_block;
    cc->valid_before_block     = valid_before;
    cc->committee_sig_count    = (uint8_t)vote_count;
    for (int i = 0; i < vote_count; i++) {
        memcpy(cc->committee_votes[i].witness_id, votes[i].witness_id, 32);
        memcpy(cc->committee_votes[i].signature, votes[i].signature,
               DNAC_SIGNATURE_SIZE);
    }
    memcpy(tx->chain_id, supply.chain_id, 32);

    /* Signer = proposer. */
    memcpy(tx->signers[0].pubkey, identity.pk.bytes, DNAC_PUBKEY_SIZE);
    tx->signer_count = 1;

    if (dnac_tx_compute_hash(tx, tx->tx_hash) != DNAC_SUCCESS) {
        fprintf(stderr, "tx_compute_hash failed\n");
        goto done;
    }

    nodus_sig_t sender_sig;
    nodus_sign(&sender_sig, tx->tx_hash, DNAC_TX_HASH_SIZE, &identity.sk);
    memcpy(tx->signers[0].signature, sender_sig.bytes, DNAC_SIGNATURE_SIZE);

    static uint8_t tx_bytes[DNAC_MAX_TX_SIZE];
    size_t tx_len = 0;
    if (dnac_tx_serialize(tx, tx_bytes, sizeof(tx_bytes),
                            &tx_len) != DNAC_SUCCESS) {
        fprintf(stderr, "tx_serialize failed\n");
        goto done;
    }

    /* 12. Submit via tier-2 dnac_spend. */
    nodus_pubkey_t sender_pk;
    memcpy(sender_pk.bytes, identity.pk.bytes, NODUS_PK_BYTES);

    nodus_dnac_spend_result_t spend_result;
    memset(&spend_result, 0, sizeof(spend_result));
    int srv_rc = nodus_client_dnac_spend(&client, tx->tx_hash, tx_bytes,
                                           (uint32_t)tx_len, &sender_pk,
                                           &sender_sig, fee, &spend_result);
    if (srv_rc != 0) {
        fprintf(stderr, "dnac_spend RPC failed (rc=%d)\n", srv_rc);
        goto done;
    }

    printf("\nTX submitted. hash=");
    for (int i = 0; i < 8; i++) printf("%02x", tx->tx_hash[i]);
    printf("... fee=%llu change=%llu inputs=%d\n",
           (unsigned long long)fee,
           (unsigned long long)change,
           selected_count);
    rc = 0;

done:
    if (tx) dnac_free_transaction(tx);
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    nodus_client_close(&client);
    return rc;
}
#endif /* NODUS_CLI_HAS_DNAC */

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
    fprintf(stderr, "  witness          Show witness roster + BFT status\n");
    fprintf(stderr, "  ch_listen <uuid> [logfile]  Subscribe to channel on TCP 4003, log posts\n");
#ifdef NODUS_CLI_HAS_DNAC
    fprintf(stderr, "  chain-config propose --param <NAME> --value <N> --effective <BLOCK>\n");
    fprintf(stderr, "                              [--nonce <N>]  (committee operator only)\n");
#endif
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    const char *server_ip = NULL;
    uint16_t server_port = NODUS_DEFAULT_TCP_PORT;
    const char *identity_dir = NULL;
    int opt;

    /* Leading "+" makes getopt stop at the first non-option argument so
     * sub-command long options (e.g. `chain-config propose --param ...`)
     * are not consumed here and instead reach the command handler. */
    while ((opt = getopt(argc, argv, "+s:p:i:h")) != -1) {
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

    /* All other commands need a server, except cluster-status which
     * takes its target list as positional args. */
    if (!server_ip && strcmp(command, "cluster-status") != 0) {
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

    /* cluster-status: drives its own per-target connect+auth+query loop,
     * does not use the default single-target connection below. */
    if (strcmp(command, "cluster-status") == 0) {
        int rc = cmd_cluster_status(argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }

#ifdef NODUS_CLI_HAS_DNAC
    /* chain-config: drives its own nodus_client_t session, uses tier-2
     * DNAC RPCs + Stage E.2 tier-3 helper. Bypasses the outer
     * single-target connect+auth below. */
    if (strcmp(command, "chain-config") == 0) {
        if (optind + 1 >= argc || strcmp(argv[optind + 1], "propose") != 0) {
            fprintf(stderr, "Usage: chain-config propose --param <NAME> "
                             "--value <N> --effective <BLOCK> [--nonce <N>]\n");
            nodus_identity_clear(&identity);
            return 1;
        }
        int rc = cmd_chain_config_propose(server_ip, server_port,
                                            argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }
#endif

    /* ch_listen: connects to TCP 4003 directly, bypasses TCP 4001 */
    if (strcmp(command, "ch_listen") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: ch_listen <uuid> [logfile]\n");
            nodus_identity_clear(&identity);
            return 1;
        }
        uint16_t ch_port = server_port + 2;  /* 4001 → 4003 */
        const char *lf = (optind + 2 < argc) ? argv[optind + 2] : NULL;
        int rc = cmd_ch_listen(server_ip, ch_port, argv[optind + 1], lf);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* Remaining commands: connect to TCP 4001, authenticate */
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
    } else if (strcmp(command, "witness") == 0) {
        rc = cmd_witness(server_ip);
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
