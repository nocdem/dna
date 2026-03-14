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
#include "nodus/nodus_types.h"
#include "protocol/nodus_cbor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

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
                        sprintf(node_id_hex + b * 2, "%02x", v.bstr.ptr[b]);
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

    nodus_sig_t sig;
    nodus_sign(&sig, last_response.nonce, NODUS_NONCE_LEN, &identity.sk);
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
