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
#include "crypto/hash/qgp_sha3.h"   /* S3: stake verb unstake-dest fp */
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
#include "crypto/sign/qgp_dilithium.h"      /* qgp_dsa87_sign (offline votes) */
/* O15D — `v2-envelope chain-config`: successor-chain envelope builder.
 * Everything is derived from the COMMITTED successor database (read-only
 * sqlite open) through the same production authorities the engine uses:
 * chain id, registry ruleset, committee snapshot, set hash, approval
 * digests. Offline-signed with operator key dirs (the O15C --keys
 * pattern); submitted through the ordinary tier-2 dnac_spend lane. */
#include <sqlite3.h>
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/ledger_ids.h"                /* DNA_DOMAIN_SYSTEM          */
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_v2_claims.h"   /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_v2_produce.h"  /* tip height                */
#include "witness/nodus_witness_v2_apply.h"    /* nodus_v2_epoch_for_height */
#include "witness/nodus_witness_runtime.h"     /* set-hash / approval digest */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"      /* O15F T6: fp raw<->hex      */
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
        { "TARGET_ACTIVE_COUNT",  DNAC_CFG_TARGET_ACTIVE_COUNT },
        { "target_active_count",  DNAC_CFG_TARGET_ACTIVE_COUNT },
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
            "Params (--value range):\n"
            "  MAX_TXS_PER_BLOCK      [1, %llu]\n"
            "  BLOCK_INTERVAL_SEC     [%llu, %llu]\n"
            "  INFLATION_START_BLOCK  [0, %llu]\n"
            "  TARGET_ACTIVE_COUNT    [%llu, %llu]   "
            "(active validator set; epoch-boundary effective)\n",
            (unsigned long long)DNAC_CFG_MAX_TXS_HARD_CAP,
            (unsigned long long)DNAC_CFG_MIN_BLOCK_INTERVAL_SEC,
            (unsigned long long)DNAC_CFG_MAX_BLOCK_INTERVAL_SEC,
            (unsigned long long)DNAC_CFG_MAX_INFLATION_START_BLOCK,
            (unsigned long long)DNAC_CFG_MIN_TARGET_ACTIVE,
            (unsigned long long)DNAC_CFG_MAX_TARGET_ACTIVE);
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
    /* S3: heap buffers, declared HERE so every `goto done` below sees
     * them initialized (a goto over an initialized declaration would
     * leave the pointer indeterminate at the cleanup label). */
    nodus_dnac_committee_result_t *committee = NULL;   /* ~370 KB */
    dnac_chain_config_collected_vote_t *votes = NULL;  /* ~597 KB */

    /* 3. Committee query. S3: ~370 KB result (entries sized to the
     * release ceiling, nodus_types.h) — heap, never the stack. */
    committee = calloc(1, sizeof(*committee));
    if (!committee) {
        fprintf(stderr, "out of memory\n");
        goto done;
    }
    if (nodus_client_dnac_committee(&client, committee) != 0) {
        fprintf(stderr, "committee query failed\n");
        goto done;
    }
    if (committee->count < DNAC_CHAIN_CONFIG_MIN_SIGS) {
        fprintf(stderr, "Committee size %d < min_sigs %d — quorum impossible\n",
                committee->count, DNAC_CHAIN_CONFIG_MIN_SIGS);
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
    for (int i = 0; i < committee->count; i++) {
        uint8_t m_wid[32];
        if (nodus_chain_config_derive_witness_id(
                committee->entries[i].pubkey, m_wid) != 0) continue;
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
    uint64_t signed_at_block = committee->block_height;
    uint64_t valid_before = committee->block_height +
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

    /* 8. Collect votes. Self-vote first, then fan out via Stage E.2 helper.
     *
     * S3: sized to the release ceiling and HEAP-allocated — 128 collected
     * votes are ~597 KB. The static assert pins the committee-query wire
     * capacity to this buffer so the two can never drift apart again. */
    _Static_assert(sizeof(((nodus_dnac_committee_result_t *)0)->entries) /
                   sizeof(((nodus_dnac_committee_result_t *)0)->entries[0])
                   <= DNAC_MAX_ACTIVE_VALIDATORS,
                   "committee-query wire outgrew the local vote buffer");
    votes = calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*votes));
    if (!votes) {
        fprintf(stderr, "out of memory\n");
        goto done;
    }
    int vote_count = 0;

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

    for (int i = 0; i < committee->count; i++) {
        if (i == self_idx) continue;
        const nodus_dnac_committee_entry_t *peer = &committee->entries[i];
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
            if (vote_count >= DNAC_MAX_ACTIVE_VALIDATORS) { printf("DROP (full)\n"); continue; }
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

    /* v0.17.1: committed_fee MUST be set before compute_hash — preimage
     * includes it at offset 74 and witness Check 0 rejects committed_fee=0
     * for non-GENESIS TXs. Same value is passed to dnac_spend RPC below
     * so the witness sees matching wire fee + RPC fee. */
    tx->committed_fee = fee;

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
    free(committee);   /* S3: heap committee result (NULL-safe) */
    free(votes);       /* S3: heap vote buffer (NULL-safe) */
    nodus_client_close(&client);
    return rc;
}

/* ── Offline operator key loading (shared helper) ──────────────────
 *
 * Loads a CSV list of operator identity directories (--keys d1,d2,...)
 * so a verb can sign OFFLINE with keys it holds locally, instead of
 * needing a vote-collect RPC — the harness owns every node key, and the
 * witness verifies those signatures against the committee exactly as it
 * would networked ones. Used by `v2-envelope chain-config`, `v2-claim`
 * and `v2-envelope stake`.
 */
static int act_load_keys(const char *csv, nodus_identity_t *out, int cap) {
    int n = 0;
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", csv);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        if (n >= cap) return -1;
        if (nodus_identity_load(tok, &out[n]) != 0) {
            fprintf(stderr, "cannot load identity from %s\n", tok);
            return -1;
        }
        n++;
    }
    return n;
}

/* ── S3 — `stake` verb ─────────────────────────────────────────────
 *
 * Bonds THIS NODE's witness identity (-i dir) as a validator: builds a
 * DNAC_TX_STAKE whose signer is the node's Dilithium5 key, spending
 * UTXOs that already sit on the node identity's fingerprint (fund it
 * first, e.g. `dna send <node_fp> ...`). This is the ops/harness path
 * that lets a nodus-server join the validator set with the SAME key it
 * votes with — the wallet CLI's `dna stake` bonds the wallet identity,
 * which no server runs.
 *
 * --bond RAW (default exactly the DNA minimum) supports the S3 extra
 * self-bond rule: bond = Σin − Σchange − fee, witness requires
 * bond >= DNAC_SELF_STAKE_AMOUNT. unstake destination = this identity's
 * own fingerprint. */
static int cmd_stake(const char *server_ip, uint16_t server_port,
                     int argc, char **argv, int cmd_start) {
    uint64_t commission_bps = 500;
    uint64_t bond_raw = DNAC_SELF_STAKE_AMOUNT;

    for (int i = cmd_start + 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--commission") == 0 && i + 1 < argc) {
            commission_bps = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(a, "--bond") == 0 && i + 1 < argc) {
            bond_raw = strtoull(argv[++i], NULL, 10);
        } else {
            fprintf(stderr, "Unknown arg: %s\n"
                    "Usage: stake [--commission BPS] [--bond RAW>=%llu]\n",
                    a, (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
            return 1;
        }
    }
    if (commission_bps > 10000) {
        fprintf(stderr, "--commission must be 0..10000\n");
        return 1;
    }
    if (bond_raw < DNAC_SELF_STAKE_AMOUNT) {
        fprintf(stderr, "--bond %llu < minimum self-bond %llu\n",
                (unsigned long long)bond_raw,
                (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
        return 1;
    }

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

    /* Fee + chain_id. */
    nodus_dnac_fee_info_t fee_info;
    memset(&fee_info, 0, sizeof(fee_info));
    if (nodus_client_dnac_fee_info(&client, &fee_info) != 0) {
        fprintf(stderr, "fee info query failed\n");
        goto done;
    }
    uint64_t fee = fee_info.min_fee;

    nodus_dnac_supply_result_t supply;
    memset(&supply, 0, sizeof(supply));
    if (nodus_client_dnac_supply(&client, &supply) != 0) {
        fprintf(stderr, "supply query (for chain_id) failed\n");
        goto done;
    }

    /* UTXO selection: need bond + fee on the NODE identity's fp. */
    uint64_t need = bond_raw + fee;
    if (need < bond_raw) { fprintf(stderr, "overflow\n"); goto done; }

    if (nodus_client_dnac_utxo(&client, identity.fingerprint, 100,
                                 &utxos) != 0) {
        fprintf(stderr, "utxo query failed\n");
        goto done;
    }
    utxos_valid = true;
    if (utxos.count == 0) {
        fprintf(stderr, "No UTXOs on this node identity (%.16s…). Fund it "
                "first: dna send <node_fp> %llu ...\n",
                identity.fingerprint, (unsigned long long)need);
        goto done;
    }

    static const uint8_t stake_zero_token[DNAC_TOKEN_ID_SIZE] = {0};
    dnac_utxo_t selected[DNAC_MAX_UTXO_QUERY_RESULTS];
    int selected_count = 0;
    uint64_t total_input = 0;
    for (int i = 0; i < utxos.count && total_input < need; i++) {
        const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
        /* native DNAC only — same filter as the cc-propose verb above */
        if (memcmp(e->token_id, stake_zero_token, DNAC_TOKEN_ID_SIZE) != 0)
            continue;
        dnac_utxo_t *s = &selected[selected_count++];
        memset(s, 0, sizeof(*s));
        s->version = 1;
        memcpy(s->tx_hash, e->tx_hash, DNAC_TX_HASH_SIZE);
        s->output_index = e->output_index;
        s->amount       = e->amount;
        memcpy(s->nullifier, e->nullifier, DNAC_NULLIFIER_SIZE);
        snprintf(s->owner_fingerprint, sizeof(s->owner_fingerprint), "%s",
                 identity.fingerprint);
        total_input += e->amount;
    }
    if (total_input < need) {
        fprintf(stderr, "Insufficient native DNAC: have %llu raw, need %llu\n",
                (unsigned long long)total_input, (unsigned long long)need);
        goto done;
    }
    uint64_t change = total_input - need;

    /* Build the STAKE TX (mirrors dnac/src/transaction/stake.c). */
    tx = dnac_tx_create(DNAC_TX_STAKE);
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

    tx->stake_fields.commission_bps = (uint16_t)commission_bps;
    /* Unstake destination = this identity's own raw fingerprint
     * (SHA3-512 of the Dilithium5 pubkey — the same derivation the
     * hex identity.fingerprint encodes). */
    qgp_sha3_512(identity.pk.bytes, NODUS_PK_BYTES,
                 tx->stake_fields.unstake_destination_fp);

    memcpy(tx->chain_id, supply.chain_id, 32);
    tx->committed_fee = fee;

    memcpy(tx->signers[0].pubkey, identity.pk.bytes, DNAC_PUBKEY_SIZE);
    tx->signer_count = 1;

    if (dnac_tx_compute_hash(tx, tx->tx_hash) != DNAC_SUCCESS) {
        fprintf(stderr, "tx_compute_hash failed\n");
        goto done;
    }

    nodus_sig_t sender_sig;
    nodus_sign(&sender_sig, tx->tx_hash, DNAC_TX_HASH_SIZE, &identity.sk);
    memcpy(tx->signers[0].signature, sender_sig.bytes, DNAC_SIGNATURE_SIZE);

    static uint8_t stake_tx_bytes[DNAC_MAX_TX_SIZE];
    size_t tx_len = 0;
    if (dnac_tx_serialize(tx, stake_tx_bytes, sizeof(stake_tx_bytes),
                            &tx_len) != DNAC_SUCCESS) {
        fprintf(stderr, "tx_serialize failed\n");
        goto done;
    }

    nodus_pubkey_t sender_pk;
    memcpy(sender_pk.bytes, identity.pk.bytes, NODUS_PK_BYTES);

    nodus_dnac_spend_result_t spend_result;
    memset(&spend_result, 0, sizeof(spend_result));
    /* The RPC 'fee' parameter is the DECLARED input-output delta, not the
     * committed fee: the witness's Check 5 compares it against
     * Σin − Σout (nodus_witness_verify.c "fee mismatch"), and the wallet
     * declares exactly that (dnac/src/transaction/builder.c:352-355).
     * For STAKE the delta is bond + fee. */
    int srv_rc = nodus_client_dnac_spend(&client, tx->tx_hash, stake_tx_bytes,
                                           (uint32_t)tx_len, &sender_pk,
                                           &sender_sig, bond_raw + fee,
                                           &spend_result);
    if (srv_rc != 0) {
        fprintf(stderr, "dnac_spend RPC failed (rc=%d)\n", srv_rc);
        goto done;
    }

    printf("\nSTAKE submitted. hash=");
    for (int i = 0; i < 8; i++) printf("%02x", tx->tx_hash[i]);
    printf("... bond=%llu fee=%llu change=%llu commission=%llubps\n",
           (unsigned long long)bond_raw, (unsigned long long)fee,
           (unsigned long long)change, (unsigned long long)commission_bps);
    rc = 0;

done:
    if (tx) dnac_free_transaction(tx);
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    nodus_client_close(&client);
    return rc;
}

/* ── O15D — `v2-envelope chain-config` (successor rehearsal driver) ──
 *
 * Builds the ONE envelope shape a fresh successor can execute: a
 * single-leg SYSTEM CHAIN_CONFIG (fee 0 — a SYSTEM leg has no fee sink)
 * under auth_kind 2 (submitter + committee approvals by SEAT against the
 * committed snapshot). Approvals bind epoch(H−1) + the resolved-set
 * hash; with every rehearsal height inside the first successor epoch the
 * snapshot row is the seam-frozen e_start-0 set, so offline approvals
 * stay valid at whichever height the block lands. Expiry is 0 = none
 * (env_preflight.h step 3), so an interleaved block cannot strand it.
 *
 * The two-pass auth build: auth_len IS committed (auth_context_commit),
 * so the envelope is first encoded with a zero-filled auth blob of the
 * EXACT final length, preflighted to derive the leg auth digest, signed,
 * re-encoded with the real bytes (same length ⇒ same digest), and
 * re-preflighted as a self-check before submission.
 */
static int cmd_v2_envelope(const char *server_ip, uint16_t server_port,
                           int argc, char **argv, int cmd_start) {
    const char *sub = (cmd_start + 1 < argc) ? argv[cmd_start + 1] : NULL;
    const char *db_path = NULL, *keys_csv = NULL;
    uint64_t param_id = 4;              /* DNAC_CFG_TARGET_ACTIVE_COUNT  */
    uint64_t new_value = 7;             /* == compiled default: inert    */
    uint64_t effective = 0, valid_before = 0, nonce = 1;

    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--db")    && i + 1 < argc) db_path  = argv[++i];
        else if (!strcmp(a, "--keys")  && i + 1 < argc) keys_csv = argv[++i];
        else if (!strcmp(a, "--param") && i + 1 < argc)
            param_id = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--value") && i + 1 < argc)
            new_value = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--effective") && i + 1 < argc)
            effective = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--valid-before") && i + 1 < argc)
            valid_before = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--nonce") && i + 1 < argc)
            nonce = strtoull(argv[++i], NULL, 10);
        else { sub = NULL; break; }
    }
    if (!sub || strcmp(sub, "chain-config") != 0 || !db_path || !keys_csv) {
        fprintf(stderr,
            "Usage: v2-envelope chain-config --db <successor.db> "
            "--keys <dir1,...,dirN>\n"
            "       [--param ID --value V --effective H --valid-before H "
            "--nonce N]\n");
        return 1;
    }

    int rc = 1;
    nodus_witness_t *wr = NULL;
    nodus_identity_t *keys = NULL;
    int n_keys = 0;
    nodus_committee_member_t *committee = NULL;
    int cm_count = 0;
    uint8_t *fps = NULL;
    uint8_t *env_bytes = NULL;
    uint8_t *auth = NULL;
    dna_env_preflight_t *pf = NULL;

    keys = calloc(16, sizeof(*keys));
    if (!keys) return 1;
    n_keys = act_load_keys(keys_csv, keys, 16);
    if (n_keys < 1) goto done;

    /* Minimal READ-ONLY witness view over the committed successor DB —
     * enough for the production authorities used below (they read
     * w->db and the committee cache). The cache sentinel MUST be
     * poisoned: a zeroed epoch_start would false-hit for e_start 0. */
    wr = calloc(1, sizeof(*wr));
    if (!wr) goto done;
    wr->cached_committee_epoch_start = UINT64_MAX;
    wr->cached_committee_count = -1;
    if (sqlite3_open_v2(db_path, &wr->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK || !wr->db) {
        fprintf(stderr, "cannot open %s read-only\n", db_path);
        goto done;
    }

    uint8_t chain32[32];
    uint64_t tip = 0;
    if (nodus_witness_v2_chain_id(wr, chain32) != 0 ||
        nodus_witness_v2_tip_height(wr, &tip) != 0) {
        fprintf(stderr, "not a committed successor V2 database\n");
        goto done;
    }

    dna_domain_manifest_t sys_man;
    if (nodus_witness_domreg_get(wr, DNA_DOMAIN_SYSTEM, NULL, &sys_man,
                                 NULL) != 0) {
        fprintf(stderr, "SYSTEM registry row unreadable\n");
        goto done;
    }

    /* The governing committee for inclusion height H = tip+1 is resolved
     * at H−1 = tip (the engine's expression). */
    if (nodus_committee_get_for_block_alloc(wr, tip, &committee,
                                            &cm_count) != 0 ||
        cm_count < 1) {
        fprintf(stderr, "committee resolution failed\n");
        goto done;
    }
    uint64_t appr_epoch = nodus_v2_epoch_for_height(tip);
    uint32_t quorum = dna_bft_quorum((uint32_t)cm_count);
    if ((uint32_t)(n_keys - 0) < quorum) {
        fprintf(stderr, "need >= %u approver keys (committee %d), got %d\n",
                (unsigned)quorum, cm_count, n_keys);
        goto done;
    }

    uint8_t set_hash[64];
    fps = malloc((size_t)cm_count * 64);
    if (!fps) goto done;
    for (int i = 0; i < cm_count; i++)
        if (qgp_sha3_512(committee[i].pubkey, DNAC_PUBKEY_SIZE,
                         fps + (size_t)i * 64) != 0)
            goto done;
    if (nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                    (uint32_t)cm_count, set_hash) != 0)
        goto done;

    /* Defaults derived from the committed tip: SAFETY grace floor is
     * H + grace at the (unknown) inclusion height — parked far beyond
     * the rehearsal window; valid_before must exceed effective. */
    if (effective == 0)    effective    = tip + 100000;
    if (valid_before == 0) valid_before = effective + 100000;

    uint8_t call[41];
    call[0] = (uint8_t)param_id;
    for (int i = 0; i < 8; i++) call[1 + i]  = (uint8_t)(new_value    >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) call[9 + i]  = (uint8_t)(effective    >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) call[17 + i] = (uint8_t)(nonce        >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) call[25 + i] = (uint8_t)(1ULL         >> (56 - 8 * i)); /* signed_at = 1 */
    for (int i = 0; i < 8; i++) call[33 + i] = (uint8_t)(valid_before >> (56 - 8 * i));

    /* auth blob: submitter(1 signer) ‖ approval_count u16 ‖ q × (seat ‖ sig) */
    uint32_t n_appr = quorum;
    size_t auth_len = 1 + NODUS_RT_AUTH_SIGNER_LEN + 2 +
                      (size_t)n_appr * NODUS_RT_AUTH_APPROVAL_LEN;
    auth = calloc(1, auth_len);
    if (!auth) goto done;

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
    leg.hdr.ruleset_version      = sys_man.ruleset_version;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_CC_V1;
    leg.hdr.call_len             = sizeof(call);
    leg.hdr.auth_len             = (uint32_t)auth_len;
    leg.hdr.res_max_effects      = 4;
    leg.hdr.res_max_effect_bytes = 4096;
    leg.call_data = call;
    leg.auth_data = auth;                    /* pass 1: zero-filled     */

    dna_env_in_t env_in;
    memset(&env_in, 0, sizeof(env_in));
    env_in.expiry_height       = 0;          /* none — race-proof       */
    env_in.fee_amount          = 0;          /* SYSTEM leg rule         */
    env_in.res_max_total_units = 200000;
    env_in.leg_count           = 1;
    env_in.legs                = &leg;

    size_t env_len = 0;
    if (dna_env_encoded_size(&leg, 1, &env_len) != 0) goto done;
    env_bytes = malloc(env_len);
    pf = calloc(1, sizeof(*pf));
    if (!env_bytes || !pf) goto done;

    dna_env_leg_ctx_t lctx;
    lctx.domain_id       = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys_man.ruleset_version;
    memcpy(lctx.ruleset_hash, sys_man.ruleset_hash, 64);

    size_t used = 0;
    if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
        used != env_len) goto done;
    if (dna_env_preflight(env_bytes, env_len, chain32, tip + 1, &lctx, 1,
                          pf) != DNA_ENV_PF_OK) {
        fprintf(stderr, "pass-1 preflight failed\n");
        goto done;
    }

    /* Sign: submitter (keys[0]) over the leg auth digest; each approver
     * over its 154-byte DNA.CCAPPR.v1 digest, sorted by SEAT. */
    {
        uint8_t *p = auth;
        p[0] = 1;
        memcpy(p + 1, keys[0].pk.bytes, DNAC_PUBKEY_SIZE);
        size_t sl = 0;
        if (qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl,
                           pf->auth_digest[0], 64, keys[0].sk.bytes) != 0)
            goto done;
        p += 1 + NODUS_RT_AUTH_SIGNER_LEN;
        p[0] = (uint8_t)(n_appr >> 8);
        p[1] = (uint8_t)n_appr;
        p += 2;

        /* seat lookup per key, then emit in strictly ascending seats */
        int seat_of[16];
        for (int k = 0; k < (int)n_appr; k++) {
            seat_of[k] = -1;
            for (int s = 0; s < cm_count; s++) {
                if (memcmp(committee[s].pubkey, keys[k].pk.bytes,
                           DNAC_PUBKEY_SIZE) == 0) { seat_of[k] = s; break; }
            }
            if (seat_of[k] < 0) {
                fprintf(stderr, "key %d is not a committee member\n", k);
                goto done;
            }
        }
        /* simple selection sort of (seat, key) pairs */
        for (int a = 0; a < (int)n_appr; a++) {
            int best = a;
            for (int b = a + 1; b < (int)n_appr; b++)
                if (seat_of[b] < seat_of[best]) best = b;
            int ts = seat_of[a]; seat_of[a] = seat_of[best]; seat_of[best] = ts;
            nodus_identity_t tk = keys[a]; keys[a] = keys[best]; keys[best] = tk;
        }
        for (int k = 0; k < (int)n_appr; k++) {
            if (k > 0 && seat_of[k] == seat_of[k - 1]) {
                fprintf(stderr, "duplicate committee seat among keys\n");
                goto done;
            }
            uint8_t adg[64];
            if (nodus_rt_cc_approval_digest(pf->auth_digest[0], set_hash,
                                            appr_epoch,
                                            (uint16_t)seat_of[k],
                                            adg) != 0)
                goto done;
            p[0] = (uint8_t)((uint16_t)seat_of[k] >> 8);
            p[1] = (uint8_t)seat_of[k];
            sl = 0;
            if (qgp_dsa87_sign(p + 2, &sl, adg, 64, keys[k].sk.bytes) != 0)
                goto done;
            p += NODUS_RT_AUTH_APPROVAL_LEN;
        }
    }

    /* Pass 2: same lengths, real auth bytes — digest-stable by design. */
    if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
        used != env_len) goto done;
    if (dna_env_preflight(env_bytes, env_len, chain32, tip + 1, &lctx, 1,
                          pf) != DNA_ENV_PF_OK) {
        fprintf(stderr, "pass-2 preflight failed\n");
        goto done;
    }

    printf("envelope built: %zu bytes, wire_id=", env_len);
    for (int i = 0; i < 8; i++) printf("%02x", pf->wire_id[i]);
    printf("... intent_id=");
    for (int i = 0; i < 8; i++) printf("%02x", pf->intent_id[i]);
    printf("...\n");

    /* Submit through the ordinary tier-2 dnac_spend lane. */
    {
        nodus_client_t client;
        nodus_client_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s",
                 server_ip);
        cfg.servers[0].port = server_port;
        cfg.server_count    = 1;
        cfg.auto_reconnect  = false;
        if (nodus_client_init(&client, &cfg, &identity) != 0 ||
            nodus_client_connect(&client) != 0) {
            fprintf(stderr, "client connect failed\n");
            nodus_client_close(&client);
            goto done;
        }
        nodus_pubkey_t sender_pk;
        nodus_sig_t sender_sig;
        memcpy(sender_pk.bytes, identity.pk.bytes, NODUS_PK_BYTES);
        nodus_sign(&sender_sig, pf->wire_id, 64, &identity.sk);
        nodus_dnac_spend_result_t sres;
        memset(&sres, 0, sizeof(sres));
        int srv_rc = nodus_client_dnac_spend(&client, pf->wire_id,
                                             env_bytes, (uint32_t)env_len,
                                             &sender_pk, &sender_sig, 0,
                                             &sres);
        nodus_client_close(&client);
        if (srv_rc != 0 || sres.status != NODUS_DNAC_APPROVED) {
            fprintf(stderr, "dnac_spend RPC failed (rc=%d status=%d)\n",
                    srv_rc, (int)sres.status);
            goto done;
        }
        printf("ENVELOPE committed: height=%llu index=%u\n",
               (unsigned long long)sres.block_height, sres.tx_index);
    }
    rc = 0;

done:
    if (pf) free(pf);
    if (env_bytes) free(env_bytes);
    if (auth) free(auth);
    if (fps) free(fps);
    free(committee);
    if (wr) {
        if (wr->db) sqlite3_close(wr->db);
        free(wr);
    }
    if (keys) {
        for (int i = 0; i < 16; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* ── O15F Task 6 — submission-target parse + shared submit ──────────
 *
 * The O15D verbs submit to the outer -s server. T6's verbs additionally
 * accept `--submit ip:port` to name a target explicitly; when absent they
 * fall back to the outer -s server. This mirrors cmd_v2_envelope's
 * dnac_spend lane byte-for-byte (the classification into class 200 /
 * class 201 is SERVER-side: bytes beginning with the 16-byte envelope
 * family marker → 200, otherwise → 201, so a claim's canonical bytes —
 * which begin with claim_version u32 BE, never the marker — divert into
 * the claim lane without any wire flag). @return 0 / -1. */
static int t6_resolve_target(const char *submit, const char *def_ip,
                             uint16_t def_port, char ip_out[64],
                             uint16_t *port_out) {
    if (!submit) {
        if (!def_ip) return -1;
        snprintf(ip_out, 64, "%s", def_ip);
        *port_out = def_port;
        return 0;
    }
    const char *colon = strchr(submit, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - submit);
        if (hlen == 0 || hlen >= 64) return -1;
        memcpy(ip_out, submit, hlen);
        ip_out[hlen] = '\0';
        *port_out = (uint16_t)atoi(colon + 1);
        if (*port_out == 0) return -1;
    } else {
        snprintf(ip_out, 64, "%s", submit);
        *port_out = def_port;
    }
    return 0;
}

/* Submit one transaction (claim bytes OR envelope bytes) through the
 * ordinary tier-2 dnac_spend lane, signed at the transport layer by
 * `id`. `tx_hash` is the wire id the server keys the transaction by
 * (SHA3-512(claim bytes) for a claim; the envelope wire_id for a
 * stake). @return 0 committed / -1. */
static int t6_submit(const char *ip, uint16_t port, nodus_identity_t *id,
                     const uint8_t tx_hash[64], const uint8_t *bytes,
                     uint32_t len) {
    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", ip);
    cfg.servers[0].port = port;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;
    if (nodus_client_init(&client, &cfg, id) != 0 ||
        nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", ip, port);
        nodus_client_close(&client);
        return -1;
    }
    nodus_pubkey_t spk;
    nodus_sig_t ssig;
    memcpy(spk.bytes, id->pk.bytes, NODUS_PK_BYTES);
    nodus_sign(&ssig, tx_hash, 64, &id->sk);
    nodus_dnac_spend_result_t sres;
    memset(&sres, 0, sizeof(sres));
    int rc = nodus_client_dnac_spend(&client, tx_hash, bytes, len, &spk,
                                     &ssig, 0, &sres);
    nodus_client_close(&client);
    if (rc != 0 || sres.status != NODUS_DNAC_APPROVED) {
        fprintf(stderr, "dnac_spend RPC failed (rc=%d status=%d)\n",
                rc, (int)sres.status);
        return -1;
    }
    printf("committed: height=%llu index=%u\n",
           (unsigned long long)sres.block_height, sres.tx_index);
    return 0;
}

/* ── O15F Task 6 — `v2-claim` (successor GENESIS_CLAIM builder) ──────
 *
 * Re-derives the FULL distribution leaf set from the TERMINAL legacy
 * database with the SEAM'S EXACT query and leaf construction
 * (source_id = the 64-byte legacy nullifier, source_amount = amount,
 * dest_binding = owner fp → 64 raw bytes, version DNA_DIST_VERSION),
 * asserts the recomputed
 * dna_dist_snapshot_root EQUALS the successor manifest's committed
 * snapshot_root (proving leaf-set equivalence — a mismatch ABORTS and
 * never submits a bad proof), selects the caller's leaf(s) by
 * dest_binding == SHA3-512(pk), builds the Merkle proof, signs the claim
 * preimage (ML-DSA-87), emits canonical claim bytes and either self-checks
 * (--dry-run) or submits them (dnac_spend, class-201 server-side).
 *
 * Fail-closed leaf derivation (mirrors the seam): a malformed owner fp,
 * a mid-scan non-64-byte nullifier, a non-positive amount, or a
 * short/truncated scan ABORTS — a skipped row would shift every later
 * leaf_index and could never reproduce the committed root, but the abort
 * is explicit (the silent-substitution ban, root CLAUDE.md).
 */
static long claim_derive_legacy_leaves(sqlite3 *legacy,
                                       dna_dist_leaf_t **leaves_out) {
    *leaves_out = NULL;
    sqlite3_int64 n_utxo = 0;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(legacy,
                "SELECT COUNT(*) FROM utxo_set WHERE amount > 0",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_step(st) == SQLITE_ROW)
            n_utxo = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    if (n_utxo <= 0 || (uint64_t)n_utxo > DNA_DIST_MAX_LEAVES) return -1;

    dna_dist_leaf_t *leaves = calloc((size_t)n_utxo, sizeof(*leaves));
    if (!leaves) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(legacy,
            "SELECT nullifier, owner, amount FROM utxo_set "
            "WHERE amount > 0 ORDER BY nullifier ASC",
            -1, &st, NULL) != SQLITE_OK) {
        free(leaves);
        return -1;
    }
    size_t n = 0;
    int rc, bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= (size_t)n_utxo) { bad = 1; break; }
        const void *nul = sqlite3_column_blob(st, 0);
        const unsigned char *own = sqlite3_column_text(st, 1);
        sqlite3_int64 amt = sqlite3_column_int64(st, 2);
        if (!nul || sqlite3_column_bytes(st, 0) != 64 || !own || amt <= 0) {
            bad = 1; break;
        }
        dna_dist_leaf_t *L = &leaves[n];
        L->leaf_version  = DNA_DIST_VERSION;
        L->source_id_len = 64;
        memcpy(L->source_id, nul, 64);
        L->source_amount = (uint64_t)amt;
        /* seam_fp_to_binding: 128-char lowercase-hex owner → 64 raw. */
        if (qgp_fp_hex_to_raw((const char *)own, L->dest_binding) != 0) {
            bad = 1; break;
        }
        n++;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE || n == 0 || n != (size_t)n_utxo) {
        free(leaves);
        return -1;
    }
    *leaves_out = leaves;
    return (long)n;
}

static int cmd_v2_claim(const char *server_ip, uint16_t server_port,
                        int argc, char **argv, int cmd_start) {
    const char *legacy_db = NULL, *succ_db = NULL, *keys_csv = NULL;
    const char *submit = NULL;
    int dry_run = 0;

    for (int i = cmd_start + 1; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--legacy-db") && i + 1 < argc) legacy_db = argv[++i];
        else if (!strcmp(a, "--db")        && i + 1 < argc) succ_db   = argv[++i];
        else if (!strcmp(a, "--keys")      && i + 1 < argc) keys_csv  = argv[++i];
        else if (!strcmp(a, "--submit")    && i + 1 < argc) submit    = argv[++i];
        else if (!strcmp(a, "--dry-run"))                   dry_run   = 1;
        else { legacy_db = NULL; break; }
    }
    if (!legacy_db || !succ_db || !keys_csv || (!submit && !dry_run)) {
        fprintf(stderr,
            "Usage: v2-claim --legacy-db <terminal.db> --db <successor.db> "
            "--keys <keydir> (--dry-run | --submit ip:port)\n");
        return 1;
    }

    int rc = 1;
    nodus_witness_t *wr = NULL;
    nodus_identity_t *keys = NULL;
    int n_keys = 0;
    sqlite3 *legacy = NULL;
    dna_dist_leaf_t *leaves = NULL;
    uint8_t (*leaf_hashes)[64] = NULL;
    long n_leaves = 0;

    keys = calloc(4, sizeof(*keys));
    if (!keys) return 1;
    n_keys = act_load_keys(keys_csv, keys, 4);
    if (n_keys != 1) {
        fprintf(stderr, "v2-claim needs exactly one --keys identity\n");
        goto done;
    }

    /* Read-only successor view (cmd_v2_envelope pattern; poisoned cache). */
    wr = calloc(1, sizeof(*wr));
    if (!wr) goto done;
    wr->cached_committee_epoch_start = UINT64_MAX;
    wr->cached_committee_count = -1;
    if (sqlite3_open_v2(succ_db, &wr->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK || !wr->db) {
        fprintf(stderr, "cannot open %s read-only\n", succ_db);
        goto done;
    }

    uint8_t chain32[DNA_CHAIN_ID_LEN];
    uint64_t tip = 0;
    if (nodus_witness_v2_chain_id(wr, chain32) != 0 ||
        nodus_witness_v2_tip_height(wr, &tip) != 0) {
        fprintf(stderr, "not a committed successor V2 database\n");
        goto done;
    }

    /* The committed GENESIS manifest (locator 0 — nodus_witness_v2_apply.c
     * commits it at manifest_seq 0). Its snapshot_root is the equivalence
     * anchor and its distribution parameters drive the claim fields. */
    dna_gman_t m;
    if (nodus_witness_v2_manifest_load(wr, 0, &m) != 0) {
        fprintf(stderr, "successor genesis manifest unreadable\n");
        goto done;
    }
    if (!m.dist_present) {
        fprintf(stderr, "successor manifest carries no distribution\n");
        goto done;
    }
    uint8_t manifest_hash[64];
    if (dna_gman_hash(&m, manifest_hash) != 0) goto done;

    /* Re-derive the FULL leaf set from the terminal legacy DB. */
    if (sqlite3_open_v2(legacy_db, &legacy, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK || !legacy) {
        fprintf(stderr, "cannot open %s read-only\n", legacy_db);
        goto done;
    }
    n_leaves = claim_derive_legacy_leaves(legacy, &leaves);
    if (n_leaves < 1) {
        fprintf(stderr, "legacy leaf-set derivation failed (fail-closed)\n");
        goto done;
    }
    if ((uint64_t)n_leaves != m.leaf_count) {
        fprintf(stderr, "leaf count %ld != committed leaf_count %llu — "
                "ABORT (leaf-set mismatch)\n", n_leaves,
                (unsigned long long)m.leaf_count);
        goto done;
    }

    /* Equivalence assertion: the recomputed snapshot_root MUST equal the
     * committed one, else the leaves this build derived are not the leaves
     * the chain committed — refuse to submit a proof against a foreign
     * tree. */
    uint8_t snap_root[64];
    if (dna_dist_snapshot_root(leaves, (size_t)n_leaves, snap_root) != 0) {
        fprintf(stderr, "snapshot root recompute failed\n");
        goto done;
    }
    if (memcmp(snap_root, m.snapshot_root, 64) != 0) {
        fprintf(stderr, "recomputed snapshot_root != committed — ABORT "
                "(leaf-set not equivalent to the successor manifest)\n");
        goto done;
    }

    leaf_hashes = calloc((size_t)n_leaves, 64);
    if (!leaf_hashes) goto done;
    for (long i = 0; i < n_leaves; i++)
        if (dna_dist_leaf_hash(&leaves[i], leaf_hashes[i]) != 0) goto done;

    /* Caller binding = SHA3-512(pk). */
    uint8_t my_binding[64];
    if (qgp_sha3_512(keys[0].pk.bytes, DNAC_PUBKEY_SIZE, my_binding) != 0)
        goto done;

    /* Optional submission client (opened once, reused per matching leaf). */
    char sip[64];
    uint16_t sport = 0;
    if (!dry_run &&
        t6_resolve_target(submit, server_ip, server_port, sip, &sport) != 0) {
        fprintf(stderr, "invalid --submit target\n");
        goto done;
    }

    int matched = 0;
    for (long idx = 0; idx < n_leaves; idx++) {
        if (memcmp(leaves[idx].dest_binding, my_binding, 64) != 0) continue;
        matched++;

        dna_claim_t c;
        memset(&c, 0, sizeof(c));
        c.claim_version  = DNA_CLAIM_VERSION;
        memcpy(c.chain_id, chain32, DNA_CHAIN_ID_LEN);
        memcpy(c.manifest_hash, manifest_hash, 64);
        c.leaf_index     = (uint64_t)idx;
        c.source_id_len  = leaves[idx].source_id_len;
        memcpy(c.source_id, leaves[idx].source_id, leaves[idx].source_id_len);
        c.source_amount  = leaves[idx].source_amount;
        memcpy(c.dest_binding, leaves[idx].dest_binding, 64);
        c.auth_mode      = m.auth_mode;
        memcpy(c.pubkey, keys[0].pk.bytes, DNA_CLAIM_PUBKEY_LEN);
        if (dna_dist_proof_build((const uint8_t (*)[64])leaf_hashes,
                                 (size_t)n_leaves, (uint64_t)idx,
                                 c.siblings, &c.n_siblings) != 0) {
            fprintf(stderr, "proof build failed (leaf %ld)\n", idx);
            goto done;
        }

        /* Sign the tag-prefixed claim preimage (ML-DSA-87). */
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t pre_len = 0;
        if (dna_claim_preimage(&c, pre, &pre_len) != 0) goto done;
        size_t sl = 0;
        if (qgp_dsa87_sign(c.signature, &sl, pre, pre_len,
                           keys[0].sk.bytes) != 0 ||
            sl != DNA_CLAIM_SIG_LEN) {
            fprintf(stderr, "claim signature failed\n");
            goto done;
        }

        /* Canonical bytes + tx hash. */
        uint8_t bytes[DNA_CLAIM_MAX_WIRE];
        size_t blen = 0;
        if (dna_claim_encode(&c, bytes, sizeof(bytes), &blen) != 0) {
            fprintf(stderr, "claim encode failed\n");
            goto done;
        }
        uint8_t tx_hash[64];
        if (qgp_sha3_512(bytes, blen, tx_hash) != 0) goto done;

        uint8_t leafh[64], nul[64];
        if (dna_dist_leaf_hash(&leaves[idx], leafh) != 0 ||
            dna_claim_nullifier(chain32, manifest_hash, m.target_domain_id,
                                m.target_asset_ref, m.target_asset_len,
                                leafh, nul) != 0)
            goto done;

        if (dry_run) {
            printf("v2-claim leaf_index=%ld amount=%llu bytes=%zu\n",
                   idx, (unsigned long long)c.source_amount, blen);
            printf("  tx_hash=");
            for (int b = 0; b < 64; b++) printf("%02x", tx_hash[b]);
            printf("\n  nullifier=");
            for (int b = 0; b < 64; b++) printf("%02x", nul[b]);
            printf("\n");
            /* Local admission self-check through the REAL engine path. */
            nodus_v2_claim_admit_t adm;
            memset(&adm, 0, sizeof(adm));
            if (nodus_witness_v2_claim_admit(wr, &c, tip + 1, &adm) != 0) {
                fprintf(stderr, "  LOCAL ADMIT: REJECT (leaf %ld)\n", idx);
                goto done;
            }
            printf("  LOCAL ADMIT: OK (converted=%llu)\n",
                   (unsigned long long)adm.converted);
        } else {
            if (t6_submit(sip, sport, &keys[0], tx_hash, bytes,
                          (uint32_t)blen) != 0)
                goto done;
        }
    }
    if (!matched) {
        fprintf(stderr, "no distribution leaf binds this key\n");
        goto done;
    }
    rc = 0;

done:
    free(leaf_hashes);
    free(leaves);
    if (legacy) sqlite3_close(legacy);
    if (wr) {
        if (wr->db) sqlite3_close(wr->db);
        free(wr);
    }
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* ── O15F Task 6 — `v2-envelope stake` (O11 two-leg STAKE builder) ───
 *
 * Builds the canonical O11 staking envelope entirely from the committed
 * successor database and the operator key dir: leg0 = SYSTEM STAKE
 * (runtime_op 1, call = staker_pk[2592] ‖ commission u16 ‖ bond u64 ‖
 * dest_fp[64 RAW] = 2666, nodus_witness_rt_native.c:199-200), leg1 = CORE
 * SYSFUND (runtime_op 7, call = the SPEND transfer section funded from the
 * caller's successor utxo_set rows). Conservation Σin == Σchange + fee +
 * lock is enforced by the exec (the lock = bond derives from the SYSTEM
 * sibling); the CLI just supplies inputs summing to bond + fee + change.
 * fee = max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE). Each leg carries a
 * kind-1 single-signer auth blob (the staker) over the ENGINE-derived leg
 * auth_digest — the two-pass build cmd_v2_envelope uses (zero-fill →
 * preflight → sign → re-encode → re-preflight self-check).
 *
 * Reuses cmd_v2_envelope's registry-ruleset lookup, derived chain id,
 * dna_env_encode, dna_env_preflight self-check and the dnac_spend lane.
 */
/* SYSFUND / SPEND transfer-section wire widths (nodus_witness_rt_native.c:
 * RTN_SPEND_MAX_IN=15, RTN_SPEND_OUT_LEN=232 = fp128 + amount8 + token64 +
 * seed32; the codec lives behind libnodus so the widths are restated here
 * with their source citation, not #included). */
#define T6_SPEND_MAX_IN   15u
#define T6_SPEND_OUT_LEN  232u

static int cmd_v2_stake(const char *server_ip, uint16_t server_port,
                        int argc, char **argv, int cmd_start) {
    const char *db_path = NULL, *keys_csv = NULL, *dest_fp_hex = NULL;
    const char *submit = NULL;
    uint64_t bond = 0;
    uint32_t commission = 0;
    int dry_run = 0, have_bond = 0, have_comm = 0;

    for (int i = cmd_start + 2; i < argc; i++) {   /* skip the "stake" word */
        const char *a = argv[i];
        if      (!strcmp(a, "--db")         && i + 1 < argc) db_path = argv[++i];
        else if (!strcmp(a, "--keys")       && i + 1 < argc) keys_csv = argv[++i];
        else if (!strcmp(a, "--bond")       && i + 1 < argc) {
            bond = strtoull(argv[++i], NULL, 10); have_bond = 1;
        } else if (!strcmp(a, "--commission") && i + 1 < argc) {
            commission = (uint32_t)strtoul(argv[++i], NULL, 10); have_comm = 1;
        } else if (!strcmp(a, "--dest-fp")  && i + 1 < argc) dest_fp_hex = argv[++i];
        else if (!strcmp(a, "--submit")     && i + 1 < argc) submit = argv[++i];
        else if (!strcmp(a, "--dry-run"))                    dry_run = 1;
        else { db_path = NULL; break; }
    }
    if (!db_path || !keys_csv || !dest_fp_hex || !have_bond || !have_comm ||
        (!submit && !dry_run)) {
        fprintf(stderr,
            "Usage: v2-envelope stake --db <successor.db> --keys <keydir> "
            "--bond <raw> --commission <bps> --dest-fp <hex128> "
            "(--dry-run | --submit ip:port)\n");
        return 1;
    }
    if (commission > 0xFFFFu) {
        fprintf(stderr, "commission out of range\n");
        return 1;
    }
    uint8_t dest_fp[64];
    if (qgp_fp_hex_to_raw(dest_fp_hex, dest_fp) != 0) {
        fprintf(stderr, "--dest-fp must be exactly 128 lowercase hex chars\n");
        return 1;
    }

    int rc = 1;
    nodus_witness_t *wr = NULL;
    nodus_identity_t *keys = NULL;
    int n_keys = 0;
    uint8_t *auth0 = NULL, *auth1 = NULL, *env_bytes = NULL;
    dna_env_preflight_t *pf = NULL;
    uint8_t *scall = NULL, *fcall = NULL;

    keys = calloc(4, sizeof(*keys));
    if (!keys) return 1;
    n_keys = act_load_keys(keys_csv, keys, 4);
    if (n_keys != 1) {
        fprintf(stderr, "v2-envelope stake needs exactly one --keys identity\n");
        goto done;
    }

    wr = calloc(1, sizeof(*wr));
    if (!wr) goto done;
    wr->cached_committee_epoch_start = UINT64_MAX;
    wr->cached_committee_count = -1;
    if (sqlite3_open_v2(db_path, &wr->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK || !wr->db) {
        fprintf(stderr, "cannot open %s read-only\n", db_path);
        goto done;
    }

    uint8_t chain32[DNA_CHAIN_ID_LEN];
    uint64_t tip = 0;
    if (nodus_witness_v2_chain_id(wr, chain32) != 0 ||
        nodus_witness_v2_tip_height(wr, &tip) != 0) {
        fprintf(stderr, "not a committed successor V2 database\n");
        goto done;
    }

    dna_domain_manifest_t sys_man, core_man;
    if (nodus_witness_domreg_get(wr, DNA_DOMAIN_SYSTEM, NULL, &sys_man,
                                 NULL) != 0 ||
        nodus_witness_domreg_get(wr, DNA_DOMAIN_CORE, NULL, &core_man,
                                 NULL) != 0) {
        fprintf(stderr, "registry ruleset unreadable\n");
        goto done;
    }

    /* Staker fingerprint (128 lowercase hex) — the utxo_set owner form and
     * the change-output owner. */
    uint8_t staker_raw[64];
    char staker_fp[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(keys[0].pk.bytes, DNAC_PUBKEY_SIZE, staker_raw) != 0)
        goto done;
    qgp_fp_raw_to_hex(staker_raw, staker_fp);

    uint64_t fee = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                 ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
    uint64_t need = bond;
    if (need > UINT64_MAX - fee) { fprintf(stderr, "bond+fee overflow\n"); goto done; }
    need += fee;

    /* Select native, unlocked, CORE-domain funding inputs owned by the
     * staker, ascending by nullifier (canonical), until the sum covers
     * bond + fee. */
    uint8_t nulls[T6_SPEND_MAX_IN][64];
    int n_in = 0;
    uint64_t sum_in = 0;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(wr->db,
                "SELECT nullifier, amount, token_id, unlock_block "
                "FROM utxo_set WHERE owner = ?1 AND domain_id = ?2 "
                "ORDER BY nullifier ASC", -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_text(st, 1, staker_fp, 128, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, (int)DNA_DOMAIN_CORE);
        static const uint8_t native_tok[64] = {0};
        int step, scan_bad = 0;
        while ((step = sqlite3_step(st)) == SQLITE_ROW &&
               sum_in < need && n_in < (int)T6_SPEND_MAX_IN) {
            const void *nul = sqlite3_column_blob(st, 0);
            sqlite3_int64 amt = sqlite3_column_int64(st, 1);
            const void *tok = sqlite3_column_blob(st, 2);
            sqlite3_int64 unlock = sqlite3_column_int64(st, 3);
            if (!nul || sqlite3_column_bytes(st, 0) != 64 || amt <= 0 ||
                !tok || sqlite3_column_bytes(st, 2) != 64) {
                scan_bad = 1; break;
            }
            if (memcmp(tok, native_tok, 64) != 0) continue;   /* non-native */
            if ((uint64_t)unlock > tip) continue;             /* locked     */
            memcpy(nulls[n_in], nul, 64);
            if (sum_in > UINT64_MAX - (uint64_t)amt) { scan_bad = 1; break; }
            sum_in += (uint64_t)amt;
            n_in++;
        }
        sqlite3_finalize(st);
        if (scan_bad) { fprintf(stderr, "malformed funding row\n"); goto done; }
    }
    if (n_in < 1 || sum_in < need) {
        fprintf(stderr, "insufficient native funding: have %llu, need %llu "
                "(bond %llu + fee %llu) over %d input(s)\n",
                (unsigned long long)sum_in, (unsigned long long)need,
                (unsigned long long)bond, (unsigned long long)fee, n_in);
        goto done;
    }
    uint64_t change = sum_in - need;

    /* leg0 STAKE call (2666): staker_pk ‖ commission u16 ‖ bond u64 ‖
     * dest_fp[64 RAW]. */
    scall = calloc(1, 2666);
    if (!scall) goto done;
    memcpy(scall, keys[0].pk.bytes, DNAC_PUBKEY_SIZE);
    scall[2592] = (uint8_t)(commission >> 8);
    scall[2593] = (uint8_t)commission;
    for (int i = 0; i < 8; i++) scall[2594 + i] = (uint8_t)(bond >> (56 - 8 * i));
    memcpy(scall + 2602, dest_fp, 64);
    uint32_t scall_len = 2666;

    /* leg1 SYSFUND call = SPEND transfer section: in_count ‖ nullifiers
     * (ascending — the SELECT already returns them so) ‖ out_count ‖
     * change output (staker fp ‖ change ‖ native token ‖ seed). */
    size_t fcap = 2 + (size_t)T6_SPEND_MAX_IN * 64 + T6_SPEND_OUT_LEN;
    fcall = calloc(1, fcap);
    if (!fcall) goto done;
    size_t off = 0;
    fcall[off++] = (uint8_t)n_in;
    for (int i = 0; i < n_in; i++) { memcpy(fcall + off, nulls[i], 64); off += 64; }
    uint8_t out_count = change > 0 ? 1 : 0;
    fcall[off++] = out_count;
    if (out_count) {
        /* deterministic change seed = SHA3-512(input nullifiers)[0..31] —
         * unique per input set, so the derived output id never collides. */
        uint8_t seed_full[64];
        if (qgp_sha3_512((const uint8_t *)nulls, (size_t)n_in * 64,
                         seed_full) != 0) goto done;
        memcpy(fcall + off, staker_fp, 128);                 /* owner fp   */
        for (int i = 0; i < 8; i++)
            fcall[off + 128 + i] = (uint8_t)(change >> (56 - 8 * i));
        memset(fcall + off + 136, 0, 64);                    /* native tok */
        memcpy(fcall + off + 200, seed_full, 32);            /* seed       */
        off += T6_SPEND_OUT_LEN;
    }
    uint32_t fcall_len = (uint32_t)off;

    /* ── two-leg envelope, two-pass auth (cmd_v2_envelope pattern) ─── */
    uint32_t alen0 = 1u + 1u * NODUS_RT_AUTH_SIGNER_LEN;  /* kind-1, 1 sig */
    uint32_t alen1 = 1u + 1u * NODUS_RT_AUTH_SIGNER_LEN;
    auth0 = calloc(1, alen0);
    auth1 = calloc(1, alen1);
    pf    = calloc(1, sizeof(*pf));
    if (!auth0 || !auth1 || !pf) goto done;

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op           = DNA_SYSRULE_STAKE;
    legs[0].hdr.ruleset_version      = sys_man.ruleset_version;
    legs[0].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len             = scall_len;
    legs[0].hdr.auth_len             = alen0;
    legs[0].hdr.res_max_effects      = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = scall;
    legs[0].auth_data = auth0;
    legs[1].hdr.domain_id            = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op           = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version      = core_man.ruleset_version;
    legs[1].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len             = fcall_len;
    legs[1].hdr.auth_len             = alen1;
    legs[1].hdr.res_max_effects      = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = fcall;
    legs[1].auth_data = auth1;

    dna_env_in_t env_in;
    memset(&env_in, 0, sizeof(env_in));
    env_in.expiry_height       = 0;
    env_in.fee_amount          = fee;
    env_in.res_max_total_units = 400000;
    env_in.leg_count           = 2;
    env_in.legs                = legs;

    size_t env_len = 0;
    if (dna_env_encoded_size(legs, 2, &env_len) != 0) goto done;
    env_bytes = malloc(env_len);
    if (!env_bytes) goto done;

    dna_env_leg_ctx_t lctx[2];
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id       = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = sys_man.ruleset_version;
    memcpy(lctx[0].ruleset_hash, sys_man.ruleset_hash, 64);
    lctx[1].domain_id       = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = core_man.ruleset_version;
    memcpy(lctx[1].ruleset_hash, core_man.ruleset_hash, 64);

    size_t used = 0;
    if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
        used != env_len) goto done;
    if (dna_env_preflight(env_bytes, env_len, chain32, tip + 1, lctx, 2, pf)
        != DNA_ENV_PF_OK) {
        fprintf(stderr, "pass-1 preflight failed\n");
        goto done;
    }

    /* Sign each leg's auth_digest with the staker sk (kind-1: count=1 ‖
     * pubkey ‖ sig). One key covers BOTH legs: it is the STAKE identity
     * AND the owner of the funding inputs. */
    for (int L = 0; L < 2; L++) {
        uint8_t *ab = (L == 0) ? auth0 : auth1;
        ab[0] = 1;
        memcpy(ab + 1, keys[0].pk.bytes, DNAC_PUBKEY_SIZE);
        size_t sl = 0;
        if (qgp_dsa87_sign(ab + 1 + DNAC_PUBKEY_SIZE, &sl, pf->auth_digest[L],
                           64, keys[0].sk.bytes) != 0 ||
            sl != 4627) {
            fprintf(stderr, "leg %d signature failed\n", L);
            goto done;
        }
    }

    if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
        used != env_len) goto done;
    if (dna_env_preflight(env_bytes, env_len, chain32, tip + 1, lctx, 2, pf)
        != DNA_ENV_PF_OK) {
        fprintf(stderr, "pass-2 preflight (self-check) failed\n");
        goto done;
    }

    if (dry_run) {
        printf("v2-envelope stake: %zu bytes, inputs=%d sum_in=%llu "
               "bond=%llu fee=%llu change=%llu\n", env_len, n_in,
               (unsigned long long)sum_in, (unsigned long long)bond,
               (unsigned long long)fee, (unsigned long long)change);
        printf("  wire_id=");
        for (int b = 0; b < 64; b++) printf("%02x", pf->wire_id[b]);
        printf("\n  intent_id=");
        for (int b = 0; b < 64; b++) printf("%02x", pf->intent_id[b]);
        printf("\n  PREFLIGHT SELF-CHECK: OK (2 legs SYSTEM STAKE + CORE "
               "SYSFUND)\n");
    } else {
        char sip[64];
        uint16_t sport = 0;
        if (t6_resolve_target(submit, server_ip, server_port, sip,
                              &sport) != 0) {
            fprintf(stderr, "invalid --submit target\n");
            goto done;
        }
        if (t6_submit(sip, sport, &keys[0], pf->wire_id, env_bytes,
                      (uint32_t)env_len) != 0)
            goto done;
    }
    rc = 0;

done:
    free(scall);
    free(fcall);
    free(auth0);
    free(auth1);
    free(env_bytes);
    free(pf);
    if (wr) {
        if (wr->db) sqlite3_close(wr->db);
        free(wr);
    }
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
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
    fprintf(stderr, "  stake [--commission BPS] [--bond RAW]   Bond this node identity as validator (S3)\n");
    fprintf(stderr, "                              [--nonce <N>]  (committee operator only)\n");
    fprintf(stderr, "                  NAME: MAX_TXS_PER_BLOCK | BLOCK_INTERVAL_SEC |\n");
    fprintf(stderr, "                        INFLATION_START_BLOCK | TARGET_ACTIVE_COUNT\n");
    fprintf(stderr, "                  run without --value for per-param ranges\n");
    fprintf(stderr, "  v2-claim --legacy-db <t.db> --db <s.db> --keys <dir>\n");
    fprintf(stderr, "           (--dry-run | --submit ip:port)   Successor GENESIS_CLAIM\n");
    fprintf(stderr, "  v2-envelope stake --db <s.db> --keys <dir> --bond <raw>\n");
    fprintf(stderr, "           --commission <bps> --dest-fp <hex128>\n");
    fprintf(stderr, "           (--dry-run | --submit ip:port)   O11 two-leg STAKE\n");
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

    /* S3 — stake: bond THIS node identity as a validator. */
    if (strcmp(command, "stake") == 0) {
        int rc = cmd_stake(server_ip, server_port, argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* O15D — v2-envelope: successor-chain envelope builder/submitter.
     * O15F T6 adds the `stake` subcommand (O11 two-leg STAKE). */
    if (strcmp(command, "v2-envelope") == 0) {
        int rc;
        if (optind + 1 < argc && strcmp(argv[optind + 1], "stake") == 0)
            rc = cmd_v2_stake(server_ip, server_port, argc, argv, optind);
        else
            rc = cmd_v2_envelope(server_ip, server_port, argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* O15F T6 — v2-claim: successor GENESIS_CLAIM builder/submitter. */
    if (strcmp(command, "v2-claim") == 0) {
        int rc = cmd_v2_claim(server_ip, server_port, argc, argv, optind);
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
