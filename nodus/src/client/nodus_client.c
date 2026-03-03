/**
 * Nodus v5 — Client SDK Implementation
 *
 * Provides connect/auth/DHT/channel operations with multi-server
 * failover and auto-reconnect (exponential backoff 1s-30s).
 *
 * @file nodus_client.c
 */

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "core/nodus_value.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "NODUS_CLIENT"

/* ── Internal state ─────────────────────────────────────────────── */

/* Buffer for building protocol messages */
#define CLIENT_BUF_SIZE (256 * 1024)   /* 256KB — enough for max Nodus value (1MB) + CBOR + sig */
static uint8_t g_proto_buf[CLIENT_BUF_SIZE];

/* ── Forward declarations ───────────────────────────────────────── */

static void client_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                             size_t len, void *ctx);
static void client_on_disconnect(nodus_tcp_conn_t *conn, void *ctx);
static void client_on_connect(nodus_tcp_conn_t *conn, void *ctx);
static void set_state(nodus_client_t *client, nodus_client_state_t new_state);
static int  do_connect_one(nodus_client_t *client, int server_idx);
static int  do_auth(nodus_client_t *client);
static bool wait_response(nodus_client_t *client, int timeout_ms);
static int  send_request(nodus_client_t *client, const uint8_t *payload, size_t len);
static int  resubscribe_all(nodus_client_t *client);
static int  try_reconnect(nodus_client_t *client);

/* ── Helpers ────────────────────────────────────────────────────── */

static uint64_t now_ms(void) {
    return nodus_time_now() * 1000ULL;
}

static void set_state(nodus_client_t *client, nodus_client_state_t new_state) {
    if (client->state == new_state) return;
    nodus_client_state_t old = client->state;
    client->state = new_state;
    if (client->config.on_state_change)
        client->config.on_state_change(old, new_state, client->config.callback_data);
}

static int send_request(nodus_client_t *client, const uint8_t *payload, size_t len) {
    nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)client->conn;
    if (!conn) return -1;
    return nodus_tcp_send(conn, payload, len);
}

static bool wait_response(nodus_client_t *client, int timeout_ms) {
    nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
    client->response_ready = false;
    int elapsed = 0;
    while (!client->response_ready && elapsed < timeout_ms) {
        nodus_tcp_poll(tcp, 50);
        if (!client->conn) return false;  /* Disconnected */
        elapsed += 50;
    }
    return client->response_ready;
}

/* ── TCP Callbacks ──────────────────────────────────────────────── */

static void client_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                             size_t len, void *ctx) {
    (void)conn;
    nodus_client_t *client = (nodus_client_t *)ctx;

    /* Decode into a temporary struct first to check if it's a push notification.
     * Push notifications must NOT clobber the pending_response — multiple frames
     * can arrive in a single TCP read, and a push following a synchronous response
     * would zero the response data before the caller reads it. */
    nodus_tier2_msg_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    if (nodus_t2_decode(payload, len, &tmp) != 0)
        return;

    /* Push notifications (async — not a response to a request) */
    if (strcmp(tmp.method, "value_changed") == 0) {
        if (client->config.on_value_changed && tmp.value)
            client->config.on_value_changed(&tmp.key, tmp.value,
                                             client->config.callback_data);
        nodus_t2_msg_free(&tmp);
        return;
    }

    if (strcmp(tmp.method, "ch_ntf") == 0) {
        if (client->config.on_ch_post) {
            /* ch_ntf encodes post fields individually in args, not as posts array.
             * Construct a temporary post from decoded fields. */
            nodus_channel_post_t post;
            memset(&post, 0, sizeof(post));
            memcpy(post.channel_uuid, tmp.channel_uuid, NODUS_UUID_BYTES);
            memcpy(post.post_uuid, tmp.post_uuid_ch, NODUS_UUID_BYTES);
            post.author_fp = tmp.fp;
            post.timestamp = tmp.ch_timestamp;
            post.seq_id = (uint32_t)tmp.seq;  /* "seq" in args → msg->seq */
            post.signature = tmp.sig;
            post.body = (char *)tmp.data;
            post.body_len = tmp.data_len;
            client->config.on_ch_post(tmp.channel_uuid, &post,
                                       client->config.callback_data);
        }
        nodus_t2_msg_free(&tmp);
        return;
    }

    /* Save raw payload for DNAC-specific CBOR decoding */
    free(client->raw_response);
    client->raw_response = malloc(len);
    if (client->raw_response) {
        memcpy(client->raw_response, payload, len);
        client->raw_response_len = len;
    } else {
        client->raw_response_len = 0;
    }

    /* Synchronous response — move into pending_response */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    nodus_t2_msg_free(resp);
    *resp = tmp;  /* Transfer ownership (shallow copy, no double-free) */
    client->response_ready = true;
}

static void client_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn;
    nodus_client_t *client = (nodus_client_t *)ctx;
    client->conn = NULL;

    if (client->state == NODUS_CLIENT_READY ||
        client->state == NODUS_CLIENT_AUTHENTICATING) {
        if (client->config.auto_reconnect) {
            set_state(client, NODUS_CLIENT_RECONNECTING);
            client->backoff_ms = client->config.reconnect_min_ms;
            client->reconnect_at = now_ms() + client->backoff_ms;
        } else {
            set_state(client, NODUS_CLIENT_DISCONNECTED);
        }
    }
}

static void client_on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
}

/* ── Lifecycle ──────────────────────────────────────────────────── */

int nodus_client_init(nodus_client_t *client,
                       const nodus_client_config_t *config,
                       const nodus_identity_t *identity) {
    if (!client || !config || !identity) return -1;
    if (config->server_count <= 0 || config->server_count > NODUS_CLIENT_MAX_SERVERS)
        return -1;

    memset(client, 0, sizeof(*client));
    client->config = *config;
    client->identity = *identity;
    client->state = NODUS_CLIENT_DISCONNECTED;
    client->next_txn = 1;
    client->server_idx = 0;

    /* Apply defaults */
    if (client->config.connect_timeout_ms <= 0)
        client->config.connect_timeout_ms = 5000;
    if (client->config.request_timeout_ms <= 0)
        client->config.request_timeout_ms = 30000;
    if (client->config.reconnect_min_ms <= 0)
        client->config.reconnect_min_ms = 1000;
    if (client->config.reconnect_max_ms <= 0)
        client->config.reconnect_max_ms = 30000;
    /* auto_reconnect defaults to false since memset zeroed it — caller must opt in */

    /* Allocate response structure */
    client->pending_response = calloc(1, sizeof(nodus_tier2_msg_t));
    if (!client->pending_response) return -1;

    /* Initialize TCP transport */
    nodus_tcp_t *tcp = calloc(1, sizeof(nodus_tcp_t));
    if (!tcp) {
        free(client->pending_response);
        client->pending_response = NULL;
        return -1;
    }
    nodus_tcp_init(tcp, -1);
    tcp->on_frame = client_on_frame;
    tcp->on_disconnect = client_on_disconnect;
    tcp->on_connect = client_on_connect;
    tcp->cb_ctx = client;
    client->tcp = tcp;

    return 0;
}

int nodus_client_connect(nodus_client_t *client) {
    if (!client || !client->tcp) return -1;

    /* Try each server in order */
    for (int i = 0; i < client->config.server_count; i++) {
        int idx = (client->server_idx + i) % client->config.server_count;
        if (do_connect_one(client, idx) == 0) {
            client->server_idx = idx;
            client->backoff_ms = client->config.reconnect_min_ms;
            return 0;
        }
    }

    set_state(client, NODUS_CLIENT_DISCONNECTED);
    return -1;
}

static int do_connect_one(nodus_client_t *client, int server_idx) {
    nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
    nodus_server_endpoint_t *ep = &client->config.servers[server_idx];

    QGP_LOG_INFO(LOG_TAG, "Connecting to %s:%d ...", ep->ip, ep->port);
    fprintf(stderr, "[NODUS_CLIENT] Connecting to %s:%d ...\n", ep->ip, ep->port);
    set_state(client, NODUS_CLIENT_CONNECTING);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(tcp, ep->ip, ep->port);
    if (!conn) {
        QGP_LOG_ERROR(LOG_TAG, "TCP connect failed to %s:%d (socket error)", ep->ip, ep->port);
        fprintf(stderr, "[NODUS_CLIENT] TCP connect failed to %s:%d (socket error)\n", ep->ip, ep->port);
        return -1;
    }
    client->conn = conn;

    /* Wait for TCP connection to establish.
     * Note: nodus_tcp_poll() may free conn via on_disconnect callback
     * (which sets client->conn = NULL), so check client->conn after
     * each poll iteration to avoid use-after-free on the local ptr. */
    int elapsed = 0;
    while (client->conn && conn->state == NODUS_CONN_CONNECTING &&
           elapsed < client->config.connect_timeout_ms) {
        nodus_tcp_poll(tcp, 50);
        elapsed += 50;
        conn = (nodus_tcp_conn_t *)client->conn;  /* re-read (may be NULL) */
        if (!conn) break;
    }

    if (!client->conn || conn == NULL || conn->state != NODUS_CONN_CONNECTED) {
        QGP_LOG_ERROR(LOG_TAG, "TCP connect to %s:%d failed after %dms (state=%d)",
                      ep->ip, ep->port, elapsed,
                      conn ? (int)conn->state : -1);
        fprintf(stderr, "[NODUS_CLIENT] TCP connect to %s:%d FAILED after %dms (state=%d)\n",
                ep->ip, ep->port, elapsed, conn ? (int)conn->state : -1);
        if (client->conn) {
            nodus_tcp_disconnect(tcp, (nodus_tcp_conn_t *)client->conn);
            client->conn = NULL;
        }
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "TCP connected to %s:%d, authenticating...", ep->ip, ep->port);
    fprintf(stderr, "[NODUS_CLIENT] TCP connected to %s:%d, authenticating...\n", ep->ip, ep->port);

    /* Authenticate */
    set_state(client, NODUS_CLIENT_AUTHENTICATING);
    if (do_auth(client) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth failed to %s:%d", ep->ip, ep->port);
        fprintf(stderr, "[NODUS_CLIENT] Auth FAILED to %s:%d\n", ep->ip, ep->port);
        if (client->conn) {
            nodus_tcp_disconnect(tcp, (nodus_tcp_conn_t *)client->conn);
            client->conn = NULL;
        }
        return -1;
    }

    set_state(client, NODUS_CLIENT_READY);

    /* Re-subscribe after reconnect */
    resubscribe_all(client);
    return 0;
}

static int do_auth(nodus_client_t *client) {
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;

    /* Step 1: HELLO */
    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_hello(txn, &client->identity.pk, &client->identity.node_id,
                    g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: HELLO send failed");
        fprintf(stderr, "[NODUS_CLIENT] Auth: HELLO send failed\n");
        return -1;
    }

    fprintf(stderr, "[NODUS_CLIENT] Auth: HELLO sent, waiting for challenge...\n");
    if (!wait_response(client, client->config.connect_timeout_ms)) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: no response to HELLO (timeout %dms)", client->config.connect_timeout_ms);
        fprintf(stderr, "[NODUS_CLIENT] Auth: no response to HELLO (timeout %dms)\n", client->config.connect_timeout_ms);
        return -1;
    }

    if (strcmp(resp->method, "challenge") != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: expected 'challenge', got '%s'", resp->method);
        fprintf(stderr, "[NODUS_CLIENT] Auth: expected 'challenge', got '%s'\n", resp->method);
        return -1;
    }

    /* Step 2: Sign nonce and send AUTH */
    nodus_sig_t sig;
    nodus_sign(&sig, resp->nonce, NODUS_NONCE_LEN, &client->identity.sk);

    len = 0;
    txn = client->next_txn++;
    nodus_t2_auth(txn, &sig, g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: AUTH send failed");
        fprintf(stderr, "[NODUS_CLIENT] Auth: AUTH send failed\n");
        return -1;
    }

    fprintf(stderr, "[NODUS_CLIENT] Auth: AUTH sent, waiting for auth_ok...\n");
    if (!wait_response(client, client->config.connect_timeout_ms)) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: no response to AUTH (timeout %dms)", client->config.connect_timeout_ms);
        fprintf(stderr, "[NODUS_CLIENT] Auth: no response to AUTH (timeout %dms)\n", client->config.connect_timeout_ms);
        return -1;
    }

    if (strcmp(resp->method, "auth_ok") != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: expected 'auth_ok', got '%s'", resp->method);
        fprintf(stderr, "[NODUS_CLIENT] Auth: expected 'auth_ok', got '%s'\n", resp->method);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Auth: success");
    memcpy(client->token, resp->token, NODUS_SESSION_TOKEN_LEN);
    return 0;
}

static int resubscribe_all(nodus_client_t *client) {
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    size_t len;
    uint32_t txn;

    /* Re-subscribe DHT listeners */
    for (int i = 0; i < client->listen_count; i++) {
        len = 0;
        txn = client->next_txn++;
        nodus_t2_listen(txn, client->token, &client->listen_keys[i],
                         g_proto_buf, CLIENT_BUF_SIZE, &len);
        send_request(client, g_proto_buf, len);
        wait_response(client, 2000);
        /* Best-effort — don't fail reconnect if a re-sub fails */
    }

    /* Re-subscribe channels */
    for (int i = 0; i < client->ch_sub_count; i++) {
        len = 0;
        txn = client->next_txn++;
        nodus_t2_ch_subscribe(txn, client->token, client->ch_subs[i],
                               g_proto_buf, CLIENT_BUF_SIZE, &len);
        send_request(client, g_proto_buf, len);
        wait_response(client, 2000);
    }

    (void)resp;
    return 0;
}

static int try_reconnect(nodus_client_t *client) {
    if (client->state != NODUS_CLIENT_RECONNECTING) return -1;
    if (now_ms() < client->reconnect_at) return -1;

    /* Try next server in rotation */
    int start_idx = (client->server_idx + 1) % client->config.server_count;
    for (int i = 0; i < client->config.server_count; i++) {
        int idx = (start_idx + i) % client->config.server_count;
        if (do_connect_one(client, idx) == 0) {
            client->server_idx = idx;
            client->backoff_ms = client->config.reconnect_min_ms;
            return 0;
        }
    }

    /* Exponential backoff */
    client->backoff_ms *= 2;
    if (client->backoff_ms > client->config.reconnect_max_ms)
        client->backoff_ms = client->config.reconnect_max_ms;
    client->reconnect_at = now_ms() + client->backoff_ms;
    set_state(client, NODUS_CLIENT_RECONNECTING);

    return -1;
}

int nodus_client_poll(nodus_client_t *client, int timeout_ms) {
    if (!client || !client->tcp) return -1;

    /* Handle reconnect */
    if (client->state == NODUS_CLIENT_RECONNECTING) {
        try_reconnect(client);
        if (client->state != NODUS_CLIENT_READY) {
            /* Still reconnecting — short sleep to avoid busy-wait */
            nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
            return nodus_tcp_poll(tcp, timeout_ms < 100 ? timeout_ms : 100);
        }
    }

    if (!client->conn) return 0;

    nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
    return nodus_tcp_poll(tcp, timeout_ms);
}

bool nodus_client_is_ready(const nodus_client_t *client) {
    return client && client->state == NODUS_CLIENT_READY;
}

nodus_client_state_t nodus_client_state(const nodus_client_t *client) {
    return client ? client->state : NODUS_CLIENT_DISCONNECTED;
}

void nodus_client_close(nodus_client_t *client) {
    if (!client) return;

    if (client->conn && client->tcp) {
        nodus_tcp_disconnect((nodus_tcp_t *)client->tcp,
                              (nodus_tcp_conn_t *)client->conn);
        client->conn = NULL;
    }

    if (client->tcp) {
        nodus_tcp_close((nodus_tcp_t *)client->tcp);
        free(client->tcp);
        client->tcp = NULL;
    }

    if (client->pending_response) {
        nodus_t2_msg_free((nodus_tier2_msg_t *)client->pending_response);
        free(client->pending_response);
        client->pending_response = NULL;
    }

    free(client->raw_response);
    client->raw_response = NULL;
    client->raw_response_len = 0;

    client->state = NODUS_CLIENT_DISCONNECTED;
    client->listen_count = 0;
    client->ch_sub_count = 0;
    nodus_identity_clear(&client->identity);
}

/* ── DHT Operations ─────────────────────────────────────────────── */

int nodus_client_put(nodus_client_t *client,
                      const nodus_key_t *key,
                      const uint8_t *data, size_t data_len,
                      nodus_value_type_t type, uint32_t ttl,
                      uint64_t vid, uint64_t seq,
                      const nodus_sig_t *sig) {
    if (!nodus_client_is_ready(client)) return -1;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_put(txn, client->token, key, data, data_len,
                  type, ttl, vid, seq, sig,
                  g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;
    return 0;
}

int nodus_client_get(nodus_client_t *client,
                      const nodus_key_t *key,
                      nodus_value_t **val_out) {
    if (!nodus_client_is_ready(client) || !val_out) return -1;
    *val_out = NULL;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_get(txn, client->token, key,
                  g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    if (resp->value) {
        /* Transfer ownership to caller */
        *val_out = resp->value;
        resp->value = NULL;
    } else {
        return NODUS_ERR_NOT_FOUND;
    }
    return 0;
}

int nodus_client_get_all(nodus_client_t *client,
                          const nodus_key_t *key,
                          nodus_value_t ***vals_out,
                          size_t *count_out) {
    if (!nodus_client_is_ready(client) || !vals_out || !count_out) return -1;
    *vals_out = NULL;
    *count_out = 0;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_get_all(txn, client->token, key,
                      g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    if (resp->values && resp->value_count > 0) {
        /* Transfer ownership */
        *vals_out = resp->values;
        *count_out = resp->value_count;
        resp->values = NULL;
        resp->value_count = 0;
    }
    return 0;
}

int nodus_client_listen(nodus_client_t *client, const nodus_key_t *key) {
    if (!nodus_client_is_ready(client) || !key) return -1;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_listen(txn, client->token, key,
                     g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    /* Track subscription for re-subscribe on reconnect */
    if (client->listen_count < NODUS_CLIENT_MAX_LISTENS) {
        /* Check for duplicate */
        bool found = false;
        for (int i = 0; i < client->listen_count; i++) {
            if (nodus_key_cmp(&client->listen_keys[i], key) == 0) {
                found = true;
                break;
            }
        }
        if (!found)
            client->listen_keys[client->listen_count++] = *key;
    }
    return 0;
}

int nodus_client_unlisten(nodus_client_t *client, const nodus_key_t *key) {
    if (!nodus_client_is_ready(client) || !key) return -1;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_unlisten(txn, client->token, key,
                       g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    /* Remove from tracking */
    for (int i = 0; i < client->listen_count; i++) {
        if (nodus_key_cmp(&client->listen_keys[i], key) == 0) {
            client->listen_keys[i] = client->listen_keys[--client->listen_count];
            break;
        }
    }
    return 0;
}

int nodus_client_get_servers(nodus_client_t *client,
                              nodus_server_endpoint_t *endpoints_out,
                              int max_count, int *count_out) {
    if (!nodus_client_is_ready(client) || !endpoints_out || !count_out) return -1;
    *count_out = 0;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_servers(txn, client->token,
                      g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    int n = resp->server_count < max_count ? resp->server_count : max_count;
    for (int i = 0; i < n; i++) {
        memset(&endpoints_out[i], 0, sizeof(endpoints_out[i]));
        strncpy(endpoints_out[i].ip, resp->servers[i].ip,
                sizeof(endpoints_out[i].ip) - 1);
        endpoints_out[i].port = resp->servers[i].tcp_port;
    }
    *count_out = n;
    return 0;
}

/* ── Channel Operations ─────────────────────────────────────────── */

int nodus_client_ch_create(nodus_client_t *client,
                            const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_ch_create(txn, client->token, uuid,
                        g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;
    return 0;
}

int nodus_client_ch_post(nodus_client_t *client,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          const uint8_t post_uuid[NODUS_UUID_BYTES],
                          const uint8_t *body, size_t body_len,
                          uint64_t timestamp, const nodus_sig_t *sig,
                          uint32_t *seq_out) {
    if (!nodus_client_is_ready(client) || !ch_uuid || !body) return -1;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_ch_post(txn, client->token, ch_uuid, post_uuid,
                      body, body_len, timestamp, sig,
                      g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    if (seq_out) *seq_out = resp->ch_seq_id;
    return 0;
}

int nodus_client_ch_get_posts(nodus_client_t *client,
                               const uint8_t uuid[NODUS_UUID_BYTES],
                               uint32_t since_seq, int max_count,
                               nodus_channel_post_t **posts_out,
                               size_t *count_out) {
    if (!nodus_client_is_ready(client) || !uuid || !posts_out || !count_out)
        return -1;
    *posts_out = NULL;
    *count_out = 0;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_ch_get_posts(txn, client->token, uuid, since_seq, max_count,
                           g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    if (resp->ch_posts && resp->ch_post_count > 0) {
        /* Transfer ownership */
        *posts_out = resp->ch_posts;
        *count_out = resp->ch_post_count;
        resp->ch_posts = NULL;
        resp->ch_post_count = 0;
    }
    return 0;
}

int nodus_client_ch_subscribe(nodus_client_t *client,
                               const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_ch_subscribe(txn, client->token, uuid,
                           g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    /* Track for re-subscribe on reconnect */
    if (client->ch_sub_count < NODUS_CLIENT_MAX_CH_SUBS) {
        bool found = false;
        for (int i = 0; i < client->ch_sub_count; i++) {
            if (memcmp(client->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            memcpy(client->ch_subs[client->ch_sub_count], uuid, NODUS_UUID_BYTES);
            client->ch_sub_count++;
        }
    }
    return 0;
}

int nodus_client_ch_unsubscribe(nodus_client_t *client,
                                 const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    size_t len = 0;
    uint32_t txn = client->next_txn++;
    nodus_t2_ch_unsubscribe(txn, client->token, uuid,
                              g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    /* Remove from tracking */
    for (int i = 0; i < client->ch_sub_count; i++) {
        if (memcmp(client->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
            memcpy(client->ch_subs[i], client->ch_subs[--client->ch_sub_count],
                   NODUS_UUID_BYTES);
            break;
        }
    }
    return 0;
}

/* ── Utility ────────────────────────────────────────────────────── */

const char *nodus_client_fingerprint(const nodus_client_t *client) {
    return client ? client->identity.fingerprint : NULL;
}

void nodus_client_free_posts(nodus_channel_post_t *posts, size_t count) {
    if (!posts) return;
    for (size_t i = 0; i < count; i++)
        free(posts[i].body);
    free(posts);
}

/* ── DNAC Operations ─────────────────────────────────────────────── */

/**
 * Helper: find the "r" response map in raw CBOR payload.
 * On success, decoder is positioned at first entry of "r" map.
 * Returns 0 on success, -1 if "r" not found or not a map.
 */
static int find_response_map(const uint8_t *raw, size_t raw_len,
                              cbor_decoder_t *dec, size_t *map_count) {
    cbor_decoder_init(dec, raw, raw_len);
    cbor_item_t top = cbor_decode_next(dec);
    if (top.type != CBOR_ITEM_MAP) return -1;

    for (size_t i = 0; i < top.count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type == CBOR_ITEM_TSTR &&
            key.tstr.len == 1 && key.tstr.ptr[0] == 'r') {
            cbor_item_t rmap = cbor_decode_next(dec);
            if (rmap.type != CBOR_ITEM_MAP) return -1;
            *map_count = rmap.count;
            return 0;
        }
        cbor_decode_skip(dec);
    }
    return -1;
}

/** Helper: encode DNAC query header + token + args map start */
static void enc_dnac_query(cbor_encoder_t *enc, uint32_t txn,
                            const uint8_t *token, const char *method,
                            size_t args_count) {
    cbor_encode_map(enc, 5);  /* t, y, q, tok, a */
    cbor_encode_cstr(enc, "t");   cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y");   cbor_encode_cstr(enc, "q");
    cbor_encode_cstr(enc, "q");   cbor_encode_cstr(enc, method);
    cbor_encode_cstr(enc, "tok"); cbor_encode_bstr(enc, token, NODUS_SESSION_TOKEN_LEN);
    cbor_encode_cstr(enc, "a");   cbor_encode_map(enc, args_count);
}

int nodus_client_dnac_spend(nodus_client_t *client,
                              const uint8_t *tx_hash,
                              const uint8_t *tx_data, uint32_t tx_len,
                              const nodus_pubkey_t *sender_pk,
                              const nodus_sig_t *sender_sig,
                              uint64_t fee,
                              nodus_dnac_spend_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !tx_hash || !tx_data ||
        !sender_pk || !sender_sig || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_spend", 5);

    cbor_encode_cstr(&enc, "tx");
    cbor_encode_bstr(&enc, tx_data, tx_len);
    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(&enc, "pk");
    cbor_encode_bstr(&enc, sender_pk->bytes, NODUS_PK_BYTES);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, sender_sig->bytes, NODUS_SIG_BYTES);
    cbor_encode_cstr(&enc, "fee");
    cbor_encode_uint(&enc, fee);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    /* BFT consensus can take up to 30s */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, 30000)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    /* Decode spend result from raw response */
    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "status", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->status = (nodus_dnac_status_t)v.uint_val;
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "wid", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(result_out->witness_id, v.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "wpk", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_PK_BYTES)
                memcpy(result_out->witness_pubkey, v.bstr.ptr, NODUS_PK_BYTES);
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->timestamp = v.uint_val;
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "wsig", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_SIG_BYTES)
                memcpy(result_out->signature, v.bstr.ptr, NODUS_SIG_BYTES);
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

int nodus_client_dnac_nullifier(nodus_client_t *client,
                                  const uint8_t *nullifier,
                                  nodus_dnac_nullifier_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !nullifier || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_nullifier", 1);

    cbor_encode_cstr(&enc, "nullifier");
    cbor_encode_bstr(&enc, nullifier, NODUS_T3_NULLIFIER_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms))
        return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "spent", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL)
                result_out->is_spent = v.bool_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

int nodus_client_dnac_ledger(nodus_client_t *client,
                               const uint8_t *tx_hash,
                               nodus_dnac_ledger_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !tx_hash || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_ledger", 1);

    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms))
        return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "found", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL)
                result_out->found = v.bool_val;
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "seq", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->sequence = v.uint_val;
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "hash", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->tx_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "type", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_type = (uint8_t)v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "epoch", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->epoch = v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->timestamp = v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "nc", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->nullifier_count = v.uint_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

int nodus_client_dnac_supply(nodus_client_t *client,
                               nodus_dnac_supply_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_supply", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms))
        return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "genesis", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->genesis_supply = v.uint_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "burned", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->total_burned = v.uint_val;
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "current", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->current_supply = v.uint_val;
        } else if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "last_seq", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->last_sequence = v.uint_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

int nodus_client_dnac_utxo(nodus_client_t *client,
                             const char *owner,
                             int max_results,
                             nodus_dnac_utxo_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !owner || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));
    if (max_results <= 0) max_results = NODUS_DNAC_MAX_UTXO_RESULTS;
    if (max_results > NODUS_DNAC_MAX_UTXO_RESULTS)
        max_results = NODUS_DNAC_MAX_UTXO_RESULTS;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_utxo", 2);

    cbor_encode_cstr(&enc, "owner");
    cbor_encode_cstr(&enc, owner);
    cbor_encode_cstr(&enc, "max");
    cbor_encode_uint(&enc, (uint64_t)max_results);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms))
        return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    int count = 0;
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                count = (int)v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "utxos", 5) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            if (arr.count > 0) {
                result_out->entries = calloc(arr.count,
                                              sizeof(nodus_dnac_utxo_entry_t));
                if (!result_out->entries) return NODUS_ERR_INTERNAL_ERROR;
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;

                nodus_dnac_utxo_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }

                    if (ek.tstr.len == 1 && ek.tstr.ptr[0] == 'n') {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_NULLIFIER_LEN)
                            memcpy(e->nullifier, v.bstr.ptr,
                                   NODUS_T3_NULLIFIER_LEN);
                    } else if (ek.tstr.len == 5 &&
                               memcmp(ek.tstr.ptr, "owner", 5) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_TSTR) {
                            size_t cl = v.tstr.len < sizeof(e->owner) - 1 ?
                                        v.tstr.len : sizeof(e->owner) - 1;
                            memcpy(e->owner, v.tstr.ptr, cl);
                            e->owner[cl] = '\0';
                        }
                    } else if (ek.tstr.len == 6 &&
                               memcmp(ek.tstr.ptr, "amount", 6) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->amount = v.uint_val;
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "hash", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_TX_HASH_LEN)
                            memcpy(e->tx_hash, v.bstr.ptr,
                                   NODUS_T3_TX_HASH_LEN);
                    } else if (ek.tstr.len == 3 &&
                               memcmp(ek.tstr.ptr, "idx", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->output_index = (uint32_t)v.uint_val;
                    } else if (ek.tstr.len == 2 &&
                               memcmp(ek.tstr.ptr, "bh", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->block_height = v.uint_val;
                    } else {
                        cbor_decode_skip(&dec);
                    }
                }
                result_out->count++;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    (void)count;  /* Server count for cross-check, not used */
    return 0;
}

int nodus_client_dnac_ledger_range(nodus_client_t *client,
                                     uint64_t from_seq, uint64_t to_seq,
                                     nodus_dnac_range_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_ledger_range", 2);

    cbor_encode_cstr(&enc, "from");
    cbor_encode_uint(&enc, from_seq);
    cbor_encode_cstr(&enc, "to");
    cbor_encode_uint(&enc, to_seq);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms))
        return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "total", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->total_entries = v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->count = (int)v.uint_val;
        } else if (key.tstr.len == 7 &&
                   memcmp(key.tstr.ptr, "entries", 7) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            if (arr.count > 0) {
                result_out->entries = calloc(arr.count,
                                              sizeof(nodus_dnac_range_entry_t));
                if (!result_out->entries) return NODUS_ERR_INTERNAL_ERROR;
                result_out->count = 0;
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;

                nodus_dnac_range_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }

                    if (ek.tstr.len == 3 &&
                        memcmp(ek.tstr.ptr, "seq", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->sequence = v.uint_val;
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "hash", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_TX_HASH_LEN)
                            memcpy(e->tx_hash, v.bstr.ptr,
                                   NODUS_T3_TX_HASH_LEN);
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "type", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->tx_type = (uint8_t)v.uint_val;
                    } else if (ek.tstr.len == 5 &&
                               memcmp(ek.tstr.ptr, "epoch", 5) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->epoch = v.uint_val;
                    } else if (ek.tstr.len == 2 &&
                               memcmp(ek.tstr.ptr, "ts", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->timestamp = v.uint_val;
                    } else if (ek.tstr.len == 2 &&
                               memcmp(ek.tstr.ptr, "nc", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->nullifier_count = v.uint_val;
                    } else {
                        cbor_decode_skip(&dec);
                    }
                }
                result_out->count++;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

int nodus_client_dnac_roster(nodus_client_t *client,
                               nodus_dnac_roster_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_roster", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, client->config.request_timeout_ms))
        return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "version", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->version = (uint32_t)v.uint_val;
        } else if (key.tstr.len == 5 &&
                   memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->count = (int)v.uint_val;
        } else if (key.tstr.len == 9 &&
                   memcmp(key.tstr.ptr, "witnesses", 9) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            result_out->count = 0;
            for (size_t j = 0;
                 j < arr.count && result_out->count < NODUS_T3_MAX_WITNESSES;
                 j++) {
                cbor_item_t wmap = cbor_decode_next(&dec);
                if (wmap.type != CBOR_ITEM_MAP) continue;

                nodus_dnac_roster_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));

                for (size_t k = 0; k < wmap.count; k++) {
                    cbor_item_t wk = cbor_decode_next(&dec);
                    if (wk.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }

                    if (wk.tstr.len == 3 &&
                        memcmp(wk.tstr.ptr, "wid", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                            memcpy(e->witness_id, v.bstr.ptr,
                                   NODUS_T3_WITNESS_ID_LEN);
                    } else if (wk.tstr.len == 2 &&
                               memcmp(wk.tstr.ptr, "pk", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_PK_BYTES)
                            memcpy(e->pubkey, v.bstr.ptr, NODUS_PK_BYTES);
                    } else if (wk.tstr.len == 4 &&
                               memcmp(wk.tstr.ptr, "addr", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_TSTR) {
                            size_t cl = v.tstr.len < sizeof(e->address) - 1 ?
                                        v.tstr.len : sizeof(e->address) - 1;
                            memcpy(e->address, v.tstr.ptr, cl);
                            e->address[cl] = '\0';
                        }
                    } else if (wk.tstr.len == 6 &&
                               memcmp(wk.tstr.ptr, "active", 6) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BOOL)
                            e->active = v.bool_val;
                    } else {
                        cbor_decode_skip(&dec);
                    }
                }
                result_out->count++;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

void nodus_client_free_utxo_result(nodus_dnac_utxo_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->count = 0;
}

void nodus_client_free_range_result(nodus_dnac_range_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->count = 0;
}

/* ── TX Query (v0.10.0 hub/spoke) ───────────────────────────────── */

int nodus_client_dnac_tx(nodus_client_t *client,
                           const uint8_t *tx_hash,
                           nodus_dnac_tx_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !tx_hash || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_tx", 1);

    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, 10000)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "found", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL)
                result_out->found = v.bool_val;
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "hash", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->tx_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "type", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_type = (uint8_t)v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "tx", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len > 0) {
                result_out->tx_data = malloc(v.bstr.len);
                if (result_out->tx_data) {
                    memcpy(result_out->tx_data, v.bstr.ptr, v.bstr.len);
                    result_out->tx_len = (uint32_t)v.bstr.len;
                }
            }
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "len", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            /* tx_len already set from blob, this is informational */
            (void)v;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "bh", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->block_height = v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->timestamp = v.uint_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

void nodus_client_free_tx_result(nodus_dnac_tx_result_t *result) {
    if (!result) return;
    free(result->tx_data);
    result->tx_data = NULL;
    result->tx_len = 0;
}

/* ── Block Query (v0.10.0 hub/spoke) ────────────────────────────── */

int nodus_client_dnac_block(nodus_client_t *client,
                              uint64_t height,
                              nodus_dnac_block_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_block", 1);

    cbor_encode_cstr(&enc, "height");
    cbor_encode_uint(&enc, height);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, 10000)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "found", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL)
                result_out->found = v.bool_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "height", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->height = v.uint_val;
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "hash", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->tx_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "type", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_type = (uint8_t)v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->timestamp = v.uint_val;
        } else if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "proposer", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(result_out->proposer_id, v.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

/* ── Block Range Query (v0.10.0 hub/spoke) ──────────────────────── */

int nodus_client_dnac_block_range(nodus_client_t *client,
                                    uint64_t from_height, uint64_t to_height,
                                    nodus_dnac_block_range_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_proto_buf, CLIENT_BUF_SIZE);
    uint32_t txn = client->next_txn++;
    enc_dnac_query(&enc, txn, client->token, "dnac_block_range", 2);

    cbor_encode_cstr(&enc, "from");
    cbor_encode_uint(&enc, from_height);
    cbor_encode_cstr(&enc, "to");
    cbor_encode_uint(&enc, to_height);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -1;
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)client->pending_response;
    if (!wait_response(client, 10000)) return NODUS_ERR_TIMEOUT;
    if (resp->type == 'e') return resp->error_code;

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(client->raw_response, client->raw_response_len,
                           &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "total", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->total_blocks = v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->count = (int)v.uint_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "blocks", 6) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            if (arr.count > 0) {
                result_out->blocks = calloc(arr.count,
                                              sizeof(nodus_dnac_block_result_t));
                if (!result_out->blocks) continue;
            }

            result_out->count = 0;
            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) {
                    cbor_decode_skip(&dec);
                    continue;
                }

                nodus_dnac_block_result_t *b =
                    &result_out->blocks[result_out->count];
                b->found = true;

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec);
                        continue;
                    }

                    if (ek.tstr.len == 6 && memcmp(ek.tstr.ptr, "height", 6) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) b->height = v.uint_val;
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "hash", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                            memcpy(b->tx_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "type", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) b->tx_type = (uint8_t)v.uint_val;
                    } else if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "ts", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) b->timestamp = v.uint_val;
                    } else if (ek.tstr.len == 8 && memcmp(ek.tstr.ptr, "proposer", 8) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                            memcpy(b->proposer_id, v.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
                    } else {
                        cbor_decode_skip(&dec);
                    }
                }
                result_out->count++;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    return 0;
}

void nodus_client_free_block_range_result(nodus_dnac_block_range_result_t *result) {
    if (!result) return;
    free(result->blocks);
    result->blocks = NULL;
    result->count = 0;
}
