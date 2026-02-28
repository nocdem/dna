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
#include "protocol/nodus_wire.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "core/nodus_value.h"

#include <stdlib.h>
#include <string.h>

/* ── Internal state ─────────────────────────────────────────────── */

/* Buffer for building protocol messages */
#define CLIENT_BUF_SIZE 32768
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
        client->config.request_timeout_ms = 10000;
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

    set_state(client, NODUS_CLIENT_CONNECTING);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(tcp, ep->ip, ep->port);
    if (!conn) { return -1; }
    client->conn = conn;

    /* Wait for TCP connection to establish */
    int elapsed = 0;
    while (conn->state == NODUS_CONN_CONNECTING &&
           elapsed < client->config.connect_timeout_ms) {
        nodus_tcp_poll(tcp, 50);
        elapsed += 50;
    }

    if (!client->conn || conn->state != NODUS_CONN_CONNECTED) {
        if (client->conn) {
            nodus_tcp_disconnect(tcp, conn);
            client->conn = NULL;
        }
        return -1;
    }

    /* Authenticate */
    set_state(client, NODUS_CLIENT_AUTHENTICATING);
    if (do_auth(client) != 0) {
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
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    if (!wait_response(client, client->config.connect_timeout_ms)) return -1;

    if (strcmp(resp->method, "challenge") != 0) return -1;

    /* Step 2: Sign nonce and send AUTH */
    nodus_sig_t sig;
    nodus_sign(&sig, resp->nonce, NODUS_NONCE_LEN, &client->identity.sk);

    len = 0;
    txn = client->next_txn++;
    nodus_t2_auth(txn, &sig, g_proto_buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, g_proto_buf, len) != 0) return -1;

    if (!wait_response(client, client->config.connect_timeout_ms)) return -1;

    if (strcmp(resp->method, "auth_ok") != 0) return -1;

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
