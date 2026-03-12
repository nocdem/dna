/**
 * Nodus — Client SDK Implementation
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
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <unistd.h>
  #include <sys/socket.h>
#endif

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "NODUS_CLIENT"

/* ── Internal state ─────────────────────────────────────────────── */

/* Buffer sizes for building protocol messages.
 * CLIENT_BUF_SIZE: used for most operations (auth, get, listen, etc.)
 * CLIENT_BUF_SIZE_PUT: used for PUT — must accommodate max value (1MB) + sig + CBOR.
 * Previous 256KB CLIENT_BUF_SIZE was too small for PUT with >245KB data. */
#define CLIENT_BUF_SIZE       (256 * 1024)
#define CLIENT_BUF_SIZE_PUT   (NODUS_MAX_VALUE_SIZE + 65536)

/* ── Forward declarations ───────────────────────────────────────── */

static void client_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                             size_t len, void *ctx);
static void client_on_disconnect(nodus_tcp_conn_t *conn, void *ctx);
static void client_on_connect(nodus_tcp_conn_t *conn, void *ctx);
static uint64_t now_ms(void);
static nodus_pending_t *alloc_pending(nodus_client_t *client, uint32_t txn);
static void free_pending(nodus_client_t *client, nodus_pending_t *p);
static int send_request(nodus_client_t *client, const uint8_t *buf, size_t len);
static void set_state(nodus_client_t *client, nodus_client_state_t new_state);
static int  do_connect_one(nodus_client_t *client, int server_idx);
static int  do_auth(nodus_client_t *client);
static bool wait_response(nodus_client_t *client, nodus_pending_t *req, int timeout_ms);
static int  send_request(nodus_client_t *client, const uint8_t *payload, size_t len);
static int  resubscribe_all(nodus_client_t *client);
static int  try_reconnect(nodus_client_t *client);

/* ── Cross-platform millisecond sleep ──────────────────────────── */

static void sleep_ms(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

/* ── Internal read thread ──────────────────────────────────────── */

static void *read_thread_fn(void *arg) {
    nodus_client_t *client = (nodus_client_t *)arg;
    QGP_LOG_INFO(LOG_TAG, "Read thread started");

    while (!atomic_load(&client->read_thread_stop)) {
        pthread_mutex_lock(&client->poll_mutex);

        /* Handle reconnect */
        if (client->state == NODUS_CLIENT_RECONNECTING) {
            try_reconnect(client);
            if (client->state != NODUS_CLIENT_READY && client->tcp) {
                nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
                nodus_tcp_poll(tcp, 100);
            }
            pthread_mutex_unlock(&client->poll_mutex);
            continue;
        }

        if (!client->conn || !client->tcp) {
            pthread_mutex_unlock(&client->poll_mutex);
            sleep_ms(100);
            continue;
        }

        nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
        int rc = nodus_tcp_poll(tcp, 100);

        pthread_mutex_unlock(&client->poll_mutex);

        if (rc < 0 && atomic_load(&client->read_thread_stop))
            break;
        if (client->state == NODUS_CLIENT_DISCONNECTED)
            sleep_ms(100);
    }

    QGP_LOG_INFO(LOG_TAG, "Read thread stopped");
    return NULL;
}

static void start_read_thread(nodus_client_t *client) {
    if (atomic_load(&client->read_thread_running)) return;
    atomic_store(&client->read_thread_stop, false);
    if (pthread_create(&client->read_thread, NULL, read_thread_fn, client) == 0) {
        atomic_store(&client->read_thread_running, true);
        QGP_LOG_INFO(LOG_TAG, "Read thread launched");
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create read thread");
    }
}

static void stop_read_thread(nodus_client_t *client) {
    if (!atomic_load(&client->read_thread_running)) return;
    atomic_store(&client->read_thread_stop, true);
    pthread_join(client->read_thread, NULL);
    atomic_store(&client->read_thread_running, false);
    QGP_LOG_INFO(LOG_TAG, "Read thread joined");
}

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
    pthread_mutex_lock(&client->send_mutex);
    int rc = nodus_tcp_send(conn, payload, len);
    pthread_mutex_unlock(&client->send_mutex);
    return rc;
}

/* ── Pending slot management ───────────────────────────────────── */

static nodus_pending_t *alloc_pending(nodus_client_t *client, uint32_t txn) {
    /* Retry with exponential backoff if all slots are busy (startup burst) */
    const int max_retries = 5;
    int backoff_ms = 10;

    for (int attempt = 0; attempt <= max_retries; attempt++) {
        pthread_mutex_lock(&client->pending_mutex);
        for (int i = 0; i < NODUS_MAX_PENDING; i++) {
            if (!client->pending[i].in_use) {
                nodus_pending_t *p = &client->pending[i];
                memset(p, 0, sizeof(*p));
                p->txn = txn;
                p->response = calloc(1, sizeof(nodus_tier2_msg_t));
                p->in_use = true;
                pthread_mutex_unlock(&client->pending_mutex);
                if (attempt > 0) {
                    QGP_LOG_DEBUG(LOG_TAG, "Pending slot acquired after %d retries", attempt);
                }
                return p;
            }
        }
        pthread_mutex_unlock(&client->pending_mutex);

        if (attempt < max_retries) {
            QGP_LOG_WARN(LOG_TAG, "All %d pending slots busy, retry %d/%d in %dms",
                         NODUS_MAX_PENDING, attempt + 1, max_retries, backoff_ms);
            struct timespec ts = { .tv_sec = 0, .tv_nsec = backoff_ms * 1000000L };
            nanosleep(&ts, NULL);
            backoff_ms *= 2;  /* 10, 20, 40, 80, 160ms */
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "No pending slots available (max %d) after %d retries",
                  NODUS_MAX_PENDING, max_retries);
    return NULL;
}

static void free_pending(nodus_client_t *client, nodus_pending_t *p) {
    if (!p) return;
    pthread_mutex_lock(&client->pending_mutex);
    if (p->response) {
        nodus_t2_msg_free((nodus_tier2_msg_t *)p->response);
        free(p->response);
    }
    free(p->raw_response);
    p->in_use = false;
    pthread_mutex_unlock(&client->pending_mutex);
}

static bool wait_response(nodus_client_t *client, nodus_pending_t *req, int timeout_ms) {
    int elapsed = 0;

    while (!atomic_load(&req->ready) && elapsed < timeout_ms) {
        if (!client->conn && client->state != NODUS_CLIENT_RECONNECTING)
            return false;

        if (atomic_load(&client->read_thread_running) &&
            !pthread_equal(pthread_self(), client->read_thread)) {
            /* Read thread handles TCP — just wait for ready flag */
            sleep_ms(10);
            elapsed += 10;
        } else {
            /* We ARE the read thread (reconnect path), or no thread — poll directly */
            nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
            if (tcp) nodus_tcp_poll(tcp, 50);
            elapsed += 50;
        }
    }
    return atomic_load(&req->ready);
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

    /* Find pending slot by txn ID */
    pthread_mutex_lock(&client->pending_mutex);
    nodus_pending_t *slot = NULL;
    for (int i = 0; i < NODUS_MAX_PENDING; i++) {
        if (client->pending[i].in_use && client->pending[i].txn == tmp.txn_id) {
            slot = &client->pending[i];
            break;
        }
    }
    if (!slot) {
        pthread_mutex_unlock(&client->pending_mutex);
        QGP_LOG_WARN(LOG_TAG, "Response for unknown txn %u (no pending slot)", tmp.txn_id);
        nodus_t2_msg_free(&tmp);
        return;
    }

    /* Save raw payload for DNAC-specific CBOR decoding */
    free(slot->raw_response);
    slot->raw_response = malloc(len);
    if (slot->raw_response) {
        memcpy(slot->raw_response, payload, len);
        slot->raw_response_len = len;
    } else {
        slot->raw_response_len = 0;
    }

    /* Move decoded response into slot */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)slot->response;
    nodus_t2_msg_free(resp);
    *resp = tmp;  /* Transfer ownership (shallow copy, no double-free) */
    slot->ready = true;
    pthread_mutex_unlock(&client->pending_mutex);
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
    atomic_store(&client->next_txn, 1);
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

    /* Initialize concurrency primitives */
    pthread_mutex_init(&client->pending_mutex, NULL);
    pthread_mutex_init(&client->send_mutex, NULL);
    pthread_mutex_init(&client->poll_mutex, NULL);
    atomic_store(&client->read_thread_running, false);
    atomic_store(&client->read_thread_stop, false);

    /* Initialize TCP transport */
    nodus_tcp_t *tcp = calloc(1, sizeof(nodus_tcp_t));
    if (!tcp) {
        pthread_mutex_destroy(&client->pending_mutex);
        pthread_mutex_destroy(&client->send_mutex);
        pthread_mutex_destroy(&client->poll_mutex);
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
            /* Start internal read thread for continuous TCP reading */
            start_read_thread(client);
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
    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    int result = -1;

    /* Step 1: HELLO */
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_hello(txn, &client->identity.pk, &client->identity.node_id,
                    buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: HELLO send failed");
        free_pending(client, req);
        free(buf);
        return -1;
    }

    if (!wait_response(client, req, client->config.connect_timeout_ms)) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: no response to HELLO (timeout %dms)", client->config.connect_timeout_ms);
        free_pending(client, req);
        free(buf);
        return -1;
    }

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (strcmp(resp->method, "challenge") != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: expected 'challenge', got '%s'", resp->method);
        free_pending(client, req);
        free(buf);
        return -1;
    }

    /* Step 2: Sign nonce and send AUTH */
    nodus_sig_t sig;
    nodus_sign(&sig, resp->nonce, NODUS_NONCE_LEN, &client->identity.sk);
    free_pending(client, req);

    len = 0;
    txn = atomic_fetch_add(&client->next_txn, 1);
    req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_auth(txn, &sig, buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: AUTH send failed");
        free_pending(client, req);
        free(buf);
        return -1;
    }

    if (!wait_response(client, req, client->config.connect_timeout_ms)) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: no response to AUTH (timeout %dms)", client->config.connect_timeout_ms);
        free_pending(client, req);
        free(buf);
        return -1;
    }

    resp = (nodus_tier2_msg_t *)req->response;
    if (strcmp(resp->method, "auth_ok") != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: expected 'auth_ok', got '%s'", resp->method);
        free_pending(client, req);
        free(buf);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Auth: success");
    memcpy(client->token, resp->token, NODUS_SESSION_TOKEN_LEN);
    result = 0;

    free_pending(client, req);
    free(buf);
    return result;
}

static int resubscribe_all(nodus_client_t *client) {
    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;

    /* Fire-and-forget: send all LISTEN/CH_SUBSCRIBE requests without waiting.
     * Previous implementation blocked 2s per listener (wait_response), which
     * stalled the read thread during reconnect — notifications were delayed.
     * Server processes them async; if any fail, ping timeout will re-trigger. */

    /* Re-subscribe DHT listeners */
    for (int i = 0; i < client->listen_count; i++) {
        size_t len = 0;
        uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
        nodus_t2_listen(txn, client->token, &client->listen_keys[i],
                         buf, CLIENT_BUF_SIZE, &len);
        send_request(client, buf, len);
        /* No wait — server will send listen_ok which read thread discards
         * (no pending slot → "unknown txn" warning, harmless) */
    }

    /* Re-subscribe channels */
    for (int i = 0; i < client->ch_sub_count; i++) {
        size_t len = 0;
        uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
        nodus_t2_ch_subscribe(txn, client->token, client->ch_subs[i],
                               buf, CLIENT_BUF_SIZE, &len);
        send_request(client, buf, len);
    }

    QGP_LOG_INFO(LOG_TAG, "Re-subscribed %d listeners + %d channels (fire-and-forget)",
                 client->listen_count, client->ch_sub_count);

    free(buf);
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

    /* Read thread handles all TCP reading — external callers are no-ops */
    if (atomic_load(&client->read_thread_running))
        return 0;

    pthread_mutex_lock(&client->poll_mutex);

    /* Handle reconnect */
    if (client->state == NODUS_CLIENT_RECONNECTING) {
        try_reconnect(client);
        if (client->state != NODUS_CLIENT_READY) {
            nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
            int rc = nodus_tcp_poll(tcp, timeout_ms < 100 ? timeout_ms : 100);
            pthread_mutex_unlock(&client->poll_mutex);
            return rc;
        }
    }

    if (!client->conn) {
        pthread_mutex_unlock(&client->poll_mutex);
        return 0;
    }

    nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
    int rc = nodus_tcp_poll(tcp, timeout_ms);
    pthread_mutex_unlock(&client->poll_mutex);
    return rc;
}

bool nodus_client_is_ready(const nodus_client_t *client) {
    return client && client->state == NODUS_CLIENT_READY;
}

nodus_client_state_t nodus_client_state(const nodus_client_t *client) {
    return client ? client->state : NODUS_CLIENT_DISCONNECTED;
}

void nodus_client_force_disconnect(nodus_client_t *client) {
    if (!client) return;
    /* Signal read thread to stop */
    atomic_store(&client->read_thread_stop, true);
    /* Close socket FIRST — breaks epoll_wait so read thread exits quickly */
    if (client->conn) {
        nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)client->conn;
        if (conn->fd >= 0) {
#ifdef _WIN32
            shutdown(conn->fd, SD_BOTH);
            closesocket(conn->fd);
#else
            shutdown(conn->fd, SHUT_RDWR);
            close(conn->fd);
#endif
            conn->fd = -1;
        }
        client->conn = NULL;
    }
    client->state = NODUS_CLIENT_DISCONNECTED;
    /* Now join the read thread (it should exit fast since socket is closed) */
    stop_read_thread(client);
}

void nodus_client_close(nodus_client_t *client) {
    if (!client) return;

    /* Stop read thread before tearing down TCP */
    stop_read_thread(client);

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

    /* Free all pending slots */
    for (int i = 0; i < NODUS_MAX_PENDING; i++) {
        nodus_pending_t *p = &client->pending[i];
        if (p->in_use) {
            if (p->response) {
                nodus_t2_msg_free((nodus_tier2_msg_t *)p->response);
                free(p->response);
            }
            free(p->raw_response);
            p->in_use = false;
        }
    }

    pthread_mutex_destroy(&client->pending_mutex);
    pthread_mutex_destroy(&client->send_mutex);
    pthread_mutex_destroy(&client->poll_mutex);

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

    uint8_t *buf = malloc(CLIENT_BUF_SIZE_PUT);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    if (nodus_t2_put(txn, client->token, key, data, data_len,
                      type, ttl, vid, seq, sig,
                      buf, CLIENT_BUF_SIZE_PUT, &len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "PUT encode failed (data_len=%zu, buf=%d)", data_len, CLIENT_BUF_SIZE_PUT);
        free_pending(client, req); free(buf); return -1;
    }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    int rc = (resp->type == 'e') ? resp->error_code : 0;
    free_pending(client, req);
    return rc;
}

int nodus_client_get(nodus_client_t *client,
                      const nodus_key_t *key,
                      nodus_value_t **val_out) {
    if (!nodus_client_is_ready(client) || !val_out) return -1;
    *val_out = NULL;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_get(txn, client->token, key,
                  buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (resp->value) {
        *val_out = resp->value;
        resp->value = NULL;
    } else {
        free_pending(client, req);
        return NODUS_ERR_NOT_FOUND;
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_get_all(nodus_client_t *client,
                          const nodus_key_t *key,
                          nodus_value_t ***vals_out,
                          size_t *count_out) {
    if (!nodus_client_is_ready(client) || !vals_out || !count_out) return -1;
    *vals_out = NULL;
    *count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_get_all(txn, client->token, key,
                      buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (resp->values && resp->value_count > 0) {
        /* Transfer ownership */
        *vals_out = resp->values;
        *count_out = resp->value_count;
        resp->values = NULL;
        resp->value_count = 0;
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_listen(nodus_client_t *client, const nodus_key_t *key) {
    if (!nodus_client_is_ready(client) || !key) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_listen(txn, client->token, key,
                     buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

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
    free_pending(client, req);
    return 0;
}

int nodus_client_unlisten(nodus_client_t *client, const nodus_key_t *key) {
    if (!nodus_client_is_ready(client) || !key) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_unlisten(txn, client->token, key,
                       buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Remove from tracking */
    for (int i = 0; i < client->listen_count; i++) {
        if (nodus_key_cmp(&client->listen_keys[i], key) == 0) {
            client->listen_keys[i] = client->listen_keys[--client->listen_count];
            break;
        }
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_get_servers(nodus_client_t *client,
                              nodus_server_endpoint_t *endpoints_out,
                              int max_count, int *count_out) {
    if (!nodus_client_is_ready(client) || !endpoints_out || !count_out) return -1;
    *count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_servers(txn, client->token,
                      buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    int n = resp->server_count < max_count ? resp->server_count : max_count;
    for (int i = 0; i < n; i++) {
        memset(&endpoints_out[i], 0, sizeof(endpoints_out[i]));
        strncpy(endpoints_out[i].ip, resp->servers[i].ip,
                sizeof(endpoints_out[i].ip) - 1);
        endpoints_out[i].port = resp->servers[i].tcp_port;
    }
    *count_out = n;
    free_pending(client, req);
    return 0;
}

/* ── Channel Operations ─────────────────────────────────────────── */

int nodus_client_ch_create(nodus_client_t *client,
                            const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_create(txn, client->token, uuid,
                        buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }
    free_pending(client, req);
    return 0;
}

int nodus_client_ch_post(nodus_client_t *client,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          const uint8_t post_uuid[NODUS_UUID_BYTES],
                          const uint8_t *body, size_t body_len,
                          uint64_t timestamp, const nodus_sig_t *sig,
                          uint32_t *seq_out) {
    if (!nodus_client_is_ready(client) || !ch_uuid || !body) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_post(txn, client->token, ch_uuid, post_uuid,
                      body, body_len, timestamp, sig,
                      buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (seq_out) *seq_out = resp->ch_seq_id;
    free_pending(client, req);
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

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_get_posts(txn, client->token, uuid, since_seq, max_count,
                           buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (resp->ch_posts && resp->ch_post_count > 0) {
        /* Transfer ownership */
        *posts_out = resp->ch_posts;
        *count_out = resp->ch_post_count;
        resp->ch_posts = NULL;
        resp->ch_post_count = 0;
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_ch_subscribe(nodus_client_t *client,
                               const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_subscribe(txn, client->token, uuid,
                           buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

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
    free_pending(client, req);
    return 0;
}

int nodus_client_ch_unsubscribe(nodus_client_t *client,
                                 const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_unsubscribe(txn, client->token, uuid,
                              buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Remove from tracking */
    for (int i = 0; i < client->ch_sub_count; i++) {
        if (memcmp(client->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
            memcpy(client->ch_subs[i], client->ch_subs[--client->ch_sub_count],
                   NODUS_UUID_BYTES);
            break;
        }
    }
    free_pending(client, req);
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

/* ── Presence Operations ─────────────────────────────────────────── */

int nodus_client_presence_query(nodus_client_t *client,
                                  const nodus_key_t *fps, int count,
                                  nodus_presence_result_t *result) {
    if (!nodus_client_is_ready(client) || !fps || !result || count <= 0)
        return -1;
    if (count > NODUS_PRESENCE_MAX_QUERY)
        count = NODUS_PRESENCE_MAX_QUERY;

    memset(result, 0, sizeof(*result));
    result->total_queried = count;

    /* Encode pq request using T2 encoder */
    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t buf_len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    if (nodus_t2_presence_query(txn, client->token,
                                  fps, count, buf, CLIENT_BUF_SIZE, &buf_len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }

    if (send_request(client, buf, buf_len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 10000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Parse result from T2-decoded fields */
    if (resp->pq_fps && resp->pq_count > 0) {
        result->online_count = resp->pq_count;
        result->entries = calloc((size_t)resp->pq_count,
                                   sizeof(nodus_presence_entry_result_t));
        if (result->entries) {
            for (int i = 0; i < resp->pq_count; i++) {
                result->entries[i].fp = resp->pq_fps[i];
                result->entries[i].online = resp->pq_online ? resp->pq_online[i] : true;
                result->entries[i].peer_index = resp->pq_peers ? resp->pq_peers[i] : 0;
                result->entries[i].last_seen = resp->pq_last_seen ? resp->pq_last_seen[i] : 0;
            }
        }
    }

    /* Parse offline-seen entries */
    if (resp->os_fps && resp->os_count > 0) {
        result->offline_seen_count = resp->os_count;
        result->offline_seen = calloc((size_t)resp->os_count,
                                        sizeof(nodus_presence_entry_result_t));
        if (result->offline_seen) {
            for (int i = 0; i < resp->os_count; i++) {
                result->offline_seen[i].fp = resp->os_fps[i];
                result->offline_seen[i].online = false;
                result->offline_seen[i].last_seen = resp->os_last_seen ? resp->os_last_seen[i] : 0;
            }
        }
    }

    free_pending(client, req);
    return 0;
}

void nodus_client_free_presence_result(nodus_presence_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->online_count = 0;
    free(result->offline_seen);
    result->offline_seen = NULL;
    result->offline_seen_count = 0;
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

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

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
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    /* BFT consensus can take up to 30s */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 30000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Decode spend result from raw response */
    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_nullifier(nodus_client_t *client,
                                  const uint8_t *nullifier,
                                  nodus_dnac_nullifier_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !nullifier || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_nullifier", 1);

    cbor_encode_cstr(&enc, "nullifier");
    cbor_encode_bstr(&enc, nullifier, NODUS_T3_NULLIFIER_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_ledger(nodus_client_t *client,
                               const uint8_t *tx_hash,
                               nodus_dnac_ledger_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !tx_hash || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_ledger", 1);

    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_supply(nodus_client_t *client,
                               nodus_dnac_supply_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_supply", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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

    free_pending(client, req);
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

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_utxo", 2);

    cbor_encode_cstr(&enc, "owner");
    cbor_encode_cstr(&enc, owner);
    cbor_encode_cstr(&enc, "max");
    cbor_encode_uint(&enc, (uint64_t)max_results);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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
                if (!result_out->entries) { free_pending(client, req); return NODUS_ERR_INTERNAL_ERROR; }
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
    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_ledger_range(nodus_client_t *client,
                                     uint64_t from_seq, uint64_t to_seq,
                                     nodus_dnac_range_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_ledger_range", 2);

    cbor_encode_cstr(&enc, "from");
    cbor_encode_uint(&enc, from_seq);
    cbor_encode_cstr(&enc, "to");
    cbor_encode_uint(&enc, to_seq);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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
                if (!result_out->entries) { free_pending(client, req); return NODUS_ERR_INTERNAL_ERROR; }
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

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_roster(nodus_client_t *client,
                               nodus_dnac_roster_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_roster", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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

    free_pending(client, req);
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

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_tx", 1);

    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 10000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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

    free_pending(client, req);
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

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_block", 1);

    cbor_encode_cstr(&enc, "height");
    cbor_encode_uint(&enc, height);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 10000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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

    free_pending(client, req);
    return 0;
}

/* ── Block Range Query (v0.10.0 hub/spoke) ──────────────────────── */

int nodus_client_dnac_block_range(nodus_client_t *client,
                                    uint64_t from_height, uint64_t to_height,
                                    nodus_dnac_block_range_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_block_range", 2);

    cbor_encode_cstr(&enc, "from");
    cbor_encode_uint(&enc, from_height);
    cbor_encode_cstr(&enc, "to");
    cbor_encode_uint(&enc, to_height);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 10000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

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

    free_pending(client, req);
    return 0;
}

void nodus_client_free_block_range_result(nodus_dnac_block_range_result_t *result) {
    if (!result) return;
    free(result->blocks);
    result->blocks = NULL;
    result->count = 0;
}
